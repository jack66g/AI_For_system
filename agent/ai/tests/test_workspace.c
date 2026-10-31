// SPDX-License-Identifier: GPL-2.0
/*
 * test_workspace.c - W79 workspace 通道回归
 *
 * 默认（非 root）：纯函数校验 + 注册表接线 + 不存在/非法参数的诚实错误。
 *   - name 字符集/长度/点开头/..；size 边界；
 *   - tools.json 204 件、workspace 通道 6 件、risk R/R/R/W2/W1/W1；
 *   - destroy 不存在 → AI_OK（幂等）；run/inspect/quota 不存在 →
 *     AI_ERR_NOT_FOUND；create 非法参数 → AI_ERR_INVALID_ARG 且零副作用。
 *
 * --live（需要 root + 真 aik-sandbox）：走 tool_executor_run 真链路
 *   create 64MB → list → inspect → run 写 /data.txt → run 读回 hello →
 *   run id/ls/df 证明根是镜像 → quota 64→96 → destroy 两次幂等 → 零残留。
 *   环境：AIKERNEL_SANDBOX_BIN 指向构建出的 aik-sandbox。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "tools/workspace_tools.h"
#include "policy/ai_lease.h"

static int fails;
static int checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (cond) { \
		printf("ok %s\n", msg); \
	} else { \
		printf("FAIL %s\n", msg); \
		fails++; \
	} \
} while (0)

static void test_validators(void)
{
	CHECK(ai_ws_valid_name("ws-test") == 1, "name ws-test 合法");
	CHECK(ai_ws_valid_name("W79.a_b-c") == 1, "name W79.a_b-c 合法");
	CHECK(ai_ws_valid_name("abcdefghijklmnopqrstuvwxyz012345") == 1,
	      "name 32 字符（字母数字混合）合法");
	CHECK(ai_ws_valid_name("12345678901234567890123456789012") == 1,
	      "name 恰好 32 字符合法");
	CHECK(ai_ws_valid_name("123456789012345678901234567890123") == 0,
	      "name 33 字符拒绝");
	CHECK(ai_ws_valid_name("") == 0, "name 空拒绝");
	CHECK(ai_ws_valid_name(NULL) == 0, "name NULL 拒绝");
	CHECK(ai_ws_valid_name(".hidden") == 0, "name 点开头拒绝");
	CHECK(ai_ws_valid_name("-opt") == 0, "name 横线开头拒绝");
	CHECK(ai_ws_valid_name("a/b") == 0, "name 斜杠拒绝");
	CHECK(ai_ws_valid_name("a;rm") == 0, "name 分号拒绝");
	CHECK(ai_ws_valid_name("a b") == 0, "name 空格拒绝");
	CHECK(ai_ws_valid_name("a..b") == 0, "name 连续点拒绝");
	CHECK(ai_ws_valid_name("..") == 0, "name .. 拒绝");

	CHECK(ai_ws_valid_size_mb(16) == 1, "size 16 合法（下界）");
	CHECK(ai_ws_valid_size_mb(8192) == 1, "size 8192 合法（上界）");
	CHECK(ai_ws_valid_size_mb(15) == 0, "size 15 拒绝");
	CHECK(ai_ws_valid_size_mb(8193) == 0, "size 8193 拒绝");
	CHECK(ai_ws_valid_size_mb(0) == 0, "size 0 拒绝");
	CHECK(ai_ws_valid_size_mb(-1) == 0, "size -1 拒绝");

	CHECK(ai_ws_valid_label("") == 1, "label 空合法");
	CHECK(ai_ws_valid_label("team-a v0.1") == 1, "label 常规合法");
	CHECK(ai_ws_valid_label("bad/label") == 0, "label 斜杠拒绝");
	CHECK(ai_ws_valid_label("bad\nlabel") == 0, "label 换行拒绝");
}

/* 直接调通道实现：验证返回码（tool_executor_run 一律回 AI_OK，只给
 * ok 标志，错误码语义只存在于通道实现层） */
static void call_ch(const struct ai_tool *t, const char *args, char **out,
		    int *rc)
{
	*out = NULL;
	*rc = exec_workspace_channel(t, args, out);
}

static void test_registry(void)
{
	struct tool_registry reg;
	char *err = NULL;
	const struct ai_tool *t;
	int i, ws = 0, risks_ok = 1;
	static const char *const want[] = {
		"workspace_create", "workspace_list", "workspace_inspect",
		"workspace_run", "workspace_destroy", "workspace_quota",
	};
	static const char *const want_risk[] = {
		"W1", "R", "R", "W2", "W1", "W1",
	};

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "tools.json 加载（197 件口径）");
	CHECK(reg.tool_count == 204, "注册表总数 204");
	CHECK(tool_channel_from_str("workspace") == TOOL_CH_WORKSPACE,
	      "channel 字符串 workspace 映射");
	for (i = 0; i < reg.tool_count; i++)
		if (reg.tools[i].channel == TOOL_CH_WORKSPACE)
			ws++;
	CHECK(ws == 6, "workspace 通道恰 6 件");
	for (i = 0; i < 6; i++) {
		t = tool_registry_find(&reg, want[i]);
		if (!t || t->channel != TOOL_CH_WORKSPACE ||
		    !t->risk || strcmp(t->risk, want_risk[i]) != 0 ||
		    t->sub_count < 1)
			risks_ok = 0;
	}
	CHECK(risks_ok, "六件工具注册/channel/risk/sub 齐全");
	t = tool_registry_find(&reg, "workspace_run");
	CHECK(t && strcmp(tool_exec_effective_risk(t, "{}"), "W2") == 0,
	      "workspace_run 有效风险 = W2");
}

static void test_no_side_effects(const char *root)
{
	char path[512], cmd[1024];
	struct ai_tool t;
	char *out = NULL;
	int rc;
	struct stat st;

	snprintf(path, sizeof(path), "%s/no-such-ws.img", root);
	CHECK(stat(path, &st) != 0, "回滚演练前置：目标镜像不存在");

	/* run 不存在的 workspace：明确 NOT_FOUND，绝不自动建区 */
	memset(&t, 0, sizeof(t));
	t.name = "workspace_run";
	t.channel = TOOL_CH_WORKSPACE;
	t.risk = "W2";
	call_ch(&t, "{\"name\":\"no-such-ws\",\"command\":\"true\"}",
		&out, &rc);
	CHECK(rc == AI_ERR_NOT_FOUND && out &&
	      strstr(out, "不存在") != NULL,
	      "run 不存在 → AI_ERR_NOT_FOUND + 明确文案");
	CHECK(stat(path, &st) != 0, "run 失败未留下空镜像");
	free(out);

	/* inspect 不存在 */
	memset(&t, 0, sizeof(t));
	t.name = "workspace_inspect";
	t.channel = TOOL_CH_WORKSPACE;
	t.risk = "R";
	out = NULL;
	call_ch(&t, "{\"name\":\"no-such-ws\"}", &out, &rc);
	CHECK(rc == AI_ERR_NOT_FOUND, "inspect 不存在 → AI_ERR_NOT_FOUND");
	free(out);

	/* quota 不存在 */
	memset(&t, 0, sizeof(t));
	t.name = "workspace_quota";
	t.channel = TOOL_CH_WORKSPACE;
	t.risk = "W1";
	out = NULL;
	call_ch(&t, "{\"name\":\"no-such-ws\",\"mb\":32}", &out, &rc);
	CHECK(rc == AI_ERR_NOT_FOUND, "quota 不存在 → AI_ERR_NOT_FOUND");
	free(out);

	/* create 非法 name：拒绝且零文件 */
	memset(&t, 0, sizeof(t));
	t.name = "workspace_create";
	t.channel = TOOL_CH_WORKSPACE;
	t.risk = "W1";
	out = NULL;
	call_ch(&t, "{\"name\":\"../evil\",\"size_mb\":64}", &out, &rc);
	CHECK(rc == AI_ERR_INVALID_ARG, "create 注入名 → INVALID_ARG");
	free(out);

	/* create 非法 size（回滚演练）：明确错误 + 无镜像/loop/目录 */
	snprintf(cmd, sizeof(cmd),
		 "{\"name\":\"w79rollback\",\"size_mb\":8}");
	out = NULL;
	call_ch(&t, cmd, &out, &rc);
	CHECK(rc == AI_ERR_INVALID_ARG && out &&
	      strstr(out, "size_mb") != NULL,
	      "create size=8 → INVALID_ARG + 指出 size 范围");
	snprintf(path, sizeof(path), "%s/w79rollback.img", root);
	CHECK(stat(path, &st) != 0, "size 拒绝后无镜像残留");
	{
		char sbdir[512];

		snprintf(sbdir, sizeof(sbdir), "%s/w79rollback",
			 getenv("AIKERNEL_SANDBOX_BASE"));
		CHECK(stat(sbdir, &st) != 0, "size 拒绝后无空沙盒目录");
	}
	free(out);

	/* destroy 不存在：幂等成功 */
	memset(&t, 0, sizeof(t));
	t.name = "workspace_destroy";
	t.channel = TOOL_CH_WORKSPACE;
	t.risk = "W1";
	out = NULL;
	call_ch(&t, "{\"name\":\"no-such-ws\"}", &out, &rc);
	CHECK(rc == AI_OK && out && strstr(out, "无残留") != NULL,
	      "destroy 不存在 → AI_OK + 无残留（幂等）");
	free(out);
}

static void run_tool(const struct tool_registry *reg, const char *name,
		     const char *args, char **out, int *ok)
{
	const struct ai_tool *t = tool_registry_find(reg, name);
	int rc;

	*out = NULL;
	*ok = 0;
	if (!t) {
		printf("FATAL: tool %s 缺失\n", name);
		return;
	}
	rc = tool_executor_run(t, args, out, ok);
	if (rc != AI_OK && *out)
		printf("  (%s rc=%d)\n", name, rc);
}

static const char *test_ws_root(void)
{
	const char *e = getenv("AIKERNEL_WORKSPACE_ROOT");

	return (e && e[0]) ? e : "/var/lib/aikernel/ws";
}

/* ws 根下 <name>.img.tmp.* 残留个数 */
static int tmp_leftovers(const char *name)
{
	char prefix[512];
	char dir[512];
	DIR *d;
	struct dirent *e;
	int n = 0;

	snprintf(prefix, sizeof(prefix), "%s.img.tmp.", name);
	snprintf(dir, sizeof(dir), "%s", test_ws_root());
	d = opendir(dir);
	if (!d)
		return 0;
	while ((e = readdir(d))) {
		if (strncmp(e->d_name, prefix, strlen(prefix)) == 0)
			n++;
	}
	closedir(d);
	return n;
}

/* /sys/block/loop* 是否有回指 image 的设备 */
static int loop_for_image(const char *image)
{
	DIR *d = opendir("/sys/block");
	struct dirent *e;
	int found = 0;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		char p[512], b[512];
		FILE *fp;

		if (strncmp(e->d_name, "loop", 4) != 0)
			continue;
		snprintf(p, sizeof(p), "/sys/block/%s/loop/backing_file",
			 e->d_name);
		fp = fopen(p, "r");
		if (!fp)
			continue;
		if (fgets(b, sizeof(b), fp)) {
			b[strcspn(b, "\r\n")] = '\0';
			if (strcmp(b, image) == 0 ||
			    (b[0] != '/' && strcmp(b, image + 1) == 0))
				found = 1;
		}
		fclose(fp);
		if (found)
			break;
	}
	closedir(d);
	return found;
}

static int make_sparse(const char *path, long mb)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);

	if (fd < 0)
		return -1;
	if (ftruncate(fd, (off_t)mb * 1024 * 1024)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int live(void)
{
	struct tool_registry reg;
	char *err = NULL, *out = NULL;
	int ok = 0, pass = 0, total = 0;
	char lerr[AI_LEASE_ERR_MAX] = "";
	struct stat st;
	char img[512];
	const char *stub = "/tmp/w79-fail-resize2fs";

	{
		const char *bin = getenv("AIKERNEL_SANDBOX_BIN");

		printf("== test_workspace --live (uid=%u, bin=%s) ==\n",
		       (unsigned)getuid(), bin ? bin : "(default)");
	}
	if (getuid() != 0) {
		printf("SKIP: --live 需要 root（mount/loop）\n");
		return 0;
	}
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));

	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		printf("FATAL: tools.json: %s\n", err ? err : "?");
		return 1;
	}

#define LIVE(step, tool, args, want_ok, want_str) do { \
	total++; \
	ok = 0; \
	out = NULL; \
	run_tool(&reg, tool, args, &out, &ok); \
	if (ok == (want_ok) && out && strstr(out, want_str) != NULL) { \
		printf("ok LIVE-%d %s\n", step, tool); \
		pass++; \
	} else { \
		printf("FAIL LIVE-%d %s (ok=%d want_ok=%d)\n%s\n", \
		       step, tool, ok, want_ok, out ? out : "(null)"); \
	} \
	free(out); \
} while (0)

	/* 先清场（幂等） */
	total++;
	out = NULL;
	run_tool(&reg, "workspace_destroy", "{\"name\":\"ws-test\"}",
		 &out, &ok);
	printf("ok LIVE-0 cleanup destroy (ok=%d): %s\n", ok,
	       out ? out : "");
	pass++;
	free(out);
	{
		char *o = NULL;
		int k = 0;

		run_tool(&reg, "workspace_destroy", "{\"name\":\"ws-badimg\"}",
			 &o, &k);
		free(o);
	}

	LIVE(1, "workspace_create",
	     "{\"name\":\"ws-test\",\"size_mb\":64,\"net\":\"none\","
	     "\"label\":\"w79\"}", 1, "就绪");
	/* create 的临时镜像必须已 rename 掉，不留 .img.tmp.* */
	total++;
	if (tmp_leftovers("ws-test") == 0) {
		printf("ok LIVE-1b create 无临时镜像残留\n");
		pass++;
	} else {
		printf("FAIL LIVE-1b create 残留 %d 个 .img.tmp.*\n",
		       tmp_leftovers("ws-test"));
	}
	LIVE(2, "workspace_list", "{}", 1, "ws-test");
	LIVE(3, "workspace_inspect", "{\"name\":\"ws-test\"}", 1,
	     "/var/lib/aikernel/ws/ws-test.img");
	LIVE(4, "workspace_run",
	     "{\"name\":\"ws-test\",\"command\":\"echo hello > /data.txt\"}",
	     1, "命令执行成功");
	LIVE(5, "workspace_run",
	     "{\"name\":\"ws-test\",\"command\":\"cat /data.txt\"}",
	     1, "hello");
	LIVE(6, "workspace_run",
	     "{\"name\":\"ws-test\",\"command\":\"id; ls /; df -h /\"}",
	     1, "/dev/loop");
	/* 退出码语义：非零 = 工具失败（对齐 exec_run） */
	LIVE(7, "workspace_run",
	     "{\"name\":\"ws-test\",\"command\":\"false\"}", 0,
	     "命令退出码 1");
	LIVE(8, "workspace_quota", "{\"name\":\"ws-test\",\"mb\":96}", 1,
	     "96MB");
	LIVE(9, "workspace_inspect", "{\"name\":\"ws-test\"}", 1,
	     "size:      96 MB");

	/* quota 失败回滚：注入必然失败的 resize2fs 桩 */
	LIVE(10, "workspace_run",
	     "{\"name\":\"ws-test\",\"command\":\"echo ok96 > /ok96\"}",
	     1, "命令执行成功");
	{
		FILE *fp = fopen(stub, "w");

		if (!fp) {
			printf("FAIL LIVE-11 无法写 resize2fs 桩\n");
			total++;
		} else {
			fputs("#!/bin/sh\nexit 1\n", fp);
			fclose(fp);
			chmod(stub, 0755);
		}
	}
	setenv("AIKERNEL_WORKSPACE_RESIZE2FS", stub, 1);
	LIVE(11, "workspace_quota", "{\"name\":\"ws-test\",\"mb\":128}", 0,
	     "已回滚到原大小 96MB");
	unsetenv("AIKERNEL_WORKSPACE_RESIZE2FS");
	snprintf(img, sizeof(img), "%s/ws-test.img", test_ws_root());
	total++;
	if (stat(img, &st) == 0 &&
	    st.st_size == (off_t)96 * 1024 * 1024) {
		printf("ok LIVE-11b 回滚后镜像文件大小=96MB\n");
		pass++;
	} else {
		printf("FAIL LIVE-11b 回滚后镜像大小=%lld（期望 96MB）\n",
		       stat(img, &st) == 0 ? (long long)st.st_size : -1);
	}
	LIVE(12, "workspace_inspect", "{\"name\":\"ws-test\"}", 1,
	     "size:      96 MB");
	LIVE(13, "workspace_run",
	     "{\"name\":\"ws-test\",\"command\":\"cat /ok96\"}", 1,
	     "ok96");
	LIVE(14, "workspace_destroy", "{\"name\":\"ws-test\"}", 1, "已清理");
	LIVE(15, "workspace_destroy", "{\"name\":\"ws-test\"}", 1, "无残留");

	/* 已存在的未格式化同名镜像：必须明确拒绝，且无 temp/loop/沙盒目录 */
	snprintf(img, sizeof(img), "%s/ws-badimg.img", test_ws_root());
	make_sparse(img, 64);
	LIVE(16, "workspace_create",
	     "{\"name\":\"ws-badimg\",\"size_mb\":64,\"net\":\"none\"}",
	     0, "不是可用 ext4");
	{
		char sdir[512];
		int left = tmp_leftovers("ws-badimg");

		snprintf(sdir, sizeof(sdir), "/sandbox/ws-badimg");
		total++;
		if (left == 0 && !loop_for_image(img) &&
		    stat(sdir, &st) != 0) {
			printf("ok LIVE-16b 坏镜像失败后无 temp/loop/沙盒目录\n");
			pass++;
		} else {
			printf("FAIL LIVE-16b 坏镜像残留 temp=%d loop=%d "
			       "sandbox=%d\n", left, loop_for_image(img),
			       stat(sdir, &st) == 0);
		}
	}
	unlink(img);
	unlink(stub);

	printf("LIVE SUMMARY: %d/%d\n", pass, total);
	return pass == total ? 0 : 1;
}

int main(int argc, char **argv)
{
	char tmpl[] = "/tmp/w79ws-XXXXXX";
	char sbdir[512];
	char *root;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc > 1 && strcmp(argv[1], "--live") == 0)
		return live();
	/* 取证单调用模式：--call <tool> <args-json>（真执行器/真沙盒） */
	if (argc == 4 && strcmp(argv[1], "--call") == 0) {
		struct tool_registry reg;
		char *err = NULL, *out = NULL;
		char lerr[AI_LEASE_ERR_MAX] = "";
		int ok = 0;

		setenv("AIKERNEL_POLICY", "/dev/null", 1);
		setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
		memset(&reg, 0, sizeof(reg));
		if (tool_registry_load(&reg, &err) != AI_OK) {
			printf("FATAL: tools.json: %s\n", err ? err : "?");
			return 2;
		}
		run_tool(&reg, argv[2], argv[3], &out, &ok);
		printf("%s\n", out ? out : "(null)");
		free(out);
		return ok ? 0 : 1;
	}

	root = mkdtemp(tmpl);
	if (!root) {
		perror("mkdtemp");
		return 2;
	}
	snprintf(sbdir, sizeof(sbdir), "%s/sandbox", root);
	if (mkdir(sbdir, 0755)) {
		perror("mkdir sandbox");
		return 2;
	}
	setenv("AIKERNEL_WORKSPACE_ROOT", root, 1);
	setenv("AIKERNEL_SANDBOX_BASE", sbdir, 1);
	setenv("AIKERNEL_SANDBOX_CGROUP_ROOT", "/nonexistent-w79-cgroup", 1);
	setenv("AIKERNEL_SANDBOX_ARTIFACTS", "/nonexistent-w79-artifacts", 1);
	setenv("AIKERNEL_SANDBOX_BIN", "/nonexistent-w79-sandbox", 1);
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}

	printf("== test_workspace (unit, root=%s) ==\n", root);
	test_registry();
	test_validators();
	test_no_side_effects(root);

	/* 临时根下确无工作区 */
	{
		DIR *d = opendir(root);
		struct dirent *e;
		int n = 0;

		if (d) {
			while ((e = readdir(d))) {
				if (e->d_name[0] == '.')
					continue;
				if (strcmp(e->d_name, "sandbox") == 0)
					continue;
				n++;
			}
			closedir(d);
		}
		CHECK(n == 0, "单测结束：临时工作区根零残留");
	}

	printf("SUMMARY: %d checks, %d failed\n", checks, fails);
	rmdir(sbdir);
	rmdir(root);
	return fails ? 1 : 0;
}
