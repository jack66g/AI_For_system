// SPDX-License-Identifier: GPL-2.0
/*
 * test_workspace_backend.c - W82e（V1.8）统一后端回归
 *
 * 断言「sandbox 隔离区 = workspace 的一个 backend（backing=tmpfs）」：
 *   1. 区名 → 工作区名映射（≤32 同名；33-64 确定性短名 + alias；
 *      非法名拒绝）；
 *   2. 建区走 workspace：元数据落工作区根、backing=tmpfs、net=host；
 *      长区名记 alias；
 *   3. 区内执行走 workspace 的 run 翻译：有元数据时下发
 *      --backing=tmpfs/--cpus/--mem-mb/--pids/--net；无元数据时保持
 *      aik-sandbox 的临时区语义（run <name> -- <cmd>）；
 *   4. 销毁只有一条路径：zone_destroy 与 workspace_destroy（ai_ws_destroy）
 *      都能把同一份状态清干净、幂等、零残留；
 *   5. 持久盘保护：同名 backing=disk 工作区，sandbox_create 不覆盖、
 *      sandbox_destroy 不删除；
 *   6. 33-64 字符历史区（V1.8 前直接由 aik-sandbox 建）仍能按原名回收；
 *   7. 统一采集：取消标志置位 → SIGKILL 全组、快速返回、无残留。
 *
 * 纯 mock（AIKERNEL_SANDBOX_BIN 指向测试写出的 sh 脚本），不需要 root，
 * 不触碰 /var/lib/aikernel、/sandbox 与真实 cgroup。
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#include "ai_types.h"
#include "ai_lang.h"
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

static void write_file(const char *path, const char *content, int exe)
{
	FILE *fp = fopen(path, "w");

	if (!fp) {
		perror(path);
		exit(2);
	}
	fputs(content, fp);
	fclose(fp);
	if (exe)
		chmod(path, 0755);
}

static int file_exists(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0;
}

static char *read_all(const char *path)
{
	FILE *fp = fopen(path, "rb");
	long n;
	char *b;

	if (!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	n = ftell(fp);
	rewind(fp);
	b = malloc((size_t)n + 1);
	if (!b) {
		fclose(fp);
		return NULL;
	}
	if (fread(b, 1, (size_t)n, fp) != (size_t)n) {
		free(b);
		fclose(fp);
		return NULL;
	}
	b[n] = '\0';
	fclose(fp);
	return b;
}

/* 扫描工作区根里某工作区名残留的 .meta/.img（零残留断言用） */
static int ws_residue(const char *root, const char *name)
{
	char p[512];

	snprintf(p, sizeof(p), "%s/%s.meta", root, name);
	if (file_exists(p))
		return 1;
	snprintf(p, sizeof(p), "%s/%s.img", root, name);
	return file_exists(p);
}

static int proc_alive_marker(const char *marker)
{
	DIR *d = opendir("/proc");
	struct dirent *e;
	int alive = 0;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		char path[320], buf[1024];
		FILE *fp;
		size_t n;

		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
		fp = fopen(path, "rb");
		if (!fp)
			continue;
		n = fread(buf, 1, sizeof(buf) - 1, fp);
		fclose(fp);
		buf[n] = '\0';
		if (n && strstr(buf, marker)) {
			alive = 1;
			break;
		}
	}
	closedir(d);
	return alive;
}

/* 手写一份 backing=disk 的元数据（模拟既有持久工作区） */
static void write_disk_meta(const char *root, const char *name)
{
	char path[512];
	char body[1024];

	snprintf(path, sizeof(path), "%s/%s.meta", root, name);
	snprintf(body, sizeof(body),
		 "name=%s\nbacking=disk\nimage=%s/%s.img\nloop=\n"
		 "size_mb=64\ncreated=1\nlabel=\ncpus=1.00\nmem_mb=1024\n"
		 "pids_max=256\nnet=host\n", name, root, name);
	write_file(path, body, 0);
}

/* ------------------------------------------------------------------
 * 非 root 单测：mock 后端，纯状态机语义（默认模式）
 * ------------------------------------------------------------------ */
static int run_unit(void)
{
	char tmp[] = "/tmp/wsbe-XXXXXX";
	char wsroot[256], sbroot[256], artroot[256], mock[256];
	char path[512];
	char *out = NULL;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!mkdtemp(tmp)) {
		perror("mkdtemp");
		return 2;
	}
	snprintf(wsroot, sizeof(wsroot), "%s/ws", tmp);
	snprintf(sbroot, sizeof(sbroot), "%s/sb", tmp);
	snprintf(artroot, sizeof(artroot), "%s/art", tmp);
	snprintf(mock, sizeof(mock), "%s/mock-aik-sandbox", tmp);
	setenv("AIKERNEL_WORKSPACE_ROOT", wsroot, 1);
	setenv("AIKERNEL_SANDBOX_BASE", sbroot, 1);
	setenv("AIKERNEL_SANDBOX_ARTIFACTS", artroot, 1);
	setenv("AIKERNEL_SANDBOX_CGROUP_ROOT", "/nonexistent-w82e-cgroup", 1);

	write_file(mock,
		   "#!/bin/sh\n"
		   "case \"$1\" in\n"
		   "status) echo \"MOCK_STATUS_LINE zones=0\"; exit 0;;\n"
		   "create) echo \"MOCK_CREATE_OK $2\"; exit 0;;\n"
		   "destroy) echo \"MOCK_DESTROY_OK $2\"; exit 0;;\n"
		   "run) echo \"MOCK_RUN_ARGS $@\"; exit 0;;\n"
		   "esac\n"
		   "echo MOCK_UNKNOWN; exit 3\n", 1);
	setenv("AIKERNEL_SANDBOX_BIN", mock, 1);

	/* ============ 1. 区名 → 工作区名映射（纯函数） ============ */
	{
		char ws[64];
		char n32[33], n33[34], longname[41];

		memset(n32, 'a', 32);
		n32[32] = '\0';
		memset(n33, 'b', 33);
		n33[33] = '\0';
		memset(longname, 'c', 40);
		longname[40] = '\0';

		CHECK(ai_ws_zone_name("sb1", ws, sizeof(ws)) &&
		      strcmp(ws, "sb1") == 0, "区名 ≤32 与工作区名同名");
		CHECK(ai_ws_zone_name(n32, ws, sizeof(ws)) &&
		      strcmp(ws, n32) == 0, "区名恰好 32 字符保持原样");
		CHECK(ai_ws_zone_name(n33, ws, sizeof(ws)) &&
		      strlen(ws) == 32 && strncmp(ws, n33, 23) == 0 &&
		      ws[23] == '-', "33 字符区名映射为 32 字符短名");
		{
			char ws2[64];

			CHECK(ai_ws_zone_name(n33, ws2, sizeof(ws2)) &&
			      strcmp(ws, ws2) == 0, "短名映射确定性（同输入同输出）");
		}
		CHECK(ai_ws_zone_name(longname, ws, sizeof(ws)) &&
		      strlen(ws) == 32, "40 字符区名映射为 32 字符短名");
		CHECK(!ai_ws_zone_name(".hidden", ws, sizeof(ws)) &&
		      !ai_ws_zone_name("-opt", ws, sizeof(ws)) &&
		      !ai_ws_zone_name("a..b", ws, sizeof(ws)) &&
		      !ai_ws_zone_name("a b", ws, sizeof(ws)) &&
		      !ai_ws_zone_name("", ws, sizeof(ws)) &&
		      !ai_ws_zone_name(NULL, ws, sizeof(ws)),
		      "非法区名拒绝（点/横线开头、..、空格、空、NULL）");
		{
			char n65[66];

			memset(n65, 'd', 65);
			n65[65] = '\0';
			CHECK(!ai_ws_zone_name(n65, ws, sizeof(ws)),
			      "65 字符区名拒绝（上限 64）");
		}
	}

	/* ============ 2. 建区 = workspace backing=tmpfs ============ */
	{
		int net_none = -1, rc;
		char backing[16] = "";

		rc = ai_ws_zone_create("sb-zone1", &out);
		CHECK(rc == AI_OK && out && strstr(out, "MOCK_CREATE_OK sb-zone1"),
		      "建区委托 workspace_create（后端 create 被调用）");
		free(out);
		out = NULL;
		snprintf(path, sizeof(path), "%s/sb-zone1.meta", wsroot);
		CHECK(file_exists(path), "元数据落工作区根（统一状态目录）");
		CHECK(ai_ws_meta_net("sb-zone1", &net_none, backing,
				     sizeof(backing)) == 0 &&
		      strcmp(backing, "tmpfs") == 0 && net_none == 0,
		      "元数据 backing=tmpfs / net=host（与 W42 默认一致）");
	}

	/* 长区名：短名 + alias */
	{
		char longname[41];
		char ws[64];

		memset(longname, 'c', 40);
		longname[40] = '\0';
		CHECK(ai_ws_zone_create(longname, &out) == AI_OK,
		      "40 字符区名可建（历史兼容）");
		free(out);
		out = NULL;
		ai_ws_zone_name(longname, ws, sizeof(ws));
		snprintf(path, sizeof(path), "%s/%s.meta", wsroot, ws);
		{
			char *txt = read_all(path);
			char want[128];

			snprintf(want, sizeof(want), "alias=%s\n", longname);
			CHECK(txt && strstr(txt, want),
			      "长区名在元数据记 alias（可追溯原名）");
			free(txt);
		}
	}

	/* ============ 3. 区内执行：run 参数面翻译 ============ */
	{
		char *rargv[4];
		char *tail = NULL;
		int rc, exit_code = -1, timed = 0, cancelled = 0, trunc = 0;
		char *err = NULL;

		rargv[0] = (char *)"/bin/sh";
		rargv[1] = (char *)"-c";
		rargv[2] = (char *)"echo hi";
		rargv[3] = NULL;
		rc = ai_ws_zone_run("sb-zone1", rargv, 3, 10, 4096, NULL, 0,
				    NULL, &tail, &exit_code, &timed,
				    &cancelled, &trunc, &err);
		CHECK(rc == AI_OK && tail && exit_code == 0 && !timed &&
		      !cancelled, "有元数据：区内执行成功");
		CHECK(tail && strstr(tail, "MOCK_RUN_ARGS run sb-zone1") &&
		      strstr(tail, "--backing=tmpfs") &&
		      strstr(tail, "--cpus=1.00") &&
		      strstr(tail, "--mem-mb=1024") &&
		      strstr(tail, "--pids=256") &&
		      strstr(tail, "--net=host") &&
		      strstr(tail, "-- /bin/sh -c"),
		      "run 参数面按元数据下发（backing/限额/net/--）");
		free(tail);
		free(err);
		tail = NULL;
		err = NULL;

		/* 无元数据：保持 aik-sandbox 临时区语义（不加任何选项） */
		rc = ai_ws_zone_run("sb-eph", rargv, 3, 10, 4096, NULL, 0,
				    NULL, &tail, &exit_code, &timed,
				    &cancelled, &trunc, &err);
		CHECK(rc == AI_OK && tail &&
		      strstr(tail, "MOCK_RUN_ARGS run sb-eph -- /bin/sh") &&
		      strstr(tail, "--backing=") == NULL,
		      "无元数据：临时区语义不变（run <name> -- <cmd>）");
		free(tail);
		free(err);
	}

	/* ============ 4. 销毁：一条路径、幂等、零残留 ============ */
	{
		CHECK(ai_ws_zone_destroy("sb-zone1", &out) == AI_OK && out &&
		      strstr(out, "MOCK_DESTROY_OK sb-zone1"),
		      "焚区走 workspace 销毁路径（后端 destroy 被调用）");
		CHECK(out && strstr(out, "已清理"), "销毁文案给出清理结果");
		free(out);
		out = NULL;
		CHECK(!ws_residue(wsroot, "sb-zone1"),
		      "销毁后工作区根无 .meta/.img 残留");
		snprintf(path, sizeof(path), "%s/sb-zone1/.lock", sbroot);
		CHECK(!file_exists(path), "销毁后无 /sandbox 状态残留");

		CHECK(ai_ws_zone_destroy("sb-zone1", &out) == AI_OK && out,
		      "重复销毁幂等成功（无残留）");
		CHECK(out && strstr(out, "无残留"), "幂等销毁文案为无残留");
		free(out);
		out = NULL;

		/* 同一份状态用 workspace_destroy 也清得掉 = 单一真相 */
		CHECK(ai_ws_zone_create("sb-zone2", &out) == AI_OK,
		      "建第二个区");
		free(out);
		out = NULL;
		CHECK(ai_ws_destroy("sb-zone2", &out) == AI_OK && out &&
		      strstr(out, "已清理"), "workspace_destroy 清理 tmpfs 区");
		CHECK(!ws_residue(wsroot, "sb-zone2"),
		      "workspace_destroy 后零元数据残留");
		free(out);
		out = NULL;
	}

	/* ============ 5. 持久盘保护 ============ */
	{
		write_disk_meta(wsroot, "pdisk");
		CHECK(ai_ws_zone_create("pdisk", &out) == AI_ERR_API,
		      "同名 disk 工作区：sandbox_create 拒绝覆盖");
		free(out);
		out = NULL;
		CHECK(ai_ws_zone_destroy("pdisk", &out) == AI_ERR_API,
		      "同名 disk 工作区：sandbox_destroy 拒绝删除");
		free(out);
		out = NULL;
		snprintf(path, sizeof(path), "%s/pdisk.meta", wsroot);
		CHECK(file_exists(path), "拒绝后持久盘元数据仍在（未误删）");
		unlink(path);
	}

	/* 无元数据但有镜像：不覆盖、不吞用户数据 */
	{
		snprintf(path, sizeof(path), "%s/orphan.img", wsroot);
		write_file(path, "", 0);
		CHECK(ai_ws_zone_create("orphan", &out) == AI_ERR_STORAGE,
		      "无元数据镜像：sandbox_create 拒绝覆盖");
		free(out);
		out = NULL;
		CHECK(file_exists(path), "拒绝后孤儿镜像未被删除");
		unlink(path);
	}

	/* ============ 6. 33-64 字符历史区按原名回收 ============ */
	{
		char longname[41];
		char ws[64];

		memset(longname, 'c', 40);
		longname[40] = '\0';
		ai_ws_zone_name(longname, ws, sizeof(ws));
		snprintf(path, sizeof(path), "%s/%s", sbroot, longname);
		mkdir(sbroot, 0755);
		mkdir(path, 0755);
		CHECK(ai_ws_zone_destroy(longname, &out) == AI_OK && out &&
		      strstr(out, "MOCK_DESTROY_OK"),
		      "历史长区名销毁成功");
		{
			char want[128];

			snprintf(want, sizeof(want), "MOCK_DESTROY_OK %s",
				 longname);
			CHECK(out && strstr(out, want),
			      "历史长区名按原名交给后端回收（不因映射漏清）");
		}
		free(out);
		out = NULL;
		rmdir(path);
	}

	/* ============ 7. 统一状态视图 ============ */
	{
		CHECK(ai_ws_zone_create("sb-list", &out) == AI_OK,
		      "建列表用区");
		free(out);
		out = NULL;
		CHECK(ai_ws_zone_status(&out) == AI_OK && out &&
		      strstr(out, "MOCK_STATUS_LINE") &&
		      strstr(out, "sb-list") &&
		      strstr(out, "backing=tmpfs"),
		      "status = workspace 区表 + aik-sandbox 原文");
		free(out);
		out = NULL;
		CHECK(ai_ws_zone_destroy("sb-list", &out) == AI_OK,
		      "清理列表用区");
		free(out);
		out = NULL;
	}

	/* ============ 8. 统一采集：取消 SIGKILL 全组 ============ */
	{
		char slow[256];
		char *cargv[2];
		char *tail = NULL;
		volatile sig_atomic_t flag = 0;
		int exit_code = -1, timed = 0, cancelled = 0, trunc = 0;
		time_t t0, t1;

		snprintf(slow, sizeof(slow), "%s/slow-w82e", tmp);
		write_file(slow, "#!/bin/sh\necho SLOW_STARTED\nexec /bin/sleep 60\n",
			   1);
		cargv[0] = slow;
		cargv[1] = NULL;
		flag = 1;
		t0 = time(NULL);
		CHECK(ai_ws_spawn_capture(cargv, NULL, 0, 30, 4096, &flag,
					  &tail, &exit_code, &timed,
					  &cancelled, &trunc) == 0 &&
		      cancelled == 1, "取消标志 → 采集立即收回（cancelled=1）");
		t1 = time(NULL);
		CHECK(t1 - t0 < 5, "取消响应在 5 秒内（实测）");
		CHECK(!proc_alive_marker(slow), "取消后无残留进程");
		free(tail);
	}

	/* ============ 收尾：工作区根只剩零散状态之外的东西 ============ */
	{
		char cmd[512];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp);
		if (system(cmd) != 0)
			printf("warn: 清理临时目录失败 %s\n", tmp);
	}

	if (fails) {
		printf("test_workspace_backend: FAIL (%d/%d)\n", fails, checks);
		return 1;
	}
	printf("test_workspace_backend: ALL PASS (%d checks)\n", checks);
	return 0;
}

/* ------------------------------------------------------------------
 * --live：真机（root + 真 aik-sandbox）：双 backend 同跑
 *   tmpfs 由 sandbox_create / workspace_create(backing=tmpfs) 建，
 *   disk 由 workspace_create(backing=disk) 建，二者互不影响；
 *   销毁全部走 workspace_destroy，最后逐项扫残留。
 * ------------------------------------------------------------------ */
static int dir_p(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static int any_loop_refs(const char *image)
{
	DIR *d = opendir("/sys/block");
	struct dirent *e;
	int hit = 0;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		char p[512], buf[1024];
		FILE *fp;
		size_t n;

		if (strncmp(e->d_name, "loop", 4) != 0)
			continue;
		snprintf(p, sizeof(p), "/sys/block/%s/loop/backing_file",
			 e->d_name);
		fp = fopen(p, "r");
		if (!fp)
			continue;
		n = fread(buf, 1, sizeof(buf) - 1, fp);
		fclose(fp);
		buf[n] = '\0';
		if (strstr(buf, image))
			hit = 1;
	}
	closedir(d);
	return hit;
}

static int run_tool(const struct tool_registry *reg, const char *tool,
		    const char *args, char **out, int *ok)
{
	const struct ai_tool *t = tool_registry_find(reg, tool);
	int rc;

	*out = NULL;
	*ok = 0;
	if (!t) {
		*out = strdup("(工具缺失)");
		return AI_ERR_NOT_FOUND;
	}
	rc = tool_executor_run(t, args, out, ok);
	return rc;
}

static int run_live(void)
{
	struct tool_registry reg;
	char *err = NULL;
	char *out = NULL;
	int ok = 0;
	char zone[64], tmpws[64], disk[64];
	char p[512], args[512];
	char image[512];

	printf("== test_workspace_backend --live ==\n");
	if (geteuid() != 0) {
		printf("SKIP: --live 需要 root（真 namespace/loop/cgroup）\n");
		return 0;
	}
	snprintf(zone, sizeof(zone), "w82ezone%ld", (long)getpid());
	snprintf(tmpws, sizeof(tmpws), "w82etmp%ld", (long)getpid());
	snprintf(disk, sizeof(disk), "w82edisk%ld", (long)getpid());
	snprintf(image, sizeof(image), "/var/lib/aikernel/ws/%s.img", disk);

	/* 生产路径（不覆盖），真实 aik-sandbox 二进制 */
	unsetenv("AIKERNEL_WORKSPACE_ROOT");
	unsetenv("AIKERNEL_SANDBOX_BASE");
	unsetenv("AIKERNEL_SANDBOX_ARTIFACTS");
	unsetenv("AIKERNEL_SANDBOX_CGROUP_ROOT");
	if (!getenv("AIKERNEL_SANDBOX_BIN"))
		setenv("AIKERNEL_SANDBOX_BIN", "../aik-sandbox", 1);
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "LIVE 注册表加载（tools.json 226 件）");
	free(err);

	/* ---- 1. sandbox_create → tmpfs backend 建区 ---- */
	{
		char *discard = NULL;

		snprintf(args, sizeof(args), "{\"name\":\"%s\"}", zone);
		/* 先清掉可能的同名残留（幂等） */
		(void)ai_ws_zone_destroy(zone, &discard);
		free(discard);
		discard = NULL;
		CHECK(run_tool(&reg, "sandbox_create", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "backing=tmpfs"),
		      "LIVE-1 sandbox_create 建 tmpfs backend");
		free(out);
		out = NULL;
		snprintf(p, sizeof(p), "/var/lib/aikernel/ws/%s.meta", zone);
		{
			char *txt = read_all(p);

			CHECK(txt && strstr(txt, "backing=tmpfs"),
			      "LIVE-1 元数据落 workspace 根且 backing=tmpfs");
			free(txt);
		}
		snprintf(p, sizeof(p), "/sandbox/%s/root", zone);
		CHECK(dir_p(p), "LIVE-1 后端挂载点 /sandbox/<zone>/root 就绪");
		snprintf(p, sizeof(p), "/sys/fs/cgroup/aik-sandbox/%s", zone);
		CHECK(dir_p(p), "LIVE-1 cgroup 由统一路径创建");
	}

	/* ---- 2. 区内跑命令（workspace_run 面，真隔离根） ---- */
	{
		snprintf(args, sizeof(args),
			 "{\"name\":\"%s\",\"command\":\"id -u; "
			 "echo hi > /w82e.txt; cat /w82e.txt; "
			 "[ -e /var/lib/aikernel ] && echo LEAK || echo NOLEAK\"}",
			 zone);
		CHECK(run_tool(&reg, "workspace_run", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "\n0\n") &&
		      strstr(out, "hi") && strstr(out, "NOLEAK"),
		      "LIVE-2 tmpfs 区能跑命令（uid=0、可写根、宿主 /var 不可见）");
		free(out);
		out = NULL;
	}

	/* ---- 3. workspace_create backing=tmpfs 独立入口 ---- */
	{
		snprintf(args, sizeof(args),
			 "{\"name\":\"%s\",\"backing\":\"tmpfs\"}", tmpws);
		CHECK(run_tool(&reg, "workspace_create", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "backing=tmpfs"),
		      "LIVE-3 workspace_create backing=tmpfs 可建");
		free(out);
		out = NULL;
		snprintf(args, sizeof(args),
			 "{\"name\":\"%s\",\"command\":\"echo tmp-ok\"}", tmpws);
		CHECK(run_tool(&reg, "workspace_run", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "tmp-ok"),
		      "LIVE-3 tmpfs 工作区能跑命令");
		free(out);
		out = NULL;
	}

	/* ---- 4. disk backend：旧行为不变（跨调用持久） ---- */
	{
		snprintf(args, sizeof(args),
			 "{\"name\":\"%s\",\"size_mb\":64,\"backing\":\"disk\"}",
			 disk);
		CHECK(run_tool(&reg, "workspace_create", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "backing=disk"),
		      "LIVE-4 workspace_create backing=disk 建镜像");
		free(out);
		out = NULL;
		snprintf(args, sizeof(args),
			 "{\"name\":\"%s\",\"command\":\"echo disk-data > /persist.txt\"}",
			 disk);
		CHECK(run_tool(&reg, "workspace_run", args, &out, &ok) == AI_OK &&
		      ok, "LIVE-4 盘内写文件");
		free(out);
		out = NULL;
		snprintf(args, sizeof(args),
			 "{\"name\":\"%s\",\"command\":\"cat /persist.txt\"}",
			 disk);
		CHECK(run_tool(&reg, "workspace_run", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "disk-data"),
		      "LIVE-4 跨调用读回（disk 持久化行为不变）");
		free(out);
		out = NULL;
		/* 双 backend 同跑：disk 存在时 tmpfs 区仍可执行 */
		snprintf(args, sizeof(args),
			 "{\"name\":\"%s\",\"command\":\"echo both-ok\"}", zone);
		CHECK(run_tool(&reg, "workspace_run", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "both-ok"),
		      "LIVE-5 双 backend 同跑互不影响（disk + tmpfs）");
		free(out);
		out = NULL;
	}

	/* ---- 6. 销毁：全部走 workspace_destroy，零残留 ---- */
	{
		snprintf(args, sizeof(args), "{\"name\":\"%s\"}", disk);
		CHECK(run_tool(&reg, "workspace_destroy", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "已清理"),
		      "LIVE-6 disk 销毁");
		free(out);
		out = NULL;
		CHECK(!file_exists(image), "LIVE-6 disk 镜像已删");
		CHECK(!any_loop_refs(image), "LIVE-6 无 loop 残留");

		snprintf(args, sizeof(args), "{\"name\":\"%s\"}", tmpws);
		CHECK(run_tool(&reg, "workspace_destroy", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "已清理"),
		      "LIVE-6 tmpfs 工作区销毁");
		free(out);
		out = NULL;

		snprintf(args, sizeof(args), "{\"name\":\"%s\"}", zone);
		CHECK(run_tool(&reg, "sandbox_destroy", args, &out, &ok) == AI_OK &&
		      ok && out && strstr(out, "已清理"),
		      "LIVE-6 sandbox_destroy 委托同一条销毁路径");
		free(out);
		out = NULL;

		/* 残留扫描：mount / cgroup / /sandbox / 元数据 / 产物 / 进程 */
		snprintf(p, sizeof(p), "/var/lib/aikernel/ws/%s.meta", zone);
		CHECK(!file_exists(p), "LIVE-6 zone 元数据无残留");
		snprintf(p, sizeof(p), "/var/lib/aikernel/ws/%s.meta", tmpws);
		CHECK(!file_exists(p), "LIVE-6 tmpfs 工作区元数据无残留");
		snprintf(p, sizeof(p), "/var/lib/aikernel/ws/%s.meta", disk);
		CHECK(!file_exists(p), "LIVE-6 disk 元数据无残留");
		snprintf(p, sizeof(p), "/sandbox/%s", zone);
		CHECK(!dir_p(p), "LIVE-6 /sandbox 区目录无残留");
		snprintf(p, sizeof(p), "/sys/fs/cgroup/aik-sandbox/%s", zone);
		CHECK(!dir_p(p), "LIVE-6 cgroup 无残留");
		snprintf(p, sizeof(p), "/var/ai/sandbox-artifacts/%s", zone);
		CHECK(!dir_p(p), "LIVE-6 空产物目录已按 B-109 清理");
		{
			char tpath[128];

			snprintf(tpath, sizeof(tpath), "/sandbox/%s/.lock", zone);
			CHECK(!file_exists(tpath), "LIVE-6 区锁文件无残留");
		}
	}

	tool_registry_free(&reg);
	printf("SUMMARY(live): %d checks, %d failed\n", checks, fails);
	return fails ? 1 : 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--live") == 0)
		return run_live();
	return run_unit();
}
