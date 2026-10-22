// SPDX-License-Identifier: GPL-2.0
/*
 * test_clarify.c - W77c：结构化澄清（clarify 工具）回归
 *
 * 覆盖：参数解析/校验（2-4 选项、id 唯一、recommended/default、D3/D4）、
 * 多选与取消/Other、无效输入重试、非 TTY CLARIFY_REQUIRED JSON、max 2、
 * 不创建租约、歧义检测（服务缺 unit/破坏动作缺目标/唯一目标不提问）、
 * clarify_request/clarify_answer 轨迹事件。
 *
 * 全部本地完成：临时目录 + 真实 ai_trace/ai_lease（无网络/内核依赖）。
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

#include "ask_clarify.h"
#include "ai_trace.h"
#include "policy/ai_lease.h"

static int g_fail;
static int g_pass;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (cond)
		g_pass++;
	else
		g_fail++;
}

static int build_req(const char *json, struct ask_clarify_request *req,
		     char *err, size_t errlen)
{
	memset(req, 0, sizeof(*req));
	if (ask_clarify_parse_request(json, req, err, errlen) != 0)
		return -1;
	return ask_clarify_validate(req, err, errlen);
}

static const char *valid_json =
	"{\"question\":\"要对哪个服务执行重启？\","
	"\"header\":\"选择要重启的服务\","
	"\"options\":[{\"id\":\"1\",\"label\":\"nginx.service\","
	"\"why\":\"systemctl 显示该服务正在运行\"},"
	"{\"id\":\"2\",\"label\":\"sshd.service\"}],"
	"\"recommended\":\"1\"}";

static void test_parse_valid(void)
{
	struct ask_clarify_request req;
	char err[256];

	expect(build_req(valid_json, &req, err, sizeof(err)) == 0 &&
	       req.n_options == 2 &&
	       strcmp(req.question, "要对哪个服务执行重启？") == 0,
	       "合法参数解析（2 选项）");
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\"},"
			 "{\"id\":\"b\",\"label\":\"B\"},"
			 "{\"id\":\"c\",\"label\":\"C\"},"
			 "{\"id\":\"d\",\"label\":\"D\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) == 0,
	       "4 选项合法");
}

static void test_option_count(void)
{
	struct ask_clarify_request req;
	char err[256];

	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) != 0,
	       "少于 2 个选项被拒绝");
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\"},"
			 "{\"id\":\"b\",\"label\":\"B\"},"
			 "{\"id\":\"c\",\"label\":\"C\"},"
			 "{\"id\":\"d\",\"label\":\"D\"},"
			 "{\"id\":\"e\",\"label\":\"E\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) != 0,
	       "多于 4 个选项被拒绝");
}

static void test_duplicate_ids(void)
{
	struct ask_clarify_request req;
	char err[256];

	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\"},"
			 "{\"id\":\"a\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) != 0,
	       "重复 id 被拒绝");
}

static void test_multi_select(void)
{
	const char *j =
		"{\"question\":\"选哪些目标？\",\"multi_select\":true,"
		"\"options\":[{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\"},"
		"{\"id\":\"b\",\"label\":\"B\"},"
		"{\"id\":\"c\",\"label\":\"C\"}],"
		"\"recommended\":\"a\"}";
	struct ask_clarify_request req;
	struct ask_clarify_answer ans;
	char err[256];

	expect(build_req(j, &req, err, sizeof(err)) == 0, "多选请求合法");
	expect(ask_clarify_parse_answer("1, 3", &req, &ans) ==
	       ASK_CLARIFY_ANS_OK && ans.n_selected == 2 &&
	       ans.selected[0] == 0 && ans.selected[1] == 2,
	       "多选：逗号分隔序号");
	expect(ask_clarify_parse_answer("a b", &req, &ans) ==
	       ASK_CLARIFY_ANS_OK && ans.n_selected == 2,
	       "多选：空格分隔 id");
	expect(ask_clarify_parse_answer("1 1", &req, &ans) ==
	       ASK_CLARIFY_ANS_OK && ans.n_selected == 1,
	       "多选：重复选择去重");
	expect(ask_clarify_parse_answer("1 2 3 x", &req, &ans) ==
	       ASK_CLARIFY_ANS_INVALID,
	       "多选：任一非法 token 整行无效");
}

static void test_recommended_default(void)
{
	struct ask_clarify_request req;
	char err[256];

	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}]}", &req, err,
			 sizeof(err)) != 0,
	       "非 D3/D4 缺少 recommended 被拒绝");
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"z\"}", &req, err,
			 sizeof(err)) != 0,
	       "recommended 引用不存在的 id 被拒绝");
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\",\"default\":\"z\"}", &req,
			 err, sizeof(err)) != 0,
	       "default 引用不存在的 id 被拒绝");
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\",\"default\":\"b\"}", &req,
			 err, sizeof(err)) == 0,
	       "default 引用合法 id 通过");

	/* authorization D3/D4：允许省略 recommended，但禁止 default */
	expect(build_req("{\"question\":\"q\",\"kind\":\"authorization\","
			 "\"danger\":\"D3\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"},"
			 "{\"id\":\"b\",\"label\":\"B\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"}],"
			 "\"default\":\"a\"}", &req, err, sizeof(err)) != 0,
	       "authorization D3 带 default 被拒绝");
	expect(build_req("{\"question\":\"q\",\"kind\":\"authorization\","
			 "\"danger\":\"D3\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"},"
			 "{\"id\":\"b\",\"label\":\"B\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"}]}", &req, err,
			 sizeof(err)) == 0,
	       "authorization D3 可省略 recommended（无 default）");
	expect(build_req("{\"question\":\"q\",\"kind\":\"authorization\","
			 "\"danger\":\"D4\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\","
			 "\"impact\":\"影响\",\"rollback\":\"回滚\"},"
			 "{\"id\":\"b\",\"label\":\"B\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) == 0,
	       "authorization D4 可带 recommended（无 default）");
	expect(build_req("{\"question\":\"q\",\"kind\":\"authorization\","
			 "\"danger\":\"D4\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\","
			 "\"impact\":\"影响\",\"rollback\":\"回滚\"},"
			 "{\"id\":\"b\",\"label\":\"B\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"}],"
			 "\"recommended\":\"a\",\"default\":\"a\"}",
			 &req, err, sizeof(err)) != 0,
	       "authorization D4 带 default 被拒绝");
	expect(build_req("{\"kind\":\"authorization\",\"danger\":\"D2\","
			 "\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"danger\":\"D3\","
			 "\"impact\":\"x\",\"rollback\":\"y\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"b\",\"default\":\"a\"}", &req, err,
			 sizeof(err)) != 0,
	       "请求 D2 但选项 D3 仍禁止 default");
	expect(build_req("{\"question\":\"q\",\"kind\":\"authorization\","
			 "\"options\":[{\"id\":\"a\",\"label\":\"A\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) != 0,
	       "authorization 缺少 danger 被拒绝");
}

static void test_kinds_header(void)
{
	static const char *const kinds[] = {
		"intent", "scope", "strategy", "authorization", "recovery",
	};
	struct ask_clarify_request req;
	char err[256];
	char json[1024];
	int i;

	for (i = 0; i < 5; i++) {
		snprintf(json, sizeof(json),
			 "{\"question\":\"q\",\"kind\":\"%s\","
			 "\"danger\":\"D2\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\"}", kinds[i]);
		expect(build_req(json, &req, err, sizeof(err)) == 0 &&
		       strcmp(req.kind, kinds[i]) == 0,
		       "canonical kind 接受");
	}
	expect(build_req("{\"question\":\"q\",\"kind\":\"bogus\","
			 "\"options\":[{\"id\":\"a\",\"label\":\"A\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) != 0,
	       "未知 kind 被拒绝");
	expect(build_req("{\"question\":\"q\",\"kind\":\"choice\","
			 "\"options\":[{\"id\":\"a\",\"label\":\"A\","
			 "\"why\":\"证据\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) == 0 && strcmp(req.kind, "intent") == 0,
	       "旧 kind=choice 兼容映射为 intent");
	expect(build_req("{\"question\":\"q\",\"kind\":\"service\","
			 "\"options\":[{\"id\":\"a\",\"label\":\"A\","
			 "\"why\":\"证据\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) == 0 && strcmp(req.kind, "scope") == 0,
	       "旧 kind=service 兼容映射为 scope");

	expect(build_req(valid_json, &req, err, sizeof(err)) == 0 &&
	       strcmp(req.header, "选择要重启的服务") == 0,
	       "header 被解析");
}

static void test_option_decision_fields(void)
{
	struct ask_clarify_request req;
	char err[256];

	/* recommended 必须带 why */
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) != 0,
	       "recommended 缺少 why 被拒绝");
	/* 选项 D3/D4 必须有 impact + rollback */
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\","
			 "\"danger\":\"D3\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) != 0,
	       "选项 danger=D3 缺 impact/rollback 被拒绝");
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\","
			 "\"danger\":\"D3\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) == 0,
	       "选项 danger=D3 带 impact/rollback 通过");
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"why\":\"证据\"},"
			 "{\"id\":\"b\",\"label\":\"B\",\"danger\":\"D4\"}],"
			 "\"recommended\":\"a\"}", &req, err,
			 sizeof(err)) != 0,
	       "非推荐选项 danger=D4 缺 impact/rollback 被拒绝");
	/* 请求 danger 继承：authorization D3 所有选项都需要 impact/rollback */
	expect(build_req("{\"question\":\"q\",\"kind\":\"authorization\","
			 "\"danger\":\"D3\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\"},"
			 "{\"id\":\"b\",\"label\":\"B\"}]}", &req, err,
			 sizeof(err)) != 0,
	       "请求 danger=D3 继承后缺 impact/rollback 被拒绝");
	expect(build_req("{\"question\":\"q\",\"kind\":\"authorization\","
			 "\"danger\":\"D3\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"},"
			 "{\"id\":\"b\",\"label\":\"B\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"}]}", &req, err,
			 sizeof(err)) == 0,
	       "请求 danger=D3 继承后带 impact/rollback 通过");
	/* 显式选项 danger 覆盖请求 danger */
	expect(build_req("{\"question\":\"q\",\"kind\":\"authorization\","
			 "\"danger\":\"D3\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"danger\":\"D0\"},"
			 "{\"id\":\"b\",\"label\":\"B\",\"danger\":\"D1\"}]}",
			 &req, err, sizeof(err)) == 0,
	       "选项 danger=D0/D1 覆盖请求 D3（无需 impact/rollback）");

	/* 缺省 danger 在 JSON 中按请求 danger 继承输出 */
	expect(build_req("{\"question\":\"q\",\"kind\":\"authorization\","
			 "\"danger\":\"D3\",\"options\":["
			 "{\"id\":\"a\",\"label\":\"A\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"},"
			 "{\"id\":\"b\",\"label\":\"B\",\"impact\":\"影响\","
			 "\"rollback\":\"回滚\"}]}", &req, err,
			 sizeof(err)) == 0,
	       "继承 danger 的请求合法");
	{
		char *out = NULL;

		expect(ask_clarify_build_required_json(&req, "cq-test",
						       900000, &out) == 0 &&
		       out && strstr(out, "\"danger\":\"D3\"") != NULL &&
		       strstr(out, "\"impact\":\"影响\"") != NULL,
		       "选项缺省 danger 在 JSON 中继承请求 D3");
		free(out);
	}
}

static void test_cancel_other(void)
{
	struct ask_clarify_request req;
	struct ask_clarify_answer ans;
	char err[256];

	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	expect(ask_clarify_parse_answer("q", &req, &ans) ==
	       ASK_CLARIFY_ANS_CANCEL, "[q] 取消");
	expect(ask_clarify_parse_answer("取消", &req, &ans) ==
	       ASK_CLARIFY_ANS_CANCEL, "中文取消");
	expect(ask_clarify_parse_answer("o 清理缓存文件", &req, &ans) ==
	       ASK_CLARIFY_ANS_OTHER &&
	       strcmp(ans.text, "清理缓存文件") == 0,
	       "[o] Other 自由文本");
	expect(ask_clarify_parse_answer("o", &req, &ans) ==
	       ASK_CLARIFY_ANS_OTHER && ans.text[0] == '\0',
	       "[o] 单独输入等待自由文本");
}

static void test_invalid_reprompt(void)
{
	struct ask_clarify_request req;
	struct ask_clarify_answer ans;
	const char *bad[] = { "9", "x", "0" };
	const char *retry[] = { "9", "2" };
	const char *other[] = { "o", "/tmp/old.log" };
	char err[256];
	int attempts = 0;

	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	expect(ask_clarify_run_inputs(bad, 3, &req, &ans, &attempts) ==
	       ASK_CLARIFY_ANS_INVALID && attempts == 3,
	       "无效输入重试 3 次后放弃");
	expect(ask_clarify_run_inputs(retry, 2, &req, &ans, &attempts) ==
	       ASK_CLARIFY_ANS_OK && attempts == 2 &&
	       ans.n_selected == 1 && ans.selected[0] == 1,
	       "第 2 次输入有效（重试成功）");
	expect(ask_clarify_run_inputs(other, 2, &req, &ans, &attempts) ==
	       ASK_CLARIFY_ANS_OTHER &&
	       strcmp(ans.text, "/tmp/old.log") == 0,
	       "单独 [o] 后一行作为 Other 文本");
}

static void test_non_tty_json(void)
{
	struct ask_clarify_request req;
	struct ask_clarify_state st;
	char err[256];
	char *out = NULL;

	memset(&st, 0, sizeof(st));
	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	expect(ask_clarify_handle_tool_ex(valid_json, &st, 0, &out) == 0,
	       "非 TTY handle_tool 返回成功");
	expect(st.stop == 1 && st.stop_text != NULL,
	       "非 TTY 置 stop 并保留最终 JSON");
	expect(out && strstr(out, "\"status\":\"CLARIFY_REQUIRED\"") != NULL,
	       "非 TTY 返回 CLARIFY_REQUIRED");
	expect(out && strstr(out, "\"nonce\":\"cq-") != NULL,
	       "CLARIFY_REQUIRED 含 cq- 前缀 nonce");
	expect(out && strstr(out, "\"header\":\"选择要重启的服务\"") != NULL,
	       "CLARIFY_REQUIRED 含 header");
	expect(out && strstr(out, "\"why\":\"systemctl 显示该服务正在运行\"")
	       != NULL,
	       "CLARIFY_REQUIRED 含选项 why");
	expect(out && strstr(out, "\"expires_at\":") != NULL &&
	       strstr(out, "\"expires_at_ms\":") != NULL &&
	       strstr(out, "\"expires_at_iso\":\"") != NULL,
	       "CLARIFY_REQUIRED 含 expires_at/expires_at_ms/ISO");
	expect(out && strstr(out, "\"options\":[") != NULL &&
	       strstr(out, "\"recommended\":\"1\"") != NULL,
	       "CLARIFY_REQUIRED 含 options/recommended");
	expect(out && strstr(out, "\"tty\"") == NULL,
	       "用户 JSON 不暴露内部 tty 字段");
	expect(out && strstr(out, "\"resume_saved\":false") != NULL &&
	       strstr(out, "\"resume_error\"") != NULL,
	       "无 session 上下文时明确标记不可恢复");
	free(out);
	ask_clarify_state_free(&st);
}

static char *save_home(void)
{
	const char *h = getenv("HOME");

	return h ? strdup(h) : NULL;
}

static void restore_home(char *h)
{
	if (h)
		setenv("HOME", h, 1);
	else
		unsetenv("HOME");
	free(h);
}

static void cleanup_dir(const char *dir)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		printf("WARN: 临时目录清理失败: %s\n", dir);
}

/*
 * W77c-2b：tagged stderr event 恰好一行；tag 读取后从环境移除；
 * 同一 state 第二次非 TTY clarify 不再写事件；非法 tag fail closed。
 */
static void test_event_channel(void)
{
	char tmpl[] = "/tmp/w77c-event-XXXXXX";
	struct ask_clarify_state st;
	char buf[8192];
	char *out = NULL;
	const char *tag = "0123456789abcdef0123456789abcdef";
	int fd, saved_fd, n;
	int count = 0;
	char *p;

	fd = mkstemp(tmpl);
	if (fd < 0) {
		expect(0, "创建事件捕获临时文件");
		return;
	}
	saved_fd = dup(STDERR_FILENO);
	if (saved_fd < 0 || dup2(fd, STDERR_FILENO) < 0) {
		expect(0, "重定向 stderr");
		close(fd);
		if (saved_fd >= 0)
			close(saved_fd);
		unlink(tmpl);
		return;
	}
	close(fd);

	setenv("AIKERNEL_EVENT_TAG", tag, 1);
	expect(ask_clarify_event_tag_init() == 1, "合法 tag 初始化");
	expect(getenv("AIKERNEL_EVENT_TAG") == NULL,
	       "tag 读取后立即从环境移除");

	memset(&st, 0, sizeof(st));
	expect(ask_clarify_handle_tool_ex(valid_json, &st, 0, &out) == 0 &&
	       st.event_sent == 1, "非 TTY 首次发事件");
	free(out);
	out = NULL;
	expect(ask_clarify_handle_tool_ex(valid_json, &st, 0, &out) == 0,
	       "非 TTY 第二次仍可澄清");
	free(out);
	out = NULL;
	ask_clarify_state_free(&st);

	fflush(stderr);
	dup2(saved_fd, STDERR_FILENO);
	close(saved_fd);

	fd = open(tmpl, O_RDONLY);
	if (fd < 0) {
		expect(0, "读事件捕获文件");
		unlink(tmpl);
		return;
	}
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	unlink(tmpl);
	if (n < 0)
		n = 0;
	buf[n] = '\0';

	p = buf;
	while ((p = strstr(p, "AIKERNEL_EVENT ")) != NULL) {
		count++;
		p += strlen("AIKERNEL_EVENT ");
	}
	expect(count == 1, "每轮 ask 恰好一行 tagged event");
	expect(strstr(buf, "AIKERNEL_EVENT ") != NULL &&
	       strstr(buf, tag) != NULL &&
	       strstr(buf, "\"status\":\"CLARIFY_REQUIRED\"") != NULL,
	       "事件含 tag 与 CLARIFY_REQUIRED JSON");

	setenv("AIKERNEL_EVENT_TAG", "bad tag", 1);
	expect(ask_clarify_event_tag_init() == -1, "非法 tag fail closed");
	unsetenv("AIKERNEL_EVENT_TAG");
}

static void test_pending_roundtrip(void)
{
	char tmpl[] = "/tmp/w77c-pend-XXXXXX";
	char *home = mkdtemp(tmpl);
	char path[1024];
	struct ask_clarify_request req;
	struct ask_clarify_pending p;
	struct stat st;
	char err[256];
	char *old;
	const char *nonce = "cq-pendingtest01";
	long long expires;

	if (!home) {
		expect(0, "创建 pending 临时 HOME");
		return;
	}
	old = save_home();
	setenv("HOME", home, 1);
	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	expires = ai_trace_wall_ms() + 60000;
	expect(ask_clarify_pending_save(&req, nonce, expires, "sess-a",
					"重启服务", 1, err, sizeof(err)) == 0,
	       "pending 写入成功");
	snprintf(path, sizeof(path), "%s/.aikernel/clarify/pending", home);
	expect(stat(path, &st) == 0 && (st.st_mode & 0777) == 0700,
	       "pending 目录 0700");
	snprintf(path, sizeof(path), "%s/.aikernel/clarify/pending/%s.json",
		 home, nonce);
	expect(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600,
	       "pending 文件 0600");
	memset(&p, 0, sizeof(p));
	expect(ask_clarify_pending_load(nonce, "sess-a", &p, err,
					sizeof(err)) == 0 &&
	       strcmp(p.session, "sess-a") == 0 &&
	       strcmp(p.original_question, "重启服务") == 0 &&
	       strcmp(p.req.question, req.question) == 0 && p.asked == 1,
	       "pending 加载/校验通过");
	ask_clarify_pending_free(&p);
	memset(&p, 0, sizeof(p));
	expect(ask_clarify_pending_load(nonce, "sess-b", &p, err,
					sizeof(err)) != 0 &&
	       strstr(err, "session") != NULL,
	       "pending 错误 session 被拒绝");
	expect(ask_clarify_pending_consume(nonce, err, sizeof(err)) == 0,
	       "pending 原子消费成功");
	expect(ask_clarify_pending_load(nonce, NULL, &p, err,
					sizeof(err)) != 0,
	       "消费后 load 拒绝");
	expect(ask_clarify_pending_consume(nonce, err, sizeof(err)) != 0,
	       "重放 consume 失败");
	snprintf(path, sizeof(path), "%s/.aikernel/clarify/pending/%s.json",
		 home, nonce);
	expect(access(path, F_OK) != 0, "pending 已移除");
	snprintf(path, sizeof(path), "%s/.aikernel/clarify/consumed/%s.json",
		 home, nonce);
	expect(access(path, F_OK) == 0, "consumed 标记存在");
	restore_home(old);
	cleanup_dir(home);
}

static void test_pending_expiry(void)
{
	char tmpl[] = "/tmp/w77c-exp-XXXXXX";
	char *home = mkdtemp(tmpl);
	struct ask_clarify_request req;
	struct ask_clarify_pending p;
	char err[256];
	char *old;

	if (!home) {
		expect(0, "创建 expiry 临时 HOME");
		return;
	}
	old = save_home();
	setenv("HOME", home, 1);
	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	expect(ask_clarify_pending_save(&req, "cq-expired01",
					ai_trace_wall_ms() - 1000,
					"sess-a", "重启服务", 1, err,
					sizeof(err)) == 0,
	       "过期 pending 可写入");
	memset(&p, 0, sizeof(p));
	expect(ask_clarify_pending_load("cq-expired01", NULL, &p, err,
					sizeof(err)) != 0 &&
	       strstr(err, "过期") != NULL,
	       "过期 pending 被拒绝");
	expect(ask_clarify_pending_save(&req, "cq-future01",
					ai_trace_wall_ms() +
					ASK_CLARIFY_TTL_MS + 120000,
					"sess-a", "重启服务", 1, err,
					sizeof(err)) == 0,
	       "超长 TTL pending 可写入");
	expect(ask_clarify_pending_load("cq-future01", NULL, &p, err,
					sizeof(err)) != 0 &&
	       strstr(err, "TTL") != NULL,
	       "超出 15 分钟 TTL 的记录被拒绝");
	restore_home(old);
	cleanup_dir(home);
}

static void test_pending_visibility(void)
{
	char tmpl[] = "/tmp/w77c-vis-XXXXXX";
	char *home = mkdtemp(tmpl);
	struct ask_clarify_state st;
	char *out = NULL;
	char err[256];
	char *old;
	char path[1024];

	if (!home) {
		expect(0, "创建 visibility 临时 HOME");
		return;
	}
	old = save_home();
	setenv("HOME", home, 1);
	memset(&st, 0, sizeof(st));
	ask_clarify_state_set_context(&st, "sess-a", "重启服务");
	expect(ask_clarify_handle_tool_ex(valid_json, &st, 0, &out) == 0 &&
	       out && strstr(out, "\"resume_saved\":true") != NULL &&
	       strstr(out, "\"resume_hint\"") != NULL,
	       "pending 写入成功在 JSON 中可见");
	free(out);
	out = NULL;
	ask_clarify_state_free(&st);
	snprintf(path, sizeof(path), "%s/.aikernel/clarify/pending",
		 home);
	expect(access(path, F_OK) == 0, "非 TTY handler 落盘 pending");

	setenv("HOME", "/proc", 1);
	memset(&st, 0, sizeof(st));
	ask_clarify_state_set_context(&st, "sess-a", "重启服务");
	expect(ask_clarify_handle_tool_ex(valid_json, &st, 0, &out) == 0 &&
	       out && strstr(out, "\"resume_saved\":false") != NULL &&
	       strstr(out, "\"resume_error\"") != NULL,
	       "pending 写失败在 JSON 中显式可见");
	free(out);
	ask_clarify_state_free(&st);
	(void)err;
	restore_home(old);
	cleanup_dir(home);
}

static void test_resolve_selection(void)
{
	const char *multi_json =
		"{\"question\":\"选哪些目标？\",\"multi_select\":true,"
		"\"options\":[{\"id\":\"a\",\"label\":\"A\","
		"\"why\":\"证据\"},{\"id\":\"b\",\"label\":\"B\"},"
		"{\"id\":\"c\",\"label\":\"C\"}],"
		"\"recommended\":\"a\"}";
	struct ask_clarify_request req;
	char out[ASK_CLARIFY_RESUMED_MAX];
	char err[256];

	expect(build_req(multi_json, &req, err, sizeof(err)) == 0,
	       "multi req 就绪");
	expect(ask_clarify_resolve_selection(&req, "a b", NULL, out,
					     sizeof(out), err,
					     sizeof(err)) == 0 &&
	       strcmp(out, "A, B") == 0,
	       "多选 id 解析");
	expect(ask_clarify_resolve_selection(&req, "1", NULL, out,
					     sizeof(out), err,
					     sizeof(err)) == 0 &&
	       strcmp(out, "A") == 0,
	       "序号解析（推荐项置顶）");
	expect(ask_clarify_resolve_selection(&req, NULL, "自定义目标", out,
					     sizeof(out), err,
					     sizeof(err)) == 0 &&
	       strcmp(out, "[Other] 自定义目标") == 0,
	       "Other 解析");
	expect(ask_clarify_resolve_selection(&req, "a", "补充", out,
					     sizeof(out), err,
					     sizeof(err)) == 0 &&
	       strcmp(out, "A, [Other] 补充") == 0,
	       "选择+Other 解析");
	expect(ask_clarify_resolve_selection(&req, "z", NULL, out,
					     sizeof(out), err,
					     sizeof(err)) != 0,
	       "未知 id 被拒绝");
	expect(ask_clarify_resolve_selection(&req, NULL, NULL, out,
					     sizeof(out), err,
					     sizeof(err)) != 0,
	       "空选择被拒绝");
	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "single req");
	expect(ask_clarify_resolve_selection(&req, "1 2", NULL, out,
					     sizeof(out), err,
					     sizeof(err)) != 0,
	       "单选多值被拒绝");

	/* 数字既是选项 id 时优先按 id，而不是菜单序号 */
	expect(build_req("{\"question\":\"q\",\"options\":["
			 "{\"id\":\"1\",\"label\":\"one\"},"
			 "{\"id\":\"2\",\"label\":\"two\",\"why\":\"证据\"}],"
			 "\"recommended\":\"2\"}", &req, err,
			 sizeof(err)) == 0,
	       "数字 id req 就绪");
	expect(ask_clarify_resolve_selection(&req, "1", NULL, out,
					     sizeof(out), err,
					     sizeof(err)) == 0 &&
	       strcmp(out, "one") == 0,
	       "数字 id 优先于菜单序号");
}

static void test_tty_timeout(void)
{
	struct ask_clarify_request req;
	struct ask_clarify_answer ans;
	struct ask_clarify_input t1[] = { { NULL, 1 } };
	struct ask_clarify_input t2[] = { { "9", 0 }, { NULL, 1 } };
	struct ask_clarify_input t3[] = { { "o", 0 }, { NULL, 1 } };
	char err[256];
	int attempts = 0;
	int timed = 0;

	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	expect(ask_clarify_run_events(t1, 1, &req, &ans, &attempts, &timed) ==
	       ASK_CLARIFY_ANS_CANCEL && timed && ans.timed_out &&
	       ans.n_selected == 0,
	       "TTY 超时=取消且不自动选择");
	expect(ask_clarify_run_events(t2, 2, &req, &ans, &attempts, &timed) ==
	       ASK_CLARIFY_ANS_CANCEL && timed && attempts == 2,
	       "无效输入后超时：按取消处理");
	expect(ask_clarify_run_events(t3, 2, &req, &ans, &attempts, &timed) ==
	       ASK_CLARIFY_ANS_CANCEL && timed,
	       "Other 行超时：按取消处理");
}

static void test_suppress_peers(void)
{
	int tty;

	for (tty = 0; tty <= 1; tty++) {
		expect(ask_clarify_suppress_peer(1, "exec_run", tty) == 1,
		       "同轮 clarify 抑制其他工具");
		expect(ask_clarify_suppress_peer(1, "clarify", tty) == 0,
		       "clarify 自身不被抑制");
		expect(ask_clarify_suppress_peer(0, "exec_run", tty) == 0,
		       "无 clarify 时不抑制");
	}
}

static void test_timeout_json(void)
{
	struct ask_clarify_request req;
	struct ask_clarify_answer ans;
	char err[256];
	char *out = NULL;

	memset(&ans, 0, sizeof(ans));
	ans.timed_out = 1;
	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	expect(ask_clarify_build_answer_json(&req, "cq-test", &ans,
					    "CLARIFY_CANCELLED", 1,
					    &out) == 0 &&
	       out && strstr(out, "\"timed_out\":true") != NULL &&
	       strstr(out, "\"reason\":\"timeout\"") != NULL,
	       "超时答案 JSON 标记 timed_out/reason");
	free(out);
}

static int dir_file_count(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	int n = 0;

	if (!d)
		return -1;
	while ((de = readdir(d))) {
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
			n++;
	}
	closedir(d);
	return n;
}

static char *read_file(const char *path)
{
	FILE *fp = fopen(path, "rb");
	char *buf;
	long sz;

	if (!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	rewind(fp);
	if (sz < 0 || sz > 4 * 1024 * 1024) {
		fclose(fp);
		return NULL;
	}
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
		free(buf);
		fclose(fp);
		return NULL;
	}
	buf[sz] = '\0';
	fclose(fp);
	return buf;
}

static void test_no_lease(void)
{
	char tmpl[] = "/tmp/w77c-lease-XXXXXX";
	char *dir = mkdtemp(tmpl);
	struct ask_clarify_state st;
	char *out = NULL;
	char cmd[512];

	if (!dir) {
		expect(0, "创建租约临时目录");
		return;
	}
	setenv("AIKERNEL_LEASE_DIR", dir, 1);
	setenv("AIKERNEL_CONFIRM_DIR", dir, 1);
	memset(&st, 0, sizeof(st));
	ai_lease_last_reset();
	expect(ask_clarify_handle_tool_ex(valid_json, &st, 0, &out) == 0,
	       "澄清执行成功（租约测试）");
	expect(ai_lease_last_lease_id() == NULL ||
	       ai_lease_last_lease_id()[0] == '\0',
	       "澄清未产生租约（last_lease 为空）");
	expect(dir_file_count(dir) == 0, "租约目录无新文件");
	free(out);
	ask_clarify_state_free(&st);
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		printf("WARN: 临时目录清理失败: %s\n", dir);
}

static void test_max_two(void)
{
	struct ask_clarify_state st;
	char *out = NULL;

	ask_clarify_answered_reset();
	memset(&st, 0, sizeof(st));
	expect(ask_clarify_state_begin(&st) == 1 &&
	       ask_clarify_state_begin(&st) == 1 &&
	       ask_clarify_state_begin(&st) == 0 &&
	       st.asked == 2,
	       "单次 ask 最多 2 个澄清问题");
	expect(ask_clarify_budget_exhausted(&st) == 1,
	       "到限后链级预算判定为耗尽");
	expect(ask_clarify_handle_tool_ex(valid_json, &st, 0, &out) == 0 &&
	       out && strstr(out, "已达提问上限") != NULL &&
	       strstr(out, "声明假设") != NULL && st.stop == 0,
	       "第 3 次 clarify 返回预算注记（按最佳理解执行，不终止本轮）");
	free(out);
	ask_clarify_state_free(&st);
}

static void test_detector_service(void)
{
	static const char *const svc3[] = {
		"nginx.service", "sshd.service", "cron.service",
	};
	static const char *const svc1[] = { "nginx.service" };
	struct ask_clarify_evidence ev;
	struct ask_clarify_request req;
	char err[256];

	memset(&ev, 0, sizeof(ev));
	ev.services = svc3;
	ev.n_services = 3;
	expect(ask_clarify_detect("帮我重启服务", &ev, &req, err,
				  sizeof(err)) == 1 &&
	       strcmp(req.kind, "scope") == 0 &&
	       strstr(req.header, "选择要") != NULL &&
	       req.n_options == 3 && strcmp(req.recommended, "1") == 0 &&
	       req.options[0].why[0] &&
	       ask_clarify_validate(&req, err, sizeof(err)) == 0,
	       "服务动作缺 unit：kind=scope + header + 候选 why 并提问");
	expect(ask_clarify_detect("重启 nginx.service", &ev, &req, err,
				  sizeof(err)) == 0,
	       "服务动作带明确 unit：不提问");
	expect(ask_clarify_detect("系统启动时间是多少", &ev, &req, err,
				  sizeof(err)) == 0,
	       "名词语境（启动时间）：不提问");

	memset(&ev, 0, sizeof(ev));
	ev.services = svc1;
	ev.n_services = 1;
	expect(ask_clarify_detect("重启服务", &ev, &req, err,
				  sizeof(err)) == 0,
	       "只有一个运行中服务：不提问");
}

static void test_detector_destructive(void)
{
	static const char *const tmp_paths[] = { "/tmp/a.log" };
	struct ask_clarify_evidence ev;
	struct ask_clarify_request req;
	char err[256];

	memset(&ev, 0, sizeof(ev));
	ev.tmp_paths = tmp_paths;
	ev.n_tmp_paths = 1;
	ev.tmp_exists = 1;
	ev.root_exists = 1;
	expect(ask_clarify_detect("删除文件", &ev, &req, err,
				  sizeof(err)) == 1 &&
	       req.n_options >= 2 && strcmp(req.kind, "scope") == 0 &&
	       strcmp(req.header, "选择删除目标") == 0 &&
	       req.options[0].why[0] &&
	       ask_clarify_validate(&req, err, sizeof(err)) == 0,
	       "破坏动作缺目标：kind=scope + header + 证据 why 并提问");
	expect(ask_clarify_detect("删除 /tmp/a.log", &ev, &req, err,
				  sizeof(err)) == 0,
	       "破坏动作带明确路径：不提问");

	memset(&ev, 0, sizeof(ev));
	ev.tmp_exists = 1;
	expect(ask_clarify_detect("删除文件", &ev, &req, err,
				  sizeof(err)) == 0,
	       "只有一个安全根候选：不提问");
}

static void test_trace_events(void)
{
	char tmpl[] = "/tmp/w77c-trace-XXXXXX";
	char *dir = mkdtemp(tmpl);
	struct ask_clarify_state st;
	char *out = NULL;
	char cmd[512];
	int found_req = 0;
	int found_ans = 0;
	DIR *d;
	struct dirent *de;

	if (!dir) {
		expect(0, "创建轨迹临时目录");
		return;
	}
	setenv("AIKERNEL_TRACE_DIR", dir, 1);
	setenv("AIKERNEL_TRACE_ENABLED", "1", 1);
	setenv("AIKERNEL_TRACE_INCLUDE_TEXT", "1", 1);
	ai_trace_init(NULL, 0);
	memset(&st, 0, sizeof(st));
	ask_clarify_handle_tool_ex(valid_json, &st, 0, &out);
	ai_trace_shutdown();
	free(out);
	ask_clarify_state_free(&st);

	d = opendir(dir);
	if (d) {
		while ((de = readdir(d))) {
			char path[1024];
			char *txt;

			if (strstr(de->d_name, ".jsonl") == NULL)
				continue;
			snprintf(path, sizeof(path), "%s/%s", dir,
				 de->d_name);
			txt = read_file(path);
			if (!txt)
				continue;
			if (strstr(txt, "\"event\":\"clarify_request\""))
				found_req = 1;
			if (strstr(txt, "\"event\":\"clarify_answer\""))
				found_ans = 1;
			free(txt);
		}
		closedir(d);
	}
	expect(found_req, "轨迹含 clarify_request");
	expect(found_ans, "轨迹含 clarify_answer");
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		printf("WARN: 临时目录清理失败: %s\n", dir);
}

/* ---- W77e：detector 2.0 评分制 / 去重记忆 / 链级预算 / 自动默认 ---- */

static void test_threshold_env(void)
{
	expect(ask_clarify_threshold() == 5, "阈值默认 5（未设环境变量）");
	setenv("AIKERNEL_CLARIFY_THRESHOLD", "0", 1);
	expect(ask_clarify_threshold() == 0, "AIKERNEL_CLARIFY_THRESHOLD=0 关");
	setenv("AIKERNEL_CLARIFY_THRESHOLD", "9", 1);
	expect(ask_clarify_threshold() == 9, "AIKERNEL_CLARIFY_THRESHOLD=9 生效");
	setenv("AIKERNEL_CLARIFY_THRESHOLD", "-3", 1);
	expect(ask_clarify_threshold() == 5, "负数回落默认 5");
	setenv("AIKERNEL_CLARIFY_THRESHOLD", "abc", 1);
	expect(ask_clarify_threshold() == 5, "非法值回落默认 5");
	unsetenv("AIKERNEL_CLARIFY_THRESHOLD");
}

static void test_score_signals(void)
{
	static const char *const svc3[] = {
		"nginx.service", "sshd.service", "cron.service",
	};
	static const char *const svc4[] = {
		"a.service", "b.service", "c.service", "d.service",
		"e.service",
	};
	static const char *const tmp2[] = { "/tmp/a", "/tmp/b" };
	static const char *const ents2[] = { "nginx.service", "sshd.service" };
	static const char *const ents1[] = { "nginx.service" };
	struct ask_clarify_evidence ev;
	struct ask_clarify_score sc;

	memset(&ev, 0, sizeof(ev));
	expect(ask_clarify_score_signals("帮我重启服务", &ev, &sc) == 0 &&
	       sc.verb_no_target == 3 && sc.candidates == 0 &&
	       sc.total == 3,
	       "信号：动作动词无目标 +3（无候选不再加分）");

	ev.services = svc3;
	ev.n_services = 3;
	expect(ask_clarify_score_signals("帮我重启服务", &ev, &sc) == 0 &&
	       sc.candidates == 3 && sc.total == 6,
	       "信号：证据候选 3 个 +3");

	ev.services = svc4;
	ev.n_services = 5;
	expect(ask_clarify_score_signals("帮我重启服务", &ev, &sc) == 0 &&
	       sc.candidates == 4 && sc.total == 7,
	       "信号：候选封顶 +4（5 个候选仍 +4）");

	memset(&ev, 0, sizeof(ev));
	expect(ask_clarify_score_signals("删除文件", &ev, &sc) == 0 &&
	       sc.verb_no_target == 4 && sc.total == 4,
	       "信号：破坏性动词无目标 +4（无候选）");
	ev.tmp_paths = tmp2;
	ev.n_tmp_paths = 2;
	ev.tmp_exists = 1;
	ev.root_exists = 1;
	ev.var_ai_exists = 1;
	expect(ask_clarify_score_signals("删除文件", &ev, &sc) == 0 &&
	       sc.verb_no_target == 4 && sc.candidates == 4 &&
	       sc.total == 8,
	       "信号：破坏候选 5 个封顶 +4");

	memset(&ev, 0, sizeof(ev));
	ev.ctx_entities = ents2;
	ev.n_ctx_entities = 2;
	expect(ask_clarify_score_signals("重启它", &ev, &sc) == 0 &&
	       sc.verb_no_target == 3 && sc.pronoun_entities == 3 &&
	       sc.total == 6,
	       "信号：代词指代且上文实体>1 +3");
	ev.ctx_entities = ents1;
	ev.n_ctx_entities = 1;
	expect(ask_clarify_score_signals("重启它", &ev, &sc) == 0 &&
	       sc.pronoun_entities == 0 && sc.total == 3,
	       "信号：单实体时代词不加分");

	memset(&ev, 0, sizeof(ev));
	expect(ask_clarify_score_signals("帮我发送", &ev, &sc) == 0 &&
	       sc.missing_param == 2 && sc.total == 2,
	       "信号：发送缺目的地 +2");
	expect(ask_clarify_score_signals("发送到 /tmp/x", &ev, &sc) == 0 &&
	       sc.missing_param == 0,
	       "有目的地（/ 路径）不加分");
	expect(ask_clarify_score_signals("帮我改配置", &ev, &sc) == 0 &&
	       sc.missing_param == 2,
	       "信号：改配置无对象 +2");
	expect(ask_clarify_score_signals("改配置 /etc/app.conf", &ev,
					 &sc) == 0 &&
	       sc.missing_param == 0,
	       "改配置带路径不加分");

	memset(&ev, 0, sizeof(ev));
	ev.conflict = 1;
	expect(ask_clarify_score_signals("查看状态", &ev, &sc) == 0 &&
	       sc.conflict == 3 && sc.total == 3,
	       "信号：证据冲突 +3");
}

static void test_detector_scoring(void)
{
	static const char *const svc2[] = {
		"nginx.service", "sshd.service",
	};
	static const char *const svc3[] = {
		"nginx.service", "sshd.service", "cron.service",
	};
	static const char *const ents2[] = { "nginx.service", "sshd.service" };
	static const char *const ents1[] = { "nginx.service" };
	struct ask_clarify_evidence ev;
	struct ask_clarify_request req;
	char err[256];

	memset(&ev, 0, sizeof(ev));
	ev.services = svc2;
	ev.n_services = 2;
	expect(ask_clarify_detect("重启服务", &ev, &req, err,
				  sizeof(err)) == 1,
	       "评分边界：总分=阈值(5) 触发（动词3+候选2）");
	setenv("AIKERNEL_CLARIFY_THRESHOLD", "6", 1);
	expect(ask_clarify_detect("重启服务", &ev, &req, err,
				  sizeof(err)) == 0,
	       "评分边界：总分 5 < 阈值 6 不触发");
	setenv("AIKERNEL_CLARIFY_THRESHOLD", "0", 1);
	memset(&ev, 0, sizeof(ev));
	ev.services = svc3;
	ev.n_services = 3;
	expect(ask_clarify_detect("重启服务", &ev, &req, err,
				  sizeof(err)) == 0,
	       "AIKERNEL_CLARIFY_THRESHOLD=0 关闭检测器");
	unsetenv("AIKERNEL_CLARIFY_THRESHOLD");

	/* 代词 + 多实体触发（通用指代澄清）；单实体不触发 */
	memset(&ev, 0, sizeof(ev));
	ev.ctx_entities = ents2;
	ev.n_ctx_entities = 2;
	expect(ask_clarify_detect("重启它", &ev, &req, err,
				  sizeof(err)) == 1 &&
	       strcmp(req.kind, "scope") == 0 && req.n_options == 2 &&
	       strcmp(req.options[0].label, "nginx.service") == 0 &&
	       strcmp(req.options[1].label, "sshd.service") == 0 &&
	       ask_clarify_validate(&req, err, sizeof(err)) == 0,
	       "代词+多实体：通用指代澄清（候选=会话实体）");
	ev.ctx_entities = ents1;
	ev.n_ctx_entities = 1;
	expect(ask_clarify_detect("重启它", &ev, &req, err,
				  sizeof(err)) == 0,
	       "代词+单实体：评分不足不提问");

	/* 缺参模式：单独 2 分不足；叠加证据冲突达阈值走通用澄清 */
	memset(&ev, 0, sizeof(ev));
	expect(ask_clarify_detect("帮我发送", &ev, &req, err,
				  sizeof(err)) == 0,
	       "缺参 2 分单独不触发");
	ev.ctx_entities = ents2;
	ev.n_ctx_entities = 2;
	ev.conflict = 1;
	expect(ask_clarify_detect("帮我发送", &ev, &req, err,
				  sizeof(err)) == 1 &&
	       req.n_options == 2,
	       "缺参 2 + 冲突 3 = 5 达阈值触发");
}

static void test_fingerprint(void)
{
	struct ask_clarify_request a, b;
	char err[256];

	expect(build_req(valid_json, &a, err, sizeof(err)) == 0, "req 就绪");
	expect(build_req("{\"question\":\"要对哪个服务执行重启 ？\","
			 "\"options\":[{\"id\":\"1\","
			 "\"label\":\"nginx.service\","
			 "\"why\":\"x\"},{\"id\":\"2\","
			 "\"label\":\"sshd.service\"}],"
			 "\"recommended\":\"1\"}", &b, err,
			 sizeof(err)) == 0,
	       "空白差异 req 就绪");
	expect(ask_clarify_fingerprint(&a) == ask_clarify_fingerprint(&b),
	       "指纹：空白差异同指纹");
	expect(build_req("{\"question\":\"要对哪个服务执行重启？\","
			 "\"kind\":\"scope\","
			 "\"options\":[{\"id\":\"1\","
			 "\"label\":\"nginx.service\",\"why\":\"x\"},"
			 "{\"id\":\"2\",\"label\":\"sshd.service\"}],"
			 "\"recommended\":\"1\"}", &b, err,
			 sizeof(err)) == 0,
	       "kind 差异 req 就绪");
	expect(ask_clarify_fingerprint(&a) != ask_clarify_fingerprint(&b),
	       "指纹：kind 不同则不同");
	expect(build_req("{\"question\":\"要对哪个服务执行重启？\","
			 "\"options\":[{\"id\":\"a\","
			 "\"label\":\"nginx.service\",\"why\":\"x\"},"
			 "{\"id\":\"b\",\"label\":\"sshd.service\"}],"
			 "\"recommended\":\"a\"}", &b, err,
			 sizeof(err)) == 0,
	       "选项 id 差异 req 就绪");
	expect(ask_clarify_fingerprint(&a) != ask_clarify_fingerprint(&b),
	       "指纹：选项 id 不同则不同");
	{
		char n1[64], n2[64];

		ask_clarify_normalize_question("  Restart NGINX\tService\n",
					       n1, sizeof(n1));
		ask_clarify_normalize_question("restart nginx service", n2,
					       sizeof(n2));
		expect(strcmp(n1, n2) == 0,
		       "归一化：大小写+空白一致");
	}
}

static void test_answered_memory(void)
{
	char tmpl[] = "/tmp/w77e-ans-XXXXXX";
	char *home = mkdtemp(tmpl);
	struct ask_clarify_request req;
	struct ask_clarify_answer ans;
	struct stat st;
	char path[1024];
	char label[ASK_CLARIFY_LABEL_MAX + 1];
	char err[256];
	char *old;

	if (!home) {
		expect(0, "创建 answered 临时 HOME");
		return;
	}
	old = save_home();
	setenv("HOME", home, 1);
	ask_clarify_answered_reset();
	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	memset(&ans, 0, sizeof(ans));
	ans.selected[0] = 0;
	ans.n_selected = 1;
	ask_clarify_note_answered(NULL, &req, &ans);
	snprintf(path, sizeof(path),
		 "%s/.aikernel/clarify/answered.jsonl", home);
	expect(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600,
	       "answered.jsonl 落盘且 0600");
	/* 清缓存后跨"会话"（重新载入文件）仍命中 */
	ask_clarify_answered_reset();
	expect(ask_clarify_already_answered(NULL, &req, label,
					    sizeof(label)) == 1 &&
	       strcmp(label, "nginx.service") == 0,
	       "跨会话：answered.jsonl 命中并回带 label");
	expect(build_req("{\"question\":\"另一个问题？\","
			 "\"options\":[{\"id\":\"1\",\"label\":\"A\","
			 "\"why\":\"x\"},{\"id\":\"2\",\"label\":\"B\"}],"
			 "\"recommended\":\"1\"}", &req, err,
		 sizeof(err)) == 0,
	       "不同问题 req 就绪");
	expect(ask_clarify_already_answered(NULL, &req, label,
					    sizeof(label)) == 0,
	       "不同问题不命中");
	ask_clarify_answered_reset();
	restore_home(old);
	cleanup_dir(home);
}

static void test_chain_dedup(void)
{
	char tmpl[] = "/tmp/w77e-dedup-XXXXXX";
	char *home = mkdtemp(tmpl);
	struct ask_clarify_request req, req2;
	struct ask_clarify_answer ans;
	struct ask_clarify_state st;
	char label[ASK_CLARIFY_LABEL_MAX + 1];
	char err[256];
	char *old;

	if (!home) {
		expect(0, "创建链内去重临时 HOME");
		return;
	}
	old = save_home();
	setenv("HOME", home, 1);
	ask_clarify_answered_reset();
	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	expect(build_req(valid_json, &req2, err, sizeof(err)) == 0,
	       "同指纹 req 就绪");
	memset(&ans, 0, sizeof(ans));
	ans.selected[0] = 1;
	ans.n_selected = 1;
	memset(&st, 0, sizeof(st));
	ask_clarify_note_answered(&st, &req, &ans);
	expect(st.asked_label[0][0] != '\0', "链内记忆写入 state");
	expect(ask_clarify_already_answered(&st, &req2, label,
					    sizeof(label)) == 1 &&
	       strcmp(label, "sshd.service") == 0,
	       "链内去重：同指纹命中回带选择");
	expect(build_req("{\"question\":\"换一个问题？\","
			 "\"options\":[{\"id\":\"1\",\"label\":\"A\","
			 "\"why\":\"x\"},{\"id\":\"2\",\"label\":\"B\"}],"
			 "\"recommended\":\"1\"}", &req2, err,
		 sizeof(err)) == 0,
	       "不同问题 req 就绪");
	expect(ask_clarify_already_answered(&st, &req2, label,
					    sizeof(label)) == 0,
	       "链内不同指纹不命中");
	ask_clarify_state_free(&st);
	ask_clarify_answered_reset();
	restore_home(old);
	cleanup_dir(home);
}

static void test_dedup_injection(void)
{
	char tmpl[] = "/tmp/w77e-inject-XXXXXX";
	char *home = mkdtemp(tmpl);
	struct ask_clarify_state st;
	char *out = NULL;
	char *old;

	if (!home) {
		expect(0, "创建注入临时 HOME");
		return;
	}
	old = save_home();
	setenv("HOME", home, 1);
	ask_clarify_answered_reset();
	/* 预置答案记忆：同指纹 clarify 不再问，注入旧选择 */
	{
		struct ask_clarify_request req;
		struct ask_clarify_answer ans;
		char err[256];

		memset(&ans, 0, sizeof(ans));
		ans.selected[0] = 0;
		ans.n_selected = 1;
		if (build_req(valid_json, &req, err, sizeof(err)) == 0)
			ask_clarify_note_answered(NULL, &req, &ans);
	}
	memset(&st, 0, sizeof(st));
	expect(ask_clarify_handle_tool_ex(valid_json, &st, 0, &out) == 0 &&
	       out && strstr(out, "已按你此前的选择") != NULL &&
	       strstr(out, "nginx.service") != NULL &&
	       st.asked == 0 && st.stop == 0,
	       "已答不再问：注入旧选择且不占预算/不终止");
	free(out);
	ask_clarify_state_free(&st);
	ask_clarify_answered_reset();
	restore_home(old);
	cleanup_dir(home);
}

static void test_auto_default_eligible(void)
{
	struct ask_clarify_request req;
	char err[256];

	expect(build_req(valid_json, &req, err, sizeof(err)) == 0 &&
	       ask_clarify_auto_default_eligible(&req) == 1,
	       "自动默认资格：scope+recommended 可自动");
	memset(&req, 0, sizeof(req));
	strcpy(req.kind, "authorization");
	req.has_recommended = 1;
	strcpy(req.recommended, "1");
	expect(ask_clarify_auto_default_eligible(&req) == 0,
	       "自动默认资格：authorization 永不自动");
	memset(&req, 0, sizeof(req));
	strcpy(req.kind, "scope");
	req.has_default = 1;
	strcpy(req.default_id, "b");
	expect(ask_clarify_auto_default_eligible(&req) == 1,
	       "自动默认资格：仅 default 也可自动");
	memset(&req, 0, sizeof(req));
	strcpy(req.kind, "scope");
	expect(ask_clarify_auto_default_eligible(&req) == 0,
	       "自动默认资格：无 recommended/default 不自动");
}

static void test_auto_default_flow(void)
{
	char tmpl[] = "/tmp/w77e-auto-XXXXXX";
	char *home = mkdtemp(tmpl);
	static const char *auth_json =
		"{\"question\":\"确认执行危险操作？\","
		"\"kind\":\"authorization\",\"danger\":\"D3\","
		"\"options\":[{\"id\":\"a\",\"label\":\"确认\","
		"\"impact\":\"影响\",\"rollback\":\"回滚\"},"
		"{\"id\":\"b\",\"label\":\"取消\","
		"\"impact\":\"影响\",\"rollback\":\"回滚\"}]}";
	struct ask_clarify_request req;
	struct ask_clarify_pending ap;
	char path[1024];
	char label[ASK_CLARIFY_LABEL_MAX + 1];
	char err[256];
	char aerr[256];
	char *old;
	long long now;

	if (!home) {
		expect(0, "创建自动默认临时 HOME");
		return;
	}
	old = save_home();
	setenv("HOME", home, 1);
	now = ai_trace_wall_ms();
	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");

	/* 1) 过期 + 非授权 + 有推荐 → 自动选推荐继续 */
	expect(ask_clarify_pending_save(&req, "cq-auto01", now - 1000,
					"sess-a", "重启服务", 1, err,
					sizeof(err)) == 0,
	       "过期 pending 写入");
	memset(&ap, 0, sizeof(ap));
	label[0] = '\0';
	expect(ask_clarify_auto_default("cq-auto01", "sess-a", 1, &ap,
					label, sizeof(label), aerr,
					sizeof(aerr)) == 1 &&
	       strcmp(label, "nginx.service") == 0 &&
	       strcmp(ap.original_question, "重启服务") == 0 &&
	       ap.asked == 1,
	       "过期自动默认：选推荐项并回填恢复上下文");
	expect(ask_clarify_pending_load("cq-auto01", "sess-a", &ap, err,
					sizeof(err)) != 0 &&
	       strstr(err, "已被消费") != NULL,
	       "自动默认后 pending 已原子消费");
	ask_clarify_pending_free(&ap);

	/* 2) authorization 永不自动（维持挂起） */
	expect(build_req(auth_json, &req, err, sizeof(err)) == 0,
	       "authorization req 就绪");
	expect(ask_clarify_pending_save(&req, "cq-auto02", now - 1000,
					"sess-a", "危险操作", 1, err,
					sizeof(err)) == 0,
	       "authorization 过期 pending 写入");
	memset(&ap, 0, sizeof(ap));
	expect(ask_clarify_auto_default("cq-auto02", "sess-a", 1, &ap,
					label, sizeof(label), aerr,
					sizeof(aerr)) == 0 &&
	       strstr(aerr, "不满足") != NULL,
	       "authorization 永不自动默认");
	snprintf(path, sizeof(path),
		 "%s/.aikernel/clarify/pending/cq-auto02.json", home);
	expect(access(path, F_OK) == 0, "authorization pending 维持挂起");

	/* 3) 未过期不动（有效窗口内语义不变） */
	expect(build_req(valid_json, &req, err, sizeof(err)) == 0, "req 就绪");
	expect(ask_clarify_pending_save(&req, "cq-auto03", now + 60000,
					"sess-a", "重启服务", 1, err,
					sizeof(err)) == 0,
	       "未过期 pending 写入");
	memset(&ap, 0, sizeof(ap));
	expect(ask_clarify_auto_default("cq-auto03", "sess-a", 1, &ap,
					label, sizeof(label), aerr,
					sizeof(aerr)) == 0 &&
	       strstr(aerr, "未过期") != NULL,
	       "未过期 pending 不自动（等待答复）");
	expect(ask_clarify_pending_consume("cq-auto03", err,
					   sizeof(err)) == 0,
	       "清理未过期 pending");

	/* 4) 开关关闭不自动 */
	expect(ask_clarify_pending_save(&req, "cq-auto04", now - 1000,
					"sess-a", "重启服务", 1, err,
					sizeof(err)) == 0,
	       "开关测试 pending 写入");
	memset(&ap, 0, sizeof(ap));
	expect(ask_clarify_auto_default("cq-auto04", "sess-a", 0, &ap,
					label, sizeof(label), aerr,
					sizeof(aerr)) == 0 &&
	       strstr(aerr, "已关闭") != NULL,
	       "clarify_auto_default=off 不自动");
	expect(ask_clarify_pending_consume("cq-auto04", err,
					   sizeof(err)) == 0,
	       "清理开关测试 pending");
	ask_clarify_pending_free(&ap);
	restore_home(old);
	cleanup_dir(home);
}

static void test_entities_from_history(void)
{
	const char *msgs[] = {
		"刚才看了 nginx.service 的状态",
		"还有 /tmp/a.log 和 /var/ai/config 的说明",
		"nginx.service 又提到了一次",
	};
	const char *out[4];
	char buf[512];

	expect(ask_clarify_entities_from_history(msgs, 3, buf, sizeof(buf),
						  out, 4) == 3 &&
	       strcmp(out[0], "nginx.service") == 0 &&
	       strcmp(out[1], "/tmp/a.log") == 0 &&
	       strcmp(out[2], "/var/ai/config") == 0,
	       "会话实体提取：*.service 与绝对路径，重复去重");
	expect(ask_clarify_entities_from_history(msgs, 3, buf, sizeof(buf),
						  out, 2) == 2,
	       "会话实体提取：上限截断");
	expect(ask_clarify_entities_from_history(NULL, 0, buf, sizeof(buf),
						  out, 4) == 0,
	       "会话实体提取：空输入返回 0");
}

int main(void)
{
	printf("==== test_clarify: W77c 结构化澄清 + W77e 询问意识 2.0 ====\n");
	test_parse_valid();
	test_option_count();
	test_duplicate_ids();
	test_multi_select();
	test_recommended_default();
	test_kinds_header();
	test_option_decision_fields();
	test_cancel_other();
	test_invalid_reprompt();
	test_tty_timeout();
	test_suppress_peers();
	test_timeout_json();
	test_non_tty_json();
	test_event_channel();
	test_pending_roundtrip();
	test_pending_expiry();
	test_pending_visibility();
	test_resolve_selection();
	test_no_lease();
	test_max_two();
	test_detector_service();
	test_detector_destructive();
	test_trace_events();
	/* W77e：评分制 / 去重记忆 / 链级预算 / 自动默认降级 */
	test_threshold_env();
	test_score_signals();
	test_detector_scoring();
	test_fingerprint();
	test_entities_from_history();
	test_answered_memory();
	test_chain_dedup();
	test_dedup_injection();
	test_auto_default_eligible();
	test_auto_default_flow();
	printf("RESULT: %s (%d pass / %d fail)\n",
	       g_fail == 0 ? "PASS" : "FAIL", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
