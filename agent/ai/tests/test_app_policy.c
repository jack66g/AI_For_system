/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
/*
 * test_app_policy - W82 V4.5 画像 → 自动策略单测
 *
 * 覆盖（默认非 root 全跑，不碰真实 LSM/内核状态）：
 *   - 常量锚点：64 条上限、63 字节前缀、op 编号与内核 enum 对齐；
 *   - 纯函数：危险路径分类、路径/前缀合法性、前缀推导（文件→目录、
 *     目录→自身、根拒绝、超长向上收敛）、op 名称往返、标签稳定性；
 *   - 生成：真实 curl 形态事件流 → ≥5 条规则、每条带 because/fact、
 *     去重合并、网络目标 enforceable=false、绝不出现 allow-all；
 *   - 危险项：合成「读了 /etc/shadow + /proc/<pid>/mem + ~/.ssh/id_rsa」
 *     → 每条 deny=true/sensitive=true/requires_confirm=true，策略级
 *     requires_confirm=true，且没有任何 allow 覆盖这些路径；
 *   - 异常画像：空画像、坏 JSON、只有 / 路径、只有网络事件；
 *   - 策略 JSON 往返：render → parse 规则数一致；schema/allow-all/
 *     缺 because/op=any/prefix=/ 一律拒绝；
 *   - LSM 探测：真机 /sys/kernel/security/lsm + 临时文件（有 ai/无 ai/
 *     读不到三态）；
 *   - 注入面探测：空 root 找不到、造一个可写节点能找到；
 *   - 下发状态机（临时文件 sink）：成功、中途写失败回滚、读回不一致
 *     回滚、快照失败零改动；
 *   - 工具级：profile_dynamic=@文件 生成、缺参、apply 在本机 fail-closed
 *     （真机有 ai LSM 时自动跳过该断言）。
 *
 * --emit DIR：把生成的策略 JSON、拒绝 JSON、环境信息写到 DIR（证据目录）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "../tools/tool_registry.h"
#include "../tools/app_profile.h"
#include "../tools/app_policy.h"

static int fails;
static int checks;
static int skips;
static const char *g_emit;
static char g_tmp[512];

#define CHECK(cond, msg) do { \
	checks++; \
	if (cond) { \
		printf("ok %s\n", msg); \
	} else { \
		printf("FAIL %s\n", msg); \
		fails++; \
	} \
} while (0)

#define SKIP(msg, why) do { \
	printf("skip %s（%s）\n", msg, why); \
	skips++; \
} while (0)

/* ------------------------------------------------------------------ */
/* 临时目录 / 文件                                                     */
/* ------------------------------------------------------------------ */

static int rm_rf(const char *path)
{
	char cmd[600];

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
	return system(cmd);
}

static void mk_tmp(void)
{
	snprintf(g_tmp, sizeof(g_tmp), "/tmp/aik-test-apppolicy-%ld",
		 (long)getpid());
	rm_rf(g_tmp);
	if (mkdir(g_tmp, 0700) != 0)
		printf("WARN mkdir %s: %s\n", g_tmp, strerror(errno));
}

static int put_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");

	if (!f)
		return -1;
	fputs(text, f);
	fclose(f);
	return 0;
}

/* 独立实现（不依赖被测代码的读文件） */
static char *slurp(const char *path)
{
	FILE *f = fopen(path, "r");
	char *buf;
	long n;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	n = ftell(f);
	if (n < 0 || n > 4 * 1024 * 1024) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf);
		fclose(f);
		return NULL;
	}
	buf[n] = '\0';
	fclose(f);
	return buf;
}

static void emit(const char *name, const char *text)
{
	char path[700];
	FILE *f;

	if (!g_emit || !text)
		return;
	snprintf(path, sizeof(path), "%s/%s", g_emit, name);
	f = fopen(path, "w");
	if (!f)
		return;
	fputs(text, f);
	fclose(f);
}

/* ------------------------------------------------------------------ */
/* 1) 常量锚点                                                        */
/* ------------------------------------------------------------------ */

static void test_anchors(void)
{
	CHECK(APOL_MAX_RULES == 64, "anchor-64-rules");
	CHECK(APOL_PREFIX_LEN == 63, "anchor-63-prefix");
	CHECK(APOL_OP_ANY == 0 && APOL_OP_FILE_OPEN == 1 &&
	      APOL_OP_FILE_READ == 2 && APOL_OP_FILE_WRITE == 3 &&
	      APOL_OP_FILE_EXEC == 4 && APOL_OP_SOCKET_CONNECT == 5 &&
	      APOL_OP_SOCKET_SENDMSG == 6, "anchor-op-ids-match-kernel");
	CHECK(strcmp(APOL_SCHEMA, "aik-app-policy/1") == 0, "anchor-schema");
}

/* ------------------------------------------------------------------ */
/* 2) 纯函数                                                          */
/* ------------------------------------------------------------------ */

static void test_sensitive(void)
{
	CHECK(apol_path_sensitive("/etc/shadow") == 1, "sens-shadow");
	CHECK(apol_path_sensitive("/etc/gshadow") == 1, "sens-gshadow");
	CHECK(apol_path_sensitive("/etc/sudoers") == 1, "sens-sudoers");
	CHECK(apol_path_sensitive("/etc/sudoers.d/90-cloud") == 1,
	      "sens-sudoers-d");
	CHECK(apol_path_sensitive("/root/.bashrc") == 1, "sens-root");
	CHECK(apol_path_sensitive("/home/u/.ssh/id_rsa") == 1, "sens-ssh");
	CHECK(apol_path_sensitive("/proc/1234/mem") == 1, "sens-proc-mem");
	CHECK(apol_path_sensitive("/proc/self/mem") == 1, "sens-proc-self-mem");
	CHECK(apol_path_sensitive("/proc/1/environ") == 1, "sens-proc-environ");
	CHECK(apol_path_sensitive("/proc/kcore") == 1, "sens-kcore");
	CHECK(apol_path_sensitive("/dev/mem") == 1, "sens-devmem");
	CHECK(apol_path_sensitive("/etc/ssl/private/x.key") == 1,
	      "sens-ssl-private");
	CHECK(apol_path_sensitive("/usr/bin/curl") == 0, "sens-curl");
	CHECK(apol_path_sensitive("/etc/hosts") == 0, "sens-hosts");
	CHECK(apol_path_sensitive("/proc/1234/status") == 0, "sens-proc-status");
	CHECK(apol_path_sensitive("/lib/x86_64-linux-gnu/libc.so.6") == 0,
	      "sens-libc");
	CHECK(apol_path_sensitive("/home/u/.sshx/id") == 0, "sens-sshx-neg");
}

static void test_path_rules(void)
{
	char out[APOL_PREFIX_MAX];
	int clamped = 0;

	CHECK(apol_path_valid("/usr/bin/curl") == 1, "path-valid-abs");
	CHECK(apol_path_valid("usr/bin/curl") == 0, "path-valid-rel");
	CHECK(apol_path_valid("/usr/../etc/shadow") == 0, "path-valid-dotdot");
	CHECK(apol_path_valid("/") == 0, "path-valid-root");
	CHECK(apol_path_valid("/a\tb") == 0, "path-valid-ctl");
	CHECK(apol_path_valid(NULL) == 0, "path-valid-null");

	CHECK(apol_prefix_valid("/") == 0, "prefix-valid-root");
	CHECK(apol_prefix_valid("") == 0, "prefix-valid-empty");
	CHECK(apol_prefix_valid("etc/") == 0, "prefix-valid-rel");
	CHECK(apol_prefix_valid("/etc/") == 1, "prefix-valid-etc");
	CHECK(apol_prefix_valid("/a//b") == 0, "prefix-valid-double-slash");
	{
		char longp[APOL_PREFIX_LEN + 8];
		int i;

		snprintf(longp, sizeof(longp), "/%s/",
			 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			 "aaaaaaaaaaaa");
		for (i = 0; longp[i]; i++)
			;
		CHECK((size_t)i > APOL_PREFIX_LEN, "prefix-long-fixture");
		CHECK(apol_prefix_valid(longp) == 0, "prefix-valid-toolong");
	}

	/* 普通文件 → 所在目录 + '/' */
	CHECK(apol_path_to_prefix("/usr/bin/curl", out, sizeof(out), &clamped)
	      == 1 && strcmp(out, "/usr/bin/") == 0 && clamped == 0,
	      "prefix-file-to-dir");
	/* 目录（真实存在的 /tmp）→ 自身 + '/' */
	CHECK(apol_path_to_prefix("/tmp", out, sizeof(out), &clamped) == 1 &&
	      strcmp(out, "/tmp/") == 0, "prefix-dir-itself");
	/* 根文件 → 拒绝（否则就是 allow-all） */
	CHECK(apol_path_to_prefix("/foo", out, sizeof(out), &clamped) == 0,
	      "prefix-root-refused");
	/* 超长 → 向上收敛且不切断分量 */
	{
		char deep[512];

		snprintf(deep, sizeof(deep), "/aaaa/%s/%s/file",
			 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			 "cccccccccccccccccccccccccccccccc");
		CHECK(apol_path_to_prefix(deep, out, sizeof(out), &clamped) == 1,
		      "prefix-deep-ok");
		CHECK(clamped == 1, "prefix-deep-clamped");
		CHECK(out[strlen(out) - 1] == '/', "prefix-deep-trailing-slash");
		CHECK(strlen(out) <= APOL_PREFIX_LEN, "prefix-deep-len");
	}
}

static void test_op_label(void)
{
	CHECK(apol_op_from_name("file_read") == APOL_OP_FILE_READ,
	      "op-name-read");
	CHECK(apol_op_from_name("file_exec") == APOL_OP_FILE_EXEC,
	      "op-name-exec");
	CHECK(apol_op_from_name("2") == APOL_OP_FILE_READ, "op-name-num");
	CHECK(apol_op_from_name("any") == APOL_OP_ANY, "op-name-any");
	CHECK(apol_op_from_name("bogus") == -1, "op-name-bogus");
	CHECK(strcmp(apol_op_name(APOL_OP_FILE_WRITE), "file_write") == 0,
	      "op-render-write");

	{
		char l1[APOL_LABEL_MAX], l2[APOL_LABEL_MAX];
		int id1 = 0, id2 = 0;

		CHECK(apol_label_of("/usr/bin/curl", l1, sizeof(l1), &id1) == 0,
		      "label-ok");
		CHECK(apol_label_of("/usr/bin/curl", l2, sizeof(l2), &id2) == 0,
		      "label-ok2");
		CHECK(strcmp(l1, l2) == 0 && id1 == id2, "label-stable");
		CHECK(id1 >= 1 && id1 <= 255, "label-range");
		CHECK(apol_label_of("/usr/bin/wget", l2, sizeof(l2), &id2) == 0 &&
		      strcmp(l1, l2) != 0, "label-distinct");
	}
}

/* ------------------------------------------------------------------ */
/* 3) 生成                                                            */
/* ------------------------------------------------------------------ */

/* curl --version 的真实形态（W81 采集的 03b-dynamic-curl.json 缩编） */
static const char *k_curl_dyn =
"{\"tool\":\"app_profile_dynamic\",\"path\":\"/usr/bin/curl\","
"\"events\":["
"{\"seq\":1,\"type\":\"proc_exec\",\"path\":\"/usr/bin/curl\",\"note\":\"target\",\"count\":2},"
"{\"seq\":2,\"type\":\"file_read\",\"path\":\"/lib/x86_64-linux-gnu/libcurl.so.4\"},"
"{\"seq\":3,\"type\":\"file_read\",\"path\":\"/lib/x86_64-linux-gnu/libz.so.1\"},"
"{\"seq\":4,\"type\":\"file_read\",\"path\":\"/lib/x86_64-linux-gnu/libc.so.6\"},"
"{\"seq\":5,\"type\":\"file_read\",\"path\":\"/lib/x86_64-linux-gnu/libssl.so.3\"},"
"{\"seq\":6,\"type\":\"file_read\",\"path\":\"/etc/nsswitch.conf\"},"
"{\"seq\":7,\"type\":\"file_read\",\"path\":\"/etc/resolv.conf\"},"
"{\"seq\":8,\"type\":\"file_read\",\"path\":\"/etc/hosts\"},"
"{\"seq\":9,\"type\":\"file_read\",\"path\":\"/usr/lib/x86_64-linux-gnu/sasl2\"},"
"{\"seq\":10,\"type\":\"file_read\",\"path\":\"/usr/lib/x86_64-linux-gnu/sasl2/libplain.so\"},"
"{\"seq\":11,\"type\":\"net_connect\",\"proto\":\"inet\","
"\"local\":\"\",\"remote\":\"127.0.0.53:53\",\"state\":\"CONNECT\",\"count\":2}"
"],\"warnings\":[],\"degraded\":[]}";

static const char *k_curl_static =
"{\"tool\":\"app_profile_static\",\"path\":\"/usr/bin/curl\","
"\"kind\":\"elf\",\"stat\":{\"size\":260328,\"mode\":\"0755\","
"\"setuid\":false,\"setgid\":false},"
"\"elf\":{\"parsed\":true,\"type\":\"DYN\",\"machine\":\"x86-64\","
"\"interp\":\"/lib64/ld-linux-x86-64.so.2\"},"
"\"deps\":{\"parsed\":true,\"needed\":[\"libcurl.so.4\",\"libz.so.1\","
"\"libc.so.6\"],\"soname\":\"\"},"
"\"caps\":{\"state\":\"none\"},"
"\"pkg\":{\"checked\":true,\"found\":true,\"package\":\"curl\"},"
"\"warnings\":[],\"declared\":[]}";

static int dyn_to_events(const char *json, struct ap_event *ev, int *n,
			 char *err, size_t errcap)
{
	int truncated = 0;

	return ap_dynamic_json_to_events(json, ev, AP_MAX_EVENTS, n, &truncated,
					 err, errcap);
}

static void test_generate_curl(void)
{
	struct ap_event ev[AP_MAX_EVENTS];
	struct apol_static_input st;
	struct apol_policy p;
	char err[512] = "";
	char jerr[512] = "";
	char *json = NULL;
	int n = 0, i, has_exec = 0, has_read = 0, has_net_rule = 0;
	int all_explained = 1, no_allow_all = 1, because_len_ok = 0;

	CHECK(dyn_to_events(k_curl_dyn, ev, &n, jerr, sizeof(jerr)) == 0,
	      "gen-dyn-parse");
	CHECK(n == 11, "gen-dyn-11-events");
	CHECK(apol_static_json_parse(k_curl_static, &st, jerr, sizeof(jerr)) == 0,
	      "gen-static-parse");
	CHECK(strcmp(st.interp, "/lib64/ld-linux-x86-64.so.2") == 0,
	      "gen-static-interp");
	CHECK(st.needed_n == 3, "gen-static-needed");
	CHECK(st.pkg_found == 1, "gen-static-pkg");

	CHECK(apol_generate("/usr/bin/curl", ev, n, &st, &p, err, sizeof(err))
	      == 0, "gen-ok");
	CHECK(p.rule_n >= 5, "gen-rules-ge-5");
	CHECK(p.merged > 0, "gen-merged");
	CHECK(p.dropped == 0, "gen-dropped-0");
	CHECK(p.requires_confirm == 0, "gen-no-confirm-for-curl");
	CHECK(p.dynamic_available == 1, "gen-dynamic-available");
	CHECK(p.sens_n == 0, "gen-no-sensitive");
	CHECK(p.net_n == 1, "gen-net-1");
	CHECK(strcmp(p.net[0].remote, "127.0.0.53:53") == 0, "gen-net-remote");
	CHECK(p.net[0].loopback == 1, "gen-net-loopback");
	CHECK(p.label_id >= 1 && p.label_id <= 255, "gen-label-range");

	for (i = 0; i < p.rule_n; i++) {
		const struct apol_rule *r = &p.rules[i];

		if (!r->because[0] || r->path_prefix[0] == 0)
			all_explained = 0;
		if (r->op == APOL_OP_FILE_EXEC)
			has_exec = 1;
		if (r->op == APOL_OP_FILE_READ)
			has_read = 1;
		if (r->op == APOL_OP_SOCKET_CONNECT)
			has_net_rule = 1;
		if (r->fact_seq > 0 && r->because[0] &&
		    strlen(r->because) > 20)
			because_len_ok++;
		if (!r->deny && (r->path_prefix[0] == 0 ||
				 strcmp(r->path_prefix, "/") == 0))
			no_allow_all = 0;
	}
	CHECK(all_explained, "gen-all-rules-explained");
	CHECK(has_exec, "gen-has-exec-rule");
	CHECK(has_read, "gen-has-read-rule");
	CHECK(!has_net_rule, "gen-no-net-path-rule");
	CHECK(no_allow_all, "gen-no-allow-all-rule");
	CHECK(apol_has_allow_all(&p) == 0, "gen-allow-all-check");
	CHECK(because_len_ok >= 3, "gen-because-substantial");

	if (apol_policy_render_json(&p, "app_policy_generate", &json) == 0) {
		CHECK(strstr(json, "\"schema\": \"aik-app-policy/1\"") != NULL ||
		      strstr(json, "\"schema\":\"aik-app-policy/1\"") != NULL,
		      "gen-json-schema");
		CHECK(strstr(json, "\"because\":") != NULL, "gen-json-because");
		CHECK(strstr(json, "\"enforceable\":false") != NULL,
		      "gen-json-net-unenforceable");
		CHECK(strstr(json, "\"allow_all\":false") != NULL,
		      "gen-json-allow-all-false");
		emit("01-curl-policy.json", json);
		free(json);
	} else {
		CHECK(0, "gen-json-render");
	}
}

static void test_generate_sensitive(void)
{
	/* 合成：读了 /etc/shadow、/proc/<pid>/mem、~/.ssh/id_rsa */
	static const char *dyn =
	"{\"tool\":\"app_profile_dynamic\",\"path\":\"/usr/bin/evil\","
	"\"events\":["
	"{\"seq\":1,\"type\":\"file_read\",\"path\":\"/etc/shadow\"},"
	"{\"seq\":2,\"type\":\"file_read\",\"path\":\"/proc/4321/mem\"},"
	"{\"seq\":3,\"type\":\"file_read\",\"path\":\"/home/u/.ssh/id_rsa\"},"
	"{\"seq\":4,\"type\":\"file_read\",\"path\":\"/usr/lib/libsafe.so\"},"
	"{\"seq\":5,\"type\":\"file_write\",\"path\":\"/tmp/out.txt\"},"
	"{\"seq\":6,\"type\":\"file_read\",\"path\":\"/etc/hosts\"}"
	"]}";
	struct ap_event ev[AP_MAX_EVENTS];
	struct apol_static_input st;
	struct apol_policy p;
	char err[512] = "";
	char jerr[512] = "";
	char *json = NULL;
	int n = 0, i, sens_rules = 0, allow_covers_sens = 0;

	CHECK(dyn_to_events(dyn, ev, &n, jerr, sizeof(jerr)) == 0,
	      "sens-dyn-parse");
	memset(&st, 0, sizeof(st));
	snprintf(st.path, sizeof(st.path), "%s", "/usr/bin/evil");

	CHECK(apol_generate("/usr/bin/evil", ev, n, &st, &p, err, sizeof(err))
	      == 0, "sens-gen-ok");
	CHECK(p.requires_confirm == 1, "sens-policy-requires-confirm");
	CHECK(p.sens_n == 3, "sens-hits-3");
	for (i = 0; i < p.rule_n; i++) {
		const struct apol_rule *r = &p.rules[i];

		if (!r->sensitive)
			continue;
		sens_rules++;
		CHECK(r->deny == 1, "sens-rule-deny");
		CHECK(r->requires_confirm == 1, "sens-rule-confirm");
		CHECK(strstr(r->path_prefix, "/.ssh/") ||
		      strcmp(r->path_prefix, "/etc/shadow") == 0 ||
		      strstr(r->path_prefix, "/mem") != NULL,
		      "sens-rule-exact-path");
	}
	CHECK(sens_rules == 3, "sens-rules-3");
	/* 不允许任何 allow 规则"就是"敏感路径本身（那是放行危险项） */
	for (i = 0; i < p.rule_n; i++) {
		const struct apol_rule *r = &p.rules[i];
		int k;

		if (r->deny)
			continue;
		for (k = 0; k < p.sens_n; k++) {
			if (strcmp(r->path_prefix, p.sens[k].path) == 0)
				allow_covers_sens = 1;
		}
	}
	CHECK(!allow_covers_sens, "sens-no-allow-equals-sensitive");
	/* 更宽的 allow 前缀（如 /etc/）与精确 deny 共存时必须有 warning 解释 */
	CHECK(p.warn_n > 0, "sens-broader-allow-explained");
	CHECK(p.warn_n > 0 && strstr(p.warn[0], "/etc/shadow") != NULL,
	      "sens-broader-warning-names-path");

	if (apol_policy_render_json(&p, "app_policy_generate", &json) == 0) {
		CHECK(strstr(json, "\"requires_confirm\":true") != NULL,
		      "sens-json-confirm");
		CHECK(strstr(json, "\"sensitive\":true") != NULL,
		      "sens-json-sensitive");
		emit("02-sensitive-policy.json", json);
		free(json);
	}
}

static void test_generate_edges(void)
{
	struct apol_policy p;
	char err[512] = "";
	struct ap_event ev[4];
	struct apol_static_input st;

	/* 空画像 */
	memset(&p, 0, sizeof(p));
	CHECK(apol_generate("/usr/bin/x", NULL, 0, NULL, &p, err,
			    sizeof(err)) == -1, "edge-empty-fails");
	CHECK(strstr(err, "empty_profile") != NULL, "edge-empty-code");

	/* 图片非法路径 → bad_app_path */
	memset(&p, 0, sizeof(p));
	CHECK(apol_generate("relative/path", NULL, 0, NULL, &p, err,
			    sizeof(err)) == -1, "edge-relpath-fails");
	CHECK(strstr(err, "bad_app_path") != NULL, "edge-relpath-code");

	/* 只有网络事件：仍应有一个主体 exec 规则，网络目标声明化 */
	memset(ev, 0, sizeof(ev));
	ev[0].type = AP_EV_NET_CONNECT;
	snprintf(ev[0].proto, sizeof(ev[0].proto), "inet");
	snprintf(ev[0].remote, sizeof(ev[0].remote), "10.1.2.3:443");
	ev[0].count = 1;
	memset(&p, 0, sizeof(p));
	CHECK(apol_generate("/usr/bin/x", ev, 1, NULL, &p, err, sizeof(err))
	      == 0, "edge-net-only-ok");
	CHECK(p.rule_n == 1, "edge-net-only-one-rule");
	CHECK(p.net_n == 1 && p.net[0].loopback == 0, "edge-net-nonloopback");

	/* 路径为 "/" 的事件：必须被丢弃，绝不生成 allow-all */
	memset(ev, 0, sizeof(ev));
	ev[0].type = AP_EV_FILE_READ;
	snprintf(ev[0].path, sizeof(ev[0].path), "/");
	ev[0].count = 1;
	ev[1].type = AP_EV_FILE_READ;
	snprintf(ev[1].path, sizeof(ev[1].path), "/usr/lib/libx.so");
	ev[1].count = 1;
	memset(&p, 0, sizeof(p));
	CHECK(apol_generate("/usr/bin/x", ev, 2, NULL, &p, err, sizeof(err))
	      == 0, "edge-rootpath-ok");
	CHECK(p.dropped == 1, "edge-rootpath-dropped");
	CHECK(apol_has_allow_all(&p) == 0, "edge-rootpath-no-allowall");

	/* 坏 JSON 画像 */
	{
		int n = 0;
		char jerr[256] = "";

		CHECK(ap_dynamic_json_to_events("{\"tool\":\"x\"}", ev, 4, &n,
						NULL, jerr, sizeof(jerr)) == -1,
		      "edge-bad-dyn-json");
		CHECK(strstr(jerr, "events") != NULL, "edge-bad-dyn-msg");
		memset(&st, 0, sizeof(st));
		CHECK(apol_static_json_parse("not json", &st, jerr,
					     sizeof(jerr)) == -1,
		      "edge-bad-static-json");
	}

	/* 去重合并：同一目录的多个文件只留一条规则 */
	memset(ev, 0, sizeof(ev));
	ev[0].type = AP_EV_FILE_READ;
	snprintf(ev[0].path, sizeof(ev[0].path), "/opt/app/a.so");
	ev[1].type = AP_EV_FILE_READ;
	snprintf(ev[1].path, sizeof(ev[1].path), "/opt/app/b.so");
	ev[2].type = AP_EV_FILE_READ;
	snprintf(ev[2].path, sizeof(ev[2].path), "/opt/app/c.so");
	memset(&p, 0, sizeof(p));
	CHECK(apol_generate("/usr/bin/x", ev, 3, NULL, &p, err, sizeof(err))
	      == 0, "edge-merge-ok");
	CHECK(p.rule_n == 2, "edge-merge-rules-2");
	CHECK(p.merged == 2, "edge-merge-count");

	/* allow 与 deny 同前缀冲突：deny 胜 */
	{
		struct apol_rule r;

		memset(&p, 0, sizeof(p));
		memset(&r, 0, sizeof(r));
		r.kind = APOL_KIND_PATH;
		r.op = APOL_OP_FILE_READ;
		snprintf(r.path_prefix, sizeof(r.path_prefix), "/etc/hosts");
		CHECK(apol_rule_add(&p, &r) == 1, "edge-conflict-add-allow");
		r.deny = 1;
		r.sensitive = 1;
		snprintf(r.because, sizeof(r.because), "test");
		CHECK(apol_rule_add(&p, &r) == 3, "edge-conflict-add-deny");
		CHECK(p.rule_n == 1 && p.rules[0].deny == 1 &&
		      p.conflicts == 1, "edge-conflict-deny-wins");
		/* 再 allow 一次 → 合并到 deny，不新增 */
		r.deny = 0;
		CHECK(apol_rule_add(&p, &r) == 2, "edge-conflict-merge");
		CHECK(p.rule_n == 1 && p.rules[0].deny == 1,
		      "edge-conflict-still-deny");
	}
	/* allow-all 规则永远进不来 */
	{
		struct apol_rule r;

		memset(&p, 0, sizeof(p));
		memset(&r, 0, sizeof(r));
		r.kind = APOL_KIND_PATH;
		r.op = APOL_OP_FILE_READ;
		snprintf(r.path_prefix, sizeof(r.path_prefix), "/");
		CHECK(apol_rule_add(&p, &r) == 0, "edge-rule-root-refused");
		memset(&r, 0, sizeof(r));
		r.kind = APOL_KIND_PATH;
		r.op = APOL_OP_ANY;
		snprintf(r.path_prefix, sizeof(r.path_prefix), "/etc/");
		CHECK(apol_rule_add(&p, &r) == 0, "edge-rule-any-refused");
		CHECK(p.rule_n == 0, "edge-rule-none-added");
	}
}

/* ------------------------------------------------------------------ */
/* 4) 策略 JSON 往返 / 校验                                           */
/* ------------------------------------------------------------------ */

static const char *k_policy2 =
"{\"schema\":\"aik-app-policy/1\",\"app_path\":\"/usr/bin/demo\","
"\"label\":\"app-test\",\"label_id\":7,\"allow_all\":false,"
"\"requires_confirm\":false,\"rules\":["
"{\"id\":1,\"kind\":\"path\",\"op\":\"file_exec\",\"op_id\":4,"
"\"deny\":false,\"path_prefix\":\"/usr/bin/demo\","
"\"because\":\"策略主体：目标自身\"},"
"{\"id\":2,\"kind\":\"path\",\"op\":\"file_read\",\"op_id\":2,"
"\"deny\":false,\"path_prefix\":\"/etc/\","
"\"because\":\"动态画像事件 #1 读取了 /etc/hosts\"}"
"]}";

static void test_policy_parse(void)
{
	struct apol_policy p;
	char err[512] = "";
	char *bad = NULL;

	CHECK(apol_policy_parse(k_policy2, &p, err, sizeof(err)) == 0,
	      "parse-ok");
	CHECK(p.rule_n == 2, "parse-2-rules");
	CHECK(strcmp(p.label, "app-test") == 0, "parse-label");
	CHECK(p.label_id == 7, "parse-label-id");
	CHECK(strcmp(p.rules[0].path_prefix, "/usr/bin/demo") == 0,
	      "parse-prefix");

	/* schema 不匹配 */
	CHECK(apol_policy_parse("{\"schema\":\"other\",\"rules\":[]}", &p, err,
				sizeof(err)) == -1, "parse-bad-schema");
	/* 不是 JSON */
	CHECK(apol_policy_parse("nope", &p, err, sizeof(err)) == -1,
	      "parse-not-json");
	/* 空策略 */
	CHECK(apol_policy_parse("{\"schema\":\"aik-app-policy/1\","
				"\"rules\":[]}", &p, err, sizeof(err)) == -1,
	      "parse-empty-policy");
	CHECK(strstr(err, "empty_policy") != NULL, "parse-empty-code");
	/* allow_all=true */
	if (asprintf(&bad,
		     "{\"schema\":\"aik-app-policy/1\",\"allow_all\":true,"
		     "\"rules\":[{\"op\":\"file_read\",\"path_prefix\":\"/e/\","
		     "\"because\":\"x\"}]}") > 0) {
		CHECK(apol_policy_parse(bad, &p, err, sizeof(err)) == -1,
		      "parse-allow-all-refused");
		free(bad);
	}
	/* op=any 的 allow */
	CHECK(apol_policy_parse("{\"schema\":\"aik-app-policy/1\",\"rules\":"
				"[{\"op\":\"any\",\"path_prefix\":\"/e/\","
				"\"because\":\"x\"}]}", &p, err,
				sizeof(err)) == -1, "parse-op-any-refused");
	/* prefix=/ */
	CHECK(apol_policy_parse("{\"schema\":\"aik-app-policy/1\",\"rules\":"
				"[{\"op\":\"file_read\",\"path_prefix\":\"/\","
				"\"because\":\"x\"}]}", &p, err,
				sizeof(err)) == -1, "parse-root-prefix-refused");
	/* 缺 because */
	CHECK(apol_policy_parse("{\"schema\":\"aik-app-policy/1\",\"rules\":"
				"[{\"op\":\"file_read\","
				"\"path_prefix\":\"/e/\"}]}", &p, err,
				sizeof(err)) == -1, "parse-no-because-refused");
	/* op 缺 */
	CHECK(apol_policy_parse("{\"schema\":\"aik-app-policy/1\",\"rules\":"
				"[{\"path_prefix\":\"/e/\",\"because\":\"x\"}]}",
				&p, err, sizeof(err)) == -1,
	      "parse-no-op-refused");
	/* 超 64 条 */
	{
		char *big = NULL;
		size_t cap = 128 + 64 * 200;
		int i;

		big = malloc(cap);
		if (big) {
			size_t off = 0;

			off += (size_t)snprintf(big + off, cap - off,
						"{\"schema\":\"aik-app-policy/1\","
						"\"rules\":[");
			for (i = 0; i < 70; i++)
				off += (size_t)snprintf(big + off, cap - off,
					"%s{\"op\":\"file_read\","
					"\"path_prefix\":\"/d%d/\","
					"\"because\":\"x\"}",
					i ? "," : "", i);
			snprintf(big + off, cap - off, "]}");
			CHECK(apol_policy_parse(big, &p, err, sizeof(err))
			      == -1, "parse-70-rules-refused");
			free(big);
		}
	}
}

static void test_render_roundtrip(void)
{
	struct ap_event ev[AP_MAX_EVENTS];
	struct apol_static_input st;
	struct apol_policy p, q;
	char err[512] = "";
	char jerr[512] = "";
	char *json = NULL;
	int n = 0;

	CHECK(dyn_to_events(k_curl_dyn, ev, &n, jerr, sizeof(jerr)) == 0,
	      "rt-dyn");
	CHECK(apol_static_json_parse(k_curl_static, &st, jerr, sizeof(jerr)) == 0,
	      "rt-static");
	CHECK(apol_generate("/usr/bin/curl", ev, n, &st, &p, err, sizeof(err))
	      == 0, "rt-generate");
	CHECK(apol_policy_render_json(&p, "app_policy_generate", &json) == 0,
	      "rt-render");
	CHECK(json && apol_policy_parse(json, &q, err, sizeof(err)) == 0,
	      "rt-parse-back");
	CHECK(q.rule_n == p.rule_n, "rt-rule-count");
	CHECK(q.requires_confirm == p.requires_confirm, "rt-confirm");
	CHECK(strcmp(q.label, p.label) == 0, "rt-label");
	CHECK(q.label_id == p.label_id, "rt-label-id");
	free(json);
}

/* ------------------------------------------------------------------ */
/* 5) 探测                                                            */
/* ------------------------------------------------------------------ */

static void test_probes(void)
{
	char path[600];
	struct apol_lsm_info li;
	struct apol_inject_info ii;

	snprintf(path, sizeof(path), "%s/lsm-none", g_tmp);
	put_file(path, "lockdown,capability,landlock,yama,apparmor\n");
	CHECK(apol_lsm_probe(path, &li) == 0, "lsm-probe-ok");
	CHECK(li.ai_present == 0, "lsm-no-ai");
	CHECK(strstr(li.raw, "apparmor") != NULL, "lsm-raw-preserved");
	CHECK(strstr(li.list, "lockdown,capability,landlock,yama,apparmor")
	      != NULL, "lsm-list");

	snprintf(path, sizeof(path), "%s/lsm-ai", g_tmp);
	put_file(path, " capability,ai,apparmor\n");
	CHECK(apol_lsm_probe(path, &li) == 0 && li.ai_present == 1,
	      "lsm-ai-present");

	snprintf(path, sizeof(path), "%s/lsm-missing", g_tmp);
	unlink(path);
	CHECK(apol_lsm_probe(path, &li) == -1 && li.ai_present == -1,
	      "lsm-unreadable-failclosed");

	snprintf(path, sizeof(path), "%s/emptyroot", g_tmp);
	mkdir(path, 0700);
	CHECK(apol_inject_probe(path, &ii) == -1 && ii.found == 0,
	      "inject-not-found");
	CHECK(strstr(ii.probes, "proc/ai/lsm/rules") != NULL,
	      "inject-probes-listed");

	/* 造一个可写节点（模拟未来内核提供的注入面） */
	snprintf(path, sizeof(path), "%s/emptyroot/proc/ai/lsm", g_tmp);
	{
		char cmd[700];

		snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", path);
		if (system(cmd) == 0) {
			snprintf(path, sizeof(path),
				 "%s/emptyroot/proc/ai/lsm/rules", g_tmp);
			char root[600];

			put_file(path, "");
			snprintf(root, sizeof(root), "%s/emptyroot", g_tmp);
			CHECK(apol_inject_probe(root, &ii) == 0 &&
			      ii.found == 1, "inject-found");
			CHECK(strstr(ii.path, "proc/ai/lsm/rules") != NULL,
			      "inject-path");
		}
	}
}

/* ------------------------------------------------------------------ */
/* 6) 下发状态机（临时文件 sink）                                      */
/* ------------------------------------------------------------------ */

struct fsink {
	char file[600];
	int fail_at;		/* 第 N 次 add 失败（1 起，0=不失败） */
	int adds;
	int lie_readback;	/* 读回返回空 */
	int fail_snapshot;
};

static int fs_read(const char *path, char **out)
{
	char *buf = slurp(path);

	if (!buf)
		buf = strdup("");
	*out = buf;
	return *out ? 0 : -1;
}

static int fs_snapshot(void *ctx, char **snap, char *err, size_t errcap)
{
	struct fsink *s = ctx;

	if (s->fail_snapshot) {
		snprintf(err, errcap, "快照注入失败（测试）");
		return -1;
	}
	return fs_read(s->file, snap);
}

static int fs_clear(void *ctx, char *err, size_t errcap)
{
	struct fsink *s = ctx;

	if (put_file(s->file, "") != 0) {
		snprintf(err, errcap, "清空失败");
		return -1;
	}
	return 0;
}

static int fs_add(void *ctx, const struct apol_rule *r, char *err,
		  size_t errcap)
{
	struct fsink *s = ctx;
	char uri[200];
	char line[260];
	FILE *f;

	s->adds++;
	if (s->fail_at && s->adds == s->fail_at) {
		snprintf(err, errcap, "注入节点拒绝第 %d 条（测试）", s->adds);
		return -1;
	}
	(void)apol_rule_uri(r, uri, sizeof(uri));
	snprintf(line, sizeof(line), "%s\n", uri);
	f = fopen(s->file, "a");
	if (!f) {
		snprintf(err, errcap, "追加失败");
		return -1;
	}
	fputs(line, f);
	fclose(f);
	return 0;
}

static int fs_readback(void *ctx, char **txt, char *err, size_t errcap)
{
	struct fsink *s = ctx;

	if (s->lie_readback) {
		*txt = strdup("");
		return *txt ? 0 : -1;
	}
	if (fs_read(s->file, txt) != 0) {
		snprintf(err, errcap, "读回失败");
		return -1;
	}
	return 0;
}

static int fs_restore(void *ctx, const char *snap, char *err, size_t errcap)
{
	struct fsink *s = ctx;

	if (put_file(s->file, snap ? snap : "") != 0) {
		snprintf(err, errcap, "恢复失败");
		return -1;
	}
	return 0;
}

static void fs_init(struct apol_sink *sink, struct fsink *s, const char *name)
{
	memset(s, 0, sizeof(*s));
	snprintf(s->file, sizeof(s->file), "%s/%s", g_tmp, name);
	memset(sink, 0, sizeof(*sink));
	sink->name = "test-filesink";
	sink->ctx = s;
	sink->snapshot = fs_snapshot;
	sink->clear = fs_clear;
	sink->add = fs_add;
	sink->readback = fs_readback;
	sink->restore = fs_restore;
}

static void test_apply_machine(void)
{
	struct apol_policy p, q;
	char err[512] = "";
	struct apol_sink sink;
	struct fsink s;
	struct apol_apply_result res;
	char *before = NULL, *after = NULL;

	CHECK(apol_policy_parse(k_policy2, &p, err, sizeof(err)) == 0,
	      "am-parse");
	/* 成功路径 */
	fs_init(&sink, &s, "ok.rules");
	put_file(s.file, "path:/old/:file_read:allow\n");
	CHECK(fs_read(s.file, &before) == 0, "am-read-before");
	CHECK(apol_apply_run(&sink, &p, &res, err, sizeof(err)) == 0,
	      "am-ok");
	CHECK(res.rules_applied == 2 && res.readback_ok == 1,
	      "am-applied-2");
	CHECK(res.readback_matched == 2, "am-readback-2");
	CHECK(!res.rolled_back, "am-no-rollback");
	CHECK(strstr(res.snapshot_ref, "fnv64") != NULL, "am-snapshot-ref");
	CHECK(fs_read(s.file, &after) == 0 && strstr(after, "/old/") != NULL,
	      "am-old-rule-kept");
	CHECK(strstr(after, "path:/usr/bin/demo:file_exec:allow") != NULL,
	      "am-new-rule-present");
	free(before);
	free(after);

	/* 中途写失败 → 回滚到快照 */
	fs_init(&sink, &s, "fail.rules");
	put_file(s.file, "path:/old/:file_read:allow\npath:/keep/:file_read:allow\n");
	CHECK(fs_read(s.file, &before) == 0, "am-fail-before");
	s.fail_at = 2;
	CHECK(apol_apply_run(&sink, &p, &res, err, sizeof(err)) == -1,
	      "am-add-fail");
	CHECK(strstr(err, "apply_failed") != NULL, "am-add-fail-code");
	CHECK(res.rules_applied == 1, "am-add-fail-applied-1");
	CHECK(res.rolled_back == 1 && res.rollback_ok == 1, "am-rollback-ok");
	CHECK(fs_read(s.file, &after) == 0 && strcmp(before, after) == 0,
	      "am-rollback-restored");
	free(before);
	free(after);

	/* 读回不一致 → 回滚 */
	fs_init(&sink, &s, "lie.rules");
	put_file(s.file, "path:/old/:file_read:allow\n");
	CHECK(fs_read(s.file, &before) == 0, "am-lie-before");
	s.lie_readback = 1;
	CHECK(apol_apply_run(&sink, &p, &res, err, sizeof(err)) == -1,
	      "am-readback-fail");
	CHECK(strstr(err, "读回校验") != NULL, "am-readback-msg");
	CHECK(res.rolled_back == 1 && res.rollback_ok == 1,
	      "am-readback-rollback");
	CHECK(fs_read(s.file, &after) == 0 && strcmp(before, after) == 0,
	      "am-readback-restored");
	free(before);
	free(after);

	/* 快照失败 → 零改动 */
	fs_init(&sink, &s, "snap.rules");
	put_file(s.file, "path:/old/:file_read:allow\n");
	s.fail_snapshot = 1;
	CHECK(apol_apply_run(&sink, &p, &res, err, sizeof(err)) == -1,
	      "am-snapshot-fail");
	CHECK(strstr(err, "snapshot_failed") != NULL, "am-snapshot-code");
	CHECK(res.rules_applied == 0 && s.adds == 0, "am-snapshot-no-write");

	/* allow-all 策略直接拒绝（构造非法内存策略） */
	memset(&q, 0, sizeof(q));
	snprintf(q.schema, sizeof(q.schema), "%s", APOL_SCHEMA);
	q.rule_n = 1;
	q.rules[0].kind = APOL_KIND_PATH;
	q.rules[0].op = APOL_OP_FILE_READ;
	snprintf(q.rules[0].path_prefix, sizeof(q.rules[0].path_prefix), "/");
	fs_init(&sink, &s, "allowall.rules");
	CHECK(apol_apply_run(&sink, &q, &res, err, sizeof(err)) == -1,
	      "am-allowall-refused");
	CHECK(strstr(err, "allow_all_refused") != NULL,
	      "am-allowall-code");
	CHECK(s.adds == 0, "am-allowall-no-write");
}

/* ------------------------------------------------------------------ */
/* 7) 工具级                                                          */
/* ------------------------------------------------------------------ */

static int host_has_ai_lsm(char *raw, size_t cap);

static int tool_call(const char *name, const char *args, char **out, int *rc)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.name = (char *)name;
	t.channel = TOOL_CH_APPCTL;
	t.available = 1;
	*out = NULL;
	*rc = exec_app_policy_tool(name, args, out);
	return *rc;
}

static void test_tool_generate(void)
{
	char dynpath[700], statpath[700], argbuf[1200];
	char *out = NULL;
	int rc = 0;

	snprintf(dynpath, sizeof(dynpath), "%s/curl-dyn.json", g_tmp);
	snprintf(statpath, sizeof(statpath), "%s/curl-static.json", g_tmp);
	put_file(dynpath, k_curl_dyn);
	put_file(statpath, k_curl_static);

	snprintf(argbuf, sizeof(argbuf),
		 "{\"app\":\"/usr/bin/curl\",\"profile_dynamic\":\"@%.200s\","
		 "\"profile_static\":\"@%.200s\"}", dynpath, statpath);
	tool_call("app_policy_generate", argbuf, &out, &rc);
	CHECK(rc == 0, "tool-gen-rc");
	CHECK(out && strstr(out, "aik-app-policy/1") != NULL, "tool-gen-schema");
	CHECK(out && strstr(out, "\"because\":") != NULL, "tool-gen-because");
	CHECK(out && strstr(out, "\"rules\":") != NULL, "tool-gen-rules");
	emit("03-tool-generate.json", out);
	free(out);

	/* 缺参 */
	out = NULL;
	tool_call("app_policy_generate", "{}", &out, &rc);
	CHECK(rc < 0 && out && strstr(out, "MISSING") != NULL,
	      "tool-gen-missing");
	free(out);

	/* 坏动态画像 */
	out = NULL;
	tool_call("app_policy_generate",
		  "{\"app\":\"/usr/bin/curl\",\"profile_dynamic\":\"{}\"}",
		  &out, &rc);
	CHECK(rc < 0 && out && strstr(out, "BAD_DYNAMIC_PROFILE") != NULL,
	      "tool-gen-bad-dyn");
	free(out);

	/* 空画像：静态也拿不到（不存在的目标）+ 动态 0 事件 */
	out = NULL;
	tool_call("app_policy_generate",
		  "{\"app\":\"/nonexistent-aik-test/x\","
		  "\"profile_dynamic\":\"{\\\"events\\\":[]}\"}",
		  &out, &rc);
	CHECK(rc < 0 && out && strstr(out, "empty_profile") != NULL,
	      "tool-gen-empty-profile");
	free(out);
}

static int host_has_ai_lsm(char *raw, size_t cap)
{
	FILE *f = fopen("/sys/kernel/security/lsm", "r");
	char buf[512] = "";

	if (!f) {
		if (cap)
			snprintf(raw, cap, "(unreadable)");
		return -1;
	}
	if (!fgets(buf, sizeof(buf), f))
		buf[0] = 0;
	fclose(f);
	if (cap)
		snprintf(raw, cap, "%s", buf);
	{
		char tmp[512], *save = NULL, *tok;

		snprintf(tmp, sizeof(tmp), "%s", buf);
		for (tok = strtok_r(tmp, ",", &save); tok;
		     tok = strtok_r(NULL, ",", &save)) {
			while (*tok == ' ' || *tok == '	')
				tok++;
			if (strcmp(tok, "ai") == 0)
				return 1;
		}
	}
	return 0;
}

static void test_tool_apply(void)
{
	char *out = NULL;
	int rc = 0;
	char lsmraw[512] = "";
	char ppath[700], spath[700], argbuf[900];

	CHECK(host_has_ai_lsm(lsmraw, sizeof(lsmraw)) >= 0,
	      "apply-host-lsm-readable");

	/* 1) 真实策略 + 本机 apply：没有 ai LSM 必须 fail-closed 并报实际列表 */
	snprintf(ppath, sizeof(ppath), "%s/apply-curl.json", g_tmp);
	put_file(ppath,
		 "{\"schema\":\"aik-app-policy/1\",\"app_path\":"
		 "\"/usr/bin/curl\",\"label\":\"app-test\","
		 "\"label_id\":7,\"rules\":["
		 "{\"kind\":\"path\",\"op\":\"file_exec\","
		 "\"deny\":false,\"path_prefix\":\"/usr/bin/curl\","
		 "\"because\":\"策略主体：目标自身\"},"
		 "{\"kind\":\"path\",\"op\":\"file_read\","
		 "\"deny\":false,\"path_prefix\":\"/usr/lib/\","
		 "\"because\":\"动态画像事件 #1 读取\"},"
		 "{\"kind\":\"path\",\"op\":\"file_read\","
		 "\"deny\":false,\"path_prefix\":\"/lib/\","
		 "\"because\":\"动态画像事件 #2 读取\"},"
		 "{\"kind\":\"path\",\"op\":\"file_read\","
		 "\"deny\":false,\"path_prefix\":\"/etc/\","
		 "\"because\":\"动态画像事件 #3 读取\"},"
		 "{\"kind\":\"path\",\"op\":\"file_write\","
		 "\"deny\":false,\"path_prefix\":\"/tmp/\","
		 "\"because\":\"动态画像事件 #4 写入\"}"
		 "]}");
	snprintf(argbuf, sizeof(argbuf), "{\"policy\":\"@%.400s\"}", ppath);
	out = NULL;
	tool_call("app_policy_apply", argbuf, &out, &rc);
	CHECK(rc < 0, "tool-apply-rc-nonzero");
	if (host_has_ai_lsm(lsmraw, sizeof(lsmraw)) == 0) {
		CHECK(out && strstr(out, "\"refused\":true") != NULL,
		      "tool-apply-refused");
		CHECK(out && strstr(out, "no_ai_lsm") != NULL,
		      "tool-apply-no-ai-lsm");
		CHECK(out && strstr(out, "\"changed\":false") != NULL,
		      "tool-apply-unchanged");
		CHECK(out && strstr(out, "apparmor") != NULL,
		      "tool-apply-actual-lsm-listed");
		emit("04-apply-refused.json", out);
	} else {
		SKIP("tool-apply-no-ai-lsm",
		     "宿主 LSM 列表含 ai（本用例只在本机无 ai 时成立）");
	}
	free(out);

	/* 2) 敏感策略：先要求人工确认（不碰内核） */
	snprintf(spath, sizeof(spath), "%s/apply-sens.json", g_tmp);
	put_file(spath,
		 "{\"schema\":\"aik-app-policy/1\","
		 "\"requires_confirm\":true,\"rules\":["
		 "{\"kind\":\"path\",\"op\":\"file_read\","
		 "\"deny\":true,\"sensitive\":true,"
		 "\"requires_confirm\":true,"
		 "\"path_prefix\":\"/etc/shadow\","
		 "\"because\":\"命中 /etc/shadow\"}"
		 "]}");
	snprintf(argbuf, sizeof(argbuf), "{\"policy\":\"@%.400s\"}", spath);
	out = NULL;
	tool_call("app_policy_apply", argbuf, &out, &rc);
	CHECK(rc < 0 && out && strstr(out, "requires_confirmation") != NULL,
	      "tool-apply-needs-confirm");
	CHECK(out && strstr(out, "\"changed\":false") != NULL,
	      "tool-apply-confirm-unchanged");
	emit("05-apply-needs-confirm.json", out);
	free(out);

	/* 3) 坏策略（schema 不匹配） */
	snprintf(spath, sizeof(spath), "%s/apply-bad.json", g_tmp);
	put_file(spath, "{\"schema\":\"x\",\"rules\":[]}");
	snprintf(argbuf, sizeof(argbuf), "{\"policy\":\"@%.400s\"}", spath);
	out = NULL;
	tool_call("app_policy_apply", argbuf, &out, &rc);
	CHECK(rc < 0 && out && strstr(out, "schema") != NULL,
	      "tool-apply-bad-schema");
	free(out);

	/* 4) 缺参 */
	out = NULL;
	tool_call("app_policy_apply", "{}", &out, &rc);
	CHECK(rc < 0 && out && strstr(out, "MISSING") != NULL,
	      "tool-apply-missing");
	free(out);
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	int i;
	char env[1024];

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--emit") == 0 && i + 1 < argc)
			g_emit = argv[++i];
	}
	mk_tmp();
	if (g_emit) {
		mkdir(g_emit, 0755);
		snprintf(env, sizeof(env),
			 "uname: %s\n", "linux");
		emit("00-env.txt", env);
	}
	printf("== test_app_policy (W82 V4.5) ==\n");
	test_anchors();
	test_sensitive();
	test_path_rules();
	test_op_label();
	test_generate_curl();
	test_generate_sensitive();
	test_generate_edges();
	test_policy_parse();
	test_render_roundtrip();
	test_probes();
	test_apply_machine();
	test_tool_generate();
	test_tool_apply();
	{
		char path[700];

		snprintf(path, sizeof(path), "%s/lsm-actual", g_tmp);
		if (put_file(path, "") == 0)
			unlink(path);
	}
	rm_rf(g_tmp);
	printf("\nchecks=%d fails=%d skips=%d\n", checks, fails, skips);
	if (fails)
		printf("RESULT: FAIL\n");
	else
		printf("RESULT: PASS\n");
	return fails ? 1 : 0;
}
