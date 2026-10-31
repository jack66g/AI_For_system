/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
/*
 * test_net_intent - W81 V3.1 网络意图 ↔ nft 双向编译单测
 *
 * 默认（非 root）：纯函数 + 注入拒绝 + 空/畸形/截断 JSON 摘要 + 诚实错误，
 *                 零 side effect（不建表、不改规则、不写内核）。
 * --live（root + 必须已在 ip netns add aiktest 内 + AIK_TEST_NETNS=1）：
 *                 真实下发/回读/命中计数/确认保留/超时自动回滚/手动回滚。
 *                 未在指定 netns 内一律拒绝运行——绝不在宿主默认 ns 上
 *                 应用任何 nft 规则。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../tools/tool_registry.h"
#include "../tools/net_intent.h"

static int fails = 0;
static int skips = 0;

#define CHECK(cond, name) do { \
	if (cond) { printf("ok %s\n", name); } \
	else { printf("FAIL %s\n", name); fails++; } \
} while (0)

#define SKIP(name, why) do { \
	printf("skip %s（%s）\n", name, why); skips++; \
} while (0)

/* ===================== 纯函数：表名 ===================== */
static void test_table_name(void)
{
	CHECK(ni_valid_table("aik_intent") == 1, "table-ok");
	CHECK(ni_valid_table("a") == 1, "table-1char");
	CHECK(ni_valid_table("_x") == 1, "table-underscore");
	CHECK(ni_valid_table("Aik") == 0, "table-upper-rej");
	CHECK(ni_valid_table("") == 0, "table-empty-rej");
	CHECK(ni_valid_table("1234") == 0, "table-digitstart-rej");
	CHECK(ni_valid_table("a-b") == 0, "table-dash-rej");
	CHECK(ni_valid_table("a b") == 0, "table-space-rej");
	CHECK(ni_valid_table("aik_intent_1234567") == 0, "table-16-rej");
	CHECK(ni_valid_table("aik_intent_1234") == 1, "table-15-ok");
	CHECK(ni_valid_table("t;flush") == 0, "table-semicolon-rej");
}

/* ===================== 意图解析 ===================== */
static void parse_ok(const char *intent, const char *allow, const char *deny,
		     const char *pol, const char *proto, const char *dir,
		     struct ni_intent *out)
{
	char err[512] = "";

	int rc = ni_parse_intent(intent, allow, deny, pol, proto, dir, NULL,
				 out, err, sizeof(err));

	if (rc != 0) {
		printf("  parse error: %s\n", err);
		CHECK(0, "parse-should-succeed");
		return;
	}
	CHECK(1, "parse-ok");
}

static void test_intent_parse(void)
{
	struct ni_intent in;
	char err[512];

	/* 典型一句话：只允许 22 端口进来，其他全拒 */
	parse_ok("只允许 22 端口进来，其他全拒", NULL, NULL, NULL, NULL, NULL,
		 &in);
	CHECK(in.rule_n == 1, "zh-1rule");
	CHECK(in.rule_n == 1 && in.rule[0].act == NI_ALLOW &&
	      in.rule[0].proto == NI_PROTO_TCP && in.rule[0].lo == 22 &&
	      in.rule[0].hi == 22, "zh-allow-tcp22");
	CHECK(in.policy == NI_POLICY_DROP && in.has_policy == 1, "zh-policy-drop");
	CHECK(in.dir == NI_DIR_IN, "zh-dir-in");
	CHECK(strcmp(in.table, "aik_intent") == 0, "zh-default-table");

	/* 放行 + 拒绝 混合 → 显式黑名单语义 accept */
	parse_ok("放行 80,443 拒绝 8080", NULL, NULL, NULL, NULL, NULL, &in);
	CHECK(in.rule_n == 3, "mix-3rules");
	CHECK(in.rule[0].act == NI_ALLOW && in.rule[0].lo == 80, "mix-allow80");
	CHECK(in.rule[1].act == NI_ALLOW && in.rule[1].lo == 443, "mix-allow443");
	CHECK(in.rule[2].act == NI_DENY && in.rule[2].lo == 8080, "mix-deny8080");
	CHECK(in.policy == NI_POLICY_ACCEPT, "mix-policy-accept");

	/* 英文 + 协议后缀 */
	parse_ok("allow 53/udp default deny", NULL, NULL, NULL, NULL, NULL, &in);
	CHECK(in.rule_n == 1 && in.rule[0].proto == NI_PROTO_UDP &&
	      in.rule[0].lo == 53, "en-udp53");
	CHECK(in.policy == NI_POLICY_DROP, "en-default-deny");

	/* 区间 */
	parse_ok("允许 1000-2000/tcp", NULL, NULL, NULL, NULL, NULL, &in);
	CHECK(in.rule_n == 1 && in.rule[0].lo == 1000 && in.rule[0].hi == 2000,
	      "range-1000-2000");

	/* 只有拒绝 → accept */
	parse_ok("拒绝 53/udp", NULL, NULL, NULL, NULL, NULL, &in);
	CHECK(in.rule_n == 1 && in.rule[0].act == NI_DENY &&
	      in.rule[0].proto == NI_PROTO_UDP, "deny-only-rule");
	CHECK(in.policy == NI_POLICY_ACCEPT, "deny-only-policy-accept");

	/* 出站方向 */
	parse_ok("只允许 22 端口出去，其他全拒", NULL, NULL, NULL, NULL, NULL,
		 &in);
	CHECK(in.dir == NI_DIR_OUT, "dir-out");

	/* 结构化参数（意图为空） */
	parse_ok("", "22,443/udp", "8080", "drop", "tcp", "in", &in);
	CHECK(in.rule_n == 3, "struct-3rules");
	CHECK(in.rule[0].lo == 22 && in.rule[0].proto == NI_PROTO_TCP,
	      "struct-tcp22");
	CHECK(in.rule[1].lo == 443 && in.rule[1].proto == NI_PROTO_UDP,
	      "struct-udp443");
	CHECK(in.rule[2].act == NI_DENY && in.rule[2].lo == 8080,
	      "struct-deny8080");

	/* 端口去重 */
	parse_ok("允许 22,22 22", NULL, NULL, NULL, NULL, NULL, &in);
	CHECK(in.rule_n == 1, "dedupe-22");

	/* 中文顿号 / 分号分隔 */
	parse_ok("允许 80、443；8080-8090", NULL, NULL, NULL, NULL, NULL, &in);
	CHECK(in.rule_n == 3, "cjk-separators");

	/* ICMP */
	parse_ok("允许 icmp", NULL, NULL, NULL, NULL, NULL, &in);
	CHECK(in.rule_n == 1 && in.rule[0].proto == NI_PROTO_ICMP,
	      "icmp-rule");

	/* 隐式允许（端口前无动词）在预览里要标注 */
	parse_ok("22,443 其他全拒", NULL, NULL, NULL, NULL, NULL, &in);
	CHECK(in.implicit_allow == 1, "implicit-allow-flagged");

	/* ---- 拒绝路径 ---- */
	memset(&in, 0, sizeof(in));
	CHECK(ni_parse_intent("", NULL, NULL, NULL, NULL, NULL, NULL, &in, err,
			      sizeof(err)) != 0, "empty-rej");
	CHECK(ni_parse_intent("随便说点什么", NULL, NULL, NULL, NULL, NULL,
			      NULL, &in, err, sizeof(err)) != 0, "noport-rej");
	CHECK(ni_parse_intent("允许 70000", NULL, NULL, NULL, NULL, NULL, NULL,
			      &in, err, sizeof(err)) != 0, "port-70000-rej");
	CHECK(ni_parse_intent("允许 0", NULL, NULL, NULL, NULL, NULL, NULL,
			      &in, err, sizeof(err)) != 0, "port-0-rej");
	CHECK(ni_parse_intent("允许 90-80", NULL, NULL, NULL, NULL, NULL, NULL,
			      &in, err, sizeof(err)) != 0, "range-inverted-rej");
	CHECK(ni_parse_intent("", "1-abc", NULL, NULL, NULL, NULL, NULL, &in,
			      err, sizeof(err)) != 0, "struct-junk-rej");
	CHECK(ni_parse_intent("", NULL, NULL, "maybe", NULL, NULL, NULL, &in,
			      err, sizeof(err)) != 0, "policy-enum-rej");
	CHECK(ni_parse_intent("", NULL, NULL, NULL, "sctp", NULL, NULL, &in,
			      err, sizeof(err)) != 0, "proto-enum-rej");
	CHECK(ni_parse_intent("允许 22", NULL, NULL, NULL, NULL, "sideways",
			      NULL, &in, err, sizeof(err)) != 0,
	      "dir-enum-rej");
	CHECK(ni_parse_intent("允许 22", NULL, NULL, NULL, NULL, NULL,
			      "Bad-Table", &in, err, sizeof(err)) != 0,
	      "table-rej");
	CHECK(ni_parse_intent("允许 22", NULL, NULL, NULL, NULL, NULL,
			      "t;flush ruleset", &in, err, sizeof(err)) != 0,
	      "table-inject-rej");
}

/* ===================== 编译 ===================== */
static void test_compile(void)
{
	struct ni_intent in;
	char err[512];
	char buf[NI_TEXT_MAX];
	const char *want;

	memset(&in, 0, sizeof(in));
	CHECK(ni_parse_intent("只允许 22 端口进来，其他全拒", NULL, NULL, NULL,
			      NULL, NULL, NULL, &in, err, sizeof(err)) == 0,
	      "cmp-parse");
	CHECK(ni_compile(&in, buf, sizeof(buf)) == 0, "cmp-compile");
	want =
		"table inet aik_intent {\n"
		"\tchain input {\n"
		"\t\ttype filter hook input priority filter; policy drop;\n"
		"\t\tct state established,related accept\n"
		"\t\tiif \"lo\" accept\n"
		"\t\ttcp dport 22 accept\n"
		"\t\tcounter drop\n"
		"\t}\n"
		"}\n";
	CHECK(strcmp(buf, want) == 0, "cmp-exact-text");
	if (strcmp(buf, want) != 0)
		printf("---- got ----\n%s---- want ----\n%s", buf, want);

	/* 白名单 + deny 混合 → policy accept，无 counter drop 兜底 */
	memset(&in, 0, sizeof(in));
	CHECK(ni_parse_intent("放行 22 拒绝 8080", NULL, NULL, NULL, NULL, NULL,
			      NULL, &in, err, sizeof(err)) == 0, "cmp2-parse");
	CHECK(ni_compile(&in, buf, sizeof(buf)) == 0, "cmp2-compile");
	CHECK(strstr(buf, "policy accept;") != NULL, "cmp2-policy-accept");
	CHECK(strstr(buf, "tcp dport 8080 drop") != NULL, "cmp2-deny-rule");
	CHECK(strstr(buf, "counter drop") == NULL, "cmp2-no-terminal-drop");

	/* 出站 */
	memset(&in, 0, sizeof(in));
	CHECK(ni_parse_intent("允许 443 出去", NULL, NULL, NULL, NULL, NULL,
			      NULL, &in, err, sizeof(err)) == 0, "out-parse");
	CHECK(ni_compile(&in, buf, sizeof(buf)) == 0, "out-compile");
	CHECK(strstr(buf, "chain output") != NULL &&
	      strstr(buf, "hook output") != NULL &&
	      strstr(buf, "oif \"lo\" accept") != NULL, "out-chain");

	/* 注入面：意图里的 shell 元字符不得进入规则文本 */
	memset(&in, 0, sizeof(in));
	CHECK(ni_parse_intent("允许 22; reboot now `id` $(id) && rm -rf /",
			      NULL, NULL, NULL, NULL, NULL, NULL, &in, err,
			      sizeof(err)) == 0, "inject-parse");
	CHECK(ni_compile(&in, buf, sizeof(buf)) == 0, "inject-compile");
	CHECK(strstr(buf, "reboot") == NULL && strstr(buf, "rm -rf") == NULL &&
	      strstr(buf, "`") == NULL && strstr(buf, "$(") == NULL,
	      "inject-not-in-ruleset");

	/* 区间编译 */
	memset(&in, 0, sizeof(in));
	CHECK(ni_parse_intent("允许 8080-8090/tcp", NULL, NULL, NULL, NULL,
			      NULL, NULL, &in, err, sizeof(err)) == 0,
	      "range-parse");
	CHECK(ni_compile(&in, buf, sizeof(buf)) == 0, "range-compile");
	CHECK(strstr(buf, "tcp dport 8080-8090 accept") != NULL,
	      "range-compiled");

	/* 缓冲不足必须报错而不是截断后当真 */
	memset(&in, 0, sizeof(in));
	CHECK(ni_parse_intent("允许 22", NULL, NULL, NULL, NULL, NULL, NULL,
			      &in, err, sizeof(err)) == 0, "tiny-parse");
	CHECK(ni_compile(&in, buf, 20) != 0, "compile-trunc-detected");
}

/* ===================== 摘要 ===================== */
static const char *FX_EMPTY =
	"{\"nftables\": [{\"metainfo\": {\"version\": \"1.0.2\", "
	"\"release_name\": \"Lester Gooch\", \"json_schema_version\": 1}}]}";

static const char *FX_FULL =
	"{\"nftables\": ["
	"{\"metainfo\": {\"version\": \"1.0.2\"}},"
	"{\"table\": {\"family\": \"inet\", \"name\": \"aik_intent\", "
	"\"handle\": 1}},"
	"{\"chain\": {\"family\": \"inet\", \"table\": \"aik_intent\", "
	"\"name\": \"input\", \"handle\": 1, \"type\": \"filter\", "
	"\"hook\": \"input\", \"prio\": 0, \"policy\": \"drop\"}},"
	"{\"rule\": {\"family\": \"inet\", \"table\": \"aik_intent\", "
	"\"chain\": \"input\", \"handle\": 2, \"expr\": ["
	"{\"match\": {\"op\": \"in\", \"left\": {\"ct\": {\"key\": "
	"\"state\"}}, \"right\": [\"established\", \"related\"]}},"
	"{\"accept\": null}]}},"
	"{\"rule\": {\"family\": \"inet\", \"table\": \"aik_intent\", "
	"\"chain\": \"input\", \"handle\": 3, \"expr\": ["
	"{\"match\": {\"op\": \"==\", \"left\": {\"meta\": {\"key\": "
	"\"iif\"}}, \"right\": \"lo\"}}, {\"accept\": null}]}},"
	"{\"rule\": {\"family\": \"inet\", \"table\": \"aik_intent\", "
	"\"chain\": \"input\", \"handle\": 4, \"expr\": ["
	"{\"match\": {\"op\": \"==\", \"left\": {\"payload\": {\"protocol\": "
	"\"tcp\", \"field\": \"dport\"}}, \"right\": 22}}, "
	"{\"accept\": null}]}},"
	"{\"rule\": {\"family\": \"inet\", \"table\": \"aik_intent\", "
	"\"chain\": \"input\", \"handle\": 5, \"expr\": ["
	"{\"match\": {\"op\": \"==\", \"left\": {\"payload\": {\"protocol\": "
	"\"tcp\", \"field\": \"dport\"}}, \"right\": {\"range\": [8080, "
	"8090]}}}, {\"accept\": null}]}},"
	"{\"rule\": {\"family\": \"inet\", \"table\": \"aik_intent\", "
	"\"chain\": \"input\", \"handle\": 6, \"expr\": ["
	"{\"match\": {\"op\": \"==\", \"left\": {\"payload\": {\"protocol\": "
	"\"ip\", \"field\": \"saddr\"}}, \"right\": {\"prefix\": {\"addr\": "
	"\"10.0.0.0\", \"len\": 8}}}}, {\"counter\": {\"packets\": 7, "
	"\"bytes\": 900}}, {\"drop\": null}]}},"
	"{\"table\": {\"family\": \"ip\", \"name\": \"nat2\", \"handle\": 2}},"
	"{\"chain\": {\"family\": \"ip\", \"table\": \"nat2\", \"name\": "
	"\"post\", \"handle\": 1, \"type\": \"nat\", \"hook\": "
	"\"postrouting\", \"prio\": 100, \"policy\": \"accept\"}},"
	"{\"rule\": {\"family\": \"ip\", \"table\": \"nat2\", \"chain\": "
	"\"post\", \"handle\": 2, \"expr\": ["
	"{\"match\": {\"op\": \"==\", \"left\": {\"meta\": {\"key\": "
	"\"oifname\"}}, \"right\": \"eth0\"}},"
	"{\"masquerade\": null}]}}"
	"]}";

static void test_summarize(void)
{
	char out[65536];
	char err[512];

	/* 空规则集 */
	memset(out, 0, sizeof(out));
	CHECK(ni_summarize(FX_EMPTY, NULL, out, sizeof(out), err,
			   sizeof(err)) == 0, "sum-empty-ok");
	CHECK(strstr(out, "规则集为空") != NULL, "sum-empty-text");
	CHECK(strstr(out, "== 默认策略 ==") != NULL, "sum-empty-sections");

	/* 完整规则集 */
	memset(out, 0, sizeof(out));
	CHECK(ni_summarize(FX_FULL, NULL, out, sizeof(out), err,
			   sizeof(err)) == 0, "sum-full-ok");
	CHECK(strstr(out, "policy=drop") != NULL, "sum-full-policy");
	CHECK(strstr(out, "未匹配流量一律丢弃") != NULL, "sum-full-policy-text");
	CHECK(strstr(out, "连接状态 属于 {established, related}") != NULL,
	      "sum-ct-state");
	CHECK(strstr(out, "入接口 \"lo\"") != NULL, "sum-iif");
	CHECK(strstr(out, "TCP 目的端口 22") != NULL, "sum-tcp22");
	CHECK(strstr(out, "TCP 目的端口 8080-8090") != NULL, "sum-range");
	CHECK(strstr(out, "IPv4 源地址 10.0.0.0/8") != NULL, "sum-prefix");
	CHECK(strstr(out, "计数 7 包/900 字节") != NULL, "sum-counter");
	CHECK(strstr(out, "SNAT 伪装") != NULL, "sum-masquerade");
	CHECK(strstr(out, "出接口名 \"eth0\"") != NULL, "sum-oifname");
	CHECK(strstr(out, "小结：2 表 / 2 链 / 6 规则") != NULL, "sum-counts");
	CHECK(strstr(out, "允许 4 条，拒绝 1 条，其他 1 条") != NULL,
	      "sum-verdicts");

	/* 只摘一张表 */
	memset(out, 0, sizeof(out));
	CHECK(ni_summarize(FX_FULL, "nat2", out, sizeof(out), err,
			   sizeof(err)) == 0, "sum-filter-ok");
	CHECK(strstr(out, "SNAT 伪装") != NULL &&
	      strstr(out, "aik_intent") == NULL, "sum-filter-only");
	memset(out, 0, sizeof(out));
	CHECK(ni_summarize(FX_FULL, "nope", out, sizeof(out), err,
			   sizeof(err)) == 0, "sum-filter-miss-ok");
	CHECK(strstr(out, "指定表 nope 不存在") != NULL, "sum-filter-miss-text");

	/* 异常输入：一律报错不崩 */
	CHECK(ni_summarize("", NULL, out, sizeof(out), err, sizeof(err)) != 0,
	      "sum-empty-input-rej");
	CHECK(ni_summarize("{not json", NULL, out, sizeof(out), err,
			   sizeof(err)) != 0, "sum-badjson-rej");
	CHECK(ni_summarize("\"nftables\":{}", NULL, out, sizeof(out), err,
			   sizeof(err)) != 0, "sum-notarray-rej");
	CHECK(ni_summarize("{\"x\":1}", NULL, out, sizeof(out), err,
			   sizeof(err)) != 0, "sum-nokey-rej");
	{
		char trunc[512];

		snprintf(trunc, sizeof(trunc), "%.*s", 120, FX_FULL);
		CHECK(ni_summarize(trunc, NULL, out, sizeof(out), err,
				   sizeof(err)) != 0, "sum-truncated-rej");
	}
	{
		char deep[2048];
		int i, n = 0;

		for (i = 0; i < 200 && n < (int)sizeof(deep) - 2; i++)
			deep[n++] = '[';
		deep[n] = '\0';
		CHECK(ni_summarize(deep, NULL, out, sizeof(out), err,
				   sizeof(err)) != 0, "sum-deep-rej");
	}
	{
		const char *nonobj =
			"{\"nftables\":[1,\"x\",null,{\"table\":{\"family\":"
			"\"inet\",\"name\":\"t\",\"handle\":1}}]}";

		memset(out, 0, sizeof(out));
		CHECK(ni_summarize(nonobj, NULL, out, sizeof(out), err,
				   sizeof(err)) == 0, "sum-nonobj-ok");
		CHECK(strstr(out, "跳过 3 个非对象数组元素") != NULL,
		      "sum-nonobj-count");
	}
	/* 超小缓冲不得越界/不崩 */
	{
		char tiny[48];

		CHECK(ni_summarize(FX_FULL, NULL, tiny, sizeof(tiny), err,
				   sizeof(err)) == 0, "sum-tiny-buf-ok");
	}
}

/* ===================== digest / diff ===================== */
static void test_digest_diff(void)
{
	char a[17], b[17], c[17];
	char diff[NI_TEXT_MAX];

	ni_digest("hello", a);
	ni_digest("hello", b);
	ni_digest("hellp", c);
	CHECK(strlen(a) == 16, "digest-len");
	CHECK(strcmp(a, b) == 0, "digest-stable");
	CHECK(strcmp(a, c) != 0, "digest-differs");

	/* 空 → 全新增 */
	CHECK(ni_diff("", "table inet t {\n}\n", diff, sizeof(diff)) == 0,
	      "diff-ok");
	CHECK(strstr(diff, "+ table inet t {") != NULL, "diff-add-line");
	CHECK(strstr(diff, "\n- ") == NULL, "diff-no-removal");

	/* 相同 → 无增删 */
	CHECK(ni_diff("a\nb\n", "a\nb\n", diff, sizeof(diff)) == 0,
	      "diff-same-ok");
	CHECK(strstr(diff, "\n+ ") == NULL && strstr(diff, "\n- ") == NULL,
	      "diff-same-nochange");

	/* counter 计数归一：packets/bytes 不同不算差异 */
	CHECK(ni_diff("counter packets 0 bytes 0 drop",
		      "counter drop", diff, sizeof(diff)) == 0,
	      "diff-counter-ok");
	CHECK(strstr(diff, "\n+ ") == NULL && strstr(diff, "\n- ") == NULL,
	      "diff-counter-normalized");
}

/* ===================== 通道分发 / 诚实错误 ===================== */
static void call(const char *name, const char *args, char **out, int *rc)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.channel = TOOL_CH_NETINTENT;
	t.risk = "W2";
	t.name = (char *)name;
	*rc = exec_net_intent_channel(&t, args, out);
}

static void test_dispatch(void)
{
	char *out = NULL;
	int rc;

	call("nft_bogus", "{}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "dispatch-unknown-rej");
	free(out); out = NULL;

	/* 参数缺失 */
	call("nft_intent_compile", "{}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "意图为空"), "compile-empty-rej");
	free(out); out = NULL;
	call("nft_intent_confirm", "{}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "action"), "confirm-noaction-rej");
	free(out); out = NULL;
	call("nft_intent_confirm", "{\"action\":\"explode\"}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "confirm 或 rollback"),
	      "confirm-badaction-rej");
	free(out); out = NULL;

	/* compile 只读：任何 uid 都应成功且明确"未下发" */
	call("nft_intent_compile",
	     "{\"intent\":\"只允许 22 端口进来，其他全拒\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "未下发任何规则") &&
	      strstr(out, "tcp dport 22 accept") != NULL,
	      "compile-readonly-ok");
	if (out && strstr(out, "语法预检：通过") == NULL &&
	    geteuid() != 0)
		CHECK(strstr(out, "不可用") != NULL, "compile-nonroot-preflight");
	free(out); out = NULL;

	/* 锁死闸：apply 无 root 时先报权限；root 且非 --live 时本用例必须
	 * 先于调用跳过——绝不能在宿主默认 ns 上真的下发（硬约束）。 */
	if (geteuid() != 0) {
		call("nft_intent_apply",
		     "{\"intent\":\"只允许 22 端口进来，其他全拒\"}", &out,
		     &rc);
		CHECK(rc != 0 && out &&
		      strstr(out, "root/CAP_NET_ADMIN") != NULL,
		      "apply-nonroot-rej");
		free(out); out = NULL;
	} else {
		SKIP("apply-root-nonlive", "拒绝在非 netns 环境实际下发");
	}

	/* 锁死闸：默认拒绝且不放行 22 → 无论 uid 都必须拒绝（root 下也先撞
	 * 这个闸之前会先过 root 检查，故仅非 root 时可断言；root 用 --live
	 * 覆盖） */
	if (geteuid() != 0) {
		call("nft_intent_apply",
		     "{\"intent\":\"只允许 443 端口进来，其他全拒\"}",
		     &out, &rc);
		CHECK(rc != 0 && out && strstr(out, "root/CAP_NET_ADMIN"),
		      "apply-lockout-order");
		free(out); out = NULL;
	}

	/* summarize：nft 不可用/无权限时诚实报错，不崩 */
	call("nft_ruleset_summarize", "{}", &out, &rc);
	if (geteuid() != 0) {
		CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
		      "summarize-nonroot-honest");
	} else {
		CHECK(rc == 0 && out && strstr(out, "默认策略") != NULL,
		      "summarize-root-ok");
	}
	free(out); out = NULL;

	/* 非法 table 参数 */
	call("nft_ruleset_summarize", "{\"table\":\"A;B\"}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "summarize-badtable-rej");
	free(out); out = NULL;
}

/* ===================== live（netns 内真下发） ===================== */

static int in_named_netns(const char *name)
{
	char path[128];
	struct stat a, b;

	snprintf(path, sizeof(path), "/var/run/netns/%s", name);
	if (stat(path, &a) != 0)
		return 0;
	if (stat("/proc/self/ns/net", &b) != 0)
		return 0;
	return a.st_ino == b.st_ino;
}

/* 读表里 counter 的 packets 数（-1=没找到 counter 行） */
static long long table_drop_packets(const char *tbl)
{
	char path[64], cmd[256], line[512];
	FILE *f;
	long long pk = -1;

	snprintf(path, sizeof(path), "/tmp/aik-w81-list-%d.txt",
		 (int)getpid());
	snprintf(cmd, sizeof(cmd), "nft list table inet %s > %s 2>&1",
		 tbl, path);
	(void)system(cmd);
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *p = strstr(line, "counter packets ");

		if (p) {
			pk = strtoll(p + 16, NULL, 10);
			break;
		}
	}
	fclose(f);
	unlink(path);
	return pk;
}

static int udp_send_to(const char *dst, int port, const char *bindaddr)
{
	int fd, rc;
	struct sockaddr_in to;
	struct sockaddr_in from;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons((unsigned short)port);
	if (inet_pton(AF_INET, dst, &to.sin_addr) != 1)
		return -1;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	if (bindaddr) {
		memset(&from, 0, sizeof(from));
		from.sin_family = AF_INET;
		from.sin_port = 0;
		if (inet_pton(AF_INET, bindaddr, &from.sin_addr) != 1 ||
		    bind(fd, (struct sockaddr *)&from, sizeof(from)) != 0) {
			close(fd);
			return -1;
		}
	}
	rc = (int)sendto(fd, "w81", 3, 0, (struct sockaddr *)&to,
			 sizeof(to));
	close(fd);
	return rc < 0 ? -1 : 0;
}

static int run_live(void)
{
	char *out = NULL;
	int rc, i;
	char args[1024];
	char logpath[512];
	long long pk0, pk1;

	printf("== LIVE（netns aiktest）==\n");

	/* 0) 安全前置：必须确实在指定 netns 内 */
	if (in_named_netns("aiktest") != 1) {
		printf("REFUSE: 当前进程不在 netns aiktest 内，"
		       "拒绝执行任何 nft 下发\n");
		return 2;
	}
	if (geteuid() != 0) {
		printf("REFUSE: --live 需要 root\n");
		return 2;
	}

	/* 1) 编译（只读） */
	snprintf(args, sizeof(args),
		 "{\"intent\":\"只允许 22 端口进来，其他全拒\","
		 "\"table\":\"aik_intent\"}");
	call("nft_intent_compile", args, &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "语法预检：通过") != NULL,
	      "live-compile-preflight");
	CHECK(out && strstr(out, "policy drop") != NULL, "live-compile-policy");
	if (out)
		printf("---- compile 输出（前 12 行）----\n%.900s\n", out);
	free(out); out = NULL;

	/* 2) 下发（窗口 90 秒，足够人工确认；命中计数后再 confirm） */
	snprintf(args, sizeof(args),
		 "{\"intent\":\"只允许 22 端口进来，其他全拒\","
		 "\"table\":\"aik_intent\",\"arm_seconds\":90}");
	call("nft_intent_apply", args, &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "状态=armed") != NULL,
	      "live-apply-ok");
	(void)system("nft list table inet aik_intent "
		     "> /tmp/aik-w81-apply-read.txt 2>&1");
	CHECK(system("grep -q 'policy drop' /tmp/aik-w81-apply-read.txt") == 0,
	      "live-apply-policy-drop");
	CHECK(system("grep -q 'tcp dport 22 accept' "
		     "/tmp/aik-w81-apply-read.txt") == 0,
	      "live-apply-rule-present");

	/* 2b) 读回原文 + 输入侧真实命中（peer netns 打流 → counter 递增） */
	{
		FILE *f = fopen("/tmp/aik-w81-apply-read.txt", "r");
		char line[512];

		if (f) {
			printf("---- aiktest 读回（nft list table inet "
			       "aik_intent）----\n");
			while (fgets(line, sizeof(line), f))
				fputs(line, stdout);
			fclose(f);
		}
	}
	if (getenv("AIK_W81_PEER")) {
		long long b0 = table_drop_packets("aik_intent");
		long long b1;

		(void)system("ip netns exec aikw81peer ping -c 3 -W 1 "
			     "-i 0.3 10.99.0.1 >/dev/null 2>&1");
		(void)usleep(300000);
		b1 = table_drop_packets("aik_intent");
		printf("  input 命中计数：before=%lld after=%lld\n", b0, b1);
		CHECK(b0 >= 0 && b1 > b0, "live-input-hit-counter");
	} else {
		SKIP("live-input-hit-counter", "未设 AIK_W81_PEER");
	}
	free(out); out = NULL;

	/* 3) 命中：dummy 出接口 + out 链白名单，UDP 打非本地地址必然被 drop */
	snprintf(args, sizeof(args),
		 "{\"intent\":\"只允许 9999/udp 出去，其他全拒\","
		 "\"table\":\"aik_hit\",\"dir\":\"out\","
		 "\"arm_seconds\":90}");
	call("nft_intent_apply", args, &out, &rc);
	CHECK(rc == 0, "live-hit-apply");
	free(out); out = NULL;
	(void)system("ip link add aikd0 type dummy 2>/dev/null; "
		     "ip link set aikd0 up 2>/dev/null; "
		     "ip addr add 10.99.0.1/24 dev aikd0 2>/dev/null");
	pk0 = table_drop_packets("aik_hit");
	for (i = 0; i < 3; i++)
		(void)udp_send_to("10.99.0.99", 5555, "10.99.0.1");
	usleep(200000);
	pk1 = table_drop_packets("aik_hit");
	printf("  命中计数：before=%lld after=%lld\n", pk0, pk1);
	CHECK(pk0 >= 0 && pk1 > pk0, "live-hit-counter-increased");

	/* 4) 确认：窗口内 confirm 后规则保留 */
	call("nft_intent_confirm",
	     "{\"action\":\"confirm\",\"table\":\"aik_hit\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "已确认") != NULL,
	      "live-confirm-ok");
	free(out); out = NULL;
	sleep(2);
	CHECK(system("nft list table inet aik_hit > /dev/null 2>&1") == 0,
	      "live-confirm-kept");
	/* 确认后看门狗不得再回滚 */
	sleep(3);
	CHECK(system("nft list table inet aik_hit > /dev/null 2>&1") == 0,
	      "live-confirm-no-later-rollback");

	/* 4b) 手动回滚 */
	call("nft_intent_confirm",
	     "{\"action\":\"rollback\",\"table\":\"aik_hit\"}", &out, &rc);
	CHECK(rc == 0, "live-manual-rollback-ok");
	free(out); out = NULL;
	CHECK(system("nft list table inet aik_hit > /dev/null 2>&1") != 0,
	      "live-manual-rollback-gone");

	/* 5) 超时自动回滚：窗口 10 秒，不确认 */
	snprintf(args, sizeof(args),
		 "{\"intent\":\"只允许 22 端口进来，其他全拒\","
		 "\"table\":\"aik_auto\",\"arm_seconds\":10}");
	call("nft_intent_apply", args, &out, &rc);
	CHECK(rc == 0, "live-auto-apply");
	free(out); out = NULL;
	CHECK(system("nft list table inet aik_auto > /dev/null 2>&1") == 0,
	      "live-auto-present");
	printf("  等待 13 秒观察自动回滚…\n");
	sleep(13);
	CHECK(system("nft list table inet aik_auto > /dev/null 2>&1") != 0,
	      "live-auto-rolled-back");
	{
		const char *sdir = getenv("AIKERNEL_NFT_INTENT_DIR");
		FILE *f;

		snprintf(logpath, sizeof(logpath), "%s/t-aik_auto/rollback.log",
			 sdir && *sdir ? sdir : "/run/aik-nft-intent");
		f = fopen(logpath, "r");
		char line[1024];
		int saw = 0;

		if (f) {
			while (fgets(line, sizeof(line), f))
				if (strstr(line, "自动回滚完成"))
					saw = 1;
			fclose(f);
		}
		CHECK(saw, "live-auto-log");
	}

	/* 6) 反向摘要（真实规则集） */
	call("nft_ruleset_summarize", "{\"table\":\"aik_intent\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "== 默认策略 ==") != NULL &&
	      strstr(out, "TCP 目的端口 22") != NULL, "live-summarize");
	if (out)
		printf("---- summarize 输出 ----\n%s\n", out);
	free(out); out = NULL;

	/* 7) 收尾：先回滚会话（关掉 90 秒看门狗），再删表/设备 */
	call("nft_intent_confirm",
	     "{\"action\":\"rollback\",\"table\":\"aik_intent\"}", &out, &rc);
	printf("  收尾回滚 aik_intent rc=%d\n", rc);
	free(out); out = NULL;
	(void)system("nft delete table inet aik_intent 2>/dev/null; "
		     "nft delete table inet aik_hit 2>/dev/null; "
		     "nft delete table inet aik_auto 2>/dev/null; "
		     "ip link del aikd0 2>/dev/null");
	return 0;
}

int main(int argc, char **argv)
{
	int live = (argc > 1 && strcmp(argv[1], "--live") == 0);

	printf("== test_net_intent (uid=%u, live=%d) ==\n",
	       (unsigned)geteuid(), live);
	test_table_name();
	test_intent_parse();
	test_compile();
	test_summarize();
	test_digest_diff();
	test_dispatch();
	if (live) {
		const char *env = getenv("AIK_TEST_NETNS");

		if (!env || strcmp(env, "1") != 0) {
			printf("REFUSE: --live 需要 AIK_TEST_NETNS=1 "
			       "且在 ip netns aiktest 内运行\n");
			return 2;
		}
		if (run_live() != 0)
			return 2;
	} else {
		printf("（未跑 live：netns 真下发用 --live + "
		       "AIK_TEST_NETNS=1）\n");
	}
	if (fails) {
		printf("FAILURES: %d (skips=%d)\n", fails, skips);
		return 1;
	}
	printf("ALL PASS (skips=%d)\n", skips);
	return 0;
}
