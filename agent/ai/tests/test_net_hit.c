/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_net_hit.c - W81 V3.2 规则命中观测闭环单测
 *
 * 非 root（run_all 默认）：
 *   - 配置解析/校验（阈值/窗口/interval 关系/level/src/chain/handle）
 *   - 滑动窗口累计与冷却判定（纯函数）
 *   - nft -a list chain 文本解析（handle 精确匹配、counter 剥离、
 *     多行/跳转/语句分隔符拒绝）
 *   - ni_ruleset_snapshot（counter/动作/comment/table 过滤/坏 JSON）
 *   - 策略 get/set 往返（临时目录）、非法参数拒绝
 *   - status/stop 诚实错误、死 pid → orphan
 *   - start 非 root → 明确权限错误（零副作用）
 *
 * --live（root + AIK_TEST_NETNS=1 + ip netns aiktest 内）：
 *   真流量 → counter 增长 → 阈值触发 → alert 事件 → escalate 加规则 +
 *   TTL 自动撤 → degrade 换日志规则 + stop 恢复。全程只在 aiktest netns。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "tools/tool_registry.h"
#include "../tools/net_intent.h"
#include "../tools/net_hit.h"

static int fails, checks, skips;

#define CHECK(cond, name)						\
	do {								\
		checks++;						\
		if (cond)						\
			printf("ok %s\n", name);				\
		else {							\
			printf("FAIL %s\n", name);			\
			fails++;					\
		}							\
	} while (0)

static void SKIP(const char *name, const char *why)
{
	skips++;
	printf("skip %s（%s）\n", name, why);
}

static void run_cmd(const char *cmd)
{
	int rc = system(cmd);

	(void)rc;
}

static void call(const char *name, const char *args, char **out, int *rc)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.channel = TOOL_CH_NETINTENT;
	t.risk = "W1";
	t.name = (char *)name;
	*out = NULL;
	*rc = exec_net_intent_channel(&t, args, out);
}

/* ===================== 配置 ===================== */

static void test_cfg(void)
{
	struct nh_cfg c;
	char err[256];

	nh_cfg_default(&c);
	CHECK(strcmp(c.table, "aik_intent") == 0 && c.threshold == 10 &&
	      c.window == 60 && c.interval == 5 && c.cooldown == 60 &&
	      c.esc_ttl == 60 && strcmp(c.level, "alert") == 0,
	      "cfg-default");
	CHECK(nh_cfg_check(&c, err, sizeof(err)) == 0, "cfg-default-valid");

	CHECK(nh_cfg_parse("{\"table\":\"aik_t\",\"chain\":\"input\","
			   "\"handle\":5,\"threshold\":7,\"window\":30,"
			   "\"interval\":2,\"cooldown\":9,"
			   "\"level\":\"escalate\","
			   "\"escalate_src\":\"10.99.0.0/24\","
			   "\"escalate_ttl\":15}", &c, err, sizeof(err)) == 0,
	      "cfg-parse-ok");
	CHECK(strcmp(c.table, "aik_t") == 0 && strcmp(c.chain, "input") == 0 &&
	      c.handle == 5 && c.threshold == 7 && c.window == 30 &&
	      c.interval == 2 && c.cooldown == 9 &&
	      strcmp(c.level, "escalate") == 0 &&
	      strcmp(c.esc_src, "10.99.0.0/24") == 0 && c.esc_ttl == 15,
	      "cfg-parse-values");
	CHECK(nh_cfg_check(&c, err, sizeof(err)) == 0, "cfg-parsed-valid");

	nh_cfg_default(&c);
	c.threshold = 0;
	CHECK(nh_cfg_check(&c, err, sizeof(err)) != 0 &&
	      strstr(err, "threshold") != NULL, "cfg-bad-threshold");
	nh_cfg_default(&c);
	c.window = 0;
	CHECK(nh_cfg_check(&c, err, sizeof(err)) != 0 &&
	      strstr(err, "window") != NULL, "cfg-bad-window");
	nh_cfg_default(&c);
	c.interval = 10;
	c.window = 5;
	CHECK(nh_cfg_check(&c, err, sizeof(err)) != 0, "cfg-interval-gt-window");
	nh_cfg_default(&c);
	c.interval = 1;
	c.window = 600;
	CHECK(nh_cfg_check(&c, err, sizeof(err)) != 0 &&
	      strstr(err, "上限") != NULL, "cfg-window-sample-cap");
	nh_cfg_default(&c);
	snprintf(c.table, sizeof(c.table), "A;B");
	CHECK(nh_cfg_check(&c, err, sizeof(err)) != 0, "cfg-bad-table");
	nh_cfg_default(&c);
	snprintf(c.chain, sizeof(c.chain), "in put");
	CHECK(nh_cfg_check(&c, err, sizeof(err)) != 0, "cfg-bad-chain");
	nh_cfg_default(&c);
	snprintf(c.level, sizeof(c.level), "kill");
	CHECK(nh_cfg_check(&c, err, sizeof(err)) != 0, "cfg-bad-level");
	nh_cfg_default(&c);
	snprintf(c.level, sizeof(c.level), "escalate");
	CHECK(nh_cfg_check(&c, err, sizeof(err)) != 0 &&
	      strstr(err, "escalate_src") != NULL, "cfg-escalate-needs-src");
	nh_cfg_default(&c);
	c.esc_ttl = 1;
	CHECK(nh_cfg_check(&c, err, sizeof(err)) != 0, "cfg-bad-ttl");
	nh_cfg_default(&c);
	CHECK(nh_cfg_parse("{\"handle\":-1}", &c, err, sizeof(err)) != 0,
	      "cfg-negative-handle");
	nh_cfg_default(&c);
	CHECK(nh_cfg_parse("{\"threshold\":12x}", &c, err, sizeof(err)) != 0,
	      "cfg-bad-int");
	{
		char js[256], big[120];

		memset(big, 'a', 100);
		big[100] = '\0';
		snprintf(js, sizeof(js), "{\"table\":\"%s\"}", big);
		nh_cfg_default(&c);
		CHECK(nh_cfg_parse(js, &c, err, sizeof(err)) != 0,
		      "cfg-overlong-str");
	}

	CHECK(nh_src_valid("10.99.0.2") && nh_src_valid("10.0.0.0/8") &&
	      nh_src_valid("fe80::1") && nh_src_valid("2001:db8::/32"),
	      "src-valid");
	CHECK(!nh_src_valid("10.0.0.2;drop") && !nh_src_valid("abc") &&
	      !nh_src_valid("1.2.3.4/") && !nh_src_valid("1.2.3.4/99") &&
	      !nh_src_valid("10.0.0.0/8 drop") && !nh_src_valid(""),
	      "src-inject-rej");
	CHECK(nh_chain_valid("input") && nh_chain_valid("my-chain_1") &&
	      !nh_chain_valid("a b") && !nh_chain_valid("-x") &&
	      !nh_chain_valid(""),
	      "chain-valid");
	CHECK(nh_level_valid("alert") && nh_level_valid("escalate") &&
	      nh_level_valid("degrade") && !nh_level_valid("drop"),
	      "level-valid");
}

/* ===================== 滑动窗口 ===================== */

static void test_hist(void)
{
	struct nh_hist h;

	memset(&h, 0, sizeof(h));
	CHECK(nh_hist_sum(&h, 100, 60) == 0, "hist-empty");
	nh_hist_add(&h, 100, 3);
	nh_hist_add(&h, 105, 2);
	nh_hist_add(&h, 110, 4);
	CHECK(nh_hist_sum(&h, 111, 60) == 9, "hist-sum-60");
	CHECK(nh_hist_sum(&h, 111, 2) == 4, "hist-window-evict");
	CHECK(nh_hist_sum(&h, 111, 7) == 6, "hist-window-boundary");
	{
		int i;

		for (i = 0; i < NH_HIST + 50; i++)
			nh_hist_add(&h, 200 + i, 1);
		CHECK(nh_hist_sum(&h, 200 + NH_HIST + 49, 60000) == NH_HIST,
		      "hist-capacity");
	}
	CHECK(nh_should_fire(10, 10, 100, 0, 60) == 1, "fire-first");
	CHECK(nh_should_fire(9, 10, 100, 0, 60) == 0, "fire-below-threshold");
	CHECK(nh_should_fire(10, 10, 120, 100, 30) == 0, "fire-cooldown");
	CHECK(nh_should_fire(10, 10, 130, 100, 30) == 1, "fire-cooldown-pass");
}

/* ===================== nft 文本解析 ===================== */

static const char *RULES =
	"table inet aik_hit {\n"
	"\tchain input {\n"
	"\t\ttype filter hook input priority filter; policy accept;\n"
	"\t\tcounter packets 0 bytes 0 drop # handle 3\n"
	"\t\ttcp dport 9999 counter packets 7 bytes 420 drop # handle 5\n"
	"\t\tmeta l4proto { tcp, udp } th dport 53 accept # handle 7\n"
	"\t\tiif \"lo\" accept # handle 9\n"
	"\t}\n"
	"}\n";

static void test_rule_text(void)
{
	char match[512], action[16], err[256];

	match[0] = action[0] = '\0';
	CHECK(nh_parse_rule_text(RULES, 5, match, sizeof(match), action,
				 sizeof(action), err, sizeof(err)) == 0 &&
	      strcmp(match, "tcp dport 9999") == 0 &&
	      strcmp(action, "drop") == 0,
	      "rule-text-match");
	CHECK(nh_parse_rule_text(RULES, 3, match, sizeof(match), action,
				 sizeof(action), err, sizeof(err)) == 0 &&
	      match[0] == '\0' && strcmp(action, "drop") == 0,
	      "rule-text-no-match");
	CHECK(nh_parse_rule_text(RULES, 7, match, sizeof(match), action,
				 sizeof(action), err, sizeof(err)) == 0 &&
	      strcmp(match, "meta l4proto { tcp, udp } th dport 53") == 0 &&
	      strcmp(action, "accept") == 0,
	      "rule-text-set");
	CHECK(nh_parse_rule_text(RULES, 50, match, sizeof(match), action,
				 sizeof(action), err, sizeof(err)) != 0 &&
	      strstr(err, "未找到") != NULL,
	      "rule-text-handle-exact");
	{
		const char *bad =
			"tcp dport 1 jump foo # handle 11\n";
		const char *inj =
			"tcp dport 1 drop; reboot # handle 13\n";
		const char *multi = "\t\t# handle 15\n";

		CHECK(nh_parse_rule_text(bad, 11, match, sizeof(match),
					 action, sizeof(action), err,
					 sizeof(err)) != 0,
		      "rule-text-jump-rej");
		CHECK(nh_parse_rule_text(inj, 13, match, sizeof(match),
					 action, sizeof(action), err,
					 sizeof(err)) != 0 &&
		      strstr(err, "分隔符") != NULL,
		      "rule-text-inject-rej");
		CHECK(nh_parse_rule_text(multi, 15, match, sizeof(match),
					 action, sizeof(action), err,
					 sizeof(err)) != 0,
		      "rule-text-multiline-rej");
	}
	{
		const char *esc =
			"ip saddr 10.99.0.2 counter drop "
			"comment \"aikhit-esc-1-5\" # handle 12\n";
		long h = 0;

		CHECK(nh_parse_handle_by_comment(esc, "aikhit-esc-1-5", &h) == 0 &&
		      h == 12, "comment-handle-ok");
		CHECK(nh_parse_handle_by_comment(esc, "aikhit-deg-5", &h) != 0,
		      "comment-handle-miss");
		CHECK(nh_parse_handle_by_comment(RULES, "drop", &h) != 0,
		      "comment-no-comment");
	}
}

/* ===================== nft -j 快照 ===================== */

static const char *NJSON =
	"{\"nftables\":["
	"{\"metainfo\":{\"version\":\"1.0.2\",\"json_schema_version\":1}},"
	"{\"table\":{\"family\":\"inet\",\"name\":\"aik_hit\",\"handle\":1}},"
	"{\"chain\":{\"family\":\"inet\",\"table\":\"aik_hit\","
	"\"name\":\"input\",\"handle\":1,\"type\":\"filter\","
	"\"hook\":\"input\",\"prio\":0,\"policy\":\"accept\"}},"
	"{\"rule\":{\"family\":\"inet\",\"table\":\"aik_hit\","
	"\"chain\":\"input\",\"handle\":5,\"expr\":["
	"{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{"
	"\"protocol\":\"tcp\",\"field\":\"dport\"}},\"right\":9999}},"
	"{\"counter\":{\"packets\":7,\"bytes\":420}},{\"drop\":null}]}},"
	"{\"rule\":{\"family\":\"inet\",\"table\":\"aik_hit\","
	"\"chain\":\"input\",\"handle\":6,\"expr\":["
	"{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{"
	"\"protocol\":\"tcp\",\"field\":\"dport\"}},\"right\":22}},"
	"{\"counter\":{\"packets\":3,\"bytes\":180}},{\"accept\":null}]}},"
	"{\"rule\":{\"family\":\"inet\",\"table\":\"aik_hit\","
	"\"chain\":\"input\",\"handle\":7,\"expr\":["
	"{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{"
	"\"protocol\":\"ip\",\"field\":\"saddr\"}},"
	"\"right\":{\"prefix\":{\"addr\":\"10.99.0.2\",\"len\":32}}}},"
	"{\"counter\":{\"packets\":1,\"bytes\":60}},{\"drop\":null},"
	"{\"comment\":\"aikhit-esc-1-5\"}]}},"
	"{\"rule\":{\"family\":\"inet\",\"table\":\"aik_hit\","
	"\"chain\":\"input\",\"handle\":8,\"expr\":[{\"drop\":null}]}},"
	"{\"rule\":{\"family\":\"inet\",\"table\":\"other\","
	"\"chain\":\"x\",\"handle\":1,\"expr\":[{\"drop\":null}]}}"
	"]}";

static void test_snapshot(void)
{
	struct ni_rule_sample s[16];
	char err[256];
	int n = 0, i;

	CHECK(ni_ruleset_snapshot(NJSON, "aik_hit", s, 16, &n, err,
				  sizeof(err)) == 0 && n == 4,
	      "snap-count");
	CHECK(strcmp(s[0].table, "aik_hit") == 0 &&
	      strcmp(s[0].chain, "input") == 0 && s[0].handle == 5 &&
	      s[0].packets == 7 && s[0].bytes == 420 &&
	      s[0].has_counter == 1 && s[0].kind == NI_R_DENY,
	      "snap-drop-counter");
	CHECK(strstr(s[0].desc, "拒绝") != NULL, "snap-desc-deny");
	CHECK(s[1].kind == NI_R_ALLOW && s[1].packets == 3, "snap-allow");
	CHECK(s[2].kind == NI_R_DENY && s[2].packets == 1 &&
	      strcmp(s[2].comment, "aikhit-esc-1-5") == 0,
	      "snap-comment");
	CHECK(s[3].has_counter == 0 && s[3].packets == -1,
	      "snap-no-counter");
	CHECK(ni_ruleset_snapshot(NJSON, "aik_hit", s, 2, &n, err,
				  sizeof(err)) == 0 && n == 2,
	      "snap-max");
	CHECK(ni_ruleset_snapshot(NJSON, "nope", s, 16, &n, err,
				  sizeof(err)) == 0 && n == 0,
	      "snap-filter-empty");
	CHECK(ni_ruleset_snapshot("", "aik_hit", s, 16, &n, err,
				  sizeof(err)) != 0,
	      "snap-empty-rej");
	CHECK(ni_ruleset_snapshot("{\"nftables\":", "aik_hit", s, 16, &n,
				  err, sizeof(err)) != 0,
	      "snap-truncated-rej");
	CHECK(ni_ruleset_snapshot("[]", "aik_hit", s, 16, &n, err,
				  sizeof(err)) != 0,
	      "snap-not-obj-rej");
	{
		char buf[256];

		snprintf(buf, sizeof(buf), "%s", s[0].desc);
		for (i = 0; buf[i]; i++)
			;
		CHECK(i > 0, "snap-desc-nonempty");
	}
}

/* ===================== 策略 / 生命周期（非 root） ===================== */

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");

	if (f) {
		fputs(text, f);
		fclose(f);
	}
}

static void test_tools(void)
{
	char tmpl[] = "/tmp/w81b-hit-XXXXXX";
	char *dir = mkdtemp(tmpl);
	char path[512];
	char *out = NULL;
	int rc;

	if (!dir) {
		SKIP("tools", "mkdtemp 失败");
		return;
	}
	setenv("AIKERNEL_NFT_HIT_DIR", dir, 1);

	call("net_hit_policy", "{}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "threshold=10") != NULL,
	      "policy-get-default");
	free(out);
	out = NULL;
	call("net_hit_policy",
	     "{\"action\":\"set\",\"threshold\":7,\"window\":30,"
	     "\"interval\":2,\"cooldown\":9}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "set 完成") != NULL,
	      "policy-set-ok");
	free(out);
	out = NULL;
	call("net_hit_policy", "{}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "threshold=7") != NULL &&
	      strstr(out, "window=30s") != NULL, "policy-get-roundtrip");
	free(out);
	out = NULL;
	call("net_hit_policy", "{\"action\":\"set\",\"threshold\":0}",
	     &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "policy-set-invalid-rej");
	free(out);
	out = NULL;
	call("net_hit_policy", "{\"action\":\"set\",\"level\":\"escalate\","
	     "\"escalate_src\":\"10.0.0.1\"}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "level") != NULL,
	      "policy-level-rej");
	free(out);
	out = NULL;
	call("net_hit_policy", "{\"action\":\"set\",\"level\":5}",
	     &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "level") != NULL,
	      "policy-level-nonstring-rej");
	free(out);
	out = NULL;
	call("net_hit_policy", "{\"action\":\"bogus\"}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "policy-bad-action-rej");
	free(out);
	out = NULL;

	call("net_hit_watch", "{}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "action") != NULL,
	      "watch-noaction-rej");
	free(out);
	out = NULL;
	call("net_hit_watch", "{\"action\":\"bogus\"}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "watch-bad-action-rej");
	free(out);
	out = NULL;
	call("net_hit_watch", "{\"action\":\"status\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "state=not-running") != NULL,
	      "status-not-running");
	free(out);
	out = NULL;

	snprintf(path, sizeof(path), "%s/state", dir);
	write_file(path, "running\n");
	snprintf(path, sizeof(path), "%s/pid", dir);
	write_file(path, "999999\n");
	call("net_hit_watch", "{\"action\":\"status\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "state=orphan") != NULL,
	      "status-orphan-detect");
	free(out);
	out = NULL;
	call("net_hit_watch", "{\"action\":\"stop\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "已停止") != NULL,
	      "stop-no-daemon-ok");
	free(out);
	out = NULL;
	call("net_hit_watch", "{\"action\":\"status\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "state=stopped") != NULL,
	      "status-after-stop");
	free(out);
	out = NULL;

	call("net_hit_watch",
	     "{\"action\":\"start\",\"level\":\"escalate\"}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "escalate_src") != NULL,
	      "start-escalate-nosrc-rej");
	free(out);
	out = NULL;
	call("net_hit_watch", "{\"action\":\"start\",\"table\":\"A;B\"}",
	     &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "table") != NULL,
	      "start-badtable-rej");
	free(out);
	out = NULL;

	if (geteuid() != 0) {
		call("net_hit_watch",
		     "{\"action\":\"start\",\"table\":\"aik_hit\","
		     "\"threshold\":3,\"interval\":1,\"window\":4}",
		     &out, &rc);
		CHECK(rc != 0 && out && strstr(out, "root") != NULL &&
		      strstr(out, "权限") != NULL,
		      "start-nonroot-rej");
		free(out);
		out = NULL;
	} else {
		SKIP("start-nonroot-rej", "当前 root，非 root 路径由 run_all 覆盖");
	}
	call("net_hit_bogus", "{}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "dispatch-unknown-rej");
	free(out);
	out = NULL;

	unlink(path);
	{
		char cmd[600];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
		run_cmd(cmd);
	}
	unsetenv("AIKERNEL_NFT_HIT_DIR");
}

/* ===================== live（netns aiktest 内真流量） ===================== */

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

static int file_has(const char *path, const char *needle)
{
	char *buf;
	size_t n = 0;
	int fd, found;

	buf = malloc(262144);
	if (!buf)
		return 0;
	buf[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t r = read(fd, buf, 262143);

		close(fd);
		if (r > 0)
			n = (size_t)r;
	}
	buf[n] = '\0';
	found = strstr(buf, needle) != NULL;
	free(buf);
	return found;
}

static int wait_file(const char *path, const char *needle, int secs)
{
	int i;

	for (i = 0; i < secs * 10; i++) {
		if (file_has(path, needle))
			return 1;
		usleep(100000);
	}
	return 0;
}

static long long table_drop_packets(const char *tbl)
{
	char path[64], cmd[256], line[512];
	FILE *f;
	long long pk = -1;

	snprintf(path, sizeof(path), "/tmp/aik-w81b-list-%d.txt",
		 (int)getpid());
	snprintf(cmd, sizeof(cmd), "nft list table inet %s > %s 2>&1",
		 tbl, path);
	run_cmd(cmd);
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *q = strstr(line, "counter packets ");

		if (q) {
			pk = strtoll(q + 16, NULL, 10);
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
	rc = (int)sendto(fd, "w81b", 4, 0, (struct sockaddr *)&to,
			 sizeof(to));
	close(fd);
	return rc < 0 ? -1 : 0;
}

/* PEER=1：从 aikw81peer netns 发真实 UDP（证据用）；否则同 ns 自发 */
static void send_traffic(int n)
{
	const char *peer = getenv("AIK_W81B_PEER");
	int i;

	if (peer && strcmp(peer, "1") == 0) {
		char cmd[512];

		snprintf(cmd, sizeof(cmd),
			 "ip netns exec aikw81peer python3 -c "
			 "\"import socket;"
			 "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
			 "[s.sendto(b'x',('10.99.0.1',9999)) for _ in range(%d)]\""
			 " 2>/dev/null", n);
		run_cmd(cmd);
		return;
	}
	for (i = 0; i < n; i++)
		(void)udp_send_to("10.99.0.1", 9999, "10.99.0.1");
}

/* 把当前链原文写到 <dir>/chain.txt；返回是否含 needle */
static int chain_has(const char *dir, const char *needle)
{
	char path[600];
	char cmd[800];

	snprintf(path, sizeof(path), "%s/chain.txt", dir);
	snprintf(cmd, sizeof(cmd),
		 "nft -a list chain inet aik_hitloop input > '%s' 2>&1", path);
	run_cmd(cmd);
	return file_has(path, needle);
}

static int run_live(void)
{
	char tmpl[] = "/tmp/w81b-hit-live-XXXXXX";
	const char *edir = getenv("AIK_W81B_EVIDENCE_DIR");
	char *dir;
	char audit[600], events[600];
	char *out = NULL;
	int rc;

	printf("== LIVE（netns aiktest 内真流量）==\n");
	if (edir && *edir) {
		dir = strdup(edir);
		if (dir)
			(void)mkdir(dir, 0700);
	} else {
		dir = mkdtemp(tmpl);
	}
	if (!dir) {
		printf("FAIL: 状态目录创建失败\n");
		return 2;
	}
	if (geteuid() != 0) {
		printf("REFUSE: --live 需要 root\n");
		return 2;
	}
	if (in_named_netns("aiktest") != 1) {
		printf("REFUSE: 当前进程不在 netns aiktest 内，"
		       "拒绝执行任何 nft 下发\n");
		return 2;
	}
	setenv("AIKERNEL_NFT_HIT_DIR", dir, 1);
	snprintf(audit, sizeof(audit), "%s/audit.log", dir);
	snprintf(events, sizeof(events), "%s/events.jsonl", dir);
	printf("  状态目录：%s\n", dir);

	/* 0) 在 netns 内造一张表：base chain policy accept + 一条 drop+count */
	run_cmd("nft delete table inet aik_hitloop 2>/dev/null");
	CHECK(system("nft add table inet aik_hitloop") == 0,
	      "live-setup-table");
	CHECK(system("nft add chain inet aik_hitloop input "
		     "'{ type filter hook input priority filter; "
		     "policy accept; }'") == 0, "live-setup-chain");
	CHECK(system("nft add rule inet aik_hitloop input udp dport 9999 "
		     "counter drop") == 0, "live-setup-rule");
	CHECK(chain_has(dir, "udp dport 9999 counter") &&
	      chain_has(dir, "drop"), "live-setup-readback");

	/* 1) alert（D1）：真流量 → counter 增长 → 触发只审计 */
	call("net_hit_watch",
	     "{\"action\":\"start\",\"table\":\"aik_hitloop\","
	     "\"level\":\"alert\",\"interval\":1,\"window\":4,"
	     "\"threshold\":5,\"cooldown\":30}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "state=running") != NULL,
	      "live-alert-start");
	if (out)
		printf("---- start 输出 ----\n%s\n", out);
	free(out);
	out = NULL;
	sleep(2);	/* 第一拍建立基线（首见规则 delta=0） */
	{
		long long c0 = table_drop_packets("aik_hitloop");
		long long c1;

		send_traffic(12);
		(void)wait_file(audit, "action=alert", 8);
		c1 = table_drop_packets("aik_hitloop");
		printf("  alert 计数：before=%lld after=%lld（delta=%lld）\n",
		       c0, c1, c1 - c0);
		CHECK(c1 > c0, "live-counter-grew");
	}
	CHECK(wait_file(audit, "action=alert", 1), "live-alert-trigger");
	CHECK(file_has(events, "\"action\":\"alert\"") &&
	      file_has(events, "\"window_packets\""), "live-alert-event-json");
	{
		char *snap = NULL;

		/* 审计行必须含规则/计数/阈值/快照路径四要素 */
		CHECK(file_has(audit, "rule=\"inet aik_hitloop input") &&
		      file_has(audit, "total=") &&
		      file_has(audit, "threshold=5") &&
		      file_has(audit, "snapshot="),
		      "live-audit-fields");
		(void)snap;
	}
	call("net_hit_watch", "{\"action\":\"status\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "active_escalations=0") != NULL,
	      "live-alert-no-rule-change");
	free(out);
	out = NULL;
	call("net_hit_watch", "{\"action\":\"stop\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "已停止") != NULL,
	      "live-alert-stop");
	free(out);
	out = NULL;

	/* 2) escalate（D3）：加源隔离规则 + TTL 到期自动撤 */
	call("net_hit_watch",
	     "{\"action\":\"start\",\"table\":\"aik_hitloop\","
	     "\"level\":\"escalate\",\"interval\":1,\"window\":4,"
	     "\"threshold\":3,\"cooldown\":30,"
	     "\"escalate_src\":\"10.99.0.2/32\",\"escalate_ttl\":5}",
	     &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "level=escalate") != NULL,
	      "live-escalate-start");
	free(out);
	out = NULL;
	sleep(2);
	send_traffic(12);
	CHECK(wait_file(audit, "action=escalate", 8), "live-escalate-trigger");
	CHECK(wait_file(audit, "escalation-added", 3),
	      "live-escalate-added");
	CHECK(chain_has(dir, "aikhit-esc-") &&
	      chain_has(dir, "10.99.0.2"), "live-escalate-rule-present");
	{
		char cmd[800];

		snprintf(cmd, sizeof(cmd),
			 "cp '%s/chain.txt' '%s/chain-escalate.txt'",
			 dir, dir);
		run_cmd(cmd);
	}
	{
		char *st = NULL;

		call("net_hit_watch", "{\"action\":\"status\"}", &st, &rc);
		if (st)
			printf("---- escalate status ----\n%s\n", st);
		CHECK(rc == 0 && st && strstr(st, "active_escalations=1") != NULL &&
		      strstr(st, "expires_in=") != NULL,
		      "live-escalate-status-ttl");
		free(st);
	}
	printf("  等待 7 秒观察 TTL 自动撤…\n");
	sleep(7);
	CHECK(!chain_has(dir, "aikhit-esc-"), "live-escalate-ttl-withdraw");
	CHECK(file_has(audit, "ESCALATE-EXPIRE"), "live-escalate-expire-audit");
	call("net_hit_watch", "{\"action\":\"stop\"}", &out, &rc);
	CHECK(rc == 0, "live-escalate-stop");
	free(out);
	out = NULL;

	/* 3) degrade（D3）：drop 规则换只记日志；stop 后恢复原动作 */
	call("net_hit_watch",
	     "{\"action\":\"start\",\"table\":\"aik_hitloop\","
	     "\"level\":\"degrade\",\"interval\":1,\"window\":4,"
	     "\"threshold\":3,\"cooldown\":30}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "level=degrade") != NULL,
	      "live-degrade-start");
	free(out);
	out = NULL;
	sleep(2);
	send_traffic(12);
	CHECK(wait_file(audit, "action=degrade", 8), "live-degrade-trigger");
	CHECK(wait_file(audit, "degraded orig_handle", 3),
	      "live-degrade-recorded");
	CHECK(chain_has(dir, "aik-hit-degraded") &&
	      chain_has(dir, "log prefix"), "live-degrade-log-rule");
	{
		char cmd[800];

		snprintf(cmd, sizeof(cmd),
			 "cp '%s/chain.txt' '%s/chain-degrade.txt'",
			 dir, dir);
		run_cmd(cmd);
	}
	CHECK(!chain_has(dir, "counter packets") ||
	      chain_has(dir, "aik-hit-degraded"), "live-degrade-drop-replaced");
	call("net_hit_watch", "{\"action\":\"stop\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "已停止") != NULL &&
	      file_has(audit, "DEGRADE-RESTORE"),
	      "live-degrade-stop-restore");
	free(out);
	out = NULL;
	CHECK(chain_has(dir, "udp dport 9999") &&
	      chain_has(dir, "drop") && !chain_has(dir, "aik-hit-degraded"),
	      "live-degrade-original-restored");

	/* 4) 收尾：删表，确认 watcher 已停 */
	run_cmd("nft delete table inet aik_hitloop 2>/dev/null");
	free(out);
	unsetenv("AIKERNEL_NFT_HIT_DIR");
	printf("  证据目录保留：%s\n", dir);
	return 0;
}

int main(int argc, char **argv)
{
	int live = (argc > 1 && strcmp(argv[1], "--live") == 0);

	printf("== test_net_hit (uid=%u, live=%d) ==\n",
	       (unsigned)geteuid(), live);
	test_cfg();
	test_hist();
	test_rule_text();
	test_snapshot();
	test_tools();
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
		printf("（未跑 live：netns 真流量用 --live + "
		       "AIK_TEST_NETNS=1）\n");
	}
	if (fails) {
		printf("FAILURES: %d (checks=%d skips=%d)\n", fails, checks,
		       skips);
		return 1;
	}
	printf("ALL PASS (checks=%d skips=%d)\n", checks, skips);
	return 0;
}
