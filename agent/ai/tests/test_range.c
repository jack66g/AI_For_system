/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_range.c - W81 E2 靶场攻击面（range 通道）回归
 *
 * 默认（run_all，非 root）：
 *   - 边界：未启用时四个能力工具拒绝（原文含「未启用 + 如何启用」），
 *     range_enable 的 D3 映射；非法 CIDR/TTL 拒绝；启用后越界目标
 *     （192.168.245.1 / 8.8.8.8 / 清单外 / 声明外）全部拒绝并留审计。
 *   - 纯函数：CIDR/端口/payload hex/状态往返/惰性过期。
 *   - watchdog：合成 2 秒到期状态 → 自动关闭（不等待 1 分钟）。
 *   - 注册表：5 件工具、channel=range、总数 237。
 *   - 策略：range_status=D0 / disable=D1 / enable+scan+inject=D3。
 *
 * --boundary：打印第一步边界场景的完整命令/输出/审计（证据用）。
 * --ttl-wait：真实 ttl_minutes=1，等待 65 秒验证到期自动关闭。
 * --live：root；创建 netns aikrange + veth 10.99.1.1/24 ↔ 10.99.1.2/24，
 *   TCP/UDP 监听器作靶标；scan 发现 open → inject UDP 标记 payload →
 *   监听端字节一致；TCP SYN/ICMP 发送；最后 range_disable + 删 netns +
 *   宿主 nft ruleset/路由前后 diff 必须 0 行。
 *
 * 安全：只动自建 netns 与 veth；不写宿主 nft、不打真实服务、不扫描
 * 宿主 LAN（越界目标在到达网络前即被拒绝）。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../tools/net_range.h"
#include "../tools/tool_registry.h"
#include "../policy/ai_lease.h"

static int checks, fails, skips;

#define CHECK(cond, name)						\
	do {								\
		checks++;						\
		if (cond)						\
			printf("ok %s\n", name);			\
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

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void call(const char *name, const char *args, char **out, int *rc)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.channel = TOOL_CH_RANGE;
	t.risk = "W2";
	t.name = (char *)name;
	*out = NULL;
	*rc = exec_net_range_channel(&t, args, out);
}

static int read_file(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;
	size_t off = 0;

	if (fd < 0)
		return -1;
	while (off + 1 < cap && (n = read(fd, buf + off, cap - 1 - off)) > 0)
		off += (size_t)n;
	close(fd);
	buf[off] = '\0';
	return (int)off;
}

static int file_has(const char *path, const char *needle)
{
	char buf[262144];

	if (read_file(path, buf, sizeof(buf)) < 0)
		return 0;
	return strstr(buf, needle) != NULL;
}

static int cmd(const char *fmt, ...)
{
	char line[1024];
	va_list ap;
	int rc;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	rc = system(line);
	return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

static void audit_path_of(char *out, size_t cap)
{
	char dir[512];

	if (rg_state_dir(dir, sizeof(dir)) != 0)
		snprintf(out, cap, "/nonexistent/audit.log");
	else
		snprintf(out, cap, "%s/audit.log", dir);
}

static void cleanup_dir(const char *dpath, int keep)
{
	if (keep)
		printf("KEEP_DIR=%s\n", dpath);
	else
		(void)cmd("rm -rf %s", dpath);
}

static void print_audit_tail(size_t max_lines)
{
	char path[600];
	char line[32768];
	char *ring[32];
	size_t cap, total = 0, i, start;
	FILE *fp;

	if (max_lines > 32)
		max_lines = 32;
	cap = max_lines;
	for (i = 0; i < cap; i++)
		ring[i] = NULL;
	audit_path_of(path, sizeof(path));
	fp = fopen(path, "r");
	if (!fp) {
		printf("(audit.log 不存在: %s)\n", path);
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		free(ring[total % cap]);
		ring[total % cap] = strdup(line);
		total++;
	}
	fclose(fp);
	start = total > cap ? total - cap : 0;
	for (i = start; i < total; i++)
		printf("  %s", ring[i % cap] ? ring[i % cap] : "");
	for (i = 0; i < cap; i++)
		free(ring[i]);
}

/* ===================== 纯函数 ===================== */

static void test_pure(void)
{
	struct rg_cidr c, d;
	char err[256];
	unsigned short ports[16];
	int n = 0;
	unsigned char payload[8];
	size_t plen = 0;

	printf("== pure: CIDR / ports / hex ==\n");
	CHECK(rg_cidr_parse("10.231.0.0/16", &c, err, sizeof(err)) == 0,
	      "cidr-parse-10.231.0.0/16");
	CHECK(c.prefix == 16 && c.net == 0x0ae70000, "cidr-net-mask");
	CHECK(rg_cidr_contains(&c, "10.231.1.2"), "cidr-contains-in");
	CHECK(!rg_cidr_contains(&c, "10.232.1.2"), "cidr-contains-out");
	CHECK(rg_cidr_parse("10.231.0.0/16", &d, err, sizeof(err)) == 0 &&
	      strcmp(c.text, d.text) == 0, "cidr-normalize");
	CHECK(rg_cidr_parse("10.231.1.0/16", &d, err, sizeof(err)) != 0,
	      "cidr-reject-host-bits");
	CHECK(rg_cidr_parse("10.0.0.0/33", &d, err, sizeof(err)) != 0,
	      "cidr-reject-prefix-33");
	CHECK(rg_cidr_parse("8.8.8.8", &d, err, sizeof(err)) != 0,
	      "cidr-reject-no-prefix");
	CHECK(rg_cidr_allowlisted("10.231.0.0/16", err, sizeof(err)) == 0,
	      "allowlist-10.231");
	CHECK(rg_cidr_allowlisted("10.99.0.0/16", err, sizeof(err)) == 0,
	      "allowlist-10.99");
	CHECK(rg_cidr_allowlisted("127.0.0.0/8", err, sizeof(err)) == 0,
	      "allowlist-127");
	CHECK(rg_cidr_allowlisted("192.168.245.0/24", err, sizeof(err)) != 0,
	      "allowlist-reject-lab");
	CHECK(rg_cidr_allowlisted("10.0.0.0/8", err, sizeof(err)) != 0,
	      "allowlist-reject-10/8");
	CHECK(rg_cidr_allowlisted("10.231.0.0/24", err, sizeof(err)) != 0,
	      "allowlist-reject-narrower");

	CHECK(rg_parse_ports("22,80,8000-8002", ports, 16, &n, err,
			     sizeof(err)) == 0 && n == 5,
	      "ports-parse-mixed");
	CHECK(ports[0] == 22 && ports[1] == 80 && ports[4] == 8002,
	      "ports-values");
	CHECK(rg_parse_ports("0", ports, 16, &n, err, sizeof(err)) != 0,
	      "ports-reject-0");
	CHECK(rg_parse_ports("65536", ports, 16, &n, err, sizeof(err)) != 0,
	      "ports-reject-65536");
	CHECK(rg_parse_ports("9-1", ports, 16, &n, err, sizeof(err)) != 0,
	      "ports-reject-reverse");
	CHECK(rg_parse_ports("1-100", ports, 16, &n, err, sizeof(err)) != 0,
	      "ports-reject-over-cap");

	CHECK(rg_hex_decode("5738314532", payload, sizeof(payload), &plen,
			    err, sizeof(err)) == 0,
	      "hex-decode-ok");
	CHECK(plen == 5 && payload[0] == 0x57 && payload[4] == 0x32,
	      "hex-decode-bytes");
	CHECK(rg_hex_decode("573", payload, sizeof(payload), &plen, err,
			    sizeof(err)) != 0, "hex-reject-odd");
	CHECK(rg_hex_decode("zz", payload, sizeof(payload), &plen, err,
			    sizeof(err)) != 0, "hex-reject-nonhex");
	{
		char enc[32];

		rg_hex_encode(payload, 5, enc, sizeof(enc));
		CHECK(strcmp(enc, "5738314532") == 0, "hex-encode-roundtrip");
	}
}

static void test_state_and_watchdog(void)
{
	struct rg_state st;
	char err[128];
	char path[700];
	int r;
	time_t t0;

	printf("== state roundtrip / lazy expiry / watchdog ==\n");
	rg_state_default(&st);
	snprintf(st.cidr, sizeof(st.cidr), "10.231.0.0/16");
	if (rg_cidr_parse(st.cidr, &st.net, err, sizeof(err)) != 0) {
		CHECK(0, "state-cidr-parse");
		return;
	}
	st.enabled = 1;
	st.ttl_minutes = 30;
	st.enabled_at = (long long)time(NULL);
	st.expires_at = st.enabled_at + 1800;
	st.actions = 7;
	st.session = 0x123456789ULL;
	snprintf(st.lsm, sizeof(st.lsm), "absent: test");
	CHECK(rg_state_save(&st) == 0, "state-save");
	{
		struct rg_state rd;

		memset(&rd, 0, sizeof(rd));
		CHECK(rg_state_load(&rd, err, sizeof(err)) == 1,
		      "state-load-enabled");
		CHECK(strcmp(rd.cidr, st.cidr) == 0 && rd.actions == 7 &&
		      rd.session == st.session && rd.expires_at ==
		      st.expires_at, "state-roundtrip-values");
	}
	/* 惰性到期：把 expires_at 拨到过去，普通 load 必须自动关闭 */
	st.expires_at = (long long)time(NULL) - 1;
	CHECK(rg_state_save(&st) == 0, "state-save-expired");
	{
		struct rg_state rd;

		CHECK(rg_state_load(&rd, err, sizeof(err)) == 0,
		      "state-lazy-expiry-disabled");
	}
	audit_path_of(path, sizeof(path));
	CHECK(file_has(path, "\"action\":\"auto_disable\""),
	      "state-lazy-expiry-audited");
	CHECK(access(path, F_OK) == 0, "audit-file-exists");

	/* watchdog：合成 now+2 秒，2..6 秒内自动关闭 */
	rg_state_default(&st);
	snprintf(st.cidr, sizeof(st.cidr), "10.99.0.0/16");
	(void)rg_cidr_parse(st.cidr, &st.net, err, sizeof(err));
	st.enabled = 1;
	st.ttl_minutes = 1;
	st.enabled_at = (long long)time(NULL);
	st.expires_at = st.enabled_at + 2;
	st.session = 0xABCDEF12ULL;
	CHECK(rg_state_save(&st) == 0, "wd-state-save");
	CHECK(rg_watchdog_spawn(st.session, err, sizeof(err)) == 0,
	      "wd-spawn");
	t0 = time(NULL);
	for (;;) {
		struct rg_state rd;

		r = rg_state_load(&rd, err, sizeof(err));
		if (r == 0 || time(NULL) - t0 >= 8)
			break;
		sleep(1);
	}
	CHECK(r == 0, "wd-auto-disabled");
	CHECK(time(NULL) - t0 <= 6, "wd-auto-disable-within-6s");
	CHECK(rg_state_load(&st, err, sizeof(err)) == 0,
	      "wd-state-removed");
	usleep(200000);
	audit_path_of(path, sizeof(path));
	CHECK(file_has(path, "\"action\":\"auto_disable\""),
	      "wd-auto-disable-audited");
}

/* ===================== 边界（默认跑） ===================== */

static int disabled_refusal(const char *tool, const char *args)
{
	char *out = NULL;
	int rc;
	int ok;

	call(tool, args, &out, &rc);
	ok = rc != 0 && out && strstr(out, "未启用") &&
	     strstr(out, "如何启用");
	printf("---- %s (rc=%d) ----\n%s\n", tool, rc, out ? out : "(null)");
	free(out);
	return ok;
}

static void test_boundary(const char *tag)
{
	char *out = NULL;
	int rc;
	char path[700];

	printf("== %s: 未启用五个工具 ==\n", tag);
	CHECK(disabled_refusal("range_status", "{}"), "disabled-status");
	CHECK(disabled_refusal("range_scan",
			       "{\"target\":\"10.231.1.2\",\"ports\":\"22\"}"),
	      "disabled-scan");
	CHECK(disabled_refusal("range_inject",
			       "{\"target\":\"10.231.1.2\",\"protocol\":\"udp\","
			       "\"port\":9,\"payload_hex\":\"00\"}"),
	      "disabled-inject");
	CHECK(disabled_refusal("range_disable", "{}"), "disabled-disable");
	/* 第五件 range_enable 是唯一启用入口，D3 由策略层闸门管辖 */
	{
		enum ai_danger d;
		const char *why = NULL;

		d = ai_danger_classify("range_enable", "", "W2",
				       "{\"cidr\":\"10.231.0.0/16\"}", NULL,
				       &why);
		CHECK(d == AI_D3, "disabled-enable-requires-D3");
		printf("range_enable D3 reason=%s\n", why ? why : "?");
	}

	printf("== %s: 非法 enable 参数 ==\n", tag);
	{
		const char *bad[] = {
			"{\"cidr\":\"192.168.245.0/24\"}",
			"{\"cidr\":\"8.8.8.8/32\"}",
			"{\"cidr\":\"10.0.0.0/8\"}",
			"{\"cidr\":\"10.231.0.0/24\"}",
			"{\"cidr\":\"10.231.0.0/16\",\"ttl_minutes\":0}",
			"{\"cidr\":\"10.231.0.0/16\",\"ttl_minutes\":61}",
			"{\"cidr\":\"10.231.0.0/16\",\"ttl_minutes\":\"30\"}",
		};
		size_t i;

		for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			call("range_enable", bad[i], &out, &rc);
			printf("---- range_enable %s (rc=%d) ----\n%s\n",
			       bad[i], rc, out ? out : "(null)");
			CHECK(rc != 0 && out && strstr(out, "ERROR"),
			      "enable-reject-bad-args");
			free(out);
			out = NULL;
		}
	}

	printf("== %s: 合法启用 10.231.0.0/16 ==\n", tag);
	call("range_enable", "{\"cidr\":\"10.231.0.0/16\","
	     "\"ttl_minutes\":5}", &out, &rc);
	printf("---- range_enable valid (rc=%d) ----\n%s\n", rc,
	       out ? out : "(null)");
	CHECK(rc == 0 && out && strstr(out, "enabled=1"), "enable-valid");
	free(out);
	out = NULL;

	printf("== %s: 启用后越界目标拒绝 ==\n", tag);
	{
		const char *targets[] = { "192.168.245.1", "8.8.8.8",
					  "10.99.1.2" };

		for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]);
		     i++) {
			char args[256];

			snprintf(args, sizeof(args),
				 "{\"target\":\"%s\",\"ports\":\"22\"}",
				 targets[i]);
			call("range_scan", args, &out, &rc);
			printf("---- range_scan target=%s (rc=%d) ----\n%s\n",
			       targets[i], rc, out ? out : "(null)");
			CHECK(rc != 0 && out && strstr(out, "拒绝") &&
			      strstr(out, targets[i]), "scan-refuse-outside");
			free(out);
			out = NULL;
		}
		audit_path_of(path, sizeof(path));		CHECK(file_has(path, "\"target\":\"192.168.245.1\""),
		      "audit-has-lab-target");
		CHECK(file_has(path, "\"target\":\"8.8.8.8\""),
		      "audit-has-public-target");
		CHECK(file_has(path, "\"result\":\"refused\""),
		      "audit-has-refused");
	}

	printf("== %s: inject 越界目标拒绝（payload 已给） ==\n", tag);
	call("range_inject", "{\"target\":\"192.168.245.1\","
	     "\"protocol\":\"udp\",\"port\":9000,"
	     "\"payload_hex\":\"deadbeef\"}", &out, &rc);
	printf("---- range_inject lab target (rc=%d) ----\n%s\n", rc,
	       out ? out : "(null)");
	CHECK(rc != 0 && out && strstr(out, "拒绝"), "inject-refuse-lab");
	free(out);
	out = NULL;

	printf("== %s: 127.0.0.0/8 仅 netns 内 ==\n", tag);
	call("range_disable", "{}", &out, &rc);
	free(out);
	out = NULL;
	call("range_enable", "{\"cidr\":\"127.0.0.0/8\"}", &out, &rc);
	CHECK(rc == 0, "enable-loopback-cidr");
	free(out);
	out = NULL;
	call("range_scan", "{\"target\":\"127.0.0.1\",\"ports\":\"1\"}",
	     &out, &rc);
	printf("---- range_scan 127.0.0.1 in host netns (rc=%d) ----\n%s\n",
	       rc, out ? out : "(null)");
	CHECK(rc != 0 && out && strstr(out, "仅允许在 netns 内"),
	      "loopback-refused-in-host-netns");
	free(out);
	out = NULL;

	printf("== %s: disable + 关闭后再拒绝 ==\n", tag);
	call("range_disable", "{}", &out, &rc);
	printf("---- range_disable (rc=%d) ----\n%s\n", rc,
	       out ? out : "(null)");
	CHECK(rc == 0 && out && strstr(out, "enabled=0"), "disable-ok");
	free(out);
	out = NULL;
	CHECK(disabled_refusal("range_scan",
			       "{\"target\":\"10.231.1.2\",\"ports\":\"22\"}"),
	      "after-disable-scan-refused");

	printf("---- %s audit tail ----\n", tag);
	print_audit_tail(24);
}

/* ===================== 注册表 ===================== */

static const char *find_registry(void)
{
	static const char *cands[] = {
		"../tools/tools.json",
		"tools/tools.json",
		"agent/ai/tools/tools.json",
	};
	size_t i;

	for (i = 0; i < sizeof(cands) / sizeof(cands[0]); i++)
		if (access(cands[i], R_OK) == 0)
			return cands[i];
	return NULL;
}

static void test_registry(void)
{
	const char *path = find_registry();
	static char buf[524288];
	int n = 0;
	char *p;

	if (!path) {
		SKIP("registry-range-tools", "找不到 tools.json");
		return;
	}
	if (read_file(path, buf, sizeof(buf)) < 0) {
		SKIP("registry-range-tools", "tools.json 读取失败");
		return;
	}
	p = buf;
	while ((p = strstr(p, "\"channel\": \"range\"")) != NULL) {
		n++;
		p++;
	}
	CHECK(n == 5, "registry-rate-5-range-tools");
	CHECK(strstr(buf, "\"tool_count\": 237") != NULL,
	      "registry-tool-count-237");
	CHECK(strstr(buf, "\"range\": 5") != NULL,
	      "registry-channel-count-range-5");
	CHECK(strstr(buf, "\"name\": \"range_status\"") != NULL,
	      "registry-has-range_status");
	CHECK(strstr(buf, "\"name\": \"range_enable\"") != NULL,
	      "registry-has-range_enable");
	CHECK(strstr(buf, "\"name\": \"range_disable\"") != NULL,
	      "registry-has-range_disable");
	CHECK(strstr(buf, "\"name\": \"range_scan\"") != NULL,
	      "registry-has-range_scan");
	CHECK(strstr(buf, "\"name\": \"range_inject\"") != NULL,
	      "registry-has-range_inject");
	CHECK(strstr(buf, "\"cidr\"") != NULL &&
	      strstr(buf, "10.231.0.0/16") != NULL,
	      "registry-cidr-allowlist-documented");
}

static void test_policy(void)
{
	enum ai_danger d;
	const char *why = NULL;

	printf("== policy: D0/D1/D3 ==\n");
	d = ai_danger_classify("range_status", "", "R", "{}", NULL, &why);
	CHECK(d == AI_D0, "policy-status-D0");
	d = ai_danger_classify("range_disable", "", "W1", "{}", NULL, &why);
	CHECK(d == AI_D1, "policy-disable-D1");
	d = ai_danger_classify("range_enable", "", "W2",
			       "{\"cidr\":\"10.231.0.0/16\"}", NULL, &why);
	CHECK(d == AI_D3, "policy-enable-D3");
	d = ai_danger_classify("range_scan", "", "W2",
			       "{\"target\":\"10.231.1.2\"}", NULL, &why);
	CHECK(d == AI_D3, "policy-scan-D3");
	d = ai_danger_classify("range_inject", "", "W2",
			       "{\"target\":\"10.231.1.2\"}", NULL, &why);
	CHECK(d == AI_D3, "policy-inject-D3");
}

/* ===================== TTL=1 分钟真实等待 ===================== */

static int test_ttl_wait(void)
{
	char *out = NULL;
	int rc;
	double t0 = now_s();
	char path[700];

	printf("== ttl-wait: range_enable ttl_minutes=1 ==\n");
	call("range_enable", "{\"cidr\":\"10.231.0.0/16\","
	     "\"ttl_minutes\":1}", &out, &rc);
	printf("[+%.3fs] enable rc=%d\n%s\n", now_s() - t0, rc,
	       out ? out : "(null)");
	if (rc != 0) {
		free(out);
		return 1;
	}
	free(out);
	out = NULL;
	while (now_s() - t0 < 65)
		sleep(1);
	printf("[+%.3fs] 65s 后调用 range_status\n", now_s() - t0);
	call("range_status", "{}", &out, &rc);
	printf("[+%.3fs] status rc=%d\n%s\n", now_s() - t0, rc,
	       out ? out : "(null)");
	CHECK(rc != 0 && out && strstr(out, "未启用"),
	      "ttl-auto-disabled-status");
	free(out);
	out = NULL;
	audit_path_of(path, sizeof(path));
	printf("---- audit tail ----\n");
	print_audit_tail(8);
	CHECK(file_has(path, "\"action\":\"auto_disable\""),
	      "ttl-auto-disable-audited");
	{
		char dir[512], state[600];

		CHECK(rg_state_dir(dir, sizeof(dir)) == 0, "ttl-state-dir");
		snprintf(state, sizeof(state), "%s/state.json", dir);
		CHECK(access(state, F_OK) != 0, "ttl-state-removed");
	}
	return fails ? 1 : 0;
}

/* ===================== live（root + netns） ===================== */

static int netns_exists(const char *ns)
{
	char line[1024];
	FILE *fp = popen("ip netns list 2>/dev/null", "r");
	int found = 0;

	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, ns)) {
			found = 1;
			break;
		}
	}
	pclose(fp);
	return found;
}

static void capture(const char *cmdline, const char *path)
{
	cmd("%s > %s 2>&1", cmdline, path);
}

static void diff_lines(const char *a, const char *b, const char *label)
{
	char tmp[256];
	int rc;

	snprintf(tmp, sizeof(tmp), "/tmp/aikrange-diff-%d.txt", (int)getpid());
	cmd("diff -u %s %s > %s", a, b, tmp);
	rc = cmd("test -s %s", tmp);
	printf("diff %s: %s（0 行 = 一致）\n", label, rc == 0 ? "有差异" : "0 行");
	if (rc == 0)
		cmd("sed -n '1,40p' %s", tmp);
	unlink(tmp);
	CHECK(rc != 0, label);
}

static int test_live(void)
{
	static const char payload_hex[] = "57383145322d52414e47452d5544502d00ff0102";
	unsigned char payload[64];
	size_t plen = 0;
	char err[128];
	char *out = NULL;
	int rc;
	char audit[700], udphex[700], ready[700], listener[700], log[700];
	char pidfile[700], nft_before[256], nft_after[256];
	char route_before[256], route_after[256];
	double t0 = now_s();
	int created_ns = 0, created_link = 0;
	int ok = 1;

	printf("== live: netns aikrange + veth 10.99.1.0/24 ==\n");
	if (geteuid() != 0) {
		SKIP("live", "需要 root（sudo ./test_range --live）");
		return 0;
	}
	if (netns_exists("aikrange")) {
		SKIP("live", "netns aikrange 已存在，拒绝删除他人命名空间");
		return 0;
	}
	if (cmd("ip link show aikrh0 >/dev/null 2>&1") == 0) {
		SKIP("live", "aikrh0 已存在");
		return 0;
	}
	snprintf(audit, sizeof(audit), "%s/audit.log", getenv("AIKERNEL_RANGE_DIR") ?
		 getenv("AIKERNEL_RANGE_DIR") : "/tmp/aik-range-0");
	snprintf(udphex, sizeof(udphex), "/tmp/aikrange-udp-%d.hex", (int)getpid());
	snprintf(ready, sizeof(ready), "/tmp/aikrange-ready-%d", (int)getpid());
	snprintf(listener, sizeof(listener), "/tmp/aikrange-listener-%d.py", (int)getpid());
	snprintf(log, sizeof(log), "/tmp/aikrange-listener-%d.log", (int)getpid());
	snprintf(pidfile, sizeof(pidfile), "/tmp/aikrange-pid-%d", (int)getpid());
	snprintf(nft_before, sizeof(nft_before), "/tmp/aikrange-nft-%d.before", (int)getpid());
	snprintf(nft_after, sizeof(nft_after), "/tmp/aikrange-nft-%d.after", (int)getpid());
	snprintf(route_before, sizeof(route_before), "/tmp/aikrange-route-%d.before", (int)getpid());
	snprintf(route_after, sizeof(route_after), "/tmp/aikrange-route-%d.after", (int)getpid());

	capture("nft list ruleset", nft_before);
	capture("ip route show", route_before);
	printf("[+%.3fs] 基线：nft/路由已快照\n", now_s() - t0);

	if (cmd("ip netns add aikrange") != 0) {
		CHECK(0, "live-netns-add");
		return 1;
	}
	created_ns = 1;
	if (cmd("ip netns exec aikrange ip link set lo up") != 0 ||
	    cmd("ip link add aikrh0 type veth peer name aikrn0") != 0) {
		CHECK(0, "live-netns-veth");
		ok = 0;
		goto cleanup;
	}
	created_link = 1;
	if (cmd("ip link set aikrn0 netns aikrange") != 0 ||
	    cmd("ip addr add 10.99.1.1/24 dev aikrh0") != 0 ||
	    cmd("ip link set aikrh0 up") != 0 ||
	    cmd("ip netns exec aikrange ip addr add 10.99.1.2/24 dev aikrn0") != 0 ||
	    cmd("ip netns exec aikrange ip link set aikrn0 up") != 0) {
		CHECK(0, "live-netns-addr-up");
		ok = 0;
		goto cleanup;
	}
	printf("[+%.3fs] netns/veth 就绪：10.99.1.1 <-> 10.99.1.2\n",
	       now_s() - t0);

	/* 靶标：TCP 8000 + UDP 9000，UDP 收到的字节 hex 写文件 */
	{
		FILE *fp = fopen(listener, "w");

		if (!fp) {
			CHECK(0, "live-listener-write");
			ok = 0;
			goto cleanup;
		}
		fprintf(fp,
			"import socket, sys, threading, time\n"
			"out, ready = sys.argv[1], sys.argv[2]\n"
			"tcp = socket.socket()\n"
			"tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
			"tcp.bind(('10.99.1.2', 8000)); tcp.listen(8)\n"
			"udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
			"udp.bind(('10.99.1.2', 9000))\n"
			"open(ready, 'w').write('ready')\n"
			"def tl():\n"
			"    while True:\n"
			"        c, _ = tcp.accept()\n"
			"        c.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nok')\n"
			"        c.close()\n"
			"threading.Thread(target=tl, daemon=True).start()\n"
			"data, _ = udp.recvfrom(65535)\n"
			"open(out, 'w').write(data.hex())\n"
			"while True: time.sleep(1)\n");
		fclose(fp);
	}
	if (cmd("sh -c 'ip netns exec aikrange python3 -u %s %s %s > %s 2>&1 & echo $! > %s'",
		listener, udphex, ready, log, pidfile) != 0) {
		CHECK(0, "live-listener-start");
		ok = 0;
		goto cleanup;
	}
	for (int i = 0; i < 50 && access(ready, F_OK) != 0; i++)
		usleep(100000);
	if (access(ready, F_OK) != 0) {
		CHECK(0, "live-listener-ready");
		ok = 0;
		goto cleanup;
	}
	printf("[+%.3fs] 靶标监听就绪：TCP 10.99.1.2:8000 / UDP :9000\n",
	       now_s() - t0);

	/* 先测拒绝：非法 CIDR、越界目标 */
	call("range_enable", "{\"cidr\":\"192.168.245.0/24\"}", &out, &rc);
	printf("[+%.3fs] range_enable 192.168.245.0/24 rc=%d\n%s\n",
	       now_s() - t0, rc, out ? out : "(null)");
	CHECK(rc != 0, "live-enable-refuse-lab-cidr");
	free(out);
	out = NULL;

	call("range_enable", "{\"cidr\":\"10.99.0.0/16\","
	     "\"ttl_minutes\":10}", &out, &rc);
	printf("[+%.3fs] range_enable 10.99.0.0/16 rc=%d\n%s\n",
	       now_s() - t0, rc, out ? out : "(null)");
	CHECK(rc == 0 && out && strstr(out, "enabled=1"), "live-enable");
	free(out);
	out = NULL;

	call("range_scan", "{\"target\":\"192.168.245.1\",\"ports\":\"22\"}",
	     &out, &rc);
	printf("[+%.3fs] scan 192.168.245.1 rc=%d\n%s\n", now_s() - t0,
	       rc, out ? out : "(null)");
	CHECK(rc != 0, "live-scan-refuse-lab");
	free(out);
	out = NULL;
	call("range_scan", "{\"target\":\"8.8.8.8\",\"ports\":\"53\"}",
	     &out, &rc);
	printf("[+%.3fs] scan 8.8.8.8 rc=%d\n%s\n", now_s() - t0, rc,
	       out ? out : "(null)");
	CHECK(rc != 0, "live-scan-refuse-public");
	free(out);
	out = NULL;

	/* 发现：8000 open / 8001 closed */
	call("range_scan", "{\"target\":\"10.99.1.2\","
	     "\"ports\":\"8000,8001\",\"timeout_ms\":200,\"protocol\":\"tcp\"}",
	     &out, &rc);
	printf("[+%.3fs] scan 10.99.1.2:8000,8001 rc=%d\n%s\n",
	       now_s() - t0, rc, out ? out : "(null)");
	CHECK(rc == 0 && out && strstr(out, "8000 open"), "live-scan-open");
	CHECK(out && strstr(out, "8001 closed"), "live-scan-closed");
	free(out);
	out = NULL;

	/* 构造 + 注入 + 验证：UDP 标记 payload 字节一致 */
	(void)rg_hex_decode(payload_hex, payload, sizeof(payload), &plen, err,
			    sizeof(err));
	call("range_inject", "{\"target\":\"10.99.1.2\","
	     "\"protocol\":\"udp\",\"port\":9000,"
	     "\"payload_hex\":\"57383145322d52414e47452d5544502d00ff0102\"}",
	     &out, &rc);
	printf("[+%.3fs] inject UDP payload_hex=%s rc=%d\n%s\n",
	       now_s() - t0, payload_hex, rc, out ? out : "(null)");
	CHECK(rc == 0 && out && strstr(out, "bytes_sent="), "live-inject-udp");
	free(out);
	out = NULL;
	{
		char got[700] = "";
		int i;

		for (i = 0; i < 60; i++) {
			memset(got, 0, sizeof(got));
			if (read_file(udphex, got, sizeof(got)) > 0) {
				got[strcspn(got, "\r\n")] = '\0';
				if (strcmp(got, payload_hex) == 0)
					break;
			}
			usleep(50000);
		}
		if (got[0] == '\0') {
			CHECK(0, "live-udp-listener-file");
		} else {
			printf("[+%.3fs] 监听端收到 payload_hex=%s\n",
			       now_s() - t0, got);
			CHECK(strcmp(got, payload_hex) == 0,
			      "live-udp-bytes-identical");
		}
	}

	/* TCP SYN（root）与 ICMP（root）：发送成功即可 */
	call("range_inject", "{\"target\":\"10.99.1.2\","
	     "\"protocol\":\"tcp_syn\",\"port\":8000}", &out, &rc);
	printf("[+%.3fs] inject TCP SYN rc=%d\n%s\n", now_s() - t0, rc,
	       out ? out : "(null)");
	CHECK(rc == 0 && out && strstr(out, "tcp_sport="),
	      "live-inject-tcp-syn");
	free(out);
	out = NULL;
	call("range_inject", "{\"target\":\"10.99.1.2\","
	     "\"protocol\":\"icmp\",\"payload_hex\":\"5738314532\"}", &out,
	     &rc);
	printf("[+%.3fs] inject ICMP rc=%d\n%s\n", now_s() - t0, rc,
	       out ? out : "(null)");
	CHECK(rc == 0 && out && strstr(out, "icmp_id="), "live-inject-icmp");
	free(out);
	out = NULL;

	printf("[+%.3fs] 完整链：scan 发现 8000/open → 构造 payload %s → "
	       "UDP 注入 9000 → 监听端字节校验\n", now_s() - t0, payload_hex);

	call("range_disable", "{}", &out, &rc);
	printf("[+%.3fs] range_disable rc=%d\n%s\n", now_s() - t0, rc,
	       out ? out : "(null)");
	CHECK(rc == 0 && out && strstr(out, "enabled=0"), "live-disable");
	free(out);
	out = NULL;
	call("range_scan", "{\"target\":\"10.99.1.2\",\"ports\":\"8000\"}",
	     &out, &rc);
	CHECK(rc != 0, "live-after-disable-refused");
	free(out);
	out = NULL;

	printf("---- live audit tail ----\n");
	print_audit_tail(12);
	CHECK(file_has(audit, "\"payload_hex\":\"57383145322d52414e47452d5544502d00ff0102\""),
	      "live-audit-payload-full");
	CHECK(file_has(audit, "\"target\":\"192.168.245.1\""),
	      "live-audit-refusal-target");
	CHECK(file_has(audit, "\"action\":\"auto_disable\"") ||
	      file_has(audit, "\"action\":\"disable\""),
	      "live-audit-disable");

cleanup:
	printf("[+%.3fs] 清理：kill listener / 删 netns/veth\n", now_s() - t0);
	{
		char pidbuf[64];
		long pid = 0;

		if (read_file(pidfile, pidbuf, sizeof(pidbuf)) > 0)
			pid = strtol(pidbuf, NULL, 10);
		if (pid > 1)
			(void)kill((pid_t)pid, SIGTERM);
	}
	(void)cmd("pkill -f 'aikrange-listener-%d.py' 2>/dev/null", (int)getpid());
	if (created_link)
		(void)cmd("ip link del aikrh0 2>/dev/null");
	if (created_ns)
		(void)cmd("ip netns del aikrange 2>/dev/null");
	(void)unlink(udphex);
	(void)unlink(ready);
	(void)unlink(listener);
	(void)unlink(log);
	(void)unlink(pidfile);

	capture("nft list ruleset", nft_after);
	capture("ip route show", route_after);
	diff_lines(nft_before, nft_after, "host-nft-ruleset");
	diff_lines(route_before, route_after, "host-route-table");
	CHECK(cmd("ip netns list 2>/dev/null | grep -q '^aikrange'") != 0,
	      "live-netns-removed");
	CHECK(cmd("ip link show aikrh0 >/dev/null 2>&1") != 0,
	      "live-veth-removed");
	{
		char dir[512], state[600];

		if (rg_state_dir(dir, sizeof(dir)) == 0) {
			snprintf(state, sizeof(state), "%s/state.json", dir);
			CHECK(access(state, F_OK) != 0, "live-state-cleared");
		}
	}
	(void)unlink(nft_before);
	(void)unlink(nft_after);
	(void)unlink(route_before);
	(void)unlink(route_after);
	ok = (fails == 0);
	printf("live result: %s\n", ok ? "PASS" : "FAIL");
	return ok ? 0 : 1;
}

/* ===================== main ===================== */

int main(int argc, char **argv)
{
	char dir[] = "/tmp/aik-range-test-XXXXXX";
	int live = 0, ttl = 0, boundary_only = 0, keep = 0;
	char dpath[512];

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0)
			live = 1;
		else if (strcmp(argv[i], "--ttl-wait") == 0)
			ttl = 1;
		else if (strcmp(argv[i], "--boundary") == 0)
			boundary_only = 1;
		else if (strcmp(argv[i], "--keep") == 0)
			keep = 1;
		else if (strcmp(argv[i], "--all") == 0) {
			live = 1;
			ttl = 1;
		} else {
			fprintf(stderr, "usage: %s [--boundary|--live|--ttl-wait|--all] [--keep]\n",
				argv[0]);
			return 2;
		}
	}
	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 2;
	}
	chmod(dir, 0700);
	snprintf(dpath, sizeof(dpath), "%s", dir);
	setenv("AIKERNEL_RANGE_DIR", dpath, 1);

	printf("AIKERNEL_RANGE_DIR=%s euid=%d\n", dpath, (int)geteuid());
	printf("allowlist=%s\n", rg_allowlist_text());

	if (boundary_only) {
		test_boundary("boundary");
		printf("\nSUMMARY(boundary): checks=%d fails=%d skips=%d\n",
		       checks, fails, skips);
		cleanup_dir(dpath, keep);
		return fails ? 1 : 0;
	}
	if (ttl) {
		int r = test_ttl_wait();

		printf("\nSUMMARY(ttl-wait): checks=%d fails=%d skips=%d\n",
		       checks, fails, skips);
		cleanup_dir(dpath, keep);
		return r;
	}
	if (live) {
		int r = test_live();

		printf("\nSUMMARY(live): checks=%d fails=%d skips=%d\n",
		       checks, fails, skips);
		cleanup_dir(dpath, keep);
		return r;
	}

	/* 默认：run_all 快测（无真实扫描/发送） */
	test_pure();
	test_state_and_watchdog();
	test_boundary("default");
	test_registry();
	test_policy();
	printf("\nSUMMARY: checks=%d fails=%d skips=%d\n", checks, fails,
	       skips);
	cleanup_dir(dpath, keep);
	return fails ? 1 : 0;
}
