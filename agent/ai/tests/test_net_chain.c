/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_net_chain.c - W81 E1 conntrack 事件流 + 攻击链关联单测
 *
 * 非 root（run_all 默认）：
 *   - 阈值默认值 / 解析 / 范围与窗口-采样周期上限校验
 *   - conntrack 文本解析（procfs 与 conntrack -L 两种行型、IPv4/IPv6、
 *     TCP 状态词、UDP [UNREPLIED]、坏行跳过）
 *   - 三条关联规则（scan/lateral/burst）真值 + 冷却 + 源隔离
 *   - net_chain_rules get/set 往返（临时目录、0600、非法参数拒绝）
 *   - net_chain_watch status/stop 诚实输出；start 无事件源时明确失败
 *   - tools.json 已注册 net_chain_watch/net_chain_rules（channel=netchain）
 *
 * --live（root + AIK_TEST_NETNS=1 + ip netns 内；默认 aiktest，
 *   可用 AIK_W81E_NETNS 指定）：
 *   真 UDP 流量 → ctnetlink 采样 → scan（20 端口）/lateral（5 主机同端口）/
 *   burst（前窗 2 → 当前 8）三类事件落 events.jsonl + audit.log。
 *   测试自建 inet aik_chain_probe 表（仅 netns 内，用于激活 conntrack），
 *   结束删除；被测工具本身只读，不写任何 nft 规则。
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

#include "../tools/net_chain.h"
#include "../tools/tool_registry.h"

static int fails, checks, skips;

static void run_cmd(const char *cmd)
{
	int rc = system(cmd);

	(void)rc;
}

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

static void call(const char *name, const char *args, char **out, int *rc)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.channel = TOOL_CH_NETCHAIN;
	t.risk = "W1";
	t.name = (char *)name;
	*out = NULL;
	*rc = exec_net_chain_channel(&t, args, out);
}

/* ===================== 配置 ===================== */

static void test_cfg(void)
{
	struct nc_cfg c;
	char err[256];

	nc_cfg_default(&c);
	CHECK(c.interval == 2 && c.scan_window == 60 && c.scan_ports == 15,
	      "cfg-default-scan");
	CHECK(c.lateral_window == 60 && c.lateral_hosts == 3,
	      "cfg-default-lateral");
	CHECK(c.burst_window == 30 && c.burst_ratio == 4 &&
	      c.burst_min == 8 && c.burst_low == 3,
	      "cfg-default-burst");
	CHECK(c.cooldown == 60 && c.netns[0] == '\0', "cfg-default-misc");

	CHECK(nc_cfg_parse("{\"interval\":1,\"scan_ports\":9,"
			   "\"lateral_hosts\":5,\"netns\":\"aiktest\"}",
			   &c, err, sizeof(err)) == 0,
	      "cfg-parse-ok");
	CHECK(c.interval == 1 && c.scan_ports == 9 && c.lateral_hosts == 5 &&
	      strcmp(c.netns, "aiktest") == 0, "cfg-parse-values");
	CHECK(nc_cfg_check(&c, err, sizeof(err)) == 0, "cfg-check-ok");

	nc_cfg_default(&c);
	c.interval = 0;
	CHECK(nc_cfg_check(&c, err, sizeof(err)) != 0, "cfg-reject-interval-0");
	nc_cfg_default(&c);
	c.scan_ports = 1;
	CHECK(nc_cfg_check(&c, err, sizeof(err)) != 0, "cfg-reject-scan-1");
	nc_cfg_default(&c);
	c.lateral_hosts = 1;
	CHECK(nc_cfg_check(&c, err, sizeof(err)) != 0,
	      "cfg-reject-lateral-1");
	nc_cfg_default(&c);
	c.burst_ratio = 1;
	CHECK(nc_cfg_check(&c, err, sizeof(err)) != 0, "cfg-reject-ratio-1");
	nc_cfg_default(&c);
	c.burst_min = 3;
	c.burst_low = 3;
	CHECK(nc_cfg_check(&c, err, sizeof(err)) != 0,
	      "cfg-reject-min-le-low");
	nc_cfg_default(&c);
	c.scan_window = 3600;
	c.interval = 1;
	CHECK(nc_cfg_check(&c, err, sizeof(err)) != 0,
	      "cfg-reject-window-too-many-ticks");
	nc_cfg_default(&c);
	snprintf(c.netns, sizeof(c.netns), "bad|name");
	CHECK(nc_cfg_check(&c, err, sizeof(err)) != 0, "cfg-reject-bad-netns");
}

/* ===================== 文本解析 ===================== */

static void test_parse(void)
{
	struct nc_conn c;
	struct nc_conn arr[8];
	int n = 0, bad = 0;
	const char *tcp_line =
		"ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.1 "
		"dst=10.0.0.2 sport=43210 dport=80 packets=5 bytes=300 "
		"src=10.0.0.2 dst=10.0.0.1 sport=80 dport=43210 "
		"[ASSURED] mark=0 use=1";
	const char *udp_line =
		"ipv4     2 udp      17 29 src=127.0.0.1 dst=127.0.0.1 "
		"sport=60765 dport=20019 packets=1 bytes=1 "
		"src=127.0.0.1 dst=127.0.0.1 sport=20019 dport=60765 "
		"[UNREPLIED] mark=0 use=1";
	const char *cmd_line =
		"tcp      6 431999 ESTABLISHED src=192.0.2.1 dst=192.0.2.2 "
		"sport=1234 dport=443 packets=9 bytes=900";
	const char *v6_line =
		"ipv6    10 tcp      6 431999 ESTABLISHED src=fd00::1 "
		"dst=fd00::2 sport=1234 dport=443 packets=2 bytes=100";

	CHECK(nc_parse_ct_line(tcp_line, &c) == 1, "parse-tcp-procfs-ok");
	CHECK(strcmp(c.src, "10.0.0.1") == 0 &&
	      strcmp(c.dst, "10.0.0.2") == 0 &&
	      c.sport == 43210 && c.dport == 80 && c.proto == 6,
	      "parse-tcp-procfs-tuple");
	CHECK(strcmp(c.state, "ESTABLISHED") == 0 && c.packets == 5 &&
	      c.bytes == 300 && c.has_counter == 1,
	      "parse-tcp-procfs-state-counter");

	CHECK(nc_parse_ct_line(udp_line, &c) == 1, "parse-udp-procfs-ok");
	CHECK(c.proto == 17 && c.dport == 20019 &&
	      strcmp(c.state, "UNREPLIED") == 0,
	      "parse-udp-procfs-fields");

	CHECK(nc_parse_ct_line(cmd_line, &c) == 1, "parse-conntrack-L-ok");
	CHECK(strcmp(c.src, "192.0.2.1") == 0 && c.dport == 443 &&
	      strcmp(c.state, "ESTABLISHED") == 0,
	      "parse-conntrack-L-fields");

	CHECK(nc_parse_ct_line(v6_line, &c) == 1, "parse-ipv6-ok");
	CHECK(strcmp(c.src, "fd00::1") == 0 && strcmp(c.dst, "fd00::2") == 0,
	      "parse-ipv6-fields");

	CHECK(nc_parse_ct_line("this is not conntrack", &c) == 0,
	      "parse-garbage-rejected");
	CHECK(nc_parse_ct_line("ipv4 2 tcp 6 30 src=1.2.3.4", &c) == 0,
	      "parse-incomplete-rejected");

	{
		char text[1024];

		snprintf(text, sizeof(text), "%s\n\n%s\n%s\n", tcp_line,
			 "garbage line", udp_line);
		CHECK(nc_parse_ct_text(text, arr, 8, &n, &bad) == 0 &&
		      n == 2 && bad == 1, "parse-text-count");
	}
}

/* ===================== 关联规则 ===================== */

static void add_obs(struct nc_engine *e, long ts, const char *src,
		    const char *dst, int dport, int proto)
{
	struct nc_conn c;

	memset(&c, 0, sizeof(c));
	snprintf(c.src, sizeof(c.src), "%s", src);
	snprintf(c.dst, sizeof(c.dst), "%s", dst);
	c.proto = proto;
	c.sport = (unsigned short)(20000 + dport % 1000);
	c.dport = (unsigned short)dport;
	c.packets = -1;
	c.bytes = -1;
	c.hash = 0;
	(void)nc_engine_add(e, ts, &c);
}

static void test_engine(void)
{
	struct nc_engine *e = calloc(1, sizeof(*e));
	struct nc_cfg cfg;
	struct nc_hit hits[8];
	int hn = 0, i;

	if (!e) {
		printf("FAIL calloc engine\n");
		fails++;
		return;
	}
	nc_cfg_default(&cfg);

	/* --- scan：20 个不同目的端口 --- */
	nc_engine_init(e);
	for (i = 0; i < 20; i++)
		add_obs(e, 1000, "10.1.0.5", "10.2.0.9", 30000 + i, 17);
	CHECK(nc_engine_eval(e, &cfg, 1000, hits, 8, &hn) == 0 && hn == 1,
	      "engine-scan-hit");
	if (hn == 1) {
		CHECK(hits[0].type == NC_HIT_SCAN && hits[0].port_n == 20 &&
		      hits[0].evidence_count == 20 && hits[0].dst_n == 1 &&
		      hits[0].window == 60, "engine-scan-fields");
		CHECK(strstr(hits[0].rule, "scan_ports>=15") != NULL,
		      "engine-scan-rule");
	}

	/* --- scan 负例：5 个端口不够 --- */
	nc_engine_init(e);
	for (i = 0; i < 5; i++)
		add_obs(e, 1000, "10.1.0.6", "10.2.0.9", 40000 + i, 17);
	CHECK(nc_engine_eval(e, &cfg, 1000, hits, 8, &hn) == 0 && hn == 0,
	      "engine-scan-negative");

	/* --- lateral：同源同端口 4 个不同目的主机 --- */
	nc_engine_init(e);
	for (i = 0; i < 4; i++) {
		char dst[64];

		snprintf(dst, sizeof(dst), "10.3.0.%d", 10 + i);
		add_obs(e, 1000, "10.1.0.7", dst, 445, 6);
	}
	CHECK(nc_engine_eval(e, &cfg, 1000, hits, 8, &hn) == 0 && hn == 1,
	      "engine-lateral-hit");
	if (hn == 1)
		CHECK(hits[0].type == NC_HIT_LATERAL && hits[0].dst_n == 4 &&
		      hits[0].port_n == 1 && hits[0].ports[0] == 445 &&
		      hits[0].evidence_count == 4,
		      "engine-lateral-fields");

	/* --- lateral 负例：4 个不同端口到同一主机不算 --- */
	nc_engine_init(e);
	for (i = 0; i < 4; i++)
		add_obs(e, 1000, "10.1.0.8", "10.3.0.20", 5000 + i, 6);
	CHECK(nc_engine_eval(e, &cfg, 1000, hits, 8, &hn) == 0 && hn == 0,
	      "engine-lateral-negative");

	/* --- burst：前窗 2 → 当前 8（30s 窗口） --- */
	nc_engine_init(e);
	nc_cfg_default(&cfg);
	for (i = 0; i < 2; i++)
		add_obs(e, 950, "10.1.0.9", "10.4.0.5", 8080, 17);
	for (i = 0; i < 8; i++)
		add_obs(e, 985, "10.1.0.9", "10.4.0.5", 8080, 17);
	/* now=1000：当前窗 >970 有 8 条，前窗 (940,970] 有 2 条 */
	CHECK(nc_engine_eval(e, &cfg, 1000, hits, 8, &hn) == 0 && hn == 1,
	      "engine-burst-hit");
	if (hn == 1)
		CHECK(hits[0].type == NC_HIT_BURST && hits[0].cur_count == 8 &&
		      hits[0].prev_count == 2 && hits[0].evidence_count == 8,
		      "engine-burst-fields");

	/* --- burst 负例：前窗 6 已不算低位 --- */
	nc_engine_init(e);
	for (i = 0; i < 6; i++)
		add_obs(e, 950, "10.1.0.10", "10.4.0.6", 8080, 17);
	for (i = 0; i < 8; i++)
		add_obs(e, 985, "10.1.0.10", "10.4.0.6", 8080, 17);
	CHECK(nc_engine_eval(e, &cfg, 1000, hits, 8, &hn) == 0 && hn == 0,
	      "engine-burst-negative");

	/* --- 冷却：同键 60s 内不重复 --- */
	nc_engine_init(e);
	nc_cfg_default(&cfg);
	cfg.cooldown = 60;
	for (i = 0; i < 20; i++)
		add_obs(e, 1000, "10.1.0.11", "10.4.0.7", 30000 + i, 17);
	CHECK(nc_engine_eval(e, &cfg, 1000, hits, 8, &hn) == 0 && hn == 1,
	      "engine-cooldown-first");
	for (i = 0; i < 20; i++)
		add_obs(e, 1001, "10.1.0.11", "10.4.0.7", 31000 + i, 17);
	CHECK(nc_engine_eval(e, &cfg, 1001, hits, 8, &hn) == 0 && hn == 0,
	      "engine-cooldown-suppressed");
	for (i = 0; i < 20; i++)
		add_obs(e, 1062, "10.1.0.11", "10.4.0.7", 32000 + i, 17);
	CHECK(nc_engine_eval(e, &cfg, 1062, hits, 8, &hn) == 0 && hn == 1,
	      "engine-cooldown-expired");

	/* --- 源隔离：两个源各 10 端口，互不拼成 scan --- */
	nc_engine_init(e);
	for (i = 0; i < 10; i++) {
		add_obs(e, 1000, "10.1.0.12", "10.5.0.1", 40000 + i, 17);
		add_obs(e, 1000, "10.1.0.13", "10.5.0.2", 41000 + i, 17);
	}
	CHECK(nc_engine_eval(e, &cfg, 1000, hits, 8, &hn) == 0 && hn == 0,
	      "engine-source-isolation");

	free(e);
}

/* ===================== 工具层（rules/status/stop/start） ===================== */

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

static void test_tools(void)
{
	char tmpl[] = "/tmp/w81e-chain-XXXXXX";
	char *dir = mkdtemp(tmpl);
	char *out = NULL;
	int rc;
	struct stat st;

	if (!dir) {
		printf("FAIL mkdtemp\n");
		fails++;
		return;
	}
	setenv("AIKERNEL_NET_CHAIN_DIR", dir, 1);

	call("net_chain_rules", "{\"action\":\"get\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "interval=2s") &&
	      strstr(out, "scan") && strstr(out, "lateral") &&
	      strstr(out, "burst"), "rules-get-defaults");
	free(out);
	out = NULL;

	call("net_chain_rules",
	     "{\"action\":\"set\",\"scan_ports\":7,\"lateral_hosts\":4,"
	     "\"netns\":\"aiktest\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "set 完成") != NULL,
	      "rules-set-ok");
	free(out);
	out = NULL;
	{
		char path[600];

		snprintf(path, sizeof(path), "%s/rules.json", dir);
		CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600,
		      "rules-file-0600");
		CHECK(file_has(path, "\"scan_ports\": 7"), "rules-file-value");
	}
	call("net_chain_rules", "{\"action\":\"get\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "ports>=7") != NULL,
	      "rules-get-after-set");
	free(out);
	out = NULL;

	call("net_chain_rules", "{\"action\":\"set\",\"scan_ports\":1}",
	     &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ERROR") != NULL,
	      "rules-set-invalid-rejected");
	free(out);
	out = NULL;

	call("net_chain_watch", "{\"action\":\"status\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "state=") != NULL,
	      "watch-status-ok");
	CHECK(out && strstr(out, "source_probe:") != NULL &&
	      strstr(out, "procfs=") != NULL &&
	      strstr(out, "conntrack_cmd=") != NULL &&
	      strstr(out, "ctnetlink=") != NULL,
	      "watch-status-source-probe-honest");
	CHECK(out && strstr(out, "只观测") != NULL, "watch-status-no-ban-note");
	free(out);
	out = NULL;

	call("net_chain_watch", "{\"action\":\"stop\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "已停止") != NULL,
	      "watch-stop-not-running");
	free(out);
	out = NULL;

	if (geteuid() != 0 &&
	    access("/proc/net/nf_conntrack", R_OK) != 0 &&
	    access("/usr/sbin/conntrack", X_OK) != 0 &&
	    access("/sbin/conntrack", X_OK) != 0 &&
	    access("/usr/bin/conntrack", X_OK) != 0) {
		call("net_chain_watch",
		     "{\"action\":\"start\",\"interval\":1}", &out, &rc);
		CHECK(rc != 0 && out && strstr(out, "ERROR") != NULL,
		      "watch-start-nonroot-explicit-error");
		CHECK(out && (strstr(out, "权限不足") != NULL ||
			      strstr(out, "不可用") != NULL),
		      "watch-start-nonroot-no-silent-success");
		free(out);
		out = NULL;
	} else {
		SKIP("watch-start-nonroot-explicit-error",
		     "当前为 root 或存在可读事件源");
	}

	call("net_chain_watch", "{\"action\":\"bogus\"}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ERROR") != NULL,
	      "watch-bogus-action-rejected");
	free(out);
	out = NULL;
	call("net_chain_bogus", "{}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "未知") != NULL,
	      "unknown-tool-rejected");
	free(out);
	out = NULL;

	/* 注册表：两个工具 + netchain 通道（cwd 可能在 tests/ 或其他） */
	{
		const char *cands[] = {
			"../tools/tools.json",
			"tools/tools.json",
			"agent/ai/tools/tools.json",
			NULL,
		};
		const char *path = NULL;
		int i;

		for (i = 0; cands[i]; i++)
			if (access(cands[i], R_OK) == 0) {
				path = cands[i];
				break;
			}
		if (path) {
			CHECK(file_has(path, "\"name\": \"net_chain_watch\"") &&
			      file_has(path, "\"name\": \"net_chain_rules\""),
			      "registry-has-netchain-tools");
			CHECK(file_has(path, "\"channel\": \"netchain\""),
			      "registry-has-netchain-channel");
		} else {
			SKIP("registry-has-netchain-tools",
			     "未找到 tools/tools.json（cwd 不在仓库内）");
			SKIP("registry-has-netchain-channel",
			     "未找到 tools/tools.json（cwd 不在仓库内）");
		}
		CHECK(TOOL_CH_NETCHAIN > TOOL_CH_APPPROFILE &&
		      TOOL_CH_NETCHAIN < TOOL_CH_UNKNOWN,
		      "channel-enum-order");
	}
	unsetenv("AIKERNEL_NET_CHAIN_DIR");
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

static int udp_send_to(const char *dst, int port)
{
	int fd, rc;
	struct sockaddr_in to;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons((unsigned short)port);
	if (inet_pton(AF_INET, dst, &to.sin_addr) != 1)
		return -1;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	rc = (int)sendto(fd, "w81e", 4, 0, (struct sockaddr *)&to,
			 sizeof(to));
	close(fd);
	return rc < 0 ? -1 : 0;
}

static void save_text(const char *dir, const char *name, const char *text)
{
	char path[600];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	if (text)
		(void)!write(fd, text, strlen(text));
	close(fd);
}

static const char *event_line(const char *path, const char *type,
			      char *buf, size_t cap)
{
	static char *all;
	size_t n = 0;
	int fd;

	if (!all) {
		all = malloc(1024 * 1024);
		if (!all)
			return NULL;
	}
	all[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t r = read(fd, all, 1024 * 1024 - 1);

		close(fd);
		if (r > 0)
			n = (size_t)r;
	}
	all[n] = '\0';
	{
		char needle[64];
		char *p;

		snprintf(needle, sizeof(needle), "\"type\":\"%s\"", type);
		p = strstr(all, needle);
		if (!p)
			return NULL;
		{
			char *start = p;

			while (start > all && start[-1] != '\n')
				start--;
			{
				char *end = strchr(p, '\n');
				size_t len = end ? (size_t)(end - start) :
						  strlen(start);

				if (len >= cap)
					len = cap - 1;
				memcpy(buf, start, len);
				buf[len] = '\0';
			}
		}
		return buf;
	}
}

static int field_int(const char *line, const char *key, long *out)
{
	char needle[64];
	const char *p;

	snprintf(needle, sizeof(needle), "\"%s\":", key);
	p = strstr(line, needle);
	if (!p)
		return -1;
	p += strlen(needle);
	*out = strtol(p, NULL, 10);
	return 0;
}

static int run_live(void)
{
	char tmpl[] = "/tmp/w81e-chain-live-XXXXXX";
	const char *edir = getenv("AIK_W81E_EVIDENCE_DIR");
	char *dir;
	char audit[600], events[600];
	char *out = NULL;
	char line[4096];
	char startargs[1024];
	const char *nsname = getenv("AIK_W81E_NETNS");
	int rc, i;

	if (!nsname || !*nsname)
		nsname = "aiktest";
	printf("== LIVE（netns %s 内真流量）==\n", nsname);
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
	if (in_named_netns(nsname) != 1) {
		printf("REFUSE: 当前进程不在 netns %s 内\n", nsname);
		return 2;
	}
	setenv("AIKERNEL_NET_CHAIN_DIR", dir, 1);
	snprintf(audit, sizeof(audit), "%s/audit.log", dir);
	snprintf(events, sizeof(events), "%s/events.jsonl", dir);
	printf("  状态目录：%s\n", dir);

	/* 测试夹具：仅 netns 内加一条 ct 规则激活 conntrack（工具本身只读） */
	run_cmd("nft delete table inet aik_chain_probe 2>/dev/null");
	CHECK(system("nft add table inet aik_chain_probe") == 0,
	      "live-setup-table");
	CHECK(system("nft add chain inet aik_chain_probe pre "
		     "'{ type filter hook prerouting priority raw; "
		     "policy accept; }'") == 0, "live-setup-chain");
	CHECK(system("nft add rule inet aik_chain_probe pre ct state new "
		     "counter accept") == 0, "live-setup-ct-rule");
	/* 只在测试 netns 内清空连接表：让“空表”证据可复现 */
	run_cmd("echo 0 > /proc/sys/net/netfilter/nf_conntrack_flush "
		"2>/dev/null");

	/* 1) start：事件源探测 + 空表/计数不可用如实标注 */
	snprintf(startargs, sizeof(startargs),
		 "{\"action\":\"start\",\"interval\":1,\"scan_window\":10,"
		 "\"scan_ports\":12,\"lateral_window\":10,"
		 "\"lateral_hosts\":3,\"burst_window\":5,"
		 "\"burst_ratio\":3,\"burst_min\":5,\"burst_low\":2,"
		 "\"cooldown\":30,\"netns\":\"%s\"}", nsname);
	call("net_chain_watch", startargs, &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "state=running") != NULL,
	      "live-start");
	CHECK(out && strstr(out, "procfs=") && strstr(out, "ctnetlink="),
	      "live-start-source-probe");
	if (out) {
		printf("---- start 输出 ----\n%s\n", out);
		save_text(dir, "start.txt", out);
	}
	free(out);
	out = NULL;
	sleep(3);	/* 首拍建立基线 */
	call("net_chain_watch", "{\"action\":\"status\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "table=") != NULL,
	      "live-status-before-traffic");
	CHECK(out && strstr(out, "table=empty") != NULL,
	      "live-status-empty-table-honest");
	CHECK(out && strstr(out, "acct=") != NULL,
	      "live-status-acct-honest");
	if (out)
		save_text(dir, "status-before-traffic.txt", out);
	free(out);
	out = NULL;

	/* 2) scan：20 个不同目的端口 */
	for (i = 0; i < 20; i++)
		(void)udp_send_to("127.0.0.1", 30000 + i);
	CHECK(wait_file(events, "\"type\":\"scan\"", 10), "live-scan-event");
	if (event_line(events, "scan", line, sizeof(line))) {
		long ev = 0, win = 0;

		printf("---- scan 事件 ----\n%s\n", line);
		CHECK(strstr(line, "\"src\":\"127.0.0.1\"") != NULL,
		      "live-scan-src");
		CHECK(field_int(line, "evidence_count", &ev) == 0 && ev >= 20,
		      "live-scan-evidence");
		CHECK(field_int(line, "window", &win) == 0 && win == 10,
		      "live-scan-window");
		CHECK(strstr(line, "30000") && strstr(line, "30019"),
		      "live-scan-ports-span");
	} else {
		CHECK(0, "live-scan-fields");
	}

	/* 3) lateral：同一端口 5 个不同目的主机 */
	for (i = 2; i <= 6; i++) {
		char dst[32];

		snprintf(dst, sizeof(dst), "127.0.0.%d", i);
		(void)udp_send_to(dst, 4444);
	}
	CHECK(wait_file(events, "\"type\":\"lateral\"", 10),
	      "live-lateral-event");
	if (event_line(events, "lateral", line, sizeof(line))) {
		long ev = 0;

		printf("---- lateral 事件 ----\n%s\n", line);
		CHECK(strstr(line, "\"src\":\"127.0.0.1\"") != NULL &&
		      strstr(line, "\"ports\":[4444]") != NULL,
		      "live-lateral-fields");
		CHECK(field_int(line, "evidence_count", &ev) == 0 && ev >= 5,
		      "live-lateral-evidence");
	} else {
		CHECK(0, "live-lateral-fields");
	}

	/* 4) burst：前窗 2 条 → 当前 8 条（同一源→目的） */
	(void)udp_send_to("127.0.0.9", 5555);
	(void)udp_send_to("127.0.0.9", 5555);
	sleep(6);	/* 让这 2 条落入前一窗口 */
	for (i = 0; i < 8; i++)
		(void)udp_send_to("127.0.0.9", 5555);
	CHECK(wait_file(events, "\"type\":\"burst\"", 10), "live-burst-event");
	if (event_line(events, "burst", line, sizeof(line))) {
		long cur = 0, prev = 0;

		printf("---- burst 事件 ----\n%s\n", line);
		CHECK(strstr(line, "\"dsts\":[\"127.0.0.9\"]") != NULL,
		      "live-burst-dst");
		CHECK(field_int(line, "cur_count", &cur) == 0 && cur >= 8 &&
		      field_int(line, "prev_count", &prev) == 0 && prev >= 1,
		      "live-burst-counts");
	} else {
		CHECK(0, "live-burst-fields");
	}

	/* 5) 审计 + 事件文件 + stop */
	CHECK(file_has(audit, "CHAIN type=scan") &&
	      file_has(audit, "CHAIN type=lateral") &&
	      file_has(audit, "CHAIN type=burst"), "live-audit-chain-lines");
	CHECK(file_has(audit, "action=observe"), "live-audit-observe-only");
	call("net_chain_watch", "{\"action\":\"status\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "events=") != NULL,
	      "live-status-after-traffic");
	if (out)
		save_text(dir, "status-after-traffic.txt", out);
	free(out);
	out = NULL;
	call("net_chain_watch", "{\"action\":\"stop\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "已停止") != NULL, "live-stop");
	if (out)
		save_text(dir, "stop.txt", out);
	free(out);
	out = NULL;
	call("net_chain_watch", "{\"action\":\"status\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "state=stopped") != NULL,
	      "live-state-stopped");
	if (out)
		save_text(dir, "status-stopped.txt", out);
	free(out);

	run_cmd("nft delete table inet aik_chain_probe 2>/dev/null");
	unsetenv("AIKERNEL_NET_CHAIN_DIR");
	printf("  证据目录保留：%s\n", dir);
	return 0;
}

/* 非 root 降级证据：status/rules/start 的真实输出落文件（不启动采样器） */
static int run_degrade(const char *dir)
{
	char *out = NULL;
	int rc;

	printf("== DEGRADE EVIDENCE（uid=%u, dir=%s）==\n",
	       (unsigned)geteuid(), dir);
	if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
		printf("ERROR: 目录创建失败 %s: %s\n", dir, strerror(errno));
		return 2;
	}
	setenv("AIKERNEL_NET_CHAIN_DIR", dir, 1);
	call("net_chain_watch", "{\"action\":\"status\"}", &out, &rc);
	CHECK(rc == 0 && out != NULL, "degrade-status-call");
	if (out) {
		printf("%s\n", out);
		save_text(dir, "status.txt", out);
	}
	free(out);
	out = NULL;
	call("net_chain_rules", "{\"action\":\"get\"}", &out, &rc);
	CHECK(rc == 0 && out != NULL, "degrade-rules-call");
	if (out)
		save_text(dir, "rules.txt", out);
	free(out);
	out = NULL;
	call("net_chain_watch", "{\"action\":\"start\",\"interval\":1}",
	     &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ERROR") != NULL,
	      "degrade-start-refused");
	if (out) {
		printf("---- start 拒绝原文 ----\n%s\n", out);
		save_text(dir, "start-error.txt", out);
	}
	free(out);
	out = NULL;
	call("net_chain_watch", "{\"action\":\"stop\"}", &out, &rc);
	if (out)
		save_text(dir, "stop.txt", out);
	free(out);
	unsetenv("AIKERNEL_NET_CHAIN_DIR");
	return fails ? 1 : 0;
}

int main(int argc, char **argv)
{
	int live = (argc > 1 && strcmp(argv[1], "--live") == 0);

	if (argc > 2 && strcmp(argv[1], "--degrade") == 0)
		return run_degrade(argv[2]);

	printf("== test_net_chain (uid=%u, live=%d) ==\n",
	       (unsigned)geteuid(), live);
	test_cfg();
	test_parse();
	test_engine();
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
