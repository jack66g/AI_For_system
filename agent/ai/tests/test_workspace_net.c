// SPDX-License-Identifier: GPL-2.0
/*
 * test_workspace_net.c - W81d 工作区网络（net=veth）回归
 *
 * 默认（非 root，零副作用）：
 *   - 白名单校验：dst 地址/CIDR 边界、port 边界、proto 枚举、icmp 不接受
 *     port、注入字符一律拒绝；
 *   - 命名派生：netns=aikws-<name>、表=aik_ws_<name>、veth=aikv/aikc<hash>
 *     （IFNAMSIZ<=15，确定性）；
 *   - 注册表接线：226 件、workspace 通道 8 件、新增两件的 risk/sub；
 *   - 危险分级：workspace_net_allow=D2、workspace_net_status=D0；
 *   - 元数据往返：net=veth + net_ns/net_ip/allow 行解析；
 *   - 诚实错误：不存在的工作区 → NOT_FOUND；net 非法 → INVALID_ARG；
 *     allow 用在 net=none → INVALID_ARG（零副作用）。
 *
 * --live（root + 真 aik-sandbox + ip/nft）：
 *   net=none 旧行为（只有 lo）→ net=veth（独立 netns + 一对 veth + aikbr0）
 *   → 缺省拒出站（ping/curl 全失败）→ 加白名单后目标可达（ICMP/TCP 22）
 *   → 非白名单仍不可达（:80）→ 删白名单后重新不可达 → net_status 计数
 *   → destroy 零残留（netns/veth/网桥成员/产物目录）→ 宿主 ruleset 与
 *     路由表与操作前逐字节一致。
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
#include <sys/wait.h>

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

/* ---- 直接调通道实现（不经过 lease 闸门，专测语义） ---- */
static int call_tool(const char *tool, const char *args, char **out)
{
	struct ai_tool t;
	int rc;

	memset(&t, 0, sizeof(t));
	t.name = (char *)tool;
	t.channel = TOOL_CH_WORKSPACE;
	t.risk = (char *)"W2";
	*out = NULL;
	rc = exec_workspace_channel(&t, args, out);
	return rc;
}

/* ---- 纯函数 ---- */
static void test_allow_validator(void)
{
	/* dst：IPv4 / IPv6 / CIDR */
	CHECK(ai_ws_valid_allow("10.231.0.1", 0, "any") == 1,
	      "dst IPv4 + any 合法");
	CHECK(ai_ws_valid_allow("10.231.0.1", 22, "tcp") == 1,
	      "dst IPv4 + tcp/22 合法");
	CHECK(ai_ws_valid_allow("192.168.1.0/24", 53, "udp") == 1,
	      "CIDR + udp/53 合法");
	CHECK(ai_ws_valid_allow("0.0.0.0/0", 443, "tcp") == 1,
	      "0.0.0.0/0 合法");
	CHECK(ai_ws_valid_allow("::1", 22, "tcp") == 1, "IPv6 ::1 合法");
	CHECK(ai_ws_valid_allow("2001:db8::/32", 0, "icmp") == 1,
	      "IPv6 CIDR + icmp 合法");
	CHECK(ai_ws_valid_allow("10.0.0.1", 0, NULL) == 1,
	      "proto 省略 + 无 port → 按 any 处理");
	CHECK(ai_ws_valid_allow("10.0.0.1", 8080, NULL) == 1,
	      "proto 省略 + port → 按 tcp 处理");

	/* 边界/非法 */
	CHECK(ai_ws_valid_allow("10.0.0.0/33", 0, "any") == 0,
	      "IPv4 前缀 33 拒绝");
	CHECK(ai_ws_valid_allow("10.0.0.0/32", 0, "any") == 1,
	      "IPv4 前缀 32 合法");
	CHECK(ai_ws_valid_allow("2001:db8::/129", 0, "any") == 0,
	      "IPv6 前缀 129 拒绝");
	CHECK(ai_ws_valid_allow("10.0.0.0/", 0, "any") == 0, "空前缀拒绝");
	CHECK(ai_ws_valid_allow("10.0.0.0/8x", 0, "any") == 0,
	      "前缀含字母拒绝");
	CHECK(ai_ws_valid_allow("999.1.1.1", 0, "any") == 0,
	      "非法 IPv4 拒绝");
	CHECK(ai_ws_valid_allow("10.0.0.1", 65536, "tcp") == 0,
	      "port 65536 拒绝");
	CHECK(ai_ws_valid_allow("10.0.0.1", 65535, "tcp") == 1,
	      "port 65535 合法");
	CHECK(ai_ws_valid_allow("10.0.0.1", 0, "tcp") == 1,
	      "port 0 = 任意端口合法");
	CHECK(ai_ws_valid_allow("10.0.0.1", 22, "sctp") == 0,
	      "未知 proto 拒绝");
	CHECK(ai_ws_valid_allow("10.0.0.1", 22, "icmp") == 0,
	      "icmp 不接受 port");
	CHECK(ai_ws_valid_allow("10.0.0.1", 22, "any") == 0,
	      "any 不接受 port");

	/* 注入面 */
	CHECK(ai_ws_valid_allow("1.2.3.4; reboot", 0, "any") == 0,
	      "dst 含分号拒绝");
	CHECK(ai_ws_valid_allow("1.2.3.4 $(id)", 0, "any") == 0,
	      "dst 含 $( ) 拒绝");
	CHECK(ai_ws_valid_allow("1.2.3.4\naccept", 0, "any") == 0,
	      "dst 含换行拒绝");
	CHECK(ai_ws_valid_allow("", 0, "any") == 0, "dst 空拒绝");
	CHECK(ai_ws_valid_allow(NULL, 0, "any") == 0, "dst NULL 拒绝");
}

static void test_net_names(void)
{
	char ns[64], tbl[64], hif[32], wif[32];
	char ns2[64], tbl2[64], hif2[32], wif2[32];

	ai_ws_net_names("ws-test", ns, sizeof(ns), tbl, sizeof(tbl),
			hif, sizeof(hif), wif, sizeof(wif));
	CHECK(strcmp(ns, "aikws-ws-test") == 0, "netns 名 = aikws-<name>");
	CHECK(strcmp(tbl, "aik_ws_ws-test") == 0, "nft 表名 = aik_ws_<name>");
	CHECK(strncmp(hif, "aikv", 4) == 0 && strlen(hif) <= 15,
	      "宿主侧 veth 名 aikv<hash>（<=15 字符）");
	CHECK(strncmp(wif, "aikc", 4) == 0 && strlen(wif) <= 15,
	      "工作区侧 veth 名 aikc<hash>（<=15 字符）");
	CHECK(strcmp(hif, wif) != 0, "两侧 veth 名不同");

	ai_ws_net_names("ws-test", ns2, sizeof(ns2), tbl2, sizeof(tbl2),
			hif2, sizeof(hif2), wif2, sizeof(wif2));
	CHECK(strcmp(ns, ns2) == 0 && strcmp(tbl, tbl2) == 0 &&
	      strcmp(hif, hif2) == 0 && strcmp(wif, wif2) == 0,
	      "命名派生确定性（同名同结果）");

	ai_ws_net_names("ws-test2", ns2, sizeof(ns2), tbl2, sizeof(tbl2),
			hif2, sizeof(hif2), wif2, sizeof(wif2));
	CHECK(strcmp(hif, hif2) != 0, "不同工作区 veth 名不同");
	CHECK(strlen(ns) <= 63 && strlen(tbl) <= 63, "名字长度在上限内");
}

/* ---- 注册表 / 危险分级 ---- */
static void test_registry(struct tool_registry *reg)
{
	const struct ai_tool *t;
	int i, ws = 0, ok = 1;
	static const char *const want[] = {
		"workspace_create", "workspace_list", "workspace_inspect",
		"workspace_run", "workspace_destroy", "workspace_quota",
		"workspace_net_allow", "workspace_net_status",
	};
	static const char *const want_risk[] = {
		"W1", "R", "R", "W2", "W1", "W1", "W2", "R",
	};

	CHECK(reg->tool_count == 226, "注册表总数 226（W82：215 + 3 控制面 + 2 策略 + 2 适配）");
	for (i = 0; i < reg->tool_count; i++)
		if (reg->tools[i].channel == TOOL_CH_WORKSPACE)
			ws++;
	CHECK(ws == 8, "workspace 通道恰 8 件");
	for (i = 0; i < 8; i++) {
		t = tool_registry_find(reg, want[i]);
		if (!t || t->channel != TOOL_CH_WORKSPACE || !t->risk ||
		    strcmp(t->risk, want_risk[i]) != 0 || t->sub_count < 1)
			ok = 0;
	}
	CHECK(ok, "八件工具注册/channel/risk/sub 齐全");
	t = tool_registry_find(reg, "workspace_net_allow");
	CHECK(t && strcmp(tool_exec_effective_risk(t, "{}"), "W2") == 0,
	      "workspace_net_allow 有效风险 = W2（D2 级）");
	t = tool_registry_find(reg, "workspace_net_status");
	CHECK(t && strcmp(tool_exec_effective_risk(t, "{}"), "R") == 0,
	      "workspace_net_status 有效风险 = R（D0 级）");
}

static void test_danger(void)
{
	char *target = NULL;
	const char *why = NULL;

	CHECK(ai_danger_classify("workspace_net_allow", "sandbox,fs", "W2",
				 "{}", &target, &why) == AI_D2,
	      "workspace_net_allow 危险级 = D2");
	free(target);
	target = NULL;
	why = NULL;
	CHECK(ai_danger_classify("workspace_net_status", "sandbox,fs", "R",
				 "{}", &target, &why) == AI_D0,
	      "workspace_net_status 危险级 = D0");
	free(target);
}

/* ---- 元数据往返 + 诚实错误（零副作用） ---- */
static void write_fake_meta(const char *root, const char *name, int veth)
{
	char path[1024];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s.meta", root, name);
	f = fopen(path, "w");
	if (!f)
		return;
	fprintf(f, "name=%s\nbacking=tmpfs\nimage=\nloop=\nsize_mb=0\n"
		"created=1700000000\nlabel=\ncpus=1.00\nmem_mb=1024\n"
		"pids_max=256\nnet=%s\n", name, veth ? "veth" : "none");
	if (veth)
		fprintf(f, "net_ns=aikws-%s\nnet_ip=10.231.7.7\n"
			"net_host_if=aikv0bad0000\nnet_ws_if=aikc0bad0000\n"
			"allow=tcp;22;10.231.0.1\nallow=icmp;0;10.231.0.2\n",
			name);
	fclose(f);
}

static void test_meta_and_errors(const char *root)
{
	char *out = NULL;
	int rc;

	/* 不存在 */
	rc = call_tool("workspace_net_status", "{\"name\":\"no-such-ws\"}",
		       &out);
	CHECK(rc == AI_ERR_NOT_FOUND && out && strstr(out, "不存在"),
	      "net_status 不存在 → NOT_FOUND + 明确文案");
	free(out);
	out = NULL;
	rc = call_tool("workspace_net_allow",
		       "{\"name\":\"no-such-ws\",\"action\":\"list\"}", &out);
	CHECK(rc == AI_ERR_NOT_FOUND, "net_allow 不存在 → NOT_FOUND");
	free(out);
	out = NULL;

	/* net 非法 */
	rc = call_tool("workspace_create",
		       "{\"name\":\"w81dbadnet\",\"size_mb\":64,"
		       "\"net\":\"bridge\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "none|veth|host"),
	      "create net=bridge → INVALID_ARG（只接受 none|veth|host）");
	free(out);
	out = NULL;

	/* allow 只对 veth 有意义；且非法 dst 被拒 */
	rc = call_tool("workspace_create",
		       "{\"name\":\"w81dbadnet\",\"size_mb\":64,"
		       "\"net\":\"none\",\"allow\":[{\"dst\":\"1.1.1.1\","
		       "\"port\":22,\"proto\":\"tcp\"}]}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "allow 只对 net=veth"),
	      "create net=none + allow → INVALID_ARG");
	free(out);
	out = NULL;
	rc = call_tool("workspace_create",
		       "{\"name\":\"w81dbadnet\",\"size_mb\":64,"
		       "\"net\":\"veth\",\"allow\":[{\"dst\":\"1.1.1.1; id\","
		       "\"port\":22,\"proto\":\"tcp\"}]}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "dst="),
	      "create allow 注入 dst → INVALID_ARG");
	free(out);
	out = NULL;

	/* 假 meta：net=veth 的元数据往返（不存在的 netns 一律“缺失”，不崩） */
	write_fake_meta(root, "w81dfake", 1);
	rc = call_tool("workspace_net_status", "{\"name\":\"w81dfake\"}", &out);
	CHECK(rc == AI_OK && out && strstr(out, "net=veth") &&
	      strstr(out, "10.231.7.7") && strstr(out, "aikws-w81dfake") &&
	      strstr(out, "tcp;22;10.231.0.1") &&
	      strstr(out, "icmp;0;10.231.0.2"),
	      "net_status 解析 net=veth 元数据（netns/地址/白名单）");
	free(out);
	out = NULL;

	/* net=none 的工作区：net_allow 明确拒绝 */
	write_fake_meta(root, "w81dfakenone", 0);
	rc = call_tool("workspace_net_allow",
		       "{\"name\":\"w81dfakenone\",\"action\":\"add\","
		       "\"dst\":\"10.0.0.1\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "只有 net=veth"),
	      "net=none 工作区 + net_allow → INVALID_ARG");
	free(out);
	out = NULL;
	rc = call_tool("workspace_net_status", "{\"name\":\"w81dfakenone\"}",
		       &out);
	CHECK(rc == AI_OK && out && strstr(out, "net=none") &&
	      strstr(out, "无工作区网络拓扑"),
	      "net=none 工作区 net_status 明说无拓扑");
	free(out);
	out = NULL;

	/* 非法 action */
	rc = call_tool("workspace_net_allow",
		       "{\"name\":\"w81dfake\",\"action\":\"flushall\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "add|del|list"),
	      "非法 action → INVALID_ARG");
	free(out);
	out = NULL;

	/* add 缺 dst */
	rc = call_tool("workspace_net_allow",
		       "{\"name\":\"w81dfake\",\"action\":\"add\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "需要 dst"),
	      "add 缺 dst → INVALID_ARG");
	free(out);
}

/* ---- live：真实 netns/veth/nft ---- */

static char *sh_run(const char *cmd, int *rc)
{
	FILE *p;
	char *buf = NULL;
	size_t len = 0, cap = 0;
	char chunk[512];
	size_t n;

	p = popen(cmd, "r");
	if (!p) {
		if (rc)
			*rc = -1;
		return NULL;
	}
	while ((n = fread(chunk, 1, sizeof(chunk), p)) > 0) {
		if (len + n + 1 > cap) {
			cap = (len + n + 1) * 2;
			buf = realloc(buf, cap);
			if (!buf) {
				pclose(p);
				return NULL;
			}
		}
		memcpy(buf + len, chunk, n);
		len += n;
	}
	if (!buf) {
		buf = malloc(1);
		if (buf)
			buf[0] = '\0';
	} else {
		buf[len] = '\0';
	}
	if (rc) {
		int st = pclose(p);

		*rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	} else {
		pclose(p);
	}
	return buf;
}

static int sh_ok(const char *cmd)
{
	int rc = -1;

	free(sh_run(cmd, &rc));
	return rc == 0;
}

static char *snapshot(const char *what)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd), "%s", what);
	return sh_run(cmd, NULL);
}

/*
 * workspace_run 包装：create 后首次挂载偶发 EIO 是 W79 loop 复用路径的既有
 * 抖动（与本棒无关；test_workspace --live 也复现，重跑即好）。只在
 * "sandbox 组装失败 + Input/output error" 时重试一次，其余失败原样返回。
 */
static int run_ws(const char *name, const char *cmd, char **out)
{
	char args[512];
	int rc;

	snprintf(args, sizeof(args),
		 "{\"name\":\"%s\",\"command\":\"%s\"}", name, cmd);
	rc = call_tool("workspace_run", args, out);
	if (rc != AI_OK && *out && strstr(*out, "Input/output error")) {
		free(*out);
		*out = NULL;
		rc = call_tool("workspace_run", args, out);
	}
	return rc;
}

static void live_step(int *pass, int *total, const char *tag, int cond,
		      const char *detail)
{
	(*total)++;
	if (cond) {
		printf("ok LIVE-%s\n", tag);
		(*pass)++;
	} else {
		printf("FAIL LIVE-%s%s%s\n", tag,
		       detail && detail[0] ? " :: " : "",
		       detail ? detail : "");
	}
}

static int live(void)
{
	char *out = NULL;
	char *r0 = NULL, *r60 = NULL, *r4 = NULL, *r6 = NULL;
	char ns[64], tbl[64], hif[32], wif[32];
	char path[512];
	struct stat st;
	int rc, pass = 0, total = 0;
	const char *bin = getenv("AIKERNEL_SANDBOX_BIN");

	printf("== test_workspace_net --live (uid=%u, bin=%s) ==\n",
	       (unsigned)getuid(), bin ? bin : "(default)");
	if (getuid() != 0) {
		printf("SKIP: --live 需要 root（netns/veth/nft）\n");
		return 0;
	}

	ai_ws_net_names("w81dnet", ns, sizeof(ns), tbl, sizeof(tbl),
			hif, sizeof(hif), wif, sizeof(wif));

	/* 0. 清场 */
	(void)call_tool("workspace_destroy", "{\"name\":\"w81dnet\"}", &out);
	free(out);
	out = NULL;
	(void)call_tool("workspace_destroy", "{\"name\":\"w81dnone\"}", &out);
	free(out);
	out = NULL;

	/* 1. 宿主基线：ruleset + 路由表（IPv4/IPv6） */
	r0 = snapshot("nft list ruleset 2>&1");
	r60 = snapshot("ip route show; echo ---; ip -6 route show");
	live_step(&pass, &total, "1-baseline", r0 && r60, "快照失败");

	/* 2. net=none 旧行为不回归：只有 lo */
	rc = call_tool("workspace_create",
		       "{\"name\":\"w81dnone\",\"size_mb\":64,\"net\":\"none\"}",
		       &out);
	live_step(&pass, &total, "2-create-none",
		  rc == AI_OK && out && strstr(out, "net=none"), out);
	free(out);
	out = NULL;
	rc = run_ws("w81dnone", "ip -o addr", &out);
	live_step(&pass, &total, "2-none-only-lo",
		  rc == AI_OK && out && strstr(out, "127.0.0.1") &&
		  !strstr(out, "aikc"), out);
	free(out);
	out = NULL;

	/* 3. net=veth：独立 netns + 一对 veth + aikbr0 */
	rc = call_tool("workspace_create",
		       "{\"name\":\"w81dnet\",\"size_mb\":64,\"net\":\"veth\"}",
		       &out);
	live_step(&pass, &total, "3-create-veth",
		  rc == AI_OK && out && strstr(out, "net=veth") &&
		  strstr(out, ns), out);
	free(out);
	out = NULL;
	live_step(&pass, &total, "3-netns-exists", sh_ok("ip netns list | grep -q '^aikws-w81dnet'"),
		  "netns 未创建");
	{
		char cmd[256];

		snprintf(cmd, sizeof(cmd),
			 "ip link show dev %s >/dev/null 2>&1", hif);
		live_step(&pass, &total, "3-veth-exists", sh_ok(cmd),
			  "宿主侧 veth 未创建");
		snprintf(cmd, sizeof(cmd),
			 "ip -o link show master aikbr0 | grep -q %s", hif);
		live_step(&pass, &total, "3-bridge-member", sh_ok(cmd),
			  "veth 未挂到 aikbr0");
	}

	/* 4. 工作区里只有 lo + veth。
	 * 注：create 后首挂偶发 EIO 是 W79 loop 复用路径的既有现象（与本棒
	 * 无关，test_workspace --live 也会偶发），这里对首挂做一次重试以免
	 * 证据跑被无关抖动打断。 */
	rc = run_ws("w81dnet", "ip -o addr", &out);
	live_step(&pass, &total, "4-only-lo-and-veth",
		  rc == AI_OK && out && strstr(out, "127.0.0.1") &&
		  strstr(out, "aikca5668d32") && strstr(out, "10.231.") &&
		  !strstr(out, "ens33"), out);
	free(out);
	out = NULL;

	/* 4b. inspect 回显网络拓扑与产物目录 */
	rc = call_tool("workspace_inspect", "{\"name\":\"w81dnet\"}", &out);
	live_step(&pass, &total, "4b-inspect",
		  rc == AI_OK && out && strstr(out, "net=veth") &&
		  strstr(out, "net_ns:    aikws-w81dnet") &&
		  strstr(out, "artifacts:"), out);
	free(out);
	out = NULL;

	/* 5. 缺省拒出站：ping / curl 全失败 */
	rc = run_ws("w81dnet", "ping -c1 -W2 10.231.0.1", &out);
	live_step(&pass, &total, "5-deny-icmp",
		  rc != AI_OK && out && strstr(out, "100% packet loss"), out);
	free(out);
	out = NULL;
	rc = run_ws("w81dnet", "curl -sS -m 3 http://10.231.0.1:22/", &out);
	live_step(&pass, &total, "5-deny-tcp22",
		  rc != AI_OK && out && strstr(out, "timed out"), out);
	free(out);
	out = NULL;
	rc = run_ws("w81dnet", "curl -sS -m 3 http://1.1.1.1/", &out);
	live_step(&pass, &total, "5-deny-external", rc != AI_OK, out);
	free(out);
	out = NULL;

	/* 6. 加白名单：ICMP → 目标可达 */
	rc = call_tool("workspace_net_allow",
		       "{\"name\":\"w81dnet\",\"action\":\"add\","
		       "\"dst\":\"10.231.0.1\",\"proto\":\"icmp\"}", &out);
	live_step(&pass, &total, "6-allow-icmp",
		  rc == AI_OK && out && strstr(out, "已下发"), out);
	free(out);
	out = NULL;
	rc = run_ws("w81dnet", "ping -c1 -W2 10.231.0.1", &out);
	live_step(&pass, &total, "6-icmp-reachable",
		  rc == AI_OK && out && strstr(out, "1 received"), out);
	free(out);
	out = NULL;

	/* 7. 加白名单：TCP 22 → 可达；非白名单 :80 仍不可达 */
	rc = call_tool("workspace_net_allow",
		       "{\"name\":\"w81dnet\",\"action\":\"add\","
		       "\"dst\":\"10.231.0.1\",\"port\":22,"
		       "\"proto\":\"tcp\"}", &out);
	live_step(&pass, &total, "7-allow-tcp22",
		  rc == AI_OK && out && strstr(out, "tcp;22;10.231.0.1"), out);
	free(out);
	out = NULL;
	rc = run_ws("w81dnet", "curl -sS -m 3 http://10.231.0.1:22/", &out);
	live_step(&pass, &total, "7-tcp22-reachable",
		  out && strstr(out, "HTTP/0.9"), out);
	free(out);
	out = NULL;
	rc = run_ws("w81dnet", "curl -sS -m 3 http://10.231.0.1:80/", &out);
	live_step(&pass, &total, "7-tcp80-still-denied",
		  rc != AI_OK && out && strstr(out, "timed out"), out);
	free(out);
	out = NULL;

	/* 8. 删白名单：重新不可达 */
	rc = call_tool("workspace_net_allow",
		       "{\"name\":\"w81dnet\",\"action\":\"del\","
		       "\"dst\":\"10.231.0.1\",\"port\":22,"
		       "\"proto\":\"tcp\"}", &out);
	live_step(&pass, &total, "8-del-tcp22",
		  rc == AI_OK && out && strstr(out, "删除 1 条"), out);
	free(out);
	out = NULL;
	rc = run_ws("w81dnet", "curl -sS -m 3 http://10.231.0.1:22/", &out);
	live_step(&pass, &total, "8-denied-again",
		  rc != AI_OK && out && strstr(out, "timed out"), out);
	free(out);
	out = NULL;

	/* 9. net_status：规则/计数/地址全可见 */
	rc = call_tool("workspace_net_status", "{\"name\":\"w81dnet\"}", &out);
	live_step(&pass, &total, "9-status",
		  rc == AI_OK && out && strstr(out, "policy drop") &&
		  strstr(out, "inet aik_ws_w81dnet") &&
		  strstr(out, "aikws-w81dnet") && strstr(out, "10.231.") &&
		  strstr(out, "counter packets") &&
		  strstr(out, "白名单"), out);
	free(out);
	out = NULL;

	/* 10. destroy：零残留 */
	rc = call_tool("workspace_destroy", "{\"name\":\"w81dnet\"}", &out);
	live_step(&pass, &total, "10-destroy",
		  rc == AI_OK && out && strstr(out, "已清理") &&
		  strstr(out, "netns/veth/nft 表") &&
		  strstr(out, "空产物目录"), out);
	free(out);
	out = NULL;
	live_step(&pass, &total, "10-netns-gone",
		  !sh_ok("ip netns list | grep -q '^aikws-w81dnet'"),
		  "netns 仍存在");
	{
		char cmd[256];

		snprintf(cmd, sizeof(cmd),
			 "ip link show dev %s >/dev/null 2>&1", hif);
		live_step(&pass, &total, "10-veth-gone", !sh_ok(cmd),
			  "宿主侧 veth 仍存在");
	}
	live_step(&pass, &total, "10-bridge-empty",
		  !sh_ok("ip -o link show master aikbr0 2>/dev/null | grep -q ."),
		  "aikbr0 仍有成员");
	snprintf(path, sizeof(path), "%s/w81dnet", getenv("AIKERNEL_SANDBOX_ARTIFACTS"));
	live_step(&pass, &total, "10-artifacts-gone", stat(path, &st) != 0,
		  "空产物目录仍在（B-109）");

	/* 11. 宿主对照：ruleset 与路由表逐字节一致 */
	r4 = snapshot("nft list ruleset 2>&1");
	r6 = snapshot("ip route show; echo ---; ip -6 route show");
	live_step(&pass, &total, "11-host-ruleset-identical",
		  r0 && r4 && strcmp(r0, r4) == 0, r4);
	live_step(&pass, &total, "11-host-routes-identical",
		  r60 && r6 && strcmp(r60, r6) == 0, r6);

	/* 12. 幂等 */
	rc = call_tool("workspace_destroy", "{\"name\":\"w81dnet\"}", &out);
	live_step(&pass, &total, "12-destroy-idempotent",
		  rc == AI_OK && out && strstr(out, "无残留"), out);
	free(out);
	out = NULL;
	(void)call_tool("workspace_destroy", "{\"name\":\"w81dnone\"}", &out);
	free(out);

	free(r0);
	free(r4);
	free(r60);
	free(r6);
	printf("LIVE SUMMARY: %d/%d\n", pass, total);
	return pass == total ? 0 : 1;
}

int main(int argc, char **argv)
{
	char tmpl[] = "/tmp/w81dnet-XXXXXX";
	char sbdir[512], artdir[512], aux[600], aux2[600];
	char *root;
	struct tool_registry reg;
	char *err = NULL;
	char lerr[AI_LEASE_ERR_MAX] = "";
	int live_mode = argc > 1 && strcmp(argv[1], "--live") == 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	root = mkdtemp(tmpl);
	if (!root) {
		perror("mkdtemp");
		return 2;
	}
	snprintf(sbdir, sizeof(sbdir), "%s/sandbox", root);
	snprintf(artdir, sizeof(artdir), "%s/artifacts", root);
	if (mkdir(sbdir, 0755) || mkdir(artdir, 0755)) {
		perror("mkdir");
		return 2;
	}
	setenv("AIKERNEL_WORKSPACE_ROOT", root, 1);
	setenv("AIKERNEL_SANDBOX_BASE", sbdir, 1);
	setenv("AIKERNEL_SANDBOX_ARTIFACTS", artdir, 1);
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	snprintf(aux, sizeof(aux), "%s/.net.lock", root);   /* 网络锁 */
	snprintf(aux2, sizeof(aux2), "%s/.net.seq", root);  /* 地址序号 */
	if (live_mode) {
		/* live：保留调用者给的 aik-sandbox 路径（默认装好的那个） */
		int r;

		setenv("AIKERNEL_SANDBOX_CGROUP_ROOT", "/sys/fs/cgroup", 1);
		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
		r = live();
		unlink(aux);
		unlink(aux2);
		rmdir(artdir);
		rmdir(sbdir);
		rmdir(root);
		return r;
	}
	if (argc == 4 && strcmp(argv[1], "--call") == 0) {
		char *out = NULL;
		int rc = call_tool(argv[2], argv[3], &out);

		printf("%s\n", out ? out : "(null)");
		free(out);
		return rc == AI_OK ? 0 : 1;
	}

	setenv("AIKERNEL_SANDBOX_CGROUP_ROOT", "/nonexistent-w81d-cgroup", 1);
	setenv("AIKERNEL_SANDBOX_BIN", "/nonexistent-w81d-sandbox", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));

	printf("== test_workspace_net (unit, root=%s) ==\n", root);
	test_allow_validator();
	test_net_names();

	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "tools.json 加载（210 件口径）");
	if (reg.tool_count > 0)
		test_registry(&reg);
	test_danger();
	test_meta_and_errors(root);

	/* 假 meta 不能污染"零残留"断言：测试自己清掉 */
	{
		char p[1024];

		snprintf(p, sizeof(p), "%s/w81dfake.meta", root);
		unlink(p);
		snprintf(p, sizeof(p), "%s/w81dfakenone.meta", root);
		unlink(p);
	}
	{
		DIR *d = opendir(root);
		struct dirent *e;
		int n = 0;

		if (d) {
			while ((e = readdir(d))) {
				if (e->d_name[0] == '.')
					continue;
				if (strcmp(e->d_name, "sandbox") == 0 ||
				    strcmp(e->d_name, "artifacts") == 0)
					continue;
				n++;
			}
			closedir(d);
		}
		CHECK(n == 0, "单测结束：临时工作区根零残留");
	}

	printf("SUMMARY: %d checks, %d failed\n", checks, fails);
	unlink(aux);
	unlink(aux2);
	rmdir(artdir);
	rmdir(sbdir);
	rmdir(root);
	return fails ? 1 : 0;
}
