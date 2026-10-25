/* SPDX-License-Identifier: GPL-2.0 */
/* test_net_admin - W78 agent-E P2 网络执行面单测：
 * 纯函数校验 + 注入拒绝 + 无 root 时 rtnetlink/nft 写路径的诚实错误。
 * 任何用例都不得在 root 下真的改动系统状态（root 分支只走 dry/预检只读路径）。 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../tools/tool_registry.h"
#include "../tools/net_admin.h"

static int fails = 0;

#define CHECK(cond, name) do { \
	if (cond) { printf("ok %s\n", name); } \
	else { printf("FAIL %s\n", name); fails++; } \
} while (0)

static void call(const char *name, const char *args, char **out, int *rc)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.channel = TOOL_CH_NETADMIN;
	t.risk = "W2";
	t.name = (char *)name;
	*rc = exec_net_admin_channel(&t, args, out);
}

static void test_validators(void)
{
	unsigned char a[16];
	int fam = 0, plen = 0;

	CHECK(ai_net_admin_valid_iface("eth0") == 1, "iface-eth0");
	CHECK(ai_net_admin_valid_iface("w78e0") == 1, "iface-w78e0");
	CHECK(ai_net_admin_valid_iface("br-lan.100") == 1, "iface-vlan");
	CHECK(ai_net_admin_valid_iface("w_if-1.x") == 1, "iface-mixed");
	CHECK(ai_net_admin_valid_iface("") == 0, "iface-empty-rej");
	CHECK(ai_net_admin_valid_iface("eth0;rm") == 0, "iface-semi-rej");
	CHECK(ai_net_admin_valid_iface("a/b") == 0, "iface-slash-rej");
	CHECK(ai_net_admin_valid_iface("eth 0") == 0, "iface-space-rej");
	CHECK(ai_net_admin_valid_iface("e`h0") == 0, "iface-backtick-rej");
	CHECK(ai_net_admin_valid_iface("123456789012345") == 1,
	      "iface-15-ok");
	CHECK(ai_net_admin_valid_iface("1234567890123456") == 0,
	      "iface-16-rej");

	CHECK(ai_net_admin_parse_cidr("192.168.5.9/24", &fam, a, &plen) == 0 &&
	      fam == AF_INET && plen == 24, "cidr-v4");
	CHECK(ai_net_admin_parse_cidr("fd00::9/64", &fam, a, &plen) == 0 &&
	      fam == AF_INET6 && plen == 64, "cidr-v6");
	CHECK(ai_net_admin_parse_cidr("192.168.5.9", &fam, a, &plen) != 0,
	      "cidr-nopfx-rej");
	CHECK(ai_net_admin_parse_cidr("192.168.5.999/24", &fam, a, &plen) != 0,
	      "cidr-badoctet-rej");
	CHECK(ai_net_admin_parse_cidr("192.168.5.9/33", &fam, a, &plen) != 0,
	      "cidr-pfx33-rej");
	CHECK(ai_net_admin_parse_cidr("fd00::9/129", &fam, a, &plen) != 0,
	      "cidr-pfx129-rej");
	CHECK(ai_net_admin_parse_cidr("192.168.5.9/", &fam, a, &plen) != 0,
	      "cidr-emptypfx-rej");
	CHECK(ai_net_admin_parse_cidr("/24", &fam, a, &plen) != 0,
	      "cidr-noaddr-rej");
	CHECK(ai_net_admin_parse_cidr("1.2.3.4/24x", &fam, a, &plen) != 0,
	      "cidr-junkpfx-rej");
	CHECK(ai_net_admin_parse_cidr("1.2.3.4/99999999999999999999",
				      &fam, a, &plen) != 0,
	      "cidr-hugepfx-rej");

	CHECK(ai_net_admin_parse_ip("10.1.2.3", &fam, a) == 0 &&
	      fam == AF_INET, "ip-v4");
	CHECK(ai_net_admin_parse_ip("fd00::1", &fam, a) == 0 &&
	      fam == AF_INET6, "ip-v6");
	CHECK(ai_net_admin_parse_ip("10.1.2.3/24", &fam, a) != 0,
	      "ip-withpfx-rej");
	CHECK(ai_net_admin_parse_ip("not-an-ip", &fam, a) != 0,
	      "ip-junk-rej");

	CHECK(ai_net_admin_table_id("main", &fam) == 0 && fam == 254,
	      "table-main");
	CHECK(ai_net_admin_table_id("local", &fam) == 0 && fam == 255,
	      "table-local");
	CHECK(ai_net_admin_table_id("default", &fam) == 0 && fam == 253,
	      "table-default");
	CHECK(ai_net_admin_table_id("100", &fam) == 0 && fam == 100,
	      "table-numeric");
	CHECK(ai_net_admin_table_id("bogus", &fam) != 0, "table-junk-rej");
	CHECK(ai_net_admin_table_id("-1", &fam) != 0, "table-neg-rej");

	CHECK(ai_net_admin_valid_nft_op(
		"add rule inet filter input ip saddr 1.2.3.4 drop") == 1,
		"nftop-ok");
	CHECK(ai_net_admin_valid_nft_op("add rule x;y") == 0,
		"nftop-semi-rej");
	CHECK(ai_net_admin_valid_nft_op("add rule `x`") == 0,
		"nftop-backtick-rej");
	CHECK(ai_net_admin_valid_nft_op("add rule $(x)") == 0,
		"nftop-cmdsub-rej");
	CHECK(ai_net_admin_valid_nft_op("add\nrule") == 0,
		"nftop-newline-rej");
	CHECK(ai_net_admin_valid_nft_op("") == 0, "nftop-empty-rej");
	{
		char longop[600];

		memset(longop, 'a', sizeof(longop) - 1);
		longop[sizeof(longop) - 1] = '\0';
		CHECK(ai_net_admin_valid_nft_op(longop) == 0,
		      "nftop-toolong-rej");
	}
}

static void test_param_rejects(void)
{
	char *out = NULL;
	int rc;

	/* net_iface 参数拒绝 */
	call("net_iface", "{\"iface\":\"eth;0\",\"state\":\"up\"}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "iface-inject-rejected");
	free(out); out = NULL;
	call("net_iface", "{\"iface\":\"eth0\",\"state\":\"sideways\"}",
	     &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "state-bad-rejected");
	free(out); out = NULL;

	/* net_addr_* 参数拒绝（粗校验必须被 inet_pton 真校验替代） */
	call("net_addr_add", "{\"iface\":\"eth0\",\"addr\":\"300.1.1.1/24\"}",
	     &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "addr-bad-rejected");
	free(out); out = NULL;
	call("net_addr_add", "{\"iface\":\"eth0\",\"addr\":\"fd00::9\"}",
	     &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "addr-nopfx-rejected");
	free(out); out = NULL;

	/* net_route_* 参数拒绝：双栈不一致 / table 非法 */
	call("net_route_add",
	     "{\"dst\":\"10.0.0.0/8\",\"gateway\":\"fd00::1\"}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "route-family-mismatch-rejected");
	free(out); out = NULL;
	call("net_route_add", "{\"dst\":\"10.0.0.0/8\",\"table\":\"bogus\"}",
	     &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "route-table-rejected");
	free(out); out = NULL;

	/* nft_txn 注入拒绝：分号 / 反引号 / $() / 数组第二元素（证明数组真解析） */
	call("nft_txn", "{\"ops\":[\"add rule inet f i; reboot\"]}",
	     &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ops[0]"),
	      "nft-semicolon-rejected");
	free(out); out = NULL;
	call("nft_txn", "{\"ops\":[\"add table inet t1\",\"x;y\"]}",
	     &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ops[1]"),
	      "nft-second-op-rejected");
	free(out); out = NULL;
	call("nft_txn", "{\"ops\":[\"add rule `id`\"]}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ops[0]"),
	      "nft-backtick-rejected");
	free(out); out = NULL;
	call("nft_txn", "{\"ops\":[\"add rule $(x)\"]}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ops[0]"),
	      "nft-cmdsub-rejected");
	free(out); out = NULL;
	call("nft_txn", "{\"ops\":[]}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "nft-empty-ops-rejected");
	free(out); out = NULL;
	call("nft_txn", "{\"ops\":\"add table inet t\"}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "nft-ops-not-array-rejected");
	free(out); out = NULL;

	/* 未知工具名 */
	call("net_bogus", "{}", &out, &rc);
	CHECK(rc != 0 && out && strncmp(out, "ERROR", 5) == 0,
	      "unknown-tool-rejected");
	free(out); out = NULL;
}

static void test_netlink_honest_errors(void)
{
	char *out = NULL;
	int rc;

	/* 不存在的接口：GETLINK 直接 ENODEV（任何 uid 都安全，零写入） */
	call("net_iface", "{\"iface\":\"aik-no-such0\",\"state\":\"up\"}",
	     &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ERROR") &&
	      (strstr(out, "No such device") ||
	       strstr(out, "接口不存在")),
	      "iface-enodev-honest");
	free(out); out = NULL;
	call("net_addr_del",
	     "{\"iface\":\"aik-no-such0\",\"addr\":\"10.9.9.9/32\"}",
	     &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ERROR"),
	      "addr-del-enodev-honest");
	free(out); out = NULL;
	call("net_link_del", "{\"iface\":\"aik-no-such0\"}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ERROR"),
	      "link-del-enodev-honest");
	free(out); out = NULL;

	if (geteuid() != 0) {
		/* 非 root：读得动 lo、写必须 EPERM（诚实错误，不装成功） */
		call("net_iface", "{\"iface\":\"lo\",\"state\":\"up\"}",
		     &out, &rc);
		CHECK(rc != 0 && out && strstr(out, "ERROR") &&
		      strstr(out, "无 root/CAP_NET_ADMIN"),
		      "iface-eperm-honest-nonroot");
		free(out); out = NULL;
		call("nft_txn", "{\"ops\":[\"add table inet aik_t\"],"
		     "\"dry_run\":true}", &out, &rc);
		CHECK(rc != 0 && out && strstr(out, "ERROR") &&
		      strstr(out, "预检失败"),
		      "nft-check-eperm-honest-nonroot");
		free(out); out = NULL;
	} else {
		/* root（CI 意外提权时）：只走只读/预检路径，仍不改系统 */
		call("nft_txn", "{\"ops\":[\"add table inet aik_w78e_t\"],"
		     "\"dry_run\":true}", &out, &rc);
		CHECK(rc == 0 && out && strstr(out, "预检通过未应用"),
		      "nft-dryrun-root");
		free(out); out = NULL;
	}
}

int main(void)
{
	printf("== test_net_admin (uid=%u) ==\n", (unsigned)geteuid());
	test_validators();
	test_param_rejects();
	test_netlink_honest_errors();
	if (fails) {
		printf("FAILURES: %d\n", fails);
		return 1;
	}
	printf("ALL PASS\n");
	return 0;
}
