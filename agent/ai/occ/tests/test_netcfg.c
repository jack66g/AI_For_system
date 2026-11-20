/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_netcfg.c - C-P2a config_write_network 单测
 *
 * 面1 旗控：默认关=清单 6 件+未知工具（差分红线回归）；开=7 件+known。
 * 面2 分类器：write/remove=W2，show=R，缺 action=W2（安全缺省）。
 * 面3 执行（occ_tool_exec 真链，OCC_NETCFG_DIR 沙盒）：
 *   W2 拒（restricted 无门）/allow_w2 放行写成功/校验矩阵（iface 路径
 *   花样、address CIDR、gateway、dns）/remove 两态/show 过滤/未知 action。
 */
#define _POSIX_C_SOURCE 200809L	/* setenv/unsetenv（c11 严格面藏） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "occ_tools/occ_tools.h"

static int fails;

#define CK(cond, name) do { \
	if (cond) { printf("ok %s\n", name); } \
	else { printf("FAIL %s\n", name); fails++; } \
} while (0)

#define SB "/tmp/netcfg-test-dir"

static void run_tool(const char *args, occ_w2_gate *g, occ_tool_result *r)
{
	occ_tool_ctx c;

	memset(&c, 0, sizeof(c));
	c.workdir = "/tmp";
	c.session_id = "ses_netcfg";
	c.msg_id = "msg_netcfg";
	c.trace_dir = "/tmp/netcfg-test-trace";
	c.snaproot = "/tmp/netcfg-test-snap";
	c.w2 = g;
	memset(r, 0, sizeof(*r));
	occ_tool_exec(&c, OCC_T_NETCFG, "call_netcfg", args, r);
}

static void prep_sandbox(void)
{
	char cmd[256];

	snprintf(cmd, sizeof(cmd), "rm -rf %s /tmp/netcfg-test-snap", SB);
	if (system(cmd) != 0)
		exit(2);
	mkdir(SB, 0755);
	mkdir("/tmp/netcfg-test-trace", 0755);
}

static void put(const char *name, const char *content)
{
	char p[300];
	FILE *f;

	snprintf(p, sizeof(p), "%s/%s", SB, name);
	f = fopen(p, "wb");
	if (!f)
		exit(2);
	fputs(content, f);
	fclose(f);
}

int main(void)
{
	occ_w2_gate g_open, g_denied;
	occ_tool_result r;
	const occ_tool_def *defs;
	size_t n;
	char detail[200];

	/* ---- 面1：旗控（差分红线：默认零变化） ---- */
	unsetenv("OCC_ORCH_TOOLS");
	unsetenv("OCC_NETCFG_TOOLS");
	defs = occ_tool_defs(&n);
	CK(n == 9, "defs_default_9");	/* O-17 起 base=9（六件+rm/mv/mkdir） */
	CK(!occ_tool_is_known(OCC_T_NETCFG), "known_off_default");
	{
		occ_tool_ctx c;

		memset(&c, 0, sizeof(c));
		c.workdir = "/tmp";
		memset(&r, 0, sizeof(r));
		occ_tool_exec(&c, OCC_T_NETCFG, "m1",
			      "{\"action\":\"show\"}", &r);
		CK(r.text && strstr(r.text, "未知工具") != NULL,
		   "exec_off_unknown");
		occ_tool_result_free(&r);
	}
	setenv("OCC_NETCFG_TOOLS", "1", 1);
	setenv("OCC_NETCFG_DIR", SB, 1);
	defs = occ_tool_defs(&n);
	CK(n == 10, "defs_flag_on_10");
	CK(defs && strcmp(defs[9].name, OCC_T_NETCFG) == 0,
	   "defs_9_is_netcfg");
	CK(occ_tool_is_known(OCC_T_NETCFG), "known_on");

	/* ---- 面2：分类器 ---- */
	{
		occ_tool_ctx c;

		memset(&c, 0, sizeof(c));
		c.workdir = "/tmp";
		CK(strcmp(occ_w2_classify(&c, OCC_T_NETCFG,
					  "{\"action\":\"write\","
					  "\"iface\":\"eth0\",\"address\":"
					  "\"192.168.1.10/24\"}",
					  detail, sizeof(detail)),
			  "W2") == 0, "cls_write_W2");
		CK(strcmp(occ_w2_classify(&c, OCC_T_NETCFG,
					  "{\"action\":\"remove\","
					  "\"iface\":\"eth0\"}",
					  detail, sizeof(detail)),
			  "W2") == 0, "cls_remove_W2");
		CK(strcmp(occ_w2_classify(&c, OCC_T_NETCFG,
					  "{\"action\":\"show\"}",
					  detail, sizeof(detail)),
			  "R") == 0, "cls_show_R");
		CK(strcmp(occ_w2_classify(&c, OCC_T_NETCFG, "{}",
					  detail, sizeof(detail)),
			  "W2") == 0, "cls_noaction_W2");
	}

	/* ---- 面3：执行（沙盒 OCC_NETCFG_DIR） ---- */
	prep_sandbox();
	memset(&g_open, 0, sizeof(g_open));
	g_open.allow_w2 = 1;
	memset(&g_denied, 0, sizeof(g_denied));
	g_denied.tier = OCC_W2_TIER_RESTRICTED;

	run_tool("{\"action\":\"write\",\"iface\":\"eth0\","
		 "\"address\":\"192.168.1.10/24\"}", &g_denied, &r);
	CK(r.text && strstr(r.text, "ERROR: W2") != NULL, "exec_w2_denied");
	occ_tool_result_free(&r);

	run_tool("{\"action\":\"write\",\"iface\":\"eth0\","
		 "\"address\":\"192.168.1.10/24\",\"gateway\":"
		 "\"192.168.1.1\",\"dns\":\"223.5.5.5,1.1.1.1\"}",
		 &g_open, &r);
	CK(r.text && strstr(r.text, "已写入") != NULL, "exec_write_ok");
	occ_tool_result_free(&r);
	{
		char p[300];
		char buf[1024];
		FILE *f;
		size_t got;

		snprintf(p, sizeof(p), "%s/70-static-eth0.network", SB);
		f = fopen(p, "rb");
		CK(f != NULL, "file_created");
		if (f) {
			got = fread(buf, 1, sizeof(buf) - 1, f);
			buf[got] = '\0';
			fclose(f);
			CK(strstr(buf, "Name=eth0") != NULL, "content_match");
			CK(strstr(buf, "Address=192.168.1.10/24") != NULL,
			   "content_address");
			CK(strstr(buf, "Gateway=192.168.1.1") != NULL,
			   "content_gateway");
			CK(strstr(buf, "DNS=223.5.5.5") != NULL &&
			   strstr(buf, "DNS=1.1.1.1") != NULL,
			   "content_dns_two");
		}
	}

	/* 校验矩阵：iface 花样（文件名注入面） */
	run_tool("{\"action\":\"write\",\"iface\":\"../evil\","
		 "\"address\":\"10.0.0.1/8\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "iface 非法") != NULL, "iface_traversal");
	occ_tool_result_free(&r);
	run_tool("{\"action\":\"write\",\"iface\":\".hidden\","
		 "\"address\":\"10.0.0.1/8\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "iface 非法") != NULL, "iface_dot");
	occ_tool_result_free(&r);
	run_tool("{\"action\":\"write\",\"iface\":\"eth0/../../x\","
		 "\"address\":\"10.0.0.1/8\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "iface 非法") != NULL, "iface_slash");
	occ_tool_result_free(&r);
	{
		char longiface[20];
		char args[160];

		memset(longiface, 'e', 16);
		longiface[16] = '\0';
		snprintf(args, sizeof(args),
			 "{\"action\":\"write\",\"iface\":\"%s\","
			 "\"address\":\"10.0.0.1/8\"}", longiface);
		run_tool(args, &g_open, &r);
		CK(r.text && strstr(r.text, "iface 非法") != NULL,
		   "iface_too_long");
		occ_tool_result_free(&r);
	}

	/* 校验矩阵：address/gateway/dns */
	run_tool("{\"action\":\"write\",\"iface\":\"eth1\","
		 "\"address\":\"192.168.1.10\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "address 非法") != NULL,
	   "addr_no_slash");
	occ_tool_result_free(&r);
	run_tool("{\"action\":\"write\",\"iface\":\"eth1\","
		 "\"address\":\"192.168.1.10/33\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "address 非法") != NULL,
	   "addr_prefix_33");
	occ_tool_result_free(&r);
	run_tool("{\"action\":\"write\",\"iface\":\"eth1\","
		 "\"address\":\"1.2.3.999/24\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "address 非法") != NULL,
	   "addr_octet_999");
	occ_tool_result_free(&r);
	run_tool("{\"action\":\"write\",\"iface\":\"eth1\","
		 "\"address\":\"1.2.3.4/24\",\"gateway\":\"not-an-ip\"}",
		 &g_open, &r);
	CK(r.text && strstr(r.text, "gateway 非法") != NULL,
	   "gw_bad");
	occ_tool_result_free(&r);
	run_tool("{\"action\":\"write\",\"iface\":\"eth1\","
		 "\"address\":\"1.2.3.4/24\",\"dns\":\"1.1.1.1,foo\"}",
		 &g_open, &r);
	CK(r.text && strstr(r.text, "dns 非法") != NULL, "dns_bad");
	occ_tool_result_free(&r);

	/* remove 两态 + show 过滤 + 未知 action */
	run_tool("{\"action\":\"remove\",\"iface\":\"eth9\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "不存在") != NULL, "remove_enoent");
	occ_tool_result_free(&r);
	put("80-wired.network",
	    "[Match]\nName=en*\n\n[Network]\nDHCP=yes\n");
	run_tool("{\"action\":\"show\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "70-static-eth0.network") != NULL &&
	   strstr(r.text, "Address=192.168.1.10/24") != NULL &&
	   strstr(r.text, "80-wired.network") != NULL &&
	   strstr(r.text, "DHCP=yes") != NULL, "show_lists_both");
	occ_tool_result_free(&r);
	run_tool("{\"action\":\"show\",\"iface\":\"eth0\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "70-static-eth0.network") != NULL &&
	   strstr(r.text, "80-wired.network") == NULL, "show_filter");
	occ_tool_result_free(&r);
	run_tool("{\"action\":\"frobnicate\",\"iface\":\"eth0\"}", &g_open,
		 &r);
	CK(r.text && strstr(r.text, "未知 action") != NULL,
	   "action_unknown");
	occ_tool_result_free(&r);
	run_tool("{\"iface\":\"eth0\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "缺少 action") != NULL,
	   "action_missing");
	occ_tool_result_free(&r);
	run_tool("{\"action\":\"remove\",\"iface\":\"eth0\"}", &g_open, &r);
	CK(r.text && strstr(r.text, "已删除") != NULL, "remove_existing");
	occ_tool_result_free(&r);
	{
		char p[300];

		snprintf(p, sizeof(p), "%s/70-static-eth0.network", SB);
		CK(access(p, F_OK) != 0, "file_removed");
	}

	if (fails) {
		printf("test_netcfg: %d FAIL\n", fails);
		return 1;
	}
	printf("test_netcfg: ALL GREEN (%s face)\n", "flag-on");
	return 0;
}
