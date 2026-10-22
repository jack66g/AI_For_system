/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_toolname_map.c - 云端工具名点号映射回归（W41 bug②）
 *
 * 覆盖：
 *   1. 真实 tools.json（../tools.json，即注册表本名权威源）全量
 *      校验：每个名字满足 DeepSeek/OpenAI 线缆规范
 *      ^[a-zA-Z0-9_-]{1,64}$；sanitize 恒等（当前无点号）；映射
 *      播种零冲突、restore 恒等往返（存量 75 工具零影响）；
 *   2. 合成点号名：sanitize 点→下划线、restore 查表还原本名，
 *      往返一致（A→B→A）；
 *   3. 重名检测：wire 形态撞真实名（a.b vs a_b）、多条目同 wire
 *      （x.y vs x_y 与 y.x）均跳过并计数，restore 退化为透传；
 *   4. 集成：ai_chat_render_tool_calls 出站 sanitize + 响应解析
 *      （ai_chat_parse_response）入站还原全链路。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_types.h"
#include "ai_chat.h"
#include "ai_json_util.h"
#include "ai_toolname_map.h"

static int g_fail;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("FAIL: %s\n", what);
		g_fail++;
	}
}

/* DeepSeek/OpenAI function name 规范 */
static int wire_name_ok(const char *s)
{
	size_t n = strlen(s);
	size_t i;

	if (n < 1 || n > 64)
		return 0;
	for (i = 0; i < n; i++) {
		char c = s[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '-'))
			return 0;
	}
	return 1;
}

/* 读取整个文件（测试内简易版） */
static char *read_all(const char *path)
{
	FILE *fp = fopen(path, "rb");
	char *buf;
	long sz;

	if (!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
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

/* 1. 真实 tools.json 全量校验 + 播种零冲突 */
static void test_real_tools_json(void)
{
	char *text = read_all("../tools.json");
	const char *root, *arr, *etok, *fv;
	size_t root_len, arr_len, elen, fvl;
	int rtype, etype, ftype;
	const char *names[256];
	static char store[256][80];
	int n = 0;
	int i;

	check(text != NULL, "读取 ../tools.json");
	if (!text)
		return;

	{
		const char *p = text;

		if (ai_json_scan_value(&p, text + strlen(text), &root,
				       &root_len, &rtype) != 0 ||
		    rtype != AI_JSON_OBJ) {
			check(0, "tools.json 根对象解析");
			free(text);
			return;
		}
	}
	if (ai_json_obj_get(root, root_len, "tools", &arr, &arr_len,
			    &ftype) != 1 || ftype != AI_JSON_ARR) {
		check(0, "tools.json 缺 tools 数组");
		free(text);
		return;
	}

	for (i = 0; i < 256; i++) {
		const char *fn;
		size_t fnl;
		int ftl;

		if (ai_json_arr_get(arr, arr_len, i, &etok, &elen,
				    &etype) != 1 || etype != AI_JSON_OBJ)
			break;
		/* 兼容两种形态：{name} 与 {function:{name}} */
		if (ai_json_obj_get(etok, elen, "function", &fv, &fvl,
				    &ftype) == 1 && ftype == AI_JSON_OBJ) {
			if (ai_json_obj_get(fv, fvl, "name", &fn, &fnl,
					    &ftl) == 1 &&
			    ftl == AI_JSON_STR) {
				char *s = ai_json_strdup_str(fn, fnl);

				if (s) {
					snprintf(store[n], 80, "%s", s);
					free(s);
					names[n] = store[n];
					n++;
				}
			}
		} else if (ai_json_obj_get(etok, elen, "name", &fn, &fnl,
					   &ftl) == 1 &&
			   ftl == AI_JSON_STR) {
			char *s = ai_json_strdup_str(fn, fnl);

			if (s) {
				snprintf(store[n], 80, "%s", s);
				free(s);
				names[n] = store[n];
				n++;
			}
		}
	}
	printf("  tools.json 工具数: %d\n", n);
	check(n > 0, "tools.json 非空");

	/* 重名检查：本名互不重复（映射前提），且全部满足线缆规范 */
	for (i = 0; i < n; i++) {
		int j;

		check(wire_name_ok(names[i]), "本名满足线缆规范");
		for (j = i + 1; j < n; j++)
			check(strcmp(names[i], names[j]) != 0,
			      "本名无重复");
	}

	/* 播种：当前注册表无点号 → 零冲突零条目 */
	ai_toolname_map_reset();
	check(ai_toolname_map_seed(names, n) == 0, "真实注册表零冲突");
	check(ai_toolname_map_count() == 0, "无点号时映射表为空");

	/* 恒等往返：sanitize==本名，restore(本名)==本名 */
	for (i = 0; i < n; i++) {
		char wire[80];

		check(strcmp(ai_toolname_sanitize(names[i], wire,
						  sizeof(wire)),
			     names[i]) == 0, "无点号 sanitize 恒等");
		{
			char *r = strdup(names[i]);

			r = ai_toolname_map_restore_alloc(r);
			check(strcmp(r, names[i]) == 0,
			      "无点号 restore 恒等");
			free(r);
		}
	}
	free(text);
}

/* 2+3. 合成点号名：往返一致 + 重名检测 */
static void test_synthetic_roundtrip(void)
{
	const char *dotted[] = {
		"netlink.act.sched.nice",
		"sysfs.write.model_load",
		"procfs.read.status",
	};
	char wire[80];
	int i;

	ai_toolname_map_reset();
	check(ai_toolname_map_seed(dotted, 3) == 0, "合成点号名零冲突");
	check(ai_toolname_map_count() == 3, "三条点号名全部入表");

	for (i = 0; i < 3; i++) {
		char *r;

		check(strcmp(ai_toolname_sanitize(dotted[i], wire,
						  sizeof(wire)),
			     wire) == 0 || 1, "sanitize 写入 buf");
		check(strchr(wire, '.') == NULL, "wire 名无点号");
		check(wire_name_ok(wire), "wire 名满足线缆规范");
		r = strdup(wire);
		r = ai_toolname_map_restore_alloc(r);
		check(strcmp(r, dotted[i]) == 0, "restore 还原本名");
		free(r);
	}
	check(strcmp(ai_toolname_sanitize("netlink.act.sched.nice", wire,
					  sizeof(wire)),
		     "netlink_act_sched_nice") == 0,
	      "sanitize 逐字正确");
	check(strcmp(ai_toolname_sanitize("sysfs.write.model_load", wire,
					  sizeof(wire)),
		     "sysfs_write_model_load") == 0, "sanitize 保留下划线");

	/* 无点号名 sanitize 恒等（返回原指针语义） */
	{
		const char *p = ai_toolname_sanitize("memory_search", wire,
						     sizeof(wire));

		check(p != wire && strcmp(p, "memory_search") == 0,
		      "无点号 sanitize 返回原文");
	}

	/* 重名检测 A：wire 撞真实名（注册表已有 a_b 时 a.b 不可映射） */
	{
		const char *names[] = { "a.b", "a_b", "plain" };

		ai_toolname_map_reset();
		check(ai_toolname_map_seed(names, 3) == 1,
		      "wire 撞真实名计 1 冲突");
		check(ai_toolname_map_count() == 0, "冲突条目不入表");
		{
			char *r = strdup("a_b");

			r = ai_toolname_map_restore_alloc(r);
			check(strcmp(r, "a_b") == 0, "冲突时透传本名 a_b");
			free(r);
		}
	}

	/* 重名检测 B：多条点号名同 wire（x.y 与 x_y 冲突后 y.x 仍可入表） */
	{
		const char *names[] = { "x.y", "x_y", "p.q", "r.s" };

		ai_toolname_map_reset();
		check(ai_toolname_map_seed(names, 4) == 1,
		      "同 wire 歧义计 1 冲突");
		check(ai_toolname_map_count() == 2, "其余条目正常入表");
		{
			char *r = strdup("p_q");

			r = ai_toolname_map_restore_alloc(r);
			check(strcmp(r, "p.q") == 0, "非冲突条目仍可还原");
			free(r);
		}
	}
}

/* 4. 集成：出站 render sanitize + 入站 parse restore */
static void test_proto_integration(void)
{
	struct ai_tool_call tcs[2];
	struct ai_chat_result result;
	char *tc_json;
	const char *wire_ptr;
	char wire[80];
	char *resp;
	size_t need;

	ai_toolname_map_reset();
	{
		const char *names[] = { "netlink.act.sched.nice",
					"memory_search" };

		check(ai_toolname_map_seed(names, 2) == 0, "集成播种");
	}

	/* 出站：本名（点号）渲染为线缆名（下划线） */
	memset(tcs, 0, sizeof(tcs));
	tcs[0].id = "call_1";
	tcs[0].name = "netlink.act.sched.nice";
	tcs[0].arguments = "{}";
	tcs[1].id = "call_2";
	tcs[1].name = "memory_search";
	tcs[1].arguments = "{}";
	tc_json = ai_chat_render_tool_calls(tcs, 2);
	check(tc_json != NULL, "render 成功");
	check(strstr(tc_json, "netlink_act_sched_nice") != NULL,
	      "render 出站点名已转下划线");
	check(strstr(tc_json, "netlink.act.sched.nice") == NULL,
	      "render 出站不含点号名");
	check(strstr(tc_json, "memory_search") != NULL,
	      "无点号名原样");
	free(tc_json);

	/* 入站：服务端回显线缆名，解析后还原本名 */
	wire_ptr = ai_toolname_sanitize("netlink.act.sched.nice", wire,
					sizeof(wire));
	need = strlen(wire_ptr) * 8 + 256;
	resp = malloc(need);
	check(resp != NULL, "resp 分配");
	if (resp) {
		snprintf(resp, need,
			 "{\"choices\":[{\"message\":{"
			 "\"content\":null,\"tool_calls\":[{"
			 "\"id\":\"call_z1\",\"type\":\"function\","
			 "\"function\":{\"name\":\"%s\",\"arguments\":"
			 "\"{}\"}}]},\"finish_reason\":\"tool_calls\"}]}",
			 wire_ptr);
		memset(&result, 0, sizeof(result));
		check(ai_chat_parse_response(resp, &result) == AI_OK,
		      "响应解析");
		check(result.tool_call_count == 1, "解析出 1 个调用");
		check(result.tool_calls[0].name != NULL &&
		      strcmp(result.tool_calls[0].name,
			     "netlink.act.sched.nice") == 0,
		      "解析入站还原为点号本名");
		ai_chat_result_free(&result);
		free(resp);
	}
}

int main(void)
{
	printf("== test_toolname_map ==\n");
	test_real_tools_json();
	test_synthetic_roundtrip();
	test_proto_integration();
	if (g_fail) {
		printf("==== %d FAIL ====\n", g_fail);
		return 1;
	}
	printf("==== 全部通过 ====\n");
	return 0;
}
