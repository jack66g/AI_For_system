// SPDX-License-Identifier: GPL-2.0
/* test_dtjson.c - 三模式 dumps 黄金串 + dtoa + utf8 工具(单测) */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

static int fails = 0;

static void check_str(const char *name, const char *got, const char *want)
{
	if (!got || strcmp(got, want) != 0) {
		printf("FAIL %s:\n  got : %s\n  want: %s\n", name,
		       got ? got : "(null)", want);
		fails++;
	} else {
		printf("ok %s\n", name);
	}
}

int main(void)
{
	/* python 默认分隔符:{"a": 1, "b": [1, 2]} */
	{
		aik_json *o = dt_new_obj();
		aik_json *a = dt_new_arr();
		char *s;

		dt_put_int(o, "zh", 1);
		dt_put_str(o, "名", "值\"引\\反斜杠\n换行\t制表\x01");
		dt_arr_push_int(a, 1);
		dt_arr_push_int(a, 2);
		aik_json_obj_put(o, "arr", a);
		s = dt_json_dump_default(o);
		check_str("default-separators", s,
			  "{\"zh\": 1, \"名\": \"值\\\"引\\\\反斜杠\\n换行\\t制表"
			  "\\u0001\", \"arr\": [1, 2]}");
		free(s);
		aik_json_free(o);
	}
	/* indent=2 黄金串(空容器 {} / [] 原样) */
	{
		aik_json *o = dt_new_obj();
		aik_json *inner = dt_new_obj();
		char *s;

		dt_put_int(inner, "x", 120);
		aik_json_obj_put(o, "geometry", inner);
		dt_put_str(o, "empty_arr", "");
		aik_json_obj_set(o, "empty_arr", dt_new_arr());
		dt_put_str(o, "empty_obj", "");
		aik_json_obj_set(o, "empty_obj", dt_new_obj());
		s = dt_json_dump_indent2(o);
		check_str("indent2", s,
			  "{\n  \"geometry\": {\n    \"x\": 120\n  },\n"
			  "  \"empty_arr\": [],\n  \"empty_obj\": {}\n}");
		free(s);
		aik_json_free(o);
	}
	/* 浮点 dtoa:0.52 / 34.2 / 1.5 / 整数值浮点 20.0 → "20.0" */
	{
		char buf[40];

		aik_json_dtoa(0.52, buf, sizeof(buf));
		check_str("dtoa-0.52", buf, "0.52");
		aik_json_dtoa(34.2, buf, sizeof(buf));
		check_str("dtoa-34.2", buf, "34.2");
		aik_json_dtoa(1.5, buf, sizeof(buf));
		check_str("dtoa-1.5", buf, "1.5");
		aik_json_dtoa(20.0, buf, sizeof(buf));
		check_str("dtoa-20.0", buf, "20.0");
		aik_json_dtoa(0.042, buf, sizeof(buf));
		check_str("dtoa-0.042", buf, "0.042");
	}
	{
		aik_json *o = dt_new_obj();

		dt_put_num(o, "a", 0.52);
		dt_put_num(o, "b", 34.2);
		{
			char *s = dt_json_dump_default(o);

			check_str("float-dump", s, "{\"a\": 0.52, \"b\": 34.2}");
			free(s);
		}
		aik_json_free(o);
	}
	/* utf8 码点计数/截断 */
	{
		char buf[64];

		snprintf(buf, sizeof(buf), "%zu",
			 dt_utf8_cplen("Hello 世界", strlen("Hello 世界")));
		check_str("cplen", buf, "8");
		{
			char *h = dt_utf8_head("Hello 世界", 5);

			check_str("cp-head", h, "Hello");
			free(h);
			h = dt_utf8_head("Hello 世界", 8);
			check_str("cp-head-8", h, "Hello 世界");
			free(h);
			h = dt_utf8_tail("消息一二三", 2);
			check_str("cp-tail-2", h, "二三");
			free(h);
			h = dt_utf8_chop_last("消息x");
			check_str("cp-chop", h, "消息");
			free(h);
		}
	}
	/* md5/sha256 已知向量 */
	{
		char md5[33], sha[65];

		dt_md5_hex("0.042", 5, md5);
		check_str("md5(0.042)", md5, "4ab355948d3d8e16778cfe2bc019b84f");
		dt_md5_hex("0.5", 3, md5);
		check_str("md5(0.5)", md5, "d310cb367d993fb6fb584b198a2fd72c");
		dt_sha256_hex("", 0, sha);
		check_str("sha256(empty)", sha,
			  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		dt_sha256_hex("d310cb367d99:135713", 19, sha);
		check_str("sha256(salt:pin)", sha, "c2671f645856192c51b3933660d1da8559f3f4b72ca3ee0acd2ac415db80d246");
	}
	/* truthiness / pystr */
	{
		aik_json *o = dt_new_obj();

		dt_put_str(o, "t", "x");
		check_str("truthy-str",
			  dt_truthy(dt_get(o, "t")) ? "1" : "0", "1");
		dt_put_str(o, "f", "");
		check_str("falsy-empty-str",
			  dt_truthy(dt_get(o, "f")) ? "1" : "0", "0");
		{
			char *s = dt_pystr(dt_get(o, "t"));

			check_str("pystr-str", s, "x");
			free(s);
		}
		aik_json_free(o);
		{
			aik_json *arr = dt_new_arr();
			char *s;

			dt_arr_push_str(arr, "x");
			s = dt_pystr(arr);
			check_str("pystr-arr", s, "['x']");
			free(s);
			aik_json_free(arr);
		}
	}
	if (fails) {
		printf("test_dtjson: %d FAIL\n", fails);
		return 1;
	}
	printf("test_dtjson: PASS\n");
	return 0;
}
