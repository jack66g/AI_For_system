/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_api_units.c - T7b 单测:黄金串/构包字节/解析器(对拍录制向量值)。
 * 黄金数据来自 parity/vectors/aikapi/ 向量文件(录制实测,非手抄)。
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "apic/api.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

static int g_fails = 0;
static int g_checks = 0;

#define CHECK(cond) do { \
	g_checks++; \
	if (!(cond)) { \
		g_fails++; \
		printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

#define CHECK_STR(got, want) do { \
	const char *g_ = (got); \
	g_checks++; \
	if (!g_ || strcmp(g_, (want)) != 0) { \
		g_fails++; \
		printf("FAIL %s:%d: got %s want %s\n", __FILE__, __LINE__, \
		       g_ ? g_ : "(null)", (want)); \
	} \
} while (0)

static char *g_home_base;

static char *dirname_of(char *path)
{
	static char buf[4096];
	char *slash;

	snprintf(buf, sizeof(buf), "%s", path);
	slash = strrchr(buf, '/');
	if (slash)
		*slash = '\0';
	return buf;
}

static void write_file_mode(const char *rel, const char *data, int mode)
{
	char p[4096];

	snprintf(p, sizeof(p), "%s/%s", g_home_base, rel);
	mkdir(dirname_of(p), 0755);
	{
		int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, mode);

		if (fd >= 0) {
			(void)api_write_discard(fd, data, strlen(data));
			close(fd);
			chmod(p, mode);
		}
	}
}

static void test_py_int(void)
{
	long long v = 0;

	CHECK(api_py_int("42", &v) && v == 42);
	CHECK(api_py_int(" 12 ", &v) && v == 12);
	CHECK(api_py_int("+5", &v) && v == 5);
	CHECK(api_py_int("-5", &v) && v == -5);
	CHECK(api_py_int("1_0", &v) && v == 10);
	CHECK(!api_py_int("", &v));
	CHECK(!api_py_int("zz", &v));
	CHECK(!api_py_int("12x", &v));
	CHECK(!api_py_int("0x10", &v));
	CHECK(api_py_int("007", &v) && v == 7);
	CHECK(api_py_int0("0x10", &v) && v == 16);
	CHECK(api_py_int0("0X1F", &v) && v == 31);
	CHECK(api_py_int0("0o17", &v) && v == 15);
	CHECK(api_py_int0("0b11", &v) && v == 3);
	CHECK(api_py_int0("010", &v) && v == 10);
	CHECK(api_py_int0("1_0", &v) && v == 10);
	CHECK(!api_py_int0("0x", &v));
	CHECK(!api_py_int0("zz", &v));
	CHECK(api_py_int0("0", &v) && v == 0);
}

static void test_regexes(void)
{
	char s96[128], s97[128];

	memcpy(s96, "api-", 4);
	memset(s96 + 4, 'a', 96);
	s96[4 + 96] = 0;
	memcpy(s97, "api-", 4);
	memset(s97 + 4, 'a', 97);
	s97[4 + 97] = 0;

	CHECK(api_valid_session("api-a"));
	CHECK(api_valid_session("api-a95."));
	CHECK(api_valid_session("api-A.B_c-d"));
	CHECK(!api_valid_session("api-"));
	CHECK(!api_valid_session("nope"));
	CHECK(!api_valid_session(s97));
	CHECK(api_valid_session(s96));
	CHECK(api_valid_nonce("cq-x"));
	CHECK(!api_valid_nonce("cq-"));
	CHECK(!api_valid_nonce("bad"));
	CHECK(!api_valid_nonce("cq-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
			       "xxxxxxxxxxxxxxxxxxxxxxxxxx")); /* 61 */
}

static void test_utf8(void)
{
	char *out = NULL;
	size_t n = 0;
	char msg[256];

	api_utf8_decode_replace("\xff\xfeok\xe6\xb5\x8b\n", 10, &out, &n);
	CHECK_STR(out, "\xef\xbf\xbd\xef\xbf\xbdok\xe6\xb5\x8b\n");
	free(out);
	api_utf8_decode_replace("abc", 3, &out, &n);
	CHECK_STR(out, "abc");
	free(out);
	api_utf8_errmsg("\x80\x81", 2, msg, sizeof(msg));
	CHECK_STR(msg, "'utf-8' codec can't decode byte 0x80 in position 0: "
			"invalid start byte");
	api_utf8_errmsg("ok\xff", 3, msg, sizeof(msg));
	CHECK_STR(msg, "'utf-8' codec can't decode byte 0xff in position 2: "
			"invalid start byte");
	CHECK(dt_utf8_cplen("汉字a", strlen("汉字a")) == 3);
	CHECK_STR(dt_utf8_head("汉字abc测试", 3), "汉字a");
	CHECK_STR(dt_utf8_tail("汉字abc测试", 2), "测试");
}

static void test_toml(void)
{
	aik_json *o = api_parse_toml_section(
		"# comment\n[models.cloud]\nbase_url = \"u\"\n"
		"[api]\ntoken = \" tk \"\nport = 0x2450\n"
		"tls = true\ncert = \"a.crt\"\nbad = xx\nempty = \"\"\n");
	char *dump = dt_json_dump_default(o);

	/* 向量 toml-full 黄金(键序=出现序) */
	CHECK_STR(dump, "{\"token\": \" tk \", \"port\": 9296, "
			"\"tls\": true, \"cert\": \"a.crt\", \"bad\": \"xx\", "
			"\"empty\": \"\"}");
	free(dump);
	aik_json_free(o);
	o = api_parse_toml_section("[other]\nx = 1\n");
	CHECK(aik_json_count(o) == 0);
	aik_json_free(o);
	o = api_parse_toml_section("");
	CHECK(aik_json_count(o) == 0);
	aik_json_free(o);
}

static const char *CONTROL_FIXTURE =
	"# AI control parameters (fixture)\n"
	"llm.top_k           domain=4 [real] min=0 max=100 current=40 default=40\n"
	"llm.temperature     domain=4 [real] min=0 max=200 current=70 default=70\n"
	"net.greedy          domain=2 [real] min=0 max=1 current=1 default=0\n"
	"mm.scan_threshold   domain=3 [real] min=-50 max=50 current=-20 default=0\n"
	"io.readahead_kb     domain=1 [real] min=4 max=128 current=128 default=64\n"
	"sched.nice          domain=5 [real] min=-20 max=19 current=0 default=0\n"
	"sched.affinity      domain=5 [real] min=0 max=255 current=0 default=0\n"
	"sched.oom_score     domain=5 [real] min=-1000 max=1000 current=0 default=0\n"
	"proc.signal         domain=6 [real] min=1 max=64 current=15 default=15\n"
	"proc.freeze          domain=6 [real] min=0 max=1 current=0 default=0\n"
	"proc.rlimit         domain=6 [real] min=0 max=1048576 current=1048576 default=65536\n"
	"junk line without pattern\n"
	"spaces  domain=7 [real] min=0 max=9 current=3 default=3\n";

static void test_control_parse(void)
{
	char name[128];
	long long dom, lo, hi, cur, def;
	const char *line =
		"llm.top_k           domain=4 [real] min=0 max=100 current=40 default=40";

	CHECK(api_parse_control_line(line, name, sizeof(name), &dom, &lo,
				      &hi, &cur, &def) == 0);
	CHECK_STR(name, "llm.top_k");
	CHECK(dom == 4 && lo == 0 && hi == 100 && cur == 40 && def == 40);
	CHECK(api_parse_control_line(
		      "mm.scan_threshold domain=3 [real] min=-50 max=50 "
		      "current=-20 default=0",
		      name, sizeof(name), &dom, &lo, &hi, &cur,
		      &def) == 0);
	CHECK_STR(name, "mm.scan_threshold");
	CHECK(lo == -50 && hi == 50 && cur == -20 && def == 0);
	CHECK(api_parse_control_line("junk line without pattern", name,
				      sizeof(name), &dom, &lo, &hi, &cur,
				      &def) != 0);
	CHECK(api_parse_control_line("cd domain=x [real] min=0 max=1 "
				      "current=0 default=0",
				      name, sizeof(name), &dom, &lo, &hi,
				      &cur, &def) != 0);
	CHECK(api_parse_control_line("a.b domain=1 [real] min=0 max=1 "
				      "current=0 default=0x1",
				      name, sizeof(name), &dom, &lo, &hi,
				      &cur, &def) != 0);
	CHECK(api_parse_control_line("a.b domain=1 [real] min=0 max=1 "
				      "current=0 default=0 ",
				      name, sizeof(name), &dom, &lo, &hi,
				      &cur, &def) == 0);
	/* 全表:12 行匹配(fixture) */
	{
		char *copy = strdup(CONTROL_FIXTURE);
		char *save = NULL;
		char *l = strtok_r(copy, "\n", &save);
		int hits = 0;

		for (; l; l = strtok_r(NULL, "\n", &save)) {
			if (api_parse_control_line(l, name, sizeof(name),
						   &dom, &lo, &hi, &cur,
						   &def) == 0)
				hits++;
		}
		CHECK(hits == 12);
		free(copy);
	}
	CHECK(api_is_task_param("sched.nice"));
	CHECK(api_is_task_param("proc.rlimit"));
	CHECK(!api_is_task_param("llm.top_k"));
}

static void test_nl_pack(void)
{
	unsigned char out[AI_NL_ACT_SIZE];
	char hex[AI_NL_ACT_SIZE * 2 + 1];
	size_t i;

	api_nl_pack_act(out, 4, 90, "sched.nice", 4242, 7);
	for (i = 0; i < AI_NL_ACT_SIZE; i++)
		snprintf(hex + i * 2, 3, "%02x", out[i]);
	/* 向量 pack-basic 黄金字节 */
	CHECK_STR(hex,
		  "000000000000000000000000045a000000000000000000009210000000000000"
		  "0700000000000000000000000000000000000000000000000000000000000000"
		  "00000000000000000000000000000000000000000000000073636865642e6e69"
		  "63650000000000000000000000000000");
	api_nl_pack_act(out, 6, 90, "proc.rlimit", 1234567890123, 0);
	for (i = 0; i < AI_NL_ACT_SIZE; i++)
		snprintf(hex + i * 2, 3, "%02x", out[i]);
	CHECK_STR(hex,
		  "000000000000000000000000065a00000000000000000000cb04fb711f010000"
		  "0000000000000000000000000000000000000000000000000000000000000000"
		  "00000000000000000000000000000000000000000000000070726f632e726c69"
		  "6d697400000000000000000000000000");
	api_nl_pack_act(out, 4, 255, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
		      "xxxx", 1, 0);
	for (i = 0; i < AI_NL_ACT_SIZE; i++)
		snprintf(hex + i * 2, 3, "%02x", out[i]);
	CHECK_STR(hex,
		  "00000000000000000000000004ff000000000000000000000100000000000000"
		  "0000000000000000000000000000000000000000000000000000000000000000"
		  "0000000000000000000000000000000000000000000000007878787878787878"
		  "78787878787878787878787878787800");
}

static void test_nl_unpack(void)
{
	unsigned char ok16[16] = { 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				   0, 0 };
	unsigned char err16[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0,
				    0, 0, 0 };
	unsigned char long18[18] = { 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
				     0, 0, 0, 99, 99 };
	aik_json *a = api_nl_unpack_act_ack(ok16, 16);
	char *dump = dt_json_dump_default(a);

	CHECK_STR(dump, "{\"executed\": 2, \"hit\": 1, \"ai_err\": 0}");
	free(dump);
	aik_json_free(a);
	a = api_nl_unpack_act_ack(err16, 16);
	dump = dt_json_dump_default(a);
	CHECK_STR(dump, "{\"executed\": 0, \"hit\": 0, \"ai_err\": 7}");
	free(dump);
	aik_json_free(a);
	CHECK(api_nl_unpack_act_ack(ok16, 8) == NULL);
	a = api_nl_unpack_act_ack(long18, 18);
	dump = dt_json_dump_default(a);
	CHECK_STR(dump, "{\"executed\": 3, \"hit\": 2, \"ai_err\": 0}");
	free(dump);
	aik_json_free(a);
}

static void test_query(void)
{
	char *v;

	v = api_query_get("channel=a&channel=b", "channel");
	CHECK_STR(v, "a");
	free(v);
	v = api_query_get("channel=", "channel");
	CHECK(v == NULL);
	v = api_query_get("channel", "channel");
	CHECK(v == NULL);
	v = api_query_get("what=status&limit=%2012", "limit");
	CHECK_STR(v, " 12");
	free(v);
	v = api_query_get("q=a+b&r=%2F", "q");
	CHECK_STR(v, "a b");
	free(v);
	v = api_query_get("q=%zz", "q");
	CHECK_STR(v, "%zz");
	free(v);
	v = api_query_get("", "q");
	CHECK(v == NULL);
}

static const char *EV_OK =
	"{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-x\", "
	"\"question\": \"q\", \"options\": ["
	"{\"id\": \"a\", \"label\": \"甲\"}, {\"id\": \"b\", \"label\": \"乙\"}"
	"], \"recommended\": \"a\"}";

static aik_json *ev_of(const char *json)
{
	return dt_parse(json, strlen(json));
}

static void test_validate_event(void)
{
	aik_json *ev = ev_of(EV_OK);

	CHECK(api_validate_clarify_event(ev) == NULL);
	aik_json_free(ev);
	ev = ev_of("123");
	CHECK_STR(api_validate_clarify_event(ev), "event 不是对象");
	aik_json_free(ev);
	ev = ev_of("{\"status\": \"OK\", \"nonce\": \"cq-x\", \"question\": "
		   "\"q\", \"options\": [{\"id\": \"a\", \"label\": \"1\"}, "
		   "{\"id\": \"b\", \"label\": \"2\"}]}");
	CHECK_STR(api_validate_clarify_event(ev), "event status 非法");
	aik_json_free(ev);
	ev = ev_of("{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"bad\", "
		   "\"question\": \"q\", \"options\": [{\"id\": \"a\", "
		   "\"label\": \"1\"}, {\"id\": \"b\", \"label\": \"2\"}]}");
	CHECK_STR(api_validate_clarify_event(ev), "event nonce 非法");
	aik_json_free(ev);
	ev = ev_of("{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-x\", "
		   "\"question\": \"qq\", \"options\": [{\"id\": \"a\", "
		   "\"label\": \"1\"}]}");
	CHECK_STR(api_validate_clarify_event(ev), "event options 数量非法");
	aik_json_free(ev);
	ev = ev_of("{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-x\", "
		   "\"question\": \"q\", \"options\": [\"x\", "
		   "{\"id\": \"a\", \"label\": \"1\"}, {\"id\": \"b\", "
		   "\"label\": \"2\"}]}");
	CHECK_STR(api_validate_clarify_event(ev), "event option 非法");
	aik_json_free(ev);
	ev = ev_of("{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-x\", "
		   "\"question\": \"q\", \"options\": [{\"id\": \"a\", "
		   "\"label\": \"1\"}, {\"id\": \"a\", \"label\": \"2\"}]}");
	CHECK_STR(api_validate_clarify_event(ev), "event option id 非法");
	aik_json_free(ev);
	ev = ev_of("{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-x\", "
		   "\"question\": \"q\", \"options\": [{\"id\": \"a\", "
		   "\"label\": \"1\"}, {\"id\": \"b\", \"label\": \"\", "
		   "\"description\": 5}]}");
	CHECK_STR(api_validate_clarify_event(ev), "event option label 非法");
	aik_json_free(ev);
	ev = ev_of("{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-x\", "
		   "\"question\": \"q\", \"options\": [{\"id\": \"a\", "
		   "\"label\": \"1\", \"why\": 5}, {\"id\": \"b\", "
		   "\"label\": \"2\"}]}");
	CHECK_STR(api_validate_clarify_event(ev), "event option why 非法");
	aik_json_free(ev);
	ev = ev_of("{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-x\", "
		   "\"question\": \"q\", \"options\": [{\"id\": \"a\", "
		   "\"label\": \"1\"}, {\"id\": \"b\", \"label\": \"2\"}], "
		   "\"recommended\": \"zz\"}");
	CHECK_STR(api_validate_clarify_event(ev),
		  "event recommended 非法");
	aik_json_free(ev);
	ev = ev_of("{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-x\", "
		   "\"question\": \"q\", \"options\": [{\"id\": \"a\", "
		   "\"label\": \"1\"}, {\"id\": \"b\", \"label\": \"2\"}], "
		   "\"danger\": \"D3\", \"default\": \"a\"}");
	CHECK_STR(api_validate_clarify_event(ev),
		  "D3/D4 事件不得带 default");
	aik_json_free(ev);
}

static void test_render(void)
{
	/* 向量 ask_clarify_ok 场景 answer 黄金(推荐置顶/多选/推荐理由) */
	aik_json *ev = ev_of(
		"{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-fix1\", "
		"\"question\": \"要执行哪个方案？\", \"header\": \"升级确认\", "
		"\"options\": [{\"id\": \"opt-a\", \"label\": \"方案甲\", "
		"\"description\": \"第一方案说明\"}, {\"id\": \"opt-b\", "
		"\"label\": \"方案乙\"}, {\"id\": \"opt-c\", \"label\": "
		"\"方案丙\", \"description\": \"第三方案说明\", "
		"\"why\": \"风险最低\"}], \"recommended\": \"opt-c\", "
		"\"multi_select\": true, \"danger\": \"D2\", "
		"\"session\": \"api-hijack\"}");
	char *a = api_render_clarify_answer(ev, "api-fix1");

	CHECK_STR(a,
		  "【升级确认】\n"
		  "要执行哪个方案？\n"
		  "1. 方案丙（推荐）\n"
		  "   第三方案说明\n"
		  "2. 方案甲\n"
		  "   第一方案说明\n"
		  "3. 方案乙\n"
		  "可多选。\n"
		  "推荐理由：风险最低\n"
		  "回复：POST /clarify {\"nonce\":\"cq-fix1\","
		  "\"session\":\"api-fix1\","
		  "\"selection\":[\"<选项 id 或序号>\"]}");
	free(a);
	aik_json_free(ev);
	/* 向量 probes render-blank-header 黄金 */
	ev = ev_of(
		"{\"status\": \"CLARIFY_REQUIRED\", \"nonce\": \"cq-r\", "
		"\"question\": \"问题\", \"options\": [{\"id\": \"a\", "
		"\"label\": \"甲\"}, {\"id\": \"b\", \"label\": \"乙\", "
		"\"description\": \"说明乙\"}], \"recommended\": \"a\", "
		"\"multi_select\": false, \"danger\": \"D1\"}");
	a = api_render_clarify_answer(ev, "api-r");
	CHECK_STR(a,
		  "需要澄清：\n"
		  "问题\n"
		  "1. 甲（推荐）\n"
		  "2. 乙\n"
		  "   说明乙\n"
		  "回复：POST /clarify {\"nonce\":\"cq-r\","
		  "\"session\":\"api-r\","
		  "\"selection\":[\"<选项 id 或序号>\"]}");
	free(a);
	aik_json_free(ev);
}

static void test_pte(void)
{
	aik_json *ev = NULL;
	const char *err = NULL;
	const char *t1 = "AIKERNEL_EVENT dead line\nother";
	const char *t2 = "x\nAIKERNEL_EVENT abcd {\"k\": 1}  \ny";
	const char *t3 = "AIKERNEL_EVENT abcd {bad";

	api_parse_tagged_event(t1, strlen(t1), "abcd", &ev, &err);
	CHECK(ev == NULL && err == NULL);
	api_parse_tagged_event(t2, strlen(t2), "abcd", &ev, &err);
	CHECK(ev != NULL && err == NULL && aik_json_count(ev) == 1);
	aik_json_free(ev);
	ev = NULL;
	api_parse_tagged_event(t3, strlen(t3), "abcd", &ev, &err);
	CHECK(ev == NULL);
	CHECK_STR(err, "invalid_event_json");
	err = NULL;
	api_parse_tagged_event("x", 1, "", &ev, &err);
	CHECK_STR(err, "missing_tag");
}

static void test_pending_and_selection(void)
{
	char pend[4096], cons[4096];
	aik_json *doc = NULL;
	aik_json *sel = NULL;
	char *other = NULL;
	const char *errc = NULL;
	int st;

	/* HOME 沙箱 */
	{
		char tmpl[] = "/tmp/aik-test-pending-XXXXXX";

		g_home_base = mkdtemp(tmpl);
		CHECK(g_home_base != NULL);
		g_home_base = strdup(g_home_base);
	}
	setenv("HOME", g_home_base, 1);
	snprintf(pend, sizeof(pend), "%s/.aikernel/clarify/pending",
		 g_home_base);
	snprintf(cons, sizeof(cons), "%s/.aikernel/clarify/consumed",
		 g_home_base);
	CHECK(dt_mkdir_p(pend, 0755) == 0);
	CHECK(dt_mkdir_p(cons, 0755) == 0);

	/* ok(多选 3 项;推荐 opt-c 显示位 1) */
	write_file_mode(".aikernel/clarify/pending/cq-sel.json",
			"{\"status\": \"CLARIFY_PENDING\", \"version\": 1, "
			"\"nonce\": \"cq-sel\", \"session\": \"api-sel\", "
			"\"expires_at_ms\": 1775000099999, "
			"\"clarify\": {\"question\": \"q\", \"options\": ["
			"{\"id\": \"opt-a\", \"label\": \"1\"}, "
			"{\"id\": \"opt-b\", \"label\": \"2\"}, "
			"{\"id\": \"opt-c\", \"label\": \"3\"}], "
			"\"recommended\": \"opt-c\", "
			"\"multi_select\": true}}",
			0600);
	st = api_read_pending("cq-sel", &doc);
	CHECK(st == API_PENDING_OK && doc != NULL);
	sel = dt_parse("[\"1\"]", 5);
	CHECK(api_normalize_selection(doc, sel, NULL, &sel, &other,
				      &errc) == 0);
	{
		char *dump = dt_json_dump_default(sel);

		CHECK_STR(dump, "[\"opt-c\"]"); /* 序号 1 → 推荐(第 3 项) */
		free(dump);
	}
	aik_json_free(sel);
	free(other);
	aik_json_free(doc);
	/* 过期边界(== now*1000) */
	write_file_mode(".aikernel/clarify/pending/cq-exp.json",
			"{\"status\": \"CLARIFY_PENDING\", \"version\": 1, "
			"\"nonce\": \"cq-exp\", \"session\": \"s\", "
			"\"expires_at_ms\": 1775000000000, "
			"\"clarify\": {\"question\": \"q\", \"options\": "
			"[{\"id\": \"a\", \"label\": \"1\"}, {\"id\": \"b\", "
			"\"label\": \"2\"}]}}",
			0600);
	st = api_read_pending("cq-exp", &doc);
	CHECK(st == API_PENDING_EXPIRED);
	aik_json_free(doc);
	/* 模式 0644 → invalid */
	write_file_mode(".aikernel/clarify/pending/cq-mode.json", "{}",
			0644);
	st = api_read_pending("cq-mode", &doc);
	CHECK(st == API_PENDING_INVALID);
	/* 空 JSON → invalid */
	write_file_mode(".aikernel/clarify/pending/cq-bad.json", "{oops",
			0600);
	st = api_read_pending("cq-bad", &doc);
	CHECK(st == API_PENDING_INVALID);
	/* 坏 UTF-8 → invalid */
	{
		char p[4096];
		int fd;

		snprintf(p, sizeof(p),
			 "%s/.aikernel/clarify/pending/cq-enc.json",
			 g_home_base);
		fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		(void)api_write_discard(fd, "\xff\xfe", 2);
		close(fd);
		st = api_read_pending("cq-enc", &doc);
		CHECK(st == API_PENDING_INVALID);
	}
	/* symlink → unknown(O_NOFOLLOW ELOOP) */
	{
		char p[4096], t[4096];

		snprintf(t, sizeof(t),
			 "%s/.aikernel/clarify/pending/cq-sel.json",
			 g_home_base);
		snprintf(p, sizeof(p),
			 "%s/.aikernel/clarify/pending/cq-link.json",
			 g_home_base);
		unlink(p);
		CHECK(symlink(t, p) == 0);
		st = api_read_pending("cq-link", &doc);
		CHECK(st == API_PENDING_UNKNOWN);
	}
	/* consumed */
	write_file_mode(".aikernel/clarify/consumed/cq-cons.json", "{}",
			0600);
	st = api_read_pending("cq-cons", &doc);
	CHECK(st == API_PENDING_CONSUMED);
	/* unknown */
	st = api_read_pending("cq-none", &doc);
	CHECK(st == API_PENDING_UNKNOWN);
	/* 状态码映射 */
	{
		const char *e, *m;

		CHECK(api_pending_state_error(API_PENDING_UNKNOWN, &e, &m) ==
		      404);
		CHECK_STR(e, "unknown_nonce");
		CHECK(api_pending_state_error(API_PENDING_CONSUMED, &e, &m) ==
		      409);
		CHECK(api_pending_state_error(API_PENDING_EXPIRED, &e, &m) ==
		      410);
		CHECK(api_pending_state_error(API_PENDING_INVALID, &e, &m) ==
		      500);
		CHECK(api_pending_state_error(API_PENDING_OK, &e, &m) == 0);
	}
	/* normalize 边界(单选多选/未知选项/other) */
	write_file_mode(".aikernel/clarify/pending/cq-single.json",
			"{\"status\": \"CLARIFY_PENDING\", \"version\": 1, "
			"\"nonce\": \"cq-single\", \"session\": \"s\", "
			"\"expires_at_ms\": 1775000099999, "
			"\"clarify\": {\"question\": \"q\", \"options\": ["
			"{\"id\": \"a\", \"label\": \"1\"}, {\"id\": \"b\", "
			"\"label\": \"2\"}], \"multi_select\": false}}",
			0600);
	st = api_read_pending("cq-single", &doc);
	CHECK(st == API_PENDING_OK);
	sel = dt_parse("[\"a\", \"b\"]", 10);
	CHECK(api_normalize_selection(doc, sel, NULL, &sel, &other,
				      &errc) != 0);
	CHECK_STR(errc, "单选澄清只能选择一个选项");
	aik_json_free(sel);
	sel = NULL;
	{
		aik_json *sel2 = dt_parse("[\"zz\"]", strlen("[\"zz\"]"));

		CHECK(api_normalize_selection(doc, sel2, NULL, &sel, &other,
					      &errc) != 0);
		CHECK_STR(errc, "未知选项 zz");
		aik_json_free(sel2);
	}
	{
		aik_json *sel2 = dt_parse("[true]", 6);

		CHECK(api_normalize_selection(doc, sel2, NULL, &sel, &other,
					      &errc) != 0);
		CHECK_STR(errc, "selection 元素必须是字符串或整数");
		aik_json_free(sel2);
	}
	{
		aik_json *sel2 = dt_parse("[]", 2);
		aik_json *oth = dt_new_str("  txt  ");

		CHECK(api_normalize_selection(doc, sel2, oth, &sel, &other,
					      &errc) == 0);
		CHECK_STR(other, "txt");
		aik_json_free(sel2);
		aik_json_free(oth);
		aik_json_free(sel);
		free(other);
	}
	{
		/* other 513 码点 → 非法 */
		char big[600];
		aik_json *sel2 = dt_parse("[]", 2);
		aik_json *oth2;

		memset(big, 'x', sizeof(big));
		big[513] = '\0';
		oth2 = dt_new_str(big);
		CHECK(api_normalize_selection(doc, sel2, oth2, &sel, &other,
					      &errc) != 0);
		CHECK_STR(errc, "other 非法（单行、≤512 字符）");
		aik_json_free(sel2);
		aik_json_free(oth2);
	}
	aik_json_free(doc);
	{
		char cmd[4200];
		int rc_;

		snprintf(cmd, sizeof(cmd), "rm -rf %s", g_home_base);
		rc_ = system(cmd);
		(void)rc_;
	}
}

static void test_misc(void)
{
	struct api_cfg saved = g_api;
	char hx[33];

	memset(&g_api, 0, sizeof(g_api));
	g_api.frozen = 1;
	g_api.frozen_epoch = 1775000000;
	CHECK(api_time() == 1775000000);
	/* 冻结 secrets 定序(向量:ask 生成 session=..01,tag=..02) */
	{
		char s[40];

		api_token_hex16(hx);
		snprintf(s, sizeof(s), "api-%s", hx);
		CHECK_STR(s, "api-00000000000000000000000000000001");
		api_token_hex16(hx);
		CHECK_STR(hx, "00000000000000000000000000000002");
	}
	{
		aik_json *b = api_err_body("unauthorized",
					   "缺少 Bearer token");
		char *dump = dt_json_dump_default(b);

		CHECK_STR(dump, "{\"error\": \"unauthorized\", "
				"\"message\": \"缺少 Bearer token\"}");
		free(dump);
		aik_json_free(b);
	}
	{
		char buf[128];

		api_oserr_str(buf, sizeof(buf), ENOENT, "/x/y.json");
		CHECK_STR(buf, "[Errno 2] No such file or directory: "
				"'/x/y.json'");
		api_oserr_str(buf, sizeof(buf), 93, "/proc/ai/status");
		CHECK_STR(buf, "[Errno 93] Protocol not supported: "
				"'/proc/ai/status'");
	}
	g_api = saved;
}

int main(void)
{
	memset(&g_api, 0, sizeof(g_api));
	g_api.frozen = 1;
	g_api.frozen_epoch = 1775000000;
	test_py_int();
	test_regexes();
	test_utf8();
	test_toml();
	test_control_parse();
	test_nl_pack();
	test_nl_unpack();
	test_query();
	test_validate_event();
	test_render();
	test_pte();
	test_pending_and_selection();
	test_misc();
	printf("test_api_units: %d checks, %d failures\n", g_checks,
	       g_fails);
	return g_fails ? 1 : 0;
}
