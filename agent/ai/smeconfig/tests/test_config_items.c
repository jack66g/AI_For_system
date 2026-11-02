/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_config_items.c - T4e 配置注册表自测（E1-A）
 *
 * 数据（$AIK_PARITY_VECTORS 定位，缺省 $HOME/aikernel-longterm/parity/vectors）：
 *   <root>/config/groups_default.json   GET /config groups（默认 SMEConfig）
 *   <root>/config/groups_mutated.json   同上（密钥/令牌/枚举/阈值改过）
 *   <root>/config/presets.json          presets 摘要
 *   <root>/config/config_file.expected.txt  save_config() 逐字节输出
 *
 * 覆盖（T4E-DESIGN.md §1.3）：
 *   1) 注册表 101/5/10、抽样字段、api_key 结尾项数量；
 *   2) groups/presets 与向量逐字节一致（默认）；
 *   3) mutated 场景逐字节一致（掩码 ****** + set:true）；
 *   4) save_file 与 config_file.expected.txt 逐字节一致 + load_file 往返；
 *   5) parse_value 正/负例（含逐字错误文案）；
 *   6) validate_value 正/负例；
 *   7) validate_all：默认 0 告警、注入 LLM/embedding 后文案逐字；
 *   8) load_file：缺失/坏 JSON/顶层数组 -> 101 项默认；
 *   9) value_equal 的 Python == 语义。
 *
 * 换行基准：向量 config_file.expected.txt 已归一到 LF（Linux 参考实现的
 * 文本形态；Windows 文本模式会写 CRLF，与 T2-LOG.md 的 WAL 结论同源）。
 * 本测试显式断言向量与输出都是纯 LF，再逐字节比较；
 * 并显式断言 C 写出的文件 LF-only、无结尾换行。
 *
 * 输出末行：test_config_items: N checks, M failed；M>0 时 exit 1。
 */
#define _POSIX_C_SOURCE 200809L

#include "smeconfig/config.h"
#include "smeconfig/config_items.h"
#include "store/store_json.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t checks;
static size_t failures;

/* ------------------------------------------------------------------ */
/* 断言                                                               */
/* ------------------------------------------------------------------ */
static void check(int cond, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (cond)
		return;
	failures++;
	fprintf(stderr, "FAIL ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/* ------------------------------------------------------------------ */
/* 文件 / 路径工具                                                     */
/* ------------------------------------------------------------------ */
static char *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long n;
	size_t got;

	if (!f) {
		fprintf(stderr, "cannot open %s\n", path);
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
	    fseek(f, 0, SEEK_SET) != 0) {
		fprintf(stderr, "cannot seek %s\n", path);
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fprintf(stderr, "out of memory reading %s\n", path);
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, (size_t)n, f);
	fclose(f);
	if (got != (size_t)n) {
		fprintf(stderr, "short read %s\n", path);
		free(buf);
		return NULL;
	}
	buf[n] = '\0';
	*len = (size_t)n;
	return buf;
}

static const char *vectors_root(void)
{
	static char buf[1024];
	const char *d = getenv("AIK_PARITY_VECTORS");
	const char *home = getenv("HOME");

	if (d && *d)
		return d;
	snprintf(buf, sizeof(buf), "%s/aikernel-longterm/parity/vectors",
		 home && *home ? home : ".");
	return buf;
}

/* <root>/config/<name>；返回静态缓冲（用完即弃，最多 4 路同时用） */
static const char *vector_path(const char *name)
{
	static char bufs[4][1200];
	static int slot;
	char *buf = bufs[slot++ & 3];

	snprintf(buf, 1200, "%s/config/%s", vectors_root(), name);
	return buf;
}

static int write_file(const char *path, const char *text, size_t len)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return -1;
	if (fwrite(text, 1, len, f) != len) {
		fclose(f);
		return -1;
	}
	return fclose(f) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* DOM 工具                                                           */
/* ------------------------------------------------------------------ */
static char *dump_dom(const aik_json *dom, size_t *len)
{
	char *out = NULL;

	*len = 0;
	if (!dom)
		return NULL;
	if (aik_json_dump(dom, &out, len) != 0)
		return NULL;
	return out;
}

/* 严格深比较：类型（INT/NUM 互通）、值、键序、元素序 */
static int json_strict_eq(const aik_json *a, const aik_json *b)
{
	aik_json_type ta = aik_json_typeof(a);
	aik_json_type tb = aik_json_typeof(b);
	size_t i, n;

	if (ta != tb) {
		if ((ta == AIK_JSON_INT || ta == AIK_JSON_NUM) &&
		    (tb == AIK_JSON_INT || tb == AIK_JSON_NUM))
			return aik_json_num(a) == aik_json_num(b);
		return 0;
	}
	switch (ta) {
	case AIK_JSON_NULL:
		return 1;
	case AIK_JSON_BOOL:
		return aik_json_bool(a) == aik_json_bool(b);
	case AIK_JSON_INT:
		return aik_json_int(a) == aik_json_int(b);
	case AIK_JSON_NUM:
		return aik_json_num(a) == aik_json_num(b);
	case AIK_JSON_STR:
		return aik_json_str(a) && aik_json_str(b) &&
		       strcmp(aik_json_str(a), aik_json_str(b)) == 0;
	case AIK_JSON_ARR:
		if (aik_json_count(a) != aik_json_count(b))
			return 0;
		n = aik_json_count(a);
		for (i = 0; i < n; i++)
			if (!json_strict_eq(aik_json_at(a, i), aik_json_at(b, i)))
				return 0;
		return 1;
	case AIK_JSON_OBJ:
		if (aik_json_count(a) != aik_json_count(b))
			return 0;
		n = aik_json_count(a);
		for (i = 0; i < n; i++) {
			const char *ka = aik_json_key_at(a, i);
			const char *kb = aik_json_key_at(b, i);

			if (!ka || !kb || strcmp(ka, kb) != 0)
				return 0;
			if (!json_strict_eq(aik_json_val_at(a, i),
					    aik_json_val_at(b, i)))
				return 0;
		}
		return 1;
	}
	return 0;
}

/* 字节比较 + 首个差异偏移（便于定位） */
static void expect_bytes(const char *label, const char *got, size_t gotlen,
			 const char *want, size_t wantlen)
{
	int eq = got && want && gotlen == wantlen &&
		 memcmp(got, want, gotlen) == 0;

	check(eq, "%s: %zu bytes vs %zu bytes", label, gotlen, wantlen);
	if (!eq && got && want && gotlen == wantlen) {
		size_t i;

		for (i = 0; i < gotlen; i++)
			if (got[i] != want[i]) {
				fprintf(stderr,
					"  first diff at %zu: got 0x%02x want 0x%02x\n",
					i, (unsigned char)got[i],
					(unsigned char)want[i]);
				break;
			}
	}
}

static void set_json(aik_json *cfg, const char *path, aik_json *value)
{
	const aik_config_item *it = aik_config_item_find(path);

	check(it != NULL, "set: unknown item %s", path);
	if (!it) {
		aik_json_free(value);
		return;
	}
	check(aik_config_item_set(cfg, it, value) == 0, "set: %s failed", path);
	aik_json_free(value);
}

/* ------------------------------------------------------------------ */
/* 1) 注册表                                                          */
/* ------------------------------------------------------------------ */
static void test_registry(void)
{
	static const char *const GROUP_KEYS[] = {
		"llm", "embedding", "retrieval", "region", "dynamics",
		"storage", "api", "visualization", "memory", "extensions"
	};
	const aik_config_item *it;
	const aik_config_preset *p;
	size_t i, api_key_items = 0;

	check(aik_config_item_count == 101, "registry: %zu items != 101",
	      aik_config_item_count);
	check(aik_config_preset_count == 5, "registry: %zu presets != 5",
	      aik_config_preset_count);
	check(aik_config_group_count == 10, "registry: %zu groups != 10",
	      aik_config_group_count);

	for (i = 0; i < aik_config_item_count; i++) {
		const char *path = aik_config_items[i].path;
		size_t n = strlen(path);

		if (n >= 7 && strcmp(path + n - 7, "api_key") == 0)
			api_key_items++;
	}
	check(api_key_items == 2, "registry: %zu api_key items != 2",
	      api_key_items);

	it = aik_config_item_find("llm.base_url");
	check(it != NULL, "registry: llm.base_url missing");
	if (it) {
		check(strcmp(it->name, "接口地址") == 0,
		      "registry: llm.base_url name");
		check(strcmp(it->group, "llm") == 0,
		      "registry: llm.base_url group");
		check(it->kind == AIK_CFG_KIND_STR,
		      "registry: llm.base_url kind");
		check(it->required == 0, "registry: llm.base_url required");
		check(it->minimum == NULL && it->maximum == NULL,
		      "registry: llm.base_url bounds");
		check(strcmp(it->default_json, "\"\"") == 0,
		      "registry: llm.base_url default");
		check(strncmp(it->desc, "OpenAI 兼容 /chat/completions",
			      strlen("OpenAI 兼容 /chat/completions")) == 0,
		      "registry: llm.base_url desc");
	}

	it = aik_config_item_find("llm.max_tokens");
	check(it != NULL, "registry: llm.max_tokens missing");
	if (it) {
		check(it->kind == AIK_CFG_KIND_INT,
		      "registry: llm.max_tokens kind");
		check(it->minimum && strcmp(it->minimum, "1") == 0,
		      "registry: llm.max_tokens minimum");
		check(it->maximum && strcmp(it->maximum, "128000") == 0,
		      "registry: llm.max_tokens maximum");
		check(strcmp(it->default_json, "1024") == 0,
		      "registry: llm.max_tokens default");
		check(strcmp(it->name, "最大 token") == 0,
		      "registry: llm.max_tokens name");
		check(strcmp(it->desc,
			     "单次回答最大 token 数，越长越贵") == 0,
		      "registry: llm.max_tokens desc");
	}

	it = aik_config_item_find("llm.temperature");
	check(it != NULL && it->kind == AIK_CFG_KIND_FLOAT,
	      "registry: llm.temperature kind");
	if (it) {
		check(it->minimum && strcmp(it->minimum, "0") == 0,
		      "registry: llm.temperature minimum");
		check(it->maximum && strcmp(it->maximum, "2") == 0,
		      "registry: llm.temperature maximum");
		check(strcmp(it->default_json, "0.6") == 0,
		      "registry: llm.temperature default");
	}

	it = aik_config_item_find("embedding.provider");
	check(it != NULL && it->kind == AIK_CFG_KIND_ENUM,
	      "registry: embedding.provider kind");
	if (it) {
		check(it->n_choices == 4, "registry: embedding.provider choices");
		check(it->choices && strcmp(it->choices[0], "hashing") == 0,
		      "registry: embedding.provider choices[0]");
		check(it->choices && strcmp(it->choices[3], "fastembed") == 0,
		      "registry: embedding.provider choices[3]");
		check(strcmp(it->default_json, "\"hashing\"") == 0,
		      "registry: embedding.provider default");
	}

	it = aik_config_item_find("llm.reasoning_effort");
	check(it != NULL && it->kind == AIK_CFG_KIND_ENUM &&
	      it->n_choices == 5 && strcmp(it->choices[0], "") == 0,
	      "registry: llm.reasoning_effort choices");

	it = aik_config_item_find("memory.consolidate_every");
	check(it != NULL && it->kind == AIK_CFG_KIND_INTERVAL,
	      "registry: memory.consolidate_every kind");
	if (it) {
		check(it->minimum && strcmp(it->minimum, "1") == 0,
		      "registry: memory.consolidate_every minimum");
		check(it->maximum == NULL,
		      "registry: memory.consolidate_every maximum");
		check(strcmp(it->default_json, "8") == 0,
		      "registry: memory.consolidate_every default");
	}

	it = aik_config_item_find("llm.model");
	check(it != NULL && it->required == 1,
	      "registry: llm.model must be required");
	it = aik_config_item_find("storage.path");
	check(it != NULL && it->required == 1,
	      "registry: storage.path must be required");
	it = aik_config_item_find("api.host");
	check(it != NULL && it->required == 1,
	      "registry: api.host must be required");

	check(aik_config_item_find("no.such.path") == NULL,
	      "registry: unknown item must be NULL");
	check(aik_config_item_find(NULL) == NULL,
	      "registry: find(NULL) must be NULL");

	for (i = 0; i < aik_config_group_count; i++)
		check(strcmp(aik_config_groups[i].key, GROUP_KEYS[i]) == 0,
		      "registry: group[%zu] key %s != %s", i,
		      aik_config_groups[i].key, GROUP_KEYS[i]);
	check(strcmp(aik_config_groups[2].name, "检索与排序") == 0,
	      "registry: group[2] name");
	check(strcmp(aik_config_groups[1].description,
		     "向量化引擎、模型与维度") == 0,
	      "registry: group[1] description");

	p = aik_config_preset_find("chat");
	check(p != NULL && strcmp(p->name, "01 聊天助手（默认）") == 0,
	      "registry: preset chat name");
	check(p && p->n_values == 17, "registry: preset chat count");
	check(p && strncmp(p->desc, "动态记忆", strlen("动态记忆")) == 0,
	      "registry: preset chat desc");
	p = aik_config_preset_find("kb_dynamic");
	check(p != NULL && p->n_values == 20, "registry: preset kb_dynamic");
	p = aik_config_preset_find("kb_static");
	check(p != NULL && p->n_values == 20, "registry: preset kb_static");
	p = aik_config_preset_find("robot");
	check(p != NULL && p->n_values == 18, "registry: preset robot");
	p = aik_config_preset_find("minimal");
	check(p != NULL && p->n_values == 17, "registry: preset minimal");
	check(aik_config_preset_find("nope") == NULL,
	      "registry: unknown preset must be NULL");

	/* defaults_config()：101 项、ITEMS 插入序 */
	{
		aik_json *def = aik_config_defaults_build();
		size_t n = 0;

		check(def != NULL, "registry: defaults_build failed");
		if (def) {
			check(aik_json_typeof(def) == AIK_JSON_OBJ,
			      "registry: defaults not OBJ");
			for (i = 0; i < aik_config_item_count; i++)
				if (aik_config_item_has(def, &aik_config_items[i]))
					n++;
			check(n == 101, "registry: defaults has %zu items != 101",
			      n);
			check(aik_json_count(def) == 25,
			      "registry: defaults has %zu sections != 25",
			      aik_json_count(def));
			it = aik_config_item_find("llm.base_url");
			check(it && aik_config_item_get(def, it) &&
			      aik_json_typeof(aik_config_item_get(def, it)) ==
				      AIK_JSON_STR,
			      "registry: defaults llm.base_url");
			aik_json_free(def);
		}
	}
}

/* ------------------------------------------------------------------ */
/* 2) groups / presets（默认）                                        */
/* ------------------------------------------------------------------ */
static void test_groups_presets(const aik_json *cdef)
{
	aik_json *disp = aik_config_display(cdef);
	aik_json *groups = aik_config_groups_build(disp);
	aik_json *presets = aik_config_presets_build();
	char *got = NULL;
	size_t gotlen = 0;
	char *want;
	size_t wantlen = 0;

	check(disp != NULL, "groups: display failed");
	check(groups != NULL, "groups: groups_build failed");
	check(presets != NULL, "groups: presets_build failed");

	got = dump_dom(groups, &gotlen);
	want = read_file(vector_path("groups_default.json"), &wantlen);
	check(got != NULL && want != NULL, "groups: cannot read vector");
	if (got && want)
		expect_bytes("groups_default", got, gotlen, want, wantlen);
	free(got);
	free(want);

	got = dump_dom(presets, &gotlen);
	want = read_file(vector_path("presets.json"), &wantlen);
	check(got != NULL && want != NULL, "presets: cannot read vector");
	if (got && want)
		expect_bytes("presets", got, gotlen, want, wantlen);
	free(got);
	free(want);

	/* 结构抽样：9 个非空分组、101 项、空可视化组不下发 */
	if (groups) {
		size_t i, items = 0;
		int has_viz = 0;

		check(aik_json_count(groups) == 9,
		      "groups: %zu groups != 9", aik_json_count(groups));
		for (i = 0; i < aik_json_count(groups); i++) {
			const aik_json *g = aik_json_at(groups, i);
			const aik_json *items_arr = aik_json_get(g, "items");

			items += aik_json_count(items_arr);
			if (aik_json_get(g, "key") &&
			    strcmp(aik_json_str(aik_json_get(g, "key")),
				   "visualization") == 0)
				has_viz = 1;
		}
		check(items == 101, "groups: %zu items != 101", items);
		check(!has_viz, "groups: empty visualization group leaked");
	}

	/* 密钥项：空值 set=false、不下发掩码 */
	if (groups) {
		size_t i, j;
		int seen = 0;

		for (i = 0; i < aik_json_count(groups); i++) {
			const aik_json *arr = aik_json_get(aik_json_at(groups, i),
							   "items");

			for (j = 0; j < aik_json_count(arr); j++) {
				const aik_json *it = aik_json_at(arr, j);
				const char *path = aik_json_str(
					aik_json_get(it, "path"));
				const aik_json *set = aik_json_get(it, "set");

				if (!path || strcmp(path, "llm.api_key") != 0)
					continue;
				seen = 1;
				check(set && aik_json_typeof(set) ==
						     AIK_JSON_BOOL &&
				      aik_json_bool(set) == 0,
				      "groups: default llm.api_key set");
				check(strcmp(aik_json_str(
						     aik_json_get(it, "value")),
					     "") == 0,
				      "groups: default llm.api_key value");
				check(strcmp(aik_json_str(
						     aik_json_get(it, "type")),
					     "str") == 0,
				      "groups: llm.api_key type");
				check(aik_json_count(
					      aik_json_get(it, "choices")) == 0,
				      "groups: llm.api_key choices");
			}
		}
		check(seen, "groups: llm.api_key payload missing");
	}

	free(disp);
	aik_json_free(groups);
	aik_json_free(presets);
}

/* ------------------------------------------------------------------ */
/* 3) mutated                                                         */
/* ------------------------------------------------------------------ */
static void test_mutated(void)
{
	char err[256];
	aik_config *mut = aik_config_defaults(err, sizeof(err));
	aik_json *disp, *groups;
	char *got = NULL, *want;
	size_t gotlen = 0, wantlen = 0;

	check(mut != NULL, "mutated: defaults failed: %s", err);
	if (!mut)
		return;

	set_json((aik_json *)aik_config_dom(mut), "llm.api_key",
		 aik_json_new_str("sk-test"));
	set_json((aik_json *)aik_config_dom(mut), "embedding.api_key",
		 aik_json_new_str("emb-test"));
	set_json((aik_json *)aik_config_dom(mut), "api.auth_token",
		 aik_json_new_str("tok"));
	set_json((aik_json *)aik_config_dom(mut), "embedding.provider",
		 aik_json_new_str("openai"));
	set_json((aik_json *)aik_config_dom(mut), "retrieval.fusion",
		 aik_json_new_str("weighted"));
	set_json((aik_json *)aik_config_dom(mut), "llm.reasoning_effort",
		 aik_json_new_str("none"));
	set_json((aik_json *)aik_config_dom(mut),
		 "consolidation.similarity_threshold", aik_json_new_num(0.9));

	disp = aik_config_display(aik_config_dom(mut));
	groups = aik_config_groups_build(disp);
	check(disp != NULL && groups != NULL, "mutated: build failed");

	got = dump_dom(groups, &gotlen);
	want = read_file(vector_path("groups_mutated.json"), &wantlen);
	check(got != NULL && want != NULL, "mutated: cannot read vector");
	if (got && want)
		expect_bytes("groups_mutated", got, gotlen, want, wantlen);
	free(got);
	free(want);

	/* 掩码与 set 标记 */
	if (groups) {
		size_t i, j;
		int masks = 0, token_clear = 0;

		for (i = 0; i < aik_json_count(groups); i++) {
			const aik_json *arr = aik_json_get(aik_json_at(groups, i),
							   "items");

			for (j = 0; j < aik_json_count(arr); j++) {
				const aik_json *it = aik_json_at(arr, j);
				const char *path = aik_json_str(
					aik_json_get(it, "path"));
				const aik_json *value =
					aik_json_get(it, "value");
				const aik_json *set = aik_json_get(it, "set");
				const aik_json *mod = aik_json_get(it, "modified");

				if (!path)
					continue;
				if (strcmp(path, "llm.api_key") == 0 ||
				    strcmp(path, "embedding.api_key") == 0) {
					check(value && strcmp(
						       aik_json_str(value),
						       "******") == 0,
					      "mutated: %s not masked", path);
					check(set && aik_json_typeof(set) ==
							    AIK_JSON_BOOL &&
						      aik_json_bool(set) == 1,
					      "mutated: %s set flag", path);
					check(mod && aik_json_bool(mod) == 1,
					      "mutated: %s modified", path);
					masks++;
				}
				if (strcmp(path, "api.auth_token") == 0) {
					check(value && strcmp(
						       aik_json_str(value),
						       "tok") == 0,
					      "mutated: auth_token must be clear");
					check(set == NULL,
					      "mutated: auth_token has set key");
					check(mod && aik_json_bool(mod) == 1,
					      "mutated: auth_token modified");
					token_clear = 1;
				}
			}
		}
		check(masks == 2, "mutated: %d masked items != 2", masks);
		check(token_clear, "mutated: auth_token payload missing");
	}

	free(disp);
	aik_json_free(groups);
	aik_config_free(mut);
}

/* ------------------------------------------------------------------ */
/* 4) save_file / load_file                                           */
/* ------------------------------------------------------------------ */
/* CRLF -> LF（Windows 文本模式录制产物；见文件头注释） */
static char *normalize_newlines(const char *src, size_t len, size_t *outlen,
				size_t *crlf)
{
	char *out = malloc(len + 1);
	size_t i, n = 0;

	*crlf = 0;
	if (!out)
		return NULL;
	for (i = 0; i < len; i++) {
		if (src[i] == '\r' && i + 1 < len && src[i + 1] == '\n') {
			(*crlf)++;
			continue;
		}
		out[n++] = src[i];
	}
	out[n] = '\0';
	*outlen = n;
	return out;
}

static void test_save_load(const aik_json *cdef)
{
	char tmpl[] = "/tmp/aik-cfgitems-XXXXXX";
	char path[256];
	char err[256];
	char *raw, *want;
	size_t rawlen = 0, wantlen = 0, crlf = 0;
	size_t n_sections = 0, i;

	check(mkdtemp(tmpl) != NULL, "save: mkdtemp failed");
	snprintf(path, sizeof(path), "%s/sme.config.json", tmpl);

	err[0] = '\0';
	check(aik_config_save_file(path, cdef, err, sizeof(err)) == 0,
	      "save: failed: %s", err);

	raw = read_file(path, &rawlen);
	check(raw != NULL, "save: cannot read back");
	want = read_file(vector_path("config_file.expected.txt"), &wantlen);
	check(want != NULL, "save: cannot read vector");
	if (raw && want) {
		char *lf = normalize_newlines(want, wantlen, &wantlen, &crlf);
		size_t lf_len = wantlen;

		check(crlf == 0, "save: vector CRLF %zu != 0", crlf);
		check(lf != NULL, "save: normalize failed");
		if (lf)
			expect_bytes("save_file", raw, rawlen, lf, lf_len);
		free(lf);
	}
	if (raw) {
		size_t k;
		int has_crlf = 0;

		for (k = 0; k + 1 < rawlen; k++)
			if (raw[k] == '\r' && raw[k + 1] == '\n')
				has_crlf = 1;
		check(!has_crlf, "save: output must be LF-only");
		check(rawlen > 0 && raw[rawlen - 1] != '\n',
		      "save: output must not end with newline");
		check(rawlen == 15208, "save: %zu bytes != 15208", rawlen);
		check(strstr(raw, "\"min_similarity\": -1.0") != NULL,
		      "save: -1.0 must stay NUM");
		check(strstr(raw, "\"max_density\": 120.0") != NULL,
		      "save: 120.0 must stay NUM");
	}

	/* 调用方 DOM 不被污染（save 内部复制） */
	check(aik_json_get(cdef, "_help") == NULL,
	      "save: caller DOM mutated with _help");

	/* load 往返：完整 DOM + _help */
	{
		aik_json *loaded = aik_config_load_file(path, err, sizeof(err));
		const aik_json *help;

		check(loaded != NULL, "load: round-trip failed: %s", err);
		if (loaded) {
			check(aik_json_count(loaded) == 28,
			      "load: %zu top keys != 28",
			      aik_json_count(loaded));
			help = aik_json_get(loaded, "_help");
			check(help && aik_json_typeof(help) == AIK_JSON_OBJ,
			      "load: _help missing");
			if (help) {
				const char *first = aik_json_key_at(help, 0);
				const char *last = aik_json_key_at(
					help, aik_json_count(help) - 1);
				const aik_json *d = aik_json_get(
					help, "llm.max_tokens");

				check(aik_json_count(help) == 101,
				      "load: _help %zu != 101",
				      aik_json_count(help));
				check(first && strcmp(first, "llm.base_url") == 0,
				      "load: _help first key");
				check(last && strcmp(last, "rerank.top_n") == 0,
				      "load: _help last key");
				check(d && strcmp(aik_json_str(d),
						  "单次回答最大 token 数，越长越贵") == 0,
				      "load: _help llm.max_tokens desc");
			}
			check(aik_json_get(loaded, "memory") != NULL,
			      "load: memory section missing");
			{
				const aik_json *mem =
					aik_json_get(loaded, "memory");
				const aik_json *v =
					aik_json_get(mem, "consolidate_every");

				check(v && aik_json_typeof(v) == AIK_JSON_INT &&
				      aik_json_int(v) == 8,
				      "load: memory.consolidate_every");
			}
			/* 原有 section 与保存前的 DOM 逐节点相等 */
			n_sections = aik_json_count(cdef);
			for (i = 0; i < n_sections; i++) {
				const char *key = aik_json_key_at(cdef, i);
				const aik_json *a = aik_json_val_at(cdef, i);
				const aik_json *b = aik_json_get(loaded, key);

				check(b != NULL && json_strict_eq(a, b),
				      "load: section %s differs", key);
			}
			/* 101 项全部可读 */
			{
				size_t hits = 0;

				for (i = 0; i < aik_config_item_count; i++)
					if (aik_config_item_has(
						    loaded,
						    &aik_config_items[i]))
						hits++;
				check(hits == 101,
				      "load: %zu items != 101", hits);
			}
			/* 再存一次：字节完全相同（往返稳定） */
			{
				char path2[256];

				snprintf(path2, sizeof(path2), "%s/again.json",
					 tmpl);
				check(aik_config_save_file(path2, loaded, err,
							   sizeof(err)) == 0,
				      "load: re-save failed: %s", err);
				{
					size_t len2 = 0;
					char *raw2 = read_file(path2, &len2);

					check(raw2 && rawlen == len2 &&
					      memcmp(raw, raw2, len2) == 0,
					      "load: re-save bytes differ");
					free(raw2);
				}
				unlink(path2);
			}
			/* 载入的配置全部值合法（0 告警） */
			{
				aik_json *disp = aik_config_display(loaded);
				aik_json *warn = aik_config_validate_all(
					disp, err, sizeof(err));

				check(warn != NULL, "load: validate_all: %s", err);
				check(warn && aik_json_count(warn) == 0,
				      "load: %zu warnings on saved config",
				      warn ? aik_json_count(warn) : 99);
				aik_json_free(warn);
				aik_json_free(disp);
			}
			aik_json_free(loaded);
		}
	}

	free(raw);
	free(want);
	unlink(path);
	rmdir(tmpl);
}

/* ------------------------------------------------------------------ */
/* 5) parse_value                                                     */
/* ------------------------------------------------------------------ */
static void parse_ok(const char *label, const char *path, const char *raw,
		     const char *want_json)
{
	const aik_config_item *it = aik_config_item_find(path);
	aik_json *out = NULL;
	char err[512];
	char *dump = NULL;
	size_t dlen = 0;
	int rc;

	err[0] = '\0';
	check(it != NULL, "%s: unknown item %s", label, path);
	if (!it)
		return;
	rc = aik_config_item_parse(it, raw, &out, err, sizeof(err));
	check(rc == 0 && out != NULL, "%s: rc=%d err=%s", label, rc, err);
	if (rc != 0 || !out) {
		aik_json_free(out);
		return;
	}
	dump = dump_dom(out, &dlen);
	check(dump && strcmp(dump, want_json) == 0, "%s: got %s want %s", label,
	      dump ? dump : "(null)", want_json);
	aik_json_free(out);
	free(dump);
}

static void parse_err(const char *label, const char *path, const char *raw,
		      const char *want_err)
{
	const aik_config_item *it = aik_config_item_find(path);
	aik_json *out = NULL;
	char err[512];
	int rc;

	err[0] = '\0';
	check(it != NULL, "%s: unknown item %s", label, path);
	if (!it)
		return;
	rc = aik_config_item_parse(it, raw, &out, err, sizeof(err));
	check(rc == -1 && out == NULL, "%s: rc=%d out=%p", label, rc,
	      (void *)out);
	check(strcmp(err, want_err) == 0, "%s: err \"%s\" want \"%s\"", label,
	      err, want_err);
	aik_json_free(out);
}

static void test_parse(void)
{
	/* bool：全部同义词 + 大小写 + 空白 */
	parse_ok("bool 1", "memory.reinforce_on", "1", "true");
	parse_ok("bool 0", "memory.reinforce_on", "0", "false");
	parse_ok("bool true", "memory.reinforce_on", "true", "true");
	parse_ok("bool TRUE", "memory.reinforce_on", "TRUE", "true");
	parse_ok("bool False", "memory.reinforce_on", "False", "false");
	parse_ok("bool yes", "memory.reinforce_on", "yes", "true");
	parse_ok("bool no", "memory.reinforce_on", "no", "false");
	parse_ok("bool on", "memory.reinforce_on", "on", "true");
	parse_ok("bool off", "memory.reinforce_on", "off", "false");
	parse_ok("bool y", "memory.reinforce_on", "y", "true");
	parse_ok("bool N", "memory.reinforce_on", "N", "false");
	parse_ok("bool 开", "memory.reinforce_on", "开", "true");
	parse_ok("bool 关", "memory.reinforce_on", "关", "false");
	parse_ok("bool 是", "memory.reinforce_on", "是", "true");
	parse_ok("bool 否", "memory.reinforce_on", "否", "false");
	parse_ok("bool strip", "memory.reinforce_on", "  True\t", "true");
	parse_err("bool bad", "memory.reinforce_on", "verdad",
		  "请输入 开/关（或 1/0 / true/false / on/off）");
	parse_err("bool empty", "memory.reinforce_on", "",
		  "请输入 开/关（或 1/0 / true/false / on/off）");

	/* enum：大小写不敏感、空串合法、返回注册表规范写法 */
	parse_ok("enum none", "llm.reasoning_effort", "none", "\"none\"");
	parse_ok("enum NONE", "llm.reasoning_effort", "NONE", "\"none\"");
	parse_ok("enum High", "llm.reasoning_effort", "High", "\"high\"");
	parse_ok("enum empty", "llm.reasoning_effort", "", "\"\"");
	parse_ok("enum blank", "llm.reasoning_effort", "   ", "\"\"");
	parse_ok("enum openai", "embedding.provider", "OpenAI", "\"openai\"");
	parse_ok("enum fastembed", "embedding.provider", "FastEmbed",
		 "\"fastembed\"");
	parse_err("enum bad", "llm.reasoning_effort", "maybe",
		  "可选值：空 / none / low / medium / high");
	parse_err("enum bad2", "embedding.provider", "bogus",
		  "可选值：hashing / openai / sentence-transformers / fastembed");
	parse_err("enum bad3", "retrieval.fusion", "min_max",
		  "可选值：weighted / minmax");

	/* interval：off/none/关/关闭 -> 1e9，其余按整数 */
	parse_ok("interval off", "memory.consolidate_every", "off",
		 "1000000000");
	parse_ok("interval OFF", "memory.consolidate_every", "OFF",
		 "1000000000");
	parse_ok("interval none", "memory.consolidate_every", "none",
		 "1000000000");
	parse_ok("interval 关", "memory.consolidate_every", "关",
		 "1000000000");
	parse_ok("interval 关闭", "memory.compress_every", "关闭",
		 "1000000000");
	parse_ok("interval 8", "memory.consolidate_every", "8", "8");
	parse_ok("interval +8", "memory.consolidate_every", " +8 ", "8");
	parse_err("interval small", "memory.consolidate_every", "0",
		  "融合周期 不能小于 1");
	parse_err("interval bad", "memory.consolidate_every", "abc",
		  "融合周期 必须是整数");
	parse_err("interval float", "memory.consolidate_every", "1.5",
		  "融合周期 必须是整数");

	/* int：符号、空白、下划线、边界、错误 */
	parse_ok("int 42", "llm.max_tokens", "42", "42");
	parse_ok("int strip", "llm.max_tokens", " 42 ", "42");
	parse_ok("int +7", "llm.max_tokens", "+7", "7");
	parse_ok("int -0", "retrieval.keyword_candidates", "-0", "0");
	parse_ok("int underscore", "llm.max_tokens", "1_0", "10");
	parse_ok("int min", "llm.max_tokens", "1", "1");
	parse_ok("int max", "llm.max_tokens", "128000", "128000");
	parse_err("int low", "llm.max_tokens", "0", "最大 token 不能小于 1");
	parse_err("int high", "llm.max_tokens", "128001",
		  "最大 token 不能大于 128000");
	parse_err("int decimal", "llm.max_tokens", "3.5",
		  "最大 token 必须是整数");
	parse_err("int exp", "llm.max_tokens", "1e3",
		  "最大 token 必须是整数");
	parse_err("int text", "llm.max_tokens", "abc",
		  "最大 token 必须是整数");
	parse_err("int empty", "llm.max_tokens", "",
		  "最大 token 必须是整数");
	parse_err("int underscore bad", "llm.max_tokens", "1__0",
		  "最大 token 必须是整数");

	/* float：形态、NaN/inf、min/max */
	parse_ok("float 0.5", "llm.temperature", "0.5", "0.5");
	parse_ok("float .5", "llm.temperature", ".5", "0.5");
	parse_ok("float 5.", "maintenance.idle_after_s", "5.", "5.0");
	parse_ok("float 1e3", "maintenance.every_s", "1e3", "1000.0");
	parse_ok("float 3", "maintenance.every_s", "3", "3.0");
	parse_ok("float min", "llm.temperature", "0", "0.0");
	parse_ok("float max", "llm.temperature", "2", "2.0");
	parse_ok("float 0.1 bound", "reinforcement.ebbinghaus_half_life_days",
		 "0.1", "0.1");
	parse_err("float high", "llm.temperature", "2.5",
		  "温度 不能大于 2");
	parse_err("float low", "llm.temperature", "-0.1",
		  "温度 不能小于 0");
	parse_err("float low2", "reinforcement.ebbinghaus_half_life_days",
		  "0.05", "强化半衰期 不能小于 0.1");
	parse_err("float nan", "llm.temperature", "nan",
		  "温度 必须是有限数字");
	parse_err("float inf", "llm.temperature", "inf",
		  "温度 必须是有限数字");
	parse_err("float -inf", "llm.temperature", "-Infinity",
		  "温度 必须是有限数字");
	parse_err("float overflow", "llm.temperature", "1e999",
		  "温度 必须是有限数字");
	parse_err("float text", "llm.temperature", "abc",
		  "温度 必须是数字");
	parse_err("float hex", "llm.temperature", "0x10",
		  "温度 必须是数字");

	/* required + str */
	parse_err("required empty", "llm.model", "",
		  "模型 不能为空，请输入一个值");
	parse_err("required blank", "llm.model", "   ",
		  "模型 不能为空，请输入一个值");
	parse_err("required storage", "storage.path", "\t\n",
		  "快照路径 不能为空，请输入一个值");
	parse_ok("str plain", "llm.base_url", "  https://x/v1  ",
		 "\"https://x/v1\"");
	parse_ok("str empty", "llm.base_url", "", "\"\"");
	parse_ok("str unicode space", "llm.base_url", "\u3000值\u3000",
		 "\"值\"");
	parse_ok("str keeps inner", "llm.base_url", " a b ", "\"a b\"");

	/* NULL raw 等价于 "" */
	parse_ok("null raw str", "llm.base_url", NULL, "\"\"");
	parse_err("null raw required", "llm.model", NULL,
		  "模型 不能为空，请输入一个值");
}

/* ------------------------------------------------------------------ */
/* 6) validate_value                                                  */
/* ------------------------------------------------------------------ */
static void val_ok(const char *label, const char *path, const char *json)
{
	const aik_config_item *it = aik_config_item_find(path);
	aik_json *v = aik_json_parse(json, strlen(json), NULL, 0);
	char err[512];
	int rc;

	err[0] = '\0';
	check(it != NULL && v != NULL, "%s: setup failed", label);
	if (!it || !v) {
		aik_json_free(v);
		return;
	}
	rc = aik_config_item_validate(it, v, err, sizeof(err));
	check(rc == 0, "%s: rc=%d err=%s", label, rc, err);
	aik_json_free(v);
}

static void val_err(const char *label, const char *path, const char *json,
		    const char *want_err)
{
	const aik_config_item *it = aik_config_item_find(path);
	aik_json *v = aik_json_parse(json, strlen(json), NULL, 0);
	char err[512];
	int rc;

	err[0] = '\0';
	check(it != NULL && v != NULL, "%s: setup failed", label);
	if (!it || !v) {
		aik_json_free(v);
		return;
	}
	rc = aik_config_item_validate(it, v, err, sizeof(err));
	check(rc == -1, "%s: rc=%d want -1", label, rc);
	check(strcmp(err, want_err) == 0, "%s: err \"%s\" want \"%s\"", label,
	      err, want_err);
	aik_json_free(v);
}

static void test_validate(void)
{
	/* bool：只认 BOOL */
	val_ok("val bool true", "memory.reinforce_on", "true");
	val_ok("val bool false", "memory.reinforce_on", "false");
	val_err("val bool int", "memory.reinforce_on", "1",
		"应为 开/关（true/false）");
	val_err("val bool str", "memory.reinforce_on", "\"true\"",
		"应为 开/关（true/false）");
	val_err("val bool null", "memory.reinforce_on", "null", "值为空");
	val_err("val bool arr", "memory.reinforce_on", "[]",
		"应为 开/关（true/false）");

	/* int：只认 INT（BOOL 不算）+ 区间 */
	val_ok("val int ok", "llm.max_tokens", "1024");
	val_ok("val int min", "llm.max_tokens", "1");
	val_err("val int low", "llm.max_tokens", "0", "不能小于 1");
	val_err("val int high", "llm.max_tokens", "128001",
		"不能大于 128000");
	val_err("val int bool", "llm.max_tokens", "true", "应为整数");
	val_err("val int num", "llm.max_tokens", "1024.0", "应为整数");
	val_err("val int str", "llm.max_tokens", "\"1024\"", "应为整数");
	val_err("val int null", "llm.max_tokens", "null", "值为空");

	/* interval：同 int 规则（off 哨兵在范围内） */
	val_ok("val interval ok", "memory.consolidate_every", "8");
	val_ok("val interval off", "memory.consolidate_every", "1000000000");
	val_err("val interval low", "memory.consolidate_every", "0",
		"不能小于 1");
	val_err("val interval bool", "memory.consolidate_every", "false",
		"应为整数");
	val_err("val interval num", "memory.consolidate_every", "8.0",
		"应为整数");

	/* float：INT/NUM 都算，BOOL 不算，非有限拦截 */
	val_ok("val float num", "llm.temperature", "0.5");
	val_ok("val float int", "llm.temperature", "1");
	val_ok("val float 0", "llm.temperature", "0");
	val_err("val float high", "llm.temperature", "3", "不能大于 2");
	val_err("val float low", "llm.temperature", "-0.5", "不能小于 0");
	val_err("val float bool", "llm.temperature", "true", "应为数字");
	val_err("val float str", "llm.temperature", "\"0.5\"", "应为数字");
	val_err("val float null", "llm.temperature", "null", "值为空");
	{
		const aik_config_item *it =
			aik_config_item_find("llm.temperature");
		char err[512];
		aik_json *nan = aik_json_new_num(NAN);
		aik_json *inf = aik_json_new_num(INFINITY);

		err[0] = '\0';
		check(it && nan && aik_config_item_validate(it, nan, err,
							    sizeof(err)) == -1,
		      "val float nan: must fail");
		check(strcmp(err, "必须是有限数字") == 0,
		      "val float nan: err \"%s\"", err);
		err[0] = '\0';
		check(inf && aik_config_item_validate(it, inf, err,
						      sizeof(err)) == -1,
		      "val float inf: must fail");
		check(strcmp(err, "必须是有限数字") == 0,
		      "val float inf: err \"%s\"", err);
		aik_json_free(nan);
		aik_json_free(inf);
	}

	/* enum：空串合法；非字符串/未注册值报错；不显示"空" */
	val_ok("val enum empty", "llm.reasoning_effort", "\"\"");
	val_ok("val enum none", "llm.reasoning_effort", "\"none\"");
	val_err("val enum case", "llm.reasoning_effort", "\"None\"",
		"可选值： / none / low / medium / high");
	val_err("val enum int", "llm.reasoning_effort", "0",
		"可选值： / none / low / medium / high");
	val_err("val enum provider", "embedding.provider", "\"bogus\"",
		"可选值：hashing / openai / sentence-transformers / fastembed");

	/* str */
	val_ok("val str ok", "llm.base_url", "\"https://x\"");
	val_ok("val str empty", "llm.base_url", "\"\"");
	val_err("val str int", "llm.base_url", "1", "应为字符串");
	val_err("val str bool", "llm.base_url", "false", "应为字符串");
	val_err("val str arr", "llm.base_url", "[]", "应为字符串");
	val_err("val str null", "llm.base_url", "null", "值为空");
}

/* ------------------------------------------------------------------ */
/* 7) validate_all                                                    */
/* ------------------------------------------------------------------ */
static void test_validate_all(const aik_json *cdef)
{
	char err[256];
	aik_json *cfg = aik_config_display(cdef);
	aik_json *warn;

	check(cfg != NULL, "validate_all: display failed");
	if (!cfg)
		return;

	warn = aik_config_validate_all(cfg, err, sizeof(err));
	check(warn != NULL, "validate_all: failed: %s", err);
	check(warn && aik_json_count(warn) == 0,
	      "validate_all: defaults %zu warnings != 0",
	      warn ? aik_json_count(warn) : 99);
	aik_json_free(warn);

	/* 注入 LLM + embedding 端点（模型/密钥留空） */
	set_json(cfg, "llm.base_url", aik_json_new_str("https://api.deepseek.com/v1"));
	set_json(cfg, "llm.model", aik_json_new_str(""));
	set_json(cfg, "llm.api_key", aik_json_new_str(""));
	set_json(cfg, "embedding.base_url",
		 aik_json_new_str("https://api.siliconflow.cn/v1"));
	set_json(cfg, "embedding.api_key", aik_json_new_str(""));

	warn = aik_config_validate_all(cfg, err, sizeof(err));
	check(warn != NULL, "validate_all: injection failed: %s", err);
	check(warn && aik_json_count(warn) == 3,
	      "validate_all: %zu warnings != 3",
	      warn ? aik_json_count(warn) : 99);
	if (warn && aik_json_count(warn) == 3) {
		check(strcmp(aik_json_str(aik_json_at(warn, 0)),
			     "[llm.model]：LLM 已配置（llm.base_url）时 模型 必填") == 0,
		      "validate_all: warning[0] \"%s\"",
		      aik_json_str(aik_json_at(warn, 0)));
		check(strcmp(aik_json_str(aik_json_at(warn, 1)),
			     "[llm.api_key]：LLM 已配置（llm.base_url）时 API 密钥 必填") == 0,
		      "validate_all: warning[1] \"%s\"",
		      aik_json_str(aik_json_at(warn, 1)));
		check(strcmp(aik_json_str(aik_json_at(warn, 2)),
			     "[embedding.api_key]：已配置 embedding.base_url 时 API 密钥 必填") == 0,
		      "validate_all: warning[2] \"%s\"",
		      aik_json_str(aik_json_at(warn, 2)));
	}
	aik_json_free(warn);

	/* 补齐 llm.model / llm.api_key -> 只剩 embedding 一条 */
	set_json(cfg, "llm.model", aik_json_new_str("deepseek-v4-flash"));
	set_json(cfg, "llm.api_key", aik_json_new_str("sk-x"));
	warn = aik_config_validate_all(cfg, err, sizeof(err));
	check(warn && aik_json_count(warn) == 1,
	      "validate_all: %zu warnings != 1",
	      warn ? aik_json_count(warn) : 99);
	if (warn && aik_json_count(warn) == 1)
		check(strcmp(aik_json_str(aik_json_at(warn, 0)),
			     "[embedding.api_key]：已配置 embedding.base_url 时 API 密钥 必填") == 0,
		      "validate_all: remaining warning");
	aik_json_free(warn);

	/* 默认 OpenAI 地址 + 空密钥 = 未配置（零配置离线承诺） */
	{
		aik_json *base = aik_config_display(cdef);
		aik_json *w;

		set_json(base, "llm.base_url",
			 aik_json_new_str("https://api.openai.com/v1"));
		set_json(base, "llm.api_key", aik_json_new_str(""));
		w = aik_config_validate_all(base, err, sizeof(err));
		check(w && aik_json_count(w) == 0,
		      "validate_all: default OpenAI URL must not warn");
		aik_json_free(w);
		aik_json_free(base);
	}

	/* 非法值 + 条件必填：值告警行在前，且 repr 用 Python 形态 */
	{
		aik_json *bad = aik_config_display(cdef);
		aik_json *w;

		set_json(bad, "llm.base_url",
			 aik_json_new_str("https://api.deepseek.com/v1"));
		set_json(bad, "llm.model", aik_json_new_str(""));
		set_json(bad, "llm.max_tokens", aik_json_new_int(0));
		set_json(bad, "llm.temperature", aik_json_new_num(9.5));
		set_json(bad, "memory.reinforce_on", aik_json_new_str("yes"));
		w = aik_config_validate_all(bad, err, sizeof(err));
		check(w && aik_json_count(w) == 5,
		      "validate_all: %zu warnings != 5",
		      w ? aik_json_count(w) : 99);
		if (w && aik_json_count(w) == 5) {
			check(strcmp(aik_json_str(aik_json_at(w, 0)),
				     "[llm.max_tokens] = 0：不能小于 1") == 0,
			      "validate_all: int repr \"%s\"",
			      aik_json_str(aik_json_at(w, 0)));
			check(strcmp(aik_json_str(aik_json_at(w, 1)),
				     "[llm.temperature] = 9.5：不能大于 2") == 0,
			      "validate_all: float repr \"%s\"",
			      aik_json_str(aik_json_at(w, 1)));
			check(strcmp(aik_json_str(aik_json_at(w, 2)),
				     "[memory.reinforce_on] = 'yes'：应为 开/关（true/false）") == 0,
			      "validate_all: str repr \"%s\"",
			      aik_json_str(aik_json_at(w, 2)));
			check(strcmp(aik_json_str(aik_json_at(w, 4)),
				     "[llm.api_key]：LLM 已配置（llm.base_url）时 API 密钥 必填") == 0,
			      "validate_all: conditional last \"%s\"",
			      aik_json_str(aik_json_at(w, 4)));
		}
		aik_json_free(w);
		aik_json_free(bad);
	}

	aik_json_free(cfg);
}

/* ------------------------------------------------------------------ */
/* 8) load_file 回退                                                  */
/* ------------------------------------------------------------------ */
static void test_load_fallback(void)
{
	char tmpl[] = "/tmp/aik-cfgload-XXXXXX";
	char path[256];
	char err[256];

	check(mkdtemp(tmpl) != NULL, "load: mkdtemp failed");
	snprintf(path, sizeof(path), "%s/cfg.json", tmpl);

	/* 缺失 -> 101 项默认 */
	{
		aik_json *dom = aik_config_load_file(path, err, sizeof(err));
		size_t i, hits = 0;

		check(dom != NULL, "load(missing): NULL: %s", err);
		if (dom) {
			check(aik_json_count(dom) == 25,
			      "load(missing): %zu sections != 25",
			      aik_json_count(dom));
			for (i = 0; i < aik_config_item_count; i++)
				if (aik_config_item_has(dom,
							&aik_config_items[i]))
					hits++;
			check(hits == 101, "load(missing): %zu items != 101",
			      hits);
			aik_json_free(dom);
		}
	}

	/* 坏 JSON -> 默认 */
	check(write_file(path, "{bad", 4) == 0, "load: write bad");
	{
		aik_json *dom = aik_config_load_file(path, err, sizeof(err));

		check(dom && aik_json_count(dom) == 25,
		      "load(bad json): not defaults");
		aik_json_free(dom);
	}

	/* 顶层数组 -> 默认 */
	check(write_file(path, "[1,2,3]", 7) == 0, "load: write array");
	{
		aik_json *dom = aik_config_load_file(path, err, sizeof(err));

		check(dom && aik_config_item_has(
				    dom, aik_config_item_find("llm.base_url")),
		      "load(array): not defaults");
		aik_json_free(dom);
	}

	/* 顶层 null -> 默认 */
	check(write_file(path, "null", 4) == 0, "load: write null");
	{
		aik_json *dom = aik_config_load_file(path, err, sizeof(err));

		check(dom && aik_config_item_has(
				    dom, aik_config_item_find("llm.base_url")),
		      "load(null): not defaults");
		aik_json_free(dom);
	}

	/* BOM + 合法对象 -> 原样返回（不补全） */
	{
		const char *json = "\xEF\xBB\xBF{\"only\": 1}";
		aik_json *dom;

		check(write_file(path, json, strlen(json)) == 0,
		      "load: write bom");
		dom = aik_config_load_file(path, err, sizeof(err));
		check(dom && aik_json_count(dom) == 1 &&
		      aik_json_get(dom, "only") != NULL,
		      "load(bom): BOM object must be returned as-is");
		aik_json_free(dom);
	}

	/* 空对象 -> 原样返回（不补全） */
	check(write_file(path, "{}", 2) == 0, "load: write empty");
	{
		aik_json *dom = aik_config_load_file(path, err, sizeof(err));

		check(dom && aik_json_count(dom) == 0,
		      "load({}): must be returned as-is");
		aik_json_free(dom);
	}

	/* 空路径 -> 默认 */
	{
		aik_json *dom = aik_config_load_file("", err, sizeof(err));

		check(dom && aik_json_count(dom) == 25,
		      "load(empty path): not defaults");
		aik_json_free(dom);
	}

	unlink(path);
	rmdir(tmpl);
}

/* ------------------------------------------------------------------ */
/* 9) value_equal                                                     */
/* ------------------------------------------------------------------ */
static int eq_lit(const char *a, const char *b)
{
	aik_json *x = a ? aik_json_parse(a, strlen(a), NULL, 0) : NULL;
	aik_json *y = b ? aik_json_parse(b, strlen(b), NULL, 0) : NULL;
	int r;

	if ((a && !x) || (b && !y)) {
		aik_json_free(x);
		aik_json_free(y);
		return -2;
	}
	r = aik_config_value_equal(x, y);
	aik_json_free(x);
	aik_json_free(y);
	return r;
}

static void test_value_equal(void)
{
	check(eq_lit("true", "1") == 1, "equal: true == 1");
	check(eq_lit("false", "0") == 1, "equal: false == 0");
	check(eq_lit("true", "2") == 0, "equal: true != 2");
	check(eq_lit("false", "0.0") == 1, "equal: false == 0.0");
	check(eq_lit("1", "1.0") == 1, "equal: 1 == 1.0");
	check(eq_lit("1", "1.5") == 0, "equal: 1 != 1.5");
	check(eq_lit("\"a\"", "\"a\"") == 1, "equal: str eq");
	check(eq_lit("\"a\"", "\"b\"") == 0, "equal: str ne");
	check(eq_lit("\"a\"", "\"ab\"") == 0, "equal: str prefix");
	check(eq_lit("null", "null") == 1, "equal: null == null");
	check(eq_lit("null", "0") == 0, "equal: null != 0");
	check(eq_lit("true", "\"true\"") == 0, "equal: bool != str");
	check(eq_lit("[1,2]", "[1,2]") == 1, "equal: arr eq");
	check(eq_lit("[1,2]", "[1,3]") == 0, "equal: arr ne");
	check(eq_lit("[1]", "[1,2]") == 0, "equal: arr len");
	check(eq_lit("[true]", "[1]") == 1, "equal: arr bool/int");
	check(eq_lit("[]", "[]") == 1, "equal: empty arr");
	check(eq_lit("[]", "{}") == 0, "equal: arr != obj");
	check(eq_lit("{\"a\":1,\"b\":2}", "{\"b\":2,\"a\":1}") == 1,
	      "equal: obj order-insensitive");
	check(eq_lit("{\"a\":1}", "{\"a\":1,\"b\":2}") == 0,
	      "equal: obj len");
	check(eq_lit("{\"a\":{\"b\":[1,2]}}", "{\"a\":{\"b\":[1,2]}}") == 1,
	      "equal: nested eq");
	check(eq_lit("{\"a\":{\"b\":[1,2]}}", "{\"a\":{\"b\":[1,3]}}") == 0,
	      "equal: nested ne");
	check(aik_config_value_equal(NULL, NULL) == 1,
	      "equal: NULL==NULL not true");
	{
		aik_json *one = aik_json_new_int(1);

		check(aik_config_value_equal(NULL, one) == 0,
		      "equal: NULL != 1");
		check(aik_config_value_equal(one, NULL) == 0,
		      "equal: 1 != NULL");
		aik_json_free(one);
	}
	check(eq_lit("0", "-0.0") == 1, "equal: 0 == -0.0");
	check(eq_lit("\"\"", "\"\"") == 1, "equal: empty str");

	/* 实际配置里的 INT/NUM 桥：retrieval.min_similarity -1.0 vs -1 */
	check(eq_lit("-1.0", "-1") == 1, "equal: -1.0 == -1");
	check(eq_lit("0.3", "0.3") == 1, "equal: 0.3 == 0.3");
}

/* ------------------------------------------------------------------ */
/* 10) item_set / get / has                                           */
/* ------------------------------------------------------------------ */
static void test_set_get(void)
{
	char err[256];
	aik_config *cdef = aik_config_defaults(err, sizeof(err));
	aik_json *cfg = aik_json_new_obj();
	aik_json *scratch;
	const aik_config_item *it;
	aik_json *v;
	const aik_json *got;

	check(cdef != NULL, "set: defaults failed: %s", err);
	check(cfg != NULL, "set: new obj failed");
	if (!cdef || !cfg)
		return;

	/* 缺段建 OBJ */
	it = aik_config_item_find("llm.base_url");
	v = aik_config_item_default(it);
	set_json(cfg, "llm.base_url", v);
	check(aik_json_get(cfg, "llm") != NULL &&
	      aik_json_typeof(aik_json_get(cfg, "llm")) == AIK_JSON_OBJ,
	      "set: llm section not created");
	check(aik_config_item_has(cfg, it), "set: llm.base_url missing");
	v = aik_config_item_default(it);
	check(v && aik_config_item_get(cfg, it) &&
	      aik_config_value_equal(v, aik_config_item_get(cfg, it)),
	      "set: llm.base_url wrong");
	aik_json_free(v);

	/* 非对象中间段被覆盖为空对象 */
	scratch = aik_json_new_obj();
	aik_json_obj_set(scratch, "llm", aik_json_new_int(5));
	it = aik_config_item_find("llm.model");
	v = aik_json_new_str("m1");
	check(aik_config_item_set(scratch, it, v) == 0, "set: overwrite fail");
	aik_json_free(v);
	check(aik_json_typeof(aik_json_get(scratch, "llm")) == AIK_JSON_OBJ,
	      "set: non-obj intermediate not replaced");
	check(aik_config_item_get(scratch, it) &&
	      strcmp(aik_json_str(aik_config_item_get(scratch, it)), "m1") == 0,
	      "set: value after overwrite");
	aik_json_free(scratch);

	/* 已存在键保持位置 */
	scratch = aik_json_new_obj();
	aik_json_obj_set(scratch, "a", aik_json_new_int(1));
	aik_json_obj_set(scratch, "llm", aik_json_new_obj());
	aik_json_obj_set(scratch, "z", aik_json_new_int(9));
	it = aik_config_item_find("llm.model");
	v = aik_json_new_str("m2");
	aik_config_item_set(scratch, it, v);
	aik_json_free(v);
	check(strcmp(aik_json_key_at(scratch, 0), "a") == 0 &&
	      strcmp(aik_json_key_at(scratch, 1), "llm") == 0 &&
	      strcmp(aik_json_key_at(scratch, 2), "z") == 0,
	      "set: top-level order changed");
	{
		const aik_json *llm = aik_json_get(scratch, "llm");

		check(strcmp(aik_json_key_at(llm, 0), "model") == 0,
		      "set: section order");
	}
	/* 二次设值不换位 */
	v = aik_json_new_str("m3");
	aik_config_item_set(scratch, it, v);
	aik_json_free(v);
	check(strcmp(aik_json_key_at(aik_json_get(scratch, "llm"), 0),
		     "model") == 0,
	      "set: replace changed position");
	aik_json_free(scratch);

	/* 值 null 也算存在（get 非 NULL） */
	scratch = aik_json_new_obj();
	{
		aik_json *llm = aik_json_new_obj();

		aik_json_obj_set(llm, "base_url", aik_json_new_null());
		aik_json_obj_set(scratch, "llm", llm);
	}
	it = aik_config_item_find("llm.base_url");
	check(aik_config_item_get(scratch, it) != NULL,
	      "get: null leaf must be non-NULL");
	check(aik_config_item_has(scratch, it) == 1,
	      "has: null leaf must be present");
	aik_json_free(scratch);

	/* 路径缺失 / 中间段非对象 */
	scratch = aik_json_new_obj();
	aik_json_obj_set(scratch, "llm", aik_json_new_int(1));
	check(aik_config_item_get(scratch, it) == NULL,
	      "get: non-obj intermediate must be NULL");
	check(aik_config_item_has(scratch, it) == 0,
	      "has: non-obj intermediate must be absent");
	aik_json_free(scratch);
	check(aik_config_item_get(NULL, it) == NULL, "get: NULL cfg");
	check(aik_config_item_get(cfg, NULL) == NULL, "get: NULL item");

	/* defaults：无显式键也能读 */
	it = aik_config_item_find("llm.max_tokens");
	got = aik_config_item_get(aik_config_dom(cdef), it);
	check(got && aik_json_typeof(got) == AIK_JSON_INT &&
	      aik_json_int(got) == 1024,
	      "get: llm.max_tokens from SMEConfig defaults");

	/* 典型配置项默认值都在 defaults_config() 里 */
	{
		aik_json *def = aik_config_defaults_build();

		check(def != NULL, "get: defaults_build failed");
		it = aik_config_item_find("memory.graph_expand");
		got = aik_config_item_get(def, it);
		check(got && aik_json_int(got) == 1,
		      "get: memory.graph_expand default");
		it = aik_config_item_find("retrieval.min_similarity");
		got = aik_config_item_get(def, it);
		check(got && aik_json_typeof(got) == AIK_JSON_INT &&
		      aik_json_int(got) == -1,
		      "get: min_similarity default is INT -1");
		aik_json_free(def);
	}

	aik_json_free(cfg);
	aik_config_free(cdef);
}

/* ------------------------------------------------------------------ */
int main(void)
{
	char err[256];
	aik_config *cdef;

	err[0] = '\0';
	cdef = aik_config_defaults(err, sizeof(err));
	if (!cdef) {
		fprintf(stderr, "FATAL: aik_config_defaults: %s\n", err);
		printf("test_config_items: 1 checks, 1 failed\n");
		return 1;
	}

	test_registry();
	test_groups_presets(aik_config_dom(cdef));
	test_mutated();
	test_save_load(aik_config_dom(cdef));
	test_parse();
	test_validate();
	test_validate_all(aik_config_dom(cdef));
	test_load_fallback();
	test_value_equal();
	test_set_get();

	aik_config_free(cdef);

	printf("test_config_items: %zu checks, %zu failed\n", checks,
	       failures);
	return failures ? 1 : 0;
}
