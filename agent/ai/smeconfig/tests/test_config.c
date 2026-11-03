/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_config.c - T4a SME 配置中心自测
 *
 * 数据：
 *   $AIK_PARITY_VECTORS/api/reference.json
 *     （默认 $HOME/aikernel-longterm/parity/vectors）
 *   $AIK_PARITY_CASES/api_cases.json（可选，也可直接给文件；默认
 *     $HOME/aikernel-longterm/parity/cases/api_cases.json）
 *
 * 覆盖：
 *   1) 默认 DOM 与 reference 的配置逐 section 逐键比较。reference.json 的
 *      final_export.body 只有 memories/graph/stats，没有 config；因此回退
 *      到 meta.config（API 运行配置，由 api_cases 的 config_template
 *      构造）。该运行配置相对 SMEConfig() 默认值只改了四个键：
 *      storage.path=<TMP>/data/engine.json.gz、embedding.model、
 *      embedding.hash_seed、storage.autosave —— 这四个键只校验存在，并在
 *      结构检查里逐一断言其 Python 默认值。运行配置保留的是
 *      config_template 的手写键序（不是 to_dict() 键序），所以这里只比
 *      存在性与值；26 section / 133 键的完整键序由内置 Python 默认 JSON
 *      与全键覆盖用例验证。
 *   2) 内置默认 JSON（config_default.h，Python 真值）的结构：26 section /
 *      133 键 / 每节键名顺序 / 非 ASCII 字符串。
 *   3) 全键覆盖：用 Python 默认 JSON 的每个键构造覆盖值跑
 *      aik_config_from_json，要求 DOM 与输入逐键逐序逐类型相等、133 个键
 *      全部 is_explicit（seed 除外）、get_* 读回覆盖值、默认对象不被污染。
 *   4) config_template：<TMP> 替换为 /tmp/x 后覆盖生效、未覆盖键保持
 *      默认、键序不变、is_explicit 只标记文件里写了的键。
 *   5) aik_config_load：{"sme": {...}} 包装、未知 section/key 忽略、
 *      坏 JSON/缺失文件/空路径报错。
 *   6) get_i64/get_num/get_bool/get_str 类型规则（各 2 个正例 + 反例）。
 *
 * 输出末行：SUMMARY config checks=N mismatches=M；有失配 exit 1。
 */
#define _POSIX_C_SOURCE 200809L

#include "smeconfig/config.h"
#include "store/store_json.h"

#include "../config_default.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t checks;
static size_t mismatches;

/* ------------------------------------------------------------------ */
/* 断言                                                               */
/* ------------------------------------------------------------------ */
static void check(int cond, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (cond)
		return;
	mismatches++;
	fprintf(stderr, "MISMATCH ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/*
 * 下面四个 expect_* 先取值再断言：C 的参数求值顺序未指定，绝不能在同一个
 * 调用里把 &out 和 out 一起传给 check_*（会读到上一次的旧值）。
 */
static void expect_i64(const char *label, const aik_config *c,
		       const char *dotted, long long want)
{
	long long got = 0;
	int rc = aik_config_get_i64(c, dotted, &got);

	check(rc == 0 && got == want, "%s: rc=%d got=%lld want=%lld", label, rc,
	      got, want);
}

static void expect_num(const char *label, const aik_config *c,
		       const char *dotted, double want)
{
	double got = 0.0;
	int rc = aik_config_get_num(c, dotted, &got);

	check(rc == 0 && got == want, "%s: rc=%d got=%.17g want=%.17g", label,
	      rc, got, want);
}

static void expect_bool(const char *label, const aik_config *c,
			const char *dotted, int want)
{
	int got = -1;
	int rc = aik_config_get_bool(c, dotted, &got);

	check(rc == 0 && got == want, "%s: rc=%d got=%d want=%d", label, rc,
	      got, want);
}

static void expect_str(const char *label, const aik_config *c,
		       const char *dotted, const char *want)
{
	const char *got = aik_config_get_str(c, dotted);

	check(got && want && strcmp(got, want) == 0, "%s: got \"%s\" want \"%s\"",
	      label, got ? got : "(null)", want ? want : "(null)");
}

/* 期望 get_* 拒绝（类型不符 / 路径不存在） */
static void expect_no_i64(const char *label, const aik_config *c,
			  const char *dotted)
{
	long long got = 0;
	int rc = aik_config_get_i64(c, dotted, &got);

	check(rc == -1, "%s: rc=%d want -1", label, rc);
}

static void expect_no_num(const char *label, const aik_config *c,
			  const char *dotted)
{
	double got = 0.0;
	int rc = aik_config_get_num(c, dotted, &got);

	check(rc == -1, "%s: rc=%d want -1", label, rc);
}

static void expect_no_bool(const char *label, const aik_config *c,
			   const char *dotted)
{
	int got = -1;
	int rc = aik_config_get_bool(c, dotted, &got);

	check(rc == -1, "%s: rc=%d want -1", label, rc);
}

static void expect_no_str(const char *label, const aik_config *c,
			  const char *dotted)
{
	const char *got = aik_config_get_str(c, dotted);

	check(got == NULL, "%s: got \"%s\" want NULL", label,
	      got ? got : "(null)");
}

/* ------------------------------------------------------------------ */
/* 读文件 / 环境                                                       */
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

static const char *vectors_dir(void)
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

/* AIK_PARITY_CASES 允许是目录（拼 /api_cases.json）或 JSON 文件本身 */
static const char *cases_path(void)
{
	static char buf[1024];
	const char *d = getenv("AIK_PARITY_CASES");
	const char *home = getenv("HOME");
	size_t n;

	if (d && *d) {
		n = strlen(d);
		if (n > 5 && strcmp(d + n - 5, ".json") == 0)
			return d;
		snprintf(buf, sizeof(buf), "%s/api_cases.json", d);
		return buf;
	}
	snprintf(buf, sizeof(buf),
		 "%s/aikernel-longterm/parity/cases/api_cases.json",
		 home && *home ? home : ".");
	return buf;
}

/* ------------------------------------------------------------------ */
/* DOM 小工具                                                          */
/* ------------------------------------------------------------------ */
/* 深比较：类型、值、键序、元素序全部一致 */
static int json_eq(const aik_json *a, const aik_json *b)
{
	aik_json_type ta = aik_json_typeof(a);
	aik_json_type tb = aik_json_typeof(b);
	size_t i, n;

	if (ta != tb) {
		/* INT/NUM 数值等价（参考向量里 42 与 42.0 视为同值） */
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
			if (!json_eq(aik_json_at(a, i), aik_json_at(b, i)))
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
			if (!json_eq(aik_json_val_at(a, i),
				     aik_json_val_at(b, i)))
				return 0;
		}
		return 1;
	}
	return 0;
}

typedef struct {
	char *p;
	size_t len;
	size_t cap;
} sbuf;

static int sb_init(sbuf *s)
{
	s->cap = 256;
	s->p = malloc(s->cap);
	if (!s->p)
		return -1;
	s->p[0] = '\0';
	s->len = 0;
	return 0;
}

static int sb_puts(sbuf *s, const char *txt)
{
	size_t n = strlen(txt);

	if (s->len + n + 1 > s->cap) {
		size_t cap = s->cap;
		char *grown;

		while (cap < s->len + n + 1)
			cap *= 2;
		grown = realloc(s->p, cap);
		if (!grown)
			return -1;
		s->p = grown;
		s->cap = cap;
	}
	memcpy(s->p + s->len, txt, n + 1);
	s->len += n;
	return 0;
}

/* 键序签名："seed|embedding:provider,model,...|region:..." */
static char *order_sig(const aik_json *dom)
{
	sbuf s;
	size_t i, j;

	if (sb_init(&s) != 0)
		return NULL;
	for (i = 0; i < aik_json_count(dom); i++) {
		const char *k = aik_json_key_at(dom, i);
		const aik_json *v = aik_json_val_at(dom, i);

		if (!k)
			continue;
		if (sb_puts(&s, k) != 0)
			goto fail;
		if (aik_json_typeof(v) == AIK_JSON_OBJ) {
			if (sb_puts(&s, ":") != 0)
				goto fail;
			for (j = 0; j < aik_json_count(v); j++) {
				const char *sk = aik_json_key_at(v, j);

				if (!sk || sb_puts(&s, sk) != 0 ||
				    sb_puts(&s, ",") != 0)
					goto fail;
			}
		}
		if (sb_puts(&s, "|") != 0)
			goto fail;
	}
	return s.p;
fail:
	free(s.p);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* 1) 默认配置结构（Python 真值：26 section / 133 键）                 */
/* ------------------------------------------------------------------ */
static const struct {
	const char *name;
	size_t nkeys;	/* 顶层 seed 记 1 */
} EXPECT_SECTIONS[] = {
	{ "seed", 1 },
	{ "embedding", 13 },
	{ "region", 10 },
	{ "retrieval", 11 },
	{ "ranking", 8 },
	{ "policy", 3 },
	{ "reinforcement", 7 },
	{ "decay", 3 },
	{ "consolidation", 4 },
	{ "compression", 3 },
	{ "llm", 8 },
	{ "storage", 5 },
	{ "maintenance", 3 },
	{ "visualization", 5 },
	{ "extraction", 5 },
	{ "factversion", 5 },
	{ "noise", 6 },
	{ "qapair", 4 },
	{ "factgraph", 5 },
	{ "profile", 4 },
	{ "persistence", 5 },
	{ "api", 3 },
	{ "observability", 3 },
	{ "context", 4 },
	{ "namespaces", 2 },
	{ "rerank", 3 },
};

#define N_EXPECT_SECTIONS (sizeof(EXPECT_SECTIONS) / sizeof(EXPECT_SECTIONS[0]))

static void test_structure(const aik_config *cdef)
{
	const aik_json *dom = aik_config_dom(cdef);
	const aik_json *v;
	size_t i, total = 0;

	check(dom && aik_json_typeof(dom) == AIK_JSON_OBJ,
	      "defaults: DOM is not an object");
	if (!dom || aik_json_typeof(dom) != AIK_JSON_OBJ)
		return;
	check(aik_json_count(dom) == N_EXPECT_SECTIONS,
	      "defaults: %zu sections != %zu", aik_json_count(dom),
	      N_EXPECT_SECTIONS);

	/* section 顺序 + 每节键数（键序见下方内置 JSON 与全键覆盖用例） */
	for (i = 0; i < N_EXPECT_SECTIONS && i < aik_json_count(dom); i++) {
		const char *k = aik_json_key_at(dom, i);

		check(k && strcmp(k, EXPECT_SECTIONS[i].name) == 0,
		      "defaults: section[%zu]=%s want %s", i,
		      k ? k : "(null)", EXPECT_SECTIONS[i].name);
	}
	for (i = 0; i < aik_json_count(dom); i++) {
		const aik_json *sec = aik_json_val_at(dom, i);

		if (i == 0) {
			check(aik_json_typeof(sec) == AIK_JSON_INT &&
				      aik_json_int(sec) == 42,
			      "defaults: seed != 42");
			total += 1;
		} else {
			check(aik_json_typeof(sec) == AIK_JSON_OBJ &&
				      aik_json_count(sec) ==
					      EXPECT_SECTIONS[i].nkeys,
			      "defaults: section %s key count %zu != %zu",
			      aik_json_key_at(dom, i), aik_json_count(sec),
			      EXPECT_SECTIONS[i].nkeys);
			total += aik_json_count(sec);
		}
	}
	check(total == 133, "defaults: %zu keys != 133", total);

	/* 默认 DOM 必须与 Python 真值 JSON 逐键逐序逐值一致（133 键） */
	{
		char perr[256];
		aik_json *py = aik_json_parse(
			AIK_CONFIG_DEFAULT_JSON,
			sizeof(AIK_CONFIG_DEFAULT_JSON) - 1, perr,
			sizeof(perr));

		check(py != NULL, "defaults: Python JSON parse: %s", perr);
		check(py && json_eq(dom, py),
		      "defaults: DOM != Python default JSON（键序/值有偏差）");
		aik_json_free(py);
	}

	/* 生成文件本身：长度 + 非 ASCII 字符串（八进制转义正确性） */
	check(strlen(AIK_CONFIG_DEFAULT_JSON) == 3333,
	      "config_default.h: JSON length %zu != 3333",
	      strlen(AIK_CONFIG_DEFAULT_JSON));
	v = aik_json_get(aik_json_get(dom, "factversion"), "correct_markers");
	check(v && aik_json_typeof(v) == AIK_JSON_ARR &&
		      aik_json_count(v) == 11,
	      "defaults: factversion.correct_markers != 11 items");
	if (v && aik_json_typeof(v) == AIK_JSON_ARR && aik_json_count(v) == 11) {
		check(aik_json_str(aik_json_at(v, 0)) &&
			      strcmp(aik_json_str(aik_json_at(v, 0)), "其实") ==
				      0,
		      "defaults: correct_markers[0] != 其实");
		check(aik_json_str(aik_json_at(v, 10)) &&
			      strcmp(aik_json_str(aik_json_at(v, 10)), "错了") ==
				      0,
		      "defaults: correct_markers[10] != 错了");
	}

	/* reference.meta.config 相对默认值改掉的四个键：此处断言 Python 默认 */
	expect_str("defaults: storage.path", cdef, "storage.path",
		   "data/engine.json");
	expect_str("defaults: embedding.model", cdef, "embedding.model",
		   "text-embedding-3-small");
	expect_i64("defaults: embedding.hash_seed", cdef,
		   "embedding.hash_seed", 0);
	expect_bool("defaults: storage.autosave", cdef, "storage.autosave", 1);

	/* 数组 + null 默认值原样保留 */
	v = aik_json_get(aik_json_get(dom, "visualization"), "figure_size");
	check(v && aik_json_typeof(v) == AIK_JSON_ARR &&
		      aik_json_count(v) == 2 &&
		      aik_json_int(aik_json_at(v, 0)) == 12 &&
		      aik_json_int(aik_json_at(v, 1)) == 9,
	      "defaults: visualization.figure_size != [12, 9]");
	v = aik_json_get(aik_json_get(dom, "llm"), "reasoning_effort");
	check(v && aik_json_typeof(v) == AIK_JSON_NULL,
	      "defaults: llm.reasoning_effort != null");
	v = aik_json_get(aik_json_get(dom, "retrieval"), "region_options");
	check(v && aik_json_typeof(v) == AIK_JSON_ARR &&
		      aik_json_count(v) == 3 &&
		      aik_json_int(aik_json_at(v, 0)) == 1 &&
		      aik_json_int(aik_json_at(v, 2)) == 5,
	      "defaults: retrieval.region_options != [1, 3, 5]");
}

/* ------------------------------------------------------------------ */
/* 2) reference.json 对比                                             */
/* ------------------------------------------------------------------ */
static int config_masked(const char *section, const char *key)
{
	char dotted[160];

	snprintf(dotted, sizeof(dotted), "%s.%s", section, key);
	/* storage.path：期望是 <TMP> 临时路径，只校验存在；
	 * 其余三个是 parity 运行通过 config_template 改掉的值 */
	return strcmp(dotted, "storage.path") == 0 ||
	       strcmp(dotted, "embedding.model") == 0 ||
	       strcmp(dotted, "embedding.hash_seed") == 0 ||
	       strcmp(dotted, "storage.autosave") == 0;
}

static const aik_json *find_step(const aik_json *root, const char *id)
{
	const aik_json *steps = aik_json_get(root, "steps");
	size_t i, n = aik_json_count(steps);

	for (i = 0; i < n; i++) {
		const aik_json *step = aik_json_at(steps, i);
		const char *sid = aik_json_str(aik_json_get(step, "id"));

		if (sid && strcmp(sid, id) == 0)
			return step;
	}
	return NULL;
}

static void compare_reference_config(const aik_json *exp,
				     const aik_config *cdef)
{
	const aik_json *dom = aik_config_dom(cdef);
	size_t i, j, n = aik_json_count(exp);

	check(aik_json_typeof(dom) == AIK_JSON_OBJ, "reference: bad C DOM");
	/* 运行配置保留 config_template 的手写键序，因此只比存在与值 */
	for (i = 0; i < n; i++) {
		const char *sname = aik_json_key_at(exp, i);
		const aik_json *e = aik_json_val_at(exp, i);
		const aik_json *csec;

		if (!sname)
			continue;
		csec = aik_json_get(dom, sname);
		check(csec != NULL, "reference: section %s missing in C",
		      sname);
		if (!csec)
			continue;
		if (aik_json_typeof(e) != AIK_JSON_OBJ) {
			check(json_eq(e, csec), "reference: %s value mismatch",
			      sname);
			continue;
		}
		check(aik_json_typeof(csec) == AIK_JSON_OBJ,
		      "reference: %s is not an object in C", sname);
		if (aik_json_typeof(csec) != AIK_JSON_OBJ)
			continue;
		for (j = 0; j < aik_json_count(e); j++) {
			const char *k = aik_json_key_at(e, j);
			const aik_json *ev = aik_json_val_at(e, j);
			const aik_json *cv;
			char label[192];

			if (!k)
				continue;
			snprintf(label, sizeof(label), "%s.%s", sname, k);
			cv = aik_json_get(csec, k);
			check(cv != NULL, "reference: %s missing in C", label);
			if (!cv)
				continue;
			if (config_masked(sname, k))
				continue;
			check(json_eq(ev, cv), "reference: %s value mismatch",
			      label);
		}
	}
}

static void test_reference(const aik_config *cdef)
{
	char path[1200];
	char err[256];
	size_t len = 0;
	char *buf;
	aik_json *ref;
	const aik_json *exp, *body, *fe;
	int from_meta = 0;

	snprintf(path, sizeof(path), "%s/api/reference.json", vectors_dir());
	buf = read_file(path, &len);
	check(buf != NULL, "reference: cannot read %s", path);
	if (!buf)
		return;
	ref = aik_json_parse(buf, len, err, sizeof(err));
	free(buf);
	check(ref != NULL, "reference: parse failed: %s", err);
	if (!ref)
		return;

	fe = find_step(ref, "final_export");
	check(fe != NULL, "reference: steps[final_export] missing");
	body = fe ? aik_json_get(fe, "body") : NULL;
	exp = body ? aik_json_get(body, "config") : NULL;
	if (!exp || aik_json_typeof(exp) != AIK_JSON_OBJ) {
		exp = aik_json_get(aik_json_get(ref, "meta"), "config");
		from_meta = 1;
	}
	if (!exp || aik_json_typeof(exp) != AIK_JSON_OBJ) {
		check(0, "reference: no config in final_export.body or meta");
		aik_json_free(ref);
		return;
	}
	printf("note: reference config source = %s（%s）\n",
	       from_meta ? "meta.config" : "final_export.body.config",
	       from_meta ? "API 运行配置，非 SMEConfig() 默认值" : "默认值");
	compare_reference_config(exp, cdef);
	aik_json_free(ref);
}

/* ------------------------------------------------------------------ */
/* 3) 全键覆盖：Python 默认 JSON 的 133 个键全部改写                  */
/* ------------------------------------------------------------------ */
static aik_json *perturb(const aik_json *v)
{
	aik_json *out;
	char *txt;
	size_t n;

	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return aik_json_new_str("x-null");
	case AIK_JSON_BOOL:
		return aik_json_new_bool(!aik_json_bool(v));
	case AIK_JSON_INT:
		return aik_json_new_int(aik_json_int(v) + 1);
	case AIK_JSON_NUM:
		return aik_json_new_num(aik_json_num(v) + 0.5);
	case AIK_JSON_STR:
		n = strlen(aik_json_str(v)) + 3;
		txt = malloc(n);
		if (!txt)
			return NULL;
		snprintf(txt, n, "x-%s", aik_json_str(v));
		out = aik_json_new_str(txt);
		free(txt);
		return out;
	case AIK_JSON_ARR:
		return aik_json_new_arr();	/* 覆盖成空数组，验证原样保留 */
	case AIK_JSON_OBJ:
		out = aik_json_new_obj();
		if (!out)
			return NULL;
		if (aik_json_obj_put(out, "k", aik_json_new_str("v")) != 0) {
			aik_json_free(out);
			return NULL;
		}
		return out;
	}
	return NULL;
}

static void test_override_all(const aik_config *cdef)
{
	char err[256];
	char label[192];
	aik_json *pydef, *input;
	aik_config *ov;
	size_t i, j, n;

	pydef = aik_json_parse(AIK_CONFIG_DEFAULT_JSON,
			       sizeof(AIK_CONFIG_DEFAULT_JSON) - 1, err,
			       sizeof(err));
	check(pydef != NULL, "override: embedded JSON parse: %s", err);
	if (!pydef)
		return;
	input = aik_json_new_obj();
	check(input != NULL, "override: out of memory");
	if (!input) {
		aik_json_free(pydef);
		return;
	}
	n = aik_json_count(pydef);
	for (i = 0; i < n; i++) {
		const char *k = aik_json_key_at(pydef, i);
		const aik_json *v = aik_json_val_at(pydef, i);
		aik_json *nv;

		if (strcmp(k, "seed") == 0) {
			nv = aik_json_new_int(43);
		} else {
			nv = aik_json_new_obj();
			if (!nv)
				break;
			for (j = 0; j < aik_json_count(v); j++) {
				const char *sk = aik_json_key_at(v, j);
				aik_json *sv = perturb(aik_json_val_at(v, j));

				if (!sk || !sv ||
				    aik_json_obj_put(nv, sk, sv) != 0) {
					aik_json_free(sv);
					aik_json_free(nv);
					nv = NULL;
					break;
				}
			}
		}
		if (!nv || aik_json_obj_put(input, k, nv) != 0) {
			aik_json_free(nv);
			break;
		}
	}

	ov = aik_config_from_json(input, err, sizeof(err));
	check(ov != NULL, "override: from_json failed: %s", err);
	if (!ov) {
		aik_json_free(input);
		aik_json_free(pydef);
		return;
	}
	/* 133 键逐键逐序逐类型（含数组/对象/null 覆盖） */
	check(json_eq(aik_config_dom(ov), input),
	      "override: DOM != input（值/类型/键序有偏差）");

	for (i = 0; i < n; i++) {
		const char *sname = aik_json_key_at(pydef, i);
		const aik_json *isec = aik_json_get(input, sname);

		if (strcmp(sname, "seed") == 0)
			continue;
		for (j = 0; j < aik_json_count(isec); j++) {
			const char *k = aik_json_key_at(isec, j);
			const aik_json *iv = aik_json_val_at(isec, j);

			snprintf(label, sizeof(label), "%s.%s", sname, k);
			check(aik_config_is_explicit(ov, label) == 1,
			      "override: %s not explicit", label);
			switch (aik_json_typeof(iv)) {
			case AIK_JSON_BOOL:
				expect_bool(label, ov, label,
					    aik_json_bool(iv));
				break;
			case AIK_JSON_INT:
				expect_i64(label, ov, label, aik_json_int(iv));
				expect_num(label, ov, label,
					   (double)aik_json_int(iv));
				break;
			case AIK_JSON_NUM:
				expect_num(label, ov, label, aik_json_num(iv));
				break;
			case AIK_JSON_STR:
				expect_str(label, ov, label, aik_json_str(iv));
				break;
			default:	/* 数组/对象：值由 json_eq 覆盖 */
				break;
			}
		}
	}

	check(aik_config_is_explicit(ov, "seed") == 0,
	      "override: seed must not be explicit");
	expect_i64("override: seed", ov, "seed", 43);
	/* 新配置不能污染默认对象 */
	expect_i64("defaults untouched: seed", cdef, "seed", 42);
	expect_num("defaults untouched: region.min_join_cosine", cdef,
		   "region.min_join_cosine", 0.7);

	aik_config_free(ov);
	aik_json_free(input);
	aik_json_free(pydef);
}

/* ------------------------------------------------------------------ */
/* 4) api_cases.json 的 config_template                                */
/* ------------------------------------------------------------------ */
/* 深拷贝并把字符串里的 needle 替换成 repl */
static aik_json *clone_replace(const aik_json *v, const char *needle,
			       const char *repl)
{
	aik_json *out;
	size_t i, n;

	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return aik_json_new_null();
	case AIK_JSON_BOOL:
		return aik_json_new_bool(aik_json_bool(v));
	case AIK_JSON_INT:
		return aik_json_new_int(aik_json_int(v));
	case AIK_JSON_NUM:
		return aik_json_new_num(aik_json_num(v));
	case AIK_JSON_STR: {
		const char *s = aik_json_str(v);
		const char *hit = strstr(s, needle);
		char *txt;
		size_t pre, mid, post;

		if (!hit)
			return aik_json_new_str(s);
		pre = (size_t)(hit - s);
		mid = strlen(needle);
		post = strlen(hit + mid);
		txt = malloc(pre + strlen(repl) + post + 1);
		if (!txt)
			return NULL;
		memcpy(txt, s, pre);
		memcpy(txt + pre, repl, strlen(repl));
		memcpy(txt + pre + strlen(repl), hit + mid, post + 1);
		out = aik_json_new_str(txt);
		free(txt);
		return out;
	}
	case AIK_JSON_ARR:
		out = aik_json_new_arr();
		if (!out)
			return NULL;
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			aik_json *item = clone_replace(aik_json_at(v, i), needle,
						       repl);

			if (!item || aik_json_arr_push(out, item) != 0) {
				aik_json_free(item);
				aik_json_free(out);
				return NULL;
			}
		}
		return out;
	case AIK_JSON_OBJ:
		out = aik_json_new_obj();
		if (!out)
			return NULL;
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			const char *k = aik_json_key_at(v, i);
			aik_json *item = clone_replace(aik_json_val_at(v, i),
						       needle, repl);

			if (!k || !item || aik_json_obj_put(out, k, item) != 0) {
				aik_json_free(item);
				aik_json_free(out);
				return NULL;
			}
		}
		return out;
	}
	return NULL;
}

static void test_template(const aik_config *cdef)
{
	char err[256];
	char *buf;
	size_t len = 0;
	aik_json *cases, *rep;
	aik_config *t;
	const aik_json *tpl;
	char *sig_t, *sig_d;

	buf = read_file(cases_path(), &len);
	if (!buf) {
		printf("note: %s 不存在，跳过 config_template 检查\n",
		       cases_path());
		return;
	}
	cases = aik_json_parse(buf, len, err, sizeof(err));
	free(buf);
	check(cases != NULL, "template: api_cases parse failed: %s", err);
	if (!cases)
		return;
	tpl = aik_json_get(cases, "config_template");
	check(tpl && aik_json_typeof(tpl) == AIK_JSON_OBJ,
	      "template: config_template missing");
	if (!tpl || aik_json_typeof(tpl) != AIK_JSON_OBJ) {
		aik_json_free(cases);
		return;
	}
	rep = clone_replace(tpl, "<TMP>", "/tmp/x");
	check(rep != NULL, "template: replace <TMP> failed");
	if (!rep) {
		aik_json_free(cases);
		return;
	}
	t = aik_config_from_json(rep, err, sizeof(err));
	check(t != NULL, "template: from_json failed: %s", err);
	if (t) {
		/* 覆盖值正确 */
		expect_str("tpl: storage.path", t, "storage.path",
			   "/tmp/x/data/engine.json.gz");
		expect_str("tpl: retrieval.fusion", t, "retrieval.fusion",
			   "minmax");
		expect_i64("tpl: embedding.dim", t, "embedding.dim", 64);
		expect_str("tpl: embedding.model", t, "embedding.model",
			   "hashing-d64-w3");
		expect_i64("tpl: embedding.hash_seed", t,
			   "embedding.hash_seed", 42);
		expect_bool("tpl: storage.autosave", t, "storage.autosave", 0);

		/* 未覆盖的键保持默认 */
		expect_i64("tpl: region.split_threshold", t,
			   "region.split_threshold", 48);
		expect_str("tpl: llm.model", t, "llm.model", "gpt-4o-mini");
		expect_num("tpl: ranking.semantic", t, "ranking.semantic",
			   0.4);
		expect_bool("tpl: retrieval.cjk_bigram", t,
			    "retrieval.cjk_bigram", 1);
		expect_str("tpl: visualization.projection", t,
			   "visualization.projection", "pca");

		/* is_explicit：文件里写了的键（含等于默认值的）显式 */
		check(aik_config_is_explicit(t, "region.min_join_cosine") == 1,
		      "tpl: region.min_join_cosine must be explicit");
		check(aik_config_is_explicit(t, "region.split_threshold") == 0,
		      "tpl: region.split_threshold must not be explicit");
		check(aik_config_is_explicit(t, "storage.path") == 1,
		      "tpl: storage.path must be explicit");
		check(aik_config_is_explicit(t, "retrieval.fusion") == 1,
		      "tpl: retrieval.fusion must be explicit");
		check(aik_config_is_explicit(t, "embedding.dim") == 1,
		      "tpl: embedding.dim must be explicit");
		check(aik_config_is_explicit(t, "seed") == 0,
		      "tpl: seed must not be explicit");

		/* 覆盖不换位：完整键序签名与默认一致 */
		sig_t = order_sig(aik_config_dom(t));
		sig_d = order_sig(aik_config_dom(cdef));
		check(sig_t && sig_d && strcmp(sig_t, sig_d) == 0,
		      "tpl: key order changed by overrides");
		free(sig_t);
		free(sig_d);
		aik_config_free(t);
	}
	aik_json_free(rep);
	aik_json_free(cases);
}

/* ------------------------------------------------------------------ */
/* 5) get_* 类型规则                                                   */
/* ------------------------------------------------------------------ */
static void test_types(const aik_config *cdef)
{
	/* int：2 正例 + 数值桥 + 反例 */
	expect_i64("type: embedding.dim", cdef, "embedding.dim", 64);
	expect_i64("type: region.evolve_interval", cdef,
		   "region.evolve_interval", 40);
	expect_i64("type: region.max_density (NUM 120.0 整数桥)", cdef,
		   "region.max_density", 120);
	expect_no_i64("type: region.min_join_cosine is not i64", cdef,
		      "region.min_join_cosine");

	/* num：2 正例 + INT 桥 */
	expect_num("type: region.min_join_cosine", cdef,
		   "region.min_join_cosine", 0.7);
	expect_num("type: ranking.semantic", cdef, "ranking.semantic", 0.4);
	expect_num("type: retrieval.top_k (INT 桥)", cdef,
		   "retrieval.top_k", 10.0);

	/* bool：2 正例 + 反例 */
	expect_bool("type: embedding.normalize", cdef, "embedding.normalize",
		    1);
	expect_bool("type: policy.full_memory", cdef, "policy.full_memory", 1);
	expect_no_bool("type: retrieval.top_k is not bool", cdef,
		       "retrieval.top_k");

	/* str：2 正例 + 反例 */
	expect_str("type: retrieval.fusion", cdef, "retrieval.fusion",
		   "minmax");
	expect_str("type: api.host", cdef, "api.host", "127.0.0.1");
	expect_no_str("type: get_str(INT) must be NULL", cdef,
		      "embedding.dim");

	/* dotted path / 单段 seed / 缺失 / NULL 输入 */
	expect_i64("type: seed via single segment", cdef, "seed", 42);
	expect_no_i64("type: missing key", cdef, "no.such.key");
	expect_no_i64("type: non-existent section", cdef, "nosuch.key");
	expect_no_str("type: missing str must be NULL", cdef, "no.such");
	expect_no_num("type: get_num(STR) must return -1", cdef, "api.host");

	check(aik_config_dom(NULL) == NULL, "type: dom(NULL) != NULL");
	check(aik_config_is_explicit(NULL, "seed") == 0,
	      "type: is_explicit(NULL) != 0");
	check(aik_config_get_i64(NULL, "seed", NULL) == -1,
	      "type: get_i64(NULL) != -1");
	check(aik_config_get_str(NULL, "seed") == NULL,
	      "type: get_str(NULL) != NULL");
	aik_config_free(NULL);	/* 必须安全 */
	checks++;

	/* 默认键永不显式 */
	check(aik_config_is_explicit(cdef, "region.min_join_cosine") == 0,
	      "type: default region.min_join_cosine must not be explicit");
	check(aik_config_is_explicit(cdef, "storage.path") == 0,
	      "type: default storage.path must not be explicit");
	check(aik_config_is_explicit(cdef, "seed") == 0,
	      "type: default seed must not be explicit");
}

/* ------------------------------------------------------------------ */
/* 6) aik_config_load                                                  */
/* ------------------------------------------------------------------ */
static int write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "wb");
	size_t n = strlen(text);

	if (!f)
		return -1;
	if (fwrite(text, 1, n, f) != n) {
		fclose(f);
		return -1;
	}
	return fclose(f);
}

static void test_load(void)
{
	static const char json[] =
		"{\"sme\":{\"seed\":7,"
		"\"region\":{\"min_join_cosine\":0.55,\"split_threshold\":9,"
		"\"bogus\":1},"
		"\"retrieval\":{\"fusion\":\"weighted\"},"
		"\"nosuch\":{\"a\":1}},\"other\":1}";
	char path[256];
	char err[256];
	aik_config *c;

	snprintf(path, sizeof(path), "/tmp/aik-config-test-%ld.json",
		 (long)getpid());
	check(write_file(path, json) == 0, "load: cannot write %s", path);

	err[0] = '\0';
	c = aik_config_load(path, err, sizeof(err));
	check(c != NULL, "load: failed: %s", err);
	if (c) {
		expect_i64("load: seed", c, "seed", 7);
		expect_i64("load: region.split_threshold", c,
			   "region.split_threshold", 9);
		expect_num("load: region.min_join_cosine", c,
			   "region.min_join_cosine", 0.55);
		expect_str("load: retrieval.fusion", c, "retrieval.fusion",
			   "weighted");
		expect_i64("load: unoverridden embedding.dim", c,
			   "embedding.dim", 64);
		check(aik_config_is_explicit(c, "region.min_join_cosine") == 1,
		      "load: region.min_join_cosine must be explicit");
		check(aik_config_is_explicit(c, "region.split_threshold") == 1,
		      "load: region.split_threshold must be explicit");
		check(aik_config_is_explicit(c, "retrieval.fusion") == 1,
		      "load: retrieval.fusion must be explicit");
		check(aik_config_is_explicit(c, "region.bogus") == 0,
		      "load: region.bogus must be ignored");
		check(aik_config_is_explicit(c, "nosuch.a") == 0,
		      "load: nosuch.a must be ignored");
		expect_no_i64("load: unknown section ignored", c, "nosuch.a");
		expect_no_i64("load: unknown top-level ignored", c, "other");
		aik_config_free(c);
	}
	unlink(path);

	check(write_file(path, "{bad") == 0, "load: cannot write %s", path);
	err[0] = '\0';
	check(aik_config_load(path, err, sizeof(err)) == NULL,
	      "load: bad JSON must fail");
	check(err[0] != '\0', "load: bad JSON must set err");
	unlink(path);

	err[0] = '\0';
	check(aik_config_load(path, err, sizeof(err)) == NULL,
	      "load: missing file must fail");
	check(err[0] != '\0', "load: missing file must set err");

	err[0] = '\0';
	check(aik_config_load(NULL, err, sizeof(err)) == NULL,
	      "load: NULL path must fail");
	check(err[0] != '\0', "load: NULL path must set err");
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
		printf("SUMMARY config checks=1 mismatches=1\n");
		return 1;
	}
	test_structure(cdef);
	test_reference(cdef);
	test_override_all(cdef);
	test_template(cdef);
	test_types(cdef);
	test_load();
	aik_config_free(cdef);

	printf("SUMMARY config checks=%zu mismatches=%zu\n", checks, mismatches);
	return mismatches ? 1 : 0;
}
