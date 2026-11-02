/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_engine.c - T4a Engine 自测（API 契约重放 + 老数据原地读）
 *
 * 数据：
 *   $AIK_PARITY_CASES/api_cases.json
 *     （默认 $HOME/aikernel-longterm/parity/cases/api_cases.json）
 *   $AIK_PARITY_VECTORS/api/reference.json
 *   $AIK_PARITY_VECTORS/storage/{engine.json.gz,engine.embeddings.npz,
 *                                snapshot.canonical.json,snapshot.meta.json,
 *                                space_load.expected.json}
 *
 * 段 1：API 重放 + actual.json
 *   - 临时目录 + 冻结时钟（cases.frozen_now）+ 确定性 id 生成器
 *     （m_/r_ + 12 位小写十六进制，从 1000 起）；
 *   - config_template（<TMP> 替换为临时目录）建引擎，/import 13 条种子；
 *   - 按 cases.steps 顺序执行 19 步的进程内等价操作，产出与 record_api.py
 *     同 schema 的工件（$AIK_ENGINE_DUMP，默认 tests/engine.actual.json）：
 *     {meta:{ref_commit,frozen_now,config}, seed_import, steps[], final_state,
 *      id_maps:{memory:{id:text}, region:{rid:[member ids]}}}；
 *   - 自检：steps=19、seed imported=13、final export 记忆数=参考值、逐步
 *     status 序列一致、每个 search 的 count 一致；另比对关键浮点/计数
 *     （1e-9）与 hit 的 4 个 round 值。
 *
 * 段 2：老数据原地读
 *   - 临时目录复制 engine.json.gz，按快照 embedding_file 把
 *     engine.embeddings.npz 复制成该名字，aik_engine_load；
 *   - 断言 549 总记忆 / 539 active / 10 archived / 226 Region /
 *     memory_edges=0，抽 3 条记忆 text+embedding 与快照逐位一致，
 *     stats 与 snapshot.canonical.json 独立重算的期望一致（1e-9），
 *     region_edges 数与 space_load.expected.json 一致，counters 恢复。
 *
 * 末行 "SUMMARY engine checks=N mismatches=M"；有失配退出码 1。
 */
#define _POSIX_C_SOURCE 200809L

#include "../../include/engine/engine.h"
#include "../../include/store/store_json.h"
#include "../../include/store/store_npz.h"
#include "../../include/store/store_snapshot.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* memory.c 内部符号：深拷贝 DOM（测试构造配置用） */
aik_json *aik_json__clone(const aik_json *v);

static size_t checks;
static size_t mismatches;

/* ------------------------------------------------------------------ */
/* 基础工具                                                           */
/* ------------------------------------------------------------------ */
static void die(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "test_engine: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

static void check_int(const char *path, long long got, long long exp)
{
	checks++;
	if (got != exp) {
		mismatches++;
		printf("MISMATCH %s: got %lld expected %lld\n", path, got, exp);
	}
}

static void check_num(const char *path, double got, double exp, double tol)
{
	checks++;
	if (!(fabs(got - exp) <= tol)) {
		mismatches++;
		printf("MISMATCH %s: got %.17g expected %.17g\n", path, got, exp);
	}
}

static void check_str(const char *path, const char *got, const char *exp)
{
	checks++;
	if (!got)
		got = "(null)";
	if (!exp)
		exp = "(null)";
	if (strcmp(got, exp) != 0) {
		mismatches++;
		printf("MISMATCH %s: got '%s' expected '%s'\n", path, got, exp);
	}
}

static const char *cases_dir(void)
{
	static char buf[1024];
	const char *d = getenv("AIK_PARITY_CASES");
	const char *home = getenv("HOME");

	if (d && *d)
		return d;
	snprintf(buf, sizeof(buf), "%s/aikernel-longterm/parity/cases",
		 home && *home ? home : ".");
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
		fclose(f);
		fprintf(stderr, "out of memory reading %s\n", path);
		return NULL;
	}
	got = fread(buf, 1, (size_t)n, f);
	fclose(f);
	if (got != (size_t)n) {
		free(buf);
		fprintf(stderr, "short read on %s\n", path);
		return NULL;
	}
	buf[got] = '\0';
	*len = got;
	return buf;
}

static aik_json *load_json(const char *path)
{
	char err[512];
	size_t len = 0;
	char *buf = read_file(path, &len);
	aik_json *v;

	if (!buf)
		return NULL;
	v = aik_json_parse(buf, len, err, sizeof(err));
	free(buf);
	if (!v) {
		fprintf(stderr, "invalid JSON %s: %s\n", path, err);
		return NULL;
	}
	return v;
}

static char *path_join(const char *dir, const char *name)
{
	size_t dl = strlen(dir);
	size_t nl = strlen(name);
	char *p = malloc(dl + nl + 2);

	if (!p)
		return NULL;
	memcpy(p, dir, dl);
	if (dl > 0 && dir[dl - 1] != '/')
		p[dl++] = '/';
	memcpy(p + dl, name, nl + 1);
	return p;
}

static char *make_tmpdir(void)
{
	const char *base = getenv("TMPDIR");
	char tmpl[1024];
	char *p;

	snprintf(tmpl, sizeof(tmpl), "%s/aik-engine-XXXXXX",
		 base && *base ? base : "/tmp");
	p = mkdtemp(tmpl);
	if (!p)
		die("mkdtemp failed");
	return strdup(p);
}

static int copy_file(const char *src, const char *dst)
{
	FILE *in = fopen(src, "rb");
	FILE *out;
	char buf[65536];
	size_t n;

	if (!in) {
		fprintf(stderr, "cannot open %s\n", src);
		return -1;
	}
	out = fopen(dst, "wb");
	if (!out) {
		fclose(in);
		fprintf(stderr, "cannot create %s\n", dst);
		return -1;
	}
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (fwrite(buf, 1, n, out) != n) {
			fclose(in);
			fclose(out);
			return -1;
		}
	}
	fclose(in);
	return fclose(out) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* JSON 构造与访问                                                    */
/* ------------------------------------------------------------------ */
static aik_json *jobj(void)
{
	aik_json *v = aik_json_new_obj();

	if (!v)
		die("out of memory");
	return v;
}

static aik_json *jarr(void)
{
	aik_json *v = aik_json_new_arr();

	if (!v)
		die("out of memory");
	return v;
}

static aik_json *jstr(const char *s)
{
	aik_json *v = aik_json_new_str(s ? s : "");

	if (!v)
		die("out of memory");
	return v;
}

static aik_json *jint(long long i)
{
	aik_json *v = aik_json_new_int(i);

	if (!v)
		die("out of memory");
	return v;
}

static aik_json *jnum(double d)
{
	aik_json *v = aik_json_new_num(d);

	if (!v)
		die("out of memory");
	return v;
}

static aik_json *jbool(int b)
{
	aik_json *v = aik_json_new_bool(b ? 1 : 0);

	if (!v)
		die("out of memory");
	return v;
}

static aik_json *jnull(void)
{
	aik_json *v = aik_json_new_null();

	if (!v)
		die("out of memory");
	return v;
}

static void jput(aik_json *obj, const char *key, aik_json *v)
{
	if (!v || aik_json_obj_put(obj, key, v) != 0)
		die("out of memory building JSON (key %s)", key);
}

static void jpush(aik_json *arr, aik_json *v)
{
	if (!v || aik_json_arr_push(arr, v) != 0)
		die("out of memory building JSON (array push)");
}

static const aik_json *need(const aik_json *obj, const char *key,
			    const char *where)
{
	const aik_json *v = aik_json_get(obj, key);

	if (!v)
		die("%s: missing key '%s'", where, key);
	return v;
}

static const char *need_str(const aik_json *obj, const char *key,
			    const char *where)
{
	const char *s = aik_json_str(need(obj, key, where));

	if (!s)
		die("%s: key '%s' is not a string", where, key);
	return s;
}

static double need_num(const aik_json *obj, const char *key, const char *where)
{
	const aik_json *v = need(obj, key, where);

	if (aik_json_typeof(v) != AIK_JSON_NUM &&
	    aik_json_typeof(v) != AIK_JSON_INT)
		die("%s: key '%s' is not a number", where, key);
	return aik_json_num(v);
}

static long long need_int(const aik_json *obj, const char *key,
			  const char *where)
{
	const aik_json *v = need(obj, key, where);

	if (aik_json_typeof(v) != AIK_JSON_NUM &&
	    aik_json_typeof(v) != AIK_JSON_INT)
		die("%s: key '%s' is not a number", where, key);
	return aik_json_int(v);
}

static const aik_json *at_idx(const aik_json *arr, size_t i,
			      const char *where)
{
	const aik_json *v = aik_json_at(arr, i);

	if (!v)
		die("%s: index %zu out of range", where, i);
	return v;
}

static int json_num_field(const aik_json *obj, const char *key, double *out)
{
	const aik_json *v = aik_json_get(obj, key);

	if (aik_json_typeof(v) != AIK_JSON_NUM &&
	    aik_json_typeof(v) != AIK_JSON_INT)
		return 0;
	*out = aik_json_num(v);
	return 1;
}

static int json_int_field(const aik_json *obj, const char *key,
			  long long *out)
{
	const aik_json *v = aik_json_get(obj, key);

	if (aik_json_typeof(v) != AIK_JSON_NUM &&
	    aik_json_typeof(v) != AIK_JSON_INT)
		return 0;
	*out = aik_json_int(v);
	return 1;
}

static const char *json_str_field(const aik_json *obj, const char *key)
{
	return aik_json_str(aik_json_get(obj, key));
}

/* ------------------------------------------------------------------ */
/* 时钟与 id                                                          */
/* ------------------------------------------------------------------ */
static double g_now;

static double clock_now(void *ud)
{
	(void)ud;
	return g_now;
}

static unsigned long long g_id_counter = 999;	/* 首个 id 从 1000 起 */

static int id_gen(void *ud, const char *prefix, char out[16])
{
	(void)ud;
	g_id_counter++;
	snprintf(out, 16, "%s_%012llx", prefix ? prefix : "m", g_id_counter);
	return 0;
}

/* ------------------------------------------------------------------ */
/* 配置                                                               */
/* ------------------------------------------------------------------ */
static char *substitute_tmp(const char *path, const char *tmpdir)
{
	const char *mark = "<TMP>";
	const char *hit = strstr(path, mark);
	size_t plen;
	size_t tlen;
	size_t rest;
	char *out;

	if (!hit)
		return strdup(path);
	plen = (size_t)(hit - path);
	tlen = strlen(tmpdir);
	rest = strlen(hit + strlen(mark));
	out = malloc(plen + tlen + rest + 1);
	if (!out)
		return NULL;
	memcpy(out, path, plen);
	memcpy(out + plen, tmpdir, tlen);
	memcpy(out + plen + tlen, hit + strlen(mark), rest + 1);
	return out;
}

static aik_config *config_from_template(const aik_json *tmpl,
					const char *tmpdir, char *err,
					size_t errlen)
{
	aik_json *copy = aik_json__clone(tmpl);
	aik_json *storage;
	const char *path;
	char *filled;
	aik_json *nv;
	aik_config *cfg;

	if (!copy)
		die("out of memory cloning config_template");
	storage = (aik_json *)aik_json_get(copy, "storage");
	path = aik_json_str(aik_json_get(storage, "path"));
	if (!path)
		die("config_template.storage.path is not a string");
	filled = substitute_tmp(path, tmpdir);
	nv = filled ? aik_json_new_str(filled) : NULL;
	if (!filled || !nv || aik_json_obj_set(storage, "path", nv) != 0)
		die("out of memory building config");
	free(filled);
	cfg = aik_config_from_json(copy, err, errlen);
	aik_json_free(copy);
	return cfg;
}

/* ------------------------------------------------------------------ */
/* 引擎操作的小包装                                                   */
/* ------------------------------------------------------------------ */
static const char **json_tags(const aik_json *arr, size_t *n_out)
{
	const char **tags;
	size_t n;
	size_t i;

	*n_out = 0;
	if (aik_json_typeof(arr) != AIK_JSON_ARR)
		return NULL;
	n = aik_json_count(arr);
	if (n == 0)
		return NULL;
	tags = calloc(n, sizeof(*tags));
	if (!tags)
		die("out of memory (tags)");
	for (i = 0; i < n; i++)
		tags[i] = aik_json_str(aik_json_at(arr, i));
	*n_out = n;
	return tags;
}

static aik_json *detail_not_found(void)
{
	aik_json *body = jobj();

	jput(body, "detail", jstr("memory not found"));
	return body;
}

/* POST /memories 的进程内等价：返回 memory.to_dict(include_embedding=true) */
static aik_json *do_add(aik_engine *e, const aik_json *body, char *err,
			size_t errlen)
{
	const char *text = aik_json_str(aik_json_get(body, "text"));
	const char *source = aik_json_str(aik_json_get(body, "source"));
	const char *link_to = aik_json_str(aik_json_get(body, "link_to"));
	const char *link_kind = aik_json_str(aik_json_get(body, "link_kind"));
	const char *ns = aik_json_str(aik_json_get(body, "ns"));
	const aik_json *md = aik_json_get(body, "metadata");
	double importance = 0.5;
	const char **tags;
	size_t n_tags = 0;
	aik_memory *m;
	aik_json *out;

	if (!json_num_field(body, "importance", &importance))
		importance = 0.5;
	tags = json_tags(aik_json_get(body, "tags"), &n_tags);
	m = aik_engine_add(e, text, md, tags, n_tags, importance,
			   source ? source : "user", link_to, link_kind, ns,
			   NULL, err, errlen);
	free(tags);
	if (!m)
		return NULL;
	out = aik_memory_to_json(m, 1);
	if (!out)
		die("out of memory (memory JSON)");
	return out;
}

/* POST /memories/batch */
static aik_json *do_batch(aik_engine *e, const aik_json *body, char *err,
			  size_t errlen)
{
	const aik_json *items = aik_json_get(body, "memories");
	aik_json *out = jobj();
	size_t n = aik_json_count(items);
	size_t i;
	long long added = 0;

	for (i = 0; i < n; i++) {
		const aik_json *item = aik_json_at(items, i);
		aik_json *d = do_add(e, item, err, errlen);

		if (!d)
			die("batch add failed: %s", err);
		aik_json_free(d);
		added++;
	}
	jput(out, "added", jint(added));
	jput(out, "dropped", jint((long long)n - added));
	jput(out, "total", jint((long long)n));
	return out;
}

/* POST /memories/search */
static aik_json *do_search(aik_engine *e, const aik_json *body, char *err,
			   size_t errlen, long long *out_count)
{
	const char *text = aik_json_str(aik_json_get(body, "text"));
	aik_search_query q;
	aik_search_hit *hits = NULL;
	size_t n_hits = 0;
	const char **tags;
	size_t n_tags = 0;
	aik_json *out;
	aik_json *results;
	size_t i;
	long long top_k = 10;

	if (json_int_field(body, "top_k", &top_k) == 0)
		top_k = 10;
	memset(&q, 0, sizeof(q));
	q.text = text ? text : "";
	q.top_k = (int)top_k;
	q.top_regions = -1;
	q.metadata_filters = aik_json_get(body, "metadata_filters");
	q.region_retrieval = 0;
	q.graph_expand = 0;
	q.include_archived = 0;
	tags = json_tags(aik_json_get(body, "tags"), &n_tags);
	q.tags = tags;
	q.n_tags = n_tags;
	if (aik_engine_search(e, &q, &hits, &n_hits, err, errlen) != 0)
		die("search failed: %s", err);
	free(tags);
	out = jobj();
	jput(out, "query", jstr(text ? text : ""));
	jput(out, "count", jint((long long)n_hits));
	results = jarr();
	for (i = 0; i < n_hits; i++) {
		aik_json *d = aik_search_hit_to_json(e, &hits[i]);

		if (!d)
			die("search hit %zu has no memory", i);
		jpush(results, d);
	}
	jput(out, "results", results);
	aik_search_hits_free(hits, n_hits);
	if (out_count)
		*out_count = (long long)n_hits;
	return out;
}

/* Pydantic v2 的两条 422 形状（route 层在 T4b；这里按参考逐键构造） */
static aik_json *pydantic_blank(const char *text)
{
	aik_json *body = jobj();
	aik_json *items = jarr();
	aik_json *item = jobj();
	aik_json *loc = jarr();
	aik_json *ctx = jobj();

	jpush(loc, jstr("body"));
	jpush(loc, jstr("text"));
	jput(ctx, "error", jobj());
	jput(item, "type", jstr("value_error"));
	jput(item, "loc", loc);
	jput(item, "msg", jstr("Value error, text must not be blank"));
	jput(item, "input", jstr(text ? text : ""));
	jput(item, "ctx", ctx);
	jpush(items, item);
	jput(body, "detail", items);
	return body;
}

static aik_json *pydantic_missing(const aik_json *request_body)
{
	aik_json *body = jobj();
	aik_json *items = jarr();
	aik_json *item = jobj();
	aik_json *loc = jarr();

	jpush(loc, jstr("body"));
	jpush(loc, jstr("text"));
	jput(item, "type", jstr("missing"));
	jput(item, "loc", loc);
	jput(item, "msg", jstr("Field required"));
	jput(item, "input",
	     request_body ? aik_json__clone(request_body) : jobj());
	jpush(items, item);
	jput(body, "detail", items);
	return body;
}

static char *id_from_path(const char *path)
{
	const char *p = strstr(path, "/memories/");
	const char *start;
	const char *end;
	size_t n;
	char *out;

	if (!p)
		return NULL;
	start = p + strlen("/memories/");
	end = strchr(start, '/');
	n = end ? (size_t)(end - start) : strlen(start);
	out = malloc(n + 1);
	if (!out)
		return NULL;
	memcpy(out, start, n);
	out[n] = '\0';
	return out;
}

/* ------------------------------------------------------------------ */
/* 段 1：API 重放                                                     */
/* ------------------------------------------------------------------ */
static aik_json *run_step(aik_engine *e, const aik_json *spec,
			  const aik_json *ref_step, int *out_status,
			  long long *out_search_count, char *err,
			  size_t errlen)
{
	const char *id = need_str(spec, "id", "cases.steps");
	const char *path = need_str(ref_step, "path", "reference.steps");
	const aik_json *req = aik_json_get(spec, "body");
	aik_json *body = NULL;

	*out_status = 200;
	*out_search_count = -1;

	if (strcmp(id, "health") == 0) {
		body = jobj();
		jput(body, "status", jstr("ok"));
		jput(body, "memories",
		     jint((long long)aik_engine_memory_count(e)));
	} else if (strcmp(id, "stats_before") == 0 ||
		   strcmp(id, "stats_after") == 0) {
		if (aik_engine_stats(e, &body, err, errlen) != 0)
			die("%s: stats failed: %s", id, err);
	} else if (strcmp(id, "add_memory") == 0) {
		body = do_add(e, req, err, errlen);
		if (!body)
			die("%s: add failed: %s", id, err);
	} else if (strcmp(id, "add_batch") == 0) {
		body = do_batch(e, req, err, errlen);
	} else if (strncmp(id, "search_", 7) == 0) {
		body = do_search(e, req, err, errlen, out_search_count);
	} else if (strcmp(id, "get_seed_3") == 0 ||
		   strcmp(id, "get_seed_3_after_hit") == 0) {
		char *mid = id_from_path(path);
		aik_memory *m = mid ? aik_engine_get(e, mid) : NULL;

		if (!mid)
			die("%s: cannot parse memory id from %s", id, path);
		if (!m) {
			*out_status = 404;
			body = detail_not_found();
		} else {
			body = aik_memory_to_json(m, 1);
			if (!body)
				die("%s: out of memory", id);
		}
		free(mid);
	} else if (strcmp(id, "hit_seed_3") == 0) {
		char *mid = id_from_path(path);
		int rc = mid ? aik_engine_reinforce(e, mid, &body, err, errlen)
			     : -1;

		if (!mid)
			die("%s: cannot parse memory id from %s", id, path);
		if (rc == 1) {
			*out_status = 404;
			body = detail_not_found();
		} else if (rc != 0) {
			die("%s: reinforce failed: %s", id, err);
		}
		free(mid);
	} else if (strcmp(id, "err_get_missing") == 0) {
		char *mid = id_from_path(path);
		aik_memory *m = mid ? aik_engine_get(e, mid) : NULL;

		if (!mid)
			die("%s: cannot parse memory id from %s", id, path);
		if (m)
			die("%s: expected a missing memory, found '%s'", id, mid);
		*out_status = 404;
		body = detail_not_found();
		free(mid);
	} else if (strcmp(id, "err_add_blank") == 0) {
		const char *text = aik_json_str(aik_json_get(req, "text"));

		if (aik_engine_add(e, text, NULL, NULL, 0, 0.5, "user", NULL,
				   NULL, NULL, NULL, err, errlen) != NULL)
			die("%s: blank text was accepted", id);
		*out_status = 422;
		body = pydantic_blank(text);
	} else if (strcmp(id, "err_add_missing_text") == 0) {
		if (aik_engine_add(e, NULL, NULL, NULL, 0, 0.5, "user", NULL,
				   NULL, NULL, NULL, err, errlen) != NULL)
			die("%s: missing text was accepted", id);
		*out_status = 422;
		body = pydantic_missing(req);
	} else if (strcmp(id, "final_export") == 0) {
		if (aik_engine_export(e, &body, err, errlen) != 0)
			die("%s: export failed: %s", id, err);
	} else if (strcmp(id, "final_regions") == 0) {
		if (aik_engine_regions(e, &body, err, errlen) != 0)
			die("%s: regions failed: %s", id, err);
	} else {
		die("unknown step id '%s'", id);
	}
	return body;
}

static void write_json(const char *path, const aik_json *root)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *f;

	if (aik_json_dump(root, &buf, &len) != 0 || !buf)
		die("cannot serialize actual.json");
	f = fopen(path, "wb");
	if (!f)
		die("cannot create %s", path);
	if (fwrite(buf, 1, len, f) != len || fputc('\n', f) == EOF) {
		fclose(f);
		free(buf);
		die("short write on %s", path);
	}
	fclose(f);
	free(buf);
}

static void compare_final_stats(const aik_json *got, const aik_json *ref)
{
	const aik_json *gm = need(got, "memories", "actual.stats");
	const aik_json *rm = need(ref, "memories", "reference.stats");
	const aik_json *gr = need(got, "regions", "actual.stats");
	const aik_json *rr = need(ref, "regions", "reference.stats");
	long long gi;
	long long ri;
	double gd;
	double rd;
	const char *gs;
	const char *rs;

	if (json_int_field(gm, "total", &gi) && json_int_field(rm, "total", &ri))
		check_int("stats.memories.total", gi, ri);
	if (json_int_field(gm, "active", &gi) &&
	    json_int_field(rm, "active", &ri))
		check_int("stats.memories.active", gi, ri);
	if (json_int_field(gm, "archived", &gi) &&
	    json_int_field(rm, "archived", &ri))
		check_int("stats.memories.archived", gi, ri);
	if (json_int_field(gm, "total_hits", &gi) &&
	    json_int_field(rm, "total_hits", &ri))
		check_int("stats.memories.total_hits", gi, ri);
	if (json_int_field(gm, "summarized", &gi) &&
	    json_int_field(rm, "summarized", &ri))
		check_int("stats.memories.summarized", gi, ri);
	if (json_num_field(gm, "avg_weight", &gd) &&
	    json_num_field(rm, "avg_weight", &rd))
		check_num("stats.memories.avg_weight", gd, rd, 1e-9);
	if (json_num_field(gm, "avg_importance", &gd) &&
	    json_num_field(rm, "avg_importance", &rd))
		check_num("stats.memories.avg_importance", gd, rd, 1e-9);
	if (json_num_field(gm, "avg_hit_count", &gd) &&
	    json_num_field(rm, "avg_hit_count", &rd))
		check_num("stats.memories.avg_hit_count", gd, rd, 1e-9);
	if (json_num_field(gm, "oldest_age_days", &gd) &&
	    json_num_field(rm, "oldest_age_days", &rd))
		check_num("stats.memories.oldest_age_days", gd, rd, 1e-9);

	if (json_int_field(gr, "count", &gi) &&
	    json_int_field(rr, "count", &ri))
		check_int("stats.regions.count", gi, ri);
	if (json_int_field(gr, "max_size", &gi) &&
	    json_int_field(rr, "max_size", &ri))
		check_int("stats.regions.max_size", gi, ri);
	if (json_int_field(gr, "min_size", &gi) &&
	    json_int_field(rr, "min_size", &ri))
		check_int("stats.regions.min_size", gi, ri);
	if (json_int_field(gr, "edge_count", &gi) &&
	    json_int_field(rr, "edge_count", &ri))
		check_int("stats.regions.edge_count", gi, ri);
	if (json_num_field(gr, "avg_size", &gd) &&
	    json_num_field(rr, "avg_size", &rd))
		check_num("stats.regions.avg_size", gd, rd, 1e-9);
	if (json_num_field(gr, "avg_density", &gd) &&
	    json_num_field(rr, "avg_density", &rd))
		check_num("stats.regions.avg_density", gd, rd, 1e-9);
	if (json_num_field(gr, "avg_radius", &gd) &&
	    json_num_field(rr, "avg_radius", &rd))
		check_num("stats.regions.avg_radius", gd, rd, 1e-9);
	if (json_num_field(gr, "avg_neighbors", &gd) &&
	    json_num_field(rr, "avg_neighbors", &rd))
		check_num("stats.regions.avg_neighbors", gd, rd, 1e-9);

	if (json_int_field(got, "splits", &gi) &&
	    json_int_field(ref, "splits", &ri))
		check_int("stats.splits", gi, ri);
	if (json_int_field(got, "merges", &gi) &&
	    json_int_field(ref, "merges", &ri))
		check_int("stats.merges", gi, ri);
	if (json_int_field(got, "consolidations", &gi) &&
	    json_int_field(ref, "consolidations", &ri))
		check_int("stats.consolidations", gi, ri);
	if (json_int_field(got, "compressions", &gi) &&
	    json_int_field(ref, "compressions", &ri))
		check_int("stats.compressions", gi, ri);
	if (json_int_field(got, "graph_edges", &gi) &&
	    json_int_field(ref, "graph_edges", &ri))
		check_int("stats.graph_edges", gi, ri);
	gs = json_str_field(got, "provider");
	rs = json_str_field(ref, "provider");
	if (gs && rs)
		check_str("stats.provider", gs, rs);
}

static void run_api_case(void)
{
	char err[512];
	char *cases_path;
	char *ref_path;
	aik_json *cases;
	aik_json *reference;
	const aik_json *ref_meta;
	const aik_json *ref_seed;
	const aik_json *step_specs;
	const aik_json *ref_steps;
	const aik_json *tmpl;
	char *tmpdir;
	aik_config *cfg;
	aik_engine *e;
	const aik_json *seed;
	long long imported = 0;
	size_t n_steps;
	aik_json *steps_out;
	aik_json *seed_rec;
	aik_json *seed_body;
	size_t i;
	aik_json *final_export_body = NULL;
	aik_json *final_regions_body = NULL;
	aik_json *final_state;
	aik_json *memory_map;
	aik_json *region_map;
	aik_json *root;
	aik_json *meta;
	const char *dump;
	char *dump_path;

	cases_path = path_join(cases_dir(), "api_cases.json");
	ref_path = path_join(vectors_dir(), "api/reference.json");
	if (!cases_path || !ref_path)
		die("out of memory");
	cases = load_json(cases_path);
	if (!cases)
		die("cannot load %s", cases_path);
	reference = load_json(ref_path);
	if (!reference)
		die("cannot load %s", ref_path);

	ref_meta = need(reference, "meta", "reference");
	ref_seed = need(reference, "seed_import", "reference");
	ref_steps = need(reference, "steps", "reference");
	step_specs = need(cases, "steps", "cases");
	tmpl = need(cases, "config_template", "cases");
	seed = need(cases, "seed_import", "cases");
	n_steps = aik_json_count(step_specs);

	check_int("cases.steps.count", (long long)n_steps,
		  (long long)aik_json_count(ref_steps));
	check_int("cases.steps.expected", (long long)n_steps, 19);
	if (n_steps != aik_json_count(ref_steps))
		die("cases/reference step count mismatch");

	g_now = need_num(ref_meta, "frozen_now", "reference.meta");
	tmpdir = make_tmpdir();
	cfg = config_from_template(tmpl, tmpdir, err, sizeof(err));
	if (!cfg)
		die("aik_config_from_json: %s", err);
	e = aik_engine_new(cfg, 1, clock_now, NULL, id_gen, NULL, err,
			   sizeof(err));
	if (!e)
		die("aik_engine_new: %s", err);

	if (aik_engine_import(e, seed, &imported, err, sizeof(err)) != 0)
		die("seed import: %s", err);
	check_int("seed.imported.ref", imported,
		  need_int(need(ref_seed, "body", "reference.seed_import"),
			   "imported", "reference.seed_import.body"));
	check_int("seed.imported.expected", imported, 13);

	seed_body = jobj();
	jput(seed_body, "imported", jint(imported));
	seed_rec = jobj();
	jput(seed_rec, "status", jint(need_int(ref_seed, "status",
					       "reference.seed_import")));
	jput(seed_rec, "content_type",
	     jstr(need_str(ref_seed, "content_type",
			   "reference.seed_import")));
	jput(seed_rec, "body", seed_body);

	steps_out = jarr();
	for (i = 0; i < n_steps; i++) {
		const aik_json *spec = at_idx(step_specs, i, "cases.steps");
		const aik_json *ref_step = at_idx(ref_steps, i, "reference.steps");
		const aik_json *req = aik_json_get(spec, "body");
		aik_json *rec = jobj();
		aik_json *body;
		int status = 200;
		long long count = -1;

		body = run_step(e, spec, ref_step, &status, &count, err,
				sizeof(err));
		jput(rec, "id", jstr(need_str(spec, "id", "cases.steps")));
		jput(rec, "method",
		     jstr(need_str(ref_step, "method", "reference.steps")));
		jput(rec, "path",
		     jstr(need_str(ref_step, "path", "reference.steps")));
		jput(rec, "request_body",
		     req ? aik_json__clone(req) : jnull());
		jput(rec, "status", jint(status));
		jput(rec, "content_type",
		     jstr(need_str(ref_step, "content_type",
				   "reference.steps")));
		jput(rec, "body", body);
		jpush(steps_out, rec);

		if (strncmp(need_str(spec, "id", "cases.steps"), "search_", 7) ==
		    0) {
			long long ref_count = need_int(
				need(ref_step, "body", "reference.steps"),
				"count", "reference.steps.body");
			check_int(need_str(spec, "id", "cases.steps"), count,
				  ref_count);
		}
		/* get_seed_3_after_hit：强化后的 4 个核心字段 */
		if (strcmp(need_str(spec, "id", "cases.steps"),
			   "get_seed_3_after_hit") == 0) {
			const aik_json *rb =
				need(ref_step, "body", "reference.steps");
			double g;
			double r;

			if (json_num_field(body, "weight", &g) &&
			    json_num_field(rb, "weight", &r))
				check_num("hit.weight", g, r, 1e-9);
			if (json_num_field(body, "importance", &g) &&
			    json_num_field(rb, "importance", &r))
				check_num("hit.importance", g, r, 1e-9);
			check_int("hit.hit_count",
				  need_int(body, "hit_count", "actual"),
				  need_int(rb, "hit_count", "reference"));
			check_int("hit.version",
				  need_int(body, "version", "actual"),
				  need_int(rb, "version", "reference"));
		}
		/* 每条 search 的首位分数（同分重排不影响最大值） */
		if (count > 0) {
			const aik_json *gres =
				need(body, "results", "actual");
			const aik_json *rres = aik_json_get(
				need(ref_step, "body", "reference.steps"),
				"results");
			double g;
			double r;

			if (json_num_field(at_idx(gres, 0, "actual.results"),
					   "score", &g) &&
			    rres && aik_json_count(rres) > 0 &&
			    json_num_field(aik_json_at(rres, 0), "score", &r))
				check_num("search.first_score", g, r, 1e-9);
		}
	}

	/* final_state：export + regions（read-only，重跑一次） */
	if (aik_engine_export(e, &final_export_body, err, sizeof(err)) != 0)
		die("final export: %s", err);
	if (aik_engine_regions(e, &final_regions_body, err, sizeof(err)) != 0)
		die("final regions: %s", err);
	final_state = jobj();
	{
		aik_json *ex = jobj();

		jput(ex, "status", jint(200));
		jput(ex, "body", final_export_body);
		jput(final_state, "export", ex);
	}
	{
		aik_json *rg = jobj();

		jput(rg, "status", jint(200));
		jput(rg, "body", final_regions_body);
		jput(final_state, "regions", rg);
	}

	/* Region 时间源：space 已注入引擎时钟，每个 Region 都等于冻结时钟 */
	{
		const aik_json *regs =
			need(final_regions_body, "regions", "final regions");
		size_t k;

		for (k = 0; k < aik_json_count(regs); k++) {
			const aik_json *r = aik_json_at(regs, k);
			double ca = 0.0;
			double lu = 0.0;
			char pathbuf[96];

			snprintf(pathbuf, sizeof(pathbuf),
				 "final_regions[%zu].created_at", k);
			if (!json_num_field(r, "created_at", &ca))
				die("final region %zu has no created_at", k);
			check_num(pathbuf, ca, g_now, 1e-9);
			snprintf(pathbuf, sizeof(pathbuf),
				 "final_regions[%zu].last_updated", k);
			if (!json_num_field(r, "last_updated", &lu))
				die("final region %zu has no last_updated", k);
			check_num(pathbuf, lu, g_now, 1e-9);
		}
	}

	/* id_maps */
	memory_map = jobj();
	{
		const aik_json *mems = need(final_export_body, "memories",
					    "final export");
		size_t k;

		for (k = 0; k < aik_json_count(mems); k++) {
			const aik_json *m = aik_json_at(mems, k);
			const char *mid = json_str_field(m, "id");
			const char *text = json_str_field(m, "text");

			if (!mid)
				die("final export memory %zu has no id", k);
			jput(memory_map, mid, jstr(text));
		}
	}
	region_map = jobj();
	{
		const aik_json *regs = need(final_regions_body, "regions",
					    "final regions");
		size_t k;

		for (k = 0; k < aik_json_count(regs); k++) {
			const aik_json *r = aik_json_at(regs, k);
			const char *rid = json_str_field(r, "id");

			if (!rid)
				die("final regions region %zu has no id", k);
			jput(region_map, rid,
			     aik_json__clone(need(r, "member_ids",
						  "final regions")));
		}
	}

	/* 交叉自检 */
	{
		const aik_json *ref_final =
			need(need(reference, "final_state", "reference"),
			     "export", "reference.final_state");
		const aik_json *ref_body =
			need(ref_final, "body", "reference.final_state.export");
		const aik_json *ref_mems =
			need(ref_body, "memories", "reference.final_state");
		const aik_json *ref_regions =
			need(need(need(reference, "final_state", "reference"),
				  "regions", "reference.final_state"),
			     "body", "reference.final_state.regions");
		const aik_json *got_mems =
			need(final_export_body, "memories", "final export");

		check_int("final.memories",
			  (long long)aik_json_count(got_mems),
			  (long long)aik_json_count(ref_mems));
		check_int("final.regions",
			  need_int(final_regions_body, "count",
				   "final regions"),
			  need_int(ref_regions, "count",
				   "reference.final_state.regions"));
		compare_final_stats(need(final_export_body, "stats",
					 "final export"),
				    need(ref_body, "stats",
					 "reference.final_state.export"));
	}

	/* 逐步 status 序列 */
	{
		char got[512];
		char exp[512];
		size_t off = 0;
		size_t k;

		got[0] = '\0';
		exp[0] = '\0';
		for (k = 0; k < n_steps; k++) {
			const aik_json *g = at_idx(steps_out, k, "actual.steps");
			const aik_json *r =
				at_idx(ref_steps, k, "reference.steps");
			int n1 = snprintf(got + off, sizeof(got) - off, "%s%lld",
					  k ? "," : "",
					  need_int(g, "status", "actual.steps"));
			long long rs = need_int(r, "status", "reference.steps");
			size_t off2 = strlen(exp);

			if (n1 > 0 && (size_t)n1 < sizeof(got) - off)
				off += (size_t)n1;
			snprintf(exp + off2, sizeof(exp) - off2, "%s%lld",
				 k ? "," : "", rs);
		}
		check_str("steps.status_sequence", got, exp);
	}

	/* 工件 */
	root = jobj();
	meta = jobj();
	jput(meta, "ref_commit",
	     jstr(need_str(ref_meta, "ref_commit", "reference.meta")));
	jput(meta, "frozen_now", jnum(need_num(ref_meta, "frozen_now",
					       "reference.meta")));
	jput(meta, "config", aik_json__clone(tmpl));
	jput(root, "meta", meta);
	jput(root, "seed_import", seed_rec);
	jput(root, "steps", steps_out);
	jput(root, "final_state", final_state);
	{
		aik_json *maps = jobj();

		jput(maps, "memory", memory_map);
		jput(maps, "region", region_map);
		jput(root, "id_maps", maps);
	}

	dump = getenv("AIK_ENGINE_DUMP");
	if (dump && *dump) {
		dump_path = strdup(dump);
	} else {
		dump_path = strdup("tests/engine.actual.json");
	}
	if (!dump_path)
		die("out of memory");
	write_json(dump_path, root);
	printf("engine.actual.json: %s\n", dump_path);
	free(dump_path);

	/* 附加契约（不进工件）：metadata ns 追加 + link_to 图边 + 错误码 */
	{
		aik_json *md = jobj();
		aik_memory *m;
		aik_json *stats2 = NULL;
		const aik_json *policy;

		jput(md, "k", jstr("v"));
		m = aik_engine_add(e, "ns 与图边契约", md, NULL, 0, 0.5, "user",
				   "m_000000000003", "reference", "bench", NULL,
				   err, sizeof(err));
		aik_json_free(md);
		if (!m)
			die("ns/link add failed: %s", err);
		check_str("add.ns", aik_json_str(aik_json_get(m->metadata, "ns")),
			  "bench");
		check_int("add.ns.appended",
			  (long long)aik_json_count(m->metadata), 2);
		if (aik_engine_stats(e, &stats2, err, sizeof(err)) != 0)
			die("stats after link: %s", err);
		check_int("add.link_edge",
			  need_int(stats2, "graph_edges", "stats"), 1);
		policy = need(stats2, "policy", "stats");
		check_int("stats.policy.decay",
			  aik_json_bool(aik_json_get(policy, "decay_enabled")),
			  1);
		aik_json_free(stats2);
	}
	check_int("reinforce.missing",
		  aik_engine_reinforce(e, "m_ffffffffffff", NULL, err,
				       sizeof(err)), 1);
	check_int("archive.missing",
		  aik_engine_archive(e, "m_ffffffffffff"), 1);
	check_int("restore.missing",
		  aik_engine_restore(e, "m_ffffffffffff"), 1);

	aik_json_free(root);
	aik_json_free(reference);
	aik_json_free(cases);
	aik_engine_free(e);	/* 同时释放 take_ownership 的 cfg */
	free(tmpdir);
	free(cases_path);
	free(ref_path);
}

/* ------------------------------------------------------------------ */
/* 段 2：老数据原地读                                                 */
/* ------------------------------------------------------------------ */
static aik_config *build_min_config(const char *tmpdir, char *err,
				    size_t errlen)
{
	aik_json *raw = jobj();
	aik_json *storage = jobj();
	char *path = path_join(tmpdir, "data/engine.json");
	aik_config *cfg;

	if (!path)
		die("out of memory");
	jput(storage, "autosave", jbool(0));
	jput(storage, "path", jstr(path));
	free(path);
	jput(raw, "storage", storage);
	cfg = aik_config_from_json(raw, err, errlen);
	aik_json_free(raw);
	return cfg;
}

static void run_legacy_load(void)
{
	static const int sample_idx[3] = {0, 274, 548};
	const char *vdir = vectors_dir();
	char err[512];
	char *snap_src;
	char *npz_src;
	char *canon_path;
	char *meta_path;
	char *expected_path;
	char *tmpdir;
	char *snap_tmp;
	aik_json *canon;
	aik_json *meta;
	aik_json *expected;
	const aik_json *canon_mems;
	const char *embedding_file;
	char *npz_tmp;
	aik_npz *z;
	unsigned char *ids_buf = NULL;
	unsigned char *mat_buf = NULL;
	size_t ids_len = 0;
	size_t mat_len = 0;
	aik_npy ids_npy;
	aik_npy mat_npy;
	char **vec_ids = NULL;
	double *matrix = NULL;
	size_t n_ids;
	int dim;
	aik_engine *e;
	aik_config *cfg;
	size_t i;
	aik_json *stats;
	const aik_json *mstats;
	const aik_json *rstats;
	long long total = 0;
	long long active = 0;
	long long archived = 0;
	long long summarized = 0;
	long long total_hits = 0;
	double sum_w = 0.0;
	double sum_i = 0.0;
	long long sum_hc = 0;
	double min_created = 0.0;
	int have = 0;
	double frozen;

	snap_src = path_join(vdir, "storage/engine.json.gz");
	npz_src = path_join(vdir, "storage/engine.embeddings.npz");
	canon_path = path_join(vdir, "storage/snapshot.canonical.json");
	meta_path = path_join(vdir, "storage/snapshot.meta.json");
	expected_path = path_join(vdir, "storage/space_load.expected.json");
	if (!snap_src || !npz_src || !canon_path || !meta_path || !expected_path)
		die("out of memory");
	canon = load_json(canon_path);
	meta = load_json(meta_path);
	expected = load_json(expected_path);
	if (!canon || !meta || !expected)
		die("cannot load storage fixtures");

	canon_mems = need(canon, "memories", "snapshot.canonical");
	embedding_file = need_str(need(meta, "snapshot", "snapshot.meta"),
				  "embedding_file", "snapshot.meta");
	frozen = need_num(meta, "frozen_now", "snapshot.meta");

	tmpdir = make_tmpdir();
	snap_tmp = path_join(tmpdir, "engine.json.gz");
	npz_tmp = path_join(tmpdir, embedding_file);
	if (!snap_tmp || !npz_tmp)
		die("out of memory");
	if (copy_file(snap_src, snap_tmp) != 0)
		die("cannot copy %s", snap_src);
	if (copy_file(npz_src, npz_tmp) != 0)
		die("cannot copy %s", npz_src);

	/* NPZ 原始表（抽样比对用） */
	z = aik_npz_open(npz_tmp, err, sizeof(err));
	if (!z)
		die("aik_npz_open: %s", err);
	if (aik_npz_read(z, "ids", &ids_buf, &ids_len, err, sizeof(err)) != 0 ||
	    aik_npz_read(z, "matrix", &mat_buf, &mat_len, err, sizeof(err)) !=
		    0)
		die("npz read: %s", err);
	if (aik_npy_parse(ids_buf, ids_len, &ids_npy, err, sizeof(err)) != 0 ||
	    aik_npy_parse(mat_buf, mat_len, &mat_npy, err, sizeof(err)) != 0)
		die("npy parse: %s", err);
	n_ids = aik_npy_nelem(&ids_npy);
	dim = (int)mat_npy.shape[1];
	vec_ids = calloc(n_ids ? n_ids : 1, sizeof(*vec_ids));
	matrix = malloc((n_ids ? n_ids : 1) * (size_t)dim * sizeof(double));
	if (!vec_ids || !matrix)
		die("out of memory (npz)");
	for (i = 0; i < n_ids * (size_t)dim; i++) {
		if (aik_npy_get_f8(&mat_npy, i, &matrix[i]) != 0)
			die("npy matrix element %zu", i);
	}
	for (i = 0; i < n_ids; i++) {
		char name[128];

		if (aik_npy_get_ustr(&ids_npy, i, name, sizeof(name)) < 0)
			die("npy ids element %zu", i);
		vec_ids[i] = strdup(name);
		if (!vec_ids[i])
			die("out of memory");
	}
	aik_npz_close(z);

	g_now = frozen;
	cfg = build_min_config(tmpdir, err, sizeof(err));
	if (!cfg)
		die("min config: %s", err);
	e = aik_engine_new(cfg, 1, clock_now, NULL, id_gen, NULL, err,
			   sizeof(err));
	if (!e)
		die("aik_engine_new: %s", err);
	if (aik_engine_load(e, snap_tmp, err, sizeof(err)) != 0)
		die("aik_engine_load: %s", err);

	check_int("load.memories", (long long)aik_engine_memory_count(e),
		  (long long)aik_json_count(canon_mems));
	for (i = 0; i < aik_engine_memory_count(e); i++) {
		const aik_memory *m = aik_engine_memory_at(e, i);

		if (m->archived)
			archived++;
		else
			active++;
	}
	check_int("load.total", (long long)aik_engine_memory_count(e), 549);
	check_int("load.active", active, 539);
	check_int("load.archived", archived, 10);

	if (aik_engine_stats(e, &stats, err, sizeof(err)) != 0)
		die("stats: %s", err);
	mstats = need(stats, "memories", "stats");
	rstats = need(stats, "regions", "stats");

	check_int("load.regions", need_int(rstats, "count", "stats.regions"),
		  (long long)aik_json_count(need(canon, "regions",
						 "snapshot.canonical")));
	check_int("load.regions.expected",
		  need_int(rstats, "count", "stats.regions"), 226);
	check_int("load.graph_edges", need_int(stats, "graph_edges", "stats"),
		  (long long)aik_json_count(need(canon, "memory_edges",
						 "snapshot.canonical")));
	check_int("load.graph_edges.expected",
		  need_int(stats, "graph_edges", "stats"), 0);
	check_int("load.counters.splits",
		  need_int(stats, "splits", "stats"),
		  need_int(need(canon, "counters", "snapshot.canonical"),
			   "splits", "snapshot.counters"));
	check_int("load.counters.merges", need_int(stats, "merges", "stats"),
		  need_int(need(canon, "counters", "snapshot.canonical"),
			   "merges", "snapshot.counters"));
	check_int("load.region_edges",
		  need_int(rstats, "edge_count", "stats.regions"),
		  (long long)aik_json_count(need(expected, "region_edges",
						 "space_load.expected")));
	{
		const char *want = aik_json_str(aik_json_get(
			aik_json_get(need(canon, "config", "snapshot.canonical"),
				     "embedding"), "model"));
		const char *got = json_str_field(stats, "provider");

		if (want && got)
			check_str("load.provider.model", got, want);
	}

	/* 期望的 memory stats：直接从 canonical 重算（不依赖 Python 运行） */
	active = 0;
	archived = 0;
	for (i = 0; i < aik_json_count(canon_mems); i++) {
		const aik_json *m = aik_json_at(canon_mems, i);
		const aik_json *summary = aik_json_get(m, "summary");
		long long hc = 0;
		double created;

		total++;
		if (json_int_field(m, "hit_count", &hc))
			total_hits += hc;
		if (aik_json_typeof(summary) == AIK_JSON_STR)
			summarized++;
		if (aik_json_bool(aik_json_get(m, "archived"))) {
			archived++;
			continue;
		}
		active++;
		{
			double w = 0.0;
			double imp = 0.0;

			if (json_num_field(m, "weight", &w))
				sum_w += w;
			if (json_num_field(m, "importance", &imp))
				sum_i += imp;
			if (json_int_field(m, "hit_count", &hc))
				sum_hc += hc;
			if (json_num_field(m, "created_at", &created)) {
				if (!have || created < min_created) {
					min_created = created;
					have = 1;
				}
			}
		}
	}
	check_int("load.stats.total", need_int(mstats, "total", "stats"), total);
	check_int("load.stats.active", need_int(mstats, "active", "stats"),
		  active);
	check_int("load.stats.archived", need_int(mstats, "archived", "stats"),
		  archived);
	check_int("load.stats.summarized",
		  need_int(mstats, "summarized", "stats"), summarized);
	check_int("load.stats.total_hits",
		  need_int(mstats, "total_hits", "stats"), total_hits);
	{
		double g;

		if (json_num_field(mstats, "avg_weight", &g))
			check_num("load.stats.avg_weight", g,
				  sum_w / (double)active, 1e-9);
		if (json_num_field(mstats, "avg_importance", &g))
			check_num("load.stats.avg_importance", g,
				  sum_i / (double)active, 1e-9);
		if (json_num_field(mstats, "avg_hit_count", &g))
			check_num("load.stats.avg_hit_count", g,
				  (double)sum_hc / (double)active, 1e-9);
		if (json_num_field(mstats, "oldest_age_days", &g))
			check_num("load.stats.oldest_age_days", g,
				  (frozen - min_created) / 86400.0, 1e-9);
	}

	/* 抽样：text + embedding 与快照逐位一致 */
	{
		size_t k;

		for (k = 0; k < 3; k++) {
			const aik_json *cm =
				at_idx(canon_mems, (size_t)sample_idx[k],
				       "snapshot.canonical.memories");
			const char *mid = json_str_field(cm, "id");
			const char *text = json_str_field(cm, "text");
			aik_memory *m = mid ? aik_engine_get(e, mid) : NULL;
			size_t j;
			int row = -1;
			char pathbuf[64];

			if (!mid)
				die("canonical memory %d has no id",
				    sample_idx[k]);
			if (!m)
				die("loaded engine is missing '%s'", mid);
			check_str("load.sample.text", m->text, text);
			for (j = 0; j < n_ids; j++) {
				if (strcmp(vec_ids[j], mid) == 0) {
					row = (int)j;
					break;
				}
			}
			check_int("load.sample.npz_row", row >= 0 ? 1 : 0, 1);
			if (row < 0)
				continue;
			check_int("load.sample.dim", m->dim, dim);
			snprintf(pathbuf, sizeof(pathbuf), "load.sample[%zu].emb",
				 k);
			if (m->dim != dim || !m->embedding)
				continue;
			{
				size_t bad = 0;

				for (j = 0; j < (size_t)dim; j++) {
					if (memcmp(&m->embedding[j],
						   &matrix[(size_t)row *
								(size_t)dim + j],
						   sizeof(double)) != 0)
						bad++;
				}
				check_int(pathbuf, (long long)bad, 0);
			}
		}
	}

	/* save 必须明确失败（T4c） */
	{
		char *out_path = path_join(tmpdir, "should-not-exist.json.gz");

		if (!out_path)
			die("out of memory");
		check_int("load.save_disabled",
			  aik_engine_save(e, out_path, err, sizeof(err)), -1);
		check_int("load.save_wrote_nothing",
			  access(out_path, F_OK) == 0 ? 1 : 0, 0);
		free(out_path);

	/* archive / restore 往返（最后做，不影响上面的 stats 断言） */
	{
		const char *mid = "m_000000000001";
		aik_memory *m = aik_engine_get(e, mid);

		check_int("load.archive.present", m != NULL ? 1 : 0, 1);
		if (m) {
			check_int("load.archive.rc",
				  aik_engine_archive(e, mid), 0);
			check_int("load.archive.flag", m->archived, 1);
			check_int("load.archive.region_null",
				  m->region_id == NULL ? 1 : 0, 1);
			check_int("load.archive.reinforce",
				  aik_engine_reinforce(e, mid, NULL, err,
						       sizeof(err)), 1);
			check_int("load.archive.idempotent",
				  aik_engine_archive(e, mid), 1);
			check_int("load.restore.rc",
				  aik_engine_restore(e, mid), 0);
			check_int("load.restore.flag", m->archived, 0);
			check_int("load.restore.region",
				  m->region_id != NULL ? 1 : 0, 1);
			check_int("load.restore.idempotent",
				  aik_engine_restore(e, mid), 1);
		}
	}
	}

	aik_json_free(stats);
	aik_engine_free(e);
	aik_json_free(expected);
	aik_json_free(meta);
	aik_json_free(canon);
	for (i = 0; i < n_ids; i++)
		free(vec_ids[i]);
	free(vec_ids);
	free(matrix);
	free(ids_buf);
	free(mat_buf);
	free(npz_tmp);
	free(snap_tmp);
	free(tmpdir);
	free(expected_path);
	free(meta_path);
	free(canon_path);
	free(npz_src);
	free(snap_src);
}

int main(void)
{
	run_api_case();
	run_legacy_load();
	printf("SUMMARY engine checks=%zu mismatches=%zu\n", checks,
	       mismatches);
	return mismatches ? 1 : 0;
}
