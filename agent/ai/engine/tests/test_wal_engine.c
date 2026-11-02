/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_wal_engine.c - T4e-D：Engine WAL 接线自测
 *
 * 覆盖：
 *   1) 逐字节对齐参考录制（parity）：同一脚本化序列（add ×10、update
 *      importance、update text、archive、restore、reinforce、link(cause)、
 *      delete、consolidate、compress）在 C 引擎上重放，自己的 .wal 归一化
 *      （id → "MIDn"/"RIDn"，seq 不归一化）后与
 *      $AIK_PARITY_VECTORS/wal/wal_engine.reference.normalized.txt 逐字节
 *      相等。向量由 parity/rec/record_wal_engine.py 用冻结参考树录制。
 *   2) 崩溃恢复：A add/save → 再 add/update/link（不 save）→ B load 同一
 *      快照 + WAL，记忆全字段/图边/计数器/Region 成员一致；恢复前 WAL
 *      非空（未被 A 截断），恢复后 checkpoint 截断。
 *   3) 幂等：同一快照再 load 一次 →0 条重放，状态一致。
 *   4) checkpoint：checkpoint_every=3 时写满 3 条自动 save，快照
 *      wal_sequence=3、WAL 变空、再次 load 正常。
 *   5) 失败保留日志：坏行/未知 op → load 失败且 err 含
 *      "WAL replay failed at record N; log retained"，WAL 字节不变。
 *   6) 诚实限制：backend=sqlite / sync_mode=grouped → new 拒绝（"未接线"）；
 *      默认 WAL 路径 = storage.path + ".wal"；persistence.enabled=false
 *      时快照 wal_sequence=0 且不产生 .wal 文件。
 *
 * 末行 "test_wal_engine: N checks, M failed"；有失配退出码非 0。
 */
#define _POSIX_C_SOURCE 200809L

#include "engine/engine.h"
#include "smeconfig/config.h"
#include "store/store_json.h"
#include "store/store_snapshot.h"
#include "store/store_wal.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int g_checked;
static int g_failed;

#define CHECK(cond) do {						\
	g_checked++;							\
	if (!(cond)) {							\
		g_failed++;						\
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,	\
			#cond);						\
	}								\
} while (0)

static void note(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */
static double g_now;

static double fixed_now(void *ud)
{
	(void)ud;
	return g_now;
}

static int g_id_seq;

/* 与参考 new_id 同形的确定 id（m_/r_ + 12 位小写十六进制） */
static int seq_id(void *ud, const char *prefix, char out[16])
{
	(void)ud;
	g_id_seq++;
	snprintf(out, 16, "%s_%012x", prefix && prefix[0] ? prefix : "m",
		 g_id_seq);
	return 0;
}

static void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);

	if (!p) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return p;
}

static char *xstrdup(const char *s)
{
	char *p = strdup(s ? s : "");

	if (!p) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return p;
}

static char *path_join(const char *dir, const char *name)
{
	size_t n = strlen(dir) + strlen(name) + 2;
	char *p = xmalloc(n);

	snprintf(p, n, "%s/%s", dir, name);
	return p;
}

static char *make_tmpdir(void)
{
	const char *base = getenv("TMPDIR");
	char templ[512];

	if (!base || !*base)
		base = "/tmp";
	snprintf(templ, sizeof(templ), "%s/aik-wal-XXXXXX", base);
	if (!mkdtemp(templ)) {
		fprintf(stderr, "mkdtemp(%s): %s\n", templ, strerror(errno));
		exit(2);
	}
	return xstrdup(templ);
}

static int read_file(const char *path, unsigned char **out, size_t *out_len)
{
	FILE *fh = fopen(path, "rb");
	long sz;
	unsigned char *buf;

	*out = NULL;
	*out_len = 0;
	if (!fh)
		return -1;
	if (fseek(fh, 0, SEEK_END) != 0 || (sz = ftell(fh)) < 0 ||
	    fseek(fh, 0, SEEK_SET) != 0) {
		fclose(fh);
		return -1;
	}
	buf = xmalloc((size_t)sz + 1);
	if (sz > 0 && fread(buf, 1, (size_t)sz, fh) != (size_t)sz) {
		free(buf);
		fclose(fh);
		return -1;
	}
	fclose(fh);
	buf[sz] = 0;
	*out = buf;
	*out_len = (size_t)sz;
	return 0;
}

static int write_file(const char *path, const void *data, size_t len)
{
	FILE *fh = fopen(path, "wb");

	if (!fh)
		return -1;
	if (len && fwrite(data, 1, len, fh) != len) {
		fclose(fh);
		return -1;
	}
	return fclose(fh);
}

static int file_size(const char *path, long long *out)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return -1;
	*out = (long long)st.st_size;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 配置                                                                */
/* ------------------------------------------------------------------ */
static aik_json *jobj(void)
{
	aik_json *o = aik_json_new_obj();

	if (!o) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return o;
}

static void jput(aik_json *obj, const char *key, aik_json *v)
{
	if (!v || aik_json_obj_put(obj, key, v) != 0) {
		fprintf(stderr, "out of memory (json %s)\n", key);
		exit(2);
	}
}

struct cfg_opts {
	int wal_enabled;
	const char *sync_mode;
	const char *backend;
	const char *wal_path;	/* NULL/"" → <storage.path>.wal */
	int autosave;
	long long checkpoint_every;
};

static aik_config *make_cfg(const char *tmpdir, const struct cfg_opts *o,
			    char *err, size_t errlen)
{
	aik_json *raw = jobj();
	aik_json *reg = jobj();
	aik_json *stor = jobj();
	aik_json *pers = jobj();
	char *path = path_join(tmpdir, "data/engine.json");
	aik_config *cfg;

	jput(raw, "embedding", jobj());
	jput(raw, "region", reg);
	jput(reg, "auto_evolve", aik_json_new_bool(0));
	jput(stor, "path", aik_json_new_str(path));
	jput(stor, "autosave", aik_json_new_bool(o->autosave));
	jput(stor, "autosave_interval", aik_json_new_int(100));
	jput(stor, "compress", aik_json_new_bool(0));
	jput(stor, "backend", aik_json_new_str(o->backend ? o->backend : "json"));
	jput(pers, "enabled", aik_json_new_bool(o->wal_enabled));
	jput(pers, "checkpoint_every", aik_json_new_int(o->checkpoint_every));
	jput(pers, "sync_mode",
	     aik_json_new_str(o->sync_mode ? o->sync_mode : "fsync"));
	if (o->wal_path && o->wal_path[0])
		jput(pers, "wal_path", aik_json_new_str(o->wal_path));
	jput(raw, "storage", stor);
	jput(raw, "persistence", pers);
	cfg = aik_config_from_json(raw, err, errlen);
	aik_json_free(raw);
	free(path);
	return cfg;
}

static aik_engine *new_engine(aik_config *cfg, char *err, size_t errlen)
{
	return aik_engine_new(cfg, 1, fixed_now, NULL, seq_id, NULL, err,
			      errlen);
}

/* ------------------------------------------------------------------ */
/* WAL 归一化（与 record_wal_engine.py 的 normalize_wal 一致）         */
/* ------------------------------------------------------------------ */
struct idtab {
	char tok[80][17];
	char pre[80];
	int n;
};

static int idtab_lookup(struct idtab *t, const char *tok)
{
	int i;

	for (i = 0; i < t->n; i++)
		if (memcmp(t->tok[i], tok, 16) == 0)
			return i;
	if (t->n >= (int)(sizeof(t->tok) / sizeof(t->tok[0])))
		return t->n - 1;
	memcpy(t->tok[t->n], tok, 16);
	t->tok[t->n][16] = '\0';
	t->pre[t->n] = tok[1];
	return t->n++;
}

static int is_hex12(const unsigned char *p)
{
	int i;

	for (i = 0; i < 12; i++) {
		unsigned char c = p[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			return 0;
	}
	return 1;
}

/*
 * 把 "m_<12hex>" / "r_<12hex>"（含引号，共 16 字节）替换为
 * "MIDk" / "RIDk"（k = 该前缀下首次出现序）。其余字节原样保留。
 */
static char *normalize_wal(const unsigned char *raw, size_t len,
			   size_t *out_len)
{
	struct idtab mt;
	struct idtab rt;
	char *out;
	size_t i = 0, o = 0;

	memset(&mt, 0, sizeof(mt));
	memset(&rt, 0, sizeof(rt));
	out = xmalloc(len * 2 + 64);

	while (i < len) {
		if (raw[i] == '"' && i + 15 < len &&
		    (raw[i + 1] == 'm' || raw[i + 1] == 'r') &&
		    raw[i + 2] == '_' && is_hex12(raw + i + 3) &&
		    raw[i + 15] == '"') {
			struct idtab *t = raw[i + 1] == 'm' ? &mt : &rt;
			char tok[17];
			int idx;
			char pre[8];

			memcpy(tok, raw + i, 16);
			tok[16] = '\0';
			idx = idtab_lookup(t, tok);
			snprintf(pre, sizeof(pre), "%cID%d",
				 raw[i + 1] == 'm' ? 'M' : 'R', idx);
			out[o++] = '"';
			memcpy(out + o, pre, strlen(pre));
			o += strlen(pre);
			out[o++] = '"';
			i += 16;
			continue;
		}
		out[o++] = (char)raw[i++];
	}
	out[o] = '\0';
	*out_len = o;
	return out;
}

/* ------------------------------------------------------------------ */
/* 脚本化序列（与 parity/rec/record_wal_engine.py 完全一致）           */
/* ------------------------------------------------------------------ */
#define WAL_T0 1775000000.0
#define WAL_T1 (WAL_T0 + 4 * 86400.0)

static const char *const SCENARIO_TEXTS[10] = {
	"记忆系统日志恢复流程说明 第1条",
	"记忆系统日志恢复流程说明 第2条",
	"记忆系统日志恢复流程说明 第3条",
	"记忆系统日志恢复流程说明 第4条",
	"记忆系统日志恢复流程说明 第5条",
	"记忆系统日志恢复流程说明 第6条",
	"记忆系统日志恢复流程说明 第7条",
	"记忆系统日志恢复流程说明 第8条",
	"记忆系统日志恢复流程说明 第9条",
	"记忆系统日志恢复流程说明 第10条",
};
static const double SCENARIO_IMPORTANCE[10] = {
	0.90, 0.80, 0.75, 0.70, 0.65, 0.60, 0.55, 0.50, 0.45, 0.40,
};

static int run_scenario(aik_engine *e, int *consolidated, int *compressed)
{
	const char *tags[1] = { "wal" };
	aik_json *meta = jobj();
	aik_json *patch = NULL;
	aik_json *created = NULL;
	char err[512];
	char *ids[10];
	int i;
	int rc = 0;

	memset(ids, 0, sizeof(ids));
	jput(meta, "batch", aik_json_new_str("alpha"));
	g_now = WAL_T0;
	for (i = 0; i < 10; i++) {
		aik_memory *m = aik_engine_add(e, SCENARIO_TEXTS[i], meta, tags,
					       1, SCENARIO_IMPORTANCE[i], NULL,
					       NULL, NULL, NULL, NULL, err, sizeof(err));

		if (!m) {
			note("scenario add %d failed: %s\n", i, err);
			rc = -1;
			goto out;
		}
		ids[i] = xstrdup(m->id);
	}
	/* update importance（patches） */
	patch = jobj();
	jput(patch, "importance", aik_json_new_num(0.95));
	if (aik_engine_update(e, ids[0], patch, err, sizeof(err)) != 0) {
		note("scenario update importance failed: %s\n", err);
		rc = -1;
		goto out;
	}
	aik_json_free(patch);
	/* update text（memories，含向量） */
	patch = jobj();
	jput(patch, "text",
	     aik_json_new_str("记忆系统日志恢复流程说明 第2条 已修订"));
	if (aik_engine_update(e, ids[1], patch, err, sizeof(err)) != 0) {
		note("scenario update text failed: %s\n", err);
		rc = -1;
		goto out;
	}
	aik_json_free(patch);
	patch = NULL;
	if (aik_engine_archive(e, ids[2]) != 0) {
		note("scenario archive failed\n");
		rc = -1;
		goto out;
	}
	if (aik_engine_restore(e, ids[2]) != 0) {
		note("scenario restore failed\n");
		rc = -1;
		goto out;
	}
	if (aik_engine_reinforce(e, ids[0], NULL, err, sizeof(err)) != 0) {
		note("scenario reinforce failed: %s\n", err);
		rc = -1;
		goto out;
	}
	if (aik_engine_link(e, ids[3], ids[4], "cause", 0.5, "因果关系", err,
			    sizeof(err)) != 0) {
		note("scenario link failed: %s\n", err);
		rc = -1;
		goto out;
	}
	g_now = WAL_T1;
	if (aik_engine_delete(e, ids[9], err, sizeof(err)) != 0) {
		note("scenario delete failed: %s\n", err);
		rc = -1;
		goto out;
	}
	if (aik_engine_consolidate(e, &created, err, sizeof(err)) != 0) {
		note("scenario consolidate failed: %s\n", err);
		rc = -1;
		goto out;
	}
	*consolidated = created ? (int)aik_json_count(created) : 0;
	aik_json_free(created);
	created = NULL;
	if (aik_engine_compress(e, &created, err, sizeof(err)) != 0) {
		note("scenario compress failed: %s\n", err);
		rc = -1;
		goto out;
	}
	*compressed = created ? (int)aik_json_count(created) : 0;

out:
	aik_json_free(patch);
	aik_json_free(created);
	aik_json_free(meta);
	for (i = 0; i < 10; i++)
		free(ids[i]);
	return rc;
}

/* ------------------------------------------------------------------ */
/* 1) 逐字节 parity                                                    */
/* ------------------------------------------------------------------ */
static const char *parity_dir(void)
{
	const char *d = getenv("AIK_PARITY_VECTORS");
	static char buf[1024];

	if (d && *d)
		return d;
	snprintf(buf, sizeof(buf), "%s/aikernel-longterm/parity/vectors",
		 getenv("HOME") ? getenv("HOME") : ".");
	return buf;
}

static char *path_in(const char *dir, const char *rel)
{
	size_t n = strlen(dir) + strlen(rel) + 2;
	char *p = xmalloc(n);

	snprintf(p, n, "%s/%s", dir, rel);
	return p;
}

static void test_parity(void)
{
	char *tmp = make_tmpdir();
	struct cfg_opts o;
	char err[512];
	char *snap = path_join(tmp, "data/engine.json");
	char *wal = path_join(tmp, "data/engine.json.wal");
	char *vec_path = path_in(parity_dir(),
				 "wal/wal_engine.reference.normalized.txt");
	unsigned char *raw = NULL, *vec = NULL;
	size_t raw_len = 0, vec_len = 0, norm_len = 0;
	char *norm = NULL;
	aik_config *cfg;
	aik_engine *e;
	int cons = -1, comp = -1;
	int rc;

	memset(&o, 0, sizeof(o));
	o.wal_enabled = 1;
	o.sync_mode = "fsync";
	o.backend = "json";
	o.wal_path = wal;
	o.autosave = 1;
	o.checkpoint_every = 1000;
	cfg = make_cfg(tmp, &o, err, sizeof(err));
	CHECK(cfg != NULL);
	if (!cfg) {
		note("parity cfg: %s\n", err);
		goto out;
	}
	e = new_engine(cfg, err, sizeof(err));
	CHECK(e != NULL);
	if (!e) {
		note("parity engine: %s\n", err);
		goto out;
	}
	rc = run_scenario(e, &cons, &comp);
	CHECK(rc == 0);
	CHECK(cons == 1);
	CHECK(comp == 1);
	aik_engine_free(e);

	rc = read_file(wal, &raw, &raw_len);
	CHECK(rc == 0);
	CHECK(raw_len > 0);
	rc = read_file(vec_path, &vec, &vec_len);
	CHECK(rc == 0);
	if (rc != 0) {
		note("missing parity vector: %s\n", vec_path);
		goto out;
	}
	norm = normalize_wal(raw, raw_len, &norm_len);
	CHECK(norm_len == vec_len);
	if (norm_len == vec_len && memcmp(norm, vec, vec_len) != 0) {
		size_t i, line = 1, first = 0;

		for (i = 0; i < vec_len; i++) {
			if (norm[i] == '\n')
				line++;
			if (norm[i] != vec[i]) {
				first = i;
				break;
			}
		}
		note("parity mismatch at byte %zu (line %zu):\n", first, line);
		{
			size_t s = first > 160 ? first - 160 : 0;
			size_t n1 = norm_len - s > 400 ? 400 : norm_len - s;

			note("  C   : %.*s\n", (int)n1, norm + s);
			note("  REF : %.*s\n",
			     (int)(vec_len - s > 400 ? 400 : vec_len - s),
			     vec + s);
		}
	}
	CHECK(memcmp(norm, vec, vec_len) == 0);
	/* 序列本身的可观测形状（与录制 meta 对齐） */
	{
		size_t lines = 0;
		const char *p = (const char *)vec;

		while (p && *p) {
			const char *nl = strchr(p, '\n');

			if (!nl)
				break;
			lines++;
			p = nl + 1;
		}
		CHECK(lines == 19);
	}
	note("parity: wal=%zu bytes normalized=%zu ", raw_len, norm_len);
	note("vector=%zu bytes\n", vec_len);

out:
	free(norm);
	free(raw);
	free(vec);
	free(snap);
	free(wal);
	free(vec_path);
	free(tmp);
}

/* ------------------------------------------------------------------ */
/* 状态比较：记忆全字段 / 图 / 计数器 / Region 成员                    */
/* ------------------------------------------------------------------ */
static int json_dump_eq(const aik_json *a, const aik_json *b)
{
	char *sa = NULL, *sb = NULL;
	size_t la = 0, lb = 0;
	int same;

	if (aik_json_dump(a, &sa, &la) != 0 ||
	    aik_json_dump(b, &sb, &lb) != 0) {
		free(sa);
		free(sb);
		return 0;
	}
	same = la == lb && memcmp(sa, sb, la) == 0;
	free(sa);
	free(sb);
	return same;
}

static int json_long(const aik_json *obj, const char *key, long long *out)
{
	const aik_json *v = aik_json_get(obj, key);

	if (aik_json_typeof(v) == AIK_JSON_INT) {
		*out = aik_json_int(v);
		return 0;
	}
	return -1;
}

/* 每个 Region 的成员 id 排序后拼成一个签名；整个签名字典序排序 */
static int region_signatures(aik_engine *e, char ***out, size_t *n_out)
{
	aik_json *regions = NULL;
	char err[256];
	char **sigs = NULL;
	size_t n = 0;
	size_t i;
	int rc = -1;

	*out = NULL;
	*n_out = 0;
	if (aik_engine_regions(e, &regions, err, sizeof(err)) != 0)
		return -1;
	{
		const aik_json *arr = aik_json_get(regions, "regions");
		size_t nr = aik_json_typeof(arr) == AIK_JSON_ARR
				    ? aik_json_count(arr)
				    : 0;

		sigs = xmalloc((nr ? nr : 1) * sizeof(*sigs));
		for (i = 0; i < nr; i++) {
			const aik_json *r = aik_json_at(arr, i);
			const aik_json *mids = aik_json_get(r, "member_ids");
			size_t nm = aik_json_typeof(mids) == AIK_JSON_ARR
					    ? aik_json_count(mids)
					    : 0;
			char **ids = xmalloc((nm ? nm : 1) * sizeof(*ids));
			size_t j, k;
			size_t len = 1;
			char *sig, *p;

			for (j = 0; j < nm; j++)
				ids[j] = (char *)aik_json_str(
					aik_json_at(mids, j));
			for (j = 0; j + 1 < nm; j++)
				for (k = j + 1; k < nm; k++)
					if (strcmp(ids[j], ids[k]) > 0) {
						char *t = ids[j];

						ids[j] = ids[k];
						ids[k] = t;
					}
			for (j = 0; j < nm; j++)
				len += strlen(ids[j]) + 1;
			sig = xmalloc(len);
			p = sig;
			for (j = 0; j < nm; j++) {
				size_t l = strlen(ids[j]);

				memcpy(p, ids[j], l);
				p += l;
				*p++ = '|';
			}
			*p = '\0';
			sigs[n++] = sig;
			free(ids);
		}
		for (i = 0; i + 1 < n; i++) {
			size_t k;

			for (k = i + 1; k < n; k++)
				if (strcmp(sigs[i], sigs[k]) > 0) {
					char *t = sigs[i];

					sigs[i] = sigs[k];
					sigs[k] = t;
				}
		}
	}
	*out = sigs;
	*n_out = n;
	rc = 0;
	aik_json_free(regions);
	return rc;
}

/* A/B 两引擎的记忆（按 id 对齐）逐字段比较；返回 0 = 一致 */
static int compare_memories(aik_engine *a, aik_engine *b)
{
	size_t i;
	int bad = 0;

	if (aik_engine_memory_count(a) != aik_engine_memory_count(b))
		return -1;
	for (i = 0; i < aik_engine_memory_count(a); i++) {
		aik_memory *ma = aik_engine_memory_at(a, i);
		aik_memory *mb = ma ? aik_engine_get(b, ma->id) : NULL;

		if (!ma || !mb)
			return -1;
		if (strcmp(ma->text, mb->text) != 0 ||
		    ma->created_at != mb->created_at ||
		    ma->last_hit != mb->last_hit ||
		    ma->hit_count != mb->hit_count ||
		    ma->weight != mb->weight ||
		    ma->importance != mb->importance ||
		    ma->freshness != mb->freshness ||
		    ma->decay_factor != mb->decay_factor ||
		    ma->version != mb->version || ma->archived != mb->archived ||
		    !json_dump_eq(ma->metadata, mb->metadata) ||
		    (ma->summary ? strcmp(ma->summary, mb->summary) : 0) != 0 ||
		    (ma->parent_id ? strcmp(ma->parent_id, mb->parent_id) : 0) !=
			    0) {
			note("memory %s differs: text=%d created=%d last_hit=%d "
			     "hit=%d weight=%d imp=%d fresh=%d decay=%d ver=%d "
			     "arch=%d meta=%d sum=%d parent=%d\n",
			     ma->id, strcmp(ma->text, mb->text),
			     ma->created_at == mb->created_at,
			     ma->last_hit == mb->last_hit,
			     ma->hit_count == mb->hit_count,
			     ma->weight == mb->weight,
			     ma->importance == mb->importance,
			     ma->freshness == mb->freshness,
			     ma->decay_factor == mb->decay_factor,
			     ma->version == mb->version,
			     ma->archived == mb->archived,
			     json_dump_eq(ma->metadata, mb->metadata),
			     (ma->summary ? strcmp(ma->summary, mb->summary) : 0) ==
				     0,
			     (ma->parent_id
				      ? strcmp(ma->parent_id, mb->parent_id)
				      : 0) == 0);
			bad++;
		}
		{
			aik_json *ja = aik_memory_to_json(ma, 0);
			aik_json *jb = aik_memory_to_json(mb, 0);
			/*
			 * Region id 是易失标识：参考 replay 的 _register 也会给
			 * 重新插入的记忆分配新 Region（uuid4）。成员关系由
			 * region_signatures() 单独比较，这里只比其余 18 个字段。
			 */
			aik_json *null_a = aik_json_new_null();
			aik_json *null_b = aik_json_new_null();

			if (!null_a || aik_json_obj_set(ja, "region_id", null_a) != 0) {
				aik_json_free(null_a);
				bad++;
			}
			if (!null_b || aik_json_obj_set(jb, "region_id", null_b) != 0) {
				aik_json_free(null_b);
				bad++;
			}
			if (!json_dump_eq(ja, jb)) {
				char *sa = NULL, *sb = NULL;
				size_t la = 0, lb = 0;

				aik_json_dump(ja, &sa, &la);
				aik_json_dump(jb, &sb, &lb);
				note("memory %s full-json differs:\n  A: %s\n  B: %s\n",
				     ma->id, sa ? sa : "?", sb ? sb : "?");
				free(sa);
				free(sb);
				bad++;
			}
			aik_json_free(ja);
			aik_json_free(jb);
		}
		if (ma->n_tags != mb->n_tags || ma->n_neighbors != mb->n_neighbors ||
		    ma->n_children != mb->n_children)
			bad++;
		{
			size_t k;

			for (k = 0; k < ma->n_tags && k < mb->n_tags; k++)
				if (strcmp(ma->tags[k], mb->tags[k]) != 0)
					bad++;
			for (k = 0; k < ma->n_neighbors && k < mb->n_neighbors;
			     k++)
				if (strcmp(ma->neighbors[k], mb->neighbors[k]) != 0)
					bad++;
			for (k = 0; k < ma->n_children && k < mb->n_children;
			     k++)
				if (strcmp(ma->children[k], mb->children[k]) != 0)
					bad++;
		}
		if (ma->embedding || mb->embedding) {
			if (!ma->embedding || !mb->embedding ||
			    ma->dim != mb->dim ||
			    memcmp(ma->embedding, mb->embedding,
				   (size_t)ma->dim * sizeof(double)) != 0)
				bad++;
		}
	}
	return bad == 0 ? 0 : -1;
}

static int compare_engines(aik_engine *a, aik_engine *b)
{
	aik_json *ga = NULL, *gb = NULL;
	aik_json *sa = NULL, *sb = NULL;
	char **ra = NULL, **rb = NULL;
	size_t na = 0, nb = 0;
	char err[256];
	int ok = 1;
	size_t i;

	if (compare_memories(a, b) != 0)
		ok = 0;
	if (aik_engine_graph(a, &ga, err, sizeof(err)) != 0 ||
	    aik_engine_graph(b, &gb, err, sizeof(err)) != 0 ||
	    !json_dump_eq(ga, gb))
		ok = 0;
	if (region_signatures(a, &ra, &na) != 0 ||
	    region_signatures(b, &rb, &nb) != 0)
		ok = 0;
	else if (na != nb)
		ok = 0;
	else {
		for (i = 0; i < na; i++)
			if (strcmp(ra[i], rb[i]) != 0)
				ok = 0;
	}
	if (aik_engine_stats(a, &sa, err, sizeof(err)) != 0 ||
	    aik_engine_stats(b, &sb, err, sizeof(err)) != 0) {
		ok = 0;
	} else {
		static const char *const keys[] = {
			"memories", "regions", "splits", "merges",
			"consolidations", "compressions", "graph_edges",
		};
		size_t k;

		for (k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
			long long va = 0, vb = 0;

			if (aik_json_typeof(aik_json_get(sa, keys[k])) ==
			    AIK_JSON_OBJ) {
				/* "memories"/"regions" 是子对象：比较 total */
				if (json_long(aik_json_get(sa, keys[k]), "total",
					      &va) != 0 ||
				    json_long(aik_json_get(sb, keys[k]), "total",
					      &vb) != 0)
					continue;
			} else if (json_long(sa, keys[k], &va) != 0 ||
				   json_long(sb, keys[k], &vb) != 0) {
				continue;
			}
			if (va != vb)
				ok = 0;
		}
	}
	for (i = 0; i < na; i++)
		free(ra[i]);
	for (i = 0; i < nb; i++)
		free(rb[i]);
	free(ra);
	free(rb);
	aik_json_free(ga);
	aik_json_free(gb);
	aik_json_free(sa);
	aik_json_free(sb);
	return ok ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* 2) 崩溃恢复 + 3) 幂等                                               */
/* ------------------------------------------------------------------ */
static int replay_count_visitor(void *ctx, const aik_json *op, char *err,
				size_t errlen)
{
	long long *n = ctx;

	(void)op;
	(void)err;
	(void)errlen;
	(*n)++;
	return 0;
}

static void test_crash_recovery(void)
{
	char *tmp = make_tmpdir();
	struct cfg_opts o;
	char err[512];
	char *snap = path_join(tmp, "data/engine.json");
	char *wal = path_join(tmp, "data/engine.json.wal");
	char *snap_copy = path_join(tmp, "data/engine.before-recovery.json");
	aik_config *cfg;
	aik_engine *a = NULL, *b = NULL, *c = NULL;
	long long sz = 0;
	aik_json *stats = NULL;
	char *ids[4] = { NULL, NULL, NULL, NULL };
	int i;

	memset(&o, 0, sizeof(o));
	o.wal_enabled = 1;
	o.sync_mode = "fsync";
	o.backend = "json";
	o.wal_path = wal;
	o.autosave = 1;
	o.checkpoint_every = 1000;
	cfg = make_cfg(tmp, &o, err, sizeof(err));
	CHECK(cfg != NULL);
	if (!cfg)
		goto out;
	a = new_engine(cfg, err, sizeof(err));
	CHECK(a != NULL);
	if (!a)
		goto out;
	g_now = WAL_T0;
	for (i = 0; i < 3; i++) {
		char text[64];
		aik_memory *m;

		snprintf(text, sizeof(text), "崩溃恢复基线记忆 第%d条", i + 1);
		m = aik_engine_add(a, text, NULL, NULL, 0, 0.5, NULL, NULL, NULL,
				   NULL, NULL, err, sizeof(err));
		CHECK(m != NULL);
		if (!m)
			goto out;
		ids[i] = xstrdup(m->id);
	}
	CHECK(aik_engine_save(a, NULL, err, sizeof(err)) == 0);
	/* 快照之后：archive + add + update + link，不 save */
	CHECK(aik_engine_archive(a, ids[1]) == 0);
	{
		aik_memory *m;
		aik_json *patch = jobj();

		m = aik_engine_add(a, "崩溃恢复增量记忆 第4条", NULL, NULL, 0, 0.4,
				   NULL, NULL, NULL, NULL, NULL, err, sizeof(err));
		CHECK(m != NULL);
		if (!m)
			goto out;
		ids[3] = xstrdup(m->id);
		jput(patch, "importance", aik_json_new_num(0.85));
		CHECK(aik_engine_update(a, ids[0], patch, err, sizeof(err)) == 0);
		aik_json_free(patch);
	}
	CHECK(aik_engine_link(a, ids[3], ids[1], "cause", 0.5, "因果关系", err,
			      sizeof(err)) == 0);
	CHECK(file_size(wal, &sz) == 0 && sz > 0);	/* A 的现场：日志非空 */

	/* 把 A 的 WAL 与快照复制一份，供第二次 load（幂等）使用 */
	{
		unsigned char *raw = NULL;
		size_t len = 0;

		CHECK(read_file(snap, &raw, &len) == 0);
		CHECK(write_file(snap_copy, raw, len) == 0);
		free(raw);
	}

	b = new_engine(make_cfg(tmp, &o, err, sizeof(err)), err, sizeof(err));
	CHECK(b != NULL);
	if (!b)
		goto out;
	CHECK(aik_engine_load(b, snap, err, sizeof(err)) == 0);
	if (err[0])
		note("recovery load note: %s\n", err);
	CHECK(compare_engines(a, b) == 0);

	CHECK(aik_engine_wal_stats(b, &stats, err, sizeof(err)) == 0);
	if (stats) {
		long long replayed = 0, seq = 0, ckpt = 0, ckpt_seq = 0;

		CHECK(json_long(stats, "replayed", &replayed) == 0 &&
		      replayed == 4);
		CHECK(json_long(stats, "sequence", &seq) == 0 && seq == 7);
		CHECK(json_long(stats, "checkpointed", &ckpt) == 0 && ckpt == 1);
		CHECK(json_long(stats, "checkpoint_sequence", &ckpt_seq) == 0 &&
		      ckpt_seq == 7);
		aik_json_free(stats);
		stats = NULL;
	}
	/* 恢复后 checkpoint：WAL 被截断，快照 wal_sequence=6 */
	CHECK(file_size(wal, &sz) == 0 && sz == 0);
	{
		aik_snapshot s;

		memset(&s, 0, sizeof(s));
		CHECK(aik_snapshot_load(snap, &s, err, sizeof(err)) == 0);
		if (s.root) {
			long long wseq = -1;

			CHECK(json_long(s.root, "wal_sequence", &wseq) == 0 &&
			      wseq == 7);
		}
		aik_snapshot_free(&s);
	}

	/* 幂等：同一快照再 load → 0 条重放，状态与 b 一致 */
	c = new_engine(make_cfg(tmp, &o, err, sizeof(err)), err, sizeof(err));
	CHECK(c != NULL);
	if (!c)
		goto out;
	CHECK(aik_engine_load(c, snap, err, sizeof(err)) == 0);
	CHECK(aik_engine_wal_stats(c, &stats, err, sizeof(err)) == 0);
	if (stats) {
		long long replayed = -1;

		CHECK(json_long(stats, "replayed", &replayed) == 0 &&
		      replayed == 0);
		aik_json_free(stats);
		stats = NULL;
	}
	CHECK(compare_engines(b, c) == 0);
	/* 同一（已空）WAL 再 replay 一次：0 条（幂等） */
	{
		long long seen = 0, rec = -1;

		CHECK(aik_wal_replay(wal, 7, replay_count_visitor, &seen, err,
				     sizeof(err)) == 0);
		CHECK(seen == 0);
		CHECK(aik_wal_replay_ex(wal, 7, replay_count_visitor, &seen, &rec,
					NULL, err, sizeof(err)) == 0);
		CHECK(seen == 0 && rec == 0);
	}
out:
	aik_json_free(stats);
	aik_engine_free(a);
	aik_engine_free(b);
	aik_engine_free(c);
	for (i = 0; i < 4; i++)
		free(ids[i]);
	free(snap);
	free(wal);
	free(snap_copy);
	free(tmp);
}

/* ------------------------------------------------------------------ */
/* 4) checkpoint 节奏                                                  */
/* ------------------------------------------------------------------ */
static void test_checkpoint(void)
{
	char *tmp = make_tmpdir();
	struct cfg_opts o;
	char err[512];
	char *snap = path_join(tmp, "data/engine.json");
	char *wal = path_join(tmp, "data/engine.json.wal");
	aik_config *cfg;
	aik_engine *a = NULL, *b = NULL;
	aik_json *stats = NULL;
	long long sz = 0;
	int i;

	memset(&o, 0, sizeof(o));
	o.wal_enabled = 1;
	o.sync_mode = "fsync";
	o.backend = "json";
	o.wal_path = wal;
	o.autosave = 1;
	o.checkpoint_every = 3;
	cfg = make_cfg(tmp, &o, err, sizeof(err));
	CHECK(cfg != NULL);
	if (!cfg)
		goto out;
	a = new_engine(cfg, err, sizeof(err));
	CHECK(a != NULL);
	if (!a)
		goto out;
	g_now = WAL_T0;
	for (i = 0; i < 3; i++) {
		char text[64];

		snprintf(text, sizeof(text), "checkpoint 记忆 第%d条", i + 1);
		CHECK(aik_engine_add(a, text, NULL, NULL, 0, 0.5, NULL, NULL,
				     NULL, NULL, NULL, err, sizeof(err)) != NULL);
	}
	/* 第 3 条触发 autosave → checkpoint */
	CHECK(aik_engine_wal_stats(a, &stats, err, sizeof(err)) == 0);
	if (stats) {
		long long pending = -1, seq = -1, ckpt = -1;

		CHECK(json_long(stats, "pending_ops", &pending) == 0 &&
		      pending == 0);
		CHECK(json_long(stats, "sequence", &seq) == 0 && seq == 3);
		CHECK(json_long(stats, "checkpointed", &ckpt) == 0 && ckpt == 1);
		aik_json_free(stats);
		stats = NULL;
	}
	CHECK(file_size(wal, &sz) == 0 && sz == 0);
	{
		aik_snapshot s;

		memset(&s, 0, sizeof(s));
		CHECK(aik_snapshot_load(snap, &s, err, sizeof(err)) == 0);
		if (s.root) {
			long long wseq = -1;

			CHECK(json_long(s.root, "wal_sequence", &wseq) == 0 &&
			      wseq == 3);
			CHECK(aik_json_count(aik_json_get(s.root, "memories")) ==
			      3);
		}
		aik_snapshot_free(&s);
	}
	/* 第 4 条：seq=4，等 1 条 pending */
	CHECK(aik_engine_add(a, "checkpoint 记忆 第4条", NULL, NULL, 0, 0.5,
			     NULL, NULL, NULL, NULL, NULL, err,
			     sizeof(err)) != NULL);
	CHECK(aik_engine_wal_stats(a, &stats, err, sizeof(err)) == 0);
	if (stats) {
		long long pending = -1, seq = -1;

		CHECK(json_long(stats, "pending_ops", &pending) == 0 &&
		      pending == 1);
		CHECK(json_long(stats, "sequence", &seq) == 0 && seq == 4);
		aik_json_free(stats);
		stats = NULL;
	}
	CHECK(file_size(wal, &sz) == 0 && sz > 0);

	/* 再次 load：0 条快照 + 1 条 WAL → 4 条记忆 */
	b = new_engine(make_cfg(tmp, &o, err, sizeof(err)), err, sizeof(err));
	CHECK(b != NULL);
	if (!b)
		goto out;
	CHECK(aik_engine_load(b, snap, err, sizeof(err)) == 0);
	CHECK(aik_engine_memory_count(b) == 4);
	CHECK(aik_engine_wal_stats(b, &stats, err, sizeof(err)) == 0);
	if (stats) {
		long long replayed = -1, seq = -1;

		CHECK(json_long(stats, "replayed", &replayed) == 0 &&
		      replayed == 1);
		CHECK(json_long(stats, "sequence", &seq) == 0 && seq == 4);
		aik_json_free(stats);
		stats = NULL;
	}
	CHECK(compare_engines(a, b) == 0);
out:
	aik_json_free(stats);
	aik_engine_free(a);
	aik_engine_free(b);
	free(snap);
	free(wal);
	free(tmp);
}

/* ------------------------------------------------------------------ */
/* 4b) export 到非配置路径不截断 WAL（参考 _save_locked recovery_path） */
/* ------------------------------------------------------------------ */
static void test_export_no_truncate(void)
{
	char *tmp = make_tmpdir();
	struct cfg_opts o;
	char err[512];
	char *wal = path_join(tmp, "data/engine.json.wal");
	char *export_path = path_join(tmp, "data/export.json");
	aik_config *cfg;
	aik_engine *e = NULL;
	aik_json *stats = NULL;
	long long before = 0, after = 0;

	memset(&o, 0, sizeof(o));
	o.wal_enabled = 1;
	o.sync_mode = "fsync";
	o.backend = "json";
	o.wal_path = wal;
	o.autosave = 0;
	o.checkpoint_every = 1000;
	cfg = make_cfg(tmp, &o, err, sizeof(err));
	CHECK(cfg != NULL);
	if (!cfg)
		goto out;
	e = new_engine(cfg, err, sizeof(err));
	CHECK(e != NULL);
	if (!e)
		goto out;
	g_now = WAL_T0;
	CHECK(aik_engine_add(e, "export 记忆一", NULL, NULL, 0, 0.5, NULL, NULL,
			     NULL, NULL, NULL, err, sizeof(err)) != NULL);
	CHECK(aik_engine_add(e, "export 记忆二", NULL, NULL, 0, 0.5, NULL, NULL,
			     NULL, NULL, NULL, err, sizeof(err)) != NULL);
	CHECK(file_size(wal, &before) == 0 && before > 0);
	/* 导出到其它路径：写快照但不算 checkpoint */
	CHECK(aik_engine_save(e, export_path, err, sizeof(err)) == 0);
	CHECK(file_size(wal, &after) == 0 && after == before);
	CHECK(aik_engine_wal_stats(e, &stats, err, sizeof(err)) == 0);
	if (stats) {
		long long pending = -1, ckpt = -1, ckpt_seq = -1;

		CHECK(json_long(stats, "pending_ops", &pending) == 0 &&
		      pending == 2);
		CHECK(json_long(stats, "checkpointed", &ckpt) == 0 && ckpt == 0);
		CHECK(json_long(stats, "checkpoint_sequence", &ckpt_seq) == 0 &&
		      ckpt_seq == 0);
		aik_json_free(stats);
		stats = NULL;
	}
	/* 保存到配置路径：checkpoint，WAL 截断 */
	CHECK(aik_engine_save(e, NULL, err, sizeof(err)) == 0);
	CHECK(file_size(wal, &after) == 0 && after == 0);
	CHECK(aik_engine_wal_stats(e, &stats, err, sizeof(err)) == 0);
	if (stats) {
		long long ckpt = -1, ckpt_seq = -1, seq = -1;

		CHECK(json_long(stats, "checkpointed", &ckpt) == 0 && ckpt == 1);
		CHECK(json_long(stats, "checkpoint_sequence", &ckpt_seq) == 0 &&
		      ckpt_seq == 2);
		CHECK(json_long(stats, "sequence", &seq) == 0 && seq == 2);
		aik_json_free(stats);
		stats = NULL;
	}
out:
	aik_json_free(stats);
	aik_engine_free(e);
	free(wal);
	free(export_path);
	free(tmp);
}

/* ------------------------------------------------------------------ */
/* 4c) add(link_to) 的事务形态 + import 立即 checkpoint                */
/* ------------------------------------------------------------------ */
static void test_add_link_and_import(void)
{
	char *tmp = make_tmpdir();
	struct cfg_opts o;
	char err[512];
	char *snap = path_join(tmp, "data/engine.json");
	char *wal = path_join(tmp, "data/engine.json.wal");
	aik_config *cfg;
	aik_engine *e = NULL, *b = NULL;
	aik_memory *m1, *m2;
	unsigned char *raw = NULL;
	size_t len = 0;
	long long sz = 0;

	memset(&o, 0, sizeof(o));
	o.wal_enabled = 1;
	o.sync_mode = "fsync";
	o.backend = "json";
	o.wal_path = wal;
	o.autosave = 1;
	o.checkpoint_every = 1000;
	cfg = make_cfg(tmp, &o, err, sizeof(err));
	CHECK(cfg != NULL);
	if (!cfg)
		goto out;
	e = new_engine(cfg, err, sizeof(err));
	CHECK(e != NULL);
	if (!e)
		goto out;
	g_now = WAL_T0;
	m1 = aik_engine_add(e, "事务形态记忆一", NULL, NULL, 0, 0.5, NULL, NULL,
			    NULL, NULL, NULL, err, sizeof(err));
	CHECK(m1 != NULL);
	if (!m1)
		goto out;
	CHECK(aik_engine_save(e, NULL, err, sizeof(err)) == 0);
	CHECK(file_size(wal, &sz) == 0 && sz == 0);
	m2 = aik_engine_add(e, "事务形态记忆二", NULL, NULL, 0, 0.5, NULL,
			    m1->id, NULL, NULL, NULL, err, sizeof(err));
	CHECK(m2 != NULL);
	if (!m2)
		goto out;
	/* 参考 add(link_to)：op,memories,graph,seq（无 counters） */
	CHECK(read_file(wal, &raw, &len) == 0 && len > 0);
	{
		aik_json *op = aik_json_parse((const char *)raw, len, err,
					      sizeof(err));
		const aik_json *mem;
		const aik_json *graph;
		const aik_json *edges;

		CHECK(op != NULL);
		if (op) {
			CHECK(strcmp(aik_json_str(aik_json_get(op, "op")),
				     "transaction") == 0);
			mem = aik_json_get(op, "memories");
			graph = aik_json_get(op, "graph");
			edges = aik_json_get(graph, "edges");
			CHECK(aik_json_typeof(mem) == AIK_JSON_ARR &&
			      aik_json_count(mem) == 1);
			CHECK(aik_json_typeof(aik_json_get(op, "patches")) ==
			      AIK_JSON_NULL);
			CHECK(aik_json_typeof(aik_json_get(op, "counters")) ==
			      AIK_JSON_NULL);
			CHECK(aik_json_typeof(edges) == AIK_JSON_ARR &&
			      aik_json_count(edges) == 1);
			CHECK(aik_json_get(op, "seq") != NULL);
			aik_json_free(op);
		}
	}
	free(raw);
	raw = NULL;

	/* 崩溃恢复：快照 1 条 + WAL 事务 1 条 → 2 条记忆 + 1 条边 */
	b = new_engine(make_cfg(tmp, &o, err, sizeof(err)), err, sizeof(err));
	CHECK(b != NULL);
	if (!b)
		goto out;
	CHECK(aik_engine_load(b, snap, err, sizeof(err)) == 0);
	CHECK(aik_engine_memory_count(b) == 2);
	CHECK(compare_engines(e, b) == 0);
	aik_engine_free(e);
	e = NULL;
	aik_engine_free(b);
	b = NULL;

	/* import：不逐条写 WAL，完成即 checkpoint */
	{
		char *tmp2 = make_tmpdir();
		char *snap2 = path_join(tmp2, "data/engine.json");
		char *wal2 = path_join(tmp2, "data/engine.json.wal");
		static const char items_json[] =
			"[{\"id\":\"m_aaaaaaaaaaaa\",\"text\":\"导入一\"},"
			"{\"id\":\"m_bbbbbbbbbbbb\",\"text\":\"导入二\"}]";
		aik_json *items = aik_json_parse(items_json,
						 strlen(items_json), err,
						 sizeof(err));
		aik_json *stats = NULL;
		long long n = -1;

		CHECK(items != NULL);
		memset(&o, 0, sizeof(o));
		o.wal_enabled = 1;
		o.sync_mode = "fsync";
		o.backend = "json";
		o.wal_path = wal2;
		o.autosave = 1;
		o.checkpoint_every = 1000;
		cfg = make_cfg(tmp2, &o, err, sizeof(err));
		CHECK(cfg != NULL);
		if (cfg) {
			e = new_engine(cfg, err, sizeof(err));
			CHECK(e != NULL);
			if (e) {
				CHECK(aik_engine_import(e, items, &n, err,
							sizeof(err)) == 0);
				CHECK(n == 2);
				CHECK(aik_engine_wal_stats(
					      e, &stats, err, sizeof(err)) == 0);
				if (stats) {
					long long ckpt = -1, pending = -1,
						  seq = -1;

					CHECK(json_long(stats, "checkpointed",
							&ckpt) == 0 &&
					      ckpt == 1);
					CHECK(json_long(stats, "pending_ops",
							&pending) == 0 &&
					      pending == 0);
					CHECK(json_long(stats, "sequence", &seq) ==
						      0 &&
					      seq == 0);
					aik_json_free(stats);
					stats = NULL;
				}
				CHECK(file_size(wal2, &sz) != 0);
				{
					aik_snapshot s;

					memset(&s, 0, sizeof(s));
					CHECK(aik_snapshot_load(snap2, &s, err,
								sizeof(err)) ==
					      0);
					if (s.root) {
						long long wseq = -1;

						CHECK(aik_json_count(aik_json_get(
								      s.root,
								      "memories")) ==
						      2);
						CHECK(json_long(s.root,
								"wal_sequence",
								&wseq) == 0 &&
						      wseq == 0);
					}
					aik_snapshot_free(&s);
				}
				aik_engine_free(e);
				e = NULL;
			}
		}
		aik_json_free(items);
		free(snap2);
		free(wal2);
		free(tmp2);
	}
out:
	free(raw);
	aik_engine_free(e);
	aik_engine_free(b);
	free(snap);
	free(wal);
	free(tmp);
}

/* ------------------------------------------------------------------ */
/* 5) 失败保留日志                                                     */
/* ------------------------------------------------------------------ */
static void test_failure_retention(void)
{
	char *tmp = make_tmpdir();
	struct cfg_opts o;
	char err[512];
	char *snap = path_join(tmp, "data/engine.json");
	char *wal = path_join(tmp, "data/engine.json.wal");
	char *wal_save = path_join(tmp, "data/engine.json.wal.saved");
	aik_config *cfg;
	aik_engine *a = NULL, *b = NULL;
	unsigned char *raw = NULL;
	size_t len = 0;
	long long sz_before = 0, sz_after = 0;
	char *bad;

	memset(&o, 0, sizeof(o));
	o.wal_enabled = 1;
	o.sync_mode = "fsync";
	o.backend = "json";
	o.wal_path = wal;
	o.autosave = 1;
	o.checkpoint_every = 1000;
	cfg = make_cfg(tmp, &o, err, sizeof(err));
	CHECK(cfg != NULL);
	if (!cfg)
		goto out;
	a = new_engine(cfg, err, sizeof(err));
	CHECK(a != NULL);
	if (!a)
		goto out;
	g_now = WAL_T0;
	CHECK(aik_engine_add(a, "失败保留基线一", NULL, NULL, 0, 0.5, NULL,
			     NULL, NULL, NULL, NULL, err, sizeof(err)) != NULL);
	CHECK(aik_engine_add(a, "失败保留基线二", NULL, NULL, 0, 0.5, NULL,
			     NULL, NULL, NULL, NULL, err, sizeof(err)) != NULL);
	CHECK(aik_engine_save(a, NULL, err, sizeof(err)) == 0);
	CHECK(aik_engine_add(a, "失败保留增量", NULL, NULL, 0, 0.5, NULL, NULL,
			     NULL, NULL, NULL, err, sizeof(err)) != NULL);
	aik_engine_free(a);
	a = NULL;

	CHECK(read_file(wal, &raw, &len) == 0 && len > 0);
	CHECK(write_file(wal_save, raw, len) == 0);
	free(raw);
	raw = NULL;

	/* 追加一条坏行（第 2 条记录） */
	bad = xstrdup("this is not JSON\n");
	CHECK(write_file(path_join(tmp, "data/bad.append"), bad, strlen(bad)) ==
	      0);
	{
		FILE *fh = fopen(wal, "ab");

		CHECK(fh != NULL);
		if (fh) {
			fputs(bad, fh);
			fclose(fh);
		}
	}
	free(bad);
	CHECK(file_size(wal, &sz_before) == 0);
	CHECK(sz_before > (long long)len);

	b = new_engine(make_cfg(tmp, &o, err, sizeof(err)), err, sizeof(err));
	CHECK(b != NULL);
	if (!b)
		goto out;
	err[0] = '\0';
	CHECK(aik_engine_load(b, snap, err, sizeof(err)) != 0);
	CHECK(strstr(err, "WAL replay failed at record 2") != NULL);
	CHECK(strstr(err, "log retained") != NULL);
	CHECK(file_size(wal, &sz_after) == 0 && sz_after == sz_before);
	aik_engine_free(b);
	b = NULL;

	/* 恢复原 WAL 后可正常 load */
	CHECK(read_file(wal_save, &raw, &len) == 0);
	CHECK(write_file(wal, raw, len) == 0);
	free(raw);
	raw = NULL;
	b = new_engine(make_cfg(tmp, &o, err, sizeof(err)), err, sizeof(err));
	CHECK(b != NULL);
	if (!b)
		goto out;
	CHECK(aik_engine_load(b, snap, err, sizeof(err)) == 0);
	CHECK(aik_engine_memory_count(b) == 3);

out:
	aik_engine_free(a);
	aik_engine_free(b);
	free(raw);
	free(snap);
	free(wal);
	free(wal_save);
	free(tmp);
}

/* ------------------------------------------------------------------ */
/* 6) 限制与默认路径                                                   */
/* ------------------------------------------------------------------ */
static void test_limits_and_defaults(void)
{
	char *tmp = make_tmpdir();
	char err[512];
	aik_config *cfg;
	aik_engine *e = NULL;
	aik_json *stats = NULL;
	struct cfg_opts o;
	char *wal = path_join(tmp, "data/engine.json.wal");

	/* grouped → 拒绝 */
	memset(&o, 0, sizeof(o));
	o.wal_enabled = 1;
	o.sync_mode = "grouped";
	o.backend = "json";
	cfg = make_cfg(tmp, &o, err, sizeof(err));
	if (cfg) {
		e = new_engine(cfg, err, sizeof(err));
		CHECK(e == NULL);
		CHECK(strstr(err, "未接线") != NULL);
		aik_engine_free(e);
		e = NULL;
	}
	/* sqlite → 拒绝 */
	memset(&o, 0, sizeof(o));
	o.wal_enabled = 1;
	o.sync_mode = "fsync";
	o.backend = "sqlite";
	cfg = make_cfg(tmp, &o, err, sizeof(err));
	if (cfg) {
		e = new_engine(cfg, err, sizeof(err));
		CHECK(e == NULL);
		CHECK(strstr(err, "未接线") != NULL);
		aik_engine_free(e);
		e = NULL;
	}
	/* 默认 WAL 路径 = storage.path + ".wal" */
	memset(&o, 0, sizeof(o));
	o.wal_enabled = 1;
	o.sync_mode = "fsync";
	o.backend = "json";
	o.autosave = 0;
	cfg = make_cfg(tmp, &o, err, sizeof(err));
	if (cfg) {
		e = new_engine(cfg, err, sizeof(err));
		CHECK(e != NULL);
		if (e) {
			CHECK(aik_engine_wal_stats(e, &stats, err, sizeof(err)) ==
			      0);
			if (stats) {
				const char *p = aik_json_str(
					aik_json_get(stats, "path"));

				CHECK(p != NULL && strcmp(p, wal) == 0);
			}
			aik_json_free(stats);
			stats = NULL;
			CHECK(aik_engine_add(e, "默认路径记忆", NULL, NULL, 0, 0.5,
					     NULL, NULL, NULL, NULL, NULL, err,
					     sizeof(err)) != NULL);
			{
				long long sz = 0;

				CHECK(file_size(wal, &sz) == 0 && sz > 0);
			}
			aik_engine_free(e);
			e = NULL;
		}
	}
	/* persistence.enabled=false：不写 .wal，快照 wal_sequence=0 */
	{
		char *tmp2 = make_tmpdir();
		char *snap = path_join(tmp2, "data/engine.json");
		char *waloff = path_join(tmp2, "data/engine.json.wal");
		long long szo = 0;

		memset(&o, 0, sizeof(o));
		o.wal_enabled = 0;
		o.sync_mode = "fsync";
		o.backend = "json";
		o.autosave = 1;
		o.checkpoint_every = 1000;
		cfg = make_cfg(tmp2, &o, err, sizeof(err));
		CHECK(cfg != NULL);
		if (cfg) {
			e = new_engine(cfg, err, sizeof(err));
			CHECK(e != NULL);
			if (e) {
				CHECK(aik_engine_add(e, "无 WAL 记忆", NULL, NULL,
						     0, 0.5, NULL, NULL, NULL,
						     NULL, NULL, err, sizeof(err)) !=
				      NULL);
				CHECK(aik_engine_save(e, NULL, err, sizeof(err)) ==
				      0);
				CHECK(aik_engine_wal_stats(
					      e, &stats, err, sizeof(err)) == 0);
				if (stats) {
					long long seq = -1;
					const aik_json *en =
						aik_json_get(stats, "enabled");

					CHECK(aik_json_typeof(en) ==
						      AIK_JSON_BOOL &&
					      aik_json_bool(en) == 0);
					CHECK(json_long(stats, "sequence", &seq) ==
						      0 &&
					      seq == 0);
					aik_json_free(stats);
					stats = NULL;
				}
				aik_engine_free(e);
				e = NULL;
			}
			{
				aik_snapshot s;

				memset(&s, 0, sizeof(s));
				CHECK(aik_snapshot_load(snap, &s, err,
							sizeof(err)) == 0);
				if (s.root) {
					long long wseq = -1;

					CHECK(json_long(s.root, "wal_sequence",
							&wseq) == 0 &&
					      wseq == 0);
				}
				aik_snapshot_free(&s);
			}
			CHECK(file_size(waloff, &szo) != 0);
		}
		free(snap);
		free(waloff);
		free(tmp2);
	}
	aik_json_free(stats);
	aik_engine_free(e);
	free(wal);
	free(tmp);
}

int main(void)
{
	test_parity();
	test_crash_recovery();
	test_checkpoint();
	test_export_no_truncate();
	test_add_link_and_import();
	test_failure_retention();
	test_limits_and_defaults();
	printf("test_wal_engine: %d checks, %d failed\n", g_checked, g_failed);
	return g_failed ? 1 : 0;
}
