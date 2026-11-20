/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_shadow.c - 影子记录落盘 + 对照 mismatch（schema 见 aip_shadow.h）
 *
 * Parquet writer：as_parquet.c 同格式面（单 row group / PLAIN / snappy /
 * DataPageV1 / OPTIONAL 全 1 def / statistics / tmp+fsync+rename）的
 * 独立实现——不动 aistreamd（其 pq_write_table 静态 + as_pq_write_
 * decisions 固定 decisions.parquet 名与 32 列 PQ_MAXCOL 冻结，不适配
 * shadow_NNNN 33 列；设计 §1.4 逃生条款=本目录独立 writer）。页压缩
 * 复用 ../aistreamd/as_snappy.c（显式只读链接，occ PQ_REUSE 先例）。
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "aistreamd/as_snappy.h"

#include "aip_model.h"
#include "aip_shadow.h"
#include "aip_table.h"
#include "aip_util.h"

#define PQ_PAR1		"PAR1"
#define PQ_CREATED_BY	"aipd aip_shadow 1.0 (AIPD-M1 writer-only)"

/* ================= 1. 字节缓冲（as_parquet.c 同手法） ================= */

struct pq_buf {
	uint8_t *b;
	size_t n, cap;
};

static int buf_reserve(struct pq_buf *o, size_t need)
{
	if (o->n + need <= o->cap)
		return 0;
	{
		size_t cap = o->cap ? o->cap : 256;
		uint8_t *nb;

		while (cap < o->n + need)
			cap *= 2;
		nb = realloc(o->b, cap);
		if (!nb)
			return -1;
		o->b = nb;
		o->cap = cap;
	}
	return 0;
}

static void buf_free(struct pq_buf *o)
{
	free(o->b);
	o->b = NULL;
	o->n = o->cap = 0;
}

static int w8(struct pq_buf *o, uint8_t v)
{
	if (buf_reserve(o, 1) != 0)
		return -1;
	o->b[o->n++] = v;
	return 0;
}

static int wraw(struct pq_buf *o, const void *p, size_t n)
{
	if (n && buf_reserve(o, n) != 0)
		return -1;
	if (n)
		memcpy(o->b + o->n, p, n);
	o->n += n;
	return 0;
}

static int wle32(struct pq_buf *o, uint32_t v)
{
	uint8_t t[4];

	t[0] = (uint8_t)v;
	t[1] = (uint8_t)(v >> 8);
	t[2] = (uint8_t)(v >> 16);
	t[3] = (uint8_t)(v >> 24);
	return wraw(o, t, 4);
}

static int wle64(struct pq_buf *o, uint64_t v)
{
	uint8_t t[8];

	for (int i = 0; i < 8; i++)
		t[i] = (uint8_t)(v >> (8 * i));
	return wraw(o, t, 8);
}

static int wvar(struct pq_buf *o, uint64_t v)
{
	while (v >= 0x80) {
		if (w8(o, (uint8_t)(v | 0x80)) != 0)
			return -1;
		v >>= 7;
	}
	return w8(o, (uint8_t)v);
}

static int wzig(struct pq_buf *o, int64_t v)
{
	return wvar(o, ((uint64_t)v << 1) ^ (uint64_t)(v >> 63));
}

static void le_into(uint8_t *dst, int len, int64_t v)
{
	for (int i = 0; i < len; i++)
		dst[i] = (uint8_t)((uint64_t)v >> (8 * i));
}

/* ================= 2. thrift compact writer（同手法） ================= */

#define TT_STOP		0
#define TT_TRUE		1
#define TT_FALSE	2
#define TT_BYTE		3
#define TT_I16		4
#define TT_I32		5
#define TT_I64		6
#define TT_DOUBLE	7
#define TT_BIN		8
#define TT_LIST		9
#define TT_SET		10
#define TT_MAP		11
#define TT_STRUCT	12

struct tw {
	struct pq_buf b;
	int last[12];
	int depth;
};

static void tw_init(struct tw *t)
{
	memset(t, 0, sizeof(*t));
}

static int wfield(struct tw *t, int id, int type)
{
	int last = t->last[t->depth];

	if (id > last && id - last <= 15) {
		if (w8(&t->b, (uint8_t)((id - last) << 4 | type)) != 0)
			return -1;
	} else {
		if (w8(&t->b, (uint8_t)type) != 0 || wzig(&t->b, id) != 0)
			return -1;
	}
	t->last[t->depth] = id;
	return 0;
}

static void tw_open(struct tw *t)
{
	t->depth++;
	t->last[t->depth] = 0;
}

static void tw_close(struct tw *t)
{
	t->depth--;
}

static int wstop(struct tw *t)
{
	return w8(&t->b, TT_STOP);
}

static int wi32f(struct tw *t, int id, int32_t v)
{
	if (wfield(t, id, TT_I32) != 0 || wzig(&t->b, v) != 0)
		return -1;
	return 0;
}

static int wi64f(struct tw *t, int id, int64_t v)
{
	if (wfield(t, id, TT_I64) != 0 || wzig(&t->b, v) != 0)
		return -1;
	return 0;
}

static int wbinf(struct tw *t, int id, const void *p, size_t n)
{
	if (wfield(t, id, TT_BIN) != 0 || wvar(&t->b, n) != 0 ||
	    wraw(&t->b, p, n) != 0)
		return -1;
	return 0;
}

static int wstrf(struct tw *t, int id, const char *s)
{
	return wbinf(t, id, s, strlen(s));
}

static int wbegin(struct tw *t, int id)
{
	if (wfield(t, id, TT_STRUCT) != 0)
		return -1;
	tw_open(t);
	return 0;
}

static int wend(struct tw *t)
{
	if (wstop(t) != 0)
		return -1;
	tw_close(t);
	return 0;
}

static int wlist(struct tw *t, int id, int etype, size_t n)
{
	if (wfield(t, id, TT_LIST) != 0)
		return -1;
	if (n < 15)
		return w8(&t->b, (uint8_t)((n << 4) | etype));
	if (w8(&t->b, (uint8_t)(0xf0 | etype)) != 0)
		return -1;
	return wvar(&t->b, n);
}

/* ================= 3. 列定义与写表 ================= */

enum pq_ph {
	PQ_INT32,
	PQ_INT64,
	PQ_BYTE_ARRAY,
	PQ_DOUBLE,
};

enum pq_lg {
	PQ_LG_NONE = 0,
	PQ_LG_I8,
	PQ_LG_I16,
	PQ_LG_I32,
	PQ_LG_I64,
	PQ_LG_STR,
};

struct pq_coldef {
	const char *name;
	enum pq_ph ph;
	enum pq_lg lg;
};

static int conv_type(enum pq_lg lg)
{
	switch (lg) {
	case PQ_LG_STR:	return 0;
	case PQ_LG_I8:	return 15;
	case PQ_LG_I16:	return 16;
	case PQ_LG_I32:	return 17;
	case PQ_LG_I64:	return 18;
	default:	return -1;
	}
}

static int phys_type(enum pq_ph ph)
{
	switch (ph) {
	case PQ_INT32:	return 1;
	case PQ_INT64:	return 2;
	case PQ_DOUBLE:	return 5;
	default:	return 6;
	}
}

/* decisions v3 32 列同构（=as_parquet.c dec_cols 逐字段）+ source 尾列 */
static const struct pq_coldef shadow_cols[AIP_SHADOW_NCOL] = {
	{ "decision_id",		PQ_INT64,	PQ_LG_I64 },
	{ "trigger_ts",			PQ_INT64,	PQ_LG_I64 },
	{ "trigger_event_id",		PQ_INT64,	PQ_LG_I64 },
	{ "decision_ts",		PQ_INT64,	PQ_LG_I64 },
	{ "decision_type",		PQ_INT32,	PQ_LG_I8 },
	{ "data_0",			PQ_INT64,	PQ_LG_I64 },
	{ "data_1",			PQ_INT64,	PQ_LG_I64 },
	{ "data_2",			PQ_INT64,	PQ_LG_I64 },
	{ "data_3",			PQ_INT64,	PQ_LG_I64 },
	{ "data_4",			PQ_INT64,	PQ_LG_I64 },
	{ "data_5",			PQ_INT64,	PQ_LG_I64 },
	{ "data_6",			PQ_INT64,	PQ_LG_I64 },
	{ "data_7",			PQ_INT64,	PQ_LG_I64 },
	{ "exec_ts",			PQ_INT64,	PQ_LG_I64 },
	{ "outcome_ts",			PQ_INT64,	PQ_LG_I64 },
	{ "outcome",			PQ_INT32,	PQ_LG_I8 },
	{ "metric_delta",		PQ_INT64,	PQ_LG_I64 },
	{ "model_version",		PQ_INT32,	PQ_LG_I32 },
	{ "confidence",			PQ_INT32,	PQ_LG_I8 },
	{ "domain",			PQ_INT32,	PQ_LG_I8 },
	{ "source",			PQ_INT32,	PQ_LG_I8 },
	{ "executed",			PQ_INT32,	PQ_LG_I8 },
	{ "safety_clamped",		PQ_INT32,	PQ_LG_I8 },
	{ "trace_hi",			PQ_INT64,	PQ_LG_I64 },
	{ "trace_lo",			PQ_INT64,	PQ_LG_I64 },
	{ "intent_id",			PQ_INT64,	PQ_LG_I64 },
	{ "parent_id",			PQ_INT64,	PQ_LG_I64 },
	{ "agent_id",			PQ_INT32,	PQ_LG_I32 },
	{ "expected",			PQ_INT64,	PQ_LG_I64 },
	{ "cost_ns",			PQ_INT64,	PQ_LG_I64 },
	{ "side_effect_mask",		PQ_INT32,	PQ_LG_I32 },
	{ "value",			PQ_DOUBLE,	PQ_LG_NONE },
	/* 尾列（Lane-B 合同：按列位 32=第 33 列）。P-56：列名 source 与
	 * 决策块 int source（列位 20）撞名——标准读者（pyarrow
	 * read_table）对重复列名直接拒读（E1' 回放断链真身）；改名
	 * producer（值恒=AIP_SHADOW_SOURCE_STR，语义=行生产者标识），
	 * 列位合同不动。 */
	{ "producer",			PQ_BYTE_ARRAY,	PQ_LG_STR },
};

/* P-56：列名访问/唯一性自检（见 aip_shadow.h 尾注） */
const char *aip_shadow_colname(int ci)
{
	if (ci < 0 || ci >= AIP_SHADOW_NCOL)
		return NULL;
	return shadow_cols[ci].name;
}

int aip_shadow_ncols(void)
{
	return AIP_SHADOW_NCOL;
}

int aip_shadow_cols_unique(void)
{
	for (int i = 0; i < AIP_SHADOW_NCOL; i++)
		for (int j = i + 1; j < AIP_SHADOW_NCOL; j++)
			if (strcmp(shadow_cols[i].name,
				   shadow_cols[j].name) == 0)
				return -1;
	return 0;
}

static int64_t narrow(enum pq_lg lg, int64_t v)
{
	switch (lg) {
	case PQ_LG_I8:	return (int8_t)v;
	case PQ_LG_I16:	return (int16_t)v;
	case PQ_LG_I32:	return (int32_t)v;
	default:	return v;
	}
}

struct pq_ba {
	const uint8_t *p;
	size_t n;
};

static int build_page(const struct pq_coldef *c, int64_t nrows,
		      const int64_t *ints, const struct pq_ba *bas,
		      struct pq_buf *raw)
{
	/* def-levels：全 1 → RLE run（as_parquet.c 同布局） */
	{
		struct pq_buf run;

		memset(&run, 0, sizeof(run));
		if (wvar(&run, ((uint64_t)nrows << 1)) != 0 ||
		    w8(&run, 0x01) != 0)
			return -1;
		if (wle32(raw, (uint32_t)run.n) != 0 ||
		    wraw(raw, run.b, run.n) != 0) {
			buf_free(&run);
			return -1;
		}
		buf_free(&run);
	}
	if (c->ph == PQ_BYTE_ARRAY) {
		for (int64_t i = 0; i < nrows; i++) {
			if (wle32(raw, (uint32_t)bas[i].n) != 0 ||
			    (bas[i].n && wraw(raw, bas[i].p, bas[i].n) != 0))
				return -1;
		}
	} else if (c->ph == PQ_INT32) {
		for (int64_t i = 0; i < nrows; i++) {
			int32_t v = (int32_t)narrow(c->lg, ints[i]);

			if (wle32(raw, (uint32_t)v) != 0)
				return -1;
		}
	} else {
		for (int64_t i = 0; i < nrows; i++) {
			if (wle64(raw, (uint64_t)narrow(c->lg, ints[i])) != 0)
				return -1;
		}
	}
	return 0;
}

static void col_minmax(const struct pq_coldef *c, int64_t nrows,
		       const int64_t *ints, int64_t *pmin, int64_t *pmax)
{
	int64_t mn = 0, mx = 0;

	if (c->ph == PQ_DOUBLE && nrows > 0) {
		double dmn, dmx;

		memcpy(&dmn, &ints[0], sizeof(dmn));
		dmx = dmn;
		for (int64_t i = 1; i < nrows; i++) {
			double dv;

			memcpy(&dv, &ints[i], sizeof(dv));
			if (dv < dmn)
				dmn = dv;
			if (dv > dmx)
				dmx = dv;
		}
		memcpy(&mn, &dmn, sizeof(mn));
		memcpy(&mx, &dmx, sizeof(mx));
	} else if (c->ph != PQ_BYTE_ARRAY && nrows > 0) {
		mn = mx = narrow(c->lg, ints[0]);
		for (int64_t i = 1; i < nrows; i++) {
			int64_t v = narrow(c->lg, ints[i]);

			if (v < mn)
				mn = v;
			if (v > mx)
				mx = v;
		}
	}
	*pmin = mn;
	*pmax = mx;
}

struct pq_chunk_info {
	long data_page_offset;
	long hdr_len;
	size_t raw_len, comp_len;
	int stat_len;
	uint8_t stat_min[8], stat_max[8];
};

/*
 * shadow_write_table - 单表写（存在即新文件；tmp+fsync+rename 原子）。
 * ints[]/bas[] 按列序供给（数值列 int64；BA 列 pq_ba）。
 */
static int shadow_write_table(const char *path,
			      const struct pq_coldef *cols, int ncols,
			      int64_t nrows, int64_t *const *ints,
			      const struct pq_ba *const *bas)
{
	FILE *f = NULL;
	char tmp[PATH_MAX + 8];
	long off = 4;
	struct pq_chunk_info chunk[AIP_SHADOW_NCOL];
	uint8_t *comp = NULL;
	int rc = -1;
	int nint = 0, nba = 0;

	memset(chunk, 0, sizeof(chunk));
	if (ncols != AIP_SHADOW_NCOL || nrows < 0)
		return -1;
	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -1;
	f = fopen(tmp, "wb");
	if (!f)
		return -1;
	if (fwrite(PQ_PAR1, 1, 4, f) != 4)
		goto out;

	for (int ci = 0; ci < ncols; ci++) {
		const struct pq_coldef *c = &cols[ci];
		const int64_t *col_ints = NULL;
		const struct pq_ba *col_bas = NULL;
		struct pq_buf raw;
		struct tw t;
		size_t clen = 0;
		int64_t vmin, vmax;
		int badp = 0;

		if (c->ph == PQ_BYTE_ARRAY)
			col_bas = bas[nba++];
		else
			col_ints = ints[nint++];

		memset(&raw, 0, sizeof(raw));
		memset(&t, 0, sizeof(t));
		if (build_page(c, nrows, col_ints, col_bas, &raw) != 0)
			badp = 1;
		if (!badp) {
			comp = malloc(as_snappy_max_len(raw.n));
			if (!comp) {
				badp = 1;
			} else if (as_snappy_compress(raw.b, raw.n, comp,
						      &clen) != 0) {
				badp = 1;
			} else {
				chunk[ci].raw_len = raw.n;
				chunk[ci].comp_len = clen;
			}
		}
		if (!badp) {
			tw_init(&t);
			tw_open(&t);
			if (wi32f(&t, 1, 0) != 0 ||		/* DATA_PAGE */
			    wi32f(&t, 2, (int32_t)chunk[ci].raw_len) != 0 ||
			    wi32f(&t, 3, (int32_t)chunk[ci].comp_len) != 0 ||
			    wbegin(&t, 5) != 0 ||
			    wi32f(&t, 1, (int32_t)nrows) != 0 ||
			    wi32f(&t, 2, 0) != 0 ||		/* PLAIN */
			    wi32f(&t, 3, 3) != 0 ||		/* RLE */
			    wi32f(&t, 4, 3) != 0 ||		/* RLE */
			    wend(&t) != 0 ||
			    wstop(&t) != 0)
				badp = 1;
			tw_close(&t);
			chunk[ci].data_page_offset = off;
			chunk[ci].hdr_len = (long)t.b.n;
		}
		if (!badp) {
			col_minmax(c, nrows, col_ints, &vmin, &vmax);
			if (c->ph == PQ_INT32) {
				chunk[ci].stat_len = 4;
				le_into(chunk[ci].stat_min, 4,
					narrow(c->lg, vmin));
				le_into(chunk[ci].stat_max, 4,
					narrow(c->lg, vmax));
			} else if (c->ph == PQ_INT64 || c->ph == PQ_DOUBLE) {
				chunk[ci].stat_len = 8;
				le_into(chunk[ci].stat_min, 8, vmin);
				le_into(chunk[ci].stat_max, 8, vmax);
			}
			if (fwrite(t.b.b, 1, t.b.n, f) != t.b.n ||
			    fwrite(comp, 1, clen, f) != clen)
				badp = 1;
			else
				off += (long)t.b.n + (long)clen;
		}
		buf_free(&raw);
		buf_free(&t.b);
		free(comp);
		comp = NULL;
		if (badp)
			goto out;
	}

	/* footer：FileMetaData{1 ver,2 schema,3 num_rows,4 row_groups,
	 *                       6 created_by} */
	{
		struct tw t;
		uint32_t flen;
		uint8_t len4[4];
		int badf = 0;

		tw_init(&t);
		tw_open(&t);
		if (wi32f(&t, 1, 1) != 0)
			badf = 1;
		if (!badf && wlist(&t, 2, TT_STRUCT, (size_t)ncols + 1) != 0)
			badf = 1;
		if (!badf) {
			tw_open(&t);
			if (wstrf(&t, 4, "schema") != 0 ||
			    wi32f(&t, 5, ncols) != 0 || wstop(&t) != 0)
				badf = 1;
			tw_close(&t);
		}
		for (int ci = 0; !badf && ci < ncols; ci++) {
			const struct pq_coldef *c = &cols[ci];

			tw_open(&t);
			if (wi32f(&t, 1, phys_type(c->ph)) != 0 ||
			    wi32f(&t, 3, 1) != 0 ||		/* OPTIONAL */
			    wstrf(&t, 4, c->name) != 0)
				badf = 1;
			if (!badf && conv_type(c->lg) >= 0 &&
			    wi32f(&t, 6, conv_type(c->lg)) != 0)
				badf = 1;
			if (!badf) {
				if (c->lg == PQ_LG_STR) {
					if (wbegin(&t, 10) != 0 ||
					    wbegin(&t, 1) != 0 ||
					    wend(&t) != 0 || wend(&t) != 0)
						badf = 1;
				} else if (c->lg != PQ_LG_NONE) {
					int bits = c->lg == PQ_LG_I8 ? 8 :
						   c->lg == PQ_LG_I16 ? 16 :
						   c->lg == PQ_LG_I32 ? 32 : 64;

					if (wbegin(&t, 10) != 0 ||
					    wbegin(&t, 10) != 0 ||
					    wfield(&t, 1, TT_BYTE) != 0 ||
					    w8(&t.b, (uint8_t)bits) != 0 ||
					    wfield(&t, 2, TT_TRUE) != 0 ||
					    wend(&t) != 0 || wend(&t) != 0)
						badf = 1;
				}
			}
			if (!badf && wstop(&t) != 0)
				badf = 1;
			tw_close(&t);
		}
		if (!badf && wi64f(&t, 3, nrows) != 0)
			badf = 1;
		if (!badf && wlist(&t, 4, TT_STRUCT, nrows > 0 ? 1 : 0) != 0)
			badf = 1;
		if (!badf && nrows > 0) {
			int64_t sum_unc = 0, sum_comp = 0;

			for (int ci = 0; ci < ncols; ci++) {
				sum_unc += (int64_t)chunk[ci].hdr_len +
					   (int64_t)chunk[ci].raw_len;
				sum_comp += (int64_t)chunk[ci].hdr_len +
					    (int64_t)chunk[ci].comp_len;
			}
			tw_open(&t);			/* RowGroup */
			if (wlist(&t, 1, TT_STRUCT, (size_t)ncols) != 0)
				badf = 1;
			for (int ci = 0; !badf && ci < ncols; ci++) {
				const struct pq_coldef *c = &cols[ci];

				tw_open(&t);		/* ColumnChunk */
				if (wi64f(&t, 2,
					  chunk[ci].data_page_offset) != 0 ||
				    wbegin(&t, 3) != 0)
					badf = 1;
				if (!badf) {
					if (wi32f(&t, 1, phys_type(c->ph)) != 0 ||
					    wlist(&t, 2, TT_I32, 2) != 0 ||
					    wzig(&t.b, 0) != 0 ||	/* PLAIN */
					    wzig(&t.b, 3) != 0 ||	/* RLE */
					    wlist(&t, 3, TT_BIN, 1) != 0 ||
					    wvar(&t.b, strlen(c->name)) != 0 ||
					    wraw(&t.b, c->name,
						 strlen(c->name)) != 0 ||
					    wi32f(&t, 4, 1) != 0 || /* SNAPPY */
					    wi64f(&t, 5, nrows) != 0 ||
					    wi64f(&t, 6,
						  (int64_t)chunk[ci].hdr_len +
						  (int64_t)chunk[ci].raw_len) != 0 ||
					    wi64f(&t, 7,
						  (int64_t)chunk[ci].hdr_len +
						  (int64_t)chunk[ci].comp_len) != 0 ||
					    wi64f(&t, 9,
						  chunk[ci].data_page_offset) != 0)
						badf = 1;
				}
				if (!badf && chunk[ci].stat_len > 0) {
					if (wbegin(&t, 12) != 0 ||
					    wbinf(&t, 1, chunk[ci].stat_max,
						  (size_t)chunk[ci].stat_len) != 0 ||
					    wbinf(&t, 2, chunk[ci].stat_min,
						  (size_t)chunk[ci].stat_len) != 0 ||
					    wi64f(&t, 3, 0) != 0 ||
					    wbinf(&t, 5, chunk[ci].stat_max,
						  (size_t)chunk[ci].stat_len) != 0 ||
					    wbinf(&t, 6, chunk[ci].stat_min,
						  (size_t)chunk[ci].stat_len) != 0 ||
					    wend(&t) != 0)
						badf = 1;
				}
				if (!badf && (wend(&t) != 0 || wstop(&t) != 0))
					badf = 1;
				tw_close(&t);		/* ColumnChunk */
			}
			if (!badf) {
				if (wi64f(&t, 2, sum_unc) != 0 ||
				    wi64f(&t, 3, nrows) != 0 ||
				    wi64f(&t, 6, sum_comp) != 0 ||
				    wstop(&t) != 0)
					badf = 1;
			}
			tw_close(&t);			/* RowGroup */
		}
		if (!badf && (wstrf(&t, 6, PQ_CREATED_BY) != 0 ||
			      wstop(&t) != 0))
			badf = 1;
		tw_close(&t);
		if (badf) {
			buf_free(&t.b);
			goto out;
		}
		flen = (uint32_t)t.b.n;
		le_into(len4, 4, (int64_t)flen);
		if (fwrite(t.b.b, 1, t.b.n, f) != t.b.n ||
		    fwrite(len4, 1, 4, f) != 4 ||
		    fwrite(PQ_PAR1, 1, 4, f) != 4) {
			buf_free(&t.b);
			goto out;
		}
		buf_free(&t.b);
	}
	rc = 0;
out:
	free(comp);
	if (f) {
		if (rc == 0 && (fflush(f) != 0 || fsync(fileno(f)) != 0))
			rc = -1;
		fclose(f);
		if (rc == 0 && rename(tmp, path) != 0)
			rc = -1;
		if (rc != 0)
			unlink(tmp);
	}
	return rc;
}

/* ================= 4. 日期/目录/序号（as_parquet.c 同手法） ================= */

static void civil_from_days(long long z, int *py, int *pm, int *pd)
{
	long long era, y;
	unsigned doe, yoe, doy, mp, d, m;

	z += 719468;
	era = (z >= 0 ? z : z - 146096) / 146097;
	doe = (unsigned)(z - era * 146097);
	yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	y = (long long)yoe + era * 400;
	doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	mp = (5 * doy + 2) / 153;
	d = doy - (153 * mp + 2) / 5 + 1;
	m = mp < 10 ? mp + 3 : mp - 9;
	if (m <= 2)
		y++;
	*py = (int)y;
	*pm = (int)m;
	*pd = (int)d;
}

static void day_str(long long days, char *out)
{
	int y, m, d;
	char tmp[64];

	civil_from_days(days, &y, &m, &d);
	if (y < 0)
		y = 0;
	if (y > 9999)
		y = 9999;
	snprintf(tmp, sizeof(tmp), "%04d-%02d-%02d", y, m, d);
	memcpy(out, tmp, 10);
	out[10] = '\0';
}

static long long floordiv64(long long a, long long b)
{
	long long q = a / b;

	if ((a % b != 0) && ((a < 0) != (b < 0)))
		q--;
	return q;
}

#define NS_PER_DAY	86400000000000LL

/* ts（单调 ns）→ UTC 日串（btime<=0 → 写时今天，REF 同语义） */
static void day_from_ts(int64_t ts_ns, int64_t btime_sec, char *out)
{
	long long sec;

	if (btime_sec > 0)
		sec = btime_sec + floordiv64(ts_ns, 1000000000LL);
	else
		sec = (long long)time(NULL);
	day_str(floordiv64(sec, 86400), out);
}

static int64_t read_btime(void)
{
	FILE *f = fopen("/proc/stat", "r");
	char line[256];
	long long bt = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "btime %lld", &bt) == 1)
			break;
	}
	fclose(f);
	return (int64_t)bt;
}

static int mkdirs(const char *path)
{
	char tmp[600];
	size_t len;

	if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	len = strlen(tmp);
	for (size_t i = 1; i < len; i++) {
		if (tmp[i] == '/') {
			tmp[i] = '\0';
			if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
				return -1;
			}
			tmp[i] = '/';
		}
	}
	if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

long aip_shadow_next_seq(const char *root, const char *day)
{
	char dir[600];
	DIR *d;
	struct dirent *de;
	long max = 0;

	if (snprintf(dir, sizeof(dir), "%s/aipd/%s", root, day) >=
	    (int)sizeof(dir))
		return -1;
	d = opendir(dir);
	if (!d)
		return 1;		/* 无目录=首号 1 */
	while ((de = readdir(d)) != NULL) {
		long seq;

		if (sscanf(de->d_name, "shadow_%ld.parquet", &seq) == 1) {
			if (seq > max)
				max = seq;
		}
	}
	closedir(d);
	return max + 1;
}

/* ================= 5. 影子记录器 ================= */

int aip_shadow_init(struct aip_shadow *s, const struct aip_conf *c)
{
	memset(s, 0, sizeof(*s));
	s->enabled = 1;			/* M1 SHADOW 恒 1 */
	snprintf(s->root, sizeof(s->root), "%s", c->parquet_dir);
	s->flush_sec = c->shadow_flush_sec;
	s->flush_rows = c->shadow_flush_rows;
	/* M2 §1：AI_AGENT_AIPD=6（uapi 镜像值；CANARY_ENABLED=0 → 0
	 * 保持 M1 逐字节等价） */
	s->agent_id = c->canary_enabled ? 6 : 0;
	s->btime = read_btime();
	s->cap = 64;
	s->buf = malloc(s->cap * sizeof(*s->buf));
	if (!s->buf) {
		s->cap = 0;
		return -1;
	}
	return 0;
}

void aip_shadow_feed(struct aip_shadow *s, const struct aip_fvec *v,
		     int stale, const struct aip_decision *d,
		     long long decision_ts_ns, int executed,
		     int model_version)
{
	struct aip_shadow_row *r;

	if (!s->enabled)
		return;
	if (s->n == s->cap) {
		size_t ncap = s->cap * 2;
		struct aip_shadow_row *nb = realloc(s->buf,
						    ncap * sizeof(*nb));

		if (!nb) {
			s->errors++;	/* 缓冲满且无内存：丢批计数（诚实） */
			return;
		}
		s->buf = nb;
		s->cap = ncap;
	}
	r = &s->buf[s->n++];
	memset(r, 0, sizeof(*r));
	r->decision_id = (int64_t)++s->next_id;
	r->trigger_ts = (int64_t)v->ts;
	r->trigger_event_id = (int64_t)v->seq;
	r->decision_ts = decision_ts_ns;
	r->decision_type = (int8_t)d->action;
	r->data[0] = (int64_t)v->lat_ewma_ns;
	r->data[1] = (int64_t)v->iowait_pct;
	r->data[2] = (int64_t)v->psi_mem_some;
	r->data[3] = (int64_t)v->cache_misses;
	r->data[4] = (int64_t)v->valid_bits;
	r->data[5] = stale ? 1 : 0;
	r->data[6] = d->rule_idx;		/* 无命中=-1（如实） */
	r->exec_ts = 0;
	r->outcome_ts = 0;
	r->outcome = 0;
	r->metric_delta = 0;
	r->model_version = (int32_t)model_version;	/* M2 §4：1=builtin
							 * A / 2=file B */
	r->confidence = 100;			/* 静态表确定性 */
	r->domain = 0;
	r->source = 0;
	r->executed = executed ? 1 : 0;		/* M2 §2.2：canary 实发才 1
						 * （M1 恒 0 等价） */
	r->safety_clamped = 0;
	r->agent_id = s->agent_id;		/* M2：0（M1 等价）|6（§1）*/
	r->value = 0.0;
}

int aip_shadow_write_file(const char *path, const struct aip_shadow_row *rows,
			  size_t n)
{
	int64_t *blob;
	int64_t *cols[AIP_SHADOW_NCOL - 1];	/* 32 数值列（ints 路） */
	struct pq_ba *bas;			/* 第 33 列（BA 路）逐行 */
	const struct pq_ba *bacol[1];
	uint8_t src[32];
	size_t srclen;
	int rc;

	if (n == 0 || !rows || !path)
		return -1;
	blob = malloc(n * (AIP_SHADOW_NCOL - 1) * sizeof(int64_t));
	bas = malloc(n * sizeof(*bas));
	if (!blob || !bas) {
		free(blob);
		free(bas);
		return -1;
	}
	/* 数值列 0..31（31 int 列 + 列 31=value DOUBLE 位型）；
	 * BA 列=列位 32（producer 尾列，P-56 改名） */
	for (int c = 0; c < AIP_SHADOW_NCOL - 1; c++)
		cols[c] = blob + n * (size_t)c;
	srclen = strlen(AIP_SHADOW_SOURCE_STR);
	if (srclen > sizeof(src))
		srclen = sizeof(src);
	memcpy(src, AIP_SHADOW_SOURCE_STR, srclen);
	for (size_t r = 0; r < n; r++) {
		const struct aip_shadow_row *d = &rows[r];
		int64_t vbits;
		const int64_t v[AIP_SHADOW_NCOL - 2] = {
			d->decision_id, d->trigger_ts, d->trigger_event_id,
			d->decision_ts, d->decision_type,
			d->data[0], d->data[1], d->data[2], d->data[3],
			d->data[4], d->data[5], d->data[6], d->data[7],
			d->exec_ts, d->outcome_ts, d->outcome,
			d->metric_delta, d->model_version, d->confidence,
			d->domain, d->source, d->executed, d->safety_clamped,
			d->trace_hi, d->trace_lo, d->intent_id, d->parent_id,
			d->agent_id, d->expected, d->cost_ns,
			d->side_effect_mask,
		};

		memcpy(&vbits, &d->value, sizeof(vbits));	/* DOUBLE 位型 */
		for (int c = 0; c < AIP_SHADOW_NCOL - 2; c++)
			cols[c][r] = v[c];
		cols[AIP_SHADOW_NCOL - 2][r] = vbits;
		bas[r].p = src;
		bas[r].n = srclen;
	}
	bacol[0] = bas;
	rc = shadow_write_table(path, shadow_cols, AIP_SHADOW_NCOL,
				(int64_t)n, cols, bacol);
	free(blob);
	free(bas);
	return rc;
}

void aip_shadow_flush(struct aip_shadow *s)
{
	char day[11], dir[600], path[640];
	long seq;
	size_t rows;

	if (!s->enabled || s->n == 0)
		return;
	rows = s->n;
	day_from_ts(s->buf[0].decision_ts, s->btime, day);
	seq = aip_shadow_next_seq(s->root, day);
	if (seq < 1)
		seq = 1;
	if (snprintf(dir, sizeof(dir), "%s/aipd/%s", s->root, day) >=
	    (int)sizeof(dir) ||
	    snprintf(path, sizeof(path), "%s/aipd/%s/shadow_%04ld.parquet",
		     s->root, day, seq) >= (int)sizeof(path)) {
		s->errors++;
		s->n = 0;
		return;
	}
	if (mkdirs(dir) != 0) {
		s->errors++;
		aip_warn_ratelimit("shadow-mkdir", 60000,
				   "shadow mkdir %s: %s (batch dropped)",
				   dir, strerror(errno));
		s->n = 0;
		return;
	}
	if (aip_shadow_write_file(path, s->buf, rows) != 0) {
		s->errors++;
		aip_warn_ratelimit("shadow-write", 60000,
				   "shadow write %s: %s (batch dropped)",
				   path, strerror(errno));
		s->n = 0;
		return;
	}
	{
		struct stat st;

		if (stat(path, &st) == 0)
			s->bytes += (long long)st.st_size;
	}
	s->rows_written += (long long)rows;
	s->files++;
	s->flushes++;
	s->n = 0;
	aip_log_debug("shadow flush: %s (%zu rows)", path, rows);
}

void aip_shadow_close(struct aip_shadow *s)
{
	aip_shadow_flush(s);
	free(s->buf);
	s->buf = NULL;
	s->n = s->cap = 0;
}

/* ================= 6. 对照 mismatch 滚动窗 ================= */

int aip_cmp_init(struct aip_cmp *m, unsigned window)
{
	memset(m, 0, sizeof(*m));
	if (window < 8)
		window = 8;
	m->ring = calloc(window, sizeof(*m->ring));
	if (!m->ring)
		return -1;
	m->cap = window;
	return 0;
}

void aip_cmp_free(struct aip_cmp *m)
{
	free(m->ring);
	m->ring = NULL;
	m->cap = m->count = 0;
}

void aip_cmp_shadow(struct aip_cmp *m, uint32_t action)
{
	m->last_shadow_action = action;
	m->have_shadow = 1;
}

void aip_cmp_observe(struct aip_cmp *m, unsigned long long id, uint32_t action)
{
	struct aip_cmp_ent *e;

	if (!m->cap)
		return;
	/* 窗口滚动：满则弹出最老 */
	if (m->count == m->cap) {
		struct aip_cmp_ent *old = &m->ring[m->head];

		if (old->matched)
			m->matched--;
		else
			m->mismatch--;
		m->head = (m->head + 1) % m->cap;
		m->count--;
	}
	e = &m->ring[(m->head + m->count) % m->cap];
	e->id = id;
	e->matched = (m->have_shadow &&
		      m->last_shadow_action == action) ? 1 : 0;
	if (e->matched)
		m->matched++;
	else
		m->mismatch++;
	m->count++;
	if (!m->have_cursor || id > m->cursor) {
		m->cursor = id;
		m->have_cursor = 1;
	}
}

double aip_cmp_pct(const struct aip_cmp *m)
{
	unsigned tot = (unsigned)(m->matched + m->mismatch);

	if (tot == 0)
		return 0.0;
	return (double)m->mismatch * 100.0 / (double)tot;
}

int aip_cmp_parse_mock_line(const char *line, unsigned long long *id,
			    uint32_t *action)
{
	char *end;
	const char *p;
	unsigned long long v;

	if (!line || !id || !action)
		return -1;
	p = strstr(line, "\"decision_id\":");
	if (!p)
		return -1;
	errno = 0;
	v = strtoull(p + 14, &end, 10);
	if (errno != 0 || end == p + 14)
		return -1;
	*id = v;
	p = strstr(line, "\"action\":");
	if (!p)
		return -1;
	errno = 0;
	v = strtoull(p + 9, &end, 10);
	if (errno != 0 || end == p + 9 || v > 0xffffffffULL)
		return -1;
	*action = (uint32_t)v;
	return 0;
}

int aip_cmp_parse_proc_line(const char *line, unsigned long long *id,
			    uint32_t *type)
{
	unsigned long long rid, t1, evid, t2, e1, ots;
	unsigned long long d[8];
	unsigned dtype, oc, ver, conf, dom, src, exec, sc;
	long long delta;

	if (!line || !id || !type)
		return -1;
	if (sscanf(line,
		   "id=%llu trig_ts=%llu trig_evid=%llx dec_ts=%llu "
		   "type=%u data=%llu:%llu:%llu:%llu:%llu:%llu:%llu:"
		   "%llu exec_ts=%llu outcome_ts=%llu outcome=%u "
		   "delta=%lld ver=%u conf=%u domain=%u src=%u "
		   "executed=%u safety_clamped=%u",
		   &rid, &t1, &evid, &t2, &dtype,
		   &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6], &d[7],
		   &e1, &ots, &oc, &delta, &ver, &conf, &dom, &src,
		   &exec, &sc) != 23)
		return -1;
	*id = rid;
	*type = dtype;
	return 0;
}
