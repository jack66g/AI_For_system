/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_parquet.c - Parquet writer-only 实现（T8；规格见 as_parquet.h）
 *
 * 自包含（仅 libc + as_snappy）：
 *   1. 字节缓冲 + 小端读/写
 *   2. thrift compact 序列化子集（writer）
 *   3. 单表写文件（单 row group / PLAIN / snappy / DataPageV1 /
 *      OPTIONAL 全 1 def-levels / statistics min-max）
 *   4. REF 对齐高层（write_telemetry / write_decisions / write_chains /
 *      update_index + 序号旋转 + UTC 日界）
 *   5. footer FileMetaData 统计读取（thrift compact 反序列化子集；
 *      读边界=footer 统计，不做数据页读取）
 *
 * 有意差异（相对 REF=pyarrow 产出；逐值读回等价，差分按值比较）：
 *   - 编码：REF 默认 dictionary+PLAIN 混合；本 writer 全 PLAIN
 *   - created_by：自家串（不冒充 parquet-cpp）
 *   - index.parquet 行序：路径字典序（REF 为 readdir 序）
 *   - 分页：每列单数据页（REF 大表按 ~1MB 拆页）
 *   - total_*_size：含页头长度
 *   - 离谱 ts（负/超 1e18）：REF 直接 OverflowError 崩溃；此处钳到
 *     btime（落"开机日"）不崩——防御性差异，向量不覆盖该输入
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "aistreamd/as_parquet.h"
#include "aistreamd/as_snappy.h"

#define PQ_PAR1		"PAR1"
#define PQ_CREATED_BY	"aistreamd as_parquet 1.0 (T8 writer-only)"

/* ================= 1. 字节缓冲 ================= */

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

static int64_t rle32b(const uint8_t *p)
{
	return (int64_t)((uint32_t)p[0] | (uint32_t)p[1] << 8 |
			 (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24);
}

static int64_t rle64b(const uint8_t *p)
{
	uint64_t v = 0;

	for (int i = 7; i >= 0; i--)
		v = v << 8 | (uint64_t)p[i];
	return (int64_t)v;
}

static void le_into(uint8_t *dst, int len, int64_t v)
{
	for (int i = 0; i < len; i++)
		dst[i] = (uint8_t)((uint64_t)v >> (8 * i));
}

/* ================= 2. thrift compact writer ================= */
/*
 * 类型码：1=TRUE 2=FALSE 3=BYTE 4=I16 5=I32 6=I64 7=DOUBLE 8=BINARY
 *         9=LIST 10=SET 11=MAP 12=STRUCT；0=STOP
 * 字段头：delta(1..15)<<4|type；delta=0 时 type 后跟 zigzag varint 字段号。
 * struct 字段的布尔值编码在字段头类型位（TRUE/FALSE）。
 */
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

/* struct 字段：写头后进入嵌套作用域（配对 wend） */
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

static int wboolf(struct tw *t, int id, int v)
{
	return wfield(t, id, v ? TT_TRUE : TT_FALSE);
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

/* ================= 3. 列定义与单表写 ================= */

enum pq_ph {
	PQ_INT32,
	PQ_INT64,
	PQ_BYTE_ARRAY,
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

struct pq_ba {
	const uint8_t *p;
	size_t n;
};

/* ConvertedType：UTF8=0 INT_8=15 INT_16=16 INT_32=17 INT_64=18 */
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

/* Parquet 物理类型：INT32=1 INT64=2 BYTE_ARRAY=6 */
static int phys_type(enum pq_ph ph)
{
	switch (ph) {
	case PQ_INT32:	return 1;
	case PQ_INT64:	return 2;
	default:	return 6;
	}
}

/* ---- schema 三套（列名/物理类型/逻辑宽度/顺序逐字段对齐 REF） ---- */

static const struct pq_coldef tel_cols[9] = {
	{ "timestamp_ns",	PQ_INT64,	PQ_LG_I64 },
	{ "pid",		PQ_INT32,	PQ_LG_I32 },
	{ "tgid",		PQ_INT32,	PQ_LG_I32 },
	{ "cpu",		PQ_INT32,	PQ_LG_I16 },
	{ "category",		PQ_INT32,	PQ_LG_I8 },
	{ "event_type",		PQ_INT32,	PQ_LG_I8 },
	{ "severity",		PQ_INT32,	PQ_LG_I8 },
	{ "data_len",		PQ_INT32,	PQ_LG_I16 },
	{ "data",		PQ_BYTE_ARRAY,	PQ_LG_NONE },
};

static const struct pq_coldef dec_cols[23] = {
	{ "decision_id",	PQ_INT64,	PQ_LG_I64 },
	{ "trigger_ts",		PQ_INT64,	PQ_LG_I64 },
	{ "trigger_event_id",	PQ_INT64,	PQ_LG_I64 },
	{ "decision_ts",	PQ_INT64,	PQ_LG_I64 },
	{ "decision_type",	PQ_INT32,	PQ_LG_I8 },
	{ "data_0",		PQ_INT64,	PQ_LG_I64 },
	{ "data_1",		PQ_INT64,	PQ_LG_I64 },
	{ "data_2",		PQ_INT64,	PQ_LG_I64 },
	{ "data_3",		PQ_INT64,	PQ_LG_I64 },
	{ "data_4",		PQ_INT64,	PQ_LG_I64 },
	{ "data_5",		PQ_INT64,	PQ_LG_I64 },
	{ "data_6",		PQ_INT64,	PQ_LG_I64 },
	{ "data_7",		PQ_INT64,	PQ_LG_I64 },
	{ "exec_ts",		PQ_INT64,	PQ_LG_I64 },
	{ "outcome_ts",		PQ_INT64,	PQ_LG_I64 },
	{ "outcome",		PQ_INT32,	PQ_LG_I8 },
	{ "metric_delta",	PQ_INT64,	PQ_LG_I64 },
	{ "model_version",	PQ_INT32,	PQ_LG_I32 },
	{ "confidence",		PQ_INT32,	PQ_LG_I8 },
	{ "domain",		PQ_INT32,	PQ_LG_I8 },
	{ "source",		PQ_INT32,	PQ_LG_I8 },
	{ "executed",		PQ_INT32,	PQ_LG_I8 },
	{ "safety_clamped",	PQ_INT32,	PQ_LG_I8 },
};

static const struct pq_coldef idx_cols[6] = {
	{ "file",		PQ_BYTE_ARRAY,	PQ_LG_STR },
	{ "date",		PQ_BYTE_ARRAY,	PQ_LG_STR },
	{ "category",		PQ_INT32,	PQ_LG_I8 },
	{ "records",		PQ_INT64,	PQ_LG_I64 },
	{ "start_ts",		PQ_INT64,	PQ_LG_I64 },
	{ "end_ts",		PQ_INT64,	PQ_LG_I64 },
};

#define TEL_NCOL	9
#define DEC_NCOL	23
#define IDX_NCOL	6
#define PQ_MAXCOL	24

/* 数值窄化到逻辑宽度（符号语义保持；编码按物理宽度） */
static int64_t narrow(enum pq_lg lg, int64_t v)
{
	switch (lg) {
	case PQ_LG_I8:	return (int8_t)v;
	case PQ_LG_I16:	return (int16_t)v;
	case PQ_LG_I32:	return (int32_t)v;
	default:	return v;
	}
}

static int build_page(const struct pq_coldef *c, int64_t nrows,
		      const int64_t *ints, const struct pq_ba *bas,
		      struct pq_buf *raw)
{
	/* def-levels：max_def=1 → bit width 1；全 1 → RLE run：
	 * 头 varint = (n<<1)|0（LSB=0=RLE run，count=n；LSB=1 是
	 * bit-packed 组数——勿混），值 0x01 占 ceil(1/8)=1 字节；
	 * 前置 4 字节小端段长（DataPageV1 levels 布局；与 pyarrow
	 * PLAIN+V1 页逐字节对照核实） */
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

/* 统计原始值（min/max 按窄化后的序比较） */
static void col_minmax(const struct pq_coldef *c, int64_t nrows,
		       const int64_t *ints, int64_t *pmin, int64_t *pmax)
{
	int64_t mn = 0, mx = 0;

	if (c->ph != PQ_BYTE_ARRAY && nrows > 0) {
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
	int stat_len;			/* 0=无 min/max（BA 列） */
	uint8_t stat_min[8], stat_max[8];
};

/*
 * pq_write_table - 单表写文件（存在即覆盖）。返回 0/-1。
 * ints[]/bas[]：数值列与 BA 列按各自声明顺序供给（int64 值）。
 */
static int pq_write_table(const char *path, const struct pq_coldef *cols,
			  int ncols, int64_t nrows,
			  int64_t *const *ints, const struct pq_ba *const *bas)
{
	FILE *f = NULL;
	long off = 4;
	struct pq_chunk_info chunk[PQ_MAXCOL];
	uint8_t *comp = NULL;
	int rc = -1;
	int nint = 0, nba = 0;

	memset(chunk, 0, sizeof(chunk));
	if (ncols < 1 || ncols > PQ_MAXCOL || nrows < 0)
		return -1;
	f = fopen(path, "wb");
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
		int bad = 0;

		if (c->ph == PQ_BYTE_ARRAY) {
			col_bas = bas[nba++];
		} else {
			col_ints = ints[nint++];
		}

		memset(&raw, 0, sizeof(raw));
		memset(&t, 0, sizeof(t));
		if (build_page(c, nrows, col_ints, col_bas, &raw) != 0)
			bad = 1;
		if (!bad) {
			comp = malloc(as_snappy_max_len(raw.n));
			if (!comp) {
				bad = 1;
			} else if (as_snappy_compress(raw.b, raw.n, comp,
						      &clen) != 0) {
				bad = 1;
			} else {
				chunk[ci].raw_len = raw.n;
				chunk[ci].comp_len = clen;
			}
		}
		if (!bad) {
			/* PageHeader{1 type,2 unc,3 comp,5 data_page_header} */
			tw_init(&t);
			tw_open(&t);
			if (wi32f(&t, 1, 0) != 0 ||		/* DATA_PAGE */
			    wi32f(&t, 2, (int32_t)chunk[ci].raw_len) != 0 ||
			    wi32f(&t, 3, (int32_t)chunk[ci].comp_len) != 0 ||
			    wbegin(&t, 5) != 0 ||	/* data_page_header */
			    wi32f(&t, 1, (int32_t)nrows) != 0 ||
			    wi32f(&t, 2, 0) != 0 ||		/* PLAIN */
			    wi32f(&t, 3, 3) != 0 ||		/* RLE */
			    wi32f(&t, 4, 3) != 0 ||		/* RLE */
			    wend(&t) != 0 ||
			    wstop(&t) != 0)
				bad = 1;
			tw_close(&t);
			chunk[ci].data_page_offset = off;
			chunk[ci].hdr_len = (long)t.b.n;
		}
		if (!bad) {
			col_minmax(c, nrows, col_ints, &vmin, &vmax);
			if (c->ph == PQ_INT32) {
				chunk[ci].stat_len = 4;
				le_into(chunk[ci].stat_min, 4,
					narrow(c->lg, vmin));
				le_into(chunk[ci].stat_max, 4,
					narrow(c->lg, vmax));
			} else if (c->ph == PQ_INT64) {
				chunk[ci].stat_len = 8;
				le_into(chunk[ci].stat_min, 8, vmin);
				le_into(chunk[ci].stat_max, 8, vmax);
			}
			if (fwrite(t.b.b, 1, t.b.n, f) != t.b.n ||
			    fwrite(comp, 1, clen, f) != clen)
				bad = 1;
			else
				off += (long)t.b.n + (long)clen;
		}
		buf_free(&raw);
		buf_free(&t.b);
		free(comp);
		comp = NULL;
		if (bad)
			goto out;
	}

	/* ---- footer：FileMetaData{1 version,2 schema,3 num_rows,
	 *                       4 row_groups,6 created_by} ---- */
	{
		struct tw t;
		uint32_t flen;
		uint8_t len4[4];
		int bad = 0;

		tw_init(&t);
		tw_open(&t);
		if (wi32f(&t, 1, 1) != 0)
			bad = 1;
		/* schema：root{4 name,5 num_children} + 叶{1 type,3 repetition,
		 * 4 name,6 converted_type,10 logicalType} */
		if (!bad && wlist(&t, 2, TT_STRUCT, (size_t)ncols + 1) != 0)
			bad = 1;
		if (!bad) {
			tw_open(&t);
			if (wstrf(&t, 4, "schema") != 0 ||
			    wi32f(&t, 5, ncols) != 0 || wstop(&t) != 0)
				bad = 1;
			tw_close(&t);
		}
		for (int ci = 0; !bad && ci < ncols; ci++) {
			const struct pq_coldef *c = &cols[ci];

			tw_open(&t);
			if (wi32f(&t, 1, phys_type(c->ph)) != 0 ||
			    wi32f(&t, 3, 1) != 0 ||		/* OPTIONAL */
			    wstrf(&t, 4, c->name) != 0)
				bad = 1;
			if (!bad && conv_type(c->lg) >= 0 &&
			    wi32f(&t, 6, conv_type(c->lg)) != 0)
				bad = 1;
			if (!bad) {
				if (c->lg == PQ_LG_STR) {
					if (wbegin(&t, 10) != 0 ||	/* logical */
					    wbegin(&t, 1) != 0 ||	/* STRING */
					    wend(&t) != 0 || wend(&t) != 0)
						bad = 1;
				} else if (c->lg != PQ_LG_NONE) {
					int bits = c->lg == PQ_LG_I8 ? 8 :
						   c->lg == PQ_LG_I16 ? 16 :
						   c->lg == PQ_LG_I32 ? 32 : 64;

					if (wbegin(&t, 10) != 0 ||
					    wbegin(&t, 10) != 0 ||	/* INTEGER */
					    wfield(&t, 1, TT_BYTE) != 0 ||
					    w8(&t.b, (uint8_t)bits) != 0 ||
					    wboolf(&t, 2, 1) != 0 ||/* signed */
					    wend(&t) != 0 || wend(&t) != 0)
						bad = 1;
				}
			}
			if (!bad && wstop(&t) != 0)
				bad = 1;
			tw_close(&t);
		}
		if (!bad && wi64f(&t, 3, nrows) != 0)
			bad = 1;
		if (!bad && wlist(&t, 4, TT_STRUCT, nrows > 0 ? 1 : 0) != 0)
			bad = 1;
		if (!bad && nrows > 0) {
			int64_t sum_unc = 0, sum_comp = 0;

			for (int ci = 0; ci < ncols; ci++) {
				sum_unc += (int64_t)chunk[ci].hdr_len +
					   (int64_t)chunk[ci].raw_len;
				sum_comp += (int64_t)chunk[ci].hdr_len +
					    (int64_t)chunk[ci].comp_len;
			}
			tw_open(&t);				/* RowGroup */
			if (wlist(&t, 1, TT_STRUCT, (size_t)ncols) != 0)
				bad = 1;
			for (int ci = 0; !bad && ci < ncols; ci++) {
				const struct pq_coldef *c = &cols[ci];

				tw_open(&t);			/* ColumnChunk */
				if (wi64f(&t, 2,
					  chunk[ci].data_page_offset) != 0 ||
				    wbegin(&t, 3) != 0)		/* meta_data */
					bad = 1;
				if (!bad) {
					if (wi32f(&t, 1, phys_type(c->ph)) != 0 ||
					    wlist(&t, 2, TT_I32, 2) != 0 ||
					    wzig(&t.b, 0) != 0 ||	/* PLAIN */
					    wzig(&t.b, 3) != 0 ||	/* RLE */
					    wlist(&t, 3, TT_BIN, 1) != 0 ||
					    /* 列表元素=裸值（varint 长+字节），
					     * 勿写字段头 */
					    wvar(&t.b, strlen(c->name)) != 0 ||
					    wraw(&t.b, c->name,
						 strlen(c->name)) != 0 ||
					    wi32f(&t, 4, 1) != 0 ||  /* SNAPPY */
					    wi64f(&t, 5, nrows) != 0 ||
					    wi64f(&t, 6,
						  (int64_t)chunk[ci].hdr_len +
						  (int64_t)chunk[ci].raw_len) != 0 ||
					    wi64f(&t, 7,
						  (int64_t)chunk[ci].hdr_len +
						  (int64_t)chunk[ci].comp_len) != 0 ||
					    wi64f(&t, 9,
						  chunk[ci].data_page_offset) != 0)
						bad = 1;
				}
				if (!bad && chunk[ci].stat_len > 0) {
					if (wbegin(&t, 12) != 0 ||  /* Statistics */
					    wbinf(&t, 1, chunk[ci].stat_max,
						  (size_t)chunk[ci].stat_len) != 0 ||
					    wbinf(&t, 2, chunk[ci].stat_min,
						  (size_t)chunk[ci].stat_len) != 0 ||
					    wi64f(&t, 3, 0) != 0 || /* nulls=0 */
					    wbinf(&t, 5, chunk[ci].stat_max,
						  (size_t)chunk[ci].stat_len) != 0 ||
					    wbinf(&t, 6, chunk[ci].stat_min,
						  (size_t)chunk[ci].stat_len) != 0 ||
					    wend(&t) != 0)
						bad = 1;
				}
				if (!bad && (wend(&t) != 0 || wstop(&t) != 0))
					bad = 1;
				tw_close(&t);			/* ColumnChunk */
			}
			if (!bad) {
				if (wi64f(&t, 2, sum_unc) != 0 ||
				    wi64f(&t, 3, nrows) != 0 ||
				    wi64f(&t, 6, sum_comp) != 0 ||
				    wstop(&t) != 0)
					bad = 1;
			}
			tw_close(&t);				/* RowGroup */
		}
		if (!bad && (wstrf(&t, 6, PQ_CREATED_BY) != 0 ||
			     wstop(&t) != 0))
			bad = 1;
		tw_close(&t);
		if (bad) {
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
	if (f)
		fclose(f);
	return rc;
}

/* ================= 4. 日期 / btime / 目录 / 序号 ================= */

/* days(1970-01-01=0) → 公历（Hinnant civil_from_days） */
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

static void day_str(long long days, char *out /*11*/)
{
	int y, m, d;
	char tmp[64];

	civil_from_days(days, &y, &m, &d);
	/* 年份钳到四位（溢出输入的防御；正常输入恒在范围内） */
	if (y < 0)
		y = 0;
	if (y > 9999)
		y = 9999;
	snprintf(tmp, sizeof(tmp), "%04d-%02d-%02d", y, m, d);
	memcpy(out, tmp, 10);
	out[10] = '\0';
}

/* 向下取整除（负数安全；正常遥测 ts 非负） */
static long long floordiv64(long long a, long long b)
{
	long long q = a / b;

	if ((a % b != 0) && ((a < 0) != (b < 0)))
		q--;
	return q;
}

#define NS_PER_DAY	86400000000000LL

/*
 * REF _ts_to_day：sec = btime + ts_ns/1e9（float64）后取 UTC 日期。
 * 此处整数实现：days = floor((btime*1e9 + ts_ns) / 86400e9)。
 * 两者仅在距 UTC 午夜 <1µs（float64 精度）时可能分歧——向量避开该窗。
 */
void as_pq_day_from_ts(int64_t ts_ns, int64_t btime_sec, char *out)
{
	long long days;

	if (btime_sec > 0) {
		int64_t wall = btime_sec * 1000000000LL + ts_ns;

		/* 防 int64 溢出：ts 钳到 [0, 1e18]（REF 对离谱 ts 会
		 * OverflowError 崩溃——防御性差异，见文件头注释） */
		if (ts_ns < 0 || ts_ns > (int64_t)1000000000000000000LL)
			wall = btime_sec * 1000000000LL;
		days = floordiv64(wall, NS_PER_DAY);
	} else {
		days = (long long)time(NULL) / 86400;
	}
	day_str(days, out);
}

int64_t as_pq_btime(void)
{
	FILE *f = fopen("/proc/stat", "r");
	char line[256];
	long long bt = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "btime ", 6) == 0) {
			bt = strtoll(line + 6, NULL, 10);
			break;
		}
	}
	fclose(f);
	return bt > 0 ? bt : -1;
}

/* mkdir -p（逐组件；EEXIST 容忍；path 会被破坏性修改） */
static int mkdirs(char *path)
{
	for (char *p = path + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(path, 0755) != 0 && errno != EEXIST) {
				*p = '/';
				return -1;
			}
			*p = '/';
		}
	}
	if (mkdir(path, 0755) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

int as_pq_ensure_root(const char *root)
{
	char p[512];

	snprintf(p, sizeof(p), "%s/telemetry", root);
	if (mkdirs(p) != 0)
		return -1;
	snprintf(p, sizeof(p), "%s/decisions", root);
	if (mkdirs(p) != 0)
		return -1;
	snprintf(p, sizeof(p), "%s/models", root);
	if (mkdirs(p) != 0)
		return -1;
	return 0;
}

/* CAT_NAMES 对齐 REF（1..18；未知 cat%02d） */
void as_pq_cat_name(int category, char *out, size_t cap)
{
	static const char *const names[19] = {
		NULL,
		"sched", "mm", "io", "net", "user_input",
		"process", "fs", "security", "interrupt", "lock",
		"time", "power", "virt", "bpf", "user_behavior",
		"hw", "kconfig", "ai",
	};

	if (category >= 1 && category <= 18)
		snprintf(out, cap, "%s", names[category]);
	else
		snprintf(out, cap, "cat%02d", category);
}

/*
 * next_seq 对齐 REF _next_seq：dir 下 prefix_<digits>.parquet 最大序号+1
 * （无=0）。匹配语义同 REF regex `_(\d+)\.parquet$`：最后一个 '_' 到
 * .parquet 之间为纯数字（"sched_1_2.parquet" 取 2）。
 */
static long next_seq(const char *dir, const char *prefix)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	size_t plen = strlen(prefix);
	long seq = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL) {
		const char *nm = e->d_name;
		size_t n = strlen(nm);
		const char *lastu = NULL, *q, *digend;
		int ndig;
		long v = 0;

		if (strncmp(nm, prefix, plen) != 0 || nm[plen] != '_')
			continue;
		if (n < 12 || strcmp(nm + n - 8, ".parquet") != 0)
			continue;
		for (q = nm; *q; q++)
			if (*q == '_')
				lastu = q;
		/* nm[plen]=='_' 已保证 lastu >= nm+plen（分隔符即合法
		 * 候选——"process_0000.parquet" 的 lastu 就是它）。
		 * 数字区 = lastu+1 .. .parquet 前（REF regex 语义） */
		if (!lastu)
			continue;
		digend = nm + n - 8;
		for (q = lastu + 1; q < digend; q++)
			if (*q < '0' || *q > '9')
				break;
		ndig = (int)(q - (lastu + 1));
		if (ndig == 0 || ndig > 9 || q != digend)
			continue;
		for (q = lastu + 1; q < digend; q++)
			v = v * 10 + (*q - '0');
		if (v + 1 > seq)
			seq = v + 1;
	}
	closedir(d);
	return seq;
}

/* ================= 5. REF 对齐高层写 ================= */

static void add_stat(struct pq_write_stat *st, const char *path)
{
	struct stat sb;

	if (stat(path, &sb) == 0) {
		st->files++;
		st->bytes += (long long)sb.st_size;
	}
}

static int cmp_i64(const void *a, const void *b)
{
	int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;

	return x < y ? -1 : x > y ? 1 : 0;
}

int as_pq_write_telemetry(const char *root, const struct pq_tel_row *rows,
			  size_t n, int64_t btime_sec, size_t chunk_max,
			  struct pq_write_stat *wstat)
{
	int cats[256];
	size_t catn = 0;
	long total = 0;
	struct pq_write_stat local = { 0, 0 };
	int rc_ret = -1;

	if (n == 0)
		return 0;
	if (!rows || chunk_max == 0)
		return -1;

	memset(cats, 0, sizeof(cats));
	for (size_t i = 0; i < n; i++) {
		int c = rows[i].category;
		int seen = 0;

		for (size_t k = 0; k < catn; k++)
			if (cats[k] == c) {
				seen = 1;
				break;
			}
		if (!seen && catn < 256)
			cats[catn++] = c;
	}
	qsort(cats, catn, sizeof(cats[0]), cmp_i64);

	for (size_t k = 0; k < catn; k++) {
		int cat = cats[k];
		size_t cnt = 0;
		struct pq_tel_row *grp = malloc(n * sizeof(*grp));
		size_t *idx = NULL;
		char day[11], dir[512], prefix[16];

		if (!grp)
			goto out;
		for (size_t i = 0; i < n; i++)
			if (rows[i].category == cat)
				grp[cnt++] = rows[i];
		/* 组内按 ts 稳定排序（插入排序天然稳定，同 ts 保输入序） */
		idx = malloc(cnt * sizeof(*idx));
		if (!idx) {
			free(grp);
			goto out;
		}
		for (size_t i = 0; i < cnt; i++)
			idx[i] = i;
		for (size_t i = 1; i < cnt; i++) {
			size_t cur = idx[i];
			size_t j = i;

			while (j > 0 && grp[idx[j - 1]].ts_ns > grp[cur].ts_ns) {
				idx[j] = idx[j - 1];
				j--;
			}
			idx[j] = cur;
		}

		as_pq_day_from_ts(grp[idx[0]].ts_ns, btime_sec, day);
		snprintf(dir, sizeof(dir), "%s/telemetry/%s", root, day);
		if (mkdirs(dir) != 0) {
			free(grp);
			free(idx);
			goto out;
		}
		as_pq_cat_name(cat, prefix, sizeof(prefix));
		for (size_t i = 0; i < cnt; i += chunk_max) {
			size_t clen = cnt - i < chunk_max ? cnt - i : chunk_max;
			long seq = next_seq(dir, prefix);
			char path[600];
			int64_t *cols[8];
			int64_t *blob = malloc(clen * 8 * sizeof(int64_t));
			struct pq_ba *ba = malloc(clen * sizeof(*ba));
			struct pq_ba *bp[1];
			int bad = 0;

			if (!blob || !ba) {
				free(blob);
				free(ba);
				free(grp);
				free(idx);
				goto out;
			}
			for (int c = 0; c < 8; c++)
				cols[c] = blob + clen * (size_t)c;
			for (size_t r = 0; r < clen; r++) {
				const struct pq_tel_row *tr = &grp[idx[i + r]];

				cols[0][r] = tr->ts_ns;
				cols[1][r] = tr->pid;
				cols[2][r] = tr->tgid;
				cols[3][r] = tr->cpu;
				cols[4][r] = tr->category;
				cols[5][r] = tr->event_type;
				cols[6][r] = tr->severity;
				cols[7][r] = tr->data_len;
				ba[r].p = tr->data;
				ba[r].n = (size_t)(tr->data_len < 0 ?
						   0 : tr->data_len);
			}
			bp[0] = ba;
			snprintf(path, sizeof(path), "%s/%s_%04ld.parquet",
				 dir, prefix, seq);
			if (pq_write_table(path, tel_cols, TEL_NCOL,
					   (int64_t)clen,
					   (int64_t *const *)cols,
					   (const struct pq_ba *const *)bp) != 0)
				bad = 1;
			free(blob);
			free(ba);
			if (bad) {
				free(grp);
				free(idx);
				goto out;
			}
			add_stat(&local, path);
			total += (long)clen;
		}
		free(grp);
		free(idx);
	}
	if (total > 0) {
		long sk = 0;

		if (as_pq_update_index(root, &sk) != 0)
			goto out;
	}
	if (wstat)
		*wstat = local;
	rc_ret = (int)total;
out:
	return rc_ret;
}

static int write_dec_table(const char *root, const struct pq_dec_row *rows,
			   size_t n, int64_t btime_sec, int chains,
			   struct pq_write_stat *wstat)
{
	char day[11], dir[512], path[600];
	int64_t *blob;
	int64_t *cols[DEC_NCOL];
	int64_t ts0 = chains ? rows[0].trigger_ts : rows[0].decision_ts;
	int rc;

	if (n == 0)
		return 0;
	as_pq_day_from_ts(ts0, btime_sec, day);
	snprintf(dir, sizeof(dir), "%s/decisions/%s", root, day);
	if (mkdirs(dir) != 0)
		return -1;
	blob = malloc(n * DEC_NCOL * sizeof(int64_t));
	if (!blob)
		return -1;
	for (int c = 0; c < DEC_NCOL; c++)
		cols[c] = blob + n * (size_t)c;
	for (size_t r = 0; r < n; r++) {
		const struct pq_dec_row *d = &rows[r];
		const int64_t v[DEC_NCOL] = {
			d->decision_id, d->trigger_ts, d->trigger_event_id,
			d->decision_ts, d->decision_type,
			d->data[0], d->data[1], d->data[2], d->data[3],
			d->data[4], d->data[5], d->data[6], d->data[7],
			d->exec_ts, d->outcome_ts, d->outcome,
			d->metric_delta, d->model_version, d->confidence,
			d->domain, d->source, d->executed, d->safety_clamped,
		};

		for (int c = 0; c < DEC_NCOL; c++)
			cols[c][r] = v[c];
	}
	if (chains)
		snprintf(path, sizeof(path), "%s/chains_%s.parquet", dir, day);
	else
		snprintf(path, sizeof(path), "%s/decisions.parquet", dir);
	rc = pq_write_table(path, dec_cols, DEC_NCOL, (int64_t)n,
			    (int64_t *const *)cols, NULL);
	free(blob);
	if (rc != 0)
		return -1;
	if (wstat)
		add_stat(wstat, path);
	return (int)n;
}

int as_pq_write_decisions(const char *root, const struct pq_dec_row *rows,
			  size_t n, int64_t btime_sec,
			  struct pq_write_stat *wstat)
{
	return write_dec_table(root, rows, n, btime_sec, 0, wstat);
}

int as_pq_write_chains(const char *root, const struct pq_dec_row *rows,
		       size_t n, int64_t btime_sec,
		       struct pq_write_stat *wstat)
{
	return write_dec_table(root, rows, n, btime_sec, 1, wstat);
}

/* ================= 6. index 重建 ================= */

/* 名字匹配 telemetry 数据文件（同 REF glob "*_*.parquet" 去掉 index） */
static int is_tel_data_file(const char *nm)
{
	size_t n = strlen(nm);

	if (n < 9 || strcmp(nm + n - 8, ".parquet") != 0)
		return 0;
	if (strchr(nm, '_') == NULL)
		return 0;
	if (n >= 12 && strcmp(nm + n - 12, "index.parquet") == 0)
		return 0;
	return 1;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* index 重建内部行（date/date_len 为两遍填充的暂存） */
struct pq_idx_row {
	const char *file;
	const char *date;
	size_t date_len;
	int8_t category;
	int64_t records;
	int64_t start_ts;
	int64_t end_ts;
};

int as_pq_update_index(const char *root, long *skipped)
{
	char teldir[512];
	DIR *dir = NULL;
	struct dirent *e;
	char **paths = NULL;
	size_t np = 0, pcap = 0;
	int rc = -1;

	snprintf(teldir, sizeof(teldir), "%s/telemetry", root);
	dir = opendir(teldir);
	if (!dir)
		return -1;
	while ((e = readdir(dir)) != NULL) {
		char sub[1024];
		DIR *sd;
		struct dirent *se;

		if (e->d_name[0] == '.')
			continue;
		snprintf(sub, sizeof(sub), "%s/%s", teldir, e->d_name);
		sd = opendir(sub);
		if (!sd)
			continue;
		while ((se = readdir(sd)) != NULL) {
			char rel[600];

			if (se->d_name[0] == '.')
				continue;
			if (!is_tel_data_file(se->d_name))
				continue;
			snprintf(rel, sizeof(rel), "telemetry/%s/%s",
				 e->d_name, se->d_name);
			if (np == pcap) {
				char **nb = realloc(paths,
						    (pcap ? pcap * 2 : 16) *
						    sizeof(*nb));

				if (!nb)
					goto out;
				paths = nb;
				pcap = pcap ? pcap * 2 : 16;
			}
			paths[np] = strdup(rel);
			if (!paths[np])
				goto out;
			np++;
		}
		closedir(sd);
	}
	closedir(dir);
	dir = NULL;

	qsort(paths, np, sizeof(paths[0]), cmp_str);

	/* 两遍：先取各文件统计（记录 file/date 字符串长度与统计），
	 * 再一次性建 arena 与列数组（避免 realloc 悬指针） */
	{
		size_t nr = 0, arena_sz = 0;
		struct pq_idx_row *irows = malloc((np ? np : 1) *
						  sizeof(*irows));
		size_t *flens = malloc((np ? np : 1) * sizeof(*flens));
		size_t *dlens = malloc((np ? np : 1) * sizeof(*dlens));
		char *arena = NULL, *cur;
		int64_t *blob = NULL, *cols[4];
		struct pq_ba *bas = NULL;
		struct pq_ba *bp[2];
		char ipath[600];
		int ok;

		if (!irows || !flens || !dlens)
			goto out_tbl;
		for (size_t i = 0; i < np; i++) {
			const char *rel = paths[i];
			const char *slash1 = strchr(rel, '/');
			const char *slash2;
			char full[1024];
			struct pq_file_stats fs;

			if (!slash1)
				continue;
			slash2 = strchr(slash1 + 1, '/');
			if (!slash2)
				continue;
			snprintf(full, sizeof(full), "%s/%s", root, rel);
			if (as_pq_file_stats(full, &fs) != 0) {
				if (skipped)
					(*skipped)++;
				continue;	/* REF：异常静默跳过；此处计数 */
			}
			irows[nr].file = rel;	/* 暂指向 paths[i]（strdup 稳定） */
			irows[nr].date = slash1 + 1;
			irows[nr].date_len = (size_t)(slash2 - slash1 - 1);
			irows[nr].category =
				fs.has_cat ? (int8_t)fs.cat_max : 0;
			irows[nr].records = fs.num_rows;
			irows[nr].start_ts = fs.has_ts ? fs.ts_min : 0;
			irows[nr].end_ts = fs.has_ts ? fs.ts_max : 0;
			flens[nr] = strlen(rel);
			dlens[nr] = irows[nr].date_len;
			arena_sz += flens[nr] + 1 + dlens[nr] + 1;
			nr++;
		}
		arena = malloc(arena_sz ? arena_sz : 1);
		blob = malloc((nr ? nr : 1) * 4 * sizeof(int64_t));
		bas = malloc((nr ? nr : 1) * 2 * sizeof(*bas));
		if (!arena || !blob || !bas)
			goto out_tbl;
		for (int c = 0; c < 4; c++)
			cols[c] = blob + nr * (size_t)c;
		bp[0] = bas;
		bp[1] = bas + nr;
		cur = arena;
		for (size_t i = 0; i < nr; i++) {
			char *fslot = cur;
			char *dslot;

			memcpy(fslot, irows[i].file, flens[i]);
			fslot[flens[i]] = '\0';
			cur += flens[i] + 1;
			dslot = cur;
			memcpy(dslot, irows[i].date, dlens[i]);
			dslot[dlens[i]] = '\0';
			cur += dlens[i] + 1;
			cols[0][i] = irows[i].category;
			cols[1][i] = irows[i].records;
			cols[2][i] = irows[i].start_ts;
			cols[3][i] = irows[i].end_ts;
			bas[i].p = (const uint8_t *)fslot;
			bas[i].n = flens[i];
			bas[nr + i].p = (const uint8_t *)dslot;
			bas[nr + i].n = dlens[i];
		}
		snprintf(ipath, sizeof(ipath), "%s/telemetry/index.parquet",
			 root);
		ok = pq_write_table(ipath, idx_cols, IDX_NCOL, (int64_t)nr,
				    (int64_t *const *)cols,
				    (const struct pq_ba *const *)bp);
		if (ok != 0)
			goto out_tbl;
	}
	rc = 0;
out_tbl:
	;
out:
	if (dir)
		closedir(dir);
	for (size_t i = 0; i < np; i++)
		free(paths[i]);
	free(paths);
	return rc;
}

/* ================= 7. footer 统计读取（thrift compact reader） ====== */

struct tr {
	const uint8_t *p, *end;
	int last[16];
	int depth;
};

static int rbyte(struct tr *r, uint8_t *out)
{
	if (r->p >= r->end)
		return -1;
	*out = *r->p++;
	return 0;
}

static int rvar(struct tr *r, uint64_t *out)
{
	uint64_t v = 0;
	int shift = 0;

	while (1) {
		uint8_t b;

		if (rbyte(r, &b) != 0)
			return -1;
		v |= (uint64_t)(b & 0x7f) << shift;
		if (!(b & 0x80))
			break;
		shift += 7;
		if (shift > 63)
			return -1;
	}
	*out = v;
	return 0;
}

static int rzig(struct tr *r, int64_t *out)
{
	uint64_t u;

	if (rvar(r, &u) != 0)
		return -1;
	*out = (int64_t)(u >> 1) ^ -(int64_t)(u & 1);
	return 0;
}

/* 读字段头：1=字段(id,type)；0=STOP；-1=截断 */
static int rfield(struct tr *r, int *id, int *type)
{
	uint8_t b;
	int delta;

	if (rbyte(r, &b) != 0)
		return -1;
	if (b == 0)
		return 0;
	*type = b & 0xf;
	delta = b >> 4;
	if (delta == 0) {
		int64_t fid;

		if (rzig(r, &fid) != 0)
			return -1;
		*id = (int)fid;
	} else {
		*id = r->last[r->depth] + delta;
	}
	r->last[r->depth] = *id;
	return 1;
}

static void ropen(struct tr *r)
{
	r->depth++;
	r->last[r->depth] = 0;
}

static void rclose(struct tr *r)
{
	r->depth--;
}

static int rbin(struct tr *r, const uint8_t **p, size_t *n)
{
	uint64_t len;

	if (rvar(r, &len) != 0 || (size_t)(r->end - r->p) < len)
		return -1;
	*p = r->p;
	*n = (size_t)len;
	r->p += len;
	return 0;
}

static int rskip(struct tr *r, int type);

static int rskip_list(struct tr *r)
{
	uint8_t h;
	int etype;
	size_t n;

	if (rbyte(r, &h) != 0)
		return -1;
	etype = h & 0xf;
	if ((h >> 4) == 15) {
		uint64_t v;

		if (rvar(r, &v) != 0 || v > (1u << 24))
			return -1;
		n = (size_t)v;
	} else {
		n = (size_t)(h >> 4);
	}
	for (size_t i = 0; i < n; i++) {
		if (etype == TT_STRUCT) {
			int id, type, rf;

			ropen(r);
			while ((rf = rfield(r, &id, &type)) == 1) {
				if (rskip(r, type) != 0)
					return -1;
			}
			if (rf < 0)
				return -1;
			rclose(r);
		} else if (rskip(r, etype) != 0) {
			return -1;
		}
	}
	return 0;
}

static int rskip(struct tr *r, int type)
{
	switch (type) {
	case TT_TRUE:
	case TT_FALSE:
		return 0;
	case TT_BYTE:
		if (r->p >= r->end)
			return -1;
		r->p++;
		return 0;
	case TT_I16:
	case TT_I32:
	case TT_I64: {
		int64_t v;

		return rzig(r, &v);
	}
	case TT_DOUBLE:
		if ((size_t)(r->end - r->p) < 8)
			return -1;
		r->p += 8;
		return 0;
	case TT_BIN: {
		const uint8_t *p;
		size_t n;

		return rbin(r, &p, &n);
	}
	case TT_LIST:
	case TT_SET:
		return rskip_list(r);
	case TT_MAP:
		/* footer 元数据不含 MAP；出现即按损坏拒绝 */
		return -1;
	case TT_STRUCT: {
		int id, type, rf;

		ropen(r);
		while ((rf = rfield(r, &id, &type)) == 1) {
			if (rskip(r, type) != 0)
				return -1;
		}
		if (rf < 0)
			return -1;
		rclose(r);
		return 0;
	}
	default:
		return -1;
	}
}

/* 列表头：元素类型 + 元素数（供精确遍历） */
static int rlist_hdr(struct tr *r, int *etype, size_t *n)
{
	uint8_t h;

	if (rbyte(r, &h) != 0)
		return -1;
	*etype = h & 0xf;
	if ((h >> 4) == 15) {
		uint64_t v;

		if (rvar(r, &v) != 0 || v > (1u << 24))
			return -1;
		*n = (size_t)v;
	} else {
		*n = (size_t)(h >> 4);
	}
	return 0;
}

/* ---- 逐层解析 FileMetaData ---- */

/* Statistics：合并进 agg（ts_min/ts_max/cat_max 跨 chunk/row group 合并；
 * min/max 各自独立"已见"标志——footer 里先见 max 时 min 不得视作已置） */
struct pq_agg {
	int ts_min_set, ts_max_set;
	int64_t ts_min, ts_max;
	int cat_set;
	int64_t cat_max;
};

static int read_statistics(struct tr *r, int col_is_ts, int col_is_cat,
			   struct pq_agg *agg)
{
	int sid, stype, rf;
	int bad = 0;

	ropen(r);
	while (!bad && (rf = rfield(r, &sid, &stype)) == 1) {
		if (stype == TT_BIN && (sid == 1 || sid == 2 ||
					sid == 5 || sid == 6)) {
			const uint8_t *bp;
			size_t bn;

			if (rbin(r, &bp, &bn) != 0 || bn > 8) {
				bad = 1;
				break;
			}
			{
				uint8_t v[8];
				int64_t iv = 0;

				memset(v, 0, sizeof(v));
				memcpy(v, bp, bn);
				/* 仅目标列取值；其它长度（如 binary 列的
				 * bin[1] 统计）与本读取器无关，忽略 */
				if (bn == 8)
					iv = rle64b(v);
				else if (bn == 4)
					iv = rle32b(v);
				if (col_is_ts && bn == 8) {
					if (sid == 2 || sid == 6) { /* min */
						if (!agg->ts_min_set ||
						    iv < agg->ts_min) {
							agg->ts_min = iv;
							agg->ts_min_set = 1;
						}
					} else {		/* max */
						if (!agg->ts_max_set ||
						    iv > agg->ts_max) {
							agg->ts_max = iv;
							agg->ts_max_set = 1;
						}
					}
				}
				if (col_is_cat && bn == 4 &&
				    (sid == 1 || sid == 5)) {
					if (!agg->cat_set || iv > agg->cat_max)
						agg->cat_max = iv;
					agg->cat_set = 1;
				}
			}
		} else if (rskip(r, stype) != 0) {
			bad = 1;
		}
	}
	if (rf < 0)
		bad = 1;
	rclose(r);
	return bad ? -1 : 0;
}

/* ColumnMetaData{3 path,12 statistics,...}；其余跳过 */
static int read_col_meta(struct tr *r, struct pq_agg *agg)
{
	int mid, mtype, rf;
	int col_is_ts = 0, col_is_cat = 0;
	int bad = 0;

	ropen(r);
	while (!bad && (rf = rfield(r, &mid, &mtype)) == 1) {
		if (mid == 3 && mtype == TT_LIST) {
			int et;
			size_t nbn;
			const uint8_t *first = NULL;
			size_t firstn = 0;

			if (rlist_hdr(r, &et, &nbn) != 0 || et != TT_BIN) {
				bad = 1;
				break;
			}
			for (size_t i = 0; i < nbn; i++) {
				const uint8_t *bp;
				size_t bn;

				if (rbin(r, &bp, &bn) != 0) {
					bad = 1;
					break;
				}
				if (i == 0) {
					first = bp;
					firstn = bn;
				}
			}
			if (bad)
				break;
			{
				char nm[40];

				if (firstn == 12 &&
				    memcmp(first, "timestamp_ns", 12) == 0)
					col_is_ts = 1;
				else if (firstn == 8 &&
					 memcmp(first, "category", 8) == 0)
					col_is_cat = 1;
				(void)nm;
			}
		} else if (mid == 12 && mtype == TT_STRUCT) {
			if (read_statistics(r, col_is_ts, col_is_cat, agg) != 0)
				bad = 1;
		} else if (rskip(r, mtype) != 0) {
			bad = 1;
		}
	}
	if (rf < 0)
		bad = 1;
	rclose(r);
	return bad ? -1 : 0;
}

/* ColumnChunk{3 meta_data,...} */
static int read_col_chunk(struct tr *r, struct pq_agg *agg)
{
	int cid, ctype, rf;
	int bad = 0;

	ropen(r);
	while (!bad && (rf = rfield(r, &cid, &ctype)) == 1) {
		if (cid == 3 && ctype == TT_STRUCT) {
			if (read_col_meta(r, agg) != 0)
				bad = 1;
		} else if (rskip(r, ctype) != 0) {
			bad = 1;
		}
	}
	if (rf < 0)
		bad = 1;
	rclose(r);
	return bad ? -1 : 0;
}

/* RowGroup{1 columns,...} */
static int read_row_group(struct tr *r, struct pq_agg *agg)
{
	int rid, rtype, rf;
	int bad = 0;

	ropen(r);
	while (!bad && (rf = rfield(r, &rid, &rtype)) == 1) {
		if (rid == 1 && rtype == TT_LIST) {
			int et;
			size_t ncc;

			if (rlist_hdr(r, &et, &ncc) != 0 || et != TT_STRUCT) {
				bad = 1;
				break;
			}
			for (size_t i = 0; i < ncc && !bad; i++) {
				if (read_col_chunk(r, agg) != 0)
					bad = 1;
			}
		} else if (rskip(r, rtype) != 0) {
			bad = 1;
		}
	}
	if (rf < 0)
		bad = 1;
	rclose(r);
	return bad ? -1 : 0;
}

int as_pq_file_stats(const char *path, struct pq_file_stats *out)
{
	FILE *f;
	uint8_t tail[8], *meta = NULL;
	long sz;
	uint32_t mlen;
	struct tr r;
	struct pq_agg agg;
	int64_t num_rows = -1;
	int rc = -1;

	memset(out, 0, sizeof(*out));
	memset(&agg, 0, sizeof(agg));
	f = fopen(path, "rb");
	if (!f)
		return -1;
	if (fseek(f, 0, SEEK_END) != 0)
		goto out;
	sz = ftell(f);
	if (sz < 12)
		goto out;
	if (fseek(f, sz - 8, SEEK_SET) != 0 || fread(tail, 1, 8, f) != 8)
		goto out;
	if (memcmp(tail + 4, PQ_PAR1, 4) != 0)
		goto out;
	mlen = (uint32_t)tail[0] | (uint32_t)tail[1] << 8 |
	       (uint32_t)tail[2] << 16 | (uint32_t)tail[3] << 24;
	if (mlen == 0 || mlen > (uint32_t)(sz - 12))
		goto out;
	meta = malloc(mlen);
	if (!meta)
		goto out;
	if (fseek(f, sz - 8 - (long)mlen, SEEK_SET) != 0 ||
	    fread(meta, 1, mlen, f) != mlen)
		goto out;

	r.p = meta;
	r.end = meta + mlen;
	r.depth = -1;
	ropen(&r);					/* FileMetaData */
	{
		int id, type, rf;

		while ((rf = rfield(&r, &id, &type)) == 1) {
			if (id == 3 && type == TT_I64) {
				if (rzig(&r, &num_rows) != 0)
					goto out;
			} else if (id == 4 && type == TT_LIST) {
				int et;
				size_t nrg;

				if (rlist_hdr(&r, &et, &nrg) != 0 ||
				    et != TT_STRUCT)
					goto out;
				for (size_t g = 0; g < nrg; g++) {
					if (read_row_group(&r, &agg) != 0)
						goto out;
				}
			} else if (rskip(&r, type) != 0) {
				goto out;
			}
		}
		if (rf < 0)
			goto out;
		rclose(&r);
	}
	if (num_rows < 0)
		goto out;
	out->num_rows = num_rows;
	out->has_ts = agg.ts_min_set && agg.ts_max_set;
	out->ts_min = out->has_ts ? agg.ts_min : 0;
	out->ts_max = out->has_ts ? agg.ts_max : 0;
	out->has_cat = agg.cat_set;
	out->cat_max = agg.cat_set ? agg.cat_max : 0;
	rc = 0;
out:
	if (rc != 0)
		memset(out, 0, sizeof(*out));
	free(meta);
	fclose(f);
	return rc;
}
