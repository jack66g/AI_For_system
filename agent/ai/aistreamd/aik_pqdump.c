/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aik_pqdump.c — P-27：C 版 parquet 读者（aik-pqdump）
 *
 * 读 **自家 parquet 面**（as_parquet.c / aipd aip_shadow.c 写入器产物：
 * DataPageV1 / PLAIN / snappy / OPTIONAL 全 1 def / 单 row group 或
 * 顺序多 row group）。不是通用 parquet 读者——外部任意 parquet 超面
 * （字典页/其他编码/嵌套 rep levels）= 人话拒绝（P-27 立项边界：
 * 修出厂数据面断，aikctl dataset 子族去 pyarrow 依赖）。
 *
 * 用法：
 *   aik-pqdump [OPTS] <file.parquet>
 *     --schema        只打 footer 概要（列名/类型/num_rows，一行一列）
 *     --bycol         输出单个 JSON 对象 {col:[v,...],...}（aikctl 集成
 *                     形态；默认=JSONL 每行 {"col":v,...}）
 *     --limit N       行数上限（--bycol/JSONL 均截断；--schema 忽略）
 *   rc：0=成功；1=人话错误（坏魔数/截断/超面）
 *
 * 输出形态对齐 pyarrow read_table().to_pydict()（列式）与 iter 行式
 * ——数值=int；byte array=字符串（utf-8 replace 语义，JSON 转义）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aistreamd/as_snappy.h"

/* ---------------- thrift compact 读取器（footer/页头用） ---------------- */

#define TT_STOP 0
#define TT_TRUE 1
#define TT_FALSE 2
#define TT_BYTE 3
#define TT_I16 4
#define TT_I32 5
#define TT_I64 6
#define TT_DOUBLE 7
#define TT_BIN 8
#define TT_LIST 9
#define TT_SET 10
#define TT_MAP 11
#define TT_STRUCT 12

struct tr {
	const uint8_t *b;
	size_t n, o;
	int last_fid;
};

static int tr_err;

static uint64_t tr_uvar(struct tr *t)
{
	uint64_t v = 0;
	int shift = 0;

	while (t->o < t->n) {
		uint8_t c = t->b[t->o++];
		v |= (uint64_t)(c & 0x7f) << shift;
		if (!(c & 0x80))
			return v;
		shift += 7;
		if (shift > 63) {
			tr_err = 1;
			return 0;
		}
	}
	tr_err = 1;
	return 0;
}

static int64_t tr_uzig(struct tr *t)
{
	uint64_t u = tr_uvar(t);
	return (int64_t)(u >> 1) ^ -(int64_t)(u & 1);
}

/* 字段头：返回 type（0=STOP）；*fid 出参（delta 累加） */
static int tr_field(struct tr *t, int *fid)
{
	if (t->o >= t->n) {
		tr_err = 1;
		return 0;
	}
	{
		uint8_t h = t->b[t->o++];

		if (h == 0)
			return 0;
		{
			int delta = h >> 4;
			int ty = h & 0x0f;

			if (delta)
				*fid += delta;
			else
				*fid = (int)tr_uzig(t);
			return ty;
		}
	}
}

/* list/set 头：低 4 位=元素类型，高 4 位=size（15=跟 varint） */
static long tr_list(struct tr *t, int *ety)
{
	if (t->o >= t->n) {
		tr_err = 1;
		return 0;
	}
	{
		uint8_t h = t->b[t->o++];
		long sz = h >> 4;

		*ety = h & 0x0f;
		if (sz == 15)
			sz = (long)tr_uvar(t);
		return sz;
	}
}

static const uint8_t *tr_bin(struct tr *t, size_t *len)
{
	size_t n = (size_t)tr_uvar(t);
	const uint8_t *p;

	if (t->o + n > t->n) {
		tr_err = 1;
		*len = 0;
		return (const uint8_t *)"";
	}
	p = t->b + t->o;
	t->o += n;
	*len = n;
	return p;
}

/* 通用值跳过（未消费字段）——TRUE/FALSE 不占字节（logicalType union
 * 的 isSigned 等）；嵌套 struct/list 递归（footer 深层 statistics/
 * logicalType 用） */
static void tr_skip(struct tr *t, int ty)
{
	switch (ty) {
	case TT_TRUE:
	case TT_FALSE:
		break;
	case TT_BYTE:
	case TT_I16:
	case TT_I32:
	case TT_I64:
		tr_uzig(t);
		break;
	case TT_DOUBLE:
		if (t->o + 8 > t->n) {
			tr_err = 1;
			break;
		}
		t->o += 8;
		break;
	case TT_BIN: {
		size_t nn;
		tr_bin(t, &nn);
		break;
	}
	case TT_LIST:
	case TT_SET: {
		int ety;
		long sz = tr_list(t, &ety);
		for (long i = 0; i < sz && !tr_err; i++)
			tr_skip(t, ety);
		break;
	}
	case TT_STRUCT: {
		int sf = 0, sty;
		while ((sty = tr_field(t, &sf)) != TT_STOP && !tr_err)
			tr_skip(t, sty);
		break;
	}
	default:
		/* MAP 等自家面未用——保守置错 */
		tr_err = 1;
		break;
	}
}

/* ---------------- parquet 侧结构 ---------------- */

#define PQT_BOOLEAN 0
#define PQT_INT32 1
#define PQT_INT64 2
#define PQT_INT96 3
#define PQT_FLOAT 4
#define PQT_DOUBLE 5
#define PQT_BYTE_ARRAY 6
#define PQT_FIXED 7

#define CODEC_SNAPPY 1

struct colmeta {
	char name[128];
	int pqt;			/* 物理类型 */
	long num_values;
	long data_page_offset;
	long comp_total;
	int codec;
};

#define MAX_COLS 64
#define MAX_RGS 8

struct pqmeta {
	int64_t num_rows;
	int nrg;
	struct {
		int ncols;
		struct colmeta cols[MAX_COLS];
	} rg[MAX_RGS];
};

static const char *pqt_name(int t)
{
	switch (t) {
	case PQT_BOOLEAN: return "BOOLEAN";
	case PQT_INT32: return "INT32";
	case PQT_INT64: return "INT64";
	case PQT_INT96: return "INT96";
	case PQT_FLOAT: return "FLOAT";
	case PQT_DOUBLE: return "DOUBLE";
	case PQT_BYTE_ARRAY: return "BYTE_ARRAY";
	case PQT_FIXED: return "FIXED_LEN_BYTE_ARRAY";
	default: return "?";
	}
}

static void die(const char *msg, const char *arg)
{
	fprintf(stderr, "aik-pqdump: %s%s%s\n", msg, arg ? ": " : "",
		arg ? arg : "");
	exit(1);
}

/* ---------------- footer 解析 ---------------- */

static void parse_schema_elem(struct tr *t, char *name, int *pqt)
{
	int fid = 0, ty;

	/* SchemaElement{1:type 2:type_length 3:repetition_type 4:name
	 *              5:num_children 6:converted_type ...} */
	while ((ty = tr_field(t, &fid)) != TT_STOP && !tr_err) {
		switch (fid) {
		case 1:
			*pqt = (int)tr_uzig(t);
			break;
		case 4: {
			size_t n;
			const uint8_t *p = tr_bin(t, &n);
			size_t cpy = n < sizeof(((struct colmeta *)0)->name) - 1 ?
				     n : sizeof(((struct colmeta *)0)->name) - 1;
			memcpy(name, p, cpy);
			name[cpy] = 0;
			break;
		}
		default:
			tr_skip(t, ty);
			break;
		}
	}
}

static void parse_col_meta(struct tr *t, struct colmeta *cm)
{
	int fid = 0, ty;

	memset(cm, 0, sizeof(*cm));
	cm->pqt = -1;
	cm->codec = -1;
	/* ColumnMetaData{1:type 2:encodings 3:path_in_schema 4:codec
	 *               5:num_values 6:total_uncompressed_size
	 *               7:total_compressed_size 9:data_page_offset ...} */
	while ((ty = tr_field(t, &fid)) != TT_STOP && !tr_err) {
		switch (fid) {
		case 1: cm->pqt = (int)tr_uzig(t); break;
		case 3: {
			int ety;
			long sz = tr_list(t, &ety);
			int first = 1;
			for (long i = 0; i < sz && !tr_err; i++) {
				size_t nn;
				const uint8_t *p = tr_bin(t, &nn);
				if (first) {
					size_t cpy = nn < sizeof(cm->name) - 1 ?
						     nn : sizeof(cm->name) - 1;
					memcpy(cm->name, p, cpy);
					cm->name[cpy] = 0;
					first = 0;
				}
			}
			break;
		}
		case 4: cm->codec = (int)tr_uzig(t); break;
		case 5: cm->num_values = (long)tr_uzig(t); break;
		case 7: cm->comp_total = (long)tr_uzig(t); break;
		case 9: cm->data_page_offset = (long)tr_uzig(t); break;
		default:
			tr_skip(t, ty);
			break;
		}
	}
}

static void parse_col_chunk(struct tr *t, struct colmeta *cm)
{
	int fid = 0, ty;

	/* ColumnChunk{1:file_path 2:file_offset 3:meta_data} */
	while ((ty = tr_field(t, &fid)) != TT_STOP && !tr_err) {
		switch (fid) {
		case 3: {
			/* meta_data=STRUCT：复用解析（fid 从 0 重启） */
			parse_col_meta(t, cm);
			break;
		}
		default:
			tr_skip(t, ty);
			break;
		}
	}
}

static void parse_footer(const uint8_t *b, size_t n, struct pqmeta *m)
{
	struct tr t = { b, n, 0, 0 };
	int fid = 0, ty;
	int schema_cols = 0;
	static char names[MAX_COLS][128];
	static int pqts[MAX_COLS];
	int top_after_schema = 0;

	memset(m, 0, sizeof(*m));
	memset(names, 0, sizeof(names));
	memset(pqts, 0, sizeof(pqts));

	/* FileMetaData{1:version 2:schema 3:num_rows 4:row_groups ...} */
	while ((ty = tr_field(&t, &fid)) != TT_STOP && !tr_err) {
		switch (fid) {
		case 2: {
			int ety;
			long sz = tr_list(&t, &ety);
			for (long i = 0; i < sz && !tr_err; i++) {
				parse_schema_elem(&t, names[schema_cols],
						  &pqts[schema_cols]);
				schema_cols++;
			}
			break;
		}
		case 3:
			m->num_rows = tr_uzig(&t);
			top_after_schema = 1;
			break;
		case 4: {
			int ety;
			long sz = tr_list(&t, &ety);
			for (long i = 0; i < sz && !tr_err; i++) {
				/* RowGroup=STRUCT */
				int rf = 0, rty;
				int rgi = m->nrg;
				m->rg[rgi].ncols = 0;
				while ((rty = tr_field(&t, &rf)) != TT_STOP &&
				       !tr_err) {
					switch (rf) {
					case 1: {
						/* columns list<ColumnChunk> */
						int e2;
						long cs = tr_list(&t, &e2);
						for (long j = 0; j < cs && !tr_err; j++) {
							struct colmeta cm;
							parse_col_chunk(&t, &cm);
							if (m->rg[rgi].ncols < MAX_COLS)
								m->rg[rgi].cols[m->rg[rgi].ncols++] = cm;
						}
						break;
					}
					default:
						tr_skip(&t, rty);
						break;
					}
				}
				m->nrg++;
				if (m->nrg >= MAX_RGS)
					tr_err = 1;
			}
			break;
		}
		default:
			tr_skip(&t, ty);
			break;
		}
	}
	(void)top_after_schema;
	if (tr_err)
		die("footer 解析失败（损坏或超出自家写入面）", NULL);

	/* 根 schema[0]=.schema 名（num_children=列数）——列名以 row group
	 * 的 path_in_schema 为准（footer schema 顺序同构，双源校验） */
	if (m->nrg >= 1) {
		int nc = m->rg[0].ncols;
		for (int i = 0; i < nc; i++) {
			struct colmeta *cm = &m->rg[0].cols[i];
			if (cm->pqt < 0)
				cm->pqt = (i < schema_cols) ? pqts[i + 1 < schema_cols ? i + 1 : i] : PQT_INT64;
			if (!cm->name[0] && i + 1 < schema_cols)
				snprintf(cm->name, sizeof(cm->name), "%s",
					 names[i + 1]);
		}
	}
}

/* ---------------- 页解码 ---------------- */

static uint8_t *read_all(FILE *f, size_t *n)
{
	long sz;
	uint8_t *b;

	if (fseek(f, 0, SEEK_END) != 0)
		return NULL;
	sz = ftell(f);
	if (sz < 12)
		return NULL;
	rewind(f);
	b = malloc((size_t)sz);
	if (!b)
		return NULL;
	if (fread(b, 1, (size_t)sz, f) != (size_t)sz) {
		free(b);
		return NULL;
	}
	*n = (size_t)sz;
	return b;
}

static void put_json_str(FILE *o, const uint8_t *s, size_t n)
{
	fputc('"', o);
	for (size_t i = 0; i < n; i++) {
		uint8_t c = s[i];
		switch (c) {
		case '"': fputs("\\\"", o); break;
		case '\\': fputs("\\\\", o); break;
		case '\n': fputs("\\n", o); break;
		case '\r': fputs("\\r", o); break;
		case '\t': fputs("\\t", o); break;
		default:
			if (c < 0x20)
				fprintf(o, "\\u%04x", c);
			else
				fputc(c, o);
		}
	}
	fputc('"', o);
}

struct colvals {
	int64_t *ints;			/* 数值列 */
	struct { const uint8_t *p; size_t n; } *bas;	/* byte array 列 */
	long n;
};

/* 单列解码：data_page_offset 起，读到 num_values 满（页循环） */
static void decode_col(const uint8_t *fb, size_t fn, struct colmeta *cm,
		       struct colvals *cv)
{
	size_t off = (size_t)cm->data_page_offset;
	long got = 0;

	cv->n = cm->num_values;
	cv->ints = NULL;
	cv->bas = NULL;
	if (cv->n <= 0)
		return;
	/* DOUBLE=8B 定长，位模式走 INT64 解码路径（输出时位转 double） */
	if (cm->pqt != PQT_BYTE_ARRAY) {
		cv->ints = calloc((size_t)cv->n, sizeof(int64_t));
		if (!cv->ints)
			die("内存不足", NULL);
	} else {
		cv->bas = calloc((size_t)cv->n, sizeof(*cv->bas));
		if (!cv->bas)
			die("内存不足", NULL);
	}

	while (got < cv->n) {
		struct tr t;
		int fid = 0, ty;
		long nvals = -1, uncompressed = -1, compressed = -1;
		int page_type = -1;
		int enc = -1;
		const uint8_t *body;
		uint8_t *raw = NULL;
		size_t roff = 0;

		if (off >= fn)
			die("页数据越界（文件截断？）", cm->name);
		t.b = fb + off;
		t.n = fn - off;
		t.o = 0;
		t.last_fid = 0;

		/* PageHeader{1:type 2:uncompressed 3:compressed
		 *           5:data_page_header{1:num_values 2:encoding ...}} */
		while ((ty = tr_field(&t, &fid)) != TT_STOP && !tr_err) {
			switch (fid) {
			case 1: page_type = (int)tr_uzig(&t); break;
			case 2: uncompressed = (long)tr_uzig(&t); break;
			case 3: compressed = (long)tr_uzig(&t); break;
			case 5: {
				int df = 0, dty;
				while ((dty = tr_field(&t, &df)) != TT_STOP &&
				       !tr_err) {
					switch (df) {
					case 1: nvals = (long)tr_uzig(&t); break;
					case 2: enc = (int)tr_uzig(&t); break;
					default:
						tr_skip(&t, dty);
						break;
					}
				}
				break;
			}
			default:
				tr_skip(&t, ty);
				break;
			}
		}
		if (tr_err || page_type != 0 || nvals <= 0 ||
		    compressed <= 0 || enc != 0)
			die("页头超面（需 DATA_PAGE+PLAIN——自家写入器产物）",
			    cm->name);

		body = t.b + t.o;
		if ((size_t)compressed > t.n - t.o)
			die("页体越界", cm->name);

		if (cm->codec == CODEC_SNAPPY) {
			size_t outn;
			raw = malloc((size_t)uncompressed);
			if (!raw)
				die("内存不足", NULL);
			outn = (size_t)uncompressed;
			if (as_snappy_uncompress(body, (size_t)compressed,
						 raw, &outn) != 0 ||
			    outn != (size_t)uncompressed)
				die("snappy 解压失败", cm->name);
		} else if (cm->codec == 0) {
			raw = malloc((size_t)compressed);
			if (!raw)
				die("内存不足", NULL);
			memcpy(raw, body, (size_t)compressed);
			uncompressed = compressed;
		} else {
			die("不支持的非 snappy 压缩", cm->name);
		}

		/* def-levels 段：le32 长度前缀 + RLE（全 1 run）→跳过 */
		if (roff + 4 > (size_t)uncompressed)
			die("def 段缺失", cm->name);
		{
			uint32_t dlen = (uint32_t)raw[roff] |
					(uint32_t)raw[roff + 1] << 8 |
					(uint32_t)raw[roff + 2] << 16 |
					(uint32_t)raw[roff + 3] << 24;
			roff += 4;
			if (roff + dlen > (size_t)uncompressed)
				die("def 段越界", cm->name);
			roff += dlen;
		}

		/* PLAIN 数据 */
		{
			long take = nvals;
			if (got + take > cv->n)
				take = cv->n - got;
			if (cm->pqt == PQT_INT32 || cm->pqt == PQT_BOOLEAN) {
				for (long i = 0; i < take; i++) {
					uint32_t v;
					if (roff + 4 > (size_t)uncompressed)
						die("INT32 数据越界", cm->name);
					v = (uint32_t)raw[roff] |
					    (uint32_t)raw[roff + 1] << 8 |
					    (uint32_t)raw[roff + 2] << 16 |
					    (uint32_t)raw[roff + 3] << 24;
					roff += 4;
					cv->ints[got + i] = (int32_t)v;
				}
			} else if (cm->pqt == PQT_INT64 || cm->pqt == PQT_DOUBLE) {
				/* INT64/DOUBLE：8B 定长（DOUBLE 位存，输出转） */
				for (long i = 0; i < take; i++) {
					uint64_t v = 0;
					if (roff + 8 > (size_t)uncompressed)
						die("INT64 数据越界", cm->name);
					for (int k = 7; k >= 0; k--)
						v = v << 8 | raw[roff + (size_t)k];
					roff += 8;
					cv->ints[got + i] = (int64_t)v;
				}
			} else if (cm->pqt == PQT_BYTE_ARRAY) {
				for (long i = 0; i < take; i++) {
					uint32_t ln;
					uint8_t *own;
					if (roff + 4 > (size_t)uncompressed)
						die("BYTE_ARRAY 长度越界", cm->name);
					ln = (uint32_t)raw[roff] |
					     (uint32_t)raw[roff + 1] << 8 |
					     (uint32_t)raw[roff + 2] << 16 |
					     (uint32_t)raw[roff + 3] << 24;
					roff += 4;
					if (roff + ln > (size_t)uncompressed)
						die("BYTE_ARRAY 数据越界", cm->name);
					/* 深拷贝（raw 页缓冲生命周期独立） */
					own = malloc(ln ? ln : 1);
					if (!own)
						die("内存不足", NULL);
					memcpy(own, raw + roff, ln);
					cv->bas[got + i].p = own;
					cv->bas[got + i].n = ln;
					roff += ln;
				}
			} else {
				die("不支持的物理类型", pqt_name(cm->pqt));
			}
			got += take;
		}

		off = (size_t)(body - fb) + (size_t)compressed;
		free(raw);
		/* 自家写入面=每列 chunk 单页：一页后仍有缺口=超面 */
		break;
	}
	if (got < cv->n)
		die("页内值数不足 footer 声明（多页超面）", cm->name);
}

/* ---------------- main ---------------- */

int main(int argc, char **argv)
{
	const char *path = NULL;
	int want_schema = 0, bycol = 0;
	long limit = -1;
	FILE *f;
	uint8_t *fb;
	size_t fn, footer_len;
	struct pqmeta m;
	struct colvals *cvs;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--schema"))
			want_schema = 1;
		else if (!strcmp(argv[i], "--bycol"))
			bycol = 1;
		else if (!strcmp(argv[i], "--limit") && i + 1 < argc)
			limit = atol(argv[++i]);
		else if (argv[i][0] == '-')
			die("未知参数", argv[i]);
		else if (!path)
			path = argv[i];
		else
			die("多余参数", argv[i]);
	}
	if (!path)
		die("用法: aik-pqdump [--schema|--bycol] [--limit N] <file.parquet>", NULL);

	f = fopen(path, "rb");
	if (!f)
		die("打不开文件", path);
	fb = read_all(f, &fn);
	fclose(f);
	if (!fb)
		die("读取失败（<12 字节？）", path);

	if (memcmp(fb, "PAR1", 4) != 0)
		die("非 parquet（缺 PAR1 头）", path);
	if (memcmp(fb + fn - 4, "PAR1", 4) != 0)
		die("非 parquet（缺 PAR1 尾）", path);
	footer_len = (size_t)fb[fn - 8] | (size_t)fb[fn - 7] << 8 |
		     (size_t)fb[fn - 6] << 16 | (size_t)fb[fn - 5] << 24;
	if (footer_len == 0 || footer_len > fn - 12)
		die("footer 长度非法（损坏文件？）", path);

	parse_footer(fb + fn - 8 - footer_len, footer_len, &m);

	if (m.nrg < 1 || m.rg[0].ncols < 1)
		die("footer 无列信息", path);
	if (m.nrg > 1)
		die("多 row group 超面（自家写入器=单 row group）", path);

	if (want_schema) {
		printf("num_rows=%ld columns=%d\n",
		       (long)m.num_rows, m.rg[0].ncols);
		for (int i = 0; i < m.rg[0].ncols; i++) {
			struct colmeta *cm = &m.rg[0].cols[i];
			printf("%s %s values=%ld\n", cm->name,
			       pqt_name(cm->pqt), cm->num_values);
		}
		free(fb);
		return 0;
	}

	cvs = calloc((size_t)m.rg[0].ncols, sizeof(*cvs));
	if (!cvs)
		die("内存不足", NULL);
	for (int i = 0; i < m.rg[0].ncols; i++)
		decode_col(fb, fn, &m.rg[0].cols[i], &cvs[i]);

	if (limit < 0 || limit > m.num_rows)
		limit = (long)m.num_rows;

	if (bycol) {
		printf("{");
		for (int i = 0; i < m.rg[0].ncols; i++) {
			struct colmeta *cm = &m.rg[0].cols[i];
			printf("%s\"%s\":[", i ? "," : "", cm->name);
			for (long r = 0; r < limit; r++) {
				if (cm->pqt == PQT_BYTE_ARRAY) {
					if (r)
						putchar(',');
					put_json_str(stdout, cvs[i].bas[r].p,
						     cvs[i].bas[r].n);
				} else if (cm->pqt == PQT_DOUBLE) {
					double dv;
					memcpy(&dv, &cvs[i].ints[r], sizeof(dv));
					printf("%s%.17g", r ? "," : "", dv);
				} else {
					printf("%s%lld", r ? "," : "",
					       (long long)cvs[i].ints[r]);
				}
			}
			printf("]");
		}
		printf("}\n");
	} else {
		for (long r = 0; r < limit; r++) {
			printf("{");
			for (int i = 0; i < m.rg[0].ncols; i++) {
				struct colmeta *cm = &m.rg[0].cols[i];
				printf("%s\"%s\":", i ? "," : "", cm->name);
				if (cm->pqt == PQT_BYTE_ARRAY)
					put_json_str(stdout, cvs[i].bas[r].p,
						     cvs[i].bas[r].n);
				else if (cm->pqt == PQT_DOUBLE) {
					double dv;
					memcpy(&dv, &cvs[i].ints[r], sizeof(dv));
					printf("%.17g", dv);
				} else
					printf("%lld", (long long)cvs[i].ints[r]);
			}
			printf("}\n");
		}
	}

	for (int i = 0; i < m.rg[0].ncols; i++) {
		free(cvs[i].ints);
		free(cvs[i].bas);
	}
	free(cvs);
	free(fb);
	return 0;
}
