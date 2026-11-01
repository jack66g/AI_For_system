/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_bm25.c - T3a BM25 向量自测
 *
 * 数据：$AIK_PARITY_VECTORS/text/text.vectors.json
 *   12 篇文档 × 18 组 query：raw / normalized 分数 rel_err <= 1e-12，
 *   top5 完全一致；query token 与 query_tokens_hex 逐字节一致。
 *
 * 输出：SUMMARY bm25 checked=<n> mismatch=<m>；有失配 exit 1。
 */
#include "../../include/retrieval/bm25.h"
#include "../../include/retrieval/text.h"
#include "../../include/store/store_json.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DOCS 64

static size_t checked;
static size_t mismatched;

static const char *vectors_dir(void)
{
	static char buf[4096];
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
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, (size_t)n, f);
	fclose(f);
	if (got != (size_t)n) {
		free(buf);
		return NULL;
	}
	buf[got] = '\0';
	*len = got;
	return buf;
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static size_t hex_to_bytes(const char *hex, unsigned char *out, size_t cap)
{
	size_t n = strlen(hex), i;

	if (n % 2 != 0 || n / 2 > cap)
		return SIZE_MAX;
	for (i = 0; i < n / 2; i++) {
		int hi = hexval((unsigned char)hex[2 * i]);
		int lo = hexval((unsigned char)hex[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return SIZE_MAX;
		out[i] = (unsigned char)((hi << 4) | lo);
	}
	return n / 2;
}

static char *hex_to_str(const char *hex)
{
	size_t n = strlen(hex) / 2;
	unsigned char *tmp = malloc(n + 1);

	if (!tmp)
		return NULL;
	if (hex_to_bytes(hex, tmp, n + 1) != n) {
		free(tmp);
		return NULL;
	}
	tmp[n] = '\0';
	return (char *)tmp;
}

static int close_enough(double got, double exp)
{
	double d = fabs(got - exp);
	double scale = fabs(exp) > 1.0 ? fabs(exp) : 1.0;

	return d <= 1e-12 * scale;
}

static int tokens_match(const aik_token_list *tl, const aik_json *want)
{
	size_t i;

	if (tl->count != aik_json_count(want))
		return 0;
	for (i = 0; i < tl->count; i++) {
		char *s = hex_to_str(aik_json_str(aik_json_at(want, i)));
		int ok;

		if (!s)
			return 0;
		ok = strcmp(s, tl->items[i]) == 0;
		free(s);
		if (!ok)
			return 0;
	}
	return 1;
}

int main(void)
{
	char path[8192];
	char *buf;
	size_t len = 0;
	aik_json *root = NULL;
	const aik_json *meta, *docs, *cases;
	const char *ids[MAX_DOCS];
	size_t nd, i;
	double k1 = 1.5, b = 0.75;
	aik_bm25 *ix[2] = { NULL, NULL };

	snprintf(path, sizeof(path), "%s/text/text.vectors.json", vectors_dir());
	buf = read_file(path, &len);
	if (!buf) {
		printf("SUMMARY bm25 checked=0 mismatch=1\n");
		return 1;
	}
	root = aik_json_parse(buf, len, NULL, 0);
	free(buf);
	if (!root) {
		printf("SUMMARY bm25 checked=0 mismatch=1\n");
		return 1;
	}
	meta = aik_json_get(root, "meta");
	docs = meta ? aik_json_get(meta, "docs") : NULL;
	cases = aik_json_get(root, "bm25");
	if (!meta || !docs || !cases) {
		mismatched++;
		printf("MISMATCH missing meta/docs/bm25\n");
		goto out;
	}
	if (aik_json_get(meta, "k1"))
		k1 = aik_json_num(aik_json_get(meta, "k1"));
	if (aik_json_get(meta, "b"))
		b = aik_json_num(aik_json_get(meta, "b"));
	nd = aik_json_count(docs);
	if (nd > MAX_DOCS) {
		mismatched++;
		printf("MISMATCH too many docs (%zu)\n", nd);
		goto out;
	}

	for (i = 0; i < nd; i++) {
		const aik_json *d = aik_json_at(docs, i);
		const char *id = aik_json_str(aik_json_get(d, "id"));
		char *text = hex_to_str(aik_json_str(aik_json_get(d, "text_hex")));

		if (!id || !text) {
			mismatched++;
			printf("MISMATCH doc %zu malformed\n", i);
			free(text);
			goto out;
		}
		ids[i] = id;
		free(text);
	}

	for (i = 0; i < 2; i++) {
		ix[i] = aik_bm25_new(k1, b, (int)i, NULL, 0);
		if (!ix[i]) {
			mismatched++;
			printf("MISMATCH index create failed\n");
			goto out;
		}
	}
	for (i = 0; i < nd; i++) {
		const aik_json *d = aik_json_at(docs, i);
		char *text = hex_to_str(aik_json_str(aik_json_get(d, "text_hex")));

		if (!text || aik_bm25_add(ix[0], ids[i], text, NULL, 0) != 0 ||
		    aik_bm25_add(ix[1], ids[i], text, NULL, 0) != 0) {
			mismatched++;
			printf("MISMATCH add doc %s\n", ids[i]);
			free(text);
			goto out;
		}
		free(text);
	}
	if (aik_bm25_n_docs(ix[0]) != nd || aik_bm25_n_docs(ix[1]) != nd) {
		mismatched++;
		printf("MISMATCH n_docs got=%zu/%zu exp=%zu\n",
		       aik_bm25_n_docs(ix[0]), aik_bm25_n_docs(ix[1]), nd);
	}

	for (i = 0; i < aik_json_count(cases); i++) {
		const aik_json *c = aik_json_at(cases, i);
		const aik_json *qtok = aik_json_get(c, "query_tokens_hex");
		const aik_json *raw = aik_json_get(c, "raw");
		const aik_json *norm = aik_json_get(c, "normalized");
		const aik_json *top5 = aik_json_get(c, "top5");
		char *qtext = hex_to_str(aik_json_str(aik_json_get(c, "query_hex")));
		int bigram = aik_json_bool(aik_json_get(c, "cjk_bigram"));
		aik_bm25 *idx = ix[bigram ? 1 : 0];
		aik_token_list tl = { NULL, 0 };
		double got[16], gotn[16];
		const char *rids[16];
		char **top = NULL;
		size_t top_n = 0, j;
		int bad = 0;

		checked++;
		if (!qtext || !qtok || !raw || !norm || !top5) {
			mismatched++;
			printf("MISMATCH case %zu malformed\n", i);
			free(qtext);
			continue;
		}
		if (aik_tokenize(qtext, bigram, &tl, NULL, 0) != 0) {
			mismatched++;
			printf("MISMATCH case %zu tokenize failed\n", i);
			free(qtext);
			continue;
		}
		if (!tokens_match(&tl, qtok)) {
			mismatched++;
			printf("MISMATCH case %zu query tokens differ\n", i);
			bad = 1;
		}
		for (j = 0; j < nd; j++)
			rids[j] = aik_json_str(aik_json_get(
				aik_json_at(raw, j), "id"));
		if (aik_bm25_scores(idx, &tl, rids, nd, 0, got, NULL, 0) != 0 ||
		    aik_bm25_scores(idx, &tl, rids, nd, 1, gotn, NULL, 0) != 0) {
			mismatched++;
			printf("MISMATCH case %zu scores failed\n", i);
			bad = 1;
		}
		for (j = 0; !bad && j < nd; j++) {
			double er = aik_json_num(aik_json_get(
				aik_json_at(raw, j), "value"));
			double en = aik_json_num(aik_json_get(
				aik_json_at(norm, j), "value"));

			if (!close_enough(got[j], er) ||
			    !close_enough(gotn[j], en)) {
				mismatched++;
				if (mismatched <= 10)
					printf("MISMATCH case %zu doc %zu raw %.17g/%.17g norm %.17g/%.17g\n",
					       i, j, got[j], er, gotn[j], en);
				bad = 1;
			}
		}
		if (!bad) {
			if (aik_bm25_top(idx, qtext, 5, NULL, 0, &top, &top_n,
					 NULL, 0) != 0) {
				mismatched++;
				printf("MISMATCH case %zu top failed\n", i);
				bad = 1;
			} else if (top_n != aik_json_count(top5)) {
				mismatched++;
				printf("MISMATCH case %zu top count got=%zu exp=%zu\n",
				       i, top_n, aik_json_count(top5));
				bad = 1;
			} else {
				for (j = 0; j < top_n; j++) {
					const char *want = aik_json_str(
						aik_json_at(top5, j));

					if (strcmp(top[j], want) != 0) {
						mismatched++;
						if (mismatched <= 10)
							printf("MISMATCH case %zu top %zu got=%s exp=%s\n",
							       i, j, top[j],
							       want);
						bad = 1;
						break;
					}
				}
			}
		}
		free(top);
		aik_token_list_free(&tl);
		free(qtext);
	}

	/* 增量语义自查：删掉最后一篇再加回，n_docs 与 top 结果都应复原 */
	if (ix[1] && nd > 0) {
		const char *last = ids[nd - 1];
		char *last_text = hex_to_str(aik_json_str(
			aik_json_get(aik_json_at(docs, nd - 1), "text_hex")));
		char *qtext = hex_to_str(aik_json_str(
			aik_json_get(aik_json_at(cases, 0), "query_hex")));
		char **top = NULL;
		size_t top_n = 0;

		if (!last_text || !qtext ||
		    aik_bm25_remove(ix[1], last) != 0 ||
		    aik_bm25_n_docs(ix[1]) != nd - 1 ||
		    aik_bm25_add(ix[1], last, last_text, NULL, 0) != 0 ||
		    aik_bm25_n_docs(ix[1]) != nd) {
			mismatched++;
			printf("MISMATCH incremental remove/add state\n");
		} else if (aik_bm25_top(ix[1], qtext, 5, NULL, 0, &top, &top_n,
					NULL, 0) != 0 ||
			   top_n != aik_json_count(aik_json_get(
				   aik_json_at(cases, 0), "top5"))) {
			mismatched++;
			printf("MISMATCH incremental top recover\n");
		}
		free(top);
		free(last_text);
		free(qtext);
	}

out:
	for (i = 0; i < 2; i++)
		aik_bm25_free(ix[i]);
	aik_json_free(root);
	printf("SUMMARY bm25 checked=%zu mismatch=%zu\n", checked, mismatched);
	return mismatched ? 1 : 0;
}
