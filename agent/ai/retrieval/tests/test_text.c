/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_text.c - T3a tokenize 向量自测 + MEM-01a 混合词分词回归
 *
 * 数据：$AIK_PARITY_VECTORS/text/text.vectors.json 的 tokenize 段
 * （42 例，逐 token 输入/输出都用 hex，避免编码歧义）。
 *
 * 对齐向量的基线说明（MEM-01a）：混合 run（拉丁+CJK 连写）的切法自
 * e72bc75 起**有意偏离**，依据上游 ed5378a `sme/utils.py::tokenize`
 * （_RUN_SPLIT_RE，2026-11-20 测试战役 P2-1）。向量里的 d07
 * （"abc中文123"）因此换为按 ed5378a 重录的期望值；其余 40 例不变。
 *
 * 混合词回归（自包含，不读向量）：期望 token 序列是上游 ed5378a 的
 * tokenize 在同一批输入上的实际输出（录制时只读加载上游
 * sme/utils.py），对应上游回归用例 experiment/regression/
 * test_fix_round2_20261120.py::test_tokenize_mixed_run_keeps_latin_words /
 * test_mixed_word_bm25_recall。覆盖：
 *   - 混合 run 按书写系统切段：拉丁整词保留、CJK 段逐字 + 段内二元组；
 *     顺序 = 段序，CJK 段先全部单字再全部二元组；
 *   - 多段交替、CJK 与数字相邻、单个 CJK 字符相邻等边界；
 *   - 纯 CJK / 纯拉丁输入与 e72bc75 基线逐 token 相同；
 *   - BM25 索引与查询共用同一分词入口：纯拉丁查询经关键词通道命中
 *     混合词文档（基线下文档侧没有 "gpt" 这个 token，分数恒为 0）。
 *
 * 输出：SUMMARY text checked=<n> mismatch=<m>；有失配 exit 1。
 */
#include "retrieval/bm25.h"
#include "retrieval/text.h"
#include "store/store_json.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checked;
static size_t mismatched;

static void check(int cond, const char *fmt, ...)
{
	va_list ap;

	checked++;
	if (cond)
		return;
	mismatched++;
	printf("MISMATCH ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}

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

/* hex -> malloc 的 NUL 结尾字符串；失败 NULL */
static char *hex_to_str(const char *hex, size_t *out_len)
{
	size_t n = strlen(hex) / 2;
	unsigned char *tmp = malloc(n + 1);
	char *s;

	if (!tmp)
		return NULL;
	if (hex_to_bytes(hex, tmp, n + 1) != n) {
		free(tmp);
		return NULL;
	}
	tmp[n] = '\0';
	s = (char *)tmp;
	if (out_len)
		*out_len = n;
	return s;
}

static void run_tokenize(const char *dir)
{
	char path[8192];
	char *buf;
	size_t len = 0;
	aik_json *root;
	const aik_json *list;

	snprintf(path, sizeof(path), "%s/text/text.vectors.json", dir);
	buf = read_file(path, &len);
	if (!buf) {
		mismatched++;
		printf("MISMATCH text.vectors.json missing\n");
		return;
	}
	root = aik_json_parse(buf, len, NULL, 0);
	free(buf);
	if (!root) {
		mismatched++;
		printf("MISMATCH text.vectors.json parse failed\n");
		return;
	}
	list = aik_json_get(root, "tokenize");
	if (!list) {
		mismatched++;
		printf("MISMATCH no tokenize section\n");
		aik_json_free(root);
		return;
	}

	for (size_t ci = 0; ci < aik_json_count(list); ci++) {
		const aik_json *c = aik_json_at(list, ci);
		const aik_json *toks = aik_json_get(c, "tokens_hex");
		const char *doc = aik_json_str(aik_json_get(c, "doc"));
		const char *text_hex = aik_json_str(aik_json_get(c, "text_hex"));
		int bigram = aik_json_bool(aik_json_get(c, "cjk_bigram"));
		char *text;
		aik_token_list tl = { NULL, 0 };
		size_t want_n, i;
		int bad = 0;

		checked++;
		if (!toks || !doc || !text_hex) {
			mismatched++;
			printf("MISMATCH tokenize case %zu missing fields\n", ci);
			continue;
		}
		text = hex_to_str(text_hex, NULL);
		if (!text) {
			mismatched++;
			printf("MISMATCH %s bad text hex\n", doc);
			continue;
		}
		if (aik_tokenize(text, bigram, &tl, NULL, 0) != 0) {
			mismatched++;
			printf("MISMATCH %s tokenize failed\n", doc);
			free(text);
			continue;
		}
		want_n = aik_json_count(toks);
		if (tl.count != want_n) {
			mismatched++;
			printf("MISMATCH %s bigram=%d count got=%zu exp=%zu\n",
			       doc, bigram, tl.count, want_n);
			bad = 1;
		}
		for (i = 0; !bad && i < want_n; i++) {
			char *want = hex_to_str(aik_json_str(aik_json_at(toks, i)),
						NULL);

			if (!want) {
				mismatched++;
				printf("MISMATCH %s bad token hex\n", doc);
				bad = 1;
				break;
			}
			if (strcmp(want, tl.items[i]) != 0) {
				mismatched++;
				if (mismatched <= 10)
					printf("MISMATCH %s bigram=%d token %zu got=%s exp=%s\n",
					       doc, bigram, i, tl.items[i], want);
				bad = 1;
			}
			free(want);
		}
		aik_token_list_free(&tl);
		free(text);
	}
	aik_json_free(root);
}

static void run_negative(void)
{
	aik_token_list tl = { NULL, 0 };
	aik_token_list empty = { NULL, 0 };

	/* 非法 UTF-8 必须返回错误 */
	if (aik_tokenize("ok\xc0\xaf", 0, &tl, NULL, 0) != -1) {
		mismatched++;
		printf("MISMATCH invalid UTF-8 accepted\n");
		aik_token_list_free(&tl);
	}
	/* 空串 0 token */
	if (aik_tokenize("", 1, &tl, NULL, 0) != 0 || tl.count != 0) {
		mismatched++;
		printf("MISMATCH empty string\n");
		aik_token_list_free(&tl);
	}
	aik_token_list_free(&empty);
}

/* ------------------------------------------------------------------ */
/* MEM-01a：混合词分词回归（自包含）                                   */
/* ------------------------------------------------------------------ */

/* expect = 以 '/' 分隔的期望 token 序列；比较数量与逐项内容 */
static void expect_tokens(const char *text, int bigram, const char *expect)
{
	aik_token_list tl = { NULL, 0 };
	char err[256];
	const char *p = expect;
	size_t i = 0;
	int bad = 0;

	if (aik_tokenize(text, bigram, &tl, err, sizeof(err)) != 0) {
		check(0, "mixed tokenize %s: failed: %s", text, err);
		return;
	}
	for (;;) {
		const char *slash = strchr(p, '/');
		size_t n = slash ? (size_t)(slash - p) : strlen(p);

		if (n == 0 && !slash && i == 0 && tl.count == 0)
			break;	/* 期望空序列 */
		if (i >= tl.count) {
			check(0, "mixed tokenize bigram=%d: count got=%zu exp>%zu",
			      bigram, tl.count, i);
			bad = 1;
			break;
		}
		if (strlen(tl.items[i]) != n || memcmp(tl.items[i], p, n) != 0) {
			check(0, "mixed tokenize bigram=%d token %zu got=%s exp=%.*s",
			      bigram, i, tl.items[i], (int)n, p);
			bad = 1;
			break;
		}
		i++;
		if (!slash)
			break;
		p = slash + 1;
	}
	if (!bad && i != tl.count)
		check(0, "mixed tokenize bigram=%d count got=%zu exp=%zu",
		      bigram, tl.count, i);
	else if (!bad)
		checked++;
	aik_token_list_free(&tl);
}

static int tl_has(const aik_token_list *tl, const char *tok)
{
	size_t i;

	for (i = 0; i < tl->count; i++)
		if (strcmp(tl->items[i], tok) == 0)
			return 1;
	return 0;
}

static void run_mixed_tokenize(void)
{
	static const struct {
		const char *text;
		int bigram;
		const char *expect;
	} cases[] = {
		/* 上游 P2-1 回归用例的三条混合词文档 */
		{ "GPT模型的推理能力很强", 0,
		  "gpt/模/型/的/推/理/能/力/很/强" },
		{ "GPT模型的推理能力很强", 1,
		  "gpt/模/型/的/推/理/能/力/很/强/模型/型的/的推/推理/理能/能力/力很/很强" },
		{ "iPhone手机的价格", 0, "iphone/手/机/的/价/格" },
		{ "iPhone手机的价格", 1,
		  "iphone/手/机/的/价/格/手机/机的/的价/价格" },
		{ "Python语言的生态很好", 0, "python/语/言/的/生/态/很/好" },
		{ "Python语言的生态很好", 1,
		  "python/语/言/的/生/态/很/好/语言/言的/的生/生态/态很/很好" },
		/* parity 向量里的 d07：e72bc75 基线为 a/b/c/中/文/1/2/3 */
		{ "abc中文123", 0, "abc/中/文/123" },
		{ "abc中文123", 1, "abc/中/文/中文/123" },
		/* 多段交替：每段先单字、CJK 段再二元组 */
		{ "中文abc中文", 0, "中/文/abc/中/文" },
		{ "中文abc中文", 1, "中/文/中文/abc/中/文/中文" },
		{ "a中b文c", 0, "a/中/b/文/c" },
		{ "a中b文c", 1, "a/中/b/文/c" },
		/* 单字符拉丁段、单个 CJK 字符相邻 */
		{ "GPT模", 0, "gpt/模" },
		{ "GPT模", 1, "gpt/模" },
		{ "模", 0, "模" },
		{ "x", 1, "x" },
		/* CJK 与数字相邻 */
		{ "第1章abc", 1, "第/1/章/abc" },
		{ "中文123", 1, "中/文/中文/123" },
		{ "123中文", 1, "123/中/文/中文" },
		/* 标点切开的多个 run */
		{ "GPT-4模型的API接口v2版本", 1,
		  "gpt/4/模/型/的/模型/型的/api/接/口/接口/v2/版/本/版本" },
		{ "AIKernel的理念是：AI 是主体", 1,
		  "aikernel/的/理/念/是/的理/理念/念是/ai/是/主/体/是主/主体" },
		{ "用Python写代码", 1, "用/python/写/代/码/写代/代码" },
		{ "AI即系统AIKernel", 1, "ai/即/系/统/即系/系统/aikernel" },
		/* 基线不变的输入：纯 CJK / 纯拉丁 / 空 */
		{ "违约金", 0, "违/约/金" },
		{ "违约金", 1, "违/约/金/违约/约金" },
		{ "hello world", 1, "hello/world" },
		{ "ABC abc AbC", 1, "abc/abc/abc" },
		{ "合同违约金按合同总额的百分之三十计算。", 0,
		  "合/同/违/约/金/按/合/同/总/额/的/百/分/之/三/十/计/算" },
		{ "合同违约金按合同总额的百分之三十计算。", 1,
		  "合/同/违/约/金/按/合/同/总/额/的/百/分/之/三/十/计/算/合同/同违/违约/约金/金按/按合/合同/同总/总额/额的/的百/百分/分之/之三/三十/十计/计算" },
		{ "", 1, "" },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		expect_tokens(cases[i].text, cases[i].bigram, cases[i].expect);
}

/* BM25 索引与查询共用 aik_tokenize：纯拉丁查询必须命中混合词文档 */
static void run_mixed_bm25(void)
{
	static const char *const docs[] = {
		"g1", "GPT模型的推理能力很强",
		"g2", "iPhone手机的价格很贵",
		"g3", "Python语言的生态很好",
		"n1", "违约金违约金违约金",
	};
	static const char *const ids[] = { "g1", "g2", "g3", "n1" };
	static const struct { const char *q; const char *top; } qs[] = {
		{ "GPT", "g1" }, { "iPhone", "g2" }, { "Python", "g3" },
		{ "iphone手机", "g2" }, { "gpt模型", "g1" },
		{ "iPhone手机的价格", "g2" },
	};
	int bigram;

	for (bigram = 0; bigram <= 1; bigram++) {
		char err[256];
		aik_bm25 *ix = aik_bm25_new(1.5, 0.75, bigram, err,
					    sizeof(err));
		size_t i;

		check(ix != NULL, "mixed bm25(%d): new failed: %s", bigram,
		      err);
		if (!ix)
			continue;
		for (i = 0; i < sizeof(docs) / sizeof(docs[0]); i += 2) {
			if (aik_bm25_add(ix, docs[i], docs[i + 1], err,
					 sizeof(err)) != 0)
				check(0, "mixed bm25(%d): add %s failed: %s",
				      bigram, docs[i], err);
		}
		for (i = 0; i < sizeof(qs) / sizeof(qs[0]); i++) {
			char **top_ids = NULL;
			size_t n_top = 0;

			if (aik_bm25_top(ix, qs[i].q, 3, NULL, 0, &top_ids,
					 &n_top, err, sizeof(err)) != 0) {
				check(0, "mixed bm25(%d): top(%s) failed: %s",
				      bigram, qs[i].q, err);
				continue;
			}
			check(n_top >= 1 && top_ids &&
			      strcmp(top_ids[0], qs[i].top) == 0,
			      "mixed bm25(%d): top(%s) = %s exp %s", bigram,
			      qs[i].q,
			      n_top && top_ids ? top_ids[0] : "(none)",
			      qs[i].top);
			free(top_ids);
		}
		/* 查询侧分词与索引同入口：gpt 对 g1 的原始分必须 > 0 */
		{
			aik_token_list q = { NULL, 0 };
			double raw[4];

			if (aik_tokenize("GPT", bigram, &q, err, sizeof(err)) != 0) {
				check(0, "mixed bm25(%d): query tokenize: %s",
				      bigram, err);
			} else if (aik_bm25_scores(ix, &q, ids, 4, 0, raw, err,
						   sizeof(err)) != 0) {
				check(0, "mixed bm25(%d): scores failed: %s",
				      bigram, err);
			} else {
				check(q.count == 1 && strcmp(q.items[0], "gpt") == 0,
				      "mixed bm25(%d): query tokens=%zu first=%s",
				      bigram, q.count, q.count ? q.items[0] : "-");
				check(raw[0] > 0.0,
				      "mixed bm25(%d): score(g1,\"GPT\")=%g exp >0",
				      bigram, raw[0]);
				check(raw[1] == 0.0 && raw[2] == 0.0 &&
				      raw[3] == 0.0,
				      "mixed bm25(%d): score(others,\"GPT\")=%g/%g/%g exp 0",
				      bigram, raw[1], raw[2], raw[3]);
			}
			aik_token_list_free(&q);
		}
		/* 文档侧：拉丁整词进得了索引的 token 流，且无跨书写系统 bigram */
		{
			aik_token_list d = { NULL, 0 };

			if (aik_tokenize(docs[1], bigram, &d, NULL, 0) == 0) {
				check(tl_has(&d, "gpt"),
				      "mixed bm25(%d): doc g1 lacks gpt", bigram);
				check(!tl_has(&d, "t\xe6\xa8\xa1"),
				      "mixed bm25(%d): doc g1 has cross-script bigram",
				      bigram);
			} else {
				check(0, "mixed bm25(%d): doc tokenize failed",
				      bigram);
			}
			aik_token_list_free(&d);
		}
		aik_bm25_free(ix);
	}
}

int main(void)
{
	const char *dir = vectors_dir();

	run_tokenize(dir);
	run_negative();
	run_mixed_tokenize();
	run_mixed_bm25();

	printf("SUMMARY text checked=%zu mismatch=%zu\n", checked, mismatched);
	return mismatched ? 1 : 0;
}
