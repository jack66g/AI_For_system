/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_text.c - T3a tokenize 向量自测
 *
 * 数据：$AIK_PARITY_VECTORS/text/text.vectors.json 的 tokenize 段
 * （42 例，逐 token 输入/输出都用 hex，避免编码歧义）。
 *
 * 输出：SUMMARY text checked=<n> mismatch=<m>；有失配 exit 1。
 */
#include "retrieval/text.h"
#include "store/store_json.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(void)
{
	const char *dir = vectors_dir();

	run_tokenize(dir);
	run_negative();

	printf("SUMMARY text checked=%zu mismatch=%zu\n", checked, mismatched);
	return mismatched ? 1 : 0;
}
