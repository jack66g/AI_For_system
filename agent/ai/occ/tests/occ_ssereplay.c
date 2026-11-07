/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_ssereplay.c - 差分台架驱动：SSE 字节流回放 → 规范化 JSON
 * 用法: occ_ssereplay <openai|anthropic> <file|->
 * stdout: 规范化 JSON + "\n"
 * exit: 0 干净；3 检出错误（坏块/截断/负向）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../occ_llm/occ_llm.h"
#include "occ_norm.h"

#define REPLAY_CHUNK 7		/* 固定小切片喂入：跨块切分路径同被台架覆盖 */

static char *read_all(FILE *f, size_t *outlen)
{
	size_t cap = 65536, len = 0;
	char *buf = malloc(cap);

	while (buf) {
		size_t n;

		if (len + 1 >= cap) {
			char *nb;

			cap *= 2;
			nb = realloc(buf, cap);
			if (!nb) {
				free(buf);
				return NULL;
			}
			buf = nb;
		}
		n = fread(buf + len, 1, cap - 1 - len, f);
		len += n;
		if (n == 0)
			break;
	}
	if (buf)
		buf[len] = '\0';
	if (outlen)
		*outlen = len;
	return buf;
}

int main(int argc, char **argv)
{
	occ_protocol proto;
	occ_norm *n;
	occ_sse *s;
	char *data;
	size_t len, off;
	FILE *f = stdin;
	char *out;
	int rc = 0;

	if (argc != 3 ||
	    (strcmp(argv[1], "openai") && strcmp(argv[1], "anthropic"))) {
		fprintf(stderr, "usage: occ_ssereplay <openai|anthropic> <file|->\n");
		return 2;
	}
	proto = !strcmp(argv[1], "openai") ?
		OCC_PROTO_OPENAI_COMPAT : OCC_PROTO_ANTHROPIC;
	if (strcmp(argv[2], "-")) {
		f = fopen(argv[2], "rb");
		if (!f) {
			fprintf(stderr, "occ_ssereplay: cannot open %s\n", argv[2]);
			return 2;
		}
	}
	data = read_all(f, &len);
	if (!data) {
		fprintf(stderr, "occ_ssereplay: read failed\n");
		if (f != stdin)
			fclose(f);
		return 2;
	}
	if (f != stdin)
		fclose(f);

	n = occ_norm_new();
	s = occ_sse_new(proto, occ_norm_event, n);
	for (off = 0; off < len; off += REPLAY_CHUNK) {
		size_t take = len - off > REPLAY_CHUNK ? REPLAY_CHUNK : len - off;

		occ_sse_feed(s, data + off, take);
	}
	occ_sse_finish(s);
	free(data);

	out = occ_norm_dump(n, NULL);
	if (!out) {
		fprintf(stderr, "occ_ssereplay: dump failed\n");
		rc = 1;
	} else {
		printf("%s\n", out);
		free(out);
		if (occ_norm_error_count(n) > 0 || occ_sse_error_count(s) > 0)
			rc = 3;
	}
	occ_sse_free(s);
	occ_norm_free(n);
	return rc;
}
