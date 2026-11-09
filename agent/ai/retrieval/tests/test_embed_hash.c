/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_embed_hash.c - T3a hashing 嵌入 + BLAKE2b 向量自测
 *
 * 数据（$AIK_PARITY_VECTORS，默认 $HOME/aikernel-longterm/parity/vectors）：
 *   embed/reference.json : 45 例，逐维 double 与 "hex" 逐位相同
 *   embed/blake2b.tsv    : 300 例，digest 完全一致
 *   embed/unicode_lower.tsv       : 1,393 条码点小写映射
 *   embed/unicode_lower_cases.tsv : 27 条上下文用例（sigma/组合/emoji）
 *
 * 输出：SUMMARY embed_hash checked=<n> mismatch=<m>；有失配 exit 1。
 */
#include "memory/embed_hash.h"
#include "store/store_json.h"
#include "unicode.h"

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

/* 成功返回字节数，失败返回 SIZE_MAX */
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

static unsigned long long bits_of(double v)
{
	unsigned long long u;

	memcpy(&u, &v, sizeof(u));
	return u;
}

static void report_mismatch(const char *what, const char *id, size_t i,
			    double got, double exp)
{
	mismatched++;
	if (mismatched <= 10)
		printf("MISMATCH %s id=%s dim=%zu got=%016llx exp=%016llx\n",
		       what, id, i, bits_of(got), bits_of(exp));
}

static void run_reference(const char *dir)
{
	char path[8192];
	char *buf;
	size_t len = 0;
	aik_json *root;
	const aik_json *cases;

	snprintf(path, sizeof(path), "%s/embed/reference.json", dir);
	buf = read_file(path, &len);
	if (!buf) {
		mismatched++;
		printf("MISMATCH reference.json missing\n");
		return;
	}
	root = aik_json_parse(buf, len, NULL, 0);
	free(buf);
	if (!root) {
		mismatched++;
		printf("MISMATCH reference.json parse failed\n");
		return;
	}
	cases = aik_json_get(root, "cases");
	if (!cases) {
		mismatched++;
		printf("MISMATCH reference.json has no cases\n");
		aik_json_free(root);
		return;
	}

	for (size_t ci = 0; ci < aik_json_count(cases); ci++) {
		const aik_json *c = aik_json_at(cases, ci);
		const aik_json *p = aik_json_get(c, "params");
		const aik_json *vec = aik_json_get(c, "vector");
		const aik_json *hex = aik_json_get(c, "hex");
		const char *id = aik_json_str(aik_json_get(c, "id"));
		const char *text = aik_json_str(aik_json_get(c, "text"));
		aik_hash_params hp;
		int expect_dim, got_dim;
		double out[512];
		size_t i, n;

		checked++;
		if (!p || !vec || !hex || !id || !text) {
			mismatched++;
			printf("MISMATCH case %zu missing fields\n", ci);
			continue;
		}
		memset(&hp, 0, sizeof(hp));
		hp.dim = (int)aik_json_int(aik_json_get(p, "dim"));
		hp.factors = (int)aik_json_int(aik_json_get(p, "factors"));
		hp.window = (int)aik_json_int(aik_json_get(p, "window"));
		hp.seed = (unsigned long long)aik_json_int(
			aik_json_get(p, "seed"));
		hp.normalize_output = aik_json_bool(
			aik_json_get(p, "normalize_output"));
		hp.mrl_dim = (int)aik_json_int(aik_json_get(p, "mrl_dim"));
		expect_dim = (int)aik_json_int(aik_json_get(p, "effective_dim"));

		if (aik_hash_effective_dim(&hp) != expect_dim) {
			mismatched++;
			printf("MISMATCH %s effective_dim got=%d exp=%d\n",
			       id, aik_hash_effective_dim(&hp), expect_dim);
			continue;
		}
		got_dim = aik_hash_embed_one(&hp, text, out,
					     sizeof(out) / sizeof(out[0]),
					     NULL, 0);
		if (got_dim != expect_dim) {
			mismatched++;
			printf("MISMATCH %s embed got=%d exp=%d\n",
			       id, got_dim, expect_dim);
			continue;
		}
		n = aik_json_count(hex);
		if (n != (size_t)expect_dim || aik_json_count(vec) != n) {
			mismatched++;
			printf("MISMATCH %s vector length %zu/%zu exp %d\n",
			       id, aik_json_count(vec), n, expect_dim);
			continue;
		}
		for (i = 0; i < n; i++) {
			unsigned char hb[8];
			double exp;

			if (hex_to_bytes(aik_json_str(aik_json_at(hex, i)),
					 hb, sizeof(hb)) != 8) {
				mismatched++;
				printf("MISMATCH %s dim=%zu bad hex\n", id, i);
				break;
			}
			memcpy(&exp, hb, sizeof(exp));
			if (memcmp(&exp, &out[i], sizeof(double)) != 0)
				report_mismatch("embed", id, i, out[i], exp);
		}
	}
	aik_json_free(root);
}

static void run_blake2b(const char *dir)
{
	char path[8192];
	char *buf;
	size_t len = 0;
	char *p;

	snprintf(path, sizeof(path), "%s/embed/blake2b.tsv", dir);
	buf = read_file(path, &len);
	if (!buf) {
		mismatched++;
		printf("MISMATCH blake2b.tsv missing\n");
		return;
	}
	(void)len;
	p = buf;
	while (*p) {
		char *nl = strchr(p, '\n');
		char *tab;
		unsigned char in[4096];
		unsigned char dg[8];
		size_t in_len;
		char want[17];
		int i;

		if (nl)
			*nl = '\0';
		if (*p && p[strlen(p) - 1] == '\r')
			p[strlen(p) - 1] = '\0';
		if (*p == '\0') {
			if (!nl)
				break;
			p = nl + 1;
			continue;
		}
		checked++;
		tab = strchr(p, '\t');
		if (!tab) {
			mismatched++;
			printf("MISMATCH blake2b.tsv malformed line\n");
		} else {
			*tab = '\0';
			in_len = hex_to_bytes(p, in, sizeof(in));
			if (in_len == SIZE_MAX || aik_blake2b64(in, in_len,
							       dg) != 0) {
				mismatched++;
				printf("MISMATCH blake2b input %s\n", p);
			} else {
				for (i = 0; i < 8; i++)
					snprintf(want + 2 * i, 3, "%02x", dg[i]);
				want[16] = '\0';
				if (strcmp(want, tab + 1) != 0) {
					mismatched++;
					if (mismatched <= 10)
						printf("MISMATCH blake2b in=%s got=%s exp=%s\n",
						       p, want, tab + 1);
				}
			}
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	free(buf);
}

static void check_lower_line(const char *in, size_t in_len,
			     const char *want_hex, const char *what)
{
	unsigned char want[512];
	size_t wn = hex_to_bytes(want_hex, want, sizeof(want));
	char *got;

	if (wn == SIZE_MAX) {
		mismatched++;
		printf("MISMATCH %s bad expected hex\n", what);
		return;
	}
	got = aik_unicode_lower_alloc(in, NULL, 0);
	if (!got) {
		mismatched++;
		printf("MISMATCH %s lower failed\n", what);
		return;
	}
	if (strlen(got) != wn || memcmp(got, want, wn) != 0) {
		mismatched++;
		if (mismatched <= 10)
			printf("MISMATCH %s in=%s got_len=%zu exp_len=%zu\n",
			       what, in, strlen(got), wn);
	}
	free(got);
	(void)in_len;
}

static void run_unicode_lower(const char *dir)
{
	char path[8192];
	char *buf;
	size_t len = 0;
	char *p;

	/* 表：码点（hex） -> 小写 UTF-8 字节（hex） */
	snprintf(path, sizeof(path), "%s/embed/unicode_lower.tsv", dir);
	buf = read_file(path, &len);
	if (!buf) {
		mismatched++;
		printf("MISMATCH unicode_lower.tsv missing\n");
		return;
	}
	p = buf;
	while (*p) {
		char *nl = strchr(p, '\n');
		char *tab;

		if (nl)
			*nl = '\0';
		if (*p && p[strlen(p) - 1] == '\r')
			p[strlen(p) - 1] = '\0';
		if (*p) {
			char in[8];
			size_t in_len;
			unsigned long cp;

			checked++;
			tab = strchr(p, '\t');
			if (!tab) {
				mismatched++;
				printf("MISMATCH unicode_lower.tsv malformed\n");
			} else {
				*tab = '\0';
				cp = strtoul(p, NULL, 16);
				in_len = aik_utf8_encode((unsigned int)cp, in);
				in[in_len] = '\0';
				check_lower_line(in, in_len, tab + 1,
						 "unicode_lower");
			}
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	free(buf);

	/* 上下文：输入 UTF-8 字节（hex） -> 输出 UTF-8 字节（hex） */
	snprintf(path, sizeof(path), "%s/embed/unicode_lower_cases.tsv", dir);
	buf = read_file(path, &len);
	if (!buf) {
		mismatched++;
		printf("MISMATCH unicode_lower_cases.tsv missing\n");
		return;
	}
	p = buf;
	while (*p) {
		char *nl = strchr(p, '\n');
		char *tab;

		if (nl)
			*nl = '\0';
		if (*p && p[strlen(p) - 1] == '\r')
			p[strlen(p) - 1] = '\0';
		checked++;
		tab = strchr(p, '\t');
		if (!tab) {
			mismatched++;
			printf("MISMATCH unicode_lower_cases.tsv malformed\n");
		} else {
			unsigned char in[512];
			size_t in_len;

			*tab = '\0';
			in_len = hex_to_bytes(p, in, sizeof(in) - 1);
			if (in_len == SIZE_MAX) {
				mismatched++;
				printf("MISMATCH cases bad input hex\n");
			} else {
				in[in_len] = '\0';
				check_lower_line((const char *)in, in_len,
						 tab + 1, "unicode_cases");
			}
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	free(buf);
	(void)len;
}

static void run_negative(void)
{
	aik_hash_params hp;
	double out[8];
	int rc;

	memset(&hp, 0, sizeof(hp));
	hp.dim = 8;
	hp.factors = 1;
	hp.window = 2;
	hp.seed = 42;
	hp.normalize_output = 1;
	hp.mrl_dim = 0;

	/* 非法 UTF-8 必须报错，不得静默替换 */
	rc = aik_hash_embed_one(&hp, "a\xff\xfe" "b", out, 8, NULL, 0);
	if (rc != -1) {
		mismatched++;
		printf("MISMATCH invalid UTF-8 accepted (rc=%d)\n", rc);
	}
	/* 空串可用（_empty_ 回退） */
	rc = aik_hash_embed_one(&hp, "", out, 8, NULL, 0);
	if (rc != 8) {
		mismatched++;
		printf("MISMATCH empty text rc=%d\n", rc);
	}
	if (aik_hash_embed_one(&hp, "x", out, 4, NULL, 0) != -1) {
		mismatched++;
		printf("MISMATCH small out buffer accepted\n");
	}
}

int main(void)
{
	const char *dir = vectors_dir();

	run_reference(dir);
	run_blake2b(dir);
	run_unicode_lower(dir);
	run_negative();

	printf("SUMMARY embed_hash checked=%zu mismatch=%zu\n",
	       checked, mismatched);
	return mismatched ? 1 : 0;
}
