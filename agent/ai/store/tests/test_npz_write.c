/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_npz_write.c - store_npz_write 自测（T4c 保存路径门禁）
 *
 * 覆盖：
 *   1) 写 3 条（dim=4，generation=32 hex，含中文 id）→ T2 读侧
 *      aik_npz_open/aik_npz_read/aik_npy_parse 读回 ids/matrix/generation，
 *      字符串逐字相等、matrix 逐位（memcmp）相等；
 *   2) NPY 头：ids "<U<max codepoints>"、(n,)、头总长按 64 字节对齐；
 *      matrix "<f8"、(n,dim)、fortran_order=false；generation "<U32"、()；
 *   3) ZIP 结构：首字节 local header 签名、EOCD 在文件尾且条目数=3；
 *   4) 边界：n_ids=0 / generation="" / 非法 UTF-8 id / id 超过 64 码点
 *      均返回 -1 且不产生文件；成功写后目录里没有 .tmp.<pid> 残留。
 *
 * 末行 "SUMMARY npz_write checked=N mismatch=0"；有失配退出码 1。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_npz.h"
#include "store/store_npz_write.h"

#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_checked;
static int g_mismatch;

static void report(const char *fmt, ...)
{
	va_list ap;

	g_mismatch++;
	va_start(ap, fmt);
	fprintf(stderr, "FAIL: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

#define CHECK(cond) do {						\
	g_checked++;							\
	if (!(cond))							\
		report("%s:%d: CHECK(%s)", __FILE__, __LINE__, #cond);	\
} while (0)

static char *path_join(const char *dir, const char *name)
{
	size_t dl = strlen(dir);
	size_t nl = strlen(name);
	char *p = malloc(dl + nl + 2);

	if (!p)
		return NULL;
	memcpy(p, dir, dl);
	p[dl] = '/';
	memcpy(p + dl + 1, name, nl + 1);
	return p;
}

static unsigned char *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	long sz;
	unsigned char *buf;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
	    fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)sz ? (size_t)sz : 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = (size_t)sz;
	return buf;
}

static uint32_t rd32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int dir_entry_count(const char *dir)
{
	char cmd[2048];
	FILE *p;
	int n = 0;
	char line[4096];

	(void)snprintf(cmd, sizeof(cmd), "ls -1 '%s' 2>/dev/null | wc -l", dir);
	p = popen(cmd, "r");
	if (!p)
		return -1;
	if (fgets(line, sizeof(line), p))
		n = atoi(line);
	pclose(p);
	return n;
}

int main(void)
{
	static const char *ids[3] = {
		"m_000000000001",
		"记忆-α",
		"m_zz",
	};
	double matrix[3 * 4] = {
		1.5, -0.25, 0.0, 5e-324,
		-3.0, 0.125, 2.0, -0.0,
		1e300, -1e-300, 0.5, 42.0
	};
	static const char *gen =
		"0123456789abcdef0123456789abcdef";
	char err[512];
	char tmpdir[] = "/tmp/aik-npzw-XXXXXX";
	char *dir;
	char *path;
	aik_npz *z;
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	aik_npy ids_npy;
	aik_npy mat_npy;
	aik_npy gen_npy;
	size_t i;
	int rc;

	dir = mkdtemp(tmpdir);
	if (!dir) {
		fprintf(stderr, "mkdtemp failed\n");
		return 1;
	}
	path = path_join(dir, "emb.npz");
	if (!path) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	/* ---- 1) 正常写 ---- */
	err[0] = '\0';
	rc = aik_npz_write_embeddings(path, gen, ids, 3, matrix, 4, err,
				      sizeof(err));
	CHECK(rc == 0);
	if (rc != 0)
		fprintf(stderr, "write err: %s\n", err);
	CHECK(access(path, F_OK) == 0);
	CHECK(dir_entry_count(dir) == 1);

	raw = read_file(path, &raw_len);
	CHECK(raw != NULL);
	if (raw && raw_len >= 4) {
		CHECK(raw[0] == 0x50 && raw[1] == 0x4b && raw[2] == 0x03 &&
		      raw[3] == 0x04);
		/* 无注释的 EOCD 恰好 22 字节 */
		CHECK(raw_len >= 22);
		if (raw_len >= 22) {
			const unsigned char *eocd = raw + raw_len - 22;
			uint32_t total;

			total = (uint32_t)eocd[10] |
				((uint32_t)eocd[11] << 8);
			CHECK(rd32(eocd) == 0x06054b50u);
			CHECK(total == 3u);
		}
	}
	free(raw);
	raw = NULL;

	z = aik_npz_open(path, err, sizeof(err));
	CHECK(z != NULL);
	if (!z) {
		fprintf(stderr, "open err: %s\n", err);
		return 1;
	}
	CHECK(aik_npz_has(z, "ids"));
	CHECK(aik_npz_has(z, "matrix"));
	CHECK(aik_npz_has(z, "generation"));
	CHECK(aik_npz_count(z) == 3);

	if (aik_npz_read(z, "ids", &raw, &raw_len, err, sizeof(err)) == 0) {
		CHECK(aik_npy_parse(raw, raw_len, &ids_npy, err, sizeof(err)) ==
		      0);
		CHECK(strcmp(ids_npy.descr, "<U14") == 0);
		CHECK(ids_npy.ndim == 1);
		CHECK(ids_npy.shape[0] == 3);
		CHECK(ids_npy.fortran_order == 0);
		CHECK((10 + (size_t)((uint32_t)raw[8] |
				     ((uint32_t)raw[9] << 8))) %
				      64 ==
			      0);
		for (i = 0; i < 3; i++) {
			char got[128];
			int n;

			got[0] = '\0';
			n = aik_npy_get_ustr(&ids_npy, i, got, sizeof(got));
			CHECK(n >= 0);
			CHECK(strcmp(got, ids[i]) == 0);
		}
	} else {
		CHECK(0);
	}
	free(raw);
	raw = NULL;

	if (aik_npz_read(z, "matrix", &raw, &raw_len, err, sizeof(err)) == 0) {
		CHECK(aik_npy_parse(raw, raw_len, &mat_npy, err, sizeof(err)) ==
		      0);
		CHECK(strcmp(mat_npy.descr, "<f8") == 0);
		CHECK(mat_npy.ndim == 2);
		CHECK(mat_npy.shape[0] == 3);
		CHECK(mat_npy.shape[1] == 4);
		CHECK(aik_npy_nelem(&mat_npy) == 12);
		for (i = 0; i < 12; i++) {
			double got = 0.0;

			CHECK(aik_npy_get_f8(&mat_npy, i, &got) == 0);
			CHECK(memcmp(&got, &matrix[i], sizeof(double)) == 0);
		}
	} else {
		CHECK(0);
	}
	free(raw);
	raw = NULL;

	if (aik_npz_read(z, "generation", &raw, &raw_len, err, sizeof(err)) ==
	    0) {
		char got[128];

		CHECK(aik_npy_parse(raw, raw_len, &gen_npy, err, sizeof(err)) ==
		      0);
		CHECK(strcmp(gen_npy.descr, "<U32") == 0);
		CHECK(gen_npy.ndim == 0);
		CHECK(aik_npy_nelem(&gen_npy) == 1);
		CHECK(aik_npy_get_ustr(&gen_npy, 0, got, sizeof(got)) == 32);
		CHECK(strcmp(got, gen) == 0);
	} else {
		CHECK(0);
	}
	free(raw);
	raw = NULL;
	aik_npz_close(z);

	/* ---- 2) 边界 ---- */
	{
		char *p0 = path_join(dir, "zero.npz");

		err[0] = '\0';
		rc = aik_npz_write_embeddings(p0, gen, ids, 0, matrix, 4, err,
					      sizeof(err));
		CHECK(rc == -1);
		CHECK(err[0] != '\0');
		CHECK(access(p0, F_OK) != 0);
		free(p0);
	}
	{
		char *p1 = path_join(dir, "nogen.npz");

		err[0] = '\0';
		rc = aik_npz_write_embeddings(p1, "", ids, 3, matrix, 4, err,
					      sizeof(err));
		CHECK(rc == -1);
		CHECK(access(p1, F_OK) != 0);
		free(p1);
	}
	{
		static const char *bad[1] = { "m_bad\xff" };
		char *p2 = path_join(dir, "badutf.npz");

		err[0] = '\0';
		rc = aik_npz_write_embeddings(p2, gen, bad, 1, matrix, 4, err,
					      sizeof(err));
		CHECK(rc == -1);
		CHECK(access(p2, F_OK) != 0);
		free(p2);
	}
	{
		static const char *long_id[1] = {
			"0123456789abcdef0123456789abcdef"
			"0123456789abcdef0123456789abcdef"
			"0123456789abcdefX"
		};
		char *p3 = path_join(dir, "long.npz");

		err[0] = '\0';
		rc = aik_npz_write_embeddings(p3, gen, long_id, 1, matrix, 4,
					      err, sizeof(err));
		CHECK(rc == -1);
		CHECK(access(p3, F_OK) != 0);
		free(p3);
	}

	/* 只有成功的 emb.npz；临时文件已清理 */
	CHECK(dir_entry_count(dir) == 1);

	printf("SUMMARY npz_write checked=%d mismatch=%d\n", g_checked,
	       g_mismatch);
	free(path);
	(void)dir;
	return g_mismatch ? 1 : 0;
}
