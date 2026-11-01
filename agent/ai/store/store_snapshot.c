/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_snapshot.c - engine.json[.gz] 快照读路径
 *
 * 设计依据 T2-DESIGN.md §5。读取整文件后按「后缀 .gz 或文件头 1f 8b」
 * 判定是否 gzip：是则走 aik_gzip_inflate（256 MiB 上限），否则直接当
 * UTF-8 JSON 文本。文本与 DOM 一起交给 aik_snapshot_free。
 *
 * validate 只覆盖 T2a 门禁需要的最小集（见头文件）；字段级 schema 的完整
 * 校验属于 T4 接入时的引擎侧工作。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_snapshot.h"

#include "store/store_gzip.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SNAP_MAX_FILE (256u * 1024u * 1024u)

static void snap_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	(void)vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

static int read_file(const char *path, unsigned char **out, size_t *len,
		     char *err, size_t errlen)
{
	FILE *f;
	long sz;
	unsigned char *buf;

	f = fopen(path, "rb");
	if (!f) {
		snap_err(err, errlen, "snapshot: cannot open %s: %s", path,
			 strerror(errno));
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		snap_err(err, errlen, "snapshot: seek failed on %s", path);
		fclose(f);
		return -1;
	}
	sz = ftell(f);
	if (sz < 0) {
		snap_err(err, errlen, "snapshot: ftell failed on %s", path);
		fclose(f);
		return -1;
	}
	if ((unsigned long)sz > SNAP_MAX_FILE) {
		snap_err(err, errlen, "snapshot: file too large (%ld)", sz);
		fclose(f);
		return -1;
	}
	rewind(f);
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		snap_err(err, errlen, "snapshot: out of memory");
		fclose(f);
		return -1;
	}
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		snap_err(err, errlen, "snapshot: short read on %s", path);
		free(buf);
		fclose(f);
		return -1;
	}
	buf[sz] = '\0';
	fclose(f);
	*out = buf;
	*len = (size_t)sz;
	return 0;
}

/* 后缀 .gz 或 gzip magic 都算 gzip */
static int looks_gzip(const char *path, const unsigned char *buf, size_t len)
{
	size_t n;

	if (buf && len >= 2 && buf[0] == 0x1f && buf[1] == 0x8b)
		return 1;
	if (!path)
		return 0;
	n = strlen(path);
	if (n >= 3 && strcmp(path + n - 3, ".gz") == 0)
		return 1;
	return 0;
}

int aik_snapshot_load(const char *path, aik_snapshot *out,
		      char *err, size_t errlen)
{
	unsigned char *raw = NULL;
	unsigned char *text = NULL;
	size_t raw_len = 0, text_len = 0;

	if (!out) {
		snap_err(err, errlen, "snapshot: null output");
		return -1;
	}
	memset(out, 0, sizeof(*out));
	if (err && errlen)
		err[0] = '\0';
	if (!path) {
		snap_err(err, errlen, "snapshot: null path");
		return -1;
	}

	if (read_file(path, &raw, &raw_len, err, errlen) != 0)
		return -1;

	if (looks_gzip(path, raw, raw_len)) {
		if (aik_gzip_inflate(raw, raw_len, &text, &text_len,
				     err, errlen) != 0) {
			free(raw);
			return -1;
		}
		free(raw);
	} else {
		text = raw;
		text_len = raw_len;
	}

	out->root = aik_json_parse((const char *)text, text_len, err, errlen);
	if (!out->root) {
		free(text);
		return -1;
	}
	out->json = text;
	out->json_len = text_len;
	return 0;
}

void aik_snapshot_free(aik_snapshot *s)
{
	if (!s)
		return;
	aik_json_free(s->root);
	free(s->json);
	memset(s, 0, sizeof(*s));
}

/* basename 安全性：非空、无 '/'、无反斜杠、无 ".."、不是 . 或 .. */
static int basename_ok(const char *name, size_t n)
{
	size_t i;

	if (!name || n == 0 || n > 255)
		return 0;
	if (n == 1 && name[0] == '.')
		return 0;
	for (i = 0; i < n; i++) {
		if (name[i] == '/' || name[i] == 0x5c || name[i] == ':')
			return 0;
		if (name[i] == '.' && i + 1 < n && name[i + 1] == '.')
			return 0;
		if ((unsigned char)name[i] < 0x20)
			return 0;
	}
	return 1;
}

static int require_key(const aik_json *root, const char *key,
		       aik_json_type want, char *err, size_t errlen)
{
	const aik_json *v = aik_json_get(root, key);

	if (!v) {
		snap_err(err, errlen, "snapshot: missing key \"%s\"", key);
		return -1;
	}
	if (aik_json_typeof(v) != want) {
		snap_err(err, errlen, "snapshot: key \"%s\" has wrong type", key);
		return -1;
	}
	return 0;
}

int aik_snapshot_validate(const aik_snapshot *s, char *err, size_t errlen)
{
	const aik_json *root, *ver, *emb;
	const char *name;
	size_t n;

	if (!s || !s->root) {
		snap_err(err, errlen, "snapshot: empty snapshot");
		return -1;
	}
	root = s->root;
	if (aik_json_typeof(root) != AIK_JSON_OBJ) {
		snap_err(err, errlen, "snapshot: root is not an object");
		return -1;
	}
	ver = aik_json_get(root, "schema_version");
	if (!ver) {
		snap_err(err, errlen, "snapshot: missing schema_version");
		return -1;
	}
	if (aik_json_typeof(ver) != AIK_JSON_INT || aik_json_int(ver) != 2) {
		snap_err(err, errlen, "snapshot: schema_version != 2");
		return -1;
	}
	if (require_key(root, "memories", AIK_JSON_ARR, err, errlen) != 0)
		return -1;
	if (require_key(root, "regions", AIK_JSON_ARR, err, errlen) != 0)
		return -1;
	if (require_key(root, "region_edges", AIK_JSON_ARR, err, errlen) != 0)
		return -1;
	if (require_key(root, "memory_edges", AIK_JSON_ARR, err, errlen) != 0)
		return -1;
	if (require_key(root, "config", AIK_JSON_OBJ, err, errlen) != 0)
		return -1;

	emb = aik_json_get(root, "embedding_file");
	if (!emb) {
		snap_err(err, errlen, "snapshot: missing embedding_file");
		return -1;
	}
	if (aik_json_typeof(emb) != AIK_JSON_STR) {
		snap_err(err, errlen, "snapshot: embedding_file is not a string");
		return -1;
	}
	name = aik_json_str(emb);
	n = aik_json_strlen(emb);
	if (!basename_ok(name, n)) {
		snap_err(err, errlen,
			 "snapshot: embedding_file is not a safe basename");
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* T2b-1：原子写                                                       */
/* ------------------------------------------------------------------ */

static int write_all(int fd, const unsigned char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

/* rename 后 fsync 父目录，保证目录项落盘；无 '/' 时用 "." */
static int fsync_dir_of(const char *path, char *err, size_t errlen)
{
	char *dir;
	char *slash;
	int fd;

	dir = strdup(path);
	if (!dir) {
		snap_err(err, errlen, "snapshot: out of memory");
		return -1;
	}
	slash = strrchr(dir, '/');
	if (!slash)
		(void)strcpy(dir, ".");
	else if (slash == dir)
		slash[1] = '\0';
	else
		*slash = '\0';

	fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		snap_err(err, errlen, "snapshot: cannot open directory %s: %s",
			 dir, strerror(errno));
		free(dir);
		return -1;
	}
	if (fsync(fd) != 0) {
		snap_err(err, errlen,
			 "snapshot: fsync failed on directory %s: %s",
			 dir, strerror(errno));
		(void)close(fd);
		free(dir);
		return -1;
	}
	if (close(fd) != 0) {
		snap_err(err, errlen,
			 "snapshot: close failed on directory %s: %s",
			 dir, strerror(errno));
		free(dir);
		return -1;
	}
	free(dir);
	return 0;
}

int aik_snapshot_save(const aik_json *root, const char *path, int gzip,
		      char *err, size_t errlen)
{
	char *text = NULL, *tmp = NULL;
	unsigned char *packed = NULL;
	const unsigned char *data;
	size_t text_len = 0, packed_len = 0, data_len, tlen;
	int fd = -1, rc = -1;

	if (err && errlen)
		err[0] = '\0';
	if (!root) {
		snap_err(err, errlen, "snapshot: null root");
		return -1;
	}
	if (!path || !*path) {
		snap_err(err, errlen, "snapshot: null path");
		return -1;
	}
	if (aik_json_dump(root, &text, &text_len) != 0 || !text) {
		snap_err(err, errlen, "snapshot: cannot serialize root");
		return -1;
	}
	if (gzip) {
		char gerr[256] = "";

		if (aik_gzip_deflate(text, text_len, 9, &packed, &packed_len,
				     gerr, sizeof(gerr)) != 0) {
			snap_err(err, errlen, "snapshot: %s",
				 gerr[0] ? gerr : "gzip compression failed");
			free(text);
			return -1;
		}
		data = packed;
		data_len = packed_len;
	} else {
		data = (const unsigned char *)text;
		data_len = text_len;
	}

	tlen = strlen(path);
	tmp = malloc(tlen + 32);
	if (!tmp) {
		snap_err(err, errlen, "snapshot: out of memory");
		goto out;
	}
	(void)snprintf(tmp, tlen + 32, "%s.tmp.%ld", path, (long)getpid());

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		snap_err(err, errlen, "snapshot: cannot create %s: %s", tmp,
			 strerror(errno));
		goto out;
	}
	if (write_all(fd, data, data_len) != 0) {
		snap_err(err, errlen, "snapshot: write failed on %s: %s", tmp,
			 strerror(errno));
		goto out;
	}
	if (fsync(fd) != 0) {
		snap_err(err, errlen, "snapshot: fsync failed on %s: %s", tmp,
			 strerror(errno));
		goto out;
	}
	if (close(fd) != 0) {
		fd = -1;
		snap_err(err, errlen, "snapshot: close failed on %s: %s", tmp,
			 strerror(errno));
		goto out;
	}
	fd = -1;
	if (rename(tmp, path) != 0) {
		snap_err(err, errlen, "snapshot: rename %s -> %s failed: %s",
			 tmp, path, strerror(errno));
		goto out;
	}
	if (fsync_dir_of(path, err, errlen) != 0)
		goto out;
	rc = 0;

out:
	if (fd >= 0)
		(void)close(fd);
	if (rc != 0 && tmp)
		(void)unlink(tmp);
	free(tmp);
	free(packed);
	free(text);
	return rc;
}
