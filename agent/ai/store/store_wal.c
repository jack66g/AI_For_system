/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_wal.c - 追加式 JSON WAL（T2b-1）
 *
 * 设计依据 T2-DESIGN.md §7.1。写路径只做两件事：aik_json_dump 出紧凑
 * JSON，追加 "\n" 后按 O_APPEND 写入；fsync_each 时每条 fsync。只写
 * LF，不写 CRLF：Linux 目标下参考实现同样是纯 LF（冻结向量的 CRLF 只是
 * Windows 文本模式录制产物）。replay 按 '\n' 分行，行尾 '\r' 被 JSON
 * 解析器当空白接受，因此同时兼容 LF 与 CRLF 日志。
 * 读路径一次性读入文件后逐行解析：空行/纯空白行跳过（参考
 * line.strip()）；缺失 seq 视为 0（旧版无序号日志），present seq 必须
 * 是 >= 0 的 JSON 整数；seq=0 永不因 checkpoint 跳过。坏行、非整数 seq、
 * 负 seq、回调失败都立即报 "wal: record N: ..." 并返回 -1；文件不存在
 * 返回 0。replay 绝不修改文件（不截断、不删除），便于崩溃现场保留。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_wal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* replay 单次读入上限，与快照读路径的 256 MiB 保持一致 */
#define WAL_MAX_FILE (256u * 1024u * 1024u)

struct aik_wal {
	int fd;
	int fsync_each;
};

static void wal_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	(void)vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

aik_wal *aik_wal_open(const char *path, int fsync_each,
		      char *err, size_t errlen)
{
	aik_wal *w;
	int fd;

	if (err && errlen)
		err[0] = '\0';
	if (!path || !*path) {
		wal_err(err, errlen, "wal: null path");
		return NULL;
	}

	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
	if (fd < 0) {
		wal_err(err, errlen, "wal: cannot open %s: %s", path,
			strerror(errno));
		return NULL;
	}
	w = malloc(sizeof(*w));
	if (!w) {
		wal_err(err, errlen, "wal: out of memory");
		(void)close(fd);
		return NULL;
	}
	w->fd = fd;
	w->fsync_each = fsync_each ? 1 : 0;
	return w;
}

int aik_wal_append(aik_wal *w, const aik_json *op, char *err, size_t errlen)
{
	char *buf = NULL;
	size_t len = 0, total, off = 0;

	if (err && errlen)
		err[0] = '\0';
	if (!w) {
		wal_err(err, errlen, "wal: null handle");
		return -1;
	}
	if (!op) {
		wal_err(err, errlen, "wal: null op");
		return -1;
	}
	if (aik_json_dump(op, &buf, &len) != 0 || !buf) {
		wal_err(err, errlen, "wal: cannot serialize op");
		return -1;
	}

	/* dump 缓冲末尾的 NUL 正好换成记录分隔符 LF */
	buf[len] = '\n';
	total = len + 1;
	while (off < total) {
		ssize_t n = write(w->fd, buf + off, total - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			wal_err(err, errlen, "wal: write failed: %s",
				strerror(errno));
			free(buf);
			return -1;
		}
		if (n == 0) {
			wal_err(err, errlen, "wal: short write");
			free(buf);
			return -1;
		}
		off += (size_t)n;
	}
	free(buf);

	if (w->fsync_each && fsync(w->fd) != 0) {
		wal_err(err, errlen, "wal: fsync failed: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int aik_wal_close(aik_wal *w)
{
	int rc = 0;

	if (!w)
		return 0;
	if (close(w->fd) != 0)
		rc = -1;
	free(w);
	return rc;
}

/*
 * 读入整文件；成功 0，*out 带结尾 NUL。
 * 返回 1 表示文件不存在（ENOENT，参考实现视为空日志），其它失败 -1。
 */
static int wal_read_file(const char *path, unsigned char **out, size_t *len,
			 char *err, size_t errlen)
{
	struct stat st;
	unsigned char *buf;
	size_t sz, off = 0;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return 1;
		wal_err(err, errlen, "wal: cannot open %s: %s", path,
			strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) != 0) {
		wal_err(err, errlen, "wal: stat failed on %s: %s", path,
			strerror(errno));
		(void)close(fd);
		return -1;
	}
	if (st.st_size < 0 || (uintmax_t)st.st_size > WAL_MAX_FILE) {
		wal_err(err, errlen, "wal: file too large (%lld)",
			(long long)st.st_size);
		(void)close(fd);
		return -1;
	}
	sz = (size_t)st.st_size;
	buf = malloc(sz + 1);
	if (!buf) {
		wal_err(err, errlen, "wal: out of memory");
		(void)close(fd);
		return -1;
	}
	while (off < sz) {
		ssize_t n = read(fd, buf + off, sz - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			wal_err(err, errlen, "wal: read failed on %s: %s", path,
				strerror(errno));
			free(buf);
			(void)close(fd);
			return -1;
		}
		if (n == 0) {
			wal_err(err, errlen, "wal: short read on %s", path);
			free(buf);
			(void)close(fd);
			return -1;
		}
		off += (size_t)n;
	}
	(void)close(fd);
	buf[sz] = '\0';
	*out = buf;
	*len = sz;
	return 0;
}

/* 参考 line.strip()：整行只含空白（空格/tab/\r/\v/\f）视为空行 */
static int line_is_blank(const unsigned char *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (p[i] != ' ' && p[i] != '\t' && p[i] != '\r' &&
		    p[i] != '\v' && p[i] != '\f')
			return 0;
	}
	return 1;
}

int aik_wal_replay(const char *path, long long checkpoint,
		   aik_wal_visit fn, void *ctx,
		   char *err, size_t errlen)
{
	unsigned char *buf = NULL;
	size_t len = 0, pos = 0;
	long long record = 0, visited = 0;
	int rrc;

	if (err && errlen)
		err[0] = '\0';
	if (!path || !*path) {
		wal_err(err, errlen, "wal: null path");
		return -1;
	}
	if (!fn) {
		wal_err(err, errlen, "wal: null replay callback");
		return -1;
	}
	rrc = wal_read_file(path, &buf, &len, err, errlen);
	if (rrc == 1)
		return 0;	/* 文件不存在：参考实现直接返回 0 */
	if (rrc != 0)
		return -1;

	while (pos < len) {
		size_t start = pos, line_len;
		const unsigned char *nl = memchr(buf + pos, '\n', len - pos);
		const aik_json *op;
		const aik_json *seq;
		aik_json *parsed;
		long long seqval;
		char cerr[256];

		line_len = nl ? (size_t)(nl - (buf + pos)) : len - pos;
		pos = nl ? (size_t)(nl - buf) + 1 : len;
		record++;
		/* 空行/纯空白行跳过（参考 line.strip() 为空即 continue），
		 * 行号仍递增；这类行不交给回调、也不算错误。 */
		if (line_is_blank(buf + start, line_len))
			continue;
		parsed = aik_json_parse((const char *)(buf + start), line_len,
					cerr, sizeof(cerr));
		if (!parsed) {
			wal_err(err, errlen, "wal: record %lld: %s", record,
				cerr);
			free(buf);
			return -1;
		}
		if (aik_json_typeof(parsed) != AIK_JSON_OBJ) {
			wal_err(err, errlen,
				"wal: record %lld: not a JSON object", record);
			aik_json_free(parsed);
			free(buf);
			return -1;
		}
		seq = aik_json_get(parsed, "seq");
		if (!seq) {
			/* 参考 op.get("seq", 0)：缺失视为 0（旧版无序号日志） */
			seqval = 0;
		} else {
			if (aik_json_typeof(seq) != AIK_JSON_INT) {
				wal_err(err, errlen,
					"wal: record %lld: seq is not an integer",
					record);
				aik_json_free(parsed);
				free(buf);
				return -1;
			}
			seqval = aik_json_int(seq);
			if (seqval < 0) {
				wal_err(err, errlen,
					"wal: record %lld: seq must be >= 0 (got %lld)",
					record, seqval);
				aik_json_free(parsed);
				free(buf);
				return -1;
			}
		}
		/* 参考 if seq and seq <= checkpoint：seq=0 永不被跳过 */
		if (seqval != 0 && seqval <= checkpoint) {
			aik_json_free(parsed);
			continue;
		}
		op = parsed;
		cerr[0] = '\0';
		if (fn(ctx, op, cerr, sizeof(cerr)) != 0) {
			wal_err(err, errlen, "wal: record %lld: %s", record,
				cerr[0] ? cerr : "replay callback failed");
			aik_json_free(parsed);
			free(buf);
			return -1;
		}
		visited++;
		aik_json_free(parsed);
	}
	free(buf);
	return (int)visited;
}
