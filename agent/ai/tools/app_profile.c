// SPDX-License-Identifier: GPL-2.0
/*
 * app_profile.c - W81 V4 应用画像三件套（TOOL_CH_APPPROFILE）
 *
 * 见 app_profile.h 的设计说明。本文件分四段：
 *   1) 通用工具（有界 execv、字符串构造、JSON 转义、路径/参数解析）
 *   2) 静态画像（ELF 头自解析 + readelf -d/--dyn-syms + caps + desktop
 *      + dpkg 包来源）
 *   3) 动态画像（workspace 沙盒 + strace 优先 / /proc 采样退化 + TSV →
 *      JSON 事件流）
 *   4) 差集报告（静态声明 vs 动态行为 → 三栏 + 风险分 + 放行条件）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "workspace_tools.h"
#include "app_profile.h"

/* ======================================================================
 * 1) 通用工具
 * ====================================================================== */

struct apb {
	char *p;
	size_t len;
	size_t cap;
	int trunc;
};

static void apb_init(struct apb *b, char *buf, size_t cap)
{
	b->p = buf;
	b->len = 0;
	b->cap = cap;
	b->trunc = 0;
	if (cap)
		buf[0] = '\0';
}

static void apb_printf(struct apb *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!b->p || b->trunc || b->len + 1 >= b->cap) {
		b->trunc = 1;
		return;
	}
	va_start(ap, fmt);
	n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
	va_end(ap);
	if (n < 0) {
		b->trunc = 1;
		return;
	}
	if ((size_t)n >= b->cap - b->len) {
		b->len = b->cap - 1;
		b->trunc = 1;
		return;
	}
	b->len += (size_t)n;
}

static void apb_json_str(struct apb *b, const char *s)
{
	char *e = ai_json_escape(s ? s : "");

	apb_printf(b, "\"%s\"", e ? e : "");
	free(e);
}

static const char *ap_base(const char *p)
{
	const char *s;

	if (!p)
		return "";
	s = strrchr(p, '/');
	return s ? s + 1 : p;
}

static char *ap_trim(char *s)
{
	char *e;

	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
		s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' ||
			 e[-1] == '\n'))
		*--e = '\0';
	return s;
}

static int ap_has_ctl(const char *s)
{
	for (; s && *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c < 0x20 || c == 0x7f)
			return 1;
	}
	return 0;
}

static char *ap_read_file(const char *path, size_t max, size_t *out_len)
{
	int fd;
	char *buf;
	size_t cap = 4096, len = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	buf = malloc(cap + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}
	for (;;) {
		ssize_t n;

		if (len >= max) {
			buf[len] = '\0';
			break;
		}
		if (len == cap) {
			char *nbuf;

			if (cap >= max)
				cap = max;
			else
				cap *= 2;
			if (cap > max)
				cap = max;
			nbuf = realloc(buf, cap + 1);
			if (!nbuf) {
				free(buf);
				close(fd);
				return NULL;
			}
			buf = nbuf;
		}
		n = read(fd, buf + len, cap - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			close(fd);
			return NULL;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	buf[len] = '\0';
	close(fd);
	if (out_len)
		*out_len = len;
	return buf;
}

/*
 * 有界 fork/execv 采集 stdout+stderr 合流（尾部 ≤ AP_EXEC_RING 字节）。
 * 子进程新会话（setsid），超时 SIGKILL 整个进程组；LC_ALL=C 固定
 * readelf/dpkg 输出语言。返回 0=已执行（exit_code 有效），-1=启动失败。
 */
#define AP_EXEC_RING	(256 * 1024)

static int ap_exec_capture(char *const argv[], int timeout_sec, char **out,
			   int *exit_code, int *timed_out)
{
	int pipefd[2];
	pid_t pid;
	int st = 0;
	char *ring;
	size_t ring_off = 0, ring_fill = 0;
	long long deadline_ms;
	ssize_t n;

	*out = NULL;
	*exit_code = -1;
	*timed_out = 0;
	ring = malloc(AP_EXEC_RING);
	if (!ring)
		return -1;
	if (pipe(pipefd)) {
		free(ring);
		return -1;
	}
	fflush(stdout);
	fflush(stderr);
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		free(ring);
		return -1;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDONLY);

		close(pipefd[0]);
		setsid();
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			close(devnull);
		}
		setenv("LC_ALL", "C", 1);
		setenv("LANG", "C", 1);
		execvp(argv[0], argv);
		_exit(127);
	}
	close(pipefd[1]);
	fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
	deadline_ms = (long long)time(NULL) * 1000 +
		      (long long)timeout_sec * 1000;
	for (;;) {
		struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
		char chunk[4096];
		long long now_ms = (long long)time(NULL) * 1000;

		if (now_ms >= deadline_ms) {
			kill(-(pid_t)pid, SIGKILL);
			kill((pid_t)pid, SIGKILL);
			*timed_out = 1;
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0)
				;
			break;
		}
		if (poll(&pfd, 1, 200) > 0 &&
		    (pfd.revents & (POLLIN | POLLHUP))) {
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0) {
				int i;

				for (i = 0; i < (int)n; i++) {
					ring[ring_off] = chunk[i];
					ring_off = (ring_off + 1) %
						   AP_EXEC_RING;
					if (ring_fill < AP_EXEC_RING)
						ring_fill++;
				}
			}
		}
		if (pfd.revents & POLLHUP) {
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			break;
		}
		waitpid(pid, &st, WNOHANG);
	}
	close(pipefd[0]);
	{
		size_t start = (ring_fill < AP_EXEC_RING) ? 0 : ring_off;
		size_t i;

		*out = malloc(ring_fill + 1);
		if (!*out) {
			free(ring);
			return -1;
		}
		for (i = 0; i < ring_fill; i++)
			(*out)[i] = ring[(start + i) % AP_EXEC_RING];
		(*out)[ring_fill] = '\0';
	}
	free(ring);
	if (WIFEXITED(st))
		*exit_code = WEXITSTATUS(st);
	else if (WIFSIGNALED(st))
		*exit_code = 128 + WTERMSIG(st);
	return 0;
}

/* JSON 取参：字符串（malloc）/ 整数 / 布尔 */
static char *ap_arg_str(const char *json, const char *key)
{
	const char *val;
	size_t vlen;
	int type;

	if (!json)
		return NULL;
	if (ai_json_obj_get(json, strlen(json), key, &val, &vlen, &type) != 1)
		return NULL;
	if (type != AI_JSON_STR)
		return NULL;
	return ai_json_strdup_str(val, vlen);
}

static long long ap_arg_ll(const char *json, const char *key, long long def)
{
	const char *val;
	size_t vlen;
	int type;

	if (!json)
		return def;
	if (ai_json_obj_get(json, strlen(json), key, &val, &vlen, &type) != 1)
		return def;
	if (type != AI_JSON_NUM)
		return def;
	return ai_json_ll(val, vlen);
}

static int ap_arg_bool(const char *json, const char *key, int def)
{
	const char *val;
	size_t vlen;
	int type;

	if (!json)
		return def;
	if (ai_json_obj_get(json, strlen(json), key, &val, &vlen, &type) != 1)
		return def;
	if (type != AI_JSON_BOOL)
		return def;
	return (vlen > 0 && val[0] == 't') ? 1 : 0;
}

/* 解析 args 数组（最多 max 项，每项 ≤ 255 字节） */
static int ap_arg_argv(const char *json, char *argv[], int max,
		       char *err, size_t errcap)
{
	const char *arr;
	size_t alen;
	int type, i, n = 0;

	if (!json)
		return 0;
	if (ai_json_obj_get(json, strlen(json), "args", &arr, &alen,
			    &type) != 1)
		return 0;
	if (type != AI_JSON_ARR) {
		snprintf(err, errcap, "args 必须是字符串数组");
		return -1;
	}
	for (i = 0; i < max; i++) {
		const char *el;
		size_t elen;
		char *s;

		if (ai_json_arr_get(arr, alen, i, &el, &elen, &type) != 1)
			break;
		if (type != AI_JSON_STR) {
			snprintf(err, errcap, "args[%d] 不是字符串", i);
			return -1;
		}
		s = ai_json_strdup_str(el, elen);
		if (!s) {
			snprintf(err, errcap, "args[%d] 解码失败", i);
			return -1;
		}
		if (strlen(s) > 255 || ap_has_ctl(s)) {
			snprintf(err, errcap,
				 "args[%d] 超长（>255 字节）或含控制字符",
				 i);
			free(s);
			return -1;
		}
		argv[n++] = s;
	}
	/* 还有更多元素 → 超限 */
	{
		const char *el;
		size_t elen;

		if (ai_json_arr_get(arr, alen, n, &el, &elen, &type) == 1) {
			snprintf(err, errcap, "args 超过上限 %d 项", max);
			return -1;
		}
	}
	return n;
}

/* ======================================================================
 * 2) 静态画像
 * ====================================================================== */

static unsigned short ap_rd16(const unsigned char *p, int be)
{
	return be ? (unsigned short)((p[0] << 8) | p[1])
		  : (unsigned short)(p[0] | (p[1] << 8));
}

static unsigned int ap_rd32(const unsigned char *p, int be)
{
	if (be)
		return ((unsigned int)p[0] << 24) |
		       ((unsigned int)p[1] << 16) |
		       ((unsigned int)p[2] << 8) | p[3];
	return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
	       ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static unsigned long long ap_rd64(const unsigned char *p, int be)
{
	unsigned long long v = 0;
	int i;

	if (be) {
		for (i = 0; i < 8; i++)
			v = (v << 8) | p[i];
	} else {
		for (i = 7; i >= 0; i--)
			v = (v << 8) | p[i];
	}
	return v;
}

const char *ap_elf_type_str(unsigned t)
{
	switch (t) {
	case 0: return "NONE";
	case 1: return "REL";
	case 2: return "EXEC";
	case 3: return "DYN";
	case 4: return "CORE";
	default: return "OTHER";
	}
}

const char *ap_elf_machine_str(unsigned m)
{
	switch (m) {
	case 3: return "x86";
	case 8: return "mips";
	case 20: return "ppc";
	case 21: return "ppc64";
	case 22: return "s390";
	case 40: return "arm";
	case 62: return "x86-64";
	case 183: return "aarch64";
	case 243: return "riscv";
	default: return "unknown";
	}
}

struct ap_elf {
	int ok;
	int bits;
	int be;
	unsigned type;
	unsigned machine;
	unsigned long long entry;
	int has_interp;
	char interp[AP_PATH_MAX];
	int has_gnu_stack;
	int gnu_stack_exec;
	int has_relro;
};

static int ap_elf_parse(const char *path, struct ap_elf *e, char *err,
			size_t errcap)
{
	int fd;
	unsigned char eh[64];
	ssize_t n;
	struct stat sbuf;
	unsigned long long phoff;
	unsigned short phentsize, phnum;
	unsigned i;
	int rc = -1;

	memset(e, 0, sizeof(*e));
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		snprintf(err, errcap, "无法打开 %.400s：%s", path,
			 strerror(errno));
		return -1;
	}
	if (fstat(fd, &sbuf) != 0) {
		snprintf(err, errcap, "stat %.400s 失败：%s", path,
			 strerror(errno));
		close(fd);
		return -1;
	}
	n = read(fd, eh, sizeof(eh));
	if (n != (ssize_t)sizeof(eh)) {
		snprintf(err, errcap, "文件过短（%ld 字节），不是 ELF",
			 (long)sbuf.st_size);
		close(fd);
		return -1;
	}
	if (eh[0] != 0x7f || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F') {
		snprintf(err, errcap, "不是 ELF（magic 非 \\x7fELF）");
		close(fd);
		return -1;
	}
	if (eh[4] != 1 && eh[4] != 2) {
		snprintf(err, errcap, "非法 EI_CLASS=%u", eh[4]);
		close(fd);
		return -1;
	}
	if (eh[5] != 1 && eh[5] != 2) {
		snprintf(err, errcap, "非法 EI_DATA=%u", eh[5]);
		close(fd);
		return -1;
	}
	e->bits = eh[4] == 2 ? 64 : 32;
	e->be = eh[5] == 2;
	e->type = ap_rd16(eh + 16, e->be);
	e->machine = ap_rd16(eh + 18, e->be);
	if (e->bits == 64) {
		e->entry = ap_rd64(eh + 24, e->be);
		phoff = ap_rd64(eh + 32, e->be);
		phentsize = ap_rd16(eh + 54, e->be);
		phnum = ap_rd16(eh + 56, e->be);
	} else {
		e->entry = ap_rd32(eh + 24, e->be);
		phoff = ap_rd32(eh + 28, e->be);
		phentsize = ap_rd16(eh + 42, e->be);
		phnum = ap_rd16(eh + 44, e->be);
	}
	if (phnum == 0 || phnum > 512 || phentsize < (e->bits == 64 ? 56 : 32)) {
		snprintf(err, errcap, "程序头表异常（phnum=%u phentsize=%u）",
			 phnum, phentsize);
		close(fd);
		return -1;
	}
	if (phoff > (unsigned long long)sbuf.st_size) {
		snprintf(err, errcap, "程序头偏移越界（%llu）", phoff);
		close(fd);
		return -1;
	}
	for (i = 0; i < phnum; i++) {
		unsigned char ph[128];
		off_t off = (off_t)(phoff + (unsigned long long)i *
				    phentsize);
		unsigned ptype;
		unsigned pflags;
		unsigned long long poff, pfilesz;

		if (lseek(fd, off, SEEK_SET) != off)
			break;
		if (read(fd, ph, e->bits == 64 ? 56 : 32) !=
		    (e->bits == 64 ? 56 : 32))
			break;
		ptype = ap_rd32(ph, e->be);
		if (e->bits == 64) {
			pflags = ap_rd32(ph + 4, e->be);
			poff = ap_rd64(ph + 8, e->be);
			pfilesz = ap_rd64(ph + 32, e->be);
		} else {
			poff = ap_rd32(ph + 4, e->be);
			pfilesz = ap_rd32(ph + 16, e->be);
			pflags = ap_rd32(ph + 24, e->be);
		}
		if (ptype == 3) {	/* PT_INTERP */
			size_t want = (size_t)pfilesz;

			if (want >= sizeof(e->interp))
				want = sizeof(e->interp) - 1;
			if (lseek(fd, (off_t)poff, SEEK_SET) ==
			    (off_t)poff &&
			    read(fd, e->interp, want) == (ssize_t)want) {
				e->interp[want] = '\0';
				e->has_interp = 1;
			}
		} else if (ptype == 0x6474e551) {	/* PT_GNU_STACK */
			e->has_gnu_stack = 1;
			e->gnu_stack_exec = (pflags & 1) ? 1 : 0;
		} else if (ptype == 0x6474e552) {	/* PT_GNU_RELRO */
			e->has_relro = 1;
		}
	}
	close(fd);
	e->ok = 1;
	rc = 0;
	return rc;
}

/* readelf -d 输出解析 */
static int ap_extract_bracket(const char *line, char *out, size_t cap)
{
	const char *l = strchr(line, '[');
	const char *r = l ? strchr(l, ']') : NULL;
	size_t n;

	if (!l || !r || r <= l)
		return -1;
	n = (size_t)(r - l - 1);
	if (n >= cap)
		n = cap - 1;
	memcpy(out, l + 1, n);
	out[n] = '\0';
	return 0;
}

static void ap_split_paths(const char *s, char out[][512], int *n, int max)
{
	const char *p = s;

	*n = 0;
	while (*p && *n < max) {
		const char *c = strchr(p, ':');
		size_t len = c ? (size_t)(c - p) : strlen(p);
		char tmp[512];

		if (len >= sizeof(tmp))
			len = sizeof(tmp) - 1;
		memcpy(tmp, p, len);
		tmp[len] = '\0';
		if (tmp[0]) {
			snprintf(out[*n], 512, "%s", tmp);
			(*n)++;
		}
		if (!c)
			break;
		p = c + 1;
	}
}

int ap_dyn_parse(const char *txt, struct ap_dynsec *d, char *err,
		 size_t errcap)
{
	const char *p;
	int saw_section = 0;

	memset(d, 0, sizeof(*d));
	if (!txt || !txt[0]) {
		snprintf(err, errcap, "readelf 输出为空");
		return -1;
	}
	if (strstr(txt, "no dynamic section") != NULL) {
		snprintf(err, errcap, "无动态段（可能是静态链接）");
		return -1;
	}
	p = txt;
	while (*p) {
		const char *eol = strchr(p, '\n');
		char line[1024];
		size_t len = eol ? (size_t)(eol - p) : strlen(p);

		if (len >= sizeof(line))
			len = sizeof(line) - 1;
		memcpy(line, p, len);
		line[len] = '\0';
		if (strstr(line, "Dynamic section") != NULL)
			saw_section = 1;
		if (strstr(line, "(NEEDED)") != NULL && d->needed_n <
		    AP_MAX_NEEDED) {
			if (ap_extract_bracket(line, d->needed[d->needed_n],
					       128) == 0)
				d->needed_n++;
		} else if (strstr(line, "(SONAME)") != NULL) {
			ap_extract_bracket(line, d->soname, 128);
		} else if (strstr(line, "(RPATH)") != NULL ||
			   strstr(line, "(RUNPATH)") != NULL) {
			char tmp[512];
			int is_run = strstr(line, "(RUNPATH)") != NULL;

			if (ap_extract_bracket(line, tmp, sizeof(tmp)) == 0) {
				int before = is_run ? d->runpath_n :
						     d->rpath_n;

				if (is_run)
					ap_split_paths(tmp, d->runpath,
						       &d->runpath_n,
						       AP_MAX_RUNPATH);
				else
					ap_split_paths(tmp, d->rpath,
						       &d->rpath_n,
						       AP_MAX_RUNPATH);
				(void)before;
			}
		}
		if (strstr(line, "(FLAGS)") != NULL &&
		    strstr(line, "BIND_NOW") != NULL)
			d->bind_now = 1;
		if (strstr(line, "(FLAGS_1)") != NULL &&
		    strstr(line, "PIE") != NULL)
			d->pie_flag = 1;
		if (strstr(line, "(TEXTREL)") != NULL)
			d->textrel = 1;
		if (!eol)
			break;
		p = eol + 1;
	}
	if (!saw_section && !d->needed_n && !d->bind_now &&
	    !d->pie_flag && !d->textrel && !d->soname[0]) {
		snprintf(err, errcap,
			 "无法识别 readelf -d 输出（缺 Dynamic section）");
		return -1;
	}
	return 0;
}

int ap_dynsym_parse(const char *txt, struct ap_symcount *s, char *err,
		    size_t errcap)
{
	const char *p;
	int saw_table = 0;

	memset(s, 0, sizeof(*s));
	if (!txt || !txt[0]) {
		snprintf(err, errcap, "readelf --dyn-syms 输出为空");
		return -1;
	}
	if (strstr(txt, "no symbols") != NULL ||
	    strstr(txt, "No symbol table") != NULL) {
		snprintf(err, errcap, "无动态符号表（静态链接或已 strip）");
		return -1;
	}
	p = txt;
	while (*p) {
		const char *eol = strchr(p, '\n');
		char line[1024];
		size_t len = eol ? (size_t)(eol - p) : strlen(p);

		if (len >= sizeof(line))
			len = sizeof(line) - 1;
		memcpy(line, p, len);
		line[len] = '\0';
		if (strstr(line, "Symbol table") != NULL &&
		    strstr(line, "contains") != NULL) {
			const char *c = strstr(line, "contains");

			c += strlen("contains");
			while (*c == ' ')
				c++;
			s->total = atoi(c);
			saw_table = 1;
		} else {
			char tmp[1024];
			char *save = NULL, *tok;
			int idx = 0;
			const char *ttype = NULL, *ndx = NULL;

			snprintf(tmp, sizeof(tmp), "%s", line);
			for (tok = strtok_r(tmp, " \t", &save); tok;
			     tok = strtok_r(NULL, " \t", &save)) {
				if (idx == 3)
					ttype = tok;
				if (idx == 6)
					ndx = tok;
				idx++;
			}
			if (idx > 3 && ttype) {
				if (strcmp(ttype, "FUNC") == 0)
					s->func++;
				else if (strcmp(ttype, "OBJECT") == 0)
					s->object++;
				else if (strcmp(ttype, "IFUNC") == 0)
					s->ifunc++;
				else if (strcmp(ttype, "TLS") == 0)
					s->tls++;
				else if (strcmp(ttype, "NOTYPE") == 0)
					s->notype++;
				if (ndx && strcmp(ndx, "UND") == 0)
					s->undef++;
			}
		}
		if (!eol)
			break;
		p = eol + 1;
	}
	if (!saw_table) {
		snprintf(err, errcap, "未找到 Symbol table 头");
		return -1;
	}
	return 0;
}

int ap_dpkg_s_parse(const char *txt, char *pkg, size_t pkgcap, char *err,
		    size_t errcap)
{
	const char *p;
	char line[2048];
	const char *sep;

	pkg[0] = '\0';
	if (!txt || !txt[0]) {
		snprintf(err, errcap, "dpkg -S 无输出");
		return -1;
	}
	if (strstr(txt, "no path found matching pattern") != NULL) {
		snprintf(err, errcap, "dpkg -S 未命中（无包归属）");
		return 1;
	}
	if (strstr(txt, "dpkg: error") != NULL ||
	    strstr(txt, "dpkg-query: error") != NULL ||
	    strstr(txt, "not found") != NULL) {
		char tmp[512];

		snprintf(tmp, sizeof(tmp), "%s", txt);
		snprintf(err, errcap, "dpkg -S 报错：%s", ap_trim(tmp));
		return -1;
	}
	p = txt;
	{
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);

		if (len >= sizeof(line))
			len = sizeof(line) - 1;
		memcpy(line, p, len);
		line[len] = '\0';
	}
	sep = strstr(line, ": ");
	if (!sep) {
		snprintf(err, errcap, "dpkg -S 输出无法解析：%s", line);
		return -1;
	}
	{
		size_t n = (size_t)(sep - line);
		char *comma;

		if (n >= pkgcap)
			n = pkgcap - 1;
		memcpy(pkg, line, n);
		pkg[n] = '\0';
		comma = strchr(pkg, ',');
		if (comma)
			*comma = '\0';
		{
			char *t = ap_trim(pkg);

			if (t != pkg)
				memmove(pkg, t, strlen(t) + 1);
		}
	}
	if (!pkg[0]) {
		snprintf(err, errcap, "dpkg -S 输出包名为空");
		return -1;
	}
	return 0;
}

/* 取 Exec 的首个可执行 token（跳过 env 与 VAR=VAL） */
static int ap_lex_token(const char **pp, char *out, size_t cap)
{
	const char *p = *pp;
	size_t o = 0;
	char q = 0;

	while (*p == ' ' || *p == '\t')
		p++;
	if (!*p)
		return 0;
	if (*p == '"' || *p == '\'')
		q = *p++;
	while (*p) {
		if (q) {
			if (*p == q) {
				p++;
				break;
			}
		} else if (*p == ' ' || *p == '\t') {
			break;
		}
		if (*p == '\\' && p[1])
			p++;
		if (o + 1 < cap)
			out[o++] = *p;
		p++;
	}
	out[o] = '\0';
	*pp = p;
	return 1;
}

static int ap_exec_first_token(const char *exec, char *out, size_t cap)
{
	const char *p = exec;
	char tok[8][512];
	int n = 0, i;

	while (n < 8 && ap_lex_token(&p, tok[n], sizeof(tok[n])))
		n++;
	out[0] = '\0';
	if (n == 0)
		return -1;
	i = 0;
	if (strcmp(tok[0], "env") == 0)
		i = 1;
	for (; i < n; i++) {
		if (strchr(tok[i], '=') && tok[i][0] != '/')
			continue;
		snprintf(out, cap, "%s", tok[i]);
		return 0;
	}
	return -1;
}

static int ap_desktop_append_sandbox(struct ap_desktop *d, const char *key,
				     const char *val)
{
	char low[128];
	size_t i;
	int hit = 0;

	if (strncmp(key, "X-Flatpak", 9) == 0 ||
	    strncmp(key, "X-SnapInstanceName", 18) == 0 ||
	    strncmp(key, "X-AppImage", 10) == 0 ||
	    strncmp(key, "X-Containment", 13) == 0)
		hit = 1;
	for (i = 0; key[i] && i < sizeof(low) - 1; i++) {
		char c = key[i];

		if (c >= 'A' && c <= 'Z')
			c = (char)(c - 'A' + 'a');
		low[i] = c;
	}
	low[i] = '\0';
	if (strstr(low, "sandbox") != NULL || strstr(low, "bwrap") != NULL ||
	    strstr(low, "flatpak") != NULL || strstr(low, "snap") != NULL)
		hit = 1;
	if (!hit)
		return 0;
	if (d->sandbox[0])
		strncat(d->sandbox, "; ",
			sizeof(d->sandbox) - strlen(d->sandbox) - 1);
	strncat(d->sandbox, key,
		sizeof(d->sandbox) - strlen(d->sandbox) - 1);
	strncat(d->sandbox, "=",
		sizeof(d->sandbox) - strlen(d->sandbox) - 1);
	strncat(d->sandbox, val,
		sizeof(d->sandbox) - strlen(d->sandbox) - 1);
	return 1;
}

int ap_desktop_parse_text(const char *text, const char *target_base,
			  struct ap_desktop *d)
{
	char *buf, *p;
	char exec_first[512] = "", try_first[512] = "";

	if (!text)
		return 0;
	buf = strdup(text);
	if (!buf)
		return 0;
	p = buf;
	while (*p) {
		char *eol = strchr(p, '\n');
		char *line = p;
		char *eq;

		if (eol) {
			*eol = '\0';
			p = eol + 1;
		} else {
			p = line + strlen(line);
		}
		line = ap_trim(line);
		if (!line[0] || line[0] == '#')
			continue;
		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		{
			char *key = ap_trim(line);
			char *val = ap_trim(eq + 1);

			if (strcmp(key, "Name") == 0)
				snprintf(d->name, sizeof(d->name), "%s", val);
			else if (strcmp(key, "Exec") == 0) {
				snprintf(d->exec, sizeof(d->exec), "%s", val);
				ap_exec_first_token(val, exec_first,
						    sizeof(exec_first));
			} else if (strcmp(key, "TryExec") == 0) {
				snprintf(d->tryexec, sizeof(d->tryexec), "%s",
					 val);
				ap_exec_first_token(val, try_first,
						    sizeof(try_first));
			} else if (strcmp(key, "Type") == 0) {
				snprintf(d->type, sizeof(d->type), "%s", val);
			} else if (strcmp(key, "Terminal") == 0) {
				snprintf(d->terminal, sizeof(d->terminal),
					 "%s", val);
			} else {
				ap_desktop_append_sandbox(d, key, val);
			}
		}
	}
	free(buf);
	if ((exec_first[0] && strcmp(ap_base(exec_first), target_base) == 0) ||
	    (try_first[0] && strcmp(ap_base(try_first), target_base) == 0))
		d->found = 1;
	return d->found;
}

static int ap_desktop_scan_dir(const char *dir, const char *target_base,
			       struct ap_desktop *d)
{
	DIR *dp;
	struct dirent *de;

	dp = opendir(dir);
	if (!dp)
		return 0;
	while ((de = readdir(dp)) != NULL) {
		char path[AP_PATH_MAX];
		char *text;
		struct ap_desktop tmp;
		size_t len = strlen(de->d_name);

		if (de->d_name[0] == '.' ||
		    len < 8 ||
		    strcmp(de->d_name + len - 8, ".desktop") != 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		text = ap_read_file(path, 64 * 1024, NULL);
		if (!text)
			continue;
		memset(&tmp, 0, sizeof(tmp));
		if (ap_desktop_parse_text(text, target_base, &tmp)) {
			struct stat st;

			snprintf(tmp.path, sizeof(tmp.path), "%s", path);
			if (stat(path, &st) == 0 &&
			    strstr(dir, "autostart") != NULL)
				tmp.autostart = 1;
			*d = tmp;
			free(text);
			closedir(dp);
			return 1;
		}
		free(text);
	}
	closedir(dp);
	return 0;
}

static int ap_desktop_find(const char *target_path, struct ap_desktop *d)
{
	static const char *const sys_dirs[] = {
		"/usr/share/applications",
		"/usr/local/share/applications",
		"/usr/share/applications/kde4",
		"/var/lib/flatpak/exports/share/applications",
		"/var/lib/snapd/desktop/applications",
		NULL,
	};
	const char *home = getenv("HOME");
	char buf[AP_PATH_MAX];
	int i;

	memset(d, 0, sizeof(*d));
	for (i = 0; sys_dirs[i]; i++) {
		if (ap_desktop_scan_dir(sys_dirs[i], ap_base(target_path), d))
			return 1;
	}
	if (home && home[0] == '/') {
		snprintf(buf, sizeof(buf), "%s/.local/share/applications",
			 home);
		if (ap_desktop_scan_dir(buf, ap_base(target_path), d))
			return 1;
		snprintf(buf, sizeof(buf), "%s/.config/autostart", home);
		if (ap_desktop_scan_dir(buf, ap_base(target_path), d))
			return 1;
	}
	if (ap_desktop_scan_dir("/etc/xdg/autostart", ap_base(target_path),
				d))
		return 1;
	return 0;
}

/* 文件能力：getcap + security.capability xattr 原始解码 */
static const char *const ap_cap_names[] = {
	"chown", "dac_override", "dac_read_search", "fowner", "fsetid",
	"kill", "setgid", "setuid", "setpcap", "linux_immutable",
	"net_bind_service", "net_broadcast", "net_admin", "net_raw",
	"ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot",
	"sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
	"sys_resource", "sys_time", "sys_tty_config", "mknod", "lease",
	"audit_write", "audit_control", "setfcap", "mac_override",
	"mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read",
	"perfmon", "bpf", "checkpoint_restore",
};

static void ap_caps_lookup(const char *path, char *getcap_out, size_t gcap,
			   char *xattr_hex, size_t hcap, char *decoded,
			   size_t dcap, char *state, size_t scap, char *warn,
			   size_t wcap)
{
	unsigned char buf[64];
	ssize_t n;
	char *argv[3];
	char *out = NULL;
	int rc = 0, timed = 0;

	snprintf(state, scap, "none");
	getcap_out[0] = '\0';
	xattr_hex[0] = '\0';
	decoded[0] = '\0';
	n = getxattr(path, "security.capability", buf, sizeof(buf));
	if (n < 0) {
		if (errno == ENODATA) {
			snprintf(state, scap, "none");
		} else if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			snprintf(state, scap, "unsupported");
			snprintf(warn, wcap,
				 "文件系统不支持 security.capability xattr");
		} else if (errno == EACCES || errno == EPERM) {
			snprintf(state, scap, "unknown");
			snprintf(warn, wcap,
				 "读取 security.capability 权限不足（能力未知）");
		} else {
			snprintf(state, scap, "error");
			snprintf(warn, wcap, "getxattr 失败：%s",
				 strerror(errno));
		}
	} else if (n >= 4) {
		int i;
		unsigned int magic = (unsigned int)buf[0] |
				     ((unsigned int)buf[1] << 8) |
				     ((unsigned int)buf[2] << 16) |
				     ((unsigned int)buf[3] << 24);
		unsigned int perm = 0, inh = 0;
		size_t off = 4;

		while (off + 8 <= (size_t)n) {
			perm |= (unsigned int)buf[off] |
				((unsigned int)buf[off + 1] << 8) |
				((unsigned int)buf[off + 2] << 16) |
				((unsigned int)buf[off + 3] << 24);
			inh |= (unsigned int)buf[off + 4] |
			       ((unsigned int)buf[off + 5] << 8) |
			       ((unsigned int)buf[off + 6] << 16) |
			       ((unsigned int)buf[off + 7] << 24);
			off += 8;
		}
		(void)magic;
		for (i = 0; i < (int)n && (size_t)i * 2 + 2 < hcap; i++)
			snprintf(xattr_hex + i * 2, hcap - i * 2, "%02x",
				 buf[i]);
		for (i = 0; i < 41; i++) {
			if (!(perm & (1u << i)) && !(inh & (1u << i)))
				continue;
			if (decoded[0])
				strncat(decoded, ",",
					dcap - strlen(decoded) - 1);
			strncat(decoded, "cap_",
				dcap - strlen(decoded) - 1);
			strncat(decoded, ap_cap_names[i],
				dcap - strlen(decoded) - 1);
			strncat(decoded, "=",
				dcap - strlen(decoded) - 1);
			if (perm & (1u << i))
				strncat(decoded, "p",
					dcap - strlen(decoded) - 1);
			if (inh & (1u << i))
				strncat(decoded, "i",
					dcap - strlen(decoded) - 1);
			if (perm & (1u << i))
				strncat(decoded, "e",
					dcap - strlen(decoded) - 1);
		}
		snprintf(state, scap, "present");
	}
	argv[0] = (char *)"getcap";
	argv[1] = (char *)path;
	argv[2] = NULL;
	if (ap_exec_capture(argv, 8, &out, &rc, &timed) == 0) {
		char *t = ap_trim(out ? out : (char *)"");

		if (t[0])
			snprintf(getcap_out, gcap, "%s", t);
		else if (n >= 4)
			snprintf(getcap_out, gcap, "(getcap 无输出，xattr 有值)");
	} else {
		snprintf(warn, wcap, "getcap 不可用（仅用 xattr 原始值）");
	}
	free(out);
}
/* ======================================================================
 * 2) 静态画像（续）：采集 + 文本/JSON 渲染
 * ====================================================================== */

struct ap_static {
	char input[AP_PATH_MAX];
	char path[AP_PATH_MAX];
	int is_symlink;
	char kind[16];		/* elf | script | dir | other */
	char shebang[256];
	long long size;
	unsigned mode;
	unsigned uid, gid;
	int setuid, setgid, sticky;
	struct ap_elf elf;
	struct ap_dynsec dyn;
	struct ap_symcount sym;
	int has_dyn, has_sym;
	char caps_getcap[512];
	char caps_xattr[256];
	char caps_decoded[768];
	char caps_state[32];
	struct ap_desktop desk;
	int pkg_found;
	int pkg_checked;
	char pkg[256];
	char pkg_version[128];
	char warn[12][256];
	int warn_n;
};

static void ap_warn(struct ap_static *st, const char *fmt, ...)
{
	va_list ap;

	if (st->warn_n >= 12)
		return;
	va_start(ap, fmt);
	vsnprintf(st->warn[st->warn_n], sizeof(st->warn[0]), fmt, ap);
	va_end(ap);
	st->warn_n++;
}

static int ap_resolve_path(const char *in, char *out, size_t cap)
{
	char rp[PATH_MAX];

	if (!in || !in[0] || strlen(in) >= AP_PATH_MAX)
		return -1;
	if (strchr(in, '/')) {
		if (!realpath(in, rp))
			return -1;
		snprintf(out, cap, "%s", rp);
		return 0;
	}
	{
		const char *path = getenv("PATH");
		char *dup, *save = NULL, *dir;

		if (!path || !path[0])
			path = "/usr/local/bin:/usr/bin:/bin:"
			       "/usr/local/sbin:/usr/sbin:/sbin";
		dup = strdup(path);
		if (!dup)
			return -1;
		for (dir = strtok_r(dup, ":", &save); dir;
		     dir = strtok_r(NULL, ":", &save)) {
			char cand[PATH_MAX];

			snprintf(cand, sizeof(cand), "%s/%s",
				 dir[0] ? dir : ".", in);
			if (access(cand, X_OK) == 0 && realpath(cand, rp)) {
				snprintf(out, cap, "%s", rp);
				free(dup);
				return 0;
			}
		}
		free(dup);
	}
	return -1;
}

static void ap_mode_str(unsigned mode, char *out, size_t cap)
{
	snprintf(out, cap, "%04o", mode & 07777);
}

static int ap_tool_exists(const char *name)
{
	if (strchr(name, '/'))
		return access(name, X_OK) == 0;
	{
		const char *path = getenv("PATH");
		char *dup, *save = NULL, *dir;
		int found = 0;

		if (!path || !path[0])
			path = "/usr/local/bin:/usr/bin:/bin:"
			       "/usr/local/sbin:/usr/sbin:/sbin";
		dup = strdup(path);
		if (!dup)
			return 0;
		for (dir = strtok_r(dup, ":", &save); dir;
		     dir = strtok_r(NULL, ":", &save)) {
			char cand[PATH_MAX];

			snprintf(cand, sizeof(cand), "%s/%s",
				 dir[0] ? dir : ".", name);
			if (access(cand, X_OK) == 0) {
				found = 1;
				break;
			}
		}
		free(dup);
		return found;
	}
}

static void ap_run_tool(struct ap_static *st, char *const argv[],
			const char *what, char **out)
{
	int rc = 0, timed = 0;

	if (!ap_tool_exists(argv[0])) {
		ap_warn(st, "%s 不可用：相关字段降级", what);
		return;
	}
	if (ap_exec_capture(argv, 10, out, &rc, &timed) != 0) {
		ap_warn(st, "%s 启动失败：相关字段降级", what);
		return;
	}
	if (timed)
		ap_warn(st, "%s 超时（10s），输出可能不完整", what);
	if (rc != 0 && (!*out || !(*out)[0]))
		ap_warn(st, "%s 退出码 %d（无输出）", what, rc);
}

static int ap_static_collect(const char *input, struct ap_static *st,
			     char *err, size_t errcap)
{
	struct stat sbuf, lbuf;
	char *out = NULL;

	memset(st, 0, sizeof(*st));
	snprintf(st->input, sizeof(st->input), "%s", input ? input : "");
	if (!input || !input[0]) {
		snprintf(err, errcap, "缺少 path");
		return -1;
	}
	if (ap_resolve_path(input, st->path, sizeof(st->path)) != 0) {
		if (strchr(input, '/'))
			snprintf(err, errcap,
				 "路径不存在或不可访问：%s（%s）", input,
				 strerror(errno));
		else
			snprintf(err, errcap,
				 "在 PATH 中找不到可执行文件：%s", input);
		return -1;
	}
	if (stat(st->path, &sbuf) != 0) {
		if (errno == ENOENT)
			snprintf(err, errcap, "文件不存在：%.400s", st->path);
		else if (errno == EACCES)
			snprintf(err, errcap, "权限不足：%.400s", st->path);
		else
			snprintf(err, errcap, "stat 失败：%.400s（%s）",
				 st->path, strerror(errno));
		return -1;
	}
	if (lstat(strchr(st->input, '/') ? st->input : st->path,
		  &lbuf) == 0 && S_ISLNK(lbuf.st_mode))
		st->is_symlink = 1;
	st->size = (long long)sbuf.st_size;
	st->mode = sbuf.st_mode;
	st->uid = sbuf.st_uid;
	st->gid = sbuf.st_gid;
	st->setuid = (sbuf.st_mode & S_ISUID) ? 1 : 0;
	st->setgid = (sbuf.st_mode & S_ISGID) ? 1 : 0;
	st->sticky = (sbuf.st_mode & S_ISVTX) ? 1 : 0;

	if (S_ISDIR(sbuf.st_mode)) {
		snprintf(st->kind, sizeof(st->kind), "dir");
	} else {
		unsigned char head[256];
		int fd = open(st->path, O_RDONLY | O_CLOEXEC);
		ssize_t n = fd >= 0 ? read(fd, head, sizeof(head)) : -1;

		if (fd >= 0)
			close(fd);
		if (n >= 4 && head[0] == 0x7f && head[1] == 'E' &&
		    head[2] == 'L' && head[3] == 'F') {
			snprintf(st->kind, sizeof(st->kind), "elf");
			if (ap_elf_parse(st->path, &st->elf, err, errcap) != 0) {
				ap_warn(st, "ELF 解析失败：%s", err);
				st->elf.ok = 0;
			}
		} else if (n >= 2 && head[0] == '#' && head[1] == '!') {
			size_t i, want;

			snprintf(st->kind, sizeof(st->kind), "script");
			want = (size_t)n < sizeof(st->shebang) - 1 ?
			       (size_t)n : sizeof(st->shebang) - 1;
			for (i = 2; i < want && head[i] != '\n'; i++)
				st->shebang[i - 2] = (char)head[i];
			st->shebang[i - 2] = '\0';
			{
				char *t = ap_trim(st->shebang);

				if (t != st->shebang)
					memmove(st->shebang, t,
						strlen(t) + 1);
			}
		} else {
			snprintf(st->kind, sizeof(st->kind), "other");
		}
	}

	if (st->elf.ok) {
		char *argv[5];

		argv[0] = (char *)"readelf";
		argv[1] = (char *)"-W";
		argv[2] = (char *)"-d";
		argv[3] = st->path;
		argv[4] = NULL;
		ap_run_tool(st, argv, "readelf -d", &out);
		if (out) {
			char derr[256] = "";

			if (ap_dyn_parse(out, &st->dyn, derr,
					 sizeof(derr)) == 0) {
				st->has_dyn = 1;
			} else {
				ap_warn(st, "动态段：%s", derr);
			}
		}
		free(out);
		out = NULL;

		argv[1] = (char *)"-W";
		argv[2] = (char *)"--dyn-syms";
		ap_run_tool(st, argv, "readelf --dyn-syms", &out);
		if (out) {
			char serr[256] = "";

			if (ap_dynsym_parse(out, &st->sym, serr,
					    sizeof(serr)) == 0) {
				st->has_sym = 1;
			} else {
				ap_warn(st, "动态符号：%s", serr);
			}
		}
		free(out);
		out = NULL;
	}

	{
		char cw[256] = "";

		ap_caps_lookup(st->path, st->caps_getcap,
			       sizeof(st->caps_getcap), st->caps_xattr,
			       sizeof(st->caps_xattr), st->caps_decoded,
			       sizeof(st->caps_decoded), st->caps_state,
			       sizeof(st->caps_state), cw, sizeof(cw));
		if (cw[0])
			ap_warn(st, "%s", cw);
	}

	ap_desktop_find(st->path, &st->desk);

	{
		char *argv[4] = { NULL, NULL, NULL, NULL };
		char perr[512] = "";

		st->pkg_checked = 1;
		argv[0] = (char *)"dpkg";
		argv[1] = (char *)"-S";
		argv[2] = st->path;
		argv[3] = NULL;
		ap_run_tool(st, argv, "dpkg -S", &out);
		if (out) {
			char pkg[256] = "";
			int prc = ap_dpkg_s_parse(out, pkg, sizeof(pkg), perr,
						  sizeof(perr));

			if (prc == 0) {
				st->pkg_found = 1;
				snprintf(st->pkg, sizeof(st->pkg), "%s", pkg);
				free(out);
				out = NULL;
				{
					char *qargv[5] =
					    { NULL, NULL, NULL, NULL, NULL };

					qargv[0] = (char *)"dpkg-query";
					qargv[1] = (char *)"-W";
					qargv[2] =
					    (char *)"-f=${Version}";
					qargv[3] = st->pkg;
					qargv[4] = NULL;
					ap_run_tool(st, qargv,
						    "dpkg-query", &out);
					if (out && out[0])
						snprintf(st->pkg_version,
							 sizeof(st->pkg_version),
							 "%s", ap_trim(out));
					free(out);
					out = NULL;
				}
				if (!st->pkg_version[0])
					snprintf(st->pkg_version,
						 sizeof(st->pkg_version),
						 "未知");
			} else if (prc > 0 &&
				   (strncmp(st->path, "/usr/bin/", 9) == 0 ||
				    strncmp(st->path, "/usr/sbin/", 10) == 0)) {
				const char *pre =
				    strncmp(st->path, "/usr/bin/", 9) == 0 ?
				    "/bin/" : "/sbin/";
				char alt[AP_PATH_MAX];
				char *aargv[4] =
				    { NULL, NULL, NULL, NULL };

				snprintf(alt, sizeof(alt), "%s%.200s", pre,
					 ap_base(st->path));
				aargv[0] = (char *)"dpkg";
				aargv[1] = (char *)"-S";
				aargv[2] = alt;
				aargv[3] = NULL;
				free(out);
				out = NULL;
				ap_run_tool(st, aargv, "dpkg -S (usrmerge)",
					    &out);
				prc = -1;
				if (out) {
					prc = ap_dpkg_s_parse(out, pkg,
							      sizeof(pkg),
							      perr,
							      sizeof(perr));
				}
				if (prc == 0) {
					st->pkg_found = 1;
					snprintf(st->pkg, sizeof(st->pkg),
						 "%s", pkg);
					ap_warn(st, "usrmerge：包归属按 %.200s "
						"命中（/usr 是 /bin 的符号链接）",
						alt);
				} else {
					st->pkg_found = 0;
				}
			} else if (prc > 0) {
				st->pkg_found = 0;
			} else {
				ap_warn(st, "包来源：%s", perr);
			}
		}
		free(out);
		out = NULL;
	}

	if (st->dyn.runpath_n > 0)
		ap_warn(st, "含 RUNPATH（%s）：搜索路径可被用于库劫持",
			st->dyn.runpath[0]);
	if (st->dyn.rpath_n > 0)
		ap_warn(st, "含 RPATH（%s）：搜索路径可被用于库劫持",
			st->dyn.rpath[0]);
	if (st->dyn.textrel)
		ap_warn(st, "含 TEXTREL：存在可写代码段（W^X 失效）");
	if (st->setuid || st->setgid)
		ap_warn(st, "setuid/setgid 位已设置：提权面，运行需单独评审");
	if (st->caps_state[0] && strcmp(st->caps_state, "present") == 0)
		ap_warn(st, "文件能力已设置：%s（%s）", st->caps_decoded,
			st->caps_getcap[0] ? st->caps_getcap : "getcap 无输出");
	if (strcmp(st->kind, "elf") == 0 && st->elf.ok &&
	    !st->elf.has_gnu_stack)
		ap_warn(st, "缺 PT_GNU_STACK：NX 状态未知（内核按可执行栈处理）");
	if (strcmp(st->kind, "elf") == 0 && st->elf.ok &&
	    !st->has_dyn)
		ap_warn(st, "无动态段：静态链接或 readelf 数据缺失");
	return 0;
}

static void ap_elf_summary(const struct ap_static *st, char *out, size_t cap)
{
	const struct ap_elf *e = &st->elf;

	if (!e->ok) {
		snprintf(out, cap, "解析失败");
		return;
	}
	snprintf(out, cap,
		 "%s 位%s端 类型=%s 架构=%s 入口=0x%llx PIE=%s NX=%s RELRO=%s",
		 e->bits == 64 ? "64" : "32", e->be ? "大" : "小",
		 ap_elf_type_str(e->type), ap_elf_machine_str(e->machine),
		 e->entry,
		 (e->type == 3 && e->has_interp) ? "是" : "否",
		 e->has_gnu_stack ? (e->gnu_stack_exec ? "关闭（可执行栈）" :
				     "开启") : "未知（无 GNU_STACK）",
		 e->has_relro ? (st->dyn.bind_now ? "完全" : "部分") : "无");
}

static int ap_declared_lines(const struct ap_static *st,
			     char lines[][256], int max)
{
	int n = 0, i;

#define AP_DECL(...) do { \
	if (n < max) \
		snprintf(lines[n++], 256, __VA_ARGS__); \
} while (0)

	if (strcmp(st->kind, "elf") != 0) {
		if (strcmp(st->kind, "script") == 0)
			AP_DECL("解释器 %.200s（脚本，无 ELF 依赖声明）",
				st->shebang[0] ? st->shebang : "?");
		else
			AP_DECL("非 ELF（%s），无 ELF 依赖声明", st->kind);
	} else if (!st->elf.ok) {
		AP_DECL("ELF 头解析失败（声明缺失）");
	} else {
		AP_DECL("ELF %s %s PIE=%s NX=%s RELRO=%s",
			ap_elf_type_str(st->elf.type),
			ap_elf_machine_str(st->elf.machine),
			(st->elf.type == 3 && st->elf.has_interp) ? "是" :
			"否",
			st->elf.has_gnu_stack ?
			(st->elf.gnu_stack_exec ? "关闭" : "开启") : "未知",
			st->elf.has_relro ? (st->dyn.bind_now ? "完全" :
					     "部分") : "无");
		if (st->elf.has_interp)
			AP_DECL("解释器 %.200s", st->elf.interp);
		if (st->has_dyn && st->dyn.needed_n == 0)
			AP_DECL("无 NEEDED 依赖（静态链接）");
		for (i = 0; i < st->dyn.needed_n; i++)
			AP_DECL("依赖库 %s", st->dyn.needed[i]);
		if (st->dyn.soname[0])
			AP_DECL("SONAME %s", st->dyn.soname);
		for (i = 0; i < st->dyn.runpath_n; i++)
			AP_DECL("RUNPATH %.200s（非系统目录可致库劫持）",
				st->dyn.runpath[i]);
		for (i = 0; i < st->dyn.rpath_n; i++)
			AP_DECL("RPATH %.200s（非系统目录可致库劫持）",
				st->dyn.rpath[i]);
		if (st->dyn.bind_now)
			AP_DECL("绑定 BIND_NOW（立即符号绑定）");
		if (st->dyn.textrel)
			AP_DECL("TEXTREL 存在（可写代码段）");
	}
	if (st->caps_decoded[0])
		AP_DECL("文件能力 %.200s", st->caps_decoded);
	else if (st->caps_getcap[0])
		AP_DECL("文件能力 %.200s", st->caps_getcap);
	if (st->setuid)
		AP_DECL("setuid 位（owner uid=%u）", st->uid);
	if (st->setgid)
		AP_DECL("setgid 位（group gid=%u）", st->gid);
	if (st->desk.found)
		AP_DECL("桌面入口 %.140s Exec=%.45s%s", st->desk.path,
			st->desk.exec, st->desk.autostart ? "（autostart）" : "");
	if (st->pkg_found)
		AP_DECL("包来源 %.120s %.80s", st->pkg, st->pkg_version);
#undef AP_DECL
	return n;
}

static void ap_static_render_text(const struct ap_static *st, struct apb *b)
{
	char mode[16];
	char elfsum[512];
	char lines[64][256];
	int n, i;

	ap_mode_str(st->mode, mode, sizeof(mode));
	apb_printf(b, "== 静态画像: %s ==\n", st->path);
	apb_printf(b, "[文件] 类型=%s 大小=%lld 权限=%s uid=%u gid=%u "
		   "setuid=%s setgid=%s\n", st->kind, st->size, mode,
		   st->uid, st->gid, st->setuid ? "是" : "否",
		   st->setgid ? "是" : "否");
	if (st->is_symlink)
		apb_printf(b, "[符号链接] 是（输入 %s 解析为 %s）\n",
			   st->input, st->path);
	if (strcmp(st->kind, "elf") == 0) {
		ap_elf_summary(st, elfsum, sizeof(elfsum));
		apb_printf(b, "[ELF] %s\n", elfsum);
		if (st->elf.ok && st->elf.has_interp)
			apb_printf(b, "[解释器] %s\n", st->elf.interp);
		apb_printf(b, "[依赖] %d 个", st->dyn.needed_n);
		for (i = 0; i < st->dyn.needed_n; i++)
			apb_printf(b, "%s%s", i ? ", " : ": ",
				   st->dyn.needed[i]);
		apb_printf(b, "\n");
		if (st->dyn.soname[0])
			apb_printf(b, "[SONAME] %s\n", st->dyn.soname);
		for (i = 0; i < st->dyn.runpath_n; i++)
			apb_printf(b, "[RUNPATH] %s\n", st->dyn.runpath[i]);
		for (i = 0; i < st->dyn.rpath_n; i++)
			apb_printf(b, "[RPATH] %s\n", st->dyn.rpath[i]);
		if (st->has_sym)
			apb_printf(b, "[符号] 动态符号 %d：FUNC %d / OBJECT %d"
				   " / IFUNC %d / TLS %d / NOTYPE %d / 未定义 %d\n",
				   st->sym.total, st->sym.func,
				   st->sym.object, st->sym.ifunc, st->sym.tls,
				   st->sym.notype, st->sym.undef);
	} else if (strcmp(st->kind, "script") == 0) {
		apb_printf(b, "[脚本] shebang=%s\n", st->shebang);
	} else if (strcmp(st->kind, "dir") == 0) {
		apb_printf(b, "[目录] 不是可执行文件\n");
	} else {
		apb_printf(b, "[其他] 非 ELF、无 shebang\n");
	}
	apb_printf(b, "[能力] 状态=%s 解码=%s getcap=%s xattr=%s\n",
		   st->caps_state,
		   st->caps_decoded[0] ? st->caps_decoded : "（无）",
		   st->caps_getcap[0] ? st->caps_getcap : "（空）",
		   st->caps_xattr[0] ? st->caps_xattr : "（空）");
	if (st->desk.found)
		apb_printf(b, "[桌面] %s Name=%s Exec=%s TryExec=%s "
			   "Type=%s Terminal=%s autostart=%s 沙箱=%s\n",
			   st->desk.path,
			   st->desk.name[0] ? st->desk.name : "?",
			   st->desk.exec[0] ? st->desk.exec : "?",
			   st->desk.tryexec[0] ? st->desk.tryexec : "（无）",
			   st->desk.type[0] ? st->desk.type : "?",
			   st->desk.terminal[0] ? st->desk.terminal : "?",
			   st->desk.autostart ? "是" : "否",
			   st->desk.sandbox[0] ? st->desk.sandbox : "（无）");
	else
		apb_printf(b, "[桌面] 未找到匹配的 .desktop\n");
	if (st->pkg_found)
		apb_printf(b, "[包] %s %s（dpkg -S 命中）\n", st->pkg,
			   st->pkg_version);
	else
		apb_printf(b, "[包] 未命中 dpkg 包（无包归属）\n");
	if (st->warn_n) {
		for (i = 0; i < st->warn_n; i++)
			apb_printf(b, "[警告] %s\n", st->warn[i]);
	}
	n = ap_declared_lines(st, lines, 64);
	apb_printf(b, "[要的] 静态声明 %d 项：\n", n);
	for (i = 0; i < n; i++)
		apb_printf(b, "  - %s\n", lines[i]);
}

static void ap_static_render_json(const struct ap_static *st, struct apb *b)
{
	char mode[16];
	char lines[64][256];
	int n, i;

	ap_mode_str(st->mode, mode, sizeof(mode));
	apb_printf(b, "{\"tool\":\"app_profile_static\",\"path\":");
	apb_json_str(b, st->path);
	apb_printf(b, ",\"input\":");
	apb_json_str(b, st->input);
	apb_printf(b, ",\"kind\":");
	apb_json_str(b, st->kind);
	apb_printf(b, ",\"symlink\":%s", st->is_symlink ? "true" : "false");
	apb_printf(b, ",\"stat\":{\"size\":%lld,\"mode\":\"%s\","
		   "\"uid\":%u,\"gid\":%u,\"setuid\":%s,\"setgid\":%s}",
		   st->size, mode, st->uid, st->gid,
		   st->setuid ? "true" : "false",
		   st->setgid ? "true" : "false");
	if (strcmp(st->kind, "elf") == 0) {
		apb_printf(b, ",\"elf\":{\"parsed\":%s,\"class\":%d,"
			   "\"endian\":\"%s\",\"type\":\"%s\","
			   "\"machine\":\"%s\",\"entry\":\"0x%llx\","
			   "\"pie\":%s,\"nx\":%s,\"nx_known\":%s,"
			   "\"relro\":\"%s\",\"bind_now\":%s,"
			   "\"interp\":",
			   st->elf.ok ? "true" : "false",
			   st->elf.bits, st->elf.be ? "BE" : "LE",
			   ap_elf_type_str(st->elf.type),
			   ap_elf_machine_str(st->elf.machine),
			   st->elf.entry,
			   (st->elf.ok && st->elf.type == 3 &&
			    st->elf.has_interp) ? "true" : "false",
			   !st->elf.has_gnu_stack ? "null" :
			   (st->elf.gnu_stack_exec ? "false" : "true"),
			   st->elf.has_gnu_stack ? "true" : "false",
			   st->elf.has_relro ?
			   (st->dyn.bind_now ? "full" : "partial") : "none",
			   st->dyn.bind_now ? "true" : "false");
		if (st->elf.has_interp)
			apb_json_str(b, st->elf.interp);
		else
			apb_printf(b, "null");
		apb_printf(b, "}");
	}
	apb_printf(b, ",\"deps\":{\"parsed\":%s,\"needed\":[",
		   st->has_dyn ? "true" : "false");
	for (i = 0; i < st->dyn.needed_n; i++) {
		if (i)
			apb_printf(b, ",");
		apb_json_str(b, st->dyn.needed[i]);
	}
	apb_printf(b, "],\"soname\":");
	apb_json_str(b, st->dyn.soname);
	apb_printf(b, ",\"rpath\":[");
	for (i = 0; i < st->dyn.rpath_n; i++) {
		if (i)
			apb_printf(b, ",");
		apb_json_str(b, st->dyn.rpath[i]);
	}
	apb_printf(b, "],\"runpath\":[");
	for (i = 0; i < st->dyn.runpath_n; i++) {
		if (i)
			apb_printf(b, ",");
		apb_json_str(b, st->dyn.runpath[i]);
	}
	apb_printf(b, "],\"bind_now\":%s,\"textrel\":%s}",
		   st->dyn.bind_now ? "true" : "false",
		   st->dyn.textrel ? "true" : "false");
	apb_printf(b, ",\"symbols\":{\"parsed\":%s,\"total\":%d,"
		   "\"func\":%d,\"object\":%d,\"ifunc\":%d,\"tls\":%d,"
		   "\"notype\":%d,\"undefined\":%d}",
		   st->has_sym ? "true" : "false", st->sym.total,
		   st->sym.func, st->sym.object, st->sym.ifunc,
		   st->sym.tls, st->sym.notype, st->sym.undef);
	apb_printf(b, ",\"caps\":{\"state\":");
	apb_json_str(b, st->caps_state);
	apb_printf(b, ",\"getcap\":");
	apb_json_str(b, st->caps_getcap);
	apb_printf(b, ",\"xattr\":");
	apb_json_str(b, st->caps_xattr);
	apb_printf(b, ",\"decoded\":");
	apb_json_str(b, st->caps_decoded);
	apb_printf(b, "},\"desktop\":{\"found\":%s",
		   st->desk.found ? "true" : "false");
	if (st->desk.found) {
		apb_printf(b, ",\"path\":");
		apb_json_str(b, st->desk.path);
		apb_printf(b, ",\"name\":");
		apb_json_str(b, st->desk.name);
		apb_printf(b, ",\"exec\":");
		apb_json_str(b, st->desk.exec);
		apb_printf(b, ",\"tryexec\":");
		apb_json_str(b, st->desk.tryexec);
		apb_printf(b, ",\"type\":");
		apb_json_str(b, st->desk.type);
		apb_printf(b, ",\"autostart\":%s",
			   st->desk.autostart ? "true" : "false");
		apb_printf(b, ",\"sandbox\":");
		apb_json_str(b, st->desk.sandbox);
	}
	apb_printf(b, "},\"pkg\":{\"checked\":%s,\"found\":%s,"
		   "\"package\":", st->pkg_checked ? "true" : "false",
		   st->pkg_found ? "true" : "false");
	apb_json_str(b, st->pkg);
	apb_printf(b, ",\"version\":");
	apb_json_str(b, st->pkg_version);
	apb_printf(b, "},\"warnings\":[");
	for (i = 0; i < st->warn_n; i++) {
		if (i)
			apb_printf(b, ",");
		apb_json_str(b, st->warn[i]);
	}
	n = ap_declared_lines(st, lines, 64);
	apb_printf(b, "],\"declared\":[");
	for (i = 0; i < n; i++) {
		if (i)
			apb_printf(b, ",");
		apb_json_str(b, lines[i]);
	}
	apb_printf(b, "]}\n");
}
/* ======================================================================
 * 3) 动态画像（workspace 沙盒 + strace 优先 / /proc 采样退化）
 * ====================================================================== */

static const char *const ap_bin_allow[] = {
	"ls", "cat", "head", "tail", "wc", "sort", "uniq", "cut", "tr",
	"base64", "sha256sum", "md5sum", "stat", "file", "readelf",
	"objdump", "nm", "strings", "grep", "tar", "curl", "du", "df",
	"uname", "id", "whoami", "pwd", "date", "true", "echo", "printf",
	"nproc", "arch", NULL,
};

static const char *const ap_bin_dirs[] = {
	"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin",
	"/usr/local/sbin", NULL,
};

static int ap_in_list(const char *s, const char *const *list)
{
	int i;

	for (i = 0; list[i]; i++)
		if (strcmp(s, list[i]) == 0)
			return 1;
	return 0;
}

int ap_target_allowed(const char *realpath, char *err, size_t errcap)
{
	char dir[AP_PATH_MAX];
	const char *slash, *base;
	int i, ok = 0;

	if (!realpath || realpath[0] != '/') {
		snprintf(err, errcap, "目标必须是绝对路径（解析后）");
		return -1;
	}
	if (strstr(realpath, "..") != NULL) {
		snprintf(err, errcap, "目标路径含 ..（拒绝）");
		return -1;
	}
	slash = strrchr(realpath, '/');
	if (!slash) {
		snprintf(err, errcap, "无法取目录名");
		return -1;
	}
	base = slash + 1;
	{
		size_t n = (size_t)(slash - realpath);

		if (n == 0)
			n = 1;
		if (n >= sizeof(dir))
			n = sizeof(dir) - 1;
		memcpy(dir, realpath, n);
		dir[n] = '\0';
	}
	if (!ap_in_list(base, ap_bin_allow)) {
		snprintf(err, errcap,
			 "程序 %s 不在动态画像白名单（只允许无害只读命令，"
			 "如 ls/cat/tar -t/curl --version）", base);
		return -1;
	}
	for (i = 0; ap_bin_dirs[i]; i++)
		if (strcmp(dir, ap_bin_dirs[i]) == 0) {
			ok = 1;
			break;
		}
	if (!ok) {
		snprintf(err, errcap,
			 "程序目录 %s 不是系统 bin 目录（%s/...）：拒绝", dir,
			 "/usr/bin");
		return -1;
	}
	if (access(realpath, X_OK) != 0) {
		snprintf(err, errcap, "目标不可执行：%s（%s）", realpath,
			 strerror(errno));
		return -1;
	}
	return 0;
}

static int ap_is_dangerous_tar_flag(const char *arg)
{
	static const char *const bad_long[] = {
		"--extract", "--get", "--create", "--append", "--update",
		"--delete", "--concatenate", "--catenate", "--diff",
		"--compare", "--to-command", "--checkpoint-action",
		"--use-compress-program", "--transform", "--xform",
		"--remove-files", "--one-top-level", NULL,
	};
	int i;

	for (i = 0; bad_long[i]; i++)
		if (strncmp(arg, bad_long[i], strlen(bad_long[i])) == 0)
			return 1;
	return 0;
}

int ap_arg_allowed(const char *base, char *const argv[], int argc, char *err,
		   size_t errcap)
{
	int i;

	if (argc > 16) {
		snprintf(err, errcap, "参数超过 16 项上限");
		return -1;
	}
	for (i = 0; i < argc; i++) {
		if (!argv[i]) {
			snprintf(err, errcap, "参数 %d 为空指针", i);
			return -1;
		}
		if (strlen(argv[i]) > 255) {
			snprintf(err, errcap, "参数 %d 超长（>255 字节）", i);
			return -1;
		}
		if (ap_has_ctl(argv[i])) {
			snprintf(err, errcap, "参数 %d 含控制字符", i);
			return -1;
		}
	}
	if (strcmp(base, "curl") == 0) {
		static const char *const ok[] = {
			"--version", "-V", "--help", "-h", "--manual",
			"--usage", NULL,
		};

		for (i = 0; i < argc; i++) {
			if (!ap_in_list(argv[i], ok)) {
				snprintf(err, errcap,
					 "curl 只允许 --version/-V/--help/-h/"
					 "--manual（禁止 URL、-o/-O/-d/-F/-T/"
					 "-K 等联网或写文件参数），拒绝：%s",
					 argv[i]);
				return -1;
			}
		}
		return 0;
	}
	if (strcmp(base, "tar") == 0) {
		int list_mode = 0, help = 0;

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (a[0] == '-' && a[1] == '-') {
				if (strcmp(a, "--list") == 0) {
					list_mode = 1;
					continue;
				}
				if (strncmp(a, "--help", 6) == 0 ||
				    strncmp(a, "--version", 9) == 0 ||
				    strncmp(a, "--usage", 7) == 0) {
					help = 1;
					continue;
				}
				if (ap_is_dangerous_tar_flag(a)) {
					snprintf(err, errcap,
						 "tar 拒绝解包/创建/删除类参数：%s",
						 a);
					return -1;
				}
				continue;
			}
			if (a[0] == '-' && a[1]) {
				const char *c;

				for (c = a + 1; *c; c++) {
					if (strchr("xcruAd", *c)) {
						snprintf(err, errcap,
							 "tar 拒绝解包/创建/删除类"
							 "短参数：-%c（仅允许"
							 "列表 -t/-tf）", *c);
						return -1;
					}
					if (*c == 't')
						list_mode = 1;
				}
			}
		}
		if (!list_mode && !help) {
			snprintf(err, errcap,
				 "tar 只允许列表模式（-t/--list）或 --help/"
				 "--version");
			return -1;
		}
		return 0;
	}
	if (strcmp(base, "sort") == 0) {
		for (i = 0; i < argc; i++) {
			if (strcmp(argv[i], "-o") == 0 ||
			    strncmp(argv[i], "-o", 2) == 0 ||
			    strncmp(argv[i], "--output", 8) == 0 ||
			    strncmp(argv[i], "--compress-program", 18) == 0) {
				snprintf(err, errcap,
					 "sort 拒绝写文件/外部程序参数：%s",
					 argv[i]);
				return -1;
			}
		}
		return 0;
	}
	if (strcmp(base, "date") == 0) {
		for (i = 0; i < argc; i++) {
			if (strcmp(argv[i], "-s") == 0 ||
			    strncmp(argv[i], "-s", 2) == 0 ||
			    strncmp(argv[i], "--set", 5) == 0) {
				snprintf(err, errcap,
					 "date 拒绝改系统时间参数：%s",
					 argv[i]);
				return -1;
			}
		}
		return 0;
	}
	return 0;
}

/*
 * 沙盒内追踪脚本（POSIX sh）。
 * 参数：$1=目标 $2=sample_ms $3=auto|strace|proc $4=timeout_s
 *       $5.. = 目标参数（不拼接进脚本文本，杜绝注入）
 *
 * 输出 TSV（C 侧解析）：
 *   B<TAB>start<TAB>mode   G<TAB>target       U<TAB>实际模式
 *   L<TAB>strace 原文行    F<TAB>path<TAB>flags（/proc fd）
 *   M<TAB>maps 路径        P<TAB>pid<TAB>exe  N<TAB>tbl<TAB>local<TAB>remote<TAB>state<TAB>inode
 *   O<TAB>目标输出行       W<TAB>警告         R<TAB>exit<TAB>timed_out
 */
static const char *const AP_TRACER_SCRIPT =
"t=$1; ms=$2; mode=$3; tmo=$4\n"
"shift 4\n"
"d=/tmp/.aikprof.$$\n"
"mkdir -p \"$d\" 2>/dev/null || d=/.aikprof.$$\n"
"mkdir -p \"$d\" 2>/dev/null || { printf 'W\\t无法创建临时目录\\n'; printf 'R\\t97\\t0\\n'; exit 97; }\n"
"seen=$d/seen; : > \"$seen\"\n"
"emit() { grep -Fqx -- \"$1\" \"$seen\" 2>/dev/null && return 0; printf '%s\\n' \"$1\" >> \"$seen\"; printf '%s\\n' \"$1\"; }\n"
"start=$(date +%s)\n"
"use=proc\n"
"if [ \"$mode\" != proc ] && command -v strace >/dev/null 2>&1 && command -v setsid >/dev/null 2>&1; then use=strace; fi\n"
"printf 'B\\t%d\\t%s\\n' \"$start\" \"$use\"\n"
"printf 'G\\t%s\\n' \"$t\"\n"
"rc=0; to=0; end=$((start + tmo))\n"
"if [ \"$use\" = strace ]; then\n"
"  export LC_ALL=C LANG=C\n"
"  setsid strace -f -qq -s 256 -e trace=execve,execveat,open,openat,openat2,connect,bind,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,chmod,fchmodat,chown,lchown,fchownat -o \"$d/st\" -- \"$t\" \"$@\" > \"$d/out\" 2>&1 &\n"
"  sp=$!\n"
"  while kill -0 \"$sp\" 2>/dev/null; do\n"
"    now=$(date +%s)\n"
"    if [ \"$now\" -ge \"$end\" ]; then kill -KILL -\"$sp\" 2>/dev/null; kill -KILL \"$sp\" 2>/dev/null; to=1; break; fi\n"
"    sleep 0.1\n"
"  done\n"
"  wait \"$sp\" 2>/dev/null; rc=$?\n"
"  if [ -r \"$d/st\" ]; then\n"
"    printf 'L\\tBEGIN\\n'\n"
"    if [ \"$(wc -c < \"$d/st\")\" -gt 180000 ]; then head -c 180000 \"$d/st\" | sed 's/^/L\\t/'; printf 'L\\t(TRACELOG-TRUNCATED)\\n'; else sed 's/^/L\\t/' \"$d/st\"; fi\n"
"    printf 'L\\tEND\\n'\n"
"  else\n"
"    printf 'W\\tstrace 未产出日志（ptrace 可能被禁止）\\n'\n"
"  fi\n"
"else\n"
"  \"$t\" \"$@\" > \"$d/out\" 2>&1 &\n"
"  tp=$!\n"
"  printf 'P\\t%d\\t%s\\n' \"$tp\" \"$t\"\n"
"  sockf=$d/socks; : > \"$sockf\"\n"
"  s=$((ms / 1000)); r=$((ms % 1000))\n"
"  if [ \"$r\" -lt 10 ]; then r=\"00$r\"; elif [ \"$r\" -lt 100 ]; then r=\"0$r\"; fi\n"
"  slp=\"$s.$r\"; ns=0\n"
"  while kill -0 \"$tp\" 2>/dev/null; do\n"
"    now=$(date +%s)\n"
"    if [ \"$now\" -ge \"$end\" ]; then kill -KILL -\"$tp\" 2>/dev/null; kill -KILL \"$tp\" 2>/dev/null; to=1; break; fi\n"
"    ns=$((ns + 1))\n"
"    for f in /proc/$tp/fd/*; do\n"
"      [ -e \"$f\" ] || continue\n"
"      l=$(readlink \"$f\" 2>/dev/null) || continue\n"
"      case $l in\n"
"        socket:*) x=${l#socket:[}; x=${x%]}; printf '%s\\n' \"$x\" >> \"$sockf\" ;;\n"
"        /*) fl=\"\"; firaw=/proc/$tp/fdinfo/${f##*/}; if [ -r \"$firaw\" ]; then fl=$(awk '$1==\"flags:\"{print $2; exit}' \"$firaw\" 2>/dev/null); fi; emit \"F\\t$l\\t$fl\" ;;\n"
"      esac\n"
"    done\n"
"    if [ -r /proc/$tp/maps ]; then\n"
"      while read -r a1 perms off dev ino mp; do\n"
"        [ -n \"$mp\" ] || continue\n"
"        case $mp in \\[*) continue ;; esac\n"
"        emit \"M\\t$mp\"\n"
"      done < /proc/$tp/maps\n"
"    fi\n"
"    for p in /proc/[0-9]*; do\n"
"      cp=${p##*/}\n"
"      [ \"$cp\" = \"$tp\" ] && continue\n"
"      c=$cp; i=0; isd=0\n"
"      while [ \"$i\" -lt 8 ]; do\n"
"        [ \"$c\" = \"$tp\" ] && { isd=1; break; }\n"
"        [ \"$c\" -le 1 ] 2>/dev/null && break\n"
"        ss=$(cat /proc/$c/stat 2>/dev/null) || break\n"
"        rr=${ss##*) }\n"
"        set -- $rr\n"
"        c=${2:-1}\n"
"        i=$((i+1))\n"
"      done\n"
"      [ \"$isd\" = 1 ] || continue\n"
"      ex=$(readlink \"$p/exe\" 2>/dev/null)\n"
"      emit \"P\\t$cp\\t${ex:-?}\"\n"
"    done\n"
"    if [ -s \"$sockf\" ]; then\n"
"      sort -u \"$sockf\" > \"$d/su\" 2>/dev/null || cp \"$sockf\" \"$d/su\"\n"
"      for tb in tcp tcp6 udp udp6; do\n"
"        nf=/proc/$tp/net/$tb\n"
"        [ -r \"$nf\" ] || continue\n"
"        while read -r sl la ra st tx tr uid to ino rest; do\n"
"          [ \"$sl\" = \"sl\" ] && continue\n"
"          [ -n \"$ino\" ] || continue\n"
"          grep -Fqx -- \"$ino\" \"$d/su\" 2>/dev/null || continue\n"
"          emit \"N\\t$tb\\t$la\\t$ra\\t$st\\t$ino\"\n"
"        done < \"$nf\"\n"
"      done\n"
"    fi\n"
"    sleep \"$slp\" 2>/dev/null || sleep 1\n"
"  done\n"
"  wait \"$tp\" 2>/dev/null; rc=$?\n"
"  printf 'I\\t%d\\n' \"$ns\"\n"
"fi\n"
"printf 'R\\t%d\\t%d\\n' \"$rc\" \"$to\"\n"
"if [ -r \"$d/out\" ]; then\n"
"  sz=$(wc -c < \"$d/out\")\n"
"  if [ \"$sz\" -gt 4096 ]; then tail -c 4096 \"$d/out\" | sed 's/^/O\\t/'; printf 'O\\t(OUTPUT-TRUNCATED)\\n'; else sed 's/^/O\\t/' \"$d/out\"; fi\n"
"fi\n"
"rm -rf \"$d\"\n";

/* ---- TSV / strace 解析 ---- */

struct ap_runres {
	char mode[16];
	int actual_strace;
	int exit_code;
	int timed_out;
	long long start;
	int samples;
	int strace_lines;
	int strace_execve;
	int failed_opens;
	struct ap_event *ev;
	int ev_n;
	int ev_cap;
	int ev_trunc;
	char out_tail[4096];
	size_t out_len;
	int out_trunc;
	char warn[8][256];
	int warn_n;
};

static void ap_run_warn(struct ap_runres *r, const char *fmt, ...)
{
	va_list ap;

	if (r->warn_n >= 8)
		return;
	va_start(ap, fmt);
	vsnprintf(r->warn[r->warn_n], sizeof(r->warn[0]), fmt, ap);
	va_end(ap);
	r->warn_n++;
}

int ap_event_add(struct ap_event *ev, int *n, int max,
		 const struct ap_event *e)
{
	int i;

	for (i = 0; i < *n; i++) {
		if (ev[i].type != e->type)
			continue;
		if (e->type == AP_EV_NET_CONNECT ||
		    e->type == AP_EV_NET_LISTEN ||
		    e->type == AP_EV_NET_UNIX) {
			if (strcmp(ev[i].proto, e->proto) == 0 &&
			    strcmp(ev[i].remote, e->remote) == 0 &&
			    strcmp(ev[i].local, e->local) == 0) {
				ev[i].count++;
				if (!ev[i].pid && e->pid)
					ev[i].pid = e->pid;
				return 0;
			}
		} else {
			if (strcmp(ev[i].path, e->path) == 0) {
				ev[i].count++;
				if (!ev[i].pid && e->pid)
					ev[i].pid = e->pid;
				return 0;
			}
		}
	}
	if (*n >= max)
		return -1;
	ev[*n] = *e;
	ev[*n].count = 1;
	(*n)++;
	return 1;
}

static const char *ap_unquote_strace(const char *p, char *out, size_t cap)
{
	size_t o = 0;

	if (*p != '"')
		return NULL;
	p++;
	while (*p) {
		char c;

		if (*p == '"') {
			p++;
			break;
		}
		if (*p == '\\' && p[1]) {
			p++;
			switch (*p) {
			case 'n': c = '\n'; p++; break;
			case 't': c = '\t'; p++; break;
			case 'r': c = '\r'; p++; break;
			case 'f': c = '\f'; p++; break;
			case 'v': c = '\v'; p++; break;
			case 'a': c = '\a'; p++; break;
			case 'b': c = '\b'; p++; break;
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7': {
				int v = 0, k = 0;

				while (k < 3 && *p >= '0' && *p <= '7') {
					v = v * 8 + (*p - '0');
					p++;
					k++;
				}
				c = (char)v;
				break;
			}
			case 'x': {
				int v = 0, k = 0;

				p++;
				while (k < 2 && ((*p >= '0' && *p <= '9') ||
						(*p >= 'a' && *p <= 'f') ||
						(*p >= 'A' && *p <= 'F'))) {
					int d = *p <= '9' ? *p - '0' :
						(*p | 0x20) - 'a' + 10;

					v = v * 16 + d;
					p++;
					k++;
				}
				c = (char)v;
				break;
			}
			default:
				c = *p;
				p++;
				break;
			}
		} else {
			c = *p++;
		}
		if (o + 1 < cap && (unsigned char)c >= 0x20 && c != 0x7f)
			out[o++] = c;
	}
	out[o] = '\0';
	return p;
}

static int ap_find_port(const char *line, const char *key, int *port)
{
	const char *p = strstr(line, key);

	if (!p)
		return -1;
	*port = atoi(p + strlen(key));
	return 0;
}

int ap_strace_line(const char *line, struct ap_event *out, int *failed)
{
	const char *p, *name;
	size_t nlen;
	char q[8][AP_EV_PATH];
	int qn = 0;
	const char *ret = NULL;
	int ok;

	if (!line)
		return 0;
	p = line;
	while (*p == ' ' || *p == '\t')
		p++;
	while (*p >= '0' && *p <= '9')
		p++;
	while (*p == ' ' || *p == '\t')
		p++;
	name = p;
	while (*p && *p != '(')
		p++;
	if (*p != '(')
		return 0;
	nlen = (size_t)(p - name);
	if (nlen == 0 || nlen > 32)
		return 0;
	/* quoted tokens（最多 8 个） */
	p++;
	while (*p && qn < 8) {
		if (*p == '"') {
			char *after = (char *)ap_unquote_strace(p, q[qn],
							       AP_EV_PATH);

			if (!after)
				break;
			qn++;
			p = after;
			continue;
		}
		if (*p == '\n' || *p == '\0')
			break;
		p++;
	}
	{
		const char *s = line;

		while ((s = strstr(s, " = ")) != NULL) {
			ret = s;
			s += 3;
		}
	}
	ok = ret && !(ret[3] == '-' && ret[4] == '1');
	memset(out, 0, sizeof(*out));
	out->pid = 0;

#define AP_NAME_IS(x) (nlen == strlen(x) && strncmp(name, x, nlen) == 0)
	if (AP_NAME_IS("execve") || AP_NAME_IS("execveat")) {
		if (!ok || qn == 0 || !q[0][0])
			return 0;
		out->type = AP_EV_PROC_EXEC;
		snprintf(out->path, sizeof(out->path), "%s", q[0]);
		snprintf(out->note, sizeof(out->note), "strace-execve");
		return 1;
	}
	if (AP_NAME_IS("open") || AP_NAME_IS("openat") ||
	    AP_NAME_IS("openat2")) {
		if (!ok) {
			if (failed)
				(*failed)++;
			return -1;
		}
		if (qn == 0 || !q[0][0])
			return 0;
		snprintf(out->path, sizeof(out->path), "%s", q[0]);
		if (strstr(line, "O_WRONLY") || strstr(line, "O_RDWR") ||
		    strstr(line, "O_CREAT") || strstr(line, "O_TRUNC") ||
		    strstr(line, "O_APPEND")) {
			out->type = AP_EV_FILE_WRITE;
			snprintf(out->note, sizeof(out->note), "strace-open-w");
		} else {
			out->type = AP_EV_FILE_READ;
			snprintf(out->note, sizeof(out->note), "strace-open");
		}
		return 1;
	}
	if (AP_NAME_IS("unlink") || AP_NAME_IS("unlinkat") ||
	    AP_NAME_IS("rename") || AP_NAME_IS("renameat") ||
	    AP_NAME_IS("renameat2") || AP_NAME_IS("mkdir") ||
	    AP_NAME_IS("mkdirat") || AP_NAME_IS("chmod") ||
	    AP_NAME_IS("fchmodat") || AP_NAME_IS("chown") ||
	    AP_NAME_IS("lchown") || AP_NAME_IS("fchownat")) {
		int pick = 0;

		if (!ok || qn == 0)
			return 0;
		if ((AP_NAME_IS("rename") || AP_NAME_IS("renameat") ||
		     AP_NAME_IS("renameat2")) && qn > 1)
			pick = 1;
		if (!q[pick][0])
			return 0;
		out->type = AP_EV_FILE_WRITE;
		snprintf(out->path, sizeof(out->path), "%s", q[pick]);
		snprintf(out->note, sizeof(out->note), "strace-%.*s",
			 (int)nlen, name);
		return 1;
	}
	if (AP_NAME_IS("connect") || AP_NAME_IS("bind")) {
		int is_bind = AP_NAME_IS("bind");
		int port = -1;
		char addr[128] = "";

		if (!ok && strstr(line, "EINPROGRESS") == NULL)
			return 0;
		if (strstr(line, "AF_UNIX") != NULL) {
			if (qn == 0 || !q[0][0])
				return 0;
			out->type = AP_EV_NET_UNIX;
			snprintf(out->remote, sizeof(out->remote), "%.60s", q[0]);
			snprintf(out->proto, sizeof(out->proto), "unix");
			snprintf(out->state, sizeof(out->state), "CONNECT");
			return 1;
		}
		if (strstr(line, "AF_INET6") != NULL) {
			if (qn == 0 || !q[0][0])
				return 0;
			snprintf(addr, sizeof(addr), "[%.100s]", q[0]);
			if (ap_find_port(line, "sin6_port=htons(", &port) != 0)
				port = -1;
		} else if (strstr(line, "AF_INET") != NULL) {
			if (qn == 0 || !q[0][0])
				return 0;
			snprintf(addr, sizeof(addr), "%.100s", q[0]);
			if (ap_find_port(line, "sin_port=htons(", &port) != 0)
				port = -1;
		} else {
			return 0;
		}
		if (port >= 0)
			snprintf(out->remote, sizeof(out->remote), "%s:%d",
				 addr, port);
		else
			snprintf(out->remote, sizeof(out->remote), "%s", addr);
		out->type = is_bind ? AP_EV_NET_LISTEN : AP_EV_NET_CONNECT;
		snprintf(out->proto, sizeof(out->proto), "inet");
		snprintf(out->state, sizeof(out->state), is_bind ? "BIND" :
			 "CONNECT");
		return 1;
	}
#undef AP_NAME_IS
	(void)qn;
	return 0;
}

static void ap_net_hex_ipv4(const char *hex, char *out, size_t cap)
{
	unsigned b[4];
	int i;

	if (strlen(hex) < 8) {
		snprintf(out, cap, "%s", hex);
		return;
	}
	for (i = 0; i < 4; i++) {
		char two[3];
		unsigned v;

		two[0] = hex[(3 - i) * 2];
		two[1] = hex[(3 - i) * 2 + 1];
		two[2] = '\0';
		v = (unsigned)strtoul(two, NULL, 16);
		b[i] = v;
	}
	snprintf(out, cap, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static void ap_net_hex_ipv6(const char *hex, char *out, size_t cap)
{
	char buf[64];
	int g, i;
	size_t o = 0;

	buf[0] = '\0';
	if (strlen(hex) < 32) {
		snprintf(out, cap, "%s", hex);
		return;
	}
	for (g = 0; g < 4; g++) {
		unsigned v = 0;
		unsigned char b[4];

		for (i = 0; i < 8; i++) {
			char c = hex[g * 8 + i];
			unsigned d;

			if (c >= '0' && c <= '9')
				d = (unsigned)(c - '0');
			else if (c >= 'a' && c <= 'f')
				d = (unsigned)(c - 'a' + 10);
			else if (c >= 'A' && c <= 'F')
				d = (unsigned)(c - 'A' + 10);
			else
				d = 0;
			v = (v << 4) | d;
		}
		/* /proc/net/tcp6 每个 32 位字按小端存储 */
		b[0] = (unsigned char)(v & 0xff);
		b[1] = (unsigned char)((v >> 8) & 0xff);
		b[2] = (unsigned char)((v >> 16) & 0xff);
		b[3] = (unsigned char)((v >> 24) & 0xff);
		if (g > 0 && o + 1 < sizeof(buf))
			buf[o++] = ':';
		if (o + 10 < sizeof(buf))
			o += (size_t)snprintf(buf + o, sizeof(buf) - o,
					      "%02x%02x:%02x%02x",
					      b[0], b[1], b[2], b[3]);
	}
	if (o < sizeof(buf))
		buf[o] = '\0';
	else
		buf[sizeof(buf) - 1] = '\0';
	snprintf(out, cap, "%s", buf);
}

static const char *ap_tcp_state(const char *hex)
{
	if (strcmp(hex, "01") == 0) return "ESTABLISHED";
	if (strcmp(hex, "02") == 0) return "SYN_SENT";
	if (strcmp(hex, "03") == 0) return "SYN_RECV";
	if (strcmp(hex, "04") == 0) return "FIN_WAIT1";
	if (strcmp(hex, "05") == 0) return "FIN_WAIT2";
	if (strcmp(hex, "06") == 0) return "TIME_WAIT";
	if (strcmp(hex, "07") == 0) return "CLOSE";
	if (strcmp(hex, "08") == 0) return "CLOSE_WAIT";
	if (strcmp(hex, "09") == 0) return "LAST_ACK";
	if (strcmp(hex, "0A") == 0 || strcmp(hex, "0a") == 0)
		return "LISTEN";
	if (strcmp(hex, "0B") == 0) return "CLOSING";
	return hex;
}

int ap_procnet_decode(const char *line, const char *proto,
		      struct ap_netinfo *n)
{
	char tmp[512];
	char *save = NULL, *tok;
	char *f[11];
	int nf = 0, is6, is_udp;

	memset(n, 0, sizeof(*n));
	if (!line || !proto)
		return -1;
	snprintf(tmp, sizeof(tmp), "%s", line);
	for (tok = strtok_r(tmp, " \t\r\n", &save); tok && nf < 11;
	     tok = strtok_r(NULL, " \t\r\n", &save))
		f[nf++] = tok;
	if (nf < 10)
		return -1;
	if (strcmp(f[0], "sl") == 0)
		return -1;
	is6 = strstr(proto, "6") != NULL;
	is_udp = strncmp(proto, "udp", 3) == 0;
	snprintf(n->proto, sizeof(n->proto), "%s", is_udp ? "udp" : "tcp");
	if (is6)
		strncat(n->proto, "6", sizeof(n->proto) -
			strlen(n->proto) - 1);
	{
		char la[256], ra[256], a[128], b[128];
		char *colon;

		snprintf(la, sizeof(la), "%s", f[1]);
		snprintf(ra, sizeof(ra), "%s", f[2]);
		colon = strchr(la, ':');
		if (!colon)
			return -1;
		*colon = '\0';
		if (is6)
			ap_net_hex_ipv6(la, a, sizeof(a));
		else
			ap_net_hex_ipv4(la, a, sizeof(a));
		snprintf(n->local, sizeof(n->local), "%.60s:%u", a,
			 (unsigned)strtoul(colon + 1, NULL, 16));
		colon = strchr(ra, ':');
		if (!colon)
			return -1;
		*colon = '\0';
		if (is6)
			ap_net_hex_ipv6(ra, b, sizeof(b));
		else
			ap_net_hex_ipv4(ra, b, sizeof(b));
		snprintf(n->remote, sizeof(n->remote), "%.60s:%u", b,
			 (unsigned)strtoul(colon + 1, NULL, 16));
	}
	snprintf(n->state, sizeof(n->state), "%s", ap_tcp_state(f[3]));
	snprintf(n->inode, sizeof(n->inode), "%s", f[9]);
	return 0;
}

static void ap_parse_tsv(const char *text, struct ap_runres *r)
{
	const char *p = text ? text : "";

	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);
		char line[8192];
		char tag;

		if (len >= sizeof(line))
			len = sizeof(line) - 1;
		memcpy(line, p, len);
		line[len] = '\0';
		if (len > 0 && line[len - 1] == '\r')
			line[len - 1] = '\0';
		tag = line[0];
		if (len >= 2 && line[1] == '\t') {
			const char *body = line + 2;

			switch (tag) {
			case 'B': {
				char *tab = strchr(body, '\t');

				if (tab) {
					*tab = '\0';
					r->start = atoll(body);
					snprintf(r->mode, sizeof(r->mode),
						 "%s", tab + 1);
					r->actual_strace =
						strcmp(tab + 1, "strace") == 0;
				}
				break;
			}
			case 'G': {
				struct ap_event e;

				memset(&e, 0, sizeof(e));
				e.type = AP_EV_PROC_EXEC;
				snprintf(e.path, sizeof(e.path), "%.500s", body);
				snprintf(e.note, sizeof(e.note), "target");
				if (ap_event_add(r->ev, &r->ev_n, r->ev_cap,
						 &e) < 0)
					r->ev_trunc = 1;
				break;
			}
			case 'U':
				snprintf(r->mode, sizeof(r->mode), "%.15s", body);
				r->actual_strace =
					strcmp(body, "strace") == 0;
				break;
			case 'L': {
				struct ap_event e;
				int rc;

				if (strcmp(body, "BEGIN") == 0 ||
				    strcmp(body, "END") == 0 ||
				    strstr(body, "TRACELOG-TRUNCATED"))
					break;
				r->strace_lines++;
				rc = ap_strace_line(body, &e,
						    &r->failed_opens);
				if (rc == 1) {
					if (strcmp(e.note, "strace-execve") == 0)
						r->strace_execve++;
					if (ap_event_add(r->ev, &r->ev_n,
							 r->ev_cap, &e) < 0)
						r->ev_trunc = 1;
				}
				break;
			}
			case 'F': {
				char *tab = strchr(body, '\t');
				long flags = 0;
				struct ap_event e;

				memset(&e, 0, sizeof(e));
				if (tab) {
					*tab = '\0';
					flags = strtol(tab + 1, NULL, 8);
				}
				e.type = (flags & 3) ? AP_EV_FILE_WRITE :
						      AP_EV_FILE_READ;
				snprintf(e.path, sizeof(e.path), "%.500s", body);
				snprintf(e.note, sizeof(e.note), "proc-fd");
				if (ap_event_add(r->ev, &r->ev_n, r->ev_cap,
						 &e) < 0)
					r->ev_trunc = 1;
				break;
			}
			case 'M': {
				struct ap_event e;

				memset(&e, 0, sizeof(e));
				e.type = AP_EV_FILE_MMAP;
				snprintf(e.path, sizeof(e.path), "%.500s", body);
				snprintf(e.note, sizeof(e.note), "proc-maps");
				if (ap_event_add(r->ev, &r->ev_n, r->ev_cap,
						 &e) < 0)
					r->ev_trunc = 1;
				break;
			}
			case 'P': {
				char *tab = strchr(body, '\t');
				struct ap_event e;

				memset(&e, 0, sizeof(e));
				e.type = AP_EV_PROC_EXEC;
				if (tab) {
					*tab = '\0';
					e.pid = atoi(body);
					snprintf(e.path, sizeof(e.path), "%.500s",
						 tab + 1);
				} else {
					snprintf(e.path, sizeof(e.path), "%.500s",
						 body);
				}
				snprintf(e.note, sizeof(e.note), "proc-tree");
				if (ap_event_add(r->ev, &r->ev_n, r->ev_cap,
						 &e) < 0)
					r->ev_trunc = 1;
				break;
			}
			case 'N': {
				/* tbl \t localhex \t remotehex \t state \t inode */
				char nbuf[512], *sv = NULL, *t0, *t1, *t2, *t3;
				struct ap_netinfo ni;
				struct ap_event e;
				char proto[8];

				snprintf(nbuf, sizeof(nbuf), "%s", body);
				t0 = strtok_r(nbuf, "\t", &sv);
				t1 = t0 ? strtok_r(NULL, "\t", &sv) : NULL;
				t2 = t1 ? strtok_r(NULL, "\t", &sv) : NULL;
				t3 = t2 ? strtok_r(NULL, "\t", &sv) : NULL;
				{
					char *t4 = t3 ?
						   strtok_r(NULL, "\t", &sv) :
						   NULL;
					char row[512];

					if (!t0 || !t1 || !t2 || !t3 || !t4)
						break;
					snprintf(proto, sizeof(proto), "%s",
						 t0);
					snprintf(row, sizeof(row),
						 "0 %s %s %s 0 0 0 0 0 %s",
						 t1, t2, t3, t4);
					if (ap_procnet_decode(row, proto,
							      &ni) != 0)
						break;
				}
				memset(&e, 0, sizeof(e));
				e.type = strcmp(ni.state, "LISTEN") == 0 ?
					 AP_EV_NET_LISTEN :
					 AP_EV_NET_CONNECT;
				snprintf(e.proto, sizeof(e.proto), "%s",
					 ni.proto);
				snprintf(e.local, sizeof(e.local), "%s",
					 ni.local);
				snprintf(e.remote, sizeof(e.remote), "%s",
					 ni.remote);
				snprintf(e.state, sizeof(e.state), "%s",
					 ni.state);
				e.inode = atoll(ni.inode);
				snprintf(e.note, sizeof(e.note), "proc-net");
				if (ap_event_add(r->ev, &r->ev_n, r->ev_cap,
						 &e) < 0)
					r->ev_trunc = 1;
				break;
			}
			case 'O': {
				size_t blen = strlen(body);

				if (r->out_len + blen + 2 <
				    sizeof(r->out_tail)) {
					memcpy(r->out_tail + r->out_len, body,
					       blen);
					r->out_len += blen;
					r->out_tail[r->out_len++] = '\n';
					r->out_tail[r->out_len] = '\0';
				} else {
					r->out_trunc = 1;
				}
				if (strstr(body, "OUTPUT-TRUNCATED"))
					r->out_trunc = 1;
				break;
			}
			case 'W':
				ap_run_warn(r, "%s", body);
				break;
			case 'R': {
				char *tab = strchr(body, '\t');

				if (tab) {
					*tab = '\0';
					r->exit_code = atoi(body);
					r->timed_out = atoi(tab + 1);
				}
				break;
			}
			case 'I':
				r->samples = atoi(body);
				break;
			default:
				break;
			}
		}
		if (!eol)
			break;
		p = eol + 1;
	}
}

static int ap_runres_init(struct ap_runres *r)
{
	memset(r, 0, sizeof(*r));
	r->ev = calloc(AP_MAX_EVENTS, sizeof(struct ap_event));
	if (!r->ev)
		return -1;
	r->ev_cap = AP_MAX_EVENTS;
	return 0;
}

static void ap_runres_free(struct ap_runres *r)
{
	free(r->ev);
	r->ev = NULL;
}

static int ap_ev_count(const struct ap_runres *r, int type)
{
	int i, n = 0;

	for (i = 0; i < r->ev_n; i++)
		if (r->ev[i].type == type)
			n++;
	return n;
}

static const char *ap_ev_type_name(int t)
{
	switch (t) {
	case AP_EV_FILE_READ: return "file_read";
	case AP_EV_FILE_WRITE: return "file_write";
	case AP_EV_FILE_MMAP: return "file_mmap";
	case AP_EV_PROC_EXEC: return "proc_exec";
	case AP_EV_NET_CONNECT: return "net_connect";
	case AP_EV_NET_LISTEN: return "net_listen";
	case AP_EV_NET_UNIX: return "net_unix";
	default: return "unknown";
	}
}

static void ap_degraded_lines(const struct ap_runres *r, int net_none,
			      char lines[][256], int *n, int max)
{
	int i = 0;

#define AP_DEG(...) do { \
	if (i < max) \
		snprintf(lines[i++], 256, __VA_ARGS__); \
} while (0)

	if (r->actual_strace) {
		AP_DEG("fanotify 未实现：文件访问以 strace(ptrace) 为来源，"
		       "ptrace 有开销、可能改变时序");
		if (r->strace_execve == 0)
			AP_DEG("strace 日志未见 execve：ptrace 可能被禁止，"
			       "事件不完整");
	} else {
		AP_DEG("无 fanotify/inotify 事件工具且 strace 不可用：退化为 "
		       "/proc 采样（fd+fdinfo+maps+net），可能漏采短命 fd");
	}
	if (r->timed_out)
		AP_DEG("目标超时被 SIGKILL：事件流为超时前部分");
	if (r->out_trunc)
		AP_DEG("目标输出超过 4KB，仅保留尾部");
	if (r->ev_trunc)
		AP_DEG("事件数达到上限 %d，后续事件被截断", AP_MAX_EVENTS);
	if (net_none)
		AP_DEG("net=none：无网络命名空间外连能力，连接事件必为空"
		       "（测试环境为本机回环也禁）");
	AP_DEG("动态画像只覆盖本次运行的可观察行为：dlopen 延迟加载、"
	       "父子进程竞态、内核内部访问可能漏采");
	if (r->failed_opens > 0)
		AP_DEG("strace 记录到 %d 次失败的 open（ENOENT/EACCES 等），"
		       "已从事件流剔除", r->failed_opens);
#undef AP_DEG
	*n = i;
}

static void ap_dynamic_render_json(const char *path, char *const argv[],
				   int argc, const char *ws, const char *backing,
				   int net_none, long long elapsed_ms,
				   const struct ap_runres *r, struct apb *b)
{
	char deg[10][256];
	int deg_n = 0, i;

	ap_degraded_lines(r, net_none, deg, &deg_n, 10);
	apb_printf(b, "{\"tool\":\"app_profile_dynamic\",\"path\":");
	apb_json_str(b, path);
	apb_printf(b, ",\"argv\":[");
	apb_json_str(b, path);
	for (i = 0; i < argc; i++) {
		apb_printf(b, ",");
		apb_json_str(b, argv[i]);
	}
	apb_printf(b, "],\"workspace\":");
	apb_json_str(b, ws);
	apb_printf(b, ",\"workspace_backing\":");
	apb_json_str(b, backing);
	apb_printf(b, ",\"net\":\"%s\"", net_none ? "none" : "host");
	apb_printf(b, ",\"sandbox\":\"aik-sandbox run（独立 mount/pid/uts "
		   "namespace + no_new_privs + 能力清空）\"");
	apb_printf(b, ",\"mode\":");
	apb_json_str(b, r->mode);
	apb_printf(b, ",\"started_at\":%lld", r->start);
	apb_printf(b, ",\"duration_ms\":%lld", elapsed_ms);
	apb_printf(b, ",\"exit_code\":%d,\"timed_out\":%s",
		   r->exit_code, r->timed_out ? "true" : "false");
	apb_printf(b, ",\"stats\":{\"events\":%d,\"file_read\":%d,"
		   "\"file_write\":%d,\"file_mmap\":%d,\"exec\":%d,"
		   "\"net\":%d,\"strace_lines\":%d,\"samples\":%d}",
		   r->ev_n, ap_ev_count(r, AP_EV_FILE_READ),
		   ap_ev_count(r, AP_EV_FILE_WRITE),
		   ap_ev_count(r, AP_EV_FILE_MMAP),
		   ap_ev_count(r, AP_EV_PROC_EXEC),
		   ap_ev_count(r, AP_EV_NET_CONNECT) +
		   ap_ev_count(r, AP_EV_NET_LISTEN) +
		   ap_ev_count(r, AP_EV_NET_UNIX),
		   r->strace_lines, r->samples);
	apb_printf(b, ",\"events\":[");
	for (i = 0; i < r->ev_n; i++) {
		const struct ap_event *e = &r->ev[i];

		if (i)
			apb_printf(b, ",");
		apb_printf(b, "{\"seq\":%d,\"type\":\"%s\",\"pid\":%d",
			   i + 1, ap_ev_type_name(e->type), e->pid);
		if (e->type == AP_EV_FILE_READ ||
		    e->type == AP_EV_FILE_WRITE ||
		    e->type == AP_EV_FILE_MMAP ||
		    e->type == AP_EV_PROC_EXEC) {
			apb_printf(b, ",\"path\":");
			apb_json_str(b, e->path);
		}
		if (e->type == AP_EV_NET_CONNECT ||
		    e->type == AP_EV_NET_LISTEN ||
		    e->type == AP_EV_NET_UNIX) {
			apb_printf(b, ",\"proto\":");
			apb_json_str(b, e->proto);
			apb_printf(b, ",\"local\":");
			apb_json_str(b, e->local);
			apb_printf(b, ",\"remote\":");
			apb_json_str(b, e->remote);
			apb_printf(b, ",\"state\":");
			apb_json_str(b, e->state);
			apb_printf(b, ",\"inode\":%lld", e->inode);
		}
		if (e->note[0]) {
			apb_printf(b, ",\"note\":");
			apb_json_str(b, e->note);
		}
		if (e->count > 1)
			apb_printf(b, ",\"count\":%d", e->count);
		apb_printf(b, "}");
	}
	apb_printf(b, "],\"output_tail\":");
	apb_json_str(b, r->out_tail);
	apb_printf(b, ",\"warnings\":[");
	for (i = 0; i < r->warn_n; i++) {
		if (i)
			apb_printf(b, ",");
		apb_json_str(b, r->warn[i]);
	}
	apb_printf(b, "],\"degraded\":[");
	for (i = 0; i < deg_n; i++) {
		if (i)
			apb_printf(b, ",");
		apb_json_str(b, deg[i]);
	}
	apb_printf(b, "]}\n");
}

static void ap_dynamic_render_text(const char *path, char *const argv[],
				   int argc, const char *ws, const char *backing,
				   int net_none, long long elapsed_ms,
				   const struct ap_runres *r, struct apb *b)
{
	char deg[10][256];
	int deg_n = 0, i;

	ap_degraded_lines(r, net_none, deg, &deg_n, 10);
	apb_printf(b, "== 动态画像: %s ==\n", path);
	apb_printf(b, "[命令]");
	for (i = 0; i < argc; i++)
		apb_printf(b, " %s", argv[i]);
	apb_printf(b, "\n[工作区] %s（backing=%s, net=%s）\n", ws, backing,
		   net_none ? "none" : "host");
	apb_printf(b, "[沙盒] aik-sandbox run：独立 mount/pid/uts namespace"
		   " + no_new_privs + 能力清空\n");
	apb_printf(b, "[执行] exit=%d%s 耗时=%lldms 采样模式=%s"
		   "（strace 行 %d / 采样 %d）\n", r->exit_code,
		   r->timed_out ? "（超时强杀）" : "", elapsed_ms, r->mode,
		   r->strace_lines, r->samples);
	apb_printf(b, "[事件] 共 %d：读 %d / 写 %d / 映射 %d / 子进程 %d / "
		   "网络 %d\n", r->ev_n, ap_ev_count(r, AP_EV_FILE_READ),
		   ap_ev_count(r, AP_EV_FILE_WRITE),
		   ap_ev_count(r, AP_EV_FILE_MMAP),
		   ap_ev_count(r, AP_EV_PROC_EXEC),
		   ap_ev_count(r, AP_EV_NET_CONNECT) +
		   ap_ev_count(r, AP_EV_NET_LISTEN) +
		   ap_ev_count(r, AP_EV_NET_UNIX));
	for (i = 0; i < r->ev_n; i++) {
		const struct ap_event *e = &r->ev[i];

		if (e->type == AP_EV_FILE_READ ||
		    e->type == AP_EV_FILE_WRITE ||
		    e->type == AP_EV_FILE_MMAP)
			apb_printf(b, "  [%s] %s%s（%s）\n",
				   ap_ev_type_name(e->type), e->path,
				   e->count > 1 ? " ×N" : "", e->note);
		else if (e->type == AP_EV_PROC_EXEC)
			apb_printf(b, "  [exec] pid=%d %s（%s）\n", e->pid,
				   e->path, e->note);
		else
			apb_printf(b, "  [%s] %s %s -> %s [%s]%s\n",
				   ap_ev_type_name(e->type), e->proto,
				   e->local[0] ? e->local : "*", e->remote,
				   e->state, e->count > 1 ? " ×N" : "");
	}
	if (r->out_tail[0])
		apb_printf(b, "[目标输出尾部]\n%s", r->out_tail);
	for (i = 0; i < r->warn_n; i++)
		apb_printf(b, "[警告] %s\n", r->warn[i]);
	apb_printf(b, "[降级/局限]\n");
	for (i = 0; i < deg_n; i++)
		apb_printf(b, "  - %s\n", deg[i]);
}
/* ======================================================================
 * 4) 差集报告（静态声明 vs 动态行为）
 * ====================================================================== */

enum {
	AP_CAT_LIB = 0,		/* 库目录下的未声明库 */
	AP_CAT_ETC,		/* /etc 配置读取 */
	AP_CAT_NET,		/* 网络连接/监听 */
	AP_CAT_SENS,		/* 敏感路径/setuid/能力 */
	AP_CAT_WRITE,		/* 写入 */
	AP_CAT_EXEC,		/* 未声明子进程 */
	AP_CAT_PROC,		/* /proc /sys */
	AP_CAT_OTHER,		/* 其他读取（本地化/设备/临时目录） */
	AP_CAT_N,
};

/* 分类封顶：同类项只按类别上限计分，避免 40 个同质库把分数堆到 100 */
static const int ap_cat_cap[AP_CAT_N] = {
	10, 15, 30, 40, 50, 20, 5, 10,
};

static int ap_ev_type_from_name(const char *s)
{
	if (!s)
		return -1;
	if (strcmp(s, "file_read") == 0) return AP_EV_FILE_READ;
	if (strcmp(s, "file_write") == 0) return AP_EV_FILE_WRITE;
	if (strcmp(s, "file_mmap") == 0) return AP_EV_FILE_MMAP;
	if (strcmp(s, "proc_exec") == 0) return AP_EV_PROC_EXEC;
	if (strcmp(s, "net_connect") == 0) return AP_EV_NET_CONNECT;
	if (strcmp(s, "net_listen") == 0) return AP_EV_NET_LISTEN;
	if (strcmp(s, "net_unix") == 0) return AP_EV_NET_UNIX;
	return -1;
}

static char *ap_json_strdup_member(const char *obj, size_t olen,
				   const char *key)
{
	const char *v;
	size_t vlen;
	int t;

	if (ai_json_obj_get(obj, olen, key, &v, &vlen, &t) != 1)
		return NULL;
	if (t != AI_JSON_STR)
		return NULL;
	return ai_json_strdup_str(v, vlen);
}

int ap_dynamic_json_to_events(const char *json, struct ap_event *ev, int max,
			      int *n, int *truncated, char *err,
			      size_t errcap)
{
	const char *arr;
	size_t alen, jlen;
	int type, i;

	*n = 0;
	if (truncated)
		*truncated = 0;
	if (!json || !json[0]) {
		snprintf(err, errcap, "dynamic 为空（需要 app_profile_dynamic "
			 "format=json 的输出）");
		return -1;
	}
	jlen = strlen(json);
	if (ai_json_obj_get(json, jlen, "events", &arr, &alen, &type) != 1) {
		if (strstr(json, "app_profile_static") != NULL)
			snprintf(err, errcap,
				 "dynamic 是静态画像，不是动态事件流");
		else
			snprintf(err, errcap,
				 "dynamic 缺 events 数组（需要 app_profile_"
				 "dynamic 的 JSON 输出）");
		return -1;
	}
	if (type != AI_JSON_ARR) {
		snprintf(err, errcap, "dynamic.events 不是数组");
		return -1;
	}
	for (i = 0; i < max; i++) {
		const char *el;
		size_t elen;
		int etype;
		char *ts, *path, *proto, *local, *remote, *state;
		const char *v;
		size_t vlen;
		int vt;

		if (ai_json_arr_get(arr, alen, i, &el, &elen, &etype) != 1)
			break;
		if (etype != AI_JSON_OBJ)
			continue;
		ts = ap_json_strdup_member(el, elen, "type");
		if (!ts)
			continue;
		etype = ap_ev_type_from_name(ts);
		free(ts);
		if (etype < 0)
			continue;
		memset(&ev[*n], 0, sizeof(ev[*n]));
		ev[*n].type = etype;
		ev[*n].count = 1;
		path = ap_json_strdup_member(el, elen, "path");
		proto = ap_json_strdup_member(el, elen, "proto");
		local = ap_json_strdup_member(el, elen, "local");
		remote = ap_json_strdup_member(el, elen, "remote");
		state = ap_json_strdup_member(el, elen, "state");
		if (path)
			snprintf(ev[*n].path, sizeof(ev[*n].path), "%s", path);
		if (proto)
			snprintf(ev[*n].proto, sizeof(ev[*n].proto), "%s",
				 proto);
		if (local)
			snprintf(ev[*n].local, sizeof(ev[*n].local), "%s",
				 local);
		if (remote)
			snprintf(ev[*n].remote, sizeof(ev[*n].remote), "%s",
				 remote);
		if (state)
			snprintf(ev[*n].state, sizeof(ev[*n].state), "%s",
				 state);
		free(path);
		free(proto);
		free(local);
		free(remote);
		free(state);
		if (ai_json_obj_get(el, elen, "pid", &v, &vlen, &vt) == 1 &&
		    vt == AI_JSON_NUM)
			ev[*n].pid = (int)ai_json_ll(v, vlen);
		if (ai_json_obj_get(el, elen, "count", &v, &vlen, &vt) == 1 &&
		    vt == AI_JSON_NUM) {
			int c = (int)ai_json_ll(v, vlen);

			ev[*n].count = c > 0 ? c : 1;
		}
		(*n)++;
	}
	{
		const char *el;
		size_t elen;
		int etype;

		if (ai_json_arr_get(arr, alen, *n, &el, &elen, &etype) == 1 &&
		    truncated)
			*truncated = 1;
	}
	return 0;
}

static int ap_needed_has(const struct ap_static *st, const char *path)
{
	const char *b = ap_base(path);
	int i;

	for (i = 0; i < st->dyn.needed_n; i++)
		if (strcmp(ap_base(st->dyn.needed[i]), b) == 0)
			return 1;
	return 0;
}

static int ap_is_under(const char *p, const char *prefix)
{
	size_t n = strlen(prefix);

	return strncmp(p, prefix, n) == 0;
}

static int ap_is_sensitive(const char *p)
{
	if (strcmp(p, "/etc/shadow") == 0 ||
	    strcmp(p, "/etc/gshadow") == 0 ||
	    strncmp(p, "/etc/sudoers", 12) == 0 ||
	    strncmp(p, "/root/", 6) == 0 ||
	    strncmp(p, "/proc/kcore", 11) == 0 ||
	    strncmp(p, "/dev/mem", 8) == 0 ||
	    strncmp(p, "/dev/kmem", 9) == 0 ||
	    strncmp(p, "/dev/port", 9) == 0)
		return 1;
	if (strstr(p, "/.ssh/") != NULL)
		return 1;
	if (strncmp(p, "/proc/", 6) == 0 && strstr(p, "/environ") != NULL)
		return 1;
	return 0;
}

/*
 * 单条路径风险归类：返回权重（0 = 静态已声明/公认无害），cat 填类别。
 */
static int ap_path_weight(const struct ap_static *st, const char *p,
			  int is_write, int *cat, char *why, size_t whycap)
{
	*cat = AP_CAT_OTHER;
	if (strcmp(p, st->path) == 0 || strcmp(p, st->input) == 0) {
		snprintf(why, whycap, "目标自身");
		return 0;
	}
	if (ap_needed_has(st, p)) {
		*cat = AP_CAT_LIB;
		if (is_write) {
			snprintf(why, whycap,
				 "静态声明的依赖库被写（异常：库文件应只读）");
			return 30;
		}
		snprintf(why, whycap, "静态声明的依赖库");
		return 0;
	}
	if (strncmp(ap_base(p), "ld-", 3) == 0 &&
	    (ap_is_under(p, "/lib") || ap_is_under(p, "/usr/lib"))) {
		*cat = AP_CAT_LIB;
		snprintf(why, whycap, "动态加载器（运行必需）");
		return 0;
	}
	if (ap_is_sensitive(p)) {
		*cat = AP_CAT_SENS;
		snprintf(why, whycap, "敏感路径（凭据/内核内存/root 家目录）");
		return 40;
	}
	if (ap_is_under(p, "/etc/ld.so.cache") ||
	    ap_is_under(p, "/etc/ld.so.conf") ||
	    ap_is_under(p, "/etc/ld.so.preload")) {
		if (is_write) {
			*cat = AP_CAT_SENS;
			snprintf(why, whycap,
				 "写 ld.so 配置（可致全系统库劫持）");
			return 40;
		}
		*cat = AP_CAT_ETC;
		snprintf(why, whycap, "加载器缓存/配置（非 ELF 声明）");
		return 1;
	}
	if (ap_is_under(p, "/usr/lib/locale") ||
	    ap_is_under(p, "/usr/share/locale") ||
	    ap_is_under(p, "/usr/lib/terminfo") ||
	    ap_is_under(p, "/usr/share/terminfo") ||
	    ap_is_under(p, "/usr/share/zoneinfo") ||
	    ap_is_under(p, "/usr/share/i18n")) {
		*cat = AP_CAT_OTHER;
		snprintf(why, whycap, "本地化/时区数据（常见运行时读取）");
		return 1;
	}
	if (strcmp(p, "/dev/null") == 0 || strcmp(p, "/dev/zero") == 0 ||
	    strcmp(p, "/dev/full") == 0 ||
	    strcmp(p, "/dev/random") == 0 ||
	    strcmp(p, "/dev/urandom") == 0 ||
	    strncmp(p, "/dev/tty", 8) == 0 ||
	    strcmp(p, "/dev/console") == 0) {
		*cat = AP_CAT_OTHER;
		snprintf(why, whycap, "标准设备节点（常见运行时）");
		return 1;
	}
	if (ap_is_under(p, "/usr/lib") || ap_is_under(p, "/lib") ||
	    ap_is_under(p, "/lib64") || ap_is_under(p, "/usr/lib64") ||
	    ap_is_under(p, "/usr/local/lib")) {
		*cat = AP_CAT_LIB;
		if (is_write) {
			snprintf(why, whycap,
				 "写系统库目录（可致库劫持）");
			return 30;
		}
		snprintf(why, whycap,
			 "系统库目录下的未声明库（间接依赖或 dlopen）");
		return 2;
	}
	if (ap_is_under(p, "/proc/") || ap_is_under(p, "/sys/")) {
		*cat = AP_CAT_PROC;
		snprintf(why, whycap, is_write ? "写 /proc 或 /sys（异常）" :
			 "读取 /proc 或 /sys（非 ELF 声明）");
		return is_write ? 20 : 1;
	}
	if (ap_is_under(p, "/tmp/") || ap_is_under(p, "/var/tmp/") ||
	    ap_is_under(p, "/dev/shm/")) {
		*cat = is_write ? AP_CAT_WRITE : AP_CAT_OTHER;
		snprintf(why, whycap, is_write ? "写临时目录" :
			 "读临时目录");
		return is_write ? 8 : 2;
	}
	if (ap_is_under(p, "/etc/")) {
		*cat = is_write ? AP_CAT_WRITE : AP_CAT_ETC;
		snprintf(why, whycap, is_write ?
			 "写 /etc 系统配置（未声明，高危）" :
			 "读 /etc 系统配置（非 ELF 声明）");
		return is_write ? 40 : 5;
	}
	if (ap_is_under(p, "/usr/bin/") || ap_is_under(p, "/bin/") ||
	    ap_is_under(p, "/usr/sbin/") || ap_is_under(p, "/sbin/")) {
		*cat = is_write ? AP_CAT_WRITE : AP_CAT_OTHER;
		snprintf(why, whycap, is_write ? "写系统可执行文件（异常）" :
			 "读系统可执行文件（非声明依赖）");
		return is_write ? 40 : 3;
	}
	*cat = is_write ? AP_CAT_WRITE : AP_CAT_OTHER;
	snprintf(why, whycap, is_write ? "未声明的文件写入" :
		 "未声明的文件读取");
	return is_write ? 25 : 5;
}

struct ap_finding {
	char item[AP_EV_PATH + 96];
	char why[256];
	int weight;
	int cat;
};

static void ap_add_finding(struct ap_finding *f, int *n, int max,
			   const char *item, const char *why, int weight,
			   int cat)
{
	int i;

	if (weight <= 0)
		return;
	for (i = 0; i < *n; i++) {
		if (strcmp(f[i].item, item) == 0) {
			if (weight > f[i].weight) {
				f[i].weight = weight;
				f[i].cat = cat;
				snprintf(f[i].why, sizeof(f[i].why), "%s",
					 why);
			}
			return;
		}
	}
	if (*n >= max)
		return;
	snprintf(f[*n].item, sizeof(f[*n].item), "%s", item);
	snprintf(f[*n].why, sizeof(f[*n].why), "%s", why);
	f[*n].weight = weight;
	f[*n].cat = cat;
	(*n)++;
}

static void ap_sort_findings(struct ap_finding *f, int n)
{
	int i, j;

	/* 插入排序：按权重降序（n ≤ 128） */
	for (i = 1; i < n; i++) {
		struct ap_finding key = f[i];

		j = i - 1;
		while (j >= 0 && f[j].weight < key.weight) {
			f[j + 1] = f[j];
			j--;
		}
		f[j + 1] = key;
	}
}

static const char *ap_risk_level(int score)
{
	if (score <= 0) return "无风险";
	if (score < 20) return "低危";
	if (score < 50) return "中危";
	if (score < 80) return "高危";
	return "严重";
}

static const char *ap_cat_name(int c)
{
	switch (c) {
	case AP_CAT_LIB: return "库目录";
	case AP_CAT_ETC: return "配置读取";
	case AP_CAT_NET: return "网络";
	case AP_CAT_SENS: return "敏感/提权";
	case AP_CAT_WRITE: return "写入";
	case AP_CAT_EXEC: return "子进程";
	case AP_CAT_PROC: return "proc/sys";
	case AP_CAT_OTHER: return "其他读取";
	default: return "?";
	}
}

/* 分类封顶后的总分；detail 输出各分类（原始/封顶） */
static int ap_score(const struct ap_finding *f, int fn, char *detail,
		    size_t cap)
{
	int sums[AP_CAT_N] = { 0 };
	int score = 0, c;
	size_t off = 0;

	for (c = 0; c < fn; c++)
		sums[f[c].cat] += f[c].weight;
	for (c = 0; c < AP_CAT_N; c++) {
		int contrib = sums[c] > ap_cat_cap[c] ? ap_cat_cap[c] :
			      sums[c];

		if (sums[c] <= 0)
			continue;
		score += contrib;
		if (off < cap)
			off += (size_t)snprintf(detail + off, cap - off,
						"%s%s %d/%d", off ? "，" : "",
						ap_cat_name(c), contrib,
						ap_cat_cap[c]);
	}
	if (score > 100)
		score = 100;
	if (detail && cap && off == 0)
		detail[0] = '\0';
	return score;
}

static int ap_net_weight(const struct ap_event *e, char *why, size_t cap)
{
	if (e->type == AP_EV_NET_LISTEN) {
		snprintf(why, cap, "监听端口（未声明服务面）");
		return 5;
	}
	if (e->type == AP_EV_NET_UNIX) {
		snprintf(why, cap, "Unix socket 连接（本地 IPC）");
		return 3;
	}
	if (strncmp(e->remote, "127.", 4) == 0 ||
	    strncmp(e->remote, "[::1]", 5) == 0) {
		snprintf(why, cap, "本机回环 connect 尝试（未声明）");
		return 8;
	}
	snprintf(why, cap,
		 "外部网络目标（ELF 无法声明网络意图，需 nft 白名单）");
	return 30;
}

static void ap_collect_findings(const struct ap_static *st,
				const struct ap_event *ev, int ev_n,
				struct ap_finding *find, int *fn,
				int *used_files, int *used_exec, int *used_net)
{
	int i;

	*fn = 0;
	*used_files = 0;
	*used_exec = 0;
	*used_net = 0;
	for (i = 0; i < ev_n; i++) {
		const struct ap_event *e = &ev[i];

		if (e->type == AP_EV_FILE_READ ||
		    e->type == AP_EV_FILE_WRITE ||
		    e->type == AP_EV_FILE_MMAP) {
			char why[256];
			int cat = AP_CAT_OTHER;
			int w = ap_path_weight(st, e->path,
					       e->type == AP_EV_FILE_WRITE,
					       &cat, why, sizeof(why));

			(*used_files)++;
			ap_add_finding(find, fn, 128, e->path, why, w, cat);
		} else if (e->type == AP_EV_PROC_EXEC) {
			if (strcmp(e->path, st->path) == 0)
				continue;
			(*used_exec)++;
			ap_add_finding(find, fn, 128, e->path,
				       "动态 exec 了静态未声明的子进程", 15,
				       AP_CAT_EXEC);
		} else {
			char why[256], item[AP_EV_PATH + 96];
			int w = ap_net_weight(e, why, sizeof(why));

			(*used_net)++;
			snprintf(item, sizeof(item), "net %s %s",
				 e->proto[0] ? e->proto : "inet", e->remote);
			ap_add_finding(find, fn, 128, item, why, w,
				       AP_CAT_NET);
		}
	}
	ap_sort_findings(find, *fn);
}

static void ap_diff_text(const struct ap_static *st,
			 const struct ap_event *ev, int ev_n,
			 const char *dyn_note, struct apb *b)
{
	char lines[64][256];
	int dn = ap_declared_lines(st, lines, 64);
	struct ap_finding find[128];
	int fn = 0, i, score, used_files, used_exec, used_net;
	int unused_n = 0;
	char detail[512] = "";

	ap_collect_findings(st, ev, ev_n, find, &fn, &used_files,
			    &used_exec, &used_net);
	score = ap_score(find, fn, detail, sizeof(detail));

	apb_printf(b, "== 差集风险报告: %s ==\n", st->path);
	apb_printf(b, "[动态输入] %s\n", dyn_note);
	apb_printf(b, "\n[一、要的（静态声明）] %d 项\n", dn);
	for (i = 0; i < dn; i++)
		apb_printf(b, "  + %s\n", lines[i]);
	if (dn == 0)
		apb_printf(b, "  （无 ELF 声明）\n");

	apb_printf(b, "\n[二、用的（动态实际）] 文件 %d / 子进程 %d / 网络 %d\n",
		   used_files, used_exec, used_net);
	for (i = 0; i < ev_n; i++) {
		const struct ap_event *e = &ev[i];

		if (e->type == AP_EV_FILE_READ ||
		    e->type == AP_EV_FILE_WRITE ||
		    e->type == AP_EV_FILE_MMAP)
			apb_printf(b, "  - [%s] %s%s\n",
				   e->type == AP_EV_FILE_WRITE ? "写" :
				   e->type == AP_EV_FILE_MMAP ? "映射" : "读",
				   e->path, e->count > 1 ? " ×N" : "");
		else if (e->type == AP_EV_PROC_EXEC)
			apb_printf(b, "  - [exec] %s\n", e->path);
		else
			apb_printf(b, "  - [%s] %s -> %s [%s]\n", e->proto,
				   e->local[0] ? e->local : "*", e->remote,
				   e->state);
	}

	apb_printf(b, "\n[三、偷偷碰的（动态出现但静态没声明）] %d 项\n",
		   fn);
	for (i = 0; i < fn; i++)
		apb_printf(b, "  ! [%d] %s — %s\n", find[i].weight,
			   find[i].item, find[i].why);
	if (fn == 0)
		apb_printf(b, "  （无：动态行为均可由静态声明解释）\n");

	/* 声明未用 */
	if (st->has_dyn) {
		for (i = 0; i < st->dyn.needed_n; i++) {
			int j, seen = 0;

			for (j = 0; j < ev_n; j++) {
				if ((ev[j].type == AP_EV_FILE_READ ||
				     ev[j].type == AP_EV_FILE_MMAP) &&
				    strcmp(ap_base(ev[j].path),
					   ap_base(st->dyn.needed[i])) == 0) {
					seen = 1;
					break;
				}
			}
			if (!seen) {
				if (unused_n == 0)
					apb_printf(b,
						   "\n[声明但本次未用]\n");
				apb_printf(b, "  - %s\n",
					   st->dyn.needed[i]);
				unused_n++;
			}
		}
	}

	apb_printf(b, "\n[风险分] %d/100（%s）%s%s\n", score,
		   ap_risk_level(score), detail[0] ? " 分类：" : "",
		   detail);
	apb_printf(b, "[放行条件建议]\n");
	{
		int c = 0;
		int has_net = 0, has_write = 0, has_sensitive = 0;
		int has_other = 0;

		for (i = 0; i < fn; i++) {
			if (find[i].cat == AP_CAT_NET)
				has_net = 1;
			else if (find[i].cat == AP_CAT_WRITE)
				has_write = 1;
			else if (find[i].cat == AP_CAT_SENS)
				has_sensitive = 1;
			else
				has_other = 1;
		}
		if (score == 0) {
			apb_printf(b, "  1. 动态行为可由静态声明解释：可按 "
				   "D0/D1 放行；保持 workspace 隔离 + "
				   "net=none。\n");
		}
		if (has_sensitive || st->setuid || st->caps_decoded[0]) {
			apb_printf(b, "  %d. 敏感路径/setuid/文件能力：运行需 "
				   "D3 显式授权并单独评审；建议丢弃能力后"
				   "降权运行。\n", ++c);
		}
		if (has_net) {
			apb_printf(b, "  %d. 网络目标未声明：在 nft 白名单显式"
				   "放行（nft_intent_compile 生成规则，D3 "
				   "授权后 nft_intent_apply）；否则保持 "
				   "net=none。\n", ++c);
		}
		if (has_write) {
			apb_printf(b, "  %d. 写入路径未声明：只允许 workspace "
				   "rw-path（workspace_create 显式声明）或 "
				   "W1 租约；/etc、/usr 写入一律拒绝。\n",
				   ++c);
		}
		if (has_other) {
			apb_printf(b, "  %d. 未声明文件/子进程（含间接依赖库、"
				   "/etc 配置读取）：只读访问可按 D0/D1 "
				   "放行；需禁止时用 BPF LSM file_open "
				   "路径拦截。\n", ++c);
		}
		if (st->dyn.runpath_n > 0 || st->dyn.rpath_n > 0)
			apb_printf(b, "  %d. RUNPATH/RPATH 非空：消除搜索路径"
				   "或固定系统目录（防库劫持）。\n", ++c);
		if (st->dyn.textrel)
			apb_printf(b, "  %d. 含 TEXTREL：拒绝该构建（可写"
				   "代码段）。\n", ++c);
		if (!st->pkg_found)
			apb_printf(b, "  %d. 无包归属：要求提供 sha256/签名"
				   "后再放行。\n", ++c);
		if (c == 0 && score > 0)
			apb_printf(b, "  %d. 按发现项逐条确认后放行。\n",
				   ++c);
		apb_printf(b, "  %d. 本报告只给建议：不写 nft、不改权限、"
			   "不执行任何策略。\n", ++c);
	}
}

static void ap_diff_json(const struct ap_static *st,
			 const struct ap_event *ev, int ev_n,
			 const char *dyn_note, struct apb *b)
{
	char lines[64][256];
	int dn = ap_declared_lines(st, lines, 64);
	struct ap_finding find[128];
	int fn = 0, i, score, used_files, used_exec, used_net;
	char detail[512] = "";

	ap_collect_findings(st, ev, ev_n, find, &fn, &used_files,
			    &used_exec, &used_net);
	score = ap_score(find, fn, detail, sizeof(detail));

	apb_printf(b, "{\"tool\":\"app_profile_diff\",\"path\":");
	apb_json_str(b, st->path);
	apb_printf(b, ",\"dynamic\":");
	apb_json_str(b, dyn_note);
	apb_printf(b, ",\"declared\":[");
	for (i = 0; i < dn; i++) {
		if (i)
			apb_printf(b, ",");
		apb_json_str(b, lines[i]);
	}
	apb_printf(b, "],\"used\":[");
	for (i = 0; i < ev_n; i++) {
		const struct ap_event *e = &ev[i];

		if (i)
			apb_printf(b, ",");
		apb_printf(b, "{\"type\":\"%s\"", ap_ev_type_name(e->type));
		if (e->type == AP_EV_FILE_READ ||
		    e->type == AP_EV_FILE_WRITE ||
		    e->type == AP_EV_FILE_MMAP ||
		    e->type == AP_EV_PROC_EXEC) {
			apb_printf(b, ",\"path\":");
			apb_json_str(b, e->path);
		} else {
			apb_printf(b, ",\"proto\":");
			apb_json_str(b, e->proto);
			apb_printf(b, ",\"local\":");
			apb_json_str(b, e->local);
			apb_printf(b, ",\"remote\":");
			apb_json_str(b, e->remote);
			apb_printf(b, ",\"state\":");
			apb_json_str(b, e->state);
		}
		apb_printf(b, "}");
	}
	apb_printf(b, "],\"unexpected\":[");
	for (i = 0; i < fn; i++) {
		if (i)
			apb_printf(b, ",");
		apb_printf(b, "{\"item\":");
		apb_json_str(b, find[i].item);
		apb_printf(b, ",\"why\":");
		apb_json_str(b, find[i].why);
		apb_printf(b, ",\"category\":\"%s\"", ap_cat_name(find[i].cat));
		apb_printf(b, ",\"weight\":%d}", find[i].weight);
	}
	apb_printf(b, "],\"risk_score\":%d,\"risk_level\":", score);
	apb_json_str(b, ap_risk_level(score));
	apb_printf(b, ",\"risk_detail\":");
	apb_json_str(b, detail);
	apb_printf(b, ",\"stats\":{\"events\":%d,\"used_files\":%d,"
		   "\"used_exec\":%d,\"used_net\":%d,\"unexpected\":%d}}",
		   ev_n, used_files, used_exec, used_net, fn);
}
/* ======================================================================
 * 5) 工具入口与分发
 * ====================================================================== */

#define AP_OUT_STATIC	(256 * 1024)
#define AP_OUT_DYNAMIC	(512 * 1024)
#define AP_OUT_DIFF	(512 * 1024)

static int ap_tool_static(const char *args, char **out)
{
	char *path = ap_arg_str(args, "path");
	char *fmt = ap_arg_str(args, "format");
	struct ap_static *st;
	char err[512] = "";
	char *buf;
	struct apb b;
	int json = fmt && strcmp(fmt, "json") == 0;

	*out = NULL;
	if (!path || !path[0]) {
		if (asprintf(out, "ERROR: 缺少 path（目标可执行文件绝对路径）")
		    < 0)
			*out = NULL;
		free(path);
		free(fmt);
		return AI_ERR_INVALID_ARG;
	}
	st = calloc(1, sizeof(*st));
	buf = malloc(AP_OUT_STATIC);
	if (!st || !buf) {
		free(st);
		free(buf);
		free(path);
		free(fmt);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	if (ap_static_collect(path, st, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 静态画像失败：%s", err) < 0)
			*out = NULL;
		free(st);
		free(buf);
		free(path);
		free(fmt);
		return AI_ERR_NOT_FOUND;
	}
	apb_init(&b, buf, AP_OUT_STATIC);
	if (json)
		ap_static_render_json(st, &b);
	else
		ap_static_render_text(st, &b);
	if (b.trunc)
		apb_printf(&b, "\n[警告] 输出超过 %d 字节，已截断\n",
			   AP_OUT_STATIC);
	*out = buf;
	free(st);
	free(path);
	free(fmt);
	return AI_OK;
}

static int ap_tool_dynamic(const char *args, char **out)
{
	char *path = ap_arg_str(args, "path");
	char *ws = ap_arg_str(args, "workspace");
	char *mode = ap_arg_str(args, "mode");
	char *net = ap_arg_str(args, "net");
	char *fmt = ap_arg_str(args, "format");
	char *argv[16];
	int argc = 0;
	char real[PATH_MAX];
	char err[512] = "";
	char *werr = NULL;
	char msbuf[16], tbuf[16];
	char *sargv[40];
	int sn = 0, i, wr, created = 0;
	int actual_net_none = 1;
	char backing[16] = "tmpfs";
	long long timeout_s = ap_arg_ll(args, "timeout_s", 10);
	long long sample_ms = ap_arg_ll(args, "sample_ms", 50);
	int cleanup = ap_arg_bool(args, "cleanup", 0);
	int net_none = !(net && strcmp(net, "host") == 0);
	int json = !(fmt && strcmp(fmt, "text") == 0);
	char *tail = NULL;
	int exit_code = 0, timed_out = 0, truncated = 0;
	struct ap_runres r;
	struct timespec ts0, ts1;
	long long elapsed_ms;
	char *buf;
	struct apb b;
	const char *modestr = mode && mode[0] ? mode : "auto";

	*out = NULL;
	if (!path || !path[0]) {
		if (asprintf(out, "ERROR: 缺少 path（目标可执行文件绝对路径）")
		    < 0)
			*out = NULL;
		goto fail_args;
	}
	if (sample_ms < 20 || sample_ms > 1000)
		sample_ms = 50;
	if (timeout_s < 1 || timeout_s > 60)
		timeout_s = 10;
	if (strcmp(modestr, "auto") != 0 && strcmp(modestr, "strace") != 0 &&
	    strcmp(modestr, "proc") != 0) {
		if (asprintf(out, "ERROR: mode 只允许 auto|strace|proc") < 0)
			*out = NULL;
		goto fail_args;
	}
	if (!ws || !ws[0]) {
		free(ws);
		ws = strdup("appprofile");
	}
	if (!ai_ws_valid_name(ws)) {
		if (asprintf(out, "ERROR: 非法工作区名 workspace='%s'",
			     ws ? ws : "(无)") < 0)
			*out = NULL;
		goto fail_args;
	}
	if (ap_resolve_path(path, real, sizeof(real)) != 0) {
		if (asprintf(out, "ERROR: 目标不存在或不可执行：%s", path) < 0)
			*out = NULL;
		goto fail_args;
	}
	if (ap_target_allowed(real, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: %s", err) < 0)
			*out = NULL;
		goto fail_args;
	}
	argc = ap_arg_argv(args, argv, 16, err, sizeof(err));
	if (argc < 0) {
		if (asprintf(out, "ERROR: %s", err) < 0)
			*out = NULL;
		goto fail_args;
	}
	if (ap_arg_allowed(ap_base(real), argv, argc, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 参数被白名单拒绝：%s", err) < 0)
			*out = NULL;
		goto fail_args;
	}

	wr = ai_ws_ensure(ws, net_none, 64, &werr, &created);
	if (wr != AI_OK) {
		if (asprintf(out, "ERROR: 无法准备工作区 '%s'：%s\n提示：动态"
			     "画像必须在 workspace 沙盒里跑，需要 root + "
			     "loop/mkfs + %s", ws,
			     werr ? werr : "未知错误",
			     "/usr/local/bin/aik-sandbox") < 0)
			*out = NULL;
		free(werr);
		goto fail_args;
	}
	free(werr);
	werr = NULL;
	if (ai_ws_meta_net(ws, &actual_net_none, backing,
			   sizeof(backing)) != 0) {
		actual_net_none = net_none;
		snprintf(backing, sizeof(backing), "unknown");
	}

	snprintf(msbuf, sizeof(msbuf), "%lld", sample_ms);
	snprintf(tbuf, sizeof(tbuf), "%lld", timeout_s);
	sargv[sn++] = (char *)"/bin/sh";
	sargv[sn++] = (char *)"-c";
	sargv[sn++] = (char *)AP_TRACER_SCRIPT;
	sargv[sn++] = (char *)"aikprof";
	sargv[sn++] = real;
	sargv[sn++] = msbuf;
	sargv[sn++] = (char *)modestr;
	sargv[sn++] = tbuf;
	for (i = 0; i < argc; i++)
		sargv[sn++] = argv[i];
	sargv[sn] = NULL;

	clock_gettime(CLOCK_MONOTONIC, &ts0);
	wr = ai_ws_run_argv(ws, sargv, sn, (int)timeout_s + 8, &tail,
			    &exit_code, &timed_out, &truncated, &werr);
	clock_gettime(CLOCK_MONOTONIC, &ts1);
	elapsed_ms = (long long)(ts1.tv_sec - ts0.tv_sec) * 1000 +
		     (ts1.tv_nsec - ts0.tv_nsec) / 1000000;
	if (wr != AI_OK) {
		if (asprintf(out, "ERROR: 工作区执行失败：%s",
			     werr ? werr : "未知错误") < 0)
			*out = NULL;
		free(werr);
		free(tail);
		goto fail_args;
	}
	free(werr);
	if (ap_runres_init(&r) != 0) {
		free(tail);
		*out = strdup("ERROR: 内存不足（事件表）");
		goto fail_args;
	}
	ap_parse_tsv(tail, &r);
	if (timed_out)
		ap_run_warn(&r, "外层沙盒超时（%lld+8s）被强杀：事件流可能"
			    "不完整", timeout_s);
	if (truncated)
		ap_run_warn(&r, "工作区输出超过 256KB：仅保留尾部");
	if (r.exit_code == 97 && !r.mode[0])
		ap_run_warn(&r, "沙盒内临时目录创建失败（/tmp 不可写）");
	if (!actual_net_none)
		ap_run_warn(&r, "工作区已存在且 net=host（未改动）：目标具备"
			    "宿主网络视图，如需隔离请先 workspace_destroy");

	buf = malloc(AP_OUT_DYNAMIC);
	if (!buf) {
		ap_runres_free(&r);
		free(tail);
		*out = strdup("ERROR: 内存不足（输出缓冲）");
		goto fail_args;
	}
	apb_init(&b, buf, AP_OUT_DYNAMIC);
	if (json)
		ap_dynamic_render_json(real, argv, argc, ws, backing,
				       actual_net_none, elapsed_ms, &r, &b);
	else
		ap_dynamic_render_text(real, argv, argc, ws, backing,
				       actual_net_none, elapsed_ms, &r, &b);
	if (b.trunc)
		apb_printf(&b, "\n[警告] 输出超过 %d 字节，已截断\n",
			   AP_OUT_DYNAMIC);
	*out = buf;
	ap_runres_free(&r);
	free(tail);
	free(werr);
	if (cleanup && created) {
		char *cerr = NULL;

		ai_ws_destroy(ws, &cerr);
		free(cerr);
	}
	for (i = 0; i < argc; i++)
		free(argv[i]);
	free(path);
	free(ws);
	free(mode);
	free(net);
	free(fmt);
	return AI_OK;

fail_args:
	for (i = 0; i < argc; i++)
		free(argv[i]);
	free(path);
	free(ws);
	free(mode);
	free(net);
	free(fmt);
	if (!*out)
		*out = strdup("ERROR: 动态画像参数错误");
	return AI_ERR_INVALID_ARG;
}

static int ap_tool_diff(const char *args, char **out)
{
	char *path = ap_arg_str(args, "path");
	char *dynamic = ap_arg_str(args, "dynamic");
	char *fmt = ap_arg_str(args, "format");
	struct ap_static *st;
	struct ap_event *ev;
	char err[512] = "";
	int n = 0, truncated = 0, rc, json;
	char *buf;
	struct apb b;

	*out = NULL;
	if (!path || !path[0]) {
		if (asprintf(out, "ERROR: 缺少 path（目标可执行文件）") < 0)
			*out = NULL;
		free(path);
		free(dynamic);
		free(fmt);
		return AI_ERR_INVALID_ARG;
	}
	if (!dynamic || !dynamic[0]) {
		if (asprintf(out, "ERROR: 缺少 dynamic（app_profile_dynamic "
			     "的 JSON 输出，format=json）") < 0)
			*out = NULL;
		free(path);
		free(dynamic);
		free(fmt);
		return AI_ERR_INVALID_ARG;
	}
	if (strlen(dynamic) > 512 * 1024) {
		if (asprintf(out, "ERROR: dynamic 超过 512KB 上限") < 0)
			*out = NULL;
		free(path);
		free(dynamic);
		free(fmt);
		return AI_ERR_INVALID_ARG;
	}
	json = fmt && strcmp(fmt, "json") == 0;
	st = calloc(1, sizeof(*st));
	ev = calloc(AP_MAX_EVENTS, sizeof(*ev));
	buf = malloc(AP_OUT_DIFF);
	if (!st || !ev || !buf) {
		free(st);
		free(ev);
		free(buf);
		free(path);
		free(dynamic);
		free(fmt);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	if (ap_static_collect(path, st, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 静态画像失败：%s", err) < 0)
			*out = NULL;
		free(st);
		free(ev);
		free(buf);
		free(path);
		free(dynamic);
		free(fmt);
		return AI_ERR_NOT_FOUND;
	}
	rc = ap_dynamic_json_to_events(dynamic, ev, AP_MAX_EVENTS, &n,
				       &truncated, err, sizeof(err));
	if (rc != 0) {
		if (asprintf(out, "ERROR: 动态事件流解析失败：%s", err) < 0)
			*out = NULL;
		free(st);
		free(ev);
		free(buf);
		free(path);
		free(dynamic);
		free(fmt);
		return AI_ERR_INVALID_ARG;
	}
	apb_init(&b, buf, AP_OUT_DIFF);
	if (truncated)
		apb_printf(&b, "[警告] 动态事件超过 %d 条，仅分析前 %d 条\n",
			   AP_MAX_EVENTS, n);
	if (json)
		ap_diff_json(st, ev, n, "app_profile_dynamic", &b);
	else
		ap_diff_text(st, ev, n, "app_profile_dynamic", &b);
	*out = buf;
	free(st);
	free(ev);
	free(path);
	free(dynamic);
	free(fmt);
	return AI_OK;
}

int exec_app_profile_channel(const void *tool_v, const char *args_json,
			     char **out)
{
	const struct ai_tool *tool = tool_v;

	*out = NULL;
	if (!tool || !tool->name || !args_json) {
		*out = strdup("ERROR: appprofile 调用参数为空");
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(tool->name, "app_profile_static") == 0)
		return ap_tool_static(args_json, out);
	if (strcmp(tool->name, "app_profile_dynamic") == 0)
		return ap_tool_dynamic(args_json, out);
	if (strcmp(tool->name, "app_profile_diff") == 0)
		return ap_tool_diff(args_json, out);
	if (asprintf(out, "ERROR: 未知 appprofile 工具（注册表异常）") < 0)
		*out = NULL;
	return AI_ERR_INVALID_ARG;
}
