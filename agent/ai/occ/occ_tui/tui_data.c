/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_data.c - /tools /trace /lease 读取器实现（T9c3）
 *
 * 纯文件解析（aik_json DOM），产出 tui_ov_item 数组（heap，调用方 free：
 * tui_data_items_free）。单条坏记录跳过计数不炸；目录 ENOENT 按空。
 * 详情/文本统一 UTF-8 安全截断（不切多字节，尾补 …）。
 */
#define _DEFAULT_SOURCE 1
#include "tui_data.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "store/store_json.h"

#define TD_TOOLS_MAX (32u * 1024u * 1024u)
#define TD_LINE_MAX 8192
#define TD_TAIL_BYTES (256 * 1024)
#define TD_LEASE_MAX (64 * 1024)

/* ---- 通用 ---- */

void tui_data_items_free(tui_ov_item *items)
{
	free(items);
}

static void set_trunc(char *dst, size_t cap, const char *src)
{
	size_t l;
	size_t n;

	if (!dst || cap == 0)
		return;
	if (!src)
		src = "";
	l = strlen(src);
	if (l + 1 <= cap) {
		memcpy(dst, src, l + 1);
		return;
	}
	if (cap < 5) {
		memcpy(dst, src, cap - 1);
		dst[cap - 1] = '\0';
		return;
	}
	n = cap - 4;
	memcpy(dst, src, n);
	while (n > 0 && ((unsigned char)dst[n] & 0xC0) == 0x80)
		n--;
	dst[n] = '\xE2';
	dst[n + 1] = '\x80';
	dst[n + 2] = '\xA6';
	dst[n + 3] = '\0';
}

static char *read_file(const char *path, size_t max, size_t *len_out,
		       char *err, size_t errlen)
{
	struct stat st;
	FILE *f;
	char *buf;
	size_t got;

	if (len_out)
		*len_out = 0;
	/* stat 而非 lstat：系统数据文件可为符号链接（repo 的 tools.json
	 * → tools/tools.json）；目录级 symlink 拒收在调用方（lease/trace
	 * 各自 lstat 过滤），此处只保证「可达的普通文件」。 */
	if (stat(path, &st) != 0) {
		if (err)
			snprintf(err, errlen, "打不开 %.160s: %s", path,
				 strerror(errno));
		return NULL;
	}
	if (!S_ISREG(st.st_mode)) {
		if (err)
			snprintf(err, errlen, "非普通文件 %.160s", path);
		return NULL;
	}
	if ((unsigned long long)st.st_size > (unsigned long long)max) {
		if (err)
			snprintf(err, errlen, "文件过大 %.160s (%llu B)",
				 path, (unsigned long long)st.st_size);
		return NULL;
	}
	f = fopen(path, "rb");
	if (!f) {
		if (err)
			snprintf(err, errlen, "打不开 %.160s: %s", path,
				 strerror(errno));
		return NULL;
	}
	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		fclose(f);
		if (err)
			snprintf(err, errlen, "OOM reading %.160s", path);
		return NULL;
	}
	got = fread(buf, 1, (size_t)st.st_size, f);
	fclose(f);
	buf[got] = '\0';
	if (len_out)
		*len_out = got;
	return buf;
}

static int readable(const char *p)
{
	return p && p[0] && access(p, R_OK) == 0;
}

static int exe_dir(char *buf, size_t cap)
{
	char tmp[4096];
	ssize_t n = readlink("/proc/self/exe", tmp, sizeof(tmp) - 1);
	char *slash;

	if (n <= 0)
		return -1;
	tmp[n] = '\0';
	slash = strrchr(tmp, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	if (strlen(tmp) + 1 > cap)
		return -1;
	memcpy(buf, tmp, strlen(tmp) + 1);
	return 0;
}

/* items 动态数组 */
struct td_vec {
	tui_ov_item *v;
	int n, cap;
};

static int td_push(struct td_vec *vec, const char *text, const char *tag,
		   const char *detail, int flags)
{
	tui_ov_item *it;

	if (vec->n >= vec->cap) {
		int nc = vec->cap ? vec->cap * 2 : 64;
		tui_ov_item *nv = realloc(vec->v, (size_t)nc * sizeof(*nv));

		if (!nv)
			return -1;
		vec->v = nv;
		vec->cap = nc;
	}
	it = &vec->v[vec->n++];
	memset(it, 0, sizeof(*it));
	set_trunc(it->text, sizeof(it->text), text);
	set_trunc(it->tag, sizeof(it->tag), tag);
	set_trunc(it->detail, sizeof(it->detail), detail);
	it->flags = flags;
	return 0;
}

/* ---- tools.json ---- */

int tui_data_tools_path(char *buf, size_t cap)
{
	const char *env = getenv("AIKERNEL_TOOLS_JSON");
	static const char *const fixed[] = {
		"tools.json",
		"tools/tools.json",
		"/usr/local/share/aikernel/tools.json",
		NULL
	};
	char exed[1024];
	char exejson[1120];
	int i;

	if (env && env[0]) {
		if (!readable(env))
			return -1;	/* 显式配置坏：响亮失败不静默回退 */
		if (strlen(env) + 1 > cap)
			return -1;
		memcpy(buf, env, strlen(env) + 1);
		return 0;
	}
	if (exe_dir(exed, sizeof(exed)) == 0) {
		snprintf(exejson, sizeof(exejson), "%s/tools.json", exed);
		if (readable(exejson)) {
			if (strlen(exejson) + 1 > cap)
				return -1;
			memcpy(buf, exejson, strlen(exejson) + 1);
			return 0;
		}
	}
	for (i = 0; fixed[i]; i++) {
		if (readable(fixed[i])) {
			if (strlen(fixed[i]) + 1 > cap)
				return -1;
			memcpy(buf, fixed[i], strlen(fixed[i]) + 1);
			return 0;
		}
	}
	return -1;
}

static int push_tool_arr(struct td_vec *vec, const aik_json *arr)
{
	size_t i, n;

	if (!arr || aik_json_typeof(arr) != AIK_JSON_ARR)
		return 0;
	n = aik_json_count(arr);
	for (i = 0; i < n; i++) {
		const aik_json *t = aik_json_at(arr, i);
		const aik_json *v;
		char tag[80];
		const char *name, *ch, *risk, *desc;

		if (!t || aik_json_typeof(t) != AIK_JSON_OBJ)
			continue;
		v = aik_json_get(t, "name");
		name = v ? aik_json_str(v) : NULL;
		if (!name || !name[0])
			continue;
		v = aik_json_get(t, "channel");
		ch = v ? aik_json_str(v) : "-";
		v = aik_json_get(t, "risk");
		risk = v ? aik_json_str(v) : "-";
		v = aik_json_get(t, "description");
		desc = v ? aik_json_str(v) : "";
		snprintf(tag, sizeof(tag), "%s · %s", ch ? ch : "-",
			 risk ? risk : "-");
		if (td_push(vec, name, tag, desc, 0) != 0)
			return -1;
	}
	return 0;
}

int tui_data_tools_load(const char *path, tui_ov_item **out, int *n,
			char *err, size_t errlen)
{
	struct td_vec vec = { NULL, 0, 0 };
	char *buf;
	size_t len;
	char jerr[160];
	aik_json *root;
	const aik_json *occ, *main;
	size_t nocc = 0, nmain = 0;
	char hdr[80];

	if (err && errlen)
		err[0] = '\0';
	if (out)
		*out = NULL;
	if (n)
		*n = 0;
	if (!path || !out || !n) {
		if (err)
			snprintf(err, errlen, "tools: bad args");
		return -1;
	}
	buf = read_file(path, TD_TOOLS_MAX, &len, err, errlen);
	if (!buf)
		return -1;
	jerr[0] = '\0';
	root = aik_json_parse(buf, len, jerr, sizeof(jerr));
	free(buf);
	if (!root) {
		if (err)
			snprintf(err, errlen, "tools.json 解析失败: %.100s",
				 jerr);
		return -1;
	}
	occ = aik_json_get(root, "occ_tools");
	if (occ)
		occ = aik_json_get(occ, "tools");
	main = aik_json_get(root, "tools");
	if ((!occ || aik_json_typeof(occ) != AIK_JSON_ARR) &&
	    (!main || aik_json_typeof(main) != AIK_JSON_ARR)) {
		if (err)
			snprintf(err, errlen,
				 "tools.json 无 tools/occ_tools.tools 数组");
		aik_json_free(root);
		return -1;
	}
	if (occ && aik_json_typeof(occ) == AIK_JSON_ARR)
		nocc = aik_json_count(occ);
	if (main && aik_json_typeof(main) == AIK_JSON_ARR)
		nmain = aik_json_count(main);

	if (nocc) {
		snprintf(hdr, sizeof(hdr), "occ 六件套（%zu）", nocc);
		if (td_push(&vec, hdr, "", "", TUI_OV_HEADER) != 0)
			goto oom;
		if (push_tool_arr(&vec, occ) != 0)
			goto oom;
	}
	if (nmain) {
		snprintf(hdr, sizeof(hdr), "内核工具注册表（%zu）", nmain);
		if (td_push(&vec, hdr, "", "", TUI_OV_HEADER) != 0)
			goto oom;
		if (push_tool_arr(&vec, main) != 0)
			goto oom;
	}
	aik_json_free(root);
	*out = vec.v;
	*n = vec.n;
	return 0;
oom:
	if (err)
		snprintf(err, errlen, "tools: OOM");
	aik_json_free(root);
	free(vec.v);
	return -1;
}

/* ---- trace ---- */

struct tr_file {
	char path[1280];
	time_t mtime;
};

static int tr_cmp(const void *a, const void *b)
{
	const struct tr_file *x = a, *y = b;

	if (x->mtime > y->mtime)
		return -1;
	if (x->mtime < y->mtime)
		return 1;
	return 0;
}

int tui_data_trace_dir(char *buf, size_t cap)
{
	const char *env = getenv("OCC_TRACE_DIR");
	const char *home;
	char def[1024];

	if (env && env[0]) {
		if (strlen(env) + 1 > cap)
			return -1;
		memcpy(buf, env, strlen(env) + 1);
		return 0;
	}
	home = getenv("HOME");
	if (!home || !home[0])
		return -1;
	snprintf(def, sizeof(def), "%s/.occ/trace", home);
	if (strlen(def) + 1 > cap)
		return -1;
	memcpy(buf, def, strlen(def) + 1);
	return 0;
}

/* 读一个 trace 文件的尾部行（>TD_TAIL_BYTES 时跳过首个残行），逐行回调
 * （newest-first：文件内倒序）。返回推入条数；-1=alloc 失败。 */
static int tr_scan_file(const char *path, int max_lines, struct td_vec *vec,
			int *skipped)
{
	char *buf;
	size_t len = 0;
	char err[160];
	size_t start = 0;
	char *lines[4096];
	int nlines = 0;
	int i, pushed = 0;
	struct stat st;

	if (max_lines <= 0)
		max_lines = 200;
	buf = read_file(path, (size_t)TD_TAIL_BYTES + 1, &len, err,
			sizeof(err));
	(void)err;
	if (!buf) {
		/* 大文件：只读尾窗 */
		if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
			return 0;
		{
			FILE *f = fopen(path, "rb");
			long long off;

			if (!f)
				return 0;
			off = (long long)st.st_size - TD_TAIL_BYTES;
			if (off < 0)
				off = 0;
			if (fseek(f, (long)off, SEEK_SET) != 0) {
				fclose(f);
				return 0;
			}
			buf = malloc(TD_TAIL_BYTES + 1);
			if (!buf) {
				fclose(f);
				return -1;
			}
			len = fread(buf, 1, TD_TAIL_BYTES, f);
			fclose(f);
			buf[len] = '\0';
			if (off > 0) {
				char *nl = strchr(buf, '\n');

				if (nl)
					start = (size_t)(nl - buf + 1);
			}
		}
	}
	/* 切行（限制在 4096 行内——尾窗足够） */
	{
		size_t i2 = start;

		while (i2 < len && nlines < 4096) {
			size_t j = i2;

			while (j < len && buf[j] != '\n')
				j++;
			if (j > i2) {
				size_t l = j - i2;
				char *cp = malloc(l + 1);

				if (!cp) {
					free(buf);
					return -1;
				}
				memcpy(cp, buf + i2, l);
				cp[l] = '\0';
				lines[nlines++] = cp;
			}
			i2 = j + 1;
		}
	}
	free(buf);
	/* 倒序（新在前）推入，直到总量够；每行用完即 free（含跳过行） */
	{
		int oom = 0;

		for (i = nlines - 1; i >= 0 && vec->n < max_lines; i--) {
			char *line = lines[i];
			char jerr[96];
			aik_json *o = aik_json_parse(line, strlen(line),
						     jerr, sizeof(jerr));
			const aik_json *v;
			const char *ts, *tool, *session, *args;
			char when[32];
			char text[TUI_OV_TEXT_MAX];
			long long rc = 0, dur = 0;

			if (!o) {
				(*skipped)++;
				free(line);
				continue;
			}
			v = aik_json_get(o, "ts");
			ts = v ? aik_json_str(v) : NULL;
			v = aik_json_get(o, "tool");
			tool = v ? aik_json_str(v) : "?";
			v = aik_json_get(o, "session");
			session = v ? aik_json_str(v) : "";
			v = aik_json_get(o, "args");
			args = v ? aik_json_str(v) : "";
			v = aik_json_get(o, "rc");
			rc = v ? aik_json_int(v) : 0;
			v = aik_json_get(o, "dur_ms");
			dur = v ? aik_json_int(v) : 0;
			/* ts "2026-11-07T12:34:56.789+0800" → "12:34:56" */
			when[0] = '\0';
			if (ts) {
				const char *tp = strchr(ts, 'T');

				if (tp && strlen(tp) >= 9)
					snprintf(when, sizeof(when), "%.8s",
						 tp + 1);
				else
					snprintf(when, sizeof(when), "%.24s",
						 ts);
			}
			snprintf(text, sizeof(text), "%s %s rc=%lld %lldms",
				 when[0] ? when : "--:--:--", tool, rc, dur);
			if (td_push(vec, text, session, args, 0) != 0) {
				aik_json_free(o);
				free(line);
				oom = 1;
				i--;
				break;
			}
			pushed++;
			aik_json_free(o);
			free(line);
		}
		/* 收尾：释放未处理的剩余行（含 OOM 中断点之后） */
		for (; i >= 0; i--)
			free(lines[i]);
		if (oom)
			return -1;
	}
	return pushed;
}

int tui_data_trace_load(const char *dir, int max_lines, tui_ov_item **out,
			int *n, char *err, size_t errlen)
{
	struct td_vec vec = { NULL, 0, 0 };
	DIR *d;
	struct dirent *de;
	struct tr_file files[128];
	int nfiles = 0;
	int i, skipped = 0;

	if (err && errlen)
		err[0] = '\0';
	if (out)
		*out = NULL;
	if (n)
		*n = 0;
	if (!dir || !out || !n) {
		if (err)
			snprintf(err, errlen, "trace: bad args");
		return -1;
	}
	d = opendir(dir);
	if (!d) {
		if (errno == ENOENT)
			return 0;	/* 无目录=无记录（空） */
		if (err)
			snprintf(err, errlen, "trace 目录 %.160s: %s", dir,
				 strerror(errno));
		return -1;
	}
	while ((de = readdir(d)) != NULL && nfiles < 128) {
		size_t l = strlen(de->d_name);
		char path[1200];
		struct stat st;

		if (l < 7 || strcmp(de->d_name + l - 6, ".jsonl") != 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
			continue;
		snprintf(files[nfiles].path, sizeof(files[nfiles].path), "%s",
			 path);
		files[nfiles].mtime = st.st_mtime;
		nfiles++;
	}
	closedir(d);
	if (nfiles > 1)
		qsort(files, (size_t)nfiles, sizeof(files[0]), tr_cmp);
	for (i = 0; i < nfiles && vec.n < max_lines; i++) {
		int got = tr_scan_file(files[i].path, max_lines, &vec,
				       &skipped);

		if (got < 0) {
			if (err)
				snprintf(err, errlen, "trace: OOM");
			free(vec.v);
			return -1;
		}
	}
	*out = vec.v;
	*n = vec.n;
	return 0;
}

/* ---- lease ---- */

struct ls_ent {
	tui_ov_item it;
	int rank;		/* 0=valid 1=expired 2=revoked */
	long long expires;
};

static int ls_cmp(const void *a, const void *b)
{
	const struct ls_ent *x = a, *y = b;

	if (x->rank != y->rank)
		return x->rank - y->rank;
	if (x->expires > y->expires)
		return -1;
	if (x->expires < y->expires)
		return 1;
	return 0;
}

int tui_data_lease_dir(char *buf, size_t cap)
{
	const char *env = getenv("AIKERNEL_LEASE_DIR");
	static const char def[] = "/var/lib/aikernel/leases";
	const char *use = (env && env[0]) ? env : def;

	if (strlen(use) + 1 > cap)
		return -1;
	memcpy(buf, use, strlen(use) + 1);
	return 0;
}

int tui_data_lease_load(const char *dir, tui_ov_item **out, int *n,
			char *err, size_t errlen)
{
	DIR *d;
	struct dirent *de;
	struct ls_ent *ents = NULL;
	int nents = 0, cap = 0;
	long long now;
	int i;

	if (err && errlen)
		err[0] = '\0';
	if (out)
		*out = NULL;
	if (n)
		*n = 0;
	if (!dir || !out || !n) {
		if (err)
			snprintf(err, errlen, "lease: bad args");
		return -1;
	}
	d = opendir(dir);
	if (!d) {
		if (errno == ENOENT)
			return 0;	/* 未签发过租约 */
		if (err)
			snprintf(err, errlen, "lease 目录 %.160s: %s", dir,
				 strerror(errno));
		return -1;
	}
	now = (long long)time(NULL);
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name);
		char path[1200], mark[272];
		struct stat st;
		char *buf2;
		size_t len = 0;
		char jerr[96];
		aik_json *o;
		const aik_json *v;
		const char *lid = NULL, *mission = NULL;
		long long exp = 0;
		int revoked = 0;
		struct ls_ent *e;
		char remain[48];
		char scope[96];
		size_t si, sn;

		if (l < 6 || strcmp(de->d_name + l - 5, ".json") != 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
			continue;	/* 拒符号链接（展示级校验） */
		/* 撤销标记 <id>.revoked */
		snprintf(mark, sizeof(mark), "%.*s.revoked",
			 (int)(l - 5), de->d_name);
		{
			char mp[1400];

			snprintf(mp, sizeof(mp), "%s/%s", dir, mark);
			if (access(mp, F_OK) == 0)
				revoked = 1;
		}
		buf2 = read_file(path, TD_LEASE_MAX, &len, err, errlen);
		if (!buf2)
			continue;	/* 坏文件跳过 */
		jerr[0] = '\0';
		o = aik_json_parse(buf2, len, jerr, sizeof(jerr));
		free(buf2);
		if (!o)
			continue;
		v = aik_json_get(o, "lease_id");
		lid = v ? aik_json_str(v) : NULL;
		v = aik_json_get(o, "expires_at");
		exp = v ? aik_json_int(v) : 0;
		v = aik_json_get(o, "mission");
		mission = v ? aik_json_str(v) : NULL;
		v = aik_json_get(o, "revoked");
		if (v && aik_json_typeof(v) == AIK_JSON_BOOL &&
		    aik_json_bool(v))
			revoked = 1;
		if (!lid) {
			static char idbuf[256];	/* readdir 名短，静态可 */

			snprintf(idbuf, sizeof(idbuf), "%.*s", (int)(l - 5),
				 de->d_name);
			lid = idbuf;
		}
		/* scope 摘要 */
		scope[0] = '\0';
		v = aik_json_get(o, "scope");
		if (v && aik_json_typeof(v) == AIK_JSON_ARR) {
			sn = aik_json_count(v);
			scope[0] = '\0';
			for (si = 0; si < sn && si < 3; si++) {
				const aik_json *s2 = aik_json_at(v, si);
				const char *sv = s2 ? aik_json_str(s2) : NULL;

				if (!sv)
					continue;
				if (si)
					strncat(scope, ",",
						sizeof(scope) -
						strlen(scope) - 1);
				strncat(scope, sv,
					sizeof(scope) - strlen(scope) - 1);
			}
		}
		if (nents >= cap) {
			int nc = cap ? cap * 2 : 8;
			struct ls_ent *ne = realloc(ents,
						    (size_t)nc * sizeof(*ne));

			if (!ne) {
				aik_json_free(o);
				free(ents);
				closedir(d);
				if (err)
					snprintf(err, errlen, "lease: OOM");
				return -1;
			}
			ents = ne;
			cap = nc;
		}
		e = &ents[nents++];
		memset(e, 0, sizeof(*e));
		if (revoked) {
			e->rank = 2;
			snprintf(remain, sizeof(remain), "已撤销");
		} else if (exp > 0 && now >= exp) {
			e->rank = 1;
			snprintf(remain, sizeof(remain), "已过期");
		} else {
			long long left = exp > 0 ? exp - now : 0;

			e->rank = 0;
			if (left >= 86400)
				snprintf(remain, sizeof(remain),
					 "剩余%lldd", left / 86400);
			else if (left >= 3600)
				snprintf(remain, sizeof(remain),
					 "剩余%lldh", left / 3600);
			else
				snprintf(remain, sizeof(remain),
					 "剩余%lldm", left / 60);
		}
		e->expires = exp;
		set_trunc(e->it.text, sizeof(e->it.text), lid);
		{
			size_t tl = strlen(e->it.text);
			int w = snprintf(e->it.text + tl,
					 sizeof(e->it.text) - tl, " %s",
					 remain);

			if (w < 0)
				e->it.text[tl] = '\0';
		}
		snprintf(e->it.tag, sizeof(e->it.tag), "%s",
			 e->rank == 0 ? "valid" :
			 e->rank == 1 ? "expired" : "revoked");
		if (mission && mission[0]) {
			set_trunc(e->it.detail, sizeof(e->it.detail),
				  mission);
			if (scope[0]) {
				size_t dl = strlen(e->it.detail);

				snprintf(e->it.detail + dl,
					 sizeof(e->it.detail) - dl, " · %s",
					 scope);
			}
		} else if (scope[0]) {
			set_trunc(e->it.detail, sizeof(e->it.detail), scope);
		}
		aik_json_free(o);
	}
	closedir(d);
	if (nents > 1)
		qsort(ents, (size_t)nents, sizeof(ents[0]), ls_cmp);
	/* 拆成 flat items（struct ls_ent 内嵌 item——重排后拷出） */
	{
		tui_ov_item *res = malloc((size_t)(nents ? nents : 1) *
					  sizeof(*res));

		if (!res && nents) {
			free(ents);
			if (err)
				snprintf(err, errlen, "lease: OOM");
			return -1;
		}
		for (i = 0; i < nents; i++)
			res[i] = ents[i].it;
		free(ents);
		*out = res;
		*n = nents;
	}
	return 0;
}
