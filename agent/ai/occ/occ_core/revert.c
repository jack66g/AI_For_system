/* SPDX-License-Identifier: GPL-2.0 */
/*
 * revert.c - /undo 三段式逻辑主体（T9b2；OCD §7.3 headless 形态）
 *
 * 三段（契约与语义见 occ_revert.h 头注）：
 *   stage（occ_undo）   找边界 → 收集范围内快照（最早者=改动前状态）→
 *                       捕获 _redo 现状 → 回滚文件 → 隐藏消息 → 写
 *                       occ_revert 行 + system 注记。先收集后提交；
 *                       单文件回滚失败不中止（failed 标记，报告如实列出）。
 *   commit（occ_revert_commit）用户重发即认：删 occ_revert 行 + 清 _redo
 *                       段（注记消息留给 loop 折叠进下一条 user 文本）。
 *   redo（occ_redo）    _redo 段还原 + 按 hidden_json 精确解隐藏（早期
 *                       已 commit 的保持隐藏）+ 删注记 + 删 stage 行。
 *
 * 文件发现走快照目录（<root>/<ses>/<msg>/<mangled>[.ABSENT]，mangle 单射
 * 可逆）——快照在执行时已按绝对路径落盘，undo 无需猜路径；session.workdir
 * 仅用于把范围内 write/edit 的相对参数解析回绝对路径，对账「有调用但
 * 无快照」的跳过项（bash 无快照同列）。bash 改动不在恢复集（b1 只对
 * write/edit 快照），报告如实计数，不谎称全量回滚。
 */
#define _POSIX_C_SOURCE 200809L
#include "occ_revert.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "occ_tools/occ_tools.h"			/* mangle/unmangle/snap_root/resolve */
#include "store/store_json.h"

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || !errlen)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* 递归建父目录（session.c mkdirs 同口径） */
static int mkdirs(const char *path)
{
	char tmp[1024];
	char *p;

	if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp))
		return -1;
	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(tmp, 0755) && errno != EEXIST)
				return -1;
			*p = '/';
		}
	}
	return mkdir(tmp, 0755) && errno != EEXIST ? -1 : 0;
}

/* 二进制整文件拷贝（快照还原；0 成功） */
static int copy_file(const char *src, const char *dst)
{
	char buf[65536];
	FILE *in, *out;
	size_t n;
	int rc = -1;

	in = fopen(src, "rb");
	if (!in)
		return -1;
	out = fopen(dst, "wb");
	if (!out) {
		fclose(in);
		return -1;
	}
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (fwrite(buf, 1, n, out) != n)
			goto out;
	}
	if (ferror(in))
		goto out;
	rc = 0;
out:
	fclose(in);
	if (fclose(out) && rc == 0)
		rc = -1;
	return rc;
}

/* 递归删除（_redo 段清理；尽力，不报错阻断） */
static void rm_rf(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *de;
	char child[9216];

	if (!d) {
		unlink(path);			/* 非目录：直接删 */
		return;
	}
	while ((de = readdir(d))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (snprintf(child, sizeof(child), "%s/%s", path, de->d_name) >=
		    (int)sizeof(child))
			continue;
		rm_rf(child);
	}
	closedir(d);
	rmdir(path);
}

/* ---- 范围内快照收集（首见即最早——行序升序扫描保证） ---- */

typedef struct {
	char path[4096];		/* 还原目标绝对路径 */
	char msg[OCC_ID_LEN];		/* 首见快照所在消息 */
	int action;			/* OCC_UNDO_RESTORE / _DELETE */
	int failed;			/* 回滚失败标记 */
} snap_ent;

typedef struct {
	snap_ent *v;
	size_t n, cap;
} entvec;

static void entvec_free(entvec *e)
{
	free(e->v);
	e->v = NULL;
	e->n = e->cap = 0;
}

/* 返回 1=已存在（未追加），0=新追加，-1=oom/缓冲不合规 */
static int entvec_add(entvec *e, const char *path, const char *msg,
		      int action)
{
	size_t i;

	for (i = 0; i < e->n; i++)
		if (!strcmp(e->v[i].path, path))
			return 1;
	if (e->n == e->cap) {
		size_t nc = e->cap ? e->cap * 2 : 16;
		snap_ent *nv = realloc(e->v, nc * sizeof(*nv));

		if (!nv)
			return -1;
		e->v = nv;
		e->cap = nc;
	}
	memset(&e->v[e->n], 0, sizeof(*e->v));
	snprintf(e->v[e->n].path, sizeof(e->v[e->n].path), "%s", path);
	snprintf(e->v[e->n].msg, sizeof(e->v[e->n].msg), "%s", msg);
	e->v[e->n].action = action;
	e->n++;
	return 0;
}

/*
 * 扫一条消息的快照目录：<root>/<ses>/<msg>/<mangled>[.ABSENT]。
 * 无目录=该消息无快照（正常）。条目名先剥 .ABSENT 后缀再 unmangle
 * ——mangle 把 '.' 编码为 %2e，裸 '.' 只可能来自后缀，二者不歧义。
 */
static void scan_msg_dir(const char *root, const char *ses, const char *msg,
			 entvec *ev)
{
	char dir[768];
	DIR *d;
	struct dirent *de;

	if (snprintf(dir, sizeof(dir), "%s/%s/%s", root, ses, msg) >=
	    (int)sizeof(dir))
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d))) {
		char name[8200];
		char abs[4096];
		size_t nl;
		int action = OCC_UNDO_RESTORE;

		if (de->d_name[0] == '.')
			continue;
		if (snprintf(name, sizeof(name), "%s", de->d_name) >=
		    (int)sizeof(name))
			continue;
		nl = strlen(name);
		if (nl > 7 && !strcmp(name + nl - 7, ".ABSENT")) {
			name[nl - 7] = '\0';
			action = OCC_UNDO_DELETE;
		}
		if (occ_snap_unmangle(name, abs, sizeof(abs)))
			continue;		/* 异常条目：跳过 */
		if (abs[0] != '/')
			continue;
		if (entvec_add(ev, abs, msg, action) < 0)
			break;			/* oom：停止收集 */
	}
	closedir(d);
}

/* ---- JSON 数组助手（aik_json DOM，路径转义安全） ---- */

static char *str_array_to_json(const char *const *ids, size_t n)
{
	aik_json *arr = aik_json_new_arr();
	char *out = NULL;
	size_t i, dummy;

	if (!arr)
		return NULL;
	for (i = 0; i < n; i++) {
		aik_json *s = aik_json_new_str(ids[i]);

		if (!s || aik_json_arr_push(arr, s) < 0) {
			aik_json_free(s);
			goto out;
		}
	}
	if (aik_json_dump(arr, &out, &dummy) < 0)
		out = NULL;
out:
	aik_json_free(arr);
	return out;
}

/* 合并：old JSON 数组（可空/[]）∪ new ids（去重，保序） */
static char *merge_ids_json(const char *old_json, const char *const *ids,
			    size_t n)
{
	aik_json *arr = NULL;
	char *out = NULL;
	char perr[96];
	size_t i, j, dummy, oldn = 0;

	if (old_json && old_json[0] && strcmp(old_json, "[]")) {
		arr = aik_json_parse(old_json, strlen(old_json), perr,
				     sizeof(perr));
		if (!arr || aik_json_typeof(arr) != AIK_JSON_ARR) {
			aik_json_free(arr);
			arr = NULL;
		}
	}
	if (!arr) {
		return str_array_to_json(ids, n);
	}
	oldn = aik_json_count(arr);
	for (i = 0; i < n; i++) {
		int dup = 0;
		aik_json *s;

		for (j = 0; j < oldn; j++) {
			const aik_json *e = aik_json_at(arr, j);
			const char *t = e && aik_json_typeof(e) == AIK_JSON_STR ?
					aik_json_str(e) : NULL;

			if (t && !strcmp(t, ids[i])) {
				dup = 1;
				break;
			}
		}
		if (dup)
			continue;
		s = aik_json_new_str(ids[i]);
		if (!s || aik_json_arr_push(arr, s) < 0) {
			aik_json_free(s);
			goto out;
		}
	}
	if (aik_json_dump(arr, &out, &dummy) < 0)
		out = NULL;
out:
	aik_json_free(arr);
	return out;
}

/* JSON 字符串数组 → C 数组（heap，调用方 free 每项+数组） */
static int json_to_str_array(const char *json, char ***out, size_t *n)
{
	aik_json *arr;
	char perr[96];
	size_t i, cnt;
	char **v;

	*out = NULL;
	*n = 0;
	if (!json || !json[0] || !strcmp(json, "[]"))
		return 0;
	arr = aik_json_parse(json, strlen(json), perr, sizeof(perr));
	if (!arr || aik_json_typeof(arr) != AIK_JSON_ARR) {
		aik_json_free(arr);
		return -1;
	}
	cnt = aik_json_count(arr);
	v = calloc(cnt ? cnt : 1, sizeof(*v));
	if (!v) {
		aik_json_free(arr);
		return -1;
	}
	for (i = 0; i < cnt; i++) {
		const aik_json *e = aik_json_at(arr, i);
		const char *t = e && aik_json_typeof(e) == AIK_JSON_STR ?
				aik_json_str(e) : NULL;

		v[i] = strdup(t ? t : "");
	}
	aik_json_free(arr);
	*out = v;
	*n = cnt;
	return 0;
}

static void str_array_free(char **v, size_t n)
{
	size_t i;

	if (!v)
		return;
	for (i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

/* ---- _redo 段（stage 时另存「撤销前现状」；已存在即跳过——叠加 undo
 *      保留最早现状，redo 一步回到首次撤销前） ---- */

static void redo_capture(const char *root, const char *ses,
			 const snap_ent *e)
{
	char dir[768], dst[9216], mangled[8200], probe[9248];
	struct stat st;

	if (snprintf(dir, sizeof(dir), "%s/%s/_redo", root, ses) >=
	    (int)sizeof(dir))
		return;
	if (mkdirs(dir))
		return;
	occ_snap_mangle(e->path, mangled, sizeof(mangled));
	snprintf(dst, sizeof(dst), "%s/%s", dir, mangled);
	snprintf(probe, sizeof(probe), "%s", dst);
	if (!access(probe, F_OK))
		return;				/* 已捕获：不覆盖 */
	snprintf(probe, sizeof(probe), "%s.ABSENT", dst);
	if (!access(probe, F_OK))
		return;
	if (!stat(e->path, &st) && S_ISREG(st.st_mode)) {
		if (copy_file(e->path, dst))
			fprintf(stderr, "occ-undo: redo 捕获失败 %s\n",
				e->path);
		return;
	}
	/* 现状不存在 → 墓碑（redo 据此删除） */
	snprintf(dst, sizeof(dst), "%s/%s.ABSENT", dir, mangled);
	{
		FILE *f = fopen(dst, "wb");

		if (f) {
			fputs("absent\n", f);
			fclose(f);
		}
	}
}

/* 还原单文件（快照 → 目标；DELETE=墓碑→删除）。0 成功 */
static int apply_restore(const char *root, const char *ses,
			 const snap_ent *e)
{
	char dir[768], src[9216], mangled[8200];

	if (snprintf(dir, sizeof(dir), "%s/%s/%s", root, ses, e->msg) >=
	    (int)sizeof(dir))
		return -1;
	occ_snap_mangle(e->path, mangled, sizeof(mangled));
	if (e->action == OCC_UNDO_DELETE) {
		if (snprintf(src, sizeof(src), "%s/%s.ABSENT", dir,
			     mangled) >= (int)sizeof(src))
			return -1;
		if (access(src, F_OK))
			return -1;		/* 墓碑缺失：不谎报成功 */
		if (unlink(e->path) && errno != ENOENT)
			return -1;
		return 0;
	}
	if (snprintf(src, sizeof(src), "%s/%s", dir, mangled) >=
	    (int)sizeof(src))
		return -1;
	if (access(src, F_OK))
		return -1;
	{
		/* 目标父目录可能已被删（write 递归建过）——尽力重建 */
		char parent[4096];
		char *slash;

		snprintf(parent, sizeof(parent), "%s", e->path);
		slash = strrchr(parent, '/');
		if (slash && slash != parent) {
			*slash = '\0';
			if (mkdirs(parent))
				return -1;
		}
	}
	return copy_file(src, e->path);
}

/* ---- redo 还原（_redo 段 → 目标） ---- */

static int apply_redo(const char *root, const char *ses, const snap_ent *e,
		      int *failed)
{
	char dir[768], src[9216], mangled[8200];
	struct stat st;

	if (snprintf(dir, sizeof(dir), "%s/%s/_redo", root, ses) >=
	    (int)sizeof(dir)) {
		*failed = 1;
		return -1;
	}
	occ_snap_mangle(e->path, mangled, sizeof(mangled));
	snprintf(src, sizeof(src), "%s/%s.ABSENT", dir, mangled);
	if (!stat(src, &st)) {
		if (unlink(e->path) && errno != ENOENT) {
			*failed = 1;
			return -1;
		}
		return 0;
	}
	snprintf(src, sizeof(src), "%s/%s", dir, mangled);
	if (stat(src, &st)) {
		*failed = 1;			/* _redo 缺该文件 */
		return -1;
	}
	{
		char parent[4096];
		char *slash;

		snprintf(parent, sizeof(parent), "%s", e->path);
		slash = strrchr(parent, '/');
		if (slash && slash != parent) {
			*slash = '\0';
			if (mkdirs(parent)) {
				*failed = 1;
				return -1;
			}
		}
	}
	if (copy_file(src, e->path)) {
		*failed = 1;
		return -1;
	}
	return 0;
}

/* ---- 结果填充/释放 ---- */

void occ_undo_result_free(occ_undo_result *r)
{
	size_t i;

	if (!r)
		return;
	free(r->user_text);
	for (i = 0; i < r->nfiles; i++)
		free(r->files[i].path);
	memset(r, 0, sizeof(*r));
}

static int result_push_file(occ_undo_result *out, const char *path,
			    int action, int failed)
{
	if (!out || out->nfiles >= OCC_UNDO_MAX_FILES)
		return 0;
	out->files[out->nfiles].path = strdup(path);
	if (!out->files[out->nfiles].path)
		return -1;
	out->files[out->nfiles].action = action;
	out->files[out->nfiles].failed = failed;
	out->nfiles++;
	return 0;
}

/* ---- 快照根（参数显式 > OCC_SNAPROOT > ~/.occ/snapshots） ---- */

static const char *resolve_root(const char *snaproot, char *buf,
				size_t buflen)
{
	if (snaproot && snaproot[0])
		return snaproot;
	return occ_snap_root(buf, buflen);
}

/* ---- occ_undo ---- */

int occ_undo(occ_db *db, const char *session_id, int steps,
	     const char *snaproot, occ_undo_result *out, char *err,
	     size_t errlen)
{
	occ_session_row s;
	occ_msg_row *rows = NULL;
	size_t n = 0, i, bidx = 0;
	size_t *users = NULL;
	size_t nusers = 0;
	long long boundary_rowid;
	entvec ev;
	char rootbuf[512];
	const char *root;
	occ_revert_row oldstage;
	int have_old = 0;
	char **newly_hidden = NULL;
	size_t nhidden = 0;
	char **old_hidden = NULL;
	size_t nold_hidden = 0;
	char *hidden_json = NULL;
	char *files_json = NULL;
	char **file_paths = NULL;
	size_t nfiles_json = 0;
	char note_id[OCC_ID_LEN];
	char note[1024];
	char filelist[512];
	size_t nskipped = 0;
	long long nchanged = 0;
	int rc = -1;
	occ_tc_row *tcs = NULL;
	size_t ntc = 0;
	char terr[160];

	memset(&ev, 0, sizeof(ev));
	memset(&oldstage, 0, sizeof(oldstage));
	note_id[0] = '\0';
	if (out)
		memset(out, 0, sizeof(*out));
	if (!db || !session_id || steps < 1) {
		set_err(err, errlen, "occ_undo: bad args（steps 须 ≥1）");
		return -1;
	}
	if (occ_session_get(db, session_id, &s, err, errlen) != 1) {
		set_err(err, errlen, "occ undo: 会话 %s 不存在", session_id);
		return -1;
	}
	if (!strcmp(s.status, OCC_ST_RUNNING)) {
		set_err(err, errlen,
			"occ undo: 会话正在执行（status=running），"
			"请等本轮结束或先中断");
		return -1;
	}
	if (occ_msg_list(db, session_id, &rows, &n, err, errlen))
		return -1;
	if (!n) {
		set_err(err, errlen, "occ undo: 会话没有消息，无可撤销");
		goto out;
	}
	/* 边界 = 非 reverted 的 user 中倒数第 steps 条（叠加 undo 时已
	 * 被撤的 user 不计步——从现边界再往深处数，OCD 反复 /undo） */
	users = calloc(n, sizeof(*users));
	if (!users) {
		set_err(err, errlen, "occ undo: oom");
		goto out;
	}
	for (i = 0; i < n; i++)
		if (!strcmp(rows[i].role, "user") && !rows[i].reverted)
			users[nusers++] = i;
	if (!nusers) {
		set_err(err, errlen, "occ undo: 没有可撤销的用户消息");
		goto out;
	}
	if ((size_t)steps > nusers) {
		set_err(err, errlen,
			"occ undo: 只有 %zu 步可撤（请求 %d 步）", nusers,
			steps);
		goto out;
	}
	bidx = users[nusers - (size_t)steps];
	boundary_rowid = rows[bidx].rowid;

	root = resolve_root(snaproot, rootbuf, sizeof(rootbuf));
	if (!root) {
		set_err(err, errlen, "occ undo: 无法解析快照根（无 HOME）");
		goto out;
	}

	/* ---- 先收集：范围内全部消息的快照目录（首见=最早=改动前状态） */
	for (i = bidx; i < n; i++)
		scan_msg_dir(root, session_id, rows[i].id, &ev);

	/* 工具调用对账 → 无快照跳过项（bash 无快照；write/edit 有调用
	 * 但快照缺失也如实计列） */
	if (occ_toolcalls_since(db, session_id, boundary_rowid, &tcs, &ntc,
				terr, sizeof(terr)) < 0) {
		set_err(err, errlen, "occ undo: %s", terr);
		goto out;
	}
	for (i = 0; i < ntc; i++) {
		if (!strcmp(tcs[i].tool, OCC_T_BASH)) {
			nskipped++;
			continue;
		}
		if (strcmp(tcs[i].tool, OCC_T_WRITE) &&
		    strcmp(tcs[i].tool, OCC_T_EDIT))
			continue;
		if (tcs[i].rc != 0)
			continue;		/* 调用失败：文件未变 */
		{
			char abs[4096];
			char rawpath[4096];
			char perr2[96];
			aik_json *a;
			size_t k;
			int found = 0;

			rawpath[0] = '\0';
			if (tcs[i].args_json) {
				a = aik_json_parse(tcs[i].args_json,
						   strlen(tcs[i].args_json),
						   perr2, sizeof(perr2));
				if (a && aik_json_typeof(a) == AIK_JSON_OBJ) {
					const aik_json *pv =
						aik_json_get(a, "path");

					if (pv &&
					    aik_json_typeof(pv) == AIK_JSON_STR)
						/* 先拷出再 free——aik_json_str
						 * 指针随树释放（a1 教训同款） */
						snprintf(rawpath,
							 sizeof(rawpath), "%s",
							 aik_json_str(pv));
				}
				aik_json_free(a);
			}
			if (rawpath[0] &&
			    !occ_resolve_path(s.workdir, rawpath, abs,
					      sizeof(abs))) {
				for (k = 0; k < ev.n; k++)
					if (!strcmp(ev.v[k].path, abs)) {
						found = 1;
						break;
					}
			}
			if (!found)
				nskipped++;
		}
	}

	if (!ev.n) {
		set_err(err, errlen,
			"occ undo: 被撤范围没有文件快照（纯对话轮或快照"
			"缺失）——不改库、不隐藏消息");
		goto out;
	}

	/* ---- redo 捕获（撤销前现状；已存在不覆盖） ---- */
	for (i = 0; i < ev.n; i++)
		redo_capture(root, session_id, &ev.v[i]);

	/* ---- 回滚文件（单个失败标记，不中止——部分失败如实列出） ---- */
	for (i = 0; i < ev.n; i++) {
		if (apply_restore(root, session_id, &ev.v[i])) {
			ev.v[i].failed = 1;
			fprintf(stderr, "occ-undo: 回滚失败 %s\n",
				ev.v[i].path);
		}
	}

	/* ---- DB 提交 ---- */
	/* 1) 新隐藏集合（范围内当前未隐藏的）+ 合并旧 stage 隐藏集 */
	newly_hidden = calloc(ev.n + n, sizeof(*newly_hidden));
	if (!newly_hidden) {
		set_err(err, errlen, "occ undo: oom");
		goto out;
	}
	for (i = bidx; i < n; i++) {
		if (rows[i].reverted)
			continue;
		/* system 注记不进隐藏集：它是本 stage/旧 stage 的临时
		 * 记录——旧注记随后被删、新注记保持可见（供折叠） */
		if (!strcmp(rows[i].role, "system"))
			continue;
		newly_hidden[nhidden] = strdup(rows[i].id);
		if (!newly_hidden[nhidden]) {
			set_err(err, errlen, "occ undo: oom");
			goto out;
		}
		nhidden++;
	}
	have_old = occ_revert_get(db, session_id, &oldstage, err, errlen);
	if (have_old < 0)
		goto out;
	if (have_old == 1 &&
	    json_to_str_array(oldstage.hidden_json, &old_hidden,
			      &nold_hidden) < 0) {
		set_err(err, errlen, "occ undo: 旧 stage hidden_json 损坏");
		goto out;
	}
	hidden_json = merge_ids_json(have_old == 1 ? oldstage.hidden_json :
				     NULL, (const char *const *)newly_hidden,
				     nhidden);
	if (!hidden_json) {
		set_err(err, errlen, "occ undo: hidden_json oom");
		goto out;
	}
	/* files_json（本 stage 全量恢复集；redo 据此查 _redo 段） */
	file_paths = calloc(ev.n, sizeof(*file_paths));
	if (!file_paths) {
		set_err(err, errlen, "occ undo: oom");
		goto out;
	}
	for (i = 0; i < ev.n; i++) {
		file_paths[i] = strdup(ev.v[i].path);
		if (!file_paths[i]) {
			set_err(err, errlen, "occ undo: oom");
			goto out;
		}
	}
	nfiles_json = ev.n;
	files_json = str_array_to_json((const char *const *)file_paths,
				       nfiles_json);
	if (!files_json) {
		set_err(err, errlen, "occ undo: files_json oom");
		goto out;
	}

	/* 2) 注记消息（下一轮模型知道哪些改动被撤） */
	filelist[0] = '\0';
	for (i = 0; i < ev.n && strlen(filelist) + 80 <
	     sizeof(filelist); i++) {
		if (i)
			strncat(filelist, "、", sizeof(filelist) -
				strlen(filelist) - 1);
		strncat(filelist, ev.v[i].path, sizeof(filelist) -
			strlen(filelist) - 1);
	}
	if (ev.n && strlen(filelist) + 4 < sizeof(filelist))
		strncat(filelist, "…", sizeof(filelist) - strlen(filelist) - 1);
	snprintf(note, sizeof(note),
		 "[occ 注记] 已撤销最近 %d 步：%zu 条消息不再进上下文，"
		 "%zu 个文件回滚到改动前（%s）。无快照不回滚项 %zu 处"
		 "（bash 改动等）。发送新消息即确认撤销（此后不可 redo），"
		 "或执行 occ redo 恢复。",
		 steps, nhidden, ev.n, filelist[0] ? filelist : "见回滚列表",
		 nskipped);
	if (occ_msg_add_note(db, session_id, note, note_id, sizeof(note_id),
			     err, errlen))
		goto out;

	/* 3) 隐藏消息（单事务批量） */
	if (occ_msgs_set_reverted(db, session_id, hidden_json, 1, &nchanged,
				  err, errlen)) {
		occ_msg_delete(db, note_id, NULL, 0);	/* 回滚注记 */
		goto out;
	}

	/* 4) 撤旧 stage 注记（叠加 undo：新注记取代） */
	if (have_old == 1 && oldstage.note_msg[0]) {
		if (occ_msg_delete(db, oldstage.note_msg, terr,
				   sizeof(terr)))
			fprintf(stderr, "occ-undo: 撤旧注记失败（%s）\n",
				terr);
	}

	/* 5) stage 行（边界/注记/文件清单/本 stage 隐藏集） */
	if (occ_revert_put(db, session_id, rows[bidx].id, note_id,
			   files_json, hidden_json, err, errlen)) {
		occ_msg_delete(db, note_id, NULL, 0);
		goto out;
	}

	/* ---- 结果 ---- */
	if (out) {
		snprintf(out->boundary_user_msg,
			 sizeof(out->boundary_user_msg), "%s", rows[bidx].id);
		out->user_text = rows[bidx].text ?
				 strdup(rows[bidx].text) : NULL;
		snprintf(out->note_msg, sizeof(out->note_msg), "%s", note_id);
		out->nmsgs_reverted = (size_t)nchanged;
		out->nskipped = nskipped;
		for (i = 0; i < ev.n; i++)
			if (result_push_file(out, ev.v[i].path,
					     ev.v[i].action,
					     ev.v[i].failed)) {
				/* oom：已推条目保留 */
				break;
			}
	}
	rc = 0;
out:
	occ_revert_row_free(&oldstage);
	entvec_free(&ev);
	occ_tc_rows_free(tcs, ntc);
	free(users);
	if (rows)
		occ_msg_rows_free(rows, n);
	free(hidden_json);
	free(files_json);
	str_array_free(newly_hidden, nhidden);
	str_array_free(old_hidden, nold_hidden);
	str_array_free(file_paths, nfiles_json);
	return rc;
}

/* ---- occ_redo ---- */

int occ_redo(occ_db *db, const char *session_id, const char *snaproot,
	     occ_undo_result *out, char *err, size_t errlen)
{
	occ_revert_row st;
	char rootbuf[512];
	const char *root;
	char **files = NULL;
	size_t nfiles = 0, i;
	char **hidden = NULL;
	size_t nhidden = 0;
	size_t nfailed = 0;
	long long nunc = 0;
	int rc = -1;
	char terr[160];

	memset(&st, 0, sizeof(st));
	if (out)
		memset(out, 0, sizeof(*out));
	if (!db || !session_id) {
		set_err(err, errlen, "occ_redo: bad args");
		return -1;
	}
	{
		occ_session_row s;

		if (occ_session_get(db, session_id, &s, err, errlen) != 1) {
			set_err(err, errlen, "occ redo: 会话 %s 不存在",
				session_id);
			return -1;
		}
	}
	{
		int g = occ_revert_get(db, session_id, &st, err, errlen);

		if (g < 0)
			return -1;
		if (g == 0) {
			set_err(err, errlen,
				"occ redo: 没有待恢复的撤销（无 stage 态）");
			return -1;
		}
	}
	root = resolve_root(snaproot, rootbuf, sizeof(rootbuf));
	if (!root) {
		set_err(err, errlen, "occ redo: 无法解析快照根（无 HOME）");
		goto out;
	}
	if (json_to_str_array(st.files_json, &files, &nfiles) < 0) {
		set_err(err, errlen, "occ redo: files_json 损坏");
		goto out;
	}
	/* 1) 文件还原（_redo 段 → 目标） */
	for (i = 0; i < nfiles; i++) {
		snap_ent e;
		int failed = 0;

		memset(&e, 0, sizeof(e));
		snprintf(e.path, sizeof(e.path), "%s", files[i]);
		apply_redo(root, session_id, &e, &failed);
		if (failed) {
			nfailed++;
			fprintf(stderr, "occ-redo: 还原失败 %s\n", files[i]);
		}
		if (out && out->nfiles < OCC_UNDO_MAX_FILES)
			result_push_file(out, files[i], OCC_UNDO_RESTORE,
					 failed);
	}
	/* 2) 精确解隐藏（只解本 stage 的；早期已 commit 的保持隐藏） */
	if (json_to_str_array(st.hidden_json, &hidden, &nhidden) < 0) {
		set_err(err, errlen, "occ redo: hidden_json 损坏");
		goto out;
	}
	{
		char *ids = str_array_to_json((const char *const *)hidden,
					      nhidden);

		if (ids) {
			if (occ_msgs_set_reverted(db, session_id, ids, 0,
						  &nunc, err, errlen)) {
				free(ids);
				goto out;
			}
			free(ids);
		}
	}
	/* 3) 删注记 + stage 行 */
	if (st.note_msg[0] &&
	    occ_msg_delete(db, st.note_msg, terr, sizeof(terr)))
		fprintf(stderr, "occ-redo: 删注记失败（%s）\n", terr);
	if (occ_revert_clear(db, session_id, err, errlen))
		goto out;
	/* 4) 清 _redo 段 */
	{
		char dir[768];

		if (snprintf(dir, sizeof(dir), "%s/%s/_redo", root,
			     session_id) < (int)sizeof(dir))
			rm_rf(dir);
	}
	if (out)
		out->nmsgs_reverted = (size_t)nunc;
	rc = 0;
	if (nfailed)
		set_err(err, errlen,
			"occ redo: 完成，但 %zu 个文件还原失败（见 stderr）",
			nfailed);
out:
	occ_revert_row_free(&st);
	str_array_free(files, nfiles);
	str_array_free(hidden, nhidden);
	return rc;
}

/* ---- occ_revert_commit（用户重发即认；幂等，绝不阻断主流程） ---- */

void occ_revert_commit(occ_db *db, const char *session_id,
		       const char *snaproot)
{
	occ_revert_row st;
	char rootbuf[512];
	const char *root;
	char terr[128];

	memset(&st, 0, sizeof(st));
	terr[0] = '\0';			/* 无 stage 时 get 不置 err——防
					  * 未初始化缓冲被当字符串打印 */
	if (!db || !session_id)
		return;
	if (occ_revert_get(db, session_id, &st, terr, sizeof(terr)) != 1) {
		if (terr[0])
			fprintf(stderr, "occ-commit: %s\n", terr);
		return;
	}
	occ_revert_row_free(&st);
	if (occ_revert_clear(db, session_id, terr, sizeof(terr)))
		fprintf(stderr, "occ-commit: 清 stage 失败（%s）\n", terr);
	root = resolve_root(snaproot, rootbuf, sizeof(rootbuf));
	if (root) {
		char dir[768];

		if (snprintf(dir, sizeof(dir), "%s/%s/_redo", root,
			     session_id) < (int)sizeof(dir))
			rm_rf(dir);
	}
}
