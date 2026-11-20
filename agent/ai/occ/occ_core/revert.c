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
 *
 * P-50（manifest 对账——DB 外部锚）：P-49 的 sidecar 与快照同目录=自证，
 * 对快照树有 FS 写权的攻击者可换内容后重造 sidecar。修法：写侧
 * occ_snapshot_stage 把 manifest（msg→{path,kind,sha256}）落 occ_snap 表
 * （威胁模型：攻击者无 DB 写权），undo/redo 消费前对账：
 *   ① 换内容/换墓碑字节：anchored 条目直接比内容 sha 与 DB 期望——
 *      sidecar 免读（重造也无用）；
 *   ② 删标记：manifest 有行而 FS 上该 path 的快照/墓碑全缺 → 合成
 *      failed 条目上报，该文件不回滚；
 *   ③ 搬目录：FS 位置 (msg,path) 与 manifest 不符（path 出现在其它
 *      msg 行）→ 该条判死；
 *   ④ redo 对称锚：undo 捕获 _redo 时把在盘文件 {path,kind,sha256}
 *      落 stage.redo_json，redo 消费前比对。
 * db 无行=全 legacy（P-49 sidecar 校验原路）；逐条 fail-closed 语义
 * 与 P-49 一致：该条 failed=1、目标保持现状、undo 整体 rc=0。
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
#include "occ_tools/sha256.h"		/* S-FINDING-01：快照校验 */
#include "store/store_json.h"

#include "occ_tui/tui_lang.h"		/* O-20 A2：语档文案面 */

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
	int failed_before;		/* P-50：对账阶段即判死（apply 循环
					 * 直接标 failed 跳过——stderr 已
					 * 打过具体原因） */
	int anchored;			/* P-50：DB manifest 命中（want_*
					 * 有效——DB 锚比同目录 sidecar 强） */
	char want_kind[8];		/* manifest 期望类型 snap|absent */
	char want_sha[65];		/* manifest 期望字节摘要 */
} snap_ent;

typedef struct {
	snap_ent *v;
	size_t n, cap;
} entvec;

/* P-50：raw 集——FS 实况全集（每 (msg,path) 一条，不做跨 msg 的 path
 * 去重——去重只属于 ev）。删标记检测按它判「path 在范围内任何 msg
 * 目录都不在盘」；ev 只是首见投影，不能区分「仅首见副本在盘」。 */
typedef struct {
	char msg[OCC_ID_LEN];
	char path[4096];
} raw_ent;

typedef struct {
	raw_ent *v;
	size_t n, cap;
} rawvec;

static void entvec_free(entvec *e)
{
	free(e->v);
	e->v = NULL;
	e->n = e->cap = 0;
}

static void rawvec_free(rawvec *r)
{
	free(r->v);
	r->v = NULL;
	r->n = r->cap = 0;
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

/* (msg,path) 去重追加（同目录同名 readdir 不会重，防御足矣） */
static int rawvec_add(rawvec *r, const char *path, const char *msg)
{
	size_t i;

	for (i = 0; i < r->n; i++)
		if (!strcmp(r->v[i].path, path) &&
		    !strcmp(r->v[i].msg, msg))
			return 1;
	if (r->n == r->cap) {
		size_t nc = r->cap ? r->cap * 2 : 16;
		raw_ent *nv = realloc(r->v, nc * sizeof(*nv));

		if (!nv)
			return -1;
		r->v = nv;
		r->cap = nc;
	}
	snprintf(r->v[r->n].path, sizeof(r->v[r->n].path), "%s", path);
	snprintf(r->v[r->n].msg, sizeof(r->v[r->n].msg), "%s", msg);
	r->n++;
	return 0;
}

/*
 * 扫一条消息的快照目录：<root>/<ses>/<msg>/<mangled>[.ABSENT]。
 * 无目录=该消息无快照（正常）。条目名先剥 .ABSENT 后缀再 unmangle
 * ——mangle 把 '.' 编码为 %2e，裸 '.' 只可能来自后缀，二者不歧义。
 */
static void scan_msg_dir(const char *root, const char *ses, const char *msg,
			 entvec *ev, rawvec *rv)
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
		/* S-FINDING-01：完整性 sidecar 不是快照条目（否则计数
		 * 膨胀+幽灵恢复 <path>.sha256 文件） */
		if (nl > 7 && !strcmp(name + nl - 7, ".sha256"))
			continue;
		if (nl > 7 && !strcmp(name + nl - 7, ".ABSENT")) {
			name[nl - 7] = '\0';
			action = OCC_UNDO_DELETE;
		}
		if (occ_snap_unmangle(name, abs, sizeof(abs)))
			continue;		/* 异常条目：跳过 */
		if (abs[0] != '/')
			continue;
		if (rawvec_add(rv, abs, msg) < 0)
			break;			/* oom：停止收集 */
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

static char *rv_read(const char *path, size_t *out_len);	/* 定义随校验助手在下方 */

/* P-50：读文件算 sha（rv_read+occ_sha256_hex 封装；失败置空串） */
static int file_sha(const char *path, char hex[OCC_SHA256_HEX + 1])
{
	char *data;
	size_t len = 0;
	int rc;

	hex[0] = '\0';
	data = rv_read(path, &len);
	if (!data)
		return -1;
	rc = occ_sha256_hex(data, len, hex);
	free(data);
	if (rc)
		hex[0] = '\0';
	return rc;
}

/* P-50：整块写文件（redo_capture 写 _redo 副本用；0=成功） */
static int write_whole(const char *dst, const void *data, size_t len)
{
	FILE *f = fopen(dst, "wb");

	if (!f)
		return -1;
	if (len && fwrite(data, 1, len, f) != len) {
		fclose(f);
		return -1;
	}
	if (fclose(f))
		return -1;
	return 0;
}

/* _redo 段 sidecar 写（P-50：摘要由调用方传入——捕获路径已算过，不再
 * 写后回读 dst 重算一遍） */
static void redo_write_sidecar(const char *dst, const char *hex)
{
	char sp[9280];
	FILE *sf;

	snprintf(sp, sizeof(sp), "%s.sha256", dst);
	sf = fopen(sp, "w");
	if (sf) {
		fprintf(sf, "%s\n", hex);
		fclose(sf);
	}
}

/*
 * redo_capture - 捕获撤销前现状（内容副本或墓碑）。
 * P-50：sha_out/kind_out 回传在盘 _redo 文件的 {摘要,类型}（undo 据此
 * 落 stage.redo_json 锚）；捕获失败两者置空串（该条不锚，redo 走 legacy）。
 * 已存在的捕获（叠加 undo）不覆盖——摘要改读现盘文件回传（锚覆盖全部
 * _redo 在盘文件，不只本次新捕的）。
 */
static void redo_capture(const char *root, const char *ses,
			 const snap_ent *e,
			 char sha_out[OCC_SHA256_HEX + 1], char kind_out[8])
{
	char dir[768], dst[9216], mangled[8200], probe[9248];
	struct stat st;

	sha_out[0] = '\0';
	kind_out[0] = '\0';
	if (snprintf(dir, sizeof(dir), "%s/%s/_redo", root, ses) >=
	    (int)sizeof(dir))
		return;
	if (mkdirs(dir))
		return;
	occ_snap_mangle(e->path, mangled, sizeof(mangled));
	snprintf(dst, sizeof(dst), "%s/%s", dir, mangled);
	snprintf(probe, sizeof(probe), "%s", dst);
	if (!access(probe, F_OK)) {
		/* 已捕获：不覆盖——锚仍要回传（读现盘算） */
		snprintf(kind_out, 8, "%s", "snap");
		file_sha(probe, sha_out);
		return;
	}
	snprintf(probe, sizeof(probe), "%s.ABSENT", dst);
	if (!access(probe, F_OK)) {
		snprintf(kind_out, 8, "%s", "absent");
		file_sha(probe, sha_out);
		return;
	}
	if (!stat(e->path, &st) && S_ISREG(st.st_mode)) {
		char *data;
		size_t len = 0;

		data = rv_read(e->path, &len);
		if (!data) {
			fprintf(stderr, L_("occ-undo: redo 捕获失败 %s\n"),
				e->path);
			return;
		}
		if (occ_sha256_hex(data, len, sha_out)) {
			free(data);
			sha_out[0] = '\0';
			fprintf(stderr, L_("occ-undo: redo 捕获失败 %s\n"),
				e->path);
			return;
		}
		if (write_whole(dst, data, len)) {
			free(data);
			sha_out[0] = '\0';
			fprintf(stderr, L_("occ-undo: redo 捕获失败 %s\n"),
				e->path);
			return;
		}
		redo_write_sidecar(dst, sha_out);	/* S-FINDING-01 */
		snprintf(kind_out, 8, "%s", "snap");
		free(data);
		return;
	}
	/* 现状不存在 → 墓碑（redo 据此删除） */
	snprintf(dst, sizeof(dst), "%s/%s.ABSENT", dir, mangled);
	{
		FILE *f = fopen(dst, "wb");

		if (f) {
			fputs("absent\n", f);
			if (fclose(f) == 0) {
				if (occ_sha256_hex("absent\n", 7, sha_out))
					sha_out[0] = '\0';
				else
					redo_write_sidecar(dst, sha_out);
				snprintf(kind_out, 8, "%s", "absent");
			}
		}
	}
}

/* ---- S-FINDING-01（S-TRACK §5）：快照完整性校验 ---- */

/* 读文件全量（≤64MB；revert 自留——tools.c read_whole 是 static） */
static char *rv_read(const char *path, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long sz;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) || (sz = ftell(f)) < 0 ||
	    sz > 64 * 1024 * 1024 || fseek(f, 0, SEEK_SET)) {
		fclose(f);
		return NULL;
	}
	buf = malloc(sz ? (size_t)sz : 1);
	if (!buf || (sz && fread(buf, 1, (size_t)sz, f) != (size_t)sz)) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*out_len = (size_t)sz;
	return buf;
}

/* 校验 <snap>.sha256：无 sidecar=legacy 快照放行（向后兼容）；有则
 * 比对内容摘要。0=可恢复；-1=校验失败（被篡改/IO 错——拒绝恢复）。 */
static int snap_verify(const char *snap_path)
{
	char side[9280], want[OCC_SHA256_HEX + 2];
	char *data, *p;
	size_t len = 0;
	char hex[OCC_SHA256_HEX + 1];
	FILE *f;

	snprintf(side, sizeof(side), "%s.sha256", snap_path);
	f = fopen(side, "r");
	if (!f)
		return 0;			/* legacy：无校验面 */
	if (!fgets(want, sizeof(want), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	for (p = want; *p; p++)
		if (*p == '\n' || *p == '\r')
			*p = '\0';
	if (strlen(want) != OCC_SHA256_HEX)
		return -1;		/* sidecar 形损：fail closed */
	data = rv_read(snap_path, &len);
	if (!data)
		return -1;
	if (occ_sha256_hex(data, len, hex) || strcmp(hex, want)) {
		free(data);
		return -1;
	}
	free(data);
	return 0;
}

/* P-49（B6 验收线）：ABSENT 墓碑纳入完整性校验。
 *
 * 墓碑语义是常量（存在=目标写前不存在，undo 据此删；内容本无信息），
 * 但对投毒零校验=篡改无感——与内容快照拒收（S-FINDING-01）不同口径
 * 即缺口（真机实证：append 毒字节后 undo 照单全收）。校验面两层：
 *   1) 规范形态直通：空文件（0 字节）或生成器写的 "absent\n"（7 字节）
 *      ——legacy 墓碑无 sidecar 也能判定，合法 undo 行为不变；
 *   2) 非规范形态须持有 sidecar（<墓碑>.sha256，P-49 起生成器随墓碑
 *      落盘）且 sha 比对通过——内容快照同款 fail closed。
 * 返回 0=可信墓碑；-1=被篡改/形损（拒绝按墓碑行事）。actual_hex
 * 回填墓碑实际内容摘要（人话报错用）。 */
static int absent_verify(const char *absent_path,
			 char actual_hex[OCC_SHA256_HEX + 1])
{
	char side[9280], want[OCC_SHA256_HEX + 2];
	char *data;
	size_t len = 0;
	FILE *f;
	int canon;

	if (occ_sha256_hex("", 0, actual_hex))
		actual_hex[0] = '\0';		/* 兜底：失败也有可打印值 */
	data = rv_read(absent_path, &len);
	if (!data)
		return -1;			/* 读不了≠空墓碑：fail closed */
	if (occ_sha256_hex(data, len, actual_hex))
		actual_hex[0] = '\0';
	canon = len == 0 ||
		(len == 7 && !memcmp(data, "absent\n", 7));
	free(data);
	if (canon)
		return 0;
	snprintf(side, sizeof(side), "%s.sha256", absent_path);
	f = fopen(side, "r");
	if (!f)
		return -1;			/* legacy 墓碑被改动：拒 */
	{
		char *p;
		int ok = 0;

		if (fgets(want, sizeof(want), f)) {
			for (p = want; *p; p++)
				if (*p == '\n' || *p == '\r')
					*p = '\0';
			if (strlen(want) == OCC_SHA256_HEX &&
			    !strcmp(want, actual_hex))
				ok = 1;
		}
		fclose(f);
		return ok ? 0 : -1;
	}
}

/* P-50：墓碑规范形态判定（空文件或恰 "absent\n"——与 absent_verify
 * 第一层同口径；DB 锚路径复用：墓碑语义是常量「目标写前不存在」，
 * 规范形态即合法表达，与 manifest 锚结论一致）。 */
static int tomb_canonical(const char *path)
{
	char *data;
	size_t len = 0;
	int canon;

	data = rv_read(path, &len);
	if (!data)
		return 0;
	canon = len == 0 ||
		(len == 7 && !memcmp(data, "absent\n", 7));
	free(data);
	return canon;
}

/*
 * 还原单文件（快照 → 目标；DELETE=墓碑→删除）。0 成功。
 * P-50：e->anchored=1（DB manifest 命中）时跳过 sidecar/规范形态校验
 * （sidecar 与快照同目录=自证——重造也无法通过 DB 锚），改比内容字节
 * 摘要与 manifest 期望。墓碑口径：规范形态（空/"absent\n"）直通——
 * 墓碑语义是常量「目标写前不存在」，规范形态即合法表达，与 DB 锚
 * 结论一致；非规范形态须字节摘要恰等（append 毒字节必拒）。
 */
static int apply_restore(const char *root, const char *ses,
			 const snap_ent *e)
{
	char dir[768], src[9216], mangled[8200];
	char hex[OCC_SHA256_HEX + 1];

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
		if (e->anchored) {
			/* P-50：DB 锚——比墓碑字节摘要（规范形态直通） */
			if (file_sha(src, hex))
				return -1;
			if (strcmp(hex, e->want_sha) &&
			    !tomb_canonical(src)) {
				fprintf(stderr, L_("occ-undo: 快照校验失败"
					"（与 DB manifest 不符，被篡改？"
					"sha256=%s 期望 %s）：%s\n"),
					hex, e->want_sha, e->path);
				return -1;
			}
		} else if (absent_verify(src, hex)) {
			/* P-49：墓碑投毒 → 拒绝按墓碑行事（不删目标，
			 * 与内容快照篡改拒收同款语义，fail closed） */
			fprintf(stderr, L_("occ-undo: 快照校验失败（ABSENT 墓碑"
				"被篡改？sha256=%s）：%s\n"), hex, e->path);
			return -1;
		}
		if (unlink(e->path) && errno != ENOENT)
			return -1;
		return 0;
	}
	if (snprintf(src, sizeof(src), "%s/%s", dir, mangled) >=
	    (int)sizeof(src))
		return -1;
	if (access(src, F_OK))
		return -1;
	if (e->anchored) {
		/* P-50：DB 锚——比内容字节摘要，sidecar 免读（重造无效） */
		if (file_sha(src, hex) || strcmp(hex, e->want_sha)) {
			fprintf(stderr, L_("occ-undo: 快照校验失败"
				"（与 DB manifest 不符，被篡改？sha256=%s"
				" 期望 %s）：%s\n"),
				hex[0] ? hex : L_("(读失败)"), e->want_sha,
				e->path);
			return -1;
		}
	} else if (snap_verify(src)) {
		/* S-FINDING-01：篡改/形损快照拒绝恢复（fail closed） */
		fprintf(stderr, L_("occ-undo: 快照校验失败（被篡改？）：%s\n"),
			e->path);
		return -1;
	}
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

/*
 * P-50：apply_redo 的锚校验（redo_json 命中时）。want_kind 同时参与
 * 比对——内容/墓碑对调（kind 不符）与字节摘要任一不符即拒。墓碑与
 * apply_restore 同口径：规范形态直通、非规范须摘要恰等。
 * 返回 0=锚校验通过；-1=不符（stderr 已说人话）。
 */
static int redo_anchor_verify(const snap_ent *e, const char *src,
			      int is_tomb)
{
	char hex[OCC_SHA256_HEX + 1];
	const char *want = is_tomb ? "absent" : "snap";

	if (strcmp(e->want_kind, want)) {
		fprintf(stderr, L_("occ-redo: 快照校验失败（与 DB manifest "
			"不符，被篡改？类型 %s 期望 %s）：%s\n"),
			want, e->want_kind, e->path);
		return -1;
	}
	if (file_sha(src, hex)) {
		fprintf(stderr, L_("occ-redo: 快照校验失败（与 DB manifest "
			"不符，被篡改？sha256=(读失败) 期望 %s）：%s\n"),
			e->want_sha, e->path);
		return -1;
	}
	if (strcmp(hex, e->want_sha) && !(is_tomb && tomb_canonical(src))) {
		fprintf(stderr, L_("occ-redo: 快照校验失败（与 DB manifest "
			"不符，被篡改？sha256=%s 期望 %s）：%s\n"),
			hex, e->want_sha, e->path);
		return -1;
	}
	return 0;
}

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
		char hex[OCC_SHA256_HEX + 1];

		if (e->anchored) {
			/* P-50：redo 锚（stage.redo_json）——sidecar 免读 */
			if (redo_anchor_verify(e, src, 1)) {
				*failed = 1;
				return -1;
			}
		} else if (absent_verify(src, hex)) {
			/* P-49：_redo 墓碑同口径校验（投毒拒绝删行） */
			fprintf(stderr, L_("occ-redo: 快照校验失败（ABSENT 墓碑"
				"被篡改？sha256=%s）：%s\n"), hex, e->path);
			*failed = 1;
			return -1;
		}
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
	if (e->anchored) {
		/* P-50：redo 锚——比内容字节摘要（重造 sidecar 无效） */
		if (redo_anchor_verify(e, src, 0)) {
			*failed = 1;
			return -1;
		}
	} else if (snap_verify(src)) {
		/* S-FINDING-01：_redo 同口径校验（篡改拒绝还原） */
		fprintf(stderr, L_("occ-redo: 快照校验失败（被篡改？）：%s\n"),
			e->path);
		*failed = 1;
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

/* ---- P-50：redo 锚 JSON（aik_json DOM，路径转义安全） ---- */

/* undo 侧：ev + 捕获摘要 → [{"path":…,"kind":"snap|absent","sha256":…}]
 * 锚数组（覆盖全部 _redo 在盘文件；捕获失败的条目不锚=redo 走 legacy）。
 * 返回 heap 文本（"[]" 起），NULL=oom（调用方退化 legacy）。 */
static char *redo_json_build(const snap_ent *ev, size_t n,
			     const char (*shas)[OCC_SHA256_HEX + 1],
			     const char (*kinds)[8])
{
	aik_json *arr = aik_json_new_arr();
	char *out = NULL;
	size_t i, dummy;

	if (!arr)
		return NULL;
	for (i = 0; i < n; i++) {
		aik_json *o;
		aik_json *t;

		if (!shas[i][0] || !kinds[i][0])
			continue;		/* 捕获失败：不锚 */
		o = aik_json_new_obj();
		if (!o)
			goto out;
		t = aik_json_new_str(ev[i].path);
		if (!t || aik_json_obj_put(o, "path", t) < 0) {
			aik_json_free(t);
			aik_json_free(o);
			goto out;
		}
		t = aik_json_new_str(kinds[i]);
		if (!t || aik_json_obj_put(o, "kind", t) < 0) {
			aik_json_free(t);
			aik_json_free(o);
			goto out;
		}
		t = aik_json_new_str(shas[i]);
		if (!t || aik_json_obj_put(o, "sha256", t) < 0) {
			aik_json_free(t);
			aik_json_free(o);
			goto out;
		}
		if (aik_json_arr_push(arr, o) < 0) {
			aik_json_free(o);
			goto out;
		}
	}
	if (aik_json_dump(arr, &out, &dummy) < 0)
		out = NULL;
out:
	aik_json_free(arr);
	return out;
}

/* redo 侧：按 path 查锚（空/损 JSON=不命中，走 legacy）。0=查过（命中
 * 与否见 anchored 回填）；不返回错误——锚损即 legacy，不阻断 redo。 */
static void redo_anchor_get(const char *redo_json, const char *path,
			    snap_ent *e)
{
	char perr[96];
	aik_json *arr;
	size_t n, i;

	e->anchored = 0;
	if (!redo_json || !redo_json[0] || !strcmp(redo_json, "[]"))
		return;
	arr = aik_json_parse(redo_json, strlen(redo_json), perr, sizeof(perr));
	if (!arr || aik_json_typeof(arr) != AIK_JSON_ARR) {
		aik_json_free(arr);
		fputs(L_("occ-redo: redo 锚 JSON 损坏（退化为 legacy "
			 "sidecar 校验）\n"), stderr);
		return;
	}
	n = aik_json_count(arr);
	for (i = 0; i < n; i++) {
		const aik_json *o = aik_json_at(arr, i);
		const aik_json *t;
		const char *s;

		if (!o || aik_json_typeof(o) != AIK_JSON_OBJ)
			continue;
		t = aik_json_get(o, "path");
		if (!t || aik_json_typeof(t) != AIK_JSON_STR ||
		    strcmp(aik_json_str(t), path))
			continue;
		t = aik_json_get(o, "kind");
		s = t && aik_json_typeof(t) == AIK_JSON_STR ? aik_json_str(t) : "";
		snprintf(e->want_kind, sizeof(e->want_kind), "%s", s);
		t = aik_json_get(o, "sha256");
		s = t && aik_json_typeof(t) == AIK_JSON_STR ? aik_json_str(t) : "";
		snprintf(e->want_sha, sizeof(e->want_sha), "%s", s);
		/* 形损锚（kind/sha 缺失）不按命中处理——legacy 更安全 */
		if ((e->want_kind[0] == 's' || e->want_kind[0] == 'a') &&
		    strlen(e->want_sha) == OCC_SHA256_HEX)
			e->anchored = 1;
		break;
	}
	aik_json_free(arr);
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
	rawvec rawv;				/* P-50：FS 实况全集 */
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
	/* P-50：manifest 对账 */
	occ_snap_row *mrows = NULL;
	size_t nmrows = 0;
	const char **mids = NULL;
	size_t nmids = 0;
	struct {
		char *path;
		int action;
	} synth[OCC_UNDO_MAX_FILES];		/* 删标记合成条目 */
	size_t nsynth = 0;
	char (*rshas)[OCC_SHA256_HEX + 1] = NULL;	/* _redo 捕获摘要 */
	char (*rkinds)[8] = NULL;
	char *redo_json = NULL;

	memset(&ev, 0, sizeof(ev));
	memset(&rawv, 0, sizeof(rawv));
	memset(&oldstage, 0, sizeof(oldstage));
	memset(synth, 0, sizeof(synth));
	note_id[0] = '\0';
	if (out)
		memset(out, 0, sizeof(*out));
	if (!db || !session_id || steps < 1) {
		set_err(err, errlen, "%s", L_("occ_undo: bad args（steps 须 ≥1）"));
		return -1;
	}
	if (occ_session_get(db, session_id, &s, err, errlen) != 1) {
		set_err(err, errlen, L_("occ undo: 会话 %s 不存在"), session_id);
		return -1;
	}
	if (!strcmp(s.status, OCC_ST_RUNNING)) {
		/* P-48：真在跑等本轮收口即可；楔死/强杀残留的 running 挡
		 * 路——给 unstuck 指引（轻量归位，不像 recover 全重放） */
		set_err(err, errlen,
			L_("occ undo: 会话正在执行（status=running），"
			  "请等本轮结束或先中断，或 `occ unstuck --session %s`"
			  " 轻量解僵（不重放）"), session_id);
		return -1;
	}
	if (occ_msg_list(db, session_id, &rows, &n, err, errlen))
		return -1;
	if (!n) {
		set_err(err, errlen, "%s", L_("occ undo: 会话没有消息，无可撤销"));
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
		set_err(err, errlen, "%s", L_("occ undo: 没有可撤销的用户消息"));
		goto out;
	}
	if ((size_t)steps > nusers) {
		set_err(err, errlen,
			L_("occ undo: 只有 %zu 步可撤（请求 %d 步）"), nusers,
			steps);
		goto out;
	}
	bidx = users[nusers - (size_t)steps];
	boundary_rowid = rows[bidx].rowid;

	root = resolve_root(snaproot, rootbuf, sizeof(rootbuf));
	if (!root) {
		set_err(err, errlen, "%s", L_("occ undo: 无法解析快照根（无 HOME）"));
		goto out;
	}

	/* ---- 先收集：范围内全部消息的快照目录（首见=最早=改动前状态） */
	for (i = bidx; i < n; i++)
		scan_msg_dir(root, session_id, rows[i].id, &ev, &rawv);

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

	/* ---- P-50 对账：DB manifest（occ_snap）载入 + anchored 匹配 +
	 *      删标记检测（db 内无行=全 legacy，零行为变化） ---- */
	{
		nmids = n - bidx;
		mids = calloc(nmids, sizeof(*mids));
		if (!mids) {
			set_err(err, errlen, "occ undo: oom");
			goto out;
		}
		for (i = bidx; i < n; i++)
			mids[i - bidx] = rows[i].id;
		/* DB 是信任根——读不动的库上不做任何文件动作（fail closed） */
		if (occ_snap_rows_for_msgs(db, mids, nmids, &mrows, &nmrows,
					   terr, sizeof(terr))) {
			set_err(err, errlen, L_("occ undo: manifest 读失败：%s"),
				terr);
			goto out;
		}
	}
	/* ③ 删标记检测：manifest 有行而该 path 的快照/墓碑在范围内任何
	 * msg 目录都不在盘（raw=FS 实况全集）→ 合成 failed 条目 + stderr
	 * 人话——该文件不回滚；rc 仍 0、DB 提交照常（P-49 部分失败语义）。
	 * 同 path 多 manifest 行只合成一条；合成条目也占 result 额度
	 * （OCC_UNDO_MAX_FILES 满即止——stderr 已逐条报过）。 */
	for (i = 0; i < nmrows; i++) {
		int present = 0, dup = 0;
		size_t k, j;

		for (k = 0; k < rawv.n; k++)
			if (!strcmp(rawv.v[k].path, mrows[i].path)) {
				present = 1;
				break;
			}
		if (present)
			continue;
		for (j = 0; j < nsynth; j++)
			if (!strcmp(synth[j].path, mrows[i].path)) {
				dup = 1;
				break;
			}
		if (dup)
			continue;
		fprintf(stderr, L_("occ-undo: DB manifest 有记录但快照缺失"
			"（被删除？）：%s——该文件未回滚\n"), mrows[i].path);
		if (nsynth >= OCC_UNDO_MAX_FILES)
			continue;		/* result 满额：stderr 已报 */
		synth[nsynth].path = strdup(mrows[i].path);
		if (synth[nsynth].path) {
			synth[nsynth].action =
				!strcmp(mrows[i].kind, "absent") ?
				OCC_UNDO_DELETE : OCC_UNDO_RESTORE;
			nsynth++;
		}
	}
	if (!ev.n && !nsynth) {
		set_err(err, errlen, "%s",
			L_("occ undo: 被撤范围没有文件快照（纯对话轮或快照"
			  "缺失）——不改库、不隐藏消息"));
		goto out;
	}
	/* ①② anchored 匹配：对每个 ev 条目查 manifest (msg,path)——
	 * 命中拷期望并校 kind↔action 一致（换墓碑/换内容类型即判死）；
	 * 未命中但 path 出现在同会话其它 msg 的 manifest 行=搬目录判死；
	 * 都不命中=legacy（P-49 sidecar 校验原路）。 */
	for (i = 0; i < ev.n; i++) {
		snap_ent *e = &ev.v[i];
		size_t r;
		int hit = 0, other_msg = 0;

		for (r = 0; r < nmrows; r++) {
			if (strcmp(mrows[r].path, e->path))
				continue;
			if (!strcmp(mrows[r].message_id, e->msg)) {
				hit = 1;
				break;
			}
			other_msg = 1;		/* 同 path 其余 msg 行：搬动嫌疑 */
		}
		if (hit) {
			e->anchored = 1;
			snprintf(e->want_kind, sizeof(e->want_kind), "%s",
				 mrows[r].kind);
			snprintf(e->want_sha, sizeof(e->want_sha), "%s",
				 mrows[r].sha256);
			if ((!strcmp(e->want_kind, "absent")) !=
			    (e->action == OCC_UNDO_DELETE)) {
				e->failed_before = 1;
				fprintf(stderr, L_("occ-undo: 快照类型与 DB "
					"manifest 不符（被篡改？）：%s\n"),
					e->path);
			}
		} else if (other_msg) {
			e->failed_before = 1;
			fprintf(stderr, L_("occ-undo: 快照出现位置与 DB "
				"manifest 不符（被搬动？）：%s\n"), e->path);
		}
	}

	/* ---- redo 捕获（撤销前现状；已存在不覆盖）+ P-50 锚摘要回传 ---- */
	if (ev.n) {
		rshas = calloc(ev.n, sizeof(*rshas));
		rkinds = calloc(ev.n, sizeof(*rkinds));
		if (!rshas || !rkinds) {
			set_err(err, errlen, "occ undo: oom");
			goto out;
		}
	}
	for (i = 0; i < ev.n; i++)
		redo_capture(root, session_id, &ev.v[i], rshas[i],
			     rkinds[i]);
	/* 锚数组覆盖全部 _redo 在盘文件（含叠加 undo 的先前捕获——其摘要
	 * 由 redo_capture 读现盘回填）；构建失败=空锚，redo 全 legacy */
	redo_json = redo_json_build(ev.v, ev.n, rshas, rkinds);

	/* ---- 回滚文件（单个失败标记，不中止——部分失败如实列出） ---- */
	for (i = 0; i < ev.n; i++) {
		if (ev.v[i].failed_before) {
			/* P-50：对账阶段已判死（stderr 已说原因）——不碰
			 * 目标文件，如实标 failed */
			ev.v[i].failed = 1;
			continue;
		}
		if (apply_restore(root, session_id, &ev.v[i])) {
			ev.v[i].failed = 1;
			fprintf(stderr, L_("occ-undo: 回滚失败 %s\n"),
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
		set_err(err, errlen, "%s", L_("occ undo: 旧 stage hidden_json 损坏"));
		goto out;
	}
	hidden_json = merge_ids_json(have_old == 1 ? oldstage.hidden_json :
				     NULL, (const char *const *)newly_hidden,
				     nhidden);
	if (!hidden_json) {
		set_err(err, errlen, "occ undo: hidden_json oom");
		goto out;
	}
	/* files_json（本 stage 全量恢复集；redo 据此查 _redo 段）。
	 * P-50：ev 可为空（纯删标记场景——快照全缺、仅合成条目），
	 * calloc(0) 可测地返回 NULL 的实现下不能按 oom 处理 */
	if (ev.n) {
		file_paths = calloc(ev.n, sizeof(*file_paths));
		if (!file_paths) {
			set_err(err, errlen, "occ undo: oom");
			goto out;
		}
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
			strncat(filelist, L_("、"), sizeof(filelist) -
				strlen(filelist) - 1);
		strncat(filelist, ev.v[i].path, sizeof(filelist) -
			strlen(filelist) - 1);
	}
	if (ev.n && strlen(filelist) + 4 < sizeof(filelist))
		strncat(filelist, "…", sizeof(filelist) - strlen(filelist) - 1);
	snprintf(note, sizeof(note),
		 L_("[occ 注记] 已撤销最近 %d 步：%zu 条消息不再进上下文，"
		   "%zu 个文件回滚到改动前（%s）。无快照不回滚项 %zu 处"
		   "（bash 改动等）。发送新消息即确认撤销（此后不可 redo），"
		   "或执行 occ redo 恢复。"),
		 steps, nhidden, ev.n, filelist[0] ? filelist : L_("见回滚列表"),
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
			fprintf(stderr, L_("occ-undo: 撤旧注记失败（%s）\n"),
				terr);
	}

	/* 5) stage 行（边界/注记/文件清单/本 stage 隐藏集/redo 锚） */
	if (occ_revert_put(db, session_id, rows[bidx].id, note_id,
			   files_json, hidden_json, redo_json, err, errlen)) {
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
		/* P-50：删标记合成条目（全部 failed=1，占 result 额度） */
		for (i = 0; i < nsynth; i++)
			if (result_push_file(out, synth[i].path,
					     synth[i].action, 1)) {
				/* oom：已推条目保留 */
				break;
			}
	}
	rc = 0;
out:
	occ_revert_row_free(&oldstage);
	entvec_free(&ev);
	rawvec_free(&rawv);
	occ_snap_rows_free(mrows, nmrows);
	free(mids);
	occ_tc_rows_free(tcs, ntc);
	free(users);
	if (rows)
		occ_msg_rows_free(rows, n);
	free(hidden_json);
	free(files_json);
	free(redo_json);
	free(rshas);
	free(rkinds);
	for (i = 0; i < nsynth; i++)
		free(synth[i].path);
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
			set_err(err, errlen, L_("occ redo: 会话 %s 不存在"),
				session_id);
			return -1;
		}
	}
	{
		int g = occ_revert_get(db, session_id, &st, err, errlen);

		if (g < 0)
			return -1;
		if (g == 0) {
			set_err(err, errlen, "%s",
				L_("occ redo: 没有待恢复的撤销（无 stage 态）"));
			return -1;
		}
	}
	root = resolve_root(snaproot, rootbuf, sizeof(rootbuf));
	if (!root) {
		set_err(err, errlen, "%s", L_("occ redo: 无法解析快照根（无 HOME）"));
		goto out;
	}
	if (json_to_str_array(st.files_json, &files, &nfiles) < 0) {
		set_err(err, errlen, "%s", L_("occ redo: files_json 损坏"));
		goto out;
	}
	/* 1) 文件还原（_redo 段 → 目标）。P-50：stage.redo_json 锚命中
	 *    的条目按 {kind,sha256} 比对（sidecar 免读——重造无效）；
	 *    空/损/未命中=legacy（P-49 sidecar/规范形态检查原路不动） */
	for (i = 0; i < nfiles; i++) {
		snap_ent e;
		int failed = 0;

		memset(&e, 0, sizeof(e));
		snprintf(e.path, sizeof(e.path), "%s", files[i]);
		redo_anchor_get(st.redo_json, files[i], &e);
		apply_redo(root, session_id, &e, &failed);
		if (failed) {
			nfailed++;
			fprintf(stderr, L_("occ-redo: 还原失败 %s\n"), files[i]);
		}
		if (out && out->nfiles < OCC_UNDO_MAX_FILES)
			result_push_file(out, files[i], OCC_UNDO_RESTORE,
					 failed);
	}
	/* 2) 精确解隐藏（只解本 stage 的；早期已 commit 的保持隐藏） */
	if (json_to_str_array(st.hidden_json, &hidden, &nhidden) < 0) {
		set_err(err, errlen, "%s", L_("occ redo: hidden_json 损坏"));
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
		fprintf(stderr, L_("occ-redo: 删注记失败（%s）\n"), terr);
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
			L_("occ redo: 完成，但 %zu 个文件还原失败（见 stderr）"),
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
		fprintf(stderr, L_("occ-commit: 清 stage 失败（%s）\n"), terr);
	root = resolve_root(snaproot, rootbuf, sizeof(rootbuf));
	if (root) {
		char dir[768];

		if (snprintf(dir, sizeof(dir), "%s/%s/_redo", root,
			     session_id) < (int)sizeof(dir))
			rm_rf(dir);
	}
}
