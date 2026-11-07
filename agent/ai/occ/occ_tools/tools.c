/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tools.c - occ 工具六件套实现（T9b1；OPENCODE-PLAN §7）
 *
 * read/write/edit/glob/grep 直接实现（朴素、零第三方依赖：fnmatch +
 * 字节子串搜索，不引 PCRE——任务书明示）；bash 经 occ_tools/sandbox.c
 * 的 aik-sandbox 对接（namespace 隔离；不可用即拒）。
 *
 * 每次执行的副作用链（occ_tool_exec 单入口）：
 *   参数解析 → （write/edit）快照 stage → 执行 → trace JSONL →
 *   （ctx->db 给定）occ_toolcall 行 + tool 结果消息单事务落库
 *   （durable：先落库再回灌——loop 下轮从库重读，OPENCODE-PLAN §6）。
 *
 * 结果文本化：成功=payload（read/grep 带行号等上下文），失败=
 * "ERROR: <人话>"；一律 UTF-8 边界安全截断至 8KB。
 */
#define _GNU_SOURCE
#include "occ_tools.h"
#include "occ_tools_priv.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "store/store_json.h"

/* ---- 结果缓冲（occ_tools_priv.h 契约实现） ---- */

void occ_ob_put(occ_obuf *o, const char *s, size_t n)
{
	o->total += n;
	if (o->len + n <= OCC_TOOL_OUT_MAX) {
		memcpy(o->buf + o->len, s, n);
		o->len += n;
	} else {
		size_t room = OCC_TOOL_OUT_MAX > o->len ?
			      OCC_TOOL_OUT_MAX - o->len : 0;

		if (room) {
			size_t keep = n < room ? n : room;
			size_t cut = keep;

			/* UTF-8 边界回退（不切多字节字符） */
			while (cut > 0 &&
			       ((unsigned char)s[cut] & 0xC0) == 0x80)
				cut--;
			if (cut == 0)
				cut = keep;
			memcpy(o->buf + o->len, s, cut);
			o->len += cut;
		}
		o->truncated = 1;
	}
}

void occ_ob_puts(occ_obuf *o, const char *s)
{
	occ_ob_put(o, s, strlen(s));
}

void occ_ob_printf(occ_obuf *o, const char *fmt, ...)
{
	char tmp[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	occ_ob_puts(o, tmp);
}

/* ---- 参数 schema（LLM 请求 tools 定义；键序=此处字面序） ---- */

static const char SCHEMA_READ[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"path\":{\"type\":\"string\",\"description\":\"文件绝对或相对"
	"（工作目录）路径\"},"
	"\"offset\":{\"type\":\"integer\",\"description\":\"起始行号"
	"（1 起；缺省 1）\",\"minimum\":1},"
	"\"limit\":{\"type\":\"integer\",\"description\":\"读取行数上限"
	"（缺省 500）\",\"minimum\":1}"
	"},\"required\":[\"path\"]}";

static const char SCHEMA_WRITE[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"path\":{\"type\":\"string\",\"description\":\"目标文件路径"
	"（限工作目录子树、/tmp、/var/ai）\"},"
	"\"content\":{\"type\":\"string\",\"description\":\"完整文件内容"
	"（整文件覆写）\"}"
	"},\"required\":[\"path\",\"content\"]}";

static const char SCHEMA_EDIT[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"path\":{\"type\":\"string\",\"description\":\"目标文件路径\"},"
	"\"oldString\":{\"type\":\"string\",\"description\":\"被替换的精确"
	"字符串（必须在文件中唯一，或配合 replaceAll）\"},"
	"\"newString\":{\"type\":\"string\",\"description\":\"替换后的"
	"字符串\"},"
	"\"replaceAll\":{\"type\":\"boolean\",\"description\":\"true=替换"
	"全部出现；缺省 false（多处命中即报错）\"}"
	"},\"required\":[\"path\",\"oldString\",\"newString\"]}";

static const char SCHEMA_GLOB[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"pattern\":{\"type\":\"string\",\"description\":\"glob 模式："
	"** 跨任意层目录，* 不跨 /；点文件需模式显式以 . 开头"
	"（如 **/.*）\"},"
	"\"path\":{\"type\":\"string\",\"description\":\"搜索根目录"
	"（缺省工作目录）\"}"
	"},\"required\":[\"pattern\"]}";

static const char SCHEMA_GREP[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"pattern\":{\"type\":\"string\",\"description\":\"搜索文本"
	"（朴素字节子串匹配，大小写敏感；中文可用）\"},"
	"\"path\":{\"type\":\"string\",\"description\":\"搜索目标：文件或"
	"目录（缺省工作目录，递归）\"},"
	"\"glob\":{\"type\":\"string\",\"description\":\"仅搜文件名匹配"
	"该 glob 的文件（如 *.c）\"}"
	"},\"required\":[\"pattern\"]}";

static const char SCHEMA_BASH[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"command\":{\"type\":\"string\",\"description\":\"要执行的 shell"
	" 命令（在 aik-sandbox 隔离区内以 /bin/sh -c 运行；工作目录以读写"
	"方式挂入，宿主其余路径不可见；网络保留）\"},"
	"\"workdir\":{\"type\":\"string\",\"description\":\"工作目录"
	"（缺省 occ 启动目录；将以读写方式挂入沙箱，须与沙箱同 uid 属主）\"},"
	"\"timeout\":{\"type\":\"integer\",\"description\":\"超时秒数"
	"（缺省 60，上限同全局配置）\",\"minimum\":1}"
	"},\"required\":[\"command\"]}";

static const occ_tool_def TOOLS[] = {
	{ OCC_T_READ,  "读取文件内容（带行号，支持行窗 offset/limit）。二进制文件拒绝。", SCHEMA_READ },
	{ OCC_T_WRITE, "整文件写入（覆盖），父目录不存在则递归创建；写前自动快照原文件（可撤销地基）。", SCHEMA_WRITE },
	{ OCC_T_EDIT,  "精确字符串替换：oldString 必须在文件中唯一命中，或 replaceAll=true 全部替换；未命中/多处命中不带 replaceAll 均报错。", SCHEMA_EDIT },
	{ OCC_T_GLOB,  "文件模式匹配（递归，** 跨目录）；返回匹配路径列表。", SCHEMA_GLOB },
	{ OCC_T_GREP,  "文本搜索（字节子串匹配，含中文；返回 文件:行号:行）。", SCHEMA_GREP },
	{ OCC_T_BASH,  "在 aik-sandbox 隔离区（mount/pid/uts namespace，能力裁剪）内执行 shell 命令；沙箱不可用时拒绝执行（绝不裸跑）。", SCHEMA_BASH },
};

const occ_tool_def *occ_tool_defs(size_t *n)
{
	if (n)
		*n = sizeof(TOOLS) / sizeof(TOOLS[0]);
	return TOOLS;
}

int occ_tool_is_known(const char *name)
{
	size_t i;

	for (i = 0; i < sizeof(TOOLS) / sizeof(TOOLS[0]); i++)
		if (!strcmp(TOOLS[i].name, name))
			return 1;
	return 0;
}

/* ---- 通用小件 ---- */

long long occ_monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

size_t occ_utf8_trunc(const char *src, size_t len, size_t max,
		      char *dst, size_t dstlen)
{
	size_t keep = len <= max ? len : max;

	(void)dstlen;
	if (keep < len) {
		size_t cut = keep;

		while (cut > 0 && ((unsigned char)src[cut] & 0xC0) == 0x80)
			cut--;
		if (cut == 0)
			cut = keep;	/* 防御：整段续字节 */
		keep = cut;
	}
	memcpy(dst, src, keep);
	dst[keep] = '\0';
	return keep;
}

int occ_path_is_under(const char *abs, const char *base)
{
	size_t lb;

	if (!abs || !base || abs[0] != '/' || base[0] != '/')
		return 0;
	lb = strlen(base);
	if (lb > 1 && base[lb - 1] == '/')
		lb--;
	if (!strncmp(abs, base, lb) && abs[lb] == '\0')
		return 1;
	if (lb == 1)
		return 1;			/* base="/" */
	return !strncmp(abs, base, lb) && abs[lb] == '/';
}

int occ_write_target_ok(const char *abs, const char *cwd)
{
	static char home_occ[512];
	static int home_occ_init;
	const char *home;

	if (!abs || abs[0] != '/')
		return 0;
	if (!home_occ_init) {
		home = getenv("HOME");
		if (home)
			snprintf(home_occ, sizeof(home_occ), "%s/.occ",
				 home);
		home_occ_init = 1;
	}
	if (home_occ[0] && occ_path_is_under(abs, home_occ))
		return 0;			/* 会话库/快照区拒绝 */
	if (occ_path_is_under(abs, "/tmp") ||
	    occ_path_is_under(abs, "/var/ai"))
		return 1;
	if (cwd && cwd[0] == '/' && occ_path_is_under(abs, cwd))
		return 1;
	return 0;
}

/* mkdir -p（忽略已存在） */
static int mkdirs(const char *path)
{
	char buf[4096];
	size_t i, n = strlen(path);

	if (!n || n + 1 > sizeof(buf))
		return -1;
	memcpy(buf, path, n + 1);
	for (i = 1; i < n; i++) {
		if (buf[i] == '/') {
			buf[i] = '\0';
			if (mkdir(buf, 0777) && errno != EEXIST)
				return -1;
			buf[i] = '/';
		}
	}
	if (mkdir(buf, 0777) && errno != EEXIST)
		return -1;
	return 0;
}

/* 读整文件（上限 max 字节；*out heap NUL 结尾） */
static int read_whole(const char *path, size_t max, char **out, size_t *len)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long sz;

	if (!f)
		return -1;
	if (fseek(f, 0, SEEK_END)) {
		fclose(f);
		return -1;
	}
	sz = ftell(f);
	if (sz < 0 || (unsigned long)sz > max) {
		fclose(f);
		errno = EFBIG;
		return -1;
	}
	rewind(f);
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		errno = ENOMEM;
		return -1;
	}
	if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return -1;
	}
	fclose(f);
	buf[sz] = '\0';
	*out = buf;
	*len = (size_t)sz;
	return 0;
}

static int is_binary(const char *buf, size_t len)
{
	return memchr(buf, '\0', len) != NULL;
}

/* 朴素字节子串搜索（不依赖 GNU memmem） */
static const char *byte_search(const char *hay, size_t hlen,
			       const char *needle, size_t nlen)
{
	if (nlen == 0)
		return hay;
	if (hlen < nlen)
		return NULL;
	for (size_t i = 0; i + nlen <= hlen; i++)
		if (hay[i] == needle[0] && !memcmp(hay + i, needle, nlen))
			return hay + i;
	return NULL;
}

static size_t count_occurrences(const char *hay, size_t hlen,
				const char *needle, size_t nlen)
{
	size_t n = 0;
	size_t off = 0;

	if (!nlen)
		return 0;
	while (off < hlen) {
		const char *hit = byte_search(hay + off, hlen - off,
					      needle, nlen);

		if (!hit)
			break;
		n++;
		off = (size_t)(hit - hay) + nlen;
	}
	return n;
}

/* ---- 参数视图（args JSON → 便捷取值；解析失败按缺失处理） ---- */

typedef struct {
	aik_json *root;			/* NULL=无/坏参数 */
} occ_args;

static void args_init(occ_args *a, const char *args_json)
{
	char err[128];

	a->root = NULL;
	if (!args_json || !args_json[0] || !strcmp(args_json, "{}"))
		return;
	a->root = aik_json_parse(args_json, strlen(args_json),
				 err, sizeof(err));
}

static void args_free(occ_args *a)
{
	if (a->root)
		aik_json_free(a->root);
	a->root = NULL;
}

static const char *args_str(const occ_args *a, const char *key)
{
	if (!a->root)
		return NULL;
	return aik_json_str(aik_json_get(a->root, key));
}

static long long args_int(const occ_args *a, const char *key, long long dflt)
{
	const aik_json *v;

	if (!a->root)
		return dflt;
	v = aik_json_get(a->root, key);
	if (!v)
		return dflt;
	if (aik_json_typeof(v) == AIK_JSON_STR)
		return atoll(aik_json_str(v));
	return aik_json_int(v);
}

static int args_bool(const occ_args *a, const char *key)
{
	const aik_json *v;

	if (!a->root)
		return 0;
	v = aik_json_get(a->root, key);
	if (!v)
		return 0;
	if (aik_json_typeof(v) == AIK_JSON_STR)
		return strcasecmp(aik_json_str(v), "true") == 0;
	return aik_json_bool(v);
}

/* 工作目录（优先 ctx，缺省 getcwd；失败 NULL） */
static const char *ctx_cwd(const occ_tool_ctx *ctx, char *buf, size_t buflen)
{
	if (ctx->workdir && ctx->workdir[0]) {
		snprintf(buf, buflen, "%s", ctx->workdir);
		return buf;
	}
	return getcwd(buf, buflen);
}

/* 路径参数 → 绝对路径（相对按工作目录；存在则 realpath 归一，
 * 不存在则父目录归一 + 基名拼接——write 新文件路径）。
 * b2：主体抽出为 occ_resolve_path（revert.c undo 以 session.workdir
 * 同口径解析历史 toolcall 的 file_path）。 */
int occ_resolve_path(const char *workdir, const char *raw,
		     char *out, size_t outlen)
{
	char trial[4200];

	if (!raw || !raw[0])
		return -1;
	if (raw[0] == '/') {
		snprintf(trial, sizeof(trial), "%s", raw);
	} else {
		if (!workdir || !workdir[0])
			return -1;
		snprintf(trial, sizeof(trial), "%s/%s", workdir, raw);
	}
	if (realpath(trial, out))
		return 0;
	{
		/*
		 * 目标不存在（write 新文件等）：向上找最近的现存祖先
		 * （父目录可多级缺失——write 负责递归建），归一后拼回
		 * 缺失后缀。
		 */
		char parent[4200];
		char rp[4200];
		size_t plen, rlen, slen;
		int up;

		snprintf(parent, sizeof(parent), "%s", trial);
		for (up = 0; up < 64; up++) {
			char *slash = strrchr(parent, '/');

			if (!slash || slash == parent)
				return -1;
			*slash = '\0';
			if (realpath(parent, rp))
				break;
		}
		if (up >= 64)
			return -1;
		plen = strlen(parent);
		rlen = strlen(rp);
		slen = strlen(trial) - plen;	/* 含前导 '/' 的后缀 */
		if (rlen + slen + 1 > outlen)
			return -1;
		memcpy(out, rp, rlen);
		memcpy(out + rlen, trial + plen, slen + 1);
	}
	return 0;
}

static int resolve_arg_path(const occ_tool_ctx *ctx, const char *raw,
			    char *out, size_t outlen)
{
	char cwd[4096];

	if (raw && raw[0] != '/')
		return occ_resolve_path(ctx_cwd(ctx, cwd, sizeof(cwd)), raw,
					out, outlen);
	return occ_resolve_path(NULL, raw, out, outlen);
}

/* ---- read ---- */

static int tool_read(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *path = args_str(a, "path");
	char abs[4096];
	char *data = NULL;
	size_t len = 0;
	long long offset = args_int(a, "offset", 1);
	long long limit = args_int(a, "limit", 500);
	size_t lineno = 0, shown = 0;

	if (!path) {
		occ_ob_puts(o, "ERROR: read 缺少参数 path");
		return -1;
	}
	if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
		occ_ob_printf(o, "ERROR: read 路径无法解析：%s", path);
		return -1;
	}
	if (read_whole(abs, 4 * 1024 * 1024, &data, &len)) {
		if (errno == EFBIG) {
			occ_ob_printf(o, "ERROR: read %s 过大"
				      "（上限 4MB）", abs);
		} else {
			occ_ob_printf(o, "ERROR: read %s 失败：%s", abs,
				      strerror(errno));
		}
		return -1;
	}
	if (is_binary(data, len)) {
		free(data);
		occ_ob_printf(o, "ERROR: read %s 拒绝读取二进制文件"
			      "（%zu 字节，含 NUL）", abs, len);
		return -1;
	}
	if (offset < 1)
		offset = 1;
	if (limit < 1)
		limit = 1;
	{
		char *p = data;
		char *end = data + len;

		while (p < end) {
			char *nl = memchr(p, '\n', (size_t)(end - p));
			size_t ll = nl ? (size_t)(nl - p) :
					 (size_t)(end - p);

			lineno++;
			if ((long long)lineno >= offset &&
			    (long long)shown < limit) {
				occ_ob_printf(o, "%6zu\t", lineno);
				occ_ob_put(o, p, ll);
				occ_ob_puts(o, "\n");
				shown++;
			}
			p = nl ? nl + 1 : end;
			if ((long long)shown >= limit)
				break;
		}
	}
	free(data);
	if (!shown && lineno)
		occ_ob_printf(o, "（%s 共 %zu 行，offset=%lld 超出范围）",
			      abs, lineno, offset);
	else if (!shown)
		occ_ob_printf(o, "（%s 为空文件）", abs);
	else
		occ_ob_printf(o, "（%s 第 %lld-%zu 行，共 %zu 行）",
			      abs, offset, offset + shown - 1, lineno);
	return 0;
}

/* ---- write ---- */

static int write_guard(const occ_tool_ctx *ctx, const char *abs, occ_obuf *o)
{
	char cwd[4096];
	const char *cwdp = ctx_cwd(ctx, cwd, sizeof(cwd));

	if (occ_write_target_ok(abs, cwdp ? cwdp : ""))
		return 0;
	occ_ob_printf(o, "ERROR: 目标 %s 越界：允许域=工作目录子树 ∪ "
		      "/tmp ∪ /var/ai（W1 惯例；~/.occ 一律拒绝）", abs);
	return -1;
}

static int tool_write(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *path = args_str(a, "path");
	const char *content = args_str(a, "content");
	char abs[4096];
	char snapbuf[512];
	FILE *f;
	size_t clen;

	if (!path || !content) {
		occ_ob_puts(o, "ERROR: write 缺少参数 path/content");
		return -1;
	}
	if (strlen(content) > 512 * 1024) {
		occ_ob_puts(o, "ERROR: write content 过大（上限 512KB）");
		return -1;
	}
	if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
		occ_ob_printf(o, "ERROR: write 路径无法解析：%s", path);
		return -1;
	}
	if (write_guard(ctx, abs, o))
		return -1;
	/* 快照 stage（原文件不存在 → ABSENT 墓碑；/undo 地基，b2 接） */
	occ_snapshot_stage(ctx->snaproot, ctx->session_id, ctx->msg_id,
			   abs, snapbuf, sizeof(snapbuf));
	/* 父目录递归建 */
	{
		char *slash = strrchr(abs, '/');
		char parent[4096];

		if (slash && slash != abs) {
			size_t pl = (size_t)(slash - abs);

			memcpy(parent, abs, pl);
			parent[pl] = '\0';
			if (mkdirs(parent)) {
				occ_ob_printf(o, "ERROR: write 建父目录 %s "
					      "失败：%s", parent,
					      strerror(errno));
				return -1;
			}
		}
	}
	f = fopen(abs, "wb");
	if (!f) {
		occ_ob_printf(o, "ERROR: write 打开 %s 失败：%s", abs,
			      strerror(errno));
		return -1;
	}
	clen = strlen(content);
	if (clen && fwrite(content, 1, clen, f) != clen) {
		fclose(f);
		occ_ob_printf(o, "ERROR: write %s 写入失败：%s", abs,
			      strerror(errno));
		return -1;
	}
	if (fclose(f)) {
		occ_ob_printf(o, "ERROR: write %s 关闭失败：%s", abs,
			      strerror(errno));
		return -1;
	}
	occ_ob_printf(o, "已写入 %s（%zu 字节）", abs, clen);
	return 0;
}

/* ---- edit ---- */

static int tool_edit(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *path = args_str(a, "path");
	const char *olds = args_str(a, "oldString");
	const char *news = args_str(a, "newString");
	int all = args_bool(a, "replaceAll");
	char abs[4096];
	char snapbuf[512];
	char *data = NULL, *out = NULL;
	size_t len = 0, olen, nold, nnew, nocc;
	FILE *f;

	if (!path || !olds || !news) {
		occ_ob_puts(o, "ERROR: edit 缺少参数"
			    " path/oldString/newString");
		return -1;
	}
	if (!olds[0]) {
		occ_ob_puts(o, "ERROR: edit oldString 为空串"
			    "（必须给出非空精确文本）");
		return -1;
	}
	if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
		occ_ob_printf(o, "ERROR: edit 路径无法解析：%s", path);
		return -1;
	}
	if (write_guard(ctx, abs, o))
		return -1;
	if (read_whole(abs, 8 * 1024 * 1024, &data, &len)) {
		if (errno == EFBIG) {
			occ_ob_printf(o, "ERROR: edit %s 过大（上限 8MB）",
				      abs);
		} else {
			occ_ob_printf(o, "ERROR: edit 读 %s 失败：%s", abs,
				      strerror(errno));
		}
		return -1;
	}
	if (is_binary(data, len)) {
		free(data);
		occ_ob_printf(o, "ERROR: edit %s 拒绝编辑二进制文件"
			      "（含 NUL 字节）", abs);
		return -1;
	}
	nold = strlen(olds);
	nnew = strlen(news);
	nocc = count_occurrences(data, len, olds, nold);
	if (!nocc) {
		free(data);
		occ_ob_printf(o, "ERROR: edit %s 未找到 oldString"
			      "（%zu 字节精确文本，0 次命中）", abs, nold);
		return -1;
	}
	if (nocc > 1 && !all) {
		free(data);
		occ_ob_printf(o, "ERROR: edit %s oldString 命中 %zu 处"
			      "——需改到唯一片段，或 replaceAll=true",
			      abs, nocc);
		return -1;
	}
	/* 快照 stage（原文件必然存在——上面 read_whole 已证） */
	occ_snapshot_stage(ctx->snaproot, ctx->session_id, ctx->msg_id,
			   abs, snapbuf, sizeof(snapbuf));

	out = malloc(len + (nnew > nold ? (nnew - nold) * nocc : 0) + 1);
	if (!out) {
		free(data);
		occ_ob_puts(o, "ERROR: edit 内存不足");
		return -1;
	}
	{
		char *dst = out;
		size_t off = 0;

		while (off < len) {
			const char *hit = byte_search(data + off, len - off,
						      olds, nold);

			if (!hit) {
				memcpy(dst, data + off, len - off);
				dst += len - off;
				break;
			}
			memcpy(dst, data + off, (size_t)(hit - data) - off);
			dst += (size_t)(hit - data) - off;
			memcpy(dst, news, nnew);
			dst += nnew;
			off = (size_t)(hit - data) + nold;
			if (!all) {
				memcpy(dst, data + off, len - off);
				dst += len - off;
				break;
			}
		}
		*dst = '\0';
		olen = (size_t)(dst - out);
	}
	f = fopen(abs, "wb");
	if (!f) {
		free(data);
		free(out);
		occ_ob_printf(o, "ERROR: edit 打开 %s 失败：%s", abs,
			      strerror(errno));
		return -1;
	}
	if (olen && fwrite(out, 1, olen, f) != olen) {
		fclose(f);
		free(data);
		free(out);
		occ_ob_printf(o, "ERROR: edit %s 写入失败：%s", abs,
			      strerror(errno));
		return -1;
	}
	if (fclose(f)) {
		free(data);
		free(out);
		occ_ob_printf(o, "ERROR: edit %s 关闭失败：%s", abs,
			      strerror(errno));
		return -1;
	}
	free(data);
	free(out);
	occ_ob_printf(o, "已编辑 %s：%zu 处替换（%s），文件 %zu → %zu 字节",
		      abs, nocc, all ? "replaceAll" : "唯一命中", len, olen);
	return 0;
}

/* ---- glob ---- */

#define GLOB_MAX_RESULTS 200
#define GLOB_MAX_DEPTH   24
#define GLOB_MAX_COMPS   32

typedef struct {
	char *comps[GLOB_MAX_COMPS];	/* pattern 组件（strdup） */
	size_t ncomps;
	char *results[GLOB_MAX_RESULTS];
	size_t nresults;
	int overflow;
} glob_walk;

static int glob_match_c(const glob_walk *g, size_t ci, size_t ri,
			char **parts, size_t np)
{
	if (ci == g->ncomps)
		return ri == np;
	if (!strcmp(g->comps[ci], "**")) {
		for (size_t k = ri; k <= np; k++)
			if (glob_match_c(g, ci + 1, k, parts, np))
				return 1;
		return 0;
	}
	if (ri < np && !fnmatch(g->comps[ci], parts[ri], FNM_PERIOD))
		return glob_match_c(g, ci + 1, ri + 1, parts, np);
	return 0;
}

/* 递归走查：parts 为当前相对路径组件（heap 拷贝，防 readdir 缓冲复用） */
static void glob_walk_dir(glob_walk *g, const char *dir, char **parts,
			  size_t np, int depth)
{
	DIR *d = opendir(dir);
	struct dirent *de;

	if (!d)
		return;
	if (depth > GLOB_MAX_DEPTH) {
		closedir(d);
		g->overflow = 1;
		return;
	}
	while ((de = readdir(d)) != NULL) {
		char full[4096];
		char *name = strdup(de->d_name);
		struct stat st;

		if (!name)
			continue;
		if (!strcmp(name, ".") || !strcmp(name, "..")) {
			free(name);
			continue;
		}
		snprintf(full, sizeof(full), "%s/%s", dir, name);
		parts[np] = name;
		if (glob_match_c(g, 0, 0, parts, np + 1)) {
			if (g->nresults < GLOB_MAX_RESULTS)
				g->results[g->nresults++] = strdup(full);
			else
				g->overflow = 1;
		}
		if (!stat(full, &st) && S_ISDIR(st.st_mode) &&
		    np + 1 < 60)
			glob_walk_dir(g, full, parts, np + 1, depth + 1);
		free(name);
	}
	closedir(d);
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int tool_glob(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *pattern = args_str(a, "pattern");
	const char *path = args_str(a, "path");
	char root[4096];
	glob_walk g;
	char *parts[64];
	char *pbuf;
	char *save = NULL;
	size_t i;

	if (!pattern || !pattern[0]) {
		occ_ob_puts(o, "ERROR: glob 缺少参数 pattern");
		return -1;
	}
	if (path && path[0]) {
		if (resolve_arg_path(ctx, path, root, sizeof(root))) {
			occ_ob_printf(o, "ERROR: glob 根目录无法解析：%s",
				      path);
			return -1;
		}
	} else if (!ctx_cwd(ctx, root, sizeof(root))) {
		occ_ob_puts(o, "ERROR: glob 无法确定工作目录");
		return -1;
	}
	memset(&g, 0, sizeof(g));
	memset(parts, 0, sizeof(parts));
	pbuf = strdup(pattern);
	if (!pbuf) {
		occ_ob_puts(o, "ERROR: glob 内存不足");
		return -1;
	}
	for (char *tok = strtok_r(pbuf, "/", &save); tok;
	     tok = strtok_r(NULL, "/", &save)) {
		if (g.ncomps < GLOB_MAX_COMPS)
			g.comps[g.ncomps++] = strdup(tok);
	}
	glob_walk_dir(&g, root, parts, 0, 0);
	qsort(g.results, g.nresults, sizeof(char *), cmp_str);
	for (i = 0; i < g.nresults; i++) {
		occ_ob_puts(o, g.results[i]);
		occ_ob_puts(o, "\n");
		free(g.results[i]);
	}
	for (i = 0; i < g.ncomps; i++)
		free(g.comps[i]);
	free(pbuf);
	if (!g.nresults)
		occ_ob_printf(o, "（%s 下无匹配 %s 的路径）", root,
			      pattern);
	else
		occ_ob_printf(o, "（%zu 项%s）", g.nresults,
			      g.overflow ? "，超 200 上限截断" : "");
	return 0;
}

/* ---- grep ---- */

#define GREP_MAX_LINES 100
#define GREP_FILE_MAX  (4 * 1024 * 1024)

static void grep_file(const char *abs, const char *needle,
		      const char *globf, occ_obuf *o, size_t *hits)
{
	char *data = NULL;
	size_t len = 0;
	const char *base = strrchr(abs, '/');
	size_t nlen = strlen(needle);
	size_t lineno = 0;
	char *p, *end;

	base = base ? base + 1 : abs;
	if (globf && globf[0] && fnmatch(globf, base, FNM_PERIOD) != 0)
		return;
	if (read_whole(abs, GREP_FILE_MAX, &data, &len))
		return;				/* 打不开/过大：跳过 */
	if (is_binary(data, len > 4096 ? 4096 : len)) {
		free(data);
		return;				/* 二进制跳过 */
	}
	p = data;
	end = data + len;
	while (p < end && *hits < GREP_MAX_LINES) {
		char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t ll = nl ? (size_t)(nl - p) : (size_t)(end - p);

		lineno++;
		if (byte_search(p, ll, needle, nlen)) {
			occ_ob_printf(o, "%s:%zu:", abs, lineno);
			occ_ob_put(o, p, ll);
			occ_ob_puts(o, "\n");
			(*hits)++;
		}
		p = nl ? nl + 1 : end;
	}
	free(data);
}

static void grep_walk(const char *dir, const char *needle, const char *globf,
		      occ_obuf *o, size_t *hits, int depth)
{
	DIR *d = opendir(dir);
	struct dirent *de;

	if (!d || depth > GLOB_MAX_DEPTH)
		return;
	while ((de = readdir(d)) != NULL && *hits < GREP_MAX_LINES) {
		char full[4096];
		struct stat st;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
		if (stat(full, &st))
			continue;
		if (S_ISDIR(st.st_mode)) {
			grep_walk(full, needle, globf, o, hits, depth + 1);
		} else if (S_ISREG(st.st_mode)) {
			grep_file(full, needle, globf, o, hits);
		}
	}
	closedir(d);
}

static int tool_grep(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *pattern = args_str(a, "pattern");
	const char *path = args_str(a, "path");
	const char *globf = args_str(a, "glob");
	char abs[4096];
	size_t hits = 0;
	struct stat st;

	if (!pattern || !pattern[0]) {
		occ_ob_puts(o, "ERROR: grep 缺少参数 pattern");
		return -1;
	}
	if (path && path[0]) {
		if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
			occ_ob_printf(o, "ERROR: grep 路径无法解析：%s",
				      path);
			return -1;
		}
	} else if (!ctx_cwd(ctx, abs, sizeof(abs))) {
		occ_ob_puts(o, "ERROR: grep 无法确定工作目录");
		return -1;
	}
	if (stat(abs, &st)) {
		occ_ob_printf(o, "ERROR: grep %s 不存在：%s", abs,
			      strerror(errno));
		return -1;
	}
	if (S_ISREG(st.st_mode)) {
		grep_file(abs, pattern, globf, o, &hits);
	} else if (S_ISDIR(st.st_mode)) {
		grep_walk(abs, pattern, globf, o, &hits, 0);
	} else {
		occ_ob_printf(o, "ERROR: grep %s 非普通文件/目录", abs);
		return -1;
	}
	if (!hits)
		occ_ob_printf(o, "（%s 下未匹配到「%s」）", abs, pattern);
	else
		occ_ob_printf(o, "（%zu 行命中%s）", hits,
			      hits >= GREP_MAX_LINES ?
			      "，达 100 行上限截断" : "");
	return 0;
}

/* ---- bash（底座在 sandbox.c） ---- */

int occ_sandbox_bash(const occ_tool_ctx *ctx, const char *command,
		     const char *workdir, long long timeout_ms, void *obuf);

static int tool_bash(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *command = args_str(a, "command");
	const char *workdir = args_str(a, "workdir");
	long long timeout_s = args_int(a, "timeout", 0);

	if (!command || !command[0]) {
		occ_ob_puts(o, "ERROR: bash 缺少参数 command");
		return -1;
	}
	return occ_sandbox_bash(ctx, command, workdir,
				timeout_s > 0 ? timeout_s * 1000 : 0, o);
}

/* ---- 快照 stage ---- */

/*
 * b2 mangle 修复：'%'→%25、'/'→%2f、'.'→%2e 百分比编码（单射，单遍
 * 左到右可安全反解）。b1 的 '/'→'_' 使 /tmp/a_b 与 /tmp/a/b 碰撞同名
 * ——同消息两次写这类路径时快照互相覆盖、undo 会恢复错文件（b2 勘察
 * 发现，报告在案）。'.' 必须编码：否则名为 x.ABSENT 的文件快照与
 * x 的墓碑条目同名不可分。b1 旧编码快照与新编码不兼容（b1 快照从未
 * 被消费，无负担）。
 */
void occ_snap_mangle(const char *abs, char *out, size_t outlen)
{
	size_t i, j = 0;

	for (i = 0; abs[i] && j + 6 < outlen; i++) {
		if (abs[i] == '%') {
			out[j++] = '%';
			out[j++] = '2';
			out[j++] = '5';
		} else if (abs[i] == '/') {
			out[j++] = '%';
			out[j++] = '2';
			out[j++] = 'f';
		} else if (abs[i] == '.') {
			out[j++] = '%';
			out[j++] = '2';
			out[j++] = 'e';
		} else {
			out[j++] = abs[i];
		}
	}
	out[j] = '\0';
}

/*
 * occ_snap_unmangle - occ_snap_mangle 的逆（单遍左到右 %XX 解码）。
 * mangle 是单射 ⇒ 逆映射良定。返回 0；outlen 不足截断（返回 -1）。
 * undo 扫描快照目录时把条目名还原为绝对路径。
 */
int occ_snap_unmangle(const char *mangled, char *out, size_t outlen)
{
	size_t i = 0, j = 0;

	if (!mangled || !out || !outlen)
		return -1;
	while (mangled[i]) {
		if (mangled[i] == '%' && mangled[i + 1] && mangled[i + 2]) {
			char hx[3] = { mangled[i + 1], mangled[i + 2], '\0' };
			char *end = NULL;
			long v = strtol(hx, &end, 16);

			if (end && *end == '\0' && j + 1 < outlen) {
				out[j++] = (char)v;
				i += 3;
				continue;
			}
		}
		if (j + 1 >= outlen)
			return -1;
		out[j++] = mangled[i++];
	}
	out[j] = '\0';
	return 0;
}

/* 快照根解析（参数显式 > OCC_SNAPROOT > ~/.occ/snapshots）；buf 静态
 * 或调用方缓冲均可——返回 NULL=无 HOME。b2 起 revert.c 复用。 */
const char *occ_snap_root(char *buf, size_t buflen)
{
	const char *env = getenv("OCC_SNAPROOT");
	const char *home;

	if (env && env[0])
		return env;
	home = getenv("HOME");
	if (!home)
		return NULL;
	if (snprintf(buf, buflen, "%s/.occ/snapshots", home) >= (int)buflen)
		return NULL;
	return buf;
}

int occ_snapshot_stage(const char *snaproot, const char *session_id,
		       const char *msg_id, const char *abs_path,
		       char *buf, size_t buflen)
{
	char dir[4300], dst[12512], mangled[8192];
	char *data = NULL;
	size_t len = 0;
	FILE *f;
	const char *root = (snaproot && snaproot[0]) ? snaproot : NULL;
	static char defroot[512];

	if (!root) {
		root = occ_snap_root(defroot, sizeof(defroot));
		if (!root)
			return -1;
	}
	if (!session_id || !msg_id || !abs_path || abs_path[0] != '/')
		return -1;
	snprintf(dir, sizeof(dir), "%s/%s/%s", root, session_id, msg_id);
	if (mkdirs(dir)) {
		fprintf(stderr, "occ-snap: mkdir %s: %s\n", dir,
			strerror(errno));
		return -1;
	}
	occ_snap_mangle(abs_path, mangled, sizeof(mangled));
	snprintf(dst, sizeof(dst), "%s/%s", dir, mangled);
	if (buf)
		snprintf(buf, buflen, "%s", dst);
	/*
	 * b2 首见即定：同消息内同文件多次 write/edit 时保留最早快照
	 * （=该消息触及前的原状态）——undo 恢复目标是「进入该回合前」，
	 * 覆盖会把快照推进到中间态。recover 重放 write 也依赖此（不把
	 * 快照污染成已写入态）。内容与墓碑任一已存在即跳过。
	 */
	{
		char probe[12520];

		snprintf(probe, sizeof(probe), "%s", dst);
		if (!access(probe, F_OK))
			return 0;
		snprintf(probe, sizeof(probe), "%s.ABSENT", dst);
		if (!access(probe, F_OK))
			return 0;
	}
	if (read_whole(abs_path, 64 * 1024 * 1024, &data, &len)) {
		if (errno != ENOENT) {
			fprintf(stderr, "occ-snap: read %s: %s\n", abs_path,
				strerror(errno));
			return -1;
		}
		/* 原文件不存在：ABSENT 墓碑（b2 /undo 据此删除还原） */
		snprintf(dst, sizeof(dst), "%s/%s.ABSENT", dir, mangled);
		f = fopen(dst, "wb");
		if (!f)
			return -1;
		fputs("absent\n", f);
		fclose(f);
		return 0;
	}
	f = fopen(dst, "wb");
	if (!f) {
		free(data);
		return -1;
	}
	if (len && fwrite(data, 1, len, f) != len) {
		fclose(f);
		free(data);
		return -1;
	}
	fclose(f);
	free(data);
	return 0;
}

/* ---- 单入口 ---- */

void occ_tool_result_free(occ_tool_result *r)
{
	if (!r)
		return;
	free(r->text);
	memset(r, 0, sizeof(*r));
}

int occ_tool_exec(const occ_tool_ctx *ctx, const char *name,
		  const char *call_id, const char *args_json,
		  occ_tool_result *out)
{
	occ_args a;
	occ_obuf o;
	long long t0, t1;
	int rc = 0;
	char err[160];
	occ_tool_ctx c;

	if (!ctx || !name || !out)
		return -1;
	memset(out, 0, sizeof(*out));
	memset(&o, 0, sizeof(o));
	c = *ctx;
	if (!c.timeout_ms) {
		const char *e = getenv("OCC_TOOL_TIMEOUT_MS");

		c.timeout_ms = (e && atoll(e) > 0) ? atoll(e) :
			       OCC_TOOL_TIMEOUT_DEF_MS;
	}
	args_init(&a, args_json);
	t0 = occ_monotonic_ms();
	if (!strcmp(name, OCC_T_READ)) {
		rc = tool_read(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_WRITE)) {
		rc = tool_write(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_EDIT)) {
		rc = tool_edit(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_GLOB)) {
		rc = tool_glob(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_GREP)) {
		rc = tool_grep(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_BASH)) {
		rc = tool_bash(&c, &a, &o);
	} else {
		occ_ob_printf(&o, "ERROR: 未知工具「%s」（可用：read/write/"
			      "edit/glob/grep/bash）", name);
		rc = -1;
	}
	args_free(&a);
	t1 = occ_monotonic_ms();

	if (o.truncated) {
		/* 截断注记：缓冲已满，直接落尾部 slack（buf 容量
		 * MAX+256，len≤MAX，note≤96——必然放得下） */
		char note[96];
		size_t nl = (size_t)snprintf(note, sizeof(note),
					     "\n…[truncated %zu B]",
					     o.total - o.len);

		if (o.len + nl + 1 <= sizeof(o.buf)) {
			memcpy(o.buf + o.len, note, nl + 1);
			o.len += nl;
		}
	}
	if (!o.len)
		occ_ob_puts(&o, "（无输出）");
	out->text = strdup(o.buf[0] ? o.buf : "（无输出）");
	out->rc = rc ? 1 : 0;
	out->dur_ms = t1 - t0;
	out->out_bytes = o.total;

	/* trace（永不阻断；失败仅 stderr 警告一次） */
	occ_trace_tool(c.trace_dir, c.session_id, c.msg_id, name,
		       args_json, out->rc, out->dur_ms, out->out_bytes);

	/* durable：occ_toolcall 行 + tool 结果消息单事务落库
	 * （先落库再回灌——loop 下轮从库重读） */
	if (c.db && c.session_id && c.msg_id) {
		char msg_id[OCC_ID_LEN];

		if (occ_tool_record(c.db, c.session_id, c.msg_id, name,
				    args_json ? args_json : "{}",
				    out->text, out->rc, out->dur_ms,
				    call_id, msg_id, sizeof(msg_id),
				    out->toolcall_id,
				    sizeof(out->toolcall_id),
				    err, sizeof(err)))
			fprintf(stderr, "occ-tool: durable record 失败："
				"%s\n", err);
	}
	return out->rc;
}
