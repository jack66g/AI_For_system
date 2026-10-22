// SPDX-License-Identifier: GPL-2.0
/*
 * sme_client.c - SME（外部记忆服务）REST 客户端实现
 *
 * 实现说明：
 *   - 基地址优先取环境变量 SME_URL（getenv 运行时读取，支持 QEMU 内
 *     以 http://10.0.2.2:8000 指向宿主机服务），否则用默认回环地址；
 *   - POST 走 local_http_post，GET 走 local_http_get（本次扩展），
 *     不重复造 socket 轮子；
 *   - body 构造只在 text 处做 JSON 转义（对齐 local_chat.c 的
 *     json_escape 行为，经 ai_json_escape 统一实现），meta_json 由
 *     调用者保证合法后原样嵌入（薄客户端不校验不重组）；
 *   - 错误时 out 一定有内容：调用者 printf 即可向用户解释。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "local/local_http.h"
#include "memory/sme_client.h"

/* 单请求默认超时（毫秒）：检索涉及嵌入计算，给足余量 */
#define SME_DEFAULT_TIMEOUT_MS  15000

/* 健康检查/探测超时（毫秒） */
#define SME_HEALTH_TIMEOUT_MS   3000

/* 全量/报告类请求超时（毫秒）：导出、遥测报告、配置检查可能较慢 */
#define SME_BULK_TIMEOUT_MS     30000

/* 导入文件大小上限（字节）：防止误读大文件耗尽内存 */
#define SME_IMPORT_MAX_BYTES    (8 * 1024 * 1024)

const char *sme_base_url(void)
{
	const char *env = getenv("SME_URL");

	if (env && env[0])
		return env;
	return SME_DEFAULT_BASE_URL;
}

/*
 * sme_write_out - 统一写出结果/错误文本（保证 NUL 结尾、截断安全）
 *
 * UTF-8 字节安全（T2 问题 1 实测第三根因）：vsnprintf 按 size 截断
 * 会切在多字节序列中间——SME 记忆命中为中文 JSON 原文，超出调用方
 * 缓冲（如 SME_OUT_BUF_MIN*2）时残缺字符随 mem_ctx 注入请求体回传
 * LLM，服务端 UnicodeDecodeError 拒收。截断后回退到字符边界。
 */
static void sme_write_out(char *out, size_t n, const char *fmt, ...)
{
	va_list ap;
	size_t len, i, lead;

	if (!out || n == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(out, n, fmt, ap);
	va_end(ap);

	len = strlen(out);
	if (len == 0 || (unsigned char)out[len - 1] < 0x80)
		return;   /* 末字节 ASCII：无截断损伤 */
	/* 末字节 >= 0x80：向回找本字符 lead（最多回看 3 字节） */
	i = len - 1;
	lead = 0;
	while (i > 0 && ((unsigned char)out[i] & 0xC0) == 0x80) {
		i--;
		lead++;
	}
	if (((unsigned char)out[i] & 0x80) == 0)
		return;   /* lead 是 ASCII：非截断所致（理论不可达） */
	{
		unsigned char c = (unsigned char)out[i];
		size_t need = (c & 0xE0) == 0xC0 ? 2 :
			      (c & 0xF0) == 0xE0 ? 3 :
			      (c & 0xF8) == 0xF0 ? 4 : 0;

		/* lead 与后续字节数不足 expected 长度 → 不完整序列，截掉 */
		if (need >= 2 && lead + 1 < need)
			out[i] = '\0';
	}
}

/*
 * sme_request_method - 发送请求并处理公共错误路径
 * @method:   "GET"/"POST"/"PATCH"/"DELETE"
 * @url:      完整 URL
 * @body:     请求体（GET/DELETE 传 NULL）
 * @timeout:  超时毫秒
 * @out/@n:   输出缓冲
 * 返回: AI_OK（2xx）/ AI_ERR_NETWORK / AI_ERR_API / AI_ERR_MEMORY
 */
static int sme_request_method(const char *method, const char *url,
			      const char *body, int timeout,
			      char *out, size_t n)
{
	char *resp = NULL;
	char *err = NULL;
	int status = 0;
	int ret;

	if (!out || n == 0)
		return AI_ERR_INVALID_ARG;
	out[0] = '\0';

	if (strcmp(method, "GET") == 0)
		ret = local_http_get(url, timeout, &resp, &err, &status);
	else if (strcmp(method, "DELETE") == 0)
		ret = local_http_delete(url, timeout, &resp, &err, &status);
	else
		ret = local_http_request(method, url, NULL,
					 body ? body : "", timeout,
					 &resp, &err, &status);

	if (ret != AI_OK) {
		/* 连接失败是最常见场景：给出"服务未启动"可操作提示 */
		sme_write_out(out, n, "SME 服务不可达: %s （提示: 检查服务"
			      "是否已启动，或用环境变量 SME_URL 指定地址）",
			      err ? err : ai_error_string(ret));
		free(resp);
		free(err);
		return ret;
	}

	if (status >= 400) {
		sme_write_out(out, n, "SME 服务返回 HTTP %d: %.256s",
			      status, resp ? resp : "(无响应体)");
		free(resp);
		free(err);
		return AI_ERR_API;
	}

	/* 2xx：原始响应体交给调用者（截断保护） */
	if (resp)
		sme_write_out(out, n, "%s", resp);
	else
		sme_write_out(out, n, "(空响应)");
	free(resp);
	free(err);
	return AI_OK;
}

/* 兼容旧调用面：body 非 NULL 走 POST，否则走 GET */
static int sme_request(const char *url, const char *body, int timeout,
		       char *out, size_t n)
{
	return sme_request_method(body ? "POST" : "GET", url, body, timeout,
				  out, n);
}

/*
 * sme_degrade_reason_of - 把 sme_* 返回码映射为结构化降级原因码（W43）
 * 调用方（ask 循环/工具结果回填/UI）据此附注降级说明并如实审计，
 * 不再静默空结果或裸报错。
 */
int sme_degrade_reason_of(int rc)
{
	if (rc == AI_OK)
		return SME_DEGRADED_NONE;
	if (rc == AI_ERR_NETWORK)
		return SME_DEGRADED_UNAVAILABLE;
	if (rc == AI_ERR_API)
		return SME_DEGRADED_HTTP;
	return SME_DEGRADED_NONE;
}

/* 拼接完整端点 URL（容忍 base 末尾多余的 '/'） */
static void sme_url(char *buf, size_t n, const char *path)
{
	const char *base = sme_base_url();
	size_t blen = strlen(base);

	while (blen > 0 && base[blen - 1] == '/')
		blen--;
	snprintf(buf, n, "%.*s%s", (int)blen, base, path);
}

int sme_health(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/health");
	return sme_request(url, NULL, SME_HEALTH_TIMEOUT_MS, out, n);
}

int sme_add(const char *text, const char *meta_json, char *out, size_t n)
{
	char url[512];
	char *esc_text;
	char *body;
	size_t cap;
	int ret;

	if (!text || !text[0]) {
		sme_write_out(out, n, "sme_add: 记忆文本不能为空");
		return AI_ERR_INVALID_ARG;
	}

	esc_text = ai_json_escape(text);
	if (!esc_text) {
		sme_write_out(out, n, "sme_add: 内存不足");
		return AI_ERR_MEMORY;
	}

	/* body: {"text":"..","metadata":{..}}；meta 合法性由调用者保证 */
	cap = strlen(esc_text) + (meta_json ? strlen(meta_json) : 0) + 64;
	body = malloc(cap);
	if (!body) {
		free(esc_text);
		sme_write_out(out, n, "sme_add: 内存不足");
		return AI_ERR_MEMORY;
	}

	if (meta_json && meta_json[0])
		snprintf(body, cap,
			 "{\"text\":\"%s\",\"metadata\":%s}",
			 esc_text, meta_json);
	else
		snprintf(body, cap, "{\"text\":\"%s\"}", esc_text);
	free(esc_text);

	sme_url(url, sizeof(url), "/memories");
	ret = sme_request(url, body, SME_DEFAULT_TIMEOUT_MS, out, n);
	free(body);
	return ret;
}

int sme_search(const char *text, int top_k, char *out, size_t n)
{
	char url[512];
	char *esc_text;
	char *body;
	size_t cap;
	int ret;

	if (!text || !text[0]) {
		sme_write_out(out, n, "sme_search: 查询文本不能为空");
		return AI_ERR_INVALID_ARG;
	}

	esc_text = ai_json_escape(text);
	if (!esc_text) {
		sme_write_out(out, n, "sme_search: 内存不足");
		return AI_ERR_MEMORY;
	}

	/* body: {"text":"..","top_k":N}；top_k<=0 时省略，用服务端默认 */
	cap = strlen(esc_text) + 64;
	body = malloc(cap);
	if (!body) {
		free(esc_text);
		sme_write_out(out, n, "sme_search: 内存不足");
		return AI_ERR_MEMORY;
	}

	if (top_k > 0)
		snprintf(body, cap, "{\"text\":\"%s\",\"top_k\":%d}",
			 esc_text, top_k);
	else
		snprintf(body, cap, "{\"text\":\"%s\"}", esc_text);
	free(esc_text);

	sme_url(url, sizeof(url), "/memories/search");
	ret = sme_request(url, body, SME_DEFAULT_TIMEOUT_MS, out, n);
	free(body);
	return ret;
}

int sme_stats(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/stats");
	return sme_request(url, NULL, SME_HEALTH_TIMEOUT_MS, out, n);
}

/* ---- v2 扩展 ---- */

/*
 * sme_id_safe - 记忆 ID 白名单校验（[A-Za-z0-9_.-]+，防 URL 路径注入）
 */
static int sme_id_safe(const char *id)
{
	static const char ok[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-";

	if (!id || !id[0])
		return 0;
	return strspn(id, ok) == strlen(id);
}

/* 拼接 "/memories/<id>" 前缀 + 动作的 URL */
static void sme_memory_url(char *url, size_t n, const char *id,
			   const char *action)
{
	char path[512];

	if (action && action[0])
		snprintf(path, sizeof(path), "/memories/%s/%s", id, action);
	else
		snprintf(path, sizeof(path), "/memories/%s", id);
	sme_url(url, n, path);
}

int sme_memory_get(const char *memory_id, char *out, size_t n)
{
	char url[512];

	if (!sme_id_safe(memory_id)) {
		sme_write_out(out, n, "sme_memory_get: 非法记忆 ID"
			      "（仅允许字母/数字/_-./，且非空）");
		return AI_ERR_INVALID_ARG;
	}
	sme_memory_url(url, sizeof(url), memory_id, NULL);
	return sme_request(url, NULL, SME_DEFAULT_TIMEOUT_MS, out, n);
}

/*
 * sme_memory_action - hit/archive/restore 共用：空体 POST 到
 * /memories/<id>/<action>（server.py 三端点均无必填 body）
 */
static int sme_memory_action(const char *memory_id, const char *action,
			     char *out, size_t n)
{
	char url[512];

	if (!sme_id_safe(memory_id)) {
		sme_write_out(out, n, "sme_memory_%s: 非法记忆 ID"
			      "（仅允许字母/数字/_-./，且非空）",
			      action ? action : "action");
		return AI_ERR_INVALID_ARG;
	}
	sme_memory_url(url, sizeof(url), memory_id, action);
	/* body 传 ""（非 NULL）：走 POST 且 Content-Length: 0 */
	return sme_request(url, "", SME_DEFAULT_TIMEOUT_MS, out, n);
}

int sme_memory_hit(const char *memory_id, char *out, size_t n)
{
	return sme_memory_action(memory_id, "hit", out, n);
}

int sme_memory_archive(const char *memory_id, char *out, size_t n)
{
	return sme_memory_action(memory_id, "archive", out, n);
}

int sme_memory_restore(const char *memory_id, char *out, size_t n)
{
	return sme_memory_action(memory_id, "restore", out, n);
}

int sme_facts_multi_hop(const char *text, int top_k, char *out, size_t n)
{
	char url[512];
	char *esc_text;
	char *body;
	size_t cap;
	int ret;

	if (!text || !text[0]) {
		sme_write_out(out, n, "sme_facts_multi_hop: 查询文本不能为空");
		return AI_ERR_INVALID_ARG;
	}
	esc_text = ai_json_escape(text);
	if (!esc_text) {
		sme_write_out(out, n, "sme_facts_multi_hop: 内存不足");
		return AI_ERR_MEMORY;
	}
	/* body: {"text":"..","top_k":N}（SearchRequest，top_k 缺省 10） */
	cap = strlen(esc_text) + 64;
	body = malloc(cap);
	if (!body) {
		free(esc_text);
		sme_write_out(out, n, "sme_facts_multi_hop: 内存不足");
		return AI_ERR_MEMORY;
	}
	if (top_k > 0)
		snprintf(body, cap, "{\"text\":\"%s\",\"top_k\":%d}",
			 esc_text, top_k);
	else
		snprintf(body, cap, "{\"text\":\"%s\"}", esc_text);
	free(esc_text);

	sme_url(url, sizeof(url), "/facts/multi_hop");
	ret = sme_request(url, body, SME_DEFAULT_TIMEOUT_MS, out, n);
	free(body);
	return ret;
}

int sme_regions_search(const char *text, int top_k, char *out, size_t n)
{
	char url[512];
	char *esc_text;
	char *body;
	size_t cap;
	int ret;

	if (!text || !text[0]) {
		sme_write_out(out, n, "sme_regions_search: 查询文本不能为空");
		return AI_ERR_INVALID_ARG;
	}
	esc_text = ai_json_escape(text);
	if (!esc_text) {
		sme_write_out(out, n, "sme_regions_search: 内存不足");
		return AI_ERR_MEMORY;
	}
	/* body: {"text":"..","top_k":N}（RegionSearchRequest，缺省 5） */
	cap = strlen(esc_text) + 64;
	body = malloc(cap);
	if (!body) {
		free(esc_text);
		sme_write_out(out, n, "sme_regions_search: 内存不足");
		return AI_ERR_MEMORY;
	}
	if (top_k > 0)
		snprintf(body, cap, "{\"text\":\"%s\",\"top_k\":%d}",
			 esc_text, top_k);
	else
		snprintf(body, cap, "{\"text\":\"%s\"}", esc_text);
	free(esc_text);

	sme_url(url, sizeof(url), "/regions/search");
	ret = sme_request(url, body, SME_DEFAULT_TIMEOUT_MS, out, n);
	free(body);
	return ret;
}

/* consolidate/compress 共用：无 body POST（server.py 两端点均无必填 body） */
static int sme_engine_action(const char *path, char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), path);
	/* 巩固/压缩涉及全库聚类，余量放大到默认超时 */
	return sme_request(url, "", SME_DEFAULT_TIMEOUT_MS, out, n);
}

int sme_consolidate(char *out, size_t n)
{
	return sme_engine_action("/consolidate", out, n);
}

int sme_compress(char *out, size_t n)
{
	return sme_engine_action("/compress", out, n);
}

/*
 * sme_export_path_allowed - 导出落盘路径白名单（W43 安全修复）
 * finding：sme_export 的 path 参数此前无任何校验，可以运行身份
 * （root）向任意路径写文件（/etc/cron.d、ssh authorized_keys、
 * systemd unit 等）。
 * 规则（风格对齐 executor.c 的 w1_path_allowed）：
 *   a. 必须绝对路径；
 *   b. 拒绝含 ".." 路径穿越分量；
 *   c. realpath 规范化（文件已存在解析全路径；不存在解析其目录
 *      再拼 basename）——目录符号链接一并解析，链接逃逸被拒；
 *   d. 规范化结果必须严格落在 /tmp 或 /var/ai 之下（等于目录
 *      本身也不行——那是目录不是导出文件）。
 * @norm: 输出规范化路径（调用者据此 fopen）
 */
static int sme_local_path_allowed(const char *path, const char *what,
				  char *norm, size_t nsize, char **err_out)
{
	static const char *const allow_dirs[] = { "/tmp", "/var/ai", NULL };
	char tmp[PATH_MAX];
	char dirreal[PATH_MAX];
	const char *base;
	char *slash;
	const char *dot;
	char msg[512];
	int j;

	if (!what)
		what = "文件";
	if (err_out)
		*err_out = NULL;
	if (!path || !path[0]) {
		if (err_out)
			*err_out = strdup("路径为空");
		return 0;
	}
	if (path[0] != '/') {
		snprintf(msg, sizeof(msg), "%s路径必须是绝对路径"
			 "（/tmp 或 /var/ai 下）", what);
		if (err_out)
			*err_out = strdup(msg);
		return 0;
	}

	/* ".." 分量预检（语义同 executor.c path_has_dotdot） */
	dot = path;
	while ((dot = strstr(dot, "..")) != NULL) {
		int start_ok = (dot == path || dot[-1] == '/');
		int end_ok = (dot[2] == '\0' || dot[2] == '/');

		if (start_ok && end_ok) {
			snprintf(msg, sizeof(msg), "%s路径含 \"..\" 路径"
				 "穿越分量，已拒绝", what);
			if (err_out)
				*err_out = strdup(msg);
			return 0;
		}
		dot += 2;
	}

	/* realpath 规范化：符号链接/相对分量全部解析为真实落点 */
	if (realpath(path, tmp)) {
		snprintf(norm, nsize, "%s", tmp);
	} else {
		snprintf(tmp, sizeof(tmp), "%s", path);
		slash = strrchr(tmp, '/');
		if (!slash) {
			snprintf(msg, sizeof(msg), "%s路径非法", what);
			if (err_out)
				*err_out = strdup(msg);
			return 0;
		}
		base = slash + 1;
		if (!base[0]) {
			snprintf(msg, sizeof(msg), "%s路径以 / 结尾"
				 "（需要文件名）", what);
			if (err_out)
				*err_out = strdup(msg);
			return 0;
		}
		if (slash == tmp)
			snprintf(dirreal, sizeof(dirreal), "/");
		else {
			*slash = '\0';
			if (!realpath(tmp, dirreal)) {
				snprintf(msg, sizeof(msg), "%s目录不存在或"
					 "不可解析", what);
				if (err_out)
					*err_out = strdup(msg);
				return 0;
			}
		}
		/* 显式拼接（超长路径明确拒绝，不静默截断） */
		{
			size_t dl2 = strlen(dirreal);
			size_t bl2 = strlen(base);

			if (dl2 + 1 + bl2 + 1 > nsize) {
				snprintf(msg, sizeof(msg), "%s路径过长", what);
				if (err_out)
					*err_out = strdup(msg);
				return 0;
			}
			memcpy(norm, dirreal, dl2);
			norm[dl2] = '/';
			memcpy(norm + dl2 + 1, base, bl2 + 1);
		}
	}

	/* 白名单判定：规范化结果必须严格落在允许目录之下 */
	for (j = 0; allow_dirs[j]; j++) {
		const char *d = allow_dirs[j];
		size_t dl = strlen(d);

		if (strncmp(norm, d, dl) == 0 && norm[dl] == '/')
			return 1;
	}
	snprintf(msg, sizeof(msg),
		 "%s路径 %.256s 不在允许目录（/tmp /var/ai）内，"
		 "已拒绝；请改用 /tmp 或 /var/ai 下的绝对路径", what, norm);
	if (err_out)
		*err_out = strdup(msg);
	return 0;
}

/* 兼容旧名：导出路径白名单（W43 安全修复） */
static int sme_export_path_allowed(const char *path, char *norm,
				   size_t nsize, char **err_out)
{
	return sme_local_path_allowed(path, "导出", norm, nsize, err_out);
}

int sme_export(const char *save_path, char *out, size_t n)
{
	char url[512];
	char *resp = NULL;
	char *err = NULL;
	int status = 0;
	int ret;
	FILE *fp;
	const char *path_used = save_path && save_path[0] ?
				save_path : "/tmp/sme-export.json";
	size_t body_len;
	size_t written;
	char norm[PATH_MAX];   /* W43：规范化后的导出路径 */

	if (!out || n == 0)
		return AI_ERR_INVALID_ARG;
	out[0] = '\0';

	/* W43 安全修复（finding：导出路径无白名单）：导出落盘路径强制
	 * realpath 规范化后必须落在 /tmp 或 /var/ai 下，否则在触碰网络
	 * 之前即拒绝（见 sme_export_path_allowed 注释）。默认路径
	 * /tmp/sme-export.json 不受影响。 */
	{
		char *perr = NULL;

		if (!sme_export_path_allowed(path_used, norm, sizeof(norm),
					     &perr)) {
			sme_write_out(out, n, "sme_export: %s",
				      perr ? perr : "导出路径非法");
			free(perr);
			return AI_ERR_INVALID_ARG;
		}
		free(perr);
		path_used = norm;   /* fopen 用规范化路径（符号链接已解析） */
	}

	sme_url(url, sizeof(url), "/export");
	ret = local_http_get(url, SME_DEFAULT_TIMEOUT_MS, &resp, &err,
			     &status);
	if (ret != AI_OK) {
		sme_write_out(out, n, "SME 服务不可达: %s （提示: 检查服务"
			      "是否已启动，或用环境变量 SME_URL 指定地址）",
			      err ? err : ai_error_string(ret));
		free(resp);
		free(err);
		return ret;
	}
	if (status >= 400) {
		sme_write_out(out, n, "SME 服务返回 HTTP %d: %.256s",
			      status, resp ? resp : "(无响应体)");
		free(resp);
		free(err);
		return AI_ERR_API;
	}

	/* 落盘（导出可能远超缓冲区，完整内容看文件） */
	body_len = resp ? strlen(resp) : 0;
	fp = fopen(path_used, "wb");
	if (!fp) {
		sme_write_out(out, n, "sme_export: 无法打开导出文件 %s: %s"
			      "（/tmp 一般可写，请检查目标目录）",
			      path_used, strerror(errno));
		free(resp);
		free(err);
		return AI_ERR_STORAGE;
	}
	written = resp ? fwrite(resp, 1, body_len, fp) : 0;
	fclose(fp);

	sme_write_out(out, n,
		      "OK: 已导出 %zu 字节 -> %s\n预览(前 384 字节): %.384s",
		      written, path_used, resp ? resp : "");
	free(resp);
	free(err);
	return AI_OK;
}

int sme_metrics(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/metrics");
	return sme_request(url, NULL, SME_DEFAULT_TIMEOUT_MS, out, n);
}

/* ==================================================================== */
/* W50：完整记忆管理面                                                   */
/* ==================================================================== */

/* ---- JSON 请求体构造（动态缓冲 + 转义 + 片段注入校验） ---- */

struct sme_jb {
	char *s;
	size_t len;
	size_t cap;
	int oom;
};

static void sme_jb_init(struct sme_jb *b)
{
	b->s = NULL;
	b->len = 0;
	b->cap = 0;
	b->oom = 0;
}

static void sme_jb_free(struct sme_jb *b)
{
	free(b->s);
	b->s = NULL;
	b->len = b->cap = 0;
}

static int sme_jb_grow(struct sme_jb *b, size_t extra)
{
	size_t need, cap;
	char *ns;

	if (b->oom)
		return -1;
	need = b->len + extra + 1;
	if (need <= b->cap)
		return 0;
	cap = b->cap ? b->cap : 256;
	while (cap < need) {
		if (cap > (size_t)-1 / 2) {
			b->oom = 1;
			return -1;
		}
		cap *= 2;
	}
	ns = realloc(b->s, cap);
	if (!ns) {
		b->oom = 1;
		return -1;
	}
	b->s = ns;
	b->cap = cap;
	return 0;
}

static int sme_jb_printf(struct sme_jb *b, const char *fmt, ...)
{
	va_list ap, ap2;
	int need;

	if (b->oom)
		return -1;
	va_start(ap, fmt);
	va_copy(ap2, ap);
	need = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (need < 0) {
		va_end(ap2);
		b->oom = 1;
		return -1;
	}
	if (sme_jb_grow(b, (size_t)need) < 0) {
		va_end(ap2);
		return -1;
	}
	vsnprintf(b->s + b->len, b->cap - b->len, fmt, ap2);
	va_end(ap2);
	b->len += (size_t)need;
	return 0;
}

/*
 * sme_fragment_ok - 校验调用者提供的 JSON 片段（对象/数组）
 *
 * 用途：metadata/tags/filters/memories 等"原样嵌入"的参数。要求恰好
 * 一个顶层 open..close 值、括号配平、字符串转义合法、尾部除空白外无
 * 附加内容——阻断 `{},"x":1` 这类 JSON 注入改变请求语义。
 */
static int sme_fragment_ok(const char *s, char open, char close)
{
	const char *p;
	int depth = 0;
	int in_str = 0;
	int esc = 0;

	if (!s)
		return 0;
	p = s;
	while (*p && isspace((unsigned char)*p))
		p++;
	if (*p != open)
		return 0;
	for (; *p; p++) {
		unsigned char c = (unsigned char)*p;

		if (in_str) {
			if (esc) {
				esc = 0;
				continue;
			}
			if (c == '\\') {
				esc = 1;
				continue;
			}
			if (c == '"') {
				in_str = 0;
				continue;
			}
			if (c < 0x20)
				return 0;   /* 字符串内裸控制字符 */
			continue;
		}
		if (c == '"') {
			in_str = 1;
			continue;
		}
		if (c == (unsigned char)open) {
			depth++;
		} else if (c == (unsigned char)close) {
			depth--;
			if (depth == 0) {
				p++;
				break;
			}
			if (depth < 0)
				return 0;
		} else if (c < 0x20 && !isspace(c)) {
			return 0;
		}
	}
	if (depth != 0 || in_str || esc)
		return 0;
	while (*p && isspace((unsigned char)*p))
		p++;
	return *p == '\0';
}

static int sme_jb_kv_str(struct sme_jb *b, const char *key,
			 const char *val, int *first)
{
	char *esc;
	int rc;

	if (!val)
		return 0;
	esc = ai_json_escape(val);
	if (!esc) {
		b->oom = 1;
		return -1;
	}
	rc = sme_jb_printf(b, "%s\"%s\":\"%s\"", *first ? "" : ",", key, esc);
	free(esc);
	if (rc == 0)
		*first = 0;
	return rc;
}

/* 返回: 0 成功；-1 内存不足；-2 片段非法 */
static int sme_jb_kv_raw(struct sme_jb *b, const char *key, const char *val,
			 char open, char close, int *first)
{
	int rc;

	if (!val || !val[0])
		return 0;
	if (!sme_fragment_ok(val, open, close))
		return -2;
	rc = sme_jb_printf(b, "%s\"%s\":%s", *first ? "" : ",", key, val);
	if (rc == 0)
		*first = 0;
	return rc;
}

static int sme_jb_kv_int(struct sme_jb *b, const char *key, long long v,
			 int *first)
{
	int rc = sme_jb_printf(b, "%s\"%s\":%lld", *first ? "" : ",", key, v);

	if (rc == 0)
		*first = 0;
	return rc;
}

static int sme_jb_kv_double(struct sme_jb *b, const char *key, double v,
			    int *first)
{
	int rc = sme_jb_printf(b, "%s\"%s\":%.17g", *first ? "" : ",", key, v);

	if (rc == 0)
		*first = 0;
	return rc;
}

static int sme_jb_kv_bool(struct sme_jb *b, const char *key, int v,
			  int *first)
{
	int rc = sme_jb_printf(b, "%s\"%s\":%s", *first ? "" : ",", key,
			       v ? "true" : "false");

	if (rc == 0)
		*first = 0;
	return rc;
}

/* URL 查询参数百分号编码（UTF-8 字节逐个编码；unreserved 原样保留） */
static char *sme_url_encode(const char *s)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t i, len, o = 0;
	char *out;

	if (!s)
		return NULL;
	len = strlen(s);
	if (len > ((size_t)-1 - 1) / 3)
		return NULL;
	out = malloc(len * 3 + 1);
	if (!out)
		return NULL;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];

		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		    c == '.' || c == '~') {
			out[o++] = (char)c;
		} else {
			out[o++] = '%';
			out[o++] = hex[c >> 4];
			out[o++] = hex[c & 0x0f];
		}
	}
	out[o] = '\0';
	return out;
}

/* 发起带 JSON body 的请求；返回码同 sme_request_method */
static int sme_send_body(const char *method, const char *path,
			 const struct sme_jb *b, int timeout,
			 char *out, size_t n)
{
	char url[512];
	int rc;

	if (b->oom || !b->s) {
		sme_write_out(out, n, "SME 请求体构造失败（内存不足）");
		return AI_ERR_MEMORY;
	}
	sme_url(url, sizeof(url), path);
	rc = sme_request_method(method, url, b->s, timeout, out, n);
	return rc;
}

/* ---- 写入 / 高级检索 ---- */

int sme_add_ex(const struct sme_add_opts *o, char *out, size_t n)
{
	struct sme_jb b;
	int first = 1;
	int rc;

	if (!o || !o->text || !o->text[0]) {
		sme_write_out(out, n, "sme_add_ex: 记忆文本不能为空");
		return AI_ERR_INVALID_ARG;
	}
	sme_jb_init(&b);
	if (sme_jb_printf(&b, "{") < 0 ||
	    sme_jb_kv_str(&b, "text", o->text, &first) < 0)
		goto oom;
	rc = sme_jb_kv_raw(&b, "metadata", o->metadata_json, '{', '}', &first);
	if (rc == -2) {
		sme_jb_free(&b);
		sme_write_out(out, n, "sme_add_ex: metadata 不是合法 JSON 对象");
		return AI_ERR_INVALID_ARG;
	}
	if (rc < 0)
		goto oom;
	rc = sme_jb_kv_raw(&b, "tags", o->tags_json, '[', ']', &first);
	if (rc == -2) {
		sme_jb_free(&b);
		sme_write_out(out, n, "sme_add_ex: tags 不是合法 JSON 数组");
		return AI_ERR_INVALID_ARG;
	}
	if (rc < 0)
		goto oom;
	if (o->has_importance &&
	    sme_jb_kv_double(&b, "importance", o->importance, &first) < 0)
		goto oom;
	if (sme_jb_kv_str(&b, "source", o->source, &first) < 0 ||
	    sme_jb_kv_str(&b, "link_to", o->link_to, &first) < 0 ||
	    sme_jb_kv_str(&b, "link_kind", o->link_kind, &first) < 0 ||
	    sme_jb_kv_str(&b, "ns", o->ns, &first) < 0)
		goto oom;
	if (sme_jb_printf(&b, "}") < 0)
		goto oom;
	rc = sme_send_body("POST", "/memories", &b,
			   SME_DEFAULT_TIMEOUT_MS, out, n);
	sme_jb_free(&b);
	return rc;
oom:
	sme_jb_free(&b);
	sme_write_out(out, n, "sme_add_ex: 内存不足");
	return AI_ERR_MEMORY;
}

int sme_search_ex(const struct sme_search_opts *o, char *out, size_t n)
{
	struct sme_jb b;
	int first = 1;
	int rc;

	if (!o || !o->text || !o->text[0]) {
		sme_write_out(out, n, "sme_search_ex: 查询文本不能为空");
		return AI_ERR_INVALID_ARG;
	}
	sme_jb_init(&b);
	if (sme_jb_printf(&b, "{") < 0 ||
	    sme_jb_kv_str(&b, "text", o->text, &first) < 0)
		goto oom;
	if (o->top_k > 0 &&
	    sme_jb_kv_int(&b, "top_k", o->top_k, &first) < 0)
		goto oom;
	if (o->top_regions > 0 &&
	    sme_jb_kv_int(&b, "top_regions", o->top_regions, &first) < 0)
		goto oom;
	rc = sme_jb_kv_raw(&b, "metadata_filters", o->metadata_filters_json,
			   '{', '}', &first);
	if (rc == -2) {
		sme_jb_free(&b);
		sme_write_out(out, n,
			      "sme_search_ex: metadata_filters 不是合法 JSON 对象");
		return AI_ERR_INVALID_ARG;
	}
	if (rc < 0)
		goto oom;
	rc = sme_jb_kv_raw(&b, "tags", o->tags_json, '[', ']', &first);
	if (rc == -2) {
		sme_jb_free(&b);
		sme_write_out(out, n, "sme_search_ex: tags 不是合法 JSON 数组");
		return AI_ERR_INVALID_ARG;
	}
	if (rc < 0)
		goto oom;
	if (sme_jb_kv_str(&b, "region_retrieval", o->region_retrieval,
			  &first) < 0)
		goto oom;
	if (o->has_include_archived &&
	    sme_jb_kv_bool(&b, "include_archived", o->include_archived,
			   &first) < 0)
		goto oom;
	if (o->graph_expand > 0 &&
	    sme_jb_kv_int(&b, "graph_expand", o->graph_expand, &first) < 0)
		goto oom;
	if (sme_jb_kv_str(&b, "ns", o->ns, &first) < 0)
		goto oom;
	if (sme_jb_printf(&b, "}") < 0)
		goto oom;
	rc = sme_send_body("POST", "/memories/search", &b,
			   SME_DEFAULT_TIMEOUT_MS, out, n);
	sme_jb_free(&b);
	return rc;
oom:
	sme_jb_free(&b);
	sme_write_out(out, n, "sme_search_ex: 内存不足");
	return AI_ERR_MEMORY;
}

int sme_memory_update(const char *memory_id, const struct sme_update_opts *o,
		      char *out, size_t n)
{
	struct sme_jb b;
	int first = 1;
	int any = 0;
	int rc;

	if (!sme_id_safe(memory_id)) {
		sme_write_out(out, n, "sme_memory_update: 非法记忆 ID"
			      "（仅允许字母/数字/_-./，且非空）");
		return AI_ERR_INVALID_ARG;
	}
	if (!o) {
		sme_write_out(out, n, "sme_memory_update: 至少提供一个待更新字段");
		return AI_ERR_INVALID_ARG;
	}
	if (o->text && !o->text[0]) {
		sme_write_out(out, n, "sme_memory_update: text 不能为空串");
		return AI_ERR_INVALID_ARG;
	}
	sme_jb_init(&b);
	if (sme_jb_printf(&b, "{") < 0)
		goto oom;
	if (o->text) {
		if (sme_jb_kv_str(&b, "text", o->text, &first) < 0)
			goto oom;
		any = 1;
	}
	rc = sme_jb_kv_raw(&b, "metadata", o->metadata_json, '{', '}', &first);
	if (rc == -2) {
		sme_jb_free(&b);
		sme_write_out(out, n,
			      "sme_memory_update: metadata 不是合法 JSON 对象");
		return AI_ERR_INVALID_ARG;
	}
	if (rc < 0)
		goto oom;
	if (o->metadata_json && o->metadata_json[0])
		any = 1;
	rc = sme_jb_kv_raw(&b, "tags", o->tags_json, '[', ']', &first);
	if (rc == -2) {
		sme_jb_free(&b);
		sme_write_out(out, n,
			      "sme_memory_update: tags 不是合法 JSON 数组");
		return AI_ERR_INVALID_ARG;
	}
	if (rc < 0)
		goto oom;
	if (o->tags_json && o->tags_json[0])
		any = 1;
	if (o->has_importance) {
		if (sme_jb_kv_double(&b, "importance", o->importance,
				     &first) < 0)
			goto oom;
		any = 1;
	}
	if (o->has_weight) {
		if (sme_jb_kv_double(&b, "weight", o->weight, &first) < 0)
			goto oom;
		any = 1;
	}
	if (o->summary) {
		if (sme_jb_kv_str(&b, "summary", o->summary, &first) < 0)
			goto oom;
		any = 1;
	}
	if (!any) {
		sme_jb_free(&b);
		sme_write_out(out, n,
			      "sme_memory_update: 至少提供一个待更新字段"
			      "（text/metadata/tags/importance/weight/summary）");
		return AI_ERR_INVALID_ARG;
	}
	if (sme_jb_printf(&b, "}") < 0)
		goto oom;
	{
		char path[512];

		snprintf(path, sizeof(path), "/memories/%s", memory_id);
		rc = sme_send_body("PATCH", path, &b,
				   SME_DEFAULT_TIMEOUT_MS, out, n);
	}
	sme_jb_free(&b);
	return rc;
oom:
	sme_jb_free(&b);
	sme_write_out(out, n, "sme_memory_update: 内存不足");
	return AI_ERR_MEMORY;
}

int sme_memory_delete(const char *memory_id, char *out, size_t n)
{
	char url[512];

	if (!sme_id_safe(memory_id)) {
		sme_write_out(out, n, "sme_memory_delete: 非法记忆 ID"
			      "（仅允许字母/数字/_-./，且非空）");
		return AI_ERR_INVALID_ARG;
	}
	sme_memory_url(url, sizeof(url), memory_id, NULL);
	return sme_request_method("DELETE", url, NULL,
				  SME_DEFAULT_TIMEOUT_MS, out, n);
}

/* 批量新增/无损导入共用：校验数组后 POST 到指定端点 */
static int sme_post_memories_array(const char *path, const char *what,
				   const char *memories_json,
				   char *out, size_t n)
{
	struct sme_jb b;
	int rc;

	if (!memories_json || !memories_json[0]) {
		sme_write_out(out, n, "%s: memories 不能为空", what);
		return AI_ERR_INVALID_ARG;
	}
	if (!sme_fragment_ok(memories_json, '[', ']')) {
		sme_write_out(out, n,
			      "%s: memories 不是合法 JSON 数组"
			      "（尾部不得附加内容）", what);
		return AI_ERR_INVALID_ARG;
	}
	sme_jb_init(&b);
	if (sme_jb_printf(&b, "{\"memories\":%s}", memories_json) < 0) {
		sme_jb_free(&b);
		sme_write_out(out, n, "%s: 内存不足", what);
		return AI_ERR_MEMORY;
	}
	rc = sme_send_body("POST", path, &b, SME_DEFAULT_TIMEOUT_MS, out, n);
	sme_jb_free(&b);
	return rc;
}

int sme_memories_batch(const char *memories_json, char *out, size_t n)
{
	return sme_post_memories_array("/memories/batch", "sme_memories_batch",
				       memories_json, out, n);
}

int sme_import(const char *memories_json, char *out, size_t n)
{
	return sme_post_memories_array("/import", "sme_import",
				       memories_json, out, n);
}

int sme_import_path(const char *path, char *out, size_t n)
{
	char norm[PATH_MAX];
	char *perr = NULL;
	char *raw = NULL;
	char *body = NULL;
	FILE *fp;
	struct stat st;
	size_t got;
	const char *p;
	int rc;

	if (!sme_local_path_allowed(path, "导入", norm, sizeof(norm), &perr)) {
		sme_write_out(out, n, "sme_import_path: %s",
			      perr ? perr : "导入路径非法");
		free(perr);
		return AI_ERR_INVALID_ARG;
	}
	free(perr);

	if (stat(norm, &st) != 0 || !S_ISREG(st.st_mode)) {
		sme_write_out(out, n, "sme_import_path: 文件不存在或不是普通文件: %s",
			      norm);
		return AI_ERR_NOT_FOUND;
	}
	if (st.st_size <= 0 || st.st_size > SME_IMPORT_MAX_BYTES) {
		sme_write_out(out, n,
			      "sme_import_path: 文件大小非法（%lld 字节；"
			      "允许 1..%d）",
			      (long long)st.st_size, SME_IMPORT_MAX_BYTES);
		return AI_ERR_INVALID_ARG;
	}
	raw = malloc((size_t)st.st_size + 1);
	if (!raw) {
		sme_write_out(out, n, "sme_import_path: 内存不足");
		return AI_ERR_MEMORY;
	}
	fp = fopen(norm, "rb");
	if (!fp) {
		free(raw);
		sme_write_out(out, n, "sme_import_path: 无法打开 %s: %s",
			      norm, strerror(errno));
		return AI_ERR_STORAGE;
	}
	got = fread(raw, 1, (size_t)st.st_size, fp);
	fclose(fp);
	if (got != (size_t)st.st_size) {
		free(raw);
		sme_write_out(out, n, "sme_import_path: 读取 %s 不完整", norm);
		return AI_ERR_STORAGE;
	}
	if (memchr(raw, '\0', got) != NULL) {
		free(raw);
		sme_write_out(out, n, "sme_import_path: 文件含 NUL 字节"
			      "（不是 UTF-8 JSON 文本）");
		return AI_ERR_INVALID_ARG;
	}
	raw[got] = '\0';

	p = raw;
	while (*p && isspace((unsigned char)*p))
		p++;
	if (*p == '[') {
		if (!sme_fragment_ok(raw, '[', ']')) {
			free(raw);
			sme_write_out(out, n,
				      "sme_import_path: 文件不是合法 JSON 数组");
			return AI_ERR_INVALID_ARG;
		}
		if (asprintf(&body, "{\"memories\":%s}", raw) < 0) {
			free(raw);
			sme_write_out(out, n, "sme_import_path: 内存不足");
			return AI_ERR_MEMORY;
		}
	} else if (*p == '{') {
		if (!sme_fragment_ok(raw, '{', '}') ||
		    strstr(raw, "\"memories\"") == NULL) {
			free(raw);
			sme_write_out(out, n,
				      "sme_import_path: 对象缺少 memories 数组");
			return AI_ERR_INVALID_ARG;
		}
		body = strdup(raw);
		if (!body) {
			free(raw);
			sme_write_out(out, n, "sme_import_path: 内存不足");
			return AI_ERR_MEMORY;
		}
	} else {
		free(raw);
		sme_write_out(out, n,
			      "sme_import_path: 文件必须是 JSON 数组或含 "
			      "memories 的对象");
		return AI_ERR_INVALID_ARG;
	}
	free(raw);

	{
		char url[512];

		sme_url(url, sizeof(url), "/import");
		rc = sme_request_method("POST", url, body,
					SME_DEFAULT_TIMEOUT_MS, out, n);
	}
	free(body);
	return rc;
}

/* ---- 图谱 / Region / 事实 / 画像 / 问答 ---- */

int sme_graph(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/graph");
	return sme_request_method("GET", url, NULL,
				  SME_DEFAULT_TIMEOUT_MS, out, n);
}

int sme_graph_link(const char *a, const char *b, const char *kind,
		   int has_weight, double weight, const char *note,
		   char *out, size_t n)
{
	struct sme_jb jb;
	int first = 1;
	int rc;

	if (!sme_id_safe(a) || !sme_id_safe(b)) {
		sme_write_out(out, n, "sme_graph_link: 非法记忆 ID"
			      "（仅允许字母/数字/_-./，且非空）");
		return AI_ERR_INVALID_ARG;
	}
	sme_jb_init(&jb);
	if (sme_jb_printf(&jb, "{") < 0 ||
	    sme_jb_kv_str(&jb, "a", a, &first) < 0 ||
	    sme_jb_kv_str(&jb, "b", b, &first) < 0 ||
	    sme_jb_kv_str(&jb, "kind", kind, &first) < 0)
		goto oom;
	if (has_weight &&
	    sme_jb_kv_double(&jb, "weight", weight, &first) < 0)
		goto oom;
	if (sme_jb_kv_str(&jb, "note", note, &first) < 0)
		goto oom;
	if (sme_jb_printf(&jb, "}") < 0)
		goto oom;
	rc = sme_send_body("POST", "/graph/link", &jb,
			   SME_DEFAULT_TIMEOUT_MS, out, n);
	sme_jb_free(&jb);
	return rc;
oom:
	sme_jb_free(&jb);
	sme_write_out(out, n, "sme_graph_link: 内存不足");
	return AI_ERR_MEMORY;
}

int sme_regions(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/regions");
	return sme_request_method("GET", url, NULL,
				  SME_DEFAULT_TIMEOUT_MS, out, n);
}

int sme_regions_evolve(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/regions/evolve");
	return sme_request_method("POST", url, "",
				  SME_DEFAULT_TIMEOUT_MS, out, n);
}

int sme_facts(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/facts");
	return sme_request_method("GET", url, NULL,
				  SME_DEFAULT_TIMEOUT_MS, out, n);
}

int sme_facts_history(const char *text, const char *memory_id,
		      char *out, size_t n)
{
	char *et = NULL;
	char *ei = NULL;
	char *path = NULL;
	char *url = NULL;
	size_t cap;
	int rc;

	if ((!text || !text[0]) && (!memory_id || !memory_id[0])) {
		sme_write_out(out, n,
			      "sme_facts_history: text 与 memory_id 至少提供一个");
		return AI_ERR_INVALID_ARG;
	}
	et = sme_url_encode(text ? text : "");
	ei = sme_url_encode(memory_id ? memory_id : "");
	if (!et || !ei) {
		free(et);
		free(ei);
		sme_write_out(out, n, "sme_facts_history: 内存不足");
		return AI_ERR_MEMORY;
	}
	if (asprintf(&path, "/facts/history?text=%s&memory_id=%s",
		     et, ei) < 0) {
		free(et);
		free(ei);
		sme_write_out(out, n, "sme_facts_history: 内存不足");
		return AI_ERR_MEMORY;
	}
	free(et);
	free(ei);
	cap = strlen(sme_base_url()) + strlen(path) + 2;
	url = malloc(cap);
	if (!url) {
		free(path);
		sme_write_out(out, n, "sme_facts_history: 内存不足");
		return AI_ERR_MEMORY;
	}
	sme_url(url, cap, path);
	free(path);
	rc = sme_request_method("GET", url, NULL,
				SME_DEFAULT_TIMEOUT_MS, out, n);
	free(url);
	return rc;
}

int sme_profile(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/profile");
	return sme_request_method("GET", url, NULL,
				  SME_DEFAULT_TIMEOUT_MS, out, n);
}

int sme_qapairs(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/qapairs");
	return sme_request_method("GET", url, NULL,
				  SME_DEFAULT_TIMEOUT_MS, out, n);
}

int sme_metrics_report(const char *save_path, char *out, size_t n)
{
	char url[512];
	char norm[PATH_MAX];
	char *perr = NULL;
	char *resp = NULL;
	char *err = NULL;
	char *body = NULL;
	int status = 0;
	const char *path_used = save_path && save_path[0] ?
				save_path : "/tmp/sme-metrics-report.json";
	FILE *fp;
	size_t body_len, written;
	int ret;

	if (!out || n == 0)
		return AI_ERR_INVALID_ARG;
	out[0] = '\0';
	if (!sme_local_path_allowed(path_used, "报告", norm, sizeof(norm),
				    &perr)) {
		sme_write_out(out, n, "sme_metrics_report: %s",
			      perr ? perr : "报告路径非法");
		free(perr);
		return AI_ERR_INVALID_ARG;
	}
	free(perr);
	path_used = norm;

	sme_url(url, sizeof(url), "/metrics/report");
	ret = local_http_get(url, SME_BULK_TIMEOUT_MS, &resp, &err, &status);
	if (ret != AI_OK) {
		sme_write_out(out, n, "SME 服务不可达: %s （提示: 检查服务"
			      "是否已启动，或用环境变量 SME_URL 指定地址）",
			      err ? err : ai_error_string(ret));
		free(resp);
		free(err);
		return ret;
	}
	if (status >= 400) {
		/* telemetry 未启用时服务端 404：保留原始 detail 供模型判断 */
		sme_write_out(out, n, "SME 服务返回 HTTP %d: %.256s",
			      status, resp ? resp : "(无响应体)");
		free(resp);
		free(err);
		return AI_ERR_API;
	}
	body = resp ? resp : (char *)"";
	body_len = strlen(body);
	fp = fopen(path_used, "wb");
	if (!fp) {
		sme_write_out(out, n, "sme_metrics_report: 无法打开 %s: %s",
			      path_used, strerror(errno));
		free(resp);
		free(err);
		return AI_ERR_STORAGE;
	}
	written = fwrite(body, 1, body_len, fp);
	fclose(fp);
	sme_write_out(out, n,
		      "OK: 已导出遥测报告 %zu 字节 -> %s\n预览(前 384 字节): %.384s",
		      written, path_used, body);
	free(resp);
	free(err);
	return AI_OK;
}

/* ---- 配置中心（只读诊断） ---- */

int sme_config(char *out, size_t n)
{
	char url[512];

	sme_url(url, sizeof(url), "/config");
	return sme_request_method("GET", url, NULL,
				  SME_DEFAULT_TIMEOUT_MS, out, n);
}

int sme_config_check(int ping, char *out, size_t n)
{
	char url[512];
	char body[32];

	sme_url(url, sizeof(url), "/config/check");
	snprintf(body, sizeof(body), "{\"ping\":%s}", ping ? "true" : "false");
	/* ping=true 会现场探测 LLM/Embedding，给足超时 */
	return sme_request_method("POST", url, body, SME_BULK_TIMEOUT_MS,
				  out, n);
}
