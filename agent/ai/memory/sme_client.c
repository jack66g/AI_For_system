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

#include "ai_types.h"
#include "ai_json_util.h"
#include "local/local_http.h"
#include "memory/sme_client.h"

/* 单请求默认超时（毫秒）：检索涉及嵌入计算，给足余量 */
#define SME_DEFAULT_TIMEOUT_MS  15000

/* 健康检查/探测超时（毫秒） */
#define SME_HEALTH_TIMEOUT_MS   3000

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
 * sme_request - 发送请求并处理公共错误路径
 * @url:      完整 URL
 * @body:     POST body（NULL 表示 GET）
 * @timeout:  超时毫秒
 * @out/@n:   输出缓冲
 * 返回: AI_OK（2xx）/ AI_ERR_NETWORK / AI_ERR_API / AI_ERR_MEMORY
 */
static int sme_request(const char *url, const char *body, int timeout,
		       char *out, size_t n)
{
	char *resp = NULL;
	char *err = NULL;
	int status = 0;
	int ret;

	if (!out || n == 0)
		return AI_ERR_INVALID_ARG;
	out[0] = '\0';

	if (body)
		ret = local_http_post(url, NULL, body, timeout,
				      &resp, &err, &status);
	else
		ret = local_http_get(url, timeout, &resp, &err, &status);

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

	if (!out || n == 0)
		return AI_ERR_INVALID_ARG;
	out[0] = '\0';

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
