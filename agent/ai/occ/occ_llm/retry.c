/* SPDX-License-Identifier: GPL-2.0 */
/*
 * retry.c - occ_llm 自动重试参数族与错误分级（T9b2；OCD §7.2 数值）
 *
 * 策略（opencode model-retry.ts:18-46 对齐；B4（T9B2 §8-5）清欠：
 * 429/503 带 Retry-After 时 occ_llm_retry_after_ms 解析服务端定向
 * 退避替代指数基数，经 https_capture_resp_header 响应头捕获通道
 * 透传——畸形/过大钳制见该函数头注）：
 *   指数退避 2s 起步、单次间隔封顶 10s、常规类最多 10 次、超时类最多
 *   3 次、带抖动（±10%，在 llm_call 侧施加；本文件给确定性基数）。
 *
 * 分级 occ_llm_retry_class（单测直测）：
 *   0=不可重试（其余 4xx、本地配置错）
 *   1=常规（409/429/5xx、一般传输错、流内坏块/供应商报错）
 *   2=超时类（408、连接/读超时文案、连接建立失败、流提前终止无 finish）
 *
 * 节奏为产品配置族 env（缺省即 OCD 数值；单测用它跑毫秒级）——同
 * OCC_TOOL_TIMEOUT_MS 惯例：
 *   OCC_LLM_RETRY_MAX          常规类尝试上限（缺省 10）
 *   OCC_LLM_RETRY_TIMEOUT_MAX  超时类尝试上限（缺省 3）
 *   OCC_LLM_RETRY_BASE_MS      起步退避（缺省 2000）
 *   OCC_LLM_RETRY_CAP_MS       单次封顶（缺省 10000）
 *
 * 本文件不引 http_client（纯配置/分级/退避计算）——test_retry 只链它。
 */
#define _POSIX_C_SOURCE 200809L
#include "occ_llm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- 进程级中断旗标（occ.c SIGINT 处理器置位；单测直接置位模拟） ---- */
volatile sig_atomic_t occ_interrupt_flag = 0;

/* ---- 旋钮（单测/调参直设；-1/0=该键回缺省 → env → 缺省） ---- */
static int g_knob_max = -1;
static int g_knob_tmax = -1;
static int g_knob_base = -1;
static int g_knob_cap = -1;

void occ_llm_set_retry_knobs(int max_attempts, int timeout_max, int base_ms,
			     int cap_ms)
{
	g_knob_max = max_attempts;
	g_knob_tmax = timeout_max;
	g_knob_base = base_ms;
	g_knob_cap = cap_ms;
}

#define OCC_RETRY_DFLT_MAX 10
#define OCC_RETRY_DFLT_TMAX 3
#define OCC_RETRY_DFLT_BASE 2000
#define OCC_RETRY_DFLT_CAP 10000

/* env 整数（缺省/非法/负值 → dflt） */
static int env_int(const char *name, int dflt)
{
	const char *v = getenv(name);
	char *end = NULL;
	long x;

	if (!v || !v[0])
		return dflt;
	x = strtol(v, &end, 10);
	if (end == v || *end != '\0' || x < 0 || x > 10000000L)
		return dflt;
	return (int)x;
}

void occ_llm_retry_params(occ_retry_params *out)
{
	if (!out)
		return;
	out->max_attempts = g_knob_max > 0 ? g_knob_max :
			    env_int("OCC_LLM_RETRY_MAX",
				    OCC_RETRY_DFLT_MAX);
	out->timeout_max = g_knob_tmax > 0 ? g_knob_tmax :
			   env_int("OCC_LLM_RETRY_TIMEOUT_MAX",
				   OCC_RETRY_DFLT_TMAX);
	out->base_ms = g_knob_base > 0 ? g_knob_base :
		       env_int("OCC_LLM_RETRY_BASE_MS", OCC_RETRY_DFLT_BASE);
	out->cap_ms = g_knob_cap > 0 ? g_knob_cap :
		      env_int("OCC_LLM_RETRY_CAP_MS", OCC_RETRY_DFLT_CAP);
	if (out->max_attempts < 1)
		out->max_attempts = 1;
	if (out->timeout_max < 1)
		out->timeout_max = 1;
	if (out->base_ms < 1)
		out->base_ms = 1;
	if (out->cap_ms < out->base_ms)
		out->cap_ms = out->base_ms;
}

long long occ_llm_retry_backoff_ms(int attempt)
{
	occ_retry_params rp;
	long long d;
	int i;

	if (attempt < 1)
		attempt = 1;
	occ_llm_retry_params(&rp);
	d = rp.base_ms;
	for (i = 1; i < attempt; i++) {
		if (d >= rp.cap_ms)
			break;
		d *= 2;
	}
	if (d > rp.cap_ms)
		d = rp.cap_ms;
	return d;
}

/*
 * occ_llm_retry_after_ms - B4（T9B2 §8-5）：Retry-After 响应头值 →
 * 等待毫秒。仅 delta-seconds 形态（"120"=120s）；HTTP-date 形态
 * （RFC 9110 允许）不支持——LLM API 实况（OpenAI/Anthropic/DeepSeek）
 * 均用秒数，date 形态返回 -1 回指数基数（诚实边界，BLLM-REPORT §7）。
 *   返回 >=0：等待毫秒（0=服务端指示立即重试）
 *   返回 -1：畸形/NULL/空/非纯数字/带符号/溢出 → 调用方回指数退避
 * 上限保护：v_ms > cap_ms → 钳制 cap_ms（cap<=0 视为不钳制）。
 */
long long occ_llm_retry_after_ms(const char *v, long long cap_ms)
{
	long long sec = 0;
	size_t i;

	if (!v)
		return -1;
	/* 前后容忍 OWS（http 层捕获已去值外空白，这里双保险） */
	while (*v == ' ' || *v == '\t')
		v++;
	if (!*v)
		return -1;
	for (i = 0; v[i]; i++) {
		char c = v[i];

		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			/* 尾随空白：其后必须再无内容 */
			size_t j = i;

			while (v[j] == ' ' || v[j] == '\t' || v[j] == '\r' ||
			       v[j] == '\n')
				j++;
			if (v[j] != '\0')
				return -1;
			break;
		}
		if (c < '0' || c > '9')
			return -1;	/* 负号/小数/日期形态/杂字符 */
		if (sec > 99999999)	/* 已 9 位：再进位必超界 → 钳制 */
			sec = 999999999;
		else
			sec = sec * 10 + (c - '0');
	}
	if (sec > 999999999)
		sec = 999999999;
	{
		long long ms = sec * 1000;

		if (cap_ms > 0 && ms > cap_ms)
			ms = cap_ms;
		return ms;
	}
}

/* 大小写不敏感子串（-std=c11 无 strcasestr，自写） */
static int has_ci(const char *hay, const char *needle)
{
	size_t nl = strlen(needle);
	size_t i;

	if (!hay || !nl)
		return 0;
	for (i = 0; hay[i]; i++) {
		size_t k;

		for (k = 0; k < nl; k++) {
			char a = hay[i + k];
			char b = needle[k];

			if (!a)
				return 0;
			if (a >= 'A' && a <= 'Z')
				a = (char)(a + 32);
			if (b >= 'A' && b <= 'Z')
				b = (char)(b + 32);
			if (a != b)
				break;
		}
		if (k == nl)
			return 1;
	}
	return 0;
}

int occ_llm_retry_class(int http_status, const char *transport_err,
			int stream_incomplete)
{
	if (http_status >= 400) {
		if (http_status == 408)
			return 2;		/* REQUEST_TIMEOUT → 超时类 */
		if (http_status == 429 || http_status == 409 ||
		    http_status >= 500)
			return 1;		/* 限流/冲突/服务端错 → 常规 */
		return 0;			/* 其余 4xx：立即人话报错 */
	}
	if (transport_err && transport_err[0]) {
		/* 连接/读超时、连接建立失败、流截断 → 超时类；
		 * 坏块、供应商报错、其余传输错 → 常规 */
		if (has_ci(transport_err, "timeout") ||
		    has_ci(transport_err, "timed out") ||
		    has_ci(transport_err, "truncated") ||
		    has_ci(transport_err, "connect"))
			return 2;
		return 1;
	}
	if (stream_incomplete)
		return 2;			/* 干净提前 EOF（无 finish/哨兵） */
	return 0;
}
