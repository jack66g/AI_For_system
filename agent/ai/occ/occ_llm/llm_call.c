
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * llm_call.c - occ_llm 传输层：全部经仓库自有 cloud/http http_client
 * （mbedTLS，https_post_stream 真增量 SSE）——只读复用，编译进
 * occ/obj/reuse/（参照 desktop/Makefile:24-33 与 aistreamd obj/reuse 手法，
 * 不改 cloud/ 源文件）。
 *
 * 出网互斥：照 dtchat.c:1466 先例（共享 mbedTLS ctr_drbg 非线程安全，
 * g_occ_http_lock 全局串行）——occ 多会话并发出网在 a3 棒细化。
 * 退避等待在锁外（不阻塞其他会话出网）。
 *
 * 状态码语义：http_client 在响应头解析后、首个 body 回调前写入
 * *status（http_client.c:1065-1083）；on_data 里 >=400 的 body 不进
 * SSE 解析器，聚合为错误负载（{"error":{...}} / 裸文本）。
 *
 * 认证头（T9a2 解 a1 遗留 #1）：openai 走 Bearer（https_post_stream
 * 原通道）；anthropic 走 https_post_stream_ex extra_headers 通道发
 * x-api-key + anthropic-version: 2023-06-01（anthropic.ts:36 /
 * anthropic-messages.ts:1710）。extra 数组含认证头时默认 Bearer
 * 自动让位（cloud/http/http_client.h T9a2 增量规则）。
 *
 * T9b2 自动重试（OCD §7.2）：每次 https_post_stream 尝试之间——失败→
 * occ_llm_retry_class 分级→未达类上限且未被中断→发 OCC_EV_RESET（上一
 * 尝试部分输出作废，消费方清空收集器）→抖动退避（SIGINT 可打断）→
 * 重发同一请求体。SSE 层 ERROR 事件在尝试内暂存不转发（否则消费方
 * llm_error 会误置位、把可重试失败当终局）；终局才发一次 ERROR。
 * 成功判定=收到协议终结（FINISH 或 DONE 哨兵/message_stop）且无流内
 * 错误。B4（T9B2 §8-5 清欠）：Retry-After 已接——https_capture_resp_
 * header 响应头捕获通道（cloud/http 纯增量）+ occ_llm_retry_after_ms
 * 解析（畸形/非数字→回指数基数；过大钳制 cap）。
 */
#define _POSIX_C_SOURCE 200809L
#include "occ_llm.h"
#include "occ_provider.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cloud/http/http_client.h"
#include "store/store_json.h"

static pthread_mutex_t g_occ_http_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_http_inited;

struct occ_call_ctx {
	occ_sse *sse;
	int *status;
	char *err;			/* >=400 body 聚合 */
	size_t err_len, err_cap;
	int oom;
	/* ---- b2 重试（trampoline 观测面） ---- */
	occ_event_cb cb;		/* 原始消费方回调 */
	void *ud;
	int finish_seen;		/* 收到 OCC_EV_FINISH */
	int done_real;			/* DONE 哨兵/message_stop（eof 补发
					 * 不算——那是干净提前 EOF） */
	char first_err[192];		/* 首个流内 ERROR 文本（分级/人话） */
};

static int err_append(struct occ_call_ctx *c, const char *data, size_t len)
{
	if (c->err_cap - c->err_len < len) {
		size_t nc = c->err_cap ? c->err_cap : 512;
		char *nb;

		while (nc - c->err_len < len)
			nc *= 2;
		nb = realloc(c->err, nc);
		if (!nb) {
			c->oom = 1;
			return -1;
		}
		c->err = nb;
		c->err_cap = nc;
	}
	memcpy(c->err + c->err_len, data, len);
	c->err_len += len;
	if (c->err_cap > c->err_len)
		c->err[c->err_len] = '\0';
	return 0;
}

static void occ_on_data(void *ud, const char *data, size_t len)
{
	struct occ_call_ctx *c = ud;

	if (c->oom)
		return;
	if (c->status && *c->status >= 400) {
		err_append(c, data, len);
		return;
	}
	occ_sse_feed(c->sse, data, len);
}

static void emit_str_error(occ_event_cb cb, void *ud, const char *msg)
{
	occ_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = OCC_EV_ERROR;
	ev.err = msg;
	cb(&ev, ud);
}

static void emit_reset(occ_event_cb cb, void *ud, const char *msg)
{
	occ_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = OCC_EV_RESET;
	ev.err = msg;
	cb(&ev, ud);
}

/*
 * trampoline：观测 FINISH/DONE/ERROR 并转发。ERROR 暂存不转发——
 * 是否重试未定，转发会让消费方 llm_error 置位、把可重试失败当终局
 * （终局统一由本文件发一次 ERROR）。
 */
static void tramp_event(const occ_event *ev, void *ud)
{
	struct occ_call_ctx *c = ud;

	switch (ev->type) {
	case OCC_EV_FINISH:
		c->finish_seen = 1;
		break;
	case OCC_EV_DONE:
		/* done_src 在 finish 字段：eof=occ 对干净 EOF 的补发
		 * （不算协议终结）；sentinel/message_stop=真终结 */
		if (ev->finish && strcmp(ev->finish, "eof"))
			c->done_real = 1;
		break;
	case OCC_EV_ERROR:
		if (!c->first_err[0] && ev->err)
			snprintf(c->first_err, sizeof(c->first_err), "%s",
				 ev->err);
		return;			/* 暂存，不转发 */
	default:
		break;
	}
	if (c->cb)
		c->cb(ev, c->ud);
}

/* {"error":{"message":...}} / {"message":...} / 裸文本 → 人话错误（不发事件） */
static void build_http_msg(struct occ_call_ctx *c, int status, char *msg,
			   size_t msglen)
{
	char perr[96];
	const char *m = NULL;
	aik_json *root = NULL;

	if (c->err && c->err_len) {
		root = aik_json_parse(c->err, c->err_len, perr, sizeof(perr));
		if (root) {
			const aik_json *e = aik_json_get(root, "error");
			const aik_json *v;

			if (!e)
				e = root;
			v = aik_json_get(e, "message");
			if (v && aik_json_typeof(v) == AIK_JSON_STR)
				m = aik_json_str(v);
		}
	}
	if (m)
		snprintf(msg, msglen, "HTTP %d: %s", status, m);
	else
		snprintf(msg, msglen, "HTTP %d", status);
	aik_json_free(root);
}

/* 可打断退避（20ms 步进查旗标；返回 1=被中断）。POSIX.1-2008 无
 * usleep——nanosleep 逐段睡（每段后查旗标，保证中断响应 ≤20ms）。 */
static int backoff_wait(long long delay_ms)
{
	long long slept = 0;

	while (slept < delay_ms) {
		struct timespec ts;

		if (occ_interrupt_flag)
			return 1;
		ts.tv_sec = 0;
		ts.tv_nsec = 20 * 1000 * 1000;
		nanosleep(&ts, NULL);
		slept += 20;
	}
	return occ_interrupt_flag ? 1 : 0;
}

int occ_llm_call(const occ_provider *p, const occ_llm_req *req,
		 occ_event_cb cb, void *ud, char **err_out)
{
	struct occ_call_ctx c;
	char url[512];
	char *body = NULL;
	int rc = -1;
	occ_retry_params rp;
	int attempt = 0, n_regular = 0, n_timeout = 0;

	memset(&c, 0, sizeof(c));
	c.cb = cb;
	c.ud = ud;
	if (err_out)
		*err_out = NULL;
	if (!p || !req || !cb) {
		if (err_out)
			*err_out = strdup("occ_llm_call: bad args");
		return -1;
	}
	if (occ_chat_url(url, sizeof(url), req->proto, p->base_url)) {
		if (err_out)
			*err_out = strdup("occ_llm_call: bad base_url");
		return -1;
	}
	/* openai-chat.ts:662-672 requireReasoning 判定（provider 名 a1 不入
	 * 注册表，取 base_url/model 两条件） */
	{
		occ_llm_req r2 = *req;

		/* B1（NEXT-PLAN 波次 B；T9B1 §8-4）：并行工具调用旗标接线。
		 * 请求构造面字段 openai.c:293 已就位（旗标+有 tools 时发
		 * "parallel_tool_calls":true，末位）；本层补真实调用面开关：
		 * OCC_PARALLEL_TOOL_CALLS=1 → openai 协议且有 tools 时置位
		 *（同 OCC_LLM_RETRY_* 产品配置族 env 惯例，retry.c 先例）。
		 * 缺省关=请求体逐字节零变化（差分 62/62 回归红线）。
		 * anthropic 面显式不支持：Anthropic Messages API 无该字段
		 *（工具并行是缺省行为，反方向按工具配 disable_parallel_tool_
		 * use，见 anthropic.c 头注）——此处仅 openai 协议生效。 */
		if (!r2.parallel_tool_calls &&
		    r2.proto == OCC_PROTO_OPENAI_COMPAT && r2.ntools > 0) {
			const char *pv = getenv("OCC_PARALLEL_TOOL_CALLS");

			if (pv && (!strcmp(pv, "1") || !strcasecmp(pv, "on") ||
				   !strcasecmp(pv, "true")))
				r2.parallel_tool_calls = 1;
		}
		if (r2.proto == OCC_PROTO_OPENAI_COMPAT && !r2.require_reasoning) {
			const char *mp;
			int hit = 0;

			if (strstr(p->base_url, "deepseek.com"))
				hit = 1;
			for (mp = r2.model; mp && *mp; mp++)
				if (!strncasecmp(mp, "deepseek", 8)) {
					hit = 1;
					break;
				}
			r2.require_reasoning = hit;
		}
		body = occ_build_request(&r2, NULL);
	}
	if (!body) {
		if (err_out)
			*err_out = strdup("occ_llm_call: request build failed");
		return -1;
	}
	if (!g_http_inited) {
		https_init();
		g_http_inited = 1;
	}
	/* B4（T9B2 §8-5）：Retry-After 响应头捕获通道开启（cloud/http
	 * 纯增量接口；每次 https_* 调用先清后存——无该头的响应读到
	 * NULL，绝不误用上一次尝试的陈旧值）。occ 自身出网经
	 * g_occ_http_lock 串行，捕获缓冲消费窗口安全；进程级共享面
	 * （desktop 等同进程其他调用方）为诚实边界，见 BLLM-REPORT §7。 */
	https_capture_resp_header("Retry-After");
	occ_llm_retry_params(&rp);

	for (;;) {
		char *herr = NULL;
		int status = 0;
		int hrc;
		char reason[256];
		int cls;
		int terminal;

		/* 尝试前：中断即中止（不发 ERROR——消费方按中断处理） */
		if (occ_interrupt_flag) {
			if (err_out)
				*err_out = strdup("interrupted by user");
			rc = -1;
			break;
		}
		attempt++;
		/* 每次尝试：新 SSE 解析器 + 清观测面（body 复用——同一
		 * 请求体重发；RESET 已告知消费方丢弃上一尝试的部分输出） */
		occ_sse_free(c.sse);
		c.sse = occ_sse_new(req->proto, tramp_event, &c);
		if (!c.sse) {
			if (err_out)
				*err_out = strdup("occ_llm_call: sse oom");
			rc = -1;
			break;
		}
		c.status = &status;
		c.finish_seen = 0;
		c.done_real = 0;
		c.first_err[0] = '\0';
		c.oom = 0;
		c.err_len = 0;
		if (c.err)
			c.err[0] = '\0';

		pthread_mutex_lock(&g_occ_http_lock);
		https_set_timeout(60, 60);
		if (req->proto == OCC_PROTO_ANTHROPIC) {
			/*
			 * Anthropic 原生认证（T9a2）：x-api-key +
			 * anthropic-version 头——经 https_post_stream_ex
			 * extra_headers 通道；数组含认证头时默认 Bearer
			 * 自动让位。key 只进栈缓冲，绝不打印/落日志。
			 */
			char xapi[OCC_PROVIDER_URL_MAX];
			const char *extra[3];

			snprintf(xapi, sizeof(xapi), "x-api-key: %s",
				 p->api_key ? p->api_key : "");
			extra[0] = xapi;
			extra[1] = "anthropic-version: 2023-06-01";
			extra[2] = NULL;
			hrc = https_post_stream_ex(url, NULL, body, extra,
						   occ_on_data, &c, &status,
						   &herr);
		} else {
			hrc = https_post_stream(url,
						p->api_key ? p->api_key : "",
						body, occ_on_data, &c, &status,
						&herr);
		}
		pthread_mutex_unlock(&g_occ_http_lock);

		/* ---- 本次尝试判定 ---- */
		if (hrc != 0) {
			snprintf(reason, sizeof(reason), "%s",
				 (herr && herr[0]) ? herr :
				 "transport error");
			cls = occ_llm_retry_class(0, reason, 0);
			free(herr);
			herr = NULL;
		} else if (status >= 400) {
			build_http_msg(&c, status, reason, sizeof(reason));
			cls = occ_llm_retry_class(status, NULL, 0);
		} else {
			occ_sse_finish(c.sse);	/* 可能补发截断 ERROR/DONE-eof */
			terminal = c.finish_seen || c.done_real;
			if (terminal && !c.first_err[0]) {
				rc = 0;		/* 成功收口 */
				break;
			}
			if (c.first_err[0])
				snprintf(reason, sizeof(reason), "%s",
					 c.first_err);
			else
				snprintf(reason, sizeof(reason),
					 "流提前终止（无 finish/终结哨兵）");
			cls = occ_llm_retry_class(status,
						  c.first_err[0] ?
						  c.first_err : NULL,
						  !terminal);
		}

		if (cls == 0) {
			/* 不可重试：立即人话报错（终局唯一一次 ERROR） */
			if (err_out)
				*err_out = strdup(reason);
			emit_str_error(cb, ud, reason);
			rc = -1;
			break;
		}
		{
			int cap = (cls == 2) ? rp.timeout_max : rp.max_attempts;
			int *cnt = (cls == 2) ? &n_timeout : &n_regular;
			char msg[400];
			long long base_d, delay, ra_ms;

			(*cnt)++;
			if (*cnt >= cap) {
				/* 类上限封顶：终局报错 */
				if (err_out)
					*err_out = strdup(reason);
				emit_str_error(cb, ud, reason);
				rc = -1;
				break;
			}
			/* 上一尝试部分输出作废（消费方清空收集器） */
			/* B4（T9B2 §8-5）：服务端 Retry-After 定向退避替代
			 * 固定指数基数——429/503 响应带该头时（经 http 层
			 * 捕获通道透传）按服务端指令等待（不加抖动）；
			 * 无头/畸形/非数字（HTTP-date 形态不支持，诚实
			 * 边界）→ -1 回指数基数；过大值在解析侧钳制到
			 * cap_ms（上限保护，替代旧「钳制抖动值」单一面）。 */
			{
				const char *ra = https_last_resp_header();

				ra_ms = ra ? occ_llm_retry_after_ms(ra,
								    rp.cap_ms)
					   : -1;
				if (ra_ms >= 0) {
					delay = ra_ms;
					snprintf(msg, sizeof(msg),
						 "重试：第 %d/%d 次尝试将在"
						 " %lldms 后重发（服务端"
						 " Retry-After：%s；%s）",
						 *cnt + 1, cap, delay, ra,
						 reason);
					emit_reset(cb, ud, msg);
					if (backoff_wait(delay)) {
						if (err_out)
							*err_out = strdup(
								"interrupted by user");
						rc = -1;
						break;
					}
					continue;
				}
			}
			base_d = occ_llm_retry_backoff_ms(attempt);
			delay = base_d * (90 + rand() % 21) / 100;
			if (delay < 1)
				delay = 1;
			if (delay > rp.cap_ms)
				delay = rp.cap_ms;
			snprintf(msg, sizeof(msg),
				 "重试：第 %d/%d 次尝试将在 %lldms 后重发"
				 "（%s）", *cnt + 1, cap, delay, reason);
			emit_reset(cb, ud, msg);
			if (backoff_wait(delay)) {
				if (err_out)
					*err_out = strdup("interrupted by user");
				rc = -1;
				break;
			}
		}
	}

	occ_sse_free(c.sse);
	free(c.err);
	free(body);
	return rc;
}
