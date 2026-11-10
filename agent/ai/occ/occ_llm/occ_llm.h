/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_llm.h - occ LLM 双协议层公共 API（T9a1）
 *
 * 协议对齐源：opencode v2.2.1 packages/ai/src/protocols/
 *   - openai-chat.ts（chat completions + tools；体序 :901-925）
 *   - anthropic-messages.ts（messages + {name,input_schema}；体序 :1108-1129）
 *   - route/framing.ts:38-83（SSE 容错：data:null / ": keepalive" / [DONE]）
 *
 * 请求构造字节确定性：全部经 store_json 的 aik_json DOM + 紧凑 dump
 * （插入序、ensure_ascii=False、","/":" 分隔），与差分台架 Python 参考
 * 构造器 json.dumps(ensure_ascii=False,separators=(",",":")) 同构。
 */
#ifndef _OCC_LLM_H
#define _OCC_LLM_H

#include <signal.h>
#include <stddef.h>

/* ---- 协议（OPENCODE-PLAN §2.1） ---- */
typedef enum {
	OCC_PROTO_OPENAI_COMPAT = 0,	/* chat completions + tools */
	OCC_PROTO_ANTHROPIC = 1,	/* messages + {name,input_schema} */
} occ_protocol;

const char *occ_protocol_name(occ_protocol p);

/* ---- 请求模型（opencode LLMRequest 的 a1 子集） ---- */
typedef enum {
	OCC_ROLE_USER = 0,
	OCC_ROLE_ASSISTANT,
	OCC_ROLE_TOOL,			/* 工具结果回灌 */
} occ_role;

typedef struct occ_tool_call {
	const char *id;			/* provider 工具调用 id */
	const char *name;
	const char *arguments;		/* JSON 文本（紧凑） */
} occ_tool_call;

typedef struct occ_msg {
	occ_role role;
	const char *text;		/* 文本内容（可 NULL） */
	const char *reasoning;		/* assistant 思维链回放（deepseek 等
					 * requireReasoning 厂商必带；可 NULL） */
	const occ_tool_call *calls;	/* OCC_ROLE_ASSISTANT 的工具调用 */
	size_t ncalls;
	const char *tool_call_id;	/* OCC_ROLE_TOOL 对应的调用 id */
} occ_msg;

typedef struct occ_tool_def {
	const char *name;
	const char *description;	/* NULL/空 = 省略该键 */
	const char *parameters;		/* JSON Schema 文本（object） */
} occ_tool_def;

typedef struct occ_gen {
	long long max_tokens;		/* has=0：openai 省略 / anthropic 默认 32000 */
	double temperature;		/* has=0：省略 */
	int has_max_tokens;
	int has_temperature;
} occ_gen;

typedef struct occ_llm_req {
	occ_protocol proto;
	const char *model;
	const char *system;		/* NULL = 无 */
	const occ_msg *msgs;
	size_t nmsgs;
	const occ_tool_def *tools;
	size_t ntools;
	occ_gen gen;
	int parallel_tool_calls;	/* 0=省略；1=true（openai 且有 tools 时） */
	int require_reasoning;		/* openai-chat.ts:662-672：deepseek 系
					 * assistant 回放必带 reasoning_content */
} occ_llm_req;

/*
 * occ_build_request - 构造请求体（协议内部分派）
 * 返回 malloc 字符串（NUL 结尾；*outlen 可 NULL，不含 NUL），失败 NULL。
 */
char *occ_build_request(const occ_llm_req *req, size_t *outlen);

/* 协议各自构造器（差分台架/单测直接调用） */
char *occ_build_request_openai(const occ_llm_req *req, size_t *outlen);
char *occ_build_request_anthropic(const occ_llm_req *req, size_t *outlen);

/*
 * occ_chat_url - 端点 URL 拼接
 * openai: {base}/chat/completions（base 已含 /v1，deepseek 先例）
 * anthropic: {base}/messages（PATH=/messages，anthropic-messages.ts:39）
 * 成功 0；参数/缓冲问题 -1。
 */
int occ_chat_url(char *buf, size_t buflen, occ_protocol proto, const char *base_url);

/* ---- SSE 事件模型 ---- */
typedef enum {
	OCC_EV_TEXT_DELTA = 0,		/* text 增量片段 */
	OCC_EV_REASONING_DELTA,		/* 思维链增量（openai reasoning_content / anthropic thinking） */
	OCC_EV_TOOL_START,		/* idx + id/name（可分批补齐） */
	OCC_EV_TOOL_ARGS,		/* idx + arguments 增量片段 */
	OCC_EV_USAGE,			/* usage 回传（* 账本钩子挂点，a3 挂账本） */
	OCC_EV_FINISH,			/* finish 规范化（stop/tool-calls/length/content-filter/unknown） */
	OCC_EV_ERROR,			/* err（坏块/负向检出/流内 error） */
	OCC_EV_DONE,			/* 流终结（[DONE]/message_stop/EOF） */
	/* ---- T9b2 自动重试（传输层） ---- */
	OCC_EV_RESET,			/* 上一次尝试的部分输出作废（err=人话
					 * 重试通告：第 N/M 次+退避毫秒+原因）；
					 * 消费方清空已累积 text/reasoning/
					 * calls/usage/finish */
} occ_event_type;

/*
 * T9b2 自动重试（OCD §7.2：2s 指数退避、封顶 10s、最多 10 次、超时类
 * 最多 3 次、带抖动）。occ_llm_retry_class 分级（单测直测）：
 *   0=不可重试（其余 4xx、本地配置错）
 *   1=常规（409/429/5xx、一般传输错、流内坏块）
 *   2=超时类（408、连接/读超时文案、连接建立失败、流提前终止无 finish）
 * 重试发生在每次 https_post_stream 尝试之间：失败→分级→未达上限且未被
 * 中断→发 OCC_EV_RESET→退避（SIGINT 可打断）→重发同一请求体。
 * 节奏为产品配置族 env（缺省即 OCD 数值；单测用它跑毫秒级）：
 *   OCC_LLM_RETRY_MAX（常规上限，缺省 10）/ OCC_LLM_RETRY_TIMEOUT_MAX
 *   （超时类上限，缺省 3）/ OCC_LLM_RETRY_BASE_MS（起步，缺省 2000）/
 *   OCC_LLM_RETRY_CAP_MS（封顶，缺省 10000）
 * provider Retry-After 未接（http_client 不透传响应头——诚实差异，见
 * T9B2-REPORT）。
 */
int occ_llm_retry_class(int http_status, const char *transport_err,
			int stream_incomplete);

/* 有效重试参数（旋钮 > env OCC_LLM_RETRY_* > 缺省；retry.c） */
typedef struct occ_retry_params {
	int max_attempts;		/* 常规类尝试上限（缺省 10） */
	int timeout_max;		/* 超时类尝试上限（缺省 3） */
	int base_ms;			/* 起步退避（缺省 2000） */
	int cap_ms;			/* 单次退避封顶（缺省 10000） */
} occ_retry_params;

void occ_llm_retry_params(occ_retry_params *out);

/* 第 attempt 次失败后的确定性退避基数（指数 base*2^(n-1) 封顶 cap；
 * 抖动 ±10% 由 llm_call 侧施加）。attempt 从 1 起。 */
long long occ_llm_retry_backoff_ms(int attempt);

/*
 * occ_llm_retry_after_ms - B4（T9B2 §8-5）：Retry-After 响应头值
 * （delta-seconds 形态）→ 等待毫秒；畸形/NULL/HTTP-date 形态 → -1
 * （调用方回指数退避）；过大值钳制到 cap_ms（cap<=0=不钳制）。
 */
long long occ_llm_retry_after_ms(const char *v, long long cap_ms);

/*
 * occ_interrupt_flag - 进程级中断旗标（T9b2 SIGINT 语义；放传输层使
 * llm_call 重试与 loop 安全点共用一处）。SIGINT 处理器（occ.c）置 1；
 * loop 在安全点（每轮 LLM 前/每工具后/流返回后）检查；llm_call 在每次
 * 尝试前与退避中检查（置位即中止重试）。单测直接置位模拟，不经信号。
 */
extern volatile sig_atomic_t occ_interrupt_flag;

/* 单测/调参直设重试旋钮（-1/0=该键回缺省）。生产走 env 配置族。 */
void occ_llm_set_retry_knobs(int max_attempts, int timeout_max,
			     int base_ms, int cap_ms);

/*
 * usage 口径（对齐两协议 mapUsage）：
 *   openai    input=prompt_tokens（inclusive）、cache_read=
 *             prompt_tokens_details.cached_tokens ?? prompt_cache_hit_tokens
 *             ?? cached_tokens、cache_write=prompt_tokens_details.
 *             cache_write_tokens ?? cache_created_input_tokens
 *   anthropic input=inclusive=非缓存 input_tokens+cache_read+cache_write
 *   output    completion_tokens / output_tokens
 */
typedef struct occ_usage {
	long long input;
	long long output;
	long long cache_read;
	long long cache_write;
	int present;			/* 是否观测到 usage */
} occ_usage;

typedef struct occ_event {
	occ_event_type type;
	int idx;			/* TOOL_START/TOOL_ARGS：工具流内下标 */
	const char *id;			/* TOOL_START（可 NULL=未知） */
	const char *name;		/* TOOL_START（可 NULL=未知） */
	const char *text;		/* TEXT/REASONING 片段 */
	const char *args;		/* TOOL_ARGS 片段 */
	occ_usage usage;		/* USAGE */
	const char *finish;		/* FINISH 规范化值 */
	const char *err;		/* ERROR */
} occ_event;

typedef void (*occ_event_cb)(const occ_event *ev, void *ud);

typedef struct occ_sse occ_sse;

occ_sse *occ_sse_new(occ_protocol proto, occ_event_cb cb, void *ud);
void occ_sse_free(occ_sse *s);

/* 喂入响应体字节段（https_post_stream 回调直连；任意切分安全） */
void occ_sse_feed(occ_sse *s, const char *data, size_t len);

/*
 * EOF 冲刷：未终结的 data 块 → OCC_EV_ERROR（截断检出）；
 * 未见过终结哨兵 → 补发 OCC_EV_DONE（done_src=eof）。
 */
void occ_sse_finish(occ_sse *s);

/* 累计 ERROR 事件数（负向/坏块检出标志） */
int occ_sse_error_count(const occ_sse *s);

/*
 * 约定：OCC_EV_DONE 事件的 finish 字段承载 done_src：
 *   "sentinel"（openai [DONE]）/ "message_stop"（anthropic）/ "eof"
 */
#endif /* _OCC_LLM_H */
