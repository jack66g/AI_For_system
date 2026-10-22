// SPDX-License-Identifier: GPL-2.0
/*
 * ai_trace.h - AI 全轨迹日志（JSONL）公共接口
 *
 * 目标：记录 AI 一次完整运行的因果链（session → turn → model request/
 * response → route activation → tool call → policy decision → degraded →
 * error），为后续训练（SFT/DPO）保留结构化、可导出、可回放的数据。
 *
 * 设计要求：
 *   - 一行一事件（JSONL，UTF-8），每行带 ts / mono_ms / session_id /
 *     turn / event_seq 头字段，可独立解析；
 *   - 写入永不阻断主流程：打开/写入失败只向 stderr 警告一次后静默降级；
 *   - 所有字符串字段统一脱敏（API key / Bearer / token / password 等），
 *     密钥类绝不落盘；
 *   - 单写：每行在内存拼装完整后一次 write()（O_APPEND），并加进程内
 *     互斥锁，保证并发写不交错；
 *   - 按大小轮转：<name>.jsonl → <name>.1.jsonl → ...，保留 max_files。
 *
 * 本模块是纯用户态、内核无关的 C 代码，只依赖 libc/pthread。
 */
#ifndef _AI_TRACE_H
#define _AI_TRACE_H

#include <stddef.h>

#include "ai_chat.h"   /* struct ai_chat_msg / ai_chat_result */

#define AI_TRACE_VERSION "1.0"

/* ---- 配置（~/.aikernel/trace.toml 的 [trace] 段） ---- */
struct ai_trace_config {
	int enabled;            /* 默认 1 */
	char *dir;              /* 默认 ~/.aikernel/trace/；root 默认
				 * /var/log/aikernel/trace/ */
	int max_file_mb;        /* 单文件上限（默认 64 MB） */
	int max_files;          /* 轮转保留文件数（默认 20） */
	int include_model_text; /* 是否记录模型输入/输出全文（默认 1） */
	int max_payload_kb;     /* 单字段载荷上限（默认 64 KB） */
};

/*
 * ai_trace_init - 初始化轨迹日志（进程级单例，可重复调用）
 * @config_path: trace.toml 路径；NULL 时按
 *   $AIKERNEL_TRACE_CONFIG → $HOME/.aikernel/trace.toml →
 *   /etc/aikernel/trace.toml → 内置默认值 的顺序加载。
 *   配置不存在/解析失败时使用默认值（日志仍可用）。
 * @flags: AI_TRACE_FLAG_* 位掩码；AI_TRACE_FLAG_DISABLE 强制关闭。
 * 返回: AI_OK（含 enabled=0 的合法关闭）；AI_ERR_STORAGE 无法建目录/
 *       创建文件（已向 stderr 警告一次，后续事件静默丢弃）。
 *
 * 环境变量覆盖（优先级最高，便于测试/临时采样）：
 *   AIKERNEL_TRACE_DIR、AIKERNEL_TRACE_ENABLED、AIKERNEL_TRACE_MAX_FILE_MB、
 *   AIKERNEL_TRACE_MAX_FILES、AIKERNEL_TRACE_INCLUDE_TEXT、
 *   AIKERNEL_TRACE_MAX_PAYLOAD_KB
 */
#define AI_TRACE_FLAG_DISABLE  (1u << 0)
#define AI_TRACE_FLAG_VERBOSE  (1u << 1)

int ai_trace_init(const char *config_path, unsigned int flags);
void ai_trace_shutdown(void);
int ai_trace_is_enabled(void);
const struct ai_trace_config *ai_trace_get_config(void);

/*
 * ai_trace_load_config - 只读取配置（不打开日志文件）
 * 供 trace stats/dump/export 等只读命令使用。
 */
int ai_trace_load_config(const char *config_path, struct ai_trace_config *cfg);
void ai_trace_config_free(struct ai_trace_config *cfg);

/* ---- 时间与工具 ---- */

/* 单调时钟（CLOCK_MONOTONIC）毫秒，用于耗时/顺序 */
long long ai_trace_now_ms(void);
/* 墙钟毫秒（Unix epoch），用于 ISO8601 输出 */
long long ai_trace_wall_ms(void);
/* wall_ms → ISO8601（毫秒 + 时区），如 2026-10-19T22:00:00.123+0800 */
void ai_trace_format_ts(long long wall_ms, char *buf, size_t n);
/* 文件内容 FNV-1a 64 位哈希（工具表指纹）；失败写 "unavailable" */
int ai_trace_hash_file(const char *path, char *out, size_t n);

/* ---- 事件发射（全部线程安全；未初始化/关闭时返回 -1 且无副作用） ---- */

/*
 * session_start - 进程内只发射一次；重复调用返回 0。
 * @routing: "autonomous" / "pre_retrieve" / "-"。
 */
int ai_trace_session_start(const char *session, const char *model,
			   const char *provider, int ctx_len, int max_tokens,
			   int stream, const char *routing,
			   const char *tools_hash);

int ai_trace_session_end(const char *reason);

/* turn_start/end：内部维护单调轮号；返回当前轮号（>=1） */
int ai_trace_turn_start(const char *question);
int ai_trace_turn_end(const char *reason, int rounds);
int ai_trace_current_turn(void);
const char *ai_trace_session_id(void);

/*
 * model_request - 记录一次模型请求
 * 返回: malloc 的 request_id（调用方 free，并传给 model_response）；
 *       未启用时返回 NULL。
 */
char *ai_trace_model_request(const char *provider, const char *model,
			     const struct ai_chat_msg *msgs, int nmsgs,
			     const char *tools_json, int stream);

int ai_trace_model_response(const char *request_id,
			    const struct ai_chat_result *result,
			    long elapsed_ms);

/* SME 路由激活：tools 为本次新激活工具名数组 */
int ai_trace_route_activate(const char *trigger_token,
			    const char *const *tools, int ntools,
			    int active_before, int active_after);

/*
 * W77c：结构化澄清。
 * clarify_request 记录提问（nonce/kind/option ids/recommended/multi/tty）；
 * clarify_answer 记录回答（selected ids/text/status/attempts/elapsed）。
 * 问题与自由文本仍走 trace_redact（密钥类脱敏）。
 */
int ai_trace_clarify_request(const char *nonce, const char *kind,
			     const char *question,
			     const char *const *option_ids, int n_options,
			     const char *recommended, int multi_select,
			     int tty);
int ai_trace_clarify_answer(const char *nonce, const char *kind,
			    const char *const *option_ids, int n_options,
			    const char *recommended,
			    const char *const *selected_ids, int n_selected,
			    const char *selected_text, const char *status,
			    int attempts, long elapsed_ms);

/*
 * tool_call - 一次工具调用（含被策略拒绝的调用，status 区分）
 * @start_wall_ms: 调用开始墙钟（毫秒）
 * @duration_ms:   调用耗时
 * @ok:            1=成功，0=失败
 * @exit_code:     exec 通道退出码；-1=未知/不适用
 * @result:        工具输出原文（按 max_payload_kb 截断）
 */
#define AI_TRACE_STATUS_OK      "ok"
#define AI_TRACE_STATUS_FAIL    "fail"
#define AI_TRACE_STATUS_DENIED  "denied"
#define AI_TRACE_STATUS_ERROR   "error"

int ai_trace_tool_call(const char *tool, const char *channel,
		       const char *risk, const char *args_json,
		       long long start_wall_ms, long duration_ms,
		       int ok, int exit_code,
		       const char *result, size_t result_len);
/* 同上，但显式指定 status（denied/error 用） */
int ai_trace_tool_call_status(const char *tool, const char *channel,
			      const char *risk, const char *args_json,
			      long long start_wall_ms, long duration_ms,
			      const char *status, int exit_code,
			      const char *result, size_t result_len);

/* W74：tool_call 追加 danger / lease_id（NULL 表示不写该字段） */
int ai_trace_tool_call_ex(const char *tool, const char *channel,
			  const char *risk, const char *args_json,
			  long long start_wall_ms, long duration_ms,
			  const char *status, int exit_code,
			  const char *result, size_t result_len,
			  const char *danger, const char *lease_id);

/*
 * policy_decision - W1/W2/PLAN 闸门判定
 * @gate:   "W1" / "W2" / "PLAN"
 * @decision: "ALLOW" / "DENY" / "CONFIRM"
 * @reason: "policy_allow" / "user_refused" / "policy_tier" /
 *          "needs_confirmation_no_tty" / "plan_read_only"
 * @confirm_source: "auto" / "interactive" / "assume_yes" / "none"
 */
int ai_trace_policy_decision(const char *gate, const char *decision,
			     const char *reason, const char *tool,
			     const char *confirm_source,
			     const char *args_json);

/*
 * W74：policy_decision 扩展字段（NULL 表示不写该字段）
 * @lease_id / @danger / @confirmation（none/interactive/ephemeral/lease/
 * approved_file）/ @pending_nonce / @lease_source。
 */
int ai_trace_policy_decision_ex(const char *gate, const char *decision,
				const char *reason, const char *tool,
				const char *confirm_source,
				const char *args_json,
				const char *lease_id, const char *danger,
				const char *confirmation,
				const char *pending_nonce,
				const char *lease_source);

/* degraded - 组件不可达/降级（SME、云端、工具协议降级） */
int ai_trace_degraded(const char *component, const char *reason_code,
		      const char *detail);

/* error - 关键阶段错误（阶段、错误码、消息） */
int ai_trace_error(const char *phase, const char *code, const char *message);

/* 进程内累计事件数（诊断/测试用） */
unsigned long long ai_trace_event_count(void);

#endif /* _AI_TRACE_H */
