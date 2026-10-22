/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ask_clarify.h - W77c：结构化澄清（clarify 工具）
 *
 * 澄清不是授权：本模块只收集用户选择，不创建租约、不执行待办动作。
 * TTY 会话给数字菜单并把选择回填给模型；非 TTY 只输出一条
 * CLARIFY_REQUIRED JSON（nonce/expires_at 供 W77c-2 恢复），由
 * cmd_ask 结束本轮 ask。单次 ask 最多 2 个澄清问题，每次一个问题。
 *
 * 纯函数（parse/validate/detect）与 I/O（TTY 菜单、evidence 采集）
 * 分离，便于单测；检测器只使用调用方给定的 evidence，不读全局状态。
 */
#ifndef _ASK_CLARIFY_H
#define _ASK_CLARIFY_H

#include <stddef.h>

#define ASK_CLARIFY_MIN_OPTIONS      2
#define ASK_CLARIFY_MAX_OPTIONS      4
#define ASK_CLARIFY_MAX_PER_ASK      2
#define ASK_CLARIFY_MAX_ATTEMPTS     3
#define ASK_CLARIFY_QUESTION_MAX     1024
#define ASK_CLARIFY_HEADER_MAX       120
#define ASK_CLARIFY_ID_MAX           32
#define ASK_CLARIFY_LABEL_MAX        200
#define ASK_CLARIFY_DESC_MAX         256
#define ASK_CLARIFY_WHY_MAX          256
#define ASK_CLARIFY_IMPACT_MAX       256
#define ASK_CLARIFY_ROLLBACK_MAX     256
#define ASK_CLARIFY_TEXT_MAX         512
#define ASK_CLARIFY_KIND_MAX         32
#define ASK_CLARIFY_DANGER_MAX       8
#define ASK_CLARIFY_NONCE_MAX        64
#define ASK_CLARIFY_SESSION_MAX      128
#define ASK_CLARIFY_RESUMED_MAX      4096
#define ASK_CLARIFY_TTL_MS           (15 * 60 * 1000)

struct ask_clarify_option {
	char id[ASK_CLARIFY_ID_MAX + 1];
	char label[ASK_CLARIFY_LABEL_MAX + 1];
	char description[ASK_CLARIFY_DESC_MAX + 1];
	char why[ASK_CLARIFY_WHY_MAX + 1];
	char impact[ASK_CLARIFY_IMPACT_MAX + 1];
	char rollback[ASK_CLARIFY_ROLLBACK_MAX + 1];
	char danger[ASK_CLARIFY_DANGER_MAX + 1];	/* 空=继承请求 danger */
};

struct ask_clarify_request {
	char question[ASK_CLARIFY_QUESTION_MAX + 1];
	char header[ASK_CLARIFY_HEADER_MAX + 1];	/* 可选短标题 */
	char kind[ASK_CLARIFY_KIND_MAX + 1];	/* intent/scope/strategy/... */
	char danger[ASK_CLARIFY_DANGER_MAX + 1];/* D0..D4（authorization 必填） */
	char recommended[ASK_CLARIFY_ID_MAX + 1];
	char default_id[ASK_CLARIFY_ID_MAX + 1];
	int has_recommended;
	int has_default;
	int multi_select;
	struct ask_clarify_option options[ASK_CLARIFY_MAX_OPTIONS];
	int n_options;
};

struct ask_clarify_answer {
	int selected[ASK_CLARIFY_MAX_OPTIONS];  /* 下标指向 request.options */
	int n_selected;
	char text[ASK_CLARIFY_TEXT_MAX + 1];    /* [o] Other 自由文本 */
	int timed_out;                          /* 1=菜单/Other 等待超时 */
};

/* ask_clarify_parse_answer 的返回值（超时按取消处理，见 timed_out） */
#define ASK_CLARIFY_ANS_OK       0
#define ASK_CLARIFY_ANS_CANCEL   1
#define ASK_CLARIFY_ANS_OTHER    2
#define ASK_CLARIFY_ANS_INVALID  3

/* 纯输入事件：line 或 timeout=1（TTY 等待超时） */
struct ask_clarify_input {
	const char *line;
	int timeout;
};

struct ask_clarify_state {
	int asked;              /* 本 ask 已发起的澄清问题数 */
	int stop;               /* 1=结束本轮 ask（非 TTY/取消/重试耗尽） */
	int event_sent;         /* W77c-2b：本轮已写 tagged event（最多一行） */
	char *stop_text;        /* 结束时的最终答案 JSON（malloc） */
	char session[ASK_CLARIFY_SESSION_MAX + 1];	/* W77c-2a 恢复用 */
	char *original_question;			/* 澄清前的用户问题 */
};

/* 非 TTY pending 记录（W77c-2a） */
struct ask_clarify_pending {
	char nonce[ASK_CLARIFY_NONCE_MAX + 1];
	long long expires_at_ms;
	int asked;
	char session[ASK_CLARIFY_SESSION_MAX + 1];
	char *original_question;
	struct ask_clarify_request req;
};

/*
 * 歧义检测证据。服务列表来自 systemctl list-units（或测试注入）；
 * tmp_paths 是 /tmp 下实测存在的绝对路径。detector 不自行探测。
 */
struct ask_clarify_evidence {
	const char *const *services;
	int n_services;
	const char *const *tmp_paths;
	int n_tmp_paths;
	int tmp_exists;
	int root_exists;
	int var_ai_exists;
};

/* 解析并校验模型给出的 clarify 参数；失败写 err 并返回 <0 */
int ask_clarify_parse_request(const char *json, struct ask_clarify_request *req,
			      char *err, size_t errlen);
int ask_clarify_validate(const struct ask_clarify_request *req,
			 char *err, size_t errlen);

/* 解析一行菜单输入；纯函数，供 TTY 与单测共用 */
int ask_clarify_parse_answer(const char *line,
			     const struct ask_clarify_request *req,
			     struct ask_clarify_answer *ans);

/*
 * 用给定的输入行模拟菜单：最多 3 次无效输入后返回 INVALID。
 * [o] 单独一行时，下一行作为 Other 文本；用于无 TTY 的单测。
 */
int ask_clarify_run_inputs(const char *const *lines, int nlines,
			   const struct ask_clarify_request *req,
			   struct ask_clarify_answer *ans, int *attempts);

/*
 * 纯输入事件模拟（含超时）：最多 3 次无效输入；timeout 事件按取消处理，
 * ans->timed_out=1 且不自动选择任何选项。供 TTY 超时路径单测。
 */
int ask_clarify_run_events(const struct ask_clarify_input *events, int nevents,
			   const struct ask_clarify_request *req,
			   struct ask_clarify_answer *ans, int *attempts,
			   int *timed_out);

/*
 * 同一轮含 clarify 时，除 clarify 外的工具是否必须抑制（TTY 与非 TTY
 * 一致：任何副作用都不得先于澄清答案）。返回 1=抑制。
 */
int ask_clarify_suppress_peer(int round_has_clarify, const char *tool_name,
			      int tty);

/* 本 ask 是否还允许发起澄清（返回 1=允许并计数，0=已达上限） */
int ask_clarify_state_begin(struct ask_clarify_state *st);
void ask_clarify_state_free(struct ask_clarify_state *st);

/*
 * W77c-2b：API tagged event 通道。
 *
 * 启动时读取 AIKERNEL_EVENT_TAG 并立即 unsetenv（工具子进程不可见）。
 * tag 只允许 [A-Za-z0-9._-]，长度 1..64；设置了非法 tag 返回 -1（调用方
 * fail closed）。非 TTY 澄清时写恰好一行到 stderr：
 *   AIKERNEL_EVENT <tag> {CLARIFY_REQUIRED JSON}
 * API 只解析匹配 tag 的行，避免靠 stdout 字符串扫描（模型可伪造）。
 */
int ask_clarify_event_tag_init(void);
void ask_clarify_emit_event(const char *json);

/* JSON 构造（返回 malloc；调用方 free） */
int ask_clarify_build_required_json(const struct ask_clarify_request *req,
				    const char *nonce, long long expires_at_ms,
				    char **out);
int ask_clarify_build_answer_json(const struct ask_clarify_request *req,
				  const char *nonce,
				  const struct ask_clarify_answer *ans,
				  const char *status, int attempts,
				  char **out);
int ask_clarify_make_nonce(char *buf, size_t n);

/*
 * 发起一次澄清：TTY 菜单或非 TTY CLARIFY_REQUIRED。
 * 调用前必须已通过 state_begin 取得名额。
 * @ans:     TTY 选择结果（非 TTY 时清零）
 * @out_json: 回填给模型/最终答案的 JSON（malloc）
 * 非 TTY、取消、重试耗尽时置 st->stop=1。
 */
int ask_clarify_exec(const struct ask_clarify_request *req,
		     struct ask_clarify_state *st, int tty,
		     struct ask_clarify_answer *ans, char **out_json);

/* cmd_ask 工具拦截入口；tty=0 可直接单测非 TTY JSON */
int ask_clarify_handle_tool(const char *args_json,
			    struct ask_clarify_state *st, char **out_text);
int ask_clarify_handle_tool_ex(const char *args_json,
			       struct ask_clarify_state *st, int tty,
			       char **out_text);

/* 终端判定：stdin/stdout 都是 TTY 才允许阻塞提问 */
int ask_clarify_tty(void);

/* 纯检测器：返回 1=需要澄清，0=不提问，<0=参数错误 */
int ask_clarify_detect(const char *question,
		       const struct ask_clarify_evidence *ev,
		       struct ask_clarify_request *req,
		       char *err, size_t errlen);
/* 廉价预判（只做动词/否定/疑问句扫描）：1=可能命中检测器 */
int ask_clarify_question_candidate(const char *question);

/* 生产 evidence 采集（固定命令/固定目录；测试可完全绕过） */
int ask_clarify_collect_evidence(struct ask_clarify_evidence *ev);
void ask_clarify_evidence_free(struct ask_clarify_evidence *ev);

/* ---- W77c-2a：非 TTY pending 存储 / CLI 恢复 ---- */

/*
 * 设置本轮 ask 的恢复上下文（session 与澄清前问题）。cmd_ask 在构造
 * question 后调用；非 TTY clarify 据此写 pending 记录。
 */
void ask_clarify_state_set_context(struct ask_clarify_state *st,
				   const char *session,
				   const char *original_question);

/*
 * pending_save - 写 $HOME/.aikernel/clarify/pending/<nonce>.json
 * 目录 0700、文件 0600；先写同目录临时文件再 rename，无半截可读窗口。
 * 返回 0 成功；<0 失败并写 err（调用方仍应返回 CLARIFY_REQUIRED，
 * 但必须在 JSON 中标记 resume_saved=false）。
 */
int ask_clarify_pending_save(const struct ask_clarify_request *req,
			     const char *nonce, long long expires_at_ms,
			     const char *session,
			     const char *original_question,
			     int asked, char *err, size_t errlen);

/*
 * pending_load - 读取并校验 pending 记录（不消费）。
 * @session_expected: 非空时必须与记录 session 一致；空表示沿用记录。
 * 校验 nonce 格式、status/version、TTL、session、内嵌 request（2-4 选项/
 * recommended/default/why/impact/rollback 等）。成功填充 *out（需 free）。
 */
int ask_clarify_pending_load(const char *nonce, const char *session_expected,
			     struct ask_clarify_pending *out,
			     char *err, size_t errlen);

/* pending_consume - 原子 rename pending -> consumed；重放/未知返回 <0 */
int ask_clarify_pending_consume(const char *nonce, char *err, size_t errlen);
void ask_clarify_pending_free(struct ask_clarify_pending *p);

/*
 * 把 CLI 选择解析为恢复行文本：
 *   - select 支持逗号/空白分隔的选项 id 或菜单序号（推荐项置顶）；
 *   - other 为自由文本；两者至少一个非空；
 *   - 输出如 "nginx.service" / "A, B" / "[Other] 清理缓存"。
 * 不创建租约。select 含未知 id、单选多选越界等返回 <0。
 */
int ask_clarify_resolve_selection(const struct ask_clarify_request *req,
				  const char *select, const char *other,
				  char *out, size_t outlen,
				  char *err, size_t errlen);

/* 同 build_required_json，附加 resume_saved/resume_error/resume_hint */
int ask_clarify_build_required_json_ex(const struct ask_clarify_request *req,
				       const char *nonce,
				       long long expires_at_ms,
				       int resume_saved,
				       const char *resume_error,
				       char **out);

#endif /* _ASK_CLARIFY_H */
