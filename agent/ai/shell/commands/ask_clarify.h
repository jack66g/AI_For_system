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

/*
 * W77e：模糊度评分阈值（detector 2.0）。默认 5；环境变量
 * AIKERNEL_CLARIFY_THRESHOLD 覆盖（0=关闭检测器，负数/非法回落默认）。
 */
#define ASK_CLARIFY_THRESHOLD_DEFAULT 5
/* W77e：answered.jsonl 启动载入条数上限 */
#define ASK_CLARIFY_ANSWERED_KEEP     100
/* W77e：代词/省略信号的会话回看消息条数 */
#define ASK_CLARIFY_ENTITY_MSGS       6

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
	int asked;              /* 本 ask（任务链）已发起的澄清问题数 */
	int stop;               /* 1=结束本轮 ask（非 TTY/取消/重试耗尽） */
	int event_sent;         /* W77c-2b：本轮已写 tagged event（最多一行） */
	char *stop_text;        /* 结束时的最终答案 JSON（malloc） */
	char session[ASK_CLARIFY_SESSION_MAX + 1];	/* W77c-2a 恢复用 */
	char *original_question;			/* 澄清前的用户问题 */
	/* W77e：链内已问指纹与答案（同链重复提问直接注入旧答案） */
	unsigned long long asked_fp[ASK_CLARIFY_MAX_PER_ASK];
	char asked_label[ASK_CLARIFY_MAX_PER_ASK][ASK_CLARIFY_LABEL_MAX + 1];
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
 * W77e 新增：ctx_entities 是本会话最近 N 条消息里提到的实体
 * （*.service / 绝对路径名词，ask_clarify_entities_from_history
 * 提取，指针指向调用方消息文本）；conflict=同一目标两种状态读数
 * 不一致（生产采集器对比 running/failed 列表，测试可注入）。
 */
struct ask_clarify_evidence {
	const char *const *services;
	int n_services;
	const char *const *tmp_paths;
	int n_tmp_paths;
	int tmp_exists;
	int root_exists;
	int var_ai_exists;
	const char *const *ctx_entities;	/* W77e：会话实体（可 NULL） */
	int n_ctx_entities;
	int conflict;				/* W77e：证据冲突 */
};

/*
 * W77e：模糊度评分（detector 2.0）。全部信号为纯函数可单测；
 * total >= ask_clarify_threshold() 才触发提问。
 */
struct ask_clarify_score {
	int total;              /* 加总分 */
	int verb_no_target;     /* 动作动词无目标 +3 / 破坏性无目标 +4 */
	int candidates;         /* 证据候选 >=2 +2，每多一个 +1，封顶 +4 */
	int pronoun_entities;   /* 代词/省略指代且上文实体>1 +3 */
	int missing_param;      /* 已知缺参数模式 +2 */
	int conflict;           /* 证据冲突 +3 */
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
/* 廉价预判（动词/代词/缺参/否定/疑问句扫描）：1=可能命中检测器 */
int ask_clarify_question_candidate(const char *question);

/* ---- W77e：detector 2.0 评分制 ---- */

/* 评分阈值：AIKERNEL_CLARIFY_THRESHOLD 覆盖（默认 5，0=关，负数回落） */
int ask_clarify_threshold(void);

/* 纯信号打分：动词无目标/证据候选/代词省略+多实体/缺参模式/证据冲突 */
int ask_clarify_score_signals(const char *question,
			      const struct ask_clarify_evidence *ev,
			      struct ask_clarify_score *out);

/*
 * 从最近会话消息提取实体（*.service 名与绝对路径名词）。
 * 纯函数：实体文本复制进 buf（NUL 结尾、有界），out[i] 指向
 * buf 内部；返回写入 out 的条数（<= max_out）。
 */
int ask_clarify_entities_from_history(const char *const *messages, int n,
				      char *buf, size_t buf_len,
				      const char *out[], int max_out);

/* ---- W77e：跨轮去重 + 答案记忆（answered.jsonl） ---- */

/*
 * 问题指纹 = hash(kind + 归一化 question + option ids)。归一化 =
 * 小写 + 去空白。纯函数（FNV-1a 64）。
 */
unsigned long long ask_clarify_fingerprint(const struct ask_clarify_request *req);
void ask_clarify_normalize_question(const char *in, char *out, size_t n);

/*
 * 该问题是否已问过且已有答案：先查链内 st->asked_fp，再查
 * ~/.aikernel/clarify/answered.jsonl（启动后首次访问载入最近
 * ASK_CLARIFY_ANSWERED_KEEP 条）。命中返回 1 并把上次选择 label
 * 写入 out_label。
 */
int ask_clarify_already_answered(const struct ask_clarify_state *st,
				 const struct ask_clarify_request *req,
				 char *out_label, size_t label_len);

/* 记录一次已回答的澄清：链内 st + answered.jsonl 追加（0600） */
void ask_clarify_note_answered(struct ask_clarify_state *st,
			       const struct ask_clarify_request *req,
			       const struct ask_clarify_answer *ans);

/* 清空 answered.jsonl 内存缓存（测试隔离用；不动文件） */
void ask_clarify_answered_reset(void);

/* 底层记忆写入：fp+label 直接入缓存与 answered.jsonl（resume 路径用） */
void ask_clarify_answered_remember(unsigned long long fp, const char *label,
				   const char *kind);

/* ---- W77e：链级提问预算 ---- */

/* 1=任务链提问预算（ASK_CLARIFY_MAX_PER_ASK）已耗尽 */
int ask_clarify_budget_exhausted(const struct ask_clarify_state *st);

/* ---- W77e：非 TTY 过期自动默认降级 ---- */

/*
 * 过期 pending 自动默认资格（纯函数）：kind != authorization 且
 * 有 recommended 或 default 时返回 1。
 */
int ask_clarify_auto_default_eligible(const struct ask_clarify_request *req);

/*
 * 消费一条已过期的 pending：资格判定 -> 原子 consume -> 发带 tag 的
 * AIKERNEL_EVENT clarify_auto_default（含 nonce/label）-> 回填
 * out（original_question/asked/req）与 label 供恢复 ask。
 * @enabled: 总开关（config clarify_auto_default，默认 on；
 *   AIKERNEL_CLARIFY_AUTO_DEFAULT=0 强制关）。
 * 返回 1=已自动默认；0=不适用（原因写 err，保持挂起）；<0=内部错误。
 */
int ask_clarify_auto_default(const char *nonce, const char *session_expected,
			     int enabled,
			     struct ask_clarify_pending *out,
			     char *label, size_t label_len,
			     char *err, size_t errlen);

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
