// SPDX-License-Identifier: GPL-2.0
/*
 * ai_lease.h - AIKernel 授权租约（Lease）与 D0-D4 意图保险丝（W74）
 *
 * 设计原则（见 MASTER-PLAN §0/§5）：
 *   - AI 是系统最高执政者，人是授权者；权力来源是显式、可撤销、可审计
 *     的租约，而不是"进程是 root"。
 *   - D0/D1 与本任务租约内的 D2 自动执行；D3/D4、无租约的高风险动作、
 *     显式租约越界才暂停/拒绝。
 *   - 所有 IO（加载/撤销/签发/确认）与纯判定（ai_lease_decide）分离，
 *     便于穷举测试与注入 now。
 *
 * 租约 JSON：
 * {
 *   "lease_id": "L-20261021-0001",
 *   "principal": "root",
 *   "subject": "root-ai",
 *   "scope": ["sysadmin", "fs:/var:write", "netsec:read"],
 *   "risk_ceiling": "D2",
 *   "mission": "排查并修复 nginx 启动失败",
 *   "issued_at": "2026-10-21T09:00:00+08:00",
 *   "expires_at": "2026-10-21T23:00:00+08:00",
 *   "revocable": true,
 *   "audit": "session-id",
 *   "revoked": false
 * }
 *
 * 存储：
 *   - 租约默认 /var/lib/aikernel/leases（root:root 0700，文件 0600）；
 *   - 确认默认 /run/aikernel/confirm（root:root 0700，文件 0600）；
 *   - AIKERNEL_LEASE_DIR / AIKERNEL_CONFIRM_DIR 可覆盖（测试/独立部署）；
 *   - 两个目录都在 executor 写目标黑名单内，普通文件工具不可写。
 */
#ifndef _AI_LEASE_H
#define _AI_LEASE_H

#include <stddef.h>
#include <sys/types.h>

#include "policy/ai_user_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AI_LEASE_ID_MAX          65
#define AI_LEASE_PRINCIPAL_MAX   64
#define AI_LEASE_SUBJECT_MAX     64
#define AI_LEASE_MISSION_MAX     256
#define AI_LEASE_AUDIT_MAX       128
#define AI_LEASE_SCOPE_MAX       16
#define AI_LEASE_SCOPE_LEN       128
#define AI_LEASE_REASON_MAX      64
#define AI_LEASE_HIT_MAX         160
#define AI_LEASE_ROLLBACK_MAX    256
#define AI_LEASE_CONFIRM_MAX     24
#define AI_LEASE_ERR_MAX         256

#define AI_LEASE_DIR_DEFAULT     "/var/lib/aikernel/leases"
#define AI_LEASE_CONFIRM_DEFAULT "/run/aikernel/confirm"

/* 短租约（-y/--yes）与确认请求的有效期（秒） */
#define AI_LEASE_EPHEMERAL_TTL   3600
#define AI_LEASE_CONFIRM_TTL     300
#define AI_LEASE_CLOCK_SKEW      60

/* 危险等级（D0 纯信息 … D4 身份/启动链） */
enum ai_danger {
	AI_D0 = 0,
	AI_D1,
	AI_D2,
	AI_D3,
	AI_D4,
	AI_DANGER__COUNT,
};

/* D0-D4 名字（"D0"…"D4"）；非法返回 "?" */
const char *ai_danger_name(enum ai_danger d);
/* "D0"…"D4" → 枚举；返回 0 成功，-1 非法 */
int ai_danger_parse(const char *s, enum ai_danger *out);

/* 一条内存租约（解析/签发/加载共用） */
struct ai_lease {
	char lease_id[AI_LEASE_ID_MAX];
	char principal[AI_LEASE_PRINCIPAL_MAX];
	char subject[AI_LEASE_SUBJECT_MAX];
	char scope[AI_LEASE_SCOPE_MAX][AI_LEASE_SCOPE_LEN];
	int scope_count;
	enum ai_danger risk_ceiling;
	char mission[AI_LEASE_MISSION_MAX];
	long long issued_at;		/* epoch；has_issued_at=0 表示缺省 */
	int has_issued_at;
	long long expires_at;		/* epoch（必填） */
	int revocable;
	char audit[AI_LEASE_AUDIT_MAX];
	int revoked;			/* JSON revoked=true */
};

/* 租约上下文模式 */
enum ai_lease_mode {
	AI_LEASE_MODE_NONE = 0,		/* 无租约：D2/D3 交互确认 */
	AI_LEASE_MODE_EPHEMERAL,	/* -y/--yes：本次 ask 的 D2 短租约 */
	AI_LEASE_MODE_EXPLICIT,		/* --lease / AIKERNEL_LEASE */
};

/* 进程级租约上下文（全局单例） */
struct ai_lease_ctx {
	enum ai_lease_mode mode;
	struct ai_lease lease;
	char source[640];		/* 文件路径或 "ephemeral(-y)" */
	char dir[512];			/* 生效的租约目录 */
	uid_t file_owner;		/* 显式租约文件属主 */
	int loaded;			/* 显式租约已成功加载 */
	/* W74 live 撤销/防篡改：加载时文件指纹 + 进程内粘滞撤销位 */
	unsigned long long file_ino;
	long long file_size;
	long long file_mtime;
	int live_revoked;
	char error[AI_LEASE_ERR_MAX];
};

/* 被判定的一次动作 */
struct ai_lease_action {
	const char *tool;		/* 工具名 */
	const char *domain;		/* 逗号分隔的域集合（tool->sub + 命令语义） */
	const char *target;		/* 目标路径/命令/参数（可 NULL） */
	const char *args_json;		/* 原始参数 JSON（可 NULL） */
	const char *risk_str;		/* tool_exec_effective_risk 原始串 R/W1/W2 */
	enum ai_tool_risk risk;		/* 外层档位判定用的粗粒度（R→W1） */
	enum ai_danger danger;
	int is_exec;			/* exec/shell/sandbox 执行类动作 */
	int plan_mode;			/* 会话 plan 只读态 */
	int worker;			/* AIKERNEL_SANDBOX 非空（worker） */
};

enum ai_lease_decision {
	AI_LEASE_ALLOW = 0,		/* 自动放行 */
	AI_LEASE_CONFIRM,		/* 需人工确认（D2/D3） */
	AI_LEASE_CONFIRM_D4,		/* 需 D4 强确认短语 */
	AI_LEASE_DENY,			/* 直接拒绝（fail-closed） */
};

const char *ai_lease_decision_name(enum ai_lease_decision d);

/* 判定结果（含审计/确认 UI 所需字段） */
struct ai_lease_verdict {
	enum ai_lease_decision decision;
	char reason[AI_LEASE_REASON_MAX];
	char lease_id[AI_LEASE_ID_MAX];
	enum ai_danger danger;
	char scope_hit[AI_LEASE_HIT_MAX];
	char rollback_hint[AI_LEASE_ROLLBACK_MAX];
	char confirmation[AI_LEASE_CONFIRM_MAX]; /* none/lease/ephemeral/... */
};

/* ---- 解析 / 时间 / ID ---- */

/* ai_lease_id_valid - [A-Za-z0-9._-]{1,64}，拒绝 "."/".."/空/控制字符 */
int ai_lease_id_valid(const char *id);

/*
 * ai_lease_parse - 解析租约 JSON（不碰 IO）
 * 必填：lease_id/principal/subject/scope/risk_ceiling/mission/expires_at。
 * expires_at 必须带时区（Z 或 ±HH:MM）；issued_at 可选，但若存在且比
 * now 超前 >60s 则拒绝。未知字段忽略（向前兼容）。
 * 返回 0 成功；-1 失败（err 填原因）。
 */
int ai_lease_parse(const char *json, size_t len, long long now,
		   struct ai_lease *out, char *err, size_t errlen);

/*
 * ai_lease_parse_time - ISO8601 → epoch（必须带时区）
 * 支持 YYYY-MM-DDTHH:MM:SS[.ffffff](Z|±HH:MM)。
 * 返回 0 成功；-1 无时区/格式错误。
 */
int ai_lease_parse_time(const char *s, long long *out);

/* ---- 存储 ---- */

/* 生效的租约目录（AIKERNEL_LEASE_DIR 或默认值） */
void ai_lease_store_dir(char *buf, size_t n);
/* 生效的确认目录（AIKERNEL_CONFIRM_DIR 或默认值） */
void ai_lease_confirm_dir(char *buf, size_t n);

/*
 * ai_lease_load - 从租约目录加载 <id>.json
 * 安全校验：目录/文件非符号链接、目录 0700、文件 0600、属主 uid/root；
 * 撤销标记（<id>.revoked）优先；过期/未来 issued_at/principal 不匹配
 * （root 租约仅 uid 0）一律失败。
 * 返回 0 成功；-1 失败（err 填原因；已 fail-closed）。
 */
int ai_lease_load(const char *dir, const char *id, uid_t uid, long long now,
		  struct ai_lease *out, uid_t *file_owner,
		  char *err, size_t errlen);

/* 列出目录内可解析租约（cap 条；*count 返回实际写入数） */
int ai_lease_store_list(struct ai_lease *items, int cap, int *count,
			char *err, size_t errlen);

/* 生成 L-YYYYMMDD-<4hex> 形式的候选 ID（不落盘） */
int ai_lease_new_id(char *buf, size_t n);

/*
 * ai_lease_issue - Principal 签发租约（调用方必须已做 root+TTY+短语校验）
 * scope_csv 为逗号分隔；ceiling 为 D0-D4；ttl 秒（1..30 天）。
 * @out_id 若非空则作为候选 ID（命令层先展示再要求 ISSUE <id> 确认）；
 * 为空时内部生成。原子落盘（temp+link+fsync），返回 0 成功；-1 失败。
 */
int ai_lease_issue(const char *scope_csv, const char *ceiling,
		   const char *mission, long ttl, uid_t uid,
		   char *out_id, size_t idlen, char *out_path, size_t pathlen,
		   char *err, size_t errlen);

/* 撤销：原子写 <id>.revoked 标记；返回 0 成功/-1 失败 */
int ai_lease_revoke(const char *id, uid_t uid, char *err, size_t errlen);

/* ---- 上下文 ---- */

/*
 * ai_lease_ctx_init - 初始化进程租约上下文
 * @explicit_id: --lease / AIKERNEL_LEASE（优先；加载失败返回 -1）
 * @ephemeral_yes: -y / AIKERNEL_ASSUME_YES（创建 D2 短租约）
 * 返回 0 成功；-1 显式租约加载失败（调用方应非 0 退出）。
 */
int ai_lease_ctx_init(const char *explicit_id, int ephemeral_yes, uid_t uid,
		      char *err, size_t errlen);
const struct ai_lease_ctx *ai_lease_ctx_get(void);
void ai_lease_ctx_reset(void);
/* 1=已调用 ai_lease_ctx_init（生产主程序）；0=未初始化（旧路径/测试） */
int ai_lease_ctx_active(void);

/* 生成一次性 ephemeral 租约（不落盘） */
int ai_lease_ephemeral_create(uid_t uid, struct ai_lease *out);

/* ---- 危险分级 ---- */

/*
 * ai_danger_classify - 工具/命令 → D0-D4
 * @tool_name:    注册表工具名
 * @domain:       逗号分隔域（可从 tool->sub 拼接）
 * @effective_risk: tool_exec_effective_risk() 原始串（R/W1/W2）
 * @args_json:    调用参数
 * @target_path:  出参（malloc，可 NULL）：目标路径（若可提取）
 * @reason:       出参：分类依据（静态串）
 * 保守原则：不确定的 W2 → D2，不确定的 D3 特征 → D3；绝不降级。
 */
enum ai_danger ai_danger_classify(const char *tool_name, const char *domain,
				  const char *effective_risk,
				  const char *args_json,
				  char **target_path, const char **reason);

/* 从 exec args 追加语义域（fs/netsec/sysadmin）到逗号分隔缓冲 */
void ai_lease_exec_domains(const char *args_json, char *buf, size_t cap);

/* 判定后人类可读动作文本（tool + 目标/命令），用于确认面板 */
void ai_lease_action_text(const struct ai_lease_action *act,
			  char *buf, size_t cap);

/* ---- 纯判定 ---- */

/*
 * ai_lease_decide - 纯函数判定（不碰 IO；now 注入便于测试）
 * 顺序：撤销 → 外层档位 → plan → worker → D0 → 租约 scope/ceiling →
 *       D0-D4 表。返回 decision；verdict 填 reason/lease_id/danger/
 *       scope_hit/rollback_hint。
 */
enum ai_lease_decision ai_lease_decide(const struct ai_lease_ctx *ctx,
				       uid_t uid,
				       const struct ai_lease_action *act,
				       long long now,
				       struct ai_lease_verdict *v);

/* ---- 网关（executor 调用） ---- */

enum ai_lease_gate_result {
	AI_LGATE_ALLOW = 0,
	AI_LGATE_DENY = 1,
	AI_LGATE_CONFIRM_REQUIRED = 2,	/* 非 TTY：已写 pending，out=JSON */
	AI_LGATE_USER_REFUSED = 3,	/* TTY 用户拒绝 / 短语错误 */
	AI_LGATE_D4_REQUIRED = 4,	/* D4 短语确认失败 */
};

/*
 * ai_lease_gate - lease-aware 工具闸门
 * @uid:     调用 uid
 * @act:     动作（danger/risk 已由调用方算好）
 * @impact:  影响描述（工具 desc）
 * @rollback: 回滚提示（NULL 用内置模板）
 * @out:     出参；CONFIRM_REQUIRED 时为 malloc 的 JSON 对象串
 * @result:  出参结果码
 * 返回 1=放行；0=拒绝。所有路径写 audit + trace。
 */
int ai_lease_gate(uid_t uid, const struct ai_lease_action *act,
		  const char *impact, const char *rollback,
		  char **out, enum ai_lease_gate_result *result);

/* 最近一次 gate 的元数据（cmd_ask 写 tool_call trace 用） */
void ai_lease_last_reset(void);
const char *ai_lease_last_lease_id(void);
const char *ai_lease_last_danger(void);
const char *ai_lease_last_confirm_source(void);
const char *ai_lease_last_reason(void);
const char *ai_lease_last_scope_hit(void);

/* ---- 非 TTY 确认协议 ---- */

/* 写入 pending/<nonce>.json；返回 0 成功，nonce 输出 32 hex */
int ai_lease_confirm_pending_write(const struct ai_lease_action *act,
				   enum ai_danger danger,
				   const char *lease_id,
				   const char *impact,
				   const char *rollback,
				   char *nonce, size_t noncelen,
				   char *err, size_t errlen);

/* 列出 pending nonce（换行分隔写入 buf） */
int ai_lease_confirm_pending_list(char *buf, size_t cap,
				  char *err, size_t errlen);

/*
 * ai_lease_confirm_approve - Principal 批准/拒绝一个 pending
 * @nonce:  32 hex
 * @yes:    1=批准，0=拒绝
 * @phrase: D4 必须精确等于 "CONFIRM D4 <nonce>"；D2/D3 忽略
 * 返回 0 成功；-1 失败（过期/不存在/短语错误/权限）。
 */
int ai_lease_confirm_approve(const char *nonce, int yes, const char *phrase,
			     char *err, size_t errlen);

/* 读取 pending 的 danger（供 /lease confirm 判断是否需要 D4 短语） */
int ai_lease_confirm_pending_danger(const char *nonce, enum ai_danger *out,
				    char *err, size_t errlen);

/*
 * ai_lease_path_protected - 路径是否属于租约/确认存储（写目标黑名单）
 * realpath 优先；相对路径按 cwd 解析；拒绝 ".."。
 * 返回 1=受保护（必须拒绝写），0=不保护。
 */
int ai_lease_path_protected(const char *path);

/* 受保护前缀（供 executor 错误文案） */
#define AI_LEASE_PROTECT_PREFIX1 "/var/lib/aikernel"
#define AI_LEASE_PROTECT_PREFIX2 "/run/aikernel"

#ifdef __cplusplus
}
#endif

#endif /* _AI_LEASE_H */
