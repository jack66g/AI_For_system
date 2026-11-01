/* SPDX-License-Identifier: GPL-2.0 */
/*
 * app_policy.h - W82 V4.5 画像结论 → 自动策略（TOOL_CH_APPCTL 复用）
 *
 * 分工：W81 的 app_profile_* 回答「APP 要什么 / 实际碰了什么」，W82 的
 * app_ctl_* 回答「怎么驱动它」，本文件回答「据此该给它什么权限」：
 *
 *   1. app_policy_generate （R/D1，只生成不落盘、不下发）
 *      输入：一个 APP 的静态+动态画像（JSON 字符串或 @文件），或直接给
 *      可执行路径（内部依次跑 app_profile_static / app_profile_dynamic）。
 *      输出：声明式策略（schema=aik-app-policy/1）——
 *        - LSM 规则面：kind=path/label、label_id、op（与内核
 *          enum ai_lsm_op_type 同号）、deny、path_prefix；
 *        - 路径白名单（按 op 分组，全部来自画像事实）；
 *        - 每条规则带 because + fact{seq,type,path}（哪条画像事实推导
 *          出来的），绝不凭空生成；
 *        - 命中危险路径（/etc/shadow、/proc/<pid>/mem、~/.ssh ...）时
 *          该条规则标 sensitive=true、requires_confirm=true 且 deny=true
 *          （危险项绝不自动放行），策略级 requires_confirm 置位。
 *
 *   2. app_policy_apply （W2/D3，需确认）
 *      先探测内核 LSM 列表里有没有 ai（/sys/kernel/security/lsm），
 *      没有就 fail-closed 明确拒绝并原样报出实际列表；有则再探测规则
 *      注入节点；两者都通过才下发：先快照旧规则 → 逐条下发 → 读回校验
 *      → 任一步失败恢复快照。全程不改系统其它状态。
 *
 * 硬约束（与内核规则面逐项对齐，代码里以静态断言/单测钉住）：
 *   - APOL_MAX_RULES == AI_LSM_RULE_MAX(64)：超限不静默截断，置 cap_hit
 *     并在 warnings 里明说丢了几条；
 *   - APOL_PREFIX_LEN == AI_LSM_PATH_PREFIX_LEN-1(63)：超长路径向上收敛
 *     到能容下的目录前缀（clamped 计数），绝不截断半个路径分量；
 *   - 规则匹配是 strncmp 前缀匹配，故目录前缀一律带结尾 '/'，避免
 *     "/etc" 命中 "/etcfoo"；
 *   - 永不生成 allow-all：path_prefix 为 "/"、空串、op=ANY 的 allow 规则
 *     在生成侧直接丢弃（dropped 计数），在校验侧（apply 入口）直接拒绝。
 *
 * 可表达性诚实边界（实测内核 6.18.39 / AIKernel W80 规则面）：
 *   - ai_lsm_socket_connect / socket_sendmsg 调 ai_lsm_rule_lookup 时
 *     path 传 NULL，只按 pid/label 匹配 —— **路径规则无法表达网络目的
 *     地址白名单**。故策略里的 net 目标只进 allowlist.net（
 *     enforceable=false + reason），绝不伪造成 path 规则；
 *   - ai_lsm_file_open 用 AI_LSM_OP_FILE_OPEN，file_permission 按 mask 用
 *     READ/WRITE/EXEC，故文件规则用 READ/WRITE/EXEC 表达即可覆盖；
 *   - 同一 (kind, op, path_prefix) 重复下发在内核里是「更新」不是新增，
 *     与生成侧的去重语义一致。
 */
#ifndef _AI_APP_POLICY_H
#define _AI_APP_POLICY_H

#include <stddef.h>

#include "app_profile.h"

#define APOL_SCHEMA		"aik-app-policy/1"
#define APOL_MAX_RULES		64	/* == AI_LSM_RULE_MAX */
#define APOL_PREFIX_MAX		64	/* == AI_LSM_PATH_PREFIX_LEN（含 NUL） */
#define APOL_PREFIX_LEN		(APOL_PREFIX_MAX - 1)
#define APOL_DETAIL_MAX		64	/* == AI_SEC_DETAIL_LEN */
#define APOL_LABEL_MAX		64
#define APOL_BECAUSE_MAX	512
#define APOL_PATH_MAX		4096
#define APOL_MAX_NET		32
#define APOL_MAX_SENS		32
#define APOL_MAX_NEEDED		64
#define APOL_MAX_LINES		10
#define APOL_MAX_UNRESOLVED	16
#define APOL_TEXT_MAX		(256 * 1024)

/* 规则操作类型：编号必须与内核 enum ai_lsm_op_type 逐项一致 */
enum apol_op {
	APOL_OP_ANY = 0,
	APOL_OP_FILE_OPEN = 1,
	APOL_OP_FILE_READ = 2,
	APOL_OP_FILE_WRITE = 3,
	APOL_OP_FILE_EXEC = 4,
	APOL_OP_SOCKET_CONNECT = 5,
	APOL_OP_SOCKET_SENDMSG = 6,
	APOL_OP_MAX
};

/* 规则主体维度（内核 struct ai_lsm_rule.kind：一条规则只占一个维度） */
enum apol_rule_kind {
	APOL_KIND_PATH = 0,	/* ai_lsm_rule_add_path */
	APOL_KIND_LABEL = 1,	/* ai_lsm_rule_add_label */
};

struct apol_rule {
	int id;			/* 1 起，稳定序号 */
	int kind;		/* enum apol_rule_kind */
	int label_id;		/* 1..255（策略绑定的工作区标签） */
	int op;			/* enum apol_op（1..6，ANY 不允许） */
	int deny;		/* 0=allow 1=deny */
	int sensitive;		/* 命中危险路径 */
	int requires_confirm;	/* 需人工确认 */
	int witnesses;		/* 合并进来的同类观测条数（含首条） */
	int fact_seq;		/* 动态画像事件 seq（0=静态事实） */
	char basis[16];		/* "dynamic" / "static" */
	char path_prefix[APOL_PREFIX_MAX];
	char fact_path[AP_EV_PATH];	/* 触发本规则的原始事实路径 */
	char detail[APOL_DETAIL_MAX];	/* 下发到内核的 detail（≤63） */
	char because[APOL_BECAUSE_MAX];
};

struct apol_net_target {
	char proto[8];
	char remote[64];
	int count;
	int loopback;
	char because[256];
};

struct apol_sens_hit {
	char path[AP_EV_PATH];
	char why[128];
};

/* 静态画像需要的事实子集（由 app_profile_static 的 JSON 解析而来） */
struct apol_static_input {
	char path[APOL_PATH_MAX];
	char interp[512];
	int had_interp;
	int needed_n;
	char needed[APOL_MAX_NEEDED][128];
	int setuid;
	int setgid;
	int pkg_found;
	char pkg[128];
	char caps_state[32];
};

struct apol_policy {
	char schema[32];
	char app_path[APOL_PATH_MAX];
	char app_base[128];
	char label[APOL_LABEL_MAX];
	int label_id;			/* 1..255 */
	int allow_all;			/* 生成器恒 0；校验器见 1 即拒 */
	int requires_confirm;
	int dynamic_available;
	int rule_n;
	struct apol_rule rules[APOL_MAX_RULES];
	int net_n;
	struct apol_net_target net[APOL_MAX_NET];
	int sens_n;
	struct apol_sens_hit sens[APOL_MAX_SENS];
	int merged;			/* 去重合并的重复事实数 */
	int dropped;			/* 因不可表达/非法被丢弃的事实数 */
	int conflicts;			/* allow/deny 冲突（deny 胜） */
	int clamped;			/* 前缀超长向上收敛的次数 */
	int cap_hit;			/* 撞到 64 条上限 */
	int resolved_sonames;
	int unresolved_n;
	char unresolved[APOL_MAX_UNRESOLVED][128];
	int warn_n;
	char warn[APOL_MAX_LINES][256];
	int deg_n;
	char degraded[APOL_MAX_LINES][256];
};

/* 下发结果（apol_apply_run 出参） */
struct apol_apply_result {
	int rules_applied;
	int readback_ok;	/* 1=读回逐条命中 */
	int readback_matched;
	int rolled_back;
	int rollback_ok;
	int snapshot_bytes;
	char sink[64];		/* 实际使用的注入后端名 */
	char snapshot_ref[256];	/* 快照指纹/位置（不回显内容） */
	char fail_rule[128];	/* 失败的规则（空=无） */
	char fail_why[256];
};

/* LSM 探测结果 */
struct apol_lsm_info {
	int ai_present;		/* 1=有 0=无 -1=读不到（未知，等同 fail-closed） */
	char source[256];	/* 实际读的路径 */
	char raw[512];		/* 原样内容（去掉结尾换行） */
	char list[256];		/* 逗号重排后的可读列表 */
	char err[256];		/* 读取失败原因 */
};

/* 注入节点探测结果 */
struct apol_inject_info {
	int found;
	char path[256];
	char kind[32];
	char probes[512];	/* 探测过的候选（逗号分隔） */
	char err[256];
};

/*
 * 注入后端抽象：apply 的状态机（快照→下发→读回→回滚）只依赖本结构，
 * 生产后端是 procfs-line 节点（apol_sink_node），单测后端是临时文件。
 */
struct apol_sink {
	const char *name;
	void *ctx;
	int (*snapshot)(void *ctx, char **snap, char *err, size_t errcap);
	int (*clear)(void *ctx, char *err, size_t errcap);
	int (*add)(void *ctx, const struct apol_rule *r, char *err,
		   size_t errcap);
	int (*readback)(void *ctx, char **txt, char *err, size_t errcap);
	int (*restore)(void *ctx, const char *snap, char *err, size_t errcap);
};

/* ===================== 纯函数（导出供单测） ===================== */

/* 危险路径分类：1=敏感（需人工确认），0=普通 */
int apol_path_sensitive(const char *path);

/* 路径合法性：绝对路径、无 ".."、无控制字符、长度 < APOL_PATH_MAX */
int apol_path_valid(const char *path);

/* 路径前缀合法性（下发前用）：非空、以 '/' 开头、非 "/"、无 ".."、
 * 长度 <= APOL_PREFIX_LEN（63）。1=合法 */
int apol_prefix_valid(const char *prefix);

/*
 * 从一条事实路径推导可下发的 path_prefix：
 *   - 目录（stat 命中 S_ISDIR）→ 自身 + '/'；
 *   - 普通文件 → 所在目录 + '/'；
 *   - 超长 → 逐级向上收敛，直到 <= 63（*clamped 置 1）；
 *   - 收敛到 "/" → 返回 0（拒绝：根前缀等于 allow-all）。
 * 成功 1；不可表达 0。
 */
int apol_path_to_prefix(const char *path, char *out, size_t cap,
			int *clamped);

/* op 名称 ↔ 编号（"file_read" ↔ APOL_OP_FILE_READ） */
int apol_op_from_name(const char *name);
const char *apol_op_name(int op);

/* 由可执行路径派生稳定标签名与 1..255 的 label_id（同一路径恒定） */
int apol_label_of(const char *app_path, char *label, size_t cap,
		  int *label_id);

/*
 * 追加一条规则（去重/合并/冲突/上限）：
 *   1=新增 2=合并（witnesses++） 3=冲突替换（deny 胜） 0=拒绝
 *   -1=撞上限（已置 cap_hit，调用者应记录 dropped）
 */
int apol_rule_add(struct apol_policy *p, const struct apol_rule *r);

/* allow-all 检测（生成侧丢弃、校验侧拒绝都用它）：1=存在 allow-all */
int apol_has_allow_all(const struct apol_policy *p);

/* app_profile_static 的 JSON → 静态事实子集；0 成功 */
int apol_static_json_parse(const char *json, struct apol_static_input *st,
			   char *err, size_t errcap);

/*
 * 核心生成：静态事实可为 NULL（纯动态）；ev/ev_n 为动态事件（可空）。
 * 返回 0 成功（*p 已填）；-1 失败（err 说明）。
 * 空画像（无事件且无静态事实）返回 -1 且 err 含 "empty_profile"。
 */
int apol_generate(const char *app_path, const struct ap_event *ev, int ev_n,
		  const struct apol_static_input *st, struct apol_policy *p,
		  char *err, size_t errcap);

/* 策略 → JSON（malloc，调用者 free） */
int apol_policy_render_json(const struct apol_policy *p, const char *tool,
			    char **out);

/* 规则的行标识（注入后端/读回校验共用）：path:<前缀>:<op>:<allow|deny>
 * 或 label:<id>:<op>:<allow|deny>。返回 snprintf 语义的长度。 */
int apol_rule_uri(const struct apol_rule *r, char *out, size_t cap);

/* 策略 JSON → struct（apply 入口的 schema 校验）；0 通过 */
int apol_policy_parse(const char *json, struct apol_policy *p, char *err,
		      size_t errcap);

/* ===================== 探测 / 下发 ===================== */

/* 读 lsm 列表并判定 ai 是否存在（path 为 NULL 时读 /sys/kernel/security/lsm） */
int apol_lsm_probe(const char *path, struct apol_lsm_info *info);

/* 探测规则注入节点（root 为 NULL 时按真实候选路径探测） */
int apol_inject_probe(const char *root, struct apol_inject_info *info);

/*
 * 下发状态机：快照 → 逐条 add → 读回校验；任一步失败 restore 快照。
 * 返回 0 全部成功；-1 失败（*res 里带失败规则与原因，rolled_back 标明
 * 是否已恢复；恢复本身失败时 err 里两段都写清楚）。
 */
int apol_apply_run(struct apol_sink *sink, const struct apol_policy *p,
		   struct apol_apply_result *res, char *err, size_t errcap);

/* 生产注入后端（procfs-line 节点）的状态；node=<注入节点路径> */
struct apol_node_sink_ctx {
	char node[256];
	char snapfile[256];
};

int apol_sink_node_init(struct apol_sink *sink, struct apol_node_sink_ctx *ctx,
			const char *node);

/* 执行器入口：app_policy_generate / app_policy_apply（channel=appctl） */
int exec_app_policy_tool(const char *name, const char *args_json, char **out);

#endif /* _AI_APP_POLICY_H */
