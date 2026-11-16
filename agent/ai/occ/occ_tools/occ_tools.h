/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_tools.h - occ 工具六件套（T9b1；OPENCODE-PLAN §7）
 *
 * 语义对齐 opencode（SURVEY §5：tool/plugin/ 内置件）：
 *   read  行窗/偏移读（cat -n 风格带行号）
 *   write 整文件写（父目录递归建）
 *   edit  精确字符串替换（oldString 唯一命中或 replaceAll；未命中/
 *         多处不带 all=错误——opencode edit.ts 同语义）
 *   glob  模式匹配（fnmatch 递归，** 跨目录，* 不越 /，点文件需显式）
 *   grep  行匹配+行号（朴素字节子串，不引 PCRE）
 *   bash  命令执行——必经 aik-sandbox（namespace 隔离）；沙箱不可用
 *         即拒绝执行并人话报错，绝不降级裸跑（红线）
 *
 * 审计与快照：
 *   每次执行写 trace JSONL（~/.occ/trace/<session>.jsonl，trace.c；
 *   形态对齐系统 ai_trace：ts ISO8601+毫秒+时区/mono_ms/seq/单行
 *   O_APPEND 原子写/永不阻断主流程）。
 *   write/edit 执行前把原文件快照到 ~/.occ/snapshots/<session>/<msg>/
 *   <file>（原文件不存在则落 <file>.ABSENT 墓碑；/undo 三段式的 stage
 *   段，b2 棒接交互）。
 *
 * 与注册表的关系：六件套已入 agent/ai/tools.json 正典（230→236，
 * channel=occ，risk R/W1/W2 分级；executor 不路由该通道，occ_tools
 * 自执行）。LLM 请求的 tools 定义由 occ_tool_defs() 提供（a1 构造器
 * 双协议序列化：openai function.parameters / anthropic input_schema）。
 *
 * E3 第七工具 task（ORCH-DESIGN §3/R1——工具层，非运行时直调）：
 *   五动作 spawn/status/wait/read_result/return；OCC_ORCH_TOOLS=1
 *   才注册（默认关——默认路径 LLM 请求字节零变化，差分/p-smoke 红线）；
 *   执行面=occ_core/orch.c 运行时（经 occ_tool_ctx.orch 注入）。
 *   工具返回一律结构化 JSON 文本（模型可读）。
 *
 * 环境覆盖（产品配置，非测试后门；与 OCC_DB 同族）：
 *   OCC_SNAPROOT       快照根（缺省 ~/.occ/snapshots）
 *   OCC_TRACE_DIR      trace 目录（缺省 ~/.occ/trace）
 *   OCC_SANDBOX_BIN    aik-sandbox 路径（缺省先 AIKERNEL_SANDBOX_BIN
 *                      ——executor 同名约定——后 /usr/local/bin/aik-sandbox）
 *   OCC_TOOL_TIMEOUT_MS 每工具超时毫秒（缺省 60000；bash 参数可下调，
 *                      上限同此值）
 */
#ifndef _OCC_TOOLS_H
#define _OCC_TOOLS_H

#include <stddef.h>
#include <time.h>

#include "occ_llm/occ_llm.h"		/* occ_tool_def */
#include "occ_core/occ_session.h"	/* occ_db / OCC_ID_LEN */

/* 工具名（LLM 面；与 tools.json 注册名一致） */
#define OCC_T_READ  "read"
#define OCC_T_WRITE "write"
#define OCC_T_EDIT  "edit"
#define OCC_T_GLOB  "glob"
#define OCC_T_GREP  "grep"
#define OCC_T_BASH  "bash"
#define OCC_T_RECALL "recall"			/* E6：第八工具
					 * （OCC_ORCH_TOOLS=1
					 * 才注册） */
#define OCC_T_RECALL "recall"			/* E6：第八工具
					 * （OCC_ORCH_TOOLS=1
					 * 才注册） */
#define OCC_T_TASK  "task"			/* E3：第七工具
						 * （OCC_ORCH_TOOLS=1
						 * 才注册） */
/* C-P2a：结构化静态网络写入（OCC_NETCFG_TOOLS=1 才注册——差分红线：
 * 默认工具清单与请求字节零变化；出厂面在 aik-console/api 侧置位） */
#define OCC_T_NETCFG "config_write_network"

/* 结果文本化截断上限（任务书：8KB） */
#define OCC_TOOL_OUT_MAX 8192

/* 每工具默认/上限超时（ms；可配 OCC_TOOL_TIMEOUT_MS） */
#define OCC_TOOL_TIMEOUT_DEF_MS 60000

/*
 * 六件套 tools 定义（name/description/parameters JSON Schema 文本）。
 * 返回静态数组；*n 恒 6。直接喂 occ_llm_req.tools。
 * E3：OCC_ORCH_TOOLS=1 时返回 7 件（尾部追加 task——判级/派发协议
 * 见 orch.h；默认关，差分红线路径恒 6 件）。
 */
const occ_tool_def *occ_tool_defs(size_t *n);
int occ_tool_is_known(const char *name);

/* ---- O-9/O-4（UX-O §2）：occ 面 W2 高危确认门 ---- */
struct occ_tool_ctx;			/* 前向（本块早于 ctx typedef） */
#define OCC_W2_TIER_PRIVILEGED 0	/* root / /su 提权：W2=确认后放行 */
#define OCC_W2_TIER_CONFIRMED  1	/* sudo 组：W1 only */
#define OCC_W2_TIER_RESTRICTED 2	/* 其他用户：W1 only（安全兜底档） */

typedef struct occ_w2_gate {
	volatile int tier;	/* 档位（O-10：main 按 policy 初始化；
				 * /su 成功→PRIVILEGED、/su 0→回落） */
	int allow_w2;		/* headless --allow-w2：显式开门免确认 */
	int denied;		/* 已拒绝计数（-p 收尾 stderr 指引用） */
	/* 交互确认回调（TUI）：1=放行 0=拒绝/超时；NULL=headless（默认拒） */
	int (*confirm)(void *ud, const char *title, const char *detail);
	void *ud;
} occ_w2_gate;

/*
 * occ_w2_classify - 判定一次调用的有效风险级（O-9/O-4）
 * 返回 "R"/"W1"/"W2"；W2 时 detail 填人话理由。口径：
 *   write/edit 目标出安全区（workdir/$HOME 子树 + /tmp）→ W2；
 *   bash 命令级 W2 表（mkfs 前缀/dd of=/rm -r/reboot/kill 等）+
 *   O-4 粘贴形态（多行/sudo/管道进 sh/链式≥2）→ W2；
 *   bash 其余=W1（aik-sandbox 面隔离；通道级 W2 上限以 tools.json
 *   正典为准——本门是命令级有效风险，口径同 executor 哲学）。
 */
const char *occ_w2_classify(const struct occ_tool_ctx *ctx,
				    const char *name,
			    const char *args_json, char *detail, size_t dcap);

/* ---- 执行上下文 ---- */
struct occ_orch;			/* 前向（occ_core/orch.h；避免头环） */
typedef struct occ_tool_ctx {
	occ_db *db;			/* 可 NULL（无 durable 落库需求时） */
	const char *session_id;		/* ses_…（trace/快照路径；task
					 * 工具 spawn 的 parent） */
	const char *msg_id;		/* 携带该 toolCall 的 assistant msg */
	const char *workdir;		/* 工作目录（glob/bash rw 面）；
					 * NULL=getcwd */
	const char *snaproot;		/* NULL=OCC_SNAPROOT/~/.occ/snapshots */
	const char *trace_dir;		/* NULL=OCC_TRACE_DIR/~/.occ/trace */
	long long timeout_ms;		/* 0=缺省 OCC_TOOL_TIMEOUT_DEF_MS */
	struct occ_orch *orch;		/* E3：编排运行时（task 工具执行
					 * 面；NULL=编排未启用——task
					 * 调用返回结构化人话错误） */
	struct occ_w2_gate *w2;		/* O-9（UX-O §2）：W2 确认门；
					 * NULL=嵌入/测试面零行为变化 */
} occ_tool_ctx;

/* ---- 执行结果 ---- */
typedef struct occ_tool_result {
	char *text;			/* 结果文本（截断至 8KB；heap） */
	int rc;				/* 0=成功；非 0=失败（text 带 ERROR） */
	long long dur_ms;		/* 耗时 */
	size_t out_bytes;		/* 截断前产物大小 */
	char toolcall_id[OCC_ID_LEN];	/* occ_toolcall 行 id（tc_…；
					 * 落库成功时非空） */
} occ_tool_result;

void occ_tool_result_free(occ_tool_result *r);

/*
 * occ_tool_exec - 执行一次工具调用（完整链：参数解析→（write/edit）
 * 快照→执行→trace JSONL→（ctx->db 非空）occ_toolcall 行落库）。
 * name 未知 → rc=ENOENT 风格错误文本（回灌模型，不崩）。args_json
 * NULL/空按 {} 处理。不会因任何工具失败而终止调用方。
 */
int occ_tool_exec(const occ_tool_ctx *ctx, const char *name,
		  const char *call_id, const char *args_json,
		  occ_tool_result *out);

/* ---- 快照（write/edit 共用；单测直接调） ----
 * 成功 0（ret 备注路径到 buf）；原文件不存在 → 0 且落 <mangled>.ABSENT。
 * err 文本人话。路径形态：~/.occ/snapshots/<session>/<msg>/<mangled>；
 * mangled = 百分比编码（'%'→%25、'/'→%2f，单射——b2 修复 b1 的
 * '/'→'_' 碰撞缺陷 /tmp/a_b vs /tmp/a/b，详见 tools.c 头注）。
 */
int occ_snapshot_stage(const char *snaproot, const char *session_id,
		       const char *msg_id, const char *abs_path,
		       char *buf, size_t buflen);

/* b2（revert.c 复用）：mangle 编码（'%','/','.'→%XX，单射）与反解、
 * 快照根解析。unmangle 返回 0 成功 / -1（NULL 或缓冲不足）。 */
void occ_snap_mangle(const char *abs, char *out, size_t outlen);
int occ_snap_unmangle(const char *mangled, char *out, size_t outlen);
const char *occ_snap_root(char *buf, size_t buflen);

/* b2：相对路径按指定 workdir 解析为绝对（与工具执行同口径；undo 用） */
int occ_resolve_path(const char *workdir, const char *raw,
		     char *out, size_t outlen);

/* path_is_under - abs 路径是否位于 base 之下（含相等） */
int occ_path_is_under(const char *abs, const char *base);

/* 写面守卫（write/edit）：cwd 子树 ∪ /tmp ∪ /var/ai（W1 惯例目标域）；
 * ~/.occ 一律拒绝（会话库完整性）。abs 必须已 realpath 化或以 / 开头。 */
int occ_write_target_ok(const char *abs, const char *cwd);

/* UTF-8 边界安全截断：至多 max 字节，返回实际保留字节数（不切多字节）。
 * 尾部补 suffix（如 "\n…[truncated N B]"）写入 dst。 */
size_t occ_utf8_trunc(const char *src, size_t len, size_t max,
		      char *dst, size_t dstlen);

/* ---- trace（单测直接调） ----
 * 单行 JSONL 追加。args 摘要：原文截 256 字节（UTF-8 安全）。
 * 永不失败阻断：打开/写失败仅 stderr 警告一次。
 */
int occ_trace_tool(const char *trace_dir, const char *session_id,
		   const char *msg_id, const char *tool,
		   const char *args_json, int rc, long long dur_ms,
		   size_t out_bytes);

/* 当前单调毫秒（耗时测量） */
long long occ_monotonic_ms(void);

/* 测试钩子：清空 aik-sandbox --rw-path 探测缓存（单测换 stub 用；
 * 生产进程探测一次即缓存，不调用本函数） */
void occ_sandbox_probe_cache_reset(void);

#endif /* _OCC_TOOLS_H */
