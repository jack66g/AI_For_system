// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_ask.c - ask 命令实现（AI 工具调用闭环）
 *
 * "AI 为主体"的入口：用户用自然语言下达系统管理任务，AI 通过工具
 * （procfs 读 / sysfs 写 / NETLINK_AI ACT / 白名单 exec / SME 记忆）
 * 自主完成操作并给出回答。
 *
 * 流程：
 *   1. 加载工具注册表（tools.json，tools/gen_registry.py 生成）；
 *   2. SME 路由决策：会话级"已激活工具集合"（默认 8 个）+ 路由模式
 *      （[routing].mode；auto 按 provider：cloud=autonomous 云端模型
 *      自主检索 / local=pre_retrieve 框架预检索）；
 *   3. 组 system prompt：身份 + 目录页（自主模式常驻，~3KB）+ 检索
 *      指引 + 精简约束（原全量 8KB 工具清单不再常驻，降级路径除外）；
 *   4. 会话历史加载：从 ~/.aikernel/sessions/<name>.jsonl 读入跨 ask
 *      历史（session 命令管理，UI Phase 起默认会话 "default"）；
 *   5. 上下文注入：最近一次 NETLINK_AI sense 摘要（可选）+ 本地预
 *      检索模式的 SME 命中（激活+注入一次完成；autonomous 模式不
 *      被动注入，模型自主 memory_search）；
 *   6. 模型循环（上限 12 轮防失控，触顶后一次无工具收尾结论）：
 *        - 流式优先（[ui].stream=on）：delta.content 逐段实时打印，
 *          后端失败自动回退非流式（本地通道在 local_backend 内回退，
 *          云端通道整体缓冲后按 SSE 语义解析，行为一致）；
 *        - 原生 tool_calls 路径：请求体带 tools 数组（=已激活集合，
 *          memory_search 命中的工具由框架解析后动态扩入下一请求）；
 *        - 降级路径：模型/服务不支持 tools 字段时（请求报错或模型只
 *          回文本），改用"文本 JSON 约定"（系统提示声明格式，文本解析）；
 *        - 每个工具调用 → 注册表查表 → 自动执行（无交互确认，全部
 *          自动执行；审计由决策 ring/因果链 + [audit] 行承载）→
 *          role:tool 消息回填 → 继续下一轮；
 *        - 等待模型期间显示 braille spinner（首 token 到达即清除）；
 *   7. 无工具调用的回答即最终答案；全部消息追加落盘会话文件。
 *
 * 过程可见性：工具调用输出折叠为单行卡片（`└─ 名字 · OK · 摘要`），
 * 结果超过 3 行提示行数；verbose on 切换为全展开。
 *
 * 上下文预算治理（W18 P0-2，README 式说明）：
 *   预算模型：历史可用预算 = ctx_len − 生效 max_tokens − 预留
 *   （字节口径 ×3 粗估，见 ask_compact_msg_tokens）。治理三道闸门：
 *   1) 单条工具结果入历史前摘要化（execute_round 钩子）：超过
 *      min(8KB, (ctx_len−max_tokens)×3/4) 字节的结果替换为
 *      "头部 2KB + [摘要：原 N 字节/约 M 行，工具 X，完整结果可重新
 *      调用获取]"——屏幕卡片仍显示原文首行，会话文件同样落摘要；
 *      role/tool_call_id 配对不变（工具调用对完整性），memory_search
 *      豁免（SME JSON 是路由核心，体量有界）；
 *   2) ask 入口自动 compact：加载历史后估算占用 ≥80% 历史预算即复用
 *      compact 命令通道（LLM 摘要替换全部历史、会话累计 token 归零），
 *      屏幕提示 [历史已自动压缩]；失败如实提示并按原历史继续；
 *   3) 轮间窗口裁剪（ask_hist_trim，既有）：按整轮裁最老历史，工具
 *      调用对绝不拆散，compact 摘要钉住。
 *   三闸门叠加后，单次请求注入有硬上限，本地 8k 窗口不爆，云端 1M
 *   行为不变；占用百分比常规曲线 ≤100%，仍超限的场景（compact 失败
 *   /单轮超预算）如实显示真实值。
 *
 * 内存所有权：消息数组中的 content/tool_calls_json 一律指向
 * owned 字符串池中的副本（进入池后统一在 cmd_ask 退出时释放），
 * 避免消息数组悬挂指针。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_runtime.h"
#include "ai_config.h"
#include "ai_json_util.h"
#include "ai_ui.h"
#include "netlink/ai_netlink_client.h"
#include "memory/sme_client.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "ai_lang.h"
#include "policy/ai_user_policy.h"   /* W43: plan 模式查询 */
#include "policy/ai_lease.h"         /* W74: danger/lease trace 字段 */
#include "ai_trace.h"                /* W48B: 全轨迹日志 */
#include "ask_context.h"             /* W55: 状态紧凑摘要/请求预算口径 */
#include "ask_compact.h"             /* W59: 压缩替换计划/循环上限 */
#include "ask_clarify.h"             /* W77c: 结构化澄清（clarify 工具） */
#include "local/offline_intent.h"    /* W77: 离线意图层 */

/* 模型调用轮数上限（防工具循环失控；T2 P1-4：5 轮对白名单受限环境
 * 过低常态化烧尽，放宽为 8，可用环境变量 AIKERNEL_MAX_ROUNDS 覆盖）。
 * W72：8→12（W70 T17 删除+验证 8 轮触顶且无最终结论）；触顶后再发一次
 * "禁止工具、只给结论"的收尾请求，仍由 max_rounds 硬上限防死循环。 */
#define ASK_MAX_ROUNDS      12

/*
 * W72：单次压缩的最后保留统计（cmd_compact.c 提供）。kept>0 说明压缩
 * 已留下最近原文；即使仍高于触发线也接受软 target，不在同一 ask 内
 * 二次压缩/截断（否则刚保留的近轮原文会被再次裁掉）。
 */
extern int cmd_compact_last_kept(void);
extern long cmd_compact_last_after(void);

/* ---- W65 P1-01：Ctrl-C 取消（REPL 空闲清行 / ask 生成中取消） ----
 *
 * linenoise 在 raw 模式关闭 ISIG，Ctrl-C 以字节形式返回 NULL+EAGAIN；
 * ask 执行期 tty 只关 ICANON/ECHO、保留 ISIG，Ctrl-C 会真的产生 SIGINT。
 * 旧实现没有 handler，默认动作直接杀死进程（W62 rob-03 rc=255）。
 *
 * 方案：进程级 SIGINT handler 只置位 ai_cancel_requested；ask 活跃时
 * 额外对 3..1023 的 socket fd 做 shutdown()——TLS/明文 HTTP 的阻塞 read
 * 会立即返回，模型调用/工具等待在 100ms 级退出，无需 longjmp（避免
 * 跨 TLS/stdio 栈帧跳转的锁与资源泄漏）。REPL 空闲时 handler 不 shutdown，
 * 只让 fgets/read 返回 EINTR，aikernel_main 负责清行继续。
 */
volatile sig_atomic_t ai_cancel_requested;
static volatile sig_atomic_t g_ask_active;
static int g_sigint_installed;
static struct sigaction g_sigint_old;

static void ask_sigint_handler(int sig)
{
	int fd;

	(void)sig;
	ai_cancel_requested = 1;
	if (!g_ask_active)
		return;
	/* 只 shutdown socket：stdin/stdout/stderr（0..2）与普通文件不受
	 * 影响；非 socket fd 返回 ENOTSOCK，可安全忽略。 */
	for (fd = 3; fd < 1024; fd++)
		shutdown(fd, SHUT_RDWR);
}

void ai_cancel_install(void)
{
	struct sigaction sa;

	if (g_sigint_installed)
		return;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = ask_sigint_handler;
	sigemptyset(&sa.sa_mask);
	/* 不置 SA_RESTART：让阻塞 read/fgets 返回 EINTR（空闲 Ctrl-C
	 * 的清行路径依赖此语义）。 */
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, &g_sigint_old) == 0)
		g_sigint_installed = 1;
}

void ai_cancel_restore(void)
{
	if (!g_sigint_installed)
		return;
	sigaction(SIGINT, &g_sigint_old, NULL);
	g_sigint_installed = 0;
}

/* ask 入口：安装 handler、清旧标志、进入活跃态 */
void ai_cancel_arm(void)
{
	ai_cancel_install();
	ai_cancel_requested = 0;
	g_ask_active = 1;
}

/* ask 出口：退出活跃态（handler 保留给 REPL 空闲 Ctrl-C 使用） */
void ai_cancel_disarm(void)
{
	g_ask_active = 0;
}


/* 轮数上限的环境变量覆盖边界 */
#define ASK_MAX_ROUNDS_MIN  1
#define ASK_MAX_ROUNDS_MAX  32

/* 单次对话最大消息数（动态数组，64 提到 256：8 轮 × 多工具并行的
 * 最坏组合下 64 会静默丢消息——ask_msgs_push 满即弃） */
#define ASK_MAX_MESSAGES    256

/*
 * 历史窗口裁剪（修复 5，T2 P1-5）参数：
 * - ASK_HIST_RESERVE_TOKENS / ASK_HIST_BUDGET_MIN：预算口径统一在
 *   ask_context.h（W59 起 cmd_compact 共用同一算式）；
 * - ASK_HIST_MIN_TURNS：保底保留的最近轮数（预算再紧也不全裁光）；
 * - ASK_HIST_MAX_MESSAGES：条数硬上限（防内存，仍按整轮裁）。
 */
#define ASK_HIST_MIN_TURNS       2
#define ASK_HIST_MAX_MESSAGES    64

/* 上下文注入片段上限（字节） */
#define ASK_CTX_SNIPPET_MAX 2048

/*
 * 工具结果入历史摘要化（W18 P0-2a）参数：
 * 单轮内大量工具调用的大结果（观测 +840 行/份）全量入历史后，轮间
 * 窗口裁剪追不上，上下文预算语义失效（云端 1M 无害，本地 8k 必死）。
 * 修复分三层：
 *   a) 入历史前摘要化（本节参数 + execute_round 钩子）——超阈值的
 *      工具结果替换为"头部 2KB + 摘要标注"，role:tool 的配对 ID 不变，
 *      工具调用对完整性不受影响；会话文件同样落摘要（否则下次 ask
 *      重放又胀回去）；
 *   b) ask 入口自动 compact（cmd_ask 第 4 步，历史估算 ≥80% 预算时
 *      复用既有 compact 通道）；
 *   c) 占用显示如实（治理后常规曲线 ≤100%，仍超限如实显示真值）。
 * 摘要阈值预算驱动：min(ASK_TOOL_RESULT_CAP,
 * (ctx_len - max_tokens) * 3 / ASK_TOOL_RESULT_DENOM) 字节——
 * 3 = ask_compact_msg_tokens 的字节/token 粗估系数；分母 4 即单条工具
 * 结果最多吃掉历史预算的 1/4。cloud/local 同一逻辑。
 */
#define ASK_TOOL_SUMMARY_KEEP   2048	/* 摘要保留头部字节（UTF-8 对齐） */
#define ASK_TOOL_RESULT_CAP     8192	/* 阈值上限（字节） */
#define ASK_TOOL_RESULT_DENOM   4	/* 预算占比分母（1/4） */

/* ---- SME 路由（C 阶段：SME 检索成为接口路由核心） ----
 *
 * OpenAI 协议严格模式下模型只能调用请求 tools 列表里的工具，所以
 * "补全 schema"必须是框架行为：维护会话级"已激活工具集合"——SME
 * 检索结果命中的工具名 → 框架解析 → 下一请求的 tools 数组动态扩入
 * 该工具完整 schema。两种驱动（[routing].mode，auto 按 provider）：
 *   autonomous    云端：模型自主检索——system 常驻目录页（工具名+
 *                 一句话）+ 检索指引；模型先 memory_search 查接口
 *                 用法，命中工具自动扩入下一请求。
 *   pre_retrieve  本地：框架预检索——ask 进来框架先 SME 检索
 *                 top-K，命中工具扩入请求 tools，模型无感知。
 * 目录页不是 tools 数组成员（避免模型直接调"目录"），放 system
 * prompt 里作为可点名清单。 */

/* 本地预检索条数（框架预检索 top_k；注入+激活一次完成） */
#define ASK_ROUTE_PRE_TOPK      5

/* SME 预检索结果缓冲（top_k=5 时完整 JSON 可达 ~10KB，栈上放大） */
#define ASK_ROUTE_SME_BUF       16384

/*
 * 默认激活集（12 题命中分布定）：q01-q07/q10-q12 全走 exec_run，
 * q08/q09 走 procfs_read_status/procfs_read_control，memory_search
 * 是路由核心常驻，netlink_sense 供遥测类问题。
 *
 * W56 T2：memory_stats/memory_health 是记忆元能力（统计/健康探活），
 * "记忆库统计"这类提问若靠检索激活会慢一轮，模型容易在命中前放弃；
 * 二者均为 R 级只读，常驻 8 件（W77c 含 clarify；round1 即可直接调用）。
 */
static const char *const ASK_DEFAULT_ACTIVE[] = {
	"memory_search",
	"memory_stats",
	"memory_health",
	"exec_run",
	"procfs_read_status",
	"procfs_read_control",
	"netlink_sense",
	"clarify",          /* W77c：所有模型常驻，可主动发起结构化澄清 */
};
#define ASK_DEFAULT_ACTIVE_N \
	(sizeof(ASK_DEFAULT_ACTIVE) / sizeof(ASK_DEFAULT_ACTIVE[0]))

/*
 * W70：router 激活上限。SME 检索结果里的工具名会被逐个扩入 tools 数组；
 * 单次长会话实测最多扩到 74/130，schema 体积和请求延迟都明显上升。
 * 默认 8 件 + 24 件检索命中足够覆盖单轮任务；超出部分下一轮检索仍可
 * 重新激活，不会丢失能力发现。
 */
#define ASK_ROUTER_MAX_ACTIVE 32

/* 会话级已激活工具集合 */
struct ask_router {
	int mode;               /* AI_ROUTE_AUTONOMOUS / PRE_RETRIEVE */
	int catalog;            /* system 是否带目录页 */
	char **active;          /* 已激活工具名（去重，strdup 持有） */
	int n_active;
	int cap_active;
	int dirty;              /* 1=tools_json 需按激活集重建 */
	int activated_total;    /* 统计：累计激活新工具个数（证据） */
};

/* 消息数组（动态增长） */
struct ask_msgs {
	struct ai_chat_msg *m;
	int n;
	int cap;
};

/* 字符串所有权池：放入的字符串在 ask 结束时统一释放 */
struct ask_owned {
	char **s;
	int n;
	int cap;
};

/* 流式打印上下文 */
struct ask_stream {
	int color;
	int printed;            /* 本轮已打印过增量内容 */
};

/* 接管字符串所有权（返回原指针，便于链式赋值；接管失败则立即释放） */
static char *ask_own(struct ask_owned *o, char *s)
{
	if (!s)
		return NULL;
	if (o->n >= o->cap) {
		int ncap = o->cap ? o->cap * 2 : 16;
		char **ns = realloc(o->s, sizeof(char *) * (size_t)ncap);

		if (!ns) {
			free(s);
			return NULL;
		}
		o->s = ns;
		o->cap = ncap;
	}
	o->s[o->n++] = s;
	return s;
}

static void ask_owned_free(struct ask_owned *o)
{
	int i;

	for (i = 0; i < o->n; i++)
		free(o->s[i]);
	free(o->s);
	memset(o, 0, sizeof(*o));
}

static int ask_msgs_push(struct ask_msgs *a, const struct ai_chat_msg *msg)
{
	if (a->n >= ASK_MAX_MESSAGES)
		return AI_ERR_INVALID_ARG;
	if (a->n >= a->cap) {
		int ncap = a->cap ? a->cap * 2 : 16;
		struct ai_chat_msg *nm = realloc(a->m,
						 sizeof(*nm) * (size_t)ncap);

		if (!nm)
			return AI_ERR_MEMORY;
		a->m = nm;
		a->cap = ncap;
	}
	a->m[a->n++] = *msg;
	return AI_OK;
}

/*
 * ask_add_repair_hint - 参数契约自动纠正（W65 P2-03）
 * 工具返回 ERROR[E_PARAM*] 后追加一条 user 提示，要求模型按结构化
 * USAGE 立即重试一次；每轮 ask 最多一次（cmd_ask 里 repair_used 守卫）。
 */
static void ask_add_repair_hint(struct ask_msgs *a, struct ask_owned *owned)
{
	struct ai_chat_msg m;

	memset(&m, 0, sizeof(m));
	m.role = "user";
	m.content = ask_own(owned, strdup(tr(TR_ASK_ARG_REPAIR_HINT)));
	if (m.content)
		ask_msgs_push(a, &m);
}

/* ---- 流式增量打印 ---- */

/*
 * ask_on_delta - delta.content 逐段回调（流式路径）
 * 首段到达时清除 spinner 并打出 "AI:" 前缀，之后原样写 stdout。
 */
static void ask_on_delta(void *ud, const char *d, size_t n)
{
	struct ask_stream *s = ud;

	if (!s->printed) {
		ui_spinner_stop();
		printf("%sAI:%s ", ui_c(s->color, UI_C_CYAN),
		       ui_c(s->color, UI_C_RESET));
		s->printed = 1;
	}
	fwrite(d, 1, n, stdout);
	fflush(stdout);
}

/* ---- system prompt ----
 * 双语（i18n 表 TR_ASK_SYS_*）：界面语言只决定提示词文案；回答语言
 * 跟随用户提问语言（W56 T4）。W56 T1：assume_yes 预授权在 prompt 中
 * 对模型可见，避免模型停在"请确认"；plan 模式优先（不输出预授权段）。 */

#define ASK_SYSTEM_IDENTITY tr(TR_ASK_SYS_IDENTITY)

/* 检索指引（autonomous 模式常驻：教模型用 memory_search 查接口用法，
 * 替代原全量工具枚举——工具用法细节由 SME 语料按需检索提供） */
#define ASK_SYSTEM_RETRIEVAL tr(TR_ASK_SYS_RETRIEVAL)

/* 约束（精简版：接口检索条移入检索指引；工具枚举由目录页/tools
 * 数组承担，原 8KB 全量清单不再常驻） */
#define ASK_SYSTEM_RULES_SHORT tr(TR_ASK_SYS_RULES_SHORT)

/* 降级模式仍需全量清单（文本协议下模型没有 tools 数组，工具名+
 * 参数只能从 system 里拿） */
#define ASK_SYSTEM_RULES tr(TR_ASK_SYS_RULES)

/* 降级协议声明（模型不支持 tools 字段时追加到 system prompt） */
#define ASK_FALLBACK_RULES tr(TR_ASK_FALLBACK_RULES)

/* W43：plan 只读模式注入段（≤200 token，plan 态追加到 system 末尾；
 * 开关状态在 policy/ai_user_policy.c，闸门在 executor.c） */
#define ASK_SYSTEM_PLAN_NOTE tr(TR_PLAN_SYS_NOTE)

/*
 * build_system_prompt - 组装 system 消息内容
 * @sum:     全量工具清单文本（tool_registry_summarize；仅降级路径用）
 * @fallback: 1=追加降级 JSON 协议说明（配全量清单）
 * @mode:    AI_ROUTE_AUTONOMOUS / AI_ROUTE_PRE_RETRIEVE
 * @catalog: 目录页文本（autonomous 常驻；pre_retrieve 可 NULL）
 *
 * 瘦身后 native 路径 = 身份 + 目录页(可选) + 检索指引(自主模式) +
 * 精简约束 + 运行时策略段（assume_yes/语言），不再内嵌全量工具枚举
 * （原 ~8KB → 目标 ≤5KB）。
 */
static char *build_system_prompt(const char *sum, int fallback, int mode,
				 const char *catalog)
{
	int plan = ai_policy_get_plan_mode();
	char notes[1024];
	size_t nlen = 0;
	size_t cap;
	char *out;

	/* W56 T1/T4：assume_yes 预授权 + 语言默认（plan 优先，见函数内） */
	notes[0] = '\0';
	if (ask_prompt_policy_notes_build(ai_policy_get_assume_yes(), plan,
					  notes, sizeof(notes)) > 0)
		nlen = strlen(notes);

	if (fallback) {
		size_t plen = plan ? strlen(ASK_SYSTEM_PLAN_NOTE) : 0;

		cap = strlen(ASK_SYSTEM_IDENTITY) + strlen(ASK_SYSTEM_RULES) +
		      strlen(ASK_FALLBACK_RULES) + (sum ? strlen(sum) : 0) +
		      nlen + plen + 256;
		out = malloc(cap);
		if (!out)
			return NULL;
		snprintf(out, cap, tr(TR_ASK_TOOLS_LIST_FMT),
			 ASK_SYSTEM_IDENTITY, sum ? sum : "",
			 ASK_SYSTEM_RULES, ASK_FALLBACK_RULES);
		if (nlen)
			snprintf(out + strlen(out), cap - strlen(out), "%s",
				 notes);
		if (plen)
			snprintf(out + strlen(out), cap - strlen(out), "%s",
				 ASK_SYSTEM_PLAN_NOTE);
		return out;
	}

	/* native 路径：工具说明交给目录页 + tools 数组 schema */
	cap = strlen(ASK_SYSTEM_IDENTITY) + strlen(ASK_SYSTEM_RULES_SHORT) +
	      512 + (catalog ? strlen(catalog) : 0) +
	      (mode == AI_ROUTE_AUTONOMOUS ? strlen(ASK_SYSTEM_RETRIEVAL) : 0) +
	      nlen + (plan ? strlen(ASK_SYSTEM_PLAN_NOTE) : 0);
	out = malloc(cap);
	if (!out)
		return NULL;

	snprintf(out, cap, "%s%s%s%s",
		 ASK_SYSTEM_IDENTITY,
		 catalog ? tr(TR_ASK_CATALOG_HDR) : "",
		 catalog ? catalog : "",
		 mode == AI_ROUTE_AUTONOMOUS ? ASK_SYSTEM_RETRIEVAL : "");
	{
		size_t len = strlen(out);

		snprintf(out + len, cap - len, "%s", ASK_SYSTEM_RULES_SHORT);
	}
	/* W56 T1/T4：运行时策略段（assume_yes 仅在非 plan 态出现） */
	if (nlen) {
		size_t len = strlen(out);

		snprintf(out + len, cap - len, "%s", notes);
	}
	/* W43：plan 态追加只读约束（≤200 token，预算内） */
	if (plan) {
		size_t len = strlen(out);

		snprintf(out + len, cap - len, "%s", ASK_SYSTEM_PLAN_NOTE);
	}
	return out;
}

/*
 * build_fallback_system - 降级路径 system（全量清单按激活集合裁剪）
 *
 * W55 P1：tools 数组扩入后，降级路径的文本清单也必须同步重建，否则
 * 模型看到的工具清单仍是启动时的 8 件（框架提示与实际能力不一致）。
 */
static char *build_fallback_system(struct tool_registry *reg,
				   const struct ask_router *router,
				   int route_mode)
{
	char *fsum;
	char *sum = NULL;
	char *sys;

	if (!reg || !router)
		return NULL;
	fsum = tool_registry_summarize_filtered(
		reg, (const char *const *)router->active, router->n_active);
	if (!fsum)
		sum = tool_registry_summarize(reg);
	sys = build_system_prompt(fsum ? fsum : (sum ? sum : ""), 1,
				  route_mode, NULL);
	free(fsum);
	free(sum);
	return sys;
}

/* ---- SME 路由：会话级激活集合 ---- */

/*
 * router_init - 初始化路由器（载入默认激活集）
 * @mode:    AI_ROUTE_AUTONOMOUS / AI_ROUTE_PRE_RETRIEVE
 * @catalog: 1=system 带目录页
 */
static int router_init(struct ask_router *r, int mode, int catalog)
{
	size_t i;

	memset(r, 0, sizeof(*r));
	r->mode = mode;
	r->catalog = catalog;
	r->cap_active = (int)ASK_DEFAULT_ACTIVE_N + 4;
	r->active = malloc(sizeof(char *) * (size_t)r->cap_active);
	if (!r->active)
		return AI_ERR_MEMORY;
	for (i = 0; i < ASK_DEFAULT_ACTIVE_N; i++) {
		char *dup = strdup(ASK_DEFAULT_ACTIVE[i]);

		if (!dup)
			continue;
		r->active[r->n_active++] = dup;
	}
	r->dirty = 1;
	return AI_OK;
}

static void router_free(struct ask_router *r)
{
	int i;

	for (i = 0; i < r->n_active; i++)
		free(r->active[i]);
	free(r->active);
	memset(r, 0, sizeof(*r));
}

/*
 * router_activate - 工具名扩入激活集合（去重）
 * 返回: 1=新激活（调用方记证据），0=已在集合或加入失败
 */
static int router_activate(struct ask_router *r, const char *name)
{
	int i;
	char *dup;

	if (!name || !name[0] || strlen(name) >= 64)
		return 0;
	for (i = 0; i < r->n_active; i++)
		if (strcmp(r->active[i], name) == 0)
			return 0;
	if (r->n_active >= ASK_ROUTER_MAX_ACTIVE)
		return 0;
	if (r->n_active >= r->cap_active) {
		int ncap = r->cap_active * 2;
		char **na = realloc(r->active,
				    sizeof(char *) * (size_t)ncap);

		if (!na)
			return 0;
		r->active = na;
		r->cap_active = ncap;
	}
	dup = strdup(name);
	if (!dup)
		return 0;
	r->active[r->n_active++] = dup;
	r->dirty = 1;
	r->activated_total++;
	return 1;
}

/*
 * router_activate_from_sme - 从 SME 检索结果 JSON 提取工具名并激活
 *
 * 语料 text 里工具名有两种书写形态：下划线原样（exec_run）与点号
 * （netlink.act.sched.nice，接口语料惯例）。扫描 JSON 文本中的标识
 * 符 token（[A-Za-z_][A-Za-z0-9_.]*），点号形态转下划线后对照注册表
 * 查存在性——查不到的 token（URL 片段/普通词等）自然丢弃，无害。
 * 返回: 新激活个数
 */
static int router_activate_from_sme(struct ask_router *r,
				    const struct tool_registry *reg,
				    const char *json)
{
	const char *p = json;
	char tok[64];
	int added = 0;

	if (!r || !reg || !json)
		return 0;

	while (*p) {
		size_t n = 0;
		char clean[64];
		size_t ci, cl;

		/* 找 token 起点 */
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      *p == '_')) {
			p++;
			continue;
		}
		while (p[n] &&
		       ((p[n] >= 'a' && p[n] <= 'z') ||
			(p[n] >= 'A' && p[n] <= 'Z') ||
			(p[n] >= '0' && p[n] <= '9') ||
			p[n] == '_' || p[n] == '.') &&
		       n < sizeof(tok) - 1)
			n++;
		if (n < 3) {
			p += n ? n : 1;
			continue;
		}
		memcpy(tok, p, n);
		tok[n] = '\0';

		/* 形态 1：下划线原样（token 尾部 '.' 去掉） */
		cl = n;
		while (cl > 0 && tok[cl - 1] == '.')
			cl--;
		memcpy(clean, tok, cl);
		clean[cl] = '\0';
		if (cl >= 3) {
			const struct ai_tool *ft =
				tool_registry_find(reg, clean);

			/* W65 P2-05：能力探测不可用的工具不激活
			 * （如内核无 PSI 时的 /proc/pressure 工具），
			 * 避免模型拿到不可调用的 schema。 */
			if (ft && ft->available &&
			    router_activate(r, clean))
				added++;
		}

		/* 形态 2：点号 → 下划线 */
		if (memchr(clean, '.', cl)) {
			const struct ai_tool *ft;

			for (ci = 0; ci < cl; ci++)
				if (clean[ci] == '.')
					clean[ci] = '_';
			ft = tool_registry_find(reg, clean);
			if (ft && ft->available &&
			    router_activate(r, clean))
				added++;
		}
		p += n;
	}
	return added;
}

/* ---- 上下文注入 ---- */

/*
 * inject_sense_context - 尝试拉取最近一次内核遥测（NETLINK_AI SENSE）
 * 成功返回 malloc 摘要文本；失败（宿主机无 AIKernel 内核等）返回 NULL，
 * 属正常场景静默跳过。该调用同时让 QEMU 内 ask 的 netlink sense 真实发生。
 */
static char *inject_sense_context(void)
{
	struct ai_nl_client cli;
	struct ai_nl_sense_ack ack;
	unsigned char *stream;
	size_t stream_len = 0;
	int kern_err = 0;
	int rc;
	char *out;

	rc = ai_nl_client_open(&cli);
	if (rc != AI_OK)
		return NULL;

	stream = malloc(AI_NL_PAYLOAD_MAX);
	if (!stream) {
		ai_nl_client_close(&cli);
		return NULL;
	}

	rc = ai_nl_send_sense(&cli, AI_NL_SENSE_CPU_ALL, 8,
			      AI_NL_FORMAT_HUMAN, &ack,
			      stream, AI_NL_PAYLOAD_MAX, &stream_len,
			      &kern_err);
	ai_nl_client_close(&cli);

	if (rc != AI_OK || ack.records == 0) {
		free(stream);
		return NULL;
	}

	{
		size_t snip = stream_len < (size_t)ASK_CTX_SNIPPET_MAX ?
			      stream_len : (size_t)ASK_CTX_SNIPPET_MAX;

		/* 截断对齐 UTF-8 边界（T2 问题 1：切半的汉字进请求体
		 * 会被服务端以非法 UTF-8 拒收） */
		snip = ai_json_utf8_floor((const char *)stream, snip);

		if (asprintf(&out, tr(TR_ASK_SENSE_FMT), ack.records,
			     (int)snip, (const char *)stream) < 0) {
			free(stream);
			return NULL;
		}
	}
	free(stream);
	return out;
}

/*
 * inject_kernel_context - 内核上下文注入（W55 P2）
 *
 * 首选 /proc/ai/status 紧凑摘要（≤2KB，完整内容留给
 * procfs_read_status 工具按需读取）；文件不可读（非 AIKernel 宿主 /
 * 权限不足）时回退既有 NETLINK SENSE 摘要。@is_status 出参标记走了
 * 哪条路径，供 UI 打印准确提示。
 */
static char *inject_kernel_context(int *is_status)
{
	FILE *fp;
	char *raw;
	size_t n;
	char summary[ASK_STATUS_SUMMARY_MAX];
	char *body = NULL;
	char *out = NULL;
	int rc;

	if (is_status)
		*is_status = 0;
	fp = fopen("/proc/ai/status", "r");
	if (!fp)
		return inject_sense_context();
	raw = malloc(131073);
	if (!raw) {
		fclose(fp);
		return inject_sense_context();
	}
	n = fread(raw, 1, 131072, fp);
	fclose(fp);
	raw[n] = '\0';

	rc = ask_status_summary_build(raw, summary, sizeof(summary));
	free(raw);
	if (rc <= 0)
		return inject_sense_context();

	if (asprintf(&body, tr(TR_ASK_STATUS_FMT), summary) < 0)
		return NULL;
	if (asprintf(&out, "%s%s", body, tr(TR_ASK_STATUS_NOTE)) < 0) {
		free(body);
		return NULL;
	}
	free(body);

	/* 硬上限：摘要块（含框架文案与 sampled_skip 说明）≤2KB */
	if (strlen(out) >= ASK_STATUS_SUMMARY_MAX) {
		size_t keep = ai_json_utf8_floor(out,
						 ASK_STATUS_SUMMARY_MAX - 1);

		out[keep] = '\0';
	}
	if (is_status)
		*is_status = 1;
	return out;
}

/*
 * route_pre_retrieve - 本地预检索（pre_retrieve 模式）
 * ask 进来框架先 SME 检索 top-K：命中语料里的工具名激活进请求
 * tools 数组（模型无感知），命中文本照旧注入 user 消息辅助回答。
 * 一次检索同时完成两件事。SME 不可达时返回 NULL 静默跳过。
 * （原 inject_memory_context 被其取代：autonomous 模式不再被动
 * 注入记忆，改由模型自主 memory_search；pre_retrieve 模式注入+
 * 激活一次完成。）
 */
static char *route_pre_retrieve(const char *question,
				struct tool_registry *reg,
				struct ask_router *router)
{
	char *resp;
	char *out;
	size_t snip;
	int rc;
	int before;

	resp = malloc(ASK_ROUTE_SME_BUF);
	if (!resp)
		return NULL;

	rc = sme_search(question, ASK_ROUTE_PRE_TOPK, resp,
			ASK_ROUTE_SME_BUF);
	if (rc != AI_OK) {
		/* W43 失忆降级：不再静默——明示本次无记忆检索
		 * （工具路径的降级标记在 executor.c memory 通道） */
		printf("%s", tr(TR_SME_DEGRADED_NOTE));
		ai_trace_degraded("sme",
			sme_degrade_reason_of(rc) == SME_DEGRADED_UNAVAILABLE ?
			"unavailable" : "http_error",
			"pre_retrieve search failed");
		free(resp);
		return NULL;
	}

	/* 命中工具激活（下一请求 tools 数组扩入完整 schema） */
	before = router->n_active;
	{
		int added = router_activate_from_sme(router, reg, resp);

		if (added > 0) {
			const char **names = malloc(sizeof(char *) *
						    (size_t)added);
			int i;

			if (names) {
				for (i = 0; i < added; i++)
					names[i] = router->active[before + i];
				ai_trace_route_activate("pre_retrieve", names,
							added, before,
							router->n_active);
				free(names);
			}
		}
	}

	/* 注入文本（与 inject_memory_context 同格式） */
	snip = strlen(resp);
	{
		char body[ASK_CTX_SNIPPET_MAX + 1];

		if (snip > (size_t)ASK_CTX_SNIPPET_MAX)
			snip = (size_t)ASK_CTX_SNIPPET_MAX;
		snip = ai_json_utf8_floor(resp, snip);
		memcpy(body, resp, snip);
		body[snip] = '\0';

		if (asprintf(&out, tr(TR_ASK_MEM_FMT), body) < 0)
			out = NULL;
	}
	free(resp);
	return out;
}

/* ---- 会话持久化 ---- */

/*
 * ask_sess_append - 追加一条消息到当前会话（失败静默：会话是增强，
 * 不因磁盘问题打断 ask 主流程）
 */
static void ask_sess_append(struct ai_shell *shell, const char *role,
			    const char *content, const char *tool_call_id,
			    const char *tool_name,
			    const char *tool_calls_json)
{
	struct ui_session_rec rec;

	memset(&rec, 0, sizeof(rec));
	rec.role = role;
	rec.content = content;
	rec.tool_call_id = tool_call_id;
	rec.tool_name = tool_name;
	rec.tool_calls_json = tool_calls_json;
	rec.ts = time(NULL);
	ui_session_append(shell->config->ui.session, &rec);
}

/* ---- 工具执行 ---- */

/*
 * run_one_tool - 查注册表并执行，返回结果文本（malloc，调用者接管）
 * 失败（未知工具/执行失败）也返回可回填模型的说明文本。
 * W48B：工具调用全量轨迹（参数/耗时/退出码/结果）在此记录。
 */
static const char *ask_trace_channel(enum tool_channel ch)
{
	switch (ch) {
	case TOOL_CH_PROCFS_READ:	return "procfs-read";
	case TOOL_CH_SYSFS_WRITE:	return "sysfs-write";
	case TOOL_CH_NETLINK_ACT:	return "netlink-act";
	case TOOL_CH_NETLINK_SENSE:	return "netlink-sense";
	case TOOL_CH_EXEC:		return "exec";
	case TOOL_CH_MEMORY:		return "memory";
	case TOOL_CH_SHELL:		return "shell";
	case TOOL_CH_SANDBOX:		return "sandbox";
	case TOOL_CH_CLARIFY:		return "interaction";
	default:			return "unknown";
	}
}

static int ask_trace_exit_code(const struct ai_tool *tool, int ok,
			       const char *out)
{
	if (tool->channel != TOOL_CH_EXEC)
		return -1;
	if (ok)
		return 0;
	if (out) {
		const char *p = strstr(out, "命令退出码 ");

		if (p)
			return atoi(p + strlen("命令退出码 "));
	}
	return -1;
}

static const char *ask_tool_status(int ok, const char *out)
{
	if (ok)
		return AI_TRACE_STATUS_OK;
	/* W69 P1-4：denied 只认 executor 的显式策略拒绝前缀
	 * （plan/W2/黑名单/沙箱隔离）。二进制缺失、执行失败、参数错误
	 * 一律 fail——此前 "拒绝执行" 子串把二进制缺失也算 denied。 */
	if (tool_exec_result_is_denied(out))
		return AI_TRACE_STATUS_DENIED;
	return AI_TRACE_STATUS_FAIL;
}

static char *run_one_tool(const struct tool_registry *reg,
			  const struct ai_tool_call *tc, int *ok)
{
	const struct ai_tool *tool;
	char *out;
	long long t0;
	long long wall0;

	*ok = 0;
	ai_lease_last_reset();
	tool = tool_registry_find(reg, tc->name);
	if (!tool) {
		if (asprintf(&out, tr(TR_ASK_UNKNOWN_TOOL), tc->name) < 0)
			out = NULL;
		ai_trace_tool_call_status(tc->name, "unknown", "-",
			tc->arguments, ai_trace_wall_ms(), 0,
			AI_TRACE_STATUS_ERROR, -1, out,
			out ? strlen(out) : 0);
		return out;
	}
	t0 = ai_trace_now_ms();
	wall0 = ai_trace_wall_ms();
	tool_executor_run(tool, tc->arguments, &out, ok);
	ai_trace_tool_call_ex(tool->name,
			   ask_trace_channel(tool->channel),
			   tool_exec_effective_risk(tool, tc->arguments),
			   tc->arguments,
			   wall0, (long)(ai_trace_now_ms() - t0),
			   ask_tool_status(*ok, out),
			   ask_trace_exit_code(tool, *ok, out), out,
			   out ? strlen(out) : 0,
			   ai_lease_last_danger(), ai_lease_last_lease_id());
	if (tool->channel == TOOL_CH_MEMORY && !*ok) {
		/* W69 P2-3：按真实返回码分类，不再一律 "unavailable"。
		 * 参数错误（E_PARAM）不是降级，不写 degraded 事件。 */
		int dr = sme_degrade_reason_of(tool_exec_memory_last_rc());

		if (dr == SME_DEGRADED_UNAVAILABLE)
			ai_trace_degraded("sme", "unavailable", tool->name);
		else if (dr == SME_DEGRADED_HTTP)
			ai_trace_degraded("sme", "http_error", tool->name);
	}
	return out;
}

/* 结果文本行数统计 */
static int count_lines(const char *s)
{
	int n = 1;
	const char *p;

	if (!s || !s[0])
		return 0;
	for (p = s; *p; p++) {
		if (*p == '\n')
			n++;
	}
	return n;
}

/*
 * ask_tool_summary_threshold - 单条工具结果入历史的字节阈值（预算驱动）
 * 阈值 = min(8KB, (ctx_len - max_tokens) * 3 / 4)；配得过小时保底
 * 2*KEEP（历史窗口裁剪另有兜底，双保险）。
 */
static long ask_tool_summary_threshold(const struct ai_shell *sh)
{
	long budget_tok = (long)sh->config->ui.ctx_len -
			  (sh->config->ui.max_tokens > 0 ?
			   sh->config->ui.max_tokens : 0);
	long bytes;

	if (budget_tok < 0)
		budget_tok = 0;
	bytes = budget_tok * 3 / ASK_TOOL_RESULT_DENOM;
	if (bytes > ASK_TOOL_RESULT_CAP)
		bytes = ASK_TOOL_RESULT_CAP;
	if (bytes < (long)ASK_TOOL_SUMMARY_KEEP * 2)
		bytes = (long)ASK_TOOL_SUMMARY_KEEP * 2;
	return bytes;
}

/*
 * ask_summarize_tool_result - 大结果入历史前摘要化（P0-2a）
 * 超阈值返回 malloc 的"头部 2KB + 摘要标注"替换文本（调用方接管）；
 * 未超返回 NULL（沿用原文）。摘要标注向模型如实说明原字节/行数与
 * 工具名，并指明可重新调用该工具取回完整结果。
 */
static char *ask_summarize_tool_result(const struct ai_shell *sh,
				       const char *tool, const char *out)
{
	size_t len;
	size_t keep;
	char *sum;

	if (!out)
		return NULL;
	len = strlen(out);
	if ((long)len <= ask_tool_summary_threshold(sh))
		return NULL;
	keep = ai_json_utf8_floor(out, ASK_TOOL_SUMMARY_KEEP);
	sum = malloc(keep + 512);
	if (!sum)
		return NULL;
	memcpy(sum, out, keep);
	sum[keep] = '\0';
	snprintf(sum + keep, 512, tr(TR_ASK_TOOL_SUMMARY_FMT),
		 (long)len, count_lines(out), tool ? tool : "-");
	return sum;
}

/*
 * print_tool_exchange - 打印单条工具调用与结果（折叠卡片 / 详展两种）
 * 默认（折叠）：`  └─ 名字(参数) · OK · 结果首行`，>3 行附行数提示；
 * verbose：两行全展开（兼容 UI Phase 之前的输出格式）。
 */
static void print_tool_exchange(int color, int verbose,
				const struct ai_tool_call *tc,
				const char *result, int ok)
{
	char disp[512];

	if (verbose) {
		size_t dlen = strlen(result ? result : tr(TR_ASK_EMPTY));

		/* verbose 全展开也按 UTF-8 边界截断（512B 显示缓冲） */
		if (dlen >= sizeof(disp)) {
			dlen = ai_json_utf8_floor(result, sizeof(disp) - 4);
			memcpy(disp, result, dlen);
			disp[dlen] = '\0';
			strcat(disp, "…");
		} else {
			snprintf(disp, sizeof(disp), "%s",
				 result ? result : tr(TR_ASK_EMPTY));
		}
		printf(tr(TR_ASK_TC_VERBOSE), tc->name,
		       tc->arguments ? tc->arguments : "{}");
		printf(tr(TR_ASK_TR_VERBOSE), ok ? "ok" : "fail", disp,
		       strlen(result ? result : "") >= sizeof(disp) ?
		       tr(TR_ASK_TRUNCATED) : "");
		return;
	}

	/* 折叠单行卡片 */
	{
		char args[64];
		char first[96];
		const char *src = result ? result : tr(TR_ASK_EMPTY);
		const char *nl = strchr(src, '\n');
		size_t flen = nl ? (size_t)(nl - src) : strlen(src);
		size_t alen;
		int lines = count_lines(result);

		alen = tc->arguments ? strlen(tc->arguments) : 2;
		if (alen > 48) {
			/* 截断对齐 UTF-8 边界（T2 问题 2：截半汉字显示乱码） */
			alen = ai_json_utf8_floor(tc->arguments, 45);
			memcpy(args, tc->arguments, alen);
			args[alen] = '\0';
			strcat(args, "...");
		} else {
			snprintf(args, sizeof(args), "%s",
				 tc->arguments ? tc->arguments : "{}");
		}
		if (flen >= sizeof(first)) {
			/* 预留 '…'(3B)+NUL；floor 保证不截半汉字 */
			flen = ai_json_utf8_floor(src, sizeof(first) - 5);
			memcpy(first, src, flen);
			first[flen] = '\0';
			strcat(first, "…");
		} else {
			memcpy(first, src, flen);
			first[flen] = '\0';
		}

		printf("  %s└─%s %s(%s) %s·%s %s%s%s %s·%s %s\n",
		       ui_c(color, UI_C_DIM), ui_c(color, UI_C_RESET),
		       tc->name, args,
		       ui_c(color, UI_C_DIM), ui_c(color, UI_C_RESET),
		       ok ? ui_c(color, UI_C_GREEN) : ui_c(color, UI_C_RED),
		       ok ? "OK" : "FAIL",
		       ok ? ui_c(color, UI_C_RESET) : ui_c(color, UI_C_RESET),
		       ui_c(color, UI_C_DIM), ui_c(color, UI_C_RESET),
		       first);
		if (lines > 3)
			printf(tr(TR_ASK_MORE_LINES),
			       ui_c(color, UI_C_DIM), lines - 1,
			       ui_c(color, UI_C_RESET));
	}
}

/*
 * ask_clarify_precheck - W77c：shell 侧歧义预检（小/本地模型路径）
 *
 * 只对 pre_retrieve（本地模型）生效：服务启停缺 unit、破坏动作缺目标
 * 两类歧义由 shell 生成问题（模型不必自己规划澄清）。候选唯一致时
 * 不提问；TTY 把用户选择追加到 question 供模型使用；非 TTY 生成
 * CLARIFY_REQUIRED 并停止本轮 ask。可用 AIKERNEL_CLARIFY_DETECT=0 关闭。
 *
 * W77e：检测器升级评分制（阈值 AIKERNEL_CLARIFY_THRESHOLD）；新增
 *  - 链级预算到限：预检停触发，向 question 注入"按最佳理解执行"注记；
 *  - 跨轮/跨会话去重：已问过的问题不再问，注入"已按你此前的选择"；
 *  - 会话实体采集（最近 ASK_CLARIFY_ENTITY_MSGS 条消息中的服务/路径
 *    名词），供代词/省略指代信号评分；
 *  - TTY 答复写入答案记忆（链内 + answered.jsonl）。
 *
 * 返回 1=已停止（st->stop_text 为最终答案）；0=继续。
 */
static int ask_clarify_precheck(char **question, int route_mode,
				struct ask_clarify_state *st)
{
	struct ask_clarify_request req;
	struct ask_clarify_evidence ev;
	struct ask_clarify_answer ans;
	char err[256];
	char chosen[ASK_CLARIFY_LABEL_MAX + ASK_CLARIFY_TEXT_MAX + 16];
	char note[ASK_CLARIFY_LABEL_MAX + 256];
	char mem_label[ASK_CLARIFY_LABEL_MAX + 1];
	char *out = NULL;
	char *nq = NULL;
	const char *env;
	size_t off = 0;
	int tty;
	int i;

	if (!question || !*question || !st ||
	    route_mode != AI_ROUTE_PRE_RETRIEVE)
		return 0;
	env = getenv("AIKERNEL_CLARIFY_DETECT");
	if (env && strcmp(env, "0") == 0)
		return 0;
	/* W77e：链级预算到限 → 预检不再触发；注入预算注记 */
	if (ask_clarify_budget_exhausted(st)) {
		if (asprintf(&nq, "%s\n%s", *question,
			     tr(TR_ASK_CLARIFY_BUDGET_NOTE)) >= 0) {
			free(*question);
			*question = nq;
		}
		return 0;
	}
	if (!ask_clarify_question_candidate(*question))
		return 0;

	memset(&ev, 0, sizeof(ev));
	if (ask_clarify_collect_evidence(&ev) != 0)
		return 0;
	/* W77e：最近会话消息中的实体（*.service/绝对路径），供代词指代
	 * 评分与通用指代澄清使用；消息/池在本块内即取即放
	 * （collect_evidence 会重置 ev，实体在采集之后回填） */
	{
		struct ai_chat_msg *hm = NULL;
		char **hpool = NULL;
		int hpool_n = 0;
		int nh = 0;
		int nlast = 0;
		const char *last[ASK_CLARIFY_ENTITY_MSGS];
		const char *ents[ASK_CLARIFY_MAX_OPTIONS];
		char ent_buf[ASK_CLARIFY_MAX_OPTIONS *
			    (ASK_CLARIFY_LABEL_MAX + 1)];
		int n_ents;

		if (st->session[0] &&
		    ui_session_load(st->session, &hm, &nh, &hpool,
				    &hpool_n) == AI_OK) {
			for (i = nh - 1; i >= 0 &&
			     nlast < ASK_CLARIFY_ENTITY_MSGS; i--)
				if (hm[i].content && hm[i].content[0])
					last[nlast++] = hm[i].content;
			n_ents = ask_clarify_entities_from_history(
				last, nlast, ent_buf, sizeof(ent_buf),
				ents, ASK_CLARIFY_MAX_OPTIONS);
			for (i = 0; i < hpool_n; i++)
				free(hpool[i]);
			free(hpool);
			free(hm);
			if (n_ents > 0) {
				ev.ctx_entities = (const char *const *)ents;
				ev.n_ctx_entities = n_ents;
			}
		}
	}
	if (ask_clarify_detect(*question, &ev, &req, err, sizeof(err)) != 1 ||
	    ask_clarify_validate(&req, err, sizeof(err)) != 0) {
		ask_clarify_evidence_free(&ev);
		return 0;
	}
	/* W77e：已问过（链内/answered.jsonl）→ 不再问，注入旧选择 */
	if (ask_clarify_already_answered(st, &req, mem_label,
					 sizeof(mem_label))) {
		snprintf(note, sizeof(note), tr(TR_ASK_CLARIFY_MEM_NOTE),
			 mem_label);
		if (asprintf(&nq, "%s\n%s", *question, note) >= 0) {
			free(*question);
			*question = nq;
		}
		ask_clarify_evidence_free(&ev);
		return 0;
	}
	if (!ask_clarify_state_begin(st)) {
		ask_clarify_evidence_free(&ev);
		return 0;
	}

	tty = ask_clarify_tty();
	memset(&ans, 0, sizeof(ans));
	if (ask_clarify_exec(&req, st, tty, &ans, &out) != 0 || !out) {
		ask_clarify_evidence_free(&ev);
		free(out);
		return 0;
	}
	if (st->stop) {
		free(st->stop_text);
		st->stop_text = out;
		ask_clarify_evidence_free(&ev);
		return 1;
	}
	/* W77e：TTY 已作答 → 答案记忆（链内去重 + answered.jsonl） */
	ask_clarify_note_answered(st, &req, &ans);

	chosen[0] = '\0';
	for (i = 0; i < ans.n_selected; i++) {
		off += (size_t)snprintf(chosen + off, sizeof(chosen) - off,
					"%s%s", off ? ", " : "",
					req.options[ans.selected[i]].label);
	}
	if (ans.text[0] && off < sizeof(chosen))
		snprintf(chosen + off, sizeof(chosen) - off, "%s[Other] %s",
			 off ? ", " : "", ans.text);
	if (asprintf(&nq, "%s\n[clarify] %s -> %s", *question, req.question,
		     chosen[0] ? chosen : "-") >= 0) {
		free(*question);
		*question = nq;
	}
	free(out);
	ask_clarify_evidence_free(&ev);
	return 0;
}

/*
 * ask_clarify_finish - 澄清终止本轮时的最终答案输出（非 TTY/取消）
 * 结构化 JSON 既回填给模型（tool 消息）也作为本轮最终答案落会话。
 */
static void ask_clarify_finish(struct ai_shell *shell, int color,
			       const struct ask_clarify_state *st,
			       int *final_ok, int *ret,
			       const char **end_reason)
{
	const char *txt = (st && st->stop_text) ? st->stop_text : "{}";

	printf("\n%sAI:%s %s\n", ui_c(color, UI_C_CYAN),
	       ui_c(color, UI_C_RESET), txt);
	ask_sess_append(shell, "assistant", txt, NULL, NULL, NULL);
	*final_ok = 1;
	*ret = AI_OK;
	*end_reason = "clarify_stopped";
}

/*
 * execute_round - 执行一轮全部工具调用并回填消息
 * @native: 1=原生 tool_calls（assistant 带 tool_calls_json + role:tool）；
 *          0=降级路径（assistant 保留原文 + user 消息带工具结果，
 *          对不支持 role:tool 的通道协议安全）
 * @executed: 出参，1=至少执行了一个工具
 * @router: 会话级激活集合（memory_search 结果命中工具动态扩入，
 *          下一请求 tools 数组随之扩入完整 schema；可 NULL）
 */
static int execute_round(struct ai_shell *shell, struct ask_msgs *a,
			 struct ask_owned *owned,
			 const struct tool_registry *reg,
			 const struct ai_chat_result *result,
			 const char *assistant_tool_calls_json,
			 int native, int *executed, int *param_error,
			 struct ask_router *router,
			 struct ask_clarify_state *clarify)
{
	struct ai_shell *sh = shell;
	int color = sh->config->ui.color;
	int verbose = sh->config->ui.verbose;
	struct ai_chat_msg am;
	int i;
	int clarify_stop = 0;
	int round_clarify = 0;
	int clarify_tty = clarify ? ask_clarify_tty() : 0;

	/* 本轮含 clarify：无论 TTY 与否，其他工具一律不执行——澄清未
	 * 回答前不得产生任何副作用（模型可能把破坏性动作与提问放在同一
	 * 轮）。被抑制的调用会得到配对的 not executed 结果，答案后重试。 */
	for (i = 0; i < result->tool_call_count; i++)
		if (result->tool_calls[i].name &&
		    strcmp(result->tool_calls[i].name, "clarify") == 0)
			round_clarify = 1;

	memset(&am, 0, sizeof(am));

	/* assistant 消息先入列（工具结果必须跟随其后）。
	 * content/tool_calls_json 取副本入所有权池（result 随后被释放） */
	am.role = "assistant";
	am.content = ask_own(owned,
			     strdup(result->content ? result->content : ""));
	if (native)
		am.tool_calls_json =
			ask_own(owned, strdup(
				assistant_tool_calls_json ?
				assistant_tool_calls_json : "[]"));
	if (ask_msgs_push(a, &am) != AI_OK)
		return AI_ERR_MEMORY;

	/* 会话落盘：assistant 工具调用消息 */
	ask_sess_append(sh, "assistant", am.content, NULL, NULL,
			native ? am.tool_calls_json : NULL);

	for (i = 0; i < result->tool_call_count; i++) {
		const struct ai_tool_call *tc = &result->tool_calls[i];
		char *tool_out;
		int ok = 0;
		struct ai_chat_msg tm;

		/* W65 P1：Ctrl-C 后不再执行本轮剩余工具；为已声明的
		 * tool_calls 补一条取消结果，保持 assistant(tool_calls) 与
		 * role:tool 配对完整（否则会话文件留下孤儿调用，下次 ask
		 * 重放可能被服务端 400）。 */
		if (ai_cancel_requested) {
			for (; i < result->tool_call_count; i++) {
				const struct ai_tool_call *ctc =
					&result->tool_calls[i];
				struct ai_chat_msg cm;
				char *msg = NULL;

				if (!ctc->name)
					continue;
				memset(&cm, 0, sizeof(cm));
				if (asprintf(&msg,
					     "ERROR: cancelled by user (Ctrl-C); "
					     "tool not executed: %s",
					     ctc->name) < 0)
					msg = strdup("ERROR: cancelled by "
						     "user (Ctrl-C)");
				if (native) {
					cm.role = "tool";
					cm.tool_call_id = ask_own(owned,
						strdup(ctc->id ? ctc->id :
						       "unknown"));
					cm.tool_name = ask_own(owned,
						strdup(ctc->name));
					cm.content = ask_own(owned, msg);
					msg = NULL;
					ask_msgs_push(a, &cm);
					ask_sess_append(sh, "tool", cm.content,
							cm.tool_call_id,
							ctc->name, NULL);
				} else {
					char *merged = NULL;

					if (asprintf(&merged,
						     tr(TR_ASK_TOOL_RESULT_FMT),
						     ctc->name,
						     msg ? msg : "cancelled") < 0)
						merged = NULL;
					cm.role = "user";
					cm.content = ask_own(owned, merged);
					ask_msgs_push(a, &cm);
					ask_sess_append(sh, "user", cm.content,
							NULL, ctc->name, NULL);
				}
				free(msg);
			}
			break;
		}
		if (!tc->name)
			continue;
		/* W77c：clarify 由交互层直接处理，绝不进 executor（不建租约、
		 * 不执行动作）；取消/超时/非 TTY 时置 clarify->stop 结束本轮。
		 * 同轮其他工具在 TTY 与非 TTY 下一律抑制（答案后重试）。 */
		if (ask_clarify_suppress_peer(round_clarify, tc->name,
					      clarify_tty)) {
			tool_out = strdup("ERROR: not executed "
					  "(clarify pending)");
			ok = 0;
		} else if (clarify && strcmp(tc->name, "clarify") == 0) {
			char *cout = NULL;

			ask_clarify_handle_tool(tc->arguments, clarify, &cout);
			tool_out = cout;
			ok = cout && strncmp(cout, "ERROR", 5) != 0;
			if (clarify->stop)
				clarify_stop = 1;
		} else {
			tool_out = run_one_tool(reg, tc, &ok);
		}
		if (!tool_out)
			tool_out = strdup(tr(TR_ASK_NO_EXEC_OUTPUT));
		/* W65 P2-03：结构化参数错误（ERROR[E_PARAM*]）标记，
		 * cmd_ask 据此自动纠正重试一次。只认结果文本前缀，
		 * 避免普通命令输出里恰好含该字符串时误触发。 */
		if (tool_out && param_error &&
		    strncmp(tool_out, TOOL_ERR_PARAM_PREFIX,
			    strlen(TOOL_ERR_PARAM_PREFIX)) == 0)
			*param_error = 1;
		print_tool_exchange(color, verbose, tc, tool_out, ok);
		*executed = 1;

		/* SME 路由钩子：memory_search 的结果即 SME JSON 原文，
		 * 提取其中点名的工具扩入激活集合（dirty 置位，下一轮
		 * 请求前重建 tools 数组），并在回填文本末尾向模型宣告
		 * 激活名单——tools 数组每轮重建，模型需要显式被告知
		 * "哪些工具新进来、下一轮可直接调用"。 */
		if (router && tc->name &&
		    strcmp(tc->name, "memory_search") == 0 && tool_out) {
			int added = router_activate_from_sme(router, reg,
							     tool_out);

			if (added > 0) {
				char *list = NULL;
				char *merged = NULL;
				size_t list_len = 0;
				size_t pos = 0;
				int j;
				int first = router->n_active - added;

				for (j = first; j < router->n_active; j++)
					list_len +=
						strlen(router->active[j]) + 3;
				list = malloc(list_len + 1);
				if (list) {
					list[0] = '\0';
					for (j = first;
					     j < router->n_active; j++) {
						pos += (size_t)snprintf(
							list + pos,
							list_len + 1 - pos,
							"%s%s",
							j > first ?
							tr(TR_ASK_LIST_SEP) :
							"",
							router->active[j]);
					}
				}
				/* W55 P1：native 明确告知"当前请求 tools
				 * 数组已含这些工具"；降级路径没有 tools
				 * 数组，改为告知文本 JSON 可直接调用。
				 * 旧文案"下一轮可直接调用"被模型理解为
				 * "本轮还不能调"，导致只输出计划。 */
				if (asprintf(&merged,
					     native ?
					     tr(TR_ASK_ROUTER_MERGED) :
					     tr(TR_ASK_ROUTER_MERGED_TEXT),
					     tool_out, added,
					     list ? list : "") < 0)
					merged = NULL;
				free(list);
				if (merged) {
					free(tool_out);
					tool_out = merged;
				}
				{
					const char **names = malloc(
						sizeof(char *) * (size_t)added);
					int k;

					if (names) {
						for (k = 0; k < added; k++)
							names[k] =
								router->active[
								first + k];
						ai_trace_route_activate(
							"memory_search", names,
							added, first,
							router->n_active);
						free(names);
					}
				}
				printf(tr(TR_ASK_ROUTER_ACT_UI),
				       ui_c(color, UI_C_DIM), added,
				       router->n_active, reg->tool_count,
				       ui_c(color, UI_C_RESET));
			}
		}

		/* P0-2a：大结果入历史前摘要化。memory_search 豁免——
		 * SME JSON 是路由核心（本轮已按原文完成激活），截断会
		 * 破坏点名工具与模型复读，且体量天然有界（16KB 缓冲）。
		 * 屏幕卡片已按原文打印（见上方 print_tool_exchange），
		 * 此处只替换"入历史 + 落会话"的副本；role/tool_call_id
		 * 配对不变，工具调用对完整性不受影响。 */
		if (!tc->name || strcmp(tc->name, "memory_search") != 0) {
			char *sum = ask_summarize_tool_result(sh, tc->name,
							      tool_out);

			if (sum) {
				printf(tr(TR_ASK_TOOL_SUMMARY_UI),
				       ui_c(color, UI_C_DIM),
				       ui_c(color, UI_C_RESET),
				       tc->name ? tc->name : "-",
				       (long)strlen(tool_out),
				       count_lines(tool_out),
				       (long)strlen(sum),
				       ui_c(color, UI_C_RESET));
				free(tool_out);
				tool_out = sum;
			}
		}

		memset(&tm, 0, sizeof(tm));
		if (native) {
			/* T3 发现的 tool_call_id 乱码根因：tc->id/tc->name
			 * 指向 result，主循环在本轮末尾 ai_chat_result_free()
			 * 释放——消息数组要跨轮重放，必须拷贝入所有权池，
			 * 否则下一轮请求序列化时读到悬垂指针（历史重放乱码
			 * /服务端 400）。与修复 1（孤儿剔除）联动。 */
			tm.role = "tool";
			tm.tool_call_id =
				ask_own(owned,
					strdup(tc->id ? tc->id : "unknown"));
			tm.tool_name = tc->name ?
				       ask_own(owned, strdup(tc->name)) : NULL;
			tm.content = ask_own(owned, tool_out);
		} else {
			/* 降级路径：user 消息回填（协议最兼容） */
			char *merged;

			if (asprintf(&merged, tr(TR_ASK_TOOL_RESULT_FMT),
				     tc->name, tool_out) < 0)
				merged = NULL;
			tm.role = "user";
			tm.content = ask_own(owned, merged);
			free(tool_out);
		}
		if (ask_msgs_push(a, &tm) != AI_OK)
			return AI_ERR_MEMORY;

		/* 会话落盘：工具结果（附工具名便于人读） */
		if (native)
			ask_sess_append(sh, "tool", tm.content,
					tm.tool_call_id, tc->name, NULL);
		else
			ask_sess_append(sh, "user", tm.content, NULL,
					tc->name, NULL);

		/* W77c：澄清已终止本轮（非 TTY/取消/重试耗尽）。同轮剩余
		 * tool_calls 补一条未执行结果，保持 assistant(tool_calls)
		 * 与 role:tool 配对完整（否则会话重放可能 400）。 */
		if (clarify_stop) {
			for (i++; i < result->tool_call_count; i++) {
				const struct ai_tool_call *ctc =
					&result->tool_calls[i];
				struct ai_chat_msg cm;
				char *msg = NULL;

				if (!ctc->name)
					continue;
				memset(&cm, 0, sizeof(cm));
				if (asprintf(&msg, "ERROR: not executed "
					     "(clarify pending): %s",
					     ctc->name) < 0)
					msg = strdup("ERROR: not executed "
						     "(clarify pending)");
				if (native) {
					cm.role = "tool";
					cm.tool_call_id = ask_own(owned,
						strdup(ctc->id ? ctc->id :
						       "unknown"));
					cm.tool_name = ask_own(owned,
						strdup(ctc->name));
					cm.content = ask_own(owned, msg);
					msg = NULL;
					ask_msgs_push(a, &cm);
					ask_sess_append(sh, "tool", cm.content,
							cm.tool_call_id,
							ctc->name, NULL);
				} else {
					char *merged = NULL;

					if (asprintf(&merged,
						     tr(TR_ASK_TOOL_RESULT_FMT),
						     ctc->name,
						     msg ? msg : "not executed")
					    < 0)
						merged = NULL;
					cm.role = "user";
					cm.content = ask_own(owned, merged);
					ask_msgs_push(a, &cm);
					ask_sess_append(sh, "user", cm.content,
							NULL, ctc->name, NULL);
				}
				free(msg);
			}
			break;
		}
	}

	return AI_OK;
}

/* ---- 历史窗口裁剪（修复 5） ---- */

/*
 * ask_hist_trim - 会话历史窗口裁剪（T2 P1-5：线性累加不裁剪）
 * @hist/@nhist: in/out——滑动窗口（指针后移 + 条数缩减，不复制）；
 *               传入 ui_session_load 的完整历史
 * @budget_tokens: 历史 token 预算（调用方按 ctx_len-max_tokens-预留算）
 * @max_msgs: 条数硬上限
 * @cut_turns: 出参，被裁掉的轮数（0=未触发裁剪）
 *
 * 策略：
 *   - 按"轮"分组：user 锚点起至下一条 user 前的全部 assistant/tool
 *     消息同轮同组，整轮保留/整轮裁掉——工具调用与结果绝不拆散
 *     （与修复 1 的 assistant(tool_calls)+tool 配对不变式联动）；
 *   - 自最新往最老累积，超出预算/条数即停，窗口起点退到整轮锚点；
 *   - 最近 ASK_HIST_MIN_TURNS 轮保底（预算再紧也保留）；
 *   - compact 写入的首条 "[历史摘要]" 钉住不裁（与 compact 命令
 *     语义兼容：压缩后的摘要视为长期记忆而非普通轮次）；
 *   - 裁完若以 role:tool 开头（历史损坏的极端情形）继续丢弃至非 tool，
 *     兜底防孤儿（序列化器另有兜底，双保险）。
 *
 * W59：token 估算/摘要识别/轮锚点判断统一由 ask_compact.c 提供。
 */
static void ask_hist_trim(struct ai_chat_msg **hist, int *nhist,
			  long budget_tokens, int max_msgs, int *cut_turns)
{
	struct ai_chat_msg *h = *hist;
	int n = *nhist;
	int start = 0;
	int cut = 0;
	long acc = 0;
	int msgs = 0;
	int turns = 0;
	int i;

	*cut_turns = 0;
	if (!h || n <= 0)
		return;

	/* compact 摘要钉住 */
	if (ask_compact_is_summary(&h[0]))
		start = 1;

	for (i = n - 1; i >= start; i--) {
		acc += ask_compact_msg_tokens(&h[i]);
		msgs++;
		if (ask_compact_is_user(&h[i]))
			turns++;
		if ((acc > budget_tokens || msgs > max_msgs) &&
		    turns > ASK_HIST_MIN_TURNS) {
			/* 超线：窗口起点 = i 之后的第一个 user 锚点
			 * （i 所在轮整轮裁掉，不拆散工具配对） */
			int j = i + 1;

			while (j < n && !ask_compact_is_user(&h[j]))
				j++;
			cut = j;
			break;
		}
	}

	/* 孤儿兜底：窗口不得以 role:tool 开头 */
	while (cut < n && h[cut].role && strcmp(h[cut].role, "tool") == 0)
		cut++;

	if (cut > start) {
		for (i = start; i < cut; i++)
			if (ask_compact_is_user(&h[i]))
				(*cut_turns)++;
		/* 摘要钉住（窗口重定位）：窗口是 [cut..n) 连续区间，钉在
		 * h[0] 的 "[历史摘要]" 必须换入窗口起点才能随请求携带
		 * （compact 语义兼容：摘要视作长期记忆，不随轮裁剪丢失）。
		 * 换出的是被裁区域 h[cut] 的消息（同样被丢弃），无损。 */
		if (start == 1 && cut > start) {
			struct ai_chat_msg tmp = h[0];

			h[0] = h[cut];
			h[cut] = tmp;
		}
		*hist = h + cut;
		*nhist = n - cut;
	}
}

/* ---- W59：自动压缩循环保护 ---- */

/*
 * 进程内连续压缩状态（按会话名隔离）。
 * - streak：连续触发压缩的 ask 次数；入口历史已低于阈值即清零；
 * - warned：本轮连续超限已打印过一次降级警告（不再刷屏）；
 * - since_compact：自上次成功压缩以来的 ask 轮数。W72 冷却：<2 时即使
 *   再次越线也跳过压缩（只做历史裁剪），第 3 轮才允许下一次。新会话/
 *   新进程初值 = 冷却阈值（恢复后允许立即压缩一次）；
 * - 上限 2：同一 ask 最多两次（首次 + 收紧重试），跨 ask 连续最多
 *   两次；再超限只做本地截断，绝不再发摘要请求。
 */
struct ask_ac_state {
	char session[128];
	int streak;
	int warned;
	int since_compact;
};

static struct ask_ac_state g_ask_ac;

/*
 * W77b2：自动压缩冷却跨进程持久化。
 * 侧车文件 <session>.jsonl.compact 记录 since_compact 与会话消息条数；
 * 进程重启（如 workday phase2）后若会话未被重置（当前条数 >= 记录条数）
 * 则恢复冷却，避免同一会话在恢复后立刻再次摘要压缩。
 */
static void ask_ac_state_path(const char *sess, char *buf, size_t len)
{
	char sp[AI_PATH_MAX];

	if (!buf || len == 0)
		return;
	buf[0] = '\0';
	if (ui_session_path(sess, sp, sizeof(sp)) != AI_OK)
		return;
	if (strlen(sp) + 9 > len)
		return;
	snprintf(buf, len, "%s.compact", sp);
}

static void ask_ac_restore(const char *sess)
{
	char path[AI_PATH_MAX];
	int since = -1, msgs = -1;
	FILE *fp;

	ask_ac_state_path(sess, path, sizeof(path));
	if (!path[0])
		return;
	fp = fopen(path, "r");
	if (!fp)
		return;
	if (fscanf(fp, "since_compact=%d\nmsgs=%d\n", &since, &msgs) == 2 &&
	    since >= 0 && since <= ASK_COMPACT_COOLDOWN_TURNS &&
	    msgs >= 0 && ui_session_count(sess) >= msgs)
		g_ask_ac.since_compact = since;
	fclose(fp);
}

static void ask_ac_save(const char *sess)
{
	char path[AI_PATH_MAX];
	char tmp[AI_PATH_MAX];
	FILE *fp;

	if (!sess)
		return;
	ask_ac_state_path(sess, path, sizeof(path));
	if (!path[0])
		return;
	if (g_ask_ac.since_compact >= ASK_COMPACT_COOLDOWN_TURNS) {
		unlink(path);
		return;
	}
	snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
	fp = fopen(tmp, "w");
	if (!fp)
		return;
	fprintf(fp, "since_compact=%d\nmsgs=%d\n",
		g_ask_ac.since_compact, ui_session_count(sess));
	if (fclose(fp) != 0) {
		unlink(tmp);
		return;
	}
	if (rename(tmp, path) != 0)
		unlink(tmp);
}

static void ask_ac_select(const char *sess)
{
	if (!sess)
		sess = "";
	if (strcmp(g_ask_ac.session, sess) != 0) {
		snprintf(g_ask_ac.session, sizeof(g_ask_ac.session), "%s",
			 sess);
		g_ask_ac.streak = 0;
		g_ask_ac.warned = 0;
		/* 新会话/新进程：无需冷却，恢复后允许压缩一次 */
		g_ask_ac.since_compact = ASK_COMPACT_COOLDOWN_TURNS;
		ask_ac_restore(sess);
	}
}

static void ask_hist_reload(struct ai_shell *shell, const char *sess,
			    struct ai_chat_msg **hist, int *nhist,
			    char ***pool, int *npool)
{
	int i;

	(void)shell;
	for (i = 0; i < *npool; i++)
		free((*pool)[i]);
	free(*pool);
	*pool = NULL;
	*npool = 0;
	*hist = NULL;
	*nhist = 0;
	ui_session_load(sess, hist, nhist, pool, npool);
}

/*
 * ask_hist_truncate_session - 压缩不达标时的确定性截断（写回会话文件）
 * @hist/@nhist: 当前历史快照
 * @target:      截断后 token 上限
 * @dropped:     出参：丢弃的原文条数
 *
 * 保留已有摘要（装得下时）+ 最近的整轮原文；一条都装不下就清空历史。
 * 返回 AI_OK/AI_ERR_*。
 */
static int ask_hist_truncate_session(const char *sess,
				     struct ai_chat_msg *hist, int nhist,
				     long target, int *dropped)
{
	struct ask_compact_plan plan;
	struct ui_session_rec *recs;
	int n = 0, i, rc;

	if (ask_compact_plan_truncate(hist, nhist, target,
				      ASK_COMPACT_KEEP_MAX_MSGS,
				      &plan) != 0)
		return AI_ERR_INVALID_ARG;
	{
		int kept = (plan.keep_first ? 1 : 0) +
			   (plan.keep_from < nhist ?
			    nhist - plan.keep_from : 0);

		*dropped = nhist - kept;
	}
	recs = calloc((size_t)(nhist - plan.keep_from + 2), sizeof(*recs));
	if (!recs)
		return AI_ERR_MEMORY;
	if (plan.keep_first && nhist > 0) {
		recs[n].role = hist[0].role;
		recs[n].content = hist[0].content;
		recs[n].tool_call_id = hist[0].tool_call_id;
		recs[n].tool_name = hist[0].tool_name;
		recs[n].tool_calls_json = hist[0].tool_calls_json;
		recs[n].ts = time(NULL);
		n++;
	}
	for (i = plan.keep_from; i < nhist; i++) {
		recs[n].role = hist[i].role;
		recs[n].content = hist[i].content;
		recs[n].tool_call_id = hist[i].tool_call_id;
		recs[n].tool_name = hist[i].tool_name;
		recs[n].tool_calls_json = hist[i].tool_calls_json;
		recs[n].ts = time(NULL);
		n++;
	}
	rc = ui_session_replace(sess, recs, n);
	free(recs);
	return rc;
}

/*
 * ask_degrade_text - W77 降级 UX 文案（明确“离线/能力受限” + 可执行替代）
 *
 * 所有模型不可用路径共用：不伪装成功、不丢会话、给可执行的下一步；
 * 同时明确 D2+ 写操作仍需 W74 租约/确认，离线不绕过。
 */
static void ask_degrade_text(const char *why, const char *detail,
			     char *out, size_t n)
{
	snprintf(out, n,
		 "[offline] 模型不可用：%s%s%s。能力受限（capability limited），"
		 "但以下离线查询仍可用（D0 只读，不依赖模型）：\n"
		 "  系统状态 / 内存 / 磁盘 / 负载 / 服务 [名] / 文件 <路径> / "
		 "沙箱 / 租约 / 记忆 <查询> / 最近计划 / 路由模式 / 配置 / "
		 "网络 / 内核 / 运行多久\n"
		 "重试：检查本地 `ollama serve` 与 model.toml [local].base_url，"
		 "或设置 AIKERNEL_ROUTE=cloud 走云端；会话已保留，可直接继续。\n"
		 "注意：D2+ 写操作仍需 W74 lease/确认，离线模式不绕过。",
		 why ? why : "未知原因",
		 detail && detail[0] ? " (" : "",
		 detail && detail[0] ? detail : "");
}

/* ---- 主命令 ---- */

int cmd_ask(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;
	struct tool_registry reg;
	struct ask_router router;
	char *reg_err = NULL;
	struct ask_msgs a = { NULL, 0, 0 };
	struct ask_owned owned = { NULL, 0, 0 };
	struct ask_stream st;
	struct ask_clarify_state clarify;
	char *system_native = NULL;
	char *system_fallback = NULL;
	char *catalog = NULL;
	char *tools_json = NULL;
	char *question = NULL;
	char *sense_ctx = NULL;
	int status_ctx = 0;
	char *mem_ctx = NULL;
	char **hist_pool = NULL;
	int hist_pool_n = 0;
	const char *sess_name;
	int color;
	int hist_n = 0;
	int hist_before = 0;
	int trim_turns = 0;
	int max_rounds;
	int fallback_mode = 0;
	int route_mode = AI_ROUTE_AUTO;
	int round;
	int ret = AI_OK;
	char tools_hash[32] = "unavailable";
	int trace_turn = 0;
	int rounds_run = 0;
	int param_error = 0;
	int repair_used = 0;
	int compacted_now = 0;  /* W72：本次 ask 已压缩/截断（冷却计数用） */
	int final_ok = 0;       /* W72：是否已产出最终回答（spawn 状态用） */
	const char *end_reason = "completed";
	/* W77：模型路由/离线意图 */
	struct ai_route_choice route_choice;
	struct ai_offline_answer offline_ans = { 0 };
	int route_decided = 0;
	int current_target = 0;
	int route_failed_over = 0;
	int local_retry_used = 0;
	int offline_used = 0;
	int plan_cached = 0;
	long long route_apply_ms = 0;

	/* 轮数上限：默认 ASK_MAX_ROUNDS(12)，AIKERNEL_MAX_ROUNDS 覆盖
	 * （修复 9：可配置；越界值忽略） */
	{
		const char *env = getenv("AIKERNEL_MAX_ROUNDS");
		int v = env ? atoi(env) : 0;

		max_rounds = (v >= ASK_MAX_ROUNDS_MIN &&
			      v <= ASK_MAX_ROUNDS_MAX) ? v : ASK_MAX_ROUNDS;
	}

	color = shell->config->ui.color;
	sess_name = (shell->config->ui.session &&
		     shell->config->ui.session[0]) ?
		    shell->config->ui.session : UI_DEFAULT_SESSION;
	st.color = color;
	st.printed = 0;
	memset(&clarify, 0, sizeof(clarify));
	{
		const char *ca = getenv("AIKERNEL_CLARIFY_ASKED");

		if (ca && ca[0]) {
			int n = atoi(ca);

			if (n < 0)
				n = 0;
			if (n > ASK_CLARIFY_MAX_PER_ASK)
				n = ASK_CLARIFY_MAX_PER_ASK;
			clarify.asked = n;
		}
	}

	if (argc < 2) {
		printf("%s", tr(TR_ASK_USAGE));
		printf("%s", tr(TR_ASK_USAGE_EX));
		return AI_ERR_INVALID_ARG;
	}

	/* 1. 工具注册表 */
	ret = tool_registry_load(&reg, &reg_err);
	if (ret != AI_OK) {
		printf("ask: %s\n", reg_err ? reg_err : tr(TR_ASK_REG_FAIL));
		free(reg_err);
		return ret;
	}

	/* W77：先做模型路由决策（需要问题文本；此处先拼一份临时问题，
	 * 正式 question 在下面第 3 步构造）。决策结果决定 1a 的 SME 模式
	 * 与后面 apply 的目标，避免“默认云 → 路由本地”时仍用云端
	 * autonomous 提示。 */
	{
		size_t cap = 256, off = 0;
		char *early_q;
		int i;

		for (i = 1; i < argc; i++)
			cap += strlen(argv[i]) + 1;
		early_q = malloc(cap);
		if (early_q) {
			early_q[0] = '\0';
			for (i = 1; i < argc; i++) {
				if (i > 1)
					early_q[off++] = ' ';
				early_q[off] = '\0';
				snprintf(early_q + off, cap - off, "%s",
					 argv[i]);
				off = strlen(early_q);
			}
			route_decided = (ai_route_decide(shell->config,
							 early_q,
							 &route_choice) ==
					 AI_OK);
			free(early_q);
		}
	}

	/* 1a. SME 路由模式（[routing].mode；auto 按 provider 缺省：
	 * cloud=autonomous（模型自主检索），local=pre_retrieve（框架
	 * 预检索）。W77：provider 以模型路由决策为准（路由到本地时
	 * 用 pre_retrieve），路由失败再退回默认模型类型。 */
	route_mode = shell->config->routing.mode;
	{
		const char *dm = ai_config_get_default_model(shell->config);
		char *ptype = NULL;
		int is_local;

		if (!dm && shell->runtime.current_model)
			dm = shell->runtime.current_model;
		is_local = (dm &&
			    ai_config_get_model(shell->config, dm, &ptype,
						NULL, NULL, NULL) == AI_OK &&
			    ptype && strcmp(ptype, "local") == 0);
		free(ptype);
		if (route_decided)
			is_local = route_choice.target ==
				   AI_ROUTE_TARGET_LOCAL;
		if (route_mode == AI_ROUTE_AUTO)
			route_mode = is_local ? AI_ROUTE_PRE_RETRIEVE :
						AI_ROUTE_AUTONOMOUS;
	}
	{
		int with_catalog = (route_mode == AI_ROUTE_AUTONOMOUS);

		if (route_mode == AI_ROUTE_PRE_RETRIEVE)
			with_catalog =
				shell->config->routing.local_catalog;
		ret = router_init(&router, route_mode, with_catalog);
		if (ret != AI_OK) {
			tool_registry_free(&reg);
			return ret;
		}
		if (with_catalog) {
			catalog = tool_registry_build_catalog(&reg);
			if (!catalog) {
				router_free(&router);
				tool_registry_free(&reg);
				return AI_ERR_MEMORY;
			}
		}
	}

	/* W48B：会话轨迹起点（工具表 hash 取实际加载的 tools.json） */
	ai_trace_hash_file(reg.source_path, tools_hash, sizeof(tools_hash));
	{
		const char *dm = shell->runtime.model_name ?
				 shell->runtime.model_name :
				 ai_config_get_default_model(shell->config);

		ai_trace_session_start(sess_name, dm,
			shell->runtime.model_provider_type,
			shell->config->ui.ctx_len,
			shell->config->ui.max_tokens,
			shell->config->ui.stream,
			route_mode == AI_ROUTE_PRE_RETRIEVE ?
			"pre_retrieve" :
			route_mode == AI_ROUTE_AUTONOMOUS ?
			"autonomous" : "-",
			tools_hash);
	}

	{
		char *sum = tool_registry_summarize(&reg);

		if (!sum) {
			free(catalog);
			router_free(&router);
			tool_registry_free(&reg);
			return AI_ERR_MEMORY;
		}
		/* native 路径：瘦身 system（目录页+检索指引+精简约束）；
		 * fallback 路径：清单也按激活集合裁剪（文本 JSON 协议没有
		 * tools 数组，工具名+参数只能从 system 拿——但本地通道降级
		 * 循环时全量 10KB 清单会把 token 吃回去） */
		system_native = build_system_prompt(sum, 0, route_mode,
						    catalog);
		system_fallback = build_fallback_system(&reg, &router,
							route_mode);
		free(sum);
		if (!system_native || !system_fallback) {
			free(system_native);
			free(system_fallback);
			free(catalog);
			router_free(&router);
			tool_registry_free(&reg);
			return AI_ERR_MEMORY;
		}
	}

	/* 2. 模型（复用 chat 命令的默认模型逻辑） */
	{
		const char *default_model = ai_config_get_default_model(
			shell->config);

		if (!shell->runtime.current_model) {
			if (!default_model) {
				char **names;
				int count;

				ai_config_get_models(shell->config, &names,
						     &count);
				if (count == 0) {
					printf("No models configured.\n"
					       "Use 'model add <name>' "
					       "first.\n");
					ret = AI_ERR_NO_MODEL;
					goto out;
				}
				ai_config_set_default_model(shell->config,
							    names[0]);
				ai_config_save(shell->config);
				for (int i = 0; i < count; i++)
					free(names[i]);
				free(names);
				default_model = shell->config->default_model;
			}
			ret = ai_runtime_set_model(&shell->runtime,
						   default_model);
			if (ret != AI_OK) {
				printf("Failed to initialize model '%s': %s\n",
				       default_model, ai_error_string(ret));
				goto out;
			}
		}
	}

	/* W65 P1：从这里开始进入阻塞面（SME/compact/模型），安装 SIGINT
	 * handler 并进入 ask 活跃态；out: 统一 disarm。 */
	ai_cancel_arm();

	/* 3. 拼接问题 + 上下文注入 */
	{
		size_t cap = 256;
		size_t off = 0;
		int i;

		for (i = 1; i < argc; i++)
			cap += strlen(argv[i]) + 1;
		question = malloc(cap);
		if (!question) {
			ret = AI_ERR_MEMORY;
			goto out;
		}
		for (i = 1; i < argc; i++) {
			if (i > 1)
				question[off++] = ' ';
			off += (size_t)snprintf(question + off, cap - off,
						"%s", argv[i]);
		}

		/* W48B：回合起点（含后续上下文注入/自动压缩/模型循环） */
		trace_turn = ai_trace_turn_start(question);

		/* W77c-2a：非 TTY clarify 写 pending 需要原始问题与会话名 */
		ask_clarify_state_set_context(&clarify, sess_name, question);

		/* W77：离线意图层（不依赖模型）。auto/local 模式先尝试；
		 * 命中即结构化回答并落会话，绝不发模型请求。强制 cloud 模式
		 * 默认跳过（尊重显式选择），AIKERNEL_OFFLINE_INTENTS=force 可开。 */
		if (ai_route_offline_intents_enabled(shell->config) &&
		    ai_offline_intent_match(question, shell->config,
					    &offline_ans)) {
			long long ot0 = ai_trace_now_ms();

			ai_route_trace_offline(offline_ans.intent,
					       offline_ans.source,
					       offline_ans.cache_age_ms,
					       ai_trace_now_ms() - ot0);
			printf("\n%s\n", offline_ans.text ? offline_ans.text :
			       "");
			ask_sess_append(shell, "user", question, NULL, NULL,
					NULL);
			ask_sess_append(shell, "assistant",
					offline_ans.text ? offline_ans.text : "",
					NULL, NULL, NULL);
			ai_offline_cache_plan(question, "offline",
					      offline_ans.degraded ?
					      "degraded" : "ok", 0, NULL,
					      offline_ans.intent);
			plan_cached = 1;
			offline_used = 1;
			final_ok = 1;
			ret = AI_OK;
			end_reason = "offline_intent";
			goto out;
		}

		/* W77c：本地模型路径的 shell 侧歧义预检（服务缺 unit/
		 * 破坏动作缺目标）。非 TTY 直接输出 CLARIFY_REQUIRED 并
		 * 结束本轮，不执行任何动作；TTY 选择已追加到 question。 */
		if (ask_clarify_precheck(&question, route_mode, &clarify)) {
			const char *txt = clarify.stop_text ?
					  clarify.stop_text : "{}";

			printf("\n%sAI:%s %s\n", ui_c(color, UI_C_CYAN),
			       ui_c(color, UI_C_RESET), txt);
			ask_sess_append(shell, "user", question, NULL, NULL,
					NULL);
			ask_sess_append(shell, "assistant", txt, NULL, NULL,
					NULL);
			plan_cached = 1;
			final_ok = 1;
			ret = AI_OK;
			end_reason = "clarify_required";
			goto out;
		}

		sense_ctx = inject_kernel_context(&status_ctx);
		if (route_mode == AI_ROUTE_PRE_RETRIEVE) {
			/* 框架预检索：一次 SME 检索同时完成命中工具激活
			 * （tools 数组扩入）与文本注入（辅助回答） */
			mem_ctx = route_pre_retrieve(question, &reg,
						     &router);
		}
		/* autonomous 模式不被动注入记忆：模型自主 memory_search
		 * （定案架构——给它目录页+检索指引，让它熟练地查） */
	}

	/* W65 P1：注入阶段（SME/netlink）被 Ctrl-C 中断 */
	if (ai_cancel_requested) {
		end_reason = "cancelled";
		ret = AI_ERR_GENERIC;
		goto out;
	}

	/* W77：应用模型路由（本地/云端/明确离线降级）。
	 * 只在模型层切换，不触碰工具执行/租约；D2+ 仍走 W74 gate。 */
	if (!route_decided)
		route_decided = (ai_route_decide(shell->config, question,
						 &route_choice) == AI_OK);
	current_target = ai_route_current_target(&shell->runtime);
	if (route_decided && route_choice.target == AI_ROUTE_TARGET_OFFLINE) {
		char dmsg[1600];

		ask_degrade_text("离线（云端与本地模型均不可用）",
				 route_choice.reason, dmsg, sizeof(dmsg));
		printf("\n%s\n", dmsg);
		ask_sess_append(shell, "user", question, NULL, NULL, NULL);
		ask_sess_append(shell, "assistant", dmsg, NULL, NULL, NULL);
		ai_offline_cache_plan(question, "offline", "degraded", 0,
				      NULL, route_choice.reason);
		plan_cached = 1;
		ret = AI_ERR_NETWORK;
		end_reason = "offline_degraded";
		goto out;
	}
	if (route_decided && route_choice.target != AI_ROUTE_TARGET_OFFLINE &&
	    route_choice.target != current_target) {
		int ar = ai_route_apply(&shell->runtime, route_choice.target,
					&route_apply_ms);

		if (ar != AI_OK) {
			char dmsg[1600];
			char why[128];

			snprintf(why, sizeof(why), "路由到%s失败",
				 route_choice.target ==
				 AI_ROUTE_TARGET_LOCAL ? "本地" : "云端");
			ask_degrade_text(why, ai_error_string(ar), dmsg,
					 sizeof(dmsg));
			printf("\n%s\n", dmsg);
			ask_sess_append(shell, "user", question, NULL, NULL,
					NULL);
			ask_sess_append(shell, "assistant", dmsg, NULL, NULL,
					NULL);
			ai_offline_cache_plan(question,
					      route_choice.target ==
					      AI_ROUTE_TARGET_LOCAL ?
					      "local" : "cloud",
					      "degraded", 0, NULL,
					      route_choice.reason);
			plan_cached = 1;
			ret = ar;
			end_reason = "route_apply_failed";
			goto out;
		}
		current_target = route_choice.target;
	}
	if (route_decided) {
		ai_route_trace_decision(shell->config, &shell->runtime,
					&route_choice, route_apply_ms);
		printf("[route] mode=%s decision=%s reason=%s task=%s "
		       "provider=%s model=%s latency=%lldms%s\n",
		       ai_route_mode_name(ai_route_effective_mode(
					       shell->config)),
		       route_choice.target == AI_ROUTE_TARGET_LOCAL ? "local" :
		       route_choice.target == AI_ROUTE_TARGET_CLOUD ? "cloud" :
		       "offline",
		       route_choice.reason ? route_choice.reason : "-",
		       route_choice.task_class == AI_ROUTE_TASK_OPERATIONAL ?
		       "operational" :
		       route_choice.task_class == AI_ROUTE_TASK_REASONING ?
		       "reasoning" : "chat",
		       shell->runtime.model_provider_type ?
		       shell->runtime.model_provider_type : "-",
		       shell->runtime.model_name ? shell->runtime.model_name :
		       "-",
		       route_apply_ms,
		       route_choice.target == AI_ROUTE_TARGET_LOCAL ?
		       " (local; 32768 ctx)" : "");
	}

	/* 4. 会话历史加载（跨 ask；按轮+预算裁剪，见 ask_hist_trim） */
	{
		struct ai_chat_msg *hist = NULL;
		int nhist = 0;
		int i;

		ui_session_load(sess_name, &hist, &nhist, &hist_pool,
				&hist_pool_n);

		/* P0-2b/W56 T5 + W59 + W72：ask 入口自动 compact——历史估算达
		 * 历史预算 80%（ASK_AUTOCOMPACT_PCT）时先压缩再装载。
		 *
		 * W59 循环保护（p5-03 实机：每行输入都触发一次压缩，模型
		 * 请求翻倍、REPL 永不静默）：
		 *   - 同一 ask 最多 2 次（首次 55% 目标 + 收紧 40% 重试）；
		 *   - 跨 ask 连续压缩最多 2 次，入口低于阈值即清零；
		 *   - 仍超限则只做确定性截断（丢弃最旧整轮），只警告一次；
		 *   - 压缩请求本身绝不写入历史（cmd_compact_apply 只读快照）。
		 *
		 * W72：
		 *   - 冷却 ASK_COMPACT_COOLDOWN_TURNS：压缩后跳过 2 个 ask 轮，
		 *     即使再次越线也不压（防 T08→T09/T16→T17 连续压缩）；
		 *   - 压缩已保留最近原文（kept>0）时接受软 target，不在同一
		 *     ask 内二次压缩/截断（避免把刚保留的近轮又裁掉）；
		 *   - 新进程/新会话恢复：冷却初值满足，允许恢复后压缩一次，
		 *     且 plan 保证最近原文窗口非空（不再 kept=0）。
		 */
		{
			long mt = ai_config_effective_max_tokens(
				shell->config,
				shell->runtime.model_provider_type);
			long budget = ask_ctx_hist_budget(
				shell->config->ui.ctx_len, mt);
			long used = ask_compact_hist_tokens(hist, nhist);
			int attempt;

			ask_ac_select(sess_name);
			if (!ask_ctx_should_autocompact(used, budget)) {
				g_ask_ac.streak = 0;
				g_ask_ac.warned = 0;
			} else if (nhist > 1 &&
				   g_ask_ac.since_compact <
				   ASK_COMPACT_COOLDOWN_TURNS) {
				/* W72 冷却：仍按预算裁剪（ask_hist_trim 在后面
				 * 执行），但不再发摘要请求。 */
				printf(tr(TR_ASK_COMPACT_COOLDOWN),
				       ui_c(color, UI_C_DIM),
				       g_ask_ac.since_compact,
				       ASK_COMPACT_COOLDOWN_TURNS,
				       ui_c(color, UI_C_RESET));
			} else if (nhist > 1) {
				long target = budget *
					      ASK_COMPACT_TARGET_PCT / 100;

				if (target < 256)
					target = 256;
				for (attempt = 1; attempt <= 2; attempt++) {
					int crc;
					int kept;

					if (g_ask_ac.streak >= 2)
						break;
					if (attempt == 2) {
						target = budget *
							 ASK_COMPACT_RETRY_PCT /
							 100;
						if (target < 128)
							target = 128;
					}
					printf(tr(TR_ASK_AUTOCOMPACT_TRY),
					       ui_c(color, UI_C_DIM),
					       ui_c(color, UI_C_RESET));
					fflush(stdout);
					crc = cmd_compact_apply(shell, target,
								attempt);
					g_ask_ac.streak++;
					if (crc != AI_OK) {
						printf(tr(TR_ASK_AUTOCOMPACT_FAIL),
						       ui_c(color, UI_C_DIM),
						       ai_error_string(crc),
						       ui_c(color, UI_C_RESET));
						break;
					}
					/* 成功压缩/截断：进入冷却，且重置连续计数
					 * （下一次仍受 since_compact 约束）。 */
					compacted_now = 1;
					g_ask_ac.since_compact = 0;
					g_ask_ac.streak = 0;
					printf("%s", tr(TR_ASK_AUTOCOMPACT));
					ask_hist_reload(shell, sess_name,
							&hist, &nhist,
							&hist_pool,
							&hist_pool_n);
					used = ask_compact_hist_tokens(hist,
								       nhist);
					kept = cmd_compact_last_kept();
					printf("[compact] check attempt=%d/2 "
					       "used=%ld budget=%ld pct=%ld%% "
					       "kept_recent=%d after=%ld\n",
					       attempt, used, budget,
					       budget > 0 ?
					       used * 100 / budget : 0,
					       kept,
					       cmd_compact_last_after());
					if (!ask_ctx_should_autocompact(used,
									budget))
						break;
					if (kept > 0) {
						/* 软 target：最近原文已保留，
						 * 余量交给冷却与后续裁剪。 */
						printf("[compact] soft-target "
						       "accepted kept_recent=%d "
						       "used=%ld target=%ld\n",
						       kept, used, target);
						break;
					}
				}
				/* 两次仍不达标且一条原文都没留下 →
				 * 截断（只警告一次） */
				if (ask_ctx_should_autocompact(used, budget) &&
				    cmd_compact_last_kept() == 0) {
					int dropped = 0;

					if (!g_ask_ac.warned) {
						printf(tr(TR_CMP_GUARD),
						       ui_c(color, UI_C_DIM));
						g_ask_ac.warned = 1;
					}
					if (ask_hist_truncate_session(
						    sess_name, hist, nhist,
						    target, &dropped) == AI_OK) {
						compacted_now = 1;
						g_ask_ac.since_compact = 0;
						ask_hist_reload(shell, sess_name,
								&hist, &nhist,
								&hist_pool,
								&hist_pool_n);
						used = ask_compact_hist_tokens(
							hist, nhist);
						printf("[compact] truncate "
						       "dropped=%d after=%ld "
						       "target=%ld\n",
						       dropped, used, target);
					}
				}
			} else {
				/* 只有 1 条（通常是摘要）仍超限：直接截断 */
				long target = budget *
					      ASK_COMPACT_TARGET_PCT / 100;
				int dropped = 0;

				if (!g_ask_ac.warned) {
					printf(tr(TR_CMP_GUARD),
					       ui_c(color, UI_C_DIM));
					g_ask_ac.warned = 1;
				}
				if (ask_hist_truncate_session(
					    sess_name, hist, nhist,
					    target, &dropped) == AI_OK) {
					compacted_now = 1;
					g_ask_ac.since_compact = 0;
					ask_hist_reload(shell, sess_name,
							&hist, &nhist,
							&hist_pool,
							&hist_pool_n);
					used = ask_compact_hist_tokens(hist,
								       nhist);
					printf("[compact] truncate dropped=%d "
					       "after=%ld target=%ld\n",
					       dropped, used, target);
				}
			}
			(void)used;
		}

		hist_before = nhist;
		{
			/* 历史可用预算 = ctx_len - 生效 max_tokens - 预留
			 * （system+tools schema+本轮问题+注入） */
			long mt = ai_config_effective_max_tokens(
				shell->config,
				shell->runtime.model_provider_type);
			long budget = ask_ctx_hist_budget(
				shell->config->ui.ctx_len, mt);

			ask_hist_trim(&hist, &nhist, budget,
				      ASK_HIST_MAX_MESSAGES, &trim_turns);
		}
		hist_n = nhist;

		/* 首条 system（降级切换时 system 会重建） */
		{
			struct ai_chat_msg m;

			memset(&m, 0, sizeof(m));
			m.role = "system";
			m.content = system_native;
			ask_msgs_push(&a, &m);

			for (i = 0; i < nhist; i++)
				ask_msgs_push(&a, &hist[i]);
		}
		/* 注意：hist 指针入列后 hist_pool 在 out 处统一释放 */
	}

	/* 5. 本轮 user 消息（含遥测/记忆注入） */
	{
		char *user;
		struct ai_chat_msg m;

		if (asprintf(&user, tr(TR_ASK_USER_TASK_FMT),
			     sense_ctx ? sense_ctx : "",
			     mem_ctx ? mem_ctx : "",
			     (sense_ctx || mem_ctx) ? "\n" : "",
			     question) < 0) {
			ret = AI_ERR_MEMORY;
			goto out;
		}
		ask_own(&owned, user);

		memset(&m, 0, sizeof(m));
		m.role = "user";
		m.content = user;
		ask_msgs_push(&a, &m);

		/* 会话落盘：用户原始问题（注入内容不落盘） */
		ask_sess_append(shell, "user", question, NULL, NULL, NULL);
	}

	/* W77b hotfix (B-077): 用户明确要求隔离区/沙箱时，预激活 sandbox_*
	 * 工具，避免首轮仅 8 件、模型在后续轮忽略动态扩入而拒绝执行。 */
	if (strstr(question, "隔离") || strstr(question, "沙箱") ||
	    strstr(question, "sandbox") || strstr(question, "isolation")) {
		int pi;

		for (pi = 0; pi < reg.tool_count; pi++) {
			if (strncmp(reg.tools[pi].name, "sandbox_", 8) == 0)
				router_activate(&router, reg.tools[pi].name);
		}
	}

	/* 请求 tools 数组 = 已激活集合（默认激活 8 个；SME 检索命中
	 * 动态扩入——dirty 置位后下一轮请求前重建） */
	tools_json = tool_registry_build_tools_json_filtered(&reg,
			(const char *const *)router.active, router.n_active);
	router.dirty = 0;

	printf("%s=== AIKernel ask ===%s\n", ui_c(color, UI_C_CYAN),
	       ui_c(color, UI_C_RESET));
	/* W20：单发模式（-p）下若默认模型未成功 set_model，current_model
	 * 可为 NULL——TR_ASK_HEADER_FMT 对其 %s 打印会 strlen 崩溃
	 * （L1 t14 金标准复测实证 SIGSEGV@__strlen_avx2），兜底占位 */
	printf(tr(TR_ASK_HEADER_FMT),
	       shell->runtime.current_model ? shell->runtime.current_model
					    : "-",
	       router.n_active, reg.tool_count,
	       route_mode == AI_ROUTE_PRE_RETRIEVE ? tr(TR_ROUTE_PRE_LABEL) :
	       tr(TR_ROUTE_AUTO_LABEL),
	       max_rounds, sess_name, hist_n);
	if (trim_turns > 0)
		printf(tr(TR_ASK_TRIM_FMT), ui_c(color, UI_C_DIM),
		       trim_turns, hist_before, hist_n,
		       ui_c(color, UI_C_RESET));
	if (sense_ctx)
		printf("%s", status_ctx ? tr(TR_ASK_CTX_STATUS) :
		       tr(TR_ASK_CTX_SENSE));
	if (mem_ctx)
		printf(tr(TR_ASK_CTX_MEM), ASK_ROUTE_PRE_TOPK);
	printf("\n");

	/* 6. 模型循环 */
	for (round = 1; round <= max_rounds; round++) {
		struct ai_chat_result *result = NULL;

		rounds_run = round;

		/* W65 P1：上一轮工具执行期间收到 Ctrl-C */
		if (ai_cancel_requested) {
			printf(tr(TR_ASK_CANCELLED), ui_c(color, UI_C_DIM),
			       ui_c(color, UI_C_RESET));
			end_reason = "cancelled";
			ret = AI_ERR_GENERIC;
			break;
		}

		/* SME 路由激活扩入：上一轮 memory_search 命中的工具已
		 * 进激活集合，本请求的 tools 数组重建扩入完整 schema。
		 * W55 P1：降级路径没有 tools 数组，但 system 里的文本
		 * 清单同样必须重建（否则模型看到的仍是启动时的 8 件，
		 * 框架提示与实际能力不一致）。 */
		if (router.dirty) {
			char *nj = tool_registry_build_tools_json_filtered(
				&reg, (const char *const *)router.active,
				router.n_active);

			if (nj) {
				free(tools_json);
				tools_json = nj;
			}
			if (fallback_mode) {
				char *nsys = build_fallback_system(&reg,
						&router, route_mode);

				if (nsys) {
					free(system_fallback);
					system_fallback = nsys;
					a.m[0].content = system_fallback;
				}
			}
			router.dirty = 0;
			printf(tr(TR_ASK_TOOLS_EXPANDED),
			       ui_c(color, UI_C_DIM), router.n_active,
			       reg.tool_count, ui_c(color, UI_C_RESET));
		}

		printf(tr(TR_ASK_ROUND_FMT), ui_c(color, UI_C_DIM), round,
		       ui_c(color, UI_C_RESET));
		fflush(stdout);
		st.printed = 0;
		ui_spinner_start("thinking...");

		{
			long long call_t0 = ai_trace_now_ms();
			long long call_ms;

			ret = ai_runtime_chat_ex(&shell->runtime, a.m, a.n,
					 fallback_mode ? NULL : tools_json,
					 (shell->config->ui.stream &&
					  !ui_fbterm_compat()) ?
					 ask_on_delta : NULL, &st, &result);
			call_ms = ai_trace_now_ms() - call_t0;
			if (shell->runtime.last_was_local)
				ai_route_note_local(ret == AI_OK,
					shell->runtime.last_status_code, ret,
					call_ms);
			else
				ai_route_note_cloud(ret == AI_OK,
					shell->runtime.last_status_code, ret);
		}
		/* fbterm 兼容模式（W18 问题 3）不挂 delta 回调：回复走
		 * 非流式整行输出路径（"AI: <全文>" 一次成行，不含覆盖类
		 * 序列），spinner 已退化为单行静态提示。 */
		/* 无增量输出（非流式/工具调用轮）时收掉 spinner */
		ui_spinner_stop();

		/* W65 P1：生成期 Ctrl-C——handler 已置位并 shutdown socket，
		 * ai_runtime_chat_ex 立即返回。丢弃半截响应，如实告知取消，
		 * 回到提示符（turn_end 记 cancelled）。 */
		if (ai_cancel_requested) {
			if (result) {
				ai_chat_result_free(result);
				free(result);
				result = NULL;
			}
			printf(tr(TR_ASK_CANCELLED), ui_c(color, UI_C_DIM),
			       ui_c(color, UI_C_RESET));
			end_reason = "cancelled";
			ret = AI_ERR_GENERIC;
			break;
		}

		if (ret != AI_OK) {
			int status = shell->runtime.last_status_code;
			int was_local = shell->runtime.last_was_local;

			/* W77 1)：云失败自动切本地（网络/DNS/认证/429/5xx/
			 * 超时）。切换只改 provider 配置，实测 <2s；失败记忆
			 * 让后续 ask 直接走本地。 */
			if (!was_local && !route_failed_over &&
			    ai_route_should_failover(shell->config,
					AI_ROUTE_TARGET_CLOUD, ret, status,
					route_failed_over)) {
				char reason[64];
				long long sw = 0;
				int fr;

				if (status == 429)
					snprintf(reason, sizeof(reason),
						 "http_429");
				else if (status >= 500)
					snprintf(reason, sizeof(reason),
						 "http_%d", status);
				else if (ret == AI_ERR_NETWORK)
					snprintf(reason, sizeof(reason),
						 "network_or_dns");
				else if (ret == AI_ERR_AUTH)
					snprintf(reason, sizeof(reason),
						 "auth");
				else
					snprintf(reason, sizeof(reason),
						 "api_error");
				fr = ai_route_failover(&shell->runtime,
					AI_ROUTE_TARGET_CLOUD,
					AI_ROUTE_TARGET_LOCAL, reason, &sw);
				if (fr == AI_OK) {
					printf("\n[offline] 云端不可用（%s），"
					       "已切换到本地模型 %s "
					       "（capability limited；D2+ "
					       "仍需 lease/确认）。"
					       "切换 %lldms。\n",
					       reason,
					       shell->runtime.model_name ?
					       shell->runtime.model_name : "-",
					       sw);
					route_failed_over = 1;
					current_target = AI_ROUTE_TARGET_LOCAL;
					route_choice.target =
						AI_ROUTE_TARGET_LOCAL;
					/* 本地 qwen 不保证原生 tools：下一轮
					 * 若仍失败会走文本 JSON 协议降级 */
					round--;
					continue;
				}
			}

			/* W77 2)：本地 429/5xx 临时错误重试一次（100ms
			 * 退避），避免单次抖动直接判死；仍失败则明确降级。 */
			if (was_local && !local_retry_used &&
			    (status == 429 || status == 500 ||
			     status == 502 || status == 503 ||
			     status == 504)) {
				local_retry_used = 1;
				printf("\n[offline] 本地模型临时错误 HTTP %d，"
				       "重试一次...\n", status);
				usleep(100000);
				round--;
				continue;
			}

			/* 3)：协议/参数问题（400/422/未知状态）→ 文本 JSON
			 * 工具协议降级重试一次；网络/认证错误不走此路径。 */
			if (!fallback_mode &&
			    (status == 400 || status == 422 || status == 0) &&
			    ret != AI_ERR_NETWORK && ret != AI_ERR_AUTH) {
				printf("%s", tr(TR_ASK_FALLBACK_RETRY));
				ai_trace_degraded("cloud",
					"tools_unsupported",
					"switch to text tool-call protocol");
				fallback_mode = 1;
				{
					char *nsys = build_fallback_system(
						&reg, &router, route_mode);

					if (nsys) {
						free(system_fallback);
						system_fallback = nsys;
					}
				}
				a.m[0].content = system_fallback;
				round--;
				continue;
			}

			/* 4)：明确降级（不伪装成功、不丢会话、给替代）。 */
			{
				char dmsg[1600];

				if (was_local) {
					ask_degrade_text("本地模型不可用",
							 ai_error_string(ret),
							 dmsg, sizeof(dmsg));
					end_reason = "local_unavailable";
				} else {
					ask_degrade_text(
						"云端模型不可用且本地不可用",
						ai_error_string(ret),
						dmsg, sizeof(dmsg));
					end_reason = "cloud_unavailable";
				}
				printf("\n%s\n", dmsg);
				ask_sess_append(shell, "assistant", dmsg,
						NULL, NULL, NULL);
				ai_offline_cache_plan(question,
					was_local ? "local" : "cloud",
					"degraded", rounds_run, NULL,
					end_reason);
				plan_cached = 1;
				if (result) {
					ai_chat_result_free(result);
					free(result);
					result = NULL;
				}
				break;
			}
		}

		if (!result) {
			ret = AI_ERR_API;
			printf("%s", tr(TR_ASK_NO_RESULT));
			end_reason = "no_result";
			break;
		}

		/* finish_reason=length：生成被 max_tokens 截断 */
		if (result->finish_reason &&
		    strcmp(result->finish_reason, "length") == 0)
			printf(tr(TR_ASK_TRUNC_WARN),
			       ui_c(color, UI_C_YELLOW),
			       ui_c(color, UI_C_RESET));

		/* 6a. 原生 tool_calls */
		if (result->tool_call_count > 0) {
			char *tc_json = ai_chat_render_tool_calls(
				result->tool_calls, result->tool_call_count);
			int executed = 0;

			if (st.printed)
				printf("\n");
			printf(tr(TR_ASK_TC_REQ),
			       ui_c(color, UI_C_DIM),
			       result->tool_call_count,
			       ui_c(color, UI_C_RESET));
			param_error = 0;
			execute_round(shell, &a, &owned, &reg, result,
				      tc_json, 1, &executed, &param_error,
				      &router, &clarify);
			free(tc_json);
			ai_chat_result_free(result);
			free(result);
			if (clarify.stop) {
				ask_clarify_finish(shell, color, &clarify,
						   &final_ok, &ret,
						   &end_reason);
				break;
			}
			if (ai_cancel_requested) {
				printf(tr(TR_ASK_CANCELLED),
				       ui_c(color, UI_C_DIM),
				       ui_c(color, UI_C_RESET));
				end_reason = "cancelled";
				ret = AI_ERR_GENERIC;
				break;
			}
			if (param_error && !repair_used &&
			    round < max_rounds) {
				repair_used = 1;
				printf(tr(TR_ASK_ARG_REPAIR),
				       ui_c(color, UI_C_DIM),
				       ui_c(color, UI_C_RESET));
				ai_trace_degraded("tool_args", "auto_repair",
					"structured E_PARAM returned; retrying once");
				ask_add_repair_hint(&a, &owned);
				continue;
			}
			if (!executed) {
				end_reason = "no_tool_executed";
				break;
			}
			continue;
		}

		/* 6b. 降级模式：文本 JSON 工具调用 */
		if (fallback_mode && result->content) {
			struct ai_tool_call tc;
			char *answer = NULL;
			int rc2 = ai_chat_parse_text_toolcall(result->content,
							      &tc, &answer);

			if (rc2 == AI_TEXT_TOOL_CALL) {
				int executed = 0;
				struct ai_chat_result tmp;

				memset(&tmp, 0, sizeof(tmp));
				tmp.content = result->content;
				tmp.tool_calls = &tc;
				tmp.tool_call_count = 1;
				printf(tr(TR_ASK_FALLBACK_TC),
				       ui_c(color, UI_C_DIM),
				       ui_c(color, UI_C_RESET));
				param_error = 0;
				execute_round(shell, &a, &owned, &reg, &tmp,
					      NULL, 0, &executed, &param_error,
					      &router, &clarify);
				free(tc.id);
				free(tc.name);
				free(tc.arguments);
				ai_chat_result_free(result);
				free(result);
				if (clarify.stop) {
					ask_clarify_finish(shell, color, &clarify,
							   &final_ok, &ret,
							   &end_reason);
					break;
				}
				if (ai_cancel_requested) {
					printf(tr(TR_ASK_CANCELLED),
					       ui_c(color, UI_C_DIM),
					       ui_c(color, UI_C_RESET));
					end_reason = "cancelled";
					ret = AI_ERR_GENERIC;
					break;
				}
				if (param_error && !repair_used &&
				    round < max_rounds) {
					repair_used = 1;
					printf(tr(TR_ASK_ARG_REPAIR),
					       ui_c(color, UI_C_DIM),
					       ui_c(color, UI_C_RESET));
					ai_trace_degraded("tool_args",
						"auto_repair",
						"structured E_PARAM returned; retrying once");
					ask_add_repair_hint(&a, &owned);
					continue;
				}
				if (!executed) {
					end_reason = "no_tool_executed";
					break;
				}
				continue;
			}
			/* {"answer":...} 或纯文本 → 最终回答 */
			if (st.printed) {
				printf("\n");
			} else {
				printf("\n%sAI:%s %s\n",
				       ui_c(color, UI_C_CYAN),
				       ui_c(color, UI_C_RESET),
				       answer ? answer : result->content);
			}
			/* 会话落盘：最终回答 */
			ask_sess_append(shell, "assistant",
					answer ? answer : result->content,
					NULL, NULL, NULL);
			free(answer);
			ai_chat_result_free(result);
			free(result);
			final_ok = 1;
			ret = AI_OK;
			break;
		}

		/* 6c. 原生模式但模型没用 tools：内容形似约定 JSON 时
		 * 自动降级解析一次（模型忽略 tools 字段的兜底） */
		if (result->content && strchr(result->content, '{')) {
			struct ai_tool_call tc;
			char *answer = NULL;

			if (ai_chat_parse_text_toolcall(result->content,
							&tc, &answer) ==
			    AI_TEXT_TOOL_CALL) {
				int executed = 0;
				struct ai_chat_result tmp;

				printf(tr(TR_ASK_SWITCH_FALLBACK),
				       ui_c(color, UI_C_DIM),
				       ui_c(color, UI_C_RESET));
				fallback_mode = 1;
				{
					char *nsys = build_fallback_system(
						&reg, &router, route_mode);

					if (nsys) {
						free(system_fallback);
						system_fallback = nsys;
					}
				}
				a.m[0].content = system_fallback;
				memset(&tmp, 0, sizeof(tmp));
				tmp.content = result->content;
				tmp.tool_calls = &tc;
				tmp.tool_call_count = 1;
				param_error = 0;
				execute_round(shell, &a, &owned, &reg, &tmp,
					      NULL, 0, &executed, &param_error,
					      &router, &clarify);
				free(tc.id);
				free(tc.name);
				free(tc.arguments);
				ai_chat_result_free(result);
				free(result);
				if (clarify.stop) {
					ask_clarify_finish(shell, color, &clarify,
							   &final_ok, &ret,
							   &end_reason);
					break;
				}
				if (ai_cancel_requested) {
					printf(tr(TR_ASK_CANCELLED),
					       ui_c(color, UI_C_DIM),
					       ui_c(color, UI_C_RESET));
					end_reason = "cancelled";
					ret = AI_ERR_GENERIC;
					break;
				}
				if (param_error && !repair_used &&
				    round < max_rounds) {
					repair_used = 1;
					printf(tr(TR_ASK_ARG_REPAIR),
					       ui_c(color, UI_C_DIM),
					       ui_c(color, UI_C_RESET));
					ai_trace_degraded("tool_args",
						"auto_repair",
						"structured E_PARAM returned; retrying once");
					ask_add_repair_hint(&a, &owned);
					continue;
				}
				if (!executed) {
					end_reason = "no_tool_executed";
					break;
				}
				continue;
			}
			free(answer);
		}

		/* 6d. 最终回答（流式已实时打印则只补换行） */
		if (st.printed) {
			printf("\n");
		} else {
			printf("\n%sAI:%s %s\n", ui_c(color, UI_C_CYAN),
			       ui_c(color, UI_C_RESET),
			       result->content ? result->content :
			       tr(TR_ASK_EMPTY_ANSWER));
		}
		/* 会话落盘：最终回答 */
		ask_sess_append(shell, "assistant",
				result->content ? result->content : "",
				NULL, NULL, NULL);
		ai_chat_result_free(result);
		free(result);
		final_ok = 1;
		ret = AI_OK;
		break;
	}

	if (round > max_rounds) {
		struct ai_chat_result *result = NULL;
		struct ai_chat_msg fm;
		int frc;

		end_reason = "max_rounds";
		/* W72：触顶不再只打印英文错误。追加一条"禁止工具、只给
		 * 结论"的本地提示（不落盘），再发一次无 tools 的收尾请求；
		 * 工具轮数仍由 max_rounds 硬上限约束，不会死循环。 */
		printf(tr(TR_ASK_MAX_ROUNDS_FINAL), max_rounds);
		fflush(stdout);
		memset(&fm, 0, sizeof(fm));
		fm.role = "user";
		fm.content = ask_own(&owned, strdup(tr(TR_ASK_FINAL_HINT)));
		if (fm.content && ask_msgs_push(&a, &fm) == AI_OK) {
			ui_spinner_start("thinking...");
			frc = ai_runtime_chat_ex(&shell->runtime, a.m, a.n,
						 NULL, NULL, NULL, &result);
			ui_spinner_stop();
		} else {
			frc = AI_ERR_MEMORY;
		}
		if (ai_cancel_requested) {
			printf(tr(TR_ASK_CANCELLED), ui_c(color, UI_C_DIM),
			       ui_c(color, UI_C_RESET));
			end_reason = "cancelled";
			ret = AI_ERR_GENERIC;
		} else if (frc == AI_OK && result && result->content &&
			   result->content[0]) {
			printf("%sAI:%s %s\n", ui_c(color, UI_C_CYAN),
			       ui_c(color, UI_C_RESET), result->content);
			ask_sess_append(shell, "assistant", result->content,
					NULL, NULL, NULL);
			final_ok = 1;
			ret = AI_OK;
		} else {
			printf(tr(TR_ASK_MAX_ROUNDS), max_rounds);
			ret = AI_ERR_API;
		}
		ai_chat_result_free(result);
		free(result);
	}

	/* 上下文预算 >80% 黄色警告（W56 T5：按最近一次请求的 prompt
	 * 计算——completion 是输出且会进入下一轮 prompt，相加属重复
	 * 计数，会在 compact 后产生 110% 假超限；也不累加整个会话） */
	{
		struct ai_runtime *rt = &shell->runtime;
		int pct = ask_ctx_budget_percent(rt->token_last_in,
						 rt->token_last_out,
						 shell->config->ui.ctx_len);

		if (pct > 80)
			printf(tr(TR_ASK_CTX_WARN),
			       ui_c(color, UI_C_YELLOW), pct,
			       ui_c(color, UI_C_RESET));
	}

out:
	if (trace_turn)
		ai_trace_turn_end(end_reason, rounds_run);

	/*
	 * W72：提示符百分比口径修正。REPL 提示符用
	 * token_session_in + token_session_out 计算百分比；旧代码让这两个
	 * 计数器跨轮/跨工具累计，W70 实测显示到 999%。这里在每次 ask
	 * 结束时把它们改写为"本次最终请求的 prompt"，completion 归零——
	 * 提示符即"当前请求上下文 / ctx_len"，并按 ctx_len 钳到 100%
	 * （显示层不再出现 999%）。累计用量仍保留在 token_used。
	 */
	{
		struct ai_runtime *rt = &shell->runtime;
		int cap = shell->config->ui.ctx_len;
		int in = rt->token_last_in;

		if (in < 0)
			in = 0;
		if (cap > 0 && in > cap)
			in = cap;
		rt->token_session_in = in;
		rt->token_session_out = 0;
	}
	/* W72 压缩冷却：本 ask 未压缩/截断才累计"距上次压缩轮数"；
	 * 压缩轮归零，后续 2 轮跳过自动压缩。 */
	if (!compacted_now &&
	    g_ask_ac.since_compact < ASK_COMPACT_COOLDOWN_TURNS)
		g_ask_ac.since_compact++;
	ask_ac_save(sess_name);

	/* W72：沙箱子智能体的机器可读收尾状态。父模型只看到 spawn 的
	 * dispatcher 退出码，无法区分"派发进程退出"与"子任务完成"；
	 * 沙盒内单发 ask 在 stdout 末尾输出该行，sandbox_spawn 解析后
	 * 在结果中同时给出 dispatcher_exit 与 task_status。 */
	{
		const char *sb = getenv("AIKERNEL_SANDBOX");

		if (sb && sb[0])
			printf("[ai-status] end_reason=%s rounds=%d final=%d "
			       "rc=%d\n", end_reason, rounds_run, final_ok,
			       ret);
	}

	/* W77：缓存最近计划摘要（离线“最近计划”查询使用；不含密钥）。
	 * 失败路径也记录，便于断网后回看上次做了什么、卡在哪。 */
	if (question && !plan_cached) {
		char tools_csv[512] = "";
		const char *rname = offline_used ? "offline" :
				    shell->runtime.last_was_local ? "local" :
				    current_target == AI_ROUTE_TARGET_LOCAL ?
				    "local" : "cloud";
		int i;

		for (i = 0; i < a.n; i++) {
			const char *tn = a.m[i].tool_name;
			size_t off;

			if (!tn || !tn[0])
				continue;
			if (strstr(tools_csv, tn))
				continue;
			off = strlen(tools_csv);
			snprintf(tools_csv + off, sizeof(tools_csv) - off,
				 "%s%s", off ? "," : "", tn);
		}
		ai_offline_cache_plan(question, rname,
				      final_ok ? "ok" : end_reason,
				      rounds_run,
				      tools_csv[0] ? tools_csv : NULL,
				      end_reason);
	}

	/* W65 P1：退出活跃态；ai_cancel_requested 保留到下一次 arm，
	 * 供单发模式判定 session_end 原因。 */
	ai_cancel_disarm();
	ask_clarify_state_free(&clarify);
	free(question);
	free(sense_ctx);
	free(mem_ctx);
	free(tools_json);
	free(system_native);
	free(system_fallback);
	free(catalog);
	free(a.m);
	ai_offline_answer_free(&offline_ans);
	ask_owned_free(&owned);
	router_free(&router);
	{
		int i;

		for (i = 0; i < hist_pool_n; i++)
			free(hist_pool[i]);
		free(hist_pool);
	}
	tool_registry_free(&reg);
	return ret;
}
