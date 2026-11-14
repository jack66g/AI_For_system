/* SPDX-License-Identifier: GPL-2.0 */
/*
 * orch.h - occ 子智能体运行时（ORCH-DESIGN §8 棒 E2；R4 进程隔离）
 *
 * 设计基线（§0 R4，五条理由=弃线程池）：每子智能体一个 `occ -p`
 * 子进程 + 一个 kind='child' 私有会话（occ_session_create_kind），
 * 取消=杀进程（精准无全局旗标误伤）、崩溃隔离、蒸馏后丢弃=进程退出。
 * 全局静态态（g_ac_state/g_sme_state/occ_interrupt_flag）零触碰——
 * 子进程各自成库会话，主会话上下文不受污染。
 *
 * 五件硬约束（§8 E2 行；实现语义如下）：
 *  1) 并发上限 2（OCC_ORCH_MAX_CHILDREN）：第三路 spawn 立即拒绝
 *     （OCC_ORCH_ELIMIT），并开 30s 退避窗（OCC_ORCH_BACKOFF_MS）
 *     ——窗内再 spawn 一律 OCC_ORCH_EBACKOFF（含槽位已空时：撞过限
 *     的路必须等满窗，非 sleep 阻塞——调用方以 occ_orch_backoff_ms
 *     拿剩余毫秒自行调度）。正常 ≤2 路轮转永不触发窗。
 *  2) 取消两段（TERM→宽限 OCC_ORCH_TERM_GRACE_MS→KILL）：子进程
 *     独立进程组（setpgid），TERM/KILL 发往 -pgid——只断目标子树，
 *     绝不误伤无关进程；终局 waitpid 收尸（进程表零残留）。
 *  3) 超时：spawn 时钉 deadline（timeout_ms），超时走取消同路径
 *     （TERM→宽限→KILL），终局分类 occ_orch_end=TIMEOUT。
 *  4) 结果回收：子进程 stdout/stderr 重定向文件（R4「任务书写文件/
 *     报告读文件」IPC——本棒 prompt 经 argv（occ -p 协议字节零变化）、
 *     报告=stdout 文件；brief 全文落 occ_task.brief_json 审计）；
 *     终局区分正常退出（EXIT+exit_code）/崩溃（SIGNAL+信号号，
 *     SIGSEGV 等）/我方取消（CANCELLED）/超时（TIMEOUT），stdout
 *     尾窗（OCC_ORCH_STDOUT_TAIL）读回进结果。
 *  5) 任务面联动（消费 E1）：spawn 自动建 child 会话+occ_task 行
 *     （pending→dispatched）；子进程终局回收即 occ_task_review
 *     （dispatched→in_review，result_json=终局摘要；E4 验收环裁决）。
 *     spawn 在任务已 dispatched 后失败 → occ_task_escalate 落审计。
 *
 * 生命周期合同：
 *   occ_orch_spawn → occ_orch_child*（活子表内；终局前有效）
 *   occ_orch_wait/poll/cancel 终局 → occ_orch_result 填充且 child*
 *     即刻失效（库内已收尸+出表+释放——调用方不得再引用）
 *   occ_orch_free：仍活着的子按取消两段收尸（不 review——半完成态
 *     留 dispatched 可审计，§10 风险 3）
 *
 * 线程合同：非线程安全（occ 主环单线程调用；R4 进程隔离后无需加锁）。
 * 链接面：只依赖 session.o/task.o（E1 底座）；E3 起经 occ_tool_ctx.orch
 * 接入主程序（occ.c 进程级实例），headless `occ -p` 协议零变化。
 *
 * E3 追加（§8 棒 E3——Task 工具+派发协议）：
 *  - occ_orch_tools_enabled：OCC_ORCH_TOOLS 总闸（默认关——第七工具
 *    task 与判级提示段仅在开关打开时注册/注入；默认路径 LLM 请求字节
 *    零变化，差分 62/62 与 p-smoke 红线不动）。
 *  - 文件集互斥（§3 拍板 7 独占声明）：spawn 携带 fileset（绝对路径
 *    数组）→ 并发闸之后、任务面建行之前查登记表，与在跑任务声明撞车
 *    即 OCC_ORCH_EFILESET 拒绝（任务面未动，干净拒绝）；spawn 成功即
 *    登记，任务终局（poll/wait/cancel 回收）或 occ_orch_free 自动注销。
 *  - 结果文件 env 通道：spawn 建任务行后若未显式给 result_path，自动
 *    /tmp mkstemp 生成并以 OCC_TASK_RESULT_FILE 注入子进程 env（子智能
 *    体报告写它；prompt 侧由 task 工具告知）。登记进任务注册表，终局
 *    后保留（read_result 窗口），orch 自动生成的文件 occ_orch_free 时
 *    清理；显式给的归调用方。
 *  - occ_orch_find_task/occ_orch_result_path：task 工具 status/wait/
 *    read_result 动作的运行时查询面。
 */
#ifndef _OCC_ORCH_H
#define _OCC_ORCH_H

#include <sys/types.h>

#include "occ_session.h"
#include "task.h"

#define OCC_ORCH_MAX_CHILDREN	2	/* R4/拍板：并发子进程上限 */
#define OCC_ORCH_BACKOFF_MS	30000L	/* 撞限退避窗（闸内时间窗语义） */
#define OCC_ORCH_TERM_GRACE_MS	2000L	/* 取消两段：TERM 宽限后 KILL */
#define OCC_ORCH_STDOUT_TAIL	8192	/* 结果回收保留的 stdout 尾窗 */

/* 结果文件 env 注入键（spawn 自动通道；子进程把报告写往该文件） */
#define OCC_ORCH_RESULT_ENV	"OCC_TASK_RESULT_FILE"

/* 运行时错误码（spawn/cancel 返回；err 缓冲带人话） */
#define OCC_ORCH_OK		0
#define OCC_ORCH_EARGS		(-1)	/* 参数不合法 */
#define OCC_ORCH_ELIMIT		(-2)	/* 并发上限 2 已满（第三路拒绝） */
#define OCC_ORCH_EBACKOFF	(-3)	/* 撞限退避窗内（err 带剩余 ms） */
#define OCC_ORCH_ESPAWN		(-4)	/* fork/execve/occ 可执行解析失败 */
#define OCC_ORCH_EDB		(-5)	/* 会话/任务面（E1 API）失败 */
#define OCC_ORCH_EFILESET	(-6)	/* E3：文件集与在跑任务独占声明冲突 */

/* 子进程终局分类（结果回收四分开记） */
typedef enum {
	OCC_ORCH_END_EXIT = 0,		/* 正常退出：exit_code 有效
					 *（0=成功完成；127=execve 失败）*/
	OCC_ORCH_END_SIGNAL,		/* 崩溃：被信号杀且非我方所为
					 *（signal=SIGSEGV 等） */
	OCC_ORCH_END_CANCELLED,		/* 我方取消：TERM 段（15）或宽限
					 * 后 KILL 段（9） */
	OCC_ORCH_END_TIMEOUT		/* 超时→取消同路径（signal 同上） */
} occ_orch_end;

typedef struct occ_orch_result {
	occ_orch_end end;		/* 终局分类 */
	int exit_code;			/* END_EXIT：退出码 */
	int signal;			/* END_SIGNAL/CANCELLED/TIMEOUT：
					 * 致死信号（15/9/11…） */
	long long dur_ms;		/* spawn→终局墙钟 */
	char *stdout_tail;		/* heap；stdout 尾窗（≤8KiB）；
					 * 可 NULL（无输出/读失败） */
	char session_id[OCC_ID_LEN];	/* 子会话 id（空=无会话面） */
	char task_id[OCC_ID_LEN];	/* 任务 id（空=无任务面） */
	int reviewed;			/* 1=终局已 occ_task_review 进
					 * in_review；0=无任务面或落库
					 * 失败（任务留 dispatched） */
} occ_orch_result;

typedef struct occ_orch occ_orch;		/* 运行时（并发闸+活子表） */
typedef struct occ_orch_child occ_orch_child;	/* 活子（终局即失效） */

/*
 * occ_orch_spawn_opts - spawn 入参（memset 0 后按需填；prompt 必填）。
 *
 *   prompt        发给 `occ -p` 的指令/任务书（argv 传递——headless
 *                 协议字节零变化；全文同时落 brief_json 审计）
 *   session_id    已建子会话 id；NULL=自动 occ_session_create_kind
 *                 （kind='child'，model 列=model 参数）
 *   model         自动建子会话时的 model 列；NULL=""
 *   parent_session 自动建任务（task_id NULL）时的主会话 id（FK 必须
 *                 存在）；NULL=不建任务行（纯 runtime 面，测试用）
 *   task_id       已建任务 id（须 pending/rework）；NULL+parent_session
 *                 非 NULL=自动建任务（title/brief_json/缺省 rework_max）
 *   title         自动建任务标题；NULL=prompt 截断（UTF-8 边界）
 *   occ_bin       occ 可执行路径；NULL=缺省解析（/proc/self/exe 同目录
 *                 occ，找不到退 PATH 搜索「occ」）
 *   workdir       子进程 cwd；NULL=继承当前
 *   stdout_path / stderr_path  子进程输出重定向文件；NULL=/tmp 下
 *                 mkstemp 自动生成（终局读回后随 child 释放删除）
 *   env           附加环境 NAME=VALUE 数组（NULL 结尾）；OCC_DB 由
 *                 运行时自动注入（=本运行时库路径，子会话/任务同库；
 *                 env 中同名项后写覆盖）；有任务面时 OCC_TASK_RESULT_FILE
 *                 亦自动注入（见头注 E3 段）
 *   timeout_ms    per-任务墙钟上限；0=无限。超时→取消同路径
 *   fileset       E3：授权文件集（独占声明；元素须绝对路径——调用方
 *                 归一）。与在跑任务撞车 → OCC_ORCH_EFILESET 拒绝；
 *                 NULL/0=不声明不登记（互斥面不参与）
 *   nfileset      fileset 元素数
 *   result_path   E3：结果文件（报告 IPC）。NULL+有任务面=自动 /tmp
 *                 mkstemp+env 注入+登记（occ_orch_free 清理）；显式给
 *                 =调用方持有；无任务面时不自动生成
 */
typedef struct occ_orch_spawn_opts {
	const char *prompt;
	const char *session_id;
	const char *model;
	const char *parent_session;
	const char *task_id;
	const char *title;
	const char *occ_bin;
	const char *workdir;
	const char *stdout_path;
	const char *stderr_path;
	const char *const *env;
	long long timeout_ms;
	const char *const *fileset;
	size_t nfileset;
	const char *result_path;
} occ_orch_spawn_opts;

/* ---- 运行时生命周期 ---- */

occ_orch *occ_orch_new(occ_db *db);	/* db 必填；NULL 返回 NULL */

/*
 * occ_orch_free - 释放运行时。仍活着的子按取消两段收尸（TERM→宽限
 * →KILL→waitpid），不 review（任务面留 dispatched 半完成态可审计）。
 */
void occ_orch_free(occ_orch *o);

/* 活子数（并发闸实时值；上限 OCC_ORCH_MAX_CHILDREN） */
int occ_orch_nrunning(const occ_orch *o);

/*
 * occ_orch_backoff_ms - 撞限退避窗剩余毫秒（0=无窗可 spawn）。
 * 撞限（ELIMIT）即开 30s 窗；窗过期自动复位。
 */
long long occ_orch_backoff_ms(const occ_orch *o);

/*
 * occ_orch_set_backoff_ms - 覆写退避窗长（测试时间窗用；产品勿调）。
 * ms<=0 复位缺省 OCC_ORCH_BACKOFF_MS。
 */
void occ_orch_set_backoff_ms(occ_orch *o, long long ms);

/* ---- spawn / 回收 ---- */

/*
 * occ_orch_spawn - 起一路子智能体：并发闸（上限 2+退避窗）→ 建子会话
 * （可免）→ 建任务+dispatch（可免）→ fork+execve `<occ_bin> -p
 * <prompt> --session <sid>`（env 注入 OCC_DB+附加项；独立进程组；
 * stdout/stderr→文件）。成功 *out=活子；失败回错误码（err 人话；
 * 任务已 dispatched 后失败自动 occ_task_escalate 落审计）。
 */
int occ_orch_spawn(occ_orch *o, const occ_orch_spawn_opts *opts,
		   occ_orch_child **out, char *err, size_t errlen);

/*
 * occ_orch_poll - 非阻塞探测。返回 1=已终局（收尸+review+读回完成，
 * *res 填充且 c 失效释放；res 可 NULL=丢弃细节）；0=在跑；-1=错。
 * deadline 到点在此触发取消同路径（后续 poll 轮推进 KILL 段）。
 */
int occ_orch_poll(occ_orch_child *c, occ_orch_result *res);

/*
 * occ_orch_wait - 阻塞等终局（20ms 轮询；deadline/取消两段在轮内
 * 推进）。0=终局（*res 填充，c 失效）；-1=错。SIGKILL 后进程必终
 * （D 状态除外——不设等待上限，如实挂起）。
 */
int occ_orch_wait(occ_orch_child *c, occ_orch_result *res,
		  char *err, size_t errlen);

/*
 * occ_orch_cancel - 主动取消（两段：TERM→OCC_ORCH_TERM_GRACE_MS
 * 宽限→KILL；只断 -pgid 目标子树）。终局分类 CANCELLED（若子进程
 * 在 TERM 前已自行退出则如实 EXIT/SIGNAL）。返回语义同 wait。
 */
int occ_orch_cancel(occ_orch_child *c, occ_orch_result *res,
		    char *err, size_t errlen);

void occ_orch_result_free(occ_orch_result *r);	/* stdout_tail 归零 */

/* ---- 活子观测（E3 Task 工具 status/wait 用） ---- */

pid_t occ_orch_child_pid(const occ_orch_child *c);
const char *occ_orch_child_session(const occ_orch_child *c);	/* 空=无 */
const char *occ_orch_child_task(const occ_orch_child *c);	/* 空=无 */

/* ---- E3：Task 工具/判级提示段总闸 + 文件集互斥 + 任务查询 ---- */

/*
 * occ_orch_tools_enabled - OCC_ORCH_TOOLS 开关（env；非空且非 "0"/
 * "false" 即开）。开=第七工具 task 注册（occ_tool_defs 返回 7 件）+
 * 判级提示段并入系统提示；关=全部零变化（差分/p-smoke 红线路径）。
 */
int occ_orch_tools_enabled(void);

/*
 * occ_orch_fileset_conflict - files 是否与在跑任务的独占声明撞车。
 * 返回 1=冲突（owner_task 回填持有任务 id；可 NULL 不取）；0=无冲突
 * （含 o/files 参数不完整——按无冲突放行，登记面缺省不拦截）。
 */
int occ_orch_fileset_conflict(const occ_orch *o, const char *const *files,
			      size_t n, char *owner_task, size_t buflen);

/*
 * occ_orch_find_task - 按任务 id 找活子（status/wait 动作运行时面）。
 * 返回活子句柄（终局前有效）；NULL=不在活表（已终局或无此任务）。
 */
occ_orch_child *occ_orch_find_task(occ_orch *o, const char *task_id);

/*
 * occ_orch_result_path - 任务结果文件路径（spawn 时登记；终局后保留
 * 至 occ_orch_free——read_result 窗口）。NULL=无该任务记录（进程
 * 重启后内存表丢失，调用方回退任务面 result 事件）。
 */
const char *occ_orch_result_path(const occ_orch *o, const char *task_id);

/* ---- E4：终局验收环挂点（ORCH-DESIGN §8 棒 E4；§4 验收环） ---- */

/*
 * occ_orch_review_hook - 独立评审智能体挂载点（§4「大任务可选独立
 * 评审智能体（第二双眼，fresh eyes）」——可选件）。子进程终局、
 * occ_task_review 落 in_review、机械预判（occ_review_prenote）完成后
 * 回调；回调内自行调 occ_review_run 裁决（裁判权在回调方）。返回值
 * 忽略（评审失败任务留 in_review 待主会话 return 动作兜底——验收环
 * 永不因评审挂掉而丢任务）。缺省 NULL=不挂（裁判=主会话，§4 缺省）。
 */
typedef int (*occ_orch_review_hook)(void *ud, occ_db *db,
				    const char *task_id,
				    const char *result_path,
				    const char *result_event_json);

void occ_orch_set_review_hook(occ_orch *o, occ_orch_review_hook fn,
			      void *ud);


/* E5（ORCH §5）：done 任务两级蒸馏第二级（关键实体清单）+审计+
 * child archived+SME 条目；幂等。返回蒸馏文（调用方 free）。 */
char *occ_orch_distill(occ_db *db, const char *task_id);
int occ_orch_compact_take(void);	/* E5 闸1：取走压缩请求旗 */

#endif /* _OCC_ORCH_H */
