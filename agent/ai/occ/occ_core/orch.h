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
 * 链接面：只依赖 session.o/task.o（E1 底座）；尚未链入 occ 主程序
 * （E3 Task 工具接线），headless `occ -p` 协议零变化。
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

/* 运行时错误码（spawn/cancel 返回；err 缓冲带人话） */
#define OCC_ORCH_OK		0
#define OCC_ORCH_EARGS		(-1)	/* 参数不合法 */
#define OCC_ORCH_ELIMIT		(-2)	/* 并发上限 2 已满（第三路拒绝） */
#define OCC_ORCH_EBACKOFF	(-3)	/* 撞限退避窗内（err 带剩余 ms） */
#define OCC_ORCH_ESPAWN		(-4)	/* fork/execve/occ 可执行解析失败 */
#define OCC_ORCH_EDB		(-5)	/* 会话/任务面（E1 API）失败 */

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
 *                 env 中同名项后写覆盖）
 *   timeout_ms    per-任务墙钟上限；0=无限。超时→取消同路径
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

#endif /* _OCC_ORCH_H */
