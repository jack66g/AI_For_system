// SPDX-License-Identifier: GPL-2.0
/*
 * ai_proc.h - AIKernel 进程/线程管理与用户感知统一接口（Prompt 12）
 *
 * A 轨（重构计划 模块14）：ai_proc_*_hook() 系列——AI 参与进程分类、exec 预测、
 *   futex 优先级、信号评估（空实现 = 原样放行，决策表后续 Prompt 填充）。
 *
 * B 轨（数据计划 第5类 用户输入 / 第6类 进程与线程 / 第15类 用户行为）：
 *   ai_telemetry_* 类型化发射辅助，payload 全量原始零脱敏，首个字段 type 常量。
 *
 * 门控：
 *   - A 轨接口门控 CONFIG_AIKERNEL_RUNTIME；
 *   - B 轨遥测辅助门控 CONFIG_AIKERNEL_TELEMETRY；
 *   - n 配置全部 static inline 空函数兜底（零开销零回归）。
 *
 * 性能预算：热路径发射 < 100ns（per-CPU ring 无锁直写）；syscall 事件默认
 *   采样 1/256（ai_proc.c 内 ai_telemetry_init 覆盖默认率）；输入事件携带
 *   u64 ktime_get_ns() 事件时间戳。
 */

#ifndef _AIKERNEL_AI_PROC_H
#define _AIKERNEL_AI_PROC_H

#include "ai_types.h"
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cgroup.h>

/* ---- 按键序列元素（key_sequence raw_sequence 用） ---- */

struct ai_key_pair {
	u16 keycode;
	u16 delay_ms;
};

/* ---- 进程分类常量（对齐 ai_sched.h enum ai_sched_class 语义） ---- */

enum ai_proc_class {
	AI_PROC_CLASS_AI_LOAD     = 0,   /* AI 负载 */
	AI_PROC_CLASS_INTERACTIVE = 1,   /* 交互式 */
	AI_PROC_CLASS_BATCH       = 2,   /* 批处理 */
	AI_PROC_CLASS_KERNEL      = 3,   /* 内核线程 */
	AI_PROC_CLASS_MAX,               /* 边界（W3 决策注入范围校验用） */
};

/* ---- A 轨：分类槽表条目 ---- */

struct ai_proc_slot {
	int pid;
	u8  class;
	u8  alive;
	u32 gen;                 /* 换代计数（槽满时淘汰最旧） */
	u64 app_start_ns;        /* exec 后启动时刻（app_lifetime 用） */
	u64 app_start_boot_ns;
	char app_path[256];      /* exec 全路径（槽表存，用于 app_lifetime/crash） */
};

/* ---- A 轨：ai_proc_query 输出 ---- */

struct ai_proc_info {
	u8  class;
	u64 app_start_ns;
	u64 app_start_boot_ns;
	char app_path[256];
};

/* ---- A 轨：Hook 决策统计 ---- */

struct ai_proc_stats {
	u64 classify_count;
	u64 exec_count;
	u64 futex_count;
	u64 signal_count;
	u64 query_count;
	u64 slot_insert, slot_update, slot_remove, slot_evict;
};

#include "ai_proc_payload.h"

/* ==================================================================
 * A 轨接口（CONFIG_AIKERNEL_RUNTIME）
 * ================================================================== */

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_proc_classify_hook() - 新进程 AI 分类标记（模块14.1）
 * @p:    新创建的子进程
 * @args: clone 参数（flags/kthread/name）
 *
 * 由 kernel/fork.c copy_process() 成功路径调用。按父进程分类 + clone 特征
 * （kthread/io_thread→KERNEL、父交互式→INTERACTIVE、其余走
 * ai_sched_classify_task 启发式语义）写 pid 槽表。
 *
 * 返回分类（enum ai_proc_class）。
 */
u8 ai_proc_classify_hook(struct task_struct *p,
			 struct kernel_clone_args *args);

/**
 * ai_proc_exec_hook() - exec 路径 AI 预测（模块14.2）
 * @p:    正在 exec 的进程
 * @path: 新程序全路径
 *
 * 由 fs/exec.c bprm_execve() 成功路径调用。更新槽表分类与 app 启动记录
 * （本步按路径特征微调启发式；AI 预测后续 Prompt 替换）。
 */
void ai_proc_exec_hook(struct task_struct *p, const char *path);

/**
 * ai_proc_futex_hook() - AI 任务 futex 优先（模块14.4）
 * @p:    等待 futex 的进程
 * @addr: futex 地址
 * @val:  期望值
 *
 * 由 kernel/futex/ futex_wait() 调用。空实现 = 原逻辑放行 + 计数；
 * AI 优先级调整决策表后续 Prompt 填充。
 *
 * 返回 0 = 原逻辑。
 */
int ai_proc_futex_hook(struct task_struct *p, u32 addr, u32 val);

/**
 * ai_proc_signal_hook() - AI 评估异常信号模式（模块14.5）
 * @sig:   信号号
 * @target: 目标进程
 * @info:  信号详情（可为 NULL）
 *
 * 由 kernel/signal.c __send_signal_locked() 调用。空实现 = 放行 + 计数；
 * AI 信号过滤/降权决策表后续 Prompt 填充。
 *
 * 返回 0 = 放行。
 */
int ai_proc_signal_hook(int sig, struct task_struct *target,
			struct kernel_siginfo *info);

/**
 * ai_proc_query() - 查询进程 AI 信息（供 Prompt 13 调度接入）
 * @pid: 目标进程（当前 pid ns）
 * @out: 输出（class/app 启动时刻/路径）
 *
 * 返回 AI_OK 或 AI_ERR_NOT_FOUND（槽表 miss）。
 */
int ai_proc_query(int pid, struct ai_proc_info *out);

/**
 * ai_proc_stats() - Hook 决策统计
 * @out: 统计输出
 *
 * 返回 AI_OK。
 */
int ai_proc_stats(struct ai_proc_stats *out);

/**
 * ai_proc_slot_remove() - 删除进程分类槽位（进程退出时）
 * @pid: 目标进程
 *
 * 由 kernel/exit.c do_exit() 调用；槽位不存在时无操作。
 */
void ai_proc_slot_remove(int pid);

/**
 * ai_proc_slot_get() - 读取进程分类槽位（exec/app 生命周期用）
 * @pid: 目标进程
 * @out: 输出槽位内容
 *
 * 返回 AI_OK 或 AI_ERR_NOT_FOUND。
 */
int ai_proc_slot_get(int pid, struct ai_proc_slot *out);

/**
 * ai_proc_class_peek() - 轻量类查询（W3 决策注入热路径专用）
 * @pid: 目标进程
 *
 * 与 ai_proc_slot_get() 同一槽表，但只拷贝 class 单字段（临界区极短），
 * 且用 spin_trylock —— 槽表争用时不等待，直接返回 -1（调用方按"槽无效"
 * 回退原生行为）。未找到返回 -2。
 *
 * 返回 enum ai_proc_class（>=0）或负错误码。
 */
int ai_proc_class_peek(int pid);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline u8 ai_proc_classify_hook(struct task_struct *p,
				       struct kernel_clone_args *args)
{
	return AI_PROC_CLASS_BATCH;
}
static inline void ai_proc_exec_hook(struct task_struct *p, const char *path)
{
}
static inline int ai_proc_futex_hook(struct task_struct *p, u32 addr, u32 val)
{
	return 0;   /* 空函数兜底：原逻辑放行 */
}
static inline int ai_proc_signal_hook(int sig, struct task_struct *target,
				      struct kernel_siginfo *info)
{
	return 0;
}
static inline int ai_proc_query(int pid, struct ai_proc_info *out)
{
	if (out)
		memset(out, 0, sizeof(*out));
	return AI_ERR_NOT_FOUND;
}
static inline int ai_proc_stats(struct ai_proc_stats *out)
{
	if (out)
		memset(out, 0, sizeof(*out));
	return AI_OK;
}
static inline void ai_proc_slot_remove(int pid)
{
}
static inline int ai_proc_slot_get(int pid, struct ai_proc_slot *out)
{
	if (out)
		memset(out, 0, sizeof(*out));
	return AI_ERR_NOT_FOUND;
}
static inline int ai_proc_class_peek(int pid)
{
	return -1;   /* 决策注入未编译：按槽无效回退原生行为 */
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

/* ==================================================================
 * B 轨类型化发射辅助（CONFIG_AIKERNEL_TELEMETRY）
 * ================================================================== */

#ifdef CONFIG_AIKERNEL_TELEMETRY

#include "ai_telemetry.h"

/* ---- 第5类：用户输入 ---- */

void ai_telemetry_tty_input(const char *tty_name, const u8 *raw, u16 len);
void ai_telemetry_tty_output(const char *tty_name, const u8 *raw, u16 len);
void ai_telemetry_tty_line_discipline(const char *tty_name,
				      int old_ldisc, int new_ldisc);
void ai_telemetry_input_key_event(const char *device, u16 keycode,
				  u8 pressed, u64 ts_ns, const char *key_name);
void ai_telemetry_input_key_sequence(const char *device,
				     const struct ai_key_pair *pairs, u16 n,
				     u64 duration_ns);
void ai_telemetry_input_key_combo(const char *device, const u16 *keys,
				  u16 n, u32 duration_ms);
void ai_telemetry_input_mouse_move(const char *device, s16 dx, s16 dy,
				   s16 x, s16 y, u64 ts_ns);
void ai_telemetry_input_mouse_button(const char *device, u16 button,
				     u8 pressed, s16 x, s16 y, u64 ts_ns);
void ai_telemetry_input_mouse_scroll(const char *device, s16 dx, s16 dy);
void ai_telemetry_input_touch_event(const char *device, u16 x, u16 y,
				    u16 pressure, u8 touch_type,
				    u8 contact_count, u64 ts_ns);
/**
 * ai_telemetry_syscall_entry() - 系统调用全量参数（采样，默认 1/256）
 * @nr:           系统调用号
 * @name:         系统调用名（调用方从 syscalls_64.h 生成表提供）
 * @a0..a5:       6 个参数全量
 * @entry_ts_ns:  输出 entry 时刻（ktime_get_ns()）；采样未命中时为 0
 *
 * 返回 true = 本次采样命中（调用方需在出口调 ai_telemetry_syscall_exit 配对）。
 * 采样未命中仍累计频率/序列统计。由 arch/x86/entry/ do_syscall_64() 调用。
 */
bool ai_telemetry_syscall_entry(u32 nr, const char *name,
				u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5,
				u64 *entry_ts_ns);

/**
 * ai_telemetry_syscall_exit() - 系统调用出口（返回值/时延，随 entry 配对）
 * @nr:           系统调用号
 * @retval:       返回值
 * @entry_ts_ns:  entry 采样命中时刻（未命中为 0 → 不发射 exit）
 * @sampled:      entry 是否采样命中
 *
 * 由 do_syscall_64() 出口调用；始终累计 syscall_error_cluster 统计。
 */
void ai_telemetry_syscall_exit(u32 nr, s64 retval, u64 entry_ts_ns,
			       bool sampled);
void ai_telemetry_exec_command(u32 pid, u32 ppid, u16 argc,
			       const u8 *full_cmdline, u16 cmdline_len,
			       const u8 *envp_sample, u16 envp_len);
void ai_telemetry_shell_command(const char *shell, u16 cmdline_len,
				const u8 *cmdline, u16 cwd_len,
				const u8 *cwd);
void ai_telemetry_script_exec(const char *interp, const char *script_path,
			      const u8 *content, u16 content_len);

/* ---- 第6类：进程与线程 ---- */

void ai_telemetry_process_fork(u32 parent_pid, u32 child_pid,
			       u64 clone_flags, const char *parent_comm,
			       const char *child_comm);
void ai_telemetry_process_exec(u32 pid, u32 uid, u32 gid, u32 euid, u32 egid,
			       const char *full_path);
void ai_telemetry_process_exit(u32 pid, int exit_code, int exit_signal,
			       u64 total_runtime_ns, const char *comm);
void ai_telemetry_process_kthread(u32 pid, const char *kthread_name);
void ai_telemetry_process_state(u32 pid, u32 old_state, u32 new_state, u16 cpu,
				const char *comm);
void ai_telemetry_process_priority(u32 pid, s32 old_prio, s32 new_prio,
				   s32 old_nice, s32 new_nice);
void ai_telemetry_process_name(u32 pid, const char *old_comm,
			       const char *new_comm);
void ai_telemetry_signal_generate(u32 from_pid, const char *from_comm,
				  u32 to_pid, const char *to_comm,
				  int signum, int sig_code);
void ai_telemetry_signal_deliver(u32 pid, int signum, u8 handler_type,
				 const char *comm);
void ai_telemetry_signal_abnormal(u32 pid, int signum, unsigned long fault_addr,
				  const char *comm);
void ai_telemetry_cred_change(u32 pid, u32 old_uid, u32 new_uid,
			      u32 old_gid, u32 new_gid, u32 old_euid,
			      u32 new_euid, u32 old_egid, u32 new_egid,
			      const char *comm);
void ai_telemetry_ns_change(u32 pid, u64 ns_type_flags, const char *comm);
void ai_telemetry_cgroup_attach(u32 pid, const char *comm,
				const char *cgroup_path);
void ai_telemetry_cgroup_limit_hit(const char *cgroup_path,
				   const char *resource, u64 limit, u64 usage);
void ai_telemetry_process_rusage(u32 pid, u64 utime_us, u64 stime_us,
				 u32 minflt, u32 majflt, u32 nvcsw,
				 u32 nivcsw, u32 rss_kb, u32 vsz_kb,
				 const char *comm);
void ai_telemetry_process_io_stats(u32 pid, u64 rchar, u64 wchar,
				   u64 read_bytes, u64 write_bytes,
				   const char *comm);
void ai_telemetry_process_fd_list(u32 pid, u32 fd_count,
				  const u8 *fd_details, u16 detail_len,
				  const char *comm);
void ai_telemetry_futex_wait(u32 pid, u64 addr, u32 val,
			     u64 wait_duration_us, const char *comm);
void ai_telemetry_futex_wake(u32 pid, u64 addr, u32 woken_count,
			     const char *comm);

/* ---- 第15类：用户行为 ---- */

void ai_telemetry_user_session(u32 uid, u32 pid, u64 login_time_ns,
			       const char *tty_name, const char *comm);
void ai_telemetry_app_launch(u32 uid, u32 pid, const char *full_path,
			     u16 cmdline_len, const u8 *cmdline,
			     u16 cwd_len, const u8 *cwd);
void ai_telemetry_app_lifetime(const char *full_path, u64 total_runtime_s,
			       int exit_code);
void ai_telemetry_app_crash(u32 pid, const char *full_path,
			    const char *signal_name);
void ai_telemetry_user_active(u32 uid);
void ai_telemetry_user_idle(u64 idle_duration_s, const char *reason);
void ai_telemetry_focus_window(const char *tty_name, u32 pid,
			       const char *title, const char *klass,
			       u64 duration_ns);
void ai_telemetry_syscall_frequency(u32 nr, u32 count_per_sec,
				    const char *name);
void ai_telemetry_syscall_sequence(u32 pid, const u32 *seq, u16 n,
				   const char *comm);
void ai_telemetry_syscall_error_cluster(u32 pid, u32 nr, s32 errno_val,
					u32 consecutive_count,
					const char *comm);
void ai_telemetry_gpu_usage(u32 pid, u32 gpu_id, u32 utilization_pct,
			    u32 mem_used_mb);
void ai_telemetry_gpu_compute(u32 pid, u32 gpu_id, const char *kernel_name,
			      u64 duration_us);

/**
 * ai_proc_input_event() - 输入子系统状态机入口
 * @device:     设备名（dev->name）
 * @type:       EV_KEY / EV_REL / EV_ABS
 * @code:       事件码（KEY_x / REL_x / ABS_x）
 * @value:      事件值
 * @is_pointer: 设备是否为指针设备（键盘按钮 vs 鼠标按钮区分）
 *
 * 由 drivers/input/input.c input_handle_event() 调用（event_lock + irq 关闭
 * 上下文，无锁无睡眠）。内部维护 per-CPU 按键序列/组合键/鼠标位置/触摸状态，
 * 发射 key_event/sequence/combo、mouse_move/button/scroll、touch_event。
 */
void ai_proc_input_event(const char *device, unsigned int type,
			 unsigned int code, int value, bool is_pointer);

/**
 * ai_proc_tty_input_focus() - tty 输入 → 焦点窗口跟踪
 * @tty_name: tty 名
 * @fg_pid:   前台进程组 pid（0=无）
 * @fg_comm:  前台进程 comm
 *
 * 由 n_tty 输入路径调用。内部维护 8 槽 tty 焦点表，发射
 * user_focus_window（window_title=fg_comm 基础版）。
 */
void ai_proc_tty_input_focus(const char *tty_name, u32 fg_pid,
			     const char *fg_comm);

#else /* !CONFIG_AIKERNEL_TELEMETRY */

static inline void ai_telemetry_tty_input(const char *t, const u8 *r, u16 l) {}
static inline void ai_telemetry_tty_output(const char *t, const u8 *r, u16 l) {}
static inline void ai_telemetry_tty_line_discipline(const char *t, int o, int n) {}
static inline void ai_telemetry_input_key_event(const char *d, u16 k, u8 p,
						u64 ts, const char *n) {}
static inline void ai_telemetry_input_key_sequence(const char *d,
						   const struct ai_key_pair *p,
						   u16 n, u64 dur) {}
static inline void ai_telemetry_input_key_combo(const char *d, const u16 *k,
						u16 n, u32 dur) {}
static inline void ai_telemetry_input_mouse_move(const char *d, s16 dx, s16 dy,
						 s16 x, s16 y, u64 ts) {}
static inline void ai_telemetry_input_mouse_button(const char *d, u16 b, u8 p,
						   s16 x, s16 y, u64 ts) {}
static inline void ai_telemetry_input_mouse_scroll(const char *d, s16 dx, s16 dy) {}
static inline void ai_telemetry_input_touch_event(const char *d, u16 x, u16 y,
						  u16 p, u8 t, u8 c, u64 ts) {}
static inline bool ai_telemetry_syscall_entry(u32 n, const char *nm,
					      u64 a0, u64 a1, u64 a2, u64 a3,
					      u64 a4, u64 a5, u64 *ets)
{
	if (ets)
		*ets = 0;
	return false;
}
static inline void ai_telemetry_syscall_exit(u32 n, s64 r, u64 ets,
					     bool sampled) {}
static inline void ai_telemetry_exec_command(u32 p, u32 pp, u16 ac,
					     const u8 *cl, u16 cll,
					     const u8 *es, u16 el) {}
static inline void ai_telemetry_shell_command(const char *s, u16 cll,
					      const u8 *cl, u16 cwl,
					      const u8 *cw) {}
static inline void ai_telemetry_script_exec(const char *i, const char *sp,
					    const u8 *c, u16 l) {}
static inline void ai_telemetry_process_fork(u32 pp, u32 cp, u64 cf,
					     const char *pc, const char *cc) {}
static inline void ai_telemetry_process_exec(u32 p, u32 u, u32 g, u32 eu,
					     u32 eg, const char *fp) {}
static inline void ai_telemetry_process_exit(u32 p, int ec, int es, u64 tr,
					     const char *c) {}
static inline void ai_telemetry_process_kthread(u32 p, const char *n) {}
static inline void ai_telemetry_process_state(u32 p, u32 o, u32 n, u16 c,
					      const char *cm) {}
static inline void ai_telemetry_process_priority(u32 p, s32 o, s32 n,
						 s32 on, s32 nn) {}
static inline void ai_telemetry_process_name(u32 p, const char *o,
					     const char *n) {}
static inline void ai_telemetry_signal_generate(u32 fp, const char *fc,
						u32 tp, const char *tc,
						int s, int c) {}
static inline void ai_telemetry_signal_deliver(u32 p, int s, u8 ht,
					       const char *c) {}
static inline void ai_telemetry_signal_abnormal(u32 p, int s,
						unsigned long fa,
						const char *c) {}
static inline void ai_telemetry_cred_change(u32 p, u32 ou, u32 nu, u32 og,
					    u32 ng, u32 oeu, u32 neu,
					    u32 oeg, u32 neg, const char *c) {}
static inline void ai_telemetry_ns_change(u32 p, u64 nsf, const char *c) {}
static inline void ai_telemetry_cgroup_attach(u32 p, const char *c,
					      const char *cp) {}
static inline void ai_telemetry_cgroup_limit_hit(const char *cp,
						 const char *r, u64 l, u64 u) {}
static inline void ai_telemetry_process_rusage(u32 p, u64 ut, u64 st, u32 mf,
					       u32 mj, u32 nc, u32 ni,
					       u32 rk, u32 vk, const char *c) {}
static inline void ai_telemetry_process_io_stats(u32 p, u64 rc, u64 wc,
						 u64 rb, u64 wb, const char *c) {}
static inline void ai_telemetry_process_fd_list(u32 p, u32 fc,
						const u8 *fd, u16 dl,
						const char *c) {}
static inline void ai_telemetry_futex_wait(u32 p, u64 a, u32 v, u64 d,
					   const char *c) {}
static inline void ai_telemetry_futex_wake(u32 p, u64 a, u32 w, const char *c) {}
static inline void ai_telemetry_user_session(u32 u, u32 p, u64 lt,
					     const char *t, const char *c) {}
static inline void ai_telemetry_app_launch(u32 u, u32 p, const char *fp,
					   u16 cll, const u8 *cl,
					   u16 cwl, const u8 *cw) {}
static inline void ai_telemetry_app_lifetime(const char *fp, u64 tr, int ec) {}
static inline void ai_telemetry_app_crash(u32 p, const char *fp,
					  const char *sn) {}
static inline void ai_telemetry_user_active(u32 u) {}
static inline void ai_telemetry_user_idle(u64 d, const char *r) {}
static inline void ai_telemetry_focus_window(const char *t, u32 p,
					     const char *ti, const char *k,
					     u64 d) {}
static inline void ai_telemetry_syscall_frequency(u32 n, u32 c, const char *nm) {}
static inline void ai_telemetry_syscall_sequence(u32 p, const u32 *s, u16 n,
						 const char *c) {}
static inline void ai_telemetry_syscall_error_cluster(u32 p, u32 n, s32 e,
						      u32 cc, const char *c) {}
static inline void ai_telemetry_gpu_usage(u32 p, u32 g, u32 u, u32 m) {}
static inline void ai_telemetry_gpu_compute(u32 p, u32 g, const char *k, u64 d) {}
static inline void ai_proc_input_event(const char *d, unsigned int t,
				       unsigned int c, int v, bool ip) {}
static inline void ai_proc_tty_input_focus(const char *t, u32 fp,
					   const char *fc) {}

#endif /* CONFIG_AIKERNEL_TELEMETRY */

#endif /* _AIKERNEL_AI_PROC_H */
