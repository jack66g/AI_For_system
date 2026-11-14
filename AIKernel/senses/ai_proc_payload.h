// SPDX-License-Identifier: GPL-2.0
/*
 * ai_proc_payload.h - AIKernel B 轨遥测 payload 结构定义（第5/6/15类）
 *
 * 职责一句话：进程/用户感知遥测的类型化 payload 结构（第5类用户输入、
 * 第6类进程与线程、第15类用户行为，首字段 type 常量，全量原始零脱敏）。
 *
 * 拆分说明：本头文件由原 ai_proc.h（880 行）的 payload 结构段（77-475 行）
 * 逐字拆出，仅被 ai_proc.h include；对外仍只需 include ai_proc.h 即可获得
 * 全部原名，接口集合不变。A 轨结构（ai_proc_slot/ai_proc_info/ai_proc_stats）
 * 与函数声明仍留在 ai_proc.h。
 */

#ifndef _AIKERNEL_AI_PROC_PAYLOAD_H
#define _AIKERNEL_AI_PROC_PAYLOAD_H

#include <linux/types.h>
#include <linux/sched.h>	/* TASK_COMM_LEN */

/* ==================================================================
 * B 轨 payload 结构（第5类 用户输入）
 * ================================================================== */

/* 05.01 tty_input：终端输入完整内容（零脱敏） */
struct ai_tty_input_payload {
	u8  type;                    /* 1=tty_input 2=tty_output */
	char tty_name[64];
	u16 data_len;
	u8  data[];                  /* raw 字节（原始内容，非字符语义化） */
};

/* 05.01 tty_output：终端输出采样 */
struct ai_tty_output_payload {
	u8  type;                    /* 2=tty_output */
	char tty_name[64];
	u16 data_len;
	u8  data[];
};

/* 05.01 tty_line_discipline：线路规程切换 */
struct ai_tty_ldisc_payload {
	u8  type;                    /* 3=tty_line_discipline */
	char tty_name[64];
	int old_ldisc, new_ldisc;
};

/* 05.02 input_key_event：每个按键全量 */
struct ai_input_key_payload {
	u8  type;                    /* 1=key_event 2=key_sequence 3=key_combo */
	char device[64];
	u16 keycode;
	u8  pressed;                 /* 1=按下 0=释放 2=重复 */
	u64 event_ts_ns;             /* 事件自身纳秒时间戳 */
	char key_name[24];
};

/* 05.02 input_key_sequence：按键序列完整内容 */
struct ai_input_key_seq_payload {
	u8  type;                    /* 2=key_sequence */
	char device[64];
	u16 n_keys;
	u64 duration_ns;             /* 序列总时长 */
	u16 typing_speed_keys_per_s; /* 键入速度（键/秒） */
	/* 后随 n_keys 个 {u16 keycode; u16 delay_ms;} 对（raw_sequence） */
};

/* 05.02 input_key_combo：组合键 */
struct ai_input_key_combo_payload {
	u8  type;                    /* 3=key_combo */
	char device[64];
	u16 n_keys;
	u32 duration_ms;
	u16 keys[8];                 /* 组合键 keycode 集合 */
};

/* 05.03 input_mouse_move：轨迹 */
struct ai_input_mouse_payload {
	u8  type;                    /* 1=move 2=button 3=scroll */
	char device[64];
	s16 dx, dy;
	s16 x, y;                    /* 累计位置（per-CPU 跟踪） */
	u64 event_ts_ns;
};

/* 05.03 input_mouse_button */
struct ai_input_btn_payload {
	u8  type;                    /* 2=button */
	char device[64];
	u16 button;
	u8  pressed;
	s16 x, y;
	u64 event_ts_ns;
};

/* 05.03 input_mouse_scroll */
struct ai_input_scroll_payload {
	u8  type;                    /* 3=scroll */
	char device[64];
	s16 dx, dy;
};

/* 05.03 input_touch_event */
struct ai_input_touch_payload {
	u8  type;                    /* 4=touch */
	char device[64];
	u16 x, y;
	u16 pressure;
	u8  touch_type;              /* 1=down 2=move 3=up */
	u8  contact_count;
	u64 event_ts_ns;
};

/* 05.04 syscall_entry：系统调用全量参数（采样） */
struct ai_syscall_entry_payload {
	u8  type;                    /* 1=entry 2=exit */
	u32 syscall_nr;
	char syscall_name[32];
	u64 arg0, arg1, arg2, arg3, arg4, arg5;
};

/* 05.04 syscall_exit */
struct ai_syscall_exit_payload {
	u8  type;                    /* 2=exit */
	u32 syscall_nr;
	s64 retval;
	u64 latency_ns;
};

/* 05.05 exec_command：完整命令行与环境变量采样 */
struct ai_exec_command_payload {
	u8  type;                    /* 1=exec_command 2=shell_command 3=script_exec */
	u32 pid, ppid;
	u16 argc;
	u16 full_cmdline_len;
	/* full_cmdline（argv 全量，NUL 分隔）后随 envp_sample（"K=V" NUL 分隔） */
	u8  data[];
};

/* 05.05 shell_command：Shell 命令完整内容 */
struct ai_shell_command_payload {
	u8  type;                    /* 2=shell_command */
	char shell[32];
	u16 cmdline_len;
	u16 cwd_len;
	u8  data[];                  /* cmdline + cwd（NUL 分隔） */
};

/* 05.05 script_exec：脚本执行内容采样 */
struct ai_script_exec_payload {
	u8  type;                    /* 3=script_exec */
	char interpreter[32];
	char script_path[256];
	u16 content_len;
	u8  content[];               /* bprm->buf 前 256B 原始内容 */
};

/* ==================================================================
 * B 轨 payload 结构（第6类 进程与线程）
 * ================================================================== */

/* 06.01 process_fork */
struct ai_process_fork_payload {
	u8  type;                    /* 1=fork 2=exec 3=exit 4=kthread */
	u32 parent_pid, child_pid;
	u64 clone_flags;
	u8  child_class;             /* AI 分类（enum ai_proc_class） */
	char parent_comm[TASK_COMM_LEN];
	char child_comm[TASK_COMM_LEN];
};

/* 06.01 process_exec */
struct ai_process_exec_payload {
	u8  type;                    /* 2=exec */
	u32 pid;
	u32 uid, gid, euid, egid;
	char full_path[256];
};

/* 06.01 process_exit */
struct ai_process_exit_payload {
	u8  type;                    /* 3=exit */
	u32 pid;
	int exit_code, exit_signal;
	u64 total_runtime_ns;
	char comm[TASK_COMM_LEN];
};

/* 06.01 process_kthread */
struct ai_process_kthread_payload {
	u8  type;                    /* 4=kthread */
	u32 pid;
	char kthread_name[TASK_COMM_LEN];
};

/* 06.02 process_state */
struct ai_process_state_payload {
	u8  type;                    /* 1=state 2=priority 3=name */
	u32 pid;
	u32 old_state, new_state;
	u16 cpu;
	char comm[TASK_COMM_LEN];
};

/* 06.02 process_priority */
struct ai_process_prio_payload {
	u8  type;                    /* 2=priority */
	u32 pid;
	s32 old_prio, new_prio;
	s32 old_nice, new_nice;
};

/* 06.02 process_name */
struct ai_process_name_payload {
	u8  type;                    /* 3=name */
	u32 pid;
	char old_comm[TASK_COMM_LEN];
	char new_comm[TASK_COMM_LEN];
};

/* 06.03 signal_generate */
struct ai_signal_gen_payload {
	u8  type;                    /* 1=generate 2=deliver 3=abnormal */
	u32 from_pid, to_pid;
	int signum;
	int sig_code;
	unsigned long fault_addr;
	char from_comm[TASK_COMM_LEN];
	char to_comm[TASK_COMM_LEN];
	char sig_name[16];
};

/* 06.03 signal_deliver（handler_type 并入 type 字段外的 sig_name 语义） */
struct ai_signal_deliver_payload {
	u8  type;                    /* 2=deliver */
	u32 pid;
	int signum;
	u8  handler_type;            /* 0=IGN 1=DFL 2=USER */
	char sig_name[16];
	char comm[TASK_COMM_LEN];
};

/* 06.03 signal_abnormal */
struct ai_signal_abnormal_payload {
	u8  type;                    /* 3=abnormal */
	u32 pid;
	int signum;
	unsigned long fault_addr;
	char sig_name[16];
	char comm[TASK_COMM_LEN];
};

/* 06.04 cred_change */
struct ai_cred_change_payload {
	u8  type;                    /* 1=cred 2=ns */
	u32 pid;
	u32 old_uid, new_uid, old_gid, new_gid;
	u32 old_euid, new_euid, old_egid, new_egid;
	char comm[TASK_COMM_LEN];
};

/* 06.04 ns_change */
struct ai_ns_change_payload {
	u8  type;                    /* 2=ns */
	u32 pid;
	u64 ns_type_flags;           /* CLONE_NEW* 位集合 */
	char comm[TASK_COMM_LEN];
};

/* 06.05 cgroup_attach */
struct ai_cgroup_attach_payload {
	u8  type;                    /* 1=attach 2=limit_hit */
	u32 pid;
	char comm[TASK_COMM_LEN];
	char cgroup_path[256];
	char subsys[16];
};

/* 06.05 cgroup_limit_hit */
struct ai_cgroup_limit_payload {
	u8  type;                    /* 2=limit_hit */
	char cgroup_path[256];
	char resource[16];
	u64 limit, usage;
};

/* 06.06 process_rusage */
struct ai_process_rusage_payload {
	u8  type;                    /* 1=rusage 2=io_stats 3=fd_list */
	u32 pid;
	u64 utime_us, stime_us;
	u32 minflt, majflt, nvcsw, nivcsw;
	u32 rss_kb, vsz_kb;
	char comm[TASK_COMM_LEN];
};

/* 06.06 process_io_stats */
struct ai_process_io_payload {
	u8  type;                    /* 2=io_stats */
	u32 pid;
	u64 rchar, wchar, read_bytes, write_bytes;
	char comm[TASK_COMM_LEN];
};

/* 06.06 process_fd_list */
struct ai_process_fd_payload {
	u8  type;                    /* 3=fd_list */
	u32 pid;
	u32 fd_count;
	u8  fd_details[256];         /* "fd:type:path\n" 文本，前 8 个 fd，零脱敏 */
	char comm[TASK_COMM_LEN];
};

/* 06.07 futex_wait */
struct ai_futex_wait_payload {
	u8  type;                    /* 1=wait 2=wake */
	u32 pid;
	u64 addr;
	u32 val;
	u64 wait_duration_us;
	char comm[TASK_COMM_LEN];
};

/* 06.07 futex_wake */
struct ai_futex_wake_payload {
	u8  type;                    /* 2=wake */
	u32 pid;
	u64 addr;
	u32 woken_count;
	char comm[TASK_COMM_LEN];
};

/* ==================================================================
 * B 轨 payload 结构（第15类 用户行为）
 * ================================================================== */

/* 15.01 user_session */
struct ai_user_session_payload {
	u8  type;                    /* 1=session */
	u32 uid, pid;
	u64 login_time_ns;
	char tty_name[64];
	char comm[TASK_COMM_LEN];
};

/* 15.01 app_launch（exec_command 同源，携带 cwd/env 摘要） */
struct ai_app_launch_payload {
	u8  type;                    /* 1=launch 2=lifetime 3=crash */
	u32 uid, pid;
	char full_path[256];
	u16 cmdline_len;
	u16 cwd_len;
	u8  data[];                  /* cmdline + cwd（NUL 分隔） */
};

/* 15.01 app_lifetime */
struct ai_app_lifetime_payload {
	u8  type;                    /* 2=lifetime */
	char full_path[256];
	u64 total_runtime_s;
	int exit_code;
};

/* 15.01 app_crash */
struct ai_app_crash_payload {
	u8  type;                    /* 3=crash */
	u32 pid;
	char full_path[256];
	char signal_name[16];
};

/* 15.02 user_focus_window（基础版：tty + fg pgrp comm） */
struct ai_focus_payload {
	u8  type;                    /* 1=active 2=idle 3=focus */
	u32 uid, pid;
	u64 duration_ns;
	char window_title[128];      /* 基础版 = fg comm */
	char window_class[64];
	char tty_name[64];
};

/* 15.03 syscall_frequency */
struct ai_syscall_freq_payload {
	u8  type;                    /* 1=frequency 2=sequence 3=error_cluster */
	u32 syscall_nr;
	u32 count_per_sec;
	char syscall_name[32];
};

/* 15.03 syscall_sequence（完整序列无哈希） */
struct ai_syscall_seq_payload {
	u8  type;                    /* 2=sequence */
	u32 pid;
	u16 n;                       /* 序列长度 */
	char comm[TASK_COMM_LEN];
	u32 seq[64];                 /* 完整 syscall 序列 */
};

/* 15.03 syscall_error_cluster */
struct ai_syscall_err_payload {
	u8  type;                    /* 3=error_cluster */
	u32 pid;
	u32 syscall_nr;
	s32 errno_val;
	u32 consecutive_count;
	char syscall_name[32];
	char comm[TASK_COMM_LEN];
};

/* 15.06 gpu_usage / gpu_compute（接口占位） */
struct ai_gpu_payload {
	u8  type;                    /* 1=usage 2=compute */
	u32 pid;
	u32 gpu_id;
	u32 utilization_pct;
	u32 mem_used_mb;
	char kernel_name[64];
	u64 duration_us;
};

#endif /* _AIKERNEL_AI_PROC_PAYLOAD_H */
