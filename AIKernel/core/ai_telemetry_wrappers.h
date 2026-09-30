// SPDX-License-Identifier: GPL-2.0
/*
 * ai_telemetry_wrappers.h - AIKernel 101 子类类型化发射占位（static inline 骨架）
 *
 * 职责一句话：为每个大类/子类提供命名包装 ai_telemetry_<大类>_<事件>()
 * （统一签名 u8 severity, const void *data, u16 data_len），转发到
 * ai_telemetry_emit()；CONFIG_AIKERNEL_TELEMETRY=n 时随 emit 空函数整体
 * 被编译器优化掉。
 *
 * 拆分说明：本头文件由原 ai_telemetry.h（837 行）的 101 子类包装段
 * （395-655 行）逐字拆出，仅被 ai_telemetry.h 在核心 API 之后 include；
 * 对外仍只需 include ai_telemetry.h 即可获得全部原名，接口集合不变。
 */

#ifndef _AIKERNEL_AI_TELEMETRY_WRAPPERS_H
#define _AIKERNEL_AI_TELEMETRY_WRAPPERS_H


/* ---- 101 子类埋点占位（static inline 骨架） ----
 *
 * 每个大类为每个子类提供一个命名包装，转发到 ai_telemetry_emit()。
 * 本步只建骨架：具体字段提取逻辑从 Prompt 03 起逐模块填入各子系统。
 * CONFIG_AIKERNEL_TELEMETRY=n 时全部为空函数，编译器整体优化掉。
 * 签名统一：int ai_telemetry_<大类>_<事件>(u8 severity, const void *data, u16 data_len)
 */

/* 01 CPU 与调度 */
static inline int ai_telemetry_sched_switch(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_SCHED_CTX_SWITCH, s, d, l); }
static inline int ai_telemetry_sched_wakeup(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_SCHED_CTX_SWITCH, s, d, l); }
static inline int ai_telemetry_sched_wakeup_new(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_SCHED_CTX_SWITCH, s, d, l); }
static inline int ai_telemetry_sched_migrate(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_SCHED_CTX_SWITCH, s, d, l); }
static inline int ai_telemetry_sched_latency(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_SCHED_LATENCY, s, d, l); }
static inline int ai_telemetry_cpu_load(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_CPU_LOAD, s, d, l); }
static inline int ai_telemetry_pelt(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_PELT, s, d, l); }
static inline int ai_telemetry_rq_depth(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_RQ_DEPTH, s, d, l); }
static inline int ai_telemetry_psi(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_PSI, s, d, l); }
static inline int ai_telemetry_cpu_hotplug(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_CPU_HOTPLUG, s, d, l); }
static inline int ai_telemetry_sched_domain(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SCHED, AI_EV_SCHED_DOMAIN, s, d, l); }

/* 02 内存管理 */
static inline int ai_telemetry_page_alloc(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_PAGE_ALLOC, s, d, l); }
static inline int ai_telemetry_slab_alloc(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_SLAB_ALLOC, s, d, l); }
static inline int ai_telemetry_page_fault(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_PAGE_FAULT, s, d, l); }
static inline int ai_telemetry_reclaim(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_RECLAIM, s, d, l); }
static inline int ai_telemetry_workingset(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_WORKINGSET, s, d, l); }
static inline int ai_telemetry_page_cache(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_PAGE_CACHE, s, d, l); }
static inline int ai_telemetry_thp(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_THP, s, d, l); }
static inline int ai_telemetry_compaction(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_COMPACTION, s, d, l); }
static inline int ai_telemetry_oom(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_OOM, s, d, l); }
static inline int ai_telemetry_mem_error(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_MM, AI_EV_MEM_ERROR, s, d, l); }

/* 03 I/O 与存储 */
static inline int ai_telemetry_bio(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_IO, AI_EV_BIO, s, d, l); }
static inline int ai_telemetry_blk_mq(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_IO, AI_EV_BLK_MQ, s, d, l); }
static inline int ai_telemetry_io_sched(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_IO, AI_EV_IO_SCHED, s, d, l); }
static inline int ai_telemetry_io_qos(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_IO, AI_EV_IO_QOS, s, d, l); }
static inline int ai_telemetry_disk_stats(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_IO, AI_EV_DISK_STATS, s, d, l); }
static inline int ai_telemetry_char_dev(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_IO, AI_EV_CHAR_DEV, s, d, l); }

/* 04 网络 */
static inline int ai_telemetry_socket(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_SOCKET, s, d, l); }
static inline int ai_telemetry_tcp(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_TCP, s, d, l); }
static inline int ai_telemetry_udp(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_UDP, s, d, l); }
static inline int ai_telemetry_ip(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_IP, s, d, l); }
static inline int ai_telemetry_netfilter(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_NETFILTER, s, d, l); }
static inline int ai_telemetry_xdp(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_XDP, s, d, l); }
static inline int ai_telemetry_tc(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_TC, s, d, l); }
static inline int ai_telemetry_dns(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_DNS, s, d, l); }
static inline int ai_telemetry_http_tls(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_HTTP_TLS, s, d, l); }
static inline int ai_telemetry_netdev(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_NET, AI_EV_NETDEV, s, d, l); }

/* 05 用户输入 */
static inline int ai_telemetry_tty(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_TTY, s, d, l); }
static inline int ai_telemetry_input_key(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_INPUT_KEY, s, d, l); }
static inline int ai_telemetry_input_pointer(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_INPUT_POINTER, s, d, l); }
static inline int ai_telemetry_syscall(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_SYSCALL, s, d, l); }
static inline int ai_telemetry_exec(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_EXEC, s, d, l); }

/* 06 进程与线程 */
static inline int ai_telemetry_process_life(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_LIFE, s, d, l); }
static inline int ai_telemetry_process_state_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_STATE, s, d, l); }
static inline int ai_telemetry_signal(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_SIGNAL, s, d, l); }
static inline int ai_telemetry_cred(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_CRED, s, d, l); }
static inline int ai_telemetry_cgroup(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_CGROUP, s, d, l); }
static inline int ai_telemetry_rusage(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_RUSAGE, s, d, l); }
static inline int ai_telemetry_futex(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_FUTEX, s, d, l); }

/* 07 文件系统（通用原始发射骨架；子事件类型化发射见 AIKernel/vfs/ai_vfs.h。
 * 为避免命名冲突，path_lookup/mount/fs_error 三个同名骨架加 _raw 后缀，
 * 类型化发射辅助 ai_telemetry_path_lookup()/mount()/fs_error() 由 Prompt 08
 * 在 ai_vfs.h 落地（本骨架无调用者，改名零影响）。） */
static inline int ai_telemetry_vfs(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_FS, AI_EV_VFS, s, d, l); }
static inline int ai_telemetry_path_lookup_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_FS, AI_EV_PATH_LOOKUP, s, d, l); }
static inline int ai_telemetry_mount_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_FS, AI_EV_MOUNT, s, d, l); }
static inline int ai_telemetry_file_lock(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_FS, AI_EV_FILE_LOCK, s, d, l); }
static inline int ai_telemetry_epoll(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_FS, AI_EV_EPOLL, s, d, l); }
static inline int ai_telemetry_fs_error_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_FS, AI_EV_FS_ERROR, s, d, l); }

/* 08 安全事件 */
static inline int ai_telemetry_lsm(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SECURITY, AI_EV_LSM, s, d, l); }
static inline int ai_telemetry_seccomp(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SECURITY, AI_EV_SECCOMP, s, d, l); }
static inline int ai_telemetry_capability(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SECURITY, AI_EV_CAPABILITY, s, d, l); }
static inline int ai_telemetry_audit(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SECURITY, AI_EV_AUDIT, s, d, l); }
static inline int ai_telemetry_key(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SECURITY, AI_EV_KEY, s, d, l); }
static inline int ai_telemetry_crypto(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SECURITY, AI_EV_CRYPTO, s, d, l); }
static inline int ai_telemetry_mem_detect(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SECURITY, AI_EV_MEM_DETECT, s, d, l); }
static inline int ai_telemetry_hardening(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_SECURITY, AI_EV_HARDENING, s, d, l); }

/* 18 AI 自我观测（Prompt 13：决策/结果事件，payload 见 ai_policy.h） */
static inline int ai_telemetry_ai_decision(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_DECISION, s, d, l); }
static inline int ai_telemetry_ai_outcome(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_OUTCOME, s, d, l); }

/* 09 中断与异常 */
static inline int ai_telemetry_irq(u8 s, const void *d, u16 l){ return ai_telemetry_emit(AI_CAT_INTERRUPT, AI_EV_IRQ, s, d, l); }
static inline int ai_telemetry_exception(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_INTERRUPT, AI_EV_EXCEPTION, s, d, l); }
static inline int ai_telemetry_irq_balance(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_INTERRUPT, AI_EV_IRQ_BALANCE, s, d, l); }
static inline int ai_telemetry_nmi_watchdog(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_INTERRUPT, AI_EV_NMI_WATCHDOG, s, d, l); }
static inline int ai_telemetry_softirq(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_INTERRUPT, AI_EV_SOFTIRQ, s, d, l); }

/* 10 锁竞争与同步 */
static inline int ai_telemetry_mutex(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_LOCK, AI_EV_MUTEX, s, d, l); }
static inline int ai_telemetry_spinlock(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_LOCK, AI_EV_SPINLOCK, s, d, l); }
static inline int ai_telemetry_rwsem(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_LOCK, AI_EV_RWSEM, s, d, l); }
static inline int ai_telemetry_rtmutex(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_LOCK, AI_EV_RTMUTEX, s, d, l); }

/* 11 时间与定时器 */
static inline int ai_telemetry_timer(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_TIME, AI_EV_TIMER, s, d, l); }
static inline int ai_telemetry_hrtimer(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_TIME, AI_EV_HRTIMER, s, d, l); }
static inline int ai_telemetry_clocksource(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_TIME, AI_EV_CLOCKSOURCE, s, d, l); }
static inline int ai_telemetry_delay(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_TIME, AI_EV_DELAY, s, d, l); }

/* 12 电源管理 */
static inline int ai_telemetry_cpufreq(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_POWER, AI_EV_CPUFREQ, s, d, l); }
static inline int ai_telemetry_cpuidle(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_POWER, AI_EV_CPUIDLE, s, d, l); }
static inline int ai_telemetry_suspend(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_POWER, AI_EV_SUSPEND, s, d, l); }
static inline int ai_telemetry_runtime_pm(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_POWER, AI_EV_RUNTIME_PM, s, d, l); }
static inline int ai_telemetry_thermal(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_POWER, AI_EV_THERMAL, s, d, l); }

/* 13 虚拟化 */
static inline int ai_telemetry_vcpu(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_VIRT, AI_EV_VCPU, s, d, l); }
static inline int ai_telemetry_guest_mem(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_VIRT, AI_EV_GUEST_MEM, s, d, l); }
static inline int ai_telemetry_kvm_exit(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_VIRT, AI_EV_KVM_EXIT, s, d, l); }
static inline int ai_telemetry_virtio(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_VIRT, AI_EV_VIRTIO, s, d, l); }
static inline int ai_telemetry_hypercall(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_VIRT, AI_EV_HYPERCALL, s, d, l); }

/* 14 BPF/Tracing/Perf */
static inline int ai_telemetry_bpf_prog(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_BPF, AI_EV_BPF_PROG, s, d, l); }
static inline int ai_telemetry_bpf_map(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_BPF, AI_EV_BPF_MAP, s, d, l); }
static inline int ai_telemetry_tracing(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_BPF, AI_EV_TRACING, s, d, l); }
static inline int ai_telemetry_perf(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_BPF, AI_EV_PERF, s, d, l); }

/* 15 用户行为 */
static inline int ai_telemetry_user_session_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_USER_SESSION, s, d, l); }
static inline int ai_telemetry_user_activity(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_USER_ACTIVITY, s, d, l); }
static inline int ai_telemetry_syscall_pattern(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_SYSCALL_PATTERN, s, d, l); }
static inline int ai_telemetry_mem_pattern(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_MEM_PATTERN, s, d, l); }
static inline int ai_telemetry_net_pattern(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_NET_PATTERN, s, d, l); }
static inline int ai_telemetry_gpu(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_GPU, s, d, l); }

/* 16 硬件与驱动（通用原始发射骨架；类型化发射函数见下
 * ai_telemetry_hw_error()/device_evt()/dma_evt()/nmi_evt()/platform_evt()
 * ——Prompt 15 落地，原名加 _raw 后缀避免冲突） */
static inline int ai_telemetry_device_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_HW, AI_EV_DEVICE, s, d, l); }
static inline int ai_telemetry_driver_pm_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_HW, AI_EV_DRIVER_PM, s, d, l); }
static inline int ai_telemetry_hw_error_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_HW, AI_EV_HW_ERROR, s, d, l); }
static inline int ai_telemetry_dma_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_HW, AI_EV_DMA, s, d, l); }
static inline int ai_telemetry_pci_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_HW, AI_EV_PCI, s, d, l); }

/* 17 内核构建与配置（通用原始发射骨架；类型化发射函数见下
 * ai_telemetry_config_change_evt()/module_evt()/sysctl_evt()） */
static inline int ai_telemetry_config_change_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_KCONFIG, AI_EV_CONFIG_CHANGE, s, d, l); }
static inline int ai_telemetry_sysctl_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_KCONFIG, AI_EV_SYSCTL, s, d, l); }
static inline int ai_telemetry_build_raw(u8 s, const void *d, u16 l)
{ return ai_telemetry_emit(AI_CAT_KCONFIG, AI_EV_BUILD, s, d, l); }


#endif /* _AIKERNEL_AI_TELEMETRY_WRAPPERS_H */
