// SPDX-License-Identifier: GPL-2.0
/*
 * ai_telemetry.h - AIKernel 遥测采集核心（AI 的感官神经系统）
 *
 * 全系统唯一的 AI 感知写入入口：ai_telemetry_emit()。
 * 所有子系统埋点（Prompt 03 起逐模块落进内核）最终都汇聚到
 * per-CPU ring buffer（每 CPU 128KB，无锁，单次写入 < 100ns）。
 *
 * 数据原则（all-ai）：记录携带 24B 定长头 + 原始数据，不脱敏、不哈希、不截断。
 *
 * 性能预算：
 *   单次写入      < 100ns（ktime_get_ns() + 两段 memcpy，无锁）
 *   CONFIG_AIKERNEL_TELEMETRY=n 时全部为 static inline 空函数，零开销零回归。
 *
 * 事件体系：17 大类（enum ai_category）~101 子类（enum ai_event_type），
 * 编号对齐《AIKernel_数据源与日志系统计划》01 CPU调度 ~ 17 内核配置。
 */

#ifndef _AIKERNEL_AI_TELEMETRY_H
#define _AIKERNEL_AI_TELEMETRY_H

#include "ai_types.h"
#include <linux/types.h>

/* ---- 常量 ---- */

#define AI_TELEMETRY_RING_SIZE     (128 * 1024)  /* 每 CPU ring buffer 128KB */
#define AI_TELEMETRY_MAX_DATA_LEN  4096          /* 原始数据最大长度（对齐计划 0-4096） */

/* ---- 严重级别 ---- */

enum ai_severity {
	AI_SEV_DEBUG      = 0,  /* 调试 */
	AI_SEV_NORMAL     = 1,  /* 常规 */
	AI_SEV_IMPORTANT  = 2,  /* 重要 */
	AI_SEV_CRITICAL   = 3,  /* 关键 */
};

/* ---- 记录结构（对齐数据计划 23.1 节，全量原始数据零脱敏） ---- */

struct ai_telemetry_record {
	u64 timestamp_ns;   /* 纳秒时间戳 */
	u32 pid, tgid;      /* 触发进程 */
	u16 cpu;            /* 触发 CPU */
	u8  category;       /* 大类（1~17） */
	u8  event_type;     /* 事件子类（1~101 全局唯一） */
	u8  severity;       /* 0=调试 1=常规 2=重要 3=关键 */
	u16 data_len;       /* 原始数据长度 0-4096 */
	/* 后随 data_len 字节原始数据，不脱敏不哈希 */
} __attribute__((packed));

/* 记录定长头字节数 = 23（8+4+4+2+1+1+1+2，packed；计划文档称 24B，以字段为准） */
#define AI_TELEMETRY_HEADER_LEN    (sizeof(struct ai_telemetry_record))

/* ---- 18 大类（Prompt 13 新增第18类：AI 自我观测——决策与结果） ---- */

enum ai_category {
	AI_CAT_SCHED        = 1,   /* 01 CPU与调度 */
	AI_CAT_MM           = 2,   /* 02 内存管理 */
	AI_CAT_IO           = 3,   /* 03 I/O与存储 */
	AI_CAT_NET          = 4,   /* 04 网络 */
	AI_CAT_USER_INPUT   = 5,   /* 05 用户输入 */
	AI_CAT_PROCESS      = 6,   /* 06 进程与线程 */
	AI_CAT_FS           = 7,   /* 07 文件系统 */
	AI_CAT_SECURITY     = 8,   /* 08 安全事件 */
	AI_CAT_INTERRUPT    = 9,   /* 09 中断与异常 */
	AI_CAT_LOCK         = 10,  /* 10 锁竞争与同步 */
	AI_CAT_TIME         = 11,  /* 11 时间与定时器 */
	AI_CAT_POWER        = 12,  /* 12 电源管理 */
	AI_CAT_VIRT         = 13,  /* 13 虚拟化 */
	AI_CAT_BPF          = 14,  /* 14 BPF/Tracing/Perf */
	AI_CAT_USER_BEHAVIOR = 15, /* 15 用户行为 */
	AI_CAT_HW           = 16,  /* 16 硬件与驱动 */
	AI_CAT_KCONFIG      = 17,  /* 17 内核构建与配置 */
	AI_CAT_AI           = 18,  /* 18 AI 自我观测（决策/结果，Prompt 13） */
};

/* ---- 101 子类事件（编号对齐数据计划：注释标注计划章节号） ---- */

enum ai_event_type {
	/* 01 CPU与调度（8） */
	AI_EV_SCHED_CTX_SWITCH = 1,   /* 01.01 上下文切换（switch/wakeup/migrate） */
	AI_EV_SCHED_LATENCY,          /* 01.02 调度延迟 */
	AI_EV_CPU_LOAD,               /* 01.03 CPU 负载（周期） */
	AI_EV_PELT,                   /* 01.04 PELT 负载跟踪 */
	AI_EV_RQ_DEPTH,               /* 01.05 运行队列状态 */
	AI_EV_PSI,                    /* 01.06 PSI 压力 */
	AI_EV_CPU_HOTPLUG,            /* 01.07 CPU 隔离与热插拔 */
	AI_EV_SCHED_DOMAIN,           /* 01.08 调度域拓扑 */

	/* 02 内存管理（10） */
	AI_EV_PAGE_ALLOC,             /* 02.01 页分配 */
	AI_EV_SLAB_ALLOC,             /* 02.02 Slab/Slub 分配 */
	AI_EV_PAGE_FAULT,             /* 02.03 缺页异常（全量） */
	AI_EV_RECLAIM,                /* 02.04 页面回收 */
	AI_EV_WORKINGSET,             /* 02.05 工作集检测 */
	AI_EV_PAGE_CACHE,             /* 02.06 页面缓存 */
	AI_EV_THP,                    /* 02.07 THP/大页 */
	AI_EV_COMPACTION,             /* 02.08 内存压缩与迁移 */
	AI_EV_OOM,                    /* 02.09 OOM */
	AI_EV_MEM_ERROR,              /* 02.10 内存错误与检测（全量） */

	/* 03 I/O与存储（6） */
	AI_EV_BIO,                    /* 03.01 块层 BIO */
	AI_EV_BLK_MQ,                 /* 03.02 blk-mq */
	AI_EV_IO_SCHED,               /* 03.03 I/O 调度器 */
	AI_EV_IO_QOS,                 /* 03.04 I/O 节流与 QoS */
	AI_EV_DISK_STATS,             /* 03.05 块设备状态（周期） */
	AI_EV_CHAR_DEV,               /* 03.06 字符设备 I/O */

	/* 04 网络（10） */
	AI_EV_SOCKET,                 /* 04.01 Socket 层 */
	AI_EV_TCP,                    /* 04.02 TCP 详细数据 */
	AI_EV_UDP,                    /* 04.03 UDP 数据 */
	AI_EV_IP,                     /* 04.04 IP 层 */
	AI_EV_NETFILTER,              /* 04.05 Netfilter 防火墙 */
	AI_EV_XDP,                    /* 04.06 XDP 快速路径 */
	AI_EV_TC,                     /* 04.07 流量控制 */
	AI_EV_DNS,                    /* 04.08 DNS 查询（全量） */
	AI_EV_HTTP_TLS,               /* 04.09 HTTP/TLS（采样） */
	AI_EV_NETDEV,                 /* 04.10 设备级网络 */

	/* 05 用户输入（5） */
	AI_EV_TTY,                    /* 05.01 TTY/终端输入（全量） */
	AI_EV_INPUT_KEY,              /* 05.02 键盘输入（全量） */
	AI_EV_INPUT_POINTER,          /* 05.03 鼠标/触摸输入 */
	AI_EV_SYSCALL,                /* 05.04 系统调用全量参数 */
	AI_EV_EXEC,                   /* 05.05 命令行和执行（全量） */

	/* 06 进程与线程（7） */
	AI_EV_PROCESS_LIFE,           /* 06.01 进程生命周期 */
	AI_EV_PROCESS_STATE,          /* 06.02 进程状态变化 */
	AI_EV_SIGNAL,                 /* 06.03 信号处理 */
	AI_EV_CRED,                   /* 06.04 凭证与权限 */
	AI_EV_CGROUP,                 /* 06.05 cgroup 事件 */
	AI_EV_RUSAGE,                 /* 06.06 资源使用统计（周期） */
	AI_EV_FUTEX,                  /* 06.07 Futex */

	/* 07 文件系统（6） */
	AI_EV_VFS,                    /* 07.01 VFS 操作（全量原始路径） */
	AI_EV_PATH_LOOKUP,            /* 07.02 路径解析 */
	AI_EV_MOUNT,                  /* 07.03 文件系统挂载 */
	AI_EV_FILE_LOCK,              /* 07.04 文件锁 */
	AI_EV_EPOLL,                  /* 07.05 epoll/事件通知 */
	AI_EV_FS_ERROR,               /* 07.06 文件系统错误 */

	/* 08 安全事件（8） */
	AI_EV_LSM,                    /* 08.01 LSM 钩子事件（全量） */
	AI_EV_SECCOMP,                /* 08.02 Seccomp */
	AI_EV_CAPABILITY,             /* 08.03 能力事件 */
	AI_EV_AUDIT,                  /* 08.04 审计事件 */
	AI_EV_KEY,                    /* 08.05 密钥操作 */
	AI_EV_CRYPTO,                 /* 08.06 加密操作 */
	AI_EV_MEM_DETECT,             /* 08.07 内存安全检测（训练金矿） */
	AI_EV_HARDENING,              /* 08.08 内核加固违规 */

	/* 09 中断与异常（5） */
	AI_EV_IRQ,                    /* 09.01 中断 */
	AI_EV_EXCEPTION,              /* 09.02 异常 */
	AI_EV_IRQ_BALANCE,            /* 09.03 中断均衡/亲和 */
	AI_EV_NMI_WATCHDOG,           /* 09.04 NMI/Watchdog */
	AI_EV_SOFTIRQ,                /* 09.05 softirq/tasklet */

	/* 10 锁竞争与同步（4） */
	AI_EV_MUTEX,                  /* 10.01 mutex */
	AI_EV_SPINLOCK,               /* 10.02 spinlock */
	AI_EV_RWSEM,                  /* 10.03 rwsem */
	AI_EV_RTMUTEX,                /* 10.04 rtmutex/其他 */

	/* 11 时间与定时器（4） */
	AI_EV_TIMER,                  /* 11.01 定时器 */
	AI_EV_HRTIMER,                /* 11.02 高精度定时器 */
	AI_EV_CLOCKSOURCE,            /* 11.03 时钟源/时钟域 */
	AI_EV_DELAY,                  /* 11.04 延迟与睡眠 */

	/* 12 电源管理（5） */
	AI_EV_CPUFREQ,                /* 12.01 频率调速 */
	AI_EV_CPUIDLE,                /* 12.02 空闲/C-state */
	AI_EV_SUSPEND,                /* 12.03 休眠/唤醒 */
	AI_EV_RUNTIME_PM,             /* 12.04 运行时电源管理 */
	AI_EV_THERMAL,                /* 12.05 热管理 */

	/* 13 虚拟化（5） */
	AI_EV_VCPU,                   /* 13.01 vCPU */
	AI_EV_GUEST_MEM,              /* 13.02 客户机内存 */
	AI_EV_KVM_EXIT,               /* 13.03 KVM 退出 */
	AI_EV_VIRTIO,                 /* 13.04 virtio */
	AI_EV_HYPERCALL,              /* 13.05 半虚拟化/hypercall */

	/* 14 BPF/Tracing/Perf（4） */
	AI_EV_BPF_PROG,               /* 14.01 BPF 程序 */
	AI_EV_BPF_MAP,                /* 14.02 BPF Map */
	AI_EV_TRACING,                /* 14.03 Tracing */
	AI_EV_PERF,                   /* 14.04 Perf 事件 */

	/* 15 用户行为（6） */
	AI_EV_USER_SESSION,           /* 15.01 会话与应用启动（全量） */
	AI_EV_USER_ACTIVITY,          /* 15.02 用户活动模式 */
	AI_EV_SYSCALL_PATTERN,        /* 15.03 系统调用模式 */
	AI_EV_MEM_PATTERN,            /* 15.04 内存分配模式 */
	AI_EV_NET_PATTERN,            /* 15.05 网络使用模式 */
	AI_EV_GPU,                    /* 15.06 GPU/加速器使用 */

	/* 16 硬件与驱动（5） */
	AI_EV_DEVICE,                 /* 16.01 设备 probe/remove */
	AI_EV_DRIVER_PM,              /* 16.02 驱动电源 */
	AI_EV_HW_ERROR,               /* 16.03 硬件错误 */
	AI_EV_DMA,                    /* 16.04 DMA */
	AI_EV_PCI,                    /* 16.05 PCI/资源 */

	/* 17 内核构建与配置（3） */
	AI_EV_CONFIG_CHANGE,          /* 17.01 配置变更 */
	AI_EV_SYSCTL,                 /* 17.02 sysctl */
	AI_EV_BUILD,                  /* 17.03 构建信息 */

	/* 18 AI 自我观测（2，Prompt 13） */
	AI_EV_AI_DECISION,            /* 18.01 AI 决策（决策记录回写 ring） */
	AI_EV_AI_OUTCOME,             /* 18.02 AI 决策结果（outcome 事件写回） */

	AI_EV_MAX,                    /* 事件总数 = 104 */
};

/* 合成全局事件 ID（16 位：高 8 位大类 + 低 8 位子类） */
#define AI_EVENT_ID(category, event) \
	(((u16)(category) << 8) | (u16)(event))

/* ---- 统计结构 ---- */

struct ai_telemetry_cpu_stats {
	u32 emitted;        /* 成功写入条数 */
	u32 dropped;        /* 满丢弃条数 */
	u32 sampled_skip;   /* 采样跳过条数 */
	u32 ring_size;      /* 环形缓冲字节数 */
	u32 head, tail;     /* 读写位置 */
};

/* ---- 核心接口 ---- */

#ifdef CONFIG_AIKERNEL_TELEMETRY

/**
 * ai_telemetry_init() - 初始化遥测核心（分配 per-CPU ring buffer）
 *
 * 由 ai_runtime_init() 调用；幂等。返回 AI_OK 或负错误码。
 */
int ai_telemetry_init(void);

/**
 * ai_telemetry_exit() - 销毁遥测核心（释放 per-CPU ring buffer）
 *
 * 由 ai_runtime_destroy() 调用；幂等。
 */
void ai_telemetry_exit(void);

/**
 * ai_telemetry_emit() - 全系统唯一的感知数据写入入口
 * @category:   大类（enum ai_category，1~17）
 * @event_type: 事件子类（enum ai_event_type，1~101）
 * @severity:   严重级别（0=调试 1=常规 2=重要 3=关键）
 * @data:       原始数据（零脱敏；data_len=0 时可为 NULL）
 * @data_len:   原始数据长度 0~4096（超长返回 AI_ERR_INVALID_ARG，不截断）
 *
 * 写入属主 CPU 的 ring buffer，无锁、不阻塞、< 100ns 预算。
 * 满则丢弃并累计 dropped，返回 AI_ERR_RING_FULL；采样跳过累计 sampled_skip。
 * 返回 AI_OK 或负错误码。
 */
int ai_telemetry_emit(u8 category, u8 event_type, u8 severity,
		      const void *data, u16 data_len);

/**
 * ai_telemetry_read() - 从指定 CPU 的 ring buffer 读出记录（供 AI Runtime）
 * @cpu: CPU 编号（0 ~ nr_cpu_ids-1）
 * @buf: 接收缓冲（定长头 + 原始数据逐条拼接）
 * @len: 接收缓冲容量；不足时只拷贝完整的记录
 * @out_bytes: 回填实际拷贝字节数
 *
 * 单读者语义（AI Runtime 独占）；返回 AI_OK 或负错误码。
 */
int ai_telemetry_read(u32 cpu, void *buf, size_t len, size_t *out_bytes);

/**
 * ai_telemetry_set_sample_rate() - 设置采样率
 * @category:   大类（1~17）
 * @event_type: 事件子类（1~101）
 * @rate:       0=丢弃全部；1=全量（默认）；N=每 N 条记 1 条
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_telemetry_set_sample_rate(u8 category, u8 event_type, u32 rate);

/**
 * ai_telemetry_get_sample_rate() - 读取采样率
 * @category:   大类（1~17）
 * @event_type: 事件子类（1~101）
 * @rate:       输出当前采样率（0=丢弃 1=全量 N=每 N 条记 1 条）
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_telemetry_get_sample_rate(u8 category, u8 event_type, u32 *rate);

/**
 * ai_telemetry_sample_take() - 采样判定（供热路径埋点在构建 payload 前调用）
 * @category:   大类（1~17）
 * @event_type: 事件子类（1~101）
 *
 * 与 ai_telemetry_emit() 共用同一个 per-CPU 采样计数器与采样率表：
 *   - rate==0     → 返回 false（该事件关闭，调用方直接跳过）；
 *   - rate==1     → 返回 true（全量，不推进计数器）；
 *   - rate==N     → 每 N 次返回 true 一次（其余推进计数器并返回 false）。
 * 返回 true 后必须调用 ai_telemetry_emit_direct()（同 rate 配置下不会再被
 * emit 二次采样）。不可与 ai_telemetry_emit() 混用同一事件（会双重计数）。
 *
 * 返回：true=本次应发射，false=本次跳过。
 */
bool ai_telemetry_sample_take(u8 category, u8 event_type);

/**
 * ai_telemetry_emit_direct() - 已采样判定的直写入口
 * @category:   大类（1~17）
 * @event_type: 事件子类（1~101）
 * @severity:   严重级别（0=调试 1=常规 2=重要 3=关键）
 * @data:       原始数据（零脱敏；data_len=0 时可为 NULL）
 * @data_len:   原始数据长度 0~4096（超长返回 AI_ERR_INVALID_ARG，不截断）
 *
 * 与 ai_telemetry_emit() 唯一区别：不再做采样判定（调用方已用
 * ai_telemetry_sample_take() 判定过，且必须返回 true 才调用本函数）。
 * 其余语义完全一致（无锁、不阻塞、< 100ns 预算、满则丢弃）。
 */
int ai_telemetry_emit_direct(u8 category, u8 event_type, u8 severity,
			     const void *data, u16 data_len);

/**
 * ai_telemetry_reset() - 清空全部 CPU 的 ring buffer 与计数
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_telemetry_reset(void);

/**
 * ai_telemetry_stats() - 读取指定 CPU 的统计
 * @cpu: CPU 编号
 * @st: 统计输出
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_telemetry_stats(u32 cpu, struct ai_telemetry_cpu_stats *st);

#else /* !CONFIG_AIKERNEL_TELEMETRY */

static inline int ai_telemetry_init(void) { return AI_OK; }
static inline void ai_telemetry_exit(void) { }
static inline int ai_telemetry_emit(u8 category, u8 event_type, u8 severity,
				    const void *data, u16 data_len)
{
	return AI_OK;   /* 空函数兜底：零开销零回归 */
}
static inline int ai_telemetry_read(u32 cpu, void *buf, size_t len,
				    size_t *out_bytes)
{
	if (out_bytes)
		*out_bytes = 0;
	return AI_OK;
}
static inline int ai_telemetry_set_sample_rate(u8 category, u8 event_type,
					       u32 rate)
{
	return AI_OK;
}
static inline int ai_telemetry_get_sample_rate(u8 category, u8 event_type,
					       u32 *rate)
{
	if (rate)
		*rate = 1;
	return AI_OK;
}
static inline bool ai_telemetry_sample_take(u8 category, u8 event_type)
{
	return false;   /* TELEMETRY 关闭：跳过（配合 emit_direct 零开销） */
}
static inline int ai_telemetry_emit_direct(u8 category, u8 event_type,
					   u8 severity, const void *data,
					   u16 data_len)
{
	return AI_OK;
}
static inline int ai_telemetry_reset(void) { return AI_OK; }
static inline int ai_telemetry_stats(u32 cpu, struct ai_telemetry_cpu_stats *st)
{
	if (st)
		memset(st, 0, sizeof(*st));
	return AI_OK;
}

#endif /* CONFIG_AIKERNEL_TELEMETRY */
#include "ai_telemetry_wrappers.h"
/* ---- 第 16/17 类类型化发射函数（Prompt 15，全量原始零脱敏） ---- */

#ifdef CONFIG_AIKERNEL_TELEMETRY

/* 16 硬件与驱动 payload 结构（全量零脱敏） */

struct ai_hw_error_payload {
	u64 status;            /* MCE status */
	u64 mcgstatus;         /* MCG status */
	u64 addr;              /* 出错地址 */
	u64 misc;              /* misc 寄存器 */
	u64 ip;                /* 出错 IP */
	u16 cpu;               /* 出错 CPU */
	u8  bank;              /* MCE bank 号 */
	u8  severity;          /* 内核 mce_severity 映射（0~4） */
	u8  msg[48];           /* 错误描述（MCE/AER 原始消息） */
};

struct ai_device_payload {
	u8  action;            /* 0=probe 1=remove */
	u8  reserved[3];
	char dev[64];          /* 设备名（dev_name） */
	char drv[64];          /* 驱动名（可为空） */
};

struct ai_dma_payload {
	u8  dir;               /* 0=map 1=unmap 2=map_sg 3=unmap_sg */
	u8  reserved[7];
	u64 dma_addr;          /* 映射地址 */
	u32 size;              /* 映射大小 */
	u32 flags;             /* 映射标志 */
	char dev[64];          /* 设备名 */
};

struct ai_nmi_payload {
	u8  reason;            /* 0=unknown NMI 1=watchdog 2=其他 */
	u8  reserved[7];
	u64 ip;                /* NMI 时 RIP */
	char msg[64];          /* 原因描述 */
};

struct ai_platform_payload {
	char name[64];         /* platform 设备名 */
	s32  id;               /* 设备 id */
	u32  nres;             /* 资源数 */
	u32  flags;
};

/* 17 内核构建与配置 payload 结构 */

struct ai_kconfig_payload {
	u8  kunit;             /* KUNIT=y */
	u8  bpf;               /* BPF=y */
	u8  kvm;               /* KVM=y */
	u8  aikernel;          /* CONFIG_AIKERNEL=y */
	u8  smp;               /* SMP=y */
	u8  preempt;           /* PREEMPT 级别 0~3 */
	u8  reserved[2];
	char release[64];      /* UTS_RELEASE */
};

struct ai_module_payload {
	u8  action;            /* 0=load 1=unload */
	u8  reserved[7];
	char name[64];         /* 模块名（全量） */
};

struct ai_sysctl_payload {
	char name[64];         /* 表名（procname，全量） */
	char old_val[32];      /* 写前值（字符串原样） */
	char new_val[32];      /* 写后值（字符串原样） */
};

/**
 * ai_telemetry_hw_error() - 硬件错误全量入遥测（MCE/AER 路径）
 * @p: 硬件错误 payload（MCE status/addr/ip 等全量字段）
 *
 * 硬件错误是训练金矿（内存/总线/处理器错误与系统状态关联）：
 * 不采样、severity 由调用方给定（通常 CRITICAL），ring 满时驱逐最旧
 * 记录保证关键错误不丢。返回 AI_OK 或负错误码。
 */
int ai_telemetry_hw_error(const struct ai_hw_error_payload *p, u8 severity);

/**
 * ai_telemetry_device_evt() - 设备 probe/remove 事件（16.01）
 * @action: 0=probe 1=remove
 * @dev:    设备名
 * @drv:    驱动名（可 NULL）
 *
 * 默认采样率 1/16。返回 AI_OK 或负错误码。
 */
int ai_telemetry_device_evt(u8 action, const char *dev, const char *drv);

/**
 * ai_telemetry_dma_evt() - DMA 映射事件（16.04）
 * @dir: 0=map 1=unmap
 * @dev: 设备名
 * @dma_addr: 映射地址
 * @size: 映射大小
 *
 * 默认采样率 1/64（DMA 高频）。返回 AI_OK 或负错误码。
 */
int ai_telemetry_dma_evt(u8 dir, const char *dev, u64 dma_addr, u32 size);

/**
 * ai_telemetry_nmi_evt() - NMI 事件（16 类语境：硬件级 NMI）
 * @reason: 0=unknown NMI 1=watchdog 2=其他
 * @ip: NMI 时 RIP
 * @msg: 原因描述（可 NULL）
 *
 * 全量不采样（NMI 稀少且关键）。返回 AI_OK 或负错误码。
 */
int ai_telemetry_nmi_evt(u8 reason, u64 ip, const char *msg);

/**
 * ai_telemetry_platform_evt() - platform 设备注册事件（16.01 变体）
 * @name: 设备名
 * @id: 设备 id
 * @nres: 资源数
 *
 * 默认采样率 1/16。返回 AI_OK 或负错误码。
 */
int ai_telemetry_platform_evt(const char *name, s32 id, u32 nres);

/**
 * ai_telemetry_config_change_evt() - 内核配置快照（17.01，启动采集一次）
 * @p: 配置 payload（release/KUNIT/BPF/KVM/AIKERNEL/SMP/PREEMPT）
 *
 * 全量一次。返回 AI_OK 或负错误码。
 */
int ai_telemetry_config_change_evt(const struct ai_kconfig_payload *p);

/**
 * ai_telemetry_module_evt() - 模块加载/卸载事件（17.02）
 * @action: 0=load 1=unload
 * @name: 模块名（全量）
 *
 * 全量不采样（模块事件稀少）。返回 AI_OK 或负错误码。
 */
int ai_telemetry_module_evt(u8 action, const char *name);

/**
 * ai_telemetry_sysctl_evt() - sysctl 写入事件（17.02）
 * @name: 表名（procname，全量）
 * @old_val: 写前值（字符串，全量）
 * @new_val: 写后值（字符串，全量）
 *
 * 默认采样率 1/16。返回 AI_OK 或负错误码。
 */
int ai_telemetry_sysctl_evt(const char *name, const char *old_val,
			    const char *new_val);

#else /* !CONFIG_AIKERNEL_TELEMETRY */

static inline int ai_telemetry_hw_error(const struct ai_hw_error_payload *p,
					u8 severity)
{ return AI_OK; }
static inline int ai_telemetry_device_evt(u8 action, const char *dev,
					  const char *drv)
{ return AI_OK; }
static inline int ai_telemetry_dma_evt(u8 dir, const char *dev,
				       u64 dma_addr, u32 size)
{ return AI_OK; }
static inline int ai_telemetry_nmi_evt(u8 reason, u64 ip, const char *msg)
{ return AI_OK; }
static inline int ai_telemetry_platform_evt(const char *name, s32 id,
					    u32 nres)
{ return AI_OK; }
static inline int ai_telemetry_config_change_evt(
	const struct ai_kconfig_payload *p)
{ return AI_OK; }
static inline int ai_telemetry_module_evt(u8 action, const char *name)
{ return AI_OK; }
static inline int ai_telemetry_sysctl_evt(const char *name,
					  const char *old_val,
					  const char *new_val)
{ return AI_OK; }

#endif /* CONFIG_AIKERNEL_TELEMETRY */

#endif /* _AIKERNEL_AI_TELEMETRY_H */
