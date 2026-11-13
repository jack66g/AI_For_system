// SPDX-License-Identifier: GPL-2.0
/*
 * ai_telemetry.h - AIKernel 遥测采集核心（AI 的感官神经系统）
 *
 * 全系统唯一的 AI 感知写入入口：ai_telemetry_emit()。
 * 所有子系统埋点（Prompt 03 起逐模块落进内核）最终都汇聚到
 * per-CPU ring buffer（每 CPU 128KB，无锁，单次写入 < 100ns）。
 *
 * 数据原则（all-ai）：记录携带 44B 定长头（K7 D1 由 23B 扩展）+ 原始数据，
 * 不脱敏、不哈希、不截断。
 *
 * 性能预算：
 *   单次写入      < 100ns（ktime_get_ns() + 两段 memcpy，无锁）
 *   CONFIG_AIKERNEL_TELEMETRY=n 时全部为 static inline 空函数，零开销零回归。
 *
 * 事件体系：18 大类（enum ai_category）~105 子类（enum ai_event_type），
 * 编号对齐《AIKernel_数据源与日志系统计划》01 CPU调度 ~ 18 AI 自我观测。
 */

#ifndef _AIKERNEL_AI_TELEMETRY_H
#define _AIKERNEL_AI_TELEMETRY_H

#include "ai_types.h"
#include <linux/types.h>

/* ---- 常量 ---- */

/*
 * 每 CPU ring buffer 256KB（w24 由 128KB 扩容）：
 *   - 64 CPU 内存代价 = 64 x 256KB = 16MB（VM 8GB 级，远低于 64MB 预算）；
 *   - 目的：为"后台排空周期 + 积压自适应降采样生效窗口"提供突发缓冲，
 *     使环满真丢弃（dropped）在实际负载下趋近 0。
 */
#define AI_TELEMETRY_RING_SIZE     (256 * 1024)
#define AI_TELEMETRY_MAX_DATA_LEN  4096          /* 原始数据最大长度（对齐计划 0-4096） */

/* ---- 严重级别 ---- */

enum ai_severity {
	AI_SEV_DEBUG      = 0,  /* 调试 */
	AI_SEV_NORMAL     = 1,  /* 常规 */
	AI_SEV_IMPORTANT  = 2,  /* 重要 */
	AI_SEV_CRITICAL   = 3,  /* 关键 */
};

/* ---- 记录结构（K7 D1：23B→44B 统一事件头，全量原始数据零脱敏） ---- */

/*
 * 统一事件头（KERNEL-K7-DESIGN §2 D1）：在旧 23B（ts/pid/tgid/cpu/
 * cat/ev/sev/len）之上补 seq/trace/agent/privacy 四组决策关联字段。
 * 零外部 raw 读者（aistreamd 不摄 ring），扩头时机安全；仓内 raw 读者
 * 清单与对齐状态见 K7 施工记录。
 * 布局（packed，_Static_assert 钉死）：
 *   off 0   u64 timestamp_ns   纳秒时间戳
 *   off 8   u64 seq            per-CPU 单调序号（读者可自算丢失）
 *   off 16  u32 pid            触发进程 pid
 *   off 20  u32 tgid           触发进程 tgid
 *   off 24  u16 cpu            触发 CPU
 *   off 26  u64 trace          决策链 trace（per-CPU ctx 对携带；无上下文=0）
 *   off 34  u32 agent          enum ai_agent_id（无上下文=0）
 *   off 38  u8  category       大类（1~18）
 *   off 39  u8  event_type     事件子类（1~105 全局唯一）
 *   off 40  u8  severity       0=调试 1=常规 2=重要 3=关键
 *   off 41  u8  privacy        隐私位（v1 仅字段+渲染，产生侧后波接）
 *   off 42  u16 data_len       原始数据长度 0-4096
 * 注：设计册字段清单含 u16 rsv（合计 46B），与其自设 _Static_assert(==44)
 * 冲突——以 44B 断言为准（K7 施工偏差登记），去掉 rsv 尾垫。
 */
struct ai_telemetry_record {
	u64 timestamp_ns;   /* 纳秒时间戳 */
	u64 seq;            /* per-CPU 单调序号（K7 D1） */
	u32 pid, tgid;      /* 触发进程 */
	u16 cpu;            /* 触发 CPU */
	u64 trace;          /* 决策链 trace（ctx 对携带，默认 0） */
	u32 agent;          /* enum ai_agent_id（ctx 对携带，默认 0） */
	u8  category;       /* 大类（1~18） */
	u8  event_type;     /* 事件子类（1~105 全局唯一） */
	u8  severity;       /* 0=调试 1=常规 2=重要 3=关键 */
	u8  privacy;        /* 隐私位（v1 仅渲染，默认 0） */
	u16 data_len;       /* 原始数据长度 0-4096 */
	/* 后随 data_len 字节原始数据，不脱敏不哈希 */
} __attribute__((packed));

/* K7 D1：44B 头钉扎（drift 即编译失败） */
_Static_assert(sizeof(struct ai_telemetry_record) == 44,
	       "ai_telemetry_record must be 44B packed (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, seq) == 8,
	       "seq must sit at offset 8 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, pid) == 16,
	       "pid must sit at offset 16 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, tgid) == 20,
	       "tgid must sit at offset 20 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, cpu) == 24,
	       "cpu must sit at offset 24 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, trace) == 26,
	       "trace must sit at offset 26 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, agent) == 34,
	       "agent must sit at offset 34 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, category) == 38,
	       "category must sit at offset 38 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, event_type) == 39,
	       "event_type must sit at offset 39 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, severity) == 40,
	       "severity must sit at offset 40 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, privacy) == 41,
	       "privacy must sit at offset 41 (K7 D1)");
_Static_assert(__builtin_offsetof(struct ai_telemetry_record, data_len) == 42,
	       "data_len must sit at offset 42 (K7 D1)");

/* 记录定长头字节数 = 44（语义保持 = sizeof(struct ai_telemetry_record)） */
#define AI_TELEMETRY_HEADER_LEN    (sizeof(struct ai_telemetry_record))

/* K7 D1：human 渲染单行上限（含 NUL；procfs/SENSE/测试三处共用，
 * 行内容见 ai_telemetry_format_human()） */
#define AI_TELEMETRY_HUMAN_LINE_MAX  192

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

/* ---- 105 子类事件（编号对齐数据计划：注释标注计划章节号） ---- */

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

	/* 18 AI 自我观测（3，Prompt 13 + K7 D2） */
	AI_EV_AI_DECISION,            /* 18.01 AI 决策（决策记录回写 ring） */
	AI_EV_AI_OUTCOME,             /* 18.02 AI 决策结果（outcome 事件写回） */
	AI_EV_AI_RING_FULL,           /* 18.03 环满告警回合（K7 D2 自遥测） */

	AI_EV_MAX,                    /* 事件总数 = 105 */
};

/* 合成全局事件 ID（16 位：高 8 位大类 + 低 8 位子类） */
#define AI_EVENT_ID(category, event) \
	(((u16)(category) << 8) | (u16)(event))

/* ---- 统计结构 ---- */

/*
 * 统计结构（w24 末尾追加字段，原有字段偏移与语义不变——/proc/ai/status
 * 仅追加输出，ABI 兼容）：
 *   - dropped 为"真实丢失记录条数"（w58 起满丢弃/CRITICAL 驱逐/resync
 *     弃积压逐条计入；resync 的坏头残段按 1 条下界计并见 dmesg 字节数；
 *     旧版 resync 一次只计 1）；sampled_skip 保持
 *     "采样跳过"（含 w24 积压自适应降采样跳过——丢的是采样密度，不是
 *     已发生事件计数）；
 *   - consumed/adapt_shift/adapt_skipped 为 w24 新增观测字段；
 *   - resyncs/adapt_peak_shift/adapt_episodes 为 w58 末尾追加字段
 *     （原有字段偏移与语义不变，/proc/ai/status 仅追加输出）；
 *   - predrain_dropped 为 w63 末尾追加字段：排空线程（消费者）就绪前
 *     的环满丢弃条数。w63 起该窗口的丢弃计入 sampled_skip（按采样跳过
 *     语义，不属于稳态背压），predrain_dropped 保留真实损失观测；消费者
 *     就绪后的环满丢弃仍计入 dropped。
 *   - K7（KERNEL-K7-DESIGN D1/D2/D4）末尾追加字段（旧字段偏移/语义不变，
 *     /proc/ai/status 仅追加输出）：emitted64/dropped64/sampled_skip64 为
 *     旧 u32/atomic 计数的 64 位原子镜像（写侧双写，读侧新优先防回绕）；
 *     sampled_skip64 = rate_skipped + adapt_skipped + predrain_dropped
 *     （三源拆标列）；drain_discards=drain_all 读出即丢条数；
 *     sense_overread_dropped=NETLINK SENSE 读侧过读丢弃条数；
 *     resync_races=resync cmpxchg 失败次数；full_latch/full_episodes=
 *     环满告警闩（首次 RING_FULL 置位+告警一次，free 过半复位）与回合数；
 *     seq=该 CPU 最近发出的记录序号；adapt_last_backlog/adapt_last_change_ns
 *     =D4 上次升降档时的积压快照与时刻（采样率可解释）。
 */
struct ai_telemetry_cpu_stats {
	u32 emitted;        /* 成功写入条数 */
	u32 dropped;        /* 真实丢失记录条数（满/驱逐/resync 逐条） */
	u32 sampled_skip;   /* 采样跳过条数 */
	u32 ring_size;      /* 环形缓冲字节数 */
	u32 head, tail;     /* 读写位置 */
	u64 consumed;       /* w24：后台/读者已消费（读出并释放）字节数 */
	u32 adapt_shift;    /* w24：当前降档级（瞬时；0=当前无降档，非"未启用"） */
	u64 adapt_skipped;  /* w24：被自适应降采样跳过的条数（含于 sampled_skip） */
	u32 resyncs;        /* w58：环错位 resync 次数（正常恒 0） */
	u32 adapt_peak_shift; /* w58：历史最高降档级（0..6） */
	u64 adapt_episodes; /* w58：进入降档（shift 0→>0）的次数 */
	u64 predrain_dropped; /* w63：消费者就绪前环满丢弃条数（含于
			       * sampled_skip；dropped 不含） */
	/* ---- K7 尾追（D1/D2/D4），旧字段偏移/语义不变 ---- */
	u64 emitted64;      /* D2：emitted 的 64 位原子镜像（防回绕，读侧优先） */
	u64 dropped64;      /* D2：dropped 的 64 位原子镜像 */
	u64 sampled_skip64; /* D2：sampled_skip 的 64 位原子镜像
			     * （=三源 rate+adapt+predrain 之和） */
	u64 rate_skipped;   /* D2：rate 表跳过条数（含 rate=0 关闭；三源列之一） */
	u64 drain_discards; /* D2：drain_all 读出即丢条数（原只计字节不计条） */
	u64 sense_overread_dropped; /* D2：SENSE 读侧过读丢弃条数 */
	u64 resync_races;   /* D2：resync cmpxchg 失败次数（原 return 0 不计账） */
	u32 full_latch;     /* D2：环满告警闩当前态（1=告警未复位） */
	u64 full_episodes;  /* D2：环满告警回合数（闩 0→1 计数） */
	u64 seq;            /* D1：该 CPU 最近发出的记录序号（单调） */
	u32 adapt_last_backlog; /* D4：上次升降档时的积压字节快照 */
	u64 adapt_last_change_ns; /* D4：上次升降档时刻（0=从未变档） */
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
 * 由 ai_runtime_destroy() 调用；幂等。必须在可睡眠进程上下文调用
 * （w63：内部用 on_each_cpu() 等生产者退出写临界区、逐个 read_lock
 * 等读者退出，之后才 vfree）。
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
 * 线程安全（w58）：每 CPU 一把读者 mutex，串行化"复制记录 + 推进 tail"
 * 临界区；可在可睡眠进程上下文并发调用（drain kthread / procfs read /
 * NETLINK SENSE 回调均满足）。返回的每条记录完整、不撕裂；不可在原子/
 * 软中断上下文调用。返回 AI_OK 或负错误码。
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
 * ai_telemetry_rate_cmd() - 采样率设置命令（w21 用户态写入口）
 * @s: NUL 结尾命令串 "cat:ev:N"（cat∈[1,AI_CAT_AI] ev∈[1,AI_EV_MAX)，
 *     N∈[0,65535]；0=丢弃全部 1=全量 N=每 N 条记 1 条）
 *
 * 解析并落 ai_telemetry_set_sample_rate()（>65535 钳 65535）。
 * 返回 AI_OK 或负错误码（语法/边界非法 = AI_ERR_INVALID_ARG）。
 */
int ai_telemetry_rate_cmd(const char *s);

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

/* ---- K7（KERNEL-K7-DESIGN D1/D2）：决策上下文对 + 渲染统一 + 读侧计账 ---- */

/**
 * ai_telemetry_ctx_set() - 设置当前 CPU 的决策上下文对（K7 D1）
 * @trace: 决策链 trace（写进后续每条记录头 rec->trace）
 * @agent: enum ai_agent_id（写进 rec->agent）
 *
 * 决策/策略 emit 路径（ai_policy 执行段等）在铸造决策记录后包住
 * ai_telemetry_emit() 调用段：set → emit…→ clear（try/finally 语义，
 * 提前 return 路径也须 clear）。per-CPU 上下文对：emit 在同 CPU 关中断
 * 临界区内读取；未 set（或跨 CPU 迁移窗口）时记录头诚实填 0。
 */
void ai_telemetry_ctx_set(u64 trace, u32 agent);

/**
 * ai_telemetry_ctx_clear() - 清除当前 CPU 的决策上下文对（trace/agent 归 0）
 */
void ai_telemetry_ctx_clear(void);

/**
 * ai_telemetry_format_human() - 统一 human 单行渲染（K7 D1：单份实现）
 * @rec: 记录头指针（其后须紧跟 data_len 字节数据，即环读缓冲中的连续布局）
 * @buf: 输出缓冲
 * @cap: 缓冲容量（调用方按 AI_TELEMETRY_HUMAN_LINE_MAX=192 起）
 *
 * 行内容：ts/seq/pid/tgid/cpu/trace/agent/cat/ev/sev/privacy/len/data
 * 前 16 字节 hex（data_len>16 追加 "..."），恒以 '\n' 结尾且 NUL 终止。
 * procfs（/proc/ai/telemetry human）与 NETLINK SENSE（human）两出口
 * 字节级同源（K7 验收：两路 golden）。理论极限前缀（全字段最大宽）超
 * 192B 时按剩余预算降 hex 字节数，行完整性（'\n' 终止）不破——偏差
 * 登记见 K7 施工记录。返回写入字节数（含 '\n'，不含 NUL）。
 */
size_t ai_telemetry_format_human(const struct ai_telemetry_record *rec,
				 char *buf, size_t cap);

/**
 * ai_telemetry_note_sense_overread() - SENSE 读侧过读计账（K7 D2）
 * @cpu: 被读的 CPU ring
 * @records: 已从 ring 消费但未交付订阅端的记录条数
 *
 * SENSE 限读后仍可能因 max_records 截断产生"读出即丢"——tail 已推进，
 * 无下次可拉。由 ai_netlink.c 回调计额（sense_overread_dropped）。
 */
void ai_telemetry_note_sense_overread(u32 cpu, u32 records);

/**
 * ai_telemetry_count_records() - 统计缓冲中完整记录条数（K7 D2 助手）
 * @buf: 记录流缓冲（定长头+数据逐条拼接布局）
 * @len: 缓冲有效字节数
 *
 * 按记录头逐条推进（坏头即停，宁可少计不越界）。drain_discards 计额
 * 与 SENSE 过读计数共用。
 */
u32 ai_telemetry_count_records(const void *buf, size_t len);

/* 18.03 环满告警自遥测 payload（K7 D2，emit 侧内部铸造） */
struct ai_tp_ring_full {
	u64 ts_ns;          /* 告警回合首次 RING_FULL 时刻 */
	u32 cpu;            /* 环满 CPU */
	u32 dropped;        /* 告警时该 CPU 累计 dropped（快照） */
};

/* ---- w24：消费者常驻化（后台排空） ---- */

/*
 * 后台排空周期（毫秒）。#58 起稳态基准改为 10ms（100Hz）：250ms 的空闲
 * 窗口足以让重负载突发先填满 256KB 环再被看到，事后提速无法补回已丢事件。
 * 10ms 空闲排空 + 环占用 ≥1/4 时 2ms，兼顾训练日志完整性与 CPU 开销；
 * 每 CPU 每次至多整环，排空能力仍 >=1MB/s。
 */
#define AI_TEL_DRAIN_PERIOD_MS  10

/**
 * ai_telemetry_drain_all() - 同步把全部 CPU 的 ring 读空并释放
 *
 * 读出内容计入 consumed 后丢弃（与环满丢弃同损益，但事件先入环、
 * 在排空周期窗口内仍可被被动读者捕获）。与 /proc/ai/telemetry 读者、
 * NETLINK SENSE 读者的并发由每 CPU read_lock 串行化（w58）：复制与
 * tail 推进在同一临界区，慢读者复制中的记录不会被快读者消费后覆盖。
 * 供后台排空线程周期调用与 KUnit 直接调用。返回 AI_OK 或负错误码。
 */
int ai_telemetry_drain_all(void);

/**
 * ai_telemetry_drain_start() - 启动后台排空线程（"ai_tel_drain"）
 *
 * 周期 AI_TEL_DRAIN_PERIOD_MS 调 ai_telemetry_drain_all()，线程首轮
 * 立即排空一次（w63，不再等首个周期）。幂等；w63 起由 ai_telemetry.c
 * 的 early_initcall 尽早启动（kthreadd 可用后最早安全点），
 * ai_proc_init（late_initcall）再幂等调用一次作为失败重试。
 * 返回 AI_OK 或负错误码。
 */
int ai_telemetry_drain_start(void);

/**
 * ai_telemetry_drain_stop() - 停止后台排空线程并等待退出
 *
 * 幂等；ai_telemetry_exit() 释放 ring 前必须先调用（防 vfree 后访问）。
 */
void ai_telemetry_drain_stop(void);

/**
 * ai_telemetry_drain_running() - 排空线程是否在运行（status 观测用）
 */
bool ai_telemetry_drain_running(void);

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/**
 * ai_telemetry_test_set_consumer_ready() - 仅 KUnit：置位/复位消费者就绪闩锁
 * @ready: true=模拟消费者已就绪；false=模拟启动窗口（尚无消费者）
 *
 * 用于验证 w63 启动窗口计额：消费者就绪前的环满丢弃计入
 * sampled_skip + predrain_dropped，dropped 保持 0。
 */
void ai_telemetry_test_set_consumer_ready(bool ready);
#endif

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
/* K7：TELEMETRY 关闭时的空实现（零开销零回归） */
static inline void ai_telemetry_ctx_set(u64 trace, u32 agent) { }
static inline void ai_telemetry_ctx_clear(void) { }
static inline size_t
ai_telemetry_format_human(const struct ai_telemetry_record *rec,
			  char *buf, size_t cap)
{
	return 0;
}
static inline void ai_telemetry_note_sense_overread(u32 cpu, u32 records) { }
static inline u32 ai_telemetry_count_records(const void *buf, size_t len)
{
	return 0;
}
static inline int ai_telemetry_drain_all(void) { return AI_OK; }
static inline int ai_telemetry_drain_start(void) { return AI_OK; }
static inline void ai_telemetry_drain_stop(void) { }
static inline bool ai_telemetry_drain_running(void) { return false; }

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
