/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * include/uapi/linux/ai_netlink.h - NETLINK_AI 协议族（AI 与内核高速指令通道）
 *
 * 协议族编号 NETLINK_AI = 31（定义于 include/uapi/linux/netlink.h；
 * 取值 < MAX_LINKS=32，23~31 保留区中的空闲编号）。
 *
 * 命令（nlmsg_type）：
 *   AI_CMD_SENSE - 拉取感知数据（最近 N 条遥测记录，N 由载荷携带，上限 4096；
 *                  需 CAP_SYS_ADMIN——K2b K1B-13：遥测流零脱敏与 ACT 同权）
 *   AI_CMD_ACT   - 下发决策指令（执行对应决策域策略 + 记录决策日志，需 CAP_SYS_ADMIN）
 *   AI_CMD_REG   - 注册回调（登记发起方 portid，供后续异步事件推送，需 CAP_SYS_ADMIN）
 *
 * 载荷结构（对齐 AIKernel/core/ai_telemetry.h 与 ai_policy.h 的
 * struct ai_telemetry_record / struct ai_decision_log，感知数据全量原始零脱敏）。
 */

#ifndef _UAPI_LINUX_AI_NETLINK_H
#define _UAPI_LINUX_AI_NETLINK_H

#include <linux/types.h>
#include <linux/netlink.h>

/* NETLINK_AI 协议族编号（同时定义于 netlink.h，保持一致） */
#define NETLINK_AI		31

/* ---- 命令（必须 >= NLMSG_MIN_TYPE=16，否则被 netlink 当作控制消息跳过） ---- */

#define AI_CMD_SENSE		16	/* 读感知数据（遥测记录流） */
#define AI_CMD_ACT		17	/* 下发决策指令 */
#define AI_CMD_REG		18	/* 注册/注销异步事件推送（CAP_SYS_ADMIN） */
#define AI_CMD_EVENT		19	/* 内核 → 用户异步事件通知（推送，非请求） */
#define AI_CMD_ACT2		20	/* K1：下发决策指令（nlattr，D1） */

/* ---- 常量 ---- */

#define AI_NL_SENSE_CPU_ALL	0xFFFFFFFFu	/* cpu=全部 */
#define AI_NL_SENSE_MAX_RECORDS	4096		/* 单次拉取记录数上限 */
#define AI_NL_FORMAT_RAW	0		/* 原始二进制（头+数据） */
#define AI_NL_FORMAT_HUMAN	1		/* 可读文本 */
#define AI_NL_PAYLOAD_MAX	(64 * 1024)	/* 单次回传载荷上限 */

/* ---- SENSE 请求载荷 ---- */

struct ai_nl_sense {
	__u32 cpu;		/* AI_NL_SENSE_CPU_ALL=全部 CPU */
	__u32 max_records;	/* 1..AI_NL_SENSE_MAX_RECORDS */
	__u32 format;		/* AI_NL_FORMAT_RAW / AI_NL_FORMAT_HUMAN */
	__u32 reserved;
};

/* ---- SENSE 应答载荷：头 + 记录流 ---- */

struct ai_nl_sense_ack {
	__u32 records;		/* 实际回传记录数 */
	__u32 bytes;		/* 记录流字节数（raw: 头+数据；human: 文本行） */
	__s32 ai_err;		/* AI_OK 或负 AI 错误码 */
	__u32 reserved;
	/* 后随 records 条记录：raw = struct ai_telemetry_record 定长头+原始数据；
	 * human = 文本行 */
};

/* ---- ACT 请求载荷（对齐 struct ai_policy_ctx） ---- */

/* v2 定向参数名长度（与 AIKernel/core/ai_policy.h 的 AI_POLICY_PARAM_LEN
 * 保持一致；现有参数全名如 sched.nice/mm.swappiness/net.rto 均 < 12 字符） */
#define AI_NL_ACT_PARAM_LEN	24

struct ai_nl_act {
	__u64 trigger_event_id;	/* 触发事件 ID（AI_EVENT_ID，可为 0） */
	__u32 decision_type;	/* 决策类型 */
	__u8  domain;		/* 决策域（enum ai_policy_domain，0~11） */
	__u8  confidence;	/* 模型置信度 0-100 */
	__u16 reserved;
	__u32 model_version;	/* 决策模型版本 */
	__u64 data[8];		/* 决策参数（最大 64B） */
	char  param[AI_NL_ACT_PARAM_LEN];	/* v2：定向参数名（NUL 结尾，
			 * 如 "mm.swappiness"；空串 = 按 domain 广播）。
			 * 旧 v1 客户端消息无此尾部（88B，长度判定），
			 * 内核视为 param 空 = 广播，向后兼容 */
};

/* v1 旧布局（无 param 尾部）载荷长度：内核按 nlmsg_len 兼容判定基准。
 * sizeof 用在 #define 展开处（本定义必须位于结构体之后） */
#define AI_NL_ACT_V1_LEN	(sizeof(struct ai_nl_act) - \
				 AI_NL_ACT_PARAM_LEN)

/* ---- ACT 应答载荷 ---- */

struct ai_nl_act_ack {
	__u32 executed;		/* 执行到的策略数 */
	__u32 hit;		/* 命中数（executed>0 即命中） */
	__s32 ai_err;		/* AI_OK 或负 AI 错误码 */
	__u32 reserved;
};

/* ---- ACT2 请求载荷（K1，KERNEL-K1-DESIGN §3/D1/D3/D6） ----
 *
 * v1 ACT（定长 struct + 88/112B 长度轨）原封不动；ACT2 为新命令 =
 * nlattr 载荷，天然为 K2 批量事务（重复 PARAM 元组）铺路。
 * 必备 DOMAIN+TYPE+PARAM，缺任一内核拒收（-EINVAL）；其余可选，
 * DATA 缺省零数组。TRACE 显式携带（hi/lo 任一非零即采用，不改写）。 */
enum {
	AI_DEC_ATTR_UNSPEC,
	AI_DEC_ATTR_DOMAIN,	/* u8：决策域（enum ai_policy_domain，0~12） */
	AI_DEC_ATTR_TYPE,	/* u32：决策类型 */
	AI_DEC_ATTR_PARAM,	/* NUL 结尾字符串：≤23 字符+NUL（含 NUL ≤24） */
	AI_DEC_ATTR_DATA,	/* 二进制 64B = 8×u64 决策参数（缺省零数组） */
	AI_DEC_ATTR_CONFIDENCE,	/* u8：模型置信度 0-100 */
	AI_DEC_ATTR_MODEL_VER,	/* u32：决策模型版本 */
	AI_DEC_ATTR_TRIG_EVID,	/* u64：触发事件 ID（AI_EVENT_ID，可为 0） */
	AI_DEC_ATTR_TRACE_HI,	/* u64：统一 trace 高 64 位 */
	AI_DEC_ATTR_TRACE_LO,	/* u64：统一 trace 低 64 位 */
	AI_DEC_ATTR_INTENT,	/* u64：意图 ID（0=未供给） */
	AI_DEC_ATTR_PARENT,	/* u64：父决策 ID（0=无父） */
	AI_DEC_ATTR_AGENT,	/* u32：发起方（enum ai_agent_id） */
	AI_DEC_ATTR_EXPECTED,	/* s64：调用方预期 delta（0=未供给） */
	/* K2a（KERNEL-K2-DESIGN §3/D1）：批量事务元组内新属性（续枚举尾，
	 * 不动现有号）。仅 AI_CMD_ACT_BATCH 元组内合法——ACT2 严格 policy
	 * 表中二者为 NULL 项=拒收，ACT2 行为不变（D12 追加式）。 */
	AI_DEC_ATTR_VALUE,	/* u64：元组目标值（元组内必备） */
	AI_DEC_ATTR_PID,	/* u32：task 作用域目标 pid（元组内可选，0=全局） */

	__AI_DEC_ATTR_MAX,
	AI_DEC_ATTR_MAX = __AI_DEC_ATTR_MAX - 1,
};

/* ACT2 应答载荷：决策关联键回带（铸造发生在 ai_policy_execute 内） */
struct ai_nl_act2_ack {
	__u8  executed;		/* 执行到的策略数（钳 U8_MAX） */
	__u8  hit;		/* 命中（executed>0 即 1） */
	__s32 ai_err;		/* AI_OK 或负 AI 错误码 */
	__u64 decision_id;	/* 本决策 ID */
	__u64 trace_hi;		/* 统一 trace 高 64 位（回读铸造结果） */
	__u64 trace_lo;		/* 统一 trace 低 64 位 */
};

/* K1 D6：决策发起方小枚举（防自由数；与 source（决策来源通道）正交） */
enum ai_agent_id {
	AI_AGENT_KERNEL		= 0,	/* 内核自身（heuristic/think 闭环） */
	AI_AGENT_OCC_CLI	= 1,	/* occ CLI 手工下发 */
	AI_AGENT_OCC_AI		= 2,	/* occ AI 会话（executor 工具轨） */
	AI_AGENT_AISTREAMD	= 3,	/* aistreamd 采集/回填 */
	AI_AGENT_APIC		= 4,	/* aikernel-api HTTP 网关 */
	AI_AGENT_TOOL		= 5,	/* 其它工具进程 */
	AI_AGENT_OTHER		= 255,	/* 未登记发起方 */
};

/* K1 D6：side_effect_mask 诚实三位（v1 只放真实发生的；
 * 按 handler 细分位留给 K2/K4 做深时扩，不预冒充） */
#define AI_SE_PARAM_WRITTEN	(1U << 0)	/* executed>0：至少写一参数 */
#define AI_SE_SAFETY_CLAMPED	(1U << 1)	/* 被安全边界限幅（clamp） */
#define AI_SE_ROLLED_BACK	(1U << 2)	/* 失败回退内核默认行为 */

/* ---- REG 请求载荷 ---- */

#define AI_NL_REG_F_UNREG	(1U << 0)	/* 置位=注销（默认 0=注册） */

struct ai_nl_reg {
	__u32 flags;		/* AI_NL_REG_F_UNREG；其余位必须为 0 */
	__u32 reserved;		/* 必须为 0（前向兼容） */
};

/* ---- 异步事件（AI_CMD_EVENT，内核主动推送给已注册 portid） ---- */

/* 事件大类（category）：只追加不重排 */
#define AI_NL_EV_POLICY		1	/* 策略执行结果（event_id=decision_id） */
#define AI_NL_EV_MODEL		2	/* 模型装载/卸载（event_id=model id） */
/*
 * K-B NETLINK EVENT glue（REVIEW3 §C，只追加不重排）：遥测热插拔事件
 * 镜像（ai_telemetry.c 中心白名单桥），3/4/5 语义与 K3d-2 用户侧冻结
 * 契约（as_streams.c:225-250）严格一致：
 *   DEVICE      code 0=probe / 1=remove，param=dev 名（>23B 截断）
 *   CPU_HOTPLUG code=online 位（1=上线 / 0=下线），param=cpu 号（十进制）
 *   HW_ERROR    MCE 硬件错误，param="cpu,bank"
 * 注意：本 category 空间与遥测 18 大类（AI_CAT_*）是两个命名空间，
 * 勿按数值混用（AI_CAT_SCHED=1 与 AI_NL_EV_POLICY=1 撞号，K3D2 §7-4）。
 */
#define AI_NL_EV_DEVICE		3	/* 设备 probe/remove（遥测 16.01 镜像） */
#define AI_NL_EV_CPU_HOTPLUG	4	/* CPU 上下线（遥测 01.07 镜像） */
#define AI_NL_EV_HW_ERROR	5	/* MCE 硬件错误（遥测 16.03 镜像） */
#define AI_NL_EV_MAX		5

/* 严重级 */
#define AI_NL_EV_SEV_INFO	0
#define AI_NL_EV_SEV_WARN	1
#define AI_NL_EV_SEV_ERROR	2

struct ai_nl_event {
	__u64 ts;		/* 事件时间（ktime_get_ns） */
	__u64 event_id;		/* 事件 ID：策略=decision_id，模型=model id */
	__u32 category;		/* AI_NL_EV_* */
	__u32 severity;		/* AI_NL_EV_SEV_* */
	__s32 code;		/* 策略=executed 数；模型=1 装载 / 0 卸载 */
	__u32 reserved;
	char  param[AI_NL_ACT_PARAM_LEN];	/* 关联参数名/模型名（NUL 结尾） */
};

/* K1 D7：EVENT 72B 形态的尾巴（policy 事件带记录 trace；环境事件
 * 不带 = 56B 原样，trace 0:0 = 无意图归属，诚实零） */
struct ai_nl_event_tail {
	__u64 trace_hi;		/* 统一 trace 高 64 位（0=无归属） */
	__u64 trace_lo;		/* 统一 trace 低 64 位 */
};

/* K1 D8：三层同步防线——冻结长度轨钉死（drift 即编译失败）。
 * ai_nl_act 112B（v2 全量）/ AI_NL_ACT_V1_LEN 88B（v1 旧布局）双轨；
 * act2_ack=32B（1+1+4pad+8+8+8 自然对齐）；event=56B、tail=16B。 */
_Static_assert(sizeof(struct ai_nl_act) == 112,
	       "ai_nl_act v2 布局漂移（冻结契约）");
_Static_assert(AI_NL_ACT_V1_LEN == 88,
	       "ai_nl_act v1 长度轨漂移（冻结契约）");
_Static_assert(sizeof(struct ai_nl_act_ack) == 16,
	       "ai_nl_act_ack 布局漂移");
_Static_assert(sizeof(struct ai_nl_act2_ack) == 32,
	       "ai_nl_act2_ack 布局漂移");
_Static_assert(sizeof(struct ai_nl_event) == 56,
	       "ai_nl_event 布局漂移（as_streams 56B 定长契约）");
_Static_assert(sizeof(struct ai_nl_event_tail) == 16,
	       "ai_nl_event_tail 布局漂移");

/* ---- ACT_BATCH 请求/应答（K2，KERNEL-K2-DESIGN §3/D1 追加段） ----
 *
 * AI_CMD_ACT_BATCH(21)：嵌套 nlattr 批量事务（两阶段，单 decision_id）。
 * 载荷 = 批级 attr（TRACE_HI/LO、INTENT、AGENT 复用 AI_DEC_ATTR_* 8/9/10/12
 * + AUTO_ROLLBACK_MS + CONFIRM_TOKEN）+ 可重复 AI_BATCH_ATTR_OPS 元组
 * （NLA_F_NESTED，每元组内 {AI_DEC_ATTR_PARAM, VALUE(u64 必备),
 * PID(u32 可选)}）；1≤元组数≤AI_BATCH_MAX_OPS，重复 param 名拒收。 */
#define AI_CMD_ACT_BATCH	21		/* K2：批量事务（嵌套 nlattr） */
#define AI_BATCH_MAX_OPS	27		/* 对齐 KTB 验收口径 */

enum {
	AI_BATCH_ATTR_OPS = 1,		/* NLA_F_NESTED 可重复：单参数元组 */
	AI_BATCH_ATTR_AUTO_ROLLBACK_MS = 2,	/* u32；0=不 arm（缺省） */
	AI_BATCH_ATTR_CONFIRM_TOKEN = 3,	/* u64；blast 拒后重试携带 */

	__AI_BATCH_ATTR_MAX,
	AI_BATCH_ATTR_MAX = __AI_BATCH_ATTR_MAX - 1,
};

/* ACT_BATCH 应答载荷：executed=成功子项数（失败全退时=失败前成功数）、
 * first_fail_idx=-1 无失败；blast_radius=受影响任务数粗估（D6），
 * token 未触发=0；ai_err=-EAGAIN 时 radius+token 供两段式重试。 */
struct ai_nl_batch_ack {		/* _Static_assert 钉布局（下行） */
	__u8 executed;			/* 成功子项数（钳 U8_MAX） */
	__u8 hit;			/* 1=整批成功 */
	__s32 ai_err;			/* 0 / -EINVAL / -EAGAIN / -EIO / -EBUSY */
	__u64 decision_id;		/* 本批决策 ID */
	__u64 trace_hi;			/* 统一 trace 高 64 位 */
	__u64 trace_lo;			/* 统一 trace 低 64 位 */
	__s32 first_fail_idx;		/* 首个失败元组序号（-1=无） */
	__u32 blast_radius;		/* D6 粗估（pid 定向=1/全局=nr_threads） */
	__u64 token;			/* D6 派生 token（未触发=0） */
};

/* K2a D4：自然对齐实际尺寸——1+1+(pad2)+4 + 3×8 + 4+4 + 8 = 48B */
_Static_assert(sizeof(struct ai_nl_batch_ack) == 48,
		       "ai_nl_batch_ack 布局漂移（K2 冻结契约）");

#endif /* _UAPI_LINUX_AI_NETLINK_H */
