/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * include/uapi/linux/ai_netlink.h - NETLINK_AI 协议族（AI 与内核高速指令通道）
 *
 * 协议族编号 NETLINK_AI = 31（定义于 include/uapi/linux/netlink.h；
 * 取值 < MAX_LINKS=32，23~31 保留区中的空闲编号）。
 *
 * 命令（nlmsg_type）：
 *   AI_CMD_SENSE - 拉取感知数据（最近 N 条遥测记录，N 由载荷携带，上限 4096）
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
#define AI_NL_EV_MAX		2

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

#endif /* _UAPI_LINUX_AI_NETLINK_H */
