/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ai_netlink_client.h - NETLINK_AI 用户态客户端（Agent 侧）
 *
 * 让 Agent 的 AI 子系统通过 NETLINK_AI（协议族 31）直接对内核下指令 /
 * 读遥测，不再只依赖文件接口（/proc/aikernel 等）间接观测内核。
 *
 * 协议对端：AIKernel/net/ai_netlink.c（内核端）
 * 协议定义：include/uapi/linux/ai_netlink.h（本文件底部持有一份带来源
 *           注释的复制，并在编译期用 _Static_assert 钉住布局）
 *
 * 命令：
 *   AI_CMD_SENSE(16) - 拉取感知数据（无权限要求，但要求 AI 子系统已启用）
 *   AI_CMD_ACT(17)   - 下发决策指令（需 CAP_SYS_ADMIN，缺权返回 EACCES）
 *   AI_CMD_REG(18)   - 登记本进程 portid（需 CAP_SYS_ADMIN；内核按
 *                      portid 幂等去重，登记表上限 32 槽，满返回 EBUSY）
 *
 * 内核端应答行为（实读 AIKernel/net/ai_netlink.c 与 net/netlink/af_netlink.c）：
 *   - 请求 nlmsg_flags 必须带 NLM_F_REQUEST，否则 netlink_rcv_skb 静默跳过
 *   - 内核不要求 NLM_F_ACK：成功应答以「同命令号」类型单消息回传，
 *     nlmsg_seq 回显请求 seq；失败以 NLMSG_ERROR 回传（nlmsgerr.error 为
 *     负 errno，nlmsgerr.msg 回显请求头）
 *   - SENSE 成功应答载荷 = struct ai_nl_sense_ack + 记录流
 *     （raw: 定长记录头+原始数据；human: 文本行），总长不超过
 *     NLMSG_HDRLEN + AI_NL_PAYLOAD_MAX
 *
 * 返回码约定：成功 AI_OK；传输层失败 AI_ERR_NETWORK（errno 保持有效）；
 * 协议解析失败 AI_ERR_PARSE；内核拒绝（NLMSG_ERROR）AI_ERR_API 且
 * *kern_err 收到正 errno。
 */
#ifndef _AI_NETLINK_CLIENT_H
#define _AI_NETLINK_CLIENT_H

#if !defined(__linux__)
#error "ai_netlink_client: NETLINK_AI 通道仅在 Linux 上可用"
#endif

#include <stddef.h>
#include <linux/netlink.h>      /* sockaddr_nl / nlmsghdr / nlmsgerr / NLM_F_* / NLMSG_* */
#include "ai_types.h"

/* ---- 协议族与命令、常量、载荷结构 ----
 *
 * 优先使用构建主机已安装的 AIKernel uapi 头（__has_include 探测）；
 * 否则使用下方复制。复制来源（只读参考，勿改语义）：
 *   - include/uapi/linux/netlink.h 第 32 行：NETLINK_AI 31
 *   - include/uapi/linux/ai_netlink.h 全文
 * 若两者都不符（如内核侧协议演进），下方的 _Static_assert 会编译失败
 * 强制重新同步。
 */
#if defined(__has_include)
#if __has_include(<linux/ai_netlink.h>)
#include <linux/ai_netlink.h>
#define AI_NL_UAPI_FROM_HOST 1
#endif
#endif

#ifndef AI_NL_UAPI_FROM_HOST

/* NETLINK_AI 协议族编号（include/uapi/linux/netlink.h:32）；
 * 主线头文件不含此定义，故带 #ifndef 防御未来主机头收录 */
#ifndef NETLINK_AI
#define NETLINK_AI      31
#endif

/* 命令（nlmsg_type），include/uapi/linux/ai_netlink.h:28-30。
 * 必须 >= NLMSG_MIN_TYPE(16)，否则 netlink_rcv_skb 当作控制消息跳过 */
#define AI_CMD_SENSE        16
#define AI_CMD_ACT          17
#define AI_CMD_REG          18
#define AI_CMD_ACT2         20   /* K1 D1：nlattr 载荷的决策指令（uapi §3） */
#define AI_CMD_ACT_BATCH    21   /* K2 D1：批量事务（嵌套 nlattr，uapi §3 镜像） */
#define AI_BATCH_MAX_OPS    27   /* K2：元组数上限（对齐 KTB 验收口径） */

/* 常量，include/uapi/linux/ai_netlink.h:34-38 */
#define AI_NL_SENSE_CPU_ALL     0xFFFFFFFFu
#define AI_NL_SENSE_MAX_RECORDS 4096
#define AI_NL_FORMAT_RAW        0
#define AI_NL_FORMAT_HUMAN      1
#define AI_NL_PAYLOAD_MAX       (64 * 1024)

/* SENSE 请求载荷（include/uapi/linux/ai_netlink.h:42-47） */
struct ai_nl_sense {
    __u32 cpu;          /* AI_NL_SENSE_CPU_ALL=全部 CPU */
    __u32 max_records;  /* 1..AI_NL_SENSE_MAX_RECORDS */
    __u32 format;       /* AI_NL_FORMAT_RAW / AI_NL_FORMAT_HUMAN */
    __u32 reserved;
};

/* SENSE 应答载荷头（include/uapi/linux/ai_netlink.h:51-58），
 * 后随 records 条记录流（bytes 字节，不含本头） */
struct ai_nl_sense_ack {
    __u32 records;      /* 实际回传记录数 */
    __u32 bytes;        /* 记录流字节数 */
    __s32 ai_err;       /* AI_OK 或负 AI 错误码 */
    __u32 reserved;
};

/* ACT 请求载荷（include/uapi/linux/ai_netlink.h:62-92）
 * v2：尾部新增 param 定向参数名（NUL 结尾，空串=按 domain 广播）；
 * 旧 v1 客户端消息无此尾部（88B），内核按 nlmsg_len 长度判定兼容 */
#define AI_NL_ACT_PARAM_LEN 24

struct ai_nl_act {
    __u64 trigger_event_id; /* 触发事件 ID（可为 0） */
    __u32 decision_type;    /* 决策类型 */
    __u8  domain;           /* 决策域（enum ai_policy_domain，0~12） */
    __u8  confidence;       /* 模型置信度 0-100 */
    __u16 reserved;
    __u32 model_version;    /* 决策模型版本 */
    __u64 data[8];          /* 决策参数（最大 64B） */
    char  param[AI_NL_ACT_PARAM_LEN];   /* v2 定向参数名（如
                         * "mm.swappiness"；空 = 广播）。旧 v1 消息
                         * 无此尾部，内核视为广播 */
};

/* v1 旧布局（无 param 尾部）载荷长度（sizeof 展开于结构体定义之后） */
#define AI_NL_ACT_V1_LEN    (sizeof(struct ai_nl_act) - AI_NL_ACT_PARAM_LEN)

/* ACT 应答载荷（include/uapi/linux/ai_netlink.h:74-79） */
struct ai_nl_act_ack {
    __u32 executed;     /* 执行到的策略数 */
    __u32 hit;          /* 命中数（executed>0 即命中） */
    __s32 ai_err;       /* AI_OK 或负 AI 错误码 */
    __u32 reserved;
};

/* ACT2 决策属性（K1 D1，uapi §3 镜像）：nlattr 流载荷——
 * NLA_HDRLEN+NLA_ALIGN(4) 手写编码（u16 nla_len/u16 nla_type +
 * payload）。必备 DOMAIN+TYPE+PARAM；其余可选（缺省零，DATA 缺省
 * 零数组）。attr 号=枚举序（与 uapi 同源，编号由下方 _Static_assert
 * 钉住）。 */
enum {
    AI_DEC_ATTR_UNSPEC,        /* 0 */
    AI_DEC_ATTR_DOMAIN,        /* 1  u8   决策域 0..12 */
    AI_DEC_ATTR_TYPE,          /* 2  u32  决策类型 */
    AI_DEC_ATTR_PARAM,         /* 3  string ≤23+NUL（定向参数名，非空）*/
    AI_DEC_ATTR_DATA,          /* 4  64B=8×u64 决策参数 */
    AI_DEC_ATTR_CONFIDENCE,    /* 5  u8   0-100 */
    AI_DEC_ATTR_MODEL_VER,     /* 6  u32 */
    AI_DEC_ATTR_TRIG_EVID,     /* 7  u64 */
    AI_DEC_ATTR_TRACE_HI,      /* 8  u64  统一 trace 高 64 位 */
    AI_DEC_ATTR_TRACE_LO,      /* 9  u64  统一 trace 低 64 位 */
    AI_DEC_ATTR_INTENT,        /* 10 u64  意图 id（0=未供给）*/
    AI_DEC_ATTR_PARENT,        /* 11 u64  父决策 id（0=无）*/
    AI_DEC_ATTR_AGENT,         /* 12 u32  enum ai_agent_id */
    AI_DEC_ATTR_EXPECTED,      /* 13 s64  调用方预期 delta（0=未供给）*/
    __AI_DEC_ATTR_MAX,
    AI_DEC_ATTR_MAX = __AI_DEC_ATTR_MAX - 1,
};

/* 决策发起方（K1 D6，uapi 小枚举——防自由数）。
 * M2（AIPD-M2-DESIGN §1）：uapi 在 TOOL=5 后插 AI_AGENT_AIPD = 6
 * （OTHER=255 不动；值追加合法）——本镜像同位追加。 */
enum ai_agent_id {
    AI_AGENT_KERNEL     = 0,
    AI_AGENT_OCC_CLI    = 1,
    AI_AGENT_OCC_AI     = 2,
    AI_AGENT_AISTREAMD  = 3,
    AI_AGENT_APIC       = 4,
    AI_AGENT_TOOL       = 5,
    AI_AGENT_AIPD       = 6,
    AI_AGENT_OTHER      = 255,
};

/* ACT2 应答载荷（K1 D2/uapi §3）：ack 回带决策关联——decision_id 与
 * 内核侧铸造/采用的 trace（ctx 回读，golden 三跳的第一跳） */
struct ai_nl_act2_ack {
    __u8  executed;     /* 执行到的策略数 */
    __u8  hit;          /* 命中数（executed>0 即命中） */
    __s32 ai_err;       /* AI_OK 或负 AI 错误码 */
    __u64 decision_id;  /* 内核分配的决策 id */
    __u64 trace_hi;     /* D2：铸造/采用的 trace（显式携带=原样回显） */
    __u64 trace_lo;
};

/* ACT_BATCH 批级属性（K2 D1/uapi §3 镜像）：TRACE_HI/LO(8/9)、INTENT(10)、
 * AGENT(12) 复用 AI_DEC_ATTR_* 号；AUTO_ROLLBACK_MS/CONFIRM_TOKEN 为 K2 新号。
 * OPS 每元组一个 attr，nla_type 置 NLA_F_NESTED，内嵌元组 attr。 */
enum {
    AI_BATCH_ATTR_OPS = 1,              /* NLA_F_NESTED 可重复：{PARAM, VALUE, PID?} */
    AI_BATCH_ATTR_AUTO_ROLLBACK_MS = 2, /* u32；0=不 arm（缺省） */
    AI_BATCH_ATTR_CONFIRM_TOKEN = 3,    /* u64；blast 拒后重试携带 */
    __AI_BATCH_ATTR_MAX,
    AI_BATCH_ATTR_MAX = __AI_BATCH_ATTR_MAX - 1,
};

/* 元组内 attr（K2 D1）：PARAM 复用 AI_DEC_ATTR_PARAM(3)；VALUE/PID 为
 * AI_DEC_ATTR_* 命名空间的 K2 新号（续 EXPECTED=13 之后）。#ifndef 防御：
 * 主机已装 K2 uapi 头时直接采用其定义，号漂移由下方 _Static_assert 捕获 */
#ifndef AI_DEC_ATTR_VALUE
#define AI_DEC_ATTR_VALUE  14   /* u64：元组内钳前请求值（必备） */
#endif
#ifndef AI_DEC_ATTR_PID
#define AI_DEC_ATTR_PID    15   /* u32：元组内可选 pid（0=不带 attr） */
#endif

/* ACT_BATCH 应答载荷（K2 D4/uapi §3 镜像，_Static_assert 钉布局） */
struct ai_nl_batch_ack {
    __u8  executed;       /* 成功子项数 */
    __u8  hit;            /* 命中（executed>0 即 1） */
    __s32 ai_err;         /* AI_OK 或负 AI 错误码 */
    __u64 decision_id;    /* 本批决策 ID（一个 batch=一个 decision） */
    __u64 trace_hi;       /* 统一 trace 高 64 位（回读铸造结果） */
    __u64 trace_lo;
    __s32 first_fail_idx; /* 首个失败元组序号（-1=无） */
    __u32 blast_radius;   /* D6：粗粒度受影响任务数 */
    __u64 token;          /* blast 拒派生 token（未触发=0） */
};

/* REG 请求载荷（include/uapi/linux/ai_netlink.h:83-86） */
struct ai_nl_reg {
    __u32 flags;        /* 0=仅登记（预留位） */
    __u32 reserved;
};

#endif /* !AI_NL_UAPI_FROM_HOST */

/* M2（AIPD-M2-DESIGN §1）AI_AGENT_AIPD 镜像兜底（文件既有 #ifndef
 * 防御风格，同 AI_DEC_ATTR_VALUE/PID 先例）：主机已装 uapi 头
 * （AI_NL_UAPI_FROM_HOST）但版本旧、无 AIPD=6 项时，按 §1 冻结值 6
 * 直取——内核补丁轮 #44 落地后由 uapi 枚举接管（枚举常量非宏，本
 * define 恒定义、与枚举同值共存无害）。 */
#ifndef AI_AGENT_AIPD
#define AI_AGENT_AIPD  6
#endif

/* ACT 决策域上限 —— uapi 头注释写 0~11 已过时；以内核端实际校验为准：
 * AIKernel/net/ai_netlink.c:235 按 AI_POLICY_DOMAIN_PROC（=
 * AIKernel/core/ai_policy.h:39 的 12）判定 domain 合法范围 0~12 */
#define AI_NL_DOMAIN_MAX    12

/* REG 应答载荷 —— uapi 头未提供具名结构；对齐内核端
 * AIKernel/net/ai_netlink.c ai_nl_reg() 中的内联匿名结构：
 *   struct { __s32 ai_err; __u32 count; } ack;                */
struct ai_nl_reg_ack {
    __s32 ai_err;
    __u32 count;
};

/* ---- 布局钉扎（编译期校验 agent 侧视图与 uapi 一致） ---- */

_Static_assert(NETLINK_AI == 31, "NETLINK_AI must be 31");
_Static_assert(AI_CMD_SENSE == 16 && AI_CMD_ACT == 17 &&
               AI_CMD_REG == 18, "AI netlink command numbers drifted");
/* K1：ACT2 命令号与 attr 编号钉死（uapi §3；漂移即编译失败强制同步） */
_Static_assert(AI_CMD_ACT2 == 20, "AI_CMD_ACT2 must be 20");
_Static_assert(AI_DEC_ATTR_DOMAIN == 1 && AI_DEC_ATTR_TYPE == 2 &&
               AI_DEC_ATTR_PARAM == 3 && AI_DEC_ATTR_DATA == 4 &&
               AI_DEC_ATTR_TRACE_HI == 8 && AI_DEC_ATTR_TRACE_LO == 9 &&
               AI_DEC_ATTR_INTENT == 10 && AI_DEC_ATTR_PARENT == 11 &&
               AI_DEC_ATTR_AGENT == 12 && AI_DEC_ATTR_EXPECTED == 13,
               "AI_DEC_ATTR_* numbers drifted");
_Static_assert(sizeof(struct ai_nl_act2_ack) == 32, "ai_nl_act2_ack size");
_Static_assert(offsetof(struct ai_nl_act2_ack, executed) == 0 &&
               offsetof(struct ai_nl_act2_ack, hit) == 1 &&
               offsetof(struct ai_nl_act2_ack, ai_err) == 4 &&
               offsetof(struct ai_nl_act2_ack, decision_id) == 8 &&
               offsetof(struct ai_nl_act2_ack, trace_hi) == 16 &&
               offsetof(struct ai_nl_act2_ack, trace_lo) == 24,
               "ai_nl_act2_ack offsets");
_Static_assert(AI_NL_PAYLOAD_MAX == 65536, "AI_NL_PAYLOAD_MAX drifted");
/* K2：ACT_BATCH 命令号/批级 attr 号/元组号钉死（uapi §3；漂移即编译失败） */
_Static_assert(AI_CMD_ACT_BATCH == 21, "AI_CMD_ACT_BATCH must be 21");
_Static_assert(AI_BATCH_MAX_OPS == 27, "AI_BATCH_MAX_OPS must be 27");
_Static_assert(AI_BATCH_ATTR_OPS == 1 &&
               AI_BATCH_ATTR_AUTO_ROLLBACK_MS == 2 &&
               AI_BATCH_ATTR_CONFIRM_TOKEN == 3,
               "AI_BATCH_ATTR_* numbers drifted");
_Static_assert(AI_DEC_ATTR_VALUE == 14 && AI_DEC_ATTR_PID == 15,
               "batch tuple attr numbers drifted");
_Static_assert(sizeof(struct ai_nl_batch_ack) == 48, "ai_nl_batch_ack size");
_Static_assert(offsetof(struct ai_nl_batch_ack, executed) == 0 &&
               offsetof(struct ai_nl_batch_ack, hit) == 1 &&
               offsetof(struct ai_nl_batch_ack, ai_err) == 4 &&
               offsetof(struct ai_nl_batch_ack, decision_id) == 8 &&
               offsetof(struct ai_nl_batch_ack, trace_hi) == 16 &&
               offsetof(struct ai_nl_batch_ack, trace_lo) == 24 &&
               offsetof(struct ai_nl_batch_ack, first_fail_idx) == 32 &&
               offsetof(struct ai_nl_batch_ack, blast_radius) == 36 &&
               offsetof(struct ai_nl_batch_ack, token) == 40,
               "ai_nl_batch_ack offsets");

_Static_assert(sizeof(struct nlmsghdr) == 16, "struct nlmsghdr layout");
_Static_assert(sizeof(struct nlmsgerr) == 20, "struct nlmsgerr layout");

_Static_assert(sizeof(struct ai_nl_sense) == 16, "ai_nl_sense size");
_Static_assert(offsetof(struct ai_nl_sense, cpu) == 0 &&
               offsetof(struct ai_nl_sense, max_records) == 4 &&
               offsetof(struct ai_nl_sense, format) == 8 &&
               offsetof(struct ai_nl_sense, reserved) == 12,
               "ai_nl_sense offsets");

_Static_assert(sizeof(struct ai_nl_sense_ack) == 16, "ai_nl_sense_ack size");
_Static_assert(offsetof(struct ai_nl_sense_ack, records) == 0 &&
               offsetof(struct ai_nl_sense_ack, bytes) == 4 &&
               offsetof(struct ai_nl_sense_ack, ai_err) == 8,
               "ai_nl_sense_ack offsets");

_Static_assert(sizeof(struct ai_nl_act) == 112, "ai_nl_act size");
_Static_assert(offsetof(struct ai_nl_act, trigger_event_id) == 0 &&
               offsetof(struct ai_nl_act, decision_type) == 8 &&
               offsetof(struct ai_nl_act, domain) == 12 &&
               offsetof(struct ai_nl_act, confidence) == 13 &&
               offsetof(struct ai_nl_act, model_version) == 16 &&
               offsetof(struct ai_nl_act, data) == 24 &&
               sizeof(((struct ai_nl_act *)0)->data) == 64 &&
               offsetof(struct ai_nl_act, param) == 88 &&
               sizeof(((struct ai_nl_act *)0)->param) == 24,
               "ai_nl_act offsets");

_Static_assert(sizeof(struct ai_nl_act_ack) == 16, "ai_nl_act_ack size");
_Static_assert(offsetof(struct ai_nl_act_ack, executed) == 0 &&
               offsetof(struct ai_nl_act_ack, hit) == 4 &&
               offsetof(struct ai_nl_act_ack, ai_err) == 8,
               "ai_nl_act_ack offsets");

_Static_assert(sizeof(struct ai_nl_reg) == 8, "ai_nl_reg size");
_Static_assert(offsetof(struct ai_nl_reg, flags) == 0, "ai_nl_reg offsets");

_Static_assert(sizeof(struct ai_nl_reg_ack) == 8, "ai_nl_reg_ack size");

/* ---- 客户端 ---- */

#define AI_NL_DEFAULT_TIMEOUT_MS 3000   /* 单次收包超时 */
#define AI_NL_DEFAULT_RETRIES    2      /* 超时后 recv 额外尝试次数（不重发请求） */

/* 应答接收缓冲：内核应答总长 <= NLMSG_HDRLEN + AI_NL_PAYLOAD_MAX */
#define AI_NL_RX_BUF_LEN (NLMSG_HDRLEN + AI_NL_PAYLOAD_MAX)

/*
 * ai_nl_client - NETLINK_AI 客户端句柄
 *
 * 生命周期：open（分配 rx_buf、socket+bind）→ 若干次请求 → close。
 * 每次请求只发送一次（SENSE 会排空内核 ring、ACT 会执行策略，
 * 重发会造成副作用，因此超时只重试收包，不重发）。
 */
struct ai_nl_client {
    int fd;                     /* NETLINK_AI socket，-1=未打开 */
    unsigned int portid;        /* bind 后内核分配的本地 portid */
    unsigned int next_seq;      /* 请求序号（单调递增，应答按 seq 匹配） */
    unsigned int timeout_ms;    /* 单次 recv 超时（SO_RCVTIMEO） */
    unsigned int retries;       /* recv 超时后的额外尝试次数 */
    void *rx_buf;               /* 应答接收缓冲（open 分配，close 释放） */
};

/*
 * ai_nl_client_open - 创建 NETLINK_AI socket 并绑定
 * @cli: 客户端句柄（须未初始化或已 close，本函数会先清零）
 * 返回: AI_OK / AI_ERR_MEMORY / AI_ERR_NETWORK / AI_ERR_INVALID_ARG
 */
int ai_nl_client_open(struct ai_nl_client *cli);

/*
 * ai_nl_client_close - 关闭客户端（幂等，可安全重复调用）
 */
void ai_nl_client_close(struct ai_nl_client *cli);

/*
 * ai_nl_send_sense - AI_CMD_SENSE：拉取内核遥测记录
 * @cpu:         CPU 编号或 AI_NL_SENSE_CPU_ALL
 * @max_records: 1..AI_NL_SENSE_MAX_RECORDS（与内核校验一致）
 * @format:      AI_NL_FORMAT_RAW / AI_NL_FORMAT_HUMAN
 * @ack:         出参，应答头（records/bytes/ai_err）
 * @stream:      出参缓冲，记录流；容量不足时返回 AI_ERR_INVALID_ARG
 *               （不静默截断），建议直接给 AI_NL_PAYLOAD_MAX
 * @stream_cap:  stream 缓冲容量
 * @stream_len:  出参，记录流实际字节数（= ack.bytes）
 * @kern_err:    出参（可 NULL），内核拒绝时收到正 errno
 * 返回: AI_OK / AI_ERR_API（内核拒绝）/ AI_ERR_NETWORK / AI_ERR_PARSE /
 *       AI_ERR_INVALID_ARG
 */
int ai_nl_send_sense(struct ai_nl_client *cli,
                     __u32 cpu, __u32 max_records, __u32 format,
                     struct ai_nl_sense_ack *ack,
                     void *stream, size_t stream_cap, size_t *stream_len,
                     int *kern_err);

/*
 * ai_nl_send_act - AI_CMD_ACT：下发决策指令（内核需 CAP_SYS_ADMIN）
 * @req:      决策内容（domain 0..12、confidence 0..100，客户端先做
 *            与内核一致的预校验；req.param 非空 = 按参数名定向 apply
 *            （内核按动作名全等或末段匹配），空 = 按 domain 广播）
 * @ack:      出参，执行结果（executed/hit/ai_err；ai_err 为负表示
 *            策略层报错，此时消息仍是成功应答而非 NLMSG_ERROR）
 * @kern_err: 出参（可 NULL），内核拒绝时收到正 errno
 * 返回: 同 ai_nl_send_sense
 */
int ai_nl_send_act(struct ai_nl_client *cli,
                   const struct ai_nl_act *req,
                   struct ai_nl_act_ack *ack,
                   int *kern_err);

/*
 * ai_nl_send_act2 - AI_CMD_ACT2：nlattr 载荷下发决策指令（K1 D1；v1
 * ai_nl_send_act 一字不动，两轨并存）。必备 DOMAIN+TYPE+PARAM；其余
 * 可选（零=缺省，attr 恒携带——消息形状恒定）。trace_hi/trace_lo 任一
 * 非零=显式携带（内核原样采用不铸）；全零=由内核铸造（D2），铸造结果
 * 从 ack 回读。
 * @req:      决策内容（domain 0..12、confidence 0..100、param 非空且
 *            NUL 结尾 ≤23 字节——客户端先做与内核一致的预校验）
 * @ack:      出参，执行结果（executed/hit/ai_err + decision_id/trace）
 * @kern_err: 出参（可 NULL），内核拒绝时收到正 errno
 * 返回: 同 ai_nl_send_sense
 */
struct ai_nl_act2_req {
    __u8  domain;         /* AI_DEC_ATTR_DOMAIN（u8 载荷）*/
    __u32 decision_type;  /* AI_DEC_ATTR_TYPE（u32 载荷）*/
    __u8  confidence;     /* AI_DEC_ATTR_CONFIDENCE（u8 载荷，0-100）*/
    __u32 model_version;  /* AI_DEC_ATTR_MODEL_VER（u32 载荷）*/
    __u64 trig_evid;      /* AI_DEC_ATTR_TRIG_EVID（u64 载荷）*/
    char  param[AI_NL_ACT_PARAM_LEN];   /* AI_DEC_ATTR_PARAM（非空 NUL 结尾）*/
    __u64 data[8];        /* AI_DEC_ATTR_DATA（64B 定长）*/
    __u64 trace_hi;       /* AI_DEC_ATTR_TRACE_HI（0:0=内核铸）*/
    __u64 trace_lo;       /* AI_DEC_ATTR_TRACE_LO */
    __u64 intent_id;      /* AI_DEC_ATTR_INTENT（0=未供给）*/
    __u64 parent_id;      /* AI_DEC_ATTR_PARENT（0=无）*/
    __u32 agent;          /* AI_DEC_ATTR_AGENT（enum ai_agent_id）*/
    __s64 expected;       /* AI_DEC_ATTR_EXPECTED（0=未供给）*/
};

_Static_assert(sizeof(struct ai_nl_act2_req) == 160, "ai_nl_act2_req size");
_Static_assert(offsetof(struct ai_nl_act2_req, domain) == 0 &&
               offsetof(struct ai_nl_act2_req, decision_type) == 4 &&
               offsetof(struct ai_nl_act2_req, confidence) == 8 &&
               offsetof(struct ai_nl_act2_req, model_version) == 12 &&
               offsetof(struct ai_nl_act2_req, trig_evid) == 16 &&
               offsetof(struct ai_nl_act2_req, param) == 24 &&
               offsetof(struct ai_nl_act2_req, data) == 48 &&
               offsetof(struct ai_nl_act2_req, trace_hi) == 112 &&
               offsetof(struct ai_nl_act2_req, trace_lo) == 120 &&
               offsetof(struct ai_nl_act2_req, intent_id) == 128 &&
               offsetof(struct ai_nl_act2_req, parent_id) == 136 &&
               offsetof(struct ai_nl_act2_req, agent) == 144 &&
               offsetof(struct ai_nl_act2_req, expected) == 152,
               "ai_nl_act2_req offsets");

int ai_nl_send_act2(struct ai_nl_client *cli,
                    const struct ai_nl_act2_req *req,
                    struct ai_nl_act2_ack *ack,
                    int *kern_err);

/*
 * ai_nl_pack_act_batch / ai_nl_send_act_batch - AI_CMD_ACT_BATCH：批量
 * 事务（K2 D1/D9；嵌套 nlattr——AIKernel 用户态客户端首个嵌套面）。
 * 一个 batch=一个 decision_id；ops 每元组一个 AI_BATCH_ATTR_OPS
 * （NLA_F_NESTED），内嵌 PARAM（复用 AI_DEC_ATTR_PARAM）+ VALUE(u64
 * 必备) + PID(u32 可选，ops[].pid==0 不带)。批级 AUTO_ROLLBACK_MS(u32)
 * + CONFIRM_TOKEN(u64) 恒携带（零=显式缺省）+ TRACE_HI/LO/INTENT/AGENT
 * 复用 AI_DEC_ATTR_* 号（沿 act2「可选恒携带、消息形状恒定」先例）。
 * 对齐规则：NLA_ALIGN(4)——attr 头 4B（u16 nla_len 含头/u16 nla_type），
 * 载荷补零到 4 的倍数；嵌套由 nla_type 高位 NLA_F_NESTED(1<<8) 标记，
 * 内层 attr 流即外层载荷（无嵌套长度魔法——nla_len 覆盖头+全部内层）。
 * 预校验与内核同口径：1<=n<=27、param 非空 NUL 结尾 <=23B、重复
 * param 名拒收（-EINVAL 同义 -> AI_ERR_INVALID_ARG）。
 *
 * ai_nl_pack_act_batch 为纯打包器（单测面：tests/test_netlink_batch.c
 * 逐字节断言）；attr_len 出参=编码后 attr 流长度。
 */
struct ai_nl_batch_op {
    char  param[AI_NL_ACT_PARAM_LEN];  /* 定向参数名（非空 NUL 结尾 ≤23）*/
    __u64 value;                       /* 钳前请求值 */
    __u32 pid;                         /* 0=不带 PID attr（全局参数） */
    __u32 reserved;                    /* 必须为 0（前向兼容） */
};

struct ai_nl_batch_opts {
    __u32 auto_rollback_ms;   /* 0=不 arm（缺省） */
    __u32 agent;              /* enum ai_agent_id */
    __u64 confirm_token;      /* 0=不带语义（blast 拒后重试携带） */
    __u64 trace_hi;           /* 全零=内核铸造（ack 回读） */
    __u64 trace_lo;
    __u64 intent_id;          /* 0=未供给 */
};

_Static_assert(sizeof(struct ai_nl_batch_op) == 40, "ai_nl_batch_op size");
_Static_assert(offsetof(struct ai_nl_batch_op, param) == 0 &&
               offsetof(struct ai_nl_batch_op, value) == 24 &&
               offsetof(struct ai_nl_batch_op, pid) == 32,
               "ai_nl_batch_op offsets");
_Static_assert(sizeof(struct ai_nl_batch_opts) == 40, "ai_nl_batch_opts size");

/* 最坏 attr 流：27 元组×52B（OPS 头 4+PARAM 28+VALUE 12+PID 8）+ 批级
 * 64B（AUTO_ROLLBACK_MS 8+CONFIRM_TOKEN 12+TRACE_HI/LO 12×2+INTENT
 * 12+AGENT 8）=1468B，取 1600 裕量 */
#define AI_BATCH_ATTRS_MAX 1600

int ai_nl_pack_act_batch(unsigned char *attrs, size_t cap,
                         const struct ai_nl_batch_op *ops, size_t n,
                         const struct ai_nl_batch_opts *opts,
                         size_t *attr_len);

int ai_nl_send_act_batch(struct ai_nl_client *cli,
                         const struct ai_nl_batch_op *ops, size_t n,
                         const struct ai_nl_batch_opts *opts,
                         struct ai_nl_batch_ack *ack,
                         int *kern_err);

/*
 * ai_nl_trace_mint - 进程级统一 trace_id 铸造（K1 D9：executor 换轨用）。
 * hi：进程内一次铸造（8B /dev/urandom，失败退 time^pid），恒非零、
 *     进程级恒定；lo：原子递增计数（自 1 起）。调用方填入
 * req->trace_hi/trace_lo 显式携带（内核不再改写）。
 */
void ai_nl_trace_mint(__u64 *hi, __u64 *lo);

/*
 * ai_nl_send_reg - AI_CMD_REG：登记本进程 portid（内核需 CAP_SYS_ADMIN）
 *
 * 幂等性：内核按 portid 去重（AIKernel/net/ai_netlink.c ai_nl_reg_add，
 * 32 槽上限，满返回 EBUSY）；同一进程内 netlink autobind 固定取
 * task_tgid_vnr(current)（net/netlink/af_netlink.c netlink_autobind），
 * 因此本进程反复 open+reg 得到同一 portid，天然幂等。
 *
 * @flags:    0（预留位）
 * @ai_err:   出参（可 NULL），内核回传的 ai_err（AI_OK）
 * @count:    出参（可 NULL），内核当前已登记 portid 数
 * @kern_err: 出参（可 NULL），内核拒绝时收到正 errno
 * 返回: 同 ai_nl_send_sense
 */
int ai_nl_send_reg(struct ai_nl_client *cli,
                   __u32 flags,
                   __s32 *ai_err, __u32 *count,
                   int *kern_err);

/*
 * ai_nl_errno_hint - 内核 errno 的人类可读提示（NETLINK_AI 语义）
 * 返回: 中文提示串；无匹配返回 NULL（调用方退回 strerror）
 */
const char *ai_nl_errno_hint(int errno_val);

#endif /* _AI_NETLINK_CLIENT_H */
