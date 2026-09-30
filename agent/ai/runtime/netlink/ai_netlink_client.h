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

/* REG 请求载荷（include/uapi/linux/ai_netlink.h:83-86） */
struct ai_nl_reg {
    __u32 flags;        /* 0=仅登记（预留位） */
    __u32 reserved;
};

#endif /* !AI_NL_UAPI_FROM_HOST */

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
_Static_assert(AI_NL_PAYLOAD_MAX == 65536, "AI_NL_PAYLOAD_MAX drifted");

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
