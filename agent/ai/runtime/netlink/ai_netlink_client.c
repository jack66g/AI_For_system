/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ai_netlink_client.c - NETLINK_AI 用户态客户端实现（Agent 侧）
 *
 * 对端内核：AIKernel/net/ai_netlink.c（实读核对，协议细节见头文件注释）。
 *
 * 传输路径：
 *   socket(AF_NETLINK, SOCK_RAW, NETLINK_AI=31) → bind(pid=0，内核分配) →
 *   sendto(nlmsghdr + 裸结构载荷) → recvmsg(超时重试) → nlmsghdr 解析
 *
 * 关键内核行为（net/netlink/af_netlink.c + AIKernel/net/ai_netlink.c）：
 *   - 请求 nlmsg_flags 必须带 NLM_F_REQUEST，否则 netlink_rcv_skb 静默跳过
 *   - 不设 NLM_F_ACK：成功应答类型=命令号且 nlmsg_seq 回显；失败应答为
 *     NLMSG_ERROR（nlmsgerr.error=负 errno）
 *   - SENSE/ACT/REG 的成功应答均由内核端主动 netlink_unicast 回本进程
 *
 * 资源约定：open 分配 rx_buf / close 释放，任何失败路径都走 close 或
 * 就地 free，无泄漏；请求只发送一次，超时仅重试收包（SENSE 排空 ring、
 * ACT 执行策略，重发会引入副作用）。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "netlink/ai_netlink_client.h"

/* ---- 内部辅助：构造请求 ---- */

/*
 * ai_nl_build_req - 在 buf 中填充 nlmsghdr + 裸结构载荷（无 NLA）
 *
 * 内核端以 nlmsg_data(nlh) 直接按 struct ai_nl_* 取载荷（裸结构，
 * 非 netlink attribute 流），因此载荷长度 = sizeof(结构) 原样传递。
 * buf 容量须 >= NLMSG_HDRLEN + payload_len。
 */
static void ai_nl_build_req(void *buf, __u16 type,
                            const void *payload, size_t payload_len,
                            __u32 seq, unsigned int portid)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

    memset(buf, 0, NLMSG_HDRLEN + payload_len);
    nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + payload_len);
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = NLM_F_REQUEST;   /* 必须：否则内核静默跳过 */
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_pid = portid;
    if (payload_len)
        memcpy(NLMSG_DATA(nlh), payload, payload_len);
}

/* ---- 内部辅助：发送请求（只发一次） ---- */

static int ai_nl_send_req(struct ai_nl_client *cli,
                          const void *req_buf, size_t req_len)
{
    struct sockaddr_nl dst;
    ssize_t sent;

    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    dst.nl_pid = 0;     /* 0 = 内核 */
    dst.nl_groups = 0;

    sent = sendto(cli->fd, req_buf, req_len, 0,
                  (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0 || (size_t)sent != req_len)
        return AI_ERR_NETWORK;  /* errno 保持有效，供调用方 strerror */
    return AI_OK;
}

/* ---- 内部辅助：收取并匹配应答 ---- */

/*
 * ai_nl_recv_match - 收取一条应答并与 seq/type 匹配
 *
 * 匹配规则：
 *   - 来源必须为内核（src.nl_pid == 0），否则视为杂音丢弃
 *   - nlmsg_seq 必须等于本次请求 seq，否则视为上一请求的迟到应答丢弃
 *     （丢弃后继续 recv，不消耗发送机会）
 *   - NLMSG_ERROR：nlmsgerr.error != 0 时 *kern_err 收正 errno 并返回
 *     AI_ERR_API；error == 0（ACK）在本客户端不请求 NLM_F_ACK 的前提下
 *     不应出现，按协议异常处理
 *
 * 重试语义：recvmsg 超时（EAGAIN/EWOULDBLOCK）或 EINTR 时进入下一轮
 * attempt（共 retries+1 次），期间不重发请求。
 */
static int ai_nl_recv_match(struct ai_nl_client *cli, __u16 expect_type,
                            __u32 seq, const struct nlmsghdr **nlh_out,
                            int *kern_err)
{
    unsigned int attempt;

    if (kern_err)
        *kern_err = 0;

    for (attempt = 0; attempt <= cli->retries; attempt++) {
        struct sockaddr_nl src;
        struct iovec iov;
        struct msghdr msg;
        struct nlmsghdr *nlh;
        ssize_t n;

        memset(&src, 0, sizeof(src));
        memset(&iov, 0, sizeof(iov));
        memset(&msg, 0, sizeof(msg));
        iov.iov_base = cli->rx_buf;
        iov.iov_len = AI_NL_RX_BUF_LEN;
        msg.msg_name = &src;
        msg.msg_namelen = sizeof(src);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        n = recvmsg(cli->fd, &msg, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;   /* SO_RCVTIMEO 超时：下一轮 attempt */
            return AI_ERR_NETWORK;
        }
        if ((size_t)n < (size_t)NLMSG_HDRLEN)
            return AI_ERR_PARSE;
        if (msg.msg_flags & MSG_TRUNC)
            return AI_ERR_PARSE;    /* 应答超过缓冲上限：协议漂移 */

        if (msg.msg_namelen >= sizeof(src) && src.nl_pid != 0)
            continue;   /* 非内核来源，丢弃 */

        nlh = (struct nlmsghdr *)cli->rx_buf;
        if ((size_t)nlh->nlmsg_len < (size_t)NLMSG_HDRLEN ||
            (size_t)nlh->nlmsg_len > (size_t)n)
            return AI_ERR_PARSE;
        if (nlh->nlmsg_seq != seq)
            continue;   /* 过期应答，丢弃继续等 */

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            const struct nlmsgerr *err;

            if ((size_t)nlh->nlmsg_len <
                (size_t)(NLMSG_HDRLEN + sizeof(struct nlmsgerr)))
                return AI_ERR_PARSE;
            err = (const struct nlmsgerr *)NLMSG_DATA(nlh);
            if (err->error == 0)
                return AI_ERR_PARSE;    /* 未请求 ACK，error=0 不合协议 */
            if (err->msg.nlmsg_seq != 0 && err->msg.nlmsg_seq != seq)
                continue;   /* 过期错误应答，丢弃 */
            if (kern_err)
                *kern_err = err->error < 0 ? -err->error : (int)err->error;
            return AI_ERR_API;
        }
        if (nlh->nlmsg_type != expect_type)
            continue;   /* 非本请求应答类型，丢弃 */

        *nlh_out = nlh;
        return AI_OK;
    }
    return AI_ERR_NETWORK;  /* 重试耗尽仍无应答 */
}

/* ---- 客户端生命周期 ---- */

int ai_nl_client_open(struct ai_nl_client *cli)
{
    struct sockaddr_nl addr;
    struct timeval tv;
    socklen_t alen;
    int saved;

    if (!cli)
        return AI_ERR_INVALID_ARG;
    memset(cli, 0, sizeof(*cli));
    cli->fd = -1;
    cli->timeout_ms = AI_NL_DEFAULT_TIMEOUT_MS;
    cli->retries = AI_NL_DEFAULT_RETRIES;

    cli->rx_buf = malloc(AI_NL_RX_BUF_LEN);
    if (!cli->rx_buf)
        return AI_ERR_MEMORY;

    cli->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_AI);
    if (cli->fd < 0) {
        free(cli->rx_buf);
        cli->rx_buf = NULL;
        return AI_ERR_NETWORK;
    }

    /* 收发超时；setsockopt 失败不致命（退化为默认阻塞行为） */
    tv.tv_sec = (long)(cli->timeout_ms / 1000);
    tv.tv_usec = (long)((cli->timeout_ms % 1000) * 1000);
    if (setsockopt(cli->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        /* 非致命，保留默认行为 */
    }
    if (setsockopt(cli->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        /* 非致命，保留默认行为 */
    }

    /* bind：nl_pid=0 由内核自动分配（netlink_autobind 取 task_tgid_vnr，
     * 同进程重开 socket 得到同一 portid，reg 幂等的基础） */
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    if (bind(cli->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        saved = errno;
        close(cli->fd);
        cli->fd = -1;
        free(cli->rx_buf);
        cli->rx_buf = NULL;
        errno = saved;  /* 保留 bind 失败的 errno 供调用方打印 */
        return AI_ERR_NETWORK;
    }

    /* 取内核分配的 portid（getsockname 失败仅影响展示，不致命） */
    alen = sizeof(addr);
    if (getsockname(cli->fd, (struct sockaddr *)&addr, &alen) == 0 &&
        addr.nl_family == AF_NETLINK)
        cli->portid = addr.nl_pid;

    cli->next_seq = 1;
    return AI_OK;
}

void ai_nl_client_close(struct ai_nl_client *cli)
{
    if (!cli)
        return;
    if (cli->fd >= 0) {
        close(cli->fd);
        cli->fd = -1;
    }
    free(cli->rx_buf);
    cli->rx_buf = NULL;
}

/* ---- AI_CMD_SENSE ---- */

int ai_nl_send_sense(struct ai_nl_client *cli,
                     __u32 cpu, __u32 max_records, __u32 format,
                     struct ai_nl_sense_ack *ack,
                     void *stream, size_t stream_cap, size_t *stream_len,
                     int *kern_err)
{
    unsigned char req[NLMSG_HDRLEN + sizeof(struct ai_nl_sense)];
    const unsigned char *data;
    const struct ai_nl_sense_ack *ack_rx;
    const struct nlmsghdr *nlh = NULL;
    struct ai_nl_sense payload;
    size_t payload_len, stream_bytes;
    __u32 seq;
    int rc;

    if (!cli || cli->fd < 0 || !ack || !stream || !stream_len)
        return AI_ERR_INVALID_ARG;

    /* 与内核端 ai_nl_sense() 校验一致（AIKernel/net/ai_netlink.c:110-115） */
    if (max_records == 0 || max_records > AI_NL_SENSE_MAX_RECORDS)
        return AI_ERR_INVALID_ARG;
    if (format != AI_NL_FORMAT_RAW && format != AI_NL_FORMAT_HUMAN)
        return AI_ERR_INVALID_ARG;

    memset(&payload, 0, sizeof(payload));
    payload.cpu = cpu;
    payload.max_records = max_records;
    payload.format = format;

    seq = cli->next_seq++;
    ai_nl_build_req(req, AI_CMD_SENSE, &payload, sizeof(payload),
                    seq, cli->portid);

    rc = ai_nl_send_req(cli, req, sizeof(req));
    if (rc != AI_OK)
        return rc;

    rc = ai_nl_recv_match(cli, (__u16)AI_CMD_SENSE, seq, &nlh, kern_err);
    if (rc != AI_OK)
        return rc;

    /* 应答载荷 = ai_nl_sense_ack + 记录流（bytes 字节，不含 ack 头） */
    payload_len = (size_t)nlh->nlmsg_len - NLMSG_HDRLEN;
    if (payload_len < sizeof(struct ai_nl_sense_ack))
        return AI_ERR_PARSE;

    data = (const unsigned char *)NLMSG_DATA(nlh);
    ack_rx = (const struct ai_nl_sense_ack *)data;
    memcpy(ack, ack_rx, sizeof(*ack));

    stream_bytes = payload_len - sizeof(struct ai_nl_sense_ack);
    if (stream_bytes > stream_cap)
        return AI_ERR_INVALID_ARG;  /* 缓冲不足：不截断，调用方扩容重试 */
    if (stream_bytes)
        memcpy(stream, data + sizeof(struct ai_nl_sense_ack), stream_bytes);
    *stream_len = stream_bytes;
    return AI_OK;
}

/* ---- AI_CMD_ACT ---- */

int ai_nl_send_act(struct ai_nl_client *cli,
                   const struct ai_nl_act *req,
                   struct ai_nl_act_ack *ack,
                   int *kern_err)
{
    unsigned char reqbuf[NLMSG_HDRLEN + sizeof(struct ai_nl_act)];
    const unsigned char *data;
    const struct ai_nl_act_ack *ack_rx;
    const struct nlmsghdr *nlh = NULL;
    size_t payload_len;
    __u32 seq;
    int rc;

    if (!cli || cli->fd < 0 || !req || !ack)
        return AI_ERR_INVALID_ARG;

    /* 与内核端 ai_nl_act() 校验一致（AIKernel/net/ai_netlink.c:235：
     * domain 上限 AI_POLICY_DOMAIN_PROC=12，confidence 上限 100）；
     * 缺 CAP_SYS_ADMIN 时内核返回 EACCES（ai_netlink.c:233-234） */
    if (req->domain > AI_NL_DOMAIN_MAX || req->confidence > 100)
        return AI_ERR_INVALID_ARG;

    seq = cli->next_seq++;
    ai_nl_build_req(reqbuf, AI_CMD_ACT, req, sizeof(*req), seq, cli->portid);

    rc = ai_nl_send_req(cli, reqbuf, sizeof(reqbuf));
    if (rc != AI_OK)
        return rc;

    rc = ai_nl_recv_match(cli, (__u16)AI_CMD_ACT, seq, &nlh, kern_err);
    if (rc != AI_OK)
        return rc;

    payload_len = (size_t)nlh->nlmsg_len - NLMSG_HDRLEN;
    if (payload_len < sizeof(struct ai_nl_act_ack))
        return AI_ERR_PARSE;

    data = (const unsigned char *)NLMSG_DATA(nlh);
    ack_rx = (const struct ai_nl_act_ack *)data;
    memcpy(ack, ack_rx, sizeof(*ack));
    return AI_OK;
}

/* ---- AI_CMD_ACT2（K1 D1：nlattr 载荷；v1 AI_CMD_ACT 原样不动） ---- */

/*
 * nla_append - 追加一个 nlattr（手写编码：u16 nla_len/u16 nla_type +
 * payload，NLA_ALIGN(4) 补零）。返回推进后的游标；容量不足返回 NULL。
 */
static unsigned char *nla_append(unsigned char *p, unsigned char *end,
                                 __u16 type, const void *payload, size_t len)
{
    size_t total = (size_t)NLA_HDRLEN + len;
    struct nlattr *nla;

    if (total > (size_t)(end - p))
        return NULL;
    memset(p, 0, NLA_ALIGN(total));
    nla = (struct nlattr *)p;
    nla->nla_len = (__u16)total;
    nla->nla_type = type;
    memcpy(p + NLA_HDRLEN, payload, len);
    return p + NLA_ALIGN(total);
}

int ai_nl_send_act2(struct ai_nl_client *cli,
                    const struct ai_nl_act2_req *req,
                    struct ai_nl_act2_ack *ack,
                    int *kern_err)
{
    /* 最坏 attr 流 220B：DOMAIN 8+TYPE 8+PARAM 28+DATA 68+CONF 8+
     * VER 8+EVID 12+TRACE_HI/LO/INTENT/PARENT 12×4+AGENT 8+EXPECTED 12 */
    unsigned char reqbuf[NLMSG_HDRLEN + 232];
    unsigned char attrs[232];
    unsigned char *p = attrs, *end = attrs + sizeof(attrs);
    const unsigned char *data;
    const struct ai_nl_act2_ack *ack_rx;
    const struct nlmsghdr *nlh = NULL;
    size_t plen, param_len, attr_len;
    __u8 u8v;
    __u32 u32v;
    __u64 u64v;
    __s64 s64v;
    __u32 seq;
    int rc;

    if (!cli || cli->fd < 0 || !req || !ack)
        return AI_ERR_INVALID_ARG;

    /* 与内核端 ai_nl_act() 同口径预校验（domain/confidence 上限）+
     * ACT2 必备 PARAM：非空且在 param[] 内 NUL 结尾（≤23 字节） */
    if (req->domain > AI_NL_DOMAIN_MAX || req->confidence > 100)
        return AI_ERR_INVALID_ARG;
    param_len = strnlen(req->param, sizeof(req->param));
    if (param_len == 0 || param_len >= sizeof(req->param))
        return AI_ERR_INVALID_ARG;

    /* 必备属性（DOMAIN u8 / TYPE u32 / PARAM 字符串带 NUL） */
    u8v = req->domain;
    p = nla_append(p, end, AI_DEC_ATTR_DOMAIN, &u8v, sizeof(u8v));
    u32v = req->decision_type;
    p = nla_append(p, end, AI_DEC_ATTR_TYPE, &u32v, sizeof(u32v));
    p = nla_append(p, end, AI_DEC_ATTR_PARAM, req->param, param_len + 1);
    /* 可选属性恒携带（零值=显式缺省，内核缺省同零；消息形状恒定）：
     * DATA=64B 定长，数值型 attr 直接 u64/u32/u8/s64 载荷 */
    p = nla_append(p, end, AI_DEC_ATTR_DATA, req->data, sizeof(req->data));
    u8v = req->confidence;
    p = nla_append(p, end, AI_DEC_ATTR_CONFIDENCE, &u8v, sizeof(u8v));
    u32v = req->model_version;
    p = nla_append(p, end, AI_DEC_ATTR_MODEL_VER, &u32v, sizeof(u32v));
    u64v = req->trig_evid;
    p = nla_append(p, end, AI_DEC_ATTR_TRIG_EVID, &u64v, sizeof(u64v));
    u64v = req->trace_hi;
    p = nla_append(p, end, AI_DEC_ATTR_TRACE_HI, &u64v, sizeof(u64v));
    u64v = req->trace_lo;
    p = nla_append(p, end, AI_DEC_ATTR_TRACE_LO, &u64v, sizeof(u64v));
    u64v = req->intent_id;
    p = nla_append(p, end, AI_DEC_ATTR_INTENT, &u64v, sizeof(u64v));
    u64v = req->parent_id;
    p = nla_append(p, end, AI_DEC_ATTR_PARENT, &u64v, sizeof(u64v));
    u32v = req->agent;
    p = nla_append(p, end, AI_DEC_ATTR_AGENT, &u32v, sizeof(u32v));
    s64v = req->expected;
    p = nla_append(p, end, AI_DEC_ATTR_EXPECTED, &s64v, sizeof(s64v));
    if (!p)
        return AI_ERR_INVALID_ARG;  /* 容量不足：编码防御（220<232） */

    attr_len = (size_t)(p - attrs);
    seq = cli->next_seq++;
    ai_nl_build_req(reqbuf, AI_CMD_ACT2, attrs, attr_len, seq, cli->portid);

    rc = ai_nl_send_req(cli, reqbuf, NLMSG_HDRLEN + attr_len);
    if (rc != AI_OK)
        return rc;

    rc = ai_nl_recv_match(cli, (__u16)AI_CMD_ACT2, seq, &nlh, kern_err);
    if (rc != AI_OK)
        return rc;

    plen = (size_t)nlh->nlmsg_len - NLMSG_HDRLEN;
    if (plen < sizeof(struct ai_nl_act2_ack))
        return AI_ERR_PARSE;

    data = (const unsigned char *)NLMSG_DATA(nlh);
    ack_rx = (const struct ai_nl_act2_ack *)data;
    memcpy(ack, ack_rx, sizeof(*ack));
    return AI_OK;
}

/* ---- AI_CMD_ACT_BATCH（K2 D1/D9：嵌套 nlattr；v1/ACT2 一字不动） ---- */

int ai_nl_pack_act_batch(unsigned char *attrs, size_t cap,
                         const struct ai_nl_batch_op *ops, size_t n,
                         const struct ai_nl_batch_opts *opts,
                         size_t *attr_len)
{
    unsigned char *p = attrs, *end = attrs + cap;
    unsigned char inner[48];   /* 元组内层最坏 48B（28+12+8） */
    unsigned char *q, *qend = inner + sizeof(inner);
    __u32 u32v;
    __u64 u64v;
    size_t i, j, param_len, inner_len;

    if (!attrs || !ops || !opts || !attr_len || n == 0 ||
        n > AI_BATCH_MAX_OPS)
        return AI_ERR_INVALID_ARG;
    for (i = 0; i < n; i++) {
        param_len = strnlen(ops[i].param, sizeof(ops[i].param));
        if (param_len == 0 || param_len >= sizeof(ops[i].param))
            return AI_ERR_INVALID_ARG;
        if (ops[i].reserved != 0)
            return AI_ERR_INVALID_ARG;
        /* 重复 param 名拒收（-EINVAL 同义：防同参双值歧义，D1） */
        for (j = 0; j < i; j++)
            if (strcmp(ops[i].param, ops[j].param) == 0)
                return AI_ERR_INVALID_ARG;
    }

    /* 每元组：内层 {PARAM, VALUE[, PID]} 编入 inner，再作为 OPS 嵌套
     * attr（nla_type 置 NLA_F_NESTED）载荷追加——平铺 nla_parse 同型
     * attr 互覆盖，重复元组必须嵌套（rows-a §3 实锚） */
    for (i = 0; i < n; i++) {
        param_len = strnlen(ops[i].param, sizeof(ops[i].param));
        q = inner;
        q = nla_append(q, qend, AI_DEC_ATTR_PARAM, ops[i].param,
                       param_len + 1);
        if (!q)
            return AI_ERR_INVALID_ARG;
        u64v = ops[i].value;
        q = nla_append(q, qend, AI_DEC_ATTR_VALUE, &u64v, sizeof(u64v));
        if (!q)
            return AI_ERR_INVALID_ARG;
        if (ops[i].pid != 0) {
            u32v = ops[i].pid;
            q = nla_append(q, qend, AI_DEC_ATTR_PID, &u32v, sizeof(u32v));
            if (!q)
                return AI_ERR_INVALID_ARG;
        }
        inner_len = (size_t)(q - inner);
        p = nla_append(p, end, AI_BATCH_ATTR_OPS | NLA_F_NESTED,
                       inner, inner_len);
        if (!p)
            return AI_ERR_INVALID_ARG;
    }
    /* 批级：AUTO_ROLLBACK_MS + CONFIRM_TOKEN + TRACE/INTENT/AGENT
     * （复用 AI_DEC_ATTR_* 号；零=显式缺省，消息形状恒定） */
    u32v = opts->auto_rollback_ms;
    p = nla_append(p, end, AI_BATCH_ATTR_AUTO_ROLLBACK_MS, &u32v,
                   sizeof(u32v));
    u64v = opts->confirm_token;
    p = nla_append(p, end, AI_BATCH_ATTR_CONFIRM_TOKEN, &u64v,
                   sizeof(u64v));
    u64v = opts->trace_hi;
    p = nla_append(p, end, AI_DEC_ATTR_TRACE_HI, &u64v, sizeof(u64v));
    u64v = opts->trace_lo;
    p = nla_append(p, end, AI_DEC_ATTR_TRACE_LO, &u64v, sizeof(u64v));
    u64v = opts->intent_id;
    p = nla_append(p, end, AI_DEC_ATTR_INTENT, &u64v, sizeof(u64v));
    u32v = opts->agent;
    p = nla_append(p, end, AI_DEC_ATTR_AGENT, &u32v, sizeof(u32v));
    if (!p)
        return AI_ERR_INVALID_ARG;  /* 容量不足：编码防御（1468<1600） */

    *attr_len = (size_t)(p - attrs);
    return AI_OK;
}

int ai_nl_send_act_batch(struct ai_nl_client *cli,
                         const struct ai_nl_batch_op *ops, size_t n,
                         const struct ai_nl_batch_opts *opts,
                         struct ai_nl_batch_ack *ack,
                         int *kern_err)
{
    unsigned char reqbuf[NLMSG_HDRLEN + AI_BATCH_ATTRS_MAX];
    unsigned char attrs[AI_BATCH_ATTRS_MAX];
    const unsigned char *data;
    const struct ai_nl_batch_ack *ack_rx;
    const struct nlmsghdr *nlh = NULL;
    size_t attr_len = 0, plen;
    __u32 seq;
    int rc;

    if (!cli || cli->fd < 0 || !ack)
        return AI_ERR_INVALID_ARG;

    rc = ai_nl_pack_act_batch(attrs, sizeof(attrs), ops, n, opts, &attr_len);
    if (rc != AI_OK)
        return rc;

    seq = cli->next_seq++;
    ai_nl_build_req(reqbuf, AI_CMD_ACT_BATCH, attrs, attr_len, seq,
                    cli->portid);

    rc = ai_nl_send_req(cli, reqbuf, NLMSG_HDRLEN + attr_len);
    if (rc != AI_OK)
        return rc;

    rc = ai_nl_recv_match(cli, (__u16)AI_CMD_ACT_BATCH, seq, &nlh, kern_err);
    if (rc != AI_OK)
        return rc;

    plen = (size_t)nlh->nlmsg_len - NLMSG_HDRLEN;
    if (plen < sizeof(struct ai_nl_batch_ack))
        return AI_ERR_PARSE;

    data = (const unsigned char *)NLMSG_DATA(nlh);
    ack_rx = (const struct ai_nl_batch_ack *)data;
    memcpy(ack, ack_rx, sizeof(*ack));
    return AI_OK;
}

void ai_nl_trace_mint(__u64 *hi, __u64 *lo)
{
    /* 进程级一次铸造（D9）：hi 恒非零且进程内恒定；lo 原子递增 */
    static __u64 base;
    static unsigned long long seq;

    if (!hi || !lo)
        return;
    if (__atomic_load_n(&base, __ATOMIC_RELAXED) == 0) {
        __u64 r = 0, expect = 0;
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

        if (fd >= 0) {
            ssize_t n = read(fd, &r, sizeof(r));

            close(fd);
            if (n != (ssize_t)sizeof(r))
                r = 0;
        }
        if (r == 0) {
            /* 退路：time^pid（D9 允许口径；秒级时钟+nspid 混淆熵） */
            struct timespec ts;

            clock_gettime(CLOCK_REALTIME, &ts);
            r = ((__u64)ts.tv_sec << 20) ^ (__u64)ts.tv_nsec ^
                (__u64)getpid();
        }
        r |= 1;     /* 恒非零（D2：trace 全决策恒非零） */
        /* 并发首次铸造：CAS 定胜负，败者采用赢者的 base（进程级恒定） */
        __atomic_compare_exchange_n(&base, &expect, r, 0,
                                    __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
    *hi = __atomic_load_n(&base, __ATOMIC_RELAXED);
    *lo = __atomic_add_fetch(&seq, 1, __ATOMIC_RELAXED);
}

/* ---- AI_CMD_REG ---- */

int ai_nl_send_reg(struct ai_nl_client *cli,
                   __u32 flags,
                   __s32 *ai_err, __u32 *count,
                   int *kern_err)
{
    unsigned char reqbuf[NLMSG_HDRLEN + sizeof(struct ai_nl_reg)];
    const unsigned char *data;
    const struct ai_nl_reg_ack *ack_rx;
    const struct nlmsghdr *nlh = NULL;
    struct ai_nl_reg payload;
    struct ai_nl_reg_ack ack;
    size_t payload_len;
    __u32 seq;
    int rc;

    if (!cli || cli->fd < 0)
        return AI_ERR_INVALID_ARG;

    memset(&payload, 0, sizeof(payload));
    payload.flags = flags;  /* 0=仅登记（uapi 预留位） */

    seq = cli->next_seq++;
    ai_nl_build_req(reqbuf, AI_CMD_REG, &payload, sizeof(payload),
                    seq, cli->portid);

    rc = ai_nl_send_req(cli, reqbuf, sizeof(reqbuf));
    if (rc != AI_OK)
        return rc;

    rc = ai_nl_recv_match(cli, (__u16)AI_CMD_REG, seq, &nlh, kern_err);
    if (rc != AI_OK)
        return rc;

    payload_len = (size_t)nlh->nlmsg_len - NLMSG_HDRLEN;
    if (payload_len < sizeof(struct ai_nl_reg_ack))
        return AI_ERR_PARSE;

    data = (const unsigned char *)NLMSG_DATA(nlh);
    ack_rx = (const struct ai_nl_reg_ack *)data;
    memcpy(&ack, ack_rx, sizeof(ack));
    if (ai_err)
        *ai_err = ack.ai_err;
    if (count)
        *count = ack.count;
    return AI_OK;
}

/* ---- errno 语义提示 ---- */

const char *ai_nl_errno_hint(int errno_val)
{
    switch (errno_val) {
    case EACCES:
        /* 内核端 ACT/REG 缺 CAP_SYS_ADMIN 返回 -EACCES（ai_netlink.c:234/277） */
        return "权限不足：该 NETLINK_AI 操作需要 CAP_SYS_ADMIN（请用 root/sudo 运行）";
    case EPERM:
        /* 内核 AI 子系统未启用（ai.enabled=0）时各命令返回 -EPERM */
        return "内核 AI 子系统未启用（启动参数 ai.enabled=0），NETLINK_AI 协议族未创建";
    case EBUSY:
        /* REG 登记表 32 槽占满返回 AI_ERR_BUSY -> -EBUSY（ai_netlink.c:55-57） */
        return "内核 REG 登记表已满（上限 32 个 portid）";
    case EINVAL:
        return "参数超出内核校验范围（domain 0~12 / confidence 0~100 / max_records 1~4096）";
    case ENOBUFS:
        return "内核发送缓冲不足，可减小 max_records 后重试";
    default:
        return NULL;
    }
}
