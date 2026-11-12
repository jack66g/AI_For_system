/* SPDX-License-Identifier: GPL-2.0 */
/*
 * cmd_netlink.c - netlink 命令实现
 *
 * NETLINK_AI（协议族 31）用户态通道：让 AI 直接对内核下指令/读遥测。
 *
 *   netlink sense [all|<cpu>] [count] [raw|human]
 *       - AI_CMD_SENSE：拉取内核 AI 遥测记录（无权限要求）
 *   netlink act <domain> <decision_type> [confidence] [hexdata]
 *       - AI_CMD_ACT：下发决策指令（需 CAP_SYS_ADMIN，交互确认）
 *   netlink act2 <domain> <decision_type> [confidence] [hexdata] [k=v ...]
 *       - AI_CMD_ACT2（K1 D1）：nlattr 载荷，携带统一 trace_id/intent
 *         等元数据（需 CAP_SYS_ADMIN，交互确认）。k: param=<参数名>（
 *         必填）、trace_id=0x<hex>:0x<hex>（键名 trace/trace_id 等价）、
 *         intent= parent= agent= expected= ver= trig_evid=
 *   netlink act2batch <param=value[:pid] ...> [k=v ...]
 *       - AI_CMD_ACT_BATCH（K2 D1/D9）：批量事务（嵌套 nlattr，一个
 *         decision_id，任一项失败整体回滚）。元组 param=value[:pid]
 *         （1-27 个，重复 param 拒收）；k: rollback_ms= trace_id=
 *         intent= agent=（batch 无 expected）。需 CAP_SYS_ADMIN，
 *         交互确认；blast radius 超阈内核拒（回显 token——重试带
 *         confirm_token 走 HTTP /act ops）
 *   netlink confirm <decision_id>
 *       - 写 /sys/kernel/ai/policy/confirm（K2 D5：取消 pending 自动
 *         回滚；已回滚返回 ENOENT）
 *   netlink reg
 *       - AI_CMD_REG：登记本进程 portid（需 CAP_SYS_ADMIN，内核幂等去重）
 *
 * 协议与传输实现在 runtime/netlink/ai_netlink_client.c；
 * 输出风格对齐 cmd_status.c / cmd_network.c。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_lang.h"
#include "netlink/ai_netlink_client.h"

/* 决策域名称（对齐 AIKernel/core/ai_policy.h enum ai_policy_domain 0~12） */
static const char *const domain_names[] = {
    "general", "sched", "mm", "io", "net", "security", "power",
    "vfs", "interrupt", "lock", "time", "virt", "proc",
};

static const char *domain_name(__u32 domain)
{
    if (domain <= AI_NL_DOMAIN_MAX)
        return domain_names[domain];
    return "?";
}

static void netlink_usage(void)
{
    printf("Usage:\n");
    printf("  netlink sense [all|<cpu>] [count] [raw|human]");
    printf("%s", tr(TR_NL_HELP_SENSE));
    printf("  netlink act <domain> <decision_type> [confidence] [hexdata]\n");
    printf("%s", tr(TR_NL_HELP_ACT));
    printf("  netlink act2 <domain> <decision_type> [confidence] [hexdata]"
           " [k=v ...]\n");
    printf("                                                  下发决策指令"
           " v2：nlattr 载荷（需 CAP_SYS_ADMIN）\n");
    printf("                                                  k: param=<内核"
           "参数名>(必填) trace_id=0x<hex>:0x<hex>\n"
           "                                                  "
           "intent= parent= agent= expected= ver= trig_evid=\n");
    printf("  netlink act2batch <param=value[:pid] ...> [k=v ...]\n");
    printf("                                                  批量事务"
           "（K2：一个 decision_id，失败整体回滚；需 CAP_SYS_ADMIN）\n");
    printf("                                                  元组: "
           "param=value[:pid]（1-27 个）；k: rollback_ms= trace_id="
           "intent= agent=\n");
    printf("  netlink confirm <decision_id>                   确认决策"
           "（取消 pending 自动回滚；写 /sys/kernel/ai/policy/confirm）\n");
    printf("%s", tr(TR_NL_HELP_REG));
    printf("\n");
    printf("domain: 0=general 1=sched 2=mm 3=io 4=net 5=security 6=power\n");
    printf("        7=vfs 8=interrupt 9=lock 10=time 11=virt 12=proc\n");
    printf("%s", tr(TR_NL_HELP_COUNT));
    printf("%s", tr(TR_NL_HELP_HEXDATA));
}

/* 解析无符号整数参数（0 进制，支持 0x 前缀；全串消费 + 上限校验） */
static int parse_u32_arg(const char *s, unsigned long max, __u32 *out)
{
    char *end;
    unsigned long v;

    if (!s || !*s)
        return AI_ERR_INVALID_ARG;
    errno = 0;
    v = strtoul(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0' || v > max)
        return AI_ERR_INVALID_ARG;
    *out = (__u32)v;
    return AI_OK;
}

/*
 * parse_hex_data - 解析十六进制字节串到 data[8]
 * 接受 "aabbcc" / "aa bb cc"；小端打包：byte k 填入 data[k/8] 的
 * 第 (k%8)*8 位起（与内核端 memcpy 语义一致）。最多 64 字节。
 */
static int parse_hex_data(const char *s, __u64 data[8], size_t *nbytes)
{
    unsigned char bytes[64];
    size_t nb = 0;
    const char *p;
    int hi = -1;

    for (p = s; *p; p++) {
        int v;

        if (*p == ' ' || *p == '\t')
            continue;
        if (*p >= '0' && *p <= '9')
            v = *p - '0';
        else if (*p >= 'a' && *p <= 'f')
            v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F')
            v = *p - 'A' + 10;
        else
            return AI_ERR_INVALID_ARG;

        if (hi < 0) {
            hi = v;
        } else {
            if (nb >= sizeof(bytes))
                return AI_ERR_INVALID_ARG;  /* 超过 data[8]=64B 上限 */
            bytes[nb++] = (unsigned char)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0)
        return AI_ERR_INVALID_ARG;  /* 半字节，非法 */

    memset(data, 0, 8 * sizeof(__u64));
    {
        size_t i;

        for (i = 0; i < nb; i++)
            data[i / 8] |= (__u64)bytes[i] << ((i % 8) * 8);
    }
    *nbytes = nb;
    return AI_OK;
}

/* 统一错误输出：区分内核拒绝 / 传输失败 / 协议异常 */
static void netlink_print_error(int rc, int kern_err)
{
    const char *hint;

    switch (rc) {
    case AI_ERR_API:
        printf(tr(TR_NL_KERN_REJECT), kern_err, strerror(kern_err));
        hint = ai_nl_errno_hint(kern_err);
        if (hint)
            printf(tr(TR_NL_HINT), hint);
        break;
    case AI_ERR_NETWORK:
        printf(tr(TR_NL_SEND_FAIL), strerror(errno));
        break;
    case AI_ERR_PARSE:
        printf("%s", tr(TR_NL_PARSE_FAIL));
        break;
    default:
        printf(tr(TR_NL_ERR), ai_error_string(rc));
        break;
    }
}

/* socket 初始化失败输出 */
static void netlink_print_open_fail(int rc)
{
    printf(tr(TR_NL_INIT_FAIL), ai_error_string(rc));
    if (rc == AI_ERR_NETWORK)
        printf(tr(TR_NL_HINT), strerror(errno));
}

/* raw 记录流十六进制转储（16 字节/行，带偏移与 ASCII 栏） */
static void hexdump_stream(const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t i, j;

    for (i = 0; i < len; i += 16) {
        printf("  %04zx  ", i);
        for (j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", p[i + j]);
            else
                printf("   ");
            if (j == 7)
                printf(" ");
        }
        printf(" |");
        for (j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = p[i + j];

            putchar(c >= 0x20 && c < 0x7f ? c : '.');
        }
        printf("|\n");
    }
}

/* netlink sense [all|<cpu>] [count] [raw|human] */
static int netlink_sense_cmd(int argc, char **argv)
{
    struct ai_nl_client cli;
    struct ai_nl_sense_ack ack;
    unsigned char *stream;
    __u32 cpu = AI_NL_SENSE_CPU_ALL;
    __u32 count = 32;
    __u32 format = AI_NL_FORMAT_HUMAN;
    size_t stream_len = 0;
    int kern_err = 0;
    int rc;

    if (argc >= 4) {
        netlink_usage();
        return AI_ERR_INVALID_ARG;
    }
    if (argc >= 1 && strcmp(argv[0], "all") != 0) {
        /* cpu 合法性（< nr_cpu_ids）由内核端校验（ai_netlink.c:139-144） */
        rc = parse_u32_arg(argv[0], 0xFFFFFFFFul, &cpu);
        if (rc != AI_OK) {
            printf("Invalid cpu: %s\n", argv[0]);
            netlink_usage();
            return rc;
        }
    }
    if (argc >= 2) {
        rc = parse_u32_arg(argv[1], AI_NL_SENSE_MAX_RECORDS, &count);
        if (rc != AI_OK) {
            printf("Invalid count: %s (1~%d)\n", argv[1], AI_NL_SENSE_MAX_RECORDS);
            netlink_usage();
            return rc;
        }
    }
    if (argc >= 3) {
        if (strcmp(argv[2], "raw") == 0) {
            format = AI_NL_FORMAT_RAW;
        } else if (strcmp(argv[2], "human") == 0) {
            format = AI_NL_FORMAT_HUMAN;
        } else {
            printf("Invalid format: %s\n", argv[2]);
            netlink_usage();
            return AI_ERR_INVALID_ARG;
        }
    }

    /* 内核单次应答（头+记录流）不超过 AI_NL_PAYLOAD_MAX */
    stream = malloc(AI_NL_PAYLOAD_MAX);
    if (!stream) {
        printf(tr(TR_NL_ALLOC_FAIL), (unsigned)AI_NL_PAYLOAD_MAX);
        return AI_ERR_MEMORY;
    }

    rc = ai_nl_client_open(&cli);
    if (rc != AI_OK) {
        netlink_print_open_fail(rc);
        free(stream);
        return rc;
    }

    rc = ai_nl_send_sense(&cli, cpu, count, format, &ack,
                          stream, AI_NL_PAYLOAD_MAX, &stream_len, &kern_err);
    if (rc != AI_OK) {
        netlink_print_error(rc, kern_err);
    } else {
        printf("\n=== NETLINK_AI SENSE ===\n\n");
        printf("Portid:   %u\n", cli.portid);
        if (cpu == AI_NL_SENSE_CPU_ALL)
            printf("Cpu:      all\n");
        else
            printf("Cpu:      %u\n", cpu);
        printf("Records:  %u\n", ack.records);
        printf("Bytes:    %u\n", ack.bytes);
        if (ack.ai_err != 0)
            printf("ai_err:   %d\n", ack.ai_err);
        printf("\n");
        if (ack.records == 0) {
            printf("%s", tr(TR_NL_NO_RECORDS));
        } else if (format == AI_NL_FORMAT_HUMAN) {
            /* 内核 human 格式为按 \n 结尾的文本行，原样输出 */
            fwrite(stream, 1, stream_len, stdout);
        } else {
            hexdump_stream(stream, stream_len);
        }
        printf("\n");
    }

    ai_nl_client_close(&cli);
    free(stream);
    return rc;
}

/* netlink act <domain> <decision_type> [confidence] [hexdata] */
static int netlink_act_cmd(int argc, char **argv)
{
    struct ai_nl_client cli;
    struct ai_nl_act req;
    struct ai_nl_act_ack ack;
    __u32 val;
    size_t data_bytes = 0;
    int kern_err = 0;
    int rc;
    char confirm[16];

    if (argc < 2 || argc > 4) {
        netlink_usage();
        return AI_ERR_INVALID_ARG;
    }

    memset(&req, 0, sizeof(req));

    rc = parse_u32_arg(argv[0], AI_NL_DOMAIN_MAX, &val);
    if (rc != AI_OK) {
        printf("Invalid domain: %s (0~%d)\n", argv[0], AI_NL_DOMAIN_MAX);
        netlink_usage();
        return rc;
    }
    req.domain = (__u8)val;

    /* 内核端按 u8 使用 decision_type（ai_netlink.c:241 强转） */
    rc = parse_u32_arg(argv[1], 255, &val);
    if (rc != AI_OK) {
        printf("Invalid decision_type: %s (0~255)\n", argv[1]);
        netlink_usage();
        return rc;
    }
    req.decision_type = val;

    if (argc >= 3) {
        rc = parse_u32_arg(argv[2], 100, &val);
        if (rc != AI_OK) {
            printf("Invalid confidence: %s (0~100)\n", argv[2]);
            netlink_usage();
            return rc;
        }
        req.confidence = (__u8)val;
    } else {
        req.confidence = 50;
    }

    if (argc >= 4) {
        rc = parse_hex_data(argv[3], req.data, &data_bytes);
        if (rc != AI_OK) {
            printf("Invalid hexdata: %s\n", argv[3]);
            netlink_usage();
            return rc;
        }
    }

    /* ACT 直接影响系统行为且需 CAP_SYS_ADMIN：先确认再下发 */
    printf("%s", tr(TR_NL_ACT_CONFIRM1));
    printf(tr(TR_NL_ACT_CONFIRM2),
           req.domain, domain_name(req.domain),
           req.decision_type, req.confidence, data_bytes);
    printf("%s", tr(TR_NL_ACT_CONFIRM3));
    fflush(stdout);
    if (!fgets(confirm, sizeof(confirm), stdin) ||
        (confirm[0] != 'y' && confirm[0] != 'Y')) {
        printf("%s", tr(TR_NL_CANCELLED));
        return AI_OK;
    }

    rc = ai_nl_client_open(&cli);
    if (rc != AI_OK) {
        netlink_print_open_fail(rc);
        return rc;
    }

    rc = ai_nl_send_act(&cli, &req, &ack, &kern_err);
    if (rc != AI_OK) {
        netlink_print_error(rc, kern_err);
    } else {
        printf("\n=== NETLINK_AI ACT ===\n\n");
        printf("Domain:        %u (%s)\n",
               req.domain, domain_name(req.domain));
        printf("Decision type: %u\n", req.decision_type);
        printf("Confidence:    %u\n", req.confidence);
        printf("Executed:      %u\n", ack.executed);
        printf("Hit:           %s\n", ack.hit ? "yes" : "no");
        if (ack.ai_err != 0)
            printf(tr(TR_NL_ACK_AIERR), ack.ai_err);
        if (ack.executed == 0 && ack.ai_err == 0)
            printf("%s", tr(TR_NL_ACK_NO_POLICY));
        printf("\n");
    }

    ai_nl_client_close(&cli);
    return rc;
}

/*
 * parse_trace_arg - 解析统一 trace_id 参数 "0x<hex>:0x<hex>" 或
 * "<hex>:<hex>"（两段 16 进制）。注：occ 对外文案一律写 trace_id 全称
 * ——裸 "trace" 一词已被训练轨迹命令（cmd_trace）占用（D9）。
 */
static int parse_trace_arg(const char *s, __u64 *hi, __u64 *lo)
{
    const char *colon;
    char buf[96];
    char *end;
    unsigned long long a, b;

    if (!s || !hi || !lo || !*s || strlen(s) >= sizeof(buf))
        return AI_ERR_INVALID_ARG;
    snprintf(buf, sizeof(buf), "%s", s);
    colon = strchr(buf, ':');
    if (!colon || !colon[1])
        return AI_ERR_INVALID_ARG;
    *(char *)colon = '\0';
    errno = 0;
    a = strtoull(buf, &end, 16);
    if (errno != 0 || end == buf || *end != '\0')
        return AI_ERR_INVALID_ARG;
    errno = 0;
    b = strtoull(colon + 1, &end, 16);
    if (errno != 0 || end == colon + 1 || *end != '\0')
        return AI_ERR_INVALID_ARG;
    *hi = (__u64)a;
    *lo = (__u64)b;
    return AI_OK;
}

/* 解析有符号 64 位整数参数（0 进制，支持 0x 前缀；全串消费） */
static int parse_s64_arg(const char *s, long long *out)
{
    char *end;
    long long v;

    if (!s || !*s)
        return AI_ERR_INVALID_ARG;
    errno = 0;
    v = strtoll(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0')
        return AI_ERR_INVALID_ARG;
    *out = v;
    return AI_OK;
}

/*
 * netlink act2 <domain> <decision_type> [confidence] [hexdata] [k=v ...]
 * K1 D1/D9：nlattr 载荷决策指令；param 必填（定向参数名单源），
 * trace_id 缺省=内核铸造（D2，ack 回读）。
 */
static int netlink_act2_cmd(int argc, char **argv)
{
    struct ai_nl_client cli;
    struct ai_nl_act2_req req;
    struct ai_nl_act2_ack ack;
    __u32 val;
    size_t data_bytes = 0;
    int have_param = 0;
    int kern_err = 0;
    int rc, i;
    char confirm[16];

    if (argc < 2 || argc > 4 + 8) {
        netlink_usage();
        return AI_ERR_INVALID_ARG;
    }

    memset(&req, 0, sizeof(req));

    rc = parse_u32_arg(argv[0], AI_NL_DOMAIN_MAX, &val);
    if (rc != AI_OK) {
        printf("Invalid domain: %s (0~%d)\n", argv[0], AI_NL_DOMAIN_MAX);
        netlink_usage();
        return rc;
    }
    req.domain = (__u8)val;

    rc = parse_u32_arg(argv[1], 255, &val);
    if (rc != AI_OK) {
        printf("Invalid decision_type: %s (0~255)\n", argv[1]);
        netlink_usage();
        return rc;
    }
    req.decision_type = val;

    if (argc >= 3) {
        rc = parse_u32_arg(argv[2], 100, &val);
        if (rc != AI_OK) {
            printf("Invalid confidence: %s (0~100)\n", argv[2]);
            netlink_usage();
            return rc;
        }
        req.confidence = (__u8)val;
    } else {
        req.confidence = 50;
    }

    i = 3;
    /* [hexdata] 位置槽只吃非 k=v token（含 = 视为键值对起点——
     * act2 允许省略 hexdata 直接给 k=v） */
    if (argc >= 4 && !strchr(argv[3], '=')) {
        rc = parse_hex_data(argv[3], req.data, &data_bytes);
        if (rc != AI_OK) {
            printf("Invalid hexdata: %s\n", argv[3]);
            netlink_usage();
            return rc;
        }
        i = 4;
    }

    req.agent = AI_AGENT_OCC_CLI;   /* 手工 occ 命令（D6） */

    for (; i < argc; i++) {
        const char *arg = argv[i];
        const char *eq = strchr(arg, '=');
        long long v64;

        if (!eq || eq == arg || !eq[1]) {
            printf("Invalid key=value: %s (k: param= trace_id= intent= "
                   "parent= agent= expected= ver= trig_evid=)\n", arg);
            netlink_usage();
            return AI_ERR_INVALID_ARG;
        }
        if (strncmp(arg, "param=", 6) == 0) {
            if (strlen(eq + 1) >= sizeof(req.param)) {
                printf("Invalid param: %s (length must be < %d)\n",
                       eq + 1, (int)sizeof(req.param));
                return AI_ERR_INVALID_ARG;
            }
            snprintf(req.param, sizeof(req.param), "%s", eq + 1);
            have_param = 1;
            continue;
        } else if (strncmp(arg, "trace_id=", 9) == 0 ||
                   strncmp(arg, "trace=", 6) == 0) {
            rc = parse_trace_arg(eq + 1, &req.trace_hi, &req.trace_lo);
        } else if (strncmp(arg, "intent=", 7) == 0) {
            rc = parse_s64_arg(eq + 1, &v64);
            if (rc == AI_OK)
                req.intent_id = (__u64)v64;
        } else if (strncmp(arg, "parent=", 7) == 0) {
            rc = parse_s64_arg(eq + 1, &v64);
            if (rc == AI_OK)
                req.parent_id = (__u64)v64;
        } else if (strncmp(arg, "agent=", 6) == 0) {
            rc = parse_u32_arg(eq + 1, 255, &val);
            if (rc == AI_OK)
                req.agent = val;
        } else if (strncmp(arg, "expected=", 9) == 0) {
            rc = parse_s64_arg(eq + 1, &v64);
            if (rc == AI_OK)
                req.expected = v64;
        } else if (strncmp(arg, "ver=", 4) == 0) {
            rc = parse_u32_arg(eq + 1, 0xFFFFFFFFul, &val);
            if (rc == AI_OK)
                req.model_version = val;
        } else if (strncmp(arg, "trig_evid=", 10) == 0) {
            rc = parse_s64_arg(eq + 1, &v64);
            if (rc == AI_OK)
                req.trig_evid = (__u64)v64;
        } else {
            printf("Unknown key: %s (k: param= trace_id= intent= parent= "
                   "agent= expected= ver= trig_evid=)\n", arg);
            netlink_usage();
            return AI_ERR_INVALID_ARG;
        }
        if (rc != AI_OK) {
            printf("Invalid value for %s\n", arg);
            netlink_usage();
            return rc;
        }
    }

    if (!have_param) {
        printf("act2 requires param=<内核参数名>（定向参数名单源，"
               "与 AI 工具执行器同口径）\n");
        netlink_usage();
        return AI_ERR_INVALID_ARG;
    }

    /* 与 act 同闸：直接影响系统行为且需 CAP_SYS_ADMIN，先确认再下发 */
    printf("%s", tr(TR_NL_ACT_CONFIRM1));
    printf(tr(TR_NL_ACT_CONFIRM2),
           req.domain, domain_name(req.domain),
           req.decision_type, req.confidence, data_bytes);
    printf("%s", tr(TR_NL_ACT_CONFIRM3));
    fflush(stdout);
    if (!fgets(confirm, sizeof(confirm), stdin) ||
        (confirm[0] != 'y' && confirm[0] != 'Y')) {
        printf("%s", tr(TR_NL_CANCELLED));
        return AI_OK;
    }

    rc = ai_nl_client_open(&cli);
    if (rc != AI_OK) {
        netlink_print_open_fail(rc);
        return rc;
    }

    rc = ai_nl_send_act2(&cli, &req, &ack, &kern_err);
    if (rc != AI_OK) {
        netlink_print_error(rc, kern_err);
    } else {
        printf("\n=== NETLINK_AI ACT2 ===\n\n");
        printf("Domain:        %u (%s)\n",
               req.domain, domain_name(req.domain));
        printf("Decision type: %u\n", req.decision_type);
        printf("Confidence:    %u\n", req.confidence);
        printf("Param:         %s\n", req.param);
        printf("Executed:      %u\n", (unsigned)ack.executed);
        printf("Hit:           %s\n", ack.hit ? "yes" : "no");
        printf("Decision id:   %llu\n",
               (unsigned long long)ack.decision_id);
        printf("trace_id:      0x%016llx:0x%016llx%s\n",
               (unsigned long long)ack.trace_hi,
               (unsigned long long)ack.trace_lo,
               (ack.trace_hi || ack.trace_lo) ? "" : " (kernel mint)");
        if (ack.ai_err != 0)
            printf(tr(TR_NL_ACK_AIERR), ack.ai_err);
        if (ack.executed == 0 && ack.ai_err == 0)
            printf("%s", tr(TR_NL_ACK_NO_POLICY));
        printf("\n");
    }

    ai_nl_client_close(&cli);
    return rc;
}

/*
 * netlink act2batch <param=value[:pid] ...> [k=v ...]（K2 D9）
 * 批量事务：AI_CMD_ACT_BATCH 嵌套 nlattr，一个 decision_id；任一项
 * 失败整体回滚（修「step2 失败不撤 step1」类痛点）。k 集合无
 * expected（batch 无单值预期语义，设计册明示不加）。
 */
static int netlink_act2batch_cmd(int argc, char **argv)
{
	struct ai_nl_client cli;
	struct ai_nl_batch_op ops[AI_BATCH_MAX_OPS];
	struct ai_nl_batch_opts opts;
	struct ai_nl_batch_ack ack;
	size_t nops = 0;
	int kern_err = 0;
	int rc, i;
	char confirm[16];

	memset(&opts, 0, sizeof(opts));
	opts.agent = AI_AGENT_OCC_CLI;   /* 手工 occ 命令（沿 act2 先例） */

	if (argc < 1) {
		netlink_usage();
		return AI_ERR_INVALID_ARG;
	}
	for (i = 0; i < argc; i++) {
		const char *arg = argv[i];
		const char *eq = strchr(arg, '=');

		if (!eq || eq == arg || !eq[1]) {
			printf("Invalid tuple/key: %s (元组 param=value[:pid]"
			       "；k: rollback_ms= trace_id= intent= agent=)\n",
			       arg);
			netlink_usage();
			return AI_ERR_INVALID_ARG;
		}
		if (strncmp(arg, "rollback_ms=", 12) == 0) {
			__u32 v;

			rc = parse_u32_arg(eq + 1, 600000, &v);
			if (rc != AI_OK) {
				printf("Invalid rollback_ms: %s (0~600000)\n",
				       eq + 1);
				return rc;
			}
			opts.auto_rollback_ms = v;
			continue;
		}
		if (strncmp(arg, "trace_id=", 9) == 0 ||
		    strncmp(arg, "trace=", 6) == 0) {
			rc = parse_trace_arg(eq + 1, &opts.trace_hi,
					     &opts.trace_lo);
			if (rc != AI_OK) {
				printf("Invalid trace_id: %s"
				       "（0x<hex>:0x<hex>）\n", eq + 1);
				return rc;
			}
			continue;
		}
		if (strncmp(arg, "intent=", 7) == 0) {
			long long v64;

			rc = parse_s64_arg(eq + 1, &v64);
			if (rc != AI_OK) {
				printf("Invalid intent: %s\n", eq + 1);
				return rc;
			}
			opts.intent_id = (__u64)v64;
			continue;
		}
		if (strncmp(arg, "agent=", 6) == 0) {
			__u32 v;

			rc = parse_u32_arg(eq + 1, 255, &v);
			if (rc != AI_OK) {
				printf("Invalid agent: %s\n", eq + 1);
				return rc;
			}
			opts.agent = v;
			continue;
		}
		{
			/* 元组：param=value[:pid]（param 不含 '='，key 不在
			 * k 集合即元组——与 act2 的 k=v 约定同界） */
			char buf[128];
			char *colon;
			size_t plen = (size_t)(eq - arg);
			long long v64;
			char *end;

			if (plen == 0 || plen >= sizeof(ops[0].param)) {
				printf("Invalid param (too long): %.*s\n",
				       (int)plen, arg);
				return AI_ERR_INVALID_ARG;
			}
			if (nops >= AI_BATCH_MAX_OPS) {
				printf("Too many ops (max %d)\n",
				       AI_BATCH_MAX_OPS);
				return AI_ERR_INVALID_ARG;
			}
			for (size_t k = 0; k < nops; k++)
				if (strlen(ops[k].param) == plen &&
				    strncmp(ops[k].param, arg, plen) == 0) {
					printf("Duplicate param: %.*s"
					       "（同参双值歧义，拒收）\n",
					       (int)plen, arg);
					return AI_ERR_INVALID_ARG;
				}
			snprintf(buf, sizeof(buf), "%s", eq + 1);
			colon = strrchr(buf, ':');
			ops[nops].pid = 0;
			if (colon) {
				unsigned long long pv;

				*colon = '\0';
				errno = 0;
				pv = strtoull(colon + 1, &end, 0);
				if (errno != 0 || end == colon + 1 ||
				    *end != '\0' || pv == 0 || pv > 0xFFFFFFFFull) {
					printf("Invalid pid: %s（正整数）\n",
					       colon + 1);
					return AI_ERR_INVALID_ARG;
				}
				ops[nops].pid = (__u32)pv;
			}
			errno = 0;
			v64 = strtoll(buf, &end, 0);
			if (errno != 0 || end == buf || *end != '\0') {
				printf("Invalid value: %s\n", buf);
				return AI_ERR_INVALID_ARG;
			}
			memcpy(ops[nops].param, arg, plen);
			ops[nops].param[plen] = '\0';
			ops[nops].value = (__u64)v64;
			ops[nops].reserved = 0;
			nops++;
		}
	}
	if (nops == 0) {
		printf("act2batch 需要至少 1 个元组 param=value[:pid]\n");
		netlink_usage();
		return AI_ERR_INVALID_ARG;
	}

	/* 与 act 同闸：直接影响系统行为且需 CAP_SYS_ADMIN，先确认再下发 */
	printf("%s", tr(TR_NL_ACT_CONFIRM1));
	printf("  批量事务 ops=%zu  rollback_ms=%u\n", nops,
	       opts.auto_rollback_ms);
	for (i = 0; (size_t)i < nops; i++) {
		if (ops[i].pid)
			printf("    [%d] %s=%llu:pid=%u\n", i, ops[i].param,
			       (unsigned long long)ops[i].value, ops[i].pid);
		else
			printf("    [%d] %s=%llu\n", i, ops[i].param,
			       (unsigned long long)ops[i].value);
	}
	printf("%s", tr(TR_NL_ACT_CONFIRM3));
	fflush(stdout);
	if (!fgets(confirm, sizeof(confirm), stdin) ||
	    (confirm[0] != 'y' && confirm[0] != 'Y')) {
		printf("%s", tr(TR_NL_CANCELLED));
		return AI_OK;
	}

	rc = ai_nl_client_open(&cli);
	if (rc != AI_OK) {
		netlink_print_open_fail(rc);
		return rc;
	}

	rc = ai_nl_send_act_batch(&cli, ops, nops, &opts, &ack, &kern_err);
	if (rc != AI_OK) {
		netlink_print_error(rc, kern_err);
	} else if (ack.ai_err == -EAGAIN && ack.token != 0) {
		printf("\n=== NETLINK_AI ACT_BATCH（blast radius 拒） ===\n\n");
		printf("Blast radius:  %u（超阈）\n", ack.blast_radius);
		printf("Confirm token: %llu\n",
		       (unsigned long long)ack.token);
		printf("提示: 确认影响面后重试——HTTP POST /act ops 请求带 "
		       "\"confirm_token\": %llu 放行\n",
		       (unsigned long long)ack.token);
		rc = AI_ERR_API;
	} else {
		printf("\n=== NETLINK_AI ACT_BATCH ===\n\n");
		printf("Ops:           %zu\n", nops);
		printf("Rollback_ms:   %u\n", opts.auto_rollback_ms);
		printf("Executed:      %u\n", (unsigned)ack.executed);
		printf("Hit:           %s\n", ack.hit ? "yes" : "no");
		printf("Decision id:   %llu\n",
		       (unsigned long long)ack.decision_id);
		printf("trace_id:      0x%016llx:0x%016llx%s\n",
		       (unsigned long long)ack.trace_hi,
		       (unsigned long long)ack.trace_lo,
		       (ack.trace_hi || ack.trace_lo) ? "" : " (kernel mint)");
		printf("First fail:    %d%s\n", ack.first_fail_idx,
		       ack.first_fail_idx < 0 ? "（无）" : "");
		printf("Blast radius:  %u\n", ack.blast_radius);
		if (ack.ai_err != 0)
			printf(tr(TR_NL_ACK_AIERR), ack.ai_err);
		if (ack.executed == 0 && ack.ai_err == 0)
			printf("%s", tr(TR_NL_ACK_NO_POLICY));
		printf("\n");
	}

	ai_nl_client_close(&cli);
	return rc;
}

/*
 * netlink confirm <decision_id>（K2 D5）：写
 * /sys/kernel/ai/policy/confirm（0200）。内核端 kstrtoull(buf, 0)
 * 不吃尾随 \n——写纯十进制数字。已回滚=-ENOENT（窗口已过）。
 */
#define AI_POLICY_CONFIRM_SYSFS "/sys/kernel/ai/policy/confirm"

static int netlink_confirm_cmd(int argc, char **argv)
{
	char idbuf[32];
	unsigned long long id;
	char *end;
	int fd;
	ssize_t w;
	int n;

	if (argc != 1) {
		netlink_usage();
		return AI_ERR_INVALID_ARG;
	}
	errno = 0;
	id = strtoull(argv[0], &end, 0);
	if (errno != 0 || end == argv[0] || *end != '\0') {
		printf("Invalid decision_id: %s（十进制/0x 十六进制）\n",
		       argv[0]);
		return AI_ERR_INVALID_ARG;
	}
	n = snprintf(idbuf, sizeof(idbuf), "%llu", id);
	if (n < 0 || (size_t)n >= sizeof(idbuf))
		return AI_ERR_INVALID_ARG;
	fd = open(AI_POLICY_CONFIRM_SYSFS, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			printf("confirm 节点不存在（/sys/kernel/ai/policy/"
			       "confirm）——未加载 K2 内核或节点未注册\n");
		else
			printf("open %s: %s（需 root/CAP_SYS_ADMIN）\n",
			       AI_POLICY_CONFIRM_SYSFS, strerror(errno));
		return AI_ERR_API;
	}
	w = write(fd, idbuf, (size_t)n);
	if (w != n) {
		if (errno == ENOENT)
			printf("决策 %llu 已回滚（confirm 窗口已过）\n", id);
		else
			printf("write %s: %s\n", AI_POLICY_CONFIRM_SYSFS,
			       strerror(errno));
		close(fd);
		return AI_ERR_API;
	}
	close(fd);
	printf("OK: 决策 %llu 已确认（pending 自动回滚已取消）\n", id);
	return AI_OK;
}

/* netlink reg */
static int netlink_reg_cmd(void)
{
    struct ai_nl_client cli;
    __s32 ai_err = 0;
    __u32 count = 0;
    int kern_err = 0;
    int rc;

    rc = ai_nl_client_open(&cli);
    if (rc != AI_OK) {
        netlink_print_open_fail(rc);
        return rc;
    }

    rc = ai_nl_send_reg(&cli, 0, &ai_err, &count, &kern_err);
    if (rc != AI_OK) {
        netlink_print_error(rc, kern_err);
    } else {
        printf("\n=== NETLINK_AI REG ===\n\n");
        printf(tr(TR_NL_REG_PORTID), cli.portid);
        printf("ai_err:           %d\n", ai_err);
        printf(tr(TR_NL_REG_COUNT), count);
        printf("%s", tr(TR_NL_REG_IDEMPOTENT));
        printf("\n");
    }

    ai_nl_client_close(&cli);
    return rc;
}

int cmd_netlink(void *shell_ptr, int argc, char **argv)
{
    (void)shell_ptr;

    if (argc < 2) {
        netlink_usage();
        return AI_ERR_INVALID_ARG;
    }

    if (strcmp(argv[1], "sense") == 0)
        return netlink_sense_cmd(argc - 2, argv + 2);
    if (strcmp(argv[1], "act") == 0)
        return netlink_act_cmd(argc - 2, argv + 2);
    if (strcmp(argv[1], "act2") == 0)
        return netlink_act2_cmd(argc - 2, argv + 2);
    if (strcmp(argv[1], "act2batch") == 0)
        return netlink_act2batch_cmd(argc - 2, argv + 2);
    if (strcmp(argv[1], "confirm") == 0)
        return netlink_confirm_cmd(argc - 2, argv + 2);
    if (strcmp(argv[1], "reg") == 0) {
        if (argc > 2) {
            printf("%s", tr(TR_NL_REG_NOARGS));
            netlink_usage();
            return AI_ERR_INVALID_ARG;
        }
        return netlink_reg_cmd();
    }

    printf("Unknown netlink subcommand: %s\n", argv[1]);
    netlink_usage();
    return AI_ERR_INVALID_ARG;
}
