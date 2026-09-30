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
 *   netlink reg
 *       - AI_CMD_REG：登记本进程 portid（需 CAP_SYS_ADMIN，内核幂等去重）
 *
 * 协议与传输实现在 runtime/netlink/ai_netlink_client.c；
 * 输出风格对齐 cmd_status.c / cmd_network.c。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_shell.h"
#include "ai_commands.h"
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
    printf("   拉取内核 AI 遥测记录\n");
    printf("  netlink act <domain> <decision_type> [confidence] [hexdata]\n");
    printf("                                                  下发决策指令（需 CAP_SYS_ADMIN）\n");
    printf("  netlink reg                                     登记本进程 portid（需 CAP_SYS_ADMIN）\n");
    printf("\n");
    printf("domain: 0=general 1=sched 2=mm 3=io 4=net 5=security 6=power\n");
    printf("        7=vfs 8=interrupt 9=lock 10=time 11=virt 12=proc\n");
    printf("count:  1~4096（默认 32）\n");
    printf("hexdata: 最多 64 字节，如 \"aabbcc\" 或 \"aa bb cc\"\n");
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
        printf("内核拒绝: errno=%d (%s)\n", kern_err, strerror(kern_err));
        hint = ai_nl_errno_hint(kern_err);
        if (hint)
            printf("提示: %s\n", hint);
        break;
    case AI_ERR_NETWORK:
        printf("传输失败: %s\n", strerror(errno));
        break;
    case AI_ERR_PARSE:
        printf("应答解析失败（与内核协议不一致？请核对 ai_netlink.h）\n");
        break;
    default:
        printf("错误: %s\n", ai_error_string(rc));
        break;
    }
}

/* socket 初始化失败输出 */
static void netlink_print_open_fail(int rc)
{
    printf("NETLINK_AI socket 初始化失败: %s\n", ai_error_string(rc));
    if (rc == AI_ERR_NETWORK)
        printf("提示: %s\n", strerror(errno));
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
        printf("内存分配失败 (%u 字节)\n", (unsigned)AI_NL_PAYLOAD_MAX);
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
            printf("(无记录)\n");
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
    printf("即将向内核下发决策:\n");
    printf("  domain=%u (%s)  decision_type=%u  confidence=%u  data=%zu 字节\n",
           req.domain, domain_name(req.domain),
           req.decision_type, req.confidence, data_bytes);
    printf("该操作需要 CAP_SYS_ADMIN（root/sudo），并会直接影响系统行为。确认执行? [y/N] ");
    fflush(stdout);
    if (!fgets(confirm, sizeof(confirm), stdin) ||
        (confirm[0] != 'y' && confirm[0] != 'Y')) {
        printf("已取消\n");
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
            printf("ai_err:        %d（策略层报错）\n", ack.ai_err);
        if (ack.executed == 0 && ack.ai_err == 0)
            printf("未命中任何策略（executed=0）\n");
        printf("\n");
    }

    ai_nl_client_close(&cli);
    return rc;
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
        printf("Portid:           %u（内核分配，同进程固定）\n", cli.portid);
        printf("ai_err:           %d\n", ai_err);
        printf("已登记 portid 数:  %u/32\n", count);
        printf("重复执行 reg 幂等（内核按 portid 去重）\n");
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
    if (strcmp(argv[1], "reg") == 0) {
        if (argc > 2) {
            printf("netlink reg 不接受参数\n");
            netlink_usage();
            return AI_ERR_INVALID_ARG;
        }
        return netlink_reg_cmd();
    }

    printf("Unknown netlink subcommand: %s\n", argv[1]);
    netlink_usage();
    return AI_ERR_INVALID_ARG;
}
