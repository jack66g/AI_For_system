/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net_range.h - W81 E2：V3.6 靶场攻击面（TOOL_CH_RANGE，五件）
 *
 *   1. range_status   D0  是否启用 / 剩余 TTL / 声明 CIDR / 累计动作数
 *   2. range_enable   D3  cidr（硬编码允许清单）+ ttl_minutes（1..60）
 *   3. range_disable  D1  立即关闭并清状态
 *   4. range_scan     D3  TCP/UDP connect 探测（默认超时 200ms）
 *   5. range_inject   D3  UDP / TCP SYN / ICMP 构造发送，payload 自定义
 *
 * 边界（先于能力落地，全部在代码里硬校验，不靠文档约定）：
 *   - 出厂默认关闭：无状态文件 = 未启用；五个工具全部返回
 *     "未启用 + 如何启用"（range_enable 是唯一启用入口，本身 D3 管辖）。
 *   - 允许 CIDR 清单硬编码：10.231.0.0/16、10.99.0.0/16、127.0.0.0/8；
 *     其它一律拒绝（含实验室 192.168.245.0/24、10.0.0.0/8 与公网）。
 *   - 目标必须同时满足：在启用时声明的 CIDR 内 + 在该硬编码清单内。
 *   - TTL 默认 30 分钟、上限 60；后台 watchdog 到期自动关闭，
 *     且每次调用前惰性检查 expires_at（watchdog 丢失也不会失效）。
 *   - 每次动作（含拒绝）写 audit.log：目标/端口/协议/payload 十六进制
 *     全文/返回码；无关闭开关；审计写失败则动作失败（fail-closed）。
 *   - 不写漏洞利用、不打真实服务、不做 DoS、不扫描宿主 LAN。
 *
 * LSM socket hook：内核侧在 AIKernel/security/ai_lsm.c（socket_connect /
 * socket_sendmsg）。本文件在 range_enable 时尝试给当前进程打
 * sec.ws_label=226（NETLINK_AI ACT）；宿主 6.8 无该 hook/协议族时
 * 如实记录 "pending #61"，用户态 CIDR 校验仍是主闸门。详见
 * rg_lsm_attach() 与报告 W81-RANGE.md 的验证步骤。
 */
#ifndef _AI_NET_RANGE_H
#define _AI_NET_RANGE_H

#include <stddef.h>
#include <sys/types.h>

#define RG_MAX_PAYLOAD		4096
#define RG_MAX_PORTS		1024
#define RG_MAX_CIDR		64
#define RG_DEFAULT_TTL_MIN	30
#define RG_MAX_TTL_MIN		60
#define RG_DEFAULT_TIMEOUT_MS	200
#define RG_MAX_TIMEOUT_MS	1000
#define RG_LSM_LABEL		226

/* 规范化 CIDR（IPv4） */
struct rg_cidr {
	unsigned int net;	/* 主机字节序 */
	unsigned int mask;
	int prefix;
	char text[RG_MAX_CIDR];
};

/* 启用状态（state.json 单源；0600） */
struct rg_state {
	int enabled;
	char cidr[RG_MAX_CIDR];
	struct rg_cidr net;
	int ttl_minutes;
	long long enabled_at;
	long long expires_at;
	unsigned long long actions;
	unsigned long long session;
	char lsm[256];		/* LSM 接线结果（如实文本） */
};

/* ---- 纯函数（导出供单测） ---- */
const char *rg_allowlist_text(void);
int rg_cidr_parse(const char *s, struct rg_cidr *out, char *err, size_t ecap);
int rg_cidr_contains(const struct rg_cidr *c, const char *ip);
int rg_cidr_allowlisted(const char *s, char *err, size_t ecap);
int rg_parse_ports(const char *s, unsigned short *ports, int max, int *n,
		   char *err, size_t ecap);
int rg_hex_decode(const char *hex, unsigned char *out, size_t cap,
		  size_t *n, char *err, size_t ecap);
void rg_hex_encode(const unsigned char *buf, size_t n, char *out,
		   size_t cap);
int rg_state_expired(const struct rg_state *st, long long now);

/* ---- 状态 / 审计（导出供单测与 live 驱动） ---- */
void rg_state_default(struct rg_state *st);
int rg_state_dir(char *out, size_t cap);
int rg_audit_path(char *out, size_t cap);
int rg_state_save(const struct rg_state *st);
int rg_state_load(struct rg_state *st, char *err, size_t ecap);
int rg_state_remove(void);
int rg_watchdog_spawn(unsigned long long session, char *err, size_t ecap);
void rg_watchdog_stop(void);

/* ---- LSM 接线 ---- */
int rg_lsm_probe(void);		/* 1=内核 LSM 列表含 ai；0=无 */
int rg_lsm_attach(char *out, size_t cap);

/* 执行器入口（executor.c 的 TOOL_CH_RANGE 分发调用） */
int exec_net_range_channel(const void *tool, const char *args_json,
			   char **out);

#endif /* _AI_NET_RANGE_H */
