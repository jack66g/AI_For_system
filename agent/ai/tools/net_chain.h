/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net_chain.h - W81 E1：conntrack 事件流 + 攻击链关联（TOOL_CH_NETCHAIN，两件）
 *
 *   1. net_chain_watch  start/stop/status 合一的后台采样器：
 *                       按 interval（默认 2s）轮询连接事件源 → 滑动窗口
 *                       → 三条关联规则（scan/lateral/burst）→ 攻击链事件
 *                       （audit.log + events.jsonl）。
 *   2. net_chain_rules  阈值 get/set（全部可配；运行中每拍重读）。
 *
 * 事件源（按优先级自动选择，全部只读）：
 *   a. /proc/net/nf_conntrack（第一优先；解析五元组/状态/包数/字节）。
 *   b. conntrack 命令（若安装；`conntrack -L` 快照；不强制依赖）。
 *   c. 内置 ctnetlink（NETLINK_NETFILTER / CTNETLINK dump；无需外部库，
 *      需要 root/CAP_NET_ADMIN）——本机内核未开 CONFIG_NF_CONNTRACK_PROCFS
 *      且未装 conntrack 时仍能拿到真实连接事件。
 * 每一档的可用性都在 status 里逐条如实标注；全部不可用时 start 直接失败，
 * 绝不静默假装成功。表为空单独标注 "empty"，采样继续。
 *
 * 关联规则（窗口内新出现的连接事件，全部阈值可配）：
 *   scan    同一源访问 ≥ scan_ports 个不同目的端口（默认 60s / 15 个）
 *   lateral 同一源在 ≤ lateral_window 内连 ≥ lateral_hosts 个不同目的主机
 *           的同一目的端口（默认 60s / 3 台）
 *   burst   同一 (源,目的) 的连接数从前一窗口的低位跃变到当前窗口的高位
 *           （默认窗口 30s、current ≥ 8、≥ 4× 前窗、前窗 ≤ 3）
 *
 * 命中产出 {type, src, dsts, ports, window, evidence_count, ...} 一行 JSON，
 * 同时写 audit.log 与 events.jsonl。只观测：不写任何 nft 规则、不封禁、
 * 不改网络配置（封禁在 B 棒 net_hit 三档响应里，本模块不重复造）。
 *
 * 生命周期与 net_hit 同款：start 分叉 setsid 后台进程（父进程探测 + flock
 * 单例 + 握手后立即返回）；stop SIGTERM 等自清理；进程被杀后 status 标
 * orphan，下一次 start/stop 清残。
 */
#ifndef _AI_NET_CHAIN_H
#define _AI_NET_CHAIN_H

#include <stddef.h>

#define NC_MAX_ENTRIES		4096
#define NC_MAX_OBS		512
#define NC_MAX_SRCS		128
#define NC_MAX_TARGETS		32
#define NC_MAX_FIRES		256
#define NC_MAX_EVENTS_PER_TICK	32

/* 命中类型 */
enum nc_hit_type {
	NC_HIT_SCAN = 0,
	NC_HIT_LATERAL,
	NC_HIT_BURST,
};

/* 事件源 */
enum nc_source_kind {
	NC_SRC_NONE = 0,
	NC_SRC_PROCFS,
	NC_SRC_CMD,
	NC_SRC_NETLINK,
};

struct nc_source {
	int procfs;			/* 1 可用 / 0 不存在 / -1 权限或读失败 */
	char procfs_msg[256];
	int cmd;			/* 1 找到 conntrack / 0 未安装 */
	char cmd_path[128];
	char cmd_msg[256];
	int netlink;			/* 1 dump 成功 / 0 不可用 / -1 权限 */
	char netlink_msg[256];
	int active;			/* enum nc_source_kind */
	char active_name[32];
};

/* 阈值配置（rules.json 单源；全部字段可配） */
struct nc_cfg {
	int interval;		/* 采样周期秒（默认 2） */
	int scan_window;	/* scan 判定窗口秒（默认 60） */
	int scan_ports;		/* scan 不同目的端口数阈值（默认 15） */
	int lateral_window;	/* lateral 判定窗口秒（默认 60） */
	int lateral_hosts;	/* lateral 不同目的主机数阈值（默认 3） */
	int burst_window;	/* burst 当前/前一窗口秒（默认 30） */
	int burst_ratio;	/* burst 当前/前窗倍数下限（默认 4） */
	int burst_min;		/* burst 当前连接数下限（默认 8） */
	int burst_low;		/* burst 前窗连接数上限（默认 3） */
	int cooldown;		/* 同类同键再次触发最小间隔秒（默认 60） */
	char netns[64];		/* 可选标注（证据/多命名空间辨识） */
};

/* 单条 conntrack 连接（原始方向五元组 + 计数/状态） */
struct nc_conn {
	char src[64];
	char dst[64];
	unsigned short sport;
	unsigned short dport;
	int proto;		/* 6=tcp / 17=udp / 1=icmp */
	long long packets;	/* -1 = 无计数（nf_conntrack_acct=0） */
	long long bytes;
	int has_counter;
	char state[32];		/* ESTABLISHED / TIME_WAIT / UNREPLIED / ... */
	unsigned long long hash;
};

/* 一条“新连接”观测 */
struct nc_obs {
	long ts;
	char dst[64];
	unsigned short dport;
	int proto;
};

struct nc_src_state {
	char src[64];
	struct nc_obs obs[NC_MAX_OBS];
	int n;
	long long total;
};

struct nc_fire_key {
	char key[192];
	long ts;
};

struct nc_engine {
	struct nc_src_state src[NC_MAX_SRCS];
	int src_n;
	struct nc_fire_key fires[NC_MAX_FIRES];
	int fire_n;
	int dropped_srcs;
	int dropped_obs;
};

/* 规则命中（调用方逐条写事件/审计） */
struct nc_hit {
	int type;				/* enum nc_hit_type */
	char src[64];
	char dsts[NC_MAX_TARGETS][64];
	int dst_n;
	unsigned short ports[NC_MAX_TARGETS];
	int port_n;
	int ports_truncated;
	int window;
	long evidence_count;
	long prev_count;
	long cur_count;
	int threshold;
	char rule[64];				/* 如 scan_ports>=15 */
};

/* ---- 纯函数（导出供单测） ---- */
void nc_cfg_default(struct nc_cfg *c);
int nc_cfg_parse(const char *json, struct nc_cfg *c, char *err, size_t ecap);
int nc_cfg_check(const struct nc_cfg *c, char *err, size_t ecap);

int nc_parse_ct_line(const char *line, struct nc_conn *out);
int nc_parse_ct_text(const char *text, struct nc_conn *out, int max, int *n,
		     int *lines_bad);

void nc_engine_init(struct nc_engine *e);
int nc_engine_add(struct nc_engine *e, long ts, const struct nc_conn *c);
int nc_engine_eval(struct nc_engine *e, const struct nc_cfg *cfg, long now,
		   struct nc_hit *out, int max, int *n);

/* 事件源探测 / 采样（导出供 status 与测试复用）：
 * probe 返回 0 表示至少一个源可用（active 已设置）；-1 全部不可用。 */
int nc_probe_sources(struct nc_source *s, char *err, size_t ecap);
int nc_sample_now(struct nc_source *s, struct nc_conn *out, int max, int *n,
		  int *empty, char *err, size_t ecap);

/* 状态目录：AIKERNEL_NET_CHAIN_DIR 优先；root /run/aik-net-chain；
 * 非 root /tmp/aik-net-chain-<uid>。返回 0 表示目录可写。 */
int nc_chain_dir(char *out, size_t cap);

/* 执行器入口（executor.c 的 TOOL_CH_NETCHAIN 分发调用） */
int exec_net_chain_channel(const void *tool, const char *args_json,
			   char **out);

#endif /* _AI_NET_CHAIN_H */
