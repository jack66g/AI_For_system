/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_streams.h - 六路内核事件流常驻订阅（单进程多 socket）
 *
 * 订阅面（K3-DESIGN §K3c 规格）：
 *   event     NETLINK_AI REG→EVENT 常驻（协议 31；AI_MOCK_PROTO!=0 时
 *             用测试协议号替代并跳过 REG——mock 只允许出现在测试，conf
 *             显式打开，journal 明示）
 *   proc      CN_PROC（NETLINK_CONNECTOR，需 CAP_NET_ADMIN）
 *   net       RTNLGRP_{LINK,IPV4_IFADDR,IPV6_IFADDR,IPV4_ROUTE,IPV6_ROUTE}
 *   uevent    KOBJECT_UEVENT 组 1（原始文本协议）
 *   nflog     NFNETLINK_LOG 组 0（PF_BIND+BIND 后内核单播）
 *   taskstats NETLINK_GENERIC TASKSTATS 族——非常驻推送，改周期采样
 *             （TASKSTATS_INTERVAL_SEC，默认 30s）
 *
 * 某 socket 打开失败（内核不支持/无权限）＝诚实降级：journal 告警一行、
 * 该路计数 state=stopped，进程不退（规格 §K3c 降级诚实）。
 *
 * socket 建立与报文解析抽取自 agent/ai/runtime/netlink/ai_streams.c
 * （W78 六条流订阅器，只读复用；该文件面向一次性有界循环，函数形态
 * 无法直接常驻，此处抽取其 nl_open/握手/解析体，语义保持一致）。
 */
#ifndef _AS_STREAMS_H
#define _AS_STREAMS_H

#include <poll.h>

#include "as_conf.h"
#include "as_event.h"
#include "as_stats.h"

struct as_streams {
	struct as_conf *conf;
	struct as_stats *stats;
	void (*on_event)(struct as_event *ev, void *u);	/* 管道回调 */
	void *ud;
	/* 各路 socket fd（-1=disabled/failed；配合 stats->per[].state） */
	int fd_event;		/* NETLINK_AI 或 mock 通道 */
	int fd_proc;
	int fd_net;
	int fd_uevent;
	int fd_nflog;
	int fd_ts;		/* taskstats 请求 socket（不进 poll） */
	int ts_family;		/* TASKSTATS genl 族号（0=未解析） */
	uint32_t ts_seq;
	long long ts_next_ms;	/* 下次采样 deadline（mono ms） */
	long long ts_last_ms;
};

/*
 * as_streams_setup - 按 conf 打开全部使能的流。
 * 返回 0（个别流降级不算失败——state=stopped 诚实可见）；-1 仅致命错
 * （如 taskstats socket 意外错误仍继续，只有内存类错误返回 -1）。
 */
int as_streams_setup(struct as_streams *sp, struct as_conf *c,
		     struct as_stats *st,
		     void (*on_event)(struct as_event *ev, void *u),
		     void *ud);

void as_streams_close_all(struct as_streams *sp);

/*
 * as_streams_fill_poll - 把 running 态 fd 填进 pfds（idx_map 回填流下标）。
 * 返回 fd 数。taskstats 请求 socket 不在内（请求-应答式）。
 */
int as_streams_fill_poll(struct as_streams *sp, struct pollfd *pfds,
			 int *idx_map, int max);

/*
 * as_streams_dispatch - 某 fd 可读：收包+解析+逐事件回调
 * （回调内已计 received）。返回处理事件数；-1=recv 致错（已日志）。
 */
int as_streams_dispatch(struct as_streams *sp, int stream_idx);

/*
 * as_streams_taskstats_tick - 到期执行一轮周期采样（可选产出一条
 * sample 事件）。返回产出事件数（0 或 1）。
 */
int as_streams_taskstats_tick(struct as_streams *sp);

/* 下次采样还差多久（ms；给主循环 poll 超时用；<0 视为 0） */
long long as_streams_taskstats_due_ms(const struct as_streams *sp);

#endif /* _AS_STREAMS_H */
