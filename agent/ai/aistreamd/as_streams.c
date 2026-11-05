/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_streams.c - 六路事件流常驻订阅实现
 *
 * socket 建立/组播加入/报文解析抽取自 ai_streams.c（只读复用，出处随段
 * 标注）；与原文件的差异：常驻（fd 由调用方 poll）、解析产物为
 * struct as_event（规范化构造见 as_event.c）、失败=降级不退出。
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/taskstats.h>
#include <linux/genetlink.h>

#include "ai_types.h"
#include "netlink/ai_netlink_client.h"

#include "as_streams.h"
#include "as_util.h"

/* ---- AI 异步事件载荷（kernel-overlays uapi ai_netlink.h 只读对齐） ----
 * event_id：策略类=decision_id（审计链关键，原样透传）；模型类=model id。
 * 仓库 uapi 不在构建 include 路径上，本地副本 + 布局钉扎。 */
#ifndef AI_CMD_EVENT
#define AI_CMD_EVENT 19
#endif
#ifndef AI_NL_EV_POLICY
#define AI_NL_EV_POLICY 1
#define AI_NL_EV_MODEL 2
#endif
/* K3d-2（I-9）：EVENT 通道热插拔 category（AI_NL_EV_* 只追加空间的
 * 预留契约值；现 uapi 只到 2。L1 经 K3c mock 通道注入 3/4/5，qemu 真
 * 内核收口轮随内核 glue + uapi 正式化——见 as_hotplug.h）。 */
#define AS_AI_NL_EV_DEVICE	3
#define AS_AI_NL_EV_CPU_HOTPLUG	4
#define AS_AI_NL_EV_HW_ERROR	5

struct as_ai_nl_event {
	uint64_t ts;
	uint64_t event_id;
	uint32_t category;
	uint32_t severity;
	int32_t code;
	uint32_t reserved;
	char param[24];
};

_Static_assert(sizeof(struct as_ai_nl_event) == 56, "ai_nl_event layout");

/* ====================================================================
 * 通用 netlink socket（抽取自 ai_streams.c nl_open：组加入双保险——
 * 组号 1..31 走 bind 位掩码 + setsockopt 成员加入）
 * ==================================================================== */
static int nl_open(int proto, const int *groups, int ngroups, int *err)
{
	struct sockaddr_nl sa;
	uint32_t mask = 0;
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, proto);

	*err = 0;
	if (fd < 0) {
		*err = errno;
		return -1;
	}
	for (int i = 0; i < ngroups; i++) {
		int covered = (groups[i] >= 1 && groups[i] <= 31);

		if (covered)
			mask |= 1u << (groups[i] - 1);
		if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
			       &groups[i], sizeof(groups[i])) < 0 && !covered) {
			*err = errno;
			close(fd);
			return -1;
		}
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = mask;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		*err = errno;
		close(fd);
		return -1;
	}
	return fd;
}

/* 常驻订阅 socket 加大接收缓冲：fork 风暴下内核 netlink 队列默认
 * (~208KB) 会 ENOBUFS 溢出丢事件（e2e 实测）。SO_RCVBUFFORCE 需
 * CAP_NET_ADMIN（root 守护满足），失败回退 SO_RCVBUF（受 rmem_max 钳制）。 */
static void sock_big_rcvbuf(int fd)
{
	int sz = 4 * 1024 * 1024;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz)) < 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
}

/* 某路降级：告警一行 + state=stopped（计数器照常暴露） */
static void degrade(struct as_stats *st, int idx, const char *what, int err)
{
	st->per[idx].state = AS_ST_STOPPED;
	as_warn_ratelimit(what, 3600000,
			  "stream %s degraded (stopped): %s (errno=%d %s)"
			  " — daemon continues",
			  as_stream_name(idx), what, err, strerror(err));
}

/* ====================================================================
 * 1) event：NETLINK_AI REG→EVENT（真协议）或测试协议（mock，跳过 REG）
 * ==================================================================== */
static int setup_ai(struct as_streams *sp)
{
	int idx = as_stream_idx(AS_STREAM_EVENT);

	if (sp->conf->ai_mock_proto != 0) {
		/* 测试通道（仅测试，conf 显式打开）：NETLINK_USERSOCK(2)
		 * 用户态↔用户态 netlink，EVENT 解析路径与真协议同一代码 */
		struct sockaddr_nl sa;
		int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
				sp->conf->ai_mock_proto);
		socklen_t sl;

		if (fd < 0) {
			degrade(sp->stats, idx, "ai-mock-open", errno);
			return -1;
		}
		memset(&sa, 0, sizeof(sa));
		sa.nl_family = AF_NETLINK;
		if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			degrade(sp->stats, idx, "ai-mock-bind", errno);
			close(fd);
			return -1;
		}
		sl = sizeof(sa);
		if (getsockname(fd, (struct sockaddr *)&sa, &sl) == 0)
			sp->stats->nl_ai_portid = (int)sa.nl_pid;
		sock_big_rcvbuf(fd);
		sp->fd_event = fd;
		sp->stats->per[idx].state = AS_ST_RUNNING;
		as_log("stream event: MOCK channel proto=%d portid=%u "
		       "(TEST ONLY — no kernel REG)",
		       sp->conf->ai_mock_proto, sa.nl_pid);
		return 0;
	}

	/* 真协议：ai_netlink_client 打开 + REG 登记 portid */
	{
		struct ai_nl_client cli;
		int rc = ai_nl_client_open(&cli);
		int kern_err = 0;
		__s32 ai_err = 0;
		__u32 count = 0;

		if (rc != AI_OK) {
			degrade(sp->stats, idx, "ai-open", errno);
			return -1;
		}
		rc = ai_nl_send_reg(&cli, 0, &ai_err, &count, &kern_err);
		if (rc != AI_OK) {
			degrade(sp->stats, idx, "ai-reg", kern_err ?: errno);
			ai_nl_client_close(&cli);
			return -1;
		}
		sock_big_rcvbuf(cli.fd);
		sp->fd_event = cli.fd;
		sp->stats->nl_ai_portid = (int)cli.portid;
		sp->stats->per[idx].state = AS_ST_RUNNING;
		as_log("stream event: NETLINK_AI registered portid=%u "
		       "(registered=%u)", cli.portid, count);
		/* cli.rx_buf 不用于常驻 EVENT 收包，释放但保留 fd */
		free(cli.rx_buf);
		cli.rx_buf = NULL;
		cli.fd = -1;	/* 防 close 关 fd */
		ai_nl_client_close(&cli);
		return 0;
	}
}

static void parse_ai_msg(struct as_streams *sp, struct nlmsghdr *nh)
{
	int idx = as_stream_idx(AS_STREAM_EVENT);

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);

		if (e->error)
			as_warn_ratelimit("ai-nl-err", 60000,
					  "NETLINK_AI error ack: %d",
					  e->error);
		return;
	}
	if (nh->nlmsg_type != AI_CMD_EVENT)
		return;
	if (nh->nlmsg_len < NLMSG_HDRLEN + (int)sizeof(struct as_ai_nl_event))
		return;
	{
		struct as_ai_nl_event *ev =
			(struct as_ai_nl_event *)NLMSG_DATA(nh);
		struct as_event out;
		const char *sev = ev->severity == 2 ? "error" :
				  ev->severity == 1 ? "warn" : "info";
		char param[25];

		memcpy(param, ev->param, sizeof(ev->param));
		param[sizeof(ev->param)] = '\0';

		as_stats_received(sp->stats, idx);
		if (ev->category == AI_NL_EV_POLICY) {
			/* decision_id = event_id，原样透传 */
			as_event_ai_policy(&out, ev->event_id, ev->code, sev,
					   param);
		} else if (ev->category == AI_NL_EV_MODEL) {
			as_event_ai_model(&out, ev->event_id, ev->code,
					  param);
		} else if (ev->category == AS_AI_NL_EV_DEVICE) {
			/* K3d-2：16.01 对齐（code 0=probe 1=remove，param=dev） */
			as_event_ai_device(&out, ev->code != 0, param);
		} else if (ev->category == AS_AI_NL_EV_CPU_HOTPLUG) {
			/* K3d-2：01.07 对齐（code=online 位，param=cpu 号） */
			as_event_ai_cpu(&out, ev->code != 0, atoi(param));
		} else if (ev->category == AS_AI_NL_EV_HW_ERROR) {
			/* K3d-2：16.03 对齐（param="cpu,bank"） */
			int mc = -1, mb = -1;

			sscanf(param, "%d,%d", &mc, &mb);
			as_event_ai_mce(&out, mc, mb, sev);
		} else {
			as_event_mk(&out, idx, "other", sev,
				    "event_id=%llu category=%u",
				    (unsigned long long)ev->event_id,
				    ev->category);
		}
		sp->on_event(&out, sp->ud);
	}
}

/* ====================================================================
 * 2) proc：CN_PROC（抽取自 ai_streams.c proc_send_mcast_listen）
 * ==================================================================== */
static int proc_send_mcast_listen(int fd)
{
	char buf[NLMSG_SPACE(sizeof(struct cn_msg) + 4)];
	struct sockaddr_nl dst;
	struct nlmsghdr *nh;
	struct cn_msg *cn;
	enum proc_cn_mcast_op op = PROC_CN_MCAST_LISTEN;

	memset(buf, 0, sizeof(buf));
	nh = (struct nlmsghdr *)buf;
	nh->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(op));
	nh->nlmsg_type = NLMSG_NOOP;
	nh->nlmsg_flags = NLM_F_REQUEST;
	nh->nlmsg_seq = 1;
	cn = (struct cn_msg *)NLMSG_DATA(nh);
	cn->id.idx = CN_IDX_PROC;
	cn->id.val = CN_VAL_PROC;
	cn->seq = 1;
	cn->len = sizeof(op);
	memcpy(cn->data, &op, sizeof(op));
	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	if (sendto(fd, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst,
		   sizeof(dst)) < 0)
		return -1;
	return 0;
}

static void parse_proc_msg(struct as_streams *sp, struct nlmsghdr *nh)
{
	int idx = as_stream_idx(AS_STREAM_PROC);
	struct cn_msg *cn;
	struct proc_event *ev;

	/* connector 事件实测以 NLMSG_DONE 类型到达（ai_streams.c 实测注释），
	 * 以 cn_msg id 判别 */
	cn = (struct cn_msg *)NLMSG_DATA(nh);
	if (cn->id.idx != CN_IDX_PROC || cn->id.val != CN_VAL_PROC)
		return;
	ev = (struct proc_event *)cn->data;
	as_stats_received(sp->stats, idx);
	{
		struct as_event out;

		/* 进程粒度优先 tgid（exec/exit/fork 有）；comm/id 只有
		 * process_pid（线程 id）——uapi cn_proc.h 字段事实 */
		switch (ev->what) {
		case PROC_EVENT_FORK:
			as_event_proc_fork(&out,
				ev->event_data.fork.parent_tgid,
				ev->event_data.fork.child_tgid);
			break;
		case PROC_EVENT_EXEC:
			as_event_proc_exec(&out,
				ev->event_data.exec.process_tgid);
			break;
		case PROC_EVENT_UID:
			as_event_proc_id(&out, "uid",
				ev->event_data.id.process_pid,
				ev->event_data.id.r.ruid,
				ev->event_data.id.e.euid);
			break;
		case PROC_EVENT_GID:
			as_event_proc_id(&out, "gid",
				ev->event_data.id.process_pid,
				ev->event_data.id.r.rgid,
				ev->event_data.id.e.egid);
			break;
		case PROC_EVENT_EXIT:
			as_event_proc_exit(&out,
				ev->event_data.exit.process_tgid,
				ev->event_data.exit.exit_code);
			break;
		/* 注意：PROC_EVENT_* 是 cn_proc.h 的枚举成员而非宏——
		 * `#ifdef PROC_EVENT_COMM` 恒假（原 ai_streams.c 的隐患，
		 * 此处直接引用枚举常量；该事件自内核 3.10 起存在于 uapi） */
		case PROC_EVENT_COMM:
			as_event_proc_comm(&out,
				ev->event_data.comm.process_pid,
				ev->event_data.comm.comm);
			break;
		case PROC_EVENT_SID:
			as_event_proc_other(&out, ev->what,
				ev->event_data.sid.process_tgid);
			break;
		default:
			as_event_proc_other(&out, ev->what, 0);
			break;
		}
		sp->on_event(&out, sp->ud);
	}
}

/* ====================================================================
 * 3) net：RTNLGRP（抽取自 ai_streams.c rtnl_parse）
 * ==================================================================== */
static void addr_str(char *dst, size_t cap, int family, const void *raw,
		     int len)
{
	if (!raw || len <= 0) {
		snprintf(dst, cap, "?");
		return;
	}
	if (family == AF_INET && len >= 4) {
		inet_ntop(AF_INET, raw, dst, (socklen_t)cap);
		return;
	}
	if (family == AF_INET6 && len >= 16) {
		inet_ntop(AF_INET6, raw, dst, (socklen_t)cap);
		return;
	}
	snprintf(dst, cap, "raw(%d)", len);
}

static void parse_rtnl_msg(struct as_streams *sp, struct nlmsghdr *nh)
{
	int idx = as_stream_idx(AS_STREAM_NET);

	switch (nh->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK: {
		struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
		struct rtattr *ra;
		const char *ifname = NULL;
		int len = (int)(nh->nlmsg_len - NLMSG_HDRLEN - sizeof(*ifi));
		struct as_event out;

		for (ra = IFLA_RTA(ifi); RTA_OK(ra, len);
		     ra = RTA_NEXT(ra, len)) {
			if (ra->rta_type == IFLA_IFNAME)
				ifname = (const char *)RTA_DATA(ra);
		}
		as_stats_received(sp->stats, idx);
		as_event_net_link(&out, nh->nlmsg_type == RTM_NEWLINK,
				  ifi->ifi_index, ifname, ifi->ifi_flags);
		sp->on_event(&out, sp->ud);
		return;
	}
	case RTM_NEWADDR:
	case RTM_DELADDR: {
		struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
		struct rtattr *ra;
		void *local = NULL;
		int local_len = 0, len;
		char as[64];
		struct as_event out;

		len = (int)(nh->nlmsg_len - NLMSG_HDRLEN - sizeof(*ifa));
		for (ra = IFA_RTA(ifa); RTA_OK(ra, len);
		     ra = RTA_NEXT(ra, len)) {
			if (ra->rta_type == IFA_LOCAL) {
				local = RTA_DATA(ra);
				local_len = (int)RTA_PAYLOAD(ra);
			}
		}
		addr_str(as, sizeof(as), ifa->ifa_family, local, local_len);
		as_stats_received(sp->stats, idx);
		as_event_net_addr(&out, nh->nlmsg_type == RTM_NEWADDR,
				  ifa->ifa_family == AF_INET6 ? "inet6" :
							       "inet",
				  as, ifa->ifa_prefixlen, ifa->ifa_index);
		sp->on_event(&out, sp->ud);
		return;
	}
	case RTM_NEWROUTE:
	case RTM_DELROUTE: {
		struct rtmsg *r = (struct rtmsg *)NLMSG_DATA(nh);
		struct rtattr *ra;
		void *dsta = NULL, *gw = NULL;
		int dst_len = 0, gw_len = 0, oif = 0;
		int len = (int)(nh->nlmsg_len - NLMSG_HDRLEN - sizeof(*r));
		char ds[64], gs[64];
		struct as_event out;

		for (ra = RTM_RTA(r); RTA_OK(ra, len);
		     ra = RTA_NEXT(ra, len)) {
			if (ra->rta_type == RTA_DST) {
				dsta = RTA_DATA(ra);
				dst_len = (int)RTA_PAYLOAD(ra);
			} else if (ra->rta_type == RTA_GATEWAY) {
				gw = RTA_DATA(ra);
				gw_len = (int)RTA_PAYLOAD(ra);
			} else if (ra->rta_type == RTA_OIF &&
				   RTA_PAYLOAD(ra) >= 4) {
				memcpy(&oif, RTA_DATA(ra), 4);
			}
		}
		addr_str(ds, sizeof(ds), r->rtm_family, dsta, dst_len);
		if (gw)
			addr_str(gs, sizeof(gs), r->rtm_family, gw, gw_len);
		else
			gs[0] = '\0';
		as_stats_received(sp->stats, idx);
		as_event_net_route(&out, nh->nlmsg_type == RTM_NEWROUTE,
				   r->rtm_family == AF_INET6 ? "inet6" :
							      "inet",
				   ds, r->rtm_dst_len, oif, gs);
		sp->on_event(&out, sp->ud);
		return;
	}
	default:
		return;
	}
}

/* ====================================================================
 * 4) uevent：KOBJECT_UEVENT（原始文本；抽取自 ai_streams.c udev 循环）
 * ==================================================================== */
static void parse_uevent_buf(struct as_streams *sp, char *buf, ssize_t n)
{
	int idx = as_stream_idx(AS_STREAM_UEVENT);
	char *p = buf, *end = buf + n;
	char action[16] = "?", devpath[400] = "?", subsys[64] = "?";
	struct as_event out;

	/* 首段 "verb@devpath"，其后 KEY=VAL\0 序列（取 SUBSYSTEM） */
	while (p < end) {
		char *nul = memchr(p, '\0', (size_t)(end - p));

		if (!nul)
			break;
		if (p[0] == '\0') {
			p++;
			continue;
		}
		if (p == buf && strchr(p, '@')) {
			char *at = strchr(p, '@');

			*at = '\0';
			snprintf(action, sizeof(action), "%.15s", p);
			snprintf(devpath, sizeof(devpath), "%.399s", at + 1);
		} else {
			char *eq = strchr(p, '=');

			if (eq && strncmp(p, "SUBSYSTEM=", 10) == 0) {
				*eq = '\0';
				snprintf(subsys, sizeof(subsys), "%.63s",
					 eq + 1);
			}
		}
		p = nul + 1;
	}
	as_stats_received(sp->stats, idx);
	as_event_uevent(&out, action, devpath, subsys);
	sp->on_event(&out, sp->ud);
}

/* ====================================================================
 * 5) nflog：NFNETLINK_LOG（抽取自 ai_streams.c nflog_cfg_send/nflog_parse）
 * ==================================================================== */
static int nflog_cfg_send(int fd, uint8_t cmd, uint16_t res_id)
{
	char buf[NLMSG_SPACE(sizeof(struct nfgenmsg) + 16)];
	struct sockaddr_nl dst;
	struct nlmsghdr *nh;
	struct nfgenmsg *ng;
	struct {
		uint16_t len;
		uint16_t type;
		uint8_t cmd;
		uint8_t pad;
	} *attr;

	memset(buf, 0, sizeof(buf));
	nh = (struct nlmsghdr *)buf;
	nh->nlmsg_len = NLMSG_LENGTH(sizeof(*ng) + 8);
	nh->nlmsg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
	nh->nlmsg_flags = NLM_F_REQUEST;
	nh->nlmsg_seq = (cmd == NFULNL_CFG_CMD_PF_BIND) ? 10 : 11;
	ng = (struct nfgenmsg *)NLMSG_DATA(nh);
	ng->nfgen_family = AF_UNSPEC;
	ng->version = NFNETLINK_V0;
	ng->res_id = htons(res_id);
	attr = (void *)((char *)ng + sizeof(*ng));
	attr->len = 8;
	attr->type = NFULA_CFG_CMD;
	attr->cmd = cmd;
	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	if (sendto(fd, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst,
		   sizeof(dst)) < 0)
		return -1;
	return 0;
}

static void parse_nflog_msg(struct as_streams *sp, struct nlmsghdr *nh)
{
	int idx = as_stream_idx(AS_STREAM_NFLOG);
	struct nfulnl_msg_packet_hdr *hdr;
	struct {
		uint16_t len;
		uint16_t type;
	} *a;
	int alen;
	uint32_t mark = 0, uid = 0;
	int has_uid = 0;
	const char *prefix = NULL;
	int prefix_len = 0;
	struct as_event out;

	if ((nh->nlmsg_type >> 8) != NFNL_SUBSYS_ULOG)
		return;
	if ((nh->nlmsg_type & 0xff) != NFULNL_MSG_PACKET)
		return;
	hdr = (struct nfulnl_msg_packet_hdr *)NLMSG_DATA(nh);
	alen = (int)(nh->nlmsg_len - NLMSG_HDRLEN -
		     NLMSG_ALIGN(sizeof(*hdr)));
	a = (void *)((char *)hdr + NLMSG_ALIGN(sizeof(*hdr)));
	for (; alen >= 4; ) {
		int l = a->len;
		int t = a->type;

		if (l < 4 || l > alen)
			break;
		{
			const void *d = (const char *)a + 4;
			int dl = l - 4;

			switch (t) {
			case NFULA_MARK:
				if (dl >= 4)
					memcpy(&mark, d, 4);
				break;
			case NFULA_UID:
				if (dl >= 4) {
					memcpy(&uid, d, 4);
					has_uid = 1;
				}
				break;
			case NFULA_PREFIX:
				if (dl > 0) {
					prefix = (const char *)d;
					prefix_len = dl;
				}
				break;
			default:
				break;
			}
		}
		l = (l + 3) & ~3;
		if (l <= 0 || l > alen)
			break;
		a = (void *)((char *)a + l);
		alen -= l;
	}
	as_stats_received(sp->stats, idx);
	{
		char pfx[80];

		if (prefix) {
			/* NFULA_PREFIX 不保证 NUL 结尾：按 attr 长度定界拷贝 */
			int i, m = prefix_len < (int)sizeof(pfx) - 1 ?
				  prefix_len : (int)sizeof(pfx) - 1;

			for (i = 0; i < m && prefix[i]; i++)
				pfx[i] = prefix[i];
			pfx[i] = '\0';
			as_event_nflog(&out, hdr->hook, mark, pfx, has_uid,
				       uid);
		} else {
			as_event_nflog(&out, hdr->hook, mark, NULL, has_uid,
				       uid);
		}
	}
	sp->on_event(&out, sp->ud);
}

/* ====================================================================
 * 6) taskstats：周期采样（genl 请求-应答；族解析抽取自
 *    ai_streams.c genl_resolve_family；聚合器为本文件新增）
 * ==================================================================== */
static int genl_resolve_family(int fd, const char *name, uint16_t *id)
{
	char buf[4096];
	struct sockaddr_nl dst;
	struct nlmsghdr *nh;
	struct genlmsghdr *gh;
	struct rtattr *ra;
	int alen;
	ssize_t n;

	memset(buf, 0, sizeof(buf));
	nh = (struct nlmsghdr *)buf;
	nh->nlmsg_type = GENL_ID_CTRL;
	nh->nlmsg_flags = NLM_F_REQUEST;
	nh->nlmsg_seq = 1;
	gh = (struct genlmsghdr *)NLMSG_DATA(nh);
	gh->cmd = CTRL_CMD_GETFAMILY;
	gh->version = 1;
	ra = (struct rtattr *)((char *)gh + sizeof(*gh));
	ra->rta_type = CTRL_ATTR_FAMILY_NAME;
	ra->rta_len = RTA_LENGTH((int)strlen(name) + 1);
	memcpy(RTA_DATA(ra), name, strlen(name) + 1);
	nh->nlmsg_len = NLMSG_LENGTH(sizeof(*gh) +
				     RTA_LENGTH(strlen(name) + 1));
	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	if (sendto(fd, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst,
		   sizeof(dst)) < 0)
		return -1;
	n = recv(fd, buf, sizeof(buf), 0);
	if (n < (ssize_t)sizeof(*nh))
		return -1;
	nh = (struct nlmsghdr *)buf;
	if (nh->nlmsg_type == NLMSG_ERROR)
		return -1;
	gh = (struct genlmsghdr *)NLMSG_DATA(nh);
	alen = (int)(nh->nlmsg_len - NLMSG_HDRLEN - sizeof(*gh));
	for (ra = (struct rtattr *)((char *)gh + sizeof(*gh));
	     RTA_OK(ra, alen); ra = RTA_NEXT(ra, alen)) {
		if (ra->rta_type == CTRL_ATTR_FAMILY_ID &&
		    RTA_PAYLOAD(ra) >= 2) {
			memcpy(id, RTA_DATA(ra), 2);
			return 0;
		}
	}
	return -1;
}

struct ts_agg {
	long long cpu_delay_ns;
	long long blkio_delay_ns;
	unsigned long long swapin_count;
	int n;
};

static void ts_accum(struct ts_agg *agg, const struct taskstats *t)
{
	agg->cpu_delay_ns += (long long)t->cpu_delay_total;
	agg->blkio_delay_ns += (long long)t->blkio_delay_total;
	agg->swapin_count += (unsigned long long)t->swapin_count;
	agg->n++;
}

static int ts_parse_reply(struct nlmsghdr *nh, struct ts_agg *agg)
{
	struct genlmsghdr *gh;
	struct rtattr *ra;
	int alen;

	if (nh->nlmsg_type == NLMSG_ERROR) {
		/* 单 pid 失败（内核线程/已退出 pid）不中断整轮——跳过 */
		return 0;
	}
	gh = (struct genlmsghdr *)NLMSG_DATA(nh);
	alen = (int)(nh->nlmsg_len - NLMSG_HDRLEN - sizeof(*gh));
	for (ra = (struct rtattr *)((char *)gh + sizeof(*gh));
	     RTA_OK(ra, alen); ra = RTA_NEXT(ra, alen)) {
		if (ra->rta_type == TASKSTATS_TYPE_STATS &&
		    RTA_PAYLOAD(ra) >= (int)sizeof(struct taskstats)) {
			ts_accum(agg, (struct taskstats *)RTA_DATA(ra));
		} else if (ra->rta_type == TASKSTATS_TYPE_AGGR_PID ||
			   ra->rta_type == TASKSTATS_TYPE_AGGR_TGID) {
			/* 内核实际返回形态：AGGR_{PID,TGID}{ PID, STATS }
			 * 嵌套（抽取源 ai_streams.c ts_parse 同款处理） */
			struct rtattr *inner = (struct rtattr *)RTA_DATA(ra);
			int ilen = (int)RTA_PAYLOAD(ra);

			for (; RTA_OK(inner, ilen);
			     inner = RTA_NEXT(inner, ilen)) {
				if (inner->rta_type == TASKSTATS_TYPE_STATS &&
				    RTA_PAYLOAD(inner) >=
				    (int)sizeof(struct taskstats))
					ts_accum(agg,
						 (struct taskstats *)
						 RTA_DATA(inner));
			}
		}
	}
	return 0;
}

static int ts_send_query(int fd, uint16_t fam, uint32_t seq, uint32_t pid)
{
	char buf[512];
	struct sockaddr_nl dst;
	struct nlmsghdr *nh;
	struct genlmsghdr *gh;
	struct rtattr *ra;
	uint32_t pid32 = pid;

	memset(buf, 0, sizeof(buf));
	nh = (struct nlmsghdr *)buf;
	gh = (struct genlmsghdr *)NLMSG_DATA(nh);
	ra = (struct rtattr *)((char *)gh + sizeof(*gh));
	ra->rta_type = TASKSTATS_TYPE_PID;
	ra->rta_len = RTA_LENGTH(sizeof(pid32));
	memcpy(RTA_DATA(ra), &pid32, sizeof(pid32));
	nh->nlmsg_len = NLMSG_LENGTH(sizeof(*gh) +
				     RTA_LENGTH(sizeof(pid32)));
	nh->nlmsg_type = fam;
	nh->nlmsg_flags = NLM_F_REQUEST;
	nh->nlmsg_seq = seq;
	gh->cmd = TASKSTATS_CMD_GET;
	gh->version = 1;
	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	if (sendto(fd, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst,
		   sizeof(dst)) < 0)
		return -1;
	return 0;
}

/* 一轮采样：批量发请求 → 有限预算内收应答（整轮 ≤ ~3s，不逐 pid 阻塞） */
int as_streams_taskstats_tick(struct as_streams *sp)
{
	int idx = as_stream_idx(AS_STREAM_TASKSTATS);
	DIR *d;
	struct dirent *de;
	struct ts_agg agg;
	int sent = 0;
	long long deadline;
	struct as_event out;

	if (sp->fd_ts < 0 || sp->ts_family == 0)
		return 0;
	sp->ts_last_ms = as_now_mono_ms();
	sp->ts_next_ms = sp->ts_last_ms +
		sp->conf->taskstats_interval_sec * 1000;
	memset(&agg, 0, sizeof(agg));
	/* 先收集 pid 列表（上限 taskstats_max_pids；4096=conf 硬顶） */
	{
		static uint32_t pids[4096];
		int npids = 0;

		d = opendir("/proc");
		if (!d)
			return 0;
		while ((de = readdir(d)) && npids < 4096 &&
		       npids < sp->conf->taskstats_max_pids) {
			char *end;
			long pid;

			if (de->d_name[0] < '0' || de->d_name[0] > '9')
				continue;
			pid = strtol(de->d_name, &end, 10);
			if (*end != '\0' || pid <= 0)
				continue;
			pids[npids++] = (uint32_t)pid;
		}
		closedir(d);
		/* 分批（32 pid/批）发+收：不淹没 rcvbuf，错误应答不中断 */
		for (int b = 0; b < npids; b += 32) {
			int bend = b + 32 < npids ? b + 32 : npids;

			for (int i = b; i < bend; i++) {
				if (ts_send_query(sp->fd_ts,
						  (uint16_t)sp->ts_family,
						  ++sp->ts_seq, pids[i]) == 0)
					sent++;
			}
			deadline = as_now_mono_ms() + 500;
			while (as_now_mono_ms() < deadline) {
				struct pollfd pfd = { .fd = sp->fd_ts,
						      .events = POLLIN };
				long long remain = deadline -
						   as_now_mono_ms();
				char buf[65536];
				ssize_t n;

				if (poll(&pfd, 1, (int)remain) <= 0)
					break;
				n = recv(sp->fd_ts, buf, sizeof(buf),
					 MSG_DONTWAIT);
				if (n <= 0)
					break;
				for (struct nlmsghdr *h =
					(struct nlmsghdr *)buf;
				     NLMSG_OK(h, (unsigned)n);
				     h = NLMSG_NEXT(h, n))
					ts_parse_reply(h, &agg);
			}
		}
	}
	as_log_debug("taskstats round: queried=%d stats=%d", sent, agg.n);
	if (agg.n == 0)
		return 0;
	/* 仅当存在非零延迟字段才产出（delayacct 关闭时内核回全零——
	 * 诚实不刷屏；journal debug 记录轮次） */
	if (agg.cpu_delay_ns == 0 && agg.blkio_delay_ns == 0 &&
	    agg.swapin_count == 0)
		return 0;
	as_stats_received(sp->stats, idx);
	as_event_taskstats(&out, agg.n,
			   (double)agg.cpu_delay_ns / 1e6,
			   (double)agg.blkio_delay_ns / 1e6,
			   agg.swapin_count);
	sp->on_event(&out, sp->ud);
	return 1;
}

long long as_streams_taskstats_due_ms(const struct as_streams *sp)
{
	if (sp->fd_ts < 0)
		return -1;
	return sp->ts_next_ms - as_now_mono_ms();
}

/* ====================================================================
 * setup / poll / dispatch
 * ==================================================================== */
int as_streams_setup(struct as_streams *sp, struct as_conf *c,
		     struct as_stats *st,
		     void (*on_event)(struct as_event *ev, void *u),
		     void *ud)
{
	int err = 0;
	int idx;

	memset(sp, 0, sizeof(*sp));
	sp->conf = c;
	sp->stats = st;
	sp->on_event = on_event;
	sp->ud = ud;
	sp->fd_event = -1;
	sp->fd_proc = -1;
	sp->fd_net = -1;
	sp->fd_uevent = -1;
	sp->fd_nflog = -1;
	sp->fd_ts = -1;
	sp->ts_family = 0;
	sp->ts_seq = 100;
	sp->ts_next_ms = as_now_mono_ms() + c->taskstats_interval_sec * 1000;

	/* event */
	idx = as_stream_idx(AS_STREAM_EVENT);
	if (!c->enable_event)
		st->per[idx].state = AS_ST_DISABLED;
	else
		setup_ai(sp);

	/* proc */
	idx = as_stream_idx(AS_STREAM_PROC);
	if (!c->enable_proc) {
		st->per[idx].state = AS_ST_DISABLED;
	} else {
		int groups[1] = { CN_IDX_PROC };
		int fd = nl_open(NETLINK_CONNECTOR, groups, 1, &err);

		if (fd < 0 || proc_send_mcast_listen(fd) < 0) {
			if (fd >= 0)
				close(fd);
			degrade(st, idx, "proc-connector",
				fd < 0 ? err : errno);
		} else {
			sock_big_rcvbuf(fd);
			sp->fd_proc = fd;
			st->per[idx].state = AS_ST_RUNNING;
			as_log("stream proc: CN_PROC subscribed");
		}
	}

	/* net */
	idx = as_stream_idx(AS_STREAM_NET);
	if (!c->enable_net) {
		st->per[idx].state = AS_ST_DISABLED;
	} else {
		int groups[5] = { RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR,
				  RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV4_ROUTE,
				  RTNLGRP_IPV6_ROUTE };
		int fd = nl_open(NETLINK_ROUTE, groups, 5, &err);

		if (fd < 0) {
			degrade(st, idx, "rtnetlink", err);
		} else {
			sock_big_rcvbuf(fd);
			sp->fd_net = fd;
			st->per[idx].state = AS_ST_RUNNING;
			as_log("stream net: RTNLGRPs subscribed (5 groups)");
		}
	}

	/* uevent */
	idx = as_stream_idx(AS_STREAM_UEVENT);
	if (!c->enable_uevent) {
		st->per[idx].state = AS_ST_DISABLED;
	} else {
		int groups[1] = { 1 };
		int fd = nl_open(NETLINK_KOBJECT_UEVENT, groups, 1, &err);

		if (fd < 0) {
			degrade(st, idx, "kobject-uevent", err);
		} else {
			sock_big_rcvbuf(fd);
			sp->fd_uevent = fd;
			st->per[idx].state = AS_ST_RUNNING;
			as_log("stream uevent: KOBJECT_UEVENT group 1");
		}
	}

	/* nflog */
	idx = as_stream_idx(AS_STREAM_NFLOG);
	if (!c->enable_nflog) {
		st->per[idx].state = AS_ST_DISABLED;
	} else {
		int fd = nl_open(NETLINK_NETFILTER, NULL, 0, &err);

		if (fd < 0 || nflog_cfg_send(fd, NFULNL_CFG_CMD_PF_BIND, 0) ||
		    nflog_cfg_send(fd, NFULNL_CFG_CMD_BIND, 0)) {
			if (fd >= 0)
				close(fd);
			degrade(st, idx, "nflog",
				fd < 0 ? err : errno);
		} else {
			sock_big_rcvbuf(fd);
			sp->fd_nflog = fd;
			st->per[idx].state = AS_ST_RUNNING;
			/* socket 已就绪但无 nft log 规则时无事件（真订阅） */
			as_log("stream nflog: bound group 0 (events require"
			       " nft log rule)");
		}
	}

	/* taskstats（请求 socket + 族解析；采样在 tick） */
	idx = as_stream_idx(AS_STREAM_TASKSTATS);
	if (!c->enable_taskstats) {
		st->per[idx].state = AS_ST_DISABLED;
	} else {
		uint16_t fam = 0;
		int fd = nl_open(NETLINK_GENERIC, NULL, 0, &err);

		if (fd < 0) {
			degrade(st, idx, "taskstats-socket", err);
		} else if (genl_resolve_family(fd, TASKSTATS_GENL_NAME,
					       &fam) < 0) {
			close(fd);
			st->per[idx].state = AS_ST_STOPPED;
			as_warn_ratelimit("taskstats-family", 3600000,
				"stream taskstats degraded (stopped): "
				"TASKSTATS genl family missing — daemon "
				"continues");
		} else {
			sock_big_rcvbuf(fd);
			sp->fd_ts = fd;
			sp->ts_family = fam;
			st->per[idx].state = AS_ST_RUNNING;
			as_log("stream taskstats: family=%u interval=%llds",
			       fam, c->taskstats_interval_sec);
		}
	}

	return 0;
}

void as_streams_close_all(struct as_streams *sp)
{
	int fds[6] = { sp->fd_event, sp->fd_proc, sp->fd_net, sp->fd_uevent,
		       sp->fd_nflog, sp->fd_ts };

	for (int i = 0; i < 6; i++)
		if (fds[i] >= 0)
			close(fds[i]);
	sp->fd_event = sp->fd_proc = sp->fd_net = -1;
	sp->fd_uevent = sp->fd_nflog = sp->fd_ts = -1;
}

int as_streams_fill_poll(struct as_streams *sp, struct pollfd *pfds,
			 int *idx_map, int max)
{
	int n = 0;
	int fds[AS_NSTREAMS] = { sp->fd_event, sp->fd_proc, sp->fd_net,
				 sp->fd_uevent, sp->fd_nflog, -1 };

	for (int i = 0; i < AS_NSTREAMS && n < max; i++) {
		if (fds[i] < 0 || sp->stats->per[i].state != AS_ST_RUNNING)
			continue;
		pfds[n].fd = fds[i];
		pfds[n].events = POLLIN;
		pfds[n].revents = 0;
		idx_map[n] = i;
		n++;
	}
	return n;
}

int as_streams_dispatch(struct as_streams *sp, int stream_idx)
{
	char buf[65536];
	ssize_t n;
	int count = 0;
	int fd;

	if (stream_idx == as_stream_idx(AS_STREAM_UEVENT)) {
		n = recv(sp->fd_uevent, buf, sizeof(buf) - 1, MSG_DONTWAIT);
		if (n <= 0) {
			if (n < 0 && errno != EAGAIN && errno != EINTR)
				as_warn_ratelimit("uevent-recv", 60000,
						  "uevent recv: %s",
						  strerror(errno));
			return 0;
		}
		buf[n] = '\0';
		parse_uevent_buf(sp, buf, n);
		return 1;
	}
	fd = stream_idx == as_stream_idx(AS_STREAM_EVENT) ? sp->fd_event :
	     stream_idx == as_stream_idx(AS_STREAM_PROC) ? sp->fd_proc :
	     stream_idx == as_stream_idx(AS_STREAM_NET) ? sp->fd_net :
	     sp->fd_nflog;
	if (fd < 0)
		return 0;
	n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (n <= 0) {
		if (n < 0 && errno != EAGAIN && errno != EINTR)
			as_warn_ratelimit("nl-recv", 60000,
					  "stream %s recv: %s",
					  as_stream_name(stream_idx),
					  strerror(errno));
		return 0;
	}
	for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	     NLMSG_OK(nh, (unsigned)n) && count < 256;
	     nh = NLMSG_NEXT(nh, n)) {
		if (stream_idx == as_stream_idx(AS_STREAM_EVENT))
			parse_ai_msg(sp, nh);
		else if (stream_idx == as_stream_idx(AS_STREAM_PROC))
			parse_proc_msg(sp, nh);
		else if (stream_idx == as_stream_idx(AS_STREAM_NET))
			parse_rtnl_msg(sp, nh);
		else if (stream_idx == as_stream_idx(AS_STREAM_NFLOG))
			parse_nflog_msg(sp, nh);
		else
			break;
		count++;
	}
	return count;
}
