/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ai_streams.c - W78 六条内核事件流订阅实现
 *
 * 流与协议：
 *   event_listen   NETLINK_AI(31)：REG 登记 portid 后收 AI_CMD_EVENT
 *                  （策略 category=1 / 模型 category=2 推送）
 *   proc_watch     NETLINK_CONNECTOR + CN_PROC：MCAST_LISTEN 后收
 *                  fork/exec/exit/uid/comm 事件（需 CAP_NET_ADMIN）
 *   taskstats_sample NETLINK_GENERIC + TASKSTATS 族：按 pid 拉延迟记账
 *   nflog_dump     NETLINK_NETFILTER + NFNLGRP_CONNLOG：NFLOG 包级取证
 *                  （需 nft 规则带 log 目标才有事件）
 *   net_monitor    NETLINK_ROUTE + RTNLGRP_{LINK,IFADDR,ROUTE} 组播
 *   udev_monitor   NETLINK_KOBJECT_UEVENT 组 1：内核设备事件（原始文本
 *                  协议，非 nlmsg 帧）
 *
 * 输出统一 JSON 行；事件时间 ts 为本进程 CLOCK_MONOTONIC 毫秒。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
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
#include "ai_streams.h"
#include "netlink/ai_netlink_client.h"

/* ---- 公共小工具 ---- */

long long ai_streams_clamp_ll(long long v, long long lo, long long hi,
			      long long dflt)
{
	if (v < lo || v > hi)
		return dflt;
	return v;
}

int ai_streams_json_escape(const char *in, char *out, size_t cap)
{
	size_t o = 0;

	if (!in || !out || cap < 2)
		return -1;
	for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
		char tmp[8];

		if (*p == '"' || *p == '\\') {
			snprintf(tmp, sizeof(tmp), "\\%c", *p);
		} else if (*p < 0x20) {
			snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
		} else {
			tmp[0] = (char)*p;
			tmp[1] = '\0';
		}
		size_t l = strlen(tmp);

		if (o + l + 1 >= cap)
			return -1;
		memcpy(out + o, tmp, l);
		o += l;
	}
	out[o] = '\0';
	return 0;
}

/* 把字符串以 JSON 值写进 FILE*（带引号转义） */
static void jstr(FILE *f, const char *s)
{
	char tmp[4096];

	if (ai_streams_json_escape(s ? s : "", tmp, sizeof(tmp)) == 0)
		fprintf(f, "\"%s\"", tmp);
	else
		fprintf(f, "\"<too-long>\"");
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void hex_out(FILE *f, const unsigned char *p, int n)
{
	fprintf(f, "\"");
	for (int i = 0; i < n; i++)
		fprintf(f, "%02x", p[i]);
	fprintf(f, "\"");
}

/* 打开 netlink 套接字并（可选）加入组播组；失败返回 -1 且 err 收 errno。
 * 组加入用双保险：组号 1..31 走 bind 时 nl_groups 位掩码（iproute2 同款，
 * W78 实测 setsockopt ADD_MEMBERSHIP 在部分内核不投递、位掩码可靠），
 * 同时也尝试 setsockopt 成员加入（>31 的组只有这条路）。 */
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

/*
 * 通用 nlmsg 接收循环：parse 返回 1=产出一条事件（已写 FILE*），0=忽略，
 * -1=致命解析错误（终止循环）。返回收到的事件数（-1=传输错误）。
 */
static int recv_loop_nlmsg(int fd, int timeout_ms, int max_events,
			   int (*parse)(struct nlmsghdr *hdr, void *u),
			   void *u)
{
	char buf[65536];
	long long deadline = now_ms() + timeout_ms;
	int count = 0;

	while (count < max_events) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		long long remain = deadline - now_ms();
		int n;

		if (remain <= 0)
			break;
		n = poll(&pfd, 1, (int)remain);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0 || !(pfd.revents & POLLIN))
			continue;
		n = (int)recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (n == 0)
			continue;
		for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
		     NLMSG_OK(nh, (unsigned)n);
		     nh = NLMSG_NEXT(nh, n)) {
			int r = parse(nh, u);

			if (r < 0)
				return count;
			if (r > 0 && ++count >= max_events)
				return count;
		}
	}
	return count;
}

/* 汇总首行 + 事件体拼装（events 为事件行内容，n 为条数） */
static char *compose_out(const char *stream, int timeout_ms, int max_events,
			 int n, char *events)
{
	char *out = NULL;

	if (asprintf(&out,
		     "{\"stream\":\"%s\",\"timeout_ms\":%d,"
		     "\"max_events\":%d,\"events\":%d}%s%s",
		     stream, timeout_ms, max_events, n,
		     n ? "\n" : "", events ? events : "") < 0)
		return NULL;
	return out;
}

static int err_out(char **out, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (vasprintf(out, fmt, ap) < 0)
		*out = NULL;
	va_end(ap);
	return AI_ERR_NETWORK;
}

/* ---- 1) event_listen：NETLINK_AI 异步事件 ---- */

#ifndef AI_CMD_EVENT
/* 宿主机无 AIKernel uapi 头时的最小回退视图（对齐 uapi ai_netlink.h） */
#define AI_CMD_EVENT 19
struct ai_nl_event_min {
	uint64_t ts;
	uint64_t event_id;
	uint32_t category;
	uint32_t severity;
	int32_t code;
	uint32_t reserved;
	char param[24];
};
#define AI_HAVE_LOCAL_EVENT 1
#endif

struct ev_ctx {
	FILE *f;
	int rc_ok;
};

static int ev_parse(struct nlmsghdr *nh, void *u)
{
	struct ev_ctx *c = (struct ev_ctx *)u;

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);

		if (e->error) {
			fprintf(c->f,
				"{\"stream\":\"event\",\"error\":\"kernel error %d\"}\n",
				e->error);
			return -1;
		}
		return 0;
	}
	if (nh->nlmsg_type != AI_CMD_EVENT)
		return 0;
#ifdef AI_HAVE_LOCAL_EVENT
	struct ai_nl_event_min *ev = (struct ai_nl_event_min *)NLMSG_DATA(nh);
#else
	struct ai_nl_event *ev = (struct ai_nl_event *)NLMSG_DATA(nh);
#endif
	const char *cat = ev->category == 1 ? "policy" :
			  ev->category == 2 ? "model" : "other";
	const char *sev = ev->severity == 2 ? "error" :
			  ev->severity == 1 ? "warn" : "info";

	fprintf(c->f,
		"{\"stream\":\"event\",\"ts_ms\":%lld,\"event_id\":%llu,"
		"\"category\":\"%s\",\"severity\":\"%s\",\"code\":%d,\"param\":",
		now_ms(), (unsigned long long)ev->event_id, cat, sev,
		ev->code);
	jstr(c->f, ev->param);
	fprintf(c->f, "}\n");
	return 1;
}

int ai_streams_event_listen(int timeout_ms, int max_events, char **out)
{
	struct ai_nl_client cli;
	struct ev_ctx c;
	char *body = NULL;
	size_t body_len = 0;
	int rc, kern_err = 0, n;

	rc = ai_nl_client_open(&cli);
	if (rc != AI_OK) {
		return err_out(out, "ERROR: NETLINK_AI 通道不可用（%s）——"
			     "本工具需在 AIKernel 内核上运行",
			     ai_error_string(rc));
	}
	rc = ai_nl_send_reg(&cli, 0, NULL, NULL, &kern_err);
	if (rc == AI_ERR_API) {
		const char *hint = ai_nl_errno_hint(kern_err);

		ai_nl_client_close(&cli);
		return err_out(out, "ERROR: 内核拒绝 REG 登记事件端口"
			     "（errno=%d %s）%s%s——事件订阅需要 root/"
			     "CAP_SYS_ADMIN 会话", kern_err, strerror(kern_err),
			     hint ? "提示: " : "", hint ? hint : "");
	}
	if (rc != AI_OK) {
		ai_nl_client_close(&cli);
		return err_out(out, "ERROR: NETLINK_AI REG 失败: %s",
			     ai_error_string(rc));
	}

	c.f = open_memstream(&body, &body_len);
	if (!c.f) {
		ai_nl_client_close(&cli);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	n = recv_loop_nlmsg(cli.fd, timeout_ms, max_events, ev_parse, &c);
	fclose(c.f);
	ai_nl_client_close(&cli);
	if (n < 0) {
		free(body);
		return err_out(out, "ERROR: 事件接收失败: %s", strerror(errno));
	}
	*out = compose_out("event", timeout_ms, max_events, n, body);
	free(body);
	if (!*out) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	return AI_OK;
}

/* ---- 2) proc_watch：proc connector ---- */

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

static const char *proc_what_str(int what)
{
	switch (what) {
	case PROC_EVENT_FORK: return "fork";
	case PROC_EVENT_EXEC: return "exec";
	case PROC_EVENT_UID: return "uid";
	case PROC_EVENT_GID: return "gid";
	case PROC_EVENT_EXIT: return "exit";
#ifdef PROC_EVENT_COMM
	case PROC_EVENT_COMM: return "comm";
#endif
	default: return "other";
	}
}

static int proc_parse(struct nlmsghdr *nh, void *u)
{
	struct ev_ctx *c = (struct ev_ctx *)u;
	struct cn_msg *cn;
	struct proc_event *ev;

	/* 注意：connector 事件实测以 NLMSG_DONE(3) 类型到达（非 NOOP），
	 * 类型不可作过滤条件，以 cn_msg 的 id.idx/id.val 判别。 */
	cn = (struct cn_msg *)NLMSG_DATA(nh);
	if (cn->id.idx != CN_IDX_PROC || cn->id.val != CN_VAL_PROC)
		return 0;
	ev = (struct proc_event *)cn->data;
	fprintf(c->f, "{\"stream\":\"proc\",\"ts_ms\":%lld,\"event\":\"%s\"",
		now_ms(), proc_what_str(ev->what));
	switch (ev->what) {
	case PROC_EVENT_FORK:
		fprintf(c->f,
			",\"parent_pid\":%d,\"parent_tgid\":%d,"
			"\"child_pid\":%d,\"child_tgid\":%d",
			ev->event_data.fork.parent_pid, ev->event_data.fork.parent_tgid,
			ev->event_data.fork.child_pid, ev->event_data.fork.child_tgid);
		break;
	case PROC_EVENT_EXEC:
		fprintf(c->f, ",\"pid\":%d,\"tgid\":%d",
			ev->event_data.exec.process_pid, ev->event_data.exec.process_tgid);
		break;
	case PROC_EVENT_UID:
		fprintf(c->f, ",\"pid\":%d,\"ruid\":%u,\"euid\":%u",
			ev->event_data.id.process_pid, ev->event_data.id.r.ruid,
			ev->event_data.id.e.euid);
		break;
	case PROC_EVENT_GID:
		fprintf(c->f, ",\"pid\":%d,\"rgid\":%u,\"egid\":%u",
			ev->event_data.id.process_pid, ev->event_data.id.r.rgid,
			ev->event_data.id.e.egid);
		break;
	case PROC_EVENT_EXIT:
		fprintf(c->f, ",\"pid\":%d,\"tgid\":%d,\"exit_code\":%u",
			ev->event_data.exit.process_pid, ev->event_data.exit.process_tgid,
			ev->event_data.exit.exit_code);
		break;
#ifdef PROC_EVENT_COMM
	case PROC_EVENT_COMM:
		fprintf(c->f, ",\"pid\":%d,\"comm\":", ev->event_data.comm.process_pid);
		jstr(c->f, ev->event_data.comm.comm);
		break;
#endif
	default:
		fprintf(c->f, ",\"what\":%d", ev->what);
		break;
	}
	fprintf(c->f, "}\n");
	return 1;
}

int ai_streams_proc_watch(int timeout_ms, int max_events, char **out)
{
	int groups[1] = { CN_IDX_PROC };
	int err = 0, fd, n;
	struct ev_ctx c;
	char *body = NULL;
	size_t body_len = 0;

	fd = nl_open(NETLINK_CONNECTOR, groups, 1, &err);
	if (fd < 0) {
		return err_out(out, "ERROR: proc connector 订阅失败"
			     "（errno=%d %s）——监听进程事件流需要 "
			     "root/CAP_NET_ADMIN，且内核需 CONFIG_PROC_EVENTS=y",
			     err, strerror(err));
	}
	if (proc_send_mcast_listen(fd) < 0) {
		close(fd);
		return err_out(out, "ERROR: 发送 CN_PROC MCAST_LISTEN 失败"
			     "（errno=%d %s）", errno, strerror(errno));
	}
	c.f = open_memstream(&body, &body_len);
	if (!c.f) {
		close(fd);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	n = recv_loop_nlmsg(fd, timeout_ms, max_events, proc_parse, &c);
	fclose(c.f);
	close(fd);
	if (n < 0) {
		free(body);
		return err_out(out, "ERROR: proc 事件接收失败: %s",
			     strerror(errno));
	}
	if (n == 0 && geteuid() != 0)
		fprintf(stderr, "proc_watch: 0 events（提示：无 root 时"
			" CN_PROC 通常被内核拒绝）\n");
	*out = compose_out("proc", timeout_ms, max_events, n, body);
	free(body);
	if (!*out) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	return AI_OK;
}

/* ---- 3) taskstats_sample：任务延迟记账 ---- */

struct ts_ctx {
	FILE *f;
	int found;
	long long pid;
};

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
	nh->nlmsg_len = NLMSG_LENGTH(sizeof(*gh) + RTA_LENGTH(64));
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
	nh->nlmsg_len = NLMSG_LENGTH(sizeof(*gh) + RTA_LENGTH(strlen(name) + 1));

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
		if (ra->rta_type == CTRL_ATTR_FAMILY_ID && RTA_PAYLOAD(ra) >= 2) {
			memcpy(id, RTA_DATA(ra), 2);
			return 0;
		}
	}
	return -1;
}

static void ts_emit(FILE *f, long long pid, struct taskstats *t)
{
	/* 注意：uapi taskstats 的延迟字段是平铺成员（非内核内部的结构体） */
	fprintf(f,
		"{\"stream\":\"taskstats\",\"pid\":%lld,\"version\":%u,"
		"\"cpu_count\":%llu,\"cpu_delay_total_ns\":%llu,"
		"\"blkio_count\":%llu,\"blkio_delay_total_ns\":%llu,"
		"\"swapin_count\":%llu,\"swapin_delay_total_ns\":%llu,"
		"\"freepages_count\":%llu,\"freepages_delay_total_ns\":%llu,"
		"\"cpu_run_real_total_ns\":%llu,"
		"\"ac_utime_us\":%llu,\"ac_stime_us\":%llu,"
		"\"nvcsw\":%llu,\"nivcsw\":%llu}\n",
		pid, t->version,
		(unsigned long long)t->cpu_count,
		(unsigned long long)t->cpu_delay_total,
		(unsigned long long)t->blkio_count,
		(unsigned long long)t->blkio_delay_total,
		(unsigned long long)t->swapin_count,
		(unsigned long long)t->swapin_delay_total,
		(unsigned long long)t->freepages_count,
		(unsigned long long)t->freepages_delay_total,
		(unsigned long long)t->cpu_run_real_total,
		(unsigned long long)t->ac_utime,
		(unsigned long long)t->ac_stime,
		(unsigned long long)t->nvcsw,
		(unsigned long long)t->nivcsw);
}

static int ts_parse(struct nlmsghdr *nh, void *u)
{
	struct ts_ctx *c = (struct ts_ctx *)u;
	struct genlmsghdr *gh;
	struct rtattr *ra;
	int alen;

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);

		fprintf(c->f,
			"{\"stream\":\"taskstats\",\"error\":\"kernel error %d\"}\n",
			e->error);
		return -1;
	}
	gh = (struct genlmsghdr *)NLMSG_DATA(nh);
	alen = (int)(nh->nlmsg_len - NLMSG_HDRLEN - sizeof(*gh));
	for (ra = (struct rtattr *)((char *)gh + sizeof(*gh));
	     RTA_OK(ra, alen); ra = RTA_NEXT(ra, alen)) {
		if (ra->rta_type == TASKSTATS_TYPE_STATS &&
		    RTA_PAYLOAD(ra) >= (int)sizeof(struct taskstats)) {
			ts_emit(c->f, c->pid,
				(struct taskstats *)RTA_DATA(ra));
			c->found = 1;
			return -1;	/* 拿到即止 */
		}
		if ((ra->rta_type == TASKSTATS_TYPE_AGGR_PID ||
		     ra->rta_type == TASKSTATS_TYPE_AGGR_TGID)) {
			struct rtattr *inner = (struct rtattr *)RTA_DATA(ra);
			int ilen = (int)RTA_PAYLOAD(ra);
			int pid = (int)c->pid;

			for (; RTA_OK(inner, ilen);
			     inner = RTA_NEXT(inner, ilen)) {
				if (inner->rta_type == TASKSTATS_TYPE_PID &&
				    RTA_PAYLOAD(inner) >= 4)
					memcpy(&pid, RTA_DATA(inner), 4);
				if (inner->rta_type == TASKSTATS_TYPE_STATS &&
				    RTA_PAYLOAD(inner) >=
				    (int)sizeof(struct taskstats)) {
					ts_emit(c->f, pid,
						(struct taskstats *)
						RTA_DATA(inner));
					c->found = 1;
					return -1;
				}
			}
		}
	}
	return 0;
}

int ai_streams_taskstats(long long pid, char **out)
{
	char buf[4096];
	struct sockaddr_nl dst;
	struct nlmsghdr *nh;
	struct genlmsghdr *gh;
	struct rtattr *ra;
	struct ts_ctx c;
	uint16_t fam = 0;
	uint32_t pid32;
	int fd, err = 0;

	fd = nl_open(NETLINK_GENERIC, NULL, 0, &err);
	if (fd < 0) {
		return err_out(out, "ERROR: NETLINK_GENERIC 打开失败"
			     "（errno=%d %s）", err, strerror(err));
	}
	if (genl_resolve_family(fd, TASKSTATS_GENL_NAME, &fam) < 0) {
		close(fd);
		return err_out(out, "ERROR: TASKSTATS generic netlink 族"
			     "不存在——内核需 CONFIG_TASKSTATS=y");
	}

	memset(buf, 0, sizeof(buf));
	nh = (struct nlmsghdr *)buf;
	gh = (struct genlmsghdr *)NLMSG_DATA(nh);
	ra = (struct rtattr *)((char *)gh + sizeof(*gh));
	pid32 = (uint32_t)pid;
	ra->rta_type = TASKSTATS_TYPE_PID;
	ra->rta_len = RTA_LENGTH(sizeof(pid32));
	memcpy(RTA_DATA(ra), &pid32, sizeof(pid32));
	nh->nlmsg_len = NLMSG_LENGTH(sizeof(*gh) + RTA_LENGTH(sizeof(pid32)));
	nh->nlmsg_type = fam;
	nh->nlmsg_flags = NLM_F_REQUEST;
	nh->nlmsg_seq = 2;
	gh->cmd = TASKSTATS_CMD_GET;
	gh->version = 1;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	if (sendto(fd, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst,
		   sizeof(dst)) < 0) {
		close(fd);
		return err_out(out, "ERROR: taskstats 请求发送失败: %s",
			     strerror(errno));
	}

	{
		char *body = NULL;
		size_t blen = 0;

		c.f = open_memstream(&body, &blen);
		if (!c.f) {
			close(fd);
			*out = strdup("ERROR: 内存不足");
			return AI_ERR_MEMORY;
		}
		c.found = 0;
		c.pid = pid;
		recv_loop_nlmsg(fd, 3000, 4, ts_parse, &c);
		fclose(c.f);
		close(fd);
		if (!c.found) {
			free(body);
			return err_out(out, "ERROR: 未取到 pid=%lld 的"
				     " taskstats（pid 不存在，或内核未开"
				     " CONFIG_TASK_DELAY_ACCT）", pid);
		}
		*out = body;
	}
	return AI_OK;
}

/* ---- 4) nflog_dump：NFLOG 包级取证 ---- */

struct nflog_ctx {
	FILE *f;
	int payload_bytes;
};

static int nflog_parse(struct nlmsghdr *nh, void *u)
{
	struct nflog_ctx *c = (struct nflog_ctx *)u;
	struct nfulnl_msg_packet_hdr *hdr;
	struct {
		uint16_t len;
		uint16_t type;
	} *a;
	int alen;
	uint32_t mark = 0, uid = 0;
	int has_uid = 0;
	int ifin = 0, ifout = 0;
	const char *prefix = NULL;
	const unsigned char *payload = NULL;
	int payload_len = 0;

	if ((nh->nlmsg_type >> 8) != NFNL_SUBSYS_ULOG)
		return 0;
	if ((nh->nlmsg_type & 0xff) != NFULNL_MSG_PACKET)
		return 0;
	hdr = (struct nfulnl_msg_packet_hdr *)NLMSG_DATA(nh);
	alen = (int)(nh->nlmsg_len - NLMSG_HDRLEN -
		     NLMSG_ALIGN(sizeof(*hdr)));
	a = (void *)((char *)hdr + NLMSG_ALIGN(sizeof(*hdr)));
	for (; alen >= 4; ) {
		int l = a->len;
		int t = a->type;

		if (l < 4 || l > alen)
			break;
		const void *d = (const char *)a + 4;
		int dl = l - 4;

		switch (t) {
		case NFULA_MARK:
			if (dl >= 4) memcpy(&mark, d, 4);
			break;
		case NFULA_IFINDEX_INDEV:
			if (dl >= 4) memcpy(&ifin, d, 4);
			break;
		case NFULA_IFINDEX_OUTDEV:
			if (dl >= 4) memcpy(&ifout, d, 4);
			break;
		case NFULA_PREFIX:
			if (dl > 0) prefix = (const char *)d;
			break;
		case NFULA_UID:
			if (dl >= 4) {
				memcpy(&uid, d, 4);
				has_uid = 1;
			}
			break;
		case NFULA_PAYLOAD:
			payload = (const unsigned char *)d;
			payload_len = dl;
			break;
		default:
			break;
		}
		l = (l + 3) & ~3;
		if (l <= 0 || l > alen)
			break;
		a = (void *)((char *)a + l);
		alen -= l;
	}
	fprintf(c->f,
		"{\"stream\":\"nflog\",\"ts_ms\":%lld,\"hw_proto\":\"0x%04x\","
		"\"hook\":%u,\"mark\":%u,\"ifindex_in\":%d,\"ifindex_out\":%d",
		now_ms(), ntohs(hdr->hw_protocol), hdr->hook, mark,
		ifin, ifout);
	if (has_uid)
		fprintf(c->f, ",\"uid\":%u", uid);
	if (prefix) {
		fprintf(c->f, ",\"prefix\":");
		jstr(c->f, prefix);
	}
	if (c->payload_bytes > 0 && payload && payload_len > 0) {
		int n = payload_len < c->payload_bytes ? payload_len :
						       c->payload_bytes;

		fprintf(c->f, ",\"payload_len\":%d,\"payload\":", payload_len);
		hex_out(c->f, payload, n);
	}
	fprintf(c->f, "}\n");
	return 1;
}

/*
 * NFLOG 订阅说明：nfnetlink_log 不是组播协议——用户态需向内核发
 * CONFIG 消息（PF_BIND + BIND，nfgenmsg.res_id=日志组号）后，内核把命中
 * NFLOG 规则的包**单播**回本 portid。默认组 0；nft 规则形如
 * "nft add rule ... log group 0"。
 */
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
	attr->len = 8;	/* 4 字节 attr 头 + 1 字节命令 + 对齐 */
	attr->type = NFULA_CFG_CMD;
	attr->cmd = cmd;
	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	if (sendto(fd, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst,
		   sizeof(dst)) < 0)
		return -1;
	return 0;
}

int ai_streams_nflog(int timeout_ms, int max_events, int payload_bytes,
		     char **out)
{
	int err = 0, fd, n;
	struct nflog_ctx c;
	char *body = NULL;
	size_t blen = 0;

	fd = nl_open(NETLINK_NETFILTER, NULL, 0, &err);
	if (fd < 0) {
		return err_out(out, "ERROR: NFLOG 通道打开失败（errno=%d %s）"
			     "——需要 root/CAP_NET_ADMIN，内核需"
			     " CONFIG_NETFILTER_NETLINK_LOG=y",
			     err, strerror(err));
	}
	if (nflog_cfg_send(fd, NFULNL_CFG_CMD_PF_BIND, 0) < 0 ||
	    nflog_cfg_send(fd, NFULNL_CFG_CMD_BIND, 0) < 0) {
		close(fd);
		return err_out(out, "ERROR: NFLOG BIND 失败（errno=%d %s）",
			     errno, strerror(errno));
	}
	c.f = open_memstream(&body, &blen);
	if (!c.f) {
		close(fd);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	c.payload_bytes = payload_bytes;
	n = recv_loop_nlmsg(fd, timeout_ms, max_events, nflog_parse, &c);
	fclose(c.f);
	close(fd);
	if (n < 0) {
		free(body);
		return err_out(out, "ERROR: nflog 接收失败: %s",
			     strerror(errno));
	}
	if (n == 0) {
		fprintf(stderr, "nflog_dump: 0 events（提示：需 nftables 规则"
			"带 log group（如 \"log group 0\"）才会产生事件）\n");
	}
	*out = compose_out("nflog", timeout_ms, max_events, n, body);
	free(body);
	if (!*out) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	return AI_OK;
}

/* ---- 5) net_monitor：rtnetlink 拓扑变化 ---- */

struct rtnl_ctx {
	FILE *f;
};

static void rtnl_addr_str(char *dst, size_t cap, int family,
			  const void *raw, int len)
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

static int rtnl_parse(struct nlmsghdr *nh, void *u)
{
	struct rtnl_ctx *c = (struct rtnl_ctx *)u;
	char as[64];
	int len;

	switch (nh->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK: {
		struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
		struct rtattr *ra;
		const char *ifname = NULL;

		len = (int)(nh->nlmsg_len - NLMSG_HDRLEN - sizeof(*ifi));
		for (ra = IFLA_RTA(ifi); RTA_OK(ra, len);
		     ra = RTA_NEXT(ra, len)) {
			if (ra->rta_type == IFLA_IFNAME)
				ifname = (const char *)RTA_DATA(ra);
		}
		fprintf(c->f,
			"{\"stream\":\"net\",\"ts_ms\":%lld,\"event\":\"%s\","
			"\"ifindex\":%d,\"flags\":\"0x%x\",\"ifname\":",
			now_ms(),
			nh->nlmsg_type == RTM_NEWLINK ? "newlink" : "dellink",
			ifi->ifi_index, ifi->ifi_flags);
		jstr(c->f, ifname ? ifname : "?");
		fprintf(c->f, "}\n");
		return 1;
	}
	case RTM_NEWADDR:
	case RTM_DELADDR: {
		struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
		struct rtattr *ra;
		void *local = NULL;
		int local_len = 0;

		len = (int)(nh->nlmsg_len - NLMSG_HDRLEN - sizeof(*ifa));
		for (ra = IFA_RTA(ifa); RTA_OK(ra, len);
		     ra = RTA_NEXT(ra, len)) {
			if (ra->rta_type == IFA_LOCAL) {
				local = RTA_DATA(ra);
				local_len = (int)RTA_PAYLOAD(ra);
			}
		}
		rtnl_addr_str(as, sizeof(as), ifa->ifa_family, local,
			      local_len);
		fprintf(c->f,
			"{\"stream\":\"net\",\"ts_ms\":%lld,\"event\":\"%s\","
			"\"family\":\"%s\",\"addr\":\"%s\",\"prefixlen\":%u,"
			"\"ifindex\":%d}\n",
			now_ms(),
			nh->nlmsg_type == RTM_NEWADDR ? "newaddr" : "deladdr",
			ifa->ifa_family == AF_INET6 ? "inet6" : "inet",
			as, ifa->ifa_prefixlen, ifa->ifa_index);
		return 1;
	}
	case RTM_NEWROUTE:
	case RTM_DELROUTE: {
		struct rtmsg *r = (struct rtmsg *)NLMSG_DATA(nh);
		struct rtattr *ra;
		void *dsta = NULL, *gw = NULL;
		int dst_len = 0, gw_len = 0, oif = 0;

		len = (int)(nh->nlmsg_len - NLMSG_HDRLEN - sizeof(*r));
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
		rtnl_addr_str(as, sizeof(as), r->rtm_family, dsta, dst_len);
		fprintf(c->f,
			"{\"stream\":\"net\",\"ts_ms\":%lld,\"event\":\"%s\","
			"\"family\":\"%s\",\"dst\":\"%s/%u\",\"oif\":%d",
			now_ms(),
			nh->nlmsg_type == RTM_NEWROUTE ? "newroute" :
							 "delroute",
			r->rtm_family == AF_INET6 ? "inet6" : "inet",
			as, r->rtm_dst_len, oif);
		if (gw) {
			rtnl_addr_str(as, sizeof(as), r->rtm_family, gw,
				      gw_len);
			fprintf(c->f, ",\"gateway\":\"%s\"", as);
		}
		fprintf(c->f, "}\n");
		return 1;
	}
	default:
		return 0;
	}
}

int ai_streams_net_monitor(int timeout_ms, int max_events, char **out)
{
	int groups[5] = { RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR,
			  RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV4_ROUTE,
			  RTNLGRP_IPV6_ROUTE };
	int err = 0, fd, n;
	struct rtnl_ctx c;
	char *body = NULL;
	size_t blen = 0;

	fd = nl_open(NETLINK_ROUTE, groups, 5, &err);
	if (fd < 0) {
		return err_out(out, "ERROR: rtnetlink 组播订阅失败"
			     "（errno=%d %s）", err, strerror(err));
	}
	c.f = open_memstream(&body, &blen);
	if (!c.f) {
		close(fd);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	n = recv_loop_nlmsg(fd, timeout_ms, max_events, rtnl_parse, &c);
	fclose(c.f);
	close(fd);
	if (n < 0) {
		free(body);
		return err_out(out, "ERROR: rtnetlink 接收失败: %s",
			     strerror(errno));
	}
	*out = compose_out("net", timeout_ms, max_events, n, body);
	free(body);
	if (!*out) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	return AI_OK;
}

/* ---- 6) udev_monitor：内核设备事件（原始文本协议） ---- */

int ai_streams_udev_monitor(int timeout_ms, int max_events, char **out)
{
	int groups[1] = { 1 };	/* 组 1 = 内核原生 uevent */
	int err = 0, fd, count = 0;
	char buf[16384];
	long long deadline = now_ms() + timeout_ms;
	FILE *f;
	char *body = NULL;
	size_t blen = 0;

	fd = nl_open(NETLINK_KOBJECT_UEVENT, groups, 1, &err);
	if (fd < 0) {
		return err_out(out, "ERROR: uevent 订阅失败（errno=%d %s）",
			     err, strerror(err));
	}
	f = open_memstream(&body, &blen);
	if (!f) {
		close(fd);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	while (count < max_events) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		long long remain = deadline - now_ms();
		ssize_t n;
		char *p, *end;
		char action[16] = "?", devpath[512] = "?";
		int kv = 0;

		if (remain <= 0)
			break;
		if (poll(&pfd, 1, (int)remain) <= 0)
			continue;
		if (!(pfd.revents & POLLIN))
			continue;
		n = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
		if (n <= 0)
			continue;
		buf[n] = '\0';
		end = buf + n;
		fprintf(f, "{\"stream\":\"uevent\",\"ts_ms\":%lld",
			now_ms());
		/* 首段 "verb@devpath"，其后 KEY=VAL\0 序列 */
		p = buf;
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
				snprintf(devpath, sizeof(devpath), "%.511s",
					 at + 1);
				fprintf(f, ",\"action\":");
				jstr(f, action);
				fprintf(f, ",\"devpath\":");
				jstr(f, devpath);
			} else if (kv < 10) {
				char *eq = strchr(p, '=');

				if (eq) {
					*eq = '\0';
					fprintf(f, ",");
					jstr(f, p);
					fprintf(f, ":");
					jstr(f, eq + 1);
					kv++;
				}
			}
			p = nul + 1;
		}
		fprintf(f, "}\n");
		count++;
	}
	fclose(f);
	close(fd);
	*out = compose_out("uevent", timeout_ms, max_events, count, body);
	free(body);
	if (!*out) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	return AI_OK;
}
