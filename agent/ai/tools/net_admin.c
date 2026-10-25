/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net_admin.c - W78 P2 网络执行面实现（7 件，TOOL_CH_NETADMIN，全 W2）
 *
 * 设计纪律（与 macro_tools.c / ai_streams.c 同款）：
 *  - rtnetlink 写三族：链路（up/down/del）、地址（add/del）、路由（add/del），
 *    全部走原生 NETLINK_ROUTE 套接字（不 shell 出 ip 命令）；
 *  - 诚实第一：每次写前先 RTM_GET* 读旧值落进输出（回滚凭据），
 *    写后回读验证，失败如实报内核 errno；
 *  - nft_txn：ops 逐条内容校验（禁分号/换行/反引号/$(）后写 0600 临时
 *    文件，先 `nft -c -f` 全量语法预检（不生效），dry_run 到此为止；
 *    正式应用 `nft -f` 后 `nft list ruleset` 抽查关键串验证落位；
 *  - run-time 参数校验：iface 字符集白名单 [A-Za-z0-9._-]{1,15}，
 *    addr/dst/gateway 用 inet_pton 双栈真校验（不做字符串粗校验）；
 *  - 风险：全 W2，executor 通用 lease D0-D4 闸门逐次确认，绝无旁路。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tool_registry.h"
#include "netlink/ai_streams.h"	/* JSON 转义复用（不修改该文件） */
#include "net_admin.h"

#define NA_MAX_IFACE	15
#define NA_MAX_OPS	32
#define NA_MAX_OP_LEN	512
#define NA_NFT		"/usr/sbin/nft"

/* ---- 小工具：JSON 取参（扁平键，macro_tools 同款纪律） ---- */

static int jstr_get(const char *json, const char *key, char *out, size_t cap)
{
	char pat[64];
	const char *p, *q;
	size_t n;

	snprintf(pat, sizeof(pat), "\"%s\":\"", key);
	p = strstr(json, pat);
	if (!p)
		return -1;
	p += strlen(pat);
	q = strchr(p, '"');
	if (!q)
		return -1;
	n = (size_t)(q - p);
	if (n >= cap)
		n = cap - 1;
	memcpy(out, p, n);
	out[n] = '\0';
	return 0;
}

static int jbool(const char *json, const char *key, int dflt)
{
	char pat[64];
	const char *p;

	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(json, pat);
	if (!p)
		return dflt;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t')
		p++;
	if (strncmp(p, "true", 4) == 0)
		return 1;
	if (strncmp(p, "false", 5) == 0)
		return 0;
	return dflt;
}

/* 解析 "ops":["..",".."] 字符串数组（支持基本 JSON 转义 \\ \" \/ \n \t \r；
 * \uXXXX 与其他转义拒绝）。返回条数（0=空数组）；格式错/超限返回 -1 */
static int jstr_array_get(const char *json, const char *key,
			  char ops[][NA_MAX_OP_LEN], int max_ops)
{
	char pat[64];
	const char *p;
	int n = 0;

	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(json, pat);
	if (!p)
		return -1;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	if (*p != '[')
		return -1;
	p++;
	for (;;) {
		char *o;

		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ',')
			p++;
		if (*p == ']')
			return n;
		if (*p != '"')
			return -1;
		if (n >= max_ops)
			return -1;
		p++;
		o = ops[n];
		{
			size_t used = 0;

			while (*p && *p != '"') {
				char c = *p;

				if (c == '\\') {
					p++;
					switch (*p) {
					case '"': c = '"'; break;
					case '\\': c = '\\'; break;
					case '/': c = '/'; break;
					case 'n': c = '\n'; break;
					case 't': c = '\t'; break;
					case 'r': c = '\r'; break;
					default:
						return -1;
					}
				}
				if (used + 1 >= NA_MAX_OP_LEN)
					return -1;
				o[used++] = c;
				p++;
			}
			if (*p != '"')
				return -1;
			o[used] = '\0';
		}
		p++;
		n++;
	}
}

/* 有界 fork/execv：合并 stdout+stderr；超时 SIGKILL（macro_tools 同款）。
 * 返回：>=0 退出码；-99 超时；-1 启动/内部失败 */
static int run_argv(char *const argv[], int timeout_s, char *out, size_t cap)
{
	int pfd[2];
	pid_t pid;
	size_t used = 0;
	long deadline_ms = (long)timeout_s * 1000;
	long spent = 0;
	int status;

	if (pipe(pfd) < 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}
	if (pid == 0) {
		close(pfd[0]);
		dup2(pfd[1], 1);
		dup2(pfd[1], 2);
		close(pfd[1]);
		execv(argv[0], (char *const *)argv);
		_exit(127);
	}
	close(pfd[1]);
	while (spent < deadline_ms) {
		struct pollfd p = { .fd = pfd[0], .events = POLLIN };
		int r = poll(&p, 1, 200);

		if (r > 0 && (p.revents & (POLLIN | POLLHUP))) {
			ssize_t n;

			if (used + 1 >= cap)
				break;
			n = read(pfd[0], out + used, cap - used - 1);
			if (n <= 0) {
				/* EOF：子进程已关输出端——阻塞收尸拿真实
				 * 退出码（nft -c 成功时零输出直接退出，
				 * 不得误报超时 -99；W78E 冒烟实测教训） */
				while (waitpid(pid, &status, 0) < 0 &&
				       errno == EINTR)
					;
				close(pfd[0]);
				out[used] = '\0';
				return WIFEXITED(status) ?
					WEXITSTATUS(status) : -1;
			}
			used += (size_t)n;
		} else if (r < 0 && errno != EINTR) {
			break;
		}
		spent += 200;
		if (waitpid(pid, &status, WNOHANG) == pid) {
			ssize_t n;

			while (used + 1 < cap &&
			       (n = read(pfd[0], out + used,
					 cap - used - 1)) > 0)
				used += (size_t)n;
			close(pfd[0]);
			out[used] = '\0';
			return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		}
	}
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	{
		ssize_t n;

		while (used + 1 < cap &&
		       (n = read(pfd[0], out + used, cap - used - 1)) > 0)
			used += (size_t)n;
	}
	close(pfd[0]);
	out[used] = '\0';
	return -99;
}

/* ---- 纯函数校验 ---- */

int ai_net_admin_valid_iface(const char *s)
{
	size_t n = 0;

	if (!s || !*s)
		return 0;
	for (; s[n]; n++) {
		char c = s[n];

		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == '-'))
			return 0;
	}
	return n <= NA_MAX_IFACE ? 1 : 0;
}

int ai_net_admin_valid_nft_op(const char *op)
{
	size_t i, n;

	if (!op || !*op)
		return 0;
	n = strlen(op);
	if (n > NA_MAX_OP_LEN)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)op[i];

		if (c == ';' || c == '\n' || c == '\r' || c == '`')
			return 0;
		if (c == '$' && i + 1 < n && op[i + 1] == '(')
			return 0;
		if (c < 0x20 || c == 0x7f)	/* 其余控制字符一律拒绝 */
			return 0;
	}
	return 1;
}

int ai_net_admin_parse_cidr(const char *s, int *family, void *addr,
			    int *plen)
{
	char buf[64];
	char *slash, *q;
	size_t n;
	long p;

	if (!s || !family || !addr || !plen)
		return -1;
	n = strlen(s);
	if (n == 0 || n >= sizeof(buf))
		return -1;
	memcpy(buf, s, n + 1);
	slash = strchr(buf, '/');
	if (!slash || slash == buf || !slash[1])
		return -1;
	*slash = '\0';
	for (q = slash + 1; *q; q++)
		if (*q < '0' || *q > '9')
			return -1;
	p = strtol(slash + 1, NULL, 10);
	if (inet_pton(AF_INET, buf, addr) == 1) {
		*family = AF_INET;
		if (p < 0 || p > 32)
			return -1;
	} else if (inet_pton(AF_INET6, buf, addr) == 1) {
		*family = AF_INET6;
		if (p < 0 || p > 128)
			return -1;
	} else {
		return -1;
	}
	*plen = (int)p;
	return 0;
}

int ai_net_admin_parse_ip(const char *s, int *family, void *addr)
{
	char buf[64];
	size_t n;

	if (!s || !family || !addr)
		return -1;
	n = strlen(s);
	if (n == 0 || n >= sizeof(buf) || strchr(s, '/'))
		return -1;
	memcpy(buf, s, n + 1);
	if (inet_pton(AF_INET, buf, addr) == 1) {
		*family = AF_INET;
		return 0;
	}
	if (inet_pton(AF_INET6, buf, addr) == 1) {
		*family = AF_INET6;
		return 0;
	}
	return -1;
}

int ai_net_admin_table_id(const char *name, int *id)
{
	long v;
	char *end;

	if (!name || !id || !*name)
		return -1;
	if (strcmp(name, "main") == 0) {
		*id = RT_TABLE_MAIN;
		return 0;
	}
	if (strcmp(name, "local") == 0) {
		*id = RT_TABLE_LOCAL;
		return 0;
	}
	if (strcmp(name, "default") == 0) {
		*id = RT_TABLE_DEFAULT;
		return 0;
	}
	v = strtol(name, &end, 10);
	if (end == name || *end || v < 0 || v > 0x7fffffffL)
		return -1;
	*id = (int)v;
	return 0;
}

/* ---- rtnetlink 底座 ---- */

struct na_sock {
	int fd;
	unsigned seq;
};

static int na_open(struct na_sock *sk)
{
	struct sockaddr_nl sa;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sk->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sk->fd < 0)
		return -1;
	if (bind(sk->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sk->fd);
		sk->fd = -1;
		return -1;
	}
	sk->seq = (unsigned)getpid() & 0xffff;
	return 0;
}

static void na_close(struct na_sock *sk)
{
	if (sk->fd >= 0)
		close(sk->fd);
	sk->fd = -1;
}

static int na_send(struct na_sock *sk, const void *buf, size_t len)
{
	struct sockaddr_nl kernel;
	struct iovec iov;
	struct msghdr mh;

	memset(&kernel, 0, sizeof(kernel));
	kernel.nl_family = AF_NETLINK;
	iov.iov_base = (void *)buf;
	iov.iov_len = len;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name = &kernel;
	mh.msg_namelen = sizeof(kernel);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	return sendmsg(sk->fd, &mh, 0) < 0 ? -1 : 0;
}

/* 有界等待可读（总预算 budget_ms） */
static int na_wait(int fd, int *spent, int budget_ms)
{
	while (*spent < budget_ms) {
		struct pollfd p = { .fd = fd, .events = POLLIN };
		int r = poll(&p, 1, 100);

		if (r > 0 && (p.revents & (POLLIN | POLLHUP)))
			return 1;
		if (r < 0 && errno != EINTR)
			return 0;
		*spent += 100;
	}
	return 0;
}

static const char *na_err(int rc)
{
	return rc > 0 ? strerror(rc) : "本地错误（发送/接收/超时）";
}

/* 发写请求并等待 ACK（NLM_F_ACK）。
 * 返回 0=ACK；-1=本地错误；正数=内核 errno */
static int na_talk_ack(struct na_sock *sk, void *buf, size_t len)
{
	char rbuf[8192];
	int spent = 0;
	ssize_t r;

	if (na_send(sk, buf, len) < 0)
		return -1;
	for (;;) {
		int mlen;
		struct nlmsghdr *nh;

		if (!na_wait(sk->fd, &spent, 3000))
			return -1;
		r = recv(sk->fd, rbuf, sizeof(rbuf), 0);
		if (r <= 0)
			return -1;
		mlen = (int)r;
		for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, mlen);
		     nh = NLMSG_NEXT(nh, mlen)) {
			if (nh->nlmsg_seq != sk->seq)
				continue;
			if (nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(nh);

				return e->error == 0 ? 0 : -e->error;
			}
			/* 其他伴随消息继续等 ACK */
		}
	}
}

typedef int (*na_msg_fn)(const struct nlmsghdr *n, void *arg);

/* 发 dump 请求（NLM_F_ROOT|NLM_F_MATCH）并逐条回调直到 NLMSG_DONE。
 * 返回 0 成功；-1 本地错误；正数=NLMSG_DONE 携带的 errno */
static int na_dump(struct na_sock *sk, void *req, size_t reqlen,
		   na_msg_fn cb, void *arg)
{
	char rbuf[16384];
	struct nlmsghdr *reqh = req;
	int spent = 0;
	int rc = 0;

	reqh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
	reqh->nlmsg_seq = ++sk->seq;
	if (na_send(sk, req, reqlen) < 0)
		return -1;
	for (;;) {
		ssize_t r;
		int mlen;
		struct nlmsghdr *nh;

		if (!na_wait(sk->fd, &spent, 3000))
			return -1;
		r = recv(sk->fd, rbuf, sizeof(rbuf), 0);
		if (r <= 0)
			return -1;
		mlen = (int)r;
		for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, mlen);
		     nh = NLMSG_NEXT(nh, mlen)) {
			if (nh->nlmsg_seq != sk->seq)
				continue;
			if (nh->nlmsg_type == NLMSG_DONE) {
				unsigned *e = NLMSG_DATA(nh);

				return *e ? (int)*e : rc;
			}
			if (nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(nh);

				return -e->error;
			}
			if (cb)
				if (cb(nh, arg) != 0)
					rc = -1;
		}
	}
}

/* RTM_GETLINK 按名精确查询（NLM_F_REQUEST 单播）。
 * 返回 0=找到（idx、flags、kind 出参填充，kind 可传 NULL）；
 * -1=本地错；正数=内核 errno（ENODEV=不存在） */
static int na_getlink_byname(struct na_sock *sk, const char *ifname,
			     int *idx, unsigned *flags, char *kind,
			     size_t kind_cap)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char attr[64];
	} req;
	struct rtattr *rta;
	size_t nlen = strlen(ifname);
	char rbuf[16384];
	int spent = 0;
	ssize_t r;

	if (nlen > NA_MAX_IFACE)
		return -1;
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_type = RTM_GETLINK;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_seq = ++sk->seq;
	req.ifi.ifi_family = AF_UNSPEC;
	rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
	rta->rta_type = IFLA_IFNAME;
	rta->rta_len = (unsigned short)RTA_LENGTH(nlen);
	memcpy(RTA_DATA(rta), ifname, nlen);
	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) +
			 (unsigned)RTA_LENGTH(nlen);
	if (kind && kind_cap)
		kind[0] = '\0';
	if (na_send(sk, &req, req.n.nlmsg_len) < 0)
		return -1;
	for (;;) {
		int mlen;
		struct nlmsghdr *nh;

		if (!na_wait(sk->fd, &spent, 3000))
			return -1;
		r = recv(sk->fd, rbuf, sizeof(rbuf), 0);
		if (r <= 0)
			return -1;
		mlen = (int)r;
		for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, mlen);
		     nh = NLMSG_NEXT(nh, mlen)) {
			if (nh->nlmsg_seq != sk->seq)
				continue;
			if (nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(nh);

				return -e->error;
			}
			if (nh->nlmsg_type == RTM_NEWLINK) {
				struct ifinfomsg *ifi = NLMSG_DATA(nh);
				int alen = nh->nlmsg_len -
					   NLMSG_LENGTH(sizeof(*ifi));
				struct rtattr *a;

				*idx = ifi->ifi_index;
				*flags = ifi->ifi_flags;
				for (a = IFLA_RTA(ifi); RTA_OK(a, alen);
				     a = RTA_NEXT(a, alen)) {
					if (a->rta_type != IFLA_LINKINFO ||
					    !kind || !kind_cap)
						continue;
					{
						int slen = RTA_PAYLOAD(a);
						struct rtattr *sa;

						for (sa = RTA_DATA(a);
						     RTA_OK(sa, slen);
						     sa = RTA_NEXT(sa, slen)) {
							if (sa->rta_type ==
							    IFLA_INFO_KIND) {
								size_t cp =
									RTA_PAYLOAD(sa);

								if (cp >= kind_cap)
									cp = kind_cap - 1;
								memcpy(kind,
								       RTA_DATA(sa),
								       cp);
								kind[cp] = '\0';
							}
						}
					}
				}
				return 0;
			}
		}
	}
}

/* ifindex→名字缓存（路由行回显用） */
struct na_link_cache {
	int count;
	int idx[64];
	char name[64][NA_MAX_IFACE + 1];
};

static int na_link_cb(const struct nlmsghdr *n, void *arg)
{
	struct na_link_cache *lc = arg;
	struct ifinfomsg *ifi;
	int alen;
	struct rtattr *a;

	if (n->nlmsg_type != RTM_NEWLINK || lc->count >= 64)
		return 0;
	ifi = NLMSG_DATA(n);
	alen = n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	lc->idx[lc->count] = ifi->ifi_index;
	lc->name[lc->count][0] = '\0';
	for (a = IFLA_RTA(ifi); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
		if (a->rta_type == IFLA_IFNAME) {
			size_t cp = RTA_PAYLOAD(a);

			if (cp > NA_MAX_IFACE)
				cp = NA_MAX_IFACE;
			memcpy(lc->name[lc->count], RTA_DATA(a), cp);
			lc->name[lc->count][cp] = '\0';
			break;
		}
	}
	lc->count++;
	return 0;
}

static int na_link_cache_fill(struct na_sock *sk, struct na_link_cache *lc)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
	} req;

	memset(&req, 0, sizeof(req));
	memset(lc, 0, sizeof(*lc));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_type = RTM_GETLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	return na_dump(sk, &req, req.n.nlmsg_len, na_link_cb, lc);
}

static const char *na_link_name(const struct na_link_cache *lc, int idx)
{
	int i;

	if (!lc)
		return "-";
	for (i = 0; i < lc->count; i++)
		if (lc->idx[i] == idx && lc->name[i][0])
			return lc->name[i];
	return "-";
}

/* ---- 地址 dump（写前凭据 + 写后回读共用） ---- */

struct na_addr_ctx {
	FILE *f;
	unsigned ifindex;		/* 过滤：仅该接口 */
	int want;			/* 1=回读匹配目标地址 */
	int want_family;
	int want_plen;
	unsigned char want_addr[16];
	int found;			/* 目标地址在位 */
	int count;			/* 该接口地址总数 */
	int shown;			/* 已打印行数 */
};

static int na_addr_cb(const struct nlmsghdr *n, void *arg)
{
	struct na_addr_ctx *c = arg;
	struct ifaddrmsg *ifa = NLMSG_DATA(n);
	int alen = n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
	unsigned char local_raw[16], addr_raw[16];
	int have_local = 0, have_addr = 0;
	size_t blen;
	struct rtattr *a;
	char disp[INET6_ADDRSTRLEN];
	const unsigned char *show = NULL;
	int shown_ok = 0;

	if (n->nlmsg_type != RTM_NEWADDR || ifa->ifa_index != c->ifindex)
		return 0;
	blen = ifa->ifa_family == AF_INET ? 4 : 16;
	/* 一次遍历收齐两属性：v4 无 peer 时内核只发 IFA_LOCAL（本地）；
	 * v6 相反只发 IFA_ADDRESS（本地）。不得复用已耗尽的 alen 二次
	 * 遍历（W78E 冒烟实测教训）。 */
	for (a = IFA_RTA(ifa); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
		if (a->rta_type == IFA_LOCAL && !have_local) {
			memcpy(local_raw, RTA_DATA(a),
			       RTA_PAYLOAD(a) > 16 ? 16 : RTA_PAYLOAD(a));
			have_local = 1;
		} else if (a->rta_type == IFA_ADDRESS && !have_addr) {
			memcpy(addr_raw, RTA_DATA(a),
			       RTA_PAYLOAD(a) > 16 ? 16 : RTA_PAYLOAD(a));
			have_addr = 1;
		}
	}
	if (have_local)
		show = local_raw;
	else if (have_addr)
		show = addr_raw;
	if (show)
		shown_ok = inet_ntop(ifa->ifa_family, show, disp,
				     sizeof(disp)) != NULL;
	c->count++;
	if (c->shown < 16) {
		fprintf(c->f, "  %s %s/%d\n",
			ifa->ifa_family == AF_INET ? "inet" : "inet6",
			shown_ok ? disp : "?", ifa->ifa_prefixlen);
		c->shown++;
		if (c->shown == 16)
			fprintf(c->f, "  …（仅显示前 16 条）\n");
	}
	if (c->want && ifa->ifa_family == c->want_family &&
	    ifa->ifa_prefixlen == c->want_plen &&
	    ((have_local &&
	      memcmp(local_raw, c->want_addr, blen) == 0) ||
	     (have_addr &&
	      memcmp(addr_raw, c->want_addr, blen) == 0)))
		c->found = 1;
	return 0;
}

static int na_addr_dump(struct na_sock *sk, struct na_addr_ctx *c)
{
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_type = RTM_GETADDR;
	req.ifa.ifa_family = AF_UNSPEC;
	return na_dump(sk, &req, req.n.nlmsg_len, na_addr_cb, c);
}

/* ---- 路由 dump ---- */

struct na_route_ctx {
	FILE *f;
	int family;			/* 过滤：协议栈 */
	int table;			/* 过滤：路由表（-1 不过滤） */
	const struct na_link_cache *lc;
	int want;			/* 1=回读匹配目标路由 */
	int want_plen;
	unsigned char want_dst[16];
	int found;
	int count;
	int shown;
};

static int na_route_cb(const struct nlmsghdr *n, void *arg)
{
	struct na_route_ctx *c = arg;
	struct rtmsg *rtm = NLMSG_DATA(n);
	int alen = n->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
	char dst[INET6_ADDRSTRLEN] = "";
	char gw[INET6_ADDRSTRLEN] = "";
	unsigned char dstraw[16];
	int have_dst = 0, have_gw = 0, oif = 0, table;
	struct rtattr *a;

	if (rtm->rtm_family != c->family)
		return 0;
	table = rtm->rtm_table;
	for (a = RTM_RTA(rtm); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
		switch (a->rta_type) {
		case RTA_DST:
			memcpy(dstraw, RTA_DATA(a),
			       RTA_PAYLOAD(a) > 16 ? 16 : RTA_PAYLOAD(a));
			have_dst = 1;
			inet_ntop(c->family, RTA_DATA(a), dst, sizeof(dst));
			break;
		case RTA_GATEWAY:
			have_gw = 1;
			inet_ntop(c->family, RTA_DATA(a), gw, sizeof(gw));
			break;
		case RTA_OIF:
			memcpy(&oif, RTA_DATA(a), sizeof(oif));
			break;
		case RTA_TABLE:
			memcpy(&table, RTA_DATA(a), sizeof(table));
			break;
		default:
			break;
		}
	}
	if (c->table >= 0 && table != c->table)
		return 0;
	c->count++;
	if (c->shown < 24) {
		fprintf(c->f, "  %s/%d via %s dev %s table %d%s\n",
			have_dst ? dst :
			(c->family == AF_INET ? "0.0.0.0" : "::"),
			rtm->rtm_dst_len, have_gw ? gw : "-",
			na_link_name(c->lc, oif), table,
			rtm->rtm_protocol == RTPROT_KERNEL ? "  [kernel]" : "");
		c->shown++;
		if (c->shown == 24)
			fprintf(c->f, "  …（仅显示前 24 条）\n");
	}
	if (c->want && table == c->table &&
	    rtm->rtm_dst_len == c->want_plen &&
	    ((c->want_plen == 0 && !have_dst) ||
	     (have_dst && memcmp(dstraw, c->want_dst,
				 c->family == AF_INET ? 4 : 16) == 0)))
		c->found = 1;
	return 0;
}

static int na_route_dump(struct na_sock *sk, struct na_route_ctx *c)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = (unsigned char)c->family;
	return na_dump(sk, &req, req.n.nlmsg_len, na_route_cb, c);
}

/* ---- 1) net_iface：链路 up/down ---- */

static int na_iface(const char *args, char **out)
{
	char iface[32], state[16];
	struct na_sock sk;
	FILE *f;
	int idx = 0, rc;
	unsigned oflags = 0, nflags = 0;
	char kind[32] = "";
	int want_up, ok = -1;

	if (jstr_get(args, "iface", iface, sizeof(iface)) < 0 ||
	    !ai_net_admin_valid_iface(iface)) {
		*out = strdup("ERROR: 需要 iface（[A-Za-z0-9._-]{1,15}）");
		return -1;
	}
	if (jstr_get(args, "state", state, sizeof(state)) < 0 ||
	    (strcmp(state, "up") != 0 && strcmp(state, "down") != 0)) {
		*out = strdup("ERROR: 需要 state=up|down");
		return -1;
	}
	want_up = strcmp(state, "up") == 0;
	if (na_open(&sk) < 0) {
		if (asprintf(out, "ERROR: rtnetlink 套接字打开失败: %s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	f = open_memstream(out, &(size_t){0});
	if (!f) {
		na_close(&sk);
		*out = strdup("ERROR: 内存不足");
		return -1;
	}

	rc = na_getlink_byname(&sk, iface, &idx, &oflags, kind, sizeof(kind));
	if (rc != 0) {
		fprintf(f, "ERROR: RTM_GETLINK 读旧值失败（%s）: %s\n",
			na_err(rc),
			rc == ENODEV ? "接口不存在" : iface);
		goto done;
	}
	fprintf(f, "写前旧状态（回滚凭据）: iface=%s ifindex=%d flags=0x%x "
	       "UP=%d RUNNING=%d LOWER_UP=%d%s%s\n",
	       iface, idx, oflags, !!(oflags & IFF_UP),
	       !!(oflags & IFF_RUNNING), !!(oflags & IFF_LOWER_UP),
	       kind[0] ? " kind=" : "", kind);

	{
		struct {
			struct nlmsghdr n;
			struct ifinfomsg ifi;
		} req;

		memset(&req, 0, sizeof(req));
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
		req.n.nlmsg_type = RTM_NEWLINK;
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		req.n.nlmsg_seq = ++sk.seq;
		req.ifi.ifi_family = AF_UNSPEC;
		req.ifi.ifi_index = idx;
		req.ifi.ifi_change = IFF_UP;
		req.ifi.ifi_flags = want_up ? IFF_UP : 0;
		rc = na_talk_ack(&sk, &req, req.n.nlmsg_len);
		if (rc != 0) {
			fprintf(f, "ERROR: RTM_NEWLINK 置 %s 失败（%s）"
				"——未生效；常见原因：无 root/CAP_NET_ADMIN、"
				"接口不支持该操作\n",
				state, na_err(rc));
			goto done;
		}
	}
	fprintf(f, "写 RTM_NEWLINK: %s IFF_UP=%d 已 ACK\n", iface,
		want_up ? 1 : 0);

	rc = na_getlink_byname(&sk, iface, &idx, &nflags, NULL, 0);
	if (rc == 0 && !!(nflags & IFF_UP) == want_up) {
		fprintf(f, "写后回读: flags=0x%x UP=%d —— 验证通过\n",
			nflags, !!(nflags & IFF_UP));
		ok = 0;
	} else {
		fprintf(f, "ERROR: 写后回读验证失败（%s，UP=%d != %d）——"
			"如实报告，请人工复核\n",
			rc != 0 ? na_err(rc) : "flags 未达预期",
			rc == 0 ? !!(nflags & IFF_UP) : -1, want_up ? 1 : 0);
		ok = -1;
	}
	fprintf(f, "回滚提示：state 反向再调一次即回滚（%s → %s）。\n",
		state, want_up ? "down" : "up");
	rc = 0;

done:
	fclose(f);
	na_close(&sk);
	return ok;
}

/* ---- 2/3) net_addr_add / net_addr_del ---- */

static int na_addr(const char *args, char **out, int add)
{
	char iface[32], addrs[64];
	int family = AF_UNSPEC, plen = 0, idx = 0, rc, rdc;
	unsigned char a[16];
	struct na_sock sk;
	FILE *f;
	struct na_addr_ctx pre, post;
	unsigned flags = 0;

	if (jstr_get(args, "iface", iface, sizeof(iface)) < 0 ||
	    !ai_net_admin_valid_iface(iface)) {
		*out = strdup("ERROR: 需要 iface（[A-Za-z0-9._-]{1,15}）");
		return -1;
	}
	if (jstr_get(args, "addr", addrs, sizeof(addrs)) < 0 ||
	    ai_net_admin_parse_cidr(addrs, &family, a, &plen) != 0) {
		*out = strdup("ERROR: 需要 addr（CIDR，如 192.168.5.9/24 或 "
			      "fd00::9/64；inet_pton 双栈校验未通过）");
		return -1;
	}
	if (na_open(&sk) < 0) {
		if (asprintf(out, "ERROR: rtnetlink 套接字打开失败: %s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	f = open_memstream(out, &(size_t){0});
	if (!f) {
		na_close(&sk);
		*out = strdup("ERROR: 内存不足");
		return -1;
	}

	rc = na_getlink_byname(&sk, iface, &idx, &flags, NULL, 0);
	if (rc != 0) {
		fprintf(f, "ERROR: 接口查询失败（%s）: %s%s\n", na_err(rc),
			iface, rc == ENODEV ? "（接口不存在）" : "");
		rc = -1;
		goto done;
	}

	/* 写前 dump 该接口现地址（回滚凭据） */
	memset(&pre, 0, sizeof(pre));
	pre.f = f;
	pre.ifindex = idx;
	fprintf(f, "写前 %s 现地址（回滚凭据）:\n", iface);
	rdc = na_addr_dump(&sk, &pre);
	if (rdc != 0)
		fprintf(f, "  （dump 失败：%s）\n", na_err(rdc));
	else if (pre.count == 0)
		fprintf(f, "  （无地址）\n");

	{
		struct {
			struct nlmsghdr n;
			struct ifaddrmsg ifa;
			char attr[128];
		} req;
		size_t alen = family == AF_INET ? 4 : 16;

		memset(&req, 0, sizeof(req));
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
		req.n.nlmsg_type = add ? RTM_NEWADDR : RTM_DELADDR;
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
				    (add ? (NLM_F_CREATE | NLM_F_EXCL) : 0);
		req.n.nlmsg_seq = ++sk.seq;
		req.ifa.ifa_family = (unsigned char)family;
		req.ifa.ifa_prefixlen = (unsigned char)plen;
		req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
		req.ifa.ifa_index = idx;
		{
			struct rtattr *rta = (struct rtattr *)
				((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));

			rta->rta_type = IFA_LOCAL;
			rta->rta_len = (unsigned short)RTA_LENGTH(alen);
			memcpy(RTA_DATA(rta), a, alen);
			req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) +
					 (unsigned)RTA_LENGTH(alen);
		}
		rc = na_talk_ack(&sk, &req, req.n.nlmsg_len);
		if (rc != 0) {
			fprintf(f, "ERROR: RTM_%sADDR 失败（%s）——未生效",
				add ? "NEW" : "DEL", na_err(rc));
			if (add && rc == EEXIST)
				fprintf(f, "（地址已存在，EXCL 保护未重复添加）");
			if (!add && rc == EADDRNOTAVAIL)
				fprintf(f, "（地址本就不存在，无可删除）");
			fprintf(f, "\n");
			rc = -1;
			goto done;
		}
	}
	fprintf(f, "写 RTM_%sADDR: %s %s 已 ACK\n",
		add ? "NEW" : "DEL", iface, addrs);

	/* 写后回读验证 */
	memset(&post, 0, sizeof(post));
	post.f = f;
	post.ifindex = idx;
	post.want = 1;
	post.want_family = family;
	post.want_plen = plen;
	memcpy(post.want_addr, a, sizeof(a));
	fprintf(f, "写后回读:\n");
	post.shown = 16;	/* 回读段不重复罗列全部地址 */
	rdc = na_addr_dump(&sk, &post);
	if (rdc != 0) {
		fprintf(f, "ERROR: 写后回读 dump 失败（%s）\n", na_err(rdc));
		goto done;
	}
	if (post.found == add) {
		fprintf(f, "  目标 %s %s —— 验证%s\n",
			add ? "已在位" : "已移除", addrs,
			add ? "通过" : "通过");
	} else {
		fprintf(f, "  目标 %s %s —— 验证失败（如实报告，请人工复核）\n",
			add ? "未在位" : "仍存在", addrs);
	}
	fprintf(f, "回滚提示：%s 同参数（iface+addr）再调一次即回滚/恢复。\n",
		add ? "net_addr_del" : "net_addr_add");
	rc = post.found == add ? 0 : -1;

done:
	fclose(f);
	na_close(&sk);
	return rc;
}

/* ---- 4/5) net_route_add / net_route_del ---- */

static int na_route(const char *args, char **out, int add)
{
	char dsts[64], gws[64], ifaces[32], tables[24];
	int family = AF_UNSPEC, plen = 0, gwfam = AF_UNSPEC;
	int idx = 0, table = RT_TABLE_MAIN, rc, rdc, ok = -1;
	int have_gw = 0, have_oif = 0;
	unsigned char d[16], g[16];
	struct na_sock sk;
	FILE *f;
	struct na_link_cache lc;
	struct na_route_ctx pre, post;
	unsigned flags = 0;

	if (jstr_get(args, "dst", dsts, sizeof(dsts)) < 0 ||
	    ai_net_admin_parse_cidr(dsts, &family, d, &plen) != 0) {
		*out = strdup("ERROR: 需要 dst（CIDR，如 192.168.99.0/24、"
			      "fd00::/64；默认路由 0.0.0.0/0）");
		return -1;
	}
	have_gw = jstr_get(args, "gateway", gws, sizeof(gws)) == 0;
	if (have_gw && ai_net_admin_parse_ip(gws, &gwfam, g) != 0) {
		*out = strdup("ERROR: gateway 非法（裸地址，如 192.168.1.1；"
			      "不带前缀）");
		return -1;
	}
	if (have_gw && gwfam != family) {
		*out = strdup("ERROR: gateway 与 dst 协议栈不一致"
			      "（v4/v6 必须同栈）");
		return -1;
	}
	have_oif = jstr_get(args, "iface", ifaces, sizeof(ifaces)) == 0;
	if (have_oif && !ai_net_admin_valid_iface(ifaces)) {
		*out = strdup("ERROR: iface 非法（[A-Za-z0-9._-]{1,15}）");
		return -1;
	}
	if (jstr_get(args, "table", tables, sizeof(tables)) == 0) {
		if (ai_net_admin_table_id(tables, &table) != 0) {
			*out = strdup("ERROR: table 非法（main/local/default"
				      " 或数字）");
			return -1;
		}
	}
	if (na_open(&sk) < 0) {
		if (asprintf(out, "ERROR: rtnetlink 套接字打开失败: %s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	f = open_memstream(out, &(size_t){0});
	if (!f) {
		na_close(&sk);
		*out = strdup("ERROR: 内存不足");
		return -1;
	}

	if (na_link_cache_fill(&sk, &lc) != 0)
		memset(&lc, 0, sizeof(lc));	/* 名字解析失败只影响回显 */
	if (have_oif) {
		rc = na_getlink_byname(&sk, ifaces, &idx, &flags, NULL, 0);
		if (rc != 0) {
			fprintf(f, "ERROR: 出接口查询失败（%s）: %s%s\n",
				na_err(rc), ifaces,
				rc == ENODEV ? "（接口不存在）" : "");
			goto done;
		}
	}

	/* 写前 dump 目标路由表相关路由（回滚凭据） */
	memset(&pre, 0, sizeof(pre));
	pre.f = f;
	pre.family = family;
	pre.table = table;
	pre.lc = &lc;
	fprintf(f, "写前 table %d（%s 栈）相关路由（回滚凭据）:\n",
		table, family == AF_INET ? "v4" : "v6");
	rdc = na_route_dump(&sk, &pre);
	if (rdc != 0)
		fprintf(f, "  （dump 失败：%s）\n", na_err(rdc));
	else if (pre.count == 0)
		fprintf(f, "  （该表此栈无路由）\n");

	{
		struct {
			struct nlmsghdr n;
			struct rtmsg r;
			char attr[256];
		} req;
		size_t alen = family == AF_INET ? 4 : 16;
		unsigned tail;

		memset(&req, 0, sizeof(req));
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
		req.n.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
				    (add ? (NLM_F_CREATE | NLM_F_EXCL) : 0);
		req.n.nlmsg_seq = ++sk.seq;
		req.r.rtm_family = (unsigned char)family;
		req.r.rtm_dst_len = (unsigned char)plen;
		req.r.rtm_table = (unsigned char)table;
		req.r.rtm_protocol = RTPROT_STATIC;
		req.r.rtm_scope = RT_SCOPE_UNIVERSE;
		req.r.rtm_type = RTN_UNICAST;
		tail = NLMSG_ALIGN(req.n.nlmsg_len);
		if (plen > 0) {
			struct rtattr *rta = (struct rtattr *)
				((char *)&req + tail);

			rta->rta_type = RTA_DST;
			rta->rta_len = (unsigned short)RTA_LENGTH(alen);
			memcpy(RTA_DATA(rta), d, alen);
			tail += (unsigned)RTA_LENGTH(alen);
		}
		if (have_gw) {
			struct rtattr *rta = (struct rtattr *)((char *)&req + tail);

			rta->rta_type = RTA_GATEWAY;
			rta->rta_len = (unsigned short)RTA_LENGTH(alen);
			memcpy(RTA_DATA(rta), g, alen);
			tail += (unsigned)RTA_LENGTH(alen);
		}
		if (have_oif) {
			struct rtattr *rta = (struct rtattr *)((char *)&req + tail);

			rta->rta_type = RTA_OIF;
			rta->rta_len = (unsigned short)RTA_LENGTH(sizeof(int));
			memcpy(RTA_DATA(rta), &idx, sizeof(idx));
			tail += (unsigned)RTA_LENGTH(sizeof(int));
		}
		if (table != RT_TABLE_MAIN) {
			struct rtattr *rta = (struct rtattr *)((char *)&req + tail);

			rta->rta_type = RTA_TABLE;
			rta->rta_len = (unsigned short)
				RTA_LENGTH(sizeof(unsigned));
			memcpy(RTA_DATA(rta), &table, sizeof(table));
			tail += (unsigned)RTA_LENGTH(sizeof(unsigned));
		}
		req.n.nlmsg_len = tail;
		rc = na_talk_ack(&sk, &req, req.n.nlmsg_len);
		if (rc != 0) {
			fprintf(f, "ERROR: RTM_%sROUTE 失败（%s）——未生效",
				add ? "NEW" : "DEL", na_err(rc));
			if (add && rc == EEXIST)
				fprintf(f, "（同目标路由已存在，EXCL 保护"
					"未覆盖旧条目）");
			if (!add && rc == ESRCH)
				fprintf(f, "（该路由本就不存在）");
			fprintf(f, "\n");
			goto done;
		}
	}
	fprintf(f, "写 RTM_%sROUTE: dst=%s%s%s table=%d 已 ACK%s\n",
		add ? "NEW" : "DEL", dsts,
		have_gw ? " via " : "", have_gw ? gws : "", table,
		have_oif ? "（dev 见下行）" : "");
	if (have_oif)
		fprintf(f, "（dev=%s ifindex=%d）\n", ifaces, idx);

	/* 写后回读验证 */
	memset(&post, 0, sizeof(post));
	post.f = f;
	post.family = family;
	post.table = table;
	post.lc = &lc;
	post.want = 1;
	post.want_plen = plen;
	memcpy(post.want_dst, d, sizeof(d));
	fprintf(f, "写后回读:\n");
	post.shown = 24;	/* 回读段不重复罗列路由 */
	rdc = na_route_dump(&sk, &post);
	if (rdc != 0) {
		fprintf(f, "ERROR: 写后回读 dump 失败（%s）\n", na_err(rdc));
		goto done;
	}
	if (post.found == add) {
		fprintf(f, "  目标路由 %s —— 验证通过\n",
			add ? "已在位" : "已移除");
		ok = 0;
	} else {
		fprintf(f, "  目标路由 %s —— 验证失败（如实报告，请人工复核）\n",
			add ? "未在位" : "仍存在");
		ok = -1;
	}
	fprintf(f, "回滚提示：%s 同参数（dst+gateway+iface+table）再调一次"
		"即回滚/恢复。\n", add ? "net_route_del" : "net_route_add");
	rc = 0;

done:
	fclose(f);
	na_close(&sk);
	return ok;
}

/* ---- 6) net_link_del：删接口（内核仅允许虚拟接口） ---- */

static int na_link_del(const char *args, char **out)
{
	char iface[32];
	struct na_sock sk;
	FILE *f;
	int idx = 0, rc, ok = -1;
	unsigned flags = 0;
	char kind[32] = "";

	if (jstr_get(args, "iface", iface, sizeof(iface)) < 0 ||
	    !ai_net_admin_valid_iface(iface)) {
		*out = strdup("ERROR: 需要 iface（[A-Za-z0-9._-]{1,15}）");
		return -1;
	}
	if (na_open(&sk) < 0) {
		if (asprintf(out, "ERROR: rtnetlink 套接字打开失败: %s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	f = open_memstream(out, &(size_t){0});
	if (!f) {
		na_close(&sk);
		*out = strdup("ERROR: 内存不足");
		return -1;
	}

	rc = na_getlink_byname(&sk, iface, &idx, &flags, kind, sizeof(kind));
	if (rc != 0) {
		fprintf(f, "ERROR: RTM_GETLINK 读旧值失败（%s）: %s%s\n",
			na_err(rc), iface,
			rc == ENODEV ? "（接口不存在）" : "");
		goto done;
	}
	fprintf(f, "写前旧状态（重建凭据）: iface=%s ifindex=%d flags=0x%x "
	       "kind=%s\n", iface, idx, flags,
	       kind[0] ? kind : "<未知（物理接口？）>");

	{
		struct {
			struct nlmsghdr n;
			struct ifinfomsg ifi;
		} req;

		memset(&req, 0, sizeof(req));
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
		req.n.nlmsg_type = RTM_DELLINK;
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		req.n.nlmsg_seq = ++sk.seq;
		req.ifi.ifi_family = AF_UNSPEC;
		req.ifi.ifi_index = idx;
		rc = na_talk_ack(&sk, &req, req.n.nlmsg_len);
		if (rc != 0) {
			fprintf(f, "ERROR: RTM_DELLINK 失败（%s）——未生效",
				na_err(rc));
			if (rc == EOPNOTSUPP)
				fprintf(f, "（内核只允许删虚拟接口：dummy/"
					"veth/vlan/bridge/wg 等；物理网卡"
					"一律拒绝）");
			fprintf(f, "\n");
			goto done;
		}
	}
	fprintf(f, "写 RTM_DELLINK: %s 已 ACK\n", iface);

	rc = na_getlink_byname(&sk, iface, &idx, &flags, NULL, 0);
	if (rc == ENODEV) {
		fprintf(f, "写后回读: ENODEV —— 接口已消失，验证通过\n");
		ok = 0;
	} else {
		fprintf(f, "ERROR: 写后回读验证失败（%s，接口仍在）——"
			"如实报告，请人工复核\n", rc != 0 ? na_err(rc) : "?");
		ok = -1;
	}
	fprintf(f, "回滚提示：按上方 kind 用 exec「ip link add %s type %s」"
		"重建（kind 未知则无法恢复）；接口上的地址/路由需另行恢复。\n",
		iface, kind[0] ? kind : "<kind>");
	rc = 0;

done:
	fclose(f);
	na_close(&sk);
	return ok;
}

/* ---- 7) nft_txn：nftables 规则级事务 ---- */

/* 返回 op 中第 n 个词（0 起）在原串中的起点（原样保留后续文本） */
static const char *na_nth_token(const char *op, int n)
{
	int i = 0;
	const char *p = op;

	while (*p == ' ' || *p == '\t')
		p++;
	while (i < n && *p) {
		while (*p && *p != ' ' && *p != '\t')
			p++;
		while (*p == ' ' || *p == '\t')
			p++;
		i++;
	}
	return *p ? p : NULL;
}

/* 从 op 提取 ruleset 抽查关键串：剥掉 "add <obj>" 与对象定位前缀，
 * 取表达式主体。返回 0=key 有效；-1=回退整条 */
/* 词前缀相等判定（na_nth_token 返回"从该词起的余串"，
 * 不能直接 strcmp——W78E 冒烟实测教训） */
static int na_tok_eq(const char *rest, const char *word)
{
	size_t l = strlen(word);

	if (!rest || strncmp(rest, word, l) != 0)
		return 0;
	return rest[l] == '\0' || rest[l] == ' ' || rest[l] == '\t';
}

static int na_nft_key(const char *op, char *key, size_t cap)
{
	const char *tok0, *tok1;
	const char *expr = NULL;
	int skip = -1;
	size_t n;

	tok0 = na_nth_token(op, 0);
	tok1 = tok0 ? na_nth_token(op, 1) : NULL;
	if (!tok0 || !tok1)
		return -1;
	if (na_tok_eq(tok0, "add")) {
		if (na_tok_eq(tok1, "rule"))
			skip = 5;	/* add rule <fam> <tbl> <chn> <expr> */
		else if (na_tok_eq(tok1, "table"))
			skip = 3;	/* add table <fam> <name> */
		else if (na_tok_eq(tok1, "chain"))
			skip = 4;	/* add chain <fam> <tbl> <name> */
		else if (na_tok_eq(tok1, "set") ||
			 na_tok_eq(tok1, "map") ||
			 na_tok_eq(tok1, "counter") ||
			 na_tok_eq(tok1, "quota") ||
			 na_tok_eq(tok1, "limit"))
			skip = 4;
		else if (na_tok_eq(tok1, "element"))
			skip = 5;	/* add element <fam> <tbl> <set> {…} */
		else
			return -1;
	} else {
		return -1;		/* delete/insert/flush 等回退整条 */
	}
	expr = na_nth_token(op, skip);
	if (!expr || !*expr)
		return -1;
	n = strlen(expr);
	if (n >= cap)
		n = cap - 1;
	memcpy(key, expr, n);
	key[n] = '\0';
	return 0;
}

/* 空白不敏感子串查找（ruleset 输出单空格，op 可能多空格） */
static int na_ws_contains(const char *hay, const char *needle)
{
	const char *h = hay;
	size_t nlen = strlen(needle);

	if (!nlen)
		return 0;
	while (*h) {
		const char *hh = h, *nn = needle;
		int ok = 1;

		while (*nn) {
			while (*hh == ' ' || *hh == '\t')
				hh++;
			if (*hh != *nn) {
				ok = 0;
				break;
			}
			hh++;
			nn++;
			while (*nn == ' ' || *nn == '\t')
				nn++;
		}
		if (ok)
			return 1;
		h++;
	}
	return 0;
}

static int na_nft_txn(const char *args, char **out)
{
	static char ops[NA_MAX_OPS][NA_MAX_OP_LEN];
	static char buf[16384], rs[65536];
	int nops, dry, i, rc = -1, fd, listed = 0;
	char path[64];
	FILE *f;
	char *nargv[6];

	dry = jbool(args, "dry_run", 0);
	nops = jstr_array_get(args, "ops", ops, NA_MAX_OPS);
	if (nops < 1) {
		*out = strdup("ERROR: 需要 ops（字符串数组，每条一个 nft 片段，"
			      "1-32 条；JSON 数组格式非法也报此错）");
		return -1;
	}
	for (i = 0; i < nops; i++) {
		if (!ai_net_admin_valid_nft_op(ops[i])) {
			if (asprintf(out, "ERROR: ops[%d] 内容校验拒绝"
				     "（仅允许可打印文本；禁分号/换行/"
				     "反引号/$()，单条 1-%d 字节）——"
				     "整批不执行", i, NA_MAX_OP_LEN) < 0)
				*out = NULL;
			return -1;
		}
	}

	snprintf(path, sizeof(path), "/tmp/aik-nft-txn-%d.nft", (int)getpid());
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		if (asprintf(out, "ERROR: 临时文件创建失败 %s: %s",
			     path, strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	{
		ssize_t off = 0, wlen;
		size_t total = 0;
		char filebuf[NA_MAX_OPS * (NA_MAX_OP_LEN + 2)];

		for (i = 0; i < nops; i++) {
			size_t l = strlen(ops[i]);

			if (total + l + 1 >= sizeof(filebuf))
				break;
			memcpy(filebuf + total, ops[i], l);
			total += l;
			filebuf[total++] = '\n';
		}
		while (off < (ssize_t)total) {
			wlen = write(fd, filebuf + off, total - off);
			if (wlen <= 0)
				break;
			off += wlen;
		}
		close(fd);
		if (off != (ssize_t)total) {
			unlink(path);
			*out = strdup("ERROR: 临时文件写入失败");
			return -1;
		}
	}

	f = open_memstream(out, &(size_t){0});
	if (!f) {
		unlink(path);
		*out = strdup("ERROR: 内存不足");
		return -1;
	}
	fprintf(f, "nft_txn: %d 条 op（每条独立一行，0600 临时文件 %s）\n",
		nops, path);
	for (i = 0; i < nops; i++) {
		if (strstr(ops[i], "delete") || strstr(ops[i], "flush"))
			fprintf(f, "  op[%d] [警告:含 delete/flush，删规则/"
				"清表属高危，请授权者重点复核]: %s\n",
				i, ops[i]);
		else
			fprintf(f, "  op[%d]: %s\n", i, ops[i]);
	}

	/* 第一步：nft -c -f 全量语法预检（不生效） */
	memset(buf, 0, sizeof(buf));
	nargv[0] = (char *)NA_NFT;
	nargv[1] = (char *)"-c";
	nargv[2] = (char *)"-f";
	nargv[3] = path;
	nargv[4] = NULL;
	rc = run_argv(nargv, 15, buf, sizeof(buf));
	if (rc != 0) {
		fprintf(f, "ERROR: 预检失败（nft -c -f，退出码 %d，"
			"未应用任何变更）:\n%s\n", rc, buf);
		if (rc == 127)
			fprintf(f, "（%s 不存在——预检即失败，"
				"零副作用）\n", NA_NFT);
		rc = -1;
		goto out;
	}
	fprintf(f, "预检通过（nft -c -f 语法全量校验，未生效）\n");
	if (dry) {
		fprintf(f, "dry_run=true：预检通过未应用（临时文件已清理）。\n");
		rc = 0;
		goto out;
	}

	/* 第二步：正式应用（nft -f 单文件单批次提交） */
	memset(buf, 0, sizeof(buf));
	nargv[0] = (char *)NA_NFT;
	nargv[1] = (char *)"-f";
	nargv[2] = path;
	nargv[3] = NULL;
	rc = run_argv(nargv, 15, buf, sizeof(buf));
	if (rc != 0) {
		fprintf(f, "ERROR: 应用失败（nft -f，退出码 %d）:\n%s\n"
			"（nft -f 按文件单批次提交，内核拒绝批次则整体不生效；"
			"预检已过滤绝大多数此类失败）\n", rc, buf);
		rc = -1;
		goto out;
	}
	fprintf(f, "应用完成（nft -f 退出码 0）\n");

	/* 第三步：nft list ruleset 抽查关键串验证落位 */
	memset(rs, 0, sizeof(rs));
	nargv[0] = (char *)NA_NFT;
	nargv[1] = (char *)"list";
	nargv[2] = (char *)"ruleset";
	nargv[3] = NULL;
	rc = run_argv(nargv, 10, rs, sizeof(rs));
	if (rc == 0)
		listed = 1;
	else
		fprintf(f, "抽查失败：nft list ruleset 退出码 %d（规则可能"
			"已生效，抽查不等于验证失败）\n", rc);
	if (listed) {
		if (strlen(rs) >= sizeof(rs) - 1)
			fprintf(f, "（ruleset 输出超 %zu 字节被截断，"
				"抽查以截断窗口为准）\n", sizeof(rs) - 1);
		for (i = 0; i < nops; i++) {
			char key[NA_MAX_OP_LEN];

			if (na_nft_key(ops[i], key, sizeof(key)) == 0 &&
			    na_ws_contains(rs, key))
				fprintf(f, "抽查 op[%d]: 关键串命中"
					"（已落位）\n", i);
			else if (na_nft_key(ops[i], key, sizeof(key)) == 0)
				fprintf(f, "抽查 op[%d]: 关键串未命中"
					"（nft 列表会规范化部分语法，"
					"未命中≠未生效；可用 exec「nft list "
					"ruleset」人工复核）\n", i);
			else
				fprintf(f, "抽查 op[%d]: 无自动关键串"
					"（非 add 形态，跳过抽查）\n", i);
		}
	}
	fprintf(f, "回滚提示：逐条 delete 对应对象（如 delete rule inet "
		"filter input handle <N>，handle 用 exec「nft -a list "
		"ruleset」查）；整表用 delete table <fam> <name>。\n");
	fprintf(f, "锁死风险场景：AI 识别→暂停→授权者确认，SSH 放行规则"
		"是硬闸（出厂 SSH 放行规则严禁删除）；运行时规则重启即清，"
		"持久化须另走 config_write_nftables。\n");
	rc = 0;

out:
	unlink(path);
	fclose(f);
	return rc;
}

/* ---- 分发 ---- */

int exec_net_admin_channel(const void *tool_v, const char *args_json,
			   char **out)
{
	const struct ai_tool *tool = tool_v;

	*out = NULL;
	if (!tool || !tool->name || !args_json)
		return -1;
	if (strcmp(tool->name, "net_iface") == 0)
		return na_iface(args_json, out);
	if (strcmp(tool->name, "net_addr_add") == 0)
		return na_addr(args_json, out, 1);
	if (strcmp(tool->name, "net_addr_del") == 0)
		return na_addr(args_json, out, 0);
	if (strcmp(tool->name, "net_route_add") == 0)
		return na_route(args_json, out, 1);
	if (strcmp(tool->name, "net_route_del") == 0)
		return na_route(args_json, out, 0);
	if (strcmp(tool->name, "net_link_del") == 0)
		return na_link_del(args_json, out);
	if (strcmp(tool->name, "nft_txn") == 0)
		return na_nft_txn(args_json, out);
	if (asprintf(out, "ERROR: 未知 netadmin 工具（注册表异常）") < 0)
		*out = NULL;
	return -1;
}
