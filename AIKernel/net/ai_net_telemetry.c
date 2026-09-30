// SPDX-License-Identifier: GPL-2.0
/*
 * ai_net_telemetry.c - AIKernel B 轨第4类复杂解析发射（自 ai_net.c 拆分）
 *
 * 职责一句话：socket 生命周期（close/listen/accept/connect）、TCP 重传/中止/
 * raw payload、UDP 收发、IP 报文、netfilter hook/conntrack/NAT、XDP、DNS、
 * 邻居表事件的发射辅助（复杂地址/端口/载荷解析在这里做，采样判定后
 * emit_direct 直写）。
 *
 * 拆分说明：函数体自原 ai_net.c（1141 行）逐字搬移；ai_net_fill_packet_raw/
 * ai_net_fill_ct_tuple/ai_net_neigh_fill 仅本文件使用保持 static；
 * ai_net_sock_addr4 提升为模块内部共享（定义在本文件，声明见
 * ai_net_internal.h，供 ai_net_scan.c 复用）。门控：随 ai_net.o 在
 * CONFIG_AIKERNEL_NET 下构建（与拆分前一致）。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ktime.h>
#include <linux/netfilter.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <net/xdp.h>
#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include "ai_net.h"
#include "../core/ai_control.h"

#ifdef CONFIG_INET
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#endif

#ifdef CONFIG_NF_CONNTRACK
#include <net/netfilter/nf_conntrack.h>
#endif
#ifdef CONFIG_NF_NAT
#include <net/netfilter/nf_nat.h>
#endif
#ifdef CONFIG_NF_CONNTRACK_ACCT
#include <net/netfilter/nf_conntrack_acct.h>
#endif
#include "ai_net_internal.h"

#ifdef CONFIG_INET
void ai_net_sock_addr4(const struct sock *sk, u32 *saddr, u32 *daddr,
			      u16 *sport, u16 *dport)
{
	const struct inet_sock *inet;

	if (!sk || sk->sk_family != AF_INET)
		return;
	inet = inet_sk(sk);
	if (saddr)
		*saddr = inet->inet_saddr;
	if (daddr)
		*daddr = inet->inet_daddr;
	if (sport)
		*sport = inet->inet_num;
	if (dport)
		*dport = ntohs(inet->inet_dport);
}
#endif

/*
 * ---- B 轨：复杂解析发射 ----
 */

void ai_telemetry_socket_close(struct socket *sock)
{
	struct ai_net_pl_socket_close pl;

	if (!ai_net_sample_take(AI_NET_SUB_SOCKET_CLOSE))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_SOCKET_CLOSE;
	if (sock) {
		pl.family = sock->ops ? sock->ops->family : 0;
		pl.stype = sock->type;
		if (sock->sk)
			ai_net_sock_bytes_take(sock->sk, &pl.bytes_sent,
					       &pl.bytes_recv);
	}
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_SOCKET, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_socket_close);

void ai_telemetry_socket_listen(struct socket *sock, int backlog)
{
	struct ai_net_pl_socket_listen pl;

	if (!ai_net_sample_take(AI_NET_SUB_SOCKET_LISTEN))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_SOCKET_LISTEN;
	pl.backlog = backlog;
	pl.pid = task_tgid_nr(current);
	strscpy(pl.comm, current->comm, sizeof(pl.comm));
#ifdef CONFIG_INET
	if (sock && sock->sk && sock->sk->sk_family == AF_INET)
		pl.port = inet_sk(sock->sk)->inet_num;
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_SOCKET, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_socket_listen);

void ai_telemetry_socket_accept(struct socket *listener, struct socket *newsock)
{
	struct ai_net_pl_socket_accept pl;

	if (!ai_net_sample_take(AI_NET_SUB_SOCKET_ACCEPT))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_SOCKET_ACCEPT;
#ifdef CONFIG_INET
	if (listener && listener->sk &&
	    listener->sk->sk_family == AF_INET)
		pl.listen_port = inet_sk(listener->sk)->inet_num;
	if (newsock && newsock->sk && newsock->sk->sk_family == AF_INET) {
		pl.client_addr = inet_sk(newsock->sk)->inet_daddr;
		pl.client_port = ntohs(inet_sk(newsock->sk)->inet_dport);
	}
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_SOCKET, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_socket_accept);

void ai_telemetry_socket_connect(struct sock *sk, u64 latency_us, int err)
{
	struct ai_net_pl_socket_connect pl;

	if (!ai_net_sample_take(AI_NET_SUB_SOCKET_CONNECT))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_SOCKET_CONNECT;
	pl.latency_us = latency_us;
	pl.pid = task_tgid_nr(current);
	strscpy(pl.comm, current->comm, sizeof(pl.comm));
#ifdef CONFIG_INET
	ai_net_sock_addr4(sk, &pl.dst_addr, NULL, NULL, &pl.dst_port);
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_SOCKET, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_socket_connect);

void ai_telemetry_tcp_retransmit(struct sock *sk, struct sk_buff *skb, int err)
{
	struct ai_net_pl_tcp_retransmit pl;

	if (!ai_net_sample_take(AI_NET_SUB_TCP_RETRANSMIT))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_TCP_RETRANSMIT;
	pl.reason = err;
#ifdef CONFIG_INET
	ai_net_sock_addr4(sk, &pl.src_addr, &pl.dst_addr, &pl.sport,
			  &pl.dport);
	if (skb)
		pl.seq = TCP_SKB_CB(skb)->seq;
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TCP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_tcp_retransmit);

void ai_telemetry_tcp_abort(struct sock *sk, int err)
{
	struct ai_net_pl_tcp_abort pl;

	if (!ai_net_sample_take(AI_NET_SUB_TCP_ABORT))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_TCP_ABORT;
	pl.reason = err;
#ifdef CONFIG_INET
	ai_net_sock_addr4(sk, &pl.src_addr, &pl.dst_addr, &pl.sport,
			  &pl.dport);
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TCP, AI_SEV_IMPORTANT,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_tcp_abort);

#ifdef CONFIG_INET
static void ai_net_fill_packet_raw(struct ai_net_pl_tcp_packet_raw *pl,
				   const struct tcphdr *th,
				   struct sk_buff *skb, u32 payload_off)
{
	u32 len = skb->len - payload_off;
	u32 n = min_t(u32, len, sizeof(pl->payload_sample));

	pl->flags = tcp_flags_ntohs(th);
	pl->seq = ntohl(th->seq);
	pl->ack = ntohl(th->ack_seq);
	pl->payload_len = len > 0xffff ? 0xffff : (u16)len;
	memset(pl->payload_sample, 0, sizeof(pl->payload_sample));
	if (n)
		skb_copy_bits(skb, payload_off, pl->payload_sample, n);
}
#endif

void ai_telemetry_tcp_packet_raw_tx(struct sock *sk, struct sk_buff *skb)
{
	struct ai_net_pl_tcp_packet_raw pl;

	if (!ai_net_sample_take(AI_NET_SUB_TCP_PACKET_RAW))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_TCP_PACKET_RAW;
#ifdef CONFIG_INET
	ai_net_sock_addr4(sk, &pl.src_addr, &pl.dst_addr, &pl.sport,
			  &pl.dport);
	if (skb) {
		const struct tcphdr *th = tcp_hdr(skb);
		u32 hlen = th->doff << 2;

		if (skb->len >= hlen)
			ai_net_fill_packet_raw(&pl, th, skb, hlen);
	}
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TCP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_tcp_packet_raw_tx);

void ai_telemetry_tcp_packet_raw_rx(struct sock *sk, struct sk_buff *skb)
{
	struct ai_net_pl_tcp_packet_raw pl;

	if (!ai_net_sample_take(AI_NET_SUB_TCP_PACKET_RAW))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_TCP_PACKET_RAW;
#ifdef CONFIG_INET
	if (skb && skb->len >= sizeof(struct tcphdr)) {
		const struct tcphdr *th = (const struct tcphdr *)skb->data;

		if (th->doff * 4 <= skb->len) {
			ai_net_fill_packet_raw(&pl, th, skb, th->doff * 4);
			pl.sport = ntohs(th->source);
			pl.dport = ntohs(th->dest);
			if (skb->protocol == htons(ETH_P_IP)) {
				const struct iphdr *iph = ip_hdr(skb);

				pl.src_addr = iph->saddr;
				pl.dst_addr = iph->daddr;
			}
		}
	} else {
		ai_net_sock_addr4(sk, &pl.src_addr, &pl.dst_addr, &pl.sport,
				  &pl.dport);
	}
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TCP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_tcp_packet_raw_rx);

void ai_telemetry_udp_send(struct sock *sk, struct sk_buff *skb)
{
	struct ai_net_pl_udp pl;

	if (!ai_net_sample_take(AI_NET_SUB_UDP_SEND))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_UDP_SEND;
#ifdef CONFIG_INET
	if (skb) {
		const struct udphdr *uh = udp_hdr(skb);
		u32 off = skb_transport_offset(skb);
		u32 len = skb->len - off;
		u32 n;

		pl.sport = ntohs(uh->source);
		pl.dport = ntohs(uh->dest);
		pl.bytes = len;
		n = min_t(u32, len - min_t(u32, len, sizeof(*uh)),
			  sizeof(pl.payload_sample));
		if (n)
			skb_copy_bits(skb, off + sizeof(*uh),
				      pl.payload_sample, n);
	}
	ai_net_sock_addr4(sk, &pl.src_addr, &pl.dst_addr, NULL, NULL);
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_UDP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_udp_send);

void ai_telemetry_udp_recv(struct sk_buff *skb)
{
	struct ai_net_pl_udp pl;

	if (!ai_net_sample_take(AI_NET_SUB_UDP_RECV))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_UDP_RECV;
#ifdef CONFIG_INET
	if (skb && skb->len >= sizeof(struct udphdr)) {
		const struct udphdr *uh = udp_hdr(skb);
		u32 len = ntohs(uh->len);
		u32 n;

		pl.sport = ntohs(uh->source);
		pl.dport = ntohs(uh->dest);
		pl.bytes = len ? len - sizeof(*uh) : skb->len - sizeof(*uh);
		n = min_t(u32, pl.bytes, sizeof(pl.payload_sample));
		if (n)
			skb_copy_bits(skb, sizeof(*uh), pl.payload_sample, n);
		if (skb->protocol == htons(ETH_P_IP)) {
			const struct iphdr *iph = ip_hdr(skb);

			pl.src_addr = iph->saddr;
			pl.dst_addr = iph->daddr;
		}
	}
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_UDP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_udp_recv);

void ai_telemetry_ip_packet(struct sk_buff *skb)
{
	struct ai_net_pl_ip_packet pl;

	if (!ai_net_sample_take(AI_NET_SUB_IP_PACKET))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_IP_PACKET;
#ifdef CONFIG_INET
	if (skb && skb_network_header_len(skb)) {
		const struct iphdr *iph = ip_hdr(skb);

		pl.proto = iph->protocol;
		pl.ttl = iph->ttl;
		pl.src_ip = iph->saddr;
		pl.dst_ip = iph->daddr;
		pl.bytes = ntohs(iph->tot_len);
		pl.tos = ipv4_get_dsfield(iph);
		pl.frag_info = ntohs(iph->frag_off);
	}
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_IP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_ip_packet);

void ai_telemetry_nf_hook(struct sk_buff *skb,
			  const struct nf_hook_state *state,
			  unsigned int verdict)
{
	struct ai_net_pl_nf_hook pl;

	if (!ai_net_sample_take(AI_NET_SUB_NF_HOOK))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_NF_HOOK;
	pl.verdict = verdict;
	if (state)
		pl.hook_num = state->hook;
#ifdef CONFIG_INET
	if (state && state->pf == NFPROTO_IPV4 && skb &&
	    skb_network_header_len(skb)) {
		const struct iphdr *iph = ip_hdr(skb);

		pl.proto = iph->protocol;
		pl.src_ip = iph->saddr;
		pl.dst_ip = iph->daddr;
		if (iph->protocol == IPPROTO_TCP ||
		    iph->protocol == IPPROTO_UDP) {
			struct tcphdr th;
			u32 off = 0;

			/* 钩子路径上 data 通常即网络头（LOCAL_OUT 在 IP 头构建后）；
			 * 个别路径 transport_header 已就位且偏移非负时用传输头偏移。 */
			if (skb_network_header_len(skb) &&
			    skb->data == skb_network_header(skb))
				off = ip_hdrlen(skb);
			else if (skb_transport_header_was_set(skb) &&
				 (int)skb_transport_offset(skb) >= 0)
				off = skb_transport_offset(skb);
			if (skb_header_pointer(skb, off, sizeof(th), &th)) {
				pl.sport = ntohs(th.source);
				pl.dport = ntohs(th.dest);
			}
		}
	}
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETFILTER, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_nf_hook);

#ifdef CONFIG_NF_CONNTRACK
static void ai_net_fill_ct_tuple(struct ai_net_pl_nf_conntrack *pl,
				 const struct nf_conn *ct)
{
	const struct nf_conntrack_tuple *t =
		&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

	pl->src_ip = t->src.u3.ip;
	pl->dst_ip = t->dst.u3.ip;
	pl->proto = t->dst.protonum;
	if (t->dst.protonum == IPPROTO_TCP || t->dst.protonum == IPPROTO_UDP) {
		pl->sport = ntohs(t->src.u.tcp.port);
		pl->dport = ntohs(t->dst.u.tcp.port);
	}
}
#endif

void ai_telemetry_nf_conntrack_new(struct nf_conn *ct)
{
	struct ai_net_pl_nf_conntrack pl;

	if (!ai_net_sample_take(AI_NET_SUB_NF_CONNTRACK_NEW))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_NF_CONNTRACK_NEW;
#ifdef CONFIG_NF_CONNTRACK
	if (ct)
		ai_net_fill_ct_tuple(&pl, ct);
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETFILTER, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_nf_conntrack_new);

void ai_telemetry_nf_conntrack_destroy(struct nf_conn *ct)
{
	struct ai_net_pl_nf_conntrack pl;

	if (!ai_net_sample_take(AI_NET_SUB_NF_CONNTRACK_DESTROY))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_NF_CONNTRACK_DESTROY;
#ifdef CONFIG_NF_CONNTRACK
	if (ct) {
		ai_net_fill_ct_tuple(&pl, ct);
#ifdef CONFIG_NF_CONNTRACK_ACCT
		{
			const struct nf_conn_acct *acct = nf_ct_acct(ct);

			if (acct) {
				pl.bytes_sent =
					atomic64_read(&acct->counter[IP_CT_DIR_ORIGINAL].bytes);
				pl.bytes_recv =
					atomic64_read(&acct->counter[IP_CT_DIR_REPLY].bytes);
			}
		}
#endif
	}
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETFILTER, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_nf_conntrack_destroy);

void ai_telemetry_nf_nat(struct nf_conn *ct, const void *range,
			 unsigned int maniptype)
{
	struct ai_net_pl_nf_nat pl;

	if (!ai_net_sample_take(AI_NET_SUB_NF_NAT))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_NF_NAT;
#ifdef CONFIG_NF_NAT
	if (ct) {
		const struct nf_conntrack_tuple *t =
			&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
		const struct nf_nat_range2 *r = range;

		pl.src_ip = t->src.u3.ip;
		pl.dst_ip = t->dst.u3.ip;
		if (r) {
			pl.old_addr = t->src.u3.ip;
			pl.new_addr = r->min_addr.ip;
			pl.old_port = ntohs(t->src.u.tcp.port);
			pl.new_port = ntohs(r->min_proto.tcp.port);
		}
	}
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETFILTER, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_nf_nat);

void ai_telemetry_xdp_rx(const struct xdp_buff *xdp, struct net_device *dev)
{
	struct ai_net_pl_xdp_rx pl;

	if (!ai_net_sample_take(AI_NET_SUB_XDP_RX))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_XDP_RX;
	pl.action = XDP_PASS;
	if (xdp)
		pl.len = xdp->data_end - xdp->data;
	if (dev)
		strscpy(pl.dev, dev->name, sizeof(pl.dev));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_XDP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_xdp_rx);

void ai_telemetry_dns_query(const char *name, size_t namelen,
			    const char *type, const char *result, int ret)
{
	struct ai_net_pl_dns_query pl;
	size_t n;

	if (!ai_net_sample_take(AI_NET_SUB_DNS_QUERY))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_DNS_QUERY;
	pl.pid = task_tgid_nr(current);
	strscpy(pl.comm, current->comm, sizeof(pl.comm));
	n = min_t(size_t, namelen, sizeof(pl.domain_name) - 1);
	if (n)
		memcpy(pl.domain_name, name, n);
	if (type)
		strscpy(pl.query_type, type, sizeof(pl.query_type));
	if (result && ret > 0)
		strscpy(pl.resolved_ips, result,
			sizeof(pl.resolved_ips));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_DNS, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_dns_query);

#ifdef CONFIG_INET
static void ai_net_neigh_fill(struct ai_net_pl_neigh *pl,
			      const struct neighbour *n)
{
	if (!n)
		return;
	if (n->dev)
		strscpy(pl->dev, n->dev->name, sizeof(pl->dev));
	pl->family = n->tbl->family;
	pl->state = n->nud_state;
	if (n->tbl->family == AF_INET)
		memcpy(&pl->daddr, n->primary_key,
		       min_t(int, n->tbl->key_len, 4));
}
#endif

void ai_telemetry_neigh_new(struct neighbour *n)
{
	struct ai_net_pl_neigh pl;

	if (!ai_net_sample_take(AI_NET_SUB_NEIGH_NEW))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_NEIGH_NEW;
#ifdef CONFIG_INET
	ai_net_neigh_fill(&pl, n);
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETDEV, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_neigh_new);

void ai_telemetry_neigh_expire(struct neighbour *n)
{
	struct ai_net_pl_neigh pl;

	if (!ai_net_sample_take(AI_NET_SUB_NEIGH_EXPIRE))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_NEIGH_EXPIRE;
#ifdef CONFIG_INET
	ai_net_neigh_fill(&pl, n);
#endif
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETDEV, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}
EXPORT_SYMBOL_GPL(ai_telemetry_neigh_expire);

