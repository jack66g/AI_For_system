// SPDX-License-Identifier: GPL-2.0
/*
 * ai_net_payload.h - AIKernel 第4类网络遥测 payload 结构与子事件枚举
 *
 * 职责一句话：第4类 10 子类 36 个子事件的枚举（enum ai_net_sub_event）与
 * 类型化 payload 结构（全量原始零脱敏，首字段 type = 子事件号）。
 *
 * 拆分说明：本头文件由原 ai_net.h（881 行）的枚举 + payload 结构段
 * （36-294 行）逐字拆出，仅被 ai_net.h 在 CONFIG_AIKERNEL_NET 分支内
 * include；对外仍只需 include ai_net.h 即可获得全部原名，接口集合不变。
 */

#ifndef _AIKERNEL_AI_NET_PAYLOAD_H
#define _AIKERNEL_AI_NET_PAYLOAD_H

#include <linux/types.h>


/*
 * ---- 子事件枚举（payload 首字段 type，全局唯一） ----
 * 对应《AIKernel_数据源与日志系统计划》第4类各子类，数字编号见表 2.4。
 */
enum ai_net_sub_event {
	AI_NET_SUB_SOCKET_CREATE	= 1,
	AI_NET_SUB_SOCKET_CLOSE,
	AI_NET_SUB_SOCKET_LISTEN,
	AI_NET_SUB_SOCKET_ACCEPT,
	AI_NET_SUB_SOCKET_CONNECT,
	AI_NET_SUB_SOCKET_SEND,
	AI_NET_SUB_SOCKET_RECV,
	AI_NET_SUB_TCP_RETRANSMIT,
	AI_NET_SUB_TCP_RTT_UPDATE,
	AI_NET_SUB_TCP_CWND_UPDATE,
	AI_NET_SUB_TCP_CONGESTION_STATE,
	AI_NET_SUB_TCP_ABORT,
	AI_NET_SUB_TCP_PACKET_RAW,
	AI_NET_SUB_UDP_SEND,
	AI_NET_SUB_UDP_RECV,
	AI_NET_SUB_IP_PACKET,
	AI_NET_SUB_IP_ROUTE_LOOKUP,
	AI_NET_SUB_NF_HOOK,
	AI_NET_SUB_NF_CONNTRACK_NEW,
	AI_NET_SUB_NF_CONNTRACK_DESTROY,
	AI_NET_SUB_NF_NAT,
	AI_NET_SUB_XDP_RX,
	AI_NET_SUB_TC_ENQUEUE,
	AI_NET_SUB_TC_DEQUEUE,
	AI_NET_SUB_TC_DROP,
	AI_NET_SUB_DNS_QUERY,
	AI_NET_SUB_HTTP_REQUEST,
	AI_NET_SUB_TLS_HANDSHAKE,
	AI_NET_SUB_NETDEV_RX,
	AI_NET_SUB_NETDEV_TX,
	AI_NET_SUB_NETDEV_DROP,
	AI_NET_SUB_NAPI_POLL,
	AI_NET_SUB_GRO_RECEIVE,
	AI_NET_SUB_GRO_MERGE,
	AI_NET_SUB_NEIGH_NEW,
	AI_NET_SUB_NEIGH_EXPIRE,
	AI_NET_SUB_MAX,
};

/* ---- 第4类 payload 结构（全量原始零脱敏，首字段 type = 子事件号） ---- */

struct ai_net_pl_socket_create {
	u16 type;
	u16 family, stype, protocol;
	u32 pid;
	char comm[16];
};

struct ai_net_pl_socket_close {
	u16 type;
	u16 family, stype, reserved;
	u64 bytes_sent, bytes_recv;
};

struct ai_net_pl_socket_listen {
	u16 type;
	u16 port;
	u32 backlog;
	u32 pid;
	char comm[16];
};

struct ai_net_pl_socket_accept {
	u16 type;
	u16 listen_port, client_port;
	u32 client_addr;
};

struct ai_net_pl_socket_connect {
	u16 type;
	u16 dst_port, reserved;
	u32 dst_addr;
	u64 latency_us;
	u32 pid;
	char comm[16];
};

struct ai_net_pl_socket_sendrecv {
	u16 type;
	u16 reserved;
	u64 sock_ptr;
	u32 bytes;
	u32 pid;
	char comm[16];
};

struct ai_net_pl_tcp_retransmit {
	u16 type;
	u16 sport, dport;
	u32 src_addr, dst_addr;
	u32 seq;
	s32 reason;
};

struct ai_net_pl_tcp_rtt_update {
	u16 type;
	u16 reserved;
	u32 srtt_us, rttvar_us, rto_us;
};

struct ai_net_pl_tcp_cwnd_update {
	u16 type;
	u16 cwnd_event;
	u32 cwnd, ssthresh;
};

struct ai_net_pl_tcp_congestion_state {
	u16 type;
	u8  state;
	u8  reserved;
	char ca_name[16];
};

struct ai_net_pl_tcp_abort {
	u16 type;
	u16 sport, dport;
	u32 src_addr, dst_addr;
	s32 reason;
};

struct ai_net_pl_tcp_packet_raw {
	u16 type;
	u16 sport, dport;
	u32 src_addr, dst_addr;
	u8  flags;
	u8  reserved[3];
	u32 seq, ack;
	u16 payload_len;
	u8  payload_sample[128];
};

struct ai_net_pl_udp {
	u16 type;
	u16 sport, dport;
	u32 src_addr, dst_addr;
	u32 bytes;
	u8  payload_sample[64];
};

struct ai_net_pl_ip_packet {
	u16 type;
	u8  proto, ttl;
	u32 src_ip, dst_ip;
	u16 bytes, tos, frag_info;
};

struct ai_net_pl_ip_route_lookup {
	u16 type;
	u16 reserved;
	u32 dst_ip;
	u32 oif;
	s32 result;
};

struct ai_net_pl_nf_hook {
	u16 type;
	u8  hook_num, proto;
	u32 verdict;
	u32 src_ip, dst_ip;
	u16 sport, dport;
};

struct ai_net_pl_nf_conntrack {
	u16 type;
	u8  proto, reserved;
	u32 src_ip, dst_ip;
	u16 sport, dport;
	u64 bytes_sent, bytes_recv;
};

struct ai_net_pl_nf_nat {
	u16 type;
	u16 old_port, new_port;
	u32 src_ip, dst_ip, old_addr, new_addr;
};

struct ai_net_pl_xdp_rx {
	u16 type;
	u16 reserved;
	u32 action, len;
	char dev[16];
};

struct ai_net_pl_tc {
	u16 type;
	u16 reserved;
	u32 bytes;
	s32 reason;
	char dev[16];
	char qdisc_name[16];
};

struct ai_net_pl_dns_query {
	u16 type;
	u16 reserved;
	u32 pid;
	char comm[16];
	char domain_name[128];
	char query_type[16];
	char resolved_ips[128];
};

struct ai_net_pl_http_request {
	u16 type;
	u16 status_code;
	u32 bytes;
	u32 pid;
	char comm[16];
	char method[8];
	char url[128];
	char host[64];
};

struct ai_net_pl_tls_handshake {
	u16 type;
	u16 dst_port;
	u32 dst_addr;
	u16 version, cipher_suite;
	u32 pid;
	char comm[16];
	char sni[128];
};

struct ai_net_pl_netdev {
	u16 type;
	u16 cpu;
	u32 bytes;
	u32 reason;
	char dev[16];
};

struct ai_net_pl_napi_poll {
	u16 type;
	u16 reserved;
	u32 budget, work_done;
	char dev[16];
};

struct ai_net_pl_gro {
	u16 type;
	u16 reserved;
	u32 result;
	char dev[16];
};

struct ai_net_pl_neigh {
	u16 type;
	u16 family;
	u8  state;
	u8  reserved;
	u32 daddr;
	char dev[16];
};

#endif /* _AIKERNEL_AI_NET_PAYLOAD_H */
