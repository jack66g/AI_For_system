// SPDX-License-Identifier: GPL-2.0
/*
 * ai_net.h - AIKernel 网络子系统唯一接入头（Prompt 06）
 *
 * net/ 全部 AI 埋点（A 轨 Hook + B 轨第4类网络感知）的唯一接入头，门控 CONFIG_AIKERNEL_NET。
 * - A 轨：ai_net_*_hook 系列（AI 网络决策点，空实现 = 原样放行，不改内核行为）；
 * - B 轨：ai_telemetry_* 系列（第4类 10 子类 26 事件，payload 首字段 type =
 *   enum ai_net_sub_event，全量原始零脱敏；payload_sample 保留原始字节）；
 * - 子事件采样门控：ai_net_sample_take(sub)（per-CPU 无锁计数，采样率表见 ai_net.c，
 *   分级策略见 AIKernel_Design/06_*.md 2.4 节——网络是最大感知域，必须分级）；
 * - CONFIG_AIKERNEL_NET=n 时本头文件不参与编译（调用点 #ifdef 剔除，
 *   预处理产物与基线逐字节一致，零回归由构造保证）。
 */

#ifndef _AIKERNEL_AI_NET_H
#define _AIKERNEL_AI_NET_H

#ifdef CONFIG_AIKERNEL_NET

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/gro.h>
#include "../../core/ai_types.h"
#include "../../core/ai_telemetry.h"

struct Qdisc;
struct neighbour;
struct napi_struct;
struct nf_conn;
struct nf_hook_state;
struct xdp_buff;
#include "ai_net_payload.h"

/*
 * ---- 子事件采样门控（采样率表与实现见 ai_net.c，分级策略定稿见设计文档 2.4） ----
 *
 * 每个 ai_telemetry_* 发射前先过本门控：rate==0 跳过（默认 off）、rate==1 全量、
 * rate==N 每 N 次记 1 次（per-CPU 无锁计数）。tcp_packet_raw 额外受
 * ai_net_payload_sampling 参数（/sys/module/ai_net/parameters/）门控——默认关闭，
 * 打开后按 1/256 采样，内容零脱敏。
 */

/**
 * ai_net_sample_take() - 子事件采样判定
 * @sub: 子事件号（enum ai_net_sub_event）
 *
 * 返回 true=本次应发射（随后必须用 emit_direct 直写），false=跳过。
 */
bool ai_net_sample_take(u16 sub);

/**
 * ai_net_set_sub_rate() - 覆盖子事件采样率
 * @sub: 子事件号
 * @rate: 0=关闭 1=全量 N=每 N 次记 1 条
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_net_set_sub_rate(u16 sub, u32 rate);

/*
 * ---- A 轨：AI 网络决策 Hook（ai_net.c 实现，全部 EXPORT_SYMBOL_GPL） ----
 * nf 为真行为钩（异常检测观测）。K5 删除 cong 域两个空桩咨询钩
 * （见 AIKernel/CHANGELOG.md）；决策计数经 ai_net_stats_read() 读取。
 */

/**
 * ai_net_nf_hook() - AI 包级异常/攻击检测
 * @skb: 待判定报文
 * @state: netfilter 钩子状态
 * @verdict: 钩子链已产生的判定（NF_ACCEPT/NF_DROP/NF_QUEUE/NF_STOLEN）
 *
 * 空实现返回原 verdict（语义不变）。调用点：netfilter/core.c nf_hook_slow()。
 */
unsigned int ai_net_nf_hook(struct sk_buff *skb,
			    const struct nf_hook_state *state,
			    unsigned int verdict);

/**
 * w21 net.qdisc 运行时 graft 的 KUnit 测试钩子（实现在 ai_net.c 的
 * CONFIG_NET_SCHED && CONFIG_INET 门控段；声明同门控，避免 n 配置链接错）。
 * dryrun=true 时 net.qdisc apply 正常钳制/提交/current 更新但不调度
 * worker（不碰真实网卡）；pending_get 读未消费的提交值（确定性断言）。
 */
#if IS_ENABLED(CONFIG_NET_SCHED) && defined(CONFIG_INET)
void ai_net_qdisc_dryrun_set(bool on);
u8 ai_net_qdisc_pending_get(void);
#endif

/* K5（2026-11）：cong 域两个空桩门控钩（cwnd 增量 / ssthresh 咨询）的
 * 双桩声明已删除（判决与复活路径见 AIKernel/CHANGELOG.md 与
 * work/refactor/KERNEL-K5-DESIGN.md §3）；ai_cca CCA 本体保留。 */

/*
 * ---- 决策框架（占位启发式，AI 推理后续替换，ai_net.c 实现） ----
 */

/**
 * ai_net_classify() - 流量粗分类（端口/协议/TCP flags 启发式）
 * @skb: 报文
 *
 * 返回分类号（0=未知 1=TCP 2=UDP 3=ICMP 4=监听/SYN 5=重传 6=控制）。供后续 Hook 消费。
 */
u8 ai_net_classify(struct sk_buff *skb);

/**
 * ai_net_detect_anomaly() - 攻击检测启发式（SYN 洪泛计数/重传率统计）
 * @skb: 报文
 * @verdict: netfilter 判定
 *
 * per-CPU 计数（syn/retrans/other），不干预数据面。计数经 ai_net_stats_read() 读取。
 */
void ai_net_detect_anomaly(struct sk_buff *skb, unsigned int verdict);

struct ai_net_stats {
	u64 nf_hook_calls;	/* netfilter 咨询计数（cong 两槽随 K5 删钩收缩） */
	u64 classify_calls;
	u64 anomaly_syn_pkts;
	u64 anomaly_retrans_pkts;
	u64 anomaly_samples;
};

/**
 * ai_net_stats_read() - 决策统计读取
 * @st: 统计输出
 */
void ai_net_stats_read(struct ai_net_stats *st);

/*
 * ---- B 轨：第4类 发射接口 ----
 * 简单事件为 static inline（调用点传已提取标量）；复杂解析（地址/端口/payload）为
 * ai_net.c 真实函数（调用点传 struct 指针）。全部先 ai_net_sample_take 判定，
 * 判定通过后 ai_telemetry_emit_direct 直写（无二次采样）。
 */

static inline void ai_telemetry_socket_create(u16 family, u16 type, u16 protocol)
{
	struct ai_net_pl_socket_create pl;

	if (!ai_net_sample_take(AI_NET_SUB_SOCKET_CREATE))
		return;
	pl.type = AI_NET_SUB_SOCKET_CREATE;
	pl.family = family;
	pl.stype = type;
	pl.protocol = protocol;
	pl.pid = task_tgid_nr(current);
	strscpy(pl.comm, current->comm, sizeof(pl.comm));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_SOCKET, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_socket_send(struct socket *sock, u32 bytes)
{
	struct ai_net_pl_socket_sendrecv pl;

	if (!ai_net_sample_take(AI_NET_SUB_SOCKET_SEND))
		return;
	pl.type = AI_NET_SUB_SOCKET_SEND;
	pl.sock_ptr = (u64)(unsigned long)sock;
	pl.bytes = bytes;
	pl.pid = task_tgid_nr(current);
	strscpy(pl.comm, current->comm, sizeof(pl.comm));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_SOCKET, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_socket_recv(struct socket *sock, u32 bytes)
{
	struct ai_net_pl_socket_sendrecv pl;

	if (!ai_net_sample_take(AI_NET_SUB_SOCKET_RECV))
		return;
	pl.type = AI_NET_SUB_SOCKET_RECV;
	pl.sock_ptr = (u64)(unsigned long)sock;
	pl.bytes = bytes;
	pl.pid = task_tgid_nr(current);
	strscpy(pl.comm, current->comm, sizeof(pl.comm));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_SOCKET, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_tcp_rtt_update(u32 srtt_us, u32 rttvar_us,
					       u32 rto_us)
{
	struct ai_net_pl_tcp_rtt_update pl;

	if (!ai_net_sample_take(AI_NET_SUB_TCP_RTT_UPDATE))
		return;
	pl.type = AI_NET_SUB_TCP_RTT_UPDATE;
	pl.srtt_us = srtt_us;
	pl.rttvar_us = rttvar_us;
	pl.rto_us = rto_us;
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TCP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_tcp_cwnd_update(u32 cwnd, u32 ssthresh,
						u16 cwnd_event)
{
	struct ai_net_pl_tcp_cwnd_update pl;

	if (!ai_net_sample_take(AI_NET_SUB_TCP_CWND_UPDATE))
		return;
	pl.type = AI_NET_SUB_TCP_CWND_UPDATE;
	pl.cwnd = cwnd;
	pl.ssthresh = ssthresh;
	pl.cwnd_event = cwnd_event;
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TCP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_tcp_congestion_state(u8 state,
						     const char *ca_name)
{
	struct ai_net_pl_tcp_congestion_state pl;

	if (!ai_net_sample_take(AI_NET_SUB_TCP_CONGESTION_STATE))
		return;
	pl.type = AI_NET_SUB_TCP_CONGESTION_STATE;
	pl.state = state;
	strscpy(pl.ca_name, ca_name ? ca_name : "?", sizeof(pl.ca_name));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TCP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_ip_route_lookup(u32 dst_ip, u32 oif, s32 result)
{
	struct ai_net_pl_ip_route_lookup pl;

	if (!ai_net_sample_take(AI_NET_SUB_IP_ROUTE_LOOKUP))
		return;
	pl.type = AI_NET_SUB_IP_ROUTE_LOOKUP;
	pl.dst_ip = dst_ip;
	pl.oif = oif;
	pl.result = result;
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_IP, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_tc_enqueue(const char *dev, const char *qname,
					   u32 bytes)
{
	struct ai_net_pl_tc pl;

	if (!ai_net_sample_take(AI_NET_SUB_TC_ENQUEUE))
		return;
	pl.type = AI_NET_SUB_TC_ENQUEUE;
	pl.bytes = bytes;
	pl.reason = 0;
	strscpy(pl.dev, dev ? dev : "?", sizeof(pl.dev));
	strscpy(pl.qdisc_name, qname ? qname : "?", sizeof(pl.qdisc_name));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TC, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_tc_dequeue(const char *dev, const char *qname,
					   u32 bytes)
{
	struct ai_net_pl_tc pl;

	if (!ai_net_sample_take(AI_NET_SUB_TC_DEQUEUE))
		return;
	pl.type = AI_NET_SUB_TC_DEQUEUE;
	pl.bytes = bytes;
	pl.reason = 0;
	strscpy(pl.dev, dev ? dev : "?", sizeof(pl.dev));
	strscpy(pl.qdisc_name, qname ? qname : "?", sizeof(pl.qdisc_name));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TC, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_tc_drop(const char *dev, const char *qname,
					s32 reason)
{
	struct ai_net_pl_tc pl;

	if (!ai_net_sample_take(AI_NET_SUB_TC_DROP))
		return;
	pl.type = AI_NET_SUB_TC_DROP;
	pl.bytes = 0;
	pl.reason = reason;
	strscpy(pl.dev, dev ? dev : "?", sizeof(pl.dev));
	strscpy(pl.qdisc_name, qname ? qname : "?", sizeof(pl.qdisc_name));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_TC, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_netdev_rx(const char *dev, u32 bytes)
{
	struct ai_net_pl_netdev pl;

	if (!ai_net_sample_take(AI_NET_SUB_NETDEV_RX))
		return;
	pl.type = AI_NET_SUB_NETDEV_RX;
	pl.cpu = raw_smp_processor_id();
	pl.bytes = bytes;
	pl.reason = 0;
	strscpy(pl.dev, dev ? dev : "?", sizeof(pl.dev));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETDEV, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_netdev_tx(const char *dev, u32 bytes)
{
	struct ai_net_pl_netdev pl;

	if (!ai_net_sample_take(AI_NET_SUB_NETDEV_TX))
		return;
	pl.type = AI_NET_SUB_NETDEV_TX;
	pl.cpu = raw_smp_processor_id();
	pl.bytes = bytes;
	pl.reason = 0;
	strscpy(pl.dev, dev ? dev : "?", sizeof(pl.dev));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETDEV, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_netdev_drop(const char *dev, u32 reason)
{
	struct ai_net_pl_netdev pl;

	if (!ai_net_sample_take(AI_NET_SUB_NETDEV_DROP))
		return;
	pl.type = AI_NET_SUB_NETDEV_DROP;
	pl.cpu = raw_smp_processor_id();
	pl.bytes = 0;
	pl.reason = reason;
	strscpy(pl.dev, dev ? dev : "?", sizeof(pl.dev));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETDEV, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_napi_poll(const char *dev, u32 budget,
					  u32 work_done)
{
	struct ai_net_pl_napi_poll pl;

	if (!ai_net_sample_take(AI_NET_SUB_NAPI_POLL))
		return;
	pl.type = AI_NET_SUB_NAPI_POLL;
	pl.budget = budget;
	pl.work_done = work_done;
	strscpy(pl.dev, dev ? dev : "?", sizeof(pl.dev));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETDEV, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_gro_receive(const char *dev, u32 result)
{
	struct ai_net_pl_gro pl;

	if (!ai_net_sample_take(AI_NET_SUB_GRO_RECEIVE))
		return;
	pl.type = AI_NET_SUB_GRO_RECEIVE;
	pl.result = result;
	strscpy(pl.dev, dev ? dev : "?", sizeof(pl.dev));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETDEV, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

static inline void ai_telemetry_gro_merge(const char *dev, u32 result)
{
	struct ai_net_pl_gro pl;

	if (!ai_net_sample_take(AI_NET_SUB_GRO_MERGE))
		return;
	pl.type = AI_NET_SUB_GRO_MERGE;
	pl.result = result;
	strscpy(pl.dev, dev ? dev : "?", sizeof(pl.dev));
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_NETDEV, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

/* ---- 复杂解析发射（ai_net.c 实现，调用点传 struct 指针） ---- */

void ai_telemetry_socket_close(struct socket *sock);
void ai_telemetry_socket_listen(struct socket *sock, int backlog);
void ai_telemetry_socket_accept(struct socket *listener, struct socket *newsock);
void ai_telemetry_socket_connect(struct sock *sk, u64 latency_us, int err);

/**
 * ai_net_sock_bytes_update() - 生命周期字节计数（socket_close 的 bytes_sent/recv 数据源）
 * @sk: socket
 * @sent: 本次发送字节增量
 * @recv: 本次接收字节增量
 *
 * 固定 64 槽小表（spinklock 保护，无分配）；__sock_sendmsg/__sock_recvmsg 每次调用。
 * 槽满/表满时静默忽略（遥测尽力而为，不阻塞数据面）。
 */
void ai_net_sock_bytes_update(struct sock *sk, u64 sent, u64 recv);

/**
 * ai_net_sock_bytes_take() - 读取并移除生命周期字节计数（close 语义）
 * @sk: socket
 * @sent: 输出累计发送字节
 * @recv: 输出累计接收字节
 *
 * 由 ai_telemetry_socket_close() 消费。
 */
void ai_net_sock_bytes_take(struct sock *sk, u64 *sent, u64 *recv);
void ai_telemetry_tcp_retransmit(struct sock *sk, struct sk_buff *skb, int err);
void ai_telemetry_tcp_abort(struct sock *sk, int err);
void ai_telemetry_tcp_packet_raw_tx(struct sock *sk, struct sk_buff *skb);
void ai_telemetry_tcp_packet_raw_rx(struct sock *sk, struct sk_buff *skb);
void ai_telemetry_udp_send(struct sock *sk, struct sk_buff *skb);
void ai_telemetry_udp_recv(struct sk_buff *skb);
void ai_telemetry_ip_packet(struct sk_buff *skb);
void ai_telemetry_nf_hook(struct sk_buff *skb,
			  const struct nf_hook_state *state,
			  unsigned int verdict);
void ai_telemetry_nf_conntrack_new(struct nf_conn *ct);
void ai_telemetry_nf_conntrack_destroy(struct nf_conn *ct);
void ai_telemetry_nf_nat(struct nf_conn *ct, const void *range,
			 unsigned int maniptype);
void ai_telemetry_xdp_rx(const struct xdp_buff *xdp, struct net_device *dev);
void ai_telemetry_dns_query(const char *name, size_t namelen,
			    const char *type, const char *result, int ret);
void ai_telemetry_neigh_new(struct neighbour *n);
void ai_telemetry_neigh_expire(struct neighbour *n);
void ai_net_http_tls_scan(struct sock *sk, struct sk_buff *skb,
			  u32 payload_off, bool is_tx);

#else /* !CONFIG_AIKERNEL_NET */

/*
 * ---- 空函数兜底：CONFIG_AIKERNEL_NET=n 时零开销零回归 ----
 * 注：本头文件在 n 配置下不被 net/ 埋点 include，以下 stub 为防御性兜底。
 */

struct sock;
struct socket;
struct sk_buff;
struct net_device;
struct nf_hook_state;
struct Qdisc;
struct neighbour;
struct napi_struct;
struct xdp_buff;
struct nf_conn;
struct ai_net_stats;

static inline bool ai_net_sample_take(u16 sub) { return false; }
static inline int ai_net_set_sub_rate(u16 sub, u32 rate) { return 0; /* AI_OK 宏实不存在（K10.4 实抓）——语义=0 */ }

static inline unsigned int ai_net_nf_hook(struct sk_buff *skb,
					  const struct nf_hook_state *state,
					  unsigned int verdict)
{
	return verdict;
}
static inline u8 ai_net_classify(struct sk_buff *skb) { return 0; }
static inline void ai_net_detect_anomaly(struct sk_buff *skb,
					 unsigned int verdict) { }
static inline void ai_net_stats_read(struct ai_net_stats *st) { }

static inline void ai_telemetry_socket_create(u16 family, u16 type,
					      u16 protocol) { }
static inline void ai_telemetry_socket_send(struct socket *sock, u32 bytes) { }
static inline void ai_telemetry_socket_recv(struct socket *sock, u32 bytes) { }
static inline void ai_telemetry_tcp_rtt_update(u32 srtt_us, u32 rttvar_us,
					       u32 rto_us) { }
static inline void ai_telemetry_tcp_cwnd_update(u32 cwnd, u32 ssthresh,
						u16 cwnd_event) { }
static inline void ai_telemetry_tcp_congestion_state(u8 state,
						     const char *ca_name) { }
static inline void ai_telemetry_ip_route_lookup(u32 dst_ip, u32 oif,
						s32 result) { }
static inline void ai_telemetry_tc_enqueue(const char *dev, const char *qname,
					   u32 bytes) { }
static inline void ai_telemetry_tc_dequeue(const char *dev, const char *qname,
					   u32 bytes) { }
static inline void ai_telemetry_tc_drop(const char *dev, const char *qname,
					s32 reason) { }
static inline void ai_telemetry_netdev_rx(const char *dev, u32 bytes) { }
static inline void ai_telemetry_netdev_tx(const char *dev, u32 bytes) { }
static inline void ai_telemetry_netdev_drop(const char *dev, u32 reason) { }
static inline void ai_telemetry_napi_poll(const char *dev, u32 budget,
					  u32 work_done) { }
static inline void ai_telemetry_gro_receive(const char *dev, u32 result) { }
static inline void ai_telemetry_gro_merge(const char *dev, u32 result) { }

static inline void ai_telemetry_socket_close(struct socket *sock) { }
static inline void ai_telemetry_socket_listen(struct socket *sock,
					      int backlog) { }
static inline void ai_telemetry_socket_accept(struct socket *listener,
					      struct socket *newsock) { }
static inline void ai_telemetry_socket_connect(struct sock *sk, u64 latency_us,
					       int err) { }
static inline void ai_net_sock_bytes_update(struct sock *sk, u64 sent,
					    u64 recv) { }
static inline void ai_net_sock_bytes_take(struct sock *sk, u64 *sent,
					  u64 *recv) { }
static inline void ai_telemetry_tcp_retransmit(struct sock *sk,
					       struct sk_buff *skb, int err) { }
static inline void ai_telemetry_tcp_abort(struct sock *sk, int err) { }
static inline void ai_telemetry_tcp_packet_raw_tx(struct sock *sk,
						  struct sk_buff *skb) { }
static inline void ai_telemetry_tcp_packet_raw_rx(struct sock *sk,
						  struct sk_buff *skb) { }
static inline void ai_telemetry_udp_send(struct sock *sk,
					 struct sk_buff *skb) { }
static inline void ai_telemetry_udp_recv(struct sk_buff *skb) { }
static inline void ai_telemetry_ip_packet(struct sk_buff *skb) { }
static inline void ai_telemetry_nf_hook(struct sk_buff *skb,
					const struct nf_hook_state *state,
					unsigned int verdict) { }
static inline void ai_telemetry_nf_conntrack_new(struct nf_conn *ct) { }
static inline void ai_telemetry_nf_conntrack_destroy(struct nf_conn *ct) { }
static inline void ai_telemetry_nf_nat(struct nf_conn *ct, const void *range,
				       unsigned int maniptype) { }
static inline void ai_telemetry_xdp_rx(const struct xdp_buff *xdp,
				       struct net_device *dev) { }
static inline void ai_telemetry_dns_query(const char *name, size_t namelen,
					  const char *type, const char *result,
					  int ret) { }
static inline void ai_telemetry_neigh_new(struct neighbour *n) { }
static inline void ai_telemetry_neigh_expire(struct neighbour *n) { }
static inline void ai_net_http_tls_scan(struct sock *sk, struct sk_buff *skb,
					u32 payload_off, bool is_tx) { }

#endif /* CONFIG_AIKERNEL_NET */

/* ---- TCP RTO min 访问器（net.rto 可控制参数；实现于 net/ipv4/tcp.c，
 *      CONFIG_AIKERNEL_RUNTIME 门控 —— vmscan.c swappiness 同范式） ----
 * ---- AI cwnd 钳制访问器（net.cwnd 可控制参数；实现于 ai_tcp_cca.c，
 *      真实作用于 ai_cca 拥塞控制管理的连接，0=不受限） ----
 * ---- netfilter 采集钩子（net.nftables 参数；实现于 ai_net.c：nft chain
 *      内核侧编程需模拟 netlink 事务无安全路径，语义如实为 AIKernel 自有
 *      netfilter LOCAL_OUT 采集钩子开关，真注册/真计数/真摘除） ---- */
#ifdef CONFIG_AIKERNEL_RUNTIME
int ai_tcp_rto_min_get(void);
int ai_tcp_rto_min_set(int ms);
#ifdef CONFIG_AIKERNEL_NET
u32 ai_cca_cwnd_clamp_get(void);
void ai_cca_cwnd_clamp_set(u32 pkts);
u64 ai_cca_clamp_hits_read(void);
bool ai_netfilter_is_enabled(void);
u64 ai_netfilter_stats_read(bool *on, u64 *pkts, u64 *bytes);
#else /* NET=n（base 片）：实现不编译，AI 侧访问器零值桩兜底
 * （K10.4 矩阵实抓；tcp_rto_min 实现于 net/ipv4/tcp.c 随
 *  RUNTIME 在，不在此列） */
static inline u32 ai_cca_cwnd_clamp_get(void)
{ return 0; }
static inline void ai_cca_cwnd_clamp_set(u32 pkts)
{ }
static inline u64 ai_cca_clamp_hits_read(void)
{ return 0; }
static inline bool ai_netfilter_is_enabled(void)
{ return false; }
static inline u64 ai_netfilter_stats_read(bool *on, u64 *pkts, u64 *bytes)
{ return 0; }
#endif /* CONFIG_AIKERNEL_NET */
#endif /* CONFIG_AIKERNEL_RUNTIME */

#endif /* _AIKERNEL_AI_NET_H */
