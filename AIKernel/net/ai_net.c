// SPDX-License-Identifier: GPL-2.0
/*
 * ai_net.c - AIKernel 网络核心（Prompt 06）
 *
 * A 轨：AI 网络决策框架（流量分类/攻击检测/参数建议）+ 9 个 Hook 空实现 + CCA 咨询点
 *       （ai_net_rtt/nf/xdp/qdisc/neigh/napi/backlog/gro/conntrack/cong/cong_ssthresh_hook，
 *       空实现 = 原样放行，不改变内核默认行为）；
 * B 轨：第4类 10 子类 26 事件发射（复杂解析在这里做，简单事件为 ai_net.h static inline）
 *       + 子事件采样门控（ai_net_sample_take，per-CPU 无锁；分级策略见设计文档 2.4 定稿）
 *       + socket 生命周期字节计数表（socket_close 的 bytes_sent/recv 数据源）。
 *
 * 性能：全部发射 sample_take 前置判定（不通过零开销）+ emit_direct 直写（<100ns 无锁）；
 * 中断上下文安全（无锁、无分配、不睡眠；skb 内容经 skb_copy_bits/skb_header_pointer 只读）。
 * 门控 CONFIG_AIKERNEL_NET；n 配置下本文件不参与构建。
 *
 * 拆分说明：本文件为拆分后的 A 轨核心（原 ai_net.c 1141 行）：采样门控 +
 * Hook/决策框架 + socket 字节表 + init。B 轨拆至 ai_net_telemetry.c（复杂
 * 解析发射）与 ai_net_scan.c（HTTP/TLS 内容识别）；模块内部共享符号见
 * ai_net_internal.h；对外接口 ai_net.h 不变。
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
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/net_namespace.h>
#include <linux/rtnetlink.h>
#endif
#if IS_ENABLED(CONFIG_NETFILTER)
#include <linux/netfilter_ipv4.h>
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

/*
 * ---- 子事件采样门控 ----
 * 分级策略定稿（设计文档 2.4）：
 *   全量（rate=1）：socket 生命周期、tcp_retransmit/abort/congestion_state、
 *     nf_conntrack_new/destroy、nf_nat、tc_drop、netdev_drop、neigh_expire、dns_query；
 *   采样（rate=N）：tcp_rtt/cwnd=1/16、udp=1/64、ip_packet=1/128、ip_route=1/256、
 *     nf_hook=1/256、xdp_rx=1/256、tc_enqueue/dequeue=1/128、netdev_rx/tx=1/256、
 *     napi_poll=1/64、gro=1/256、neigh_new=1/16、http=1/64、tls=1/16；
 *   关（默认 off）：tcp_packet_raw（payload 采样，受 ai_net_payload_sampling 参数门控，
 *     打开后按 1/256 采样，内容零脱敏）。
 */

static u32 ai_net_sub_rates[AI_NET_SUB_MAX] = {
	[AI_NET_SUB_SOCKET_CREATE]	= 1,
	[AI_NET_SUB_SOCKET_CLOSE]	= 1,
	[AI_NET_SUB_SOCKET_LISTEN]	= 1,
	[AI_NET_SUB_SOCKET_ACCEPT]	= 1,
	[AI_NET_SUB_SOCKET_CONNECT]	= 1,
	[AI_NET_SUB_SOCKET_SEND]	= 1,
	[AI_NET_SUB_SOCKET_RECV]	= 1,
	[AI_NET_SUB_TCP_RETRANSMIT]	= 1,
	[AI_NET_SUB_TCP_RTT_UPDATE]	= 16,
	[AI_NET_SUB_TCP_CWND_UPDATE]	= 16,
	[AI_NET_SUB_TCP_CONGESTION_STATE] = 1,
	[AI_NET_SUB_TCP_ABORT]		= 1,
	[AI_NET_SUB_TCP_PACKET_RAW]	= 256,
	[AI_NET_SUB_UDP_SEND]		= 64,
	[AI_NET_SUB_UDP_RECV]		= 64,
	[AI_NET_SUB_IP_PACKET]		= 128,
	[AI_NET_SUB_IP_ROUTE_LOOKUP]	= 256,
	[AI_NET_SUB_NF_HOOK]		= 256,
	[AI_NET_SUB_NF_CONNTRACK_NEW]	= 1,
	[AI_NET_SUB_NF_CONNTRACK_DESTROY] = 1,
	[AI_NET_SUB_NF_NAT]		= 1,
	[AI_NET_SUB_XDP_RX]		= 256,
	[AI_NET_SUB_TC_ENQUEUE]		= 128,
	[AI_NET_SUB_TC_DEQUEUE]		= 128,
	[AI_NET_SUB_TC_DROP]		= 1,
	[AI_NET_SUB_DNS_QUERY]		= 1,
	[AI_NET_SUB_HTTP_REQUEST]	= 64,
	[AI_NET_SUB_TLS_HANDSHAKE]	= 16,
	[AI_NET_SUB_NETDEV_RX]		= 256,
	[AI_NET_SUB_NETDEV_TX]		= 256,
	[AI_NET_SUB_NETDEV_DROP]	= 1,
	[AI_NET_SUB_NAPI_POLL]		= 64,
	[AI_NET_SUB_GRO_RECEIVE]	= 256,
	[AI_NET_SUB_GRO_MERGE]		= 128,
	[AI_NET_SUB_NEIGH_NEW]		= 16,
	[AI_NET_SUB_NEIGH_EXPIRE]	= 1,
};

static DEFINE_PER_CPU(u32, ai_net_sub_cnt[AI_NET_SUB_MAX]);

/*
 * payload 采样开关（/sys/module/ai_net/parameters/ai_net_payload_sampling）。
 * 默认 0=关闭（防海量数据淹没 ring buffer）；1=打开（tcp_packet_raw 按 1/256 采样，
 * 内容零脱敏）。测试后必须还原为 0。
 */
int ai_net_payload_sampling;
module_param(ai_net_payload_sampling, int, 0644);
MODULE_PARM_DESC(ai_net_payload_sampling,
		 "0=payload sampling off (default), 1=on (tcp_packet_raw, zero-desensitized)");

bool ai_net_sample_take(u16 sub)
{
	u32 rate;

	if (sub >= AI_NET_SUB_MAX)
		return false;
	if (sub == AI_NET_SUB_TCP_PACKET_RAW &&
	    !READ_ONCE(ai_net_payload_sampling))
		return false;
	rate = READ_ONCE(ai_net_sub_rates[sub]);
	if (rate <= 1)
		return rate == 1;
	{
		u32 *cnt = this_cpu_ptr(ai_net_sub_cnt);

		cnt[sub]++;
		return (cnt[sub] % rate) == 1;
	}
}
EXPORT_SYMBOL_GPL(ai_net_sample_take);

int ai_net_set_sub_rate(u16 sub, u32 rate)
{
	if (sub >= AI_NET_SUB_MAX)
		return AI_ERR_INVALID_ARG;
	WRITE_ONCE(ai_net_sub_rates[sub], rate);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_net_set_sub_rate);

/*
 * ---- 决策计数 / 异常检测统计（per-CPU，无锁） ----
 */

static DEFINE_PER_CPU(u64, ai_net_hook_cnt[11]);
static DEFINE_PER_CPU(u64, ai_net_classify_cnt);
static DEFINE_PER_CPU(u64, ai_net_anom_syn);
static DEFINE_PER_CPU(u64, ai_net_anom_retrans);
static DEFINE_PER_CPU(u64, ai_net_anom_samples);

/*
 * ---- A 轨：Hook 空实现（原样放行） + 决策框架占位 ----
 */

void ai_net_rtt_hook(struct sock *sk, long mrtt_us,
		     u32 *srtt_us, u32 *mdev_us, u32 *rttvar_us)
{
	this_cpu_inc(ai_net_hook_cnt[0]);
}
EXPORT_SYMBOL_GPL(ai_net_rtt_hook);

unsigned int ai_net_nf_hook(struct sk_buff *skb,
			    const struct nf_hook_state *state,
			    unsigned int verdict)
{
	this_cpu_inc(ai_net_hook_cnt[1]);
	ai_net_detect_anomaly(skb, verdict);
	return verdict;
}
EXPORT_SYMBOL_GPL(ai_net_nf_hook);

bool ai_net_xdp_hook(struct net_device *dev, struct xdp_buff *xdp)
{
	this_cpu_inc(ai_net_hook_cnt[2]);
	return true;
}
EXPORT_SYMBOL_GPL(ai_net_xdp_hook);

void ai_net_qdisc_hook(struct net_device *dev, struct Qdisc *sch)
{
	this_cpu_inc(ai_net_hook_cnt[3]);
}
EXPORT_SYMBOL_GPL(ai_net_qdisc_hook);

void ai_net_neigh_hook(struct neighbour *n, bool *refresh)
{
	this_cpu_inc(ai_net_hook_cnt[4]);
}
EXPORT_SYMBOL_GPL(ai_net_neigh_hook);

void ai_net_napi_hook(struct napi_struct *n, int *weight)
{
	this_cpu_inc(ai_net_hook_cnt[5]);
}
EXPORT_SYMBOL_GPL(ai_net_napi_hook);

void ai_net_backlog_hook(struct socket *sock, int *backlog)
{
	this_cpu_inc(ai_net_hook_cnt[6]);
}
EXPORT_SYMBOL_GPL(ai_net_backlog_hook);

void ai_net_gro_hook(struct sk_buff *skb, gro_result_t *ret)
{
	this_cpu_inc(ai_net_hook_cnt[7]);
}
EXPORT_SYMBOL_GPL(ai_net_gro_hook);

void ai_net_conntrack_hook(struct nf_conn *ct, unsigned int ct_count)
{
	this_cpu_inc(ai_net_hook_cnt[8]);
}
EXPORT_SYMBOL_GPL(ai_net_conntrack_hook);

void ai_net_cong_hook(struct sock *sk, u32 *cwnd_inc)
{
	this_cpu_inc(ai_net_hook_cnt[9]);
}
EXPORT_SYMBOL_GPL(ai_net_cong_hook);

void ai_net_cong_ssthresh_hook(struct sock *sk, u32 *ssthresh)
{
	this_cpu_inc(ai_net_hook_cnt[10]);
}
EXPORT_SYMBOL_GPL(ai_net_cong_ssthresh_hook);

u8 ai_net_classify(struct sk_buff *skb)
{
	u8 cls = 0;

	this_cpu_inc(ai_net_classify_cnt);
#ifdef CONFIG_INET
	if (!skb || skb->protocol != htons(ETH_P_IP) ||
	    !skb_network_header_len(skb))
		return 0;
	switch (ip_hdr(skb)->protocol) {
	case IPPROTO_TCP:
		cls = 1;
		break;
	case IPPROTO_UDP:
		cls = 2;
		break;
	case IPPROTO_ICMP:
		cls = 3;
		break;
	}
#endif
	return cls;
}
EXPORT_SYMBOL_GPL(ai_net_classify);

void ai_net_detect_anomaly(struct sk_buff *skb, unsigned int verdict)
{
#ifdef CONFIG_INET
	const struct iphdr *iph;
	struct tcphdr th;

	if (!skb || !skb_network_header_len(skb))
		return;
	this_cpu_inc(ai_net_anom_samples);
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return;
	if (skb_header_pointer(skb, skb_network_header_len(skb), sizeof(th),
			       &th)) {
		if (th.syn && !th.ack) {
			this_cpu_inc(ai_net_anom_syn);
		} else if (th.rst) {
			this_cpu_inc(ai_net_anom_retrans);
		}
	}
#endif
}
EXPORT_SYMBOL_GPL(ai_net_detect_anomaly);

void ai_net_stats_read(struct ai_net_stats *st)
{
	int cpu, i;

	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		u64 *cnt = per_cpu_ptr(ai_net_hook_cnt, cpu);

		for (i = 0; i < 11; i++)
			st->hook_calls[i] += cnt[i];
		st->classify_calls += per_cpu(ai_net_classify_cnt, cpu);
		st->anomaly_syn_pkts += per_cpu(ai_net_anom_syn, cpu);
		st->anomaly_retrans_pkts += per_cpu(ai_net_anom_retrans, cpu);
		st->anomaly_samples += per_cpu(ai_net_anom_samples, cpu);
	}
}
EXPORT_SYMBOL_GPL(ai_net_stats_read);

/*
 * ---- socket 生命周期字节计数（close 事件 bytes_sent/bytes_recv 数据源） ----
 * 固定 64 槽表：send/recv 收敛点累加，close 时读取并移除。
 */

#define AI_NET_SOCK_TBL_MAX	64

struct ai_net_sock_ent {
	struct sock *sk;
	u64 sent, recv;
};

static struct ai_net_sock_ent ai_net_sock_tbl[AI_NET_SOCK_TBL_MAX];
static DEFINE_SPINLOCK(ai_net_sock_lock);

void ai_net_sock_bytes_update(struct sock *sk, u64 sent, u64 recv)
{
	struct ai_net_sock_ent *free = NULL;
	unsigned long flags;
	int i;

	if (!sk || (!sent && !recv))
		return;
	spin_lock_irqsave(&ai_net_sock_lock, flags);
	for (i = 0; i < AI_NET_SOCK_TBL_MAX; i++) {
		if (ai_net_sock_tbl[i].sk == sk) {
			ai_net_sock_tbl[i].sent += sent;
			ai_net_sock_tbl[i].recv += recv;
			goto out;
		}
		if (!ai_net_sock_tbl[i].sk && !free)
			free = &ai_net_sock_tbl[i];
	}
	if (free) {
		free->sk = sk;
		free->sent = sent;
		free->recv = recv;
	}
out:
	spin_unlock_irqrestore(&ai_net_sock_lock, flags);
}
EXPORT_SYMBOL_GPL(ai_net_sock_bytes_update);

void ai_net_sock_bytes_take(struct sock *sk, u64 *sent, u64 *recv)
{
	unsigned long flags;
	int i;

	if (sent)
		*sent = 0;
	if (recv)
		*recv = 0;
	if (!sk)
		return;
	spin_lock_irqsave(&ai_net_sock_lock, flags);
	for (i = 0; i < AI_NET_SOCK_TBL_MAX; i++) {
		if (ai_net_sock_tbl[i].sk == sk) {
			if (sent)
				*sent = ai_net_sock_tbl[i].sent;
			if (recv)
				*recv = ai_net_sock_tbl[i].recv;
			memset(&ai_net_sock_tbl[i], 0,
			       sizeof(ai_net_sock_tbl[i]));
			break;
		}
	}
	spin_unlock_irqrestore(&ai_net_sock_lock, flags);
}
EXPORT_SYMBOL_GPL(ai_net_sock_bytes_take);


/* ---- net.rto 立即生效参数（经 net/ipv4/tcp.c 门控访问器） ----
 * value 单位毫秒（1~10000），写 init_net.ipv4.sysctl_tcp_rto_min_us
 * （微秒，作用于 init_net 内新建 TCP 连接的 RTO 下限）；
 * CONFIG_INET=n 时本函数剔除，注册退回接口预留。 */
#ifdef CONFIG_INET
static int ai_net_rto_apply(struct ai_control_param *p, s32 pid,
			    s64 value, s64 *eff)
{
	int cur;

	if (value < 1 || value > 10000)
		return AI_ERR_INVALID_ARG;
	cur = ai_tcp_rto_min_get();
	ai_tcp_rto_min_set((int)value);
	if (eff)
		*eff = value;
	pr_info("AIKernel: tcp rto_min %d us -> %lld ms (pid=%d)\n",
		cur, value, pid);
	return AI_OK;
}
#endif /* CONFIG_INET */   /* rto apply（上文）配对：原锚替换时补回 */

/* ---- net.cwnd 立即生效参数（ai_cca 拥塞窗口上限钳制） ----
 * value=包数（1..4096），经 ai_tcp_cca.c 钳制访问器真实作用于 ai_cca
 * 管理的全部连接（cong_avoid 出口 + ssthresh 上限）。 */
#ifdef CONFIG_INET
static int ai_net_cwnd_apply(struct ai_control_param *p, s32 pid,
			     s64 value, s64 *eff)
{
	if (value < 1 || value > 4096)
		return AI_ERR_INVALID_ARG;
	ai_cca_cwnd_clamp_set((u32)value);
	*eff = value;
	pr_info("AIKernel: net.cwnd clamp -> %lld pkts (ai_cca)\n", value);
	return AI_OK;
}

#endif /* CONFIG_INET */


/* ---- net.qdisc 运行时 graft（w21 接线） ----
 * 值域 0=回滚快照 kind（无快照 no-op）/1=codel/2=fq/3=fq_codel。
 * 历史教训（2026-09-29，~/w1k-evidence/07_qdisc.txt）：ACT 执行上下文直接
 * dev_graft_qdisc 使 guest 网络栈整体冻结（rtnl/qdisc 锁冲突）。本次：
 *   - apply 回调（netlink ACT 上下文）只写 pending + queue_work，绝不持 rtnl；
 *   - 独立 singlethread workqueue 持 rtnl 后按 sch_api.c
 *     qdisc_graft(parent=NULL) 标准序列换根（create→deactivate→per-txq
 *     graft→dev->qdisc→activate，全部 EXPORT 符号）。
 * 作用范围：init_net 内 IFF_UP 非回环且 num_tx_queues==1 的设备；多队列
 * 设备诚实跳过（mq leaf graft 超本次语义边界）。首目标设备 root kind 快照，
 * 值 0 按快照 kind 经白名单重建回滚（pfifo_fast/noqueue/codel/fq/fq_codel）。
 * dryrun（KUnit 护栏）：apply 正常钳制/提交/current 更新但不调度 worker。 */
#if IS_ENABLED(CONFIG_NET_SCHED) && defined(CONFIG_INET)
#include <linux/workqueue.h>
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>

extern struct Qdisc_ops codel_qdisc_ops;
extern struct Qdisc_ops fq_qdisc_ops;
extern struct Qdisc_ops fq_codel_qdisc_ops;

#define AI_QDISC_NONE 0xFFu

static u8 ai_qdisc_pending = AI_QDISC_NONE;
static bool ai_qdisc_dryrun;
static s32 ai_qdisc_last_err;
static char ai_qdisc_saved_kind[32];
static bool ai_qdisc_saved_valid;
static DEFINE_MUTEX(ai_qdisc_lock);
static struct workqueue_struct *ai_qdisc_wq;
static struct work_struct ai_qdisc_work;

/* 值→qdisc ops（各 sch_*.c 去 static 后全局可见；CONFIG 缺失返回 NULL） */
static const struct Qdisc_ops *ai_qdisc_ops_for(s64 value)
{
	switch (value) {
	case 1:
#ifdef CONFIG_NET_SCH_CODEL
		return &codel_qdisc_ops;
#else
		return NULL;
#endif
	case 2:
#ifdef CONFIG_NET_SCH_FQ
		return &fq_qdisc_ops;
#else
		return NULL;
#endif
	case 3:
#ifdef CONFIG_NET_SCH_FQ_CODEL
		return &fq_codel_qdisc_ops;
#else
		return NULL;
#endif
	default:
		return NULL;
	}
}

/* 快照 kind→ops（回滚白名单；未收录 kind 返回 NULL=诚实失败不 graft） */
static const struct Qdisc_ops *ai_qdisc_ops_for_kind(const char *kind)
{
	if (!kind || !kind[0])
		return NULL;
	if (!strcmp(kind, "pfifo_fast"))
		return &pfifo_fast_ops;
	if (!strcmp(kind, "noqueue"))
		return &noqueue_qdisc_ops;
	if (!strcmp(kind, "codel")) {
#ifdef CONFIG_NET_SCH_CODEL
		return &codel_qdisc_ops;
#else
		return NULL;
#endif
	}
	if (!strcmp(kind, "fq")) {
#ifdef CONFIG_NET_SCH_FQ
		return &fq_qdisc_ops;
#else
		return NULL;
#endif
	}
	if (!strcmp(kind, "fq_codel")) {
#ifdef CONFIG_NET_SCH_FQ_CODEL
		return &fq_codel_qdisc_ops;
#else
		return NULL;
#endif
	}
	return NULL;
}

/* 换根单个设备（调用方持 rtnl；单队列已由遍历守卫保证） */
static int ai_qdisc_graft_dev(struct net_device *dev,
			      const struct Qdisc_ops *ops)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);
	struct Qdisc *newq, *old;

	newq = qdisc_create_dflt(txq, ops, TC_H_ROOT, NULL);
	if (!newq)
		return -EINVAL;

	if (dev->flags & IFF_UP)
		dev_deactivate(dev);

	old = dev_graft_qdisc(txq, newq);
	if (old)
		qdisc_put(old);

	old = rtnl_dereference(dev->qdisc);
	qdisc_refcount_inc(newq);
	rcu_assign_pointer(dev->qdisc, newq);
	if (old)
		qdisc_put(old);

	if (dev->flags & IFF_UP)
		dev_activate(dev);
	return 0;
}

static void ai_qdisc_work_fn(struct work_struct *w)
{
	u8 mode = xchg(&ai_qdisc_pending, AI_QDISC_NONE);
	struct net_device *dev;
	int grafted = 0, skipped_mq = 0, failed = 0;
	const struct Qdisc_ops *ops;

	mutex_lock(&ai_qdisc_lock);
	if (mode == AI_QDISC_NONE || mode > 3) {
		mutex_unlock(&ai_qdisc_lock);
		return;
	}

	rtnl_lock();
	for_each_netdev(&init_net, dev) {
		if ((dev->flags & IFF_LOOPBACK) || !(dev->flags & IFF_UP))
			continue;
		if (dev->num_tx_queues != 1) {
			skipped_mq++;
			continue;
		}
		if (mode != 0 && !ai_qdisc_saved_valid) {
			struct Qdisc *root = rtnl_dereference(dev->qdisc);

			strscpy(ai_qdisc_saved_kind,
				root && root->ops ? root->ops->id : "unknown",
				sizeof(ai_qdisc_saved_kind));
			ai_qdisc_saved_valid = true;
			pr_info("AIKernel: net.qdisc snapshot kind=%s (%s)\n",
				ai_qdisc_saved_kind, dev->name);
		}
		if (mode == 0) {
			if (!ai_qdisc_saved_valid)
				continue; /* 无快照：回滚 no-op（诚实） */
			ops = ai_qdisc_ops_for_kind(ai_qdisc_saved_kind);
			if (!ops) {
				pr_warn("AIKernel: net.qdisc rollback kind=%s not in whitelist\n",
					ai_qdisc_saved_kind);
				failed++;
				continue;
			}
		} else {
			ops = ai_qdisc_ops_for(mode);
		}
		if (ai_qdisc_graft_dev(dev, ops) == 0)
			grafted++;
		else
			failed++;
	}
	rtnl_unlock();
	WRITE_ONCE(ai_qdisc_last_err, failed ? -1 : 0);
	pr_info("AIKernel: net.qdisc mode=%u done (grafted=%d skipped_mq=%d failed=%d)\n",
		mode, grafted, skipped_mq, failed);
	mutex_unlock(&ai_qdisc_lock);
}

void ai_net_qdisc_dryrun_set(bool on)
{
	WRITE_ONCE(ai_qdisc_dryrun, on);
}
EXPORT_SYMBOL_GPL(ai_net_qdisc_dryrun_set);

u8 ai_net_qdisc_pending_get(void)
{
	return READ_ONCE(ai_qdisc_pending);
}
EXPORT_SYMBOL_GPL(ai_net_qdisc_pending_get);

static int ai_net_qdisc_apply(struct ai_control_param *p, s32 pid,
			      s64 value, s64 *eff)
{
	if (value < 0 || value > 3)
		return AI_ERR_INVALID_ARG;
	if (!ai_qdisc_wq)
		return AI_ERR_DISABLED;
	WRITE_ONCE(ai_qdisc_pending, (u8)value);
	if (!READ_ONCE(ai_qdisc_dryrun))
		queue_work(ai_qdisc_wq, &ai_qdisc_work);
	*eff = value;
	pr_info("AIKernel: net.qdisc request mode=%lld (pid=%d%s)\n",
		value, pid, READ_ONCE(ai_qdisc_dryrun) ? ", dryrun" : "");
	return AI_OK;
}
#endif /* CONFIG_NET_SCHED && CONFIG_INET */


#if IS_ENABLED(CONFIG_NETFILTER)
/* ---- net.nftables 开关（AIKernel 自有 netfilter LOCAL_OUT 采集钩子） ----
 * 语义如实（不虚标 nft chain）：nft chain 内核侧编程需模拟 netlink
 * 事务操作 nf_tables 私有数据结构、超出安全边界；本开关真实注册/摘除
 * AIKernel 自有 LOCAL_OUT 采集钩子（真计数、真生效），规则下发接口
 * 语义由主控侧文案如实描述。 */
#include <linux/mutex.h>

static DEFINE_PER_CPU(u64, ai_nf_pkts);
static DEFINE_PER_CPU(u64, ai_nf_bytes);
static bool ai_nf_enabled;
static DEFINE_MUTEX(ai_nf_lock);

static unsigned int ai_nf_local_out_hook(void *priv, struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	this_cpu_inc(ai_nf_pkts);
	this_cpu_add(ai_nf_bytes, skb->len);
	return NF_ACCEPT;
}

static struct nf_hook_ops ai_nf_hook_ops __read_mostly = {
	.hook		= ai_nf_local_out_hook,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP_PRI_FILTER + 25,
};

bool ai_netfilter_is_enabled(void)
{
	return READ_ONCE(ai_nf_enabled);
}
EXPORT_SYMBOL_GPL(ai_netfilter_is_enabled);

u64 ai_netfilter_stats_read(bool *on, u64 *pkts, u64 *bytes)
{
	u64 np = 0, nb = 0;
	int c;

	for_each_possible_cpu(c) {
		np += per_cpu(ai_nf_pkts, c);
		nb += per_cpu(ai_nf_bytes, c);
	}
	if (on)
		*on = READ_ONCE(ai_nf_enabled);
	if (pkts)
		*pkts = np;
	if (bytes)
		*bytes = nb;
	return np;
}
EXPORT_SYMBOL_GPL(ai_netfilter_stats_read);

static int ai_net_nftables_apply(struct ai_control_param *p, s32 pid,
				 s64 value, s64 *eff)
{
	int rc = 0;

	if (value != 0 && value != 1)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_nf_lock);
	if (value == 1 && !ai_nf_enabled) {
		rc = nf_register_net_hook(&init_net, &ai_nf_hook_ops);
		if (!rc)
			ai_nf_enabled = true;
	} else if (value == 0 && ai_nf_enabled) {
		nf_unregister_net_hook(&init_net, &ai_nf_hook_ops);
		ai_nf_enabled = false;
	}
	mutex_unlock(&ai_nf_lock);
	if (rc)
		return AI_ERR_GENERIC;
	*eff = value;
	pr_info("AIKernel: net.nftables %lld (AIKernel netfilter %s)\n",
		value, value ? "registered" : "unregistered");
	return AI_OK;
}
#endif /* CONFIG_NETFILTER */


/*
 * ---- init ----
 */

static int __init ai_net_init(void)
{
	/* 可控制参数表（数据计划 20.3 网络域）：net.cwnd（ai_cca 钳制）、
	 * net.rto（tcp.c 门控访问器）、net.qdisc（运行时 graft）、
	 * net.nftables（AIKernel 自有 netfilter 采集钩子开关，语义如实） */
#ifdef CONFIG_INET
	ai_control_register("net.cwnd", AI_POLICY_DOMAIN_NET,
			    AI_CTRL_F_REAL, 1, 4096, 256, ai_net_cwnd_apply);
	ai_control_register("net.rto", AI_POLICY_DOMAIN_NET, AI_CTRL_F_REAL,
			    1, 10000, 200, ai_net_rto_apply);
#else
	ai_control_register("net.cwnd", AI_POLICY_DOMAIN_NET, 0,
			    1, 4096, 256, NULL);
	ai_control_register("net.rto", AI_POLICY_DOMAIN_NET, 0,
			    1, 10000, 200, NULL);
#endif
	/* net.qdisc 运行时 graft（w21 接线）：值域 0=回滚/1=codel/2=fq/
	 * 3=fq_codel；apply 回调只提交 pending+queue_work（ACT 上下文不持
	 * rtnl——2026-09-29 直接 graft 冻结网络栈的教训），真换根在独立
	 * ai_qdisc_wq worker。wq 分配失败则诚实退回 [reserved]。 */
#if IS_ENABLED(CONFIG_NET_SCHED) && defined(CONFIG_INET)
	ai_qdisc_wq = create_singlethread_workqueue("ai_qdisc_wq");
	if (ai_qdisc_wq) {
		INIT_WORK(&ai_qdisc_work, ai_qdisc_work_fn);
		ai_control_register("net.qdisc", AI_POLICY_DOMAIN_NET,
				    AI_CTRL_F_REAL, 0, 3, 0,
				    ai_net_qdisc_apply);
	} else {
		pr_warn("AIKernel: net.qdisc workqueue alloc failed; kept reserved\n");
		ai_control_register("net.qdisc", AI_POLICY_DOMAIN_NET, 0,
				    0, 3, 0, NULL);
	}
#else
	ai_control_register("net.qdisc", AI_POLICY_DOMAIN_NET, 0,
			    0, 3, 0, NULL);
#endif

#if IS_ENABLED(CONFIG_NETFILTER)
	ai_control_register("net.nftables", AI_POLICY_DOMAIN_NET,
			    AI_CTRL_F_REAL, 0, 1, 0, ai_net_nftables_apply);
#else
	ai_control_register("net.nftables", AI_POLICY_DOMAIN_NET, 0,
			    0, 1, 0, NULL);
#endif

	pr_info("AIKernel: net subsystem ready (AI hooks + telemetry)\n");
	return 0;
}
late_initcall(ai_net_init);
