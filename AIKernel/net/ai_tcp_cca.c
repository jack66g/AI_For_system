// SPDX-License-Identifier: GPL-2.0
/*
 * ai_tcp_cca.c - AI TCP 拥塞控制算法（注册名 ai_cca，Prompt 06 模块5 任务 5.2）
 *
 * 本步基础版 = reno 族语义（AIMD）：慢启动走 tcp_slow_start，拥塞避免每窗口 +1
 * （增量经 ai_net_cong_hook 咨询，空实现不改 → 与 reno 行为一致族）；
 * ssthresh 丢包折半（ai_net_cong_ssthresh_hook 咨询）；undo_cwnd/min_cwnd 用 reno 语义。
 *
 * 零回归：CONFIG_AIKERNEL_NET=n 时本文件不参与构建 → 不注册 → 系统默认 CCA 仍为
 * CONFIG_DEFAULT_CUBIC（cubic）。仅当用户显式
 * `echo ai_cca > /proc/sys/net/ipv4/tcp_congestion_control` 才生效；
 * 测试后必须 `echo cubic` 还原。
 *
 * 必需 ops（tcp_validate_congestion_control 强制）：ssthresh / undo_cwnd / cong_avoid 齐全。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <net/tcp.h>
#include "../core/ai_types.h"
#include "ai_net.h"

/* ==================================================================
 * AI cwnd 上限钳制（net.cwnd 可控制参数，value=包数，0=不受限）
 * 真实作用于 ai_cca 管理的全部连接：cong_avoid 出口钳制发送窗口、
 * ssthresh 上限钳制；钳制命中计数供观测面（/sys/kernel/ai/stats/
 * ai_actions）与 ss -ti 实测。per-CPU 计数（调度/TC 热路径无锁）。
 * ================================================================== */
static u32 ai_cca_cwnd_clamp;   /* 0 = 不受限（默认） */
static DEFINE_PER_CPU(u64, ai_cca_clamp_hits);

u32 ai_cca_cwnd_clamp_get(void)
{
	return READ_ONCE(ai_cca_cwnd_clamp);
}
EXPORT_SYMBOL_GPL(ai_cca_cwnd_clamp_get);

void ai_cca_cwnd_clamp_set(u32 pkts)
{
	WRITE_ONCE(ai_cca_cwnd_clamp, pkts);
}
EXPORT_SYMBOL_GPL(ai_cca_cwnd_clamp_set);

u64 ai_cca_clamp_hits_read(void)
{
	u64 sum = 0;
	int c;

	for_each_possible_cpu(c)
		sum += per_cpu(ai_cca_clamp_hits, c);
	return sum;
}
EXPORT_SYMBOL_GPL(ai_cca_clamp_hits_read);

/**
 * tcp_ai_cong_avoid() - AI 拥塞避免
 *
 * 慢启动：tcp_slow_start 指数增窗；拥塞避免：分数 AIMD（同 tcp_cong_avoid_ai 语义），
 * 每窗口增窗量默认 1，先经 ai_net_cong_hook 咨询（AI 可调整增窗节奏）。
 */
static void tcp_ai_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 inc = 1;
	u32 cwnd;

	if (!tcp_is_cwnd_limited(sk))
		return;

	cwnd = tcp_snd_cwnd(tp);
	if (cwnd <= tp->snd_ssthresh) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			goto clamp_out;
	}

	ai_net_cong_hook(sk, &inc);
	if (!inc)
		inc = 1;
	if (inc > tcp_snd_cwnd(tp))
		inc = tcp_snd_cwnd(tp);

	if (tp->snd_cwnd_cnt >= tcp_snd_cwnd(tp)) {
		tp->snd_cwnd_cnt = 0;
		WRITE_ONCE(tp->snd_cwnd, tcp_snd_cwnd(tp) + inc);
	} else {
		tp->snd_cwnd_cnt += acked;
		if (tp->snd_cwnd_cnt >= tcp_snd_cwnd(tp)) {
			u32 delta = tp->snd_cwnd_cnt / tcp_snd_cwnd(tp);

			tp->snd_cwnd_cnt -= delta * tcp_snd_cwnd(tp);
			WRITE_ONCE(tp->snd_cwnd, tcp_snd_cwnd(tp) + delta * inc);
		}
	}

clamp_out:
	/* net.cwnd 钳制出口：真实限制本连接发送窗口 */
	cwnd = READ_ONCE(ai_cca_cwnd_clamp);
	if (cwnd && tcp_snd_cwnd(tp) > cwnd) {
		WRITE_ONCE(tp->snd_cwnd, cwnd);
		this_cpu_inc(ai_cca_clamp_hits);
	}
}

/**
 * tcp_ai_ssthresh() - 丢包后的慢启动阈值（reno 语义折半，AI 可调整）
 */
static u32 tcp_ai_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 ssthresh = max(tcp_snd_cwnd(tp) >> 1U, 2U);
	u32 clamp = READ_ONCE(ai_cca_cwnd_clamp);

	ai_net_cong_ssthresh_hook(sk, &ssthresh);
	if (clamp)
		ssthresh = min(ssthresh, clamp);
	return max(ssthresh, 2U);
}

/**
 * tcp_ai_undo_cwnd() - 撤销窗口（reno 语义）
 */
static u32 tcp_ai_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return max(tcp_snd_cwnd(tp), tp->prior_cwnd);
}

static struct tcp_congestion_ops tcp_ai_congestion_ops __read_mostly = {
	.name		= "ai_cca",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_ai_ssthresh,
	.undo_cwnd	= tcp_ai_undo_cwnd,
	.cong_avoid	= tcp_ai_cong_avoid,
	.flags		= TCP_CONG_NON_RESTRICTED,
};

static int __init ai_tcp_cca_init(void)
{
	int err;

	err = tcp_register_congestion_control(&tcp_ai_congestion_ops);
	if (err) {
		pr_err("AIKernel: ai_cca registration failed (%d)\n", err);
		return err;
	}
	pr_info("AIKernel: ai_cca TCP congestion control registered\n");
	return 0;
}
late_initcall(ai_tcp_cca_init);
