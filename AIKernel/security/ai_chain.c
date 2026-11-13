// SPDX-License-Identifier: GPL-2.0
/*
 * ai_chain.c - K8 审计链核心：append-only xxh64 哈希链 + 锚 + 窗口验证
 *
 * 设计册 KERNEL-K8-DESIGN.md §2：
 *   D1 独立 72B 节点流（决策记录 183B 冻约；NEW/OUTCOME 事件对覆盖
 *      ring 条目 outcome 回填可变性）；
 *   D2 xxh64（lib/xxhash，CONFIG_XXHASH）+ 用户态 sha256 锚文件；
 *   D3 出入口 /proc/ai/audit + /sys/kernel/ai/chain/ 子树（本文件只提供
 *      数据面，procfs/sysfs 挂接在 ai_procfs.c/ai_sysfs.c）；
 *   D4 惰性 genesis：首个 append 先铸 GENESIS（prev = seed 值或 0，
 *      data={boot_cookie}）——跨 boot 续链经 seed sysfs；
 *   D5 满覆盖最旧 + evicted 计数（链保持前进；内核 verify 只证窗口
 *      内 seq 连续 + 哈希链接，首存活节点 prev 为窗口锚点）。
 *
 * 锁纪律：ai_chain_lock 为叶级锁——持锁内不调用任何其他 AI 子系统
 * 函数；所有发射点（ai_policy/ai_agent/ai_model/ai_audit/ai_lsm）一律
 * 忽略返回值（fire-and-forget，链永不阻断业务路径）。
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/xxhash.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/init.h>

#include "ai_chain.h"

static struct ai_chain_node ai_chain_ring[AI_CHAIN_RING_NODES];
static DEFINE_SPINLOCK(ai_chain_lock);

static u64  ai_chain_head_seq;		/* 末节点 seq；0=空链 */
static u64  ai_chain_head_hash;		/* 末节点 self_hash */
static u64  ai_chain_boot_cookie;	/* genesis 后非 0 */
static u64  ai_chain_seeded_val;
static bool ai_chain_seeded;
static u64  ai_chain_evicted;
static u64  ai_chain_anchor_count;
static u64  ai_chain_last_anchor_seq;	/* 0=尚无 anchor */
static u32  ai_chain_anchor_epoch;
static u32  ai_chain_since_anchor;	/* 距上个 anchor 的普通节点数 */
static u32  ai_chain_period = AI_CHAIN_DEFAULT_PERIOD;
static bool ai_chain_enabled = true;

/*
 * D4 续链种子引导期入口：aichain.seed=<hex>（early_param，先于任何
 * 首节点——boot 期决策早于串口 shell，sysfs 入口在真机时序上不可达，
 * k8v 干跑实证；rig/部署以此从 boot 参数携带上一 boot 锚值续链。
 * sysfs seed 保留：空链窗（极早期无参启动）与负断言用）。
 */
static int __init ai_chain_seed_cmdline(char *str)
{
	u64 v;

	if (!str)
		return -EINVAL;
	if (kstrtou64(str, 16, &v) == 0) {
		ai_chain_seeded = true;
		ai_chain_seeded_val = v;
		pr_info("AIKernel: chain seed from cmdline %016llx\n", v);
	}
	return 0;
}
early_param("aichain.seed", ai_chain_seed_cmdline);

_Static_assert(sizeof(struct ai_chain_node) == 72, "ai_chain_node 72B 冻约");
_Static_assert(sizeof(struct ai_chain_ev_decision_new) <= AI_CHAIN_NODE_DATA,
	       "decision_new fits");
_Static_assert(sizeof(struct ai_chain_ev_decision_outcome) <= AI_CHAIN_NODE_DATA,
	       "decision_outcome fits");
_Static_assert(sizeof(struct ai_chain_ev_rollback) <= AI_CHAIN_NODE_DATA,
	       "rollback fits");
_Static_assert(sizeof(struct ai_chain_ev_agent_reject) <= AI_CHAIN_NODE_DATA,
	       "agent_reject fits");
_Static_assert(sizeof(struct ai_chain_ev_model) <= AI_CHAIN_NODE_DATA,
	       "model fits");
_Static_assert(sizeof(struct ai_chain_ev_key) <= AI_CHAIN_NODE_DATA,
	       "key fits");
_Static_assert(sizeof(struct ai_chain_ev_seccomp) <= AI_CHAIN_NODE_DATA,
	       "seccomp fits");
_Static_assert(sizeof(struct ai_chain_ev_anomaly) <= AI_CHAIN_NODE_DATA,
	       "anomaly fits");
_Static_assert(sizeof(struct ai_chain_ev_anchor) <= AI_CHAIN_NODE_DATA,
	       "anchor fits");

/* self_hash = xxh64(整 72B 且 self_hash 字段清零)；节点定长 packed，
 * 端序即本机端序（导出面 hex 行按字节序转储，aikctl 同口径解码） */
static u64 ai_chain_hash_node(const struct ai_chain_node *n)
{
	struct ai_chain_node tmp = *n;

	tmp.self_hash = 0;
	return xxh64(&tmp, sizeof(tmp), AI_CHAIN_XXH_SEED);
}

static struct ai_chain_node *ai_chain_slot(u64 seq)
{
	return &ai_chain_ring[(seq - 1) % AI_CHAIN_RING_NODES];
}

static u64 ai_chain_first_seq_nolock(void)
{
	if (ai_chain_head_seq <= AI_CHAIN_RING_NODES)
		return ai_chain_head_seq ? 1 : 0;
	return ai_chain_head_seq - AI_CHAIN_RING_NODES + 1;
}

/* 铸一个节点（须持锁）。seq 恒为 head+1；空链先落 GENESIS。 */
static int ai_chain_emit_locked(u16 kind, u16 flags,
				const void *data, u16 len)
{
	struct ai_chain_node *n;
	u64 seq, ts;

	if (len > AI_CHAIN_NODE_DATA || kind >= AI_CHAIN_KIND_NR)
		return -EINVAL;

	/* D4 惰性 genesis：首节点先铸（含 seed 续链值） */
	if (!ai_chain_head_seq) {
		struct ai_chain_node *g = &ai_chain_ring[0];
		u64 cookie = get_random_u64();

		memset(g, 0, sizeof(*g));
		g->seq = 1;
		g->ts_ns = ktime_get_ns();
		g->prev_hash = ai_chain_seeded ? ai_chain_seeded_val : 0;
		g->pid = current ? current->pid : 0;
		g->kind = AI_CHAIN_KIND_GENESIS;
		memcpy(g->data, &cookie, sizeof(cookie));
		g->self_hash = ai_chain_hash_node(g);
		ai_chain_head_seq = 1;
		ai_chain_head_hash = g->self_hash;
		ai_chain_boot_cookie = cookie;
	}

	seq = ai_chain_head_seq + 1;
	ts = ktime_get_ns();
	if (seq > AI_CHAIN_RING_NODES)
		ai_chain_evicted++;	/* 覆盖最旧（链保持前进） */

	n = ai_chain_slot(seq);
	memset(n, 0, sizeof(*n));
	n->seq = seq;
	n->ts_ns = ts;
	n->prev_hash = ai_chain_head_hash;
	n->pid = current ? current->pid : 0;
	n->kind = kind;
	n->flags = flags;
	if (data && len)
		memcpy(n->data, data, len);
	n->self_hash = ai_chain_hash_node(n);

	ai_chain_head_seq = seq;
	ai_chain_head_hash = n->self_hash;
	return (int)seq;
}

/* 周期锚（须持锁）：window_first_seq = 上个锚（或 genesis）之后首 seq */
static int ai_chain_anchor_locked(void)
{
	struct ai_chain_ev_anchor ev = {
		.nodes_total = ai_chain_head_seq,
		.window_first_seq = ai_chain_last_anchor_seq + 1,
		.epoch = ++ai_chain_anchor_epoch,
	};
	int rc = ai_chain_emit_locked(AI_CHAIN_KIND_ANCHOR,
				      AI_CHAIN_FLAG_ANCHOR, &ev, sizeof(ev));

	if (rc > 0) {
		ai_chain_anchor_count++;
		ai_chain_last_anchor_seq = ai_chain_head_seq;
		ai_chain_since_anchor = 0;
	}
	return rc;
}

int ai_chain_append(u16 kind, const void *data, u16 len)
{
	unsigned long flags;
	int rc = 0;

	if (!READ_ONCE(ai_chain_enabled))
		return 0;

	spin_lock_irqsave(&ai_chain_lock, flags);
	rc = ai_chain_emit_locked(kind, 0, data, len);
	if (rc > 0 && kind != AI_CHAIN_KIND_ANCHOR) {
		ai_chain_since_anchor++;
		if (ai_chain_since_anchor >= READ_ONCE(ai_chain_period))
			ai_chain_anchor_locked();
	}
	spin_unlock_irqrestore(&ai_chain_lock, flags);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_chain_append);

int ai_chain_anchor_now(void)
{
	unsigned long flags;
	int rc;

	if (!READ_ONCE(ai_chain_enabled))
		return 0;
	spin_lock_irqsave(&ai_chain_lock, flags);
	rc = ai_chain_anchor_locked();
	spin_unlock_irqrestore(&ai_chain_lock, flags);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_chain_anchor_now);

/* 续链种子：仅空链收（genesis 未铸）；非空 -EBUSY（防事后改史） */
int ai_chain_seed(u64 anchor_hash)
{
	unsigned long flags;

	spin_lock_irqsave(&ai_chain_lock, flags);
	if (ai_chain_head_seq) {
		spin_unlock_irqrestore(&ai_chain_lock, flags);
		return -EBUSY;
	}
	ai_chain_seeded = true;
	ai_chain_seeded_val = anchor_hash;
	spin_unlock_irqrestore(&ai_chain_lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_chain_seed);

/*
 * 窗口验证：从首存活节点重算到 head。
 *   - 逐节点：seq 字段==期望值（防移位/断档）、self_hash 重算吻合、
 *     prev_hash==前节点 self_hash（首存活节点 prev 为窗口锚点，免验）；
 *   - 失配/断档：-EIO 且 *bad_seq=期望 seq（篡改定位到条）。
 */
int ai_chain_verify(u64 *bad_seq)
{
	unsigned long flags;
	u64 s, first, prev = 0;
	int rc = 0;

	spin_lock_irqsave(&ai_chain_lock, flags);
	if (!ai_chain_head_seq) {
		spin_unlock_irqrestore(&ai_chain_lock, flags);
		return -ENODATA;
	}
	first = ai_chain_first_seq_nolock();
	for (s = first; s <= ai_chain_head_seq && rc == 0; s++) {
		const struct ai_chain_node *n = ai_chain_slot(s);

		if (n->seq != s || n->self_hash != ai_chain_hash_node(n) ||
		    (s > first && n->prev_hash != prev)) {
			if (bad_seq)
				*bad_seq = s;
			rc = -EIO;
			break;
		}
		prev = n->self_hash;
	}
	spin_unlock_irqrestore(&ai_chain_lock, flags);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_chain_verify);

int ai_chain_node_copy(u64 seq, struct ai_chain_node *out)
{
	unsigned long flags;
	u64 first;
	int rc = -ENOENT;

	if (!out)
		return -EINVAL;
	spin_lock_irqsave(&ai_chain_lock, flags);
	first = ai_chain_first_seq_nolock();
	if (seq >= first && seq <= ai_chain_head_seq) {
		*out = *ai_chain_slot(seq);
		rc = 0;
	}
	spin_unlock_irqrestore(&ai_chain_lock, flags);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_chain_node_copy);

void ai_chain_stats_read(struct ai_chain_stats *out)
{
	unsigned long flags;

	if (!out)
		return;
	spin_lock_irqsave(&ai_chain_lock, flags);
	out->nodes = ai_chain_head_seq;
	out->evicted = ai_chain_evicted;
	out->anchors = ai_chain_anchor_count;
	out->head_hash = ai_chain_head_hash;
	out->first_seq = ai_chain_first_seq_nolock();
	out->period = ai_chain_period;
	out->seeded_val = ai_chain_seeded ? ai_chain_seeded_val : 0;
	out->seeded = ai_chain_seeded;
	out->enabled = READ_ONCE(ai_chain_enabled);
	out->boot_cookie = ai_chain_boot_cookie;
	spin_unlock_irqrestore(&ai_chain_lock, flags);
}
EXPORT_SYMBOL_GPL(ai_chain_stats_read);

int ai_chain_enable_set(bool on)
{
	WRITE_ONCE(ai_chain_enabled, on);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_chain_enable_set);

bool ai_chain_enable_read(void)
{
	return READ_ONCE(ai_chain_enabled);
}
EXPORT_SYMBOL_GPL(ai_chain_enable_read);

/* 周期 sysfs 写入口（ai_sysfs.c 调；min 钳制） */
int ai_chain_period_set(u32 period)
{
	unsigned long flags;

	if (period < AI_CHAIN_MIN_PERIOD)
		return -EINVAL;
	spin_lock_irqsave(&ai_chain_lock, flags);
	ai_chain_period = period;
	spin_unlock_irqrestore(&ai_chain_lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_chain_period_set);

/* ---- sec 钩便捷发射器（ai_lsm.c；EXPERIMENTAL 门内钩体调用） ---- */

void ai_chain_key_event(const char *type, const char *desc,
			size_t plen, u8 strength)
{
	struct ai_chain_ev_key ev = {};

	strscpy(ev.type, type ? type : "?", sizeof(ev.type));
	ev.desc_hash = desc ? xxh64(desc, strlen(desc), AI_CHAIN_XXH_SEED) : 0;
	ev.plen = (u32)min_t(size_t, plen, U32_MAX);
	ev.strength = strength;
	ai_chain_append(AI_CHAIN_KIND_KEY_EVENT, &ev, sizeof(ev));
}
EXPORT_SYMBOL_GPL(ai_chain_key_event);

void ai_chain_seccomp_anomaly(int syscall_nr, u32 score)
{
	struct ai_chain_ev_seccomp ev = {
		.syscall_nr = syscall_nr,
		.score = score,
	};

	ai_chain_append(AI_CHAIN_KIND_SECCOMP_ANOMALY, &ev, sizeof(ev));
}
EXPORT_SYMBOL_GPL(ai_chain_seccomp_anomaly);

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/*
 * KUnit 专用：链全量复位（真机活 boot 与生产 wiring 共存——每例开头
 * 复位隔离）；篡改注入（field：0=data 1=self_hash 2=prev_hash 3=seq）。
 */
void ai_chain_test_reset(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ai_chain_lock, flags);
	memset(ai_chain_ring, 0, sizeof(ai_chain_ring));
	ai_chain_head_seq = 0;
	ai_chain_head_hash = 0;
	ai_chain_boot_cookie = 0;
	ai_chain_seeded = false;
	ai_chain_seeded_val = 0;
	ai_chain_evicted = 0;
	ai_chain_anchor_count = 0;
	ai_chain_last_anchor_seq = 0;
	ai_chain_anchor_epoch = 0;
	ai_chain_since_anchor = 0;
	ai_chain_enabled = true;
	spin_unlock_irqrestore(&ai_chain_lock, flags);
}

int ai_chain_test_tamper(u64 seq, u32 field)
{
	unsigned long flags;
	struct ai_chain_node *n;

	spin_lock_irqsave(&ai_chain_lock, flags);
	if (seq < ai_chain_first_seq_nolock() || seq > ai_chain_head_seq) {
		spin_unlock_irqrestore(&ai_chain_lock, flags);
		return -ENOENT;
	}
	n = ai_chain_slot(seq);
	switch (field) {
	case 0:
		n->data[0] ^= 0x5a;
		break;
	case 1:
		n->self_hash ^= 1;
		break;
	case 2:
		n->prev_hash ^= 1;
		break;
	case 3:
		n->seq ^= 1;
		break;
	default:
		spin_unlock_irqrestore(&ai_chain_lock, flags);
		return -EINVAL;
	}
	spin_unlock_irqrestore(&ai_chain_lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_chain_test_tamper);
#endif	/* CONFIG_AIKERNEL_KUNIT_TEST */
