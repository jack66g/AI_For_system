// SPDX-License-Identifier: GPL-2.0
/*
 * ai_agent.c - AIKernel agent 角色注册表与配额准入（K3，KERNEL-K3-DESIGN §2）
 *
 * D1 静态槽注册表：身份空间=既有 enum ai_agent_id（uapi 冻结零改），
 * 槽 0-5=枚举直映、槽 6=OTHER(255)、槽 7 保留；全静态零 kmalloc
 * （kmemleak 天然干净）。绑定=AI_CMD_REG 追加 AGENT/CGROUP 属性：
 * 内核记 owner=NETLINK_CB portid，此后该 socket 的 ACT/ACT2/ACT_BATCH
 * 以绑定角色覆盖自报值；重复 REG=改绑（先解旧）；UNREG/URELEASE 解绑；
 * 记账保留至 reboot（D1 v1：解绑即槽回收=可再绑，计数不清）。
 *
 * D2 cgroup 关系：申报路径只读校验存在性（kern_path），不存在/空=
 * degraded 显式可见（该角色仅记账不限制——「静默不限制」是反模式）；
 * 路径仅用于记账展示与 limit_hit 审计上下文，不建/不删/不写任何
 * cgroupfs 节点（资源强制=cgroup v2 文件本身）。
 *
 * D3 配额准入（热路径零分配零阻塞）：
 *   - system(0) 旁路：出厂零绑定时一次 atomic 读即出；未绑定自报 0
 *     零查表直通（现网主控流量零开销）；
 *   - 绑定 socket：绑定角色覆盖自报（防 0 逃逸/借道 legacy ACT）；
 *     actions/win_used 计数+滚动窗限额（qlock 短临界区）；超额 →
 *     -EAGAIN + failures++ + limit_hit 遥测/事件，零 ring 写入（与
 *     blast 拒绝同语义：拒绝动作不落决策 ring，防风暴灌满）；
 *   - 未绑定自报非零：枚举白名单校验（越界 -EINVAL；OTHER=255 合法
 *     逃生舱如实记账），记 actions_total 但不耗配额窗（防投毒：他人
 *     窗计数不被未绑定流量消耗——win_used 只对绑定方递增）。
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/ai_netlink.h>
#include "ai_proc.h"
#include "ai_agent.h"
#include "../net/ai_netlink.h"

/* ---- 槽表（D1 结构原样：静态 8 槽） ---- */

#define AI_AGENT_NR		8	/* 静态槽总数（含 1 保留槽） */
#define AI_AGENT_ROLES		7	/* 有效角色：0-5=枚举直映，6=OTHER */
#define AI_AGENT_WIN_MS_DEF	60000	/* 滚动窗默认（sysfs 可调） */

struct ai_agent_slot {
	char  name[AI_AGENT_NAME_LEN];	/* enum 名（内置表） */
	bool  bound;			/* 有 socket 绑定 */
	u32   owner_portid;
	char  cgroup[AI_AGENT_CG_LEN];	/* 绑定时申报的 cgroup 路径（可空） */
	bool  degraded;			/* 无 cgroup/路径无效=仅记账不限制 */
	/* 配额（sysfs 可调） */
	u32   actions_per_win;		/* 0=不限（默认） */
	u32   win_ms;			/* 滚动窗（默认 60000） */
	/* 记账（atomic64，用法照 ai_hook_stats） */
	atomic64_t actions, cost_ns, failures;
	atomic64_t win_used;		/* 当前窗动作数（过窗重置） */
	u64   win_start_ns;
	struct mutex lock;		/* bind/unbind/配额写慢路径 */
	spinlock_t  qlock;		/* admit 快路径 */
};

static struct ai_agent_slot ai_agent_slots[AI_AGENT_NR];
static atomic_t ai_agent_bound_nr;	/* 绑定 socket 数（0=快路径） */

/* 槽 → enum ai_agent_id（内置；槽 7 保留不枚举） */
static const u32 ai_agent_slot_ids[AI_AGENT_NR] = {
	AI_AGENT_KERNEL, AI_AGENT_OCC_CLI, AI_AGENT_OCC_AI,
	AI_AGENT_AISTREAMD, AI_AGENT_APIC, AI_AGENT_TOOL,
	AI_AGENT_OTHER, AI_AGENT_KERNEL,
};

static const char * const ai_agent_slot_names[AI_AGENT_NR] = {
	"kernel", "occ_cli", "occ_ai", "aistreamd", "apic", "tool",
	"other", "",
};

/* enum id → 槽序（-1=白名单外；有效值={0..5,255}） */
static int ai_agent_slot_of(u32 agent_id)
{
	if (agent_id <= AI_AGENT_TOOL)
		return (int)agent_id;
	if (agent_id == AI_AGENT_OTHER)
		return AI_AGENT_ROLES - 1;
	return -1;
}

/* ---- D2：cgroup 路径只读校验 ---- */

/* 存在性校验（kern_path 只读；不建不删不写）。无 cgroup2 挂载/路径
 * 无效均返回 false → degraded=true 显式可见。 */
static bool ai_agent_cgroup_exists(const char *path)
{
	struct path p;

	if (!path || !path[0])
		return false;
	if (kern_path(path, LOOKUP_DIRECTORY, &p))
		return false;
	path_put(&p);
	return true;
}

/* ---- 绑定/解绑（慢路径，mutex） ---- */

void ai_agent_unbind(u32 portid)
{
	struct ai_agent_slot *s;
	int i;

	for (i = 0; i < AI_AGENT_ROLES; i++) {
		s = &ai_agent_slots[i];
		mutex_lock(&s->lock);
		if (s->bound && s->owner_portid == portid) {
			s->bound = false;
			s->owner_portid = 0;
			s->cgroup[0] = '\0';	/* 绑定期数据随绑定回收 */
			s->degraded = false;
			atomic_dec(&ai_agent_bound_nr);
			mutex_unlock(&s->lock);
			pr_info("AIKernel: agent '%s' unbound portid=%u "
				"(accounting kept)\n",
				s->name, portid);
			/* 无注册者=廉价空操作；NETLINK=n 为 stub */
			ai_netlink_push_event(AI_NL_EV_AGENT_UNBIND,
					      AI_NL_EV_SEV_INFO, portid,
					      (s32)ai_agent_slot_ids[i],
					      s->name);
			return;
		}
		mutex_unlock(&s->lock);
	}
}
EXPORT_SYMBOL_GPL(ai_agent_unbind);

int ai_agent_bind(u32 portid, u32 agent_id, const char *cgroup)
{
	struct ai_agent_slot *s;
	int slot;

	if (!portid)
		return -EINVAL;		/* portid 0=内核自身 */
	slot = ai_agent_slot_of(agent_id);
	if (slot < 0)
		return -EINVAL;		/* 白名单外（D1：越界 -EINVAL） */
	if (agent_id == AI_AGENT_KERNEL)
		return -EINVAL;		/* KERNEL=0 内核自身，不可绑（防 0 逃逸） */

	/* 改绑语义（D1）：先解本 socket 旧角色——无锁先行解旧，避免持
	 * 目标槽锁再取旧槽锁的跨槽锁序（解旧与占新之间的窗口内该角色
	 * 被他 socket 抢占 → -EBUSY 由客户端重试，罕见且诚实）。 */
	ai_agent_unbind(portid);

	s = &ai_agent_slots[slot];
	mutex_lock(&s->lock);
	if (s->bound) {
		mutex_unlock(&s->lock);
		return -EBUSY;		/* 一角色一 socket（他 socket 已占） */
	}
	s->bound = true;
	s->owner_portid = portid;
	if (cgroup && cgroup[0]) {
		strscpy(s->cgroup, cgroup, sizeof(s->cgroup));
		s->degraded = !ai_agent_cgroup_exists(s->cgroup);
	} else {
		s->cgroup[0] = '\0';
		s->degraded = false;
	}
	/* 新绑定=新配额窗（不复用旧绑定残留的 win_used/win_start） */
	spin_lock(&s->qlock);
	atomic64_set(&s->win_used, 0);
	s->win_start_ns = ktime_get_ns();
	spin_unlock(&s->qlock);
	mutex_unlock(&s->lock);
	atomic_inc(&ai_agent_bound_nr);

	pr_info("AIKernel: agent '%s' bound portid=%u cgroup=%s%s\n",
		s->name, portid, s->cgroup[0] ? s->cgroup : "(none)",
		s->degraded ? " (degraded: 记账only)" : "");
	ai_netlink_push_event(AI_NL_EV_AGENT_BIND, AI_NL_EV_SEV_INFO,
			      portid, (s32)agent_id, s->name);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_agent_bind);

/* ---- D3：配额准入（热路径） ---- */

/* 超限审计：既有 cgroup_limit_hit 遥测（resource="actions"，usage=拒绝
 * 时窗计数）+ AGENT_LIMIT 异步事件。qlock 外调用（遥测/推送内部有
 * skb 分配，持自旋锁非法）。 */
static void ai_agent_limit_hit(const struct ai_agent_slot *s, u32 limit,
			       u64 used)
{
	ai_telemetry_cgroup_limit_hit(s->cgroup[0] ? s->cgroup : NULL,
				      "actions", limit, used);
	ai_netlink_push_event(AI_NL_EV_AGENT_LIMIT, AI_NL_EV_SEV_WARN, 0,
			      -EAGAIN, s->name);
	pr_info_ratelimited("AIKernel: agent '%s' quota exceeded %llu/%u "
			    "(admit rejected -EAGAIN)\n",
			    s->name, used, limit);
}

int ai_agent_admit(struct sk_buff *skb, u32 msg_agent, u32 *role_out)
{
	struct ai_agent_slot *s = NULL;
	u32 portid = NETLINK_CB(skb).portid;
	u64 now, used;
	u32 limit, win_ms;
	int i;

	if (likely(!atomic_read(&ai_agent_bound_nr)))
		goto unbound;		/* 出厂零绑定：免扫描 */

	/* 绑定扫描（静态槽线性扫；bound/owner_portid 对齐字读，与
	 * bind/unbind 慢路径的临界窗内存在极小撕裂——错归不错计，v1
	 * 口径同 D4 proc 快照；bind/unbind 为 REG 级低频操作） */
	for (i = 0; i < AI_AGENT_ROLES; i++) {
		if (READ_ONCE(ai_agent_slots[i].bound) &&
		    READ_ONCE(ai_agent_slots[i].owner_portid) == portid) {
			s = &ai_agent_slots[i];
			break;
		}
	}
	if (!s)
		goto unbound;

	/* 绑定 socket：绑定角色覆盖自报值（D1：防 0 逃逸/借道 legacy
	 * ACT 旁路；自报值不再校验——角色以绑定为准） */
	if (role_out)
		*role_out = ai_agent_slot_ids[i];
	limit = READ_ONCE(s->actions_per_win);
	win_ms = READ_ONCE(s->win_ms);
	/* 0=不限（默认）；win_ms=0=不滚窗（等效不限）；degraded=仅记账 */
	if (!limit || !win_ms || READ_ONCE(s->degraded)) {
		atomic64_inc(&s->actions);
		return 0;
	}
	spin_lock(&s->qlock);
	now = ktime_get_ns();
	if (now - s->win_start_ns >= (u64)win_ms * NSEC_PER_MSEC) {
		s->win_start_ns = now;		/* 过窗重置 */
		atomic64_set(&s->win_used, 0);
	}
	used = atomic64_read(&s->win_used);
	if (used >= limit) {
		spin_unlock(&s->qlock);
		atomic64_inc(&s->failures);
		ai_agent_limit_hit(s, limit, used);
		return -EAGAIN;
	}
	atomic64_set(&s->win_used, used + 1);
	spin_unlock(&s->qlock);
	atomic64_inc(&s->actions);
	return 0;

unbound:
	if (msg_agent == AI_AGENT_KERNEL) {
		/* system(0) 快速旁路：零查表直通零记账（现网主控流量） */
		if (role_out)
			*role_out = AI_AGENT_KERNEL;
		return 0;
	}
	i = ai_agent_slot_of(msg_agent);
	if (i < 0)
		return -EINVAL;		/* 枚举白名单外（越界 -EINVAL） */
	if (role_out)
		*role_out = msg_agent;
	/* 未绑定自报非零：记 actions_total（诚实）但不耗配额窗（D1 分离
	 * 计数，防未绑定流量投毒绑定方配额） */
	atomic64_inc(&ai_agent_slots[i].actions);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_agent_admit);

void ai_agent_note_cost(u32 agent_id, u64 cost_ns)
{
	int slot = ai_agent_slot_of(agent_id);

	if (slot < 0 || !cost_ns)
		return;
	atomic64_add(cost_ns, &ai_agent_slots[slot].cost_ns);
}
EXPORT_SYMBOL_GPL(ai_agent_note_cost);

/* ---- 视图/枚举/配额（procfs/sysfs/测试数据源） ---- */

int ai_agent_view_get(unsigned int index, struct ai_agent_view *out)
{
	const struct ai_agent_slot *s;

	if (!out || index >= AI_AGENT_ROLES)
		return -ENOENT;
	s = &ai_agent_slots[index];
	memset(out, 0, sizeof(*out));
	out->id = ai_agent_slot_ids[index];
	strscpy(out->name, s->name, sizeof(out->name));
	out->bound = s->bound ? 1 : 0;
	out->degraded = s->degraded ? 1 : 0;
	out->actions_per_win = READ_ONCE(s->actions_per_win);
	out->win_ms = READ_ONCE(s->win_ms);
	out->actions = atomic64_read(&s->actions);
	out->cost_ns = atomic64_read(&s->cost_ns);
	out->failures = atomic64_read(&s->failures);
	out->win_used = atomic64_read(&s->win_used);
	strscpy(out->cgroup, s->cgroup, sizeof(out->cgroup));
	return 0;
}
EXPORT_SYMBOL_GPL(ai_agent_view_get);

int ai_agent_enumerate(unsigned int index, u32 *agent_id, const char **name)
{
	if (index >= AI_AGENT_ROLES)
		return -ENOENT;
	if (agent_id)
		*agent_id = ai_agent_slot_ids[index];
	if (name)
		*name = ai_agent_slot_names[index];
	return 0;
}
EXPORT_SYMBOL_GPL(ai_agent_enumerate);

static struct ai_agent_slot *ai_agent_slot_mutable(u32 agent_id)
{
	int slot = ai_agent_slot_of(agent_id);

	if (slot < 0)
		return NULL;
	return &ai_agent_slots[slot];
}

int ai_agent_quota_get(u32 agent_id, u32 *actions_per_win, u32 *win_ms)
{
	struct ai_agent_slot *s = ai_agent_slot_mutable(agent_id);

	if (!s)
		return -ENOENT;
	if (actions_per_win)
		*actions_per_win = READ_ONCE(s->actions_per_win);
	if (win_ms)
		*win_ms = READ_ONCE(s->win_ms);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_agent_quota_get);

int ai_agent_set_actions_per_win(u32 agent_id, u32 val)
{
	struct ai_agent_slot *s = ai_agent_slot_mutable(agent_id);

	if (!s)
		return -EINVAL;
	mutex_lock(&s->lock);
	WRITE_ONCE(s->actions_per_win, val);	/* 调小立即生效拦新动作 */
	mutex_unlock(&s->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_agent_set_actions_per_win);

int ai_agent_set_win_ms(u32 agent_id, u32 val)
{
	struct ai_agent_slot *s = ai_agent_slot_mutable(agent_id);

	if (!s)
		return -EINVAL;
	mutex_lock(&s->lock);
	WRITE_ONCE(s->win_ms, val);
	mutex_unlock(&s->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_agent_set_win_ms);

/* ---- 初始化 + KUnit 钩子 ---- */

static int __init ai_agent_init(void)
{
	struct ai_agent_slot *s;
	int i;

	for (i = 0; i < AI_AGENT_NR; i++) {
		s = &ai_agent_slots[i];
		strscpy(s->name, ai_agent_slot_names[i], sizeof(s->name));
		s->win_ms = AI_AGENT_WIN_MS_DEF;
		mutex_init(&s->lock);
		spin_lock_init(&s->qlock);
	}
	return 0;
}
subsys_initcall(ai_agent_init);

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/* KUnit 钩子：槽表复位（锁序同 bind：mutex → qlock；仅清运行态，
 * 内置名/锁保持 init 状态） */
void ai_agent_test_reset(void)
{
	struct ai_agent_slot *s;
	int i;

	for (i = 0; i < AI_AGENT_ROLES; i++) {
		s = &ai_agent_slots[i];
		mutex_lock(&s->lock);
		s->bound = false;
		s->owner_portid = 0;
		s->cgroup[0] = '\0';
		s->degraded = false;
		s->actions_per_win = 0;
		s->win_ms = AI_AGENT_WIN_MS_DEF;
		spin_lock(&s->qlock);
		atomic64_set(&s->actions, 0);
		atomic64_set(&s->cost_ns, 0);
		atomic64_set(&s->failures, 0);
		atomic64_set(&s->win_used, 0);
		s->win_start_ns = 0;
		spin_unlock(&s->qlock);
		mutex_unlock(&s->lock);
	}
	atomic_set(&ai_agent_bound_nr, 0);
}
#endif /* CONFIG_AIKERNEL_KUNIT_TEST */
