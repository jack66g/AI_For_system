// SPDX-License-Identifier: GPL-2.0
/*
 * ai_effect.h - AIKernel 效果归因环（K4.0）
 *
 * 每个 AI 注入动作开一个「效果窗口」，窗口结算后把 outcome 回填到
 * 决策 ring，形成 注入 → 效果 → 归因 的闭环：
 *   - 开窗：挂点消费侧确认生效（ai_decision_note_effect）→
 *     ai_effect_open()；
 *   - 绑定：决策 ring 铸记录（ai_policy_record_heuristic）→
 *     ai_effect_bind() 把 decision_id 绑到该挂点最近 pending 窗；
 *   - 结算：结算器（后续挂点波的真实观测点）调 ai_effect_close()
 *     关窗 + ai_policy_fill_outcome() 回填 ring + per-hook
 *     good/bad/timeout 累计；1Hz tick（ai_sched 采样 kthread 尾部）
 *     对到窗长未结算的窗按 timeout 兜底关窗回填。
 *
 * 并发/上下文安全：写侧=钩子原子上下文（rq 锁内），开窗只做字段写
 * +时间戳（WRITE_ONCE 语义），零分配零睡眠零自旋；per-hook 单槽
 * pending，竞态容忍=最后写赢（窗口本身即采样近似）。结算/tick 路径
 * 才触碰 policy ring 锁（进程上下文）。
 */

#ifndef _AIKERNEL_AI_EFFECT_H
#define _AIKERNEL_AI_EFFECT_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include "ai_decision.h"   /* enum ai_hook_id / AI_HOOK_NR */

/* ---- 结算 outcome（效果窗口语义；写入 ring 的 outcome 字段） ----
 * 与 AI_OUTCOME_*（ai_policy.h）共用 u8 值域：good=1 对齐 SUCCESS、
 * bad=2 对齐 PARTIAL、timeout=3 对齐 FAILED（效果环独立常量，语义
 * 由本层定义，ring 侧只存不解释）。 */
#define AI_EFFECT_OUTCOME_NONE     0   /* 未结算（开窗在途） */
#define AI_EFFECT_OUTCOME_GOOD     1   /* 效果正向 */
#define AI_EFFECT_OUTCOME_BAD      2   /* 效果负向 */
#define AI_EFFECT_OUTCOME_TIMEOUT  3   /* 到期未结算（tick 兜底关窗） */

/* ---- per-hook 效果窗口时长（秒；0=纯事件/即时窗，tick 不超时结算） ----
 * OOM badness 偏置存活观察期长；vruntime 平移下一放置周期即可观测；
 * wakeup 抢占提示为近即时事件（K4.3：窗长 1s——1 秒未被抢回必然没有
 * 误抢占，tick 兜底按 GOOD 结算）；readahead 看后续缺页；
 * reclaim 扫描优先级即时生效。 */
#define AI_EFFECT_WIN_SEC_OOM        60
#define AI_EFFECT_WIN_SEC_VRUNTIME    2
#define AI_EFFECT_WIN_SEC_WAKEUP      1
#define AI_EFFECT_WIN_SEC_READAHEAD   5
#define AI_EFFECT_WIN_SEC_RECLAIM     0

/* ---- per-hook 单槽 pending 效果窗（写侧原子上下文：纯字段写） ---- */

struct ai_effect_win {
	u32  decision_id;   /* 绑定的决策 ring 记录 id（0=未绑定） */
	u64  open_ns;       /* 开窗时刻（note_effect） */
	u64  close_ns;      /* 关窗时刻（结算/超时；0=在途） */
	long aux0;          /* 开窗观测（挂点自定义，与决策记录 data[2] 同源） */
	long aux1;
	u8   outcome;       /* AI_EFFECT_OUTCOME_*（结算时写入） */
	long metric;        /* 结算量化（mispreempt 等语义由结算器定义） */
	u8   used;          /* 1=窗口在途（open 已发布） */
};

/* ---- per-hook 结算累计（decision/stats 扩展列数据源） ---- */

struct ai_effect_stats {
	atomic64_t good;        /* outcome=GOOD 结算次数 */
	atomic64_t bad;         /* outcome=BAD 结算次数 */
	atomic64_t timeout;     /* outcome=TIMEOUT 结算次数 */
	long last_metric;       /* 最近一次结算量化值 */
};

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_effect_open() - 开效果窗（note_effect 内调；原子上下文安全）
 * @hook: 挂点 ID
 * @aux0/aux1: 生效观测（与决策记录 decision_data[2..3] 同源）
 *
 * 单槽语义：新窗直接覆盖旧窗（未结算的旧窗被放弃，不计数）。
 * 必须先于本挂点的 record_heuristic 调用——绑定语义是「最近
 * pending 窗」，开窗在后会让绑定落到已关闭的旧窗上。
 */
void ai_effect_open(enum ai_hook_id hook, long aux0, long aux1);

/**
 * ai_effect_bind() - 绑定 decision_id 到该挂点最近 pending 窗
 * @hook: 挂点 ID
 * @decision_id: 决策 ring 记录 id（record_heuristic 铸完 id 后调）
 *
 * 无在途窗（used=0）时丢弃；重复绑定最后写赢。
 */
void ai_effect_bind(enum ai_hook_id hook, u32 decision_id);

/**
 * ai_effect_close() - 关窗结算（结算器调）
 * @hook: 挂点 ID
 * @outcome: AI_EFFECT_OUTCOME_GOOD/BAD（TIMEOUT 留给 tick 兜底）
 * @metric: 结算量化（语义由结算器定义，本层只存只转发）
 *
 * 关窗 + 绑定记录回填 ring（ai_policy_fill_outcome，被覆盖=静默） +
 * good/bad 计数 + last_metric。无在途窗时幂等空转。
 */
void ai_effect_close(enum ai_hook_id hook, u8 outcome, long metric);

/**
 * ai_effect_win_peek() - 读在途窗快照（K4 结算器观测用）
 * @hook: 挂点 ID
 * @out: 输出快照（可 NULL=仅探测在途）
 *
 * 有在途窗（used=1）→ 拷贝当前字段返回 true；否则 false。无锁近似
 * 一致快照（结算器观测面语义，与 stats_get 同级撕裂容忍）。
 */
bool ai_effect_win_peek(enum ai_hook_id hook, struct ai_effect_win *out);

/**
 * ai_effect_tick() - 1Hz 兜底结算（ai_sched 采样 kthread 尾部调）
 *
 * 各窗到 per-hook 窗长仍未结算 → 按到期 outcome 关窗回填：默认
 * TIMEOUT；per-hook 覆盖表例外（K4.1 OOM 60s 无 re-OOM=偏置方向
 * 正确→GOOD、K4.3 wakeup 1s 未被抢回=无误抢占→GOOD，见
 * ai_effect.c 的 ai_effect_tick_outcome）。窗口时长 0 的纯事件窗
 * 永不超时。
 */
void ai_effect_tick(void);

/**
 * ai_effect_stats_get() - 读取 per-hook 结算累计快照
 * @out: 输出数组（AI_HOOK_NR 个元素；无锁近似一致，观测面用）
 */
void ai_effect_stats_get(struct ai_effect_stats out[AI_HOOK_NR]);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline void ai_effect_open(enum ai_hook_id hook, long a0, long a1)
{
}
static inline void ai_effect_bind(enum ai_hook_id hook, u32 decision_id)
{
}
static inline void ai_effect_close(enum ai_hook_id hook, u8 outcome, long m)
{
}

static inline bool ai_effect_win_peek(enum ai_hook_id hook,
				      struct ai_effect_win *out)
{
	return false;
}
static inline void ai_effect_tick(void)
{
}
static inline void ai_effect_stats_get(struct ai_effect_stats out[AI_HOOK_NR])
{
	if (out)
		memset(out, 0, sizeof(*out) * AI_HOOK_NR);
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/* K4.0 测试面（ai_effect_test.c / ai_decision_test.c）：直读窗口槽
 * （断言字段/测试内回拨 open_ns 强制超时）与整体复位；纯测试钩子，
 * 不进任何生产调用链（模式同 ai_policy.h 的
 * ai_policy_test_record_write）。 */
struct ai_effect_win *ai_effect_test_win(enum ai_hook_id hook);
void ai_effect_test_reset(void);
#endif

#endif /* _AIKERNEL_AI_EFFECT_H */
