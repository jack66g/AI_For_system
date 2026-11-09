/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_outcome.h - I-10 决策闭环第 4 步 outcome 回填器（C3，默认关）
 *
 * 设计依据：work/refactor/I10-METRIC-DESIGN.md（§3 逐旋钮指标表 /
 * §4 回填器草图 / §5 验收门）。语义要点：
 *
 *   1) 输入面：EVENT 路 AI_NL_EV_POLICY（as_event_ai_policy 已把
 *      decision_id/executed/param 原样透传）。param 空（域广播）与
 *      executed=0 不回填（§4.4 skip_broadcast/skip_noexec）。
 *   2) 反查面：/proc/ai/decisions 尾条（最新在前）按 decision_id 反查
 *      domain/pid/data（EVENT 载荷不带 domain/pid——设计 §7.9）。
 *      扫描截断在 OUTCOME_DECISIONS_SCAN_MAX 行（557KB 全量读成本，
 *      设计 §7.6），截断漏查 → notfound 计数（如实）。
 *   3) 指标面：§3 表 C 化静态表 as_oc_rows（28 旋钮全量收录）。
 *      全部走既有只读面：/proc/pressure、/proc/vmstat、/proc/net/netstat、
 *      /sys/kernel/ai/stats/<键>、/proc/ai/control、/proc/<pid>/<file>、
 *      /sys/class/{bdi,net}/<leaf>、cpufreq/cpuidle sysfs。零新增内核面。
 *   4) 写口：/sys/kernel/ai/policy/outcome "<decision_id>,<outcome>,
 *      <metric_delta>"（0200 root；内核纯注记不改行为，C3）。
 *      回填器只写 {SUCCESS=1, PARTIAL=2, WORSE=4}——FAILED(3) 保留给
 *      内核执行失败口径（arm 已滤 executed=0），避免「测量失败」被
 *      误读为「动作失败」（§4.3 分类语义约定）。
 *   5) 分类（§4.3）：按「注入前值 vs 注入值」推意图方向；delta 与意图
 *      同向且出噪声带 → SUCCESS；反向出带 → WORSE；带内 → PARTIAL；
 *      指标源读失败/需场景无负载 → PARTIAL + delta=0 + meas_fail。
 *      match 类（确定性读回旋钮）按 状态迁移 判：达成→SUCCESS、
 *      回退→WORSE、未变/无期望→PARTIAL（无操作对照天然 PARTIAL）。
 *   6) metric_delta 单位逐行见 as_oc_rows.unit（内核不解释单位——
 *      ai_policy.h 注释，文档义务在本侧，设计 §1.1）。
 *   7) SME/Parquet 衔接：回填结果经 as_event_outcome 合成事件走既有
 *      管道（SME 记忆路 + T8 parquet telemetry；decision 23 列 schema
 *      的 outcome/outcome_ts 列已在 as_parquet.h:59-60 预留——落盘侧
 *      零改动即兼容，设计 §0.5）。SME 不可达不阻塞 outcome 写
 *      （合成事件走既有环形缓冲路径，§4.4）。
 *   8) outcome_auto_rollback（C4）：conf 键接收（默认 0），但写
 *      policy/rollback 的路径本轮**不实现**（C4 需单独拍板——
 *      设计 §4.6/§6.4；置 1 时 journal 明示 acknowledged-not-active）。
 *
 * 路径前缀 root：默认 "/"（真内核）；单测/L1 冒烟用 mock 树前缀
 * （as_outcome_set_root，如 "/tmp/mock"——L1 无 AIKernel 内核，
 * /sys/kernel/ai 不在，用 mock 树覆盖，真内核 qemu 轮移交 K3C §9-1）。
 */
#ifndef _AS_OUTCOME_H
#define _AS_OUTCOME_H

#include <stdint.h>

#include "as_conf.h"
#include "as_event.h"
#include "as_stats.h"

/* ---- 内核 outcome 枚举（ai_policy.h AI_OUTCOME_*，只读对齐） ---- */
#define AS_OC_SUCCESS	1
#define AS_OC_PARTIAL	2
#define AS_OC_WORSE	4

/* ---- 指标种类（§4.2 metric_kind；每行一种主指标） ---- */
enum as_oc_kind {
	OC_K_NONE = 0,
	/* /proc/pressure/<res> some avg10（厘=×100 整数，avg10 差） */
	OC_K_PSI_CPU,
	OC_K_PSI_MEM,
	OC_K_PSI_IO,
	/* /proc/vmstat 键计数器（速率差=条/s） */
	OC_K_VMSTAT_RATE,
	/* /proc/net/netstat TcpExt 键计数器（速率差=段/s） */
	OC_K_TCPEXT_RATE,
	/* /sys/kernel/ai/stats/ai_actions 键：速率差（计数器键） */
	OC_K_AI_ACT_RATE,
	/* /sys/kernel/ai/stats/ai_actions 键：原量纲差（gauge 键） */
	OC_K_AI_ACT_GAUGE,
	/* /sys/kernel/ai/stats/decisions_total 计数器（条数差） */
	OC_K_DECISIONS_TOTAL,
	/* /proc/ai/control 本旋钮 current 读回（原量纲差） */
	OC_K_CONTROL_CURRENT,
	/* /sys/class/bdi/<first>/ra_pages 读回（KB 差） */
	OC_K_BDI_RA_PAGES,
	/* /sys/class/bdi/<first>/max_ratio 读回（percent 差） */
	OC_K_BDI_MAX_RATIO,
	/* /sys/devices/system/cpu/cpu<N>/cpufreq/scaling_cur_freq 均值（kHz 差） */
	OC_K_CPUFREQ_MEAN,
	/* cpuidle 深态（state1+）time 之和（us 差） */
	OC_K_CPUIDLE_DEEP_US,
	/* /proc/<pid>/schedstat 第 2 列 run 等待（ms 差；taskstats cpu_delay
	 * 同源替代——设计 §3 sched.nice 行） */
	OC_K_TASK_SCHED_DELAY,
	/* /proc/<pid>/oom_score_adj 读回（原值差） */
	OC_K_TASK_OOMADJ,
	/* /proc/<pid>/limits 第 <data[2]> 行 soft 列读回（原值差） */
	OC_K_TASK_LIMITS_SOFT,
	/* ---- match 类（确定性读回；-1/0/1 迁移判定，见 as_oc_match） ---- */
	OC_K_MATCH_AFFINITY,	/* Cpus_allowed_list == 注入 CPU（单核钉扎） */
	OC_K_MATCH_QDISC,	/* /sys/class/net/<dev>/qdisc 名（RTNL 同源面） */
	OC_K_MATCH_WS_LABEL,	/* /proc/ai/ws_labels 出现 "<pid> <label>" 行 */
	OC_K_MATCH_SIGNAL,	/* /proc/<pid>/stat state（按信号号映射期望态） */
	OC_K_MATCH_FREEZE,	/* state==T；delta=冻结期 CPU 增量 ms（§3 最干净行） */
	/* reserved：不可注入生效（ai_lsm.c 诚实降级），固定 skip */
	OC_K_RESERVED,
};

/* 方向：d(主指标)/d(旋钮值) 符号（意图=注入值-注入前值，§4.3） */
#define AS_OC_DIR_DOWN	(-1)	/* 旋钮升→指标降（负相关） */
#define AS_OC_DIR_UP	(1)	/* 旋钮升→指标升（正相关） */
#define AS_OC_DIR_INTENT	0	/* 权衡型：方向按注入意图——出噪声带
					 * 即算生效（SUCCESS），不判 WORSE
					 * （§3 timeslice/cwnd/rto 行） */
/* match 类不走数值方向（迁移判定），dir 字段无意义 */

/* 行标志 */
#define AS_OC_F_TASK		(1 << 0)	/* task 旋钮：data[0]=pid
						 * data[1]=value（全局=data[0]） */
#define AS_OC_F_SCENARIO	(1 << 1)	/* 效果类需场景（OOM 等）——读回
						 * 变化也如实 PARTIAL（§3
						 * oom_score 行「无场景时只回
						 * 读回=PARTIAL」） */

/* pending 队硬上限（conf OUTCOME_MAX_PENDING 的解析上界） */
#define AS_OC_MAX_PENDING_HARD	4096
/* decisions 反查扫描硬上界 */
#define AS_OC_SCAN_HARD		4096
/* param 名长（内核 EVENT 载荷 char[24]，留余量） */
#define AS_OC_PARAM_MAX		32

/* metric 表行（§3 的 C 化；unit=metric_delta 量纲文档） */
struct as_oc_row {
	const char *param;	/* 旋钮名（EVENT param 原样） */
	enum as_oc_kind kind;
	const char *key;	/* 键名（vmstat/tcpext/ai_actions 行/qdisc dev） */
	int8_t win_long;	/* 0=S 窗口 1=L 窗口（§3 表 W 列） */
	int8_t dir;		/* AS_OC_DIR_*（数值类） */
	int32_t threshold;	/* 噪声带（数值类；单位同 delta） */
	const char *unit;	/* metric_delta 量纲（写口不解释，文档义务） */
	uint8_t flags;		/* AS_OC_F_* */
};

/* 表全量（28 行含 reserved；测试冻结引用 as_oc_rows/as_oc_rows_n） */
extern const struct as_oc_row as_oc_rows[];
extern const size_t as_oc_rows_n;

/* 旋钮名 → 行下标（-1=未收录；测试与 tap 共用） */
int as_oc_row_lookup(const char *param);

/* ---- /proc/ai/decisions 尾条反查产物（解析格式见 as_outcome.c） ---- */
struct as_oc_decision {
	unsigned long long id;
	unsigned long long data[8];
	unsigned domain;
	unsigned executed;
	unsigned long long outcome_ts;	/* 自校验用：>0 ⇔ 已被回填 */
};

/*
 * as_oc_scan_decisions - 在 path 的前 scan_max 行内按 id 反查（最新在前）。
 * 0=命中（*out 填充）；1=未命中（截断/不存在）；-1=读失败。
 */
int as_oc_scan_decisions(const char *path, unsigned long long id, int scan_max,
			 struct as_oc_decision *out);

/* ---- 数值快照（arm 基线与 fill 重读共用；返回 0/-1） ----
 * out[0]=主指标值（含义按 kind）；match 类 out[0]=期望态是否已成立(0/1)、
 * out[1]=辅助值（freeze：utime+stime 累计 tick）。task 类 pid 必填。 */
int as_oc_snapshot(const char *root, const struct as_oc_row *row, int32_t pid,
		   unsigned long long injected, const unsigned long long data[8],
		   long long out[2]);

/* intent 计算（注入前值 vs 注入值；纯函数）：-1/0/+1 */
int as_oc_intent(long long injected, long long before);

/* ---- 分类（纯函数；§4.3——单测冻结口径） ---- */
struct as_oc_class {
	int outcome;		/* AS_OC_SUCCESS/PARTIAL/WORSE */
	long long delta;	/* 写入 metric_delta（量纲=row->unit） */
	int meas_fail;		/* 指标源读失败（PARTIAL+delta=0 的理由） */
	int noop;		/* 注入值==注入前值（无操作对照→PARTIAL） */
	int no_expect;		/* match 类无期望态（qdisc=0 回滚/未知信号） */
};

/*
 * as_oc_classify - 数值类分类。
 *   injected/before：意图；has_before=0 → meas_fail（无法推意图，如实）。
 *   base/now：主指标 T0/窗口末快照；window_sec 用于速率类换算。
 */
struct as_oc_class as_oc_classify_num(const struct as_oc_row *row,
				      long long injected, long long before,
				      int has_before, long long base,
				      long long now, int window_sec);

/*
 * as_oc_classify_match - match 类分类（状态迁移）：
 *   base_ok/now_ok=期望态在 T0/窗口末是否成立；
 *   aux_base/aux_now=辅助量（freeze 的 CPU 累计 tick→delta ms）。
 *   迁移：未成立→成立=SUCCESS；成立→未成立=WORSE；其余=PARTIAL
 *   （含 无操作：已成立→仍成立——对照注入天然 PARTIAL，§5.3）。
 *   no_expect（无期望态）=PARTIAL+delta=0。
 */
struct as_oc_class as_oc_classify_match(const struct as_oc_row *row,
					int no_expect, int base_ok, int now_ok,
					long long aux_base, long long aux_now);

/* outcome 枚举名（journal/合成事件用；静态字面量） */
const char *as_oc_outcome_name(int outcome);

/* ---- 合成事件（SME 记忆路 + T8 parquet telemetry 衔接） ---- */
/*
 * 行格式冻结：
 *   [kern] event outcome decision_id=%llu outcome=%s delta=%lld knob=%s
 * 走既有 as_event 管道（quota/ring/SME/parquet），不新增路径。
 */
void as_event_outcome(struct as_event *ev, unsigned long long decision_id,
		      int outcome, long long delta, const char *knob);

/* ---- 回填器主体 ---- */

struct as_oc_job {
	unsigned long long decision_id;
	char param[AS_OC_PARAM_MAX];
	int row_idx;		/* as_oc_rows 下标 */
	int32_t pid;		/* task 旋钮；全局 0 */
	unsigned long long data[8];	/* decisions 反查原样（rlimit data[2] 等） */
	long long injected;		/* data[1]（task）/data[0]（全局） */
	long long before;		/* /proc/ai/control current（意图计算） */
	int has_before;
	long long base[2];	/* T0 快照（as_oc_snapshot 产物） */
	int has_base;
	long long arm_mono_ms;
	long long due_mono_ms;
};

struct as_outcome {
	struct as_conf *conf;
	struct as_stats *stats;
	struct as_oc_job *jobs;		/* pending FIFO 环（cap=conf） */
	int cap, head, count;
	long long dropped;		/* 队满丢旧（洪泛，§5.6） */
	void (*emit)(struct as_event *ev, void *ud);	/* 合成事件出口 */
	void *emit_ud;
	char root[256];			/* 路径前缀（默认 "/"；测试 mock 树） */
	int armed_any;			/* 已 arm 过（关闭时 journal 提示用） */
};

/* 初始化（pending 按 conf 分配；enabled=0 不分配，零开销）。0/-1（内存） */
int as_outcome_init(struct as_outcome *oc, struct as_conf *c,
		    struct as_stats *st);

/* 释放 */
void as_outcome_close(struct as_outcome *oc);

/* 测试/mock 钩子：路径前缀（仅测试与 L1 mock 冒烟用；生产恒 "/"） */
void as_outcome_set_root(struct as_outcome *oc, const char *root);

/* 合成事件出口注册（aistreamd.c 注 on_event 管道；NULL=不合成） */
void as_outcome_set_sink(struct as_outcome *oc,
			 void (*emit)(struct as_event *ev, void *ud),
			 void *ud);

/*
 * as_outcome_tap - EVENT 路 arm 入口（on_event 内调用；非 policy 事件
 * 零副作用返回；enabled=0 零开销）。arm 规则见 §4.4：broadcast/noexec/
 * reserved/unknown/notfound 各自计数，命中才入 pending 队。
 */
void as_outcome_tap(struct as_outcome *oc, const struct as_event *ev);

/*
 * as_outcome_tick - 窗口到期回填（主循环定时器挂接）。now_mono_ms 由
 * 调用方传（可测）。每 job：重读指标 → 分类 → 写口 → decisions 自校验
 * （outcome_ts>0，失败 verify_fail 计数，§4.3 t0+W+δ）→ 合成事件。
 */
void as_outcome_tick(struct as_outcome *oc, long long now_mono_ms);

/* 最近到期 job 还差多久（ms；无 job 返回 -1；主循环 poll 超时用） */
long long as_outcome_due_ms(const struct as_outcome *oc, long long now_mono_ms);

#endif /* _AS_OUTCOME_H */
