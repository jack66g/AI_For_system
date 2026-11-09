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
 *      domain/pid/data/pre（EVENT 载荷不带 domain/pid——设计 §7.9）。
 *      扫描截断在 OUTCOME_DECISIONS_SCAN_MAX 行（557KB 全量读成本，
 *      设计 §7.6），截断漏查 → notfound 计数（如实）。
 *      **U66/A1（F16 §2-1 根因修复）：决策前值基线改从行尾 `pre=`
 *      字段取**（K66-REPORT §5 契约；内核 #66 起追加）。F16 实测
 *      arm 时点读 /proc/ai/control current= 已是注入值（内核 execute
 *      先于 arm）→ before==injected → noop-PARTIAL（8×sched.nice 全
 *      落此路）；match 基线同病（post-execute 读回 → base==now →
 *      PARTIAL）。pre= 生命周期随快照环（64 决策，rollback 即消费）
 *      ——消费方应尽早读（arm 时反查即取，本模块照做）。
 *   3) 指标面：§3 表 C 化静态表 as_oc_rows（28 旋钮全量收录）。
 *      全部走既有只读面：/proc/pressure、/proc/vmstat、/proc/net/netstat、
 *      /sys/kernel/ai/stats/<键>、/proc/ai/control、/proc/<pid>/<file>、
 *      /sys/class/{bdi,net}/<leaf>、cpufreq/cpuidle sysfs。零新增内核面。
 *   4) 写口：/sys/kernel/ai/policy/outcome "<decision_id>,<outcome>,
 *      <metric_delta>"（0200 root；内核纯注记不改行为，C3）。
 *      回填器只写 {SUCCESS=1, PARTIAL=2, WORSE=4}——FAILED(3) 保留给
 *      内核执行失败口径（arm 已滤 executed=0），避免「测量失败」被
 *      误读为「动作失败」（§4.3 分类语义约定）。
 *   5) 分类（§4.3，U66 pre= 基线口径）：方向一致 =（after−pre）与
 *      （requested−pre）同向且出噪声带 → SUCCESS；反向出带 → WORSE；
 *      带内 → PARTIAL；指标源读失败 → PARTIAL + delta=0 + meas_fail。
 *      数值类意图 before=decisions 行 pre=（TASK 旋钮 pre 为决策前
 *      per-task 真值——有 read 回调者；无回调者为全局表值，K66 §5
 *      语义，见 AS_OC_F_READBACK 注）。读回型行（AS_OC_F_READBACK）
 *      主指标基线也取 pre（after=窗口末读回，delta=读回−pre——execute
 *      即落地型指标在 arm 时点已=注入值，T0 快照结构性恒零）。
 *      match 类基线 base_ok = pre 状态映射（as_oc_match_base）：期望态
 *      在决策前已成立 ⇔ pre 与 injected 映射到同一状态 → 无迁移 →
 *      PARTIAL（无操作对照天然 PARTIAL）。
 *      `pre=none`（恒等快路径未应用/无快照/rollback 已消费/环淘汰/
 *      #65 前旧行）→ PARTIAL + pre_none 计数（I10 §4.4 降级纪律；
 *      恒等决策 no-op→PARTIAL 本就是诚实判定，保留；消费者不可区分
 *      none 的成因，统一按「基线不可得」如实降级——非 meas_fail，
 *      指标源未失败）。
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
#define AS_OC_F_READBACK	(1 << 2)	/* U66：读回型指标——主指标即
						 * 旋钮自身读回（control
						 * current/bdi/gauge/per-task
						 * oom_adj/limits），execute
						 * 即落地 → T0=arm 快照恒等
						 * 注入值，delta 结构性=0。
						 * 基线改取 decisions pre=
						 * （after−pre 口径）。 */
						 /* 注：proc.rlimit 无 read
						  * 回调 → pre 为全局表值
						  * （K66 §5 fallback 语义），
						  * 基线可能失真——保守方向，
						  * 详见 U66-REPORT §1 */

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
	/* U66/A1：行尾 pre= 字段（K66-REPORT §5；#65 及之前无此字段）。
	 * pre_n=0 ⇔ 无快照（none）/字段缺席/#65 旧行/解析失败（容忍：
	 * 23 字段主解析已成功，pre 不构成坏行）。多参（广播）按 handler
	 * 保存序 1..8 项；本模块只处理 v2 定向（param 非空）→ 取 pre[0]。 */
	long long pre[8];
	int pre_n;
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

/* intent 计算（注入前值 vs 注入值；纯函数）：-1/0/+1
 * U66：before=decisions 行 pre= 值（决策前真值），非 control current */
int as_oc_intent(long long injected, long long before);

/* ---- 分类（纯函数；§4.3——单测冻结口径；U66 pre= 基线版） ---- */
struct as_oc_class {
	int outcome;		/* AS_OC_SUCCESS/PARTIAL/WORSE */
	long long delta;	/* 写入 metric_delta（量纲=row->unit） */
	int meas_fail;		/* 指标源读失败（PARTIAL+delta=0 的理由） */
	int noop;		/* 注入值==注入前值（无操作对照→PARTIAL） */
	int no_expect;		/* match 类无期望态（qdisc=0 回滚/未知信号） */
	int pre_none;		/* U66：pre= 基线不可得（none/缺席/环淘汰/
				 * rollback 已消费）→ PARTIAL（非 meas_fail
				 * ——指标源未失败，基线不可得如实降级） */
};

/*
 * as_oc_classify - 数值类分类。
 *   injected/before：意图（U66：before=decisions pre= 值）；
 *   has_before=0（pre=none/#65 旧行）→ PARTIAL+pre_none（delta 照算
 *   ——base/now 可得时 delta 仍有意义；读回型行 base 即不可得由
 *   调用侧走 meas/pre_none 分支）。
 *   base/now：主指标 T0/窗口末快照（读回型行 base=pre——调用侧职责）；
 *   window_sec 用于速率类换算。
 */
struct as_oc_class as_oc_classify_num(const struct as_oc_row *row,
				      long long injected, long long before,
				      int has_before, long long base,
				      long long now, int window_sec);

/*
 * as_oc_match_base - match 类决策前基线（U66 核心新增；纯函数）：
 * 由 pre 值与注入值的状态映射推「期望态在决策前是否已成立」。
 *   affinity/qdisc/ws_label：pre==injected（值域即状态域；
 *     ws_label/signal 无 read 回调 → pre 为全局表值——K66 §5
 *     fallback 语义，同值连发保守判「已成立」→PARTIAL，见报告 §1）
 *   freeze：((pre!=0)==(injected!=0))（per-task 读回真值）
 *   signal：信号组映射（19→stop；18→run；9/15→dead；他值组 0）
 *     pre 与 injected 同组 → 已成立（保守）；
 * 返回 0/1（base_ok）。
 */
int as_oc_match_base(enum as_oc_kind kind, long long injected,
		     long long pre);

/* proc.signal 信号→状态组（19→1 stop；18→2 run；9/15→3 dead；他→0） */
int as_oc_sig_group(long long sig);

/*
 * as_oc_classify_match - match 类分类（状态迁移）：
 *   base_known=0（pre=none/#65 旧行）→ PARTIAL+pre_none（迁移不可
 *   判；freeze 的 aux delta 仍报——CPU 累计 tick 与基线无关）。
 *   base_ok/now_ok=期望态在决策前/窗口末是否成立（U66：base_ok 由
 *   as_oc_match_base(pre) 出，非 arm 时点读回）；
 *   aux_base/aux_now=辅助量（freeze 的 CPU 累计 tick→delta ms）。
 *   迁移：未成立→成立=SUCCESS；成立→未成立=WORSE；其余=PARTIAL
 *   （含 无操作：已成立→仍成立——对照注入天然 PARTIAL，§5.3）。
 *   no_expect（无期望态）=PARTIAL+delta=0。
 */
struct as_oc_class as_oc_classify_match(const struct as_oc_row *row,
					int no_expect, int base_known,
					int base_ok, int now_ok,
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
	long long before;		/* U66：decisions pre=[0]（意图计算；
					 * TASK 真值或全局表值 fallback） */
	int has_before;		/* pre_n>0 */
	long long base[2];	/* 主指标 T0（环境型=arm 快照；读回型=
				 * pre[0]——AS_OC_F_READBACK；match 型
				 * base[0]=as_oc_match_base 产物，
				 * base[1]=arm 快照 aux） */
	int has_base;		/* 基线可得（读回/match 型=has_before） */
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
