/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acpsi.h - PSI（内核压力信号）触发源：/proc/pressure 解析 + 抑制状态机
 *
 * K3d-1（I-7）：autocondense 压缩时机从"轮次/水位"升级为"系统忙时少压/
 * 闲时多压"。周期读 /proc/pressure/{cpu,memory,io}（some avg10 为主，
 * full avg10 记录）；memory some avg10 ≥ 高阈 → 开抑制窗口（窗口内压缩
 * 触发被延迟而非丢弃）；回落 < 低阈 → 提前解除；窗口到期时压力仍高则
 * 续开新窗口（滞回带 [低阈, 高阈) 内维持现状）。
 *
 * 默认关（psi.enabled=0）：不采样、不判定、状态文件与 /status 无 psi
 * 段——与现状逐位一致（回滚保证）。/proc/pressure 不可读（非 PSI 内核）
 * 时诚实降级：启动一行日志、该源停用、其余触发源不受影响。
 *
 * 配置模型在 acconfig.h（ac_psi_config，"psi" 配置段）；本模块只做
 * 解析与状态机，时间由调用方注入（ac_now/测试冻结时钟），零第三方依赖。
 */
#ifndef _AIK_AUTOCONDENSE_ACPSI_H
#define _AIK_AUTOCONDENSE_ACPSI_H

#include "autocondense/acconfig.h"

/* procfs PSI 根目录（监控用；测试用 fixture 目录调 ac_psi_read）*/
#define AC_PSI_PROC_DIR "/proc/pressure"

/* 状态机状态 */
enum {
	AC_PSI_STATE_OFF = 0,		/* 未启用（psi.enabled=0）*/
	AC_PSI_STATE_NORMAL = 1,	/* 启用且未抑制 */
	AC_PSI_STATE_SUPPRESSED = 2,	/* 抑制窗口内 */
	AC_PSI_STATE_DEGRADED = 3,	/* 源停用（读失败，无自动恢复）*/
};

/* 事件（审计日志用；每次抑制开始/结束/降级各一行）*/
enum {
	AC_PSI_EV_NONE = 0,
	AC_PSI_EV_SUPPRESS_START,	/* 开窗 */
	AC_PSI_EV_REARM,		/* 到期续开 */
	AC_PSI_EV_END_CLEAR,		/* 压力回落解除 */
	AC_PSI_EV_END_EXPIRE,		/* 到期解除（滞回带）*/
	AC_PSI_EV_WARN,			/* 读失败（限频告警）*/
	AC_PSI_EV_DEGRADE,		/* 连续失败降级 */
};

/* 连续读失败该次数后降级 */
#define AC_PSI_FAIL_STREAK_DEGRADE 3

/* 读失败告警限频（秒）*/
#define AC_PSI_WARN_INTERVAL_S 60.0

/* 单资源采样值（单位 %，与 /proc/pressure 一致；full 缺失记 has_full=0）*/
typedef struct {
	double some;
	double full;
	int has_full;
} ac_psi_res;

/* 一次完整采样（cpu/memory/io）*/
typedef struct {
	ac_psi_res cpu;
	ac_psi_res mem;
	ac_psi_res io;
	double at;		/* 采样时刻 epoch（注入时钟域）*/
} ac_psi_values;

/* 状态机（含审计计数；阈值/周期为配置快照，可热刷新）*/
typedef struct {
	int state;
	double period_s;	/* 配置快照（钳制后 ≥1）*/
	double high_threshold;	/* 快照（0,100] */
	double low_threshold;	/* 快照 [0,100) */
	double window_s;	/* 快照 ≥1 */
	double window_open_at;	/* 当前窗口开启 epoch；0=无 */
	long long suppressed_count;	/* 抑制窗口开启次数（含续开）*/
	long long deferred_count;	/* 被延迟的压缩触发数 */
	long long degrade_count;	/* 降级次数 */
	long long samples;	/* 成功采样次数 */
	ac_psi_values last;	/* 最近一次成功采样 */
	int has_last;
	int fail_streak;	/* 连续读失败次数 */
	double last_warn_at;	/* 上次告警 epoch（限频）*/
} ac_psi_machine;

/* 事件描述（ac_psi_step 输出；格式化成日志行用）*/
typedef struct {
	int kind;
	double now;
	ac_psi_values v;	/* 触发事件的采样（DEGRADE/WARN 为最近成功值）*/
	long long counter;	/* 窗口编号 / 降级编号 */
	double window_s;
	double high_threshold;
	double low_threshold;
	int fail_streak;
	int was_suppressed;	/* DEGRADE 时此前是否处于抑制窗口 */
} ac_psi_event;

/*
 * ac_psi_parse - 解析一个 /proc/pressure/<res> 文件内容
 *
 * 形如 "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=..."。
 * some 行必须存在且 avg10 合法（0-100 的十进制数），否则返回 -1；
 * full 行可选（cpu 资源无 full），存在但坏行同样返回 -1；
 * 其余未知行忽略。成功返回 0，*full 在无 full 行时 has_full=0。
 */
int ac_psi_parse(const char *text, ac_psi_res *out);

/*
 * ac_psi_read - 读 <dir>/{cpu,memory,io} 三个文件组成一次采样
 *
 * 任一文件缺失/读失败/解析失败 → 返回 -1（调用方按采样失败处理）。
 * 成功返回 0 且 out->at = now（由调用方注入的时钟取值）。
 */
int ac_psi_read(const char *dir, ac_psi_values *out, double now);

/*
 * ac_psi_machine_init - 按配置初始化状态机（NORMAL，计数清零）
 *
 * 配置越界值回落默认（period<1→5、window<1→120、high 出 (0,100]→50、
 * low 出 [0,100)→20、low≥high→双双回落默认）——加载期容忍的最后防线。
 */
void ac_psi_machine_init(ac_psi_machine *m, const ac_psi_config *cfg);

/* 热刷新阈值/周期（PUT /config 后调用；状态与计数保留），同样钳制 */
void ac_psi_machine_refresh(ac_psi_machine *m, const ac_psi_config *cfg);

/* 置 OFF（保留计数，窗口清零；psi.enabled=0 时）*/
void ac_psi_machine_off(ac_psi_machine *m);

/* 直接降级（启动探测失败时；degrade_count++，窗口清零）*/
void ac_psi_degrade(ac_psi_machine *m, double now);

/*
 * ac_psi_step - 喂一次采样推进状态机（v=NULL 表示本次读失败）
 *
 * 状态转换语义：
 *   NORMAL   + mem_some ≥ 高阈           → SUPPRESSED（开窗，START）
 *   SUPPRESSED + mem_some < 低阈          → NORMAL（END_CLEAR，提前解除）
 *   SUPPRESSED + 窗口到期 + mem_some ≥ 高阈 → 续开新窗（REARM，计数++）
 *   SUPPRESSED + 窗口到期（滞回带）       → NORMAL（END_EXPIRE）
 *   读失败连续 ≥3 次                       → DEGRADED（抑制一并解除）
 *   读失败未到降级阈值                      → 限频 WARN
 * 返回事件 kind（ev 可 NULL）；DEGRADED 后不再推进（无自动恢复）。
 */
int ac_psi_step(ac_psi_machine *m, const ac_psi_values *v, double now,
		ac_psi_event *ev);

/*
 * ac_psi_suppressed - 当前时刻是否处于抑制窗口（时间判定）
 *
 * state==SUPPRESSED 且 now < window_open_at + window_s。窗口已到期但
 * 尚未采样续开时返回 0（到期后照常评估）。
 */
int ac_psi_suppressed(const ac_psi_machine *m, double now);

/*
 * ac_psi_gate - 触发闸门：抑制中返回 1 并写延迟原因文案
 *
 * 原因（中文，含实时 PSI 值与阈值）：
 * "PSI 内存压力抑制窗口内（memory some avg10=X.XX%，高阈 Y.YY%），
 *  压缩触发延迟（不丢弃），窗口结束或压力回落后恢复评估"
 */
int ac_psi_gate(const ac_psi_machine *m, double now, char *reason,
		size_t reasonlen);

/* 计一次被延迟的压缩触发（deferred_count++）*/
void ac_psi_note_deferred(ac_psi_machine *m);

/* 状态名（"off"/"normal"/"suppressed"/"degraded"）*/
const char *ac_psi_state_name(int state);

/*
 * ac_psi_status_dict - 状态文件 / GET /status 的 psi 段
 *
 * 键序：enabled, state, period_s, high_threshold, low_threshold,
 * window_s, last_values{cpu,memory,io}{some,full}, sampled_at,
 * suppressed_count, deferred_count, degrade_count, samples。
 * last_values 未采样时各项为 null；sampled_at 同。
 */
aik_json *ac_psi_status_dict(const ac_psi_machine *m,
			     const ac_psi_config *cfg);

/*
 * ac_psi_format_event - 事件格式化为审计日志正文（不含前缀/时间戳）
 *
 * 写入 buf（NUL 结尾）；返回 buf。每事件恰好一行文案。
 */
const char *ac_psi_format_event(const ac_psi_event *ev, char *buf,
				size_t buflen);

#endif /* _AIK_AUTOCONDENSE_ACPSI_H */
