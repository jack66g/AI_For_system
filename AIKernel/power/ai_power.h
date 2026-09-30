// SPDX-License-Identifier: GPL-2.0
/*
 * ai_power.h - AIKernel 电源管理子系统统一接口头（Prompt 10，重构计划 模块11）
 *
 * 本文件是 kernel/power/、drivers/cpufreq/、drivers/cpuidle/、drivers/thermal/
 * 全部 AI 埋点的唯一接入点：
 *   A 轨（控制）：ai_power_*_hook() 系列 —— 让 AI 参与电源管理决策，
 *                 空实现 = 原样放行（返回值不改变内核默认行为）；
 *   B 轨（感知）：第12类 电源管理感知的 payload 结构 + 发射辅助，
 *                 全量原始零脱敏。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_POWER=n：本头文件不参与任何编译（调用点条件剔除）；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_* 退化为 static inline
 *     空函数（ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 热路径安全性：
 *   - cpuidle 决策路径（menu_select）：Hook 只计一次数，遥测全部在出口侧采样；
 *   - 全部发射辅助 = sample_take + 栈上 payload + emit_direct 直写（无锁无分配）；
 *   - per-CPU 计数器一律直接对符号操作（Prompt 09 早期启动崩溃先例）。
 *
 * 跨目录类型隔离：Hook 全部传标量/稳定内核指针，不引入 struct cpuidle_*、
 * struct thermal_zone_device 等依赖，保证 ai_power.c 在任意 CONFIG 组合可编译。
 */

#ifndef _AIKERNEL_POWER_AI_POWER_H
#define _AIKERNEL_POWER_AI_POWER_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/types.h>

/* 内核类型前向声明（本头只传指针） */
struct cpufreq_policy;
struct device;
struct em_perf_table;

/* ==================================================================
 * B 轨：第12类 电源管理感知 payload（事件编号对齐 enum ai_event_type
 * 12.01~12.05；首字节 type 区分计划内子事件）
 * ==================================================================
 */

enum ai_power_sub_event {
	AI_POWER_CPUFREQ_CHANGE		= 1,	/* 12.01 频率调整 */
	AI_POWER_CPUIDLE_STATE,			/* 12.02 C-state 驻留 */
	AI_POWER_ENERGY_MODEL_UPDATE,		/* 12.01 能耗模型实时更新 */
	AI_POWER_THERMAL_TREND,			/* 12.05 温度趋势 */
	AI_POWER_QOS_CONSTRAINT,		/* 12.04 QoS 约束变更 */
	AI_POWER_WAKELOCK_EVENT,		/* 12.03 唤醒锁事件 */
};

struct ai_power_cpufreq_payload {
	u8 type;			/* AI_POWER_CPUFREQ_CHANGE */
	u16 cpu;
	u32 old_freq_khz;
	u32 new_freq_khz;
	u8 relation;			/* CPUFREQ_RELATION_* */
	char governor[24];		/* 当前 governor 名 */
};

struct ai_power_cpuidle_payload {
	u8 type;			/* AI_POWER_CPUIDLE_STATE */
	u16 cpu;
	u32 state_idx;
	u64 residency_ns;		/* 本次驻留时长（去 exit latency 前原始值） */
	char state_name[24];
};

struct ai_power_energy_model_payload {
	u8 type;			/* AI_POWER_ENERGY_MODEL_UPDATE */
	u32 nr_states;
	u32 freq_khz[8];		/* 各性能态频率（kHz） */
	u32 power_mw[8];		/* 各性能态功耗（mW） */
	char device_name[32];		/* 能耗域设备名（如 cpu0） */
};

struct ai_power_thermal_payload {
	u8 type;			/* AI_POWER_THERMAL_TREND */
	s32 temperature;		/* 当前温度（m°C） */
	s32 last_temperature;		/* 上次温度（m°C） */
	s32 trend;			/* temperature - last_temperature */
	char zone_name[32];		/* 热区名（如 x86_pkg_temp） */
};

struct ai_power_qos_payload {
	u8 type;			/* AI_POWER_QOS_CONSTRAINT */
	u8 qos_type;			/* enum pm_qos_type（MIN/MAX/SUM） */
	u8 action;			/* enum pm_qos_req_action */
	s32 prev_value;
	s32 curr_value;			/* 聚合后的约束值 */
};

struct ai_power_wakelock_payload {
	u8 type;			/* AI_POWER_WAKELOCK_EVENT */
	u8 action;			/* 1=acquire 2=release */
	u32 pid;
	u64 timeout_ns;			/* 超时（0=无限） */
	char name[128];			/* 唤醒锁名全量 */
};

/* ---- 决策统计 ---- */

struct ai_power_stats {
	u64 cpufreq_hook_calls, cpufreq_hook_adjusted;
	u64 cpuidle_hook_calls, cpuidle_hook_adjusted;
	u64 em_hook_calls;
	u64 thermal_hook_calls;
	u64 qos_hook_calls;
	u64 wakelock_hook_calls;
	u64 emit_cpufreq, emit_cpuidle, emit_em, emit_thermal, emit_qos,
	    emit_wakelock;
};

#ifdef CONFIG_AIKERNEL_POWER

/* ---- A 轨 Hook（实现见 ai_power.c；空实现 = 原样放行） ---- */

/**
 * ai_power_cpufreq_hook() - AI 频率决策接口（aiguard governor 调用）
 * @policy: 当前 cpufreq 政策
 * @time: 本次更新时刻
 * @util: 当前 util 估算（0~SCHED_CAPACITY_SCALE）
 * @max: 当前容量
 * @freq: 出参/入参；schedutil 同款公式算出的目标频率（AI 可改写；resolve 前调用）
 *
 * 由 AIKernel/power/ai_cpufreq.c aiguard governor 频率计算后调用。空实现不改。
 */
void ai_power_cpufreq_hook(struct cpufreq_policy *policy, u64 time,
			   unsigned long util, unsigned long max,
			   unsigned int *freq);

/**
 * ai_power_cpuidle_hook() - AI 预测空闲时长，选 C-state
 * @cpu: 当前 CPU
 * @state_count: 可用 C-state 数
 * @latency_req_ns: 当前延迟约束
 * @predicted_ns: 出参/入参；menu 预测的空闲时长（AI 可调整）
 * @idx: 出参/入参；menu 选中的 state 索引（AI 可改写，调用点钳制边界）
 *
 * 由 drivers/cpuidle/governors/menu.c menu_select() 返回前调用。空实现不改。
 * 注意：本 Hook 在 idle 决策热路径上，实现必须零锁零分配零 printk。
 */
void ai_power_cpuidle_hook(int cpu, int state_count, u64 latency_req_ns,
			   u64 *predicted_ns, int *idx);

/**
 * ai_power_em_hook() - AI 实时更新能耗模型参数
 * @dev: 能耗域设备
 * @table: 刚交换完成的新能耗表（AI 可调整 state[] 的 power/frequency）
 *
 * 由 kernel/power/energy_model.c em_dev_update_perf_domain() 表交换后调用。
 * 空实现不改表。
 */
void ai_power_em_hook(struct device *dev, struct em_perf_table *table);

/**
 * ai_power_thermal_hook() - AI 预测温度趋势，提前降频防过热
 * @zone: 热区名
 * @temperature: 当前温度（m°C）
 * @last_temperature: 上次温度（m°C）
 * @target_temp: 出参/入参；AI 建议的降频起始温度（空实现不改）
 *
 * 由 drivers/thermal/thermal_core.c __thermal_zone_device_update() 温度更新后调用。
 * 空实现不改。
 */
void ai_power_thermal_hook(const char *zone, int temperature,
			   int last_temperature, int *target_temp);

/**
 * ai_power_qos_hook() - AI 评估 QoS 约束合理性
 * @qos_type: enum pm_qos_type（PM_QOS_MIN/MAX/SUM）
 * @action: enum pm_qos_req_action（ADD/UPDATE/REMOVE）
 * @prev_value: 变更前聚合值
 * @curr_value: 出参/入参；变更后聚合值（AI 可改写）
 *
 * 由 kernel/power/qos.c pm_qos_update_target() 解锁后调用。空实现不改。
 */
void ai_power_qos_hook(int qos_type, int action, int prev_value,
		       int *curr_value);

/**
 * ai_power_wakelock_hook() - AI 预测 wakeup 事件，预唤醒
 * @name: 唤醒锁名
 * @len: 名字长度
 * @timeout_ns: 超时（0=无限）
 * @action: 1=acquire 2=release
 *
 * 由 kernel/power/wakelock.c pm_wake_lock()/pm_wake_unlock() capable 校验后调用。
 * 空实现无操作（AI 预唤醒决策预留位）。
 */
void ai_power_wakelock_hook(const char *name, size_t len, u64 timeout_ns,
			    u8 action);

/* ---- 第12类发射辅助（实现见 ai_power.c；全部 sample_take + emit_direct） ---- */

void ai_telemetry_cpufreq_change(u16 cpu, u32 old_freq, u32 new_freq,
				 u8 relation, const char *governor);
void ai_telemetry_cpuidle_state(u16 cpu, u32 state_idx, u64 residency_ns,
				const char *state_name);
void ai_telemetry_energy_model(const char *dev_name, u32 nr_states,
			       const u32 *freq_khz, const u32 *power_mw);
void ai_telemetry_thermal_trend(const char *zone, s32 temperature,
				s32 last_temperature);
void ai_telemetry_qos_constraint(u8 qos_type, u8 action, s32 prev_value,
				 s32 curr_value);
void ai_telemetry_wakelock_event(u8 action, u64 timeout_ns, const char *name,
				 size_t len);

/* ---- 决策框架 ---- */

void ai_power_stats_read(struct ai_power_stats *st);
bool ai_power_sample_take(u32 rate);

/* ---- 可控参数访问器（power.freq/cstate/wakeup；vmscan swappiness 范式） ----
 * freq 实现于 ai_cpufreq.c（aiguard 频率上限万分比 0..10000，0=不受限，
 * 请求/钳制计数供观测面）；cstate/wakeup 实现于 ai_power.c（PM QoS
 * cpu_dma_latency 档位、sched_wakeup tracepoint 唤醒事件采集门控） */
unsigned int ai_aiguard_freq_max_pct_get(void);
void ai_aiguard_freq_max_pct_set(unsigned int pct);
void ai_aiguard_freq_stats_read(u64 *requests, u64 *clamped);
bool ai_power_wakeup_capture_is_enabled(void);
void ai_power_wakeup_stats_read(bool *on, u64 *events);

#else /* !CONFIG_AIKERNEL_POWER */

/* 空函数兜底：CONFIG_AIKERNEL_POWER=n 时调用点不编译，
 * 此处兜底仅供 AIKernel/ 内部其他模块引用时保持可编译。 */
static inline void ai_power_cpufreq_hook(struct cpufreq_policy *policy,
					 u64 time, unsigned long util,
					 unsigned long max,
					 unsigned int *freq)
{ }
static inline void ai_power_cpuidle_hook(int cpu, int state_count,
					 u64 latency_req_ns, u64 *predicted_ns,
					 int *idx)
{ }
static inline void ai_power_em_hook(struct device *dev,
				    struct em_perf_table *table)
{ }
static inline void ai_power_thermal_hook(const char *zone, int temperature,
					 int last_temperature,
					 int *target_temp)
{ }
static inline void ai_power_qos_hook(int qos_type, int action,
				     int prev_value, int *curr_value)
{ }
static inline void ai_power_wakelock_hook(const char *name, size_t len,
					  u64 timeout_ns, u8 action)
{ }
static inline void ai_telemetry_cpufreq_change(u16 cpu, u32 old_freq,
					       u32 new_freq, u8 relation,
					       const char *governor)
{ }
static inline void ai_telemetry_cpuidle_state(u16 cpu, u32 state_idx,
					      u64 residency_ns,
					      const char *state_name)
{ }
static inline void ai_telemetry_energy_model(const char *dev_name,
					     u32 nr_states,
					     const u32 *freq_khz,
					     const u32 *power_mw)
{ }
static inline void ai_telemetry_thermal_trend(const char *zone,
					      s32 temperature,
					      s32 last_temperature)
{ }
static inline void ai_telemetry_qos_constraint(u8 qos_type, u8 action,
					       s32 prev_value, s32 curr_value)
{ }
static inline void ai_telemetry_wakelock_event(u8 action, u64 timeout_ns,
					       const char *name, size_t len)
{ }
static inline void ai_power_stats_read(struct ai_power_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }
static inline bool ai_power_sample_take(u32 rate)
{ return false; }

#endif /* CONFIG_AIKERNEL_POWER */

#endif /* _AIKERNEL_POWER_AI_POWER_H */
