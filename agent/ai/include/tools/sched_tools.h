/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sched_tools.h - W79 双调度台（sched 通道，五件工具）
 *
 * "两块台子并存——一块规则/固定参数，一块模型输出；一句话切换，两者
 *  可做 A/B 对照"（计划书 V2.1–V2.3）。本棒只做台子 + 旋钮 + 对照能力，
 * 不做 ML 模型（W83）：ml 台未就绪时必须明确拒绝，绝不假成功（C2）。
 *
 * 工具（5 件）：
 *   sched_status    (R)  一次看全：mode/生效参数集/cgroup 限额/PSI/旋钮清单
 *   sched_knob_set  (W1) 写单旋钮：范围校验 → 写 → 读回验证 → 期望/实际
 *   sched_mode_set  (W2) static|ml|off：切换前自动快照、切换后逐项读回
 *   sched_snapshot  (W1) save/list/restore 参数集快照（/var/lib/aikernel/
 *                        sched/snap-<ts>.json，0600）
 *   sched_ab_run    (W2) 2 参数集 × 3 档负载对照实验（硬超时 180s，
 *                        无论成败恢复实验前参数集，C6）
 *
 * 旋钮（10 个）：
 *   任务级（NETLINK_AI ACT，per-pid）：nice / affinity / oom_score /
 *     timeslice
 *   cgroup v2（/sys/fs/cgroup/aikernel-sched）：cpu.weight / cpu.max /
 *     cpu.max.burst / io.weight / io.max
 *   台子自身：sched.mode（static|ml|off）
 *
 * 所有值真读文件（写后 pread 读回比对），不由配置回显；读回不一致
 * 一律报失败并回滚，绝不"写成功"了事。
 */
#ifndef _AI_SCHED_TOOLS_H
#define _AI_SCHED_TOOLS_H

#include <stddef.h>

/* 旋钮种类（写路径不同，校验/读回口径也不同） */
enum ai_sched_knob_kind {
	AI_SCHED_KNOB_TASK = 1,		/* NETLINK_AI ACT（需 pid） */
	AI_SCHED_KNOB_CGROUP = 2,	/* cgroup v2 控制文件 */
	AI_SCHED_KNOB_MODE = 3,		/* sched.mode 自身 */
};

struct ai_sched_knob {
	const char *name;		/* 调用面旋钮名（如 cpu.max） */
	enum ai_sched_knob_kind kind;
	const char *param;		/* TASK：ACT 参数名（sched.nice） */
	const char *file;		/* CGROUP：控制文件名（cpu.max） */
	long long vmin;			/* 数值下界（TASK/简单 CGROUP） */
	long long vmax;			/* 数值上界 */
	const char *range;		/* 人类可读值域（status 展示） */
	const char *dflt;		/* 内核默认值（off/初始态） */
	/* 内核 ACT 取参口径：1 = AI_CTRL_F_TASK（data[0]=pid, data[1]=value），
	 * 0 = 全局参数（data[0]=value，如 sched.timeslice）。与内核
	 * core/ai_control.c:155 的判定一致；填错会把 pid 当值写进内核。 */
	int is_task;
};

int ai_sched_knob_count(void);
const struct ai_sched_knob *ai_sched_knob_at(int idx);
int ai_sched_knob_find(const char *name);	/* -1 = 未知旋钮 */

/* ---- 纯函数（导出供单测；不碰文件系统） ---- */

/* mode 合法名：static | ml | off */
int ai_sched_valid_mode(const char *s);

/* 单旋钮值校验：0=合法；-1=非法（err 填原因，含值域） */
int ai_sched_validate_value(const struct ai_sched_knob *k, const char *value,
			    char *err, size_t errlen);

/* 读回比对：0=一致；1=不一致（内核归一化/字段补全按旋钮口径处理） */
int ai_sched_value_match(const struct ai_sched_knob *k, const char *want,
			 const char *got);

/* 负载名清单解析：mask 位 0=cpu 1=io 2=mix；0=合法；-1=非法 */
int ai_sched_parse_loads(const char *s, int *mask);
const char *ai_sched_load_name(int bit);

/* ---- 执行器入口（executor.c 的 TOOL_CH_SCHED 分发调用） ---- */
int exec_sched_channel(const void *tool, const char *args_json, char **out);

#endif /* _AI_SCHED_TOOLS_H */
