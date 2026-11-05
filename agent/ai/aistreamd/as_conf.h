/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_conf.h - aistreamd 配置（KEY=VALUE 扁平格式，风格对齐 aikd.conf）
 *
 * 解析语义（严格，坏值拒绝）：
 *   - '#' 开头行与空行忽略；KEY=VALUE 一行一键；
 *   - 未知键、重复键、越界/非法值 → 返回错误（含行号与人可读原因），
 *     守护进程启动即退（exit 1）——绝不用默认值静默吞掉拼错的配置。
 */
#ifndef _AS_CONF_H
#define _AS_CONF_H

#include <stddef.h>

#define AS_CONF_PATH_DEFAULT	"/etc/aikernel/aistreamd.conf"

/* 流名（固定六路；统计/日志/标签都用这些名字） */
#define AS_STREAM_EVENT		"event"		/* NETLINK_AI REG→EVENT */
#define AS_STREAM_PROC		"proc"		/* CN_PROC */
#define AS_STREAM_NET		"net"		/* RTNLGRP */
#define AS_STREAM_UEVENT	"uevent"	/* KOBJECT_UEVENT */
#define AS_STREAM_NFLOG		"nflog"		/* NFLOG 单播 */
#define AS_STREAM_TASKSTATS	"taskstats"	/* 周期采样 */
#define AS_NSTREAMS		6

struct as_conf {
	/* SME 写入 */
	char sme_url[256];
	double importance;		/* 0 < x <= 1（默认 0.3） */
	long long sme_retry_sec;	/* 不可达后重试间隔（默认 5） */

	/* 配额（lease） */
	long long rate_per_min;		/* 全局每分钟写入上限（默认 60） */
	long long daily_max;		/* 全局日上限（默认 5000） */
	long long stream_daily_max;	/* 每路日上限（默认 1000） */
	long long dedup_window_ms;	/* 同 digest 去重窗口（默认 10000） */

	/* 降级环形缓冲 */
	long long ring_size;		/* 条数上限（默认 4096） */

	/* 每路开关 */
	int enable_event;
	int enable_proc;
	int enable_net;
	int enable_uevent;
	int enable_nflog;
	int enable_taskstats;

	/* taskstats 采样 */
	long long taskstats_interval_sec;	/* 默认 30 */
	long long taskstats_max_pids;		/* 每轮扫描上限（默认 256） */

	/* NETLINK_AI mock 通道（仅测试）：非 0 时用该协议号开 socket
	 * （如 2=NETLINK_USERSOCK），跳过 REG。默认 0=真 NETLINK_AI(31)。 */
	int ai_mock_proto;

	/* ---- K3d-2（I-9）：热插拔建议流水线（advisory-only，C7 红线：
	 * 设备移除/下线类动作永不自动执行；executed 恒 false） ---- */
	int hotplug_enabled;			/* 默认 0（出厂默认收口轮拍板） */
	char hotplug_model[64];		/* 模型名；空=未配 → infer 记
						 * skipped_unconfigured，流水线其余照走 */
	long long hotplug_daily_max;		/* advisory 日限（默认 200） */
	long long hotplug_infer_dim;		/* 特征向量维度（默认 8，1..64） */
	int hotplug_infer_mock;		/* 无 /sys/kernel/ai 时 1=确定性
						 * mock 前向（journal 明示 TEST
						 * ONLY）；0=skipped_noiface */
	char hotplug_log[256];		/* advisory JSONL 落盘路径 */

	/* 可观测 */
	long long stats_interval_sec;	/* stats 文件周期写（默认 10） */
	int log_debug;			/* 1=开 debug 日志 */

	/* 运行时路径 */
	char stats_file[256];
	char pid_file[256];
	char lock_file[256];
};

/* 填默认值（解析前调用） */
void as_conf_defaults(struct as_conf *c);

/*
 * as_conf_load - 解析配置文件。
 * 返回 0 成功；-1 失败且 err（容量 errcap）收到 "行号: 原因"。
 */
int as_conf_load(struct as_conf *c, const char *path, char *err, size_t errcap);

#endif /* _AS_CONF_H */
