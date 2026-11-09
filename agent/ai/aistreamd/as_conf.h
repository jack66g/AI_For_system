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

	/* ---- T8：Parquet 落盘链（aikd_lib.py C 化；宿主=aistreamd） ----
	 * 布局/schema 对齐 REF（见 as_parquet.h）。事件→行映射见
	 * as_pq_sink.h。默认关（本轮保守；出厂默认开留收口轮 ISO 拍板）。 */
	int parquet_enabled;			/* 默认 0；1=写 Parquet */
	char parquet_dir[256];			/* 数据根（默认
						 * /var/lib/aikernel，同 REF） */
	long long parquet_max_gb;		/* 保留上限（默认 2GB；超限删最老
						 * UTC 天目录，当天永不删，删前
						 * journal 列名，只删布局内文件） */
	long long parquet_flush_sec;		/* 批写节流：秒（默认 30） */
	long long parquet_flush_rows;		/* 批写节流：行（默认 128） */

	/* ---- I-10：决策闭环第 4 步 outcome 回填器（as_outcome.c；C3 纯注记
	 * 面，出厂默认关——设计 I10-METRIC-DESIGN §4.5/§6.4） ---- */
	int outcome_enabled;			/* 默认 0（出厂默认 off） */
	long long outcome_window_short_sec;	/* S 类窗口（默认 30） */
	long long outcome_window_long_sec;	/* L 类窗口（默认 300） */
	long long outcome_grace_sec;		/* 窗口后宽容（读口确认用，
						 * 默认 10——外部验收脚本
						 * 口径，模块内自校验即时） */
	long long outcome_max_pending;		/* pending 队容量（默认 256，
						 * 满丢旧+计数） */
	long long outcome_decisions_scan_max;	/* decisions 尾条反查最大行数
						 * （默认 64——557KB 全量读
						 * 成本截断，K1B-20 口径） */
	int outcome_write_sme;			/* 回填结果走既有 SME/parquet
						 * 管道（合成事件，默认 1） */
	char outcome_mock_root[256];		/* TEST ONLY：指标/decisions 树前缀
					 * （L1 无 AIKernel 内核的 mock 冒烟用；
					 * 生产恒默认 "/"——journal 明示 TEST） */
	int outcome_auto_rollback;		/* C4：WORSE 自动 rollback——
						 * 默认 0，且写路径本轮不实现
						 * （需单独拍板，置 1 仅 journal
						 * 提示） */

	/* ---- T8 遗留接线：/proc/ai/decisions 消费面（as_decisions.c；
	 * C1 只读轮询 + T8 parquet decisions 行 + 合成事件 18.01 口径；
	 * 默认关——与 HOTPLUG/OUTCOME/SENSE 新面节奏一致，ISO 拍板翻） ---- */
	int decisions_enabled;			/* 默认 0（建议与理由见
						 * aistreamd.conf 注释） */
	long long decisions_interval_sec;	/* 轮询间隔（默认 5，同 REF
						 * aikd POLL_SEC） */
	long long decisions_scan_max;		/* 单轮最大解析行数（默认 4096
						 * =内核 ring 全量） */
	long long decisions_batch_max;		/* 日批行容量（默认 8192；满
						 * 丢最旧+计数） */
	int decisions_write_sme;		/* 新决策合成事件走既有 SME/
						 * parquet 管道（默认 1） */
	char decisions_mock_root[256];		/* TEST ONLY：decisions 树前缀
						 * （L1 mock 冒烟用；生产恒
						 * 默认 "/"——journal 明示） */

	/* ---- SENSE 遥测脱敏（产生侧；设计 SENSE-REDACT-DESIGN §2.2/§5；
	 * 多用户前提，出厂默认 off=单用户现状零字节变化 ---- */
	int sense_redact_level;			/* 0=off 1=soft 2=strict
						 * （默认 0） */
	char sense_redact_salt[65];		/* hash 盐（默认空=确定性格式；
						 * ≤64B 非空白，不落遥测） */

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
