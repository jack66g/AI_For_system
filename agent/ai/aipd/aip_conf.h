/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_conf.h - aipd 配置（KEY=VALUE 扁平格式；解析风格对齐 as_conf：
 * '#' 注释/空行忽略；未知键、重复键、越界/非法值 → 错误含行号原因，
 * 守护启动 exit 1——绝不用默认值静默吞掉拼错的配置）
 */
#ifndef _AIP_CONF_H
#define _AIP_CONF_H

#include <stddef.h>

#define AIP_CONF_PATH_DEFAULT	"/etc/aikernel/aipd.conf"

/* 特征源 */
#define AIP_SRC_MAP35		"map35"
#define AIP_SRC_MOCK		"mock"

struct aip_conf {
	/* 特征输入 */
	int feat_source;			/* 0=map35 1=mock（FEAT_SOURCE） */
	char feat_mock_file[256];		/* FEAT_MOCK_FILE（mock 源必填） */
	int feat_degrade_mock;			/* map35 失败：0=诚实 exit 1
						 * （默认）1=降级 mock+计数 */
	long long poll_hz;			/* 特征轮询频率（默认 10，1..1000）*/

	/* 模型表 */
	/* MODEL_TABLE=builtin 恒（M1 内置表；生成器产物同编——值仅此一种） */

	/* 影子（M1 冻结：SHADOW 恒 1——无 ACT 下发代码路径，置 0=拒绝） */
	int shadow;

	/* 落盘/对照 */
	char parquet_dir[256];			/* 影子根（默认 /var/lib/aikernel；
						 * 布局 <dir>/aipd/<UTC日>/
						 * shadow_NNNN.parquet） */
	long long shadow_flush_sec;		/* 影子批写节流秒（默认 10） */
	long long shadow_flush_rows;		/* 影子批写节流行（默认 128） */
	int compare_enabled;			/* 对照流消费（默认 0=关） */
	int compare_mock;			/* 对照源：0=/proc/ai/decisions
						 * 1=mock jsonl（TEST ONLY）*/
	char compare_mock_file[256];		/* mock 对照流文件 */
	long long compare_interval_sec;		/* 对照轮询间隔（默认 5） */
	long long cmp_window;			/* mismatch 滚动窗容量
						 * （默认 256） */

	/* 可观测 */
	long long stats_interval_sec;		/* stats 周期写秒（默认 10） */
	int log_debug;				/* 1=debug 日志 */

	/* 运行时路径（测试隔离用） */
	char stats_file[256];
	char pid_file[256];
	char lock_file[256];

	/* 金丝雀（M2 设计册 §6；CANARY_ENABLED=0=禁用——守护行为与 M1
	 * 等价：无 REG/无下发/无 canary 计数） */
	int canary_enabled;			/* 0|1（默认 0） */
	char canary_table[256];		/* B 表 AIPTBL 文件绝对路径
						 * （""=无 B 表=B 即 A；aikctl
						 * release --stage shadow 先落
						 * 此键再拍板 ENABLED——staged
						 * 未 armed 合法态） */
	long long canary_rollback_ms;		/* armed 批自动回退窗 ms
						 * （100..600000，默认 30000；
						 * 亦=confirm 期限） */
	long long canary_confirm_sec;		/* condition-abated 检查节拍
						 * 上限秒（1..3600，默认 10；
						 * 非 confirm 期限） */
	long long canary_min_interval_sec;	/* 两次下发最小间隔秒
						 * （1..3600，默认 30） */
};

/* 填默认值（解析前调用） */
void aip_conf_defaults(struct aip_conf *c);

/* 解析（同 as_conf_load 语义）。0 成功；-1 失败且 err 收 "行号: 原因"。 */
int aip_conf_load(struct aip_conf *c, const char *path, char *err,
		  size_t errcap);

#endif /* _AIP_CONF_H */
