// SPDX-License-Identifier: GPL-2.0
/*
 * ai_audit.h - AIKernel AI 安全审计模块（审计关联 + 攻击链）
 *
 * 门控 CONFIG_AIKERNEL_SECURITY（default n）。
 * kernel/audit.c 在每个审计记录完成点（audit_log_end）把原始记录同步到
 * ai_audit_ingest()：AI 实时关联审计事件，构建攻击链（攻击链记录接口本步就位，
 * 查询/推理由后续步骤填充）。
 *
 * 零脱敏：审计记录原始字节（含路径、凭证上下文）全量进入 AI 视野；
 * 决策日志默认仅特权可读。
 */

#ifndef _AIKERNEL_AI_AUDIT_H
#define _AIKERNEL_AI_AUDIT_H

#include <linux/types.h>
#include "../core/ai_types.h"
#include "ai_lsm.h"

/* 攻击链关联表容量（无分配，spinlock 保护） */
#define AI_AUDIT_CHAIN_SLOTS	64
#define AI_AUDIT_CHAIN_DEPTH	8

#ifdef CONFIG_AIKERNEL_SECURITY

/**
 * ai_telemetry_audit_path() - 审计文件路径事件（8.4）
 * @full_path: 完整路径（d_path 结果，零脱敏）
 * @rec_type:  所属审计记录类型
 *
 * 由 kernel/audit.c audit_log_d_path() 调用。
 */
void ai_telemetry_audit_path(const char *full_path, u32 rec_type);

/**
 * ai_telemetry_audit_anomaly() - 审计异常事件（8.4）
 * @anomaly_type: 异常类型（lost/panic/backlog...）
 * @detail:       完整详情（原始文本，零脱敏）
 *
 * 由 kernel/audit.c audit_log_lost()/audit_panic() 调用。
 */
void ai_telemetry_audit_anomaly(const char *anomaly_type,
				const char *detail);

/**
 * ai_audit_ingest() - AI 审计关联分析入口
 * @rec_type: 审计记录类型（uapi AUDIT_* 值，如 AUDIT_SYSCALL=1300）
 * @data:     审计记录原始字节（零脱敏，≤4096）
 * @data_len: 原始字节长度
 *
 * 由 kernel/audit.c audit_log_end() 每个记录调用：原始记录写入 AI 审计
 * per-CPU ring + 类型分派发射 audit_syscall 遥测（成功/退出码从记录文本
 * 轻量解析，解析失败保留 raw 不报错）。
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_audit_ingest(u32 rec_type, const void *data, u32 data_len);

/**
 * ai_audit_chain_record() - 攻击链记录接口
 * @pid:    关联进程
 * @type:   链节点类型（0=普通 1=拒绝 2=异常 3=崩溃）
 * @detail: 节点详情（原始文本，零脱敏）
 *
 * 把 (pid, 类型序列) 写入攻击链关联表（满覆盖最旧）；AI 后续填充关联推理。
 * 返回 AI_OK 或负错误码。
 */
int ai_audit_chain_record(u32 pid, u8 type, const char *detail);

/**
 * ai_audit_stats_read() - 读取 AI 审计统计
 * @total:    已接收记录总数
 * @syscall:  audit_syscall 事件数
 * @path:     audit_path 事件数
 * @anomaly:  audit_anomaly 事件数
 * @chains:   攻击链条数
 *
 * 供 AI Runtime 读取。返回 AI_OK。
 */
int ai_audit_stats_read(u32 *total, u32 *syscall, u32 *path, u32 *anomaly,
			u32 *chains);

/**
 * ai_audit_capture_is_enabled() - AI 审计采集开关当前状态（sec.audit 参数）
 */
bool ai_audit_capture_is_enabled(void);

/**
 * ai_audit_capture_enable() - 切换 AI 审计采集（真开关：关后 ingest 不再
 * 入 ring/发射/建链，gate 丢弃计数供观测面）
 */
int ai_audit_capture_enable(bool on);

/**
 * ai_audit_gate_drops_read() - 采集关闭期间被 gate 丢弃的记录数
 */
u64 ai_audit_gate_drops_read(void);

#else /* !CONFIG_AIKERNEL_SECURITY */

static inline void ai_telemetry_audit_path(const char *full_path,
					   u32 rec_type) { }
static inline void ai_telemetry_audit_anomaly(const char *anomaly_type,
					      const char *detail) { }
static inline int ai_audit_ingest(u32 rec_type, const void *data, u32 data_len)
{ return AI_OK; }
static inline int ai_audit_chain_record(u32 pid, u8 type, const char *detail)
{ return AI_OK; }
static inline int ai_audit_stats_read(u32 *total, u32 *syscall, u32 *path,
				      u32 *anomaly, u32 *chains)
{
	if (total) *total = 0;
	if (syscall) *syscall = 0;
	if (path) *path = 0;
	if (anomaly) *anomaly = 0;
	if (chains) *chains = 0;
	return AI_OK;
}
static inline bool ai_audit_capture_is_enabled(void) { return true; }
static inline int ai_audit_capture_enable(bool on) { return AI_OK; }
static inline u64 ai_audit_gate_drops_read(void) { return 0; }

#endif /* CONFIG_AIKERNEL_SECURITY */

#endif /* _AIKERNEL_AI_AUDIT_H */
