/* SPDX-License-Identifier: GPL-2.0 */
/*
 * apiredact.h - /sense 暴露侧遥测脱敏（设计 SENSE-REDACT-DESIGN §2.1/§3）
 *
 * 位置：apiv2.c api_do_sense 在 utf8 解码后、limit 截断前调用
 * api_sense_redact_text()；off 档恒等（api_do_sense 零字节差——
 * aikapi 重放门/差分向量的前提）。
 *
 * 配置（每次 /sense 请求解析，与 api_effective_token 的 config 读频
 * 同量级）：model.toml `sense_redact = off|soft|strict`（默认 off），
 * env AIK_SENSE_REDACT 覆盖（测试；先例 AIK_DISABLE_URANDOM）；
 * 盐 sense_redact_salt / env AIK_SENSE_REDACT_SALT（默认空）。
 *
 * 字段表（设计 §2.1）：
 *   telemetry: pid/tgid → hash(hash)；data → trunc(soft 8 hex)/drop
 *   status:   model_path: → hash/drop；models 行 name= → hash/drop
 *   chains/decisions: data → pass/mask；id/ts 全 pass（审计链例外：
 *   decision_id 恒原样）
 *   control/latency/hitrate/sched/vfs: 纯计数，整体 pass
 * 未知键（telemetry/chains/decisions 行内）：pass + 计数（不静默吞）。
 */
#ifndef _APIC_APIREDACT_H
#define _APIC_APIREDACT_H

#include <stddef.h>

/* 档位（与 aistreamd as_redact.h 枚举同值——语义对齐由对拍测试锁） */
#define API_REDACT_OFF		0
#define API_REDACT_SOFT		1
#define API_REDACT_STRICT	2

/* 策略 */
#define API_R_PASS	0
#define API_R_HASH	1
#define API_R_TRUNC	2
#define API_R_MASK	3
#define API_R_DROP	4

/* 进程内观测计数（单线程 accept 循环；无锁） */
struct api_redact_stats {
	long long applied;	/* 非 pass 变换次数 */
	long long unknown_pass;	/* 未知键透传次数 */
	long long lines_in;	/* 处理行数（含 pass-through 行） */
};

struct api_redact_stats *api_redact_stats(void);

/*
 * api_sense_redact_level - 解析当前档位（env > model.toml > off）。
 * salt_out 非 NULL 时写入当前盐（容量 saltcap；截断安全）。
 */
int api_sense_redact_level(char *salt_out, size_t saltcap);

/*
 * api_sense_redact_text - 按 what 脱敏 procfs 文本。
 * 返回 malloc 新串（NUL 结尾；*out_len 收字节长度——输入可能极长，
 * 靠 NUL 定界不安全？/sense 文本经 api_utf8_decode_replace 后 NUL
 * 安全，此处仍如实回长度）；off 档返回 strdup 原文（语义等价直通）。
 * 失败返回 NULL（调用方回退原文——脱敏失效宁可漏过也不吞 /sense）。
 */
char *api_sense_redact_text(const char *what, const char *text,
			    size_t text_len, size_t *out_len);

/* 值级变换（引擎导出：单测对拍 aistreamd as_redact 同公式） */
size_t api_redact_str(char *out, size_t cap, int strat, const char *salt,
		      const char *value);
unsigned long long api_redact_fnv64(const char *salt, const char *value);

#endif /* _APIC_APIREDACT_H */
