/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_redact.h - SENSE 遥测脱敏引擎（产生侧；设计 SENSE-REDACT-DESIGN §3）
 *
 * 五档值级策略 + 三态全局开关（off/soft/strict）+ 可选盐：
 *   pass  原值恒等（off 档=全 pass，字节零变化——差分/冻结 fixture 前提）
 *   hash  "h:<FNV-1a64 16hex>"，盐参与（FNV-1a64(salt||0x01||value)）；
 *         诚实声明：无盐时低熵值（pid）可枚举——定位是去标识化+保关联，
 *         不是密码学匿名（设计 §3.1）
 *   trunc 前 8 字符 + "~<原长>"（仅 telemetry data hex 类）
 *   mask  首字符 + "***"（空值→"***"）
 *   drop  键保留值置 "-"（可见的删除，不静默吞字段）
 *
 * 策略表：设计 §2.2（stream × 字段 × soft/strict），静态内嵌于
 * as_event.c 构造器调用点（字段类型在调用点已知，无需字符串查表）；
 * decision_id 恒原样（K3-DESIGN §K3c 审计链冻结契约，例外写死）。
 *
 * 单线程守护语义：level/salt 为进程级全局，启动时 as_redact_set 一次
 * （aistreamd.c conf 装载后）；测试可多次重置。off 快路径=一次 int
 * 比较，零格式化。
 */
#ifndef _AS_REDACT_H
#define _AS_REDACT_H

#include <stdint.h>
#include <stddef.h>

/* 三态开关（conf SENSE_REDACT；默认 AS_REDACT_OFF=单用户现状） */
enum as_redact_level {
	AS_REDACT_OFF = 0,
	AS_REDACT_SOFT = 1,
	AS_REDACT_STRICT = 2,
};

/* 策略标识（值级变换种类；off/soft/strict 映射见设计 §2.2 表） */
enum as_redact_strat {
	AS_R_PASS = 0,		/* 透传 */
	AS_R_HASH = 1,		/* 哈希化 h:<16hex> */
	AS_R_TRUNC = 2,		/* 截断 前8字符+~<len> */
	AS_R_MASK = 3,		/* 掩码 首字符+*** */
	AS_R_DROP = 4,		/* 丢弃 键保留值置 "-" */
};

/* 计数器（stats 文件 sense_redact.* 段；A/B 与泄漏扫描的观测口径） */
struct as_redact_stats {
	long long applied;		/* 非 pass 变换次数（hash/trunc/
					 * mask/drop 之和） */
	long long hashed;
	long long truncated;
	long long masked;
	long long dropped;
	long long unknown_pass;		/* 未知键透传计数（设计 §3.5：
					 * 不静默吞，计数提示升级字段表） */
};

/* 全局设置（启动一次；salt NULL/""=无盐确定性格式）。0=成功。 */
void as_redact_set(int level, const char *salt);

/* 当前 level（0/1/2） */
int as_redact_level(void);

/* 计数器（进程级单例；直接读，无锁——单线程守护） */
struct as_redact_stats *as_redact_stats(void);

/*
 * as_redact_str - 按策略变换字符串值。
 * out 容量不足时安全截断（返回写入长度不含 NUL；调用方缓冲 AS_LINE_MAX
 * 级，脱敏产物恒不长于 原长+20）。value NULL → 按空串处理。
 */
size_t as_redact_str(char *out, size_t cap, int strat, const char *value);

/*
 * as_redact_int - 整数值（pid/uid 等）按策略变换；十进制化后同
 * as_redact_str 语义（hash 对十进制串散列——等值 join 语义保留）。
 */
size_t as_redact_int(char *out, size_t cap, int strat, long long value);

/*
 * as_redact_pid_col - T8 parquet pid 列脱敏（设计 §4.2）：
 * off → 原值；hash → (u32)(fnv64(十进制串) & 0x7fffffff)，非零保
 * 「无主体=0」语义；pid<=0 原样。
 */
int as_redact_pid_col(int pid);

/* FNV-1a64（盐参与；引擎内部，测试对拍需要而导出） */
uint64_t as_redact_fnv64(const char *salt, const char *value);

#endif /* _AS_REDACT_H */
