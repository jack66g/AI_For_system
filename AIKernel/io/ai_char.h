// SPDX-License-Identifier: GPL-2.0
/*
 * ai_char.h - AIKernel 字符设备核心统一接口头（Prompt 05）
 *
 * 字符设备层 AI 埋点（重构计划 模块4 任务 4.8~4.10）：
 *   A 轨（控制）：ai_io_entropy_hook() 熵源质量评估（drivers/char/random.c）、
 *                 ai_io_tty_hook() 用户输入预判（drivers/tty/tty_io.c）；
 *   B 轨（感知）：第3类 3.6 字符设备 I/O 事件（char_dev_open/read/write）
 *                 + entropy 子事件，全量原始零脱敏（device_name/bytes/pid/comm）。
 *
 * 采集点：
 *   - char_dev_open：fs/char_dev.c chrdev_open()（全字符设备打开）
 *   - char_dev_read/write：drivers/char/random.c random_read_iter()/
 *     random_write_iter() + drivers/tty/tty_io.c tty_read()/tty_write()
 *     （fs/char_dev.c 无 read/write 路径——字符设备读写由 VFS 直接分发到驱动
 *       fops，本步由 random/tty 两个代表性字符设备类覆盖，通用读写事件由
 *       VFS Prompt 归口）
 *   - entropy：drivers/char/random.c mix_pool_bytes()（1/64 采样）
 *
 * 零回归策略：CONFIG_AIKERNEL_IO=n 时本头文件不参与编译（各 .c 文件条件
 * include 一并剔除）；CONFIG_AIKERNEL_TELEMETRY=n 时发射退化为空函数。
 *
 * 遥测函数铁律：不阻塞、不分配、无锁（mix_pool_bytes 在自旋锁内调用）。
 */

#ifndef _AIKERNEL_IO_AI_CHAR_H
#define _AIKERNEL_IO_AI_CHAR_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/string.h>

/* ==================================================================
 * B 轨：3.6 字符设备 I/O payload（AI_EV_CHAR_DEV，AI_CAT_IO）
 * ================================================================== */

enum ai_char_dev_type {
	AI_CHAR_OPEN		= 1,	/* 设备打开 */
	AI_CHAR_READ,			/* 设备读取 */
	AI_CHAR_WRITE,			/* 设备写入 */
	AI_CHAR_ENTROPY,		/* 熵源质量（random.c 扩展子事件） */
};

struct ai_char_open_payload {
	u8 type;			/* AI_CHAR_OPEN */
	char device_name[24];
	u32 pid;
	char comm[TASK_COMM_LEN];
};

struct ai_char_rw_payload {
	u8 type;			/* AI_CHAR_READ / AI_CHAR_WRITE */
	char device_name[24];
	u32 bytes;
	u32 pid;
	char comm[TASK_COMM_LEN];
};

struct ai_char_entropy_payload {
	u8 type;			/* AI_CHAR_ENTROPY */
	char device_name[24];
	u32 len;			/* 本次混入池字节数 */
	u32 credit_bits;		/* 当前累计熵位数（init_bits） */
};

#ifdef CONFIG_AIKERNEL_IO

/* ---- A 轨：推理/控制 Hook（ai_char.c 实现，EXPORT_SYMBOL_GPL） ---- */

/**
 * ai_io_char_stats_read() - 字符设备 Hook 决策计数读取
 * @entropy_calls: 熵源 Hook 调用次数
 * @tty_calls:     TTY Hook 调用次数
 *
 * 由 ai_io_stats_read()（ai_block.c）汇总进 ai_io_stats。
 */
void ai_io_char_stats_read(u64 *entropy_calls, u64 *tty_calls);

/**
 * ai_io_entropy_hook() - AI 辅助熵源质量评估
 * @len:         本次混入池的字节数
 * @credit_bits: 建议的熵位数（AI 可修改；空实现不改）
 *
 * 在 random.c mix_pool_bytes() 调用；空实现不干预。
 */
void ai_io_entropy_hook(size_t len, unsigned int *credit_bits);

struct tty_struct;	/* linux/tty.h，前向声明 */

/**
 * ai_io_tty_hook() - AI 预判用户输入
 * @tty:        终端设备
 * @prediction: 预判结果输出（0=无预判；非 0=AI 预判有输入）
 *
 * 在 tty_io.c tty_read() 入口调用；空实现不改（恒 0）。
 */
void ai_io_tty_hook(struct tty_struct *tty, u8 *prediction);

/* ---- B 轨：发射辅助（ai_char.c 实现，EXPORT_SYMBOL_GPL） ---- */

void ai_io_emit_char_open(const char *device_name);
void ai_io_emit_char_read(const char *device_name, u32 bytes);
void ai_io_emit_char_write(const char *device_name, u32 bytes);
void ai_io_emit_entropy(const char *device_name, size_t len,
			unsigned int credit_bits);

#else /* !CONFIG_AIKERNEL_IO */

/* 空函数兜底：防御性提供，零开销 */

static inline void ai_io_char_stats_read(u64 *entropy_calls, u64 *tty_calls)
{
	if (entropy_calls)
		*entropy_calls = 0;
	if (tty_calls)
		*tty_calls = 0;
}
static inline void ai_io_entropy_hook(size_t len,
				      unsigned int *credit_bits) { }
static inline void ai_io_tty_hook(struct tty_struct *tty,
				  u8 *prediction) { }
static inline void ai_io_emit_char_open(const char *device_name) { }
static inline void ai_io_emit_char_read(const char *device_name,
					u32 bytes) { }
static inline void ai_io_emit_char_write(const char *device_name,
					 u32 bytes) { }
static inline void ai_io_emit_entropy(const char *device_name, size_t len,
				      unsigned int credit_bits) { }

#endif /* CONFIG_AIKERNEL_IO */

#endif /* _AIKERNEL_IO_AI_CHAR_H */
