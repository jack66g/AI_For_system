// SPDX-License-Identifier: GPL-2.0
/*
 * ai_char.c - AIKernel 字符设备核心（Prompt 05）
 *
 * A 轨：ai_io_entropy_hook()（熵源质量评估，空实现不改）、
 *       ai_io_tty_hook()（用户输入预判，空实现不改）+ 决策计数。
 * B 轨：3.6 字符设备 I/O 事件发射辅助（sample_take + emit_direct 直写）。
 *
 * 门控：CONFIG_AIKERNEL_IO。CONFIG_AIKERNEL_TELEMETRY=n 时本文件仍编译
 * （Hook 计数 + 空放行），发射辅助退化为无操作。
 *
 * 铁律：发射路径无锁、无分配、不睡眠（mix_pool_bytes 在自旋锁内调用，
 * TTY/random 读写在进程上下文）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "ai_char.h"

/* ---- 决策计数（per-CPU，ai_io_stats_read 汇总） ---- */

static DEFINE_PER_CPU(u64, ai_char_entropy_calls);
static DEFINE_PER_CPU(u64, ai_char_tty_calls);

void ai_io_char_stats_read(u64 *entropy_calls, u64 *tty_calls)
{
	int cpu;

	*entropy_calls = 0;
	*tty_calls = 0;
	for_each_possible_cpu(cpu) {
		*entropy_calls += per_cpu(ai_char_entropy_calls, cpu);
		*tty_calls += per_cpu(ai_char_tty_calls, cpu);
	}
}
EXPORT_SYMBOL_GPL(ai_io_char_stats_read);

/* ==================================================================
 * A 轨：Hook 空实现（= 原样放行）
 * ================================================================== */

void ai_io_entropy_hook(size_t len, unsigned int *credit_bits)
{
	this_cpu_inc(ai_char_entropy_calls);
}
EXPORT_SYMBOL_GPL(ai_io_entropy_hook);

void ai_io_tty_hook(struct tty_struct *tty, u8 *prediction)
{
	this_cpu_inc(ai_char_tty_calls);
}
EXPORT_SYMBOL_GPL(ai_io_tty_hook);

/* ==================================================================
 * B 轨：3.6 字符设备事件发射辅助
 * ================================================================== */

static void ai_char_fill(struct ai_char_rw_payload *p, u8 type,
			 const char *device_name, u32 bytes)
{
	p->type = type;
	strscpy(p->device_name, device_name ? device_name : "?",
		sizeof(p->device_name));
	p->bytes = bytes;
	p->pid = task_pid_nr(current);
	strscpy(p->comm, current->comm, TASK_COMM_LEN);
}

void ai_io_emit_char_open(const char *device_name)
{
	struct ai_char_open_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_CHAR_DEV))
		return;

	p.type = AI_CHAR_OPEN;
	strscpy(p.device_name, device_name ? device_name : "?",
		sizeof(p.device_name));
	p.pid = task_pid_nr(current);
	strscpy(p.comm, current->comm, TASK_COMM_LEN);
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_CHAR_DEV, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_char_open);

void ai_io_emit_char_read(const char *device_name, u32 bytes)
{
	struct ai_char_rw_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_CHAR_DEV))
		return;

	ai_char_fill(&p, AI_CHAR_READ, device_name, bytes);
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_CHAR_DEV, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_char_read);

void ai_io_emit_char_write(const char *device_name, u32 bytes)
{
	struct ai_char_rw_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_CHAR_DEV))
		return;

	ai_char_fill(&p, AI_CHAR_WRITE, device_name, bytes);
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_CHAR_DEV, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_char_write);

void ai_io_emit_entropy(const char *device_name, size_t len,
			unsigned int credit_bits)
{
	struct ai_char_entropy_payload p;

	/* 熵源评估低频（1/64，ai_io_init 设定） */
	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_CHAR_DEV))
		return;

	p.type = AI_CHAR_ENTROPY;
	strscpy(p.device_name, device_name, sizeof(p.device_name));
	p.len = (u32)len;
	p.credit_bits = credit_bits;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_CHAR_DEV, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_entropy);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AIKernel char device core: hooks + class-3 char telemetry");
