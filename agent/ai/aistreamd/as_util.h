/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_util.h - aistreamd 公共小工具（时间/FNV 哈希/限频日志/原子写文件）
 *
 * K3c（I-5+I-4+I-6）：常驻事件流 → SME 记忆。
 */
#ifndef _AS_UTIL_H
#define _AS_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* 单调时钟毫秒（窗口/超时计算用，不受系统时间跳变影响） */
long long as_now_mono_ms(void);

/* 单调时钟纳秒（K3d-2 infer 延迟 latency_ns 用） */
long long as_now_mono_ns(void);

/* 墙钟毫秒（事件 ts 用，epoch 毫秒） */
long long as_now_real_ms(void);

/*
 * as_fnv1a64 - FNV-1a 64bit。去重 digest 用（16 hex 表示）。
 * 输入为 (stream|category|text) 拼接（分隔符 \0），见 as_event.c。
 */
uint64_t as_fnv1a64(const char *s, size_t n);

/* digest → 16 字符小写 hex（out 容量 >= 17） */
void as_digest_hex(uint64_t d, char out[17]);

/*
 * as_warn_ratelimit - 限频日志（stderr → journald）。
 * 同 key 在 cooldown_ms 内只发一条（防刷屏；规格：超限丢并计数，
 * 不静默——journal 限频告警）。key 为静态字符串字面量。
 * 返回 1=本次已输出，0=被限频。
 */
int as_warn_ratelimit(const char *key, long long cooldown_ms,
		      const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/* 普通日志（无限频）：前缀 "aistreamd: " */
void as_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void as_log_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* debug 日志开关（conf LOG_DEBUG） */
void as_set_debug(int on);

/*
 * as_write_file_atomic - 原子写文件（tmp + rename），全有或全无。
 * 返回 0 成功；-1 失败（errno 有效）。
 */
int as_write_file_atomic(const char *path, const char *data, size_t len);

#endif /* _AS_UTIL_H */
