/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_wal.h - 追加式 JSON WAL（T2b-1）
 *
 * 设计依据 T2-DESIGN.md §7.1。每条记录是 aik_json_dump 的紧凑 JSON 文本
 * 加 "\n" 后按顺序追加到文件；fsync_each 非零时每条追加后立即 fsync，
 * 保证崩溃后已确认的记录不丢。只写 LF，不写 CRLF（Linux 目标的参考实现
 * 就是纯 LF；冻结向量的 CRLF 只是 Windows 文本模式录制产物）。
 *
 * aik_wal_replay 只读：逐行解析，空行/纯空白行跳过（行号仍递增）；
 * 缺失 seq 视为 0（旧版无序号日志兼容），seq=0 永不因 checkpoint 跳过；
 * present seq 必须是 >= 0 的 JSON 整数，非整数或 <0 才算损坏。按 '\n'
 * 分行，行尾 '\r' 由 JSON 解析器按空白接受，因此读取兼容 LF 与 CRLF。
 * 任一行损坏或回调失败返回 -1，错误形如 "wal: record N: ..."（N 为 1
 * 起的行号），绝不截断或删除日志文件；文件不存在时返回 0。
 */
#ifndef _AIK_STORE_WAL_H
#define _AIK_STORE_WAL_H

#include <stddef.h>

#include "store/store_json.h"

/* 不透明写句柄 */
typedef struct aik_wal aik_wal;

/*
 * aik_wal_open - 打开（不存在则创建）追加式 WAL
 *
 * 成功返回句柄（调用者 aik_wal_close）；失败返回 NULL 并写 err
 * "wal: ..."。fsync_each 非零 → 每次 append 后 fsync。
 */
aik_wal *aik_wal_open(const char *path, int fsync_each,
		      char *err, size_t errlen);

/*
 * aik_wal_append - 追加一条记录
 *
 * 写入 aik_json_dump(op) + "\n"（O_APPEND 下次追加，单条记录一次逻辑
 * write）；fsync_each 时随后 fsync。成功返回 0，失败 -1 并写 err。
 */
int aik_wal_append(aik_wal *w, const aik_json *op, char *err, size_t errlen);

/*
 * aik_wal_reset - checkpoint 后截断日志（T4e-D）
 *
 * ftruncate(fd, 0) + fsync，并把 append 计数清零；seq 由调用方（引擎）持有，
 * store 不解释也不保存它（参考 wal.reset 只删文件，sequence 属引擎状态）。
 * 成功 0；失败 -1 并写 err "wal: ..."（日志保留，调用方必须把 reset 失败
 * 当作 checkpoint 失败，不能报告已落盘）。
 */
int aik_wal_reset(aik_wal *w, char *err, size_t errlen);

/* 自 open（或最近一次 reset）以来成功 append 的条数（未 open 返回 0） */
long long aik_wal_ops(const aik_wal *w);

/* 关闭并释放句柄；成功 0，close 失败 -1（句柄总是被释放） */
int aik_wal_close(aik_wal *w);

/*
 * aik_wal_visit - replay 回调
 *
 * 收到未被 checkpoint 跳过的 op（seq=0 总是回调；DOM 只在回调期间有效，
 * 不得持有）；返回非 0 中止 replay 并把 err 内容带进
 * "wal: record N: ..."。
 */
typedef int (*aik_wal_visit)(void *ctx, const aik_json *op,
			     char *err, size_t errlen);

/*
 * aik_wal_replay - 只读重放
 *
 * 成功返回回调次数（>=0）；失败 -1 并写 err，日志文件保持原样；文件
 * 不存在返回 0。checkpoint 为已落盘快照的序号：seq <= checkpoint 且
 * seq != 0 的记录跳过（缺失 seq / seq=0 总是重放）。
 */
int aik_wal_replay(const char *path, long long checkpoint,
		   aik_wal_visit fn, void *ctx,
		   char *err, size_t errlen);

/*
 * aik_wal_replay_ex - 同 aik_wal_replay，另回传行号与最大序号（T4e-D）
 *
 * *out_record 在返回时总是被写：失败时为出错记录（1 起，与 err 里的 N 一致），
 * 成功时为最后一条被检查的行号（空文件/文件不存在为 0）。*out_last_seq
 * 为扫描到的最大 seq（含被 checkpoint 跳过的记录；缺失 seq 记 0），引擎用
 * 它把 wal.sequence 推进到参考 replay() 的 max(sequence, seq)。两个出参都
 * 可为 NULL。replay 语义与 aik_wal_replay 完全相同（不截断、不删除）。
 */
int aik_wal_replay_ex(const char *path, long long checkpoint,
		      aik_wal_visit fn, void *ctx, long long *out_record,
		      long long *out_last_seq, char *err, size_t errlen);

#endif /* _AIK_STORE_WAL_H */
