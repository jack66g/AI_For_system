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

#endif /* _AIK_STORE_WAL_H */
