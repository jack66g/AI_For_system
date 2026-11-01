/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_snapshot.h - engine.json[.gz] 快照读路径（T2a）
 *
 * 设计依据 T2-DESIGN.md §5。aik_snapshot_load 自动识别 gzip（后缀 .gz
 * 或文件头 1f 8b）与明文 JSON：前者先 inflate，再统一解析成 DOM；文本
 * 缓冲与 DOM 都由本模块持有，aik_snapshot_free 一起释放。
 *
 * aik_snapshot_validate 只做 T2a 关心的结构门禁：schema_version==2、
 * memories/regions/region_edges/memory_edges/config 齐备且类型正确、
 * embedding_file 是安全的 basename（无路径分隔符、无 ".."）。
 */
#ifndef _AIK_STORE_SNAPSHOT_H
#define _AIK_STORE_SNAPSHOT_H

#include <stddef.h>

#include "store/store_json.h"

typedef struct {
	unsigned char *json;	/* malloc，解压/读取后的 UTF-8 JSON 文本（带 NUL） */
	size_t json_len;
	aik_json *root;		/* 解析后的 DOM */
} aik_snapshot;

/*
 * aik_snapshot_load - 读取并解析快照
 *
 * 成功返回 0（out 已填好，调用者 aik_snapshot_free）；失败返回 -1，err
 * 给出 "snapshot: ..." 原因，out 处于可 free 的空状态。
 */
int aik_snapshot_load(const char *path, aik_snapshot *out,
		      char *err, size_t errlen);

/* 释放文本与 DOM；NULL 安全，可重复调用 */
void aik_snapshot_free(aik_snapshot *s);

/*
 * aik_snapshot_validate - 结构校验
 *
 * 成功返回 0；失败返回 -1 并写 err。
 */
int aik_snapshot_validate(const aik_snapshot *s, char *err, size_t errlen);

/*
 * aik_snapshot_save - 原子写快照
 *
 * 把 root 写成紧凑 JSON：gzip 非零时 aik_gzip_deflate(level 9)，否则
 * 明文。同目录 path.tmp.<pid> → fsync → rename → 目录 fsync。成功 0，
 * 失败 -1 并写 "snapshot: ..." 原因（临时文件尽力清理）。
 */
int aik_snapshot_save(const aik_json *root, const char *path, int gzip,
		      char *err, size_t errlen);

#endif /* _AIK_STORE_SNAPSHOT_H */
