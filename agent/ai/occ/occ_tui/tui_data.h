/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_data.h - /tools /trace /lease 数据读取器（T9c3；纯文件解析）
 *
 * 只读消费系统现成数据（tools.json 注册表 / trace JSONL / 租约目录），
 * 产出 overlay items。链接 aik_json（store 库）——**只入 occ 主程序与
 * occ 级单测**，不进 occ_tui 库（保住 occ_tui「只有 libc」头注）。
 *
 * 路径族（产品配置路径，OCC_MODEL_TOML 先例；报告 §数据文件）：
 *   tools.json: AIKERNEL_TOOLS_JSON → ./tools.json → tools/tools.json
 *               → /proc/self/exe 目录 → /usr/local/share/aikernel/tools.json
 *               （与 shell tool_registry_load 同链 + exe 锚定）
 *   trace:      OCC_TRACE_DIR → ~/.occ/trace
 *   lease:      AIKERNEL_LEASE_DIR → /var/lib/aikernel/leases
 *               （与 policy/ai_lease.c ai_lease_store_dir 同口径）
 *
 * 返回约定：0=成功（*n 可为 0=空数据）；-1=失败（err 人话）。
 * 解析容错：单条记录坏 → 跳过计数不炸；目录不存在按空处理（ENOENT→0）。
 * lease 为**展示级轻量校验**（lstat 拒符号链接），非 ai_lease_load 全套
 * fail-closed 安全校验——签发/撤销仍走系统命令（台账裁定 9）。
 */
#ifndef OCC_TUI_DATA_H
#define OCC_TUI_DATA_H

#include <stddef.h>

#include "tui_overlay.h"

#ifdef __cplusplus
extern "C" {
#endif

/* items 数组释放（三个 load 的 *out 统一出口；NULL 安全） */
void tui_data_items_free(tui_ov_item *items);

/* ---- tools.json ---- */
int tui_data_tools_path(char *buf, size_t cap);
int tui_data_tools_load(const char *path, tui_ov_item **out, int *n,
			char *err, size_t errlen);

/* ---- trace（尾部 max_lines 行，新在前） ---- */
int tui_data_trace_dir(char *buf, size_t cap);
int tui_data_trace_load(const char *dir, int max_lines, tui_ov_item **out,
			int *n, char *err, size_t errlen);

/* ---- lease ---- */
int tui_data_lease_dir(char *buf, size_t cap);
int tui_data_lease_load(const char *dir, tui_ov_item **out, int *n,
			char *err, size_t errlen);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_DATA_H */
