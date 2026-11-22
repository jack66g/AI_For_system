/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_exit_marker.h - P-47/P-2a：occ 终局退出 marker 路径面+写面
 *
 * P-47 背景：fbterm 转手吞掉子进程退出码（occ 退 71 → aik-console 只
 * 见 fbterm 的 0）——71 出带外写 marker 文件，aik-console 在 rc 判定链
 * 之前消费（读后即焚）。
 *
 * P-2a per-user：uid==0 → /run/aik-occ-exit（P-47 原名，兼容不动）；
 * uid!=0 → /run/aik-occ-exit.<uid>（aik-console v9 按同一契约读）。
 * /run 不可写回落 /tmp 同名。OCC_EXIT_MARKER env 仅测试用（显式覆盖
 * 整路径，不做 uid 后缀——M1-M3 契约不变）。
 */
#ifndef _OCC_EXIT_MARKER_H
#define _OCC_EXIT_MARKER_H

#include <stddef.h>
#include <sys/types.h>

/*
 * occ_exit_marker_path - 路径选择（纯函数，可测）。
 * buf 写入选中路径（NUL 结尾），返回 buf。env_override 为
 * getenv("OCC_EXIT_MARKER") 的值（NULL/空=未设）——测试可直接传桩。
 */
const char *occ_exit_marker_path(char *buf, size_t buflen, uid_t uid,
				 const char *env_override);

/*
 * occ_exit_marker_write - 写 marker（含 /run→/tmp 回落）；成功 0。
 * path_out/path_out_len（可 NULL/0）回写实际使用的路径（供调用方
 * 人话报错）。零输出（诊断归调用方，occ.c 保持 stderr 口径）。
 */
int occ_exit_marker_write(uid_t uid, int code, const char *env_override,
			  char *path_out, size_t path_out_len);

#endif /* _OCC_EXIT_MARKER_H */
