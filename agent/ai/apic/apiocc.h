/* SPDX-License-Identifier: GPL-2.0 */
/*
 * apiocc.h - LT-BUG-007：/ask 的 occ 入口约定。
 *
 * 出厂镜像（T9e 换代）的 /usr/local/bin 只有 occ；aikernel-shell 时代的
 * /usr/local/bin/ai 已随出厂移除（agent/ai/build-rootfs.sh 的 .profile
 * exec 链同理指向 /usr/local/bin/occ）。apic 的 /ask 必须按 argv 直接
 * exec `occ -p <question>`（绝不拼 shell 命令串），answer = occ stdout。
 *
 * 路径优先级：AIKERNEL_OCC_BIN（测试/本地钻证指向假 occ；出厂不设置）>
 *             g_api.ai_bin（apimain 由同名变量/AIKERNEL_AI_BIN 初始化）>
 *             API_OCC_BIN_DEFAULT。
 */
#ifndef _AIK_APIC_OCC_H
#define _AIK_APIC_OCC_H

#include <stddef.h>

#include "apic/api.h"

#define API_OCC_BIN_DEFAULT "/usr/local/bin/occ"
#define API_OCC_BIN_ENV "AIKERNEL_OCC_BIN"

/* 当前生效的 occ 绝对路径（永不返回 NULL） */
const char *api_occ_bin(void);

/*
 * 跑一轮 `occ -p <question>`：
 *   - argv 直传（question 是单个 argv 元素），无 /bin/sh -c，防注入；
 *   - stdin=/dev/null、stdout/stderr 全捕获、超时杀进程（复用
 *     api_run_ai 的既有机制，timeout_s 即 [api] ask_timeout）；
 *   - 成功时 answer 取 stdout（api_do_ask 负责 strip）。
 *
 * 返回 0：进程正常退出且退出码 0。*out 与 *err 为 malloc 缓冲（NUL 结尾，
 *         调用方 free），*outlen 与 *errlen 为真实长度，*rc_out=0。
 * 返回 1：调用未完成。*status_out 为应回状态码，*fail_body 为错误 JSON
 *         （调用方 free），结构与既有 /ask 错误体兼容（error/message，
 *         非 0 退出另带 detail）：
 *           502 occ 不存在（人话 + 查法提示）
 *           502 occ 非 0 退出（message="occ rc=N"，detail=stderr 尾
 *               400 码点，UTF-8 安全截断）
 *           502 fork/pipe 失败
 *           504 超时（沿用 api_run_ai 的超时杀进程路径）
 *         非 0 返回时 *out 与 *err 仍可能已分配，由调用方统一 free。
 */
int api_run_occ(const char *question, long long timeout_s,
		char **out, size_t *outlen, char **err, size_t *errlen,
		int *rc_out, int *status_out, aik_json **fail_body);

#endif /* _AIK_APIC_OCC_H */
