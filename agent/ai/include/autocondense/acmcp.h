/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acmcp.h - T5e autocondense MCP stdio 薄代理
 *
 * 对齐 REF-PY 42466f1 `autocondense/mcp_server.py`：
 *   - stdio 逐行 JSON-RPC（initialize / notifications/initialized / tools/list /
 *     tools/call / ping）；
 *   - 7 个工具的中文格式化输出逐字节对齐（_fmt_decision/_fmt_snapshots 与
 *     各工具包装文案）；
 *   - cwd → session_id 映射（data/mcp-session-map.json，原子写 indent=2 + LF）；
 *   - 服务不可达时拉起同级 `autocondensed`（POSIX setsid，日志追加
 *     /tmp/autocondense_service.log）。
 *
 * 服务地址：AUTOCONDENSE_PORT（默认 8762——T9d 改号，8761 归
 * aikernel-api）+ 127.0.0.1；数据目录：
 * AUTOCONDENSE_DATA_DIR（默认 ~/.autocondense）。
 */
#ifndef _AIK_AUTOCONDENSE_ACMCP_H
#define _AIK_AUTOCONDENSE_ACMCP_H

#include "store/store_json.h"

/* 主循环：读 stdin 直到 EOF，逐行处理并写 stdout。返回 0。 */
int acmcp_run(const char *argv0);

/* 便于单测/复用：格式化工具（返回 malloc 字符串，调用者 free） */
char *acmcp_fmt_decision(const aik_json *d);
char *acmcp_fmt_snapshots(const aik_json *snaps);

/* http 客户端（内部使用；暴露给测试） */
struct ac_http_resp {
	int status;
	char *body;
	size_t len;
};
int ac_http_call(const char *method, const char *path, const aik_json *body,
		 struct ac_http_resp *out, char *err, size_t errlen);
void ac_http_resp_free(struct ac_http_resp *r);
/* 读写超时（秒，默认 60；hook 用 3） */
void ac_http_set_timeout(int seconds);

/* 数据目录解析（AUTOCONDENSE_DATA_DIR 优先，否则 $HOME/.autocondense） */
int acmcp_data_dir(char *out, size_t outlen);

#endif /* _AIK_AUTOCONDENSE_ACMCP_H */
