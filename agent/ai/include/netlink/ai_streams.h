/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ai_streams.h - 内核事件流订阅（W78：六条"被推即应"感知流）
 *
 * 背景（W78A 深挖报告 A 路）：内核侧六条事件面全部就绪但用户态零消费者——
 *   NETLINK_AI EVENT 推送 / proc connector / TASKSTATS / NFLOG /
 *   rtnetlink 组播 / KOBJ_UEVENT。本模块把它们封装为统一的有界订阅接口，
 * 由 executor 的 TOOL_CH_STREAM 通道按工具名分发。
 *
 * 设计约定：
 *   - 全部只读（订阅+收），不写内核/系统任何状态
 *   - 统一输出：首行 {"stream":...,"timeout_ms":...,"max_events":...,"events":N}
 *     之后每事件一行 JSON；事件时间为订阅方单调时钟毫秒
 *   - 有界：poll 总时长受 timeout_ms 控制，事件数受 max_events 控制
 *   - 权限不足（CN_PROC 需 CAP_NET_ADMIN、EVENT REG 需 CAP_SYS_ADMIN）或
 *     协议族不存在时，明确报错/提示，绝不返回假数据
 */
#ifndef _AI_STREAMS_H
#define _AI_STREAMS_H

#include <stddef.h>

/*
 * 参数钳制（导出供单测）：v 越界时收到 [lo,hi]，v<=LLONG_MIN 等异常
 * 落到 dflt。timeout/max_events/payload_bytes 都走这里统一防呆。
 */
long long ai_streams_clamp_ll(long long v, long long lo, long long hi,
			      long long dflt);

/*
 * JSON 字符串转义（导出供单测）：把 in 的字节逐个转义（引号/反斜杠/
 * 控制字符 → \u00XX；UTF-8 多字节原样透传）写入 out（NUL 结尾）。
 * 返回 0 成功；-1 容量不足或参数非法。
 */
int ai_streams_json_escape(const char *in, char *out, size_t cap);

/*
 * 六条流。成功返回 AI_OK 且 *out 为 JSON 行文本（调用方 free(*out)）；
 * 失败返回 ai_types.h 的 AI_ERR_* 且 *out 为人类可读错误说明。
 */
int ai_streams_event_listen(int timeout_ms, int max_events, char **out);
int ai_streams_proc_watch(int timeout_ms, int max_events, char **out);
int ai_streams_taskstats(long long pid, char **out);
int ai_streams_nflog(int timeout_ms, int max_events, int payload_bytes,
		     char **out);
int ai_streams_net_monitor(int timeout_ms, int max_events, char **out);
int ai_streams_udev_monitor(int timeout_ms, int max_events, char **out);

#endif /* _AI_STREAMS_H */
