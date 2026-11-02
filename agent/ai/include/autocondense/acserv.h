/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acserv.h - autocondense 常驻 REST 服务（HTTP/1.1 + 12 端点）
 *
 * T5d 逐语义复刻 ref-autocondense/service.py（831 行）：
 *   - 传输层复刻 T4 smehttp 模式：64 KiB 请求头 / 8 MiB 请求体上限、
 *     Content-Length 定长读、HTTP/1.1 keep-alive、每连接一个 detached
 *     线程、请求处理整体持互斥（单写者语义，等价单 worker ASGI）；
 *   - 12 端点：GET /health、POST /session/start、POST /report、
 *     POST /events/hook、GET /check、POST /judge、POST /begin、
 *     POST /commit、GET /restore、GET /status、GET|PUT /config；
 *   - 响应体 = FastAPI 紧凑 JSON（aik_json_dump，键序 = Python dict
 *     插入序）；400 {"errors":[...]}；Pydantic 422 形态照向量
 *     （missing/loc 从 body 起，batch 项 loc 含 plan_items.<i>）。
 *
 * 时钟：全部 ISO/文件名走 acconfig.h 注入时钟（--frozen-now 由
 * autocondensed.c 注入）。本模块不依赖 LLM，服务端为纯状态机。
 */
#ifndef _AIK_AUTOCONDENSE_ACSERV_H
#define _AIK_AUTOCONDENSE_ACSERV_H

#include "autocondense/acconfig.h"
#include "autocondense/acdigest.h"
#include "autocondense/acsme.h"
#include "autocondense/acsignals.h"
#include "autocondense/acstate.h"

#include <stddef.h>

/* 参考实现 autocondense.__version__（向量 /health 里的 version）*/
#define AC_SERV_VERSION "0.3.0"

/* 数据目录下的自报身份文件（service.py PID_FILE_NAME）*/
#define AC_PID_FILE_NAME "service.pid"

/* 传输上限（与 T4 smehttp 相同）*/
#define AC_HTTP_MAX_HEADER (64 * 1024)
#define AC_HTTP_MAX_BODY (8 * 1024 * 1024)

typedef struct ac_http_server ac_http_server;

/*
 * ac_http_server_new - 构造并绑定监听套接字
 *
 * data_dir 为数据目录（加载 config.json / sessions 状态；SME 桥用初始
 * 配置构造一次，PUT /config 不重建桥——与 create_app 一致）。host 为
 * NULL/空时 127.0.0.1；port 0 由内核分配（实际端口 ac_http_server_port）。
 * 失败返回 NULL 并在 err 写入原因。
 */
ac_http_server *ac_http_server_new(const char *data_dir, const char *host,
				   int port, char *err, size_t errlen);

/* 关停等待活动连接（keep-alive 空闲上限 5s）后释放全部资源 */
void ac_http_server_free(ac_http_server *s);

int ac_http_server_port(const ac_http_server *s);
const char *ac_http_server_data_dir(const ac_http_server *s);

/*
 * ac_http_server_serve - accept 循环（每连接 detached 线程）
 *
 * 直到 ac_http_server_request_stop() 被调用（可从信号 handler 内调用，
 * 只置 flag）；返回 0 干净退出，-1 套接字错误。
 */
int ac_http_server_serve(ac_http_server *s);

/* 请求停机：async-signal-safe（仅置 sig_atomic_t 标志）*/
void ac_http_server_request_stop(void);

#endif /* _AIK_AUTOCONDENSE_ACSERV_H */
