// SPDX-License-Identifier: GPL-2.0
/*
 * sme_client.h - SME（外部记忆服务）REST 客户端接口
 *
 * SME 服务由独立进程提供（默认 127.0.0.1:8000，环境变量 SME_URL 可覆盖），
 * REST 接口：
 *   GET  /health           健康检查
 *   POST /memories         写入记忆 {"text":..,"metadata":{..}}
 *   POST /memories/search  语义检索 {"text":..,"top_k":N}
 *   GET  /stats            统计信息
 *
 * 设计原则：C 侧保持"薄客户端"——四个函数都只负责构造请求、发送、
 * 把**原始 JSON 响应体**交给调用者（不做字段级解析），语义解读交给
 * 上层（executor 的 memory 通道直接把 JSON 原文作为工具结果回填给
 * 模型；cmd_ask 的记忆注入也直接引用原文片段）。
 *
 * 传输复用 local/local_http.c（POST + 新增 GET），JSON 转义对齐
 * local_chat.c 的 json_escape（经 ai_json_util.ai_json_escape 统一）。
 * SME 服务未启动属于正常场景（记忆是增强能力，不是硬依赖）：所有
 * 函数失败时返回 AI_ERR_* 并在 out 里给出人可读的错误说明。
 */
#ifndef _AI_SME_CLIENT_H
#define _AI_SME_CLIENT_H

#include <stddef.h>

/* SME 服务默认基地址（可用环境变量 SME_URL 覆盖，如 http://10.0.2.2:8000） */
#define SME_DEFAULT_BASE_URL  "http://127.0.0.1:8000"

/* 输出缓冲区建议大小（原始 JSON 响应体足够放入即可） */
#define SME_OUT_BUF_MIN       4096

/*
 * sme_base_url - 读取当前 SME 基地址
 * 返回: 环境变量 SME_URL（非空时）；否则默认 http://127.0.0.1:8000
 */
const char *sme_base_url(void);

/*
 * sme_health - GET /health 健康检查
 * @out: 输出缓冲，收到原始响应体（如 {"status":"ok","memories":3}）；
 *       失败时收到人可读错误说明
 * @n:   缓冲大小（>= SME_OUT_BUF_MIN 视为安全）
 * 返回: AI_OK（HTTP 2xx）；AI_ERR_NETWORK 连接失败；AI_ERR_API 非 2xx
 */
int sme_health(char *out, size_t n);

/*
 * sme_add - POST /memories 写入一条记忆
 * @text:     记忆文本（内部做 JSON 转义）
 * @meta_json: 元数据 JSON 对象字符串（原样嵌入，NULL/空则省略字段；
 *             调用者保证是合法 JSON 对象，如 "{\"src\":\"ask\"}"）
 * @out/@n:   同 sme_health
 * 返回: 同 sme_health
 */
int sme_add(const char *text, const char *meta_json, char *out, size_t n);

/*
 * sme_search - POST /memories/search 语义检索
 * @text:  查询文本
 * @top_k: 返回条数上限（<=0 时服务端默认）
 * @out/@n: 同 sme_health
 * 返回: 同 sme_health
 */
int sme_search(const char *text, int top_k, char *out, size_t n);

/*
 * sme_stats - GET /stats 统计信息
 * @out/@n: 同 sme_health
 * 返回: 同 sme_health
 */
int sme_stats(char *out, size_t n);

/* ---- v2 扩展（对照 sme/api/server.py 实读确认的端点） ----
 *
 * 通用约定：
 *   - memory_id 仅接受 [A-Za-z0-9_.-]（防 URL 路径注入），非法返回
 *     AI_ERR_INVALID_ARG；
 *   - 空体 POST（hit/archive/restore/consolidate/compress）发送
 *     Content-Length: 0，FastAPI 端点无必填 body，接受该形态；
 *   - out 收到的仍是原始 JSON 响应体（或人可读错误说明），薄客户端
 *     不做字段级解析。
 */

/*
 * sme_memory_get - GET /memories/{id} 读取单条记忆（risk=R）
 */
int sme_memory_get(const char *memory_id, char *out, size_t n);

/*
 * sme_memory_hit - POST /memories/{id}/hit Ebbinghaus 强化（risk=W1）
 * 语义：命中计数 +1、检索权重上调；响应体为强化后的记忆 dict
 */
int sme_memory_hit(const char *memory_id, char *out, size_t n);

/*
 * sme_memory_archive - POST /memories/{id}/archive 归档（risk=W1）
 * 归档后默认检索不可见（include_archived=false 时跳过）
 */
int sme_memory_archive(const char *memory_id, char *out, size_t n);

/*
 * sme_memory_restore - POST /memories/{id}/restore 恢复归档（risk=W1）
 */
int sme_memory_restore(const char *memory_id, char *out, size_t n);

/*
 * sme_facts_multi_hop - POST /facts/multi_hop 知识图谱多跳查询（risk=R）
 * @text:  实体查询文本（服务端先找实体再按关系跳）
 * @top_k: 透传 SearchRequest.top_k（默认 10）
 * 注意：factgraph 模块未启用时服务端返回 {"enabled":false,...}
 */
int sme_facts_multi_hop(const char *text, int top_k, char *out, size_t n);

/*
 * sme_regions_search - POST /regions/search 空间区域检索（risk=R）
 * @text:  查询文本；@top_k: 区域条数上限（<=0 时服务端默认 5）
 */
int sme_regions_search(const char *text, int top_k, char *out, size_t n);

/*
 * sme_consolidate - POST /consolidate 触发巩固（聚类生成摘要记忆，risk=W2）
 * 会新增派生记忆（响应 "created":[...]）
 */
int sme_consolidate(char *out, size_t n);

/*
 * sme_compress - POST /compress 触发压缩（risk=W2）
 * 会新增压缩摘要记忆（响应 "created":[...]）
 */
int sme_compress(char *out, size_t n);

/*
 * sme_export - GET /export 全量导出并落盘（risk=R）
 * @save_path: 导出文件目标路径（NULL 时默认 /tmp/sme-export.json）；
 *             目录不可写时返回 AI_ERR_STORAGE 并在 out 说明
 * @out/@n:    收到摘要文本（文件路径 + 字节数 + JSON 预览），非原始
 *             响应体——导出内容可能远超缓冲，完整内容看文件
 */
int sme_export(const char *save_path, char *out, size_t n);

/*
 * sme_metrics - GET /metrics 观测指标摘要（Module 10，risk=R）
 * 未启用 telemetry 模块时服务端返回 {"enabled":false,...}
 */
int sme_metrics(char *out, size_t n);

#endif /* _AI_SME_CLIENT_H */
