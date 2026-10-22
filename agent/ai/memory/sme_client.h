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

/* ---- W50：完整记忆管理面（增删改查/批量导入/图谱/Region/事实/配置） ----
 *
 * 通用约定与 v2 相同：memory_id 白名单 [A-Za-z0-9_.-]；metadata_json /
 * tags_json / memories_json 由调用者提供**合法 JSON**（客户端做括号
 * 配平与注入校验后原样嵌入，不做字段级重组）；所有文本字段内部经
 * ai_json_escape 转义；out 始终收到原始响应体或人可读错误说明。
 */

/* 写入选项：任意字段为 NULL/0 表示省略（服务端保持默认）。 */
struct sme_add_opts {
	const char *text;            /* 必填 */
	const char *metadata_json;   /* JSON object 字符串，可 NULL */
	const char *tags_json;       /* JSON array 字符串，可 NULL */
	int has_importance;          /* 非 0 时携带 importance */
	double importance;
	const char *source;          /* 如 "user"/"llm"/"system"，可 NULL */
	const char *link_to;         /* 写入后链接到既有记忆 id，可 NULL */
	const char *link_kind;       /* link_to 的关系类型，默认 reference */
	const char *ns;              /* 命名空间（多用户隔离），可 NULL */
};

/* sme_add_ex - POST /memories（扩展字段；risk=W1） */
int sme_add_ex(const struct sme_add_opts *o, char *out, size_t n);

/* 高级检索选项（SearchRequest 全字段）。text 必填；top_k<=0 省略；
 * top_regions<=0 省略；*_json 为 NULL 省略；has_include_archived 非 0
 * 时才发送 include_archived；graph_expand<=0 省略；ns 为 NULL 省略。 */
struct sme_search_opts {
	const char *text;
	int top_k;
	int top_regions;
	const char *metadata_filters_json;  /* JSON object 字符串 */
	const char *tags_json;              /* JSON array 字符串 */
	const char *region_retrieval;       /* 区域检索策略字符串 */
	int has_include_archived;
	int include_archived;
	int graph_expand;
	const char *ns;
};

/* sme_search_ex - POST /memories/search（带过滤/图谱扩展/ns；risk=R） */
int sme_search_ex(const struct sme_search_opts *o, char *out, size_t n);

/* 更新选项：至少提供一个字段（NULL 且 has_*=0 表示不修改）。 */
struct sme_update_opts {
	const char *text;
	const char *metadata_json;
	const char *tags_json;
	int has_importance;
	double importance;
	int has_weight;
	double weight;
	const char *summary;
};

/*
 * sme_memory_update - PATCH /memories/{id} 更新记忆（risk=W1）
 * 改 text 会触发重新向量化；返回更新后的记忆 dict。
 */
int sme_memory_update(const char *memory_id,
		      const struct sme_update_opts *o, char *out, size_t n);

/*
 * sme_memory_delete - DELETE /memories/{id} 永久删除（risk=W2）
 * 响应 {"deleted": "<id>"}；不可恢复（保留历史请用 archive）。
 */
int sme_memory_delete(const char *memory_id, char *out, size_t n);

/*
 * sme_memories_batch - POST /memories/batch 批量新增（risk=W1）
 * @memories_json: JSON 数组字符串；每条走完整 add 管线（抽取/去噪）。
 * 每条生成新 id，**非幂等**：重试会产生重复记忆。
 */
int sme_memories_batch(const char *memories_json, char *out, size_t n);

/*
 * sme_import - POST /import 无损导入（risk=W1）
 * @memories_json: JSON 数组（导出格式条目：id/text/metadata/weight/...）。
 * 条目带 id 时按 id 覆盖恢复（可重试幂等）；缺 id 的条目每次生成新
 * id（重试会重复）。
 */
int sme_import(const char *memories_json, char *out, size_t n);

/*
 * sme_import_path - 从本地文件读取后 POST /import（risk=W1）
 * @path: 绝对路径，realpath 必须落在 /tmp 或 /var/ai 下；文件内容为
 *        JSON 数组，或含 "memories" 键的导出对象；最大 8MB。
 */
int sme_import_path(const char *path, char *out, size_t n);

/* sme_graph - GET /graph 记忆图（edge_count + edges，risk=R） */
int sme_graph(char *out, size_t n);

/*
 * sme_graph_link - POST /graph/link 建立记忆间链接（risk=W1）
 * @a/@b: 记忆 id（均须存在）；@kind: 关系类型（默认 reference）；
 * @has_weight 非 0 时携带 weight；@note 可 NULL。
 * 注意：服务端没有 unlink 端点，边只能随记忆删除/图重建移除。
 */
int sme_graph_link(const char *a, const char *b, const char *kind,
		   int has_weight, double weight, const char *note,
		   char *out, size_t n);

/* sme_regions - GET /regions 列出全部空间 Region（risk=R） */
int sme_regions(char *out, size_t n);

/* sme_regions_evolve - POST /regions/evolve 触发 Region 演化（risk=W1） */
int sme_regions_evolve(char *out, size_t n);

/* sme_facts - GET /facts 事实图谱/双时态事实（risk=R） */
int sme_facts(char *out, size_t n);

/*
 * sme_facts_history - GET /facts/history 单事实版本链（risk=R）
 * @text/@memory_id 至少一个非空；均会做 URL 百分号编码。
 */
int sme_facts_history(const char *text, const char *memory_id,
		      char *out, size_t n);

/* sme_profile - GET /profile 用户画像事实与快照（risk=R） */
int sme_profile(char *out, size_t n);

/* sme_qapairs - GET /qapairs 问答对清单（risk=R） */
int sme_qapairs(char *out, size_t n);

/*
 * sme_metrics_report - GET /metrics/report 完整遥测报告落盘（risk=R）
 * @save_path: NULL 时 /tmp/sme-metrics-report.json；realpath 必须在
 *             /tmp 或 /var/ai 下。telemetry 未启用时服务端 404。
 */
int sme_metrics_report(const char *save_path, char *out, size_t n);

/* sme_config - GET /config 配置中心（服务端已对 api_key 掩码，risk=R） */
int sme_config(char *out, size_t n);

/*
 * sme_config_check - POST /config/check 配置校验（risk=R，只读诊断）
 * @ping: 非 0 时额外探测 LLM/Embedding 连通性（可能产生外部调用）。
 */
int sme_config_check(int ping, char *out, size_t n);

/* ---- W43：失忆降级标记 ----
 * SME 不可达属正常场景（记忆是增强能力，不是硬依赖）：调用方
 * （ask 循环/工具结果回填/UI）据原因码附注降级说明，不再静默
 * 空结果或裸报错；/session 的可达性显示亦据此判定。
 */
enum sme_degrade_reason {
	SME_DEGRADED_NONE = 0,	/* 未降级 */
	SME_DEGRADED_UNAVAILABLE = 1,	/* 连接失败/超时（服务未启动或不可达） */
	SME_DEGRADED_HTTP = 2,	/* 服务返回非 2xx */
};

/* sme_degrade_reason_of - 把 sme_* 返回码映射为降级原因码 */
int sme_degrade_reason_of(int rc);

#endif /* _AI_SME_CLIENT_H */
