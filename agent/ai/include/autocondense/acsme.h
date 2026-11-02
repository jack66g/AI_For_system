/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acsme.h - SME 记忆服务桥接（POSIX socket HTTP/1.1 薄客户端）
 *
 * T5c 逐语义复刻 ref-autocondense/sme_bridge.py（289 行）：
 *   - 每请求新建连接（httpx.Client 逐请求 with 语义），trust_env 等价
 *     （不读系统代理，直连 host:port）；
 *   - 请求体 = httpx json= 形态：json.dumps(body, ensure_ascii=False,
 *     separators=(",", ":"), allow_nan=False)（经 T4 差分验证的
 *     aik_json_dump 与其逐字节一致）；
 *   - health：GET /health，结果缓存 health_cache_s 秒（默认 60s，缓存计时
 *     从探测完成后起算）；任何异常按 false 处理，不抛给调用方；
 *   - store_digest：POST /memories 整篇兜底；失败降级返回错误串；
 *   - store_segments：≥2 段先 POST /memories/batch（一次往返），任何异常/
 *     非 2xx 回落逐条 POST /memories；
 *   - dedupe_segments：逐段 POST /memories/search（查询截 160 码点），
 *     score ≥ 阈值且同项目同类型 → POST /memories/{id}/hit 强化；
 *     软预算（默认 10s）用尽后剩余段跳过查重直接入库；
 *   - search：POST /memories/search 后客户端过滤 tags 含 session_digest。
 *
 * 错误串形态对齐 Python f"{type(e).__name__}: {e}" 的类别名
 * （ConnectError/ConnectTimeout/ReadTimeout/ProtocolError），消息文本为
 * C 侧 strerror 等价物（仅类别可逐字对齐，向量不含错误分支文本）。
 */
#ifndef _AIK_AUTOCONDENSE_ACSME_H
#define _AIK_AUTOCONDENSE_ACSME_H

#include "autocondense/acdigest.h"

#include <stddef.h>

/* 默认 tags（SMEBridge DEFAULT_TAGS）*/
#define AC_SME_DEFAULT_TAGS ((const char *const[]){ "project", "todo", "session_digest" })
#define AC_SME_DEFAULT_N_TAGS 3
#define AC_SME_DEFAULT_TIMEOUT_S 2.0
#define AC_SME_DEFAULT_IMPORTANCE 0.7
#define AC_SME_DEFAULT_HEALTH_CACHE_S 60.0
/* 去重阶段软预算（DEDUP_BUDGET_S）*/
#define AC_SME_DEDUP_BUDGET_S 10.0

typedef struct ac_sme_bridge ac_sme_bridge;

/*
 * ac_sme_bridge_open - 构造桥（base_url 形如 "http://127.0.0.1:8000"，
 * 尾部 '/' 全部剥掉；tags 为 NULL 时用默认三标签）
 *
 * 目前仅支持 http://（https 需要 TLS，配置里不会出现；出现时返回 NULL）。
 * 失败返回 NULL。
 */
ac_sme_bridge *ac_sme_bridge_open(const char *base_url, double timeout_s,
				  const char *const *tags, size_t n_tags,
				  double importance, double health_cache_s);
void ac_sme_bridge_close(ac_sme_bridge *b);

/*
 * ac_sme_bridge_set_importance_int - importance 整型形态（配置注入 1 → 体
 * 序列化 "importance":1 而非 1.0；等价 Python int 传参）
 */
void ac_sme_bridge_set_importance_int(ac_sme_bridge *b, long long v);

/* GET /health；结果缓存 health_cache_s 秒（探测异常 → 0）*/
int ac_sme_health(ac_sme_bridge *b);

/* POST /memories 整篇兜底。返回 {"stored","memory_id","error"}（键序同 Python）。*/
aik_json *ac_sme_store_digest(ac_sme_bridge *b, const char *digest_md,
			      const char *project, const char *session_id,
			      const char *trigger);

/*
 * ac_sme_store_segments - 分段入库（≥2 段先 batch，失败回落逐条）
 *
 * metadata 为 OBJ（键序保留，逐键并入 "tool"/"segment_type"/"segment_index"
 * 之后，等价 Python **metadata）。返回 {"stored","failed","memory_ids",
 * "errors"}。
 */
aik_json *ac_sme_store_segments(ac_sme_bridge *b, const ac_segment *segs,
				size_t n_segs, const aik_json *metadata);

/*
 * ac_sme_dedupe_segments - 逐段查重（命中 → hit 强化）
 *
 * has_budget_s=0 用默认 10s。返回 0 成功；new_segs 为深拷贝段数组（调用方
 * ac_segments_free），reinforced 为 malloc 的 STR 数组（调用方逐个 free +
 * free 数组）。
 */
int ac_sme_dedupe_segments(ac_sme_bridge *b, const ac_segment *segs,
			   size_t n_segs, const char *project, double threshold,
			   int has_budget_s, double budget_s,
			   ac_segment **new_segs, size_t *n_new,
			   char ***reinforced, size_t *n_reinforced);

/* POST /memories/search 检索，只留 tags 含 session_digest 的条目
 * （{"id","text","score"}，值原样回带）*/
aik_json *ac_sme_search(ac_sme_bridge *b, const char *query, long long top_k);

#endif /* _AIK_AUTOCONDENSE_ACSME_H */
