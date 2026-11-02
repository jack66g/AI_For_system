/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acdigest.h - 会话摘要模板 / 校验 / 分段画像 / 恢复载荷 / delta 合并链
 *
 * T5c 逐语义复刻 ref-autocondense/digest.py（638 行，纯函数，不碰磁盘网络）：
 *   - render_template：完整 markdown 模板，占位 {project} {ts} {reason}；
 *   - validate：必填章节齐全 + 总长 ≥ 200 字符（长度按 Unicode 码点计）；
 *   - split_digest：7 章节规格 + misc + digest 兜底；cap 溢出按 importance
 *     升序（稳定排序）保留 cap-1 段，溢出段按原序合成一个 misc(0.55)；
 *     文件清单 bullet ≤ 8 逐条、> 8 整节合并（_FILE_LIST_MAX_BULLETS）；
 *   - build_restore_payload：优先级预算打包（标题/未完成/恢复指针/决策/坑/
 *     目标/已完成/散行/旧标题逐档装入，超预算低优先级先丢），截断时文末
 *     追加「（完整快照：{full_file}）」指针行；
 *   - merge_delta_chain：whole=取最新非空版本、union=bullet 并集（新在前）。
 *
 * 所有长度/切片语义对齐 Python str：按码点计数与切片、Unicode 空白 strip、
 * Python splitlines 边界。共享 split_sections 解析（分段/打包/合并同一实现）。
 *
 * 本模块依赖 store/store_json.h（JSON DOM），零第三方依赖，C11。
 */
#ifndef _AIK_AUTOCONDENSE_ACDIGEST_H
#define _AIK_AUTOCONDENSE_ACDIGEST_H

#include "store/store_json.h"

#include <stddef.h>

/* ------------------------------------------------------------------ */
/* 模板与校验                                                          */
/* ------------------------------------------------------------------ */

/* render_template(project, ts, reason)：malloc 结果（调用者 free）*/
char *ac_render_template(const char *project, const char *ts, const char *reason);

/*
 * ac_validate - 校验摘要，返回中文错误 STR 的 ARR（malloc DOM，调用者释放）
 *
 * ok = 数组为空。文案逐字（digest.py:286-296）：
 *   空/纯空白 → ["摘要为空"]；
 *   缺章节 → "缺少必填章节：{sec}"（REQUIRED_SECTIONS 顺序）；
 *   过短 → "总长度不足 200 字符（当前 {n}）"（码点数）。
 */
aik_json *ac_validate(const char *digest_md);

/* ------------------------------------------------------------------ */
/* 分段画像（split_digest）                                            */
/* ------------------------------------------------------------------ */

/* 单条语义段（对应 Python Segment dataclass；堆串深拷贝所有权归本结构）*/
typedef struct {
	char *type;		/* goal/accomplishment/todo/decision/pitfall/
				 * file_change/restore_pointer/misc/digest */
	char *text;		/* 含 "[autocondense|{project}|{ts}|{trigger}] " 前缀 */
	char **tags;
	size_t n_tags;
	double importance;
} ac_segment;

/* 释放成员并释放结构本身 */
void ac_segment_free(ac_segment *s);
void ac_segments_free(ac_segment *segs, size_t n);

/* 段数组转 JSON（键序 type,text,tags,importance；供测试/展示）*/
aik_json *ac_segments_to_json(const ac_segment *segs, size_t n);

/*
 * ac_split_digest - 把整篇摘要拆成语义段（纯函数，任何输入不 raise）
 *
 * base_tags 为 NULL 时按空表处理。cap：has_cap=0 → 不限；否则 cap>=1 且
 * 段数超限时按 importance 升序（稳定）溢出合并。返回 malloc 数组（元素为
 * 深拷贝），*n_out 为段数；失败返回 NULL。
 */
ac_segment *ac_split_digest(const char *digest_md,
			    const char *const *base_tags, size_t n_base_tags,
			    const char *project, const char *ts, const char *trigger,
			    int has_cap, long long cap, size_t *n_out);

/* ------------------------------------------------------------------ */
/* 恢复载荷                                                            */
/* ------------------------------------------------------------------ */

/* 从「## 文件变更清单」bullet 解析建议重读的文件路径（前 limit 条）*/
aik_json *ac_extract_reread_files(const char *md, int limit);

/* 未完成章节是否有实际内容（非空且不是「（无）」占位）*/
int ac_todo_open(const char *md);

/*
 * ac_build_restore_payload - 合并快照生成优先级恢复载荷
 *
 * files 最新在前；has_merged_md=1 时以 merged_md 为打包底稿（可为空串），
 * 否则读最新快照全文。reread_limit 对齐 Python 缺省 5（传 0 → 空）。
 * 返回键序 {text,truncated,full_file,note,reread_files,todo_open} 的 OBJ。
 */
aik_json *ac_build_restore_payload(const char *const *files, size_t n_files,
				   long long max_chars,
				   int has_reread_limit, long long reread_limit,
				   int has_merged_md, const char *merged_md);

/* ------------------------------------------------------------------ */
/* delta 合并链                                                        */
/* ------------------------------------------------------------------ */

/* 把 delta 链多份摘要（最新在前）合并成完整 markdown；malloc 结果 */
char *ac_merge_delta_chain(const char *const *texts, size_t n);

#endif /* _AIK_AUTOCONDENSE_ACDIGEST_H */
