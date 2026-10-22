// SPDX-License-Identifier: GPL-2.0
/*
 * offline_intent.h - W77 离线意图层（不依赖模型）
 *
 * 目标：断网时常见“状态/诊断/文件/服务/沙箱/记忆/租约/计划/配置/
 * 路由”查询仍可用。所有答案来自 /proc、statvfs、systemctl、文件
 * 元数据、SME；答案带 intent/source/cache_age/latency，机器可读 JSON
 * 与人类可读文本双份，绝不把 raw `cat` 当世界模型。
 *
 * 只读 D0：本模块没有任何写路径；D2+ 动作仍走 executor + W74 lease。
 */
#ifndef _AI_OFFLINE_INTENT_H
#define _AI_OFFLINE_INTENT_H

#include <stddef.h>

struct ai_config;

struct ai_offline_answer {
	int matched;              /* 1=已识别并生成答案 */
	char intent[32];          /* memory/disk/service/... */
	char *text;               /* 人类可读（含 header + 结构化字段） */
	char *json;               /* 机器可读 JSON（intent/source/age/data） */
	char source[512];         /* 主数据来源（可多个，逗号分隔） */
	long long cache_age_ms;   /* 数据年龄（实时 /proc 为 0） */
	long long latency_ms;     /* 生成本答案耗时 */
	int degraded;             /* 1=数据源不可用（如实告知，不伪造） */
};

/*
 * ai_offline_intent_match - 离线意图识别与答案生成
 * @question: 用户问题（自然语言，中英混合）
 * @cfg:      配置（路由/模型摘要；可为 NULL）
 * @ans:      输出（调用者 ai_offline_answer_free）
 * 返回: 1=命中（ans->matched=1），0=未命中（交给模型）
 *
 * 含动作词（修复/重启/删除/安装/修改/写脚本等）或重推理问法
 * （如何/为什么/分析/设计）不命中，避免离线层越权作答。
 */
int ai_offline_intent_match(const char *question, const struct ai_config *cfg,
			    struct ai_offline_answer *ans);

void ai_offline_answer_free(struct ai_offline_answer *ans);

/*
 * ai_offline_cache_plan - 缓存最近一次 ask 的计划摘要
 * @question: 用户问题（截断 240 字符）
 * @route:    offline/local/cloud
 * @status:   ok/degraded/model_error/...
 * @rounds:   模型轮数（离线意图为 0）
 * @tools_csv: 本次调用过的工具名（逗号分隔，可 NULL）
 * @detail:   结果摘要（截断 200 字符，可 NULL；不含密钥）
 * 写 ~/.aikernel/offline/plans.jsonl（0600，>1MB 轮转）。
 */
int ai_offline_cache_plan(const char *question, const char *route,
			  const char *status, int rounds,
			  const char *tools_csv, const char *detail);

/*
 * ai_offline_last_plans - 读取最近计划缓存（最多 5 行 / 4KB）
 * @age_ms: 输出缓存文件年龄（毫秒）
 * 返回: malloc 文本（每行一条 JSON），无缓存返回 NULL。
 */
char *ai_offline_last_plans(long long *age_ms);

#endif /* _AI_OFFLINE_INTENT_H */
