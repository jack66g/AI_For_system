// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_compact.c - compact 命令实现（会话历史 LLM 摘要压缩）
 *
 * 上下文预算治理：会话历史持续增长会逼近 ctx_len 预算（提示符与
 * config show 显示百分比，>80% 黄色警告）。compact 把当前会话的
 * 历史通过现有 provider 通道让 LLM 摘要，并**原子替换**为：
 *
 *     [历史摘要] <summary>  +  最近 N 条整轮原文（按预算）
 *
 * 旧实现只写一条摘要，且摘要长度不受控：摘要本身仍可能高于 80%
 * 阈值；每次 ask 又独立触发压缩，多行输入逐行压缩 -> 模型请求翻倍、
 * REPL 永不静默（W59 p5-03 实机）。W59 起：
 *   - 压缩输入 = 旧历史快照（只读），摘要请求本身绝不写入历史；
 *   - 压缩输出受目标预算硬约束（默认 55% 历史预算，重试 40%）；
 *   - 摘要正文按目标预算截断（UTF-8 边界），保留最近整轮原文；
 *   - 写临时文件 + fsync + rename 原子替换，不再 clear+append；
 *   - 摘要失败降级为确定性截断（仍受目标预算约束）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_runtime.h"
#include "ai_config.h"
#include "ai_json_util.h"
#include "ai_ui.h"
#include "ai_lang.h"
#include "ask_compact.h"
#include "ask_context.h"

/* 送入摘要的对话文本上限基准（字节；超长从头截断保住最近内容） */
#define COMPACT_TEXT_MAX  48000

/* 摘要输入的消息条数上限（只压缩最近 N 条，防渲染缓冲无界） */
#define COMPACT_MSG_MAX   200

/*
 * W72：最近一次压缩的保留窗口统计。cmd_ask 用它判断"压缩是否已经
 * 留下最近原文"——kept>0 时即使历史仍高于触发线也接受软目标，不再
 * 在同一 ask 里二次压缩/截断（避免把刚保留的近期原文又裁掉）。
 */
static int g_compact_last_kept;
static long g_compact_last_after;

int cmd_compact_last_kept(void)
{
	return g_compact_last_kept;
}

long cmd_compact_last_after(void)
{
	return g_compact_last_after;
}

/*
 * compact_text_cap - 送入摘要的对话文本实际上限（字节）
 * W18 P0-2b：ask 入口自动 compact 复用本命令后，上限必须预算感知——
 * 原固定 48000B 在本地 8k 窗口（预算 (ctx_len−max_tokens)≈7k token）
 * 下摘要请求本身就超窗必败。cap = min(48000, (ctx_len−max_tokens)×3
 * − 512 system/骨架余量)，下限 4096B 保底。云端大窗口行为不变。
 *
 * W20 修2：max_tokens 取按 provider 生效档（ai_config_effective_max_tokens，
 * 云端 8192/本地 1024），不再用 [ui] 全局单档。
 */
static size_t compact_text_cap(const struct ai_shell *sh)
{
	const struct ai_config *cfg = sh->config;
	int is_cloud = sh->runtime.model_provider_type &&
		       strcmp(sh->runtime.model_provider_type,
			      "openai_compatible") == 0;
	long mt = ai_config_effective_max_tokens(
			cfg, sh->runtime.model_provider_type);
	long budget_tok;
	long bytes;

	if (is_cloud)
		return COMPACT_TEXT_MAX;

	budget_tok = (long)cfg->ui.ctx_len - mt;
	if (budget_tok < 0)
		budget_tok = 0;
	bytes = budget_tok * 3 - 512;
	if (bytes > COMPACT_TEXT_MAX)
		bytes = COMPACT_TEXT_MAX;
	if (bytes < 4096)
		bytes = 4096;
	return (size_t)bytes;
}

/* 默认压缩目标：历史预算的 55%（低于 80% 触发线，W72 从 70% 收紧） */
static long compact_default_target(const struct ai_shell *sh)
{
	long mt = ai_config_effective_max_tokens(
			sh->config, sh->runtime.model_provider_type);
	long budget = ask_ctx_hist_budget(sh->config->ui.ctx_len, mt);
	long target = budget * ASK_COMPACT_TARGET_PCT / 100;

	if (target < 256)
		target = 256;
	return target;
}

/*
 * compact_rewrite - 按计划原子替换会话文件
 * @summary_body: 非 NULL 时写入 "[历史摘要] <body>" 并保留 plan->keep_from
 *                之后的原文；NULL 时按 plan->keep_first / keep_from 裁剪。
 */
static int compact_rewrite(const char *sess,
			   const struct ai_chat_msg *hist, int nhist,
			   const char *summary_body,
			   const struct ask_compact_plan *plan)
{
	struct ui_session_rec *recs;
	char *summary = NULL;
	int n = 0, i, rc;

	recs = calloc((size_t)(nhist - plan->keep_from + 2), sizeof(*recs));
	if (!recs)
		return AI_ERR_MEMORY;

	if (summary_body) {
		if (asprintf(&summary, "%s%s", ASK_COMPACT_SUMMARY_PREFIX,
			     summary_body) < 0) {
			free(recs);
			return AI_ERR_MEMORY;
		}
		recs[n].role = "user";
		recs[n].content = summary;
		recs[n].ts = time(NULL);
		n++;
	} else if (plan->keep_first && nhist > 0) {
		recs[n].role = hist[0].role;
		recs[n].content = hist[0].content;
		recs[n].tool_call_id = hist[0].tool_call_id;
		recs[n].tool_name = hist[0].tool_name;
		recs[n].tool_calls_json = hist[0].tool_calls_json;
		recs[n].ts = time(NULL);
		n++;
	}

	for (i = plan->keep_from; i < nhist; i++) {
		recs[n].role = hist[i].role;
		recs[n].content = hist[i].content;
		recs[n].tool_call_id = hist[i].tool_call_id;
		recs[n].tool_name = hist[i].tool_name;
		recs[n].tool_calls_json = hist[i].tool_calls_json;
		recs[n].ts = time(NULL);
		n++;
	}

	rc = ui_session_replace(sess, recs, n);
	free(summary);
	free(recs);
	return rc;
}

/*
 * compact_truncate_locked - 摘要失败/仍超限时的确定性截断
 * @hist/@nhist: 旧历史快照
 * @target:      裁剪后 token 上限
 * @before/@after: 出参
 * 返回: 0 成功（可能未变）；<0 写盘失败
 */
static int compact_truncate_locked(const char *sess,
				   const struct ai_chat_msg *hist, int nhist,
				   long target, long *before, long *after,
				   int *kept)
{
	struct ask_compact_plan plan;

	if (ask_compact_plan_truncate(hist, nhist, target,
				      ASK_COMPACT_KEEP_MAX_MSGS,
				      &plan) != 0)
		return AI_ERR_INVALID_ARG;
	*before = plan.before_tokens;
	*after = plan.after_tokens;
	*kept = (plan.keep_first ? 1 : 0) +
		(plan.keep_from < nhist ? nhist - plan.keep_from : 0);
	/* 即使一条都留不下也必须写空文件：否则旧历史仍在，下一轮继续超限 */
	return compact_rewrite(sess, hist, nhist, NULL, &plan);
}

/*
 * cmd_compact_apply - 压缩实现（cmd_compact 与 ask 自动压缩共用）
 * @target_tokens: 压缩后历史 token 上限（<=0 用默认 55% 预算）
 * @attempt:       第几次尝试（日志用；0=手动 compact）
 *
 * 返回: AI_OK 成功（含降级截断）；AI_ERR_* 失败（会话保持原样）。
 */
int cmd_compact_apply(void *shell_ptr, long target_tokens, int attempt)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;
	const char *sess;
	struct ai_chat_msg *hist = NULL;
	int nhist = 0;
	char **pool = NULL;
	int npool = 0;
	char *text = NULL;
	size_t off = 0, cap;
	size_t text_cap;
	struct ai_chat_msg req[2];
	struct ai_chat_result *result = NULL;
	char *sum_prompt = NULL;
	char *summary_body = NULL;
	struct ask_compact_plan plan;
	long before = 0, after = 0;
	int color;
	int ret;
	int i;

	color = shell->config->ui.color;
	sess = (shell->config->ui.session && shell->config->ui.session[0]) ?
	       shell->config->ui.session : UI_DEFAULT_SESSION;
	g_compact_last_kept = 0;
	g_compact_last_after = 0;

	ret = ui_session_load(sess, &hist, &nhist, &pool, &npool);
	if (ret != AI_OK) {
		printf(tr(TR_CMP_LOAD_FAIL), ai_error_string(ret));
		return ret;
	}
	if (nhist == 0) {
		printf(tr(TR_CMP_EMPTY), sess);
		ret = AI_OK;
		goto out_pool;
	}
	if (nhist > COMPACT_MSG_MAX) {
		printf(tr(TR_CMP_CAP), COMPACT_MSG_MAX, COMPACT_MSG_MAX);
		hist += nhist - COMPACT_MSG_MAX;
		nhist = COMPACT_MSG_MAX;
		/* 快照起点对齐到整轮（不得以 tool/assistant 开头） */
		while (nhist > 0 && !ask_compact_is_user(&hist[0])) {
			hist++;
			nhist--;
		}
		if (nhist == 0)
			goto out_pool;
	}
	before = ask_compact_hist_tokens(hist, nhist);
	/* 手动 compact（target<=0）：至少砍半，避免大 ctx_len 下几乎不收缩 */
	if (target_tokens <= 0) {
		long def = compact_default_target(shell);
		long half = before / 2;

		if (def > half)
			def = half;
		if (def < 256)
			def = 256;
		target_tokens = def;
	}

	/* 渲染历史为对话文本（上限预算感知，见 compact_text_cap） */
	text_cap = compact_text_cap(shell);
	cap = 4096;
	text = malloc(cap);
	if (!text) {
		ret = AI_ERR_MEMORY;
		goto out_pool;
	}
	text[0] = '\0';
	for (i = 0; i < nhist; i++) {
		char line[2048];
		const char *role = hist[i].role ? hist[i].role : "?";
		const char *content = hist[i].content ? hist[i].content : "";
		const char *tag = "";

		if (hist[i].tool_calls_json)
			tag = tr(TR_CMP_TAG_TOOLCALL);
		else if (hist[i].tool_call_id)
			tag = tr(TR_CMP_TAG_TOOLRESULT);
		snprintf(line, sizeof(line), "%s%s: %.900s\n", tag, role,
			 content);
		{
			size_t ll = strlen(line);

			if (off + ll + 1 > text_cap) {
				/* 超预算：腾出空间保留最近内容 */
				size_t keep = off / 2;
				size_t cut = off - keep;

				memmove(text, text + cut, keep + 1);
				off = keep;
			}
			while (off + ll + 1 > cap) {
				size_t ncap = cap * 2;
				char *nt = realloc(text, ncap);

				if (!nt)
					break;
				text = nt;
				cap = ncap;
			}
			memcpy(text + off, line, ll + 1);
			off += ll;
		}
	}

	/* 摘要请求（仅本请求使用；绝不写入会话历史） */
	sum_prompt = malloc(strlen(text) + 512);
	if (!sum_prompt) {
		ret = AI_ERR_MEMORY;
		goto out;
	}
	snprintf(sum_prompt, strlen(text) + 512,
		 tr(TR_CMP_PROMPT), text);

	memset(req, 0, sizeof(req));
	req[0].role = "system";
	req[0].content = tr(TR_CMP_SYS_PROMPT);
	req[1].role = "user";
	req[1].content = sum_prompt;

	printf(tr(TR_CMP_RUNNING), sess, nhist, off);
	ret = ai_runtime_chat_ex(&shell->runtime, req, 2, NULL, NULL, NULL,
				 &result);
	if (ret != AI_OK || !result || !result->content ||
	    !result->content[0]) {
		printf(tr(TR_CMP_SUM_FAIL),
		       ret != AI_OK ? ai_error_string(ret) :
		       tr(TR_ASK_EMPTY));
		if (ret == AI_OK)
			ret = AI_ERR_API;
		/* 降级：确定性截断（仍受 target 约束） */
		if (compact_truncate_locked(sess, hist, nhist, target_tokens,
					    &before, &after,
					    &g_compact_last_kept) == 0) {
			g_compact_last_after = after;
			printf(tr(TR_CMP_TRUNC), ui_c(color, UI_C_DIM));
			shell->runtime.token_used = 0;
			shell->runtime.token_session_in = 0;
			shell->runtime.token_session_out = 0;
			printf("[compact] before=%ld after=%ld attempt=%d/2 "
			       "target=%ld mode=truncate\n",
			       before, after, attempt, target_tokens);
			ret = AI_OK;
		}
		goto out;
	}

	/* 摘要成功：按目标预算截断正文（UTF-8 边界） */
	{
		size_t cap_bytes = ask_compact_summary_cap(target_tokens);
		size_t keep = strlen(result->content);

		if (keep > cap_bytes) {
			keep = ai_json_utf8_floor(result->content,
						  cap_bytes > 3 ?
						  cap_bytes - 3 : 0);
			summary_body = malloc(keep + 4);
			if (!summary_body) {
				ret = AI_ERR_MEMORY;
				goto out;
			}
			memcpy(summary_body, result->content, keep);
			memcpy(summary_body + keep, "…", 4);
		} else {
			summary_body = strdup(result->content);
			if (!summary_body) {
				ret = AI_ERR_MEMORY;
				goto out;
			}
		}
	}

	if (ask_compact_plan_summary(hist, nhist, strlen(summary_body),
				     target_tokens, ASK_COMPACT_KEEP_MAX_MSGS,
				     &plan) != 0) {
		/* 理论上 summary_cap 已保证可装下；兜底再截一半重试 */
		size_t half = strlen(summary_body) / 2;
		char *nb = realloc(summary_body, half + 4);

		if (!nb) {
			ret = AI_ERR_MEMORY;
			goto out;
		}
		summary_body = nb;
		summary_body[half] = '\0';
		if (ask_compact_plan_summary(hist, nhist,
					     strlen(summary_body),
					     target_tokens,
					     ASK_COMPACT_KEEP_MAX_MSGS,
					     &plan) != 0) {
			ret = AI_ERR_API;
			goto out;
		}
	}

	{
		int wrc = compact_rewrite(sess, hist, nhist, summary_body,
					  &plan);

		if (wrc != AI_OK) {
			printf(tr(TR_CMP_WRITE_FAIL), ai_error_string(wrc));
			ret = wrc;
			goto out;
		}
	}

	/* 历史已被原子替换：会话累计 token 同步归零 */
	shell->runtime.token_used = 0;
	shell->runtime.token_session_in = 0;
	shell->runtime.token_session_out = 0;

	before = plan.before_tokens;
	after = plan.after_tokens;
	g_compact_last_kept = nhist - plan.keep_from;
	g_compact_last_after = after;
	printf("[compact] before=%ld after=%ld attempt=%d/2 target=%ld "
	       "kept=%d summary=%zu%s\n",
	       before, after, attempt, target_tokens,
	       nhist - plan.keep_from, strlen(summary_body),
	       after > target_tokens ? " over_target=1(soft)" : "");
	printf(tr(TR_CMP_DONE), nhist - plan.keep_from,
	       ui_c(color, UI_C_DIM));
	ret = AI_OK;

out:
	free(summary_body);
	free(text);
	free(sum_prompt);
	ai_chat_result_free(result);
	free(result);
out_pool:
	{
		int j;

		for (j = 0; j < npool; j++)
			free(pool[j]);
		free(pool);
	}
	return ret;
}

int cmd_compact(void *shell_ptr, int argc, char **argv)
{
	(void)argc;
	(void)argv;
	return cmd_compact_apply(shell_ptr, 0, 0);
}
