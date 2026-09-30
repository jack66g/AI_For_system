// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_compact.c - compact 命令实现（会话历史 LLM 摘要压缩）
 *
 * 上下文预算治理：会话历史持续增长会逼近 ctx_len 预算（提示符与
 * config show 显示百分比，>80% 黄色警告）。compact 把当前会话的
 * 全部历史通过现有 provider 通道让 LLM 摘要成一条消息，替换原文件
 * （保留会话名），预算随即回落。
 *
 * 流程：
 *   1. 加载当前会话全部消息（user/assistant/tool 渲染为对话文本）；
 *   2. 组摘要请求（system + 对话文本），走 ai_runtime_chat_ex
 *      非流式（不带 tools）；
 *   3. 摘要成功 → ui_session_clear 清空文件 → 追加一条
 *      user 消息 "[历史摘要] ..."（后续 ask 自动作为历史携带）；
 *      摘要失败 → 原会话不动，返回错误。
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
#include "ai_ui.h"

/* 送入摘要的对话文本上限（字节；超长从头截断保住最近内容） */
#define COMPACT_TEXT_MAX  48000

/* 摘要消息条数上限 */
#define COMPACT_MSG_MAX   200

int cmd_compact(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;
	const char *sess;
	struct ai_chat_msg *hist = NULL;
	int nhist = 0;
	char **pool = NULL;
	int npool = 0;
	char *text = NULL;
	size_t off = 0, cap;
	struct ai_chat_msg req[2];
	struct ai_chat_result *result = NULL;
	char *sum_prompt = NULL;
	int color;
	int ret;
	int i;

	(void)argc;
	(void)argv;

	color = shell->config->ui.color;
	sess = (shell->config->ui.session && shell->config->ui.session[0]) ?
	       shell->config->ui.session : UI_DEFAULT_SESSION;

	ret = ui_session_load(sess, &hist, &nhist, &pool, &npool);
	if (ret != AI_OK) {
		printf("compact: 会话加载失败: %s\n", ai_error_string(ret));
		return ret;
	}
	if (nhist == 0) {
		printf("compact: 会话 '%s' 无历史，无需压缩\n", sess);
		ret = AI_OK;
		goto out_pool;
	}
	if (nhist > COMPACT_MSG_MAX) {
		printf("compact: 历史超过 %d 条，仅压缩最近 %d 条\n",
		       COMPACT_MSG_MAX, COMPACT_MSG_MAX);
		hist += nhist - COMPACT_MSG_MAX;
		nhist = COMPACT_MSG_MAX;
	}

	/* 渲染历史为对话文本 */
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
			tag = "[发起工具调用] ";
		else if (hist[i].tool_call_id)
			tag = "[工具结果] ";
		snprintf(line, sizeof(line), "%s%s: %.900s\n", tag, role,
			 content);
		{
			size_t ll = strlen(line);

			if (off + ll + 1 > COMPACT_TEXT_MAX) {
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

	/* 摘要请求 */
	sum_prompt = malloc(strlen(text) + 512);
	if (!sum_prompt) {
		ret = AI_ERR_MEMORY;
		goto out;
	}
	snprintf(sum_prompt, strlen(text) + 512,
		 "请把以下 AIKernel Shell 会话历史压缩成一段简明的中文摘要"
		 "（保留：用户的目标与偏好、已执行的操作系统操作与结果、"
		 "重要事实如设备参数/代号/结论；去掉寒暄与重复），"
		 "直接输出摘要正文：\n\n%s", text);

	memset(req, 0, sizeof(req));
	req[0].role = "system";
	req[0].content = "你是会话摘要助手。只输出摘要正文，不要任何前后缀。";
	req[1].role = "user";
	req[1].content = sum_prompt;

	printf("compact: 压缩会话 '%s'（%d 条消息，%zu 字节）...\n",
	       sess, nhist, off);
	ret = ai_runtime_chat_ex(&shell->runtime, req, 2, NULL, NULL, NULL,
				 &result);
	if (ret != AI_OK || !result || !result->content ||
	    !result->content[0]) {
		printf("compact: 摘要失败（原会话保持不变）: %s\n",
		       ret != AI_OK ? ai_error_string(ret) : "空响应");
		if (ret == AI_OK)
			ret = AI_ERR_API;
		goto out;
	}

	/* 摘要成功：清空会话并写入单条摘要消息 */
	{
		char *summary = malloc(strlen(result->content) + 64);
		struct ui_session_rec rec;
		int rc;

		if (!summary) {
			ret = AI_ERR_MEMORY;
			goto out;
		}
		sprintf(summary, "[历史摘要] %s", result->content);
		rc = ui_session_clear(sess);
		if (rc != AI_OK) {
			printf("compact: 会话清空失败: %s\n",
			       ai_error_string(rc));
			free(summary);
			ret = rc;
			goto out;
		}
		memset(&rec, 0, sizeof(rec));
		rec.role = "user";
		rec.content = summary;
		rec.ts = time(NULL);
		rc = ui_session_append(sess, &rec);
		free(summary);
		if (rc != AI_OK) {
			printf("compact: 摘要写入失败: %s\n",
			       ai_error_string(rc));
			ret = rc;
			goto out;
		}

		/* 历史已被摘要替换：会话累计 token 同步归零，提示符与
		 * config show 的上下文预算百分比如实回落（否则压缩后
		 * 仍显示压缩前的虚高占用） */
		shell->runtime.token_used = 0;
		shell->runtime.token_session_in = 0;
		shell->runtime.token_session_out = 0;
	}

	printf("compact: 完成，历史压缩为 1 条摘要消息%s\n",
	       ui_c(color, UI_C_DIM));
	ret = AI_OK;

out:
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
