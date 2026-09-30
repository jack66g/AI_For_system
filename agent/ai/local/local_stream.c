// SPDX-License-Identifier: GPL-2.0
/*
 * local_stream.c - 本地通道流式聊天（SSE / Ollama NDJSON 统一）
 *
 * 请求 stream:true 后响应体逐字节到达即经 ai_stream_agg 增量解析：
 *   - v1（OpenAI 兼容）：SSE data: 帧 + stream_options.include_usage
 *     （末帧回传 usage 真值），[DONE] 终止；
 *   - native（Ollama /api/chat）：NDJSON 逐行 JSON，done:true 行带
 *     prompt_eval_count/eval_count。
 * delta.content 逐段经调用方回调交付（cmd_ask 实时打印），
 * delta.tool_calls 碎片按 index 聚合，最终产出与非流式完全同构的
 * struct ai_chat_result（cmd_ask 下游无感）。
 *
 * 失败语义：连接失败/HTTP 4xx/5xx 返回 AI_ERR_* 且不产生任何输出
 * ——调用方（local_backend）据此自动回退非流式路径（保底可用）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_types.h"
#include "ai_stream.h"
#include "local_http.h"
#include "local_chat.h"
#include "ollama_native.h"

/* 透传给 ai_stream_agg 的上下文 */
struct feed_ctx {
	struct ai_stream_agg *agg;
	ai_stream_delta_cb cb;
	void *ud;
};

static void feed_to_agg(void *v, const char *data, size_t len)
{
	struct feed_ctx *f = v;

	ai_stream_agg_feed(f->agg, data, len, f->cb, f->ud);
}

int local_chat_stream_messages(const char *base_url, const char *model_name,
			       const char *api_key,
			       const struct ai_chat_msg *msgs, int nmsgs,
			       const char *tools_json,
			       int max_tokens, int num_ctx, int native,
			       ai_stream_delta_cb cb, void *ud,
			       struct ai_chat_result **result,
			       char **error_message, int *http_status)
{
	char url[600];
	char *body = NULL;
	struct ai_stream_agg *agg;
	struct feed_ctx f;
	char *http_resp_err = NULL;
	char *err = NULL;
	int ret;

	if (result)
		*result = NULL;
	if (error_message)
		*error_message = NULL;
	if (http_status)
		*http_status = 0;

	if (!base_url || !model_name || !msgs || nmsgs <= 0 || !result ||
	    !error_message || !cb)
		return AI_ERR_INVALID_ARG;

	agg = ai_stream_agg_create();
	if (!agg)
		return AI_ERR_MEMORY;

	if (native) {
		char root[512];

		/* num_ctx 按模型上限钳制（与非流式同一缓存） */
		if (num_ctx > 0) {
			int cap = ollama_native_ctx_cap(base_url, model_name,
							NULL);

			if (cap > 0 && num_ctx > cap)
				num_ctx = cap;
		}
		ollama_native_strip_v1(base_url, root, sizeof(root));
		snprintf(url, sizeof(url), "%s/api/chat", root);
		body = ollama_native_build_body(model_name, msgs, nmsgs,
						tools_json, max_tokens,
						num_ctx, 1);
	} else {
		size_t bl;

		bl = strlen(base_url);
		while (bl > 0 && base_url[bl - 1] == '/')
			bl--;
		snprintf(url, sizeof(url), "%.*s/chat/completions",
			 (int)bl, base_url);
		body = ai_chat_build_request_json_ex(model_name, msgs, nmsgs,
						     tools_json, 0.7,
						     max_tokens > 0 ?
						     max_tokens :
						     LOCAL_CHAT_DEFAULT_MAX_TOKENS,
						     1);
	}
	if (!body) {
		ai_stream_agg_free(agg);
		return AI_ERR_MEMORY;
	}

	f.agg = agg;
	f.cb = cb;
	f.ud = ud;

	ret = local_http_post_stream(url, api_key, body,
				     local_chat_get_timeout(),
				     feed_to_agg, &f,
				     &http_resp_err, &err, http_status);
	free(body);

	if (ret != AI_OK) {
		/* 流式未产出（连接失败/HTTP 错误）→ 交给调用方回退；
		 * 4xx 错误体暂存（方便上层提示），此处给出简洁原因 */
		ai_stream_agg_free(agg);
		if (ret == AI_ERR_API) {
			*error_message = strdup("stream request rejected "
						"(HTTP error)");
			free(err);
		} else if (err) {
			*error_message = err;   /* 所有权移交（不得再 free） */
		} else {
			*error_message = strdup("stream request failed");
		}
		free(http_resp_err);
		return ret;
	}
	free(err);
	free(http_resp_err);

	*result = calloc(1, sizeof(**result));
	if (!*result) {
		ai_stream_agg_free(agg);
		return AI_ERR_MEMORY;
	}
	ret = ai_stream_agg_finish(agg, *result);
	ai_stream_agg_free(agg);
	if (ret != AI_OK) {
		ai_chat_result_free(*result);
		free(*result);
		*result = NULL;
	}
	return ret;
}
