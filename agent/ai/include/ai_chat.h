/*
 * ai_chat.h - OpenAI Chat Completions 消息/工具调用协议层接口
 *
 * Ask 工具调用闭环（cmd_ask）需要的协议扩展：
 *   - 请求体从单条 prompt 升级为 messages 数组（system/user/assistant/tool），
 *     可选携带 OpenAI function-calling 的 tools 数组；
 *   - 响应解析出 content 之外的 tool_calls（模型请求调用工具）；
 *   - 降级路径：模型/服务不支持 tools 字段时，约定模型在文本中输出
 *     JSON 工具调用（{"tool":..,"arguments":{..}} / {"answer":..}），
 *     ai_chat_parse_text_toolcall() 负责解析。
 *
 * 本模块只做"构造请求体 / 解析响应体"的纯函数，传输由 local_chat.c
 * （本地 HTTP）与 cloud_backend.c（HTTPS）各自完成，保持两条通道行为
 * 一致（同一构造器、同一解析器，避免双实现漂移）。
 */
#ifndef _AI_CHAT_H
#define _AI_CHAT_H

#include <stddef.h>

/* ---- 消息（请求侧） ---- */

/*
 * struct ai_chat_msg - 一条 OpenAI chat message
 *
 * @role:           "system" / "user" / "assistant" / "tool"
 * @content:        文本内容；assistant 发起工具调用时可为 NULL
 * @tool_call_id:   role=="tool" 时必填（对应 assistant 的 tool_calls[i].id）
 * @tool_calls_json: role=="assistant" 且发起工具调用时，预渲染好的
 *                   tool_calls JSON 数组（元素含 id/type/function，
 *                   arguments 为二次编码的 JSON 字符串）；其他情况 NULL
 */
struct ai_chat_msg {
	const char *role;
	const char *content;
	const char *tool_call_id;
	const char *tool_calls_json;
	/* role=="tool" 时的工具名（可 NULL）。OpenAI /v1 协议不使用，
	 * Ollama 原生 /api/chat 需要（tool 结果与调用按名配对） */
	const char *tool_name;
};

/* ---- 工具调用（响应侧） ---- */

struct ai_tool_call {
	char *id;           /* 调用 ID（回填 role:tool 消息用） */
	char *name;         /* 函数名（工具注册表查找键） */
	char *arguments;    /* 参数 JSON 对象字符串（原样，未解引号） */
};

struct ai_chat_result {
	char *content;                    /* assistant 文本（可为 NULL） */
	struct ai_tool_call *tool_calls;  /* 原生工具调用数组（可 NULL） */
	int tool_call_count;
	char *finish_reason;              /* "stop"/"tool_calls"/... 可 NULL */
	int  http_status;                 /* HTTP 状态码（0=未知） */
	/* ---- usage 真值（响应 usage 字段；0=服务端未提供） ---- */
	int prompt_tokens;                /* 输入 token 数 */
	int completion_tokens;            /* 输出 token 数 */
};

/* ai_chat_result_free - 释放解析结果（含全部 tool_call），幂等 */
void ai_chat_result_free(struct ai_chat_result *r);

/*
 * ai_chat_build_request_json - 构造 chat/completions 请求体（非流式）
 * @model_name:  模型名
 * @msgs:        消息数组
 * @nmsgs:       消息条数
 * @tools_json:  OpenAI tools 数组 JSON（原样嵌入）；NULL/空串则不带
 * @temperature: 采样温度
 * @max_tokens:  最大生成 token
 * 返回: malloc 请求体（调用者需 free），失败返回 NULL
 */
char *ai_chat_build_request_json(const char *model_name,
				 const struct ai_chat_msg *msgs, int nmsgs,
				 const char *tools_json,
				 double temperature, int max_tokens);

/*
 * ai_chat_build_request_json_ex - 同上，带流式开关
 * @stream: 1=请求 SSE 流式响应，并携带
 *          stream_options.include_usage（末帧回传 usage 真值）；
 *          0=与 ai_chat_build_request_json 完全一致
 */
char *ai_chat_build_request_json_ex(const char *model_name,
				    const struct ai_chat_msg *msgs,
				    int nmsgs, const char *tools_json,
				    double temperature, int max_tokens,
				    int stream);

/*
 * ai_chat_parse_response - 解析 chat/completions 响应体
 * @http_body: 原始响应体
 * @out:       输出结果（调用者用 ai_chat_result_free 释放）
 * 返回: AI_OK 成功；AI_ERR_API 业务错误对象（out.error_message 风格的
 *       细节经由返回 AI_ERR_* 表示，细节在 http_body 内由调用方打印）；
 *       AI_ERR_PARSE 结构不符
 * 说明：本函数不区分认证/网络错误（HTTP 状态码由传输层判断），
 *       只负责 2xx 响应体的结构解析；响应体含 "error" 对象时返回
 *       AI_ERR_API 并在 out->finish_reason 放置错误摘要。
 */
int ai_chat_parse_response(const char *http_body, struct ai_chat_result *out);

/* 文本降级协议解析结果 */
#define AI_TEXT_TOOL_NONE  0   /* 无工具调用（content 即最终回答） */
#define AI_TEXT_TOOL_CALL  1   /* 解析出工具调用 */

/*
 * ai_chat_parse_text_toolcall - 降级协议：从文本中解析工具调用
 * 约定格式（系统提示词中声明）：
 *   调用工具：一行 JSON  {"tool":"<工具名>","arguments":{...}}
 *   最终回答：一行 JSON  {"answer":"<中文回答>"} 或纯文本
 * @content: 模型文本输出
 * @tc:      出参，解析出的工具调用（id 固定 "text-1"，name/arguments
 *           需调用者 free；仅返回 AI_TEXT_TOOL_CALL 时有效）
 * @answer:  出参（可 NULL），"answer" 格式时的回答文本（调用者需 free）
 * 返回: AI_TEXT_TOOL_CALL / AI_TEXT_TOOL_NONE；-1 参数错误
 */
int ai_chat_parse_text_toolcall(const char *content,
				struct ai_tool_call *tc, char **answer);

/*
 * ai_chat_render_tool_calls - 把解析出的 tool_calls 渲染回 JSON 数组
 * （回填 role:assistant 消息时使用；arguments 做二次转义）
 * 返回: malloc JSON 数组字符串（调用者需 free），失败返回 NULL
 */
char *ai_chat_render_tool_calls(const struct ai_tool_call *tcs, int n);

#endif /* _AI_CHAT_H */
