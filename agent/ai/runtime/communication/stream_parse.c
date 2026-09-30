// SPDX-License-Identifier: GPL-2.0
/*
 * stream_parse.c - 流式响应增量解析器实现（SSE data: 帧 + Ollama NDJSON）
 *
 * 见 include/ai_stream.h 的格式约定。实现要点：
 *   - 行缓冲：feed 的字节可能把一行任意切开，用可增长行缓冲拼接，
 *     遇 '\n' 交出完整行（容忍 '\r\n'）；finish 时冲刷残行；
 *   - 每行按 SSE 语义剥离 "data:" 前缀与可选空格；"[DONE]" 终止；
 *     以 ':' 开头的行是 SSE 注释（如 ": keepalive"）直接忽略；
 *   - JSON 分派：有 "choices" → OpenAI chunk（delta.content /
 *     delta.tool_calls 碎片聚合 / finish_reason / usage）；有 "message" →
 *     Ollama 原生 chunk（message.content / 整体 tool_calls /
 *     done + prompt_eval_count/eval_count + done_reason）；
 *   - tool_calls 碎片按 index 聚合：同 index 的 arguments 字符串顺序
 *     拼接，id/name 首个出现值生效（OpenAI 流式约定）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_types.h"
#include "ai_json_util.h"
#include "ai_stream.h"

/* 单行上限（防御失控帧；正常 chunk 远小于此） */
#define SP_LINE_MAX  (1 * 1024 * 1024)

struct ai_stream_agg {
	/* 行缓冲（跨 feed 拼接半行） */
	char *line;
	size_t line_len;
	size_t line_cap;
	int line_overflow;

	/* content 全量 */
	char *content;
	size_t content_len;
	size_t content_cap;

	/* tool_calls 聚合（OpenAI 碎片按 index 对位） */
	struct ai_tool_call *tcs;
	int ntc;
	int tcs_cap;

	char *finish_reason;
	char *error_msg;
	long prompt_tokens;
	long completion_tokens;
	int done;               /* [DONE] 或 done:true */
};

struct ai_stream_agg *ai_stream_agg_create(void)
{
	return calloc(1, sizeof(struct ai_stream_agg));
}

void ai_stream_agg_free(struct ai_stream_agg *ag)
{
	int i;

	if (!ag)
		return;
	free(ag->line);
	free(ag->content);
	for (i = 0; i < ag->ntc; i++) {
		free(ag->tcs[i].id);
		free(ag->tcs[i].name);
		free(ag->tcs[i].arguments);
	}
	free(ag->tcs);
	free(ag->finish_reason);
	free(ag->error_msg);
	free(ag);
}

/* ---- 内部小工具 ---- */

static int buf_append(char **buf, size_t *len, size_t *cap,
		      const char *s, size_t n)
{
	if (*len + n + 1 > *cap) {
		size_t ncap = *cap ? *cap : 256;
		char *nb;

		while (ncap < *len + n + 1)
			ncap *= 2;
		nb = realloc(*buf, ncap);
		if (!nb)
			return -1;
		*buf = nb;
		*cap = ncap;
	}
	memcpy(*buf + *len, s, n);
	*len += n;
	(*buf)[*len] = '\0';
	return 0;
}

/* 按 index 取/建聚合槽位（index 越界新增） */
static struct ai_tool_call *agg_tc_slot(struct ai_stream_agg *ag, int index)
{
	int want = index + 1;
	int i;

	if (want > ag->tcs_cap) {
		int ncap = ag->tcs_cap ? ag->tcs_cap : 4;
		struct ai_tool_call *nt;

		while (ncap < want)
			ncap *= 2;
		nt = realloc(ag->tcs, sizeof(*nt) * (size_t)ncap);
		if (!nt)
			return NULL;
		ag->tcs = nt;
		ag->tcs_cap = ncap;
	}
	for (i = ag->ntc; i < want; i++) {
		memset(&ag->tcs[i], 0, sizeof(ag->tcs[i]));
		ag->ntc++;
	}
	return &ag->tcs[index];
}

/* 追加一段 content 并回调 */
static void emit_content(struct ai_stream_agg *ag, const char *s, size_t n,
			 ai_stream_delta_cb cb, void *ud)
{
	if (n == 0)
		return;
	if (buf_append(&ag->content, &ag->content_len, &ag->content_cap,
		       s, n) != 0)
		return;
	if (cb)
		cb(ud, s, n);
}

static void set_finish_reason(struct ai_stream_agg *ag, const char *tok,
			      size_t len)
{
	char *s = ai_json_strdup_str(tok, len);

	if (!s)
		return;
	free(ag->finish_reason);
	ag->finish_reason = s;
}

/* ---- OpenAI chunk 解析 ---- */

static void parse_openai_tool_deltas(struct ai_stream_agg *ag,
				     const char *arr, size_t alen)
{
	const char *p = arr;
	const char *end = arr + alen;

	p = ai_json_skip_ws(p + 1, end);        /* 跳过 '[' */
	while (p < end && *p != ']') {
		const char *etok, *fv;
		size_t elen, fvl;
		int etype, ftype;
		long index = 0;

		if (ai_json_scan_value(&p, end, &etok, &elen, &etype) != 0)
			return;
		if (etype == AI_JSON_OBJ) {
			struct ai_tool_call *slot;

			if (ai_json_obj_get(etok, elen, "index", &fv, &fvl,
					    &ftype) == 1 && ftype == AI_JSON_NUM)
				index = ai_json_ll(fv, fvl);
			slot = agg_tc_slot(ag, (int)index);
			if (slot) {
				if (ai_json_obj_get(etok, elen, "id", &fv,
						    &fvl, &ftype) == 1 &&
				    ftype == AI_JSON_STR && !slot->id)
					slot->id = ai_json_strdup_str(fv, fvl);
				if (ai_json_obj_get(etok, elen, "function",
						    &fv, &fvl, &ftype) == 1 &&
				    ftype == AI_JSON_OBJ) {
					const char *nv, *av;
					size_t nl, nal;
					int nt_, at;

					if (ai_json_obj_get(fv, fvl, "name",
							    &nv, &nl,
							    &nt_) == 1 &&
					    nt_ == AI_JSON_STR && !slot->name)
						slot->name =
							ai_json_strdup_str(nv,
									   nl);
					/* arguments 为字符串碎片 → 顺序拼接 */
					if (ai_json_obj_get(fv, fvl,
							    "arguments", &av,
							    &nal, &at) == 1 &&
					    at == AI_JSON_STR) {
						char *frag =
							ai_json_strdup_str(av,
									   nal);

						if (frag) {
							char *merged;

							if (slot->arguments) {
								merged = realloc(
						    slot->arguments,
						    strlen(slot->arguments) +
						    strlen(frag) + 1);
								if (merged)
									strcat(
						  merged, frag);
								free(frag);
								slot->arguments =
									merged;
							} else {
								slot->arguments =
									frag;
							}
						}
					}
				}
			}
		}
		p = ai_json_skip_ws(p, end);
		if (p < end && *p == ',') {
			p++;
			continue;
		}
		break;
	}
}

static void parse_openai_chunk(struct ai_stream_agg *ag, const char *obj,
			       size_t olen, ai_stream_delta_cb cb, void *ud)
{
	const char *v;
	size_t vl;
	int vt;

	if (ai_json_obj_get(obj, olen, "choices", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_ARR && vl > 0) {
		const char *c0 = v;
		size_t c0l = vl;

		if (ai_json_arr_get(c0, c0l, 0, &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_OBJ) {
			const char *ch = v;
			size_t chl = vl;
			const char *dv;
			size_t dl;
			int dt;

			if (ai_json_obj_get(ch, chl, "delta", &dv, &dl,
					    &dt) == 1 && dt == AI_JSON_OBJ) {
				const char *cv;
				size_t cl;
				int ct;

				if (ai_json_obj_get(dv, dl, "content", &cv,
						    &cl, &ct) == 1 &&
				    ct == AI_JSON_STR) {
					char *s = ai_json_strdup_str(cv, cl);

					if (s) {
						emit_content(ag, s, strlen(s),
							     cb, ud);
						free(s);
					}
				}
				if (ai_json_obj_get(dv, dl, "tool_calls", &cv,
						    &cl, &ct) == 1 &&
				    ct == AI_JSON_ARR)
					parse_openai_tool_deltas(ag, cv, cl);
			}
			if (ai_json_obj_get(ch, chl, "finish_reason", &dv,
					    &dl, &dt) == 1 && dt == AI_JSON_STR)
				set_finish_reason(ag, dv, dl);
		}
	}

	/* usage（任意 chunk 均可出现；include_usage 时在末帧） */
	if (ai_json_obj_get(obj, olen, "usage", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_OBJ) {
		const char *uv = v;
		size_t ul = vl;
		const char *nv;
		size_t nl;
		int nt_;

		if (ai_json_obj_get(uv, ul, "prompt_tokens", &nv, &nl,
				    &nt_) == 1 && nt_ == AI_JSON_NUM)
			ag->prompt_tokens = ai_json_ll(nv, nl);
		if (ai_json_obj_get(uv, ul, "completion_tokens", &nv, &nl,
				    &nt_) == 1 && nt_ == AI_JSON_NUM)
			ag->completion_tokens = ai_json_ll(nv, nl);
	}
}

/* ---- Ollama 原生 chunk 解析 ---- */

static void parse_ollama_tool_calls(struct ai_stream_agg *ag,
				    const char *arr, size_t alen)
{
	const char *p = arr;
	const char *end = arr + alen;

	p = ai_json_skip_ws(p + 1, end);        /* 跳过 '[' */
	while (p < end && *p != ']') {
		const char *etok, *fv;
		size_t elen, fvl;
		int etype, ftype;

		if (ai_json_scan_value(&p, end, &etok, &elen, &etype) != 0)
			return;
		if (etype == AI_JSON_OBJ &&
		    ai_json_obj_get(etok, elen, "function", &fv, &fvl,
				    &ftype) == 1 && ftype == AI_JSON_OBJ) {
			const char *nv, *av;
			size_t nl, al;
			int nt_, at;
			struct ai_tool_call *slot =
				agg_tc_slot(ag, ag->ntc);

			if (slot) {
				if (ai_json_obj_get(fv, fvl, "name", &nv, &nl,
						    &nt_) == 1 &&
				    nt_ == AI_JSON_STR)
					slot->name =
						ai_json_strdup_str(nv, nl);
				/* 原生协议 arguments 是 JSON 对象 → 原样截取 */
				if (ai_json_obj_get(fv, fvl, "arguments", &av,
						    &al, &at) == 1) {
					if (at == AI_JSON_OBJ) {
						slot->arguments = malloc(al + 1);
						if (slot->arguments) {
							memcpy(slot->arguments,
							       av, al);
							slot->arguments[al] =
								'\0';
						}
					} else if (at == AI_JSON_STR) {
						slot->arguments =
							ai_json_strdup_str(av,
									   al);
					}
				}
			}
		}
		p = ai_json_skip_ws(p, end);
		if (p < end && *p == ',') {
			p++;
			continue;
		}
		break;
	}
}

static void parse_ollama_chunk(struct ai_stream_agg *ag, const char *obj,
			       size_t olen, ai_stream_delta_cb cb, void *ud)
{
	const char *v;
	size_t vl;
	int vt;

	/* tool_calls：多数版本在 message 内；也有版本放在 chunk 顶层，
	 * 两处都查（同一 chunk 不会两处同时出现） */
	if (ai_json_obj_get(obj, olen, "tool_calls", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_ARR)
		parse_ollama_tool_calls(ag, v, vl);

	if (ai_json_obj_get(obj, olen, "message", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_OBJ) {
		const char *mv = v;
		size_t ml = vl;
		const char *cv;
		size_t cl;
		int ct;

		if (ai_json_obj_get(mv, ml, "content", &cv, &cl,
				    &ct) == 1 && ct == AI_JSON_STR) {
			char *s = ai_json_strdup_str(cv, cl);

			if (s) {
				emit_content(ag, s, strlen(s), cb, ud);
				free(s);
			}
		}
		if (ai_json_obj_get(mv, ml, "tool_calls", &cv, &cl,
				    &ct) == 1 && ct == AI_JSON_ARR)
			parse_ollama_tool_calls(ag, cv, cl);
	}

	if (ai_json_obj_get(obj, olen, "done_reason", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		set_finish_reason(ag, v, vl);

	if (ai_json_obj_get(obj, olen, "done", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_BOOL && v[1] == 't')
		ag->done = 1;

	/* token 计数：原生字段 prompt_eval_count/eval_count，
	 * 新版兼容 OpenAI 风格 usage/prompt_tokens */
	{
		const char *nv;
		size_t nl;
		int nt_;

		if (ai_json_obj_get(obj, olen, "prompt_eval_count", &nv, &nl,
				    &nt_) == 1 && nt_ == AI_JSON_NUM)
			ag->prompt_tokens = ai_json_ll(nv, nl);
		if (ai_json_obj_get(obj, olen, "eval_count", &nv, &nl,
				    &nt_) == 1 && nt_ == AI_JSON_NUM)
			ag->completion_tokens = ai_json_ll(nv, nl);
		if (ai_json_obj_get(obj, olen, "prompt_tokens", &nv, &nl,
				    &nt_) == 1 && nt_ == AI_JSON_NUM)
			ag->prompt_tokens = ai_json_ll(nv, nl);
		if (ai_json_obj_get(obj, olen, "completion_tokens", &nv, &nl,
				    &nt_) == 1 && nt_ == AI_JSON_NUM)
			ag->completion_tokens = ai_json_ll(nv, nl);
	}
}

/* ---- 单行处理 ---- */

static void process_line(struct ai_stream_agg *ag, char *line,
			 ai_stream_delta_cb cb, void *ud)
{
	const char *payload = line;
	const char *tok;
	size_t tlen;
	int ttype;
	const char *p, *end;

	/* SSE 注释（": keepalive"）与空行 */
	if (payload[0] == '\0' || payload[0] == ':')
		return;
	/* SSE "data:" 前缀 */
	if (strncmp(payload, "data:", 5) == 0) {
		payload += 5;
		while (*payload == ' ')
			payload++;
	}
	if (strcmp(payload, "[DONE]") == 0) {
		ag->done = 1;
		return;
	}

	/* Ollama 事件行（native /api/chat 另有 {"event":"..."} 形态，跳过） */
	if (strncmp(payload, "event:", 6) == 0)
		return;

	p = payload;
	end = payload + strlen(payload);
	if (ai_json_scan_value(&p, end, &tok, &tlen, &ttype) != 0)
		return;   /* 非法帧忽略（尽力而为） */
	if (ttype != AI_JSON_OBJ)
		return;

	/* 流内错误对象 */
	{
		const char *v;
		size_t vl;
		int vt;

		if (ai_json_obj_get(tok, tlen, "error", &v, &vl, &vt) == 1) {
			char *msg = NULL;

			if (vt == AI_JSON_OBJ &&
			    ai_json_obj_get(v, vl, "message", &v, &vl,
					    &vt) == 1 && vt == AI_JSON_STR)
				msg = ai_json_strdup_str(v, vl);
			else if (vt == AI_JSON_STR)
				msg = ai_json_strdup_str(v, vl);
			if (msg) {
				free(ag->error_msg);
				ag->error_msg = msg;
				ag->done = 1;
			}
			return;
		}
	}

	/* 分派：choices → OpenAI；message → Ollama 原生 */
	{
		const char *v;
		size_t vl;
		int vt;

		if (ai_json_obj_get(tok, tlen, "choices", &v, &vl,
				    &vt) == 1) {
			parse_openai_chunk(ag, tok, tlen, cb, ud);
			return;
		}
		if (ai_json_obj_get(tok, tlen, "message", &v, &vl,
				    &vt) == 1) {
			parse_ollama_chunk(ag, tok, tlen, cb, ud);
			return;
		}
	}
}

/* ---- 对外接口 ---- */

void ai_stream_agg_feed(struct ai_stream_agg *ag, const char *data,
			size_t len, ai_stream_delta_cb cb, void *ud)
{
	size_t i = 0;

	if (!ag || !data)
		return;

	while (i < len) {
		const char *nl = memchr(data + i, '\n', len - i);
		size_t take;

		if (!nl) {
			/* 残行入缓冲 */
			if (!ag->line_overflow) {
				if (buf_append(&ag->line, &ag->line_len,
					       &ag->line_cap, data + i,
					       len - i) != 0)
					ag->line_overflow = 1;
			}
			break;
		}
		take = (size_t)(nl - (data + i));
		if (take > 0 && !ag->line_overflow) {
			if (buf_append(&ag->line, &ag->line_len,
				       &ag->line_cap, data + i, take) != 0)
				ag->line_overflow = 1;
		}
		if (ag->line && ag->line_len > 0 &&
		    ag->line[ag->line_len - 1] == '\r')
			ag->line[--ag->line_len] = '\0';   /* 容忍 \r\n */

		if (ag->line_overflow) {
			/* 超长行丢弃，防失控 */
			ag->line_len = 0;
			ag->line_overflow = 0;
			if (ag->line)
				ag->line[0] = '\0';
		} else if (ag->line) {
			ag->line[ag->line_len] = '\0';
			process_line(ag, ag->line, cb, ud);
			ag->line_len = 0;
			ag->line[0] = '\0';
		}
		i += take + 1;
	}
}

int ai_stream_agg_finish(struct ai_stream_agg *ag, struct ai_chat_result *out)
{
	if (!ag || !out)
		return AI_ERR_INVALID_ARG;

	memset(out, 0, sizeof(*out));

	/* 冲刷残行（无换行结尾的最后一帧） */
	if (ag->line && ag->line_len > 0 && !ag->line_overflow) {
		ag->line[ag->line_len] = '\0';
		process_line(ag, ag->line, NULL, NULL);
	}

	if (ag->content) {
		out->content = malloc(ag->content_len + 1);
		if (out->content) {
			memcpy(out->content, ag->content, ag->content_len);
			out->content[ag->content_len] = '\0';
		}
	}
	if (ag->ntc > 0) {
		out->tool_calls = ag->tcs;
		out->tool_call_count = ag->ntc;
		ag->tcs = NULL;     /* 所有权移交 */
		ag->ntc = 0;
		ag->tcs_cap = 0;
	}
	if (ag->finish_reason)
		out->finish_reason = strdup(ag->finish_reason);
	else if (ag->done)
		out->finish_reason = strdup("stop");
	out->prompt_tokens = (int)ag->prompt_tokens;
	out->completion_tokens = (int)ag->completion_tokens;

	if (ag->error_msg) {
		free(out->finish_reason);
		out->finish_reason = ag->error_msg;   /* 借用字段携错误 */
		ag->error_msg = NULL;
		return AI_ERR_API;
	}
	return AI_OK;
}
