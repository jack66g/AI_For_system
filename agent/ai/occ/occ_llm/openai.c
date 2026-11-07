/* SPDX-License-Identifier: GPL-2.0 */
/*
 * openai.c - OpenAI 兼容协议（chat completions + tools）T9a1
 *
 * 请求构造对齐 opencode packages/ai/src/protocols/openai-chat.ts：
 *   - 体序 :901-925 model, messages, tools, tool_choice, stream,
 *     stream_options{include_usage:true}(streamUsage 默认 true :910),
 *     max_tokens(deepseek maxTokensField :49-52/781), temperature, ...,
 *     parallel_tool_calls（lowerOptions 展开在末尾 :867）
 *   - 无 tools 但有工具历史 → tools:[]（:903-906）
 *   - 工具定义 {type:"function",function:{name,description?,parameters,
 *     strict:false}}（strict 位置 :413；deepseek 不在排除表 :824-831）
 *   - assistant 空 content + tool_calls → content:null（:560-562）
 *   - requireReasoning（deepseek 系）：assistant 回放后置
 *     reasoning_content（:529-570/:662-672；真 400 实证见差分向量
 *     g07_tool_result 首录）
 *   - tool 结果独立 role:"tool" 消息（:620-625）
 *   - system 为首条 {"role":"system","content":<joined>}（:646-660）
 *
 * SSE 消费对齐同文件流解析（step :1112-1260）：
 *   - delta.content/refusal → 文本增量；reasoning_content|reasoning|
 *     reasoning_text → 思维链增量（reasoningDelta :1016-1027）
 *   - delta.tool_calls[] 按 index（缺省按 id 匹配/latest）累积，arguments
 *     片段拼接（:1192-1240）；finish 后再收到工具增量 → 错误（:1138-1146）
 *   - usage：顶层 usage ?? choice.usage（Moonshot :1125-1127）；input=
 *     prompt_tokens、cache_read=prompt_tokens_details.cached_tokens ??
 *     prompt_cache_hit_tokens ?? cached_tokens（:976-997），字段级合并
 *   - finish_reason 映射（mapFinishReason :949-972）
 */
#include "occ_llm.h"
#include "occ_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "store/store_json.h"

/* ================= 请求构造 ================= */

static aik_json *parse_json_text(const char *text, const char *what)
{
	char err[96];
	aik_json *v;

	if (!text || !*text) {
		v = aik_json_new_obj();
		return v;
	}
	v = aik_json_parse(text, strlen(text), err, sizeof(err));
	if (!v)
		return NULL;
	(void)what;
	return v;
}

static aik_json *build_msg_user(const occ_msg *m)
{
	aik_json *o = aik_json_new_obj();

	if (!o)
		return NULL;
	if (aik_json_obj_put(o, "role", aik_json_new_str("user")) ||
	    aik_json_obj_put(o, "content", aik_json_new_str(m->text ? m->text : "")))
		goto fail;
	return o;
fail:
	aik_json_free(o);
	return NULL;
}

static aik_json *build_msg_assistant(const occ_msg *m, int require_reasoning)
{
	aik_json *o = aik_json_new_obj();
	size_t i;

	if (!o)
		return NULL;
	if (aik_json_obj_put(o, "role", aik_json_new_str("assistant")))
		goto fail;
	/* openai-chat.ts:560-562：无文本 part 且有 tool_calls → content:null */
	if (m->text)
		aik_json_obj_put(o, "content", aik_json_new_str(m->text));
	else if (m->ncalls > 0)
		aik_json_obj_put(o, "content", aik_json_new_null());
	else
		aik_json_obj_put(o, "content", aik_json_new_str(""));
	if (m->ncalls > 0) {
		aik_json *arr = aik_json_new_arr();

		if (!arr)
			goto fail;
		for (i = 0; i < m->ncalls; i++) {
			aik_json *tc = aik_json_new_obj();
			aik_json *fn = aik_json_new_obj();

			if (!tc || !fn)
				goto fail;
			if (aik_json_obj_put(tc, "id",
					aik_json_new_str(m->calls[i].id)) ||
			    aik_json_obj_put(tc, "type",
					aik_json_new_str("function")) ||
			    aik_json_obj_put(fn, "name",
					aik_json_new_str(m->calls[i].name)) ||
			    aik_json_obj_put(fn, "arguments",
					aik_json_new_str(m->calls[i].arguments ?
						m->calls[i].arguments : "")) ||
			    aik_json_obj_put(tc, "function", fn)) {
				aik_json_free(fn);
				aik_json_free(tc);
				goto fail;
			}
			if (aik_json_arr_push(arr, tc)) {
				aik_json_free(tc);
				goto fail;
			}
		}
		if (aik_json_obj_put(o, "tool_calls", arr)) {
			aik_json_free(arr);
			goto fail;
		}
	}
	/* openai-chat.ts:529-570：requireReasoning（deepseek 系，:662-672）时
	 * assistant 回放必带 reasoning_content（无思维链 part → 空串）；
	 * 键在 role/content/tool_calls 之后（result 后置 spread） */
	if (require_reasoning)
		aik_json_obj_put(o, "reasoning_content",
				 aik_json_new_str(m->reasoning ? m->reasoning : ""));
	return o;
fail:
	aik_json_free(o);
	return NULL;
}

static aik_json *build_msg_tool(const occ_msg *m)
{
	aik_json *o = aik_json_new_obj();

	if (!o)
		return NULL;
	if (aik_json_obj_put(o, "role", aik_json_new_str("tool")) ||
	    aik_json_obj_put(o, "tool_call_id",
			aik_json_new_str(m->tool_call_id ? m->tool_call_id : "")) ||
	    aik_json_obj_put(o, "content",
			aik_json_new_str(m->text ? m->text : "")))
		goto fail;
	return o;
fail:
	aik_json_free(o);
	return NULL;
}

static aik_json *build_tool_def(const occ_tool_def *t)
{
	aik_json *o = aik_json_new_obj();
	aik_json *fn = aik_json_new_obj();
	aik_json *params;

	if (!o || !fn)
		goto fail;
	params = parse_json_text(t->parameters, "parameters");
	if (!params)
		goto fail;
	if (aik_json_obj_put(fn, "name", aik_json_new_str(t->name)))
		goto fail;
	if (t->description && *t->description &&
	    aik_json_obj_put(fn, "description", aik_json_new_str(t->description)))
		goto fail;
	if (aik_json_obj_put(fn, "parameters", params)) {
		aik_json_free(params);
		goto fail;
	}
	/* strict:false（openai-chat.ts:413+824-831：deepseek 支持 strict 语义位） */
	if (aik_json_obj_put(fn, "strict", aik_json_new_bool(0)))
		goto fail;
	if (aik_json_obj_put(o, "type", aik_json_new_str("function")) ||
	    aik_json_obj_put(o, "function", fn)) {
		aik_json_free(fn);
		goto fail;
	}
	return o;
fail:
	aik_json_free(fn);
	aik_json_free(o);
	return NULL;
}

char *occ_build_request_openai(const occ_llm_req *req, size_t *outlen)
{
	aik_json *body = NULL, *msgs = NULL, *tools = NULL;
	char *out = NULL;
	size_t dummy;
	size_t i;
	int has_history = 0;

	if (!outlen)
		outlen = &dummy;	/* aik_json_dump 要求非 NULL */
	body = aik_json_new_obj();
	msgs = aik_json_new_arr();
	if (!body || !msgs)
		goto out;
	if (aik_json_obj_put(body, "model", aik_json_new_str(req->model)))
		goto out;
	if (req->system) {
		aik_json *sm = aik_json_new_obj();

		if (!sm)
			goto out;
		if (aik_json_obj_put(sm, "role", aik_json_new_str("system")) ||
		    aik_json_obj_put(sm, "content", aik_json_new_str(req->system)) ||
		    aik_json_arr_push(msgs, sm)) {
			aik_json_free(sm);
			goto out;
		}
	}
	for (i = 0; i < req->nmsgs; i++) {
		const occ_msg *m = &req->msgs[i];
		aik_json *o;

		if (m->role == OCC_ROLE_ASSISTANT && m->ncalls > 0)
			has_history = 1;
		if (m->role == OCC_ROLE_TOOL)
			has_history = 1;
		if (m->role == OCC_ROLE_USER)
			o = build_msg_user(m);
		else if (m->role == OCC_ROLE_ASSISTANT)
			o = build_msg_assistant(m, req->require_reasoning);
		else
			o = build_msg_tool(m);
		if (!o)
			goto out;
		if (aik_json_arr_push(msgs, o)) {
			aik_json_free(o);
			goto out;
		}
	}
	if (aik_json_obj_put(body, "messages", msgs)) {
		msgs = NULL;
		goto out;
	}
	msgs = NULL;
	if (req->ntools > 0) {
		tools = aik_json_new_arr();
		if (!tools)
			goto out;
		for (i = 0; i < req->ntools; i++) {
			aik_json *t = build_tool_def(&req->tools[i]);

			if (!t)
				goto out;
			if (aik_json_arr_push(tools, t)) {
				aik_json_free(t);
				goto out;
			}
		}
		if (aik_json_obj_put(body, "tools", tools)) {
			tools = NULL;
			goto out;
		}
		tools = NULL;
	} else if (has_history) {
		/* openai-chat.ts:903-906：有工具历史无活跃工具 → tools:[] */
		tools = aik_json_new_arr();
		if (!tools)
			goto out;
		if (aik_json_obj_put(body, "tools", tools)) {
			tools = NULL;
			goto out;
		}
		tools = NULL;
	}
	if (aik_json_obj_put(body, "stream", aik_json_new_bool(1)))
		goto out;
	{
		aik_json *so = aik_json_new_obj();

		if (!so)
			goto out;
		if (aik_json_obj_put(so, "include_usage", aik_json_new_bool(1)) ||
		    aik_json_obj_put(body, "stream_options", so)) {
			aik_json_free(so);
			goto out;
		}
	}
	if (req->gen.has_max_tokens &&
	    aik_json_obj_put(body, "max_tokens",
			aik_json_new_int(req->gen.max_tokens)))
		goto out;
	if (req->gen.has_temperature &&
	    aik_json_obj_put(body, "temperature",
			aik_json_new_num(req->gen.temperature)))
		goto out;
	if (req->parallel_tool_calls && req->ntools > 0 &&
	    aik_json_obj_put(body, "parallel_tool_calls", aik_json_new_bool(1)))
		goto out;
	if (aik_json_dump(body, &out, outlen))
		out = NULL;
out:
	aik_json_free(body);
	aik_json_free(msgs);
	aik_json_free(tools);
	return out;
}

/* ================= 流事件解析 ================= */

#define OAI_MAX_TOOLS 64
#define OAI_ID_MAX 160

struct oai_tool {
	char id[OAI_ID_MAX];
	char name[OAI_ID_MAX];
	int started;
};

struct oai_state {
	struct oai_tool tools[OAI_MAX_TOOLS];
	int ntools;
	int latest;
	int finish_emitted;
	/* usage 字段级合并（openai-chat.ts:1125-1127 state.usage 保留） */
	long long u_in, u_out, u_cread, u_cwrite;
	int u_has;
};

void *occ_openai_state_new(void)
{
	return calloc(1, sizeof(struct oai_state));
}

void occ_openai_state_free(void *st)
{
	free(st);
}

static const aik_json *usage_cache_read(const aik_json *u)
{
	const aik_json *d = aik_json_get(u, "prompt_tokens_details");
	const aik_json *v;

	/* :984-988：details.cached_tokens ?? prompt_cache_hit_tokens ?? cached_tokens */
	if (d) {
		v = aik_json_get(d, "cached_tokens");
		if (v && aik_json_typeof(v) == AIK_JSON_INT)
			return v;
	}
	v = aik_json_get(u, "prompt_cache_hit_tokens");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		return v;
	return aik_json_get(u, "cached_tokens");
}

static const aik_json *usage_cache_write(const aik_json *u)
{
	const aik_json *d = aik_json_get(u, "prompt_tokens_details");
	const aik_json *v;

	if (d) {
		v = aik_json_get(d, "cache_write_tokens");
		if (v && aik_json_typeof(v) == AIK_JSON_INT)
			return v;
	}
	return aik_json_get(u, "cache_created_input_tokens");
}

static void map_usage(struct oai_state *st, const aik_json *u,
		      occ_event_cb cb, void *ud)
{
	occ_event ev;
	const aik_json *v;

	if (!u || aik_json_typeof(u) != AIK_JSON_OBJ)
		return;
	v = aik_json_get(u, "prompt_tokens");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		st->u_in = aik_json_int(v);
	v = aik_json_get(u, "completion_tokens");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		st->u_out = aik_json_int(v);
	v = usage_cache_read(u);
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		st->u_cread = aik_json_int(v);
	v = usage_cache_write(u);
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		st->u_cwrite = aik_json_int(v);
	st->u_has = 1;

	memset(&ev, 0, sizeof(ev));
	ev.type = OCC_EV_USAGE;
	ev.usage.input = st->u_in;
	ev.usage.output = st->u_out;
	ev.usage.cache_read = st->u_cread;
	ev.usage.cache_write = st->u_cwrite;
	ev.usage.present = 1;
	cb(&ev, ud);
}

static const char *map_finish(const char *raw, int *is_error)
{
	*is_error = 0;
	if (!raw)
		return "unknown";
	if (!strcmp(raw, "stop") || !strcmp(raw, "end"))
		return "stop";
	if (!strcmp(raw, "length"))
		return "length";
	if (!strcmp(raw, "tool_calls") || !strcmp(raw, "function_call"))
		return "tool-calls";
	if (!strcmp(raw, "content_filter"))
		return "content-filter";
	if (!strcmp(raw, "error") || !strcmp(raw, "network_error"))
		*is_error = 1;
	return "unknown";
}

static int tool_index_for(struct oai_state *st, const aik_json *tc, int position)
{
	const aik_json *v = aik_json_get(tc, "index");
	int idx = -1, i;
	const char *id = NULL;

	if (v && aik_json_typeof(v) == AIK_JSON_INT) {
		idx = (int)aik_json_int(v);
		if (idx < 0 || idx >= OAI_MAX_TOOLS)
			return -1;
		return idx;
	}
	v = aik_json_get(tc, "id");
	if (v && aik_json_typeof(v) == AIK_JSON_STR)
		id = aik_json_str(v);
	if (id) {
		for (i = 0; i < st->ntools; i++)
			if (st->tools[i].id[0] && !strcmp(st->tools[i].id, id))
				return i;
	}
	if (st->latest >= 0)
		return st->latest;
	return position;
}

static void emit_ev(occ_event_cb cb, void *ud, occ_event *ev)
{
	cb(ev, ud);
}

int occ_openai_event(void *state, const char *json, size_t len,
		     occ_event_cb cb, void *ud)
{
	struct oai_state *st = state;
	char err[96];
	aik_json *root;
	const aik_json *choices, *choice, *delta, *u, *fr;
	size_t i;

	root = aik_json_parse(json, len, err, sizeof(err));
	if (!root)
		return 0;			/* framing 层已校验，防御 */

	u = aik_json_get(root, "error");
	if (u && aik_json_typeof(u) == AIK_JSON_OBJ) {
		const aik_json *m = aik_json_get(u, "message");
		occ_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.type = OCC_EV_ERROR;
		ev.err = (m && aik_json_typeof(m) == AIK_JSON_STR) ?
			aik_json_str(m) : "provider error event";
		emit_ev(cb, ud, &ev);
		aik_json_free(root);
		return 0;
	}
	choices = aik_json_get(root, "choices");
	choice = NULL;
	if (choices && aik_json_typeof(choices) == AIK_JSON_ARR &&
	    aik_json_count(choices) > 0)
		choice = aik_json_at(choices, 0);

	/* usage：顶层 ?? choice.usage（Moonshot），字段级合并保留 */
	u = aik_json_get(root, "usage");
	if ((!u || aik_json_typeof(u) != AIK_JSON_OBJ) && choice)
		u = aik_json_get(choice, "usage");
	if (u)
		map_usage(st, u, cb, ud);

	if (!choice) {
		aik_json_free(root);
		return 0;
	}
	delta = aik_json_get(choice, "delta");
	fr = aik_json_get(choice, "finish_reason");

	if (delta && aik_json_typeof(delta) == AIK_JSON_OBJ) {
		static const char *rfields[3] = {
			"reasoning_content", "reasoning", "reasoning_text"
		};
		const aik_json *tcarr;
		const char *txt;

		for (i = 0; i < 3; i++) {
			const aik_json *rv = aik_json_get(delta, rfields[i]);

			if (rv && aik_json_typeof(rv) == AIK_JSON_STR &&
			    aik_json_strlen(rv) > 0) {
				occ_event ev;

				memset(&ev, 0, sizeof(ev));
				ev.type = OCC_EV_REASONING_DELTA;
				ev.text = aik_json_str(rv);
				emit_ev(cb, ud, &ev);
				break;
			}
		}
		txt = NULL;
		{
			const aik_json *cv = aik_json_get(delta, "content");

			if (cv && aik_json_typeof(cv) == AIK_JSON_STR)
				txt = aik_json_str(cv);
			else {
				const aik_json *rv = aik_json_get(delta, "refusal");

				if (rv && aik_json_typeof(rv) == AIK_JSON_STR)
					txt = aik_json_str(rv);
			}
		}
		if (txt) {
			occ_event ev;

			memset(&ev, 0, sizeof(ev));
			ev.type = OCC_EV_TEXT_DELTA;
			ev.text = txt;
			emit_ev(cb, ud, &ev);
		}
		tcarr = aik_json_get(delta, "tool_calls");
		if (tcarr && aik_json_typeof(tcarr) == AIK_JSON_ARR) {
			size_t n = aik_json_count(tcarr);

			for (i = 0; i < n; i++) {
				const aik_json *tc = aik_json_at(tcarr, i);
				const aik_json *v, *fn;
				const char *id = NULL, *name = NULL, *args = NULL;
				int idx;

				if (!tc || aik_json_typeof(tc) != AIK_JSON_OBJ)
					continue;
				v = aik_json_get(tc, "id");
				if (v && aik_json_typeof(v) == AIK_JSON_STR)
					id = aik_json_str(v);
				fn = aik_json_get(tc, "function");
				if (fn && aik_json_typeof(fn) == AIK_JSON_OBJ) {
					v = aik_json_get(fn, "name");
					if (v && aik_json_typeof(v) == AIK_JSON_STR)
						name = aik_json_str(v);
					v = aik_json_get(fn, "arguments");
					if (v && aik_json_typeof(v) == AIK_JSON_STR)
						args = aik_json_str(v);
				}
				if (st->finish_emitted &&
				    (id || name || (args && *args))) {
					/* :1138-1146 content after finish reason */
					occ_event ev;

					memset(&ev, 0, sizeof(ev));
					ev.type = OCC_EV_ERROR;
					ev.err = "OpenAI Chat received content after the finish reason";
					emit_ev(cb, ud, &ev);
					continue;
				}
				idx = tool_index_for(st, tc, (int)i);
				if (idx < 0)
					continue;
				if (idx >= st->ntools)
					st->ntools = idx + 1;
				st->latest = idx;
				if (id || name) {
					struct oai_tool *t = &st->tools[idx];
					int emit_start = 0;

					if (!t->started)
						emit_start = 1;
					if (id && !t->id[0]) {
						snprintf(t->id, sizeof(t->id),
							 "%s", id);
						emit_start = 1;
					}
					if (name && !t->name[0]) {
						snprintf(t->name, sizeof(t->name),
							 "%s", name);
						emit_start = 1;
					}
					t->started = 1;
					if (emit_start) {
						occ_event ev;

						memset(&ev, 0, sizeof(ev));
						ev.type = OCC_EV_TOOL_START;
						ev.idx = idx;
						ev.id = t->id[0] ? t->id : NULL;
						ev.name = t->name[0] ? t->name : NULL;
						emit_ev(cb, ud, &ev);
					}
				}
				if (args && *args) {
					occ_event ev;

					memset(&ev, 0, sizeof(ev));
					ev.type = OCC_EV_TOOL_ARGS;
					ev.idx = idx;
					ev.args = args;
					emit_ev(cb, ud, &ev);
				}
			}
		}
	}
	if (fr && aik_json_typeof(fr) == AIK_JSON_STR && !st->finish_emitted) {
		const char *raw = aik_json_str(fr);
		int is_error = 0;
		const char *mapped = map_finish(raw, &is_error);
		occ_event ev;

		st->finish_emitted = 1;
		if (is_error) {
			memset(&ev, 0, sizeof(ev));
			ev.type = OCC_EV_ERROR;
			ev.err = "Provider reported an error (finish_reason)";
			emit_ev(cb, ud, &ev);
		}
		memset(&ev, 0, sizeof(ev));
		ev.type = OCC_EV_FINISH;
		ev.finish = mapped;
		emit_ev(cb, ud, &ev);
	}
	aik_json_free(root);
	return 0;
}
