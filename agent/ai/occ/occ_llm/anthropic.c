/* SPDX-License-Identifier: GPL-2.0 */
/*
 * anthropic.c - Anthropic Messages 协议（messages + {name,input_schema}）T9a1
 *
 * 请求构造对齐 opencode packages/ai/src/protocols/anthropic-messages.ts：
 *   - 体序 :1108-1129 model, system[], messages, tools, tool_choice,
 *     stream:true, max_tokens, temperature, ...
 *   - B1：parallel_tool_calls 为 OpenAI 面字段，anthropic 面显式不
 *     支持——Anthropic Messages API 无该键（工具并行=缺省行为；禁并
 *     行是 tool_choice.disable_parallel_tool_use 的反方向能力，不在
 *     occ 请求面）。req->parallel_tool_calls=1 时本构造器也绝不发该
 *     键（test_anthropic_build B1 用例钉死）。
 *   - tools 无则整体省略（:1083）；DEFAULT_MAX_TOKENS=32000（:40,:1101）
 *   - system 顶层 text 块数组（:1091-1097）
 *   - 工具定义 {name, description?, input_schema}（:271,:561-566）
 *   - assistant tool_use 块 {type,id,name,input}，id 清洗
 *     [^a-zA-Z0-9_-]→"_"（:592-596）
 *   - tool_result 块 {type,tool_use_id,content:<string>}；连续 tool 消息
 *     并入同一 user 轮（:1017-1032）
 *   - user/assistant 空白文本 part 跳过（:930-932,:975-977）
 *
 * SSE 事件解析对齐同文件（step :1560-1616）：
 *   - message_start.usage（input 侧）+ message_delta.usage（output 侧）
 *     字段级右偏合并，inclusive input = 非缓存+读缓存+写缓存
 *     （mergeUsage :1189-1200 / mapUsage :1150-1178）
 *   - content_block_start(tool_use) → id/name；content_block_delta：
 *     text_delta/thinking_delta/input_json_delta（:1263-1290 区域）
 *   - message_delta.stop_reason 映射（:1141-1147）；message_stop → 终结
 *   - ping 忽略；error → 错误（onError :1526）
 */
#include "occ_llm.h"
#include "occ_proto.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "store/store_json.h"

#define ANT_DEFAULT_MAX_TOKENS 32000
#define ANT_ID_BUF 160

/* ================= 请求构造 ================= */

static aik_json *parse_json_text(const char *text)
{
	char err[96];

	if (!text || !*text)
		return aik_json_new_obj();
	return aik_json_parse(text, strlen(text), err, sizeof(err));
}

static void scrub_id(char *dst, size_t dstlen, const char *id)
{
	size_t i, j = 0;

	if (!id)
		id = "";
	for (i = 0; id[i] && j + 1 < dstlen; i++) {
		char c = id[i];
		int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			 (c >= '0' && c <= '9') || c == '_' || c == '-';

		dst[j++] = ok ? c : '_';
	}
	dst[j] = '\0';
}

static int text_is_blank(const char *s)
{
	size_t i;

	if (!s)
		return 1;
	for (i = 0; s[i]; i++)
		if (!isspace((unsigned char)s[i]))
			return 0;
	return 1;
}

static aik_json *build_blocks_user(const occ_msg *m)
{
	aik_json *arr = aik_json_new_arr();
	aik_json *b;

	if (!arr)
		return NULL;
	if (!text_is_blank(m->text)) {
		b = aik_json_new_obj();
		if (!b)
			goto fail;
		if (aik_json_obj_put(b, "type", aik_json_new_str("text")) ||
		    aik_json_obj_put(b, "text", aik_json_new_str(m->text)) ||
		    aik_json_arr_push(arr, b)) {
			aik_json_free(b);
			goto fail;
		}
	}
	return arr;
fail:
	aik_json_free(arr);
	return NULL;
}

static aik_json *build_blocks_assistant(const occ_msg *m)
{
	aik_json *arr = aik_json_new_arr();
	size_t i;

	if (!arr)
		return NULL;
	if (!text_is_blank(m->text)) {
		aik_json *b = aik_json_new_obj();

		if (!b)
			goto fail;
		if (aik_json_obj_put(b, "type", aik_json_new_str("text")) ||
		    aik_json_obj_put(b, "text", aik_json_new_str(m->text)) ||
		    aik_json_arr_push(arr, b)) {
			aik_json_free(b);
			goto fail;
		}
	}
	for (i = 0; i < m->ncalls; i++) {
		aik_json *b = aik_json_new_obj();
		aik_json *input;
		char id[ANT_ID_BUF];

		if (!b)
			goto fail;
		input = parse_json_text(m->calls[i].arguments);
		if (!input) {
			aik_json_free(b);
			goto fail;
		}
		scrub_id(id, sizeof(id), m->calls[i].id);
		if (aik_json_obj_put(b, "type", aik_json_new_str("tool_use")) ||
		    aik_json_obj_put(b, "id", aik_json_new_str(id)) ||
		    aik_json_obj_put(b, "name", aik_json_new_str(m->calls[i].name)) ||
		    aik_json_obj_put(b, "input", input)) {
			aik_json_free(input);
			aik_json_free(b);
			goto fail;
		}
		if (aik_json_arr_push(arr, b)) {
			aik_json_free(b);
			goto fail;
		}
	}
	return arr;
fail:
	aik_json_free(arr);
	return NULL;
}

static aik_json *build_block_tool_result(const occ_msg *m)
{
	aik_json *b = aik_json_new_obj();
	char id[ANT_ID_BUF];

	if (!b)
		return NULL;
	scrub_id(id, sizeof(id), m->tool_call_id);
	if (aik_json_obj_put(b, "type", aik_json_new_str("tool_result")) ||
	    aik_json_obj_put(b, "tool_use_id", aik_json_new_str(id)) ||
	    aik_json_obj_put(b, "content",
			aik_json_new_str(m->text ? m->text : ""))) {
		aik_json_free(b);
		return NULL;
	}
	return b;
}

char *occ_build_request_anthropic(const occ_llm_req *req, size_t *outlen)
{
	aik_json *body = NULL, *msgs = NULL;
	char *out = NULL;
	size_t dummy;
	size_t i;

	if (!outlen)
		outlen = &dummy;	/* aik_json_dump 要求非 NULL */
	body = aik_json_new_obj();
	msgs = aik_json_new_arr();
	if (!body || !msgs)
		goto out;
	if (aik_json_obj_put(body, "model", aik_json_new_str(req->model)))
		goto out;
	if (req->system && *req->system) {
		aik_json *sysa = aik_json_new_arr();
		aik_json *b = aik_json_new_obj();

		if (!sysa || !b) {
			aik_json_free(sysa);
			aik_json_free(b);
			goto out;
		}
		if (aik_json_obj_put(b, "type", aik_json_new_str("text")) ||
		    aik_json_obj_put(b, "text", aik_json_new_str(req->system)) ||
		    aik_json_arr_push(sysa, b)) {
			aik_json_free(b);
			aik_json_free(sysa);
			goto out;
		}
		if (aik_json_obj_put(body, "system", sysa)) {
			aik_json_free(sysa);
			goto out;
		}
	}
	for (i = 0; i < req->nmsgs; i++) {
		const occ_msg *m = &req->msgs[i];

		if (m->role == OCC_ROLE_USER) {
			aik_json *blocks = build_blocks_user(m);
			aik_json *o;

			if (!blocks)
				goto out;
			if (aik_json_count(blocks) == 0) {	/* 全空白→丢消息 */
				aik_json_free(blocks);
				continue;
			}
			o = aik_json_new_obj();
			if (!o || aik_json_obj_put(o, "role",
					aik_json_new_str("user")) ||
			    aik_json_obj_put(o, "content", blocks)) {
				aik_json_free(blocks);
				aik_json_free(o);
				goto out;
			}
			if (aik_json_arr_push(msgs, o)) {
				aik_json_free(o);
				goto out;
			}
		} else if (m->role == OCC_ROLE_ASSISTANT) {
			aik_json *blocks = build_blocks_assistant(m);
			aik_json *o;

			if (!blocks)
				goto out;
			if (aik_json_count(blocks) == 0) {
				aik_json_free(blocks);
				continue;
			}
			o = aik_json_new_obj();
			if (!o || aik_json_obj_put(o, "role",
					aik_json_new_str("assistant")) ||
			    aik_json_obj_put(o, "content", blocks)) {
				aik_json_free(blocks);
				aik_json_free(o);
				goto out;
			}
			if (aik_json_arr_push(msgs, o)) {
				aik_json_free(o);
				goto out;
			}
		} else {			/* tool → user 轮 tool_result 块 */
			aik_json *b = build_block_tool_result(m);

			if (!b)
				goto out;
			/* :1029-1032 连续 tool 并入同一 user 轮 */
			if (aik_json_count(msgs) > 0) {
				/* DOM 追加需去 const（store API 读侧返回 const，
				 * 构造期追加是唯一写用例） */
				aik_json *prev = (aik_json *)aik_json_at(msgs,
					aik_json_count(msgs) - 1);
				const aik_json *pr = aik_json_get(prev, "role");
				const aik_json *pc = aik_json_get(prev, "content");
				int all_tr = 1;
				size_t k;

				if (pr && aik_json_typeof(pr) == AIK_JSON_STR &&
				    !strcmp(aik_json_str(pr), "user") &&
				    pc && aik_json_typeof(pc) == AIK_JSON_ARR) {
					for (k = 0; k < aik_json_count(pc); k++) {
						const aik_json *blk = aik_json_at(pc, k);
						const aik_json *bt = aik_json_get(blk, "type");

						if (!bt || aik_json_typeof(bt) != AIK_JSON_STR ||
						    strcmp(aik_json_str(bt), "tool_result"))
							all_tr = 0;
					}
					if (all_tr) {
						if (aik_json_arr_push((aik_json *)pc, b)) {
							aik_json_free(b);
							goto out;
						}
						continue;
					}
				}
			}
			{
				aik_json *blocks = aik_json_new_arr();
				aik_json *o;

				if (!blocks) {
					aik_json_free(b);
					goto out;
				}
				if (aik_json_arr_push(blocks, b)) {
					aik_json_free(b);
					aik_json_free(blocks);
					goto out;
				}
				o = aik_json_new_obj();
				if (!o || aik_json_obj_put(o, "role",
						aik_json_new_str("user")) ||
				    aik_json_obj_put(o, "content", blocks)) {
					aik_json_free(blocks);
					aik_json_free(o);
					goto out;
				}
				if (aik_json_arr_push(msgs, o)) {
					aik_json_free(o);
					goto out;
				}
			}
		}
	}
	if (aik_json_obj_put(body, "messages", msgs)) {
		msgs = NULL;
		goto out;
	}
	msgs = NULL;
	if (req->ntools > 0) {
		aik_json *tools = aik_json_new_arr();

		if (!tools)
			goto out;
		for (i = 0; i < req->ntools; i++) {
			aik_json *t = aik_json_new_obj();
			aik_json *schema;

			if (!t)
				goto out;
			schema = parse_json_text(req->tools[i].parameters);
			if (!schema) {
				aik_json_free(t);
				goto out;
			}
			if (aik_json_obj_put(t, "name",
					aik_json_new_str(req->tools[i].name)))
				goto out;
			if (req->tools[i].description && *req->tools[i].description &&
			    aik_json_obj_put(t, "description",
					aik_json_new_str(req->tools[i].description)))
				goto out;
			if (aik_json_obj_put(t, "input_schema", schema)) {
				aik_json_free(schema);
				goto out;
			}
			if (aik_json_arr_push(tools, t)) {
				aik_json_free(t);
				goto out;
			}
		}
		if (aik_json_obj_put(body, "tools", tools)) {
			aik_json_free(tools);
			goto out;
		}
	}
	if (aik_json_obj_put(body, "stream", aik_json_new_bool(1)))
		goto out;
	if (aik_json_obj_put(body, "max_tokens", aik_json_new_int(
			req->gen.has_max_tokens ? req->gen.max_tokens :
						 ANT_DEFAULT_MAX_TOKENS)))
		goto out;
	if (req->gen.has_temperature &&
	    aik_json_obj_put(body, "temperature",
			aik_json_new_num(req->gen.temperature)))
		goto out;
	if (aik_json_dump(body, &out, outlen))
		out = NULL;
out:
	aik_json_free(body);
	aik_json_free(msgs);
	return out;
}

/* ================= 流事件解析 ================= */

#define ANT_MAX_IDX 64

struct ant_state {
	struct {
		char id[ANT_ID_BUF];
		char name[ANT_ID_BUF];
	} tools[ANT_MAX_IDX];
	/* usage 字段级合并（mergeUsage :1189-1200 右偏） */
	long long u_nc, u_cread, u_cwrite, u_out;
	int u_has;
};

void *occ_anthropic_state_new(void)
{
	return calloc(1, sizeof(struct ant_state));
}

void occ_anthropic_state_free(void *st)
{
	free(st);
}

static void ant_map_usage(struct ant_state *st, const aik_json *u,
			  occ_event_cb cb, void *ud)
{
	occ_event ev;
	const aik_json *v;

	if (!u || aik_json_typeof(u) != AIK_JSON_OBJ)
		return;
	v = aik_json_get(u, "input_tokens");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		st->u_nc = aik_json_int(v);
	v = aik_json_get(u, "cache_read_input_tokens");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		st->u_cread = aik_json_int(v);
	v = aik_json_get(u, "cache_creation_input_tokens");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		st->u_cwrite = aik_json_int(v);
	v = aik_json_get(u, "output_tokens");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		st->u_out = aik_json_int(v);
	st->u_has = 1;

	memset(&ev, 0, sizeof(ev));
	ev.type = OCC_EV_USAGE;
	/* inclusive input = 非缓存 + 读缓存 + 写缓存（:1165-1168） */
	ev.usage.input = st->u_nc + st->u_cread + st->u_cwrite;
	ev.usage.output = st->u_out;
	ev.usage.cache_read = st->u_cread;
	ev.usage.cache_write = st->u_cwrite;
	ev.usage.present = 1;
	cb(&ev, ud);
}

static const char *ant_map_finish(const char *raw)
{
	if (!raw)
		return "unknown";
	if (!strcmp(raw, "end_turn") || !strcmp(raw, "stop_sequence") ||
	    !strcmp(raw, "pause_turn"))
		return "stop";
	if (!strcmp(raw, "max_tokens") || !strcmp(raw, "model_context_window_exceeded"))
		return "length";
	if (!strcmp(raw, "tool_use"))
		return "tool-calls";
	if (!strcmp(raw, "refusal"))
		return "content-filter";
	return "unknown";
}

int occ_anthropic_event(void *state, const char *json, size_t len,
			occ_event_cb cb, void *ud)
{
	struct ant_state *st = state;
	char err[96];
	aik_json *root;
	const aik_json *t;
	const char *type;

	root = aik_json_parse(json, len, err, sizeof(err));
	if (!root)
		return 0;
	t = aik_json_get(root, "type");
	type = (t && aik_json_typeof(t) == AIK_JSON_STR) ? aik_json_str(t) : NULL;
	if (!type) {
		occ_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.type = OCC_EV_ERROR;
		ev.err = "anthropic event missing type";
		cb(&ev, ud);
		aik_json_free(root);
		return 0;
	}
	if (!strcmp(type, "message_start")) {
		const aik_json *m = aik_json_get(root, "message");

		if (m)
			ant_map_usage(st, aik_json_get(m, "usage"), cb, ud);
	} else if (!strcmp(type, "content_block_start")) {
		const aik_json *vi = aik_json_get(root, "index");
		const aik_json *cb_ = aik_json_get(root, "content_block");
		const aik_json *bt;
		const char *btype;
		int idx;

		if (!vi || aik_json_typeof(vi) != AIK_JSON_INT ||
		    !cb_ || aik_json_typeof(cb_) != AIK_JSON_OBJ)
			goto out;
		idx = (int)aik_json_int(vi);
		if (idx < 0 || idx >= ANT_MAX_IDX)
			goto out;
		bt = aik_json_get(cb_, "type");
		btype = (bt && aik_json_typeof(bt) == AIK_JSON_STR) ?
			aik_json_str(bt) : "";
		if (!strcmp(btype, "tool_use") || !strcmp(btype, "server_tool_use")) {
			const aik_json *v;
			const char *id = NULL, *name = NULL;
			occ_event ev;

			v = aik_json_get(cb_, "id");
			if (v && aik_json_typeof(v) == AIK_JSON_STR)
				id = aik_json_str(v);
			v = aik_json_get(cb_, "name");
			if (v && aik_json_typeof(v) == AIK_JSON_STR)
				name = aik_json_str(v);
			if (id)
				snprintf(st->tools[idx].id, ANT_ID_BUF, "%s", id);
			if (name)
				snprintf(st->tools[idx].name, ANT_ID_BUF, "%s", name);
			memset(&ev, 0, sizeof(ev));
			ev.type = OCC_EV_TOOL_START;
			ev.idx = idx;
			ev.id = st->tools[idx].id[0] ? st->tools[idx].id : NULL;
			ev.name = st->tools[idx].name[0] ? st->tools[idx].name : NULL;
			cb(&ev, ud);
		}
		/* text/thinking 等块起始：增量随后经 delta 到达 */
	} else if (!strcmp(type, "content_block_delta")) {
		const aik_json *vi = aik_json_get(root, "index");
		const aik_json *d = aik_json_get(root, "delta");
		const aik_json *dt;
		const char *dtype;
		int idx;

		if (!vi || aik_json_typeof(vi) != AIK_JSON_INT ||
		    !d || aik_json_typeof(d) != AIK_JSON_OBJ)
			goto out;
		idx = (int)aik_json_int(vi);
		if (idx < 0 || idx >= ANT_MAX_IDX)
			goto out;
		dt = aik_json_get(d, "type");
		dtype = (dt && aik_json_typeof(dt) == AIK_JSON_STR) ?
			aik_json_str(dt) : "";
		if (!strcmp(dtype, "text_delta")) {
			const aik_json *v = aik_json_get(d, "text");
			occ_event ev;

			if (v && aik_json_typeof(v) == AIK_JSON_STR) {
				memset(&ev, 0, sizeof(ev));
				ev.type = OCC_EV_TEXT_DELTA;
				ev.text = aik_json_str(v);
				cb(&ev, ud);
			}
		} else if (!strcmp(dtype, "thinking_delta")) {
			const aik_json *v = aik_json_get(d, "thinking");
			occ_event ev;

			if (v && aik_json_typeof(v) == AIK_JSON_STR) {
				memset(&ev, 0, sizeof(ev));
				ev.type = OCC_EV_REASONING_DELTA;
				ev.text = aik_json_str(v);
				cb(&ev, ud);
			}
		} else if (!strcmp(dtype, "input_json_delta")) {
			const aik_json *v = aik_json_get(d, "partial_json");
			occ_event ev;

			if (v && aik_json_typeof(v) == AIK_JSON_STR) {
				memset(&ev, 0, sizeof(ev));
				ev.type = OCC_EV_TOOL_ARGS;
				ev.idx = idx;
				ev.args = aik_json_str(v);
				cb(&ev, ud);
			}
		}
		/* signature_delta 等：忽略 */
	} else if (!strcmp(type, "message_delta")) {
		const aik_json *d = aik_json_get(root, "delta");
		const aik_json *v;

		ant_map_usage(st, aik_json_get(root, "usage"), cb, ud);
		if (d && aik_json_typeof(d) == AIK_JSON_OBJ) {
			v = aik_json_get(d, "stop_reason");
			if (v && aik_json_typeof(v) == AIK_JSON_STR) {
				occ_event ev;

				memset(&ev, 0, sizeof(ev));
				ev.type = OCC_EV_FINISH;
				ev.finish = ant_map_finish(aik_json_str(v));
				cb(&ev, ud);
			}
		}
	} else if (!strcmp(type, "message_stop")) {
		occ_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.type = OCC_EV_DONE;
		ev.finish = "message_stop";
		cb(&ev, ud);
		aik_json_free(root);
		return 1;			/* 流终结 */
	} else if (!strcmp(type, "error")) {
		const aik_json *e = aik_json_get(root, "error");
		const aik_json *m = e ? aik_json_get(e, "message") : NULL;
		occ_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.type = OCC_EV_ERROR;
		ev.err = (m && aik_json_typeof(m) == AIK_JSON_STR) ?
			aik_json_str(m) : "anthropic error event";
		cb(&ev, ud);
	}
	/* ping / content_block_stop / 未知：忽略 */
out:
	aik_json_free(root);
	return 0;
}
