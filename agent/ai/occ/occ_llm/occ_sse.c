/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_sse.c - SSE framing 层 + 协议分派（T9a1）
 *
 * 对齐 opencode packages/ai/src/route/framing.ts:38-83（sseFraming/sseWithDone）：
 *   - 空事件丢弃（data.length>0 才交付）
 *   - `data: null` 空刷丢弃（代理在事件间/[DONE] 后发的裸 null）
 *   - `data: : keepalive` 丢弃（Vertex 风格 keepalive）
 *   - 注释行（`:` 开头）忽略；event:/id:/retry: 行忽略（类型在 data JSON 内）
 *   - [DONE]：openai 保留为流终结哨兵（sseWithDone，openai-chat.ts:1392）；
 *     anthropic 默认丢弃（sse 语义）
 *   - 多行 data 以 "\n" 拼接（SSE 规范）
 *   - data 块 JSON 解析失败 → ERROR 且流中止（opencode jsonEvent→AIError 语义）
 *
 * 有意差异（记录在案）：EOF 时未终结的 data 块，opencode 静默丢弃；
 * occ 报 OCC_EV_ERROR（durable agent 需要知道流被截断——usage/工具参数
 * 可能丢失，静默丢弃会污染账本）。
 */
#include "occ_llm.h"
#include "occ_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "store/store_json.h"

struct occ_sse {
	occ_protocol proto;
	occ_event_cb cb;
	void *ud;

	/* 事件载荷累积（data 行以 '\n' 拼接） */
	char *ev;
	size_t ev_len, ev_cap;
	int ndata;			/* 已累积 data 行数 */
	int have_event;

	/* 当前行累积（跨 feed 边界安全） */
	char *line;
	size_t line_len, line_cap;

	/* 协议状态机 */
	void *pstate;
	int (*parse)(void *, const char *, size_t, occ_event_cb, void *);
	void (*free_state)(void *);

	int done_emitted;		/* DONE 已发（哨兵/解析器终结） */
	int fatal;			/* 坏块：后续事件不再交付 */
	int errors;
	int finished;

	char errbuf[256];		/* ERROR 事件文本（cb 存活期内有效） */
};

static int buf_reserve(char **buf, size_t *cap, size_t need)
{
	size_t nc;

	if (*cap >= need)
		return 0;
	nc = *cap ? *cap : 128;
	while (nc < need)
		nc *= 2;
	*buf = realloc(*buf, nc);
	if (!*buf) {
		*cap = 0;
		return -1;
	}
	*cap = nc;
	return 0;
}

static void emit(occ_sse *s, occ_event *ev)
{
	s->cb(ev, s->ud);
}

static void emit_error(occ_sse *s, const char *msg)
{
	occ_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = OCC_EV_ERROR;
	ev.err = msg;
	s->errors++;
	emit(s, &ev);
}

static void emit_done(occ_sse *s, const char *src)
{
	occ_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = OCC_EV_DONE;
	/* 约定：DONE 事件的 finish 字段承载 done_src（sentinel/message_stop/eof） */
	ev.finish = src;
	s->done_emitted = 1;
	emit(s, &ev);
}

/* 交付一个完整 data 事件（framing.ts sseFraming 语义） */
static void dispatch_event(occ_sse *s)
{
	const char *p = s->ev;
	size_t plen = s->ev_len;
	char err[96];
	aik_json *root;
	int r;

	s->have_event = 0;
	s->ndata = 0;
	s->ev_len = 0;
	if (plen == 0)
		return;			/* 空事件丢弃 */
	if (plen == 4 && memcmp(p, "null", 4) == 0)
		return;			/* data: null 空刷 */
	if (plen == 11 && memcmp(p, ": keepalive", 11) == 0)
		return;			/* data: : keepalive（Vertex 风格） */
	if (plen == 6 && memcmp(p, "[DONE]", 6) == 0) {
		if (s->proto != OCC_PROTO_OPENAI_COMPAT)
			return;		/* anthropic：默认丢弃 [DONE] */
		if (s->done_emitted || s->fatal) {
			emit_error(s, "duplicate [DONE] after stream end");
			return;
		}
		emit_done(s, "sentinel");
		return;
	}
	if (s->fatal) {
		emit_error(s, "data after fatal bad block");
		return;
	}
	if (s->done_emitted) {
		emit_error(s, "data after stream end");
		return;
	}
	root = aik_json_parse(p, plen, err, sizeof(err));
	if (!root) {
		snprintf(s->errbuf, sizeof(s->errbuf),
			 "bad json block: %s", err);
		emit_error(s, s->errbuf);
		s->fatal = 1;
		return;
	}
	r = s->parse(s->pstate, p, plen, s->cb, s->ud);
	aik_json_free(root);
	if (r)
		s->done_emitted = 1;
}

static void process_line(occ_sse *s, const char *line, size_t len)
{
	const char *colon;
	const char *val;
	size_t vlen;

	/* 去行尾单个 '\r'（SSE 规范 CRLF） */
	if (len > 0 && line[len - 1] == '\r')
		len--;
	if (len == 0) {			/* 空行 = 事件边界 */
		if (s->have_event)
			dispatch_event(s);
		else
			s->ndata = 0;
		return;
	}
	if (line[0] == ':')
		return;			/* 注释行（含 keepalive） */
	colon = memchr(line, ':', len);
	if (!colon) {
		/* 无冒号行 = 空值字段（如裸 "data"），按 data 空值处理 */
		if (len == 4 && memcmp(line, "data", 4) == 0) {
			s->have_event = 1; /* 空值 data 行计入事件（空串） */
			s->ndata++;
		}
		return;
	}
	if ((size_t)(colon - line) == 4 && memcmp(line, "data", 4) == 0) {
		val = colon + 1;
		vlen = len - 5;
		if (vlen > 0 && val[0] == ' ') {	/* 去一个前导空格 */
			val++;
			vlen--;
		}
		if (s->ndata > 0) {		/* 多行 data 以 '\n' 拼接 */
			if (buf_reserve(&s->ev, &s->ev_cap, s->ev_len + 1 + vlen + 1))
				return;
			s->ev[s->ev_len++] = '\n';
		} else {
			if (buf_reserve(&s->ev, &s->ev_cap, vlen + 1))
				return;
		}
		memcpy(s->ev + s->ev_len, val, vlen);
		s->ev_len += vlen;
		s->ev[s->ev_len] = '\0';
		s->have_event = 1;
		s->ndata++;
	}
	/* event:/id:/retry:/未知字段：忽略 */
}

occ_sse *occ_sse_new(occ_protocol proto, occ_event_cb cb, void *ud)
{
	occ_sse *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	s->proto = proto;
	s->cb = cb;
	s->ud = ud;
	if (proto == OCC_PROTO_OPENAI_COMPAT) {
		s->pstate = occ_openai_state_new();
		s->parse = occ_openai_event;
		s->free_state = occ_openai_state_free;
	} else {
		s->pstate = occ_anthropic_state_new();
		s->parse = occ_anthropic_event;
		s->free_state = occ_anthropic_state_free;
	}
	if (!s->pstate) {
		free(s);
		return NULL;
	}
	return s;
}

void occ_sse_free(occ_sse *s)
{
	if (!s)
		return;
	s->free_state(s->pstate);
	free(s->ev);
	free(s->line);
	free(s);
}

void occ_sse_feed(occ_sse *s, const char *data, size_t len)
{
	size_t i;

	if (!s || s->finished)
		return;
	for (i = 0; i < len; i++) {
		if (data[i] == '\n') {
			process_line(s, s->line, s->line_len);
			s->line_len = 0;
			continue;
		}
		if (buf_reserve(&s->line, &s->line_cap, s->line_len + 1))
			return;
		s->line[s->line_len++] = data[i];
	}
}

void occ_sse_finish(occ_sse *s)
{
	if (!s || s->finished)
		return;
	s->finished = 1;
	if (s->line_len > 0) {			/* EOF 前无换行的最后一行 */
		process_line(s, s->line, s->line_len);
		s->line_len = 0;
	}
	if (s->have_event && s->ev_len > 0) {
		/* 有意差异：opencode 静默丢弃未终结块；occ 报截断 */
		emit_error(s, "truncated final SSE block (unterminated event)");
		s->have_event = 0;
		s->ev_len = 0;
		s->ndata = 0;
	}
	if (!s->done_emitted && !s->fatal)
		emit_done(s, "eof");
}

int occ_sse_error_count(const occ_sse *s)
{
	return s ? s->errors : 0;
}
