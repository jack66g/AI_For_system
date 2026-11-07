
/* SPDX-License-Identifier: GPL-2.0 */
/* occ_norm.c - occ_event 流累积 → 规范化 JSON（见 occ_norm.h） */
#define _POSIX_C_SOURCE 200809L
#include "occ_norm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "store/store_json.h"

#define NORM_MAX_TOOLS 64
#define NORM_MAX_ERRORS 32

struct nstr {
	char *p;
	size_t len, cap;
};

struct ntool {
	int idx;
	int seen;
	char *id;
	char *name;
	struct nstr args;
};

struct occ_norm {
	struct nstr text;
	struct nstr reasoning;
	struct ntool tools[NORM_MAX_TOOLS];
	int ntools;
	occ_usage usage;
	char finish[32];
	int done;
	char done_src[16];
	char *errors[NORM_MAX_ERRORS];
	int nerr;
};

static int nstr_append(struct nstr *s, const char *t, size_t tl)
{
	size_t nc;

	if (!tl)
		return 0;
	if (s->cap - s->len < tl + 1) {
		nc = s->cap ? s->cap : 64;
		while (nc - s->len < tl + 1)
			nc *= 2;
		s->p = realloc(s->p, nc);
		if (!s->p) {
			s->cap = 0;
			return -1;
		}
		s->cap = nc;
	}
	memcpy(s->p + s->len, t, tl);
	s->len += tl;
	s->p[s->len] = '\0';
	return 0;
}

static struct ntool *tool_slot(occ_norm *n, int idx)
{
	int i;

	for (i = 0; i < n->ntools; i++)
		if (n->tools[i].idx == idx)
			return &n->tools[i];
	if (n->ntools >= NORM_MAX_TOOLS || idx < 0)
		return NULL;
	n->tools[n->ntools].idx = idx;
	n->tools[n->ntools].seen = 0;
	n->tools[n->ntools].id = NULL;
	n->tools[n->ntools].name = NULL;
	memset(&n->tools[n->ntools].args, 0, sizeof(struct nstr));
	return &n->tools[n->ntools++];
}

occ_norm *occ_norm_new(void)
{
	return calloc(1, sizeof(occ_norm));
}

void occ_norm_free(occ_norm *n)
{
	int i;

	if (!n)
		return;
	free(n->text.p);
	free(n->reasoning.p);
	for (i = 0; i < n->ntools; i++) {
		free(n->tools[i].id);
		free(n->tools[i].name);
		free(n->tools[i].args.p);
	}
	for (i = 0; i < n->nerr; i++)
		free(n->errors[i]);
	free(n);
}

static void set_dup(char **dst, const char *src)
{
	if (!src)
		return;
	free(*dst);
	*dst = strdup(src);
}

void occ_norm_event(const occ_event *ev, void *ud)
{
	occ_norm *n = ud;

	switch (ev->type) {
	case OCC_EV_TEXT_DELTA:
		if (ev->text)
			nstr_append(&n->text, ev->text, strlen(ev->text));
		break;
	case OCC_EV_REASONING_DELTA:
		if (ev->text)
			nstr_append(&n->reasoning, ev->text, strlen(ev->text));
		break;
	case OCC_EV_TOOL_START: {
		struct ntool *t = tool_slot(n, ev->idx);

		if (!t)
			break;
		t->seen = 1;
		set_dup(&t->id, ev->id);
		set_dup(&t->name, ev->name);
		break;
	}
	case OCC_EV_TOOL_ARGS: {
		struct ntool *t = tool_slot(n, ev->idx);

		if (t && ev->args)
			nstr_append(&t->args, ev->args, strlen(ev->args));
		break;
	}
	case OCC_EV_USAGE:
		n->usage = ev->usage;
		break;
	case OCC_EV_FINISH:
		if (ev->finish)
			snprintf(n->finish, sizeof(n->finish), "%s", ev->finish);
		break;
	case OCC_EV_ERROR:
		if (n->nerr < NORM_MAX_ERRORS && ev->err)
			n->errors[n->nerr++] = strdup(ev->err);
		break;
	case OCC_EV_DONE:
		n->done = 1;
		if (ev->finish)
			snprintf(n->done_src, sizeof(n->done_src), "%s", ev->finish);
		break;
	case OCC_EV_RESET:
		/* b2 传输层重试的「上一尝试作废」通告：归一化面无此概念
		 * （ssereplay 只喂 SSE 字节、不经 llm_call，永不产生） */
		break;
	}
}

int occ_norm_error_count(const occ_norm *n)
{
	return n ? n->nerr : 0;
}

char *occ_norm_dump(const occ_norm *n, size_t *outlen)
{
	aik_json *o, *tcs, *u, *errs;
	char *out = NULL;
	size_t dummy;
	int i;

	if (!outlen)
		outlen = &dummy;	/* aik_json_dump 要求非 NULL */
	o = aik_json_new_obj();
	if (!o)
		return NULL;
	aik_json_obj_put(o, "text", aik_json_new_str(n->text.p ? n->text.p : ""));
	aik_json_obj_put(o, "reasoning", aik_json_new_str(n->reasoning.p ? n->reasoning.p : ""));
	tcs = aik_json_new_arr();
	for (i = 0; i < n->ntools; i++) {
		aik_json *t = aik_json_new_obj();

		if (!t)
			continue;
		aik_json_obj_put(t, "idx", aik_json_new_int(n->tools[i].idx));
		aik_json_obj_put(t, "id", aik_json_new_str(n->tools[i].id ? n->tools[i].id : ""));
		aik_json_obj_put(t, "name", aik_json_new_str(n->tools[i].name ? n->tools[i].name : ""));
		aik_json_obj_put(t, "arguments",
			aik_json_new_str(n->tools[i].args.p ? n->tools[i].args.p : ""));
		aik_json_arr_push(tcs, t);
	}
	aik_json_obj_put(o, "tool_calls", tcs);
	u = aik_json_new_obj();
	aik_json_obj_put(u, "present", aik_json_new_int(n->usage.present));
	aik_json_obj_put(u, "input", aik_json_new_int(n->usage.input));
	aik_json_obj_put(u, "output", aik_json_new_int(n->usage.output));
	aik_json_obj_put(u, "cache_read", aik_json_new_int(n->usage.cache_read));
	aik_json_obj_put(u, "cache_write", aik_json_new_int(n->usage.cache_write));
	aik_json_obj_put(o, "usage", u);
	aik_json_obj_put(o, "finish", aik_json_new_str(n->finish));
	aik_json_obj_put(o, "done", aik_json_new_int(n->done));
	aik_json_obj_put(o, "done_src", aik_json_new_str(n->done_src));
	errs = aik_json_new_arr();
	for (i = 0; i < n->nerr; i++)
		aik_json_arr_push(errs, aik_json_new_str(n->errors[i]));
	aik_json_obj_put(o, "errors", errs);
	if (aik_json_dump(o, &out, outlen))
		out = NULL;
	aik_json_free(o);
	return out;
}
