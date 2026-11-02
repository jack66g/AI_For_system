// SPDX-License-Identifier: GPL-2.0
/*
 * acstate.c - 会话状态 / 快照 / 事件流水的线程安全存储
 *
 * 逐语义对齐 ref-autocondense/state.py（详见 acstate.h）。
 * 时间全部走 acconfig.h 注入时钟；JSON DOM 走 store/store_json。
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acstate.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define AC_SNAPSHOTS_DIR "snapshots"
#define AC_SESSIONS_STATE_FILE "sessions-state.json"
#define AC_EVENTS_FILE "sessions.jsonl"
#define AC_INDEX_FILE "index.json"
#define AC_DELTA_STATE_FILE "delta-state.json"

/* ================================================================== */
/* SHA-1（project_hash 用；无外部依赖）                                */
/* ================================================================== */

struct sha1_ctx {
	uint32_t h[5];
	uint64_t total;
	unsigned char buf[64];
	size_t fill;
};

static uint32_t rol32(uint32_t v, int s)
{
	return (v << s) | (v >> (32 - s));
}

static void sha1_init(struct sha1_ctx *c)
{
	c->h[0] = 0x67452301u;
	c->h[1] = 0xEFCDAB89u;
	c->h[2] = 0x98BADCFEu;
	c->h[3] = 0x10325476u;
	c->h[4] = 0xC3D2E1F0u;
	c->total = 0;
	c->fill = 0;
}

static void sha1_block(struct sha1_ctx *c, const unsigned char *p)
{
	uint32_t w[80];

	for (int i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
	for (int i = 16; i < 80; i++)
		w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	uint32_t a = c->h[0], b = c->h[1], d = c->h[3], e = c->h[4];
	uint32_t cc = c->h[2];

	for (int i = 0; i < 80; i++) {
		uint32_t f, k;

		if (i < 20) {
			f = (b & cc) | ((~b) & d);
			k = 0x5A827999u;
		} else if (i < 40) {
			f = b ^ cc ^ d;
			k = 0x6ED9EBA1u;
		} else if (i < 60) {
			f = (b & cc) | (b & d) | (cc & d);
			k = 0x8F1BBCDCu;
		} else {
			f = b ^ cc ^ d;
			k = 0xCA62C1D6u;
		}
		uint32_t t = rol32(a, 5) + f + e + k + w[i];

		e = d;
		d = cc;
		cc = rol32(b, 30);
		b = a;
		a = t;
	}
	c->h[0] += a;
	c->h[1] += b;
	c->h[2] += cc;
	c->h[3] += d;
	c->h[4] += e;
}

static void sha1_update(struct sha1_ctx *c, const void *data, size_t len)
{
	const unsigned char *p = data;

	c->total += len;
	while (len > 0) {
		size_t take = 64 - c->fill;

		if (take > len)
			take = len;
		memcpy(c->buf + c->fill, p, take);
		c->fill += take;
		p += take;
		len -= take;
		if (c->fill == 64) {
			sha1_block(c, c->buf);
			c->fill = 0;
		}
	}
}

static void sha1_final(struct sha1_ctx *c, unsigned char out[20])
{
	uint64_t bits = c->total * 8;
	unsigned char pad = 0x80;

	sha1_update(c, &pad, 1);
	unsigned char zero = 0;

	while (c->fill != 56)
		sha1_update(c, &zero, 1);
	unsigned char lenb[8];

	for (int i = 0; i < 8; i++)
		lenb[i] = (unsigned char)(bits >> (56 - i * 8));
	sha1_update(c, lenb, 8);
	for (int i = 0; i < 5; i++) {
		out[i * 4] = (unsigned char)(c->h[i] >> 24);
		out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
		out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
		out[i * 4 + 3] = (unsigned char)c->h[i];
	}
}

/* ================================================================== */
/* 路径工具                                                            */
/* ================================================================== */

static char *xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = malloc(n);

	if (p)
		memcpy(p, s, n);
	return p;
}

static char *path_join(const char *a, const char *b)
{
	if (!a || !*a)
		return xstrdup(b);
	if (!b || !*b)
		return xstrdup(a);
	size_t n = strlen(a) + 1 + strlen(b) + 1;
	char *out = malloc(n);

	if (out)
		snprintf(out, n, "%s/%s", a, b);
	return out;
}

/* 绝对化 + 词法规范化（Python Path.resolve() 在无符号链接分量时等价；
 * T5-DESIGN §1 口径：normpath(normcase(abs))，Linux 无大小写折叠）*/
static int path_resolve_norm(const char *in, char *out, size_t cap)
{
	char raw[4096];

	if (!in || !*in) {
		if (!getcwd(raw, sizeof(raw)))
			return -1;
	} else if (in[0] == '/') {
		if (strlen(in) >= sizeof(raw))
			return -1;
		strcpy(raw, in);
	} else {
		char cwd[4096];

		if (!getcwd(cwd, sizeof(cwd)))
			return -1;
		if (snprintf(raw, sizeof(raw), "%s/%s", cwd, in) >= (int)sizeof(raw))
			return -1;
	}

	/* 分段偏移栈（不改动 raw）*/
	size_t coff[512], clen[512];
	size_t ncomp = 0;
	const char *p = raw;

	while (*p) {
		while (*p == '/')
			p++;
		if (!*p)
			break;
		const char *start = p;

		while (*p && *p != '/')
			p++;
		size_t len = (size_t)(p - start);

		if (len == 1 && start[0] == '.')
			continue;
		if (len == 2 && start[0] == '.' && start[1] == '.') {
			if (ncomp > 0)
				ncomp--;
			continue;
		}
		if (ncomp >= sizeof(coff) / sizeof(coff[0]))
			return -1;
		coff[ncomp] = (size_t)(start - raw);
		clen[ncomp] = len;
		ncomp++;
	}

	size_t off = 0;

	if (cap < 2)
		return -1;
	out[off++] = '/';
	for (size_t i = 0; i < ncomp; i++) {
		if (i)
			out[off++] = '/';
		if (off + clen[i] + 1 > cap)
			return -1;
		memcpy(out + off, raw + coff[i], clen[i]);
		off += clen[i];
	}
	out[off] = '\0';
	return 0;
}

int ac_project_hash(const char *cwd, char *out)
{
	char norm[4096];

	if (path_resolve_norm(cwd, norm, sizeof(norm)) != 0)
		return -1;
	struct sha1_ctx ctx;

	sha1_init(&ctx);
	sha1_update(&ctx, norm, strlen(norm));
	unsigned char digest[20];

	sha1_final(&ctx, digest);
	static const char HEXD[] = "0123456789abcdef";

	for (int i = 0; i < 5; i++) {
		out[i * 2] = HEXD[digest[i] >> 4];
		out[i * 2 + 1] = HEXD[digest[i] & 0x0F];
	}
	out[10] = '\0';
	return 0;
}

int ac_project_name(const char *cwd, char *out, size_t buflen)
{
	if (!cwd || !*cwd) {
		if (buflen < 1)
			return -1;
		out[0] = '\0';
		return 0;
	}
	const char *end = cwd + strlen(cwd);

	while (end > cwd + 1 && end[-1] == '/')
		end--;
	const char *slash = NULL;

	for (const char *q = cwd; q < end; q++)
		if (*q == '/')
			slash = q;
	const char *name = slash ? slash + 1 : cwd;
	size_t len = (size_t)(end - name);

	if (len + 1 > buflen)
		return -1;
	memcpy(out, name, len);
	out[len] = '\0';
	return 0;
}

const char *ac_normalize_status(const char *raw)
{
	if (!raw)
		return "pending";
	char buf[64];
	size_t n = 0;

	while (*raw && n < sizeof(buf) - 1) {
		char c = *raw;

		if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
		    c == '\v' || c == '\f') {
			raw++;
			continue;
		}
		buf[n++] = (char)tolower((unsigned char)c);
		raw++;
	}
	buf[n] = '\0';
	if (strcmp(buf, "completed") == 0 || strcmp(buf, "done") == 0)
		return "completed";
	if (strcmp(buf, "in_progress") == 0 || strcmp(buf, "in-progress") == 0 ||
	    strcmp(buf, "inprogress") == 0)
		return "in_progress";
	return "pending";
}

/* ================================================================== */
/* 通用 DOM 小工具                                                     */
/* ================================================================== */

static aik_json *dom_copy(const aik_json *v)
{
	if (!v)
		return NULL;
	char *text = NULL;
	size_t n = 0;

	if (aik_json_dump(v, &text, &n) != 0)
		return NULL;
	char err[128];
	aik_json *out = aik_json_parse(text, n, err, sizeof(err));

	free(text);
	return out;
}

static aik_json *jstr_or_null(const char *s)
{
	return s ? aik_json_new_str(s) : aik_json_new_null();
}

static int put_str(aik_json *o, const char *k, const char *v)
{
	return aik_json_obj_put(o, k, jstr_or_null(v)) == 0 ? 0 : -1;
}

static int put_opt_int(aik_json *o, const char *k, int has, long long v)
{
	return aik_json_obj_put(o, k,
				has ? aik_json_new_int(v) : aik_json_new_null()) == 0 ? 0 : -1;
}

static int put_copy(aik_json *o, const char *k, const aik_json *v)
{
	aik_json *cp = v ? dom_copy(v) : aik_json_new_null();

	if (!cp || aik_json_obj_put(o, k, cp) != 0) {
		aik_json_free(cp);
		return -1;
	}
	return 0;
}

/* UTF-8 码点计数（Python len(str)）*/
static size_t utf8_count(const char *s, size_t bytes)
{
	size_t n = 0;

	for (size_t i = 0; i < bytes; i++)
		if (((unsigned char)s[i] & 0xC0) != 0x80)
			n++;
	return n;
}

/* ================================================================== */
/* SessionState                                                        */
/* ================================================================== */

ac_session *ac_session_new(const char *session_id, const char *cwd)
{
	if (!session_id)
		return NULL;
	ac_session *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	s->session_id = xstrdup(session_id);
	s->cwd = xstrdup(cwd ? cwd : "");
	s->token_samples = aik_json_new_arr();
	s->plan_items = aik_json_new_arr();
	s->plan_archive = aik_json_new_arr();
	char now[32];

	if (!s->session_id || !s->cwd || !s->token_samples || !s->plan_items ||
	    !s->plan_archive || ac_iso_now(now, sizeof(now)) != 0) {
		ac_session_free(s);
		return NULL;
	}
	s->created_at = xstrdup(now);
	s->last_seen = xstrdup(now);
	if (!s->created_at || !s->last_seen) {
		ac_session_free(s);
		return NULL;
	}
	return s;
}

void ac_session_free(ac_session *s)
{
	if (!s)
		return;
	free(s->session_id);
	free(s->cwd);
	free(s->transcript_path);
	free(s->last_condense_at);
	free(s->cooldown_until);
	free(s->last_trigger);
	free(s->begin_mode);
	free(s->created_at);
	free(s->last_seen);
	aik_json_free(s->token_samples);
	aik_json_free(s->plan_items);
	aik_json_free(s->plan_archive);
	aik_json_free(s->last_judge);
	free(s);
}

static char *dup_str_field(const aik_json *d, const char *key)
{
	const aik_json *v = aik_json_get(d, key);

	if (!v || aik_json_typeof(v) != AIK_JSON_STR)
		return NULL;
	return xstrdup(aik_json_str(v));
}

static void parse_opt_int(const aik_json *d, const char *key, int *has,
			  long long *out)
{
	const aik_json *v = aik_json_get(d, key);

	if (v && aik_json_typeof(v) == AIK_JSON_INT) {
		*has = 1;
		*out = aik_json_int(v);
	}
}

ac_session *ac_session_from_dict(const aik_json *d)
{
	if (aik_json_typeof(d) != AIK_JSON_OBJ)
		return NULL;
	const aik_json *sid = aik_json_get(d, "session_id");

	if (!sid || aik_json_typeof(sid) != AIK_JSON_STR || !*aik_json_str(sid))
		return NULL;

	ac_session *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	s->session_id = xstrdup(aik_json_str(sid));
	s->cwd = dup_str_field(d, "cwd");
	if (!s->cwd)
		s->cwd = xstrdup("");
	s->transcript_path = dup_str_field(d, "transcript_path");
	s->last_condense_at = dup_str_field(d, "last_condense_at");
	s->cooldown_until = dup_str_field(d, "cooldown_until");
	s->last_trigger = dup_str_field(d, "last_trigger");
	s->begin_mode = dup_str_field(d, "begin_mode");
	s->created_at = dup_str_field(d, "created_at");
	s->last_seen = dup_str_field(d, "last_seen");
	s->token_samples = aik_json_new_arr();
	s->plan_items = aik_json_new_arr();
	s->plan_archive = aik_json_new_arr();
	if (!s->session_id || !s->cwd || !s->token_samples || !s->plan_items ||
	    !s->plan_archive) {
		ac_session_free(s);
		return NULL;
	}

	parse_opt_int(d, "context_tokens", &s->has_context_tokens,
		      &s->context_tokens);
	parse_opt_int(d, "est_tokens", &s->has_est_tokens, &s->est_tokens);
	parse_opt_int(d, "context_tokens_turn", &s->has_context_tokens_turn,
		      &s->context_tokens_turn);
	parse_opt_int(d, "last_file_turn", &s->has_last_file_turn,
		      &s->last_file_turn);
	parse_opt_int(d, "last_fail_turn", &s->has_last_fail_turn,
		      &s->last_fail_turn);
	parse_opt_int(d, "defer_until_turn", &s->has_defer_until_turn,
		      &s->defer_until_turn);

	const aik_json *v = aik_json_get(d, "turns");

	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		s->turns = aik_json_int(v);
	v = aik_json_get(d, "turns_since_condense");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		s->turns_since_condense = aik_json_int(v);
	v = aik_json_get(d, "defer_streak");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		s->defer_streak = aik_json_int(v);
	v = aik_json_get(d, "condensing");
	if (v && aik_json_typeof(v) == AIK_JSON_BOOL)
		s->condensing = aik_json_bool(v);

	const struct { const char *key; aik_json **dst; } arrs[] = {
		{ "token_samples", &s->token_samples },
		{ "plan_items", &s->plan_items },
		{ "plan_archive", &s->plan_archive },
	};

	for (size_t i = 0; i < sizeof(arrs) / sizeof(arrs[0]); i++) {
		const aik_json *a = aik_json_get(d, arrs[i].key);

		if (a && aik_json_typeof(a) == AIK_JSON_ARR) {
			aik_json *cp = dom_copy(a);

			if (!cp) {
				ac_session_free(s);
				return NULL;
			}
			aik_json_free(*arrs[i].dst);
			*arrs[i].dst = cp;
		}
	}
	const aik_json *lj = aik_json_get(d, "last_judge");

	if (lj && aik_json_typeof(lj) != AIK_JSON_NULL) {
		aik_json *cp = dom_copy(lj);

		if (!cp) {
			ac_session_free(s);
			return NULL;
		}
		s->last_judge = cp;
	}

	char now[32];

	if (ac_iso_now(now, sizeof(now)) != 0) {
		ac_session_free(s);
		return NULL;
	}
	if (!s->created_at) {
		s->created_at = xstrdup(now);
		if (!s->created_at) {
			ac_session_free(s);
			return NULL;
		}
	}
	if (!s->last_seen) {
		s->last_seen = xstrdup(now);
		if (!s->last_seen) {
			ac_session_free(s);
			return NULL;
		}
	}
	return s;
}

aik_json *ac_session_asdict(const ac_session *s)
{
	if (!s)
		return NULL;
	aik_json *o = aik_json_new_obj();

	if (!o)
		return NULL;
	if (put_str(o, "session_id", s->session_id) != 0 ||
	    put_str(o, "cwd", s->cwd) != 0 ||
	    put_str(o, "transcript_path", s->transcript_path) != 0 ||
	    put_opt_int(o, "context_tokens", s->has_context_tokens,
			s->context_tokens) != 0 ||
	    put_opt_int(o, "est_tokens", s->has_est_tokens, s->est_tokens) != 0 ||
	    put_copy(o, "token_samples", s->token_samples) != 0 ||
	    put_opt_int(o, "context_tokens_turn", s->has_context_tokens_turn,
			s->context_tokens_turn) != 0 ||
	    put_opt_int(o, "last_file_turn", s->has_last_file_turn,
			s->last_file_turn) != 0 ||
	    put_opt_int(o, "last_fail_turn", s->has_last_fail_turn,
			s->last_fail_turn) != 0 ||
	    put_copy(o, "plan_items", s->plan_items) != 0 ||
	    put_copy(o, "plan_archive", s->plan_archive) != 0 ||
	    aik_json_obj_put(o, "turns", aik_json_new_int(s->turns)) != 0 ||
	    aik_json_obj_put(o, "turns_since_condense",
			     aik_json_new_int(s->turns_since_condense)) != 0 ||
	    put_str(o, "last_condense_at", s->last_condense_at) != 0 ||
	    put_str(o, "cooldown_until", s->cooldown_until) != 0 ||
	    put_str(o, "last_trigger", s->last_trigger) != 0 ||
	    aik_json_obj_put(o, "condensing", aik_json_new_bool(s->condensing)) != 0 ||
	    put_copy(o, "last_judge", s->last_judge) != 0 ||
	    put_opt_int(o, "defer_until_turn", s->has_defer_until_turn,
			s->defer_until_turn) != 0 ||
	    aik_json_obj_put(o, "defer_streak", aik_json_new_int(s->defer_streak)) != 0 ||
	    put_str(o, "begin_mode", s->begin_mode) != 0 ||
	    put_str(o, "created_at", s->created_at) != 0 ||
	    put_str(o, "last_seen", s->last_seen) != 0) {
		aik_json_free(o);
		return NULL;
	}
	return o;
}

static size_t plan_count_status(const ac_session *s, const char *status)
{
	size_t n = 0;

	for (size_t i = 0; i < aik_json_count(s->plan_items); i++) {
		const aik_json *it = aik_json_at(s->plan_items, i);
		const aik_json *st = aik_json_get(it, "status");

		if (st && aik_json_typeof(st) == AIK_JSON_STR &&
		    strcmp(aik_json_str(st), status) == 0)
			n++;
	}
	return n;
}

aik_json *ac_session_summary(const ac_session *s)
{
	if (!s)
		return NULL;
	aik_json *o = aik_json_new_obj();

	if (!o)
		return NULL;
	size_t plan_total = aik_json_count(s->plan_items);

	if (put_str(o, "session_id", s->session_id) != 0 ||
	    put_str(o, "cwd", s->cwd) != 0 ||
	    put_str(o, "transcript_path", s->transcript_path) != 0 ||
	    put_opt_int(o, "context_tokens", s->has_context_tokens,
			s->context_tokens) != 0 ||
	    put_opt_int(o, "context_tokens_turn", s->has_context_tokens_turn,
			s->context_tokens_turn) != 0 ||
	    put_copy(o, "token_samples", s->token_samples) != 0 ||
	    put_opt_int(o, "est_tokens", s->has_est_tokens, s->est_tokens) != 0 ||
	    aik_json_obj_put(o, "plan_total", aik_json_new_int((long long)plan_total)) != 0 ||
	    aik_json_obj_put(o, "plan_completed",
			     aik_json_new_int((long long)plan_count_status(s, "completed"))) != 0 ||
	    aik_json_obj_put(o, "plan_in_progress",
			     aik_json_new_int((long long)plan_count_status(s, "in_progress"))) != 0 ||
	    aik_json_obj_put(o, "turns", aik_json_new_int(s->turns)) != 0 ||
	    aik_json_obj_put(o, "turns_since_condense",
			     aik_json_new_int(s->turns_since_condense)) != 0 ||
	    put_str(o, "last_condense_at", s->last_condense_at) != 0 ||
	    put_str(o, "cooldown_until", s->cooldown_until) != 0 ||
	    put_str(o, "last_trigger", s->last_trigger) != 0 ||
	    aik_json_obj_put(o, "condensing", aik_json_new_bool(s->condensing)) != 0 ||
	    put_copy(o, "last_judge", s->last_judge) != 0 ||
	    put_opt_int(o, "defer_until_turn", s->has_defer_until_turn,
			s->defer_until_turn) != 0 ||
	    aik_json_obj_put(o, "defer_streak", aik_json_new_int(s->defer_streak)) != 0 ||
	    put_str(o, "begin_mode", s->begin_mode) != 0 ||
	    put_opt_int(o, "last_file_turn", s->has_last_file_turn,
			s->last_file_turn) != 0 ||
	    put_opt_int(o, "last_fail_turn", s->has_last_fail_turn,
			s->last_fail_turn) != 0 ||
	    put_str(o, "created_at", s->created_at) != 0 ||
	    put_str(o, "last_seen", s->last_seen) != 0) {
		aik_json_free(o);
		return NULL;
	}
	return o;
}

/* ================================================================== */
/* StateStore                                                          */
/* ================================================================== */

struct ac_store {
	char *data_dir;
	const ac_config *cfg;
	int owns_cfg;
	ac_config cfg_storage;
	pthread_mutex_t lock;
	ac_session **sess;
	size_t n, cap;
};

static ac_session *find_session_locked(ac_store *st, const char *sid)
{
	for (size_t i = 0; i < st->n; i++)
		if (strcmp(st->sess[i]->session_id, sid) == 0)
			return st->sess[i];
	return NULL;
}

static int ensure_cap(ac_store *st, size_t need)
{
	if (need <= st->cap)
		return 0;
	size_t cap = st->cap ? st->cap : 8;

	while (cap < need)
		cap *= 2;
	ac_session **arr = realloc(st->sess, cap * sizeof(*arr));

	if (!arr)
		return -1;
	st->sess = arr;
	st->cap = cap;
	return 0;
}

static char *store_file(ac_store *st, const char *name)
{
	return path_join(st->data_dir, name);
}

static char *snap_dir(ac_store *st, const char *h)
{
	char *p1 = path_join(st->data_dir, AC_SNAPSHOTS_DIR);
	char *out = path_join(p1, h);

	free(p1);
	return out;
}

/* ---- sessions-state.json ---- */

static int save_sessions_locked(ac_store *st)
{
	aik_json *payload = aik_json_new_obj();

	if (!payload)
		return -1;
	char now[32];

	if (ac_iso_now(now, sizeof(now)) != 0 ||
	    aik_json_obj_put(payload, "version", aik_json_new_int(1)) != 0 ||
	    put_str(payload, "saved_at", now) != 0)
		goto fail;
	aik_json *sessions = aik_json_new_obj();

	if (!sessions)
		goto fail;
	for (size_t i = 0; i < st->n; i++) {
		aik_json *d = ac_session_asdict(st->sess[i]);

		if (!d || aik_json_obj_put(sessions, st->sess[i]->session_id, d) != 0) {
			aik_json_free(d);
			aik_json_free(sessions);
			goto fail;
		}
	}
	if (aik_json_obj_put(payload, "sessions", sessions) != 0) {
		aik_json_free(sessions);
		goto fail;
	}
	char *text = ac_json_dump_indent(payload, 2);

	aik_json_free(payload);
	if (!text)
		return -1;
	char *path = store_file(st, AC_SESSIONS_STATE_FILE);

	if (!path) {
		free(text);
		return -1;
	}
	int rc = ac_atomic_write_text(path, text, strlen(text));

	free(path);
	free(text);
	return rc;
fail:
	aik_json_free(payload);
	return -1;
}

static void load_sessions_locked(ac_store *st)
{
	char *path = store_file(st, AC_SESSIONS_STATE_FILE);

	if (!path)
		return;
	char *text = ac_read_file(path, NULL);

	if (!text) {
		free(path);
		return;
	}
	char err[128];
	aik_json *loaded = aik_json_parse(text, strlen(text), err, sizeof(err));

	free(text);
	if (!loaded) {
		char *q = ac_quarantine_corrupt(path);

		free(q);	/* 损坏：现场保留为 .corrupt-<ts>，清空重来 */
		free(path);
		return;
	}
	free(path);

	const aik_json *raw = NULL;
	aik_json_type lt = aik_json_typeof(loaded);

	if (lt == AIK_JSON_OBJ)
		raw = aik_json_get(loaded, "sessions");
	else if (lt == AIK_JSON_ARR)
		raw = loaded;

	const aik_json *items = NULL;
	size_t nitems = 0;

	if (raw && aik_json_typeof(raw) == AIK_JSON_OBJ) {
		items = raw;
		nitems = aik_json_count(raw);
		for (size_t i = 0; i < nitems; i++) {
			ac_session *s = ac_session_from_dict(aik_json_val_at(items, i));

			if (s && ensure_cap(st, st->n + 1) == 0)
				st->sess[st->n++] = s;
			else
				ac_session_free(s);
		}
	} else if (raw && aik_json_typeof(raw) == AIK_JSON_ARR) {
		items = raw;
		nitems = aik_json_count(raw);
		for (size_t i = 0; i < nitems; i++) {
			ac_session *s = ac_session_from_dict(aik_json_at(items, i));

			if (s && ensure_cap(st, st->n + 1) == 0)
				st->sess[st->n++] = s;
			else
				ac_session_free(s);
		}
	}
	/* sessions 字段非列表/字典：告警忽略（state.py:182）*/
	aik_json_free(loaded);
}

ac_store *ac_store_open(const char *data_dir, const ac_config *cfg)
{
	if (!data_dir || !*data_dir)
		return NULL;
	ac_store *st = calloc(1, sizeof(*st));

	if (!st)
		return NULL;
	/* Path 语义去尾斜杠（"/" 除外）*/
	size_t n = strlen(data_dir);

	while (n > 1 && data_dir[n - 1] == '/')
		n--;
	st->data_dir = malloc(n + 1);
	if (!st->data_dir) {
		free(st);
		return NULL;
	}
	memcpy(st->data_dir, data_dir, n);
	st->data_dir[n] = '\0';

	if (pthread_mutex_init(&st->lock, NULL) != 0) {
		free(st->data_dir);
		free(st);
		return NULL;
	}
	if (cfg) {
		st->cfg = cfg;
		st->owns_cfg = 0;
	} else {
		ac_config_default(&st->cfg_storage);
		st->cfg = &st->cfg_storage;
		st->owns_cfg = 1;
	}
	load_sessions_locked(st);
	return st;
}

void ac_store_close(ac_store *st)
{
	if (!st)
		return;
	for (size_t i = 0; i < st->n; i++)
		ac_session_free(st->sess[i]);
	free(st->sess);
	if (st->owns_cfg)
		ac_config_cleanup(&st->cfg_storage);
	pthread_mutex_destroy(&st->lock);
	free(st->data_dir);
	free(st);
}

const ac_config *ac_store_config(const ac_store *st)
{
	return st ? st->cfg : NULL;
}

/* ---- 会话操作 ---- */

static void touch_last_seen(ac_store *st, ac_session *s)
{
	char now[32];

	if (ac_iso_now(now, sizeof(now)) == 0) {
		free(s->last_seen);
		s->last_seen = xstrdup(now);
	}
	(void)st;
}

static int set_str_field(char **field, const char *v)
{
	char *dup = xstrdup(v);

	if (!dup)
		return -1;
	free(*field);
	*field = dup;
	return 0;
}

int ac_store_upsert(ac_store *st, const char *session_id, const char *cwd,
		    const char *transcript_path,
		    int has_context_tokens, long long context_tokens,
		    int has_est_tokens, long long est_tokens)
{
	if (!st || !session_id || !*session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		s = ac_session_new(session_id, cwd && *cwd ? cwd : "");
		if (!s || ensure_cap(st, st->n + 1) != 0) {
			ac_session_free(s);
			pthread_mutex_unlock(&st->lock);
			return -1;
		}
		st->sess[st->n++] = s;
	} else if (cwd && *cwd) {
		if (set_str_field(&s->cwd, cwd) != 0) {
			pthread_mutex_unlock(&st->lock);
			return -1;
		}
	}
	if (transcript_path && *transcript_path) {
		if (set_str_field(&s->transcript_path, transcript_path) != 0) {
			pthread_mutex_unlock(&st->lock);
			return -1;
		}
	}
	if (has_context_tokens) {
		s->has_context_tokens = 1;
		s->context_tokens = context_tokens;
		s->has_context_tokens_turn = 1;
		s->context_tokens_turn = s->turns;
		aik_json *sample = aik_json_new_obj();

		if (!sample ||
		    aik_json_obj_put(sample, "turn", aik_json_new_int(s->turns)) != 0 ||
		    aik_json_obj_put(sample, "tokens", aik_json_new_int(context_tokens)) != 0 ||
		    aik_json_arr_push(s->token_samples, sample) != 0) {
			aik_json_free(sample);
			pthread_mutex_unlock(&st->lock);
			return -1;
		}
		if (aik_json_count(s->token_samples) > 10) {
			aik_json *trimmed = aik_json_new_arr();

			if (!trimmed) {
				pthread_mutex_unlock(&st->lock);
				return -1;
			}
			for (size_t i = aik_json_count(s->token_samples) - 10;
			     i < aik_json_count(s->token_samples); i++) {
				aik_json *cp = dom_copy(aik_json_at(s->token_samples, i));

				if (!cp || aik_json_arr_push(trimmed, cp) != 0) {
					aik_json_free(cp);
					aik_json_free(trimmed);
					pthread_mutex_unlock(&st->lock);
					return -1;
				}
			}
			aik_json_free(s->token_samples);
			s->token_samples = trimmed;
		}
	}
	if (has_est_tokens) {
		s->has_est_tokens = 1;
		s->est_tokens = est_tokens;
	}
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

int ac_store_mark_activity(ac_store *st, const char *session_id,
			   enum ac_activity kind)
{
	if (!st || !session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	if (kind == AC_ACTIVITY_FILE) {
		s->has_last_file_turn = 1;
		s->last_file_turn = s->turns;
	} else if (kind == AC_ACTIVITY_FAIL) {
		s->has_last_fail_turn = 1;
		s->last_fail_turn = s->turns;
	}
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

const ac_session *ac_store_get_session(ac_store *st, const char *session_id)
{
	if (!st || !session_id)
		return NULL;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	pthread_mutex_unlock(&st->lock);
	return s;
}

static int cmp_last_seen_desc(const void *a, const void *b)
{
	const ac_session *sa = *(const ac_session *const *)a;
	const ac_session *sb = *(const ac_session *const *)b;

	return strcmp(sb->last_seen, sa->last_seen);
}

const ac_session **ac_store_all_sessions(ac_store *st, size_t *n)
{
	if (!st || !n)
		return NULL;
	pthread_mutex_lock(&st->lock);
	const ac_session **out = malloc((st->n ? st->n : 1) * sizeof(*out));

	if (!out) {
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	for (size_t i = 0; i < st->n; i++)
		out[i] = st->sess[i];
	/* last_seen 降序插入排序；并列保持插入序（sorted(reverse=True) 稳定）*/
	for (size_t i = 1; i < st->n; i++) {
		const ac_session *key = out[i];
		size_t j = i;

		while (j > 0 && cmp_last_seen_desc(&out[j - 1], &key) > 0) {
			out[j] = out[j - 1];
			j--;
		}
		out[j] = key;
	}
	*n = st->n;
	pthread_mutex_unlock(&st->lock);
	return out;
}

int ac_store_set_condensing(ac_store *st, const char *session_id, int flag)
{
	if (!st || !session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	s->condensing = flag ? 1 : 0;
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

int ac_store_set_est_tokens(ac_store *st, const char *session_id,
			    int has_est, long long est)
{
	if (!st || !session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	if (s->has_est_tokens == (has_est ? 1 : 0) &&
	    (!has_est || s->est_tokens == est)) {
		pthread_mutex_unlock(&st->lock);
		return 0;	/* 未变化：不落盘（state.py:264-268）*/
	}
	s->has_est_tokens = has_est ? 1 : 0;
	s->est_tokens = est;
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

int ac_store_bump_turn(ac_store *st, const char *session_id)
{
	if (!st || !session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	s->turns += 1;
	s->turns_since_condense += 1;
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

int ac_store_mark_condensed(ac_store *st, const char *session_id,
			    const char *trigger)
{
	if (!st || !session_id || !trigger)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	time_t now = ac_now();
	char iso[32];

	if (ac_iso_epoch(now, iso, sizeof(iso)) != 0 ||
	    set_str_field(&s->last_condense_at, iso) != 0) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	char iso2[32];

	if (ac_iso_epoch(now + (time_t)st->cfg->cooldown_minutes * 60,
			 iso2, sizeof(iso2)) != 0 ||
	    set_str_field(&s->cooldown_until, iso2) != 0 ||
	    set_str_field(&s->last_trigger, trigger) != 0) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	s->turns_since_condense = 0;
	s->condensing = 0;
	aik_json_free(s->plan_archive);
	s->plan_archive = aik_json_new_arr();
	s->has_defer_until_turn = 0;
	s->defer_streak = 0;
	free(s->begin_mode);
	s->begin_mode = NULL;
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

int ac_store_record_judge(ac_store *st, const char *session_id,
			  const aik_json *verdict, const char *result)
{
	if (!st || !session_id || !verdict || !result)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	char now[32];
	aik_json *rec = aik_json_new_obj();
	aik_json *vcopy = dom_copy(verdict);

	if (!rec || !vcopy || ac_iso_now(now, sizeof(now)) != 0 ||
	    aik_json_obj_put(rec, "turn", aik_json_new_int(s->turns)) != 0 ||
	    put_str(rec, "ts", now) != 0 ||
	    aik_json_obj_put(rec, "verdict", vcopy) != 0 ||
	    put_str(rec, "result", result) != 0) {
		aik_json_free(rec);
		aik_json_free(vcopy);
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	aik_json_free(s->last_judge);
	s->last_judge = rec;
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

int ac_store_set_defer_until_turn(ac_store *st, const char *session_id,
				  int has_turn, long long turn)
{
	if (!st || !session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	s->has_defer_until_turn = has_turn ? 1 : 0;
	s->defer_until_turn = turn;
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

int ac_store_set_defer_streak(ac_store *st, const char *session_id,
			      long long streak)
{
	if (!st || !session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	s->defer_streak = streak;
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

int ac_store_set_begin_mode(ac_store *st, const char *session_id,
			    const char *mode)
{
	if (!st || !session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	if (mode && set_str_field(&s->begin_mode, mode) != 0) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	if (!mode) {
		free(s->begin_mode);
		s->begin_mode = NULL;
	}
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

/* ---- 计划合并 ---- */

static char *plan_title_of(const aik_json *raw)
{
	const aik_json *v = aik_json_get(raw, "title");

	if (!v || aik_json_typeof(v) != AIK_JSON_STR || !*aik_json_str(v))
		v = aik_json_get(raw, "content");
	if (!v || aik_json_typeof(v) != AIK_JSON_STR || !*aik_json_str(v))
		return NULL;
	/* strip 后为空 → 无效（str().strip() 语义）*/
	const char *t = aik_json_str(v);
	size_t start = 0, end = strlen(t);

	while (start < end && isspace((unsigned char)t[start]))
		start++;
	while (end > start && isspace((unsigned char)t[end - 1]))
		end--;
	if (start >= end)
		return NULL;
	size_t len = end - start;
	char *out = malloc(len + 1);

	if (out) {
		memcpy(out, t + start, len);
		out[len] = '\0';
	}
	return out;
}

int ac_store_update_plan(ac_store *st, const char *session_id,
			 const aik_json *items)
{
	if (!st || !session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}

	/* merged：按 title 的插入序容器（后见同名保持首见位置、值更新）*/
	size_t n_items = (items && aik_json_typeof(items) == AIK_JSON_ARR) ?
		aik_json_count(items) : 0;
	char **titles = NULL;
	aik_json **entries = NULL;
	size_t n_merged = 0;

	if (n_items) {
		titles = calloc(n_items, sizeof(*titles));
		entries = calloc(n_items, sizeof(*entries));
		if (!titles || !entries)
			goto oom;
	}

	long long turns = s->turns;

	for (size_t i = 0; i < n_items; i++) {
		const aik_json *raw = aik_json_at(items, i);

		if (aik_json_typeof(raw) != AIK_JSON_OBJ)
			continue;
		char *title = plan_title_of(raw);

		if (!title)
			continue;
		const char *status = ac_normalize_status(aik_json_str(
			aik_json_get(raw, "status")));

		/* 同名已并入：保持位置，更新值 */
		size_t at = n_merged;
		int exists = 0;

		for (size_t j = 0; j < n_merged; j++) {
			if (strcmp(titles[j], title) == 0) {
				at = j;
				exists = 1;
				break;
			}
		}
		if (!exists) {
			titles[n_merged] = title;
			at = n_merged;
			n_merged++;
		} else {
			free(title);
		}

		/* prev：当前计划里的同名旧条目 */
		const aik_json *prev = NULL;

		for (size_t j = 0; j < aik_json_count(s->plan_items); j++) {
			const aik_json *it = aik_json_at(s->plan_items, j);
			const aik_json *t = aik_json_get(it, "title");

			if (t && aik_json_typeof(t) == AIK_JSON_STR &&
			    strcmp(aik_json_str(t), titles[at]) == 0) {
				prev = it;
				break;
			}
		}

		aik_json *entry;

		if (prev) {
			entry = dom_copy(prev);
			if (!entry)
				goto oom;
			const aik_json *old_status = aik_json_get(prev, "status");
			int was_completed = old_status &&
				aik_json_typeof(old_status) == AIK_JSON_STR &&
				strcmp(aik_json_str(old_status), "completed") == 0;
			aik_json *st_node = aik_json_new_str(status);

			if (!st_node) {
				aik_json_free(entry);
				goto oom;
			}
			if (aik_json_obj_set(entry, "status", st_node) != 0) {
				aik_json_free(st_node);	/* 未被接管 */
				aik_json_free(entry);
				goto oom;
			}
			if (strcmp(status, "completed") == 0 && !was_completed) {
				aik_json *ct = aik_json_new_int(turns);

				if (!ct) {
					aik_json_free(entry);
					goto oom;
				}
				if (aik_json_obj_set(entry, "completed_turn", ct) != 0) {
					aik_json_free(ct);
					aik_json_free(entry);
					goto oom;
				}
			}
		} else {
			entry = aik_json_new_obj();
			if (!entry)
				goto oom;
			aik_json *t_node = aik_json_new_str(titles[at]);
			aik_json *s_node = aik_json_new_str(status);
			aik_json *fs = aik_json_new_int(turns);
			aik_json *ct = strcmp(status, "completed") == 0 ?
				aik_json_new_int(turns) : aik_json_new_null();

			if (!t_node || !s_node || !fs || !ct ||
			    aik_json_obj_put(entry, "title", t_node) != 0 ||
			    aik_json_obj_put(entry, "status", s_node) != 0 ||
			    aik_json_obj_put(entry, "first_seen_turn", fs) != 0 ||
			    aik_json_obj_put(entry, "completed_turn", ct) != 0) {
				aik_json_free(t_node);
				aik_json_free(s_node);
				aik_json_free(fs);
				aik_json_free(ct);
				aik_json_free(entry);
				goto oom;
			}
		}
		if (exists)
			aik_json_free(entries[at]);
		entries[at] = entry;
	}

	/* 消失的 completed → plan_archive */
	for (size_t j = 0; j < aik_json_count(s->plan_items); j++) {
		const aik_json *prev = aik_json_at(s->plan_items, j);
		const aik_json *t = aik_json_get(prev, "title");

		if (!t || aik_json_typeof(t) != AIK_JSON_STR)
			continue;
		int still = 0;

		for (size_t k = 0; k < n_merged; k++) {
			if (titles[k] && strcmp(titles[k], aik_json_str(t)) == 0) {
				still = 1;
				break;
			}
		}
		if (still)
			continue;
		const aik_json *st = aik_json_get(prev, "status");

		if (!st || aik_json_typeof(st) != AIK_JSON_STR ||
		    strcmp(aik_json_str(st), "completed") != 0)
			continue;
		aik_json *arch = aik_json_new_obj();

		if (!arch)
			goto oom;
		aik_json *t2 = aik_json_new_str(aik_json_str(t));
		const aik_json *fs = aik_json_get(prev, "first_seen_turn");
		const aik_json *ct = aik_json_get(prev, "completed_turn");
		aik_json *fs2 = fs ? dom_copy(fs) : aik_json_new_null();
		aik_json *ct2 = ct ? dom_copy(ct) : aik_json_new_null();

		if (!t2 || !fs2 || !ct2 ||
		    aik_json_obj_put(arch, "title", t2) != 0 ||
		    aik_json_obj_put(arch, "first_seen_turn", fs2) != 0 ||
		    aik_json_obj_put(arch, "completed_turn", ct2) != 0 ||
		    aik_json_arr_push(s->plan_archive, arch) != 0) {
			aik_json_free(t2);
			aik_json_free(fs2);
			aik_json_free(ct2);
			aik_json_free(arch);
			goto oom;
		}
	}

	/* 重建 plan_items */
	aik_json *new_items = aik_json_new_arr();

	if (!new_items)
		goto oom;
	for (size_t i = 0; i < n_merged; i++) {
		if (aik_json_arr_push(new_items, entries[i]) != 0) {
			/* push 失败不接管 entries[i]；[i, n) 全部就地释放 */
			for (size_t k = i; k < n_merged; k++)
				aik_json_free(entries[k]);
			n_merged = i;	/* oom 只再释放 [0, i) */
			aik_json_free(new_items);
			goto oom;
		}
	}
	aik_json_free(s->plan_items);
	s->plan_items = new_items;
	for (size_t i = 0; i < n_merged; i++)
		free(titles[i]);
	free(titles);
	free(entries);
	touch_last_seen(st, s);
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
oom:
	if (titles) {
		for (size_t i = 0; i < n_merged; i++)
			free(titles[i]);
		free(titles);
	}
	if (entries) {
		for (size_t i = 0; i < n_merged; i++)
			aik_json_free(entries[i]);
		free(entries);
	}
	pthread_mutex_unlock(&st->lock);
	return -1;
}

int ac_store_clear_completed_plan_items(ac_store *st, const char *session_id)
{
	if (!st || !session_id)
		return -1;
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	aik_json *kept = aik_json_new_arr();

	if (!kept) {
		pthread_mutex_unlock(&st->lock);
		return -1;
	}
	for (size_t i = 0; i < aik_json_count(s->plan_items); i++) {
		const aik_json *it = aik_json_at(s->plan_items, i);
		const aik_json *stv = aik_json_get(it, "status");

		if (stv && aik_json_typeof(stv) == AIK_JSON_STR &&
		    strcmp(aik_json_str(stv), "completed") == 0)
			continue;
		aik_json *cp = dom_copy(it);

		if (!cp || aik_json_arr_push(kept, cp) != 0) {
			aik_json_free(cp);
			aik_json_free(kept);
			pthread_mutex_unlock(&st->lock);
			return -1;
		}
	}
	aik_json_free(s->plan_items);
	s->plan_items = kept;
	int rc = save_sessions_locked(st);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

/* ---- 事件流水 ---- */

static int append_event_locked(ac_store *st, const char *event,
			       const char *session_id, const char *cwd,
			       const aik_json *data)
{
	if (ac_mkdir_p(st->data_dir) != 0)
		return -1;
	aik_json *rec = aik_json_new_obj();
	aik_json *data_copy = data ? dom_copy(data) : aik_json_new_obj();
	char now[32];

	if (!rec || !data_copy || ac_iso_now(now, sizeof(now)) != 0 ||
	    put_str(rec, "ts", now) != 0 ||
	    put_str(rec, "event", event) != 0 ||
	    put_str(rec, "session_id", session_id) != 0 ||
	    put_str(rec, "cwd", cwd) != 0 ||
	    aik_json_obj_put(rec, "data", data_copy) != 0) {
		aik_json_free(rec);
		aik_json_free(data_copy);
		return -1;
	}
	char *line = ac_json_dump_default(rec);

	aik_json_free(rec);
	if (!line)
		return -1;
	char *path = store_file(st, AC_EVENTS_FILE);

	if (!path) {
		free(line);
		return -1;
	}
	FILE *f = fopen(path, "ab");

	free(path);
	if (!f) {
		free(line);
		return -1;
	}
	size_t len = strlen(line);
	int ok = fwrite(line, 1, len, f) == len && fputc('\n', f) != EOF;

	free(line);
	if (fclose(f) != 0)
		ok = 0;
	return ok ? 0 : -1;
}

int ac_store_append_event(ac_store *st, const char *event,
			  const char *session_id, const char *cwd,
			  const aik_json *data)
{
	if (!st || !event)
		return -1;
	pthread_mutex_lock(&st->lock);
	int rc = append_event_locked(st, event, session_id, cwd, data);

	pthread_mutex_unlock(&st->lock);
	return rc;
}

aik_json *ac_store_recent_events(ac_store *st, size_t n, int use_all)
{
	if (!st)
		return NULL;
	pthread_mutex_lock(&st->lock);
	aik_json *out = aik_json_new_arr();

	if (!out) {
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	char *path = store_file(st, AC_EVENTS_FILE);

	if (path) {
		char *text = ac_read_file(path, NULL);

		free(path);
		if (text) {
			/* 单遍解析；strtok_r 会改写缓冲区，结尾 n 条用环形取舍 */
			aik_json **all = NULL;
			size_t total = 0, cap = 0;
			char *save = NULL;

			for (char *line = strtok_r(text, "\n", &save); line;
			     line = strtok_r(NULL, "\n", &save)) {
				char *a = line;

				while (*a == ' ' || (*a >= '\t' && *a <= '\r'))
					a++;
				if (*a == '\0')
					continue;	/* 空行 */
				char err[128];
				aik_json *v = aik_json_parse(line, strlen(line),
							     err, sizeof(err));

				if (!v)
					continue;	/* 坏行跳过（state.py:459）*/
				if (total == cap) {
					size_t ncap = cap ? cap * 2 : 16;
					aik_json **na = realloc(all, ncap * sizeof(*na));

					if (!na) {
						aik_json_free(v);
						continue;
					}
					all = na;
					cap = ncap;
				}
				all[total++] = v;
			}
			free(text);
			size_t start = 0;

			if (!use_all && n > 0 && total > n)
				start = total - n;	/* out[-n:] */
			for (size_t i = start; i < total; i++) {
				if (aik_json_arr_push(out, all[i]) != 0)
					aik_json_free(all[i]);
			}
			free(all);
		}
	}
	pthread_mutex_unlock(&st->lock);
	return out;
}

/* ---- 快照 ---- */

static aik_json *read_index_locked(ac_store *st, const char *h)
{
	char *dir = snap_dir(st, h);

	if (!dir)
		return NULL;
	char *path = path_join(dir, AC_INDEX_FILE);

	free(dir);
	if (!path)
		return NULL;
	aik_json *out = aik_json_new_arr();

	if (!out) {
		free(path);
		return NULL;
	}
	char *text = ac_read_file(path, NULL);

	if (!text) {
		free(path);
		return out;
	}
	char err[128];
	aik_json *loaded = aik_json_parse(text, strlen(text), err, sizeof(err));

	free(text);
	if (!loaded) {
		char *q = ac_quarantine_corrupt(path);

		free(q);
		free(path);
		return out;
	}
	free(path);
	if (aik_json_typeof(loaded) == AIK_JSON_ARR) {
		aik_json_free(out);
		return loaded;
	}
	aik_json_free(loaded);
	return out;
}

static int cmp_entries_desc(const void *a, const void *b)
{
	const aik_json *ea = *(const aik_json *const *)a;
	const aik_json *eb = *(const aik_json *const *)b;
	const aik_json *ta = aik_json_get(ea, "ts");
	const aik_json *tb = aik_json_get(eb, "ts");
	const char *sa = (ta && aik_json_typeof(ta) == AIK_JSON_STR) ?
		aik_json_str(ta) : "";
	const char *sb = (tb && aik_json_typeof(tb) == AIK_JSON_STR) ?
		aik_json_str(tb) : "";
	int rc = strcmp(sb, sa);

	if (rc != 0)
		return rc;
	const aik_json *fa = aik_json_get(ea, "file");
	const aik_json *fb = aik_json_get(eb, "file");
	const char *da = (fa && aik_json_typeof(fa) == AIK_JSON_STR) ?
		aik_json_str(fa) : "";
	const char *db = (fb && aik_json_typeof(fb) == AIK_JSON_STR) ?
		aik_json_str(fb) : "";

	return strcmp(db, da);
}

static const aik_json **sorted_entries(const aik_json *arr, size_t *n)
{
	size_t cnt = aik_json_count(arr);
	const aik_json **vec = calloc(cnt ? cnt : 1, sizeof(*vec));

	if (!vec)
		return NULL;
	for (size_t i = 0; i < cnt; i++)
		vec[i] = aik_json_at(arr, i);
	/* qsort 非稳定：先做 (ts,file) 全序比较（file 唯一，无并列）*/
	for (size_t i = 1; i < cnt; i++) {
		const aik_json *key = vec[i];
		size_t j = i;

		while (j > 0 && cmp_entries_desc(&vec[j - 1], &key) > 0) {
			vec[j] = vec[j - 1];
			j--;
		}
		vec[j] = key;
	}
	*n = cnt;
	return vec;
}

static int write_index_locked(ac_store *st, const char *h,
			      const aik_json *entries)
{
	size_t n = 0;
	const aik_json **sorted = sorted_entries(entries, &n);

	if (!sorted) {
		free(sorted);
		return -1;
	}
	aik_json *arr = aik_json_new_arr();

	if (!arr) {
		free(sorted);
		return -1;
	}
	for (size_t i = 0; i < n; i++) {
		aik_json *cp = dom_copy(sorted[i]);

		if (!cp || aik_json_arr_push(arr, cp) != 0) {
			aik_json_free(cp);
			aik_json_free(arr);
			free(sorted);
			return -1;
		}
	}
	free(sorted);
	char *text = ac_json_dump_indent(arr, 2);

	aik_json_free(arr);
	if (!text)
		return -1;
	char *dir = snap_dir(st, h);
	char *path = dir ? path_join(dir, AC_INDEX_FILE) : NULL;

	free(dir);
	if (!path) {
		free(text);
		return -1;
	}
	int rc = ac_atomic_write_text(path, text, strlen(text));

	free(path);
	free(text);
	return rc;
}

/* trigger → \w∪{-} 保留、其余折叠 '_'、去首尾 '_'、空则 "manual" */
static char *safe_trigger(const char *trigger)
{
	const char *src = (trigger && *trigger) ? trigger : "manual";
	size_t n = strlen(src);
	char *raw = malloc(n + 1);

	if (!raw)
		return NULL;
	size_t k = 0;

	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)src[i];

		if (isalnum(c) || c == '_' || c == '-' || c >= 0x80)
			raw[k++] = (char)c;
		else
			raw[k++] = '_';
	}
	raw[k] = '\0';
	size_t start = 0, end = k;

	while (start < end && raw[start] == '_')
		start++;
	while (end > start && raw[end - 1] == '_')
		end--;
	if (start >= end) {
		char *out = xstrdup("manual");

		free(raw);
		return out;
	}
	char *out = malloc(end - start + 1);

	if (out) {
		memcpy(out, raw + start, end - start);
		out[end - start] = '\0';
	}
	free(raw);
	return out;
}

static char *digest_title(const char *md, size_t md_len)
{
	size_t i = 0;

	while (i < md_len) {
		size_t line_start = i;

		while (i < md_len && md[i] != '\n' && md[i] != '\r')
			i++;
		size_t line_end = i;
		if (i < md_len && md[i] == '\r' && i + 1 < md_len && md[i + 1] == '\n')
			i += 2;
		else if (i < md_len)
			i++;
		size_t a = line_start, b = line_end;

		while (a < b && isspace((unsigned char)md[a]))
			a++;
		while (b > a && isspace((unsigned char)md[b - 1]))
			b--;
		if (a < b) {
			size_t len = b - a;
			char *out = malloc(len + 1);

			if (out) {
				memcpy(out, md + a, len);
				out[len] = '\0';
			}
			return out;
		}
	}
	return xstrdup("");
}

aik_json *ac_store_save_snapshot(ac_store *st, const char *digest_md,
				 const char *trigger, const char *session_id,
				 int delta, char **path_out)
{
	if (!st || !digest_md || !trigger || !session_id)
		return NULL;
	size_t md_len = strlen(digest_md);
	pthread_mutex_lock(&st->lock);
	ac_session *s = find_session_locked(st, session_id);

	if (!s) {
		pthread_mutex_unlock(&st->lock);
		return NULL;	/* KeyError（会话不存在）*/
	}
	char h[11];

	if (ac_project_hash(s->cwd, h) != 0) {
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	char *dir = snap_dir(st, h);

	if (!dir || ac_mkdir_p(dir) != 0) {
		free(dir);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	char stamp[32];

	if (ac_stamp_now(stamp, sizeof(stamp)) != 0) {
		free(dir);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	char *safe = safe_trigger(trigger);

	if (!safe) {
		free(dir);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	char fname[512];
	int i = 1;

	snprintf(fname, sizeof(fname), "%s-%s.md", stamp, safe);
	for (;;) {
		char *cand = path_join(dir, fname);
		struct stat sb;
		int exists = cand && stat(cand, &sb) == 0;

		free(cand);
		if (!exists)
			break;
		snprintf(fname, sizeof(fname), "%s-%s-%d.md", stamp, safe, i);
		i++;
	}
	char *fpath = path_join(dir, fname);

	free(dir);
	free(safe);
	if (!fpath || ac_atomic_write_text(fpath, digest_md, md_len) != 0) {
		free(fpath);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	char *title = digest_title(digest_md, md_len);

	if (!title) {
		free(fpath);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	char ts[40];

	if (ac_iso_ms_now(ts, sizeof(ts)) != 0) {
		free(title);
		free(fpath);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	aik_json *entry = aik_json_new_obj();

	if (!entry) {
		free(title);
		free(fpath);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	aik_json *index = read_index_locked(st, h);
	aik_json *ev_data = aik_json_new_obj();

	if (!index || !ev_data ||
	    put_str(entry, "file", fpath) != 0 ||
	    put_str(entry, "ts", ts) != 0 ||
	    put_str(entry, "trigger", trigger) != 0 ||
	    put_str(entry, "session_id", session_id) != 0 ||
	    put_str(entry, "title", title) != 0 ||
	    aik_json_obj_put(entry, "char_count",
			     aik_json_new_int((long long)utf8_count(digest_md, md_len))) != 0 ||
	    aik_json_obj_put(entry, "sme_memory_id", aik_json_new_null()) != 0 ||
	    aik_json_obj_put(entry, "delta", aik_json_new_bool(delta ? 1 : 0)) != 0 ||
	    aik_json_arr_push(index, entry) != 0) {
		aik_json_free(entry);
		aik_json_free(index);
		aik_json_free(ev_data);
		free(title);
		free(fpath);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	/* index 持有 entry；写失败时连带释放 */
	if (write_index_locked(st, h, index) != 0) {
		aik_json_free(index);
		aik_json_free(ev_data);
		free(title);
		free(fpath);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	if (put_str(ev_data, "trigger", trigger) != 0 ||
	    put_str(ev_data, "file", fpath) != 0 ||
	    aik_json_obj_put(ev_data, "char_count",
			     aik_json_new_int((long long)utf8_count(digest_md, md_len))) != 0 ||
	    aik_json_obj_put(ev_data, "delta", aik_json_new_bool(delta ? 1 : 0)) != 0) {
		aik_json_free(index);
		aik_json_free(ev_data);
		free(title);
		free(fpath);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	append_event_locked(st, "condense", session_id, s->cwd, ev_data);
	aik_json_free(ev_data);

	/* 复制一份返回（index 里的那份已定稿）*/
	aik_json *entry_out = dom_copy(entry);

	aik_json_free(index);
	if (!entry_out) {
		free(title);
		free(fpath);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	free(title);
	if (path_out)
		*path_out = fpath;
	else
		free(fpath);
	pthread_mutex_unlock(&st->lock);
	return entry_out;
}

long long ac_store_read_delta_state(ac_store *st, const char *project_hash_)
{
	if (!st || !project_hash_)
		return 0;
	char *dir = snap_dir(st, project_hash_);

	if (!dir)
		return 0;
	char *path = path_join(dir, AC_DELTA_STATE_FILE);

	free(dir);
	if (!path)
		return 0;
	char *text = ac_read_file(path, NULL);

	free(path);
	if (!text)
		return 0;
	char err[128];
	aik_json *d = aik_json_parse(text, strlen(text), err, sizeof(err));

	free(text);
	if (!d)
		return 0;	/* 损坏按 0 */
	long long out = 0;

	if (aik_json_typeof(d) == AIK_JSON_OBJ) {
		const aik_json *v = aik_json_get(d, "delta_since_full");

		if (v && aik_json_typeof(v) == AIK_JSON_INT && aik_json_int(v) >= 0)
			out = aik_json_int(v);
	}
	aik_json_free(d);
	return out;
}

int ac_store_write_delta_state(ac_store *st, const char *project_hash_,
			       long long value)
{
	if (!st || !project_hash_)
		return -1;
	aik_json *o = aik_json_new_obj();

	if (!o)
		return -1;
	if (aik_json_obj_put(o, "delta_since_full", aik_json_new_int(value)) != 0) {
		aik_json_free(o);
		return -1;
	}
	char *body = ac_json_dump_default(o);

	aik_json_free(o);
	if (!body)
		return -1;
	size_t blen = strlen(body);
	char *full = malloc(blen + 2);

	if (!full) {
		free(body);
		return -1;
	}
	memcpy(full, body, blen);
	full[blen] = '\n';
	full[blen + 1] = '\0';
	char *dir = snap_dir(st, project_hash_);
	char *path = dir ? path_join(dir, AC_DELTA_STATE_FILE) : NULL;

	free(dir);
	if (!path) {
		free(full);
		free(body);
		return -1;
	}
	int rc = ac_atomic_write_text(path, full, blen + 1);

	free(path);
	free(full);
	free(body);
	return rc;
}

aik_json *ac_store_list_snapshots(ac_store *st, const char *project_hash_,
				  int has_top_n, long long top_n)
{
	if (!st || !project_hash_)
		return NULL;
	pthread_mutex_lock(&st->lock);
	aik_json *index = read_index_locked(st, project_hash_);

	if (!index) {
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	size_t n = 0;
	const aik_json **sorted = sorted_entries(index, &n);

	if (!sorted) {
		aik_json_free(index);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	size_t take = n;

	if (has_top_n && top_n > 0 && (size_t)top_n < take)
		take = (size_t)top_n;
	aik_json *out = aik_json_new_arr();

	if (!out) {
		free(sorted);
		aik_json_free(index);
		pthread_mutex_unlock(&st->lock);
		return NULL;
	}
	for (size_t i = 0; i < take; i++) {
		aik_json *cp = dom_copy(sorted[i]);

		if (!cp || aik_json_arr_push(out, cp) != 0) {
			aik_json_free(cp);
			aik_json_free(out);
			free(sorted);
			aik_json_free(index);
			pthread_mutex_unlock(&st->lock);
			return NULL;
		}
	}
	free(sorted);
	aik_json_free(index);
	pthread_mutex_unlock(&st->lock);
	return out;
}

int ac_store_set_snapshot_memory_id(ac_store *st, const char *project_hash_,
				    const char *file_path, const char *memory_id)
{
	if (!st || !project_hash_ || !file_path || !memory_id)
		return 0;
	pthread_mutex_lock(&st->lock);
	aik_json *index = read_index_locked(st, project_hash_);

	if (!index) {
		pthread_mutex_unlock(&st->lock);
		return 0;
	}
	int found = 0;

	for (size_t i = 0; i < aik_json_count(index) && !found; i++) {
		aik_json *e = (aik_json *)aik_json_at(index, i);
		const aik_json *f = aik_json_get(e, "file");

		if (f && aik_json_typeof(f) == AIK_JSON_STR &&
		    strcmp(aik_json_str(f), file_path) == 0) {
			aik_json *mid = aik_json_new_str(memory_id);

			if (mid && aik_json_obj_set(e, "sme_memory_id", mid) == 0)
				found = 1;
			else
				aik_json_free(mid);
		}
	}
	int rc = found ? write_index_locked(st, project_hash_, index) : 0;

	aik_json_free(index);
	pthread_mutex_unlock(&st->lock);
	return found && rc == 0 ? 1 : 0;
}
