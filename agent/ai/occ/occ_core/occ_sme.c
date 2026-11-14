/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_sme.c - occ × SME 长期记忆绑定（T9d，OPENCODE-PLAN §8）
 *
 * 复用 memory/sme_client.c（36 路由正典的 C 客户端，T4/T5 已 C 化）——
 * 本文件只做「何时查、查什么、怎么注入、何时写、写几条」，不重写 HTTP/
 * JSON 细节。SME 不可达 = 正常场景（记忆是增强能力，不是硬依赖）：
 * 状态转 `@sme:off` 诚实降级，绝不阻塞对话、绝不静默空结果。
 */
#define _POSIX_C_SOURCE 200809L
#include "occ_sme.h"
#include "occ_session.h"	/* E5：occ_sessions_dir 声明迁此 */

#include "occ_ac.h"		/* occ_sessions_dir（会话侧目录共用） */

#include "ai_types.h"
#include "memory/sme_client.h"
#include "store/store_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/* 命中段落与整块的尺寸上限（防 system prompt 膨胀） */
#define OCC_SME_HIT_MAX 400		/* 单条（字节） */
#define OCC_SME_BLOCK_MAX 6000		/* 整块（字节） */
#define OCC_SME_QUERY_MAX 480		/* 查询文本（字节） */
#define OCC_SME_RESP_MAX (512 * 1024)	/* 检索响应体上限 */

/* 状态：0=unknown 1=on 2=off */
static int g_sme_state;

int occ_sme_test_set_state(int v)
{
	int old = g_sme_state;

	g_sme_state = v;
	return old;
}

int occ_sme_enabled(void)
{
	const char *e = getenv("OCC_SME");

	return !(e && *e && !strcmp(e, "off"));
}

const char *occ_sme_status(void)
{
	if (!occ_sme_enabled())
		return "@sme:off";	/* 显式禁用也是「关」——诚实展示 */
	switch (g_sme_state) {
	case 1:
		return "@sme:on";
	case 2:
		return "@sme:off";
	default:
		return "@sme:?";	/* 尚未发生调用（unknown） */
	}
}

/* ---- UTF-8 安全截断（不在码点中间切断） ---- */
static void utf8_cut(char *s, size_t max)
{
	size_t n = strlen(s), i;

	if (n <= max)
		return;
	for (i = max; i > 0 && i < n && (s[i] & 0xC0) == 0x80; i--)
		;
	s[i] = '\0';
}

/* ---- 会话侧配额计数（<dir>/<sid>.smeq，跨进程一致） ---- */

static int quota_path(char *buf, size_t cap, const char *session_id)
{
	const char *dir = occ_sessions_dir();

	if (!dir || !session_id || !*session_id)
		return -1;
	if (snprintf(buf, cap, "%s/%s.smeq", dir, session_id) >= (int)cap)
		return -1;
	return 0;
}

static int quota_read(const char *session_id)
{
	char path[512], line[32];
	FILE *f;
	int used = 0;

	if (quota_path(path, sizeof(path), session_id) != 0)
		return 0;
	f = fopen(path, "rb");
	if (!f)
		return 0;
	if (fgets(line, sizeof(line), f))
		used = atoi(line);
	fclose(f);
	return used < 0 ? 0 : used;
}

static void quota_bump(const char *session_id)
{
	char path[512];
	int next;
	FILE *f;

	if (quota_path(path, sizeof(path), session_id) != 0)
		return;
	next = quota_read(session_id) + 1;	/* 先读后截断（wb 会清空）*/
	f = fopen(path, "wb");
	if (!f)
		return;
	fprintf(f, "%d\n", next);
	fclose(f);
}

int occ_sme_quota_left(const char *session_id)
{
	int used;

	if (!occ_sme_enabled())
		return 0;
	used = quota_read(session_id);
	return used >= OCC_SME_SESSION_QUOTA ?
	       0 : OCC_SME_SESSION_QUOTA - used;
}

/* ---- ① 检索注入 ---- */

/* 响应体：{"query":…,"count":N,"results":[{…,"text":…},…]}（smehttp
 * SearchHit = 记忆 dict + score/breakdown） */
static char *build_block(const aik_json *root)
{
	const aik_json *results = aik_json_get(root, "results");
	size_t n, i, used = 0;
	char *blk;
	int any = 0;

	if (!results || aik_json_typeof(results) != AIK_JSON_ARR)
		return NULL;
	n = aik_json_count(results);
	blk = malloc(OCC_SME_BLOCK_MAX + 64);
	if (!blk)
		return NULL;
	used = (size_t)snprintf(blk, OCC_SME_BLOCK_MAX + 64, OCC_SME_BLOCK_HEAD
				"（来自长期记忆，可能过时，仅供参考）\n");
	for (i = 0; i < n && used < OCC_SME_BLOCK_MAX; i++) {
		const aik_json *hit = aik_json_at(results, i);
		const aik_json *tv = hit ? aik_json_get(hit, "text") : NULL;
		const char *text;
		char line[OCC_SME_HIT_MAX + 32];
		int ln;

		if (!tv || aik_json_typeof(tv) != AIK_JSON_STR)
			continue;
		text = aik_json_str(tv);
		if (!text || !*text)
			continue;
		snprintf(line, sizeof(line), "%s", text);
		utf8_cut(line, OCC_SME_HIT_MAX);
		ln = snprintf(blk + used, OCC_SME_BLOCK_MAX + 64 - used,
			      "- %s\n", line);
		if (ln < 0 || (size_t)ln >= OCC_SME_BLOCK_MAX + 64 - used)
			break;
		used += (size_t)ln;
		any = 1;
	}
	if (!any) {
		free(blk);
		return NULL;
	}
	snprintf(blk + used, OCC_SME_BLOCK_MAX + 64 - used, OCC_SME_BLOCK_TAIL
		 "\n");
	return blk;
}

/* E6 桥：默认 sme_client；测试/外接经 occ_sme_set_bridge 替换 */
static int bridge_search_def(struct sme_search_opts *o, char *resp,
			     size_t cap)
{
	return sme_search_ex(o, resp, cap);
}

static int bridge_add_def(struct sme_add_opts *o, char *resp, size_t cap)
{
	return sme_add_ex(o, resp, cap);
}

static struct occ_mem_bridge g_bridge = {
	bridge_search_def, bridge_add_def,
};

void occ_sme_set_bridge(const struct occ_mem_bridge *b)
{
	if (b)
		g_bridge = *b;
	else
		g_bridge = (struct occ_mem_bridge){ bridge_search_def,
						    bridge_add_def };
}

char *occ_sme_lookup(const char *query)
{
	struct sme_search_opts o;
	char *resp = NULL;
	char *blk = NULL;
	char q[OCC_SME_QUERY_MAX + 8];
	int rc;

	if (!occ_sme_enabled() || !query || !*query)
		return NULL;
	resp = malloc(OCC_SME_RESP_MAX);
	if (!resp)
		return NULL;
	memset(&o, 0, sizeof(o));
	snprintf(q, sizeof(q), "%s", query);
	utf8_cut(q, OCC_SME_QUERY_MAX);
	o.text = q;
	o.top_k = OCC_SME_TOP_K;
	o.tags_json = OCC_SME_SEARCH_TAGS;
	rc = g_bridge.search(&o, resp, OCC_SME_RESP_MAX);
	if (rc == AI_OK) {
		char err[128];
		aik_json *root = aik_json_parse(resp, strlen(resp), err,
						sizeof(err));

		if (root) {
			blk = build_block(root);
			aik_json_free(root);
		}
		g_sme_state = 1;	/* 服务可达即 on（无命中≠故障） */
	} else {
		g_sme_state = 2;	/* 不可达/非 2xx → 诚实降级 */
	}
	free(resp);
	return blk;
}

/* ---- ② 里程碑写回 ---- */

int occ_sme_remember(const char *session_id, const char *title,
		     const char *text)
{
	struct sme_add_opts o;
	char *resp;
	char *meta = NULL;
	char *full = NULL;
	aik_json *m;
	char *dump = NULL;
	size_t dlen = 0;
	int rc, ret;

	if (!occ_sme_enabled() || !session_id || !text || !*text)
		return 0;
	if (occ_sme_quota_left(session_id) <= 0)
		return 0;		/* 配额尽（§8.3）——不是错误 */

	full = malloc(strlen(text) + 256);
	if (!full)
		return -1;
	if (title && *title)
		snprintf(full, strlen(text) + 256, "【会话 %s】\n%s", title,
			 text);
	else
		snprintf(full, strlen(text) + 256, "%s", text);

	/* metadata JSON：{"src":"occ","session":"…","ts":<ms>} */
	m = aik_json_new_obj();
	if (m) {
		struct timeval tv;
		aik_json *v;
		int bad = 0;

		gettimeofday(&tv, NULL);
		v = aik_json_new_str("occ");
		if (!v || aik_json_obj_put(m, "src", v) != 0) {
			aik_json_free(v);
			bad = 1;
		}
		v = aik_json_new_str(session_id);
		if (!v || aik_json_obj_put(m, "session", v) != 0) {
			aik_json_free(v);
			bad = 1;
		}
		v = aik_json_new_int((long long)tv.tv_sec * 1000 +
				     tv.tv_usec / 1000);
		if (!v || aik_json_obj_put(m, "ts", v) != 0) {
			aik_json_free(v);
			bad = 1;
		}
		if (bad) {
			aik_json_free(m);
			m = NULL;
		}
	}
	if (m && aik_json_dump(m, &dump, &dlen) == 0)
		meta = dump;
	aik_json_free(m);

	resp = malloc(8192);
	if (!resp) {
		free(dump);
		free(full);
		return -1;
	}
	memset(&o, 0, sizeof(o));
	o.text = full;
	o.metadata_json = meta;
	o.tags_json = OCC_SME_WRITE_TAGS;
	o.has_importance = 1;
	o.importance = OCC_SME_WRITE_IMPORTANCE;
	o.source = "occ";
	rc = g_bridge.add(&o, resp, 8192);
	free(resp);
	free(dump);
	free(full);
	if (rc != AI_OK) {
		g_sme_state = 2;
		return -1;
	}
	g_sme_state = 1;
	quota_bump(session_id);
	ret = 1;
	return ret;
}


/* ---- E6 分层读写（ORCH §6 拍板 5/8） ---- */

int occ_sme_remember_ex(const char *session_id, const char *title,
			const char *text, const char *layer,
			const char *status)
{
	char tags[256];
	int degraded = status && (!strcmp(status, "failed") ||
				  !strcmp(status, "rejected"));
	const char *lay = (layer && *layer) ? layer : OCC_SME_LAYER_GLOBAL;
	struct {
		const char *text;
		char *dump;
		size_t dlen;
		aik_json *m;
		struct timeval tv;
		int bad;
	} x;
	char *resp, *full;
	struct sme_add_opts o;
	int rc, ret;

	if (!occ_sme_enabled() || !session_id || !text || !*text)
		return 0;
	if (!lay && !(lay = OCC_SME_LAYER_GLOBAL))
		return 0;
	/* 层→tag 族：
	 *   g:/p:  → 存量族 occ/user + 层 tag（主检索可见）
	 *   t:*    → occ_task 族独占（主检索不可见=任务隔离）
	 *   failed → occ_failed 族（清洁检索不可见；importance 0.3） */
	if (degraded)
		snprintf(tags, sizeof(tags), "[\"%s\",\"%s\"]",
			 OCC_SME_TAG_FAILED, lay);
	else if (!strncmp(lay, OCC_SME_LAYER_TASK, 2))
		snprintf(tags, sizeof(tags),
			 "[\"%s\",\"%s\"]", OCC_SME_TAG_TASK, lay);
	else
		snprintf(tags, sizeof(tags),
			 "%s,\"%s\"]", OCC_SME_WRITE_TAGS, lay);
	if (occ_sme_quota_left(session_id) <= 0)
		return 0;
	full = malloc(strlen(text) + 256);
	if (!full)
		return -1;
	if (title && *title)
		snprintf(full, strlen(text) + 256, "【会话 %s】\n%s",
			 title, text);
	else
		snprintf(full, strlen(text) + 256, "%s", text);
	x.bad = 0;
	x.dump = NULL;
	x.m = aik_json_new_obj();
	if (x.m) {
		aik_json *v;

		gettimeofday(&x.tv, NULL);
		v = aik_json_new_str("occ");
		if (!v || aik_json_obj_put(x.m, "src", v) != 0) {
			aik_json_free(v);
			x.bad = 1;
		}
		v = aik_json_new_str(session_id);
		if (!v || aik_json_obj_put(x.m, "session", v) != 0) {
			aik_json_free(v);
			x.bad = 1;
		}
		v = aik_json_new_int((long long)x.tv.tv_sec * 1000 +
				     x.tv.tv_usec / 1000);
		if (!v || aik_json_obj_put(x.m, "ts", v) != 0) {
			aik_json_free(v);
			x.bad = 1;
		}
		v = aik_json_new_str(status && *status ? status : "ok");
		if (!v || aik_json_obj_put(x.m, "status", v) != 0) {
			aik_json_free(v);
			x.bad = 1;
		}
		if (x.bad) {
			aik_json_free(x.m);
			x.m = NULL;
		}
	}
	if (x.m && aik_json_dump(x.m, &x.dump, &x.dlen) != 0)
		x.dump = NULL;
	aik_json_free(x.m);
	resp = malloc(8192);
	if (!resp) {
		free(x.dump);
		free(full);
		return -1;
	}
	memset(&o, 0, sizeof(o));
	o.text = full;
	o.metadata_json = x.dump;
	o.tags_json = tags;
	o.has_importance = 1;
	o.importance = degraded ? 0.3 : OCC_SME_WRITE_IMPORTANCE;
	o.source = "occ";
	rc = g_bridge.add(&o, resp, 8192);
	free(resp);
	free(x.dump);
	free(full);
	if (rc != AI_OK) {
		g_sme_state = 2;
		return -1;
	}
	g_sme_state = 1;
	quota_bump(session_id);
	ret = 1;
	return ret;
}

/* 响应 results[].text 收集（任务层优先序由调用序保证） */
static size_t collect_texts(const char *resp, char **lines, size_t cap,
			    size_t n)
{
	aik_json *root = aik_json_parse(resp, strlen(resp), NULL, 0);
	const aik_json *results;

	if (!root)
		return n;
	results = aik_json_get(root, "results");
	if (results && aik_json_typeof(results) == AIK_JSON_ARR) {
		size_t i, cnt = aik_json_count(results);

		for (i = 0; i < cnt && n < cap; i++) {
			const aik_json *hit = aik_json_at(results, i);
			const aik_json *tv = hit ? aik_json_get(hit, "text")
						 : NULL;
			const char *t;
			size_t j;
			int dup = 0;

			if (!tv || aik_json_typeof(tv) != AIK_JSON_STR)
				continue;
			t = aik_json_str(tv);
			if (!t || !*t)
				continue;
			for (j = 0; j < n && !dup; j++)
				if (!strncmp(lines[j], t, 64))
					dup = 1;
			if (dup)
				continue;
			lines[n] = malloc(strlen(t) + 1);
			if (lines[n])
				strcpy(lines[n], t);
			n++;
		}
	}
	aik_json_free(root);
	return n;
}

static int g_e6_failed_only;	/* lookup_ex：failed-only 检索（跳基线） */

char *occ_sme_lookup_ex(const char *query, const char *layer_filter)
{
	char *lines[OCC_SME_TOP_K * 2];
	size_t n = 0, i, used = 0;
	char *blk;
	int any = 0;
	struct {
		char q[OCC_SME_QUERY_MAX + 8];
		struct sme_search_opts o;
		char *resp;
	} s;

	if (!occ_sme_enabled() || !query || !*query)
		return NULL;
	memset(lines, 0, sizeof(lines));
	memset(&s, 0, sizeof(s));
	snprintf(s.q, sizeof(s.q), "%s", query);
	utf8_cut(s.q, OCC_SME_QUERY_MAX);

	/* 任务层/failed 令牌先搜（命中优先排前） */
	{
		const char *lf = layer_filter ? layer_filter : "";
		int had_layer_tok = 0, had_failed = 0;

		for (const char *tok = lf; tok && *tok; ) {
			const char *comma = strchr(tok, ',');
			size_t tl = comma ? (size_t)(comma - tok) : strlen(tok);
			char token[128];
			char tags[192];

			if (tl >= sizeof(token))
				tl = sizeof(token) - 1;
			memcpy(token, tok, tl);
			token[tl] = '\0';
			if (!strncmp(token, OCC_SME_LAYER_TASK, 2) ||
			    !strcmp(token, "failed")) {
				if (!strcmp(token, "failed"))
					had_failed = 1;
				else
					had_layer_tok = 1;
				snprintf(tags, sizeof(tags), "[\"%s\"]",
					 !strcmp(token, "failed") ?
					 OCC_SME_TAG_FAILED :
					 OCC_SME_TAG_TASK);
				/* 任务层须带全 tag：occ_task+t:<tid> */
				if (!strncmp(token, OCC_SME_LAYER_TASK, 2))
					snprintf(tags, sizeof(tags),
						 "[\"%s\",\"%s\"]",
						 OCC_SME_TAG_TASK, token);
				s.o.text = s.q;
				s.o.top_k = OCC_SME_TOP_K;
				s.o.tags_json = tags;
				s.resp = malloc(OCC_SME_RESP_MAX);
				if (s.resp) {
					if (g_bridge.search(&s.o, s.resp,
							    OCC_SME_RESP_MAX)
					    == AI_OK)
						n = collect_texts(s.resp,
								  lines,
								  OCC_SME_TOP_K,
								  n);
					free(s.resp);
					s.resp = NULL;
				}
			}
			tok = comma ? comma + 1 : NULL;
		}
		g_e6_failed_only = had_failed && !had_layer_tok;
	}
	/* 基线（g:/p:/存量）——failed-only 检索跳过（只查降权族） */
	if (!g_e6_failed_only) {
		s.o.text = s.q;
		s.o.top_k = OCC_SME_TOP_K;
		s.o.tags_json = OCC_SME_SEARCH_TAGS;
		s.resp = malloc(OCC_SME_RESP_MAX);
		if (s.resp) {
			if (g_bridge.search(&s.o, s.resp,
					    OCC_SME_RESP_MAX) == AI_OK)
				g_sme_state = 1;
			else
				g_sme_state = 2;
			n = collect_texts(s.resp, lines, OCC_SME_TOP_K * 2,
					  n);
			free(s.resp);
		}
	}
	if (!n)
		return NULL;
	blk = malloc(OCC_SME_BLOCK_MAX + 64);
	if (!blk) {
		for (i = 0; i < n; i++)
			free(lines[i]);
		return NULL;
	}
	used = (size_t)snprintf(blk, OCC_SME_BLOCK_MAX + 64,
				OCC_SME_BLOCK_HEAD
				"（来自长期记忆，可能过时，仅供参考）\n");
	for (i = 0; i < n && used < OCC_SME_BLOCK_MAX; i++) {
		char line[OCC_SME_HIT_MAX + 32];
		int ln;

		snprintf(line, sizeof(line), "%s", lines[i]);
		utf8_cut(line, OCC_SME_HIT_MAX);
		ln = snprintf(blk + used,
			      OCC_SME_BLOCK_MAX + 64 - used, "- %s\n",
			      line);
		if (ln < 0 || (size_t)ln >= OCC_SME_BLOCK_MAX + 64 - used)
			break;
		used += (size_t)ln;
		any = 1;
		if (i + 1 >= OCC_SME_TOP_K)
			break;
	}
	for (i = 0; i < n; i++)
		free(lines[i]);
	if (!any) {
		free(blk);
		return NULL;
	}
	used += (size_t)snprintf(blk + used, OCC_SME_BLOCK_MAX + 64 - used,
				 OCC_SME_BLOCK_TAIL);
	return blk;
}
