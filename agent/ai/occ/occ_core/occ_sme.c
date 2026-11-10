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
	rc = sme_search_ex(&o, resp, OCC_SME_RESP_MAX);
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
	rc = sme_add_ex(&o, resp, 8192);
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
