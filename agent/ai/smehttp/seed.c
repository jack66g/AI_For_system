/* SPDX-License-Identifier: GPL-2.0 */
/*
 * seed.c - T7a aikd 种子自导（--import-seed）
 *
 * 语义对齐 factory/usr/local/share/aikernel/sme-seed.sh 的 python heredoc
 * （W10-A v2 差量导入，行 25-41）：
 *   1. 逐行读 JSONL（跳过空行），每行一个 JSON 对象（记忆导入形态）；
 *   2. 内部调 GET /export 等价（aik_http_route_export，不走网络回环），
 *      取现有记忆的 text 集合；
 *   3. 差集 = seed 中 text 不在现有集合的条目；
 *   4. 有差集时内部调 POST /memories/batch 等价（aik_http_route_add_batch）
 *      一次性灌入；二次运行 missing=0 不写库（幂等）。
 *
 * stdout 输出与 sme-seed.sh 同款可 grep 行（wording 保持一致，便于
 * 运维脚本/日志比对迁移）：
 *   [aikd-seed] seed=%d existing=%d missing=%d
 *   [aikd-seed] batch resp: <响应 JSON>
 *   [aikd-seed] corpus already complete, skip
 *
 * 失败（文件不可读/行非 JSON/路由非 200）写 err 并返回 -1，调用方
 * 以非 0 退出（不静默降级）。engine 无并发访问（服务尚未对外）。
 */
#define _POSIX_C_SOURCE 200809L

#include "smehttp/seed.h"

#include "store/store_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct seed_ctx {
	aik_json **items;	/* 每行解析出的对象（移交进 batch 的置 NULL） */
	size_t n;
	size_t cap;
};

static int seed_push(struct seed_ctx *c, aik_json *v)
{
	if (c->n == c->cap) {
		size_t ncap = c->cap ? c->cap * 2 : 64;
		aik_json **ni = realloc(c->items, ncap * sizeof(*ni));

		if (!ni)
			return -1;
		c->items = ni;
		c->cap = ncap;
	}
	c->items[c->n++] = v;
	return 0;
}

static int seed_load(const char *path, struct seed_ctx *c, char *err,
		     size_t errlen)
{
	FILE *f = fopen(path, "rb");
	char *buf = NULL;
	long sz;
	size_t len, pos = 0;
	size_t lineno = 0;

	if (!f) {
		snprintf(err, errlen, "open %s failed", path);
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
	    fseek(f, 0, SEEK_SET) != 0) {
		snprintf(err, errlen, "stat %s failed", path);
		fclose(f);
		return -1;
	}
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		snprintf(err, errlen, "out of memory");
		fclose(f);
		return -1;
	}
	len = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[len] = '\0';

	while (pos < len) {
		size_t end = pos;
		char perr[256];
		aik_json *v;

		while (end < len && buf[end] != '\n')
			end++;
		lineno++;
		{
			size_t b = pos, e = end;

			while (b < e && (buf[b] == ' ' || buf[b] == '\t' ||
					 buf[b] == '\r'))
				b++;
			while (e > b && (buf[e - 1] == ' ' ||
					 buf[e - 1] == '\t' ||
					 buf[e - 1] == '\r'))
				e--;
			if (b == e) {
				pos = end + 1;
				continue;
			}
			v = aik_json_parse(buf + b, e - b, perr,
					   sizeof(perr));
			if (!v) {
				snprintf(err, errlen, "%s:%zu: %s", path,
					 lineno, perr);
				free(buf);
				return -1;
			}
		}
		if (seed_push(c, v) != 0) {
			snprintf(err, errlen, "out of memory");
			aik_json_free(v);
			free(buf);
			return -1;
		}
		pos = end + 1;
	}
	free(buf);
	return 0;
}

static void seed_free(struct seed_ctx *c)
{
	size_t i;

	for (i = 0; i < c->n; i++)
		aik_json_free(c->items[i]);
	free(c->items);
	c->items = NULL;
	c->n = c->cap = 0;
}

/* 内部 GET /export：取现有记忆 text 集合（动态 char* 数组） */
static int collect_texts(aik_http_server *s, char ***out, size_t *outn,
			 char *err, size_t errlen)
{
	aik_http_request req;
	aik_http_response resp;
	aik_json *dom = NULL;
	const aik_json *mems;
	char **texts = NULL;
	size_t n = 0, cap = 0, i;
	int rc = -1;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	req.method = "GET";
	req.path = "/export";
	req.query = "";
	req.body = "";
	req.body_len = 0;
	req.content_type = "application/json";

	aik_http_route_export(s, &req, &resp);
	if (resp.status != 200) {
		snprintf(err, errlen, "internal /export -> %d", resp.status);
		goto out;
	}
	dom = aik_json_parse(resp.body, resp.body_len, err, errlen);
	if (!dom)
		goto out;
	mems = aik_json_get(dom, "memories");
	if (mems && aik_json_typeof(mems) == AIK_JSON_ARR) {
		size_t cnt = aik_json_count(mems);

		for (i = 0; i < cnt; i++) {
			const aik_json *m = aik_json_at(mems, i);
			const aik_json *t = aik_json_get(m, "text");
			const char *sv = aik_json_str(t);

			if (n == cap) {
				size_t ncap = cap ? cap * 2 : 64;
				char **nt = realloc(texts,
						    ncap * sizeof(*nt));

				if (!nt) {
					snprintf(err, errlen,
						 "out of memory");
					goto out;
				}
				texts = nt;
				cap = ncap;
			}
			texts[n] = strdup(sv ? sv : "");
			if (!texts[n]) {
				snprintf(err, errlen, "out of memory");
				goto out;
			}
			n++;
		}
	}
	*out = texts;
	*outn = n;
	texts = NULL;
	n = 0;
	rc = 0;
out:
	for (i = 0; i < n; i++)
		free(texts[i]);
	free(texts);
	aik_json_free(dom);
	aik_http_response_free(&resp);
	return rc;
}

static int text_known(char **texts, size_t n, const char *t)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (strcmp(texts[i], t) == 0)
			return 1;
	return 0;
}

int aik_seed_import(aik_http_server *s, const char *path, char *err,
		    size_t errlen)
{
	struct seed_ctx c;
	char **texts = NULL;
	size_t ntexts = 0, i, missing = 0;
	int rc = -1;

	memset(&c, 0, sizeof(c));
	if (seed_load(path, &c, err, errlen) != 0)
		goto out;
	if (collect_texts(s, &texts, &ntexts, err, errlen) != 0)
		goto out;

	{
		aik_json *arr = aik_json_new_arr();

		if (!arr) {
			snprintf(err, errlen, "out of memory");
			goto out;
		}
		for (i = 0; i < c.n; i++) {
			const aik_json *t = aik_json_get(c.items[i], "text");
			const char *sv = aik_json_str(t);

			/*
			 * 对齐 heredoc `m.get("text") not in have`：
			 * text 缺失/非串（Python None）永不可命中 → 归入
			 * 差集（随后 batch 校验会以 422 显式失败）。
			 */
			if (sv && text_known(texts, ntexts, sv))
				continue;
			missing++;
			if (aik_json_arr_push(arr, c.items[i]) != 0) {
				aik_json_free(arr);
				snprintf(err, errlen, "out of memory");
				goto out;
			}
			c.items[i] = NULL;	/* 所有权移交 arr */
		}
		printf("[aikd-seed] seed=%zu existing=%zu missing=%zu\n",
		       c.n, ntexts, missing);
		if (missing > 0) {
			aik_json *obj = aik_json_new_obj();
			char *body = NULL;
			size_t body_len = 0;

			if (!obj ||
			    aik_json_obj_put(obj, "memories", arr) != 0) {
				aik_json_free(obj);
				aik_json_free(arr);
				snprintf(err, errlen, "out of memory");
				goto out;
			}
			arr = NULL;		/* 所有权移交 obj */
			if (aik_json_dump(obj, &body, &body_len) != 0) {
				aik_json_free(obj);
				snprintf(err, errlen, "dump failed");
				goto out;
			}
			aik_json_free(obj);
			{
				aik_http_request req;
				aik_http_response resp;

				memset(&req, 0, sizeof(req));
				memset(&resp, 0, sizeof(resp));
				req.method = "POST";
				req.path = "/memories/batch";
				req.query = "";
				req.content_type = "application/json";
				req.body = body;
				req.body_len = body_len;

				aik_http_route_add_batch(s, &req, &resp);
				if (resp.status != 200) {
					snprintf(err, errlen,
						 "internal /memories/batch -> %d: %s",
						 resp.status,
						 resp.body ? resp.body : "");
					aik_http_response_free(&resp);
					free(body);
					goto out;
				}
				printf("[aikd-seed] batch resp: %s\n",
				       resp.body ? resp.body : "");
				aik_http_response_free(&resp);
			}
			free(body);
		} else {
			aik_json_free(arr);
			printf("[aikd-seed] corpus already complete, skip\n");
		}
	}
	rc = 0;
out:
	for (i = 0; i < ntexts; i++)
		free(texts[i]);
	free(texts);
	seed_free(&c);
	return rc;
}
