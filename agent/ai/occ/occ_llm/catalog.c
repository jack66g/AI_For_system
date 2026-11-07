/* SPDX-License-Identifier: GPL-2.0 */
/*
 * catalog.c - models.dev 目录快照解析与查询（T9a2）
 *
 * 快照格式（occ-catalog-snapshot/1，裁剪器 /tmp/t9a2_trim_snapshot.py 产）：
 *   {"_meta":{source,fetched_utc,original_sha256,...},
 *    "providers":{"<pid>":{"name":..,"models":{"<mid>":{...}}}}}
 * 模型字段见 occ_catalog.h 结构注释；全部字段缺省容错。
 */
#include "occ_catalog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "store/store_json.h"

static char *read_file(const char *path, size_t *outlen)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long n;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 ||
	    fseek(f, 0, SEEK_SET)) {
		fclose(f);
		return NULL;
	}
	if (n <= 0) {
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	buf[n] = '\0';
	if (outlen)
		*outlen = (size_t)n;
	return buf;
}

static const char *jstr(const aik_json *obj, const char *key)
{
	const aik_json *v = aik_json_get(obj, key);

	if (v && aik_json_typeof(v) == AIK_JSON_STR)
		return aik_json_str(v);
	return NULL;
}

static long long jint(const aik_json *obj, const char *key)
{
	const aik_json *v = aik_json_get(obj, key);

	return v ? aik_json_int(v) : 0;
}

static double jnum(const aik_json *obj, const char *key)
{
	const aik_json *v = aik_json_get(obj, key);

	if (!v)
		return 0.0;
	if (aik_json_typeof(v) == AIK_JSON_NULL)
		return 0.0;
	return aik_json_num(v);
}

static int jbool(const aik_json *obj, const char *key)
{
	const aik_json *v = aik_json_get(obj, key);

	if (!v || aik_json_typeof(v) == AIK_JSON_NULL)
		return 0;
	return aik_json_bool(v);
}

static int cat_push(occ_catalog *c, const occ_catalog_model *m)
{
	if (c->nmodels == c->cap) {
		size_t nc = c->cap ? c->cap * 2 : 256;
		occ_catalog_model *nm = realloc(c->models,
			nc * sizeof(*nm));
		if (!nm)
			return -1;
		c->models = nm;
		c->cap = nc;
	}
	c->models[c->nmodels++] = *m;
	return 0;
}

/* 一条模型 JSON → occ_catalog_model；id 缺失/为空返回 -1（跳过） */
static int parse_model(occ_catalog_model *m, const char *pid,
		       const char *pname, const aik_json *mj)
{
	const char *s;

	memset(m, 0, sizeof(*m));
	s = jstr(mj, "id");
	if (!s || !*s)
		return -1;
	snprintf(m->id, sizeof(m->id), "%s", s);
	s = jstr(mj, "canonical_id");
	if (s)
		snprintf(m->canonical_id, sizeof(m->canonical_id), "%s", s);
	else	/* 缺省别名=厂商/模型 全名（models.dev 惯例） */
		snprintf(m->canonical_id, sizeof(m->canonical_id),
			 "%s/%s", pid, m->id);
	s = jstr(mj, "name");
	if (s && *s)
		snprintf(m->name, sizeof(m->name), "%s", s);
	else
		snprintf(m->name, sizeof(m->name), "%s", m->id);
	snprintf(m->provider, sizeof(m->provider), "%s", pid);
	if (pname && *pname)
		snprintf(m->provider_name, sizeof(m->provider_name),
			 "%s", pname);
	else
		snprintf(m->provider_name, sizeof(m->provider_name),
			 "%s", pid);
	s = jstr(mj, "type");
	m->is_chat = (s && !strcmp(s, "chat"));
	s = jstr(mj, "status");
	m->is_deprecated = (s && !strcmp(s, "deprecated"));
	m->context_limit = jint(mj, "context_limit");
	m->max_output = jint(mj, "max_output");
	m->cost_input_per_m = jnum(mj, "cost_input_per_m");
	m->cost_output_per_m = jnum(mj, "cost_output_per_m");
	m->cost_cache_read = jnum(mj, "cost_cache_read");
	m->cost_cache_write = jnum(mj, "cost_cache_write");
	m->tools = jbool(mj, "tools");
	m->reasoning = jbool(mj, "reasoning");
	return 0;
}

int occ_catalog_load(occ_catalog *c, const char *json_path)
{
	char *txt;
	size_t txtlen;
	char perr[96];
	aik_json *root;
	const aik_json *providers, *meta;
	size_t i;

	if (!c || !json_path)
		return -1;
	memset(c, 0, sizeof(*c));
	txt = read_file(json_path, &txtlen);
	if (!txt)
		return -1;
	root = aik_json_parse(txt, txtlen, perr, sizeof(perr));
	free(txt);
	if (!root)
		return -1;
	if (aik_json_typeof(root) != AIK_JSON_OBJ) {
		aik_json_free(root);
		return -1;
	}

	meta = aik_json_get(root, "_meta");
	if (meta && aik_json_typeof(meta) == AIK_JSON_OBJ) {
		const char *s = jstr(meta, "source");
		if (s)
			snprintf(c->source, sizeof(c->source), "%s", s);
		s = jstr(meta, "fetched_utc");
		if (s)
			snprintf(c->fetched_utc, sizeof(c->fetched_utc),
				 "%s", s);
		s = jstr(meta, "original_sha256");
		if (s)
			snprintf(c->original_sha256,
				 sizeof(c->original_sha256), "%s", s);
	}

	providers = aik_json_get(root, "providers");
	if (!providers || aik_json_typeof(providers) != AIK_JSON_OBJ) {
		/* 空/缺 providers：合法空目录 */
		aik_json_free(root);
		return 0;
	}
	for (i = 0; i < aik_json_count(providers); i++) {
		const char *pid = aik_json_key_at(providers, i);
		const aik_json *pv = aik_json_val_at(providers, i);
		const aik_json *pmodels, *pname;
		const char *pdisp = NULL;
		size_t j;

		if (!pid || !pv || aik_json_typeof(pv) != AIK_JSON_OBJ)
			continue;
		pname = aik_json_get(pv, "name");
		if (pname && aik_json_typeof(pname) == AIK_JSON_STR)
			pdisp = aik_json_str(pname);
		pmodels = aik_json_get(pv, "models");
		if (!pmodels || aik_json_typeof(pmodels) != AIK_JSON_OBJ)
			continue;
		for (j = 0; j < aik_json_count(pmodels); j++) {
			const aik_json *mj = aik_json_val_at(pmodels, j);
			occ_catalog_model m;

			if (!mj || aik_json_typeof(mj) != AIK_JSON_OBJ) {
				c->nskipped++;
				continue;
			}
			if (parse_model(&m, pid, pdisp, mj) < 0) {
				c->nskipped++;
				continue;
			}
			if (cat_push(c, &m) < 0) {
				aik_json_free(root);
				occ_catalog_free(c);
				return -1;
			}
		}
	}
	aik_json_free(root);
	return 0;
}

void occ_catalog_free(occ_catalog *c)
{
	if (!c)
		return;
	free(c->models);
	memset(c, 0, sizeof(*c));
}

const occ_catalog_model *occ_catalog_find(const occ_catalog *c,
					  const char *provider,
					  const char *model_id)
{
	size_t i;

	if (!c || !model_id)
		return NULL;
	for (i = 0; i < c->nmodels; i++) {
		const occ_catalog_model *m = &c->models[i];

		if (strcmp(m->id, model_id) &&
		    strcmp(m->canonical_id, model_id))
			continue;
		if (provider && *provider &&
		    strcmp(m->provider, provider))
			continue;
		return m;
	}
	return NULL;
}

size_t occ_catalog_by_provider(const occ_catalog *c, const char *provider,
			       const occ_catalog_model **out, size_t outmax)
{
	size_t i, n = 0;

	if (!c)
		return 0;
	for (i = 0; i < c->nmodels; i++) {
		if (provider && *provider &&
		    strcmp(c->models[i].provider, provider))
			continue;
		if (out && n < outmax)
			out[n] = &c->models[i];
		n++;
	}
	return n;
}

/* 大小写不敏感子串（ASCII 降档——目录 id/name 实测 ASCII 为主，
 * 非 ASCII 按原字节比较） */
static int ci_contains(const char *hay, const char *needle)
{
	const char *h, *n;

	if (!needle || !*needle)
		return 1;
	if (!hay)
		return 0;
	for (h = hay; *h; h++) {
		for (n = needle;; n++) {
			if (!*n)
				return 1;
			if (!h[n - needle] ||
			    tolower((unsigned char)h[n - needle]) !=
			    tolower((unsigned char)*n))
				break;
		}
	}
	return 0;
}

size_t occ_catalog_search(const occ_catalog *c, const char *needle,
			  int include_deprecated,
			  const occ_catalog_model **out, size_t outmax)
{
	size_t i, n = 0;

	if (!c)
		return 0;
	for (i = 0; i < c->nmodels; i++) {
		const occ_catalog_model *m = &c->models[i];

		if (!include_deprecated && m->is_deprecated)
			continue;
		if (ci_contains(m->id, needle) ||
		    ci_contains(m->canonical_id, needle) ||
		    ci_contains(m->name, needle)) {
			if (out && n < outmax)
				out[n] = m;
			n++;
		}
	}
	return n;
}
