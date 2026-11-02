/* SPDX-License-Identifier: GPL-2.0 */
/*
 * config.c - T4a SME 配置中心（默认值 + JSON 覆盖 + 显式键）
 *
 * 语义逐条对齐 REF-PY e72bc75 `sme/config.py`：
 *   - `aik_config_defaults` = 生成文件 config_default.h 的 JSON 解析结果；
 *   - `SMEConfig.from_dict` 只对已知 section 的已知字段 setattr（hasattr
 *     守卫），并把 `"<section>.<key>"` 记入 `_explicit_keys`；未知 section/
 *     key 静默忽略，`seed` 单独处理且**从不**显式；
 *   - 覆盖直接替换默认 DOM 中的节点，因此键序保持 Python to_dict() 的
 *     插入序（seed 第一），覆盖不会换位；
 *   - 值按输入 JSON 类型原样保存（Python 不做类型转换），字符串/数组原样
 *     保留，嵌套对象深拷贝，调用方随后修改输入 DOM 不会影响配置。
 *
 * 本文件零第三方依赖，C11，构建串行（见 Makefile）。
 */
#include "../include/smeconfig/config.h"

#include "config_default.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 已知 section / key 白名单（= dataclass 字段序，便于与 Python 对照）  */
/* ------------------------------------------------------------------ */
typedef struct {
	const char *name;
	const char *keys;	/* 逗号分隔，无空格 */
} section_def;

static const section_def SECTIONS[] = {
	{ "embedding",
	  "provider,model,dim,base_url,api_key,batch_size,normalize,"
	  "hash_factors,hash_window,revision,mrl_dim,hash_seed,revision_stamp,"
	  "query_prefix" },
	{ "region",
	  "min_region_size,min_join_cosine,split_threshold,max_density,"
	  "merge_distance,neighbor_factor,auto_evolve,evolve_interval,"
	  "ann_enabled,ann_min_regions" },
	{ "retrieval",
	  "top_regions,region_options,top_k,vector_weight,keyword_weight,"
	  "metadata_weight,region_dampening,summary_penalty,cjk_bigram,"
	  "candidate_window,fusion,keyword_candidates,min_similarity,"
	  "query_cache_size" },
	{ "ranking",
	  "semantic,importance,freshness,weight,decay,hit_count,recency,region" },
	{ "policy", "full_memory,importance_threshold,decay_enabled" },
	{ "reinforcement",
	  "hit_weight_delta,hit_importance_delta,max_weight,max_importance,"
	  "min_importance,ebbinghaus_half_life_days,ebbinghaus_power" },
	{ "decay", "half_life_days,max_weight_decay,max_importance_decay" },
	{ "consolidation",
	  "similarity_threshold,min_group_size,max_group_size,summary_source" },
	{ "compression",
	  "age_days_threshold,min_region_compact,summary_source" },
	{ "llm",
	  "base_url,api_key,model,timeout,temperature,max_tokens,"
	  "reasoning_effort,extra_headers" },
	{ "storage", "path,autosave,autosave_interval,compress,backend" },
	{ "maintenance", "background,idle_after_s,every_s" },
	{ "visualization",
	  "projection,figure_size,dpi,color_map,show_graph" },
	{ "extraction",
	  "enabled,mode,store_assistant,dedup_threshold,fallback_rules" },
	{ "factversion",
	  "enabled,correct_markers,stale_penalty,dedup_threshold,"
	  "correction_threshold" },
	{ "noise",
	  "enabled,dup_penalty,template_penalty,min_density,ngram_window,"
	  "dup_window" },
	{ "qapair",
	  "enabled,max_age_days,answer_top_k,similarity_threshold" },
	{ "factgraph",
	  "enabled,extract_mode,max_depth,hop_decay,max_entities" },
	{ "profile", "enabled,snapshot_every,top_facts,boost_weight" },
	{ "persistence",
	  "enabled,wal_path,checkpoint_every,sync_mode,group_window_ms" },
	{ "api", "host,port,auth_token" },
	{ "observability", "enabled,sample_rate,max_events" },
	{ "context", "enabled,budget_tokens,reserve_profile,recent_rounds" },
	{ "namespaces", "enabled,default_ns" },
	{ "rerank", "enabled,model,top_n" },
};

#define N_SECTIONS (sizeof(SECTIONS) / sizeof(SECTIONS[0]))

struct aik_config {
	aik_json *dom;		/* 自有，SMEConfig.to_dict 形状 */
	char **explicit;	/* 自有字符串，"section.key" */
	size_t n_explicit;
	size_t cap_explicit;
};

/* ------------------------------------------------------------------ */
/* 小工具                                                             */
/* ------------------------------------------------------------------ */
static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* 逗号分隔白名单的精确匹配（key 可含任意字符，按长度比较） */
static int key_known(const char *keys, const char *key)
{
	const char *p = keys;
	size_t klen = strlen(key);

	while (*p) {
		const char *comma = strchr(p, ',');
		size_t len = comma ? (size_t)(comma - p) : strlen(p);

		if (len == klen && memcmp(p, key, len) == 0)
			return 1;
		if (!comma)
			break;
		p = comma + 1;
	}
	return 0;
}

static aik_json *obj_child(aik_json *dom, const char *name)
{
	const aik_json *v = aik_json_get(dom, name);

	if (!v || aik_json_typeof(v) != AIK_JSON_OBJ)
		return NULL;
	return (aik_json *)v;
}

static aik_json *json_clone(const aik_json *v)
{
	aik_json *out;
	size_t i, n;

	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return aik_json_new_null();
	case AIK_JSON_BOOL:
		return aik_json_new_bool(aik_json_bool(v));
	case AIK_JSON_INT:
		return aik_json_new_int(aik_json_int(v));
	case AIK_JSON_NUM:
		return aik_json_new_num(aik_json_num(v));
	case AIK_JSON_STR:
		return aik_json_new_str(aik_json_str(v));
	case AIK_JSON_ARR:
		out = aik_json_new_arr();
		if (!out)
			return NULL;
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			aik_json *item = json_clone(aik_json_at(v, i));

			if (!item || aik_json_arr_push(out, item) != 0) {
				aik_json_free(item);
				aik_json_free(out);
				return NULL;
			}
		}
		return out;
	case AIK_JSON_OBJ:
		out = aik_json_new_obj();
		if (!out)
			return NULL;
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			const char *key = aik_json_key_at(v, i);
			aik_json *item = json_clone(aik_json_val_at(v, i));

			if (!key || !item || aik_json_obj_put(out, key, item) != 0) {
				aik_json_free(item);
				aik_json_free(out);
				return NULL;
			}
		}
		return out;
	}
	return NULL;	/* 不可达：aik_json_type 已穷举 */
}

static int explicit_add(aik_config *c, const char *section, const char *key)
{
	size_t sl = strlen(section);
	size_t kl = strlen(key);
	char *dotted;

	if (c->n_explicit == c->cap_explicit) {
		size_t cap = c->cap_explicit ? c->cap_explicit * 2 : 16;
		char **grown = realloc(c->explicit, cap * sizeof(*grown));

		if (!grown)
			return -1;
		c->explicit = grown;
		c->cap_explicit = cap;
	}
	dotted = malloc(sl + 1 + kl + 1);
	if (!dotted)
		return -1;
	memcpy(dotted, section, sl);
	dotted[sl] = '.';
	memcpy(dotted + sl + 1, key, kl);
	dotted[sl + 1 + kl] = '\0';
	c->explicit[c->n_explicit++] = dotted;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 构造                                                               */
/* ------------------------------------------------------------------ */
aik_config *aik_config_defaults(char *err, size_t errlen)
{
	aik_config *c;
	aik_json *dom;

	if (err && errlen)
		err[0] = '\0';
	dom = aik_json_parse(AIK_CONFIG_DEFAULT_JSON,
			     sizeof(AIK_CONFIG_DEFAULT_JSON) - 1, err, errlen);
	if (!dom) {
		if (!err || errlen == 0 || !err[0])
			set_err(err, errlen, "config: 内置默认配置解析失败");
		return NULL;
	}
	c = calloc(1, sizeof(*c));
	if (!c) {
		aik_json_free(dom);
		set_err(err, errlen, "config: 内存不足");
		return NULL;
	}
	c->dom = dom;
	return c;
}

/* 把 src（已确认为对象）里的已知 section.key 覆盖到 c */
static int overlay_section(aik_config *c, const section_def *def,
			   const aik_json *src)
{
	aik_json *dst = obj_child(c->dom, def->name);
	size_t i, n;

	if (!dst)		/* 内置默认缺该 section：不应发生，按忽略处理 */
		return 0;
	n = aik_json_count(src);
	for (i = 0; i < n; i++) {
		const char *key = aik_json_key_at(src, i);
		const aik_json *val = aik_json_val_at(src, i);
		aik_json *copy;

		if (!key || !val)
			continue;
		if (!key_known(def->keys, key))
			continue;	/* hasattr 守卫：未知键忽略 */
		copy = json_clone(val);
		if (!copy)
			return -1;
		if (aik_json_obj_set(dst, key, copy) != 0) {
			aik_json_free(copy);
			return -1;
		}
		if (explicit_add(c, def->name, key) != 0)
			return -1;
	}
	return 0;
}

aik_config *aik_config_from_json(const aik_json *root, char *err,
				 size_t errlen)
{
	aik_config *c;
	const aik_json *base, *seed;
	size_t i;

	if (err && errlen)
		err[0] = '\0';
	c = aik_config_defaults(err, errlen);
	if (!c)
		return NULL;
	/* 非对象输入没有可覆盖的键（Python from_dict 亦要求 dict） */
	if (!root || aik_json_typeof(root) != AIK_JSON_OBJ)
		return c;
	/* {"sme": {...}} 包装；包装键存在但不是对象时按无覆盖处理 */
	base = aik_json_get(root, "sme");
	if (!base || aik_json_typeof(base) != AIK_JSON_OBJ)
		base = root;

	seed = aik_json_get(base, "seed");
	if (seed) {
		aik_json *copy = json_clone(seed);

		/* seed 是标量字段：覆盖生效，但 Python 不写 _explicit_keys */
		if (!copy || aik_json_obj_set(c->dom, "seed", copy) != 0) {
			aik_json_free(copy);
			goto oom;
		}
	}
	for (i = 0; i < N_SECTIONS; i++) {
		const aik_json *sec = aik_json_get(base, SECTIONS[i].name);

		if (!sec || aik_json_typeof(sec) != AIK_JSON_OBJ)
			continue;
		if (overlay_section(c, &SECTIONS[i], sec) != 0)
			goto oom;
	}
	return c;

oom:
	aik_config_free(c);
	set_err(err, errlen, "config: 内存不足");
	return NULL;
}

aik_config *aik_config_load(const char *path, char *err, size_t errlen)
{
	aik_config *c;
	aik_json *dom;
	char *buf;
	size_t got;
	long len;
	FILE *f;

	if (err && errlen)
		err[0] = '\0';
	if (!path || !*path) {
		set_err(err, errlen, "config: 路径为空");
		return NULL;
	}
	f = fopen(path, "rb");
	if (!f) {
		set_err(err, errlen, "config: 无法打开 %s: %s", path,
			strerror(errno));
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0 ||
	    fseek(f, 0, SEEK_SET) != 0) {
		set_err(err, errlen, "config: 无法读取 %s", path);
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)len + 1);
	if (!buf) {
		set_err(err, errlen, "config: 内存不足");
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, (size_t)len, f);
	fclose(f);
	if (got != (size_t)len) {
		set_err(err, errlen, "config: 短读 %s", path);
		free(buf);
		return NULL;
	}
	buf[len] = '\0';
	dom = aik_json_parse(buf, (size_t)len, err, errlen);
	free(buf);
	if (!dom)
		return NULL;
	c = aik_config_from_json(dom, err, errlen);
	aik_json_free(dom);
	return c;
}

/* ------------------------------------------------------------------ */
/* 只读访问                                                           */
/* ------------------------------------------------------------------ */
const aik_json *aik_config_dom(const aik_config *c)
{
	return c ? c->dom : NULL;
}

int aik_config_is_explicit(const aik_config *c, const char *dotted)
{
	size_t i;

	if (!c || !dotted)
		return 0;
	for (i = 0; i < c->n_explicit; i++)
		if (strcmp(c->explicit[i], dotted) == 0)
			return 1;
	return 0;
}

/* dotted path 解析：逐段走 OBJ；缺失/类型不符返回 NULL */
static const aik_json *resolve(const aik_config *c, const char *dotted)
{
	const aik_json *cur;
	const char *p;

	if (!c || !c->dom || !dotted || !*dotted)
		return NULL;
	cur = c->dom;
	p = dotted;
	for (;;) {
		const char *dot = strchr(p, '.');
		size_t len = dot ? (size_t)(dot - p) : strlen(p);
		const aik_json *hit;
		char *key;

		if (len == 0)
			return NULL;
		key = malloc(len + 1);
		if (!key)
			return NULL;
		memcpy(key, p, len);
		key[len] = '\0';
		hit = aik_json_get(cur, key);
		free(key);
		if (!hit)
			return NULL;
		cur = hit;
		if (!dot)
			break;
		p = dot + 1;
	}
	return cur;
}

int aik_config_get_i64(const aik_config *c, const char *dotted, long long *out)
{
	const aik_json *v = resolve(c, dotted);

	if (!v)
		return -1;
	if (aik_json_typeof(v) == AIK_JSON_INT) {
		if (out)
			*out = aik_json_int(v);
		return 0;
	}
	if (aik_json_typeof(v) == AIK_JSON_NUM) {
		double d = aik_json_num(v);
		long long ll;

		/* JSON 里 10.0 与 10 同义：仅整数值接受 */
		if (!(d >= -9.223372036854775e18 && d <= 9.223372036854775e18))
			return -1;
		ll = (long long)d;
		if ((double)ll != d)
			return -1;
		if (out)
			*out = ll;
		return 0;
	}
	return -1;
}

int aik_config_get_num(const aik_config *c, const char *dotted, double *out)
{
	const aik_json *v = resolve(c, dotted);

	if (!v)
		return -1;
	if (aik_json_typeof(v) == AIK_JSON_NUM) {
		if (out)
			*out = aik_json_num(v);
		return 0;
	}
	if (aik_json_typeof(v) == AIK_JSON_INT) {
		if (out)
			*out = (double)aik_json_int(v);
		return 0;
	}
	return -1;
}

int aik_config_get_bool(const aik_config *c, const char *dotted, int *out)
{
	const aik_json *v = resolve(c, dotted);

	if (!v || aik_json_typeof(v) != AIK_JSON_BOOL)
		return -1;
	if (out)
		*out = aik_json_bool(v);
	return 0;
}

const char *aik_config_get_str(const aik_config *c, const char *dotted)
{
	const aik_json *v = resolve(c, dotted);

	if (!v || aik_json_typeof(v) != AIK_JSON_STR)
		return NULL;
	return aik_json_str(v);
}

/* 深拷贝在文件中已有 json_clone（obj_child 之后） */

int aik_config_set_dotted(aik_config *c, const char *dotted,
			  const aik_json *value)
{
	char *path;
	char *part;
	char *dot;
	aik_json *cur;
	size_t plen;

	if (!c || !dotted || !*dotted || !value)
		return -1;
	plen = strlen(dotted);
	path = malloc(plen + 1);
	if (!path)
		return -1;
	memcpy(path, dotted, plen + 1);
	cur = c->dom;
	part = path;
	while ((dot = strchr(part, '.')) != NULL) {
		aik_json *next;

		*dot = '\0';
		next = (aik_json *)aik_json_get(cur, part);
		if (!next || aik_json_typeof(next) != AIK_JSON_OBJ) {
			next = aik_json_new_obj();

			if (!next ||
			    aik_json_obj_set(cur, part, next) != 0) {
				aik_json_free(next);
				free(path);
				return -1;
			}
		}
		cur = next;
		part = dot + 1;
	}
	if (*part) {
		aik_json *copy = json_clone(value);

		if (!copy || aik_json_obj_set(cur, part, copy) != 0) {
			aik_json_free(copy);
			free(path);
			return -1;
		}
	}
	free(path);
	return 0;
}

void aik_config_free(aik_config *c)
{
	size_t i;

	if (!c)
		return;
	for (i = 0; i < c->n_explicit; i++)
		free(c->explicit[i]);
	free(c->explicit);
	aik_json_free(c->dom);
	free(c);
}
