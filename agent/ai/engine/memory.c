/* SPDX-License-Identifier: GPL-2.0 */
/*
 * memory.c - T4a Memory 记录：DOM 深拷贝、空白判定、Memory.to_dict
 *
 * 对齐 REF-PY e72bc75 `sme/models.py::Memory.to_dict/from_dict` 与
 * `sme/memory_manager.py::add_memory` 的字段语义。本文件只做纯数据操作，
 * 不触碰 space/retrieval/配置。
 *
 * 内部符号（aik_engine__dup / aik_json__clone / aik_text__is_blank /
 * aik_memory__new / aik_memory__free / aik_json__str_array /
 * aik_str_array_free）不属于 engine.h 的公开契约，由 engine.c 以 extern
 * 声明复用；它们不承诺 ABI 稳定。
 */
#include "../include/engine/engine.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 基础工具                                                           */
/* ------------------------------------------------------------------ */
char *aik_engine__dup(const char *s)
{
	size_t n;
	char *p;

	if (!s)
		return NULL;
	n = strlen(s) + 1;
	p = malloc(n);
	if (p)
		memcpy(p, s, n);
	return p;
}

/*
 * aik_json__clone - 深拷贝一个 DOM 子树
 *
 * 对象保持键插入序（重复键按 aik_json_obj_put 原样保留），数组保持顺序；
 * 标量复制值。失败返回 NULL（不返回半成品）。
 */
aik_json *aik_json__clone(const aik_json *v)
{
	aik_json *out;
	size_t i;
	size_t n;

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
			aik_json *item = aik_json__clone(aik_json_at(v, i));

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
			aik_json *item = aik_json__clone(aik_json_val_at(v, i));

			if (!key || !item ||
			    aik_json_obj_put(out, key, item) != 0) {
				aik_json_free(item);
				aik_json_free(out);
				return NULL;
			}
		}
		return out;
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Unicode 空白判定（Python str.strip() / str.isspace()）             */
/* ------------------------------------------------------------------ */
static int cp_is_space(unsigned int cp)
{
	if (cp >= 0x09 && cp <= 0x0d)
		return 1;
	if (cp >= 0x1c && cp <= 0x20)
		return 1;
	switch (cp) {
	case 0x85:
	case 0xa0:
	case 0x1680:
	case 0x2028:
	case 0x2029:
	case 0x202f:
	case 0x205f:
	case 0x3000:
		return 1;
	default:
		return cp >= 0x2000 && cp <= 0x200a;
	}
}

/*
 * 解码一个 UTF-8 码点：成功返回字节数并写 *cp；非法序列返回 -1。
 * 拒绝过长编码、代理区与 > U+10FFFF。
 */
static int utf8_next(const unsigned char *p, unsigned int *cp)
{
	unsigned int c = p[0];
	int len;
	int i;

	if (c < 0x80) {
		*cp = c;
		return 1;
	}
	if ((c & 0xe0) == 0xc0) {
		*cp = c & 0x1fu;
		len = 2;
	} else if ((c & 0xf0) == 0xe0) {
		*cp = c & 0x0fu;
		len = 3;
	} else if ((c & 0xf8) == 0xf0) {
		*cp = c & 0x07u;
		len = 4;
	} else {
		return -1;
	}
	for (i = 1; i < len; i++) {
		if ((p[i] & 0xc0) != 0x80)
			return -1;
		*cp = (*cp << 6) | (p[i] & 0x3fu);
	}
	if ((len == 2 && *cp < 0x80) || (len == 3 && *cp < 0x800) ||
	    (len == 4 && *cp < 0x10000))
		return -1;
	if (*cp >= 0xd800 && *cp <= 0xdfff)
		return -1;
	if (*cp > 0x10ffff)
		return -1;
	return len;
}

/*
 * aik_text__is_blank - NULL/空/Unicode 全空白 → 1
 *
 * 非法 UTF-8 视为非空白（fail open：只拒绝确定可判定的空白串）。
 */
int aik_text__is_blank(const char *utf8)
{
	const unsigned char *p = (const unsigned char *)(utf8 ? utf8 : "");

	if (!*p)
		return 1;
	while (*p) {
		unsigned int cp = 0;
		int len = utf8_next(p, &cp);

		if (len < 0 || !cp_is_space(cp))
			return 0;
		p += len;
	}
	return 1;
}

/* ------------------------------------------------------------------ */
/* 字符串数组                                                         */
/* ------------------------------------------------------------------ */
void aik_str_array_free(char **arr, size_t n)
{
	size_t i;

	if (!arr)
		return;
	for (i = 0; i < n; i++)
		free(arr[i]);
	free(arr);
}

/*
 * aik_json__str_array - 把 STR 数组深拷贝为 char* 数组
 *
 * 非数组或非字符串元素按 Python list(...) 的宽松口径跳过（保留顺序）。
 * 成功 0（*out 可为 NULL、*n_out=0）；OOM 返回 -1。
 */
int aik_json__str_array(const aik_json *arr, char ***out, size_t *n_out)
{
	char **items = NULL;
	size_t n = 0;
	size_t cap = 0;
	size_t i;

	*out = NULL;
	*n_out = 0;
	if (aik_json_typeof(arr) != AIK_JSON_ARR)
		return 0;
	for (i = 0; i < aik_json_count(arr); i++) {
		const char *s = aik_json_str(aik_json_at(arr, i));
		char *copy;

		if (!s)
			continue;
		if (n == cap) {
			size_t next = cap ? cap * 2 : 8;
			char **grown = realloc(items, next * sizeof(*grown));

			if (!grown) {
				aik_str_array_free(items, n);
				return -1;
			}
			items = grown;
			cap = next;
		}
		copy = aik_engine__dup(s);
		if (!copy) {
			aik_str_array_free(items, n);
			return -1;
		}
		items[n++] = copy;
	}
	*out = items;
	*n_out = n;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Memory 构造/释放                                                   */
/* ------------------------------------------------------------------ */
void aik_memory__free(aik_memory *m);

aik_memory *aik_memory__new(void)
{
	aik_memory *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;
	m->metadata = aik_json_new_obj();
	m->source = aik_engine__dup("user");
	if (!m->metadata || !m->source) {
		aik_memory__free(m);
		return NULL;
	}
	m->weight = 1.0;
	m->importance = 0.5;
	m->freshness = 1.0;
	m->decay_factor = 1.0;
	m->version = 1;
	return m;
}

void aik_memory__free(aik_memory *m)
{
	if (!m)
		return;
	free(m->id);
	free(m->text);
	aik_json_free(m->metadata);
	free(m->region_id);
	aik_str_array_free(m->neighbors, m->n_neighbors);
	aik_str_array_free(m->tags, m->n_tags);
	free(m->summary);
	free(m->parent_id);
	aik_str_array_free(m->children, m->n_children);
	free(m->source);
	free(m->embedding);
	free(m);
}

/* ------------------------------------------------------------------ */
/* Memory.to_dict                                                     */
/* ------------------------------------------------------------------ */
static int put(aik_json *obj, const char *key, aik_json *v)
{
	if (!v)
		return -1;
	if (aik_json_obj_put(obj, key, v) != 0) {
		aik_json_free(v);
		return -1;
	}
	return 0;
}

static int cmp_cstr(const void *a, const void *b)
{
	const char *const *x = a;
	const char *const *y = b;

	return strcmp(*x, *y);
}

static aik_json *str_array_json(char *const *items, size_t n, int sorted)
{
	aik_json *arr = aik_json_new_arr();
	const char **order = NULL;
	size_t i;

	if (!arr)
		return NULL;
	if (sorted && n > 1) {
		order = malloc(n * sizeof(*order));
		if (!order) {
			aik_json_free(arr);
			return NULL;
		}
		for (i = 0; i < n; i++)
			order[i] = items[i];
		qsort(order, n, sizeof(*order), cmp_cstr);
	}
	for (i = 0; i < n; i++) {
		const char *s = sorted && order ? order[i] : items[i];
		aik_json *v = aik_json_new_str(s ? s : "");

		if (!v || aik_json_arr_push(arr, v) != 0) {
			aik_json_free(v);
			free(order);
			aik_json_free(arr);
			return NULL;
		}
	}
	free(order);
	return arr;
}

static aik_json *str_or_null(const char *s)
{
	return s ? aik_json_new_str(s) : aik_json_new_null();
}

aik_json *aik_memory_to_json(const aik_memory *m, int include_embedding)
{
	aik_json *d;
	aik_json *arr;
	size_t i;

	if (!m)
		return NULL;
	d = aik_json_new_obj();
	if (!d)
		return NULL;
	if (put(d, "id", aik_json_new_str(m->id ? m->id : "")) != 0 ||
	    put(d, "text", aik_json_new_str(m->text ? m->text : "")) != 0)
		goto fail;
	arr = m->metadata ? aik_json__clone(m->metadata) : aik_json_new_obj();
	if (put(d, "metadata", arr) != 0)
		goto fail;
	if (put(d, "created_at", aik_json_new_num(m->created_at)) != 0 ||
	    put(d, "last_hit", aik_json_new_num(m->last_hit)) != 0 ||
	    put(d, "hit_count", aik_json_new_int(m->hit_count)) != 0 ||
	    put(d, "weight", aik_json_new_num(m->weight)) != 0 ||
	    put(d, "importance", aik_json_new_num(m->importance)) != 0 ||
	    put(d, "freshness", aik_json_new_num(m->freshness)) != 0 ||
	    put(d, "decay_factor", aik_json_new_num(m->decay_factor)) != 0 ||
	    put(d, "region_id", str_or_null(m->region_id)) != 0)
		goto fail;
	arr = str_array_json(m->neighbors, m->n_neighbors, 1);
	if (put(d, "neighbors", arr) != 0)
		goto fail;
	arr = str_array_json(m->tags, m->n_tags, 0);
	if (put(d, "tags", arr) != 0)
		goto fail;
	if (put(d, "summary", str_or_null(m->summary)) != 0 ||
	    put(d, "version", aik_json_new_int(m->version)) != 0 ||
	    put(d, "parent_id", str_or_null(m->parent_id)) != 0)
		goto fail;
	arr = str_array_json(m->children, m->n_children, 0);
	if (put(d, "children", arr) != 0)
		goto fail;
	if (put(d, "archived", aik_json_new_bool(m->archived ? 1 : 0)) != 0 ||
	    put(d, "source", aik_json_new_str(m->source ? m->source : "user")) !=
		    0)
		goto fail;
	if (include_embedding && m->embedding && m->dim > 0) {
		arr = aik_json_new_arr();
		if (!arr)
			goto fail;
		for (i = 0; i < (size_t)m->dim; i++) {
			aik_json *v = aik_json_new_num(m->embedding[i]);

			if (!v || aik_json_arr_push(arr, v) != 0) {
				aik_json_free(v);
				goto fail_arr;
			}
		}
		if (put(d, "embedding", arr) != 0)
			goto fail;
	}
	return d;

fail_arr:
	aik_json_free(arr);
fail:
	aik_json_free(d);
	return NULL;
}
