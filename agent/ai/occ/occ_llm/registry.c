/* SPDX-License-Identifier: GPL-2.0 */
/*
 * registry.c - occ 运行时注册表（T9a2）
 *
 * 见 occ_registry.h 头注释。fuzzy：小写化子串（score=命中长度的
 * 加权）+ 子序列（连续段越长分越高，间隔惩罚）——对齐 fuzzysort
 * 「连续命中优先」观感，不逐位复刻。
 */
#include "occ_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "store/store_json.h"

#define OLLAMA_BASE "http://127.0.0.1:11434/v1"

int occ_registry_init(occ_registry *reg)
{
	if (!reg)
		return -1;
	memset(reg, 0, sizeof(*reg));
	reg->models = calloc(OCC_REG_MAX, sizeof(*reg->models));
	if (!reg->models)
		return -1;
	return 0;
}

void occ_registry_free(occ_registry *reg)
{
	if (!reg)
		return;
	free(reg->models);
	memset(reg, 0, sizeof(*reg));
}

static int reg_key(char *out, size_t outlen, const char *provider,
		   const char *id)
{
	if (!out || !provider || !id)
		return -1;
	if (snprintf(out, outlen, "%s/%s", provider, id) >= (int)outlen)
		return -1;
	return 0;
}

static void reg_fill_from_catalog(occ_reg_model *m,
				  const occ_catalog_model *cm)
{
	memset(m, 0, sizeof(*m));
	snprintf(m->provider, sizeof(m->provider), "%s", cm->provider);
	snprintf(m->provider_name, sizeof(m->provider_name), "%s",
		 cm->provider_name);
	snprintf(m->id, sizeof(m->id), "%s", cm->id);
	snprintf(m->display, sizeof(m->display), "%s", cm->name);
	m->source = OCC_REG_SRC_CATALOG;
	m->proto = (cm->provider[0] &&
		    !strcmp(cm->provider, "anthropic")) ?
		OCC_PROTO_ANTHROPIC : OCC_PROTO_OPENAI_COMPAT;
	m->context_limit = cm->context_limit;
	m->tools = cm->tools;
	m->is_deprecated = cm->is_deprecated;
	m->is_chat = cm->is_chat ? 1 : 0;	/* 目录 type 位（数据正典） */
}

/* 子串（大小写不敏感；strcasestr 是 GNU 扩展，自实现对齐 overlay 手法） */
static int id_contains_ci(const char *hay, const char *needle)
{
	size_t nl = strlen(needle), hl = strlen(hay), i, j;

	if (!nl || nl > hl)
		return 0;
	for (i = 0; i + nl <= hl; i++) {
		for (j = 0; j < nl; j++)
			if (tolower((unsigned char)hay[i + j]) !=
			    tolower((unsigned char)needle[j]))
				break;
		if (j == nl)
			return 1;
	}
	return 0;
}

/*
 * OCC-DEBT：id 特征非对话判定。高置信特征表（子串、大小写不敏感）：
 * 嵌入/重排/语音合成与识别/内容审核/图像·视频生成系。宁缺勿错——
 * vision、audio、realtime、guard、ocr 等特征常见于真对话模型，一律
 * 不入表（实测快照内 vision 类 id 全部 type=="chat"）。
 */
int occ_reg_nonchat_by_id(const char *model_id)
{
	static const char *const feats[] = {
		"embed",			/* embedding/text-embedding */
		"rerank",
		"tts",
		"whisper",
		"speech",			/* speech-to-text 系 */
		"moderation",
		"dall-e", "dalle",
		"imagen",
		"sora",
		"seedream", "seedance",
		"flux",
		"stable-diffusion", "sdxl", "sd3",
		"video-generate", "video-generation",
		"transcribe",
		NULL
	};
	size_t i;

	if (!model_id || !model_id[0])
		return 0;
	for (i = 0; feats[i]; i++)
		if (id_contains_ci(model_id, feats[i]))
			return 1;
	return 0;
}

static int reg_has(const occ_registry *reg, const char *provider,
		   const char *id)
{
	size_t i;

	for (i = 0; i < reg->nmodels; i++)
		if (!strcmp(reg->models[i].provider, provider) &&
		    !strcmp(reg->models[i].id, id))
			return 1;
	return 0;
}

static int reg_push(occ_registry *reg, const occ_reg_model *m)
{
	if (reg->nmodels >= OCC_REG_MAX)
		return -1;
	reg->models[reg->nmodels++] = *m;
	return 0;
}

void occ_registry_build(occ_registry *reg, const occ_provider_config *cfg,
			const occ_catalog *catalog)
{
	size_t i;

	if (!reg || !reg->models)
		return;		/* 未 init：安全空操作 */
	/* 1. model.toml 槽位（配置即真相，先占位）；分组键 = provider
	 * 引用名（[provider.<name>]）优先，直填式退槽位名 */
	if (cfg) {
		for (i = 0; i < cfg->nslots; i++) {
			const occ_model_slot *s = &cfg->slots[i];
			const char *group = s->provider_ref[0] ?
				s->provider_ref : s->id;
			occ_reg_model m;

			memset(&m, 0, sizeof(m));
			snprintf(m.provider, sizeof(m.provider), "%s", group);
			snprintf(m.provider_name, sizeof(m.provider_name),
				 "%s", group);
			snprintf(m.id, sizeof(m.id), "%s",
				 s->model[0] ? s->model : s->id);
			snprintf(m.display, sizeof(m.display), "%s",
				 s->model[0] ? s->model : s->id);
			m.source = OCC_REG_SRC_TOML;
			m.proto = (int)s->proto != -1 ? s->proto :
				  OCC_PROTO_OPENAI_COMPAT;
			snprintf(m.base_url, sizeof(m.base_url), "%s",
				 s->base_url);
			snprintf(m.slot_id, sizeof(m.slot_id), "%s", s->id);
			/* 配置位无 type 数据：id 特征命中才标非对话，否则未知 */
			m.is_chat = occ_reg_nonchat_by_id(m.id) ? 0 : -1;
			reg_push(reg, &m);
		}
	}
	/* 2. 目录快照（配置已有的 provider+id 不重复入列） */
	if (catalog) {
		for (i = 0; i < catalog->nmodels; i++) {
			const occ_catalog_model *cm = &catalog->models[i];
			occ_reg_model m;

			if (reg_has(reg, cm->provider, cm->id))
				continue;
			reg_fill_from_catalog(&m, cm);
			reg_push(reg, &m);
		}
	}
}

size_t occ_registry_add_ollama(occ_registry *reg, const char *tags_json,
			       size_t len)
{
	char perr[96];
	aik_json *root;
	const aik_json *models;
	size_t added = 0, i;

	if (!reg || !tags_json || !len)
		return 0;
	root = aik_json_parse(tags_json, len, perr, sizeof(perr));
	if (!root)
		return 0;
	models = aik_json_get(root, "models");
	if (!models || aik_json_typeof(models) != AIK_JSON_ARR) {
		aik_json_free(root);
		return 0;
	}
	for (i = 0; i < aik_json_count(models); i++) {
		const aik_json *mj = aik_json_at(models, i);
		const aik_json *name;
		occ_reg_model m;

		if (!mj || aik_json_typeof(mj) != AIK_JSON_OBJ)
			continue;
		name = aik_json_get(mj, "name");
		if (!name || aik_json_typeof(name) != AIK_JSON_STR ||
		    !*aik_json_str(name))
			continue;
		if (reg_has(reg, "ollama", aik_json_str(name)))
			continue;
		memset(&m, 0, sizeof(m));
		snprintf(m.provider, sizeof(m.provider), "ollama");
		snprintf(m.provider_name, sizeof(m.provider_name),
			 "Ollama (local)");
		snprintf(m.id, sizeof(m.id), "%s", aik_json_str(name));
		snprintf(m.display, sizeof(m.display), "%s",
			 aik_json_str(name));
		m.source = OCC_REG_SRC_OLLAMA;
		m.proto = OCC_PROTO_OPENAI_COMPAT;
		snprintf(m.base_url, sizeof(m.base_url), "%s", OLLAMA_BASE);
		m.is_chat = occ_reg_nonchat_by_id(m.id) ? 0 : -1;
		if (reg_push(reg, &m) == 0)
			added++;
	}
	aik_json_free(root);
	return added;
}

const occ_reg_model *occ_registry_find(occ_registry *reg,
				       const char *provider,
				       const char *model_id)
{
	size_t i;

	if (!reg || !model_id)
		return NULL;
	for (i = 0; i < reg->nmodels; i++)
		if (!strcmp(reg->models[i].id, model_id) &&
		    (!provider || !*provider ||
		     !strcmp(reg->models[i].provider, provider)))
			return &reg->models[i];
	return NULL;
}

/* ---- 收藏/最近键查找 ---- */

static int key_equal(const char *provider, const char *id, const char *key)
{
	char want[OCC_REG_KEY_MAX];

	if (reg_key(want, sizeof(want), provider, id) < 0)
		return 0;
	return !strcmp(want, key);
}

/* 键串（"provider/id"）是否在收藏表（recents 过滤用） */
static int is_favorite_key(const occ_registry *reg, const char *key)
{
	size_t i;

	for (i = 0; i < reg->nfavorites; i++)
		if (!strcmp(reg->favorites[i], key))
			return 1;
	return 0;
}

size_t occ_registry_favorites(const occ_registry *reg,
			      size_t *idx, size_t idx_max)
{
	size_t i, n = 0;

	if (!reg)
		return 0;
	for (i = 0; i < reg->nfavorites && n < idx_max; i++) {
		size_t j;

		for (j = 0; j < reg->nmodels; j++)
			if (key_equal(reg->models[j].provider,
				      reg->models[j].id, reg->favorites[i])) {
				idx[n++] = j;
				break;
			}
	}
	return n;
}

size_t occ_registry_recents(const occ_registry *reg,
			    size_t *idx, size_t idx_max)
{
	size_t i, n = 0;

	if (!reg)
		return 0;
	/* LRU 序遍历；不在收藏里的才入列（OCD-SPEC §4.1 Recent 语义） */
	for (i = 0; i < reg->nrecents && n < idx_max; i++) {
		size_t j;

		if (is_favorite_key(reg, reg->recents[i]))
			continue;
		for (j = 0; j < reg->nmodels; j++)
			if (key_equal(reg->models[j].provider,
				      reg->models[j].id, reg->recents[i])) {
				idx[n++] = j;
				break;
			}
	}
	return n;
}

/* qsort 比较器上下文（单线程消费：occ TUI/服务单线程构建视图） */
static const occ_registry *g_sort_reg;

static int cmp_by_provider(const void *a, const void *b)
{
	const occ_reg_model *ma = &g_sort_reg->models[*(const size_t *)a];
	const occ_reg_model *mb = &g_sort_reg->models[*(const size_t *)b];
	int r;

	r = strcmp(ma->provider_name, mb->provider_name);
	if (r)
		return r;
	r = strcmp(ma->provider, mb->provider);
	if (r)
		return r;
	return strcmp(ma->id, mb->id);
}

size_t occ_registry_all_by_provider(const occ_registry *reg,
				    int include_deprecated,
				    size_t *idx, size_t idx_max)
{
	size_t i, n = 0;

	if (!reg)
		return 0;
	for (i = 0; i < reg->nmodels; i++) {
		if (!include_deprecated && reg->models[i].is_deprecated)
			continue;
		if (n < idx_max)
			idx[n] = i;
		n++;
	}
	if (n > idx_max)
		n = idx_max;
	g_sort_reg = reg;
	qsort(idx, n, sizeof(*idx), cmp_by_provider);
	return n;
}

/* ---- fuzzy ---- */

static void lower_copy(char *dst, size_t dstlen, const char *src)
{
	size_t i;

	for (i = 0; i + 1 < dstlen && src && src[i]; i++)
		dst[i] = (char)tolower((unsigned char)src[i]);
	dst[i] = '\0';
}

/*
 * 子序列打分：q 依序出现在 t 中 → 分；连续命中奖励（run*run），
 * 起始位置早奖励；不匹配 → -1。子串（连续全命中）天然得最高 run。
 */
static long fuzzy_score(const char *t, const char *q)
{
	size_t ti = 0, qi;
	long score = 0, run = 0;

	for (qi = 0; q[qi]; qi++) {
		int hit = 0;

		while (t[ti]) {
			if (t[ti] == q[qi]) {
				hit = 1;
				run = run + 1;
				score += run * run;
				if (ti == 0)
					score += 8;	/* 首字母命中加权 */
				ti++;
				break;
			}
			run = 0;
			ti++;
		}
		if (!hit)
			return -1;
	}
	/* 短目标同分优先（标题更贴切） */
	return score * 100 - (long)strlen(t);
}

struct fuzzy_hit {
	long score;
	size_t idx;
};

static int cmp_hit(const void *a, const void *b)
{
	const struct fuzzy_hit *ha = a, *hb = b;

	if (ha->score != hb->score)
		return hb->score > ha->score ? 1 : -1;
	return ha->idx < hb->idx ? -1 : (ha->idx > hb->idx ? 1 : 0);
}

size_t occ_registry_fuzzy(const occ_registry *reg, const char *query,
			  int include_deprecated,
			  size_t *idx, size_t idx_max)
{
	char q[OCC_CAT_NAME_MAX * 2];
	struct fuzzy_hit *hits;
	size_t i, nhits = 0, n;

	if (!reg || !query || !*query)
		return 0;
	hits = malloc(reg->nmodels * sizeof(*hits));
	if (!hits)
		return 0;
	lower_copy(q, sizeof(q), query);
	for (i = 0; i < reg->nmodels; i++) {
		const occ_reg_model *m = &reg->models[i];
		char target[OCC_CAT_PROVIDER_MAX + OCC_CAT_ID_MAX +
			    OCC_CAT_NAME_MAX + 4];
		long sc;

		if (!include_deprecated && m->is_deprecated)
			continue;
		snprintf(target, sizeof(target), "%s/%s %s",
			 m->provider, m->id, m->display);
		lower_copy(target, sizeof(target), target);
		sc = fuzzy_score(target, q);
		if (sc < 0)
			continue;
		hits[nhits].score = sc;
		hits[nhits].idx = i;
		nhits++;
	}
	qsort(hits, nhits, sizeof(*hits), cmp_hit);
	n = nhits < idx_max ? nhits : idx_max;
	for (i = 0; i < n; i++)
		idx[i] = hits[i].idx;
	free(hits);
	return nhits;
}

/* ---- 持久化 ---- */

static int state_write_atomic(const char *path, const char *data,
			      size_t len)
{
	char tmp[OCC_STATE_PATH_MAX + 8];
	FILE *f;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -1;
	f = fopen(tmp, "w");
	if (!f)
		return -1;
	if (fwrite(data, 1, len, f) != len || fclose(f) != 0) {
		unlink(tmp);
		return -1;
	}
	chmod(tmp, 0600);
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

int occ_state_save(const occ_registry *reg, const char *state_path)
{
	aik_json *root, *jrec, *jfav;
	char *out = NULL;
	size_t outlen = 0;
	size_t i;
	int rc;

	if (!reg || !state_path)
		return -1;
	root = aik_json_new_obj();
	jrec = aik_json_new_arr();
	jfav = aik_json_new_arr();
	if (!root || !jrec || !jfav)
		goto fail;
	for (i = 0; i < reg->nrecents; i++)
		if (aik_json_arr_push(jrec,
				aik_json_new_str(reg->recents[i])) < 0)
			goto fail;
	for (i = 0; i < reg->nfavorites; i++)
		if (aik_json_arr_push(jfav,
				aik_json_new_str(reg->favorites[i])) < 0)
			goto fail;
	/* put 成功后 jrec/jfav 归 root——此后不再走 fail（免 double-free） */
	if (aik_json_obj_put(root, "recent", jrec) < 0) {
		aik_json_free(jrec);
		jrec = NULL;
		goto fail;
	}
	jrec = NULL;
	if (aik_json_obj_put(root, "favorites", jfav) < 0) {
		aik_json_free(jfav);
		jfav = NULL;
		goto fail;
	}
	jfav = NULL;
	if (aik_json_obj_put(root, "format",
			     aik_json_new_str("occ-state/1")) < 0)
		goto fail;
	if (aik_json_dump(root, &out, &outlen) != 0) {
		aik_json_free(root);
		return -1;
	}
	aik_json_free(root);
	rc = state_write_atomic(state_path, out, outlen);
	free(out);
	return rc;
fail:
	aik_json_free(jrec);
	aik_json_free(jfav);
	aik_json_free(root);
	return -1;
}

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

static void push_recent_key(occ_registry *reg, const char *key)
{
	size_t i, j;

	/* 已存在 → 移到头；否则头插（溢出丢尾） */
	for (i = 0; i < reg->nrecents; i++)
		if (!strcmp(reg->recents[i], key))
			break;
	if (i < reg->nrecents) {
		for (j = i; j > 0; j--)
			snprintf(reg->recents[j], sizeof(reg->recents[j]),
				 "%s", reg->recents[j - 1]);
	} else {
		if (reg->nrecents < OCC_REG_RECENT_MAX)
			reg->nrecents++;
		for (j = reg->nrecents - 1; j > 0; j--)
			snprintf(reg->recents[j], sizeof(reg->recents[j]),
				 "%s", reg->recents[j - 1]);
	}
	snprintf(reg->recents[0], sizeof(reg->recents[0]), "%s", key);
}

int occ_state_load(occ_registry *reg, const char *state_path)
{
	char *txt;
	size_t len;
	char perr[96];
	aik_json *root;
	const aik_json *arr;
	size_t i;

	if (!reg || !state_path)
		return -1;
	txt = read_file(state_path, &len);
	if (!txt)
		return -1;		/* 首次运行无状态文件 */
	root = aik_json_parse(txt, len, perr, sizeof(perr));
	free(txt);
	if (!root)
		return -1;		/* 坏状态文件：宁可重建 */
	arr = aik_json_get(root, "recent");
	if (arr && aik_json_typeof(arr) == AIK_JSON_ARR)
		for (i = 0; i < aik_json_count(arr) &&
			     reg->nrecents < OCC_REG_RECENT_MAX; i++) {
			const aik_json *v = aik_json_at(arr, i);

			if (v && aik_json_typeof(v) == AIK_JSON_STR)
				snprintf(reg->recents[reg->nrecents++],
					 sizeof(reg->recents[0]), "%s",
					 aik_json_str(v));
		}
	arr = aik_json_get(root, "favorites");
	if (arr && aik_json_typeof(arr) == AIK_JSON_ARR)
		for (i = 0; i < aik_json_count(arr) &&
			     reg->nfavorites < OCC_REG_FAV_MAX; i++) {
			const aik_json *v = aik_json_at(arr, i);

			if (v && aik_json_typeof(v) == AIK_JSON_STR)
				snprintf(reg->favorites[reg->nfavorites++],
					 sizeof(reg->favorites[0]), "%s",
					 aik_json_str(v));
		}
	aik_json_free(root);
	return 0;
}

void occ_registry_touch(occ_registry *reg, const char *provider,
			const char *model_id)
{
	char key[OCC_REG_KEY_MAX];

	if (!reg || reg_key(key, sizeof(key), provider, model_id) < 0)
		return;
	push_recent_key(reg, key);
}

int occ_registry_toggle_favorite(occ_registry *reg, const char *provider,
				 const char *model_id)
{
	size_t i;

	if (!reg)
		return -1;
	for (i = 0; i < reg->nfavorites; i++)
		if (key_equal(provider, model_id, reg->favorites[i])) {
			/* 取消收藏（保持序） */
			for (; i + 1 < reg->nfavorites; i++)
				snprintf(reg->favorites[i],
					 sizeof(reg->favorites[i]), "%s",
					 reg->favorites[i + 1]);
			reg->nfavorites--;
			return 0;
		}
	if (reg->nfavorites >= OCC_REG_FAV_MAX)
		return -1;
	if (reg_key(reg->favorites[reg->nfavorites],
		    sizeof(reg->favorites[0]), provider, model_id) < 0)
		return -1;
	reg->nfavorites++;
	return 1;
}
