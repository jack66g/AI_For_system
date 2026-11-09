/* SPDX-License-Identifier: GPL-2.0 */
/*
 * provider.c - occ provider 注册表（T9a1 最小读层 → T9a2 多 provider 正典）
 *
 * a1：[models.cloud] 单段读取（dtchat.c:1183-1233 式行扫描）。
 * a2：全文段扫描——[models.*] 槽位 + [provider.*] 引用段 + provider.toml
 * [providers] available 类型表；向导写辅助（原子写 + 600）。
 * 键值行语义与 a1 一致（key = "value"，# 后注释尾，值内引号截止）。
 *
 * 红线：api_key 只进内存（heap），本文件与调用方绝不 printf/log 它；
 * 释放前 memset 清零（不留堆残影）。
 */
#define _POSIX_C_SOURCE 200809L
#include "occ_provider.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const char *occ_protocol_name(occ_protocol p)
{
	switch (p) {
	case OCC_PROTO_OPENAI_COMPAT:
		return "openai_compatible";
	case OCC_PROTO_ANTHROPIC:
		return "anthropic";
	}
	return "unknown";
}

occ_protocol occ_protocol_from_type(const char *provider_type)
{
	if (!provider_type)
		return (occ_protocol)-1;
	if (!strcmp(provider_type, "openai_compatible") ||
	    !strcmp(provider_type, "openai"))
		return OCC_PROTO_OPENAI_COMPAT;
	if (!strcmp(provider_type, "anthropic") ||
	    !strcmp(provider_type, "anthropic_messages") ||
	    !strcmp(provider_type, "anthropic_compatible"))
		return OCC_PROTO_ANTHROPIC;
	return (occ_protocol)-1;
}

int occ_chat_url(char *buf, size_t buflen, occ_protocol proto,
		 const char *base_url)
{
	const char *path;
	size_t blen;
	int need_sep;

	if (!buf || buflen == 0 || !base_url || !*base_url)
		return -1;
	/* openai-chat.ts Endpoint.path("/chat/completions")；
	 * anthropic-messages.ts:39 PATH="/messages"（path 带前导 '/'，
	 * base 侧保证分隔符后去重） */
	path = (proto == OCC_PROTO_OPENAI_COMPAT) ?
		"/chat/completions" : "/messages";
	blen = strlen(base_url);
	need_sep = blen > 0 && base_url[blen - 1] != '/';
	if (blen + (size_t)need_sep + strlen(path + 1) + 1 > buflen)
		return -1;
	snprintf(buf, buflen, "%s%s%s", base_url, need_sep ? "/" : "", path + 1);
	return 0;
}

char *occ_build_request(const occ_llm_req *req, size_t *outlen)
{
	if (!req)
		return NULL;
	if (req->proto == OCC_PROTO_OPENAI_COMPAT)
		return occ_build_request_openai(req, outlen);
	if (req->proto == OCC_PROTO_ANTHROPIC)
		return occ_build_request_anthropic(req, outlen);
	return NULL;
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

/* 在 [models.cloud] 段内提取 key = "value"（首个命中；值去引号/注释尾） */
static char *toml_section_str(const char *txt, const char *section,
			      const char *key)
{
	const char *seg, *seg_end, *lp;
	size_t klen = strlen(key);
	char *out = NULL;

	seg = strstr(txt, section);
	if (!seg)
		return NULL;
	seg += strlen(section);
	seg_end = strchr(seg, '[');
	if (!seg_end)
		seg_end = seg + strlen(seg);
	lp = seg;
	while (lp < seg_end) {
		const char *le = memchr(lp, '\n', (size_t)(seg_end - lp));
		size_t ln = le ? (size_t)(le - lp) : (size_t)(seg_end - lp);
		size_t iv = 0, jv;

		while (iv < ln && (lp[iv] == ' ' || lp[iv] == '\t'))
			iv++;
		if (iv + klen <= ln && strncmp(lp + iv, key, klen) == 0) {
			jv = iv + klen;
			while (jv < ln && (lp[jv] == ' ' || lp[jv] == '\t'))
				jv++;
			if (jv < ln && lp[jv] == '=') {
				size_t vend;
				int q = 0;

				jv++;
				while (jv < ln && (lp[jv] == ' ' || lp[jv] == '\t'))
					jv++;
				if (jv < ln && (lp[jv] == '"' || lp[jv] == '\'')) {
					q = lp[jv];
					jv++;
				}
				vend = jv;
				while (vend < ln && lp[vend] != '#' &&
				       (q ? lp[vend] != (char)q : 1))
					vend++;
				out = malloc(vend - jv + 1);
				if (!out)
					return NULL;
				memcpy(out, lp + jv, vend - jv);
				out[vend - jv] = '\0';
				return out;
			}
		}
		if (!le)
			break;
		lp = le + 1;
	}
	return NULL;
}

static void set_str(char *dst, size_t dstlen, char *heap_val)
{
	if (!heap_val)
		return;
	snprintf(dst, dstlen, "%s", heap_val);
	free(heap_val);
}

int occ_provider_load_cloud(occ_provider *p, const char *toml_path)
{
	char *txt, *ptype, *burl, *model, *apikey;

	memset(p, 0, sizeof(*p));
	txt = read_file(toml_path, NULL);
	if (!txt)
		return -1;
	ptype = toml_section_str(txt, "[models.cloud]", "provider_type");
	burl = toml_section_str(txt, "[models.cloud]", "base_url");
	model = toml_section_str(txt, "[models.cloud]", "model_name");
	apikey = toml_section_str(txt, "[models.cloud]", "api_key");
	free(txt);
	if (!ptype) {
		free(burl);
		free(model);
		free(apikey);
		return -1;
	}
	p->proto = occ_protocol_from_type(ptype);
	free(ptype);
	if ((int)p->proto == -1) {
		free(burl);
		free(model);
		free(apikey);
		return -1;
	}
	snprintf(p->name, sizeof(p->name), "cloud");
	set_str(p->base_url, sizeof(p->base_url), burl);
	set_str(p->model, sizeof(p->model), model);
	if (apikey) {
		p->api_key = apikey;
	} else {
		p->api_key = calloc(1, 1);
		if (!p->api_key)
			return -1;
	}
	return 0;
}

void occ_provider_free(occ_provider *p)
{
	if (!p)
		return;
	if (p->api_key) {
		/* 清零后释放，密钥不留堆残影 */
		memset(p->api_key, 0, strlen(p->api_key));
		free(p->api_key);
	}
	memset(p, 0, sizeof(*p));
}

/* ======================================================================
 * T9a2：多 provider 正典读层 + 写辅助（OPENCODE-PLAN §2.3）
 * ====================================================================== */

#define TOML_SEC_NAME_MAX 128
#define TOML_MAX_SECS 256

struct toml_sec {
	char name[TOML_SEC_NAME_MAX];		/* 段名（[] 内原文） */
	size_t head_off;			/* 段头行行首字节偏移 */
	size_t seg_end;				/* 段末（最后行行尾之后或 EOF） */
};

/* 行首 [name] → 段头；命中填充 name_out 返回 0 */
static int toml_section_header(const char *line, size_t len,
			       char *name_out, size_t name_max)
{
	size_t i = 0, j;

	while (i < len && (line[i] == ' ' || line[i] == '\t'))
		i++;
	if (i >= len || line[i] != '[')
		return -1;
	i++;
	j = i;
	while (j < len && line[j] != ']' && line[j] != '#')
		j++;
	if (j >= len || line[j] != ']')
		return -1;
	while (j > i && (line[j - 1] == ' ' || line[j - 1] == '\t'))
		j--;
	if (j == i || j - i >= name_max)
		return -1;
	memcpy(name_out, line + i, j - i);
	name_out[j - i] = '\0';
	return 0;
}

/*
 * 全文 → 段表。seg_end 语义：每吸收一行推进到该行行尾 \n 后
 * （无 \n 的 EOF 行推进到文本末）；段整段字节范围 = [head_off, seg_end)。
 * 返回全文段头总数（超 TOML_MAX_SECS 截断——超出段仍计数但无记录，
 * 读层循环只遍历已记录段，写层保守拒收超限文件）。
 */
static size_t toml_split_sections(const char *txt, struct toml_sec *secs,
				  size_t max)
{
	size_t nsecs = 0, recorded = 0;
	const char *lp = txt;
	size_t cur = (size_t)-1;
	size_t pos = 0;

	while (txt[pos]) {
		const char *le = strchr(lp, '\n');
		size_t ln = le ? (size_t)(le - lp) : strlen(lp);
		size_t next = le ? (size_t)(le - txt) + 1 : strlen(txt);
		char name[TOML_SEC_NAME_MAX];

		if (toml_section_header(lp, ln, name, sizeof(name)) == 0) {
			if (recorded < max) {
				cur = recorded;
				snprintf(secs[cur].name,
					 sizeof(secs[cur].name), "%s", name);
				secs[cur].head_off = pos;
				secs[cur].seg_end = next;
				recorded++;
			} else {
				cur = (size_t)-1;
			}
			nsecs++;
		} else if (cur != (size_t)-1) {
			secs[cur].seg_end = next;
		}
		if (!le)
			break;
		pos = next;
		lp = le + 1;
	}
	return nsecs;
}

/* 段体（head_off 段头行之后）内提取 key = "value"；语义同 toml_section_str */
static char *toml_body_str(const char *txt, const struct toml_sec *s,
			   const char *key)
{
	/* 段体起点 = 段头行行尾之后 */
	const char *head_end = strchr(txt + s->head_off, '\n');
	const char *lp, *end;
	size_t klen = strlen(key);

	if (!head_end)
		return NULL;
	lp = head_end + 1;
	end = txt + s->seg_end;
	while (lp < end) {
		const char *le = memchr(lp, '\n', (size_t)(end - lp));
		size_t ln = le ? (size_t)(le - lp) : (size_t)(end - lp);
		size_t iv = 0, jv;

		while (iv < ln && (lp[iv] == ' ' || lp[iv] == '\t'))
			iv++;
		if (iv + klen <= ln && strncmp(lp + iv, key, klen) == 0) {
			jv = iv + klen;
			while (jv < ln && (lp[jv] == ' ' || lp[jv] == '\t'))
				jv++;
			if (jv < ln && lp[jv] == '=') {
				size_t vend;
				int q = 0;

				jv++;
				while (jv < ln && (lp[jv] == ' ' || lp[jv] == '\t'))
					jv++;
				if (jv < ln && (lp[jv] == '"' || lp[jv] == '\'')) {
					q = lp[jv];
					jv++;
				}
				vend = jv;
				while (vend < ln && lp[vend] != '#' &&
				       (q ? lp[vend] != (char)q : 1))
					vend++;
				{
					char *out = malloc(vend - jv + 1);
					if (!out)
						return NULL;
					memcpy(out, lp + jv, vend - jv);
					out[vend - jv] = '\0';
					return out;
				}
			}
		}
		if (!le)
			break;
		lp = le + 1;
	}
	return NULL;
}

static void heap_scrub_free(char **p)
{
	if (*p) {
		memset(*p, 0, strlen(*p));
		free(*p);
		*p = NULL;
	}
}

void occ_provider_config_init(occ_provider_config *cfg)
{
	if (!cfg)
		return;
	memset(cfg, 0, sizeof(*cfg));
}

void occ_provider_config_free(occ_provider_config *cfg)
{
	size_t i;

	if (!cfg)
		return;
	for (i = 0; i < cfg->nslots; i++)
		heap_scrub_free(&cfg->slots[i].api_key);
	free(cfg->slots);
	for (i = 0; i < cfg->nproviders; i++)
		heap_scrub_free(&cfg->providers[i].api_key);
	free(cfg->providers);
	memset(cfg, 0, sizeof(*cfg));
}

static int cfg_reserve(void **arr, size_t *cap, size_t need, size_t esz)
{
	if (need <= *cap)
		return 0;
	{
		size_t nc = *cap ? *cap * 2 : 8;
		void *na;

		while (nc < need)
			nc *= 2;
		na = realloc(*arr, nc * esz);
		if (!na)
			return -1;
		*arr = na;
		*cap = nc;
	}
	return 0;
}

static void parse_model_section(const char *txt, const struct toml_sec *s,
				occ_provider_config *cfg)
{
	occ_model_slot slot;
	char *v;

	memset(&slot, 0, sizeof(slot));
	snprintf(slot.id, sizeof(slot.id), "%s", s->name + 7);
	slot.proto = (occ_protocol)-1;
	v = toml_body_str(txt, s, "provider");
	if (v) {
		snprintf(slot.provider_ref, sizeof(slot.provider_ref), "%s", v);
		free(v);
	}
	v = toml_body_str(txt, s, "provider_type");
	if (v) {
		snprintf(slot.provider_type, sizeof(slot.provider_type), "%s", v);
		slot.proto = occ_protocol_from_type(slot.provider_type);
		free(v);
	}
	v = toml_body_str(txt, s, "base_url");
	if (v) {
		snprintf(slot.base_url, sizeof(slot.base_url), "%s", v);
		free(v);
	}
	/* B3（T9A3 §5.5 清欠）：direct 地址（forwarder 代理失效时的
	 * 直连兜底，槽位级覆盖 provider 段） */
	v = toml_body_str(txt, s, "direct_base_url");
	if (v) {
		snprintf(slot.direct_base_url, sizeof(slot.direct_base_url),
			 "%s", v);
		free(v);
	}
	v = toml_body_str(txt, s, "model_name");
	if (!v)
		v = toml_body_str(txt, s, "model");
	if (v) {
		snprintf(slot.model, sizeof(slot.model), "%s", v);
		free(v);
	}
	slot.api_key = toml_body_str(txt, s, "api_key");
	if ((int)slot.proto == -1 && !slot.provider_ref[0]) {
		/* 无类型无引用 → 坏段（容错跳过计数） */
		heap_scrub_free(&slot.api_key);
		cfg->malformed++;
		return;
	}
	if (cfg_reserve((void **)&cfg->slots, &cfg->slots_cap,
			cfg->nslots + 1, sizeof(*cfg->slots)) < 0) {
		heap_scrub_free(&slot.api_key);
		return;
	}
	cfg->slots[cfg->nslots++] = slot;
}

static void parse_provider_section(const char *txt, const struct toml_sec *s,
				   occ_provider_config *cfg)
{
	occ_provider_def def;
	char *v;

	memset(&def, 0, sizeof(def));
	snprintf(def.name, sizeof(def.name), "%s", s->name + 9);
	v = toml_body_str(txt, s, "type");
	if (v) {
		snprintf(def.type, sizeof(def.type), "%s", v);
		free(v);
	} else {
		snprintf(def.type, sizeof(def.type), "openai_compatible");
	}
	def.proto = occ_protocol_from_type(def.type);
	if ((int)def.proto == -1)
		def.proto = OCC_PROTO_OPENAI_COMPAT;	/* 未知类型容错 */
	v = toml_body_str(txt, s, "base_url");
	if (v) {
		snprintf(def.base_url, sizeof(def.base_url), "%s", v);
		free(v);
	}
	v = toml_body_str(txt, s, "direct_base_url");
	if (v) {
		snprintf(def.direct_base_url, sizeof(def.direct_base_url),
			 "%s", v);
		free(v);
	}
	def.api_key = toml_body_str(txt, s, "key");
	if (!def.api_key)
		def.api_key = toml_body_str(txt, s, "api_key");
	if (cfg_reserve((void **)&cfg->providers, &cfg->providers_cap,
			cfg->nproviders + 1, sizeof(*cfg->providers)) < 0) {
		heap_scrub_free(&def.api_key);
		return;
	}
	cfg->providers[cfg->nproviders++] = def;
}

/* provider.toml [providers] 的 available = ["a","b"] → 类型表 */
static void parse_available(const char *txt, const struct toml_sec *s,
			    occ_provider_config *cfg)
{
	char *raw = toml_body_str(txt, s, "available");
	const char *p;

	if (!raw)
		return;
	p = raw;
	while (*p && cfg->navailable < 16) {
		const char *q1 = strchr(p, '"');
		const char *q2;
		size_t len;

		if (!q1)
			break;
		q2 = strchr(q1 + 1, '"');
		if (!q2)
			break;
		len = (size_t)(q2 - q1 - 1);
		if (len > 0 && len < sizeof(cfg->available_types[0])) {
			memcpy(cfg->available_types[cfg->navailable],
			       q1 + 1, len);
			cfg->available_types[cfg->navailable][len] = '\0';
			cfg->navailable++;
		}
		p = q2 + 1;
	}
	memset(raw, 0, strlen(raw));
	free(raw);
}

int occ_provider_load_all(occ_provider_config *cfg, const char *model_toml,
			  const char *provider_toml)
{
	char *txt;
	struct toml_sec secs[TOML_MAX_SECS];
	size_t nsecs, i;

	if (!cfg || !model_toml)
		return -1;
	occ_provider_config_init(cfg);

	txt = read_file(model_toml, NULL);
	if (!txt)
		return -1;
	nsecs = toml_split_sections(txt, secs, TOML_MAX_SECS);
	if (nsecs > TOML_MAX_SECS) {
		/* 超限文件拒收（写层保持可预测） */
		free(txt);
		return -1;
	}
	for (i = 0; i < nsecs; i++) {
		if (!strncmp(secs[i].name, "models.", 7) && secs[i].name[7])
			parse_model_section(txt, &secs[i], cfg);
		else if (!strncmp(secs[i].name, "provider.", 9) &&
			 secs[i].name[9])
			parse_provider_section(txt, &secs[i], cfg);
	}
	free(txt);

	if (provider_toml) {
		char *ptxt = read_file(provider_toml, NULL);

		if (ptxt) {
			struct toml_sec psecs[64];
			size_t np = toml_split_sections(ptxt, psecs, 64);
			size_t j;

			if (np <= 64)
				for (j = 0; j < np; j++)
					if (!strcmp(psecs[j].name, "providers"))
						parse_available(ptxt, &psecs[j],
								cfg);
			free(ptxt);
		}
		/* provider.toml 缺/坏 → 类型表空（不影响模型槽位） */
	}
	return 0;
}

/*
 * occ_provider_validate_url - B3（T9A3 §5.5）：provider 地址人话校验。
 * 通过返回 0；不通过 -1 且 err 写人话（截断安全）。规则：
 *   - 必须以 http:// 或 https:// 开头（大小写敏感——scheme 小写正典）
 *   - scheme 后非空（有主机名）
 *   - 全程无 ASCII 控制字符/空格/引号（防 TOML 值截断/注入）
 */
int occ_provider_validate_url(const char *url, char *err, size_t errlen)
{
	size_t i, slen;
	const char *scheme = NULL;

	if (!err || errlen == 0)
		return -1;
	err[0] = '\0';
	if (!url || !url[0]) {
		snprintf(err, errlen, "地址为空");
		return -1;
	}
	if (!strncmp(url, "http://", 7))
		scheme = "http://";
	else if (!strncmp(url, "https://", 8))
		scheme = "https://";
	if (!scheme) {
		snprintf(err, errlen,
			 "地址必须以 http:// 或 https:// 开头（当前开头 24 字符：%.24s）",
			 url);
		return -1;
	}
	if (!url[strlen(scheme)]) {
		snprintf(err, errlen, "scheme 后为空（缺主机名）：%s", url);
		return -1;
	}
	slen = strlen(url);
	for (i = 0; i < slen; i++) {
		unsigned char c = (unsigned char)url[i];

		if (c < 0x21 || c == 0x7f || c == '"' || c == '\'') {
			snprintf(err, errlen,
				 "地址含非法字符（第 %zu 字节，ASCII 0x%02x）",
				 i + 1, c);
			return -1;
		}
	}
	return 0;
}

int occ_provider_resolve(const occ_provider_config *cfg, const char *slot_id,
			 occ_provider *out)
{
	return occ_provider_resolve_ex(cfg, slot_id, out, NULL, 0);
}

/*
 * occ_provider_resolve_ex - B3：resolve + 人话报错（err 可 NULL=不要
 * 详情；resolve 失败时 out 已清零、无泄漏）。校验面：base_url 必填
 * 合法；direct_base_url 选填但给值必须合法（B3 conf 校验门）。
 */
int occ_provider_resolve_ex(const occ_provider_config *cfg, const char *slot_id,
			    occ_provider *out, char *err, size_t errlen)
{
	size_t i;
	const occ_model_slot *slot = NULL;
	const occ_provider_def *def = NULL;
	char verr[192];

	if (!err || errlen == 0) {
		err = NULL;
		errlen = 0;
	} else {
		err[0] = '\0';
	}
	if (!cfg || !slot_id || !out) {
		if (err)
			snprintf(err, errlen, "内部错误：参数为空");
		return -1;
	}
	for (i = 0; i < cfg->nslots; i++)
		if (!strcmp(cfg->slots[i].id, slot_id)) {
			slot = &cfg->slots[i];
			break;
		}
	if (!slot) {
		if (err)
			snprintf(err, errlen,
				 "model.toml 无 [models.%s] 槽位（可用槽位 %zu 个）",
				 slot_id, cfg->nslots);
		return -1;
	}
	if (slot->provider_ref[0]) {
		for (i = 0; i < cfg->nproviders; i++)
			if (!strcmp(cfg->providers[i].name,
				    slot->provider_ref)) {
				def = &cfg->providers[i];
				break;
			}
		if (!def) {
			if (err)
				snprintf(err, errlen,
					 "[models.%s] 引用的 [provider.%s] 段不存在",
					 slot->id, slot->provider_ref);
			return -1;	/* 引用目标不存在 */
		}
	}
	memset(out, 0, sizeof(*out));
	snprintf(out->name, sizeof(out->name), "%s", slot->id);
	out->proto = (int)slot->proto != -1 ? slot->proto :
		    (def ? def->proto : OCC_PROTO_OPENAI_COMPAT);
	if (slot->base_url[0])
		snprintf(out->base_url, sizeof(out->base_url), "%s",
			 slot->base_url);
	else if (def && def->base_url[0])
		snprintf(out->base_url, sizeof(out->base_url), "%s",
			 def->base_url);
	if (!out->base_url[0]) {
		if (err)
			snprintf(err, errlen,
				 "[models.%s] 无 base_url（直填式缺键，或引用的 [provider.%s] 段也未给）",
				 slot->id, slot->provider_ref[0] ?
				 slot->provider_ref : "-");
		return -1;
	}
	if (occ_provider_validate_url(out->base_url, verr, sizeof(verr))) {
		if (err)
			snprintf(err, errlen,
				 "[models.%s] base_url 非法：%s", slot->id,
				 verr);
		return -1;
	}
	/* B3：direct 地址——槽位级覆盖 provider 段；给值必须过校验 */
	if (slot->direct_base_url[0])
		snprintf(out->direct_base_url,
			 sizeof(out->direct_base_url), "%s",
			 slot->direct_base_url);
	else if (def && def->direct_base_url[0])
		snprintf(out->direct_base_url,
			 sizeof(out->direct_base_url), "%s",
			 def->direct_base_url);
	if (out->direct_base_url[0] &&
	    occ_provider_validate_url(out->direct_base_url, verr,
				      sizeof(verr))) {
		if (err)
			snprintf(err, errlen,
				 "[models.%s] direct_base_url 非法：%s",
				 slot->id, verr);
		out->direct_base_url[0] = '\0';
		return -1;
	}
	if (slot->model[0])
		snprintf(out->model, sizeof(out->model), "%s", slot->model);
	else if (def && def->base_url[0])
		snprintf(out->model, sizeof(out->model), "%s", def->name);
	/* key：槽位优先，其次 provider 段（红线性拷贝，不落日志） */
	if (slot->api_key && slot->api_key[0])
		out->api_key = strdup(slot->api_key);
	else if (def && def->api_key && def->api_key[0])
		out->api_key = strdup(def->api_key);
	else
		out->api_key = calloc(1, 1);
	if (!out->api_key) {
		if (err)
			snprintf(err, errlen, "内存不足（key 拷贝）");
		return -1;
	}
	return 0;
}

/* ---- 写辅助（向导；原子写 + 600） ---- */

static char *render_slot_section(const occ_model_slot *slot)
{
	size_t cap = 512 + (slot->api_key ? strlen(slot->api_key) : 0);
	char *buf = malloc(cap);
	int n;

	if (!buf)
		return NULL;
	n = snprintf(buf, cap, "[models.%s]\n", slot->id);
	n += snprintf(buf + n, cap - n, "provider_type = \"%s\"\n",
		      slot->provider_type[0] ? slot->provider_type :
		      occ_protocol_name(slot->proto));
	if (slot->provider_ref[0])
		n += snprintf(buf + n, cap - n, "provider = \"%s\"\n",
			      slot->provider_ref);
	if (slot->base_url[0])
		n += snprintf(buf + n, cap - n, "base_url = \"%s\"\n",
			      slot->base_url);
	if (slot->direct_base_url[0])
		n += snprintf(buf + n, cap - n,
			      "direct_base_url = \"%s\"\n",
			      slot->direct_base_url);
	if (slot->model[0])
		n += snprintf(buf + n, cap - n, "model_name = \"%s\"\n",
			      slot->model);
	if (slot->api_key && slot->api_key[0])
		n += snprintf(buf + n, cap - n, "api_key = \"%s\"\n",
			      slot->api_key);
	if (n < 0 || (size_t)n >= cap) {
		free(buf);
		return NULL;
	}
	return buf;
}

static char *render_provider_section(const occ_provider_def *def)
{
	size_t cap = 512 + (def->api_key ? strlen(def->api_key) : 0);
	char *buf = malloc(cap);
	int n;

	if (!buf)
		return NULL;
	n = snprintf(buf, cap, "[provider.%s]\n", def->name);
	n += snprintf(buf + n, cap - n, "type = \"%s\"\n", def->type);
	if (def->base_url[0])
		n += snprintf(buf + n, cap - n, "base_url = \"%s\"\n",
			      def->base_url);
	if (def->direct_base_url[0])
		n += snprintf(buf + n, cap - n,
			      "direct_base_url = \"%s\"\n",
			      def->direct_base_url);
	if (def->api_key && def->api_key[0])
		n += snprintf(buf + n, cap - n, "key = \"%s\"\n",
			      def->api_key);
	if (n < 0 || (size_t)n >= cap) {
		free(buf);
		return NULL;
	}
	return buf;
}

/* 值含引号/反斜杠/换行 → 拒收（向导输入为裸 key/URL） */
static int value_safe(const char *v)
{
	for (; v && *v; v++)
		if (*v == '"' || *v == '\\' || *v == '\n' || *v == '\r')
			return 0;
	return 1;
}

static int slot_values_safe(const occ_model_slot *s)
{
	return value_safe(s->id) && value_safe(s->provider_type) &&
	       value_safe(s->provider_ref) && value_safe(s->base_url) &&
	       value_safe(s->model) && value_safe(s->api_key) &&
	       value_safe(s->direct_base_url);	/* B3 */
}

static int def_values_safe(const occ_provider_def *d)
{
	return value_safe(d->name) && value_safe(d->type) &&
	       value_safe(d->base_url) && value_safe(d->api_key) &&
	       value_safe(d->direct_base_url);	/* B3 */
}

/*
 * 段替换核心：读原文件（可不存在=新建）→ 同名段整段替换（无则文件尾
 * 追加）→ <path>.tmp 写出 → chmod 0600 → rename。section_text 为完整
 * 段文本（"[name]\n" + 键值行，行尾 \n）。
 */
static int toml_replace_section(const char *toml_path, const char *sec_name,
				const char *section_text)
{
	char *txt = NULL;
	size_t txtlen = 0;
	struct toml_sec secs[TOML_MAX_SECS];
	size_t nsecs = 0, i, root_end = 0;
	char *out;
	size_t out_cap, out_len = 0;
	char tmp_path[512];
	FILE *f;
	int replaced = 0;

	txt = read_file(toml_path, &txtlen);
	if (txt) {
		nsecs = toml_split_sections(txt, secs, TOML_MAX_SECS);
		if (nsecs > TOML_MAX_SECS) {
			free(txt);
			return -1;
		}
	}
	out_cap = (txt ? txtlen : 0) + strlen(section_text) + 64;
	out = malloc(out_cap);
	if (!out) {
		free(txt);
		return -1;
	}
	/* 根区（首个段头行之前）原样保留 */
	if (nsecs)
		root_end = secs[0].head_off;
	else if (txt)
		root_end = txtlen;
	if (root_end > out_cap - 1)
		root_end = out_cap - 1;
	if (root_end) {
		memcpy(out, txt, root_end);
		out_len = root_end;
	}
	for (i = 0; i < nsecs; i++) {
		size_t seg_start = secs[i].head_off;
		size_t seg_end = secs[i].seg_end;
		size_t need;

		if (seg_end > txtlen)
			seg_end = txtlen;
		if (!strcmp(secs[i].name, sec_name)) {
			need = strlen(section_text) + 1;
			if (out_len + need > out_cap)
				goto oom;
			memcpy(out + out_len, section_text,
			       strlen(section_text));
			out_len += strlen(section_text);
			if (out_len && out[out_len - 1] != '\n')
				out[out_len++] = '\n';
			replaced = 1;
			continue;
		}
		need = (seg_end - seg_start) + 1;
		if (out_len + need > out_cap)
			goto oom;
		memcpy(out + out_len, txt + seg_start, seg_end - seg_start);
		out_len += seg_end - seg_start;
		if (out_len && out[out_len - 1] != '\n')
			out[out_len++] = '\n';
	}
	if (!replaced) {
		size_t need = strlen(section_text) + 1;

		if (out_len + need > out_cap)
			goto oom;
		if (out_len && out[out_len - 1] != '\n')
			out[out_len++] = '\n';
		memcpy(out + out_len, section_text, strlen(section_text));
		out_len += strlen(section_text);
		if (out[out_len - 1] != '\n')
			out[out_len++] = '\n';
	}
	free(txt);

	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", toml_path);
	f = fopen(tmp_path, "w");
	if (!f) {
		free(out);
		return -1;
	}
	if (fwrite(out, 1, out_len, f) != out_len || fclose(f) != 0) {
		free(out);
		unlink(tmp_path);
		return -1;
	}
	free(out);
	if (chmod(tmp_path, 0600) != 0 || rename(tmp_path, toml_path) != 0) {
		unlink(tmp_path);
		return -1;
	}
	return 0;
oom:
	free(txt);
	free(out);
	return -1;
}

int occ_provider_toml_add_slot(const char *toml_path,
			       const occ_model_slot *slot)
{
	char hdr[TOML_SEC_NAME_MAX];
	char *body;
	int rc;

	if (!toml_path || !slot || !slot->id[0] ||
	    strchr(slot->id, '.') || strchr(slot->id, ']'))
		return -1;
	if (!slot_values_safe(slot))
		return -1;
	snprintf(hdr, sizeof(hdr), "models.%s", slot->id);
	body = render_slot_section(slot);
	if (!body)
		return -1;
	rc = toml_replace_section(toml_path, hdr, body);
	free(body);
	return rc;
}

int occ_provider_toml_add_provider(const char *toml_path,
				   const occ_provider_def *def)
{
	char hdr[TOML_SEC_NAME_MAX];
	char *full;
	int rc;

	if (!toml_path || !def || !def->name[0] ||
	    strchr(def->name, '.') || strchr(def->name, ']'))
		return -1;
	if (!def_values_safe(def))
		return -1;
	snprintf(hdr, sizeof(hdr), "provider.%s", def->name);
	full = render_provider_section(def);
	if (!full)
		return -1;
	rc = toml_replace_section(toml_path, hdr, full);
	free(full);
	return rc;
}
