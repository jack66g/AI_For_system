// SPDX-License-Identifier: GPL-2.0
/*
 * apiredact.c - /sense 暴露侧脱敏实现（设计 SENSE-REDACT-DESIGN §2.1/§3）
 *
 * 文本形态（内核侧核实出处）：
 *   telemetry（ai_procfs.c ai_telemetry_human_record）：
 *     "ts=%llu pid=%u tgid=%u cpu=%u cat=%u ev=%u sev=%u len=%u data=<hex≤32>..."
 *     （data 尾可能带 "..."；k=v 单空格分隔，一行一条）
 *   status（ai_procfs.c ai_proc_status_show）：
 *     "model_path: <绝对路径>"（冒号风）与 "  [%u] name=%s version=..."
 *     （models 行，k=v 风）混排
 *   chains/decisions（ai_procfs.c ai_proc_dec_record）：
 *     "id=%llu trig_ts=%llu trig_evid=0x%04x ... data=<8 数冒号> ..."
 *
 * 解析口径：level != off 时 telemetry/chains/decisions 行逐 k=v 重建
 * （命中键按表变换；未知键 pass+计数——设计 §3.5 不静默吞；内核
 * scnprintf 单空格生成，重建保字节）；status 只改 model_path: 行值与
 * models 行 name= 键，其余行原字节保留；control/latency/hitrate/sched/
 * vfs 整体原样（纯计数面，设计 §2.1 全 pass）。off 档 strdup 原文
 * （api_do_sense 零字节差——重放门前提）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apic/api.h"
#include "apiredact.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

/* ---------------- 引擎（与 aistreamd as_redact 同公式；对拍锁定） ---- */

unsigned long long api_redact_fnv64(const char *salt, const char *value)
{
	unsigned long long h = 1469598103934665603ULL;
	const char *p;

	for (p = salt && *salt ? salt : ""; *p; p++) {
		h ^= (unsigned char)*p;
		h *= 1099511628211ULL;
	}
	h ^= 0x01;
	for (p = value ? value : ""; *p; p++) {
		h ^= (unsigned char)*p;
		h *= 1099511628211ULL;
	}
	return h;
}

size_t api_redact_str(char *out, size_t cap, int strat, const char *salt,
		      const char *v)
{
	switch (strat) {
	case API_R_HASH:
		return (size_t)snprintf(out, cap, "h:%016llx",
					api_redact_fnv64(salt, v));
	case API_R_TRUNC:{
			size_t n = v ? strlen(v) : 0;

			return (size_t)snprintf(out, cap, "%.*s~%zu", 8,
						v ? v : "", n);
		}
	case API_R_MASK:
		if (v && *v)
			return (size_t)snprintf(out, cap, "%c***", v[0]);
		return (size_t)snprintf(out, cap, "***");
	case API_R_DROP:
		return (size_t)snprintf(out, cap, "-");
	case API_R_PASS:
	default:
		return (size_t)snprintf(out, cap, "%s", v ? v : "");
	}
}

/* ---------------- 配置解析（env > model.toml > off） ---------------- */

static int level_from_str(const char *s, int *out)
{
	if (!s)
		return 0;
	if (strcmp(s, "off") == 0)
		*out = API_REDACT_OFF;
	else if (strcmp(s, "soft") == 0)
		*out = API_REDACT_SOFT;
	else if (strcmp(s, "strict") == 0)
		*out = API_REDACT_STRICT;
	else
		return 0;
	return 1;
}

int api_sense_redact_level(char *salt_out, size_t saltcap)
{
	int level = API_REDACT_OFF;
	const char *e = getenv("AIK_SENSE_REDACT");

	if (salt_out && saltcap)
		salt_out[0] = '\0';
	if (e && *e) {
		int v = API_REDACT_OFF;

		/* 坏 env 值：窄化降级 off（不放大配置面；测试用键，
		 * 生产不开 env——出厂面只有 model.toml） */
		level_from_str(e, &v);
		level = v;
		{
			const char *es = getenv("AIK_SENSE_REDACT_SALT");

			if (salt_out && saltcap && es)
				snprintf(salt_out, saltcap, "%s", es);
		}
		return level;
	}
	{
		aik_json *cfg = api_load_config();
		const aik_json *v = dt_get(cfg, "sense_redact");
		const aik_json *sv = dt_get(cfg, "sense_redact_salt");
		int parsed = 0;

		if (aik_json_str(v))
			parsed = level_from_str(aik_json_str(v), &level);
		if (!parsed)
			level = API_REDACT_OFF;
		if (salt_out && saltcap && aik_json_str(sv))
			snprintf(salt_out, saltcap, "%s", aik_json_str(sv));
		aik_json_free(cfg);
	}
	return level;
}

/* ---------------- 行级重写 ---------------- */

struct api_redact_stats *api_redact_stats(void)
{
	static struct api_redact_stats st;

	return &st;
}

/* 规则表：key → (soft, strict)；设计 §2.1 */
struct kv_rule {
	const char *key;
	int soft;
	int strict;
};

static const struct kv_rule telemetry_rules[] = {
	{ "ts",		API_R_PASS,  API_R_PASS },
	{ "pid",	API_R_HASH,  API_R_HASH },
	{ "tgid",	API_R_HASH,  API_R_HASH },
	{ "cpu",	API_R_PASS,  API_R_PASS },
	{ "cat",	API_R_PASS,  API_R_PASS },
	{ "ev",		API_R_PASS,  API_R_PASS },
	{ "sev",	API_R_PASS,  API_R_PASS },
	{ "len",	API_R_PASS,  API_R_PASS },
	{ "data",	API_R_TRUNC, API_R_DROP },
};

static const struct kv_rule chains_rules[] = {
	{ "id",		API_R_PASS,  API_R_PASS },	/* decision_id 例外：
							 * K3-DESIGN §K3c */
	{ "trig_ts",	API_R_PASS,  API_R_PASS },
	{ "trig_evid",	API_R_PASS,  API_R_PASS },
	{ "dec_ts",	API_R_PASS,  API_R_PASS },
	{ "type",	API_R_PASS,  API_R_PASS },
	{ "data",	API_R_PASS,  API_R_MASK },	/* 可能内嵌 pid */
	{ "exec_ts",	API_R_PASS,  API_R_PASS },
	{ "outcome_ts",API_R_PASS,  API_R_PASS },
	{ "outcome",	API_R_PASS,  API_R_PASS },
	{ "delta",	API_R_PASS,  API_R_PASS },
	{ "ver",	API_R_PASS,  API_R_PASS },
	{ "conf",	API_R_PASS,  API_R_PASS },
	{ "domain",	API_R_PASS,  API_R_PASS },
	{ "src",	API_R_PASS,  API_R_PASS },
	{ "executed",	API_R_PASS,  API_R_PASS },
	{ "safety_clamped",	API_R_PASS, API_R_PASS },
};

static const struct kv_rule *rule_find(const struct kv_rule *rules,
				       size_t n, const char *key,
				       size_t keylen)
{
	for (size_t i = 0; i < n; i++)
		if (strlen(rules[i].key) == keylen &&
		    strncmp(rules[i].key, key, keylen) == 0)
			return &rules[i];
	return NULL;
}

/* 行首空格（status models 行缩进）在调用方已剥离；此处 token 单空格
 * 重建进 tmp——changed 时取重建结果（内核单空格格式，未变 token 保
 * 字节），否则丢弃用原文（CRLF 容忍：'\r' 归入末 token 值尾，值变换
 * 场景它本就被替换） */
static int redact_kv_line(struct dt_sbuf *out, char *scratch,
			  const struct kv_rule *rules, size_t nrules,
			  int level, const char *salt)
{
	struct dt_sbuf tmp;
	char *save = NULL;
	char *tok = strtok_r(scratch, " ", &save);
	int first = 1;
	int changed = 0;
	char newv[512];

	dt_sb_init(&tmp);
	while (tok) {
		char *eq = strchr(tok, '=');
		const struct kv_rule *r = NULL;

		if (eq) {
			*eq = '\0';
			r = rule_find(rules, nrules, tok,
				      (size_t)(eq - tok));
			if (r) {
				int strat = level == API_REDACT_STRICT ?
					r->strict : r->soft;

				if (strat != API_R_PASS) {
					api_redact_str(newv, sizeof(newv),
						       strat, salt,
						       eq + 1);
					dt_sb_printf(&tmp, "%s%s=%s",
						     first ? "" : " ", tok,
						     newv);
					api_redact_stats()->applied++;
					changed = 1;
					*eq = '=';
					tok = strtok_r(NULL, " ", &save);
					first = 0;
					continue;
				}
			} else {
				/* 未知键：透传+计数（§3.5） */
				api_redact_stats()->unknown_pass++;
			}
			*eq = '=';	/* 恢复后再走原文追加 */
		}
		dt_sb_printf(&tmp, "%s%s", first ? "" : " ", tok);
		first = 0;
		tok = strtok_r(NULL, " ", &save);
	}
	if (changed) {
		dt_sb_puts(out, tmp.p ? tmp.p : "", tmp.n);
	} else {
		/* 未变行丢弃重建（strtok 归一了分隔），调用方走原文 */
	}
	free(tmp.p);
	return changed;
}

/* status 行：model_path: <val>（冒号风）；models 行 name= 键定点替换
 * （前缀/后缀字节保留）；返回 1=已重写（不含换行），0=未命中 */
static int redact_status_line(struct dt_sbuf *out, const char *line,
			      int level, const char *salt)
{
	static const char mp[] = "model_path: ";

	if (level == API_REDACT_OFF)
		return 0;
	if (strncmp(line, mp, sizeof(mp) - 1) == 0) {
		char newv[512];

		api_redact_str(newv, sizeof(newv),
			       level == API_REDACT_STRICT ?
			       API_R_DROP : API_R_HASH,
			       salt, line + sizeof(mp) - 1);
		dt_sb_printf(out, "model_path: %s", newv);
		api_redact_stats()->applied++;
		return 1;
	}
	{
		const char *nm = strstr(line, " name=");

		if (nm) {
			/* 定点：前缀（含缩进/[idx]）+ 新值 + 后缀字节保留 */
			const char *val = nm + 6;
			const char *valend = strchr(val, ' ');
			char oldval[300];
			size_t vlen = valend ? (size_t)(valend - val) :
				       strlen(val);
			char newv[512];

			if (vlen >= sizeof(oldval))
				return 0;	/* 超长值：保守原文（不吞） */
			memcpy(oldval, val, vlen);
			oldval[vlen] = '\0';
			api_redact_str(newv, sizeof(newv),
				       level == API_REDACT_STRICT ?
				       API_R_DROP : API_R_HASH,
				       salt, oldval);
			dt_sb_puts(out, line, (size_t)(val - line));
			dt_sb_putstr(out, newv);
			if (valend)
				dt_sb_puts(out, valend,
					   strlen(valend));
			api_redact_stats()->applied++;
			return 1;
		}
	}
	return 0;
}

/* ---------------- 整文处理 ---------------- */

static char *dup_text(const char *text, size_t text_len)
{
	char *out = malloc(text_len + 1);

	if (out) {
		memcpy(out, text, text_len);
		out[text_len] = '\0';
	}
	return out;
}

/* 逐行（保 '\n' 归属）；hit 行进重写，未命中行原文字节保留 */
static char *redact_parse_lines(const char *text, size_t text_len,
				const struct kv_rule *rules, size_t nrules,
				int level, const char *salt)
{
	struct dt_sbuf out;
	size_t pos = 0;

	dt_sb_init(&out);
	while (pos < text_len) {
		const char *nl = memchr(text + pos, '\n', text_len - pos);
		size_t llen = nl ? (size_t)(nl - (text + pos)) :
			      text_len - pos;
		const char *line = text + pos;
		char *scratch = malloc(llen + 1);
		int changed = 0;

		api_redact_stats()->lines_in++;
		if (scratch) {
			memcpy(scratch, line, llen);
			scratch[llen] = '\0';
			changed = redact_kv_line(&out, scratch, rules,
						 nrules, level, salt);
			free(scratch);
		}
		if (!changed)
			dt_sb_puts(&out, line, llen);
		if (nl)
			dt_sb_putc(&out, '\n');
		pos = nl ? (size_t)(nl - text) + 1 : text_len;
	}
	return dt_sb_finish(&out);
}

static char *redact_status(const char *text, size_t text_len, int level,
			   const char *salt)
{
	struct dt_sbuf out;
	size_t pos = 0;

	dt_sb_init(&out);
	while (pos < text_len) {
		const char *nl = memchr(text + pos, '\n', text_len - pos);
		size_t llen = nl ? (size_t)(nl - (text + pos)) :
			      text_len - pos;
		const char *line = text + pos;
		int changed = 0;

		api_redact_stats()->lines_in++;
		{
			char *scratch = malloc(llen + 1);

			if (scratch) {
				memcpy(scratch, line, llen);
				scratch[llen] = '\0';
				changed = redact_status_line(&out, scratch,
							     level, salt);
				free(scratch);
			}
		}
		if (!changed)
			dt_sb_puts(&out, line, llen);
		if (nl)
			dt_sb_putc(&out, '\n');
		pos = nl ? (size_t)(nl - text) + 1 : text_len;
	}
	return dt_sb_finish(&out);
}

char *api_sense_redact_text(const char *what, const char *text,
			    size_t text_len, size_t *out_len)
{
	char salt[256];
	int level = api_sense_redact_level(salt, sizeof(salt));
	char *out;

	if (level == API_REDACT_OFF) {
		out = dup_text(text, text_len);
		if (out && out_len)
			*out_len = text_len;
		return out;
	}
	if (what && strcmp(what, "telemetry") == 0)
		out = redact_parse_lines(text, text_len, telemetry_rules,
					 sizeof(telemetry_rules) /
					 sizeof(telemetry_rules[0]),
					 level, salt);
	else if (what && (strcmp(what, "chains") == 0 ||
			  strcmp(what, "decisions") == 0))
		out = redact_parse_lines(text, text_len, chains_rules,
					 sizeof(chains_rules) /
					 sizeof(chains_rules[0]),
					 level, salt);
	else if (what && strcmp(what, "status") == 0)
		out = redact_status(text, text_len, level, salt);
	else
		out = dup_text(text, text_len);	/* control/latency/hitrate/
						 * sched/vfs：纯计数整体
						 * pass（设计 §2.1） */
	if (!out)
		return NULL;
	if (out_len)
		*out_len = strlen(out);
	return out;
}
