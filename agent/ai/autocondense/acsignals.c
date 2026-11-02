// SPDX-License-Identifier: GPL-2.0
/*
 * acsignals.c - 压缩信号采集（collect）与候选判定（decide）
 *
 * 逐语义对齐 ref-autocondense/signals.py（详见 acsignals.h）。
 * 时间走 acconfig.h 注入时钟；JSON DOM 走 store/store_json。
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acsignals.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ================================================================== */
/* CJK 判定与 transcript 估算                                          */
/* ================================================================== */

static int is_cjk(unsigned int cp)
{
	return (cp >= 0x3040 && cp <= 0x30FF) ||	/* 平假名/片假名 */
	       (cp >= 0x3400 && cp <= 0x4DBF) ||	/* CJK 扩展 A */
	       (cp >= 0x4E00 && cp <= 0x9FFF) ||	/* CJK 基本区 */
	       (cp >= 0xAC00 && cp <= 0xD7A3) ||	/* 韩文音节 */
	       (cp >= 0xF900 && cp <= 0xFAFF) ||	/* CJK 兼容表意 */
	       (cp >= 0xFF00 && cp <= 0xFFEF) ||	/* 全角符号 */
	       (cp >= 0x20000 && cp <= 0x2A6DF);	/* CJK 扩展 B */
}

/*
 * next_cp - 从 buf[i..len) 解一个 UTF-8 码点
 *
 * 返回消费字节数；非法/截断序列返回 1 且 *cp = 0xFFFFFFFF（丢弃标记，
 * 对应 Python errors="ignore" 中被丢掉的坏字节）。
 */
static size_t next_cp(const unsigned char *buf, size_t len, size_t i,
		      unsigned int *cp)
{
	unsigned char c = buf[i];
	size_t need;
	unsigned int v;

	if (c < 0x80) {
		*cp = c;
		return 1;
	} else if ((c & 0xE0) == 0xC0) {
		need = 2;
		v = c & 0x1Fu;
	} else if ((c & 0xF0) == 0xE0) {
		need = 3;
		v = c & 0x0Fu;
	} else if ((c & 0xF8) == 0xF0) {
		need = 4;
		v = c & 0x07u;
	} else {
		*cp = 0xFFFFFFFFu;	/* 孤立续字节/非法首字节 */
		return 1;
	}
	if (i + need > len) {
		*cp = 0xFFFFFFFFu;	/* 截断 */
		return 1;
	}
	for (size_t k = 1; k < need; k++) {
		if ((buf[i + k] & 0xC0) != 0x80) {
			*cp = 0xFFFFFFFFu;
			return 1;
		}
		v = (v << 6) | (buf[i + k] & 0x3Fu);
	}
	*cp = v;
	return need;
}

int ac_estimate_transcript_tokens(const char *path, int *has, long long *out)
{
	if (has)
		*has = 0;
	if (out)
		*out = 0;
	if (!path || !*path)
		return 0;
	struct stat sb;

	if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode))
		return 0;	/* 无文件 → None */
	FILE *f = fopen(path, "rb");

	if (!f)
		return 0;	/* OSError：跳过估算（signals.py:89-91）*/
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return 0;
	}
	long sz = ftell(f);

	if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return 0;
	}
	unsigned char *buf = malloc((size_t)sz + 1);

	if (!buf) {
		fclose(f);
		return 0;
	}
	size_t len = 0;

	while (len < (size_t)sz) {
		size_t got = fread(buf + len, 1, (size_t)sz - len, f);

		if (got == 0)
			break;
		len += got;
	}
	fclose(f);

	double total = 0.0;
	size_t line_cjk = 0, line_len = 0;
	size_t i = 0;

	while (i < len) {
		unsigned char c = buf[i];

		if (c == '\n' || c == '\r') {
			/* universal newlines：\r\n / \r 都是一行结束，换行本身
			 * 计入行长 1 个字符（Python len(line) 含 '\n'）*/
			i++;
			if (c == '\r' && i < len && buf[i] == '\n')
				i++;
			total += (double)line_cjk +
				 ((double)line_len + 1.0 - (double)line_cjk) * 0.25;
			line_cjk = 0;
			line_len = 0;
			continue;
		}
		unsigned int cp;
		size_t used = next_cp(buf, len, i, &cp);

		i += used;
		if (cp == 0xFFFFFFFFu)
			continue;	/* 坏字节：丢弃（errors="ignore"）*/
		line_len++;
		if (is_cjk(cp))
			line_cjk++;
	}
	if (line_len > 0)	/* 末行无换行也计入 */
		total += (double)line_cjk +
			 ((double)line_len - (double)line_cjk) * 0.25;
	free(buf);
	if (has)
		*has = 1;
	if (out)
		*out = (long long)total;	/* int() 向零截断 */
	return 0;
}

/* ================================================================== */
/* urgency                                                             */
/* ================================================================== */

const char *ac_urgency_of(const aik_json *signals)
{
	const aik_json *water = aik_json_get(signals, "water_level");
	aik_json_type t = aik_json_typeof(water);

	if (t == AIK_JSON_INT || t == AIK_JSON_NUM) {
		if (aik_json_num(water) >= AC_URGENT_WATER)
			return "urgent";
	}
	return "normal";
}

/* ================================================================== */
/* collect                                                             */
/* ================================================================== */

/* Python round(x, n)：%.nf 正确十进制舍入（含 half-even）后回读 */
static double round_n(double x, int n)
{
	char fmt[16], buf[64];

	snprintf(fmt, sizeof(fmt), "%%.%df", n);
	snprintf(buf, sizeof(buf), fmt, x);
	return strtod(buf, NULL);
}

static const aik_json *int_or_none(const aik_json *v)
{
	return (v && aik_json_typeof(v) == AIK_JSON_INT) ? v : NULL;
}

/* _rounds_to_full：采样 ≥2 轮且轮差>0、平均增量>0 才给出估值 */
static void rounds_to_full(const aik_json *samples, long long current,
			   long long usable, int *has, long long *out)
{
	*has = 0;
	if (out)
		*out = 0;
	if (!samples || aik_json_typeof(samples) != AIK_JSON_ARR ||
	    aik_json_count(samples) < 2)
		return;
	const aik_json *first = aik_json_at(samples, 0);
	const aik_json *last = aik_json_at(samples, aik_json_count(samples) - 1);
	const aik_json *t0 = int_or_none(aik_json_get(first, "turn"));
	const aik_json *t1 = int_or_none(aik_json_get(last, "turn"));
	const aik_json *v0 = int_or_none(aik_json_get(first, "tokens"));
	const aik_json *v1 = int_or_none(aik_json_get(last, "tokens"));

	if (!t0 || !t1 || !v0 || !v1 || aik_json_int(t1) <= aik_json_int(t0))
		return;
	double avg = (double)(aik_json_int(v1) - aik_json_int(v0)) /
		     (double)(aik_json_int(t1) - aik_json_int(t0));

	if (avg <= 0.0)
		return;
	double remaining = (double)usable * 0.95 - (double)current;

	if (remaining <= 0.0) {
		*has = 1;
		*out = 0;
		return;
	}
	*out = (long long)ceil(remaining / avg);
	*has = 1;
}

aik_json *ac_collect(const ac_session *state, const ac_config *config)
{
	if (!state || !config)
		return NULL;

	/* token 来源：新鲜上报 > transcript 估算 > 过期上报 */
	int est_has = 0;
	long long est_transcript = 0;

	ac_estimate_transcript_tokens(state->transcript_path, &est_has,
				      &est_transcript);
	long long tokens = 0;
	int has_tokens = 0;
	const char *token_source = NULL;
	int reported_fresh = state->has_context_tokens &&
		state->has_context_tokens_turn &&
		(state->turns - state->context_tokens_turn) <=
		AC_REPORTED_TOKEN_FRESH_TURNS;

	if (reported_fresh) {
		tokens = state->context_tokens;
		has_tokens = 1;
		token_source = "reported";
	} else if (est_has) {
		tokens = est_transcript;
		has_tokens = 1;
		token_source = "estimated";
	} else if (state->has_context_tokens) {
		tokens = state->context_tokens;
		has_tokens = 1;
		token_source = "reported";
	}

	/* minutes_since_condense：round(Δ秒/60, 1) */
	int has_minutes = 0;
	double minutes = 0.0;

	if (state->last_condense_at) {
		time_t last;

		if (ac_parse_iso(state->last_condense_at, &last) == 0) {
			minutes = round_n(difftime(ac_now(), last) / 60.0, 1);
			has_minutes = 1;
		}
	}

	/* cooldown_active：cooldown_until 存在且 > now */
	int cooldown_active = 0;

	if (state->cooldown_until) {
		time_t cu;

		if (ac_parse_iso(state->cooldown_until, &cu) == 0 && cu > ac_now())
			cooldown_active = 1;
	}

	/* 水位：tokens 真值（0/None 不计）*/
	int has_water = 0;
	double water = 0.0;

	if (has_tokens && tokens != 0) {
		water = round_n((double)tokens /
				(double)config->usable_context_tokens, 4);
		has_water = 1;
	}

	int has_rtf = 0;
	long long rtf = 0;

	rounds_to_full(state->token_samples, tokens,
		       config->usable_context_tokens, &has_rtf, &rtf);

	/* idle：距最近活动轮的轮数；无活动记录 → None */
	int has_idle = 0;
	long long idle_rounds = 0;
	int has_act = 0;
	long long max_act = 0;

	if (state->has_last_file_turn) {
		has_act = 1;
		max_act = state->last_file_turn;
	}
	if (state->has_last_fail_turn) {
		if (!has_act || state->last_fail_turn > max_act)
			max_act = state->last_fail_turn;
		has_act = 1;
	}
	if (has_act) {
		idle_rounds = state->turns - max_act;
		has_idle = 1;
	}

	const char *urgency = (has_water && water >= AC_URGENT_WATER) ?
		"urgent" : "normal";

	size_t plan_total = aik_json_count(state->plan_items);
	size_t plan_completed = 0, plan_in_progress = 0;

	for (size_t i = 0; i < plan_total; i++) {
		const aik_json *it = aik_json_at(state->plan_items, i);
		const aik_json *st = aik_json_get(it, "status");

		if (!st || aik_json_typeof(st) != AIK_JSON_STR)
			continue;
		const char *sv = aik_json_str(st);

		if (strcmp(sv, "completed") == 0)
			plan_completed++;
		else if (strcmp(sv, "in_progress") == 0)
			plan_in_progress++;
	}

	aik_json *o = aik_json_new_obj();

	if (!o)
		return NULL;
	aik_json *nodes[] = {
		[0] = aik_json_new_int((long long)plan_total),
		[1] = aik_json_new_int((long long)plan_completed),
		[2] = aik_json_new_int((long long)plan_in_progress),
		[3] = aik_json_new_int(state->turns_since_condense),
		[4] = has_minutes ? aik_json_new_num(minutes) : aik_json_new_null(),
		[5] = has_tokens ? aik_json_new_int(tokens) : aik_json_new_null(),
		[6] = token_source ? aik_json_new_str(token_source)
				   : aik_json_new_null(),
		[7] = has_rtf ? aik_json_new_int(rtf) : aik_json_new_null(),
		[8] = has_idle ? aik_json_new_int(idle_rounds)
			       : aik_json_new_null(),
		[9] = has_water ? aik_json_new_num(water) : aik_json_new_null(),
		[10] = aik_json_new_bool(cooldown_active),
		[11] = aik_json_new_str(urgency),
	};
	static const char *KEYS[] = {
		"plan_total", "plan_completed", "plan_in_progress",
		"turns_since_condense", "minutes_since_condense", "est_tokens",
		"token_source", "rounds_to_full", "idle_rounds", "water_level",
		"cooldown_active", "urgency",
	};

	for (size_t i = 0; i < sizeof(KEYS) / sizeof(KEYS[0]); i++) {
		if (!nodes[i] || aik_json_obj_put(o, KEYS[i], nodes[i]) != 0) {
			for (size_t k = i; k < sizeof(KEYS) / sizeof(KEYS[0]); k++)
				aik_json_free(nodes[k]);
			aik_json_free(o);
			return NULL;
		}
	}
	return o;
}

/* ================================================================== */
/* decide                                                              */
/* ================================================================== */

/* int(sig.get(k) or 0)：null/缺失/假值 → 0；INT 原值；NUM 截断 */
static long long sig_int_or_zero(const aik_json *sig, const char *key)
{
	const aik_json *v = aik_json_get(sig, key);

	if (!v)
		return 0;
	switch (aik_json_typeof(v)) {
	case AIK_JSON_BOOL:
		return aik_json_bool(v);
	case AIK_JSON_INT:
		return aik_json_int(v);
	case AIK_JSON_NUM:
		return (long long)aik_json_num(v);
	case AIK_JSON_STR:
		return strtoll(aik_json_str(v), NULL, 10);
	default:
		return 0;
	}
}

/* Python 真值：None/False/0/""/空容器 → 假 */
static int json_truthy(const aik_json *v)
{
	if (!v)
		return 0;
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return 0;
	case AIK_JSON_BOOL:
		return aik_json_bool(v);
	case AIK_JSON_INT:
		return aik_json_int(v) != 0;
	case AIK_JSON_NUM:
		return aik_json_num(v) != 0.0;
	case AIK_JSON_STR:
		return aik_json_strlen(v) > 0;
	default:
		return aik_json_count(v) > 0;
	}
}

/* _completed_spans：plan_items + plan_archive 里 completed 的跨度达标？ */
static int any_completed_span(const ac_session *state, long long min_span)
{
	const aik_json *sources[2];
	size_t ns = 0;

	if (state->plan_items && aik_json_typeof(state->plan_items) == AIK_JSON_ARR)
		sources[ns++] = state->plan_items;
	if (state->plan_archive && aik_json_typeof(state->plan_archive) == AIK_JSON_ARR)
		sources[ns++] = state->plan_archive;

	for (size_t s = 0; s < ns; s++) {
		const aik_json *arr = sources[s];

		for (size_t i = 0; i < aik_json_count(arr); i++) {
			const aik_json *it = aik_json_at(arr, i);

			if (aik_json_typeof(it) != AIK_JSON_OBJ)
				continue;
			const aik_json *st = aik_json_get(it, "status");

			/* status 缺失（None）也按 completed 候选（signals.py:198）*/
			if (st && aik_json_typeof(st) == AIK_JSON_STR &&
			    strcmp(aik_json_str(st), "completed") != 0)
				continue;
			const aik_json *ct = aik_json_get(it, "completed_turn");
			const aik_json *ft = aik_json_get(it, "first_seen_turn");

			if (!ct || aik_json_typeof(ct) != AIK_JSON_INT)
				continue;
			if (!ft || aik_json_typeof(ft) != AIK_JSON_INT)
				continue;
			long long span = aik_json_int(ct) - aik_json_int(ft);

			if (span < 0)
				span = 0;
			if (span >= min_span)
				return 1;
		}
	}
	return 0;
}

/* 数值（INT/NUM）节点的 Python str() 形态（文案插值用）*/
static void num_to_text(const aik_json *v, char *buf, size_t buflen)
{
	if (aik_json_typeof(v) == AIK_JSON_INT) {
		snprintf(buf, buflen, "%lld", aik_json_int(v));
	} else {
		char tmp[40];

		aik_json_dtoa(aik_json_num(v), tmp, sizeof(tmp));
		snprintf(buf, buflen, "%s", tmp);
	}
}

static int put_str_kv(aik_json *o, const char *k, const char *v)
{
	aik_json *s = v ? aik_json_new_str(v) : aik_json_new_null();

	if (!s || aik_json_obj_put(o, k, s) != 0) {
		aik_json_free(s);
		return -1;
	}
	return 0;
}

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

aik_json *ac_decide(const ac_session *state, const aik_json *signals,
		    const ac_config *config)
{
	if (!state || !config)
		return NULL;
	const aik_json *sig = (signals && aik_json_typeof(signals) == AIK_JSON_OBJ) ?
		signals : NULL;
	long long in_prog = sig ? sig_int_or_zero(sig, "plan_in_progress") : 0;
	long long total = sig ? sig_int_or_zero(sig, "plan_total") : 0;
	long long done = sig ? sig_int_or_zero(sig, "plan_completed") : 0;
	const char *urgency = ac_urgency_of(sig);

	const char *should = "NO";
	const char *trigger = NULL;
	char reason[256];

	if (in_prog > 0) {
		/* 1) 进行中任务：绝不压，保证任务连续性 */
		snprintf(reason, sizeof(reason),
			 "有 %lld 项进行中的计划任务，为保证任务连续性暂不压缩",
			 in_prog);
		goto out;
	}
	if (sig && json_truthy(aik_json_get(sig, "cooldown_active"))) {
		/* 2) 冷却期未过 */
		if (state->cooldown_until) {
			time_t cu;

			if (ac_parse_iso(state->cooldown_until, &cu) == 0) {
				double remain = difftime(cu, ac_now()) / 60.0;

				if (remain < 0.0)
					remain = 0.0;
				snprintf(reason, sizeof(reason),
					 "压缩冷却期内（剩余约 %.0f 分钟），暂不压缩",
					 remain);
				goto out;
			}
		}
		snprintf(reason, sizeof(reason), "压缩冷却期内，暂不压缩");
		goto out;
	}
	if (total > 0 && done == total) {
		/* 3) 计划全部完成：任务脉络闭环 */
		should = "CANDIDATE";
		trigger = "plan_done";
		snprintf(reason, sizeof(reason),
			 "全部 %lld 项计划任务已完成，任务脉络已闭环，适合压缩",
			 total);
		goto out;
	}
	if (any_completed_span(state, config->task_min_rounds)) {
		/* 4) 长任务完成（含归档），过程细节可安全归档 */
		should = "CANDIDATE";
		trigger = "task_done";
		snprintf(reason, sizeof(reason),
			 "存在跨度 ≥%lld 轮的已完成任务，过程细节可安全归档",
			 config->task_min_rounds);
		goto out;
	}
	if (sig) {
		const aik_json *w = aik_json_get(sig, "water_level");

		if (w && aik_json_typeof(w) != AIK_JSON_NULL &&
		    aik_json_num(w) >= config->water_threshold) {
			/* 5) 水位接近上限 */
			should = "CANDIDATE";
			trigger = "water_level";
			snprintf(reason, sizeof(reason),
				 "上下文水位 %.0f%% 已达阈值 %.0f%%，接近可用上下文上限",
				 aik_json_num(w) * 100.0,
				 config->water_threshold * 100.0);
			goto out;
		}
	}
	if (sig) {
		const aik_json *idle = aik_json_get(sig, "idle_rounds");

		if (idle && aik_json_typeof(idle) != AIK_JSON_NULL &&
		    aik_json_num(idle) >= (double)config->idle_signal_rounds) {
			/* 6) 连续数轮无文件修改与失败 */
			char idle_txt[40];

			num_to_text(idle, idle_txt, sizeof(idle_txt));
			should = "CANDIDATE";
			trigger = "idle";
			snprintf(reason, sizeof(reason),
				 "连续 %s 轮无文件修改与失败，疑似任务停歇，适合压缩",
				 idle_txt);
			goto out;
		}
	}
	{
		long long tsc = sig ? sig_int_or_zero(sig, "turns_since_condense") : 0;

		if (tsc >= config->turns_threshold) {
			/* 7) 轮次候选 */
			should = "CANDIDATE";
			trigger = "turns";
			snprintf(reason, sizeof(reason),
				 "距上次压缩已累计 %lld 轮对话（阈值 %lld），建议压缩",
				 tsc, (long long)config->turns_threshold);
			goto out;
		}
	}
	/* 8) 无信号 */
	snprintf(reason, sizeof(reason), "暂未触发任何压缩信号");

out:;
	aik_json *o = aik_json_new_obj();
	aik_json *sig_echo = sig ? dom_copy(sig) : aik_json_new_obj();

	if (!o || !sig_echo)
		goto fail;
	const char *hint = (strcmp(should, "CANDIDATE") == 0) ?
		"命中压缩候选，立即调用 condense_judge 提交大模型判定，不要询问用户" :
		NULL;

	if (put_str_kv(o, "should", should) != 0 ||
	    put_str_kv(o, "trigger", trigger) != 0 ||
	    put_str_kv(o, "urgency", urgency) != 0 ||
	    put_str_kv(o, "reason", reason) != 0 ||
	    aik_json_obj_put(o, "signals", sig_echo) != 0) {
		aik_json_free(sig_echo);
		goto fail;
	}
	if (put_str_kv(o, "action_hint", hint) != 0)
		goto fail;
	return o;
fail:
	aik_json_free(o);
	return NULL;
}
