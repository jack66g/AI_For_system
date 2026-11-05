// SPDX-License-Identifier: GPL-2.0
/*
 * acpsi.c - PSI（内核压力信号）触发源：/proc/pressure 解析 + 抑制状态机
 *
 * 语义见 acpsi.h（K3d-1 / I-7）。时间全部由调用方注入（ac_now 或测试
 * 冻结时钟），本模块不直接取系统时间；DOM 走 store/store_json。
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acpsi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================== */
/* /proc/pressure 解析                                                 */
/* ================================================================== */

/* 解析 "some avg10=12.34 avg60=.. avg300=.. total=.." 形态一行的 avg10 */
static int parse_kind_avg10(const char *line, const char *kind, double *out)
{
	size_t klen = strlen(kind);

	if (strncmp(line, kind, klen) != 0)
		return -1;
	const char *p = line + klen;

	if (*p != ' ' && *p != '\t')
		return -1;	/* "somex" 之类不是该行 */
	p++;
	/* 键值对序列：找 "avg10=" */
	while (*p) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;
		const char *kp = p;

		while (*p && *p != '=' && *p != ' ' && *p != '\t')
			p++;
		if (*p != '=')
			continue;	/* 无值 token：跳过 */
		size_t kn = (size_t)(p - kp);

		p++;	/* 跳过 '=' */
		if (kn == 5 && strncmp(kp, "avg10", 5) == 0) {
			char *end = NULL;
			double v = strtod(p, &end);

			if (end == p)
				return -1;	/* 坏值 */
			if (v < 0.0 || v > 100.0)
				return -1;	/* 百分比越界 = 坏行 */
			*out = v;
			return 0;
		}
		/* 跳过值 */
		while (*p && *p != ' ' && *p != '\t')
			p++;
	}
	return -1;		/* 无 avg10 键 */
}

int ac_psi_parse(const char *text, ac_psi_res *out)
{
	if (!text || !out)
		return -1;
	memset(out, 0, sizeof(*out));
	out->full = -1.0;
	out->has_full = 0;
	int has_some = 0;
	const char *p = text;

	for (;;) {
		const char *nl = strchr(p, '\n');
		size_t len = nl ? (size_t)(nl - p) : strlen(p);

		/* 去行尾 \r 与首尾空白 */
		while (len > 0 && (p[len - 1] == '\r' || p[len - 1] == ' ' ||
				   p[len - 1] == '\t'))
			len--;
		size_t off = 0;

		while (off < len && (p[off] == ' ' || p[off] == '\t'))
			off++;
		if (off < len) {
			char line[256];

			if (len - off >= sizeof(line))
				return -1;	/* 超长行按坏行处理 */
			memcpy(line, p + off, len - off);
			line[len - off] = '\0';
			if (strncmp(line, "some", 4) == 0 &&
			    (line[4] == ' ' || line[4] == '\t' || line[4] == '\0')) {
				if (line[4] == '\0')
					return -1;	/* 只有 "some" 无键值对 */
				double v;

				if (parse_kind_avg10(line, "some", &v) != 0)
					return -1;	/* some 坏行 → 文件无效 */
				out->some = v;
				has_some = 1;
			} else if (strncmp(line, "full", 4) == 0 &&
				   (line[4] == ' ' || line[4] == '\t' ||
				    line[4] == '\0')) {
				if (line[4] == '\0')
					return -1;
				double v;

				if (parse_kind_avg10(line, "full", &v) != 0)
					return -1;	/* full 坏行 → 文件无效 */
				out->full = v;
				out->has_full = 1;
			}
			/* 其余行（total=... 独立行等）忽略 */
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	return has_some ? 0 : -1;	/* some 行缺失 = 文件无效 */
}

/*
 * slurp_text - 流式读小文本文件到 EOF（上限 buflen-1 字节）
 *
 * procfs 虚拟文件（/proc/pressure 下各资源文件）st_size 恒为 0，不能用
 * fseek/ftell 定长（ac_read_file 对常规文件的做法，对 procfs 会拿到
 * 空内容——live A/B 实测抓到，K3D1-REPORT §教训）。返回 0 成功。
 */
static int slurp_text(const char *path, char *buf, size_t buflen)
{
	FILE *f = fopen(path, "rb");

	if (!f)
		return -1;
	size_t n = 0;

	while (n + 1 < buflen) {
		size_t got = fread(buf + n, 1, buflen - 1 - n, f);

		if (got == 0)
			break;	/* EOF 或短读 */
		n += got;
	}
	int bad = ferror(f);

	fclose(f);
	buf[n] = '\0';
	return bad ? -1 : 0;
}

int ac_psi_read(const char *dir, ac_psi_values *out, double now)
{
	if (!dir || !out)
		return -1;
	static const char *const NAMES[] = { "cpu", "memory", "io" };
	ac_psi_res vals[3];
	char text[4096];

	for (int i = 0; i < 3; i++) {
		char path[512];

		if (snprintf(path, sizeof(path), "%s/%s", dir, NAMES[i]) >=
		    (int)sizeof(path))
			return -1;
		if (slurp_text(path, text, sizeof(text)) != 0)
			return -1;	/* 缺文件/读失败/超长 */
		if (ac_psi_parse(text, &vals[i]) != 0)
			return -1;	/* 坏文件 */
	}
	memset(out, 0, sizeof(*out));
	out->cpu = vals[0];
	out->mem = vals[1];
	out->io = vals[2];
	out->at = now;
	return 0;
}

/* ================================================================== */
/* 状态机                                                              */
/* ================================================================== */

static void clamp_config(const ac_psi_config *cfg, double *period,
			 double *high, double *low, double *window)
{
	double p = cfg ? (double)cfg->period_s : 5.0;
	double h = cfg ? cfg->high_threshold : 50.0;
	double l = cfg ? cfg->low_threshold : 20.0;
	double w = cfg ? (double)cfg->window_s : 120.0;

	if (!(p >= 1.0))
		p = 5.0;
	if (!(h > 0.0) || !(h <= 100.0))
		h = 50.0;
	if (!(l >= 0.0) || !(l < 100.0))
		l = 20.0;
	if (l >= h) {
		l = 20.0;
		h = 50.0;
	}
	if (!(w >= 1.0))
		w = 120.0;
	*period = p;
	*high = h;
	*low = l;
	*window = w;
}

void ac_psi_machine_init(ac_psi_machine *m, const ac_psi_config *cfg)
{
	if (!m)
		return;
	memset(m, 0, sizeof(*m));
	m->state = AC_PSI_STATE_NORMAL;
	clamp_config(cfg, &m->period_s, &m->high_threshold, &m->low_threshold,
		     &m->window_s);
}

void ac_psi_machine_refresh(ac_psi_machine *m, const ac_psi_config *cfg)
{
	if (!m)
		return;
	clamp_config(cfg, &m->period_s, &m->high_threshold, &m->low_threshold,
		     &m->window_s);
}

void ac_psi_machine_off(ac_psi_machine *m)
{
	if (!m)
		return;
	m->state = AC_PSI_STATE_OFF;
	m->window_open_at = 0.0;
	m->fail_streak = 0;
}

void ac_psi_degrade(ac_psi_machine *m, double now)
{
	if (!m)
		return;
	m->state = AC_PSI_STATE_DEGRADED;
	m->window_open_at = 0.0;
	m->degrade_count++;
	(void)now;
}

static void fill_event(ac_psi_event *ev, int kind, double now,
		       const ac_psi_machine *m, const ac_psi_values *v,
		       long long counter)
{
	if (!ev)
		return;
	memset(ev, 0, sizeof(*ev));
	ev->kind = kind;
	ev->now = now;
	ev->v = v ? *v : m->last;
	ev->counter = counter;
	ev->window_s = m->window_s;
	ev->high_threshold = m->high_threshold;
	ev->low_threshold = m->low_threshold;
	ev->fail_streak = m->fail_streak;
	ev->was_suppressed = 0;
}

int ac_psi_step(ac_psi_machine *m, const ac_psi_values *v, double now,
		ac_psi_event *ev)
{
	if (!m)
		return AC_PSI_EV_NONE;
	if (ev)
		ev->kind = AC_PSI_EV_NONE;
	if (m->state == AC_PSI_STATE_OFF || m->state == AC_PSI_STATE_DEGRADED)
		return AC_PSI_EV_NONE;

	if (!v) {
		m->fail_streak++;
		if (m->fail_streak >= AC_PSI_FAIL_STREAK_DEGRADE) {
			int was = m->state == AC_PSI_STATE_SUPPRESSED;

			m->state = AC_PSI_STATE_DEGRADED;
			m->window_open_at = 0.0;
			m->degrade_count++;
			fill_event(ev, AC_PSI_EV_DEGRADE, now, m, NULL,
				   m->degrade_count);
			if (ev)
				ev->was_suppressed = was;
			return AC_PSI_EV_DEGRADE;
		}
		if (now - m->last_warn_at >= AC_PSI_WARN_INTERVAL_S ||
		    m->last_warn_at == 0.0) {
			m->last_warn_at = now;
			fill_event(ev, AC_PSI_EV_WARN, now, m, NULL, 0);
			return AC_PSI_EV_WARN;
		}
		return AC_PSI_EV_NONE;
	}

	m->fail_streak = 0;
	m->last = *v;
	m->has_last = 1;
	m->samples++;

	if (m->state == AC_PSI_STATE_NORMAL) {
		if (v->mem.some >= m->high_threshold) {
			m->state = AC_PSI_STATE_SUPPRESSED;
			m->window_open_at = now;
			m->suppressed_count++;
			fill_event(ev, AC_PSI_EV_SUPPRESS_START, now, m, v,
				   m->suppressed_count);
			return AC_PSI_EV_SUPPRESS_START;
		}
		return AC_PSI_EV_NONE;
	}

	/* SUPPRESSED */
	if (v->mem.some < m->low_threshold) {
		m->state = AC_PSI_STATE_NORMAL;
		m->window_open_at = 0.0;
		fill_event(ev, AC_PSI_EV_END_CLEAR, now, m, v, 0);
		return AC_PSI_EV_END_CLEAR;
	}
	if (now >= m->window_open_at + m->window_s) {
		if (v->mem.some >= m->high_threshold) {
			/* 到期但压力仍高：续开新窗口（无空隙）*/
			m->window_open_at = now;
			m->suppressed_count++;
			fill_event(ev, AC_PSI_EV_REARM, now, m, v,
				   m->suppressed_count);
			return AC_PSI_EV_REARM;
		}
		m->state = AC_PSI_STATE_NORMAL;
		m->window_open_at = 0.0;
		fill_event(ev, AC_PSI_EV_END_EXPIRE, now, m, v, 0);
		return AC_PSI_EV_END_EXPIRE;
	}
	return AC_PSI_EV_NONE;
}

int ac_psi_suppressed(const ac_psi_machine *m, double now)
{
	if (!m || m->state != AC_PSI_STATE_SUPPRESSED)
		return 0;
	return now < m->window_open_at + m->window_s;
}

int ac_psi_gate(const ac_psi_machine *m, double now, char *reason,
		size_t reasonlen)
{
	if (!ac_psi_suppressed(m, now))
		return 0;
	if (reason && reasonlen > 0)
		snprintf(reason, reasonlen,
			 "PSI 内存压力抑制窗口内（memory some avg10=%.2f%%，"
			 "高阈 %.2f%%），压缩触发延迟（不丢弃），"
			 "窗口结束或压力回落后恢复评估",
			 m->has_last ? m->last.mem.some : 0.0,
			 m->high_threshold);
	return 1;
}

void ac_psi_note_deferred(ac_psi_machine *m)
{
	if (m)
		m->deferred_count++;
}

const char *ac_psi_state_name(int state)
{
	switch (state) {
	case AC_PSI_STATE_OFF:
		return "off";
	case AC_PSI_STATE_NORMAL:
		return "normal";
	case AC_PSI_STATE_SUPPRESSED:
		return "suppressed";
	case AC_PSI_STATE_DEGRADED:
		return "degraded";
	}
	return "unknown";
}

/* ================================================================== */
/* 状态字典 / 事件文案                                                 */
/* ================================================================== */

static aik_json *res_dict(const ac_psi_res *r, int has)
{
	aik_json *o = aik_json_new_obj();

	if (!o)
		return NULL;
	aik_json *some = has ? aik_json_new_num(r->some)
			     : aik_json_new_null();
	aik_json *full = (has && r->has_full) ? aik_json_new_num(r->full)
					      : aik_json_new_null();

	if (!some || !full || aik_json_obj_put(o, "some", some) != 0 ||
	    aik_json_obj_put(o, "full", full) != 0) {
		aik_json_free(some);
		aik_json_free(full);
		aik_json_free(o);
		return NULL;
	}
	return o;
}

aik_json *ac_psi_status_dict(const ac_psi_machine *m,
			     const ac_psi_config *cfg)
{
	if (!m)
		return NULL;
	aik_json *o = aik_json_new_obj();

	if (!o)
		return NULL;
	int enabled = m->state != AC_PSI_STATE_OFF;
	aik_json *lv = aik_json_new_obj();
	aik_json *sub[3];

	if (!lv)
		goto fail;
	sub[0] = res_dict(&m->last.cpu, m->has_last);
	sub[1] = res_dict(&m->last.mem, m->has_last);
	sub[2] = res_dict(&m->last.io, m->has_last);
	if (!sub[0] || !sub[1] || !sub[2] ||
	    aik_json_obj_put(lv, "cpu", sub[0]) != 0 ||
	    aik_json_obj_put(lv, "memory", sub[1]) != 0 ||
	    aik_json_obj_put(lv, "io", sub[2]) != 0) {
		aik_json_free(sub[0]);
		aik_json_free(sub[1]);
		aik_json_free(sub[2]);
		goto fail;
	}
	if (aik_json_obj_put(o, "enabled", aik_json_new_bool(enabled)) != 0 ||
	    aik_json_obj_put(o, "state",
			     aik_json_new_str(ac_psi_state_name(m->state))) != 0 ||
	    aik_json_obj_put(o, "period_s",
			     aik_json_new_num(m->period_s)) != 0 ||
	    aik_json_obj_put(o, "high_threshold",
			     aik_json_new_num(m->high_threshold)) != 0 ||
	    aik_json_obj_put(o, "low_threshold",
			     aik_json_new_num(m->low_threshold)) != 0 ||
	    aik_json_obj_put(o, "window_s",
			     aik_json_new_num(m->window_s)) != 0 ||
	    aik_json_obj_put(o, "last_values", lv) != 0) {
		aik_json_free(lv);
		goto fail;
	}
	lv = NULL;
	{
		char iso[32];
		aik_json *sat = (m->has_last &&
				 ac_iso_epoch((time_t)m->last.at, iso,
					      sizeof(iso)) == 0)
			? aik_json_new_str(iso) : aik_json_new_null();

		if (!sat || aik_json_obj_put(o, "sampled_at", sat) != 0) {
			aik_json_free(sat);
			goto fail;
		}
	}
	if (aik_json_obj_put(o, "suppressed_count",
			     aik_json_new_int(m->suppressed_count)) != 0 ||
	    aik_json_obj_put(o, "deferred_count",
			     aik_json_new_int(m->deferred_count)) != 0 ||
	    aik_json_obj_put(o, "degrade_count",
			     aik_json_new_int(m->degrade_count)) != 0 ||
	    aik_json_obj_put(o, "samples", aik_json_new_int(m->samples)) != 0)
		goto fail;
	(void)cfg;
	return o;
fail:
	aik_json_free(lv);
	aik_json_free(o);
	return NULL;
}

const char *ac_psi_format_event(const ac_psi_event *ev, char *buf,
				size_t buflen)
{
	if (!ev || !buf || buflen == 0)
		return buf;
	switch (ev->kind) {
	case AC_PSI_EV_SUPPRESS_START:
		snprintf(buf, buflen,
			 "抑制窗口开启 #%lld：memory some avg10=%.2f%% ≥ 高阈 %.2f%%"
			 "（cpu some=%.2f%%，io some=%.2f%%），窗口 %.0fs",
			 ev->counter, ev->v.mem.some, ev->high_threshold,
			 ev->v.cpu.some, ev->v.io.some, ev->window_s);
		break;
	case AC_PSI_EV_REARM:
		snprintf(buf, buflen,
			 "抑制窗口到期且压力仍高，续开 #%lld：memory some avg10=%.2f%%"
			 " ≥ 高阈 %.2f%%，窗口 %.0fs",
			 ev->counter, ev->v.mem.some, ev->high_threshold,
			 ev->window_s);
		break;
	case AC_PSI_EV_END_CLEAR:
		snprintf(buf, buflen,
			 "抑制解除（压力回落）：memory some avg10=%.2f%% < 低阈 %.2f%%"
			 "，延迟的压缩评估恢复",
			 ev->v.mem.some, ev->low_threshold);
		break;
	case AC_PSI_EV_END_EXPIRE:
		snprintf(buf, buflen,
			 "抑制窗口到期解除：memory some avg10=%.2f%% 处于滞回区间"
			 "（低阈 %.2f%%，高阈 %.2f%%），压缩评估恢复",
			 ev->v.mem.some, ev->low_threshold, ev->high_threshold);
		break;
	case AC_PSI_EV_WARN:
		snprintf(buf, buflen, "读取 /proc/pressure 失败（连续第 %d 次），"
			 "重试中（连续 %d 次后停用该源）",
			 ev->fail_streak, AC_PSI_FAIL_STREAK_DEGRADE);
		break;
	case AC_PSI_EV_DEGRADE:
		snprintf(buf, buflen,
			 "PSI 源停用（读取连续失败 %d 次%s），该触发源停用，"
			 "其余触发源不受影响",
			 ev->fail_streak,
			 ev->was_suppressed ? "，此前处于抑制窗口，一并解除" : "");
		break;
	default:
		snprintf(buf, buflen, "psi 事件 %d", ev->kind);
		break;
	}
	return buf;
}
