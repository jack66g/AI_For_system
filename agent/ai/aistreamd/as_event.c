/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_event.c - 事件规范化 + 去重窗口
 */
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "as_event.h"
#include "as_util.h"

static const char *const stream_names[AS_NSTREAMS] = {
	AS_STREAM_EVENT, AS_STREAM_PROC, AS_STREAM_NET,
	AS_STREAM_UEVENT, AS_STREAM_NFLOG, AS_STREAM_TASKSTATS,
};

int as_stream_idx(const char *name)
{
	for (int i = 0; i < AS_NSTREAMS; i++)
		if (strcmp(name, stream_names[i]) == 0)
			return i;
	return -1;
}

const char *as_stream_name(int idx)
{
	if (idx < 0 || idx >= AS_NSTREAMS)
		return "?";
	return stream_names[idx];
}

static void event_finish(struct as_event *ev)
{
	char key[AS_LINE_MAX + 64];
	int n;

	ev->ts_real_ms = as_now_real_ms();
	ev->digest = 0;
	ev->digest_hex[0] = '\0';
	ev->has_decision_id = 0;
	ev->decision_id = 0;
	ev->merged_count = 0;
	n = snprintf(key, sizeof(key), "%s%c%s%c%s", ev->stream, '\0',
		     ev->category, '\0', ev->line);
	if (n > 0)
		ev->digest = as_fnv1a64(key, (size_t)n);
	as_digest_hex(ev->digest, ev->digest_hex);
}

void as_event_mk(struct as_event *ev, int stream_idx, const char *category,
		 const char *severity, const char *kvfmt, ...)
{
	va_list ap;
	int pre;

	memset(ev, 0, sizeof(*ev));
	ev->stream_idx = stream_idx;
	ev->stream = as_stream_name(stream_idx);
	ev->category = category;
	ev->severity = severity ? severity : "info";
	/* 固定前缀 "[kern] <stream> <category> " + k=v 部分（冻结格式） */
	pre = snprintf(ev->line, sizeof(ev->line), "[kern] %s %s ",
		       ev->stream, ev->category);
	if (pre < 0 || (size_t)pre >= sizeof(ev->line))
		pre = 0;
	va_start(ap, kvfmt);
	vsnprintf(ev->line + pre, sizeof(ev->line) - (size_t)pre, kvfmt, ap);
	va_end(ap);
	event_finish(ev);
}

/* ---- proc（CN_PROC） ---- */

void as_event_proc_fork(struct as_event *ev, int ppid, int pid)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "fork", NULL,
		    "parent=%d child=%d", ppid, pid);
}

void as_event_proc_exec(struct as_event *ev, int pid)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "exec", NULL,
		    "pid=%d", pid);
}

void as_event_proc_exit(struct as_event *ev, int pid, unsigned code)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "exit", NULL,
		    "pid=%d code=%u", pid, code);
}

void as_event_proc_comm(struct as_event *ev, int pid, const char *comm)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "comm", NULL,
		    "pid=%d comm=%s", pid, comm ? comm : "?");
}

void as_event_proc_id(struct as_event *ev, const char *what, int pid,
		      unsigned from, unsigned to)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), what, NULL,
		    "pid=%d r%s=%u e%s=%u", pid, what, from, what, to);
}

void as_event_proc_other(struct as_event *ev, int what, int pid)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "other", NULL,
		    "what=%d pid=%d", what, pid);
}

/* ---- event（NETLINK_AI 异步推送） ---- */

void as_event_ai_policy(struct as_event *ev, unsigned long long decision_id,
			int executed, const char *sev, const char *param)
{
	/* decision_id 必须原样透传（K3-DESIGN §K3c 审计链）；
	 * severity!=info 时行尾附 sev=<级别>（info 是常态省略） */
	const char *s = sev ? sev : "info";

	if (strcmp(s, "info") != 0)
		as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "policy", s,
			    "decision_id=%llu executed=%d param=%s sev=%s",
			    decision_id, executed, param ? param : "", s);
	else
		as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "policy", s,
			    "decision_id=%llu executed=%d param=%s",
			    decision_id, executed, param ? param : "");
	ev->has_decision_id = 1;
	ev->decision_id = decision_id;
}

void as_event_ai_model(struct as_event *ev, unsigned long long model_id,
		       int loaded, const char *name)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "model", NULL,
		    "id=%llu op=%s name=%s", model_id,
		    loaded ? "load" : "unload", name ? name : "");
}

/* ---- K3d-2（I-9）：EVENT 通道热插拔事件（category 3/4/5，追加契约；
 * 行格式冻结——K3c 既有构造器与 fixture 零改动，见 as_event.h 注释） ---- */

void as_event_ai_device(struct as_event *ev, int removed, const char *dev)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "device", NULL,
		    "action=%s dev=%s", removed ? "remove" : "probe",
		    dev ? dev : "?");
}

void as_event_ai_cpu(struct as_event *ev, int online, int cpu)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "cpuhp", NULL,
		    "cpu=%d online=%d", cpu, online ? 1 : 0);
}

void as_event_ai_mce(struct as_event *ev, int cpu, int bank, const char *sev)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "mce",
		    sev ? sev : "error", "cpu=%d bank=%d", cpu, bank);
}

/* ---- net（RTNLGRP） ---- */

void as_event_net_link(struct as_event *ev, int is_new, int ifindex,
		       const char *name, unsigned flags)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_NET),
		    is_new ? "newlink" : "dellink", NULL,
		    "if=%d name=%s flags=0x%x", ifindex,
		    name ? name : "?", flags);
}

void as_event_net_addr(struct as_event *ev, int is_new, const char *family,
		       const char *addr, unsigned plen, int ifindex)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_NET),
		    is_new ? "newaddr" : "deladdr", NULL,
		    "if=%d family=%s addr=%s/%u", ifindex,
		    family ? family : "?", addr ? addr : "?", plen);
}

void as_event_net_route(struct as_event *ev, int is_new, const char *family,
			const char *dst, unsigned plen, int oif,
			const char *gw)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_NET),
		    is_new ? "newroute" : "delroute", NULL,
		    "family=%s dst=%s/%u oif=%d%s%s",
		    family ? family : "?", dst ? dst : "?", plen, oif,
		    gw && gw[0] ? " gw=" : "", gw && gw[0] ? gw : "");
}

/* ---- uevent（KOBJECT_UEVENT） ---- */

void as_event_uevent(struct as_event *ev, const char *action,
		     const char *devpath, const char *subsystem)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_UEVENT),
		    action && action[0] ? action : "other", NULL,
		    "dev=%s subsystem=%s", devpath ? devpath : "?",
		    subsystem ? subsystem : "?");
}

/* ---- nflog ---- */

void as_event_nflog(struct as_event *ev, unsigned hook, unsigned mark,
		    const char *prefix, int has_uid, unsigned uid)
{
	/* nflog attr 前缀是 NUL 结尾内核字符串；无 prefix/uid 时整体省略
	 * （不可用 %s%u 条件拼——%u 恒吞参） */
	if (prefix && prefix[0]) {
		if (has_uid)
			as_event_mk(ev, as_stream_idx(AS_STREAM_NFLOG),
				    "packet", NULL,
				    "hook=%u mark=%u prefix=%s uid=%u",
				    hook, mark, prefix, uid);
		else
			as_event_mk(ev, as_stream_idx(AS_STREAM_NFLOG),
				    "packet", NULL,
				    "hook=%u mark=%u prefix=%s", hook, mark,
				    prefix);
	} else if (has_uid) {
		as_event_mk(ev, as_stream_idx(AS_STREAM_NFLOG), "packet",
			    NULL, "hook=%u mark=%u uid=%u", hook, mark, uid);
	} else {
		as_event_mk(ev, as_stream_idx(AS_STREAM_NFLOG), "packet",
			    NULL, "hook=%u mark=%u", hook, mark);
	}
}

/* ---- taskstats（周期采样聚合） ---- */

void as_event_taskstats(struct as_event *ev, int n_pids,
			double cpu_delay_ms, double blkio_delay_ms,
			unsigned long long swapin_count)
{
	as_event_mk(ev, as_stream_idx(AS_STREAM_TASKSTATS), "sample", NULL,
		    "pids=%d cpu_delay_ms=%.1f blkio_delay_ms=%.1f "
		    "swapin=%llu", n_pids, cpu_delay_ms, blkio_delay_ms,
		    swapin_count);
}

/* ---- 去重窗口 ---- */

void as_dedup_init(struct as_dedup *d, long long window_ms)
{
	memset(d, 0, sizeof(*d));
	d->window_ms = window_ms;
}

static struct as_dedup_entry *dedup_find(struct as_dedup *d, uint64_t digest)
{
	for (int i = 0; i < AS_DEDUP_SLOTS; i++)
		if (d->slots[i].used && d->slots[i].digest == digest)
			return &d->slots[i];
	return NULL;
}

static struct as_dedup_entry *dedup_alloc(struct as_dedup *d)
{
	for (int i = 0; i < AS_DEDUP_SLOTS; i++)
		if (!d->slots[i].used)
			return &d->slots[i];
	/* 全满：牺牲最旧窗口（按 window_end 最小者） */
	struct as_dedup_entry *oldest = &d->slots[0];

	for (int i = 1; i < AS_DEDUP_SLOTS; i++)
		if (d->slots[i].window_end_ms < oldest->window_end_ms)
			oldest = &d->slots[i];
	oldest->used = 0;
	return oldest;
}

enum as_dedup_verdict as_dedup_filter(struct as_dedup *d,
				      const struct as_event *ev,
				      long long now_real_ms)
{
	struct as_dedup_entry *e = dedup_find(d, ev->digest);

	if (e) {
		if (now_real_ms < e->window_end_ms) {
			e->suppressed++;
			return AS_DEDUP_SUPPRESS;
		}
		/* 窗口已过：同 digest 再现＝新窗口首见 */
		e->used = 0;
		e = dedup_find(d, ev->digest);
	}
	e = dedup_alloc(d);
	e->used = 1;
	e->digest = ev->digest;
	e->window_end_ms = now_real_ms + d->window_ms;
	e->suppressed = 0;
	e->stream_idx = ev->stream_idx;
	snprintf(e->category, sizeof(e->category), "%s", ev->category);
	snprintf(e->severity, sizeof(e->severity), "%s", ev->severity);
	snprintf(e->line, sizeof(e->line), "%s", ev->line);
	e->has_decision_id = ev->has_decision_id;
	e->decision_id = ev->decision_id;
	return AS_DEDUP_PASS;
}

void as_dedup_flush(struct as_dedup *d, long long now_real_ms,
		    void (*emit)(struct as_event *agg, void *u), void *u)
{
	for (int i = 0; i < AS_DEDUP_SLOTS; i++) {
		struct as_dedup_entry *e = &d->slots[i];
		struct as_event agg;

		if (!e->used || e->suppressed <= 0)
			continue;
		if (now_real_ms < e->window_end_ms)
			continue;
		memset(&agg, 0, sizeof(agg));
		agg.stream_idx = e->stream_idx;
		agg.stream = as_stream_name(e->stream_idx);
		agg.category = e->category;
		agg.severity = e->severity;
		snprintf(agg.line, sizeof(agg.line), "%s repeats=%lld",
			 e->line, e->suppressed);
		agg.ts_real_ms = now_real_ms;
		agg.digest = e->digest;
		memcpy(agg.digest_hex, "aggregated", 11);
		agg.has_decision_id = e->has_decision_id;
		agg.decision_id = e->decision_id;
		agg.merged_count = (int)(e->suppressed + 1);
		e->used = 0;	/* 回收 */
		if (emit)
			emit(&agg, u);
	}
}
