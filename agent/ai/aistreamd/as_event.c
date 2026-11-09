/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_event.c - 事件规范化 + 去重窗口
 */
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "as_event.h"
#include "as_redact.h"
#include "as_util.h"

/* ---- SENSE 脱敏策略选择（设计 SENSE-REDACT-DESIGN §2.2 表；
 * off 恒 AS_R_PASS → 字节零变化（冻结 fixture/差分门前提）；
 * decision_id 例外不在此表——恒原样（K3-DESIGN §K3c 审计链） ---- */

static int rs_pid(void)		/* pid：soft/strict 都 hash（保聚合 join） */
{
	return as_redact_level() ? AS_R_HASH : AS_R_PASS;
}

static int rs_idval(void)	/* uid/gid 迁移值：soft hash，strict drop */
{
	return as_redact_level() == AS_REDACT_STRICT ? AS_R_DROP :
	       as_redact_level() == AS_REDACT_SOFT ? AS_R_HASH : AS_R_PASS;
}

static int rs_comm(void)	/* 进程名：soft hash，strict drop */
{
	return rs_idval();
}

static int rs_addr(void)	/* IP/路由：soft mask，strict drop */
{
	return as_redact_level() == AS_REDACT_STRICT ? AS_R_DROP :
	       as_redact_level() == AS_REDACT_SOFT ? AS_R_MASK : AS_R_PASS;
}

static int rs_path(void)	/* 路径/前缀类：soft mask，strict drop */
{
	return rs_addr();
}

static int rs_model(void)	/* 模型名：soft mask，strict drop */
{
	return rs_addr();
}

static int rs_dev(void)		/* 设备名：soft pass，strict mask */
{
	return as_redact_level() == AS_REDACT_STRICT ? AS_R_MASK : AS_R_PASS;
}

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
	char rp[32], rc[32];

	as_redact_int(rp, sizeof(rp), rs_pid(), ppid);
	as_redact_int(rc, sizeof(rc), rs_pid(), pid);
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "fork", NULL,
		    "parent=%s child=%s", rp, rc);
	ev->pid = as_redact_pid_col(pid);	/* 事件主体=子进程
						 * （T8 Parquet pid 列） */
}

void as_event_proc_exec(struct as_event *ev, int pid)
{
	char rp[32];

	as_redact_int(rp, sizeof(rp), rs_pid(), pid);
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "exec", NULL,
		    "pid=%s", rp);
	ev->pid = as_redact_pid_col(pid);
}

void as_event_proc_exit(struct as_event *ev, int pid, unsigned code)
{
	char rp[32];

	as_redact_int(rp, sizeof(rp), rs_pid(), pid);
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "exit", NULL,
		    "pid=%s code=%u", rp, code);
	ev->pid = as_redact_pid_col(pid);
}

void as_event_proc_comm(struct as_event *ev, int pid, const char *comm)
{
	char rp[32], rcomm[64];

	as_redact_int(rp, sizeof(rp), rs_pid(), pid);
	as_redact_str(rcomm, sizeof(rcomm), rs_comm(),
		      comm ? comm : "?");
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "comm", NULL,
		    "pid=%s comm=%s", rp, rcomm);
	ev->pid = as_redact_pid_col(pid);
}

void as_event_proc_id(struct as_event *ev, const char *what, int pid,
		      unsigned from, unsigned to)
{
	/* 身份迁移值只有 uid/gid 在策略表内（设计 §2.2）；其余 what
	 * （未来 CN_PROC 扩展）= 未知字段：透传+计数（§3.5 不静默吞） */
	char rp[32], rf[32], rt[32];
	int known = what && (strcmp(what, "uid") == 0 ||
			     strcmp(what, "gid") == 0);

	if (!known)
		as_redact_stats()->unknown_pass++;
	as_redact_int(rp, sizeof(rp), rs_pid(), pid);
	as_redact_int(rf, sizeof(rf), known ? rs_idval() : AS_R_PASS,
		      (long long)from);
	as_redact_int(rt, sizeof(rt), known ? rs_idval() : AS_R_PASS,
		      (long long)to);
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), what, NULL,
		    "pid=%s r%s=%s e%s=%s", rp, what, rf, what, rt);
	ev->pid = as_redact_pid_col(pid);
}

void as_event_proc_other(struct as_event *ev, int what, int pid)
{
	char rp[32];

	as_redact_int(rp, sizeof(rp), rs_pid(), pid);
	as_event_mk(ev, as_stream_idx(AS_STREAM_PROC), "other", NULL,
		    "what=%d pid=%s", what, rp);
	ev->pid = as_redact_pid_col(pid);
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

void as_event_outcome(struct as_event *ev, unsigned long long decision_id,
		      int outcome, long long delta, const char *knob)
{
	/* 回填器自带枚举→名映射在 as_outcome.c（as_oc_outcome_name）；
	 * 此处不引依赖，直接内联（仅 1/2/4 三态，冻结） */
	as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "outcome", NULL,
		    "decision_id=%llu outcome=%s delta=%lld knob=%s",
		    decision_id,
		    outcome == 1 ? "SUCCESS" :
		    outcome == 4 ? "WORSE" : "PARTIAL",
		    delta, knob ? knob : "");
	ev->has_decision_id = 1;
	ev->decision_id = decision_id;
}

void as_event_decision(struct as_event *ev, unsigned long long decision_id,
		       unsigned type, unsigned domain, unsigned executed,
		       unsigned safety_clamped, unsigned outcome,
		       long long delta)
{
	/* T8 遗留接线（as_decisions）：/proc/ai/decisions 行原生字段原样
	 * 透传（零解释——type/domain 枚举语义在内核 ai_policy.h，文档
	 * 义务在本侧头注释）；行格式冻结（as_event.h） */
	as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "decision", NULL,
		    "decision_id=%llu type=%u domain=%u executed=%u "
		    "safety_clamped=%u outcome=%u delta=%lld",
		    decision_id, type, domain, executed, safety_clamped,
		    outcome, delta);
	ev->has_decision_id = 1;
	ev->decision_id = decision_id;
}

void as_event_ai_model(struct as_event *ev, unsigned long long model_id,
		       int loaded, const char *name)
{
	char rname[160];

	as_redact_str(rname, sizeof(rname), rs_model(),
		      name ? name : "");
	as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "model", NULL,
		    "id=%llu op=%s name=%s", model_id,
		    loaded ? "load" : "unload", rname);
}

/* ---- K3d-2（I-9）：EVENT 通道热插拔事件（category 3/4/5，追加契约；
 * 行格式冻结——K3c 既有构造器与 fixture 零改动，见 as_event.h 注释） ---- */

void as_event_ai_device(struct as_event *ev, int removed, const char *dev)
{
	char rdev[160];

	as_redact_str(rdev, sizeof(rdev), rs_dev(), dev ? dev : "?");
	as_event_mk(ev, as_stream_idx(AS_STREAM_EVENT), "device", NULL,
		    "action=%s dev=%s", removed ? "remove" : "probe", rdev);
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
	char raddr[64];

	as_redact_str(raddr, sizeof(raddr), rs_addr(),
		      addr ? addr : "?");
	as_event_mk(ev, as_stream_idx(AS_STREAM_NET),
		    is_new ? "newaddr" : "deladdr", NULL,
		    "if=%d family=%s addr=%s/%u", ifindex,
		    family ? family : "?", raddr, plen);
}

void as_event_net_route(struct as_event *ev, int is_new, const char *family,
			const char *dst, unsigned plen, int oif,
			const char *gw)
{
	char rdst[64], rgw[64];

	as_redact_str(rdst, sizeof(rdst), rs_addr(), dst ? dst : "?");
	if (gw && gw[0]) {
		as_redact_str(rgw, sizeof(rgw), rs_addr(), gw);
		as_event_mk(ev, as_stream_idx(AS_STREAM_NET),
			    is_new ? "newroute" : "delroute", NULL,
			    "family=%s dst=%s/%u oif=%d gw=%s",
			    family ? family : "?", rdst, plen, oif, rgw);
	} else {
		as_event_mk(ev, as_stream_idx(AS_STREAM_NET),
			    is_new ? "newroute" : "delroute", NULL,
			    "family=%s dst=%s/%u oif=%d",
			    family ? family : "?", rdst, plen, oif);
	}
}

/* ---- uevent（KOBJECT_UEVENT） ---- */

void as_event_uevent(struct as_event *ev, const char *action,
		     const char *devpath, const char *subsystem)
{
	char rdev[300];

	as_redact_str(rdev, sizeof(rdev), rs_path(),
		      devpath ? devpath : "?");
	as_event_mk(ev, as_stream_idx(AS_STREAM_UEVENT),
		    action && action[0] ? action : "other", NULL,
		    "dev=%s subsystem=%s", rdev,
		    subsystem ? subsystem : "?");
}

/* ---- nflog ---- */

void as_event_nflog(struct as_event *ev, unsigned hook, unsigned mark,
		    const char *prefix, int has_uid, unsigned uid)
{
	/* nflog attr 前缀是 NUL 结尾内核字符串；无 prefix/uid 时整体省略
	 * （不可用 %s%u 条件拼——%u 恒吞参）；
	 * 脱敏：prefix=路径类（soft mask/strict drop）、uid=身份值
	 * （soft hash/strict drop，设计 §2.2） */
	char rpfx[160], ruid[32];

	if (prefix && prefix[0])
		as_redact_str(rpfx, sizeof(rpfx), rs_path(), prefix);
	if (has_uid)
		as_redact_int(ruid, sizeof(ruid), rs_idval(),
			      (long long)uid);
	if (prefix && prefix[0]) {
		if (has_uid)
			as_event_mk(ev, as_stream_idx(AS_STREAM_NFLOG),
				    "packet", NULL,
				    "hook=%u mark=%u prefix=%s uid=%s",
				    hook, mark, rpfx, ruid);
		else
			as_event_mk(ev, as_stream_idx(AS_STREAM_NFLOG),
				    "packet", NULL,
				    "hook=%u mark=%u prefix=%s", hook, mark,
				    rpfx);
	} else if (has_uid) {
		as_event_mk(ev, as_stream_idx(AS_STREAM_NFLOG), "packet",
			    NULL, "hook=%u mark=%u uid=%s", hook, mark, ruid);
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
	e->pid = ev->pid;
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
		agg.pid = e->pid;
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
