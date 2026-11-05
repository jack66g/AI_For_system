/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_stats.c - 计数与 stats 文件渲染
 */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "as_event.h"
#include "as_stats.h"
#include "as_util.h"

static const char *state_str(int s)
{
	switch (s) {
	case AS_ST_RUNNING:	return "running";
	case AS_ST_STOPPED:	return "stopped";
	default:		return "disabled";
	}
}

void as_stats_init(struct as_stats *st, const struct as_conf *c)
{
	memset(st, 0, sizeof(*st));
	st->started_mono_ms = as_now_mono_ms();
	st->started_real_ms = as_now_real_ms();
	st->pid = (int)getpid();
	st->nl_ai_portid = -1;
	st->sme_ok = -1;	/* 未尝试 */
	snprintf(st->conf_path, sizeof(st->conf_path), "%s", "?");
	snprintf(st->sme_url, sizeof(st->sme_url), "%s",
		 c ? c->sme_url : "?");
}

void as_stats_set_conf_path(struct as_stats *st, const char *path)
{
	snprintf(st->conf_path, sizeof(st->conf_path), "%s", path);
}

#define VALID(idx) ((idx) >= 0 && (idx) < AS_NSTREAMS)

void as_stats_received(struct as_stats *st, int idx)
{
	if (VALID(idx))
		st->per[idx].received++;
}

void as_stats_dedup(struct as_stats *st, int idx)
{
	if (VALID(idx))
		st->per[idx].filtered_dedup++;
}

void as_stats_quota(struct as_stats *st, int idx)
{
	if (VALID(idx))
		st->per[idx].filtered_quota++;
}

void as_stats_written(struct as_stats *st, int idx)
{
	if (VALID(idx)) {
		st->per[idx].written++;
		st->written_total++;
	}
}

void as_stats_render(const struct as_stats *st, int ring_used,
		     long long ring_dropped, FILE *out)
{
	static const char *const order[AS_NSTREAMS] = {
		AS_STREAM_EVENT, AS_STREAM_PROC, AS_STREAM_NET,
		AS_STREAM_UEVENT, AS_STREAM_NFLOG, AS_STREAM_TASKSTATS,
	};
	long long tot_recv = 0, tot_dedup = 0, tot_quota = 0, tot_written = 0;
	long long tot_drop = 0;

	fprintf(out, "# aistreamd stats (key=value, atomic rewrite)\n");
	fprintf(out, "pid=%d\n", st->pid);
	fprintf(out, "uptime_sec=%lld\n",
		(as_now_mono_ms() - st->started_mono_ms) / 1000);
	fprintf(out, "conf=%s\n", st->conf_path);
	fprintf(out, "sme_url=%s\n", st->sme_url);
	fprintf(out, "sme_ok=%d\n", st->sme_ok);
	fprintf(out, "sme_fail=%lld\n", st->sme_fail);
	fprintf(out, "sme_flushed=%lld\n", st->sme_flushed);
	fprintf(out, "ring_used=%d\n", ring_used);
	fprintf(out, "ring_dropped_total=%lld\n", ring_dropped);
	fprintf(out, "nl_ai_portid=%d\n", st->nl_ai_portid);
	for (int i = 0; i < AS_NSTREAMS; i++) {
		const struct as_stream_stats *p = &st->per[i];

		fprintf(out, "%s.state=%s\n", order[i], state_str(p->state));
		fprintf(out, "%s.received=%lld\n", order[i], p->received);
		fprintf(out, "%s.filtered_dedup=%lld\n", order[i],
			p->filtered_dedup);
		fprintf(out, "%s.filtered_quota=%lld\n", order[i],
			p->filtered_quota);
		fprintf(out, "%s.written=%lld\n", order[i], p->written);
		fprintf(out, "%s.buffer_dropped=%lld\n", order[i],
			p->buffer_dropped);
		tot_recv += p->received;
		tot_dedup += p->filtered_dedup;
		tot_quota += p->filtered_quota;
		tot_written += p->written;
		tot_drop += p->buffer_dropped;
	}
	fprintf(out, "totals.received=%lld\n", tot_recv);
	fprintf(out, "totals.filtered_dedup=%lld\n", tot_dedup);
	fprintf(out, "totals.filtered_quota=%lld\n", tot_quota);
	fprintf(out, "totals.written=%lld\n", tot_written);
	fprintf(out, "totals.buffer_dropped=%lld\n", tot_drop);
	/* K3d-2（I-9）热插拔建议流水线计数（advisory-only；executed 恒
	 * false 是代码红线，不在计数面——A/B 看 dropped/advisory_written） */
	fprintf(out, "hotplug.enabled=%d\n", st->hp.enabled);
	fprintf(out, "hotplug.seen=%lld\n", st->hp.seen);
	fprintf(out, "hotplug.infer_ok=%lld\n", st->hp.infer_ok);
	fprintf(out, "hotplug.infer_timeout=%lld\n", st->hp.infer_timeout);
	fprintf(out, "hotplug.infer_skipped=%lld\n", st->hp.infer_skipped);
	fprintf(out, "hotplug.advisory_written=%lld\n",
		st->hp.advisory_written);
	fprintf(out, "hotplug.dropped_noquota=%lld\n",
		st->hp.dropped_noquota);
}

int as_stats_write_file(const struct as_stats *st, const char *path,
			int ring_used, long long ring_dropped)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *m = open_memstream(&buf, &len);
	int rc;

	if (!m)
		return -1;
	as_stats_render(st, ring_used, ring_dropped, m);
	fclose(m);
	if (!buf)
		return -1;
	rc = as_write_file_atomic(path, buf, len);
	free(buf);
	return rc;
}
