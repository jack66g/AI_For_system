/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_decisions.c - /proc/ai/decisions 消费面（T8 遗留接线）
 *
 * 管道：DECISIONS_INTERVAL_SEC 轮询 ring（最新在前）→ 23 字段解析
 *   → 游标去重（id 单调）→ 坏行跳过/空洞/回绕计数（如实）
 *   → 合成事件（既有 event→ai 18.01 口径，as_event_decision）
 *   → 日批累积 → PARQUET_FLUSH_* 节流写 T8 decisions parquet
 *   → 保留策略（as_pq_retain_root，与 telemetry 链同规则）。
 *
 * 内核行格式（ai_procfs.c ai_proc_dec_record，与 as_outcome.c
 * as_oc_scan_decisions 的 sscanf 同源对齐；0x%04x evid 由 %llx 的
 * 0x 前缀兼容语义吃掉）：
 *   id=%llu trig_ts=%llu trig_evid=0x%04x dec_ts=%llu type=%u
 *   data=%llu:…:%llu exec_ts=%llu outcome_ts=%llu outcome=%u
 *   delta=%lld ver=%u conf=%u domain=%u src=%u executed=%u
 *   safety_clamped=%u
 * K1 D4 行尾 append-only 尾巴（pre= 之后）：trace=0x%016llx:0x%016llx
 * cost=%llu 恒渲染；intent=/parent=/agent=/expected=/se= 非零才
 * 渲染（见 as_decisions.h as_dec_parse_tail；老行零列不坏行）。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "as_decisions.h"
#include "as_pq_sink.h"
#include "as_util.h"

/* root 归一（init/set_root 保证无尾部 '/'，"/" 除外）；sub 以 '/' 开头 */
/* K11 golden：AS_DUMP=1 时决策记录逐条 stderr dump（测试口径，
 * 常驻仅一次 getenv 判定，零开销） */
static int as_dec_dump_enabled(void)
{
	static int dump = -1;

	if (dump < 0)
		dump = (getenv("AS_DUMP") && getenv("AS_DUMP")[0] == '1');
	return dump;
}

static void dec_path(char *buf, size_t cap, const char *root,
		     const char *sub)
{
	snprintf(buf, cap, "%s%s", root, sub);
}

int as_dec_parse_line(const char *line, struct as_dec_row *out)
{
	unsigned long long rid, t1, evid, t2, e1, ots;
	unsigned long long d[8];
	unsigned type, oc, ver, conf, dom, src, exec, sc;
	long long delta;

	if (!line || !out)
		return -1;
	if (sscanf(line,
		   "id=%llu trig_ts=%llu trig_evid=%llx dec_ts=%llu "
		   "type=%u data=%llu:%llu:%llu:%llu:%llu:%llu:%llu:"
		   "%llu exec_ts=%llu outcome_ts=%llu outcome=%u "
		   "delta=%lld ver=%u conf=%u domain=%u src=%u "
		   "executed=%u safety_clamped=%u",
		   &rid, &t1, &evid, &t2, &type,
		   &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6], &d[7],
		   &e1, &ots, &oc, &delta, &ver, &conf, &dom, &src,
		   &exec, &sc) != 23)
		return -1;
	memset(out, 0, sizeof(*out));
	out->id = rid;
	out->trig_ts = t1;
	out->trig_evid = evid;
	out->dec_ts = t2;
	out->type = type;
	for (int i = 0; i < 8; i++)
		out->data[i] = d[i];
	out->exec_ts = e1;
	out->outcome_ts = ots;
	out->outcome = oc;
	out->delta = delta;
	out->ver = ver;
	out->conf = conf;
	out->domain = dom;
	out->src = src;
	out->executed = exec;
	out->safety_clamped = sc;
	/* K1 D4/D10：23 字段全中后扫行尾尾巴（老行=零列，未知 token
	 * 忽略——oc_parse_pre 容忍口径；坏行判定不受尾巴影响） */
	as_dec_parse_tail(line, out);
	return 0;
}

/* K1 D4：行尾尾巴解析（独立助手，单测冻结口径；详见头注） */
void as_dec_parse_tail(const char *line, struct as_dec_row *out)
{
	char copy[512];
	char *save = NULL;
	char *tok;

	if (!line || !out)
		return;
	snprintf(copy, sizeof(copy), "%s", line);
	for (tok = strtok_r(copy, " \t\r\n", &save); tok;
	     tok = strtok_r(NULL, " \t\r\n", &save)) {
		unsigned long long hi, lo, v;
		long long sv;
		unsigned u;

		if (sscanf(tok, "trace=0x%16llx:0x%16llx", &hi, &lo) == 2 ||
		    sscanf(tok, "trace=%16llx:%16llx", &hi, &lo) == 2) {
			out->trace_hi = hi;
			out->trace_lo = lo;
		} else if (sscanf(tok, "cost=%llu", &v) == 1) {
			out->cost_ns = v;
		} else if (sscanf(tok, "intent=0x%16llx", &v) == 1 ||
			   sscanf(tok, "intent=%16llx", &v) == 1) {
			out->intent_id = v;
		} else if (sscanf(tok, "parent=0x%16llx", &v) == 1 ||
			   sscanf(tok, "parent=%16llx", &v) == 1) {
			out->parent_id = v;
		} else if (sscanf(tok, "agent=%u", &u) == 1) {
			out->agent_id = u;
		} else if (sscanf(tok, "expected=%lld", &sv) == 1) {
			out->expected = sv;
		} else if (sscanf(tok, "se=0x%8x", &u) == 1 ||
			   sscanf(tok, "se=%8x", &u) == 1) {
			out->side_effect_mask = u;
		}
		/* 未知 token（pre=<…> 等 23 头字段）：忽略（不坏行） */
	}
}

/* ---- 行结构 → pq_dec_row（23 列 1:1 + K1 尾 8 列；u64→i64 同宽
 * 不截断；老行尾巴字段恒 0 落零值列） ---- */
static void dec_to_pq(const struct as_dec_row *r, struct pq_dec_row *w)
{
	memset(w, 0, sizeof(*w));
	w->decision_id = (long long)r->id;
	w->trigger_ts = (long long)r->trig_ts;
	w->trigger_event_id = (long long)r->trig_evid;
	w->decision_ts = (long long)r->dec_ts;
	w->decision_type = (int8_t)r->type;
	for (int i = 0; i < 8; i++)
		w->data[i] = (long long)r->data[i];
	w->exec_ts = (long long)r->exec_ts;
	w->outcome_ts = (long long)r->outcome_ts;
	w->outcome = (int8_t)r->outcome;
	w->metric_delta = r->delta;
	w->model_version = (int32_t)r->ver;
	w->confidence = (int8_t)r->conf;
	w->domain = (int8_t)r->domain;
	w->source = (int8_t)r->src;
	w->executed = (int8_t)r->executed;
	w->safety_clamped = (int8_t)r->safety_clamped;
	/* K1 D10 append-only v2 尾 8 列 */
	w->trace_hi = (int64_t)r->trace_hi;
	w->trace_lo = (int64_t)r->trace_lo;
	w->intent_id = (int64_t)r->intent_id;
	w->parent_id = (int64_t)r->parent_id;
	w->agent_id = (int32_t)r->agent_id;
	w->expected = r->expected;
	w->cost_ns = (int64_t)r->cost_ns;
	w->side_effect_mask = (int32_t)r->side_effect_mask;
}

int as_decisions_init(struct as_decisions *d, struct as_conf *c,
		      struct as_stats *st)
{
	memset(d, 0, sizeof(*d));
	d->conf = c;
	d->stats = st;
	snprintf(d->root, sizeof(d->root), "/");
	st->dec.enabled = c->decisions_enabled ? 1 : 0;
	if (!c->decisions_enabled) {
		as_log("decisions ingest: disabled (DECISIONS_ENABLED=0) - "
		       "zero-overhead poll");
		return 0;
	}
	d->cap = (size_t)c->decisions_batch_max;
	d->batch = calloc(d->cap, sizeof(*d->batch));
	if (!d->batch) {
		d->cap = 0;
		return -1;
	}
	if (strcmp(c->decisions_mock_root, "/") != 0 &&
	    c->decisions_mock_root[0]) {
		as_decisions_set_root(d, c->decisions_mock_root);
		as_warn_ratelimit("dec-mockroot", 3600000,
				  "decisions ingest: MOCK ROOT %s "
				  "(TEST ONLY - not for production)",
				  d->root);
	}
	if (!c->parquet_enabled)
		as_warn_ratelimit("dec-nopq", 3600000,
				  "decisions ingest: PARQUET_ENABLED=0 - "
				  "decisions parquet chain suppressed "
				  "(write_skipped counts; synthetic events "
				  "still flow)");
	as_log("decisions ingest: enabled (interval=%llds scan_max=%lld "
	       "batch_max=%lld source=%s) - C1 read-only consumption",
	       c->decisions_interval_sec, c->decisions_scan_max,
	       c->decisions_batch_max, AS_DEC_SUB);
	return 0;
}

void as_decisions_set_root(struct as_decisions *d, const char *root)
{
	snprintf(d->root, sizeof(d->root), "%s",
		 root && root[0] ? root : "/");
	{
		size_t l = strlen(d->root);

		if (l > 1 && d->root[l - 1] == '/')
			d->root[l - 1] = '\0';
		if (!d->root[0])
			snprintf(d->root, sizeof(d->root), "/");
	}
	as_log("decisions ingest: root prefix %s (TEST/mock path)", d->root);
}

void as_decisions_set_sink(struct as_decisions *d,
			   void (*emit)(struct as_event *ev, void *ud),
			   void *ud)
{
	d->emit = emit;
	d->emit_ud = ud;
}

/* 批有序插入（decision_ts 升序、同 ts 按 id——真内核两键同向单调，
 * 常态尾部 O(1) 追加；晚到旧行按位插入使日分组天然连续，重写不丢行）。
 * 容量满丢最旧+计数。 */
static void dec_batch_push(struct as_decisions *d, const struct pq_dec_row *r)
{
	size_t pos;

	if (d->n >= d->cap) {
		/* 丢最旧（同名覆盖语义下的有界内存取舍；计数如实上报） */
		memmove(&d->batch[0], &d->batch[1],
			(d->cap - 1) * sizeof(*d->batch));
		d->n = d->cap - 1;
		d->stats->dec.dropped++;
	}
	pos = d->n;
	while (pos > 0 &&
	       (d->batch[pos - 1].decision_ts > r->decision_ts ||
		(d->batch[pos - 1].decision_ts == r->decision_ts &&
		 d->batch[pos - 1].decision_id > r->decision_id))) {
		d->batch[pos] = d->batch[pos - 1];
		pos--;
	}
	d->batch[pos] = *r;
	d->n++;
	d->dirty = 1;
}

/* 合成事件（既有 event 管道；category=decision；口径见头注 4） */
static void dec_emit_event(struct as_decisions *d,
			   const struct as_dec_row *r)
{
	struct as_event ev;

	if (!d->emit || !d->conf->decisions_write_sme)
		return;
	as_event_decision(&ev, r->id, r->type, r->domain, r->executed,
			  r->safety_clamped, r->outcome, r->delta,
			  r->trace_hi, r->trace_lo);
	/* L1 棒①：31 列原料透传评分器（decisions_emit 挂点，as_value；
	 * 老 K1 v2 行无尾=0——如实评分（|outcome−0|=0 反差） */
	ev.dec_material = 1;
	ev.dec_outcome = (long long)r->outcome;
	ev.dec_expected = r->expected;
	ev.dec_cost_ns = r->cost_ns;
	ev.dec_confidence = (int)r->conf;
	ev.dec_agent_id = (int)r->agent_id;
	d->emit(&ev, d->emit_ud);
	d->stats->dec.events++;
}

/*
 * 轮询一轮：读文件 → 解析收集 → 游标/去重/计数 → 批累积 → 事件。
 * 0=正常（含无新行）；-1=读失败（noiface 计数已做，诚实降级不重试）。
 */
static int dec_poll_once(struct as_decisions *d)
{
	char path[384];
	FILE *f;
	char line[512];
	struct as_dec_row *rows = NULL, *nw = NULL;
	size_t rows_n = 0, rows_cap = 0, new_n = 0;
	unsigned long long file_max = 0;
	int file_nonempty = 0;
	long long scan_max = d->conf->decisions_scan_max;
	size_t i, j;

	dec_path(path, sizeof(path), d->root, AS_DEC_SUB);
	f = fopen(path, "r");
	if (!f) {
		d->stats->dec.noiface_polls++;
		as_warn_ratelimit("dec-noiface", 60000,
				  "decisions ingest: open %s: %s (no AIKernel "
				  "face - honest degrade, poll skipped)",
				  path, strerror(errno));
		return -1;
	}
	rows_cap = 64;
	rows = calloc(rows_cap, sizeof(*rows));
	if (!rows) {
		fclose(f);
		return -1;
	}
	d->stats->dec.polls++;
	while (rows_n < (size_t)scan_max && fgets(line, sizeof(line), f)) {
		struct as_dec_row r;

		if (as_dec_parse_line(line, &r) != 0) {
			/* 坏行跳过计数（I8 §5.6：ring 尾条跨行损坏实测在） */
			d->stats->dec.bad_lines++;
			d->stats->dec.rows_seen++;
			continue;
		}
		d->stats->dec.rows_seen++;
		file_nonempty = 1;
		if (as_dec_dump_enabled())
			fprintf(stderr,
				"ASDUMP id=%llu type=%u trace=%016llx:%016llx "
				"cost_ns=%llu intent=%llu parent=%llu agent=%u "
				"executed=%u outcome=%u outcome_ts=%llu se=%u\n",
				r.id, r.type, r.trace_hi, r.trace_lo,
				r.cost_ns, r.intent_id, r.parent_id,
				r.agent_id, r.executed, r.outcome,
				r.outcome_ts, r.side_effect_mask);
		if (r.id > file_max)
			file_max = r.id;
		if (rows_n == rows_cap) {
			struct as_dec_row *nr;

			if (rows_cap >= (size_t)scan_max)
				break;
			rows_cap *= 2;
			if (rows_cap > (size_t)scan_max)
				rows_cap = (size_t)scan_max;
			nr = realloc(rows, rows_cap * sizeof(*rows));
			if (!nr)
				break;
			rows = nr;
		}
		rows[rows_n++] = r;
	}
	fclose(f);

	if (file_nonempty && d->have_cursor && file_max < d->cursor) {
		/*
		 * 可见 ring 最大 id 全部落后于游标：ring 回绕覆盖或内核
		 * 重启（id 计数重置）——单调 id 假设下二者不可区分，如实
		 * 计数 + journal；boot 级判定（uptime/boot_id）留 qemu 真
		 * 内核轮拍板（UE-REPORT 移交登记）。游标回贴可见最大 id：
		 * 重启后新决策（自 1 重新计数）从 file_max 之后恢复摄取，
		 * 重启早期（id≤file_max）如实丢失不重复计。
		 */
		d->stats->dec.rebases++;
		as_warn_ratelimit("dec-rebase", 3600000,
				  "decisions ingest: ring fully behind cursor "
				  "(file_max=%llu cursor=%llu) - overflow wrap "
				  "or reboot; cursor repositioned, early "
				  "post-reboot rows suppressed (dup guard)",
				  file_max, d->cursor);
		d->cursor = file_max;
	}

	/* 过滤新行（id>游标）并按 decision_ts 升序插入排序（ring 最新在
	 * 前；真内核 id 与 ts 同向单调——按 ts 排使日分组天然连续，晚到
	 * 同日行并入既有日组重写，无覆盖丢行） */
	nw = calloc(rows_n ? rows_n : 1, sizeof(*nw));
	if (!nw) {
		free(rows);
		return -1;
	}
	for (i = 0; i < rows_n; i++) {
		if (d->have_cursor && rows[i].id <= d->cursor) {
			d->stats->dec.dup_skip++;
			continue;
		}
		for (j = new_n; j > 0 &&
		     (nw[j - 1].dec_ts > rows[i].dec_ts ||
		      (nw[j - 1].dec_ts == rows[i].dec_ts &&
		       nw[j - 1].id > rows[i].id)); j--)
			nw[j] = nw[j - 1];
		nw[j] = rows[i];
		new_n++;
	}
	/* 空洞：最小新 id 与游标间的缺口（两轮 poll 间 ring 覆盖丢失） */
	if (d->have_cursor && new_n && nw[0].id > d->cursor + 1)
		d->stats->dec.gaps += (long long)(nw[0].id - d->cursor - 1);

	for (i = 0; i < new_n; i++) {
		struct pq_dec_row w;

		dec_to_pq(&nw[i], &w);
		dec_batch_push(d, &w);
		if (nw[i].id > d->cursor || !d->have_cursor)
			d->cursor = nw[i].id;
		d->have_cursor = 1;
		d->stats->dec.rows_new++;
		dec_emit_event(d, &nw[i]);
	}
	free(nw);
	free(rows);
	return 0;
}

/*
 * 落盘：跨日分组（decision_ts → UTC 日，btime 语义同 telemetry 链）
 * → 每组 as_pq_write_decisions（同名覆盖=REF 语义，组内含该日累积
 * 全量——批保留不剪：晚到的同日行并入下次重写，无覆盖丢行窗口；
 * 批容量由 DECISIONS_BATCH_MAX 有界，溢出丢最旧+计数）
 * → 保留策略（与 telemetry 链同规则）。
 */
static void dec_flush(struct as_decisions *d, long long now_mono_ms)
{
	char root[384];
	int64_t btime;
	size_t i, s;
	int any_fail = 0;

	if (!d->dirty || d->n == 0)
		return;
	if (!d->conf->parquet_enabled) {
		/* PARQUET_ENABLED=0：不写文件（init 已 journal 一次性明示） */
		d->stats->dec.write_skipped++;
		d->dirty = 0;
		d->last_flush_mono_ms = now_mono_ms;
		return;
	}
	dec_path(root, sizeof(root), d->conf->parquet_dir, "");
	{
		size_t l = strlen(root);

		if (l > 1 && root[l - 1] == '/')
			root[l - 1] = '\0';
	}
	if (as_pq_ensure_root(root) != 0) {
		any_fail = 1;
		d->stats->dec.write_fail++;
		as_warn_ratelimit("dec-write", 60000,
				  "decisions ingest: ensure_root %s failed: "
				  "%s (rows retained, retry next flush)",
				  root, strerror(errno));
		d->last_flush_mono_ms = now_mono_ms;
		return;
	}
	btime = as_pq_btime();

	i = 0;
	while (i < d->n) {
		char day_i[16], day_j[16];
		struct pq_write_stat wst;
		int rc;

		as_pq_day_from_ts(d->batch[i].decision_ts, btime, day_i);
		s = i + 1;
		while (s < d->n) {
			as_pq_day_from_ts(d->batch[s].decision_ts, btime,
					  day_j);
			if (strcmp(day_i, day_j) != 0)
				break;
			s++;
		}
		memset(&wst, 0, sizeof(wst));
		rc = as_pq_write_decisions(root, &d->batch[i], s - i, btime,
					   &wst);
		if (rc < 0) {
			any_fail = 1;
			d->stats->dec.write_fail++;
			as_warn_ratelimit("dec-write", 60000,
					  "decisions ingest: write_decisions "
					  "day=%s failed: %s (rows retained, "
					  "retry next flush)",
					  day_i, strerror(errno));
		} else {
			d->stats->dec.flushes++;
			d->stats->dec.rows_written += rc;
			d->stats->dec.files += wst.files;
			d->stats->dec.bytes += wst.bytes;
			as_log_debug("decisions parquet: day=%s rows=%zd "
				     "(cumulative rewrite, REF overwrite "
				     "semantics)", day_i, s - i);
		}
		i = s;	/* 无论成败组指针前进（失败组行保留批内重试） */
	}
	d->dirty = any_fail;
	d->last_flush_mono_ms = now_mono_ms;
	/* 保留策略（与 telemetry 链同规则） */
	as_pq_retain_root(root, d->conf->parquet_max_gb, btime, d->stats);
}

void as_decisions_tick(struct as_decisions *d, long long now_mono_ms)
{
	if (!d->conf->decisions_enabled)
		return;
	if (d->last_poll_mono_ms == 0 ||
	    now_mono_ms - d->last_poll_mono_ms >=
		    d->conf->decisions_interval_sec * 1000) {
		d->last_poll_mono_ms = now_mono_ms;
		dec_poll_once(d);
	}
	/* 节流：PARQUET_FLUSH_SEC 到时或批行数满（与 telemetry 链同参） */
	if (d->dirty &&
	    (now_mono_ms - d->last_flush_mono_ms >=
		     d->conf->parquet_flush_sec * 1000 ||
	     (long long)d->n >= d->conf->parquet_flush_rows))
		dec_flush(d, now_mono_ms);
}

void as_decisions_close(struct as_decisions *d)
{
	if (!d->conf || !d->conf->decisions_enabled)
		return;
	dec_flush(d, as_now_mono_ms());
	free(d->batch);
	d->batch = NULL;
	d->n = d->cap = 0;
}

long long as_decisions_due_ms(const struct as_decisions *d,
			      long long now_mono_ms)
{
	long long next;

	if (!d->conf || !d->conf->decisions_enabled)
		return -1;
	next = d->last_poll_mono_ms +
	       d->conf->decisions_interval_sec * 1000;
	if (next <= now_mono_ms)
		return 0;
	return next - now_mono_ms;
}
