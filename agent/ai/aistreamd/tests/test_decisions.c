/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_decisions.c - as_decisions 单测（T8 遗留接线）
 *
 * mock procfs 夹具（ring 格式样本=ai_proc_dec_record 23 字段行，
 * I8-DATA-REPORT §1 实测口径）→ 游标/去重/坏行/空洞/回绕/落盘断言。
 * 落盘读回走 as_pq_file_stats（footer num_rows——T8 writer-only 读面）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "as_conf.h"
#include "as_decisions.h"
#include "as_event.h"
#include "aistreamd/as_parquet.h"
#include "as_stats.h"
#include "as_util.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

static char mockdir[96], rootdir[96];

/* 事件出口计数（+末事件快照供行格式断言） */
static int ev_count;
static char ev_last_line[AS_LINE_MAX];
static unsigned long long ev_last_id;

static void test_sink(struct as_event *ev, void *u)
{
	(void)u;
	ev_count++;
	snprintf(ev_last_line, sizeof(ev_last_line), "%s", ev->line);
	ev_last_id = ev->decision_id;
}

/* 内核行（ai_proc_dec_record 同格式；id/dec_ts 可参数化） */
static void mkline(char *buf, size_t cap, unsigned long long id,
		   unsigned long long dec_ts, unsigned executed,
		   unsigned sc, long long delta)
{
	snprintf(buf, cap,
		 "id=%llu trig_ts=%llu trig_evid=0x%04x dec_ts=%llu "
		 "type=%u data=%llu:%llu:%llu:%llu:%llu:%llu:%llu:%llu "
		 "exec_ts=%llu outcome_ts=%llu outcome=%u delta=%lld "
		 "ver=%u conf=%u domain=%u src=%u executed=%u "
		 "safety_clamped=%u\n",
		 id, dec_ts - 1000000ULL, (unsigned)(0x0401),
		 dec_ts, 1u,
		 id, 42ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
		 dec_ts + 500000ULL, 0ULL, 0u, delta, 1u, 80u, 2u, 1u,
		 executed, sc);
}

static void write_ring(const char *lines)
{
	char path[192];
	FILE *f;

	snprintf(path, sizeof(path), "%s/proc/ai/decisions", mockdir);
	f = fopen(path, "w");
	if (!f) {
		printf("FATAL: fixture open %s\n", path);
		exit(2);
	}
	fputs(lines, f);
	fclose(f);
}

/* mockdir = mock 树根（模块拼 /proc/ai/decisions）；预建 proc/ai */
static void mock_setup(const char *base)
{
	char cmd[192];

	snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s/proc/ai",
		 base, base);
	snprintf(mockdir, sizeof(mockdir), "%s", base);
	if (system(cmd) != 0)
		exit(2);
}

static void dec_file_stats(const char *day, struct pq_file_stats *st)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/decisions/%s/decisions.parquet",
		 rootdir, day);
	memset(st, 0, sizeof(*st));
	CHECK(as_pq_file_stats(path, st) == 0, "footer read decisions.parquet");
}

static void mk_conf(struct as_conf *c, int parquet)
{
	as_conf_defaults(c);
	c->decisions_enabled = 1;
	c->decisions_interval_sec = 1;
	c->decisions_scan_max = 4096;
	c->decisions_batch_max = 8192;
	c->decisions_write_sme = 1;
	snprintf(c->decisions_mock_root, sizeof(c->decisions_mock_root),
		 "%s", mockdir);
	c->parquet_enabled = parquet;
	snprintf(c->parquet_dir, sizeof(c->parquet_dir), "%s", rootdir);
	c->parquet_flush_sec = 1;
	c->parquet_flush_rows = 128;
}

int main(void)
{
	struct as_conf c;
	struct as_stats st;
	struct as_decisions d;
	char buf[1024], lines[8192];
	int64_t btime = as_pq_btime();
	long long wall_ms = (long long)(as_now_real_ms());
	int64_t ts_now_ns, ts_old_ns;
	char day_now[16], day_old[16];
	char path[192];

	/* 当日/前一日 ts（同 REF 换算：墙钟-btime→单调 ns；day 由
	 * as_pq_day_from_ts 动态算——午夜竞态免疫） */
	ts_now_ns = (int64_t)(wall_ms - btime * 1000) * 1000000LL;
	ts_old_ns = ts_now_ns - 86400LL * 1000000000LL;
	as_pq_day_from_ts(ts_now_ns, btime, day_now);
	as_pq_day_from_ts(ts_old_ns, btime, day_old);

	snprintf(rootdir, sizeof(rootdir), "/tmp/as-dec-%d/pq",
		 (int)getpid());
	{
		char cmd[256];

		snprintf(cmd, sizeof(cmd), "rm -rf /tmp/as-dec-%d "
			 "/tmp/as-dec-%d-nok", (int)getpid(), (int)getpid());
		if (system(cmd) != 0)
			return 2;
	}
	{
		char base[96];

		snprintf(base, sizeof(base), "/tmp/as-dec-%d", (int)getpid());
		mock_setup(base);
	}

	/* ---- 0) 行解析纯函数 ---- */
	{
		struct as_dec_row r;

		mkline(buf, sizeof(buf), 7, 123456789ULL, 2, 1, -15);
		CHECK(as_dec_parse_line(buf, &r) == 0, "parse good line");
		CHECK(r.id == 7 && r.trig_evid == 0x0401 && r.type == 1 &&
		      r.data[0] == 7 && r.data[1] == 42 &&
		      r.executed == 2 && r.safety_clamped == 1 &&
		      r.delta == -15 && r.domain == 2 && r.src == 1 &&
		      r.ver == 1 && r.conf == 80,
		      "parse fields 1:1");
		CHECK(as_dec_parse_line("id=1 trig only garbage\n", &r) == -1,
		      "parse bad line rejected");
		CHECK(as_dec_parse_line("", &r) == -1, "parse empty rejected");
		CHECK(as_dec_parse_line(
			      "id=1 trig_ts=2 trig_evid=0x1 dec_ts=3 type=4 "
			      "data=1:2:3:4:5:6:7:8 exec_ts=9 outcome_ts=10 "
			      "outcome=0 delta=0 ver=1 conf=2 domain=3 src=4 "
			      "executed=0 safety_clamped=0", &r) == 0,
		      "parse line without trailing NL");
		/* U66（K66 §5 兼容契约）：#66 起 decisions 行尾 append-only
		 * 追加 pre=<…>——旧解析器按行尾未知字段忽略，23 列 schema
		 * 零改动；坏行计数不得因新字段递增（下方 §3 摄取共证）。
		 * 新旧混合夹具：none/单 s64（可负）/多参/畸形尾随四种形态
		 * 全部按好行解析（23 字段全中）。 */
		CHECK(as_dec_parse_line(
			      "id=11 trig_ts=2 trig_evid=0x1 dec_ts=3 type=4 "
			      "data=1:2:3:4:5:6:7:8 exec_ts=9 outcome_ts=10 "
			      "outcome=1 delta=-7 ver=1 conf=2 domain=3 src=4 "
			      "executed=2 safety_clamped=0 pre=-12\n", &r) == 0 &&
		      r.id == 11 && r.delta == -7 && r.executed == 2,
		      "U66 pre=<s64> tolerated (negative s64)");
		CHECK(as_dec_parse_line(
			      "id=12 trig_ts=2 trig_evid=0x1 dec_ts=3 type=4 "
			      "data=1:2:3:4:5:6:7:8 exec_ts=9 outcome_ts=10 "
			      "outcome=0 delta=0 ver=1 conf=2 domain=3 src=4 "
			      "executed=1 safety_clamped=0 pre=none\n", &r) == 0 &&
		      r.id == 12 && r.executed == 1,
		      "U66 pre=none tolerated");
		CHECK(as_dec_parse_line(
			      "id=13 trig_ts=2 trig_evid=0x1 dec_ts=3 type=4 "
			      "data=1:2:3:4:5:6:7:8 exec_ts=9 outcome_ts=10 "
			      "outcome=0 delta=0 ver=1 conf=2 domain=3 src=4 "
			      "executed=1 safety_clamped=0 pre=5:-3:7\n", &r) == 0 &&
		      r.id == 13,
		      "U66 multi-param pre tolerated");
		CHECK(as_dec_parse_line(
			      "id=14 trig_ts=2 trig_evid=0x1 dec_ts=3 type=4 "
			      "data=1:2:3:4:5:6:7:8 exec_ts=9 outcome_ts=10 "
			      "outcome=0 delta=0 ver=1 conf=2 domain=3 src=4 "
			      "executed=1 safety_clamped=0 pre=garbage\n", &r) == 0,
		      "U66 malformed pre tail still 23-field good line");
	}

	/* ---- 1) 首轮摄取：ring 最新在前 → 升序入批 + 事件 + 落盘 ---- */
	mk_conf(&c, 1);
	as_stats_init(&st, &c);
	snprintf(st.conf_path, sizeof(st.conf_path), "%s", "test");
	CHECK(as_decisions_init(&d, &c, &st) == 0, "init enabled");
	as_decisions_set_sink(&d, test_sink, NULL);

	mkline(buf, sizeof(buf), 3, (unsigned long long)ts_now_ns, 2, 0, 0);
	snprintf(lines, sizeof(lines), "%s", buf);
	mkline(buf, sizeof(buf), 2, (unsigned long long)ts_now_ns, 2, 0, 0);
	strcat(lines, buf);
	mkline(buf, sizeof(buf), 1, (unsigned long long)ts_now_ns, 0, 0, 0);
	strcat(lines, buf);
	write_ring(lines);

	ev_count = 0;
	as_decisions_tick(&d, 1000);
	CHECK(st.dec.polls == 1, "poll counted");
	CHECK(st.dec.rows_new == 3, "3 new rows ingested");
	CHECK(st.dec.bad_lines == 0, "no bad lines");
	CHECK(d.cursor == 3 && d.n == 3, "cursor/batch=3");
	CHECK(ev_count == 3, "3 synthetic events");
	CHECK(strncmp(ev_last_line,
		      "[kern] event decision decision_id=", 34) == 0,
	      "event line format frozen");
	CHECK(ev_last_id == 3, "event carries decision_id");
	CHECK(st.dec.dup_skip == 0 && st.dec.gaps == 0, "no dup/gap first");
	/* flush（flush_sec=1s：now=1000 → last_flush=0 已超时） */
	as_decisions_tick(&d, 1000);
	CHECK(st.dec.flushes == 1, "flush happened");
	{
		struct pq_file_stats fs;

		dec_file_stats(day_now, &fs);
		CHECK(fs.num_rows == 3, "parquet num_rows=3");
	}

	/* ---- 2) 同文件复轮：游标去重 ---- */
	as_decisions_tick(&d, 3000);
	CHECK(st.dec.dup_skip == 3, "re-poll deduped 3");
	CHECK(st.dec.rows_new == 3, "no new rows on re-poll");
	CHECK(d.n == 3, "batch unchanged");
	/* 无新行 → 无 flush 增量（dirty=0） */
	as_decisions_tick(&d, 3000);
	CHECK(st.dec.flushes == 1, "no extra flush when clean");

	/* ---- 3) 追加新决策（含坏行 + 空洞） ---- */
	mkline(buf, sizeof(buf), 9, (unsigned long long)ts_now_ns, 1, 1, -30);
	/* U66：id=9 行尾追加 #66 pre= 字段（新旧行混合夹具）——摄取照常
	 * （坏行计数仍只数真坏行，pre= 不递增 bad_lines） */
	{
		size_t l = strlen(buf);

		if (l && buf[l - 1] == '\n')
			buf[l - 1] = '\0';
		strncat(buf, " pre=-30\n", sizeof(buf) - strlen(buf) - 1);
	}
	snprintf(lines, sizeof(lines), "%s", buf);
	mkline(buf, sizeof(buf), 8, (unsigned long long)ts_now_ns, 1, 0, 0);
	strcat(lines, buf);
	strcat(lines, "id=4 truncated garbage line without fields\n");
	strcat(lines, "totally not a decision line\n");
	mkline(buf, sizeof(buf), 3, (unsigned long long)ts_now_ns, 2, 0, 0);
	strcat(lines, buf);
	mkline(buf, sizeof(buf), 1, (unsigned long long)ts_now_ns, 0, 0, 0);
	strcat(lines, buf);
	write_ring(lines);
	as_decisions_tick(&d, 5000);
	CHECK(st.dec.rows_new == 5, "ids 8,9 ingested (gap 4..7 counted)");
	CHECK(st.dec.bad_lines == 2, "2 bad lines skipped");
	CHECK(st.dec.gaps == 4, "gap ids 4..7 counted");
	CHECK(st.dec.dup_skip == 5, "old ids 3,1 re-seen deduped");
	CHECK(d.cursor == 9 && d.n == 5, "batch=5 cursor=9");
	as_decisions_tick(&d, 5000);
	{
		struct pq_file_stats fs;

		dec_file_stats(day_now, &fs);
		CHECK(fs.num_rows == 5, "parquet cumulative rewrite num_rows=5");
	}

	/* ---- 4) 回绕/重启：全旧 id → rebase + 游标回贴 ---- */
	mkline(buf, sizeof(buf), 2, (unsigned long long)ts_now_ns, 1, 0, 0);
	snprintf(lines, sizeof(lines), "%s", buf);
	mkline(buf, sizeof(buf), 1, (unsigned long long)ts_now_ns, 1, 0, 0);
	strcat(lines, buf);
	write_ring(lines);
	as_decisions_tick(&d, 7000);
	CHECK(st.dec.rebases == 1, "rebase detected");
	CHECK(d.cursor == 2, "cursor repositioned to file_max");
	/* 重启后新 id 3,4 → 摄取（>回贴游标） */
	mkline(buf, sizeof(buf), 4, (unsigned long long)ts_now_ns, 1, 0, 0);
	snprintf(lines, sizeof(lines), "%s", buf);
	mkline(buf, sizeof(buf), 3, (unsigned long long)ts_now_ns, 1, 0, 0);
	strcat(lines, buf);
	mkline(buf, sizeof(buf), 1, (unsigned long long)ts_now_ns, 1, 0, 0);
	strcat(lines, buf);
	write_ring(lines);
	as_decisions_tick(&d, 9000);
	CHECK(st.dec.rows_new == 7, "post-rebase ids 3,4 ingested");
	/* dup_skip 账：步骤2=3 + 步骤3(3,1)=2 + 回绕轮(2,1)=2 + 本轮(1)=1 */
	CHECK(st.dec.dup_skip == 8, "dup accounting across rebase");
	CHECK(d.n == 7, "batch=7 (no dup rows)");
	as_decisions_tick(&d, 9000);
	{
		struct pq_file_stats fs;

		dec_file_stats(day_now, &fs);
		CHECK(fs.num_rows == 7, "parquet num_rows=7 no dup");
	}
	as_decisions_close(&d);

	/* ---- 5) 跨日分组 + 旧日组出批 ---- */
	mk_conf(&c, 1);
	as_stats_init(&st, &c);
	snprintf(st.conf_path, sizeof(st.conf_path), "%s", "test");
	CHECK(as_decisions_init(&d, &c, &st) == 0, "init (day split)");
	as_decisions_set_sink(&d, test_sink, NULL);
	mkline(buf, sizeof(buf), 2, (unsigned long long)ts_old_ns, 1, 0, 0);
	snprintf(lines, sizeof(lines), "%s", buf);
	mkline(buf, sizeof(buf), 1, (unsigned long long)ts_old_ns, 1, 0, 0);
	strcat(lines, buf);
	mkline(buf, sizeof(buf), 3, (unsigned long long)ts_now_ns, 1, 0, 0);
	strcat(lines, buf);
	write_ring(lines);
	as_decisions_tick(&d, 1000);
	as_decisions_tick(&d, 1000);
	CHECK(st.dec.flushes == 2, "two day-groups written");
	{
		struct pq_file_stats f_old, f_now;

		dec_file_stats(day_old, &f_old);
		dec_file_stats(day_now, &f_now);
		CHECK(f_old.num_rows == 2, "old day file rows=2");
		CHECK(f_now.num_rows == 1, "today file rows=1");
	}
	CHECK(d.n == 3, "batch retained (no drop-after-write)");
	/* 晚到同日行不丢（冒烟教训回归）：追加旧日新 id=4 → 重写含全部旧日组 */
	mkline(buf, sizeof(buf), 4, (unsigned long long)ts_old_ns, 1, 0, 0);
	snprintf(lines, sizeof(lines), "%s", buf);
	write_ring(lines);
	as_decisions_tick(&d, 3000);
	CHECK(st.dec.rows_new == 4, "late old-day row ingested");
	as_decisions_tick(&d, 3000);
	{
		struct pq_file_stats f_old, f_now;

		dec_file_stats(day_old, &f_old);
		dec_file_stats(day_now, &f_now);
		CHECK(f_old.num_rows == 3,
		      "old day file rewritten full (no clobber)");
		CHECK(f_now.num_rows == 1, "today file unchanged");
	}
	as_decisions_close(&d);

	/* ---- 6) PARQUET_ENABLED=0：write_skipped，无文件，事件照走 ---- */
	mk_conf(&c, 0);
	as_stats_init(&st, &c);
	snprintf(st.conf_path, sizeof(st.conf_path), "%s", "test");
	CHECK(as_decisions_init(&d, &c, &st) == 0, "init (parquet off)");
	as_decisions_set_sink(&d, test_sink, NULL);
	mkline(buf, sizeof(buf), 1, (unsigned long long)ts_now_ns, 1, 0, 0);
	write_ring(buf);
	ev_count = 0;
	as_decisions_tick(&d, 1000);
	as_decisions_tick(&d, 1000);
	CHECK(st.dec.write_skipped == 1, "write skipped when parquet off");
	CHECK(ev_count == 1, "events still flow when parquet off");
	snprintf(path, sizeof(path), "%s/decisions/%s/decisions.parquet",
		 rootdir, day_now);
	CHECK(access(path, 0) == 0, "prior file intact (no rewrite)"); 
	as_decisions_close(&d);

	/* ---- 7) 无内核面：noiface 诚实降级 ---- */
	{
		char base[96];

		snprintf(base, sizeof(base), "/tmp/as-dec-%d-nok",
			 (int)getpid());
		mock_setup(base);
		/* 删掉 decisions 文件模拟无内核面（目录在、文件无） */
		{
			char cmd[192];

			snprintf(cmd, sizeof(cmd), "rm -f %s/proc/ai/decisions",
				 base);
			if (system(cmd) != 0)
				return 2;
		}
	}
	mk_conf(&c, 1);
	as_stats_init(&st, &c);
	snprintf(st.conf_path, sizeof(st.conf_path), "%s", "test");
	CHECK(as_decisions_init(&d, &c, &st) == 0, "init (noiface)");
	as_decisions_tick(&d, 1000);
	as_decisions_tick(&d, 3000);
	CHECK(st.dec.noiface_polls == 2, "noiface counted honestly");
	CHECK(st.dec.rows_new == 0, "nothing ingested without face");
	as_decisions_close(&d);

	/* ---- 8) 批容量满丢最旧 ---- */
	{
		char base[96];

		snprintf(base, sizeof(base), "/tmp/as-dec-%d", (int)getpid());
		mock_setup(base);
	}
	mk_conf(&c, 1);
	c.decisions_batch_max = 1024;
	as_stats_init(&st, &c);
	snprintf(st.conf_path, sizeof(st.conf_path), "%s", "test");
	CHECK(as_decisions_init(&d, &c, &st) == 0, "init (cap)");
	{
		FILE *g;
		char p[192];

		snprintf(p, sizeof(p), "%s/proc/ai/decisions", mockdir);
		g = fopen(p, "w");
		if (!g)
			return 2;
		/* 最新在前：1025..1 */
		for (int id = 1025; id >= 1; id--) {
			mkline(buf, sizeof(buf), (unsigned long long)id,
			       (unsigned long long)ts_now_ns, 1, 0, 0);
			fputs(buf, g);
		}
		fclose(g);
	}
	/* scan_max=4096 > 1025 → 全量可见 */
	as_decisions_tick(&d, 1000);
	CHECK(st.dec.dropped == 1, "cap overflow dropped=1");
	CHECK(d.n == 1024, "batch capped at 1024");
	CHECK(d.batch[0].decision_id == 2 && d.batch[1023].decision_id == 1025,
	      "oldest dropped, order ascending");
	as_decisions_close(&d);

	/* ---- 9) conf 键面：好值/坏值 ---- */
	{
		char tdp[128], err[256];
		FILE *f;

		snprintf(tdp, sizeof(tdp), "/tmp/as-dec-%d/t.conf",
			 (int)getpid());
		f = fopen(tdp, "w");
		if (!f)
			return 2;
		fputs("DECISIONS_ENABLED=1\n"
		      "DECISIONS_INTERVAL_SEC=5\n"
		      "DECISIONS_SCAN_MAX=512\n"
		      "DECISIONS_BATCH_MAX=2048\n"
		      "DECISIONS_WRITE_SME=0\n"
		      "DECISIONS_MOCK_ROOT=/tmp\n", f);
		fclose(f);
		as_conf_defaults(&c);
		CHECK(as_conf_load(&c, tdp, err, sizeof(err)) == 0,
		      "conf keys accepted");
		CHECK(c.decisions_enabled == 1 &&
		      c.decisions_interval_sec == 5 &&
		      c.decisions_scan_max == 512 &&
		      c.decisions_batch_max == 2048 &&
		      c.decisions_write_sme == 0 &&
		      strcmp(c.decisions_mock_root, "/tmp") == 0,
		      "conf values 1:1");
		f = fopen(tdp, "w");
		fputs("DECISIONS_ENABLED=2\n", f);
		fclose(f);
		as_conf_defaults(&c);
		CHECK(as_conf_load(&c, tdp, err, sizeof(err)) != 0,
		      "bad DECISIONS_ENABLED rejected");
		f = fopen(tdp, "w");
		fputs("DECISIONS_MOCK_ROOT=relative/path\n", f);
		fclose(f);
		as_conf_defaults(&c);
		CHECK(as_conf_load(&c, tdp, err, sizeof(err)) != 0,
		      "relative DECISIONS_MOCK_ROOT rejected");
		f = fopen(tdp, "w");
		fputs("DECISIONS_INTERVAL_SEC=0\n", f);
		fclose(f);
		as_conf_defaults(&c);
		CHECK(as_conf_load(&c, tdp, err, sizeof(err)) != 0,
		      "zero interval rejected");
	}

	/* ---- 清理 ---- */
	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "rm -rf /tmp/as-dec-%d "
			 "/tmp/as-dec-%d-nok", (int)getpid(), (int)getpid());
		if (system(cmd) != 0)
			return 2;
	}

	if (fails == 0)
		printf("test_decisions: all passed\n");
	else
		printf("test_decisions: %d FAILURES\n", fails);
	return fails ? 1 : 0;
}
