/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_parquet.c - T8 Parquet writer 单测（snappy + 日界/旋转/index/
 * footer 统计 + sink 映射/节流/保留）
 *
 * 值级正确性（pyarrow 读回逐值一致）由差分向量覆盖（L1，见
 * ~/aikernel-longterm/parity/vectors/parquet/）——单测只做 C 侧
 * 可自证的边界；数据页值不回读（writer-only）。
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "aistreamd/as_parquet.h"
#include "as_pq_sink.h"
#include "aistreamd/as_snappy.h"
#include "as_stats.h"
#include "as_util.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s (line %d)\n", msg, __LINE__); \
		fails++; \
	} \
} while (0)

/* 简易 LCG（确定性"随机"不可压数据） */
static uint32_t rnd_state = 0x12345678u;

static uint32_t rnd(void)
{
	rnd_state = rnd_state * 1103515245u + 12345u;
	return rnd_state >> 8;
}

static int file_exists(const char *p)
{
	struct stat sb;

	return stat(p, &sb) == 0;
}

/* ---- 1. snappy ---- */

static void test_snappy(void)
{
	const size_t N = 300000;
	uint8_t *in = malloc(N), *comp = malloc(as_snappy_max_len(N));
	uint8_t *out = malloc(N);
	size_t clen, ocap;

	CHECK(in && comp && out, "snappy alloc");

	/* 空输入 */
	clen = 99;
	CHECK(as_snappy_compress((const uint8_t *)"", 0, comp, &clen) == 0 &&
	      clen == 1 && comp[0] == 0, "snappy empty -> 1-byte varint 0");
	ocap = 0;
	CHECK(as_snappy_uncompress(comp, clen, out, &ocap) == 0 && ocap == 0,
	      "snappy empty roundtrip");

	/* 全零（高度可压） */
	memset(in, 0, N);
	CHECK(as_snappy_compress(in, N, comp, &clen) == 0, "zeros compress");
	CHECK(clen < N / 8, "zeros ratio (copy 编码生效)");
	ocap = N;
	CHECK(as_snappy_uncompress(comp, clen, out, &ocap) == 0 && ocap == N &&
	      memcmp(in, out, N) == 0, "zeros roundtrip");

	/* 确定性伪随机（不可压：膨胀有界） */
	for (size_t i = 0; i < N; i++)
		in[i] = (uint8_t)rnd();
	CHECK(as_snappy_compress(in, N, comp, &clen) == 0, "random compress");
	CHECK(clen >= N && clen <= as_snappy_max_len(N),
	      "random expansion bounded (literal-only 合法)");
	ocap = N;
	CHECK(as_snappy_uncompress(comp, clen, out, &ocap) == 0 && ocap == N &&
	      memcmp(in, out, N) == 0, "random roundtrip");

	/* 重复文本块（跨 64KB 块边界匹配） */
	for (size_t i = 0; i < N; i++)
		in[i] = (uint8_t)('a' + (i / 97) % 26);
	CHECK(as_snappy_compress(in, N, comp, &clen) == 0, "text compress");
	CHECK(clen < N / 3, "text ratio");
	ocap = N;
	CHECK(as_snappy_uncompress(comp, clen, out, &ocap) == 0 &&
	      memcmp(in, out, N) == 0, "text roundtrip");

	/* 1 字节 */
	in[0] = 0xab;
	clen = 99;
	CHECK(as_snappy_compress(in, 1, comp, &clen) == 0 && clen == 3,
	      "1-byte compress (varint+tag+byte)");
	ocap = 1;
	CHECK(as_snappy_uncompress(comp, clen, out, &ocap) == 0 &&
	      out[0] == 0xab, "1-byte roundtrip");

	/* 腐负：篡改一个字节必须解压失败或输出不一致（检出） */
	{
		uint8_t bad[64];
		uint8_t small[32];

		for (int i = 0; i < 32; i++)
			small[i] = (uint8_t)('x');
		{
			size_t bl = 0;

			CHECK(as_snappy_compress(small, 32, bad,
						 &bl) == 0 && bl >= 2,
			      "corrupt setup");
			bad[bl - 1] ^= 0x55;
			ocap = 32;
			/* 解压要么 -1，要么输出 != small（此处断言：解压成功
			 * 则必须与原值不同=被检出） */
			if (as_snappy_uncompress(bad, bl, out, &ocap) == 0)
				CHECK(memcmp(out, small, 32) != 0,
				      "corrupt detected (value mismatch)");
			else
				CHECK(1, "corrupt detected (decode error)");
		}
	}

	free(in);
	free(comp);
	free(out);
}

/* ---- 2. 日界 / cat_name ---- */

static void test_days(void)
{
	char d1[11], d2[11];
	/* btime=2026-11-05 00:00:00 UTC（date -u 核实的整数天午夜） */
	int64_t bt = 1793836800LL;

	/* 校准：bt 本身是午夜 */
	as_pq_day_from_ts(0, bt, d1);
	CHECK(strcmp(d1, "2026-11-05") == 0, "btime day (ts=0)");
	/* 午夜后 1ms（同日） */
	as_pq_day_from_ts(1000000, bt, d2);
	CHECK(strcmp(d2, "2026-11-05") == 0, "day +1ms");
	/* 23:59:59.9（86399.9s = 86399900000000ns）→ 同日 */
	as_pq_day_from_ts(86399900000000LL, bt, d2);
	CHECK(strcmp(d2, "2026-11-05") == 0, "day 23:59:59.9");
	/* 恰 24h → 次日 */
	as_pq_day_from_ts(86400000000000LL, bt, d2);
	CHECK(strcmp(d2, "2026-11-06") == 0, "day +24h exact");
	as_pq_day_from_ts(86400100000000LL, bt, d2);
	CHECK(strcmp(d2, "2026-11-06") == 0, "day +24h+1ms");
	/* btime=0 → 今天（非空 YYYY-MM-DD） */
	as_pq_day_from_ts(123, 0, d1);
	CHECK(strlen(d1) == 10 && d1[4] == '-' && d1[7] == '-',
	      "fallback today format");

	{
		char c[16];

		as_pq_cat_name(1, c, sizeof(c));
		CHECK(strcmp(c, "sched") == 0, "cat 1");
		as_pq_cat_name(18, c, sizeof(c));
		CHECK(strcmp(c, "ai") == 0, "cat 18");
		as_pq_cat_name(20, c, sizeof(c));
		CHECK(strcmp(c, "cat20") == 0, "cat 20 unknown");
		as_pq_cat_name(99, c, sizeof(c));
		CHECK(strcmp(c, "cat99") == 0, "cat 99 unknown");
	}
}

/* ---- 3. 写路径（旋转/分块/序号跳/decisions/chains/footer 统计） ---- */

static void rmrf(const char *dir)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
	if (system(cmd) != 0) {
		/* 清理失败不影响断言（目录名固定 /tmp/t8-unit-*） */
	}
}

static void test_write(void)
{
	const char *root = "/tmp/t8-unit-write";
	char path[600], day[11];
	const int64_t bt = 1793836800LL;	/* 2026-11-05 00:00 UTC */
	struct pq_tel_row rows[7];
	uint8_t payload[8] = { 1, 2, 3, 0xff, 0xfe, 0, 7, 8 };
	struct pq_file_stats fs;

	rmrf(root);
	CHECK(as_pq_ensure_root(root) == 0, "ensure_root");
	CHECK(file_exists("/tmp/t8-unit-write/telemetry") &&
	      file_exists("/tmp/t8-unit-write/decisions") &&
	      file_exists("/tmp/t8-unit-write/models"), "ensure_root dirs");

	/* 5 行 cat=6 + 2 行 cat=1，乱序 ts */
	memset(rows, 0, sizeof(rows));
	for (int i = 0; i < 5; i++) {
		rows[i].ts_ns = 5000000000LL - (int64_t)i * 1000000000;
		rows[i].pid = 100 + i;
		rows[i].tgid = 100;
		rows[i].cpu = (int16_t)(i % 4);
		rows[i].category = 6;
		rows[i].event_type = 3;
		rows[i].severity = (int8_t)(i % 3);
		rows[i].data_len = 8;
		rows[i].data = payload;
	}
	rows[5].ts_ns = 6000000000LL;
	rows[5].category = 1;
	rows[5].pid = 9;
	rows[5].data_len = 0;
	rows[5].data = NULL;
	rows[6].ts_ns = 5500000000LL;
	rows[6].category = 1;
	rows[6].pid = 10;
	rows[6].data_len = 0;
	rows[6].data = NULL;

	as_pq_day_from_ts(5000000000LL, bt, day);
	{
		int r = as_pq_write_telemetry(root, rows, 7, bt, 65536, NULL);

		CHECK(r == 7, "write_telemetry returns 7");
	}
	snprintf(path, sizeof(path), "%s/telemetry/%s/process_0000.parquet",
		 root, day);
	CHECK(file_exists(path), "process_0000 exists");
	snprintf(path, sizeof(path), "%s/telemetry/%s/sched_0000.parquet",
		 root, day);
	CHECK(file_exists(path), "sched_0000 exists");
	snprintf(path, sizeof(path), "%s/telemetry/index.parquet", root);
	CHECK(file_exists(path), "index exists");

	/* footer 统计（自产文件）：行数/ts min-max/cat max */
	snprintf(path, sizeof(path), "%s/telemetry/%s/process_0000.parquet",
		 root, day);
	CHECK(as_pq_file_stats(path, &fs) == 0, "footer stats readable");
	CHECK(fs.num_rows == 5, "footer rows=5");
	CHECK(fs.has_ts && fs.ts_min == 1000000000LL &&
	      fs.ts_max == 5000000000LL, "footer ts min/max");
	CHECK(fs.has_cat && fs.cat_max == 6, "footer cat max");

	/* 再次写同类别 → 序号递增 */
	{
		int r = as_pq_write_telemetry(root, rows, 5, bt, 65536, NULL);

		CHECK(r == 5, "second write returns 5");
		snprintf(path, sizeof(path),
			 "%s/telemetry/%s/process_0001.parquet", root, day);
		CHECK(file_exists(path), "rotation process_0001");
	}

	/* 序号跳：预置 sched_0007（空文件占位——REF 只 glob 文件名） */
	snprintf(path, sizeof(path), "%s/telemetry/%s/sched_0007.parquet",
		 root, day);
	{
		FILE *pf = fopen(path, "w");

		if (pf)
			fclose(pf);
	}
	{
		int r = as_pq_write_telemetry(root, &rows[5], 2, bt, 65536,
					      NULL);

		CHECK(r == 2, "third write returns 2");
		snprintf(path, sizeof(path),
			 "%s/telemetry/%s/sched_0008.parquet", root, day);
		CHECK(file_exists(path), "seq skip -> sched_0008");
	}

	/* 分块：chunk_max=2、5 行 → 0002/0003/0004 三文件（cat=6） */
	{
		struct pq_tel_row five[5];

		memcpy(five, rows, sizeof(five));
		for (int i = 0; i < 5; i++)
			five[i].ts_ns = 7000000000LL + i;
		{
			int r = as_pq_write_telemetry(root, five, 5, bt, 2,
						      NULL);

			CHECK(r == 5, "chunked write returns 5");
		}
		for (int s = 2; s <= 4; s++) {
			snprintf(path, sizeof(path),
				 "%s/telemetry/%s/process_%04d.parquet", root,
				 day, s);
			CHECK(file_exists(path), "chunk file present");
		}
	}

	/* index 行数 = 可解析数据文件数（0 字节占位被 skipped 计数） */
	{
		long sk = 0;

		CHECK(as_pq_update_index(root, &sk) == 0,
		      "update_index ok");
		/* sched_0007 是 0 字节占位文件 → footer 解析失败 → skipped=1
		 * （REF 静默跳过；此处计数上报）。可解析文件 =
		 * 0000×2 + 0001 + 0008 + 0002/3/4 = 7。 */
		snprintf(path, sizeof(path), "%s/telemetry/index.parquet",
			 root);
		CHECK(as_pq_file_stats(path, &fs) == 0, "index footer");
		CHECK(fs.num_rows == 7, "index rows = parseable files");
		CHECK(sk == 1, "index skipped =1 (sched_0007 空占位)");
	}

	/* decisions / chains */
	{
		struct pq_dec_row dr[2];

		memset(dr, 0, sizeof(dr));
		dr[0].decision_id = 4711;
		dr[0].trigger_ts = 1000000000LL;
		dr[0].decision_ts = 4000000000LL;	/* day D */
		dr[0].metric_delta = -42;
		dr[0].data[0] = 1;
		dr[1].decision_id = 4712;
		dr[1].trigger_ts = 1000000000LL;
		dr[1].decision_ts = 4000000000LL + 86400000000000LL; /* D+1 */
		{
			char day2[11];

			as_pq_day_from_ts(4000000000LL + 86400000000000LL,
					  bt, day2);
			CHECK(strcmp(day2, "2026-11-06") == 0, "dec day2");
		}
		CHECK(as_pq_write_decisions(root, dr, 2, bt, NULL) == 2,
		      "write_decisions 2");
		as_pq_day_from_ts(4000000000LL, bt, day);
		snprintf(path, sizeof(path), "%s/decisions/%s/decisions.parquet",
			 root, day);
		CHECK(file_exists(path), "decisions D exists");
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 2,
		      "decisions rows=2（首条 decision_ts 定日，跨日同文件）");
		CHECK(as_pq_write_chains(root, dr, 2, bt, NULL) == 2,
		      "write_chains 2");
		/* chains 按首条 trigger_ts 定日 = day D（两行同落 D） */
		as_pq_day_from_ts(1000000000LL, bt, day);
		snprintf(path, sizeof(path), "%s/decisions/%s/chains_%s.parquet",
			 root, day, day);
		CHECK(file_exists(path), "chains in day dir (REF 代码行为)");
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 2,
		      "chains rows=2");

		/* decisions 同名覆盖（REF 语义：整文件替换） */
		CHECK(as_pq_write_decisions(root, dr, 1, bt, NULL) == 1,
		      "write_decisions overwrite");
		as_pq_day_from_ts(4000000000LL, bt, day);
		snprintf(path, sizeof(path), "%s/decisions/%s/decisions.parquet",
			 root, day);
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 1,
		      "decisions overwritten rows=1");
	}

	/* 空批 = 零操作零文件 */
	{
		char teldir[600];

		snprintf(teldir, sizeof(teldir), "%s/telemetry/2099-01-01",
			 root);
		CHECK(as_pq_write_telemetry(root, NULL, 0, bt, 65536, NULL) ==
		      0, "empty batch returns 0");
		CHECK(!file_exists(teldir), "empty batch no dir");
	}
	rmrf(root);
}

/* ---- 4. sink：映射/节流/默认关零影响 ---- */

static void test_sink(void)
{
	struct as_conf conf;
	struct as_stats st;
	struct as_pq_sink sink;
	char evline[AS_LINE_MAX];

	/* 默认关：feed/flush/close 全零影响 */
	as_conf_defaults(&conf);
	snprintf(conf.parquet_dir, sizeof(conf.parquet_dir), "/tmp/t8-unit-off");
	as_stats_init(&st, &conf);
	memset(&sink, 0, sizeof(sink));
	CHECK(as_pq_sink_init(&sink, &conf, &st) == 0, "sink init off");
	{
		struct as_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.stream_idx = 1;
		ev.stream = "proc";
		ev.category = "comm";
		ev.severity = "info";
		snprintf(ev.line, sizeof(ev.line), "[kern] proc comm pid=4242 comm=t8x");
		ev.pid = 4242;
		as_pq_sink_feed(&sink, &ev);
		as_pq_sink_flush(&sink);
		as_pq_sink_close(&sink);
	}
	CHECK(!file_exists("/tmp/t8-unit-off"), "disabled: no dir");
	CHECK(st.pq.enabled == 0 && st.pq.fed == 0 && st.pq.files == 0,
	      "disabled: counters zero");
	rmrf("/tmp/t8-unit-off");

	/* 开：feed 映射 + flush 落盘 + 计数 */
	as_conf_defaults(&conf);
	snprintf(conf.parquet_dir, sizeof(conf.parquet_dir), "/tmp/t8-unit-on");
	conf.parquet_enabled = 1;
	as_stats_init(&st, &conf);
	memset(&sink, 0, sizeof(sink));
	CHECK(as_pq_sink_init(&sink, &conf, &st) == 0, "sink init on");
	for (int i = 0; i < 5; i++) {
		struct as_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.stream_idx = 1;
		ev.stream = "proc";
		ev.category = "comm";
		ev.severity = i == 4 ? "warn" : "info";
		snprintf(ev.line, sizeof(ev.line),
			 "[kern] proc comm pid=%d comm=t8mark%d", 100 + i, i);
		ev.pid = 100 + i;
		as_pq_sink_feed(&sink, &ev);
	}
	CHECK(sink.n == 5 && st.pq.fed == 5 && st.pq.buffered == 5,
	      "sink buffered 5");
	as_pq_sink_flush(&sink);
	{
		char day[11], path[600];
		struct pq_file_stats fs;

		as_pq_day_from_ts(0, sink.btime, day);
		snprintf(path, sizeof(path),
			 "%s/telemetry/%s/process_0000.parquet", conf.parquet_dir,
			 day);
		CHECK(file_exists(path), "sink flush file");
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 5,
		      "sink rows=5");
		snprintf(path, sizeof(path), "%s/telemetry/index.parquet",
			 conf.parquet_dir);
		CHECK(file_exists(path), "sink index");
	}
	CHECK(st.pq.rows_written == 5 && st.pq.files == 1 &&
	      st.pq.flushes == 1 && st.pq.buffered == 0 && st.pq.errors == 0,
	      "sink counters");
	CHECK(st.pq.bytes > 0, "sink bytes>0");

	/* ---- T8 打回补丁用例：flush 后再 flush / 退出 drain（冻结断言：
	 * 行数不得重复、空 flush 不得计数/建文件） ---- */
	as_pq_sink_flush(&sink);	/* 缓冲已空：必须零操作 */
	CHECK(as_pq_sink_pending(&sink) == 0 && st.pq.flushes == 1 &&
	      st.pq.rows_written == 5 && st.pq.files == 1,
	      "empty second flush: no-op (no dup, no counter bump)");
	as_pq_sink_flush(&sink);	/* 连打三次，仍零操作 */
	as_pq_sink_flush(&sink);
	CHECK(st.pq.flushes == 1 && st.pq.rows_written == 5 && st.pq.files == 1,
	      "empty flush x3: still no-op");
	{
		char day[11];
		long files_now = 0;
		DIR *d;
		struct dirent *de;
		char teldir[600];

		as_pq_day_from_ts(0, sink.btime, day);
		snprintf(teldir, sizeof(teldir), "%s/telemetry/%s",
			 conf.parquet_dir, day);
		d = opendir(teldir);
		if (d) {
			while ((de = readdir(d)) != NULL)
				if (strstr(de->d_name, "process_"))
					files_now++;
			closedir(d);
		}
		CHECK(files_now == 1, "empty flush: no new file");
	}

	/* 第二批 3 行 → close() 退出 drain 恰好写一次 */
	for (int i = 0; i < 3; i++) {
		struct as_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.stream_idx = 1;
		ev.stream = "proc";
		ev.category = "comm";
		ev.severity = "info";
		snprintf(ev.line, sizeof(ev.line),
			 "[kern] proc comm pid=%d comm=t8drain%d", 200 + i, i);
		ev.pid = 200 + i;
		as_pq_sink_feed(&sink, &ev);
	}
	as_pq_sink_close(&sink);	/* 内部 flush 一次 + 释放 */
	CHECK(st.pq.fed == 8 && st.pq.rows_written == 8 &&
	      st.pq.files == 2 && st.pq.flushes == 2 &&
	      st.pq.buffered == 0 && st.pq.errors == 0,
	      "close drain: 5+3 rows, 2 files, counters exact (no dup)");
	{
		char day[11], path[600];
		struct pq_file_stats fs;

		as_pq_day_from_ts(0, sink.btime, day);
		snprintf(path, sizeof(path),
			 "%s/telemetry/%s/process_0001.parquet", conf.parquet_dir,
			 day);
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 3,
		      "drain file rows=3 (not 8: stale buffer never re-flushed)");
	}
	/* close 后再 feed/flush 不得崩（buf 已 free；enabled 仍 1 → 重建缓冲
	 * 属允许行为，但断言它不再写文件：feed 后 n=1 但无人再 flush） */
	{
		struct as_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.stream_idx = 1;
		ev.stream = "proc";
		ev.category = "comm";
		ev.severity = "info";
		snprintf(ev.line, sizeof(ev.line), "[kern] proc comm pid=1");
		as_pq_sink_feed(&sink, &ev);
		as_pq_sink_flush(&sink);
		as_pq_sink_close(&sink);
	}
	CHECK(st.pq.rows_written == 8 && st.pq.files == 2,
	      "post-close feed+flush accounting sane");
	rmrf(conf.parquet_dir);
	(void)evline;
}

/* ---- 5. 保留策略 ---- */

static void write_file(const char *path, const char *tag)
{
	FILE *f = fopen(path, "w");

	if (f) {
		fprintf(f, "%s", tag);
		fclose(f);
	}
}

static void test_retain(void)
{
	const char *root = "/tmp/t8-unit-retain";
	char p[2048];
	struct as_pq_sink s;
	struct as_stats st;
	char today[11];
	/* 字面量天名（排序=时间序；与真实 today 不同名）：A 最老（含异物
	 * →整目录永不删）、B/C 干净（预算 0 → 应被清空删除） */
	const char *A = "2099-01-01", *B = "2099-01-02", *C = "2099-01-03";

	rmrf(root);
	as_pq_ensure_root(root);	/* 建父目录 */
	as_pq_day_from_ts(0, as_pq_btime(), today);
	CHECK(strcmp(today, A) != 0, "retain setup: today != literal days");

	for (int d = 0; d < 3; d++) {
		const char *days[3] = { A, B, C };
		char dir[1024];

		snprintf(dir, sizeof(dir), "%s/telemetry/%s", root, days[d]);
		mkdir(dir, 0755);
		snprintf(p, sizeof(p), "%s/sched_0000.parquet", dir);
		write_file(p, "x");
		snprintf(p, sizeof(p), "%s/sched_0001.parquet", dir);
		write_file(p, "x");
		snprintf(dir, sizeof(dir), "%s/decisions/%s", root, days[d]);
		mkdir(dir, 0755);
		snprintf(p, sizeof(p), "%s/decisions.parquet", dir);
		write_file(p, "x");
	}
	/* 异物：A 的 decisions 目录放 keepme.txt（布局外文件） */
	snprintf(p, sizeof(p), "%s/decisions/%s/keepme.txt", root, A);
	write_file(p, "DO NOT DELETE");
	/* 当天目录（真名）+ 布局文件：必须保留 */
	{
		char dir[1024];

		snprintf(dir, sizeof(dir), "%s/telemetry/%s", root, today);
		mkdir(dir, 0755);
		snprintf(p, sizeof(p), "%s/sched_0000.parquet", dir);
		write_file(p, "x");
	}

	as_stats_init(&st, NULL);
	memset(&s, 0, sizeof(s));
	snprintf(s.root, sizeof(s.root), "%s", root);
	s.enabled = 1;
	s.max_gb = 0;			/* 预算 0：触发清理直到无可删 */
	s.stats = &st;
	s.btime = as_pq_btime();

	as_pq_retain(&s);

	/* B/C（干净旧天）应被清空且目录删除 */
	snprintf(p, sizeof(p), "%s/telemetry/%s", root, B);
	CHECK(!file_exists(p), "retain: clean day B removed");
	snprintf(p, sizeof(p), "%s/decisions/%s", root, C);
	CHECK(!file_exists(p), "retain: clean day C removed");
	/* A（含异物）必须原样保留 */
	snprintf(p, sizeof(p), "%s/telemetry/%s/sched_0000.parquet", root, A);
	CHECK(file_exists(p), "retain: foreign day kept (telemetry)");
	snprintf(p, sizeof(p), "%s/decisions/%s/keepme.txt", root, A);
	CHECK(file_exists(p), "retain: foreign file untouched");
	/* 当天必须保留 */
	snprintf(p, sizeof(p), "%s/telemetry/%s/sched_0000.parquet", root,
		 today);
	CHECK(file_exists(p), "retain: today kept");
	/* B+C 各 3 个布局文件被删 */
	CHECK(st.pq.retained_files == 6, "retain counter files=6");
	CHECK(st.pq.retained_bytes > 0, "retain counter bytes>0");
	rmrf(root);
}

/* ---- 6. conf 键 ---- */

static void test_conf(void)
{
	struct as_conf c;
	char err[256];
	FILE *f;
	const char *path = "/tmp/t8-unit.conf";

	as_conf_defaults(&c);
	CHECK(c.parquet_enabled == 0 &&
	      strcmp(c.parquet_dir, "/var/lib/aikernel") == 0 &&
	      c.parquet_max_gb == 2 && c.parquet_flush_sec == 30 &&
	      c.parquet_flush_rows == 128, "parquet defaults");

	f = fopen(path, "w");
	CHECK(f != NULL, "conf file open");
	fprintf(f, "PARQUET_ENABLED=1\nPARQUET_DIR=/tmp/pqdata\n"
		   "PARQUET_MAX_GB=5\nPARQUET_FLUSH_SEC=10\n"
		   "PARQUET_FLUSH_ROWS=64\n");
	fclose(f);
	CHECK(as_conf_load(&c, path, err, sizeof(err)) == 0, "conf ok");
	CHECK(c.parquet_enabled == 1 && strcmp(c.parquet_dir, "/tmp/pqdata") == 0
	      && c.parquet_max_gb == 5 && c.parquet_flush_sec == 10 &&
	      c.parquet_flush_rows == 64, "conf values");

	f = fopen(path, "w");
	fprintf(f, "PARQUET_ENABLED=2\n");
	fclose(f);
	CHECK(as_conf_load(&c, path, err, sizeof(err)) != 0,
	      "PARQUET_ENABLED=2 rejected");

	f = fopen(path, "w");
	fprintf(f, "PARQUET_DIR=relative/path\n");
	fclose(f);
	CHECK(as_conf_load(&c, path, err, sizeof(err)) != 0,
	      "PARQUET_DIR relative rejected");

	f = fopen(path, "w");
	fprintf(f, "PARQUET_MAX_GB=0\n");
	fclose(f);
	CHECK(as_conf_load(&c, path, err, sizeof(err)) != 0,
	      "PARQUET_MAX_GB=0 rejected");

	f = fopen(path, "w");
	fprintf(f, "PARQUET_FLUSH_ROWS=0\n");
	fclose(f);
	CHECK(as_conf_load(&c, path, err, sizeof(err)) != 0,
	      "PARQUET_FLUSH_ROWS=0 rejected");

	f = fopen(path, "w");
	fprintf(f, "PARQUET_FLUSH_SEC=x\n");
	fclose(f);
	CHECK(as_conf_load(&c, path, err, sizeof(err)) != 0,
	      "PARQUET_FLUSH_SEC=bad rejected");

	f = fopen(path, "w");
	fprintf(f, "PARQUET_UNKNOWN=1\n");
	fclose(f);
	CHECK(as_conf_load(&c, path, err, sizeof(err)) != 0,
	      "unknown parquet key rejected");

	unlink(path);
}

int main(void)
{
	test_snappy();
	test_days();
	test_write();
	test_sink();
	test_retain();
	test_conf();
	if (fails == 0) {
		printf("test_parquet: all OK\n");
		return 0;
	}
	printf("test_parquet: %d FAIL(s)\n", fails);
	return 1;
}
