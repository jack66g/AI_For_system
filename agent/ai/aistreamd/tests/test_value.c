/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_value.c - L1 棒①单测：价值评分器 + schema v3 + curated 双写
 * （DATA-L1-DESIGN §1）
 *
 * 覆盖：
 *   1. 公式边界：0/1 端点、权重全零、重复罚饱和、clamp、带端点含闭
 *   2. 原料缺失位（事件路反差/代价/置信缺、纠正恒缺；writer 路稀有缺）
 *   3. 两路挂点装配（事件 fixture + decisions fixture 31 列）
 *   4. curated 落盘（telemetry 镜像+index / decisions 镜像 / 门控关）
 *   5. SME 补发请求体（mock server 逐字节断言——沿 test_sme.c 模式）
 *   6. v3 列数（footer schema 读回 13/32 + DEC_NCOL==PQ_MAXCOL 上限）
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "as_conf.h"
#include "as_event.h"
#include "as_sme.h"
#include "as_stats.h"
#include "as_value.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

static int feq(double a, double b)
{
	return fabs(a - b) < 1e-12;
}

/* ---- mock SME server（test_sme.c 同款桩：捕原始请求→200） ---- */

#define MOCK_RESP \
	"HTTP/1.1 200 OK\r\n" \
	"Content-Type: application/json\r\n" \
	"Content-Length: 13\r\n" \
	"Connection: close\r\n" \
	"\r\n" \
	"{\"id\":\"m1\"}"

static char *strcasestr_local(const char *h, const char *n)
{
	size_t nl = strlen(n);

	for (; *h; h++)
		if (strncasecmp(h, n, nl) == 0)
			return (char *)h;
	return NULL;
}

static int serve_one(int cli, FILE *cap)
{
	char req[8192];
	size_t off = 0;
	long clen = 0;

	while (off < sizeof(req) - 1) {
		ssize_t n = recv(cli, req + off, sizeof(req) - 1 - off, 0);

		if (n <= 0)
			return -1;
		off += (size_t)n;
		req[off] = '\0';
		if (strstr(req, "\r\n\r\n"))
			break;
	}
	{
		char *cl = strcasestr_local(req, "Content-Length:");

		if (cl)
			clen = strtol(cl + 15, NULL, 10);
	}
	while ((long)strlen(req) - (long)(strstr(req, "\r\n\r\n") - req) - 4
	       < clen && off < sizeof(req) - 1) {
		ssize_t n = recv(cli, req + off, sizeof(req) - 1 - off, 0);

		if (n <= 0)
			break;
		off += (size_t)n;
		req[off] = '\0';
	}
	fwrite(req, 1, off, cap);
	fputc('\n', cap);
	fflush(cap);
	{
		const char *r = MOCK_RESP;

		if (send(cli, r, strlen(r), 0) < 0)
			return -1;
	}
	return 0;
}

/* ---- 小工具 ---- */

/* 目录下 .parquet 文件计数（一层） */
static int count_parquet(const char *dir)
{
	char cmd[600];
	FILE *f;
	int n = 0;
	char line[512];

	snprintf(cmd, sizeof(cmd), "find '%s' -name '*.parquet' 2>/dev/null",
		 dir);
	f = popen(cmd, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f))
		n++;
	pclose(f);
	return n;
}

static void mkrow(struct pq_tel_row *r, int64_t ts, int8_t cat, int8_t sev,
		  const char *text, double value, int64_t flags)
{
	memset(r, 0, sizeof(*r));
	r->ts_ns = ts;
	r->pid = 1;
	r->category = cat;
	r->event_type = 0;
	r->severity = sev;
	r->data_len = (int16_t)strlen(text);
	r->data = (const uint8_t *)text;
	r->value = value;
	r->flags = flags;
}

int main(void)
{
	char dir[64];
	int btime = 1700000000;

	snprintf(dir, sizeof(dir), "/tmp/as-value-%d", (int)getpid());
	{
		char cmd[512];

		snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s", dir,
			 dir);
		if (system(cmd) != 0)
			return 2;
	}

	/* ============ 1. 纯函数核心：公式边界 ============ */
	{
		struct as_value_w w;
		struct as_value_ev_mat em;
		struct as_value_dec_mat dm;
		struct as_value_state st;
		struct as_value_out o;

		/* 默认权重（as_value_conf_init 未调时快照=as_conf 默认） */
		as_value_conf_init(NULL);	/* NULL=保持缺省快照 */
		w = *as_value_weights();
		CHECK(feq(w.w1, 0.45) && feq(w.w2, 0.25) &&
		      feq(w.promote_min, 0.50) && feq(w.promote_max, 0.95),
		      "default weights snapshot");

		/* a) 权重全零 → value 恒 0 且不 promotion（带下沿 0.5） */
		memset(&w, 0, sizeof(w));
		w.promote_min = 0.5;
		w.promote_max = 1.0;
		memset(&em, 0, sizeof(em));
		em.digest = 0x1234;
		em.severity = 2;
		em.stream_idx = 1;
		em.merged_count = 0;
		memset(&st, 0, sizeof(st));
		st.rarity_known = 1;
		as_value_score(&w, &em, NULL, &st, &o);
		CHECK(o.value == 0.0 && !(o.flags & AS_VF_PROMOTED),
		      "all-zero weights => value 0, no promote");

		/* b) 首见+新流（severity=error 抬升封顶 1）：novelty=1
		 *    rare=1 → 0.45+0.10=0.55；缺失位=反差/代价/置信/纠正
		 *    （事件路无 decisions 原料） */
		w = *as_value_weights();
		as_value_score(&w, &em, NULL, &st, &o);
		CHECK(feq(o.value, 0.55), "fresh novel event value 0.55");
		CHECK((o.flags & AS_VF_PROMOTED) != 0, "fresh event promoted");
		CHECK((o.flags & (AS_VF_MISS_DIVERGENCE | AS_VF_MISS_COST |
				  AS_VF_MISS_CONFIDENCE |
				  AS_VF_MISS_CORRECTION)) != 0,
		      "event path missing-material bits set");
		CHECK(!(o.flags & (AS_VF_MISS_NOVELTY | AS_VF_MISS_RARITY)),
		      "event path novelty/rarity present");

		/* c) 已见 digest+error：novelty=0+0.25 抬升 →
		 *    0.45*0.25+0.10*1=0.2125，不进带 */
		st.digest_seen = 1;
		em.severity = 2;
		as_value_score(&w, &em, NULL, &st, &o);
		CHECK(feq(o.value, 0.45 * 0.25 + 0.10),
		      "seen+error severity boost 0.2125");
		CHECK(!(o.flags & AS_VF_PROMOTED), "seen event not promoted");

		/* d) 重复罚饱和：已见 info + merged_count=17（repeats=16）
		 *    → novelty=0 rare=1 罚=1 → 0.10-0.10=0（clamp 下端） */
		em.severity = 0;
		em.merged_count = 17;
		as_value_score(&w, &em, NULL, &st, &o);
		CHECK(o.value == 0.0, "repeat penalty saturates to 0");

		/* e) clamp 上端：W1=1 其余 0 + 带端点 [1,1] → value=1.0
		 *    恰进带（端点含闭） */
		memset(&w, 0, sizeof(w));
		w.w1 = 1.0;
		w.promote_min = 1.0;
		w.promote_max = 1.0;
		st.digest_seen = 0;
		em.severity = 0;
		em.merged_count = 0;
		as_value_score(&w, &em, NULL, &st, &o);
		CHECK(o.value == 1.0 && (o.flags & AS_VF_PROMOTED),
		      "value 1.0 at inclusive band endpoint");

		/* f) decisions 原料：digest 已见+info → novelty=0；
		 *    |2-10|=8 → 8/72*0.9=0.1；cost=1e7 → 0.5；agent 新 →
		 *    rare=1 → 0.25*0.1+0.15*0.5+0.10*1=0.2；DEC 缺失位全清 */
		w = *as_value_weights();
		st.digest_seen = 1;
		em.severity = 0;
		em.merged_count = 0;
		memset(&dm, 0, sizeof(dm));
		dm.has = 1;
		dm.outcome = 2;
		dm.expected = 10;
		dm.cost_ns = 10000000ULL;
		dm.confidence = 90;
		dm.agent_id = 7;
		as_value_score(&w, &em, &dm, &st, &o);
		CHECK(feq(o.value, 0.025 + 0.075 + 0.10),
		      "decision material div+cost+rare = 0.2");
		CHECK(!(o.flags & (AS_VF_MISS_DIVERGENCE | AS_VF_MISS_COST |
				   AS_VF_MISS_CONFIDENCE)),
		      "decision material missing bits cleared");
		CHECK((o.flags & AS_VF_MISS_CORRECTION) != 0,
		      "correction stays missing (occ not wired)");

		/* g) 稀有态未知（writer 路）→ rare=0+缺失位 */
		st.rarity_known = 0;
		as_value_score(&w, &em, &dm, &st, &o);
		CHECK(feq(o.value, 0.025 + 0.075) &&
		      (o.flags & AS_VF_MISS_RARITY),
		      "writer path rarity-unknown => 0 contribution");
		st.rarity_known = 1;

		/* h) 老 K1 v2 行原料全 0：|0-0|=0、cost 0 → 反差/代价 0
		 *    （agent_id=0 新 agent → rare=1 仍计 0.10） */
		memset(&dm, 0, sizeof(dm));
		dm.has = 1;
		as_value_score(&w, NULL, &dm, &st, &o);
		CHECK(feq(o.value, 0.10), "old zero-tail decision row rare only");
		CHECK((o.flags & AS_VF_MISS_NOVELTY) != 0,
		      "ev NULL => novelty missing bit");
	}

	/* ============ 2. 带判定 + decisions 行评分（31 列 fixture） ==== */
	{
		struct pq_dec_row d;

		CHECK(as_value_promoted(0.50) && as_value_promoted(0.95),
		      "band endpoints inclusive");
		CHECK(!as_value_promoted(0.49) && !as_value_promoted(0.96),
		      "outside band not promoted");

		memset(&d, 0, sizeof(d));
		d.decision_id = 4711;
		d.decision_ts = 35280998948514LL;
		d.outcome = 2;
		d.confidence = 90;
		d.agent_id = 7;
		d.expected = 10;
		d.cost_ns = 10000000LL;
		/* writer 路：div=0.1 cost=0.5 rare 缺 → 0.25*0.1+0.15*0.5 */
		CHECK(feq(as_value_dec_row_score(&d), 0.1),
		      "dec row writer score 0.1 (31-col fixture)");
	}

	/* ============ 3. 挂点装配（事件 fixture / decisions fixture） ==== */
	{
		struct as_value_ctx c;
		struct as_event ev;

		as_value_conf_init(NULL);
		as_value_ctx_init(&c);

		/* 事件路：proc fork fixture（首条进带） */
		as_event_proc_fork(&ev, 1, 42);
		CHECK(as_value_hook_event(&c, &ev) == 1, "hook event promoted");
		CHECK(feq(ev.value, 0.55) && (ev.vflags & AS_VF_PROMOTED) &&
		      !(ev.vflags & AS_VF_DEC_PATH),
		      "hook fills ev value/vflags (event path)");
		/* 同 digest 再来：已见 → 不进带 */
		CHECK(as_value_hook_event(&c, &ev) == 0,
		      "second same-digest not promoted");
		CHECK(c.scored == 2 && c.promoted == 1, "ctx counters");

		/* decisions 路：合成事件 + v3 尾巴（as_decisions.c 手法） */
		as_event_decision(&ev, 4711, 0, 1, 1, 0, 2, 0, 0, 0);
		ev.dec_material = 1;
		ev.dec_outcome = 2;
		ev.dec_expected = 10;
		ev.dec_cost_ns = 10000000ULL;
		ev.dec_confidence = 90;
		ev.dec_agent_id = 7;
		{
			int pr = as_value_hook_decision(&c, &ev);

			CHECK(pr == 1, "decision hook promotes (0.65)");
			CHECK((ev.vflags & AS_VF_DEC_PATH) != 0 &&
			      !(ev.vflags & AS_VF_MISS_DIVERGENCE),
			      "decision path flag + material present");
			CHECK(feq(ev.value, 0.45 + 0.025 + 0.075 + 0.10),
			      "decision hook full score 0.65");
		}
		/* 聚合行：merged_count=5 → repeats=4 罚 0.25；proc 流已计
		 * 2 → rare=1/3 → 0.45+0.10/3-0.025 */
		as_event_proc_fork(&ev, 1, 43);
		ev.merged_count = 5;
		as_value_hook_event(&c, &ev);
		CHECK(feq(ev.value, 0.45 + 0.10 / 3.0 - 0.10 * 0.25),
		      "agg row repeat penalty (merged_count=5)");
	}

	/* ============ 4. SME 补发请求体（mock server 逐字节） ============ */
	{
		char portfile[128], capfile[128], conffile[128];
		pid_t srv;
		int port = 0;

		snprintf(portfile, sizeof(portfile), "%s/port", dir);
		snprintf(capfile, sizeof(capfile), "%s/cap.txt", dir);
		snprintf(conffile, sizeof(conffile), "%s/sme.conf", dir);
		srv = fork();
		if (srv == 0) {
			int s = socket(AF_INET, SOCK_STREAM, 0);
			struct sockaddr_in a;
			socklen_t al = sizeof(a);
			FILE *cap;
			int served = 0;

			if (s < 0)
				_exit(3);
			memset(&a, 0, sizeof(a));
			a.sin_family = AF_INET;
			a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			a.sin_port = 0;
			if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0 ||
			    listen(s, 8) < 0 ||
			    getsockname(s, (struct sockaddr *)&a, &al) < 0)
				_exit(3);
			{
				FILE *pf = fopen(portfile, "w");

				if (!pf)
					_exit(3);
				fprintf(pf, "%d\n", (int)ntohs(a.sin_port));
				fclose(pf);
			}
			cap = fopen(capfile, "w");
			if (!cap)
				_exit(3);
			while (served < 1) {
				int cli = accept(s, NULL, NULL);
				struct timeval tv = { .tv_sec = 5 };

				if (cli < 0)
					continue;
				setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv,
					   sizeof(tv));
				if (serve_one(cli, cap) == 0)
					served++;
				close(cli);
			}
			fclose(cap);
			close(s);
			_exit(0);
		}
		for (int i = 0; i < 100 && port == 0; i++) {
			FILE *f = fopen(portfile, "r");

			if (f) {
				if (fscanf(f, "%d", &port) != 1)
					port = 0;
				fclose(f);
			}
			usleep(50000);
		}
		CHECK(port > 0, "mock SME server up");
		if (port > 0) {
			struct as_conf cf;
			struct as_stats st;
			struct as_sme sm;
			struct as_value_ctx vc;
			struct as_event ev;

			as_conf_defaults(&cf);
			snprintf(cf.sme_url, sizeof(cf.sme_url),
				 "http://127.0.0.1:%d", port);
			as_stats_init(&st, &cf);
			CHECK(as_sme_init(&sm, &cf, &st) == 0, "as_sme_init");
			as_value_conf_init(&cf);
			as_value_ctx_init(&vc);
			as_event_proc_fork(&ev, 1, 4242);
			CHECK(as_value_hook_event(&vc, &ev) == 1,
			      "curated nudge row promoted");
			as_sme_deliver_curated(&sm, &ev, ev.value);
			CHECK(sm.curated_ok == 1, "curated nudge posted");
			as_sme_free(&sm);
			{
				int status;

				waitpid(srv, &status, 0);
				CHECK(WIFEXITED(status) &&
				      WEXITSTATUS(status) == 0,
				      "mock SME server exit 0");
			}
			{
				FILE *f = fopen(capfile, "r");
				char all[16384];
				size_t n;
				char imp[64];

				CHECK(f != NULL, "reopen capture");
				if (!f)
					return 1;
				n = fread(all, 1, sizeof(all) - 1, f);
				all[n] = '\0';
				fclose(f);
				CHECK(strstr(all, "POST /memories ") != NULL,
				      "request line POST /memories");
				CHECK(strstr(all, "\"tags\":[\"kernel_evt\","
				      "\"stream:proc\",\"cat:fork\","
				      "\"curated:v1\"]") != NULL,
				      "tags tail-insert curated:v1");
				snprintf(imp, sizeof(imp),
					 "\"importance\":%.17g", ev.value);
				CHECK(strstr(all, imp) != NULL,
				      "importance = value (%.17g)");
				CHECK(strstr(all, "\"text\":\"[kern] proc fork "
				      "parent=1 child=4242\"") != NULL,
				      "frozen text in curated nudge");
				CHECK(strstr(all, "\"source\":\"kernel_evt\"")
				      != NULL, "source field");
			}
		}
	}

	/* ============ 5. v3 列数 + curated 落盘 ============ */
	{
		char root[256], day[11];
		struct pq_tel_row rows[3];
		struct pq_dec_row decs[2];
		struct pq_file_stats fs;
		char path[600];
		long sk = 0;

		snprintf(root, sizeof(root), "%s/pqroot", dir);
		as_pq_day_from_ts(1000000000LL, btime, day);

		/* telemetry v3：3 行（2 promoted）→ raw 3 行 13 列；
		 * curated 镜像 2 行 13 列 + curated index 6 列 */
		mkrow(&rows[0], 1000000000LL, 6, 0, "[kern] proc fork a=1",
		      0.55, AS_VF_PROMOTED);
		mkrow(&rows[1], 1100000000LL, 6, 0, "[kern] proc fork a=2",
		      0.10, 0);
		mkrow(&rows[2], 1200000000LL, 18, 0, "[kern] event decision x",
		      0.80, AS_VF_PROMOTED | AS_VF_DEC_PATH);
		CHECK(as_pq_write_telemetry(root, rows, 3, btime, 65536,
					    NULL) == 3, "write_telemetry 3");

		snprintf(path, sizeof(path), "%s/telemetry/%s/process_0000.parquet",
			 root, day);
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 2,
		      "raw telemetry file 2 rows (process)");
		CHECK(fs.has_ncols && fs.ncols == TEL_NCOL && TEL_NCOL == 13,
		      "telemetry v3 = 13 cols (footer)");
		snprintf(path, sizeof(path), "%s/telemetry/%s/ai_0000.parquet",
			 root, day);
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 1,
		      "raw telemetry ai 1 row");
		snprintf(path, sizeof(path), "%s/curated/%s/process_0000.parquet",
			 root, day);
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 1 &&
		      fs.has_ncols && fs.ncols == 13,
		      "curated mirror process 1 row 13 cols");
		snprintf(path, sizeof(path), "%s/curated/%s/ai_0000.parquet",
			 root, day);
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 1,
		      "curated mirror ai 1 row");
		snprintf(path, sizeof(path), "%s/curated/index.parquet", root);
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 2 &&
		      fs.has_ncols && fs.ncols == IDX_NCOL,
		      "curated index 2 files 6 cols");
		CHECK(as_pq_update_index(root, &sk) == 0,
		      "raw index rebuild still ok (v3)");

		/* decisions v3：默认带下 promoted 子集镜像（低带测试配置） */
		{
			struct as_conf cf;

			as_conf_defaults(&cf);
			cf.value_promote_min = 0.05;	/* 测试带：0.1 分进带 */
			cf.value_promote_max = 1.0;
			as_value_conf_init(&cf);
		}
		memset(&decs, 0, sizeof(decs));
		decs[0].decision_id = 1;
		decs[0].decision_ts = 1000000000LL;
		decs[0].outcome = 2;
		decs[0].confidence = 90;
		decs[0].agent_id = 7;
		decs[0].expected = 10;
		decs[0].cost_ns = 10000000LL;	/* writer 分=0.1 → 进带 */
		decs[1].decision_id = 2;
		decs[1].decision_ts = 1100000000LL;	/* 全 0 → 0 分不进带 */
		CHECK(as_pq_write_decisions(root, decs, 2, btime, NULL) == 2,
		      "write_decisions 2");
		snprintf(path, sizeof(path), "%s/decisions/%s/decisions.parquet",
			 root, day);
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 2 &&
		      fs.has_ncols && fs.ncols == DEC_NCOL && DEC_NCOL == 32,
		      "decisions v3 = 32 cols (footer)");
		CHECK(DEC_NCOL == PQ_MAXCOL,
		      "decisions at PQ_MAXCOL cap (design S1.2)");
		snprintf(path, sizeof(path), "%s/curated/%s/decisions.parquet",
			 root, day);
		CHECK(as_pq_file_stats(path, &fs) == 0 && fs.num_rows == 1,
		      "curated decisions mirror 1 promoted row");
		/* chains 不镜像 */
		CHECK(as_pq_write_chains(root, decs, 1, btime, NULL) == 1,
		      "write_chains 1");
		{
			char cdir[512];

			snprintf(cdir, sizeof(cdir), "%s/curated/%s", root,
				 day);
			CHECK(count_parquet(cdir) == 3,
			      "curated day dir = 3 files (no chains mirror)");
		}

		/* curated 门控关：CURATED_ENABLED=0 → 不再增长 */
		{
			struct as_conf cf;
			int before;

			as_conf_defaults(&cf);
			cf.curated_enabled = 0;
			as_value_conf_init(&cf);
			CHECK(as_value_curated_enabled() == 0, "curated gate off");
			before = count_parquet(root);
			mkrow(&rows[0], 1300000000LL, 6, 2, "[kern] proc exit",
			      0.9, AS_VF_PROMOTED);
			CHECK(as_pq_write_telemetry(root, rows, 1, btime,
						    65536, NULL) == 1,
			      "raw write with curated off");
			CHECK(count_parquet(root) == before + 1,
			      "curated dir frozen when disabled");
		}
		as_value_conf_init(NULL);	/* 复位缺省快照 */
	}

	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
		(void)!system(cmd);
	}
	if (fails) {
		printf("test_value: %d failures\n", fails);
		return 1;
	}
	printf("test_value: OK\n");
	return 0;
}
