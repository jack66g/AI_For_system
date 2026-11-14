/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_review.c - occ_core/review 单测（波次 E4：验收环）
 *
 * 覆盖（ORCH-DESIGN §8 E4 验收门；§4 验收环【拍板 2】）：
 *   A) MD5 底座：RFC 1321 已知向量（""/"abc"/"message digest"）。
 *   B) 机械判判据表逐规则一正一反（纯函数——fixture 报告文本，不起
 *      子进程）：R-EXIT（exit0/exit7/signal/缺事件）、R-REPORT（缺件）、
 *      R-HEADER（缺标记/缺表头）、R-NOSELF（零机检行=自称完成不采信）、
 *      R-COVERAGE（标准条目无对应行）、R-ROWPASS（自报 fail 行）、
 *      R-EVIDENCE（自由文本证据/缺文件）、R-MD5（不符）、R-CONTAINS
 *      （断言子串未命中）、相对路径 base_dir 归一、全真过。
 *   C) 整改词/升级词渲染：§3 模板六要素逐标记（未达标准/差距/证据/
 *      整改要求/剩余机会）+ 裁判否决框架 + 升级三选一文案。
 *   D) DB 回炉回路「一拒一改一过」（§8 E4 验收门原文剧本）：
 *      首报自称完成缺机检证据（judge_pass=1 强行认可）→ 拒（防转述：
 *      机械判 fail 时裁判无放行权）+ 整改词第 1/2 次 → 复用 dispatch
 *      回炉 → 二报带真证据（file+md5+contains 全真）→ 过（done）；
 *      事件序 dispatch→result→verdict→rework→dispatch→result→verdict
 *      →done 对齐；verdict_json 落 machine_pass/judge_pass/forced。
 *   E) 超限升级剧本：rework_max=1 两连拒 → 第 1 拒 rework（剩余机会
 *      0 次）→ 第 2 拒 escalated + 升级文案（换智能体/拆任务/上抛用户）。
 *   F) 裁判否决路：机械判全过 + judge_pass=0 → rework +「裁判抽查
 *      否决」框架（§4 抽查亲跑强制）。
 *   G) orch 端到端（sim 子进程，有界）：spawn（已建任务携 acceptance
 *      brief）→ wait 终局 → 终局机械预判挂点（machine_verdict 事件）
 *      → task return 工具面走验收环 pass=true → done；坏报告任务 →
 *      return pass=true 强行认可 → forced_fail+rework_brief（工具面
 *      防转述）。
 *   H) 独立评审智能体挂载点（§4 可选件）：occ_orch_set_review_hook
 *      回调在终局触发，参数带 task_id/result_path。
 *
 * 子模式入口（自 exec——argv 形状与真 occ -p 合同一致，分发键走 env）：
 *   env OCC_RV_SIM=1 + -p <prompt> --session <sid>
 *     prompt 形态：首行 "rvsim"；FILE:<path> 行；交付内容行；
 *     "__RV_REPORT__" 行；其后=报告全文（写 OCC_TASK_RESULT_FILE）。
 *
 * 外部验证：独立 sqlite3 连接直查任务终态（同 test_task 口径）。
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sqlite3.h>

#include "occ_core/orch.h"
#include "occ_core/review.h"
#include "occ_tools/occ_tools.h"	/* E4：task return 工具面演练 */

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("ok %s\n", name); } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static char tmpdir[128];
static char self_bin[420];		/* /proc/self/exe：自 exec 用 */

static occ_db *g_db;
static occ_orch *g_o;
static char g_psid[OCC_ID_LEN];
static char g_dbpath[192];

/* H 段：评审挂载点记录器 */
static char g_hook_task[OCC_ID_LEN];
static char g_hook_result[280];
static int g_hook_calls;

/* ---- 小工具 ---- */

static void write_file(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");

	if (!f) {
		printf("FAIL write_file(%s)\n", path);
		n_fail++;
		return;
	}
	fputs(content, f);
	fclose(f);
}

static int has_rule(const occ_review_verdict *v, const char *rule)
{
	int i;

	for (i = 0; i < v->n_hit; i++)
		if (!strcmp(v->rule[i], rule))
			return 1;
	return 0;
}

/* 便捷跑环（D/E/F 段共用） */
static int run_rv(const char *tid, const char *result_path,
		  const char *note, int judge_pass,
		  occ_review_verdict *v, char *brief, size_t blen,
		  char *state, size_t slen)
{
	occ_review_opts ro;
	char err[192];

	memset(&ro, 0, sizeof(ro));
	ro.result_path = result_path;
	ro.base_dir = tmpdir;
	ro.judge_note = note;
	ro.judge_pass = judge_pass;
	return occ_review_run(g_db, tid, &ro, v, brief, blen, state, slen,
			      err, sizeof(err));
}

/* 建任务到 in_review（纯逻辑环：dispatch→review(exit0 事件)） */
static int task_to_review(const char *brief_json, char *tid_out,
			  size_t tlen)
{
	occ_task_row row;
	char err[192];

	if (occ_task_create(g_db, g_psid, "rv-unit", brief_json, 2, &row,
			    err, sizeof(err)) != 0) {
		printf("FAIL task_to_review create: %s\n", err);
		return -1;
	}
	snprintf(tid_out, tlen, "%s", row.id);
	occ_task_row_free(&row);
	if (occ_task_dispatch(g_db, tid_out, "ses_rv_child", err,
			      sizeof(err)) != 0) {
		printf("FAIL task_to_review dispatch: %s\n", err);
		return -1;
	}
	if (occ_task_review(g_db, tid_out,
			    "{\"end\":\"exit\",\"exit_code\":0,"
			    "\"signal\":0,\"dur_ms\":7,"
			    "\"stdout_path\":\"\"}",
			    err, sizeof(err)) != 0) {
		printf("FAIL task_to_review review: %s\n", err);
		return -1;
	}
	return 0;
}

/* ---- sim：子进程行为模拟器（argv 形状=orch spawn 真合同） ---- */

static int sim_main(int argc, char **argv)
{
	const char *prompt = "";
	const char *sid = "";
	const char *p, *nl, *fl, *rp;
	char path[512];
	FILE *f;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-p") && i + 1 < argc)
			prompt = argv[++i];
		else if (!strcmp(argv[i], "--session") && i + 1 < argc)
			sid = argv[++i];
	}
	(void)sid;
	if (strncmp(prompt, "rvsim\n", 6) != 0) {
		printf("SIM-OK\n");
		return 0;
	}
	p = prompt + 6;
	/* FILE:<path> 行 */
	nl = strchr(p, '\n');
	if (!nl)
		return 0;
	{
		size_t flen = (size_t)(nl - p);

		if (flen > 5 && flen - 5 < sizeof(path)) {
			memcpy(path, p + 5, flen - 5);
			path[flen - 5] = '\0';
		} else {
			path[0] = '\0';
		}
	}
	/* 交付内容行（单行）+ __RV_REPORT__ 分隔 */
	p = nl + 1;
	nl = strchr(p, '\n');
	if (!nl)
		return 0;
	if (path[0]) {
		f = fopen(path, "w");
		if (f) {
			fprintf(f, "%.*s\n", (int)(nl - p), p);
			fclose(f);
		}
	}
	fl = nl + 1;
	if (strncmp(fl, "__RV_REPORT__", 13) != 0)
		return 0;
	rp = getenv(OCC_ORCH_RESULT_ENV);
	if (rp && rp[0]) {
		f = fopen(rp, "w");
		if (f) {
			fputs(fl + 14, f);	/* 跳过标记行+\n */
			fclose(f);
		}
	}
	return 0;
}

/* ============ A MD5 已知向量 ============ */

static void sec_md5(void)
{
	char path[192], hex[40];

	snprintf(path, sizeof(path), "%s/md5_empty.bin", tmpdir);
	write_file(path, "");
	OK(occ_review_md5_file(path, hex, sizeof(hex)) == 0 &&
	   !strcmp(hex, "d41d8cd98f00b204e9800998ecf8427e"),
	   "a-md5-empty");

	snprintf(path, sizeof(path), "%s/md5_abc.bin", tmpdir);
	write_file(path, "abc");
	OK(occ_review_md5_file(path, hex, sizeof(hex)) == 0 &&
	   !strcmp(hex, "900150983cd24fb0d6963f7d28e17f72"),
	   "a-md5-abc");

	snprintf(path, sizeof(path), "%s/md5_msg.bin", tmpdir);
	write_file(path, "message digest");
	OK(occ_review_md5_file(path, hex, sizeof(hex)) == 0 &&
	   !strcmp(hex, "f96b697d7cb7938d525a2f31aaf161d0"),
	   "a-md5-message-digest");

	OK(occ_review_md5_file("/nonexistent/xx", hex, sizeof(hex)) != 0,
	   "a-md5-missing-file");
}

/* ============ B 机械判判据表（纯函数） ============ */

static const char EV_OK[] =
	"{\"end\":\"exit\",\"exit_code\":0,\"signal\":0,\"dur_ms\":9,"
	"\"stdout_path\":\"/tmp/x\"}";
static const char EV_EXIT7[] =
	"{\"end\":\"exit\",\"exit_code\":7,\"signal\":0,\"dur_ms\":9,"
	"\"stdout_path\":\"/tmp/x\"}";
static const char EV_SIGNAL[] =
	"{\"end\":\"signal\",\"exit_code\":0,\"signal\":11,\"dur_ms\":9,"
	"\"stdout_path\":\"/tmp/x\"}";

static void sec_parse(void)
{
	occ_review_verdict v;
	char path[192], hex[40], good[768];
	const char *acc[2];

	/* B2 R-EXIT 三反 */
	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n| criterion | result | evidence | self |\n"
			 "| x | pass | exit:0 | ok |\n",
			 EV_EXIT7, NULL, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_EXIT), "b-exit-code7");

	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n| criterion | result | evidence | self |\n"
			 "| x | pass | exit:0 | ok |\n",
			 EV_SIGNAL, NULL, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_EXIT), "b-exit-signal");

	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n| criterion | result | evidence | self |\n"
			 "| x | pass | exit:0 | ok |\n",
			 NULL, NULL, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_EXIT), "b-exit-no-event");

	/* B3 R-REPORT */
	occ_review_verdict_init(&v);
	occ_review_parse(NULL, EV_OK, NULL, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_REPORT), "b-report-missing");

	/* B4 R-HEADER：纯叙述自称完成（防转述核心用例） */
	occ_review_verdict_init(&v);
	occ_review_parse("任务已完成：目标全部达成，自检全过，无需复核。",
			 EV_OK, NULL, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_HEADER) &&
	   !has_rule(&v, OCC_RV_R_NOSELF), "b-header-narrative-only");

	/* B5 R-NOSELF：表头在、零数据行 */
	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n| criterion | result | evidence | self |\n",
			 EV_OK, NULL, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_NOSELF), "b-noself-zero-rows");

	/* 真证据 fixture：OUT 文件 + md5 + 断言行 */
	snprintf(path, sizeof(path), "%s/out_b.bin", tmpdir);
	write_file(path, "B-DELIVER\nASSERT-LINE-OK\n");
	OK(occ_review_md5_file(path, hex, sizeof(hex)) == 0, "b-fixture-md5");

	/* B6 全真过（acceptance↔行对齐 + 三类令牌） */
	acc[0] = "exit=0";
	acc[1] = "file:out_b.bin";
	{
		char md5row[96];

		snprintf(md5row, sizeof(md5row),
			 "md5:out_b.bin=%s", hex);
		snprintf(good, sizeof(good),
			 "# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| exit=0 | pass | exit:0 | 退出码已核 |\n"
			 "| file:out_b.bin | pass | file:out_b.bin | 已生成 |\n"
			 "| %s | pass | %s | 校验一致 |\n"
			 "| contains:out_b.bin:ASSERT-LINE-OK | pass | "
			 "contains:out_b.bin:ASSERT-LINE-OK | 断言在文件 |\n",
			 md5row, md5row);
		occ_review_verdict_init(&v);
		occ_review_parse(good, EV_OK, tmpdir, acc, 2, &v);
		OK(v.pass && v.n_hit == 0, "b-all-pass");
	}

	/* B7 R-COVERAGE：标准条目无对应行 */
	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| exit=0 | pass | exit:0 | ok |\n",
			 EV_OK, tmpdir, acc, 2, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_COVERAGE), "b-coverage-miss");

	/* B8 R-ROWPASS：自报 fail 行 */
	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| exit=0 | fail | exit:0 | 差一步 |\n",
			 EV_OK, tmpdir, acc, 1, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_ROWPASS) &&
	   !has_rule(&v, OCC_RV_R_EVIDENCE), "b-rowpass-fail-row");

	/* B9 R-EVIDENCE：自由文本证据 + 缺文件 */
	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| x | pass | 我亲眼看过没问题 | 相信我 |\n",
			 EV_OK, NULL, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_EVIDENCE), "b-evidence-free-text");

	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| x | pass | file:no_such_file.bin | 已生成 |\n",
			 EV_OK, tmpdir, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_EVIDENCE), "b-evidence-no-file");

	/* B10 R-MD5：hex 不符（叙述再漂亮也不救——防转述） */
	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| x | pass | md5:out_b.bin=00000000000000000000000000000000"
			 " | 已校验一致，任务完成 |\n",
			 EV_OK, tmpdir, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_MD5), "b-md5-mismatch");

	/* B11 R-CONTAINS：断言子串未命中 */
	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| x | pass | contains:out_b.bin:ASSERT-ABSENT | 在 |\n",
			 EV_OK, tmpdir, NULL, 0, &v);
	OK(!v.pass && has_rule(&v, OCC_RV_R_CONTAINS), "b-contains-miss");

	/* B13 相对路径按 base_dir 归一（file: 在场过） */
	occ_review_verdict_init(&v);
	occ_review_parse("# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| file:out_b.bin | pass | file:out_b.bin | ok |\n",
			 EV_OK, tmpdir, acc + 1, 1, &v);
	OK(v.pass, "b-basedir-relative");
}

/* ============ C 整改词/升级词渲染 ============ */

static void sec_render(void)
{
	occ_review_verdict v;
	char buf[OCC_RV_BRIEF_MAX];

	occ_review_verdict_init(&v);
	v.pass = 0;
	snprintf(v.rule[0], OCC_RV_RULE_MAX, "%s", OCC_RV_R_HEADER);
	snprintf(v.detail[0], OCC_RV_DETAIL_MAX, "缺 # VERDICT 标记");
	snprintf(v.rule[1], OCC_RV_RULE_MAX, "%s", OCC_RV_R_COVERAGE);
	snprintf(v.detail[1], OCC_RV_DETAIL_MAX,
		 "验收标准[0]「file:OUT」无对应行");
	v.n_hit = 2;

	occ_review_render_rework(&v, 0, NULL, 1, 2, buf, sizeof(buf));
	OK(strstr(buf, "【验收不通过 第 1/2 次】") &&
	   strstr(buf, "未达标准：") &&
	   strstr(buf, "差距：") &&
	   strstr(buf, "证据：") &&
	   strstr(buf, "整改要求：") &&
	   strstr(buf, "剩余机会：1 次，超限将 换智能体"),
	   "c-rework-template");

	occ_review_render_rework(&v, 1, "亲跑 md5 不一致，报告不实", 1, 2,
				 buf, sizeof(buf));
	OK(strstr(buf, "裁判抽查否决") &&
	   strstr(buf, "亲跑 md5 不一致，报告不实"),
	   "c-rework-judge-reject");

	occ_review_render_escalate(&v, 0, NULL, 2, 2, buf, sizeof(buf));
	OK(strstr(buf, "【验收超限上抛") &&
	   strstr(buf, "换智能体重派 / 拆解任务 / 上抛用户"),
	   "c-escalate-three-ways");
}

/* ============ D 回炉回路「一拒一改一过」 ============ */

static void sec_loop(void)
{
	char tid[OCC_ID_LEN];
	char brief[OCC_RV_BRIEF_MAX], state[24];
	char rep[192], out[192], hex[40], bjson[768];
	occ_review_verdict v;
	occ_task_row row;
	occ_task_event_row *evs = NULL;
	size_t nevs = 0, i;
	char seq[256];
	size_t so = 0;
	char err[192];

	snprintf(out, sizeof(out), "%s/out_d.bin", tmpdir);
	write_file(out, "D-DELIVER-V2\nASSERT-D-OK\n");
	OK(occ_review_md5_file(out, hex, sizeof(hex)) == 0, "d-fixture");

	snprintf(bjson, sizeof(bjson),
		 "{\"goal\":\"交付 out_d.bin\",\"acceptance\":"
		 "[\"exit=0\",\"file:out_d.bin\",\"md5:out_d.bin=%s\","
		 "\"contains:out_d.bin:ASSERT-D-OK\"],\"rework_max\":2}",
		 hex);
	OK(task_to_review(bjson, tid, sizeof(tid)) == 0, "d-task-in-review");

	/* 一拒：首报自称完成（叙述），裁判强行认可 → 仍拒（防转述） */
	snprintf(rep, sizeof(rep), "%s/rep_d1.md", tmpdir);
	write_file(rep, "任务完成：out_d.bin 已交付，自检全部通过，"
		 "无需再验，请直接通过。");
	OK(run_rv(tid, rep, "认可：看报告没问题", 1, &v, brief,
		  sizeof(brief), state, sizeof(state)) == 0, "d-run1");
	OK(!strcmp(state, OCC_TASK_ST_REWORK) && !v.pass &&
	   v.n_hit >= 2, "d-r1-rework");
	OK(strstr(brief, "【验收不通过 第 1/2 次】") &&
	   strstr(brief, "剩余机会：1 次"), "d-r1-brief");
	/* 防转述铁证：judge_pass=1 但机械判 fail → 任务没进 done */
	OK(occ_task_get(g_db, tid, &row, err, sizeof(err)) == 1 &&
	   strcmp(row.status, OCC_TASK_ST_DONE) != 0 &&
	   row.rework_count == 1, "d-r1-anti-paraphrase");
	occ_task_row_free(&row);

	/* 回炉：复用既有 dispatch（rework→dispatched）↺ */
	OK(occ_task_dispatch(g_db, tid, NULL, err, sizeof(err)) == 0,
	   "d-redispatch");
	OK(occ_task_review(g_db, tid,
			   "{\"end\":\"exit\",\"exit_code\":0,"
			   "\"signal\":0,\"dur_ms\":5,"
			   "\"stdout_path\":\"\"}",
			   err, sizeof(err)) == 0, "d-review2");

	/* 一改：二报带真证据（表+file+md5+contains 全真） */
	{
		char rep2[1024], md5row[300];

		snprintf(md5row, sizeof(md5row), "md5:out_d.bin=%s", hex);
		snprintf(rep2, sizeof(rep2),
			 "# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| exit=0 | pass | exit:0 | 退出码 0 |\n"
			 "| file:out_d.bin | pass | file:out_d.bin | 已生成 |\n"
			 "| %s | pass | %s | 校验一致 |\n"
			 "| contains:out_d.bin:ASSERT-D-OK | pass | "
			 "contains:out_d.bin:ASSERT-D-OK | 断言在场 |\n",
			 md5row, md5row);
		snprintf(rep, sizeof(rep), "%s/rep_d2.md", tmpdir);
		write_file(rep, rep2);
	}
	/* 一过：judge 抽查亲跑表态 → done */
	OK(run_rv(tid, rep, "抽查亲跑：md5 我亲算一致，放行", 1, &v, brief,
		  sizeof(brief), state, sizeof(state)) == 0 &&
	   !strcmp(state, OCC_TASK_ST_DONE) && v.pass,
	   "d-r2-pass-done");
	OK(brief[0] == '\0', "d-r2-no-brief");

	/* verdict_json 审计三件（machine_pass/judge_pass/forced） */
	OK(occ_task_get(g_db, tid, &row, err, sizeof(err)) == 1 &&
	   row.verdict_json &&
	   strstr(row.verdict_json, "\"machine_pass\":true") &&
	   strstr(row.verdict_json, "\"judge_pass\":true") &&
	   strstr(row.verdict_json, "\"forced\":false") &&
	   strstr(row.verdict_json, "抽查亲跑"),
	   "d-verdict-json");
	occ_task_row_free(&row);

	/* 事件序对齐（dispatch→result→verdict→rework→dispatch→result
	 * →verdict→done；return/rework_brief note 行不计入状态序） */
	seq[0] = '\0';
	if (occ_task_events(g_db, tid, &evs, &nevs, NULL, 0) == 0) {
		for (i = 0; i < nevs; i++) {
			if (!strcmp(evs[i].kind, OCC_TASK_EV_DISPATCH))
				so += snprintf(seq + so, sizeof(seq) - so,
					       "%s", "D");
			else if (!strcmp(evs[i].kind, OCC_TASK_EV_RESULT))
				so += snprintf(seq + so, sizeof(seq) - so,
					       "%s", "R");
			else if (!strcmp(evs[i].kind, OCC_TASK_EV_VERDICT))
				so += snprintf(seq + so, sizeof(seq) - so,
					       "%s", "V");
			else if (!strcmp(evs[i].kind, OCC_TASK_EV_REWORK))
				so += snprintf(seq + so, sizeof(seq) - so,
					       "%s", "W");
			else if (!strcmp(evs[i].kind, OCC_TASK_EV_DONE))
				so += snprintf(seq + so, sizeof(seq) - so,
					       "%s", "N");
			if (so >= sizeof(seq) - 2)
				break;
		}
		occ_task_event_rows_free(evs, nevs);
	}
	OK(!strcmp(seq, "DRVWDRVN"), "d-event-sequence");
}

/* ============ E 超限升级（rework_max=1 两连拒） ============ */

static void sec_escalate(void)
{
	char tid[OCC_ID_LEN];
	char brief[OCC_RV_BRIEF_MAX], state[24];
	char rep[192];
	occ_review_verdict v;
	occ_task_row row;
	char err[192];

	OK(occ_task_create(g_db, g_psid, "rv-esc",
			   "{\"goal\":\"交付\",\"acceptance\":"
			   "[\"file:out_e_missing.bin\"],\"rework_max\":1}",
			   1, &row, err, sizeof(err)) == 0, "e-create");
	snprintf(tid, sizeof(tid), "%s", row.id);
	occ_task_row_free(&row);
	OK(occ_task_dispatch(g_db, tid, "ses_rv_child2", err,
			     sizeof(err)) == 0 &&
	   occ_task_review(g_db, tid,
			   "{\"end\":\"exit\",\"exit_code\":0,"
			   "\"signal\":0,\"dur_ms\":4,\"stdout_path\":\"\"}",
			   err, sizeof(err)) == 0, "e-to-review");

	snprintf(rep, sizeof(rep), "%s/rep_e.md", tmpdir);
	write_file(rep, "任务完成：全部达标。");

	/* 第 1 拒：count=1≤1 → rework，剩余机会 0 */
	OK(run_rv(tid, rep, "转述认可", 1, &v, brief, sizeof(brief), state,
		  sizeof(state)) == 0 &&
	   !strcmp(state, OCC_TASK_ST_REWORK) &&
	   strstr(brief, "第 1/1 次") &&
	   strstr(brief, "剩余机会：0 次"), "e-r1-rework-last-chance");
	OK(occ_task_dispatch(g_db, tid, NULL, err, sizeof(err)) == 0 &&
	   occ_task_review(g_db, tid,
			   "{\"end\":\"exit\",\"exit_code\":0,"
			   "\"signal\":0,\"dur_ms\":4,\"stdout_path\":\"\"}",
			   err, sizeof(err)) == 0, "e-round2-setup");

	/* 第 2 拒：count=2>1 → escalated + 三选一文案 */
	OK(run_rv(tid, rep, "再给一次机会", 1, &v, brief, sizeof(brief),
		  state, sizeof(state)) == 0 &&
	   !strcmp(state, OCC_TASK_ST_ESCALATED) &&
	   strstr(brief, "【验收超限上抛") &&
	   strstr(brief, "换智能体重派 / 拆解任务 / 上抛用户"),
	   "e-r2-escalated");

	/* 终局后再 return：验收环拒绝（非法迁移人话，不静默） */
	{
		occ_review_opts ro;
		char err2[192];

		memset(&ro, 0, sizeof(ro));
		ro.judge_note = "还想再裁";
		ro.judge_pass = 1;
		OK(occ_review_run(g_db, tid, &ro, NULL, NULL, 0, NULL, 0,
				  err2, sizeof(err2)) != 0 &&
		   strstr(err2, "in_review"), "e-post-terminal-reject");
	}
}

/* ============ F 机械判过 + 裁判否决 → 回炉 ============ */

static void sec_judge_reject(void)
{
	char tid[OCC_ID_LEN];
	char brief[OCC_RV_BRIEF_MAX], state[24];
	char out[192], rep[192];
	occ_review_verdict v;

	snprintf(out, sizeof(out), "%s/out_f.bin", tmpdir);
	write_file(out, "F-DELIVER\n");
	snprintf(rep, sizeof(rep), "%s/rep_f.md", tmpdir);
	write_file(rep, "# VERDICT\n"
		 "| criterion | result | evidence | self |\n"
		 "| file:out_f.bin | pass | file:out_f.bin | 已生成 |\n");
	OK(task_to_review("{\"goal\":\"f\",\"acceptance\":"
			  "[\"file:out_f.bin\"],\"rework_max\":2}",
			  tid, sizeof(tid)) == 0, "f-setup");

	OK(run_rv(tid, rep, "否决：内容是占位符，与目标不符", 0, &v, brief,
		  sizeof(brief), state, sizeof(state)) == 0 &&
	   v.pass &&			/* 机械判全过 */
	   !strcmp(state, OCC_TASK_ST_REWORK) &&
	   strstr(brief, "裁判抽查否决") &&
	   strstr(brief, "内容是占位符"),
	   "f-judge-reject-rework");
}

/* ============ E5 子会话蒸馏（done 两级蒸馏第二级） ============ */

static void e5_distill_case(void)
{
	char tid[64];
	char *txt;
	char err[192];

	OK(task_to_review("{\"goal\":\"交付 out_e5.bin\",\"acceptance\":"
			  "[\"file:out_e5.bin\"],\"rework_max\":2}",
			  tid, sizeof(tid)) == 0, "e5-setup");
	/* 直接走状态机到 done（机械判面已由 D/F/G 段覆盖） */
	OK(occ_task_verdict(g_db, tid, 1, "{\"pass\":true}", err,
			    sizeof(err)) == 0, "e5-verdict-done");
	txt = occ_orch_distill(g_db, tid);
	OK(txt && strstr(txt, "【任务蒸馏") &&
	   strstr(txt, "file:out_e5.bin"),
	   "e5-distill-text");
	free(txt);
	{
		occ_task_event_row *evs = NULL;
		size_t nevs = 0, i;
		int found = 0;

		if (occ_task_events(g_db, tid, &evs, &nevs, NULL, 0) == 0) {
			for (i = 0; i < nevs; i++)
				if (!strcmp(evs[i].kind, OCC_TASK_EV_DISTILL))
					found = 1;
			occ_task_event_rows_free(evs, nevs);
		}
		OK(found, "e5-distill-event");
	}
	OK(occ_orch_distill(g_db, tid) == NULL, "e5-distill-idempotent");
}

/* ============ G orch 端到端（sim 子进程）+ return 工具面 ============ */

static const char *g_rv_env[2] = { "OCC_RV_SIM=1", NULL };

static void sec_e2e(void)
{
	occ_task_row row;
	occ_orch_spawn_opts so;
	occ_orch_child *c1 = NULL, *c2 = NULL;
	occ_orch_result r;
	occ_tool_ctx tc;
	occ_tool_result tr;
	char deliver[192], scratch[192], hex[40];
	char prompt[4096], bjson[1024], md5acc[320], args[512];
	char tid[OCC_ID_LEN], tid2[OCC_ID_LEN], err[256];
	occ_task_event_row *evs = NULL;
	size_t nevs = 0, i;
	int found_mv = 0;
	const char *fs1[1], *fs2[1];

	setenv("OCC_ORCH_TOOLS", "1", 1);
	setenv("OCC_ORCH_BIN", self_bin, 1);

	snprintf(deliver, sizeof(deliver), "%s/e2e_deliver.txt", tmpdir);
	snprintf(scratch, sizeof(scratch), "%s/e2e_scratch.txt", tmpdir);
	write_file(scratch, "RV-E2E-DELIVER-V1\n");
	OK(occ_review_md5_file(scratch, hex, sizeof(hex)) == 0, "g-md5-pre");
	snprintf(md5acc, sizeof(md5acc), "md5:%s=%s", deliver, hex);
	snprintf(bjson, sizeof(bjson),
		 "{\"goal\":\"g\",\"acceptance\":[\"file:%s\",\"%s\"],"
		 "\"rework_max\":2}", deliver, md5acc);

	memset(&tc, 0, sizeof(tc));
	tc.db = g_db;
	tc.session_id = g_psid;
	tc.workdir = tmpdir;
	tc.orch = g_o;
	tc.trace_dir = tmpdir;		/* 测试不写 ~/.occ */
	tc.snaproot = tmpdir;

	/* G1 好剧本：真交付+真报告 → 终局预判 note → return 工具面过 */
	OK(occ_task_create(g_db, g_psid, "g-good", bjson, 2, &row, err,
			   sizeof(err)) == 0, "g1-create");
	snprintf(tid, sizeof(tid), "%s", row.id);
	occ_task_row_free(&row);
	{
		char repbody[2048];

		snprintf(repbody, sizeof(repbody),
			 "# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| file:%s | pass | file:%s | 已生成 |\n"
			 "| %s | pass | %s | 校验一致 |\n",
			 deliver, deliver, md5acc, md5acc);
		snprintf(prompt, sizeof(prompt),
			 "rvsim\nFILE:%s\nRV-E2E-DELIVER-V1\n"
			 "__RV_REPORT__\n%s", deliver, repbody);
	}
	memset(&so, 0, sizeof(so));
	so.prompt = prompt;
	so.parent_session = g_psid;
	so.task_id = tid;
	so.occ_bin = self_bin;
	so.env = g_rv_env;
	fs1[0] = deliver;
	so.fileset = fs1;
	so.nfileset = 1;
	so.workdir = tmpdir;
	OK(occ_orch_spawn(g_o, &so, &c1, err, sizeof(err)) == OCC_ORCH_OK,
	   "g1-spawn");
	if (c1) {
		occ_orch_wait(c1, &r, err, sizeof(err));
		occ_orch_result_free(&r);
		c1 = NULL;
	}
	/* 终局挂点：machine_verdict 预判事件在场且 pass=true */
	if (occ_task_events(g_db, tid, &evs, &nevs, NULL, 0) == 0) {
		for (i = 0; i < nevs; i++)
			if (!strcmp(evs[i].kind, OCC_TASK_EV_RETURN) &&
			    evs[i].payload_json &&
			    strstr(evs[i].payload_json,
				   "machine_verdict") &&
			    strstr(evs[i].payload_json, "\"pass\":true"))
				found_mv = 1;
		occ_task_event_rows_free(evs, nevs);
		evs = NULL;
	}
	OK(found_mv, "g1-prenote-event");

	/* return 工具面（judge pass=true）→ done */
	memset(&tr, 0, sizeof(tr));
	snprintf(args, sizeof(args),
		 "{\"action\":\"return\",\"task_id\":\"%s\",\"pass\":true,"
		 "\"verdict\":\"抽查亲跑：md5 一致\"}", tid);
	OK(occ_tool_exec(&tc, "task", "call_g1", args, &tr) == 0 &&
	   tr.text && strstr(tr.text, "\"state\":\"done\"") &&
	   strstr(tr.text, "\"machine_pass\":true") &&
	   strstr(tr.text, "\"recorded\":true"),
	   "g1-tool-return-done");
	occ_tool_result_free(&tr);

	/* G2 坏剧本：报告自称达标但交付缺文件 → return pass=true 强行
	 * 认可 → forced_fail + rework + 整改词（工具面防转述） */
	{
		char deliver2[192];

		snprintf(deliver2, sizeof(deliver2),
			 "%s/e2e_deliver2.txt", tmpdir);
		unlink(deliver2);
		OK(occ_task_create(g_db, g_psid, "g-bad",
				   "{\"goal\":\"g2\",\"acceptance\":"
				   "[\"file:%s\"],\"rework_max\":2}",
				   2, &row, err, sizeof(err)) == 0, "g2-create");
		snprintf(tid2, sizeof(tid2), "%s", row.id);
		occ_task_row_free(&row);
		snprintf(prompt, sizeof(prompt),
			 "rvsim\nFILE:/dev/null\nX\n__RV_REPORT__\n"
			 "# VERDICT\n"
			 "| criterion | result | evidence | self |\n"
			 "| file:%s | pass | file:%s | 已生成，任务完成 |\n",
			 deliver2, deliver2);
		memset(&so, 0, sizeof(so));
		so.prompt = prompt;
		so.parent_session = g_psid;
		so.task_id = tid2;
		so.occ_bin = self_bin;
		so.env = g_rv_env;
		fs2[0] = deliver2;
		so.fileset = fs2;
		so.nfileset = 1;
		so.workdir = tmpdir;
		OK(occ_orch_spawn(g_o, &so, &c2, err, sizeof(err)) ==
		   OCC_ORCH_OK, "g2-spawn");
		if (c2) {
			occ_orch_wait(c2, &r, err, sizeof(err));
			occ_orch_result_free(&r);
			c2 = NULL;
		}
		snprintf(args, sizeof(args),
			 "{\"action\":\"return\",\"task_id\":\"%s\","
			 "\"pass\":true,\"verdict\":\"我认可，请通过\"}",
			 tid2);
		OK(occ_tool_exec(&tc, "task", "call_g2", args, &tr) == 0 &&
		   tr.text && strstr(tr.text, "\"state\":\"rework\"") &&
		   strstr(tr.text, "\"machine_pass\":false") &&
		   strstr(tr.text, "\"forced_fail\":true") &&
		   strstr(tr.text, "验收不通过"),
		   "g2-tool-return-forced-fail");
		occ_tool_result_free(&tr);
	}

	/* G3 read_result 带 machine_verdict 字段 */
	snprintf(args, sizeof(args),
		 "{\"action\":\"read_result\",\"task_id\":\"%s\"}", tid2);
	OK(occ_tool_exec(&tc, "task", "call_g3", args, &tr) == 0 &&
	   tr.text && strstr(tr.text, "\"machine_verdict\":"),
	   "g3-read-result-mv");
	occ_tool_result_free(&tr);

	/* G4 外部验证：独立 sqlite 直查 G1 任务终态=done */
	{
		sqlite3 *h;
		sqlite3_stmt *st;
		int rc, seen = 0;
		char q[256], got[24] = "";

		snprintf(q, sizeof(q),
			 "SELECT status FROM occ_task WHERE id='%s'", tid);
		OK(sqlite3_open_v2(g_dbpath, &h, SQLITE_OPEN_READONLY,
				   NULL) == SQLITE_OK, "g4-sqlite-open");
		if (sqlite3_prepare_v2(h, q, -1, &st, NULL) == SQLITE_OK) {
			rc = sqlite3_step(st);
			if (rc == SQLITE_ROW) {
				snprintf(got, sizeof(got), "%s",
					 sqlite3_column_text(st, 0));
				seen = 1;
			}
			sqlite3_finalize(st);
		}
		sqlite3_close(h);
		OK(seen && !strcmp(got, "done"), "g4-external-done");
	}

	unsetenv("OCC_ORCH_TOOLS");
	unsetenv("OCC_ORCH_BIN");
}

/* ============ H 独立评审智能体挂载点 ============ */

static int review_hook_cb(void *ud, occ_db *db, const char *task_id,
			  const char *result_path, const char *result_event_json)
{
	(void)ud;
	(void)db;
	(void)result_event_json;
	snprintf(g_hook_task, sizeof(g_hook_task), "%s",
		 task_id ? task_id : "");
	snprintf(g_hook_result, sizeof(g_hook_result), "%s",
		 result_path ? result_path : "");
	g_hook_calls++;
	return 0;
}

static void sec_hook(void)
{
	occ_task_row row;
	occ_orch_spawn_opts so;
	occ_orch_child *c = NULL;
	occ_orch_result r;
	char tid[OCC_ID_LEN], err[256];
	const char *fs[1];

	setenv("OCC_ORCH_BIN", self_bin, 1);
	occ_orch_set_review_hook(g_o, review_hook_cb, NULL);
	OK(occ_task_create(g_db, g_psid, "h-hook",
			   "{\"goal\":\"h\",\"acceptance\":[],"
			   "\"rework_max\":2}", 2, &row, err,
			   sizeof(err)) == 0, "h-create");
	snprintf(tid, sizeof(tid), "%s", row.id);
	occ_task_row_free(&row);
	/* spawn 自带 pending→dispatched（勿先手动 dispatch——状态机会拒） */
	memset(&so, 0, sizeof(so));
	so.prompt = "rvsim\nFILE:/dev/null\nX\n__RV_REPORT__\n# VERDICT\n"
		    "| criterion | result | evidence | self |\n";
	so.parent_session = g_psid;
	so.task_id = tid;
	so.occ_bin = self_bin;
	so.env = g_rv_env;
	fs[0] = "/tmp/occ_rv_h_hook.txt";
	so.fileset = fs;
	so.nfileset = 1;
	so.workdir = tmpdir;
	g_hook_calls = 0;
	OK(occ_orch_spawn(g_o, &so, &c, err, sizeof(err)) == OCC_ORCH_OK,
	   "h-spawn");
	if (c) {
		occ_orch_wait(c, &r, err, sizeof(err));
		occ_orch_result_free(&r);
		c = NULL;
	}
	OK(g_hook_calls == 1 && !strcmp(g_hook_task, tid) &&
	   g_hook_result[0] == '/', "h-review-hook-called");
	occ_orch_set_review_hook(g_o, NULL, NULL);
	unsetenv("OCC_ORCH_BIN");
}

/* ============ main ============ */

static int unit_main(void)
{
	char err[192];
	occ_session_row srow;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_test_review.XXXXXX");
	if (!mkdtemp(tmpdir)) {
		printf("FAIL mkdtemp\n");
		return 1;
	}
	if (readlink("/proc/self/exe", self_bin, sizeof(self_bin) - 1) <= 0) {
		printf("FAIL /proc/self/exe\n");
		return 1;
	}
	self_bin[sizeof(self_bin) - 1] = '\0';

	snprintf(g_dbpath, sizeof(g_dbpath), "%s/review.db", tmpdir);
	g_db = occ_db_open(g_dbpath, err, sizeof(err));
	OK(g_db != NULL, "db-open");
	if (!g_db)
		return 1;
	OK(occ_session_create(g_db, "test-model", &srow, err,
			      sizeof(err)) == 0, "parent-session");
	snprintf(g_psid, sizeof(g_psid), "%s", srow.id);
	g_o = occ_orch_new(g_db);
	OK(g_o != NULL, "orch-new");

	sec_md5();
	sec_parse();
	sec_render();
	sec_loop();
	sec_escalate();
	sec_judge_reject();
	sec_e2e();
	sec_hook();

	occ_orch_free(g_o);
		/* E5 蒸馏案（须在关库前——E5 前事故：调用于 close 后=U-C） */
	e5_distill_case();

occ_db_close(g_db);

	/* 子进程残留自检（同居生产 VM 纪律：测试收尾零残留） */
	printf("review tests: %d ok / FAIL=%d\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}

int main(int argc, char **argv)
{
	/* sim 分发键=env 标记（argv 形状与真 occ -p 合同一致） */
	if (getenv("OCC_RV_SIM") && argc >= 2 && !strcmp(argv[1], "-p"))
		return sim_main(argc, argv);
	return unit_main();
}
