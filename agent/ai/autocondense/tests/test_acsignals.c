/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_acsignals.c - T5b 信号采集/判定差分测试（acsignals.c）
 *
 * units.vectors.json（T5a 录制，宿主 parity/vectors/ac）：
 *   - estimate 2：临时 transcript 文件复现录制器 fixture（CJK 加权 30）；
 *   - urgency 8 / collect 14 / decide 14：构造输入 → 输出紧凑 dump 与向量
 *     逐字节比对。collect 的 "estimated" 用例按本机临时 transcript 路径
 *     重写 state.transcript_path（录制端为 Windows 临时路径）。
 *
 * 运行：TZ=Asia/Shanghai ./tests/test_acsignals（冻结 epoch=1775000000）
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acsignals.h"

#include "ac_vec.h"

#include <sys/stat.h>
#include <unistd.h>

#define FROZEN_EPOCH 1775000000.0

static const char *TR_FIXTURE =
	"{\"role\":\"user\",\"content\":\"hello world of tokens\"}\n"
	"{\"role\":\"assistant\",\"content\":\"你好世界，中文回答\"}\n";

static aik_json *parse_text(const char *text, const char *what)
{
	char err[128];
	aik_json *v = aik_json_parse(text, strlen(text), err, sizeof(err));

	if (!v) {
		fprintf(stderr, "FATAL: parse %s: %s\n", what, err);
		exit(2);
	}
	return v;
}

int main(void)
{
	aik_json *vec = ac_load_vector("ac/units.vectors.json");

	if (!vec)
		return 2;
	ac_time_set_now(FROZEN_EPOCH);
	unsetenv("AUTOCONDENSE_PORT");

	/* ---- estimate：临时 transcript fixture ---- */
	char *tmp = ac_mkdtemp("/tmp/ac-sig-");

	if (!tmp)
		return 2;
	char tr_path[512];

	snprintf(tr_path, sizeof(tr_path), "%s/tr.jsonl", tmp);
	FILE *f = fopen(tr_path, "wb");

	if (!f)
		return 2;
	fwrite(TR_FIXTURE, 1, strlen(TR_FIXTURE), f);
	fclose(f);

	const aik_json *est_vec = aik_json_get(vec, "estimate");

	g_ac_checks++;
	if (!est_vec || aik_json_count(est_vec) != 2)
		ac_fail("estimate vector count");

	{
		int has = 0;
		long long out = 0;

		ac_estimate_transcript_tokens(tr_path, &has, &out);
		g_ac_checks++;
		if (!has || out != aik_json_int(aik_json_get(aik_json_at(est_vec, 0), "out")))
			ac_fail("estimate fixture got has=%d out=%lld want=%lld",
				has, out,
				aik_json_int(aik_json_get(aik_json_at(est_vec, 0), "out")));

		char miss_path[512];
		int mhas = 1;
		long long mout = -1;

		snprintf(miss_path, sizeof(miss_path), "%s/missing.jsonl", tmp);
		ac_estimate_transcript_tokens(miss_path, &mhas, &mout);
		g_ac_checks++;
		if (mhas || mout != 0)
			ac_fail("estimate missing file should be None");
		ac_estimate_transcript_tokens(NULL, &mhas, &mout);
		g_ac_checks++;
		if (mhas)
			ac_fail("estimate NULL path should be None");
	}

	/* ---- urgency 8 ---- */
	{
		const aik_json *arr = aik_json_get(vec, "urgency");

		for (size_t i = 0; i < aik_json_count(arr); i++) {
			const aik_json *c = aik_json_at(arr, i);
			aik_json *sig = aik_json_new_obj();
			aik_json *w = (aik_json *)aik_json_get(c, "water_level");
			char *wtext = ac_dump(w);
			aik_json *wclone = wtext ? parse_text(wtext, "water") : NULL;

			free(wtext);
			if (!sig || !wclone ||
			    aik_json_obj_put(sig, "water_level", wclone) != 0) {
				aik_json_free(sig);
				aik_json_free(wclone);
				ac_fail("urgency[%zu] build", i);
				continue;
			}
			const char *got = ac_urgency_of(sig);
			const char *want = aik_json_str(aik_json_get(c, "out"));

			g_ac_checks++;
			if (!want || strcmp(got, want) != 0)
				ac_fail("urgency[%zu] got=%s want=%s", i, got,
					want ? want : "(null)");
			aik_json_free(sig);
		}
	}

	/* ---- collect 14 ---- */
	{
		const aik_json *arr = aik_json_get(vec, "collect");

		for (size_t i = 0; i < aik_json_count(arr); i++) {
			const aik_json *c = aik_json_at(arr, i);
			const char *name = aik_json_str(aik_json_get(c, "name"));

			aik_json *state_d = (aik_json *)aik_json_get(c, "state");

			/* 录制端 transcript 路径重写为本机临时文件 */
			const aik_json *tp = aik_json_get(state_d, "transcript_path");

			if (tp && aik_json_typeof(tp) == AIK_JSON_STR) {
				aik_json *repl = aik_json_new_str(tr_path);

				if (aik_json_obj_set(state_d, "transcript_path", repl) != 0)
					aik_json_free(repl);
			}
			ac_session *s = ac_session_from_dict(state_d);

			if (!s) {
				ac_fail("collect[%zu] (%s) state build", i, name ? name : "?");
				continue;
			}
			ac_config cfg;

			ac_config_default(&cfg);
			const aik_json *cfg_d = aik_json_get(c, "config");

			if (cfg_d)
				ac_config_apply_dict(&cfg, cfg_d);
			aik_json *out = ac_collect(s, &cfg);
			char *got = ac_dump(out);
			char *want = ac_dump(aik_json_get(c, "out"));

			g_ac_checks++;
			if (!got || !want || strcmp(got, want) != 0)
				ac_fail("collect[%zu] (%s)\n  got:  %s\n  want: %s", i,
					name ? name : "?", got ? got : "(null)",
					want ? want : "(null)");
			free(got);
			free(want);
			aik_json_free(out);
			ac_session_free(s);
			ac_config_cleanup(&cfg);
		}
	}

	/* ---- decide 14 ---- */
	{
		const aik_json *arr = aik_json_get(vec, "decide");

		for (size_t i = 0; i < aik_json_count(arr); i++) {
			const aik_json *c = aik_json_at(arr, i);
			const char *name = aik_json_str(aik_json_get(c, "name"));
			ac_session *s = ac_session_from_dict(aik_json_get(c, "state"));

			if (!s) {
				ac_fail("decide[%zu] (%s) state build", i, name ? name : "?");
				continue;
			}
			ac_config cfg;

			ac_config_default(&cfg);
			const aik_json *cfg_d = aik_json_get(c, "config");

			if (cfg_d)
				ac_config_apply_dict(&cfg, cfg_d);
			aik_json *out = ac_decide(s, aik_json_get(c, "signals"), &cfg);
			char *got = ac_dump(out);
			char *want = ac_dump(aik_json_get(c, "out"));

			g_ac_checks++;
			if (!got || !want || strcmp(got, want) != 0)
				ac_fail("decide[%zu] (%s)\n  got:  %s\n  want: %s", i,
					name ? name : "?", got ? got : "(null)",
					want ? want : "(null)");
			free(got);
			free(want);
			aik_json_free(out);
			ac_session_free(s);
			ac_config_cleanup(&cfg);
		}
	}

	/* ---- decide 的 now 注入佐证：冷却剩余分钟数 ---- */
	{
		char state_text[512];

		snprintf(state_text, sizeof(state_text),
			 "{\"session_id\":\"s1\",\"cwd\":\"/tmp/proj\","
			 "\"transcript_path\":null,\"context_tokens\":null,"
			 "\"est_tokens\":null,\"token_samples\":[],"
			 "\"context_tokens_turn\":null,\"last_file_turn\":null,"
			 "\"last_fail_turn\":null,\"plan_items\":[],"
			 "\"plan_archive\":[],\"turns\":0,\"turns_since_condense\":0,"
			 "\"last_condense_at\":null,"
			 "\"cooldown_until\":\"2026-04-01T07:58:20\","
			 "\"last_trigger\":null,\"condensing\":false,"
			 "\"last_judge\":null,\"defer_until_turn\":null,"
			 "\"defer_streak\":0,\"begin_mode\":null,"
			 "\"created_at\":\"2026-03-31T07:00:00\","
			 "\"last_seen\":\"2026-03-31T07:00:00\"}");
		ac_session *s = ac_session_from_dict(
			parse_text(state_text, "decide-cooldown-state"));
		aik_json *sig = parse_text(
			"{\"plan_total\":0,\"plan_completed\":0,\"plan_in_progress\":0,"
			"\"turns_since_condense\":0,\"minutes_since_condense\":null,"
			"\"est_tokens\":null,\"token_source\":null,\"rounds_to_full\":null,"
			"\"idle_rounds\":null,\"water_level\":null,\"cooldown_active\":true,"
			"\"urgency\":\"normal\"}", "decide-cooldown-sig");
		ac_config cfg;

		ac_config_default(&cfg);
		aik_json *out = ac_decide(s, sig, &cfg);
		const aik_json *reason = aik_json_get(out, "reason");

		g_ac_checks++;
		if (!reason || strcmp(aik_json_str(reason),
				     "压缩冷却期内（剩余约 25 分钟），暂不压缩") != 0)
			ac_fail("decide cooldown reason got=%s",
				reason ? aik_json_str(reason) : "(null)");
		aik_json_free(out);
		aik_json_free(sig);
		ac_session_free(s);
		ac_config_cleanup(&cfg);
	}

	unlink(tr_path);
	rmdir(tmp);
	free(tmp);
	aik_json_free(vec);
	ac_summary("test_acsignals");
	return g_ac_failed ? 1 : 0;
}
