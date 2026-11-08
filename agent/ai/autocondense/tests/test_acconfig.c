/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_acconfig.c - T5b 配置模块差分测试（acconfig.c）
 *
 *  - default_config 与 units.vectors.json 的 default_config 逐字节；
 *  - validate 正负例 23 组（中文文案逐字，含 lifecycle 的 400 形状）；
 *  - deep_merge（嵌套 sme、非对象覆盖、base 不受影响）；
 *  - save/load 往返（load 后 to_dict 等价）、AUTOCONDENSE_PORT 环境变量、
 *    损坏 quarantine、加载期未知/坏类型键丢弃；
 *  - lifecycle.vectors.json 的最终 config.json 磁盘字节复现。
 *
 * 运行：TZ=Asia/Shanghai ./tests/test_acconfig（冻结 epoch=1775000000）
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acconfig.h"

#include "ac_vec.h"

#include <sys/stat.h>
#include <unistd.h>

#define FROZEN_EPOCH 1775000000.0

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

static char *path_join2(const char *a, const char *b)
{
	size_t n = strlen(a) + 1 + strlen(b) + 1;
	char *out = malloc(n);

	if (out)
		snprintf(out, n, "%s/%s", a, b);
	return out;
}

static void dump_eq(const aik_json *got, const aik_json *want, const char *name)
{
	char *g = ac_dump(got);
	char *w = ac_dump(want);

	g_ac_checks++;
	if (!g || !w || strcmp(g, w) != 0)
		ac_fail("%s\n  got:  %s\n  want: %s", name, g ? g : "(null)",
			w ? w : "(null)");
	free(g);
	free(w);
}

/*
 * bump_port_lit - T9d 端口改号适配（8761→8762）。
 *
 * T5 向量（units/lifecycle.vectors.json）录的是 REF-PY 42466f1 的出厂
 * 默认端口 8761（向量在 aikkernel-longterm/parity，冻结只读、不在 T9d
 * 文件集）；任务书明令 acconfig 默认端口改 8762（8761 让给 aikernel-api）。
 * 本函数只改写 "port" 键后的那一个字面量，**其余字节仍逐字节断言**——
 * 不是放松差分，是把有意分叉的那一处显式对齐。
 */
static void bump_port_lit(char *s)
{
	static char *const keys[] = { "\"port\":8761", "\"port\": 8761" };
	size_t i;

	if (!s)
		return;
	for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		char *p = strstr(s, keys[i]);

		if (p) {
			char *lit = strchr(p, '8');

			if (lit && strncmp(lit, "8761", 4) == 0)
				memcpy(lit, "8762", 4);
			return;
		}
	}
}

static void validate_case(const char *input, const char *want_errors,
			  const char *name)
{
	aik_json *in = parse_text(input, name);
	aik_json *want = parse_text(want_errors, name);
	aik_json *got = ac_validate_config_dict(in);

	dump_eq(got, want, name);
	aik_json_free(in);
	aik_json_free(want);
	aik_json_free(got);
}

int main(void)
{
	aik_json *units = ac_load_vector("ac/units.vectors.json");

	if (!units)
		return 2;
	ac_time_set_now(FROZEN_EPOCH);
	unsetenv("AUTOCONDENSE_PORT");

	/* ---- default_config 逐字节 ---- */
	{
		ac_config cfg;

		ac_config_default(&cfg);
		aik_json *d = ac_config_to_dict(&cfg);

		{
			/* 向量 default_config 的 port 字面量随 T9d 改号 */
			char *wtxt = ac_dump(aik_json_get(units,
							  "default_config"));
			aik_json *wexp = NULL;

			if (wtxt) {
				bump_port_lit(wtxt);
				wexp = parse_text(wtxt, "default_config");
				free(wtxt);
			}
			dump_eq(d, wexp, "default_config");
			aik_json_free(wexp);
		}
		/* 环境变量端口（default_config_dict(use_env=True)）*/
		setenv("AUTOCONDENSE_PORT", "9001", 1);
		ac_config_default_env(&cfg);
		g_ac_checks++;
		if (cfg.port != 9001)
			ac_fail("env port should be 9001 (got %d)", cfg.port);
		setenv("AUTOCONDENSE_PORT", "not-a-number", 1);
		ac_config_default_env(&cfg);
		g_ac_checks++;
		if (cfg.port != 8762)
			ac_fail("bad env port should stay 8762 (got %d)", cfg.port);
		unsetenv("AUTOCONDENSE_PORT");
		aik_json_free(d);
		ac_config_cleanup(&cfg);
	}

	/* ---- validate：文案逐字（config.py:190-230 + lifecycle 400）---- */
	validate_case("{\"port\":\"x\"}", "[\"port 应为整数\"]", "validate port str");
	validate_case("{\"enabled\":\"yes\"}", "[\"enabled 应为布尔值\"]", "validate enabled str");
	validate_case("{\"enabled\":1}", "[\"enabled 应为布尔值\"]", "validate enabled int");
	validate_case("{\"no_such_key\":1}", "[\"未知配置项：no_such_key\"]", "validate unknown key");
	validate_case("{\"sme\":\"x\"}", "[\"sme 应为对象\"]", "validate sme not obj");
	validate_case("{\"sme\":{\"enabled\":1}}", "[\"sme.enabled 应为布尔值\"]", "validate sme.enabled int");
	validate_case("{\"sme\":{\"zzz\":1}}", "[\"未知配置项：sme.zzz\"]", "validate sme unknown");
	validate_case("{\"host\":5}", "[\"host 应为字符串\"]", "validate host int");
	validate_case("{\"water_threshold\":\"x\"}", "[\"water_threshold 应为数字\"]", "validate water str");
	validate_case("{\"water_threshold\":true}", "[\"water_threshold 应为数字\"]", "validate water bool");
	validate_case("{\"port\":true}", "[\"port 应为整数\"]", "validate port bool");
	validate_case("{\"cooldown_minutes\":1.5}", "[\"cooldown_minutes 应为整数\"]", "validate cooldown float");
	validate_case("{\"sme\":{\"timeout_s\":\"x\"}}", "[\"sme.timeout_s 应为数字\"]", "validate sme timeout str");
	validate_case("{\"sme\":{\"tags\":\"x\"}}", "[\"sme.tags 应为数组\"]", "validate sme tags str");
	validate_case("{\"sme\":{\"max_segments\":1.5}}", "[\"sme.max_segments 应为整数\"]", "validate sme max_segments float");
	validate_case("{\"enabled\":\"yes\",\"no_such_key\":1}",
		      "[\"enabled 应为布尔值\",\"未知配置项：no_such_key\"]",
		      "validate multi errors (lifecycle)");
	validate_case("[1,2]", "[\"配置必须是 JSON 对象\"]", "validate non-object");
	validate_case("null", "[\"配置必须是 JSON 对象\"]", "validate null");
	validate_case("{\"port\":8000}", "[]", "validate ok port");
	validate_case("{\"sme\":{\"importance\":2}}", "[]", "validate ok int-as-float");
	validate_case("{\"delta_mode\":false,\"sme\":{\"dedup\":false}}", "[]",
		      "validate ok bools");
	validate_case("{\"sme\":{\"base_url\":\"http://x\"}}", "[]", "validate ok base_url");
	validate_case("{\"sme\":{\"enabled\":2,\"qq\":3},\"host\":[]}",
		      "[\"sme.enabled 应为布尔值\",\"未知配置项：sme.qq\",\"host 应为字符串\"]",
		      "validate mixed order");

	/* ---- deep_merge ---- */
	{
		aik_json *base = parse_text(
			"{\"a\":1,\"sme\":{\"x\":1,\"y\":2},\"keep\":[1,2]}", "dm base");
		aik_json *ov = parse_text(
			"{\"sme\":{\"y\":9,\"z\":3},\"a\":2}", "dm override");
		aik_json *merged = ac_deep_merge(base, ov);

		dump_eq(merged, parse_text(
			"{\"a\":2,\"sme\":{\"x\":1,\"y\":9,\"z\":3},\"keep\":[1,2]}",
			"dm want1"), "deep_merge nested");
		/* base 不受影响 */
		dump_eq(base, parse_text(
			"{\"a\":1,\"sme\":{\"x\":1,\"y\":2},\"keep\":[1,2]}",
			"dm want2"), "deep_merge base untouched");
		/* 非对象覆盖整体替换 */
		aik_json *ov2 = parse_text("{\"sme\":\"flat\"}", "dm ov2");
		aik_json *m2 = ac_deep_merge(base, ov2);

		dump_eq(m2, parse_text(
			"{\"a\":1,\"sme\":\"flat\",\"keep\":[1,2]}", "dm want3"),
			"deep_merge scalar override");
		/* 空覆盖 = base */
		aik_json *empty = aik_json_new_obj();
		aik_json *m3 = ac_deep_merge(base, empty);

		aik_json_free(empty);
		dump_eq(m3, base, "deep_merge empty override");
		aik_json_free(base);
		aik_json_free(ov);
		aik_json_free(ov2);
		aik_json_free(merged);
		aik_json_free(m2);
		aik_json_free(m3);
	}

	/* ---- save/load 往返 + lifecycle config.json 磁盘字节 ---- */
	{
		aik_json *life = ac_load_vector("ac/lifecycle.vectors.json");

		if (!life)
			return 2;
		char *want_life = NULL;
		{
			const char *raw_life = aik_json_str(
				aik_json_get(aik_json_get(life, "disk"),
					     "config.json"));

			/* 向量 config.json 的 port 字面量随 T9d 改号（同上）*/
			if (raw_life) {
				want_life = strdup(raw_life);
				bump_port_lit(want_life);
			}
		}

		char *dir = ac_mkdtemp("/tmp/ac-cfg-");

		if (!dir)
			return 2;

		/* 默认保存：字节 = to_dict indent=2 + "\n" */
		ac_config cfg;

		ac_config_default(&cfg);
		g_ac_checks++;
		if (ac_save_config(dir, &cfg) != 0)
			ac_fail("save default failed");
		aik_json *d0 = ac_config_to_dict(&cfg);
		char *dump0 = ac_json_dump_indent(d0, 2);
		size_t dlen0 = dump0 ? strlen(dump0) : 0;
		char *expect0 = malloc(dlen0 + 2);

		if (expect0 && dump0) {
			memcpy(expect0, dump0, dlen0);
			expect0[dlen0] = '\n';
			expect0[dlen0 + 1] = '\0';
		}
		char *p0 = path_join2(dir, "config.json");
		size_t l0 = 0;
		char *got0 = ac_slurp(p0, &l0);

		g_ac_checks++;
		if (!got0 || !expect0 || l0 != dlen0 + 1 ||
		    memcmp(got0, expect0, l0) != 0)
			ac_fail("default config.json bytes differ (got %zu want %zu)",
				l0, dlen0 + 1);
		free(dump0);
		free(expect0);
		free(got0);
		free(p0);

		/* load 往返等价 */
		ac_config loaded;

		g_ac_checks++;
		if (ac_load_config(dir, &loaded) != 0) {
			ac_fail("load default failed");
		} else {
			aik_json *dl = ac_config_to_dict(&loaded);

			dump_eq(dl, d0, "load round-trip default");
			aik_json_free(dl);
			ac_config_cleanup(&loaded);
		}
		aik_json_free(d0);

		/* lifecycle 复现：sme.enabled=false + PUT 体 + save */
		ac_config_cleanup(&cfg);
		ac_config_default(&cfg);
		cfg.sme.enabled = 0;
		aik_json *put = parse_text(
			"{\"enabled\":true,\"turns_threshold\":18,"
			"\"sme\":{\"timeout_s\":3.5,\"tags\":[\"a\",\"b\"]}}",
			"lifecycle put");

		ac_config_apply_dict(&cfg, put);
		g_ac_checks++;
		if (ac_save_config(dir, &cfg) != 0)
			ac_fail("save lifecycle failed");
		char *pc = path_join2(dir, "config.json");
		size_t lc = 0;
		char *gotc = ac_slurp(pc, &lc);

		g_ac_checks++;
		if (!gotc || !want_life || strcmp(gotc, want_life) != 0)
			ac_fail("lifecycle config.json bytes differ\n  got:  %s\n  want: %s",
				gotc ? gotc : "(null)", want_life ? want_life : "(null)");
		free(gotc);
		free(pc);
		free(want_life);

		/* 修改后 load 往返等价 */
		aik_json *d1 = ac_config_to_dict(&cfg);

		g_ac_checks++;
		if (ac_load_config(dir, &loaded) != 0) {
			ac_fail("load lifecycle failed");
		} else {
			aik_json *dl = ac_config_to_dict(&loaded);

			dump_eq(dl, d1, "load round-trip lifecycle");
			aik_json_free(dl);
			ac_config_cleanup(&loaded);
		}
		aik_json_free(d1);
		aik_json_free(put);
		ac_config_cleanup(&cfg);

		/* 损坏 → quarantine 后默认 */
		char *pd = path_join2(dir, "config.json");
		FILE *f = fopen(pd, "wb");

		if (f) {
			fwrite("<<<not json>>>", 1, 14, f);
			fclose(f);
		}
		g_ac_checks++;
		if (ac_load_config(dir, &loaded) != 0) {
			ac_fail("load corrupt failed");
		} else {
			ac_config defaults;

			ac_config_default(&defaults);
			aik_json *dl = ac_config_to_dict(&loaded);
			aik_json *dd = ac_config_to_dict(&defaults);

			dump_eq(dl, dd, "corrupt falls back to defaults");
			aik_json_free(dl);
			aik_json_free(dd);
			ac_config_cleanup(&defaults);
			ac_config_cleanup(&loaded);
		}
		char stamp[32];

		ac_stamp_now(stamp, sizeof(stamp));
		char qpath[512];

		snprintf(qpath, sizeof(qpath), "%s.corrupt-%s", pd, stamp);
		g_ac_checks++;
		if (access(qpath, F_OK) != 0)
			ac_fail("config quarantine missing: %s", qpath);
		free(pd);

		/* 未知/坏类型键丢弃、合法键保留、环境端口 */
		char *pe = path_join2(dir, "config.json");

		f = fopen(pe, "wb");
		if (f) {
			fwrite("{\"port\":9000,\"mode\":\"delta\",\"host\":123,"
			       "\"turns_threshold\":\"x\"}",
			       1, strlen("{\"port\":9000,\"mode\":\"delta\",\"host\":123,"
					 "\"turns_threshold\":\"x\"}"), f);
			fclose(f);
		}
		setenv("AUTOCONDENSE_PORT", "9001", 1);
		g_ac_checks++;
		if (ac_load_config(dir, &loaded) != 0) {
			ac_fail("load sanitize failed");
		} else {
			g_ac_checks++;
			if (loaded.port != 9000)
				ac_fail("sanitize kept port should be 9000 (got %d)",
					loaded.port);
			g_ac_checks++;
			if (strcmp(loaded.host, "127.0.0.1") != 0)
				ac_fail("bad host should fall back (got %s)", loaded.host);
			g_ac_checks++;
			if (loaded.turns_threshold != 25)
				ac_fail("bad turns_threshold should stay 25 (got %d)",
					loaded.turns_threshold);
			ac_config_cleanup(&loaded);
		}
		unsetenv("AUTOCONDENSE_PORT");

		/* 缺失文件 + 环境端口 */
		char *dir2 = ac_mkdtemp("/tmp/ac-cfg-");

		setenv("AUTOCONDENSE_PORT", "9001", 1);
		g_ac_checks++;
		if (ac_load_config(dir2, &loaded) != 0) {
			ac_fail("load missing failed");
		} else {
			g_ac_checks++;
			if (loaded.port != 9001)
				ac_fail("missing file + env port should be 9001 (got %d)",
					loaded.port);
			ac_config_cleanup(&loaded);
		}
		unsetenv("AUTOCONDENSE_PORT");
		rmdir(dir2);
		free(dir2);
		free(pe);
		free(dir);
		aik_json_free(life);
	}

	aik_json_free(units);
	ac_summary("test_acconfig");
	return g_ac_failed ? 1 : 0;
}
