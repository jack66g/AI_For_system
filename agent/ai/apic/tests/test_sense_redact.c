/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_sense_redact.c - /sense 暴露侧脱敏单测（设计 SENSE-REDACT-DESIGN §6）
 *
 * 覆盖：
 *  1. 五档策略各 ≥1 精确断言（api_redact_str）
 *  2. 三态：off（strdup 等价逐字节）/soft/strict（§2.1 表逐字段期望）
 *  3. 未知键：telemetry 行 newkey= → 透传+unknown_pass 计数
 *  4. 前后对拍：soft/strict 输出敏感原文零命中（泄漏扫描）
 *  5. decision_id（chains id=）恒原样（审计链例外）
 *  6. 盐：env 盐改变 hash；同盐稳定
 *  7. status 冒号风 + models 行定点替换（前缀/后缀字节保留）
 *  8. 配置源：model.toml [api] sense_redact（g_api.toml_file 指临时文件）
 *
 * 与 aistreamd tests/test_sense_redact.c 共用敏感样例集（虚构）——两侧
 * 引擎同公式由 hash 期望值交叉锁定。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "apic/api.h"
#include "../apiredact.h"
#include "desktop/dtcore.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

#define CHECK_STR(got, want, msg) do { \
	const char *g_ = (got); \
	if (!g_ || strcmp(g_, (want)) != 0) { \
		printf("FAIL: %s\n  got:  [%s]\n  want: [%s]\n", msg, \
		       g_ ? g_ : "(null)", (want)); \
		fails++; \
	} \
} while (0)

/* 敏感样例集（虚构；与 aistreamd 侧同集） */
#define S_PATH_MODEL	"/home/alice/model.bin"
#define S_MODEL		"mlp-v3-alice.bin"
#define S_PID_STR	"4242"
#define S_TELEM_HEXVAL	"6368726f6d652065786563..."	/* "chrome exec" 11B */

static const char TELEM_IN[] =
	"ts=1775000000000000000 pid=4242 tgid=4242 cpu=3 cat=6 ev=1 "
	"sev=1 len=64 data=" S_TELEM_HEXVAL "\n";

static const char CHAINS_IN[] =
	"id=4711 trig_ts=1775000000000000000 trig_evid=0x0601 "
	"dec_ts=1775000000000000123 type=2 data=4242:10:0:0:0:0:0:0 "
	"exec_ts=1775000000000000456 outcome_ts=0 outcome=0 delta=0 "
	"ver=1 conf=80 domain=2 src=1 executed=1 safety_clamped=0\n";

static const char STATUS_IN[] =
	"runtime_state: 2\n"
	"enabled: 1\n"
	"model_path: " S_PATH_MODEL "\n"
	"telemetry_format: human\n"
	"models: 1\n"
	"  [0] name=" S_MODEL " version=1 source=1 state=1\n";

/* 无盐 FNV 期望（独立重算，公式同 aistreamd expect_hash） */
static void expect_hash(char *out, size_t cap, const char *v)
{
	unsigned long long h = 1469598103934665603ULL;
	const char *p;

	h ^= 0x01;
	for (p = v; *p; p++) {
		h ^= (unsigned char)*p;
		h *= 1099511628211ULL;
	}
	snprintf(out, cap, "h:%016llx", h);
}

static void set_level(const char *lvl)
{
	if (lvl) {
		setenv("AIK_SENSE_REDACT", lvl, 1);
	} else {
		unsetenv("AIK_SENSE_REDACT");
	}
}

int main(void)
{
	char hp[32], hmodel[32], hpath[32];

	expect_hash(hp, sizeof(hp), S_PID_STR);
	expect_hash(hmodel, sizeof(hmodel), S_MODEL);
	expect_hash(hpath, sizeof(hpath), S_PATH_MODEL);

	/* ---- 1. 五档策略精确断言 ---- */
	{
		char buf[512], h[32];

		api_redact_str(buf, sizeof(buf), API_R_PASS, "", "chrome");
		CHECK_STR(buf, "chrome", "pass identity");

		expect_hash(h, sizeof(h), "chrome");
		api_redact_str(buf, sizeof(buf), API_R_HASH, "", "chrome");
		CHECK_STR(buf, h, "hash fnv exact");

		api_redact_str(buf, sizeof(buf), API_R_TRUNC, "",
			       "abcdef0123456789xyz");
		CHECK_STR(buf, "abcdef01~19", "trunc exact");

		api_redact_str(buf, sizeof(buf), API_R_MASK, "", "chrome");
		CHECK_STR(buf, "c***", "mask exact");

		api_redact_str(buf, sizeof(buf), API_R_DROP, "", "chrome");
		CHECK_STR(buf, "-", "drop marker");
	}

	/* ---- 2. off：strdup 等价（逐字节） ---- */
	set_level("off");
	{
		char *o = api_sense_redact_text("telemetry", TELEM_IN,
						strlen(TELEM_IN), NULL);

		CHECK(o && strcmp(o, TELEM_IN) == 0, "off telemetry identity");
		free(o);
		o = api_sense_redact_text("status", STATUS_IN,
					  strlen(STATUS_IN), NULL);
		CHECK(o && strcmp(o, STATUS_IN) == 0, "off status identity");
		free(o);
	}

	/* ---- 3. soft：§2.1 表逐字段 ---- */
	set_level("soft");
	{
		char want[1024];
		char *o = api_sense_redact_text("telemetry", TELEM_IN,
						strlen(TELEM_IN), NULL);

		/* data soft=trunc：前 8 字符 + "~25"（原值 22 hex + "..."） */
		snprintf(want, sizeof(want),
			 "ts=1775000000000000000 pid=%s tgid=%s cpu=3 cat=6 "
			 "ev=1 sev=1 len=64 data=6368726f~25\n", hp, hp);
		CHECK(o && strcmp(o, want) == 0, "soft telemetry exact");
		free(o);

		/* chains soft：data pass → 全行逐字节不变 */
		o = api_sense_redact_text("chains", CHAINS_IN,
					  strlen(CHAINS_IN), NULL);
		CHECK(o && strcmp(o, CHAINS_IN) == 0,
		      "soft chains pass-through (data pass)");
		free(o);

		/* status soft：model_path/name hash，其余行原字节 */
		o = api_sense_redact_text("status", STATUS_IN,
					  strlen(STATUS_IN), NULL);
		snprintf(want, sizeof(want),
			 "runtime_state: 2\n"
			 "enabled: 1\n"
			 "model_path: %s\n"
			 "telemetry_format: human\n"
			 "models: 1\n"
			 "  [0] name=%s version=1 source=1 state=1\n",
			 hpath, hmodel);
		CHECK(o && strcmp(o, want) == 0, "soft status exact");
		free(o);
	}

	/* ---- 4. strict：drop/mask 档 ---- */
	set_level("strict");
	{
		char want[1024];
		char *o = api_sense_redact_text("telemetry", TELEM_IN,
						strlen(TELEM_IN), NULL);

		snprintf(want, sizeof(want),
			 "ts=1775000000000000000 pid=%s tgid=%s cpu=3 cat=6 "
			 "ev=1 sev=1 len=64 data=-\n", hp, hp);
		CHECK(o && strcmp(o, want) == 0, "strict telemetry exact");
		free(o);

		/* chains strict：data=mask（首字符+***） */
		o = api_sense_redact_text("chains", CHAINS_IN,
					  strlen(CHAINS_IN), NULL);
		CHECK(o && strstr(o, "data=4***") != NULL,
		      "strict chains data masked");
		CHECK(o && strstr(o, "id=4711") != NULL,
		      "strict chains id passthrough (decision_id 例外)");
		CHECK(o && strstr(o, "executed=1") != NULL,
		      "strict chains executed passthrough");
		free(o);

		/* status strict：model_path/name drop */
		o = api_sense_redact_text("status", STATUS_IN,
					  strlen(STATUS_IN), NULL);
		CHECK(o && strstr(o, "model_path: -") != NULL,
		      "strict status model_path dropped");
		CHECK(o && strstr(o, "name=-") != NULL,
		      "strict status name dropped");
		CHECK(o && strstr(o, "telemetry_format: human") != NULL,
		      "strict status other lines preserved");
		free(o);

		/* decisions what 同 chains 规则 */
		o = api_sense_redact_text("decisions", CHAINS_IN,
					  strlen(CHAINS_IN), NULL);
		CHECK(o && strstr(o, "data=4***") != NULL,
		      "strict decisions data masked");
		free(o);
	}

	/* ---- 5. 纯计数面整体透传（control/latency/hitrate/sched/vfs） ---- */
	set_level("strict");
	{
		const char *ctl = "domain=3 net.ipv4.tcp_rmem min=4096 max=6291456\n";
		char *o = api_sense_redact_text("control", ctl, strlen(ctl),
						NULL);

		CHECK(o && strcmp(o, ctl) == 0,
		      "strict control pass-through");
		free(o);
	}

	/* ---- 6. 未知键：telemetry 行 newkey= 透传+计数 ---- */
	set_level("soft");
	{
		const char *in =
			"ts=1 pid=4242 tgid=4242 cpu=0 cat=1 ev=1 sev=1 "
			"len=0 newkey=zz data=ab\n";
		long long before = api_redact_stats()->unknown_pass;
		char *o = api_sense_redact_text("telemetry", in,
						strlen(in), NULL);

		CHECK(o && strstr(o, "newkey=zz") != NULL,
		      "unknown key passed through");
		CHECK(api_redact_stats()->unknown_pass == before + 1,
		      "unknown_pass counted");
		free(o);
	}

	/* ---- 7. 泄漏扫描：soft/strict 输出敏感原文零命中 ---- */
	{
		static const char *const needles[] = {
			"alice", S_MODEL, "chrome exec",
		};
		enum { N_NEE = 3 };
		char *o;

		set_level("soft");
		o = api_sense_redact_text("telemetry", TELEM_IN,
					  strlen(TELEM_IN), NULL);
		CHECK(o && !strstr(o, "chrome exec") &&
		      !strstr(o, "alice"), "soft telemetry leak scan");
		free(o);
		o = api_sense_redact_text("status", STATUS_IN,
					  strlen(STATUS_IN), NULL);
		CHECK(o && !strstr(o, "alice") && !strstr(o, S_MODEL),
		      "soft status leak scan");
		free(o);

		set_level("strict");
		o = api_sense_redact_text("telemetry", TELEM_IN,
					  strlen(TELEM_IN), NULL);
		CHECK(o && !strstr(o, "chrome exec"),
		      "strict telemetry leak scan");
		free(o);
		o = api_sense_redact_text("status", STATUS_IN,
					  strlen(STATUS_IN), NULL);
		CHECK(o && !strstr(o, "alice") && !strstr(o, S_MODEL),
		      "strict status leak scan");
		free(o);
		(void)needles;
	}

	/* ---- 8. 盐：env 盐改变 hash、同盐稳定 ---- */
	set_level("soft");
	{
		setenv("AIK_SENSE_REDACT_SALT", "pepper", 1);
		{
			char *o = api_sense_redact_text("telemetry",
							TELEM_IN,
							strlen(TELEM_IN),
							NULL);
			char *o2;

			CHECK(o && strstr(o, hp) == NULL,
			      "salt changes pid hash");
			o2 = api_sense_redact_text("telemetry", TELEM_IN,
						   strlen(TELEM_IN), NULL);
			CHECK(o && o2 && strcmp(o, o2) == 0,
			      "salted stable");
			free(o);
			free(o2);
		}
		unsetenv("AIK_SENSE_REDACT_SALT");
	}

	/* ---- 9. 配置源：model.toml [api] sense_redact（env 未设） ---- */
	unsetenv("AIK_SENSE_REDACT");
	{
		char path[] = "/tmp/aik-redact-test-XXXXXX";
		int fd = mkstemp(path);

		CHECK(fd >= 0, "mkstemp");
		if (fd >= 0) {
			FILE *f = fdopen(fd, "w");

			fprintf(f, "[api]\nsense_redact = \"soft\"\n");
			fclose(f);
			snprintf(g_api.toml_file, sizeof(g_api.toml_file),
				 "%s", path);
			{
				char *o = api_sense_redact_text(
					"telemetry", TELEM_IN,
					strlen(TELEM_IN), NULL);

				CHECK(o && strstr(o, hp) != NULL,
				      "toml sense_redact=soft effective");
				free(o);
			}
			unlink(path);
			g_api.toml_file[0] = '\0';
		}
	}
	/* 坏 toml 值 → off（诚实降级） */
	{
		char path[] = "/tmp/aik-redact-test2-XXXXXX";
		int fd = mkstemp(path);

		if (fd >= 0) {
			FILE *f = fdopen(fd, "w");

			fprintf(f, "[api]\nsense_redact = \"bogus\"\n");
			fclose(f);
			snprintf(g_api.toml_file, sizeof(g_api.toml_file),
				 "%s", path);
			{
				char *o = api_sense_redact_text(
					"telemetry", TELEM_IN,
					strlen(TELEM_IN), NULL);

				CHECK(o && strcmp(o, TELEM_IN) == 0,
				      "bad toml value degrades to off");
				free(o);
			}
			unlink(path);
			g_api.toml_file[0] = '\0';
		}
	}

	if (fails) {
		printf("test_sense_redact: %d FAIL(s)\n", fails);
		return 1;
	}
	printf("test_sense_redact: all checks passed\n");
	return 0;
}
