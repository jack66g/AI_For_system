/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_sense_redact.c - SENSE 脱敏单测（产生侧；设计 SENSE-REDACT-DESIGN §6）
 *
 * 覆盖：
 *  1. 五档策略各 ≥1 精确断言（pass/hash/trunc/mask/drop）
 *  2. 三态开关：同一敏感样例 off（逐字节=基线冻结行）/soft/strict
 *     （§2.2 表逐字段期望）
 *  3. 未知字段：proc_id 非 uid/gid → 透传+unknown_pass 计数
 *  4. 前后对拍：soft/strict 输出中敏感原文零命中（泄漏扫描）
 *  5. decision_id 审计链例外：soft/strict 下原样
 *  6. 盐：同值加盐/不加盐 hash 不同；同盐稳定
 *  7. ev->pid 列（T8 parquet pid 源）：off=原值，hash 档=fnv 派生非零
 *  8. as_stats 渲染 sense_redact.* 段
 *
 * 敏感样例全部虚构（对拍用，非真实数据）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "as_event.h"
#include "as_redact.h"
#include "as_stats.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

#define CHECK_LINE(ev, expect) do { \
	if (strcmp((ev)->line, expect) != 0) { \
		printf("FAIL: line mismatch\n  got:  [%s]\n  want: [%s]\n", \
		       (ev)->line, expect); \
		fails++; \
	} \
} while (0)

/* 敏感样例集（虚构；与 apic 侧 test_sense_redact 同集——两侧语义对拍） */
#define S_COMM		"chrome"
#define S_USER		"alice"
#define S_ADDR		"10.0.0.23"
#define S_DST		"192.168.1.0"
#define S_GW		"10.0.0.254"
#define S_UID		1000
#define S_PATH		"/devices/pci0000:00/serial42"
#define S_PREFIX	"DROP user-a"
#define S_MODEL		"mlp-v3-alice.bin"
#define S_DEV		"ttyS42"
#define S_PID		4242

static int contains_any(const char *hay, const char *const *needles, int n)
{
	for (int i = 0; i < n; i++)
		if (strstr(hay, needles[i]))
			return 1;
	return 0;
}

/* 无盐 hash 期望串（FNV-1a64 公式独立重算，不经 as_redact 代码） */
static void expect_hash(char *out, size_t cap, const char *v)
{
	uint64_t h = 1469598103934665603ULL;
	const char *p;

	h ^= 0x01;
	for (p = v; *p; p++) {
		h ^= (unsigned char)*p;
		h *= 1099511628211ULL;
	}
	snprintf(out, cap, "h:%016llx", (unsigned long long)h);
}

int main(void)
{
	struct as_event ev;
	char buf[512];

	/* ---- 1. 五档策略精确断言（引擎直测） ---- */
	{
		char h[32], got[32];

		as_redact_str(buf, sizeof(buf), AS_R_PASS, S_COMM);
		CHECK(strcmp(buf, S_COMM) == 0, "pass identity");

		expect_hash(h, sizeof(h), S_COMM);
		as_redact_str(got, sizeof(got), AS_R_HASH, S_COMM);
		CHECK(strcmp(got, h) == 0, "hash fnv exact");

		as_redact_str(buf, sizeof(buf), AS_R_TRUNC,
			      "abcdef0123456789xyz");
		CHECK(strcmp(buf, "abcdef01~19") == 0, "trunc exact");

		as_redact_str(buf, sizeof(buf), AS_R_MASK, S_COMM);
		CHECK(strcmp(buf, "c***") == 0, "mask exact");
		as_redact_str(buf, sizeof(buf), AS_R_MASK, "");
		CHECK(strcmp(buf, "***") == 0, "mask empty");

		as_redact_str(buf, sizeof(buf), AS_R_DROP, S_COMM);
		CHECK(strcmp(buf, "-") == 0, "drop marker");
	}

	/* ---- 2. off：冻结基线逐字节（=test_event fixture 口径） ---- */
	as_redact_set(AS_REDACT_OFF, "");
	as_event_proc_comm(&ev, S_PID, S_COMM);
	CHECK_LINE(&ev, "[kern] proc comm pid=4242 comm=chrome");
	CHECK(ev.pid == S_PID, "off pid col passthrough");
	as_event_proc_fork(&ev, 1, 42);
	CHECK_LINE(&ev, "[kern] proc fork parent=1 child=42");

	/* ---- 3. soft：§2.2 表逐字段 ---- */
	as_redact_set(AS_REDACT_SOFT, "");
	{
		char hcomm[32], hpid[32], huid[32], h1001[32];

		expect_hash(hcomm, sizeof(hcomm), S_COMM);
		expect_hash(hpid, sizeof(hpid), "4242");
		expect_hash(huid, sizeof(huid), "1000");
		expect_hash(h1001, sizeof(h1001), "1001");

		as_event_proc_comm(&ev, S_PID, S_COMM);
		snprintf(buf, sizeof(buf),
			 "[kern] proc comm pid=%s comm=%s", hpid, hcomm);
		CHECK_LINE(&ev, buf);
		CHECK(ev.pid > 0 && ev.pid != S_PID, "soft pid col hashed");

		as_event_proc_id(&ev, "uid", S_PID, 1000, 1001);
		snprintf(buf, sizeof(buf),
			 "[kern] proc uid pid=%s ruid=%s euid=%s",
			 hpid, huid, h1001);
		CHECK_LINE(&ev, buf);

		as_event_net_addr(&ev, 1, "inet", S_ADDR, 24, 2);
		CHECK_LINE(&ev,
			   "[kern] net newaddr if=2 family=inet addr=1***/24");

		as_event_net_route(&ev, 1, "inet", S_DST, 24, 2, S_GW);
		CHECK_LINE(&ev,
			   "[kern] net newroute family=inet dst=1***/24 "
			   "oif=2 gw=1***");

		/* mask("/") = 斜杠 + ***（路径首字符是 '/'） */
		as_event_uevent(&ev, "add", S_PATH, "tty");
		CHECK_LINE(&ev, "[kern] uevent add dev=/*** subsystem=tty");

		as_event_nflog(&ev, 2, 0x64, S_PREFIX, 1, S_UID);
		snprintf(buf, sizeof(buf),
			 "[kern] nflog packet hook=2 mark=100 prefix=D*** "
			 "uid=%s", huid);
		CHECK_LINE(&ev, buf);

		as_event_ai_model(&ev, 7, 1, S_MODEL);
		CHECK_LINE(&ev, "[kern] event model id=7 op=load name=m***");

		as_event_ai_device(&ev, 0, S_DEV);
		CHECK_LINE(&ev, "[kern] event device action=probe dev=ttyS42");

		/* decision_id 例外：soft 下原样（K3-DESIGN §K3c） */
		as_event_ai_policy(&ev, 4711ULL, 2, NULL, "mm.swappiness");
		CHECK_LINE(&ev,
			   "[kern] event policy decision_id=4711 executed=2 "
			   "param=mm.swappiness");
		CHECK(ev.decision_id == 4711ULL && ev.has_decision_id,
		      "soft decision_id passthrough");
	}

	/* ---- 4. strict：drop 档 ---- */
	as_redact_set(AS_REDACT_STRICT, "");
	{
		char hpid[32];

		expect_hash(hpid, sizeof(hpid), "4242");

		as_event_proc_comm(&ev, S_PID, S_COMM);
		snprintf(buf, sizeof(buf),
			 "[kern] proc comm pid=%s comm=-", hpid);
		CHECK_LINE(&ev, buf);

		as_event_proc_id(&ev, "gid", S_PID, 1000, 1001);
		snprintf(buf, sizeof(buf),
			 "[kern] proc gid pid=%s rgid=- egid=-", hpid);
		CHECK_LINE(&ev, buf);

		as_event_net_addr(&ev, 1, "inet", S_ADDR, 24, 2);
		CHECK_LINE(&ev,
			   "[kern] net newaddr if=2 family=inet addr=-/24");

		as_event_uevent(&ev, "add", S_PATH, "tty");
		CHECK_LINE(&ev, "[kern] uevent add dev=- subsystem=tty");

		as_event_nflog(&ev, 2, 0x64, S_PREFIX, 1, S_UID);
		CHECK_LINE(&ev,
			   "[kern] nflog packet hook=2 mark=100 prefix=- "
			   "uid=-");

		as_event_ai_model(&ev, 7, 1, S_MODEL);
		CHECK_LINE(&ev, "[kern] event model id=7 op=load name=-");

		as_event_ai_device(&ev, 0, S_DEV);
		CHECK_LINE(&ev, "[kern] event device action=probe dev=t***");

		as_event_ai_policy(&ev, 4711ULL, 2, NULL, "mm.swappiness");
		CHECK_LINE(&ev,
			   "[kern] event policy decision_id=4711 executed=2 "
			   "param=mm.swappiness");

		as_event_outcome(&ev, 4711ULL, 1, -3, "sec.audit");
		CHECK(ev.decision_id == 4711ULL, "strict outcome decision_id");
	}

	/* ---- 5. 泄漏扫描：soft/strict 全构造器输出零命中敏感原文 ---- */
	{
		static const char *const needles[] = {
			S_COMM, S_USER, S_ADDR, S_DST, S_GW, S_PREFIX,
			S_MODEL, "serial42",
		};
		enum { N_NEE = 8 };

		as_redact_set(AS_REDACT_SOFT, "");
		as_event_proc_comm(&ev, S_PID, S_COMM);
		CHECK(!contains_any(ev.line, needles, N_NEE), "soft comm leak");
		as_event_net_addr(&ev, 1, "inet", S_ADDR, 24, 2);
		CHECK(!contains_any(ev.line, needles, N_NEE), "soft addr leak");
		as_event_net_route(&ev, 1, "inet", S_DST, 24, 2, S_GW);
		CHECK(!contains_any(ev.line, needles, N_NEE), "soft route leak");
		as_event_uevent(&ev, "add", S_PATH, "tty");
		CHECK(!contains_any(ev.line, needles, N_NEE), "soft uevent leak");
		as_event_nflog(&ev, 2, 0x64, S_PREFIX, 1, S_UID);
		CHECK(!contains_any(ev.line, needles, N_NEE), "soft nflog leak");
		as_event_ai_model(&ev, 7, 1, S_MODEL);
		CHECK(!contains_any(ev.line, needles, N_NEE), "soft model leak");

		as_redact_set(AS_REDACT_STRICT, "");
		as_event_proc_comm(&ev, S_PID, S_COMM);
		CHECK(!contains_any(ev.line, needles, N_NEE),
		      "strict comm leak");
		as_event_nflog(&ev, 2, 0x64, S_PREFIX, 1, S_UID);
		CHECK(!contains_any(ev.line, needles, N_NEE),
		      "strict nflog leak");
		as_event_uevent(&ev, "add", S_PATH, "tty");
		CHECK(!contains_any(ev.line, needles, N_NEE),
		      "strict uevent leak");
	}

	/* ---- 6. 未知字段：proc_id 非 uid/gid → 透传+计数 ---- */
	as_redact_set(AS_REDACT_SOFT, "");
	{
		long long before = as_redact_stats()->unknown_pass;
		char hpid[32];

		expect_hash(hpid, sizeof(hpid), "4242");
		as_event_proc_id(&ev, "sid", S_PID, 5, 6);
		snprintf(buf, sizeof(buf),
			 "[kern] proc sid pid=%s rsid=5 esid=6", hpid);
		CHECK_LINE(&ev, buf);
		CHECK(as_redact_stats()->unknown_pass == before + 1,
		      "unknown_pass counted");
	}

	/* ---- 7. 盐 ---- */
	{
		char none[32], salted[32];

		as_redact_set(AS_REDACT_SOFT, "");
		as_redact_str(none, sizeof(none), AS_R_HASH, S_COMM);
		as_redact_set(AS_REDACT_SOFT, "pepper");
		as_redact_str(salted, sizeof(salted), AS_R_HASH, S_COMM);
		CHECK(strcmp(none, salted) != 0, "salt changes hash");
		as_redact_str(buf, sizeof(buf), AS_R_HASH, S_COMM);
		CHECK(strcmp(buf, salted) == 0, "salted stable");
	}

	/* ---- 8. stats 渲染 sense_redact.* 段 ---- */
	{
		struct as_stats st;
		char *bp = NULL;
		size_t bl = 0;
		FILE *mm = open_memstream(&bp, &bl);

		memset(&st, 0, sizeof(st));
		CHECK(mm != NULL, "memstream open");
		if (mm) {
			as_stats_render(&st, 0, 0, mm);
			fclose(mm);
			CHECK(bp && strstr(bp, "sense_redact.applied=") != NULL,
			      "stats sense_redact.applied");
			CHECK(bp && strstr(bp, "sense_redact.unknown_pass=") !=
			      NULL, "stats sense_redact.unknown_pass");
			free(bp);
		}
	}

	/* 收尾复位 off（本进程独占，防御性） */
	as_redact_set(AS_REDACT_OFF, "");

	if (fails) {
		printf("test_sense_redact: %d FAIL(s)\n", fails);
		return 1;
	}
	printf("test_sense_redact: all checks passed\n");
	return 0;
}
