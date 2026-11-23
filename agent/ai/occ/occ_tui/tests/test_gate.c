/* SPDX-License-Identifier: GPL-2.0 */
/* test_gate.c - T4 登录门纯逻辑面单测（凭据文件/哈希/旁路判定）
 * ⑨ P-60/D1（CON-02b）：凭据「读不了」≠「没有」——errno 分类纯函数、
 *   目录/只写文件读出=TUI_GATE_READ_DENIED、写侧对读不出的既有文件拒写
 * ⑩ P-60/D7（DEC-07 过渡方案）：写出的 gate 文件权限契约——root 且机器上
 *   有 aik-gate 组=0640 root:aik-gate，否则 0600。有组环境须 root 且显式
 *   开关 AIK_TEST_HAVE_GATE_GROUP=1（测试自建组 gid 942、atexit 删组）。
 */
#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tui_gate.h"

static int fails;

#define CHECK(cond) do { \
	if (!(cond)) { fails++; \
		printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

static void write_file(const char *p, const char *s)
{
	FILE *f = fopen(p, "w");

	assert(f);
	fputs(s, f);
	fclose(f);
}

/* ⑨c 只写凭据桩（有效 admin 条目形态；哈希体为桩字节，非真密） */
#define WO_LINE ("admin:$6$wo$" \
		 "WronlyWronlyWronlyWronlyWronlyWronlyWronly" \
		 "WronlyWronlyWronlyWronlyWronlyWronlyWronly:1\n")

/* ---- P-60/D7：写出文件的权限契约 ----
 * 期望值由测试侧独立查组得出（不复用被测的判定函数——否则「把契约
 * 改没了」的变异会连期望值一起改，测试空过）。 */
static int g_made_group;		/* 本测试建的 aik-gate 组（退出时删） */

static void gate_group_cleanup(void)
{
	if (g_made_group) {
		int rc = system("groupdel aik-gate >/dev/null 2>&1");

		if (rc != 0)
			printf("WARN groupdel aik-gate failed (rc=%d) -- "
			       "please clean up\n", rc);
	}
}

/* 有组环境：仅 root 且显式开关 AIK_TEST_HAVE_GATE_GROUP=1 才建组
 * （gid 942=出厂定值）；机器上本有该组=直接沿用、不建不删。 */
static void gate_group_setup(void)
{
	struct group gr, *res = NULL;
	char buf[2048];
	const char *sw;

	if (geteuid() != 0)
		return;			/* 非 root 建不了组：测 0600 老口径 */
	if (getgrnam_r("aik-gate", &gr, buf, sizeof(buf), &res) == 0 && res) {
		printf("[D7] machine has aik-gate (gid %u): 0640 path\n",
		       (unsigned)gr.gr_gid);
		return;
	}
	sw = getenv("AIK_TEST_HAVE_GATE_GROUP");
	if (!sw || strcmp(sw, "1") != 0) {
		printf("SKIP D7 0640 path (needs AIK_TEST_HAVE_GATE_GROUP=1;"
		       " testing 0600 fallback)\n");
		return;
	}
	if (system("groupadd -g 942 aik-gate >/dev/null 2>&1") == 0) {
		g_made_group = 1;
		printf("[D7] created group aik-gate gid 942 (groupdel at "
		       "exit): 0640 path\n");
	} else {
		printf("SKIP D7 0640 path (groupadd -g 942 aik-gate failed;"
		       " testing 0600 fallback)\n");
	}
}

/* 测试侧独立判定：当前环境写出的 gate 是否应为 0640 root:aik-gate */
static int test_wide(gid_t *gid)
{
	struct group gr, *res = NULL;
	char buf[2048];

	if (geteuid() != 0)
		return 0;
	if (getgrnam_r("aik-gate", &gr, buf, sizeof(buf), &res) != 0 || !res)
		return 0;
	if (gid)
		*gid = gr.gr_gid;
	return 1;
}

static mode_t expect_gate_mode(void)
{
	return test_wide(NULL) ? (mode_t)0640 : (mode_t)0600;
}

int main(void)
{
	char dir[] = "/tmp/gateXXXXXX";
	char p[256], cmdline[256], hash[128], hash2[128], rd[128];
	long long ts = 0;
	struct stat st;

	assert(mkdtemp(dir));
	snprintf(p, sizeof(p), "%s/console-gate", dir);
	snprintf(cmdline, sizeof(cmdline), "%s/cmdline", dir);
	setenv("AIK_CONSOLE_GATE", p, 1);
	atexit(gate_group_cleanup);		/* P-60/D7：本测试建的组退出即删 */
	gate_group_setup();

	/* ① 路径覆盖生效 */
	CHECK(strcmp(tui_gate_path(), p) == 0);

	/* ② skipboot 判定（文件内容） */
	write_file(cmdline, "root=PARTUUID=x rw ai.enabled=1\n");
	CHECK(tui_gate_skipboot_path(cmdline) == 0);
	write_file(cmdline, "root=x rw ai.skipgate=1 kunit.enable=0\n");
	CHECK(tui_gate_skipboot_path(cmdline) == 1);
	write_file(cmdline, "root=x ai.skipgate=0\n");
	CHECK(tui_gate_skipboot_path(cmdline) == 0);	/* 精确 token */

	/* ③ 哈希：生成/校验/驳回 */
	CHECK(tui_gate_hash("s3cret!", hash) == 0);
	CHECK(strncmp(hash, "$6$", 3) == 0 && strlen(hash) < 128);
	CHECK(tui_gate_verify("s3cret!", hash) == 1);
	CHECK(tui_gate_verify("wrong", hash) == 0);
	CHECK(tui_gate_verify("", hash) == 0);
	CHECK(tui_gate_hash("", hash2) == -1);		/* 空密码拒 */
	{
		char longpw[128];
		int i;

		for (i = 0; i < 100; i++)
			longpw[i] = 'a';
		longpw[100] = '\0';
		CHECK(tui_gate_hash(longpw, hash2) == -1);	/* 超长拒 */
	}
	/* 同密码两次盐不同 → 哈希不同（但都验过） */
	CHECK(tui_gate_hash("s3cret!", hash2) == 0);
	CHECK(strcmp(hash, hash2) != 0);
	CHECK(tui_gate_verify("s3cret!", hash2) == 1);

	/* ④ 写+读 roundtrip */
	CHECK(tui_gate_write(p, hash) == 0);
	/* 模式=契约值（D7：root 且有 aik-gate 组=0640，否则 0600） */
	CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == expect_gate_mode());
	CHECK(access("p.tmp-path-none", 0) != 0);
	{
		char tmpchk[300];

		snprintf(tmpchk, sizeof(tmpchk), "%s.tmp", p);
		CHECK(access(tmpchk, 0) != 0);		/* 原子写无残留 */
	}
	ts = 0;
	CHECK(tui_gate_read(p, rd, &ts) == 0);
	CHECK(strcmp(rd, hash) == 0 && ts > 1700000000LL);

	/* ⑤ 坏格式拒 */
	write_file(p, "garbage-no-colon\n");
	CHECK(tui_gate_read(p, rd, &ts) == -1);
	write_file(p, "root:$6$abc$:123\n");
	CHECK(tui_gate_read(p, rd, &ts) == -1);	/* 非 admin 拒 */
	write_file(p, "admin:notcrypt:123\n");
	CHECK(tui_gate_read(p, rd, &ts) == -1);	/* 非 $6$ 拒 */

	/* ⑥ P-2a 多条目：注释/空行/重名首行/坏行/老式单行兼容 */
	{
		char h2[128], p2[256];
		int ff = -1;

		CHECK(tui_gate_hash("pw-multi-6", h2) == 0);
		{
			FILE *f = fopen(p, "w");

			assert(f);
			fputs("# comment\n\n", f);
			fprintf(f, "admin:%s:1000\n", hash);
			fprintf(f, "root:%s:1001:2\n", h2);
			fprintf(f, "bob:%s:1002\n", hash);
			fprintf(f, "admin:%s:1003\n", h2);	/* 重名——首行为准 */
			fputs("garbage-no-colon\n", f);
			fputs("five:$6$zz:1:2:3\n", f);		/* 5 段坏行 */
			fputs("neg:$6$zz:1:-1\n", f);		/* 负计数坏行 */
			fputs("badf:$6$zz:1:x\n", f);		/* 非数字坏行 */
			fputs("badh:not6:1:2\n", f);		/* 坏哈希坏行 */
			fclose(f);
		}
		CHECK(tui_gate_read(p, rd, &ts) == 0 &&
		      strcmp(rd, hash) == 0 && ts == 1000);	/* admin 首行 */
		CHECK(tui_gate_read_user(p, "root", rd, &ff) == 0 &&
		      strcmp(rd, h2) == 0 && ff == 2);
		CHECK(tui_gate_read_user(p, "bob", rd, &ff) == 0 && ff == 0);
		CHECK(tui_gate_read_user(p, "ghost", rd, &ff) == -1);	/* 无此用户 */
		CHECK(tui_gate_read_user(p, "", rd, &ff) == -1);	/* 空名 */
		CHECK(tui_gate_read_user(NULL, "root", rd, &ff) == -1);
		/* 老式单行（三段 admin）= admin 条目（向后兼容必须） */
		snprintf(p2, sizeof(p2), "%s/old-gate", dir);
		{
			FILE *f = fopen(p2, "w");

			assert(f);
			fprintf(f, "admin:%s:999\n", hash);
			fclose(f);
		}
		CHECK(tui_gate_read_user(p2, "admin", rd, &ff) == 0 &&
		      ff == 0);
		CHECK(tui_gate_read(p2, rd, &ts) == 0 && ts == 999);
		CHECK(tui_gate_read_user(p2, "root", rd, &ff) == -1);
		unlink(p2);

		/* ⑦ write_entry：更新/追加/保行/原子/逐用户计数 */
		CHECK(tui_gate_write_entry(p, "root", hash, 0) == 0);	/* 更新 */
		CHECK(tui_gate_read_user(p, "root", rd, &ff) == 0 &&
		      strcmp(rd, hash) == 0 && ff == 0);
		CHECK(tui_gate_read_user(p, "bob", rd, &ff) == 0 &&
		      ff == 0);			/* bob 行不动 */
		CHECK(tui_gate_write_entry(p, "carol", h2, 1) == 0);	/* 追加 */
		CHECK(tui_gate_read_user(p, "carol", rd, &ff) == 0 &&
		      strcmp(rd, h2) == 0 && ff == 1);
		CHECK(tui_gate_write_entry(p, "root", h2, 3) == 0);	/* 计数 */
		CHECK(tui_gate_read_user(p, "root", rd, &ff) == 0 && ff == 3);
		CHECK(tui_gate_read_user(p, "carol", rd, &ff) == 0 &&
		      ff == 1);			/* 逐用户独立 */
		{	/* 注释行保留 + admin 首行仍是首名条目（未扰乱） */
			FILE *lf = fopen(p, "r");
			int saw_comment = 0;

			CHECK(lf != NULL);
			if (lf) {
				char lb[512];

				while (fgets(lb, sizeof(lb), lf)) {
					if (strcmp(lb, "# comment\n") == 0)
						saw_comment = 1;
					if (strncmp(lb, "admin:", 6) == 0) {
						CHECK(strstr(lb, hash) != NULL);
						break;
					}
				}
				fclose(lf);
			}
			CHECK(saw_comment == 1);
		}
		{	/* 原子写无残留 */
			char tmpchk[300];

			snprintf(tmpchk, sizeof(tmpchk), "%s.tmp", p);
			CHECK(access(tmpchk, 0) != 0);
		}
		CHECK(stat(p, &st) == 0 &&
		      (st.st_mode & 0777) == expect_gate_mode());	/* D7 */
		/* 非法参数拒 */
		CHECK(tui_gate_write_entry(p, "a:b", hash, 0) == -1);
		CHECK(tui_gate_write_entry(p, "", hash, 0) == -1);
		CHECK(tui_gate_write_entry(p, "#lead", hash, 0) == -1);
		CHECK(tui_gate_write_entry(p, "has space", hash, 0) == -1);
		CHECK(tui_gate_write_entry(p, "ok", "plain", 0) == -1);
		CHECK(tui_gate_write_entry(p, "ok", hash, -1) == -1);

		/* ⑧ 老 write 委托 admin 语义（多条目文件只动 admin 行） */
		CHECK(tui_gate_write(p, hash) == 0);
		CHECK(tui_gate_read(p, rd, &ts) == 0 && strcmp(rd, hash) == 0);
		CHECK(tui_gate_read_user(p, "carol", rd, &ff) == 0 && ff == 1);
		CHECK(tui_gate_read_user(p, "root", rd, &ff) == 0 && ff == 3);
	}

	/* ⑨ P-60/D1（CON-02b）：凭据「读不了」≠「没有」 */
	{
		char dd[256], none[256], wo[256], rd2[128];
		int ff2 = -1;

		/* errno 分类纯函数：只有 ENOENT/ENOTDIR 才是「文件不在」 */
		CHECK(tui_gate_open_class(ENOENT) == TUI_GATE_OPEN_ABSENT);
		CHECK(tui_gate_open_class(ENOTDIR) == TUI_GATE_OPEN_ABSENT);
		CHECK(tui_gate_open_class(EACCES) == TUI_GATE_OPEN_DENIED);
		CHECK(tui_gate_open_class(EPERM) == TUI_GATE_OPEN_DENIED);
		CHECK(tui_gate_open_class(EISDIR) == TUI_GATE_OPEN_DENIED);
		CHECK(tui_gate_open_class(EIO) == TUI_GATE_OPEN_DENIED);
		CHECK(tui_gate_open_class(ELOOP) == TUI_GATE_OPEN_DENIED);
		/* 未知/0 一律不当作「不在」（保守：读不出就报读不出） */
		CHECK(tui_gate_open_class(0) == TUI_GATE_OPEN_DENIED);
		CHECK(tui_gate_open_class(-1) == TUI_GATE_OPEN_DENIED);

		/* ⑨a 文件不在（真 ENOENT）=-1（老语义：UI→SETUP 向导不变） */
		snprintf(none, sizeof(none), "%s/none-gate", dir);
		CHECK(tui_gate_read(none, rd2, &ts) == -1);
		CHECK(tui_gate_read_user(none, "admin", rd2, &ff2) == -1);

		/* ⑨b 路径是目录：fopen 成功、读取出错（EISDIR）——与 uid 无关
		 * （root/非 root 同路）。旧口径落 NO_USER→向导入口当首次使用 */
		snprintf(dd, sizeof(dd), "%s/gatedir", dir);
		CHECK(mkdir(dd, 0700) == 0);
		CHECK(tui_gate_read(dd, rd2, &ts) == TUI_GATE_READ_DENIED);
		CHECK(tui_gate_read_user(dd, "admin", rd2, &ff2) ==
		      TUI_GATE_READ_DENIED);
		/* 向导建密对「目录」写不成（rename 覆盖目录失败）、不留 tmp */
		CHECK(tui_gate_write(dd, hash) == -1);
		{
			char tmpchk[300];

			snprintf(tmpchk, sizeof(tmpchk), "%s.tmp", dd);
			CHECK(access(tmpchk, 0) != 0);
		}
		CHECK(stat(dd, &st) == 0 && S_ISDIR(st.st_mode));
		rmdir(dd);

		/* ⑨c 文件在却读不出（权限）→ DENIED；写侧拒写、原文件不动。
		 * 「属主他人 0600」需 root 造文件——非 root 用等价形态：自家
		 * 只写文件（0200：owner 无 r 位，非 root 无 CAP_DAC_OVERRIDE
		 * → open EACCES）且目录可写：正是旧口径「 fopen 失败=不在→
		 * 新建覆写」会丢数据的那条路。root 能读任何文件，本形态不
		 * 成立→显式 SKIP（root-only 原型见 test_gate_pty F1）。 */
		snprintf(wo, sizeof(wo), "%s/wronly-gate", dir);
		write_file(wo, WO_LINE);
		if (chmod(wo, 0200) == 0 && geteuid() != 0) {
			char got[200];
			FILE *lf;
			size_t n;

			CHECK(tui_gate_read(wo, rd2, &ts) ==
			      TUI_GATE_READ_DENIED);
			CHECK(tui_gate_read_user(wo, "admin", rd2, &ff2) ==
			      TUI_GATE_READ_DENIED);
			/* 写侧：读不出既有文件→拒写（旧口径会新建覆写） */
			CHECK(tui_gate_write_entry(wo, "carol", hash, 0) == -1);
			CHECK(tui_gate_write(wo, hash) == -1);
			{
				char tmpchk[300];

				snprintf(tmpchk, sizeof(tmpchk), "%s.tmp", wo);
				CHECK(access(tmpchk, 0) != 0);	/* 无残留 */
			}
			/* 原文件逐字未动 */
			CHECK(chmod(wo, 0600) == 0);
			lf = fopen(wo, "r");
			CHECK(lf != NULL);
			if (lf) {
				n = fread(got, 1, sizeof(got) - 1, lf);
				fclose(lf);
				got[n] = '\0';
				CHECK(strcmp(got, WO_LINE) == 0);
			}
		} else {
			printf("SKIP test_gate 9c (root-only premise: root "
			       "reads any file)\n");
		}
		unlink(wo);
	}

	/* ⑩ P-60/D7：写出的 gate 文件权限契约（期望值独立得出，见上） */
	{
		char q[256], tmpchk[300];
		struct stat sq;
		mode_t want = expect_gate_mode();
		mode_t pm = 0;
		gid_t pg = 0;
		gid_t gg = 0;
		int wide = test_wide(&gg);

		/* 纯判定（与运行 uid 无关，非 root 也可测） */
		CHECK(tui_gate_file_policy(0, 1, 942, &pm, &pg) == 1 &&
		      pm == 0640 && pg == 942);		/* root+有组 */
		CHECK(tui_gate_file_policy(0, 0, 942, &pm, &pg) == 0 &&
		      pm == 0600 && pg == (gid_t)-1);	/* root+无组 */
		CHECK(tui_gate_file_policy(1000, 1, 942, &pm, &pg) == 0 &&
		      pm == 0600 && pg == (gid_t)-1);	/* 非 root */
		CHECK(tui_gate_file_policy(0, 1, 7, &pm, &pg) == 1 &&
		      pg == 7);				/* gid 原样带出 */
		CHECK(tui_gate_file_policy(0, 1, 942, NULL, NULL) == 1);
		/* 新建路径（首启 SETUP 向导所经的 tui_gate_write） */
		snprintf(q, sizeof(q), "%s/d7-gate", dir);
		CHECK(tui_gate_write(q, hash) == 0);
		CHECK(stat(q, &sq) == 0 && (sq.st_mode & 0777) == want);
		if (wide)
			CHECK(sq.st_uid == 0 && sq.st_gid == gg);	/* root:aik-gate */
		else
			CHECK(sq.st_uid == geteuid());		/* 属主未被改 */
		/* 更新路径（登录计数/清零所经的 tui_gate_write_entry）契约保持 */
		CHECK(tui_gate_write_entry(q, "admin", hash, 1) == 0);
		CHECK(stat(q, &sq) == 0 && (sq.st_mode & 0777) == want);
		if (wide)
			CHECK(sq.st_uid == 0 && sq.st_gid == gg);
		/* 多条目文件（④~⑧ 写过多次的 p）同样符合契约 */
		CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == want);
		if (wide)
			CHECK(st.st_uid == 0 && st.st_gid == gg);
		/* 原子写无残留；内容回读无误（归一不伤内容） */
		snprintf(tmpchk, sizeof(tmpchk), "%s.tmp", q);
		CHECK(access(tmpchk, 0) != 0);
		CHECK(tui_gate_read(q, rd, &ts) == 0 && strcmp(rd, hash) == 0);
		unlink(q);
	}
	unlink(p);
	unlink(cmdline);
	rmdir(dir);
	if (fails) {
		printf("test_gate: %d FAIL\n", fails);
		return 1;
	}
	printf("test_gate: all ok\n");
	return 0;
}
