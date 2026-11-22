/* SPDX-License-Identifier: GPL-2.0 */
/* test_gate.c - T4 登录门纯逻辑面单测（凭据文件/哈希/旁路判定） */
#include <assert.h>
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
	CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600);
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
		CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600);
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
