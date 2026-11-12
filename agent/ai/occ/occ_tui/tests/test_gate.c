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
