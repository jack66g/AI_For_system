/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_tools.c - occ_tools 六件套单测（T9b1）
 *
 * 覆盖（任务书 5）：
 *   edit 边界 12 例（唯一/多处/replaceAll/未命中/空串/超长/二进制拒绝/
 *     同文件多 edit/replaceAll 未命中/越界目标/缺参数/等价替换）
 *   read 行窗（offset/limit/空/二进制/目录）
 *   glob 递归 + 隐藏文件；grep 中文 + glob 过滤 + 行号
 *   bash 沙箱契约：stub aik-sandbox（参数透传/退出码透传/超时组杀/
 *     旧版无 --rw-path=拒/二进制缺失=拒/沙箱 create 失败=拒——红线：
 *     一律拒绝文本，绝不裸跑）
 *   快照 stage/恢复（存在/ABSENT 墓碑/内容还原）
 *   trace JSONL 行形态；occ_tool_record 单事务落库 + pending 判定
 *
 * mock/ stub 仅本单测（生产路径走 /usr/local/bin/aik-sandbox 真件）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

#include "occ_core/occ_session.h"
#include "occ_tools/occ_tools.h"
#include "occ_utf8.h"		/* E10②：UTF-8 校验/净化共用件单测 */

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("ok %s\n", name); } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static char tmpdir[256];

static void wfile_n(const char *rel, const void *content, size_t n)
{
	char p[512];
	FILE *f;

	snprintf(p, sizeof(p), "%s/%s", tmpdir, rel);
	f = fopen(p, "wb");
	if (f) {
		if (n)
			fwrite(content, 1, n, f);
		fclose(f);
	}
}

static void wfile(const char *rel, const char *content)
{
	wfile_n(rel, content, strlen(content));
}

static char *rfile(const char *rel)
{
	char p[512];
	FILE *f;
	long sz;
	char *b;

	snprintf(p, sizeof(p), "%s/%s", tmpdir, rel);
	f = fopen(p, "rb");
	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	rewind(f);
	b = malloc((size_t)sz + 1);
	if (!b) {
		fclose(f);
		return NULL;
	}
	if (fread(b, 1, (size_t)sz, f) != (size_t)sz) {
		/* 空文件 */
	}
	fclose(f);
	b[sz] = '\0';
	return b;
}

/* ---- 工具执行便捷封装 ---- */

static occ_tool_result g_res;

static const char *exec_tool(const char *name, const char *args)
{
	occ_tool_ctx tc;

	memset(&tc, 0, sizeof(tc));
	tc.workdir = tmpdir;
	tc.snaproot = NULL;
	tc.trace_dir = NULL;
	tc.timeout_ms = 8000;		/* 单测快速收口 */
	occ_tool_result_free(&g_res);
	if (occ_tool_exec(&tc, name, "call_test", args, &g_res) < 0)
		return NULL;
	return g_res.text;
}

static int exec_rc(void)
{
	return g_res.rc;
}

/* ---- 沙箱 stub ---- */

static void write_stub_ok(const char *path)
{
	char body[2048];
	FILE *f;

	/*
	 * 契约 stub：usage 含 --rw-path（探测过）；create/destroy=0；
	 * run：定位 -- 后 exec（透传退出码/输出）；RUN_SLEEP 环境变量
	 * 控制 run 阶段睡眠（超时组杀用例）。
	 */
	f = fopen(path, "wb");
	if (!f) {
		perror("stub");
		exit(2);
	}
	snprintf(body, sizeof(body),
 "#!/bin/bash\n"
 "# occ test stub for aik-sandbox (test only)\n"
 "if [ \"$1\" = \"--occ-probe\" ] || [ $# -eq 0 ]; then\n"
 "  echo 'usage: stub create|run|destroy [--rw-path P] -- cmd'\n"
 "  exit 1\n"
 "fi\n"
 "case \"$1\" in\n"
 "  create|destroy) exit 0 ;;\n"
 "  run)\n"
 "    shift\n"
 "    zone=$1; shift\n"
 "    rw=\"\"\n"
 "    while [ $# -gt 0 ]; do\n"
 "      case \"$1\" in\n"
 "        --rw-path) rw=$2; shift 2 ;;\n"
 "        --) shift; break ;;\n"
 "        *) shift ;;\n"
 "      esac\n"
 "    done\n"
 "    echo \"stub-zone=$zone rw=$rw\"\n"
 "    if [ -n \"$OCC_STUB_SLEEP\" ]; then sleep \"$OCC_STUB_SLEEP\"; fi\n"
 "    exec \"$@\"\n"
 "    ;;\n"
 "  *) exit 1 ;;\n"
 "esac\n");
	fputs(body, f);
	fclose(f);
	chmod(path, 0755);
}

static void write_stub_old(const char *path)
{
	FILE *f = fopen(path, "wb");

	if (!f) {
		perror("stub-old");
		exit(2);
	}
	fputs("#!/bin/bash\n"
	      "# 旧版 stub：usage 无 --rw-path（探测应拒）\n"
	      "echo 'usage: old-stub create|run|destroy <name> -- cmd'\n"
	      "exit 1\n", f);
	fclose(f);
	chmod(path, 0755);
}

static void write_stub_fail_create(const char *path)
{
	FILE *f = fopen(path, "wb");

	if (!f) {
		perror("stub-fc");
		exit(2);
	}
	fputs("#!/bin/bash\n"
	      "# create 失败 stub：沙箱组装失败=拒（红线）\n"
	      "if [ \"$1\" = create ]; then\n"
	      "  echo 'stub: cgroup root 不可写' >&2\n"
	      "  exit 2\n"
	      "fi\n"
	      "echo 'usage: stub create|run|destroy --rw-path P -- cmd'\n"
	      "exit 1\n", f);
	fclose(f);
	chmod(path, 0755);
}

/* ---- DB helper（occ_tool_record/pending 用例） ---- */

static char *dbpath(void)
{
	static char path[300];

	snprintf(path, sizeof(path), "%s/sessions.db", tmpdir);
	return path;
}

static int db_count(const char *sql, const char *bind)
{
	sqlite3 *h;
	sqlite3_stmt *st;
	int n = -1;

	if (sqlite3_open_v2(dbpath(), &h, SQLITE_OPEN_READONLY, NULL) !=
	    SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		if (bind)
			sqlite3_bind_text(st, 1, bind, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(st) == SQLITE_ROW)
			n = sqlite3_column_int(st, 0);
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return n;
}

int main(void)
{
	char err[512] = "";
	char p[512];
	char *s;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_tools_t_%d", (int)getpid());
	mkdir(tmpdir, 0755);
	setenv("OCC_SNAPROOT", tmpdir, 0);	/* 不污染 HOME（可覆盖） */

	/* ======== 通用小件 ======== */
	OK(occ_path_is_under("/a/b/c", "/a/b"), "path-under-yes");
	OK(!occ_path_is_under("/a/bc", "/a/b"), "path-under-no");
	OK(occ_path_is_under("/a/b", "/a/b"), "path-under-eq");
	{
		char dst[32];

		/* 中文 3 字节/字：max=7 应回退到 2 字节边界（…等宽类推） */
		OK(occ_utf8_trunc("abc", 3, 7, dst, sizeof(dst)) == 3 &&
		   !strcmp(dst, "abc"), "utf8-ascii-keep");
		OK(occ_utf8_trunc("你好世界", 12, 7, dst, sizeof(dst)) == 6,
		   "utf8-cut-boundary");
	}
	{
		/* E10② 净化单测：坏字节串 → U+FFFD（最大子部口径）；
		 * 好 UTF-8（ASCII/中文/4 字节 emoji）逐字节零变化；
		 * valid 预检口径一致 */
		static const char bad[] = { 'a', (char)0xFF, 'b',
					    (char)0xC3, (char)0x28, 'c' };
		static const char trunc4[] = { (char)0xF0, (char)0x9F,
					       (char)0x98 };	/* 截断 4B */
		char out[64];
		size_t n;

		OK(occ_utf8_valid("abc你好\xF0\x9F\x98\x80", 3 + 6 + 4) == 1,
		   "utf8san-valid-good");
		OK(occ_utf8_valid(bad, sizeof(bad)) == 0,
		   "utf8san-valid-bad");
		n = occ_utf8_sanitize(bad, sizeof(bad), out, sizeof(out));
		/* a + FFFD(0xFF) + b + FFFD(0xC3 续位中断，0x28 独立
		 * 判读为合法 '(' 透传) + c */
		OK(n == 1 + 3 + 1 + 3 + 1 + 1 &&
		   !memcmp(out, "a\xEF\xBF\xBD""b\xEF\xBF\xBD(c", n),
		   "utf8san-bad-to-fffd");
		n = occ_utf8_sanitize("ok 你好 \xF0\x9F\x98\x80",
				      2 + 1 + 6 + 1 + 4, out, sizeof(out));
		OK(n == 2 + 1 + 6 + 1 + 4 &&
		   !memcmp(out, "ok 你好 \xF0\x9F\x98\x80", n),
		   "utf8san-good-unchanged");
		n = occ_utf8_sanitize(trunc4, sizeof(trunc4), out,
				      sizeof(out));
		OK(n == 3 && !memcmp(out, "\xEF\xBF\xBD", 3),
		   "utf8san-truncated-seq");
		n = occ_utf8_sanitize("a\xE4\xBD""x", 4, out, sizeof(out));
		/* 3B 序列续位中断于 'x'：最大子部 E4 BD → 一枚 FFFD，
		 * 'x' 透传 */
		OK(n == 1 + 3 + 1, "utf8san-partial-seq");
	}
	{
		char cwd[256];

		snprintf(cwd, sizeof(cwd), "%s", tmpdir);
		/* O-6 刀B：$HOME 子树放行三例（HOME=/root 桩——不缓存，
		 * 故可按例改桩；~/.occ 首步恒拒不豁免） */
		setenv("HOME", "/root", 1);
		OK(occ_write_target_ok("/root/f.txt", cwd),
		   "guard-home-ok");
		OK(occ_write_target_ok("/root/.occ/x", cwd) == 0,
		   "guard-home-occ-no");
		setenv("HOME", "", 1);		/* 空 HOME=安全跳过 */
		OK(occ_write_target_ok("/root/f.txt", cwd) == 0,
		   "guard-home-empty-no");
		unsetenv("HOME");			/* 还原，后续用例不依赖 */
		OK(occ_write_target_ok("/tmp/x", cwd), "guard-tmp-ok");
		OK(occ_write_target_ok("/etc/passwd", cwd) == 0,
		   "guard-etc-no");
		/* O-6 刀A：aik-sandbox bind 拒绝面判定（workdir 回退依据；
		 * 表与 agent/ai/sandbox/aik-sandbox.c valid_bind_src 同源） */
		OK(occ_sandbox_cwd_denied("/root"), "sbdeny-root");
		OK(occ_sandbox_cwd_denied("/root/sub"), "sbdeny-root-sub");
		OK(occ_sandbox_cwd_denied("/etc"), "sbdeny-etc");
		OK(occ_sandbox_cwd_denied("/tmp") == 0, "sbdeny-tmp-ok");
		OK(occ_sandbox_cwd_denied("/var/ai/work") == 0,
		   "sbdeny-varaiwork-ok");
		OK(occ_sandbox_cwd_denied("/var/ai/sandbox-artifacts/x"),
		   "sbdeny-artifacts");
		OK(occ_sandbox_cwd_denied(NULL) == 0 &&
		   occ_sandbox_cwd_denied("rel") == 0 &&
		   occ_sandbox_cwd_denied("/") == 0,
		   "sbdeny-bad-input");
	}

	/* ======== 工具定义（9 件=六件套+O-17 文件管理三件、名字/schema 非空） ======== */
	{
		size_t n = 0;
		const occ_tool_def *d = occ_tool_defs(&n);
		int schema_ok = 1;

		OK(n == 9, "defs-nine");
		OK(!strcmp(d[0].name, "read") &&
		   !strcmp(d[1].name, "write") &&
		   !strcmp(d[2].name, "edit") &&
		   !strcmp(d[3].name, "glob") &&
		   !strcmp(d[4].name, "grep") &&
		   !strcmp(d[5].name, "bash") &&
		   !strcmp(d[6].name, "rm") &&
		   !strcmp(d[7].name, "mv") &&
		   !strcmp(d[8].name, "mkdir"), "defs-names");
		for (size_t i = 0; i < n; i++)
			if (!d[i].parameters ||
			    !strstr(d[i].parameters, "required") ||
			    !d[i].description)
				schema_ok = 0;
		OK(schema_ok, "defs-schema");
		/* O-17 前 rm 未知面曾是否定断言——三件入正典后翻正 */
		OK(occ_tool_is_known("edit") && occ_tool_is_known("rm") &&
		   occ_tool_is_known("mv") && occ_tool_is_known("mkdir"),
		   "defs-known");
	}

	/* ======== read：行窗 ======== */
	wfile("rd.txt", "L1\nL2\nL3\nL4\nL5\n");
	s = (char *)exec_tool("read",
	      "{\"path\":\"rd.txt\",\"offset\":2,\"limit\":2}");
	OK(exec_rc() == 0 && s && strstr(s, "L2") && strstr(s, "L3") &&
	   !strstr(s, "L1\n") && !strstr(s, "L4"), "read-window-2-2");
	s = (char *)exec_tool("read", "{\"path\":\"rd.txt\"}");
	OK(exec_rc() == 0 && s && strstr(s, "L1") && strstr(s, "L5"),
	   "read-all-default");
	s = (char *)exec_tool("read", "{\"path\":\"rd.txt\",\"offset\":99}");
	OK(exec_rc() == 0 && s && strstr(s, "超出范围"), "read-offset-past");
	wfile("empty.txt", "");
	s = (char *)exec_tool("read", "{\"path\":\"empty.txt\"}");
	OK(exec_rc() == 0 && s && strstr(s, "空文件"), "read-empty");
	wfile_n("bin.dat", "a\0b", 4);
	s = (char *)exec_tool("read", "{\"path\":\"bin.dat\"}");
	OK(exec_rc() != 0 && s && strstr(s, "二进制"), "read-binary-reject");
	s = (char *)exec_tool("read", "{\"path\":\"no_such_file.txt\"}");
	OK(exec_rc() != 0 && s && strstr(s, "ERROR"), "read-missing");
	s = (char *)exec_tool("read", "{}");
	OK(exec_rc() != 0 && s && strstr(s, "缺少参数"), "read-noargs");

	/* ======== edit：12 边界 ======== */
	wfile("ed.txt", "alpha beta gamma\n");
	/* 1 唯一命中 */
	s = (char *)exec_tool("edit",
	      "{\"path\":\"ed.txt\",\"oldString\":\"beta\","
	      "\"newString\":\"BETA\"}");
	OK(exec_rc() == 0, "edit1-unique-rc");
	s = rfile("ed.txt");
	OK(s && !strcmp(s, "alpha BETA gamma\n"), "edit1-unique-content");
	free(s);
	/* 2 多处不带 all → 错 */
	wfile("ed.txt", "x ay x ay x\n");
	s = (char *)exec_tool("edit",
	      "{\"path\":\"ed.txt\",\"oldString\":\"ay\","
	      "\"newString\":\"z\"}");
	OK(exec_rc() != 0 && s && strstr(s, "2 处"), "edit2-multi-no-all");
	/* 3 多处带 all */
	s = (char *)exec_tool("edit",
	      "{\"path\":\"ed.txt\",\"oldString\":\"ay\","
	      "\"newString\":\"z\",\"replaceAll\":true}");
	OK(exec_rc() == 0, "edit3-replaceall-rc");
	s = rfile("ed.txt");
	OK(s && !strcmp(s, "x z x z x\n"), "edit3-replaceall-content");
	free(s);
	/* 4 未命中 → 错 */
	s = (char *)exec_tool("edit",
	      "{\"path\":\"ed.txt\",\"oldString\":\"NOTHERE\","
	      "\"newString\":\"y\"}");
	OK(exec_rc() != 0 && s && strstr(s, "未找到"), "edit4-not-found");
	/* 5 空串 oldString → 错 */
	s = (char *)exec_tool("edit",
	      "{\"path\":\"ed.txt\",\"oldString\":\"\","
	      "\"newString\":\"y\"}");
	OK(exec_rc() != 0 && s && strstr(s, "空串"), "edit5-empty-old");
	/* 6 超长 oldString（> 文件）→ 未命中错 */
	{
		char bigold[4097];
		char args[8192];

		memset(bigold, 'A', sizeof(bigold) - 1);
		bigold[sizeof(bigold) - 1] = '\0';
		snprintf(args, sizeof(args),
			 "{\"path\":\"ed.txt\",\"oldString\":\"%s\","
			 "\"newString\":\"y\"}", bigold);
		s = (char *)exec_tool("edit", args);
		OK(exec_rc() != 0 && s && strstr(s, "未找到"),
		   "edit6-toolong-old");
	}
	/* 7 二进制拒绝 */
	wfile_n("ed.bin", "a\0b\0c", 6);
	s = (char *)exec_tool("edit",
	      "{\"path\":\"ed.bin\",\"oldString\":\"a\","
	      "\"newString\":\"b\"}");
	OK(exec_rc() != 0 && s && strstr(s, "二进制"), "edit7-binary-reject");
	/* 8 同文件多 edit（两次连续，各自唯一命中） */
	wfile("multi.txt", "one two three\n");
	s = (char *)exec_tool("edit",
	      "{\"path\":\"multi.txt\",\"oldString\":\"one\","
	      "\"newString\":\"1\"}");
	OK(exec_rc() == 0, "edit8a-first");
	s = (char *)exec_tool("edit",
	      "{\"path\":\"multi.txt\",\"oldString\":\"three\","
	      "\"newString\":\"3\"}");
	OK(exec_rc() == 0, "edit8b-second");
	s = rfile("multi.txt");
	OK(s && !strcmp(s, "1 two 3\n"), "edit8-multi-content");
	free(s);
	/* 9 replaceAll 未命中 → 错 */
	s = (char *)exec_tool("edit",
	      "{\"path\":\"multi.txt\",\"oldString\":\"zzz\","
	      "\"newString\":\"y\",\"replaceAll\":true}");
	OK(exec_rc() != 0 && strstr(s, "未找到"), "edit9-all-not-found");
	/* 10 越界目标（/etc）→ 守卫拒 */
	s = (char *)exec_tool("edit",
	      "{\"path\":\"/etc/hosts\",\"oldString\":\"a\","
	      "\"newString\":\"b\"}");
	OK(exec_rc() != 0 && s && strstr(s, "越界"), "edit10-out-of-guard");
	/* 11 缺参数 */
	s = (char *)exec_tool("edit", "{\"path\":\"multi.txt\"}");
	OK(exec_rc() != 0 && s && strstr(s, "缺少参数"), "edit11-noargs");
	/* 12 中文替换（UTF-8 多字节精确替换） */
	wfile("cn.txt", "你好，世界\n");
	s = (char *)exec_tool("edit",
	      "{\"path\":\"cn.txt\",\"oldString\":\"世界\","
	      "\"newString\":\"AIKernel\"}");
	OK(exec_rc() == 0, "edit12-cn-rc");
	s = rfile("cn.txt");
	OK(s && !strcmp(s, "你好，AIKernel\n"), "edit12-cn-content");
	free(s);

	/* ======== write：整文件 + 父目录建 ======== */
	s = (char *)exec_tool("write",
	      "{\"path\":\"sub/dir/new.txt\",\"content\":\"created\"}");
	OK(exec_rc() == 0, "write-parents-rc");
	s = rfile("sub/dir/new.txt");
	OK(s && !strcmp(s, "created"), "write-parents-content");
	free(s);
	s = (char *)exec_tool("write",
	      "{\"path\":\"/etc/no occ write\",\"content\":\"x\"}");
	OK(exec_rc() != 0 && s && strstr(s, "越界"), "write-guard");
	s = (char *)exec_tool("write", "{\"path\":\"x.txt\"}");
	OK(exec_rc() != 0 && strstr(s, "缺少参数"), "write-noargs");
	/* 覆写已有（快照见下节断言） */
	s = (char *)exec_tool("write",
	      "{\"path\":\"sub/dir/new.txt\",\"content\":\"v2\"}");
	OK(exec_rc() == 0, "write-overwrite");
	s = rfile("sub/dir/new.txt");
	OK(s && !strcmp(s, "v2"), "write-overwrite-content");
	free(s);

	/* ======== 快照 stage/恢复 ======== */
	{
		char snapbuf[512];
		struct stat st;

		wfile("snap.txt", "ORIGINAL");
		snprintf(p, sizeof(p), "%s/snap.txt", tmpdir);
		OK(occ_snapshot_stage(NULL, tmpdir, "ses_snap", "msg_snap", p,
				      snapbuf, sizeof(snapbuf)) == 0,
		   "snap-stage-rc");
		OK(!access(snapbuf, R_OK), "snap-stage-file");
		wfile("snap.txt", "MODIFIED");
		s = rfile("snap.txt");
		OK(s && !strcmp(s, "MODIFIED"), "snap-modified-applied");
		free(s);
		/* 恢复=拷回快照 */
		{
			char cmd[1100];

			snprintf(cmd, sizeof(cmd), "cp '%s' '%s'",
				 snapbuf, p);
			OK(system(cmd) == 0, "snap-restore-cp");
		}
		s = rfile("snap.txt");
		OK(s && !strcmp(s, "ORIGINAL"), "snap-restore-content");
		free(s);
		/* 新文件墓碑 */
		snprintf(p, sizeof(p), "%s/absent.txt", tmpdir);
		unlink(p);
		OK(occ_snapshot_stage(NULL, tmpdir, "ses_snap", "msg_snap2", p,
				      snapbuf, sizeof(snapbuf)) == 0,
		   "snap-absent-rc");
		strcat(snapbuf, ".ABSENT");
		OK(!stat(snapbuf, &st), "snap-absent-marker");
	}

	/* ======== glob：递归/隐藏 ======== */
	{
		char sub2[512];
		char cmd[600];

		snprintf(sub2, sizeof(sub2), "%s/a/b", tmpdir);
		/* mkdir -p 语义（a 与 a/b 一次建） */
		snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", sub2);
		if (system(cmd)) {
			/* 失败不影响后续断言语义 */
		}
		wfile("a/top.c", "int a;");
		wfile("a/b/deep.c", "int b;");
		wfile("a/b/notes.txt", "n");
		wfile("a/.hidden.c", "int h;");
		s = (char *)exec_tool("glob", "{\"pattern\":\"**/*.c\"}");
		OK(exec_rc() == 0, "glob-rc");
		OK(s && strstr(s, "deep.c") && strstr(s, "top.c"),
		   "glob-recursive");
		OK(s && !strstr(s, "notes.txt"), "glob-txt-excluded");
		OK(s && !strstr(s, ".hidden.c"), "glob-hidden-excluded");
		s = (char *)exec_tool("glob", "{\"pattern\":\"**/.*.c\"}");
		OK(s && strstr(s, ".hidden.c"), "glob-hidden-explicit");
		/* LT-BUG-002：绝对模式 + 字面前缀锚定（修前绝对前导被当
		 * 相对组件在工作目录下永无匹配） */
		s = (char *)exec_tool("glob",
					      "{\"pattern\":\"/etc/host*\"}");
		OK(exec_rc() == 0, "glob-abs-rc");
		OK(s && strstr(s, "/etc/hostname"), "glob-abs-hit");
		/* LT-BUG-003：procfs 零尺寸虚拟文件流式读（修前报空文件；
		 * read/edit/grep/bash 出读共用路径） */
		s = (char *)exec_tool("read", "{\"path\":\"/proc/version\"}");
		OK(exec_rc() == 0, "read-proc-rc");
		OK(s && strstr(s, "Linux version"), "read-proc-content");
		s = (char *)exec_tool("grep", "{\"pattern\":\"Linux\",\"path\":\"/proc/version\"}");
		OK(exec_rc() == 0, "grep-proc-rc");
		OK(s && strstr(s, "Linux version"), "grep-proc-hit");
		s = (char *)exec_tool("glob", "{\"pattern\":\"a/*.c\"}");
		OK(s && strstr(s, "top.c") && !strstr(s, "deep.c"),
		   "glob-star-no-cross");
	}

	/* ======== grep：中文/行号/glob 过滤 ======== */
	wfile("g1.txt", "第一行 hello\n第二行 world\n第三行 hello again\n");
	wfile("g2.txt", "nothing here\n");
	s = (char *)exec_tool("grep", "{\"pattern\":\"第二行\"}");
	OK(exec_rc() == 0 && s && strstr(s, "g1.txt:2:") &&
	   strstr(s, "world"), "grep-cn-lineno");
	s = (char *)exec_tool("grep", "{\"pattern\":\"hello\"}");
	OK(exec_rc() == 0 && s && strstr(s, ":1:") && strstr(s, ":3:"),
	   "grep-multi-lines");
	s = (char *)exec_tool("grep",
			      "{\"pattern\":\"hello\",\"glob\":\"g2.txt\"}");
	OK(exec_rc() == 0 && s && strstr(s, "未匹配"), "grep-glob-filter");
	s = (char *)exec_tool("grep", "{}");
	OK(exec_rc() != 0 && strstr(s, "缺少参数"), "grep-noargs");

	/* ======== bash：沙箱契约 ======== */
	{
		char stub[512], stub_old[512], stub_fc[512];

		snprintf(stub, sizeof(stub), "%s/stub-sb.sh", tmpdir);
		snprintf(stub_old, sizeof(stub_old), "%s/stub-old.sh", tmpdir);
		snprintf(stub_fc, sizeof(stub_fc), "%s/stub-fc.sh", tmpdir);
		write_stub_ok(stub);
		write_stub_old(stub_old);
		write_stub_fail_create(stub_fc);
		setenv("OCC_SANDBOX_BIN", stub, 1);
		occ_sandbox_probe_cache_reset();

		/* B1 正常执行：rw 挂载面 + 退出码透传 */
		s = (char *)exec_tool("bash",
		      "{\"command\":\"echo out-ok; exit 7\"}");
		OK(exec_rc() == 0 && s && strstr(s, "out-ok") &&
		   strstr(s, "[exit=7]") && strstr(s, "stub-zone=occ"),
		   "bash1-exec-exit-passthrough");
		OK(s && strstr(s, tmpdir), "bash1-rwpath-workdir");

		/* B2 超时：SIGKILL 全组 + 人话 */
		{
			occ_tool_ctx tc;

			memset(&tc, 0, sizeof(tc));
			tc.workdir = tmpdir;
			tc.timeout_ms = 1500;
			setenv("OCC_STUB_SLEEP", "30", 1);
			occ_tool_result_free(&g_res);
			occ_tool_exec(&tc, "bash", "call_to",
				      "{\"command\":\"sleep 29\"}", &g_res);
			unsetenv("OCC_STUB_SLEEP");
			OK(g_res.rc != 0 && g_res.text &&
			   strstr(g_res.text, "超时"),
			   "bash2-timeout-kill");
		}

		/* B3 旧版沙箱（无 --rw-path）→ 拒（红线：不降级裸跑） */
		setenv("OCC_SANDBOX_BIN", stub_old, 1);
		occ_sandbox_probe_cache_reset();
		s = (char *)exec_tool("bash", "{\"command\":\"echo hi\"}");
		OK(exec_rc() != 0 && s && strstr(s, "拒绝执行") &&
		   strstr(s, "--rw-path"), "bash3-old-sandbox-refused");
		OK(s && !strstr(s, "[exit="), "bash3-no-bare-run");

		/* B4 二进制缺失 → 拒 */
		setenv("OCC_SANDBOX_BIN", "/nonexistent/aik-sandbox", 1);
		occ_sandbox_probe_cache_reset();
		s = (char *)exec_tool("bash", "{\"command\":\"echo hi\"}");
		OK(exec_rc() != 0 && s && strstr(s, "拒绝执行"),
		   "bash4-missing-bin-refused");

		/* B5 create 失败（沙箱组装失败）→ 拒 */
		setenv("OCC_SANDBOX_BIN", stub_fc, 1);
		occ_sandbox_probe_cache_reset();
		s = (char *)exec_tool("bash", "{\"command\":\"echo hi\"}");
		OK(exec_rc() != 0 && s && strstr(s, "create 失败") &&
		   strstr(s, "拒绝执行"), "bash5-create-fail-refused");

		/* B6 缺参数 */
		setenv("OCC_SANDBOX_BIN", stub, 1);
		occ_sandbox_probe_cache_reset();
		s = (char *)exec_tool("bash", "{}");
		OK(exec_rc() != 0 && strstr(s, "缺少参数"), "bash6-noargs");

		/* B7 未知工具（O-17 起 rm 是真工具——探针换 never_a_tool） */
		s = (char *)exec_tool("never_a_tool", "{\"path\":\"x\"}");
		OK(exec_rc() != 0 && strstr(s, "未知工具"), "bash7-unknown");

		/* B8 E10②a 源端净化：stub 透传 printf 坏字节（0xFF）→
		 * 工具结果在进缓冲前已替换 U+FFFD（无裸坏字节入库） */
		s = (char *)exec_tool("bash",
		      "{\"command\":\"printf 'a\\\\377b'\"}");
		OK(exec_rc() == 0 && s &&
		   strstr(s, "a\xEF\xBF\xBD""b") &&
		   !memchr(s, 0xFF, strlen(s)),
		   "bash8-utf8-sanitize-source");
	}

	/* ======== trace JSONL（带 session/trace_dir 的 ctx 直执） ======== */
	{
		char path[512];
		char line[1024];
		FILE *f;
		int nlines = 0, fields_ok = 0;
		occ_tool_ctx tc;

		memset(&tc, 0, sizeof(tc));
		tc.workdir = tmpdir;
		tc.session_id = "ses_snap";
		tc.trace_dir = tmpdir;		/* → <tmpdir>/ses_snap.jsonl */
		occ_tool_result_free(&g_res);
		occ_tool_exec(&tc, "read", "call_tr",
			      "{\"path\":\"rd.txt\"}", &g_res);
		snprintf(path, sizeof(path), "%s/ses_snap.jsonl", tmpdir);
		f = fopen(path, "r");
		OK(f != NULL, "trace-file-exists");
		if (f) {
			while (fgets(line, sizeof(line), f)) {
				nlines++;
				if (strstr(line, "\"event\":\"tool_exec\"") &&
				    strstr(line, "\"tool\":\"read\"") &&
				    strstr(line, "\"rc\":0") &&
				    strstr(line, "\"dur_ms\":") &&
				    strstr(line, "\"out_bytes\":") &&
				    strstr(line, "\"ts\":\"") &&
				    strstr(line, "\"session\":\"ses_snap\""))
					fields_ok++;
			}
			fclose(f);
		}
		OK(nlines >= 1 && fields_ok == nlines,
		   "trace-lines-wellformed");
	}

	/* ======== occ_tool_record + pending（durable 单事务） ======== */
	{
		occ_db *db = occ_db_open(dbpath(), err, sizeof(err));
		occ_session_row ses;
		occ_tool_call tc[1];
		char mid[OCC_ID_LEN], tcid[OCC_ID_LEN];
		occ_toolcall_part *pend = NULL;
		size_t npend = 0;

		OK(db != NULL, "durable-db-open");
		if (db) {
			OK(occ_session_create(db, "m", &ses, err,
					      sizeof(err)) == 0,
			   "durable-session");
			occ_msg_add_user(db, ses.id, "u", NULL, 0, err,
					 sizeof(err));
			tc[0].id = "call_x";
			tc[0].name = "read";
			tc[0].arguments = "{\"path\":\"x\"}";
			OK(occ_msg_add_assistant(db, ses.id, "", NULL, tc, 1,
						 NULL, 0, "tool-calls", mid,
						 sizeof(mid), err,
						 sizeof(err)) == 0,
			   "durable-assistant-interim");
			/* interim 直接落库后 status=active（a3 语义：
			 * add_assistant 无 interim 参数收口——此处仅造数，
			 * pending 判定与 status 无关） */
			OK(occ_msg_pending_calls(db, ses.id, &pend, &npend,
						 NULL, 0, err,
						 sizeof(err)) == 1 &&
			   npend == 1 && pend && pend[0].id &&
			   !strcmp(pend[0].id, "call_x"),
			   "durable-pending-1");
			for (size_t q = 0; q < npend; q++) {
				free(pend[q].id);
				free(pend[q].tool);
				free(pend[q].arguments);
			}
			free(pend);
			pend = NULL;
			OK(occ_tool_record(db, ses.id, mid, "read",
					   "{\"path\":\"x\"}", "内容", 0, 5,
					   "call_x", NULL, 0, tcid,
					   sizeof(tcid), err,
					   sizeof(err)) == 0,
			   "durable-record-rc");
			OK(db_count("SELECT COUNT(*) FROM occ_toolcall"
				    " WHERE tool='read' AND rc=0", NULL) == 1,
			   "durable-toolcall-row");
			OK(db_count("SELECT COUNT(*) FROM occ_message WHERE"
				    " session_id=?1 AND role='tool'",
				    ses.id) == 1, "durable-tool-msg");
			OK(occ_msg_pending_calls(db, ses.id, &pend, &npend,
						 NULL, 0, err,
						 sizeof(err)) == 0 &&
			   npend == 0, "durable-pending-0-after");
			/* tool 消息解析视图：tool_call_id + text=output */
			{
				sqlite3 *h;
				sqlite3_stmt *st;
				char q[512];
				char *cj = NULL, *tcview = NULL;

				snprintf(q, sizeof(q),
					 "SELECT content_json FROM"
					 " occ_message WHERE session_id='%s'"
					 " AND role='tool'", ses.id);
				if (sqlite3_open_v2(dbpath(), &h,
					SQLITE_OPEN_READONLY,
					NULL) == SQLITE_OK &&
				    sqlite3_prepare_v2(h, q, -1, &st,
						       NULL) == SQLITE_OK &&
				    sqlite3_step(st) == SQLITE_ROW) {
					const unsigned char *t =
						sqlite3_column_text(st, 0);

					cj = strdup((const char *)t);
					sqlite3_finalize(st);
					sqlite3_close(h);
				}
				(void)tcview;
				OK(cj && strstr(cj,
						"\"toolCallID\":\"call_x\"") &&
				   strstr(cj, "\"type\":\"toolResult\""),
				   "durable-toolresult-shape");
				free(cj);
			}
			occ_db_close(db);
		}
	}

	/* ======== 结果截断 8KB ======== */
	{
		char big[64 * 1024];

		memset(big, 'x', sizeof(big) - 1);
		big[sizeof(big) - 1] = '\0';
		wfile("big.txt", big);
		s = (char *)exec_tool("read",
				      "{\"path\":\"big.txt\",\"limit\":5000}");
		OK(g_res.out_bytes > OCC_TOOL_OUT_MAX, "trunc-total-counted");
		OK(g_res.text && strlen(g_res.text) <=
		   OCC_TOOL_OUT_MAX + 200 && strstr(g_res.text, "truncated"),
		   "trunc-8k-cap");
	}

	/* ======== E3：task 第七工具（开关/边界；全链演练在 test_orch） ======== */
	{
		size_t n = 0;
		const occ_tool_def *d;

		/* 默认关：未知+九件（O-17 起 base=9；task 面默认关不变） */
		OK(occ_tool_defs(&n) && n == 9 && !occ_tool_is_known("task"),
		   "task-default-off");
		s = (char *)exec_tool("task",
				      "{\"action\":\"status\",\"task_id\":\"tsk_x\"}");
		OK(exec_rc() != 0 && s && strstr(s, "未知工具"),
		   "task-default-unknown");
		/* 开关开：九件+task+recall=11（E6 起 task/recall 旗控尾部追加） */
		setenv("OCC_ORCH_TOOLS", "1", 1);
		d = occ_tool_defs(&n);
		OK(n == 11 && d && !strcmp(d[9].name, "task") &&
		   d[9].description && strstr(d[9].parameters, "spawn") &&
		   strstr(d[9].parameters, "fileset") &&
		   strstr(d[9].parameters, "rework_max"),
		   "task-on-eleven-defs");
		/* E10④⑧：schema 同步——spawn+task_id 再派面 + wait 上限
		 * 120000（缺省 2000 / minimum 100 不变） */
		OK(strstr(d[9].parameters, "120000") &&
		   strstr(d[9].parameters, "缺省 2000") &&
		   strstr(d[9].parameters, "再派"),
		   "task-schema-wait-respawn");
		OK(!strcmp(d[10].name, "recall") &&
		   strstr(d[10].parameters, "layer"), "recall-tenth-def");
		OK(occ_tool_is_known("task") && occ_tool_is_known("recall") &&
		   occ_tool_is_known("rm"), "task-on-known");
		/* 无 orch 运行时 → 结构化人话错误（JSON） */
		s = (char *)exec_tool("task",
				      "{\"action\":\"status\",\"task_id\":\"tsk_x\"}");
		OK(exec_rc() != 0 && s && strstr(s, "\"ok\":false") &&
		   strstr(s, "编排未启用"), "task-no-orch");
		/* 坏 JSON 参数 → 人话拒绝（不静默按缺失） */
		s = (char *)exec_tool("task", "{\"action\":");
		OK(exec_rc() != 0 && s && strstr(s, "JSON") &&
		   strstr(s, "参数"), "task-bad-json");
		/* 缺 action / 未知 action */
		s = (char *)exec_tool("task", "{}");
		OK(exec_rc() != 0 && s && strstr(s, "action"), "task-no-action");
		s = (char *)exec_tool("task", "{\"action\":\"fly\"}");
		OK(exec_rc() != 0 && s && strstr(s, "fly") &&
		   strstr(s, "未知 action"), "task-unknown-action");
		/* spawn 边界：缺 brief / brief 非 object / 缺 goal / 缺
		 * fileset / fileset 空数组 / rework_max 越界（R2 上限 1-3） */
		s = (char *)exec_tool("task", "{\"action\":\"spawn\"}");
		OK(exec_rc() != 0 && s && strstr(s, "brief"), "task-spawn-no-brief");
		s = (char *)exec_tool("task", "{\"action\":\"spawn\","
				      "\"brief\":\"不是对象\"}");
		OK(exec_rc() != 0 && s && strstr(s, "brief"), "task-spawn-brief-notobj");
		s = (char *)exec_tool("task",
				      "{\"action\":\"spawn\",\"brief\":{}}");
		OK(exec_rc() != 0 && s && strstr(s, "goal"), "task-spawn-no-goal");
		s = (char *)exec_tool("task",
				      "{\"action\":\"spawn\",\"brief\":"
				      "{\"goal\":\"做点事\"}}");
		OK(exec_rc() != 0 && s && strstr(s, "fileset"), "task-spawn-no-fileset");
		s = (char *)exec_tool("task",
				      "{\"action\":\"spawn\",\"brief\":"
				      "{\"goal\":\"做点事\",\"fileset\":[]}}");
		OK(exec_rc() != 0 && s && strstr(s, "空数组"),
		   "task-spawn-empty-fileset");
		s = (char *)exec_tool("task",
				      "{\"action\":\"spawn\",\"brief\":"
				      "{\"goal\":\"做点事\",\"fileset\":[\"a.c\"],"
				      "\"rework_max\":9}}");
		OK(exec_rc() != 0 && s && strstr(s, "rework_max") &&
		   strstr(s, "越界"), "task-spawn-rework-max-hi");
		s = (char *)exec_tool("task",
				      "{\"action\":\"spawn\",\"brief\":"
				      "{\"goal\":\"做点事\",\"fileset\":[\"a.c\"],"
				      "\"rework_max\":0}}");
		/* rework_max=0=缺省 2——过参数校验，走到环境检查
		 *（session 缺失——exec_tool 的 ctx 无 session_id） */
		OK(exec_rc() != 0 && s && strstr(s, "会话上下文"),
		   "task-spawn-rework-max-default2");
		/* 清单字段类型错误 → 人话 */
		s = (char *)exec_tool("task",
				      "{\"action\":\"spawn\",\"brief\":"
				      "{\"goal\":\"做点事\",\"fileset\":[\"a.c\"],"
				      "\"forbidden\":\"不是数组\"}}");
		OK(exec_rc() != 0 && s && strstr(s, "forbidden"),
		   "task-spawn-bad-list");
		/* status/read_result 缺 task_id */
		s = (char *)exec_tool("task", "{\"action\":\"status\"}");
		OK(exec_rc() != 0 && s && strstr(s, "task_id"),
		   "task-status-no-tid");
		s = (char *)exec_tool("task", "{\"action\":\"read_result\"}");
		OK(exec_rc() != 0 && s && strstr(s, "task_id"),
		   "task-readres-no-tid");
		/* return 缺 verdict */
		s = (char *)exec_tool("task",
				      "{\"action\":\"return\",\"task_id\":\"tsk_x\"}");
		OK(exec_rc() != 0 && s && strstr(s, "verdict"),
		   "task-return-no-verdict");
		/* 关回去：零变化 */
		unsetenv("OCC_ORCH_TOOLS");
		OK(occ_tool_defs(&n) && n == 9 && !occ_tool_is_known("task"),
		   "task-off-again");
	}

	/* ======== O-17：rm/mv/mkdir 端到端（宿主面；w2=NULL 嵌入面——
	 * 域外由 write_guard 硬拒；W2 分类/确认面见 test_w2gate） ======== */
	{
		struct stat st;
		char p[600], p2[600];
		char *t;

		snprintf(p, sizeof(p), "%s/o17.txt", tmpdir);
		/* write 建 → rm 删 → 无 */
		wfile("o17.txt", "dome");
		s = (char *)exec_tool("rm", "{\"path\":\"o17.txt\"}");
		OK(exec_rc() == 0 && s && strstr(s, "已删除"), "o17-rm-file");
		OK(stat(p, &st) != 0, "o17-rm-file-gone");
		/* rm 不存在 → 人话报错 */
		s = (char *)exec_tool("rm", "{\"path\":\"o17.txt\"}");
		OK(exec_rc() != 0 && s && strstr(s, "不存在"),
		   "o17-rm-missing");
		/* mkdir -p 递归 → 有；幂等 */
		s = (char *)exec_tool("mkdir",
				      "{\"path\":\"o17sub/deep/dir\"}");
		OK(exec_rc() == 0 && s && strstr(s, "已创建"), "o17-mkdir-p");
		snprintf(p, sizeof(p), "%s/o17sub/deep/dir", tmpdir);
		OK(stat(p, &st) == 0 && S_ISDIR(st.st_mode),
		   "o17-mkdir-exists");
		s = (char *)exec_tool("mkdir",
				      "{\"path\":\"o17sub/deep/dir\"}");
		OK(exec_rc() == 0, "o17-mkdir-idempotent");
		/* rm 空目录 → ok；非空目录 → 人话（v1 诚实限制） */
		s = (char *)exec_tool("rm", "{\"path\":\"o17sub/deep/dir\"}");
		OK(exec_rc() == 0 && s && strstr(s, "空目录"),
		   "o17-rm-empty-dir");
		s = (char *)exec_tool("rm", "{\"path\":\"o17sub\"}");
		OK(exec_rc() != 0 && s && strstr(s, "非空目录"),
		   "o17-rm-nonempty-dir");
		/* mv 改名 → 旧无新有；内容随迁；不覆盖已有目标 */
		wfile("o17old.txt", "moved");
		s = (char *)exec_tool("mv",
				      "{\"src\":\"o17old.txt\","
				      "\"dst\":\"o17new.txt\"}");
		OK(exec_rc() == 0 && s && strstr(s, "已移动"), "o17-mv-rename");
		snprintf(p, sizeof(p), "%s/o17old.txt", tmpdir);
		snprintf(p2, sizeof(p2), "%s/o17new.txt", tmpdir);
		OK(stat(p, &st) != 0, "o17-mv-old-gone");
		t = rfile("o17new.txt");
		OK(t && strcmp(t, "moved") == 0, "o17-mv-content");
		free(t);
		s = (char *)exec_tool("mv",
				      "{\"src\":\"o17new.txt\","
				      "\"dst\":\"o17new.txt\"}");
		OK(exec_rc() != 0 && s && strstr(s, "已存在"),
		   "o17-mv-no-overwrite");
		/* 域外（w2=NULL 嵌入面）：write_guard 硬拒（~/.occ 同拒） */
		s = (char *)exec_tool("rm", "{\"path\":\"/etc/hosts\"}");
		OK(exec_rc() != 0 && s && strstr(s, "越界"), "o17-rm-etc-no");
		s = (char *)exec_tool("mkdir", "{\"path\":\"/etc/o17x\"}");
		OK(exec_rc() != 0 && s && strstr(s, "越界"),
		   "o17-mkdir-etc-no");
		{
			const char *home = getenv("HOME");

			if (home && home[0]) {
				char args[600];

				snprintf(args, sizeof(args),
					 "{\"path\":\"%s/.occ/o17db\"}", home);
				s = (char *)exec_tool("rm", args);
				OK(exec_rc() != 0 && s && strstr(s, "越界"),
				   "o17-rm-homeocc-no");
			}
		}
	}

	/* ---- P-31：子任务 fileset 写面强制（env 注入面=orch spawn） ---- */
	{
		char p1[600], p2[600], p3[600], args[1300];

		snprintf(p1, sizeof(p1), "%s/p31_ok.txt", tmpdir);
		snprintf(p2, sizeof(p2), "%s/p31_out.txt", tmpdir);
		snprintf(p3, sizeof(p3), "%s/p31_dir_ok", tmpdir);
		/* env=多条 \n 分隔（文件 p1+目录 p3 声明）；p2 未声明 */
		{
			char fenv[1300];

			snprintf(fenv, sizeof(fenv), "%s\n%s", p1, p3);
			setenv("OCC_TASK_FILESET", fenv, 1);
		}
		snprintf(args, sizeof(args),
			 "{\"path\":\"%s\",\"content\":\"x\"}", p1);
		s = (char *)exec_tool("write", args);
		OK(exec_rc() == 0, "p31-write-declared-ok");
		snprintf(args, sizeof(args),
			 "{\"path\":\"%s/p31_sub.txt\",\"content\":\"x\"}",
			 p3);
		s = (char *)exec_tool("write", args);
		OK(exec_rc() == 0, "p31-write-declared-subtree-ok");
		snprintf(args, sizeof(args),
			 "{\"path\":\"%s\",\"content\":\"x\"}", p2);
		s = (char *)exec_tool("write", args);
		OK(exec_rc() != 0 && s && strstr(s, "fileset"),
		   "p31-write-undeclared-deny");
		snprintf(args, sizeof(args), "{\"path\":\"%s\"}", p2);
		s = (char *)exec_tool("mkdir", args);
		OK(exec_rc() != 0 && s && strstr(s, "fileset"),
		   "p31-mkdir-undeclared-deny");
		s = (char *)exec_tool("rm", args);
		OK(exec_rc() != 0 && s && strstr(s, "fileset"),
		   "p31-rm-undeclared-deny");
		snprintf(args, sizeof(args),
			 "{\"src\":\"%s\",\"dst\":\"%s\"}", p1, p2);
		s = (char *)exec_tool("mv", args);
		OK(exec_rc() != 0 && s && strstr(s, "fileset"),
		   "p31-mv-dst-undeclared-deny");
		snprintf(args, sizeof(args),
			 "{\"path\":\"%s\",\"oldString\":\"x\","
			 "\"newString\":\"y\"}", p1);
		s = (char *)exec_tool("edit", args);
		OK(exec_rc() == 0, "p31-edit-declared-ok");
		/* 无 env=零扰动（主会话面不受限） */
		unsetenv("OCC_TASK_FILESET");
		snprintf(args, sizeof(args),
			 "{\"path\":\"%s\",\"content\":\"x\"}", p2);
		s = (char *)exec_tool("write", args);
		OK(exec_rc() == 0, "p31-noenv-unrestricted");
	}

	occ_tool_result_free(&g_res);
	{
		char cmd[300];

		snprintf(cmd, sizeof(cmd), "rm -rf %.240s", tmpdir);
		if (system(cmd)) {
			/* 清理失败不影响判定 */
		}
	}
	printf("test_tools: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
