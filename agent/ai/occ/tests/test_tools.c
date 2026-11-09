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
		char cwd[256];

		snprintf(cwd, sizeof(cwd), "%s", tmpdir);
		OK(occ_write_target_ok("/tmp/x", cwd), "guard-tmp-ok");
		OK(occ_write_target_ok("/etc/passwd", cwd) == 0,
		   "guard-etc-no");
	}

	/* ======== 工具定义（6 件、名字/schema 非空） ======== */
	{
		size_t n = 0;
		const occ_tool_def *d = occ_tool_defs(&n);
		int schema_ok = 1;

		OK(n == 6, "defs-six");
		OK(!strcmp(d[0].name, "read") &&
		   !strcmp(d[1].name, "write") &&
		   !strcmp(d[2].name, "edit") &&
		   !strcmp(d[3].name, "glob") &&
		   !strcmp(d[4].name, "grep") &&
		   !strcmp(d[5].name, "bash"), "defs-names");
		for (size_t i = 0; i < n; i++)
			if (!d[i].parameters ||
			    !strstr(d[i].parameters, "required") ||
			    !d[i].description)
				schema_ok = 0;
		OK(schema_ok, "defs-schema");
		OK(occ_tool_is_known("edit") && !occ_tool_is_known("rm"),
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
		OK(occ_snapshot_stage(tmpdir, "ses_snap", "msg_snap", p,
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
		OK(occ_snapshot_stage(tmpdir, "ses_snap", "msg_snap2", p,
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

		/* B7 未知工具 */
		s = (char *)exec_tool("rm", "{\"path\":\"x\"}");
		OK(exec_rc() != 0 && strstr(s, "未知工具"), "bash7-unknown");
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
