/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_cli_rc.c - O-23：CLI 错误路径退出码六案（fork+exec 真跑 ./occ）。
 *
 * 实证（11-19 六案，当时机上旧二进制全 rc=0）：缺 prompt / undo 缺
 * --session / --recover 缺 id / 投毒拒收 / 未知 flag 当 prompt 烧真
 * 模型 / unstuck --help。修复合同：
 *   1. occ -p（缺 prompt）            → rc=2 + 用法提示
 *   2. occ undo（缺 --session）       → rc=2
 *   3. occ --recover（缺 id）         → rc=2
 *   4. occ undo --session <不存在>    → rc=1（校验/执行失败保持错误
 *      输出；快照投毒拒收的文件级断言在 test_revert I 系列
 *      （r.files[].failed==1）+ cmd_undo 映射 failed→1）
 *   5. occ -p --definitely-not-a-flag → rc=2 +「疑似 flag 误当提示词」
 *      且不发起模型调用（model.toml 指闭端口：若误发起调用则连接
 *      失败 rc=1，与 rc=2 可区分）
 *   6. occ unstuck --help             → rc=0 + 一行用法（标准惯例）
 *
 * 隔离：HOME/OCC_DB/OCC_MODEL_TOML/OCC_PROVIDER_TOML 全指临时目录
 * （不碰用户 ~/.occ 与生产库）。前置 ./occ 已构建；未构建诚实 skip。
 */
#define _DEFAULT_SOURCE 1	/* usleep 等 POSIX 惯用（邻码同口径） */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* fork+exec ./occ（argv[0] 占位由本函数补）；stdout/stderr 落文件；
 * 返回退出码（-1=执行失败）；out_buf 回读 stdout+stderr 拼接 */
static int run_occ(char **args, char *out_buf, size_t out_cap,
		   char *tmpdir, const char *tag)
{
	pid_t pid;
	int st = 0, w;
	char path[600];
	int fd_out, fd_err;
	ssize_t n;

	snprintf(path, sizeof(path), "%s/%s.out", tmpdir, tag);
	fd_out = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	snprintf(path, sizeof(path), "%s/%s.err", tmpdir, tag);
	fd_err = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd_out < 0 || fd_err < 0) {
		if (fd_out >= 0)
			close(fd_out);
		if (fd_err >= 0)
			close(fd_err);
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		close(fd_out);
		close(fd_err);
		return -1;
	}
	if (pid == 0) {
		if (dup2(fd_out, STDOUT_FILENO) < 0 ||
		    dup2(fd_err, STDERR_FILENO) < 0)
			_exit(99);
		close(fd_out);
		close(fd_err);
		execv("./occ", args);
		_exit(127);
	}
	close(fd_out);
	close(fd_err);
	for (w = 0; w < 300; w++) {
		pid_t r = waitpid(pid, &st, WNOHANG);

		if (r == pid)
			break;
		usleep(20000);
	}
	if (w == 300) {
		kill(pid, SIGKILL);
		waitpid(pid, &st, 0);
		return -1;
	}
	/* 回读 stdout + stderr */
	if (out_buf && out_cap) {
		size_t off = 0;
		int i;

		out_buf[0] = '\0';
		for (i = 0; i < 2; i++) {
			int fd;

			snprintf(path, sizeof(path), "%s/%s.%s", tmpdir,
				 tag, i == 0 ? "out" : "err");
			fd = open(path, O_RDONLY);
			if (fd < 0)
				continue;
			while (off + 1 < out_cap &&
			       (n = read(fd, out_buf + off,
					 out_cap - off - 1)) > 0)
				off += (size_t)n;
			close(fd);
			out_buf[off] = '\0';
		}
	}
	if (!WIFEXITED(st))
		return -1;
	return WEXITSTATUS(st);
}

int main(void)
{
	char tmpl[] = "/tmp/occ_cli_rc-XXXXXX";
	char *tmp;
	char home[300], dbp[300], toml[300], ptoml[300];
	static char out[16384];
	int rc;

	signal(SIGPIPE, SIG_IGN);

	if (access("./occ", X_OK) != 0) {
		printf("test_cli_rc: SKIP（./occ 未构建——occ 顶层 "
		       "make 后生效）\n");
		return 0;
	}
	tmp = mkdtemp(tmpl);
	if (!tmp) {
		printf("FAIL mkdtemp\n");
		return 1;
	}
	snprintf(home, sizeof(home), "%s/home", tmp);
	snprintf(dbp, sizeof(dbp), "%s/db.sqlite", tmp);
	snprintf(toml, sizeof(toml), "%s/model.toml", tmp);
	snprintf(ptoml, sizeof(ptoml), "%s/provider.toml", tmp);
	mkdir(home, 0700);
	{
		FILE *f = fopen(toml, "w");

		if (!f) {
			printf("FAIL fixture toml\n");
			return 1;
		}
		/* 闭端口 base_url：零网络；case5 若误发起模型调用
		 * 会连接失败 rc=1（与正确 rc=2 可区分） */
		fputs("[models.cloud]\n"
		      "provider_type = \"openai_compatible\"\n"
		      "model_name = \"mock-rc\"\n"
		      "base_url = \"http://127.0.0.1:9/v1\"\n"
		      "api_key = \"mock-key-not-real\"\n", f);
		fclose(f);
		f = fopen(ptoml, "w");
		if (f)
			fclose(f);
	}
	setenv("HOME", home, 1);
	setenv("OCC_DB", dbp, 1);
	setenv("OCC_MODEL_TOML", toml, 1);
	setenv("OCC_PROVIDER_TOML", ptoml, 1);

	/* ---- 案 1：occ -p（缺 prompt）→ rc=2 ---- */
	{
		char *args[] = { "occ", "-p", NULL };

		rc = run_occ(args, out, sizeof(out), tmp, "c1");
		OK(rc == 2, "c1-missing-prompt-rc2");
		OK(strstr(out, "missing prompt") != NULL,
		   "c1-usage-hint");
	}

	/* ---- 案 2：occ undo（缺 --session）→ rc=2 ---- */
	{
		char *args[] = { "occ", "undo", NULL };

		rc = run_occ(args, out, sizeof(out), tmp, "c2");
		OK(rc == 2, "c2-undo-no-session-rc2");
		OK(strstr(out, "--session") != NULL, "c2-session-hint");
	}

	/* ---- 案 3：occ --recover（缺 id）→ rc=2 ---- */
	{
		char *args[] = { "occ", "--recover", NULL };

		rc = run_occ(args, out, sizeof(out), tmp, "c3");
		OK(rc == 2, "c3-recover-no-id-rc2");
		OK(strstr(out, "missing") != NULL, "c3-missing-hint");
	}

	/* ---- 案 4：occ undo --session <不存在> → rc=1（校验失败；
	 *      快照投毒拒收同走 cmd_undo failed→1，文件级断言在
	 *      test_revert I 系列） ---- */
	{
		char *args[] = { "occ", "undo", "--session",
				 "ses_cli_rc_notexist", NULL };

		rc = run_occ(args, out, sizeof(out), tmp, "c4");
		OK(rc == 1, "c4-undo-verify-fail-rc1");
		OK(strstr(out, "不存在") != NULL, "c4-err-text-kept");
	}

	/* ---- 案 5：occ -p --definitely-not-a-flag → rc=2 +
	 *      「疑似 flag 误当提示词」+ 不发起模型调用 ---- */
	{
		char *args[] = { "occ", "-p", "--definitely-not-a-flag",
				 NULL };

		rc = run_occ(args, out, sizeof(out), tmp, "c5");
		OK(rc == 2, "c5-unknown-flag-rc2");
		OK(strstr(out, "疑似 flag 误当提示词") != NULL,
		   "c5-flag-hint");
		/* 不发起模型调用：若走 resolve+call，闭端口连接失败
		 * rc=1 且错误文案为传输类——此处 rc==2 已证未发起 */
	}

	/* ---- 案 6：occ unstuck --help → rc=0 + 一行用法 ---- */
	{
		char *args[] = { "occ", "unstuck", "--help", NULL };

		rc = run_occ(args, out, sizeof(out), tmp, "c6");
		OK(rc == 0, "c6-unstuck-help-rc0");
		OK(strstr(out, "用法") != NULL, "c6-usage-line");
	}

	{
		char cmd[600];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp);
		if (system(cmd) != 0) { }	/* 清理尽力而为 */
	}
	printf("test_cli_rc: %s (%d ok, %d fail)\n",
	       n_fail ? "FAIL" : "ALL GREEN", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
