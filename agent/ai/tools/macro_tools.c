/* SPDX-License-Identifier: GPL-2.0 */
/*
 * macro_tools.c - W78 宏工具实现（13 件，TOOL_CH_MACRO）
 *
 * 设计：
 *  - R 件=纯读聚合（一次调用替代多次单件采样，消除时点漂移）
 *  - W1/W2 件=组合既有执行器实现（netlink act / sysctl / nft / systemd-run），
 *    风险分级照常过 lease 闸门，绝无旁路
 *  - 输出为文本/JSON 行；失败步骤如实报告
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tool_registry.h"
#include "netlink/ai_streams.h"	/* JSON 转义复用 */
#include "macro_tools.h"

/* executor.c 既有实现（W78 去静态供组合复用；不新增旁路语义） */
extern int exec_netlink_act(const struct ai_tool *tool, const char *args_json,
			    char **out);
extern int exec_sysctl_write(const struct ai_tool *tool,
			     const char *args_json, char **out);
extern int exec_sysfs_dyn(const struct ai_tool *tool,
			  const char *args_json, char **out);

/* ---- 小工具 ---- */

static int read_file_max(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return (int)n;
}

static void jput(FILE *f, const char *s)
{
	char tmp[8192];

	if (ai_streams_json_escape(s ? s : "", tmp, sizeof(tmp)) == 0)
		fprintf(f, "%s", tmp);
	else
		fprintf(f, "\"<long>\"");
}

static void chomp(char *s)
{
	size_t n = s ? strlen(s) : 0;

	while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
		s[--n] = '\0';
}

/* 有界 fork/execv：合并 stdout+stderr；超时 SIGKILL。
 * 返回：>=0 退出码；-99 超时；-1 启动/内部失败 */
static int run_argv(char *const argv[], int timeout_s, char *out, size_t cap)
{
	int pfd[2];
	pid_t pid;
	size_t used = 0;
	long deadline_ms = (long)timeout_s * 1000;
	long spent = 0;
	int status;

	if (pipe(pfd) < 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}
	if (pid == 0) {
		close(pfd[0]);
		dup2(pfd[1], 1);
		dup2(pfd[1], 2);
		close(pfd[1]);
		execv(argv[0], (char *const *)argv);
		_exit(127);
	}
	close(pfd[1]);
	while (spent < deadline_ms) {
		struct pollfd p = { .fd = pfd[0], .events = POLLIN };
		int r = poll(&p, 1, 200);

		if (r > 0 && (p.revents & (POLLIN | POLLHUP))) {
			ssize_t n;

			if (used + 1 >= cap)
				goto done;
			n = read(pfd[0], out + used, cap - used - 1);
			if (n == 0)
				goto done;	/* EOF：进程输出完毕 */
			if (n < 0) {
				if (errno == EINTR)
					continue;
				goto done;
			}
			used += (size_t)n;
		} else if (r < 0 && errno != EINTR) {
			break;
		}
		spent += 200;
		if (waitpid(pid, &status, WNOHANG) == pid)
			goto done;
	}
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
done:
	{
		ssize_t n;

		while (used + 1 < cap &&
		       (n = read(pfd[0], out + used, cap - used - 1)) > 0)
			used += (size_t)n;
	}
	close(pfd[0]);
	out[used] = '\0';
	if (spent >= deadline_ms && waitpid(pid, &status, WNOHANG) == 0)
		return -99;	/* 真超时（进程还活着被杀） */
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* 简易 JSON 取参（扁平键） */
static long long jnum(const char *json, const char *key, long long dflt)
{
	char pat[64];
	const char *p;

	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(json, pat);
	if (!p)
		return dflt;
	return strtoll(p + strlen(pat), NULL, 10);
}

static int jstr_get(const char *json, const char *key, char *out, size_t cap)
{
	char pat[64];
	const char *p, *q;
	size_t n;

	snprintf(pat, sizeof(pat), "\"%s\":\"", key);
	p = strstr(json, pat);
	if (!p)
		return -1;
	p += strlen(pat);
	q = strchr(p, '"');
	if (!q)
		return -1;
	n = (size_t)(q - p);
	if (n >= cap)
		n = cap - 1;
	memcpy(out, p, n);
	out[n] = '\0';
	return 0;
}

int ai_macro_valid_unit(const char *s)
{
	size_t n = 0;

	if (!s)
		return 0;
	for (const char *p = s; *p; p++, n++)
		if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '.' ||
		      *p == '@' || *p == '-'))
			return 0;
	return n >= 1 && n <= 64;
}

int ai_macro_valid_ip(const char *s)
{
	int dots = 0, colons = 0;
	size_t n = 0;

	if (!s || !*s)
		return 0;
	for (const char *p = s; *p; p++, n++) {
		if (*p == '.') dots++;
		else if (*p == ':') colons++;
		else if (*p >= '0' && *p <= '9') ;
		else if ((*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) ;
		else return 0;
	}
	if (dots == 3 && colons == 0 && n <= 15)
		return 1;
	if (colons >= 2 && dots <= 1 && n <= 45)
		return 1;
	return 0;
}

int ai_macro_valid_cal(const char *s)
{
	size_t n = 0;

	if (!s)
		return 0;
	for (const char *p = s; *p; p++, n++)
		if (!(isalnum((unsigned char)*p) || strchr("*,:./- ", *p)))
			return 0;
	return n >= 1 && n <= 64;
}

/* ---- R 件 ---- */

static int m_psi_snapshot(char **out)
{
	FILE *f = open_memstream(out, &(size_t){0});
	const char *res[] = { "cpu", "memory", "io" };

	if (!f)
		goto oom;
	fprintf(f, "{");
	for (int i = 0; i < 3; i++) {
		char path[64], buf[512];

		snprintf(path, sizeof(path), "/proc/pressure/%s", res[i]);
		if (read_file_max(path, buf, sizeof(buf)) < 0)
			fprintf(f, "%s\"%s\":\"unavailable\"", i ? "," : "",
				res[i]);
		else {
			chomp(buf);
			fprintf(f, "%s\"%s\":\"", i ? "," : "", res[i]);
			jput(f, buf);
			fprintf(f, "\"");
		}
	}
	{
		char buf[512];

		if (read_file_max("/proc/loadavg", buf, sizeof(buf)) >= 0) {
			chomp(buf);
			fprintf(f, ",\"loadavg\":\"");
			jput(f, buf);
			fprintf(f, "\"");
		}
	}
	{
		FILE *mf = fopen("/proc/meminfo", "re");
		char line[256];
		int got = 0;

		if (mf) {
			while (got < 2 && fgets(line, sizeof(line), mf)) {
				char key[32], val[64];

				if (sscanf(line, "%31s %63s", key, val) == 2 &&
				    (!strcmp(key, "MemTotal:") ||
				     !strcmp(key, "MemAvailable:"))) {
					fprintf(f, ",\"%s\":\"%s\"", key, val);
					got++;
				}
			}
			fclose(mf);
		}
	}
	fprintf(f, "}\n");
	fclose(f);
	return 0;
oom:
	*out = strdup("ERROR: 内存不足");
	return -1;
}

static int m_kernel_ai_healthcheck(char **out)
{
	static const struct { const char *k, *p; } items[] = {
		{ "status", "/proc/ai/status" },
		{ "control", "/proc/ai/control" },
		{ "hitrate", "/proc/ai/hitrate" },
		{ "latency", "/proc/ai/latency" },
		{ "decisions_total", "/proc/ai/stats_decisions_total" },
		{ "decisions_hit", "/proc/ai/stats_decisions_hit" },
		{ "telemetry_emitted", "/proc/ai/stats_telemetry_emitted" },
		{ "telemetry_dropped", "/proc/ai/stats_telemetry_dropped" },
	};
	FILE *f = open_memstream(out, &(size_t){0});

	if (!f)
		goto oom;
	fprintf(f, "{");
	for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
		char buf[1024];

		if (read_file_max(items[i].p, buf, sizeof(buf)) < 0)
			fprintf(f, "%s\"%s\":\"unavailable\"", i ? "," : "",
				items[i].k);
		else {
			chomp(buf);
			fprintf(f, "%s\"%s\":\"", i ? "," : "", items[i].k);
			jput(f, buf);
			fprintf(f, "\"");
		}
	}
	fprintf(f, "}\n");
	fclose(f);
	return 0;
oom:
	*out = strdup("ERROR: 内存不足");
	return -1;
}

static int m_disk_hogs(char **out)
{
	FILE *f = open_memstream(out, &(size_t){0});
	FILE *mf;
	char line[512];
	int n = 0;

	if (!f)
		goto oom;
	mf = fopen("/proc/mounts", "re");
	if (!mf) {
		if (f) fclose(f);
		*out = strdup("ERROR: 无法读 /proc/mounts");
		return -1;
	}
	fprintf(f, "{\"mounts\":[");
	while (fgets(line, sizeof(line), mf)) {
		char dev[192], mnt[192], type[32];
		struct statvfs vfs;
		unsigned long long total, avail;
		int pct;

		if (sscanf(line, "%191s %191s %31s", dev, mnt, type) != 3)
			continue;
		if (strcmp(type, "ext4") && strcmp(type, "ext3") &&
		    strcmp(type, "xfs") && strcmp(type, "btrfs"))
			continue;
		if (statvfs(mnt, &vfs) < 0)
			continue;
		total = (unsigned long long)vfs.f_frsize * vfs.f_blocks;
		avail = (unsigned long long)vfs.f_frsize * vfs.f_bavail;
		pct = total ? (int)((total - avail) * 100 / total) : 0;
		fprintf(f, "%s{\"mount\":", n ? "," : "");
		jput(f, mnt);
		fprintf(f, ",\"type\":\"%s\",\"used_pct\":%d,"
			   "\"total_bytes\":%llu,\"avail_bytes\":%llu}",
			type, pct, total, avail);
		n++;
	}
	fclose(mf);
	fprintf(f, "]}\n");
	fclose(f);
	return 0;
oom:
	*out = strdup("ERROR: 内存不足");
	return -1;
}

static int m_service_doctor(const char *args, char **out)
{
	char unit[80];
	static char buf[16384];
	FILE *f;

	if (jstr_get(args, "unit", unit, sizeof(unit)) < 0 ||
	    !ai_macro_valid_unit(unit)) {
		*out = strdup("ERROR: 需要合法 unit 名参数（如 sshd.service）");
		return -1;
	}
	f = open_memstream(out, &(size_t){0});
	if (!f)
		goto oom;
	{
		char a1[96];
		char *argv1[] = { (char *)"/usr/bin/systemctl", (char *)"is-active",
				  a1, NULL };
		char *argv2[] = { (char *)"/usr/bin/systemctl", (char *)"status",
				  a1, (char *)"--no-pager", (char *)"-n",
				  (char *)"0", NULL };
		char *argv3[] = { (char *)"/usr/bin/journalctl", (char *)"-u",
				  a1, (char *)"--no-pager", (char *)"-n",
				  (char *)"20", NULL };
		int rc;

		snprintf(a1, sizeof(a1), "%s", unit);
		rc = run_argv(argv1, 10, buf, sizeof(buf));
		chomp(buf);
		fprintf(f, "== is-active: %s\n", buf);
		rc = run_argv(argv2, 15, buf, sizeof(buf));
		fprintf(f, "== status (exit=%d) ==\n%s\n", rc, buf);
		rc = run_argv(argv3, 15, buf, sizeof(buf));
		fprintf(f, "== 最近日志 ==\n%s\n",
			rc == -99 ? "(journalctl 超时)" : buf);
	}
	fclose(f);
	return 0;
oom:
	*out = strdup("ERROR: 内存不足");
	return -1;
}

static int m_baseline_diff(const char *args, char **out)
{
	static char baseline[32768];
	FILE *f;
	char *line, *sv;
	int total = 0, diff = 0;

	if (jstr_get(args, "baseline", baseline, sizeof(baseline)) < 0) {
		*out = strdup("ERROR: 需要 baseline 参数"
			      "（sysctl_snapshot 的输出文本）");
		return -1;
	}
	f = open_memstream(out, &(size_t){0});
	if (!f)
		goto oom;
	for (line = strtok_r(baseline, "\n", &sv); line;
	     line = strtok_r(NULL, "\n", &sv)) {
		char *eq = strchr(line, '=');
		char path[256], cur[512];

		if (!eq || line[0] == '#')
			continue;
		*eq = '\0';
		snprintf(path, sizeof(path), "/proc/sys/%s", line);
		if (read_file_max(path, cur, sizeof(cur)) < 0) {
			fprintf(f, "{\"key\":");
			jput(f, line);
			fprintf(f, ",\"current\":\"<gone>\"}\n");
			diff++;
			total++;
			continue;
		}
		chomp(cur);
		{
			int same = strcmp(cur, eq + 1) == 0;

			fprintf(f, "{\"key\":");
			jput(f, line);
			fprintf(f, ",\"equal\":%s,\"baseline\":",
				same ? "true" : "false");
			jput(f, eq + 1);
			fprintf(f, ",\"current\":");
			jput(f, cur);
			fprintf(f, "}\n");
			total++;
			if (!same)
				diff++;
		}
	}
	fprintf(f, "{\"summary\":{\"total\":%d,\"diff\":%d}}\n", total, diff);
	fclose(f);
	return 0;
oom:
	*out = strdup("ERROR: 内存不足");
	return -1;
}

/* 递归 /proc/sys/<rel>，输出 "a.b.c=value" 行（rel 用 / 形式，输出转 .） */
static int snap_dir(const char *rel, FILE *f, int depth, int *count)
{
	char dpath[512];
	DIR *d;
	struct dirent *de;

	if (depth > 6)
		return 0;
	if (rel[0])
		snprintf(dpath, sizeof(dpath), "/proc/sys/%s", rel);
	else
		snprintf(dpath, sizeof(dpath), "/proc/sys");
	d = opendir(dpath);
	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		char sub[512], key[512];
		char val[512];
		size_t i;

		if (de->d_name[0] == '.')
			continue;
		if (rel[0])
			snprintf(sub, sizeof(sub), "%s/%s", rel, de->d_name);
		else
			snprintf(sub, sizeof(sub), "%s", de->d_name);
		/* 尝试当文件读 */
		{
			char fpath[600];

			snprintf(fpath, sizeof(fpath), "/proc/sys/%s", sub);
			if (read_file_max(fpath, val, sizeof(val)) >= 0) {
				chomp(val);
				snprintf(key, sizeof(key), "%s", sub);
				for (i = 0; key[i]; i++)
					if (key[i] == '/')
						key[i] = '.';
				fprintf(f, "%s=%s\n", key, val);
				(*count)++;
				continue;
			}
		}
		snap_dir(sub, f, depth + 1, count);
	}
	closedir(d);
	return 0;
}

static int m_sysctl_snapshot(const char *args, char **out)
{
	char prefix[128];
	char rel[192];
	FILE *f;
	int count = 0;

	if (jstr_get(args, "prefix", prefix, sizeof(prefix)) < 0)
		prefix[0] = '\0';
	/* prefix 允许 "net" 或 "net/ipv4"，统一转 / 形式 */
	for (size_t i = 0; i < strlen(prefix); i++)
		if (prefix[i] == '.')
			prefix[i] = '/';
	snprintf(rel, sizeof(rel), "%s", prefix);
	f = open_memstream(out, &(size_t){0});
	if (!f)
		goto oom;
	if (snap_dir(rel, f, 0, &count) < 0) {
		fclose(f);
		*out = strdup("ERROR: /proc/sys 遍历失败（prefix 不存在？）");
		return -1;
	}
	fprintf(f, "# total=%d\n", count);
	fclose(f);
	return 0;
oom:
	*out = strdup("ERROR: 内存不足");
	return -1;
}

/* ---- W 件 ---- */

static int m_sysctl_restore(const char *args, char **out)
{
	static char snap[32768];
	FILE *f;
	char *line, *sv;
	int ok = 0, fail = 0;

	if (jstr_get(args, "snapshot", snap, sizeof(snap)) < 0) {
		*out = strdup("ERROR: 需要 snapshot 参数"
			      "（sysctl_snapshot 输出文本）");
		return -1;
	}
	f = open_memstream(out, &(size_t){0});
	if (!f)
		goto oom;
	for (line = strtok_r(snap, "\n", &sv); line;
	     line = strtok_r(NULL, "\n", &sv)) {
		char *eq = strchr(line, '=');
		struct ai_tool t;
		char ajson[768];
		char *sub = NULL;

		if (!eq || line[0] == '#')
			continue;
		*eq = '\0';
		memset(&t, 0, sizeof(t));
		t.name = "sysctl_set";
		t.risk = "W2";
		snprintf(ajson, sizeof(ajson),
			 "{\"path\":\"%s\",\"value\":\"%s\"}", line, eq + 1);
		if (exec_sysctl_write(&t, ajson, &sub) == 0) {
			ok++;
		} else {
			fail++;
			fprintf(f, "FAIL %s: %s\n", line, sub ? sub : "?");
		}
		free(sub);
	}
	fprintf(f, "restore ok=%d fail=%d\n", ok, fail);
	fclose(f);
	return fail ? -1 : 0;
oom:
	*out = strdup("ERROR: 内存不足");
	return -1;
}

static int m_schedule_list(char **out)
{
	static char buf[16384];
	char *argv[] = { (char *)"/usr/bin/systemctl", (char *)"list-timers",
			 (char *)"aik-*", (char *)"--all",
			 (char *)"--no-pager", NULL };
	int rc = run_argv(argv, 15, buf, sizeof(buf));

	if (asprintf(out, "exit=%d\n%s", rc, buf) < 0)
		*out = NULL;
	return rc == 0 ? 0 : -1;
}

static int m_schedule_create(const char *args, char **out)
{
	char name[80], cal[80], command[1024];
	static char buf[8192];
	char unit[128], desc[192], onc[128], onc_v[96];
	char *argv[9];
	int rc, i = 0;

	if (jstr_get(args, "name", name, sizeof(name)) < 0 ||
	    !ai_macro_valid_unit(name)) {
		*out = strdup("ERROR: 需要 name（[A-Za-z0-9_.@-]{1,64}）");
		return -1;
	}
	if (jstr_get(args, "calendar", cal, sizeof(cal)) < 0 ||
	    !ai_macro_valid_cal(cal)) {
		*out = strdup("ERROR: 需要 calendar（systemd OnCalendar 表达式，"
			      "如 'hourly' 'Mon *-*-* 03:00:00'）");
		return -1;
	}
	if (jstr_get(args, "command", command, sizeof(command)) < 0 ||
	    !command[0]) {
		*out = strdup("ERROR: 需要 command（经 /bin/sh -c 执行）");
		return -1;
	}
	snprintf(unit, sizeof(unit), "--unit=aik-%s.timer", name);
	snprintf(desc, sizeof(desc), "--description=AIKernel schedule %s", name);
	snprintf(onc, sizeof(onc), "--on-calendar=%s", cal);
	snprintf(onc_v, sizeof(onc_v), "%s", onc);
	argv[i++] = (char *)"/usr/bin/systemd-run";
	argv[i++] = unit;
	argv[i++] = desc;
	argv[i++] = onc_v;
	argv[i++] = (char *)"/bin/sh";
	argv[i++] = (char *)"-c";
	argv[i++] = command;
	argv[i++] = NULL;
	rc = run_argv(argv, 20, buf, sizeof(buf));
	if (asprintf(out, "systemd-run exit=%d\n%s\n"
		     "（transient timer：aik-%s.timer；schedule_remove 停止；"
		     "重启不保留，长期任务请写 systemd unit）",
		     rc, buf, name) < 0)
		*out = NULL;
	return rc == 0 ? 0 : -1;
}

static int m_schedule_remove(const char *args, char **out)
{
	char name[80], unit[128];
	static char buf[4096];
	char *argv[4];
	int rc;

	if (jstr_get(args, "name", name, sizeof(name)) < 0 ||
	    !ai_macro_valid_unit(name)) {
		*out = strdup("ERROR: 需要 name");
		return -1;
	}
	snprintf(unit, sizeof(unit), "aik-%s.timer", name);
	argv[0] = (char *)"/usr/bin/systemctl";
	argv[1] = (char *)"stop";
	argv[2] = unit;
	argv[3] = NULL;
	rc = run_argv(argv, 15, buf, sizeof(buf));
	if (asprintf(out, "systemctl stop %s exit=%d\n%s", unit, rc, buf) < 0)
		*out = NULL;
	return rc == 0 ? 0 : -1;
}

static int m_ip_ban_verified(const char *args, char **out)
{
	char ip[64], addr[96];
	static char buf[8192];
	char *argv[12];
	int rc, i = 0, remain = 0;
	FILE *cf;

	if (jstr_get(args, "ip", ip, sizeof(ip)) < 0 || !ai_macro_valid_ip(ip)) {
		*out = strdup("ERROR: 需要 ip（IPv4/IPv6 字面量）");
		return -1;
	}
	snprintf(addr, sizeof(addr), "%s", ip);
	argv[i++] = (char *)"/usr/sbin/nft";
	argv[i++] = (char *)"insert";
	argv[i++] = (char *)"rule";
	argv[i++] = (char *)"inet";
	argv[i++] = (char *)"filter";
	argv[i++] = (char *)"input";
	argv[i++] = (char *)(strchr(ip, ':') ? "ip6" : "ip");
	argv[i++] = (char *)"saddr";
	argv[i++] = addr;
	argv[i++] = (char *)"drop";
	argv[i++] = NULL;
	rc = run_argv(argv, 10, buf, sizeof(buf));
	if (rc != 0) {
		if (asprintf(out, "ERROR: nft 规则插入失败 exit=%d\n%s\n"
			     "（若表/链拓扑不同，用 exec nft list ruleset 自查后"
			     "用 config_write_nftables 持久化封禁）",
			     rc, buf) < 0)
			*out = NULL;
		return -1;
	}
	cf = fopen("/proc/net/nf_conntrack", "re");
	if (cf) {
		char l[1024];

		while (fgets(l, sizeof(l), cf))
			if (strstr(l, ip))
				remain++;
		fclose(cf);
	}
	if (asprintf(out, "OK: 已插入 inet filter input %s saddr %s drop"
		     "（运行时规则，重启即清；持久化用 config_write_nftables）\n"
		     "conntrack 残留 %d 条（老化后消失；可用 exec conntrack -D "
		     "加速清理）",
		     strchr(ip, ':') ? "ip6" : "ip", ip, remain) < 0)
		*out = NULL;
	return 0;
}

static int m_process_quarantine(const char *args, char **out)
{
	long long pid = jnum(args, "pid", 0);
	struct ai_tool t;
	char ajson[64];
	char *sub = NULL;
	FILE *f;
	char st[512], path[64];
	int rc1, rc2, rcv = -1;

	if (pid <= 1) {
		*out = strdup("ERROR: 需要 pid>1（拒绝对 init 操作）");
		return -1;
	}
	snprintf(path, sizeof(path), "/proc/%lld/status", pid);
	if (read_file_max(path, st, sizeof(st)) < 0) {
		*out = strdup("ERROR: pid 不存在");
		return -1;
	}
	f = open_memstream(out, &(size_t){0});
	if (!f)
		goto oom;
	memset(&t, 0, sizeof(t));
	t.name = "netlink_act_sched_nice";
	t.param = "sched.nice";
	t.domain = 1;
	t.risk = "W2";
	snprintf(ajson, sizeof(ajson), "{\"pid\":%lld,\"value\":19}", pid);
	rc1 = exec_netlink_act(&t, ajson, &sub);
	fprintf(f, "step1 sched.nice=19: %s\n", sub ? sub : "?");
	free(sub);
	sub = NULL;
	memset(&t, 0, sizeof(t));
	t.name = "netlink_act_proc_freeze";
	t.param = "proc.freeze";
	t.domain = 12;
	t.risk = "W2";
	snprintf(ajson, sizeof(ajson), "{\"pid\":%lld,\"value\":1}", pid);
	rc2 = exec_netlink_act(&t, ajson, &sub);
	fprintf(f, "step2 proc.freeze=1: %s\n", sub ? sub : "?");
	free(sub);
	if (read_file_max(path, st, sizeof(st)) >= 0) {
		char *sp = strstr(st, "State:");

		if (sp) {
			chomp(sp);
			fprintf(f, "verify: %s\n", sp);
			rcv = (strncmp(sp, "State:\tF", 8) == 0 ||
			       strncmp(sp, "State: F", 8) == 0) ? 0 : 1;
		}
	}
	fclose(f);
	return (rc1 == 0 && rc2 == 0) ? (rcv == 0 ? 0 : -1) : -1;
oom:
	*out = strdup("ERROR: 内存不足");
	return -1;
}

static int m_model_verify(const char *args, char **out)
{
	char path[256];
	FILE *f;
	static char buf[4096];
	struct ai_tool t;
	char ajson[512];
	char *sub = NULL;
	int rc;

	if (jstr_get(args, "path", path, sizeof(path)) < 0 || path[0] != '/') {
		*out = strdup("ERROR: 需要 path（AIKWMDL 模型文件绝对路径）");
		return -1;
	}
	f = open_memstream(out, &(size_t){0});
	if (!f)
		goto oom;
	memset(&t, 0, sizeof(t));
	t.name = "sysfs_set";
	t.risk = "W1";
	snprintf(ajson, sizeof(ajson),
		 "{\"path\":\"/sys/kernel/ai/model_load\",\"value\":\"%s\"}",
		 path);
	rc = exec_sysfs_dyn(&t, ajson, &sub);
	fprintf(f, "step1 model_load: %s\n", sub ? sub : "?");
	free(sub);
	sub = NULL;
	snprintf(ajson, sizeof(ajson),
		 "{\"path\":\"/sys/kernel/ai/model_in\","
		 "\"value\":\"aik-w78-verify\"}");
	exec_sysfs_dyn(&t, ajson, &sub);
	fprintf(f, "step2 model_in: %s\n", sub ? sub : "?");
	free(sub);
	sub = NULL;
	if (read_file_max("/sys/kernel/ai/model_out", buf, sizeof(buf)) >= 0) {
		chomp(buf);
		fprintf(f, "step3 model_out: ");
		jput(f, buf);
		fprintf(f, "\n");
	} else {
		fprintf(f, "step3 model_out: <unavailable>\n");
	}
	snprintf(ajson, sizeof(ajson),
		 "{\"path\":\"/sys/kernel/ai/model_load\",\"value\":\"0\"}");
	exec_sysfs_dyn(&t, ajson, &sub);
	fprintf(f, "step4 unload: %s\n", sub ? sub : "?");
	free(sub);
	fclose(f);
	return rc == 0 ? 0 : -1;
oom:
	*out = strdup("ERROR: 内存不足");
	return -1;
}

/* ---- 分发 ---- */

int exec_macro_channel(const void *tool_v, const char *args_json, char **out)
{
	const struct ai_tool *tool = (const struct ai_tool *)tool_v;
	const char *a = args_json ? args_json : "{}";

	if (!strcmp(tool->name, "psi_snapshot"))
		return m_psi_snapshot(out);
	if (!strcmp(tool->name, "kernel_ai_healthcheck"))
		return m_kernel_ai_healthcheck(out);
	if (!strcmp(tool->name, "disk_hogs"))
		return m_disk_hogs(out);
	if (!strcmp(tool->name, "service_doctor"))
		return m_service_doctor(a, out);
	if (!strcmp(tool->name, "baseline_diff"))
		return m_baseline_diff(a, out);
	if (!strcmp(tool->name, "sysctl_snapshot"))
		return m_sysctl_snapshot(a, out);
	if (!strcmp(tool->name, "schedule_list"))
		return m_schedule_list(out);
	if (!strcmp(tool->name, "sysctl_restore"))
		return m_sysctl_restore(a, out);
	if (!strcmp(tool->name, "schedule_create"))
		return m_schedule_create(a, out);
	if (!strcmp(tool->name, "schedule_remove"))
		return m_schedule_remove(a, out);
	if (!strcmp(tool->name, "ip_ban_verified"))
		return m_ip_ban_verified(a, out);
	if (!strcmp(tool->name, "process_quarantine"))
		return m_process_quarantine(a, out);
	if (!strcmp(tool->name, "model_verify"))
		return m_model_verify(a, out);
	*out = strdup("ERROR: 未知 macro 工具（注册表异常）");
	return -1;
}
