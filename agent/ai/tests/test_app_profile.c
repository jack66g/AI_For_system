/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
/*
 * test_app_profile - W81c 应用静态/动态画像 + 差集风险报告单测
 *
 * 默认（非 root）：纯函数（readelf/dpkg/desktop/proc-net/strace 解析）、
 *   白名单与参数闸门、真实静态画像（/usr/bin/ls 与临时脚本）、不动文件
 *   系统的诚实错误、差集三栏与风险分、注册表接线。零 side effect。
 *
 * --live（root + aik-sandbox）：在 workspace 里真跑 /usr/bin/ls 与
 *   /usr/bin/curl --version，校验 JSON 事件流，并把事件流喂给差集报告。
 * --emit DIR（root）：把静态原文/动态 JSON/三栏报告/异常输入写到 DIR，
 *   供 W81c 证据目录使用（与 --live 可叠加）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "../tools/tool_registry.h"
#include "../tools/app_profile.h"
#include "../tools/workspace_tools.h"

static int fails;
static int checks;
static int skips;

#define CHECK(cond, msg) do { \
	checks++; \
	if (cond) { \
		printf("ok %s\n", msg); \
	} else { \
		printf("FAIL %s\n", msg); \
		fails++; \
	} \
} while (0)

#define SKIP(msg, why) do { \
	printf("skip %s（%s）\n", msg, why); \
	skips++; \
} while (0)

static int tool_call(const char *name, const char *args, char **out, int *rc)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.name = (char *)name;
	t.channel = TOOL_CH_APPPROFILE;
	*out = NULL;
	*rc = exec_app_profile_channel(&t, args, out);
	return *rc;
}

/* ===================== 纯函数：ELF 枚举 ===================== */
static void test_elf_enums(void)
{
	CHECK(strcmp(ap_elf_type_str(2), "EXEC") == 0, "elf-type-EXEC");
	CHECK(strcmp(ap_elf_type_str(3), "DYN") == 0, "elf-type-DYN");
	CHECK(strcmp(ap_elf_type_str(99), "OTHER") == 0, "elf-type-other");
	CHECK(strcmp(ap_elf_machine_str(62), "x86-64") == 0, "machine-x86-64");
	CHECK(strcmp(ap_elf_machine_str(183), "aarch64") == 0, "machine-arm64");
	CHECK(strcmp(ap_elf_machine_str(999), "unknown") == 0, "machine-unknown");
}

/* ===================== readelf -d 解析 ===================== */
static const char *DYN_FIXTURE =
"Dynamic section at offset 0x3e9a0 contains 6 entries:\n"
" 0x0000000000000001 (NEEDED)             共享库：[libcurl.so.4]\n"
" 0x0000000000000001 (NEEDED)             共享库：[libc.so.6]\n"
" 0x000000000000000e (SONAME)             Library soname: [libfoo.so.1]\n"
" 0x000000000000001d (RUNPATH)            Library runpath: "
"[/opt/app/lib:/usr/local/lib]\n"
" 0x000000000000001d (RPATH)              Library rpath: [/opt/rpath]\n"
" 0x0000000000000001 (FLAGS)              BIND_NOW\n"
" 0x0000000000000001 (FLAGS_1)            Flags: NOW PIE\n"
" 0x0000000000000016 (TEXTREL)            0x0\n";

static void test_dyn_parse(void)
{
	struct ap_dynsec d;
	char err[256] = "";

	CHECK(ap_dyn_parse(DYN_FIXTURE, &d, err, sizeof(err)) == 0,
	      "dyn-parse-ok");
	CHECK(d.needed_n == 2 && strcmp(d.needed[0], "libcurl.so.4") == 0 &&
	      strcmp(d.needed[1], "libc.so.6") == 0, "dyn-needed");
	CHECK(strcmp(d.soname, "libfoo.so.1") == 0, "dyn-soname");
	CHECK(d.runpath_n == 2 && strcmp(d.runpath[0], "/opt/app/lib") == 0 &&
	      strcmp(d.runpath[1], "/usr/local/lib") == 0, "dyn-runpath");
	CHECK(d.rpath_n == 1 && strcmp(d.rpath[0], "/opt/rpath") == 0,
	      "dyn-rpath");
	CHECK(d.bind_now == 1, "dyn-bind-now");
	CHECK(d.pie_flag == 1, "dyn-flags1-pie");
	CHECK(d.textrel == 1, "dyn-textrel");

	CHECK(ap_dyn_parse("There is no dynamic section in this file.\n",
			   &d, err, sizeof(err)) == -1 &&
	      strstr(err, "静态链接") != NULL, "dyn-static-refuse");
	CHECK(ap_dyn_parse("garbage\n", &d, err, sizeof(err)) == -1,
	      "dyn-garbage-refuse");
	CHECK(ap_dyn_parse("", &d, err, sizeof(err)) == -1, "dyn-empty-refuse");
}

/* ===================== readelf --dyn-syms 解析 ===================== */
static const char *SYM_FIXTURE =
"\nSymbol table '.dynsym' contains 5 entries:\n"
"   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
"     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND \n"
"     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND ftell\n"
"     2: 0000000000000000     0 OBJECT  GLOBAL DEFAULT   20 stdout\n"
"     3: 0000000000000000     0 IFUNC   GLOBAL DEFAULT   21 memcpy\n"
"     4: 0000000000000000    16 FUNC    GLOBAL DEFAULT   22 main\n";

static void test_dynsym_parse(void)
{
	struct ap_symcount s;
	char err[256] = "";

	CHECK(ap_dynsym_parse(SYM_FIXTURE, &s, err, sizeof(err)) == 0,
	      "sym-parse-ok");
	CHECK(s.total == 5, "sym-total");
	CHECK(s.func == 2, "sym-func");
	CHECK(s.object == 1, "sym-object");
	CHECK(s.ifunc == 1, "sym-ifunc");
	CHECK(s.notype == 1, "sym-notype");
	CHECK(s.undef == 2, "sym-undef");
	CHECK(ap_dynsym_parse("readelf: Error: no symbols\n", &s, err,
			      sizeof(err)) == -1, "sym-empty-refuse");
	CHECK(ap_dynsym_parse("", &s, err, sizeof(err)) == -1,
	      "sym-blank-refuse");
}

/* ===================== dpkg -S 解析 ===================== */
static void test_dpkg_parse(void)
{
	char pkg[128], err[256] = "";

	CHECK(ap_dpkg_s_parse("curl: /usr/bin/curl\n", pkg, sizeof(pkg),
			      err, sizeof(err)) == 0 &&
	      strcmp(pkg, "curl") == 0, "dpkg-simple");
	CHECK(ap_dpkg_s_parse("libc6, libc6-dev: /usr/lib/libc.so.6\n",
			      pkg, sizeof(pkg), err, sizeof(err)) == 0 &&
	      strcmp(pkg, "libc6") == 0, "dpkg-multi-first");
	CHECK(ap_dpkg_s_parse("dpkg-query: no path found matching pattern "
			      "/tmp/x\n", pkg, sizeof(pkg), err,
			      sizeof(err)) == 1, "dpkg-not-found");
	CHECK(ap_dpkg_s_parse("dpkg: error: cannot open\n", pkg,
			      sizeof(pkg), err, sizeof(err)) == -1,
	      "dpkg-error");
	CHECK(ap_dpkg_s_parse("garbage-without-colon\n", pkg, sizeof(pkg),
			      err, sizeof(err)) == -1, "dpkg-garbage");
}

/* ===================== .desktop 解析 ===================== */
static void test_desktop_parse(void)
{
	struct ap_desktop d;
	const char *text =
	    "[Desktop Entry]\n"
	    "Type=Application\n"
	    "Name=Foo Viewer\n"
	    "Exec=/usr/bin/foo --open %U\n"
	    "Terminal=false\n"
	    "X-Flatpak=org.example.Foo\n"
	    "X-Sandbox-Mode=strict\n";

	memset(&d, 0, sizeof(d));
	CHECK(ap_desktop_parse_text(text, "foo", &d) == 1, "desktop-match");
	CHECK(strcmp(d.name, "Foo Viewer") == 0, "desktop-name");
	CHECK(strcmp(d.exec, "/usr/bin/foo --open %U") == 0, "desktop-exec");
	CHECK(strcmp(d.type, "Application") == 0, "desktop-type");
	CHECK(strstr(d.sandbox, "X-Flatpak=org.example.Foo") != NULL,
	      "desktop-sandbox-flatpak");
	CHECK(strstr(d.sandbox, "X-Sandbox-Mode=strict") != NULL,
	      "desktop-sandbox-key");

	memset(&d, 0, sizeof(d));
	CHECK(ap_desktop_parse_text(
		  "[Desktop Entry]\nExec=\"/usr/bin/bar\" --x\n", "bar",
		  &d) == 1 && strcmp(d.exec, "\"/usr/bin/bar\" --x") == 0,
	      "desktop-quoted");
	memset(&d, 0, sizeof(d));
	CHECK(ap_desktop_parse_text(
		  "[Desktop Entry]\nExec=env FOO=1 /usr/bin/foo %U\n", "foo",
		  &d) == 1, "desktop-env-prefix");
	memset(&d, 0, sizeof(d));
	CHECK(ap_desktop_parse_text("[Desktop Entry]\nTryExec=/usr/bin/foo\n",
				    "foo", &d) == 1, "desktop-tryexec");
	memset(&d, 0, sizeof(d));
	CHECK(ap_desktop_parse_text("[Desktop Entry]\nExec=/usr/bin/other\n",
				    "foo", &d) == 0, "desktop-nomatch");
	CHECK(ap_desktop_parse_text("", "foo", &d) == 0, "desktop-empty");
}

/* ===================== /proc/net 解码 ===================== */
static void test_procnet(void)
{
	struct ap_netinfo n;
	char line[512];

	snprintf(line, sizeof(line),
		 "  0: 0100007F:0016 00000000:0000 0A 00000000:00000000 "
		 "00:00000000 00000000 0 0 12345 1 0000000000000000 100 0 0 10 0");
	CHECK(ap_procnet_decode(line, "tcp", &n) == 0, "procnet-ok");
	CHECK(strcmp(n.local, "127.0.0.1:22") == 0, "procnet-local");
	CHECK(strcmp(n.remote, "0.0.0.0:0") == 0, "procnet-remote");
	CHECK(strcmp(n.state, "LISTEN") == 0, "procnet-state-listen");
	CHECK(strcmp(n.inode, "12345") == 0, "procnet-inode");

	snprintf(line, sizeof(line),
		 "  1: 0100007F:1F90 0200000A:C350 01 00000000:00000000 "
		 "00:00000000 00000000 0 0 777 1 0000000000000000 20 4 30 10 0");
	CHECK(ap_procnet_decode(line, "tcp", &n) == 0 &&
	      strcmp(n.remote, "10.0.0.2:50000") == 0 &&
	      strcmp(n.state, "ESTABLISHED") == 0, "procnet-established");

	snprintf(line, sizeof(line),
		 "  2: 00000000000000000000000001000000:0050 "
		 "00000000000000000000000000000000:0000 0A 0:0 00:0 "
		 "00000000 0 0 9 1 0 0 0 10 0");
	CHECK(ap_procnet_decode(line, "tcp6", &n) == 0 &&
	      strstr(n.local, "0000:0000:0000:0000:0000:0000:0000:0001") !=
	      NULL && strstr(n.local, ":80") != NULL, "procnet-ipv6");

	CHECK(ap_procnet_decode("sl  local_address rem_address st", "tcp",
				&n) == -1, "procnet-header-skip");
	CHECK(ap_procnet_decode("short line", "tcp", &n) == -1,
	      "procnet-short-skip");
}

/* ===================== 目标/参数白名单 ===================== */
static void test_allowlist(void)
{
	char err[256] = "";
	char *tar_ok[] = { (char *)"-tf", (char *)"/tmp/x.tar" };
	char *tar_help[] = { (char *)"--help" };
	char *tar_x[] = { (char *)"-xzf", (char *)"/tmp/x.tar" };
	char *tar_c[] = { (char *)"-cf", (char *)"/tmp/x.tar" };
	char *tar_del[] = { (char *)"--delete", (char *)"-f", (char *)"/tmp/x.tar" };
	char *curl_ok[] = { (char *)"--version" };
	char *curl_url[] = { (char *)"http://example.com" };
	char *curl_out[] = { (char *)"-o", (char *)"/tmp/x" };
	char *sort_out[] = { (char *)"-o", (char *)"/tmp/x" };
	char *date_set[] = { (char *)"-s", (char *)"2020-01-01" };
	char *bad_ctl[] = { (char *)"a\nb" };
	char *many[17];
	int i;

	CHECK(ap_target_allowed("/usr/bin/ls", err, sizeof(err)) == 0,
	      "target-ls-ok");
	CHECK(ap_target_allowed("/usr/bin/rm", err, sizeof(err)) != 0,
	      "target-rm-refuse");
	CHECK(ap_target_allowed("/tmp/ls", err, sizeof(err)) != 0,
	      "target-tmp-refuse");
	CHECK(ap_target_allowed("/usr/bin/../bin/ls", err, sizeof(err)) != 0,
	      "target-dotdot-refuse");
	CHECK(ap_target_allowed("usr/bin/ls", err, sizeof(err)) != 0,
	      "target-relative-refuse");

	CHECK(ap_arg_allowed("tar", tar_ok, 2, err, sizeof(err)) == 0,
	      "args-tar-list-ok");
	CHECK(ap_arg_allowed("tar", tar_help, 1, err, sizeof(err)) == 0,
	      "args-tar-help-ok");
	CHECK(ap_arg_allowed("tar", tar_x, 2, err, sizeof(err)) != 0,
	      "args-tar-extract-refuse");
	CHECK(ap_arg_allowed("tar", tar_c, 2, err, sizeof(err)) != 0,
	      "args-tar-create-refuse");
	CHECK(ap_arg_allowed("tar", tar_del, 3, err, sizeof(err)) != 0,
	      "args-tar-delete-refuse");
	CHECK(ap_arg_allowed("curl", curl_ok, 1, err, sizeof(err)) == 0,
	      "args-curl-version-ok");
	CHECK(ap_arg_allowed("curl", curl_url, 1, err, sizeof(err)) != 0,
	      "args-curl-url-refuse");
	CHECK(ap_arg_allowed("curl", curl_out, 2, err, sizeof(err)) != 0,
	      "args-curl-output-refuse");
	CHECK(ap_arg_allowed("sort", sort_out, 2, err, sizeof(err)) != 0,
	      "args-sort-output-refuse");
	CHECK(ap_arg_allowed("date", date_set, 2, err, sizeof(err)) != 0,
	      "args-date-set-refuse");
	CHECK(ap_arg_allowed("ls", bad_ctl, 1, err, sizeof(err)) != 0,
	      "args-control-refuse");
	for (i = 0; i < 17; i++)
		many[i] = (char *)"-l";
	CHECK(ap_arg_allowed("ls", many, 17, err, sizeof(err)) != 0,
	      "args-too-many-refuse");
}

/* ===================== strace 行解析 ===================== */
static void test_strace(void)
{
	struct ap_event e;
	int failed = 0;

	CHECK(ap_strace_line(
	    "1234 execve(\"/usr/bin/ls\", [\"ls\", \"-la\"], 0x7f /* 20 vars */) = 0",
	    &e, &failed) == 1 && e.type == AP_EV_PROC_EXEC &&
	    strcmp(e.path, "/usr/bin/ls") == 0, "strace-execve");

	CHECK(ap_strace_line(
	    "1234 openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY|O_CLOEXEC) = 3",
	    &e, &failed) == 1 && e.type == AP_EV_FILE_READ &&
	    strcmp(e.path, "/etc/passwd") == 0, "strace-open-read");

	CHECK(ap_strace_line(
	    "1234 openat(AT_FDCWD, \"/tmp/out\", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4",
	    &e, &failed) == 1 && e.type == AP_EV_FILE_WRITE &&
	    strcmp(e.path, "/tmp/out") == 0, "strace-open-write");

	CHECK(ap_strace_line(
	    "1234 openat(AT_FDCWD, \"/nope\", O_RDONLY) = -1 ENOENT (No such file or directory)",
	    &e, &failed) == -1 && failed == 1, "strace-open-fail-counted");

	CHECK(ap_strace_line(
	    "1234 connect(3, {sa_family=AF_INET, sin_port=htons(443), "
	    "sin_addr=inet_addr(\"1.2.3.4\")}, 16) = 0",
	    &e, &failed) == 1 && e.type == AP_EV_NET_CONNECT &&
	    strcmp(e.remote, "1.2.3.4:443") == 0, "strace-connect-inet");

	CHECK(ap_strace_line(
	    "1234 bind(3, {sa_family=AF_INET, sin_port=htons(8080), "
	    "sin_addr=inet_addr(\"0.0.0.0\")}, 16) = 0",
	    &e, &failed) == 1 && e.type == AP_EV_NET_LISTEN &&
	    strcmp(e.remote, "0.0.0.0:8080") == 0, "strace-bind-listen");

	CHECK(ap_strace_line(
	    "1234 connect(3, {sa_family=AF_UNIX, sun_path=\"/run/sock\"}, 110) = -1 ENOENT",
	    &e, &failed) == 0, "strace-unix-fail-skip");

	CHECK(ap_strace_line(
	    "1234 rename(\"/tmp/a\", \"/tmp/b\") = 0",
	    &e, &failed) == 1 && e.type == AP_EV_FILE_WRITE &&
	    strcmp(e.path, "/tmp/b") == 0, "strace-rename-dst");

	CHECK(ap_strace_line("1234 futex(0x7f, FUTEX_WAIT, 0, NULL) = 0",
			     &e, &failed) == 0, "strace-ignore-other");
}

static void test_event_dedupe(void)
{
	struct ap_event ev[8], e;
	int n = 0;

	memset(&e, 0, sizeof(e));
	e.type = AP_EV_FILE_READ;
	snprintf(e.path, sizeof(e.path), "/etc/passwd");
	CHECK(ap_event_add(ev, &n, 8, &e) == 1 && n == 1, "dedupe-first");
	e.pid = 42;
	CHECK(ap_event_add(ev, &n, 8, &e) == 0 && n == 1 &&
	      ev[0].count == 2 && ev[0].pid == 42, "dedupe-merge");
	memset(&e, 0, sizeof(e));
	e.type = AP_EV_FILE_WRITE;
	snprintf(e.path, sizeof(e.path), "/etc/passwd");
	CHECK(ap_event_add(ev, &n, 8, &e) == 1 && n == 2, "dedupe-type-split");
}

/* ===================== 真实静态画像 ===================== */
static int write_script(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	const char *body = "#!/bin/sh\necho w81c\n";

	if (fd < 0)
		return -1;
	if (write(fd, body, strlen(body)) != (ssize_t)strlen(body)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void test_static_real(void)
{
	char *out = NULL;
	int rc;

	tool_call("app_profile_static", "{\"path\":\"/usr/bin/ls\"}", &out,
		  &rc);
	CHECK(rc == 0 && out != NULL, "static-ls-ok");
	CHECK(out && strstr(out, "== 静态画像") != NULL, "static-ls-header");
	CHECK(out && strstr(out, "[ELF]") != NULL &&
	      strstr(out, "PIE=") != NULL && strstr(out, "NX=") != NULL &&
	      strstr(out, "RELRO=") != NULL, "static-ls-elf");
	CHECK(out && strstr(out, "libc.so.6") != NULL, "static-ls-needed");
	CHECK(out && strstr(out, "[符号]") != NULL, "static-ls-symbols");
	CHECK(out && strstr(out, "[要的]") != NULL, "static-ls-declared");
	if (!out || strstr(out, "coreutils") == NULL) {
		printf("---- static /usr/bin/ls output (package check) ----\n%s\n",
		       out ? out : "(null)");
		printf("---- end ----\n");
	}
	CHECK(out && strstr(out, "coreutils") != NULL, "static-ls-package");
	free(out);

	out = NULL;
	tool_call("app_profile_static",
		  "{\"path\":\"/usr/bin/ls\",\"format\":\"json\"}", &out, &rc);
	CHECK(rc == 0 && out != NULL &&
	      strstr(out, "\"tool\":\"app_profile_static\"") != NULL &&
	      strstr(out, "\"kind\":\"elf\"") != NULL &&
	      strstr(out, "\"needed\":[") != NULL &&
	      strstr(out, "\"declared\":[") != NULL, "static-ls-json");
	free(out);

	out = NULL;
	tool_call("app_profile_static", "{\"path\":\"/nonexistent/w81c-x\"}",
		  &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ERROR") != NULL &&
	      strstr(out, "不存在") != NULL, "static-missing-honest");
	free(out);

	out = NULL;
	tool_call("app_profile_static", "{\"path\":\"/tmp\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "目录") != NULL,
	      "static-dir-honest");
	free(out);

	{
		char path[128];

		snprintf(path, sizeof(path), "/tmp/w81c-script-%d.sh",
			 (int)getpid());
		if (write_script(path) == 0) {
			char args[256];

			snprintf(args, sizeof(args), "{\"path\":\"%s\"}", path);
			out = NULL;
			tool_call("app_profile_static", args, &out, &rc);
			CHECK(rc == 0 && out &&
			      strstr(out, "脚本") != NULL &&
			      strstr(out, "/bin/sh") != NULL,
			      "static-script-honest");
			free(out);
			unlink(path);
		} else {
			SKIP("static-script-honest", "无法创建临时脚本");
		}
	}

	out = NULL;
	tool_call("app_profile_static", "{}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "缺少 path") != NULL,
	      "static-missing-arg");
	free(out);
}

/* ===================== 动态画像闸门（非 root） ===================== */
static void test_dynamic_gates(void)
{
	char *out = NULL;
	int rc;

	if (geteuid() == 0) {
		SKIP("dynamic-gates", "root 下会真建工作区，交给 --live");
		return;
	}
	tool_call("app_profile_dynamic", "{\"path\":\"/usr/bin/rm\"}", &out,
		  &rc);
	CHECK(rc != 0 && out && strstr(out, "白名单") != NULL,
	      "dynamic-rm-refuse");
	free(out);

	out = NULL;
	tool_call("app_profile_dynamic",
		  "{\"path\":\"/usr/bin/curl\",\"args\":[\"http://x\"]}",
		  &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "参数被白名单拒绝") != NULL,
	      "dynamic-curl-url-refuse");
	free(out);

	out = NULL;
	tool_call("app_profile_dynamic",
		  "{\"path\":\"/usr/bin/tar\",\"args\":[\"-xzf\",\"/tmp/x\"]}",
		  &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "参数被白名单拒绝") != NULL,
	      "dynamic-tar-extract-refuse");
	free(out);

	out = NULL;
	tool_call("app_profile_dynamic", "{}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "缺少 path") != NULL,
	      "dynamic-missing-arg");
	free(out);

	out = NULL;
	tool_call("app_profile_dynamic", "{\"path\":\"/usr/bin/ls\"}", &out,
		  &rc);
	CHECK(rc != 0 && out != NULL &&
	      (strstr(out, "无法准备工作区") != NULL ||
	       strstr(out, "工作区") != NULL), "dynamic-nonroot-honest");
	free(out);
}

/* ===================== 差集报告 ===================== */
static const char *DYN_FIXTURE_JSON =
"{\"tool\":\"app_profile_dynamic\",\"path\":\"/usr/bin/ls\",\"events\":["
"{\"type\":\"file_read\",\"path\":\"/usr/lib/x86_64-linux-gnu/libc.so.6\"},"
"{\"type\":\"file_read\",\"path\":\"/usr/lib/x86_64-linux-gnu/libselinux.so.1\"},"
"{\"type\":\"file_read\",\"path\":\"/etc/ld.so.cache\"},"
"{\"type\":\"file_read\",\"path\":\"/etc/passwd\"},"
"{\"type\":\"file_write\",\"path\":\"/tmp/w81c-escape.txt\"},"
"{\"type\":\"proc_exec\",\"path\":\"/bin/sh\"},"
"{\"type\":\"net_connect\",\"proto\":\"tcp\",\"remote\":\"1.2.3.4:443\","
"\"state\":\"ESTABLISHED\"},"
"{\"type\":\"net_listen\",\"proto\":\"tcp\",\"local\":\"0.0.0.0:8080\","
"\"remote\":\"0.0.0.0:8080\",\"state\":\"LISTEN\"}]}";

static int score_of(const char *text)
{
	const char *p = strstr(text, "[风险分] ");

	if (!p)
		return -1;
	return atoi(p + strlen("[风险分] "));
}

static void test_diff(void)
{
	char *out = NULL;
	char *esc = ai_json_escape(DYN_FIXTURE_JSON);
	char args[4096];
	int rc;

	snprintf(args, sizeof(args),
		 "{\"path\":\"/usr/bin/ls\",\"dynamic\":\"%s\"}",
		 esc ? esc : "");
	tool_call("app_profile_diff", args, &out, &rc);
	CHECK(rc == 0 && out != NULL, "diff-ok");
	CHECK(out && strstr(out, "[一、要的") != NULL &&
	      strstr(out, "[二、用的") != NULL &&
	      strstr(out, "[三、偷偷碰的") != NULL, "diff-three-columns");
	CHECK(out && strstr(out, "/etc/passwd") != NULL, "diff-etc-passwd");
	CHECK(out && strstr(out, "net tcp 1.2.3.4:443") != NULL,
	      "diff-net-target");
	CHECK(out && strstr(out, "/tmp/w81c-escape.txt") != NULL,
	      "diff-write-path");
	CHECK(out && strstr(out, "/bin/sh") != NULL, "diff-child-exec");
	CHECK(out && score_of(out) > 0, "diff-score-positive");
	CHECK(out && strstr(out, "放行条件建议") != NULL &&
	      strstr(out, "nft_intent_compile") != NULL, "diff-conditions");
	CHECK(out && strstr(out, "不执行任何策略") != NULL,
	      "diff-read-only");
	free(out);

	out = NULL;
	snprintf(args, sizeof(args),
		 "{\"path\":\"/usr/bin/ls\",\"dynamic\":\"%s\","
		 "\"format\":\"json\"}", esc ? esc : "");
	tool_call("app_profile_diff", args, &out, &rc);
	CHECK(rc == 0 && out &&
	      strstr(out, "\"tool\":\"app_profile_diff\"") != NULL &&
	      strstr(out, "\"unexpected\":[") != NULL &&
	      strstr(out, "\"risk_score\":") != NULL, "diff-json");
	free(out);

	out = NULL;
	tool_call("app_profile_diff",
		  "{\"path\":\"/usr/bin/ls\",\"dynamic\":\"not json\"}",
		  &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "ERROR") != NULL, "diff-bad-json");
	free(out);

	out = NULL;
	tool_call("app_profile_diff",
		  "{\"path\":\"/usr/bin/ls\",\"dynamic\":\"{\\\"tool\\\":\\\""
		  "app_profile_static\\\",\\\"declared\\\":[]}\"}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "静态画像") != NULL,
	      "diff-static-as-dynamic-refuse");
	free(out);

	out = NULL;
	tool_call("app_profile_diff",
		  "{\"path\":\"/usr/bin/ls\",\"dynamic\":"
		  "\"{\\\"events\\\":[]}\"}", &out, &rc);
	CHECK(rc == 0 && out && score_of(out) == 0 &&
	      strstr(out, "可按 D0/D1 放行") != NULL, "diff-empty-zero");
	free(out);

	out = NULL;
	tool_call("app_profile_diff", "{\"path\":\"/usr/bin/ls\"}", &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "缺少 dynamic") != NULL,
	      "diff-missing-arg");
	free(out);
	free(esc);
}

/* ===================== 注册表接线 ===================== */
static void test_registry(void)
{
	struct tool_registry reg;
	char *err = NULL;
	const struct ai_tool *t;

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	if (tool_registry_load(&reg, &err) != 0) {
		printf("FAIL registry-load: %s\n", err ? err : "?");
		fails++;
		free(err);
		return;
	}
	CHECK(reg.tool_count == 206, "registry-206");
	t = tool_registry_find(&reg, "app_profile_static");
	CHECK(t && t->channel == TOOL_CH_APPPROFILE && t->risk &&
	      strcmp(t->risk, TOOL_RISK_R) == 0, "registry-static-R");
	t = tool_registry_find(&reg, "app_profile_dynamic");
	CHECK(t && t->channel == TOOL_CH_APPPROFILE && t->risk &&
	      strcmp(t->risk, TOOL_RISK_W2) == 0, "registry-dynamic-W2");
	t = tool_registry_find(&reg, "app_profile_diff");
	CHECK(t && t->channel == TOOL_CH_APPPROFILE && t->risk &&
	      strcmp(t->risk, TOOL_RISK_W1) == 0, "registry-diff-W1");
	CHECK(tool_channel_from_str("appprofile") == TOOL_CH_APPPROFILE,
	      "registry-channel-str");
	tool_registry_free(&reg);
}

/* ===================== live / evidence ===================== */
static int dump_file(const char *dir, const char *name, const char *text)
{
	char path[1024];
	FILE *fp;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fp = fopen(path, "w");
	if (!fp)
		return -1;
	if (text)
		fputs(text, fp);
	fclose(fp);
	return 0;
}

static int run_dynamic(const char *path, const char *args_json,
		       char **out, int *rc)
{
	char args[1024];

	snprintf(args, sizeof(args),
		 "{\"path\":\"%s\",\"args\":%s,\"format\":\"json\"}",
		 path, args_json);
	return tool_call("app_profile_dynamic", args, out, rc);
}

static int run_live(const char *emit_dir)
{
	char *dyn_ls = NULL, *dyn_curl = NULL, *out = NULL, *diff = NULL;
	char *static_txt = NULL, *static_json = NULL;
	int rc;

	if (geteuid() != 0) {
		printf("REFUSE: --live 需要 root（workspace 需要 loop/mkfs）\n");
		return 2;
	}

	tool_call("app_profile_static",
		  "{\"path\":\"/usr/bin/curl\",\"format\":\"text\"}", &out, &rc);
	if (rc != 0) {
		printf("FAIL live-static-curl: %s\n", out ? out : "?");
		free(out);
		return 2;
	}
	CHECK(strstr(out, "libcurl.so") != NULL, "live-static-curl-libcurl");
	static_txt = strdup(out);
	free(out);
	out = NULL;

	tool_call("app_profile_static",
		  "{\"path\":\"/usr/bin/curl\",\"format\":\"json\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"declared\":[") != NULL,
	      "live-static-curl-json");
	static_json = out ? strdup(out) : NULL;
	free(out);
	out = NULL;

	rc = run_dynamic("/usr/bin/ls", "[\"-la\",\"/usr\"]", &dyn_ls, &rc);
	CHECK(rc == 0 && dyn_ls != NULL, "live-dynamic-ls-ok");
	CHECK(dyn_ls && strstr(dyn_ls, "\"tool\":\"app_profile_dynamic\"") != NULL,
	      "live-dynamic-ls-json");
	CHECK(dyn_ls && strstr(dyn_ls, "\"events\":[") != NULL &&
	      strstr(dyn_ls, "libc.so.6") != NULL, "live-dynamic-ls-events");
	CHECK(dyn_ls && strstr(dyn_ls, "\"type\":\"proc_exec\"") != NULL,
	      "live-dynamic-ls-exec");
	CHECK(dyn_ls && strstr(dyn_ls, "nsswitch.conf") != NULL &&
	      strstr(dyn_ls, "proc/filesystems") != NULL,
	      "live-dynamic-ls-nss");

	rc = run_dynamic("/usr/bin/curl", "[\"--version\"]", &dyn_curl, &rc);
	CHECK(rc == 0 && dyn_curl && strstr(dyn_curl, "libcurl.so") != NULL,
	      "live-dynamic-curl-libs");

	{
		char *esc = ai_json_escape(dyn_ls ? dyn_ls : "");
		size_t need = (esc ? strlen(esc) : 0) + 128;
		char *dargs = malloc(need);

		if (dargs) {
			snprintf(dargs, need,
				 "{\"path\":\"/usr/bin/ls\",\"dynamic\":\"%s\"}",
				 esc ? esc : "");
			tool_call("app_profile_diff", dargs, &diff, &rc);
			free(dargs);
		}
		free(esc);
	}
	CHECK(rc == 0 && diff && strstr(diff, "[三、偷偷碰的") != NULL,
	      "live-diff-three-columns");
	CHECK(diff && strstr(diff, "/etc/nsswitch.conf") != NULL,
	      "live-diff-finds-nss");
	CHECK(diff && score_of(diff) > 0, "live-diff-score");

	if (emit_dir && emit_dir[0]) {
		char errout[4096];
		char *eout = NULL;
		int erc;

		dump_file(emit_dir, "01-static-curl.txt",
			  static_txt ? static_txt : "");
		dump_file(emit_dir, "02-static-curl.json",
			  static_json ? static_json : "");
		dump_file(emit_dir, "03-dynamic-ls.json", dyn_ls ? dyn_ls : "");
		dump_file(emit_dir, "03b-dynamic-curl.json",
			  dyn_curl ? dyn_curl : "");
		dump_file(emit_dir, "04-diff-ls.txt", diff ? diff : "");

		{
			char *cesc = ai_json_escape(dyn_curl ? dyn_curl : "");
			size_t cneed = (cesc ? strlen(cesc) : 0) + 128;
			char *cargs = malloc(cneed);
			char *cdiff = NULL;

			if (cargs) {
				snprintf(cargs, cneed,
					 "{\"path\":\"/usr/bin/curl\","
					 "\"dynamic\":\"%s\"}",
					 cesc ? cesc : "");
				tool_call("app_profile_diff", cargs, &cdiff,
					  &rc);
				dump_file(emit_dir, "04b-diff-curl.txt",
					  cdiff ? cdiff : "");
				free(cdiff);
				free(cargs);
			}
			free(cesc);
		}

		errout[0] = '\0';
		strncat(errout, "===== 非 ELF（临时 shell 脚本）=====\n",
			sizeof(errout) - strlen(errout) - 1);
		{
			char sp[128], sargs[256];

			snprintf(sp, sizeof(sp), "/tmp/w81c-ev-%d.sh",
				 (int)getpid());
			if (write_script(sp) == 0) {
				snprintf(sargs, sizeof(sargs),
					 "{\"path\":\"%s\"}", sp);
				tool_call("app_profile_static", sargs, &eout,
					  &erc);
				if (eout)
					strncat(errout, eout,
						sizeof(errout) -
						strlen(errout) - 1);
				free(eout);
				unlink(sp);
			}
		}
		strncat(errout, "\n===== 不存在的路径 =====\n",
			sizeof(errout) - strlen(errout) - 1);
		eout = NULL;
		tool_call("app_profile_static",
			  "{\"path\":\"/nonexistent/w81c-evil\"}", &eout,
			  &erc);
		if (eout)
			strncat(errout, eout,
				sizeof(errout) - strlen(errout) - 1);
		free(eout);
		strncat(errout, "\n===== 动态白名单拒绝（rm）=====\n",
			sizeof(errout) - strlen(errout) - 1);
		eout = NULL;
		tool_call("app_profile_dynamic", "{\"path\":\"/usr/bin/rm\"}",
			  &eout, &erc);
		if (eout)
			strncat(errout, eout,
				sizeof(errout) - strlen(errout) - 1);
		free(eout);
		strncat(errout, "\n===== 动态参数拒绝（tar -xzf）=====\n",
			sizeof(errout) - strlen(errout) - 1);
		eout = NULL;
		tool_call("app_profile_dynamic",
			  "{\"path\":\"/usr/bin/tar\",\"args\":[\"-xzf\","
			  "\"/tmp/x.tar\"]}", &eout, &erc);
		if (eout)
			strncat(errout, eout,
				sizeof(errout) - strlen(errout) - 1);
		free(eout);
		dump_file(emit_dir, "05-errors.txt", errout);
	}

	free(static_txt);
	free(static_json);
	free(dyn_ls);
	free(dyn_curl);
	free(diff);
	ai_ws_destroy("appprofile", NULL);
	return 0;
}

int main(int argc, char **argv)
{
	int live = 0;
	const char *emit = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0)
			live = 1;
		else if (strcmp(argv[i], "--emit") == 0 && i + 1 < argc)
			emit = argv[++i];
	}

	printf("== test_app_profile (uid=%u, live=%d) ==\n",
	       (unsigned)geteuid(), live);
	test_elf_enums();
	test_dyn_parse();
	test_dynsym_parse();
	test_dpkg_parse();
	test_desktop_parse();
	test_procnet();
	test_allowlist();
	test_strace();
	test_event_dedupe();
	test_static_real();
	test_dynamic_gates();
	test_diff();
	test_registry();

	if (live || emit) {
		if (run_live(emit) != 0)
			return 2;
	} else {
		printf("（未跑 live：workspace 真执行用 --live；证据用 "
		       "--live --emit DIR）\n");
	}
	if (fails) {
		printf("FAILURES: %d (checks=%d skips=%d)\n", fails, checks,
		       skips);
		return 1;
	}
	printf("ALL PASS (checks=%d skips=%d)\n", checks, skips);
	return 0;
}
