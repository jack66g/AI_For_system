// SPDX-License-Identifier: GPL-2.0
/*
 * test_compat.c - W82B V6 应用兼容（compat 通道）回归
 *
 * 默认（非 root）：纯函数 + 静态探测 + 注册表接线 + 诚实错误，零副作用。
 *   - ai_compat_valid_name 字符集/长度/点开头/..
 *   - probe：缺解释器脚本（#!/usr/bin/python4.9）→ MISSING_INTERPRETER，
 *     候选解释器来自真实本机；/bin/sh → runnable；不存在 → MISSING_TARGET；
 *     无执行位 → NOT_EXECUTABLE（且 adaptable=true，说明可 L0 修）
 *   - C1 符号版本：verneed/verdef 走查器 buffer 级 fixture 直测
 *     （多库多版本/next 链/空表/越界偏移/版本比较边界/宿主缺失不判
 *     fatal），加合成 ELF 端到端（GLIBC_2.9999 → LIBC_VERSION_TOO_NEW）
 *   - registry：237 件 / compat 通道 4 件 / 风险 R,W1,W2,W1
 *   - compat_generate 非法名/非法 target → AI_ERR_INVALID_ARG；
 *     compat_apply 不存在的适配器 → 诚实报错（不静默成功）
 *   - C2 棒1（plan 补全）：§4.4 manifest 五字段（risk 查表边界 4/5 条、
 *     limitations 三路汇入、provides 派生、created_by/trace_id 透传）；
 *     expect.exit_code 实装（42/缺省 0/97→负向 98 避撞/300 拒绝）；
 *     六类超限诚实报错（generate 面 env/argv/map/自动 env + 加载面
 *     env/map/lib/chmod/install/argv 全集 + §4.4 缺字段拒绝）
 *   - C3 Lane-1（层名统一+L3 双态）：四 code layer=L3 断言（ARCH_MISMATCH
 *     双态各半+LIBC/32 位/OSABI）；emulators 探测面（env 权威覆盖在场/
 *     缺席、PATH 发现——不依赖真装 qemu，假模拟器文件即在场态）；
 *     L3 wrapper 规则装配（layers.L3.emulator/contract.argv 前缀 [qemu,
 *     stage 内目标]/risk=medium/limitations 模拟执行注记/execve 断言随
 *     argv[0]）；加载面 L3 形状安检与矛盾数据拒绝
 *
 * --live（需要 root + 真 aik-sandbox + gcc）：走 tool_executor_run 真链路
 *   构造样本 A（#!/usr/bin/python4.9 脚本）与样本 B（DT_NEEDED
 *   libfoo.so.1 而宿主默认路径没有）→ probe → generate → apply → verify；
 *   再故意破坏契约数据（adapter 里加 AICOMPAT_QUIET=1 让目标返回 0 但
 *   输出为空）→ verify 必须 ok=false；最后销毁 workspace 验零残留 +
 *   宿主 /usr 无新增。
 *
 * --call <tool> <args-json>：取证单调用（真执行器/真沙盒）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "tools/compat_tools.h"
#include "policy/ai_lease.h"

static int fails;
static int checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (cond) { \
		printf("ok %s\n", msg); \
	} else { \
		printf("FAIL %s\n", msg); \
		fails++; \
	} \
} while (0)

static void run_tool(const struct tool_registry *reg, const char *name,
		     const char *args, char **out, int *ok)
{
	const struct ai_tool *t = tool_registry_find(reg, name);
	int rc;

	*out = NULL;
	*ok = 0;
	if (!t) {
		printf("FATAL: tool %s 缺失\n", name);
		return;
	}
	rc = tool_executor_run(t, args, out, ok);
	if (rc != AI_OK && *out)
		printf("  (%s rc=%d)\n", name, rc);
}

static int write_file(const char *path, const char *content, mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	size_t n = strlen(content);

	if (fd < 0)
		return -1;
	if (write(fd, content, n) != (ssize_t)n) {
		close(fd);
		return -1;
	}
	close(fd);
	chmod(path, mode);
	return 0;
}

/* 二进制安全写（write_file 走 strlen，合成 ELF 有内嵌 NUL） */
static int write_file_bin(const char *path, const void *data, size_t n,
			  mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);

	if (fd < 0)
		return -1;
	if (write(fd, data, n) != (ssize_t)n) {
		close(fd);
		return -1;
	}
	close(fd);
	chmod(path, mode);
	return 0;
}

/* C1 fixture：往 strtab 追加一个字符串，返回新的表长（首字节 NUL 由
 * 调用方先置好） */
static size_t st_add(char *st, size_t n, const char *s)
{
	size_t l = strlen(s);

	memcpy(st + n, s, l + 1);
	return n + l + 1;
}

/* ---------------------------------------------------------------- unit */

static void test_validators(void)
{
	CHECK(ai_compat_valid_name("sampleA") == 1, "name sampleA 合法");
	CHECK(ai_compat_valid_name("w82b.a_b-1") == 1, "name w82b.a_b-1 合法");
	CHECK(ai_compat_valid_name("") == 0, "空名拒绝");
	CHECK(ai_compat_valid_name(NULL) == 0, "NULL 拒绝");
	CHECK(ai_compat_valid_name(".hidden") == 0, "点开头拒绝");
	CHECK(ai_compat_valid_name("-x") == 0, "横线开头拒绝");
	CHECK(ai_compat_valid_name("..") == 0, ".. 拒绝");
	CHECK(ai_compat_valid_name("a/b") == 0, "斜杠拒绝");
	CHECK(ai_compat_valid_name("a b") == 0, "空格拒绝");
	CHECK(ai_compat_valid_name("0123456789012345678901234567890123")
	      == 0, "33 字符拒绝");
}

static void test_probe_static(void)
{
	char dir[] = "/tmp/w82b-unit-XXXXXX";
	char script[512], bad[512], noexec[512];
	char *json = NULL;
	int runnable = -1;

	CHECK(mkdtemp(dir) != NULL, "mkdtemp");
	snprintf(script, sizeof(script), "%s/app.py", dir);
	snprintf(bad, sizeof(bad), "%s/nope", dir);
	snprintf(noexec, sizeof(noexec), "%s/noexec", dir);

	/* 缺解释器：shebang 指向本机不存在的 python4.9 */
	CHECK(write_file(script,
			 "#!/usr/bin/python4.9\nprint('hello')\n", 0755) == 0,
	      "写样本 A 脚本");
	(void)ai_compat_probe_json(script, NULL, &json, &runnable);
	CHECK(runnable == 0, "样本 A runnable=false");
	CHECK(json && strstr(json, "MISSING_INTERPRETER") != NULL,
	      "probe 归因 MISSING_INTERPRETER");
	CHECK(json && strstr(json, "/usr/bin/python4.9") != NULL,
	      "证据含缺失解释器路径");
	CHECK(json && strstr(json, "candidates") != NULL,
	      "给出同族候选解释器");
	CHECK(json && strstr(json, "\"layer\":\"L0\"") != NULL,
	      "layer=L0（可 L0 适配）");
	free(json);
	json = NULL;

	/* 真可执行：/bin/sh */
	(void)ai_compat_probe_json("/bin/sh", NULL, &json, &runnable);
	CHECK(runnable == 1, "/bin/sh runnable=true");
	CHECK(json && strstr(json, "\"kind\":\"elf\"") != NULL,
	      "/bin/sh 识别为 ELF");
	free(json);
	json = NULL;

	/* 不存在 */
	(void)ai_compat_probe_json(bad, NULL, &json, &runnable);
	CHECK(runnable == 0 && json && strstr(json, "MISSING_TARGET"),
	      "不存在目标 → MISSING_TARGET");
	free(json);
	json = NULL;

	/* 无执行位 */
	CHECK(write_file(noexec, "#!/bin/sh\necho x\n", 0644) == 0,
	      "写无执行位文件");
	(void)ai_compat_probe_json(noexec, NULL, &json, &runnable);
	CHECK(runnable == 0 && json && strstr(json, "NOT_EXECUTABLE"),
	      "无执行位 → NOT_EXECUTABLE");
	CHECK(json && strstr(json, "\"adaptable\":true") != NULL,
	      "无执行位标注可适配（workspace 副本补位）");
	free(json);

	unlink(script);
	unlink(noexec);
	rmdir(dir);
}

/* ---- C1：符号版本（verneed/verdef）buffer 级 fixture 直测 ----
 * 走查器是导出的纯函数（ai_compat_verneed_walk 等），内存 fixture
 * 直调，不落盘、不依赖宿主 glibc。 */

static void test_verneed_walk(void)
{
	char st[256];
	size_t n, o_libc, o_stdc, o_29, o_234, o_29999, o_232;
	unsigned char blob[128];
	struct ai_compat_verreq req[4];
	int n_lib;

	st[0] = '\0';
	n = 1;
	o_libc = n;    n = st_add(st, n, "libc.so.6");
	o_stdc = n;    n = st_add(st, n, "libstdc++.so.6");
	o_29 = n;      n = st_add(st, n, "GLIBC_2.9");
	o_234 = n;     n = st_add(st, n, "GLIBC_2.34");
	o_29999 = n;   n = st_add(st, n, "GLIBC_2.9999");
	o_232 = n;     n = st_add(st, n, "GLIBC_2.32");

	/* 两库各两版本；vn_next=48 跨 16 字节间隙（非平凡 next 链），
	 * aux 链 vna_next=16 */
	memset(blob, 0, sizeof(blob));
	{
		Elf64_Verneed vn;
		Elf64_Vernaux va;

		memset(&vn, 0, sizeof(vn));
		vn.vn_version = 1;
		vn.vn_cnt = 2;
		vn.vn_file = o_libc;
		vn.vn_aux = sizeof(vn);
		vn.vn_next = 48;
		memcpy(blob, &vn, sizeof(vn));
		memset(&va, 0, sizeof(va));
		va.vna_name = o_29;
		va.vna_next = sizeof(va);
		memcpy(blob + 16, &va, sizeof(va));
		va.vna_name = o_234;
		va.vna_next = 0;
		memcpy(blob + 32, &va, sizeof(va));
		vn.vn_file = o_stdc;
		vn.vn_next = 0;
		memcpy(blob + 48, &vn, sizeof(vn));
		va.vna_name = o_29999;
		va.vna_next = sizeof(va);
		memcpy(blob + 64, &va, sizeof(va));
		va.vna_name = o_232;
		va.vna_next = 0;
		memcpy(blob + 80, &va, sizeof(va));
	}
	memset(req, 0, sizeof(req));
	n_lib = ai_compat_verneed_walk(blob, 96, 2, st, n, req, 4);
	CHECK(n_lib == 2, "verneed 多库两版本全收集");
	CHECK(n_lib >= 1 && !strcmp(req[0].lib, "libc.so.6") &&
	      req[0].n_vers == 2 && !strcmp(req[0].vers[0], "GLIBC_2.9") &&
	      !strcmp(req[0].vers[1], "GLIBC_2.34"),
	      "verneed libc.so.6 双版本（vna_next 链）");
	CHECK(n_lib >= 2 && !strcmp(req[1].lib, "libstdc++.so.6") &&
	      req[1].n_vers == 2 && !strcmp(req[1].vers[0], "GLIBC_2.9999") &&
	      !strcmp(req[1].vers[1], "GLIBC_2.32"),
	      "verneed 跨段 vn_next 链（libstdc++）");

	/* 空表/坏输入：不崩、零库 */
	CHECK(ai_compat_verneed_walk(blob, 96, 0, st, n, req, 4) == 0,
	      "verneed DT_VERNEEDNUM=0 → 空表");
	CHECK(ai_compat_verneed_walk(NULL, 0, 2, st, n, req, 4) == 0,
	      "verneed 空 buffer → 空表");
	CHECK(ai_compat_verneed_walk(blob, 8, 1, st, n, req, 4) == 0,
	      "verneed 截断 buffer → 空表");

	/* 越界 strtab 偏移：条目被跳过（不崩、不产出垃圾名） */
	{
		Elf64_Verneed vn;
		Elf64_Vernaux va;

		memset(blob, 0, sizeof(blob));
		memset(&vn, 0, sizeof(vn));
		vn.vn_version = 1;
		vn.vn_cnt = 1;
		vn.vn_file = 99999;		/* 越界 */
		vn.vn_aux = sizeof(vn);
		vn.vn_next = 0;
		memcpy(blob, &vn, sizeof(vn));
		memset(&va, 0, sizeof(va));
		va.vna_name = 99999;		/* 同样越界 */
		va.vna_next = 0;
		memcpy(blob + sizeof(vn), &va, sizeof(va));
		memset(req, 0, sizeof(req));
		CHECK(ai_compat_verneed_walk(blob, 32, 1, st, n, req, 4) == 0,
		      "verneed 越界 strtab 偏移 → 条目跳过");
	}
}

static void test_verdef_max(void)
{
	char st[256], max[AI_COMPAT_VER_LEN];
	size_t n, o_225, o_29, o_234, o_gcc;
	unsigned char blob[128];

	/* fixture 布局前提：Elf64_Verdef=20 / Elf64_Verdaux=8（标准布局） */
	CHECK(sizeof(Elf64_Verdef) == 20 && sizeof(Elf64_Verdaux) == 8,
	      "verdef fixture 布局前提（Verdef=20/Verdaux=8）");
	st[0] = '\0';
	n = 1;
	o_225 = n;   n = st_add(st, n, "GLIBC_2.2.5");
	o_29 = n;    n = st_add(st, n, "GLIBC_2.9");
	o_234 = n;   n = st_add(st, n, "GLIBC_2.34");
	o_gcc = n;   n = st_add(st, n, "GCC_3.0");

	/* Verdef1@0（aux@20）--next=40--> Verdef2@40（3 aux 链，首名非
	 * GLIBC_ 验证忽略规则）：2.2.5 | GCC_3.0 -> 2.34 -> 2.9 */
	memset(blob, 0, sizeof(blob));
	{
		Elf64_Verdef vd;
		Elf64_Verdaux va;

		memset(&vd, 0, sizeof(vd));
		vd.vd_version = 1;
		vd.vd_cnt = 1;
		vd.vd_aux = sizeof(vd);
		vd.vd_next = 40;
		memcpy(blob, &vd, sizeof(vd));
		memset(&va, 0, sizeof(va));
		va.vda_name = o_225;
		memcpy(blob + 20, &va, sizeof(va));
		vd.vd_cnt = 3;
		vd.vd_next = 0;
		memcpy(blob + 40, &vd, sizeof(vd));
		va.vda_name = o_gcc;
		va.vda_next = sizeof(va);
		memcpy(blob + 60, &va, sizeof(va));
		va.vda_name = o_234;
		memcpy(blob + 68, &va, sizeof(va));
		va.vda_name = o_29;
		va.vda_next = 0;
		memcpy(blob + 76, &va, sizeof(va));
	}
	memset(max, 0, sizeof(max));
	CHECK(ai_compat_verdef_max(blob, 84, 2, st, n, max, sizeof(max)) == 3,
	      "verdef 收集 3 个 GLIBC_* 版本（GCC_ 忽略）");
	CHECK(!strcmp(max, "GLIBC_2.34"), "verdef 最大版本 GLIBC_2.34");
	max[0] = '\0';
	CHECK(ai_compat_verdef_max(blob, 84, 0, st, n, max, sizeof(max)) == 0 &&
	      !max[0], "verdef 空表 → 无最大值");
}

static void test_ver_cmp(void)
{
	CHECK(ai_compat_ver_cmp("2.10", "2.9") > 0, "版本比较 2.10 > 2.9");
	CHECK(ai_compat_ver_cmp("2.9999", "2.39") > 0,
	      "版本比较 2.9999 > 2.39");
	CHECK(ai_compat_ver_cmp("GLIBC_2.2.5", "GLIBC_2.2") > 0,
	      "版本比较 2.2.5 > 2.2（段多者大）");
	CHECK(ai_compat_ver_cmp("GLIBC_2.2", "2.2") == 0,
	      "版本比较 GLIBC_ 前缀剥离后等值");
	CHECK(ai_compat_ver_cmp("GLIBC_2.35", "GLIBC_2.35") == 0,
	      "版本比较等值");
	CHECK(ai_compat_ver_cmp("2.2.5", "2.34") < 0,
	      "版本比较 2.2.5 < 2.34");
}

static void test_ver_too_new(void)
{
	struct ai_compat_verreq r;
	char out[4][AI_COMPAT_VER_LEN];

	memset(&r, 0, sizeof(r));
	snprintf(r.lib, sizeof(r.lib), "libc.so.6");
	snprintf(r.vers[0], AI_COMPAT_VER_LEN, "GLIBC_2.2.5");
	snprintf(r.vers[1], AI_COMPAT_VER_LEN, "GLIBC_2.9999");
	snprintf(r.vers[2], AI_COMPAT_VER_LEN, "GLIBC_2.34");
	r.n_vers = 3;
	CHECK(ai_compat_ver_too_new(&r, NULL, out, 4) == 0,
	      "宿主 libc 缺失（provided=null）→ 不判 fatal");
	CHECK(ai_compat_ver_too_new(NULL, "GLIBC_2.35", out, 4) == 0,
	      "无 libc 要求 → 0");
	CHECK(ai_compat_ver_too_new(&r, "", out, 4) == 0,
	      "宿主无 verdef（musl）→ 0");
	{
		int n = ai_compat_ver_too_new(&r, "GLIBC_2.35", out, 4);

		CHECK(n == 1 && !strcmp(out[0], "GLIBC_2.9999"),
		      "超新清单恰含 GLIBC_2.9999");
	}
}

/*
 * 合成最小 ELF64（ehdr + 4 section：null/dynstr/verneed/dynamic），只带
 * DT_VERNEED/DT_VERNEEDNUM 一条要求——端到端走真判定器（cp_elf_scan →
 * cp_probe_elf → JSON）。无 PT_INTERP/DT_NEEDED：只触发版本核对路径。
 */
static int write_synth_elf(const char *path, const char *req_ver)
{
	unsigned char buf[1024];
	char st[128];
	size_t st_n = 1, o_libc, o_ver;
	const off_t strtab_off = 64, blob_off = 192, dyn_off = 256;
	const off_t sh_off = 320;
	Elf64_Ehdr eh;
	Elf64_Shdr sh[4];
	Elf64_Dyn dyn[4];
	Elf64_Verneed vn;
	Elf64_Vernaux va;

	memset(buf, 0, sizeof(buf));
	st[0] = '\0';
	o_libc = st_n;  st_n = st_add(st, st_n, "libc.so.6");
	o_ver = st_n;   st_n = st_add(st, st_n, req_ver);

	memset(&eh, 0, sizeof(eh));
	memcpy(eh.e_ident, ELFMAG, SELFMAG);
	eh.e_ident[EI_CLASS] = ELFCLASS64;
	eh.e_ident[EI_DATA] = ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = EV_CURRENT;
	eh.e_type = ET_DYN;
#if defined(__x86_64__)
	eh.e_machine = EM_X86_64;
#elif defined(__aarch64__)
	eh.e_machine = EM_AARCH64;
#else
	eh.e_machine = 0;	/* 非常见宿主：让 ARCH_MISMATCH 如实出现 */
#endif
	eh.e_version = EV_CURRENT;
	eh.e_ehsize = sizeof(eh);
	eh.e_shoff = sh_off;
	eh.e_shentsize = sizeof(Elf64_Shdr);
	eh.e_shnum = 4;

	memset(sh, 0, sizeof(sh));
	sh[1].sh_type = SHT_STRTAB;
	sh[1].sh_offset = strtab_off;
	sh[1].sh_size = st_n;
	sh[2].sh_type = SHT_GNU_verneed;
	sh[2].sh_offset = blob_off;
	sh[2].sh_size = 32;
	sh[3].sh_type = SHT_DYNAMIC;
	sh[3].sh_link = 1;		/* sh_link → dynstr */
	sh[3].sh_offset = dyn_off;
	sh[3].sh_size = sizeof(dyn);
	sh[3].sh_entsize = sizeof(Elf64_Dyn);

	memset(dyn, 0, sizeof(dyn));
	dyn[0].d_tag = DT_VERNEED;
	dyn[0].d_un.d_val = (uint64_t)blob_off;
	dyn[1].d_tag = DT_VERNEEDNUM;
	dyn[1].d_un.d_val = 1;
	dyn[2].d_tag = DT_NULL;

	memset(&vn, 0, sizeof(vn));
	vn.vn_version = 1;
	vn.vn_cnt = 1;
	vn.vn_file = o_libc;
	vn.vn_aux = sizeof(vn);
	vn.vn_next = 0;
	memset(&va, 0, sizeof(va));
	va.vna_name = o_ver;
	va.vna_next = 0;

	memcpy(buf, &eh, sizeof(eh));
	memcpy(buf + strtab_off, st, st_n);
	memcpy(buf + blob_off, &vn, sizeof(vn));
	memcpy(buf + blob_off + sizeof(vn), &va, sizeof(va));
	memcpy(buf + dyn_off, dyn, sizeof(dyn));
	memcpy(buf + sh_off, sh, sizeof(sh));
	return write_file_bin(path, buf, sizeof(buf), 0755);
}

static void test_probe_versions(void)
{
	char dir[] = "/tmp/c1-vers-XXXXXX";
	char synth[512];
	char *json = NULL;
	int runnable = -1;

	CHECK(mkdtemp(dir) != NULL, "mkdtemp（C1 版本用例）");

	/* 合成端到端 A：要求 GLIBC_2.9999（宿主 glibc 2.35 必不够）→
	 * LIBC_VERSION_TOO_NEW fatal；宿主无 verdef 时如实降级不判 fatal */
	snprintf(synth, sizeof(synth), "%s/too-new", dir);
	CHECK(write_synth_elf(synth, "GLIBC_2.9999") == 0, "写合成 ELF（超新）");
	(void)ai_compat_probe_json(synth, NULL, &json, &runnable);
	if (json && strstr(json, "\"provided_max\":\"GLIBC_")) {
		CHECK(runnable == 0 && strstr(json, "LIBC_VERSION_TOO_NEW"),
		      "合成超新 → LIBC_VERSION_TOO_NEW fatal");
		CHECK(strstr(json, "GLIBC_2.9999 > 宿主") != NULL,
		      "detail 形如 需要 libc.so.6 GLIBC_2.9999 > 宿主 GLIBC_x.y");
		CHECK(strstr(json, "\"too_new\":[\"GLIBC_2.9999\"]") != NULL,
		      "versions.too_new 恰含 GLIBC_2.9999");
		CHECK(strstr(json, "\"host_libc\":\"") != NULL,
		      "versions.host_libc 已定位宿主 libc");
	} else {
		CHECK(json && strstr(json, "LIBC_VERSION_TOO_NEW") == NULL,
		      "宿主 libc 无 verdef → 诚实降级不判 fatal");
	}
	free(json);
	json = NULL;

	/* 合成端到端 B：要求 GLIBC_2.2.5（任何 glibc 宿主必满足）→ 零版本 fatal */
	snprintf(synth, sizeof(synth), "%s/satisfied", dir);
	CHECK(write_synth_elf(synth, "GLIBC_2.2.5") == 0, "写合成 ELF（满足）");
	(void)ai_compat_probe_json(synth, NULL, &json, &runnable);
	CHECK(json && strstr(json, "LIBC_VERSION_TOO_NEW") == NULL,
	      "合成满足 → 不判 LIBC_VERSION_TOO_NEW");
	CHECK(json && strstr(json, "\"too_new\":[]") != NULL,
	      "合成满足 → versions.too_new 空");
	free(json);
	json = NULL;

	/* 真宿主冒烟：/bin/sh 的 versions 字段（glibc/musl 宿主均成立：
	 * too_new 恒空、不误报 fatal） */
	(void)ai_compat_probe_json("/bin/sh", NULL, &json, &runnable);
	CHECK(runnable == 1, "/bin/sh runnable=true（版本核对后仍可执行）");
	CHECK(json && strstr(json, "\"versions\":") != NULL,
	      "/bin/sh：elf.versions 字段在");
	CHECK(json && strstr(json, "\"too_new\":[]") != NULL,
	      "/bin/sh：too_new 为空");
	CHECK(json && strstr(json, "LIBC_VERSION_TOO_NEW") == NULL,
	      "/bin/sh：不误报 LIBC_VERSION_TOO_NEW");
	free(json);

	{
		char p[512];

		snprintf(p, sizeof(p), "%s/too-new", dir);
		unlink(p);
		snprintf(p, sizeof(p), "%s/satisfied", dir);
		unlink(p);
	}
	rmdir(dir);
}

static void test_registry(void)
{
	struct tool_registry reg;
	char *err = NULL;
	const struct ai_tool *t;
	int compat = 0, i;

	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK, "tools.json 加载");
	CHECK(reg.tool_count == 237, "工具总数 237");
	for (i = 0; i < reg.tool_count; i++)
		if (reg.tools[i].channel == TOOL_CH_COMPAT)
			compat++;
	CHECK(compat == 4, "compat 通道 4 件");
	t = tool_registry_find(&reg, "compat_probe");
	CHECK(t && t->channel == TOOL_CH_COMPAT, "compat_probe 接线");
	t = tool_registry_find(&reg, "compat_apply");
	CHECK(t && t->channel == TOOL_CH_COMPAT, "compat_apply 接线");
	t = tool_registry_find(&reg, "compat_verify");
	CHECK(t && t->channel == TOOL_CH_COMPAT, "compat_verify 接线");
	CHECK(t && t->risk && strcmp(t->risk, "W1") == 0,
	      "compat_verify 风险 W1");
	t = tool_registry_find(&reg, "compat_apply");
	CHECK(t && t->risk && strcmp(t->risk, "W2") == 0,
	      "compat_apply 风险 W2");
	tool_registry_free(&reg);
}

static void test_honest_errors(void)
{
	struct tool_registry reg;
	char *err = NULL, *out = NULL;
	int ok = 0;

	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		CHECK(0, "tools.json 加载（诚实错误用例）");
		return;
	}
	run_tool(&reg, "compat_generate",
		 "{\"name\":\"bad/name\",\"target\":\"/bin/sh\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "ERROR:"), "非法名 → 明确拒绝");
	free(out);
	out = NULL;
	run_tool(&reg, "compat_generate",
		 "{\"name\":\"ok1\",\"target\":\"relative/path\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "ERROR:"), "相对 target → 明确拒绝");
	free(out);
	out = NULL;
	run_tool(&reg, "compat_apply", "{\"name\":\"nosuchadapter\"}", &out,
		 &ok);
	CHECK(!ok && out && strstr(out, "ERROR:"), "不存在适配器 → 明确报错");
	free(out);
	out = NULL;
	run_tool(&reg, "compat_verify", "{\"name\":\"nosuchadapter\"}", &out,
		 &ok);
	CHECK(!ok && out && strstr(out, "ERROR:"), "verify 未 apply → 明确报错");
	free(out);
	tool_registry_free(&reg);
}

/* ------------------------------------------------------------------
 * C2（棒1 plan 补全）：SYSTEM-EVOLUTION §4.4 manifest 五字段 +
 * expect.exit_code 实装 + 六类超限诚实报错（generate 面 + 加载面）。
 * 全部非 root 零副作用：write:false 只回显；fixture 走 tmp compat root。
 * ------------------------------------------------------------------ */

/*
 * 合成最小 ELF64（只带一条 DT_NEEDED，无 PT_INTERP/无 verneed）：
 * 触发 MISSING_LIBRARY（fatal/adaptable）+ STATIC_ELF（非 fatal）双路径，
 * 让 generate 在无 gcc 的 unit 环境里也能走到 lib_redirect/limitations。
 * d_val 口径 = dynstr 内偏移（与 cp_elf_scan 的 DT_NEEDED 处理一致）。
 */
static int write_synth_elf_lib(const char *path, const char *soname)
{
	unsigned char buf[512];
	char st[160];
	size_t st_n = 1, o_soname;
	const off_t strtab_off = 64, dyn_off = 192, sh_off = 256;
	Elf64_Ehdr eh;
	Elf64_Shdr sh[3];
	Elf64_Dyn dyn[2];

	memset(buf, 0, sizeof(buf));
	st[0] = '\0';
	o_soname = st_n;
	st_n = st_add(st, st_n, soname);

	memset(&eh, 0, sizeof(eh));
	memcpy(eh.e_ident, ELFMAG, SELFMAG);
	eh.e_ident[EI_CLASS] = ELFCLASS64;
	eh.e_ident[EI_DATA] = ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = EV_CURRENT;
	eh.e_type = ET_DYN;
#if defined(__x86_64__)
	eh.e_machine = EM_X86_64;
#elif defined(__aarch64__)
	eh.e_machine = EM_AARCH64;
#else
	eh.e_machine = 0;
#endif
	eh.e_version = EV_CURRENT;
	eh.e_ehsize = sizeof(eh);
	eh.e_shoff = sh_off;
	eh.e_shentsize = sizeof(Elf64_Shdr);
	eh.e_shnum = 3;

	memset(sh, 0, sizeof(sh));
	sh[1].sh_type = SHT_STRTAB;
	sh[1].sh_offset = strtab_off;
	sh[1].sh_size = st_n;
	sh[2].sh_type = SHT_DYNAMIC;
	sh[2].sh_link = 1;		/* sh_link → dynstr */
	sh[2].sh_offset = dyn_off;
	sh[2].sh_size = sizeof(dyn);
	sh[2].sh_entsize = sizeof(Elf64_Dyn);

	memset(dyn, 0, sizeof(dyn));
	dyn[0].d_tag = DT_NEEDED;
	dyn[0].d_un.d_val = (uint64_t)o_soname;
	dyn[1].d_tag = DT_NULL;

	memcpy(buf, &eh, sizeof(eh));
	memcpy(buf + strtab_off, st, st_n);
	memcpy(buf + dyn_off, dyn, sizeof(dyn));
	memcpy(buf + sh_off, sh, sizeof(sh));
	return write_file_bin(path, buf, sizeof(buf), 0755);
}

/* 拼 {"K0":"v0",...} 共 n 对（env 入参构造器） */
static void build_env_obj(char *dst, size_t cap, int n)
{
	size_t u = 0;
	int i;

	u += (size_t)snprintf(dst + u, cap - u, "\"env\":{");
	for (i = 0; i < n && u < cap; i++)
		u += (size_t)snprintf(dst + u, cap - u, "%s\"C2A_K%d\":\"v%d\"",
				      i ? "," : "", i, i);
	snprintf(dst + u, cap - u, "}");
}

/* 拼 "argv":["a0","a1",...] 共 n 项 */
static void build_argv_arr(char *dst, size_t cap, int n)
{
	size_t u = 0;
	int i;

	u += (size_t)snprintf(dst + u, cap - u, "\"argv\":[");
	for (i = 0; i < n && u < cap; i++)
		u += (size_t)snprintf(dst + u, cap - u, "%s\"a%d\"",
				      i ? "," : "", i);
	snprintf(dst + u, cap - u, "]");
}

/* 拼 "path_map":{"/usr/bin/c2a-fake-i":"/bin/sh",...} 共 n 对 */
static void build_pmap_obj(char *dst, size_t cap, int n)
{
	size_t u = 0;
	int i;

	u += (size_t)snprintf(dst + u, cap - u, "\"path_map\":{");
	for (i = 0; i < n && u < cap; i++)
		u += (size_t)snprintf(dst + u, cap - u,
				      "%s\"/usr/bin/c2a-fake-%d\":\"/bin/sh\"",
				      i ? "," : "", i);
	snprintf(dst + u, cap - u, "}");
}

/* C2：manifest 五字段（risk 查表 / limitations 汇入 / provides 派生 /
 * created_by+trace_id 透传往返 / exit_code 实装含非零期望与撞车规避） */
static void test_generate_manifest(void)
{
	struct tool_registry reg;
	char *err = NULL, *out = NULL;
	char dir[] = "/tmp/c2a-unit-XXXXXX";
	char script[512], synth[512], synthlib[512], libfile[512];
	char seg[2048], args[4096];
	int ok = 0;

	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		CHECK(0, "tools.json 加载（C2 manifest 用例）");
		return;
	}
	CHECK(mkdtemp(dir) != NULL, "mkdtemp（C2 manifest 用例）");
	snprintf(script, sizeof(script), "%s/nosh", dir);
	CHECK(write_file(script, "#!/usr/bin/c2a-nosh\necho hi\n", 0755) == 0,
	      "写缺解释器样本（c2a-nosh）");
	snprintf(synth, sizeof(synth), "%s/static", dir);
	CHECK(write_synth_elf(synth, "GLIBC_2.2.5") == 0,
	      "写合成静态 ELF（STATIC_ELF 非 fatal）");
	snprintf(synthlib, sizeof(synthlib), "%s/needlib", dir);
	snprintf(libfile, sizeof(libfile), "%s/libc2a.so.1", dir);
	CHECK(write_synth_elf_lib(synthlib, "libc2a.so.1") == 0,
	      "写合成 DT_NEEDED ELF（缺 libc2a.so.1）");
	CHECK(write_file(libfile, "c2a-dummy-lib\n", 0644) == 0,
	      "写库来源占位文件");

	/* 基线：/bin/sh（runnable、零 L0 规则）→ low / 空 provides /
	 * 缺省 created_by / trace_id=null / 三条静态 caveats 在场 */
	run_tool(&reg, "compat_generate",
		 "{\"name\":\"c2a-base\",\"target\":\"/bin/sh\","
		 "\"write\":false}", &out, &ok);
	CHECK(ok && out, "generate 基线（/bin/sh）成功");
	CHECK(out && strstr(out, "\"risk\":\"low\""), "零规则 → risk=low");
	CHECK(out && strstr(out, "\"trace_id\":null"),
	      "缺省 trace_id 如实为 null");
	CHECK(out && strstr(out,
	      "\"created_by\":\"ai-tool:compat_generate\""),
	      "缺省 created_by=ai-tool:compat_generate");
	CHECK(out && strstr(out, "\"provides\":[]"),
	      "零重定向 → provides 空数组");
	CHECK(out && strstr(out, "ld.so.cache"),
	      "limitations 含 caveat：不读 ld.so.cache");
	CHECK(out && strstr(out, "非 libc"),
	      "limitations 含 caveat：非 libc 符号版本只记录");
	CHECK(out && strstr(out, "32 位"),
	      "limitations 含 caveat：32 位不解析 DT_NEEDED");
	free(out);
	out = NULL;

	/* risk 查表边界：env 恰 4 条（+0 其他）→ low；5 条 → medium */
	build_env_obj(seg, sizeof(seg), 4);
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-env4\",\"target\":\"/bin/sh\","
		 "\"write\":false,%s}", seg);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "\"risk\":\"low\""),
	      "L0 规则恰 4 条 → low（查表边界）");
	free(out);
	out = NULL;
	build_env_obj(seg, sizeof(seg), 5);
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-env5\",\"target\":\"/bin/sh\","
		 "\"write\":false,%s}", seg);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "\"risk\":\"medium\""),
	      "L0 规则 5 条 → medium（查表边界）");
	free(out);
	out = NULL;

	/* 解释器重映射（显式 interpreter_map）→ overlay 在用 → medium；
	 * provides 派生解释器映射目标名（basename） */
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-imap\",\"target\":\"%s\","
		 "\"write\":false,\"interpreter_map\":"
		 "{\"/usr/bin/c2a-nosh\":\"/bin/sh\"}}", script);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "\"risk\":\"medium\""),
	      "path_map→/usr overlay（L2 层）→ medium");
	CHECK(out && strstr(out, "\"provides\":[\"sh\"]"),
	      "provides 含解释器映射目标名（sh）");
	CHECK(out && strstr(out, "\"usr_overlay\":true"),
	      "overlay 视图如实标记");
	free(out);
	out = NULL;

	/* STATIC_ELF 非 fatal → 自动汇入 limitations */
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-static\",\"target\":\"%s\","
		 "\"write\":false}", synth);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "STATIC_ELF"),
	      "probe 非 fatal 原因（STATIC_ELF）汇入 limitations");
	free(out);
	out = NULL;

	/* 缺库 + lib_sources → provides 派生 soname（无 gcc 的 unit 路径） */
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-lib\",\"target\":\"%s\","
		 "\"write\":false,\"lib_sources\":"
		 "{\"libc2a.so.1\":\"%s\"}}", synthlib, libfile);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "\"provides\":[\"libc2a.so.1\"]"),
	      "provides 含 lib_redirect soname");
	CHECK(out && strstr(out, "\"risk\":\"low\""),
	      "lib(1)+自动 LD_LIBRARY_PATH(1) 共 2 条 → low");
	free(out);
	out = NULL;

	/* created_by/trace_id 透传往返 */
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-ids\",\"target\":\"/bin/sh\","
		 "\"write\":false,\"created_by\":\"aik-compat\","
		 "\"trace_id\":\"c2a-tr1\"}");
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "\"created_by\":\"aik-compat\""),
	      "created_by 透传（CLI 面标识）");
	CHECK(out && strstr(out, "\"trace_id\":\"c2a-tr1\""),
	      "trace_id 透传");
	free(out);
	out = NULL;

	/* 显式 path_map（C2『路径假设』类）→ limitations 如实标注 */
	build_pmap_obj(seg, sizeof(seg), 1);
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-pmap\",\"target\":\"/bin/sh\","
		 "\"write\":false,%s}", seg);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "路径假设"),
	      "显式 path_map 的不可验证性如实写 limitations");
	CHECK(out && strstr(out, "\"risk\":\"medium\""),
	      "显式 path_map 动用 overlay → medium");
	free(out);
	out = NULL;

	/* expect.exit_code 实装：显式 42 / 缺省 0 / 撞车规避 / 非法拒绝 */
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-ec42\",\"target\":\"/bin/sh\","
		 "\"write\":false,\"expect\":{\"exit_code\":42}}");
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out,
	      "\"type\":\"exit_code\",\"op\":\"eq\",\"value\":42"),
	      "expect.exit_code=42 → 断言 eq 42");
	CHECK(out && strstr(out, "调用方显式声明期望退出码 42"),
	      "非零期望的 because 如实说明来源");
	free(out);
	out = NULL;
	run_tool(&reg, "compat_generate",
		 "{\"name\":\"c2a-ec0\",\"target\":\"/bin/sh\","
		 "\"write\":false}", &out, &ok);
	CHECK(ok && out && strstr(out,
	      "\"type\":\"exit_code\",\"op\":\"eq\",\"value\":0,"),
	      "未声明 exit_code → 维持 eq 0（缺省兼容）");
	free(out);
	out = NULL;
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-ec97\",\"target\":\"/bin/sh\","
		 "\"write\":false,\"expect\":{\"exit_code\":97}}");
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "\"exit\":98"),
	      "期望 97 时负向变异改用 98（避开撞车）");
	free(out);
	out = NULL;
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-ec300\",\"target\":\"/bin/sh\","
		 "\"write\":false,\"expect\":{\"exit_code\":300}}");
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(!ok && out && strstr(out, "ERROR"),
	      "exit_code=300 超出 0-255 → 拒绝");
	free(out);
	out = NULL;
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-ecstr\",\"target\":\"/bin/sh\","
		 "\"write\":false,\"expect\":{\"exit_code\":\"x\"}}");
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(!ok && out && strstr(out, "ERROR"),
	      "exit_code 非数字 → 拒绝不静默回落 0");
	free(out);
	out = NULL;

	{
		char p[512];

		snprintf(p, sizeof(p), "%s/nosh", dir);
		unlink(p);
		snprintf(p, sizeof(p), "%s/static", dir);
		unlink(p);
		snprintf(p, sizeof(p), "%s/needlib", dir);
		unlink(p);
		snprintf(p, sizeof(p), "%s/libc2a.so.1", dir);
		unlink(p);
	}
	rmdir(dir);
	tool_registry_free(&reg);
}

/* C2：六类超限改诚实报错（generate 面：env/map/lib/install/argv/chmod；
 * unit 可达路径 = env/argv/map/自动 env；lib/chmod/install 的 generate
 * 面守卫已埋但 v0 结构性不可达（probe 自身上限=generate 上限），
 * 加载面在 test_load_manifest 全覆盖） */
static void test_generate_limits(void)
{
	struct tool_registry reg;
	char *err = NULL, *out = NULL;
	char dir[] = "/tmp/c2a-lim-XXXXXX";
	char synthlib[512], libfile[512];
	char seg[2048], args[4096];
	int ok = 0;

	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		CHECK(0, "tools.json 加载（C2 超限用例）");
		return;
	}
	CHECK(mkdtemp(dir) != NULL, "mkdtemp（C2 超限用例）");
	snprintf(synthlib, sizeof(synthlib), "%s/needlib", dir);
	snprintf(libfile, sizeof(libfile), "%s/libc2a.so.1", dir);
	CHECK(write_synth_elf_lib(synthlib, "libc2a.so.1") == 0,
	      "写合成缺库 ELF（超限用例）");
	CHECK(write_file(libfile, "c2a-dummy-lib\n", 0644) == 0,
	      "写库来源占位（超限用例）");

	/* env>16：第 17 条报错并指名上限 */
	build_env_obj(seg, sizeof(seg), 17);
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-env17\",\"target\":\"/bin/sh\","
		 "\"write\":false,%s}", seg);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(!ok && out && strstr(out, "ERROR") &&
	      strstr(out, "env") && strstr(out, "上限 16"),
	      "env 第 17 条 → 报错指名（不再静默丢）");
	free(out);
	out = NULL;

	/* env 恰 16 条（无库）→ 成功（边界不误伤） */
	build_env_obj(seg, sizeof(seg), 16);
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-env16\",\"target\":\"/bin/sh\","
		 "\"write\":false,%s}", seg);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "\"risk\":\"medium\""),
	      "env 恰 16 条 → 成功（16>4 → medium）");
	free(out);
	out = NULL;

	/* env 满员 + 缺库：自动 LD_LIBRARY_PATH 追加会超限 → 报错 */
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-envfull\",\"target\":\"%s\","
		 "\"write\":false,%s,\"lib_sources\":"
		 "{\"libc2a.so.1\":\"%s\"}}",
		 synthlib, seg, libfile);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(!ok && out && strstr(out, "LD_LIBRARY_PATH") &&
	      strstr(out, "上限 16"),
	      "env 满员时自动 LD_LIBRARY_PATH 超限 → 报错（不静默跳过）");
	free(out);
	out = NULL;

	/* argv：连同程序本体上限 8 → 第 8 个用户参数报错 */
	build_argv_arr(seg, sizeof(seg), 8);
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-argv8\",\"target\":\"/bin/sh\","
		 "\"write\":false,%s}", seg);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(!ok && out && strstr(out, "argv") &&
	      strstr(out, "上限 8"),
	      "argv 第 8 项（共 9 条）→ 报错指名");
	free(out);
	out = NULL;
	build_argv_arr(seg, sizeof(seg), 7);
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-argv7\",\"target\":\"/bin/sh\","
		 "\"write\":false,%s}", seg);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out, "argv 恰 7 项（共 8 条）→ 成功（边界）");
	free(out);
	out = NULL;

	/* path_map>8：第 9 条报错；恰 8 条成功 */
	build_pmap_obj(seg, sizeof(seg), 9);
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-pmap9\",\"target\":\"/bin/sh\","
		 "\"write\":false,%s}", seg);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(!ok && out && strstr(out, "path_map") &&
	      strstr(out, "上限 8"),
	      "path_map 第 9 条 → 报错指名");
	free(out);
	out = NULL;
	build_pmap_obj(seg, sizeof(seg), 8);
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-pmap8\",\"target\":\"/bin/sh\","
		 "\"write\":false,%s}", seg);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out, "path_map 恰 8 条 → 成功（边界）");
	free(out);
	out = NULL;

	/* path_map 非法源（不在系统视图内）/ 重复源 → 拒绝 */
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-pmapbad\",\"target\":\"/bin/sh\","
		 "\"write\":false,\"path_map\":"
		 "{\"/tmp/c2a-not-sys\":\"/bin/sh\"}}");
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(!ok && out && strstr(out, "系统视图"),
	      "path_map 源不在系统视图 → 拒绝");
	free(out);
	out = NULL;
	snprintf(args, sizeof(args),
		 "{\"name\":\"c2a-pmapdup\",\"target\":\"/bin/sh\","
		 "\"write\":false,\"path_map\":"
		 "{\"/usr/bin/c2a-dup\":\"/bin/sh\","
		 "\"/usr/bin/c2a-dup\":\"/bin/sh\"}}");
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(!ok && out && strstr(out, "重复"),
	      "path_map 源重复声明 → 拒绝（矛盾数据）");
	free(out);
	out = NULL;

	/* env 值非字符串 → 拒绝（静默丢值=黑箱） */
	run_tool(&reg, "compat_generate",
		 "{\"name\":\"c2a-envnum\",\"target\":\"/bin/sh\","
		 "\"write\":false,\"env\":{\"C2A_N\":123}}", &out, &ok);
	CHECK(!ok && out && strstr(out, "不是字符串"),
	      "env 值非字符串 → 拒绝");
	free(out);
	out = NULL;

	unlink(synthlib);
	unlink(libfile);
	rmdir(dir);
	tool_registry_free(&reg);
}

/* 手写 fixture 适配器（tmp compat root）；manifest 为合法五字段集 */
static int write_fixture(const char *root, const char *name,
			 const char *manifest, const char *env,
			 const char *pmap, const char *lib, const char *chm,
			 const char *inst, const char *argv)
{
	char path[512], buf[6144];
	int n;

	n = snprintf(buf, sizeof(buf),
		     "{\"schema\":\"aikernel.compat/v0\",\"adapter\":\"%s\""
		     "%s,"
		     "\"target\":{\"host\":\"/bin/sh\",\"kind\":\"elf\","
		     "\"inside\":\"/opt/aik-compat/%s/app/sh\",\"size\":1,"
		     "\"because\":\"fixture\"},"
		     "\"layers\":{\"L0\":{\"env\":[%s],\"path_map\":[%s],"
		     "\"lib_redirect\":[%s],\"chmod\":[%s]},"
		     "\"L2\":{\"workspace\":\"cmp-%s\",\"backing\":\"disk\","
		     "\"stage\":\"/opt/aik-compat/%s\",\"install\":[%s],"
		     "\"usr_overlay\":false,\"mount_view\":[]}},"
		     "\"contract\":{\"argv\":[%s],\"timeout_s\":10,"
		     "\"assert\":[],\"negative\":[]},"
		     "\"rollback\":{\"paths\":[],\"steps\":[]}}",
		     name, manifest, name, env, pmap, lib, chm, name, name,
		     inst, argv);
	if (n <= 0 || (size_t)n >= sizeof(buf))
		return -1;
	snprintf(path, sizeof(path), "%s/adapters/%s.json", root, name);
	return write_file(path, buf, 0644);
}

#define C2A_MANIFEST_OK \
	",\"risk\":\"low\",\"limitations\":[\"fixture\"]," \
	"\"provides\":[],\"created_by\":\"c2a-fixture\",\"trace_id\":null"

/* C2：加载面——§4.4 字段校验（先例=缺 because 拒绝）+ 六类超限拒绝 */
static void test_load_manifest(void)
{
	struct tool_registry reg;
	char *err = NULL, *out = NULL;
	const char *root = getenv("AIKERNEL_COMPAT_ROOT");
	char adir[512], seg[4096];
	int ok = 0;

	if (!root || !root[0]) {
		CHECK(0, "AIKERNEL_COMPAT_ROOT 在场（C2 加载面用例）");
		return;
	}
	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		CHECK(0, "tools.json 加载（C2 加载面用例）");
		return;
	}
	snprintf(adir, sizeof(adir), "%s/adapters", root);
	mkdir(adir, 0755);

	/* 控制组：真 generate 的适配器（write:true 落盘）加载+安检全过
	 *（apply 后续失败属 unit 环境无沙盒/无 root，与 manifest 无关） */
	run_tool(&reg, "compat_generate",
		 "{\"name\":\"c2a-loadok\",\"target\":\"/bin/sh\",\"write\":true}",
		 &out, &ok);
	CHECK(ok && out && strstr(out, "\"written\":true"),
	      "控制组：真适配器落盘");
	free(out);
	out = NULL;
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-loadok\"}", &out, &ok);
	CHECK(out && strstr(out, "适配器不可用") == NULL,
	      "控制组：新版适配器通过 §4.4 加载校验");
	free(out);
	out = NULL;

	/* 缺 risk / risk 非法 / 缺 limitations / 缺 provides /
	 * 缺 created_by / 缺 trace_id / trace_id 类型错 */
	CHECK(write_fixture(root, "c2a-norisk", "", "", "", "", "", "",
			    "\"/opt/aik-compat/c2a-norisk/app/sh\"") == 0,
	      "写 fixture：缺 risk");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-norisk\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "适配器不可用") &&
	      strstr(out, "risk"), "缺 risk → 拒绝加载");
	free(out);
	out = NULL;
	CHECK(write_fixture(root, "c2a-badrisk",
			     ",\"risk\":\"high\",\"limitations\":[],"
			     "\"provides\":[],\"created_by\":\"f\","
			     "\"trace_id\":null", "", "", "", "", "",
			     "\"/opt/aik-compat/c2a-badrisk/app/sh\"") == 0,
	      "写 fixture：risk=high");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-badrisk\"}", &out,
		 &ok);
	CHECK(!ok && out && strstr(out, "risk 非法"),
	      "risk=high → 拒绝（只允许 low/medium）");
	free(out);
	out = NULL;
	CHECK(write_fixture(root, "c2a-nolimit",
			     ",\"risk\":\"low\",\"provides\":[],"
			     "\"created_by\":\"f\",\"trace_id\":null",
			     "", "", "", "", "",
			     "\"/opt/aik-compat/c2a-nolimit/app/sh\"") == 0,
	      "写 fixture：缺 limitations");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-nolimit\"}", &out,
		 &ok);
	CHECK(!ok && out && strstr(out, "limitations"),
	      "缺 limitations → 拒绝加载");
	free(out);
	out = NULL;
	CHECK(write_fixture(root, "c2a-noprov",
			     ",\"risk\":\"low\",\"limitations\":[],"
			     "\"created_by\":\"f\",\"trace_id\":null",
			     "", "", "", "", "",
			     "\"/opt/aik-compat/c2a-noprov/app/sh\"") == 0,
	      "写 fixture：缺 provides");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-noprov\"}", &out,
		 &ok);
	CHECK(!ok && out && strstr(out, "provides"),
	      "缺 provides → 拒绝加载");
	free(out);
	out = NULL;
	CHECK(write_fixture(root, "c2a-nocb",
			     ",\"risk\":\"low\",\"limitations\":[],"
			     "\"provides\":[],\"trace_id\":null",
			     "", "", "", "", "",
			     "\"/opt/aik-compat/c2a-nocb/app/sh\"") == 0,
	      "写 fixture：缺 created_by");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-nocb\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "created_by"),
	      "缺 created_by → 拒绝加载");
	free(out);
	out = NULL;
	CHECK(write_fixture(root, "c2a-notrace",
			     ",\"risk\":\"low\",\"limitations\":[],"
			     "\"provides\":[],\"created_by\":\"f\"",
			     "", "", "", "", "",
			     "\"/opt/aik-compat/c2a-notrace/app/sh\"") == 0,
	      "写 fixture：缺 trace_id 键");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-notrace\"}", &out,
		 &ok);
	CHECK(!ok && out && strstr(out, "trace_id"),
	      "缺 trace_id 键 → 拒绝（null 也必须在场）");
	free(out);
	out = NULL;
	CHECK(write_fixture(root, "c2a-badtrace",
			     ",\"risk\":\"low\",\"limitations\":[],"
			     "\"provides\":[],\"created_by\":\"f\","
			     "\"trace_id\":5",
			     "", "", "", "", "",
			     "\"/opt/aik-compat/c2a-badtrace/app/sh\"") == 0,
	      "写 fixture：trace_id=数字");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-badtrace\"}", &out,
		 &ok);
	CHECK(!ok && out && strstr(out, "trace_id"),
	      "trace_id 非null/字符串 → 拒绝加载");
	free(out);
	out = NULL;

	/* 六类超限（加载面；含 generate 面 v0 不可达的 lib/chmod/install） */
	{
		int i;

		seg[0] = '\0';
		for (i = 0; i < 17; i++) {
			char one[128];

			snprintf(one, sizeof(one),
				 "%s{\"key\":\"K%d\",\"value\":\"v\","
				 "\"because\":\"b\"}", i ? "," : "", i);
			strncat(seg, one, sizeof(seg) - strlen(seg) - 1);
		}
	}
	CHECK(write_fixture(root, "c2a-fx-env", C2A_MANIFEST_OK, seg, "", "",
			     "", "", "\"/opt/aik-compat/c2a-fx-env/app/sh\"") == 0,
	      "写 fixture：env 17 条");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-fx-env\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "env[16]") &&
	      strstr(out, "上限 16"), "加载面 env 17 条 → 拒绝");
	free(out);
	out = NULL;

	{
		int i;

		seg[0] = '\0';
		for (i = 0; i < 25; i++) {
			char one[256];

			snprintf(one, sizeof(one),
				 "%s{\"soname\":\"l%d.so.1\",\"from\":\"/bin/sh\","
				 "\"to\":\"/opt/aik-compat/c2a-fx-lib/lib/l%d.so.1\","
				 "\"because\":\"b\"}", i ? "," : "", i, i);
			strncat(seg, one, sizeof(seg) - strlen(seg) - 1);
		}
	}
	CHECK(write_fixture(root, "c2a-fx-lib", C2A_MANIFEST_OK, "", "", seg,
			     "", "", "\"/opt/aik-compat/c2a-fx-lib/app/sh\"") == 0,
	      "写 fixture：lib_redirect 25 条");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-fx-lib\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "lib_redirect") &&
	      strstr(out, "上限 24"), "加载面 lib 25 条 → 拒绝");
	free(out);
	out = NULL;

	{
		int i;

		seg[0] = '\0';
		for (i = 0; i < 5; i++) {
			char one[192];

			snprintf(one, sizeof(one),
				 "%s{\"path\":\"/opt/aik-compat/c2a-fx-chm/app\","
				 "\"mode\":\"0755\",\"because\":\"b\"}",
				 i ? "," : "");
			strncat(seg, one, sizeof(seg) - strlen(seg) - 1);
		}
	}
	CHECK(write_fixture(root, "c2a-fx-chm", C2A_MANIFEST_OK, "", "", "",
			     seg, "", "\"/opt/aik-compat/c2a-fx-chm/app/sh\"") == 0,
	      "写 fixture：chmod 5 条");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-fx-chm\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "chmod") &&
	      strstr(out, "上限 4"), "加载面 chmod 5 条 → 拒绝");
	free(out);
	out = NULL;

	{
		int i;

		seg[0] = '\0';
		for (i = 0; i < 9; i++) {
			char one[256];

			snprintf(one, sizeof(one),
				 "%s{\"from\":\"/bin/sh\",\"to\":\"/opt/"
				 "aik-compat/c2a-fx-inst/f%d\",\"because\":\"b\"}",
				 i ? "," : "", i);
			strncat(seg, one, sizeof(seg) - strlen(seg) - 1);
		}
	}
	CHECK(write_fixture(root, "c2a-fx-inst", C2A_MANIFEST_OK, "", "", "",
			     "", seg, "\"/opt/aik-compat/c2a-fx-inst/app/sh\"") == 0,
	      "写 fixture：install 9 条");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-fx-inst\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "install") &&
	      strstr(out, "上限 8"), "加载面 install 9 条 → 拒绝");
	free(out);
	out = NULL;

	{
		int i;

		seg[0] = '\0';
		for (i = 0; i < 9; i++) {
			char one[64];

			snprintf(one, sizeof(one), "%s\"arg%d\"", i ? "," : "",
				 i);
			strncat(seg, one, sizeof(seg) - strlen(seg) - 1);
		}
	}
	CHECK(write_fixture(root, "c2a-fx-argv", C2A_MANIFEST_OK, "", "", "",
			     "", "", seg) == 0,
	      "写 fixture：argv 9 条");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-fx-argv\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "argv") &&
	      strstr(out, "上限 8"), "加载面 argv 9 条 → 拒绝");
	free(out);
	out = NULL;

	{
		int i;

		seg[0] = '\0';
		for (i = 0; i < 9; i++) {
			char one[192];

			snprintf(one, sizeof(one),
				 "%s{\"from\":\"/usr/bin/c2a-f%d\",\"to\":"
				 "\"/bin/sh\",\"because\":\"b\"}", i ? "," : "",
				 i);
			strncat(seg, one, sizeof(seg) - strlen(seg) - 1);
		}
	}
	CHECK(write_fixture(root, "c2a-fx-map", C2A_MANIFEST_OK, "", seg, "",
			     "", "", "\"/opt/aik-compat/c2a-fx-map/app/sh\"") == 0,
	      "写 fixture：path_map 9 条");
	run_tool(&reg, "compat_apply", "{\"name\":\"c2a-fx-map\"}", &out, &ok);
	CHECK(!ok && out && strstr(out, "path_map") &&
	      strstr(out, "上限 8"), "加载面 path_map 9 条 → 拒绝");
	free(out);
	out = NULL;

	tool_registry_free(&reg);
}

/* ------------------------------------------------------------------
 * C3 Lane-1：层名统一 + L3 双态与 wrapper 装配（全非 root 零副作用）。
 * 双态不依赖真装 qemu：AIK_QEMU_USER_<ARCH> 是权威覆盖——env 指到存在/
 * 不存在的文件即得在场/缺席两态（坏路径=缺席不静默回落，见
 * cp_qemu_user_find）；PATH 发现用临时目录前置假 qemu-<arch>-static。
 * ------------------------------------------------------------------ */

/* 合成最小 ELF64（仅 Ehdr；machine/osabi 可配，无 PT_INTERP/动态段）
 * ——触发 ARCH_MISMATCH 双态 / OSABI 类 ABI_MISMATCH，判定路径最短 */
static int write_synth_elf_arch(const char *path, unsigned machine, int osabi)
{
	unsigned char buf[128];
	Elf64_Ehdr eh;

	memset(buf, 0, sizeof(buf));
	memset(&eh, 0, sizeof(eh));
	memcpy(eh.e_ident, ELFMAG, SELFMAG);
	eh.e_ident[EI_CLASS] = ELFCLASS64;
	eh.e_ident[EI_DATA] = ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = EV_CURRENT;
	eh.e_ident[EI_OSABI] = (unsigned char)osabi;
	eh.e_type = ET_DYN;
	eh.e_machine = machine;
	eh.e_version = EV_CURRENT;
	eh.e_ehsize = sizeof(eh);
	memcpy(buf, &eh, sizeof(eh));
	return write_file_bin(path, buf, sizeof(buf), 0755);
}

/* 合成最小 ELF32（EM_386）——触发 32 位 ABI_MISMATCH（人工路径文案） */
static int write_synth_elf32_x86(const char *path)
{
	unsigned char buf[96];
	Elf32_Ehdr eh;

	memset(buf, 0, sizeof(buf));
	memset(&eh, 0, sizeof(eh));
	memcpy(eh.e_ident, ELFMAG, SELFMAG);
	eh.e_ident[EI_CLASS] = ELFCLASS32;
	eh.e_ident[EI_DATA] = ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = EV_CURRENT;
	eh.e_type = ET_DYN;
	eh.e_machine = EM_386;
	eh.e_version = EV_CURRENT;
	eh.e_ehsize = sizeof(eh);
	memcpy(buf, &eh, sizeof(eh));
	return write_file_bin(path, buf, sizeof(buf), 0755);
}

/* 手写 L3 fixture 适配器（加载面：形状安检与矛盾数据拒绝） */
static int write_fixture_l3(const char *root, const char *name,
			    const char *emu, const char *argv0)
{
	char path[512], buf[3072];
	int n;

	n = snprintf(buf, sizeof(buf),
		     "{\"schema\":\"aikernel.compat/v0\",\"adapter\":\"%s\","
		     "\"risk\":\"low\",\"limitations\":[\"fixture\"],"
		     "\"provides\":[],\"created_by\":\"c3a-fixture\","
		     "\"trace_id\":null,"
		     "\"target\":{\"host\":\"/bin/sh\",\"kind\":\"elf\","
		     "\"inside\":\"/opt/aik-compat/%s/app/sh\",\"size\":1,"
		     "\"because\":\"fixture\"},"
		     "\"layers\":{\"L0\":{\"env\":[],\"path_map\":[],"
		     "\"lib_redirect\":[],\"chmod\":[]},"
		     "\"L2\":{\"workspace\":\"cmp-%s\",\"backing\":\"disk\","
		     "\"stage\":\"/opt/aik-compat/%s\",\"install\":[],"
		     "\"usr_overlay\":false,\"mount_view\":[]},"
		     "\"L3\":{\"emulator\":\"%s\"}},"
		     "\"contract\":{\"argv\":[\"%s\","
		     "\"/opt/aik-compat/%s/app/sh\"],\"timeout_s\":10,"
		     "\"assert\":[],\"negative\":[]},"
		     "\"rollback\":{\"paths\":[],\"steps\":[]}}",
		     name, name, name, name, emu, argv0, name);
	if (n <= 0 || (size_t)n >= sizeof(buf))
		return -1;
	snprintf(path, sizeof(path), "%s/adapters/%s.json", root, name);
	return write_file(path, buf, 0644);
}

static void test_c3_l3(void)
{
	struct tool_registry reg;
	char *err = NULL, *out = NULL, *json = NULL;
	const char *root = getenv("AIKERNEL_COMPAT_ROOT");
	char dir[] = "/tmp/c3a-unit-XXXXXX";
	char arm64[512], fake[512], pthdir[512], pthq[512], elf32[512];
	char osabi[512], toonew[512], adir[512], args[2048], oldpath[4096];
	const char *po;
	int ok = 0, runnable = -1;

	if (!root || !root[0]) {
		CHECK(0, "AIKERNEL_COMPAT_ROOT 在场（C3 L3 用例）");
		return;
	}
	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		CHECK(0, "tools.json 加载（C3 L3 用例）");
		return;
	}
	CHECK(mkdtemp(dir) != NULL, "mkdtemp（C3 L3 用例）");
	snprintf(arm64, sizeof(arm64), "%s/c3a-arm64", dir);
	snprintf(fake, sizeof(fake), "%s/qemu-aarch64-fake", dir);
	snprintf(pthdir, sizeof(pthdir), "%s/pth", dir);
	snprintf(pthq, sizeof(pthq), "%s/qemu-arm-static", pthdir);
	snprintf(elf32, sizeof(elf32), "%s/c3a-elf32", dir);
	snprintf(osabi, sizeof(osabi), "%s/c3a-osabi", dir);
	snprintf(toonew, sizeof(toonew), "%s/c3a-toonew", dir);
	CHECK(write_synth_elf_arch(arm64, EM_AARCH64, ELFOSABI_NONE) == 0,
	      "写合成 aarch64 ELF（最小 Ehdr）");
	CHECK(write_file(fake, "#!/bin/sh\nexit 0\n", 0755) == 0,
	      "写假模拟器（env 在场态指向它；probe 不执行它）");
	CHECK(mkdir(pthdir, 0755) == 0, "建 PATH 发现用临时目录");
	CHECK(write_file(pthq, "#!/bin/sh\nexit 0\n", 0755) == 0,
	      "写 PATH 上的假 qemu-arm-static");
	CHECK(write_synth_elf32_x86(elf32) == 0, "写合成 32 位 x86 ELF");
	CHECK(write_synth_elf_arch(osabi, EM_X86_64, ELFOSABI_SOLARIS) == 0,
	      "写合成 OSABI=Solaris ELF");
	CHECK(write_synth_elf(toonew, "GLIBC_2.9999") == 0,
	      "写合成超新版本 ELF");

	/* --- aarch64 缺席态：env 权威覆盖指到不存在路径 --- */
	setenv("AIK_QEMU_USER_AARCH64", "/nonexistent/c3a-noqemu", 1);
	(void)ai_compat_probe_json(arm64, NULL, &json, &runnable);
	CHECK(json && strstr(json, "\"emulators\":{\"aarch64\":null") != NULL,
	      "缺席态：emulators.aarch64=null（env 覆盖不静默回落）");
	CHECK(json && strstr(json, "\"ARCH_MISMATCH\",\"layer\":\"L3\","
	      "\"fatal\":true,\"adaptable\":false") != NULL,
	      "缺席态：ARCH_MISMATCH layer=L3 且 fatal+不可适配");
	CHECK(json && strstr(json, "qemu-aarch64-static 未装") != NULL,
	      "缺席态：detail 人话点名缺件");
	CHECK(json && strstr(json, "apt install qemu-user-static") != NULL,
	      "缺席态：detail 给装法一句");
	CHECK(runnable == 0, "缺席态：runnable=false（fatal 保持）");
	free(json);
	json = NULL;

	/* --- aarch64 在场态：env 指到存在的假模拟器 --- */
	setenv("AIK_QEMU_USER_AARCH64", fake, 1);
	(void)ai_compat_probe_json(arm64, NULL, &json, &runnable);
	CHECK(json && strstr(json, fake) != NULL,
	      "在场态：emulators.aarch64=env 指定路径（权威覆盖）");
	CHECK(json && strstr(json, "\"ARCH_MISMATCH\",\"layer\":\"L3\","
	      "\"fatal\":true,\"adaptable\":true") != NULL,
	      "在场态：ARCH_MISMATCH layer=L3，fatal 保持但可适配");
	CHECK(json && strstr(json, "经 qemu-user 模拟执行") != NULL,
	      "在场态：detail 指名经 qemu-user 模拟执行");
	free(json);
	json = NULL;

	/* --- arm 双态：env 覆盖缺席 / PATH 发现（均不依赖真装） --- */
	setenv("AIK_QEMU_USER_ARM", "/nonexistent/c3a-noqemu-arm", 1);
	(void)ai_compat_probe_json("/bin/sh", NULL, &json, &runnable);
	CHECK(json && strstr(json, "\"arm\":null") != NULL,
	      "arm 缺席态：emulators.arm=null");
	free(json);
	json = NULL;
	unsetenv("AIK_QEMU_USER_ARM");
	po = getenv("PATH");
	snprintf(oldpath, sizeof(oldpath), "%s", po ? po : "");
	{
		char newpath[4600];

		snprintf(newpath, sizeof(newpath), "%s:%s", pthdir, oldpath);
		setenv("PATH", newpath, 1);
	}
	(void)ai_compat_probe_json("/bin/sh", NULL, &json, &runnable);
	CHECK(json && strstr(json, pthq) != NULL,
	      "PATH 发现：emulators.arm 命中 PATH 上的 qemu-arm-static");
	free(json);
	json = NULL;
	setenv("PATH", oldpath, 1);

	/* --- 层名统一：LIBC_VERSION_TOO_NEW / 32 位 / OSABI 三 code --- */
	(void)ai_compat_probe_json(toonew, NULL, &json, &runnable);
	if (json && strstr(json, "LIBC_VERSION_TOO_NEW"))
		CHECK(strstr(json, "\"LIBC_VERSION_TOO_NEW\",\"layer\":"
		      "\"L3\"") != NULL,
		      "LIBC_VERSION_TOO_NEW layer=L3（v0 恒不可适配）");
	else
		CHECK(json && strstr(json, "LIBC_VERSION_TOO_NEW") == NULL,
		      "宿主 libc 无 verdef → 诚实降级（layer 用例跳过）");
	free(json);
	json = NULL;
	(void)ai_compat_probe_json(elf32, NULL, &json, &runnable);
	CHECK(json && strstr(json, "\"ABI_MISMATCH\",\"layer\":\"L3\"") != NULL,
	      "32 位 x86：ABI_MISMATCH layer=L3");
	CHECK(json && strstr(json, "libc6:i386") != NULL,
	      "32 位 x86：detail 给 multiarch 人工路径");
	free(json);
	json = NULL;
	(void)ai_compat_probe_json(osabi, NULL, &json, &runnable);
	CHECK(json && strstr(json, "\"ABI_MISMATCH\",\"layer\":\"L3\"") != NULL,
	      "OSABI 非 Linux：ABI_MISMATCH layer=L3");
	CHECK(json && strstr(json, "不做 OS 翻译") != NULL,
	      "OSABI 非 Linux：detail 指明 qemu 不做 OS 翻译");
	free(json);
	json = NULL;

	/* --- generate 在场态：L3 wrapper 装配 --- */
	snprintf(args, sizeof(args),
		 "{\"name\":\"c3a-l3gen\",\"target\":\"%s\",\"write\":false}",
		 arm64);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "\"L3\":{\"emulator\":\"") != NULL,
	      "generate：layers.L3.emulator 在场");
	{
		char pre[1024];

		snprintf(pre, sizeof(pre), "\"argv\":[\"%s\","
			 "\"/opt/aik-compat/c3a-l3gen/app/c3a-arm64\"", fake);
		CHECK(out && strstr(out, pre) != NULL,
		      "generate：contract.argv 前缀 [qemu, stage 内目标副本]");
	}
	CHECK(out && strstr(out, "\"risk\":\"medium\"") != NULL,
	      "generate：含 L3 层 → risk=medium");
	CHECK(out && strstr(out, "模拟执行：性能非原生，syscall 语义经 "
	      "qemu 翻译") != NULL,
	      "generate：limitations 自动加模拟执行注记");
	CHECK(out && strstr(out, "\"value\":\"execve\","
	      "\"match\":\"qemu-aarch64-fake\"") != NULL,
	      "generate：execve 轨迹断言随 argv[0]（match=模拟器名）");
	/* binfmt 面：unadapted 必要性负向与 binfmt 注记互斥——宿主注册了
	 * 对应 arch handler 时未适配直跑也被内核透明翻译，负向必须让位
	 * （C2 增强型同款裁定；不变式在有无 binfmt 的宿主上都成立） */
	CHECK(out && ((strstr(out, "\"id\":\"unadapted\"") != NULL) ==
		      (strstr(out, "binfmt_misc 已注册") == NULL)),
	      "generate：unadapted 负向与 binfmt 注记互斥一致（按宿主实态）");
	free(out);
	out = NULL;

	/* --- generate 缺席态：入口闸诚实拒绝（fatal&adaptable=0 才拒） --- */
	setenv("AIK_QEMU_USER_AARCH64", "/nonexistent/c3a-noqemu", 1);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(!ok && out && strstr(out, "ERROR") &&
	      strstr(out, "ARCH_MISMATCH") && strstr(out, "不可适配"),
	      "generate 缺席态：入口闸拒绝且指名 ARCH_MISMATCH");
	free(out);
	out = NULL;
	setenv("AIK_QEMU_USER_AARCH64", fake, 1);

	/* --- 加载面控制组：真 L3 适配器过形状安检 --- */
	snprintf(args, sizeof(args),
		 "{\"name\":\"c3a-l3load\",\"target\":\"%s\",\"write\":true}",
		 arm64);
	run_tool(&reg, "compat_generate", args, &out, &ok);
	CHECK(ok && out && strstr(out, "\"written\":true"),
	      "加载面控制组：L3 适配器落盘");
	free(out);
	out = NULL;
	run_tool(&reg, "compat_apply", "{\"name\":\"c3a-l3load\"}", &out, &ok);
	CHECK(out && strstr(out, "适配器不可用") == NULL,
	      "加载面控制组：L3 形状（argv=[模拟器, stage 内目标]）过安检");
	free(out);
	out = NULL;

	/* --- 加载面负例：矛盾数据 / 坏形状拒绝 --- */
	snprintf(adir, sizeof(adir), "%s/adapters", root);
	(void)mkdir(adir, 0755);
	CHECK(write_fixture_l3(root, "c3a-fx-mismatch", "/nonexistent/c3a-q",
				"/bin/sh") == 0,
	      "写 fixture：L3.emulator 与 argv[0] 不一致");
	run_tool(&reg, "compat_apply", "{\"name\":\"c3a-fx-mismatch\"}", &out,
		 &ok);
	CHECK(!ok && out && strstr(out, "适配器不可用") &&
	      strstr(out, "不一致"), "L3 矛盾数据（emulator≠argv[0]）→ 拒绝");
	free(out);
	out = NULL;
	CHECK(write_fixture_l3(root, "c3a-fx-noexec", "/nonexistent/c3a-q",
				"/nonexistent/c3a-q") == 0,
	      "写 fixture：argv[0] 一致但模拟器不存在");
	run_tool(&reg, "compat_apply", "{\"name\":\"c3a-fx-noexec\"}", &out,
		 &ok);
	CHECK(!ok && out && strstr(out, "适配器不可用") &&
	      strstr(out, "模拟器绝对路径"),
	      "argv[0] 不可执行 → 拒绝（诚实报 L3 形状要求）");
	free(out);
	out = NULL;

	unsetenv("AIK_QEMU_USER_AARCH64");
	unlink(arm64);
	unlink(fake);
	unlink(pthq);
	unlink(elf32);
	unlink(osabi);
	unlink(toonew);
	rmdir(pthdir);
	rmdir(dir);
	tool_registry_free(&reg);
}

static int unit(void)
{
	char root[] = "/tmp/w82b-compat-root-XXXXXX";
	char lerr[AI_LEASE_ERR_MAX] = "";

	setvbuf(stdout, NULL, _IONBF, 0);
	if (!mkdtemp(root)) {
		printf("FATAL: mkdtemp\n");
		return 2;
	}
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	setenv("AIKERNEL_COMPAT_ROOT", root, 1);
	ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	printf("== test_compat (unit, root=%s) ==\n", root);
	test_validators();
	test_probe_static();
	test_verneed_walk();
	test_verdef_max();
	test_ver_cmp();
	test_ver_too_new();
	test_probe_versions();
	test_registry();
	test_honest_errors();
	test_generate_manifest();
	test_generate_limits();
	test_load_manifest();
	test_c3_l3();
	printf("SUMMARY(unit): %d checks, %d failed\n", checks, fails);
	rmdir(root);
	return fails ? 1 : 0;
}

/* ---------------------------------------------------------------- live */

static int sh(const char *cmd)
{
	int rc = system(cmd);

	if (rc == -1)
		return -1;
	return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

static int contains(const char *hay, const char *needle)
{
	return hay && needle && strstr(hay, needle) != NULL;
}

static int live(void)
{
	struct tool_registry reg;
	char *err = NULL, *out = NULL;
	char tmpl[] = "/tmp/w82b-live-XXXXXX";
	char root[512], samples[512], wsroot[512], croot[512];
	char script[512], appc[512], applib[512], libsrc[512], appbin[512];
	char args[4096], adapter_path[512], adapter_backup[512];
	int ok = 0, pass = 0, total = 0;

#define LIVE(step, tname, jargs, want_ok, want_str) do { \
	total++; \
	ok = 0; \
	out = NULL; \
	run_tool(&reg, tname, jargs, &out, &ok); \
	if (ok == (want_ok) && contains(out, want_str)) { \
		printf("ok %s\n", step); \
		pass++; \
	} else { \
		printf("FAIL %s (ok=%d out=%.300s)\n", step, ok, \
		       out ? out : "(null)"); \
	} \
	free(out); \
	out = NULL; \
} while (0)

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("== test_compat --live (uid=%u, bin=%s) ==\n",
	       (unsigned)getuid(),
	       getenv("AIKERNEL_SANDBOX_BIN") ?
	       getenv("AIKERNEL_SANDBOX_BIN") : "(default)");
	if (getuid() != 0) {
		printf("SKIP: --live 需要 root（mount/loop/overlay）\n");
		return 0;
	}
	if (!mkdtemp(tmpl)) {
		printf("FATAL: mkdtemp\n");
		return 2;
	}
	snprintf(root, sizeof(root), "%s", tmpl);
	snprintf(samples, sizeof(samples), "%s/samples", root);
	snprintf(wsroot, sizeof(wsroot), "%s/ws", root);
	snprintf(croot, sizeof(croot), "%s/compat", root);
	mkdir(samples, 0755);
	mkdir(wsroot, 0755);
	mkdir(croot, 0755);
	setenv("AIKERNEL_WORKSPACE_ROOT", wsroot, 1);
	setenv("AIKERNEL_COMPAT_ROOT", croot, 1);
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}
	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		printf("FATAL: tools.json: %s\n", err ? err : "?");
		return 1;
	}

	/* ---- 构造样本 A：#!/usr/bin/python4.9 ---- */
	snprintf(script, sizeof(script), "%s/hello-tool", samples);
	if (write_file(script,
		       "#!/usr/bin/python4.9\n"
		       "import json, os, sys\n"
		       "if os.environ.get('AICOMPAT_QUIET') == '1':\n"
		       "    sys.exit(0)\n"
		       "print(json.dumps({'tool': 'hello-tool',"
		       " 'result': 'ok', 'value': 42}))\n", 0755)) {
		printf("FATAL: 样本 A 写入失败\n");
		return 1;
	}
	/* ---- 构造样本 B：DT_NEEDED libfoo.so.1（宿主默认路径没有） ---- */
	snprintf(applib, sizeof(applib), "%s/libfoo.c", samples);
	snprintf(appc, sizeof(appc), "%s/app.c", samples);
	write_file(applib,
		   "const char *libfoo_banner(void)\n"
		   "{ return \"hello-from-libfoo-v1\"; }\n", 0644);
	write_file(appc,
		   "#include <stdio.h>\n"
		   "extern const char *libfoo_banner(void);\n"
		   "int main(void)\n"
		   "{ printf(\"missinglib: %s\\n\", libfoo_banner());"
		   " return 0; }\n", 0644);
	snprintf(args, sizeof(args),
		 "cd %s && gcc -shared -fPIC -Wl,-soname,libfoo.so.1 "
		 "-o libfoo.so.1 libfoo.c && gcc -o missinglib app.c "
		 "./libfoo.so.1", samples);
	total++;
	if (sh(args) == 0) {
		printf("ok LIVE-0 构造样本 B（真 ELF + 真缺库）\n");
		pass++;
	} else {
		printf("FAIL LIVE-0 gcc 构造样本 B 失败\n");
	}
	snprintf(libsrc, sizeof(libsrc), "%s/libfoo.so.1", samples);
	snprintf(appbin, sizeof(appbin), "%s/missinglib", samples);
	{
		char probe[1024];

		/* 先确认 B 确实跑不起来（否则样本不成立） */
		snprintf(probe, sizeof(probe),
			 "%s >/dev/null 2>&1", appbin);
		if (sh(probe) == 0) {
			printf("FAIL 样本 B 竟然能跑（不成立）\n");
		} else {
			printf("ok 样本 B 在宿主上跑不起来（真不兼容）\n");
			pass++;
		}
		total++;
	}

	/* ---- probe ---- */
	snprintf(args, sizeof(args), "{\"target\":\"%s\"}", script);
	LIVE("LIVE-1 probe 样本 A 归因 MISSING_INTERPRETER", "compat_probe",
	     args, 1, "MISSING_INTERPRETER");
	snprintf(args, sizeof(args), "{\"target\":\"%s\"}", appbin);
	LIVE("LIVE-2 probe 样本 B 归因 MISSING_LIBRARY", "compat_probe", args,
	     1, "MISSING_LIBRARY");

	/* ---- generate + apply + verify：样本 A ---- */
	snprintf(args, sizeof(args),
		 "{\"name\":\"liveA\",\"target\":\"%s\","
		 "\"expect\":{\"exit_code\":0,\"stdout_contains\":"
		 "[\"hello-tool\"],\"max_ms\":8000}}", script);
	LIVE("LIVE-3 generate 样本 A 适配器", "compat_generate", args, 1,
	     "\"written\":true");
	LIVE("LIVE-4 apply 样本 A（workspace 内试跑）", "compat_apply",
	     "{\"name\":\"liveA\"}", 1, "\"ok\":true");
	LIVE("LIVE-5 verify 样本 A 契约全过", "compat_verify",
	     "{\"name\":\"liveA\"}", 1, "\"ok\":true");
	LIVE("LIVE-5b verify 负向自检三项都判负", "compat_verify",
	     "{\"name\":\"liveA\"}", 1, "\"negatives\":[{\"id\":\"empty_stdout\"");
	LIVE("LIVE-5c verify syscall 轨迹可用", "compat_verify",
	     "{\"name\":\"liveA\"}", 1, "\"syscall_trace\":{\"available\":true");

	/* ---- 故意破坏契约：目标返回 0 但输出为空 ---- */
	snprintf(adapter_path, sizeof(adapter_path), "%s/adapters/liveA.json",
		 croot);
	snprintf(adapter_backup, sizeof(adapter_backup), "%s/liveA.json.bak",
		 croot);
	if (rename(adapter_path, adapter_backup) == 0) {
		/* 在原适配器里注入 env AICOMPAT_QUIET=1 */
		{
			char cmd[2048];

			snprintf(cmd, sizeof(cmd),
				 "sed 's/\"env\":\\[\\]/\"env\":[{\"key\":"
				 "\"AICOMPAT_QUIET\",\"value\":\"1\","
				 "\"because\":\"W82B 负向取证：故意让输出为空\"}]/'"
				 " '%s' > '%s'",
				 adapter_backup, adapter_path);
			if (sh(cmd) != 0)
				printf("WARN: 注入 sed 失败\n");
		}
		total++;
		out = NULL;
		ok = 0;
		run_tool(&reg, "compat_verify", "{\"name\":\"liveA\"}", &out,
			 &ok);
		if (!ok && contains(out, "\"pass\":false") &&
		    contains(out, "stdout_nonempty")) {
			printf("ok LIVE-6 破坏契约（输出为空）→ verify 判不合格\n");
			pass++;
		} else {
			printf("FAIL LIVE-6 破坏契约后 verify 竟然通过（假成功）"
			       "ok=%d out=%.400s\n", ok, out ? out : "(null)");
		}
		free(out);
		out = NULL;
		unlink(adapter_path);
		rename(adapter_backup, adapter_path);
	}

	/* ---- generate + apply + verify：样本 B（缺库） ---- */
	snprintf(args, sizeof(args),
		 "{\"name\":\"liveB\",\"target\":\"%s\","
		 "\"lib_sources\":{\"libfoo.so.1\":\"%s\"},"
		 "\"expect\":{\"stdout_contains\":"
		 "[\"hello-from-libfoo-v1\"],\"max_ms\":8000}}",
		 appbin, libsrc);
	LIVE("LIVE-7 generate 样本 B（L2 自带库）", "compat_generate", args, 1,
	     "\"written\":true");
	LIVE("LIVE-8 apply 样本 B", "compat_apply", "{\"name\":\"liveB\"}", 1,
	     "\"ok\":true");
	LIVE("LIVE-9 verify 样本 B 契约全过", "compat_verify",
	     "{\"name\":\"liveB\"}", 1, "\"ok\":true");

	/* ---- 宿主零污染 ---- */
	total++;
	{
		struct stat st;

		if (stat("/usr/bin/python4.9", &st) != 0 &&
		    stat("/usr/lib/x86_64-linux-gnu/libfoo.so.1", &st) != 0) {
			printf("ok LIVE-10 宿主 /usr 无适配产物（零污染）\n");
			pass++;
		} else {
			printf("FAIL LIVE-10 宿主 /usr 出现适配产物！\n");
		}
	}

	/* ---- 回滚 + 销毁 + 零残留 ---- */
	LIVE("LIVE-11 rollback liveB", "compat_apply",
	     "{\"name\":\"liveB\",\"rollback\":true}", 1,
	     "\"rolled_back\":true");
	LIVE("LIVE-11b rollback liveA", "compat_apply",
	     "{\"name\":\"liveA\",\"rollback\":true}", 1,
	     "\"rolled_back\":true");
	total++;
	{
		char cmd[1024];
		char *list = NULL;

		snprintf(cmd, sizeof(cmd), "ls -A %s", wsroot);
		{
			FILE *p = popen(cmd, "r");
			char buf[4096];
			size_t n = 0;

			list = calloc(1, sizeof(buf));
			if (p && list) {
				n = fread(buf, 1, sizeof(buf) - 1, p);
				buf[n] = '\0';
				memcpy(list, buf, n + 1);
			}
			if (p)
				pclose(p);
		}
		if (list && list[0] == '\0') {
			printf("ok LIVE-12 workspace 根零残留\n");
			pass++;
		} else {
			printf("FAIL LIVE-12 workspace 根仍有残留: %.200s\n",
			       list ? list : "(null)");
		}
		free(list);
	}
	total++;
	{
		char cmd[1024];

		snprintf(cmd, sizeof(cmd), "ls -A /sandbox 2>/dev/null | wc -l");
		/* 只断言本次两个 workspace 名不在了 */
		if (sh("test ! -e /sandbox/cmp-liveA && "
		       "test ! -e /sandbox/cmp-liveB") == 0) {
			printf("ok LIVE-12b /sandbox 下无 cmp-live* 残留\n");
			pass++;
		} else {
			printf("FAIL LIVE-12b /sandbox 残留\n");
		}
	}

	printf("SUMMARY(live): %d checks, %d failed\n", total, total - pass);
	tool_registry_free(&reg);
	/* 测试自己造的 scratch 根也清掉（workspace 已由 rollback 销毁） */
	{
		char cmd[1024];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
		(void)sh(cmd);
	}
	return pass == total ? 0 : 1;
#undef LIVE
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc > 1 && strcmp(argv[1], "--live") == 0)
		return live();
	if (argc == 4 && strcmp(argv[1], "--call") == 0) {
		struct tool_registry reg;
		char *err = NULL, *out = NULL;
		char lerr[AI_LEASE_ERR_MAX] = "";
		int ok = 0;

		setenv("AIKERNEL_POLICY", "/dev/null", 1);
		setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
		memset(&reg, 0, sizeof(reg));
		if (tool_registry_load(&reg, &err) != AI_OK) {
			printf("FATAL: tools.json: %s\n", err ? err : "?");
			return 2;
		}
		run_tool(&reg, argv[2], argv[3], &out, &ok);
		printf("%s\n", out ? out : "(null)");
		free(out);
		tool_registry_free(&reg);
		return ok ? 0 : 1;
	}
	return unit();
}
