// SPDX-License-Identifier: GPL-2.0
/*
 * compat_tools.c - W82B V6 应用兼容（TOOL_CH_COMPAT）
 *
 * 设计说明见 compat_tools.h。本文件分八段：
 *   1) 通用工具（时间/路径/状态目录/原子写/审计/JSON 取值）
 *   2) ELF 静态解析（e_machine / OSABI / PT_INTERP / DT_NEEDED）
 *   3) probe（脚本 shebang 链、解释器候选、共享库解析、fatal 归因）
 *   4) generate（把 probe 结论编译成适配器数据：L0 规则 + L2 视图 + 契约）
 *   5) workspace 执行面（meta 读取、aik-sandbox argv 组装、独立 stdout/
 *      stderr 采集、strace 轨迹）
 *   6) apply（快照 -> 落地 -> 试跑 -> 失败自动回滚）
 *   7) verify（正例契约 + 三类负向变异自检；不可验证即不合格）
 *   8) 通道入口
 *
 * 诚实边界（v0）：
 *   - L1（ABI 翻译：binfmt_misc / seccomp 翻译）未实现；探测到架构不同/
 *     32 位缺 loader 时标 layer=L1 且 adaptable=0，绝不假装能修。
 *   - probe 只做静态判定（不执行目标）；真实试跑在 compat_apply 内、
 *     且只在 workspace 里发生。
 *   - syscall 轨迹依赖宿主 strace；缺 strace 时 verify 直接判"不可验证"，
 *     不静默放过。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "tools/workspace_tools.h"
#include "tools/compat_tools.h"

#define CP_MAX_REASONS 10
#define CP_MAX_EV      8
#define CP_MAX_LIBS    24
#define CP_MAX_CAND    6
#define CP_MAX_ENV     16
#define CP_MAX_MAP     8
#define CP_MAX_INST    8
#define CP_MAX_ARGV    8
#define CP_READ_MAX    (1u << 20)	/* 适配器/轨迹读取上限 1MB */
#define CP_OUT_MAX     (1u << 18)	/* 单次采集每流上限 256KB */
#define CP_UPPER       "/.aik-compat/usr-upper"
#define CP_STAGE_PFX   "/opt/aik-compat/"
#define CP_SB_DEFAULT  "/usr/local/bin/aik-sandbox"

/* ======================================================================
 * 1) 通用工具
 * ====================================================================== */

static long long cp_now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void cp_now_iso(char *out, size_t cap)
{
	time_t t = time(NULL);
	struct tm tm;

	gmtime_r(&t, &tm);
	strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/*
 * JSON 字符串输出：先 UTF-8 清洗再转义。
 * 工具结果里有子进程 stderr / 截断输出，可能是任意字节（含被 %.120s
 * 截断在多字节字符中间的片段）；直接转义会产出非法 UTF-8 的 JSON，
 * 上层解析器会整条失败。ai_json_utf8_sanitize 是仓库既有的最终防线。
 */
static void cp_jstr(FILE *f, const char *s)
{
	char *clean, *e;

	if (!s)
		s = "";
	clean = ai_json_utf8_sanitize(s);
	e = ai_json_escape(clean ? clean : "");
	fputc('"', f);
	fputs(e ? e : "", f);
	fputc('"', f);
	free(clean);
	free(e);
}

/* 适配器名：[A-Za-z0-9_.-]{1,32}；首字符非 . / -；禁 ".." */
int ai_compat_valid_name(const char *s)
{
	size_t i, n;

	if (!s)
		return 0;
	n = strlen(s);
	if (n == 0 || n > 32)
		return 0;
	if (s[0] == '.' || s[0] == '-')
		return 0;
	if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0)
		return 0;
	if (strstr(s, ".."))
		return 0;
	for (i = 0; i < n; i++) {
		char c = s[i];

		if (!(isalnum((unsigned char)c) || c == '.' || c == '_' ||
		      c == '-'))
			return 0;
	}
	return 1;
}

/*
 * 落盘路径安检（适配器是数据，数据不能指挥我们 rm -rf /etc）：
 *   - 必须绝对路径、无 ".."、无 "//"
 *   - 只允许 [A-Za-z0-9._/+=@-]（同时保证拼进 /bin/sh -c 脚本时安全）
 */
static int cp_safe_path(const char *p)
{
	size_t i;

	if (!p || p[0] != '/' || !p[1])
		return 0;
	if (strstr(p, "..") || strstr(p, "//"))
		return 0;
	for (i = 0; p[i]; i++) {
		char c = p[i];

		if (!(isalnum((unsigned char)c) || strchr("._/+=@-", c)))
			return 0;
	}
	return 1;
}

static int cp_under(const char *path, const char *prefix)
{
	size_t n = strlen(prefix);

	if (strncmp(path, prefix, n) != 0)
		return 0;
	if (path[n] == '\0')
		return 1;
	return prefix[n - 1] == '/' || path[n] == '/';
}

/*
 * overlay 的 upper 目录镜像的是 **lowerdir 的根**，而 sandbox 里 overlay
 * 挂在 /usr（lowerdir=/usr）。所以 /usr/bin/python4.9 在 upper 里必须写
 * 成 <upper>/bin/python4.9（不是 <upper>/usr/bin/...）。/bin /sbin /lib
 * /lib64 在 workspace 镜像里都是指向 usr/* 的 usrmerge 符号链接，
 * 相对 /usr 根的布局与原名一致，原样保留即可。
 */
static void cp_shim_path(const char *from, char *out, size_t cap)
{
	const char *rel = from;

	if (strncmp(from, "/usr/", 5) == 0)
		rel = from + 4;
	else if (strcmp(from, "/usr") == 0)
		rel = "/";
	snprintf(out, cap, "%s%s", CP_UPPER, rel);
}

static const char *cp_root(void)
{
	static char buf[PATH_MAX];
	const char *e = getenv("AIKERNEL_COMPAT_ROOT");
	size_t n;

	if (buf[0])
		return buf;
	if (!e || !e[0])
		e = "/var/lib/aikernel/compat";
	n = strlen(e);
	if (e[0] != '/' || n >= sizeof(buf) - 1)
		return "/var/lib/aikernel/compat";
	memcpy(buf, e, n + 1);
	while (n > 1 && buf[n - 1] == '/')
		buf[--n] = '\0';
	return buf;
}

static void cp_dir(char *out, size_t cap, const char *leaf)
{
	snprintf(out, cap, "%s/%s", cp_root(), leaf);
}

static void cp_adapter_path(const char *name, char *out, size_t cap)
{
	snprintf(out, cap, "%s/adapters/%s.json", cp_root(), name);
}

static void cp_state_path(const char *name, char *out, size_t cap)
{
	snprintf(out, cap, "%s/state/%s.applied.json", cp_root(), name);
}

static int cp_mkdir_p(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	char *p;
	size_t n;

	if (!path || !path[0])
		return -1;
	n = strlen(path);
	if (n >= sizeof(tmp))
		return -1;
	memcpy(tmp, path, n + 1);
	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) && errno != EEXIST)
			return -1;
		*p = '/';
	}
	if (mkdir(tmp, mode) && errno != EEXIST)
		return -1;
	return 0;
}

static int cp_ensure_dirs(void)
{
	char a[PATH_MAX], s[PATH_MAX];

	cp_dir(a, sizeof(a), "adapters");
	cp_dir(s, sizeof(s), "state");
	if (cp_mkdir_p(cp_root(), 0755) || cp_mkdir_p(a, 0755) ||
	    cp_mkdir_p(s, 0700))
		return -1;
	return 0;
}

static int cp_write_atomic(const char *path, const char *data, size_t len,
			   mode_t mode)
{
	char tmp[PATH_MAX];
	int fd, rc = -1;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path,
		     (long)getpid()) >= (int)sizeof(tmp))
		return -1;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0)
		return -1;
	if (write(fd, data, len) != (ssize_t)len)
		goto out;
	if (fsync(fd))
		goto out;
	if (close(fd)) {
		fd = -1;
		goto out;
	}
	fd = -1;
	if (rename(tmp, path))
		goto out;
	rc = 0;
out:
	if (fd >= 0)
		close(fd);
	if (rc)
		unlink(tmp);
	return rc;
}

static char *cp_read_file(const char *path, size_t max, size_t *out_len)
{
	struct stat st;
	char *buf;
	size_t got = 0;
	int fd;

	if (out_len)
		*out_len = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
	    (size_t)st.st_size > max) {
		close(fd);
		return NULL;
	}
	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}
	while (got < (size_t)st.st_size) {
		ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			close(fd);
			return NULL;
		}
		if (r == 0)
			break;
		got += (size_t)r;
	}
	close(fd);
	buf[got] = '\0';
	if (out_len)
		*out_len = got;
	return buf;
}

static void cp_audit(const char *tool, const char *fmt, ...)
{
	char path[PATH_MAX], line[2048];
	va_list ap;
	int n, fd;
	time_t t = time(NULL);
	struct tm tm;

	cp_dir(path, sizeof(path), "audit.log");
	(void)cp_mkdir_p(cp_root(), 0755);
	gmtime_r(&t, &tm);
	n = snprintf(line, sizeof(line), "%04d-%02d-%02dT%02d:%02d:%02dZ tool=%s ",
		     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		     tm.tm_min, tm.tm_sec, tool ? tool : "-");
	va_start(ap, fmt);
	n += vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n < sizeof(line) - 1) {
		line[n++] = '\n';
		line[n] = '\0';
	}
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	if (write(fd, line, (size_t)n) < 0)
		;
	close(fd);
}

/* ---- JSON 取值 ---- */

static char *jstr(const char *obj, size_t len, const char *key)
{
	const char *v;
	size_t vl;
	int ty;

	if (!obj || ai_json_obj_get(obj, len, key, &v, &vl, &ty) != 1 ||
	    ty != AI_JSON_STR)
		return NULL;
	return ai_json_strdup_str(v, vl);
}

static long long jll(const char *obj, size_t len, const char *key,
		     long long def)
{
	const char *v;
	size_t vl;
	int ty;

	if (!obj || ai_json_obj_get(obj, len, key, &v, &vl, &ty) != 1 ||
	    ty != AI_JSON_NUM)
		return def;
	return ai_json_ll(v, vl);
}

static int jbool(const char *obj, size_t len, const char *key, int def)
{
	const char *v;
	size_t vl;
	int ty;

	if (!obj || ai_json_obj_get(obj, len, key, &v, &vl, &ty) != 1 ||
	    ty != AI_JSON_BOOL)
		return def;
	return vl >= 4 && strncmp(v, "true", 4) == 0;
}

static int jobj(const char *obj, size_t len, const char *key,
		const char **out, size_t *olen)
{
	const char *v;
	size_t vl;
	int ty;

	if (!obj || ai_json_obj_get(obj, len, key, &v, &vl, &ty) != 1 ||
	    ty != AI_JSON_OBJ)
		return 0;
	*out = v;
	*olen = vl;
	return 1;
}

static int jarr(const char *obj, size_t len, const char *key,
		const char **out, size_t *olen)
{
	const char *v;
	size_t vl;
	int ty;

	if (!obj || ai_json_obj_get(obj, len, key, &v, &vl, &ty) != 1 ||
	    ty != AI_JSON_ARR)
		return 0;
	*out = v;
	*olen = vl;
	return 1;
}

static int jarr_strs(const char *obj, size_t len, const char *key,
		     char dst[][PATH_MAX], int max)
{
	const char *arr;
	size_t alen;
	int i, n = 0;

	if (!jarr(obj, len, key, &arr, &alen))
		return 0;
	for (i = 0; i < max; i++) {
		const char *e;
		size_t el;
		int ty;
		char *s;

		if (ai_json_arr_get(arr, alen, i, &e, &el, &ty) != 1)
			break;
		if (ty != AI_JSON_STR)
			continue;
		s = ai_json_strdup_str(e, el);
		if (!s)
			continue;
		snprintf(dst[n], PATH_MAX, "%s", s);
		free(s);
		n++;
	}
	return n;
}

/* ======================================================================
 * 2) ELF 静态解析（不依赖 readelf/ldd；ldd 会真的去加载依赖，不可取）
 * ====================================================================== */

struct cp_elf {
	int is_elf;
	int is64;
	unsigned char osabi;
	unsigned machine;
	char interp[PATH_MAX];
	char runpath[PATH_MAX];
	char needed[CP_MAX_LIBS][128];
	int n_needed;
};

static int cp_pread_full(int fd, void *buf, size_t n, off_t off)
{
	size_t got = 0;

	while (got < n) {
		ssize_t r = pread(fd, (char *)buf + got, n - got,
				  off + (off_t)got);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return -1;
		got += (size_t)r;
	}
	return 0;
}

static int cp_read_cstr(int fd, off_t off, off_t limit, char *buf, size_t cap)
{
	size_t i = 0;

	if (cap == 0)
		return -1;
	while (i < cap - 1 && off + (off_t)i < limit) {
		char c;

		if (cp_pread_full(fd, &c, 1, off + (off_t)i))
			break;
		buf[i++] = c;
		if (c == '\0')
			return 0;
	}
	buf[i] = '\0';
	return i ? 0 : -1;
}

static void cp_elf_do_needed(const char *strtab, size_t strtab_len,
			     uint64_t off, struct cp_elf *e)
{
	if (off >= strtab_len)
		return;
	if (e->n_needed >= CP_MAX_LIBS)
		return;
	snprintf(e->needed[e->n_needed], sizeof(e->needed[0]), "%s",
		 strtab + off);
	if (e->needed[e->n_needed][0])
		e->n_needed++;
}

static int cp_elf_scan(const char *path, struct cp_elf *e)
{
	unsigned char ident[EI_NIDENT];
	int fd, rv = -1;

	memset(e, 0, sizeof(*e));
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (cp_pread_full(fd, ident, sizeof(ident), 0))
		goto out;
	if (memcmp(ident, ELFMAG, SELFMAG) != 0)
		goto out;
	e->is_elf = 1;
	e->osabi = ident[EI_OSABI];
	if (ident[EI_CLASS] == ELFCLASS64) {
		Elf64_Ehdr eh;
		Elf64_Phdr *ph = NULL;
		Elf64_Shdr *sh = NULL;
		int i, dyn_idx = -1, str_idx = -1;

		e->is64 = 1;
		if (cp_pread_full(fd, &eh, sizeof(eh), 0))
			goto out;
		e->machine = eh.e_machine;
		if (eh.e_phnum && eh.e_phnum <= 128) {
			ph = calloc(eh.e_phnum, sizeof(*ph));
			if (!ph)
				goto out;
			if (cp_pread_full(fd, ph, eh.e_phnum * sizeof(*ph),
					  (off_t)eh.e_phoff)) {
				free(ph);
				goto out;
			}
			for (i = 0; i < eh.e_phnum; i++) {
				if (ph[i].p_type != PT_INTERP ||
				    ph[i].p_filesz == 0 ||
				    ph[i].p_filesz >= PATH_MAX)
					continue;
				(void)cp_read_cstr(fd, (off_t)ph[i].p_offset,
						   (off_t)(ph[i].p_offset +
							   ph[i].p_filesz),
						   e->interp,
						   sizeof(e->interp));
				break;
			}
			free(ph);
		}
		if (eh.e_shnum && eh.e_shnum <= 256) {
			sh = calloc(eh.e_shnum, sizeof(*sh));
			if (!sh)
				goto out;
			if (cp_pread_full(fd, sh, eh.e_shnum * sizeof(*sh),
					  (off_t)eh.e_shoff)) {
				free(sh);
				goto out;
			}
			for (i = 0; i < eh.e_shnum; i++) {
				if (sh[i].sh_type == SHT_DYNAMIC) {
					dyn_idx = i;
					str_idx = (int)sh[i].sh_link;
					break;
				}
			}
			if (dyn_idx >= 0 && str_idx >= 0 &&
			    str_idx < eh.e_shnum &&
			    sh[str_idx].sh_size > 0 &&
			    sh[str_idx].sh_size <= 65536 &&
			    sh[dyn_idx].sh_size > 0 &&
			    sh[dyn_idx].sh_size <= 65536) {
				char *strtab = malloc((size_t)sh[str_idx].sh_size + 1);
				Elf64_Dyn *dyn = malloc((size_t)sh[dyn_idx].sh_size);

				if (strtab && dyn &&
				    !cp_pread_full(fd, strtab,
						   (size_t)sh[str_idx].sh_size,
						   (off_t)sh[str_idx].sh_offset) &&
				    !cp_pread_full(fd, dyn,
						   (size_t)sh[dyn_idx].sh_size,
						   (off_t)sh[dyn_idx].sh_offset)) {
					size_t n = (size_t)sh[dyn_idx].sh_size /
						   sizeof(Elf64_Dyn);
					size_t k;

					strtab[sh[str_idx].sh_size] = '\0';
					for (k = 0; k < n; k++) {
						if (dyn[k].d_tag == DT_NULL)
							break;
						if (dyn[k].d_tag == DT_NEEDED)
							cp_elf_do_needed(
								strtab,
								(size_t)sh[str_idx].sh_size,
								dyn[k].d_un.d_val,
								e);
						else if ((dyn[k].d_tag == DT_RUNPATH ||
							  dyn[k].d_tag == DT_RPATH) &&
							 !e->runpath[0] &&
							 dyn[k].d_un.d_val <
							 (size_t)sh[str_idx].sh_size)
							snprintf(
								e->runpath,
								sizeof(e->runpath),
								"%s",
								strtab + dyn[k].d_un.d_val);
					}
				}
				free(strtab);
				free(dyn);
			}
			free(sh);
		}
		rv = 0;
	} else if (ident[EI_CLASS] == ELFCLASS32) {
		Elf32_Ehdr eh;
		Elf32_Phdr *ph = NULL;
		int i;

		e->is64 = 0;
		if (cp_pread_full(fd, &eh, sizeof(eh), 0))
			goto out;
		e->machine = eh.e_machine;
		if (eh.e_phnum && eh.e_phnum <= 128) {
			ph = calloc(eh.e_phnum, sizeof(*ph));
			if (!ph)
				goto out;
			if (cp_pread_full(fd, ph, eh.e_phnum * sizeof(*ph),
					  (off_t)eh.e_phoff)) {
				free(ph);
				goto out;
			}
			for (i = 0; i < eh.e_phnum; i++) {
				if (ph[i].p_type != PT_INTERP ||
				    ph[i].p_filesz == 0 ||
				    ph[i].p_filesz >= PATH_MAX)
					continue;
				(void)cp_read_cstr(fd, (off_t)ph[i].p_offset,
						   (off_t)(ph[i].p_offset +
							   ph[i].p_filesz),
						   e->interp,
						   sizeof(e->interp));
				break;
			}
			free(ph);
		}
		/* 32 位 ELF 的 DT_NEEDED v0 不解析（32 位目标一律判 ABI
		 * 不匹配；如实标注而不是猜） */
		rv = 0;
	}
out:
	close(fd);
	return rv;
}

static const char *cp_machine_name(unsigned m)
{
	switch (m) {
	case EM_386:
		return "x86_32";
	case EM_X86_64:
		return "x86_64";
	case EM_ARM:
		return "arm";
	case EM_AARCH64:
		return "aarch64";
	case EM_RISCV:
		return "riscv";
	case EM_MIPS:
		return "mips";
	case EM_PPC64:
		return "ppc64";
	case EM_S390:
		return "s390";
	default:
		return "unknown";
	}
}

static unsigned cp_host_em(const char *mach)
{
	if (!strcmp(mach, "x86_64"))
		return EM_X86_64;
	if (!strcmp(mach, "aarch64"))
		return EM_AARCH64;
	if (!strncmp(mach, "armv7", 5) || !strncmp(mach, "armv8", 5) ||
	    !strncmp(mach, "arm", 3))
		return EM_ARM;
	if (!strcmp(mach, "i686") || !strcmp(mach, "i386"))
		return EM_386;
	if (!strncmp(mach, "riscv", 5))
		return EM_RISCV;
	return 0;
}

static const char *cp_host_machine(void)
{
	static char buf[64];
	struct utsname u;

	if (buf[0])
		return buf;
	if (uname(&u))
		return "unknown";
	snprintf(buf, sizeof(buf), "%s", u.machine);
	return buf;
}

static const char *cp_multiarch(void)
{
	const char *m = cp_host_machine();

	if (!strcmp(m, "aarch64"))
		return "aarch64-linux-gnu";
	if (!strcmp(m, "i686") || !strcmp(m, "i386"))
		return "i386-linux-gnu";
	if (!strncmp(m, "armv7", 5))
		return "arm-linux-gnueabihf";
	if (!strncmp(m, "riscv64", 7))
		return "riscv64-linux-gnu";
	return "x86_64-linux-gnu";
}

/* ---- 共享库解析（v0 不解析 ld.so.cache，如实记录搜索目录） ---- */

static int cp_file_ok(const char *p)
{
	struct stat st;

	return !stat(p, &st) && S_ISREG(st.st_mode);
}

static int cp_lib_find(const char *soname, const char *runpath, char *out,
		       size_t cap, char *searched, size_t scap)
{
	char dirs[20][PATH_MAX];
	int n = 0, i;
	const char *e;
	char run_copy[PATH_MAX];
	char *tok, *save = NULL;

	if (searched && scap)
		searched[0] = '\0';
	e = getenv("LD_LIBRARY_PATH");
	if (e && e[0]) {
		snprintf(run_copy, sizeof(run_copy), "%s", e);
		for (tok = strtok_r(run_copy, ":", &save); tok && n < 4;
		     tok = strtok_r(NULL, ":", &save)) {
			if (tok[0] == '/')
				snprintf(dirs[n], PATH_MAX, "%s", tok), n++;
		}
	}
	if (runpath[0]) {
		snprintf(run_copy, sizeof(run_copy), "%s", runpath);
		save = NULL;
		for (tok = strtok_r(run_copy, ":", &save); tok && n < 8;
		     tok = strtok_r(NULL, ":", &save)) {
			if (tok[0] == '/')
				snprintf(dirs[n], PATH_MAX, "%s", tok), n++;
		}
	}
	snprintf(dirs[n++], PATH_MAX, "/lib/%s", cp_multiarch());
	snprintf(dirs[n++], PATH_MAX, "/usr/lib/%s", cp_multiarch());
	snprintf(dirs[n++], PATH_MAX, "/lib64");
	snprintf(dirs[n++], PATH_MAX, "/usr/lib64");
	snprintf(dirs[n++], PATH_MAX, "/lib");
	snprintf(dirs[n++], PATH_MAX, "/usr/lib");
	snprintf(dirs[n++], PATH_MAX, "/usr/local/lib");

	for (i = 0; i < n; i++) {
		char cand[PATH_MAX];

		snprintf(cand, sizeof(cand), "%s/%s", dirs[i], soname);
		if (searched && scap) {
			size_t used = strlen(searched);
			snprintf(searched + used, scap - used, "%s%s",
				 used ? "," : "", dirs[i]);
		}
		if (cp_file_ok(cand)) {
			snprintf(out, cap, "%s", cand);
			return 0;
		}
	}
	out[0] = '\0';
	return -1;
}

/* ======================================================================
 * 3) probe
 * ====================================================================== */

struct cp_reason {
	char code[40];
	char layer[8];
	int fatal;
	int adaptable;
	char detail[512];
	char ev[CP_MAX_EV][256];
	int n_ev;
};

struct cp_probe {
	char target[PATH_MAX];
	char kind[16];
	int runnable;
	char arch[32];
	char host_arch[32];
	struct cp_reason r[CP_MAX_REASONS];
	int n_r;
	int env_shebang;
	char shebang[256];
	char interp[PATH_MAX];		/* 缺失/待重映射的解释器路径 */
	char interp_arg[128];		/* env 风格下的命令名 */
	char needed[CP_MAX_LIBS][128];
	char resolved[CP_MAX_LIBS][PATH_MAX];
	int n_needed;
	char missing[CP_MAX_LIBS][128];
	int n_missing;
	char cand_base[128];
	char cand[CP_MAX_CAND][PATH_MAX];
	int n_cand;
	char because[1024];
};

static struct cp_reason *cp_reason(struct cp_probe *p, const char *code,
				   const char *layer, int fatal, int adaptable,
				   const char *fmt, ...)
{
	struct cp_reason *r;
	va_list ap;

	if (p->n_r >= CP_MAX_REASONS)
		return &p->r[CP_MAX_REASONS - 1];
	r = &p->r[p->n_r++];
	memset(r, 0, sizeof(*r));
	snprintf(r->code, sizeof(r->code), "%s", code);
	snprintf(r->layer, sizeof(r->layer), "%s", layer);
	r->fatal = fatal;
	r->adaptable = adaptable;
	va_start(ap, fmt);
	vsnprintf(r->detail, sizeof(r->detail), fmt, ap);
	va_end(ap);
	if (fatal)
		p->runnable = 0;
	return r;
}

static void cp_ev(struct cp_reason *r, const char *fmt, ...)
{
	va_list ap;

	if (!r || r->n_ev >= CP_MAX_EV)
		return;
	va_start(ap, fmt);
	vsnprintf(r->ev[r->n_ev], sizeof(r->ev[0]), fmt, ap);
	va_end(ap);
	r->n_ev++;
}

/* 读 shebang：成功 0；不是 #! 或读失败 -1 */
static int cp_read_shebang(const char *path, char *interp, size_t icap,
			   char *arg, size_t acap)
{
	char buf[256];
	ssize_t n;
	int fd;
	char *p, *q;
	size_t k;

	interp[0] = '\0';
	if (arg && acap)
		arg[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 3)
		return -1;
	buf[n] = '\0';
	if (buf[0] != '#' || buf[1] != '!')
		return -1;
	p = buf + 2;
	while (*p == ' ' || *p == '\t')
		p++;
	q = p;
	while (*q && *q != '\n' && *q != ' ' && *q != '\t')
		q++;
	k = (size_t)(q - p);
	if (k == 0 || k >= icap)
		return -1;
	memcpy(interp, p, k);
	interp[k] = '\0';
	while (*q == ' ' || *q == '\t')
		q++;
	if (arg && acap) {
		char *r = q;

		while (*r && *r != '\n' && *r != ' ' && *r != '\t')
			r++;
		k = (size_t)(r - q);
		if (k && k < acap) {
			memcpy(arg, q, k);
			arg[k] = '\0';
		}
	}
	return 0;
}

static int cp_lookup_path(const char *name, char *out, size_t cap)
{
	const char *pe = getenv("PATH");
	char buf[PATH_MAX];
	char *tok, *save = NULL;

	if (strchr(name, '/')) {
		if (cp_file_ok(name) && !access(name, X_OK)) {
			snprintf(out, cap, "%s", name);
			return 0;
		}
		return -1;
	}
	if (pe && pe[0]) {
		snprintf(buf, sizeof(buf), "%s", pe);
		for (tok = strtok_r(buf, ":", &save); tok;
		     tok = strtok_r(NULL, ":", &save)) {
			char cand[PATH_MAX];

			snprintf(cand, sizeof(cand), "%s/%s", tok, name);
			if (cp_file_ok(cand) && !access(cand, X_OK)) {
				snprintf(out, cap, "%s", cand);
				return 0;
			}
		}
	}
	{
		const char *fixed[] = { "/usr/bin", "/bin", "/usr/local/bin",
					"/usr/sbin", "/sbin" };
		size_t i;

		for (i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
			char cand[PATH_MAX];

			snprintf(cand, sizeof(cand), "%s/%s", fixed[i], name);
			if (cp_file_ok(cand) && !access(cand, X_OK)) {
				snprintf(out, cap, "%s", cand);
				return 0;
			}
		}
	}
	return -1;
}

/*
 * 候选解释器打分：同族同版本优先，工具脚本（*-config / *-gdb 之类）
 * 一律降级——W82B 实测踩过：/usr/bin/python3.10-config 也是可执行的
 * "python3*"，按字典序会抢在 python3 前面。分数越低越优先。
 */
static int cp_cand_score(const char *name, const char *stem)
{
	char pref[160];
	size_t pl;
	int sc;

	snprintf(pref, sizeof(pref), "%s3", stem);
	pl = strlen(pref);
	if (!strcmp(name, pref))
		sc = 0;
	else if (!strncmp(name, pref, pl))
		sc = 10;
	else if (!strncmp(name, stem, strlen(stem)))
		sc = 20;
	else
		sc = 30;
	if (strchr(name, '-'))
		sc += 5;          /* *-config / *-doc 这类不是解释器本体 */
	return sc;
}

static void cp_cand_insert(struct cp_probe *p, const char *path,
			   const char *name)
{
	int sc, i;

	if (p->n_cand >= CP_MAX_CAND)
		return;
	sc = cp_cand_score(name, p->cand_base);
	for (i = 0; i < p->n_cand; i++) {
		const char *base = strrchr(p->cand[i], '/');
		int sc2 = cp_cand_score(base ? base + 1 : p->cand[i],
					p->cand_base);

		if (strcmp(p->cand[i], path) == 0)
			return;
		if (sc < sc2 || (sc == sc2 && strlen(path) <
				 strlen(p->cand[i]))) {
			memmove(&p->cand[i + 1], &p->cand[i],
				sizeof(p->cand[0]) * (size_t)(p->n_cand - i));
			snprintf(p->cand[i], PATH_MAX, "%s", path);
			p->n_cand++;
			return;
		}
	}
	snprintf(p->cand[p->n_cand], PATH_MAX, "%s", path);
	p->n_cand++;
}

static void cp_candidates(struct cp_probe *p, const char *base)
{
	static const char *dirs[] = { "/usr/bin", "/bin", "/usr/local/bin",
				      "/usr/sbin", "/sbin" };
	char stem[128];
	size_t i, sl;

	snprintf(stem, sizeof(stem), "%s", base ? base : "");
	sl = strlen(stem);
	while (sl > 0 && (isdigit((unsigned char)stem[sl - 1]) ||
			  stem[sl - 1] == '.'))
		stem[--sl] = '\0';
	if (!stem[0])
		return;
	snprintf(p->cand_base, sizeof(p->cand_base), "%s", base);
	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		DIR *d = opendir(dirs[i]);
		struct dirent *de;

		if (!d)
			continue;
		while ((de = readdir(d)) != NULL) {
			char full[PATH_MAX];

			if (strncmp(de->d_name, stem, sl) != 0 ||
			    strcmp(de->d_name, base) == 0)
				continue;
			snprintf(full, sizeof(full), "%s/%s", dirs[i],
				 de->d_name);
			if (cp_file_ok(full) && !access(full, X_OK))
				cp_cand_insert(p, full, de->d_name);
		}
		closedir(d);
	}
}

static void cp_check_interp(struct cp_probe *p, const char *interp,
			    const char *arg, int depth)
{
	char cur[PATH_MAX];
	char next[PATH_MAX];
	char cur_arg[128];
	int d;

	snprintf(cur, sizeof(cur), "%s", interp);
	snprintf(cur_arg, sizeof(cur_arg), "%s", arg ? arg : "");
	for (d = 0; d < 3 && depth < 3; d++) {
		struct stat st;
		const char *base = strrchr(cur, '/');
		const char *bname = base ? base + 1 : cur;

		if (!strcmp(bname, "env") &&
		    (!strcmp(cur, "/usr/bin/env") ||
		     !strcmp(cur, "/bin/env"))) {
			char res[PATH_MAX];

			if (!cur_arg[0]) {
				struct cp_reason *r = cp_reason(
					p, "MISSING_INTERPRETER", "L0", 1, 1,
					"#!/usr/bin/env 缺少解释器名（无法判定）");
				cp_ev(r, "shebang: %s", p->shebang);
				return;
			}
			if (cp_lookup_path(cur_arg, res, sizeof(res)) == 0)
				return;	/* env 能解析到（但常规不会走到） */
			p->env_shebang = 1;
			snprintf(p->interp_arg, sizeof(p->interp_arg), "%s",
				 cur_arg);
			snprintf(p->interp, sizeof(p->interp),
				 "/usr/local/bin/%s", cur_arg);
			{
				struct cp_reason *r = cp_reason(
					p, "MISSING_INTERPRETER", "L0", 1, 1,
					"#!/usr/bin/env %s：PATH 中找不到 %s",
					cur_arg, cur_arg);
				cp_ev(r, "shebang: %s", p->shebang);
				cp_ev(r, "PATH=%s", getenv("PATH") ?
				      getenv("PATH") : "(空)");
				cp_ev(r, "/usr/bin/%s /bin/%s /usr/local/bin/%s "
				      "均不存在或不可执行", cur_arg, cur_arg,
				      cur_arg);
			}
			cp_candidates(p, cur_arg);
			return;
		}
		if (stat(cur, &st)) {
			struct cp_reason *r;

			snprintf(p->interp, sizeof(p->interp), "%s", cur);
			r = cp_reason(p, "MISSING_INTERPRETER", "L0", 1, 1,
				      "解释器 %s 不存在（目标 shebang 指向它）",
				      cur);
			cp_ev(r, "shebang: %s", p->shebang);
			cp_ev(r, "stat(%s): ENOENT（%s）", cur,
			      strerror(errno));
			cp_candidates(p, bname);
			if (p->n_cand) {
				int i;

				for (i = 0; i < p->n_cand && i < 4; i++)
					cp_ev(r, "候选解释器: %s",
					      p->cand[i]);
			} else {
				cp_ev(r, "未在本机找到同族解释器"
				      "（按 %s* 扫描 /usr/bin 等）", bname);
			}
			return;
		}
		if (!(st.st_mode & 0111)) {
			struct cp_reason *r = cp_reason(
				p, "INTERPRETER_NOT_EXECUTABLE", "L0", 1, 1,
				"解释器 %s 存在但不可执行（mode=%04o）", cur,
				(unsigned)(st.st_mode & 07777));
			cp_ev(r, "shebang: %s", p->shebang);
			return;
		}
		if (cp_read_shebang(cur, next, sizeof(next), cur_arg,
				    sizeof(cur_arg)) == 0) {
			/* 解释器本身是脚本：继续下钻（最多 3 层） */
			snprintf(cur, sizeof(cur), "%s", next);
			continue;
		}
		return;	/* 解释器可执行，链正常 */
	}
}

static void cp_probe_elf(struct cp_probe *p, const struct cp_elf *e)
{
	unsigned hem = cp_host_em(cp_host_machine());

	snprintf(p->arch, sizeof(p->arch), "%s", cp_machine_name(e->machine));
	if (e->osabi != ELFOSABI_NONE && e->osabi != ELFOSABI_LINUX &&
	    e->osabi != 3) {
		struct cp_reason *r = cp_reason(
			p, "ABI_MISMATCH", "L1", 1, 0,
			"ELF OSABI=%u 不是 Linux/SysV", (unsigned)e->osabi);
		cp_ev(r, "e_ident[EI_OSABI]=%u", (unsigned)e->osabi);
	}
	if (!e->is64) {
		struct cp_reason *r = cp_reason(
			p, "ABI_MISMATCH", "L1", 1, 0,
			"32 位 ELF（宿主 %s）；v0 只做 L0+L2，不做 ABI 翻译",
			cp_host_machine());
		cp_ev(r, "ELFCLASS32；需要 i386 兼容库与 32 位 loader");
		cp_ev(r, "/lib/ld-linux.so.2: %s",
		      cp_file_ok("/lib/ld-linux.so.2") ? "存在" : "不存在");
	}
	if (hem && e->machine != hem) {
		struct cp_reason *r = cp_reason(
			p, "ARCH_MISMATCH", "L1", 1, 0,
			"目标架构 %s ≠ 宿主架构 %s（需要 L1 翻译/模拟，"
			"v0 不提供）", cp_machine_name(e->machine),
			cp_host_machine());
		cp_ev(r, "e_machine=%u（%s）", e->machine,
		      cp_machine_name(e->machine));
		cp_ev(r, "uname -m = %s", cp_host_machine());
	}
	if (e->interp[0]) {
		if (!cp_file_ok(e->interp)) {
			struct cp_reason *r = cp_reason(
				p, "MISSING_ABI_LOADER", "L1", 1, 0,
				"ELF 解释器 %s 不存在（动态链接器缺失）",
				e->interp);
			cp_ev(r, "PT_INTERP=%s", e->interp);
		}
	} else if (e->is64) {
		struct cp_reason *r = cp_reason(p, "STATIC_ELF", "L2", 0, 1,
						"静态链接 ELF（无 PT_INTERP）");

		cp_ev(r, "PT_INTERP 缺失 = 静态链接");
	}
	{
		int i;

		for (i = 0; i < e->n_needed; i++) {
			char resolved[PATH_MAX];
			char searched[1024];
			struct cp_reason *r;

			snprintf(p->needed[p->n_needed], 128, "%s",
				 e->needed[i]);
			if (cp_lib_find(e->needed[i], e->runpath, resolved,
					sizeof(resolved), searched,
					sizeof(searched)) == 0) {
				snprintf(p->resolved[p->n_needed], PATH_MAX,
					 "%s", resolved);
				p->n_needed++;
				continue;
			}
			snprintf(p->missing[p->n_missing], 128, "%s",
				 e->needed[i]);
			p->n_missing++;
			p->n_needed++;
			p->resolved[p->n_needed - 1][0] = '\0';
			r = cp_reason(p, "MISSING_LIBRARY", "L0", 1, 1,
				      "共享库 %s 不在任何搜索路径", e->needed[i]);
			cp_ev(r, "DT_NEEDED: %s", e->needed[i]);
			cp_ev(r, "搜索目录: %s（ld.so.cache 未解析）",
			      searched[0] ? searched : "(无)");
		}
	}
}

static void cp_probe_run(const char *target, struct cp_probe *p)
{
	struct stat st;
	unsigned char magic[4];
	int fd;

	memset(p, 0, sizeof(*p));
	p->runnable = 1;
	snprintf(p->target, sizeof(p->target), "%s", target);
	snprintf(p->host_arch, sizeof(p->host_arch), "%s", cp_host_machine());
	snprintf(p->arch, sizeof(p->arch), "%s", cp_host_machine());

	if (stat(target, &st)) {
		struct cp_reason *r;

		snprintf(p->kind, sizeof(p->kind), "missing");
		r = cp_reason(p, "MISSING_TARGET", "L0", 1, 0,
			      "目标不存在：%s", target);
		cp_ev(r, "stat(%s): %s", target, strerror(errno));
		p->runnable = 0;
		goto summarize;
	}
	if (S_ISDIR(st.st_mode)) {
		struct cp_reason *r;

		snprintf(p->kind, sizeof(p->kind), "dir");
		r = cp_reason(p, "DIRECTORY_TARGET", "L0", 1, 0,
			      "目标是目录；请指定目录内的可执行/脚本文件"
			      "（v0 不自动挑选入口）");
		cp_ev(r, "mkdir/stat: %s 是目录", target);
		p->runnable = 0;
		goto summarize;
	}
	if (!S_ISREG(st.st_mode)) {
		struct cp_reason *r;

		snprintf(p->kind, sizeof(p->kind), "other");
		r = cp_reason(p, "NOT_REGULAR_FILE", "L0", 1, 0,
			      "目标不是普通文件（mode=%04o）",
			      (unsigned)(st.st_mode & 07777));
		cp_ev(r, "stat: 非 S_ISREG");
		p->runnable = 0;
		goto summarize;
	}
	if (!(st.st_mode & 0111)) {
		struct cp_reason *r = cp_reason(
			p, "NOT_EXECUTABLE", "L0", 1, 1,
			"目标无执行位（mode=%04o）；L0 可在 workspace 副本上"
			"补 0755（不改宿主原件）",
			(unsigned)(st.st_mode & 07777));

		cp_ev(r, "stat(%s).st_mode=%04o", target,
		      (unsigned)(st.st_mode & 07777));
	}
	fd = open(target, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		struct cp_reason *r = cp_reason(p, "UNREADABLE_TARGET", "L0",
						1, 0, "目标不可读：%s",
						strerror(errno));

		cp_ev(r, "open(%s, O_RDONLY) 失败", target);
		p->runnable = 0;
		goto summarize;
	}
	if (read(fd, magic, sizeof(magic)) != (ssize_t)sizeof(magic)) {
		close(fd);
		{
			struct cp_reason *r = cp_reason(
				p, "UNREADABLE_TARGET", "L0", 1, 0,
				"目标太短，无法判定格式");
			cp_ev(r, "read < 4 字节");
			p->runnable = 0;
		}
		goto summarize;
	}
	close(fd);

	if (memcmp(magic, ELFMAG, SELFMAG) == 0) {
		struct cp_elf e;

		snprintf(p->kind, sizeof(p->kind), "elf");
		if (cp_elf_scan(target, &e)) {
			struct cp_reason *r = cp_reason(
				p, "ELF_UNPARSEABLE", "L0", 1, 0,
				"ELF 头解析失败（截断/损坏）");
			cp_ev(r, "magic=7f 45 4c 46 但解析失败");
			p->runnable = 0;
			goto summarize;
		}
		cp_probe_elf(p, &e);
	} else if (magic[0] == '#' && magic[1] == '!') {
		char interp[PATH_MAX], arg[128];

		snprintf(p->kind, sizeof(p->kind), "script");
		if (cp_read_shebang(target, interp, sizeof(interp), arg,
				    sizeof(arg))) {
			struct cp_reason *r = cp_reason(
				p, "BAD_SHEBANG", "L0", 1, 0,
				"shebang 行无法解析");
			cp_ev(r, "目标以 #! 开头但解析失败");
			p->runnable = 0;
		} else {
			char line[256];
			int fd2 = open(target, O_RDONLY | O_CLOEXEC);

			line[0] = '\0';
			if (fd2 >= 0) {
				ssize_t n = read(fd2, line, sizeof(line) - 1);

				close(fd2);
				if (n > 0) {
					char *nl;

					line[n] = '\0';
					nl = strchr(line, '\n');
					if (nl)
						*nl = '\0';
				}
			}
			snprintf(p->shebang, sizeof(p->shebang), "%s", line);
			cp_check_interp(p, interp, arg, 0);
		}
	} else {
		struct cp_reason *r = cp_reason(
			p, "NO_EXEC_FORMAT", "L0", 1, 0,
			"既不是 ELF 也不是 #! 脚本（exec 会 ENOEXEC）；"
			"v0 不提供包装执行");
		cp_ev(r, "magic=%02x %02x %02x %02x", magic[0], magic[1],
		      magic[2], magic[3]);
		p->runnable = 0;
	}

summarize:
	{
		int i, fatal = 0;

		p->because[0] = '\0';
		for (i = 0; i < p->n_r; i++) {
			size_t used;
			char one[600];

			if (!p->r[i].fatal)
				continue;
			fatal++;
			snprintf(one, sizeof(one), "%s: %s", p->r[i].code,
				 p->r[i].detail);
			used = strlen(p->because);
			snprintf(p->because + used, sizeof(p->because) - used,
				 "%s%s", used ? "；" : "", one);
		}
		if (!fatal)
			snprintf(p->because, sizeof(p->because),
				 "静态判定未发现阻塞项（真实可执行性由 "
				 "compat_apply 在 workspace 内试跑确认）");
	}
}

static int cp_probe_json_inner(FILE *f, struct cp_probe *p)
{
	int i, j;

	fputc('{', f);
	fputs("\"ok\":true,\"target\":", f);
	cp_jstr(f, p->target);
	fputs(",\"kind\":", f);
	cp_jstr(f, p->kind);
	fprintf(f, ",\"runnable\":%s", p->runnable ? "true" : "false");
	fputs(",\"verdict\":", f);
	cp_jstr(f, p->runnable ? "runnable" : "blocked");
	fprintf(f, ",\"arch\":{\"target\":");
	cp_jstr(f, p->arch);
	fputs(",\"host\":", f);
	cp_jstr(f, p->host_arch);
	fputc('}', f);
	fputs(",\"reasons\":[", f);
	for (i = 0; i < p->n_r; i++) {
		if (i)
			fputc(',', f);
		fputs("{\"code\":", f);
		cp_jstr(f, p->r[i].code);
		fputs(",\"layer\":", f);
		cp_jstr(f, p->r[i].layer);
		fprintf(f, ",\"fatal\":%s,\"adaptable\":%s,\"detail\":",
			p->r[i].fatal ? "true" : "false",
			p->r[i].adaptable ? "true" : "false");
		cp_jstr(f, p->r[i].detail);
		fputs(",\"evidence\":[", f);
		for (j = 0; j < p->r[i].n_ev; j++) {
			if (j)
				fputc(',', f);
			cp_jstr(f, p->r[i].ev[j]);
		}
		fputs("]}", f);
	}
	fputs("],\"elf\":{\"needed\":[", f);
	for (i = 0; i < p->n_needed; i++) {
		if (i)
			fputc(',', f);
		cp_jstr(f, p->needed[i]);
	}
	fputs("],\"missing\":[", f);
	for (i = 0; i < p->n_missing; i++) {
		if (i)
			fputc(',', f);
		cp_jstr(f, p->missing[i]);
	}
	fputs("],\"resolved\":[", f);
	{
		int printed = 0;

		for (i = 0; i < p->n_needed; i++) {
			if (!p->resolved[i][0])
				continue;
			if (printed++)
				fputc(',', f);
			fputs("{\"soname\":", f);
			cp_jstr(f, p->needed[i]);
			fputs(",\"path\":", f);
			cp_jstr(f, p->resolved[i]);
			fputc('}', f);
		}
	}
	fputs("]}", f);
	if (p->shebang[0]) {
		fputs(",\"shebang\":", f);
		cp_jstr(f, p->shebang);
	}
	if (p->interp[0]) {
		fputs(",\"interpreter\":{\"missing\":", f);
		cp_jstr(f, p->interp);
		fprintf(f, ",\"env_style\":%s", p->env_shebang ? "true" : "false");
		if (p->interp_arg[0]) {
			fputs(",\"name\":", f);
			cp_jstr(f, p->interp_arg);
		}
		fputc('}', f);
	}
	if (p->cand_base[0] && p->n_cand) {
		fputs(",\"candidates\":{", f);
		cp_jstr(f, p->cand_base);
		fputs(":[", f);
		for (i = 0; i < p->n_cand; i++) {
			if (i)
				fputc(',', f);
			cp_jstr(f, p->cand[i]);
		}
		fputs("]}", f);
	}
	fputs(",\"because\":", f);
	cp_jstr(f, p->because);
	fputs(",\"note\":", f);
	cp_jstr(f, "probe 只做静态判定（不执行目标）；真实试跑由 "
		"compat_apply 在 workspace 内完成");
	fputc('}', f);
	return 0;
}

int ai_compat_probe_json(const char *target, const char *argv_extra,
			 char **out, int *runnable)
{
	struct cp_probe p;
	char *buf = NULL;
	size_t len = 0;
	FILE *f;

	(void)argv_extra;
	if (out)
		*out = NULL;
	if (!target || !target[0] || target[0] != '/')
		return -1;
	cp_probe_run(target, &p);
	if (runnable)
		*runnable = p.runnable;
	if (!out)
		return p.runnable ? 1 : 0;
	f = open_memstream(&buf, &len);
	if (!f)
		return -1;
	cp_probe_json_inner(f, &p);
	fclose(f);
	*out = buf;
	return p.runnable ? 1 : 0;
}

/* ======================================================================
 * 4) generate：probe 结论 -> 适配器数据
 * ====================================================================== */

struct cp_rule_map {
	char from[PATH_MAX];
	char to[PATH_MAX];
	char because[600];
};

struct cp_rule_lib {
	char soname[128];
	char src[PATH_MAX];
	char dst[PATH_MAX];
	char because[600];
};

struct cp_rule_chmod {
	char path[PATH_MAX];
	char mode[16];
	char because[300];
};

struct cp_adapter {
	char name[64];
	char schema[32];
	char host[PATH_MAX];
	char inside[PATH_MAX];
	char kind[16];
	long size;
	char ws[64];
	char backing[16];
	char stage[PATH_MAX];
	int usr_overlay;
	struct {
		char key[128];
		char val[PATH_MAX];
		char because[300];
	} env[CP_MAX_ENV];
	int n_env;
	struct cp_rule_map map[CP_MAX_MAP];
	int n_map;
	struct cp_rule_lib lib[CP_MAX_LIBS];
	int n_lib;
	struct cp_rule_chmod chm[4];
	int n_chm;
	struct {
		char src[PATH_MAX];
		char dst[PATH_MAX];
		char because[400];
	} inst[CP_MAX_INST];
	int n_inst;
	char argv[CP_MAX_ARGV][PATH_MAX];
	int n_argv;
	int timeout_s;
	char *raw;
	size_t rawlen;
	/* verify 时载入的 syscall 轨迹（属本次调用，非适配器数据） */
	char *trace;
	size_t trace_len;
};

static void cp_adapter_free(struct cp_adapter *a)
{
	free(a->raw);
	a->raw = NULL;
	a->rawlen = 0;
	free(a->trace);
	a->trace = NULL;
	a->trace_len = 0;
}

static void cp_basename(const char *p, char *out, size_t cap)
{
	const char *s = strrchr(p, '/');

	snprintf(out, cap, "%s", s ? s + 1 : p);
}

/* 从 probe 推出 L0/L2 规则 */
static int cp_build_rules(struct cp_adapter *a, const struct cp_probe *p,
			  const char *in_obj, size_t in_len, char *err,
			  size_t errcap)
{
	const char *obj;
	size_t olen;
	int i;

	snprintf(a->host, sizeof(a->host), "%s", p->target);
	snprintf(a->kind, sizeof(a->kind), "%s", p->kind);
	if (!p->runnable && p->n_r != 0) {
		int fatal = 0;

		for (i = 0; i < p->n_r; i++) {
			if (!p->r[i].fatal)
				continue;
			fatal++;
			if (!p->r[i].adaptable) {
				snprintf(err, errcap,
					 "probe 判定含不可适配的 fatal 原因 %s"
						"（layer=%s）：%s",
					 p->r[i].code, p->r[i].layer,
					 p->r[i].detail);
				return -1;
			}
		}
		if (!fatal) {
			snprintf(err, errcap, "probe 无 fatal 原因");
			return -1;
		}
	}
	/* 1) 解释器重映射 */
	if (p->interp[0]) {
		char *to = NULL;
		char base[128];
		const char *imap = NULL;
		size_t ilen = 0;

		cp_basename(p->interp, base, sizeof(base));
		if (jobj(in_obj, in_len, "interpreter_map", &imap, &ilen)) {
			to = jstr(imap, ilen, p->interp);
			if (!to)
				to = jstr(imap, ilen, base);
		}
		if (!to && p->n_cand)
			to = strdup(p->cand[0]);
		if (!to) {
			snprintf(err, errcap,
				 "缺解释器 %s 且未提供 interpreter_map，"
				 "本机也没有可用的同族候选（L1 未实现）",
				 p->interp);
			return -1;
		}
		if (to[0] != '/' || !cp_file_ok(to) || access(to, X_OK) ||
		    !cp_safe_path(to)) {
			snprintf(err, errcap,
				 "解释器映射目标 %s 不存在/不可执行/含危险字符",
				 to);
			free(to);
			return -1;
		}
		if (a->n_map < CP_MAX_MAP) {
			snprintf(a->map[a->n_map].from, PATH_MAX, "%s",
				 p->interp);
			snprintf(a->map[a->n_map].to, PATH_MAX, "%s", to);
			snprintf(a->map[a->n_map].because, sizeof(a->map[0].because),
				 "%s不存在（shebang: %s）；改用 %s 作为 shim "
				 "目标，应用本体不改", p->interp, p->shebang,
				 to);
			a->n_map++;
		}
		free(to);
	}
	/* 2) 缺库重定向 */
	for (i = 0; i < p->n_missing; i++) {
		char src[PATH_MAX];
		char *v = NULL;
		const char *lmap = NULL;
		size_t llen = 0;

		if (jobj(in_obj, in_len, "lib_sources", &lmap, &llen))
			v = jstr(lmap, llen, p->missing[i]);
		if (!v) {
			snprintf(err, errcap,
				 "缺共享库 %s 且未提供 lib_sources['%s']；"
				 "本机默认搜索路径里也没有",
				 p->missing[i], p->missing[i]);
			return -1;
		}
		if (v[0] != '/' || !cp_file_ok(v) || !cp_safe_path(v)) {
			snprintf(err, errcap, "库来源 %s 不是安全绝对路径", v);
			free(v);
			return -1;
		}
		snprintf(src, sizeof(src), "%s", v);
		free(v);
		if (a->n_lib < CP_MAX_LIBS) {
			snprintf(a->lib[a->n_lib].soname, 128, "%s",
				 p->missing[i]);
			snprintf(a->lib[a->n_lib].src, PATH_MAX, "%s", src);
			snprintf(a->lib[a->n_lib].dst, PATH_MAX,
				 "%s/lib/%s", a->stage, p->missing[i]);
			snprintf(a->lib[a->n_lib].because,
				 sizeof(a->lib[0].because),
				 "%s 的 DT_NEEDED 含 %s，宿主默认搜索路径无此库；"
				 "把库放进 workspace 自带 rootfs 并用 "
				 "LD_LIBRARY_PATH 指向它（不写宿主 /usr）",
				 a->host, p->missing[i]);
			a->n_lib++;
		}
	}
	/* 3) 无执行位 -> workspace 副本补位 */
	for (i = 0; i < p->n_r; i++) {
		if (strcmp(p->r[i].code, "NOT_EXECUTABLE") != 0)
			continue;
		if (a->n_chm < 4) {
			snprintf(a->chm[a->n_chm].path, PATH_MAX, "%s",
				 a->inside);
			snprintf(a->chm[a->n_chm].mode, 16, "0755");
			snprintf(a->chm[a->n_chm].because,
				 sizeof(a->chm[0].because),
				 "宿主原件无执行位（stat 证据见 probe）；只给 "
				 "workspace 内的副本补 0755，宿主文件权限不动");
			a->n_chm++;
		}
	}
	/* 4) 用户显式 env */
	if (jobj(in_obj, in_len, "env", &obj, &olen)) {
		int idx;

		for (idx = 0; idx < CP_MAX_ENV; idx++) {
			const char *k, *v;
			size_t kl, vl;
			int vty;
			char *ks, *vs;

			if (ai_json_obj_member(obj, olen, idx, &k, &kl, &v,
					       &vl, &vty) != 1)
				break;
			if (vty != AI_JSON_STR)
				continue;
			ks = ai_json_strdup_str(k, kl);
			vs = ai_json_strdup_str(v, vl);
			if (!ks || !vs) {
				free(ks);
				free(vs);
				continue;
			}
			if (a->n_env < CP_MAX_ENV) {
				snprintf(a->env[a->n_env].key, 128, "%s", ks);
				snprintf(a->env[a->n_env].val, PATH_MAX, "%s",
					 vs);
				snprintf(a->env[a->n_env].because,
					 sizeof(a->env[0].because),
					 "调用方显式声明的环境变量");
				a->n_env++;
			}
			free(ks);
			free(vs);
		}
	}
	/* 5) 缺库 -> LD_LIBRARY_PATH（若调用方没自己给） */
	if (a->n_lib > 0) {
		int have = 0;

		for (i = 0; i < a->n_env; i++)
			if (!strcmp(a->env[i].key, "LD_LIBRARY_PATH"))
				have = 1;
		if (!have && a->n_env < CP_MAX_ENV) {
			snprintf(a->env[a->n_env].key, 128,
				 "LD_LIBRARY_PATH");
			snprintf(a->env[a->n_env].val, PATH_MAX,
				 "%s/lib", a->stage);
			snprintf(a->env[a->n_env].because,
				 sizeof(a->env[0].because),
				 "把动态链接器的搜索面收口到 workspace 内的 "
				 "lib 目录（不污染宿主 /etc/ld.so.conf）");
			a->n_env++;
		}
	}
	if (a->n_map > 0)
		a->usr_overlay = 1;
	return 0;
}

static void cp_generate_contract(FILE *f, struct cp_adapter *a,
				 const struct cp_probe *p,
				 const char *in_obj, size_t in_len)
{
	const char *exp = NULL, *earr = NULL;
	size_t elen = 0, alen = 0;
	long long max_ms = jll(in_obj, in_len, "max_ms", 0);
	int i;

	if (jobj(in_obj, in_len, "expect", &exp, &elen)) {
		if (!max_ms)
			max_ms = jll(exp, elen, "max_ms", 0);
	}
	if (!max_ms)
		max_ms = 5000;
	fputs("\"contract\":{", f);
	fputs("\"argv\":[", f);
	for (i = 0; i < a->n_argv; i++) {
		if (i)
			fputc(',', f);
		cp_jstr(f, a->argv[i]);
	}
	fprintf(f, "],\"timeout_s\":%d,", a->timeout_s);
	fputs("\"assert\":[", f);
	fputs("{\"type\":\"exit_code\",\"op\":\"eq\",\"value\":0,"
	      "\"because\":\"应用正常做完就该返回 0；非 0 一律不合格\"},",
	      f);
	fputs("{\"type\":\"stdout_nonempty\","
	      "\"because\":\"返回 0 但输出为空 = 典型『把 ENOSYS 包装成功』，"
	      "必须判不合格\"},", f);
	if (jobj(in_obj, in_len, "expect", &exp, &elen)) {
		char tmp[CP_MAX_ARGV][PATH_MAX];
		int n = jarr_strs(exp, elen, "stdout_contains", tmp,
				  CP_MAX_ARGV);

		for (i = 0; i < n; i++) {
			fputs("{\"type\":\"stdout_contains\",\"value\":", f);
			cp_jstr(f, tmp[i]);
			fputs(",\"because\":\"调用方声明的预期输出\"},", f);
		}
		if (jarr(exp, elen, "stderr_not_contains", &earr, &alen)) {
			int j;

			for (j = 0; j < 4; j++) {
				const char *e;
				size_t ll;
				int ty;
				char *s;

				if (ai_json_arr_get(earr, alen, j, &e, &ll,
						    &ty) != 1)
					break;
				if (ty != AI_JSON_STR)
					continue;
				s = ai_json_strdup_str(e, ll);
				if (!s)
					continue;
				fputs("{\"type\":\"stderr_not_contains\","
				      "\"value\":", f);
				cp_jstr(f, s);
				fputs(",\"because\":\"调用方声明的禁止输出"
				      "\"},", f);
				free(s);
			}
		}
	}
	{
		char base[128];

		cp_basename(a->inside, base, sizeof(base));
		fputs("{\"type\":\"syscall_seen\",\"value\":\"execve\","
		      "\"match\":", f);
		cp_jstr(f, base);
		fputs(",\"ok_only\":false,\"because\":\"轨迹里必须真的 execve "
		      "了目标（不是被 shell 吞掉）\"},", f);
	}
	for (i = 0; i < a->n_lib; i++) {
		fputs("{\"type\":\"syscall_seen\",\"value\":\"openat\","
		      "\"match\":", f);
		cp_jstr(f, a->lib[i].dst);
		fputs(",\"ok_only\":true,\"because\":\"证明库是从 workspace "
		      "自带 rootfs 加载成功的（不是宿主同路径）\"},", f);
	}
	if (p->interp[0]) {
		fputs("{\"type\":\"syscall_absent_errno\",\"value\":\"ENOENT\","
		      "\"match\":", f);
		cp_jstr(f, p->interp);
		fputs(",\"because\":\"原来的失败形态（解释器 ENOENT）在适配后"
		      "必须彻底消失\"},", f);
	}
	fprintf(f, "{\"type\":\"max_ms\",\"value\":%lld,"
		"\"because\":\"耗时基线（契约上限；只防病态卡死，不做性能"
		"承诺）\"}", max_ms);
	fputs("],\"negative\":[", f);
	fputs("{\"id\":\"empty_stdout\",\"kind\":\"mutate_stdout_null\","
	      "\"target_assert\":\"stdout_nonempty\",\"expect\":\"fail\","
	      "\"because\":\"防『返回 0 但输出为空』被包装成成功\"},", f);
	fputs("{\"id\":\"forced_exit\",\"kind\":\"mutate_exit\","
	      "\"target_assert\":\"exit_code\",\"exit\":97,"
	      "\"expect\":\"fail\",\"because\":\"退出码断言必须真的能"
	      "拒绝非 0\"},", f);
	fputs("{\"id\":\"unadapted\",\"kind\":\"run_unadapted\","
	      "\"target_assert\":\"*\",\"expect\":\"fail\","
	      "\"because\":\"不带任何适配规则跑同一目标必须过不了契约"
	      "——否则适配器是摆设，『适配成功』就是假话\"}", f);
	fputs("]}", f);
}

static int cp_generate(const char *args, size_t alen, char **out)
{
	char *name = jstr(args, alen, "name");
	char *target = jstr(args, alen, "target");
	char *ws = jstr(args, alen, "workspace");
	long long timeout_s = jll(args, alen, "timeout_s", 10);
	int write = jbool(args, alen, "write", 1);
	struct cp_probe p;
	struct cp_adapter a;
	char err[512] = "";
	char path[PATH_MAX];
	char ts[40], base[128];
	char *buf = NULL, *body = NULL;
	size_t blen = 0, bodylen = 0;
	FILE *f;
	int i, rc = AI_OK;

	memset(&a, 0, sizeof(a));
	*out = NULL;
	if (!ai_compat_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法 name（[A-Za-z0-9_.-]{1,32}，"
			     "首字符非 . / -）：%s", name ? name : "(无)") < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}
	if (!target || target[0] != '/' || !cp_safe_path(target)) {
		if (asprintf(out, "ERROR: target 必须是安全的宿主绝对路径：%s",
			     target ? target : "(无)") < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}
	snprintf(a.name, sizeof(a.name), "%s", name);
	snprintf(a.schema, sizeof(a.schema), "%s", AI_COMPAT_SCHEMA);
	if (ws && ws[0]) {
		if (!ai_ws_valid_name(ws)) {
			if (asprintf(out, "ERROR: 非法 workspace 名：%s", ws) < 0)
				*out = NULL;
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		snprintf(a.ws, sizeof(a.ws), "%s", ws);
	} else {
		snprintf(a.ws, sizeof(a.ws), "cmp-%s", name);
	}
	snprintf(a.backing, sizeof(a.backing), "disk");
	snprintf(a.stage, sizeof(a.stage), "%s%s", CP_STAGE_PFX, name);
	cp_basename(target, base, sizeof(base));
	snprintf(a.inside, sizeof(a.inside), "%s/app/%s", a.stage, base);

	cp_probe_run(target, &p);
	if (!p.runnable) {
		int fatal = 0;

		for (i = 0; i < p.n_r; i++)
			if (p.r[i].fatal)
				fatal++;
		if (!fatal) {
			snprintf(err, sizeof(err), "probe 异常（无 fatal 但 "
				 "runnable=false）");
			goto fail;
		}
	}
	{
		struct stat st;

		if (stat(target, &st) == 0)
			a.size = (long)st.st_size;
	}
	if (cp_build_rules(&a, &p, args, alen, err, sizeof(err))) {
		if (asprintf(out, "ERROR: 生成适配器失败：%s", err) < 0)
			*out = NULL;
		rc = AI_ERR_NOT_IMPLEMENTED;
		goto done;
	}
	/* install 规则：把目标拷进 workspace（L2 自带 rootfs） */
	if (a.n_inst < CP_MAX_INST) {
		snprintf(a.inst[a.n_inst].src, PATH_MAX, "%s", a.host);
		snprintf(a.inst[a.n_inst].dst, PATH_MAX, "%s", a.inside);
		snprintf(a.inst[a.n_inst].because,
			 sizeof(a.inst[0].because),
			 "目标装进 workspace 的 stage（宿主原件零改动）；"
			 "stage 随 workspace 销毁即零残留");
		a.n_inst++;
	}
	snprintf(a.argv[a.n_argv], PATH_MAX, "%s", a.inside);
	a.n_argv++;
	{
		const char *earr;
		size_t elen;

		if (jarr(args, alen, "argv", &earr, &elen)) {
			int j;

			for (j = 0; j < CP_MAX_ARGV - 1; j++) {
				const char *e;
				size_t ll;
				int ty;
				char *s;

				if (ai_json_arr_get(earr, elen, j, &e, &ll,
						    &ty) != 1)
					break;
				if (ty != AI_JSON_STR)
					continue;
				s = ai_json_strdup_str(e, ll);
				if (!s)
					continue;
				snprintf(a.argv[a.n_argv], PATH_MAX, "%s", s);
				a.n_argv++;
				free(s);
			}
		}
	}
	a.timeout_s = timeout_s < 1 || timeout_s > 600 ? 10 : (int)timeout_s;

	cp_now_iso(ts, sizeof(ts));
	f = open_memstream(&body, &bodylen);
	if (!f) {
		if (asprintf(out, "ERROR: 内存不足") < 0)
			*out = NULL;
		rc = AI_ERR_MEMORY;
		goto done;
	}
	fputc('{', f);
	fputs("\"schema\":", f);
	cp_jstr(f, AI_COMPAT_SCHEMA);
	fputs(",\"adapter\":", f);
	cp_jstr(f, a.name);
	fputs(",\"created\":", f);
	cp_jstr(f, ts);
	fputs(",\"because\":", f);
	{
		char why[1200];

		snprintf(why, sizeof(why), "%s（目标 %s，kind=%s）",
			 p.because, a.host, p.kind);
		cp_jstr(f, why);
	}
	fputs(",\"target\":{\"host\":", f);
	cp_jstr(f, a.host);
	fputs(",\"kind\":", f);
	cp_jstr(f, p.kind);
	fputs(",\"inside\":", f);
	cp_jstr(f, a.inside);
	fprintf(f, ",\"size\":%ld", a.size);
	fputs(",\"because\":", f);
	cp_jstr(f, "目标先静态探明原因（见 probe），再由适配器在 workspace "
		"内重映射；宿主路径只读引用，不改一个字节");
	fputs("},\"layers\":{\"L0\":{\"env\":[", f);
	for (i = 0; i < a.n_env; i++) {
		if (i)
			fputc(',', f);
		fputs("{\"key\":", f);
		cp_jstr(f, a.env[i].key);
		fputs(",\"value\":", f);
		cp_jstr(f, a.env[i].val);
		fputs(",\"because\":", f);
		cp_jstr(f, a.env[i].because);
		fputc('}', f);
	}
	fputs("],\"path_map\":[", f);
	for (i = 0; i < a.n_map; i++) {
		if (i)
			fputc(',', f);
		fputs("{\"from\":", f);
		cp_jstr(f, a.map[i].from);
		fputs(",\"to\":", f);
		cp_jstr(f, a.map[i].to);
		fputs(",\"mode\":\"shim\",\"because\":", f);
		cp_jstr(f, a.map[i].because);
		fputc('}', f);
	}
	fputs("],\"lib_redirect\":[", f);
	for (i = 0; i < a.n_lib; i++) {
		if (i)
			fputc(',', f);
		fputs("{\"soname\":", f);
		cp_jstr(f, a.lib[i].soname);
		fputs(",\"from\":", f);
		cp_jstr(f, a.lib[i].src);
		fputs(",\"to\":", f);
		cp_jstr(f, a.lib[i].dst);
		fputs(",\"because\":", f);
		cp_jstr(f, a.lib[i].because);
		fputc('}', f);
	}
	fputs("],\"chmod\":[", f);
	for (i = 0; i < a.n_chm; i++) {
		if (i)
			fputc(',', f);
		fputs("{\"path\":", f);
		cp_jstr(f, a.chm[i].path);
		fputs(",\"mode\":", f);
		cp_jstr(f, a.chm[i].mode);
		fputs(",\"because\":", f);
		cp_jstr(f, a.chm[i].because);
		fputc('}', f);
	}
	fputs("]},\"L2\":{\"workspace\":", f);
	cp_jstr(f, a.ws);
	fputs(",\"backing\":", f);
	cp_jstr(f, a.backing);
	fputs(",\"stage\":", f);
	cp_jstr(f, a.stage);
	fputs(",\"install\":[", f);
	for (i = 0; i < a.n_inst; i++) {
		if (i)
			fputc(',', f);
		fputs("{\"from\":", f);
		cp_jstr(f, a.inst[i].src);
		fputs(",\"to\":", f);
		cp_jstr(f, a.inst[i].dst);
		fputs(",\"because\":", f);
		cp_jstr(f, a.inst[i].because);
		fputc('}', f);
	}
	fprintf(f, "],\"usr_overlay\":%s,", a.usr_overlay ? "true" : "false");
	fputs("\"mount_view\":[", f);
	if (a.usr_overlay) {
		fputs("{\"path\":\"/usr\",\"type\":\"overlay\",\"lower\":\"/usr\","
		      "\"upper\":", f);
		cp_jstr(f, CP_UPPER);
		fputs(",\"because\":\"目标 shebang/依赖指向 /usr 下的绝对路径，"
		      "而 /usr 默认是宿主只读 bind；用 overlay 把 workspace "
		      "自带的一层叠上去（upper 落在 workspace 镜像内，宿主 "
		      "/usr 零写入）\"}", f);
	}
	fputs("]}},", f);
	cp_generate_contract(f, &a, &p, args, alen);
	fputs(",\"rollback\":{\"paths\":[", f);
	cp_jstr(f, a.stage);
	for (i = 0; i < a.n_map; i++) {
		char up[PATH_MAX];

		fputc(',', f);
		cp_shim_path(a.map[i].from, up, sizeof(up));
		cp_jstr(f, up);
	}
	fputs("],\"steps\":[", f);
	fputs("{\"action\":\"remove\",\"path\":", f);
	cp_jstr(f, a.stage);
	fputs(",\"because\":\"stage（应用副本 + 库）全在 workspace 内，"
	      "删掉即还原\"},", f);
	for (i = 0; i < a.n_map; i++) {
		char up[PATH_MAX];

		cp_shim_path(a.map[i].from, up, sizeof(up));
		fputs("{\"action\":\"remove\",\"path\":", f);
		cp_jstr(f, up);
		fputs(",\"because\":\"overlay upper 里的 shim 删除后，"
		      "/usr 视图即回到宿主原件\"},", f);
	}
	fputs("{\"action\":\"destroy_workspace_if_created\","
	      "\"because\":\"只有当 workspace 由本次 apply 新建时才销毁，"
	      "复用的旧 workspace 不动\"}]}}", f);
	fclose(f);
	if (!body) {
		if (asprintf(out, "ERROR: 内存不足") < 0)
			*out = NULL;
		rc = AI_ERR_MEMORY;
		goto done;
	}
	cp_adapter_path(a.name, path, sizeof(path));
	if (write) {
		int overwrote = 0;
		struct stat st;

		if (!stat(path, &st))
			overwrote = 1;
		if (cp_ensure_dirs() ||
		    cp_write_atomic(path, body, bodylen, 0644)) {
			if (asprintf(out, "ERROR: 写适配器失败 %s: %s", path,
				     strerror(errno)) < 0)
				*out = NULL;
			rc = AI_ERR_STORAGE;
			goto done;
		}
		f = open_memstream(&buf, &blen);
		if (!f) {
			rc = AI_ERR_MEMORY;
			goto done;
		}
		fputs("{\"ok\":true,\"adapter\":", f);
		fputs(body, f);
		fputs(",\"path\":", f);
		cp_jstr(f, path);
		fprintf(f, ",\"overwrote\":%s,\"written\":true",
			overwrote ? "true" : "false");
		fputc('}', f);
		fclose(f);
		*out = buf;
	} else {
		f = open_memstream(&buf, &blen);
		if (!f) {
			rc = AI_ERR_MEMORY;
			goto done;
		}
		fputs("{\"ok\":true,\"written\":false,\"adapter\":", f);
		fputs(body, f);
		fputc('}', f);
		fclose(f);
		*out = buf;
	}
	cp_audit("compat_generate", "adapter=%s target=%s written=%d "
		 "rules(L0=%d/%d/%d L2=%d) because=%s", a.name, a.host,
		 write, a.n_map, a.n_lib, a.n_env, a.n_inst, p.because);
	goto done;
fail:
	if (asprintf(out, "ERROR: %s", err) < 0)
		*out = NULL;
	rc = AI_ERR_INVALID_ARG;
done:
	free(body);
	free(name);
	free(target);
	free(ws);
	return rc;
}

/* ======================================================================
 * 5) workspace 执行面
 * ====================================================================== */

static const char *cp_sb_bin(void)
{
	const char *e = getenv("AIKERNEL_SANDBOX_BIN");

	return (e && e[0]) ? e : CP_SB_DEFAULT;
}

struct cp_run {
	char *out;
	size_t out_len;
	char *err;
	size_t err_len;
	int exit_code;
	int timed_out;
	int truncated;
	int exec_fail;
	long long ms;
};

static void cp_run_free(struct cp_run *r)
{
	free(r->out);
	free(r->err);
	memset(r, 0, sizeof(*r));
	r->exit_code = -1;
}

/* 独立双管道采集（stdout/stderr 必须分开：契约要分别断言） */
static int cp_spawn(char *const argv[], char *const extra_env[], int env_n,
		    int timeout_s, struct cp_run *r)
{
	int outp[2], errp[2];
	pid_t pid;
	int i, status = 0;
	size_t oc = 0, ec = 0;
	long long start, deadline;
	int oopen = 1, eopen = 1;

	memset(r, 0, sizeof(*r));
	r->exit_code = -1;
	r->out = malloc(CP_OUT_MAX + 1);
	r->err = malloc(CP_OUT_MAX + 1);
	if (!r->out || !r->err) {
		cp_run_free(r);
		return -1;
	}
	r->out[0] = r->err[0] = '\0';
	if (pipe(outp) || pipe(errp)) {
		cp_run_free(r);
		return -1;
	}
	fflush(NULL);
	start = cp_now_ms();
	pid = fork();
	if (pid < 0) {
		close(outp[0]);
		close(outp[1]);
		close(errp[0]);
		close(errp[1]);
		cp_run_free(r);
		return -1;
	}
	if (pid == 0) {
		int devnull;

		close(outp[0]);
		close(errp[0]);
		setsid();
		dup2(outp[1], STDOUT_FILENO);
		dup2(errp[1], STDERR_FILENO);
		close(outp[1]);
		close(errp[1]);
		devnull = open("/dev/null", O_RDONLY);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			close(devnull);
		}
		for (i = 0; i < env_n; i++) {
			char *eq = strchr(extra_env[i], '=');

			if (!eq)
				continue;
			*eq = '\0';
			setenv(extra_env[i], eq + 1, 1);
			*eq = '=';
		}
		execv(argv[0], argv);
		_exit(127);
	}
	close(outp[1]);
	close(errp[1]);
	fcntl(outp[0], F_SETFL, fcntl(outp[0], F_GETFL) | O_NONBLOCK);
	fcntl(errp[0], F_SETFL, fcntl(errp[0], F_GETFL) | O_NONBLOCK);
	deadline = start + (long long)timeout_s * 1000;

	while (oopen || eopen) {
		struct pollfd pfd[2];
		int nf = 0;
		long long now = cp_now_ms();
		int wait_ms = (int)(deadline - now);

		if (wait_ms < 0)
			wait_ms = 0;
		if (wait_ms > 200)
			wait_ms = 200;
		if (oopen) {
			pfd[nf].fd = outp[0];
			pfd[nf].events = POLLIN;
			nf++;
		}
		if (eopen) {
			pfd[nf].fd = errp[0];
			pfd[nf].events = POLLIN;
			nf++;
		}
		(void)poll(pfd, (nfds_t)nf, wait_ms);
		if (oopen) {
			char buf[4096];
			ssize_t n;

			while ((n = read(outp[0], buf, sizeof(buf))) > 0) {
				size_t room = CP_OUT_MAX - oc;

				if ((size_t)n > room) {
					n = (ssize_t)room;
					r->truncated = 1;
				}
				if (n > 0) {
					memcpy(r->out + oc, buf, (size_t)n);
					oc += (size_t)n;
				}
			}
			if (n == 0) {
				close(outp[0]);
				oopen = 0;
			}
		}
		if (eopen) {
			char buf[4096];
			ssize_t n;

			while ((n = read(errp[0], buf, sizeof(buf))) > 0) {
				size_t room = CP_OUT_MAX - ec;

				if ((size_t)n > room) {
					n = (ssize_t)room;
					r->truncated = 1;
				}
				if (n > 0) {
					memcpy(r->err + ec, buf, (size_t)n);
					ec += (size_t)n;
				}
			}
			if (n == 0) {
				close(errp[0]);
				eopen = 0;
			}
		}
		if (cp_now_ms() > deadline) {
			if (!r->timed_out) {
				r->timed_out = 1;
				kill(-pid, SIGKILL);
			}
		}
	}
	r->out[oc] = '\0';
	r->err[ec] = '\0';
	r->out_len = oc;
	r->err_len = ec;
	if (waitpid(pid, &status, 0) == pid) {
		if (WIFEXITED(status))
			r->exit_code = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			r->exit_code = 128 + WTERMSIG(status);
	}
	r->ms = cp_now_ms() - start;
	if (oopen) {
		close(outp[0]);
		oopen = 0;
	}
	if (eopen) {
		close(errp[0]);
		eopen = 0;
	}
	return 0;
}

struct cp_sb {
	char *argv[96];
	int n;
	char b_backing[PATH_MAX + 16];
	char b_cpus[64], b_mem[64], b_pids[64], b_net[160];
	char b_ro[CP_MAX_INST + CP_MAX_LIBS + 4][PATH_MAX + 16];
};

static int cp_sb_build(struct cp_sb *s, const char *ws,
		       const struct ai_ws_info *w, int overlay,
		       char *const *ro, int ro_n, char *const *targv,
		       int targv_n)
{
	int i;

	memset(s, 0, sizeof(*s));
	if (10 + ro_n + targv_n >= 96)
		return -1;
	s->argv[s->n++] = (char *)cp_sb_bin();
	s->argv[s->n++] = (char *)"run";
	s->argv[s->n++] = (char *)ws;
	if (!strcmp(w->backing, "disk")) {
		snprintf(s->b_backing, sizeof(s->b_backing),
			 "--backing=disk:%s", w->image);
		s->argv[s->n++] = s->b_backing;
	} else {
		s->argv[s->n++] = (char *)"--backing=tmpfs";
	}
	snprintf(s->b_cpus, sizeof(s->b_cpus), "--cpus=%.2f",
		 w->cpus_x100 / 100.0);
	s->argv[s->n++] = s->b_cpus;
	snprintf(s->b_mem, sizeof(s->b_mem), "--mem-mb=%ld", w->mem_mb);
	s->argv[s->n++] = s->b_mem;
	snprintf(s->b_pids, sizeof(s->b_pids), "--pids=%ld", w->pids_max);
	s->argv[s->n++] = s->b_pids;
	if (!strcmp(w->net, "host")) {
		s->argv[s->n++] = (char *)"--net=host";
	} else if (!strcmp(w->net, "veth")) {
		if (!w->net_ns[0])
			return -1;
		snprintf(s->b_net, sizeof(s->b_net), "--net=join:%s",
			 w->net_ns);
		s->argv[s->n++] = s->b_net;
	} else {
		s->argv[s->n++] = (char *)"--net=none";
	}
	if (overlay)
		s->argv[s->n++] = (char *)"--usr-overlay";
	for (i = 0; i < ro_n; i++) {
		snprintf(s->b_ro[i], sizeof(s->b_ro[0]), "--ro-path=%s", ro[i]);
		s->argv[s->n++] = s->b_ro[i];
	}
	s->argv[s->n++] = (char *)"--";
	for (i = 0; i < targv_n; i++)
		s->argv[s->n++] = targv[i];
	s->argv[s->n] = NULL;
	return 0;
}

/* 去重收集目录（--ro-path 用） */
static int cp_add_dir(char dirs[][PATH_MAX], int *n, int max, const char *path)
{
	char dir[PATH_MAX];
	char *slash;
	int i;

	snprintf(dir, sizeof(dir), "%s", path);
	slash = strrchr(dir, '/');
	if (!slash || slash == dir)
		return 0;
	*slash = '\0';
	for (i = 0; i < *n; i++)
		if (!strcmp(dirs[i], dir))
			return 0;
	if (*n >= max)
		return -1;
	snprintf(dirs[*n], PATH_MAX, "%s", dir);
	(*n)++;
	return 0;
}

/* ---- JSON 轨迹断言 ---- */

static int cp_line_has(const char *hay, size_t len, const char *needle,
		       int ok_only)
{
	const char *p = hay, *end = hay + len;
	size_t nl = strlen(needle);

	while (p < end) {
		const char *nlp = memchr(p, '\n', (size_t)(end - p));
		size_t ll = nlp ? (size_t)(nlp - p) : (size_t)(end - p);

		if (ll > nl && memmem(p, ll, needle, nl)) {
			if (!ok_only)
				return 1;
			if (!memmem(p, ll, "= -1", 4))
				return 1;
		}
		if (!nlp)
			break;
		p = nlp + 1;
	}
	return 0;
}

static int cp_line_has_errno(const char *hay, size_t len, const char *needle,
			     const char *errname)
{
	const char *p = hay, *end = hay + len;
	size_t nl = strlen(needle);
	char pat[64];

	snprintf(pat, sizeof(pat), "= -1 %s", errname);
	while (p < end) {
		const char *nlp = memchr(p, '\n', (size_t)(end - p));
		size_t ll = nlp ? (size_t)(nlp - p) : (size_t)(end - p);

		if (ll > nl && memmem(p, ll, needle, nl) &&
		    memmem(p, ll, pat, strlen(pat)))
			return 1;
		if (!nlp)
			break;
		p = nlp + 1;
	}
	return 0;
}

/* ---- 契约求值 ---- */

struct cp_ares {
	char type[32];
	int pass;
	char expected[256];
	char actual[512];
	char because[300];
};

static int cp_nonblank(const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (!isspace((unsigned char)s[i]))
			return 1;
	return 0;
}

static void cp_clip(char *dst, size_t cap, const char *src, size_t n)
{
	size_t c = n < cap - 1 ? n : cap - 1;

	memcpy(dst, src, c);
	dst[c] = '\0';
}

/*
 * 求值：only_type 非空时只求该类型断言（负向变异用）；skip_syscall=1
 * 时跳过 syscall 断言（未适配跑根本 exec 不到目标，轨迹断言无意义）。
 * 返回总条数；failed 出参为失败条数；unverifiable 出参为"需要轨迹但
 * 轨迹不可用"的条数。
 */
static int cp_eval(const struct cp_adapter *a, const struct cp_run *r,
		   int ran_unadapted, int skip_syscall,
		   struct cp_ares *res, int max, int *failed,
		   int *unverifiable)
{
	const char *c, *asserts;
	size_t clen, alen;
	int i, total = 0;

	*failed = 0;
	*unverifiable = 0;
	if (!jobj(a->raw, a->rawlen, "contract", &c, &clen))
		return 0;
	if (!jarr(c, clen, "assert", &asserts, &alen))
		return 0;
	for (i = 0; i < max; i++) {
		const char *e;
		size_t el;
		int ty, pass = 0;
		char *type, *because, *val, *match;
		long long num;
		struct cp_ares *o;

		if (ai_json_arr_get(asserts, alen, i, &e, &el, &ty) != 1)
			break;
		if (ty != AI_JSON_OBJ)
			continue;
		type = jstr(e, el, "type");
		if (!type)
			continue;
		val = jstr(e, el, "value");
		match = jstr(e, el, "match");
		because = jstr(e, el, "because");
		num = jll(e, el, "value", 0);
		o = &res[total];
		memset(o, 0, sizeof(*o));
		snprintf(o->type, sizeof(o->type), "%s", type);
		if (because)
			snprintf(o->because, sizeof(o->because), "%s", because);

		if (!strcmp(type, "exit_code")) {
			snprintf(o->expected, sizeof(o->expected), "exit=%lld",
				 num);
			snprintf(o->actual, sizeof(o->actual), "exit=%d%s",
				 r->exit_code, r->timed_out ? "（超时）" : "");
			pass = !r->timed_out && r->exit_code == (int)num;
		} else if (!strcmp(type, "stdout_nonempty")) {
			snprintf(o->expected, sizeof(o->expected),
				 "stdout 非空白");
			snprintf(o->actual, sizeof(o->actual),
				 "stdout=%zu 字节%s",
				 r->out_len,
				 cp_nonblank(r->out, r->out_len) ? "" :
				 "（空白/空）");
			pass = cp_nonblank(r->out, r->out_len);
		} else if (!strcmp(type, "stdout_contains")) {
			snprintf(o->expected, sizeof(o->expected),
				 "stdout 含 %s", val ? val : "");
			snprintf(o->actual, sizeof(o->actual), "stdout=%s",
				 r->out_len ? r->out : "(空)");
			pass = val && r->out_len &&
			       memmem(r->out, r->out_len, val, strlen(val));
		} else if (!strcmp(type, "stderr_not_contains")) {
			snprintf(o->expected, sizeof(o->expected),
				 "stderr 不含 %s", val ? val : "");
			snprintf(o->actual, sizeof(o->actual),
				 "stderr=%zu 字节", r->err_len);
			pass = !(val && r->err_len &&
				 memmem(r->err, r->err_len, val, strlen(val)));
		} else if (!strcmp(type, "max_ms")) {
			snprintf(o->expected, sizeof(o->expected),
				 "耗时 <= %lldms", num);
			snprintf(o->actual, sizeof(o->actual), "%lldms",
				 r->ms);
			pass = r->ms <= num;
		} else if (!strcmp(type, "syscall_seen") ||
			   !strcmp(type, "syscall_absent_errno")) {
			if (skip_syscall) {
				/* 本趟不判轨迹（apply 试跑 / 输出变异负向）：
				 * 不计数、不算失败，避免"跳过"被当成"通过" */
				free(type);
				free(val);
				free(match);
				free(because);
				continue;
			}
			if (ran_unadapted || !a->trace || !a->trace_len) {
				snprintf(o->expected, sizeof(o->expected),
					 "%s %s", type, match ? match : "");
				snprintf(o->actual, sizeof(o->actual),
					 ran_unadapted ? "未适配跑：不做轨迹判定"
						       : "syscall 轨迹不可用");
				pass = 0;
				(*unverifiable)++;
			} else if (!strcmp(type, "syscall_seen")) {
				int ok_only = jbool(e, el, "ok_only", 0);

				snprintf(o->expected, sizeof(o->expected),
					 "轨迹出现 %s%s",
					 match ? match : "",
					 ok_only ? "（成功返回）" : "");
				pass = match && cp_line_has(a->trace,
							    a->trace_len,
							    match, ok_only);
				snprintf(o->actual, sizeof(o->actual),
					 pass ? "已出现" : "未出现");
			} else {
				snprintf(o->expected, sizeof(o->expected),
					 "轨迹不出现 %s 的 %s", match ? match : "",
					 val ? val : "ENOENT");
				pass = match && !cp_line_has_errno(
					a->trace, a->trace_len, match,
					val ? val : "ENOENT");
				snprintf(o->actual, sizeof(o->actual),
					 pass ? "未出现" : "仍出现（失败）");
			}
		} else {
			snprintf(o->expected, sizeof(o->expected),
				 "未知断言类型 %s", type);
			snprintf(o->actual, sizeof(o->actual), "-");
			pass = 0;
		}
		o->pass = pass;
		if (!pass)
			(*failed)++;
		total++;
		free(type);
		free(val);
		free(match);
		free(because);
	}
	return total;
}

/* ---- 轨迹采集：只在宿主侧包一层 strace ---- */
static const char *cp_strace_bin(void)
{
	static const char *cand[] = { "/usr/bin/strace", "/bin/strace",
				      "/usr/local/bin/strace" };
	size_t i;

	for (i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
		if (access(cand[i], X_OK) == 0)
			return cand[i];
	return NULL;
}

static int cp_run_traced(struct cp_sb *sb, char *const env[], int env_n,
			 int timeout_s, const char *trace_path,
			 struct cp_run *r)
{
	const char *st = trace_path ? cp_strace_bin() : NULL;
	char *argv[112];
	int n = 0, i, rc;

	if (st) {
		argv[n++] = (char *)st;
		argv[n++] = (char *)"-f";
		argv[n++] = (char *)"-q";
		argv[n++] = (char *)"-s";
		argv[n++] = (char *)"160";
		argv[n++] = (char *)"-e";
		argv[n++] = (char *)"trace=execve,execveat,openat,open,"
				     "access,newfstatat,stat";
		argv[n++] = (char *)"-o";
		argv[n++] = (char *)trace_path;
		argv[n++] = (char *)"--";
	}
	for (i = 0; i < sb->n && n < 111; i++)
		argv[n++] = sb->argv[i];
	argv[n] = NULL;
	rc = cp_spawn(argv, env, env_n, timeout_s, r);
	r->exec_fail = !!(r->out_len == 0 && r->err_len == 0 &&
			  r->exit_code == 127);
	return rc;
}

/* ======================================================================
 * 6) 适配器解析 + 校验
 * ====================================================================== */

static int cp_parse_arr_strs(const char *obj, size_t len, const char *key,
			     char dst[][PATH_MAX], int max)
{
	const char *arr;
	size_t alen;
	int i, n = 0;

	if (!jarr(obj, len, key, &arr, &alen))
		return 0;
	for (i = 0; i < max; i++) {
		const char *e;
		size_t el;
		int ty;
		char *s;

		if (ai_json_arr_get(arr, alen, i, &e, &el, &ty) != 1)
			break;
		if (ty != AI_JSON_STR)
			continue;
		s = ai_json_strdup_str(e, el);
		if (!s)
			continue;
		snprintf(dst[n], PATH_MAX, "%s", s);
		free(s);
		n++;
	}
	return n;
}

static int cp_adapter_load(const char *name, struct cp_adapter *a, char *err,
			   size_t errcap)
{
	char path[PATH_MAX];
	const char *o, *t, *l, *l0, *l2, *c;
	size_t olen, tlen, llen, l0len, l2len, clen;
	char *s;
	int i;

	memset(a, 0, sizeof(*a));
	snprintf(a->name, sizeof(a->name), "%s", name);
	cp_adapter_path(name, path, sizeof(path));
	a->raw = cp_read_file(path, CP_READ_MAX, &a->rawlen);
	if (!a->raw) {
		snprintf(err, errcap, "适配器不存在或不可读：%s", path);
		return -1;
	}
	o = a->raw;
	olen = a->rawlen;
	s = jstr(o, olen, "schema");
	if (!s) {
		snprintf(err, errcap, "适配器缺 schema：%s", path);
		return -1;
	}
	if (strcmp(s, AI_COMPAT_SCHEMA) != 0) {
		snprintf(err, errcap, "schema 不匹配（%s，期望 %s）", s,
			 AI_COMPAT_SCHEMA);
		free(s);
		return -1;
	}
	free(s);
	if (!jobj(o, olen, "target", &t, &tlen) ||
	    !jobj(o, olen, "layers", &l, &llen) ||
	    !jobj(l, llen, "L0", &l0, &l0len) ||
	    !jobj(l, llen, "L2", &l2, &l2len) ||
	    !jobj(o, olen, "contract", &c, &clen)) {
		snprintf(err, errcap, "适配器缺少 target/layers.L0/L2/contract");
		return -1;
	}
	s = jstr(t, tlen, "host");
	if (s)
		snprintf(a->host, sizeof(a->host), "%s", s);
	free(s);
	s = jstr(t, tlen, "inside");
	if (s)
		snprintf(a->inside, sizeof(a->inside), "%s", s);
	free(s);
	s = jstr(t, tlen, "kind");
	if (s)
		snprintf(a->kind, sizeof(a->kind), "%s", s);
	free(s);
	s = jstr(l2, l2len, "workspace");
	if (s)
		snprintf(a->ws, sizeof(a->ws), "%s", s);
	free(s);
	s = jstr(l2, l2len, "backing");
	if (s)
		snprintf(a->backing, sizeof(a->backing), "%s", s);
	free(s);
	s = jstr(l2, l2len, "stage");
	if (s)
		snprintf(a->stage, sizeof(a->stage), "%s", s);
	free(s);
	a->usr_overlay = jbool(l2, l2len, "usr_overlay", 0);
	a->timeout_s = (int)jll(c, clen, "timeout_s", 10);
	a->n_argv = cp_parse_arr_strs(c, clen, "argv", a->argv,
				      CP_MAX_ARGV);

	/* L0.env[] */
	{
		const char *arr;
		size_t alen;
		int idx;

		if (jarr(l0, l0len, "env", &arr, &alen)) {
			for (idx = 0; idx < CP_MAX_ENV; idx++) {
				const char *e;
				size_t el;
				int ty;
				char *k, *v;

				if (ai_json_arr_get(arr, alen, idx, &e, &el,
						    &ty) != 1)
					break;
				if (ty != AI_JSON_OBJ)
					continue;
				k = jstr(e, el, "key");
				v = jstr(e, el, "value");
				if (!k || !v) {
					free(k);
					free(v);
					continue;
				}
				snprintf(a->env[a->n_env].key, 128, "%s", k);
				snprintf(a->env[a->n_env].val, PATH_MAX, "%s",
					 v);
				s = jstr(e, el, "because");
				if (s)
					snprintf(a->env[a->n_env].because,
						 sizeof(a->env[0].because),
						 "%s", s);
				free(s);
				free(k);
				free(v);
				a->n_env++;
			}
		}
	}
	/* L0.path_map[] / lib_redirect[] / chmod[] */
	{
		const char *arr;
		size_t alen;
		int idx;

		if (jarr(l0, l0len, "path_map", &arr, &alen)) {
			for (idx = 0; idx < CP_MAX_MAP; idx++) {
				const char *e;
				size_t el;
				int ty;
				char *fr, *to;

				if (ai_json_arr_get(arr, alen, idx, &e, &el,
						    &ty) != 1)
					break;
				if (ty != AI_JSON_OBJ)
					continue;
				fr = jstr(e, el, "from");
				to = jstr(e, el, "to");
				if (!fr || !to) {
					free(fr);
					free(to);
					continue;
				}
				snprintf(a->map[a->n_map].from, PATH_MAX,
					 "%s", fr);
				snprintf(a->map[a->n_map].to, PATH_MAX, "%s",
					 to);
				s = jstr(e, el, "because");
				if (s)
					snprintf(a->map[a->n_map].because,
						 sizeof(a->map[0].because),
						 "%s", s);
				free(s);
				free(fr);
				free(to);
				a->n_map++;
			}
		}
		if (jarr(l0, l0len, "lib_redirect", &arr, &alen)) {
			for (idx = 0; idx < CP_MAX_LIBS; idx++) {
				const char *e;
				size_t el;
				int ty;
				char *sn, *fr, *to;

				if (ai_json_arr_get(arr, alen, idx, &e, &el,
						    &ty) != 1)
					break;
				if (ty != AI_JSON_OBJ)
					continue;
				sn = jstr(e, el, "soname");
				fr = jstr(e, el, "from");
				to = jstr(e, el, "to");
				if (!sn || !fr || !to) {
					free(sn);
					free(fr);
					free(to);
					continue;
				}
				snprintf(a->lib[a->n_lib].soname, 128, "%s",
					 sn);
				snprintf(a->lib[a->n_lib].src, PATH_MAX, "%s",
					 fr);
				snprintf(a->lib[a->n_lib].dst, PATH_MAX, "%s",
					 to);
				s = jstr(e, el, "because");
				if (s)
					snprintf(a->lib[a->n_lib].because,
						 sizeof(a->lib[0].because),
						 "%s", s);
				free(s);
				free(sn);
				free(fr);
				free(to);
				a->n_lib++;
			}
		}
		if (jarr(l0, l0len, "chmod", &arr, &alen)) {
			for (idx = 0; idx < 4; idx++) {
				const char *e;
				size_t el;
				int ty;
				char *pa, *mo;

				if (ai_json_arr_get(arr, alen, idx, &e, &el,
						    &ty) != 1)
					break;
				if (ty != AI_JSON_OBJ)
					continue;
				pa = jstr(e, el, "path");
				mo = jstr(e, el, "mode");
				if (!pa || !mo) {
					free(pa);
					free(mo);
					continue;
				}
				snprintf(a->chm[a->n_chm].path, PATH_MAX, "%s",
					 pa);
				snprintf(a->chm[a->n_chm].mode, 16, "%s", mo);
				s = jstr(e, el, "because");
				if (s)
					snprintf(a->chm[a->n_chm].because,
						 sizeof(a->chm[0].because),
						 "%s", s);
				free(s);
				free(pa);
				free(mo);
				a->n_chm++;
			}
		}
	}
	/* L2.install[] */
	{
		const char *arr;
		size_t alen;
		int idx;

		if (jarr(l2, l2len, "install", &arr, &alen)) {
			for (idx = 0; idx < CP_MAX_INST; idx++) {
				const char *e;
				size_t el;
				int ty;
				char *fr, *to;

				if (ai_json_arr_get(arr, alen, idx, &e, &el,
						    &ty) != 1)
					break;
				if (ty != AI_JSON_OBJ)
					continue;
				fr = jstr(e, el, "from");
				to = jstr(e, el, "to");
				if (!fr || !to) {
					free(fr);
					free(to);
					continue;
				}
				snprintf(a->inst[a->n_inst].src, PATH_MAX,
					 "%s", fr);
				snprintf(a->inst[a->n_inst].dst, PATH_MAX, "%s",
					 to);
				s = jstr(e, el, "because");
				if (s)
					snprintf(a->inst[a->n_inst].because,
						 sizeof(a->inst[0].because),
						 "%s", s);
				free(s);
				free(fr);
				free(to);
				a->n_inst++;
			}
		}
	}
	/* 每条规则的 because 必须存在（否则拒绝应用：没有理由的规则=黑箱） */
	for (i = 0; i < a->n_map; i++)
		if (!a->map[i].because[0]) {
			snprintf(err, errcap, "path_map[%d] 缺 because", i);
			return -1;
		}
	for (i = 0; i < a->n_lib; i++)
		if (!a->lib[i].because[0]) {
			snprintf(err, errcap, "lib_redirect[%d] 缺 because", i);
			return -1;
		}
	for (i = 0; i < a->n_env; i++)
		if (!a->env[i].because[0]) {
			snprintf(err, errcap, "env[%d] 缺 because", i);
			return -1;
		}
	return 0;
}

/* 适配器数据的安检：路径必须在 workspace 的 stage / upper 前缀内 */
static int cp_adapter_validate(struct cp_adapter *a, char *err, size_t errcap)
{
	int i;

	if (!ai_compat_valid_name(a->name)) {
		snprintf(err, errcap, "适配器名非法：%s", a->name);
		return -1;
	}
	if (!ai_ws_valid_name(a->ws)) {
		snprintf(err, errcap, "workspace 名非法：%s", a->ws);
		return -1;
	}
	if (strcmp(a->backing, "disk") != 0 && strcmp(a->backing, "tmpfs")) {
		snprintf(err, errcap, "backing 非法：%s", a->backing);
		return -1;
	}
	if (!cp_safe_path(a->stage) || !cp_under(a->stage, CP_STAGE_PFX)) {
		snprintf(err, errcap, "stage 必须位于 %s 下：%s", CP_STAGE_PFX,
			 a->stage);
		return -1;
	}
	if (!cp_safe_path(a->inside) || !cp_under(a->inside, a->stage)) {
		snprintf(err, errcap, "target.inside 必须在 stage 内：%s",
			 a->inside);
		return -1;
	}
	if (a->n_argv < 1 || !cp_safe_path(a->argv[0]) ||
	    !cp_under(a->argv[0], a->stage)) {
		snprintf(err, errcap, "contract.argv[0] 必须是 stage 内的路径");
		return -1;
	}
	for (i = 1; i < a->n_argv; i++)
		if (a->argv[i][0] == '/' && !cp_safe_path(a->argv[i])) {
			snprintf(err, errcap, "contract.argv[%d] 路径不安全", i);
			return -1;
		}
	if (a->timeout_s < 1 || a->timeout_s > 600) {
		snprintf(err, errcap, "contract.timeout_s 非法：%d",
			 a->timeout_s);
		return -1;
	}
	for (i = 0; i < a->n_map; i++) {
		if (!cp_safe_path(a->map[i].from) ||
		    !cp_safe_path(a->map[i].to)) {
			snprintf(err, errcap, "path_map[%d] 路径不安全", i);
			return -1;
		}
		if (!cp_under(a->map[i].from, "/usr") &&
		    !cp_under(a->map[i].from, "/bin") &&
		    !cp_under(a->map[i].from, "/sbin") &&
		    !cp_under(a->map[i].from, "/lib") &&
		    !cp_under(a->map[i].from, "/lib64")) {
			snprintf(err, errcap,
				 "path_map[%d].from 只允许系统视图路径：%s", i,
				 a->map[i].from);
			return -1;
		}
		if (!a->usr_overlay) {
			snprintf(err, errcap,
				 "path_map 存在但 usr_overlay=false（规则无处"
				 "落地）");
			return -1;
		}
	}
	for (i = 0; i < a->n_lib; i++) {
		if (!cp_safe_path(a->lib[i].src) ||
		    strstr(a->lib[i].soname, "/") ||
		    strstr(a->lib[i].soname, "..") ||
		    !cp_safe_path(a->lib[i].dst) ||
		    !cp_under(a->lib[i].dst, a->stage)) {
			snprintf(err, errcap, "lib_redirect[%d] 不安全", i);
			return -1;
		}
	}
	for (i = 0; i < a->n_inst; i++)
		if (!cp_safe_path(a->inst[i].src) ||
		    !cp_safe_path(a->inst[i].dst) ||
		    !cp_under(a->inst[i].dst, a->stage)) {
			snprintf(err, errcap, "install[%d] 不安全", i);
			return -1;
		}
	for (i = 0; i < a->n_chm; i++)
		if (!cp_safe_path(a->chm[i].path) ||
		    !cp_under(a->chm[i].path, a->stage) ||
		    strlen(a->chm[i].mode) != 4 ||
		    strspn(a->chm[i].mode, "01234567") != 4) {
			snprintf(err, errcap, "chmod[%d] 不安全", i);
			return -1;
		}
	return 0;
}

/* ======================================================================
 * 7) apply / verify
 * ====================================================================== */

static void cp_env_array(struct cp_adapter *a, char *env[CP_MAX_ENV])
{
	int i;

	for (i = 0; i < a->n_env; i++) {
		size_t need = strlen(a->env[i].key) + strlen(a->env[i].val) + 2;

		env[i] = malloc(need);
		if (env[i])
			snprintf(env[i], need, "%s=%s", a->env[i].key,
				 a->env[i].val);
	}
}

static void cp_env_free(char *env[], int n)
{
	int i;

	for (i = 0; i < n; i++)
		free(env[i]);
}

/* 生成 prepare 脚本（在 workspace 内执行；路径已过 cp_safe_path） */
static char *cp_prepare_script(struct cp_adapter *a, size_t *len)
{
	char *buf = NULL;
	FILE *f = open_memstream(&buf, len);
	int i;

	if (!f)
		return NULL;
	fputs("set -e\n", f);
	fputs("umask 022\n", f);
	fprintf(f, "mkdir -p '%s'\n", a->stage);
	fprintf(f, "rm -rf '%s/app'\n", a->stage);
	fprintf(f, "mkdir -p '%s/app'\n", a->stage);
	fprintf(f, "rm -rf '%s/lib'\n", a->stage);
	fprintf(f, "mkdir -p '%s/lib'\n", a->stage);
	for (i = 0; i < a->n_inst; i++) {
		char dir[PATH_MAX];
		char *slash;

		snprintf(dir, sizeof(dir), "%s", a->inst[i].dst);
		slash = strrchr(dir, '/');
		if (slash && slash != dir) {
			*slash = '\0';
			fprintf(f, "mkdir -p '%s'\n", dir);
		}
		/* 不用 cp -a：沙盒内只留 CAP_NET_RAW，无法 chown，
		 * 源属主非 root 时 -a 会失败（W82B 取证实测踩到）。
		 * cp 保留模式位（umask 022），属主统一为沙盒 root。 */
		fprintf(f, "cp -f '%s' '%s'\n", a->inst[i].src,
			a->inst[i].dst);
	}
	for (i = 0; i < a->n_lib; i++)
		fprintf(f, "cp -f '%s' '%s'\n", a->lib[i].src,
			a->lib[i].dst);
	for (i = 0; i < a->n_chm; i++)
		fprintf(f, "chmod '%s' '%s'\n", a->chm[i].mode,
			a->chm[i].path);
	for (i = 0; i < a->n_map; i++) {
		char dir[PATH_MAX];
		char shim[PATH_MAX];
		char *slash;

		cp_shim_path(a->map[i].from, shim, sizeof(shim));
		snprintf(dir, sizeof(dir), "%s", shim);
		slash = strrchr(dir, '/');
		if (slash && slash != dir) {
			*slash = '\0';
			fprintf(f, "mkdir -p '%s'\n", dir);
		}
		fprintf(f, "printf '%%s\\n' '#!/bin/sh' 'exec %s \"$@\"' > "
			"'%s'\n", a->map[i].to, shim);
		fprintf(f, "chmod 0755 '%s'\n", shim);
	}
	fprintf(f, "test -x '%s'\n", a->inside);
	fputs("echo PREPARE_OK\n", f);
	fclose(f);
	return buf;
}

static char *cp_rollback_script(struct cp_adapter *a, size_t *len)
{
	char *buf = NULL;
	FILE *f = open_memstream(&buf, len);
	int i;

	if (!f)
		return NULL;
	fputs("rm -rf '", f);
	fputs(a->stage, f);
	fputs("'\n", f);
	for (i = 0; i < a->n_map; i++) {
		char shim[PATH_MAX];

		cp_shim_path(a->map[i].from, shim, sizeof(shim));
		fprintf(f, "rm -f '%s'\n", shim);
	}
	fputs("echo ROLLBACK_OK\n", f);
	fclose(f);
	return buf;
}

static int cp_ws_ensure(struct cp_adapter *a, const char *ws, int *created,
			char *err, size_t errcap)
{
	struct ai_ws_info info;
	char *o = NULL;
	int rc;

	*created = 0;
	if (ai_ws_info_get(ws, &info) == 0)
		return 0;
	rc = ai_ws_ensure_backing(ws, a->backing, 256, 1, &o, created);
	if (rc != AI_OK) {
		snprintf(err, errcap, "创建 workspace '%s' 失败：%s", ws,
			 o ? o : "(无输出)");
		free(o);
		return -1;
	}
	free(o);
	return 0;
}

static int cp_ws_exec(const char *ws, const char *script, int overlay,
		      char *const env[], int env_n, int timeout_s,
		      struct cp_run *r, char *err, size_t errcap)
{
	struct ai_ws_info info;
	struct cp_sb sb;
	char *targv[4];

	if (ai_ws_info_get(ws, &info)) {
		snprintf(err, errcap, "workspace '%s' 不存在", ws);
		return -1;
	}
	targv[0] = (char *)"/bin/sh";
	targv[1] = (char *)"-c";
	targv[2] = (char *)script;
	targv[3] = NULL;
	if (cp_sb_build(&sb, ws, &info, overlay, NULL, 0, targv, 3)) {
		snprintf(err, errcap, "argv 组装失败");
		return -1;
	}
	return cp_spawn(sb.argv, env, env_n, timeout_s, r);
}

/* prepare 需要把宿主源目录 ro-bind 进 workspace 才能 cp */
static int cp_prepare(struct cp_adapter *a, const char *ws, char *err,
		      size_t errcap)
{
	struct ai_ws_info info;
	struct cp_sb sb;
	char *targv[4];
	char dirs[CP_MAX_INST + CP_MAX_LIBS][PATH_MAX];
	char *roptrs[CP_MAX_INST + CP_MAX_LIBS];
	int dir_n = 0, i, rc;
	char *script;
	size_t slen = 0;
	struct cp_run r;

	script = cp_prepare_script(a, &slen);
	if (!script) {
		snprintf(err, errcap, "内存不足");
		return -1;
	}
	if (ai_ws_info_get(ws, &info)) {
		snprintf(err, errcap, "workspace '%s' 不存在", ws);
		free(script);
		return -1;
	}
	for (i = 0; i < a->n_inst; i++)
		(void)cp_add_dir(dirs, &dir_n, CP_MAX_INST + CP_MAX_LIBS,
				 a->inst[i].src);
	for (i = 0; i < a->n_lib; i++)
		(void)cp_add_dir(dirs, &dir_n, CP_MAX_INST + CP_MAX_LIBS,
				 a->lib[i].src);
	for (i = 0; i < dir_n; i++)
		roptrs[i] = dirs[i];
	targv[0] = (char *)"/bin/sh";
	targv[1] = (char *)"-c";
	targv[2] = script;
	targv[3] = NULL;
	if (cp_sb_build(&sb, ws, &info, 0, roptrs, dir_n, targv, 3)) {
		snprintf(err, errcap, "argv 组装失败（ro-path 过多）");
		free(script);
		return -1;
	}
	rc = cp_spawn(sb.argv, NULL, 0, 60, &r);
	free(script);
	if (rc) {
		snprintf(err, errcap, "fork 失败");
		return -1;
	}
	if (r.exit_code != 0 || !r.out || !strstr(r.out, "PREPARE_OK")) {
		snprintf(err, errcap,
			 "workspace 内落地失败（exit=%d）：%s %.600s",
			 r.exit_code, r.err ? r.err : "", r.out ? r.out : "");
		cp_run_free(&r);
		return -1;
	}
	cp_run_free(&r);
	return 0;
}

static int cp_rollback(struct cp_adapter *a, const char *ws, int created,
		       char *err, size_t errcap)
{
	char *script;
	size_t slen = 0;
	struct cp_run r;
	struct ai_ws_info info;
	int rc = 0;

	if (ai_ws_info_get(ws, &info) == 0) {
		script = cp_rollback_script(a, &slen);
		if (script) {
			memset(&r, 0, sizeof(r));
			if (cp_ws_exec(ws, script, 0, NULL, 0, 30, &r, err,
				       errcap) || r.exit_code != 0)
				rc = -1;
			cp_run_free(&r);
			free(script);
		}
	}
	if (created) {
		char *o = NULL;

		if (ai_ws_destroy(ws, &o) != AI_OK)
			rc = -1;
		free(o);
	}
	return rc;
}

static void cp_apply_state_write(const struct cp_adapter *a, const char *ws,
				 int created, const struct cp_run *trial,
				 char *path, size_t pcap)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *f;
	char ts[40];

	cp_state_path(a->name, path, pcap);
	f = open_memstream(&buf, &len);
	if (!f)
		return;
	cp_now_iso(ts, sizeof(ts));
	fputs("{\"schema\":", f);
	cp_jstr(f, AI_COMPAT_SCHEMA);
	fputs(",\"adapter\":", f);
	cp_jstr(f, a->name);
	fputs(",\"workspace\":", f);
	cp_jstr(f, ws);
	fprintf(f, ",\"created_workspace\":%s", created ? "true" : "false");
	fputs(",\"stage\":", f);
	cp_jstr(f, a->stage);
	fprintf(f, ",\"applied_at\":");
	cp_jstr(f, ts);
	fprintf(f, ",\"trial\":{\"exit_code\":%d,\"ms\":%lld,"
		"\"stdout_bytes\":%zu,\"stderr_bytes\":%zu}",
		trial->exit_code, trial->ms, trial->out_len, trial->err_len);
	fputs(",\"rolled_back\":false}", f);
	fclose(f);
	if (buf) {
		(void)cp_ensure_dirs();
		(void)cp_write_atomic(path, buf, len, 0600);
	}
	free(buf);
}

static int cp_state_read(const char *name, char *ws, size_t wcap,
			 int *created, char *err, size_t errcap)
{
	char path[PATH_MAX];
	size_t len = 0;
	char *raw;
	char *s;
	int rc = -1;

	cp_state_path(name, path, sizeof(path));
	raw = cp_read_file(path, 65536, &len);
	if (!raw) {
		snprintf(err, errcap, "适配器 '%s' 尚未 apply（缺 state/%s."
			 "applied.json）", name, name);
		return -1;
	}
	s = jstr(raw, len, "workspace");
	if (s && ai_ws_valid_name(s)) {
		snprintf(ws, wcap, "%s", s);
		*created = jbool(raw, len, "created_workspace", 0);
		rc = 0;
	} else {
		snprintf(err, errcap, "state 文件缺 workspace");
	}
	free(s);
	free(raw);
	return rc;
}

static void cp_emit_run(FILE *f, const struct cp_run *r)
{
	fputs("{\"exit_code\":", f);
	fprintf(f, "%d,\"ms\":%lld,\"stdout_bytes\":%zu,"
		"\"stderr_bytes\":%zu,\"timed_out\":%s,\"truncated\":%s,",
		r->exit_code, r->ms, r->out_len, r->err_len,
		r->timed_out ? "true" : "false",
		r->truncated ? "true" : "false");
	fputs("\"stdout\":", f);
	{
		char tmp[1200];

		cp_clip(tmp, sizeof(tmp), r->out ? r->out : "",
			r->out_len < 1000 ? r->out_len : 1000);
		cp_jstr(f, tmp);
	}
	fputs(",\"stderr\":", f);
	{
		char tmp[600];

		cp_clip(tmp, sizeof(tmp), r->err ? r->err : "",
			r->err_len < 500 ? r->err_len : 500);
		cp_jstr(f, tmp);
	}
	fputc('}', f);
}

static void cp_emit_ares(FILE *f, const struct cp_ares *res, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (i)
			fputc(',', f);
		fputs("{\"type\":", f);
		cp_jstr(f, res[i].type);
		fprintf(f, ",\"pass\":%s,\"expected\":", res[i].pass ?
			"true" : "false");
		cp_jstr(f, res[i].expected);
		fputs(",\"actual\":", f);
		cp_jstr(f, res[i].actual);
		if (res[i].because[0]) {
			fputs(",\"because\":", f);
			cp_jstr(f, res[i].because);
		}
		fputc('}', f);
	}
}

static int cp_apply_trial(struct cp_adapter *a, const char *ws,
			  struct cp_run *r, char *err, size_t errcap)
{
	struct ai_ws_info info;
	struct cp_sb sb;
	char *env[CP_MAX_ENV];
	int en = 0, i, rc;
	char *targv[CP_MAX_ARGV + 1];
	char trace[PATH_MAX];
	const char *sb_strace;

	for (i = 0; i < a->n_argv; i++)
		targv[i] = a->argv[i];
	targv[a->n_argv] = NULL;
	cp_env_array(a, env);
	en = a->n_env;
	if (ai_ws_info_get(ws, &info)) {
		snprintf(err, errcap, "workspace '%s' 不存在", ws);
		cp_env_free(env, en);
		return -1;
	}
	if (cp_sb_build(&sb, ws, &info, a->usr_overlay, NULL, 0, targv,
			a->n_argv)) {
		snprintf(err, errcap, "argv 组装失败");
		cp_env_free(env, en);
		return -1;
	}
	sb_strace = cp_strace_bin();
	snprintf(trace, sizeof(trace), "/tmp/aik-compat-trial-%ld.trace",
		 (long)getpid());
	rc = cp_run_traced(&sb, env, en, a->timeout_s,
			   sb_strace ? trace : NULL, r);
	cp_env_free(env, en);
	if (rc) {
		snprintf(err, errcap, "fork 失败");
		return -1;
	}
	a->trace = cp_read_file(trace, CP_READ_MAX, &a->trace_len);
	unlink(trace);
	return 0;
}

static int cp_apply(const char *args, size_t alen, char **out)
{
	char *name = jstr(args, alen, "name");
	char *wso = jstr(args, alen, "workspace");
	int do_rb = jbool(args, alen, "rollback", 0);
	struct cp_adapter a;
	char err[1024] = "";
	char ws[64];
	const char *ws_use;
	int created = 0, rc = AI_OK, i;
	struct cp_run trial;
	char state_path[PATH_MAX];
	char *buf = NULL;
	size_t blen = 0;
	FILE *f;

	*out = NULL;
	memset(&trial, 0, sizeof(trial));
	if (!ai_compat_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法 name：%s", name ? name : "(无)")
		    < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}
	if (cp_adapter_load(name, &a, err, sizeof(err)) ||
	    cp_adapter_validate(&a, err, sizeof(err))) {
		if (asprintf(out, "ERROR: 适配器不可用：%s", err) < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		cp_adapter_free(&a);
		goto done;
	}
	snprintf(ws, sizeof(ws), "%s", a.ws);
	ws_use = ws;
	if (wso && wso[0]) {
		if (!ai_ws_valid_name(wso)) {
			if (asprintf(out, "ERROR: 非法 workspace：%s", wso) < 0)
				*out = NULL;
			rc = AI_ERR_INVALID_ARG;
			cp_adapter_free(&a);
			goto done;
		}
		snprintf(ws, sizeof(ws), "%s", wso);
	}
	if (do_rb) {
		int cre = 0;
		char sws[64];

		if (cp_state_read(name, sws, sizeof(sws), &cre, err,
				  sizeof(err))) {
			/* 没有 state 也允许按适配器声明回滚（幂等） */
			snprintf(sws, sizeof(sws), "%s", ws_use);
		}
		(void)cp_rollback(&a, sws, cre, err, sizeof(err));
		cp_state_path(name, state_path, sizeof(state_path));
		unlink(state_path);
		if (asprintf(out, "{\"ok\":true,\"adapter\":\"%s\","
			     "\"workspace\":\"%s\",\"rolled_back\":true,"
			     "\"because\":\"stage 与 overlay upper shim 已删；"
			     "本次 apply 新建的 workspace 已销毁\"}",
			     name, sws) < 0)
			*out = NULL;
		cp_audit("compat_apply", "adapter=%s action=rollback "
			 "workspace=%s", name, sws);
		cp_adapter_free(&a);
		goto done;
	}
	if (cp_ws_ensure(&a, ws, &created, err, sizeof(err))) {
		if (asprintf(out, "ERROR: %s", err) < 0)
			*out = NULL;
		rc = AI_ERR_STORAGE;
		cp_adapter_free(&a);
		goto done;
	}
	if (cp_prepare(&a, ws, err, sizeof(err))) {
		(void)cp_rollback(&a, ws, created, err, sizeof(err));
		if (asprintf(out, "ERROR: 落地失败（已回滚）：%s", err) < 0)
			*out = NULL;
		rc = AI_ERR_GENERIC;
		cp_adapter_free(&a);
		goto done;
	}
	if (cp_apply_trial(&a, ws, &trial, err, sizeof(err))) {
		(void)cp_rollback(&a, ws, created, err, sizeof(err));
		if (asprintf(out, "ERROR: 试跑无法启动（已回滚）：%s", err) < 0)
			*out = NULL;
		rc = AI_ERR_GENERIC;
		cp_adapter_free(&a);
		goto done;
	}
	{
		struct cp_ares res[64];
		int failed = 0, unver = 0, total;
		/* trial 只做非轨迹断言；轨迹由 verify 负责 */
		char *save_trace = a.trace;
		size_t save_len = a.trace_len;

		a.trace = NULL;
		a.trace_len = 0;
		total = cp_eval(&a, &trial, 0, 1, res, 64, &failed, &unver);
		a.trace = save_trace;
		a.trace_len = save_len;
		if (trial.exit_code != 0 || failed > 0 || trial.timed_out) {
			if (asprintf(out,
				     "ERROR: 试跑未通过契约（%d/%d 断言失败，"
				     "exit=%d%s），已自动回滚\nstdout: %.600s\n"
				     "stderr: %.400s",
				     failed, total, trial.exit_code,
				     trial.timed_out ? "，超时" : "",
				     trial.out ? trial.out : "",
				     trial.err ? trial.err : "") < 0)
				*out = NULL;
			(void)cp_rollback(&a, ws, created, err, sizeof(err));
			rc = AI_ERR_GENERIC;
			cp_adapter_free(&a);
			cp_run_free(&trial);
			goto done;
		}
	}
	cp_apply_state_write(&a, ws, created, &trial, state_path,
			     sizeof(state_path));
	f = open_memstream(&buf, &blen);
	if (!f) {
		rc = AI_ERR_MEMORY;
		cp_adapter_free(&a);
		cp_run_free(&trial);
		goto done;
	}
	fputs("{\"ok\":true,\"adapter\":", f);
	cp_jstr(f, a.name);
	fputs(",\"workspace\":", f);
	cp_jstr(f, ws);
	fprintf(f, ",\"created_workspace\":%s", created ? "true" : "false");
	fputs(",\"rules\":{\"path_map\":", f);
	fprintf(f, "%d,\"lib_redirect\":%d,\"env\":%d,\"install\":%d,"
		"\"chmod\":%d,\"usr_overlay\":%s}", a.n_map, a.n_lib,
		a.n_env, a.n_inst, a.n_chm,
		a.usr_overlay ? "true" : "false");
	fputs(",\"applied\":[", f);
	for (i = 0; i < a.n_inst; i++) {
		if (i)
			fputc(',', f);
		fputs("{\"action\":\"copy\",\"to\":", f);
		cp_jstr(f, a.inst[i].dst);
		fputc('}', f);
	}
	for (i = 0; i < a.n_map; i++) {
		fputs(",{\"action\":\"shim\",\"from\":", f);
		cp_jstr(f, a.map[i].from);
		fputs(",\"to\":", f);
		cp_jstr(f, a.map[i].to);
		fputc('}', f);
	}
	fputs("],\"trial\":", f);
	cp_emit_run(f, &trial);
	fputs(",\"rollback\":{\"available\":true,\"created_workspace\":", f);
	fputs(created ? "true" : "false", f);
	fputs(",\"how\":\"compat_apply {\\\"name\\\":\\\"", f);
	fputs(a.name, f);
	fputs("\\\",\\\"rollback\\\":true}\"},", f);
	fputs("\"note\":\"目标原件未修改；所有落地都在 workspace 内\"}", f);
	fclose(f);
	*out = buf;
	cp_audit("compat_apply", "adapter=%s workspace=%s created=%d "
		 "exit=%d ms=%lld path_map=%d lib=%d", a.name, ws, created,
		 trial.exit_code, trial.ms, a.n_map, a.n_lib);
	cp_adapter_free(&a);
	cp_run_free(&trial);
	goto done;
done:
	free(name);
	free(wso);
	return rc;
}

static int cp_verify(const char *args, size_t alen, char **out)
{
	char *name = jstr(args, alen, "name");
	int want_trace = jbool(args, alen, "trace", 1);
	struct cp_adapter a;
	char err[1024] = "";
	char ws[64];
	int created = 0, rc = AI_OK;
	struct cp_run pos;
	struct ai_ws_info info;
	struct cp_sb sb;
	char *env[CP_MAX_ENV];
	char *targv[CP_MAX_ARGV + 4];
	int en, i, total = 0, failed = 0, unver = 0;
	struct cp_ares res[64];
	char trace_path[PATH_MAX];
	int trace_used = 0;
	int neg_fail = 0, neg_total = 0;
	char neg_detail[3][200];
	int neg_ok[3];
	char *buf = NULL;
	size_t blen = 0;
	FILE *f;

	*out = NULL;
	memset(&pos, 0, sizeof(pos));
	memset(neg_ok, 0, sizeof(neg_ok));
	memset(neg_detail, 0, sizeof(neg_detail));
	if (!ai_compat_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法 name：%s", name ? name : "(无)")
		    < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}
	if (cp_adapter_load(name, &a, err, sizeof(err)) ||
	    cp_adapter_validate(&a, err, sizeof(err))) {
		if (asprintf(out, "ERROR: 适配器不可用：%s", err) < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		cp_adapter_free(&a);
		goto done;
	}
	if (cp_state_read(name, ws, sizeof(ws), &created, err, sizeof(err))) {
		if (asprintf(out, "ERROR: %s", err) < 0)
			*out = NULL;
		rc = AI_ERR_NOT_FOUND;
		cp_adapter_free(&a);
		goto done;
	}
	if (ai_ws_info_get(ws, &info)) {
		if (asprintf(out, "ERROR: state 指向的 workspace '%s' 不存在"
			     "（先 compat_apply）", ws) < 0)
			*out = NULL;
		rc = AI_ERR_NOT_FOUND;
		cp_adapter_free(&a);
		goto done;
	}
	for (i = 0; i < a.n_argv; i++)
		targv[i] = a.argv[i];
	targv[a.n_argv] = NULL;
	cp_env_array(&a, env);
	en = a.n_env;
	if (cp_sb_build(&sb, ws, &info, a.usr_overlay, NULL, 0, targv,
			a.n_argv)) {
		if (asprintf(out, "ERROR: argv 组装失败") < 0)
			*out = NULL;
		rc = AI_ERR_GENERIC;
		cp_env_free(env, en);
		cp_adapter_free(&a);
		goto done;
	}
	snprintf(trace_path, sizeof(trace_path), "/tmp/aik-compat-verify-%ld."
		 "trace", (long)getpid());
	if (want_trace && cp_strace_bin()) {
		rc = cp_run_traced(&sb, env, en, a.timeout_s, trace_path, &pos);
		trace_used = 1;
		a.trace = cp_read_file(trace_path, CP_READ_MAX, &a.trace_len);
	} else {
		rc = cp_spawn(sb.argv, env, en, a.timeout_s, &pos);
	}
	unlink(trace_path);
	if (rc) {
		if (asprintf(out, "ERROR: 无法执行（fork/权限）：%s",
			     strerror(errno)) < 0)
			*out = NULL;
		rc = AI_ERR_GENERIC;
		cp_env_free(env, en);
		cp_adapter_free(&a);
		goto done;
	}
	total = cp_eval(&a, &pos, 0, 0, res, 64, &failed, &unver);

	/* 负向 1：stdout 丢空 -> stdout 断言必须失败 */
	{
		char script[PATH_MAX + 64];
		char *t2[CP_MAX_ARGV + 4];
		struct cp_sb sb2;
		struct cp_ares r2[64];
		int f2 = 0, u2 = 0, t2n = 0;
		int j;

		snprintf(script, sizeof(script),
			 "exec \"$0\" \"$@\" >/dev/null");
		t2[t2n++] = (char *)"/bin/sh";
		t2[t2n++] = (char *)"-c";
		t2[t2n++] = script;
		for (j = 0; j < a.n_argv; j++)
			t2[t2n++] = a.argv[j];
		t2[t2n] = NULL;
		if (!cp_sb_build(&sb2, ws, &info, a.usr_overlay, NULL, 0, t2,
				 t2n)) {
			struct cp_run rr;

			if (!cp_spawn(sb2.argv, env, en, a.timeout_s, &rr)) {
				int tot2 = cp_eval(&a, &rr, 0, 1, r2, 64, &f2,
						   &u2);
				char *st;
				int k, seen = 0;

				(void)tot2;
				for (k = 0; k < tot2 && k < 64; k++)
					if (!strcmp(r2[k].type,
						    "stdout_nonempty") ||
					    !strcmp(r2[k].type,
						    "stdout_contains")) {
						seen++;
					}
				st = NULL;
				neg_total++;
				neg_ok[0] = seen > 0 && f2 > 0;
				snprintf(neg_detail[0],
					 sizeof(neg_detail[0]),
					 "seen_stdout_asserts=%d failed=%d "
					 "exit=%d", seen, f2, rr.exit_code);
				(void)st;
				cp_run_free(&rr);
			}
		}
	}
	/* 负向 2：强制退出码 97 -> exit_code 断言必须失败 */
	{
		char script[PATH_MAX + 64];
		char *t2[CP_MAX_ARGV + 4];
		struct cp_sb sb2;
		struct cp_ares r2[64];
		int f2 = 0, u2 = 0, t2n = 0, j;

		snprintf(script, sizeof(script), "\"$0\" \"$@\"; exit 97");
		t2[t2n++] = (char *)"/bin/sh";
		t2[t2n++] = (char *)"-c";
		t2[t2n++] = script;
		for (j = 0; j < a.n_argv; j++)
			t2[t2n++] = a.argv[j];
		t2[t2n] = NULL;
		if (!cp_sb_build(&sb2, ws, &info, a.usr_overlay, NULL, 0, t2,
				 t2n)) {
			struct cp_run rr;

			if (!cp_spawn(sb2.argv, env, en, a.timeout_s, &rr)) {
				int tot2 = cp_eval(&a, &rr, 0, 1, r2, 64, &f2,
						   &u2);
				int k, seen = 0, pass_exit = 1;

				for (k = 0; k < tot2 && k < 64; k++)
					if (!strcmp(r2[k].type, "exit_code")) {
						seen++;
						pass_exit = r2[k].pass;
					}
				neg_total++;
				neg_ok[1] = seen > 0 && !pass_exit;
				snprintf(neg_detail[1],
					 sizeof(neg_detail[1]),
					 "seen_exit_asserts=%d pass=%d "
					 "exit=%d", seen, pass_exit,
					 rr.exit_code);
				cp_run_free(&rr);
			}
		}
	}
	/* 负向 3：不带任何适配（无 overlay/env）跑同一目标 -> 契约必须失败 */
	{
		struct cp_sb sb2;
		struct cp_run rr;
		struct cp_ares r2[64];
		int f2 = 0, u2 = 0, tot2;

		if (!cp_sb_build(&sb2, ws, &info, 0, NULL, 0, targv,
				 a.n_argv)) {
			if (!cp_spawn(sb2.argv, NULL, 0, a.timeout_s, &rr)) {
				tot2 = cp_eval(&a, &rr, 1, 1, r2, 64, &f2, &u2);
				neg_total++;
				neg_ok[2] = tot2 > 0 && f2 > 0;
				snprintf(neg_detail[2],
					 sizeof(neg_detail[2]),
					 "unadapted exit=%d failed=%d/%d "
					 "stderr=%.120s", rr.exit_code, f2,
					 tot2, rr.err ? rr.err : "");
				cp_run_free(&rr);
			}
		}
	}
	for (i = 0; i < 3; i++)
		if (!neg_ok[i])
			neg_fail++;

	f = open_memstream(&buf, &blen);
	if (!f) {
		rc = AI_ERR_MEMORY;
		cp_env_free(env, en);
		cp_adapter_free(&a);
		cp_run_free(&pos);
		goto done;
	}
	fputs("{\"ok\":", f);
	fputs((failed == 0 && neg_fail == 0) ? "true" : "false", f);
	fputs(",\"adapter\":", f);
	cp_jstr(f, a.name);
	fputs(",\"workspace\":", f);
	cp_jstr(f, ws);
	fputs(",\"contract\":{\"total\":", f);
	fprintf(f, "%d,\"failed\":%d,\"unverifiable\":%d,\"asserts\":[",
		total, failed, unver);
	cp_emit_ares(f, res, total);
	fputs("]},\"run\":", f);
	cp_emit_run(f, &pos);
	fputs(",\"negatives\":[", f);
	fprintf(f, "{\"id\":\"empty_stdout\",\"expect\":\"fail\","
		"\"observed\":\"%s\",\"pass\":%s,\"detail\":",
		neg_ok[0] ? "fail" : "pass", neg_ok[0] ? "true" : "false");
	cp_jstr(f, neg_detail[0]);
	fputs("},", f);
	fprintf(f, "{\"id\":\"forced_exit\",\"expect\":\"fail\","
		"\"observed\":\"%s\",\"pass\":%s,\"detail\":",
		neg_ok[1] ? "fail" : "pass", neg_ok[1] ? "true" : "false");
	cp_jstr(f, neg_detail[1]);
	fputs("},", f);
	fprintf(f, "{\"id\":\"unadapted\",\"expect\":\"fail\","
		"\"observed\":\"%s\",\"pass\":%s,\"detail\":",
		neg_ok[2] ? "fail" : "pass", neg_ok[2] ? "true" : "false");
	cp_jstr(f, neg_detail[2]);
	fputs("}]", f);
	fputs(",\"syscall_trace\":{\"available\":", f);
	fputs(trace_used && a.trace ? "true" : "false", f);
	fprintf(f, ",\"bytes\":%zu,\"asserts_unverifiable\":%d}",
		a.trace_len, unver);
	fputs(",\"diff\":[", f);
	{
		int printed = 0;

		for (i = 0; i < total; i++)
			if (!res[i].pass) {
				if (printed)
					fputc(',', f);
				fputs("{\"type\":", f);
				cp_jstr(f, res[i].type);
				fputs(",\"expected\":", f);
				cp_jstr(f, res[i].expected);
				fputs(",\"actual\":", f);
				cp_jstr(f, res[i].actual);
				fputc('}', f);
				printed++;
			}
		for (i = 0; i < 3; i++)
			if (!neg_ok[i]) {
				char id[32];

				snprintf(id, sizeof(id), "%s",
					 i == 0 ? "empty_stdout" :
					 i == 1 ? "forced_exit" :
					 "unadapted");
				if (printed)
					fputc(',', f);
				fputs("{\"type\":\"negative_selfcheck\","
				      "\"id\":", f);
				cp_jstr(f, id);
				fputs(",\"expected\":\"验证器应判失败\","
				      "\"actual\":\"验证器放过了\"}", f);
				printed++;
			}
	}
	fputs("]", f);
	fputs(",\"because\":", f);
	cp_jstr(f, (failed == 0 && neg_fail == 0) ?
		"契约全过且三类负向自检都正确判负：适配真实成立" :
		"契约未全过（或负向自检失效）——按设计判不合格，不报成功");
	fputc('}', f);
	fclose(f);
	*out = buf;
	cp_audit("compat_verify", "adapter=%s workspace=%s ok=%d "
		 "failed=%d/%d neg_fail=%d trace=%d", a.name, ws,
		 (failed == 0 && neg_fail == 0), failed, total, neg_fail,
		 trace_used);
	/* 契约不过 = 工具级也判失败（executor 的 ok 标志同步为 false），
	 * 防止上层只看 ok 标志就把"契约没过"当成"验证成功"。 */
	if (failed || neg_fail)
		rc = AI_ERR_GENERIC;
	cp_env_free(env, en);
	cp_adapter_free(&a);
	cp_run_free(&pos);
	goto done;
done:
	free(name);
	return rc;
}

/* ======================================================================
 * 8) 通道入口
 * ====================================================================== */

static int cp_tool_probe(const char *args, size_t alen, char **out)
{
	char *target = jstr(args, alen, "target");
	char *json = NULL;
	int runnable = 0;

	*out = NULL;
	if (!target || target[0] != '/' || !cp_safe_path(target)) {
		free(target);
		if (asprintf(out, "ERROR: target 必须是绝对路径且不含危险字符")
		    < 0)
			*out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	(void)ai_compat_probe_json(target, NULL, &json, &runnable);
	free(target);
	if (!json) {
		*out = strdup("ERROR: probe 失败");
		return AI_ERR_GENERIC;
	}
	*out = json;
	return AI_OK;
}

int exec_compat_channel(const void *tool_v, const char *args_json,
			char **out)
{
	const struct ai_tool *tool = tool_v;
	size_t alen;

	*out = NULL;
	if (!tool || !tool->name || !args_json) {
		*out = strdup("ERROR: compat 调用参数为空");
		return AI_ERR_INVALID_ARG;
	}
	alen = strlen(args_json);
	if (strcmp(tool->name, "compat_probe") == 0)
		return cp_tool_probe(args_json, alen, out);
	if (strcmp(tool->name, "compat_generate") == 0)
		return cp_generate(args_json, alen, out);
	if (strcmp(tool->name, "compat_apply") == 0)
		return cp_apply(args_json, alen, out);
	if (strcmp(tool->name, "compat_verify") == 0)
		return cp_verify(args_json, alen, out);
	*out = strdup("ERROR: 未知 compat 工具（注册表异常）");
	return AI_ERR_INVALID_ARG;
}
