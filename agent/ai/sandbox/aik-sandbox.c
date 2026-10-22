// SPDX-License-Identifier: GPL-2.0
/*
 * aik-sandbox.c - AIKernel 隔离区工具（W42 建区；W64 成熟化）
 *
 * 用内核现成的 namespace 能力给子智能体造一个"用完即焚"的隔离区：
 *   clone(CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS[|CLONE_NEWNET]) →
 *   子进程在**自己的** mount namespace 里组装视图（宿主 namespace 不受影响）：
 *
 *     /        = tmpfs 空根（rw；随子进程退出 / destroy 消亡）
 *     /usr     = bind ro（可执行 ai、工具链）
 *     /proc    = 新挂 procfs ro（仅本 PID namespace 的进程；宿主 PID 与
 *                /proc/<hostpid>/root 不可见；AIKernel /proc/ai 照常可读）
 *     /sys     = 新挂 sysfs ro（按子进程 netns 视图；失败回退宿主 ro bind）
 *     /etc     = 仅白名单文件 bind ro：resolv.conf、hosts、nsswitch.conf、
 *                ssl/certs/ca-certificates.crt（TLS 校验要读）、aikernel/（策略）。
 *                shadow / sudoers / passwd 等敏感文件绝不挂入。
 *     /dev     = 仅 bind null/zero/full/random/urandom + tty/console（存在才挂）
 *     /root    = tmpfs 空目录 + **拷贝**（非 bind）$HOME/.aikernel 的
 *                model.toml / provider.toml——子智能体拿得到引擎配置，
 *                但宿主 /root 目录整体不可见，退出即焚
 *     /home /var /opt /srv = 沙盒 tmpfs 上的空目录（宿主内容不可见）
 *     /var/ai/sandbox-artifacts/<name> = **唯一** rw 产物通道（见下）
 *     /bin /sbin /lib /lib64 = usrmerge 符号链接 → usr/bin 等
 *     网络     = 默认保留宿主网络（子智能体需要访问 AI 引擎与 SME 记忆服务）；
 *                --net none 时新建 NET namespace，仅 lo 可用且自动 up
 *     能力     = setup 完成后 PR_SET_NO_NEW_PRIVS=1，并把除 CAP_NET_RAW
 *                （ping 需要）外的全部能力从 CapBnd/CapPrm/CapEff 丢弃；
 *                exec 后 root 只能重新取得 CapBnd 内的 CAP_NET_RAW。
 *
 *   挂载传播：进 namespace 第一件事 mount("", "/", NULL, MS_REC|MS_PRIVATE)
 *   ——后续挂载绝不传播回宿主，宿主挂载事件也不泄进沙盒。
 *
 *   /proc 用**新 procfs**（W71）：pivot_root 后挂到新根 /proc，procfs
 *   superblock 绑定挂载时的 PID namespace，因此 /proc 只列本沙盒的进程；
 *   宿主 /proc 的 /proc/1/root 等逃逸面与宿主 PID 可见性一并关闭。
 *   /sys 用**新 sysfs**：superblock 绑定 net namespace，--net none 下
 *   /sys/class/net 不再显示宿主网卡；/sys/kernel/ai 等全局节点照常可见。
 *
 * W64 成熟化（沙箱生命周期 + 资源限额 + 产物导出）：
 *   1. cgroup v2 限额：create/run 可指定 CPU 配额（cpu.max）、memory.max、
 *      pids.max。子进程的**第一条语句**把自己写进 cgroup.procs（"0" =
 *      current）；不用裸 clone3——裸 clone3 的子进程会带着新栈继续执行
 *      syscall 返回路径而崩溃（QEMU 实证 SIGSEGV@stack top）。**只移动本
 *      工具 fork 出的子进程，绝不移动任何宿主既有进程**。cgroup v2 不可用或
 *      控制器不可用时明确告警并降级（仍保留 cgroup 归组以便 cgroup.kill
 *      一次性回收）。
 *   2. 生命周期：/sandbox/<name>/meta 原子落盘（name/pid/child_pid/cgroup/
 *      时间/限额/网络/状态），不再只靠内存。create/status 能识别"父进程
 *      被杀、子进程被 init 收养"的残留（cgroup.procs 非空但 run 包装进程
 *      已死），用 cgroup.kill 回收；destroy 幂等（杀进程组 → 卸残留挂载
 *      → rm -rf → 删 cgroup），可连续调用。
 *   3. 网络：--net none / AIKERNEL_SANDBOX_NET=none 可选隔离；默认保留宿主
 *      网络（产品定位）。隔离后 lo 自动 up，/proc/net/dev 只剩 lo。
 *   4. 产物导出：run 把宿主 <artifact-root>/<name> rw bind 到沙盒内
 *      /var/ai/sandbox-artifacts/<name>（nodev+nosuid）；导出命令
 *      `export <name> <src> <dest>` 只接受 artifact root 下的路径，用
 *      realpath/openat2(RESOLVE_BENEATH) 拒绝 symlink 逃逸；dest 用
 *      O_EXCL|O_NOFOLLOW 拒绝覆盖与 symlink 落点。
 *
 * W71 隔离面加固（B-012）：
 *   1. fresh procfs：pivot_root/chroot 之后在沙盒内 `mount("proc", "/proc")`，
 *      不再 bind 宿主 /proc。PID namespace 内只能看到沙盒自己的进程；
 *      /proc 只读挂载（/proc/sys 的若干文件 uid 0 可写，不能给沙盒改宿主
 *      全局参数的机会）。AIKernel 的 /proc/ai 是 procfs 顶层节点，新挂后
 *      仍可见（QEMU #57 实证）。
 *   2. 能力裁剪：setup/切根/身份设置完成后 PR_SET_NO_NEW_PRIVS=1，再用
 *      原始 capset 把 CapEff/CapPrm/CapInh 收为 {CAP_NET_RAW}，并逐项
 *      PR_CAPBSET_DROP 其余能力（不可逆）。exec 后 root 只能从 CapBnd
 *      重新取得 CAP_NET_RAW，CAP_SYS_ADMIN/SYS_MODULE/SYS_PTRACE/SYS_BOOT/
 *      SYS_TIME/SYS_NICE/MKNOD/SYS_CHROOT/SETUID/SETGID 等永久缺席。
 *      文件读写、/tmp、产物导出、cgroup 归组、宿主侧 destroy 不受影响
 *      （这些要么在裁剪前完成，要么只需要 uid 0 的 owner 权限）。
 *   3. 可选 `AIKERNEL_SANDBOX_DEBUG=1` 在沙盒 stderr 打印 CapEff 前后值
 *      （测试取证用；executor 不设置）。
 *
 * 子命令：
 *   create <name> [限额/网络选项]   宿主侧建 /sandbox/<name>/root、meta、
 *                                   cgroup 与产物目录（已存在则先回收残留）
 *   run <name> [--keep] [选项] -- <cmd> [args...]
 *                                   组装隔离视图并 exec cmd；退出码透传。
 *                                   --keep = 宿主侧目录保留供取证
 *   destroy <name>                   杀进程/进程组 + cgroup.kill + umount +
 *                                   清除 /sandbox/<name>（幂等）
 *   status                           列隔离区、存活 pid、cgroup、限额、状态；
 *                                   无存活进程的 stale 项自动回收
 *   export <name> <src> <dest>       从产物区导出单个普通文件
 *
 * 选项（create/run 通用，优先级 CLI > 环境变量 > create 落盘的 meta > 默认）：
 *   --cpus N         CPU 配额（0=不限；默认 1.0）
 *   --mem-mb N       内存上限 MB（0=不限；默认 1024）
 *   --pids N         任务数上限（0=不限；默认 256）
 *   --net none|host  网络隔离（默认 host）
 *   --no-cgroup      禁用 cgroup（明确告警）
 *   --keep           （仅 run）保留宿主挂载点目录
 *
 * 环境变量：
 *   AIKERNEL_SANDBOX_CPUS / AIKERNEL_SANDBOX_MEM_MB / AIKERNEL_SANDBOX_PIDS
 *   AIKERNEL_SANDBOX_NET=none|host
 *   AIKERNEL_SANDBOX_NO_CGROUP=1
 *   AIKERNEL_SANDBOX_ARTIFACTS  宿主产物根（默认 /var/ai/sandbox-artifacts）
 *   AIKERNEL_SANDBOX_CGROUP_ROOT 测试/排障用 cgroup2 根（默认 /sys/fs/cgroup）
 *   AIKERNEL_SANDBOX_BASE        测试/排障用沙盒基目录（默认 /sandbox）
 *   AIKERNEL_SANDBOX             （由 run 在 exec 前注入沙盒内进程）
 *   HOME                         （沙盒内强制改写为 /root；拷贝配置以**调用方**
 *                                 的 $HOME/.aikernel 为源）
 *
 * 退出码：0 成功；1 用法错误；2 沙盒组装失败；127 exec 失败；
 *         子进程正常退出码 / 128+信号 原样透传。
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <net/if.h>

/*
 * 本文件的路径全部以 PATH_MAX 级静态上界构造；base / cgroup root / name
 * 在入口处已收紧（绝对路径、无 ".."、长度 < PATH_MAX），实际可达路径不会
 * 被 snprintf 截断。GCC 对 "PATH_MAX 源 + 后缀 -> PATH_MAX 目标" 的静态
 * 范围无法收敛，会报 -Wformat-truncation；这里显式收敛该诊断，保证
 * aik-sandbox 构建 0 新增 warning（W64 门禁）。
 */
#pragma GCC diagnostic ignored "-Wformat-truncation"

#define SB_BASE_DEFAULT        "/sandbox"
#define SB_CG_DEFAULT_ROOT     "/sys/fs/cgroup"
#define SB_ARTIFACT_DEFAULT    "/var/ai/sandbox-artifacts"
#define SB_ARTIFACT_CANON      "/var/ai/sandbox-artifacts"
#define SB_CGROUP2_MAGIC       0x63677270U
#define SB_STACK_SIZE          (4 * 1024 * 1024)

#define SB_DEF_CPUS_X100       100      /* 1.00 CPU */
#define SB_DEF_MEM_MB          1024
#define SB_DEF_PIDS            256

/* openat2：静态构建下直接走 syscall，避免 libc 版本差异 */
#ifndef SYS_openat2
#define SYS_openat2 437
#endif

#define SB_RESOLVE_NO_MAGICLINKS 0x02ULL
#define SB_RESOLVE_BENEATH       0x08ULL

struct sb_open_how {
	uint64_t flags;
	uint64_t mode;
	uint64_t resolve;
};

/*
 * 能力裁剪（W71）：不依赖 libcap，直接用内核 capset 接口。
 * 只保留 CAP_NET_RAW（ping 需要；其余能力对子智能体无必要）。
 * 注意：uid 0 在未设置 SECBIT_NOROOT 时 exec 会从 **CapBnd** 重新取得
 * 能力，所以必须同时 PR_CAPBSET_DROP 其余位——只清 CapEff 无效。
 */
#define SB_CAP_VERSION_3       0x20080522U
#define SB_CAP_NET_RAW         13
#define SB_CAP_KEEP_MASK       (1ULL << SB_CAP_NET_RAW)

struct sb_cap_header {
	uint32_t version;
	int32_t pid;
};

struct sb_cap_data {
	uint32_t effective;
	uint32_t permitted;
	uint32_t inheritable;
};

struct sb_limits {
	int cpus_x100;          /* 0 = unlimited */
	long mem_mb;            /* 0 = unlimited */
	long pids_max;          /* 0 = unlimited */
};

struct sb_config {
	struct sb_limits lim;
	int net_none;           /* 1 = CLONE_NEWNET */
	int cgroup;             /* 1 = 尝试 cgroup */
	int keep;               /* run --keep */
};

struct sb_meta {
	char name[80];
	int have;
	long pid;               /* aik-sandbox run 包装进程（宿主 pid） */
	long child_pid;         /* 沙盒 init（宿主 pid） */
	long created;
	long started;
	long ended;
	int cpus_x100;
	long mem_mb;
	long pids_max;
	int cpu_limit;          /* 1 = cpu.max 实际写入（内核支持 CFS bandwidth） */
	int mem_limit;
	int pids_limit;
	int net_none;
	int cgroup;
	int exit_code;
	char status[16];
};

struct cg_state {
	int enabled;
	char dir[PATH_MAX];
	int cpu;
	int mem;
	int pids;
};

/* /etc 白名单文件（bind ro，单文件粒度——绝无 shadow/sudoers/passwd） */
static const char *const SB_ETC_FILES[] = {
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/nsswitch.conf",
	"/etc/ssl/certs/ca-certificates.crt",
	NULL,
};
/* /dev 白名单设备节点（bind；null/zero/random/urandom 缺一不可） */
static const char *const SB_DEV_MUST[] = {
	"null", "zero", "random", "urandom", NULL,
};
static const char *const SB_DEV_OPT[] = {
	"full", "tty", "console", NULL,
};

/* ---- 基础工具 ---- */

static void die(int code, const char *fmt, ...)
{
	va_list ap;

	fputs("aik-sandbox: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(code);
}

static int is_dir(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static int file_exists(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0;
}

/* 递归建目录（等价 mkdir -p，只作用于显式给出的路径） */
static void mkdir_p(const char *path, mode_t mode)
{
	char buf[PATH_MAX];
	size_t i, n = strlen(path);

	if (n == 0 || n >= sizeof(buf))
		die(2, "路径异常: %s", path);
	memcpy(buf, path, n + 1);
	for (i = 1; i < n; i++) {
		if (buf[i] != '/')
			continue;
		buf[i] = '\0';
		if (mkdir(buf, mode) && errno != EEXIST)
			die(2, "mkdir %s: %s", buf, strerror(errno));
		buf[i] = '/';
	}
	if (mkdir(buf, mode) && errno != EEXIST)
		die(2, "mkdir %s: %s", buf, strerror(errno));
	if (!is_dir(path))
		die(2, "%s 不是目录", path);
}

/* 非致命版 mkdir -p（产物区/测试基目录用：失败只告警） */
static int mkdir_p_soft(const char *path, mode_t mode)
{
	char buf[PATH_MAX];
	size_t i, n = strlen(path);

	if (n == 0 || n >= sizeof(buf))
		return -1;
	memcpy(buf, path, n + 1);
	for (i = 1; i < n; i++) {
		if (buf[i] != '/')
			continue;
		buf[i] = '\0';
		if (mkdir(buf, mode) && errno != EEXIST)
			return -1;
		buf[i] = '/';
	}
	if (mkdir(buf, mode) && errno != EEXIST)
		return -1;
	return 0;
}

/* 沙盒基目录（默认 /sandbox；测试可覆盖，但拒绝 '/' 与 ".."） */
static const char *sb_base(void)
{
	static char buf[PATH_MAX];
	const char *e = getenv("AIKERNEL_SANDBOX_BASE");
	size_t n;

	if (buf[0])
		return buf;
	if (!e || !e[0])
		e = SB_BASE_DEFAULT;
	n = strlen(e);
	if (e[0] != '/' || strstr(e, "..") || n >= sizeof(buf) - 1)
		die(1, "非法 AIKERNEL_SANDBOX_BASE: %s", e);
	memcpy(buf, e, n + 1);
	while (n > 1 && buf[n - 1] == '/')
		buf[--n] = '\0';
	if (n <= 1)
		die(1, "AIKERNEL_SANDBOX_BASE 不能是 /");
	return buf;
}

/* 区名合法性：防路径逃逸（只允许 [A-Za-z0-9._-]，不许点开头/连续点） */
static int valid_name(const char *s)
{
	size_t i, n;

	if (!s || !s[0])
		return 0;
	n = strlen(s);
	if (n > 64)
		return 0;
	if (s[0] == '.' || s[0] == '-')
		return 0;
	for (i = 0; i < n; i++) {
		char c = s[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		      c == '.'))
			return 0;
	}
	if (strstr(s, ".."))
		return 0;
	return 1;
}

/* nftw 回调：rm_rf 用（FTW_DEPTH 自底向上） */
static int rm_rf_cb(const char *fpath, const struct stat *sb,
		    int typeflag, struct FTW *ftwbuf)
{
	(void)sb;
	(void)typeflag;
	(void)ftwbuf;
	if (remove(fpath) && errno != ENOENT)
		fprintf(stderr, "aik-sandbox: 清理 %s: %s\n",
			fpath, strerror(errno));
	return 0;
}

/* rm -rf 等价物；path 必须以 "<base>/" 开头（防御性硬约束） */
static void rm_rf_guarded(const char *path)
{
	char prefix[PATH_MAX + 2];

	snprintf(prefix, sizeof(prefix), "%s/", sb_base());
	if (strncmp(path, prefix, strlen(prefix)))
		die(2, "拒绝清理沙盒基目录之外的路径: %s", path);
	nftw(path, rm_rf_cb, 16, FTW_DEPTH | FTW_PHYS);
}

static int write_file(const char *path, const char *data)
{
	size_t len = strlen(data);
	int fd = open(path, O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;
	while (len) {
		ssize_t n = write(fd, data, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		data += n;
		len -= (size_t)n;
	}
	if (close(fd))
		return -1;
	return 0;
}

/* 读单个文件到 buf（去尾部换行）；返回字节数，失败 -1 */
static ssize_t read_str(const char *path, char *buf, size_t sz)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	if (sz == 0) {
		close(fd);
		return -1;
	}
	n = read(fd, buf, sz - 1);
	close(fd);
	if (n < 0)
		return -1;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		n--;
	buf[n] = '\0';
	return n;
}

/* 空格分隔 token 列表是否包含 tok（cgroup.controllers/subtree_control） */
static int has_token(const char *list, const char *tok)
{
	size_t tl = strlen(tok);
	const char *p = list;

	while (*p) {
		const char *s;

		while (*p == ' ' || *p == '\n' || *p == '\t')
			p++;
		if (!*p)
			break;
		s = p;
		while (*p && *p != ' ' && *p != '\n' && *p != '\t')
			p++;
		if ((size_t)(p - s) == tl && strncmp(s, tok, tl) == 0)
			return 1;
	}
	return 0;
}

static int file_has_token(const char *path, const char *tok)
{
	char buf[1024];

	if (read_str(path, buf, sizeof(buf)) < 0)
		return 0;
	return has_token(buf, tok);
}

/* ---- 产物区根目录（宿主侧；沙盒内固定映射到 SB_ARTIFACT_CANON） ---- */

static const char *artifact_root(void)
{
	static char buf[PATH_MAX];
	const char *e = getenv("AIKERNEL_SANDBOX_ARTIFACTS");
	size_t n;

	if (buf[0])
		return buf;
	if (!e || !e[0])
		return SB_ARTIFACT_DEFAULT;
	n = strlen(e);
	if (e[0] != '/' || strstr(e, "..") || n >= sizeof(buf) - 1) {
		fprintf(stderr, "aik-sandbox: 警告: 非法 AIKERNEL_SANDBOX_ARTIFACTS"
			"（%s），改用 %s\n", e, SB_ARTIFACT_DEFAULT);
		return SB_ARTIFACT_DEFAULT;
	}
	memcpy(buf, e, n + 1);
	while (n > 1 && buf[n - 1] == '/')
		buf[--n] = '\0';
	return buf;
}

static int ensure_artifact_dir(const char *name, char *host, size_t hostsz)
{
	const char *root = artifact_root();

	if (mkdir_p_soft(root, 0700)) {
		fprintf(stderr, "aik-sandbox: 警告: 无法创建产物区 %s（%s），"
			"本次不挂载产物通道\n", root, strerror(errno));
		return -1;
	}
	if (snprintf(host, hostsz, "%s/%s", root, name) >= (int)hostsz)
		return -1;
	if (mkdir_p_soft(host, 0700)) {
		fprintf(stderr, "aik-sandbox: 警告: 无法创建产物目录 %s（%s）\n",
			host, strerror(errno));
		return -1;
	}
	return 0;
}

/* ---- 元数据落盘（<base>/<name>/meta，原子替换） ---- */

static void meta_path(const char *name, char *buf, size_t n)
{
	snprintf(buf, n, "%s/%s/meta", sb_base(), name);
}

static int meta_write(const char *name, const struct sb_meta *m)
{
	char path[PATH_MAX], tmp[PATH_MAX];
	int fd, rc = -1;

	meta_path(name, path, sizeof(path));
	snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	if (dprintf(fd,
		    "name=%s\npid=%ld\nchild_pid=%ld\ncreated=%ld\n"
		    "started=%ld\nended=%ld\ncpus=%.2f\nmem_mb=%ld\n"
		    "pids_max=%ld\ncpu_limit=%d\nmem_limit=%d\n"
		    "pids_limit=%d\nnet=%s\ncgroup_dir=%s\nexit_code=%d\n"
		    "status=%s\n",
		    name, m->pid, m->child_pid, m->created, m->started,
		    m->ended, m->cpus_x100 / 100.0, m->mem_mb,
		    m->pids_max, m->cpu_limit, m->mem_limit,
		    m->pids_limit, m->net_none ? "none" : "host",
		    m->cgroup ? "1" : "0", m->exit_code, m->status) < 0)
		goto out;
	if (!fsync(fd) && !close(fd)) {
		fd = -1;
		if (!rename(tmp, path))
			rc = 0;
	}
out:
	if (fd >= 0)
		close(fd);
	if (rc)
		unlink(tmp);
	return rc;
}

static int meta_read(const char *name, struct sb_meta *m)
{
	char path[PATH_MAX], line[256];
	FILE *fp;

	memset(m, 0, sizeof(*m));
	snprintf(m->name, sizeof(m->name), "%s", name);
	m->cpus_x100 = SB_DEF_CPUS_X100;
	m->mem_mb = SB_DEF_MEM_MB;
	m->pids_max = SB_DEF_PIDS;
	meta_path(name, path, sizeof(path));
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		char *eq = strchr(line, '=');
		char *v;

		if (!eq)
			continue;
		*eq = '\0';
		v = eq + 1;
		v[strcspn(v, "\r\n")] = '\0';
		if (strcmp(line, "pid") == 0)
			m->pid = strtol(v, NULL, 10);
		else if (strcmp(line, "child_pid") == 0)
			m->child_pid = strtol(v, NULL, 10);
		else if (strcmp(line, "created") == 0)
			m->created = strtol(v, NULL, 10);
		else if (strcmp(line, "started") == 0)
			m->started = strtol(v, NULL, 10);
		else if (strcmp(line, "ended") == 0)
			m->ended = strtol(v, NULL, 10);
		else if (strcmp(line, "mem_mb") == 0)
			m->mem_mb = strtol(v, NULL, 10);
		else if (strcmp(line, "pids_max") == 0)
			m->pids_max = strtol(v, NULL, 10);
		else if (strcmp(line, "cpu_limit") == 0)
			m->cpu_limit = atoi(v);
		else if (strcmp(line, "mem_limit") == 0)
			m->mem_limit = atoi(v);
		else if (strcmp(line, "pids_limit") == 0)
			m->pids_limit = atoi(v);
		else if (strcmp(line, "cpus") == 0)
			m->cpus_x100 = (int)(strtod(v, NULL) * 100.0 + 0.5);
		else if (strcmp(line, "net") == 0)
			m->net_none = strcmp(v, "none") == 0;
		else if (strcmp(line, "cgroup_dir") == 0)
			m->cgroup = strcmp(v, "1") == 0;
		else if (strcmp(line, "exit_code") == 0)
			m->exit_code = (int)strtol(v, NULL, 10);
		else if (strcmp(line, "status") == 0)
			snprintf(m->status, sizeof(m->status), "%s", v);
	}
	fclose(fp);
	m->have = 1;
	return 0;
}

/* ---- cgroup v2 ---- */

static const char *cg_root(void)
{
	static char buf[PATH_MAX];
	const char *e = getenv("AIKERNEL_SANDBOX_CGROUP_ROOT");
	size_t n;

	if (buf[0])
		return buf;
	if (!e || !e[0])
		return SB_CG_DEFAULT_ROOT;
	n = strlen(e);
	if (e[0] != '/' || strstr(e, "..") || n >= sizeof(buf) - 1) {
		fprintf(stderr, "aik-sandbox: 警告: 非法 "
			"AIKERNEL_SANDBOX_CGROUP_ROOT，改用 %s\n",
			SB_CG_DEFAULT_ROOT);
		return SB_CG_DEFAULT_ROOT;
	}
	memcpy(buf, e, n + 1);
	while (n > 1 && buf[n - 1] == '/')
		buf[--n] = '\0';
	return buf;
}

static void cg_parent(char *buf, size_t n)
{
	snprintf(buf, n, "%s/aik-sandbox", cg_root());
}

static void cg_dir_for(const char *name, char *buf, size_t n)
{
	snprintf(buf, n, "%s/aik-sandbox/%s", cg_root(), name);
}

static int cg_procs_count_dir(const char *dir)
{
	char path[PATH_MAX], line[128];
	FILE *fp;
	int count = 0;

	snprintf(path, sizeof(path), "%s/cgroup.procs", dir);
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		if (line[0] && line[0] != '\n')
			count++;
	}
	fclose(fp);
	return count;
}

static int cg_populated_dir(const char *dir)
{
	char path[PATH_MAX], buf[512];
	const char *p;

	snprintf(path, sizeof(path), "%s/cgroup.events", dir);
	if (read_str(path, buf, sizeof(buf)) < 0)
		return -1;
	p = strstr(buf, "populated ");
	if (!p)
		return -1;
	return atoi(p + strlen("populated "));
}

/* 仅对本工具自己的 cgroup 调用：先 cgroup.kill，老内核退化为逐 pid SIGKILL */
static void cg_kill_dir(const char *dir)
{
	char path[PATH_MAX];
	int i;

	if (!is_dir(dir))
		return;
	snprintf(path, sizeof(path), "%s/cgroup.kill", dir);
	if (write_file(path, "1") == 0) {
		for (i = 0; i < 60; i++) {
			if (cg_populated_dir(dir) == 0)
				return;
			usleep(50 * 1000);
		}
		return;
	}
	/* fallback：只杀该 cgroup 成员（绝不碰组外 pid；跳过 PID 1） */
	for (i = 0; i < 40; i++) {
		FILE *fp;
		char line[128];

		snprintf(path, sizeof(path), "%s/cgroup.procs", dir);
		fp = fopen(path, "r");
		if (!fp)
			break;
		while (fgets(line, sizeof(line), fp)) {
			long pid = strtol(line, NULL, 10);

			if (pid > 1)
				kill((pid_t)pid, SIGKILL);
		}
		fclose(fp);
		if (cg_procs_count_dir(dir) <= 0)
			break;
		usleep(50 * 1000);
	}
}

/* 删 cgroup（先杀成员）；返回 0 = 已不存在 */
static int cg_remove_dir(const char *dir)
{
	int i;

	if (!is_dir(dir))
		return 0;
	for (i = 0; i < 60; i++) {
		if (rmdir(dir) == 0)
			return 0;
		if (errno == ENOENT)
			return 0;
		if (errno == EBUSY || errno == ENOTEMPTY) {
			if ((i % 5) == 0)
				cg_kill_dir(dir);
			usleep(50 * 1000);
			continue;
		}
		break;
	}
	return -1;
}

/* 内核是否启用 CFS bandwidth（cpu.max 的前提，CONFIG_CFS_BANDWIDTH）。
 * 支持时 root cpu.stat 含 nr_periods/nr_throttled；未启用则只有
 * usage/user/system/nice 四项。 */
static int cpu_bw_supported(void)
{
	char path[PATH_MAX], buf[1024];

	snprintf(path, sizeof(path), "%s/cpu.stat", cg_root());
	if (read_str(path, buf, sizeof(buf)) < 0)
		return 0;
	return strstr(buf, "nr_periods") != NULL;
}

/*
 * 建 cgroup 并落限额。返回 0 = cgroup 归组可用（限额可能部分降级）；
 * -1 = 完全不可用（无 cgroup v2 / 无权限）。
 * 安全约束：只创建/移动本工具子进程；若 aik-sandbox 锚点 cgroup 里出现
 * 意料外的进程，绝不移动它们，只降级限额（仍可用 cgroup.kill 归组回收）。
 */
static int cg_setup(const char *name, const struct sb_limits *lim,
		    struct cg_state *st, char *info, size_t infosz)
{
	static const char *const ctls[3] = { "cpu", "memory", "pids" };
	int want[3];
	char parent[PATH_MAX], dir[PATH_MAX], path[PATH_MAX], val[128];
	struct statfs sf;
	int i, attempt, nprocs, can_enable, rc = 0;

	memset(st, 0, sizeof(*st));
	info[0] = '\0';
	if (statfs(cg_root(), &sf) || (unsigned long)sf.f_type !=
	    (unsigned long)SB_CGROUP2_MAGIC) {
		fprintf(stderr, "aik-sandbox: 警告: %s 不是 cgroup v2，"
			"资源限额降级（CPU/内存/PID 均不限制）\n", cg_root());
		return -1;
	}
	cg_parent(parent, sizeof(parent));
	if (mkdir(parent, 0755) && errno != EEXIST) {
		fprintf(stderr, "aik-sandbox: 警告: 创建 %s 失败（%s），"
			"资源限额降级\n", parent, strerror(errno));
		return -1;
	}
	nprocs = cg_procs_count_dir(parent);
	can_enable = (nprocs <= 0);
	if (!can_enable)
		fprintf(stderr, "aik-sandbox: 警告: 锚点 cgroup %s 含 %d 个"
			"进程，拒绝移动宿主进程；资源限额降级为"
			"仅 cgroup 归组\n", parent, nprocs);

	want[0] = lim->cpus_x100 > 0;
	want[1] = lim->mem_mb > 0;
	want[2] = lim->pids_max > 0;

	if (want[0] && !cpu_bw_supported()) {
		fprintf(stderr, "aik-sandbox: 警告: 内核未启用 "
			"CONFIG_CFS_BANDWIDTH（cpu.stat 无 nr_periods），"
			"cpu.max 不可用，CPU 限额降级为不限制\n");
		want[0] = 0;
	}

	if (can_enable) {
		snprintf(path, sizeof(path), "%s/cgroup.controllers",
			 cg_root());
		for (i = 0; i < 3; i++) {
			if (!want[i])
				continue;
			if (!file_has_token(path, ctls[i])) {
				fprintf(stderr, "aik-sandbox: 警告: 内核未提供 "
					"%s 控制器，该项限额降级\n", ctls[i]);
				want[i] = 0;
				continue;
			}
		}
		snprintf(path, sizeof(path), "%s/cgroup.subtree_control",
			 cg_root());
		for (i = 0; i < 3; i++) {
			if (!want[i])
				continue;
			if (!file_has_token(path, ctls[i])) {
				snprintf(val, sizeof(val), "+%s", ctls[i]);
				if (write_file(path, val) &&
				    !file_has_token(path, ctls[i])) {
					fprintf(stderr, "aik-sandbox: 警告: "
						"cgroup 根启用 %s 失败（%s），"
						"该项限额降级\n", ctls[i],
						strerror(errno));
					want[i] = 0;
				}
			}
		}
		/* 根启用后锚点的 cgroup.controllers 才会列出控制器 */
		snprintf(path, sizeof(path), "%s/cgroup.controllers",
			 parent);
		for (i = 0; i < 3; i++) {
			if (!want[i])
				continue;
			if (!file_has_token(path, ctls[i])) {
				fprintf(stderr, "aik-sandbox: 警告: %s 控制器在"
					"锚点 cgroup 不可用，该项限额降级\n",
					ctls[i]);
				want[i] = 0;
			}
		}
		snprintf(path, sizeof(path), "%s/cgroup.subtree_control",
			 parent);
		for (i = 0; i < 3; i++) {
			if (!want[i])
				continue;
			if (!file_has_token(path, ctls[i])) {
				snprintf(val, sizeof(val), "+%s", ctls[i]);
				if (write_file(path, val) &&
				    !file_has_token(path, ctls[i])) {
					fprintf(stderr, "aik-sandbox: 警告: "
						"锚点 cgroup 启用 %s 失败（%s），"
						"该项限额降级\n", ctls[i],
						strerror(errno));
					want[i] = 0;
				}
			}
		}
	}

	/* 并发 destroy 可能把父目录删掉：mkdir 子目录 ENOENT 时重建重试 */
	cg_dir_for(name, dir, sizeof(dir));
	for (attempt = 0; attempt < 3; attempt++) {
		if (!mkdir(dir, 0755) || errno == EEXIST)
			break;
		if (errno == ENOENT && attempt < 2) {
			mkdir(parent, 0755);
			continue;
		}
		fprintf(stderr, "aik-sandbox: 警告: 创建 cgroup %s 失败（%s），"
			"资源限额降级\n", dir, strerror(errno));
		return -1;
	}
	snprintf(st->dir, sizeof(st->dir), "%s", dir);
	st->enabled = 1;

	/* 限额文件只有在控制器沿父链启用后才存在 */
	snprintf(path, sizeof(path), "%s/cpu.max", dir);
	if (want[0] && file_exists(path)) {
		snprintf(val, sizeof(val), "%d 100000",
			 lim->cpus_x100 * 1000);
		if (write_file(path, val) == 0)
			st->cpu = 1;
		else
			fprintf(stderr, "aik-sandbox: 警告: 写 %s 失败（%s），"
				"CPU 限额降级\n", path, strerror(errno));
	}
	snprintf(path, sizeof(path), "%s/memory.max", dir);
	if (want[1] && file_exists(path)) {
		snprintf(val, sizeof(val), "%ld",
			 lim->mem_mb * 1024L * 1024L);
		if (write_file(path, val) == 0)
			st->mem = 1;
		else
			fprintf(stderr, "aik-sandbox: 警告: 写 %s 失败（%s），"
				"内存限额降级\n", path, strerror(errno));
		/* 沙盒不做 swap：内存耗尽语义确定（OOM 杀组） */
		snprintf(path, sizeof(path), "%s/memory.swap.max", dir);
		if (file_exists(path))
			write_file(path, "0");
		/* 整组 OOM：避免只杀一个进程留下半截状态 */
		snprintf(path, sizeof(path), "%s/memory.oom.group", dir);
		if (file_exists(path))
			write_file(path, "1");
	}
	snprintf(path, sizeof(path), "%s/pids.max", dir);
	if (want[2] && file_exists(path)) {
		snprintf(val, sizeof(val), "%ld", lim->pids_max);
		if (write_file(path, val) == 0)
			st->pids = 1;
		else
			fprintf(stderr, "aik-sandbox: 警告: 写 %s 失败（%s），"
				"PID 限额降级\n", path, strerror(errno));
	}

	snprintf(info, infosz, "cgroup=%s cpu=%s mem=%s pids=%s", dir,
		 st->cpu ? "on" : "off", st->mem ? "on" : "off",
		 st->pids ? "on" : "off");
	return rc;
}

/* ---- 进程/生命周期 ---- */

static int proc_is_zombie(const char *pidstr)
{
	char path[64], buf[512];
	char *p;

	snprintf(path, sizeof(path), "/proc/%s/stat", pidstr);
	if (read_str(path, buf, sizeof(buf)) < 0)
		return 0;
	p = strrchr(buf, ')');
	if (!p || p[1] != ' ')
		return 0;
	return p[2] == 'Z';
}

/* 扫 /proc：找正在 run <name> 的 aik-sandbox 包装进程（排除自身）；
 * 返回个数，pid 列表写入 out（空格分隔） */
static int scan_live_pids(const char *name, char *out, size_t outsz)
{
	DIR *d = opendir("/proc");
	struct dirent *e;
	size_t off = 0, n;
	int count = 0;
	pid_t self = getpid();

	if (outsz)
		out[0] = '\0';
	if (!d)
		return 0;
	while ((e = readdir(d))) {
		char cl[1024];
		FILE *fp;
		size_t rn;
		char *argv0, *argv1, *argv2, *sp;

		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		if ((pid_t)strtol(e->d_name, NULL, 10) == self)
			continue;
		if (proc_is_zombie(e->d_name))
			continue;
		snprintf(cl, sizeof(cl), "/proc/%s/cmdline", e->d_name);
		fp = fopen(cl, "rb");
		if (!fp)
			continue;
		rn = fread(cl, 1, sizeof(cl) - 1, fp);
		fclose(fp);
		cl[rn] = '\0';
		if (rn == 0)
			continue;
		argv0 = cl;
		argv1 = cl + strlen(argv0) + 1;
		if ((size_t)(argv1 - cl) >= rn)
			continue;
		argv2 = argv1 + strlen(argv1) + 1;
		if ((size_t)(argv2 - cl) >= rn)
			continue;
		sp = strrchr(argv0, '/');
		sp = sp ? sp + 1 : argv0;
		if (strcmp(sp, "aik-sandbox") == 0 &&
		    strcmp(argv1, "run") == 0 && strcmp(argv2, name) == 0) {
			count++;
			if (off + 1 < outsz) {
				int w = snprintf(out + off, outsz - off,
						 "%s ", e->d_name);

				if (w > 0)
					off += (size_t)w;
				if (off >= outsz)
					off = outsz - 1;
			}
		}
	}
	closedir(d);
	if (outsz) {
		out[outsz - 1] = '\0';
		n = strlen(out);
		while (n > 0 && out[n - 1] == ' ')
			out[--n] = '\0';
	}
	return count;
}

/* 杀该区所有 run 包装进程（只杀 cmdline 精确匹配者） */
static void kill_live_runs(const char *name)
{
	int pass;

	for (pass = 0; pass < 20; pass++) {
		char pids[1024];
		char *p;

		if (scan_live_pids(name, pids, sizeof(pids)) == 0)
			return;
		p = pids;
		while (*p) {
			char *end;
			long pid = strtol(p, &end, 10);

			if (end == p)
				break;
			if (pid > 1)
				kill((pid_t)pid, SIGKILL);
			p = end;
			while (*p == ' ')
				p++;
		}
		usleep(50 * 1000);
	}
}

/* 卸载 <prefix> 下残留的宿主侧挂载（正常路径挂载在子 namespace 随死消亡） */
static void umount_under(const char *prefix)
{
	int pass;

	for (pass = 0; pass < 3; pass++) {
		FILE *fp = fopen("/proc/self/mountinfo", "r");
		char line[PATH_MAX + 256];
		int hit = 0;

		if (!fp)
			return;
		while (fgets(line, sizeof(line), fp)) {
			char mp[PATH_MAX];
			size_t pl = strlen(prefix);

			if (sscanf(line, "%*u %*u %*s %*s %4095s", mp) != 1)
				continue;
			if (strncmp(mp, prefix, pl) != 0)
				continue;
			if (mp[pl] != '/' && mp[pl] != '\0')
				continue;
			if (umount2(mp, MNT_DETACH) == 0)
				hit = 1;
		}
		fclose(fp);
		if (!hit)
			return;
	}
}

static int sb_trylock(const char *name, int wait_ms)
{
	char path[PATH_MAX];
	int fd, waited = 0;

	snprintf(path, sizeof(path), "%s/%s/.lock", sb_base(), name);
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	for (;;) {
		if (flock(fd, LOCK_EX | LOCK_NB) == 0)
			return fd;
		if (errno != EWOULDBLOCK && errno != EINTR) {
			close(fd);
			return -1;
		}
		if (waited >= wait_ms) {
			close(fd);
			return -1;
		}
		usleep(50 * 1000);
		waited += 50;
	}
}

/*
 * 回收一个区的全部残留：杀 run 包装进程 → cgroup.kill（收孤儿）→
 * 卸残留挂载 → 删目录 → 删 cgroup。幂等。
 */
static void reap_entry(const char *name, int verbose)
{
	char dir[PATH_MAX], cgdir[PATH_MAX];

	if (verbose)
		printf("reap: 回收 %s 的残留（进程/挂载/目录/cgroup）\n", name);
	kill_live_runs(name);

	cg_dir_for(name, cgdir, sizeof(cgdir));
	cg_kill_dir(cgdir);
	if (cg_remove_dir(cgdir) && is_dir(cgdir) && verbose)
		fprintf(stderr, "aik-sandbox: 警告: cgroup %s 未能删除\n",
			cgdir);

	snprintf(dir, sizeof(dir), "%s/%s", sb_base(), name);
	umount_under(dir);
	if (file_exists(dir))
		rm_rf_guarded(dir);
}

/* ---- 组装隔离视图（在子进程的新 mount namespace 内执行） ---- */

/* ro bind：先 bind 再显式 remount ro（bind+RDONLY 一步式不可靠） */
static void bind_ro(const char *src, const char *dst, int recursive)
{
	unsigned long bind_flag = recursive ? MS_BIND | MS_REC : MS_BIND;

	if (mount(src, dst, NULL, bind_flag, NULL))
		die(2, "bind %s -> %s: %s", src, dst, strerror(errno));
	if (mount(NULL, dst, NULL,
		  MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
		  NULL))
		die(2, "remount ro %s: %s", dst, strerror(errno));
}

static void bind_rw(const char *src, const char *dst, int restrict_dev)
{
	if (mount(src, dst, NULL, MS_BIND, NULL))
		die(2, "bind %s -> %s: %s", src, dst, strerror(errno));
	if (restrict_dev &&
	    mount(NULL, dst, NULL,
		  MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV, NULL))
		fprintf(stderr, "aik-sandbox: remount nodev %s 失败（忽略）:"
			" %s\n", dst, strerror(errno));
}

static void copy_file(const char *src, const char *dst, mode_t mode)
{
	char buf[8192];
	FILE *in = fopen(src, "rb");
	FILE *out;
	size_t n;

	if (!in)
		return;                         /* 源不存在：静默跳过 */
	out = fopen(dst, "wb");
	if (!out) {
		fclose(in);
		die(2, "写 %s: %s", dst, strerror(errno));
	}
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (fwrite(buf, 1, n, out) != n)
			die(2, "写 %s: %s", dst, strerror(errno));
	}
	fclose(in);
	fclose(out);
	chmod(dst, mode);
}

/* --net none：新 netns 里只有 lo（down 状态），用 ioctl 拉起 */
static void bring_loopback_up(void)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

	if (fd < 0) {
		fprintf(stderr, "aik-sandbox: 拉起 lo: socket: %s\n",
			strerror(errno));
		return;
	}
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", "lo");
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
		ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_UP | IFF_RUNNING);
		if (ioctl(fd, SIOCSIFFLAGS, &ifr))
			fprintf(stderr, "aik-sandbox: 拉起 lo 失败: %s\n",
				strerror(errno));
	} else {
		fprintf(stderr, "aik-sandbox: 读取 lo flags 失败: %s\n",
			strerror(errno));
	}
	close(fd);
}

/* 读 /proc/self/status 的 CapEff（十六进制）；失败返回 -1 */
static long long cap_eff_now(void)
{
	char line[256];
	FILE *fp = fopen("/proc/self/status", "r");

	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "CapEff:", 7) == 0) {
			char *end;
			unsigned long long v = strtoull(line + 7, &end, 16);

			fclose(fp);
			return end == line + 7 ? -1 : (long long)v;
		}
	}
	fclose(fp);
	return -1;
}

/*
 * 能力裁剪：PR_SET_NO_NEW_PRIVS + capset({CAP_NET_RAW}) + 其余位
 * PR_CAPBSET_DROP（不可逆）。在 mount/切根/sethostname 全部完成后调用，
 * 失败即 fail-closed（宁可不启动沙盒，也不带着全能力跑子智能体）。
 */
static void sandbox_drop_caps(void)
{
	struct sb_cap_header hdr;
	struct sb_cap_data data[2];
	long long pre, post;
	int cap;

	pre = cap_eff_now();
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		die(2, "prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));

	for (cap = 0; cap <= 63; cap++) {
		if (SB_CAP_KEEP_MASK & (1ULL << cap))
			continue;
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) && errno != EINVAL)
			die(2, "prctl(PR_CAPBSET_DROP, %d): %s", cap,
			    strerror(errno));
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.version = SB_CAP_VERSION_3;
	hdr.pid = 0;
	memset(data, 0, sizeof(data));
	data[0].effective = data[0].permitted = data[0].inheritable =
		(uint32_t)(SB_CAP_KEEP_MASK & 0xffffffffULL);
	data[1].effective = data[1].permitted = data[1].inheritable =
		(uint32_t)(SB_CAP_KEEP_MASK >> 32);
	if (syscall(SYS_capset, &hdr, data))
		die(2, "capset: %s", strerror(errno));

	post = cap_eff_now();
	if (post < 0 || (uint64_t)post != SB_CAP_KEEP_MASK)
		die(2, "能力裁剪未生效（CapEff=0x%llx，期望 0x%llx）",
		    post < 0 ? 0ULL : (unsigned long long)post,
		    (unsigned long long)SB_CAP_KEEP_MASK);

	if (getenv("AIKERNEL_SANDBOX_DEBUG"))
		fprintf(stderr, "aik-sandbox: caps CapEff 0x%llx -> 0x%llx "
			"(仅保留 CAP_NET_RAW；CapBnd 同步裁剪)\n",
			pre < 0 ? 0ULL : (unsigned long long)pre,
			(unsigned long long)post);
}

struct child_args {
	char *name;
	char *mnt;                              /* <base>/<name>/root */
	char **argv;                            /* 待 exec 的 cmd */
	const char *cgroup_dir;                 /* fallback 自挂载；NULL = 不挂 */
	const char *artifact_host;              /* 宿主产物目录；NULL = 不挂 */
	int net_none;
};

static int sandbox_child(void *argp)
{
	struct child_args *a = argp;
	const char *mnt = a->mnt;
	char path[PATH_MAX], src[PATH_MAX];
	const char *home;
	int i;

	/* -1. 父进程（run 包装）被 SIGKILL/异常退出时，PID 1 收到 SIGKILL，
	 *     整个 PID namespace 随之消亡——避免子智能体被 init 收养成为
	 *     孤儿（W62 sb-05 残留根因之一）。仍有 clone→prctl 的微秒级
	 *     竞态，由 create/status 的 cgroup.kill 兜底。 */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL))
		fprintf(stderr, "aik-sandbox: prctl(PDEATHSIG): %s\n",
			strerror(errno));

	/* 0. 子进程把自己放进 cgroup（写 "0" = current；只影响本进程，
	 *    绝不碰宿主进程）。glibc clone() 已在新栈上布置好入口。 */
	if (a->cgroup_dir) {
		snprintf(path, sizeof(path), "%s/cgroup.procs",
			 a->cgroup_dir);
		if (write_file(path, "0"))
			fprintf(stderr, "aik-sandbox: 加入 cgroup 失败（%s），"
				"本次无资源限额\n", strerror(errno));
	}

	/* 1. 网络隔离时拉起 lo（新 netns 内默认 down） */
	if (a->net_none)
		bring_loopback_up();

	/* 2. 挂载传播收口：本 namespace 内一切挂载不进不出 */
	if (mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL))
		die(2, "mount private: %s", strerror(errno));

	/* 3. tmpfs 空根（nosuid+nodev；/dev 节点走独立 bind 挂载不受影响） */
	if (mount("tmpfs", mnt, "tmpfs", MS_NOSUID | MS_NODEV,
		  "mode=0755"))
		die(2, "tmpfs %s: %s", mnt, strerror(errno));

	/* 4. 目录骨架 */
	snprintf(path, sizeof(path), "%s/etc/ssl/certs", mnt);
	mkdir_p(path, 0755);
	snprintf(path, sizeof(path), "%s/root/.aikernel", mnt);
	mkdir_p(path, 0700);
	{
		static const char *const flat[] = {
			"usr", "proc", "sys", "etc", "tmp", "home",
			"var", "opt", "srv", "dev", ".old", NULL,
		};
		for (i = 0; flat[i]; i++) {
			snprintf(path, sizeof(path), "%s/%s", mnt, flat[i]);
			mkdir_p(path, 0755);
		}
	}
	/* usrmerge 符号链接（宿主 /bin /sbin /lib /lib64 → usr/… 布局，
	 * 保证沙盒内 /bin/sh、动态装载器路径照常可解析） */
	snprintf(path, sizeof(path), "%s/bin", mnt);
	if (symlink("usr/bin", path) && errno != EEXIST)
		die(2, "symlink bin: %s", strerror(errno));
	snprintf(path, sizeof(path), "%s/sbin", mnt);
	if (symlink("usr/sbin", path) && errno != EEXIST)
		die(2, "symlink sbin: %s", strerror(errno));
	snprintf(path, sizeof(path), "%s/lib", mnt);
	if (symlink("usr/lib", path) && errno != EEXIST)
		die(2, "symlink lib: %s", strerror(errno));
	if (file_exists("/lib64")) {
		snprintf(path, sizeof(path), "%s/lib64", mnt);
		if (symlink("usr/lib64", path) && errno != EEXIST)
			die(2, "symlink lib64: %s", strerror(errno));
	}

	/* 5. /usr：非递归 bind ro（顶层 superblock 整体只读；宿主在
	 *    /usr 下的二级挂载不进沙盒）。
	 *    /proc 不在这一步挂：W71 改为 pivot_root/chroot 之后在沙盒内
	 *    新挂 procfs，确保只显示本 PID namespace 的进程（见步骤 10b）。
	 *    /sys 在子进程内新挂 sysfs ro：sysfs superblock 绑定创建时的
	 *    net namespace；若直接 bind 宿主 /sys，--net none 下
	 *    /sys/class/net 仍会显示宿主网卡（QEMU 实证）。新挂后 net 类
	 *    按沙盒 netns 视图呈现，/sys/kernel/ai 等全局节点照旧可见。
	 *    无权限时回退宿主 ro bind（并告警）。 */
	snprintf(path, sizeof(path), "%s/usr", mnt);
	bind_ro("/usr", path, 0);
	snprintf(path, sizeof(path), "%s/sys", mnt);
	if (mount("sysfs", path, "sysfs",
		  MS_RDONLY | MS_NOSUID | MS_NODEV, NULL)) {
		fprintf(stderr, "aik-sandbox: 新 sysfs 挂载失败（%s），回退"
			"宿主 /sys ro bind（netns 视图仍可能是宿主）\n",
			strerror(errno));
		bind_ro("/sys", path, 0);
	}

	/* 6. /etc 白名单（单文件 ro bind + aikernel 目录 ro bind）。
	 *    bind 目标 inode 须先存在：文件源建空文件，目录源建目录 */
	for (i = 0; SB_ETC_FILES[i]; i++) {
		const char *f = SB_ETC_FILES[i];
		const char *base = strrchr(f, '/') + 1;

		if (!file_exists(f))
			continue;
		if (strcmp(base, "ca-certificates.crt") == 0)
			snprintf(path, sizeof(path),
				 "%s/etc/ssl/certs/ca-certificates.crt",
				 mnt);
		else
			snprintf(path, sizeof(path), "%s/etc/%s", mnt, base);
		close(open(path, O_CREAT | O_WRONLY, 0444));
		bind_ro(f, path, 0);
	}
	if (file_exists("/etc/aikernel")) {
		snprintf(path, sizeof(path), "%s/etc/aikernel", mnt);
		mkdir_p(path, 0755);
		bind_ro("/etc/aikernel", path, 0);
	}

	/* 7. /dev 最小集（bind 设备节点；设备打开不受根 tmpfs nodev 影响） */
	for (i = 0; SB_DEV_MUST[i]; i++) {
		snprintf(src, sizeof(src), "/dev/%s", SB_DEV_MUST[i]);
		snprintf(path, sizeof(path), "%s/dev/%s", mnt,
			 SB_DEV_MUST[i]);
		if (!file_exists(src))
			die(2, "宿主缺少 %s，无法组装最小 /dev", src);
		close(open(path, O_CREAT | O_WRONLY, 0666));
		bind_rw(src, path, 0);
	}
	for (i = 0; SB_DEV_OPT[i]; i++) {
		snprintf(src, sizeof(src), "/dev/%s", SB_DEV_OPT[i]);
		snprintf(path, sizeof(path), "%s/dev/%s", mnt,
			 SB_DEV_OPT[i]);
		if (!file_exists(src))
			continue;
		close(open(path, O_CREAT | O_WRONLY, 0666));
		if (mount(src, path, NULL, MS_BIND, NULL))
			fprintf(stderr, "aik-sandbox: bind %s 失败（忽略）:"
				" %s\n", src, strerror(errno));
	}

	/* 8. 产物通道：唯一的 rw 宿主目录，nodev+nosuid 限制 */
	snprintf(path, sizeof(path), "%s%s/%s", mnt, SB_ARTIFACT_CANON,
		 a->name);
	mkdir_p(path, 0755);
	if (a->artifact_host && is_dir(a->artifact_host)) {
		if (mount(a->artifact_host, path, NULL, MS_BIND, NULL))
			fprintf(stderr, "aik-sandbox: bind 产物区 %s 失败"
				"（忽略）: %s\n", a->artifact_host,
				strerror(errno));
		else if (mount(NULL, path, NULL,
			       MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV,
			       NULL))
			fprintf(stderr, "aik-sandbox: remount nodev 产物区"
				"失败（忽略）: %s\n", strerror(errno));
	}

	/* 9. 配置拷入（拷贝而非 bind：宿主 /root 整体不可见，写不回，
	 *    退出即焚）。只取子智能体启动必需的 model.toml/provider.toml */
	home = getenv("HOME");
	if (!home || !home[0])
		home = "/root";
	snprintf(src, sizeof(src), "%s/.aikernel/model.toml", home);
	snprintf(path, sizeof(path), "%s/root/.aikernel/model.toml", mnt);
	copy_file(src, path, 0600);
	snprintf(src, sizeof(src), "%s/.aikernel/provider.toml", home);
	snprintf(path, sizeof(path), "%s/root/.aikernel/provider.toml", mnt);
	copy_file(src, path, 0600);

	/* 10. 切根：优先 pivot_root（常规 rootfs 环境）；失败（如 initramfs
	 *    rootfs——内核不允许从 rootfs pivot，qemu 演练实证 EINVAL）
	 *    回退 busybox switch_root 同款 MS_MOVE+chroot */
	if (chdir(mnt))
		die(2, "chdir %s: %s", mnt, strerror(errno));
	if (syscall(SYS_pivot_root, ".", "./.old") == 0) {
		if (chdir("/"))
			die(2, "chdir /: %s", strerror(errno));
		if (umount2("/.old", MNT_DETACH))
			fprintf(stderr, "aik-sandbox: 旧根卸载: %s\n",
				strerror(errno));
		rmdir("/.old");
	} else {
		if (mount(mnt, "/", NULL, MS_MOVE, NULL))
			die(2, "pivot_root 与 MS_MOVE 切根均失败: %s",
			    strerror(errno));
		if (chroot("."))
			die(2, "chroot: %s", strerror(errno));
		if (chdir("/"))
			die(2, "chdir /: %s", strerror(errno));
	}

	/* 10b. fresh procfs（W71）：切根后挂到新根 /proc。procfs superblock
	 *      绑定挂载时的 PID namespace，故只列本沙盒进程；宿主 PID、
	 *      /proc/<hostpid>/root、/proc/1/root 全部不可见。只读挂载：
	 *      /proc/sys 的部分文件对 uid 0 可写，不能给沙盒改宿主全局参数
	 *      的机会（--net none 的 net sysctl 也一并不给写）。AIKernel 的
	 *      /proc/ai 是 procfs 顶层节点，新挂后照常可读。失败即失败，
	 *      绝不回退宿主 /proc bind（否则隔离承诺失效）。 */
	if (mount("proc", "/proc", "proc",
		  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
		die(2, "挂载沙盒内新 procfs: %s（不回退宿主 /proc bind）",
		    strerror(errno));

	/* 11. 身份与运行时环境 */
	if (sethostname(a->name, strlen(a->name)))
		fprintf(stderr, "aik-sandbox: sethostname(忽略): %s\n",
			strerror(errno));
	setenv("AIKERNEL_SANDBOX", a->name, 1);
	setenv("HOME", "/root", 1);
	setenv("TMPDIR", "/tmp", 0);
	umask(022);

	/* 12. 能力裁剪（W71）：NO_NEW_PRIVS + CapEff/CapBnd 只留 CAP_NET_RAW。
	 *     必须在 mount/切根/sethostname 之后——这些步骤需要 CAP_SYS_ADMIN。
	 *     失败 fail-closed（见 sandbox_drop_caps）。 */
	sandbox_drop_caps();

	/* 13. 交棒 */
	execvp(a->argv[0], a->argv);
	fprintf(stderr, "aik-sandbox: exec %s: %s\n", a->argv[0],
		strerror(errno));
	_exit(127);
}

/* ---- 限额/选项解析 ---- */

static int parse_cpus(const char *s, int *out_x100)
{
	char *end;
	double v;

	if (!s || !s[0])
		return -1;
	errno = 0;
	v = strtod(s, &end);
	if (errno || *end || v < 0 || v > 64)
		return -1;
	*out_x100 = (int)(v * 100.0 + 0.5);
	if (v > 0 && *out_x100 == 0)
		*out_x100 = 1;          /* 最小 0.01 CPU，避免四舍五入成“不限” */
	return 0;
}

static int parse_num(const char *s, long min, long max, long *out)
{
	char *end;
	long v;

	if (!s || !s[0])
		return -1;
	errno = 0;
	v = strtol(s, &end, 10);
	if (errno || *end || v < min || v > max)
		return -1;
	*out = v;
	return 0;
}

static void config_defaults(struct sb_config *c)
{
	memset(c, 0, sizeof(*c));
	c->lim.cpus_x100 = SB_DEF_CPUS_X100;
	c->lim.mem_mb = SB_DEF_MEM_MB;
	c->lim.pids_max = SB_DEF_PIDS;
	c->cgroup = 1;
}

static void config_env(struct sb_config *c)
{
	const char *e;
	long v;

	e = getenv("AIKERNEL_SANDBOX_CPUS");
	if (e && e[0]) {
		if (parse_cpus(e, &c->lim.cpus_x100))
			fprintf(stderr, "aik-sandbox: 警告: 忽略非法 "
				"AIKERNEL_SANDBOX_CPUS=%s\n", e);
	}
	e = getenv("AIKERNEL_SANDBOX_MEM_MB");
	if (e && e[0]) {
		if (parse_num(e, 0, 1048576, &v))
			fprintf(stderr, "aik-sandbox: 警告: 忽略非法 "
				"AIKERNEL_SANDBOX_MEM_MB=%s\n", e);
		else
			c->lim.mem_mb = v;
	}
	e = getenv("AIKERNEL_SANDBOX_PIDS");
	if (e && e[0]) {
		if (parse_num(e, 0, 4000000, &v))
			fprintf(stderr, "aik-sandbox: 警告: 忽略非法 "
				"AIKERNEL_SANDBOX_PIDS=%s\n", e);
		else
			c->lim.pids_max = v;
	}
	e = getenv("AIKERNEL_SANDBOX_NET");
	if (e && e[0]) {
		if (strcmp(e, "none") == 0)
			c->net_none = 1;
		else if (strcmp(e, "host") == 0)
			c->net_none = 0;
		else
			fprintf(stderr, "aik-sandbox: 警告: 忽略非法 "
				"AIKERNEL_SANDBOX_NET=%s（none|host）\n", e);
	}
	e = getenv("AIKERNEL_SANDBOX_NO_CGROUP");
	if (e && e[0] && strcmp(e, "0") != 0 && strcmp(e, "no") != 0 &&
	    strcmp(e, "off") != 0)
		c->cgroup = 0;
}

/* 解析 create/run 通用选项；返回停在的下标（"--" 或首个非选项） */
static int parse_opts(struct sb_config *c, int argc, char **argv, int i)
{
	for (; i < argc; i++) {
		const char *a = argv[i];
		const char *val = NULL;
		char key[32];

		if (strcmp(a, "--") == 0)
			return i;
		if (strcmp(a, "--keep") == 0) {
			c->keep = 1;
			continue;
		}
		if (strcmp(a, "--no-cgroup") == 0) {
			c->cgroup = 0;
			continue;
		}
		if (strncmp(a, "--", 2) != 0)
			return i;
		{
			const char *eq = strchr(a, '=');

			if (eq) {
				size_t kl = (size_t)(eq - a);

				if (kl >= sizeof(key))
					die(1, "未知选项: %s", a);
				memcpy(key, a, kl);
				key[kl] = '\0';
				val = eq + 1;
			} else {
				snprintf(key, sizeof(key), "%s", a);
			}
		}
		if (strcmp(key, "--cpus") == 0 ||
		    strcmp(key, "--mem-mb") == 0 ||
		    strcmp(key, "--pids") == 0 ||
		    strcmp(key, "--net") == 0) {
			if (!val) {
				if (++i >= argc)
					die(1, "%s 需要参数", key);
				val = argv[i];
			}
			if (strcmp(key, "--cpus") == 0) {
				if (parse_cpus(val, &c->lim.cpus_x100))
					die(1, "非法 --cpus '%s'（0-64）", val);
			} else if (strcmp(key, "--mem-mb") == 0) {
				if (parse_num(val, 0, 1048576,
					      &c->lim.mem_mb))
					die(1, "非法 --mem-mb '%s'", val);
			} else if (strcmp(key, "--pids") == 0) {
				if (parse_num(val, 0, 4000000,
					      &c->lim.pids_max))
					die(1, "非法 --pids '%s'", val);
			} else {
				if (strcmp(val, "none") == 0)
					c->net_none = 1;
				else if (strcmp(val, "host") == 0)
					c->net_none = 0;
				else
					die(1, "非法 --net '%s'"
					    "（none|host）", val);
			}
			continue;
		}
		die(1, "未知选项: %s", a);
	}
	return i;
}

static void lim_from_meta(struct sb_config *c, const struct sb_meta *m)
{
	c->lim.cpus_x100 = m->cpus_x100;
	c->lim.mem_mb = m->mem_mb;
	c->lim.pids_max = m->pids_max;
	c->net_none = m->net_none;
}

/* ---- 子命令 ---- */

static int cmd_create(const char *name, int argc, char **argv, int opti)
{
	struct sb_config cfg;
	struct sb_meta m;
	struct cg_state st;
	char dir[PATH_MAX], mnt[PATH_MAX], art[PATH_MAX], info[PATH_MAX];
	char pids[512], cgdir[PATH_MAX];
	int lockfd, cgexists, stop;

	config_defaults(&cfg);
	config_env(&cfg);
	stop = parse_opts(&cfg, argc, argv, opti);
	if (stop < argc)
		die(1, "create 的多余参数: %s", argv[stop]);
	if (!valid_name(name))
		die(1, "非法区名 '%s'（允许 [A-Za-z0-9._-]，不许点开头/连续点）",
		    name ? name : "");

	mkdir_p(sb_base(), 0755);
	snprintf(dir, sizeof(dir), "%s/%s", sb_base(), name);
	snprintf(mnt, sizeof(mnt), "%s/root", dir);
	cg_dir_for(name, cgdir, sizeof(cgdir));
	cgexists = is_dir(cgdir);

	if (scan_live_pids(name, pids, sizeof(pids)) > 0) {
		printf("create: %s 已存在且存活（pid=%s），复用现有隔离区\n",
		       name, pids);
		return 0;
	}
	if (file_exists(dir) || cgexists) {
		printf("create: 检测到 %s 的历史残留（无存活 run 进程），"
		       "先回收\n", name);
		reap_entry(name, 0);
	}

	mkdir_p(dir, 0755);
	mkdir_p(mnt, 0755);
	lockfd = sb_trylock(name, 1000);
	if (lockfd < 0) {
		fprintf(stderr, "aik-sandbox: %s 正被其他进程使用（锁忙），"
			"create 放弃\n", name);
		return 1;
	}

	if (cfg.cgroup) {
		if (cg_setup(name, &cfg.lim, &st, info, sizeof(info)) < 0)
			snprintf(info, sizeof(info), "cgroup=off");
	} else {
		fprintf(stderr, "aik-sandbox: 警告: cgroup 已被显式禁用"
			"（--no-cgroup / AIKERNEL_SANDBOX_NO_CGROUP），"
			"资源限额降级\n");
		memset(&st, 0, sizeof(st));
		snprintf(info, sizeof(info), "cgroup=off");
	}

	if (ensure_artifact_dir(name, art, sizeof(art)))
		art[0] = '\0';

	memset(&m, 0, sizeof(m));
	snprintf(m.name, sizeof(m.name), "%s", name);
	m.created = (long)time(NULL);
	m.cpus_x100 = cfg.lim.cpus_x100;
	m.mem_mb = cfg.lim.mem_mb;
	m.pids_max = cfg.lim.pids_max;
	m.cpu_limit = st.cpu;
	m.mem_limit = st.mem;
	m.pids_limit = st.pids;
	m.net_none = cfg.net_none;
	m.cgroup = st.enabled;
	snprintf(m.status, sizeof(m.status), "created");
	if (meta_write(name, &m))
		fprintf(stderr, "aik-sandbox: 警告: 元数据写入失败（%s）\n",
			strerror(errno));

	printf("create: %s 就绪（挂载点 %s；%s；net=%s；产物=%s）\n",
	       name, mnt, info, cfg.net_none ? "none" : "host",
	       art[0] ? art : "(不可用)");
	close(lockfd);
	return 0;
}

static int cmd_destroy(const char *name)
{
	char dir[PATH_MAX], cgdir[PATH_MAX], art[PATH_MAX];
	int existed, lockfd;

	if (!valid_name(name))
		die(1, "非法区名 '%s'", name ? name : "");
	snprintf(dir, sizeof(dir), "%s/%s", sb_base(), name);
	cg_dir_for(name, cgdir, sizeof(cgdir));
	existed = file_exists(dir) || is_dir(cgdir);

	/* 先杀 run 包装进程，让锁释放；再拿锁做完整回收。
	 * 目录已不存在时没有锁文件，直接回收（不误报“锁忙”）。 */
	kill_live_runs(name);
	lockfd = is_dir(dir) ? sb_trylock(name, 2000) : -1;
	if (lockfd < 0 && is_dir(dir))
		fprintf(stderr, "aik-sandbox: 警告: %s 锁忙（有活跃 run？），"
			"仍执行强制回收\n", name);
	reap_entry(name, 0);
	if (lockfd >= 0)
		close(lockfd);
	if (is_dir(cgdir) || file_exists(dir))
		fprintf(stderr, "aik-sandbox: 警告: %s 仍有残留（可能进程处于"
			"D 状态），请稍后重试 destroy\n", name);

	snprintf(art, sizeof(art), "%s/%s", artifact_root(), name);
	if (existed)
		printf("destroy: %s 已焚毁（进程组/cgroup/挂载/目录已回收；"
		       "产物保留于 %s）\n", name, art);
	else
		printf("destroy: %s 无残留（本就干净）\n", name);
	return 0;
}

static int cmd_status(void)
{
	DIR *d;
	struct dirent *e;
	int count = 0;
	char parent[PATH_MAX], cgdir[PATH_MAX];

	d = opendir(sb_base());
	if (!d) {
		printf("status: 尚无隔离区（%s 不存在）\n", sb_base());
		return 0;
	}
	while ((e = readdir(d))) {
		struct sb_meta m;
		char pids[512], mnt[PATH_MAX], limits[256], state[64];
		int live, procs, lockfd, meta_ok;

		if (e->d_name[0] == '.')
			continue;
		if (!valid_name(e->d_name))
			continue;
		snprintf(mnt, sizeof(mnt), "%s/%s", sb_base(), e->d_name);
		if (!is_dir(mnt))
			continue;
		count++;
		live = scan_live_pids(e->d_name, pids, sizeof(pids));
		meta_ok = meta_read(e->d_name, &m) == 0;
		cg_dir_for(e->d_name, cgdir, sizeof(cgdir));
		procs = cg_procs_count_dir(cgdir);
		lockfd = sb_trylock(e->d_name, 100);

		if (!live && procs > 0 && lockfd >= 0) {
			printf("%-16s 状态=stale（包装进程已死，cgroup 内 %d 个"
			       "孤儿），回收\n", e->d_name, procs);
			reap_entry(e->d_name, 0);
			if (lockfd >= 0)
				close(lockfd);
			continue;
		}
		if (!live && meta_ok && lockfd >= 0 &&
		    (strcmp(m.status, "running") == 0 ||
		     strcmp(m.status, "starting") == 0)) {
			printf("%-16s 状态=stale（%s 无存活进程），回收\n",
			       e->d_name, m.status);
			reap_entry(e->d_name, 0);
			if (lockfd >= 0)
				close(lockfd);
			continue;
		}
		if (!live && !meta_ok && lockfd >= 0) {
			printf("%-16s 状态=stale（无 meta 的残留目录），回收\n",
			       e->d_name);
			reap_entry(e->d_name, 0);
			if (lockfd >= 0)
				close(lockfd);
			continue;
		}

		snprintf(mnt, sizeof(mnt), "%s/%s/root", sb_base(),
			 e->d_name);
		if (meta_ok)
			snprintf(limits, sizeof(limits),
				 "cpu=%.2f%s mem=%ldMB%s pids=%ld%s net=%s",
				 m.cpus_x100 / 100.0,
				 m.cpu_limit ? "" : "(降级)",
				 m.mem_mb, m.mem_limit ? "" : "(降级)",
				 m.pids_max, m.pids_limit ? "" : "(降级)",
				 m.net_none ? "none" : "host");
		else
			snprintf(limits, sizeof(limits), "-");
		if (live)
			snprintf(state, sizeof(state), "running");
		else
			snprintf(state, sizeof(state), "%s",
				 meta_ok ? m.status : "unknown");
		printf("%-16s 挂载点=%s 存活pid=%s cgroup=%s 限额=%s "
		       "状态=%s 进程数=%d\n",
		       e->d_name, file_exists(mnt) ? mnt : "(缺)",
		       pids[0] ? pids : "-", is_dir(cgdir) ? cgdir : "-",
		       limits, state, procs < 0 ? 0 : procs);
		if (lockfd >= 0)
			close(lockfd);
	}
	if (!count)
		printf("status: 尚无隔离区\n");
	closedir(d);

	/* 孤儿 cgroup：目录已不在 <base> 下，但仍占着锚点 */
	cg_parent(parent, sizeof(parent));
	d = opendir(parent);
	if (d) {
		while ((e = readdir(d))) {
			char dir[PATH_MAX], sbdir[PATH_MAX];

			if (e->d_name[0] == '.' || !valid_name(e->d_name))
				continue;
			snprintf(sbdir, sizeof(sbdir), "%s/%s", sb_base(),
				 e->d_name);
			if (file_exists(sbdir))
				continue;
			snprintf(dir, sizeof(dir), "%s/%s", parent,
				 e->d_name);
			/* 锚点 cgroup 里的控制器文件（memory.max 等）不是子
			 * cgroup，跳过——否则 status 会把它们误报成孤儿。 */
			if (!is_dir(dir))
				continue;
			printf("status: 回收孤儿 cgroup %s\n", dir);
			cg_kill_dir(dir);
			cg_remove_dir(dir);
		}
		closedir(d);
	}
	return 0;
}

/* ---- run ---- */

/*
 * 用 glibc 的 clone() 包装（而不是裸 clone3）：裸 clone3 的 child 会从
 * syscall 之后继续执行且栈指针已切到新栈，glibc syscall() 的 ret 会从
 * 空栈取返回地址而崩溃（QEMU 实证 SIGSEGV at stack top）。clone() 包装
 * 负责在新栈上布置 child 入口与参数。cgroup 归组改由子进程第一条语句
 * 自己写 cgroup.procs "0"（只移动自己）；与内核限额之间只有微秒级窗口，
 * 且该窗口内尚未 exec 任何用户命令。实测 cgroup.procs 归属正确。
 */
static pid_t do_clone(struct child_args *a, void *stack, int net_none)
{
	uint64_t flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS;

	if (net_none)
		flags |= CLONE_NEWNET;
	return clone(sandbox_child, (char *)stack + SB_STACK_SIZE,
		     (int)(flags | SIGCHLD), a);
}

static int cmd_run(const char *name, int argc, char **argv, int opti)
{
	struct sb_config cfg;
	struct sb_meta m;
	struct cg_state st;
	struct child_args a;
	char dir[PATH_MAX], mnt[PATH_MAX], art[PATH_MAX], info[PATH_MAX];
	char pids[512];
	void *stack;
	pid_t pid;
	int st_status = 0, lockfd, ephemeral = 0;
	int sep, have_meta, i;
	long created0 = 0;
	char *child_argv[256];
	int child_argc = 0;

	config_defaults(&cfg);
	have_meta = meta_read(name, &m) == 0;
	if (have_meta) {
		lim_from_meta(&cfg, &m);
		created0 = m.created;
	}
	config_env(&cfg);

	sep = parse_opts(&cfg, argc, argv, opti);
	if (sep >= argc || strcmp(argv[sep], "--") != 0)
		die(1, "run 需要 -- <cmd> [args...]");
	if (argc - sep - 1 > 255)
		die(1, "参数过多（上限 255）");
	for (i = sep + 1; i < argc; i++)
		child_argv[child_argc++] = argv[i];
	child_argv[child_argc] = NULL;
	if (child_argc < 1)
		die(1, "run 需要 -- <cmd> [args...]");
	if (!valid_name(name))
		die(1, "非法区名 '%s'", name);

	snprintf(dir, sizeof(dir), "%s/%s", sb_base(), name);
	snprintf(mnt, sizeof(mnt), "%s/root", dir);

	if (scan_live_pids(name, pids, sizeof(pids)) > 0)
		die(1, "隔离区 %s 已有 run 进程（pid=%s），拒绝并发重入",
		    name, pids);
	if (!file_exists(dir) || !file_exists(mnt)) {
		fprintf(stderr, "aik-sandbox: 挂载点不存在，已自动创建 %s\n",
			mnt);
		mkdir_p(sb_base(), 0755);
		mkdir_p(dir, 0755);
		mkdir_p(mnt, 0755);
		ephemeral = 1;
	}
	lockfd = sb_trylock(name, 0);
	if (lockfd < 0)
		die(1, "隔离区 %s 正被其他进程使用（锁忙），拒绝并发 run",
		    name);

	if (ensure_artifact_dir(name, art, sizeof(art)))
		art[0] = '\0';

	if (cfg.cgroup) {
		if (cg_setup(name, &cfg.lim, &st, info, sizeof(info)) < 0)
			snprintf(info, sizeof(info), "cgroup=off");
	} else {
		fprintf(stderr, "aik-sandbox: 警告: cgroup 已被显式禁用，"
			"资源限额降级\n");
		memset(&st, 0, sizeof(st));
		snprintf(info, sizeof(info), "cgroup=off");
	}

	/* 先落 meta（starting），父进程被杀后 status/create 可识别 */
	memset(&m, 0, sizeof(m));
	snprintf(m.name, sizeof(m.name), "%s", name);
	m.created = created0 ? created0 : (long)time(NULL);
	m.cpus_x100 = cfg.lim.cpus_x100;
	m.mem_mb = cfg.lim.mem_mb;
	m.pids_max = cfg.lim.pids_max;
	m.cpu_limit = st.cpu;
	m.mem_limit = st.mem;
	m.pids_limit = st.pids;
	m.net_none = cfg.net_none;
	m.cgroup = st.enabled;
	snprintf(m.status, sizeof(m.status), "starting");
	if (meta_write(name, &m))
		fprintf(stderr, "aik-sandbox: 警告: 元数据写入失败（%s）\n",
			strerror(errno));

	a.name = (char *)name;
	a.mnt = mnt;
	a.argv = child_argv;
	a.cgroup_dir = st.enabled ? st.dir : NULL;
	a.artifact_host = art[0] ? art : NULL;
	a.net_none = cfg.net_none;

	stack = mmap(NULL, SB_STACK_SIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED)
		die(2, "mmap stack: %s", strerror(errno));

	pid = do_clone(&a, stack, cfg.net_none);
	if (pid < 0)
		die(2, "clone(NS|PID|UTS%s): %s（需要 root/CAP_SYS_ADMIN）",
		    cfg.net_none ? "|NET" : "", strerror(errno));

	m.pid = (long)getpid();
	m.child_pid = (long)pid;
	m.started = (long)time(NULL);
	snprintf(m.status, sizeof(m.status), "running");
	if (meta_write(name, &m))
		fprintf(stderr, "aik-sandbox: 警告: 元数据写入失败（%s）\n",
			strerror(errno));

	while (waitpid(pid, &st_status, 0) < 0) {
		if (errno != EINTR) {
			m.ended = (long)time(NULL);
			snprintf(m.status, sizeof(m.status), "lost");
			meta_write(name, &m);
			die(2, "waitpid: %s", strerror(errno));
		}
	}

	/* PID namespace init 退出会带走全部后代；兜底清理任何残余 */
	if (st.enabled) {
		int procs = cg_procs_count_dir(st.dir);

		if (procs > 0) {
			fprintf(stderr, "aik-sandbox: 警告: run 结束后 cgroup "
				"仍有 %d 个进程，强制回收\n", procs);
			cg_kill_dir(st.dir);
		}
	}

	m.ended = (long)time(NULL);
	if (WIFEXITED(st_status))
		m.exit_code = WEXITSTATUS(st_status);
	else if (WIFSIGNALED(st_status))
		m.exit_code = 128 + WTERMSIG(st_status);
	snprintf(m.status, sizeof(m.status), "exited");
	meta_write(name, &m);

	munmap(stack, SB_STACK_SIZE);

	if (ephemeral && !cfg.keep)
		reap_entry(name, 0);
	close(lockfd);

	if (WIFEXITED(st_status)) {
		int code = WEXITSTATUS(st_status);

		if (code == 127)
			fputs("aik-sandbox: 沙盒内 exec 失败（命令在沙盒视"
			      "图中不可执行）\n", stderr);
		return code;
	}
	if (WIFSIGNALED(st_status)) {
		int sig = WTERMSIG(st_status);

		fprintf(stderr, "aik-sandbox: 子进程被信号 %d 击杀\n", sig);
		return 128 + sig;
	}
	return 2;
}

/* ---- export ---- */

static int has_dotdot(const char *rel)
{
	const char *p = rel;

	while (*p) {
		const char *s;

		while (*p == '/')
			p++;
		s = p;
		while (*p && *p != '/')
			p++;
		if ((p - s) == 2 && s[0] == '.' && s[1] == '.')
			return 1;
	}
	return 0;
}

/* 逻辑路径 → artifact root 下的相对路径（src 相对路径按 <name>/ 解释） */
static int artifact_rel(const char *name, const char *arg, int src,
			char *rel, size_t relsz)
{
	const char *canon = SB_ARTIFACT_CANON;
	size_t cl = strlen(canon);
	const char *p = arg;

	if (!arg || !arg[0])
		return -1;
	if (p[0] == '/') {
		if (strncmp(p, canon, cl) != 0 ||
		    (p[cl] != '/' && p[cl] != '\0'))
			return -1;
		p += cl;
		while (*p == '/')
			p++;
		if (!*p)
			return -1;
		if (snprintf(rel, relsz, "%s", p) >= (int)relsz)
			return -1;
	} else if (src) {
		if (snprintf(rel, relsz, "%s/%s", name, p) >= (int)relsz)
			return -1;
	} else {
		if (snprintf(rel, relsz, "%s", p) >= (int)relsz)
			return -1;
	}
	if (strstr(rel, "//") || has_dotdot(rel) || rel[0] == '/')
		return -1;
	return 0;
}

static int openat2_beneath(int dirfd, const char *rel, int flags)
{
	struct sb_open_how how;

	memset(&how, 0, sizeof(how));
	how.flags = (uint64_t)flags;
	how.resolve = SB_RESOLVE_BENEATH | SB_RESOLVE_NO_MAGICLINKS;
	return (int)syscall(SYS_openat2, dirfd, rel, &how, sizeof(how));
}

/* 逐级打开（可选创建）目录，全部带 O_NOFOLLOW；返回最终 dirfd */
static int open_dir_beneath(int rootfd, const char *rel, int create)
{
	char buf[PATH_MAX];
	char *p, *slash;
	int cur, next;

	if (snprintf(buf, sizeof(buf), "%s", rel) >= (int)sizeof(buf))
		return -1;
	cur = dup(rootfd);
	if (cur < 0)
		return -1;
	p = buf;
	while (*p) {
		while (*p == '/')
			p++;
		if (!*p)
			break;
		slash = strchr(p, '/');
		if (slash)
			*slash = '\0';
		next = openat(cur, p, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
			      O_NOFOLLOW);
		if (next < 0 && errno == ENOENT && create) {
			if (mkdirat(cur, p, 0700) && errno != EEXIST) {
				close(cur);
				return -1;
			}
			next = openat(cur, p, O_RDONLY | O_DIRECTORY |
				      O_CLOEXEC | O_NOFOLLOW);
		}
		if (next < 0) {
			close(cur);
			return -1;
		}
		close(cur);
		cur = next;
		if (!slash)
			break;
		p = slash + 1;
	}
	return cur;
}

static long copy_fd(int in, int out, int *errp)
{
	char buf[65536];
	long total = 0;

	for (;;) {
		ssize_t n = read(in, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			*errp = errno;
			return -1;
		}
		if (n == 0)
			break;
		{
			ssize_t off = 0;

			while (off < n) {
				ssize_t w = write(out, buf + off,
						  (size_t)(n - off));

				if (w < 0) {
					if (errno == EINTR)
						continue;
					*errp = errno;
					return -1;
				}
				off += w;
			}
		}
		total += n;
	}
	return total;
}

static int cmd_export(const char *name, const char *src, const char *dest)
{
	char root[PATH_MAX], rel[PATH_MAX], rel_dir[PATH_MAX];
	char inner[PATH_MAX], base[PATH_MAX];
	struct stat sb;
	int rootfd, namefd, srcfd, parentfd, destfd;
	int n, err = 0;
	size_t nl;
	char *slash;

	if (!valid_name(name))
		die(1, "非法区名 '%s'", name ? name : "");
	if (!src || !src[0] || !dest || !dest[0])
		die(1, "export 需要 <src> <dest>");

	if (mkdir_p_soft(artifact_root(), 0700) ||
	    !realpath(artifact_root(), root))
		die(1, "产物区不可用: %s", artifact_root());

	if (artifact_rel(name, src, 1, rel, sizeof(rel)))
		die(1, "非法 src '%s'（只允许 %s/%s/ 下的相对路径或该前缀"
		    "绝对路径）", src, SB_ARTIFACT_CANON, name);
	nl = strlen(name);
	if (strlen(rel) <= nl || strncmp(rel, name, nl) != 0 ||
	    rel[nl] != '/')
		die(1, "非法 src '%s'（必须位于 %s/%s/ 下）", src,
		    SB_ARTIFACT_CANON, name);
	snprintf(inner, sizeof(inner), "%s", rel + nl + 1);
	if (!inner[0])
		die(1, "src 必须是文件，不能是目录");

	rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		die(1, "打开产物区 %s: %s", root, strerror(errno));
	namefd = openat(rootfd, name, O_RDONLY | O_DIRECTORY |
			O_CLOEXEC | O_NOFOLLOW);
	if (namefd < 0)
		die(1, "产物目录 %s/%s 不存在或不可用: %s", root, name,
		    strerror(errno));

	srcfd = openat2_beneath(namefd, inner, O_RDONLY | O_CLOEXEC);
	if (srcfd < 0 && errno == ENOSYS) {
		/* 老内核兜底：realpath 后必须仍在 <root>/<name>/ 下 */
		char full[PATH_MAX], rp[PATH_MAX], pref[PATH_MAX];

		if (snprintf(full, sizeof(full), "%s/%s/%s", root, name,
			     inner) >= (int)sizeof(full) ||
		    !realpath(full, rp))
			die(1, "src 不可解析: %s", src);
		snprintf(pref, sizeof(pref), "%s/%s/", root, name);
		if (strncmp(rp, pref, strlen(pref)) != 0)
			die(1, "拒绝 symlink 逃逸: %s", src);
		srcfd = open(rp, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	}
	if (srcfd < 0)
		die(1, "打开 src '%s' 失败（symlink 逃逸/不存在/非普通文件）："
		    "%s", src, strerror(errno));
	if (fstat(srcfd, &sb) || !S_ISREG(sb.st_mode))
		die(1, "src '%s' 不是普通文件", src);

	if (artifact_rel(name, dest, 0, rel_dir, sizeof(rel_dir)))
		die(1, "非法 dest '%s'（只允许 %s/ 下的相对路径或该前缀"
		    "绝对路径）", dest, SB_ARTIFACT_CANON);

	slash = strrchr(rel_dir, '/');
	if (!slash)
		die(1, "非法 dest '%s'（缺少目录，如 exports/%s）",
		    dest, name);
	*slash = '\0';
	snprintf(base, sizeof(base), "%s", slash + 1);
	if (!base[0] || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
		die(1, "非法 dest 文件名");

	parentfd = rel_dir[0] ? open_dir_beneath(rootfd, rel_dir, 1) :
				dup(rootfd);
	if (parentfd < 0)
		die(1, "创建/打开 dest 目录 '%s' 失败: %s", rel_dir,
		    strerror(errno));
	destfd = openat(parentfd, base, O_WRONLY | O_CREAT | O_EXCL |
			O_CLOEXEC | O_NOFOLLOW, 0600);
	if (destfd < 0)
		die(1, "打开 dest '%s' 失败（目标已存在或为 symlink）：%s",
		    dest, strerror(errno));

	n = (int)copy_fd(srcfd, destfd, &err);
	if (n < 0) {
		unlinkat(parentfd, base, 0);
		close(destfd);
		close(srcfd);
		close(parentfd);
		close(namefd);
		close(rootfd);
		die(1, "复制失败: %s", strerror(err));
	}
	if (fsync(destfd))
		fprintf(stderr, "aik-sandbox: 警告: fsync %s: %s\n", dest,
			strerror(errno));
	close(destfd);
	close(srcfd);
	close(parentfd);
	close(namefd);
	close(rootfd);

	printf("export: %s -> %s（%d 字节）\n", src, dest, n);
	return 0;
}

/* ---- 入口 ---- */

static void usage(FILE *fp)
{
	fputs(
"aik-sandbox - AIKernel 隔离区工具（W42 建区 / W64 成熟化）\n"
"用法:\n"
"  aik-sandbox create <name> [选项]\n"
"  aik-sandbox run <name> [--keep] [选项] -- <cmd> [args...]\n"
"  aik-sandbox destroy <name>\n"
"  aik-sandbox status\n"
"  aik-sandbox export <name> <src> <dest>\n"
"      src 相对路径按 /var/ai/sandbox-artifacts/<name>/ 解释；\n"
"      dest 相对路径按 /var/ai/sandbox-artifacts/ 解释；\n"
"      两者都只接受该根下路径（拒绝 symlink 逃逸；dest 不覆盖）。\n"
"\n"
"选项（create/run）:\n"
"  --cpus N         CPU 配额，0=不限（默认 1.0）\n"
"  --mem-mb N       内存上限 MB，0=不限（默认 1024）\n"
"  --pids N         任务数上限，0=不限（默认 256）\n"
"  --net none|host  网络隔离（默认 host；none 时仅 lo 可用）\n"
"  --no-cgroup      禁用 cgroup（明确告警降级）\n"
"\n"
"环境变量：AIKERNEL_SANDBOX_CPUS/MEM_MB/PIDS/NET/NO_CGROUP，\n"
"          AIKERNEL_SANDBOX_ARTIFACTS（宿主产物根，默认\n"
"          /var/ai/sandbox-artifacts；沙盒内固定为\n"
"          /var/ai/sandbox-artifacts/<name>）。\n", fp);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(stderr);
		return 1;
	}
	if (strcmp(argv[1], "create") == 0) {
		if (argc < 3) {
			usage(stderr);
			return 1;
		}
		return cmd_create(argv[2], argc, argv, 3);
	}
	if (strcmp(argv[1], "destroy") == 0 && argc == 3)
		return cmd_destroy(argv[2]);
	if (strcmp(argv[1], "status") == 0 && argc == 2)
		return cmd_status();
	if (strcmp(argv[1], "export") == 0 && argc == 5)
		return cmd_export(argv[2], argv[3], argv[4]);
	if (strcmp(argv[1], "run") == 0) {
		if (argc < 4) {
			usage(stderr);
			return 1;
		}
		return cmd_run(argv[2], argc, argv, 3);
	}
	usage(stderr);
	return 1;
}
