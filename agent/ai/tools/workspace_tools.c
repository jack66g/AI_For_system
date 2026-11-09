/* SPDX-License-Identifier: GPL-2.0 */
/*
 * workspace_tools.c - W79 持久工作区实现（TOOL_CH_WORKSPACE，六件）
 *
 * 设计纪律：
 *  - 工作区 = 宿主稀疏镜像 /var/lib/aikernel/ws/<name>.img，loop 挂 ext4；
 *  - 隔离执行完全复用 aik-sandbox：workspace_run 只是
 *      aik-sandbox run <name> --backing=disk:<img> -- /bin/sh -c <command>
 *    的宿主侧包装（namespace/pivot_root/ro-bind/capset/cgroup 全在沙盒侧，
 *    本文件绝不自己 clone/mount 宿主根）；
 *  - 元数据落 <root>/<name>.meta（原子替换），记录镜像/loop/容量/限额/
 *    标签/ro/rw 拓扑；sandbox 的 meta 只作 loop 回读的补充；
 *  - destroy 幂等：先 aik-sandbox destroy（杀进程/收 cgroup/卸挂载）→
 *    解 loop → 删镜像 → 删元数据；不存在时返回成功；
 *  - 校验防注入：name [A-Za-z0-9_.-]{1,32}，size 16-8192MB，路径必须
 *    绝对且拒绝系统关键面；命令以 argv 直交给 sh -c，不经宿主 shell
 *    拼接（command 字符串只作为 sh 的单个 argv）。
 *
 * W81d（V1.7）工作区网络：net=none|veth|host
 *  - veth：每个工作区一个独立 netns（aikws-<name>）+ 一对 veth
 *    （宿主侧 aikv<hash> / 工作区侧 aikc<hash>），宿主侧挂专用网桥
 *    aikbr0（10.231.0.1/16，只给工作区用，不设 NAT/不做转发）；
 *  - 缺省拒出站：netns 内一张 inet aik_ws_<name> 表，output/input 两条
 *    基链 policy drop，只放行 lo 与 ct established,related，外加显式
 *    白名单（allow=[{dst,port,proto}]）；
 *  - 宿主面只碰 aikbr0 与 aikv*（专用网桥/端口）：绝不改宿主 filter/nat
 *    表、默认路由或其他接口；nft 只在工作区 netns 内下发；
 *  - destroy 必须零残留：删 netns（连带表/地址）、删 veth、退出网桥成员、
 *    rmdir 产物目录（B-109）；
 *  - run 走 aik-sandbox --net=join:<ns>（setns 进已有 netns，失败即
 *    fail-closed，绝不退回宿主 netns）。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/loop.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "tools/workspace_tools.h"

/* 路径均以 PATH_MAX 上界构造，snprintf 静态范围无法收敛（与 sandbox 同款） */
#pragma GCC diagnostic ignored "-Wformat-truncation"

#define WS_MAX_NAME      32
#define WS_MIN_MB        16
#define WS_MAX_MB        8192
#define WS_MAX_PATHS     16
#define WS_OUT_MAX       (256 * 1024)
#define WS_SIMPLE_TIMEOUT 180
#define WS_RUN_TIMEOUT_DEF 120
#define WS_RUN_TIMEOUT_MAX 900

#define WS_ROOT_DEFAULT  "/var/lib/aikernel/ws"
#define WS_SB_BASE_DEFAULT "/sandbox"
#define WS_SB_BIN_DEFAULT  "/usr/local/bin/aik-sandbox"
#define WS_CG_ROOT_DEFAULT "/sys/fs/cgroup"
#define WS_ART_DEFAULT     "/var/ai/sandbox-artifacts"

/* ---- W81d：工作区网络常量 ----
 * 专用网桥固定 aikbr0 + 10.231.0.1/16；工作区地址从 10.231.<a>.<b> 分配
 * （a≥1，b∈[1,250]，跳过网络/广播/网桥自身）。绝不落在宿主其他网段。
 */
#define WS_BR_NAME        "aikbr0"
#define WS_BR_ADDR        "10.231.0.1"
#define WS_BR_CIDR        "10.231.0.1/16"
#define WS_NET_NS_PREFIX  "aikws-"
#define WS_NFT_TBL_PREFIX "aik_ws_"
#define WS_NETNS_DIR      "/var/run/netns"
#define WS_NET_NS_MAX     63
#define WS_ALLOW_MAX      32
#define WS_NET_TO         15            /* 单条 ip/nft 调用超时（秒） */
#define WS_NET_LOCK_TRIES 50            /* 网络锁重试（×100ms） */

/* net 模式（元数据 net= 字段） */
enum { WS_NET_HOST = 0, WS_NET_NONE = 1, WS_NET_VETH = 2 };

/* 白名单条目：dst 为 IPv4/IPv6 地址或 CIDR；port 0 = 任意端口；
 * proto ∈ tcp|udp|icmp|any（icmp 忽略 port） */
struct ws_allow {
	char dst[64];
	int port;
	char proto[8];
};

struct ws_meta {
	char name[WS_MAX_NAME + 1];
	char backing[8];
	char image[PATH_MAX];
	char loop[64];
	long size_mb;
	long created;
	char label[65];
	int cpus_x100;
	long mem_mb;
	long pids_max;
	int net_mode;                   /* WS_NET_HOST|NONE|VETH */
	char net_ns[WS_NET_NS_MAX + 1];
	char net_ip[64];                /* 工作区侧地址（不带掩码） */
	char net_host_if[32];
	char net_ws_if[32];
	/* W82e（V1.8）：sandbox 区名的原样别名。仅当区名超过 workspace 名
	 * 上限（32）需要映射成短名时写入；≤32 字符时为空（区名=工作区名）。 */
	char alias[65];
	struct ws_allow allow[WS_ALLOW_MAX];
	int allow_n;
	char ro[WS_MAX_PATHS][PATH_MAX];
	int ro_n;
	char rw[WS_MAX_PATHS][PATH_MAX];
	int rw_n;
};

/* ---- 纯函数校验（导出供单测） ---- */

int ai_ws_valid_name(const char *s)
{
	size_t i, n;

	if (!s || !s[0])
		return 0;
	n = strlen(s);
	if (n > WS_MAX_NAME)
		return 0;
	/* 首字符不许 '.'/'-'：避免隐藏文件与选项形态；"." ".." 一并拒绝 */
	if (!((s[0] >= 'a' && s[0] <= 'z') ||
	      (s[0] >= 'A' && s[0] <= 'Z') ||
	      (s[0] >= '0' && s[0] <= '9') || s[0] == '_'))
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

int ai_ws_valid_size_mb(long long mb)
{
	return mb >= WS_MIN_MB && mb <= WS_MAX_MB;
}

int ai_ws_valid_label(const char *s)
{
	size_t i, n;

	if (!s)
		return 1;               /* 空标签合法 */
	n = strlen(s);
	if (n > 64)
		return 0;
	for (i = 0; i < n; i++) {
		char c = s[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		      c == '.' || c == ' '))
			return 0;
	}
	return 1;
}

/* 宿主绝对路径（镜像/显式 bind 源）：无 ".." 段、无控制字符 */
static int ws_valid_host_path(const char *p)
{
	size_t n, i;
	const char *seg;

	if (!p || p[0] != '/')
		return 0;
	n = strlen(p);
	if (n < 2 || n >= PATH_MAX)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)p[i];

		if (c < 0x20 || c == 0x7f)
			return 0;
	}
	for (seg = p; (seg = strstr(seg, "/..")); seg += 3) {
		if (seg[3] == '\0' || seg[3] == '/')
			return 0;
	}
	return 1;
}

/* 显式 ro/rw bind 源：拒绝覆盖系统关键面（与 aik-sandbox 同规则） */
static int ws_valid_bind_src(const char *p)
{
	static const char *const deny[] = {
		"/proc", "/sys", "/dev", "/usr", "/bin", "/sbin",
		"/lib", "/lib64", "/etc", "/root", "/boot",
		"/var/lib/aikernel", "/var/ai/sandbox-artifacts", NULL,
	};
	size_t i;

	if (!ws_valid_host_path(p) || strcmp(p, "/") == 0)
		return 0;
	for (i = 0; deny[i]; i++) {
		size_t n = strlen(deny[i]);

		if (strncmp(p, deny[i], n) == 0 &&
		    (p[n] == '\0' || p[n] == '/'))
			return 0;
	}
	return 1;
}

/* ---- 环境路径 ---- */

static const char *ws_root(void)
{
	static char buf[PATH_MAX];
	const char *e = getenv("AIKERNEL_WORKSPACE_ROOT");
	size_t n;

	if (buf[0])
		return buf;
	if (!e || !e[0])
		e = WS_ROOT_DEFAULT;
	n = strlen(e);
	if (e[0] != '/' || strstr(e, "..") || n >= sizeof(buf) - 1) {
		fprintf(stderr, "workspace: 警告: 非法 AIKERNEL_WORKSPACE_ROOT"
			"（%s），改用 %s\n", e, WS_ROOT_DEFAULT);
		return WS_ROOT_DEFAULT;
	}
	memcpy(buf, e, n + 1);
	while (n > 1 && buf[n - 1] == '/')
		buf[--n] = '\0';
	return buf;
}

static const char *ws_sb_base(void)
{
	static char buf[PATH_MAX];
	const char *e = getenv("AIKERNEL_SANDBOX_BASE");
	size_t n;

	if (buf[0])
		return buf;
	if (!e || !e[0])
		e = WS_SB_BASE_DEFAULT;
	n = strlen(e);
	if (e[0] != '/' || strstr(e, "..") || n >= sizeof(buf) - 1) {
		fprintf(stderr, "workspace: 警告: 非法 AIKERNEL_SANDBOX_BASE"
			"（%s），改用 %s\n", e, WS_SB_BASE_DEFAULT);
		return WS_SB_BASE_DEFAULT;
	}
	memcpy(buf, e, n + 1);
	while (n > 1 && buf[n - 1] == '/')
		buf[--n] = '\0';
	return buf;
}

static const char *ws_sb_bin(void)
{
	const char *e = getenv("AIKERNEL_SANDBOX_BIN");

	return (e && e[0]) ? e : WS_SB_BIN_DEFAULT;
}

static const char *ws_cg_root(void)
{
	const char *e = getenv("AIKERNEL_SANDBOX_CGROUP_ROOT");

	return (e && e[0]) ? e : WS_CG_ROOT_DEFAULT;
}

/* ---- 元数据 ---- */

static void ws_meta_path(const char *name, char *buf, size_t n)
{
	snprintf(buf, n, "%s/%s.meta", ws_root(), name);
}

static void ws_image_path(const char *name, char *buf, size_t n)
{
	snprintf(buf, n, "%s/%s.img", ws_root(), name);
}

/* 产物区根（与 aik-sandbox 同源同覆盖变量）：B-109 清理用 */
static const char *ws_artifact_root(void)
{
	static char buf[PATH_MAX];
	const char *e = getenv("AIKERNEL_SANDBOX_ARTIFACTS");
	size_t n;

	if (buf[0])
		return buf;
	if (!e || !e[0])
		e = WS_ART_DEFAULT;
	n = strlen(e);
	if (e[0] != '/' || strstr(e, "..") || n >= sizeof(buf) - 1)
		return WS_ART_DEFAULT;
	memcpy(buf, e, n + 1);
	while (n > 1 && buf[n - 1] == '/')
		buf[--n] = '\0';
	return buf;
}

static void ws_artifact_dir(const char *name, char *buf, size_t n)
{
	snprintf(buf, n, "%s/%s", ws_artifact_root(), name);
}

static const char *ws_net_mode_str(int mode)
{
	if (mode == WS_NET_VETH)
		return "veth";
	if (mode == WS_NET_HOST)
		return "host";
	return "none";
}

/* 元数据里白名单行：proto;port;dst（dst 可能含 ':'，故用 ';' 分隔） */
static void ws_allow_fmt(const struct ws_allow *a, char *buf, size_t n)
{
	snprintf(buf, n, "%s;%d;%s", a->proto, a->port, a->dst);
}

static int ws_allow_parse(const char *s, struct ws_allow *a)
{
	const char *p1 = strchr(s, ';');
	const char *p2;
	size_t n;

	if (!p1)
		return -1;
	p2 = strchr(p1 + 1, ';');
	if (!p2)
		return -1;
	n = (size_t)(p1 - s);
	if (n == 0 || n >= sizeof(a->proto))
		return -1;
	memcpy(a->proto, s, n);
	a->proto[n] = '\0';
	a->port = (int)strtol(p1 + 1, NULL, 10);
	n = strlen(p2 + 1);
	if (n == 0 || n >= sizeof(a->dst))
		return -1;
	memcpy(a->dst, p2 + 1, n + 1);
	return 0;
}

static int ws_meta_write(const char *name, const struct ws_meta *m)
{
	char path[PATH_MAX], tmp[PATH_MAX];
	int fd, i, rc = -1;

	ws_meta_path(name, path, sizeof(path));
	snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	if (dprintf(fd,
		    "name=%s\nbacking=%s\nimage=%s\nloop=%s\nsize_mb=%ld\n"
		    "created=%ld\nlabel=%s\ncpus=%.2f\nmem_mb=%ld\n"
		    "pids_max=%ld\nnet=%s\n",
		    m->name, m->backing, m->image, m->loop, m->size_mb,
		    m->created, m->label, m->cpus_x100 / 100.0,
		    m->mem_mb, m->pids_max,
		    ws_net_mode_str(m->net_mode)) < 0)
		goto out;
	/* W82e：只有发生「区名 → 短工作区名」映射时才写 alias，
	 * 旧元数据（无 alias 行）读副作用为零 */
	if (m->alias[0] && dprintf(fd, "alias=%s\n", m->alias) < 0)
		goto out;
	if (m->net_mode == WS_NET_VETH) {
		if (dprintf(fd, "net_ns=%s\nnet_ip=%s\nnet_host_if=%s\n"
			    "net_ws_if=%s\n",
			    m->net_ns, m->net_ip, m->net_host_if,
			    m->net_ws_if) < 0)
			goto out;
		for (i = 0; i < m->allow_n; i++) {
			char al[128];

			ws_allow_fmt(&m->allow[i], al, sizeof(al));
			if (dprintf(fd, "allow=%s\n", al) < 0)
				goto out;
		}
	}
	for (i = 0; i < m->ro_n; i++)
		if (dprintf(fd, "ro=%s\n", m->ro[i]) < 0)
			goto out;
	for (i = 0; i < m->rw_n; i++)
		if (dprintf(fd, "rw=%s\n", m->rw[i]) < 0)
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

static int ws_meta_read(const char *name, struct ws_meta *m)
{
	char path[PATH_MAX], line[PATH_MAX + 128];
	FILE *fp;

	memset(m, 0, sizeof(*m));
	snprintf(m->name, sizeof(m->name), "%s", name);
	snprintf(m->backing, sizeof(m->backing), "disk");
	m->cpus_x100 = 100;
	m->mem_mb = 1024;
	m->pids_max = 256;
	m->net_mode = WS_NET_NONE;
	ws_meta_path(name, path, sizeof(path));
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
		if (strcmp(line, "name") == 0)
			snprintf(m->name, sizeof(m->name), "%s", v);
		else if (strcmp(line, "backing") == 0)
			snprintf(m->backing, sizeof(m->backing), "%s", v);
		else if (strcmp(line, "image") == 0)
			snprintf(m->image, sizeof(m->image), "%s", v);
		else if (strcmp(line, "loop") == 0)
			snprintf(m->loop, sizeof(m->loop), "%s", v);
		else if (strcmp(line, "size_mb") == 0)
			m->size_mb = strtol(v, NULL, 10);
		else if (strcmp(line, "created") == 0)
			m->created = strtol(v, NULL, 10);
		else if (strcmp(line, "label") == 0)
			snprintf(m->label, sizeof(m->label), "%s", v);
		else if (strcmp(line, "alias") == 0)
			snprintf(m->alias, sizeof(m->alias), "%s", v);
		else if (strcmp(line, "cpus") == 0)
			m->cpus_x100 = (int)(strtod(v, NULL) * 100.0 + 0.5);
		else if (strcmp(line, "mem_mb") == 0)
			m->mem_mb = strtol(v, NULL, 10);
		else if (strcmp(line, "pids_max") == 0)
			m->pids_max = strtol(v, NULL, 10);
		else if (strcmp(line, "net") == 0) {
			if (strcmp(v, "veth") == 0)
				m->net_mode = WS_NET_VETH;
			else if (strcmp(v, "host") == 0)
				m->net_mode = WS_NET_HOST;
			else
				m->net_mode = WS_NET_NONE;
		} else if (strcmp(line, "net_ns") == 0) {
			snprintf(m->net_ns, sizeof(m->net_ns), "%s", v);
		} else if (strcmp(line, "net_ip") == 0) {
			snprintf(m->net_ip, sizeof(m->net_ip), "%s", v);
		} else if (strcmp(line, "net_host_if") == 0) {
			snprintf(m->net_host_if, sizeof(m->net_host_if), "%s", v);
		} else if (strcmp(line, "net_ws_if") == 0) {
			snprintf(m->net_ws_if, sizeof(m->net_ws_if), "%s", v);
		} else if (strcmp(line, "allow") == 0) {
			struct ws_allow a;

			if (m->allow_n < WS_ALLOW_MAX &&
			    ws_allow_parse(v, &a) == 0)
				m->allow[m->allow_n++] = a;
		}
		else if (strcmp(line, "ro") == 0) {
			if (m->ro_n < WS_MAX_PATHS)
				snprintf(m->ro[m->ro_n++], PATH_MAX, "%s", v);
		} else if (strcmp(line, "rw") == 0) {
			if (m->rw_n < WS_MAX_PATHS)
				snprintf(m->rw[m->rw_n++], PATH_MAX, "%s", v);
		}
	}
	fclose(fp);
	if (!m->image[0] && strcmp(m->backing, "disk") == 0)
		ws_image_path(name, m->image, sizeof(m->image));
	return 0;
}

/* 沙盒 meta 中的 loop= 回读（create 后马上拿实际 loop 号） */
static void ws_sandbox_meta(const char *name, char *loop, size_t loopsz)
{
	char path[PATH_MAX], line[512];
	FILE *fp;

	if (loop && loopsz)
		loop[0] = '\0';
	snprintf(path, sizeof(path), "%s/%s/meta", ws_sb_base(), name);
	fp = fopen(path, "r");
	if (!fp)
		return;
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "loop=", 5) == 0 && loop && loopsz) {
			line[strcspn(line, "\r\n")] = '\0';
			snprintf(loop, loopsz, "%s", line + 5);
		}
	}
	fclose(fp);
}

/* ---- 小工具 ---- */

static int ws_is_dir(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static int ws_file_exists(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0;
}

/* mkdir -p（只用于工作区根，路径来自环境变量且已校验） */
static int ws_mkdir_p(const char *path)
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
		if (mkdir(buf, 0755) && errno != EEXIST)
			return -1;
		buf[i] = '/';
	}
	if (mkdir(buf, 0755) && errno != EEXIST)
		return -1;
	return ws_is_dir(path) ? 0 : -1;
}

/* 元数据里的镜像路径必须仍在本工作区根下（防手改 meta 指向任意文件） */
static int ws_image_under_root(const char *image)
{
	const char *root = ws_root();
	size_t n = strlen(root);

	return image && strncmp(image, root, n) == 0 &&
	       image[n] == '/' && image[n + 1] != '\0';
}

static long ws_used_mb(const struct ws_meta *m)
{
	struct stat st;
	long long used;

	if (strcmp(m->backing, "disk") != 0)
		return 0;
	if (!m->image[0] || stat(m->image, &st))
		return 0;
	used = (long long)st.st_blocks * 512;
	return (long)((used + 1024 * 1024 - 1) / (1024 * 1024));
}

/* 区锁被 aik-sandbox run 持有 = 有活跃执行 */
static int ws_running(const char *name)
{
	char path[PATH_MAX];
	int fd, busy;

	snprintf(path, sizeof(path), "%s/%s/.lock", ws_sb_base(), name);
	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return 0;
	busy = flock(fd, LOCK_EX | LOCK_NB) != 0;
	if (!busy)
		flock(fd, LOCK_UN);
	close(fd);
	return busy;
}

/* 扫 /sys/block 找镜像当前 loop；成功返回 0 并写 dev */
static int ws_loop_find(const char *image, char *dev, size_t devsz)
{
	DIR *d = opendir("/sys/block");
	struct dirent *e;
	int found = -1;

	if (!d)
		return -1;
	while ((e = readdir(d))) {
		char p[PATH_MAX], b[PATH_MAX];
		int fd;
		ssize_t n;

		if (strncmp(e->d_name, "loop", 4) != 0)
			continue;
		snprintf(p, sizeof(p), "/sys/block/%s/loop/backing_file",
			 e->d_name);
		fd = open(p, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;
		n = read(fd, b, sizeof(b) - 1);
		close(fd);
		if (n <= 0)
			continue;
		b[n] = '\0';
		while (n > 0 && (b[n - 1] == '\n' || b[n - 1] == '\r'))
			b[--n] = '\0';
		if (strcmp(b, image) == 0 ||
		    (b[0] != '/' && image[0] == '/' &&
		     strcmp(b, image + 1) == 0)) {
			snprintf(dev, devsz, "/dev/%s", e->d_name);
			found = 0;
			break;
		}
	}
	closedir(d);
	return found;
}

/* 解除镜像占用的 loop（幂等） */
static int ws_loop_detach_image(const char *image)
{
	char dev[64];

	while (ws_loop_find(image, dev, sizeof(dev)) == 0) {
		int fd = open(dev, O_RDONLY | O_CLOEXEC);

		if (fd < 0)
			return -1;
		if (ioctl(fd, LOOP_CLR_FD, 0) &&
		    errno != ENXIO && errno != EINVAL) {
			close(fd);
			return -1;
		}
		close(fd);
	}
	return 0;
}

/*
 * W82e（V1.8）：统一子进程采集。
 *
 * fork + exec argv，采集 stdout/stderr 合流（尾部 ≤out_max 字节）。
 * 子进程 setsid 自成进程组；超时 / 取消（*cancel_flag 置位）→ SIGKILL
 * 整组（连泄漏的孙进程一起收掉）。extra_env 在子进程内注入（"K=V"）。
 * 传入 NULL 的出参会被忽略；返回 0=已执行（exit_code 有效）。
 *
 * 这份实现原先是两份（executor.c 的 sb_spawn_capture 与本文的
 * ws_spawn_capture）。V1.8 把 sandbox 通道收口到 workspace 后只留这一份，
 * 两条通道（workspace_run / sandbox_spawn）共用。
 */
int ai_ws_spawn_capture(char **argv, char *const extra_env[], int extra_env_n,
			int timeout_sec, size_t out_max,
			volatile sig_atomic_t *cancel_flag, char **tail_out,
			int *exit_code, int *timed_out, int *cancelled,
			int *truncated)
{
	int pipefd[2];
	pid_t pid;
	int st = 0, i;
	char *ring;
	size_t ring_off = 0, ring_fill = 0;
	long long deadline_ms;
	int cancel_local = 0, timed_local = 0, trunc_local = 0;

	if (tail_out)
		*tail_out = NULL;
	if (exit_code)
		*exit_code = -1;
	if (timed_out)
		*timed_out = 0;
	if (cancelled)
		*cancelled = 0;
	if (truncated)
		*truncated = 0;
	if (!out_max)
		out_max = WS_OUT_MAX;
	ring = malloc(out_max);
	if (!ring)
		return -1;
	if (pipe(pipefd)) {
		free(ring);
		return -1;
	}
	fflush(stdout);
	fflush(stderr);
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		free(ring);
		return -1;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDONLY);

		close(pipefd[0]);
		setsid();
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			close(devnull);
		}
		for (i = 0; i < extra_env_n; i++) {
			char *eq = strchr(extra_env[i], '=');

			if (eq) {
				*eq = '\0';
				setenv(extra_env[i], eq + 1, 1);
				*eq = '=';
			}
		}
		execv(argv[0], argv);
		fprintf(stderr, "ERROR: exec %s: %s\n", argv[0],
			strerror(errno));
		_exit(127);
	}
	close(pipefd[1]);

	/* 读端非阻塞：子进程（如 exec 成 sleep 的长任务）长期持写端但
	 * 不出数据时，排空循环的 read() 不得阻塞到 deadline 之后 */
	fcntl(pipefd[0], F_SETFL,
	      fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);

	deadline_ms = (long long)time(NULL) * 1000 +
		      (long long)timeout_sec * 1000;
	while (1) {
		struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
		char chunk[4096];
		ssize_t n;
		long long now_ms;

		now_ms = (long long)time(NULL) * 1000;
		/* 取消：SIGKILL 整个进程组 */
		if (cancel_flag && *cancel_flag) {
			kill(-(pid_t)pid, SIGKILL);
			kill((pid_t)pid, SIGKILL);
			cancel_local = 1;
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0)
				;
			break;
		}
		if (now_ms >= deadline_ms) {
			/* 超时：SIGKILL 全组（子进程 setsid 后 pgid=pid，
			 * 组内孙进程一并收掉），防孤儿拖死会话 */
			kill(-(pid_t)pid, SIGKILL);
			kill((pid_t)pid, SIGKILL);
			timed_local = 1;
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			/* 击杀后写端全关，把管道残余排干（read 到 0 为止） */
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0) {
				for (i = 0; i < (int)n; i++) {
					if (ring_fill >= out_max)
						trunc_local = 1;
					ring[ring_off] = chunk[i];
					ring_off = (ring_off + 1) % out_max;
					if (ring_fill < out_max)
						ring_fill++;
				}
			}
			break;
		}
		if (poll(&pfd, 1, 200) > 0 &&
		    (pfd.revents & (POLLIN | POLLHUP))) {
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0) {
				for (i = 0; i < (int)n; i++) {
					if (ring_fill >= out_max)
						trunc_local = 1;
					ring[ring_off] = chunk[i];
					ring_off = (ring_off + 1) % out_max;
					if (ring_fill < out_max)
						ring_fill++;
				}
			}
		}
		if (pfd.revents & POLLHUP) {
			/* 写端全关（子进程及全部孙进程都已退出）：
			 * 排空完成，收尸退出 */
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			break;
		}
		/* 子进程本体退出但写端仍被孙进程持有：先记尸不收，
		 * 继续等到 deadline——输出未完即任务未完，语义一致 */
		waitpid(pid, &st, WNOHANG);
	}
	close(pipefd[0]);

	/* 尾部取出（环缓冲 → 连续缓冲） */
	if (tail_out) {
		size_t start = (ring_fill < out_max) ? 0 : ring_off;

		*tail_out = malloc(ring_fill + 1);
		if (!*tail_out) {
			free(ring);
			return -1;
		}
		for (i = 0; (size_t)i < ring_fill; i++)
			(*tail_out)[i] = ring[(start + (size_t)i) % out_max];
		(*tail_out)[ring_fill] = '\0';
	}
	free(ring);

	if (timed_out)
		*timed_out = timed_local;
	if (cancelled)
		*cancelled = cancel_local;
	if (truncated)
		*truncated = trunc_local;
	if (exit_code) {
		if (WIFEXITED(st))
			*exit_code = WEXITSTATUS(st);
		else if (WIFSIGNALED(st))
			*exit_code = 128 + WTERMSIG(st);
	}
	return 0;
}

/* workspace 内部调用面：固定 256KB 尾部、不取消、不注入环境 */
static int ws_spawn_capture(char **argv, int timeout_sec, char **out,
			    int *exit_code, int *timed_out, int *truncated)
{
	int cancelled = 0;

	return ai_ws_spawn_capture(argv, NULL, 0, timeout_sec, WS_OUT_MAX,
				   NULL, out, exit_code, timed_out,
				   &cancelled, truncated);
}

/* ======================================================================
 * W81d：工作区网络（netns + veth + 专用网桥 aikbr0 + 缺省拒出站 nft）
 *
 * 边界（红线）：
 *  - 宿主只做三件事：建/用专用网桥 aikbr0、配 aikbr0 地址与 aikv* 端口、
 *    在工作区 netns 内下发 nft。不改宿主 filter/nat、不改默认路由、
 *    不动任何其他接口，不做 SNAT/转发；
 *  - 所有 ip/nft 调用都是有界 fork/execv（超时即 SIGKILL 整组），
 *    参数全部来自校验过的 name/hash/白名单三元组，不经 shell。
 * ====================================================================== */

/* FNV-1a 32 位：接口名短标识（IFNAMSIZ=16，"aikv%08x" 共 13 字符） */
static unsigned int ws_fnv32(const char *s)
{
	unsigned int h = 2166136261u;

	while (s && *s) {
		h ^= (unsigned char)*s++;
		h *= 16777619u;
	}
	return h;
}

static void ws_net_ns_name(const char *name, char *buf, size_t n)
{
	snprintf(buf, n, "%s%s", WS_NET_NS_PREFIX, name);
}

static void ws_nft_table_name(const char *name, char *buf, size_t n)
{
	snprintf(buf, n, "%s%s", WS_NFT_TBL_PREFIX, name);
}

static void ws_if_names(const char *name, char *host, size_t hn,
			char *ws, size_t wn)
{
	unsigned int h = ws_fnv32(name);

	snprintf(host, hn, "aikv%08x", h);
	snprintf(ws, wn, "aikc%08x", h);
}

static const char *ws_bin_of(const char *const *cand)
{
	int i;

	for (i = 0; cand[i]; i++)
		if (access(cand[i], X_OK) == 0)
			return cand[i];
	return NULL;
}

static const char *ws_ip_bin(void)
{
	static const char *cached;
	static const char *const cand[] = {
		"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip", NULL,
	};

	if (!cached)
		cached = ws_bin_of(cand);
	return cached;
}

static const char *ws_nft_bin(void)
{
	static const char *cached;
	static const char *const cand[] = {
		"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft", NULL,
	};

	if (!cached)
		cached = ws_bin_of(cand);
	return cached;
}

/* 有界执行：0=已执行（rc 有效），-1=启动/管道失败 */
static int ws_run(char *const argv[], char **out, int *rc)
{
	int timed_out = 0, truncated = 0;

	if (out)
		*out = NULL;
	*rc = -1;
	return ws_spawn_capture((char **)argv, WS_NET_TO, out, rc,
				&timed_out, &truncated);
}

static int ws_link_exists(const char *dev)
{
	const char *ip = ws_ip_bin();
	char *argv[6], *out = NULL;
	int rc = -1, r;

	if (!ip || !dev || !dev[0])
		return 0;
	argv[0] = (char *)ip;
	argv[1] = (char *)"link";
	argv[2] = (char *)"show";
	argv[3] = (char *)"dev";
	argv[4] = (char *)dev;
	argv[5] = NULL;
	r = ws_run(argv, &out, &rc);
	free(out);
	return r == 0 && rc == 0;
}

static int ws_link_in_netns(const char *ns, const char *dev)
{
	const char *ip = ws_ip_bin();
	char *argv[8], *out = NULL;
	int rc = -1, r;

	if (!ip)
		return 0;
	argv[0] = (char *)ip;
	argv[1] = (char *)"-n";
	argv[2] = (char *)ns;
	argv[3] = (char *)"link";
	argv[4] = (char *)"show";
	argv[5] = (char *)"dev";
	argv[6] = (char *)dev;
	argv[7] = NULL;
	r = ws_run(argv, &out, &rc);
	free(out);
	return r == 0 && rc == 0;
}

static int ws_netns_exists(const char *ns)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", WS_NETNS_DIR, ns);
	return access(path, F_OK) == 0;
}

/* 网桥成员列表（null 结尾的换行文本；调用者 free） */
static char *ws_bridge_members(void)
{
	const char *ip = ws_ip_bin();
	char *argv[7], *out = NULL;
	int rc = -1;

	if (!ip)
		return NULL;
	argv[0] = (char *)ip;
	argv[1] = (char *)"-o";
	argv[2] = (char *)"link";
	argv[3] = (char *)"show";
	argv[4] = (char *)"master";
	argv[5] = (char *)WS_BR_NAME;
	argv[6] = NULL;
	if (ws_run(argv, &out, &rc) || rc != 0) {
		free(out);
		return NULL;
	}
	return out;
}

static int ws_dev_has_addr(const char *dev, const char *addr)
{
	const char *ip = ws_ip_bin();
	char *argv[7], *out = NULL, needle[96];
	int rc = -1, found = 0;

	if (!ip)
		return 0;
	argv[0] = (char *)ip;
	argv[1] = (char *)"-o";
	argv[2] = (char *)"addr";
	argv[3] = (char *)"show";
	argv[4] = (char *)"dev";
	argv[5] = (char *)dev;
	argv[6] = NULL;
	snprintf(needle, sizeof(needle), "inet %s/", addr);
	if (!ws_run(argv, &out, &rc) && rc == 0 && out)
		found = strstr(out, needle) != NULL;
	free(out);
	return found;
}

/* 网络配置串行锁（<ws_root>/.net.lock，flock；最多等 5 秒） */
static int ws_net_lock(void)
{
	char path[PATH_MAX];
	int fd, i;

	snprintf(path, sizeof(path), "%s/.net.lock", ws_root());
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	for (i = 0; i < WS_NET_LOCK_TRIES; i++) {
		if (flock(fd, LOCK_EX | LOCK_NB) == 0)
			return fd;
		if (errno != EWOULDBLOCK && errno != EINTR)
			break;
		usleep(100 * 1000);
	}
	close(fd);
	return -1;
}

/*
 * 专用网桥关掉 IPv6：否则一旦有端口接入（carrier up）内核就会给 aikbr0
 * 生成 fe80 链路本地地址，并在 IPv6 路由表里留下 fe80::/64 dev aikbr0 ——
 * 工作区销毁后这条路由不会自己消失，破坏"宿主路由表逐字节一致"。
 * 只作用于我们自己的 aikbr0（内核未编 IPv6 时静默跳过）。
 */
static int ws_disable_ipv6(const char *dev)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path),
		 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", dev);
	if (access(path, F_OK) != 0)
		return 0;                       /* 无 IPv6：无需处理 */
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (write(fd, "1", 1) != 1) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/* 专用网桥：不存在才建，已有则只补地址（绝不 flush 宿主任何东西） */
static int ws_bridge_ensure(char *err, size_t errsz)
{
	const char *ip = ws_ip_bin();
	char *argv[8], *out = NULL;
	int rc = -1;

	if (!ip) {
		snprintf(err, errsz, "找不到 ip 命令（iproute2 未安装？）");
		return -1;
	}
	if (!ws_link_exists(WS_BR_NAME)) {
		argv[0] = (char *)ip;
		argv[1] = (char *)"link";
		argv[2] = (char *)"add";
		argv[3] = (char *)WS_BR_NAME;
		argv[4] = (char *)"type";
		argv[5] = (char *)"bridge";
		argv[6] = NULL;
		if (ws_run(argv, &out, &rc) || rc != 0) {
			snprintf(err, errsz, "创建网桥 %s 失败（rc=%d）: %s",
				 WS_BR_NAME, rc, out ? out : "-");
			free(out);
			return -1;
		}
		free(out);
		out = NULL;
	}
	if (ws_disable_ipv6(WS_BR_NAME)) {
		snprintf(err, errsz, "关闭 %s 的 IPv6 失败（防止宿主 IPv6 "
			 "路由表出现 fe80 残留）", WS_BR_NAME);
		return -1;
	}
	argv[0] = (char *)ip;
	argv[1] = (char *)"link";
	argv[2] = (char *)"set";
	argv[3] = (char *)WS_BR_NAME;
	argv[4] = (char *)"up";
	argv[5] = NULL;
	if (ws_run(argv, &out, &rc) || rc != 0) {
		snprintf(err, errsz, "拉起网桥 %s 失败（rc=%d）: %s",
			 WS_BR_NAME, rc, out ? out : "-");
		free(out);
		return -1;
	}
	free(out);
	out = NULL;
	if (!ws_dev_has_addr(WS_BR_NAME, WS_BR_ADDR)) {
		argv[0] = (char *)ip;
		argv[1] = (char *)"addr";
		argv[2] = (char *)"add";
		argv[3] = (char *)WS_BR_CIDR;
		argv[4] = (char *)"dev";
		argv[5] = (char *)WS_BR_NAME;
		argv[6] = NULL;
		if (ws_run(argv, &out, &rc) || rc != 0) {
			/* 已有同地址（并发/历史）不算失败 */
			if (!out || !strstr(out, "File exists")) {
				snprintf(err, errsz, "给 %s 配地址 %s 失败"
					 "（rc=%d）: %s", WS_BR_NAME,
					 WS_BR_CIDR, rc, out ? out : "-");
				free(out);
				return -1;
			}
		}
		free(out);
	}
	return 0;
}

/* 是否还有别的工作区用 veth（决定要不要撤掉网桥地址） */
static int ws_net_other_veth(const char *self)
{
	DIR *d = opendir(ws_root());
	struct dirent *e;
	int found = 0;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		struct ws_meta m;
		char nm[WS_MAX_NAME + 1];
		size_t nl = strlen(e->d_name);

		if (e->d_name[0] == '.' || nl <= 5 ||
		    strcmp(e->d_name + nl - 5, ".meta") != 0)
			continue;
		nl -= 5;
		if (nl == 0 || nl > WS_MAX_NAME)
			continue;
		memcpy(nm, e->d_name, nl);
		nm[nl] = '\0';
		if (strcmp(nm, self) == 0 || !ai_ws_valid_name(nm))
			continue;
		if (ws_meta_read(nm, &m) == 0 && m.net_mode == WS_NET_VETH) {
			found = 1;
			break;
		}
	}
	closedir(d);
	return found;
}

/* 该地址是否已被别的工作区占用（扫工作区根下全部 .meta） */
static int ws_net_ip_in_use(const char *self, const char *cand)
{
	DIR *d = opendir(ws_root());
	struct dirent *e;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		struct ws_meta m;
		char nm[WS_MAX_NAME + 1];
		size_t nl = strlen(e->d_name);

		if (e->d_name[0] == '.' || nl <= 5 ||
		    strcmp(e->d_name + nl - 5, ".meta") != 0)
			continue;
		nl -= 5;
		if (nl == 0 || nl > WS_MAX_NAME)
			continue;
		memcpy(nm, e->d_name, nl);
		nm[nl] = '\0';
		if (strcmp(nm, self) == 0 || !ai_ws_valid_name(nm))
			continue;
		if (ws_meta_read(nm, &m) != 0)
			continue;
		if (m.net_mode == WS_NET_VETH && strcmp(m.net_ip, cand) == 0) {
			closedir(d);
			return 1;
		}
	}
	closedir(d);
	return 0;
}

/* 分配 10.231.<a>.<b>（a≥1，b∈[1,250]）：序号文件自增 + 占用探测 */
static int ws_net_alloc_ip(const char *name, char *out, size_t n)
{
	char seqpath[PATH_MAX], buf[32], cand[64];
	int fd, i, seq = 0;
	ssize_t r;

	snprintf(seqpath, sizeof(seqpath), "%s/.net.seq", ws_root());
	fd = open(seqpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd >= 0) {
		r = read(fd, buf, sizeof(buf) - 1);
		if (r > 0) {
			buf[r] = '\0';
			seq = atoi(buf);
		}
		close(fd);
	}
	if (seq < 0 || seq > 60000)
		seq = 0;
	for (i = 1; i <= 60000; i++) {
		int idx = seq + i, a, b;

		if (idx > 63000)
			idx = (idx % 63000) + 1;
		a = 1 + (idx - 1) / 250;
		b = 1 + (idx - 1) % 250;
		snprintf(cand, sizeof(cand), "10.231.%d.%d", a, b);
		if (ws_net_ip_in_use(name, cand))
			continue;
		fd = open(seqpath, O_WRONLY | O_TRUNC | O_CLOEXEC);
		if (fd >= 0) {
			if (dprintf(fd, "%d\n", idx) < 0)
				(void)0;
			close(fd);
		}
		snprintf(out, n, "%s", cand);
		return 0;
	}
	return -1;
}

/* 白名单 → nft 规则行（只有校验过的枚举/整数/地址会进文本） */
static int ws_nft_emit_rules(FILE *f, const struct ws_meta *m)
{
	int i;

	for (i = 0; i < m->allow_n; i++) {
		const struct ws_allow *a = &m->allow[i];
		const char *fam = strchr(a->dst, ':') ? "ip6" : "ip";
		int portok = a->port > 0 &&
			     (strcmp(a->proto, "tcp") == 0 ||
			      strcmp(a->proto, "udp") == 0);

		if (portok) {
			if (fprintf(f, "\t\t%s daddr %s %s dport %d accept\n",
				    fam, a->dst, a->proto, a->port) < 0)
				return -1;
		} else if (strcmp(a->proto, "any") == 0) {
			if (fprintf(f, "\t\t%s daddr %s accept\n",
				    fam, a->dst) < 0)
				return -1;
		} else {
			if (fprintf(f, "\t\t%s daddr %s meta l4proto %s "
				    "accept\n", fam, a->dst, a->proto) < 0)
				return -1;
		}
	}
	return 0;
}

/*
 * 规则文件：output/input 两条基链 policy drop；固定放行 lo 与
 * ct established,related；白名单逐条 accept；末尾 counter drop 供
 * net_status 观察命中。del_first=1 时先删旧表（与建表同批次原子替换，
 * 避免 flush→add 之间的 fail-open 窗口）。
 */
static int ws_nft_write_rules(FILE *f, const char *tbl,
			      const struct ws_meta *m, int del_first)
{
	if (del_first && fprintf(f, "delete table inet %s\n", tbl) < 0)
		return -1;
	if (fprintf(f,
		    "table inet %s {\n"
		    "\tchain output {\n"
		    "\t\ttype filter hook output priority filter; policy drop;\n"
		    "\t\tct state established,related accept\n"
		    "\t\toifname \"lo\" accept\n", tbl) < 0)
		return -1;
	if (ws_nft_emit_rules(f, m))
		return -1;
	if (fprintf(f, "\t\tcounter drop\n\t}\n"
		       "\tchain input {\n"
		       "\t\ttype filter hook input priority filter; policy drop;\n"
		       "\t\tct state established,related accept\n"
		       "\t\tiifname \"lo\" accept\n"
		       "\t\tcounter drop\n\t}\n}\n") < 0)
		return -1;
	return 0;
}

static int ws_nft_table_exists(const char *ns, const char *tbl)
{
	const char *ip = ws_ip_bin(), *nft = ws_nft_bin();
	char *argv[10], *out = NULL;
	int rc = -1, r;

	if (!ip || !nft)
		return 0;
	argv[0] = (char *)ip;
	argv[1] = (char *)"netns";
	argv[2] = (char *)"exec";
	argv[3] = (char *)ns;
	argv[4] = (char *)nft;
	argv[5] = (char *)"list";
	argv[6] = (char *)"table";
	argv[7] = (char *)"inet";
	argv[8] = (char *)tbl;
	argv[9] = NULL;
	r = ws_run(argv, &out, &rc);
	free(out);
	return r == 0 && rc == 0;
}

static int ws_nft_exec(const char *ns, const char *flag, const char *path,
		       char **out, int *rc)
{
	const char *ip = ws_ip_bin();
	char *argv[10];
	int n = 0;

	argv[n++] = (char *)ip;
	argv[n++] = (char *)"netns";
	argv[n++] = (char *)"exec";
	argv[n++] = (char *)ns;
	argv[n++] = (char *)ws_nft_bin();
	if (flag && flag[0])
		argv[n++] = (char *)flag;
	argv[n++] = (char *)"-f";
	argv[n++] = (char *)path;
	argv[n] = NULL;
	return ws_run(argv, out, rc);
}

/* 在 netns 内下发规则：预检 → 单批次原子应用 */
static int ws_nft_apply(const char *name, const struct ws_meta *m, int rebuild,
			char *err, size_t errsz)
{
	char tmpl[] = "/tmp/aikws-nft-XXXXXX";
	char tbl[WS_MAX_NAME + 16], ns[WS_NET_NS_MAX + 1];
	char *out = NULL;
	int fd, exists, rc = -1, r;
	FILE *f;

	if (!ws_ip_bin() || !ws_nft_bin()) {
		snprintf(err, errsz, "找不到 ip/nft 命令（iproute2/nftables 未安装？）");
		return -1;
	}
	ws_nft_table_name(name, tbl, sizeof(tbl));
	ws_net_ns_name(name, ns, sizeof(ns));
	exists = ws_nft_table_exists(ns, tbl);
	if (exists && !rebuild)
		return 0;
	fd = mkstemp(tmpl);
	if (fd < 0) {
		snprintf(err, errsz, "创建规则临时文件失败: %s", strerror(errno));
		return -1;
	}
	fchmod(fd, 0600);
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(tmpl);
		snprintf(err, errsz, "fdopen 失败: %s", strerror(errno));
		return -1;
	}
	if (ws_nft_write_rules(f, tbl, m, exists) || fflush(f)) {
		fclose(f);
		unlink(tmpl);
		snprintf(err, errsz, "写规则文件失败: %s", strerror(errno));
		return -1;
	}
	if (fclose(f)) {
		unlink(tmpl);
		snprintf(err, errsz, "关闭规则文件失败: %s", strerror(errno));
		return -1;
	}
	r = ws_nft_exec(ns, "-c", tmpl, &out, &rc);
	if (r || rc != 0) {
		snprintf(err, errsz, "nft -c 预检失败（rc=%d，未生效）: %s",
			 rc, out ? out : "-");
		free(out);
		unlink(tmpl);
		return -1;
	}
	free(out);
	out = NULL;
	r = ws_nft_exec(ns, "", tmpl, &out, &rc);
	unlink(tmpl);
	if (r || rc != 0) {
		snprintf(err, errsz, "nft -f 下发失败（rc=%d）: %s",
			 rc, out ? out : "-");
		free(out);
		return -1;
	}
	free(out);
	return 0;
}

/*
 * 建齐并收敛工作区网络：网桥 → netns → veth/地址 → nft。
 * 幂等：已存在的组件不重建；rebuild=1 强制重写规则（保留其他组件）。
 */
static int ws_net_setup(const char *name, struct ws_meta *m, int rebuild,
			char *err, size_t errsz)
{
	char ns[WS_NET_NS_MAX + 1], hostif[32], wsif[32], cidr[96];
	const char *ip = ws_ip_bin();
	char *argv[10], *out = NULL;
	int rc = -1, lock, r;

	if (!ip) {
		snprintf(err, errsz, "找不到 ip 命令（iproute2 未安装？）");
		return -1;
	}
	ws_net_ns_name(name, ns, sizeof(ns));
	ws_if_names(name, hostif, sizeof(hostif), wsif, sizeof(wsif));
	if (!m->net_ip[0] && ws_net_alloc_ip(name, m->net_ip,
					     sizeof(m->net_ip))) {
		snprintf(err, errsz, "无法分配工作区地址（10.231/16 已用尽？）");
		return -1;
	}
	snprintf(m->net_ns, sizeof(m->net_ns), "%s", ns);
	snprintf(m->net_host_if, sizeof(m->net_host_if), "%s", hostif);
	snprintf(m->net_ws_if, sizeof(m->net_ws_if), "%s", wsif);

	lock = ws_net_lock();
	if (lock < 0) {
		snprintf(err, errsz, "工作区网络配置锁忙（%s/.net.lock）",
			 ws_root());
		return -1;
	}
	if (ws_bridge_ensure(err, errsz)) {
		close(lock);
		return -1;
	}
	if (!ws_netns_exists(ns)) {
		argv[0] = (char *)ip;
		argv[1] = (char *)"netns";
		argv[2] = (char *)"add";
		argv[3] = ns;
		argv[4] = NULL;
		if (ws_run(argv, &out, &rc) || rc != 0) {
			snprintf(err, errsz, "创建 netns %s 失败（rc=%d）: %s",
				 ns, rc, out ? out : "-");
			free(out);
			close(lock);
			return -1;
		}
		free(out);
		out = NULL;
	}
	/* 半残状态（宿主侧在、工作区侧不在）→ 删掉重建，避免两截错配 */
	if (ws_link_exists(hostif) && !ws_link_in_netns(ns, wsif)) {
		argv[0] = (char *)ip;
		argv[1] = (char *)"link";
		argv[2] = (char *)"del";
		argv[3] = hostif;
		argv[4] = NULL;
		r = ws_run(argv, &out, &rc);
		free(out);
		out = NULL;
		(void)r;
	}
	if (!ws_link_exists(hostif)) {
		argv[0] = (char *)ip;
		argv[1] = (char *)"link";
		argv[2] = (char *)"add";
		argv[3] = hostif;
		argv[4] = (char *)"type";
		argv[5] = (char *)"veth";
		argv[6] = (char *)"peer";
		argv[7] = (char *)"name";
		argv[8] = wsif;
		argv[9] = NULL;
		if (ws_run(argv, &out, &rc) || rc != 0) {
			snprintf(err, errsz, "创建 veth 对（%s/%s）失败"
				 "（rc=%d）: %s", hostif, wsif, rc,
				 out ? out : "-");
			free(out);
			close(lock);
			return -1;
		}
		free(out);
		out = NULL;
		/* 宿主侧入网桥 + up；工作区侧移入 netns + 配地址 */
		{
			char *set_master[] = { (char *)ip, (char *)"link",
					       (char *)"set", hostif,
					       (char *)"master",
					       (char *)WS_BR_NAME, NULL };
			if (ws_run(set_master, &out, &rc) || rc != 0) {
				snprintf(err, errsz, "把 %s 挂到 %s 失败"
					 "（rc=%d）: %s", hostif, WS_BR_NAME,
					 rc, out ? out : "-");
				free(out);
				close(lock);
				return -1;
			}
			free(out);
			out = NULL;
		}
		{
			char *mv[] = { (char *)ip, (char *)"link", (char *)"set",
				       wsif, (char *)"netns", ns, NULL };
			if (ws_run(mv, &out, &rc) || rc != 0) {
				snprintf(err, errsz, "把 %s 移入 netns %s 失败"
					 "（rc=%d）: %s", wsif, ns, rc,
					 out ? out : "-");
				free(out);
				close(lock);
				return -1;
			}
			free(out);
			out = NULL;
		}
		{
			char *up1[] = { (char *)ip, (char *)"link",
					(char *)"set", hostif, (char *)"up",
					NULL };
			char *up2[] = { (char *)ip, (char *)"-n", ns,
					(char *)"link", (char *)"set", wsif,
					(char *)"up", NULL };
			char *up3[] = { (char *)ip, (char *)"-n", ns,
					(char *)"link", (char *)"set",
					(char *)"lo", (char *)"up", NULL };
			if (ws_run(up1, &out, &rc) || rc != 0) {
				snprintf(err, errsz, "拉起 %s 失败: %s", hostif,
					 out ? out : "-");
				free(out);
				close(lock);
				return -1;
			}
			free(out);
			out = NULL;
			if (ws_run(up2, &out, &rc) || rc != 0) {
				snprintf(err, errsz, "拉起 %s 失败: %s", wsif,
					 out ? out : "-");
				free(out);
				close(lock);
				return -1;
			}
			free(out);
			out = NULL;
			if (ws_run(up3, &out, &rc) || rc != 0) {
				snprintf(err, errsz, "拉起 netns %s 的 lo 失败: %s",
					 ns, out ? out : "-");
				free(out);
				close(lock);
				return -1;
			}
			free(out);
			out = NULL;
		}
		snprintf(cidr, sizeof(cidr), "%s/16", m->net_ip);
		{
			char *add[] = { (char *)ip, (char *)"-n", ns,
					(char *)"addr", (char *)"add", cidr,
					(char *)"dev", wsif, NULL };
			if (ws_run(add, &out, &rc) || rc != 0) {
				if (!out || !strstr(out, "File exists")) {
					snprintf(err, errsz, "给 %s 配地址 %s "
						 "失败（rc=%d）: %s", wsif, cidr,
						 rc, out ? out : "-");
					free(out);
					close(lock);
					return -1;
				}
			}
			free(out);
			out = NULL;
		}
	}
	if (ws_nft_apply(name, m, rebuild, err, errsz)) {
		close(lock);
		return -1;
	}
	close(lock);
	return 0;
}

/*
 * 拆网络（destroy 用）：删 netns（表/地址/工作区侧 veth 随之消失）→
 * 删宿主侧 veth（退出网桥成员）。全部幂等容忍；失败写 note 不静默。
 */
static void ws_net_teardown(const char *name, char *note, size_t notesz)
{
	char ns[WS_NET_NS_MAX + 1], hostif[32], wsif[32], tbl[WS_MAX_NAME + 16];
	const char *ip = ws_ip_bin();
	char *argv[10], *out = NULL;
	int rc = -1, lock;

	if (note && notesz)
		note[0] = '\0';
	if (!ip)
		return;
	ws_net_ns_name(name, ns, sizeof(ns));
	ws_if_names(name, hostif, sizeof(hostif), wsif, sizeof(wsif));
	ws_nft_table_name(name, tbl, sizeof(tbl));
	/* 没有任何网络残留（最常见：net=none/host 的工作区）：直接返回，
	 * 不创建锁文件、不碰网桥 —— destroy 的零副作用面不扩大 */
	if (!ws_netns_exists(ns) && !ws_link_exists(hostif) &&
	    !ws_dev_has_addr(WS_BR_NAME, WS_BR_ADDR))
		return;
	lock = ws_net_lock();
	if (ws_netns_exists(ns) && ws_nft_table_exists(ns, tbl)) {
		char *del[] = { (char *)ip, (char *)"netns", (char *)"exec",
				ns, (char *)ws_nft_bin(), (char *)"delete",
				(char *)"table", (char *)"inet", tbl, NULL };

		if (ws_nft_bin() && (ws_run(del, &out, &rc) || rc != 0)) {
			if (note && notesz)
				snprintf(note + strlen(note),
					 notesz - strlen(note),
					 "netns 内删表失败(rc=%d)；", rc);
		}
		free(out);
		out = NULL;
	}
	if (ws_netns_exists(ns)) {
		argv[0] = (char *)ip;
		argv[1] = (char *)"netns";
		argv[2] = (char *)"del";
		argv[3] = ns;
		argv[4] = NULL;
		if (ws_run(argv, &out, &rc) || rc != 0) {
			if (note && notesz)
				snprintf(note + strlen(note),
					 notesz - strlen(note),
					 "删 netns %s 失败(rc=%d)；", ns, rc);
		}
		free(out);
		out = NULL;
	}
	/* 对端随 netns 消亡时宿主侧会一起没；仍在则显式删（幂等） */
	if (ws_link_exists(hostif)) {
		char *del[] = { (char *)ip, (char *)"link", (char *)"del",
				hostif, NULL };

		if (ws_run(del, &out, &rc) || rc != 0) {
			if (note && notesz)
				snprintf(note + strlen(note),
					 notesz - strlen(note),
					 "删 veth %s 失败(rc=%d)；", hostif, rc);
		}
		free(out);
		out = NULL;
	}
	/* 最后一个 veth 工作区销毁后撤掉网桥地址：宿主路由表回到
	 * "建网桥之前" 的样子（空网桥本身不产生任何路由） */
	if (!ws_net_other_veth(name) &&
	    ws_link_exists(WS_BR_NAME) &&
	    ws_dev_has_addr(WS_BR_NAME, WS_BR_ADDR)) {
		char *del[] = { (char *)ip, (char *)"addr", (char *)"del",
				(char *)WS_BR_CIDR, (char *)"dev",
				(char *)WS_BR_NAME, NULL };

		if (ws_run(del, &out, &rc) || rc != 0) {
			if (note && notesz)
				snprintf(note + strlen(note),
					 notesz - strlen(note),
					 "撤网桥地址失败(rc=%d)；", rc);
		}
		free(out);
		out = NULL;
	}
	if (lock >= 0)
		close(lock);
}

/* ---- 白名单校验与解析（W81d） ---- */

/* dst：IPv4/IPv6 地址或 CIDR；字符集与 inet_pton 双重把关（防注入） */
static int ws_valid_dst(const char *dst)
{
	char addr[64];
	const char *slash, *p;
	size_t n;
	int prefix = -1;
	struct in_addr v4;
	struct in6_addr v6;

	if (!dst || !dst[0] || strlen(dst) >= sizeof(addr))
		return 0;
	for (p = dst; *p; p++)
		if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
		      (*p >= 'A' && *p <= 'F') || *p == ':' || *p == '.' ||
		      *p == '/'))
			return 0;
	slash = strchr(dst, '/');
	n = slash ? (size_t)(slash - dst) : strlen(dst);
	if (n == 0 || n >= sizeof(addr))
		return 0;
	memcpy(addr, dst, n);
	addr[n] = '\0';
	if (slash) {
		if (!slash[1])
			return 0;
		for (p = slash + 1; *p; p++)
			if (*p < '0' || *p > '9')
				return 0;
		prefix = atoi(slash + 1);
	}
	if (inet_pton(AF_INET, addr, &v4) == 1)
		return prefix < 0 || prefix <= 32;
	if (inet_pton(AF_INET6, addr, &v6) == 1)
		return prefix < 0 || prefix <= 128;
	return 0;
}

static int ws_valid_proto(const char *proto)
{
	return proto && (strcmp(proto, "tcp") == 0 ||
			 strcmp(proto, "udp") == 0 ||
			 strcmp(proto, "icmp") == 0 ||
			 strcmp(proto, "any") == 0);
}

/* 统一校验 + 归一化一条白名单（err 填原因）；返回 0 成功 */
static int ws_allow_check(const char *dst, long long port, const char *proto,
			  struct ws_allow *out, char *err, size_t errsz)
{
	const char *p = proto && proto[0] ? proto : NULL;

	if (!ws_valid_dst(dst)) {
		snprintf(err, errsz, "dst='%s' 非法（需 IPv4/IPv6 地址或 CIDR，"
			 "如 10.231.0.1 或 192.168.1.0/24）", dst ? dst : "(无)");
		return -1;
	}
	if (port < 0 || port > 65535) {
		snprintf(err, errsz, "port=%lld 非法（0-65535，0=任意）", port);
		return -1;
	}
	if (!p) {
		/* 省略 proto：有 port 视为 tcp，无 port 视为 any（已在工具
		 * 描述里写明，不猜第三种语义） */
		p = port > 0 ? "tcp" : "any";
	}
	if (!ws_valid_proto(p)) {
		snprintf(err, errsz, "proto='%s' 非法（tcp|udp|icmp|any）", p);
		return -1;
	}
	if (port > 0 && (strcmp(p, "icmp") == 0 || strcmp(p, "any") == 0)) {
		snprintf(err, errsz, "proto=%s 不接受 port", p);
		return -1;
	}
	memset(out, 0, sizeof(*out));
	snprintf(out->dst, sizeof(out->dst), "%s", dst);
	snprintf(out->proto, sizeof(out->proto), "%s", p);
	out->port = (int)port;
	return 0;
}

/* create 的 allow=[{dst,port,proto}] 解析；返回条数或 -1（err 填原因） */
static int ws_arg_allow_array(const char *json, const char *key,
			      struct ws_allow *arr, int max,
			      char *err, size_t errsz)
{
	const char *v;
	size_t vl;
	int vt, i, n = 0;

	if (!json || !json[0])
		return 0;
	i = ai_json_obj_get(json, strlen(json), key, &v, &vl, &vt);
	if (i == 0)
		return 0;
	if (i < 0 || vt != AI_JSON_ARR) {
		snprintf(err, errsz, "%s 必须是对象数组", key);
		return -1;
	}
	for (i = 0;; i++) {
		const char *e, *fv;
		size_t el, fvl;
		int et, ft, r;
		char *dst = NULL, *proto = NULL;
		long long port = 0;
		struct ws_allow a;

		r = ai_json_arr_get(v, vl, i, &e, &el, &et);
		if (r == 0)
			break;
		if (r < 0 || et != AI_JSON_OBJ) {
			snprintf(err, errsz, "%s[%d] 非法（需对象）", key, i);
			return -1;
		}
		if (ai_json_obj_get(e, el, "dst", &fv, &fvl, &ft) != 1 ||
		    ft != AI_JSON_STR) {
			snprintf(err, errsz, "%s[%d].dst 缺失或非字符串", key,
				 i);
			return -1;
		}
		dst = ai_json_strdup_str(fv, fvl);
		if (ai_json_obj_get(e, el, "port", &fv, &fvl, &ft) == 1) {
			if (ft != AI_JSON_NUM) {
				free(dst);
				snprintf(err, errsz, "%s[%d].port 非数字", key,
					 i);
				return -1;
			}
			port = ai_json_ll(fv, fvl);
		}
		if (ai_json_obj_get(e, el, "proto", &fv, &fvl, &ft) == 1) {
			if (ft != AI_JSON_STR) {
				free(dst);
				snprintf(err, errsz, "%s[%d].proto 非字符串",
					 key, i);
				return -1;
			}
			proto = ai_json_strdup_str(fv, fvl);
		}
		if (!dst || ws_allow_check(dst, port, proto, &a, err, errsz)) {
			free(dst);
			free(proto);
			if (dst == NULL)
				snprintf(err, errsz, "%s[%d].dst 解码失败", key,
					 i);
			return -1;
		}
		free(dst);
		free(proto);
		if (n >= max) {
			snprintf(err, errsz, "%s 最多 %d 条", key, max);
			return -1;
		}
		arr[n++] = a;
	}
	return n;
}

/* ---- JSON 取参 ---- */

static char *ws_arg_str(const char *json, const char *key)
{
	const char *v;
	size_t vl;
	int vt;

	if (!json || !json[0])
		return NULL;
	if (ai_json_obj_get(json, strlen(json), key, &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		return ai_json_strdup_str(v, vl);
	return NULL;
}

static long long ws_arg_ll(const char *json, const char *key, long long def)
{
	const char *v;
	size_t vl;
	int vt;

	if (!json || !json[0])
		return def;
	if (ai_json_obj_get(json, strlen(json), key, &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_NUM)
		return ai_json_ll(v, vl);
	return def;
}

static double ws_arg_dbl(const char *json, const char *key, double def)
{
	const char *v;
	size_t vl;
	int vt;
	char tmp[64];

	if (!json || !json[0])
		return def;
	if (ai_json_obj_get(json, strlen(json), key, &v, &vl, &vt) != 1 ||
	    vt != AI_JSON_NUM || vl >= sizeof(tmp))
		return def;
	memcpy(tmp, v, vl);
	tmp[vl] = '\0';
	return strtod(tmp, NULL);
}

/* 数组字符串参数（ro_paths/rw_paths）；返回条数或 -1（err 填原因） */
static int ws_arg_paths(const char *json, const char *key,
			char paths[][PATH_MAX], int max,
			char *err, size_t errsz)
{
	const char *v;
	size_t vl;
	int vt, i, n = 0;

	if (!json || !json[0])
		return 0;
	i = ai_json_obj_get(json, strlen(json), key, &v, &vl, &vt);
	if (i == 0)
		return 0;
	if (i < 0 || vt != AI_JSON_ARR) {
		snprintf(err, errsz, "%s 必须是字符串数组", key);
		return -1;
	}
	for (i = 0;; i++) {
		const char *e;
		size_t el;
		int et, r;
		char *s;

		r = ai_json_arr_get(v, vl, i, &e, &el, &et);
		if (r == 0)
			break;
		if (r < 0 || et != AI_JSON_STR) {
			snprintf(err, errsz, "%s[%d] 非法（需字符串）", key, i);
			return -1;
		}
		s = ai_json_strdup_str(e, el);
		if (!s) {
			snprintf(err, errsz, "%s[%d] 解码失败", key, i);
			return -1;
		}
		if (!ws_valid_bind_src(s)) {
			snprintf(err, errsz, "%s[%d]='%s' 非法（必须绝对路径，"
				 "且不得是 /proc /sys /dev /usr /etc /root "
				 "等系统面）", key, i, s);
			free(s);
			return -1;
		}
		if (n >= max) {
			snprintf(err, errsz, "%s 最多 %d 条", key, max);
			free(s);
			return -1;
		}
		snprintf(paths[n++], PATH_MAX, "%s", s);
		free(s);
	}
	return n;
}

/* ---- 子命令实现 ---- */

static int ws_cmd_create(const char *args_json, char **out)
{
	char *name = ws_arg_str(args_json, "name");
	char *backing = ws_arg_str(args_json, "backing");
	char *net = ws_arg_str(args_json, "net");
	char *label = ws_arg_str(args_json, "label");
	long long size_mb = ws_arg_ll(args_json, "size_mb", 0);
	double cpu_max = ws_arg_dbl(args_json, "cpu_max", -1);
	long long mem_max = ws_arg_ll(args_json, "mem_max", -1);
	long long pids_max = ws_arg_ll(args_json, "pids_max", -1);
	char ro[WS_MAX_PATHS][PATH_MAX], rw[WS_MAX_PATHS][PATH_MAX];
	char roargs[WS_MAX_PATHS][PATH_MAX + 16];
	char rwargs[WS_MAX_PATHS][PATH_MAX + 16];
	char image[PATH_MAX], loop[64], cgdir[PATH_MAX];
	char backarg[PATH_MAX + 16], sizearg[64], cpuarg[64], memarg[64];
	char pidarg[64];
	char errmsg[256];
	struct ws_allow allow_in[WS_ALLOW_MAX];
	char *argv[64];
	char *tail = NULL;
	int ro_n, rw_n, allow_n = 0, argc = 0, i, exit_code, timed_out, truncated;
	int disk, net_mode = WS_NET_NONE, existed_before = 0;
	struct ws_meta m;

	if (!ai_ws_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法工作区名 name='%s'"
			     "（允许 [A-Za-z0-9_.-]{1,32}，首字符不能是 . 或 -）",
			     name ? name : "(无)") < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	if (backing && strcmp(backing, "disk") != 0 &&
	    strcmp(backing, "tmpfs") != 0) {
		if (asprintf(out, "ERROR: 非法 backing='%s'（disk|tmpfs）",
			     backing) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	disk = !backing || strcmp(backing, "disk") == 0;

	/* net=none（默认）|veth|host；其它值明确拒绝（不猜测、不静默降级） */
	if (!net || strcmp(net, "none") == 0)
		net_mode = WS_NET_NONE;
	else if (strcmp(net, "veth") == 0)
		net_mode = WS_NET_VETH;
	else if (strcmp(net, "host") == 0)
		net_mode = WS_NET_HOST;
	else {
		if (asprintf(out, "ERROR: 非法 net='%s'（none|veth|host）",
			     net) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	allow_n = ws_arg_allow_array(args_json, "allow", allow_in, WS_ALLOW_MAX,
				     errmsg, sizeof(errmsg));
	if (allow_n < 0) {
		if (asprintf(out, "ERROR: %s", errmsg) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	if (allow_n > 0 && net_mode != WS_NET_VETH) {
		if (asprintf(out, "ERROR: allow 只对 net=veth 有意义"
			     "（当前 net=%s）", ws_net_mode_str(net_mode)) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	if (size_mb == 0)
		size_mb = 256;
	if (!ai_ws_valid_size_mb(size_mb)) {
		if (asprintf(out, "ERROR: 非法 size_mb=%lld（允许 %d-%d）",
			     size_mb, WS_MIN_MB, WS_MAX_MB) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	if (cpu_max >= 0 && (cpu_max < 0 || cpu_max > 64)) {
		if (asprintf(out, "ERROR: 非法 cpu_max=%.2f（0-64）",
			     cpu_max) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	if (mem_max >= 0 && mem_max > 1048576) {
		if (asprintf(out, "ERROR: 非法 mem_max=%lld（0-1048576 MB）",
			     mem_max) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	if (pids_max >= 0 && pids_max > 4000000) {
		if (asprintf(out, "ERROR: 非法 pids_max=%lld（0-4000000）",
			     pids_max) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	if (!ai_ws_valid_label(label)) {
		if (asprintf(out, "ERROR: 非法 label（≤64 字符，允许字母数字"
			     " ._- 与空格）") < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	ro_n = ws_arg_paths(args_json, "ro_paths", ro, WS_MAX_PATHS,
			    errmsg, sizeof(errmsg));
	if (ro_n < 0) {
		if (asprintf(out, "ERROR: %s", errmsg) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}
	rw_n = ws_arg_paths(args_json, "rw_paths", rw, WS_MAX_PATHS,
			    errmsg, sizeof(errmsg));
	if (rw_n < 0) {
		if (asprintf(out, "ERROR: %s", errmsg) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_INVALID_ARG;
	}

	/* 已存在 → 幂等返回（绝不重新格式化，数据是用户的） */
	memset(&m, 0, sizeof(m));
	if (ws_meta_read(name, &m) == 0) {
		if (asprintf(out,
			     "workspace_create: %s 已存在，未做任何改动\n"
			     "  backing=%s size=%ldMB image=%s loop=%s\n",
			     name, m.backing, m.size_mb,
			     m.image[0] ? m.image : "-",
			     m.loop[0] ? m.loop : "-") < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_OK;
	}

	snprintf(image, sizeof(image), "%s/%s.img", ws_root(), name);
	existed_before = ws_file_exists(image);

	if (ws_mkdir_p(ws_root())) {
		if (asprintf(out, "ERROR: 无法创建工作区根 %s（%s）",
			     ws_root(), strerror(errno)) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_STORAGE;
	}

	argv[argc++] = (char *)ws_sb_bin();
	argv[argc++] = (char *)"create";
	argv[argc++] = name;
	if (disk) {
		snprintf(backarg, sizeof(backarg), "--backing=disk:%s", image);
		argv[argc++] = backarg;
		snprintf(sizearg, sizeof(sizearg), "--disk-size-mb=%lld",
			 size_mb);
		argv[argc++] = sizearg;
	} else {
		argv[argc++] = (char *)"--backing=tmpfs";
	}
	if (cpu_max >= 0) {
		snprintf(cpuarg, sizeof(cpuarg), "--cpus=%.2f", cpu_max);
		argv[argc++] = cpuarg;
	}
	if (mem_max >= 0) {
		snprintf(memarg, sizeof(memarg), "--mem-mb=%lld", mem_max);
		argv[argc++] = memarg;
	}
	if (pids_max >= 0) {
		snprintf(pidarg, sizeof(pidarg), "--pids=%lld", pids_max);
		argv[argc++] = pidarg;
	}
	/* net=none|veth|host：veth 的沙盒侧仍按 none 建（真正入网在 run 时
	 * --net=join:<ns>），网络拓扑随后由 ws_net_setup 建齐 */
	if (net_mode == WS_NET_HOST)
		argv[argc++] = (char *)"--net=host";
	else
		argv[argc++] = (char *)"--net=none";
	for (i = 0; i < ro_n; i++) {
		snprintf(roargs[i], sizeof(roargs[i]), "--ro-path=%s", ro[i]);
		argv[argc++] = roargs[i];
	}
	for (i = 0; i < rw_n; i++) {
		snprintf(rwargs[i], sizeof(rwargs[i]), "--rw-path=%s", rw[i]);
		argv[argc++] = rwargs[i];
	}
	argv[argc] = NULL;

	if (access(argv[0], X_OK)) {
		if (asprintf(out, "ERROR: 找不到 %s（%s）。请先安装 aik-sandbox，"
			     "或用 AIKERNEL_SANDBOX_BIN 指定路径",
			     argv[0], strerror(errno)) < 0)
			*out = NULL;
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_NOT_FOUND;
	}
	if (ws_spawn_capture(argv, WS_SIMPLE_TIMEOUT, &tail, &exit_code,
			     &timed_out, &truncated)) {
		*out = strdup("ERROR: fork/pipe 失败（无法启动 aik-sandbox）");
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_GENERIC;
	}
	if (timed_out || exit_code != 0) {
		if (asprintf(out, "ERROR: workspace_create 失败（exit=%d%s）\n%s",
			     exit_code, timed_out ? "，超时" : "",
			     tail ? tail : "") < 0)
			*out = NULL;
		/* 失败不留下半挂载镜像：新镜像删掉，已有镜像保留 */
		if (!existed_before) {
			ws_loop_detach_image(image);
			unlink(image);
		}
		free(tail);
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_GENERIC;
	}

	memset(&m, 0, sizeof(m));
	snprintf(m.name, sizeof(m.name), "%s", name);
	snprintf(m.backing, sizeof(m.backing), "%s",
		 disk ? "disk" : "tmpfs");
	snprintf(m.image, sizeof(m.image), "%s", disk ? image : "");
	m.size_mb = disk ? size_mb : 0;
	m.created = (long)time(NULL);
	if (label)
		snprintf(m.label, sizeof(m.label), "%s", label);
	m.cpus_x100 = cpu_max >= 0 ? (int)(cpu_max * 100.0 + 0.5) : 100;
	m.mem_mb = mem_max >= 0 ? (long)mem_max : 1024;
	m.pids_max = pids_max >= 0 ? (long)pids_max : 256;
	m.net_mode = net_mode;
	m.ro_n = ro_n;
	m.rw_n = rw_n;
	for (i = 0; i < ro_n; i++)
		snprintf(m.ro[i], PATH_MAX, "%s", ro[i]);
	for (i = 0; i < rw_n; i++)
		snprintf(m.rw[i], PATH_MAX, "%s", rw[i]);
	for (i = 0; i < allow_n; i++)
		m.allow[i] = allow_in[i];
	m.allow_n = allow_n;
	if (disk) {
		struct stat st;

		if (!stat(image, &st))
			m.size_mb = (long)((st.st_size + 1024 * 1024 - 1) /
					   (1024 * 1024));
	}
	ws_sandbox_meta(name, loop, sizeof(loop));
	if (loop[0])
		snprintf(m.loop, sizeof(m.loop), "%s", loop);

	/* net=veth：建齐 netns/veth/网桥/nft；失败即回滚整个创建，
	 * 绝不留 "建了盘但网络半残" 的工作区 */
	if (net_mode == WS_NET_VETH) {
		char nerr[512];

		if (ws_net_setup(name, &m, 1, nerr, sizeof(nerr))) {
			if (asprintf(out, "ERROR: 工作区网络建立失败：%s；"
				     "已回滚本次创建\n", nerr) < 0)
				*out = NULL;
			{
				char *dargv[4];

				dargv[0] = (char *)ws_sb_bin();
				dargv[1] = (char *)"destroy";
				dargv[2] = name;
				dargv[3] = NULL;
				free(tail);      /* create 的输出不再需要 */
				tail = NULL;
				if (access(dargv[0], X_OK) == 0)
					(void)ws_spawn_capture(dargv, 60,
							       &tail,
							       &exit_code,
							       &timed_out,
							       &truncated);
				free(tail);
				tail = NULL;
			}
			ws_net_teardown(name, NULL, 0);
			if (!existed_before) {
				ws_loop_detach_image(image);
				unlink(image);
			}
			free(name);
			free(backing);
			free(net);
			free(label);
			return AI_ERR_GENERIC;
		}
	}
	if (ws_meta_write(name, &m)) {
		if (asprintf(out, "ERROR: 元数据写入失败（%s）；已回滚本次创建",
			     strerror(errno)) < 0)
			*out = NULL;
		{
			char *dargv[4];

			dargv[0] = (char *)ws_sb_bin();
			dargv[1] = (char *)"destroy";
			dargv[2] = name;
			dargv[3] = NULL;
			(void)ws_spawn_capture(dargv, 60, &tail, &exit_code,
					       &timed_out, &truncated);
			free(tail);
		}
		if (!existed_before) {
			ws_loop_detach_image(image);
			unlink(image);
		}
		free(name);
		free(backing);
		free(net);
		free(label);
		return AI_ERR_STORAGE;
	}

	snprintf(cgdir, sizeof(cgdir), "%s/aik-sandbox/%s", ws_cg_root(), name);
	if (asprintf(out,
		     "workspace_create: %s 就绪\n"
		     "  backing=%s size=%ldMB image=%s loop=%s\n"
		     "  mount=%s/%s/root cgroup=%s\n"
		     "  limits cpu=%.2f mem=%ldMB pids=%ld net=%s\n"
		     "  label=%s ro_paths=%d rw_paths=%d\n"
		     "%s%s%s%s",
		     name, m.backing, m.size_mb,
		     m.image[0] ? m.image : "-",
		     m.loop[0] ? m.loop : "(无)",
		     ws_sb_base(), name, cgdir,
		     m.cpus_x100 / 100.0, m.mem_mb, m.pids_max,
		     ws_net_mode_str(m.net_mode),
		     m.label[0] ? m.label : "-", m.ro_n, m.rw_n,
		     tail ? tail : "",
		     m.net_mode == WS_NET_VETH ?
		     "  net=veth: 独立 netns + veth + aikbr0，缺省拒出站\n" : "",
		     m.net_mode == WS_NET_VETH ? "  netns=" : "",
		     m.net_mode == WS_NET_VETH ? m.net_ns : "") < 0)
		*out = NULL;
	if (m.net_mode == WS_NET_VETH && *out) {
		FILE *mem;
		size_t len = 0;
		char *buf = NULL, extra[512];
		int j;

		mem = open_memstream(&buf, &len);
		if (mem) {
			fputs(*out, mem);
			fprintf(mem, "  addr=%s/16 gw=%s veth=%s(宿主)<->%s"
				" 网桥=%s\n",
				m.net_ip, WS_BR_ADDR, m.net_host_if,
				m.net_ws_if, WS_BR_NAME);
			fprintf(mem, "  白名单 %d 条（缺省拒出站）：\n",
				m.allow_n);
			for (j = 0; j < m.allow_n; j++) {
				ws_allow_fmt(&m.allow[j], extra,
					     sizeof(extra));
				fprintf(mem, "    [%d] %s\n", j, extra);
			}
			fclose(mem);
			free(*out);
			*out = buf;
		}
	}
	free(tail);
	free(name);
	free(backing);
	free(net);
	free(label);
	return AI_OK;
}

static int ws_cmd_list(char **out)
{
	DIR *d = opendir(ws_root());
	struct dirent *e;
	char *buf = NULL;
	size_t len = 0;
	int count = 0;
	FILE *mem = open_memstream(&buf, &len);

	if (!mem) {
		*out = strdup("ERROR: open_memstream 失败");
		return AI_ERR_GENERIC;
	}
	fprintf(mem, "%-20s %-7s %8s %9s %-19s %-8s %s\n",
		"NAME", "BACKING", "SIZE_MB", "USED_MB", "CREATED",
		"STATUS", "LABEL");
	if (d) {
		while ((e = readdir(d))) {
			struct ws_meta m;
			char created[32] = "-";
			struct tm tm;
			time_t ct;

			{
				char name[WS_MAX_NAME + 1];
				size_t nl = strlen(e->d_name);

				if (e->d_name[0] == '.' || nl <= 5 ||
				    strcmp(e->d_name + nl - 5, ".meta") != 0)
					continue;
				nl -= 5;
				if (nl == 0 || nl > WS_MAX_NAME)
					continue;
				memcpy(name, e->d_name, nl);
				name[nl] = '\0';
				if (!ai_ws_valid_name(name))
					continue;
				if (ws_meta_read(name, &m))
					continue;
			}
			ct = (time_t)m.created;
			if (m.created > 0 && localtime_r(&ct, &tm))
				strftime(created, sizeof(created),
					 "%Y-%m-%d %H:%M:%S", &tm);
			fprintf(mem, "%-20s %-7s %8ld %9ld %-19s %-8s %s\n",
				m.name, m.backing, m.size_mb,
				ws_used_mb(&m), created,
				ws_running(m.name) ? "running" : "ready",
				m.label[0] ? m.label : "-");
			count++;
		}
		closedir(d);
	}
	if (!count)
		fprintf(mem, "(暂无工作区)\n");
	fclose(mem);
	*out = buf;
	return AI_OK;
}

static int ws_cmd_inspect(const char *args_json, char **out)
{
	char *name = ws_arg_str(args_json, "name");
	struct ws_meta m;
	char cgdir[PATH_MAX], artdir[PATH_MAX];
	char curloop[64] = "";

	if (!ai_ws_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法工作区名 name='%s'",
			     name ? name : "(无)") < 0)
			*out = NULL;
		free(name);
		return AI_ERR_INVALID_ARG;
	}
	if (ws_meta_read(name, &m)) {
		if (asprintf(out, "ERROR: 工作区 '%s' 不存在（先 "
			     "workspace_create）", name) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_NOT_FOUND;
	}
	if (m.image[0])
		(void)ws_loop_find(m.image, curloop, sizeof(curloop));
	snprintf(cgdir, sizeof(cgdir), "%s/aik-sandbox/%s", ws_cg_root(),
		 name);
	ws_artifact_dir(name, artdir, sizeof(artdir));
	if (asprintf(out,
		     "workspace: %s\n"
		     "  backing:   %s\n"
		     "  image:     %s (%s)\n"
		     "  loop:      %s\n"
		     "  size:      %ld MB\n"
		     "  used:      %ld MB\n"
		     "  mount:     %s/%s/root\n"
		     "  cgroup:    %s\n"
		     "  limits:    cpu_max=%.2f mem_max=%ldMB pids_max=%ld "
		     "net=%s\n"
		     "  label:     %s\n"
		     "  status:    %s\n"
		     "  ro_paths:  %d\n"
		     "  rw_paths:  %d\n"
		     "  artifacts: %s\n",
		     m.name, m.backing,
		     m.image[0] ? m.image : "-",
		     !m.image[0] ? "tmpfs（无镜像，数据不持久）" :
		     ws_file_exists(m.image) ? "exists" : "MISSING",
		     curloop[0] ? curloop :
		     (m.loop[0] ? m.loop : "(未接 loop)"),
		     m.size_mb, ws_used_mb(&m),
		     ws_sb_base(), name, cgdir,
		     m.cpus_x100 / 100.0, m.mem_mb, m.pids_max,
		     ws_net_mode_str(m.net_mode),
		     m.label[0] ? m.label : "-",
		     ws_running(name) ? "running" : "ready",
		     m.ro_n, m.rw_n,
		     ws_is_dir(artdir) ? artdir : "(不存在)") < 0)
		*out = NULL;
	{
		int i;
		FILE *mem;
		size_t len = 0;
		char *buf = NULL;

		if (!*out) {
			free(name);
			return AI_ERR_GENERIC;
		}
		mem = open_memstream(&buf, &len);
		if (!mem) {
			free(name);
			return AI_OK;
		}
		fputs(*out, mem);
		for (i = 0; i < m.ro_n; i++)
			fprintf(mem, "    ro[%d]=%s\n", i, m.ro[i]);
		for (i = 0; i < m.rw_n; i++)
			fprintf(mem, "    rw[%d]=%s\n", i, m.rw[i]);
		if (m.net_mode == WS_NET_VETH) {
			char tbl[WS_MAX_NAME + 16], al[128];
			int j;

			ws_nft_table_name(name, tbl, sizeof(tbl));
			fprintf(mem, "  net_ns:    %s（%s）\n", m.net_ns,
				ws_netns_exists(m.net_ns) ? "存在" : "缺失");
			fprintf(mem, "  net_ip:    %s/16（网关 %s）\n",
				m.net_ip, WS_BR_ADDR);
			fprintf(mem, "  veth:      %s（宿主侧，%s）<-> "
				"%s（工作区侧，%s）\n", m.net_host_if,
				ws_link_exists(m.net_host_if) ? "在" : "缺失",
				m.net_ws_if,
				ws_link_in_netns(m.net_ns, m.net_ws_if) ?
				"在" : "缺失");
			fprintf(mem, "  bridge:    %s（%s）\n", WS_BR_NAME,
				ws_link_exists(WS_BR_NAME) ? "存在" : "缺失");
			fprintf(mem, "  nft:       inet %s（%s）\n", tbl,
				ws_nft_table_exists(m.net_ns, tbl) ?
				"已下发" : "不存在");
			fprintf(mem, "  net_allow: %d 条\n", m.allow_n);
			for (j = 0; j < m.allow_n; j++) {
				ws_allow_fmt(&m.allow[j], al, sizeof(al));
				fprintf(mem, "    allow[%d]=%s\n", j, al);
			}
		}
		fclose(mem);
		free(*out);
		*out = buf;
	}
	free(name);
	return AI_OK;
}

/*
 * W82e（V1.8）：run 参数面只有一份翻译。
 * workspace_run 与 sandbox_spawn 都经这里把「元数据 + 用户 argv」翻译成
 * aik-sandbox 的 getopt 参数面；调用方保证 b 的生命周期覆盖 spawn。
 */
struct ws_run_buf {
	char image[PATH_MAX + 16];
	char cpus[64], mem[64], pids[64];
	char net[WS_NET_NS_MAX + 16];
	char ro[WS_MAX_PATHS][PATH_MAX + 16];
	char rw[WS_MAX_PATHS][PATH_MAX + 16];
};

static int ws_build_run_argv(const char *name, const struct ws_meta *m,
			     char *const argv[], int argc, char *sbargv[],
			     int cap, struct ws_run_buf *b)
{
	int sn = 0, i;

	if (8 + m->ro_n + m->rw_n + argc >= cap)
		return -1;
	sbargv[sn++] = (char *)ws_sb_bin();
	sbargv[sn++] = (char *)"run";
	sbargv[sn++] = (char *)name;
	if (strcmp(m->backing, "disk") == 0) {
		snprintf(b->image, sizeof(b->image), "--backing=disk:%s",
			 m->image);
		sbargv[sn++] = b->image;
	} else {
		sbargv[sn++] = (char *)"--backing=tmpfs";
	}
	snprintf(b->cpus, sizeof(b->cpus), "--cpus=%.2f",
		 m->cpus_x100 / 100.0);
	sbargv[sn++] = b->cpus;
	snprintf(b->mem, sizeof(b->mem), "--mem-mb=%ld", m->mem_mb);
	sbargv[sn++] = b->mem;
	snprintf(b->pids, sizeof(b->pids), "--pids=%ld", m->pids_max);
	sbargv[sn++] = b->pids;
	if (m->net_mode == WS_NET_VETH) {
		snprintf(b->net, sizeof(b->net), "--net=join:%s", m->net_ns);
		sbargv[sn++] = b->net;
	} else if (m->net_mode == WS_NET_NONE) {
		sbargv[sn++] = (char *)"--net=none";
	} else {
		sbargv[sn++] = (char *)"--net=host";
	}
	for (i = 0; i < m->ro_n; i++) {
		snprintf(b->ro[i], sizeof(b->ro[i]), "--ro-path=%s", m->ro[i]);
		sbargv[sn++] = b->ro[i];
	}
	for (i = 0; i < m->rw_n; i++) {
		snprintf(b->rw[i], sizeof(b->rw[i]), "--rw-path=%s", m->rw[i]);
		sbargv[sn++] = b->rw[i];
	}
	sbargv[sn++] = (char *)"--";
	for (i = 0; i < argc; i++)
		sbargv[sn++] = argv[i];
	sbargv[sn] = NULL;
	return 0;
}

/*
 * W81c：在工作区内执行任意 argv（workspace_run 与 app_profile_dynamic
 * 复用同一套隔离执行/限额/超时强杀逻辑）。
 * 返回 AI_OK = 已执行（exit_code/timed_out/truncated 有效，子进程退出码
 * 非 0 也算已执行）；其余为工作区/启动失败，err_out 给原因。
 */
int ai_ws_run_argv(const char *name, char *const argv[], int argc,
		   int timeout_s, char **tail_out, int *exit_code,
		   int *timed_out, int *truncated, char **err_out)
{
	struct ws_meta m;
	struct ws_run_buf b;
	char *sbargv[96];

	if (tail_out)
		*tail_out = NULL;
	if (exit_code)
		*exit_code = -1;
	if (timed_out)
		*timed_out = 0;
	if (truncated)
		*truncated = 0;
	if (err_out)
		*err_out = NULL;
	if (!ai_ws_valid_name(name)) {
		if (err_out && asprintf(err_out, "ERROR: 非法工作区名 name='%s'",
				       name ? name : "(无)") < 0)
			*err_out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	if (!argv || argc < 1) {
		if (err_out && asprintf(err_out,
				       "ERROR: 缺少 argv（在工作区内执行的命令）")
		    < 0)
			*err_out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	if (timeout_s < 1 || timeout_s > WS_RUN_TIMEOUT_MAX)
		timeout_s = WS_RUN_TIMEOUT_DEF;
	if (ws_meta_read(name, &m)) {
		if (err_out && asprintf(err_out, "ERROR: 工作区 '%s' 不存在（先 "
				       "workspace_create）", name) < 0)
			*err_out = NULL;
		return AI_ERR_NOT_FOUND;
	}
	if (strcmp(m.backing, "disk") == 0 &&
	    !ws_image_under_root(m.image)) {
		if (err_out && asprintf(err_out, "ERROR: 工作区 '%s' 的元数据"
				       "镜像路径非法: %s", name, m.image) < 0)
			*err_out = NULL;
		return AI_ERR_STORAGE;
	}
	if (strcmp(m.backing, "disk") == 0 && !ws_file_exists(m.image)) {
		if (err_out && asprintf(err_out, "ERROR: 工作区 '%s' 的镜像 %s"
				       " 不存在（元数据损坏或镜像被外部删除）",
				       name, m.image) < 0)
			*err_out = NULL;
		return AI_ERR_NOT_FOUND;
	}
	if (12 + m.ro_n + m.rw_n + argc >= 96) {
		if (err_out && asprintf(err_out, "ERROR: argv 过多（%d）",
				       argc) < 0)
			*err_out = NULL;
		return AI_ERR_INVALID_ARG;
	}

	if (m.net_mode == WS_NET_VETH) {
		/* 运行时状态（netns/veth）可能在重启后丢失：先幂等补齐
		 * （规则只在表缺失时重建，保留既有计数与白名单语义） */
		char nerr[512];

		if (!ws_netns_exists(m.net_ns) ||
		    !ws_link_in_netns(m.net_ns, m.net_ws_if)) {
			struct ws_meta fix = m;

			if (ws_net_setup(name, &fix, 0, nerr, sizeof(nerr))) {
				if (err_out && asprintf(err_out,
						       "ERROR: 工作区 '%s' 的"
						       "网络不可用，且自动修复"
						       "失败：%s", name,
						       nerr) < 0)
					*err_out = NULL;
				return AI_ERR_GENERIC;
			}
			m = fix;
			(void)ws_meta_write(name, &m);
		}
	}

	if (ws_build_run_argv(name, &m, argv, argc, sbargv, 96, &b)) {
		if (err_out && asprintf(err_out, "ERROR: argv 过多（%d）",
				       argc) < 0)
			*err_out = NULL;
		return AI_ERR_INVALID_ARG;
	}

	if (access(sbargv[0], X_OK)) {
		if (err_out && asprintf(err_out, "ERROR: 找不到 %s（%s）；工作区"
				       "执行依赖 aik-sandbox", sbargv[0],
				       strerror(errno)) < 0)
			*err_out = NULL;
		return AI_ERR_NOT_FOUND;
	}
	if (ws_spawn_capture(sbargv, timeout_s, tail_out, exit_code,
			     timed_out, truncated)) {
		if (err_out)
			*err_out = strdup("ERROR: fork/pipe 失败（无法启动 "
					  "aik-sandbox）");
		return AI_ERR_GENERIC;
	}
	return AI_OK;
}

static int ws_cmd_run(const char *args_json, char **out)
{
	char *name = ws_arg_str(args_json, "name");
	char *command = ws_arg_str(args_json, "command");
	long long timeout_s = ws_arg_ll(args_json, "timeout_s",
					WS_RUN_TIMEOUT_DEF);
	char *sbargv[4];
	char *tail = NULL, *err = NULL;
	int rc, exit_code = -1, timed_out = 0, truncated = 0;

	*out = NULL;
	if (!command || !command[0]) {
		if (asprintf(out, "ERROR: 缺少 command（在工作区内执行的命令）")
		    < 0)
			*out = NULL;
		free(name);
		free(command);
		return AI_ERR_INVALID_ARG;
	}
	if (timeout_s < 1 || timeout_s > WS_RUN_TIMEOUT_MAX)
		timeout_s = WS_RUN_TIMEOUT_DEF;
	sbargv[0] = (char *)"/bin/sh";
	sbargv[1] = (char *)"-c";
	sbargv[2] = command;
	sbargv[3] = NULL;
	rc = ai_ws_run_argv(name, sbargv, 3, (int)timeout_s, &tail,
			    &exit_code, &timed_out, &truncated, &err);
	if (rc != AI_OK) {
		*out = err;
		free(tail);
		free(name);
		free(command);
		return rc;
	}
	if (timed_out) {
		if (asprintf(out, "ERROR: 工具超时（超过 %lld 秒未完成），"
			     "已发送 SIGKILL 终止工作区进程组\n部分输出:\n%s",
			     timeout_s, tail ? tail : "") < 0)
			*out = NULL;
		free(tail);
		free(name);
		free(command);
		return AI_ERR_API;
	}
	/* 组装失败：aik-sandbox 自身诊断（挂载/权限/镜像损坏；die(2)） */
	if (exit_code == 2 && tail && strstr(tail, "aik-sandbox: ")) {
		if (asprintf(out, "ERROR: 工作区组装失败（exit=%d）\n%s",
			     exit_code, tail) < 0)
			*out = NULL;
		free(tail);
		free(name);
		free(command);
		return AI_ERR_GENERIC;
	}
	/* 退出码语义对齐 exec_run：非零 → AI_ERR_API + "命令退出码 N"；
	 * 0 → AI_OK + "命令执行成功"。不把失败藏在 exit= 文本里。 */
	if (exit_code != 0) {
		if (asprintf(out, "命令退出码 %d，输出:\n%s%s",
			     exit_code,
			     (tail && tail[0]) ? tail : "(无输出)",
			     truncated ? "\n(输出超长，仅保留尾部)" : "") < 0)
			*out = NULL;
		free(tail);
		free(name);
		free(command);
		return AI_ERR_API;
	}
	if (asprintf(out, "命令执行成功，输出:\n%s%s",
		     (tail && tail[0]) ? tail : "(无输出)",
		     truncated ? "\n(输出超长，仅保留尾部)" : "") < 0)
		*out = NULL;
	free(tail);
	free(name);
	free(command);
	return AI_OK;
}

/*
 * W82e：aik-sandbox destroy 的唯一调用点（后端回收执行体）。
 * 幂等：区目录/挂载/cgroup 都交给它收；输出可交回调用方。
 */
static void ws_backend_destroy(const char *name, char **tail)
{
	char *dargv[4];
	char *t = NULL;
	int exit_code = -1, timed_out = 0, truncated = 0;

	dargv[0] = (char *)ws_sb_bin();
	dargv[1] = (char *)"destroy";
	dargv[2] = (char *)name;
	dargv[3] = NULL;
	if (access(dargv[0], X_OK) == 0)
		(void)ws_spawn_capture(dargv, WS_SIMPLE_TIMEOUT, &t, &exit_code,
				       &timed_out, &truncated);
	if (tail)
		*tail = t;
	else
		free(t);
}

/* 追加后端原文到已有输出（不覆盖、不重复分配泄漏） */
static void ws_append(char **dst, const char *add)
{
	char *merged = NULL;

	if (!add || !add[0])
		return;
	if (*dst && (*dst)[0]) {
		if (asprintf(&merged, "%s\n%s", *dst, add) < 0)
			return;
	} else {
		merged = strdup(add);
		if (!merged)
			return;
	}
	free(*dst);
	*dst = merged;
}

/*
 * W82e（V1.8）：唯一的销毁实现。workspace_destroy（JSON 面）与
 * sandbox_destroy（区名适配面）都走这里——不存在第二条销毁路径。
 *
 * bin_tail 非空时，把 aik-sandbox destroy 的输出一并交回（sandbox 通道
 * 的文案需要后端原文）；workspace 面传 NULL，输出与旧版逐字一致。
 */
static int ws_destroy_impl(const char *name, char **out, char **bin_tail)
{
	struct ws_meta m;
	char sdir[PATH_MAX], cgdir[PATH_MAX], meta[PATH_MAX], image[PATH_MAX];
	char artdir[PATH_MAX], netnote[512];
	char nc_note[640];
	int have_meta, had_state, art_state = 0, ws_net_was = 0;

	if (bin_tail)
		*bin_tail = NULL;
	if (!ai_ws_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法工作区名 name='%s'",
			     name ? name : "(无)") < 0)
			*out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	have_meta = ws_meta_read(name, &m) == 0;
	snprintf(sdir, sizeof(sdir), "%s/%s", ws_sb_base(), name);
	snprintf(cgdir, sizeof(cgdir), "%s/aik-sandbox/%s", ws_cg_root(),
		 name);
	ws_meta_path(name, meta, sizeof(meta));
	ws_image_path(name, image, sizeof(image));
	had_state = have_meta || ws_is_dir(sdir) || ws_is_dir(cgdir) ||
		    ws_file_exists(image);

	/* 后端回收：aik-sandbox destroy 是「杀 run/cgroup/挂载/区目录」的
	 * 唯一执行体。V1.8 起无条件调用（幂等）：即便状态目录已被外部清掉，
	 * 仍让后端把残留 mount/cgroup 收干净；输出按调用方需要交回。 */
	if (bin_tail) {
		ws_backend_destroy(name, bin_tail);
	} else {
		ws_backend_destroy(name, NULL);
	}

	if (ws_running(name)) {
		if (asprintf(out, "ERROR: 工作区 %s 仍被执行进程占用（锁忙），"
			     "已拒绝删除镜像；请稍后重试 destroy", name) < 0)
			*out = NULL;
		return AI_ERR_API;
	}
	/* 元数据镜像路径只允许在工作区根下 */
	if (have_meta && m.image[0] && !ws_image_under_root(m.image)) {
		if (asprintf(out, "ERROR: 元数据镜像路径非法，拒绝删除: %s",
			     m.image) < 0)
			*out = NULL;
		return AI_ERR_STORAGE;
	}

	/* W81d：先拆网络（netns → nft 表/地址/工作区侧 veth → 宿主侧 veth
	 * 退出网桥），再动物理存储。名字可推导，元数据缺失也能清干净。 */
	{
		char ns[WS_NET_NS_MAX + 1], hif[32], wif[32];

		ws_net_ns_name(name, ns, sizeof(ns));
		ws_if_names(name, hif, sizeof(hif), wif, sizeof(wif));
		ws_net_was = (have_meta && m.net_mode == WS_NET_VETH) ||
			     ws_netns_exists(ns) || ws_link_exists(hif);
	}
	ws_net_teardown(name, netnote, sizeof(netnote));
	nc_note[0] = '\0';
	if (netnote[0])
		snprintf(nc_note, sizeof(nc_note), "；网络清理异常: %s", netnote);

	/* 解 loop（元数据里的镜像 + 默认路径 + 任何回指该镜像的 loop） */
	if (have_meta && m.image[0])
		(void)ws_loop_detach_image(m.image);
	(void)ws_loop_detach_image(image);
	if (have_meta && m.loop[0]) {
		int fd = open(m.loop, O_RDONLY | O_CLOEXEC);

		if (fd >= 0) {
			(void)ioctl(fd, LOOP_CLR_FD, 0);
			close(fd);
		}
	}

	if (have_meta && strcmp(m.backing, "disk") == 0 && m.image[0] &&
	    unlink(m.image) && errno != ENOENT) {
		if (asprintf(out, "ERROR: 删除镜像 %s 失败: %s", m.image,
			     strerror(errno)) < 0)
			*out = NULL;
		return AI_ERR_STORAGE;
	}
	if (!have_meta && unlink(image) && errno != ENOENT) {
		if (asprintf(out, "ERROR: 删除镜像 %s 失败: %s", image,
			     strerror(errno)) < 0)
			*out = NULL;
		return AI_ERR_STORAGE;
	}
	if (unlink(meta) && errno != ENOENT) {
		if (asprintf(out, "ERROR: 删除元数据 %s 失败: %s", meta,
			     strerror(errno)) < 0)
			*out = NULL;
		return AI_ERR_STORAGE;
	}

	/* B-109：destroy 后不留空产物目录。空 → rmdir；非空 → 明确报告
	 * （用户的产物不删），失败 → 报告，绝不静默当成功。 */
	ws_artifact_dir(name, artdir, sizeof(artdir));
	if (rmdir(artdir) == 0)
		art_state = 1;
	else if (errno == ENOTEMPTY || errno == EEXIST)
		art_state = 2;
	else if (errno == ENOENT)
		art_state = 0;
	else
		art_state = 3;

	if (had_state) {
		if (asprintf(out, "workspace_destroy: %s 已清理（进程/"
			     "cgroup/挂载/loop/镜像/元数据%s%s）%s%s%s",
			     name,
			     ws_net_was ? "/netns/veth/nft 表" : "",
			     art_state == 1 ? "/空产物目录" : "",
			     art_state == 2 ? "；产物目录非空，已保留用户产物: " :
			     art_state == 3 ? "；产物目录删除失败: " : "",
			     (art_state == 2 || art_state == 3) ? artdir : "",
			     nc_note) < 0)
			*out = NULL;
	} else {
		if (asprintf(out, "workspace_destroy: %s 无残留（本就干净，"
			     "幂等成功）%s", name,
			     art_state == 1 ? "；删除遗留空产物目录" : "") < 0)
			*out = NULL;
	}
	return AI_OK;
}

static int ws_cmd_destroy(const char *args_json, char **out)
{
	char *name = ws_arg_str(args_json, "name");
	int rc;

	if (!name) {
		*out = strdup("ERROR: 缺少 name");
		return AI_ERR_INVALID_ARG;
	}
	rc = ws_destroy_impl(name, out, NULL);
	free(name);
	return rc;
}

/* 追加某 netns 内 nft 表原文（含 counter 计数）；未下发时留空 */
static void ws_nft_dump(const char *ns, const char *tbl, FILE *mem)
{
	const char *ip = ws_ip_bin(), *nft = ws_nft_bin();
	char *argv[10], *o = NULL;
	int rc = -1;

	if (!ip || !nft)
		return;
	argv[0] = (char *)ip;
	argv[1] = (char *)"netns";
	argv[2] = (char *)"exec";
	argv[3] = (char *)ns;
	argv[4] = (char *)nft;
	argv[5] = (char *)"list";
	argv[6] = (char *)"table";
	argv[7] = (char *)"inet";
	argv[8] = (char *)tbl;
	argv[9] = NULL;
	if (ws_run(argv, &o, &rc) == 0 && rc == 0 && o)
		fprintf(mem, "%s", o);
	free(o);
}

/* 追加某 netns 内某接口的地址原文 */
static void ws_addr_dump(const char *ns, const char *dev, FILE *mem)
{
	const char *ip = ws_ip_bin();
	char *argv[8], *o = NULL;
	int rc = -1;

	if (!ip)
		return;
	argv[0] = (char *)ip;
	argv[1] = (char *)"-n";
	argv[2] = (char *)ns;
	argv[3] = (char *)"-o";
	argv[4] = (char *)"addr";
	argv[5] = (char *)"show";
	argv[6] = (char *)dev;
	argv[7] = NULL;
	if (ws_run(argv, &o, &rc) == 0 && rc == 0 && o)
		fprintf(mem, "%s", o);
	free(o);
}

static int ws_cmd_net_status(const char *args_json, char **out)
{
	char *name = ws_arg_str(args_json, "name");
	struct ws_meta m;
	char ns[WS_NET_NS_MAX + 1], tbl[WS_MAX_NAME + 16];
	char hif[32], wif[32], *buf = NULL;
	size_t len = 0;
	FILE *mem;
	int i, members = 0, mine = 0;
	char *bm;

	if (!ai_ws_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法工作区名 name='%s'",
			     name ? name : "(无)") < 0)
			*out = NULL;
		free(name);
		return AI_ERR_INVALID_ARG;
	}
	if (ws_meta_read(name, &m)) {
		if (asprintf(out, "ERROR: 工作区 '%s' 不存在（先 "
			     "workspace_create）", name) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_NOT_FOUND;
	}
	ws_net_ns_name(name, ns, sizeof(ns));
	ws_nft_table_name(name, tbl, sizeof(tbl));
	ws_if_names(name, hif, sizeof(hif), wif, sizeof(wif));
	if (m.net_ns[0])
		snprintf(ns, sizeof(ns), "%s", m.net_ns);
	if (m.net_host_if[0])
		snprintf(hif, sizeof(hif), "%s", m.net_host_if);
	if (m.net_ws_if[0])
		snprintf(wif, sizeof(wif), "%s", m.net_ws_if);

	mem = open_memstream(&buf, &len);
	if (!mem) {
		*out = strdup("ERROR: open_memstream 失败");
		free(name);
		return AI_ERR_GENERIC;
	}
	fprintf(mem, "workspace_net_status: %s\n", name);
	fprintf(mem, "  mode:      net=%s\n", ws_net_mode_str(m.net_mode));
	if (m.net_mode != WS_NET_VETH) {
		fprintf(mem, "  （net=%s 无工作区网络拓扑；只有 net=veth 才有 "
			"netns/veth/规则）\n", ws_net_mode_str(m.net_mode));
		fclose(mem);
		*out = buf;
		free(name);
		return AI_OK;
	}
	{
		int ns_ok = ws_netns_exists(ns);
		int hf_ok = ws_link_exists(hif);
		int wf_ok = ns_ok && ws_link_in_netns(ns, wif);
		int tbl_ok = ns_ok && ws_nft_table_exists(ns, tbl);

		bm = ws_bridge_members();
		if (bm) {
			char *p = bm;

			while (*p) {
				char *nl = strchr(p, '\n');

				if (nl)
					*nl = '\0';
				if (*p) {
					members++;
					if (strstr(p, hif))
						mine = 1;
				}
				if (!nl)
					break;
				p = nl + 1;
			}
		}
		fprintf(mem, "  netns:     %s（%s）\n", ns,
			ns_ok ? "存在" : "缺失");
		fprintf(mem, "  addr:      工作区 %s/16 ←→ 宿主 %s/16\n",
			m.net_ip[0] ? m.net_ip : "(未知)", WS_BR_ADDR);
		fprintf(mem, "  veth:      %s（宿主侧 %s）<-> %s（工作区侧 %s）\n",
			hif, hf_ok ? "在" : "缺失", wif, wf_ok ? "在" : "缺失");
		fprintf(mem, "  bridge:    %s（%s），成员 %d 个，本工作区%s\n",
			WS_BR_NAME, ws_link_exists(WS_BR_NAME) ? "存在" : "缺失",
			members, mine ? "在网桥内" : "不在网桥内");
		fprintf(mem, "  nft:       inet %s（%s）\n", tbl,
			tbl_ok ? "已下发" : "不存在");
		fprintf(mem, "  地址明细（netns 内）：\n");
		if (wf_ok)
			ws_addr_dump(ns, wif, mem);
		else
			fprintf(mem, "    （工作区侧接口缺失）\n");
		fprintf(mem, "  规则与计数：\n");
		if (tbl_ok)
			ws_nft_dump(ns, tbl, mem);
		else
			fprintf(mem, "    （表不存在）\n");
	}
	fprintf(mem, "  白名单:    %d 条（缺省拒出站；只放行 lo、已建立连接、"
		"下列目标）\n", m.allow_n);
	for (i = 0; i < m.allow_n; i++) {
		char al[128];

		ws_allow_fmt(&m.allow[i], al, sizeof(al));
		fprintf(mem, "    [%d] %s\n", i, al);
	}
	fclose(mem);
	free(bm);
	*out = buf;
	free(name);
	return AI_OK;
}

static int ws_cmd_net_allow(const char *args_json, char **out)
{
	char *name = ws_arg_str(args_json, "name");
	char *action = ws_arg_str(args_json, "action");
	char *dst = ws_arg_str(args_json, "dst");
	char *proto = ws_arg_str(args_json, "proto");
	long long port = ws_arg_ll(args_json, "port", -1);
	struct ws_meta m, old;
	char errmsg[256], nerr[512];
	const char *act;
	int i, removed = 0, rc = AI_OK;

	if (!ai_ws_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法工作区名 name='%s'",
			     name ? name : "(无)") < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}
	if (ws_meta_read(name, &m)) {
		if (asprintf(out, "ERROR: 工作区 '%s' 不存在（先 "
			     "workspace_create）", name) < 0)
			*out = NULL;
		rc = AI_ERR_NOT_FOUND;
		goto done;
	}
	if (m.net_mode != WS_NET_VETH) {
		if (asprintf(out, "ERROR: 工作区 '%s' 的 net=%s，没有工作区网络"
			     "白名单；只有 net=veth 的工作区才有（销毁后用 "
			     "net=veth 重建）", name,
			     ws_net_mode_str(m.net_mode)) < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}
	act = (action && action[0]) ? action : "add";

	if (strcmp(act, "list") == 0) {
		FILE *mem;
		size_t len = 0;
		char *buf = NULL;

		mem = open_memstream(&buf, &len);
		if (!mem) {
			*out = strdup("ERROR: open_memstream 失败");
			rc = AI_ERR_GENERIC;
			goto done;
		}
		fprintf(mem, "workspace_net_allow: %s 白名单 %d 条\n", name,
			m.allow_n);
		for (i = 0; i < m.allow_n; i++) {
			char al[128];

			ws_allow_fmt(&m.allow[i], al, sizeof(al));
			fprintf(mem, "  [%d] %s\n", i, al);
		}
		fclose(mem);
		*out = buf;
		goto done;
	}

	old = m;
	if (strcmp(act, "rebuild") == 0) {
		/* 重建运行时拓扑（重启后 netns/veth 丢失时用），规则按元数据
		 * 白名单重写 */
		if (ws_net_setup(name, &m, 1, nerr, sizeof(nerr))) {
			if (asprintf(out, "ERROR: 重建网络失败：%s", nerr) < 0)
				*out = NULL;
			rc = AI_ERR_GENERIC;
			goto done;
		}
	} else if (strcmp(act, "clear") == 0) {
		if (m.allow_n == 0) {
			if (asprintf(out, "workspace_net_allow: %s 白名单本就是空的"
				     "（缺省拒出站不变）", name) < 0)
				*out = NULL;
			goto done;
		}
		m.allow_n = 0;
		if (ws_net_setup(name, &m, 1, nerr, sizeof(nerr))) {
			m = old;
			if (asprintf(out, "ERROR: 下发空白名单失败：%s"
				     "（元数据未改动）", nerr) < 0)
				*out = NULL;
			rc = AI_ERR_GENERIC;
			goto done;
		}
	} else if (strcmp(act, "add") == 0) {
		struct ws_allow a;

		if (!dst || !dst[0]) {
			if (asprintf(out, "ERROR: action=add 需要 dst"
				     "（IPv4/IPv6 地址或 CIDR）") < 0)
				*out = NULL;
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		if (ws_allow_check(dst, port < 0 ? 0 : port, proto, &a, errmsg,
				   sizeof(errmsg))) {
			if (asprintf(out, "ERROR: %s", errmsg) < 0)
				*out = NULL;
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		for (i = 0; i < m.allow_n; i++)
			if (strcmp(m.allow[i].dst, a.dst) == 0 &&
			    m.allow[i].port == a.port &&
			    strcmp(m.allow[i].proto, a.proto) == 0)
				break;
		if (i < m.allow_n) {
			if (asprintf(out, "workspace_net_allow: %s 白名单里已有"
				     "该条目，未改动", name) < 0)
				*out = NULL;
			goto done;
		}
		if (m.allow_n >= WS_ALLOW_MAX) {
			if (asprintf(out, "ERROR: 白名单已达上限 %d 条",
				     WS_ALLOW_MAX) < 0)
				*out = NULL;
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		m.allow[m.allow_n++] = a;
		if (ws_net_setup(name, &m, 1, nerr, sizeof(nerr))) {
			m = old;
			if (asprintf(out, "ERROR: 规则下发失败：%s"
				     "（元数据未改动）", nerr) < 0)
				*out = NULL;
			rc = AI_ERR_GENERIC;
			goto done;
		}
	} else if (strcmp(act, "del") == 0) {
		if (!dst || !dst[0]) {
			if (asprintf(out, "ERROR: action=del 需要 dst") < 0)
				*out = NULL;
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		if (!ws_valid_dst(dst)) {
			if (asprintf(out, "ERROR: dst='%s' 非法", dst) < 0)
				*out = NULL;
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		for (i = 0; i < m.allow_n; i++) {
			if (strcmp(m.allow[i].dst, dst) != 0)
				continue;
			if (port >= 0 && m.allow[i].port != (int)port)
				continue;
			if (proto && proto[0] &&
			    strcmp(m.allow[i].proto, proto) != 0)
				continue;
			memmove(&m.allow[i], &m.allow[i + 1],
				sizeof(m.allow[0]) *
					(size_t)(m.allow_n - i - 1));
			m.allow_n--;
			removed++;
			i--;
		}
		if (!removed) {
			if (asprintf(out, "workspace_net_allow: %s 没有匹配的白名单"
				     "条目，未改动", name) < 0)
				*out = NULL;
			goto done;
		}
		if (ws_net_setup(name, &m, 1, nerr, sizeof(nerr))) {
			m = old;
			if (asprintf(out, "ERROR: 规则下发失败：%s"
				     "（元数据未改动）", nerr) < 0)
				*out = NULL;
			rc = AI_ERR_GENERIC;
			goto done;
		}
	} else {
		if (asprintf(out, "ERROR: 非法 action='%s'"
			     "（add|del|list|clear|rebuild）", act) < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}

	if (ws_meta_write(name, &m)) {
		if (asprintf(out, "ERROR: 规则已生效但元数据写入失败: %s",
			     strerror(errno)) < 0)
			*out = NULL;
		rc = AI_ERR_STORAGE;
		goto done;
	}
	{
		FILE *mem;
		size_t len = 0;
		char *buf = NULL;

		mem = open_memstream(&buf, &len);
		if (!mem) {
			*out = strdup("ERROR: open_memstream 失败");
			rc = AI_ERR_GENERIC;
			goto done;
		}
		fprintf(mem, "workspace_net_allow: %s action=%s 已下发"
			"（缺省拒出站不变；共 %d 条白名单）\n",
			name, act, m.allow_n);
		for (i = 0; i < m.allow_n; i++) {
			char al[128];

			ws_allow_fmt(&m.allow[i], al, sizeof(al));
			fprintf(mem, "  [%d] %s\n", i, al);
		}
		if (strcmp(act, "del") == 0)
			fprintf(mem, "  删除 %d 条\n", removed);
		fclose(mem);
		*out = buf;
	}
done:
	free(name);
	free(action);
	free(dst);
	free(proto);
	return rc;
}

/* 刷新 loop 容量（增长/回滚收缩都要） */static int ws_loop_set_capacity(const char *dev)
{
	int fd = open(dev, O_RDWR | O_CLOEXEC);
	int rc;

	if (fd < 0)
		return -1;
	rc = ioctl(fd, LOOP_SET_CAPACITY, 0);
	close(fd);
	return rc ? -1 : 0;
}

/* e2fsck -f -y：退出 0/1 都算可用（1 = 已修复），其他失败 */
static int ws_fsck_ok(const char *e2bin, const char *dev)
{
	char *argv[5];
	char *tail = NULL;
	int exit_code = -1, timed_out = 0, truncated = 0, rc;

	argv[0] = (char *)e2bin;
	argv[1] = (char *)"-f";
	argv[2] = (char *)"-y";
	argv[3] = (char *)dev;
	argv[4] = NULL;
	rc = ws_spawn_capture(argv, WS_SIMPLE_TIMEOUT, &tail, &exit_code,
			      &timed_out, &truncated);
	free(tail);
	if (rc || exit_code < 0 || exit_code > 1)
		return -1;
	return 0;
}

/*
 * 扩容失败回滚：truncate 回原大小 → LOOP_SET_CAPACITY 收缩 → e2fsck 复核。
 * 返回 0 = 回滚后文件系统可用；-1 = 回滚本身失败（note 写明原因）。
 */
static int ws_rollback_size(const char *image, long old_mb, const char *dev,
			    const char *e2bin, char *note, size_t notesz)
{
	int rc = 0;

	note[0] = '\0';
	if (truncate(image, (off_t)old_mb * 1024 * 1024)) {
		snprintf(note + strlen(note), notesz - strlen(note),
			 "truncate 回滚失败: %s；", strerror(errno));
		rc = -1;
	}
	if (dev && dev[0] && ws_loop_set_capacity(dev)) {
		snprintf(note + strlen(note), notesz - strlen(note),
			 "LOOP_SET_CAPACITY 回滚失败: %s；",
			 strerror(errno));
		rc = -1;
	}
	if (e2bin && e2bin[0] && dev && dev[0] && ws_fsck_ok(e2bin, dev)) {
		snprintf(note + strlen(note), notesz - strlen(note),
			 "回滚后 e2fsck 复核失败；");
		rc = -1;
	}
	return rc;
}

static int ws_cmd_quota(const char *args_json, char **out)
{
	char *name = ws_arg_str(args_json, "name");
	long long mb = ws_arg_ll(args_json, "mb", -1);
	struct ws_meta m;
	char dev[64];
	char r2bin[PATH_MAX] = "";
	char e2bin[PATH_MAX] = "";
	char rbnote[512];
	long old_mb;
	int i;

	if (!ai_ws_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法工作区名 name='%s'",
			     name ? name : "(无)") < 0)
			*out = NULL;
		free(name);
		return AI_ERR_INVALID_ARG;
	}
	if (ws_meta_read(name, &m)) {
		if (asprintf(out, "ERROR: 工作区 '%s' 不存在", name) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_NOT_FOUND;
	}
	old_mb = m.size_mb;
	if (mb < 0) {
		if (strcmp(m.backing, "tmpfs") == 0) {
			if (asprintf(out, "workspace_quota: %s backing=tmpfs"
				     "（容量由内存决定，无镜像可调）", name) < 0)
				*out = NULL;
		} else {
			if (asprintf(out, "workspace_quota: %s size=%ldMB "
				     "used=%ldMB image=%s", name, m.size_mb,
				     ws_used_mb(&m), m.image) < 0)
				*out = NULL;
		}
		free(name);
		return AI_OK;
	}
	if (!ai_ws_valid_size_mb(mb)) {
		if (asprintf(out, "ERROR: 非法 mb=%lld（允许 %d-%d）", mb,
			     WS_MIN_MB, WS_MAX_MB) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(m.backing, "tmpfs") == 0) {
		if (asprintf(out, "ERROR: tmpfs 工作区不支持 quota 调整"
			     "（容量由内存决定）") < 0)
			*out = NULL;
		free(name);
		return AI_ERR_INVALID_ARG;
	}
	if (mb < m.size_mb) {
		if (asprintf(out, "ERROR: v0 只支持扩容（当前 %ldMB，请求 "
			     "%lldMB；缩容需离线 resize2fs，未实现）",
			     m.size_mb, mb) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_INVALID_ARG;
	}
	if (mb == m.size_mb) {
		if (asprintf(out, "workspace_quota: %s 已是 %ldMB，无需调整",
			     name, m.size_mb) < 0)
			*out = NULL;
		free(name);
		return AI_OK;
	}
	if (ws_running(name)) {
		if (asprintf(out, "ERROR: 工作区 %s 正在运行，拒绝在线调整容量",
			     name) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_API;
	}
	if (!ws_image_under_root(m.image)) {
		if (asprintf(out, "ERROR: 元数据镜像路径非法: %s", m.image) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_STORAGE;
	}
	if (!ws_file_exists(m.image)) {
		if (asprintf(out, "ERROR: 镜像 %s 不存在", m.image) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_NOT_FOUND;
	}
	{
		static const char *const r2cand[] = {
			"/usr/sbin/resize2fs", "/sbin/resize2fs",
			"/usr/bin/resize2fs", NULL,
		};
		static const char *const e2cand[] = {
			"/usr/sbin/e2fsck", "/sbin/e2fsck",
			"/usr/bin/e2fsck", NULL,
		};
		const char *r2 = NULL, *e2 = NULL;
		const char *ov = getenv("AIKERNEL_WORKSPACE_RESIZE2FS");

		/* 测试/故障注入钩子：只影响 resize2fs 路径，默认不设 */
		if (ov && ov[0]) {
			if (access(ov, X_OK) == 0) {
				r2 = ov;
			} else {
				if (asprintf(out, "ERROR: "
					     "AIKERNEL_WORKSPACE_RESIZE2FS=%s "
					     "不可执行；镜像未改动", ov) < 0)
					*out = NULL;
				free(name);
				return AI_ERR_CONFIG;
			}
		}
		for (i = 0; !r2 && r2cand[i]; i++) {
			if (access(r2cand[i], X_OK) == 0) {
				r2 = r2cand[i];
				break;
			}
		}
		for (i = 0; e2cand[i]; i++) {
			if (access(e2cand[i], X_OK) == 0) {
				e2 = e2cand[i];
				break;
			}
		}
		if (!r2 || !e2) {
			if (asprintf(out, "ERROR: 找不到 %s"
				     "（e2fsprogs 未安装？）；镜像未改动",
				     !r2 ? "resize2fs" : "e2fsck") < 0)
				*out = NULL;
			free(name);
			return AI_ERR_NOT_FOUND;
		}
		snprintf(r2bin, sizeof(r2bin), "%s", r2);
		snprintf(e2bin, sizeof(e2bin), "%s", e2);
	}
	if (ws_loop_find(m.image, dev, sizeof(dev))) {
		if (asprintf(out, "ERROR: 未找到镜像 %s 的 loop 设备；请先 "
			     "workspace_run 或重新 create 后再调容量",
			     m.image) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_STORAGE;
	}
	/* 每次 run 结束后文件系统可能带 journal/dirty 标记（namespace 退出），
	 * resize2fs 要求先 e2fsck -f；离线执行（ws_running 已挡在线调整）。 */
	{
		char *eargv[5];
		char *tail = NULL;
		int exit_code = -1, timed_out, truncated;

		eargv[0] = e2bin;
		eargv[1] = (char *)"-f";
		eargv[2] = (char *)"-y";
		eargv[3] = dev;
		eargv[4] = NULL;
		if (ws_spawn_capture(eargv, WS_SIMPLE_TIMEOUT, &tail,
				     &exit_code, &timed_out, &truncated) ||
		    exit_code < 0 || exit_code > 1) {
			/* 校验失败发生在任何改动之前；truncate 到原大小是
			 * 幂等空操作，统一回滚口径。 */
			(void)ws_rollback_size(m.image, old_mb, dev, NULL,
					       rbnote, sizeof(rbnote));
			if (asprintf(out, "ERROR: e2fsck %s 失败（exit=%d；"
				     "0/1 视为已修复）；已回滚到原大小 %ldMB，"
				     "原状可用%s%s\n%s",
				     dev, exit_code, old_mb,
				     rbnote[0] ? "；回滚异常: " : "",
				     rbnote, tail ? tail : "") < 0)
				*out = NULL;
			free(tail);
			free(name);
			return AI_ERR_STORAGE;
		}
		free(tail);
	}
	if (truncate(m.image, (off_t)mb * 1024 * 1024)) {
		if (asprintf(out, "ERROR: 扩容镜像 %s 失败: %s；镜像未改动"
			     "（原大小 %ldMB，原状可用）", m.image,
			     strerror(errno), old_mb) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_STORAGE;
	}
	if (ws_loop_set_capacity(dev)) {
		(void)ws_rollback_size(m.image, old_mb, dev, e2bin, rbnote,
				       sizeof(rbnote));
		if (asprintf(out, "ERROR: 刷新 loop 容量失败: %s；已回滚到"
			     "原大小 %ldMB，原状可用%s%s", strerror(errno),
			     old_mb, rbnote[0] ? "；回滚异常: " : "",
			     rbnote) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_STORAGE;
	}
	{
		char *rargv[4];
		char *tail = NULL;
		int exit_code, timed_out, truncated;

		rargv[0] = r2bin;
		rargv[1] = dev;
		rargv[2] = NULL;
		if (ws_spawn_capture(rargv, WS_SIMPLE_TIMEOUT, &tail,
				     &exit_code, &timed_out, &truncated) ||
		    exit_code != 0) {
			int rb = ws_rollback_size(m.image, old_mb, dev, e2bin,
						  rbnote, sizeof(rbnote));

			if (asprintf(out, "ERROR: resize2fs %s 失败"
				     "（exit=%d）；已回滚到原大小 %ldMB，"
				     "原状可用%s%s%s\n%s",
				     dev, exit_code, old_mb,
				     rb ? "（注意：回滚未完全成功）" : "",
				     rbnote[0] ? "；回滚细节: " : "",
				     rbnote, tail ? tail : "") < 0)
				*out = NULL;
			free(tail);
			free(name);
			return AI_ERR_STORAGE;
		}
		free(tail);
	}
	m.size_mb = (long)mb;
	if (ws_meta_write(name, &m)) {
		if (asprintf(out, "ERROR: 扩容成功但元数据写入失败: %s",
			     strerror(errno)) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_STORAGE;
	}
	if (asprintf(out, "workspace_quota: %s 已扩容到 %lldMB（loop=%s）",
		     name, mb, dev) < 0)
		*out = NULL;
	free(name);
	return AI_OK;
}

/* ---- 执行器入口 ---- */

/*
 * W81c：应用画像复用入口（见 workspace_tools.h）。
 * ai_ws_ensure 只在工作区不存在时建 tmpfs 工作区（不覆盖既有状态）。
 */
/*
 * W82B（V6）：backing 可指定版本。compat 的适配器 workspace 必须是
 * disk（apply 落地的东西要跨 verify 那次调用持久），但生命周期与
 * workspace_create 完全同一条实现——这里只多传一个 backing 字段。
 */
int ai_ws_ensure_backing(const char *name, const char *backing,
			 long long size_mb, int net_none, char **out,
			 int *created)
{
	struct ws_meta m;
	char args[512];
	char *discard = NULL;
	char **o = out ? out : &discard;
	int rc;

	*o = NULL;
	if (created)
		*created = 0;
	if (!ai_ws_valid_name(name)) {
		if (asprintf(o, "ERROR: 非法工作区名 name='%s'",
			     name ? name : "(无)") < 0)
			*o = NULL;
		return AI_ERR_INVALID_ARG;
	}
	if (!backing || !backing[0])
		backing = "tmpfs";
	if (strcmp(backing, "disk") != 0 && strcmp(backing, "tmpfs") != 0) {
		if (asprintf(o, "ERROR: 非法 backing='%s'（disk|tmpfs）",
			     backing) < 0)
			*o = NULL;
		return AI_ERR_INVALID_ARG;
	}
	if (ws_meta_read(name, &m) == 0)
		return AI_OK;
	if (size_mb <= 0)
		size_mb = 64;
	if (size_mb < WS_MIN_MB)
		size_mb = WS_MIN_MB;
	snprintf(args, sizeof(args),
		 "{\"name\":\"%s\",\"backing\":\"%s\",\"size_mb\":%lld,"
		 "\"net\":\"%s\"}", name, backing, size_mb,
		 net_none ? "none" : "host");
	rc = ws_cmd_create(args, o);
	if (rc == AI_OK && created)
		*created = 1;
	free(discard);
	return rc;
}

int ai_ws_ensure(const char *name, int net_none, long long size_mb,
		 char **out, int *created)
{
	return ai_ws_ensure_backing(name, "tmpfs", size_mb, net_none, out,
				    created);
}

/* W82B：compat 组装 aik-sandbox argv 时需要的只读元数据视图 */
int ai_ws_info_get(const char *name, struct ai_ws_info *out)
{
	struct ws_meta m;

	if (!out)
		return -1;
	memset(out, 0, sizeof(*out));
	if (!ai_ws_valid_name(name) || ws_meta_read(name, &m))
		return -1;
	snprintf(out->backing, sizeof(out->backing), "%s", m.backing);
	snprintf(out->image, sizeof(out->image), "%s", m.image);
	out->cpus_x100 = m.cpus_x100;
	out->mem_mb = m.mem_mb;
	out->pids_max = m.pids_max;
	snprintf(out->net, sizeof(out->net), "%s",
		 ws_net_mode_str(m.net_mode));
	snprintf(out->net_ns, sizeof(out->net_ns), "%s", m.net_ns);
	return 0;
}

int ai_ws_meta_net(const char *name, int *net_none, char *backing,
		   size_t cap)
{
	struct ws_meta m;

	if (!ai_ws_valid_name(name) || ws_meta_read(name, &m) != 0)
		return -1;
	if (net_none)
		*net_none = m.net_mode != WS_NET_HOST;
	if (backing)
		snprintf(backing, cap, "%s", m.backing);
	return 0;
}

int ai_ws_destroy(const char *name, char **out)
{
	char args[128];
	char *discard = NULL;
	char **o = out ? out : &discard;
	int rc;

	*o = NULL;
	if (!ai_ws_valid_name(name)) {
		if (asprintf(o, "ERROR: 非法工作区名 name='%s'",
			     name ? name : "(无)") < 0)
			*o = NULL;
		return AI_ERR_INVALID_ARG;
	}
	snprintf(args, sizeof(args), "{\"name\":\"%s\"}", name);
	rc = ws_cmd_destroy(args, o);
	free(discard);
	return rc;
}

/* ======================================================================
 * W82e（V1.8）：sandbox 通道 = workspace 的一个 backend（backing=tmpfs）
 *
 * 这里只做「参数翻译 + 委托」：
 *   区名 → 工作区名（≤32 同名；33-64 映射短名 + alias）
 *   create → ws_cmd_create({backing:tmpfs, net:host})
 *   destroy → ws_destroy_impl（全仓唯一销毁路径）
 *   status → workspace 元数据区表 + aik-sandbox status 原文
 *   run → ws_build_run_argv（run 参数面唯一翻译）+ ai_ws_spawn_capture
 * 没有任何第二份生命周期/销毁/限额逻辑。
 * ====================================================================== */

/* 区名合法性：与 aik-sandbox 侧 valid_name 同规则（≤64，[A-Za-z0-9._-]，
 * 不以 . / - 开头，不含 ".."）。workspace 名更严（≤32），故需映射。 */
static int ws_zone_name_ok(const char *s)
{
	size_t i, n;

	if (!s || !s[0])
		return 0;
	n = strlen(s);
	if (n > 64 || s[0] == '.' || s[0] == '-')
		return 0;
	for (i = 0; i < n; i++) {
		char c = s[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		      c == '.'))
			return 0;
	}
	return !strstr(s, "..");
}

int ai_ws_zone_name(const char *zone, char *ws, size_t cap)
{
	char trunc[24];

	if (!ws || cap < 2)
		return 0;
	ws[0] = '\0';
	if (!ws_zone_name_ok(zone))
		return 0;
	/* ≤32：区名即工作区名（历史行为逐字保留，/sandbox 目录不变） */
	if (strlen(zone) <= WS_MAX_NAME) {
		snprintf(ws, cap, "%s", zone);
		return 1;
	}
	/* 33-64：确定性短名 "前 23 字符-<fnv32:08x>"（总长 32），
	 * 原区名记进元数据 alias；create/run/destroy 都经同一映射。 */
	snprintf(trunc, sizeof(trunc), "%.23s", zone);
	snprintf(ws, cap, "%s-%08x", trunc, ws_fnv32(zone));
	return 1;
}

int ai_ws_zone_create(const char *zone, char **out)
{
	char ws[WS_MAX_NAME + 1];
	char args[256];
	struct ws_meta m;
	int rc;

	*out = NULL;
	if (!ai_ws_zone_name(zone, ws, sizeof(ws))) {
		if (asprintf(out, "ERROR: 非法隔离区名 name='%s'（允许字母数字"
			     ".-_，≤64 字符，不以 . 或 - 开头）",
			     zone ? zone : "(无)") < 0)
			*out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	/* 同名持久盘绝不覆盖：sandbox_create 只建 tmpfs 后端 */
	if (ws_meta_read(ws, &m) == 0 && strcmp(m.backing, "tmpfs") != 0) {
		if (asprintf(out, "ERROR: 名字 '%s' 已被持久工作区占用"
			     "（backing=%s）；sandbox_create 不覆盖持久盘，"
			     "请换名或先 workspace_destroy",
			     zone, m.backing) < 0)
			*out = NULL;
		return AI_ERR_API;
	}
	/* 无元数据但留着实镜像：可能是元数据被外部删掉的持久盘。
	 * 不覆盖、不吞掉用户数据，直接拒绝（由人确认后再清）。 */
	if (ws_meta_read(ws, &m) != 0) {
		char img[PATH_MAX];

		ws_image_path(ws, img, sizeof(img));
		if (ws_file_exists(img)) {
			if (asprintf(out, "ERROR: 名字 '%s' 下存在无元数据的"
				     "镜像 %s；sandbox_create 不覆盖，请先人工"
				     "确认并清理", zone, img) < 0)
				*out = NULL;
			return AI_ERR_STORAGE;
		}
	}
	/* 与 W42 默认对齐：net=host（沙盒保留宿主网络） */
	snprintf(args, sizeof(args),
		 "{\"name\":\"%s\",\"backing\":\"tmpfs\",\"net\":\"host\"}",
		 ws);
	rc = ws_cmd_create(args, out);
	if (rc != AI_OK)
		return rc;
	/* 区名被映射成短名时补记 alias（status/inspect 展示用） */
	if (strcmp(ws, zone) != 0 && ws_meta_read(ws, &m) == 0) {
		snprintf(m.alias, sizeof(m.alias), "%s", zone);
		(void)ws_meta_write(ws, &m);
	}
	return AI_OK;
}

int ai_ws_zone_destroy(const char *zone, char **out)
{
	char ws[WS_MAX_NAME + 1];
	struct ws_meta m;
	char *tail = NULL;
	int rc;

	*out = NULL;
	if (!ai_ws_zone_name(zone, ws, sizeof(ws))) {
		if (asprintf(out, "ERROR: 非法隔离区名 name='%s'",
			     zone ? zone : "(无)") < 0)
			*out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	/* 持久数据保护：同名 backing=disk 的工作区不归 sandbox 管 */
	if (ws_meta_read(ws, &m) == 0 && strcmp(m.backing, "tmpfs") != 0) {
		if (asprintf(out, "ERROR: 名字 '%s' 是持久工作区"
			     "（backing=%s），sandbox_destroy 拒绝删除；"
			     "请用 workspace_destroy", zone, m.backing) < 0)
			*out = NULL;
		return AI_ERR_API;
	}
	rc = ws_destroy_impl(ws, out, &tail);
	if (rc == AI_OK)
		ws_append(out, tail);
	free(tail);
	/* V1.8 之前的 33-64 字符区直接以原名存在 /sandbox 下：升级后首次
	 * destroy 仍按原名交给同一个后端回收，避免“映射改名后老区清不掉”。 */
	if (strcmp(ws, zone) != 0) {
		char ldir[PATH_MAX];
		char *ltail = NULL;

		snprintf(ldir, sizeof(ldir), "%s/%s", ws_sb_base(), zone);
		if (ws_is_dir(ldir)) {
			ws_backend_destroy(zone, &ltail);
			if (rc == AI_OK)
				ws_append(out, ltail);
			free(ltail);
		}
	}
	return rc;
}

int ai_ws_zone_status(char **out)
{
	DIR *d = opendir(ws_root());
	struct dirent *e;
	char *buf = NULL;
	size_t len = 0;
	FILE *mem = open_memstream(&buf, &len);
	char *tail = NULL;
	int exit_code = -1, timed_out = 0, truncated = 0, count = 0;

	if (!mem) {
		*out = strdup("ERROR: open_memstream 失败");
		return AI_ERR_GENERIC;
	}
	fprintf(mem, "sandbox_status: 隔离区 = workspace tmpfs backend"
		"（元数据/销毁统一由 workspace 管理）\n");
	if (d) {
		while ((e = readdir(d))) {
			struct ws_meta m;
			char name[WS_MAX_NAME + 1];
			size_t nl = strlen(e->d_name);

			if (e->d_name[0] == '.' || nl <= 5 ||
			    strcmp(e->d_name + nl - 5, ".meta") != 0)
				continue;
			nl -= 5;
			if (nl == 0 || nl > WS_MAX_NAME)
				continue;
			memcpy(name, e->d_name, nl);
			name[nl] = '\0';
			if (!ai_ws_valid_name(name) || ws_meta_read(name, &m))
				continue;
			if (strcmp(m.backing, "tmpfs") != 0)
				continue;
			fprintf(mem, "  [%s] backing=tmpfs status=%s "
				"mount=%s/%s/root%s%s%s\n",
				m.alias[0] ? m.alias : m.name,
				ws_running(m.name) ? "running" : "ready",
				ws_sb_base(), m.name,
				m.alias[0] ? " (ws=" : "",
				m.alias[0] ? m.name : "",
				m.alias[0] ? ")" : "");
			count++;
		}
		closedir(d);
	}
	if (!count)
		fprintf(mem, "  (暂无 tmpfs 后端隔离区)\n");
	fprintf(mem, "--- aik-sandbox status ---\n");
	{
		char *sargv[3];

		sargv[0] = (char *)ws_sb_bin();
		sargv[1] = (char *)"status";
		sargv[2] = NULL;
		if (access(sargv[0], X_OK) == 0)
			(void)ws_spawn_capture(sargv, WS_SIMPLE_TIMEOUT, &tail,
					       &exit_code, &timed_out,
					       &truncated);
	}
	fprintf(mem, "%s%s", tail ? tail : "(后端不可用：未找到 aik-sandbox)\n",
		(tail && tail[0] && tail[strlen(tail) - 1] != '\n') ? "\n" : "");
	free(tail);
	fclose(mem);
	*out = buf;
	return AI_OK;
}

int ai_ws_zone_run(const char *zone, char *const argv[], int argc,
		   int timeout_s, size_t out_max, char *const extra_env[],
		   int extra_env_n, volatile sig_atomic_t *cancel_flag,
		   char **tail_out, int *exit_code, int *timed_out,
		   int *cancelled, int *truncated, char **err_out)
{
	char ws[WS_MAX_NAME + 1];
	struct ws_meta m;
	struct ws_run_buf b;
	char *sbargv[96];
	int have_meta;

	if (tail_out)
		*tail_out = NULL;
	if (exit_code)
		*exit_code = -1;
	if (timed_out)
		*timed_out = 0;
	if (cancelled)
		*cancelled = 0;
	if (truncated)
		*truncated = 0;
	if (err_out)
		*err_out = NULL;
	if (!ai_ws_zone_name(zone, ws, sizeof(ws))) {
		if (err_out && asprintf(err_out, "ERROR: 非法隔离区名 name='%s'",
				       zone ? zone : "(无)") < 0)
			*err_out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	if (!argv || argc < 1) {
		if (err_out && asprintf(err_out,
				       "ERROR: 缺少 argv（在隔离区内执行的命令）")
		    < 0)
			*err_out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	if (timeout_s < 1 || timeout_s > WS_RUN_TIMEOUT_MAX)
		timeout_s = WS_RUN_TIMEOUT_DEF;
	have_meta = ws_meta_read(ws, &m) == 0;
	/* 同名持久工作区不允许被 sandbox_spawn 当临时区跑 */
	if (have_meta && strcmp(m.backing, "disk") == 0) {
		if (err_out && asprintf(err_out, "ERROR: 名字 '%s' 是持久工作区"
				       "（backing=disk），sandbox_spawn 不在其"
				       "上派子智能体；请改用 workspace_run 或"
				       "换名", zone) < 0)
			*err_out = NULL;
		return AI_ERR_API;
	}
	if (have_meta) {
		if (ws_build_run_argv(ws, &m, argv, argc, sbargv, 96, &b)) {
			if (err_out && asprintf(err_out, "ERROR: argv 过多（%d）",
					       argc) < 0)
				*err_out = NULL;
			return AI_ERR_INVALID_ARG;
		}
	} else {
		/* 未 create 直接 run：与 aik-sandbox 的临时区语义一致，
		 * 不加任何限额/backing 参数（run 自己建临时区） */
		int sn = 0, i;

		if (4 + argc >= 96) {
			if (err_out && asprintf(err_out, "ERROR: argv 过多（%d）",
					       argc) < 0)
				*err_out = NULL;
			return AI_ERR_INVALID_ARG;
		}
		sbargv[sn++] = (char *)ws_sb_bin();
		sbargv[sn++] = (char *)"run";
		sbargv[sn++] = ws;
		sbargv[sn++] = (char *)"--";
		for (i = 0; i < argc; i++)
			sbargv[sn++] = argv[i];
		sbargv[sn] = NULL;
	}
	if (access(sbargv[0], X_OK)) {
		if (err_out && asprintf(err_out, "ERROR: 找不到 %s（%s）；隔离区"
				       "执行依赖 aik-sandbox", sbargv[0],
				       strerror(errno)) < 0)
			*err_out = NULL;
		return AI_ERR_NOT_FOUND;
	}
	if (ai_ws_spawn_capture(sbargv, extra_env, extra_env_n, timeout_s,
				out_max ? out_max : WS_OUT_MAX, cancel_flag,
				tail_out, exit_code, timed_out, cancelled,
				truncated)) {
		if (err_out)
			*err_out = strdup("ERROR: fork/pipe 失败（无法启动 "
					  "aik-sandbox）");
		return AI_ERR_GENERIC;
	}
	return AI_OK;
}

/*
 * W81d：白名单校验的导出入口（供单测；不触碰文件系统/网络）。
 * 返回 1=合法（dst 为 IPv4/IPv6 地址或 CIDR；port 0-65535，0=任意；
 * proto ∈ tcp|udp|icmp|any，省略时按 port 推导）。
 */
int ai_ws_valid_allow(const char *dst, int port, const char *proto)
{
	struct ws_allow a;
	char err[160];

	return ws_allow_check(dst, port, proto, &a, err, sizeof(err)) == 0;
}

/*
 * W81d：派生工作区网络命名（netns/表名/两侧 veth 名），供单测与运维
 * 对账；纯函数，不触碰系统。
 */
void ai_ws_net_names(const char *name, char *ns, size_t ns_cap,
		     char *tbl, size_t tbl_cap, char *host_if, size_t h_cap,
		     char *ws_if, size_t w_cap)
{
	ws_net_ns_name(name, ns, ns_cap);
	ws_nft_table_name(name, tbl, tbl_cap);
	ws_if_names(name, host_if, h_cap, ws_if, w_cap);
}

int exec_workspace_channel(const void *tool, const char *args_json,
			   char **out)
{
	const struct ai_tool *t = tool;

	*out = NULL;
	if (!t || !t->name) {
		*out = strdup("ERROR: workspace 通道缺少工具名（注册表异常）");
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(t->name, "workspace_create") == 0)
		return ws_cmd_create(args_json, out);
	if (strcmp(t->name, "workspace_list") == 0)
		return ws_cmd_list(out);
	if (strcmp(t->name, "workspace_inspect") == 0)
		return ws_cmd_inspect(args_json, out);
	if (strcmp(t->name, "workspace_run") == 0)
		return ws_cmd_run(args_json, out);
	if (strcmp(t->name, "workspace_destroy") == 0)
		return ws_cmd_destroy(args_json, out);
	if (strcmp(t->name, "workspace_quota") == 0)
		return ws_cmd_quota(args_json, out);
	if (strcmp(t->name, "workspace_net_allow") == 0)
		return ws_cmd_net_allow(args_json, out);
	if (strcmp(t->name, "workspace_net_status") == 0)
		return ws_cmd_net_status(args_json, out);
	if (asprintf(out, "ERROR: 未知 workspace 工具 %s", t->name) < 0)
		*out = NULL;
	return AI_ERR_INVALID_ARG;
}
