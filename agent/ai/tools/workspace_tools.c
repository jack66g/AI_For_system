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
 */
#define _GNU_SOURCE
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
#include "workspace_tools.h"

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
	int net_none;
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
		    m->net_none ? "none" : "host") < 0)
		goto out;
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
	m->net_none = 1;
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
		else if (strcmp(line, "cpus") == 0)
			m->cpus_x100 = (int)(strtod(v, NULL) * 100.0 + 0.5);
		else if (strcmp(line, "mem_mb") == 0)
			m->mem_mb = strtol(v, NULL, 10);
		else if (strcmp(line, "pids_max") == 0)
			m->pids_max = strtol(v, NULL, 10);
		else if (strcmp(line, "net") == 0)
			m->net_none = strcmp(v, "none") == 0;
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
 * fork + exec argv，采集 stdout/stderr 合流（尾部 ≤out_max 字节）。
 * 超时/取消 SIGKILL 整个进程组；返回 0=已执行（exit_code 有效）。
 */
static int ws_spawn_capture(char **argv, int timeout_sec, char **out,
			    int *exit_code, int *timed_out, int *truncated)
{
	int pipefd[2];
	pid_t pid;
	int st = 0, i;
	char *ring;
	size_t ring_off = 0, ring_fill = 0;
	long long deadline_ms;
	ssize_t n;

	*out = NULL;
	*exit_code = -1;
	*timed_out = 0;
	*truncated = 0;
	ring = malloc(WS_OUT_MAX);
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
		execv(argv[0], argv);
		fprintf(stderr, "ERROR: exec %s: %s\n", argv[0],
			strerror(errno));
		_exit(127);
	}
	close(pipefd[1]);
	fcntl(pipefd[0], F_SETFL,
	      fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
	deadline_ms = (long long)time(NULL) * 1000 +
		      (long long)timeout_sec * 1000;
	for (;;) {
		struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
		char chunk[4096];
		long long now_ms = (long long)time(NULL) * 1000;

		if (now_ms >= deadline_ms) {
			kill(-(pid_t)pid, SIGKILL);
			kill((pid_t)pid, SIGKILL);
			*timed_out = 1;
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0)
				;
			break;
		}
		if (poll(&pfd, 1, 200) > 0 &&
		    (pfd.revents & (POLLIN | POLLHUP))) {
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0) {
				for (i = 0; i < (int)n; i++) {
					if (ring_fill >= WS_OUT_MAX)
						*truncated = 1;
					ring[ring_off] = chunk[i];
					ring_off = (ring_off + 1) % WS_OUT_MAX;
					if (ring_fill < WS_OUT_MAX)
						ring_fill++;
				}
			}
		}
		if (pfd.revents & POLLHUP) {
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			break;
		}
		waitpid(pid, &st, WNOHANG);
	}
	close(pipefd[0]);
	{
		size_t start = (ring_fill < WS_OUT_MAX) ? 0 : ring_off;

		*out = malloc(ring_fill + 1);
		if (!*out) {
			free(ring);
			return -1;
		}
		for (i = 0; (size_t)i < ring_fill; i++)
			(*out)[i] = ring[(start + (size_t)i) % WS_OUT_MAX];
		(*out)[ring_fill] = '\0';
	}
	free(ring);
	if (WIFEXITED(st))
		*exit_code = WEXITSTATUS(st);
	else if (WIFSIGNALED(st))
		*exit_code = 128 + WTERMSIG(st);
	return 0;
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
	char *argv[64];
	char *tail = NULL;
	int ro_n, rw_n, argc = 0, i, exit_code, timed_out, truncated;
	int disk, existed_before = 0;
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
	if (net && strcmp(net, "host") == 0)
		argv[argc++] = (char *)"--net=host";
	else if (net && strcmp(net, "veth") == 0)
		argv[argc++] = (char *)"--net=none";
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
	m.net_none = !(net && strcmp(net, "host") == 0);
	m.ro_n = ro_n;
	m.rw_n = rw_n;
	for (i = 0; i < ro_n; i++)
		snprintf(m.ro[i], PATH_MAX, "%s", ro[i]);
	for (i = 0; i < rw_n; i++)
		snprintf(m.rw[i], PATH_MAX, "%s", rw[i]);
	if (disk) {
		struct stat st;

		if (!stat(image, &st))
			m.size_mb = (long)((st.st_size + 1024 * 1024 - 1) /
					   (1024 * 1024));
	}
	ws_sandbox_meta(name, loop, sizeof(loop));
	if (loop[0])
		snprintf(m.loop, sizeof(m.loop), "%s", loop);
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
		     "%s%s",
		     name, m.backing, m.size_mb,
		     m.image[0] ? m.image : "-",
		     m.loop[0] ? m.loop : "(无)",
		     ws_sb_base(), name, cgdir,
		     m.cpus_x100 / 100.0, m.mem_mb, m.pids_max,
		     m.net_none ? "none" : "host",
		     m.label[0] ? m.label : "-", m.ro_n, m.rw_n,
		     tail ? tail : "",
		     (net && strcmp(net, "veth") == 0) ?
		     "NOTE: net=veth 未实现，已按 net=none 执行\n" : "") < 0)
		*out = NULL;
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
	char cgdir[PATH_MAX];
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
		     "  rw_paths:  %d\n",
		     m.name, m.backing,
		     m.image[0] ? m.image : "-",
		     !m.image[0] ? "tmpfs（无镜像，数据不持久）" :
		     ws_file_exists(m.image) ? "exists" : "MISSING",
		     curloop[0] ? curloop :
		     (m.loop[0] ? m.loop : "(未接 loop)"),
		     m.size_mb, ws_used_mb(&m),
		     ws_sb_base(), name, cgdir,
		     m.cpus_x100 / 100.0, m.mem_mb, m.pids_max,
		     m.net_none ? "none" : "host",
		     m.label[0] ? m.label : "-",
		     ws_running(name) ? "running" : "ready",
		     m.ro_n, m.rw_n) < 0)
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
		fclose(mem);
		free(*out);
		*out = buf;
	}
	free(name);
	return AI_OK;
}

static int ws_cmd_run(const char *args_json, char **out)
{
	char *name = ws_arg_str(args_json, "name");
	char *command = ws_arg_str(args_json, "command");
	long long timeout_s = ws_arg_ll(args_json, "timeout_s",
					WS_RUN_TIMEOUT_DEF);
	struct ws_meta m;
	char imagearg[PATH_MAX + 16], cpuarg[64], memarg[64], pidarg[64];
	char roargs[WS_MAX_PATHS][PATH_MAX + 16];
	char rwargs[WS_MAX_PATHS][PATH_MAX + 16];
	char *argv[96];
	char *tail = NULL;
	int argc = 0, i, exit_code, timed_out, truncated;

	if (!ai_ws_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法工作区名 name='%s'",
			     name ? name : "(无)") < 0)
			*out = NULL;
		free(name);
		free(command);
		return AI_ERR_INVALID_ARG;
	}
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
	if (ws_meta_read(name, &m)) {
		if (asprintf(out, "ERROR: 工作区 '%s' 不存在（先 "
			     "workspace_create）", name) < 0)
			*out = NULL;
		free(name);
		free(command);
		return AI_ERR_NOT_FOUND;
	}
	if (strcmp(m.backing, "disk") == 0 &&
	    !ws_image_under_root(m.image)) {
		if (asprintf(out, "ERROR: 工作区 '%s' 的元数据镜像路径非法: %s",
			     name, m.image) < 0)
			*out = NULL;
		free(name);
		free(command);
		return AI_ERR_STORAGE;
	}
	if (strcmp(m.backing, "disk") == 0 && !ws_file_exists(m.image)) {
		if (asprintf(out, "ERROR: 工作区 '%s' 的镜像 %s 不存在"
			     "（元数据损坏或镜像被外部删除）", name, m.image) < 0)
			*out = NULL;
		free(name);
		free(command);
		return AI_ERR_NOT_FOUND;
	}

	argv[argc++] = (char *)ws_sb_bin();
	argv[argc++] = (char *)"run";
	argv[argc++] = name;
	if (strcmp(m.backing, "disk") == 0) {
		snprintf(imagearg, sizeof(imagearg), "--backing=disk:%s",
			 m.image);
		argv[argc++] = imagearg;
	} else {
		argv[argc++] = (char *)"--backing=tmpfs";
	}
	snprintf(cpuarg, sizeof(cpuarg), "--cpus=%.2f",
		 m.cpus_x100 / 100.0);
	argv[argc++] = cpuarg;
	snprintf(memarg, sizeof(memarg), "--mem-mb=%ld", m.mem_mb);
	argv[argc++] = memarg;
	snprintf(pidarg, sizeof(pidarg), "--pids=%ld", m.pids_max);
	argv[argc++] = pidarg;
	argv[argc++] = (char *)(m.net_none ? "--net=none" : "--net=host");
	for (i = 0; i < m.ro_n; i++) {
		snprintf(roargs[i], sizeof(roargs[i]), "--ro-path=%s", m.ro[i]);
		argv[argc++] = roargs[i];
	}
	for (i = 0; i < m.rw_n; i++) {
		snprintf(rwargs[i], sizeof(rwargs[i]), "--rw-path=%s", m.rw[i]);
		argv[argc++] = rwargs[i];
	}
	argv[argc++] = (char *)"--";
	argv[argc++] = (char *)"/bin/sh";
	argv[argc++] = (char *)"-c";
	argv[argc++] = command;
	argv[argc] = NULL;

	if (access(argv[0], X_OK)) {
		if (asprintf(out, "ERROR: 找不到 %s（%s）；工作区执行依赖 "
			     "aik-sandbox", argv[0], strerror(errno)) < 0)
			*out = NULL;
		free(name);
		free(command);
		return AI_ERR_NOT_FOUND;
	}
	if (ws_spawn_capture(argv, (int)timeout_s, &tail, &exit_code,
			     &timed_out, &truncated)) {
		*out = strdup("ERROR: fork/pipe 失败（无法启动 aik-sandbox）");
		free(name);
		free(command);
		return AI_ERR_GENERIC;
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

static int ws_cmd_destroy(const char *args_json, char **out)
{
	char *name = ws_arg_str(args_json, "name");
	struct ws_meta m;
	char sdir[PATH_MAX], cgdir[PATH_MAX], meta[PATH_MAX], image[PATH_MAX];
	int have_meta, had_state;

	if (!ai_ws_valid_name(name)) {
		if (asprintf(out, "ERROR: 非法工作区名 name='%s'",
			     name ? name : "(无)") < 0)
			*out = NULL;
		free(name);
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

	if (ws_is_dir(sdir) || ws_is_dir(cgdir)) {
		char *dargv[4];
		char *tail = NULL;
		int exit_code, timed_out, truncated;

		dargv[0] = (char *)ws_sb_bin();
		dargv[1] = (char *)"destroy";
		dargv[2] = name;
		dargv[3] = NULL;
		if (access(dargv[0], X_OK) == 0) {
			(void)ws_spawn_capture(dargv, WS_SIMPLE_TIMEOUT, &tail,
					       &exit_code, &timed_out,
					       &truncated);
		}
		free(tail);
	}

	if (ws_running(name)) {
		if (asprintf(out, "ERROR: 工作区 %s 仍被执行进程占用（锁忙），"
			     "已拒绝删除镜像；请稍后重试 destroy", name) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_API;
	}
	/* 元数据镜像路径只允许在工作区根下 */
	if (have_meta && m.image[0] && !ws_image_under_root(m.image)) {
		if (asprintf(out, "ERROR: 元数据镜像路径非法，拒绝删除: %s",
			     m.image) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_STORAGE;
	}

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
		free(name);
		return AI_ERR_STORAGE;
	}
	if (!have_meta && unlink(image) && errno != ENOENT) {
		if (asprintf(out, "ERROR: 删除镜像 %s 失败: %s", image,
			     strerror(errno)) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_STORAGE;
	}
	if (unlink(meta) && errno != ENOENT) {
		if (asprintf(out, "ERROR: 删除元数据 %s 失败: %s", meta,
			     strerror(errno)) < 0)
			*out = NULL;
		free(name);
		return AI_ERR_STORAGE;
	}

	if (had_state) {
		if (asprintf(out, "workspace_destroy: %s 已清理（进程/"
			     "cgroup/挂载/loop/镜像/元数据）", name) < 0)
			*out = NULL;
	} else {
		if (asprintf(out, "workspace_destroy: %s 无残留（本就干净，"
			     "幂等成功）", name) < 0)
			*out = NULL;
	}
	free(name);
	return AI_OK;
}

/* 刷新 loop 容量（增长/回滚收缩都要） */
static int ws_loop_set_capacity(const char *dev)
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
	if (asprintf(out, "ERROR: 未知 workspace 工具 %s", t->name) < 0)
		*out = NULL;
	return AI_ERR_INVALID_ARG;
}
