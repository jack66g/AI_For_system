// SPDX-License-Identifier: GPL-2.0
/*
 * offline_intent.c - W77 离线意图层
 *
 * 设计约束（W75 §10 输入）：
 *   - 不把 raw `cat` 当世界模型：所有答案先转成字段/数字/列表，
 *     并带 source + cache_age；文件只给元数据/行数，不输出正文；
 *   - 只读 D0：本文件没有写系统状态的路径；
 *   - 不依赖模型：断网、DNS 失败、云端 5xx 时仍可回答核心运维查询；
 *   - 可测试：AIKERNEL_OFFLINE_ROOT 把 /proc、/etc、/sandbox 等
 *     映射到临时根；AIKERNEL_OFFLINE_NO_EXEC=1 禁用 systemctl/dmesg
 *     子进程（测试环境无 systemd 时仍返回结构化“不可用”）。
 *
 * 支持的意图（匹配顺序见 match_intent）：
 *   plan, route, config, lease, memory_query, sandbox, service, services,
 *   logs, file, disk, memory, load, network, kernel, uptime, status
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/file.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "offline_intent.h"
#include "ai_config.h"
#include "ai_runtime.h"
#include "memory/sme_client.h"

#define OI_MAX_TEXT   (32 * 1024)
#define OI_MAX_JSON   (32 * 1024)
#define OI_MAX_FILE   (256 * 1024)

/* ---- 动态字符串缓冲 ---- */

struct sbuf {
	char *s;
	size_t len;
	size_t cap;
};

static void sb_init(struct sbuf *b, size_t cap)
{
	b->s = malloc(cap);
	b->len = 0;
	b->cap = b->s ? cap : 0;
	if (b->s)
		b->s[0] = '\0';
}

static void sb_printf(struct sbuf *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!b->s || b->cap == 0)
		return;
	va_start(ap, fmt);
	n = vsnprintf(b->s + b->len, b->cap - b->len, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n >= b->cap - b->len) {
		b->len = b->cap - 1;
		return;
	}
	b->len += (size_t)n;
}

static char *sb_take(struct sbuf *b)
{
	char *s = b->s;

	b->s = NULL;
	b->len = b->cap = 0;
	return s;
}

/* ---- 通用工具 ---- */

static long long oi_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static long long oi_wall_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static const char *oi_root(void)
{
	const char *r = getenv("AIKERNEL_OFFLINE_ROOT");

	return (r && r[0]) ? r : "";
}

static void oi_path(const char *path, char *out, size_t n)
{
	const char *r = oi_root();
	size_t rl = strlen(r);

	/* 测试根映射：绝对路径加根前缀；已经位于根内则不重复加
	 * （沙箱/租约目录由 env 直接给出时常见）。 */
	if (rl && path[0] == '/' && strncmp(path, r, rl) != 0)
		snprintf(out, n, "%s%s", r, path);
	else
		snprintf(out, n, "%s", path);
}

static long long oi_file_age_ms(const char *path)
{
	struct stat st;
	char full[1024];
	long long now = oi_wall_ms();

	oi_path(path, full, sizeof(full));
	if (stat(full, &st) != 0)
		return -1;
	if (st.st_mtime <= 0)
		return 0;
	return now - (long long)st.st_mtime * 1000LL;
}

static char *oi_read_file(const char *path, size_t max)
{
	char full[1024];
	FILE *fp;
	char *buf;
	size_t n = 0;
	int c;

	oi_path(path, full, sizeof(full));
	fp = fopen(full, "r");
	if (!fp)
		return NULL;
	buf = malloc(max + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	while (n < max && (c = fgetc(fp)) != EOF)
		buf[n++] = (char)c;
	buf[n] = '\0';
	fclose(fp);
	return buf;
}

static int oi_has(const char *hay, const char *needle)
{
	return hay && needle && strcasestr(hay, needle) != NULL;
}

/* 命令输出：2s 上限（timeout 命令存在时）；NO_EXEC 直接不可用 */
static char *oi_run_cmd(const char *cmd)
{
	const char *noexec = getenv("AIKERNEL_OFFLINE_NO_EXEC");
	char full[2048];
	FILE *fp;
	char *buf;
	size_t n = 0;
	int c;

	if (noexec && (strcmp(noexec, "1") == 0 ||
		       strcasecmp(noexec, "true") == 0))
		return NULL;
	snprintf(full, sizeof(full), "timeout 2 %s 2>/dev/null", cmd);
	fp = popen(full, "r");
	if (!fp)
		return NULL;
	buf = malloc(8192);
	if (!buf) {
		pclose(fp);
		return NULL;
	}
	while (n < 8191 && (c = fgetc(fp)) != EOF)
		buf[n++] = (char)c;
	buf[n] = '\0';
	(void)pclose(fp);
	return buf;
}

static void oi_json_escape(struct sbuf *b, const char *s)
{
	if (!s)
		return;
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		switch (c) {
		case '"':  sb_printf(b, "\\\""); break;
		case '\\': sb_printf(b, "\\\\"); break;
		case '\n': sb_printf(b, "\\n"); break;
		case '\r': sb_printf(b, "\\r"); break;
		case '\t': sb_printf(b, "\\t"); break;
		default:
			if (c < 0x20)
				sb_printf(b, " ");
			else
				sb_printf(b, "%c", c);
		}
	}
}

static void oi_trim_line(char *s)
{
	size_t n;

	if (!s)
		return;
	n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
			 s[n - 1] == ' ' || s[n - 1] == '\t'))
		s[--n] = '\0';
}

/* ---- /proc 解析 ---- */

static long long oi_meminfo_kb(const char *meminfo, const char *key)
{
	const char *p = meminfo;
	size_t kl = strlen(key);

	while (p && *p) {
		if (strncmp(p, key, kl) == 0 && p[kl] == ':')
			return strtoll(p + kl + 1, NULL, 10);
		p = strchr(p, '\n');
		if (p)
			p++;
	}
	return -1;
}

static int oi_cpu_count(void)
{
	long n = sysconf(_SC_NPROCESSORS_ONLN);

	return n > 0 ? (int)n : 0;
}

struct oi_proc {
	int pid;
	unsigned long long rss_kb;
	char name[64];
};

static int oi_proc_cmp(const void *a, const void *b)
{
	const struct oi_proc *x = a;
	const struct oi_proc *y = b;

	if (x->rss_kb < y->rss_kb)
		return 1;
	if (x->rss_kb > y->rss_kb)
		return -1;
	return 0;
}

static int oi_top_procs(struct oi_proc *out, int cap)
{
	char root[1024];
	DIR *d;
	struct dirent *de;
	struct oi_proc *all;
	int n = 0;
	int i;

	if (!out || cap <= 0)
		return 0;
	all = calloc(4096, sizeof(*all));
	if (!all)
		return 0;

	oi_path("/proc", root, sizeof(root));
	d = opendir(root);
	if (!d) {
		free(all);
		return 0;
	}
	while ((de = readdir(d)) != NULL && n < 4096) {
		char path[1200];
		char *buf;
		char *namep, *rssp;
		int pid;
		char *end = NULL;

		pid = (int)strtol(de->d_name, &end, 10);
		if (!end || *end || pid <= 0)
			continue;
		snprintf(path, sizeof(path), "/proc/%s/status", de->d_name);
		buf = oi_read_file(path, 8192);
		if (!buf)
			continue;
		namep = strstr(buf, "Name:");
		rssp = strstr(buf, "VmRSS:");
		if (rssp) {
			struct oi_proc *p = &all[n];

			p->pid = pid;
			p->rss_kb = strtoull(rssp + 6, NULL, 10);
			if (namep) {
				char *nl;

				namep += 5;
				while (*namep == ' ' || *namep == '\t')
					namep++;
				snprintf(p->name, sizeof(p->name), "%s", namep);
				nl = strchr(p->name, '\n');
				if (nl)
					*nl = '\0';
			} else {
				snprintf(p->name, sizeof(p->name), "pid-%d", pid);
			}
			n++;
		}
		free(buf);
	}
	closedir(d);
	qsort(all, (size_t)n, sizeof(all[0]), oi_proc_cmp);
	if (n > cap)
		n = cap;
	for (i = 0; i < n; i++)
		out[i] = all[i];
	free(all);
	return n;
}

/* ---- 各意图数据 ---- */

static int oi_disk_rows(struct sbuf *txt, struct sbuf *js)
{
	static const char *const paths[] = { "/", "/home", "/var", "/tmp" };
	int i;
	int first = 1;
	int any = 0;

	sb_printf(txt, "filesystems:\n");
	sb_printf(js, "[");
	for (i = 0; i < (int)(sizeof(paths) / sizeof(paths[0])); i++) {
		struct statvfs vfs;
		unsigned long long total, freeb, used;
		int pct;
		char full[1024];

		oi_path(paths[i], full, sizeof(full));
		if (statvfs(full, &vfs) != 0)
			continue;
		total = (unsigned long long)vfs.f_blocks * vfs.f_frsize;
		freeb = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
		used = total > freeb ? total - freeb : 0;
		pct = total ? (int)(used * 100 / total) : 0;
		sb_printf(txt,
			  "  %-6s total_mb=%llu free_mb=%llu used_pct=%d\n",
			  paths[i], total / (1024 * 1024),
			  freeb / (1024 * 1024), pct);
		if (!first)
			sb_printf(js, ",");
		sb_printf(js,
			  "{\"mount\":\"%s\",\"total_mb\":%llu,"
			  "\"free_mb\":%llu,\"used_pct\":%d}",
			  paths[i], total / (1024 * 1024),
			  freeb / (1024 * 1024), pct);
		first = 0;
		any = 1;
	}
	if (!any) {
		sb_printf(txt, "  (statvfs unavailable)\n");
	}
	sb_printf(js, "]");
	return 0;
}

static int oi_net(struct sbuf *txt, struct sbuf *js)
{
	struct ifaddrs *ifa = NULL, *p;
	struct sbuf ips;
	int first = 1;
	char *route = oi_read_file("/proc/net/route", 8192);
	char *resolv = oi_read_file("/etc/resolv.conf", 8192);

	sb_init(&ips, 4096);
	if (getifaddrs(&ifa) == 0) {
		for (p = ifa; p; p = p->ifa_next) {
			char addr[INET6_ADDRSTRLEN] = "-";
			int fam;
			void *src;

			if (!p->ifa_addr)
				continue;
			fam = p->ifa_addr->sa_family;
			if (fam == AF_INET)
				src = &((struct sockaddr_in *)p->ifa_addr)->sin_addr;
			else if (fam == AF_INET6)
				src = &((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
			else
				continue;
			if (!inet_ntop(fam, src, addr, sizeof(addr)))
				continue;
			if (!first)
				sb_printf(&ips, ",");
			sb_printf(&ips,
				  "{\"if\":\"%s\",\"family\":\"%s\","
				  "\"addr\":\"%s\"}",
				  p->ifa_name, fam == AF_INET ? "ipv4" : "ipv6",
				  addr);
			first = 0;
		}
		freeifaddrs(ifa);
	}
	sb_printf(txt, "interfaces:\n");
	if (ips.s && ips.len > 0) {
		/* 文本视图：拆 JSON 数组为每接口一行 */
		char *save = NULL;
		char *tok = strtok_r(ips.s, "{}", &save);

		while (tok) {
			if (strstr(tok, "\"if\""))
				sb_printf(txt, "  {%s}\n", tok);
			tok = strtok_r(NULL, "{}", &save);
		}
	}
	{
		int first_gw = 1;

		sb_printf(txt, "default_routes: ");
		if (route) {
			char *line = route;
			char *nl;

			while ((nl = strchr(line, '\n')) != NULL) {
				*nl = '\0';
				{
					unsigned int dest, gw, mask;
					char ifname[64];

					if (sscanf(line, "%63s %x %x %*x %*x %*x %*x %x",
						   ifname, &dest, &gw, &mask) == 4 &&
					    dest == 0) {
						struct in_addr a;

						a.s_addr = gw;
						sb_printf(txt, "%s%s dev %s",
							  first_gw ? "" : ",",
							  inet_ntoa(a),
							  ifname);
						first_gw = 0;
					}
				}
				line = nl + 1;
			}
		}
		if (first_gw)
			sb_printf(txt, "(none)");
		sb_printf(txt, "\n");
	}
	sb_printf(txt, "dns: ");
	if (resolv) {
		char *line = resolv;
		int first_dns = 1;

		while (*line) {
			char *nl = strchr(line, '\n');

			if (nl)
				*nl = '\0';
			if (strncmp(line, "nameserver", 10) == 0) {
				sb_printf(txt, "%s%s",
					  first_dns ? "" : ",", line + 10);
				first_dns = 0;
			}
			if (!nl)
				break;
			line = nl + 1;
		}
		if (first_dns)
			sb_printf(txt, "(none)");
	} else {
		sb_printf(txt, "(unavailable)");
	}
	sb_printf(txt, "\n");

	sb_printf(js, "\"interfaces\":[%s],\"route_raw_available\":%s,"
		  "\"resolv_available\":%s",
		  ips.s ? ips.s : "", route ? "true" : "false",
		  resolv ? "true" : "false");
	free(route);
	free(resolv);
	free(ips.s);
	return 0;
}

static int oi_sandbox(struct sbuf *txt, struct sbuf *js, long long *age)
{
	char base[1024], root[1024];
	DIR *d;
	struct dirent *de;
	int count = 0, first = 1;
	long long newest = -1;

	snprintf(base, sizeof(base), "%s",
		 getenv("AIKERNEL_SANDBOX_BASE") ?
		 getenv("AIKERNEL_SANDBOX_BASE") : "/sandbox");
	oi_path(base, root, sizeof(root));
	d = opendir(root);
	sb_printf(js, "{\"base\":\"%s\",\"sandboxes\":[", base);
	if (!d) {
		sb_printf(txt, "sandbox base %s: unavailable (no directory)\n",
			  base);
		sb_printf(js, "],\"available\":false}");
		*age = 0;
		return 0;
	}
	sb_printf(txt, "sandbox base %s:\n", base);
	while ((de = readdir(d)) != NULL) {
		char meta[1300];
		struct stat st;

		if (de->d_name[0] == '.')
			continue;
		snprintf(meta, sizeof(meta), "%s/%s/meta", root, de->d_name);
		if (stat(meta, &st) != 0)
			continue;
		if (!first)
			sb_printf(js, ",");
		sb_printf(js,
			  "{\"name\":\"%s\",\"meta_mtime\":%lld,"
			  "\"meta_bytes\":%lld}",
			  de->d_name, (long long)st.st_mtime,
			  (long long)st.st_size);
		sb_printf(txt, "  %s meta_mtime=%lld meta_bytes=%lld\n",
			  de->d_name, (long long)st.st_mtime,
			  (long long)st.st_size);
		if (newest < 0 || (long long)st.st_mtime > newest)
			newest = (long long)st.st_mtime;
		first = 0;
		count++;
	}
	closedir(d);
	if (count == 0)
		sb_printf(txt, "  (none)\n");
	sb_printf(js, "],\"available\":true,\"count\":%d}", count);
	*age = newest > 0 ? oi_wall_ms() - newest * 1000LL : 0;
	return 0;
}

static int oi_lease(struct sbuf *txt, struct sbuf *js, long long *age)
{
	const char *env_id = getenv("AIKERNEL_LEASE");
	const char *dir_env = getenv("AIKERNEL_LEASE_DIR");
	char dir[1024], root[1024];
	DIR *d;
	struct dirent *de;
	int count = 0;
	long long newest = -1;

	snprintf(dir, sizeof(dir), "%s",
		 (dir_env && dir_env[0]) ? dir_env : "/var/lib/aikernel/leases");
	oi_path(dir, root, sizeof(root));
	d = opendir(root);
	if (d) {
		while ((de = readdir(d)) != NULL) {
			char full[1300];
			struct stat st;

			if (strstr(de->d_name, ".json") == NULL)
				continue;
			snprintf(full, sizeof(full), "%s/%s", root, de->d_name);
			if (stat(full, &st) != 0)
				continue;
			count++;
			if (newest < 0 || (long long)st.st_mtime > newest)
				newest = (long long)st.st_mtime;
		}
		closedir(d);
	}
	sb_printf(txt,
		  "lease_env=%s lease_dir=%s stored_leases=%d "
		  "policy=D2+ still requires lease/confirmation (offline does not bypass)\n",
		  (env_id && env_id[0]) ? env_id : "(none)", dir, count);
	sb_printf(js,
		  "{\"env_id\":\"%s\",\"dir\":\"%s\",\"stored\":%d,"
		  "\"d2_plus_requires_lease\":true}",
		  (env_id && env_id[0]) ? env_id : "", dir, count);
	*age = newest > 0 ? oi_wall_ms() - newest * 1000LL : 0;
	return 0;
}

static int oi_plans(struct sbuf *txt, struct sbuf *js, long long *age)
{
	char *plans = ai_offline_last_plans(age);
	char *line;

	sb_printf(txt, "recent_plans:\n");
	sb_printf(js, "{\"plans\":[");
	if (!plans) {
		sb_printf(txt, "  (none cached; run ask once to populate)\n");
		sb_printf(js, "],\"available\":false}");
		*age = 0;
		return 0;
	}
	line = plans;
	{
		int first = 1;

		while (line && *line) {
			char *nl = strchr(line, '\n');

			if (nl)
				*nl = '\0';
			if (line[0]) {
				sb_printf(txt, "  %s\n", line);
				if (!first)
					sb_printf(js, ",");
				sb_printf(js, "%s", line);
				first = 0;
			}
			if (!nl)
				break;
			line = nl + 1;
		}
	}
	sb_printf(js, "],\"available\":true}");
	free(plans);
	return 0;
}

static int oi_route(struct sbuf *txt, struct sbuf *js,
		    const struct ai_config *cfg, long long *age)
{
	char status[1024];
	char *last = NULL;
	FILE *fp;
	char line[2048];
	char tpath[1024];
	const char *env = getenv("AIKERNEL_TRACE_DIR");
	const char *home = getenv("HOME");

	ai_route_status_text(cfg, NULL, status, sizeof(status));
	if (env && env[0]) {
		snprintf(tpath, sizeof(tpath), "%s/route.jsonl", env);
	} else {
		/* 与 ai_route.c 同默认：~/.aikernel/trace/route.jsonl */
		snprintf(tpath, sizeof(tpath), "%s/.aikernel/trace/route.jsonl",
			 (home && home[0]) ? home : "/tmp");
	}
	fp = fopen(tpath, "r");
	if (fp) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, "\"route_decision\"") ||
			    strstr(line, "\"route_switch\"") ||
			    strstr(line, "\"route_offline\"")) {
				free(last);
				last = strdup(line);
			}
		}
		fclose(fp);
		*age = oi_file_age_ms(tpath);
	} else {
		*age = 0;
	}
	if (last)
		oi_trim_line(last);
	sb_printf(txt, "router: %s\nlast_route_trace: %s\n",
		  status, last ? last : "(none)");
	sb_printf(js, "{\"status\":\"");
	oi_json_escape(js, status);
	sb_printf(js, "\",\"last_trace\":\"");
	oi_json_escape(js, last ? last : "");
	sb_printf(js, "\"}");
	free(last);
	return 0;
}

static int oi_config(struct sbuf *txt, struct sbuf *js,
		     const struct ai_config *cfg)
{
	const char *dm = cfg && cfg->default_model ? cfg->default_model : "-";
	const char *lm = cfg && cfg->local.model ? cfg->local.model : "-";
	const char *lb = cfg && cfg->local.base_url ? cfg->local.base_url : "-";

	sb_printf(txt,
		  "default_model=%s local_enabled=%d local_model=%s "
		  "local_base_url=%s route_mode=%s ctx_len=%d max_tokens=%d\n",
		  dm, cfg ? cfg->local.enabled : 0, lm, lb,
		  ai_route_mode_name(ai_route_effective_mode(cfg)),
		  cfg ? cfg->ui.ctx_len : 0,
		  cfg ? cfg->ui.max_tokens : 0);
	sb_printf(js,
		  "{\"default_model\":\"%s\",\"local_enabled\":%d,"
		  "\"local_model\":\"%s\",\"local_base_url\":\"%s\","
		  "\"route_mode\":\"%s\",\"ctx_len\":%d,"
		  "\"max_tokens\":%d,\"api_key_omitted\":true}",
		  dm, cfg ? cfg->local.enabled : 0, lm, lb,
		  ai_route_mode_name(ai_route_effective_mode(cfg)),
		  cfg ? cfg->ui.ctx_len : 0,
		  cfg ? cfg->ui.max_tokens : 0);
	return 0;
}

static int oi_memory_query(struct sbuf *txt, struct sbuf *js,
			   const char *question, long long *age)
{
	char *out = malloc(SME_OUT_BUF_MIN * 4);
	char query[512];
	const char *p = question;
	int rc;

	if (!out)
		return -1;
	/* 去掉常见前缀，保留查询主体 */
	while (*p == ' ') p++;
	{
		static const char *const prefixes[] = {
			"搜索记忆", "查询记忆", "查找记忆", "记忆查询", "记忆",
			"memory_search", "memory search", "recall", "sme",
			"请", "帮我", "查一下", "查询", NULL
		};
		int i;

		for (i = 0; prefixes[i]; i++) {
			size_t l = strlen(prefixes[i]);

			if (strncasecmp(p, prefixes[i], l) == 0) {
				p += l;
				while (*p == ' ' || *p == ':')
					p++;
			}
		}
	}
	snprintf(query, sizeof(query), "%s", p);
	out[0] = '\0';
	rc = sme_search(query[0] ? query : question, 5, out,
			SME_OUT_BUF_MIN * 4);
	if (rc != AI_OK) {
		sb_printf(txt,
			  "SME unavailable (%s). Cached plans still available: "
			  "ask \"最近计划\".\n", out);
		sb_printf(js,
			  "{\"sme_available\":false,\"error\":\"");
		oi_json_escape(js, out);
		sb_printf(js, "\"}");
		*age = 0;
		free(out);
		return 0;
	}
	sb_printf(txt, "SME results: %s\n", out);
	sb_printf(js, "{\"sme_available\":true,\"result\":%s}", out);
	*age = 0;
	free(out);
	return 0;
}

static int oi_file(const char *question, struct sbuf *txt, struct sbuf *js,
		   long long *age)
{
	char path[1024] = "";
	char *copy = strdup(question);
	char *tok, *save = NULL;
	struct stat st;
	char full[1024];
	int text_lines = -1;
	int dir_entries = -1;

	if (!copy)
		return -1;
	for (tok = strtok_r(copy, " \t\r\n", &save); tok;
	     tok = strtok_r(NULL, " \t\r\n", &save)) {
		char *t = tok;
		size_t l = strlen(t);

		while (l > 0 && (t[0] == '"' || t[0] == '\'')) {
			t++;
			l--;
		}
		while (l > 0 && strchr(".,;:!?)]}\"'", t[l - 1]))
			t[--l] = '\0';
		if (!t[0])
			continue;
		if (t[0] == '~' && (t[1] == '/' || t[1] == '\0')) {
			snprintf(path, sizeof(path), "%s%s",
				 getenv("HOME") ? getenv("HOME") : "", t + 1);
			break;
		}
		if (t[0] == '/' || (t[0] == '.' && t[1] == '/')) {
			snprintf(path, sizeof(path), "%s", t);
			break;
		}
	}
	free(copy);
	if (path[0] == '\0') {
		sb_printf(txt, "no absolute path found in question\n");
		sb_printf(js, "{\"error\":\"no_path\"}");
		return 0;
	}
	oi_path(path, full, sizeof(full));
	if (stat(full, &st) != 0) {
		sb_printf(txt, "path=%s exists=false\n", path);
		sb_printf(js,
			  "{\"path\":\"%s\",\"exists\":false}",
			  path);
		*age = 0;
		return 0;
	}
	if (S_ISDIR(st.st_mode)) {
		DIR *d = opendir(full);
		struct dirent *de;

		dir_entries = 0;
		if (d) {
			while ((de = readdir(d)) != NULL)
				if (strcmp(de->d_name, ".") != 0 &&
				    strcmp(de->d_name, "..") != 0)
					dir_entries++;
			closedir(d);
		}
	} else if (S_ISREG(st.st_mode) && st.st_size <= OI_MAX_FILE) {
		FILE *fp = fopen(full, "r");
		int c, lines = 0;

		if (fp) {
			while ((c = fgetc(fp)) != EOF)
				if (c == '\n')
					lines++;
			fclose(fp);
			text_lines = lines;
		}
	}
	{
		char mode[16];
		char owner[32];
		char group[32];
		const char *type = S_ISDIR(st.st_mode) ? "directory" :
				   S_ISLNK(st.st_mode) ? "symlink" :
				   S_ISREG(st.st_mode) ? "regular" :
				   S_ISCHR(st.st_mode) ? "chardev" :
				   S_ISBLK(st.st_mode) ? "blockdev" :
				   S_ISFIFO(st.st_mode) ? "fifo" :
				   S_ISSOCK(st.st_mode) ? "socket" : "other";

		snprintf(owner, sizeof(owner), "%u", (unsigned)st.st_uid);
		snprintf(group, sizeof(group), "%u", (unsigned)st.st_gid);
		snprintf(mode, sizeof(mode), "%o",
			 (unsigned)(st.st_mode & 07777));
		sb_printf(txt,
			  "path=%s exists=true type=%s size=%lld mode=%s "
			  "owner_uid=%s group_gid=%s mtime=%lld",
			  path, type, (long long)st.st_size, mode, owner,
			  group, (long long)st.st_mtime);
		if (dir_entries >= 0)
			sb_printf(txt, " entries=%d", dir_entries);
		if (text_lines >= 0)
			sb_printf(txt, " lines=%d", text_lines);
		sb_printf(txt, " (content not dumped)\n");
		sb_printf(js,
			  "{\"path\":\"%s\",\"exists\":true,\"type\":\"%s\","
			  "\"size\":%lld,\"mode\":\"%s\",\"owner_uid\":\"%s\","
			  "\"group_gid\":\"%s\",\"mtime\":%lld,"
			  "\"entries\":%d,\"lines\":%d,\"content_dumped\":false}",
			  path, type, (long long)st.st_size, mode, owner,
			  group, (long long)st.st_mtime, dir_entries,
			  text_lines);
	}
	*age = 0;
	return 0;
}

static int oi_service(const char *name, struct sbuf *txt, struct sbuf *js)
{
	char cmd[256];
	char *out;
	int active = -1;

	if (name && name[0]) {
		snprintf(cmd, sizeof(cmd), "systemctl is-active %s", name);
		out = oi_run_cmd(cmd);
		if (out) {
			oi_trim_line(out);
			active = strcmp(out, "active") == 0 ? 1 :
				 strcmp(out, "inactive") == 0 ? 0 : -1;
			sb_printf(txt, "service=%s state=%s\n", name,
				  out[0] ? out : "unknown");
		} else {
			sb_printf(txt,
				  "service=%s state=unavailable "
				  "(systemctl not available / NO_EXEC)\n", name);
		}
		sb_printf(js,
			  "{\"service\":\"%s\",\"state\":\"%s\","
			  "\"active\":%d}",
			  name, out ? out : "unavailable", active);
		free(out);
		return 0;
	}
	out = oi_run_cmd("systemctl --no-pager --failed --plain");
	if (out) {
		sb_printf(txt, "failed_units:\n%s",
			  out[0] ? out : "  (none)\n");
		sb_printf(js, "{\"failed_units\":\"");
		oi_json_escape(js, out);
		sb_printf(js, "\",\"available\":true}");
	} else {
		sb_printf(txt,
			  "failed_units: unavailable (systemctl not available "
			  "or NO_EXEC)\n");
		sb_printf(js,
			  "{\"failed_units\":[],\"available\":false}");
	}
	free(out);
	return 0;
}

static int oi_logs(struct sbuf *txt, struct sbuf *js)
{
	char *out = oi_run_cmd("dmesg --level=err,warn");

	if (!out)
		out = oi_run_cmd("dmesg");
	if (out) {
		/* 只保留最后 20 行，避免把整段 dmesg 塞进上下文 */
		int lines = 0;
		char *p = out;
		char *keep = out;

		while (*p) {
			if (*p == '\n') {
				lines++;
				if (lines > 20)
					keep = p + 1;
			}
			p++;
		}
		sb_printf(txt, "recent_kernel_errors:\n%s\n",
			  keep[0] ? keep : "  (none)\n");
		sb_printf(js, "{\"recent_kernel_errors\":\"");
		oi_json_escape(js, keep);
		sb_printf(js, "\",\"available\":true}");
	} else {
		sb_printf(txt,
			  "kernel errors: unavailable (dmesg requires privilege "
			  "or NO_EXEC)\n");
		sb_printf(js, "{\"available\":false,\"source\":\"dmesg\"}");
	}
	free(out);
	return 0;
}

/* ---- 意图识别 ---- */

static const char *const g_action_guard[] = {
	"修复", "重启", "停止", "启动服务", "安装", "删除", "创建", "修改",
	"编辑", "写入", "格式化", "挂载", "卸载", "杀掉", "分析", "设计",
	"为什么", "如何", "怎么", "方案", "代码", "脚本", "生成", "实现",
	"编写", "写一个", "帮我写", "制定", "根因", "优化", "调优",
	"fix", "restart", "reboot", "stop", "install", "remove", "delete",
	"create", "modify", "edit", "write", "format", "mount", "unmount",
	"kill", "analyz", "analys", "design", "why", "how to", "explain",
	"optimi", "plan for", "implement", "generat", "refactor", "debug",
	NULL
};

static int oi_guard(const char *q)
{
	int i;

	for (i = 0; g_action_guard[i]; i++)
		if (oi_has(q, g_action_guard[i]))
			return 1;
	return 0;
}

static int oi_is_service_list(const char *q)
{
	return oi_has(q, "失败服务") || oi_has(q, "故障服务") ||
	       oi_has(q, "所有服务") || oi_has(q, "服务列表") ||
	       oi_has(q, "failed service") || oi_has(q, "failed unit") ||
	       oi_has(q, "failed units") || oi_has(q, "service list") ||
	       oi_has(q, "services");
}

static int oi_service_name(const char *q, char *out, size_t n)
{
	char *copy = strdup(q);
	char *tok, *save = NULL;
	char prev[64] = "";
	int want = 0;
	int got = 0;

	out[0] = '\0';
	if (!copy)
		return 0;
	/* 中英文触发词前/后一个 token 作为服务名：
	 *   "nginx 服务状态" / "服务 nginx 状态" / "service nginx" */
	for (tok = strtok_r(copy, " \t\r\n,，。", &save); tok && !got;
	     tok = strtok_r(NULL, " \t\r\n,，。", &save)) {
		int is_trigger = strcasecmp(tok, "服务") == 0 ||
				 strncasecmp(tok, "服务", 6) == 0 ||
				 strcasecmp(tok, "service") == 0 ||
				 strcasecmp(tok, "systemctl") == 0;
		int skip = strcasecmp(tok, "状态") == 0 ||
			   strcasecmp(tok, "status") == 0 ||
			   strcasecmp(tok, "is-active") == 0 ||
			   strcasecmp(tok, "show") == 0 ||
			   strcasecmp(tok, "list") == 0 ||
			   strcasecmp(tok, "failed") == 0 ||
			   strcasecmp(tok, "is") == 0 ||
			   strcasecmp(tok, "active") == 0;

		if (is_trigger) {
			size_t pl = strlen(prev);
			int valid = pl > 0 && pl < 64;
			size_t i;

			for (i = 0; i < pl; i++)
				if (!isalnum((unsigned char)prev[i]) &&
				    prev[i] != '-' && prev[i] != '_' &&
				    prev[i] != '.' && prev[i] != '@')
					valid = 0;
			if (valid) {
				snprintf(out, n, "%s", prev);
				got = 1;
				break;
			}
			want = 1;
		} else if (want) {
			size_t l = strlen(tok);
			int valid = l > 0 && l < 64;
			size_t i;

			for (i = 0; i < l; i++)
				if (!isalnum((unsigned char)tok[i]) &&
				    tok[i] != '-' && tok[i] != '_' &&
				    tok[i] != '.' && tok[i] != '@')
					valid = 0;
			if (valid && !skip) {
				snprintf(out, n, "%s", tok);
				got = 1;
				break;
			}
		}
		snprintf(prev, sizeof(prev), "%s", tok);
	}
	free(copy);
	return got;
}

static int oi_match_intent(const char *q, const struct ai_config *cfg,
			   char *intent, size_t n)
{
	(void)cfg;
	if (oi_has(q, "上次计划") || oi_has(q, "最近计划") ||
	    oi_has(q, "上一个计划") || oi_has(q, "上次任务") ||
	    oi_has(q, "最近任务") || oi_has(q, "last plan") ||
	    oi_has(q, "last task") || oi_has(q, "previous plan") ||
	    oi_has(q, "recent plan")) {
		snprintf(intent, n, "plan");
		return 1;
	}
	if (oi_has(q, "路由模式") || oi_has(q, "模型路由") ||
	    oi_has(q, "模型选择") || oi_has(q, "which model") ||
	    oi_has(q, "model route") || oi_has(q, "route mode") ||
	    oi_has(q, "哪个模型") || oi_has(q, "本地还是云")) {
		snprintf(intent, n, "route");
		return 1;
	}
	if (oi_has(q, "记忆") || oi_has(q, "memory_search") ||
	    oi_has(q, "memory search") || oi_has(q, "recall") ||
	    oi_has(q, "sme ")) {
		snprintf(intent, n, "memory_query");
		return 1;
	}
	if (oi_has(q, "租约") || oi_has(q, "lease") ||
	    oi_has(q, "授权状态") || oi_has(q, "confirm nonce")) {
		snprintf(intent, n, "lease");
		return 1;
	}
	if (oi_has(q, "沙箱") || oi_has(q, "sandbox") ||
	    oi_has(q, "隔离区")) {
		snprintf(intent, n, "sandbox");
		return 1;
	}
	if (oi_has(q, "日志") || oi_has(q, "log") || oi_has(q, "dmesg") ||
	    oi_has(q, "内核错误") || oi_has(q, "kernel error") ||
	    oi_has(q, "错误日志")) {
		snprintf(intent, n, "logs");
		return 1;
	}
	if (oi_is_service_list(q)) {
		snprintf(intent, n, "services");
		return 1;
	}
	{
		char svc[64];

		if ((oi_has(q, "服务") || oi_has(q, "service") ||
		     oi_has(q, "systemctl")) &&
		    oi_service_name(q, svc, sizeof(svc))) {
			snprintf(intent, n, "service");
			return 1;
		}
	}
	if (oi_has(q, "文件") || oi_has(q, "file") ||
	    oi_has(q, "目录") || oi_has(q, "directory") ||
	    oi_has(q, "权限") || oi_has(q, "大小")) {
		if (strchr(q, '/') || strchr(q, '~')) {
			snprintf(intent, n, "file");
			return 1;
		}
	}
	if (oi_has(q, "配置文件") || oi_has(q, "模型配置") ||
	    oi_has(q, "config") || oi_has(q, "配置")) {
		snprintf(intent, n, "config");
		return 1;
	}
	if (oi_has(q, "磁盘") || oi_has(q, "disk") ||
	    oi_has(q, "空间") || oi_has(q, "storage") ||
	    oi_has(q, "分区") || oi_has(q, "df ") || oi_has(q, "df -")) {
		snprintf(intent, n, "disk");
		return 1;
	}
	if (oi_has(q, "内存") || oi_has(q, "memory") || oi_has(q, "mem") ||
	    oi_has(q, "ram") || oi_has(q, "free -") ||
	    oi_has(q, "交换分区") || oi_has(q, "swap")) {
		snprintf(intent, n, "memory");
		return 1;
	}
	if (oi_has(q, "负载") || oi_has(q, "load") || oi_has(q, "cpu") ||
	    oi_has(q, "进程") || oi_has(q, "process") ||
	    oi_has(q, "top") || oi_has(q, "ps ")) {
		snprintf(intent, n, "load");
		return 1;
	}
	if (oi_has(q, "网络") || oi_has(q, "network") ||
	    oi_has(q, "ip地址") || oi_has(q, "ip 地址") ||
	    oi_has(q, "ip addr") || oi_has(q, "dns") ||
	    oi_has(q, "网关") || oi_has(q, "gateway") ||
	    oi_has(q, "网卡") || oi_has(q, "interface")) {
		snprintf(intent, n, "network");
		return 1;
	}
	if (oi_has(q, "内核") || oi_has(q, "kernel") ||
	    oi_has(q, "uname") || oi_has(q, "版本") ||
	    oi_has(q, "version")) {
		snprintf(intent, n, "kernel");
		return 1;
	}
	if (oi_has(q, "运行多久") || oi_has(q, "uptime") ||
	    oi_has(q, "启动时间") || oi_has(q, "开机多久")) {
		snprintf(intent, n, "uptime");
		return 1;
	}
	if (oi_has(q, "状态") || oi_has(q, "status") ||
	    oi_has(q, "健康") || oi_has(q, "health") ||
	    oi_has(q, "overview") || oi_has(q, "总览") ||
	    oi_has(q, "怎么样") || oi_has(q, "how is the system")) {
		snprintf(intent, n, "status");
		return 1;
	}
	return 0;
}

/* ---- 答案组装 ---- */

static void oi_header(struct sbuf *txt, const char *intent,
		      const char *source, long long age, long long latency,
		      int degraded)
{
	sb_printf(txt,
		  "[offline] intent=%s source=%s age=%lldms latency=%lldms%s\n",
		  intent, source, age, latency,
		  degraded ? " degraded=1" : "");
}

static void oi_json_prefix(struct sbuf *js, const char *intent,
			   const char *source, long long age, int degraded)
{
	sb_printf(js, "{\"intent\":\"%s\",\"source\":\"", intent);
	oi_json_escape(js, source);
	sb_printf(js, "\",\"cache_age_ms\":%lld,\"degraded\":%d,\"data\":",
		  age, degraded);
}

static void oi_json_suffix(struct sbuf *js)
{
	sb_printf(js, "}");
}

int ai_offline_intent_match(const char *question, const struct ai_config *cfg,
			    struct ai_offline_answer *ans)
{
	char q[2048];
	char intent[32];
	struct sbuf txt, js;
	long long t0, age = 0;
	int degraded = 0;
	size_t i;

	if (!question || !ans)
		return 0;
	memset(ans, 0, sizeof(*ans));
	for (i = 0; i + 1 < sizeof(q) && question[i]; i++)
		q[i] = (char)tolower((unsigned char)question[i]);
	q[i] = '\0';

	if (!q[0] || oi_guard(q))
		return 0;
	if (!oi_match_intent(q, cfg, intent, sizeof(intent)))
		return 0;

	t0 = oi_now_ms();
	sb_init(&txt, OI_MAX_TEXT);
	sb_init(&js, OI_MAX_JSON);
	if (!txt.s || !js.s) {
		free(txt.s);
		free(js.s);
		return 0;
	}

	if (strcmp(intent, "plan") == 0) {
		oi_plans(&txt, &js, &age);
	} else if (strcmp(intent, "route") == 0) {
		oi_route(&txt, &js, cfg, &age);
	} else if (strcmp(intent, "config") == 0) {
		oi_config(&txt, &js, cfg);
	} else if (strcmp(intent, "lease") == 0) {
		oi_lease(&txt, &js, &age);
	} else if (strcmp(intent, "memory_query") == 0) {
		oi_memory_query(&txt, &js, question, &age);
		degraded = strstr(js.s, "\"sme_available\":false") != NULL;
	} else if (strcmp(intent, "sandbox") == 0) {
		oi_sandbox(&txt, &js, &age);
	} else if (strcmp(intent, "service") == 0) {
		char svc[64];

		oi_service_name(q, svc, sizeof(svc));
		oi_service(svc, &txt, &js);
	} else if (strcmp(intent, "services") == 0) {
		oi_service(NULL, &txt, &js);
	} else if (strcmp(intent, "logs") == 0) {
		oi_logs(&txt, &js);
	} else if (strcmp(intent, "file") == 0) {
		oi_file(question, &txt, &js, &age);
	} else if (strcmp(intent, "disk") == 0) {
		oi_disk_rows(&txt, &js);
	} else if (strcmp(intent, "memory") == 0) {
		char *mi = oi_read_file("/proc/meminfo", 65536);
		long long total = mi ? oi_meminfo_kb(mi, "MemTotal") : -1;
		long long freekb = mi ? oi_meminfo_kb(mi, "MemFree") : -1;
		long long avail = mi ? oi_meminfo_kb(mi, "MemAvailable") : -1;
		long long buffers = mi ? oi_meminfo_kb(mi, "Buffers") : -1;
		long long cached = mi ? oi_meminfo_kb(mi, "Cached") : -1;
		long long swtotal = mi ? oi_meminfo_kb(mi, "SwapTotal") : -1;
		long long swfree = mi ? oi_meminfo_kb(mi, "SwapFree") : -1;

		if (total < 0) {
			sb_printf(&txt, "/proc/meminfo unavailable\n");
			sb_printf(&js, "{\"available\":false}");
			degraded = 1;
		} else {
			sb_printf(&txt,
				  "MemTotal=%lldMB MemFree=%lldMB "
				  "MemAvailable=%lldMB Buffers=%lldMB "
				  "Cached=%lldMB SwapTotal=%lldMB "
				  "SwapFree=%lldMB cpu_count=%d\n",
				  total / 1024, freekb / 1024, avail / 1024,
				  buffers / 1024, cached / 1024,
				  swtotal / 1024, swfree / 1024,
				  oi_cpu_count());
			sb_printf(&js,
				  "{\"mem_total_mb\":%lld,\"mem_free_mb\":%lld,"
				  "\"mem_available_mb\":%lld,\"buffers_mb\":%lld,"
				  "\"cached_mb\":%lld,\"swap_total_mb\":%lld,"
				  "\"swap_free_mb\":%lld,\"cpu_count\":%d}",
				  total / 1024, freekb / 1024, avail / 1024,
				  buffers / 1024, cached / 1024,
				  swtotal / 1024, swfree / 1024,
				  oi_cpu_count());
		}
		free(mi);
	} else if (strcmp(intent, "load") == 0) {
		char *la = oi_read_file("/proc/loadavg", 256);
		struct oi_proc top[5];
		int n = oi_top_procs(top, 5);
		int j;

		if (la) {
			sb_printf(&txt, "loadavg=%s", la);
		} else {
			sb_printf(&txt, "loadavg=unavailable\n");
			degraded = 1;
		}
		sb_printf(&txt, "top_rss:\n");
		for (j = 0; j < n; j++)
			sb_printf(&txt, "  pid=%d name=%s rss_mb=%llu\n",
				  top[j].pid, top[j].name,
				  top[j].rss_kb / 1024);
		if (n == 0)
			sb_printf(&txt, "  (none)\n");
		sb_printf(&js, "{\"loadavg\":\"");
		if (la) {
			char *nl = strchr(la, '\n');

			if (nl)
				*nl = '\0';
			oi_json_escape(&js, la);
		}
		sb_printf(&js, "\",\"top\":[");
		for (j = 0; j < n; j++)
			sb_printf(&js, "%s{\"pid\":%d,\"name\":\"%s\","
				  "\"rss_mb\":%llu}",
				  j ? "," : "", top[j].pid, top[j].name,
				  top[j].rss_kb / 1024);
		sb_printf(&js, "],\"cpu_count\":%d}", oi_cpu_count());
		free(la);
	} else if (strcmp(intent, "network") == 0) {
		oi_net(&txt, &js);
	} else if (strcmp(intent, "kernel") == 0) {
		struct utsname u;
		char *ver = oi_read_file("/proc/version", 4096);

		if (uname(&u) == 0) {
			sb_printf(&txt, "sysname=%s release=%s version=%s "
				  "machine=%s nodename=%s\n",
				  u.sysname, u.release, u.version, u.machine,
				  u.nodename);
			sb_printf(&js,
				  "{\"sysname\":\"%s\",\"release\":\"%s\","
				  "\"version\":\"%s\",\"machine\":\"%s\"}",
				  u.sysname, u.release, u.version, u.machine);
		} else {
			sb_printf(&txt, "uname unavailable\n");
			sb_printf(&js, "{\"available\":false}");
			degraded = 1;
		}
		free(ver);
	} else if (strcmp(intent, "uptime") == 0) {
		char *up = oi_read_file("/proc/uptime", 256);

		if (up) {
			double sec = strtod(up, NULL);

			sb_printf(&txt, "uptime_seconds=%.0f uptime_hours=%.1f\n",
				  sec, sec / 3600.0);
			sb_printf(&js,
				  "{\"uptime_seconds\":%.0f,"
				  "\"uptime_hours\":%.1f}", sec, sec / 3600.0);
		} else {
			sb_printf(&txt, "/proc/uptime unavailable\n");
			sb_printf(&js, "{\"available\":false}");
			degraded = 1;
		}
		free(up);
	} else if (strcmp(intent, "status") == 0) {
		char *up = oi_read_file("/proc/uptime", 256);
		char *la = oi_read_file("/proc/loadavg", 256);
		char *mi = oi_read_file("/proc/meminfo", 65536);
		long long total = mi ? oi_meminfo_kb(mi, "MemTotal") : -1;
		long long avail = mi ? oi_meminfo_kb(mi, "MemAvailable") : -1;
		struct statvfs vfs;
		char rootp[1024];
		int disk_pct = -1;
		char *failed = oi_run_cmd("systemctl --no-pager --failed --plain");
		int nfailed = 0;

		oi_path("/", rootp, sizeof(rootp));
		if (statvfs(rootp, &vfs) == 0) {
			unsigned long long t =
				(unsigned long long)vfs.f_blocks * vfs.f_frsize;
			unsigned long long f =
				(unsigned long long)vfs.f_bavail * vfs.f_frsize;

			disk_pct = t ? (int)((t - f) * 100 / t) : 0;
		}
		if (failed) {
			char *p = failed;

			/* systemctl --failed --plain 会带 "0 loaded units
			 * listed." 等汇总行；只数真正的 unit 行 */
			while (*p) {
				char *nl = strchr(p, '\n');

				if (nl) {
					*nl = '\0';
					if (strstr(p, ".service") ||
					    strstr(p, ".socket") ||
					    strstr(p, ".timer") ||
					    strstr(p, ".mount") ||
					    strstr(p, ".target"))
						nfailed++;
					*nl = '\n';
					p = nl + 1;
				} else {
					if (strstr(p, ".service") ||
					    strstr(p, ".socket") ||
					    strstr(p, ".timer"))
						nfailed++;
					break;
				}
			}
		}
		if (!failed)
			degraded = 1;
		sb_printf(&txt,
			  "uptime_s=%.0f load=%s mem_total_mb=%lld "
			  "mem_available_mb=%lld disk_root_used_pct=%d "
			  "failed_units=%d cpu_count=%d\n",
			  up ? strtod(up, NULL) : 0.0,
			  la ? la : "unavailable\n",
			  total < 0 ? 0 : total / 1024,
			  avail < 0 ? 0 : avail / 1024,
			  disk_pct, failed ? nfailed : -1, oi_cpu_count());
		sb_printf(&js,
			  "{\"uptime_seconds\":%.0f,\"loadavg\":\"",
			  up ? strtod(up, NULL) : 0.0);
		if (la) {
			char *nl = strchr(la, '\n');

			if (nl)
				*nl = '\0';
			oi_json_escape(&js, la);
		}
		sb_printf(&js,
			  "\",\"mem_total_mb\":%lld,\"mem_available_mb\":%lld,"
			  "\"disk_root_used_pct\":%d,\"failed_units\":%d,"
			  "\"cpu_count\":%d}",
			  total < 0 ? 0 : total / 1024,
			  avail < 0 ? 0 : avail / 1024,
			  disk_pct, failed ? nfailed : -1, oi_cpu_count());
		free(up);
		free(la);
		free(mi);
		free(failed);
	} else {
		free(txt.s);
		free(js.s);
		return 0;
	}

	if (!degraded && txt.s && strstr(txt.s, "unavailable"))
		degraded = 1;
	{
		long long latency = oi_now_ms() - t0;
		struct sbuf final_txt;
		const char *src =
			strcmp(intent, "status") == 0 ?
			"/proc,/statvfs,systemctl" :
			strcmp(intent, "memory") == 0 ? "/proc/meminfo" :
			strcmp(intent, "disk") == 0 ? "statvfs" :
			strcmp(intent, "load") == 0 ?
			"/proc/loadavg,/proc/*/status" :
			strcmp(intent, "file") == 0 ? "stat" :
			strcmp(intent, "sandbox") == 0 ? "sandbox dir" :
			strcmp(intent, "lease") == 0 ? "lease store" :
			strcmp(intent, "plan") == 0 ? "plans.jsonl" :
			strcmp(intent, "route") == 0 ? "route.jsonl" :
			strcmp(intent, "memory_query") == 0 ? "SME" :
			strcmp(intent, "config") == 0 ? "model.toml" :
			strcmp(intent, "service") == 0 ? "systemctl" :
			strcmp(intent, "services") == 0 ? "systemctl" :
			strcmp(intent, "logs") == 0 ? "dmesg" :
			strcmp(intent, "network") == 0 ?
			"/proc/net,/etc/resolv.conf" :
			strcmp(intent, "kernel") == 0 ?
			"uname,/proc/version" :
			strcmp(intent, "uptime") == 0 ? "/proc/uptime" : "-";

		sb_init(&final_txt, OI_MAX_TEXT);
		if (!final_txt.s) {
			free(txt.s);
			free(js.s);
			return 0;
		}
		oi_header(&final_txt, intent, src, age, latency, degraded);
		sb_printf(&final_txt, "%s", txt.s ? txt.s : "");
		free(txt.s);
		txt.s = sb_take(&final_txt);

		/* JSON 包一层 header 字段 + data */
		{
			struct sbuf final_js;

			sb_init(&final_js, OI_MAX_JSON);
			if (!final_js.s) {
				free(txt.s);
				free(js.s);
				return 0;
			}
			oi_json_prefix(&final_js, intent, src, age, degraded);
			sb_printf(&final_js, "%s", js.s ? js.s : "{}");
			oi_json_suffix(&final_js);
			free(js.s);
			js.s = sb_take(&final_js);
		}
	}
	snprintf(ans->source, sizeof(ans->source), "%s",
		 strcmp(intent, "memory_query") == 0 ? "SME" :
		 strcmp(intent, "status") == 0 ?
		 "/proc,/statvfs,systemctl" :
		 strcmp(intent, "memory") == 0 ? "/proc/meminfo" :
		 strcmp(intent, "disk") == 0 ? "statvfs" :
		 strcmp(intent, "load") == 0 ?
		 "/proc/loadavg,/proc/*/status" :
		 strcmp(intent, "file") == 0 ? "stat" :
		 strcmp(intent, "sandbox") == 0 ? "sandbox dir" :
		 strcmp(intent, "lease") == 0 ? "lease store" :
		 strcmp(intent, "plan") == 0 ? "plans.jsonl" :
		 strcmp(intent, "route") == 0 ? "route.jsonl" :
		 strcmp(intent, "config") == 0 ? "model.toml" :
		 strcmp(intent, "service") == 0 ? "systemctl" :
		 strcmp(intent, "services") == 0 ? "systemctl" :
		 strcmp(intent, "logs") == 0 ? "dmesg" :
		 strcmp(intent, "network") == 0 ?
		 "/proc/net,/etc/resolv.conf" :
		 strcmp(intent, "kernel") == 0 ?
		 "uname,/proc/version" :
		 strcmp(intent, "uptime") == 0 ? "/proc/uptime" : "-");

	ans->matched = 1;
	snprintf(ans->intent, sizeof(ans->intent), "%s", intent);
	ans->text = txt.s;
	ans->json = js.s;
	ans->cache_age_ms = age;
	ans->latency_ms = oi_now_ms() - t0;
	ans->degraded = degraded;
	return 1;
}

void ai_offline_answer_free(struct ai_offline_answer *ans)
{
	if (!ans)
		return;
	free(ans->text);
	free(ans->json);
	memset(ans, 0, sizeof(*ans));
}

/* ---- 计划缓存 ---- */

static int oi_offline_dir(char *buf, size_t n)
{
	const char *home = getenv("HOME");

	if (!home || !home[0])
		return -1;
	snprintf(buf, n, "%s/.aikernel/offline", home);
	return 0;
}

int ai_offline_cache_plan(const char *question, const char *route,
			  const char *status, int rounds,
			  const char *tools_csv, const char *detail)
{
	char dir[1024], path[1200], rot[1300];
	struct sbuf line;
	struct stat st;
	int fd;

	if (oi_offline_dir(dir, sizeof(dir)) != 0)
		return AI_ERR_STORAGE;
	/* 先建父目录 ~/.aikernel（新 HOME/沙盒常见） */
	{
		char parent[1024];
		char *slash = strrchr(dir, '/');

		if (slash) {
			size_t pl = (size_t)(slash - dir);

			if (pl < sizeof(parent)) {
				memcpy(parent, dir, pl);
				parent[pl] = '\0';
				mkdir(parent, 0700);
			}
		}
	}
	mkdir(dir, 0700);
	snprintf(path, sizeof(path), "%s/plans.jsonl", dir);
	if (stat(path, &st) == 0 && st.st_size > 1024 * 1024) {
		snprintf(rot, sizeof(rot), "%s.1", path);
		rename(path, rot);
	}
	sb_init(&line, 2048);
	if (!line.s)
		return AI_ERR_MEMORY;
	sb_printf(&line, "{\"ts\":%lld,\"question\":\"", oi_wall_ms());
	{
		char q[241];
		size_t ql = question ? strlen(question) : 0;

		if (ql > 240)
			ql = 240;
		if (ql)
			memcpy(q, question, ql);
		q[ql] = '\0';
		oi_json_escape(&line, q);
	}
	sb_printf(&line, "\",\"route\":\"%s\",\"status\":\"%s\","
		  "\"rounds\":%d,\"tools\":[",
		  route ? route : "-", status ? status : "-", rounds);
	if (tools_csv && tools_csv[0]) {
		char *copy = strdup(tools_csv);
		char *tok, *save = NULL;
		int first = 1;

		if (copy) {
			for (tok = strtok_r(copy, ",", &save); tok;
			     tok = strtok_r(NULL, ",", &save)) {
				sb_printf(&line, "%s\"", first ? "" : ",\"");
				oi_json_escape(&line, tok);
				sb_printf(&line, "\"");
				first = 0;
			}
			free(copy);
		}
	}
	sb_printf(&line, "],\"detail\":\"");
	{
		char d[201];
		size_t dl = detail ? strlen(detail) : 0;

		if (dl > 200)
			dl = 200;
		if (dl)
			memcpy(d, detail, dl);
		d[dl] = '\0';
		oi_json_escape(&line, d);
	}
	sb_printf(&line, "\"}\n");
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		free(line.s);
		return AI_ERR_STORAGE;
	}
	flock(fd, LOCK_EX);
	if (write(fd, line.s, line.len) < 0) {
		flock(fd, LOCK_UN);
		close(fd);
		free(line.s);
		return AI_ERR_STORAGE;
	}
	flock(fd, LOCK_UN);
	close(fd);
	free(line.s);
	return AI_OK;
}

char *ai_offline_last_plans(long long *age_ms)
{
	char dir[1024], path[1200];
	FILE *fp;
	char *buf;
	long sz;
	long start = 0;
	long i;

	if (age_ms)
		*age_ms = 0;
	if (oi_offline_dir(dir, sizeof(dir)) != 0)
		return NULL;
	snprintf(path, sizeof(path), "%s/plans.jsonl", dir);
	fp = fopen(path, "r");
	if (!fp)
		return NULL;
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return NULL;
	}
	sz = ftell(fp);
	if (sz < 0 || sz > 1024 * 1024) {
		fclose(fp);
		return NULL;
	}
	/* 只取末尾 4KB 且从完整行开始 */
	start = sz > 4096 ? sz - 4096 : 0;
	if (fseek(fp, start, SEEK_SET) != 0) {
		fclose(fp);
		return NULL;
	}
	buf = malloc((size_t)(sz - start) + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	{
		size_t n = fread(buf, 1, (size_t)(sz - start), fp);

		buf[n] = '\0';
	}
	fclose(fp);
	if (start > 0) {
		char *nl = strchr(buf, '\n');

		if (nl)
			memmove(buf, nl + 1, strlen(nl + 1) + 1);
	}
	/* 只保留最后 5 行 */
	{
		long count = 0;
		char *p = buf;

		while ((p = strchr(p, '\n')) != NULL) {
			count++;
			p++;
		}
		if (count > 5) {
			long drop = count - 5;
			char *q = buf;

			for (i = 0; i < drop; i++) {
				char *nl = strchr(q, '\n');

				if (!nl)
					break;
				q = nl + 1;
			}
			memmove(buf, q, strlen(q) + 1);
		}
	}
	if (age_ms) {
		struct stat st;

		if (stat(path, &st) == 0)
			*age_ms = oi_wall_ms() - (long long)st.st_mtime * 1000LL;
	}
	return buf;
}
