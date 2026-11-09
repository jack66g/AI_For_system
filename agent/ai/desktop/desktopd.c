// SPDX-License-Identifier: GPL-2.0
/*
 * desktopd.c - T6b 主程序:旗标解析、env 校验(中文报错 rc=1)、ensure_state、
 * 启动日志 + LISTENING 行、vm_housekeeping 线程、do_GET/do_POST 全路由分发。
 *
 * T6c 起:POST /api/chat 主体与 GET /api/chat?fallback= 走 dtchat.c,
 * vm enabled 路径走 dtvm.c(sshpass 子进程);disabled 分支保持 T6b 原样。
 * read_proc_stats/read_model_conf 已移至 dtchat.c(T6b 向量锁定)。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "desktop/dtapps.h"
#include "desktop/dtcore.h"
#include "desktop/dthttp.h"
#include "desktop/dtjson.h"
#include "desktop/dtstatic.h"
#include "desktop/dtchat.h"
#include "desktop/dtstate.h"
#include "desktop/dtvm.h"
#include "cloud/http/http_client.h"
#include "desktop/dttheme.h"

#define VM_DISABLED_REASON "vm_unavailable: local desktop only (AIK_DESKTOP_VM=0)"

static char *utf8_lower(const char *s);
static int mod_name_ok(const char *m);
static int route_vm_enabled(const char *path, struct dt_resp *r);

static void resp_err(struct dt_resp *r, int status, const char *err)
{
	aik_json *o = dt_new_obj();

	dt_put_bool(o, "ok", 0);
	dt_put_str(o, "error", err);
	dt_resp_json(r, status, o);
	aik_json_free(o);
}

/* ok:false + error + 第三键 */
static void resp_err3(struct dt_resp *r, int status, const char *err,
		      const char *k3, const aik_json *v3)
{
	aik_json *o = dt_new_obj();

	dt_put_bool(o, "ok", 0);
	dt_put_str(o, "error", err);
	dt_put_copy(o, k3, v3);
	dt_resp_json(r, status, o);
	aik_json_free(o);
}

/* ---------------- 查询串(parse_qs 语义:空值丢弃,'+'→空格,%XX 解码) ---------------- */

static char *qs_unquote_plus(const char *s, size_t n)
{
	struct dt_sbuf b;

	dt_sb_init(&b);
	for (size_t i = 0; i < n; i++) {
		char c = s[i];

		if (c == '+') {
			dt_sb_putc(&b, ' ');
			continue;
		}
		if (c == '%' && i + 2 < n) {
			int hi = -1, lo = -1;
			char h = s[i + 1], l = s[i + 2];

			if (h >= '0' && h <= '9')
				hi = h - '0';
			else if (h >= 'a' && h <= 'f')
				hi = h - 'a' + 10;
			else if (h >= 'A' && h <= 'F')
				hi = h - 'A' + 10;
			if (l >= '0' && l <= '9')
				lo = l - '0';
			else if (l >= 'a' && l <= 'f')
				lo = l - 'a' + 10;
			else if (l >= 'A' && l <= 'F')
				lo = l - 'A' + 10;
			if (hi >= 0 && lo >= 0) {
				dt_sb_putc(&b, (char)((hi << 4) | lo));
				i += 2;
				continue;
			}
		}
		dt_sb_putc(&b, c);
	}
	return dt_sb_finish(&b);
}

/* parse_qs(query).get(key):返回首个非空值(malloc;缺省 NULL) */
static char *qs_get(const char *query, const char *key)
{
	size_t qlen = strlen(query);
	size_t klen = strlen(key);
	size_t i = 0;

	while (i <= qlen) {
		size_t seg_end = i;
		const char *eq = NULL;

		while (seg_end < qlen && query[seg_end] != '&')
			seg_end++;
		for (size_t j = i; j < seg_end; j++)
			if (query[j] == '=') {
				eq = query + j;
				break;
			}
		if (eq) {
			size_t klen_q = (size_t)(eq - (query + i));
			char *k = qs_unquote_plus(query + i, klen_q);
			char *v = NULL;
			int matched = 0;

			if (k && strlen(k) == klen &&
			    strncmp(k, key, klen) == 0) {
				matched = 1;
				v = qs_unquote_plus(
					eq + 1, seg_end - klen_q - 1 - i);
			}
			free(k);
			if (matched) {
				if (v && *v) /* keep_blank_values=False:空值丢 */
					return v;
				free(v);
			}
		}
		if (seg_end >= qlen)
			break;
		i = seg_end + 1;
	}
	return NULL;
}

static int qs_has(const char *query, const char *key)
{
	char *v = qs_get(query, key);

	if (v) {
		free(v);
		return 1;
	}
	return 0;
}

/* ---------------- body 取值(Python dict 语义近似;类型不对返回哨兵) -------- */

/* body.get(k):值不存在 → NULL */
static const aik_json *body_get(struct dt_req *req, const char *k)
{
	if (!req->json)
		return NULL;
	return dt_get(req->json, k);
}

static int body_has(struct dt_req *req, const char *k)
{
	if (!req->json)
		return 0;
	return dt_get(req->json, k) != NULL;
}

/* str(body.get(k, dflt)):返回 malloc;非 STR/INT/NUM/BOOL 走容器 repr */
static char *body_get_str(struct dt_req *req, const char *k, const char *dflt)
{
	const aik_json *v = body_get(req, k);

	if (!v)
		return strdup(dflt);
	return dt_pystr(v);
}

/* ---------------- _send 的静态分支 ---------------- */

static void do_static(struct dt_resp *r, const char *rel)
{
	char *body = NULL;
	size_t n = 0;
	const char *ctype = NULL;

	if (dt_static_lookup(rel, &body, &n, &ctype) == 0) {
		dt_resp_static(r, body, n, ctype);
		return;
	}
	dt_resp_json404(r);
}

/* ---------------- stats ---------------- */

static aik_json *g_hist_load;
static aik_json *g_hist_mem;

/* ---------------- screenshot 后端 ---------------- */

static const char *screenshot_backend(void)
{
	static const char *off[] = { "0",    "false", "no", "off",
				     "disabled", "unavailable" };

	for (int i = 0; i < 6; i++)
		if (strcmp(g_cfg.screenshot_mode, off[i]) == 0)
			return "unavailable";
	/* C 版无 playwright 运行时 → 恒 unavailable(200 路径 T7 形态断言) */
	return "unavailable";
}

/* ---------------- vm disabled 分支 ---------------- */

static int vm_disabled(void)
{
	return !g_cfg.vm_enabled;
}

/* ---------------- GET ---------------- */

static int route_get(struct dt_req *req, struct dt_resp *r)
{
	const char *path = req->path;
	const char *query = req->query;

	if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
		do_static(r, "index.html");
		return 0;
	}
	if (strncmp(path, "/static/", 8) == 0) {
		do_static(r, path + 8);
		return 0;
	}
	if (strcmp(path, "/favicon.ico") == 0) {
		do_static(r, "icons/favicon.svg");
		return 0;
	}
	if (strcmp(path, "/api/health") == 0) {
		aik_json *obj = dt_load_desktop();
		aik_json *o = dt_new_obj();
		const aik_json *wins = dt_get(obj, "windows");
		char ts[32];

		dt_put_bool(o, "ok", 1);
		dt_put_str(o, "service", "img1");
		dt_put_str(o, "version", g_cfg.version);
		dt_put_str(o, "built", g_cfg.start_ts);
		dt_put_str(o, "bind", g_cfg.bind_host);
		dt_put_int(o, "port", g_cfg.port);
		dt_put_str(o, "state_root", g_cfg.state_root);
		dt_put_str(o, "vm", g_cfg.vm_enabled ? "l1-tunnel" : "local");
		{
			aik_json *desk = dt_new_obj();
			size_t nw = 0;

			if (wins && aik_json_typeof(wins) == AIK_JSON_ARR)
				nw = aik_json_count(wins);
			else if (wins && aik_json_typeof(wins) == AIK_JSON_OBJ)
				nw = aik_json_count(wins); /* len(dict) 语义 */
			else if (wins)
				return -1; /* len() TypeError → 关连接
					    */
			dt_put_str(desk, "backend", "web-demo");
			dt_put_int(desk, "windows", (long long)nw);
			dt_put_str(desk, "screenshot", screenshot_backend());
			dt_put_str(desk, "input", "server-state");
			dt_put_str(desk, "power", "unavailable");
			aik_json_obj_put(o, "desktop", desk);
		}
		dt_strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S");
		dt_put_str(o, "time", ts);
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		aik_json_free(obj);
		return 0;
	}
	if (strcmp(path, "/api/wallpaper") == 0) {
		aik_json *theme = dt_load_theme();
		aik_json *o = dt_new_obj();
		const aik_json *wp = dt_get(theme, "wallpaper");
		aik_json *avail = dt_list_wallpapers();

		dt_put_str(o, "current",
			   (wp && aik_json_typeof(wp) == AIK_JSON_STR)
				   ? aik_json_str(wp)
				   : "gradient");
		aik_json_obj_put(o, "available", avail);
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		aik_json_free(theme);
		return 0;
	}
	if (strcmp(path, "/api/chat/history") == 0) {
		char *sid = qs_get(query, "session");
		aik_json *msgs;
		aik_json *o;

		if (!sid)
			sid = strdup("default");
		if (!dt_regex_session(sid)) {
			aik_json *e = dt_new_obj();

			dt_put_str(e, "error", "bad session id");
			dt_resp_json(r, 400, e);
			aik_json_free(e);
			free(sid);
			return 0;
		}
		msgs = dt_load_chat(sid);
		if (msgs && aik_json_typeof(msgs) != AIK_JSON_ARR) {
			/* msgs[-40:] TypeError → 关连接 */
			aik_json_free(msgs);
			free(sid);
			return -1;
		}
		o = dt_new_obj();
		dt_put_str(o, "session", sid);
		{
			size_t n = aik_json_count(msgs);
			aik_json *tail = dt_new_arr();

			for (size_t i = n >= 40 ? n - 40 : 0; i < n; i++)
				dt_arr_push_copy(tail, aik_json_at(msgs, i));
			aik_json_obj_put(o, "messages", tail);
		}
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		aik_json_free(msgs);
		free(sid);
		return 0;
	}
	if (strcmp(path, "/api/apps") == 0) {
		int force = qs_has(query, "refresh");
		aik_json *apps = dt_get_apps(force);
		aik_json *o = dt_new_obj();

		dt_put_int(o, "count", (long long)aik_json_count(apps));
		dt_put_copy(o, "apps", apps);
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		return 0;
	}
	if (strcmp(path, "/api/theme") == 0) {
		aik_json *theme = dt_load_theme();

		if (!theme)
			return -1;
		dt_resp_json(r, 200, theme);
		aik_json_free(theme);
		return 0;
	}
	if (strcmp(path, "/api/stats") == 0) {
		aik_json *st = dt_read_proc_stats();
		aik_json *hist = dt_new_obj();

		pthread_mutex_lock(&g_lock_stats);
		{
			const aik_json *l1 = dt_get(st, "load1");
			const aik_json *m1 = dt_get(st, "mem_used_pct");

			dt_arr_push_copy(g_hist_load, l1);
			dt_arr_push_copy(g_hist_mem, m1);
		}
		{
			size_t nl = aik_json_count(g_hist_load);

			while (nl > 60) {
				aik_json *kept = dt_new_arr();

				for (size_t i = nl - 60; i < nl; i++)
					dt_arr_push_copy(
						kept,
						aik_json_at(g_hist_load, i));
				aik_json_free(g_hist_load);
				g_hist_load = kept;
				nl = aik_json_count(g_hist_load);
			}
		}
		{
			size_t nm = aik_json_count(g_hist_mem);

			while (nm > 60) {
				aik_json *kept = dt_new_arr();

				for (size_t i = nm - 60; i < nm; i++)
					dt_arr_push_copy(
						kept,
						aik_json_at(g_hist_mem, i));
				aik_json_free(g_hist_mem);
				g_hist_mem = kept;
				nm = aik_json_count(g_hist_mem);
			}
		}
		aik_json_obj_put(hist, "load", dt_copy(g_hist_load));
		aik_json_obj_put(hist, "mem", dt_copy(g_hist_mem));
		pthread_mutex_unlock(&g_lock_stats);
		aik_json_obj_put(st, "hist", hist);
		dt_resp_json(r, 200, st);
		aik_json_free(st);
		return 0;
	}
	if (strcmp(path, "/api/vm/ai") == 0) {
		aik_json *o = dt_new_obj();

		if (vm_disabled()) {
			dt_put_bool(o, "reachable", 0);
			dt_put_bool(o, "available", 0);
			dt_put_str(o, "error", VM_DISABLED_REASON);
			dt_resp_json(r, 200, o);
			aik_json_free(o);
			return 0;
		}
		aik_json_free(o);
		return route_vm_enabled(path, r);
	}
	if (strcmp(path, "/api/vm/aiops") == 0) {
		aik_json *o = dt_new_obj();

		if (vm_disabled()) {
			dt_put_bool(o, "reachable", 0);
			dt_put_bool(o, "available", 0);
			dt_put_int(o, "decisions_size", 0);
			dt_put_str(o, "decisions_raw", "");
			dt_put_bool(o, "decisions_empty", 1);
			dt_put_null(o, "events");
			aik_json_obj_set(o, "events", dt_new_arr());
			dt_put_int(o, "event_total_recent", 0);
			dt_put_str(o, "error", VM_DISABLED_REASON);
			dt_resp_json(r, 200, o);
			aik_json_free(o);
			return 0;
		}
		aik_json_free(o);
		return route_vm_enabled(path, r);
	}
	if (strcmp(path, "/api/notifs") == 0) {
		aik_json *arr = dt_read_json(g_cfg.notif_file);

		if (!arr) {
			arr = dt_new_arr();
			if (!arr)
				return -1;
		}
		dt_resp_json(r, 200, arr);
		aik_json_free(arr);
		return 0;
	}
	if (strcmp(path, "/api/pin/status") == 0) {
		aik_json *p = dt_load_pin();
		aik_json *o = dt_new_obj();
		long long now = dt_time();
		const aik_json *lock_v = dt_get(p, "lock_until");
		long long lock_until = 0;
		int locked;

		if (lock_v && aik_json_typeof(lock_v) == AIK_JSON_INT)
			lock_until = aik_json_int(lock_v);
		else if (lock_v && aik_json_typeof(lock_v) == AIK_JSON_NUM)
			lock_until = (long long)aik_json_num(lock_v);
		else if (lock_v)
			return -1; /* 比较 TypeError → 关连接 */
		locked = lock_until > now;
		{
			const aik_json *en = dt_get(p, "enabled");

			dt_put_bool(o, "enabled", dt_truthy(en));
		}
		dt_put_bool(o, "locked", locked);
		dt_put_int(o, "retry_after", locked ? lock_until - now : 0);
		{
			const aik_json *fails = dt_get(p, "fails");
			long long f = 0;

			if (fails && aik_json_typeof(fails) == AIK_JSON_INT)
				f = aik_json_int(fails);
			else if (fails && aik_json_typeof(fails) ==
						  AIK_JSON_NUM)
				f = (long long)aik_json_num(fails);
			else if (fails)
				return -1; /* int() TypeError → 关连接
					    */
			dt_put_int(o, "fails", f);
		}
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		aik_json_free(p);
		return 0;
	}
	if (strcmp(path, "/api/chat/sessions") == 0) {
		aik_json *sessions = dt_chat_sessions();
		aik_json *o = dt_new_obj();

		aik_json_obj_put(o, "sessions", sessions);
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		return 0;
	}
	if (strcmp(path, "/api/vm/status") == 0) {
		if (vm_disabled()) {
			aik_json *obj = dt_load_desktop();
			aik_json *o = dt_new_obj();
			const aik_json *wins = dt_get(obj, "windows");
			size_t nw = (wins && aik_json_typeof(wins) ==
						       AIK_JSON_ARR)
					    ? aik_json_count(wins)
					    : 0;

			dt_put_bool(o, "reachable", 0);
			dt_put_bool(o, "available", 0);
			dt_put_str(o, "mode", "local");
			dt_put_str(o, "error", VM_DISABLED_REASON);
			{
				aik_json *desk = dt_new_obj();

				dt_put_str(desk, "backend",
					   "web-demo-virtual-window");
				dt_put_int(desk, "windows", (long long)nw);
				aik_json_obj_put(o, "desktop", desk);
			}
			dt_put_str(o, "note",
				   "factory/VM 只提供本地桌面状态;L1 VM 隧道已禁用");
			dt_resp_json(r, 200, o);
			aik_json_free(o);
			aik_json_free(obj);
			return 0;
		}
		return route_vm_enabled(path, r);
	}
	if (strcmp(path, "/api/vm/tools") == 0) {
		if (vm_disabled()) {
			aik_json *o = dt_new_obj();

			dt_put_bool(o, "reachable", 0);
			dt_put_bool(o, "available", 0);
			dt_put_str(o, "error", VM_DISABLED_REASON);
			dt_put_null(o, "tools");
			aik_json_obj_set(o, "tools", dt_new_arr());
			dt_resp_json(r, 200, o);
			aik_json_free(o);
			return 0;
		}
		return route_vm_enabled(path, r);
	}
	if (strcmp(path, "/api/model") == 0) {
		aik_json *conf = dt_new_obj();
		aik_json *o = dt_new_obj();

		dt_read_model_conf(conf);
		dt_put_copy(o, "base_url", dt_get(conf, "base_url"));
		dt_put_copy(o, "model", dt_get(conf, "model_name"));
		dt_put_bool(o, "key_loaded", dt_truthy(dt_get(conf, "api_key")));
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		aik_json_free(conf);
		return 0;
	}
	if (strcmp(path, "/api/windows") == 0) {
		aik_json *snap;
		const aik_json *wp;
		const aik_json *cur;

		pthread_mutex_lock(&g_lock_desktop);
		{
			aik_json *obj = dt_load_desktop();

			if (!obj) {
				pthread_mutex_unlock(&g_lock_desktop);
				return -1;
			}
			snap = dt_desktop_snapshot(obj);
			aik_json_free(obj);
		}
		if (!snap) {
			pthread_mutex_unlock(&g_lock_desktop);
			return -1;
		}
		{
			aik_json *theme = dt_load_theme();

			wp = dt_get(theme, "wallpaper");
			cur = dt_get(theme, "current");
			{
				aik_json *t = dt_new_obj();

				dt_put_str(t, "current",
					   (cur && aik_json_typeof(cur) ==
							 AIK_JSON_STR)
						   ? aik_json_str(cur)
						   : "dark");
				aik_json_obj_put(snap, "theme", t);
			}
			aik_json_obj_put(snap, "wallpaper",
					 wp ? dt_copy(wp) : dt_new_str("gradient"));
			aik_json_free(theme);
		}
		pthread_mutex_unlock(&g_lock_desktop);
		dt_resp_json(r, 200, snap);
		aik_json_free(snap);
		return 0;
	}
	if (strcmp(path, "/api/screenshot") == 0) {
		/* factory 恒 503;200 路径 T7 形态断言 */
		aik_json *o = dt_new_obj();
		char msg[256];

		snprintf(msg, sizeof(msg),
			 "RuntimeError: screenshot unavailable: "
			 "playwright_unavailable (AIK_DESKTOP_SCREENSHOT=%s)",
			 g_cfg.screenshot_mode);
		dt_put_bool(o, "ok", 0);
		dt_put_str(o, "error", msg);
		dt_put_str(o, "backend", "playwright");
		dt_resp_json(r, 503, o);
		aik_json_free(o);
		return 0;
	}
	if (strcmp(path, "/api/clipboard") == 0) {
		aik_json *o = dt_new_obj();
		char *text;
		const aik_json *upd;

		pthread_mutex_lock(&g_lock_desktop);
		{
			aik_json *obj = dt_load_desktop();
			const aik_json *cv = dt_get(obj, "clipboard");

			text = (cv && aik_json_typeof(cv) == AIK_JSON_STR)
				       ? strdup(aik_json_str(cv))
				       : strdup("");
			upd = dt_get(obj, "clipboard_updated");
			if (!upd)
				upd = NULL;
			else
				upd = dt_copy(upd);
			aik_json_free(obj);
		}
		pthread_mutex_unlock(&g_lock_desktop);
		dt_put_str(o, "text", text);
		dt_put_int(o, "length",
			   (long long)dt_utf8_cplen(text, strlen(text)));
		{
			char sha[65];

			dt_sha256_hex(text, strlen(text), sha);
			dt_put_str(o, "sha256", sha);
		}
		dt_put_copy(o, "updated_at", upd);
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		aik_json_free((aik_json *)(uintptr_t)upd);
		free(text);
		return 0;
	}
	if (strcmp(path, "/api/chat") == 0) {
		if (qs_has(query, "fallback")) {
			/* GET ?fallback=<msg> 调试入口:强制演示应答 */
			return dt_route_chat_fallback(req, r);
		}
		dt_resp_json404(r);
		return 0;
	}
	dt_resp_json404(r);
	return 0;
}

/* ---------------- POST ---------------- */

static int post_theme(struct dt_req *req, struct dt_resp *r)
{
	aik_json *theme = dt_load_theme();

	if (!theme)
		return -1;
	if (body_has(req, "custom")) {
		const aik_json *c = body_get(req, "custom");
		aik_json *cobj = NULL;
		char *accent, *base;

		if (!c || !dt_truthy(c)) {
			cobj = dt_new_obj();
		} else if (aik_json_typeof(c) == AIK_JSON_OBJ) {
			cobj = (aik_json *)(uintptr_t)c;
		} else {
			/* c.get → AttributeError → 未捕获异常=关连接 */
			aik_json_free(theme);
			return -1;
		}
		{
			const aik_json *a = dt_get(cobj, "accent");
			const aik_json *b = dt_get(cobj, "base");

			accent = a ? dt_pystr(a) : strdup("");
			base = b ? dt_pystr(b) : strdup("dark");
		}
		if (cobj != c)
			aik_json_free(cobj);
		if (!dt_regex_hex6(accent)) {
			resp_err(r, 400, "accent 需为 #rrggbb 十六进制色");
			free(accent);
			free(base);
			aik_json_free(theme);
			return 0;
		}
		if (strcmp(base, "dark") != 0 && strcmp(base, "light") != 0) {
			resp_err(r, 400, "base 需为 dark|light");
			free(accent);
			free(base);
			aik_json_free(theme);
			return 0;
		}
		{
			aik_json *themes = dt_get_mut(theme, "themes");
			aik_json *custom_theme =
				dt_build_custom_theme(accent, base);

			if (!themes) {
				themes = dt_new_obj();
				aik_json_obj_set(theme, "themes", themes);
			}
			if (custom_theme) {
				aik_json_obj_set(themes, "custom",
						 custom_theme);
				aik_json_obj_set(theme, "current",
						 dt_new_str("custom"));
				dt_save_theme(theme);
				{
					aik_json *o = dt_new_obj();
					aik_json *resp_theme = dt_copy(
						dt_get(themes, "custom"));

					dt_put_bool(o, "ok", 1);
					dt_put_str(o, "current", "custom");
					aik_json_obj_put(o, "theme",
							 resp_theme);
					dt_resp_json(r, 200, o);
					aik_json_free(o);
				}
			}
		}
		free(accent);
		free(base);
		aik_json_free(theme);
		return 0;
	}
	if (body_has(req, "wallpaper")) {
		char *name = dt_pystr(body_get(req, "wallpaper"));

		if (!name)
			return -1;
		{
			aik_json *avail = dt_list_wallpapers();
			int ok = strcmp(name, "gradient") == 0;

			if (!ok)
				for (size_t i = 0; i < aik_json_count(avail);
				     i++) {
					const aik_json *w =
						aik_json_at(avail, i);

					if (aik_json_typeof(w) ==
						    AIK_JSON_STR &&
					    strcmp(aik_json_str(w), name) ==
						    0) {
						ok = 1;
						break;
					}
				}
			if (!ok) {
				char msg[256];

				snprintf(msg, sizeof(msg), "未知壁纸: %s",
					 name);
				resp_err3(r, 400, msg, "available", avail);
				aik_json_free(avail);
				free(name);
				aik_json_free(theme);
				return 0;
			}
			aik_json_free(avail);
		}
		aik_json_obj_set(theme, "wallpaper", dt_new_str(name));
		dt_save_theme(theme);
		{
			aik_json *o = dt_new_obj();

			dt_put_bool(o, "ok", 1);
			dt_put_str(o, "wallpaper", name);
			dt_resp_json(r, 200, o);
			aik_json_free(o);
		}
		free(name);
		aik_json_free(theme);
		return 0;
	}
	{
		char *name = body_get_str(req, "name", "");
		const aik_json *themes = dt_get(theme, "themes");

		if (!themes || aik_json_typeof(themes) != AIK_JSON_OBJ)
			themes = NULL;
		if (themes && aik_json_get(themes, name)) {
			aik_json_obj_set(theme, "current", dt_new_str(name));
			dt_save_theme(theme);
			{
				aik_json *o = dt_new_obj();
				aik_json *resp_theme =
					dt_copy(aik_json_get(themes, name));

				dt_put_bool(o, "ok", 1);
				dt_put_str(o, "current", name);
				aik_json_obj_put(o, "theme", resp_theme);
				dt_resp_json(r, 200, o);
				aik_json_free(o);
			}
		} else {
			char msg[128];
			aik_json *avail = themes ? dt_copy(themes) : dt_new_obj();

			/* sorted(theme.get("themes", {})):按键排序取数组 */
			{
				aik_json *keys = dt_new_arr();
				size_t n = aik_json_count(avail);
				const char **ks =
					malloc((n ? n : 1) * sizeof(*ks));

				for (size_t i = 0; i < n; i++)
					ks[i] = aik_json_key_at(avail, i);
				for (size_t i = 1; i < n; i++) {
					const char *key = ks[i];
					size_t j = i;

					while (j > 0 && strcmp(ks[j - 1], key) >
							 0) {
						ks[j] = ks[j - 1];
						j--;
					}
					ks[j] = key;
				}
				for (size_t i = 0; i < n; i++)
					dt_arr_push_str(keys, ks[i]);
				free(ks);
				aik_json_free(avail);
				avail = keys;
			}
			snprintf(msg, sizeof(msg), "unknown theme: %s", name);
			resp_err3(r, 400, msg, "available", avail);
			aik_json_free(avail);
		}
		free(name);
		aik_json_free(theme);
		return 0;
	}
}

static int post_wallpaper(struct dt_req *req, struct dt_resp *r)
{
	char *name = body_get_str(req, "wallpaper", "");
	aik_json *avail = dt_list_wallpapers();
	int ok = strcmp(name, "gradient") == 0;

	if (!ok)
		for (size_t i = 0; i < aik_json_count(avail); i++) {
			const aik_json *w = aik_json_at(avail, i);

			if (aik_json_typeof(w) == AIK_JSON_STR &&
			    strcmp(aik_json_str(w), name) == 0) {
				ok = 1;
				break;
			}
		}
	if (!ok) {
		char msg[256];

		snprintf(msg, sizeof(msg), "未知壁纸: %s", name);
		resp_err3(r, 400, msg, "available", avail);
		aik_json_free(avail);
		free(name);
		return 0;
	}
	aik_json_free(avail);
	{
		aik_json *theme = dt_load_theme();

		if (!theme) {
			free(name);
			return -1;
		}
		aik_json_obj_set(theme, "wallpaper", dt_new_str(name));
		dt_save_theme(theme);
		aik_json_free(theme);
	}
	{
		aik_json *o = dt_new_obj();

		dt_put_bool(o, "ok", 1);
		dt_put_str(o, "wallpaper", name);
		dt_resp_json(r, 200, o);
		aik_json_free(o);
	}
	free(name);
	return 0;
}

static int post_chat_rename(struct dt_req *req, struct dt_resp *r)
{
	char *sid = body_get_str(req, "session", "");
	char *title_raw = body_get_str(req, "title", "");
	char *title_stripped = dt_strip(title_raw);
	char *title;
	char *path;
	aik_json *o;

	free(title_raw);
	title = dt_utf8_head(title_stripped, 40);
	free(title_stripped);
	path = dt_chat_path(sid, ".json");
	if (!path || !title) {
		free(path);
		free(title);
		free(sid);
		return -1;
	}
	if (!dt_regex_session(sid) || !dt_is_file(path)) {
		resp_err(r, 400, "会话不存在");
		free(path);
		free(title);
		free(sid);
		return 0;
	}
	free(path);
	if (!*title) {
		resp_err(r, 400, "标题不能为空");
		free(title);
		free(sid);
		return 0;
	}
	{
		aik_json *m = dt_new_obj();
		char *text;
		size_t n;
		char *meta = dt_chat_path(sid, ".meta.json");

		if (!meta) {
			free(title);
			free(sid);
			return -1;
		}
		dt_put_str(m, "title", title);
		text = dt_json_dump_default(m);
		aik_json_free(m);
		if (!text) {
			free(title);
			free(sid);
			return -1;
		}
		n = strlen(text);
		/* 非原子直写 + 写后 chmod 0600 */
		if (dt_write_file(meta, text, n) == 0)
			chmod(meta, 0600);
		free(text);
		free(meta);
	}
	o = dt_new_obj();
	dt_put_bool(o, "ok", 1);
	dt_put_str(o, "session", sid);
	dt_put_str(o, "title", title);
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	free(title);
	free(sid);
	return 0;
}

static int post_chat_delete(struct dt_req *req, struct dt_resp *r)
{
	char *sid = body_get_str(req, "session", "");
	int removed = 0;

	if (!dt_regex_session(sid)) {
		resp_err(r, 400, "非法会话 id");
		free(sid);
		return 0;
	}
	{
		static const char *suffixes[2] = { ".json", ".meta.json" };

		for (int i = 0; i < 2; i++) {
			char *p = dt_chat_path(sid, suffixes[i]);

			if (!p)
				continue;
			if (dt_is_file(p)) {
				unlink(p);
				removed = 1;
			}
			free(p);
		}
	}
	{
		aik_json *o = dt_new_obj();

		dt_put_bool(o, "ok", removed);
		dt_put_str(o, "session", sid);
		dt_resp_json(r, 200, o);
		aik_json_free(o);
	}
	free(sid);
	return 0;
}

static int post_notifs(struct dt_req *req, struct dt_resp *r)
{
	aik_json *notifs = NULL;

	if (body_has(req, "notifs")) {
		const aik_json *v = body_get(req, "notifs");

		if (!v || aik_json_typeof(v) != AIK_JSON_ARR) {
			resp_err(r, 400, "notifs 需为数组");
			return 0;
		}
		notifs = dt_copy(v);
		/* notifs[:100] 丢尾 */
		{
			size_t n = aik_json_count(notifs);

			if (n > 100) {
				aik_json *kept = dt_new_arr();

				for (size_t i = 0; i < 100; i++)
					dt_arr_push_copy(kept,
							 aik_json_at(notifs, i));
				aik_json_free(notifs);
				notifs = kept;
			}
		}
	} else {
		int bad = 0;
		aik_json *entry = dt_notif_new_entry(req->json, &bad);

		if (bad == 1) {
			resp_err(r, 400, "title/body 需为字符串");
			return 0;
		}
		if (bad == 2) {
			resp_err(r, 400, "title 不能为空");
			return 0;
		}
		if (!entry)
			return -1;
		/* 读旧(坏 → [];非 list 置 [])→ append → [-100:] 保尾 */
		notifs = dt_read_json(g_cfg.notif_file);
		if (!notifs || aik_json_typeof(notifs) != AIK_JSON_ARR) {
			aik_json_free(notifs);
			notifs = dt_new_arr();
		}
		aik_json_arr_push(notifs, entry);
		{
			size_t n = aik_json_count(notifs);

			if (n > 100) {
				aik_json *kept = dt_new_arr();

				for (size_t i = n - 100; i < n; i++)
					dt_arr_push_copy(
						kept, aik_json_at(notifs, i));
				aik_json_free(notifs);
				notifs = kept;
			}
		}
	}
	{
		aik_json *o = dt_new_obj();

		dt_write_json_default_atomic(g_cfg.notif_file, notifs);
		dt_put_bool(o, "ok", 1);
		dt_put_int(o, "count", (long long)aik_json_count(notifs));
		dt_resp_json(r, 200, o);
		aik_json_free(o);
	}
	aik_json_free(notifs);
	return 0;
}

static int post_pin_set(struct dt_req *req, struct dt_resp *r)
{
	char *pin = body_get_str(req, "pin", "");
	char *warning;
	aik_json *p;
	char rand_repr[40];
	char salt[33];
	char hash_input[512];
	char hash[65];
	aik_json *o;

	if (!dt_regex_pin(pin)) {
		resp_err(r, 400, "PIN 需为 4-8 位数字");
		free(pin);
		return 0;
	}
	warning = dt_pin_warning(pin);
	p = dt_load_pin();
	aik_json_dtoa(dt_random(), rand_repr, sizeof(rand_repr));
	dt_md5_hex(rand_repr, strlen(rand_repr), salt);
	salt[12] = '\0';
	snprintf(hash_input, sizeof(hash_input), "%s:%s", salt, pin);
	dt_sha256_hex(hash_input, strlen(hash_input), hash);
	/* 赋值顺序 salt → hash → enabled → fails → lock_until(已有键原位) */
	aik_json_obj_set(p, "salt", dt_new_str(salt));
	aik_json_obj_set(p, "hash", dt_new_str(hash));
	aik_json_obj_set(p, "enabled", dt_new_bool(1));
	aik_json_obj_set(p, "fails", dt_new_int(0));
	aik_json_obj_set(p, "lock_until", dt_new_int(0));
	dt_save_pin(p);
	aik_json_free(p);
	dt_log("PIN 已设置(仅存 hash)");
	o = dt_new_obj();
	dt_put_bool(o, "ok", 1);
	dt_put_bool(o, "enabled", 1);
	if (warning)
		dt_put_str(o, "warning", warning);
	else
		dt_put_null(o, "warning");
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	free(warning);
	free(pin);
	return 0;
}

static int post_pin_clear(struct dt_req *req, struct dt_resp *r)
{
	aik_json *p = dt_load_pin();
	aik_json *o;

	(void)req;
	/* p.enabled=False; fails=0; lock_until=0; pop hash/salt(键序保位) */
	{
		aik_json *clean = dt_new_obj();
		size_t n = aik_json_count(p);

		for (size_t i = 0; i < n; i++) {
			const char *k = aik_json_key_at(p, i);

			if (strcmp(k, "hash") == 0 || strcmp(k, "salt") == 0)
				continue;
			aik_json_obj_put(clean, k,
					 dt_copy(aik_json_val_at(p, i)));
		}
		aik_json_free(p);
		p = clean;
	}
	aik_json_obj_set(p, "enabled", dt_new_bool(0));
	aik_json_obj_set(p, "fails", dt_new_int(0));
	aik_json_obj_set(p, "lock_until", dt_new_int(0));
	dt_save_pin(p);
	o = dt_new_obj();
	dt_put_bool(o, "ok", 1);
	dt_put_bool(o, "enabled", 0);
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	aik_json_free(p);
	return 0;
}

static int post_pin_verify(struct dt_req *req, struct dt_resp *r)
{
	char *pin = body_get_str(req, "pin", "");
	aik_json *p = dt_load_pin();
	long long now = dt_time();
	aik_json *o;

	if (!dt_truthy(dt_get(p, "enabled"))) {
		o = dt_new_obj();
		dt_put_bool(o, "ok", 1);
		dt_put_bool(o, "enabled", 0);
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		aik_json_free(p);
		free(pin);
		return 0;
	}
	{
		const aik_json *lock_v = dt_get(p, "lock_until");
		long long lock_until = 0;

		if (lock_v && aik_json_typeof(lock_v) == AIK_JSON_INT)
			lock_until = aik_json_int(lock_v);
		else if (lock_v && aik_json_typeof(lock_v) == AIK_JSON_NUM)
			lock_until = (long long)aik_json_num(lock_v);
		else if (lock_v) {
			aik_json_free(p);
			free(pin);
			return -1; /* 比较 TypeError → 关连接 */
		}
		if (lock_until > now) {
			o = dt_new_obj();
			dt_put_bool(o, "ok", 0);
			dt_put_bool(o, "locked", 1);
			dt_put_int(o, "retry_after", lock_until - now);
			dt_resp_json(r, 200, o);
			aik_json_free(o);
			aik_json_free(p);
			free(pin);
			return 0;
		}
	}
	{
		const aik_json *salt_v = dt_get(p, "salt");
		char *salt;
		char hash_input[512];
		char hash[65];
		const aik_json *stored;

		if (salt_v && aik_json_typeof(salt_v) != AIK_JSON_STR) {
			aik_json_free(p);
			free(pin);
			return -1; /* 拼接 TypeError → 关连接 */
		}
		salt = salt_v ? strdup(aik_json_str(salt_v)) : strdup("");
		snprintf(hash_input, sizeof(hash_input), "%s:%s", salt, pin);
		dt_sha256_hex(hash_input, strlen(hash_input), hash);
		free(salt);
		stored = dt_get(p, "hash");
		if (stored && aik_json_typeof(stored) == AIK_JSON_STR &&
		    strcmp(aik_json_str(stored), hash) == 0) {
			aik_json_obj_set(p, "fails", dt_new_int(0));
			dt_save_pin(p);
			o = dt_new_obj();
			dt_put_bool(o, "ok", 1);
			dt_resp_json(r, 200, o);
			aik_json_free(o);
		} else {
			const aik_json *fails_v = dt_get(p, "fails");
			long long fails = 0;

			if (fails_v && aik_json_typeof(fails_v) ==
					       AIK_JSON_INT)
				fails = aik_json_int(fails_v);
			else if (fails_v && aik_json_typeof(fails_v) ==
							AIK_JSON_NUM)
				fails = (long long)aik_json_num(fails_v);
			else if (fails_v) {
				aik_json_free(p);
				free(pin);
				return -1; /* + TypeError → 关连接 */
			}
			fails += 1;
			aik_json_obj_set(p, "fails", dt_new_int(fails));
			if (fails >= 3) {
				aik_json_obj_set(p, "lock_until",
						 dt_new_int(now + 30));
				aik_json_obj_set(p, "fails", dt_new_int(0));
				o = dt_new_obj();
				dt_put_bool(o, "ok", 0);
				dt_put_bool(o, "locked", 1);
				dt_put_int(o, "retry_after", 30);
			} else {
				o = dt_new_obj();
				dt_put_bool(o, "ok", 0);
				dt_put_int(o, "fails", fails);
			}
			dt_save_pin(p);
			dt_resp_json(r, 200, o);
			aik_json_free(o);
		}
	}
	aik_json_free(p);
	free(pin);
	return 0;
}

static int post_chat_new(struct dt_req *req, struct dt_resp *r)
{
	char *sid = dt_new_session_id();
	aik_json *entry = dt_new_obj();
	char ts[32];
	aik_json *o;

	(void)req;
	if (!sid || !entry) {
		free(sid);
		aik_json_free(entry);
		return -1;
	}
	dt_strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S");
	dt_put_str(entry, "role", "system");
	dt_put_str(entry, "content", "会话开始");
	dt_put_str(entry, "ts", ts);
	dt_append_chat(sid, entry);
	o = dt_new_obj();
	dt_put_bool(o, "ok", 1);
	dt_put_str(o, "session", sid);
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	free(sid);
	return 0;
}

static int post_vm_act(struct dt_req *req, struct dt_resp *r)
{
	/* VM_ACT_WHITELIST = 空集 → 恒 403(向量逐字节) */
	aik_json *o = dt_new_obj();

	(void)req;
	dt_put_bool(o, "ok", 0);
	dt_put_str(o, "error",
		   "VM /act 实测为 W 级参数写端点,GUI 演示阶段按红线不开放任何写;"
		   "隔离区视图已改为 SSH 只读实现");
	dt_put_str(o, "hint", "用对话「看一眼隔离区」体验只读视图");
	dt_resp_json(r, 403, o);
	aik_json_free(o);
	return 0;
}

static aik_json *find_app(const char *app_id)
{
	aik_json *apps = dt_get_apps(0);

	for (size_t i = 0; i < aik_json_count(apps); i++) {
		const aik_json *a = aik_json_at(apps, i);
		const aik_json *id = aik_json_get(a, "id");

		if (id && aik_json_typeof(id) == AIK_JSON_STR &&
		    strcmp(aik_json_str(id), app_id) == 0)
			return (aik_json *)(uintptr_t)a;
	}
	return NULL;
}

static int post_apps_launch(struct dt_req *req, struct dt_resp *r)
{
	char *app_id = body_get_str(req, "app", "");
	aik_json *app;
	aik_json *obj;
	aik_json *win;
	int created = 0;
	aik_json *snap;
	aik_json *o;

	if (!dt_regex_app_id(app_id)) {
		resp_err(r, 400, "app 参数非法");
		free(app_id);
		return 0;
	}
	app = find_app(app_id);
	if (!app) {
		char msg[256];

		snprintf(msg, sizeof(msg), "未知应用: %s", app_id);
		resp_err(r, 404, msg);
		free(app_id);
		return 0;
	}
	pthread_mutex_lock(&g_lock_desktop);
	obj = dt_load_desktop();
	if (!obj) {
		pthread_mutex_unlock(&g_lock_desktop);
		free(app_id);
		return -1;
	}
	win = dt_window_launch(obj, app, &created);
	dt_save_desktop(obj);
	snap = dt_desktop_snapshot(obj);
	pthread_mutex_unlock(&g_lock_desktop);
	if (!win || !snap) {
		aik_json_free(snap);
		aik_json_free(obj);
		free(app_id);
		return -1;
	}
	o = dt_new_obj();
	dt_put_bool(o, "ok", 1);
	dt_put_bool(o, "created", created);
	{
		const aik_json *wid = dt_get(win, "id");

		dt_put_str(o, "window_id",
			   (wid && aik_json_typeof(wid) == AIK_JSON_STR)
				   ? aik_json_str(wid)
				   : "");
	}
	dt_put_copy(o, "window", win);
	dt_put_copy(o, "focused", dt_get(snap, "focused"));
	dt_put_str(o, "backend", "web-demo-virtual-window");
	dt_put_str(o, "note", "Web demo 虚拟窗口;未启动宿主进程(W84)");
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	aik_json_free(snap);
	aik_json_free(obj);
	free(app_id);
	return 0;
}

static int post_apps_close(struct dt_req *req, struct dt_resp *r)
{
	char *app_id = body_get_str(req, "app", "");
	char *wid = body_get_str(req, "id", "");
	aik_json *obj, *snap, *o;
	aik_json *closed, *keep;
	int nclosed = 0;

	if (!dt_regex_app_id(app_id) && !dt_regex_win_id(wid)) {
		resp_err(r, 400, "需要合法 app 或 id");
		free(app_id);
		free(wid);
		return 0;
	}
	pthread_mutex_lock(&g_lock_desktop);
	obj = dt_load_desktop();
	if (!obj) {
		pthread_mutex_unlock(&g_lock_desktop);
		free(app_id);
		free(wid);
		return -1;
	}
	closed = dt_new_arr();
	keep = dt_new_arr();
	{
		aik_json *wins = dt_get_mut(obj, "windows");

		if (wins && aik_json_typeof(wins) == AIK_JSON_ARR) {
			size_t n = aik_json_count(wins);

			for (size_t i = 0; i < n; i++) {
				const aik_json *w = aik_json_at(wins, i);
				const aik_json *wa = dt_get(w, "app");
				const aik_json *wv = dt_get(w, "id");
				int hit = 0;

				if (*app_id && wa &&
				    aik_json_typeof(wa) == AIK_JSON_STR &&
				    strcmp(aik_json_str(wa), app_id) == 0)
					hit = 1;
				if (!hit && *wid && wv &&
				    aik_json_typeof(wv) == AIK_JSON_STR &&
				    strcmp(aik_json_str(wv), wid) == 0)
					hit = 1;
				if (hit) {
					dt_arr_push_copy(closed, wv);
					nclosed++;
				} else {
					dt_arr_push_copy(keep, w);
				}
			}
		}
	}
	if (nclosed == 0) {
		resp_err(r, 404, "没有匹配的窗口");
		aik_json_free(closed);
		aik_json_free(keep);
		aik_json_free(obj);
		pthread_mutex_unlock(&g_lock_desktop);
		free(app_id);
		free(wid);
		return 0;
	}
	aik_json_obj_set(obj, "windows", keep);
	dt_top_focus(obj);
	dt_save_desktop(obj);
	snap = dt_desktop_snapshot(obj);
	pthread_mutex_unlock(&g_lock_desktop);
	o = dt_new_obj();
	dt_put_bool(o, "ok", 1);
	aik_json_obj_put(o, "closed", closed);
	dt_put_int(o, "count", nclosed);
	dt_put_copy(o, "focused", dt_get(snap, "focused"));
	dt_put_int(o, "windows", aik_json_count(dt_get(snap, "windows")));
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	aik_json_free(snap);
	aik_json_free(obj);
	free(app_id);
	free(wid);
	return 0;
}

static int post_windows_focus(struct dt_req *req, struct dt_resp *r)
{
	char *wid = body_get_str(req, "id", "");
	aik_json *obj, *snap, *o;

	if (!dt_regex_win_id(wid)) {
		resp_err(r, 400, "window id 非法");
		free(wid);
		return 0;
	}
	pthread_mutex_lock(&g_lock_desktop);
	obj = dt_load_desktop();
	if (!obj) {
		pthread_mutex_unlock(&g_lock_desktop);
		free(wid);
		return -1;
	}
	if (!dt_find_window(obj, wid)) {
		char msg[128];

		snprintf(msg, sizeof(msg), "窗口不存在: %s", wid);
		resp_err(r, 404, msg);
		aik_json_free(obj);
		pthread_mutex_unlock(&g_lock_desktop);
		free(wid);
		return 0;
	}
	dt_focus_window(obj, wid);
	dt_save_desktop(obj);
	snap = dt_desktop_snapshot(obj);
	pthread_mutex_unlock(&g_lock_desktop);
	o = dt_new_obj();
	dt_put_bool(o, "ok", 1);
	dt_put_str(o, "id", wid);
	dt_put_copy(o, "focused", dt_get(snap, "focused"));
	dt_put_int(o, "windows", aik_json_count(dt_get(snap, "windows")));
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	aik_json_free(snap);
	aik_json_free(obj);
	free(wid);
	return 0;
}

static int post_windows_close(struct dt_req *req, struct dt_resp *r)
{
	char *wid = body_get_str(req, "id", "");
	aik_json *obj, *snap, *o;

	if (!dt_regex_win_id(wid)) {
		resp_err(r, 400, "window id 非法");
		free(wid);
		return 0;
	}
	pthread_mutex_lock(&g_lock_desktop);
	obj = dt_load_desktop();
	if (!obj) {
		pthread_mutex_unlock(&g_lock_desktop);
		free(wid);
		return -1;
	}
	if (!dt_find_window(obj, wid)) {
		char msg[128];

		snprintf(msg, sizeof(msg), "窗口不存在: %s", wid);
		resp_err(r, 404, msg);
		aik_json_free(obj);
		pthread_mutex_unlock(&g_lock_desktop);
		free(wid);
		return 0;
	}
	{
		aik_json *wins = dt_get_mut(obj, "windows");
		aik_json *keep = dt_new_arr();

		if (wins && aik_json_typeof(wins) == AIK_JSON_ARR) {
			size_t n = aik_json_count(wins);

			for (size_t i = 0; i < n; i++) {
				const aik_json *w = aik_json_at(wins, i);
				const aik_json *wv = dt_get(w, "id");

				if (wv && aik_json_typeof(wv) ==
						   AIK_JSON_STR &&
				    strcmp(aik_json_str(wv), wid) == 0)
					continue;
				dt_arr_push_copy(keep, w);
			}
		}
		aik_json_obj_set(obj, "windows", keep);
	}
	dt_top_focus(obj);
	dt_save_desktop(obj);
	snap = dt_desktop_snapshot(obj);
	pthread_mutex_unlock(&g_lock_desktop);
	o = dt_new_obj();
	dt_put_bool(o, "ok", 1);
	dt_put_str(o, "closed", wid);
	dt_put_copy(o, "focused", dt_get(snap, "focused"));
	dt_put_int(o, "windows", aik_json_count(dt_get(snap, "windows")));
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	aik_json_free(snap);
	aik_json_free(obj);
	free(wid);
	return 0;
}

/* key 允许集(_KEY_NAMES) */
static int key_allowed(const char *key)
{
	static const char *names[] = {
		"Enter",	  "Backspace",      "Tab",
		"Escape",	  "Delete",	      "Home",
		"End",		  "PageUp",	      "PageDown",
		"ArrowUp",	  "ArrowDown",      "ArrowLeft",
		"ArrowRight", "F1", "F2",  "F3",  "F4",  "F5",  "F6",
		"F7", "F8",  "F9",  "F10", "F11", "F12",
	};

	if (strlen(key) == 1)
		return 1;
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		if (strcmp(key, names[i]) == 0)
			return 1;
	return 0;
}

/* modifiers:None/"" → [];str 逗号拆分;list 逐元素 str().strip().lower();
 * 返回 NULL = 400;数组所有权归调用者 */
static aik_json *validate_modifiers(const aik_json *mods)
{
	aik_json *out;

	if (!mods || aik_json_typeof(mods) == AIK_JSON_NULL)
		return dt_new_arr();
	if (aik_json_typeof(mods) == AIK_JSON_STR &&
	    aik_json_strlen(mods) == 0)
		return dt_new_arr();
	if (aik_json_typeof(mods) == AIK_JSON_STR) {
		/* "m1,m2" 拆分,strip+lower,空段丢弃 */
		const char *s = aik_json_str(mods);
		size_t i = 0, len = strlen(s);

		out = dt_new_arr();
		if (!out)
			return NULL;
		while (i <= len) {
			size_t seg = i;

			while (seg < len && s[seg] != ',')
				seg++;
			if (seg > i) {
				char *raw = malloc(seg - i + 1);
				char *stripped;
				char *low;

				if (!raw)
					break;
				memcpy(raw, s + i, seg - i);
				raw[seg - i] = '\0';
				stripped = dt_strip(raw);
				free(raw);
				low = utf8_lower(stripped);
				free(stripped);
				if (low && *low) {
					if (!mod_name_ok(low)) {
						free(low);
						aik_json_free(out);
						return NULL;
					}
					dt_arr_push_str(out, low);
				}
				free(low);
			}
			if (seg >= len)
				break;
			i = seg + 1;
		}
		return out;
	}
	if (aik_json_typeof(mods) == AIK_JSON_ARR) {
		size_t n = aik_json_count(mods);

		out = dt_new_arr();
		if (!out)
			return NULL;
		for (size_t i = 0; i < n; i++) {
			char *py = dt_pystr(aik_json_at(mods, i));
			char *stripped = py ? dt_strip(py) : NULL;
			char *low = stripped ? utf8_lower(stripped) : NULL;

			free(py);
			free(stripped);
			if (!low)
				return NULL;
			if (!*low || !mod_name_ok(low)) {
				free(low);
				aik_json_free(out);
				return NULL;
			}
			dt_arr_push_str(out, low);
			free(low);
		}
		return out;
	}
	return NULL; /* 非 str/list → 400 */
}

static int mod_name_ok(const char *m)
{
	return strcmp(m, "ctrl") == 0 || strcmp(m, "alt") == 0 ||
	       strcmp(m, "shift") == 0 || strcmp(m, "meta") == 0;
}

static char *utf8_lower(const char *s)
{
	char *out = strdup(s);

	if (!out)
		return NULL;
	for (char *p = out; *p; p++)
		if (*p >= 'A' && *p <= 'Z')
			*p = (char)(*p - 'A' + 'a');
	return out;
}

static int post_input(struct dt_req *req, struct dt_resp *r)
{
	char *kind = body_get_str(req, "type", "");
	aik_json *mods;
	aik_json *obj, *win, *o;
	char *before = NULL;
	long long changed = 0;
	const aik_json *focus;

	if (strcmp(kind, "type") != 0 && strcmp(kind, "key") != 0) {
		resp_err(r, 400, "type 需为 type|key");
		free(kind);
		return 0;
	}
	mods = validate_modifiers(body_get(req, "modifiers"));
	if (!mods) {
		resp_err(r, 400, "modifiers 仅支持 ctrl/alt/shift/meta");
		free(kind);
		return 0;
	}
	free(kind);
	pthread_mutex_lock(&g_lock_desktop);
	obj = dt_load_desktop();
	if (!obj) {
		pthread_mutex_unlock(&g_lock_desktop);
		aik_json_free(mods);
		return -1;
	}
	focus = dt_get(obj, "focused");
	win = NULL;
	if (focus && aik_json_typeof(focus) == AIK_JSON_STR)
		win = dt_find_window(obj, aik_json_str(focus));
	if (!win) {
		resp_err(r, 409, "no focused window");
		aik_json_free(obj);
		pthread_mutex_unlock(&g_lock_desktop);
		aik_json_free(mods);
		return 0;
	}
	{
		const aik_json *tv = dt_get(win, "text");

		if (!tv || aik_json_typeof(tv) == AIK_JSON_NULL)
			before = strdup("");
		else if (aik_json_typeof(tv) == AIK_JSON_STR)
			before = strdup(aik_json_str(tv));
		else {
			/* before 取值即 TypeError(win.get ok,但 append 内)
			 * — Python before = win.get("text","") or "" 对非字符串
			 * 取原值,len()/拼接在 append;此处非 str → 连接前不炸,
			 * type 分支 isinstance 通过后 _window_text_append 内炸 */
			before = strdup(""); /* 简化:后续 append 关连接 */
		}
	}
	{
		char *kind2 = body_get_str(req, "type", "");

		if (strcmp(kind2, "type") == 0) {
			const aik_json *text_v = body_get(req, "text");

			if (!text_v || aik_json_typeof(text_v) !=
					       AIK_JSON_STR) {
				resp_err(r, 400, "text 需为字符串");
				free(kind2);
				free(before);
				aik_json_free(obj);
				pthread_mutex_unlock(&g_lock_desktop);
				aik_json_free(mods);
				return 0;
			}
			if (dt_utf8_cplen(aik_json_str(text_v),
					  aik_json_strlen(text_v)) > 4096) {
				resp_err(r, 400, "text 超长(>4096)");
				free(kind2);
				free(before);
				aik_json_free(obj);
				pthread_mutex_unlock(&g_lock_desktop);
				aik_json_free(mods);
				return 0;
			}
			changed = dt_window_text_append(
				win, aik_json_str(text_v));
			if (changed < 0) {
				/* 非法已有 text → TypeError 等价关连接 */
				free(kind2);
				free(before);
				aik_json_free(obj);
				pthread_mutex_unlock(&g_lock_desktop);
				aik_json_free(mods);
				return -1;
			}
		} else {
			char *key = body_get_str(req, "key", "");
			int key_bad = 0;

			if (!key || !*key) {
				key_bad = 1;
				resp_err(r, 400, "key 不能为空");
			} else if (!key_allowed(key)) {
				key_bad = 1;
				resp_err(r, 400, "key 不在允许集");
			}
			if (key_bad) {
				free(key);
				free(kind2);
				free(before);
				aik_json_free(obj);
				pthread_mutex_unlock(&g_lock_desktop);
				aik_json_free(mods);
				return 0;
			}
			aik_json_obj_set(win, "last_key", dt_new_str(key));
			aik_json_obj_set(win, "last_modifiers",
					 dt_copy(mods));
			{
				int ctrl = 0;

				for (size_t i = 0; i < aik_json_count(mods);
				     i++) {
					const aik_json *m = aik_json_at(mods, i);

					if (aik_json_typeof(m) ==
						    AIK_JSON_STR &&
					    strcmp(aik_json_str(m), "ctrl") ==
						    0)
						ctrl = 1;
				}
				char *key_low = utf8_lower(key);

				if (ctrl && (strcmp(key_low, "l") == 0 ||
					     strcmp(key_low, "u") == 0)) {
					aik_json_obj_set(win, "text",
							 dt_new_str(""));
					changed = 1;
				} else if (strcmp(key, "Backspace") == 0 ||
					   strcmp(key, "Delete") == 0) {
					const aik_json *tv = dt_get(win,
								    "text");

					if (tv &&
					    aik_json_typeof(tv) ==
						    AIK_JSON_STR &&
					    aik_json_strlen(tv) > 0) {
						char *chopped =
							dt_utf8_chop_last(
								aik_json_str(
									tv));
						aik_json_obj_set(
							win, "text",
							dt_new_str(chopped));
						free(chopped);
						changed = 1;
					}
				} else if (strcmp(key, "Enter") == 0) {
					changed = dt_window_text_append(win,
									"\n");
				} else if (strcmp(key, "Tab") == 0) {
					changed = dt_window_text_append(win,
									"\t");
				} else if (strlen(key) == 1) {
					changed = dt_window_text_append(win,
									key);
				}
				free(key_low);
			}
			{
				char ts[32];

				dt_strftime(ts, sizeof(ts),
					    "%Y-%m-%d %H:%M:%S");
				aik_json_obj_set(win, "updated",
						 dt_new_str(ts));
			}
			free(key);
		}
		free(kind2);
	}
	if (changed < 0) {
		free(before);
		aik_json_free(obj);
		pthread_mutex_unlock(&g_lock_desktop);
		aik_json_free(mods);
		return -1;
	}
	dt_save_desktop(obj);
	{
		const aik_json *after_v = dt_get(win, "text");
		char *after = (after_v &&
			       aik_json_typeof(after_v) == AIK_JSON_STR)
				      ? strdup(aik_json_str(after_v))
				      : strdup("");
		const aik_json *wid = dt_get(win, "id");

		o = dt_new_obj();
		dt_put_bool(o, "ok", 1);
		dt_put_str(o, "window_id",
			   (wid && aik_json_typeof(wid) == AIK_JSON_STR)
				   ? aik_json_str(wid)
				   : "");
		{
			aik_json *inp = dt_new_obj();
			char *kind3 = body_get_str(req, "type", "");

			dt_put_str(inp, "type", kind3);
			dt_put_copy(inp, "text", body_get(req, "text"));
			dt_put_copy(inp, "key", body_get(req, "key"));
			aik_json_obj_put(inp, "modifiers", dt_copy(mods));
			aik_json_obj_put(o, "input", inp);
			free(kind3);
		}
		dt_put_int(o, "changed", changed);
		dt_put_str(o, "text_before", before);
		dt_put_str(o, "text_after", after);
		dt_put_int(o, "length",
			   (long long)dt_utf8_cplen(after, strlen(after)));
		dt_put_copy(o, "last_key", dt_get(win, "last_key"));
		dt_resp_json(r, 200, o);
		aik_json_free(o);
		free(after);
	}
	free(before);
	aik_json_free(obj);
	pthread_mutex_unlock(&g_lock_desktop);
	aik_json_free(mods);
	return 0;
}

static int post_clipboard(struct dt_req *req, struct dt_resp *r)
{
	const aik_json *text_v = body_get(req, "text");
	char *text;
	char *prev;
	aik_json *obj, *o;
	char sha[65], psha[65];
	char ts[32];

	if (!text_v || aik_json_typeof(text_v) != AIK_JSON_STR) {
		resp_err(r, 400, "text 需为字符串");
		return 0;
	}
	text = strdup(aik_json_str(text_v));
	if (dt_utf8_cplen(text, strlen(text)) > 65536) {
		resp_err(r, 400, "剪贴板超长(>65536)");
		free(text);
		return 0;
	}
	pthread_mutex_lock(&g_lock_desktop);
	obj = dt_load_desktop();
	if (!obj) {
		pthread_mutex_unlock(&g_lock_desktop);
		free(text);
		return -1;
	}
	{
		const aik_json *pv = dt_get(obj, "clipboard");

		prev = (pv && aik_json_typeof(pv) == AIK_JSON_STR)
			       ? strdup(aik_json_str(pv))
			       : strdup("");
	}
	aik_json_obj_set(obj, "clipboard", dt_new_str(text));
	dt_strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S");
	aik_json_obj_set(obj, "clipboard_updated", dt_new_str(ts));
	dt_save_desktop(obj);
	pthread_mutex_unlock(&g_lock_desktop);
	dt_sha256_hex(text, strlen(text), sha);
	dt_sha256_hex(prev, strlen(prev), psha);
	o = dt_new_obj();
	dt_put_bool(o, "ok", 1);
	dt_put_int(o, "length",
		   (long long)dt_utf8_cplen(text, strlen(text)));
	dt_put_str(o, "sha256", sha);
	dt_put_str(o, "previous", prev);
	dt_put_int(o, "previous_length",
		   (long long)dt_utf8_cplen(prev, strlen(prev)));
	dt_put_str(o, "previous_sha256", psha);
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	aik_json_free(obj);
	free(prev);
	free(text);
	return 0;
}

static int post_power(struct dt_req *req, struct dt_resp *r)
{
	static const char *allowed[5] = { "lock", "logout", "reboot",
					  "shutdown", "suspend" };
	char *act = body_get_str(req, "action", "");
	int ok_act = -1;
	aik_json *o;

	for (int i = 0; i < 5; i++)
		if (strcmp(act, allowed[i]) == 0)
			ok_act = i;
	if (ok_act < 0) {
		resp_err(r, 400, "action 需为 lock|logout|reboot|shutdown|suspend");
		free(act);
		return 0;
	}
	dt_log("power 请求被拒绝(unavailable): %s", act);
	o = dt_new_obj();
	dt_put_bool(o, "ok", 0);
	dt_put_bool(o, "available", 0);
	dt_put_bool(o, "executed", 0);
	dt_put_str(o, "action", act);
	dt_put_str(o, "backend", "unavailable");
	dt_put_str(o, "error",
		   "电源后端不可用: Web demo 无 logind 控制面;真桌面(W84)再接入");
	dt_put_bool(o, "logind_seats", dt_is_dir("/run/systemd/seats"));
	dt_put_str(o, "rollback", "no-op(未执行)");
	dt_resp_json(r, 501, o);
	aik_json_free(o);
	free(act);
	return 0;
}

static int route_post(struct dt_req *req, struct dt_resp *r)
{
	const char *path = req->path;

	if (strcmp(path, "/api/theme") == 0)
		return post_theme(req, r);
	if (strcmp(path, "/api/wallpaper") == 0)
		return post_wallpaper(req, r);
	if (strcmp(path, "/api/chat/rename") == 0)
		return post_chat_rename(req, r);
	if (strcmp(path, "/api/chat/delete") == 0)
		return post_chat_delete(req, r);
	if (strcmp(path, "/api/notifs") == 0)
		return post_notifs(req, r);
	if (strcmp(path, "/api/pin/set") == 0)
		return post_pin_set(req, r);
	if (strcmp(path, "/api/pin/clear") == 0)
		return post_pin_clear(req, r);
	if (strcmp(path, "/api/pin/verify") == 0)
		return post_pin_verify(req, r);
	if (strcmp(path, "/api/chat/new") == 0)
		return post_chat_new(req, r);
	if (strcmp(path, "/api/chat") == 0)
		return dt_route_chat_post(req, r);
	if (strcmp(path, "/api/vm/act") == 0)
		return post_vm_act(req, r);
	if (strcmp(path, "/api/apps/launch") == 0)
		return post_apps_launch(req, r);
	if (strcmp(path, "/api/apps/close") == 0)
		return post_apps_close(req, r);
	if (strcmp(path, "/api/windows/focus") == 0)
		return post_windows_focus(req, r);
	if (strcmp(path, "/api/windows/close") == 0)
		return post_windows_close(req, r);
	if (strcmp(path, "/api/input") == 0)
		return post_input(req, r);
	if (strcmp(path, "/api/clipboard") == 0)
		return post_clipboard(req, r);
	if (strcmp(path, "/api/power") == 0)
		return post_power(req, r);
	dt_resp_json404(r);
	return 0;
}

/* ---------------- dispatch(非对象体 = 未捕获异常等价) ---------------- */

int dt_dispatch(struct dt_req *req, struct dt_resp *r)
{
	if (req->non_object_body && strcmp(req->method, "POST") == 0)
		return -1; /* body 为 list/str/数 → .get/.in TypeError → 关连接 */
	if (strcmp(req->method, "GET") == 0)
		return route_get(req, r);
	return route_post(req, r);
}

/* ---------------- vm enabled 路由(dtvm.c 桥) ---------------- */

static int route_vm_enabled(const char *path, struct dt_resp *r)
{
	if (strcmp(path, "/api/vm/tools") == 0) {
		/* vm_api GET /tools:成功 200 原样透传(解析后按默认分隔符
		 * 重串,键序保持);失败 502 {"reachable": false, "error": …} */
		aik_json *data = NULL;
		char err[256];

		if (dt_vm_api_get("/tools", &data, err, sizeof(err))) {
			dt_resp_json(r, 200, data);
			aik_json_free(data);
		} else {
			aik_json *o = dt_new_obj();

			dt_put_bool(o, "reachable", 0);
			dt_put_str(o, "error", err);
			dt_resp_json(r, 502, o);
			aik_json_free(o);
		}
		return 0;
	}
	{
		aik_json *o;

		if (strcmp(path, "/api/vm/aiops") == 0)
			o = dt_vm_aiops_snapshot();
		else if (strcmp(path, "/api/vm/status") == 0)
			o = dt_vm_status_snapshot();
		else
			o = dt_vm_ai_snapshot();
		dt_resp_json(r, 200, o);
		aik_json_free(o);
	}
	return 0;
}

/* ---------------- housekeeping ---------------- */

static void *housekeeping_main(void *arg)
{
	(void)arg;
	for (;;) {
		sleep(30); /* vm_housekeeping 30s tick */
		dt_vm_housekeeping_tick();
	}
	return NULL;
}

/* ---------------- main ---------------- */

static void usage(void)
{
	fprintf(stderr,
		"usage: desktopd [--frozen-now EPOCH] [--frozen-random]\n");
	exit(2);
}

int main(int argc, char **argv)
{
	long long frozen_now = -1;
	int frozen_random = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--frozen-now") == 0 && i + 1 < argc) {
			frozen_now = atoll(argv[++i]);
		} else if (strcmp(argv[i], "--frozen-random") == 0) {
			frozen_random = 1;
		} else {
			usage();
		}
	}

	/* env 契约校验(import 期 SystemExit 等价:stderr 中文 + rc=1) */
	dt_env_port_or_die();
	dt_env_bind_or_die();
	/* 先冻结再算路径:START_TS 在 paths_init 内取冻结时刻 */
	dt_freeze_set(frozen_now, frozen_random);
	if (dt_paths_init() != 0) {
		fprintf(stderr, "desktopd: path init failed\n");
		return 1;
	}

	https_init(); /* cloud/http mbedTLS 底座(call_llm 用) */

	g_hist_load = dt_new_arr();
	g_hist_mem = dt_new_arr();

	if (dt_ensure_state() != 0) {
		fprintf(stderr, "desktopd: ensure_state failed\n");
		return 1;
	}
	dt_log("W76b desktop config root=%s port=%d bind=%s vm=%s screenshot=%s",
	       g_cfg.state_root, g_cfg.port, g_cfg.bind_host,
	       g_cfg.vm_enabled ? "enabled" : "disabled",
	       screenshot_backend());
	/* ThreadingHTTPServer((BIND, PORT)):bind 在两条启动日志之间 */
	if (dt_http_listen(g_cfg.bind_host, g_cfg.port) != 0) {
		/* 参考侧 bind 失败抛 OSError(无 LISTENING 行) */
		fprintf(stderr, "desktopd: cannot bind %s:%d\n",
			g_cfg.bind_host, g_cfg.port);
		return 1;
	}
	{
		pthread_t tid;

		if (pthread_create(&tid, NULL, housekeeping_main, NULL) == 0)
			pthread_detach(tid);
	}
	dt_log("IMG-1 demo server listening on %s:%d (loopback only; W76 desktop API)",
	       g_cfg.bind_host, g_cfg.port);
	/* LISTENING 行(重放器取端口用;C 侧新增,不入差分) */
	printf("LISTENING %d\n", g_cfg.port);
	fflush(stdout);
	dt_http_accept_loop();
	return 0;
}
