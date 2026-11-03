// SPDX-License-Identifier: GPL-2.0
/*
 * dtstate.c - W76b 状态根与虚拟窗口/PIN/通知/会话状态机。
 *
 * 所有写出:UTF-8、ensure_ascii=False、无尾换行;indent2(theme/desktop/pin)
 * 或默认分隔符(chats/notifs);tmp(无 pid)+ rename + 0600(meta 直写除外)。
 */
#define _POSIX_C_SOURCE 200809L

#include "desktop/dtstate.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

static aik_json *desktop_default(void);
static aik_json *desktop_pin_default(void);

/* ---------------------------------------------------------------- ensure */

static int copy_file(const char *src, const char *dst)
{
	size_t n = 0;
	char *buf = dt_read_file(src, &n);

	if (!buf)
		return -1;
	{
		int rc = dt_write_file(dst, buf, n);

		free(buf);
		return rc;
	}
}

int dt_ensure_state(void)
{
	const char *subdirs[4];
	struct {
		const char *src;
		const char *dst;
		int kind; /* 0: {} 1: [] 2: desktop默认 3: pin默认 */
	} seeds[4];

	if (dt_mkdir_p(g_cfg.state_root, 0700) != 0)
		return -1;
	chmod(g_cfg.state_root, 0700);

	subdirs[0] = g_cfg.chat_dir;
	subdirs[1] = g_cfg.screenshot_dir;
	subdirs[2] = g_cfg.icon_root;
	subdirs[3] = g_cfg.icon_out_dir;
	for (int i = 0; i < 4; i++) {
		if (dt_mkdir_p(subdirs[i], 0700) != 0)
			return -1;
		chmod(subdirs[i], 0700);
	}

	seeds[0].src = g_cfg.theme_seed;
	seeds[0].dst = g_cfg.theme_file;
	seeds[0].kind = 0;
	seeds[1].src = g_cfg.seed_notifs;
	seeds[1].dst = g_cfg.notif_file;
	seeds[1].kind = 1;
	seeds[2].src = g_cfg.seed_desktop;
	seeds[2].dst = g_cfg.desktop_file;
	seeds[2].kind = 2;
	seeds[3].src = g_cfg.seed_pin;
	seeds[3].dst = g_cfg.pin_file;
	seeds[3].kind = 3;

	for (int i = 0; i < 4; i++) {
		if (dt_is_file(seeds[i].dst)) {
			chmod(seeds[i].dst, 0600);
			continue;
		}
		if (dt_is_file(seeds[i].src)) {
			copy_file(seeds[i].src, seeds[i].dst);
		} else {
			aik_json *d;

			if (seeds[i].kind == 0)
				d = dt_new_obj();
			else if (seeds[i].kind == 1)
				d = dt_new_arr();
			else if (seeds[i].kind == 2)
				d = desktop_default();
			else
				d = desktop_pin_default();
			if (d) {
				dt_write_json_indent2_atomic(seeds[i].dst, d);
				aik_json_free(d);
			}
		}
		chmod(seeds[i].dst, 0600);
	}

	/* chats/ 下现有文件补 0600 */
	{
		DIR *dh = opendir(g_cfg.chat_dir);

		if (dh) {
			struct dirent *de;

			while ((de = readdir(dh)) != NULL) {
				char p[DT_CFG_PATH + 512];

				if (de->d_name[0] == '.')
					continue;
				snprintf(p, sizeof(p), "%s/%s", g_cfg.chat_dir,
					 de->d_name);
				if (dt_is_file(p))
					chmod(p, 0600);
			}
			closedir(dh);
		}
	}
	return 0;
}

/* ---------------------------------------------------------------- desktop */

static aik_json *desktop_default(void)
{
	aik_json *o = dt_new_obj();

	if (!o)
		return NULL;
	dt_put_str(o, "mode", "ai");
	dt_put_null(o, "windows");
	aik_json_obj_set(o, "windows", dt_new_arr());
	dt_put_int(o, "next_id", 1);
	dt_put_int(o, "z", 1);
	dt_put_str(o, "clipboard", "");
	dt_put_null(o, "clipboard_updated");
	return o;
}

static aik_json *desktop_pin_default(void)
{
	aik_json *o = dt_new_obj();

	if (!o)
		return NULL;
	dt_put_bool(o, "enabled", 0);
	return o;
}

aik_json *dt_load_desktop(void)
{
	aik_json *obj = dt_read_json(g_cfg.desktop_file);

	if (!obj || aik_json_typeof(obj) != AIK_JSON_OBJ) {
		aik_json_free(obj);
		obj = desktop_default();
		if (!obj)
			return NULL;
	}
	dt_obj_setdefault_str(obj, "mode", "ai");
	dt_obj_setdefault(obj, "windows", dt_new_arr());
	dt_obj_setdefault_int(obj, "next_id", 1);
	dt_obj_setdefault_int(obj, "z", 1);
	dt_obj_setdefault_str(obj, "clipboard", "");
	dt_obj_setdefault(obj, "clipboard_updated", dt_new_null());
	return obj;
}

int dt_save_desktop(aik_json *obj)
{
	return dt_write_json_indent2_atomic(g_cfg.desktop_file, obj);
}

/* z 升序稳定排序(插入排序) */
static int win_z_cmp(const aik_json *a, const aik_json *b)
{
	double za = 0, zb = 0;
	const aik_json *va = aik_json_get(a, "z");
	const aik_json *vb = aik_json_get(b, "z");

	if (va && aik_json_typeof(va) == AIK_JSON_INT)
		za = (double)aik_json_int(va);
	else if (va && aik_json_typeof(va) == AIK_JSON_NUM)
		za = aik_json_num(va);
	if (vb && aik_json_typeof(vb) == AIK_JSON_INT)
		zb = (double)aik_json_int(vb);
	else if (vb && aik_json_typeof(vb) == AIK_JSON_NUM)
		zb = aik_json_num(vb);
	if (za < zb)
		return -1;
	if (za > zb)
		return 1;
	return 0;
}

aik_json *dt_desktop_snapshot(aik_json *obj)
{
	aik_json *snap = dt_new_obj();
	const aik_json *wins = dt_get(obj, "windows");
	size_t n = (wins && aik_json_typeof(wins) == AIK_JSON_ARR)
			   ? aik_json_count(wins)
			   : 0;
	const aik_json *mode = dt_get(obj, "mode");

	if (!snap)
		return NULL;
	dt_put_str(snap, "mode",
		   (mode && aik_json_typeof(mode) == AIK_JSON_STR)
			   ? aik_json_str(mode)
			   : "ai");
	dt_put_int(snap, "count", (long long)n);
	dt_put_copy(snap, "focused", dt_get(obj, "focused"));
	if (n) {
		const aik_json **items = malloc(n * sizeof(*items));
		aik_json *sorted = dt_new_arr();

		if (!items || !sorted) {
			free(items);
			aik_json_free(sorted);
			aik_json_free(snap);
			return NULL;
		}
		for (size_t i = 0; i < n; i++)
			items[i] = aik_json_at(wins, i);
		for (size_t i = 1; i < n; i++) {
			const aik_json *key = items[i];
			size_t j = i;

			while (j > 0 && win_z_cmp(key, items[j - 1]) < 0) {
				items[j] = items[j - 1];
				j--;
			}
			items[j] = key;
		}
		for (size_t i = 0; i < n; i++)
			dt_arr_push_copy(sorted, items[i]);
		free(items);
		aik_json_obj_put(snap, "windows", sorted);
	} else {
		aik_json_obj_put(snap, "windows", dt_new_arr());
	}
	{
		aik_json *clip = dt_new_obj();
		const aik_json *text = dt_get(obj, "clipboard");
		size_t len = 0;

		if (!clip) {
			aik_json_free(snap);
			return NULL;
		}
		if (text && aik_json_typeof(text) == AIK_JSON_STR)
			len = dt_utf8_cplen(aik_json_str(text),
					    aik_json_strlen(text));
		dt_put_int(clip, "length", (long long)len);
		dt_put_copy(clip, "updated_at",
			    dt_get(obj, "clipboard_updated"));
		aik_json_obj_put(snap, "clipboard", clip);
	}
	dt_put_str(snap, "backend", "web-demo-virtual-window");
	dt_put_str(snap, "note",
		   "Web demo 虚拟窗口,不启动宿主进程;真 OS 桌面见 W84");
	return snap;
}

aik_json *dt_find_window(aik_json *obj, const char *wid)
{
	const aik_json *wins = dt_get(obj, "windows");

	if (!wins || aik_json_typeof(wins) != AIK_JSON_ARR)
		return NULL;
	for (size_t i = 0; i < aik_json_count(wins); i++) {
		const aik_json *w = aik_json_at(wins, i);
		const aik_json *id = aik_json_get(w, "id");

		if (id && aik_json_typeof(id) == AIK_JSON_STR &&
		    strcmp(aik_json_str(id), wid) == 0)
			return (aik_json *)(uintptr_t)w;
	}
	return NULL;
}

static double win_z_of(aik_json *w)
{
	const aik_json *z = dt_get(w, "z");

	if (!z)
		return 0;
	if (aik_json_typeof(z) == AIK_JSON_INT)
		return (double)aik_json_int(z);
	if (aik_json_typeof(z) == AIK_JSON_NUM)
		return aik_json_num(z);
	return 0;
}

void dt_focus_window(aik_json *obj, const char *wid)
{
	aik_json *wins = dt_get_mut(obj, "windows");
	double top = 0;
	size_t n = 0;

	if (wins && aik_json_typeof(wins) == AIK_JSON_ARR)
		n = aik_json_count(wins);
	for (size_t i = 0; i < n; i++) {
		double z = win_z_of((aik_json *)(uintptr_t)aik_json_at(wins, i));

		if (z > top)
			top = z;
	}
	for (size_t i = 0; i < n; i++) {
		aik_json *w = (aik_json *)(uintptr_t)aik_json_at(wins, i);
		const aik_json *id = dt_get(w, "id");
		int hit = id && aik_json_typeof(id) == AIK_JSON_STR &&
			  strcmp(aik_json_str(id), wid) == 0;

		aik_json_obj_set(w, "focused", dt_new_bool(hit));
		if (hit) {
			aik_json_obj_set(w, "z",
					 dt_new_int((long long)top + 1));
			aik_json_obj_set(w, "visible", dt_new_bool(1));
			aik_json_obj_set(obj, "focused", dt_new_str(wid));
		}
	}
	aik_json_obj_set(obj, "z", dt_new_int((long long)top + 1));
	aik_json_obj_set(obj, "mode", dt_new_str("desktop"));
}

void dt_top_focus(aik_json *obj)
{
	aik_json *wins = dt_get_mut(obj, "windows");
	size_t n = 0;

	if (!wins || aik_json_typeof(wins) != AIK_JSON_ARR ||
	    (n = aik_json_count(wins)) == 0) {
		aik_json_obj_set(obj, "focused", dt_new_null());
		return;
	}
	{
		size_t top_i = 0;
		double top_z = win_z_of((aik_json *)(uintptr_t)aik_json_at(wins, 0));

		for (size_t i = 1; i < n; i++) {
			double z = win_z_of((aik_json *)(uintptr_t)aik_json_at(wins, i));

			if (z > top_z) {
				top_z = z;
				top_i = i;
			}
		}
		for (size_t i = 0; i < n; i++)
			aik_json_obj_set((aik_json *)(uintptr_t)aik_json_at(wins, i),
					 "focused", dt_new_bool(i == top_i));
		{
			const aik_json *id =
				dt_get(aik_json_at(wins, top_i), "id");

			if (id && aik_json_typeof(id) == AIK_JSON_STR)
				aik_json_obj_set(obj, "focused",
						 dt_new_str(aik_json_str(id)));
			else
				aik_json_obj_set(obj, "focused", dt_new_null());
		}
	}
}

aik_json *dt_window_launch(aik_json *obj, const aik_json *app, int *created)
{
	const aik_json *app_id_v = dt_get(app, "id");
	const char *app_id = (app_id_v && aik_json_typeof(app_id_v) ==
					    AIK_JSON_STR)
				     ? aik_json_str(app_id_v)
				     : "";
	aik_json *wins = dt_obj_setdefault(obj, "windows", dt_new_arr());
	size_t n = wins ? aik_json_count(wins) : 0;

	*created = 0;
	/* 同 app 已有可见窗口(w.visible 缺省 True)→ 只 focus */
	for (size_t i = 0; i < n; i++) {
		aik_json *w = (aik_json *)(uintptr_t)aik_json_at(wins, i);
		const aik_json *wa = dt_get(w, "app");
		const aik_json *vis = dt_get(w, "visible");

		if (!wa || aik_json_typeof(wa) != AIK_JSON_STR ||
		    strcmp(aik_json_str(wa), app_id) != 0)
			continue;
		if (vis && !dt_truthy(vis))
			continue;
		{
			const aik_json *wid = dt_get(w, "id");

			if (wid && aik_json_typeof(wid) == AIK_JSON_STR)
				dt_focus_window(obj, aik_json_str(wid));
		}
		return w;
	}

	{
		const aik_json *next_id_v = dt_get(obj, "next_id");
		long long nid = 1;
		char wid[32];
		char ts[32];
		char *title;
		aik_json *win, *geo;

		if (next_id_v && aik_json_typeof(next_id_v) == AIK_JSON_INT)
			nid = aik_json_int(next_id_v);
		aik_json_obj_set(obj, "next_id", dt_new_int(nid + 1));
		snprintf(wid, sizeof(wid), "w-%04lld", nid);
		{
			/* title = app.get("name") or app["id"] */
			const aik_json *name = dt_get(app, "name");

			if (name && aik_json_typeof(name) == AIK_JSON_STR &&
			    aik_json_strlen(name) > 0)
				title = strdup(aik_json_str(name));
			else
				title = strdup(app_id);
		}
		dt_strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S");
		win = dt_new_obj();
		geo = dt_new_obj();
		if (!win || !geo || !title) {
			free(title);
			aik_json_free(geo);
			aik_json_free(win);
			return NULL;
		}
		dt_put_str(win, "id", wid);
		dt_put_str(win, "title", title);
		dt_put_str(win, "app", app_id);
		dt_put_str(win, "app_name", title);
		dt_put_int(geo, "x", 120 + ((nid - 1) % 5) * 42);
		dt_put_int(geo, "y", 96 + ((nid - 1) % 4) * 38);
		dt_put_int(geo, "w", 520);
		dt_put_int(geo, "h", 320);
		aik_json_obj_put(win, "geometry", geo);
		dt_put_bool(win, "focused", 0);
		dt_put_bool(win, "visible", 1);
		dt_put_int(win, "z", 0);
		dt_put_str(win, "text", "");
		dt_put_str(win, "created", ts);
		dt_put_null(win, "last_key");
		free(title);
		aik_json_arr_push(wins, win);
		dt_focus_window(obj, wid);
		*created = 1;
		return win;
	}
}

long long dt_window_text_append(aik_json *w, const char *text)
{
	const aik_json *cur_v = dt_get(w, "text");
	char *cur;
	long long room, add_n;
	char *add, *joined;
	char ts[32];
	size_t a, b;

	if (!cur_v || aik_json_typeof(cur_v) == AIK_JSON_NULL)
		cur = strdup("");
	else if (aik_json_typeof(cur_v) == AIK_JSON_STR)
		cur = strdup(aik_json_str(cur_v));
	else
		return -1; /* cur + add TypeError → 上层关连接 */
	if (!cur)
		return 0;
	room = 4096 - (long long)dt_utf8_cplen(cur, strlen(cur));
	if (room <= 0) {
		free(cur);
		return 0;
	}
	add = dt_utf8_head(text, (size_t)room);
	if (!add) {
		free(cur);
		return 0;
	}
	add_n = (long long)dt_utf8_cplen(add, strlen(add));
	a = strlen(cur);
	b = strlen(add);
	joined = malloc(a + b + 1);
	if (!joined) {
		free(cur);
		free(add);
		return 0;
	}
	memcpy(joined, cur, a);
	memcpy(joined + a, add, b);
	joined[a + b] = '\0';
	aik_json_obj_set(w, "text", dt_new_str(joined));
	dt_strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S");
	aik_json_obj_set(w, "updated", dt_new_str(ts));
	free(cur);
	free(add);
	free(joined);
	return add_n;
}

size_t dt_window_text_len(const aik_json *w)
{
	const aik_json *t = aik_json_get(w, "text");

	if (!t || aik_json_typeof(t) != AIK_JSON_STR)
		return 0;
	return dt_utf8_cplen(aik_json_str(t), aik_json_strlen(t));
}

/* ---------------------------------------------------------------- notifs */

aik_json *dt_notif_new_entry(const aik_json *body, int *bad_request)
{
	const aik_json *title_v = dt_get(body, "title");
	const aik_json *body_v = dt_get(body, "body");
	const aik_json *tag_v = dt_get(body, "tag");
	char *title, *text, *tag;
	aik_json *entry;
	char ts[16];
	char id[64];

	*bad_request = 0;
	if (!title_v || aik_json_typeof(title_v) != AIK_JSON_STR ||
	    !body_v || aik_json_typeof(body_v) != AIK_JSON_STR) {
		*bad_request = 1; /* title/body 需为字符串 */
		return NULL;
	}
	{
		char *s = dt_strip(aik_json_str(title_v));
		char *t = s ? dt_utf8_head(s, 80) : NULL;

		free(s);
		title = t;
	}
	{
		char *s = dt_strip(aik_json_str(body_v));
		char *t = s ? dt_utf8_head(s, 400) : NULL;

		free(s);
		text = t;
	}
	if (!title || !*title) {
		free(title);
		free(text);
		*bad_request = 2; /* title 不能为空 */
		return NULL;
	}
	{
		char *s = tag_v ? dt_pystr(tag_v) : strdup("ai");
		char *t = s ? dt_utf8_head(s, 24) : NULL;

		free(s);
		tag = t;
	}
	if (!tag || !*tag) {
		free(tag);
		tag = strdup("ai");
	}
	entry = dt_new_obj();
	if (!entry || !text || !tag) {
		free(title);
		free(text);
		free(tag);
		aik_json_free(entry);
		return NULL;
	}
	dt_put_str(entry, "title", title);
	dt_put_str(entry, "body", text);
	dt_put_str(entry, "tag", tag);
	dt_strftime(ts, sizeof(ts), "%H:%M");
	dt_put_str(entry, "time", ts);
	snprintf(id, sizeof(id), "n-%lld", dt_time_ns());
	dt_put_str(entry, "id", id);
	dt_put_str(entry, "source", "desktop.notifications.send");
	free(title);
	free(text);
	free(tag);
	return entry;
}

/* ---------------------------------------------------------------- pin */

aik_json *dt_load_pin(void)
{
	aik_json *p = dt_read_json(g_cfg.pin_file);

	if (!p || aik_json_typeof(p) != AIK_JSON_OBJ) {
		aik_json_free(p);
		return desktop_pin_default();
	}
	return p;
}

int dt_save_pin(aik_json *p)
{
	return dt_write_json_indent2_atomic(g_cfg.pin_file, p);
}

char *dt_pin_warning(const char *pin)
{
	size_t n = strlen(pin);

	if (n < 6)
		return strdup("PIN 少于 6 位,建议使用更长的 PIN");
	{
		int same = 1;

		for (size_t i = 1; i < n; i++)
			if (pin[i] != pin[0])
				same = 0;
		if (same)
			return strdup("PIN 为重复数字,过于薄弱");
	}
	{
		int up = 1, down = 1;

		for (size_t i = 0; i + 1 < n; i++) {
			int d = pin[i + 1] - pin[i];

			if (d != 1)
				up = 0;
			if (d != -1)
				down = 0;
		}
		if (up || down)
			return strdup("PIN 为连续顺序数字,过于薄弱");
	}
	return NULL;
}

/* ---------------------------------------------------------------- chats */

char *dt_chat_path(const char *sid, const char *suffix)
{
	size_t lc = strlen(g_cfg.chat_dir);
	size_t ls = strlen(sid);
	size_t lx = strlen(suffix);
	char *p;

	if (lc + ls + lx + 3 > DT_CFG_PATH)
		return NULL;
	p = malloc(DT_CFG_PATH);
	if (!p)
		return NULL;
	memcpy(p, g_cfg.chat_dir, lc);
	p[lc] = '/';
	memcpy(p + lc + 1, sid, ls);
	memcpy(p + lc + 1 + ls, suffix, lx);
	p[lc + 1 + ls + lx] = '\0';
	return p;
}

aik_json *dt_load_chat(const char *sid)
{
	char *p = dt_chat_path(sid, ".json");
	aik_json *v;

	if (!p)
		return NULL;
	v = dt_read_json(p);
	free(p);
	if (!v)
		return dt_new_arr();
	return v;
}

int dt_append_chat(const char *sid, aik_json *entry)
{
	int rc = -1;
	aik_json *msgs;

	pthread_mutex_lock(&g_lock_chat);
	msgs = dt_load_chat(sid);
	if (!msgs)
		goto out;
	if (aik_json_typeof(msgs) != AIK_JSON_ARR) {
		aik_json_free(msgs);
		msgs = dt_new_arr();
		if (!msgs)
			goto out;
	}
	aik_json_arr_push(msgs, entry);
	{
		size_t n = aik_json_count(msgs);

		if (n > 200) {
			aik_json *kept = dt_new_arr();

			if (!kept)
				goto out_free;
			for (size_t i = n - 200; i < n; i++)
				dt_arr_push_copy(kept, aik_json_at(msgs, i));
			aik_json_free(msgs);
			msgs = kept;
		}
	}
	{
		char *p = dt_chat_path(sid, ".json");

		if (!p)
			goto out_free;
		rc = dt_write_json_default_atomic(p, msgs);
		free(p);
	}
out_free:
	aik_json_free(msgs);
out:
	pthread_mutex_unlock(&g_lock_chat);
	return rc;
}

char *dt_new_session_id(void)
{
	char ts[32];
	char rand_repr[40];
	char md5[33];

	dt_strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S");
	aik_json_dtoa(dt_random(), rand_repr, sizeof(rand_repr));
	dt_md5_hex(rand_repr, strlen(rand_repr), md5);
	md5[6] = '\0';
	{
		char *out = malloc(64);

		if (!out)
			return NULL;
		snprintf(out, 64, "%.15s-%.6s", ts, md5);
		return out;
	}
}

static char **list_chat_dir(size_t *count)
{
	DIR *dh = opendir(g_cfg.chat_dir);
	char **names = NULL;
	size_t n = 0, cap = 0;
	struct dirent *de;

	*count = 0;
	if (!dh)
		return NULL;
	while ((de = readdir(dh)) != NULL) {
		size_t ln = strlen(de->d_name);

		if (ln < 6 || strcmp(de->d_name + ln - 5, ".json") != 0)
			continue;
		if (n == cap) {
			size_t ncap = cap ? cap * 2 : 16;
			char **q = realloc(names, ncap * sizeof(*q));

			if (!q)
				break;
			names = q;
			cap = ncap;
		}
		names[n] = strdup(de->d_name);
		if (!names[n])
			break;
		n++;
	}
	closedir(dh);
	for (size_t i = 1; i < n; i++) {
		char *key = names[i];
		size_t j = i;

		while (j > 0 && strcmp(names[j - 1], key) > 0) {
			names[j] = names[j - 1];
			j--;
		}
		names[j] = key;
	}
	*count = n;
	return names;
}

aik_json *dt_chat_sessions(void)
{
	size_t nfiles = 0;
	char **files = list_chat_dir(&nfiles);
	aik_json *out = dt_new_arr();
	int aborted = 0;

	if (!out) {
		for (size_t i = 0; i < nfiles; i++)
			free(files[i]);
		free(files);
		return dt_new_arr();
	}
	for (size_t i = 0; i < nfiles && !aborted; i++) {
		const char *fn = files[i];
		size_t ln = strlen(fn);
		char sid[256];
		aik_json *msgs;
		aik_json *item;
		aik_json *title_meta = NULL; /* meta 原始值(拷贝) */
		char *title_fb = NULL;

		if (ln - 5 >= sizeof(sid))
			continue;
		memcpy(sid, fn, ln - 5);
		sid[ln - 5] = '\0';
		msgs = dt_load_chat(sid);
		if (!msgs)
			continue;
		/* Python:user_msgs 推导式对 dict/标量 msgs 抛 AttributeError →
		 * 外层 except 中断整个循环;数组元素非对象同理;空容器安全。 */
		if (aik_json_count(msgs) > 0) {
			int bad = 0;

			if (aik_json_typeof(msgs) != AIK_JSON_ARR)
				bad = 1;
			else
				for (size_t k = 0; k < aik_json_count(msgs); k++)
					if (aik_json_typeof(aik_json_at(msgs, k)) !=
					    AIK_JSON_OBJ) {
						bad = 1;
						break;
					}
			if (bad) {
				aik_json_free(msgs);
				aborted = 1;
				break;
			}
		} else {
			aik_json_type t = aik_json_typeof(msgs);

			if (t != AIK_JSON_ARR && t != AIK_JSON_OBJ &&
			    t != AIK_JSON_STR) {
				/* iter(标量) TypeError → 中断 */
				aik_json_free(msgs);
				aborted = 1;
				break;
			}
		}
		item = dt_new_obj();
		if (!item) {
			aik_json_free(msgs);
			continue;
		}
		{
			char *mp = dt_chat_path(sid, ".meta.json");

			if (mp) {
				aik_json *meta = dt_read_json(mp);

				if (meta && aik_json_typeof(meta) == AIK_JSON_OBJ)
					title_meta = dt_copy(dt_get(meta, "title"));
				aik_json_free(meta);
				free(mp);
			}
		}
		if (!dt_truthy(title_meta)) {
			/* 首条 user 消息 content 前 16 码点 */
			for (size_t k = 0; k < aik_json_count(msgs); k++) {
				const aik_json *m = aik_json_at(msgs, k);
				const aik_json *role = dt_get(m, "role");
				const aik_json *content = dt_get(m, "content");

				if (role && aik_json_typeof(role) == AIK_JSON_STR &&
				    strcmp(aik_json_str(role), "user") == 0) {
					if (content &&
					    aik_json_typeof(content) == AIK_JSON_STR)
						title_fb = dt_utf8_head(
							aik_json_str(content), 16);
					else
						aborted = 1; /* m["content"] 失败 */
					break;
				}
			}
		}
		dt_put_str(item, "id", sid);
		if (dt_truthy(title_meta))
			dt_put_copy(item, "title", title_meta);
		else
			dt_put_str(item, "title", title_fb ? title_fb : sid);
		dt_put_int(item, "count", (long long)aik_json_count(msgs));
		if (aik_json_count(msgs) > 0) {
			dt_put_copy(item, "first",
				    dt_get(aik_json_at(msgs, 0), "ts"));
			dt_put_copy(item, "last",
				    dt_get(aik_json_at(msgs,
						       aik_json_count(msgs) - 1),
					   "ts"));
		} else {
			dt_put_null(item, "first");
			dt_put_null(item, "last");
		}
		if (!aborted)
			aik_json_arr_push(out, item);
		else
			aik_json_free(item);
		aik_json_free(title_meta);
		free(title_fb);
		aik_json_free(msgs);
	}
	for (size_t i = 0; i < nfiles; i++)
		free(files[i]);
	free(files);

	/* last 降序稳定排序(None/空 当 "",key = x.get("last") or "") */
	{
		size_t n = aik_json_count(out);

		if (n > 1) {
			aik_json **items = malloc(n * sizeof(*items));
			const char **keys = malloc(n * sizeof(*keys));

			if (items && keys) {
				for (size_t i = 0; i < n; i++) {
					const aik_json *it = aik_json_at(out, i);
					const aik_json *last = dt_get(it, "last");

					items[i] = (aik_json *)(uintptr_t)it;
					keys[i] = (last &&
						   aik_json_typeof(last) ==
							   AIK_JSON_STR &&
						   aik_json_strlen(last) > 0)
							  ? aik_json_str(last)
							  : "";
				}
				for (size_t i = 1; i < n; i++) {
					aik_json *key = items[i];
					const char *kkey = keys[i];
					size_t j = i;

					while (j > 0 &&
					       strcmp(keys[j - 1], kkey) < 0) {
						items[j] = items[j - 1];
						keys[j] = keys[j - 1];
						j--;
					}
					items[j] = key;
					keys[j] = kkey;
				}
				{
					aik_json *sorted = dt_new_arr();

					if (sorted) {
						for (size_t i = 0; i < n; i++)
							dt_arr_push_copy(sorted,
									 items[i]);
						aik_json_free(out);
						out = sorted;
					}
				}
			}
			free(items);
			free(keys);
		}
	}
	return out;
}
