// SPDX-License-Identifier: GPL-2.0
/*
 * dttheme.c - 主题引擎:load_theme 自愈、内嵌色板、自定义主题混色派生、
 * 壁纸画廊(>10240 规则)。
 *
 * 混色系数(server.py build_custom_theme 逐条):
 *   bg .06 / bg2 .10 / panel_solid .08 / bubble_ai .14 /
 *   bubble_user = accent 混黑 .15 / accent2 = accent 混白 .35;
 *   wallpaper 三段渐变(0.16 / 0.28,基于混合后的 bg);
 *   wallpaper_file=null 键补尾;display="自定义(<accent>)"。
 *   round() 为 Python banker's rounding。
 */
#define _POSIX_C_SOURCE 200809L

#include "desktop/dttheme.h"

#include <dirent.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

/* 内置色板 15 键序(_BASE_THEMES 同源) */
struct theme_field {
	const char *key;
	const char *dark;
	const char *light;
	const char *pink;
};

static const struct theme_field BASE_FIELDS[] = {
	{ "display", "暗色", "亮色", "粉色" },
	{ "bg", "#0b0f14", "#f4f6f9", "#fff0f5" },
	{ "bg2", "#111823", "#e9edf3", "#ffe1ec" },
	{ "panel", "rgba(17,24,35,0.86)", "rgba(255,255,255,0.88)",
	  "rgba(255,240,246,0.9)" },
	{ "panel_solid", "#141c28", "#ffffff", "#fff7fa" },
	{ "text", "#e6edf3", "#1c2733", "#4a2438" },
	{ "text_dim", "#8b98a5", "#5c6b7a", "#a86b87" },
	{ "accent", "#4f8cff", "#2563eb", "#ff5fa2" },
	{ "accent_soft", "rgba(79,140,255,0.16)", "rgba(37,99,235,0.12)",
	  "rgba(255,95,162,0.14)" },
	{ "accent2", "#7ee787", "#059669", "#b36bff" },
	{ "border", "rgba(255,255,255,0.08)", "rgba(28,39,51,0.12)",
	  "rgba(255,120,180,0.28)" },
	{ "shadow", "0 18px 50px rgba(0,0,0,0.5)",
	  "0 18px 50px rgba(30,50,80,0.18)",
	  "0 18px 50px rgba(255,95,162,0.25)" },
	{ "wallpaper",
	  "linear-gradient(135deg,#0b0f14 0%,#14202e 45%,#1d2f42 100%)",
	  "linear-gradient(135deg,#dfe7f0 0%,#eef3f9 50%,#dbe7f5 100%)",
	  "linear-gradient(135deg,#ffd6e8 0%,#ffeff6 45%,#f3d9ff 100%)" },
	{ "bubble_ai", "#182230", "#ffffff", "#ffe4ef" },
	{ "bubble_user", "#2a4d8f", "#2563eb", "#ff5fa2" },
};
#define N_BASE_FIELDS 15

aik_json *dt_base_theme(const char *name)
{
	aik_json *o = dt_new_obj();
	int idx;

	if (!o)
		return NULL;
	if (strcmp(name, "dark") == 0)
		idx = 0;
	else if (strcmp(name, "light") == 0)
		idx = 1;
	else if (strcmp(name, "pink") == 0)
		idx = 2;
	else {
		aik_json_free(o);
		return NULL;
	}
	for (int i = 0; i < N_BASE_FIELDS; i++) {
		const char *val = idx == 0   ? BASE_FIELDS[i].dark
				  : idx == 1 ? BASE_FIELDS[i].light
					     : BASE_FIELDS[i].pink;

		dt_put_str(o, BASE_FIELDS[i].key, val);
	}
	return o;
}

aik_json *dt_load_theme(void)
{
	aik_json *obj = dt_read_json(g_cfg.theme_file);
	int dirty = 0;

	pthread_mutex_lock(&g_lock_theme);
	if (!obj || aik_json_typeof(obj) != AIK_JSON_OBJ) {
		aik_json_free(obj);
		obj = dt_new_obj();
		if (!obj)
			goto out;
		dt_put_str(obj, "current", "dark");
		dt_put_null(obj, "themes");
		aik_json_obj_set(obj, "themes", dt_new_obj());
	}
	{
		static const char *names[3] = { "dark", "light", "pink" };
		aik_json *themes;

		for (int i = 0; i < 3; i++) {
			aik_json *themes_cur;
			aik_json *cur;
			aik_json *patched;

			themes = dt_get_mut(obj, "themes");
			themes_cur = themes ? dt_get_mut(themes, names[i])
					    : NULL;
			cur = themes_cur;
			if (cur && aik_json_typeof(cur) == AIK_JSON_OBJ &&
			    aik_json_get(cur, "bg"))
				continue; /* 完整,不修补 */
			patched = dt_base_theme(names[i]);
			if (!patched)
				continue;
			if (cur && aik_json_typeof(cur) == AIK_JSON_OBJ) {
				/* 保留 wallpaper_file / display(若有) */
				const aik_json *wf = aik_json_get(cur,
								  "wallpaper_file");
				const aik_json *disp = aik_json_get(cur,
								    "display");

				if (wf && dt_truthy(wf))
					aik_json_obj_set(patched,
							 "wallpaper_file",
							 dt_copy(wf));
				if (disp && dt_truthy(disp))
					aik_json_obj_set(patched, "display",
							 dt_copy(disp));
			}
			if (!themes) {
				themes = dt_new_obj();
				if (themes)
					aik_json_obj_set(obj, "themes", themes);
			}
			if (themes)
				aik_json_obj_set(themes, names[i], patched);
			dirty = 1;
		}
		themes = dt_get_mut(obj, "themes");
		if (!themes || !dt_truthy(themes)) {
			aik_json *all = dt_new_obj();

			if (all) {
				for (int i = 0; i < 3; i++)
					aik_json_obj_set(all, names[i],
							 dt_base_theme(names[i]));
				aik_json_obj_set(obj, "themes", all);
				dirty = 1;
			}
		}
	}
	dt_obj_setdefault_str(obj, "wallpaper", "gradient");
	dt_obj_setdefault_str(obj, "current", "dark");
	if (dirty) {
		/* 自愈重写:tmp + replace + 后 chmod 0600(server.py 顺序) */
		char *text = dt_json_dump_indent2(obj);
		char tmp[DT_PATH_MAX];
		FILE *fh;

		if (text &&
		    snprintf(tmp, sizeof(tmp), "%s.tmp", g_cfg.theme_file) <
			    (int)sizeof(tmp)) {
			fh = fopen(tmp, "wb");
			if (fh) {
				size_t n = strlen(text);

				if (fwrite(text, 1, n, fh) == n)
					dirty = 2;
				fclose(fh);
				if (dirty == 2) {
					rename(tmp, g_cfg.theme_file);
					chmod(g_cfg.theme_file, 0600);
					dt_log("theme.json 完整性自愈完成");
				}
			}
		}
		free(text);
	}
out:
	pthread_mutex_unlock(&g_lock_theme);
	return obj;
}

int dt_save_theme(aik_json *obj)
{
	char tmp[DT_PATH_MAX];
	char *text;
	FILE *fh;
	size_t n;
	int rc = -1;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", g_cfg.theme_file) >=
	    (int)sizeof(tmp))
		return -1;
	pthread_mutex_lock(&g_lock_theme);
	text = dt_json_dump_indent2(obj);
	if (!text)
		goto out;
	n = strlen(text);
	fh = fopen(tmp, "wb");
	if (!fh)
		goto out_free;
	if (fwrite(text, 1, n, fh) == n) {
		fclose(fh);
		chmod(tmp, 0600); /* 先 chmod 再 replace */
		if (rename(tmp, g_cfg.theme_file) == 0)
			rc = 0;
	} else {
		fclose(fh);
	}
out_free:
	free(text);
out:
	pthread_mutex_unlock(&g_lock_theme);
	return rc;
}

aik_json *dt_list_wallpapers(void)
{
	aik_json *arr = dt_new_arr();
	DIR *dh;
	struct dirent *de;
	char *names[512];
	size_t n = 0;

	if (!arr)
		return NULL;
	dh = opendir(g_cfg.wallpaper_dir);
	if (!dh)
		return arr;
	while ((de = readdir(dh)) != NULL) {
		size_t ln = strlen(de->d_name);
		char p[DT_CFG_PATH + 512];
		struct stat st;

		if (ln < 5 || strcmp(de->d_name + ln - 4, ".png") != 0)
			continue;
		snprintf(p, sizeof(p), "%s/%s", g_cfg.wallpaper_dir,
			 de->d_name);
		if (stat(p, &st) != 0 || st.st_size <= 10240)
			continue;
		if (n < 512) {
			char *s = strdup(de->d_name);

			if (s)
				names[n++] = s;
		}
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
	for (size_t i = 0; i < n; i++) {
		size_t ln = strlen(names[i]);

		names[i][ln - 4] = '\0';
		dt_arr_push_str(arr, names[i]);
		free(names[i]);
	}
	return arr;
}

/* ---------------- 自定义主题 ---------------- */

static int hex_rgb(const char *h, int rgb[3])
{
	if (h[0] == '#')
		h++;
	{
		char b[3];
		int v;

		b[2] = '\0';
		for (int i = 0; i < 3; i++) {
			b[0] = h[i * 2];
			b[1] = h[i * 2 + 1];
			v = (int)strtol(b, NULL, 16);
			rgb[i] = v;
		}
	}
	return 0;
}

/* Python round(x)(banker's rounding),输入有限 */
static long long py_round(double x)
{
	double r = nearbyint(x); /* 默认舍入模式即 half-even */

	return (long long)r;
}

static void rgb_hex(const int rgb[3], char out[8])
{
	static const char HEX[] = "0123456789abcdef";

	out[0] = '#';
	for (int i = 0; i < 3; i++) {
		int v = rgb[i];

		if (v < 0)
			v = 0;
		if (v > 255)
			v = 255;
		out[1 + i * 2] = HEX[v >> 4];
		out[2 + i * 2] = HEX[v & 0xF];
	}
	out[7] = '\0';
}

static void mix_hex(const char *h1, const char *h2, double t, char out[8])
{
	int a[3], b[3], r[3];

	hex_rgb(h1, a);
	hex_rgb(h2, b);
	for (int i = 0; i < 3; i++)
		r[i] = (int)py_round(a[i] + (b[i] - a[i]) * t);
	rgb_hex(r, out);
}

aik_json *dt_build_custom_theme(const char *accent, const char *base)
{
	aik_json *theme = dt_load_theme();
	aik_json *src;
	const aik_json *themes = theme ? dt_get(theme, "themes") : NULL;
	const aik_json *src_v =
		themes ? aik_json_get(themes, base) : NULL;

	if (src_v && aik_json_typeof(src_v) == AIK_JSON_OBJ)
		src = dt_copy(src_v);
	else
		src = dt_base_theme(base);
	aik_json_free(theme);
	if (!src)
		return NULL;

	{
		char mixed[8];
		char buf[512];
		char bg_hex[8];
		const aik_json *v;

		/* display / accent / accent_soft / accent2 */
		snprintf(buf, sizeof(buf), "自定义(%s)", accent);
		aik_json_obj_set(src, "display", dt_new_str(buf));
		aik_json_obj_set(src, "accent", dt_new_str(accent));
		{
			int rgb[3];
			char ct[32];

			hex_rgb(accent, rgb);
			/* "%.2f" of 0.16 → "0.16"(C locale 语义) */
			snprintf(ct, sizeof(ct), "rgba(%d,%d,%d,0.16)", rgb[0],
				 rgb[1], rgb[2]);
			aik_json_obj_set(src, "accent_soft", dt_new_str(ct));
		}
		mix_hex(accent, "#ffffff", 0.35, mixed);
		aik_json_obj_set(src, "accent2", dt_new_str(mixed));

		/* bg(混合后供 wallpaper 使用) */
		v = aik_json_get(src, "bg");
		mix_hex(v && aik_json_typeof(v) == AIK_JSON_STR
				? aik_json_str(v)
				: "#000000",
			accent, 0.06, bg_hex);
		aik_json_obj_set(src, "bg", dt_new_str(bg_hex));
		v = aik_json_get(src, "bg2");
		mix_hex(v && aik_json_typeof(v) == AIK_JSON_STR
				? aik_json_str(v)
				: "#000000",
			accent, 0.10, mixed);
		aik_json_obj_set(src, "bg2", dt_new_str(mixed));
		v = aik_json_get(src, "panel_solid");
		mix_hex(v && aik_json_typeof(v) == AIK_JSON_STR
				? aik_json_str(v)
				: "#000000",
			accent, 0.08, mixed);
		aik_json_obj_set(src, "panel_solid", dt_new_str(mixed));
		v = aik_json_get(src, "bubble_ai");
		mix_hex(v && aik_json_typeof(v) == AIK_JSON_STR
				? aik_json_str(v)
				: "#000000",
			accent, 0.14, mixed);
		aik_json_obj_set(src, "bubble_ai", dt_new_str(mixed));
		mix_hex(accent, "#000000", 0.15, mixed);
		aik_json_obj_set(src, "bubble_user", dt_new_str(mixed));

		{
			char m1[8], m2[8];

			mix_hex(bg_hex, accent, 0.16, m1);
			mix_hex(bg_hex, accent, 0.28, m2);
			snprintf(buf, sizeof(buf),
				 "linear-gradient(135deg,%s 0%%,%s 50%%,%s 100%%)",
				 m1, bg_hex, m2);
			aik_json_obj_set(src, "wallpaper", dt_new_str(buf));
		}
		aik_json_obj_set(src, "wallpaper_file", dt_new_null());
	}
	return src;
}
