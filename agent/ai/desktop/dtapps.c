// SPDX-License-Identifier: GPL-2.0
/*
 * dtapps.c - 应用清单:.desktop 扫描(sorted,NoDisplay/Hidden/无 Name 跳过)、
 * freedesktop 图标查找链(Yaru|hicolor|Adwaita|Humanity|gnome 尺寸序 512→32,
 * 无尺寸目录兜底,再 /usr/share/pixmaps)+ 复制(src mtime 新才复制)、
 * STATIC_DIR/icons/gen/<id>.{png,jpg,jpeg,webp} 兜底、zh_CN 映射(_meta 弹出,
 * 60s 缓存)、<5 真实应用合并 data/apps-catalog.json(virtual/source 补尾、
 * 重复 id 跳过)、get_apps 120s 缓存。
 */
#define _POSIX_C_SOURCE 200809L

#include "desktop/dtapps.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

static const char *ICON_SIZE_DIRS[] = {
	"512x512", "256x256", "192x192", "128x128", "96x96", "64x64",
	"48x48", "32x32",
};
#define N_SIZE_DIRS 8
static const char *ICON_THEMES[] = { "Yaru", "hicolor", "Adwaita", "Humanity",
				     "gnome" };
#define N_ICON_THEMES 5

/* ---------------- zh_CN 映射 ---------------- */

static aik_json *g_zh;
static long long g_zh_ts = -1;

static aik_json *zh_map(void)
{
	pthread_mutex_lock(&g_lock_zh);
	{
		long long now = dt_time();

		if (!g_zh || (g_zh_ts >= 0 && now - g_zh_ts > 60)) {
			aik_json *obj = dt_read_json(g_cfg.locale_file);

			if (!obj || aik_json_typeof(obj) != AIK_JSON_OBJ) {
				aik_json_free(obj);
				obj = dt_new_obj();
			} else if (aik_json_get(obj, "_meta")) {
				/* obj.pop("_meta"):重建去键 */
				aik_json *clean = dt_new_obj();

				if (clean) {
					size_t n = aik_json_count(obj);

					for (size_t i = 0; i < n; i++)
						aik_json_obj_put(
							clean,
							aik_json_key_at(obj, i),
							dt_copy(aik_json_val_at(obj,
										i)));
					aik_json_free(obj);
					obj = clean;
				}
			}
			aik_json_free(g_zh);
			g_zh = obj;
			g_zh_ts = now;
		}
	}
	pthread_mutex_unlock(&g_lock_zh);
	return g_zh ? g_zh : dt_new_obj();
}

/* zh.get(k) 的真值字符串(空/缺失/非字符串 → NULL) */
static char *zh_lookup(aik_json *zh, const char *k)
{
	const aik_json *v;

	if (!zh || !k)
		return NULL;
	v = aik_json_get(zh, k);
	if (!v || aik_json_typeof(v) != AIK_JSON_STR ||
	    aik_json_strlen(v) == 0)
		return NULL;
	return strdup(aik_json_str(v));
}

/* ---------------- 图标查找链 ---------------- */

static char *find_icon_file(const char *icon_name)
{
	if (!icon_name || !*icon_name)
		return NULL;
	if (icon_name[0] == '/') {
		if (dt_is_file(icon_name))
			return strdup(icon_name);
		return NULL;
	}
	for (int t = 0; t < N_ICON_THEMES; t++) {
		char d[DT_PATH_MAX];
		char p[DT_CFG_PATH + 512];

		snprintf(d, sizeof(d), "/usr/share/icons/%s", ICON_THEMES[t]);
		if (!dt_is_dir(d))
			continue;
		for (int s = 0; s < N_SIZE_DIRS; s++) {
			for (int e = 0; e < 3; e++) {
				static const char *exts[3] = { "png", "svg",
							       "xpm" };

				snprintf(p, sizeof(p), "%s/%s/apps/%s.%s", d,
					 ICON_SIZE_DIRS[s], icon_name, exts[e]);
				if (dt_is_file(p))
					return strdup(p);
			}
		}
		for (int e = 0; e < 3; e++) {
			static const char *exts[3] = { "png", "svg", "xpm" };

			snprintf(p, sizeof(p), "%s/apps/%s.%s", d, icon_name,
				 exts[e]);
			if (dt_is_file(p))
				return strdup(p);
		}
	}
	for (int e = 0; e < 3; e++) {
		static const char *exts[3] = { "png", "svg", "xpm" };
		char p[DT_CFG_PATH + 512];

		snprintf(p, sizeof(p), "/usr/share/pixmaps/%s.%s", icon_name,
			 exts[e]);
		if (dt_is_file(p))
			return strdup(p);
	}
	return NULL;
}

/* ---------------- .desktop 解析 ---------------- */

struct desktop_entry {
	char *name;
	char *name_zh;
	char *exec;
	char *icon;
	char *comment;
	char *comment_zh;
	char *categories;
	int terminal;
	int no_display;
	int hidden;
};

static char *dup_nonempty(const char *s, size_t n)
{
	char *p = malloc(n + 1);

	if (!p)
		return NULL;
	memcpy(p, s, n);
	p[n] = '\0';
	return p;
}

static void entry_free(struct desktop_entry *e)
{
	free(e->name);
	free(e->name_zh);
	free(e->exec);
	free(e->icon);
	free(e->comment);
	free(e->comment_zh);
	free(e->categories);
	memset(e, 0, sizeof(*e));
}

/* 解析单个 .desktop(损坏/NoDisplay/Hidden/无 Name → 失败) */
static int parse_desktop_file(const char *path, struct desktop_entry *e)
{
	size_t len = 0;
	char *txt = dt_read_file(path, &len);
	char *line, *save;
	int in_main = 0;

	memset(e, 0, sizeof(*e));
	e->categories = strdup("");
	if (!txt)
		return -1;
	for (line = strtok_r(txt, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *eq, *k, *v;

		if (line[0] == '[') {
			/* line.strip() == "[Desktop Entry]"(去两端空白) */
			char *s = line;
			size_t n = strlen(s);

			while (*s == ' ' || *s == '\t')
				s++;
			while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
				n--;
			s[n] = '\0';
			in_main = strcmp(s, "[Desktop Entry]") == 0;
			continue;
		}
		if (!in_main)
			continue;
		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		k = line;
		v = eq + 1;
		/* k.strip() */
		{
			size_t n = strlen(k);

			while (*k == ' ' || *k == '\t')
				k++;
			while (n > 0 && (k[n - 1] == ' ' || k[n - 1] == '\t'))
				n--;
			k[n] = '\0';
		}
		if (strcmp(k, "Name") == 0) {
			free(e->name);
			e->name = strdup(v);
		} else if (strcmp(k, "Name[zh_CN]") == 0) {
			free(e->name_zh);
			e->name_zh = strdup(v);
		} else if (strcmp(k, "Exec") == 0) {
			free(e->exec);
			e->exec = strdup(v);
		} else if (strcmp(k, "Icon") == 0) {
			free(e->icon);
			e->icon = strdup(v);
		} else if (strcmp(k, "Comment") == 0) {
			free(e->comment);
			e->comment = strdup(v);
		} else if (strcmp(k, "Comment[zh_CN]") == 0) {
			free(e->comment_zh);
			e->comment_zh = strdup(v);
		} else if (strcmp(k, "Categories") == 0) {
			free(e->categories);
			e->categories = strdup(v);
		} else if (strcmp(k, "Terminal") == 0) {
			char *s = v;
			size_t n = strlen(s);

			while (*s == ' ' || *s == '\t')
				s++;
			while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
				n--;
			s[n] = '\0';
			e->terminal = strcasecmp(s, "true") == 0;
		} else if (strcmp(k, "NoDisplay") == 0) {
			char *s = v;
			size_t n = strlen(s);

			while (*s == ' ' || *s == '\t')
				s++;
			while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
				n--;
			s[n] = '\0';
			e->no_display = strcasecmp(s, "true") == 0;
		} else if (strcmp(k, "Hidden") == 0) {
			char *s = v;
			size_t n = strlen(s);

			while (*s == ' ' || *s == '\t')
				s++;
			while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
				n--;
			s[n] = '\0';
			e->hidden = strcasecmp(s, "true") == 0;
		}
	}
	free(txt);
	if (e->no_display || e->hidden || !e->name || !*e->name) {
		entry_free(e);
		return -1;
	}
	return 0;
}

/* ---------------- catalog ---------------- */

static aik_json *load_demo_catalog(void)
{
	aik_json *obj = dt_read_json(g_cfg.catalog_file);
	const aik_json *apps;

	if (!obj)
		return dt_new_arr();
	if (aik_json_typeof(obj) == AIK_JSON_OBJ) {
		apps = aik_json_get(obj, "apps");
		if (!apps)
			apps = obj;
	} else {
		apps = obj;
	}
	if (aik_json_typeof(apps) != AIK_JSON_ARR) {
		aik_json_free(obj);
		return dt_new_arr();
	}
	{
		aik_json *list = dt_copy(apps);

		aik_json_free(obj);
		return list;
	}
}

/* ---------------- collect ---------------- */

aik_json *dt_collect_apps(void)
{
	aik_json *apps = dt_new_arr();
	aik_json *zh;
	DIR *dh;
	struct dirent *de;
	char *names[2048];
	size_t nfiles = 0;

	if (!apps)
		return NULL;
	dt_mkdir_p(g_cfg.icon_out_dir, 0777);
	zh = zh_map();
	if (!zh) {
		aik_json_free(apps);
		return NULL;
	}
	if (!dt_is_dir(g_cfg.apps_dir))
		return apps;
	dh = opendir(g_cfg.apps_dir);
	if (!dh)
		return apps;
	while ((de = readdir(dh)) != NULL) {
		size_t ln = strlen(de->d_name);

		if (ln < 8 || strcmp(de->d_name + ln - 8, ".desktop") != 0)
			continue;
		if (nfiles < 2048)
			names[nfiles++] = strdup(de->d_name);
	}
	closedir(dh);
	for (size_t i = 1; i < nfiles; i++) {
		char *key = names[i];
		size_t j = i;

		while (j > 0 && strcmp(names[j - 1], key) > 0) {
			names[j] = names[j - 1];
			j--;
		}
		names[j] = key;
	}
	for (size_t i = 0; i < nfiles; i++) {
		struct desktop_entry ent;
		char path[DT_CFG_PATH + 512];
		char app_id[256];
		size_t ln = strlen(names[i]);
		char *icon_url = NULL;
		aik_json *app;

		snprintf(path, sizeof(path), "%s/%s", g_cfg.apps_dir, names[i]);
		if (parse_desktop_file(path, &ent) != 0)
			goto next;
		memcpy(app_id, names[i], ln - 8);
		app_id[ln - 8] = '\0';

		{
			char *src = find_icon_file(ent.icon);

			if (src) {
				const char *dot = strrchr(src, '.');
				char ext[8] = "";
				char dst[DT_CFG_PATH + 512];
				struct stat sst, dst_st;

				if (dot) {
					size_t el = strlen(dot);

					if (el < sizeof(ext)) {
						memcpy(ext, dot, el + 1);
						for (size_t k = 0; k < el; k++)
							if (ext[k] >= 'A' &&
							    ext[k] <= 'Z')
								ext[k] =
									ext[k] -
									'A' + 'a';
					}
				}
				snprintf(dst, sizeof(dst), "%s/%s%s",
					 g_cfg.icon_out_dir, app_id, ext);
				/* try: dst 缺失或 mtime 较旧 → copyfile;
				 * 成功路径即设置 icon_url,任何失败 → None */
				if (stat(src, &sst) != 0) {
					/* getmtime(src) 抛 → except */
				} else {
					int need_copy;

					if (stat(dst, &dst_st) != 0)
						need_copy = 1;
					else
						need_copy = dst_st.st_mtime <
							    sst.st_mtime;
					if (!need_copy) {
						char url[512];

						snprintf(url, sizeof(url),
							 "/static/icons/apps/%s%s",
							 app_id, ext);
						icon_url = strdup(url);
					} else {
						size_t blen = 0;
						char *bdata =
							dt_read_file(src, &blen);

						if (bdata) {
							if (dt_write_file(
								    dst, bdata,
								    blen) == 0) {
								char url[512];

								snprintf(url,
									 sizeof(url),
									 "/static/icons/apps/%s%s",
									 app_id,
									 ext);
								icon_url =
									strdup(url);
							}
							free(bdata);
						}
					}
				}
				free(src);
			}
		}
		if (!icon_url) {
			static const char *exts[4] = { ".png", ".jpg", ".jpeg",
						       ".webp" };

			for (int e = 0; e < 4; e++) {
				char p[DT_CFG_PATH + 512];
				struct stat st;

				snprintf(p, sizeof(p), "%s/%s%s",
					 g_cfg.gen_icon_dir, app_id, exts[e]);
				if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
					char url[512];

					snprintf(url, sizeof(url),
						 "/static/icons/gen/%s%s",
						 app_id, exts[e]);
					icon_url = strdup(url);
					break;
				}
			}
		}

		app = dt_new_obj();
		if (app) {
			char *name_zh = NULL;
			aik_json *cats;

			dt_put_str(app, "id", app_id);
			dt_put_str(app, "name",
				   (ent.name_zh && *ent.name_zh) ? ent.name_zh
								 : ent.name);
			dt_put_str(app, "name_en", ent.name);
			name_zh = zh_lookup(zh, app_id);
			if (!name_zh)
				name_zh = zh_lookup(zh, ent.name);
			if (name_zh) {
				dt_put_str(app, "name_zh", name_zh);
				free(name_zh);
			} else {
				dt_put_null(app, "name_zh");
			}
			dt_put_str(app, "comment",
				   (ent.comment_zh && *ent.comment_zh)
					   ? ent.comment_zh
				   : (ent.comment ? ent.comment : ""));
			dt_put_str(app, "exec", ent.exec ? ent.exec : "");
			cats = dt_new_arr();
			if (cats) {
				/* 分号分段、去空,保序 */
				size_t start = 0, i = 0;
				size_t len = strlen(ent.categories);

				while (i <= len) {
					if (i == len ||
					    ent.categories[i] == ';') {
						if (i > start) {
							char *seg = dup_nonempty(
								ent.categories +
									start,
								i - start);

							if (seg) {
								dt_arr_push_str(cats,
										seg);
								free(seg);
							}
						}
						start = i + 1;
						if (i == len)
							break;
					}
					i++;
				}
				aik_json_obj_put(app, "categories", cats);
			}
			dt_put_bool(app, "terminal", ent.terminal);
			if (icon_url)
				dt_put_str(app, "icon", icon_url);
			else
				dt_put_null(app, "icon");
			dt_put_bool(app, "virtual", 0);
			aik_json_arr_push(apps, app);
		}
		free(icon_url);
		entry_free(&ent);
	next:
		free(names[i]);
	}

	/* 真实应用 <5 → 合并 catalog(virtual/source 补尾,重复 id 跳过) */
	if (aik_json_count(apps) < 5) {
		aik_json *catalog = load_demo_catalog();

		if (catalog) {
			size_t n = aik_json_count(catalog);

			for (size_t i = 0; i < n; i++) {
				const aik_json *a = aik_json_at(catalog, i);
				const aik_json *idv = aik_json_get(a, "id");
				const char *id;
				int dup = 0;

				if (aik_json_typeof(a) != AIK_JSON_OBJ ||
				    !idv ||
				    aik_json_typeof(idv) != AIK_JSON_STR ||
				    aik_json_strlen(idv) == 0)
					continue;
				id = aik_json_str(idv);
				for (size_t k = 0; k < aik_json_count(apps); k++) {
					const aik_json *kid = aik_json_get(
						aik_json_at(apps, k), "id");

					if (kid &&
					    aik_json_typeof(kid) ==
						    AIK_JSON_STR &&
					    strcmp(aik_json_str(kid), id) == 0) {
						dup = 1;
						break;
					}
				}
				if (dup)
					continue;
				{
					aik_json *item = dt_copy(a);

					if (!item)
						continue;
					aik_json_obj_set(item, "virtual",
							 dt_new_bool(1));
					if (!aik_json_get(item, "source"))
						aik_json_obj_put(
							item, "source",
							dt_new_str("w76b-demo-catalog"));
					aik_json_arr_push(apps, item);
				}
			}
			aik_json_free(catalog);
		}
	}
	/* zh 为共享缓存对象(g_zh),不得释放 */
	return apps;
}

/* ---------------- 缓存 ---------------- */

static aik_json *g_apps_cache;
static long long g_apps_ts = -1;

aik_json *dt_get_apps(int force)
{
	pthread_mutex_lock(&g_lock_apps);
	{
		long long now = dt_time();

		if (force || !g_apps_cache ||
		    (g_apps_ts >= 0 && now - g_apps_ts > 120)) {
			aik_json *fresh = dt_collect_apps();

			if (fresh) {
				aik_json_free(g_apps_cache);
				g_apps_cache = fresh;
				g_apps_ts = now;
			}
		}
	}
	pthread_mutex_unlock(&g_lock_apps);
	return g_apps_cache ? g_apps_cache : dt_new_arr();
}
