// SPDX-License-Identifier: GPL-2.0
/* test_dtstate.c - 主题自愈/custom 混色/窗口状态机/PIN/notifs 不对称截断 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "desktop/dtcore.h"
#include "desktop/dtjson.h"
#include "desktop/dtstate.h"
#include "desktop/dttheme.h"

static int fails = 0;

static void check_str(const char *name, const char *got, const char *want)
{
	if (!got || strcmp(got, want) != 0) {
		printf("FAIL %s:\n  got : %s\n  want: %s\n", name,
		       got ? got : "(null)", want);
		fails++;
	} else {
		printf("ok %s\n", name);
	}
}

static void check_bool(const char *name, int got, int want)
{
	if (got != want) {
		printf("FAIL %s: got %d want %d\n", name, got, want);
		fails++;
	} else {
		printf("ok %s\n", name);
	}
}

static char g_dir[] = "/tmp/dt-test-state-XXXXXX";
static char g_base[] = "/tmp/dt-test-base-XXXXXX";

static void setup(void)
{
	if (!mkdtemp(g_dir) || !mkdtemp(g_base)) {
		perror("mkdtemp");
		exit(1);
	}
	/* dt_paths_init 依赖 env;手工填 g_cfg */
	dt_path_join(g_cfg.state_root, sizeof(g_cfg.state_root), g_dir, "state");
	mkdir(g_cfg.state_root, 0700);
	dt_path_join(g_cfg.theme_file, sizeof(g_cfg.theme_file),
		     g_cfg.state_root, "theme.json");
	dt_path_join(g_cfg.base_dir, sizeof(g_cfg.base_dir), g_base, "");
	dt_path_join(g_cfg.theme_seed, sizeof(g_cfg.theme_seed), g_base,
		     "theme.json");
	dt_path_join(g_cfg.chat_dir, sizeof(g_cfg.chat_dir), g_cfg.state_root,
		     "chats");
	dt_path_join(g_cfg.pin_file, sizeof(g_cfg.pin_file), g_cfg.state_root,
		     "pin.json");
	dt_path_join(g_cfg.notif_file, sizeof(g_cfg.notif_file),
		     g_cfg.state_root, "notifs.json");
	dt_path_join(g_cfg.desktop_file, sizeof(g_cfg.desktop_file),
		     g_cfg.state_root, "desktop.json");
	dt_path_join(g_cfg.screenshot_dir, sizeof(g_cfg.screenshot_dir),
		     g_cfg.state_root, "screenshots");
	dt_path_join(g_cfg.icon_root, sizeof(g_cfg.icon_root), g_cfg.state_root,
		     "icons");
	dt_path_join(g_cfg.icon_out_dir, sizeof(g_cfg.icon_out_dir),
		     g_cfg.state_root, "icons/apps");
	dt_path_join(g_cfg.static_dir, sizeof(g_cfg.static_dir), g_base,
		     "static");
	dt_path_join(g_cfg.wallpaper_dir, sizeof(g_cfg.wallpaper_dir), g_base,
		     "static/wallpapers");
	dt_path_join(g_cfg.seed_notifs, sizeof(g_cfg.seed_notifs), g_base,
		     "data/notifs.json");
	dt_path_join(g_cfg.seed_desktop, sizeof(g_cfg.seed_desktop), g_base,
		     "data/desktop.json");
	dt_path_join(g_cfg.seed_pin, sizeof(g_cfg.seed_pin), g_base,
		     "data/pin.json");
	dt_path_join(g_cfg.locale_file, sizeof(g_cfg.locale_file), g_base,
		     "locales/zh_CN.json");
	dt_path_join(g_cfg.catalog_file, sizeof(g_cfg.catalog_file), g_base,
		     "data/apps-catalog.json");
	dt_path_join(g_cfg.apps_dir, sizeof(g_cfg.apps_dir), g_base, "");
	snprintf(g_cfg.version, sizeof(g_cfg.version), "IMG-7-W76b");
	dt_freeze_set(1775000000, 1); /* 冻结时钟 + 定序随机 */
}

static void write_file_str(const char *path, const char *text)
{
	FILE *fh = fopen(path, "wb");

	if (!fh)
		return;
	fwrite(text, 1, strlen(text), fh);
	fclose(fh);
}

int main(void)
{
	setup();

	/* ---------------- theme 自愈 ---------------- */
	write_file_str(g_cfg.theme_file, "CORRUPT NOT JSON");
	{
		aik_json *t = dt_load_theme();
		char *s = dt_json_dump_default(t);
		const aik_json *themes = dt_get(t, "themes");

		check_bool("heal-total-themes-n", aik_json_count(themes) == 3,
			   1);
		check_str("heal-current", aik_json_str(dt_get(t, "current")),
			  "dark");
		check_str("heal-wallpaper",
			  aik_json_str(dt_get(t, "wallpaper")), "gradient");
		free(s);
		aik_json_free(t);
		/* 自愈重写后文件可解析且 current 在首位 */
		{
			aik_json *reread = dt_read_json(g_cfg.theme_file);
			const char *k0 = aik_json_key_at(reread, 0);

			check_str("heal-file-key0", k0, "current");
			aik_json_free(reread);
		}
	}
	{
		/* 局部损坏:dark 只有两键但有 bg → 保留原样;
		 * light/pink 补入;current 保留 pink */
		write_file_str(g_cfg.theme_file,
			       "{\"current\": \"pink\", \"themes\": "
			       "{\"dark\": {\"bg\": \"#0b0f14\", "
			       "\"display\": \"保留显示名\"}}}");
		{
			aik_json *t = dt_load_theme();
			const aik_json *dark =
				dt_get(dt_get(t, "themes"), "dark");

			check_bool("heal-partial-dark-keys",
				   aik_json_count(dark) == 2, 1);
			check_str("heal-partial-current",
				  aik_json_str(dt_get(t, "current")), "pink");
			aik_json_free(t);
		}
	}

	/* ---------------- build_custom_theme(核心向量 S3 黄金色) --------- */
	/* 先回写全损文件触发整体自愈 → theme.json 为 15 键完整态(与向量 S3
	 * 前置一致;上一节的局部自愈态只有两键 dark,会让派生缺键) */
	write_file_str(g_cfg.theme_file, "CORRUPT NOT JSON");
	{
		aik_json *t = dt_load_theme();

		aik_json_free(t);
	}
	{
		aik_json *custom = dt_build_custom_theme("#3366ff", "dark");
		aik_json *themes;
		aik_json *theme = dt_load_theme();

		/* build 不落盘;手工挂入后核对向量实测色 */
		check_str("custom-bg",
			  aik_json_str(dt_get(custom, "bg")), "#0d1422");
		check_str("custom-bg2",
			  aik_json_str(dt_get(custom, "bg2")), "#142039");
		check_str("custom-panel_solid",
			  aik_json_str(dt_get(custom, "panel_solid")), "#162239");
		check_str("custom-bubble_ai",
			  aik_json_str(dt_get(custom, "bubble_ai")), "#1c2c4d");
		check_str("custom-bubble_user",
			  aik_json_str(dt_get(custom, "bubble_user")), "#2b57d9");
		check_str("custom-accent2",
			  aik_json_str(dt_get(custom, "accent2")), "#7a9cff");
		check_str("custom-accent_soft",
			  aik_json_str(dt_get(custom, "accent_soft")),
			  "rgba(51,102,255,0.16)");
		check_str("custom-wallpaper",
			  aik_json_str(dt_get(custom, "wallpaper")),
			  "linear-gradient(135deg,#132145 0%,#0d1422 50%,"
			  "#182b60 100%)");
		check_str("custom-display",
			  aik_json_str(dt_get(custom, "display")),
			  "自定义(#3366ff)");
		check_bool("custom-key-order-tail",
			   strcmp(aik_json_key_at(custom,
						  aik_json_count(custom) - 1),
				  "wallpaper_file") == 0,
			   1);
		themes = dt_get_mut(theme, "themes");
		aik_json_obj_set(themes, "custom", custom);
		aik_json_obj_set(theme, "current", dt_new_str("custom"));
		dt_save_theme(theme);
		{
			aik_json *o = dt_new_obj();
			aik_json *resp = dt_copy(dt_get(themes, "custom"));
			char *s;

			dt_put_bool(o, "ok", 1);
			dt_put_str(o, "current", "custom");
			aik_json_obj_put(o, "theme", resp);
			s = dt_json_dump_default(o);
			check_str("custom-response",
				  s,
				  "{\"ok\": true, \"current\": \"custom\", "
				  "\"theme\": {\"display\": \"自定义(#3366ff)\", "
				  "\"bg\": \"#0d1422\", \"bg2\": \"#142039\", "
				  "\"panel\": \"rgba(17,24,35,0.86)\", "
				  "\"panel_solid\": \"#162239\", "
				  "\"text\": \"#e6edf3\", "
				  "\"text_dim\": \"#8b98a5\", "
				  "\"accent\": \"#3366ff\", "
				  "\"accent_soft\": \"rgba(51,102,255,0.16)\", "
				  "\"accent2\": \"#7a9cff\", "
				  "\"border\": \"rgba(255,255,255,0.08)\", "
				  "\"shadow\": \"0 18px 50px rgba(0,0,0,0.5)\", "
				  "\"wallpaper\": \"linear-gradient(135deg,"
				  "#132145 0%,#0d1422 50%,#182b60 100%)\", "
				  "\"bubble_ai\": \"#1c2c4d\", "
				  "\"bubble_user\": \"#2b57d9\", "
				  "\"wallpaper_file\": null}}");
			free(s);
			aik_json_free(o);
		}
		aik_json_free(theme);
	}

	/* ---------------- 窗口状态机 ---------------- */
	{
		aik_json *obj = dt_load_desktop();
		aik_json *app = dt_new_obj();
		aik_json *win;
		int created = 0;
		aik_json *snap;

		dt_put_str(app, "id", "alpha-demo");
		dt_put_str(app, "name", "阿尔法演示");
		win = dt_window_launch(obj, app, &created);
		check_bool("launch-created", created, 1);
		check_str("launch-wid", aik_json_str(dt_get(win, "id")),
			  "w-0001");
		{
			char buf[32];

			snprintf(buf, sizeof(buf), "%lld",
				 aik_json_int(dt_get(win, "z")));
			check_str("launch-z-value", buf, "1");
			snprintf(buf, sizeof(buf), "%lld",
				 aik_json_int(dt_get(dt_get(win, "geometry"),
						     "x")));
			check_str("launch-geo-x", buf, "120");
			snprintf(buf, sizeof(buf), "%lld",
				 aik_json_int(dt_get(dt_get(win, "geometry"),
						     "y")));
			check_str("launch-geo-y", buf, "96");
		}
		/* 同 app 再次 launch → focus-only,z+1 */
		win = dt_window_launch(obj, app, &created);
		check_bool("launch-again-created", created, 0);
		{
			char buf[32];

			snprintf(buf, sizeof(buf), "%lld",
				 aik_json_int(dt_get(win, "z")));
			check_str("launch-again-z", buf, "2");
		}
		/* 键入文本 → updated 惰性追加,4096 上限(空文本一次灌满) */
		{
			char big[5000];

			memset(big, 'A', sizeof(big));
			big[sizeof(big) - 1] = '\0';
			{
				long long added = dt_window_text_append(win, big);
				char buf[32];

				snprintf(buf, sizeof(buf), "%lld", added);
				check_str("text-append-cap", buf, "4096");
			}
		}
		snap = dt_desktop_snapshot(obj);
		check_bool("snap-count", aik_json_count(obj) > 0, 1);
		{
			char buf[32];

			snprintf(buf, sizeof(buf), "%lld",
				 aik_json_int(dt_get(snap, "count")));
			check_str("snap-count-1", buf, "1");
			check_str("snap-focused",
				  aik_json_str(dt_get(snap, "focused")),
				  "w-0001");
		}
		aik_json_free(snap);
		aik_json_free(app);
		aik_json_free(obj);
	}

	/* ---------------- PIN 状态机 ---------------- */
	{
		char *w = dt_pin_warning("1234");

		check_str("pin-warn-short", w, "PIN 少于 6 位,建议使用更长的 PIN");
		free(w);
		w = dt_pin_warning("11111111");
		check_str("pin-warn-repeat", w, "PIN 为重复数字,过于薄弱");
		free(w);
		w = dt_pin_warning("12345678");
		check_str("pin-warn-seq", w, "PIN 为连续顺序数字,过于薄弱");
		free(w);
		w = dt_pin_warning("135713");
		check_bool("pin-warn-none", w == NULL, 1);
		free(w);
	}
	{
		/* 定序随机:第 5 次调用 = 0.618(前 4 次消耗 0.042..0.5) */
		char r[40];

		for (int i = 0; i < 4; i++)
			(void)dt_random();
		aik_json_dtoa(dt_random(), r, sizeof(r));
		check_str("pin-salt-seq", r, "0.618");
	}

	/* ---------------- notifs 不对称截断(整表丢尾/单条保尾) --------- */
	{
		/* 整表 105 条 → 前 100(丢尾) */
		static const char bulk_json[] =
			"[\"0\",\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\","
			"\"9\",\"10\",\"11\",\"12\",\"13\",\"14\",\"15\",\"16\","
			"\"17\",\"18\",\"19\",\"20\",\"21\",\"22\",\"23\",\"24\","
			"\"25\",\"26\",\"27\",\"28\",\"29\",\"30\",\"31\",\"32\","
			"\"33\",\"34\",\"35\",\"36\",\"37\",\"38\",\"39\",\"40\","
			"\"41\",\"42\",\"43\",\"44\",\"45\",\"46\",\"47\",\"48\","
			"\"49\",\"50\",\"51\",\"52\",\"53\",\"54\",\"55\",\"56\","
			"\"57\",\"58\",\"59\",\"60\",\"61\",\"62\",\"63\",\"64\","
			"\"65\",\"66\",\"67\",\"68\",\"69\",\"70\",\"71\",\"72\","
			"\"73\",\"74\",\"75\",\"76\",\"77\",\"78\",\"79\",\"80\","
			"\"81\",\"82\",\"83\",\"84\",\"85\",\"86\",\"87\",\"88\","
			"\"89\",\"90\",\"91\",\"92\",\"93\",\"94\",\"95\",\"96\","
			"\"97\",\"98\",\"99\",\"100\",\"101\",\"102\",\"103\","
			"\"104\"]";
		aik_json *bulk = dt_parse(bulk_json, strlen(bulk_json));
		check_bool("bulk-105-n", aik_json_count(bulk) == 105, 1);
		{
			/* 模拟 POST 分支:[:100] */
			aik_json *kept = dt_new_arr();

			for (size_t i = 0; i < 100; i++)
				dt_arr_push_copy(kept, aik_json_at(bulk, i));
			check_bool("bulk-kept-100", aik_json_count(kept) == 100,
				   1);
			check_str("bulk-kept-first",
				  aik_json_str(aik_json_at(kept, 0)), "0");
			check_str("bulk-kept-last",
				  aik_json_str(aik_json_at(kept, 99)), "99");
			aik_json_free(kept);
		}
		aik_json_free(bulk);
		/* 单条追加 100+1 → [-100:](保尾) */
		{
			aik_json *cur = dt_new_arr();

			for (int i = 0; i < 100; i++) {
				char buf[16];

				snprintf(buf, sizeof(buf), "n%d", i);
				dt_arr_push_str(cur, buf);
			}
			dt_arr_push_str(cur, "new");
			{
				size_t n = aik_json_count(cur);
				aik_json *kept = dt_new_arr();

				for (size_t i = n - 100; i < n; i++)
					dt_arr_push_copy(kept,
							 aik_json_at(cur, i));
				check_bool("append-kept-100",
					   aik_json_count(kept) == 100, 1);
				check_str("append-kept-first",
					  aik_json_str(aik_json_at(kept, 0)),
					  "n1");
				check_str("append-kept-last",
					  aik_json_str(aik_json_at(kept, 99)),
					  "new");
				aik_json_free(kept);
			}
			aik_json_free(cur);
		}
	}

	/* ---------------- notif 条目键序(冻结 time_ns) ---------------- */
	{
		static const char body_json[] =
			"{\"title\": \"标题\", \"body\": \"正文\", \"tag\": 5}";
		aik_json *body = dt_parse(body_json, strlen(body_json));
		int bad = 0;
		aik_json *e = dt_notif_new_entry(body, &bad);
		char *s;

		check_bool("notif-entry-ok", bad == 0, 1);
		s = dt_json_dump_default(e);
		check_str("notif-entry", s,
			  "{\"title\": \"标题\", \"body\": \"正文\", "
			  "\"tag\": \"5\", \"time\": \"07:33\", "
			  "\"id\": \"n-1775000000001000000\", "
			  "\"source\": \"desktop.notifications.send\"}");
		free(s);
		aik_json_free(e);
		aik_json_free(body);
	}

	if (fails) {
		printf("test_dtstate: %d FAIL\n", fails);
		return 1;
	}
	printf("test_dtstate: PASS\n");
	return 0;
}
