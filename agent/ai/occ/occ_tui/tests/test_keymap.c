/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_keymap.c - 键位表数据化（T9c3：OCD-SPEC §2 正典）
 *
 * 缺省表=OCD 现值子集；别名归一（enter/esc/pgup/pgdn/del + 修饰序）；
 * 覆盖文件整表提交（坏文件 -1 且表不变）；leader 序列；两上下文隔离。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../tui_keymap.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static const char *write_tmp(const char *content)
{
	static char path[128];
	FILE *f;

	snprintf(path, sizeof(path), "/tmp/occ-c3-keymap-%d.conf",
		 (int)getpid());
	f = fopen(path, "w");
	if (!f)
		return NULL;
	fputs(content, f);
	fclose(f);
	return path;
}

int main(void)
{
	tui_keymap *km;
	char buf[128];
	char nb[64];
	const char *p;
	char err[256];

	km = tui_keymap_create();
	OK(km != NULL, "create");

	/* ---- 缺省表 = OCD 现值 ---- */
	OK(strcmp(tui_keymap_leader(km), "ctrl+x") == 0, "leader-ctrl-x");
	OK(tui_keymap_leader_timeout_ms(km) == 2000, "leader-timeout-2s");
	OK(tui_keymap_binding_str(km, "app.exit", buf, sizeof(buf)) > 0 &&
	   strcmp(buf, "ctrl+c, ctrl+d, <leader>q") == 0, "exit-bindings");
	OK(tui_keymap_binding_str(km, "session.page.up", buf,
				  sizeof(buf)) > 0 &&
	   strcmp(buf, "pageup") == 0, "pageup-binding");
	OK(tui_keymap_binding_str(km, "dialog.select.submit", buf,
				  sizeof(buf)) > 0 &&
	   strcmp(buf, "return") == 0, "dialog-submit-binding");
	OK(tui_keymap_binding_str(km, "model.list", buf, sizeof(buf)) > 0 &&
	   strcmp(buf, "<leader>m") == 0, "model-list-leader");

	/* ---- 运行期查找（两上下文隔离：escape 各归其主） ---- */
	OK(strcmp(tui_keymap_lookup(km, "ctrl+c", TUI_KM_CTX_BASE),
		  "app.exit") == 0, "base-ctrl-c-exit");
	OK(strcmp(tui_keymap_lookup(km, "escape", TUI_KM_CTX_BASE),
		  "session.interrupt") == 0, "base-escape-interrupt");
	OK(strcmp(tui_keymap_lookup(km, "escape", TUI_KM_CTX_OVERLAY),
		  "dialog.close") == 0, "overlay-escape-close");
	OK(tui_keymap_lookup(km, "up", TUI_KM_CTX_BASE) == NULL,
	   "base-up-unbound");
	OK(strcmp(tui_keymap_lookup(km, "up", TUI_KM_CTX_OVERLAY),
		  "dialog.select.prev") == 0, "overlay-up-prev");
	OK(strcmp(tui_keymap_lookup(km, "ctrl+p", TUI_KM_CTX_OVERLAY),
		  "dialog.select.prev") == 0, "overlay-ctrl-p-prev");
	OK(tui_keymap_lookup(km, "f9", TUI_KM_CTX_BASE) == NULL,
	   "base-f9-unbound");

	/* matches：同一键双归属（ctrl+c 同时 exit/clear） */
	OK(tui_keymap_matches(km, "app.exit", "ctrl+c", TUI_KM_CTX_BASE),
	   "match-exit-ctrl-c");
	OK(tui_keymap_matches(km, "prompt.clear", "ctrl+c",
			      TUI_KM_CTX_BASE), "match-clear-ctrl-c");
	OK(!tui_keymap_matches(km, "prompt.clear", "ctrl+d",
			       TUI_KM_CTX_OVERLAY),
	   "match-ctx-isolated");
	OK(!tui_keymap_matches(km, "app.exit", "q", TUI_KM_CTX_BASE),
	   "match-plain-q-not-exit");

	/* leader 序列 */
	OK(strcmp(tui_keymap_lookup_leader(km, "q"), "app.exit") == 0,
	   "leader-q-exit");
	OK(strcmp(tui_keymap_lookup_leader(km, "n"), "session.new") == 0,
	   "leader-n-new");
	OK(strcmp(tui_keymap_lookup_leader(km, "l"), "session.list") == 0,
	   "leader-l-list");
	OK(strcmp(tui_keymap_lookup_leader(km, "m"), "model.list") == 0,
	   "leader-m-models");
	OK(tui_keymap_lookup_leader(km, "x") == NULL, "leader-x-none");

	/* 动作归属表（解析期校验用） */
	OK(tui_keymap_action_ctx("app.exit") == TUI_KM_CTX_BASE,
	   "ctx-app-exit");
	OK(tui_keymap_action_ctx("dialog.close") == TUI_KM_CTX_OVERLAY,
	   "ctx-dialog-close");
	OK(tui_keymap_action_ctx("no.such.action") == -1, "ctx-unknown");

	/* ---- 键串别名归一（keymap.tsx:80-88 + 修饰序） ---- */
	OK(tui_keymap_norm_key("enter", nb, sizeof(nb)) &&
	   strcmp(nb, "return") == 0, "norm-enter");
	OK(tui_keymap_norm_key("esc", nb, sizeof(nb)) &&
	   strcmp(nb, "escape") == 0, "norm-esc");
	OK(tui_keymap_norm_key("pgup", nb, sizeof(nb)) &&
	   strcmp(nb, "pageup") == 0, "norm-pgup");
	OK(tui_keymap_norm_key("pgdn", nb, sizeof(nb)) &&
	   strcmp(nb, "pagedown") == 0, "norm-pgdn");
	OK(tui_keymap_norm_key("pgdown", nb, sizeof(nb)) &&
	   strcmp(nb, "pagedown") == 0, "norm-pgdown");
	OK(tui_keymap_norm_key("del", nb, sizeof(nb)) &&
	   strcmp(nb, "delete") == 0, "norm-del");
	OK(tui_keymap_norm_key("shift+ctrl+t", nb, sizeof(nb)) &&
	   strcmp(nb, "ctrl+shift+t") == 0, "norm-mod-order");
	OK(tui_keymap_norm_key("Q", nb, sizeof(nb)) && strcmp(nb, "q") == 0,
	   "norm-lowercase");
	OK(tui_keymap_norm_key("<leader>q", nb, sizeof(nb)) &&
	   strcmp(nb, "<leader>q") == 0, "norm-leader-passthrough");
	OK(tui_keymap_norm_key("<leader>enter", nb, sizeof(nb)) &&
	   strcmp(nb, "<leader>return") == 0, "norm-leader-alias");
	OK(!tui_keymap_norm_key("ctrl+", nb, sizeof(nb)), "norm-trunc");
	OK(!tui_keymap_norm_key("+q", nb, sizeof(nb)), "norm-empty-mod");
	OK(!tui_keymap_norm_key("bogus+q", nb, sizeof(nb)),
	   "norm-unknown-mod");
	OK(!tui_keymap_norm_key("f13", nb, sizeof(nb)), "norm-unknown-key");
	OK(!tui_keymap_norm_key("<leader>ctrl+f", nb, sizeof(nb)),
	   "norm-leader-no-mods");
	OK(!tui_keymap_norm_key("", nb, sizeof(nb)), "norm-empty");

	/* ---- 覆盖文件（整表提交；坏文件表不变） ---- */
	p = write_tmp("# occ keymap\n"
		      "leader = ctrl+g\n"
		      "leader_timeout = 1500\n"
		      "app.exit = f9\n"
		      "session.rename = none\n"
		      "session.page.up = enter\n");
	OK(p != NULL, "tmp-written");
	err[0] = '\0';
	OK(tui_keymap_load(km, p, err, sizeof(err)) == 0, "load-good");
	OK(strcmp(tui_keymap_leader(km), "ctrl+g") == 0, "loaded-leader");
	OK(tui_keymap_leader_timeout_ms(km) == 1500, "loaded-timeout");
	OK(tui_keymap_binding_str(km, "app.exit", buf, sizeof(buf)) > 0 &&
	   strcmp(buf, "f9") == 0, "loaded-exit-f9");
	OK(tui_keymap_binding_str(km, "session.rename", buf,
				  sizeof(buf)) == 0, "loaded-rename-none");
	OK(tui_keymap_binding_str(km, "session.page.up", buf,
				  sizeof(buf)) > 0 &&
	   strcmp(buf, "return") == 0, "loaded-pageup-alias");
	/* 覆盖后 lookup 变化（app.exit 换到 f9；ctrl+c 仍归 prompt.clear） */
	OK(strcmp(tui_keymap_lookup(km, "f9", TUI_KM_CTX_BASE),
		  "app.exit") == 0, "lookup-f9-after-load");
	{
		const char *act = tui_keymap_lookup(km, "ctrl+c",
						    TUI_KM_CTX_BASE);

		OK(act && strcmp(act, "app.exit") != 0 &&
		   strcmp(act, "prompt.clear") == 0,
		   "old-exit-key-falls-to-clear");
	}
	/* leader 序列随覆盖变化（app.exit 不再有 <leader> 绑定） */
	OK(tui_keymap_lookup_leader(km, "q") == NULL, "old-leader-seq-gone");
	unlink(p);

	/* 坏文件：-1 + err + 表保持（leader 仍 ctrl+g） */
	p = write_tmp("leader = ctrl+z\nnot_an_action = ctrl+q\n");
	err[0] = '\0';
	OK(tui_keymap_load(km, p, err, sizeof(err)) == -1, "load-bad");
	OK(strstr(err, "未知动作") != NULL, "load-bad-msg");
	OK(strcmp(tui_keymap_leader(km), "ctrl+g") == 0,
	   "load-bad-keeps-prior");
	unlink(p);

	/* 文件不存在 → 0 静默 */
	err[0] = '\0';
	OK(tui_keymap_load(km, "/tmp/occ-c3-no-such-keymap.conf", err,
			   sizeof(err)) == 0, "load-missing-ok");

	tui_keymap_destroy(km);
	printf("test_keymap: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
