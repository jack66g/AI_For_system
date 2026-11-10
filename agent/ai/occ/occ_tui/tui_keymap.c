/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_keymap.c - 键位表数据化实现（T9c3）
 *
 * 缺省表=OCD 现值（动作子集，见头注）；覆盖文件整表解析后一次提交
 * （坏文件不动现有表）。键串归一在解析期做，与 tui_event_keystr 的
 * 规范形（ctrl+→alt+→super+→shift+ 前缀序、return/escape/pageup/
 * pagedown 键名）对齐——运行期 lookup 是纯 strcmp。
 */
#define _DEFAULT_SOURCE 1
#include "tui_keymap.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tui_utf8.h"

#define KM_ACT_NAME_MAX 40
#define KM_MAX_ACTS 32

struct km_act {
	char name[KM_ACT_NAME_MAX];
	int ctx;
	char keys[TUI_KM_KEYS_PER_ACT][TUI_KM_KEY_MAX];
	int nkeys;
};

struct tui_keymap {
	struct km_act acts[KM_MAX_ACTS];
	int nacts;
	char leader[TUI_KM_KEY_MAX];
	long leader_timeout_ms;
};

/* ---- 缺省表（OCD §2.2/§2.4 现值子集） ---- */

struct km_def {
	const char *name;
	int ctx;
	const char *keys;		/* 逗号分隔（无空格，解析期归一） */
};

static const struct km_def KM_DEFAULTS[] = {
	/* BASE：退出/中断/翻页/leader 命令 */
	{ "app.exit", TUI_KM_CTX_BASE, "ctrl+c,ctrl+d,<leader>q" },
	{ "prompt.clear", TUI_KM_CTX_BASE, "ctrl+c,ctrl+d" },
	{ "session.interrupt", TUI_KM_CTX_BASE, "escape" },
	{ "session.page.up", TUI_KM_CTX_BASE, "pageup" },
	{ "session.page.down", TUI_KM_CTX_BASE, "pagedown" },
	/* T1：Home/End = 视口顶/底（BASE 专属；OVERLAY 的 Home/End 仍归
	 * dialog.select.home/end——上下文隔离） */
	{ "session.scroll.top", TUI_KM_CTX_BASE, "home" },
	{ "session.scroll.bottom", TUI_KM_CTX_BASE, "end" },
	{ "session.new", TUI_KM_CTX_BASE, "<leader>n,ctrl+n" },
	{ "session.list", TUI_KM_CTX_BASE, "<leader>l" },
	{ "session.rename", TUI_KM_CTX_BASE, "ctrl+r" },
	{ "session.compact", TUI_KM_CTX_BASE, "<leader>c" },
	{ "model.list", TUI_KM_CTX_BASE, "<leader>m" },
	{ "opencode.status", TUI_KM_CTX_BASE, "<leader>s" },
	/* E 方案：会话侧栏展开/收起（footer `[ctrl+b] 会话` 提示同源） */
	{ "sidebar.toggle", TUI_KM_CTX_BASE, "ctrl+b" },
	/* OVERLAY：对话框标准键（keybind.ts:261-286）+ 模型框行内动作 */
	{ "dialog.select.prev", TUI_KM_CTX_OVERLAY, "up,ctrl+p" },
	{ "dialog.select.next", TUI_KM_CTX_OVERLAY, "down,ctrl+n" },
	{ "dialog.select.page_up", TUI_KM_CTX_OVERLAY, "pageup" },
	{ "dialog.select.page_down", TUI_KM_CTX_OVERLAY, "pagedown" },
	{ "dialog.select.home", TUI_KM_CTX_OVERLAY, "home" },
	{ "dialog.select.end", TUI_KM_CTX_OVERLAY, "end" },
	{ "dialog.select.submit", TUI_KM_CTX_OVERLAY, "return" },
	{ "dialog.close", TUI_KM_CTX_OVERLAY, "escape" },
	{ "model.add", TUI_KM_CTX_OVERLAY, "ctrl+a" },
	{ "model.favorite", TUI_KM_CTX_OVERLAY, "ctrl+f" },
	/* OCC-DEBT：/models 非对话条目显隐切换（OCD ctrl+t=variant 未实现，
	 * occ 借位；keymap 覆盖文件可改绑） */
	{ "model.nonchat", TUI_KM_CTX_OVERLAY, "ctrl+t" }
};
#define KM_NDEFAULTS ((int)(sizeof(KM_DEFAULTS) / sizeof(KM_DEFAULTS[0])))

/* 命名键白名单（tui_key_name 的目标形 + space） */
static const char *const KM_NAMED[] = {
	"return", "tab", "backspace", "escape", "up", "down", "left",
	"right", "home", "end", "pageup", "pagedown", "delete", "insert",
	"f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10",
	"f11", "f12", "space", NULL
};

static int km_is_named(const char *k)
{
	int i;

	for (i = 0; KM_NAMED[i]; i++) {
		if (!strcmp(k, KM_NAMED[i]))
			return 1;
	}
	return 0;
}

/* whole-key 别名（keymap.tsx:80-88 + 显示别名 del/pgdn） */
static int km_alias_whole(const char *k, char *out, size_t cap)
{
	const char *to = NULL;

	if (!strcmp(k, "enter"))
		to = "return";
	else if (!strcmp(k, "esc"))
		to = "escape";
	else if (!strcmp(k, "pgup"))
		to = "pageup";
	else if (!strcmp(k, "pgdn") || !strcmp(k, "pgdown"))
		to = "pagedown";
	else if (!strcmp(k, "del"))
		to = "delete";
	if (!to)
		return 0;
	if (strlen(to) + 1 > cap)
		return 0;
	memcpy(out, to, strlen(to) + 1);
	return 1;
}

/* 终键校验+归一：命名键/单 ASCII（字母小写）/单码点 UTF-8；别名先归 */
static int km_final_key(const char *k, char *out, size_t cap)
{
	char aliased[TUI_KM_KEY_MAX];
	size_t len;
	int n;

	if (!k || !*k || cap == 0)
		return 0;
	if (km_alias_whole(k, aliased, sizeof(aliased)))
		k = aliased;
	if (km_is_named(k)) {
		if (strlen(k) + 1 > cap)
			return 0;
		memcpy(out, k, strlen(k) + 1);
		return 1;
	}
	len = strlen(k);
	if (len == 1) {
		unsigned char c = (unsigned char)k[0];

		if (c <= 0x20 || c >= 0x7f)	/* 空格/控制/非 ASCII 单字节拒 */
			return 0;
		if (c >= 'A' && c <= 'Z')
			c = (unsigned char)(c - 'A' + 'a');
		out[0] = (char)c;
		out[1] = '\0';
		return 1;
	}
	n = tui_utf8_seqlen((uint8_t)k[0]);
	if (n > 0 && (size_t)n == len && n <= (int)cap - 1) {
		memcpy(out, k, len + 1);	/* 单码点 UTF-8 */
		return 1;
	}
	return 0;
}

/* 修饰段合法性（ctrl/alt/super/shift） */
static int km_is_mod(const char *s)
{
	return !strcmp(s, "ctrl") || !strcmp(s, "alt") ||
	       !strcmp(s, "super") || !strcmp(s, "shift");
}

int tui_keymap_norm_key(const char *in, char *out, size_t cap)
{
	char segs[6][TUI_KM_KEY_MAX];
	int mods[4] = { 0, 0, 0, 0 };	/* ctrl alt super shift */
	int nseg = 0, i;
	size_t pos = 0;
	const char *final;
	char finalbuf[TUI_KM_KEY_MAX];
	char *p;

	if (!in || !out || cap == 0)
		return 0;
	out[0] = '\0';
	/* <leader> 前缀：其后只允许「无修饰终键」 */
	if (!strncmp(in, "<leader>", 8)) {
		char rest[TUI_KM_KEY_MAX];

		if (!in[8] || strlen(in + 8) >= sizeof(rest))
			return 0;
		if (strchr(in + 8, '+'))	/* <leader>ctrl+f 形态拒（严格） */
			return 0;
		if (!km_final_key(in + 8, rest, sizeof(rest)))
			return 0;
		if (9 + strlen(rest) + 1 > cap)
			return 0;
		memcpy(out, "<leader>", 8);
		memcpy(out + 8, rest, strlen(rest) + 1);
		return 1;
	}
	/* 按 '+' 切段（≤6 段） */
	p = (char *)in;
	while (p && *p) {
		char *plus = strchr(p, '+');

		if (nseg >= 6)
			return 0;
		if (plus) {
			size_t n = (size_t)(plus - p);

			if (n == 0 || n >= sizeof(segs[0]))
				return 0;
			memcpy(segs[nseg], p, n);
			segs[nseg][n] = '\0';
			nseg++;
			p = plus + 1;
		} else {
			if (strlen(p) >= sizeof(segs[0]))
				return 0;
			strcpy(segs[nseg], p);
			nseg++;
			p = NULL;
		}
	}
	if (nseg == 0)
		return 0;
	final = segs[nseg - 1];
	for (i = 0; i < nseg - 1; i++) {
		if (!km_is_mod(segs[i]))
			return 0;
		if (!strcmp(segs[i], "ctrl"))
			mods[0]++;
		else if (!strcmp(segs[i], "alt"))
			mods[1]++;
		else if (!strcmp(segs[i], "super"))
			mods[2]++;
		else
			mods[3]++;
	}
	for (i = 0; i < 4; i++) {
		if (mods[i] > 1)
			return 0;	/* 重复修饰拒 */
	}
	if (!km_final_key(final, finalbuf, sizeof(finalbuf)))
		return 0;
	/* 按 tui_event_keystr 序重建：ctrl+ alt+ super+ shift+ + 终键 */
	pos = 0;
	{
		static const char *const ord[4] = {
			"ctrl+", "alt+", "super+", "shift+"
		};

		for (i = 0; i < 4; i++) {
			if (!mods[i])
				continue;
			if (pos + strlen(ord[i]) + 1 > cap)
				return 0;
			memcpy(out + pos, ord[i], strlen(ord[i]));
			pos += strlen(ord[i]);
		}
	}
	if (pos + strlen(finalbuf) + 1 > cap)
		return 0;
	memcpy(out + pos, finalbuf, strlen(finalbuf) + 1);
	return 1;
}

/* ---- 生命周期 ---- */

tui_keymap *tui_keymap_create(void)
{
	tui_keymap *km = calloc(1, sizeof(*km));
	int i;

	if (!km)
		return NULL;
	for (i = 0; i < KM_NDEFAULTS; i++) {
		struct km_act *a = &km->acts[km->nacts];
		char buf[192];
		char *p;

		snprintf(a->name, sizeof(a->name), "%s", KM_DEFAULTS[i].name);
		a->ctx = KM_DEFAULTS[i].ctx;
		snprintf(buf, sizeof(buf), "%s", KM_DEFAULTS[i].keys);
		p = strtok(buf, ",");
		while (p && a->nkeys < TUI_KM_KEYS_PER_ACT) {
			if (!tui_keymap_norm_key(p, a->keys[a->nkeys],
						 TUI_KM_KEY_MAX)) {
				/* 缺省表必须自身合法（写码期即炸） */
				free(km);
				return NULL;
			}
			a->nkeys++;
			p = strtok(NULL, ",");
		}
		km->nacts++;
	}
	memcpy(km->leader, "ctrl+x", 7);
	km->leader_timeout_ms = 2000;
	return km;
}

void tui_keymap_destroy(tui_keymap *km)
{
	free(km);
}

int tui_keymap_action_ctx(const char *action)
{
	int i;

	if (!action)
		return -1;
	for (i = 0; i < KM_NDEFAULTS; i++) {
		if (!strcmp(action, KM_DEFAULTS[i].name))
			return KM_DEFAULTS[i].ctx;
	}
	return -1;
}

/* ---- 覆盖加载（整表一次提交） ---- */

static struct km_act *km_find(tui_keymap *km, const char *name)
{
	int i;

	for (i = 0; i < km->nacts; i++) {
		if (!strcmp(km->acts[i].name, name))
			return &km->acts[i];
	}
	return NULL;
}

static void km_set_err(char *err, size_t errlen, int lineno, const char *why,
		       const char *detail)
{
	if (err && errlen)
		snprintf(err, errlen, "keymap: line %d: %s%.80s", lineno, why,
			 detail ? detail : "");
}

int tui_keymap_load(tui_keymap *km, const char *path, char *err,
		    size_t errlen)
{
	FILE *f;
	char line[512];
	int lineno = 0;
	int rc = 0;

	if (err && errlen)
		err[0] = '\0';
	if (!km || !path || !path[0]) {
		if (err)
			snprintf(err, errlen, "keymap: bad args");
		return -1;
	}
	f = fopen(path, "r");
	if (!f) {
		if (errno == ENOENT)
			return 0;	/* 缺省静默生效 */
		if (err)
			snprintf(err, errlen, "keymap: cannot open %.160s: %s",
				 path, strerror(errno));
		return -1;
	}
	/* 解析进副本；仅整文件全对才提交 */
	{
		tui_keymap tmp = *km;	/* 定长结构，整拷 */

		while (fgets(line, sizeof(line), f)) {
			char *s, *eq, *key, *val;
			char *end = NULL;

			lineno++;
			s = line;
			while (*s && isspace((unsigned char)*s))
				s++;
			{
				char *e = s + strlen(s);

				while (e > s && isspace((unsigned char)e[-1]))
					*--e = '\0';
			}
			if (!*s || *s == '#')
				continue;
			eq = strchr(s, '=');
			if (!eq) {
				km_set_err(err, errlen, lineno, "缺少 '='",
					   NULL);
				rc = -1;
				break;
			}
			*eq = '\0';
			key = s;
			val = eq + 1;
			while (*val && isspace((unsigned char)*val))
				val++;
			{
				char *e = key + strlen(key);

				while (e > key && isspace((unsigned char)e[-1]))
					*--e = '\0';
			}
			if (!*key) {
				km_set_err(err, errlen, lineno, "空动作名", NULL);
				rc = -1;
				break;
			}
			if (!strcmp(key, "leader")) {
				char nb[TUI_KM_KEY_MAX];

				if (!tui_keymap_norm_key(val, nb,
							 sizeof(nb)) ||
				    !strncmp(nb, "<leader>", 8)) {
					km_set_err(err, errlen, lineno,
						   "leader 键非法 `", val);
					if (err && errlen) {
						size_t l = strlen(err);

						if (l + 2 < errlen) {
							err[l] = '`';
							err[l + 1] = '\0';
						}
					}
					rc = -1;
					break;
				}
				memcpy(tmp.leader, nb, strlen(nb) + 1);
				continue;
			}
			if (!strcmp(key, "leader_timeout")) {
				long v = strtol(val, &end, 10);

				if (end == val || *end != '\0' || v < 100 ||
				    v > 60000) {
					km_set_err(err, errlen, lineno,
						   "leader_timeout 须为 "
						   "100..60000 ms", NULL);
					rc = -1;
					break;
				}
				tmp.leader_timeout_ms = v;
				continue;
			}
			if (tui_keymap_action_ctx(key) < 0) {
				km_set_err(err, errlen, lineno, "未知动作 `",
					   key);
				rc = -1;
				break;
			}
			{
				struct km_act *a = km_find(&tmp, key);

				if (!a) {	/* 理论不可达（def 全表有） */
					km_set_err(err, errlen, lineno,
						   "动作无表项 `", key);
					rc = -1;
					break;
				}
				a->nkeys = 0;	/* 覆盖=整动作替换 */
				if (!strcmp(val, "none"))
					continue;	/* 取消绑定 */
				{
					char buf[384];
					char *p;

					if (strlen(val) >= sizeof(buf)) {
						km_set_err(err, errlen, lineno,
							   "值过长", NULL);
						rc = -1;
						break;
					}
					strcpy(buf, val);
					p = strtok(buf, ",");
					while (p) {
						char *q = p;
						char nb[TUI_KM_KEY_MAX];

						while (*q && isspace((unsigned char)*q))
							q++;
						{
							char *e = q + strlen(q);

							while (e > q && isspace((unsigned char)e[-1]))
								*--e = '\0';
						}
						if (!*q) {
							km_set_err(err, errlen,
								   lineno,
								   "空键项",
								   NULL);
							rc = -1;
							break;
						}
						if (!tui_keymap_norm_key(q,
									 nb,
									 sizeof(nb))) {
							km_set_err(err, errlen,
								   lineno,
								   "键非法 `",
								   q);
							rc = -1;
							break;
						}
						if (a->nkeys >=
						    TUI_KM_KEYS_PER_ACT) {
							km_set_err(err, errlen,
								   lineno,
								   "单动作键数"
								   "超上限",
								   NULL);
							rc = -1;
							break;
						}
						memcpy(a->keys[a->nkeys], nb,
						       strlen(nb) + 1);
						a->nkeys++;
						p = strtok(NULL, ",");
					}
					if (rc)
						break;
				}
			}
		}
		fclose(f);
		if (rc == 0)
			*km = tmp;	/* 整文件全对才提交 */
	}
	return rc;
}

/* ---- 运行期查找 ---- */

const char *tui_keymap_lookup(const tui_keymap *km, const char *keystr,
			      int ctx)
{
	int i, j;

	if (!km || !keystr || !*keystr)
		return NULL;
	for (i = 0; i < km->nacts; i++) {
		const struct km_act *a = &km->acts[i];

		if (a->ctx != ctx)
			continue;
		for (j = 0; j < a->nkeys; j++) {
			if (!strcmp(a->keys[j], keystr))
				return a->name;
		}
	}
	return NULL;
}

const char *tui_keymap_lookup_leader(const tui_keymap *km,
				     const char *keystr)
{
	char full[TUI_KM_KEY_MAX + 8];
	int i, j;

	if (!km || !keystr || !*keystr)
		return NULL;
	if (strlen(keystr) + 9 > sizeof(full))
		return NULL;
	memcpy(full, "<leader>", 8);
	memcpy(full + 8, keystr, strlen(keystr) + 1);
	for (i = 0; i < km->nacts; i++) {
		const struct km_act *a = &km->acts[i];

		for (j = 0; j < a->nkeys; j++) {
			if (!strcmp(a->keys[j], full))
				return a->name;
		}
	}
	return NULL;
}

int tui_keymap_matches(const tui_keymap *km, const char *action,
		       const char *keystr, int ctx)
{
	const struct km_act *a;
	int i;

	if (!km || !action || !keystr)
		return 0;
	for (i = 0; i < km->nacts; i++) {
		if (!strcmp(km->acts[i].name, action)) {
			a = &km->acts[i];
			if (a->ctx != ctx)
				return 0;
			for (i = 0; i < a->nkeys; i++) {
				if (!strcmp(a->keys[i], keystr))
					return 1;
			}
			return 0;
		}
	}
	return 0;
}

const char *tui_keymap_leader(const tui_keymap *km)
{
	return km ? km->leader : "ctrl+x";
}

long tui_keymap_leader_timeout_ms(const tui_keymap *km)
{
	return km ? km->leader_timeout_ms : 2000;
}

int tui_keymap_binding_str(const tui_keymap *km, const char *action,
			   char *buf, size_t cap)
{
	size_t off = 0;
	int i, j;

	if (!km || !action || !buf || !cap)
		return -1;
	buf[0] = '\0';
	for (i = 0; i < km->nacts; i++) {
		const struct km_act *a = &km->acts[i];

		if (strcmp(a->name, action))
			continue;
		for (j = 0; j < a->nkeys; j++) {
			int n = snprintf(buf + off, cap - off, "%s%s",
					 j ? ", " : "", a->keys[j]);

			if (n < 0 || (size_t)n >= cap - off) {
				buf[off] = '\0';
				return (int)off;
			}
			off += (size_t)n;
		}
		return (int)off;
	}
	return -1;
}
