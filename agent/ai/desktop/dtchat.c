// SPDX-License-Identifier: GPL-2.0
/*
 * dtchat.c - 聊天主流程 C 化(T6c),对齐 server.py:181-413/2031-2150:
 *   - parse_intents:9 条正则意图表(码点级手写匹配器,语义对齐 Python re:
 *     re.I 只作用 ASCII、`.` 不跨 \n、`.{m,n}` 按码点、环视按 [A-Za-z0-9_]);
 *   - match_open_app:(?:打开|启动|运行|帮我开|launch|open)\s*(.{1,24}?)\s*
 *     [。.!]?\s*$ 惰性捕获 + _OPEN_STOP 泛指词拦截 + 19 组中文别名 +
 *     精确名/子串匹配;
 *   - call_llm:model.toml 现读 → 无 key 直接 None(不出网);forwarder→
 *     direct 双尝试;请求体键序 model,messages,temperature,max_tokens,
 *     stream,ensure_ascii 转义(python json.dumps 默认形态);底座
 *     cloud/http https_post_stream(仓库自有 mbedTLS 客户端,支持明文
 *     http://,不读 proxy 环境变量——见 T6C 报告有意差异);
 *   - [[...]] 动作抽取:DOTALL 惰性首个 + json.loads 严格(trailing 拒绝)
 *     + sort_keys 签名去重 + 保持 LLM 键序 + 标签段剔除;
 *   - demo_reply:内置应答器(read_proc_stats 实况 + VM 关闭态固定文案);
 *   - POST /api/chat 与 GET /api/chat?fallback= 路由。
 * read_proc_stats/read_model_conf 自 desktopd.c 移入(T6b 向量锁定;
 * mem_used_pct 修正为 round 后的 NUM,原先 INT 被 stats 归一掩蔽)。
 */
#define _POSIX_C_SOURCE 200809L

#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "desktop/dtapps.h"
#include "desktop/dtchat.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"
#include "desktop/dtstate.h"
#include "desktop/dtvm.h"
#include "cloud/http/http_client.h"

#define CHAT_LLM_TIMEOUT 25 /* LLM_TIMEOUT 25.0s 单次尝试 */

/* ---------------------------------------------------------------- 码点正则底座 */

/* Python re 对 str 按码点匹配;附字节偏移供捕获组回切原文 */
struct cptext {
	uint32_t *cp;  /* 码点序列 */
	size_t *off;   /* off[i] = 第 i 码点字节偏移;off[n] = 总字节数 */
	size_t n;
};

static size_t lit_cplen(const char *lit)
{
	size_t n = 0;

	for (const char *p = lit; *p;) {
		unsigned char c = (unsigned char)*p;

		if (c < 0x80)
			p += 1;
		else if ((c & 0xE0) == 0xC0)
			p += 2;
		else if ((c & 0xF0) == 0xE0)
			p += 3;
		else
			p += 4;
		n++;
	}
	return n;
}

static void cptext_free(struct cptext *t)
{
	free(t->cp);
	free(t->off);
	t->cp = NULL;
	t->off = NULL;
	t->n = 0;
}

static int cptext_init(struct cptext *t, const char *s)
{
	size_t len = strlen(s);

	t->cp = malloc((len + 1) * sizeof(uint32_t));
	t->off = malloc((len + 1) * sizeof(size_t));
	t->n = 0;
	if (!t->cp || !t->off) {
		cptext_free(t);
		return -1;
	}
	for (size_t i = 0; i < len;) {
		unsigned char c = (unsigned char)s[i];
		uint32_t v;
		size_t adv;

		if (c < 0x80) {
			v = c;
			adv = 1;
		} else if ((c & 0xE0) == 0xC0 && i + 1 < len &&
			   ((unsigned char)s[i + 1] & 0xC0) == 0x80) {
			v = ((uint32_t)(c & 0x1F) << 6) |
			    (uint32_t)((unsigned char)s[i + 1] & 0x3F);
			adv = 2;
		} else if ((c & 0xF0) == 0xE0 && i + 2 < len &&
			   ((unsigned char)s[i + 1] & 0xC0) == 0x80 &&
			   ((unsigned char)s[i + 2] & 0xC0) == 0x80) {
			v = ((uint32_t)(c & 0x0F) << 12) |
			    ((uint32_t)((unsigned char)s[i + 1] & 0x3F) << 6) |
			    (uint32_t)((unsigned char)s[i + 2] & 0x3F);
			adv = 3;
		} else if ((c & 0xF8) == 0xF0 && i + 3 < len &&
			   ((unsigned char)s[i + 1] & 0xC0) == 0x80 &&
			   ((unsigned char)s[i + 2] & 0xC0) == 0x80 &&
			   ((unsigned char)s[i + 3] & 0xC0) == 0x80) {
			v = ((uint32_t)(c & 0x07) << 18) |
			    ((uint32_t)((unsigned char)s[i + 1] & 0x3F) << 12) |
			    ((uint32_t)((unsigned char)s[i + 2] & 0x3F) << 6) |
			    (uint32_t)((unsigned char)s[i + 3] & 0x3F);
			adv = 4;
		} else {
			v = 0xFFFD; /* 坏序列按替换符(errors=replace 近似) */
			adv = 1;
		}
		t->off[t->n] = i;
		t->cp[t->n] = v;
		t->n++;
		i += adv;
	}
	t->off[t->n] = len;
	return 0;
}

/* Python re \s(str 模式:ASCII 空白 + \x1c-\x1f + \x85/\xa0/Unicode 空白) */
static int cp_is_space(uint32_t c)
{
	if (c == 0x09 || c == 0x0A || c == 0x0B || c == 0x0C || c == 0x0D ||
	    c == 0x1C || c == 0x1D || c == 0x1E || c == 0x1F || c == 0x20 ||
	    c == 0x85 || c == 0xA0 || c == 0x1680 || c == 0x2028 ||
	    c == 0x2029 || c == 0x202F || c == 0x205F || c == 0x3000)
		return 1;
	if (c >= 0x2000 && c <= 0x200A)
		return 1;
	return 0;
}

/* [A-Za-z0-9_] */
static int cp_is_word(uint32_t c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '_';
}

/* re.I 相等:仅 ASCII 字母折叠大小写 */
static int cp_ci_eq(uint32_t a, uint32_t b)
{
	if (a == b)
		return 1;
	if (a < 128 && b < 128) {
		uint32_t la = (a >= 'A' && a <= 'Z') ? a + 32 : a;
		uint32_t lb = (b >= 'A' && b <= 'Z') ? b + 32 : b;

		return la == lb;
	}
	return 0;
}

/* ci 匹配 UTF-8 字面量 lit 于 t[i..);返回推进后的码点下标,失败 -1 */
static long lit_at(const struct cptext *t, size_t i, const char *lit)
{
	size_t k = i;
	size_t adv;

	for (const char *p = lit; *p; p += adv) {
		unsigned char c = (unsigned char)p[0];
		uint32_t v;

		if (c < 0x80) {
			v = c;
			adv = 1;
		} else if ((c & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) {
			v = ((uint32_t)(c & 0x1F) << 6) |
			    (uint32_t)((unsigned char)p[1] & 0x3F);
			adv = 2;
		} else if ((c & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 &&
			   (p[2] & 0xC0) == 0x80) {
			v = ((uint32_t)(c & 0x0F) << 12) |
			    ((uint32_t)((unsigned char)p[1] & 0x3F) << 6) |
			    (uint32_t)((unsigned char)p[2] & 0x3F);
			adv = 3;
		} else {
			v = ((uint32_t)(c & 0x07) << 18) |
			    ((uint32_t)((unsigned char)p[1] & 0x3F) << 12) |
			    ((uint32_t)((unsigned char)p[2] & 0x3F) << 6) |
			    (uint32_t)((unsigned char)p[3] & 0x3F);
			adv = 4;
		}
		if (k >= t->n || !cp_ci_eq(t->cp[k], v))
			return -1;
		k++;
	}
	return (long)k;
}

/* 在 t[from..) 找 lit 首次出现(ci);返回起始码点下标或 -1 */
static long lit_find(const struct cptext *t, size_t from, const char *lit)
{
	for (size_t i = from; i < t->n; i++) {
		if (lit_at(t, i, lit) >= 0)
			return (long)i;
	}
	return -1;
}

static int any_lit(const struct cptext *t, const char **lits, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (lit_find(t, 0, lits[i]) >= 0)
			return 1;
	return 0;
}

/* (A|B|...).{0,gap}(C|D|...) 搜索;`.` 不跨 \n,按码点计 */
static int pair_rule(const struct cptext *t, const char **verbs, size_t nv,
		     const char **nouns, size_t nn, int gap)
{
	for (size_t i = 0; i < t->n; i++) {
		long e = -1;

		for (size_t v = 0; v < nv; v++) {
			e = lit_at(t, i, verbs[v]);
			if (e >= 0)
				break;
		}
		if (e < 0)
			continue;
		size_t j = (size_t)e;

		for (int k = 0; k <= gap; k++) {
			for (size_t m = 0; m < nn; m++)
				if (lit_at(t, j, nouns[m]) >= 0)
					return 1;
			if (k == gap || j >= t->n || t->cp[j] == 0x0A)
				break;
			j++;
		}
	}
	return 0;
}

/* ---------------------------------------------------------------- 意图规则表 */

static const char *INTENT_NAMES[] = {
	"set_theme_pink", "set_theme_dark", "set_theme_light", "show_apps",
	"switch_desktop", "switch_ai", "sandbox_view", "get_vm_status",
	"get_status"
};

static int rx_pink(const struct cptext *t)
{
	static const char *lits[] = { "变粉", "粉色", "粉色主题", "粉红",
				      "粉系", "pink" };

	return any_lit(t, lits, 6);
}

static int rx_dark(const struct cptext *t)
{
	static const char *lits[] = { "暗色", "深色", "夜间模式", "黑夜",
				      "变暗", "dark" };

	/* dark(\s*mode)?:组可选 → 任意 dark 即命中 */
	return any_lit(t, lits, 6);
}

static int rx_light(const struct cptext *t)
{
	static const char *lits[] = { "亮色", "浅色", "白天模式", "变亮",
				      "light" };

	return any_lit(t, lits, 5);
}

static int rx_show_apps(const struct cptext *t)
{
	{
		static const char *verbs[] = { "显示", "列出", "看看", "打开",
					       "罗列" };
		static const char *nouns[] = { "app", "应用", "软件", "程序" };

		if (pair_rule(t, verbs, 5, nouns, 4, 8))
			return 1;
	}
	{
		static const char *verbs[] = { "app", "应用", "软件" };
		static const char *nouns[] = { "清单", "列表", "抽屉", "网格" };

		if (pair_rule(t, verbs, 3, nouns, 4, 6))
			return 1;
	}
	{ /* show\s*apps? */
		for (size_t i = 0; i < t->n; i++) {
			long e = lit_at(t, i, "show");

			if (e < 0)
				continue;
			size_t j = (size_t)e;

			while (j < t->n && cp_is_space(t->cp[j]))
				j++;
			if (lit_at(t, j, "app") >= 0)
				return 1;
		}
	}
	return 0;
}

static int rx_switch_desktop(const struct cptext *t)
{
	static const uint32_t v1[] = { 0x5207, 0x56DE, 0x53BB, 0x8FDB,
				       0x6362 }; /* 切回去进换 */

	for (size_t i = 0; i < t->n; i++) {
		size_t e = 0;
		int hit = 0;

		for (size_t v = 0; v < 5; v++)
			if (t->cp[i] == v1[v]) {
				e = i + 1;
				hit = 1;
				break;
			}
		if (!hit && lit_at(t, i, "进入") >= 0) {
			e = i + 2;
			hit = 1;
		}
		if (!hit)
			continue;
		for (int k = 0; k <= 4; k++) {
			size_t j = e + (size_t)k;

			if (j > t->n)
				break;
			/* (传统)?桌面 */
			if (lit_at(t, j, "传统") >= 0 &&
			    lit_at(t, j + 2, "桌面") >= 0)
				return 1;
			if (lit_at(t, j, "桌面") >= 0)
				return 1;
			if (k == 4 || j >= t->n || t->cp[j] == 0x0A)
				break;
		}
	}
	/* 传统桌面|desktop(\s*mode)?|图标网格模式 */
	if (lit_find(t, 0, "传统桌面") >= 0)
		return 1;
	if (lit_find(t, 0, "desktop") >= 0)
		return 1;
	if (lit_find(t, 0, "图标网格模式") >= 0)
		return 1;
	return 0;
}

static int rx_switch_ai(const struct cptext *t)
{
	static const uint32_t v1[] = { 0x5207, 0x56DE, 0x8FD4 }; /* 切回返 */
	static const char *nouns[] = { "ai", "聊天", "对话" };

	for (size_t i = 0; i < t->n; i++) {
		size_t e = 0;
		int hit = 0;

		for (size_t v = 0; v < 3; v++)
			if (t->cp[i] == v1[v]) {
				e = i + 1;
				hit = 1;
				break;
			}
		if (!hit && lit_at(t, i, "回都") >= 0) {
			e = i + 2;
			hit = 1;
		}
		if (!hit)
			continue;
		for (int k = 0; k <= 4; k++) {
			size_t j = e + (size_t)k;

			if (j > t->n)
				break;
			for (size_t m = 0; m < 3; m++)
				if (lit_at(t, j, nouns[m]) >= 0)
					return 1;
			if (k == 4 || j >= t->n || t->cp[j] == 0x0A)
				break;
		}
	}
	/* ai\s*(模式|界面)|回到对话 */
	for (size_t i = 0; i < t->n; i++) {
		long e = lit_at(t, i, "ai");

		if (e < 0)
			continue;
		size_t j = (size_t)e;

		while (j < t->n && cp_is_space(t->cp[j]))
			j++;
		if (lit_at(t, j, "模式") >= 0 || lit_at(t, j, "界面") >= 0)
			return 1;
	}
	return lit_find(t, 0, "回到对话") >= 0;
}

static int rx_sandbox(const struct cptext *t)
{
	static const char *lits[] = { "隔离区", "沙箱", "sandbox" };

	return any_lit(t, lits, 3);
}

static int rx_vm(const struct cptext *t)
{
	/* (?<![A-Za-z0-9_])vm(?![A-Za-z0-9_])|真机|虚拟机|aikernel\s*api|生产机 */
	for (size_t i = 0; i < t->n; i++) {
		long e = lit_at(t, i, "vm");

		if (e < 0)
			continue;
		if (i > 0 && cp_is_word(t->cp[i - 1]))
			continue;
		if ((size_t)e < t->n && cp_is_word(t->cp[(size_t)e]))
			continue;
		return 1;
	}
	{
		static const char *lits[] = { "真机", "虚拟机", "生产机" };

		if (any_lit(t, lits, 3))
			return 1;
	}
	for (size_t i = 0; i < t->n; i++) {
		long e = lit_at(t, i, "aikernel");

		if (e < 0)
			continue;
		size_t j = (size_t)e;

		while (j < t->n && cp_is_space(t->cp[j]))
			j++;
		if (lit_at(t, j, "api") >= 0)
			return 1;
	}
	return 0;
}

static int rx_status(const struct cptext *t)
{
	/* (系统)?状态|负载|内存|占用|性能|健康|status|monitor */
	static const char *lits[] = { "状态", "负载", "内存", "占用", "性能",
				      "健康", "status", "monitor" };

	return any_lit(t, lits, 8);
}

static int (*const INTENT_RULES[])(const struct cptext *) = {
	rx_pink,   rx_dark,	  rx_light,	    rx_show_apps,
	rx_switch_desktop, rx_switch_ai, rx_sandbox, rx_vm,
	rx_status
};

/* ACTION_ALIASES(server.py:249-259,键序照抄) */
static aik_json *alias_action(const char *name)
{
	aik_json *a = dt_new_obj();

	if (strcmp(name, "set_theme_pink") == 0) {
		dt_put_str(a, "action", "set_theme");
		dt_put_str(a, "theme", "pink");
	} else if (strcmp(name, "set_theme_dark") == 0) {
		dt_put_str(a, "action", "set_theme");
		dt_put_str(a, "theme", "dark");
	} else if (strcmp(name, "set_theme_light") == 0) {
		dt_put_str(a, "action", "set_theme");
		dt_put_str(a, "theme", "light");
	} else if (strcmp(name, "show_apps") == 0) {
		dt_put_str(a, "action", "show_apps");
	} else if (strcmp(name, "switch_desktop") == 0) {
		dt_put_str(a, "action", "switch_mode");
		dt_put_str(a, "mode", "desktop");
	} else if (strcmp(name, "switch_ai") == 0) {
		dt_put_str(a, "action", "switch_mode");
		dt_put_str(a, "mode", "ai");
	} else if (strcmp(name, "get_vm_status") == 0) {
		dt_put_str(a, "action", "get_vm_status");
	} else if (strcmp(name, "sandbox_view") == 0) {
		dt_put_str(a, "action", "sandbox_view");
	} else if (strcmp(name, "get_status") == 0) {
		dt_put_str(a, "action", "get_status");
	} else {
		aik_json_free(a);
		return NULL;
	}
	return a;
}

aik_json *dt_parse_intents(const char *text)
{
	struct cptext t;
	aik_json *actions = dt_new_arr();

	if (!actions)
		return NULL;
	if (cptext_init(&t, text) != 0) {
		aik_json_free(actions);
		return NULL;
	}
	for (size_t r = 0; r < 9; r++) {
		if (aik_json_count(actions) >= 4)
			break; /* [:4] */
		if (INTENT_RULES[r](&t)) {
			aik_json *a = alias_action(INTENT_NAMES[r]);

			if (a)
				aik_json_arr_push(actions, a);
		}
	}
	cptext_free(&t);
	return actions;
}

/* ---------------------------------------------------------------- match_open_app */

static int open_stop_hit(const struct cptext *t)
{
	static const char *full[] = { "应用", "app", "软件", "程序", "抽屉",
				      "主题", "桌面", "系统", "模式", "状态",
				      "图标", "窗口" };
	static const char *sufs[] = { "抽屉", "主题", "桌面", "模式", "状态",
				      "图标", "窗口" };

	/* ^(...)$:整串等于某个泛指词 */
	for (size_t i = 0; i < 12; i++)
		if (lit_at(t, 0, full[i]) == (long)t->n && t->n > 0)
			return 1;
	/* 词$ :以泛指词结尾 */
	for (size_t i = 0; i < 7; i++) {
		size_t ln = lit_cplen(sufs[i]);

		if (t->n >= ln && lit_at(t, t->n - ln, sufs[i]) == (long)t->n)
			return 1;
	}
	return 0;
}

/* `\s*[。.!]?\s*$`(回溯存在性:全空白到尾,或 ws*+单个标点+全空白) */
static int tail_punct_end(const struct cptext *t, size_t p)
{
	size_t q = p;

	while (q < t->n && cp_is_space(t->cp[q]))
		q++;
	if (q == t->n)
		return 1;
	if (t->cp[q] == 0x3002 /* 。 */ || t->cp[q] == '.' || t->cp[q] == '!') {
		size_t q2 = q + 1;

		while (q2 < t->n && cp_is_space(t->cp[q2]))
			q2++;
		if (q2 == t->n)
			return 1;
	}
	return 0;
}

static const char *const OPEN_VERBS[] = { "打开", "启动", "运行", "帮我开",
					  "launch", "open" };

static char *app_field_str(const aik_json *app, const char *key)
{
	const aik_json *v = dt_get(app, key);

	if (v && aik_json_typeof(v) == AIK_JSON_STR)
		return strdup(aik_json_str(v));
	return NULL;
}

static aik_json *make_open_action(const aik_json *app)
{
	char *id = app_field_str(app, "id");
	char *name = app_field_str(app, "name");
	char *name_zh = app_field_str(app, "name_zh");
	const char *display = (name_zh && *name_zh) ? name_zh
			     : (name && *name)  ? name
						: "";
	aik_json *a;

	if (!id || !*id || !*display) {
		free(id);
		free(name);
		free(name_zh);
		return NULL; /* 缺 id/name → 参考侧 KeyError;向量不覆盖 */
	}
	a = dt_new_obj();
	dt_put_str(a, "action", "open_app");
	dt_put_str(a, "app", id);
	dt_put_str(a, "name", display);
	free(id);
	free(name);
	free(name_zh);
	return a;
}

aik_json *dt_match_open_app(const char *text, const aik_json *apps)
{
	struct cptext t;
	char *target = NULL;

	if (!apps || aik_json_typeof(apps) != AIK_JSON_ARR)
		return NULL;
	if (cptext_init(&t, text) != 0)
		return NULL;

	/* re.search(r"(?:打开|启动|运行|帮我开|launch|open)\s*(.{1,24}?)\s*
	 * [。.!]?\s*$", text, re.I):最左动词位优先,`\s*` 从最大回给,
	 * 组惰性扩张(≥1 码点,不跨 \n) */
	for (size_t i = 0; i < t.n && !target; i++) {
		long e = -1;

		for (size_t v = 0; v < 6; v++) {
			e = lit_at(&t, i, OPEN_VERBS[v]);
			if (e >= 0)
				break;
		}
		if (e < 0)
			continue;
		size_t maxw = 0;

		while ((size_t)e + maxw < t.n && cp_is_space(t.cp[e + maxw]))
			maxw++;
		for (size_t w = maxw + 1; w-- > 0 && !target;) {
			size_t s = (size_t)e + w;

			for (size_t g = 1; g <= 24 && !target; g++) {
				if (s + g > t.n)
					break;
				if (t.cp[s + g - 1] == 0x0A)
					break; /* `.` 不跨 \n */
				if (!tail_punct_end(&t, s + g))
					continue;
				target = strndup(text + t.off[s],
						 t.off[s + g] - t.off[s]);
				break;
			}
		}
	}
	if (!target) {
		cptext_free(&t);
		return NULL;
	}
	{ /* target.strip() */
		char *stripped = dt_strip(target);

		free(target);
		if (!stripped) {
			cptext_free(&t);
			return NULL;
		}
		target = stripped;
	}
	if (!*target) { /* not target → None */
		free(target);
		cptext_free(&t);
		return NULL;
	}
	{ /* _OPEN_STOP.search(target) */
		struct cptext tc;
		int stop;

		if (cptext_init(&tc, target) != 0) {
			free(target);
			cptext_free(&t);
			return NULL;
		}
		stop = open_stop_hit(&tc);
		cptext_free(&tc);
		if (stop) {
			free(target);
			cptext_free(&t);
			return NULL;
		}
	}
	{ /* re.sub(r"^系统|^全部|^一下|^个","",target).lower() */
		static const char *prefs[] = { "系统", "全部", "一下", "个" };
		char *t2 = target;

		for (size_t i = 0; i < 4; i++) {
			size_t ln = strlen(prefs[i]);

			if (strncmp(t2, prefs[i], ln) == 0) {
				char *moved = strdup(t2 + ln);

				free(t2);
				if (!moved) {
					cptext_free(&t);
					return NULL;
				}
				t2 = moved;
				break;
			}
		}
		target = dt_utf8_lower(t2);
		free(t2);
		if (!target) {
			cptext_free(&t);
			return NULL;
		}
	}

	{
		aik_json *out = NULL;
		size_t napps = aik_json_count(apps);
		/* 1) 别名表(口语词 → id 子串;server.py:283-303) */
		static const struct {
			const char *kw;
			const char *subs[4];
		} aliases[] = {
			{ "设置", { "control-center", "settings", NULL, NULL } },
			{ "浏览器", { "firefox", "chrom", "browser", NULL } },
			{ "上网", { "firefox", "chrom", "browser", NULL } },
			{ "文件管理", { "nautilus", "files", "pcmanfm", NULL } },
			{ "文件", { "nautilus", "files", "pcmanfm", NULL } },
			{ "终端", { "terminal", "console", "xterm", NULL } },
			{ "命令行", { "terminal", "console", "xterm", NULL } },
			{ "计算器", { "calculator", NULL, NULL, NULL } },
			{ "文本编辑",
			  { "gedit", "texteditor", "text-editor", NULL } },
			{ "编辑器",
			  { "gedit", "texteditor", "text-editor", NULL } },
			{ "记事本", { "gedit", "texteditor", NULL, NULL } },
			{ "日历", { "calendar", NULL, NULL, NULL } },
			{ "邮件", { "thunderbird", "evolution", "mail", NULL } },
			{ "音乐", { "rhythmbox", "music", NULL, NULL } },
			{ "视频", { "totem", "video", NULL, NULL } },
			{ "截图", { "screenshot", NULL, NULL, NULL } },
			{ "系统监视", { "monitor", "usage", NULL, NULL } },
			{ "磁盘", { "disk", NULL, NULL, NULL } },
			{ "软件", { "software", "snap-store", NULL, NULL } },
		};

		for (size_t a = 0; a < 19 && !out; a++) {
			if (!strstr(target, aliases[a].kw))
				continue;
			for (size_t s = 0; s < 4 && aliases[a].subs[s] && !out;
			     s++) {
				for (size_t k = 0; k < napps; k++) {
					const aik_json *app =
						aik_json_at(apps, k);
					char *id = app_field_str(app, "id");

					if (id) {
						char *id_low =
							dt_utf8_lower(id);

						if (id_low && strstr(id_low,
								     aliases[a]
									     .subs
										     [s]))
							out = make_open_action(
								app);
						free(id_low);
					}
					free(id);
					if (out)
						break;
				}
			}
		}
		/* 2) 精确名(name/name_en/id/name_zh) */
		for (size_t k = 0; k < napps && !out; k++) {
			static const char *keys[4] = { "name", "name_en",
						       "id", "name_zh" };
			const aik_json *app = aik_json_at(apps, k);
			char *fields[4];

			for (int f = 0; f < 4; f++)
				fields[f] = app_field_str(app, keys[f]);
			for (int f = 0; f < 4 && !out; f++) {
				if (!fields[f] || (f == 3 && !*fields[3]))
					continue;
				{
					char *low = dt_utf8_lower(fields[f]);

					if (low && strcmp(low, target) == 0)
						out = make_open_action(app);
					free(low);
				}
			}
			for (int f = 0; f < 4; f++)
				free(fields[f]);
		}
		/* 3) 子串(len(t)>=2) */
		if (!out && dt_utf8_cplen(target, strlen(target)) >= 2) {
			for (size_t k = 0; k < napps && !out; k++) {
				static const char *keys[4] = {
					"name", "name_en", "id", "name_zh"
				};
				const aik_json *app = aik_json_at(apps, k);
				char *fields[4];

				for (int f = 0; f < 4; f++)
					fields[f] = app_field_str(app,
								  keys[f]);
				for (int f = 0; f < 4 && !out; f++) {
					if (!fields[f] ||
					    (f == 3 && !*fields[3]))
						continue;
					{
						char *low = dt_utf8_lower(
							fields[f]);

						if (low && strstr(low, target))
							out = make_open_action(
								app);
						free(low);
					}
				}
				for (int f = 0; f < 4; f++)
					free(fields[f]);
			}
		}
		free(target);
		cptext_free(&t);
		return out;
	}
}

/* ---------------------------------------------------------------- canon 签名 */

static const char SIG_HEXD[] = "0123456789abcdef";

/* ensure_ascii=False 转义(与 dtjson put_str 同规则;单射,判等用) */
static void sig_put_str(struct dt_sbuf *b, const char *s)
{
	size_t n = strlen(s);

	dt_sb_putc(b, '"');
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '"':
			dt_sb_puts(b, "\\\"", 2);
			break;
		case '\\':
			dt_sb_puts(b, "\\\\", 2);
			break;
		case '\b':
			dt_sb_puts(b, "\\b", 2);
			break;
		case '\f':
			dt_sb_puts(b, "\\f", 2);
			break;
		case '\n':
			dt_sb_puts(b, "\\n", 2);
			break;
		case '\r':
			dt_sb_puts(b, "\\r", 2);
			break;
		case '\t':
			dt_sb_puts(b, "\\t", 2);
			break;
		default:
			if (c < 0x20) {
				char esc[6];

				esc[0] = '\\';
				esc[1] = 'u';
				esc[2] = '0';
				esc[3] = '0';
				esc[4] = SIG_HEXD[c >> 4];
				esc[5] = SIG_HEXD[c & 0x0F];
				dt_sb_puts(b, esc, 6);
			} else {
				dt_sb_putc(b, (char)c);
			}
			break;
		}
	}
	dt_sb_putc(b, '"');
}

static int keycmp(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void sig_value(struct dt_sbuf *b, const aik_json *v)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		dt_sb_putstr(b, "null");
		break;
	case AIK_JSON_BOOL:
		dt_sb_putstr(b, aik_json_bool(v) ? "true" : "false");
		break;
	case AIK_JSON_INT: {
		char tmp[32];

		snprintf(tmp, sizeof(tmp), "%lld", aik_json_int(v));
		dt_sb_putstr(b, tmp);
		break;
	}
	case AIK_JSON_NUM: {
		char tmp[40];

		aik_json_dtoa(aik_json_num(v), tmp, sizeof(tmp));
		dt_sb_putstr(b, tmp);
		break;
	}
	case AIK_JSON_STR:
		sig_put_str(b, aik_json_str(v));
		break;
	case AIK_JSON_ARR: {
		size_t n = aik_json_count(v);

		dt_sb_putc(b, '[');
		for (size_t i = 0; i < n; i++) {
			if (i)
				dt_sb_puts(b, ", ", 2);
			sig_value(b, aik_json_at(v, i));
		}
		dt_sb_putc(b, ']');
		break;
	}
	case AIK_JSON_OBJ: {
		size_t n = aik_json_count(v);
		const char **keys = malloc((n ? n : 1) * sizeof(char *));

		if (!keys) {
			b->bad = 1;
			return;
		}
		for (size_t i = 0; i < n; i++)
			keys[i] = aik_json_key_at(v, i);
		qsort(keys, n, sizeof(char *), keycmp);
		dt_sb_putc(b, '{');
		for (size_t i = 0; i < n; i++) {
			if (i)
				dt_sb_puts(b, ", ", 2);
			sig_put_str(b, keys[i]);
			dt_sb_puts(b, ": ", 2);
			/* 值按键取(键已排序,原下标不再对位) */
			sig_value(b, dt_get(v, keys[i]));
		}
		dt_sb_putc(b, '}');
		free(keys);
		break;
	}
	}
}

char *dt_canon_sig(const aik_json *v)
{
	struct dt_sbuf b;

	dt_sb_init(&b);
	sig_value(&b, v);
	return dt_sb_finish(&b);
}

/* ---------------------------------------------------------------- [[...]] 抽取 */

int dt_chat_extract_tag(char *reply, size_t *plen, aik_json *actions)
{
	size_t len = *plen;

	for (size_t i = 0; i + 1 < len; i++) {
		if (reply[i] != '[' || reply[i + 1] != '[')
			continue;
		size_t j = i + 2;

		/* 惰性 (.+?):group ≥1 码点,首个其后紧跟 ]] 处结束 */
		for (size_t k = j + 1; k + 1 < len; k++) {
			if (reply[k] != ']' || reply[k + 1] != ']')
				continue;
			/* 候选 = [j, k);json.loads 严格(trailing 拒绝) */
			aik_json *inner = dt_parse(reply + j, k - j);

			if (inner) {
				size_t cnt = 0;

				if (aik_json_typeof(inner) == AIK_JSON_ARR) {
					cnt = aik_json_count(inner);
				} else if (aik_json_typeof(inner) ==
					   AIK_JSON_OBJ) {
					cnt = 1; /* dict → 单元素列表 */
				}
				for (size_t c = 0; c < cnt; c++) {
					/* dict 单元素即 inner 本体;数组逐个 */
					const aik_json *a =
						aik_json_typeof(inner) ==
								AIK_JSON_OBJ
							? inner
							: aik_json_at(inner,
								      c);

					if (aik_json_typeof(a) != AIK_JSON_OBJ)
						continue;
					if (!dt_get(a, "action"))
						continue;
					{
						char *sig = dt_canon_sig(a);
						int dup = 0;

						for (size_t x = 0;
						     x < aik_json_count(
								actions) &&
						     !dup;
						     x++) {
							char *xs =
								dt_canon_sig(
									aik_json_at(
										actions,
										x));

							if (xs && sig &&
							    strcmp(xs, sig) ==
								    0)
								dup = 1;
							free(xs);
						}
						free(sig);
						if (!dup)
							dt_arr_push_copy(
								actions, a);
					}
				}
				aik_json_free(inner);
			}
			/* 标签段剔除:[i, k+2) */
			memmove(reply + i, reply + k + 2, len - (k + 2));
			*plen = len - (k + 2 - i);
			return 1;
		}
	}
	return 0;
}

/* ---------------------------------------------------------------- 读侧(T6b 移入) */

static char *dup_range(const char *s, size_t n)
{
	char *p = malloc(n + 1);

	if (!p)
		return NULL;
	memcpy(p, s, n);
	p[n] = '\0';
	return p;
}

double dt_py_round1(double x)
{
	return (double)(long long)nearbyint(x * 10.0) / 10.0;
}

char *dt_utf8_lower(const char *s)
{
	char *out = strdup(s);

	if (!out)
		return NULL;
	for (char *p = out; *p; p++)
		if (*p >= 'A' && *p <= 'Z')
			*p = (char)(*p - 'A' + 'a');
	return out;
}

aik_json *dt_read_proc_stats(void)
{
	aik_json *st = dt_new_obj();
	double load1 = 0.0, load5 = 0.0;
	long long cores = 1;
	long long mem_total = 0;
	double mem_used_pct = 0.0;
	double uptime_h = 0.0;
	struct utsname un;

	if (dt_is_file("/proc/loadavg")) {
		size_t n = 0;
		char *t = dt_read_file("/proc/loadavg", &n);

		if (t) {
			char *sp = strchr(t, ' ');

			if (sp) {
				*sp = '\0';
				load1 = strtod(t, NULL);
				{
					char *sp2 = strchr(sp + 1, ' ');

					if (sp2) {
						*sp2 = '\0';
						load5 = strtod(sp + 1, NULL);
					}
				}
			}
			free(t);
		}
		{
			long ncpu = sysconf(_SC_NPROCESSORS_ONLN);

			cores = ncpu > 0 ? ncpu : 1;
		}
	} else {
		load1 = load5 = 0.0;
		cores = 1;
	}
	if (dt_is_file("/proc/meminfo")) {
		size_t n = 0;
		char *t = dt_read_file("/proc/meminfo", &n);
		long long total = -1, avail = -1;

		if (t) {
			char *save = NULL;

			for (char *line = strtok_r(t, "\n", &save); line;
			     line = strtok_r(NULL, "\n", &save)) {
				char *colon = strchr(line, ':');

				if (!colon)
					continue;
				*colon = '\0';
				{
					long long v = strtoll(colon + 1, NULL,
							      10);

					if (strcmp(line, "MemTotal") == 0)
						total = v;
					else if (strcmp(line, "MemAvailable") ==
						 0)
						avail = v;
				}
			}
			free(t);
		}
		if (total > 0 && avail >= 0) {
			mem_total = total / 1024;
			mem_used_pct = dt_py_round1(
				100.0 * (double)(total - avail) /
				(double)total);
		}
	}
	if (dt_is_file("/proc/uptime")) {
		size_t n = 0;
		char *t = dt_read_file("/proc/uptime", &n);

		if (t) {
			uptime_h = dt_py_round1(strtod(t, NULL) / 3600.0);
			free(t);
		}
	}
	dt_put_num(st, "load1", load1);
	dt_put_num(st, "load5", load5);
	dt_put_int(st, "cores", cores);
	dt_put_int(st, "mem_total_mb", mem_total);
	dt_put_num(st, "mem_used_pct", mem_used_pct);
	dt_put_num(st, "uptime_h", uptime_h);
	uname(&un);
	dt_put_str(st, "kernel", un.release);
	dt_put_str(st, "arch", un.machine);
	return st;
}

void dt_read_model_conf(aik_json *conf)
{
	size_t n = 0;
	char *txt;

	dt_put_null(conf, "base_url");
	dt_put_null(conf, "api_key");
	dt_put_null(conf, "model_name");
	txt = dt_read_file(g_cfg.model_toml, &n);
	if (!txt) {
		dt_log("model.toml 读取失败: FileNotFoundError");
		return;
	}
	{
		/* re.search(r"\[models\.cloud\]([^\[]*)", txt, re.S) */
		const char *seg = txt;
		const char *hit = strstr(txt, "[models.cloud]");
		const char *seg_end;

		if (hit) {
			seg = hit + strlen("[models.cloud]");
			seg_end = strchr(seg, '[');
		} else {
			seg_end = NULL;
		}
		if (!seg_end)
			seg_end = txt + strlen(txt);
		{
			static const char *keys[3] = { "base_url", "api_key",
						       "model_name" };

			for (int k = 0; k < 3; k++) {
				size_t klen = strlen(keys[k]);
				const char *lp = seg;

				while (lp < seg_end) {
					const char *le = memchr(
						lp, '\n',
						(size_t)(seg_end - lp));
					size_t ln = le
							    ? (size_t)(le -
								       lp)
							    : (size_t)(seg_end -
								       lp);
					size_t iv = 0, jv;

					while (iv < ln && (lp[iv] == ' ' ||
							   lp[iv] == '\t'))
						iv++;
					if (iv + klen <= ln &&
					    strncmp(lp + iv, keys[k], klen) ==
						    0) {
						jv = iv + klen;
						while (jv < ln &&
						       (lp[jv] == ' ' ||
							lp[jv] == '\t'))
							jv++;
						if (jv < ln && lp[jv] == '=') {
							jv++;
							while (jv < ln &&
							       (lp[jv] ==
									' ' ||
								lp[jv] ==
									'\t'))
								jv++;
							if (jv < ln &&
							    (lp[jv] == '"' ||
							     lp[jv] == '\''))
								jv++;
							{
								size_t vend =
									jv;

								while (vend <
								       ln &&
								       lp[vend] !=
									       '"' &&
								       lp[vend] !=
									       '\'' &&
								       lp[vend] !=
										       '#')
									vend++;
								{
									char *val =
										dup_range(
											lp +
												jv,
											vend -
												jv);

									if (val) {
										char *stripped =
											dt_strip(
												val);

										aik_json_obj_set(
											conf,
											keys[k],
											dt_new_str(
												stripped));
										free(stripped);
										free(val);
									}
									break; /* ^... 每键首个匹配 */
								}
							}
						}
					}
					lp = le ? le + 1 : seg_end;
				}
			}
		}
	}
	free(txt);
}

/* ---------------------------------------------------------------- LLM */

char *dt_llm_endpoint(const char *base_url)
{
	size_t n = strlen(base_url);
	char *out;

	while (n > 0 && base_url[n - 1] == '/')
		n--;
	out = malloc(n + 32);
	if (!out)
		return NULL;
	if (n >= 3 && strncmp(base_url + n - 3, "/v1", 3) == 0)
		snprintf(out, n + 32, "%.*s/chat/completions", (int)n,
			 base_url);
	else
		snprintf(out, n + 32, "%.*s/v1/chat/completions", (int)n,
			 base_url);
	return out;
}

/* ensure_ascii=True 转义(python json.dumps 默认;\uXXXX 小写、代理对) */
static void sb_put_str_ascii(struct dt_sbuf *b, const char *s)
{
	size_t n = strlen(s);

	dt_sb_putc(b, '"');
	for (size_t i = 0; i < n;) {
		unsigned char c = (unsigned char)s[i];
		uint32_t v;
		size_t adv;

		if (c < 0x80) {
			v = c;
			adv = 1;
		} else if ((c & 0xE0) == 0xC0 && i + 1 < n &&
			   ((unsigned char)s[i + 1] & 0xC0) == 0x80) {
			v = ((uint32_t)(c & 0x1F) << 6) |
			    (uint32_t)((unsigned char)s[i + 1] & 0x3F);
			adv = 2;
		} else if ((c & 0xF0) == 0xE0 && i + 2 < n &&
			   ((unsigned char)s[i + 1] & 0xC0) == 0x80 &&
			   ((unsigned char)s[i + 2] & 0xC0) == 0x80) {
			v = ((uint32_t)(c & 0x0F) << 12) |
			    ((uint32_t)((unsigned char)s[i + 1] & 0x3F) << 6) |
			    (uint32_t)((unsigned char)s[i + 2] & 0x3F);
			adv = 3;
		} else if ((c & 0xF8) == 0xF0 && i + 3 < n &&
			   ((unsigned char)s[i + 1] & 0xC0) == 0x80 &&
			   ((unsigned char)s[i + 2] & 0xC0) == 0x80 &&
			   ((unsigned char)s[i + 3] & 0xC0) == 0x80) {
			v = ((uint32_t)(c & 0x07) << 18) |
			    ((uint32_t)((unsigned char)s[i + 1] & 0x3F)
			     << 12) |
			    ((uint32_t)((unsigned char)s[i + 2] & 0x3F) << 6) |
			    (uint32_t)((unsigned char)s[i + 3] & 0x3F);
			adv = 4;
		} else {
			v = 0xFFFD;
			adv = 1;
		}
		i += adv;
		if (v == '"') {
			dt_sb_puts(b, "\\\"", 2);
			continue;
		}
		if (v == '\\') {
			dt_sb_puts(b, "\\\\", 2);
			continue;
		}
		if (v == '\b' || v == '\f' || v == '\n' || v == '\r' ||
		    v == '\t') {
			char e[2] = { '\\', '?' };

			e[1] = (v == '\b') ? 'b'
			       : (v == '\f') ? 'f'
			       : (v == '\n') ? 'n'
			       : (v == '\r') ? 'r'
					     : 't';
			dt_sb_puts(b, e, 2);
			continue;
		}
		if (v < 0x20) {
			char e[6];

			e[0] = '\\';
			e[1] = 'u';
			e[2] = '0';
			e[3] = '0';
			e[4] = SIG_HEXD[(v >> 4) & 0xF];
			e[5] = SIG_HEXD[v & 0xF];
			dt_sb_puts(b, e, 6);
			continue;
		}
		if (v < 0x80) {
			dt_sb_putc(b, (char)v);
			continue;
		}
		{
			uint32_t u = v > 0x10FFFF ? 0xFFFD : v;

			if (u >= 0x10000) {
				uint32_t pair[2];
				char e[6];

				pair[0] = 0xD800 + ((u - 0x10000) >> 10);
				pair[1] = 0xDC00 + ((u - 0x10000) & 0x3FF);
				for (int s = 0; s < 2; s++) {
					uint32_t x = pair[s];

					e[0] = '\\';
					e[1] = 'u';
					e[2] = SIG_HEXD[(x >> 12) & 0xF];
					e[3] = SIG_HEXD[(x >> 8) & 0xF];
					e[4] = SIG_HEXD[(x >> 4) & 0xF];
					e[5] = SIG_HEXD[x & 0xF];
					dt_sb_puts(b, e, 6);
				}
			} else {
				char e[6];

				e[0] = '\\';
				e[1] = 'u';
				e[2] = SIG_HEXD[(u >> 12) & 0xF];
				e[3] = SIG_HEXD[(u >> 8) & 0xF];
				e[4] = SIG_HEXD[(u >> 4) & 0xF];
				e[5] = SIG_HEXD[u & 0xF];
				dt_sb_puts(b, e, 6);
			}
		}
	}
	dt_sb_putc(b, '"');
}

char *dt_llm_body_build(const char *model, const aik_json *messages)
{
	struct dt_sbuf b;

	dt_sb_init(&b);
	dt_sb_putstr(&b, "{\"model\": ");
	sb_put_str_ascii(&b, model ? model : "");
	dt_sb_putstr(&b, ", \"messages\": [");
	if (messages && aik_json_typeof(messages) == AIK_JSON_ARR) {
		size_t n = aik_json_count(messages);

		for (size_t i = 0; i < n; i++) {
			const aik_json *m = aik_json_at(messages, i);
			const aik_json *role = dt_get(m, "role");
			const aik_json *content = dt_get(m, "content");

			if (i)
				dt_sb_putstr(&b, ", ");
			dt_sb_putstr(&b, "{\"role\": ");
			sb_put_str_ascii(&b,
					 role && aik_json_typeof(role) ==
							 AIK_JSON_STR
						 ? aik_json_str(role)
						 : "");
			dt_sb_putstr(&b, ", \"content\": ");
			sb_put_str_ascii(&b,
					 content &&
						 aik_json_typeof(content) ==
							 AIK_JSON_STR
						 ? aik_json_str(content)
						 : "");
			dt_sb_putc(&b, '}');
		}
	}
	dt_sb_putstr(&b,
		     "], \"temperature\": 0.6, \"max_tokens\": 500, "
		     "\"stream\": false}");
	return dt_sb_finish(&b);
}

/* https_post_stream 串行化(共享 mbedTLS ctr_drbg 非线程安全;LLM 出网
 * 互斥,响应内容不受影响) */
static pthread_mutex_t g_llm_http_lock = PTHREAD_MUTEX_INITIALIZER;

struct llm_acc {
	struct dt_sbuf b;
};

static void llm_on_data(void *ud, const char *data, size_t len)
{
	struct llm_acc *a = ud;

	dt_sb_puts(&a->b, data, len);
}

static const char *llm_exc_name(int rc, int status)
{
	if (rc == 0 && status >= 300)
		return "HTTPError"; /* urllib urlopen 非 2xx */
	return "URLError";     /* 连接/读失败等价类 */
}

aik_json *dt_call_llm(const aik_json *messages)
{
	aik_json *conf = dt_new_obj();
	aik_json *result = NULL;
	char *key = NULL;
	char *base_url = NULL;
	char *model_name = NULL;

	if (!conf)
		return NULL;
	dt_read_model_conf(conf);
	{
		const aik_json *v = dt_get(conf, "api_key");

		if (v && aik_json_typeof(v) == AIK_JSON_STR)
			key = strdup(aik_json_str(v));
	}
	if (!key || !*key) {
		dt_log("无 api_key,跳过云端调用");
		goto out;
	}
	{
		const aik_json *v = dt_get(conf, "base_url");

		if (v && aik_json_typeof(v) == AIK_JSON_STR)
			base_url = strdup(aik_json_str(v));
		v = dt_get(conf, "model_name");
		if (v && aik_json_typeof(v) == AIK_JSON_STR)
			model_name = strdup(aik_json_str(v));
	}
	{
		char *urls[2];
		char *models[2];
		const char *tags[2] = { "forwarder", "direct" };
		int natt = 0;

		if (base_url && *base_url) {
			urls[natt] = dt_llm_endpoint(base_url);
			models[natt] = strdup((model_name && *model_name)
						      ? model_name
						      : "deepseek-chat");
			natt++;
		}
		urls[natt] = strdup(
			"https://api.deepseek.com/v1/chat/completions");
		models[natt] = strdup("deepseek-chat");
		natt++;

		for (int a = 0; a < natt && !result; a++) {
			char *body = dt_llm_body_build(models[a], messages);
			struct llm_acc acc;
			char *err = NULL;
			int status = 0;
			int rc;

			if (!body)
				continue;
			dt_sb_init(&acc.b);
			pthread_mutex_lock(&g_llm_http_lock);
			https_set_timeout(CHAT_LLM_TIMEOUT, CHAT_LLM_TIMEOUT);
			rc = https_post_stream(urls[a], key, body,
						llm_on_data, &acc, &status,
						&err);
			pthread_mutex_unlock(&g_llm_http_lock);
			free(body);
			if (rc == 0 && status >= 200 && status < 300 &&
			    acc.b.p) {
				aik_json *obj = dt_parse(acc.b.p, acc.b.n);
				const aik_json *ch =
					obj ? dt_get(obj, "choices") : NULL;
				const aik_json *m = NULL;

				if (ch &&
				    aik_json_typeof(ch) == AIK_JSON_ARR &&
				    aik_json_count(ch) > 0) {
					const aik_json *c0 =
						aik_json_at(ch, 0);

					m = dt_get(c0, "message");
				}
				{
					const aik_json *content =
						m ? dt_get(m, "content")
						  : NULL;

					if (content &&
					    aik_json_typeof(content) ==
						    AIK_JSON_STR) {
						result = dt_new_obj();
						dt_put_str(result, "text",
							   aik_json_str(
								   content));
						dt_put_str(result, "endpoint",
							   tags[a]);
						dt_put_str(result, "model",
							   models[a]);
					}
				}
				aik_json_free(obj);
			}
			if (result)
				dt_log("LLM OK via %s model=%s", tags[a],
				       models[a]);
			else
				dt_log("LLM %s(%s) 失败: %s", tags[a],
				       urls[a], llm_exc_name(rc, status));
			free(acc.b.p);
			free(err);
		}
		for (int a = 0; a < natt; a++) {
			free(urls[a]);
			free(models[a]);
		}
	}
out:
	free(key);
	free(base_url);
	free(model_name);
	aik_json_free(conf);
	return result;
}

/* ---------------------------------------------------------------- 上下文组装 */

static const char CHAT_SYS_PROMPT[] =
	"你是 AIKernel 操作系统的内置 AI 助手,运行在 AI-first 桌面 Demo 上。"
	"用户消息可能是语音式命令,你可以控制界面:显示应用抽屉、切换主题"
	"(暗色/亮色/粉色)、切换到传统桌面或回到 AI 对话、报告系统状态。\n"
	"规则:用简体中文回答,不超过 120 字;若用户意图是控制界面,在回复"
	"最前面输出一行 JSON 动作标签,格式:[[{\"action\":\"...\"}]],"
	"支持的 action: show_apps; set_theme(带 theme=dark|light|pink); "
	"switch_mode(带 mode=ai|desktop); get_status; open_app(带 "
	"app=<应用id> 与 name=<应用名>)。"
	"注意:创建隔离区等写操作在演示阶段不开放,若用户要求创建,"
	"如实说明只演示只读查看,不要声称已创建、不要编造界面按钮。"
	"示例:用户说\"变粉\"→ 回复 [[{\"action\":\"set_theme\","
	"\"theme\":\"pink\"}]] 已切换为粉色主题。普通闲聊则不加标签。";

const char *dt_chat_sys_prompt(void)
{
	return CHAT_SYS_PROMPT;
}

/* {"role": h["role"], "content": str(h.get("content",""))[:800]} */
static aik_json *ctx_entry(const aik_json *h)
{
	const aik_json *role = dt_get(h, "role");
	const aik_json *content = dt_get(h, "content");
	aik_json *e;
	char *s, *head;

	if (!role || aik_json_typeof(role) != AIK_JSON_STR)
		return NULL;
	e = dt_new_obj();
	if (!e)
		return NULL;
	s = content ? dt_pystr(content) : strdup("");
	if (!s) {
		aik_json_free(e);
		return NULL;
	}
	head = dt_utf8_head(s, 800);
	free(s);
	if (!head) {
		aik_json_free(e);
		return NULL;
	}
	dt_put_str(e, "role", aik_json_str(role));
	dt_put_str(e, "content", head);
	free(head);
	return e;
}

aik_json *dt_chat_context(const char *sid, const aik_json *history,
			  const char *message, int *crash)
{
	aik_json *msgs = NULL;
	aik_json *stored = dt_new_arr();
	aik_json *chat = dt_load_chat(sid);

	*crash = 0;
	if (!stored)
		return NULL;
	if (chat && aik_json_typeof(chat) == AIK_JSON_ARR) {
		size_t n = aik_json_count(chat);

		for (size_t i = 0; i < n; i++) {
			const aik_json *m = aik_json_at(chat, i);
			const aik_json *role, *content;

			if (aik_json_typeof(m) != AIK_JSON_OBJ) {
				*crash = 1; /* m.get AttributeError */
				goto fail;
			}
			role = dt_get(m, "role");
			content = dt_get(m, "content");
			if (role &&
			    aik_json_typeof(role) == AIK_JSON_STR &&
			    (strcmp(aik_json_str(role), "user") == 0 ||
			     strcmp(aik_json_str(role), "assistant") == 0) &&
			    content && dt_truthy(content))
				dt_arr_push_copy(stored, m);
		}
	}
	aik_json_free(chat);
	chat = NULL;
	{ /* [-20:] */
		size_t n = aik_json_count(stored);

		if (n > 20) {
			aik_json *kept = dt_new_arr();

			if (!kept)
				goto fail;
			for (size_t i = n - 20; i < n; i++)
				dt_arr_push_copy(kept, aik_json_at(stored, i));
			aik_json_free(stored);
			stored = kept;
		}
	}
	msgs = dt_new_arr();
	if (!msgs)
		goto fail;
	{
		aik_json *sys = dt_new_obj();

		if (!sys)
			goto fail;
		dt_put_str(sys, "role", "system");
		dt_put_str(sys, "content", CHAT_SYS_PROMPT);
		aik_json_arr_push(msgs, sys);
	}
	if (aik_json_count(stored) > 0) {
		/* 服务端持久历史优先 */
		for (size_t i = 0; i < aik_json_count(stored); i++) {
			aik_json *e = ctx_entry(aik_json_at(stored, i));

			if (!e)
				goto fail;
			aik_json_arr_push(msgs, e);
		}
	} else if (history && dt_truthy(history)) {
		/* 客户端 history 末 6 条兜底 */
		aik_json_type ht = aik_json_typeof(history);

		if (ht != AIK_JSON_ARR && ht != AIK_JSON_STR) {
			*crash = 1; /* history[-6:] TypeError */
			goto fail;
		}
		if (ht == AIK_JSON_ARR) {
			size_t n = aik_json_count(history);
			size_t start = n > 6 ? n - 6 : 0;

			for (size_t i = start; i < n; i++) {
				const aik_json *h = aik_json_at(history, i);
				const aik_json *role;

				if (aik_json_typeof(h) != AIK_JSON_OBJ)
					continue;
				role = dt_get(h, "role");
				if (!role ||
				    aik_json_typeof(role) != AIK_JSON_STR)
					continue;
				if (strcmp(aik_json_str(role), "user") != 0 &&
				    strcmp(aik_json_str(role), "assistant") !=
					    0)
					continue;
				{
					aik_json *e = ctx_entry(h);

					if (!e)
						goto fail;
					aik_json_arr_push(msgs, e);
				}
			}
		}
	}
	{
		aik_json *u = dt_new_obj();

		if (!u)
			goto fail;
		dt_put_str(u, "role", "user");
		dt_put_str(u, "content", message);
		aik_json_arr_push(msgs, u);
	}
	aik_json_free(stored);
	return msgs;
fail:
	aik_json_free(stored);
	aik_json_free(chat);
	aik_json_free(msgs);
	return NULL;
}

/* ---------------------------------------------------------------- demo_reply */

static const char *stats_str(const aik_json *st, const char *k)
{
	const aik_json *v = dt_get(st, k);

	return (v && aik_json_typeof(v) == AIK_JSON_STR) ? aik_json_str(v) : "";
}

char *dt_demo_reply(const char *message, const aik_json *actions,
		    long long apps_count)
{
	aik_json *st = dt_read_proc_stats();
	struct dt_sbuf b;
	size_t nact = (actions &&
		       aik_json_typeof(actions) == AIK_JSON_ARR)
			      ? aik_json_count(actions)
			      : 0;

	(void)message;
	dt_sb_init(&b);
	for (size_t i = 0; i < nact; i++) {
		const aik_json *a = aik_json_at(actions, i);
		const aik_json *av = dt_get(a, "action");
		const char *act = (av && aik_json_typeof(av) == AIK_JSON_STR)
					  ? aik_json_str(av)
					  : NULL;
		size_t mark = b.n;

		if (!act)
			continue;
		if (b.n)
			dt_sb_putc(&b, ' ');
		if (strcmp(act, "show_apps") == 0) {
			dt_sb_printf(&b,
				     "已为你打开应用抽屉:检测到 %lld 款已安装应用,顶部框可搜索。",
				     apps_count);
		} else if (strcmp(act, "set_theme") == 0) {
			const aik_json *tv = dt_get(a, "theme");
			const char *th = (tv && aik_json_typeof(tv) ==
						   AIK_JSON_STR)
						 ? aik_json_str(tv)
						 : NULL;
			const char *zh = NULL;

			if (th) {
				if (strcmp(th, "pink") == 0)
					zh = "粉色";
				else if (strcmp(th, "dark") == 0)
					zh = "暗色";
				else if (strcmp(th, "light") == 0)
					zh = "亮色";
			}
			if (!zh) {
				b.n = mark; /* 参考侧 KeyError;向量不覆盖 */
				continue;
			}
			dt_sb_printf(&b,
				     "已把整套系统切换为%s主题,聊天区、任务栏、壁纸一并变色。",
				     zh);
		} else if (strcmp(act, "switch_mode") == 0) {
			const aik_json *mv = dt_get(a, "mode");
			const char *md = (mv && aik_json_typeof(mv) ==
						   AIK_JSON_STR)
						 ? aik_json_str(mv)
						 : NULL;

			if (!md) {
				b.n = mark;
				continue;
			}
			if (strcmp(md, "desktop") == 0)
				dt_sb_putstr(&b, "已切换到传统桌面模式,壁纸、"
						 "图标网格与任务栏就绪;点左下"
						 "角 AI 按钮随时回来。");
			else
				dt_sb_putstr(&b, "已回到 AI 对话界面,我在。");
		} else if (strcmp(act, "get_status") == 0) {
			dt_sb_printf(&b,
				     "这是实时读取的系统态势:\n```\n$ uname -r\n%s (%s)\n$ uptime\nload %.2f / %lld cores, up %.1fh\n$ free\nmem used %.1f%% of %lld MB\n```",
				     stats_str(st, "kernel"),
				     stats_str(st, "arch"),
				     aik_json_num(dt_get(st, "load1")),
				     aik_json_int(dt_get(st, "cores")),
				     aik_json_num(dt_get(st, "uptime_h")),
				     aik_json_num(dt_get(st, "mem_used_pct")),
				     aik_json_int(dt_get(st, "mem_total_mb")));
		} else if (strcmp(act, "get_vm_status") == 0) {
			if (g_cfg.vm_enabled)
				dt_sb_putstr(&b, "正在经 SSH 隧道读取生产 "
						 "VM(192.168.245.138)的 "
						 "AIKernel 实况……");
			else
				dt_sb_putstr(&b, "当前是 factory 本地桌面演示"
						 "(AIK_DESKTOP_VM=0),不连"
						 "接 138:8761;生产实况请用"
						 " aikernel-api/ai 工具。");
		} else if (strcmp(act, "sandbox_view") == 0) {
			if (g_cfg.vm_enabled)
				dt_sb_putstr(&b, "正在经 SSH 只读读取 VM "
						 "/sandbox/ 隔离区实况(等价 "
						 "sandbox_status 工具,R "
						 "级)……");
			else
				dt_sb_putstr(&b, "factory 本地桌面演示不连接"
						 "生产 VM,隔离区视图不可"
						 "用。");
		} else if (strcmp(act, "open_app") == 0) {
			const aik_json *nv = dt_get(a, "name");
			const aik_json *pv;

			if (nv) {
				char *s = dt_pystr(nv);

				dt_sb_printf(&b,
					     "已为你定位「%s」,在应用抽屉中高亮显示(demo 不真正拉起进程)。",
					     s ? s : "?");
				free(s);
			} else if ((pv = dt_get(a, "app")) != NULL) {
				char *s = dt_pystr(pv);

				dt_sb_printf(&b,
					     "已为你定位「%s」,在应用抽屉中高亮显示(demo 不真正拉起进程)。",
					     s ? s : "?");
				free(s);
			} else {
				dt_sb_printf(&b,
					     "已为你定位「%s」,在应用抽屉中高亮显示(demo 不真正拉起进程)。",
					     "?");
			}
		} else {
			b.n = mark; /* 未知 action 无分句 */
		}
	}
	aik_json_free(st);
	if (!b.n)
		dt_sb_putstr(&b, "我在 AIKernel 演示应答模式(当前云端模型不"
				 "可达,但界面控制不受影响)。试试对我说:显"
				 "示我装的 app / 把系统变粉 / 切到桌面 / 系"
				 "统状态怎么样?");
	return dt_sb_finish(&b);
}

/* ---------------------------------------------------------------- 路由共用 */

/* parse_qs(query).get(key)(空值丢弃;unquote_plus 解码) */
static char *q_val(const char *query, const char *key)
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
			int matched = 0;
			char *v = NULL;

			if (klen_q == klen &&
			    strncmp(query + i, key, klen) == 0) {
				matched = 1;
				{
					/* unquote_plus(v) */
					size_t vlen =
						seg_end - klen_q - 1 - i;
					struct dt_sbuf b;

					dt_sb_init(&b);
					for (size_t x = 0; x < vlen; x++) {
						char c = eq[1 + x];

						if (c == '+') {
							dt_sb_putc(&b, ' ');
							continue;
						}
						if (c == '%' && x + 2 < vlen) {
							int hi = -1, lo = -1;
							char h = eq[2 + x],
							     l = eq[3 + x];

							if (h >= '0' &&
							    h <= '9')
								hi = h - '0';
							else if (h >= 'a' &&
								 h <= 'f')
								hi = h - 'a' +
								     10;
							else if (h >= 'A' &&
								 h <= 'F')
								hi = h - 'A' +
								     10;
							if (l >= '0' &&
							    l <= '9')
								lo = l - '0';
							else if (l >= 'a' &&
								 l <= 'f')
								lo = l - 'a' +
								     10;
							else if (l >= 'A' &&
								 l <= 'F')
								lo = l - 'A' +
								     10;
							if (hi >= 0 && lo >= 0) {
								dt_sb_putc(
									&b,
									(char)((hi << 4) |
									       lo));
								x += 2;
								continue;
							}
						}
						dt_sb_putc(&b, c);
					}
					v = dt_sb_finish(&b);
				}
			}
			if (matched) {
				if (v && *v)
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

static int actions_has(const aik_json *actions, const char *name)
{
	if (!actions || aik_json_typeof(actions) != AIK_JSON_ARR)
		return 0;
	for (size_t i = 0; i < aik_json_count(actions); i++) {
		const aik_json *a = aik_json_at(actions, i);
		const aik_json *av = dt_get(a, "action");

		if (av && aik_json_typeof(av) == AIK_JSON_STR &&
		    strcmp(aik_json_str(av), name) == 0)
			return 1;
	}
	return 0;
}

/* VM 实况终端块(get_vm_status 动作;server.py:2110-2125) */
static void append_vm_block(struct dt_sbuf *reply, const aik_json *actions)
{
	aik_json *snap;
	const aik_json *reach;

	if (!actions_has(actions, "get_vm_status"))
		return;
	snap = dt_vm_status_snapshot();
	reach = dt_get(snap, "reachable");
	if (reach && aik_json_bool(reach)) {
		const aik_json *st = dt_get(snap, "status");
		const aik_json *se = dt_get(snap, "sense");

		dt_sb_putstr(reply, "\n```\n[AIKernel VM 192.168.245.138 实况]\n");
		if (st && aik_json_typeof(st) == AIK_JSON_OBJ) {
			static const char *keys[] = { "uptime", "services",
						      "sandbox", "version",
						      "load" };

			for (size_t k = 0; k < 5; k++) {
				const aik_json *v = dt_get(st, keys[k]);

				if (!v)
					continue;
				{
					char *vs = dt_pystr(v);

					dt_sb_printf(reply, "%s: %s\n",
						     keys[k], vs ? vs : "");
					free(vs);
				}
			}
		}
		if (se && aik_json_typeof(se) == AIK_JSON_OBJ) {
			size_t n = aik_json_count(se);

			for (size_t i = 0; i < n; i++) {
				const char *k = aik_json_key_at(se, i);
				char *d = dt_json_dump_default(
					aik_json_val_at(se, i));

				if (d) {
					char *head = dt_utf8_head(d, 160);

					dt_sb_printf(reply, "%s: %s\n", k,
						     head ? head : "");
					free(head);
					free(d);
				}
			}
		}
		dt_sb_putstr(reply, "```");
	} else {
		const aik_json *ev = dt_get(snap, "error");
		const char *errs = (ev && aik_json_typeof(ev) == AIK_JSON_STR)
					   ? aik_json_str(ev)
					   : "?";

		dt_sb_printf(reply, "\n(VM 138 当前不可达:%s;已断开隧道)",
			     errs);
		dt_vm_close();
	}
	aik_json_free(snap);
}

/* sandbox 只读视图块(sandbox_view 动作;server.py:2127-2136) */
static void append_sandbox_block(struct dt_sbuf *reply,
				 const aik_json *actions)
{
	aik_json *snap;
	const aik_json *reach;

	if (!actions_has(actions, "sandbox_view"))
		return;
	snap = dt_vm_sandbox_snapshot();
	reach = dt_get(snap, "reachable");
	if (reach && aik_json_bool(reach)) {
		const aik_json *rawv = dt_get(snap, "raw");
		const char *raw = (rawv && aik_json_typeof(rawv) ==
					    AIK_JSON_STR)
					  ? aik_json_str(rawv)
					  : "";
		struct dt_sbuf body;

		dt_sb_init(&body);
		/* .replace("\n---MOUNTS---\n", ...).replace("\n---PROCS---\n",
		 * ...) */
		{
			const char *p = raw;

			while (*p) {
				if (p[0] == '\n' &&
				    strncmp(p, "\n---MOUNTS---\n", 15) ==
					    0) {
					dt_sb_putstr(&body,
						     "\n$ mount | grep sandbox\n");
					p += 15;
					continue;
				}
				if (p[0] == '\n' &&
				    strncmp(p, "\n---PROCS---\n", 14) == 0) {
					dt_sb_putstr(&body,
						     "\n$ ps | grep sandbox\n");
					p += 14;
					continue;
				}
				dt_sb_putc(&body, *p);
				p++;
			}
		}
		if (dt_truthy(dt_get(snap, "empty")))
			dt_sb_putstr(&body,
				     "(当前无任何隔离区;创建属 W1 写操作,GUI "
				     "演示阶段按红线不开放)");
		dt_sb_putstr(reply,
			     "\n```\n[sandbox_status @ VM 138 (R 只读)]\n$ ls "
			     "-la /sandbox/\n");
		if (body.p)
			dt_sb_putstr(reply, body.p);
		dt_sb_putstr(reply, "\n```");
		free(body.p);
	} else {
		const aik_json *ev = dt_get(snap, "error");
		const char *errs = (ev && aik_json_typeof(ev) == AIK_JSON_STR)
					   ? aik_json_str(ev)
					   : "?";

		dt_sb_printf(reply, "\n(隔离区读取失败:%s;已断开隧道)",
			     errs);
	}
	aik_json_free(snap);
}

/* ---------------------------------------------------------------- 路由 */

int dt_route_chat_post(struct dt_req *req, struct dt_resp *r)
{
	long long t0 = dt_time();
	aik_json *body = req->json;
	const aik_json *mv = body ? dt_get(body, "message") : NULL;
	char *message;
	char *sid;
	const aik_json *history = body ? dt_get(body, "history") : NULL;
	int force_fallback;
	aik_json *actions;
	const aik_json *apps;
	long long apps_count;
	char *reply_text = NULL;
	char *source = NULL; /* malloc(默认 "demo" 由下方落填) */
	aik_json *o;

	/* message = (body.get("message") or "").strip() */
	if (!mv || !dt_truthy(mv)) {
		message = strdup("");
		if (!message)
			return -1;
	} else if (aik_json_typeof(mv) == AIK_JSON_STR) {
		message = dt_strip(aik_json_str(mv));
		if (!message)
			return -1;
	} else {
		return -1; /* int.strip() AttributeError → 关连接 */
	}
	if (!*message) {
		o = dt_new_obj();
		dt_put_str(o, "error", "empty message");
		dt_resp_json(r, 400, o);
		aik_json_free(o);
		free(message);
		return 0;
	}
	{ /* len(message) > 2000 码点 → 静默截断 */
		size_t cpl = dt_utf8_cplen(message, strlen(message));

		if (cpl > 2000) {
			char *head = dt_utf8_head(message, 2000);

			free(message);
			if (!head)
				return -1;
			message = head;
		}
	}
	{ /* sid = str(body.get("session") or "default");非法回落 default */
		const aik_json *sv = body ? dt_get(body, "session") : NULL;

		if (!sv || !dt_truthy(sv)) {
			sid = strdup("default");
		} else {
			char *s = dt_pystr(sv);

			if (!s || !dt_regex_session(s)) {
				free(s);
				sid = strdup("default");
			} else {
				sid = s;
			}
		}
		if (!sid) {
			free(message);
			return -1;
		}
	}
	force_fallback = q_val(req->query, "fallback") != NULL;

	actions = dt_parse_intents(message);
	if (!actions) {
		free(message);
		free(sid);
		return -1;
	}
	apps = dt_get_apps(0);
	apps_count = (apps && aik_json_typeof(apps) == AIK_JSON_ARR)
			     ? (long long)aik_json_count(apps)
			     : 0;
	if (aik_json_count(actions) == 0) {
		aik_json *oa = dt_match_open_app(message, apps);

		if (oa)
			aik_json_arr_push(actions, oa);
	}

	if (!force_fallback) {
		int crash = 0;
		aik_json *msgs = dt_chat_context(sid, history, message,
						 &crash);
		aik_json *lr;

		if (crash || !msgs) {
			aik_json_free(actions);
			free(message);
			free(sid);
			return -1;
		}
		(void)0;
		lr = dt_call_llm(msgs);
		aik_json_free(msgs);
		if (lr) {
			const aik_json *ev = dt_get(lr, "endpoint");
			const aik_json *tv = dt_get(lr, "text");
			size_t tlen;

			/* endpoint 字符串需拷出:lr 释放后不可再引用 */
			source = strdup(
				ev && aik_json_typeof(ev) == AIK_JSON_STR
					? aik_json_str(ev)
					: "forwarder");
			reply_text = strdup(tv && aik_json_typeof(tv) ==
						 AIK_JSON_STR
						  ? aik_json_str(tv)
						  : "");
			aik_json_free(lr);
			if (!source) {
				source = strdup("forwarder");
				if (!source) {
					aik_json_free(actions);
					free(reply_text);
					free(message);
					free(sid);
					return -1;
				}
			}
			if (!reply_text) {
				aik_json_free(actions);
				free(message);
				free(sid);
				return -1;
			}
			tlen = strlen(reply_text);
			dt_chat_extract_tag(reply_text, &tlen, actions);
			reply_text[tlen] = '\0';
			{
				char *s2 = dt_strip(reply_text);

				free(reply_text);
				reply_text = s2;
				if (!reply_text) {
					aik_json_free(actions);
					free(message);
					free(sid);
					return -1;
				}
			}
		}
	}
	/* 强制降级分支的预算日志:冻结时钟下恒不触发,略 */

	if (!reply_text) {
		reply_text = dt_demo_reply(message, actions, apps_count);
		free(source);
		source = strdup("demo");
		if (!reply_text || !source) {
			aik_json_free(actions);
			free(reply_text);
			free(message);
			free(sid);
			return -1;
		}
	}
	{
		/* VM 实况附加块(无论云端/demo 来源) */
		struct dt_sbuf full;

		dt_sb_init(&full);
		dt_sb_putstr(&full, reply_text);
		free(reply_text);
		reply_text = NULL;
		append_vm_block(&full, actions);
		append_sandbox_block(&full, actions);
		reply_text = dt_sb_finish(&full);
		if (!reply_text) {
			aik_json_free(actions);
			free(message);
			free(sid);
			return -1;
		}
	}
	{
		long long took = (dt_time() - t0) * 1000;
		char ts[32];
		aik_json *eu, *ea;

		dt_strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S");
		eu = dt_new_obj();
		dt_put_str(eu, "role", "user");
		dt_put_str(eu, "content", message);
		dt_put_str(eu, "ts", ts);
		if (dt_append_chat(sid, eu) != 0)
			dt_log("聊天持久化失败: OSError");
		ea = dt_new_obj();
		dt_put_str(ea, "role", "assistant");
		dt_put_str(ea, "content", reply_text);
		dt_put_str(ea, "ts", ts);
		dt_put_str(ea, "source", source);
		if (dt_append_chat(sid, ea) != 0)
			dt_log("聊天持久化失败: OSError");

		{ /* 日志(不进差分) */
			struct dt_sbuf lg;
			char *head40 = dt_utf8_head(message, 40);

			dt_sb_init(&lg);
			dt_sb_printf(&lg, "chat: src=%s acts=[", source);
			for (size_t i = 0; i < aik_json_count(actions); i++) {
				const aik_json *a = aik_json_at(actions, i);
				const aik_json *av = dt_get(a, "action");

				if (i)
					dt_sb_puts(&lg, ", ", 2);
				dt_sb_putstr(&lg,
					     av &&
						     aik_json_typeof(av) ==
							     AIK_JSON_STR
					     ? aik_json_str(av)
					     : "?");
			}
			dt_sb_printf(&lg, "] took=%lldms msg='%s'", took,
				     head40 ? head40 : "");
			dt_log("%s", lg.p ? lg.p : "chat");
			free(lg.p);
			free(head40);
		}

		o = dt_new_obj();
		dt_put_str(o, "reply", reply_text);
		aik_json_obj_put(o, "actions", actions); /* 所有权移交 */
		dt_put_str(o, "source", source);
		dt_put_int(o, "took_ms", took);
		dt_put_str(o, "session", sid);
		dt_resp_json(r, 200, o);
		aik_json_free(o);
	}
	free(reply_text);
	free(source);
	free(message);
	free(sid);
	return 0;
}

int dt_route_chat_fallback(struct dt_req *req, struct dt_resp *r)
{
	char *msg = q_val(req->query, "fallback");
	const aik_json *apps;
	long long apps_count;
	char *reply;
	aik_json *o;

	if (!msg) {
		msg = strdup("你好"); /* parse_qs 默认值,理论不可达 */
		if (!msg)
			return -1;
	}
	apps = dt_get_apps(0);
	apps_count = (apps && aik_json_typeof(apps) == AIK_JSON_ARR)
			     ? (long long)aik_json_count(apps)
			     : 0;
	reply = dt_demo_reply(msg, NULL, apps_count);
	free(msg);
	if (!reply)
		return -1;
	o = dt_new_obj();
	dt_put_str(o, "reply", reply);
	aik_json_obj_put(o, "actions", dt_new_arr());
	dt_put_str(o, "source", "demo");
	dt_resp_json(r, 200, o);
	aik_json_free(o);
	free(reply);
	return 0;
}
