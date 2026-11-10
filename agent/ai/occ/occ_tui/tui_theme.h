/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_theme.h - occ TUI 调色板：槽位常量 + 运行时数据文件（T9c2 常量 → c3 数据化）
 *
 * 槽位语义对齐 tui_core.h tui_theme_slot（FG/BG/MUTED/ACCENT/BORDER/
 * ERROR/OK/WARN/USER_BG/ASSISTANT_BG）+ markdown/语法/工具行扩展色。
 *
 * T9c3：TUI_THM_* 从「颜色值」改为「槽位号」——tui_thm_attr 经全局
 * 调色板（tui_theme.c）解析成真色。出厂缺省 = c2 编译期默认值逐槽相等
 * （252/235/242/81/238/203/114/214/236/234 + 186/236/81/114/179/244/75）。
 *
 * 数据文件（~/.occ/theme.ini，OCC_THEME 可覆盖）：行式 `key = 0..255`、
 * `#` 整行注释。坏文件 → tui_thm_load 返回 -1 且**调色板保持加载前状态**
 * （先解析进临时表、整文件全对才提交）——view 打 notice 诚实回落，不崩。
 *
 * 取值原则不变：256 色 xterm 默认调色板可辨（深底 235 上的亮字）。
 */
#ifndef OCC_TUI_THEME_H
#define OCC_TUI_THEME_H

#include <stddef.h>
#include <stdint.h>

#include "tui_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 槽位号（tui_thm_attr 的入参；非颜色值） ---- */
enum {
	TUI_THM_FG = 0,
	TUI_THM_BG,
	TUI_THM_MUTED,
	TUI_THM_ACCENT,
	TUI_THM_BORDER,
	TUI_THM_ERROR,
	TUI_THM_OK,
	TUI_THM_WARN,
	TUI_THM_USER_BG,
	TUI_THM_ASSIST_BG,
	/* markdown / 语法扩展色 */
	TUI_THM_CODE_FG,
	TUI_THM_CODE_BG,
	TUI_THM_KW,
	TUI_THM_STR,
	TUI_THM_NUM,
	TUI_THM_CMT,
	TUI_THM_LINK,
	/* UXAB：footer cache-read（c 前缀）紫 */
	TUI_THM_CACHE,
	TUI_THM_COUNT
};

/* ---- spinner 帧（E 字形白名单：半块 3 帧，80ms/帧；常量，不入数据文件）
 * E 方案字形白名单只许 box-drawing/半块/●○◆/箭头/×·… + ASCII——盲文点阵
 * （U+2800 段）在 Noto CJK/Consolas 出豆腐，淘汰。半块帧取
 * █(U+2588)/▌(U+258C)/▎(U+258E)，VM 已实证单列渲染（宽度探针测试钉死）。 */
#define TUI_THM_SPINNER "█▌▎"
#define TUI_THM_SPINNER_MS 80

/* 槽位 → ini 键名（诊断/测试）；未知槽返回 NULL */
const char *tui_thm_slot_name(int slot);
/* ini 键名 → 槽位；未知返回 -1 */
int tui_thm_slot_by_name(const char *name);

/* 调色板真色（0-255）；槽越界返回出厂 FG（防御） */
int tui_thm_color(int slot);

/* 恢复出厂缺省（单测/加载失败自保） */
void tui_thm_reset(void);

/*
 * 加载数据文件并**整文件提交**。返回：
 *   0  = 成功提交，或文件不存在（ENOENT——出厂缺省静默生效，非错误）；
 *   -1 = 文件存在但坏（打不开/未知键/值越界/语法错）——err 填人话
 *        （带行号），调色板保持加载前状态（调用方回落缺省 + notice）。
 */
int tui_thm_load(const char *path, char *err, size_t errlen);

/* 便捷属性构造（inline：未用不告警——-Werror 友好；fg/bg 为槽位号） */
static inline tui_attr tui_thm_attr(int fg, int bg, uint16_t style)
{
	tui_attr a;

	a.fg = tui_color_idx(tui_thm_color(fg));
	a.bg = (bg >= 0) ? tui_color_idx(tui_thm_color(bg)) :
			 tui_color_default();
	a.style = style;
	return a;
}

static inline tui_attr tui_thm_plain(void)
{
	return tui_thm_attr(TUI_THM_FG, TUI_THM_BG, 0);
}

static inline tui_attr tui_thm_muted(void)
{
	return tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG, 0);
}

static inline tui_attr tui_thm_accent(uint16_t style)
{
	return tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG, style);
}

/* spinner 帧字符（now_ms 驱动；返回指向静态串的指针，1 字符+NUL 视感）
 * 注：半块每帧 3 字节 UTF-8（U+2588/258C/258E），直接返回常量。
 * 帧表放函数内 static——头文件级 static const 数组会在未用到的 TU 触发
 * -Wunused-const-variable（-Werror 下炸）。 */
static inline const char *tui_thm_spinner(uint64_t now_ms)
{
	static const char *const frames[3] = {
		"█", "▌", "▎"
	};

	return frames[(now_ms / TUI_THM_SPINNER_MS) % 3];
}

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_THEME_H */
