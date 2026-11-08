/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_overlay.h - occ TUI 全屏覆盖层（T9c3：overlays 数据件）
 *
 * 通用面板两态：
 *   - 列表态：标题 + 计数 + 可选过滤行 + 分组头（不可选）列表 + detail/
 *     status 行 + footer；view 把键解析成动作/字符后调 nav/type 等；
 *   - 输入态：标题 + 提示 + 单行输入（mask 渲染 `*`）+ status + footer。
 *
 * 供数与决策在 occ.c（registry/db/tools.json/trace/lease/向导），
 * 本模块只管「壳」：拷贝 items、可见映射（query 子串过滤、去分组）、
 * 选择窗滚动、渲染。ov_id 由 occ.c 定义（回传钩子定位场景）。
 */
#ifndef OCC_TUI_OVERLAY_H
#define OCC_TUI_OVERLAY_H

#include <stddef.h>
#include <stdint.h>

#include "tui_core.h"
#include "tui_theme.h"

#ifdef __cplusplus
extern "C" {
#endif

/* item 标志 */
#define TUI_OV_HEADER 1		/* 分组头：渲染加粗、导航跳过、不可选 */
#define TUI_OV_DIM 2		/* 次要条目（muted） */

#define TUI_OV_TEXT_MAX 176
#define TUI_OV_TAG_MAX 56
#define TUI_OV_DETAIL_MAX 200
#define TUI_OV_TITLE_MAX 64
#define TUI_OV_STATUS_MAX 220
#define TUI_OV_INPUT_MAX 240
#define TUI_OV_QUERY_MAX 96
#define TUI_OV_FOOTER_MAX 176
#define TUI_OV_PROMPT_MAX 128

typedef struct {
	char text[TUI_OV_TEXT_MAX];
	char tag[TUI_OV_TAG_MAX];
	char detail[TUI_OV_DETAIL_MAX];
	int flags;
} tui_ov_item;

typedef struct tui_overlay tui_overlay;

/* 键动作结果（SUBMIT/CLOSE 由 view 转钩子；HANDLED=已消费） */
enum {
	TUI_OVA_NONE = 0,
	TUI_OVA_HANDLED,
	TUI_OVA_SUBMIT,
	TUI_OVA_CLOSE
};

tui_overlay *tui_overlay_create(void);
void tui_overlay_destroy(tui_overlay *ov);
void tui_overlay_clear(tui_overlay *ov);	/* 关闭（内存复用） */

/* 列表态（items 深拷贝；searchable=1 时有过滤行）。0=ok */
int tui_overlay_set_list(tui_overlay *ov, int ov_id, const char *title,
			 const tui_ov_item *items, int n, int searchable,
			 const char *footer);

/* 输入态（initial 可 NULL；mask=1 渲染 `*`） */
int tui_overlay_set_input(tui_overlay *ov, int ov_id, const char *title,
			  const char *prompt, const char *initial, int mask);

int tui_overlay_active(const tui_overlay *ov);
int tui_overlay_id(const tui_overlay *ov);
int tui_overlay_is_input(const tui_overlay *ov);
int tui_overlay_searchable(const tui_overlay *ov);
int tui_overlay_nitems(const tui_overlay *ov);
/* 当前选择的可见下标；-1=无可选项 */
int tui_overlay_sel(const tui_overlay *ov);
/* 可选项总数（不含分组头） */
int tui_overlay_count_selectable(const tui_overlay *ov);
/* 当前选择在可选项中的 1 基序号（0=无）——标题右侧 [i/n] 用 */
int tui_overlay_sel_no(const tui_overlay *ov);
const char *tui_overlay_title(const tui_overlay *ov);
const char *tui_overlay_query(const tui_overlay *ov);
const char *tui_overlay_input_text(const tui_overlay *ov, size_t *len);
const char *tui_overlay_footer(const tui_overlay *ov);

/* 导航（±1 跳过分组头；无处去也返回 HANDLED=按键被面板吞掉） */
int tui_overlay_nav(tui_overlay *ov, int dir);
int tui_overlay_page(tui_overlay *ov, int dir);	/* 按上次渲染体高 */
int tui_overlay_home(tui_overlay *ov);
int tui_overlay_end(tui_overlay *ov);
/* 输入态删一个 grapheme；过滤行删一个字符（非过滤列表 NONE） */
int tui_overlay_backspace(tui_overlay *ov);
/* 输入态追加；过滤行追加并重建可见映射（选择复位到首个可选） */
int tui_overlay_type(tui_overlay *ov, const char *utf8, size_t len);
/* Enter：返回原始 items 下标；-1=无可选 */
int tui_overlay_submit_idx(const tui_overlay *ov);

/* 框内状态行（向导步骤消息/错误；msg=NULL 清除） */
void tui_overlay_status(tui_overlay *ov, const char *msg, int is_err);

/*
 * 渲染全屏面板（整屏填底 → 标题 → 过滤行 → 列表窗/detail → footer；
 * 输入态 → 提示 + 输入行 + status）。维护滚动窗（top/body_h）。
 * 光标：输入态写 (cur_row,cur_col)（文本尾，横移保可见）；列表态 -1。
 */
void tui_overlay_render(tui_overlay *ov, tui_screen *s,
			int *cur_row, int *cur_col);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_OVERLAY_H */
