/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_keymap.h - occ TUI 键位表数据化（T9c3：OCD-SPEC §2 正典）
 *
 * 模型：动作名 → 键串表（多键逗号分隔），按**上下文**隔离查找——
 * 同一键（escape）在 BASE 命中 session.interrupt、在 OVERLAY 命中
 * dialog.close（OCD 分层注册的 C 等价）。
 *
 * 缺省表 = OCD 现值（keybind.ts 行号见 T9-OCD-SPEC §2.2/§2.4）中
 * occ 已实现动作的子集；leader=ctrl+x（超时 2000ms）。
 *
 * 覆盖文件（~/.occ/keymap，OCC_KEYMAP 可覆盖）：
 *   # 注释
 *   leader = ctrl+x
 *   leader_timeout = 2000
 *   app.exit = ctrl+c, ctrl+d, <leader>q
 *   session.rename = none          （none=取消绑定）
 * 别名归一（keymap.tsx:80-88，解析期做）：enter→return、esc→escape、
 * pgup→pageup、pgdn/pgdown→pagedown、del→delete；修饰序归一为
 * ctrl+ alt+ super+ shift+（tui_event_keystr 同序）；单字母小写化。
 *
 * 文件不存在 → 0（缺省静默）；任何一行坏 → -1（err 带行号），**表保持
 * 加载前状态**（先解析后提交）——view 回落缺省 + notice。
 *
 * 取舍（报告）：输入框编辑类键（字符/光标/退格/Tab/return/ctrl+j）不入
 * 表（c2 内置实现，test_inputbox 零回归合同）；表管动作（exit/clear/
 * interrupt/scroll/leader 命令/dialog 导航）。
 */
#ifndef OCC_TUI_KEYMAP_H
#define OCC_TUI_KEYMAP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tui_keymap tui_keymap;	/* opaque heap */

/* 查找上下文（动作归属） */
enum {
	TUI_KM_CTX_BASE = 0,		/* 退出/中断/翻页/leader 命令 */
	TUI_KM_CTX_OVERLAY = 1		/* dialog.* + model.add/favorite */
};

#define TUI_KM_KEY_MAX 48		/* 单键串上限（含 <leader> 前缀） */
#define TUI_KM_KEYS_PER_ACT 8

/* 内置缺省表（OCD 现值；heap，调用方 destroy） */
tui_keymap *tui_keymap_create(void);
void tui_keymap_destroy(tui_keymap *km);

/*
 * 覆盖文件加载（合并到 km 上——仅整文件全对才提交）。
 * 0 = 成功或文件不存在；-1 = 坏文件（err 人话带行号，km 不变）。
 */
int tui_keymap_load(tui_keymap *km, const char *path, char *err,
		    size_t errlen);

/*
 * 键串（tui_event_keystr 规范形，如 "ctrl+c"/"escape"/"<leader>q" 之外的
 * 普通形）→ 动作名（按 ctx 归属、表序优先）；未命中 NULL。
 * keystr 为 NULL/空 → NULL。
 */
const char *tui_keymap_lookup(const tui_keymap *km, const char *keystr,
			      int ctx);

/* leader pending 态：keystr → 动作（只匹配含 <leader> 前缀的绑定） */
const char *tui_keymap_lookup_leader(const tui_keymap *km,
				     const char *keystr);

/* 指定动作是否绑定了该键串（ctx 归属内；ctrl+c 的 exit/clear 双归属判定） */
int tui_keymap_matches(const tui_keymap *km, const char *action,
		       const char *keystr, int ctx);

const char *tui_keymap_leader(const tui_keymap *km);	/* 缺省 "ctrl+x" */
long tui_keymap_leader_timeout_ms(const tui_keymap *km);	/* 2000 */

/*
 * 动作当前绑定串（"ctrl+c, ctrl+d" 形写入 buf，help/断言用）。
 * 返回写入长度；动作不存在 → -1。
 */
int tui_keymap_binding_str(const tui_keymap *km, const char *action,
			   char *buf, size_t cap);

/* 动作名是否属于给定 ctx（解析期校验 + 测试）；未知动作 0 */
int tui_keymap_action_ctx(const char *action);

/* 键串别名归一（写入 buf 返回 1 成功；无法归一 0）。单测直用。 */
int tui_keymap_norm_key(const char *in, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_KEYMAP_H */
