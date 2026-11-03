/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dtstate.h - W76b 运行期状态根(theme/desktop/notifs/pin/chats)与
 * 虚拟窗口状态机、PIN 状态机、通知不对称截断(T6b)。
 *
 * 写文件语义(与 server.py 逐条对齐):
 *   - write_state_json = indent=2 + ensure_ascii=False + 无尾换行 +
 *     tmp(无 pid)+ 先 fchmod 0600 + rename(theme/desktop/pin);
 *   - chats/<sid>.json 与 notifs.json = 裸 dump_default + tmp + 0600 + rename;
 *   - chats/<sid>.meta.json = 非原子直写 + 写后 chmod 0600。
 */
#ifndef _AIK_DESKTOP_DTSTATE_H
#define _AIK_DESKTOP_DTSTATE_H

#include <stddef.h>

#include "store/store_json.h"

/* 启动幂等:STATE_ROOT 0700、chats/screenshots/icons/icons/apps 0700、
 * 种子(theme 复制/copyfile,data 默认值 indent2)、chats 下文件补 0600 */
int dt_ensure_state(void);

/* ---------------- desktop.json ---------------- */

/* load_desktop:坏/缺 → 默认;setdefault 六键序
 * mode/windows/next_id/z/clipboard/clipboard_updated */
aik_json *dt_load_desktop(void);
int dt_save_desktop(aik_json *obj);

/* _desktop_snapshot:按 z 升序 stable;键序
 * mode/count/focused/windows/clipboard/backend/note */
aik_json *dt_desktop_snapshot(aik_json *obj);

/* _focus_window:最高 z+1 获焦(唯一)、obj.focused/mode/z */
void dt_focus_window(aik_json *obj, const char *wid);
/* _top_focus:最高 z(并列取首个)获焦;无窗 focused=null */
void dt_top_focus(aik_json *obj);
/* _window_launch:同 app 可见窗复用只 focus;返回窗口对象与 created */
aik_json *dt_window_launch(aik_json *obj, const aik_json *app, int *created);
/* _window_text_append:4096 码点上限;返回实际追加码点数 */
long long dt_window_text_append(aik_json *w, const char *text);
/* _find_window */
aik_json *dt_find_window(aik_json *obj, const char *wid);
/* 按码点统计窗口文本长度 */
size_t dt_window_text_len(const aik_json *w);

/* ---------------- notifs ---------------- */

/* 单条追加分支:键序 title/body/tag/time/id/source;[-100:] 保尾 */
aik_json *dt_notif_new_entry(const aik_json *body, int *bad_request);

/* ---------------- pin ---------------- */

aik_json *dt_load_pin(void);
int dt_save_pin(aik_json *p);
/* pin_strength_warning:<6 位/全同/连续升降序;无警告返回 NULL */
char *dt_pin_warning(const char *pin);

/* ---------------- chats ---------------- */

aik_json *dt_load_chat(const char *sid);
/* chats/<sid><suffix> 路径(malloc;调用者释放) */
char *dt_chat_path(const char *sid, const char *suffix);
/* append_chat:整文件读改写,>200 丢最旧,dump_default 原子写 */
int dt_append_chat(const char *sid, aik_json *entry);
/* new_session_id:%Y%m%d-%H%M%S + "-" + md5(str(random()))[:6](调用方释放) */
char *dt_new_session_id(void);
/* chat_sessions:见 server.py —— 遍历 sorted(*.json),meta 文件解析为
 * 非列表/元素非对象即中断循环(等价 AttributeError);last 降序稳定排序 */
aik_json *dt_chat_sessions(void);

#endif /* _AIK_DESKTOP_DTSTATE_H */
