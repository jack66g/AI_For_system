/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_gate.h - T4 控制台登录门（首次设密向导 / 登录框 / skipgate 旁路）
 *
 * 形态（主会话拍板 2026-11-12）：
 *   - 只在交互 TUI 形态（双 tty）启用；occ -p/headless/管道完全不启门
 *   - 账户=admin（TUI 本地账户，不动系统 root）；一个密码=全功能
 *   - 凭据文件：/etc/aikernel/console-gate（env AIK_CONSOLE_GATE 可覆盖，
 *     测试用），格式一行 `admin:<crypt 哈希>:<十进制时间戳>`，0600 root
 *   - 引导参数 ai.skipgate=1 → 旁路（物理接触本可旁路；ISO 烟测用）
 *   - 连续 3 错 → 10 秒冷却倒计时，冷却后计数清零
 *   - 哈希：glibc crypt() sha512crypt（$6$）；常数时间比较
 */
#ifndef OCC_TUI_GATE_H
#define OCC_TUI_GATE_H

/* 纯逻辑面（headless 可测） */
const char *tui_gate_path(void);	/* env 覆盖 or /etc/aikernel/console-gate */
int tui_gate_skipboot_path(const char *cmdline_path);
int tui_gate_skipboot(void);		/* 读 /proc/cmdline */
int tui_gate_read(const char *path, char hash[128], long long *ts);
int tui_gate_hash(const char *pw, char out[128]);
int tui_gate_verify(const char *pw, const char *hash);
int tui_gate_write(const char *path, const char *hash);

/*
 * UI 面：进屏登录门。返回 0=解锁（或旁路）；非 0=未解锁退出
 * （occ 退出——外层包装重启后仍在锁定态）。
 * 只应在双 tty 交互形态调用。
 */
int tui_gate_enter(void);

#endif /* OCC_TUI_GATE_H */
