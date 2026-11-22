/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_gate.h - T4 控制台登录门（首次设密向导 / 登录框 / skipgate 旁路）
 *
 * 形态（主会话拍板 2026-11-12）：
 *   - 只在交互 TUI 形态（双 tty）启用；occ -p/headless/管道完全不启门
 *   - 账户=admin（TUI 本地账户，不动系统 root）；一个密码=全功能
 *   - 引导参数 ai.skipgate=1 → 旁路（物理接触本可旁路；ISO 烟测用）
 *   - 连续 3 错 → 10 秒冷却倒计时，冷却后计数清零
 *   - 哈希：glibc crypt() sha512crypt（$6$）；常数时间比较
 *
 * P-2a 多用户（Phase A）：
 *   - 凭据文件多条目：每行 `name:$6$<sha512crypt>:<unix_ts>[:<fails>]`；
 *     `#` 注释行与空行忽略；重名首行为准；坏行跳过；老式单行文件
 *     （admin 三段）=admin 条目（向后兼容必须）
 *   - 登录框出用户名输入（预填上次成功用户：
 *     /var/lib/aikernel/console-gate.last，0600 一行用户名；缺省 admin）
 *   - 失败计数存取走用户行尾第 4 段；冷却 3 错 10s、逐用户独立
 *   - env 覆盖：AIK_CONSOLE_GATE（凭据文件）、AIK_CONSOLE_GATE_LAST
 *     （上次用户文件，测试用）
 */
#ifndef OCC_TUI_GATE_H
#define OCC_TUI_GATE_H

#define TUI_GATE_HASH_LEN 128	/* sha512crypt 文本上限（含 NUL 边界） */

/* 纯逻辑面（headless 可测） */
const char *tui_gate_path(void);	/* env 覆盖 or /etc/aikernel/console-gate */
int tui_gate_skipboot_path(const char *cmdline_path);
int tui_gate_skipboot(void);		/* 读 /proc/cmdline */
int tui_gate_read(const char *path, char hash[128], long long *ts);
int tui_gate_hash(const char *pw, char out[128]);
int tui_gate_verify(const char *pw, const char *hash);
int tui_gate_write(const char *path, const char *hash);

/*
 * P-2a 多条目 API（B 棒 aikctl 与 occ /su 依赖此契约，签名一字不许偏）：
 * tui_gate_read_user - 按用户名取条目。
 *   返回 0=找到（hash_out 收哈希；fails_out 可 NULL，收行尾第 4 段
 *   失败计数，缺省段=0）；<0=无此用户/坏文件/参数坏。
 * tui_gate_write_entry - 原子写（tmp+rename，0600）一条用户条目：
 *   更新已存在行（重名首行）或追加；其余行（含注释）原样保留。
 *   fails==0 写三段（老式字节形态），>0 写四段。成功 0。
 */
int tui_gate_read_user(const char *path, const char *user,
		       char hash_out[TUI_GATE_HASH_LEN], int *fails_out);
int tui_gate_write_entry(const char *path, const char *user,
			 const char *hash, int fails);

/*
 * UI 面：进屏登录门。返回 0=解锁（或旁路）；非 0=未解锁退出
 * （occ 退出——外层包装重启后仍在锁定态）。
 * 只应在双 tty 交互形态调用。
 */
int tui_gate_enter(void);

#endif /* OCC_TUI_GATE_H */
