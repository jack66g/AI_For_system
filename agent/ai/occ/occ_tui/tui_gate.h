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

#include <sys/types.h>		/* uid_t/gid_t/mode_t（P-60/D7 权限契约） */

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
 * tui_gate_write_entry - 原子写（tmp+rename）一条用户条目：权限按下方
 *   D7 契约（root 且机器上有 aik-gate 组=0640 root:aik-gate；否则 0600）：
 *   更新已存在行（重名首行）或追加；其余行（含注释）原样保留。
 *   fails==0 写三段（老式字节形态），>0 写四段。成功 0。
 */
int tui_gate_read_user(const char *path, const char *user,
		       char hash_out[TUI_GATE_HASH_LEN], int *fails_out);
int tui_gate_write_entry(const char *path, const char *user,
			 const char *hash, int fails);

/*
 * P-60/D1（CON-02b）：凭据「读不了」≠「没有」。
 * 背景：读侧对 fopen 失败一律按「文件不在」上报，UI 把它当首次使用
 * 进 SETUP 向导——非 root 的 occ 读不了 0600 的 gate 文件时，屏上让
 * 普通用户「设置 admin 密码」并吞掉后续键入（142 实机抓获）。
 *
 * tui_gate_open_class - 凭据文件 open 失败的 errno 分类（纯函数，可单测）：
 *   ENOENT/ENOTDIR → TUI_GATE_OPEN_ABSENT（文件不在：首次使用/管理员
 *     删文件=复位——SETUP 向导语义不变）；
 *   其余（EACCES/EPERM/EISDIR/EIO…）→ TUI_GATE_OPEN_DENIED（文件在却
 *     读不出——绝不进 SETUP）。
 * 读侧返回码补充（既有调用方只判 0/非 0；签名与「<0=未找到」契约不变）：
 *   tui_gate_read / tui_gate_read_user 另返回 TUI_GATE_READ_DENIED = 文件
 *   在却读不出（权限/非普通文件/IO）；-1 仍=无此用户/坏文件/参数坏。
 * 写侧：tui_gate_write_entry 在「既有文件读不出」时拒写返回 -1（读不到
 *   既有条目就无从保留其余行——硬写=整文件覆写丢他人条目）；文件不在
 *   照旧新建。
 * UI：tui_gate_enter 命中读不出 → 屏上诚实人话（不进 SETUP）、等按键后
 *   返回 TUI_GATE_DENIED（非零=未解锁；occ 退出，aik-console 记账后重启
 *   循环，仍处锁定态）。TUI_GATE_LOCKED=其余未解锁退出（Ctrl-C/Esc/EOF）。
 */
#define TUI_GATE_OPEN_ABSENT	0
#define TUI_GATE_OPEN_DENIED	1
#define TUI_GATE_READ_DENIED	(-2)
#define TUI_GATE_LOCKED		1
#define TUI_GATE_DENIED		2
int tui_gate_open_class(int err);

/*
 * P-60/D7（DEC-07 过渡方案）：写出的 gate 文件权限契约。
 * 背景：首启 SETUP 向导（root）建出的 gate 恒 0600 root:root，而 admin
 * 归位降权后非 root 的 occ 读不了——出厂首启的多用户控制台实际不可用
 * （admin 停在 D1 的「凭据不可读」报错屏；台架当年靠预种 0640 绕开）。
 * 契约（tui_gate_write_entry / tui_gate_write 写出的文件）：
 *   进程 euid==0 且机器上有 aik-gate 系统组 → 0640 root:aik-gate
 *     （非 root 的 occ 组读面）；
 *   否则 0600（老口径不变；非 root 写恒 0600、不改属主）。
 * 落地方式：tmp 文件建出即 0600（不靠 umask，写入期间他人读不到哈希）；
 * 属主/模式在 tmp 的 fd 上归一（fchown→fchmod）之后才 rename——最终
 * 路径上不存在「已就位但权限未归一」的窗口。fchown/fchmod 失败=写失败
 * （返回 -1，不留半成品）。
 * tui_gate_file_policy - 该契约的纯判定（无 IO，可单测）：
 *   euid==0 且 have_group 非 0 → 返回 1，*mode_out=0640、*gid_out=group_gid；
 *   否则 → 返回 0，*mode_out=0600、*gid_out=(gid_t)-1（不改属主）。
 *   出参可为 NULL。
 */
int tui_gate_file_policy(uid_t euid, int have_group, gid_t group_gid,
			 mode_t *mode_out, gid_t *gid_out);

/*
 * UI 面：进屏登录门。返回 0=解锁（或旁路）；非 0=未解锁退出
 * （occ 退出——外层包装重启后仍在锁定态）：TUI_GATE_LOCKED=未解锁；
 * TUI_GATE_DENIED=凭据文件在却读不出（诚实报错屏、按键后退出）。
 * 只应在双 tty 交互形态调用。
 */
int tui_gate_enter(void);

/*
 * CON-11：门实际认证的用户名（成功时非 NULL；NULL=未解锁/未进过门）。
 * occ 阶段 G（AIK_CONSOLE_GATE_ONLY）把它写进出带外 marker，aik-console
 * 阶段 S 据此决定目标 uid——「认证身份 = 会话身份」的不变量，不让可缺省
 * 的 .last 成为身份来源。每次 tui_gate_enter 入口清零；门只在主 TUI 之前
 * 的单线程里跑，无需加锁。
 */
const char *tui_gate_authed_user(void);

#endif /* OCC_TUI_GATE_H */
