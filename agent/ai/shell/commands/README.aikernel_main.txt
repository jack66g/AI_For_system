# SPDX-License-Identifier: GPL-2.0
#
# W46a (2026-10-10) 遗留副本清理说明：
# 本目录曾存有 shell/aikernel_main.c 的遗留副本，已于 W46a 删除
# （删除前 diff 确认与 shell/ 版逐字节一致，全树 grep 零引用）。
# REPL 主入口唯一源：shell/aikernel_main.c（ai 与 aikernel-shell 复用）。
# 切勿在本目录再生成 aikernel_main.c——改 REPL 入口只改 shell/ 那一份
# （Makefile 的 SHELL_SRCS 只链接 shell/aikernel_main.c）。
