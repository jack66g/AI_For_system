<!-- SPDX-License-Identifier: GPL-2.0 -->
# W48 死代码清理说明（N1）

本目录根下的 `cmd_session.c` 与 `ui_common.c` 已于 W48 删除。原因：

- 它们**从未参与编译**。`Makefile` 的唯一源是：
  - `shell/commands/cmd_session.c`（会话管理命令的正典）
  - `shell/ui_common.c`（颜色/token/会话存储/spinner 公共层）
- 两份根副本与正典已发散（diff 不同），保留会造成"改错文件白改"，
  与 W47B 静态分析 N1、1002 死代码清单的结论一致。
- 全树 grep 无任何 `#include "cmd_session.c"` / `ui_common.c` 引用，
  删除不影响构建与运行。

以后修改会话命令请只改 `shell/commands/cmd_session.c`；修改 UI 公共层
请只改 `shell/ui_common.c`。若再次出现根同名文件，视为同步事故而非
第二份源码，应在构建前删除。
