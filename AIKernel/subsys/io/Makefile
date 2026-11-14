# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/io - AI I/O 子系统（Prompt 05）
#
# ai_block.o: 块层 Hook 空实现 + 决策框架 + 第3类 6 子类发射辅助 + 每秒磁盘采样器
# ai_bfq.o:   AI I/O 调度器类（elv_register("ai")，简化 deadline 语义族）
# ai_char.o:  字符设备核心（熵源/TTY Hook + char_dev 事件发射辅助）
#
# 全部门控 CONFIG_AIKERNEL_IO（default n）：关闭时不参与构建 → 零回归。

obj-$(CONFIG_AIKERNEL_IO)	+= ai_block.o
obj-$(CONFIG_AIKERNEL_IO)	+= ai_bfq.o
obj-$(CONFIG_AIKERNEL_IO)	+= ai_char.o
