# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/vfs - AI VFS 子系统（Prompt 08）
#
# ai_vfs.o:            AI VFS 核心：Hook 空实现 + 决策框架 + 采样率表
# ai_vfs_telemetry.o:  第7类文件/目录/路径操作发射辅助（自 ai_vfs.c 拆分）
# ai_vfs_telemetry_fs.o: 第7类挂载/文件锁/poll/错误发射辅助（自 ai_vfs.c 拆分）
# ai_vfs_procfs.o:     /proc/ai/vfs/ 决策统计（stats/rates）
#
# 全部门控 CONFIG_AIKERNEL_VFS（default n）：关闭时不参与构建 → 零回归。

obj-$(CONFIG_AIKERNEL_VFS)	+= ai_vfs.o
obj-$(CONFIG_AIKERNEL_VFS)	+= ai_vfs_telemetry.o
obj-$(CONFIG_AIKERNEL_VFS)	+= ai_vfs_telemetry_fs.o
obj-$(CONFIG_AIKERNEL_VFS)	+= ai_vfs_procfs.o
