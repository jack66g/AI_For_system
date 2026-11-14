# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/sched - AI 调度子系统 Makefile（Prompt 03）
#
# 由 AIKernel/Makefile 的 obj-$(CONFIG_AIKERNEL_SCHED) += sched/ 递归进入。
# ai_sched.o       : AI 调度决策框架 + 全部 Hook + 每秒遥测采样器 + cpuhp 回调
# ai_sched_procfs.o: /proc/ai/sched/ 决策统计
#

obj-$(CONFIG_AIKERNEL_SCHED)	+= ai_sched.o
obj-$(CONFIG_AIKERNEL_SCHED)	+= ai_sched_procfs.o
