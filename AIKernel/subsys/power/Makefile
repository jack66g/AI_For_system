# SPDX-License-Identifier: GPL-2.0
#
# AIKernel 电源管理子系统（Prompt 10，重构计划 模块11）
# 全部目标受 CONFIG_AIKERNEL_POWER 门控，默认关闭 → 零 .o 产物，零回归。
# ai_cpufreq.o 内部 #ifdef CONFIG_CPU_FREQ（CPU_FREQ=n 时编译为空文件）。

obj-$(CONFIG_AIKERNEL_POWER)	+= ai_power.o
obj-$(CONFIG_AIKERNEL_POWER)	+= ai_cpufreq.o
