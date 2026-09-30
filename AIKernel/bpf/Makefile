# SPDX-License-Identifier: GPL-2.0
#
# AIKernel - AI BPF 集成子系统 Makefile（Prompt 11，重构计划 模块13）
#
# ai_bpf.o：AI BPF 协同核心（Hook 空实现 + BPF helper 核心 + 第14类发射辅助）
# ai_map.o：BPF_MAP_TYPE_AI_MODEL map 实现
#
# 门控 CONFIG_AIKERNEL_BPF（depends on AIKERNEL && BPF && BPF_SYSCALL）：
# 关闭时不构建任何目标，kernel/ 侧调用点 #ifdef 剔除 → 零回归由构造保证。

obj-$(CONFIG_AIKERNEL_BPF) += ai_bpf.o ai_map.o
