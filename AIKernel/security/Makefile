# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/security - AI 安全子系统
#
# AI 安全大脑（Prompt 07）：
#   - ai_lsm.o：AI LSM 模块（行为建模 + 异常检测）+ ai_sec_* Hook（LSM 主体）
#   - ai_lsm_telemetry.o：第8类安全事件发射辅助（自 ai_lsm.c 拆分）
#   - ai_audit.o：AI 安全审计模块（审计关联 + 攻击链）
# 全部门控 CONFIG_AIKERNEL_SECURITY（default n）；AI 关闭时不构建 → 零回归。
obj-$(CONFIG_AIKERNEL_SECURITY) += ai_lsm.o ai_lsm_telemetry.o ai_audit.o
