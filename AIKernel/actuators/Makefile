# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/actuators - 参数表/事务/回滚/配额（K10.1 自 core 迁入）
#   ai_control.o      : 参数表（RUNTIME）
#   ai_policy_safety.o: 快照/回滚（RUNTIME）
#   ai_agent.o        : agent 配额（RUNTIME；!RUNTIME 时 ai_agent.h 桩）
#   ai_cgroup.o       : 配额 cgroup 面（CGROUP）

obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_control.o
obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_policy_safety.o
obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_agent.o
obj-$(CONFIG_AIKERNEL_CGROUP)	+= ai_cgroup.o
