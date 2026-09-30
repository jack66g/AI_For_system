# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/core - AI Runtime 核心 Makefile
#
# AIKernel/core/ 由 AIKernel/Makefile 的 obj-$(CONFIG_AIKERNEL) += core/
# 递归进入。各目标受独立 CONFIG 门控：
#   ai_runtime.o / ai_policy.o / ai_startup.o : CONFIG_AIKERNEL_RUNTIME
#   ai_telemetry.o                            : CONFIG_AIKERNEL_TELEMETRY
#   ai_sysfs.o / ai_procfs.o                  : CONFIG_AIKERNEL_USRIFACE
#   ai_cgroup.o                               : CONFIG_AIKERNEL_CGROUP
#

obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_runtime.o
obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_policy.o
obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_policy_safety.o
obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_control.o
# ai_decision.o（W3 决策注入查询层）：决策源接口 + 三层开关 + 钳制 + 记账，
# RUNTIME 门控与 ai_control 同源（ACT 参数注册依赖 ai_control 表）。
obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_decision.o
obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_causal.o
obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_startup.o
obj-$(CONFIG_AIKERNEL_RUNTIME)	+= ai_model_mlp.o
# ai_proc*.o：A 轨（RUNTIME）与 B 轨（TELEMETRY）代码按各自 CONFIG 条件编译，
# 总开关 AIKERNEL 下构建（仅开 RUNTIME 或仅开 TELEMETRY 均可正常编译）。
# 原 ai_proc.c（1907 行）按职责拆分为六个实现文件 + 一个内部头：
#   ai_proc.c          A 轨：分类槽表 + Hook + query/stats
#   ai_proc_input.c    B 轨：第5类用户输入（tty/键鼠/触摸/焦点）
#   ai_proc_syscall.c  B 轨：syscall 采样遥测 + 15.03 模式发射
#   ai_proc_telemetry.c B 轨：05.05 exec 命令行 + 第6类进程/信号/凭证/cgroup/futex
#   ai_proc_user.c     B 轨：第15类用户行为（会话/应用/GPU）
#   ai_proc_sampler.c  B 轨：1s 周期采样器 + ai_proc_init
obj-$(CONFIG_AIKERNEL)		+= ai_proc.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_input.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_syscall.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_telemetry.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_user.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_sampler.o
obj-$(CONFIG_AIKERNEL_TELEMETRY) += ai_telemetry.o
# ai_sysfs.o + ai_sysfs_stats.o：/sys/kernel/ai/ 控制节点与只读统计视图
# （stats/ 自 ai_sysfs.c 拆分，两文件同一 USRIFACE 门控）
obj-$(CONFIG_AIKERNEL_USRIFACE) += ai_sysfs.o
obj-$(CONFIG_AIKERNEL_USRIFACE) += ai_sysfs_stats.o
obj-$(CONFIG_AIKERNEL_USRIFACE) += ai_procfs.o
obj-$(CONFIG_AIKERNEL_CGROUP)	+= ai_cgroup.o
