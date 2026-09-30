# SPDX-License-Identifier: GPL-2.0
#
# AIKernel - AI 内核融合重构子系统 Makefile
#
# 内核构建入口（由顶层 Makefile 的 core-y += AIKernel/ 引入）。
# 逐级递归：本层列出子目录，子目录 Makefile 列出本目录目标。
# 所有目标均受 CONFIG 门控，默认全部关闭 → 零 .o 产物，零回归。
#

# 总开关开启时进入 core/，core/Makefile 内部按模块开关逐目标门控
# （RUNTIME/TELEMETRY/INTERFACE/CGROUP 可独立开启）。
obj-$(CONFIG_AIKERNEL)		+= core/

# 网络子系统：Prompt 02 起 NETLINK_AI 协议族落地（net/）；Prompt 06 起 AI 网络核心
# + AI CCA + 第4类网络感知（net/，CONFIG_AIKERNEL_NET）
obj-$(CONFIG_AIKERNEL_NETLINK)	+= net/
obj-$(CONFIG_AIKERNEL_NET)	+= net/

# 调度子系统：Prompt 03 起 AI 调度 Hook + 调度感知落地（sched/）
obj-$(CONFIG_AIKERNEL_SCHED)	+= sched/

# 内存管理子系统：Prompt 04 起 AI 内存 Hook + 内存感知落地（mm/）
obj-$(CONFIG_AIKERNEL_MM)	+= mm/

# I/O 子系统：Prompt 05 起 AI 块层/字符设备 Hook + AI 调度器 + 第3类感知（io/）
obj-$(CONFIG_AIKERNEL_IO)	+= io/

# 安全子系统：Prompt 07 起 AI LSM + AI 审计 + 第8类安全感知（security/）
obj-$(CONFIG_AIKERNEL_SECURITY)	+= security/

# VFS 子系统：Prompt 08 起 AI VFS Hook + 缓存/回写/epoll 决策 + 第7类感知（vfs/）
obj-$(CONFIG_AIKERNEL_VFS)	+= vfs/

# 中断/锁/时间子系统：Prompt 09 起 AI 中断管理/同步锁/时间管理 Hook
# + 第9/10/11类感知（interrupt/、lock/、time/）
obj-$(CONFIG_AIKERNEL_INTERRUPT)	+= interrupt/
obj-$(CONFIG_AIKERNEL_LOCK)		+= lock/
obj-$(CONFIG_AIKERNEL_TIME)		+= time/

# 电源/虚拟化子系统：Prompt 10 起 AI 电源管理 Hook + aiguard governor
# + 第12类感知（power/）；AI 虚拟化 Hook + VirtIO AI 设备 + 第13类感知（virt/）
obj-$(CONFIG_AIKERNEL_POWER)	+= power/
obj-$(CONFIG_AIKERNEL_VIRT)	+= virt/

# BPF 子系统：Prompt 11 起 AI + BPF/Tracing 协同（BPF helper/AI_MODEL map/
# AI 观察 Hook）+ 第14类感知（bpf/）
obj-$(CONFIG_AIKERNEL_BPF)	+= bpf/

# KUnit 测试套件：Prompt 15 起（模块15.6，AIKernel/test/）
obj-$(CONFIG_AIKERNEL_KUNIT_TEST)	+= test/
