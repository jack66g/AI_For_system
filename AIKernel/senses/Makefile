# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/senses - 感知与出口面（K10.1：proc 感知族+procfs/sysfs/
# netlink/ebpf 特征出口，自 core|net|bpf 迁入；门控与原位同源）
#   ai_proc*.o        : 进程感知族（AIKERNEL，A/B 轨条件编译）
#   ai_sysfs*.o/ai_procfs.o : /sys /proc 出口（USRIFACE）
#   ai_netlink.o      : NETLINK_AI 协议族（NETLINK）
#   ai_features.o     : BPF_MAP_TYPE_AI_FEATURES 出口（BPF）

obj-$(CONFIG_AIKERNEL)		+= ai_proc.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_input.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_syscall.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_telemetry.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_user.o
obj-$(CONFIG_AIKERNEL)		+= ai_proc_sampler.o
obj-$(CONFIG_AIKERNEL_USRIFACE) += ai_sysfs.o
obj-$(CONFIG_AIKERNEL_USRIFACE) += ai_sysfs_stats.o
obj-$(CONFIG_AIKERNEL_USRIFACE) += ai_procfs.o
obj-$(CONFIG_AIKERNEL_NETLINK)	+= ai_netlink.o
obj-$(CONFIG_AIKERNEL_BPF)	+= ai_features.o
