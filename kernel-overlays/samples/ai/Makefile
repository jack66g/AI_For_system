# SPDX-License-Identifier: GPL-2.0
#
# samples/ai/Makefile - AIKernel AI 示例
#
# 两个示例（模块）：
#   ai_sched_policy_sample   AI 调度器策略注册示例（决策闭环模板）
#   ai_bpf_helper_sample     BPF AI helper 调用示例
# K5（2026-11）：ai_io_scheduler_sample（引用已删除的 io 域分发咨询
# 空桩钩）已连带删除，见 AIKernel/CHANGELOG.md。
#
# 构建单个示例（内核树根）：
#   make CONFIG_SAMPLE_AI_SCHED_POLICY=m samples/ai/ai_sched_policy_sample.ko

obj-$(CONFIG_SAMPLE_AI_SCHED_POLICY) += ai_sched_policy_sample.o
obj-$(CONFIG_SAMPLE_AI_BPF_HELPER)   += ai_bpf_helper_sample.o
