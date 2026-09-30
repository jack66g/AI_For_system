# SPDX-License-Identifier: GPL-2.0
#
# AIKernel 内存管理子系统（Prompt 04）
#
# ai_mm.o:                  A 轨 Hook + 决策框架 + init（门控 CONFIG_AIKERNEL_MM）
# ai_mm_telemetry_alloc.o:  B 轨第2类分配/缺页发射辅助（自 ai_mm.c 拆分）
# ai_mm_telemetry_reclaim.o: B 轨第2类回收/THP/OOM/错误发射辅助（自 ai_mm.c 拆分）
# ai_zone.o: AI 专用内存区预留骨架（可选，门控 CONFIG_AIKERNEL_AI_ZONE）

obj-$(CONFIG_AIKERNEL_MM)	+= ai_mm.o
obj-$(CONFIG_AIKERNEL_MM)	+= ai_mm_telemetry_alloc.o
obj-$(CONFIG_AIKERNEL_MM)	+= ai_mm_telemetry_reclaim.o
obj-$(CONFIG_AIKERNEL_AI_ZONE)	+= ai_zone.o
