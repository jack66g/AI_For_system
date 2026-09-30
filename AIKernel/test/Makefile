# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/test/Makefile - AIKernel KUnit 测试套件（A 轨 模块15.6）
#
# 门控：CONFIG_AIKERNEL_KUNIT_TEST（depends on AIKERNEL && KUNIT）。
# CONFIG_AIKERNEL=n 时该开关不可选 → 本目录零产物（测试编译为无操作）；
# 每个测试文件内部再对子模块开关（RUNTIME/TELEMETRY）做兜底，
# 保证部分配置下编译为空套件。

obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_runtime_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_telemetry_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_policy_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_control_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_decision_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_causal_test.o
