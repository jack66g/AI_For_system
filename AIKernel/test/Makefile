# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/test/Makefile - AIKernel KUnit 测试套件（A 轨 模块15.6）
#
# 门控：CONFIG_AIKERNEL_KUNIT_TEST（depends on AIKERNEL && KUNIT）。
# CONFIG_AIKERNEL=n 时该开关不可选 → 本目录零产物（测试编译为无操作）；
# 每个测试文件内部再对子模块开关（RUNTIME/TELEMETRY）做兜底，
# 保证部分配置下编译为空套件。

obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_runtime_test.o
# K6：AIKWMDL MLP 模型面（解析/量化数值/推理数值/边界/预算超时/percpu
# scratch/统计 hash；文件内部按 CONFIG_AIKERNEL_RUNTIME 兜底）
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_mlp_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_telemetry_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_policy_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_control_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_decision_test.o
# K4.0：效果归因环（开窗/绑定/结算回填/超时/统计/ENOENT；RUNTIME 兜底）
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_effect_test.o
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_causal_test.o
# W63：NETLINK_AI 订阅生命周期（文件内部按 CONFIG_AIKERNEL_NETLINK 兜底）
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_netlink_test.o
# K3：agent 角色注册表/配额准入（文件内部按 CONFIG_AIKERNEL_RUNTIME 兜底）
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_agent_test.o
# K5：空钩治理后 13 保留钩（11 真实/观测 + 2 sec 门控真体）——分类/
# 异常/强度启发式与指标出口断言（文件内部按 RUNTIME/MM/LOCK/BPF/NET/
# TELEMETRY/USRIFACE/EXPERIMENTAL×SECURITY 逐段兜底）
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_hooks_test.o
# K8：审计链（完整性/篡改定位/驱逐/锚/seed/并发/三层开销/事件对；
# 文件内部按 CONFIG_AIKERNEL_SECURITY 兜底，SECURITY=n 空套件）
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_chain_test.o
# K9：性能预算套（四微基准机读 PERF 行；k9_perf.py+budgets.json 同目录 perf/）
obj-$(CONFIG_AIKERNEL_KUNIT_TEST) += ai_perf_test.o
