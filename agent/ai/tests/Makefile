# SPDX-License-Identifier: GPL-2.0
#
# AIKernel agent 回归测试（T2 问题 1：UTF-8 请求体字节安全）
#
# 用法: make -C agent/ai/tests test

CC      ?= gcc
CFLAGS  := -Wall -Wextra -std=c11 -O2 -I../include
RUNTIME := ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c \
	   ../cloud/toolname_map.c
LOCAL   := ../local/local_http.c
MBEDTLS_DIR := ../third_party/mbedtls
MBEDTLS_LIBS := $(MBEDTLS_DIR)/library/libmbedtls.a \
	        $(MBEDTLS_DIR)/library/libmbedx509.a \
	        $(MBEDTLS_DIR)/library/libmbedcrypto.a

TESTS   := test_utf8_body test_http_retry test_cloud_stream test_provider_stream \
	   test_parallel_toolcalls test_toolcall_backfill test_toolname_map \
	   test_sandbox_tools test_plan_mode test_sme_degraded test_export_path \
	   test_memory_api test_trace test_router_activation test_router_cap \
	   test_ask_status_budget test_prompt_policy test_ask_autocompact \
	   test_compact_loop test_ask_repair test_exec_contract test_paste_merge \
	   test_memory_degraded_all test_exec_risk_matrix test_max_rounds \
	   test_sandbox_programming test_compact_20turns test_lease test_lease_gate \
	   test_sysctl_tools \
	   test_desktop_tools test_w77_route test_w77_offline \
	   test_w77_offline_gate test_model_lifecycle \
	   test_onboarding_cloud test_clarify

# W65：Makefile 头依赖回归（shell 脚本，clean 不得删除）
DEPS_TEST := test_make_deps.sh

all: $(TESTS)

test_utf8_body: test_utf8_body.c $(RUNTIME)
	$(CC) $(CFLAGS) -o $@ test_utf8_body.c $(RUNTIME)

# W55 P1: 检索激活集成（cmd_ask 真循环 + mock runtime/executor）
ASK_CORE := ../shell/commands/cmd_ask.c ../shell/commands/ask_context.c \
	    ../shell/commands/ask_compact.c ../shell/commands/ask_clarify.c \
	    ../tools/tool_registry.c ../i18n/lang.c ../runtime/ai_json_util.c \
	    ../runtime/ai_types.c ../runtime/ai_chat_proto.c \
	    ../cloud/toolname_map.c
test_router_activation: test_router_activation.c test_ask_stubs.c test_ask_stubs.h $(ASK_CORE)
	$(CC) $(CFLAGS) -I.. -I../runtime -I../shell/commands -o $@ \
		test_router_activation.c test_ask_stubs.c $(ASK_CORE) -lpthread

# W72: router 激活上限 32（40 个检索命中只扩入 25 个，默认 7 件保留）
test_router_cap: test_router_cap.c test_ask_stubs.c test_ask_stubs.h $(ASK_CORE)
	$(CC) $(CFLAGS) -I.. -I../runtime -I../shell/commands -o $@ \
		test_router_cap.c test_ask_stubs.c $(ASK_CORE) -lpthread

# W72: 最大轮数 12 + 触顶强制最终结论（13 次模型请求）
test_max_rounds: test_max_rounds.c test_ask_stubs.c test_ask_stubs.h $(ASK_CORE)
	$(CC) $(CFLAGS) -I.. -I../runtime -I../shell/commands -o $@ \
		test_max_rounds.c test_ask_stubs.c $(ASK_CORE) -lpthread

# W55 P2: /proc/ai/status 紧凑摘要 + 请求预算口径（W56 T3/T5 扩展）
test_ask_status_budget: test_ask_status_budget.c ../shell/commands/ask_context.c \
		$(RUNTIME) ../i18n/lang.c
	$(CC) $(CFLAGS) -I.. -I../shell/commands -o $@ test_ask_status_budget.c \
		../shell/commands/ask_context.c $(RUNTIME) ../i18n/lang.c

# W56 T1/T4: system prompt 运行时策略段（assume_yes/语言默认/plan 优先）
test_prompt_policy: test_prompt_policy.c ../shell/commands/ask_context.c \
		../i18n/lang.c
	$(CC) $(CFLAGS) -I.. -I../shell/commands -o $@ test_prompt_policy.c \
		../shell/commands/ask_context.c ../i18n/lang.c

# W56 T5: 长历史+大工具输出触发自动 compact，压缩后预算 ≤100%
test_ask_autocompact: test_ask_autocompact.c test_ask_stubs.c test_ask_stubs.h $(ASK_CORE)
	$(CC) $(CFLAGS) -I.. -I../runtime -I../shell/commands -o $@ \
		test_ask_autocompact.c test_ask_stubs.c $(ASK_CORE) -lpthread

# W59: 自动压缩死循环回归（最多 2 次 -> 截断；压缩提示不入历史）
test_compact_loop: test_compact_loop.c test_ask_stubs.c test_ask_stubs.h $(ASK_CORE)
	$(CC) $(CFLAGS) -I.. -I../runtime -I../shell/commands -o $@ \
		test_compact_loop.c test_ask_stubs.c $(ASK_CORE) -lpthread

# W72: 20 轮压缩序列（真实 plan/阈值/冷却常量；无 IO/LLM）
test_compact_20turns: test_compact_20turns.c ../shell/commands/ask_compact.c \
		../shell/commands/ask_context.c ../i18n/lang.c $(RUNTIME)
	$(CC) $(CFLAGS) -I.. -I../shell/commands -o $@ \
		test_compact_20turns.c ../shell/commands/ask_compact.c \
		../shell/commands/ask_context.c ../i18n/lang.c $(RUNTIME)

# 单轮并行多 tool_calls 序列化回归（主控合并态回归：孤儿剔除不得误杀同组）
NATIVE_SRCS := ../local/ollama_native.c ../local/local_chat.c ../local/local_http.c \
	       ../runtime/ai_types.c
test_parallel_toolcalls: test_parallel_toolcalls.c $(RUNTIME) $(NATIVE_SRCS)
	$(CC) $(CFLAGS) -I.. -I../local -o $@ test_parallel_toolcalls.c \
		$(RUNTIME) $(NATIVE_SRCS) -lpthread

# W41 bug1: 多 tool_calls 回填链路（parse→render→池化回填→重建请求）
test_toolcall_backfill: test_toolcall_backfill.c $(RUNTIME)
	$(CC) $(CFLAGS) -o $@ test_toolcall_backfill.c $(RUNTIME)

# W41 bug2: 工具名点号双向映射（往返一致性 + 重名检测）
test_toolname_map: test_toolname_map.c $(RUNTIME)
	$(CC) $(CFLAGS) -o $@ test_toolname_map.c $(RUNTIME)

# W42: sandbox 通道（隔离区+子智能体）——executor/tool_registry 真实现
# + netlink/SME/策略闸门桩（mock 进程级：mock aik-sandbox + mock ai）
SB_EXEC_SRCS := ../tools/executor.c ../tools/tool_registry.c \
	 ../config/config_manager.c \
	 ../shell/commands/model_lifecycle.c \
		 ../policy/ai_lease.c \
		 ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c \
		 ../cloud/toolname_map.c ../trace/ai_trace.c ../local/local_http.c
test_sandbox_tools: test_sandbox_tools.c test_sandbox_stubs.c $(SB_EXEC_SRCS)
	$(CC) $(CFLAGS) -I.. -I../runtime -o $@ test_sandbox_tools.c \
		test_sandbox_stubs.c $(SB_EXEC_SRCS) -lpthread

# W65 P2-01/P2-03/P2-04/P2-05: exec_run 参数契约 / stdin 别名 / 写回读 /
# 能力探测（执行器与注册表真实现，policy/netlink/SME 桩）
test_exec_contract: test_exec_contract.c test_sandbox_stubs.c $(SB_EXEC_SRCS)
	$(CC) $(CFLAGS) -I.. -I../runtime -o $@ test_exec_contract.c \
		test_sandbox_stubs.c $(SB_EXEC_SRCS) -lpthread

# W48: sysctl/sysfs 通道路径与风险回归（含 /proc/net realpath 修复）
test_sysctl_tools: test_sysctl_tools.c test_sandbox_stubs.c $(SB_EXEC_SRCS) \
		../policy/ai_user_policy.c
	$(CC) $(CFLAGS) -DW42_REAL_POLICY -I.. -I../runtime -o $@ \
		test_sysctl_tools.c test_sandbox_stubs.c $(SB_EXEC_SRCS) \
		../policy/ai_user_policy.c -lpthread

# W65 P2-03: 参数错误自动纠正重试一次（cmd_ask 真循环 + mock 模型/执行器）
# W69 round 2: 全 97 命令风险矩阵（R 危险选项/子命令表驱动）
test_exec_risk_matrix: test_exec_risk_matrix.c test_sandbox_stubs.c $(SB_EXEC_SRCS)
	$(CC) $(CFLAGS) -I.. -I../runtime -o $@ test_exec_risk_matrix.c \
		test_sandbox_stubs.c $(SB_EXEC_SRCS) -lpthread

# W72: 沙箱受限表编程冒烟（python3/gcc/cc/which；AIKERNEL_SANDBOX 下）
test_sandbox_programming: test_sandbox_programming.c test_sandbox_stubs.c $(SB_EXEC_SRCS)
	$(CC) $(CFLAGS) -I.. -I../runtime -o $@ test_sandbox_programming.c \
		test_sandbox_stubs.c $(SB_EXEC_SRCS) -lpthread

# W74：租约解析/IO 安全/scope/D0-D4/纯决策（真 policy + 真 trace）
LEASE_SRCS := ../policy/ai_lease.c ../policy/ai_user_policy.c \
	      ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c \
	      ../trace/ai_trace.c
test_lease: test_lease.c $(LEASE_SRCS)
	$(CC) $(CFLAGS) -I.. -I../runtime -o $@ test_lease.c \
		$(LEASE_SRCS) -lpthread

# W74：executor 闸门集成 / -y 短租约 / 显式租约 / 非 TTY pending→approved
test_lease_gate: test_lease_gate.c test_sandbox_stubs.c $(SB_EXEC_SRCS) \
		../policy/ai_user_policy.c
	$(CC) $(CFLAGS) -DW42_REAL_POLICY -I.. -I../runtime -o $@ \
		test_lease_gate.c test_sandbox_stubs.c $(SB_EXEC_SRCS) \
		../policy/ai_user_policy.c -lpthread

# W76：desktop 通道（真 executor/registry/lease/local_http + 本机 mock HTTP）
# 覆盖 20 件工具注册、D0/D1/D2/D3、NONE 确认、-y/显式租约放行、错误结构化
test_desktop_tools: test_desktop_tools.c test_sandbox_stubs.c $(SB_EXEC_SRCS) \
		../policy/ai_user_policy.c
	$(CC) $(CFLAGS) -DW42_REAL_POLICY -I.. -I../runtime -o $@ \
		test_desktop_tools.c test_sandbox_stubs.c $(SB_EXEC_SRCS) \
		../policy/ai_user_policy.c -lpthread

# W77：模型路由（真 config_manager/local_http/trace；ai_runtime_set_model
# 由测试 stub，避免拉入通信层）
W77_ROUTE_CORE := ../runtime/ai_route.c ../config/config_manager.c \
		  ../runtime/ai_types.c ../runtime/ai_json_util.c \
		  ../runtime/ai_chat_proto.c ../cloud/toolname_map.c \
		  ../trace/ai_trace.c
test_w77_route: test_w77_route.c $(W77_ROUTE_CORE) ../local/local_http.c
	$(CC) $(CFLAGS) -I.. -I../runtime -o $@ test_w77_route.c \
		$(W77_ROUTE_CORE) ../local/local_http.c -lpthread

# W77：离线意图层（临时根 /proc/文件/沙箱/租约；SME 不可用降级）
test_w77_offline: test_w77_offline.c ../local/offline_intent.c \
		../memory/sme_client.c $(W77_ROUTE_CORE) ../local/local_http.c
	$(CC) $(CFLAGS) -I.. -I../runtime -I../local -o $@ \
		test_w77_offline.c ../local/offline_intent.c \
		../memory/sme_client.c $(W77_ROUTE_CORE) \
		../local/local_http.c -lpthread

# W77：离线/本地路由不绕过 W74 租约（真 policy）
test_w77_offline_gate: test_w77_offline_gate.c $(LEASE_SRCS)
	$(CC) $(CFLAGS) -I.. -I../runtime -o $@ test_w77_offline_gate.c \
		$(LEASE_SRCS) -lpthread

test_ask_repair: test_ask_repair.c test_ask_stubs.c test_ask_stubs.h $(ASK_CORE)
	$(CC) $(CFLAGS) -I.. -I../runtime -I../shell/commands -o $@ \
		test_ask_repair.c test_ask_stubs.c $(ASK_CORE) -lpthread

# W65 P3-03: NoTTY/TERM=dumb bracketed paste 标记剥离与连续行合并
test_paste_merge: test_paste_merge.c ../shell/repl_paste.c ../shell/repl_paste.h
	$(CC) $(CFLAGS) -I../shell -o $@ test_paste_merge.c ../shell/repl_paste.c

# W42 演示（手动跑，不在 test 循环）：主进程经真执行器+真策略闸门
# spawn 子智能体全链路（aik-sandbox/ai/引擎全真，W2 用 assume-yes 预授权）
#   sudo ./demo_sandbox_chain ../tools/tools.json demo1 "任务文本"
DEMO_SRCS := $(SB_EXEC_SRCS) ../policy/ai_user_policy.c
demo_sandbox_chain: demo_sandbox_chain.c test_sandbox_stubs.c $(DEMO_SRCS)
	$(CC) $(CFLAGS) -DW42_REAL_POLICY -I.. -I../runtime -o $@ \
		demo_sandbox_chain.c test_sandbox_stubs.c $(DEMO_SRCS) -lpthread

test_http_retry: test_http_retry.c $(LOCAL) ../runtime/ai_types.c
	$(CC) $(CFLAGS) -I../local -o $@ test_http_retry.c $(LOCAL) ../runtime/ai_types.c

# 云通道真增量流式（审计 A1）：provider 层 openai_stream 直调 +
# 内嵌 SSE/chunked 假服务端；真实端点模式 ./test_cloud_stream <url> <model>
STREAM_SRCS := ../cloud/provider_openai_compatible.c \
	../cloud/http/http_client.c \
	../runtime/communication/stream_parse.c \
	$(RUNTIME)
test_cloud_stream: test_cloud_stream.c $(STREAM_SRCS)
	$(CC) $(CFLAGS) -DCONFIG_AI_STREAM_MODE -I.. -I../cloud -I../runtime -DMBEDTLS_CONFIG_FILE=\"config/mbedtls-trim.h\" \
		-I$(MBEDTLS_DIR)/include -o $@ test_cloud_stream.c \
		$(STREAM_SRCS) $(MBEDTLS_LIBS) -lpthread

# provider 层 local ops.stream 真实现（审计 B1）：直调 local provider
# 工厂 + ops.stream，内嵌 SSE 假服务端
LOCAL_STREAM_SRCS := ../local/provider_local.c \
	../local/local_chat.c \
	../local/local_stream.c \
	../local/local_http.c \
	../local/ollama_native.c \
	../runtime/communication/stream_parse.c \
	$(RUNTIME)
test_provider_stream: test_provider_stream.c $(LOCAL_STREAM_SRCS)
	$(CC) $(CFLAGS) -DCONFIG_AI_STREAM_MODE -I.. -I../local -I../runtime \
		-o $@ test_provider_stream.c $(LOCAL_STREAM_SRCS)

# W43: plan 只读模式（真执行器+真策略+真 i18n；SME/netlink 桩，sandbox mock）
test_plan_mode: test_plan_mode.c test_sandbox_stubs.c $(SB_EXEC_SRCS) \
		../policy/ai_user_policy.c
	$(CC) $(CFLAGS) -DW42_REAL_POLICY -I.. -I../runtime -o $@ \
		test_plan_mode.c test_sandbox_stubs.c $(SB_EXEC_SRCS) \
		../policy/ai_user_policy.c -lpthread

# W43: SME 失忆降级（真 sme_client；无服务环境快速失败语义+原因码）
SME_SRCS := ../memory/sme_client.c ../local/local_http.c \
	    ../runtime/ai_json_util.c ../runtime/ai_types.c
test_sme_degraded: test_sme_degraded.c $(SME_SRCS)
	$(CC) $(CFLAGS) -I.. -I../local -o $@ test_sme_degraded.c \
		$(SME_SRCS) -lpthread

# W43: memory_export 路径白名单（安全 finding 修复回归）
test_export_path: test_export_path.c $(SME_SRCS)
	$(CC) $(CFLAGS) -I.. -I../local -o $@ test_export_path.c \
		$(SME_SRCS) -lpthread

# W50: SME 完整记忆管理面（mock HTTP：方法/路径/编码/降级/risk）
test_memory_api: test_memory_api.c $(SME_SRCS) ../tools/tool_registry.c \
		../i18n/lang.c ../cloud/toolname_map.c
	$(CC) $(CFLAGS) -I.. -I../local -o $@ test_memory_api.c \
		$(SME_SRCS) ../tools/tool_registry.c ../i18n/lang.c \
		../cloud/toolname_map.c -lpthread

# W66：30 件 memory_* 全量降级 + 超时/HTTP500/路径白名单/Unicode/长文本
# （executor/tool_registry/sme_client/local_http 全真；netlink/policy 桩）
MEM_ALL_SRCS := ../tools/executor.c ../tools/tool_registry.c \
	 ../config/config_manager.c \
	 ../shell/commands/model_lifecycle.c \
		../policy/ai_lease.c \
		../i18n/lang.c ../runtime/ai_json_util.c \
		../runtime/ai_types.c ../cloud/toolname_map.c \
		../trace/ai_trace.c ../memory/sme_client.c \
		../local/local_http.c
test_memory_degraded_all: test_memory_degraded_all.c test_memory_stubs.c \
		$(MEM_ALL_SRCS)
	$(CC) $(CFLAGS) -I.. -I../runtime -I../local -o $@ \
		test_memory_degraded_all.c test_memory_stubs.c \
		$(MEM_ALL_SRCS) -lpthread

# W48B: 全轨迹日志（JSONL/脱敏/截断/轮转/并发/降级）
test_trace: test_trace.c ../trace/ai_trace.c $(RUNTIME)
	$(CC) $(CFLAGS) -I.. -o $@ test_trace.c ../trace/ai_trace.c \
		$(RUNTIME) -lpthread

# W77c：结构化澄清（解析/校验/多选/非 TTY JSON/检测器/无租约/轨迹）
CLARIFY_SRCS := ../shell/commands/ask_clarify.c ../trace/ai_trace.c \
		../policy/ai_lease.c ../policy/ai_user_policy.c \
		../i18n/lang.c ../runtime/ai_types.c $(RUNTIME)
test_clarify: test_clarify.c $(CLARIFY_SRCS)
	$(CC) $(CFLAGS) -I.. -I../shell/commands -o $@ test_clarify.c \
		$(CLARIFY_SRCS) -lpthread

# W77d：本地模型生命周期（真引擎+真 config+mock ollama HTTP）
ML_SRCS := ../shell/commands/model_lifecycle.c ../config/config_manager.c \
	   ../runtime/ai_json_util.c ../runtime/ai_types.c \
	   ../cloud/toolname_map.c ../local/local_http.c
test_model_lifecycle: test_model_lifecycle.c $(ML_SRCS)
	$(CC) $(CFLAGS) -I.. -o $@ test_model_lifecycle.c $(ML_SRCS) -lpthread

# W77d：云端优先 onboarding（cmd_onboarding 真实现 + mock stdin + mock 云）
OB_SRCS := ../shell/commands/cmd_onboarding.c $(ML_SRCS) \
	   ../i18n/lang.c ../runtime/ai_chat_proto.c
test_onboarding_cloud: test_onboarding_cloud.c $(OB_SRCS)
	$(CC) $(CFLAGS) -I.. -I../runtime -I../shell/commands -o $@ \
		test_onboarding_cloud.c $(OB_SRCS) -lpthread

test: all
	@for t in $(TESTS); do ./$$t || exit 1; done
	@./$(DEPS_TEST)

# W77c: real ai binary + mock OpenAI, non-TTY CLARIFY_REQUIRED + PTY menu
test-e2e: all
	cd .. && python3 tests/test_clarify_e2e.py --agent-dir .

clean:
	rm -f $(TESTS)

.PHONY: all test test-e2e clean
