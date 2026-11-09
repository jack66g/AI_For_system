# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/occ/Makefile - T9a1 occ_llm 双协议层 + SSE + 差分台架驱动
#                       + T9a2 目录/注册表/头通道
#                       + T9a3 occ_core 会话环 + SQLite + headless occ
#
# 独立目标（暂不挂 agent/ai 根 Makefile 的 all——T9e 整合时挂）：
#   make              # occ 主程序 + 单测/驱动二进制（tests/）
#   make test         # 构建并运行单测（a1 五套 + a2 两套 + a3 三套）
#   make p-smoke      # occ -p 冒烟（本地 mock LLM；须先 make）
#   make clean
#
# 只读复用（不改它们，各自编译进本目录对象）：
#   ../cloud/http/http_client.c   HTTPS+SSE 传输（mbedTLS；编译参数照
#                                 desktop/Makefile:24-33 mbedtls-trim 先例）
#   ../store/libaikstore.a        aik_json DOM（链既有 .a，不重建 store/）
#   ../store/libsqlite3.a         SQLite 引擎（T2 amalgamation 编译产物，
#                                 T9a3 occ_core 会话库只读复用）
#   ../memory/sme_client.c        SME REST 客户端（T9d §8——36 路由正典
#                                 C 客户端，复用不重写；配方照 aistreamd/
#                                 tests 的 SME_SRCS 先例）
#   ../local/local_http.c         纯 HTTP/1.1（sme_client 与 ac 绑定同底座）
#   ../runtime/ai_json_util.c     sme_client 的 JSON 转义依赖
#   ../runtime/ai_types.c         AI_OK/AI_ERR_* 错误码表
#
# 构建串行（照 aistreamd/desktop 先例：.NOTPARALLEL）。

.NOTPARALLEL:

CC      ?= cc
CFLAGS  := -Wall -Wextra -Werror -std=c11 -O2 -g -MMD -MP

INCLUDES := -Iocc_llm -Iocc_tools -I. -I.. -I../include -Itests

OBJ_DIR  := obj
REUSE_DIR := $(OBJ_DIR)/reuse

# cloud/http http_client（只读源码 → 本目录对象）
CLOUD_HTTP_SRC := ../cloud/http/http_client.c
HTTP_CLIENT_OBJ := $(REUSE_DIR)/http_client.o
MBEDTLS_DIR := ../third_party/mbedtls
CFLAGS_HTTP := $(CFLAGS) -I.. -I../cloud -I$(MBEDTLS_DIR)/include \
	       -DCONFIG_AI_STREAM_MODE \
	       -DMBEDTLS_CONFIG_FILE='"config/mbedtls-trim.h"'
MBEDTLS_LIBS := \
	$(MBEDTLS_DIR)/library/libmbedtls.a \
	$(MBEDTLS_DIR)/library/libmbedx509.a \
	$(MBEDTLS_DIR)/library/libmbedcrypto.a

STORE_LIB := ../store/libaikstore.a
SQLITE_LIB := ../store/libsqlite3.a
SQLITE_INC := -I../third_party/sqlite3

LDLIBS := -lm -lpthread

# occ_llm 库对象（llm_call.o 依赖 http_client.h，仅在链传输的程序使用）
# retry.c（T9b2）：重试参数族/分级/退避——纯计算，单测 test_retry 直链
LLM_SRCS := occ_llm/occ_sse.c occ_llm/openai.c occ_llm/anthropic.c \
	    occ_llm/provider.c occ_llm/catalog.c occ_llm/registry.c \
	    occ_llm/retry.c
LLM_OBJS := $(LLM_SRCS:%.c=$(OBJ_DIR)/%.o)
LLM_CALL_OBJ := $(OBJ_DIR)/occ_llm/llm_call.o

# occ_core（T9a3+b2）：session/loop/tokens/revert（/undo 三段式）
# T9d：+ occ_sme（§8 记忆注入/写回）+ occ_ac（§9 transcript/轮询/换窗）
#       + occ_telemetry（§9.6 会话遥测 → T8 parquet 链）
# OCC-DEBT：+ replay（TUI 历史回放规划器——纯函数）
CORE_SRCS := occ_core/session.c occ_core/loop.c occ_core/tokens.c \
	     occ_core/revert.c occ_core/occ_sme.c occ_core/occ_ac.c \
	     occ_core/occ_telemetry.c occ_core/replay.c
CORE_OBJS := $(CORE_SRCS:%.c=$(OBJ_DIR)/%.o)

# T9d 绑定复用对象（只读源码 → 本目录对象；显式规则防模式规则歧义）
SME_REUSE_SRCS := ../memory/sme_client.c ../local/local_http.c \
		  ../runtime/ai_json_util.c ../runtime/ai_types.c
SME_REUSE_OBJS := $(REUSE_DIR)/sme_client.o $(REUSE_DIR)/local_http.o \
		  $(REUSE_DIR)/ai_json_util.o $(REUSE_DIR)/ai_types.o

# T8 parquet writer（aistreamd 只读复用：as_parquet + as_snappy，零第三方库）
PQ_REUSE_SRCS := ../aistreamd/as_parquet.c ../aistreamd/as_snappy.c
PQ_REUSE_OBJS := $(REUSE_DIR)/as_parquet.o $(REUSE_DIR)/as_snappy.o

# occ_tools（T9b1）：六件套 + aik-sandbox 对接 + trace 审计
TOOLS_SRCS := occ_tools/tools.c occ_tools/sandbox.c occ_tools/trace.c
TOOLS_OBJS := $(TOOLS_SRCS:%.c=$(OBJ_DIR)/%.o)

# occ_tui（T9c1 原语 + T9c2 视图层 + T9c3 overlay/keymap/theme/usage）：
# 交互入口链入；单测仍走 occ_tui/Makefile
# c3：tui_data（/tools /trace /lease 读取器，链 aik_json——只入 occ 与
#     test_tui_data，不进 occ_tui 库）
TUI_SRCS := occ_tui/tui_utf8.c occ_tui/tui_core.c occ_tui/tui_input.c \
	    occ_tui/tui_frame.c occ_tui/tui_chat.c occ_tui/tui_inputbox.c \
	    occ_tui/tui_sidebar.c occ_tui/tui_view.c occ_tui/tui_theme.c \
	    occ_tui/tui_usage.c occ_tui/tui_keymap.c occ_tui/tui_overlay.c \
	    occ_tui/tui_data.c
TUI_OBJS := $(TUI_SRCS:%.c=$(OBJ_DIR)/%.o)

# 纯协议程序（不含传输）：单测 + 构造/回放驱动
PURE_BINS := tests/test_provider tests/test_openai_build \
	     tests/test_anthropic_build tests/test_sse_openai \
	     tests/test_sse_anthropic tests/occ_reqbuild \
	     tests/occ_ssereplay tests/test_catalog tests/test_registry

# 真传输程序（链 http_client + mbedtls）：occ_smoke（差分台架真调用证据）
# + test_http_headers（本地 mock 断言请求头字节——共享文件增量行为门）
NET_BINS := tests/occ_smoke tests/test_http_headers

# occ_core 单测（T9a3）：session（sqlite）+ tokens（纯计算）
# + loop（fixture 回放全环，链传输因 loop 默认路径引用 occ_llm_call）
# occ_tools 单测（T9b1）：六件套边界 + 快照 + trace + bash 契约（stub）
# b2：test_revert（/undo 三段式+schema 迁移）+ test_retry（重试分级/参数族）
# c2：test_sink（输出 sink 双路对拍——headless FILE 与 TUI sink 逐字节合同）
# c3：test_tui_data（tools.json/trace/lease 读取器夹具对拍——链 aik_json）
# d1：test_sme（§8 注入/写回配额/降级）+ test_ac（§9 transcript/轮询/换窗）
#     + test_telemetry（§9.6 会话遥测落 T8 parquet + footer 读回）
# OCC-DEBT：test_replay（回放规划器——纯规划 + mock db 夹具两相）
CORE_BINS := tests/test_session tests/test_tokens tests/test_loop \
	     tests/test_tools tests/test_revert tests/test_retry \
	     tests/test_sink tests/test_tui_data tests/test_sme \
	     tests/test_ac tests/test_telemetry tests/test_replay

BIN_OCC := occ

NORM_SRC := tests/occ_norm.c

.PHONY: all test p-smoke durable-drill recover-drill interrupt-drill \
	retry-drill b2-drills clean

all: $(BIN_OCC) $(PURE_BINS) $(NET_BINS) $(CORE_BINS)

test: $(PURE_BINS) $(CORE_BINS)
	@for t in tests/test_provider tests/test_openai_build \
		  tests/test_anthropic_build tests/test_sse_openai \
		  tests/test_sse_anthropic tests/test_catalog \
		  tests/test_registry tests/test_session \
		  tests/test_tokens tests/test_loop tests/test_tools \
		  tests/test_revert tests/test_retry tests/test_sink \
		  tests/test_tui_data tests/test_sme tests/test_ac \
		  tests/test_telemetry tests/test_replay; do \
		./$$t || exit 1; \
	done
	@echo "occ unit tests (a1+a2+a3+b1+b2+c2+c3+d1+debt): ALL GREEN"

# occ -p 冒烟（本地 mock LLM 回放 SSE；mock 仅测试，明标）
p-smoke: $(BIN_OCC)
	bash tests/run_p_smoke.sh

# durable 演练（kill -9 流式中途 → 库一致 → --recover 续跑；mock 端点）
durable-drill: $(BIN_OCC)
	bash tests/durable_drill.sh

# ---- T9b2 演练（夹具全在 /tmp/occ-b2-*；mock 端点，无真网） ----
# 恢复对拍：kill 于 LLM 流式中 / 工具执行中 → recover 续跑产物 ==
# 不间断跑产物（recover_drill.sh）
recover-drill: $(BIN_OCC)
	bash tests/recover_drill.sh

# 中断重试：SIGINT 安全点停 → status=interrupted → occ retry 重发
interrupt-drill: $(BIN_OCC)
	bash tests/interrupt_drill.sh

# 自动重试矩阵：第 N 次成功 / 永不成功封顶 / 超时类上限 / 4xx 不重试
retry-drill: $(BIN_OCC)
	bash tests/retry_drill.sh

b2-drills: recover-drill interrupt-drill retry-drill

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# occ_core 对象：额外需要 sqlite3.h（T2 third_party amalgamation 头）
$(OBJ_DIR)/occ_core/%.o: occ_core/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -c -o $@ $<

$(HTTP_CLIENT_OBJ): $(CLOUD_HTTP_SRC)
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS_HTTP) -c $< -o $@

# ---- T9d 绑定复用对象（sme_client/local_http/ai_json_util/ai_types）----
$(REUSE_DIR)/sme_client.o: ../memory/sme_client.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/local_http.o: ../local/local_http.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -I../local -c -o $@ $<

$(REUSE_DIR)/ai_json_util.o: ../runtime/ai_json_util.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/ai_types.o: ../runtime/ai_types.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/as_parquet.o: ../aistreamd/as_parquet.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -I../aistreamd -c -o $@ $<

$(REUSE_DIR)/as_snappy.o: ../aistreamd/as_snappy.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -I../aistreamd -c -o $@ $<

# ---- occ 主程序（T9a3+b1+c2+d1）：headless 一次对话 + 工具环 + 交互 TUI ----
$(BIN_OCC): occ.c $(CORE_OBJS) $(TOOLS_OBJS) $(TUI_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) $(HTTP_CLIENT_OBJ) $(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -Iocc_tui -o $@ occ.c $(CORE_OBJS) \
		$(TOOLS_OBJS) $(TUI_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) $(HTTP_CLIENT_OBJ) \
		$(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB) $(MBEDTLS_LIBS) $(LDLIBS)

# occ_tui 对象：-D_DEFAULT_SOURCE（与各 .c 顶部同值定义共存，照 occ_tui/Makefile）
# +$(INCLUDES)：tui_data.c 需 store/store_json.h（-I../include）
$(OBJ_DIR)/occ_tui/%.o: occ_tui/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -D_DEFAULT_SOURCE -Iocc_tui -c -o $@ $<

# 纯协议链接（无 http_client/mbedtls；aik_json 来自 STORE_LIB）
tests/test_provider: tests/test_provider.c $(LLM_OBJS) $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_provider.c $(LLM_OBJS) $(STORE_LIB) $(LDLIBS)

tests/test_openai_build: tests/test_openai_build.c $(LLM_OBJS) $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_openai_build.c $(LLM_OBJS) $(STORE_LIB) $(LDLIBS)

tests/test_anthropic_build: tests/test_anthropic_build.c $(LLM_OBJS) $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_anthropic_build.c $(LLM_OBJS) $(STORE_LIB) $(LDLIBS)

tests/test_sse_openai: tests/test_sse_openai.c $(OBJ_DIR)/occ_llm/occ_sse.o $(OBJ_DIR)/occ_llm/openai.o $(OBJ_DIR)/occ_llm/anthropic.o $(NORM_SRC) $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_sse_openai.c $(OBJ_DIR)/occ_llm/occ_sse.o $(OBJ_DIR)/occ_llm/openai.o $(OBJ_DIR)/occ_llm/anthropic.o $(NORM_SRC) $(STORE_LIB) $(LDLIBS)

tests/test_sse_anthropic: tests/test_sse_anthropic.c $(OBJ_DIR)/occ_llm/occ_sse.o $(OBJ_DIR)/occ_llm/openai.o $(OBJ_DIR)/occ_llm/anthropic.o $(NORM_SRC) $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_sse_anthropic.c $(OBJ_DIR)/occ_llm/occ_sse.o $(OBJ_DIR)/occ_llm/openai.o $(OBJ_DIR)/occ_llm/anthropic.o $(NORM_SRC) $(STORE_LIB) $(LDLIBS)

tests/occ_reqbuild: tests/occ_reqbuild.c $(LLM_OBJS) $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/occ_reqbuild.c $(LLM_OBJS) $(STORE_LIB) $(LDLIBS)

tests/occ_ssereplay: tests/occ_ssereplay.c $(OBJ_DIR)/occ_llm/occ_sse.o $(OBJ_DIR)/occ_llm/openai.o $(OBJ_DIR)/occ_llm/anthropic.o $(NORM_SRC) $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/occ_ssereplay.c $(OBJ_DIR)/occ_llm/occ_sse.o $(OBJ_DIR)/occ_llm/openai.o $(OBJ_DIR)/occ_llm/anthropic.o $(NORM_SRC) $(STORE_LIB) $(LDLIBS)

# 真传输（cloud/http + mbedtls；occ_llm_call 全链）
tests/occ_smoke: tests/occ_smoke.c $(LLM_OBJS) $(LLM_CALL_OBJ) $(NORM_SRC) $(HTTP_CLIENT_OBJ) $(STORE_LIB) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/occ_smoke.c $(LLM_OBJS) $(LLM_CALL_OBJ) $(NORM_SRC) $(HTTP_CLIENT_OBJ) $(STORE_LIB) $(MBEDTLS_LIBS) $(LDLIBS)

# 头注入行为门（T9a2）：本地 mock 断言 ex/旧通道请求字节（明文 http）
tests/test_http_headers: tests/test_http_headers.c $(HTTP_CLIENT_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_http_headers.c $(HTTP_CLIENT_OBJ) $(MBEDTLS_LIBS) $(LDLIBS)

# 目录/注册表单测（aik_json only）
tests/test_catalog: tests/test_catalog.c $(OBJ_DIR)/occ_llm/catalog.o $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_catalog.c $(OBJ_DIR)/occ_llm/catalog.o $(STORE_LIB) $(LDLIBS)

tests/test_registry: tests/test_registry.c $(LLM_OBJS) $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_registry.c $(LLM_OBJS) $(STORE_LIB) $(LDLIBS)

# ---- occ_core 单测（T9a3） ----

# session：CRUD + 崩溃安全事务 + 回滚注入（sqlite 只读复用 T2 库）
tests/test_session: tests/test_session.c $(OBJ_DIR)/occ_core/session.o $(STORE_LIB) $(SQLITE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -o $@ tests/test_session.c \
		$(OBJ_DIR)/occ_core/session.o $(STORE_LIB) $(SQLITE_LIB) $(LDLIBS)

# tokens：五项账本 + len/4 估算（纯计算，无外部依赖）
tests/test_tokens: tests/test_tokens.c $(OBJ_DIR)/occ_core/tokens.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_tokens.c \
		$(OBJ_DIR)/occ_core/tokens.o $(LDLIBS)

# loop：fixture 回放驱动全环（注入伪传输；链真传输符号因默认路径引用）
# T9d：注入伪传输 = 绑定总闸关闭（occ_bind_active），单测零触网
tests/test_loop: tests/test_loop.c $(CORE_OBJS) $(TOOLS_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) $(HTTP_CLIENT_OBJ) $(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -o $@ tests/test_loop.c \
		$(CORE_OBJS) $(TOOLS_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) \
		$(HTTP_CLIENT_OBJ) $(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB) $(MBEDTLS_LIBS) \
		$(LDLIBS)

# tools（T9b1）：六件套边界 + 快照 + trace + bash 沙箱契约（stub）
tests/test_tools: tests/test_tools.c $(TOOLS_OBJS) $(OBJ_DIR)/occ_core/session.o $(STORE_LIB) $(SQLITE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -o $@ tests/test_tools.c \
		$(TOOLS_OBJS) $(OBJ_DIR)/occ_core/session.o \
		$(STORE_LIB) $(SQLITE_LIB) $(LDLIBS)

# sink（T9c2）：输出 sink 双路对拍（链集合同 test_loop——伪传输驱动全环）
tests/test_sink: tests/test_sink.c $(CORE_OBJS) $(TOOLS_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) $(HTTP_CLIENT_OBJ) $(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -o $@ tests/test_sink.c \
		$(CORE_OBJS) $(TOOLS_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) \
		$(HTTP_CLIENT_OBJ) $(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB) $(MBEDTLS_LIBS) \
		$(LDLIBS)

# ---- T9d 绑定单测（链集合同 test_sink）----
# test_sme：§8 检索注入块/写回配额 20/降级 NOTICE/OCC_SME 开关
# test_ac ：§9 transcript 行流/session-start+check+judge+begin+commit 全链
#           （本地 mock ac HTTP 服务 + 注入 fill，零真网）/换窗四证
tests/test_sme: tests/test_sme.c $(CORE_OBJS) $(TOOLS_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) $(HTTP_CLIENT_OBJ) $(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -o $@ tests/test_sme.c \
		$(CORE_OBJS) $(TOOLS_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) \
		$(HTTP_CLIENT_OBJ) $(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB) $(MBEDTLS_LIBS) \
		$(LDLIBS)

tests/test_ac: tests/test_ac.c $(CORE_OBJS) $(TOOLS_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) $(HTTP_CLIENT_OBJ) $(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -o $@ tests/test_ac.c \
		$(CORE_OBJS) $(TOOLS_OBJS) $(LLM_OBJS) $(LLM_CALL_OBJ) \
		$(HTTP_CLIENT_OBJ) $(SME_REUSE_OBJS) $(PQ_REUSE_OBJS) $(STORE_LIB) $(SQLITE_LIB) $(MBEDTLS_LIBS) \
		$(LDLIBS)

# telemetry（T9d §9.6）：T8 writer 直链（as_parquet+as_snappy，零第三方）
tests/test_telemetry: tests/test_telemetry.c $(OBJ_DIR)/occ_core/occ_telemetry.o $(PQ_REUSE_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_telemetry.c \
		$(OBJ_DIR)/occ_core/occ_telemetry.o $(PQ_REUSE_OBJS) $(LDLIBS)

# revert（T9b2）：/undo 三段式 + schema v1→v2 迁移 + 快照回滚（链
# tools 对象——mangle/快照与执行同口径）
tests/test_revert: tests/test_revert.c $(OBJ_DIR)/occ_core/revert.o \
		   $(TOOLS_OBJS) $(OBJ_DIR)/occ_core/session.o \
		   $(STORE_LIB) $(SQLITE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -o $@ tests/test_revert.c \
		$(OBJ_DIR)/occ_core/revert.o $(TOOLS_OBJS) \
		$(OBJ_DIR)/occ_core/session.o \
		$(STORE_LIB) $(SQLITE_LIB) $(LDLIBS)

# retry（T9b2）：重试分级矩阵 + 参数族（旋钮/env/缺省）+ 退避曲线
# （retry.c 纯计算，无传输依赖）
tests/test_retry: tests/test_retry.c $(OBJ_DIR)/occ_llm/retry.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_retry.c \
		$(OBJ_DIR)/occ_llm/retry.o $(LDLIBS)

# replay（OCC-DEBT）：回放规划器——纯规划 + mock db 夹具（链 session）
tests/test_replay: tests/test_replay.c $(OBJ_DIR)/occ_core/replay.o \
		   $(OBJ_DIR)/occ_core/session.o $(STORE_LIB) $(SQLITE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_INC) -o $@ tests/test_replay.c \
		$(OBJ_DIR)/occ_core/replay.o $(OBJ_DIR)/occ_core/session.o \
		$(STORE_LIB) $(SQLITE_LIB) $(LDLIBS)

# tui_data（T9c3）：tools.json/trace/lease 读取器夹具对拍（aik_json only）
tests/test_tui_data: tests/test_tui_data.c $(OBJ_DIR)/occ_tui/tui_data.o \
		     $(STORE_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -Iocc_tui -o $@ tests/test_tui_data.c \
		$(OBJ_DIR)/occ_tui/tui_data.o $(STORE_LIB) $(LDLIBS)

$(STORE_LIB) $(SQLITE_LIB):
	@echo "缺 $@：请先在 agent/ai/store 构建（本 Makefile 不重建兄弟目录）"; exit 1

clean:
	rm -rf $(OBJ_DIR) $(PURE_BINS) $(NET_BINS) $(CORE_BINS) $(BIN_OCC) tests/*.d

-include $(LLM_OBJS:.o=.d) $(LLM_CALL_OBJ:.o=.d) $(CORE_OBJS:.o=.d) \
	$(TUI_OBJS:.o=.d)
