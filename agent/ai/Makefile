# AIKernel - AI Subsystem Makefile
#
# 构建 AI Shell 二进制文件 'ai' 和 'aikernel-shell'。
# Phase 4: 通信层重构 - 集成 Communication Layer + TLS Manager + Certificate Manager
#
# 用法:
#   make              # 构建 ai
#   make all          # 构建 ai + aikernel-shell
#   make clean        # 清理

CC      ?= gcc
CFLAGS  := -Wall -Wextra -std=c11 -O2 -g -static
LDFLAGS :=

# 目录
SRC_DIR        := .
SHELL_DIR      := shell
CMD_DIR        := shell/commands
RUNTIME_DIR    := runtime
COMM_DIR       := runtime/communication
BACKEND_DIR    := runtime/communication/backend
PROVIDER_DIR   := provider
CLOUD_DIR      := cloud
HTTP_DIR       := cloud/http
TLS_DIR        := cloud/tls
LOCAL_DIR      := local
MEMORY_DIR     := memory
TOOLS_DIR      := tools
CONFIG_DIR     := config
CERTS_DIR      := config/certs
INCLUDE_DIR    := include
BUILD_DIR      := build
MBEDTLS_DIR    := third_party/mbedtls

# ============================================================================
# Kconfig 三开关接线（A4：配置面与构建事实一致化）
#   CONFIG_AIKERNEL_CLOUD_PROVIDER → cloud provider/backend/http_client/tls
#   CONFIG_AIKERNEL_LOCAL_PROVIDER → local provider/backend/chat/native
#   CONFIG_AIKERNEL_STREAM_MODE    → 流式（local_stream + stream_parse +
#                                    云通道 SSE 增量分支；关闭时 stream 恒 off）
# 开关取值优先级：
#   1. make/环境变量 AIKERNEL_CLOUD_PROVIDER=y|n 等（显式覆盖）
#   2. 内核 .config（AIKERNEL_DOTCONFIG，默认内核树根 ../../.config）
#   3. .config 缺失 → 默认全开（发行默认全功能）
# 验证：关掉某开关重编后对应符号从二进制消失（nm 查证）。
# ============================================================================
AIKERNEL_DOTCONFIG ?= ../../.config

kc_config_flag = $(shell grep -qs "^CONFIG_$(1)=y" $(AIKERNEL_DOTCONFIG) \
		 && echo y || echo n)

ifeq ($(origin AIKERNEL_CLOUD_PROVIDER),undefined)
KC_CLOUD := $(call kc_config_flag,AIKERNEL_CLOUD_PROVIDER)
else
KC_CLOUD := $(AIKERNEL_CLOUD_PROVIDER)
endif
ifeq ($(origin AIKERNEL_LOCAL_PROVIDER),undefined)
KC_LOCAL := $(call kc_config_flag,AIKERNEL_LOCAL_PROVIDER)
else
KC_LOCAL := $(AIKERNEL_LOCAL_PROVIDER)
endif
ifeq ($(origin AIKERNEL_STREAM_MODE),undefined)
KC_STREAM := $(call kc_config_flag,AIKERNEL_STREAM_MODE)
else
KC_STREAM := $(AIKERNEL_STREAM_MODE)
endif

KC_CFLAGS :=
KC_SRCS   :=

ifeq ($(KC_CLOUD),y)
KC_CFLAGS += -DCONFIG_AI_CLOUD_PROVIDER
KC_SRCS += $(CLOUD_DIR)/provider_openai_compatible.c \
	   $(BACKEND_DIR)/cloud_backend.c \
	   $(HTTP_DIR)/http_client.c \
	   $(TLS_DIR)/tls_manager.c
endif

ifeq ($(KC_LOCAL),y)
KC_CFLAGS += -DCONFIG_AI_LOCAL_PROVIDER
KC_SRCS += $(LOCAL_DIR)/provider_local.c \
	   $(LOCAL_DIR)/local_chat.c \
	   $(LOCAL_DIR)/ollama_native.c \
	   $(BACKEND_DIR)/local_backend.c
ifeq ($(KC_STREAM),y)
# 本地流式实现依赖 local_chat/ollama_native 辅助（LOCAL 开关内文件）
KC_SRCS += $(LOCAL_DIR)/local_stream.c
endif
endif

ifeq ($(KC_STREAM),y)
KC_CFLAGS += -DCONFIG_AI_STREAM_MODE
KC_SRCS += $(COMM_DIR)/stream_parse.c
endif

CFLAGS += $(KC_CFLAGS)

# 目标
TARGET_AI     := ai
TARGET_SHELL  := aikernel-shell

# 公共源文件（provider/backend/http/tls/stream 按上方 Kconfig 开关条件编入）
COMMON_SRCS := \
	$(SHELL_DIR)/shell.c \
	$(CMD_DIR)/commands_registry.c \
	$(CMD_DIR)/cmd_help.c \
	$(CMD_DIR)/cmd_exit.c \
	$(CMD_DIR)/cmd_status.c \
	$(CMD_DIR)/cmd_config.c \
	$(CMD_DIR)/cmd_chat.c \
	$(CMD_DIR)/cmd_ask.c \
	$(CMD_DIR)/cmd_model.c \
	$(CMD_DIR)/cmd_network.c \
	$(CMD_DIR)/cmd_netlink.c \
	$(CMD_DIR)/cmd_onboarding.c \
	$(CMD_DIR)/cmd_shell.c \
	$(RUNTIME_DIR)/ai_types.c \
	$(RUNTIME_DIR)/ai_json_util.c \
	$(RUNTIME_DIR)/ai_chat_proto.c \
	$(RUNTIME_DIR)/runtime.c \
	$(RUNTIME_DIR)/netlink/ai_netlink_client.c \
	$(COMM_DIR)/communication.c \
	$(BACKEND_DIR)/backend.c \
	$(PROVIDER_DIR)/provider_core.c \
	$(MEMORY_DIR)/sme_client.c \
	$(TOOLS_DIR)/tool_registry.c \
	$(TOOLS_DIR)/executor.c \
	$(CONFIG_DIR)/config_manager.c \
	$(CERTS_DIR)/cert_manager.c \
	$(LOCAL_DIR)/local_http.c \
	$(KC_SRCS)
# 注：local_http.c 无条件编入——它是轻量 HTTP 传输工具层，被
# memory/sme_client.c（SME 记忆服务客户端）依赖，不属于本地 provider 功能。

AI_SRCS    := $(SHELL_DIR)/main.c $(COMMON_SRCS)
SHELL_SRCS := $(SHELL_DIR)/aikernel_main.c $(COMMON_SRCS)

AI_OBJS    := $(AI_SRCS:%.c=$(BUILD_DIR)/%.o)
SHELL_OBJS := $(SHELL_SRCS:%.c=$(BUILD_DIR)/%.o)

# mbedTLS 静态库
MBEDTLS_LIBS := \
	$(MBEDTLS_DIR)/library/libmbedtls.a \
	$(MBEDTLS_DIR)/library/libmbedx509.a \
	$(MBEDTLS_DIR)/library/libmbedcrypto.a

# 头文件路径
# -I$(SRC_DIR)：允许 backend 等跨目录包含内部头（如 local/local_chat.h）
INCLUDES := -I$(INCLUDE_DIR) \
	    -I$(SRC_DIR) \
	    -I$(CLOUD_DIR) \
	    -I$(RUNTIME_DIR) \
	    -I$(MBEDTLS_DIR)/include

# 颜色
GREEN  := \033[0;32m
YELLOW := \033[0;33m
NC     := \033[0m

.PHONY: all clean install help mbedtls

all: mbedtls $(TARGET_AI) $(TARGET_SHELL)

mbedtls:
	@if [ ! -f $(MBEDTLS_DIR)/library/libmbedtls.a ]; then \
		echo "$(YELLOW)[MBEDTLS]$(NC) Building mbedTLS..."; \
		$(MAKE) -C $(MBEDTLS_DIR)/library -j$$(nproc) 2>&1 | tail -1; \
	fi

$(TARGET_AI): $(AI_OBJS) $(MBEDTLS_LIBS)
	@echo "$(GREEN)[LINK]$(NC) $@"
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lpthread

$(TARGET_SHELL): $(SHELL_OBJS) $(MBEDTLS_LIBS)
	@echo "$(GREEN)[LINK]$(NC) $@"
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lpthread

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "$(YELLOW)[CC]$(NC) $<"
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	@echo "$(YELLOW)[CLEAN]$(NC)"
	rm -rf $(BUILD_DIR) $(TARGET_AI) $(TARGET_SHELL)

install: $(TARGET_AI) $(TARGET_SHELL)
	@echo "$(GREEN)[INSTALL]$(NC) $(TARGET_AI) -> /usr/local/bin/"
	install -m 755 $(TARGET_AI) /usr/local/bin/
	@echo "$(GREEN)[INSTALL]$(NC) $(TARGET_SHELL) -> /usr/local/bin/"
	install -m 755 $(TARGET_SHELL) /usr/local/bin/

help:
	@echo "AIKernel Build System (Phase 4: Communication Layer)"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build ai + aikernel-shell (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  mbedtls   - Build mbedTLS static library"
	@echo ""
	@echo "After building, run: ./ai or ./aikernel-shell"

# ============================================================================
# UI Phase（终端 AI 界面）：以下为追加内容，既有规则不修改
#  - linenoise 单文件行编辑库（antirez/linenoise，MIT，third_party_ui/）
#  - shell/ui_common.c（颜色/token 格式化/会话存储/spinner 公共层）
#  - shell/commands/cmd_session.c（会话管理命令）
#  - runtime/communication/stream_parse.c（SSE/NDJSON 流式帧解析，Phase C）
# ============================================================================

LINENOISE_DIR  := third_party_ui/linenoise
UI_COMM_DIR    := runtime/communication

# ollama_native.c / local_stream.c / stream_parse.c 已由上方 Kconfig 开关
# 段（KC_SRCS）按 CONFIG_AIKERNEL_LOCAL_PROVIDER / STREAM_MODE 条件编入，
# 不再在此无条件追加（A4：关闭开关必须真的编不进去）。
UI_EXTRA_SRCS := \
	$(LINENOISE_DIR)/linenoise.c \
	$(SHELL_DIR)/ui_common.c \
	$(CMD_DIR)/cmd_session.c \
	$(CMD_DIR)/cmd_compact.c

# 既有 AI_SRCS/SHELL_SRCS 与链接规则均为立即展开且位于本追加段之前，
# 追加源以「无命令的补充前置规则」并入链接目标（make 允许同一目标的
# 多条规则叠加前置条件，原有 recipe 保持不变）。
UI_EXTRA_OBJS := $(UI_EXTRA_SRCS:%.c=$(BUILD_DIR)/%.o)
$(TARGET_AI): $(UI_EXTRA_OBJS)
$(TARGET_SHELL): $(UI_EXTRA_OBJS)

INCLUDES += -I$(LINENOISE_DIR)

# 'ai' 二进制复用 aikernel_main.o 的共享入口（main.c 只做 main() 薄封装）
$(TARGET_AI): $(BUILD_DIR)/$(SHELL_DIR)/aikernel_main.o
# aikernel-shell 同样补入 main.o（两个目标物集完全一致，双入口同程序）
$(TARGET_SHELL): $(BUILD_DIR)/$(SHELL_DIR)/main.o

# 第三方代码不追改：仅对本目标放宽未使用参数告警并启用 GNU 扩展
# （linenoise 需要 strdup/strcasecmp/fileno 等 POSIX 声明，-std=c11 下需显式开）
$(BUILD_DIR)/$(LINENOISE_DIR)/linenoise.o: CFLAGS += -Wno-unused-parameter -D_GNU_SOURCE

# 头文件依赖（追加的前置规则，不改动既有 pattern rule）：
# 既有规则无自动依赖跟踪，头文件变更（如 ai_chat_msg 增字段）会导致
# 混合布局的旧 .o 参与链接（已实际引发 SIGSEGV）。这里让全部目标文件
# 依赖公共头目录，任一头变更即整体重编（工程体量小，代价可接受）。
$(BUILD_DIR)/%.o: $(wildcard include/*.h)

# install 追加：/usr/local/bin/ai -> aikernel-shell（同一程序的双入口）。
# 注：追加前置在原 install recipe 之前运行，会被 `install -m 755 ai`
# 覆盖为同内容副本（两入口二进制本就一致，副本与软链功能等价）；
# 如需严格软链，安装后执行一次 `make install-ui-link`。
install: install-ui-link

# 构建目录内 ./ai -> ./aikernel-shell（all 目标无 recipe，追加前置
# 在全部产物就绪后运行，时序正确）
all: build-ai-link

.PHONY: build-ai-link install-ui-link
build-ai-link:
	@ln -sf aikernel-shell ai
	@echo "$(GREEN)[LINK]$(NC) ai -> aikernel-shell (build dir)"

install-ui-link:
	@echo "$(GREEN)[INSTALL]$(NC) ai -> aikernel-shell (symlink)"
	ln -sf aikernel-shell /usr/local/bin/ai

# ============================================================================
# P2 权限分级（agent/ai/policy/）：追加段，既有规则不修改
# ============================================================================
POLICY_EXTRA_SRCS := policy/ai_user_policy.c
POLICY_EXTRA_OBJS := $(POLICY_EXTRA_SRCS:%.c=$(BUILD_DIR)/%.o)
$(TARGET_AI): $(POLICY_EXTRA_OBJS)
$(TARGET_SHELL): $(POLICY_EXTRA_OBJS)
