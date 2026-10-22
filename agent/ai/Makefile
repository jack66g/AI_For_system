# AIKernel - AI Subsystem Makefile
#
# 构建 AI Shell 二进制文件 'ai' 和 'aikernel-shell'。
# 通信层：http_client 内置 mbedTLS（TLS 证书强校验，VERIFY_REQUIRED）。
#
# 用法:
#   make              # 构建 ai
#   make all          # 构建 ai + aikernel-shell
#   make clean        # 清理

# ============================================================================
# W46a 防呆（W45 实测根因固化）：本子树独立 make 时不继承顶层 Makefile 的
# .NOTPARALLEL，`make -j4` 下 gold 链接器并发链接偶发 internal error
# (signal 7)，产出坏产物（md5 漂移）。此处强制本 Makefile 的全部目标串行
# 执行——-jN 并发标志被显式无视，任何并发度下的构建口径都与 -j1 一致。
# ============================================================================
.NOTPARALLEL:

CC      ?= gcc
CFLAGS  := -Wall -Wextra -std=c11 -O2 -g -static -DMBEDTLS_CONFIG_FILE=\"config/mbedtls-trim.h\"
# 自动头文件依赖：-MMD 生成 <obj>.d（-MP 附带空目标防删除头后报错）。
# 旧实现只在文件末尾追加了一条「%.o: include/*.h」模式规则——GNU make
# 不会把两条同模式规则合并，该规则实际不生效；ai_lang.h 增加 TR_SB_*
# 枚举后 executor.o 未重编、与新 lang.o 混链，导致 tr(TR_SB_CREATED)
# 取到 TR_CMP_TRUNC 文案（W65 P2 工具结果串线根因）。以编译期依赖文件
# 为准，任何头文件（含子目录）变更都会重编对应 .o。
DEPFLAGS := -MMD -MP
# W10-B：链接器锁定 gold。Ubuntu 22.04 的 ld.bfd 2.38 对本工程的 .bss 布局
# 存在重定位编码缺陷（全量 clean 重建必现）：init-first.o 的
# __libc_argc/__libc_argv/__environ 三处 R_X86_64_PC32 被编码到真实地址
# -0x20 的位置（argc 写进 _dl_platform），启动期 _dl_non_dynamic_init 解引用
# 垃圾指针 SIGSEGV；且 __environ 永不被初始化，链接产物整体不可信。
# 增量链接因 .o 布局不同碰巧不触发（lottery），不可依赖。ld.gold 无此问题。
LDFLAGS := -fuse-ld=gold

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
LOCAL_DIR      := local
MEMORY_DIR     := memory
TOOLS_DIR      := tools
CONFIG_DIR     := config
INCLUDE_DIR    := include
BUILD_DIR      := build
MBEDTLS_DIR    := third_party/mbedtls

# ============================================================================
# Kconfig 三开关接线（A4：配置面与构建事实一致化）
#   CONFIG_AIKERNEL_CLOUD_PROVIDER → cloud provider/backend/http_client
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
	   $(HTTP_DIR)/http_client.c
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

# 公共源文件（provider/backend/http/stream 按上方 Kconfig 开关条件编入）
COMMON_SRCS := \
	$(CLOUD_DIR)/toolname_map.c \
	$(SHELL_DIR)/shell.c \
	$(CMD_DIR)/commands_registry.c \
	$(CMD_DIR)/cmd_help.c \
	$(CMD_DIR)/cmd_exit.c \
	$(CMD_DIR)/cmd_status.c \
	$(CMD_DIR)/cmd_config.c \
	$(CMD_DIR)/cmd_chat.c \
	$(CMD_DIR)/cmd_ask.c \
	$(CMD_DIR)/cmd_lease.c \
	$(CMD_DIR)/ask_context.c \
	$(CMD_DIR)/ask_compact.c \
	$(CMD_DIR)/ask_clarify.c \
	$(CMD_DIR)/cmd_model.c \
	$(CMD_DIR)/cmd_model_lifecycle.c \
	$(CMD_DIR)/model_lifecycle.c \
	$(CMD_DIR)/cmd_network.c \
	$(CMD_DIR)/cmd_netlink.c \
	$(CMD_DIR)/cmd_onboarding.c \
	$(CMD_DIR)/cmd_shell.c \
	$(RUNTIME_DIR)/ai_types.c \
	$(RUNTIME_DIR)/ai_json_util.c \
	$(RUNTIME_DIR)/ai_chat_proto.c \
	$(RUNTIME_DIR)/runtime.c \
	$(RUNTIME_DIR)/ai_route.c \
	$(RUNTIME_DIR)/netlink/ai_netlink_client.c \
	$(COMM_DIR)/communication.c \
	$(BACKEND_DIR)/backend.c \
	$(PROVIDER_DIR)/provider_core.c \
	$(MEMORY_DIR)/sme_client.c \
	$(TOOLS_DIR)/tool_registry.c \
	$(TOOLS_DIR)/executor.c \
	$(CONFIG_DIR)/config_manager.c \
	$(LOCAL_DIR)/local_http.c \
	$(LOCAL_DIR)/offline_intent.c \
	$(KC_SRCS)
# 注：local_http.c 无条件编入——它是轻量 HTTP 传输工具层，被
# memory/sme_client.c（SME 记忆服务客户端）依赖，不属于本地 provider 功能。

# W46a：REPL 主入口唯一源是 shell/aikernel_main.c（ai 与 aikernel-shell 复用）。
# 遗留副本 shell/commands/aikernel_main.c 已删除（W46a 全树 grep 零引用、
# 与 shell/ 版 diff 逐字节一致后清理）。勿在 commands/ 下再生成同名文件——
# 改 REPL 入口只改 shell/aikernel_main.c 这一份。
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
		$(MAKE) -C $(MBEDTLS_DIR)/library -j$$(nproc) CFLAGS='-O2 -DMBEDTLS_CONFIG_FILE=\"config/mbedtls-trim.h\" -I$(CURDIR)' 2>&1 | tail -1; \
	fi

$(TARGET_AI): $(AI_OBJS) $(MBEDTLS_LIBS)
	@echo "$(GREEN)[LINK]$(NC) $@"
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lpthread

$(TARGET_SHELL): $(SHELL_OBJS) $(MBEDTLS_LIBS)
	@echo "$(GREEN)[LINK]$(NC) $@"
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lpthread

$(BUILD_DIR)/%.o: %.c $(wildcard include/*.h)
	@mkdir -p $(dir $@)
	@echo "$(YELLOW)[CC]$(NC) $<"
	$(CC) $(CFLAGS) $(DEPFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	@echo "$(YELLOW)[CLEAN]$(NC)"
	rm -rf $(BUILD_DIR) $(TARGET_AI) $(TARGET_SHELL) $(SB_BIN)

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
	$(SHELL_DIR)/repl_paste.c \
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

# 头文件依赖：以编译器生成的 .d 文件为准（见上方 DEPFLAGS；-include 汇总
# 放在文件末尾，确保所有 *_OBJS 变量已定义）。旧「%.o: include/*.h」第二
# 模式规则不会与既有 pattern rule 合并，实际是 no-op——已由 W65 修正
# （stale executor.o 串线事故）。

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
POLICY_EXTRA_SRCS := policy/ai_user_policy.c policy/ai_lease.c
POLICY_EXTRA_OBJS := $(POLICY_EXTRA_SRCS:%.c=$(BUILD_DIR)/%.o)
$(TARGET_AI): $(POLICY_EXTRA_OBJS)
$(TARGET_SHELL): $(POLICY_EXTRA_OBJS)

# ============================================================================
# W17-H i18n（agent/ai/i18n/）：追加段，既有规则不修改
#  - i18n/lang.c（中/英双语字符串表 tr() + 语言状态，见 include/ai_lang.h）
#  - shell/commands/cmd_lang.c（lang 命令：显示/切换界面语言并持久化）
#  语言来源优先级：AIKERNEL_LANG > model.toml [ui] lang > zh（缺省中文）
# ============================================================================
I18N_EXTRA_SRCS := i18n/lang.c \
	$(CMD_DIR)/cmd_lang.c
I18N_EXTRA_OBJS := $(I18N_EXTRA_SRCS:%.c=$(BUILD_DIR)/%.o)
$(TARGET_AI): $(I18N_EXTRA_OBJS)
$(TARGET_SHELL): $(I18N_EXTRA_OBJS)

# ============================================================================
# W42 隔离区工具（agent/ai/sandbox/）：追加段，既有规则不修改
#  - aik-sandbox：独立静态产物，gcc 直链单文件，不依赖 agent 其余部分
#    （子智能体宿主侧生命周期工具：create/run/destroy/status，见
#    sandbox/aik-sandbox.c；executor.c 的 sandbox 通道经它组装 namespace
#    沙盒）。生产布局装 /usr/local/bin/aik-sandbox。
# ============================================================================
SB_DIR   := sandbox
SB_BIN   := aik-sandbox
SB_CFLAGS := -Wall -Wextra -std=c11 -O2 -static

$(SB_BIN): $(SB_DIR)/aik-sandbox.c $(wildcard include/*.h)
	@echo "$(GREEN)[LINK]$(NC) $@"
	$(CC) $(SB_CFLAGS) $(LDFLAGS) -o $@ $<

all: $(SB_BIN)

install-sandbox: $(SB_BIN)
	@echo "$(GREEN)[INSTALL]$(NC) $(SB_BIN) -> /usr/local/bin/"
	install -m 755 $(SB_BIN) /usr/local/bin/
	@if [ -f tools/tools-sandbox.json ]; then \
		mkdir -p /usr/local/share/aikernel/; \
		install -m 644 tools/tools-sandbox.json \
			/usr/local/share/aikernel/; \
		echo "$(GREEN)[INSTALL]$(NC) tools/tools-sandbox.json -> /usr/local/share/aikernel/"; \
	fi

install: install-sandbox

# ============================================================================
# W43 合并波（plan 只读模式 + slash 命令体系）：追加段，既有规则不修改
#  - shell/commands/cmd_plan.c（/plan /unplan：会话级只读规划模式开关，
#    状态位在 policy/ai_user_policy.c，工具闸门在 tools/executor.c）
#  - shell/commands/cmd_tools.c（/tools：注册表清单，通道/关键词过滤）
#  - shell/commands/cmd_sandbox.c（/sandbox：隔离区手动管理——与 ask 内
#    sandbox_* 工具同链路（注册表+闸门+执行器），不旁路安全层）
# ============================================================================
W43_EXTRA_SRCS := $(CMD_DIR)/cmd_plan.c \
	$(CMD_DIR)/cmd_tools.c \
	$(CMD_DIR)/cmd_sandbox.c
W43_EXTRA_OBJS := $(W43_EXTRA_SRCS:%.c=$(BUILD_DIR)/%.o)
$(TARGET_AI): $(W43_EXTRA_OBJS)
$(TARGET_SHELL): $(W43_EXTRA_OBJS)

# ============================================================================
# W48B 全轨迹日志（agent/ai/trace/）：追加段，既有规则不修改
#  - trace/ai_trace.c：JSONL 事件写入（O_APPEND 单写/脱敏/轮转/降级），
#    session/turn/model/tool/policy/degraded/error 全链路
#  - shell/commands/cmd_trace.c：trace stats|dump|export（训练数据导出）
# ============================================================================
TRACE_EXTRA_SRCS := trace/ai_trace.c \
	$(CMD_DIR)/cmd_trace.c
TRACE_EXTRA_OBJS := $(TRACE_EXTRA_SRCS:%.c=$(BUILD_DIR)/%.o)
$(TARGET_AI): $(TRACE_EXTRA_OBJS)
$(TARGET_SHELL): $(TRACE_EXTRA_OBJS)


# W48 security fix: root tools.json / tools.openai.json / tool_catalog.txt /
# tools-sandbox.json are symlinks to tools/ (single canonical source, 114 tools).
# Never edit the root paths; regenerate tools/ with tools/gen_registry.py.

# W65：自动头文件依赖汇总（必须位于全部 *_OBJS 定义之后；见 DEPFLAGS）。
-include $(AI_OBJS:.o=.d) $(SHELL_OBJS:.o=.d) $(UI_EXTRA_OBJS:.o=.d) \
	$(POLICY_EXTRA_OBJS:.o=.d) $(I18N_EXTRA_OBJS:.o=.d) \
	$(W43_EXTRA_OBJS:.o=.d) $(TRACE_EXTRA_OBJS:.o=.d)
