# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/occ/occ_tui/Makefile - T9c1 自研 C 终端库（零第三方依赖）
#
# 独立可构建（绝不改 agent/ai/occ 顶层 Makefile——与 b2 棒互斥）：
#   make            # 库对象 + 测试二进制
#   make test       # 构建并运行全部 golden 测试
#   make clean
#
# 只有 libc（termios/ioctl/signal/pty），无任何第三方库。

.NOTPARALLEL:

CC      ?= cc
# _DEFAULT_SOURCE：-std=c11 严格模式下暴露 POSIX（struct sigaction/termios/
# sigaction 等）；与各 .c 顶部的 #define _DEFAULT_SOURCE 同值共存。
CFLAGS  := -Wall -Wextra -Werror -std=c11 -O2 -g -MMD -MP -D_DEFAULT_SOURCE
INCLUDES := -I.

# c3：+theme（数据文件）+usage（token 公式）+keymap（键位表）+overlay
#（全屏覆盖层）——全 libc。tui_data（aik_json）刻意不入本库（头注不变）。
LIB_SRCS := tui_utf8.c tui_core.c tui_input.c tui_frame.c tui_chat.c \
	    tui_inputbox.c tui_sidebar.c tui_view.c tui_theme.c \
	    tui_usage.c tui_keymap.c tui_overlay.c tui_gate.c tui_lang.c
LIB_OBJS := $(LIB_SRCS:%.c=obj/%.o)

# P-41/P-44：test_sinkbuf（缓冲汇+整帧原子刷+wd 单元）/ test_wd
# （pty 级 wd 禁用回归门——缓冲化字节总序全等）
TEST_SRCS := tests/test_utf8.c tests/test_glyphwidth.c \
	     tests/test_render.c tests/test_input.c \
	     tests/test_frame.c tests/test_pty.c tests/test_chat.c \
	     tests/test_inputbox.c tests/test_view_pty.c \
	     tests/test_keymap.c tests/test_themefile.c \
	     tests/test_overlay.c tests/test_usage.c \
	     tests/test_gate.c tests/test_gate_pty.c \
     tests/test_rename_ai.c tests/test_history_load.c \
     tests/test_models_offline.c tests/test_su_pty.c \
     tests/test_sinkbuf.c tests/test_wd.c tests/test_exitmarker.c \
     tests/test_w2_confirm_pty.c tests/test_cmd_tailws.c \
     tests/test_undo_cmd.c
TEST_BINS := $(TEST_SRCS:.c=)

.PHONY: all test clean

all: $(TEST_BINS)

# 单测入口：全部 golden（含 pty 集成）→ 一行 ALL GREEN
test: $(TEST_BINS)
	@set -e; for t in $(TEST_BINS); do ./$$t; done; \
	echo "occ_tui tests: ALL GREEN ($(TEST_BINS))"

obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# 测试直接链库对象（无外部依赖；test_pty 用 POSIX pty 三件套，无需 -lutil；
# tui_view 事件环用 pthread——链 -lpthread，tui_view 的自唤醒 pipe 依赖它；
# B8 test_rename_ai exec 真 ../occ 二进制 + 本地 python3 mock（tests/
# mock_title_llm.py，127.0.0.1）——../occ 未构建时诚实 skip）
# P-35 test_models_offline 同样 exec 真 ../occ（拷入 fixture 隔离快照
# 搜索链）——离线 /models 浮层不自退回归；未构建时诚实 skip
# P-47 test_exitmarker 同样 exec 真 ../occ（FBTERM 门控 marker 出带外
# M1 写 71 / M2 无 FBTERM 零动作 / M3 /zoom=70 不写；未构建诚实 skip）
# P-52 test_w2_confirm_pty 同样 exec 真 ../occ（拷入 fixture）+ 本地
# python3 mock（tests/mock_w2_llm.py）——W2 面板 y/Enter/n/Esc/超时
# 与写侧 w2_confirmed 豁免端到端；未构建时诚实 skip
# O-25 test_undo_cmd 同样 exec 真 ../occ + tests/mock_w2_llm.py——
# TUI /undo /redo 端到端（write 落盘→/undo 注记+文件回滚+回填面板→
# Esc→/redo 文件恢复；S2 无会话 /undo 注记）；未构建时诚实 skip
# T4 登录门纯逻辑测试（tui_gate.o 需 -lcrypt）
tests/test_gate: tests/test_gate.c $(LIB_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_gate.c $(LIB_OBJS) -lpthread -lcrypt

tests/%: tests/%.c $(LIB_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIB_OBJS) -lpthread -lcrypt

clean:
	rm -rf obj $(TEST_BINS)

-include $(LIB_OBJS:.o=.d)
