# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/autocondense/Makefile - T5 autocondense C 化（状态/配置/信号/摘要/SME 桥/服务）
#
# 依赖 store 的 JSON DOM 与 zlib/libm/libpthread。源文件按通配收集：
# ac*.c 逐个入库，tests/test_ac*.c 逐个出二进制；目标细粒度，便于分棒构建。
#
#   make -C agent/ai/autocondense -j1 all
#   make -C agent/ai/autocondense -j1 test            # 构建并运行全部 test_ac*
#   make -C agent/ai/autocondense -j1 tests/test_acstate

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include

LDLIBS := -lz -lm -lpthread

STORE_LIB := ../store/libaikstore.a
LIB := libaikautocondense.a
BINS := autocondensed autocondense-mcp autocondense-hook

SRCS := $(wildcard ac*.c)
OBJS := $(SRCS:.c=.o)
TEST_SRCS := $(wildcard tests/test_ac*.c)
TESTS := $(TEST_SRCS:.c=)

all: $(LIB) $(BINS)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

autocondensed: autocondensed.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ autocondensed.c $(LIB) $(STORE_LIB) $(LDLIBS)

autocondense-mcp: mcp_main.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ mcp_main.c $(LIB) $(STORE_LIB) $(LDLIBS)

autocondense-hook: hook_main.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ hook_main.c $(LIB) $(STORE_LIB) $(LDLIBS)

$(STORE_LIB): FORCE
	$(MAKE) -C ../store -j1 all

$(TESTS): %: %.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(STORE_LIB) $(LDLIBS)

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

clean:
	rm -f $(OBJS) $(LIB) $(BINS) $(TESTS)

FORCE:

.PHONY: all test clean FORCE
