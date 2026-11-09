# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/apic/Makefile - T7b aikernel-api(参考 agent/ai/api/aikernel-api
# 1,148 行 Python)全量 C 化。
#
# 复用 T6 基建(源码只读引用编译进本目录对象,不写 desktop/):
#   ../desktop/dtcore.c  冻结时钟/sbuf/UTF-8 码点工具/strip/文件
#   ../desktop/dtjson.c  python 默认分隔符 JSON dump + DOM 构造
#   ../store/libaikstore.a  aik_json DOM/解析
# dthttp 因响应形制不同(无 Cache-Control、AIKernelAPI/3.0、HEAD 501 无体、
# 414/bad-syntax 模板、超长体 desync 语义)拷贝改编为 apihttp.c(报告声明)。
#
#   make -C agent/ai/apic -j1 all
#   make -C agent/ai/apic -j1 test

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include -MMD -MP
LDLIBS := -lpthread

STORE_LIB := ../store/libaikstore.a
REUSE_SRC := ../desktop/dtcore.c ../desktop/dtjson.c
REUSE_OBJ := dtcore.o dtjson.o

LIB := libaikapi.a
BINS := aikerneld-api

LIB_SRCS := aikapi.c apiask.c apihttp.c apinl.c apiredact.c apiv2.c
OBJS := $(LIB_SRCS:.c=.o)
MAIN_OBJ := apimain.o
TEST_SRCS := $(wildcard tests/test_*.c)
TESTS := $(TEST_SRCS:.c=)

all: $(LIB) $(BINS)

$(LIB): $(OBJS) $(REUSE_OBJ)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(REUSE_OBJ): %.o: ../desktop/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

aikerneld-api: $(MAIN_OBJ) $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ $(MAIN_OBJ) $(LIB) $(STORE_LIB) $(LDLIBS)

$(STORE_LIB): FORCE
	$(MAKE) -C ../store -j1 all

$(TESTS): %: %.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(STORE_LIB) $(LDLIBS)

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

clean:
	rm -f $(OBJS) $(MAIN_OBJ) $(REUSE_OBJ) $(LIB) $(BINS) $(TESTS) *.d tests/*.d

FORCE:

-include $(OBJS:.o=.d) $(REUSE_OBJ:.o=.d) $(TEST_SRCS:.c=.d)

.PHONY: all test clean FORCE
