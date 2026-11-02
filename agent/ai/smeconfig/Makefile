# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/smeconfig/Makefile - T4a SME 配置中心静态库 + 自测
#
# 本目录自成一体（T4b 再接入仓库既有构建；store/、space/ 等既有目录
# 不改）。默认配置 DOM 由 config_default.h 内置（生成文件），库本身零
# 第三方依赖；自测需要 T2 的 libaikstore.a 与 zlib，库不存在时先
# `make -C ../store -j1 all`。构建串行：本目录显式 .NOTPARALLEL。
#
#   make -C agent/ai/smeconfig -j1 all      # 产出 libaiksmeconfig.a
#   make -C agent/ai/smeconfig -j1 test     # 构建并运行 tests/test_config
#   make -C agent/ai/smeconfig -j1 clean all test

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include
LDLIBS := -lz -lm

STORE_LIB := ../store/libaikstore.a
LIB := libaiksmeconfig.a
OBJS := config.o
TESTS := tests/test_config

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

config.o: config.c config_default.h ../include/smeconfig/config.h \
	../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ config.c

$(STORE_LIB):
	$(MAKE) -C ../store -j1 all

tests/test_config: tests/test_config.c $(LIB) $(STORE_LIB) config_default.h
	$(CC) $(CFLAGS) -o $@ tests/test_config.c $(LIB) $(STORE_LIB) $(LDLIBS)

test: $(TESTS)
	./tests/test_config

clean:
	rm -f $(OBJS) $(LIB) $(TESTS)

.PHONY: all test clean
