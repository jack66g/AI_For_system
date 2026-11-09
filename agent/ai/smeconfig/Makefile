# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/smeconfig/Makefile - T4a/T4e SME 配置中心静态库 + 自测
#
# 本目录自成一体（T4b 再接入仓库既有构建；store/、space/ 等既有目录
# 不改）。默认配置 DOM 由 config_default.h 内置（生成文件），配置注册表
# 由 config_items_data.h 内置（生成文件）；库本身零第三方依赖；自测需要
# T2 的 libaikstore.a 与 zlib，库不存在时先 `make -C ../store -j1 all`。
# 构建串行：本目录显式 .NOTPARALLEL。
#
#   make -C agent/ai/smeconfig -j1 all          # 产出 libaiksmeconfig.a
#   make -C agent/ai/smeconfig -j1 test         # 构建并运行两个自测
#   make -C agent/ai/smeconfig -j1 clean all test

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
# CTOPO1 棒1: -I. 进白名单（tests/test_config.c 引模块根生成头 config_default.h 裸名形态）
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I. -I../include
LDLIBS := -lz -lm

STORE_LIB := ../store/libaikstore.a
LIB := libaiksmeconfig.a
OBJS := config.o config_items.o
TESTS := tests/test_config tests/test_config_items

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

config.o: config.c config_default.h ../include/smeconfig/config.h \
	../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ config.c

config_items.o: config_items.c config_items_data.h \
	../include/smeconfig/config_items.h ../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ config_items.c

$(STORE_LIB):
	$(MAKE) -C ../store -j1 all

tests/test_config: tests/test_config.c $(LIB) $(STORE_LIB) config_default.h
	$(CC) $(CFLAGS) -o $@ tests/test_config.c $(LIB) $(STORE_LIB) $(LDLIBS)

tests/test_config_items: tests/test_config_items.c $(LIB) $(STORE_LIB) \
	config_default.h config_items_data.h ../include/smeconfig/config.h \
	../include/smeconfig/config_items.h
	$(CC) $(CFLAGS) -o $@ tests/test_config_items.c $(LIB) $(STORE_LIB) \
		$(LDLIBS)

test: $(TESTS)
	./tests/test_config
	./tests/test_config_items

clean:
	rm -f $(OBJS) $(LIB) $(TESTS)

.PHONY: all test clean
