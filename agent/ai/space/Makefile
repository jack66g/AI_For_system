# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/space/Makefile - T3b Region 几何 + Space 生命周期静态库 + 自测
#
# 本目录自成一体（T4 再接入仓库既有构建；store/、retrieval/、memory/ 均
# 不改）。读向量需要 T2 的 libaikstore.a 与 zlib；库不存在时先
# `make -C ../store -j1 all`。构建串行：本目录显式 .NOTPARALLEL。
#
#   make -C agent/ai/space -j1 all      # 产出 libaikspace.a
#   make -C agent/ai/space -j1 test     # 构建并运行 tests/test_space
#   make -C agent/ai/space -j1 clean all test

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include
LDLIBS := -lz -lm

STORE_LIB := ../store/libaikstore.a
LIB := libaikspace.a
OBJS := region.o space.o
TESTS := tests/test_space

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

region.o: region.c ../include/space/region.h
	$(CC) $(CFLAGS) -c -o $@ region.c

space.o: space.c ../include/space/space.h ../include/space/region.h
	$(CC) $(CFLAGS) -c -o $@ space.c

$(STORE_LIB):
	$(MAKE) -C ../store -j1 all

tests/test_space: tests/test_space.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_space.c $(LIB) $(STORE_LIB) $(LDLIBS)

test: $(TESTS)
	./tests/test_space

clean:
	rm -f $(OBJS) $(LIB) $(TESTS)

.PHONY: all test clean
