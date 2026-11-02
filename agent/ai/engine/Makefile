# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/engine/Makefile - T4a SME Engine 核心静态库 + 自测
#
# 依赖 L1 既有静态库（本目录不改它们）：smeconfig / retrieval / space /
# store，以及 zlib + libm。库不存在时按依赖顺序递归构建；构建串行：本
# 目录显式 .NOTPARALLEL，子 make 也带 -j1。
#
#   make -C agent/ai/engine -j1 all      # 产出 libaikengine.a
#   make -C agent/ai/engine -j1 test     # 构建并运行 tests/test_engine
#   make -C agent/ai/engine -j1 clean all test

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include
LDLIBS := -lz -lm

STORE_LIB := ../store/libaikstore.a
SPACE_LIB := ../space/libaikspace.a
RETR_LIB := ../retrieval/libaikretrieval.a
SME_LIB := ../smeconfig/libaiksmeconfig.a
LIB := libaikengine.a
OBJS := engine.o memory.o
TESTS := tests/test_engine

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

engine.o: engine.c ../include/engine/engine.h \
	../include/memory/embed_hash.h ../include/retrieval/ranker.h \
	../include/retrieval/retriever.h ../include/space/space.h \
	../include/store/store_json.h ../include/store/store_npz.h \
	../include/store/store_snapshot.h
	$(CC) $(CFLAGS) -c -o $@ engine.c

memory.o: memory.c ../include/engine/engine.h ../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ memory.c

# 依赖库：总是交给子 make 判定是否重建（避免手写的过期判断）
$(STORE_LIB): FORCE
	$(MAKE) -C ../store -j1 all

$(SPACE_LIB): $(STORE_LIB) FORCE
	$(MAKE) -C ../space -j1 all

$(RETR_LIB): $(SPACE_LIB) $(STORE_LIB) FORCE
	$(MAKE) -C ../retrieval -j1 all

$(SME_LIB): $(STORE_LIB) FORCE
	$(MAKE) -C ../smeconfig -j1 all

tests/test_engine: tests/test_engine.c $(LIB) $(SME_LIB) $(RETR_LIB) \
	$(SPACE_LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_engine.c $(LIB) $(SME_LIB) \
		$(RETR_LIB) $(SPACE_LIB) $(STORE_LIB) $(LDLIBS)

test: $(TESTS)
	./tests/test_engine

clean:
	rm -f $(OBJS) $(LIB) $(TESTS)

FORCE:

.PHONY: all test clean FORCE
