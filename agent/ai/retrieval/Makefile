# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/retrieval/Makefile - T3a 检索层静态库 + 自测
#
# 本目录自成一体（T4 再接入仓库既有构建；agent/ai/Makefile、tests/、
# store/ 均不改）。读向量需要 T2 的 libaikstore.a 与 zlib；库不存在时
# 先 `make -C ../store -j1 all`。构建串行：本目录显式 .NOTPARALLEL。
#
#   make -C agent/ai/retrieval -j1 all      # 产出 libaikretrieval.a
#   make -C agent/ai/retrieval -j1 test     # 构建并依次跑三个自测
#   make -C agent/ai/retrieval -j1 clean all test

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include
LDLIBS := -lz -lm

STORE_LIB := ../store/libaikstore.a
LIB := libaikretrieval.a
OBJS := text.o bm25.o embed_hash.o blake2b.o unicode.o ranker.o ppr.o retriever.o
TESTS := tests/test_embed_hash tests/test_text tests/test_bm25 tests/test_ranker tests/test_ppr tests/test_retrieval

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

text.o: text.c ../include/retrieval/text.h ../memory/unicode.h
	$(CC) $(CFLAGS) -c -o $@ text.c

bm25.o: bm25.c ../include/retrieval/bm25.h ../include/retrieval/text.h
	$(CC) $(CFLAGS) -c -o $@ bm25.c

embed_hash.o: ../memory/embed_hash.c ../include/memory/embed_hash.h \
	../memory/blake2b.h ../memory/unicode.h
	$(CC) $(CFLAGS) -c -o $@ ../memory/embed_hash.c

blake2b.o: ../memory/blake2b.c ../memory/blake2b.h \
	../include/memory/embed_hash.h
	$(CC) $(CFLAGS) -c -o $@ ../memory/blake2b.c

unicode.o: ../memory/unicode.c ../memory/unicode.h \
	../memory/unicode_lower_table.h
	$(CC) $(CFLAGS) -c -o $@ ../memory/unicode.c

ranker.o: ranker.c ../include/retrieval/ranker.h ../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ ranker.c

ppr.o: ppr.c ../include/retrieval/ppr.h
	$(CC) $(CFLAGS) -c -o $@ ppr.c

retriever.o: retriever.c ../include/retrieval/retriever.h \
	../include/retrieval/ranker.h ../include/retrieval/bm25.h \
	../include/retrieval/text.h ../include/retrieval/ppr.h \
	../include/space/space.h ../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ retriever.c

$(STORE_LIB):
	$(MAKE) -C ../store -j1 all

tests/test_embed_hash: tests/test_embed_hash.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_embed_hash.c $(LIB) $(STORE_LIB) $(LDLIBS)

tests/test_text: tests/test_text.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_text.c $(LIB) $(STORE_LIB) $(LDLIBS)

tests/test_bm25: tests/test_bm25.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_bm25.c $(LIB) $(STORE_LIB) $(LDLIBS)

tests/test_ranker: tests/test_ranker.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_ranker.c $(LIB) $(STORE_LIB) $(LDLIBS)

tests/test_ppr: tests/test_ppr.c $(LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_ppr.c $(LIB) $(STORE_LIB) $(LDLIBS)

tests/test_retrieval: tests/test_retrieval.c $(LIB) $(STORE_LIB) \
	../space/libaikspace.a
	$(CC) $(CFLAGS) -o $@ tests/test_retrieval.c ../space/libaikspace.a $(LIB) $(STORE_LIB) $(LDLIBS)

test: $(TESTS)
	./tests/test_embed_hash
	./tests/test_text
	./tests/test_bm25
	./tests/test_ranker
	./tests/test_ppr
	./tests/test_retrieval

clean:
	rm -f $(OBJS) $(LIB) $(TESTS)

.PHONY: all test clean
