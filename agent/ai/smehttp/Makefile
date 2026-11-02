# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/smehttp/Makefile - T4b SME HTTP 服务静态库 + 二进制 + 自测
#
# 依赖 L1 既有静态库（本目录不改它们）：engine / smeconfig / retrieval /
# space / store，以及 zlib + libm + pthread。库不存在时按依赖顺序递归构建；
# 构建串行：本目录显式 .NOTPARALLEL，子 make 也带 -j1。
#
#   make -C agent/ai/smehttp -j1 all       # libaiksmehttp.a + smehttp
#   make -C agent/ai/smehttp -j1 test      # 构建并运行 tests/test_http
#   make -C agent/ai/smehttp -j1 clean all test

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include
LDLIBS := -lz -lm -lpthread

STORE_LIB := ../store/libaikstore.a
SPACE_LIB := ../space/libaikspace.a
RETR_LIB := ../retrieval/libaikretrieval.a
SME_LIB := ../smeconfig/libaiksmeconfig.a
ENG_LIB := ../engine/libaikengine.a

LIB := libaiksmehttp.a
OBJS := http.o routes.o routes_config.o routes_extra.o
BINS := smehttp
TESTS := tests/test_http

all: $(LIB) $(BINS)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

http.o: http.c ../include/smehttp/http.h ../include/engine/engine.h \
	../include/smeconfig/config.h ../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ http.c

routes.o: routes.c ../include/smehttp/http.h ../include/engine/engine.h \
	../include/retrieval/retriever.h ../include/smeconfig/config.h \
	../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ routes.c

routes_config.o: routes_config.c ../include/smehttp/http.h \
	../include/engine/engine.h ../include/smeconfig/config.h \
	../include/smeconfig/config_items.h ../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ routes_config.c

smehttp: main.c $(LIB) $(ENG_LIB) $(SME_LIB) $(RETR_LIB) $(SPACE_LIB) \
	$(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ main.c $(LIB) $(ENG_LIB) $(SME_LIB) \
		$(RETR_LIB) $(SPACE_LIB) $(STORE_LIB) $(LDLIBS)

# 依赖库：总是交给子 make 判定是否重建（避免手写的过期判断）
$(STORE_LIB): FORCE
	$(MAKE) -C ../store -j1 all

$(SPACE_LIB): $(STORE_LIB) FORCE
	$(MAKE) -C ../space -j1 all

$(RETR_LIB): $(SPACE_LIB) $(STORE_LIB) FORCE
	$(MAKE) -C ../retrieval -j1 all

$(SME_LIB): $(STORE_LIB) FORCE
	$(MAKE) -C ../smeconfig -j1 all

$(ENG_LIB): $(SME_LIB) $(RETR_LIB) $(SPACE_LIB) $(STORE_LIB) FORCE
	$(MAKE) -C ../engine -j1 all

tests/test_http: tests/test_http.c $(LIB) $(ENG_LIB) $(SME_LIB) \
	$(RETR_LIB) $(SPACE_LIB) $(STORE_LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_http.c $(LIB) $(ENG_LIB) \
		$(SME_LIB) $(RETR_LIB) $(SPACE_LIB) $(STORE_LIB) $(LDLIBS)

test: $(TESTS) $(BINS)
	./tests/test_http

clean:
	rm -f $(OBJS) $(LIB) $(BINS) $(TESTS)

FORCE:

.PHONY: all test clean FORCE
