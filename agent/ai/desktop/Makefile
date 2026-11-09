# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/desktop/Makefile - T6b/T6c desktop/server.py C 化
#
# 依赖 store 的 JSON DOM(aik_json*/aik_json_dtoa)与 libm/libpthread;
# T6c 起 call_llm 复用仓库自有 cloud/http http_client(mbedTLS,明文
# http:// 亦支持)——http_client.c 源码只读引用,对象编入本目录,
# 不写 cloud/;链接 third_party/mbedtls 静态库(已随仓库构建)。
# 源文件通配 dt*.c 入库;tests/test_dt*.c 逐个出二进制。
#
#   make -C agent/ai/desktop -j1 all
#   make -C agent/ai/desktop -j1 test
#   make -C agent/ai/desktop -j1 tests/test_dtchat

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include \
	  -MMD -MP

# cloud/http http_client 编译参数(照 agent/ai/Makefile:mbedtls-trim 配置;
# CONFIG_AI_STREAM_MODE 打开 https_post_stream SSE 段)
CLOUD_HTTP_SRC := ../cloud/http/http_client.c
HTTP_CLIENT_OBJ := http_client.o
MBEDTLS_DIR := ../third_party/mbedtls
CFLAGS_HTTP := $(CFLAGS) -I$(MBEDTLS_DIR)/include \
	       -DCONFIG_AI_STREAM_MODE \
	       -DMBEDTLS_CONFIG_FILE='"mbedtls/mbedtls-trim.h"'
MBEDTLS_LIBS := \
	$(MBEDTLS_DIR)/library/libmbedtls.a \
	$(MBEDTLS_DIR)/library/libmbedx509.a \
	$(MBEDTLS_DIR)/library/libmbedcrypto.a

LDLIBS := -lm -lpthread

STORE_LIB := ../store/libaikstore.a
LIB := libaikdesktop.a
BINS := desktopd

SRCS := $(wildcard dt*.c)
OBJS := $(SRCS:.c=.o) $(HTTP_CLIENT_OBJ)
TEST_SRCS := $(wildcard tests/test_dt*.c)
TESTS := $(TEST_SRCS:.c=)

all: $(LIB) $(BINS)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(HTTP_CLIENT_OBJ): $(CLOUD_HTTP_SRC)
	$(CC) $(CFLAGS_HTTP) -c $< -o $@

desktopd: desktopd.c $(LIB) $(STORE_LIB) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) -o $@ desktopd.c $(LIB) $(STORE_LIB) $(MBEDTLS_LIBS) $(LDLIBS)

$(STORE_LIB): FORCE
	$(MAKE) -C ../store -j1 all

$(TESTS): %: %.c $(LIB) $(STORE_LIB) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(STORE_LIB) $(MBEDTLS_LIBS) $(LDLIBS)

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

clean:
	rm -f $(OBJS) $(LIB) $(BINS) $(TESTS) *.d tests/*.d

FORCE:

-include $(OBJS:.o=.d) $(TEST_SRCS:.c=.d)

.PHONY: all test clean FORCE
