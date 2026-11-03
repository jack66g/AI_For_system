# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/tlsgw/Makefile - T7c aik-tls-gateway C 移植(参考
# agent/ai/cloud/tls_gateway/aik_tls_gateway.py 257 行)
#
# 链接方式照 desktop(T6)/apic(T7b) 先例:third_party/mbedtls 三静态库
# + -DMBEDTLS_CONFIG_FILE(config/mbedtls-trim.h,SSL_SRV_C 已回开)。
# 复用 T6 基建(源码只读引用编译进本目录对象):
#   ../desktop/dtcore.c  冻结时钟/sbuf/文件工具
#
#   make -C agent/ai/tlsgw -j1 all
#   make -C agent/ai/tlsgw -j1 test   # /tmp 沙箱生成一次性证书,私钥不落仓库

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include -MMD -MP
LDLIBS := -lpthread

MBEDTLS_DIR := ../third_party/mbedtls
MBEDTLS_INC := -I.. -I$(MBEDTLS_DIR)/include \
	       -DMBEDTLS_CONFIG_FILE='"config/mbedtls-trim.h"'
MBEDTLS_LIBS := \
	$(MBEDTLS_DIR)/library/libmbedtls.a \
	$(MBEDTLS_DIR)/library/libmbedx509.a \
	$(MBEDTLS_DIR)/library/libmbedcrypto.a

REUSE_SRC := ../desktop/dtcore.c
REUSE_OBJ := dtcore.o
STORE_LIB := ../store/libaikstore.a	# dtcore 的 aik_json 符号(T7b 同源)

LIB_SRCS := tlsgwcore.c tlsgwserv.c
OBJS := $(LIB_SRCS:.c=.o)
MAIN_OBJ := tlsgw.o
BIN := aik-tls-gateway

TEST_SRCS := $(wildcard tests/test_*.c)
TESTS := $(TEST_SRCS:.c=)

all: $(BIN)

%.o: %.c
	$(CC) $(CFLAGS) $(MBEDTLS_INC) -c -o $@ $<

$(REUSE_OBJ): %.o: ../desktop/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(STORE_LIB): FORCE
	$(MAKE) -C ../store -j1 all

$(BIN): $(MAIN_OBJ) $(OBJS) $(REUSE_OBJ) $(STORE_LIB) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) -o $@ $(MAIN_OBJ) $(OBJS) $(REUSE_OBJ) $(STORE_LIB) \
	      $(MBEDTLS_LIBS) $(LDLIBS)

$(TESTS): %: %.c $(OBJS) $(REUSE_OBJ) $(STORE_LIB) $(MBEDTLS_LIBS)
	$(CC) $(CFLAGS) $(MBEDTLS_INC) -o $@ $< $(OBJS) $(REUSE_OBJ) \
	      $(STORE_LIB) $(MBEDTLS_LIBS) $(LDLIBS)

FORCE:

CERTS := /tmp/aik-t7c-certs

test: $(TESTS)
	@bash tests/gen_certs.sh $(CERTS) || exit 1
	@for t in $(TESTS); do ./$$t $(CERTS) || exit 1; done

clean:
	rm -f $(OBJS) $(MAIN_OBJ) $(REUSE_OBJ) $(BIN) $(TESTS) *.d tests/*.d

-include $(OBJS:.o=.d) $(REUSE_OBJ:.o=.d) $(TEST_SRCS:.c=.d)

.PHONY: all test clean FORCE
