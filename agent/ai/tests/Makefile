# SPDX-License-Identifier: GPL-2.0
#
# AIKernel agent 回归测试（T2 问题 1：UTF-8 请求体字节安全）
#
# 用法: make -C agent/ai/tests test

CC      ?= gcc
CFLAGS  := -Wall -Wextra -std=c11 -O2 -I../include
RUNTIME := ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c
LOCAL   := ../local/local_http.c
MBEDTLS_DIR := ../third_party/mbedtls
MBEDTLS_LIBS := $(MBEDTLS_DIR)/library/libmbedtls.a \
	        $(MBEDTLS_DIR)/library/libmbedx509.a \
	        $(MBEDTLS_DIR)/library/libmbedcrypto.a

TESTS   := test_utf8_body test_http_retry test_cloud_stream test_provider_stream

all: $(TESTS)

test_utf8_body: test_utf8_body.c $(RUNTIME)
	$(CC) $(CFLAGS) -o $@ test_utf8_body.c $(RUNTIME)

test_http_retry: test_http_retry.c $(LOCAL) ../runtime/ai_types.c
	$(CC) $(CFLAGS) -I../local -o $@ test_http_retry.c $(LOCAL) ../runtime/ai_types.c

# 云通道真增量流式（审计 A1）：provider 层 openai_stream 直调 +
# 内嵌 SSE/chunked 假服务端；真实端点模式 ./test_cloud_stream <url> <model>
STREAM_SRCS := ../cloud/provider_openai_compatible.c \
	../cloud/http/http_client.c \
	../runtime/communication/stream_parse.c \
	$(RUNTIME)
test_cloud_stream: test_cloud_stream.c $(STREAM_SRCS)
	$(CC) $(CFLAGS) -DCONFIG_AI_STREAM_MODE -I.. -I../cloud -I../runtime \
		-I$(MBEDTLS_DIR)/include -o $@ test_cloud_stream.c \
		$(STREAM_SRCS) $(MBEDTLS_LIBS) -lpthread

# provider 层 local ops.stream 真实现（审计 B1）：直调 local provider
# 工厂 + ops.stream，内嵌 SSE 假服务端
LOCAL_STREAM_SRCS := ../local/provider_local.c \
	../local/local_chat.c \
	../local/local_stream.c \
	../local/local_http.c \
	../local/ollama_native.c \
	../runtime/communication/stream_parse.c \
	$(RUNTIME)
test_provider_stream: test_provider_stream.c $(LOCAL_STREAM_SRCS)
	$(CC) $(CFLAGS) -DCONFIG_AI_STREAM_MODE -I.. -I../local -I../runtime \
		-o $@ test_provider_stream.c $(LOCAL_STREAM_SRCS)

test: all
	@for t in $(TESTS); do ./$$t || exit 1; done

clean:
	rm -f $(TESTS)

.PHONY: all test clean
