# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/aistreamd/Makefile - K3c 常驻事件流守护（I-5+I-4+I-6）
#
# 独立目标（不挂 agent/ai 根 Makefile 的 all——K3b 并行构建互斥考量，
# 见 K3C-REPORT.md「构建集成」）：在 agent/ai 下 `make aistreamd`。
#
#   make              # 构建 aistreamd + 注入器（tests/ai_inject）
#   make test         # 构建并运行单测（10 项：K3c 6 + K3d-2 test_hotplug
#                      #          + I-10 test_outcome + T8 test_parquet
#                      #          + SENSE 脱敏 test_sense_redact）
#   make clean
#
# 只读链接兄弟目录源码（不改它们，各自编译进本目录 obj/reuse/）：
#   ../memory/sme_client.c        SME REST 客户端（POST /memories）
#   ../local/local_http.c         本地 HTTP 传输
#   ../runtime/ai_json_util.c     JSON 转义
#   ../runtime/ai_types.c         AI_OK/AI_ERR_*
#   ../runtime/netlink/ai_netlink_client.c  NETLINK_AI 客户端（REG）

.NOTPARALLEL:

CC      ?= gcc
CFLAGS  := -Wall -Wextra -Werror -std=c11 -O2 -g -MMD -MP

INCLUDES := -I. -I.. -I../include -I../runtime -I../local

OBJ_DIR := obj
REUSE_DIR := $(OBJ_DIR)/reuse

OWN_SRCS := as_util.c as_conf.c as_quota.c as_ring.c as_event.c \
	    as_stats.c as_sme.c as_streams.c as_hotplug.c as_outcome.c \
	    as_redact.c as_snappy.c as_parquet.c as_pq_sink.c aistreamd.c
OWN_OBJS := $(OWN_SRCS:%.c=$(OBJ_DIR)/%.o)

# 复用对象（显式规则，避免与本目录模式规则歧义）
REUSE_OBJS := $(REUSE_DIR)/sme_client.o $(REUSE_DIR)/local_http.o \
	      $(REUSE_DIR)/ai_json_util.o $(REUSE_DIR)/ai_types.o \
	      $(REUSE_DIR)/ai_netlink_client.o

BIN := aistreamd
INJECT := ai_inject
PQ_DUMP := pq_dump		# T8 差分向量驱动（仅链 snappy/parquet 库）

.PHONY: all test clean

all: $(BIN) tests/$(INJECT) tests/$(PQ_DUMP)

$(BIN): $(OWN_OBJS) $(REUSE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/sme_client.o: ../memory/sme_client.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/local_http.o: ../local/local_http.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/ai_json_util.o: ../runtime/ai_json_util.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/ai_types.o: ../runtime/ai_types.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/ai_netlink_client.o: ../runtime/netlink/ai_netlink_client.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

tests/$(INJECT): tests/ai_inject.c
	$(CC) $(CFLAGS) -o $@ $<

# T8 差分向量驱动：只链 writer 库（as_snappy + as_parquet，零 aistreamd 依赖）
tests/$(PQ_DUMP): tests/pq_dump.c $(OBJ_DIR)/as_snappy.o $(OBJ_DIR)/as_parquet.o
	$(CC) $(CFLAGS) -I. -o $@ $^

# ---- 单测（对象除 aistreamd.o：tests 自带 main） ----

TESTS := test_quota test_ring test_conf test_event test_sme test_shutdown \
	 test_hotplug test_outcome test_parquet test_sense_redact
TEST_LIBS := $(filter-out $(OBJ_DIR)/aistreamd.o,$(OWN_OBJS)) $(REUSE_OBJS)

test: $(BIN) tests/$(INJECT) tests/$(PQ_DUMP) $(TESTS:%=tests/%)
	@set -e; fail=0; \
	for t in $(TESTS); do \
		if timeout 300 ./tests/$$t > /tmp/as-$$t.log 2>&1; then \
			echo "PASS $$t"; \
		else \
			echo "FAIL $$t (see /tmp/as-$$t.log)"; fail=1; \
		fi \
	done; \
	exit $$fail

tests/test_%: tests/test_%.c $(TEST_LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_LIBS)

clean:
	rm -rf $(OBJ_DIR) $(BIN) tests/$(INJECT) tests/$(PQ_DUMP) $(TESTS:%=tests/%)

-include $(OWN_OBJS:.o=.d) $(REUSE_OBJS:.o=.d)
