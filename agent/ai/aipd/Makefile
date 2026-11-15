# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/aipd/Makefile - AIPD-M1 影子守护（Lane-A；设计 AIPD-M1-DESIGN §1）
#
# 独立目标（不挂 agent/ai 根 Makefile 的 all/run_all——Lane-B 台架与
# 出厂归 m1b 工树；主会话整合亲验）：
#   make              # 构建 aipd
#   make test         # 构建并运行单测（9 套，含 daemon 冒烟与 bench 烟测）
#   make clean
#
# 只读复用兄弟目录源码（occ Makefile PQ_REUSE 先例；不改 aistreamd）：
#   ../aistreamd/as_snappy.c    影子 parquet 页压缩（aip_shadow writer）
#   ../aistreamd/as_parquet.c   单测 footer 统计读回（as_pq_file_stats
#                               ——影子行计数断言的独立读路径）
#   ../aistreamd/as_value.c     as_parquet 的链接依赖（curated 面，纯叶子）

.NOTPARALLEL:

CC      ?= gcc
CFLAGS  := -Wall -Wextra -Werror -std=c11 -O2 -g -MMD -MP

INCLUDES := -I. -I../include

OBJ_DIR := obj
REUSE_DIR := $(OBJ_DIR)/reuse

OWN_SRCS := aip_util.c aip_conf.c aip_feat.c aip_model.c aip_table.c \
	    aip_table_data.c aip_shadow.c aipd.c
OWN_OBJS := $(OWN_SRCS:%.c=$(OBJ_DIR)/%.o)

REUSE_OBJS := $(REUSE_DIR)/as_snappy.o $(REUSE_DIR)/as_parquet.o \
	      $(REUSE_DIR)/as_value.o

BIN := aipd

# ---- 单测（对象除 aipd.o：tests 自带 main） ----
TESTS := test_conf test_util test_feat test_model test_table \
	 test_shadow test_cmp test_bench test_daemon

.PHONY: all test clean

all: $(BIN)

$(BIN): $(filter-out $(OBJ_DIR)/aipd.o,$(OWN_OBJS)) $(OBJ_DIR)/aipd.o \
	$(REUSE_DIR)/as_snappy.o
	$(CC) $(CFLAGS) -o $@ $(filter-out $(OBJ_DIR)/aipd.o,$(OWN_OBJS)) \
	      $(OBJ_DIR)/aipd.o $(REUSE_DIR)/as_snappy.o

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/as_snappy.o: ../aistreamd/as_snappy.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/as_parquet.o: ../aistreamd/as_parquet.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(REUSE_DIR)/as_value.o: ../aistreamd/as_value.c
	@mkdir -p $(REUSE_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# conf 解析（坏值/未知键/重复键拒绝）
tests/test_conf: tests/test_conf.c $(OBJ_DIR)/aip_conf.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

# 锁互斥/原子写/stats 渲染
tests/test_util: tests/test_util.c $(OBJ_DIR)/aip_util.o $(OBJ_DIR)/aip_conf.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

# mock 解析/stale/map35 attr 打包自证
tests/test_feat: tests/test_feat.c $(OBJ_DIR)/aip_feat.o \
		 $(OBJ_DIR)/aip_util.o $(OBJ_DIR)/aip_conf.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

# aip_decide 边界（每规则命中/不命中/阈值/多命中首出/可信门）
tests/test_model: tests/test_model.c $(OBJ_DIR)/aip_model.o \
		  $(OBJ_DIR)/aip_table.o $(OBJ_DIR)/aip_table_data.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

# 表校验通过+篡改拒载（SHA-256 漂移）
tests/test_table: tests/test_table.c $(OBJ_DIR)/aip_table.o \
		  $(OBJ_DIR)/aip_table_data.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

# 影子 parquet 33 列落盘+行计数（footer 读回 as_pq_file_stats）+旋转
tests/test_shadow: tests/test_shadow.c $(OBJ_DIR)/aip_shadow.o \
		   $(OBJ_DIR)/aip_table.o $(OBJ_DIR)/aip_table_data.o \
		   $(OBJ_DIR)/aip_util.o \
		   $(OBJ_DIR)/aip_conf.o \
		   $(REUSE_DIR)/as_snappy.o $(REUSE_DIR)/as_parquet.o \
		   $(REUSE_DIR)/as_value.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

# 对照 mismatch 滚动窗（双流合同：mock 对照行解析+窗滚动+pct）
tests/test_cmp: tests/test_cmp.c $(OBJ_DIR)/aip_shadow.o \
		$(OBJ_DIR)/aip_table.o $(OBJ_DIR)/aip_table_data.o \
		$(OBJ_DIR)/aip_util.o \
		$(REUSE_DIR)/as_snappy.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

# bench 子命令烟测（解析 AIPD_BENCH 行；p99 合理性）
tests/test_bench: tests/test_bench.c $(BIN)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_bench.c

# daemon 冒烟（AIPD_ONCE=1 单轮：锁/stats 终笔/影子 parquet 落盘；
# 链 aip_util/aip_conf=守护级锁互斥用本测先持 lease）
tests/test_daemon: tests/test_daemon.c $(BIN) $(OBJ_DIR)/aip_util.o \
		   $(OBJ_DIR)/aip_conf.o $(OBJ_DIR)/aip_table.o \
		   $(OBJ_DIR)/aip_table_data.o \
		   $(REUSE_DIR)/as_snappy.o $(REUSE_DIR)/as_parquet.o \
		   $(REUSE_DIR)/as_value.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_daemon.c \
	      $(OBJ_DIR)/aip_util.o $(OBJ_DIR)/aip_conf.o \
	      $(OBJ_DIR)/aip_table.o $(OBJ_DIR)/aip_table_data.o \
	      $(REUSE_DIR)/as_snappy.o \
	      $(REUSE_DIR)/as_parquet.o $(REUSE_DIR)/as_value.o

test: $(BIN) $(TESTS:%=tests/%)
	@set -e; fail=0; \
	for t in $(TESTS); do \
		if timeout 300 ./tests/$$t > /tmp/aip-$$t.log 2>&1; then \
			echo "PASS $$t"; \
		else \
			echo "FAIL $$t (see /tmp/aip-$$t.log)"; fail=1; \
		fi \
	done; \
	exit $$fail

clean:
	rm -rf $(OBJ_DIR) $(BIN) $(TESTS:%=tests/%)

-include $(OWN_OBJS:.o=.d) $(REUSE_OBJS:.o=.d)
