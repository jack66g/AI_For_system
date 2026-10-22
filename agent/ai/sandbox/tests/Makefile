# SPDX-License-Identifier: GPL-2.0
#
# W64 沙箱回归（自带运行脚本；不改 agent/ai/tests/Makefile）
# 用法:
#   make -C agent/ai/sandbox/tests            # 构建 tests/aik-sandbox
#   sudo make -C agent/ai/sandbox/tests check  # 全量（root：namespace/cgroup）
# 非 root 只跑 CLI 子集（其余 SKIP）。

CC      ?= gcc
CFLAGS  := -Wall -Wextra -std=c11 -O2 -static
LDFLAGS := -fuse-ld=gold
SB_BIN  := ./aik-sandbox
SB_SRC  := ../aik-sandbox.c

all: $(SB_BIN)

$(SB_BIN): $(SB_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

check: $(SB_BIN)
	./run.sh

concurrency: $(SB_BIN)
	./concurrency.sh 3 10

clean:
	rm -f $(SB_BIN)

.PHONY: all check concurrency clean
