# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/store/Makefile - T2a/T2b 存储层静态库 + 自测
#
# 本目录自成一体（T4 再接入仓库既有构建，agent/ai/Makefile、
# agent/ai/tests/Makefile 不动）；zlib 是唯一外部依赖，T2b-2 起内联
# sqlite3 amalgamation（../third_party/sqlite3，第三方代码不加 -Werror）。
# 构建串行：本目录显式 .NOTPARALLEL。
#
#   make -C agent/ai/store -j1 all      # 产出 libaikstore.a + libsqlite3.a
#   make -C agent/ai/store -j1 test     # 构建并依次跑七个自测
#   make -C agent/ai/store -j1 clean all test

.NOTPARALLEL:

.DEFAULT_GOAL := all

CC ?= cc
AR ?= ar
CFLAGS := -Wall -Wextra -Werror -std=c11 -O2 -g -I../include
LDLIBS := -lz

SQLITE_DIR := ../third_party/sqlite3
# 第三方 amalgamation：不继承 -Werror / -Wall，只开 T2b 需要的开关
SQLITE_CFLAGS := -O2 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=1

LIB := libaikstore.a
SQLITE_LIB := libsqlite3.a
OBJS := store_json.o store_gzip.o store_npz.o store_npz_write.o \
	store_snapshot.o store_wal.o store_sqlite.o
TESTS := tests/test_store_json tests/test_store_npz tests/test_npz_write \
	tests/test_store_snapshot tests/test_store_wal \
	tests/test_store_snapshot_write tests/test_store_sqlite

all: $(LIB) $(SQLITE_LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

sqlite3.o: $(SQLITE_DIR)/sqlite3.c $(SQLITE_DIR)/sqlite3.h
	$(CC) $(SQLITE_CFLAGS) -I$(SQLITE_DIR) -c -o $@ $(SQLITE_DIR)/sqlite3.c

$(SQLITE_LIB): sqlite3.o
	$(AR) rcs $@ sqlite3.o

store_json.o: store_json.c ../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ store_json.c

store_gzip.o: store_gzip.c ../include/store/store_gzip.h
	$(CC) $(CFLAGS) -c -o $@ store_gzip.c

store_npz.o: store_npz.c ../include/store/store_npz.h
	$(CC) $(CFLAGS) -c -o $@ store_npz.c

store_npz_write.o: store_npz_write.c ../include/store/store_npz_write.h \
	../include/store/store_npz.h
	$(CC) $(CFLAGS) -c -o $@ store_npz_write.c

store_snapshot.o: store_snapshot.c ../include/store/store_snapshot.h \
	../include/store/store_json.h ../include/store/store_gzip.h
	$(CC) $(CFLAGS) -c -o $@ store_snapshot.c

store_wal.o: store_wal.c ../include/store/store_wal.h \
	../include/store/store_json.h
	$(CC) $(CFLAGS) -c -o $@ store_wal.c

store_sqlite.o: store_sqlite.c ../include/store/store_sqlite.h \
	../include/store/store_wal.h ../include/store/store_json.h \
	$(SQLITE_DIR)/sqlite3.h
	$(CC) $(CFLAGS) -I$(SQLITE_DIR) -c -o $@ store_sqlite.c

tests/test_store_json: tests/test_store_json.c $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_store_json.c $(LIB) $(LDLIBS)

tests/test_store_npz: tests/test_store_npz.c $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_store_npz.c $(LIB) $(LDLIBS)

tests/test_npz_write: tests/test_npz_write.c $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_npz_write.c $(LIB) $(LDLIBS)

tests/test_store_snapshot: tests/test_store_snapshot.c $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_store_snapshot.c $(LIB) $(LDLIBS)

tests/test_store_wal: tests/test_store_wal.c $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_store_wal.c $(LIB) $(LDLIBS)

tests/test_store_snapshot_write: tests/test_store_snapshot_write.c $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_store_snapshot_write.c $(LIB) $(LDLIBS)

tests/test_store_sqlite: tests/test_store_sqlite.c $(LIB) $(SQLITE_LIB)
	$(CC) $(CFLAGS) -I$(SQLITE_DIR) -o $@ tests/test_store_sqlite.c \
		$(LIB) $(SQLITE_LIB) -lpthread -lm -lz

test: $(TESTS)
	./tests/test_store_json
	./tests/test_store_npz
	./tests/test_npz_write
	./tests/test_store_snapshot
	./tests/test_store_wal
	./tests/test_store_snapshot_write
	./tests/test_store_sqlite

clean:
	rm -f $(OBJS) $(LIB) sqlite3.o $(SQLITE_LIB) $(TESTS)

.PHONY: all test clean
