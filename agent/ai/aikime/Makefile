# aik-ime — P-55 开发态构建
#
# librime 静态库当前引用 ~/p55-poc 勘探基座；17.9 打版棒会把 librime
# 构建入树（third_party），届时改 RIME_LIB/RIME_INC 缺省值即可。
#
# make          编 aik-ime
# make check    协议全链测试（mock_fbterm，需 AIK_IME_DATA 指向 rime 数据）

CXX      ?= g++
RIME_LIB ?= $(HOME)/p55-poc/librime/build/lib/librime.a
RIME_INC ?= $(HOME)/p55-poc/librime/src
RIME_DATA ?= $(HOME)/p55-poc/rime-data
# -Wno-missing-field-initializers：rime_api.h 的 RIME_STRUCT 宏={0} 固有
# -Wl,-rpath：出厂件自寻随包 .so（factory /usr/local/lib/aik-ime/；140
# 最小系统无 yaml-cpp/boost/icu 系统件）；L1 开发态系统路径兜底不受影响
CXXFLAGS ?= -O2 -g -Wall -Wextra -Wno-missing-field-initializers
RPATH_FLAGS ?= -Wl,-rpath,/usr/local/lib/aik-ime
LDLIBS   ?= -lyaml-cpp -lleveldb -lmarisa -lopencc -lboost_regex -licuuc -licui18n -lpthread -ldl

all: aik-ime

aik-ime: aik_ime.cpp im_proto.h
	$(CXX) $(CXXFLAGS) $(RPATH_FLAGS) -I$(RIME_INC) -o $@ aik_ime.cpp $(RIME_LIB) $(LDLIBS)

tests/mock_fbterm: tests/mock_fbterm.cpp im_proto.h
	$(CXX) $(CXXFLAGS) -I. -o $@ tests/mock_fbterm.cpp

check: aik-ime tests/mock_fbterm
	AIK_IME_DATA=$(RIME_DATA) tests/mock_fbterm ./aik-ime

clean:
	rm -f aik-ime tests/mock_fbterm

.PHONY: all check clean
