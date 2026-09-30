# SPDX-License-Identifier: GPL-2.0
#
# agent/ai/aikd/Makefile - aikd 安装脚本
#
# 用法：
#   make            # 语法检查
#   make install    # 安装到 /usr/local/sbin（aikd）+ /etc/aikd/aikd.conf
#   make uninstall  # 卸载
#   make clean      # 无操作（python 无编译产物）

PYTHON := python3
PREFIX := /usr/local
BINDIR := $(PREFIX)/sbin
CONFDIR := /etc/aikd

.PHONY: all check install uninstall clean

all: check

check:
	$(PYTHON) -m py_compile aikd aikd_lib.py
	@echo "aikd: syntax OK"

install:
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(CONFDIR)
	install -m 0755 aikd $(DESTDIR)$(BINDIR)/aikd
	install -m 0644 aikd_lib.py $(DESTDIR)$(BINDIR)/aikd_lib.py
	install -m 0644 aikd.conf $(DESTDIR)$(CONFDIR)/aikd.conf
	@echo "aikd: installed to $(BINDIR)/aikd (config $(CONFDIR)/aikd.conf)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/aikd $(DESTDIR)$(BINDIR)/aikd_lib.py
	rm -rf $(DESTDIR)$(CONFDIR)

clean:
	rm -f __pycache__/*.pyc
	rm -rf __pycache__
