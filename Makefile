# AIKernel 顶层 Makefile —— ENG-06：一条命令构建 / 测试 / 检查 / 打版 / 清理
#
# 在仓根执行（细节与前置条件见 BUILD.md 第 0 节）：
#   make world   构建全部一方用户态件（依赖序串行；任一步失败即停）
#   make test    聚合测试：tests/run_all.sh + 六套记忆门禁 + 出厂能力审计，
#                给统一汇总；任一项红即退出非零并逐项列出失败名
#   make check   轻量门（不构建）：树宪章 check_tree + 出厂能力审计
#   make iso     打版出 ISO：root + build/VERSION + 出厂树可写 前置检查通过后，
#                依次跑 build/w17n_factory_refresh.py、build/w17n_build_iso.sh
#   make clean   只清构建产物（复用各子目录 clean；不删仓内跟踪的同源锚二进制，
#                不碰出厂树）
#
# 纪律（docs/TREE-CHARTER.md）：
#   - 本文件不写死任何构建机绝对路径：一律 $(CURDIR) / $(HOME) / 可覆盖变量。
#   - 组件清单与依赖顺序单点在本文件；子 Makefile 的规则语义零修改。
#   - 构建全部串行（-j1）：smehttp 家族与仓内静态库不容并发写。
#   - make iso 只能在打版机以 root 跑，且由主会话串行独占（不与其他台架并发）。

.DEFAULT_GOAL := help

SHELL := /bin/bash

AGENT_AI := agent/ai

# ---- make iso 的输入（全部可用环境变量/命令行覆盖）----------------------
VERSION_FILE   ?= build/VERSION
FACTORY_ROOT   ?= $(HOME)/w7i-rootfs
REFRESH_SCRIPT ?= build/w17n_factory_refresh.py
ISO_SCRIPT     ?= build/w17n_build_iso.sh

# ---- aik-ime 的条件依赖：librime 静态库在位才建（不在位明示 SKIP）------
AIK_IME_RIME_LIB ?= $(HOME)/p55-poc/librime/build/lib/librime.a

# ---- world 产物清单（逐件在位核对用；aikctl 是 Python，无构建步）--------
WORLD_ARTIFACTS := \
	$(AGENT_AI)/aikernel-shell \
	$(AGENT_AI)/ai \
	$(AGENT_AI)/occ/occ \
	$(AGENT_AI)/aistreamd/aistreamd \
	$(AGENT_AI)/aistreamd/aik-pqdump \
	$(AGENT_AI)/aipd/aipd \
	$(AGENT_AI)/aik-sandbox \
	$(AGENT_AI)/aik-compat \
	$(AGENT_AI)/aik-gcm \
	$(AGENT_AI)/smehttp/smehttp \
	$(AGENT_AI)/smehttp/aikd \
	$(AGENT_AI)/tlsgw/aik-tls-gateway \
	$(AGENT_AI)/autocondense/autocondensed \
	$(AGENT_AI)/autocondense/autocondense-mcp \
	$(AGENT_AI)/autocondense/autocondense-hook \
	$(AGENT_AI)/aikctl/aikctl

# 六套记忆层门禁（各自 make test；engine 依赖其余四库，store 最底层）
MEM_GATES := engine retrieval smeconfig space smehttp store

.PHONY: help world test check iso iso-precheck clean

help:
	@echo "AIKernel 顶层入口（在仓根执行；前置条件与故障处理见 BUILD.md）"
	@echo ""
	@echo "  make world   构建全部一方用户态件（干净树一条命令；失败即停）"
	@echo "  make test    跑全部测试并给统一汇总（run_all + 六套记忆门禁 + 能力审计）"
	@echo "  make check   轻量门：树宪章 + 出厂能力审计（不构建）"
	@echo "  make iso     打版出 ISO（仅打版机 root；前置检查不过即退出非零）"
	@echo "  make clean   清构建产物（不删仓内跟踪二进制/资产，不碰出厂树）"
	@echo ""
	@echo "可覆盖变量：FACTORY_ROOT=$(FACTORY_ROOT)"
	@echo "            AIK_IME_RIME_LIB=$(AIK_IME_RIME_LIB)"

# ===========================================================================
# make world —— 全部一方用户态件，依赖序串行
#   1) mbedTLS 静态库（agent/ai/Makefile 的 mbedtls 目标，存在即短路）
#   2) 记忆层静态库：store → space → retrieval → smeconfig → engine
#   3) agent/ai 主件：aikernel-shell（+ ai 符号链接）、aik-sandbox、
#      aik-compat、aik-gcm（occ/occ_tui 的 TUI 对象编入 occ 本体）
#   4) aistreamd（同目录出 aik-pqdump）
#   5) occ（含 occ_tui 对象）
#   6) aipd、smehttp（出 aikd）、tlsgw、autocondense 三件
#   7) aik-ime：librime 在位才建，否则明示 SKIP（不静默）
# ===========================================================================
world:
	@echo "== [world] 1/7 mbedTLS 静态库 =="
	$(MAKE) -C $(AGENT_AI) mbedtls
	@echo "== [world] 2/7 记忆层静态库（store -> space -> retrieval -> smeconfig -> engine）=="
	$(MAKE) -C $(AGENT_AI)/store -j1 all
	$(MAKE) -C $(AGENT_AI)/space -j1 all
	$(MAKE) -C $(AGENT_AI)/retrieval -j1 all
	$(MAKE) -C $(AGENT_AI)/smeconfig -j1 all
	$(MAKE) -C $(AGENT_AI)/engine -j1 all
	@echo "== [world] 3/7 agent/ai 主件（aikernel-shell / aik-sandbox / aik-compat / aik-gcm）=="
	$(MAKE) -C $(AGENT_AI) -j1 aikernel-shell aik-sandbox aik-compat aik-gcm
	$(MAKE) -C $(AGENT_AI) -j1 build-ai-link
	@echo "== [world] 4/7 aistreamd（含 ai_inject / pq_dump 测试驱动与 aik-pqdump）=="
	$(MAKE) -C $(AGENT_AI)/aistreamd -j1 all
	@echo "== [world] 5/7 occ（occ_tui 对象编入同一二进制）=="
	$(MAKE) -C $(AGENT_AI)/occ -j1 all
	@echo "== [world] 6/7 aipd / smehttp(出 aikd) / tlsgw / autocondense 三件 =="
	$(MAKE) -C $(AGENT_AI)/aipd -j1 all
	$(MAKE) -C $(AGENT_AI)/smehttp -j1 all
	$(MAKE) -C $(AGENT_AI)/tlsgw -j1 all
	$(MAKE) -C $(AGENT_AI)/autocondense -j1 all
	@echo "== [world] 7/7 aik-ime（条件件）=="
	@if [ -f "$(AIK_IME_RIME_LIB)" ]; then \
		echo "aik-ime: librime 在位（$(AIK_IME_RIME_LIB)），构建"; \
		$(MAKE) -C $(AGENT_AI)/aikime -j1 all RIME_LIB=$(AIK_IME_RIME_LIB); \
	else \
		echo "SKIP  aik-ime：未找到 librime 静态库 $(AIK_IME_RIME_LIB)"; \
		echo "SKIP  aik-ime：装好勘探基座（或 make world AIK_IME_RIME_LIB=<路径>）后重跑 world"; \
	fi
	@echo "== [world] 产物核对（逐件在位；缺任一件即非零退出）=="
	@miss=0; \
	for f in $(WORLD_ARTIFACTS); do \
		if [ -x "$$f" ]; then printf 'OK    %s\n' "$$f"; \
		else printf 'MISS  %s\n' "$$f"; miss=$$((miss+1)); fi; \
	done; \
	if [ -f "$(AIK_IME_RIME_LIB)" ]; then \
		if [ -x "$(AGENT_AI)/aikime/aik-ime" ]; then printf 'OK    %s\n' "$(AGENT_AI)/aikime/aik-ime"; \
		else printf 'MISS  %s\n' "$(AGENT_AI)/aikime/aik-ime"; miss=$$((miss+1)); fi; \
	else \
		echo "SKIP  $(AGENT_AI)/aikime/aik-ime（librime 不在位，按约定跳过）"; \
	fi; \
	if [ "$$miss" -ne 0 ]; then echo "world: $$miss 件产物缺失，见上方 MISS 行"; exit 1; fi; \
	echo "world: 全部一方用户态件在位"

# ===========================================================================
# make test —— 聚合全部测试，统一汇总；任一红即非零
#   顺序：run_all -> 六套记忆门禁 -> 出厂能力审计（audit_occ_capabilities）
#   注：run_all 自 7126c14 起内含同一个 audit_occ_capabilities --check 门；
#       顶层按其任务书列为独立项再跑一次（1 秒静态检查），便于单看该项判定。
#   不重复的：六套记忆门禁各跑一次（engine 只链接 store 等库，不重跑其测试）。
# ===========================================================================
test:
	@set -u; pass=0; fail=0; failed=""; \
	run() { \
		n=$$1; shift; \
		printf '\n== [test] %s ==\n' "$$n"; \
		if "$$@"; then printf 'PASS  %s\n' "$$n"; pass=$$((pass+1)); \
		else printf 'FAIL  %s\n' "$$n"; fail=$$((fail+1)); failed="$$failed $$n"; fi; \
	}; \
	run run_all bash $(AGENT_AI)/tests/run_all.sh; \
	for d in $(MEM_GATES); do \
		run "mem-$$d" $(MAKE) -C $(AGENT_AI)/$$d -j1 test; \
	done; \
	run audit-occ-capabilities python3 $(AGENT_AI)/tools/audit_occ_capabilities.py --check; \
	printf '\nSUMMARY: pass=%d fail=%d\n' "$$pass" "$$fail"; \
	if [ "$$fail" -ne 0 ]; then printf 'FAILED:%s\n' "$$failed"; exit 1; fi; \
	echo "ALL PASS"

# ===========================================================================
# make check —— 轻量门，不构建
# ===========================================================================
check:
	@echo "== [check] 树宪章（agent/ai/tools/check_tree.sh）=="
	bash $(AGENT_AI)/tools/check_tree.sh
	@echo "== [check] 出厂能力审计（audit_occ_capabilities --check）=="
	python3 $(AGENT_AI)/tools/audit_occ_capabilities.py --check
	@echo "check: 两道门全过"

# ===========================================================================
# make iso —— 打版（真跑由主会话在打版机 root 下串行执行）
#   前置检查全部通过才会往下走；任一不满足即打印指引并非零退出，不做半途写入。
# ===========================================================================
iso: iso-precheck
	python3 $(REFRESH_SCRIPT)
	bash $(ISO_SCRIPT)

iso-precheck:
	@set -e; \
	printf '== [iso] 前置检查（root / 版本单点 / 出厂树可写 / 既有脚本在位）==\n'; \
	if [ "$$(id -u)" != "0" ]; then \
		echo "iso: 需要 root。非 root 下不做任何写入，直接退出。"; \
		echo "iso: 在打版机上执行 'sudo make iso'；且先跑过 'make world'（出厂面按清单审计仓内构建件）。"; \
		exit 1; \
	fi; \
	if [ ! -s "$(VERSION_FILE)" ]; then \
		echo "iso: $(VERSION_FILE) 缺失或为空（版本号单点）"; exit 1; \
	fi; \
	ver=$$(cat "$(VERSION_FILE)"); \
	case "$$ver" in \
		0.1.0-alpha.*) : ;; \
		*) echo "iso: $(VERSION_FILE) 版本串 '$$ver' 不是 0.1.0-alpha.* 形态"; exit 1 ;; \
	esac; \
	if [ ! -d "$(FACTORY_ROOT)" ]; then \
		echo "iso: 出厂树 $(FACTORY_ROOT) 不存在（可用 FACTORY_ROOT=<路径> 覆盖）"; exit 1; \
	fi; \
	if [ ! -w "$(FACTORY_ROOT)" ]; then \
		echo "iso: 出厂树 $(FACTORY_ROOT) 不可写（refresh 要按清单装件）；修正权限或用 root 重跑"; \
		exit 1; \
	fi; \
	[ -f "$(REFRESH_SCRIPT)" ] || { echo "iso: 缺 $(REFRESH_SCRIPT)"; exit 1; }; \
	[ -f "$(ISO_SCRIPT)" ] || { echo "iso: 缺 $(ISO_SCRIPT)"; exit 1; }; \
	echo "iso: 前置通过（root；$(VERSION_FILE)=$$ver；出厂树 $(FACTORY_ROOT) 可写）"

# ===========================================================================
# make clean —— 只清构建产物
#   - 复用各子目录 clean；仓内跟踪的同源锚二进制（occ / aistreamd / aipd）
#     通过命令行变量把 BIN 置空，避免子目录 clean 删掉入库件
#   - aistreamd 的 clean 不覆盖 aik-pqdump（子 Makefile 现状），本层补删
#   - mbedtls 第三方静态库与出厂树一律不动
# ===========================================================================
clean:
	@echo "== [clean] 只清构建产物（不删仓内跟踪二进制/资产，不碰出厂树）=="
	@set -e; \
	for d in store space retrieval smeconfig engine smehttp tlsgw autocondense aikime; do \
		echo "-- clean $(AGENT_AI)/$$d"; \
		$(MAKE) -C $(AGENT_AI)/$$d clean; \
	done; \
	echo "-- clean $(AGENT_AI)（ai / aikernel-shell / aik-sandbox / aik-compat / aik-gcm）"; \
	$(MAKE) -C $(AGENT_AI) clean; \
	echo "-- clean $(AGENT_AI)/occ 构建目录（保留入库同源锚 occ 二进制）"; \
	$(MAKE) -C $(AGENT_AI)/occ clean BIN_OCC=; \
	echo "-- clean $(AGENT_AI)/occ/occ_tui"; \
	$(MAKE) -C $(AGENT_AI)/occ/occ_tui clean; \
	echo "-- clean $(AGENT_AI)/aistreamd 构建目录（保留入库同源锚 aistreamd 二进制）"; \
	$(MAKE) -C $(AGENT_AI)/aistreamd clean BIN=; \
	rm -f $(AGENT_AI)/aistreamd/aik-pqdump; \
	echo "-- clean $(AGENT_AI)/aipd 构建目录（保留入库同源锚 aipd 二进制）"; \
	$(MAKE) -C $(AGENT_AI)/aipd clean BIN=; \
	echo "clean: 完成（mbedtls 第三方库与出厂树未动）"
