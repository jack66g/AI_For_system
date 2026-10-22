#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# test_make_deps.sh - W65 P2 回归：头文件依赖必须真正触发重编
#
# 事故根因：Makefile 里追加的 `$(BUILD_DIR)/%.o: $(wildcard include/*.h)`
# 是与既有 pattern rule 同模式的第二条无 recipe 规则——GNU make 不会合并
# 两条模式规则，该行实际是 no-op。ai_lang.h 新增 TR_SB_* 枚举后
# build/tools/executor.o 未重编，与新 lang.o 混链，tr(TR_SB_CREATED)
# 取到 TR_CMP_TRUNC 文案（sandbox 工具结果首行混入 compact 调试串）。
#
# 本测试在真实构建产物上验证：
#   1. executor.d 记录 include/ai_lang.h 依赖；
#   2. make -n -W include/ai_lang.h build/tools/executor.o 会发出编译命令；
#   3. 子目录头（tools/tool_registry.h）同样进入 .d。

set -u
cd .. || exit 2

fail=0

check_dep() {
	obj="$1"
	hdr="$2"
	dep="${obj%.o}.d"

	if [ ! -f "$obj" ]; then
		echo "SKIP: $obj 不存在（先 make all）"
		return 0
	fi
	if [ ! -f "$dep" ]; then
		echo "FAIL: 缺少依赖文件 $dep（-MMD 未生效）"
		fail=1
		return 1
	fi
	if ! grep -q "$hdr" "$dep"; then
		echo "FAIL: $dep 未记录依赖 $hdr"
		fail=1
		return 1
	fi
	echo "ok: $dep 记录 $hdr"

	out=$(make -n -W "$hdr" "$obj" 2>&1)
	case "$out" in
	*"${obj%.o}.c"*|*"$(basename "${obj%.o}").c"*)
		echo "ok: -W $hdr 触发重编 $obj"
		;;
	*)
		echo "FAIL: -W $hdr 未触发重编 $obj（输出: $out）"
		fail=1
		;;
	esac
}

check_dep build/tools/executor.o include/ai_lang.h
check_dep build/tools/tool_registry.o tools/tool_registry.h

if [ "$fail" -ne 0 ]; then
	echo "test_make_deps: FAIL"
	exit 1
fi
echo "test_make_deps: ALL PASS"
exit 0
