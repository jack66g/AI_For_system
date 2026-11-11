#!/bin/bash
# k0_truth_check.sh — WP-K0 验收 1：真相表覆盖比对（脚本 grep 防漏）
#
# 枚举源内全部钩子符号（AI_HOOK_* 枚举 + ai_*_hook 函数，AIKernel 与
# kernel-overlays 全量）与全部可控参数名（ai_control_register 首参，跨行
# 匹配），逐一对照真相表文件；任一符号缺席 = MISS（FAIL）。
# 计数即本脚本输出，禁止手数。
#
# 用法: k0_truth_check.sh <repo-root> <truth-table.md> [更多表文件...]
set -u
R=${1:?repo root}; shift
[ -d "$R/AIKernel" ] || { echo "FAIL: no $R/AIKernel"; exit 2; }
[ -f "$1" ] || { echo "FAIL: no table $1"; exit 2; }
TFILES="$*"

miss=0; total=0; miss_hooks=""; miss_params=""

# 1) 钩子符号：AI_HOOK_* + ai_*_hook（定义/调用/枚举全算——宁多勿漏）
hooks=$(grep -rhoE -e "\bAI_HOOK_[A-Z0-9_]+" -e "\bai_[a-z0-9_]*_hook\b" \
	   --include="*.c" --include="*.h" \
	   "$R/AIKernel" "$R/kernel-overlays" 2>/dev/null | sort -u)

# 2) 参数名：ai_control_register 首参字符串字面量（-z 跨行匹配注册换行）
params=$(grep -rzohE 'ai_control_register[^"]*"[a-z0-9_.]+"' \
	   --include="*.c" "$R/AIKernel" 2>/dev/null \
	   | tr '\0' '\n' | grep -oE '"[a-z0-9_.]+"' | tr -d '"' \
	   | grep -v '\.h$' | sort -u)

check_one() { # $1=symbol $2=class
	total=$((total + 1))
	if ! grep -qF -- "$1" $TFILES 2>/dev/null; then
		miss=$((miss + 1))
		if [ "$2" = hook ]; then miss_hooks="$miss_hooks $1";
		else miss_params="$miss_params $1"; fi
	fi
}

for s in $hooks; do check_one "$s" hook; done
while IFS= read -r p; do [ -n "$p" ] && check_one "$p" param; done <<< "$params"

echo "hooks_symbols=$(echo "$hooks" | grep -c .)  params_symbols=$(echo "$params" | grep -c .)"
echo "checked=$total  miss=$miss"
[ -n "$miss_hooks" ] && echo "MISS-hooks:$miss_hooks"
[ -n "$miss_params" ] && echo "MISS-params:$miss_params"
if [ "$miss" -eq 0 ]; then
	echo "K0-COVERAGE: PASS（真相表 100% 覆盖）"
else
	echo "K0-COVERAGE: FAIL（上列符号缺席真相表——补行或核实误报后重跑）"
	exit 1
fi
