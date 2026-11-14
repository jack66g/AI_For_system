#!/bin/bash
# k10_config_check.sh — K10.2 profile↔树↔代码三方校验（KERNEL-K10A-DESIGN §2 D3）
#
# 三查：
#   1) configs/aikernel_factory.config 与树 .config 的 CONFIG_AIKERNEL* 族
#      逐行一致（漂移=FAIL——profile 是出厂单一事实源）；
#   2) profile 每个符号在 AIKernel/Kconfig 或 agent/ai/Kconfig 有定义；
#   3) profile 每个 =y 符号在 AIKernel/ 源内有行为证据（obj-$/IS_ENABLED/
#      #ifdef 任一命中；零命中=「开着没用」FAIL）。
# 用法: k10_config_check.sh <repo-root> <tree-.config>
set -u
R=${1:?repo root}
C=${2:?tree .config}
P="$R/configs/aikernel_factory.config"
fail=0

[ -f "$P" ] || { echo "FAIL: profile 缺失 $P"; exit 2; }
[ -f "$C" ] || { echo "FAIL: 树 config 缺失 $C"; exit 2; }

tmp=$(mktemp)
grep "^CONFIG_AIKERNEL" "$C" | sort > "$tmp.tree"
grep -E "^CONFIG_AIKERNEL" "$P" | sort > "$tmp.profile"
if ! diff -q "$tmp.tree" "$tmp.profile" > /dev/null; then
	echo "FAIL: profile 与树 config 漂移："
	diff "$tmp.tree" "$tmp.profile" | head -10
	fail=1
else
	echo "OK: profile==tree（$(wc -l < "$tmp.tree") 符号）"
fi

while read -r line; do
	sym="${line%%=*}"
	on="${line##*=}"
	if ! grep -q "config ${sym#CONFIG_}" "$R/AIKernel/Kconfig" \
	   "$R/agent/ai/Kconfig" 2>/dev/null; then
		echo "FAIL: $sym 无 Kconfig 定义"
		fail=1
	fi
	[ "$on" = "y" ] || continue
	if grep -rq -- "$sym" "$R/AIKernel" --include="*.c" --include="Makefile" 2>/dev/null; then
		continue
	fi
	echo "FAIL: $sym =y 但 AIKernel/ 内零行为证据（开着没用）"
	fail=1
done < "$tmp.profile"

rm -f "$tmp.tree" "$tmp.profile"
if [ "$fail" -eq 0 ]; then
	echo "K10-CONFIG: PASS（三方一致，开即有行为）"
else
	echo "K10-CONFIG: FAIL"
fi
exit $fail
