#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# W64 并发寿命测试：N 并发 × R 轮 create → run → status → destroy。
# 每轮结束后检查 /sandbox 残留、挂载残留、run 进程残留、cgroup 残留。
#
# 用法: ./concurrency.sh [rounds] [workers]   （默认 3 10）
# 退出码：有失败/残留 = 1。
set -u

CDIR=$(cd "$(dirname "$0")" && pwd)
SB="${SB_BIN:-$CDIR/aik-sandbox}"
BASE="${W64_BASE:-/sandbox}"
ART="${W64_ART:-/tmp/w64-artifacts}"
ROUNDS="${1:-3}"
WORKERS="${2:-10}"
export AIKERNEL_SANDBOX_BASE="$BASE"
export AIKERNEL_SANDBOX_ARTIFACTS="$ART"

CGP="/sys/fs/cgroup/aik-sandbox"
LOG=$(mktemp /tmp/w64-conc-XXXXXX.log)
Cycles=0
Ok=0
Fail=0

worker() {
	local r=$1 i=$2 n="w64c-$1-$2"

	"$SB" create "$n" --cpus 0.5 --mem-mb 256 --pids 64 >>"$LOG" 2>&1 || return 1
	"$SB" run "$n" -- /bin/sh -c "echo worker-$r-$i; sleep 0.2" >>"$LOG" 2>&1 || return 1
	"$SB" status >>"$LOG" 2>&1 || return 1
	"$SB" destroy "$n" >>"$LOG" 2>&1 || return 1
	return 0
}

echo "CONCURRENCY: rounds=$ROUNDS workers=$WORKERS"
t0=$(date +%s%N)
for r in $(seq 1 "$ROUNDS"); do
	pids=()
	for i in $(seq 1 "$WORKERS"); do
		worker "$r" "$i" &
		pids+=("$!")
	done
	for p in "${pids[@]}"; do
		Cycles=$((Cycles + 1))
		if wait "$p"; then
			Ok=$((Ok + 1))
		else
			Fail=$((Fail + 1))
		fi
	done
	echo "  round $r: ok=$Ok fail=$Fail"
done
t1=$(date +%s%N)

# ---- 残留检查（只针对本次测试的 w64c-* 命名） ----
res_dir=$(find "$BASE" -mindepth 1 -maxdepth 1 -name 'w64c-*' 2>/dev/null | wc -l)
res_mnt=$(grep -c "$BASE/w64c-" /proc/self/mountinfo 2>/dev/null || true)
res_proc=$(pgrep -f 'aik-sandbox run w64c-' 2>/dev/null | wc -l)
res_cg=$(find "$CGP" -mindepth 1 -maxdepth 1 -name 'w64c-*' 2>/dev/null | wc -l)
anchor=$(cat "$CGP/cgroup.procs" 2>/dev/null | wc -l)

echo "RESIDUAL: dir=$res_dir mount=$res_mnt proc=$res_proc cgroup=$res_cg anchor_procs=$anchor"
echo "CONCURRENCY: cycles=$Cycles ok=$Ok fail=$Fail elapsed_ms=$(((t1 - t0) / 1000000))"

if [ "$Fail" -ne 0 ] || [ "$res_dir" -ne 0 ] || [ "$res_mnt" -ne 0 ] ||
   [ "$res_proc" -ne 0 ] || [ "$res_cg" -ne 0 ] || [ "$anchor" -ne 0 ]; then
	echo "VERDICT: FAIL（日志 $LOG）"
	exit 1
fi
echo "VERDICT: ALL PASS"
rm -f "$LOG"
exit 0
