#!/bin/bash
# ci_matrix.sh — G1 CI 编排器（外层；不在 run_all 内防递归）。
# 八段：构建×5 → occ 全套+p-smoke → aistreamd → aipd → 差分 62 →
# run_all（含 68 门）→ fuzz → sbom_check。
# 判据：全段绿 + 总时长 <1800s（CI<30min）；单段失败重试 1 次计 flake。
# 用法: agent/ai/tests/ci_matrix.sh   （在 L1 任意目录可跑）
set -u
ROOT=${1:-$HOME/aikernel-repo-alpha11}
AI="$ROOT/agent/ai"
cd "$AI" || exit 1
pass=0; flake=0; failst=0
t0=$SECONDS

stage() {  # stage <名> <命令...>
    local name=$1; shift
    local rc=0
    "$@" >/tmp/ci-$name.log 2>&1 || rc=$?
    if [ $rc -ne 0 ]; then
        sleep 3
        "$@" >/tmp/ci-$name-retry.log 2>&1 || rc=$?
        [ $rc -eq 0 ] && flake=$((flake+1))
    fi
    if [ $rc -eq 0 ]; then
        echo "STAGE_PASS $name ($((SECONDS - t0))s)"
        pass=$((pass+1))
    else
        echo "STAGE_FAIL $name (see /tmp/ci-$name.log)"
        failst=$((failst+1))
    fi
}

stage occ_build   make -C occ -j1
stage streams_build make -C aistreamd -j1
stage aipd_build  make -C aipd -j1
stage tools_build make aik-compat aik-gcm -j1
stage occ_tests   make -C occ test p-smoke -j1
stage streams_tests make -C aistreamd test -j1
stage aipd_tests  make -C aipd test -j1
stage parity_diff bash -c 'cd ~/aikernel-longterm/parity/vectors/occ && \
    python3 diff_run.py . "$1"' _ "$AI/occ"
stage run_all     bash tests/run_all.sh
stage fuzz        python3 tests/fuzz_parsers.py
stage sbom        bash "$ROOT/build/sbom_check.sh" "$ROOT"

total=$((SECONDS - t0))
stages=$((pass + failst))
budget_ok=1; [ $total -ge 1800 ] && budget_ok=0
echo
echo "CI_SUMMARY stages=$stages pass=$pass fail=$failst flake=$flake" \
     "total=${total}s budget1800s=$budget_ok"
echo "（内核三配置矩阵=K10.4 跑表器/LT soak+集成层=rig 侧，均不占本 CI 预算）"
[ $failst -eq 0 ] && [ $budget_ok -eq 1 ] || exit 1
