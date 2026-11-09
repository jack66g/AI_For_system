#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# bllm_drill.sh - BLLM 波次 B 演练（B1 旗标/OutputLimit 续跑 + B4
# Retry-After 定向退避；mock 端点，绝不触真网）
#
#   1) B1-default-off：不带 env → 请求体无 parallel_tool_calls 键
#      （缺省关=请求体零变化——差分 62/62 同门）
#   2) B1-flag-on：OCC_PARALLEL_TOOL_CALLS=1 → 请求体含
#      "parallel_tool_calls":true（末位）
#   3) B1-length：OCC_MOCK_LENGTH_FIRST=1 → 恰 2 个请求；第 2 个请求
#      上下文含轮 1 截断正文 LONGPART-A；occ 收口 finish=stop；
#      stdout 两段正文皆流式可见
#   4) B4-ra-valid：429 + Retry-After:1 → RESET 通告含「服务端
#      Retry-After」与 1000ms（不加抖动）；第 2 次成功
#   5) B4-ra-malformed：Retry-After:abc → 回指数基数（300ms±10%），
#      通告不含「服务端 Retry-After」
#   6) B4-ra-huge：Retry-After:3600 + CAP=500 → 钳制 500ms 精确值
#
# 断言尝试次数=mock 落盘 req_*.json 数；夹具 /tmp/occ-bllm-drills/。
# mock 监听 127.0.0.2（非 loopback 字面量——失败场景绝不触发
# forwarder→direct 兜底触真网；retry_drill.sh 同惯例）。
set -u
cd "$(dirname "$0")/.." || exit 1
OCCDIR=$(pwd)

ROOT=/tmp/occ-bllm-drills
FAIL=0
MOCK_PID=""

say() { printf '%s\n' "$*"; }
ok()  { say "ok $*"; }
bad() { say "FAIL $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null
    rm -rf "$ROOT"
}
trap cleanup EXIT

rm -rf "$ROOT"
mkdir -p "$ROOT"

mock_start() { # $1=port $2=reqdir（MOCK_* 环境由调用方 export）
    python3 tests/mock_llm.py "$1" "$2" &
    MOCK_PID=$!
    for _ in $(seq 1 50); do
        if (exec 3<>/dev/tcp/127.0.0.2/"$1") 2>/dev/null; then
            exec 3<&- 3>&-
            break
        fi
        sleep 0.1
    done
}

mock_stop() {
    if [ -n "$MOCK_PID" ]; then
        kill "$MOCK_PID" 2>/dev/null
        wait "$MOCK_PID" 2>/dev/null
        MOCK_PID=""
    fi
}

nreqs() { ls "$1"/req_*.json 2>/dev/null | wc -l | tr -d ' '; }

req_has_key() { # $1=file $2=key
    python3 -c "
import json,sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(2)
sys.exit(0 if (sys.argv[2] in d) else 1)" "$1" "$2"
}

occ_run() { # $1=name $2=port $3=extra_env(空=无) …prompt 固定
    local name=$1 port=$2 xenv=$3
    local dir="$ROOT/$name" toml="$ROOT/$name.toml"

    mkdir -p "$dir"
    mock_start "$port" "$dir"
    cat > "$toml" <<EOF
[models.cloud]
provider_type = "openai_compatible"
model_name = "mock-model"
base_url = "http://127.0.0.2:$port/v1"
api_key = "mock-key-not-real"
EOF
    # shellcheck disable=SC2086
    env OCC_DB="$ROOT/$name.db" OCC_MODEL_TOML="$toml" \
        OCC_SNAPROOT="$ROOT/snap" OCC_TRACE_DIR="$ROOT/trace" \
        OCC_LLM_RETRY_MAX="$RM_MAX" \
        OCC_LLM_RETRY_TIMEOUT_MAX="$RM_TMAX" \
        OCC_LLM_RETRY_BASE_MS="$RM_BASE" \
        OCC_LLM_RETRY_CAP_MS="$RM_CAP" \
        $xenv \
        "$OCCDIR/occ" -p "bllm 演练：$name" \
        >"$ROOT/$name.out" 2>"$ROOT/$name.err"
    mock_stop
}

export OCC_MOCK_SLOW=0 OCC_MOCK_TOOL=0 OCC_MOCK_BIND=127.0.0.2
export OCC_MOCK_ALWAYS_FAIL=0 OCC_MOCK_FAIL_N=0 OCC_MOCK_FAIL_STATUS=503
RM_MAX=3; RM_TMAX=3; RM_BASE=300; RM_CAP=500

# ---- 1) B1 缺省关：请求体无 parallel_tool_calls ----
unset OCC_PARALLEL_TOOL_CALLS
occ_run B1_default_off 37101 ""
[ "$(nreqs "$ROOT/B1_default_off")" = "1" ] \
    && ok "B1-default 1 req" || bad "B1-default req count"
req_has_key "$ROOT/B1_default_off/req_1.json" "parallel_tool_calls" \
    && bad "B1-default body HAS flag (want absent)" \
    || ok "B1-default body omits parallel_tool_calls"
grep -q "冒烟 mock 助手" "$ROOT/B1_default_off.out" \
    && ok "B1-default reply ok" || bad "B1-default reply"

# ---- 2) B1 旗标开：请求体含 "parallel_tool_calls":true（末位） ----
occ_run B1_flag_on 37102 "OCC_PARALLEL_TOOL_CALLS=1"
[ "$(nreqs "$ROOT/B1_flag_on")" = "1" ] \
    && ok "B1-flag 1 req" || bad "B1-flag req count"
req_has_key "$ROOT/B1_flag_on/req_1.json" "parallel_tool_calls" \
    && ok "B1-flag body has key" || bad "B1-flag body missing key"
grep -q '"parallel_tool_calls":true}' "$ROOT/B1_flag_on/req_1.json" \
    && ok "B1-flag true + last position" \
    || bad "B1-flag not true/last (byte gate)"
grep -q "冒烟 mock 助手" "$ROOT/B1_flag_on.out" \
    && ok "B1-flag reply ok" || bad "B1-flag reply"

# ---- 3) B1 OutputLimit 续跑：length 截断 → 续跑 stop ----
export OCC_MOCK_LENGTH_FIRST=1
occ_run B1_length 37103 "OCC_PARALLEL_TOOL_CALLS=1"
unset OCC_MOCK_LENGTH_FIRST
[ "$(nreqs "$ROOT/B1_length")" = "2" ] \
    && ok "B1-length 2 reqs (truncated + continuation)" \
    || bad "B1-length req count=$(nreqs "$ROOT/B1_length")"
grep -q "LONGPART-A" "$ROOT/B1_length/req_2.json" \
    && ok "B1-length round2 ctx has truncated assistant" \
    || bad "B1-length round2 ctx missing LONGPART-A"
grep -q "LONGPART-A" "$ROOT/B1_length.out" \
    && ok "B1-length part1 streamed" || bad "B1-length part1 missing"
grep -q "冒烟 mock 助手" "$ROOT/B1_length.out" \
    && ok "B1-length part2 streamed" || bad "B1-length part2 missing"
grep -q "finish=stop" "$ROOT/B1_length.err" \
    && ok "B1-length final finish=stop" || bad "B1-length final finish"

# ---- 4) B4 Retry-After:1 → 1000ms 定向退避，第 2 次成功 ----
export OCC_MOCK_FAIL_N=1 OCC_MOCK_FAIL_STATUS=429 OCC_MOCK_RETRY_AFTER=1
RM_CAP=2000
occ_run B4_ra_valid 37104 ""
RM_CAP=500
unset OCC_MOCK_RETRY_AFTER OCC_MOCK_FAIL_N OCC_MOCK_FAIL_STATUS
[ "$(nreqs "$ROOT/B4_ra_valid")" = "2" ] \
    && ok "B4-valid 2 reqs (fail→success)" \
    || bad "B4-valid req count=$(nreqs "$ROOT/B4_ra_valid")"
grep -q "服务端 Retry-After：1" "$ROOT/B4_ra_valid.err" \
    && ok "B4-valid RESET cites server header" \
    || bad "B4-valid RESET lacks header citation"
grep -q "将在 1000ms 后重发" "$ROOT/B4_ra_valid.err" \
    && ok "B4-valid exact 1000ms (no jitter)" \
    || bad "B4-valid delay not 1000ms"
grep -q "冒烟 mock 助手" "$ROOT/B4_ra_valid.out" \
    && ok "B4-valid eventual success" || bad "B4-valid no success"

# ---- 5) B4 畸形 Retry-After:abc → 回指数基数（300ms±10% 抖动） ----
export OCC_MOCK_FAIL_N=1 OCC_MOCK_FAIL_STATUS=429 OCC_MOCK_RETRY_AFTER=abc
occ_run B4_ra_malformed 37105 ""
unset OCC_MOCK_RETRY_AFTER OCC_MOCK_FAIL_N OCC_MOCK_FAIL_STATUS
[ "$(nreqs "$ROOT/B4_ra_malformed")" = "2" ] \
    && ok "B4-malformed 2 reqs" \
    || bad "B4-malformed req count"
grep -q "服务端 Retry-After" "$ROOT/B4_ra_malformed.err" \
    && bad "B4-malformed wrongly cited header" \
    || ok "B4-malformed falls back to backoff (no citation)"
MS=$(grep -o "将在 [0-9]*ms 后重发" "$ROOT/B4_ra_malformed.err" | \
     head -1 | grep -o "[0-9]*")
if [ -n "$MS" ] && [ "$MS" -ge 250 ] && [ "$MS" -le 350 ]; then
    ok "B4-malformed jittered base=${MS}ms (300±10%)"
else
    bad "B4-malformed backoff=${MS}ms out of 250..350"
fi
grep -q "冒烟 mock 助手" "$ROOT/B4_ra_malformed.out" \
    && ok "B4-malformed eventual success" || bad "B4-malformed no success"

# ---- 6) B4 过大 Retry-After:3600 + CAP=500 → 钳制 500ms ----
export OCC_MOCK_FAIL_N=1 OCC_MOCK_FAIL_STATUS=503 OCC_MOCK_RETRY_AFTER=3600
occ_run B4_ra_huge 37106 ""
unset OCC_MOCK_RETRY_AFTER OCC_MOCK_FAIL_N OCC_MOCK_FAIL_STATUS
[ "$(nreqs "$ROOT/B4_ra_huge")" = "2" ] \
    && ok "B4-huge 2 reqs" || bad "B4-huge req count"
grep -q "服务端 Retry-After：3600" "$ROOT/B4_ra_huge.err" \
    && ok "B4-huge RESET cites raw header" \
    || bad "B4-huge RESET lacks citation"
grep -q "将在 500ms 后重发" "$ROOT/B4_ra_huge.err" \
    && ok "B4-huge clamped to cap 500ms" \
    || bad "B4-huge not clamped"
grep -q "冒烟 mock 助手" "$ROOT/B4_ra_huge.out" \
    && ok "B4-huge eventual success" || bad "B4-huge no success"

say "bllm drill: FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
say "bllm drill (mock endpoint): ALL GREEN"
