#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# retry_drill.sh - T9b2 传输层自动重试矩阵演练（验收 3；OCD §7.2 数值）
#
#   A) 第 N 次成功：前 2 个请求 503 → 第 3 次成功（MAX=3，退避毫秒级）
#   B) 永不成功封顶：全 503 → 恰 MAX=3 次尝试后人话报错
#   C) 超时类上限独立：全 408 → 恰 TIMEOUT_MAX=2 次（与 MAX=99 无关）
#   D) 4xx 不重试：全 401 → 恰 1 次尝试立即报错
#
# 断言尝试次数=mock 落盘的 req_*.json 数；重试通告（OCC_EV_RESET→
# stderr）在 A 可见。夹具在 /tmp/occ-b2-drills/retry/；mock 监听
# 127.0.0.2（非 loopback 字面量——失败场景绝不触发 forwarder→direct
# 兜底触真网）；OCC_LLM_RETRY_* 毫秒级参数族（产品配置族，非后门）。
set -u
cd "$(dirname "$0")/.." || exit 1
OCCDIR=$(pwd)

ROOT=/tmp/occ-b2-drills/retry
FAIL=0
MOCK_PID=""

say() { printf '%s\n' "$*"; }
ok()  { say "ok $*"; }
bad() { say "FAIL $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
    rm -rf "$ROOT" 2>/dev/null
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

nreqs() { # $1=reqdir
    ls "$1"/req_*.json 2>/dev/null | wc -l | tr -d ' '
}

# scenario <name> <fail_env...> 由调用方 export 后调用 run_case
# run_case <name> <port> <expect_rc> <expect_reqs> <grep_pattern> <grep_file>
run_case() {
    local name=$1 port=$2 want_rc=$3 want_reqs=$4 pat=$5
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
    OCC_DB="$ROOT/$name.db" OCC_MODEL_TOML="$toml" \
        OCC_SNAPROOT="$ROOT/snap" OCC_TRACE_DIR="$ROOT/trace" \
        OCC_LLM_RETRY_MAX="$RM_MAX" \
        OCC_LLM_RETRY_TIMEOUT_MAX="$RM_TMAX" \
        OCC_LLM_RETRY_BASE_MS="$RM_BASE" \
        OCC_LLM_RETRY_CAP_MS="$RM_CAP" \
        "$OCCDIR/occ" -p "重试矩阵：$name" \
        >"$ROOT/$name.out" 2>"$ROOT/$name.err"
    local rc=$?
    local reqs
    reqs=$(nreqs "$dir")
    [ "$rc" -eq "$want_rc" ] && ok "$name rc=$rc" || {
        bad "$name rc=$rc (want $want_rc)"
        sed -n '1,5p' "$ROOT/$name.err"
    }
    [ "$reqs" = "$want_reqs" ] && ok "$name attempts=$reqs" \
        || bad "$name attempts=$reqs (want $want_reqs)"
    grep -q "$pat" "$ROOT/$name.err" && ok "$name stderr has '$pat'" \
        || { bad "$name stderr missing '$pat'"; sed -n '1,8p' "$ROOT/$name.err"; }
    mock_stop
}

export OCC_MOCK_SLOW=0 OCC_MOCK_TOOL=0 OCC_MOCK_BIND=127.0.0.2

# ---- A) 第 3 次成功（503×2 → 200） ----
export OCC_MOCK_ALWAYS_FAIL=0 OCC_MOCK_FAIL_N=2 OCC_MOCK_FAIL_STATUS=503
RM_MAX=3 RM_TMAX=3 RM_BASE=50 RM_CAP=100
run_case "A_third_try_success" 37001 0 3 "重试" "$ROOT/A_third_try_success.err"
grep -q "冒烟 mock 助手" "$ROOT/A_third_try_success.out" \
    && ok "A reply-complete" || bad "A reply-complete"

# ---- B) 永不成功封顶（全 503，MAX=3） ----
export OCC_MOCK_ALWAYS_FAIL=1 OCC_MOCK_FAIL_N=0 OCC_MOCK_FAIL_STATUS=503
RM_MAX=3 RM_TMAX=3 RM_BASE=50 RM_CAP=100
run_case "B_capped_503" 37002 1 3 "HTTP 503" "$ROOT/B_capped_503.err"

# ---- C) 超时类上限独立（全 408，TIMEOUT_MAX=2，MAX=99） ----
export OCC_MOCK_ALWAYS_FAIL=1 OCC_MOCK_FAIL_STATUS=408
RM_MAX=99 RM_TMAX=2 RM_BASE=50 RM_CAP=100
run_case "C_timeout_class_cap" 37003 1 2 "HTTP 408" \
    "$ROOT/C_timeout_class_cap.err"

# ---- D) 401 不重试（立即人话报错，恰 1 次） ----
export OCC_MOCK_ALWAYS_FAIL=1 OCC_MOCK_FAIL_STATUS=401
RM_MAX=99 RM_TMAX=99 RM_BASE=50 RM_CAP=100
run_case "D_401_no_retry" 37004 1 1 "HTTP 401" "$ROOT/D_401_no_retry.err"

say "retry drill: FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
say "retry drill (mock endpoint): ALL GREEN"
