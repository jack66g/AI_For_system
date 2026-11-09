#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# bllm_conc_drill.sh - B2：多进程并发写库压测（occ 会话库 SQLite
# durable 面；T9B2 §8-4 → NEXT-PLAN 波次 B）
#
# 面-under-test：N 个 `occ -p` 进程并发开「各自会话」写「同一共享
# occ 会话库」（OCC_DB 指向同一文件——ORCH-E2 子智能体进程隔离形态
# 的库并发前身）。绝不碰 L1 用户数据：HOME 全程重定向到临时目录 +
# OCC_DB/OCC_SNAPROOT/OCC_TRACE_DIR 指临时夹具。
#
# 阶段：
#   0) 现状核实：busy_timeout（源码 5000）+ journal_mode 实测落账
#   1) 串行基线 N=8（单进程逐个开 8 会话，各 1 轮）
#   2) 并发 N=4 / N=8（同时起，各 1 轮：user+assistant+session 行）
#   3) 零损坏断言：PRAGMA integrity_check=ok + 逐会话重放读回
#      （每会话恰 user+assistant 2 行、assistant 正文=mock 固定回复、
#      finish=stop、tokens_total>0）
#   4) 零锁错断言：所有 stderr 无 'database is locked'/'SQLITE_BUSY'
#   5) 吞吐/锁等待账：并发墙钟 vs 串行墙钟 + 每阶段 rc 全 0
#
# mock 监听 127.0.0.2（同 retry_drill 惯例）；输出 JSON 摘要到
# stdout 末行（供 BLLM-REPORT §7 引数）。
set -u
cd "$(dirname "$0")/.." || exit 1
OCCDIR=$(pwd)

ROOT=/tmp/occ-bllm-conc
FAIL=0
MOCK_PID=""
PORT=37210

say() { printf '%s\n' "$*"; }
ok()  { say "ok $*"; }
bad() { say "FAIL $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null
    rm -rf "$ROOT"
}
trap cleanup EXIT

rm -rf "$ROOT"
mkdir -p "$ROOT/home" "$ROOT/snap" "$ROOT/trace" "$ROOT/reqs"

# HOME 重定向（occ 快照/状态目录全部进临时夹具；不碰 ~/.occ）
export HOME="$ROOT/home"
# mock 绑 127.0.0.2（retry_drill 惯例；失败注入绝不触发 direct 兜底）
export OCC_MOCK_SLOW=0 OCC_MOCK_TOOL=0 OCC_MOCK_BIND=127.0.0.2

python3 tests/mock_llm.py "$PORT" "$ROOT/reqs" &
MOCK_PID=$!
for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.2/$PORT) 2>/dev/null; then
        exec 3<&- 3>&-
        break
    fi
    sleep 0.1
done

cat > "$ROOT/model.toml" <<EOF
[models.cloud]
provider_type = "openai_compatible"
model_name = "mock-model"
base_url = "http://127.0.0.2:$PORT/v1"
api_key = "mock-key-not-real"
EOF

COMMON_ENV="OCC_MODEL_TOML=$ROOT/model.toml OCC_SNAPROOT=$ROOT/snap OCC_TRACE_DIR=$ROOT/trace"

one_turn() { # $1=db $2=tag → rc
    env HOME="$ROOT/home" OCC_DB="$1" $COMMON_ENV \
        "$OCCDIR/occ" -p "并发压测 $2" \
        >"$ROOT/out_$2.$$" 2>"$ROOT/err_$2.$$"
    return $?
}

now_ms() { date +%s%3N; }

# ---- 0) 现状核实：journal_mode + 源码 busy_timeout ----
env HOME="$ROOT/home" OCC_DB="$ROOT/probe.db" $COMMON_ENV \
    "$OCCDIR/occ" -p "探针轮" >/dev/null 2>&1
JMODE=$(python3 -c "
import sqlite3
c = sqlite3.connect('$ROOT/probe.db')
print(c.execute('PRAGMA journal_mode').fetchone()[0])
c.close()")
BTMO=$(python3 -c "
import sqlite3
c = sqlite3.connect('$ROOT/probe.db')
print(c.execute('PRAGMA busy_timeout').fetchone()[0])
c.close()")
say "journal_mode=$JMODE busy_timeout_conn=${BTMO}ms (occ 打开时设 5000，见 session.c:322)"

# ---- 1) 串行基线 N=8 ----
SER_DB="$ROOT/serial.db"
T0=$(now_ms)
for i in $(seq 1 8); do
    one_turn "$SER_DB" "ser$i" || bad "serial run $i rc!=0"
done
T1=$(now_ms)
SER_MS=$((T1 - T0))
say "serial N=8 wall=${SER_MS}ms"

# ---- 2) 并发 N=4 / N=8 ----
CONC_RC_FAIL=0
C4_MS=0
C8_MS=0
run_conc() { # $1=n $2=name → 设 C_MS_* 全局（不经命令替换——子壳丢计数）
    local n=$1 name=$2
    local db="$ROOT/conc_$2.db"
    local t0 t1 i p
    rm -f "$ROOT"/out_"$name".* "$ROOT"/err_"$name".*
    t0=$(now_ms)
    for i in $(seq 1 "$n"); do
        one_turn "$db" "$name$i" &
        pids_conc+=($!)
    done
    for p in "${pids_conc[@]}"; do
        wait "$p" || CONC_RC_FAIL=$((CONC_RC_FAIL + 1))
    done
    t1=$(now_ms)
    if [ "$name" = n4 ]; then C4_MS=$((t1 - t0)); else C8_MS=$((t1 - t0)); fi
}

pids_conc=()
run_conc 4 n4
pids_conc=()
run_conc 8 n8
say "conc N=4 wall=${C4_MS}ms  N=8 wall=${C8_MS}ms (serial N=8=${SER_MS}ms)"
[ "$CONC_RC_FAIL" = "0" ] && ok "all 12 concurrent runs rc=0" \
    || bad "concurrent rc failures=$CONC_RC_FAIL"

# ---- 3/4) 零损坏 + 重放读回 + 零锁错 ----
check_db() { # $1=db $2=want_sessions $3=name
    python3 - "$1" "$2" "$3" <<'PYEOF'
import sqlite3, sys

db, want_sessions, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
c = sqlite3.connect(db)
ig = c.execute("PRAGMA integrity_check").fetchone()[0]
if ig != "ok":
    print(f"FAIL {name} integrity_check={ig}")
    sys.exit(1)
ns = c.execute("SELECT COUNT(*) FROM occ_session").fetchone()[0]
if ns != want_sessions:
    print(f"FAIL {name} sessions={ns} want={want_sessions}")
    sys.exit(1)
rows = c.execute(
    "SELECT session_id, role, content_json, finish FROM occ_message"
    " ORDER BY rowid").fetchall()
if len(rows) != want_sessions * 2:
    print(f"FAIL {name} messages={len(rows)} want={want_sessions * 2}")
    sys.exit(1)
bad_rows = 0
for sid, role, content, finish in rows:
    if role == "user":
        continue
    if finish != "stop":
        bad_rows += 1
    if "冒烟 mock 助手" not in (content or ""):
        bad_rows += 1
if bad_rows:
    print(f"FAIL {name} bad assistant rows={bad_rows}")
    sys.exit(1)
tok = c.execute(
    "SELECT COUNT(*) FROM occ_session WHERE tokens_total > 0").fetchone()[0]
if tok != want_sessions:
    print(f"FAIL {name} sessions with tokens>0: {tok}")
    sys.exit(1)
c.close()
print("ok")
PYEOF
}

for pair in "serial.db:8:serial" "conc_n4.db:4:conc4" "conc_n8.db:8:conc8"; do
    IFS=: read -r d n nm <<<"$pair"
    R=$(check_db "$ROOT/$d" "$n" "$nm")
    if [ "$R" = "ok" ]; then ok "integrity+replay $nm ($n sessions, 2x msgs)"; else bad "$nm: $R"; fi
done

LOCKERR=$(grep -l -i -E "database is locked|SQLITE_BUSY" "$ROOT"/err_* 2>/dev/null | wc -l | tr -d ' ')
[ "$LOCKERR" = "0" ] && ok "zero lock errors across 20 runs" \
    || bad "lock errors in $LOCKERR stderr files"

kill "$MOCK_PID" 2>/dev/null
MOCK_PID=""

say "bllm conc drill: FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
say "METRICS journal=$JMODE serial8_ms=$SER_MS conc4_ms=$C4_MS conc8_ms=$C8_MS"
say "bllm conc drill: ALL GREEN"
