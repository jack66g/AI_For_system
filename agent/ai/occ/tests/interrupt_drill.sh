#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# interrupt_drill.sh - T9b2 中断重试演练（验收 3：SIGINT + retry 重发）
#
# 场景（mock 一次回两枚 bash 调用：各 sleep 2 写 a.txt/b.txt）：
#   1) SIGINT 于工具执行中途（call_t1 的 sleep 中）→ 安全点语义：
#      当前工具完成后停 → call_t1 真执行、call_t2 合成「未执行」闭合
#      → status=interrupted、尾=tool、无 pending、exit 130
#   2) occ retry --session <id> → 重放（尾=tool 无产出）→ 续跑收口
#      → status=active、回复完整、user 消息不重复
#
# 夹具在 /tmp/occ-b2-drills/interrupt/（授权范围）；mock 127.0.0.2
# （非 loopback 字面量，杜绝 direct 兜底触真网）。
set -u
cd "$(dirname "$0")/.." || exit 1
OCCDIR=$(pwd)

ROOT=/tmp/occ-b2-drills/interrupt
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
mkdir -p "$ROOT" "$ROOT/mock" "$ROOT/wd"
chmod 777 "$ROOT/wd"   # 沙箱内 uid 无 DAC_OVERRIDE（b1 §6-5）

dbq() {
    python3 - "$1" "$2" <<'PYEOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
r = db.execute(sys.argv[2]).fetchone()
print(r[0] if r else "")
PYEOF
}

# pending <db> <sid>
pending() {
    python3 - "$1" "$2" <<'PYEOF'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
sid = sys.argv[2]
last = db.execute(
    "SELECT role,content_json FROM occ_message WHERE session_id=?"
    " ORDER BY created DESC,rowid DESC LIMIT 1", (sid,)).fetchone()
if not last or last[0] != "assistant":
    print(0)
    raise SystemExit
parts = json.loads(last[1])
calls = [p for p in parts if p.get("type") == "toolCall"]
answered = db.execute(
    "SELECT COUNT(*) FROM occ_message WHERE session_id=? AND role='tool'",
    (sid,)).fetchone()[0]
print(max(0, len(calls) - answered))
PYEOF
}

PORT=$((36000 + RANDOM % 4000))
export OCC_MOCK_SLOW=0 OCC_MOCK_TOOL=1 OCC_MOCK_BIND=127.0.0.2
export OCC_LLM_RETRY_BASE_MS=100 OCC_LLM_RETRY_CAP_MS=300
python3 tests/mock_llm.py "$PORT" "$ROOT/mock" &
MOCK_PID=$!
for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.2/"$PORT") 2>/dev/null; then
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

export OCC_DB="$ROOT/sessions.db"
export OCC_MODEL_TOML="$ROOT/model.toml"
export OCC_SNAPROOT="$ROOT/snap"
export OCC_TRACE_DIR="$ROOT/trace"

# ---- 1) SIGINT 于工具执行中途 ----
(
    cd "$ROOT/wd" || exit 1
    exec "$OCCDIR/occ" -p "中断演练：SIGINT 安全点"
) >"$ROOT/run.out" 2>"$ROOT/run.err" &
PID=$!
sleep 1.0                     # 请求1(快) → call_t1 sleep 2 进行中
kill -INT "$PID"
wait "$PID"
RC=$?
[ "$RC" -eq 130 ] && ok "sigint-exit-130" || bad "sigint-exit rc=$RC"
grep -q "interrupted" "$ROOT/run.err" && ok "sigint-stderr-notice" \
    || bad "sigint-stderr-notice"

SID=$(dbq "$OCC_DB" "SELECT id FROM occ_session ORDER BY created DESC LIMIT 1")
[ -n "$SID" ] && ok "session=$SID" || { bad "no session"; exit 1; }

ST=$(dbq "$OCC_DB" "SELECT status FROM occ_session WHERE id='$SID'")
[ "$ST" = "interrupted" ] && ok "status=interrupted" || bad "status=$ST"

LAST=$(dbq "$OCC_DB" "SELECT role FROM occ_message WHERE session_id='$SID' ORDER BY created DESC, rowid DESC LIMIT 1")
[ "$LAST" = "tool" ] && ok "tail=tool" || bad "tail=$LAST"
PEND=$(pending "$OCC_DB" "$SID")
[ "$PEND" = "0" ] && ok "pending=0 (应答不变量)" || bad "pending=$PEND"

# 当前工具真执行完（安全点=当前工具完成后），剩余合成闭合
[ "$(cat "$ROOT/wd/a.txt" 2>/dev/null)" = "KILL-A" ] \
    && ok "tool1-really-executed-a.txt" || bad "tool1 a.txt"
[ ! -e "$ROOT/wd/b.txt" ] && ok "tool2-not-executed" || bad "tool2 executed?"

# toolcall 行对账：call_t1 真跑 rc=0；call_t2 合成 rc=1 且带「未执行」
python3 - "$OCC_DB" "$SID" <<'PYEOF' && ok "toolcall-rows-real+synth" || bad "toolcall-rows"
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
rows = db.execute(
    "SELECT t.tool,t.rc,t.result_json FROM occ_toolcall t"
    " JOIN occ_message m ON m.id=t.message_id WHERE m.session_id=?"
    " ORDER BY t.rowid", (sys.argv[2],)).fetchall()
ok1 = any(r[0] == "bash" and r[1] == 0 for r in rows)
ok2 = any(r[0] == "bash" and r[1] != 0 and "未执行" in (r[2] or "")
          for r in rows)
sys.exit(0 if (len(rows) == 2 and ok1 and ok2) else 1)
PYEOF

# ---- 2) occ retry 重发（尾=tool → 重放，user 不重复） ----
NU1=$(dbq "$OCC_DB" "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND role='user'")
"$OCCDIR/occ" retry --session "$SID" >"$ROOT/retry.out" 2>"$ROOT/retry.err"
RC=$?
[ "$RC" -eq 0 ] && ok "retry rc=0" || { bad "retry rc=$RC"; cat "$ROOT/retry.err"; }
grep -q "occ: retry session" "$ROOT/retry.err" && ok "retry-mode-logged" \
    || bad "retry-mode-logged"
grep -q "冒烟 mock 助手" "$ROOT/retry.out" && ok "retry-reply-complete" \
    || bad "retry-reply"

ST=$(dbq "$OCC_DB" "SELECT status FROM occ_session WHERE id='$SID'")
[ "$ST" = "active" ] && ok "post-retry status=active" || bad "post status=$ST"
NU2=$(dbq "$OCC_DB" "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND role='user'")
[ "$NU1" = "$NU2" ] && ok "user-not-duplicated (replay)" \
    || bad "user $NU1 -> $NU2"
PEND=$(pending "$OCC_DB" "$SID")
[ "$PEND" = "0" ] && ok "post-retry pending=0" || bad "post pending=$PEND"

kill "$MOCK_PID" 2>/dev/null
say "interrupt drill: FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
say "interrupt drill (mock endpoint): ALL GREEN"
