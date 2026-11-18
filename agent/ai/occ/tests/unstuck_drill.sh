#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# unstuck_drill.sh - P-48 轻量解僵演练（CLI 级）
#
# 前置事实：occ_msg_add_user 即置 status=running，环收口（末轮 assistant
# 无 toolCall）才归 active——楔死/强杀落在环中即残留 running，挡
# undo/retry（revert.c running 拒绝）。occ --recover 可解但重放全上下
# 文；occ unstuck 只归位不重放。
#
#   1) 真跑一轮带 bash 工具的对话（mock LLM，interrupt_drill 同款）
#      → 库上直接置回 running（=楔死/强杀残留形态）
#      → occ undo 拒绝：rc!=0 + 文案含 running 与 unstuck 指引（P-48）
#   2) occ unstuck --session <id> → rc 0、状态 interrupted、
#      「已解僵 … 零重放」；tokens/消息数原样（上下文保留的库面证据）
#   3) 幂等诚实：再跑一次 → rc 0「无需解僵」
#   4) 不存在的会话 → rc 1 人话报错
#   5) occ undo：running 挡板解除——拒绝理由从 running 变为正常策略
#      （本夹具为纯 bash 轮无 write 快照 → 「没有文件快照」人话拒绝；
#      带 write 快照的 undo 全绿链在 test_revert U 场景库级证明）
#   6) occ --help 含 unstuck 用法行
#
# 夹具在 /tmp/occ-b2-drills/unstuck/（授权范围）；mock 监听 127.0.0.2
# （非 loopback 字面量——失败场景绝不触发 forwarder→direct 兜底触真网）。
set -u
cd "$(dirname "$0")/.." || exit 1
OCCDIR=$(pwd)

ROOT=/tmp/occ-b2-drills/unstuck
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
mkdir -p "$ROOT/mock" "$ROOT/wd"
chmod 777 "$ROOT/wd"   # 沙箱内 uid 无 DAC_OVERRIDE（b1 §6-5）

dbq() {
    python3 - "$1" "$2" <<'PYEOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
r = db.execute(sys.argv[2]).fetchone()
print(r[0] if r else "")
PYEOF
}

PORT=$((41000 + RANDOM % 4000))
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

# ---- 1) 一轮真 bash 工具对话 → 库上模拟楔死/强杀残留（running） ----
(
    cd "$ROOT/wd" || exit 1
    exec "$OCCDIR/occ" -p "解僵演练：写一轮"
) >"$ROOT/run.out" 2>"$ROOT/run.err"
RC=$?
[ "$RC" -eq 0 ] && ok "turn-rc-0" || { bad "turn rc=$RC"; cat "$ROOT/run.err"; }

SID=$(dbq "$OCC_DB" "SELECT id FROM occ_session ORDER BY created DESC LIMIT 1")
[ -n "$SID" ] && ok "session=$SID" || { bad "no session"; exit 1; }

[ "$(cat "$ROOT/wd/a.txt" 2>/dev/null)" = "KILL-A" ] \
    && ok "tool-really-ran" || bad "tool a.txt missing"

ST=$(dbq "$OCC_DB" "SELECT status FROM occ_session WHERE id='$SID'")
[ "$ST" = "active" ] && ok "turn-finished-active" || bad "post-turn status=$ST"

python3 - "$OCC_DB" "$SID" <<'PYEOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute("UPDATE occ_session SET status='running' WHERE id=?",
           (sys.argv[2],))
db.commit()
PYEOF
ST=$(dbq "$OCC_DB" "SELECT status FROM occ_session WHERE id='$SID'")
[ "$ST" = "running" ] && ok "wedge-status=running" || bad "wedge status=$ST"

TOK_A=$(dbq "$OCC_DB" "SELECT tokens_total FROM occ_session WHERE id='$SID'")
MSG_A=$(dbq "$OCC_DB" "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID'")

# ---- 1b) running 挡 undo + unstuck 指引（P-48 文案） ----
"$OCCDIR/occ" undo --session "$SID" >"$ROOT/undo1.out" 2>"$ROOT/undo1.err"
RC=$?
[ "$RC" -ne 0 ] && ok "undo-blocked-rc" || bad "undo rc=$RC (应拒)"
grep -q "running" "$ROOT/undo1.err" && grep -q "unstuck" "$ROOT/undo1.err" \
    && ok "undo-hint-has-unstuck" || { bad "undo-hint"; cat "$ROOT/undo1.err"; }
ST=$(dbq "$OCC_DB" "SELECT status FROM occ_session WHERE id='$SID'")
[ "$ST" = "running" ] && ok "undo-refusal-not-touch-db" \
    || bad "refusal touched db: $ST"

# ---- 2) occ unstuck：rc 0 + interrupted + 零重放（tokens/消息原样） ----
"$OCCDIR/occ" unstuck --session "$SID" >"$ROOT/unstuck.out" 2>"$ROOT/unstuck.err"
RC=$?
[ "$RC" -eq 0 ] && ok "unstuck-rc-0" || { bad "unstuck rc=$RC"; cat "$ROOT/unstuck.err"; }
grep -q "已解僵" "$ROOT/unstuck.out" && grep -q "interrupted" "$ROOT/unstuck.out" \
    && ok "unstuck-msg" || { bad "unstuck-msg"; cat "$ROOT/unstuck.out"; }
ST=$(dbq "$OCC_DB" "SELECT status FROM occ_session WHERE id='$SID'")
[ "$ST" = "interrupted" ] && ok "status=interrupted" || bad "status=$ST"
TOK_B=$(dbq "$OCC_DB" "SELECT tokens_total FROM occ_session WHERE id='$SID'")
MSG_B=$(dbq "$OCC_DB" "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID'")
[ "$TOK_B" = "$TOK_A" ] && ok "tokens-preserved" \
    || bad "tokens $TOK_A -> $TOK_B"
[ "$MSG_B" = "$MSG_A" ] && ok "msgs-preserved" \
    || bad "msgs $MSG_A -> $MSG_B"

# ---- 3) 幂等诚实：非 running 直言无需解僵（rc 0 不改库） ----
"$OCCDIR/occ" unstuck --session "$SID" >"$ROOT/unstuck2.out" 2>"$ROOT/unstuck2.err"
RC=$?
[ "$RC" -eq 0 ] && grep -q "无需解僵" "$ROOT/unstuck2.out" \
    && ok "unstuck-idempotent" \
    || { bad "idempotent rc=$RC"; cat "$ROOT/unstuck2.out" "$ROOT/unstuck2.err"; }

# ---- 4) 不存在的会话 → rc 1 人话 ----
"$OCCDIR/occ" unstuck --session "ses_0000000000000000000000000000dead" \
    >"$ROOT/unstuck3.out" 2>"$ROOT/unstuck3.err"
RC=$?
[ "$RC" -eq 1 ] && grep -q "不存在" "$ROOT/unstuck3.err" \
    && ok "unstuck-nonexistent" \
    || { bad "nonexistent rc=$RC"; cat "$ROOT/unstuck3.err"; }

# ---- 5) undo：running 挡板解除（拒绝理由换为正常快照策略，非 running） ----
"$OCCDIR/occ" undo --session "$SID" >"$ROOT/undo2.out" 2>"$ROOT/undo2.err"
RC=$?
if [ "$RC" -ne 0 ] && grep -q "快照" "$ROOT/undo2.err" \
    && ! grep -q "正在执行" "$ROOT/undo2.err"; then
    ok "undo-running-gate-lifted"
elif [ "$RC" -eq 0 ]; then
    ok "undo-running-gate-lifted (rc 0)"
else
    bad "undo2 rc=$RC"; cat "$ROOT/undo2.err"
fi

# ---- 6) --help 含 unstuck 用法行 ----
"$OCCDIR/occ" --help >"$ROOT/help.out" 2>&1
grep -q "unstuck" "$ROOT/help.out" && ok "help-has-unstuck" \
    || { bad "help-missing-unstuck"; cat "$ROOT/help.out"; }

if [ "$FAIL" -eq 0 ]; then
    say "unstuck_drill: ALL GREEN"
else
    say "unstuck_drill: $FAIL FAIL"
fi
exit "$FAIL"
