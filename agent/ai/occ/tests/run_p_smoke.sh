#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# run_p_smoke.sh - `occ -p` 端到端冒烟（本地 mock LLM；仅测试，明标）
#
# 1) mock_llm.py 起本地 http（回放固定 SSE；请求体落盘供断言）
# 2) 临时 model.toml（base_url 指向 mock）+ 临时 OCC_DB
# 3) occ -p 第一轮 → 断言 stdout 流式回复 + exit 0
# 4) occ -p --session <id> 第二轮 → 断言 mock 收到的请求含第一轮
#    历史（历史组装生效）+ system prompt 进请求
# 5) 库断言：2 轮 = 4 条消息、tokens_total 累计、状态 active
set -u
cd "$(dirname "$0")/.." || exit 1          # occ/ 目录

T=$(mktemp -d /tmp/occ_psmoke.XXXXXX)
PORT=$(( 20000 + RANDOM % 20000 ))
FAIL=0

say() { printf '%s\n' "$*"; }
ok()  { say "ok $*"; }
bad() { say "FAIL $*"; FAIL=$((FAIL+1)); }

cleanup() {
    [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT

python3 tests/mock_llm.py "$PORT" "$T" &
MOCK_PID=$!
for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then
        exec 3<&- 3>&-
        break
    fi
    sleep 0.1
done

cat > "$T/model.toml" <<EOF
[models.cloud]
provider_type = "openai_compatible"
model_name = "mock-model"
base_url = "http://127.0.0.1:$PORT/v1"
api_key = "mock-key-not-real"
EOF

export OCC_MODEL_TOML="$T/model.toml"
export OCC_DB="$T/sessions.db"

# ---- 第一轮 ----
OUT1=$(./occ -p "第一句：请记住暗号 abc123" 2>"$T/err1")
RC1=$?
[ "$RC1" -eq 0 ] && ok "p-smoke-turn1-rc0" || bad "p-smoke-turn1-rc=$RC1"
echo "$OUT1" | grep -q "冒烟 mock 助手" && ok "p-smoke-turn1-reply" \
    || bad "p-smoke-turn1-reply-missing"

# ---- session id（python 直查库） ----
SID=$(python3 - "$T/sessions.db" <<'EOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
r = db.execute("SELECT id FROM occ_session ORDER BY created DESC LIMIT 1").fetchone()
print(r[0] if r else "")
EOF
)
[ -n "$SID" ] && ok "p-smoke-session-id=$SID" || bad "p-smoke-no-session"

# ---- 第二轮（续接） ----
OUT2=$(./occ -p "第二句：暗号是什么" --session "$SID" 2>"$T/err2")
RC2=$?
[ "$RC2" -eq 0 ] && ok "p-smoke-turn2-rc0" || bad "p-smoke-turn2-rc=$RC2"

# mock 收到的第二个请求体：含第一轮 user 文本 + system prompt
python3 - "$T" "$SID" <<'EOF' && ok "p-smoke-history-in-req" || bad "p-smoke-history-in-req"
import json, sys
tdir, sid = sys.argv[1], sys.argv[2]
req2 = json.load(open(f"{tdir}/req_2.json"))
msgs = " ".join(m.get("content") or "" for m in req2["messages"])
sys.exit(0 if ("abc123" in msgs and req2.get("messages")) else 1)
EOF
python3 - "$T" <<'EOF' && ok "p-smoke-system-in-req" || bad "p-smoke-system-in-req"
import json, sys
req1 = json.load(open(f"{sys.argv[1]}/req_1.json"))
sys.exit(0 if req1.get("messages") and req1["messages"][0]["role"] == "system"
         and "occ" in req1["messages"][0]["content"] else 1)
EOF

# ---- 库断言 ----
python3 - "$T/sessions.db" "$SID" <<'EOF' && ok "p-smoke-db-4msgs" || bad "p-smoke-db-4msgs"
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
n = db.execute("SELECT COUNT(*) FROM occ_message WHERE session_id=?",
               (sys.argv[2],)).fetchone()[0]
sys.exit(0 if n == 4 else 1)
EOF
python3 - "$T/sessions.db" "$SID" <<'EOF' && ok "p-smoke-db-tokens-status" || bad "p-smoke-db-tokens-status"
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
tok, st = db.execute(
    "SELECT tokens_total, status FROM occ_session WHERE id=?",
    (sys.argv[2],)).fetchone()
sys.exit(0 if (tok == 100 and st == "active") else 1)
EOF

# ---- sessions 子命令 ----
./occ sessions > "$T/list" 2>&1 && grep -q "$SID" "$T/list" \
    && ok "p-smoke-sessions-cmd" || bad "p-smoke-sessions-cmd"

say "p-smoke: $((10 - FAIL)) ok assertions / FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
say "occ -p smoke (mock): ALL GREEN"
