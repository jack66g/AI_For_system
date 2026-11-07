#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# durable_drill.sh - occ durable 演练（T9a3 验收 2）
#
# 场景：流式中途 kill -9 → 库中消息状态一致（无半条）→ occ --recover
# 从库重放窗口续跑成功。
#
# LLM 端点 = 本地慢速 mock（OCC_MOCK_SLOW=0.6s/块，给 kill 留流式中途
# 窗口）——occ 二进制走全真代码路径（SQLite 落库/流式消费/recover），
# 仅模型端点为 mock（真调用预算 5 次已耗尽，如实标注）。
set -u
cd "$(dirname "$0")/.." || exit 1          # occ/ 目录

T=$(mktemp -d /tmp/occ_dur.XXXXXX)
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

OCC_MOCK_SLOW=0.6 python3 tests/mock_llm.py "$PORT" "$T" &
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

dbq() {  # dbq <sql> —— 单值查询
    python3 - "$T/sessions.db" "$1" <<'EOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
r = db.execute(sys.argv[2]).fetchone()
print(r[0] if r else "")
EOF
}

# ---- 1) 流式中途 kill -9 ----
./occ -p "durable 演练：这条消息的回复会被中途 kill" > "$T/out" 2>"$T/err" &
OCC_PID=$!
sleep 1.5          # mock 已发出 2 块（1.2s），occ 处于流式中途
kill -9 "$OCC_PID" 2>/dev/null
wait "$OCC_PID" 2>/dev/null
ok "killed occ (pid $OCC_PID) mid-stream"

SID=$(dbq "SELECT id FROM occ_session ORDER BY created DESC LIMIT 1")
[ -n "$SID" ] && ok "session=$SID" || { bad "no session"; exit 1; }

# ---- 2) 库中状态一致（无半条） ----
ST=$(dbq "SELECT status FROM occ_session WHERE id='$SID'")
LAST=$(dbq "SELECT role FROM occ_message WHERE session_id='$SID' ORDER BY created DESC, rowid DESC LIMIT 1")
N=$(dbq "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID'")
[ "$ST" = "running" ] && ok "after-kill status=running" || bad "after-kill status=$ST"
[ "$LAST" = "user" ] && ok "after-kill last-msg=user" || bad "after-kill last=$LAST"
[ "$N" = "1" ] && ok "after-kill msgs=1 (no partial assistant)" || bad "after-kill msgs=$N"

# stdout 已流出部分正文（流式中途证据）——有则记录（不强求字节数）
say "  (partial stdout bytes: $(wc -c < "$T/out"))"

# ---- 3) occ --recover 重放续跑 ----
./occ --recover "$SID" > "$T/out2" 2>"$T/err2"
RC=$?
[ "$RC" -eq 0 ] && ok "recover rc=0" || { bad "recover rc=$RC"; cat "$T/err2"; }
grep -q "冒烟 mock 助手" "$T/out2" && ok "recover-reply-complete" || bad "recover-reply"

ST2=$(dbq "SELECT status FROM occ_session WHERE id='$SID'")
N2=$(dbq "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID'")
NASS=$(dbq "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND role='assistant'")
[ "$ST2" = "active" ] && ok "post-recover status=active" || bad "post-recover status=$ST2"
[ "$N2" = "2" ] && ok "post-recover msgs=2" || bad "post-recover msgs=$N2"
[ "$NASS" = "1" ] && ok "post-recover assistant=1" || bad "post-recover assistant=$NASS"

# user 消息没有被重放复制（content 唯一）
NU=$(dbq "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND role='user'")
[ "$NU" = "1" ] && ok "user-not-duplicated" || bad "user rows=$NU"

say "durable drill: FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
say "durable drill (mock endpoint): ALL GREEN"
