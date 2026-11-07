#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# recover_drill.sh - T9b2 恢复演练（验收 1：≥2 个不同 kill 阶段）
#
#   阶段 A：kill -9 于 LLM 流式中途 → occ --recover 续跑
#   阶段 B：kill -9 于工具执行中途（bash sleep 2 批）→ occ --recover 续跑
# 每阶段与「不间断跑」对拍：产物文件逐字节一致 + 最终 assistant 文本
# 一致 + 库状态一致（status/消息数/无 pending/用户消息不重复）。
#
# 夹具全在 /tmp/occ-b2-drills/recover/（授权范围）；LLM=本地 mock（明标，
# 非真网）。mock 监听 127.0.0.2——非 loopback 字面量，杜绝 occ 的
# forwarder→direct 兜底触真网。bash 工具经 aik-sandbox（sudo -n 组装）。
set -u
cd "$(dirname "$0")/.." || exit 1
OCCDIR=$(pwd)

ROOT=/tmp/occ-b2-drills/recover
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
mkdir -p "$ROOT" "$ROOT/ra" "$ROOT/rb"

# dbq <db> <sql> —— 单值查询
dbq() {
    python3 - "$1" "$2" <<'PYEOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
r = db.execute(sys.argv[2]).fetchone()
print(r[0] if r else "")
PYEOF
}

mock_start() { # $1=port $2=reqdir；MOCK_* 环境由调用方先 export
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

mk_toml() { # $1=port $2=path
    cat > "$2" <<EOF
[models.cloud]
provider_type = "openai_compatible"
model_name = "mock-model"
base_url = "http://127.0.0.2:$1/v1"
api_key = "mock-key-not-real"
EOF
}

# run_occ <db> <toml> <cwd> <args...>（带 timeout，用于非 kill 目标）
run_occ() {
    local db=$1 toml=$2 wd=$3
    shift 3
    (cd "$wd" && OCC_DB="$db" OCC_MODEL_TOML="$toml" \
        OCC_SNAPROOT="$ROOT/snap" OCC_TRACE_DIR="$ROOT/trace" \
        timeout -k 3 90 "$OCCDIR/occ" "$@")
}

# run_occ_bg <db> <toml> <cwd> <out> <err> <args...> —— 后台直启（exec 换
# 像：$! 即 occ 本体，kill -9 打的就是它；不套 timeout——timeout 不转发
# SIGKILL 会留下孤儿 occ）
run_occ_bg() {
    local db=$1 toml=$2 wd=$3 outf=$4 errf=$5
    shift 5
    (
        cd "$wd" || exit 1
        export OCC_DB="$db" OCC_MODEL_TOML="$toml"
        export OCC_SNAPROOT="$ROOT/snap" OCC_TRACE_DIR="$ROOT/trace"
        exec "$OCCDIR/occ" "$@"
    ) >"$outf" 2>"$errf" &
    BG_PID=$!
}

# pending <db> <sid> —— 末位 assistant 未应答调用数
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

# assistant_text <db> <sid>
assistant_text() {
    python3 - "$1" "$2" <<'PYEOF'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute(
    "SELECT content_json FROM occ_message WHERE session_id=? AND role='assistant'"
    " ORDER BY created DESC,rowid DESC LIMIT 1", (sys.argv[2],)).fetchone()
parts = json.loads(row[0]) if row else []
print("".join(p.get("text", "") for p in parts if p.get("type") == "text"))
PYEOF
}

# ============================================================
say "== 阶段 A：kill -9 于 LLM 流式中途 =="
PORTA=$((21000 + RANDOM % 5000))
export OCC_MOCK_SLOW=0.6 OCC_MOCK_TOOL=0 OCC_MOCK_BIND=127.0.0.2
# 失败快速收敛（成功路径不受影响）：诊断窗口用毫秒级退避
export OCC_LLM_RETRY_BASE_MS=100 OCC_LLM_RETRY_CAP_MS=300
mock_start "$PORTA" "$ROOT/ra"
mk_toml "$PORTA" "$ROOT/model_a.toml"

DBA_K="$ROOT/a_killed.db"
mkdir -p "$ROOT/a_wd_killed"
chmod 777 "$ROOT/a_wd_killed"   # 沙箱内 uid 无 DAC_OVERRIDE（b1 §6-5）
run_occ_bg "$DBA_K" "$ROOT/model_a.toml" "$ROOT/a_wd_killed" \
    "$ROOT/a_k.out" "$ROOT/a_k.err" -p "阶段A：流式中途 kill 的消息"
PID=$BG_PID
sleep 1.5                     # mock 慢流（0.6s/块）——流式中途
kill -9 "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
ok "A killed occ (pid $PID) mid-stream"

SID=$(dbq "$DBA_K" "SELECT id FROM occ_session ORDER BY created DESC LIMIT 1")
[ -n "$SID" ] && ok "A session=$SID" || { bad "A no session"; exit 1; }
ST=$(dbq "$DBA_K" "SELECT status FROM occ_session WHERE id='$SID'")
LAST=$(dbq "$DBA_K" "SELECT role FROM occ_message WHERE session_id='$SID' ORDER BY created DESC, rowid DESC LIMIT 1")
N=$(dbq "$DBA_K" "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID'")
[ "$ST" = "running" ] && ok "A after-kill status=running" || bad "A status=$ST"
[ "$LAST" = "user" ] && ok "A after-kill last=user" || bad "A last=$LAST"
[ "$N" = "1" ] && ok "A after-kill msgs=1 (no partial)" || bad "A msgs=$N"

run_occ "$DBA_K" "$ROOT/model_a.toml" "$ROOT/a_wd_killed" \
    --recover "$SID" >"$ROOT/a_r.out" 2>"$ROOT/a_r.err"
RC=$?
[ "$RC" -eq 0 ] && ok "A recover rc=0" || { bad "A recover rc=$RC"; cat "$ROOT/a_r.err"; }
grep -q "冒烟 mock 助手" "$ROOT/a_r.out" && ok "A recover-reply-complete" \
    || bad "A recover-reply"
ST=$(dbq "$DBA_K" "SELECT status FROM occ_session WHERE id='$SID'")
N2=$(dbq "$DBA_K" "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID'")
NU=$(dbq "$DBA_K" "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND role='user'")
[ "$ST" = "active" ] && ok "A post status=active" || bad "A post status=$ST"
[ "$N2" = "2" ] && ok "A post msgs=2" || bad "A post msgs=$N2"
[ "$NU" = "1" ] && ok "A user-not-duplicated" || bad "A user rows=$NU"

# 不间断基线（同 mock，普通模式不受计数影响）
DBA_B="$ROOT/a_base.db"
mkdir -p "$ROOT/a_wd_base"
run_occ "$DBA_B" "$ROOT/model_a.toml" "$ROOT/a_wd_base" \
    -p "阶段A：流式中途 kill 的消息" >"$ROOT/a_b.out" 2>"$ROOT/a_b.err"
RC=$?
[ "$RC" -eq 0 ] && ok "A baseline rc=0" || bad "A baseline rc=$RC"
SIDB=$(dbq "$DBA_B" "SELECT id FROM occ_session ORDER BY created DESC LIMIT 1")

# 对拍：最终 assistant 文本 + tokens 一致
python3 - "$DBA_K" "$SID" "$DBA_B" "$SIDB" <<'PYEOF' && ok "A 对拍 assistant+tokens 一致" || bad "A 对拍不一致"
import sqlite3, sys
def snap(dbf, sid):
    db = sqlite3.connect(dbf)
    txt = db.execute(
        "SELECT content_json FROM occ_message WHERE session_id=? AND role='assistant'"
        " ORDER BY created DESC,rowid DESC LIMIT 1", (sid,)).fetchone()[0]
    tok = db.execute("SELECT tokens_total FROM occ_session WHERE id=?",
                     (sid,)).fetchone()[0]
    return txt, tok
a, ta = snap(sys.argv[1], sys.argv[2])
b, tb = snap(sys.argv[3], sys.argv[4])
sys.exit(0 if (a == b and ta == tb) else 1)
PYEOF
mock_stop

# ============================================================
say "== 阶段 B：kill -9 于工具执行中途（bash sleep 2 批） =="
PORTB=$((26000 + RANDOM % 5000))
export OCC_MOCK_SLOW=0 OCC_MOCK_TOOL=1 OCC_MOCK_BIND=127.0.0.2
mock_start "$PORTB" "$ROOT/rb"
mk_toml "$PORTB" "$ROOT/model_b.toml"

DBB_K="$ROOT/b_killed.db"
mkdir -p "$ROOT/b_wd_killed"
chmod 777 "$ROOT/b_wd_killed"
run_occ_bg "$DBB_K" "$ROOT/model_b.toml" "$ROOT/b_wd_killed" \
    "$ROOT/b_k.out" "$ROOT/b_k.err" -p "阶段B：工具执行中途 kill"
PID=$BG_PID
sleep 1.0                     # 请求1(快)→assistant 落库→bash t1 sleep 2 中
kill -9 "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
ok "B killed occ (pid $PID) mid-tool"

SID=$(dbq "$DBB_K" "SELECT id FROM occ_session ORDER BY created DESC LIMIT 1")
[ -n "$SID" ] && ok "B session=$SID" || { bad "B no session"; exit 1; }
ST=$(dbq "$DBB_K" "SELECT status FROM occ_session WHERE id='$SID'")
LAST=$(dbq "$DBB_K" "SELECT role FROM occ_message WHERE session_id='$SID' ORDER BY created DESC, rowid DESC LIMIT 1")
PEND=$(pending "$DBB_K" "$SID")
[ "$ST" = "running" ] && ok "B after-kill status=running" || bad "B status=$ST"
[ "$LAST" = "assistant" ] && ok "B after-kill last=assistant(toolCall)" || bad "B last=$LAST"
[ "$PEND" = "2" ] && ok "B after-kill pending=2" || bad "B pending=$PEND"

run_occ "$DBB_K" "$ROOT/model_b.toml" "$ROOT/b_wd_killed" \
    --recover "$SID" >"$ROOT/b_r.out" 2>"$ROOT/b_r.err"
RC=$?
[ "$RC" -eq 0 ] && ok "B recover rc=0" || { bad "B recover rc=$RC"; cat "$ROOT/b_r.err"; }
grep -q "冒烟 mock 助手" "$ROOT/b_r.out" && ok "B recover-reply-complete" \
    || bad "B recover-reply"
ST=$(dbq "$DBB_K" "SELECT status FROM occ_session WHERE id='$SID'")
PEND=$(pending "$DBB_K" "$SID")
[ "$ST" = "active" ] && ok "B post status=active" || bad "B post status=$ST"
[ "$PEND" = "0" ] && ok "B post pending=0 (闭合)" || bad "B post pending=$PEND"
NU=$(dbq "$DBB_K" "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND role='user'")
[ "$NU" = "1" ] && ok "B user-not-duplicated" || bad "B user rows=$NU"
[ "$(cat "$ROOT/b_wd_killed/a.txt" 2>/dev/null)" = "KILL-A" ] \
    && ok "B product a.txt" || bad "B product a.txt"
[ "$(cat "$ROOT/b_wd_killed/b.txt" 2>/dev/null)" = "KILL-B" ] \
    && ok "B product b.txt" || bad "B product b.txt"

# 不间断基线（重启 mock 归零计数：TOOL 模式只在 n==1 触发）
mock_stop
export OCC_MOCK_SLOW=0 OCC_MOCK_TOOL=1 OCC_MOCK_BIND=127.0.0.2
PORTB2=$((31000 + RANDOM % 5000))
mkdir -p "$ROOT/rb2"
mock_start "$PORTB2" "$ROOT/rb2"
mk_toml "$PORTB2" "$ROOT/model_b2.toml"
DBB_B="$ROOT/b_base.db"
mkdir -p "$ROOT/b_wd_base"
chmod 777 "$ROOT/b_wd_base"
run_occ "$DBB_B" "$ROOT/model_b2.toml" "$ROOT/b_wd_base" \
    -p "阶段B：工具执行中途 kill" >"$ROOT/b_b.out" 2>"$ROOT/b_b.err"
RC=$?
[ "$RC" -eq 0 ] && ok "B baseline rc=0" || { bad "B baseline rc=$RC"; cat "$ROOT/b_b.err"; }
SIDB=$(dbq "$DBB_B" "SELECT id FROM occ_session ORDER BY created DESC LIMIT 1")

# 对拍：产物逐字节 + 最终 assistant 文本 + 工具行数一致
for f in a.txt b.txt; do
    if cmp -s "$ROOT/b_wd_killed/$f" "$ROOT/b_wd_base/$f"; then
        ok "B 对拍 $f 逐字节一致"
    else
        bad "B 对拍 $f 不一致"
    fi
done
python3 - "$DBB_K" "$SID" "$DBB_B" "$SIDB" <<'PYEOF' && ok "B 对拍 assistant+toolcalls 一致" || bad "B 对拍不一致"
import sqlite3, sys
def snap(dbf, sid):
    db = sqlite3.connect(dbf)
    txt = db.execute(
        "SELECT content_json FROM occ_message WHERE session_id=? AND role='assistant'"
        " ORDER BY created DESC,rowid DESC LIMIT 1", (sid,)).fetchone()[0]
    ntc = db.execute(
        "SELECT COUNT(*),SUM(rc) FROM occ_toolcall t"
        " JOIN occ_message m ON m.id=t.message_id WHERE m.session_id=?",
        (sid,)).fetchone()
    st = db.execute("SELECT status FROM occ_session WHERE id=?",
                    (sid,)).fetchone()[0]
    return txt, ntc, st
a, ta, sa = snap(sys.argv[1], sys.argv[2])
b, tb, sb = snap(sys.argv[3], sys.argv[4])
sys.exit(0 if (a == b and ta == tb and sa == sb == "active") else 1)
PYEOF
mock_stop

say "recover drill: FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
say "recover drill (mock endpoint): ALL GREEN"
