#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# orch_drill.sh - ORCH-E9 回路演练：headless「派发-验收-回炉-压缩-蒸馏」
# 全回路剧本（mock 三角色 LLM + mock autocondense REST；仅测试，明标）
#
# 时序（角色×步骤；主控经 task 第七工具——OCC_ORCH_TOOLS=1）：
#   occ -p 主控    task spawn（brief 含机检令牌验收）→ 子·首报进程起
#   occ -p 子·首报 纯文本自称完成（零证据零工具）→ 终局 collect
#                  in_review + 机械预判 fail
#   occ -p 主控    wait → read_result → return(拒) → 机械判拒+整改词
#                  → 任务 rework（E4「一拒」）
#   test_orch      --e9-redrive：等 rework → C API occ_orch_spawn
#                  (task_id) 真路再派（工具面无再派参数——产品缺口
#                  测试侧桥）→ 子·二报进程起
#   occ -p 子·二报 write×2（产物 out_e9.bin + 结果文件 # VERDICT 表）
#                  → 终局 collect in_review + 机械预判 pass（「一改」）
#   occ -p 主控    [回炉窗：mock 轮询库等 in_review] → wait →
#                  read_result → return(过) → 机械判全过 → done（「一过」）
#                  → E5 蒸馏+E6 子会话 archived+E7 记账 → 收队文本
#   ac 链（同 occ -p 收口）force 压缩：session/start → begin → digest
#                  （mock 压缩角色）→ commit（快照读回）→ 换窗注记
#
# 断言：SQLite 直查（p-smoke python 模式）+ mock 日志（roles.log/
# ac_routes.log）+ 产物/报告文件；失败退非零；清理自身临时物。
set -u
cd "$(dirname "$0")/.." || exit 1          # occ/ 目录

OCCROOT=$PWD
OCCBIN=$OCCROOT/occ
TESTORCH=$OCCROOT/tests/test_orch
[ -x "$OCCBIN" ] || { echo "FAIL occ 未构建（先 make）"; exit 1; }
[ -x "$TESTORCH" ] || { echo "FAIL tests/test_orch 未构建（先 make）"; exit 1; }

T=$(mktemp -d /tmp/occ_e9_drill.XXXXXX)
PORT=$(( 20000 + RANDOM % 20000 ))
DB=$T/sessions.db
FAIL=0
MOCK_PID=""
MAIN_PID=""

say() { printf '%s\n' "$*"; }
ok()  { say "ok $*"; }
bad() { say "FAIL $*"; FAIL=$((FAIL+1)); }

cleanup() {
    [ -n "$MAIN_PID" ] && kill "$MAIN_PID" 2>/dev/null
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
    if [ "$FAIL" -ne 0 ]; then
        # 失败现场保全（排障；下次成功跑后手动清或幂等覆盖）
        KEEP=/tmp/occ_e9_drill_fail.$$
        cp -r "$T" "$KEEP" 2>/dev/null
        say "（失败现场已存 $KEEP）"
    fi
    rm -rf "$T"
}
trap cleanup EXIT

# ---- 1) mock 三角色 LLM + ac REST（同端口） ----
python3 tests/mock_llm.py "$PORT" "$T" "$DB" > "$T/mock.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then
        exec 3<&- 3>&-
        break
    fi
    sleep 0.1
done
kill -0 "$MOCK_PID" 2>/dev/null || { bad "e9-mock-up"; exit 1; }
ok "e9-mock-up port=$PORT"

cat > "$T/model.toml" <<EOF
[models.cloud]
provider_type = "openai_compatible"
model_name = "mock-model"
base_url = "http://127.0.0.1:$PORT/v1"
api_key = "mock-key-not-real"
EOF

export OCC_MODEL_TOML="$T/model.toml"
export OCC_DB="$DB"
export OCC_SESSIONS_DIR="$T/sessions"
export OCC_SNAPROOT="$T/snaps"
export OCC_SME=off
export OCC_AC_URL="http://127.0.0.1:$PORT"
export OCC_ORCH_TOOLS=1

# ---- 2) 主控 headless 起跑（后台：演练中段要注入回炉再派） ----
cd "$T"
timeout 150 "$OCCBIN" -p "ORCH-E9-主控：请派发子智能体完成「产出 out_e9.bin」任务，走完催收、机械判验收、回炉整改与复验全流程，直至任务 done 后收队。" \
    > "$T/main_out.txt" 2> "$T/main_err.txt" &
MAIN_PID=$!

# ---- 3) 等任务进 rework（条件轮询≤90s；主控首拒后落点） ----
q_task() {
    python3 - "$DB" <<'PYEOF'
import sqlite3, sys
try:
    db = sqlite3.connect(sys.argv[1])     # 只 SELECT；WAL 读者需可写 shm
    r = db.execute("SELECT id, status, rework_count FROM occ_task"
                   " ORDER BY created DESC LIMIT 1").fetchone()
    print("%s %s %d" % r if r else "")
except Exception:
    print("")
PYEOF
}
TID=""; ST=""
for _ in $(seq 1 450); do
    read -r TID ST _ < <(q_task)
    [ "$ST" = "rework" ] && break
    [ "$ST" = "escalated" ] && break
    kill -0 "$MAIN_PID" 2>/dev/null || break
    sleep 0.2
done
if [ "$ST" = "rework" ] && [ -n "$TID" ]; then
    ok "e9-saw-rework task=$TID"
else
    bad "e9-saw-rework (state=${ST:-none})"
fi

# ---- 4) 结果文件路径（spawn 工具结果——occ_toolcall.result_json） ----
RF=$(python3 - "$DB" <<'PYEOF'
import re, sqlite3, sys
db = sqlite3.connect(sys.argv[1])         # 只 SELECT；WAL 读者需可写 shm
row = db.execute(
    "SELECT result_json FROM occ_toolcall WHERE tool='task'"
    " AND result_json LIKE '%\"action\":\"spawn\"%'"
    " ORDER BY rowid LIMIT 1").fetchone()
m = row and re.search(r'"result_file":"(/tmp/occ_orch_res_\w+)"',
                      row[0] or "")
print(m.group(1) if m else "")
PYEOF
)
[ -n "$RF" ] && ok "e9-result-file $RF" || bad "e9-result-file"

# ---- 5) 回炉再派（C API 真路；工具面缺再派参数的测试侧桥） ----
if [ "$ST" = "rework" ] && [ -n "$RF" ]; then
    MD5=$(python3 - <<'PYEOF'
import hashlib
print(hashlib.md5(
    "ORCH-E9-DELIVERABLE\n回路演练产物 v1\n".encode("utf-8")).hexdigest())
PYEOF
)
    cat > "$T/redrive_prompt.txt" <<EOF
【E9-回炉整改】验收不通过（第 1/2 次）：首报无 # VERDICT 机械判表、零机检证据（自称完成不采信）。
整改要求：写出产物 out_e9.bin（内容含 ORCH-E9-DELIVERABLE 标记），并把最终报告（# VERDICT 表：criterion/result/evidence/self 四列，evidence 用 file:/md5:/contains: 机检令牌）写入结果文件。
结果文件：$RF
——原任务书要点：产出 out_e9.bin；验收=file:out_e9.bin、md5:out_e9.bin=$MD5、contains:out_e9.bin:ORCH-E9-DELIVERABLE；交付后自检 md5 亲算一致。
EOF
    if timeout 150 "$TESTORCH" --e9-redrive "$DB" "$TID" "$OCCBIN" "$T" \
            "$RF" "$T/redrive_prompt.txt" > "$T/redrive_out.txt" 2>&1; then
        # 结果文件存档副本（主进程 occ_orch_free 会清理自动生成的
        # 结果文件——read_result 窗口=进程生命期；趁在场先存证）
        cp "$RF" "$T/report_copy.md" 2>/dev/null
        ok "e9-redrive-rc0"
        grep -q "ok e9-redrive-end exit=0 reviewed=1" "$T/redrive_out.txt" \
            && ok "e9-redrive-collected" || bad "e9-redrive-collected"
    else
        bad "e9-redrive-rc0（见 $T/redrive_out.txt）"
    fi
else
    bad "e9-redrive-skipped（前置未达）"
fi

# ---- 6) 主控收队 ----
wait "$MAIN_PID"
MRC=$?
MAIN_PID=""
[ "$MRC" -eq 0 ] && ok "e9-main-rc0" || bad "e9-main-rc=$MRC"
grep -q "主控收队" "$T/main_out.txt" \
    && ok "e9-main-final-text" || bad "e9-main-final-text"

# ---- 7) 断言面：SQLite 直查 + mock 日志 + 文件 ----
PYOUT=$T/assert_out.txt
python3 - "$DB" "$T" "$TID" > "$PYOUT" 2>&1 <<'PYEOF'
import hashlib, os, re, sqlite3, sys

db_path, tdir, tid = sys.argv[1], sys.argv[2], sys.argv[3]
db = sqlite3.connect(db_path)             # 只 SELECT；WAL 读者需可写 shm
fails = []

def check(name, cond):
    print(("ok " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name)

# 任务终态：done 且恰回炉一次
row = db.execute("SELECT status, rework_count, child_session"
                 " FROM occ_task WHERE id=?", (tid,)).fetchone()
check("e9-task-done", row and row[0] == "done")
check("e9-rework-once", row and row[1] == 1)

# 审计事件序（状态机 kind；return/budget 审计不计入）
kinds = [r[0] for r in db.execute(
    "SELECT kind FROM occ_task_event WHERE task_id=? ORDER BY id",
    (tid,))]
seq = [k for k in kinds if k in ("dispatch", "result", "verdict", "rework",
                                 "escalate", "done", "distill")]
check("e9-event-seq",
      seq == ["dispatch", "result", "verdict", "rework",
              "dispatch", "result", "verdict", "done", "distill"])

# E7 预算记账事件（spawn 基线 + 终局累加）
budgets = [r[0] or "" for r in db.execute(
    "SELECT payload_json FROM occ_task_event WHERE task_id=?"
    " AND kind='budget' ORDER BY id", (tid,))]
check("e9-budget-events", len(budgets) >= 1 and
      any('"phase":"baseline"' in b for b in budgets))

# E4 机械预判：首报 fail → 二报 pass（machine_verdict 审计）
mvs = [r[0] or "" for r in db.execute(
    "SELECT payload_json FROM occ_task_event WHERE task_id=?"
    " AND kind='return' ORDER BY id", (tid,))]
mvs = [p for p in mvs if "machine_verdict" in p]
check("e9-machine-fail-then-pass",
      len(mvs) >= 2 and '"pass":false' in mvs[0]
      and '"pass":true' in mvs[-1])

# 整改词入审计（§3 模板——「验收不通过」六要素渲染）
allpay = " ".join(r[0] or "" for r in db.execute(
    "SELECT payload_json FROM occ_task_event WHERE task_id=?", (tid,)))
check("e9-rework-brief", "验收不通过" in allpay and "整改" in allpay)

# E5 蒸馏事件（两级蒸馏第二级关键实体清单）
dist = [r[0] or "" for r in db.execute(
    "SELECT payload_json FROM occ_task_event WHERE task_id=?"
    " AND kind='distill'", (tid,))]
check("e9-distill-event",
      len(dist) == 1 and "关键实体" in dist[0])

# E6 子会话 archived（蒸馏归档；消息保留可审计）
child = row[2] if row else ""
cst = db.execute("SELECT status FROM occ_session WHERE id=?",
                 (child,)).fetchone() if child else None
nmsg = db.execute(
    "SELECT COUNT(*) FROM occ_message WHERE session_id=?",
    (child,)).fetchone()[0] if child else 0
check("e9-child-archived", cst and cst[0] == "archived" and nmsg > 0)

# 产物：md5/contains 与验收令牌一致
art = os.path.join(tdir, "out_e9.bin")
want = hashlib.md5(
    "ORCH-E9-DELIVERABLE\n回路演练产物 v1\n".encode("utf-8")).hexdigest()
try:
    body = open(art, "rb").read()
    got = hashlib.md5(body).hexdigest()
    check("e9-deliverable", got == want and
          "ORCH-E9-DELIVERABLE".encode() in body)
except OSError:
    check("e9-deliverable", False)

# 结果文件（存档副本）：# VERDICT 固定表头 + 三行全 pass + md5 令牌
rep = ""
try:
    rep = open(os.path.join(tdir, "report_copy.md"),
               encoding="utf-8").read()
except OSError:
    rep = ""
check("e9-report-verdict",
      "# VERDICT" in rep and
      "| criterion | result | evidence | self |" in rep and
      rep.count("| pass |") >= 3 and
      ("md5:out_e9.bin=" + want) in rep)

# E5 闸1 压缩：ac force 链走完（REST 序 session/start→begin→commit）
routes = []
try:
    with open(os.path.join(tdir, "ac_routes.log"),
              encoding="utf-8") as f:
        routes = [ln.strip() for ln in f if ln.strip()]
except OSError:
    pass
def subseq(hay, needles):
    it = iter(hay)
    return all(any(n == x for x in it) for n in needles)
check("e9-ac-chain", subseq(routes, ["session/start", "begin", "commit"]))

# 压缩角色（digest）真被调用 + 换窗注记（〈会话摘要〉）
roles = []
try:
    with open(os.path.join(tdir, "roles.log"), encoding="utf-8") as f:
        roles = [ln.split(" ", 1)[1].strip() for ln in f if ln.strip()]
except OSError:
    pass
check("e9-ac-digest-role", "ac_digest" in roles)
note = db.execute(
    "SELECT COUNT(*) FROM occ_message WHERE role='system'"
    " AND content_json LIKE '%〈会话摘要〉%'").fetchone()[0]
check("e9-ac-window-note", note >= 1)

sys.exit(1 if fails else 0)
PYEOF
cat "$PYOUT"
NFAILPY=$(grep -c '^FAIL' "$PYOUT" || true)
FAIL=$((FAIL + NFAILPY))

# ---- 8) 收尾：mock 下线 + 残留自查 + 清理 ----
kill "$MOCK_PID" 2>/dev/null
wait "$MOCK_PID" 2>/dev/null
MOCK_PID=""
sleep 0.5
# 残留自查：按本演练夹具目录精确匹配（$T 唯一后缀——勿用宽串，
# 外层包装命令行可能含相似字样造成误报）
N_RES=$(pgrep -f "$T" 2>/dev/null | wc -l)
if [ "$N_RES" -eq 0 ]; then
    ok "e9-residue-procs-zero"
else
    bad "e9-residue-procs=$N_RES"
    pgrep -af "$T" 2>/dev/null | head -3
    pkill -9 -f "$T" 2>/dev/null
fi

say "orch-drill: FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
say "orch loop drill (mock 三角色): ALL GREEN"
