#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# undo_real_drill.sh - T9b2 /undo 端到端（*真调用：deepseek 云位*）
#
# 预算：3 次 LLM 调用（turn1 write / turn2 edit / 认证验证）+ 预留 1 次
# 不用（任务书 ≤4）。每 turn 内的工具环轮次按 DB assistant 行计并打印
# （b1 台账口径），如实报告。
#
# 流程：
#   turn1 真调用：write 创建 undo_demo.txt（内容 V1）→ 存 ref_v1 字节
#   turn2 真调用：edit 精确替换 V1→V2 → 记 ref_v2
#   occ undo --step1：文件逐字节回 ref_v1（turn2 改前态）
#   occ undo --step 1：文件回到 turn1 改前态（ABSENT 墓碑 → 删除）
#   turn3 真调用（认知验证）：AI 依据折叠进上下文的 undo 注记回答
#     「撤销了什么 / 文件在不在」
#   DB 断言：隐藏位、stage 落库与 commit、轮次计数
#
# 夹具 /tmp/occ-b2-drills/real/（授权范围）；不碰生产数据；key 不落日志。
set -u
cd "$(dirname "$0")/.." || exit 1
OCCDIR=$(pwd)

R=/tmp/occ-b2-drills/real
FAIL=0

say() { printf '%s\n' "$*"; }
ok()  { say "ok $*"; }
bad() { say "FAIL $*"; FAIL=$((FAIL + 1)); }

[ -f "${HOME}/.aikernel/model.toml" ] || {
    echo "缺 ~/.aikernel/model.toml（真调用前置）"; exit 2;
}

rm -rf "$R"
mkdir -p "$R/wd"

export OCC_DB="$R/sessions.db"
export OCC_SNAPROOT="$R/snap"
export OCC_TRACE_DIR="$R/trace"
export OCC_MODEL_TOML="$HOME/.aikernel/model.toml"
export OCC_PROVIDER_TOML="$HOME/.aikernel/provider.toml"

dbq() {
    python3 - "$OCC_DB" "$1" <<'PYEOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
r = db.execute(sys.argv[2]).fetchone()
print(r[0] if r else "")
PYEOF
}

cd "$R/wd" || exit 1

# ---- turn1（真调用 1）：write 创建 V1 ----
say "== turn1 (real)：write 创建 undo_demo.txt =="
timeout -k 3 180 "$OCCDIR/occ" -p \
    "请只用 write 工具在当前目录创建 undo_demo.txt，内容只有一行 V1（不要加换行以外的任何字符，不要用其他工具），完成后用一句话确认。" \
    >"$R/t1.out" 2>"$R/t1.err"
RC=$?
[ "$RC" -eq 0 ] && ok "turn1 rc=0" || { bad "turn1 rc=$RC"; tail -5 "$R/t1.err"; exit 1; }
[ -f undo_demo.txt ] && ok "turn1 file-created" || { bad "turn1 no file"; exit 1; }
cp undo_demo.txt "$R/ref_v1"
say "  ref_v1 bytes=$(wc -c < "$R/ref_v1") content=$(cat "$R/ref_v1")"

SID=$(grep -o 'session=ses_[0-9a-f]*' "$R/t1.err" | head -1 | cut -d= -f2)
[ -n "$SID" ] && ok "session=$SID" || { bad "no session id"; exit 1; }

# ---- turn2（真调用 2）：edit V1→V2 ----
say "== turn2 (real)：edit V1→V2 =="
timeout -k 3 180 "$OCCDIR/occ" -p --session "$SID" \
    "请只用 edit 工具把 undo_demo.txt 中的 V1 精确替换为 V2（oldString=V1，newString=V2），完成后用一句话确认，不要用其他工具。" \
    >"$R/t2.out" 2>"$R/t2.err"
RC=$?
[ "$RC" -eq 0 ] && ok "turn2 rc=0" || { bad "turn2 rc=$RC"; tail -5 "$R/t2.err"; exit 1; }
grep -q "V2" undo_demo.txt && ok "turn2 edited-to-v2" || bad "turn2 content"
cp undo_demo.txt "$R/ref_v2"
say "  ref_v2 bytes=$(wc -c < "$R/ref_v2") content=$(cat "$R/ref_v2")"
cmp -s "$R/ref_v1" "$R/ref_v2" && bad "v1==v2?!" || ok "v1!=v2 (真改了)"

# ---- undo 第一步：回 turn2 改前态（=ref_v1 逐字节） ----
say "== occ undo（第 1 步） =="
"$OCCDIR/occ" undo --session "$SID" >"$R/undo1.out" 2>"$R/undo1.err"
RC=$?
[ "$RC" -eq 0 ] && ok "undo1 rc=0" || { bad "undo1 rc=$RC"; cat "$R/undo1.err"; }
cat "$R/undo1.out"
cmp -s undo_demo.txt "$R/ref_v1" && ok "undo1 文件逐字节=ref_v1" \
    || bad "undo1 文件≠ref_v1 ($(cat undo_demo.txt 2>/dev/null))"
HID1=$(dbq "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND reverted=1")
[ "$HID1" -ge 4 ] && ok "undo1 hidden=$HID1" || bad "undo1 hidden=$HID1"
STG=$(dbq "SELECT COUNT(*) FROM occ_revert WHERE session_id='$SID'")
[ "$STG" = "1" ] && ok "undo1 stage-row" || bad "undo1 stage=$STG"

# ---- undo 第二步：回 turn1 改前态（ABSENT 墓碑 → 删除） ----
say "== occ undo（第 2 步，叠加走深） =="
"$OCCDIR/occ" undo --session "$SID" >"$R/undo2.out" 2>"$R/undo2.err"
RC=$?
[ "$RC" -eq 0 ] && ok "undo2 rc=0" || { bad "undo2 rc=$RC"; cat "$R/undo2.err"; }
cat "$R/undo2.out"
[ ! -e undo_demo.txt ] && ok "undo2 文件已删除（turn1 改前=不存在）" \
    || bad "undo2 文件仍存在"
HID2=$(dbq "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND reverted=1")
[ "$HID2" -gt "$HID1" ] && ok "undo2 hidden $HID1→$HID2" \
    || bad "undo2 hidden $HID1→$HID2"

# ---- turn3（真调用 3）：认知验证——AI 知道被撤 ----
say "== turn3 (real)：认知验证 =="
timeout -k 3 180 "$OCCDIR/occ" -p --session "$SID" \
    "不要调用任何工具。根据你可见的上下文（含系统注记）回答：1) 我刚才在这条会话里撤销了什么操作？2) undo_demo.txt 此刻在磁盘上应该存在还是不存在？逐条简答。" \
    >"$R/t3.out" 2>"$R/t3.err"
RC=$?
[ "$RC" -eq 0 ] && ok "turn3 rc=0" || { bad "turn3 rc=$RC"; tail -5 "$R/t3.err"; }
say "--- AI 认知验证回复 ---"
cat "$R/t3.out"
say "----------------------"
REPLY=$(cat "$R/t3.out")
echo "$REPLY" | grep -q "撤销" && ok "cognitive-知道被撤" || bad "cognitive 未提撤销"
echo "$REPLY" | grep -Eq "不存在|已删除|删除|没有创建" && ok "cognitive-文件不在" \
    || bad "cognitive 未判定文件不存在"

# ---- DB 断言（commit/隐藏/轮次） ----
ST=$(dbq "SELECT status FROM occ_session WHERE id='$SID'")
[ "$ST" = "active" ] && ok "final status=active" || bad "final status=$ST"
STG=$(dbq "SELECT COUNT(*) FROM occ_revert WHERE session_id='$SID'")
[ "$STG" = "0" ] && ok "cognitive 落地即 commit（stage 清除）" || bad "stage=$STG"
NOTES=$(dbq "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND role='system'")
[ "$NOTES" = "0" ] && ok "注记已折叠删除" || bad "残留注记=$NOTES"
NU=$(dbq "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND role='user'")
[ "$NU" = "3" ] && ok "user=3 (turn1+turn2+cognitive)" || bad "user=$NU"
# 轮次台账（b1 口径：每条 assistant=一次 LLM 请求轮）
ROUNDS=$(dbq "SELECT COUNT(*) FROM occ_message WHERE session_id='$SID' AND role='assistant'")
say "台账：LLM 调用次数=3 invocations（预算≤4）；assistant 轮次=$ROUNDS（turn 环内轮次，b1 口径如实列）"
say "证据留档：$R/（t1/t2/t3、undo1/2、ref_v1/ref_v2、sessions.db、snapshots/）"

say "undo real drill: FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
say "undo real drill: ALL GREEN（真调用 3 次）"
