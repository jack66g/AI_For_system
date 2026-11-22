#!/bin/sh
# test_policy.sh - P-2 Phase B aikctl policy 子族测试（root 面）。
#
# 隔离：policy.conf/sudoers 走 AIK_POLICY_CONF/AIK_SUDOERS 指向临时桩
# （不碰 /etc/aikernel/policy.conf 与 /etc/sudoers）；set 写面用
# tstp2d* 临时测试号（跑完清净，EXIT trap 兜底）。需 root（sudo 跑）。
#
# 断言面：get 结构化（段/未知键/unparsed/生效推演注）→ get --json →
# set 确认流（无 --yes=只打 diff 不写；--yes=写+备份逐字节；幂等；换档
# 只动 user 段）→ 拒绝面（无此号/root/非法档/非 root）→ --rollback
# 逐字节回退两级 → 无备份态 → sudoers 桩（正常行+unparsed 原样）→
# 非 root 读真 /etc/sudoers 人话拒绝。
set -u
cd "$(dirname "$0")/.." || exit 2          # → agent/ai/aikctl
AIKCTL="python3 ./aikctl"

[ "$(id -u)" = 0 ] || { echo "需要 root（sudo sh $0）"; exit 2; }

T=$(mktemp -d /tmp/p2b-pol.XXXXXX)
PC="$T/policy.conf"
SU="$T/sudoers"
export AIK_POLICY_CONF="$PC"
export AIK_SUDOERS="$SU"
U1="tstp2d$(printf '%s' $$)a"
UNX="tstp2d$(printf '%s' $$)x"

pass=0
fail=0
has() { printf '%s' "$1" | grep -qF -- "$2"; }
ck() { # ck <描述> <条件（已展开的 test 表达式串）>
    if eval "$2"; then
        pass=$((pass+1)); echo "  PASS $1"
    else
        fail=$((fail+1)); echo "  FAIL $1"
    fi
}

cleanup() {
    id -u "$U1" >/dev/null 2>&1 && userdel -r "$U1" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

cat > "$PC" <<'EOF'
# AIKernel 用户权限分级策略（测试桩）
# mode: privileged / confirmed / restricted
[root]
mode = privileged        # root: W1 自动；W2 二次确认
[wheel]
mode = confirmed         # sudo 组: W1 自动；W2 拒绝并提示 sudo
group = sudo             # Ubuntu 22.04 sudo 组（GID 27）
[default]
mode = restricted        # 其他用户: W1 白名单内自动；W2 拒绝
note = keep-as-is        # 未知键——必须原样保留
EOF
cp "$PC" "$T/policy.orig"
useradd -m -s /bin/sh "$U1" 2>/dev/null   # 建号先行——确认流/写面都用它

echo "== 1. policy get 结构化（含 per-user 段桩） =="
cat >> "$PC" <<'EOF'

[user:tstp2dstub]
mode = confirmed
EOF
out=$($AIKCTL policy get 2>&1); rc=$?
ck "get rc=0" "[ '$rc' = 0 ]"
ck "get 列 [root]/[wheel]/[default] 段头" \
   "has \"\$out\" '[root]' && has \"\$out\" '[wheel]' && has \"\$out\" '[default]'"
ck "get 列 per-user 段（含标记）" "has \"\$out\" '[user:tstp2dstub]'"
ck "get 未知键原样列出" "has \"\$out\" 'note = keep-as-is'"
ck "get 生效推演注明以内核侧为准" "has \"\$out\" '生效面以内核侧'"
j=$($AIKCTL policy get --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
sec = [s for s in d["sections"] if s["section"] == sys.argv[1]]
assert len(sec) == 1, "per-user 段在"
assert sec[0]["kind"] == "per_user"
assert sec[0]["keys"][0] == {"key": "mode", "value": "confirmed"}
names = [s["section"] for s in d["sections"]]
assert names == ["root", "wheel", "default", "user:tstp2dstub"], names
assert any(k["key"] == "note" and k["value"] == "keep-as-is"
           for s in d["sections"] if s["section"] == "default"
           for k in s["keys"]), "未知键如实入表"
assert d["wheel_group"] == "sudo"
assert isinstance(d["effective"], list) and d["effective"]
assert "内核侧" in d["note"]
' 'user:tstp2dstub')
ck "get --json 结构断言（段序/键值/未知键/推演面）" "[ $? = 0 ]"
# 还原无 per-user 段基线，后面 set 流从干净态起
cp "$T/policy.orig" "$PC"

echo "== 1b. 对齐 C 读取器（;/# 注释、重复键后写胜出、段尾注释） =="
PC2="$T/align.conf"
cat > "$PC2" <<'EOF'
; 分号注释行——与 # 同忽略
[root]
mode = privileged
mode = restricted        # 重复键——后写胜出
[wheel]
mode = confirmed
[default]
mode = restricted
[user:tstp2d1]  # 段尾注释容错
mode = confirmed
EOF
out=$(AIK_POLICY_CONF="$PC2" $AIKCTL policy get --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
g = {s["section"]: {k["key"]: k["value"] for k in s["keys"]}
     for s in d["sections"]}
assert g["root"]["mode"] == "restricted", "重复键后写胜出（C 覆盖语义）"
assert g["user:tstp2d1"]["mode"] == "confirmed", "段尾注释不入段名"
eff = {e["name"]: e for e in d["effective"]}
assert eff["tstp2d1"]["mode"] == "confirmed", "悬空 per-user 段也入推演"
assert d["wheel_group"] == "wheel", "无 group 键缺省=wheel（C 对齐）"
')
ck "--json 对齐断言（后写胜出/段尾注释/缺省 wheel）" "[ $? = 0 ]"
out=$(AIK_POLICY_CONF="$PC2" $AIKCTL policy get 2>&1)
ck "分号注释行不入 unparsed" "! has \"\$out\" '分号注释行'"
ck "重复 mode 行如实都列出" "[ \"\$(AIK_POLICY_CONF='$PC2' $AIKCTL policy get 2>/dev/null | grep -c 'mode = ')\" = 5 ]"

echo "== 2. set 无 --yes：只打前/后 diff 不写 =="
out=$($AIKCTL policy set user "$U1" mode=restricted 2>&1); rc=$?
ck "无 --yes rc!=0（W2 拒）" "[ '$rc' != 0 ]"
ck "打印前/后 diff（含 +mode 行）" "has \"\$out\" '+mode = restricted'"
ck "diff 标注前/后文件" "has \"\$out\" 'policy.conf(前)'"
ck "文件逐字节未动" "cmp -s '$PC' '$T/policy.orig'"

echo "== 3. set 拒绝面 =="
out=$($AIKCTL policy set user "$UNX" mode=restricted --yes 2>&1); rc=$?
ck "无此号拒绝 rc!=0" "[ '$rc' != 0 ]"
ck "无此号人话" "has \"\$out\" '无此号'"
out=$($AIKCTL policy set user root mode=restricted --yes 2>&1); rc=$?
ck "root 拒绝（恒 privileged）" "[ '$rc' != 0 ] && has \"\$out\" '恒 privileged'"
out=$($AIKCTL policy set user "$U1" mode=bogus --yes 2>&1); rc=$?
ck "非法档拒绝" "[ '$rc' != 0 ] && has \"\$out\" '非法档'"
out=$($AIKCTL policy set user "$U1" restricted --yes 2>&1); rc=$?
ck "缺 mode= 前缀拒绝" "[ '$rc' != 0 ]"

echo "== 4. set --yes：写+备份逐字节 =="
out=$($AIKCTL policy set user "$U1" mode=restricted --yes 2>&1); rc=$?
ck "set --yes rc=0" "[ '$rc' = 0 ]"
bak=$(ls "$T"/policy.conf.bak.* 2>/dev/null | head -1)
ck "备份文件在（同目录 .bak.<ts>）" "[ -n '$bak' ]"
ck "备份=写前原文逐字节" "cmp -s '$bak' '$T/policy.orig'"
ck "新段已写" "has \"\$(cat '$PC')\" '[user:$U1]'"
ck "只增不改（无 '<' 删除行）" "! diff '$T/policy.orig' '$PC' | grep -q '^<'" 
out=$($AIKCTL policy set user "$U1" mode=restricted --yes 2>&1); rc=$?
ck "幂等重跑 rc=0（已是该档不写）" "[ '$rc' = 0 ] && has \"\$out\" '幂等'"

echo "== 5. 换档：只动 user 段 mode 行 =="
cp "$PC" "$T/policy.before2"
out=$($AIKCTL policy set user "$U1" mode=confirmed --yes 2>&1); rc=$?
ck "换档 rc=0" "[ '$rc' = 0 ]"
ck "user 段 mode 行已换 confirmed" "has \"\$(cat '$PC')\" 'mode = confirmed'"
ck "[default] 的 restricted 原样（恰 1 处）" \
   "[ \"\$(grep -c 'mode = restricted' '$PC')\" = 1 ]"
ck "未知键 note 原样" "has \"\$(cat '$PC')\" 'note = keep-as-is'"
ck "注释行原样" "has \"\$(cat '$PC')\" '# root: W1 自动'"

echo "== 6. --rollback 逐字节回退 =="
out=$($AIKCTL policy set --rollback 2>&1); rc=$?
ck "rollback rc=0" "[ '$rc' = 0 ]"
ck "恢复到最近备份（换档前）逐字节" "cmp -s '$PC' '$T/policy.before2'"
out=$($AIKCTL policy set --rollback 2>&1); rc=$?
ck "再 rollback 回出厂基线逐字节" "cmp -s '$PC' '$T/policy.orig'"

echo "== 7. 无备份态人话拒绝 =="
T2=$(mktemp -d /tmp/p2b-pol2.XXXXXX)
printf '[root]\nmode = privileged\n' > "$T2/p.conf"
out=$(AIK_POLICY_CONF="$T2/p.conf" $AIKCTL policy set --rollback 2>&1); rc=$?
ck "无备份 rc!=0 人话" "[ '$rc' != 0 ] && has \"\$out\" '无备份'"
rm -rf "$T2"

echo "== 8. sudoers 桩解析（正常行+unparsed 原样） =="
cat > "$SU" <<'EOF'
Defaults env_reset
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
User_Alias ADMINS = alice, bob
ADMINS rushmore = /bin/kill
jack rushmore = /bin/kill, /bin/ls \
    NOPASSWD: /usr/bin/tee
Defaults secure_path="/usr/sbin:/usr/bin"
@includedir /etc/sudoers.d
just-a-fragment
EOF
out=$($AIKCTL policy get sudoers 2>&1); rc=$?
ck "sudoers rc=0" "[ '$rc' = 0 ]"
ck "root 行解析出 (ALL:ALL)" "has \"\$out\" '(ALL:ALL)'"
ck "%组行解析（group:sudo）" "has \"\$out\" 'group:sudo'"
ck "别名行解析+成员列出" "has \"\$out\" 'alias:ADMINS' && has \"\$out\" 'alice, bob'"
ck "续行归并（NOPASSWD 进 commands）" "has \"\$out\" 'NOPASSWD: /usr/bin/tee'"
ck "解析不了的行原样标 unparsed" "has \"\$out\" 'unparsed'"
ck "Defaults 原样入 unparsed" "has \"\$out\" 'Defaults env_reset'"
ck "@includedir 原样入 unparsed" "has \"\$out\" '@includedir /etc/sudoers.d'"
ck "碎片行原样入 unparsed" "has \"\$out\" 'just-a-fragment'"
j=$($AIKCTL policy get sudoers --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert len(d["entries"]) == 4, d["entries"]
assert d["entries"][1]["runas"] == "ALL:ALL"
assert d["entries"][2]["kind"] == "alias" and d["entries"][2]["members"] == ["alice", "bob"]
assert d["entries"][3]["commands"] == "/bin/kill, /bin/ls NOPASSWD: /usr/bin/tee"
assert len(d["unparsed"]) == 4, d["unparsed"]
')
ck "sudoers --json 断言（4 条目+4 unparsed）" "[ $? = 0 ]"

echo "== 9. 非 root 权限面 =="
if id jack66g >/dev/null 2>&1; then
    out=$(runuser -u jack66g -- env AIK_POLICY_CONF="$PC" \
          python3 ./aikctl policy set user "$U1" mode=restricted --yes 2>&1)
    rc=$?
    ck "非 root set 人话拒绝" "[ '$rc' != 0 ] && has \"\$out\" 'root'"
    out=$(runuser -u jack66g -- env AIK_SUDOERS=/etc/sudoers \
          python3 ./aikctl policy get sudoers 2>&1); rc=$?
    ck "非 root 读真 sudoers 人话拒绝（perms 自然挡）" \
       "[ '$rc' != 0 ] && has \"\$out\" '权限不够'"
else
    echo "  SKIP 非 root 面（jack66g 不在——仅 L1 打版机路径）"
fi

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
