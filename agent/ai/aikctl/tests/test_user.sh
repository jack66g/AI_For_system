#!/bin/sh
# test_user.sh - P-2 Phase A aikctl user 子族往返测试（root 面）。
#
# 隔离：gate 文件走 AIK_CONSOLE_GATE 指向临时桩（不碰 /etc/aikernel/
# console-gate）；OS 号面用 tstp2b* 临时测试号（照测试纪律跑完清净，
# EXIT trap 兜底再清一遍）。需 root（sudo 跑）。
#
# 断言面：add 四件（号在/gate 行格式/家域骨架/wheel/passwd 同步）→
# list → 重复拒绝/短密拒绝 → passwd 改（gate 哈希与 shadow 同源换新）→
# del（默认留家；--purge-home 连删；净）→ from-gate 幂等路径 → selftest。
set -u
cd "$(dirname "$0")/.." || exit 2          # → agent/ai/aikctl
AIKCTL="python3 ./aikctl"

[ "$(id -u)" = 0 ] || { echo "需要 root（sudo sh $0）"; exit 2; }

U1="tstp2b$(printf '%s' $$)a"
U2="tstp2b$(printf '%s' $$)b"
UNX="tstp2b$(printf '%s' $$)x"
GATE=$(mktemp /tmp/p2b-gate.XXXXXX)
export AIK_CONSOLE_GATE="$GATE"

pass=0
fail=0
ck() { # ck <描述> <条件（已展开的 test 表达式串）>
    if eval "$2"; then
        pass=$((pass+1)); echo "  PASS $1"
    else
        fail=$((fail+1)); echo "  FAIL $1"
    fi
}

cleanup() {
    for u in "$U1" "$U2"; do
        id -u "$u" >/dev/null 2>&1 && userdel -r "$u" 2>/dev/null
    done
    [ -d "/home/$U1" ] && rm -rf "/home/$U1"     # del 默认留家→手工清
    rm -f "$GATE"
}
trap cleanup EXIT INT TERM

echo "== 1. list 空桩 =="
out=$($AIKCTL user list 2>&1); rc=$?
ck "空 gate list rc=0" "[ '$rc' = 0 ]"
ck "空 gate list 报空桩" "case '$out' in *gate*空*) true;; *) false;; esac"

echo "== 2. 非 root 人话拒绝 =="
if id jack66g >/dev/null 2>&1; then
    out=$(runuser -u jack66g -- env AIK_CONSOLE_GATE="$GATE" \
          python3 ./aikctl user add "$U1" --password-stdin </dev/null 2>&1)
    rc=$?
    ck "非 root add rc!=0" "[ '$rc' != 0 ]"
    ck "非 root add 人话拒绝（提到 root）" \
       "case '$out' in *root*|*拒绝*) true;; *) false;; esac"
else
    echo "  SKIP 非 root 拒绝（jack66g 不在——仅 L1 打版机路径）"
fi

echo "== 3. add 四件同落 =="
oldhash=""
out=$(echo test1234 | $AIKCTL user add "$U1" --wheel --password-stdin 2>&1)
rc=$?
ck "add rc=0" "[ '$rc' = 0 ]"
ck "号已建" "id -u '$U1' >/dev/null 2>&1"
nf=$(awk -F: -v u="$U1" '$1==u{print NF}' "$GATE")
ck "gate 行字段数=3（name:hash:ts）" "[ '$nf' = 3 ]"
hp=$(awk -F: -v u="$U1" '$1==u{print substr($2,1,3)}' "$GATE")
ck "gate 哈希 \$6\$ 前缀" "[ '$hp' = '\$6\$' ]"
ts=$(awk -F: -v u="$U1" '$1==u{print $3}' "$GATE")
ck "gate 时间戳数字" "case '$ts' in ''|*[!0-9]*) false;; *) true;; esac"
oldhash=$(awk -F: -v u="$U1" '$1==u{print $2}' "$GATE")
ck "家域骨架 .aikernel/.occ" \
   "[ -d '/home/$U1/.aikernel' ] && [ -d '/home/$U1/.occ' ]"
ck "骨架属主=该号" \
   "[ \"\$(stat -c %U \"/home/$U1/.aikernel\")\" = '$U1' ] && [ \"\$(stat -c %U \"/home/$U1/.occ\")\" = '$U1' ]"
ck "骨架权限 700" "[ \"\$(stat -c %a \"/home/$U1/.aikernel\")\" = 700 ]"
ck "不动 model.toml（用户域）" "[ ! -e '/home/$U1/.aikernel/model.toml' ]"
ck "wheel：sudo 组员" "case \"\$(id -nG '$U1')\" in *sudo*) true;; *) false;; esac"
sh_hash=$(getent shadow "$U1" | cut -d: -f2)
ck "passwd 同步=gate 同一哈希（usermod -p 同源）" \
   "[ '$sh_hash' = '$oldhash' ]"

echo "== 4. list 呈现 =="
out=$($AIKCTL user list 2>&1)
ck "list 含该号" "case '$out' in *$U1*) true;; *) false;; esac"
ck "list 含 uid" "case '$out' in *\$(id -u $U1)*) true;; *) false;; esac"

echo "== 5. 重复 add 拒绝 =="
out=$(echo test1234 | $AIKCTL user add "$U1" --password-stdin 2>&1)
rc=$?
ck "重复 add rc!=0" "[ '$rc' != 0 ]"

echo "== 6. 短密拒绝（向导同规 ≥6） =="
out=$(echo abc | $AIKCTL user add "$UNX" --password-stdin 2>&1)
rc=$?
ck "短密 add rc!=0" "[ '$rc' != 0 ]"
ck "短密未建号" "! id -u '$UNX' >/dev/null 2>&1"

echo "== 7. passwd 改（gate+shadow 同源换新） =="
out=$(echo newpass99 | $AIKCTL user passwd "$U1" --password-stdin 2>&1)
rc=$?
ck "passwd rc=0" "[ '$rc' = 0 ]"
newhash=$(awk -F: -v u="$U1" '$1==u{print $2}' "$GATE")
ck "gate 哈希已换" "[ -n '$newhash' ] && [ '$newhash' != '$oldhash' ]"
sh_hash=$(getent shadow "$U1" | cut -d: -f2)
ck "shadow 同步=新 gate 哈希" "[ '$sh_hash' = '$newhash' ]"

echo "== 8. del（默认留家） =="
out=$($AIKCTL user del "$U1" 2>&1)
rc=$?
ck "del rc=0" "[ '$rc' = 0 ]"
ck "号已净" "! id -u '$U1' >/dev/null 2>&1"
ck "gate 行已净" "[ \"\$(grep -c \"^$U1:\" '$GATE' 2>/dev/null)\" = 0 ]"
ck "家目录保留（缺省）" "[ -d '/home/$U1' ]"
rm -rf "/home/$U1"

echo "== 9. from-gate 归位路径（幂等） =="
stub='$6$tcstub$TcStubStubStubStubStubStubStubStubStubStubStub'
printf '%s:%s:1750000000\n' "$U2" "$stub" > "$GATE"
out=$($AIKCTL user add "$U2" --wheel --from-gate 2>&1)
rc=$?
ck "from-gate add rc=0" "[ '$rc' = 0 ]"
ck "号已建" "id -u '$U2' >/dev/null 2>&1"
sh_hash=$(getent shadow "$U2" | cut -d: -f2)
ck "shadow=gate 桩哈希逐字一致" "[ '$sh_hash' = '$stub' ]"
ck "wheel：sudo 组员" "case \"\$(id -nG '$U2')\" in *sudo*) true;; *) false;; esac"
ck "骨架在" "[ -d '/home/$U2/.aikernel' ] && [ -d '/home/$U2/.occ' ]"
out=$($AIKCTL user add "$U2" --wheel --from-gate 2>&1)
rc=$?
ck "from-gate 幂等重跑 rc=0（号已在=跳过）" "[ '$rc' = 0 ]"
out=$($AIKCTL user del "$U2" --purge-home 2>&1)
rc=$?
ck "del --purge-home rc=0" "[ '$rc' = 0 ]"
ck "号已净" "! id -u '$U2' >/dev/null 2>&1"
ck "家目录已连删" "[ ! -d '/home/$U2' ]"

echo "== 10. del 无此用户拒绝 =="
out=$($AIKCTL user del "$UNX" 2>&1)
rc=$?
ck "del 无此用户 rc!=0" "[ '$rc' != 0 ]"

echo "== 11. selftest（含 ④ gate 格式往返桩） =="
out=$($AIKCTL selftest 2>&1)
rc=$?
ck "selftest rc=0" "[ '$rc' = 0 ]"
ck "selftest 含 user 桩用例" "case '$out' in *gate*) true;; *) false;; esac"

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
