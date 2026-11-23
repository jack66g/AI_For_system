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
#
# P-60（11-22 夜五修复回归，2026-11-24 补）：
#   12. gate 组读面：机器上有 aik-gate 组→gate 文件 0640 root:aik-gate、
#       新用户在该组、--wheel 在 sudo+aik-gate；无该组→回落 0600
#       root:root、非 wheel 不进额外组、--wheel 只进 sudo。有组路径须
#       显式开关 AIK_TEST_HAVE_GATE_GROUP=1 才 groupadd（gid 942 出厂
#       同值；trap 兜底 groupdel），默认不建组（L1 无该组=测回落路径）。
#   13. flock 串行：gate 行预置后两个 `user add <同名> --from-gate
#       --wheel` 并发起跑 ×5 轮→恰一个建号成功、另一个幂等跳过或诚实
#       拒绝；passwd 恰一行；家目录属主 uid=passwd uid（曾出孤儿家
#       目录属旧 uid）；shadow 哈希=gate 哈希。
set -u
cd "$(dirname "$0")/.." || exit 2          # → agent/ai/aikctl
AIKCTL="python3 ./aikctl"

[ "$(id -u)" = 0 ] || { echo "需要 root（sudo sh $0）"; exit 2; }

U1="tstp2b$(printf '%s' $$)a"
U2="tstp2b$(printf '%s' $$)b"
UNX="tstp2b$(printf '%s' $$)x"
U3="tstp2b$(printf '%s' $$)c"               # 12：非 wheel
U4="tstp2b$(printf '%s' $$)d"               # 12：--wheel
GATE=$(mktemp /tmp/p2b-gate.XXXXXX)
export AIK_CONSOLE_GATE="$GATE"
MADE_GG=0                                    # 12：本测试是否建了 aik-gate 组

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
    for u in "$U1" "$U2" "$U3" "$U4" tstp2c$$r*; do
        id -u "$u" >/dev/null 2>&1 && userdel -r "$u" 2>/dev/null
    done
    [ -d "/home/$U1" ] && rm -rf "/home/$U1"     # del 默认留家→手工清
    [ -d "/home/$U3" ] && rm -rf "/home/$U3"
    [ -d "/home/$U4" ] && rm -rf "/home/$U4"
    # 12：本测试建的 aik-gate 组——测试号删净后再删组（组内无员才删得掉）
    if [ "$MADE_GG" = 1 ]; then
        groupdel aik-gate 2>/dev/null || echo "  WARN groupdel aik-gate 失败（请人工清理）"
    fi
    rm -f "$GATE"
    true
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

echo "== 12. gate 组读面（P-60：有 aik-gate 组=0640 root:aik-gate；无=回落 0600 root:root） =="
# 有组路径须显式开关才建组（gid 942=出厂定值；trap 兜底 groupdel）；默认
# 不建——机器上本无该组（L1/旧盘）即测回落路径。
if getent group aik-gate >/dev/null 2>&1; then
    HAVE_GG=1
    echo "  本机已有 aik-gate 组（gid $(getent group aik-gate | cut -d: -f3)）——测有组路径"
elif [ "${AIK_TEST_HAVE_GATE_GROUP:-0}" = 1 ]; then
    if groupadd -g 942 aik-gate 2>/dev/null; then
        HAVE_GG=1
        MADE_GG=1
        echo "  AIK_TEST_HAVE_GATE_GROUP=1：已建 aik-gate 组（gid 942，测后 groupdel）——测有组路径"
    else
        HAVE_GG=0
        echo "  SKIP 有组路径（groupadd -g 942 aik-gate 失败：gid 被占？）——按无组路径测"
    fi
else
    HAVE_GG=0
    echo "  本机无 aik-gate 组且未开 AIK_TEST_HAVE_GATE_GROUP=1——测回落路径（有组路径 SKIP）"
fi
out=$(echo test1234 | $AIKCTL user add "$U3" --password-stdin 2>&1)
rc=$?
ck "12 非 wheel add rc=0" "[ '$rc' = 0 ]"
out=$(echo test1234 | $AIKCTL user add "$U4" --wheel --password-stdin 2>&1)
rc=$?
ck "12 wheel add rc=0" "[ '$rc' = 0 ]"
gm=$(stat -c %a "$GATE")
go=$(stat -c %G "$GATE")
gu=$(stat -c %U "$GATE")
g3=$(id -nG "$U3" 2>/dev/null)
g4=$(id -nG "$U4" 2>/dev/null)
echo "  gate mode=$gm owner=$gu group=$go; groups[$U3]=[$g3]; groups[$U4]=[$g4]"
if [ "$HAVE_GG" = 1 ]; then
    ck "有组：gate 文件 0640" "[ '$gm' = 640 ]"
    ck "有组：gate 属主:组=root:aik-gate" \
       "[ '$gu' = root ] && [ '$go' = aik-gate ]"
    ck "有组：非 wheel 新用户在 aik-gate 组" \
       "case \"\$(id -nG '$U3')\" in *aik-gate*) true;; *) false;; esac"
    ck "有组：非 wheel 不进 sudo" \
       "case \"\$(id -nG '$U3')\" in *sudo*) false;; *) true;; esac"
    ck "有组：--wheel 在 sudo+aik-gate" \
       "case \"\$(id -nG '$U4')\" in *sudo*aik-gate*|*aik-gate*sudo*) true;; *) false;; esac"
    # 组读面实证：aik-gate 组员（非 root）读得动 gate——非 root occ 的 LOGIN 前提
    ck "有组：组员（$U3，非 root）可读 gate 文件" \
       "runuser -u '$U3' -- cat '$GATE' >/dev/null 2>&1"
else
    ck "无组：gate 回落 0600 root:root" \
       "[ '$gm' = 600 ] && [ '$gu' = root ] && [ '$go' = root ]"
    ck "无组：非 wheel 不进额外组（仅主组）" \
       "[ \"\$(id -nG '$U3')\" = '$U3' ]"
    ck "无组：--wheel 只进 sudo（主组+sudo）" \
       "[ \"\$(id -nG '$U4')\" = '$U4 sudo' ]"
fi

echo "== 13. flock 串行（P-60 修复 1：双 console 并发归位 ×5 轮不互踩） =="
# 每轮：gate 行预置 → 两个 `user add <同名> --from-gate --wheel` 同时起跑
# → 恰一个建号成功、另一个幂等跳过（rc=0）或诚实拒绝（rc≠0）；passwd
# 恰一行；家目录属主 uid=passwd uid（曾出孤儿家目录属旧 uid）；shadow
# 哈希=gate 哈希。串行化前双 useradd 互踩会留下孤儿家目录/双行/哈希错位。
stub='$6$tcstub$TcStubStubStubStubStubStubStubStubStubStubStub'
r=1
while [ "$r" -le 5 ]; do
    UC="tstp2c$$r$r"
    printf '%s:%s:1750000000\n' "$UC" "$stub" > "$GATE"
    o1=$(mktemp /tmp/p2b-c1.XXXXXX)
    o2=$(mktemp /tmp/p2b-c2.XXXXXX)
    $AIKCTL user add "$UC" --from-gate --wheel >"$o1" 2>&1 &
    p1=$!
    $AIKCTL user add "$UC" --from-gate --wheel >"$o2" 2>&1 &
    p2=$!
    wait "$p1"; r1=$?
    wait "$p2"; r2=$?
    t1=$(cat "$o1"); t2=$(cat "$o2")
    rm -f "$o1" "$o2"
    n_ok=0
    n_skip=0
    r_other=
    case "$t1" in *"四件同落 OK"*) n_ok=$((n_ok+1)); r_other=$r2 ;; esac
    case "$t1" in *"幂等跳过"*) n_skip=$((n_skip+1)) ;; esac
    case "$t2" in *"四件同落 OK"*) n_ok=$((n_ok+1)); r_other=$r1 ;; esac
    case "$t2" in *"幂等跳过"*) n_skip=$((n_skip+1)) ;; esac
    pwc=$(getent passwd "$UC" 2>/dev/null | wc -l)
    puid=$(id -u "$UC" 2>/dev/null)
    huid=$(stat -c %u "/home/$UC" 2>/dev/null)
    hown=$(stat -c %U "/home/$UC" 2>/dev/null)
    ghash=$(awk -F: -v u="$UC" '$1==u{print $2}' "$GATE")
    shash=$(getent shadow "$UC" 2>/dev/null | cut -d: -f2)
    ok=1
    [ "$n_ok" = 1 ] || ok=0
    if [ "$n_skip" = 1 ]; then
        [ "$r1" = 0 ] && [ "$r2" = 0 ] || ok=0
    else
        # 诚实拒绝：另一路 rc≠0
        [ -n "$r_other" ] && [ "$r_other" != 0 ] || ok=0
    fi
    [ "$pwc" = 1 ] || ok=0
    [ -n "$puid" ] && [ "$huid" = "$puid" ] && [ "$hown" = "$UC" ] || ok=0
    [ "$shash" = "$stub" ] && [ "$ghash" = "$stub" ] || ok=0
    case "$(id -nG "$UC" 2>/dev/null)" in *sudo*) ;; *) ok=0 ;; esac
    if [ "$ok" = 1 ]; then
        pass=$((pass+1))
        echo "  PASS 13 第 $r 轮：一建一跳/拒（ok=$n_ok skip=$n_skip rc=$r1/$r2）passwd 1 行·家属主 $hown:$huid·shadow=gate 哈希·在 sudo"
    else
        fail=$((fail+1))
        echo "  FAIL 13 第 $r 轮：ok=$n_ok skip=$n_skip rc=$r1/$r2 passwd行=$pwc 家属主=$hown:$huid uid=$puid shadow=$(printf '%s' "$shash" | head -c 12) gate=$(printf '%s' "$ghash" | head -c 12)"
        echo "    [A] $(printf '%s' "$t1" | head -c 300)"
        echo "    [B] $(printf '%s' "$t2" | head -c 300)"
    fi
    id -u "$UC" >/dev/null 2>&1 && userdel -r "$UC" 2>/dev/null
    [ -d "/home/$UC" ] && rm -rf "/home/$UC"
    r=$((r+1))
done

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
