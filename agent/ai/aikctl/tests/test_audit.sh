#!/bin/sh
# test_audit.sh - P-2 Phase B aikctl audit tail 测试（多用户家桩）。
#
# 隔离：默认通道 HOME 指向 /tmp 桩家；--all 聚合走 AIK_AUDIT_HOME_DIRS
# 桩（不扫真 /root+/home/* 的审计面）；--user 通道用 tstp2d* 临时测试号
# （跑完清净）。需 root（--user/--all 面+建临时号）。
#
# 断言面：默认通道尾 N（缺省 20/-n 2）→ 缺失家=人话 rc0 → --user 通道
# （真号家+无此号拒绝）→ --all 聚合（行首标用户+每家尾 N+无日志家如实
# 标）→ 非 root 拒绝面（--all/--user 他人=人话；自己的默认通道可用）→
# -n 负数拒绝。
set -u
cd "$(dirname "$0")/.." || exit 2          # → agent/ai/aikctl
AIKCTL="python3 ./aikctl"

[ "$(id -u)" = 0 ] || { echo "需要 root（sudo sh $0）"; exit 2; }

T=$(mktemp -d /tmp/p2b-aud.XXXXXX)
H1="$T/alice"; H2="$T/bob"; H3="$T/carol"
for h in "$H1" "$H2" "$H3"; do mkdir -p "$h/.aikernel"; done
i=1
while [ "$i" -le 25 ]; do
    printf 'ts=17500000%02d uid=1001 user=alice ev=cmd\n' "$i" \
        >> "$H1/.aikernel/audit.log"
    i=$((i+1))
done
printf 'ts=1750000101 uid=1002 user=bob ev=cmd\n' > "$H2/.aikernel/audit.log"
# H3 无 audit.log——聚合时如实标无

U1="tstp2d$(printf '%s' $$)u"
useradd -m -s /bin/sh "$U1" 2>/dev/null
mkdir -p "/home/$U1/.aikernel"
printf 'ts=1750000201 uid=1999 user=%s ev=sudo\n' "$U1" \
    > "/home/$U1/.aikernel/audit.log"

pass=0
fail=0
has() { printf '%s' "$1" | grep -qF -- "$2"; }
nlines() { printf '%s' "$1" | grep -c "$2"; }
ck() {
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

echo "== 1. 默认通道（HOME 桩）：缺省尾 20 =="
out=$(HOME="$H1" $AIKCTL audit tail 2>&1); rc=$?
ck "rc=0" "[ '$rc' = 0 ]"
ck "恰 20 行（25 行桩）" "[ \"\$(nlines \"\$out\" 'ts=')\" = 20 ]"
ck "尾 20 含末行 ts=1750000025" "has \"\$out\" '1750000025'"
ck "头 5 行不在（1750000001）" "! has \"\$out\" '1750000001'"

echo "== 2. -n 2 =="
out=$(HOME="$H1" $AIKCTL audit tail -n 2 2>&1); rc=$?
ck "-n 2 rc=0 恰 2 行" "[ '$rc' = 0 ] && [ \"\$(nlines \"\$out\" 'ts=')\" = 2 ]"

echo "== 3. 缺失家=人话 rc0 =="
out=$(HOME="$H3" $AIKCTL audit tail 2>&1); rc=$?
ck "缺失 rc=0" "[ '$rc' = 0 ]"
ck "缺失人话（无审计日志）" "has \"\$out\" '无审计日志'"

echo "== 4. --user 通道（root） =="
out=$($AIKCTL audit tail --user "$U1" 2>&1); rc=$?
ck "--user rc=0 行原样" "[ '$rc' = 0 ] && has \"\$out\" 'user=$U1'"
out=$($AIKCTL audit tail --user tstp2dnope 2>&1); rc=$?
ck "无此号拒绝 rc!=0 人话" "[ '$rc' != 0 ] && has \"\$out\" '无此号'"

echo "== 5. --all 聚合（家目录桩） =="
out=$(AIK_AUDIT_HOME_DIRS="$H1:$H2:$H3" $AIKCTL audit tail --all -n 3 2>&1); rc=$?
ck "--all rc=0" "[ '$rc' = 0 ]"
ck "行首标用户（alice/bob）" "has \"\$out\" 'alice: ts=' && has \"\$out\" 'bob: ts='"
ck "每家尾 3 行（alice 恰 3）" "[ \"\$(nlines \"\$out\" 'alice: ts=')\" = 3 ]"
ck "无日志家如实标（carol）" "has \"\$out\" 'carol'"
ck "对端无用户行混入（原样行含 uid=/user=）" "has \"\$out\" 'uid=1002 user=bob'"

echo "== 6. 非 root 权限面 =="
if id jack66g >/dev/null 2>&1; then
    out=$(runuser -u jack66g -- env AIK_AUDIT_HOME_DIRS="$H1:$H2" \
          python3 ./aikctl audit tail --all 2>&1); rc=$?
    ck "非 root --all 人话拒绝" "[ '$rc' != 0 ] && has \"\$out\" 'root'"
    out=$(runuser -u jack66g -- python3 ./aikctl audit tail --user "$U1" \
          2>&1); rc=$?
    ck "非 root --user 他人人话拒绝" "[ '$rc' != 0 ] && has \"\$out\" 'root'"
    chmod 755 "$T" "$H2" "$H2/.aikernel"   # 桩可读化（真面=本人家自有权限）
    chmod 644 "$H2/.aikernel/audit.log"
    out=$(runuser -u jack66g -- env HOME="$H2" python3 ./aikctl audit tail \
          2>&1); rc=$?
    ck "非 root 自己默认通道可用" "[ '$rc' = 0 ] && has \"\$out\" 'user=bob'"
else
    echo "  SKIP 非 root 面（jack66g 不在——仅 L1 打版机路径）"
fi

echo "== 7. -n 负数拒绝 =="
out=$($AIKCTL audit tail -n -1 2>&1); rc=$?
ck "-n -1 rc!=0" "[ '$rc' != 0 ]"

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
