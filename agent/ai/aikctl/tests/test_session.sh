#!/bin/sh
# test_session.sh - P-2 Phase B aikctl session list 测试（utmp 桩）。
#
# 隔离：AIK_UTMP 指向 python struct 手写的桩二进制（384B/条 glibc 布局，
# 与真机 od 实测一致）——不碰 /var/run/utmp。无需 root。
#
# 断言面：USER_PROCESS 行解析（user/tty/host/时间）→ 非 7 型（BOOT_TIME）
# 与空名行滤出 → 尾零头诚实警告 → wtmp 注明 → --json 键断言 →
# 缺席态人话 rc0。
set -u
cd "$(dirname "$0")/.." || exit 2          # → agent/ai/aikctl
AIKCTL="python3 ./aikctl"

T=$(mktemp -d /tmp/p2b-sess.XXXXXX)
UT="$T/utmp"
export AIK_UTMP="$UT"

pass=0
fail=0
has() { printf '%s' "$1" | grep -qF -- "$2"; }
ck() {
    if eval "$2"; then
        pass=$((pass+1)); echo "  PASS $1"
    else
        fail=$((fail+1)); echo "  FAIL $1"
    fi
}
cleanup() { rm -rf "$T"; }
trap cleanup EXIT INT TERM

# 桩 utmp：4 条 384B 记录 + 10B 尾零头
#   rec1 USER_PROCESS(7) tstp2da pts/3 10.0.0.9 —— 应入表
#   rec2 BOOT_TIME(2) reboot —— 非 7 型滤出
#   rec3 USER_PROCESS(7) 但 user 空 —— 滤出+警告
#   rec4 USER_PROCESS(7) tstp2db pts/9 无来源 —— 入表 host=-
python3 - "$UT" <<'PYEOF'
import struct, sys
F = '<h2xi32s4s32s256shhiii16s20x'
assert struct.calcsize(F) == 384

def rec(t, pid, line, ident, user, host, sec):
    return struct.pack(F, t, pid, line.encode(), ident.encode(),
                       user.encode(), host.encode(), 0, 0, 0, sec, 0,
                       bytes(16))

blob = b''.join([
    rec(7, 3512, 'pts/3', 's3', 'tstp2da', '10.0.0.9', 1750000000),
    rec(2, 0, '~', '~~', 'reboot', '6.8.0-149-generic', 1750000100),
    rec(7, 4000, 'tty1', '1', '', '', 1750000200),
    rec(7, 4711, 'pts/9', 's9', 'tstp2db', '', 1750000300),
])
blob += b'\x00' * 10
open(sys.argv[1], 'wb').write(blob)
print('stub utmp: %d bytes (%d recs + 10 trailing)' % (len(blob), 4))
PYEOF

echo "== 1. session list 表格面 =="
out=$($AIKCTL session list 2>&1); rc=$?
ck "rc=0" "[ '$rc' = 0 ]"
ck "两个 USER_PROCESS 会话列出" "has \"\$out\" 'tstp2da' && has \"\$out\" 'tstp2db'"
ck "tty/host 呈现" "has \"\$out\" 'pts/3' && has \"\$out\" '10.0.0.9'"
ck "登录时间（1750000000 本地日 2025-06-15）" "has \"\$out\" '2025-06-15'"
ck "BOOT_TIME 行滤出（reboot 不在）" "! has \"\$out\" 'reboot'"
ck "空名 USER_PROCESS 滤出" "! has \"\$out\" 'tty1'"
ck "无来源 host=-" "has \"\$out\" 'pts/9'"
ck "idle 不可得=-" "has \"\$out\" '  -'"
ck "wtmp 历史不在此面注明" "has \"\$out\" 'wtmp'"
ck "尾零头诚实警告" "has \"\$out\" '尾 10 字节忽略'"

echo "== 2. --json 键断言 =="
j=$($AIKCTL session list --json 2>/dev/null)
rc=$?
ck "--json rc=0" "[ '$rc' = 0 ]"
out=$(printf '%s' "$j" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["utmp"].endswith("/utmp"), d["utmp"]
ss = d["sessions"]
assert len(ss) == 2, ss
a = [s for s in ss if s["user"] == "tstp2da"][0]
b = [s for s in ss if s["user"] == "tstp2db"][0]
assert a["tty"] == "pts/3" and a["host"] == "10.0.0.9"
assert a["begin_epoch"] == 1750000000 and a["pid"] == 3512
assert a["begin_local"].startswith("2025-06-15")
assert a["idle_seconds"] is None, "桩 /dev/pts/3 不可得 → null"
assert b["host"] is None
assert len(d["warnings"]) == 2, d["warnings"]
assert "wtmp" in d["note"]
')
ck "--json 键/值断言（2 会话+2 警告+note）" "[ $? = 0 ]"

echo "== 3. utmp 缺席态（人话 rc0） =="
out=$(AIK_UTMP="$T/none" $AIKCTL session list 2>&1); rc=$?
ck "缺失 rc=0" "[ '$rc' = 0 ]"
ck "缺失人话（不存在+无会话）" "has \"\$out\" '不存在'"
j=$(AIK_UTMP="$T/none" $AIKCTL session list --json 2>/dev/null)
out=$(printf '%s' "$j" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["sessions"] == [] and len(d["warnings"]) == 1
')
ck "缺失 --json：空会话+1 警告" "[ $? = 0 ]"

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
