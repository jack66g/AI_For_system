#!/bin/sh
# test_quota.sh - P-2 Phase B aikctl quota get 测试（G-007）。
#
# 隔离：工具探测走桩 PATH（$T/bin/quota 假脚本——L1 无 quota 工具，
# 桩补在场态）；挂载探测走 AIK_PROC_MOUNTS 桩文件——不碰真
# /proc/mounts。无需 root。
#
# 断言面：工具缺席=诚实 unavailable+rc0（PATH 构造藏工具）→ 挂载缺席
# （工具在场）=unavailable 提 usrquota → 工具+挂载在场=表格 blocks/
# inodes soft/hard+调用形态 quota -u → group kind 调用 -g → --json
# 结构断言（rows/mounts/tools）。
set -u
cd "$(dirname "$0")/.." || exit 2          # → agent/ai/aikctl
AIKCTL="python3 ./aikctl"

T=$(mktemp -d /tmp/p2b-quota.XXXXXX)
mkdir "$T/bin"
cat > "$T/bin/quota" <<'EOF'
#!/bin/sh
# 桩 quota：记录调用形态，吐一份 quota(8) 风格表
echo "quota $*" >> "${QUOTA_LOG:-/dev/null}"
cat <<'TBL'
Disk quotas for user stub (uid 1001):
Filesystem  blocks   quota   limit   grace   files   quota   limit   grace
/dev/sda1      100     200     300    7days      10       0       0       -
TBL
EOF
chmod +x "$T/bin/quota"
QUOTA_LOG="$T/q.log"
export QUOTA_LOG

printf '/dev/sda1 / ext4 rw,usrquota,grpquota 0 0\n/dev/sdb1 /data ext4 rw 0 0\n' \
    > "$T/mounts.quota"
printf '/dev/sda1 / ext4 rw,relatime 0 0\n' > "$T/mounts.plain"

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

echo "== 1. 工具缺席=诚实 unavailable（rc0——缺席是合法态） =="
PYDIR=$(dirname "$(command -v python3)")
if PATH="$PYDIR" command -v quota >/dev/null 2>&1; then
    echo "  SKIP 工具缺席面（quota 与 python3 同目录，PATH 藏不掉）"
else
    out=$(PATH="$PYDIR" AIK_PROC_MOUNTS="$T/mounts.quota" \
          $AIKCTL quota get 2>&1); rc=$?
    ck "工具缺席 rc=0" "[ '$rc' = 0 ]"
    ck "unavailable 人话" "has \"\$out\" 'unavailable'"
    ck "原因提工具不在 PATH" "has \"\$out\" 'quota 工具不在 PATH'"
    out=$(PATH="$PYDIR" AIK_PROC_MOUNTS="$T/mounts.quota" \
          $AIKCTL quota get --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["status"] == "unavailable" and d["reason"], d
assert d["tools"] == {"quota": False, "repquota": False, "setquota": False}
assert d["mounts"], "挂载探测结果仍如实列出"
')
    ck "工具缺席 --json：status=unavailable+tools 全缺" "[ $? = 0 ]"
fi

echo "== 2. 挂载缺席（工具在场）=unavailable 提 usrquota =="
out=$(PATH="$T/bin:$PATH" AIK_PROC_MOUNTS="$T/mounts.plain" \
      $AIKCTL quota get 2>&1); rc=$?
ck "挂载缺席 rc=0" "[ '$rc' = 0 ]"
ck "unavailable 人话" "has \"\$out\" 'unavailable'"
ck "原因提 usrquota" "has \"\$out\" 'usrquota'"
out=$(PATH="$T/bin:$PATH" AIK_PROC_MOUNTS="$T/mounts.plain" \
      $AIKCTL quota get --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["status"] == "unavailable" and "usrquota" in d["reason"]
assert d["tools"]["quota"] is True
')
ck "挂载缺席 --json：工具在场如实标" "[ $? = 0 ]"

echo "== 3. 工具+挂载在场：表格面+调用形态 =="
: > "$T/q.log"
out=$(PATH="$T/bin:$PATH" AIK_PROC_MOUNTS="$T/mounts.quota" \
      $AIKCTL quota get 2>&1); rc=$?
ck "在场 rc=0" "[ '$rc' = 0 ]"
ck "blocks used/soft/hard 呈现" "has \"\$out\" '100/200/300'"
ck "inodes used/soft/hard 呈现" "has \"\$out\" '10/0/0'"
ck "配额挂载列出" "has \"\$out\" '/dev/sda1 on /'"
ck "调用形态 quota -u <当前号>" "has \"\$(cat '$T/q.log')\" '-u'"

echo "== 4. group kind：调用 -g <名> =="
: > "$T/q.log"
out=$(PATH="$T/bin:$PATH" AIK_PROC_MOUNTS="$T/mounts.quota" \
      $AIKCTL quota get group --name wheel 2>&1); rc=$?
ck "group rc=0" "[ '$rc' = 0 ]"
ck "调用形态 quota -g wheel" "has \"\$(cat '$T/q.log')\" '-g wheel'"

echo "== 5. --json 结构断言（rows/mounts/tools） =="
out=$(PATH="$T/bin:$PATH" AIK_PROC_MOUNTS="$T/mounts.quota" \
      $AIKCTL quota get --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["status"] == "ok" and d["kind"] == "user"
assert d["tools"] == {"quota": True, "repquota": False, "setquota": False}
assert len(d["mounts"]) == 1 and d["mounts"][0]["usrquota"] is True
assert d["mounts"][0]["grpquota"] is True
r = d["rows"][0]
assert r["fs"] == "/dev/sda1"
assert r["blocks"] == {"used": "100", "soft": "200", "hard": "300",
                       "grace": "7days"}
assert r["inodes"] == {"used": "10", "soft": "0", "hard": "0",
                       "grace": "-"}
')
ck "--json rows/mounts/tools 断言" "[ $? = 0 ]"

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
