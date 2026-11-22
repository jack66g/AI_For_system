#!/bin/sh
# test_console_v9.sh - aik-console v9 可测面断言（AIK_CONSOLE_DRY=1）。
#
# v9 的 DRY 面：只打印将 exec 的完整命令与目标/marker/log 解析值，不真
# exec 不落盘（无 TTY 也可跑；AIK_CONSOLE_DRY_TTY 选分支 tty）。本测试：
# sh -n 语法门 + root 目标（现 v8 路径逐字）+ 非根目标（setpriv 命令行
# 逐字——uid/gid 由 id 实取）+ 号不在回落 + gate.last 缺省 admin + fb
# 分支。需 root（写 /var/lib/aikernel/console-gate.last 桩，测后还原）。
#
# 测试号仅作 id/getent 解析桩（v9 降权链的 uid/gid 由此取），不真登录。
set -u
CONSOLE="$(cd "$(dirname "$0")/../../../../factory/usr/local/bin" \
           && pwd)/aik-console"

[ "$(id -u)" = 0 ] || { echo "需要 root（sudo sh $0）"; exit 2; }

U="tstp2bc$(printf '%s' $$)"
LAST=/var/lib/aikernel/console-gate.last
SAVED=$(mktemp /tmp/p2b-last.XXXXXX)
had_last=0
[ -f "$LAST" ] && { cat "$LAST" > "$SAVED"; had_last=1; }

pass=0
fail=0
ck() {
    if eval "$2"; then
        pass=$((pass+1)); echo "  PASS $1"
    else
        fail=$((fail+1)); echo "  FAIL $1"
    fi
}

cleanup() {
    if [ "$had_last" = 1 ]; then
        cat "$SAVED" > "$LAST"
    else
        rm -f "$LAST"
    fi
    rm -f "$SAVED"
    id -u "$U" >/dev/null 2>&1 && userdel -r "$U" 2>/dev/null
    true
}
trap cleanup EXIT INT TERM

echo "== 0. 语法门 =="
sh -n "$CONSOLE"
ck "sh -n rc=0" "[ '$?' = 0 ]"

useradd -m -s /bin/sh "$U" >/dev/null 2>&1
uid=$(id -u "$U")
gid=$(id -g "$U")
home=$(getent passwd "$U" | cut -d: -f6)
SP="setpriv --reuid=$uid --regid=$gid --init-groups --inh-caps=-all /usr/local/bin/occ"

echo "== 1. root 目标（gate.last=root → 现 v8 路径逐字） =="
mkdir -p /var/lib/aikernel
echo root > "$LAST"
out=$(AIK_CONSOLE_DRY=1 sh "$CONSOLE" 2>&1)
ck "uid=0" "case '$out' in *uid=0*) true;; *) false;; esac"
ck "marker=现名 /run/aik-occ-exit（uid==0 契约）" \
   "case '$out' in *'marker=/run/aik-occ-exit (fallback /tmp/aik-occ-exit)'*) true;; *) false;; esac"
ck "log=/root/aik-console.log（兼容观察面）" \
   "case '$out' in *'log=/root/aik-console.log'*) true;; *) false;; esac"
ck "exec 逐字=v8 串口路径" \
   "case '$out' in *'DRY exec: OCC_NETCFG_TOOLS=1 /usr/local/bin/occ 2>> /root/aik-console.err'*) true;; *) false;; esac"
ck "无 setpriv" "case '$out' in *setpriv*) false;; *) true;; esac"

echo "== 2. 非根目标（setpriv 命令行逐字；uid/gid 由 id 取） =="
echo "$U" > "$LAST"
out=$(AIK_CONSOLE_DRY=1 sh "$CONSOLE" 2>&1)
ck "user/uid/home 解析" \
   "case '$out' in *\"user=$U uid=$uid gid=$gid home=$home\"*) true;; *) false;; esac"
ck "setpriv 命令行逐字" "case '$out' in *\"$SP\"*) true;; *) false;; esac"
ck "marker 按 uid 分路 /run/aik-occ-exit.$uid" \
   "case '$out' in *\"marker=/run/aik-occ-exit.$uid (fallback /tmp/aik-occ-exit.$uid)\"*) true;; *) false;; esac"
ck "log=/var/log/aik-console/$U.log" \
   "case '$out' in *'log=/var/log/aik-console/$U.log'*) true;; *) false;; esac"
ck "非 admin 目标无归位动作" "case '$out' in *place-admin*) false;; *) true;; esac"

echo "== 3. 号不在 → 回落 v8 路径 =="
UNX="nosuch$(printf '%s' $$)u"
echo "$UNX" > "$LAST"
out=$(AIK_CONSOLE_DRY=1 sh "$CONSOLE" 2>&1)
ck "回落 uid=0" "case '$out' in *uid=0*) true;; *) false;; esac"
ck "回落现名 marker" \
   "case '$out' in *'marker=/run/aik-occ-exit (fallback'*) true;; *) false;; esac"
ck "回落 root 日志" "case '$out' in *'log=/root/aik-console.log'*) true;; *) false;; esac"

echo "== 4. gate.last 缺失 → 缺省 admin（L1 无 admin 号 → root 路径） =="
rm -f "$LAST"
out=$(AIK_CONSOLE_DRY=1 sh "$CONSOLE" 2>&1)
ck "缺省目标=admin" "case '$out' in *user=admin*) true;; *) false;; esac"
if id -u admin >/dev/null 2>&1; then
    echo "  SKIP root 路径断言（本机竟有 admin 号——工厂面才会出现）"
else
    ck "admin 号不在→root 路径+现名 marker" \
       "case '$out' in *'marker=/run/aik-occ-exit (fallback'*) true;; *) false;; esac"
fi

echo "== 5. fb 分支（tty1）非根目标 =="
echo "$U" > "$LAST"
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 sh "$CONSOLE" 2>&1)
ck "分支=tty1" "case '$out' in *tty=/dev/tty1*) true;; *) false;; esac"
ck "fb 链 setpriv 降权（fbterm 有无都含 $SP）" \
   "case '$out' in *\"$SP\"*) true;; *) false;; esac"
ck "fb 链 marker 按 uid" "case '$out' in *\"marker=/run/aik-occ-exit.$uid\"*) true;; *) false;; esac"

echo "== 6. fb 分支 root 目标 =="
echo root > "$LAST"
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 sh "$CONSOLE" 2>&1)
ck "fb 链 root=现路径（occ 直跑或 fbterm 包裹，无 setpriv）" \
   "case '$out' in *setpriv*) false;; *) true;; esac"
ck "fb 链 root marker 现名" \
   "case '$out' in *'marker=/run/aik-occ-exit (fallback'*) true;; *) false;; esac"

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
