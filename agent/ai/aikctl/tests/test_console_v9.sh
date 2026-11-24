#!/bin/sh
# test_console_v9.sh - aik-console v9/v11 可测面断言（AIK_CONSOLE_DRY=1）。
#
# v9 的 DRY 面：只打印将 exec 的完整命令与目标/marker/log 解析值，不真
# exec 不落盘（无 TTY 也可跑；AIK_CONSOLE_DRY_TTY 选分支 tty）。本测试：
# sh -n 语法门 + root 目标（现 v8 路径逐字）+ 非根目标（setpriv 命令行
# 逐字——uid/gid 由 id 实取）+ 号不在回落 + gate.last 缺省 admin + fb
# 分支。需 root（写 /var/lib/aikernel/console-gate.last 桩，测后还原）。
#
# v11（CON-02c）增 7~9 节：fb 链上非 root 目标的 fbterm 以系统
# 配置 HOME（/root）起、occ 经 env HOME=<用户家> 拿用户家目录；/zoom
# 字号经白名单透传为 fbterm -s；root 目标与串口链 exec 行逐字不变。
# fbterm 有无都能测：DRY 面用 AIK_CONSOLE_FBTERM 指定桩路径（只影响
# 打印，不 exec）。
#
# v12（P-60/D7，DEC-07 过渡方案）增 10 节：gate 权限归一 gate_perm_fix 的
# DRY 面——不合规（组在、文件在、非 root:aik-gate+0640）打印、合规不打印、
# 无组不打印、无文件不打印、串口分支同样挂、root 与非 root 目标的 exec
# 行逐字不变。桩文件/桩组名走 DRY 专用变量 AIK_CONSOLE_GATE_FILE /
# AIK_CONSOLE_GATE_GROUP，不碰真 gate、不建组。
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
    [ -n "${FBSTUB:-}" ] && rm -f "$FBSTUB"
    [ -n "${GSTUB:-}" ] && rm -f "$GSTUB"
    [ -n "${STUBD:-}" ] && rm -rf "$STUBD"
    id -u "$U" >/dev/null 2>&1 && rm -rf "/var/ai/work/$U" \
        /var/log/aik-console/$U.log /var/log/aik-console/$U.err
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

echo "== 7. v11 fb 链非根目标：fbterm 读系统配置、occ 拿用户家目录 =="
# fbterm 有无都能测：DRY 面用桩路径指定 fbterm（只影响打印，不 exec）
FBSTUB=$(mktemp /tmp/p2b-fbterm.XXXXXX)
printf '#!/bin/sh\nexit 0\n' > "$FBSTUB"
chmod 755 "$FBSTUB"
echo "$U" > "$LAST"
rm -f "$home/.fbtermrc"
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 \
      AIK_CONSOLE_FBTERM="$FBSTUB" sh "$CONSOLE" 2>&1)
ck "fbterm 以系统配置起：HOME=/root USER=root 紧贴 fbterm" \
   "case '$out' in *'DRY exec: FBTERM=1 OCC_NETCFG_TOOLS=1 env HOME=/root USER=root $FBSTUB -- '*) true;; *) false;; esac"
ck "occ 经 env 拿用户家目录（setpriv 前缀）" \
   "case '$out' in *\"-- env HOME=$home USER=$U $SP\"*) true;; *) false;; esac"
ck "occ 的 HOME 是用户家目录（-- 之后是 env HOME=<用户家>，不是 /root）" \
   "case '$out' in *\"-- env HOME=$home USER=$U $SP\"*) true;; *) false;; esac && case '$out' in *'-- env HOME=/root'*) false;; *) true;; esac"
ck "无 ~/.fbtermrc 不传字号（无 -s）" \
   "case '$out' in *' -s '*) false;; *) true;; esac"
ck "fb 一览行：fbterm-home=/root occ-home=用户家目录 zoom=none" \
   "case '$out' in *\"DRY fb: fbterm-home=/root (system .fbtermrc) occ-home=$home user=$U zoom=none\"*) true;; *) false;; esac"

# /zoom 透传：occ 写在 ~/.fbtermrc 的 font-size（白名单档位）→ fbterm -s
printf 'font-names=mono\nfont-size=20\n' > "$home/.fbtermrc"
chown "$U" "$home/.fbtermrc" 2>/dev/null
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 \
      AIK_CONSOLE_FBTERM="$FBSTUB" sh "$CONSOLE" 2>&1)
ck "/zoom 字号透传：fbterm -s 20（在 -- 之前）" \
   "case '$out' in *\"USER=root $FBSTUB -s 20 -- env HOME=$home \"*) true;; *) false;; esac"
ck "一览行 zoom=-s 20" \
   "case '$out' in *'zoom=-s 20'*) true;; *) false;; esac"
# 非档位/注入形态一律不透传（用户可控文件只解析、不外传）
printf 'font-size=9999\nfont-size=20; rm -rf /\nfont-size=$(id)\nfont-size=abc\n' > "$home/.fbtermrc"
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 \
      AIK_CONSOLE_FBTERM="$FBSTUB" sh "$CONSOLE" 2>&1)
ck "非档位/注入形态不透传（无 -s）" \
   "case '$out' in *' -s '*|*'rm -rf'*|*'\$(id)'*) false;; *) true;; esac"
printf 'font-size=32\r\n' > "$home/.fbtermrc"
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 \
      AIK_CONSOLE_FBTERM="$FBSTUB" sh "$CONSOLE" 2>&1)
ck "CRLF 容错：fbterm -s 32" \
   "case '$out' in *\"USER=root $FBSTUB -s 32 -- \"*) true;; *) false;; esac"
# FIFO：不读、不挂死
rm -f "$home/.fbtermrc"
mkfifo "$home/.fbtermrc"
out=$(timeout 20 env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 \
     AIK_CONSOLE_FBTERM="$FBSTUB" sh "$CONSOLE" 2>&1)
frc=$?
ck "FIFO 不读不挂死（rc=0 且无 -s）" \
   "[ '$frc' = 0 ] && case '$out' in *' -s '*) false;; *) true;; esac"
rm -f "$home/.fbtermrc"

echo "== 8. v11 fb 链 root 目标：exec 行逐字不变（无 env/HOME=/-s 前缀） =="
echo root > "$LAST"
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 \
      AIK_CONSOLE_FBTERM="$FBSTUB" sh "$CONSOLE" 2>&1)
ck "root exec 行逐字" \
   "case '$out' in *'DRY exec: FBTERM=1 OCC_NETCFG_TOOLS=1 $FBSTUB -- /usr/local/bin/occ 2>> /root/aik-console.err'*) true;; *) false;; esac"
ck "root 无 env/HOME=/USER=root/-s/一览行" \
   "case '$out' in *' env HOME='*|*'HOME=/root USER='*|*'USER=root'*|*' -s '*|*'DRY fb:'*) false;; *) true;; esac"

echo "== 9. v11 串口链非根目标：不套 env（脚本导出的 HOME/USER 即用户） =="
echo "$U" > "$LAST"
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_FBTERM="$FBSTUB" sh "$CONSOLE" 2>&1)
ck "串口 exec 行逐字不变（桩 fbterm 不影响串口分支）" \
   "case '$out' in *'DRY exec: OCC_NETCFG_TOOLS=1 $SP 2>> /var/log/aik-console/$U.err'*) true;; *) false;; esac"
ck "串口无 env 前缀/无 fb 一览行" \
   "case '$out' in *' env HOME='*|*'DRY fb:'*|*'DRY exec: FBTERM'*) false;; *) true;; esac"

echo "== 10. v12 gate 权限归一（DRY 面：不合规打印／合规不打印／无组不打印；exec 行逐字不变） =="
# 三条分支全走 DRY、不碰真 gate 也不建组：AIK_CONSOLE_GATE_FILE 指桩文件，
# AIK_CONSOLE_GATE_GROUP 指桩组名——「有组」用恒在的 root 组（gid 0），
# 「无组」用必不存在的名字。结果与机器上有没有 aik-gate 组无关。
GSTUB=$(mktemp /tmp/p2b-gatefile.XXXXXX)
echo "$U" > "$LAST"
run10() { # run10 <组名> → out（fb 分支、桩 fbterm、桩 gate 文件）
    out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 \
          AIK_CONSOLE_FBTERM="$FBSTUB" \
          AIK_CONSOLE_GATE_FILE="$GSTUB" AIK_CONSOLE_GATE_GROUP="$1" \
          sh "$CONSOLE" 2>&1)
}
echo "  -- 10.1 有组+不合规（0600 root:root）→ 打印归一动作"
chown root:root "$GSTUB"
chmod 0600 "$GSTUB"
run10 root
ck "10.1 打印归一动作（现值 uid=0 gid=0 mode=600）" \
   "case '$out' in *\"DRY gate-perm: chown root:root $GSTUB; chmod 0640 $GSTUB (now uid=0 gid=0 mode=600)\"*) true;; *) false;; esac"
ck "10.1 DRY 不真改（桩文件仍 0600 root:root）" \
   "[ \"\$(stat -c '%a %U %G' '$GSTUB')\" = '600 root root' ]"
ck "10.1 非 root 目标的其余 DRY 行照常" \
   "case '$out' in *\"user=$U uid=$uid gid=$gid home=$home\"*) true;; *) false;; esac"
echo "  -- 10.2 有组+合规（0640 root:root）→ 不打印"
chmod 0640 "$GSTUB"
run10 root
ck "10.2 合规不打印 gate-perm" "case '$out' in *gate-perm*) false;; *) true;; esac"
ck "10.2 DRY 输出仍在（非误退出）" "case '$out' in *'DRY tty=/dev/tty1 user='$U*) true;; *) false;; esac"
echo "  -- 10.3 无组（组名必不存在）+不合规 → 不打印"
chmod 0600 "$GSTUB"
run10 "nosuchgp$$x"
ck "10.3 无组不打印 gate-perm" "case '$out' in *gate-perm*) false;; *) true;; esac"
echo "  -- 10.4 gate 文件不在 → 不打印"
rm -f "$GSTUB"
run10 root
ck "10.4 无文件不打印 gate-perm" "case '$out' in *gate-perm*) false;; *) true;; esac"
echo "  -- 10.5 串口分支同样挂了归一（两条循环都要）"
printf 'x\n' > "$GSTUB"
chown root:root "$GSTUB"
chmod 0600 "$GSTUB"
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_GATE_FILE="$GSTUB" \
      AIK_CONSOLE_GATE_GROUP=root sh "$CONSOLE" 2>&1)
ck "10.5 串口分支打印归一动作" \
   "case '$out' in *\"DRY gate-perm: chown root:root $GSTUB; chmod 0640 $GSTUB\"*) true;; *) false;; esac"
ck "10.5 串口 exec 行逐字不变" \
   "case '$out' in *'DRY exec: OCC_NETCFG_TOOLS=1 $SP 2>> /var/log/aik-console/$U.err'*) true;; *) false;; esac"
echo "  -- 10.6 归一动作在打印面上，exec 行逐字不变"
run10 root
ck "10.6 非 root 目标 fb 链 exec 行逐字同 v11" \
   "case '$out' in *\"DRY exec: FBTERM=1 OCC_NETCFG_TOOLS=1 env HOME=/root USER=root $FBSTUB -- env HOME=$home USER=$U $SP 2>> /var/log/aik-console/$U.err\"*) true;; *) false;; esac"
echo root > "$LAST"
run10 root
ck "10.6 root 目标 fb 链 exec 行逐字同 v11" \
   "case '$out' in *'DRY exec: FBTERM=1 OCC_NETCFG_TOOLS=1 $FBSTUB -- /usr/local/bin/occ 2>> /root/aik-console.err'*) true;; *) false;; esac"
ck "10.6 归一发生在 root 时刻，与目标用户无关（root 目标同样打印）" \
   "case '$out' in *\"DRY gate-perm: chown root:root $GSTUB; chmod 0640 $GSTUB\"*) true;; *) false;; esac"
echo "  -- 10.7 缺省组名（aik-gate）：随机器有无该组"
echo "$U" > "$LAST"
out=$(AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_TTY=/dev/tty1 \
      AIK_CONSOLE_FBTERM="$FBSTUB" AIK_CONSOLE_GATE_FILE="$GSTUB" \
      sh "$CONSOLE" 2>&1)
if getent group aik-gate >/dev/null 2>&1; then
    ck "10.7 本机有 aik-gate：缺省组名下打印归一动作" \
       "case '$out' in *\"DRY gate-perm: chown root:aik-gate $GSTUB; chmod 0640 $GSTUB\"*) true;; *) false;; esac"
else
    ck "10.7 本机无 aik-gate：缺省组名不打印（回落，行为同 v11）" \
       "case '$out' in *gate-perm*) false;; *) true;; esac"
fi
rm -f "$GSTUB"

echo "== 11. v12.1 真执行面（非 DRY）：非 root 目标的 fb 链确实起得来 =="
# v11/v12 的 exec 行把 $FB_PRE（HOME=/root USER=root）拼在命令前——shell 在
# 展开之前就判定哪些词是「变量赋值前缀」，展开出来的 HOME=/root 被当成命令
# 名（「HOME=/root: not found」rc=127，每 2 秒重启一次）：非 root 的 VGA 控制台
# 起不来（17.11.1 台架管理章咬出）。上面各节只验 DRY 打印面，验不到这个。
# 这里让脚本真跑到 exec 行：PATH 前置桩 tty（报 /dev/tty1）与桩 fbterm（记下
# 自己被怎样起动，然后以 71 退=用户主动退出→脚本断链 exit 0）。不跑 root
# 目标（那会往本机 /root/aik-console.log 写日志）。
STUBD=$(mktemp -d /tmp/p2b-stub.XXXXXX)
cat > "$STUBD/tty" <<'EOF'
#!/bin/sh
echo /dev/tty1
EOF
cat > "$STUBD/fbterm" <<'EOF'
#!/bin/sh
echo "home=$HOME user=$USER" > "$FBSTUB_OUT"
echo "args: $*" >> "$FBSTUB_OUT"
exit 71
EOF
chmod +x "$STUBD/tty" "$STUBD/fbterm"
FBSTUB_OUT=$STUBD/fb.out
HAD_LOGD=0; [ -d /var/log/aik-console ] && HAD_LOGD=1
echo "$U" > "$LAST"
out=$(cd / && env -i PATH="$STUBD:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      HOME=/root FBSTUB_OUT="$FBSTUB_OUT" timeout 20 sh "$CONSOLE" 2>&1)
rc=$?
echo "  -- rc=$rc（修复前=124：127 重启环直到超时）"
ck "11.1 脚本经 occ-logout 正常退出（rc=0，未陷入 127 重启环）" "[ '$rc' = 0 ]"
ck "11.2 桩 fbterm 真被启动（留下了起动记录）" "[ -s '$FBSTUB_OUT' ]"
ck "11.3 fbterm 以系统配置起：HOME=/root USER=root" \
   "case \"\$(cat '$FBSTUB_OUT' 2>/dev/null)\" in *'home=/root user=root'*) true;; *) false;; esac"
ck "11.4 传给 fbterm 的参数：-- env HOME=<用户家> USER=<用户> setpriv … occ" \
   "case \"\$(cat '$FBSTUB_OUT' 2>/dev/null)\" in *\"args: -- env HOME=$home USER=$U $SP\"*) true;; *) false;; esac"
ck "11.5 无「not found」" "case \"\$out\" in *'not found'*) false;; *) true;; esac"
ck "11.6 日志记的是 occ-logout，且没有 rc=127" \
   "grep -q 'occ-logout tty=fb user=$U' /var/log/aik-console/$U.log 2>/dev/null && ! grep -q 'rc=127' /var/log/aik-console/$U.log 2>/dev/null"
rm -rf "$STUBD"; STUBD=
rm -rf "/var/ai/work/$U"
rm -f /var/log/aik-console/$U.log /var/log/aik-console/$U.err
[ "$HAD_LOGD" = 1 ] || rmdir /var/log/aik-console 2>/dev/null

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
