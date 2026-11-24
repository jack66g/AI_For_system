#!/bin/sh
# test_console_v9.sh - aik-console v13 可测面断言（DRY 打印面 + 真执行桩）。
#
# v13（CON-11 两阶段控制台）后本测试的分节：
#   §0 语法门
#   §1 root 目标（.last=root → root 会话，串口链）
#   §2 非根目标（setpriv 命令行逐字；uid/gid 由 id 实取）
#   §3 目标用户无 OS 号 → fail-closed（**不再**回落 root）
#   §4 .last 缺失 → 缺省 admin；gate 无 admin 条目时同样 fail-closed
#   §5/§6 fb 分支（tty1）非根/root 目标
#   §7/§8/§9 v11 fb 链与环境/字号（exec 行按 v13 阶段 S 对齐）
#   §10 v12 gate 权限归一 gate_perm_fix（DRY 面，逐条对齐）
#   §11 v12.1 真执行面（非 DRY）：fb 链两阶段全流 + 身份断言
#   §12 阶段 G/S 的 DRY 行形状（GATE_ONLY / per-seat / 无 setpriv；S 有
#       setpriv 与 GATE_SKIP）
#   §13 席位隔离：VGA 与串口各读/各写各的 per-seat .last，互不覆盖
#   §14 旧全局 .last → per-seat 首次迁移（DRY 打印 + 真迁移落盘 0600）
#   §15 fail-closed 两条边界：alice 无号不得 root exec；admin 无号 +
#       gate 有 admin 条目 + aikctl 缺席才允许旧盘 root 回落
#   §16 兼容探针回退：桩 occ 不认 --console-gate-version（rc=2）→ console
#       不得以 root exec occ，必须走 v12.1 旧降权路径（真执行验证 uid）
#
# 两阶段的可测面：
#   · DRY 面打印阶段 G（DRY gate: …）与阶段 S（DRY exec: …）完整命令；
#     探针结果可用 AIK_CONSOLE_DRY_PROBE=ok|fail 覆盖（DRY 专用），
#     缺省跑真探针（/usr/local/bin/occ 不在=旧件=回退单阶段）。
#   · 真执行桩：AIK_CONSOLE_TEST=1 + AIK_CONSOLE_OCC=<桩>（生产不设）。
# 需 root（写 /var/lib/aikernel 席位状态桩、建测试号、跑登录门夹具）。
set -u
CONSOLE="$(cd "$(dirname "$0")/../../../../factory/usr/local/bin" \
           && pwd)/aik-console"

[ "$(id -u)" = 0 ] || { echo "需要 root（sudo sh $0）"; exit 2; }

U="tstp2bc$(printf '%s' $$)"
LASTD=/var/lib/aikernel
LAST=$LASTD/console-gate.last
LAST_VGA=$LASTD/console-gate.last.vga
LAST_SERIAL=$LASTD/console-gate.last.serial
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

# 每个 DRY 探针结果缺省 ok（=新 occ）；个别小节把它置空跑真探针。
PROBE=ok

# run_dry <env...>：AIK_CONSOLE_DRY=1 + 探针覆盖，输出进 $out
run_dry() {
    out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" "$@" \
          sh "$CONSOLE" 2>&1)
}

set_global_last() { # <user>
    mkdir -p "$LASTD"
    printf '%s\n' "$1" > "$LAST"
}
set_seat_last() { # <vga|serial> <user>
    mkdir -p "$LASTD"
    printf '%s\n' "$2" > "$LASTD/console-gate.last.$1"
    chmod 600 "$LASTD/console-gate.last.$1"
}
clear_last() { # 清全局与两席位（模拟「从未有用户登录」）
    rm -f "$LAST" "$LAST_VGA" "$LAST_SERIAL"
}

cleanup() {
    if [ "$had_last" = 1 ]; then
        cat "$SAVED" > "$LAST"
    else
        rm -f "$LAST"
    fi
    rm -f "$SAVED" "$LAST_VGA" "$LAST_SERIAL"
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
# v13：阶段 S 的身份 env（两阶段才带；单阶段回退绝不带 GATE_SKIP）
SE="AIK_CONSOLE_GATE_SKIP=1 AIK_CONSOLE_AUTHED=$U"

echo "== 1. root 目标（.last=root → root 会话；串口链） =="
set_global_last root
rm -f "$LAST_VGA" "$LAST_SERIAL"
run_dry
ck "uid=0" "case '$out' in *uid=0*) true;; *) false;; esac"
ck "marker=现名 /run/aik-occ-exit（uid==0 契约）" \
   "case '$out' in *'marker=/run/aik-occ-exit (fallback /tmp/aik-occ-exit)'*) true;; *) false;; esac"
ck "log=/root/aik-console.log（兼容观察面）" \
   "case '$out' in *'log=/root/aik-console.log'*) true;; *) false;; esac"
ck "exec=v13 阶段 S root（GATE_SKIP + AUTHED=root，串口链经 env）" \
   "case '$out' in *'DRY exec: OCC_NETCFG_TOOLS=1 env AIK_CONSOLE_GATE_SKIP=1 AIK_CONSOLE_AUTHED=root /usr/local/bin/occ 2>> /root/aik-console.err'*) true;; *) false;; esac"
ck "无 setpriv" "case '$out' in *setpriv*) false;; *) true;; esac"

echo "== 2. 非根目标（setpriv 命令行逐字；uid/gid 由 id 取） =="
set_global_last "$U"
rm -f "$LAST_VGA" "$LAST_SERIAL"
run_dry
ck "user/uid/home 解析" \
   "case '$out' in *\"user=$U uid=$uid gid=$gid home=$home\"*) true;; *) false;; esac"
ck "setpriv 命令行逐字" "case '$out' in *\"$SP\"*) true;; *) false;; esac"
ck "marker 按 uid 分路 /run/aik-occ-exit.$uid" \
   "case '$out' in *\"marker=/run/aik-occ-exit.$uid (fallback /tmp/aik-occ-exit.$uid)\"*) true;; *) false;; esac"
ck "log=/var/log/aik-console/$U.log" \
   "case '$out' in *'log=/var/log/aik-console/$U.log'*) true;; *) false;; esac"
ck "非 admin 目标无归位动作" "case '$out' in *place-admin*) false;; *) true;; esac"

echo "== 3. 目标用户无 OS 号 → fail-closed（v13 不再回落 root） =="
UNX="nosuch$(printf '%s' $$)u"
set_global_last "$UNX"
rm -f "$LAST_VGA" "$LAST_SERIAL"
run_dry
ck "fail-closed 明确行（user=$UNX）" \
   "case '$out' in *\"DRY failclosed: user=$UNX reason=no-os-account\"*) true;; *) false;; esac"
ck "不出现任何会话 exec 行" "case '$out' in *'DRY exec:'*) false;; *) true;; esac"
ck "不出现 setpriv（更无以 root 起 occ）" \
   "case '$out' in *setpriv*) false;; *) true;; esac"

echo "== 4. .last 缺失 → 缺省 admin；gate 无 admin 条目 → fail-closed =="
clear_last
NOGATE=$(mktemp -u /tmp/con11-nogate.XXXXXX)
run_dry AIK_CONSOLE_GATE_FILE="$NOGATE"
ck "缺省目标=admin" "case '$out' in *user=admin*) true;; *) false;; esac"
if id -u admin >/dev/null 2>&1; then
    echo "  SKIP fail-closed 断言（本机竟有 admin 号——工厂面才会出现）"
else
    ck "admin 号不在且 gate 无 admin 条目 → fail-closed" \
       "case '$out' in *'DRY failclosed: user=admin reason=no-os-account'*) true;; *) false;; esac"
fi

echo "== 5. fb 分支（tty1）非根目标 =="
set_seat_last vga "$U"
rm -f "$LAST"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 sh "$CONSOLE" 2>&1)
ck "分支=tty1" "case '$out' in *tty=/dev/tty1*) true;; *) false;; esac"
ck "fb 链 setpriv 降权（fbterm 有无都含 $SP）" \
   "case '$out' in *\"$SP\"*) true;; *) false;; esac"
ck "fb 链 marker 按 uid" "case '$out' in *\"marker=/run/aik-occ-exit.$uid\"*) true;; *) false;; esac"

echo "== 6. fb 分支 root 目标 =="
set_seat_last vga root
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 sh "$CONSOLE" 2>&1)
ck "fb 链 root=现路径（occ 直跑或 fbterm 包裹，无 setpriv）" \
   "case '$out' in *setpriv*) false;; *) true;; esac"
ck "fb 链 root marker 现名" \
   "case '$out' in *'marker=/run/aik-occ-exit (fallback'*) true;; *) false;; esac"

echo "== 7. v11 fb 链非根目标：fbterm 读系统配置、occ 拿用户家目录 =="
# fbterm 有无都能测：DRY 面用桩路径指定 fbterm（只影响打印，不 exec）
FBSTUB=$(mktemp /tmp/p2b-fbterm.XXXXXX)
printf '#!/bin/sh\nexit 0\n' > "$FBSTUB"
chmod 755 "$FBSTUB"
set_seat_last vga "$U"
rm -f "$LAST" "$home/.fbtermrc"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 AIK_CONSOLE_FBTERM="$FBSTUB" \
      sh "$CONSOLE" 2>&1)
ck "fbterm 以系统配置起：HOME=/root USER=root 紧贴 fbterm" \
   "case '$out' in *'DRY exec: FBTERM=1 OCC_NETCFG_TOOLS=1 env HOME=/root USER=root $FBSTUB -- '*) true;; *) false;; esac"
ck "occ 经 env 拿用户家目录（setpriv 前缀）" \
   "case '$out' in *\"-- env HOME=$home USER=$U $SE $SP\"*) true;; *) false;; esac"
ck "occ 的 HOME 是用户家目录（-- 之后不是 /root）" \
   "case '$out' in *\"-- env HOME=$home USER=$U $SE $SP\"*) true;; *) false;; esac && case '$out' in *'-- env HOME=/root'*) false;; *) true;; esac"
ck "无 ~/.fbtermrc 不传字号（无 -s）" \
   "case '$out' in *' -s '*) false;; *) true;; esac"
ck "fb 一览行：fbterm-home=/root occ-home=用户家目录 zoom=none" \
   "case '$out' in *\"DRY fb: fbterm-home=/root (system .fbtermrc) occ-home=$home user=$U zoom=none\"*) true;; *) false;; esac"

# /zoom 透传：occ 写在 ~/.fbtermrc 的 font-size（白名单档位）→ fbterm -s
printf 'font-names=mono\nfont-size=20\n' > "$home/.fbtermrc"
chown "$U" "$home/.fbtermrc" 2>/dev/null
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 AIK_CONSOLE_FBTERM="$FBSTUB" \
      sh "$CONSOLE" 2>&1)
ck "/zoom 字号透传：fbterm -s 20（在 -- 之前）" \
   "case '$out' in *\"USER=root $FBSTUB -s 20 -- env HOME=$home \"*) true;; *) false;; esac"
ck "一览行 zoom=-s 20" \
   "case '$out' in *'zoom=-s 20'*) true;; *) false;; esac"
# 非档位/注入形态一律不透传（用户可控文件只解析、不外传）
printf 'font-size=9999\nfont-size=20; rm -rf /\nfont-size=$(id)\nfont-size=abc\n' > "$home/.fbtermrc"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 AIK_CONSOLE_FBTERM="$FBSTUB" \
      sh "$CONSOLE" 2>&1)
ck "非档位/注入形态不透传（无 -s）" \
   "case '$out' in *' -s '*|*'rm -rf'*|*'\$(id)'*) false;; *) true;; esac"
printf 'font-size=32\r\n' > "$home/.fbtermrc"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 AIK_CONSOLE_FBTERM="$FBSTUB" \
      sh "$CONSOLE" 2>&1)
ck "CRLF 容错：fbterm -s 32" \
   "case '$out' in *\"USER=root $FBSTUB -s 32 -- \"*) true;; *) false;; esac"
# FIFO：不读、不挂死
rm -f "$home/.fbtermrc"
mkfifo "$home/.fbtermrc"
out=$(timeout 20 env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
     AIK_CONSOLE_DRY_TTY=/dev/tty1 AIK_CONSOLE_FBTERM="$FBSTUB" \
     sh "$CONSOLE" 2>&1)
frc=$?
ck "FIFO 不读不挂死（rc=0 且无 -s）" \
   "[ '$frc' = 0 ] && case '$out' in *' -s '*) false;; *) true;; esac"
rm -f "$home/.fbtermrc"

echo "== 8. v11 fb 链 root 目标（v13：-- 后是 env GATE_SKIP，无 HOME/USER 前缀） =="
set_seat_last vga root
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 AIK_CONSOLE_FBTERM="$FBSTUB" \
      sh "$CONSOLE" 2>&1)
ck "root exec 行=v13（-- env GATE_SKIP … occ）" \
   "case '$out' in *'DRY exec: FBTERM=1 OCC_NETCFG_TOOLS=1 $FBSTUB -- env AIK_CONSOLE_GATE_SKIP=1 AIK_CONSOLE_AUTHED=root /usr/local/bin/occ 2>> /root/aik-console.err'*) true;; *) false;; esac"
ck "root 无 fbterm 的 HOME=/root USER=root 前缀、无 -s、无一览行" \
   "case '$out' in *'HOME=/root USER='*|*' -s '*|*'DRY fb:'*) false;; *) true;; esac"

echo "== 9. 串口链非根目标：不套 env（脚本导出的 HOME/USER 即用户） =="
set_seat_last serial "$U"
rm -f "$LAST_VGA"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_FBTERM="$FBSTUB" sh "$CONSOLE" 2>&1)
ck "串口 exec 行=v13 阶段 S（env GATE_SKIP 前缀 + setpriv）" \
   "case '$out' in *'DRY exec: OCC_NETCFG_TOOLS=1 env $SE $SP 2>> /var/log/aik-console/$U.err'*) true;; *) false;; esac"
ck "串口无 env 前缀/无 fb 一览行" \
   "case '$out' in *' env HOME='*|*'DRY fb:'*|*'DRY exec: FBTERM'*) false;; *) true;; esac"

echo "== 10. v12 gate 权限归一（DRY 面：不合规打印／合规不打印／无组不打印；exec 行逐条对齐） =="
# 三条分支全走 DRY、不碰真 gate 也不建组：AIK_CONSOLE_GATE_FILE 指桩文件，
# AIK_CONSOLE_GATE_GROUP 指桩组名——「有组」用恒在的 root 组（gid 0），
# 「无组」用必不存在的名字。结果与机器上有没有 aik-gate 组无关。
GSTUB=$(mktemp /tmp/p2b-gatefile.XXXXXX)
echo "$U" > "$GSTUB"
set_seat_last vga "$U"
rm -f "$LAST"
run10() { # run10 <组名> → out（fb 分支、桩 fbterm、桩 gate 文件）
    out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
          AIK_CONSOLE_DRY_TTY=/dev/tty1 \
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
echo "  -- 10.5 串口分支同样挂了归一（两条席位都要）"
printf 'x\n' > "$GSTUB"
chown root:root "$GSTUB"
chmod 0600 "$GSTUB"
set_seat_last serial "$U"
rm -f "$LAST_VGA"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_GATE_FILE="$GSTUB" AIK_CONSOLE_GATE_GROUP=root \
      sh "$CONSOLE" 2>&1)
ck "10.5 串口分支打印归一动作" \
   "case '$out' in *\"DRY gate-perm: chown root:root $GSTUB; chmod 0640 $GSTUB\"*) true;; *) false;; esac"
ck "10.5 串口 exec 行逐字按 v13 阶段 S（env 形式）" \
   "case '$out' in *'DRY exec: OCC_NETCFG_TOOLS=1 env $SE $SP 2>> /var/log/aik-console/$U.err'*) true;; *) false;; esac"
echo "  -- 10.6 归一动作在打印面上，exec 行逐条对齐"
set_seat_last vga "$U"
rm -f "$LAST_SERIAL"
run10 root
ck "10.6 非 root 目标 fb 链 exec 行=v13" \
   "case '$out' in *\"DRY exec: FBTERM=1 OCC_NETCFG_TOOLS=1 env HOME=/root USER=root $FBSTUB -- env HOME=$home USER=$U $SE $SP 2>> /var/log/aik-console/$U.err\"*) true;; *) false;; esac"
set_seat_last vga root
run10 root
ck "10.6 root 目标 fb 链 exec 行=v13" \
   "case '$out' in *'DRY exec: FBTERM=1 OCC_NETCFG_TOOLS=1 $FBSTUB -- env AIK_CONSOLE_GATE_SKIP=1 AIK_CONSOLE_AUTHED=root /usr/local/bin/occ 2>> /root/aik-console.err'*) true;; *) false;; esac"
ck "10.6 归一发生在 root 时刻，与目标用户无关（root 目标同样打印）" \
   "case '$out' in *\"DRY gate-perm: chown root:root $GSTUB; chmod 0640 $GSTUB\"*) true;; *) false;; esac"
echo "  -- 10.7 缺省组名（aik-gate）：随机器有无该组"
set_seat_last vga "$U"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 \
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

echo "== 11. v12.1/v13 真执行面（非 DRY）：fb 链两阶段全流 + 身份断言 =="
# v11/v12 的 exec 行把 $FB_PRE 拼在命令前——shell 把展开出来的 HOME=/root
# 当命令名（rc=127 重启环）。本小节让脚本真跑到 exec 行：PATH 前置桩 tty
# （报 /dev/tty1）与桩 fbterm（记录自己被怎样起动，然后 exec 真正的命令）；
# 桩 occ 在阶段 G 写 per-seat .last+marker 退 0，在阶段 S 记 id -u 退 71。
STUBD=$(mktemp -d /tmp/con11-stub.XXXXXX)
chmod 755 "$STUBD"
mkdir -p "$STUBD/vga" "$STUBD/ser"
printf '#!/bin/sh\necho /dev/tty1\n' > "$STUBD/vga/tty"
printf '#!/bin/sh\necho /dev/ttyS0\n' > "$STUBD/ser/tty"
: > "$STUBD/occ.out"; chmod 666 "$STUBD/occ.out"
: > "$STUBD/old.out"; chmod 666 "$STUBD/old.out"
: > "$STUBD/gatefail.out"; chmod 666 "$STUBD/gatefail.out"
cat > "$STUBD/fbterm" <<EOF
#!/bin/sh
echo "home=\$HOME user=\$USER skip=\$AIK_CONSOLE_GATE_SKIP args: \$*" >> "$STUBD/fb.out"
if [ "\$1" = "--" ]; then shift; fi
exec "\$@"
EOF
cat > "$STUBD/occ" <<EOF
#!/bin/sh
if [ "\$1" = "--console-gate-version" ]; then
  echo "occ-console-gate 2"
  exit 0
fi
if [ "\$AIK_CONSOLE_GATE_ONLY" = 1 ]; then
  echo "gate uid=\$(id -u) last=\$AIK_CONSOLE_GATE_LAST" >> "$STUBD/occ.out"
  printf '%s\n' "$U" > "\$AIK_CONSOLE_GATE_LAST"
  printf '2 0 %s\n' "$U" > "/run/aik-console-gate.\$AIK_CONSOLE_SEAT"
  exit 0
fi
echo "session uid=\$(id -u) authed=\$AIK_CONSOLE_AUTHED skip=\$AIK_CONSOLE_GATE_SKIP" >> "$STUBD/occ.out"
exit 71
EOF
# 探针通过但门失败（不写 .last）：用来验「per-seat 只来自迁移」
cat > "$STUBD/occgatefail" <<EOF
#!/bin/sh
if [ "\$1" = "--console-gate-version" ]; then
  echo "occ-console-gate 2"
  exit 0
fi
echo "gatefail uid=\$(id -u)" >> "$STUBD/gatefail.out"
exit 1
EOF
chmod 755 "$STUBD/vga/tty" "$STUBD/ser/tty" "$STUBD/fbterm" \
          "$STUBD/occ" "$STUBD/occgatefail"
: > "$STUBD/fb.out"; chmod 666 "$STUBD/fb.out"
rm -f "$LAST" "$LAST_VGA" "$LAST_SERIAL"
out=$(cd / && env -i PATH="$STUBD/vga:$STUBD:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      HOME=/root AIK_CONSOLE_TEST=1 AIK_CONSOLE_OCC="$STUBD/occ" \
      timeout 20 sh "$CONSOLE" 2>&1)
rc=$?
echo "  -- rc=$rc（修复前=124：127 重启环直到超时）"
ck "11.1 脚本经 occ-logout 正常退出（rc=0，未陷入 127 重启环）" "[ '$rc' = 0 ]"
ck "11.2 桩 fbterm 真被启动（留下了起动记录）" "[ -s '$STUBD/fb.out' ]"
ck "11.3 fbterm 以系统配置起：HOME=/root USER=root（阶段 S 行）" \
   "grep -q 'home=/root user=root skip= args: -- env HOME=$home USER=$U ' '$STUBD/fb.out'"
ck "11.4 传给 fbterm 的参数：-- env HOME=<用户家> USER=<用户> GATE_SKIP … setpriv … 桩 occ" \
   "grep -qF -- 'args: -- env HOME=$home USER=$U $SE setpriv --reuid=$uid --regid=$gid --init-groups --inh-caps=-all $STUBD/occ' '$STUBD/fb.out'"
ck "11.5 无「not found」" "case \"\$out\" in *'not found'*) false;; *) true;; esac"
ck "11.6 日志记的是 occ-logout，且没有 rc=127" \
   "grep -q 'occ-logout tty=fb user=$U' /var/log/aik-console/$U.log 2>/dev/null && ! grep -q 'rc=127' /var/log/aik-console/$U.log 2>/dev/null"
ck "11.7 阶段 G 以 root 跑（uid=0）且拿到 per-seat .last 路径" \
   "grep -q \"gate uid=0 last=$LAST_VGA\" '$STUBD/occ.out'"
ck "11.8 阶段 S 真以认证用户的 uid 运行（setpriv 生效，uid=$uid）" \
   "grep -q 'session uid=$uid authed=$U skip=1' '$STUBD/occ.out'"
ck "11.9 gate 写的 per-seat .last 内容=认证用户" \
   "[ \"\$(cat '$LAST_VGA' 2>/dev/null)\" = '$U' ]"

echo "== 12. 阶段 G/S 的 DRY 行形状（两阶段契约） =="
set_seat_last vga "$U"
rm -f "$LAST"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 AIK_CONSOLE_FBTERM="$FBSTUB" \
      sh "$CONSOLE" 2>&1)
gline=$(printf '%s\n' "$out" | grep '^DRY gate:')
sline=$(printf '%s\n' "$out" | grep '^DRY exec:')
ck "12.1 阶段 G 行含 AIK_CONSOLE_GATE_ONLY=1" \
   "case \"\$gline\" in *AIK_CONSOLE_GATE_ONLY=1*) true;; *) false;; esac"
ck "12.2 阶段 G 行含 per-seat 路径 $LAST_VGA" \
   "case \"\$gline\" in *\"AIK_CONSOLE_GATE_LAST=$LAST_VGA\"*) true;; *) false;; esac"
ck "12.3 阶段 G 行含席位 AIK_CONSOLE_SEAT=vga" \
   "case \"\$gline\" in *AIK_CONSOLE_SEAT=vga*) true;; *) false;; esac"
ck "12.4 阶段 G 行无 setpriv（root 特权面只有门本身）" \
   "case \"\$gline\" in *setpriv*) false;; *) true;; esac"
ck "12.5 阶段 S 行含 GATE_SKIP 与 setpriv --reuid=$uid" \
   "case \"\$sline\" in *AIK_CONSOLE_GATE_SKIP=1*\"setpriv --reuid=$uid\"*) true;; *) false;; esac"
ck "12.6 G 与 S 是两条独立行（不是一条链）" \
   "[ -n \"\$gline\" ] && [ -n \"\$sline\" ] && [ \"\$gline\" != \"\$sline\" ]"

echo "== 13. 席位隔离：VGA 与串口各读/各写各的 per-seat .last =="
set_seat_last vga "$U"
set_seat_last serial root
rm -f "$LAST"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/tty1 sh "$CONSOLE" 2>&1)
ck "13.1 VGA 席位读 .vga（user=$U）" \
   "case '$out' in *\"DRY tty=/dev/tty1 user=$U\"*) true;; *) false;; esac"
ck "13.2 VGA 席位的 gate-last 指向 .vga" \
   "case '$out' in *\"gate-last=$LAST_VGA\"*) true;; *) false;; esac"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_DRY_TTY=/dev/ttyS0 sh "$CONSOLE" 2>&1)
ck "13.3 串口席位读 .serial（user=root，不受 VGA 影响）" \
   "case '$out' in *'DRY tty=/dev/ttyS0 user=root'*) true;; *) false;; esac"
ck "13.4 串口席位的 gate-last 指向 .serial" \
   "case '$out' in *\"gate-last=$LAST_SERIAL\"*) true;; *) false;; esac"
ck "13.5 DRY 不互相覆盖（两文件内容原样）" \
   "[ \"\$(cat '$LAST_VGA')\" = '$U' ] && [ \"\$(cat '$LAST_SERIAL')\" = 'root' ]"

echo "== 14. 旧全局 .last → per-seat 首次迁移 =="
set_global_last "$U"
rm -f "$LAST_VGA" "$LAST_SERIAL"
run_dry
ck "14.1 DRY 打印迁移动作（global → .serial）" \
   "case '$out' in *\"DRY migrate-last: $LAST -> $LAST_SERIAL user=$U\"*) true;; *) false;; esac"
ck "14.2 迁移值进入本轮目标解析（user=$U）" \
   "case '$out' in *\"user=$U uid=$uid\"*) true;; *) false;; esac"
ck "14.3 DRY 不落盘（.serial 仍不在）" "[ ! -f '$LAST_SERIAL' ]"
# 真迁移：探针通过但门失败退 1（不写 .last）——.serial 只可能来自迁移
out=$(cd / && env -i PATH="$STUBD/ser:$STUBD:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      HOME=/root AIK_CONSOLE_TEST=1 AIK_CONSOLE_OCC="$STUBD/occgatefail" \
      timeout 20 sh "$CONSOLE" 2>&1)
ck "14.4 真迁移落盘 .serial=user=$U" "[ \"\$(cat '$LAST_SERIAL' 2>/dev/null)\" = '$U' ]"
ck "14.5 per-seat 文件 0600 root:root" \
   "[ \"\$(stat -c '%a %U %G' '$LAST_SERIAL' 2>/dev/null)\" = '600 root root' ]"
rm -f "$LAST_SERIAL" "$LAST_VGA"

echo "== 15. fail-closed 边界（alice 无号 / admin 例外） =="
# 15.a 非 admin 无 OS 号：绝不 root exec（即使 gate 有其它条目）
set_seat_last serial "$UNX"
rm -f "$LAST"
GENTRY=$(mktemp /tmp/con11-gate.XXXXXX)
printf 'admin:$6$stub$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1\n' > "$GENTRY"
chmod 644 "$GENTRY"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
      AIK_CONSOLE_GATE_FILE="$GENTRY" sh "$CONSOLE" 2>&1)
ck "15.1 alice 类用户无号 → fail-closed（无会话 exec）" \
   "case '$out' in *\"DRY failclosed: user=$UNX\"*) true;; *) false;; esac && case '$out' in *'DRY exec:'*) false;; *) true;; esac"
ck "15.2 即使 gate 有 admin 条目也不给非 admin 回落" \
   "case '$out' in *'DRY exec: OCC_NETCFG_TOOLS=1 /usr/local/bin/occ'*) false;; *) true;; esac"
# 15.b admin 无号 + gate 有 admin 条目 + aikctl 缺席 → 允许旧盘 root 回落
if [ -x /usr/local/bin/aikctl ] || id -u admin >/dev/null 2>&1; then
    echo "  SKIP 15.b（本机有 aikctl 或 admin 号——不在本用例形态）"
else
    set_seat_last serial admin
    rm -f "$LAST"
    out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE="$PROBE" \
          AIK_CONSOLE_GATE_FILE="$GENTRY" sh "$CONSOLE" 2>&1)
    ck "15.3 admin 无号 + gate 有 admin 条目 → 走归位动作" \
       "case '$out' in *place-admin*) true;; *) false;; esac"
    ck "15.4 aikctl 缺席 → 允许旧盘 root 回落（v8 路径，无 setpriv）" \
       "case '$out' in *'DRY exec: OCC_NETCFG_TOOLS=1 /usr/local/bin/occ 2>> /root/aik-console.err'*) true;; *) false;; esac"
    ck "15.5 admin 回落不 fail-closed" "case '$out' in *failclosed*) false;; *) true;; esac"
fi
rm -f "$GENTRY"

echo "== 16. 兼容探针回退（新 console + 旧 occ）：不得以 root exec occ =="
cat > "$STUBD/occfail" <<EOF
#!/bin/sh
if [ "\$1" = "--console-gate-version" ]; then
  echo "occ: unknown command" >&2
  exit 2
fi
echo "legacy uid=\$(id -u) authed=\$AIK_CONSOLE_AUTHED skip=\$AIK_CONSOLE_GATE_SKIP args=\$*" >> "$STUBD/old.out"
exit 71
EOF
chmod 755 "$STUBD/occfail"
: > "$STUBD/old.out"; chmod 666 "$STUBD/old.out"
# DRY 面：探针真跑（PROBE 置空）→ 只出现 legacy 行，旧降权 exec 不带 GATE_SKIP
set_global_last "$U"
rm -f "$LAST_VGA" "$LAST_SERIAL"
out=$(env AIK_CONSOLE_DRY=1 AIK_CONSOLE_DRY_PROBE= AIK_CONSOLE_TEST=1 \
      AIK_CONSOLE_OCC="$STUBD/occfail" \
      AIK_CONSOLE_DRY_TTY=/dev/ttyS0 sh "$CONSOLE" 2>&1)
ck "16.1 探针不过 → 打印 legacy 回退行" \
   "case '$out' in *'DRY legacy: occ 无 --console-gate-version'*) true;; *) false;; esac"
ck "16.2 不打印阶段 G 行（不以 root 起 occ 走 GATE_ONLY）" \
   "case '$out' in *'DRY gate:'*) false;; *) true;; esac"
ck "16.3 旧降权路径：exec 行有 setpriv、无 GATE_SKIP" \
   "case '$out' in *\"DRY exec: OCC_NETCFG_TOOLS=1 setpriv --reuid=$uid\"*) true;; *) false;; esac && case '$out' in *AIK_CONSOLE_GATE_SKIP*) false;; *) true;; esac"
# 真执行面：旧路径确实以目标 uid 起 occ（不是 root）
out=$(cd / && env -i PATH="$STUBD/ser:$STUBD:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      HOME=/root AIK_CONSOLE_TEST=1 AIK_CONSOLE_OCC="$STUBD/occfail" \
      timeout 20 sh "$CONSOLE" 2>&1)
rc=$?
ck "16.4 旧路径真执行以目标 uid 运行（uid=$uid）" \
   "grep -q 'legacy uid=$uid' '$STUBD/old.out'"
ck "16.5 旧路径不传 GATE_SKIP（否则旧门被旁路=免密进会话）" \
   "grep -q 'legacy uid=$uid authed= skip= ' '$STUBD/old.out'"
ck "16.6 console 正常退出（rc=0，旧件不崩）" "[ '$rc' = 0 ]"
ck "16.7 旧单阶段只起一次 occ（没有多余的阶段 G 进程）" \
   "[ \"\$(wc -l < '$STUBD/old.out')\" = 1 ]"

echo "== 17. 真执行（串口链）：身份 env 必须真到 occ（防赋值词当命令名） =="
# 串口链 v13 用 `env` 传 NAME=VALUE（拼在命令前时 shell 在展开前判定赋值
# 前缀，展开出来的 AIK_CONSOLE_GATE_SKIP=1 会被当成命令名 → rc=127）。
# DRY 打印验不出这类坑：这里真跑一遍，桩 occ 在阶段 S 记 euid 与两个 env。
: > "$STUBD/occ.out"; chmod 666 "$STUBD/occ.out"
set_global_last "$U"
rm -f "$LAST_VGA" "$LAST_SERIAL" /run/aik-console-gate.serial
out=$(cd / && env -i PATH="$STUBD/ser:$STUBD:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      HOME=/root AIK_CONSOLE_TEST=1 AIK_CONSOLE_OCC="$STUBD/occ" \
      timeout 20 sh "$CONSOLE" 2>&1)
rc=$?
ck "17.1 串口两阶段全流正常退出（rc=0）" "[ '$rc' = 0 ]"
ck "17.2 无「not found」（rc=127 重启环）" \
   "case \"\$out\" in *'not found'*) false;; *) true;; esac"
ck "17.3 阶段 G 以 root 跑（uid=0）且拿到 per-seat 路径" \
   "grep -q \"gate uid=0 last=$LAST_SERIAL\" '$STUBD/occ.out'"
ck "17.4 阶段 S 以认证用户的 uid 运行（uid=$uid）" \
   "grep -q 'session uid=$uid authed=$U skip=1' '$STUBD/occ.out'"
ck "17.5 日志 occ-logout（serial）且无 rc=127" \
   "grep -q 'occ-logout tty=serial user=$U' /var/log/aik-console/$U.log 2>/dev/null && ! grep -q 'rc=127' /var/log/aik-console/$U.log 2>/dev/null"
ck "17.6 marker 读后即焚（/run 席位 marker 不在）" \
   "[ ! -e /run/aik-console-gate.serial ]"

echo "== 18. marker 身份契约：2 0 - / 无 marker 都不得起会话；/tmp 无回落 =="
cat > "$STUBD/occdash" <<EOF
#!/bin/sh
if [ "\$1" = "--console-gate-version" ]; then echo "occ-console-gate 2"; exit 0; fi
if [ "\$AIK_CONSOLE_GATE_ONLY" = 1 ]; then
  printf '2 0 -\n' > "/run/aik-console-gate.\$AIK_CONSOLE_SEAT"
  exit 0
fi
echo "session-ran uid=\$(id -u)" >> "$STUBD/bad.out"
exit 71
EOF
cat > "$STUBD/occnomark" <<EOF
#!/bin/sh
if [ "\$1" = "--console-gate-version" ]; then echo "occ-console-gate 2"; exit 0; fi
if [ "\$AIK_CONSOLE_GATE_ONLY" = 1 ]; then exit 0; fi
echo "session-ran uid=\$(id -u)" >> "$STUBD/bad.out"
exit 71
EOF
chmod 755 "$STUBD/occdash" "$STUBD/occnomark"
: > "$STUBD/bad.out"; chmod 666 "$STUBD/bad.out"
for stub in occdash occnomark; do
    rm -f /run/aik-console-gate.serial
    out=$(cd / && env -i PATH="$STUBD/ser:$STUBD:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
          HOME=/root AIK_CONSOLE_TEST=1 AIK_CONSOLE_OCC="$STUBD/$stub" \
          timeout 20 sh "$CONSOLE" 2>&1)
    rc=$?
    ck "18.[$stub] console 退出 0（回登录门，不崩不循环）" "[ '$rc' = 0 ]"
done
ck "18.3 「marker 成功但无认证用户」与「无 marker」都不起会话" \
   "[ ! -s '$STUBD/bad.out' ]"
ck "18.4 /tmp 无 marker 回落文件（信任源只在 /run）" \
   "[ ! -e /tmp/aik-console-gate.vga ] && [ ! -e /tmp/aik-console-gate.serial ]"

rm -rf "$STUBD"; STUBD=
rm -rf "/var/ai/work/$U"
rm -f /var/log/aik-console/$U.log /var/log/aik-console/$U.err
echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
