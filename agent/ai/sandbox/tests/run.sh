#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# W64 沙箱回归：生命周期 / cgroup v2 限额 / net none / 崩溃回收 / export
# 需要 root（mount namespace + cgroup v2）。非 root 只跑 CLI 子集并 SKIP。
#
# 环境：
#   W64_BASE  沙盒基目录（默认 /sandbox；测试机可覆盖到 /tmp）
#   W64_ART   产物根（默认 /tmp/w64-artifacts，避免写 /var）
#   SB_BIN    被测二进制（默认 tests/aik-sandbox）
#
# 输出：逐条 PASS/FAIL，末行 "RESULT: PASS=n FAIL=n SKIP=n"；
#       FAIL>0 时退出码 1。
set -u

CDIR=$(cd "$(dirname "$0")" && pwd)
SB="${SB_BIN:-$CDIR/aik-sandbox}"
BASE="${W64_BASE:-/sandbox}"
ART="${W64_ART:-/tmp/w64-artifacts}"
export AIKERNEL_SANDBOX_BASE="$BASE"
export AIKERNEL_SANDBOX_ARTIFACTS="$ART"

PASS=0
FAIL=0
SKIP=0
ok()  { PASS=$((PASS + 1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
ck()  { local rc=$1; shift; if [ "$rc" = 0 ]; then ok "$*"; else bad "$*"; fi; }
say() { echo; echo "== $* =="; }

NAMES="w64t-create w64t-cpu w64t-mem w64t-pids w64t-net w64t-net0 \
w64t-crash w64t-orphan w64t-stale w64t-stale2 w64t-destroy \
w64t-destroy-live w64t-export w64t-export2 w64t-degrade w64t-nocg w71t-iso"

cleanup() {
	for n in $NAMES; do
		"$SB" destroy "$n" >/dev/null 2>&1
	done
	rm -rf "$ART"
}
trap cleanup EXIT

[ -x "$SB" ] || { echo "FAIL: 缺少可执行文件 $SB（先 make）"; exit 1; }

# ---------------------------------------------------------------- 非 root
if [ "$(id -u)" != 0 ]; then
	say "CLI 子集（非 root）"
	"$SB" >/dev/null 2>&1
	[ $? = 1 ]; ck $? "无参数 usage rc=1"
	"$SB" create '../escape' >/dev/null 2>&1
	[ $? != 0 ]; ck $? "非法区名拒绝"
	"$SB" destroy '.' >/dev/null 2>&1
	[ $? != 0 ]; ck $? "非法 destroy 名字拒绝"
	"$SB" export evil /etc/passwd /tmp/w64-x >/dev/null 2>&1
	[ $? != 0 ]; ck $? "export 越界 src 拒绝"
	"$SB" run w64t-none >/dev/null 2>&1
	[ $? != 0 ]; ck $? "run 缺 -- 拒绝"
	echo "SKIP: 非 root，跳过 namespace/cgroup 用例"
	SKIP=$((SKIP + 1))
	echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
	[ "$FAIL" = 0 ]
	exit $?
fi

cleanup
mkdir -p "$BASE"

# ---------------------------------------------------------------- T1
say "T1 create + meta 落盘 + cgroup 限额"
out=$("$SB" create w64t-create --cpus 0.5 --mem-mb 256 --pids 64 2>&1)
rc=$?
ck $rc "create rc=0"
echo "$out"
M="$BASE/w64t-create/meta"
[ -f "$M" ]; ck $? "meta 已落盘"
grep -qx 'cpus=0.50' "$M"; ck $? "meta cpus=0.50"
grep -qx 'mem_mb=256' "$M"; ck $? "meta mem_mb=256"
grep -qx 'pids_max=64' "$M"; ck $? "meta pids_max=64"
grep -qx 'net=host' "$M"; ck $? "meta net=host"
grep -qx 'status=created' "$M"; ck $? "meta status=created"
CG="/sys/fs/cgroup/aik-sandbox/w64t-create"
[ -d "$CG" ]; ck $? "cgroup 目录已建"
[ "$(cat "$CG/memory.max" 2>/dev/null)" = "268435456" ]
ck $? "memory.max=256MiB"
[ "$(cat "$CG/pids.max" 2>/dev/null)" = "64" ]
ck $? "pids.max=64"
grep -qx 'mem_limit=1' "$M"; ck $? "内存限额实际生效（meta mem_limit=1）"
grep -qx 'pids_limit=1' "$M"; ck $? "PID 限额实际生效（meta pids_limit=1）"
if [ -f "$CG/cpu.max" ]; then
	[ "$(cat "$CG/cpu.max")" = "50000 100000" ]
	ck $? "cpu.max=50000 100000"
	grep -qx 'cpu_limit=1' "$M"; ck $? "CPU 限额实际生效"
else
	grep -qx 'cpu_limit=0' "$M"; ck $? "meta 记录 CPU 限额降级"
	grep -q 'CFS_BANDWIDTH' <<< "$out"
	ck $? "明确告警内核缺 CONFIG_CFS_BANDWIDTH"
fi
[ "$(cat "$CG/cgroup.procs" 2>/dev/null | wc -l)" = 0 ]
ck $? "子 cgroup 初始无进程"
[ "$(cat /sys/fs/cgroup/aik-sandbox/cgroup.procs 2>/dev/null | wc -l)" = 0 ]
ck $? "锚点 cgroup 无宿主进程"

# ---------------------------------------------------------------- T2
say "T2 run 基本隔离 + cgroup 成员 + 退出码"
out=$("$SB" run w64t-create -- /bin/sh -c '
	echo OK
	hostname
	echo UID=$(id -u)
	echo CG=$(cat /proc/self/cgroup)
	[ -e /etc/shadow ] && echo SHADOW-VISIBLE || echo NO-SHADOW
	touch /usr/w64probe 2>/dev/null && echo USR-WRITABLE || echo USR-RO
	touch /root/w64-t2-probe
	ls /root' 2>&1)
rc=$?
ck $rc "run rc=0"
echo "$out"
grep -qx 'OK' <<< "$out"; ck $? "命令输出 OK"
grep -qx 'w64t-create' <<< "$out"; ck $? "UTS hostname=区名"
grep -qx 'UID=0' <<< "$out"; ck $? "沙盒内 uid=0"
grep -qx 'CG=0::/aik-sandbox/w64t-create' <<< "$out"
ck $? "进程确实在目标 cgroup"
grep -qx 'NO-SHADOW' <<< "$out"; ck $? "/etc/shadow 不可见"
grep -qx 'USR-RO' <<< "$out"; ck $? "/usr 只读"
[ ! -e /root/w64-t2-probe ]; ck $? "宿主 /root 无沙盒 probe"
grep -qx 'status=exited' "$M"; ck $? "meta status=exited"
grep -qx 'exit_code=0' "$M"; ck $? "meta exit_code=0"

# ---------------------------------------------------------------- T3
say "T3 CPU 配额（0.2 CPU × 3s）"
cout=$("$SB" create w64t-cpu --cpus 0.2 --mem-mb 512 --pids 128 2>&1)
ck $? "create rc=0"
CG="/sys/fs/cgroup/aik-sandbox/w64t-cpu"
b=$(awk '/^usage_usec /{print $2}' "$CG/cpu.stat")
t0=$(date +%s%N)
"$SB" run w64t-cpu -- /usr/bin/timeout 3 /bin/sh -c 'while :; do :; done' >/dev/null 2>&1
rc=$?
t1=$(date +%s%N)
a=$(awk '/^usage_usec /{print $2}' "$CG/cpu.stat")
delta=$((a - b))
el=$(((t1 - t0) / 1000000))
echo "CPU: usage_usec=$delta elapsed_ms=$el rc=$rc"
[ "$rc" = 124 ]; ck $? "timeout 击杀（rc=124）"
if [ -f "$CG/cpu.max" ]; then
	[ "$delta" -ge 100000 ] && [ "$delta" -le 1500000 ]
	ck $? "CPU 用量 $delta us 落在 0.1–1.5s（无限制应≈3s）"
else
	echo "CPU: 内核 CONFIG_CFS_BANDWIDTH=n，cpu.max 不存在"
	grep -q 'CFS_BANDWIDTH' <<< "$cout"; ck $? "create 明确告警 CPU 限额降级"
	[ "$delta" -ge 1500000 ]; ck $? "未限速全速运行（$delta us ≈ 3s）"
	SKIP=$((SKIP + 1))
	echo "SKIP: CPU 强制配额（需内核 CONFIG_CFS_BANDWIDTH=y，W65/内核面）"
fi

# ---------------------------------------------------------------- T4
say "T4 memory.max（64MB 沙盒写 256MB）"
"$SB" create w64t-mem --mem-mb 64 --pids 128 >/dev/null 2>&1
CG="/sys/fs/cgroup/aik-sandbox/w64t-mem"
out=$("$SB" run w64t-mem -- /bin/sh -c \
	'dd if=/dev/zero of=/tmp/big bs=1M count=256 2>&1; echo DD_RC=$?' 2>&1)
rc=$?
oom=$(awk '/^oom_kill /{print $2}' "$CG/memory.events")
peak=$(cat "$CG/memory.peak")
echo "MEM: run_rc=$rc oom_kill=$oom memory.peak=$peak"
echo "$out" | tail -3
[ "$oom" -ge 1 ]; ck $? "memory.events oom_kill=$oom ≥1"
[ "$rc" != 0 ]; ck $? "超限任务非 0 退出（rc=$rc，期望 137）"
[ "$peak" -le 100663296 ]; ck $? "memory.peak=$peak ≤ 96MiB"

# ---------------------------------------------------------------- T5
say "T5 pids.max（上限 32，尝试 200 个 sleep）"
"$SB" create w64t-pids --pids 32 --mem-mb 256 >/dev/null 2>&1
CG="/sys/fs/cgroup/aik-sandbox/w64t-pids"
out=$("$SB" run w64t-pids -- /bin/sh -c \
	'for i in $(seq 1 200); do sleep 1 >/dev/null 2>&1 & done; wait' 2>&1)
rc=$?
peak=$(cat "$CG/pids.peak")
echo "PIDS: run_rc=$rc pids.peak=$peak"
echo "$out" | head -3
[ "$peak" -ge 10 ] && [ "$peak" -le 33 ]
ck $? "pids.peak=$peak ≤33（pids.max 生效）"

# ---------------------------------------------------------------- T6
say "T6 --net none 网络隔离 + lo up"
"$SB" create w64t-net --net none --mem-mb 256 >/dev/null 2>&1
out=$("$SB" run w64t-net -- /bin/sh -c '
	echo NETS=$(ls /sys/class/net | tr "\n" ",")
	echo FLAGS=$(cat /sys/class/net/lo/flags)
	echo ROUTES=$(ip route 2>/dev/null | wc -l)
	echo IFACES=$(( $(tail -n +3 /proc/net/dev | wc -l) ))
	ip -o addr show lo 2>/dev/null | grep -q 127.0.0.1 && echo LO-ADDR-OK
	ping -c1 -W1 127.0.0.1 >/dev/null 2>&1 && echo PING-OK || echo PING-FAIL
	' 2>&1)
rc=$?
ck $rc "net none run rc=0"
echo "$out"
echo "$out" | grep -q 'NETS=lo,'; ck $? "lo 存在"
netline=$(sed -n 's/^NETS=//p' <<< "$out")
bad=$(tr ',' '\n' <<< "$netline" | grep -v '^$' | grep -vE '^(lo|sit0)$' | wc -l)
[ "$bad" = 0 ]; ck $? "仅 lo/sit0（无物理网卡，非 lo 物理接口=$bad）"
flags=$(sed -n 's/^FLAGS=//p' <<< "$out")
[ -n "$flags" ] && [ $((flags & 1)) = 1 ]; ck $? "lo IFF_UP 已置位（$flags）"
grep -qx 'ROUTES=0' <<< "$out"; ck $? "无路由（无外网）"
grep -qx 'LO-ADDR-OK' <<< "$out"; ck $? "lo 127.0.0.1 可用"
grep -qx 'PING-OK' <<< "$out"; ck $? "CAP_NET_RAW 保留：ping 127.0.0.1 成功"

say "T6b 默认 host 网络保留"
"$SB" create w64t-net0 --mem-mb 256 >/dev/null 2>&1
out=$("$SB" run w64t-net0 -- /bin/sh -c 'ls /sys/class/net | tr "\n" ","' 2>&1)
netline=$(tail -1 <<< "$out")
echo "HOSTNET: $netline"
nif=$(tr ',' '\n' <<< "$netline" | grep -v '^$' | grep -vc '^lo$')
[ "$nif" -ge 1 ]; ck $? "默认保留宿主网络（非 lo 接口数=$nif）"

# ---------------------------------------------------------------- T7
say "T7 父进程被杀 → status 识别并回收孤儿"
"$SB" create w64t-crash --mem-mb 256 >/dev/null 2>&1
"$SB" run w64t-crash -- /bin/sleep 300 >/dev/null 2>&1 &
rp=$!
M="$BASE/w64t-crash/meta"
CG="/sys/fs/cgroup/aik-sandbox/w64t-crash"
for i in $(seq 1 50); do
	grep -qx 'status=running' "$M" 2>/dev/null && break
	sleep 0.1
done
grep -qx 'status=running' "$M"; ck $? "run 进入 running"
wrapper=$(sed -n 's/^pid=//p' "$M")
procs_before=$(wc -l < "$CG/cgroup.procs")
echo "CRASH: wrapper=$wrapper cgroup_procs=$procs_before"
kill -9 "$wrapper" 2>/dev/null
wait "$rp" 2>/dev/null
sleep 0.3
cpid=$(sed -n 's/^child_pid=//p' "$M")
state=$(ps -o stat= -p "$cpid" 2>/dev/null | tr -d ' ')
procs_after=$(wc -l < "$CG/cgroup.procs" 2>/dev/null || echo 0)
echo "CRASH: wrapper 被 SIGKILL；沙盒 init hostpid=$cpid state=${state:-gone} cgroup_procs=$procs_after"
if [ -z "$state" ] || [ "${state#Z}" != "$state" ]; then
	ok "PDEATHSIG 让沙盒 init 随 wrapper 立即死亡"
else
	bad "PDEATHSIG 未生效（沙盒 init 仍存活 state=$state）"
fi
t0=$(date +%s%N)
out=$("$SB" status 2>&1)
t1=$(date +%s%N)
echo "$out"
grep -q 'w64t-crash.*stale' <<< "$out"; ck $? "status 标记 stale"
grep -q '回收' <<< "$out"; ck $? "status 执行回收"
[ ! -e "$BASE/w64t-crash" ]; ck $? "目录已清除"
[ ! -d "$CG" ]; ck $? "cgroup 已清除"
echo "CRASH: status 回收耗时 $(((t1 - t0) / 1000000)) ms"
! pgrep -f 'aik-sandbox run w64t-crash' >/dev/null 2>&1
ck $? "无包装进程残留"

say "T7b cgroup.kill 回收孤儿（模拟 PDEATHSIG 竞态/外部残留）"
"$SB" create w64t-orphan --mem-mb 256 >/dev/null 2>&1
CG="/sys/fs/cgroup/aik-sandbox/w64t-orphan"
rm -f /tmp/w64-orphan.pid
( sleep 300 & echo $! > /tmp/w64-orphan.pid; wait ) &
wp=$!
for i in $(seq 1 50); do
	[ -s /tmp/w64-orphan.pid ] && break
	sleep 0.05
done
hp=$(cat /tmp/w64-orphan.pid)
if echo "$hp" > "$CG/cgroup.procs"; then
	ok "把测试孤儿进程移入目标 cgroup"
else
	bad "移入 cgroup 失败，跳过后续断言"
	kill -9 "$hp" 2>/dev/null
	wait "$wp" 2>/dev/null
	hp=""
fi
if [ -n "$hp" ]; then
printf 'name=w64t-orphan\npid=999999\nstarted=%s\ncpus=1.00\nmem_mb=256\npids_max=256\ncpu_limit=0\nmem_limit=1\npids_limit=1\nnet=host\ncgroup_dir=1\nstatus=running\n' \
	"$(date +%s)" > "$BASE/w64t-orphan/meta"
sleep 0.1
out=$("$SB" status 2>&1)
echo "$out"
grep -q 'w64t-orphan.*孤儿' <<< "$out"; ck $? "status 识别 cgroup 孤儿"
sleep 0.2
st=$(ps -o stat= -p "$hp" 2>/dev/null | tr -d ' ')
if [ -z "$st" ] || [ "${st#Z}" != "$st" ]; then
	ok "cgroup.kill 杀掉孤儿（state=${st:-gone}）"
else
	bad "cgroup.kill 未杀掉孤儿（state=$st）"
	kill -9 "$hp" 2>/dev/null
fi
wait "$wp" 2>/dev/null
wrc=$?
# wp 只是 hp 的父 shell，不在目标 cgroup 内；cgroup.kill 只保证 hp 死亡，
# wp 的 wait 返回 137 或 0 都属合法。真正的断言是下面 hp 已不存在。
case "$wrc" in
	137|0) ok "孤儿 watcher 退出（rc=$wrc；wp 不在 cgroup 内，0 亦合法）" ;;
	*) bad "孤儿 watcher 异常退出（rc=$wrc）" ;;
esac
[ ! -e "/proc/$hp" ]; ck $? "孤儿进程已被回收（pid $hp 不存在）"
[ ! -d "$CG" ]; ck $? "孤儿 cgroup 已删除"
[ ! -e "$BASE/w64t-orphan" ]; ck $? "孤儿目录已删除"
fi
rm -f /tmp/w64-orphan.pid

# ---------------------------------------------------------------- T8
say "T8 stale 挂载/无 meta 目录清理"
mkdir -p "$BASE/w64t-stale/root"
printf 'pid=999999\nstatus=running\n' > "$BASE/w64t-stale/meta"
mount -t tmpfs tmpfs "$BASE/w64t-stale/root"
grep -q "$BASE/w64t-stale/root" /proc/self/mountinfo
ck $? "已伪造宿主侧残留挂载"
out=$("$SB" create w64t-stale 2>&1)
rc=$?
ck $rc "create 回收残留后成功"
echo "$out"
grep -q "$BASE/w64t-stale/root" /proc/self/mountinfo
[ $? != 0 ]; ck $? "残留挂载已卸载"
grep -qx 'status=created' "$BASE/w64t-stale/meta"
ck $? "meta 已重建"
mkdir -p "$BASE/w64t-stale2"
out=$("$SB" status 2>&1)
grep -q 'w64t-stale2.*回收' <<< "$out"; ck $? "无 meta 残留目录被 status 回收"
[ ! -e "$BASE/w64t-stale2" ]; ck $? "无 meta 目录已删除"

# ---------------------------------------------------------------- T9
say "T9 destroy 幂等 + 活跃 run 强制回收"
"$SB" create w64t-destroy --mem-mb 256 >/dev/null 2>&1
"$SB" destroy w64t-destroy >/dev/null 2>&1; ck $? "第一次 destroy rc=0"
"$SB" destroy w64t-destroy >/dev/null 2>&1; ck $? "第二次 destroy rc=0（幂等）"
[ ! -e "$BASE/w64t-destroy" ]; ck $? "目录已清除"

"$SB" create w64t-destroy-live --mem-mb 256 >/dev/null 2>&1
"$SB" run w64t-destroy-live -- /bin/sleep 300 >/dev/null 2>&1 &
rp=$!
M="$BASE/w64t-destroy-live/meta"
CG="/sys/fs/cgroup/aik-sandbox/w64t-destroy-live"
for i in $(seq 1 50); do
	grep -qx 'status=running' "$M" 2>/dev/null && break
	sleep 0.1
done
"$SB" destroy w64t-destroy-live >/dev/null 2>&1; ck $? "活跃 run 时 destroy rc=0"
wait "$rp" 2>/dev/null
[ ! -e "$BASE/w64t-destroy-live" ]; ck $? "活跃 run 目录已清除"
[ ! -d "$CG" ]; ck $? "活跃 run cgroup 已清除"
! pgrep -f 'aik-sandbox run w64t-destroy-live' >/dev/null 2>&1
ck $? "run 包装进程已回收"

# ---------------------------------------------------------------- T10
say "T10 产物导出 export"
"$SB" create w64t-export --mem-mb 256 >/dev/null 2>&1
"$SB" run w64t-export -- /bin/sh -c '
	D=/var/ai/sandbox-artifacts/w64t-export
	echo ARTIFACT-OK > $D/out.txt
	mkdir -p $D/sub
	echo SUB-OK > $D/sub/y.txt
	ln -sf /etc/hostname $D/escape
	{ mknod $D/devnull c 1 3 2>/dev/null &&
		(echo x > $D/devnull 2>/dev/null && echo NODEV-BYPASS || echo NODEV-OK) ||
		echo MKNOD-FAIL; } > $D/nodev.txt' >/dev/null 2>&1
ck $? "沙盒内写产物"
[ "$(cat "$ART/w64t-export/out.txt" 2>/dev/null)" = "ARTIFACT-OK" ]
ck $? "宿主侧可见产物"
grep -qx 'NODEV-BYPASS' "$ART/w64t-export/nodev.txt" 2>/dev/null
[ $? != 0 ]; ck $? "产物区 nodev 生效（无设备节点逃逸）"
"$SB" export w64t-export out.txt exports/w64t-out.txt >/dev/null 2>&1
ck $? "export 相对路径 rc=0"
[ "$(cat "$ART/exports/w64t-out.txt" 2>/dev/null)" = "ARTIFACT-OK" ]
ck $? "导出内容一致"
"$SB" export w64t-export /var/ai/sandbox-artifacts/w64t-export/sub/y.txt \
	/var/ai/sandbox-artifacts/exports/w64t-abs.txt >/dev/null 2>&1
ck $? "export 绝对 canonical 路径 rc=0"
[ "$(cat "$ART/exports/w64t-abs.txt" 2>/dev/null)" = "SUB-OK" ]
ck $? "绝对路径导出内容一致"
"$SB" export w64t-export escape exports/w64t-escape.txt >/dev/null 2>&1
[ $? != 0 ]; ck $? "拒绝 src symlink 逃逸（→/etc/hostname）"
[ ! -e "$ART/exports/w64t-escape.txt" ]; ck $? "逃逸目标未生成"
"$SB" export w64t-export out.txt /tmp/w64-outside >/dev/null 2>&1
[ $? != 0 ]; ck $? "拒绝 dest 越界 /tmp"
mkdir -p "$ART/evil"
ln -sfn /tmp/w64-pwn "$ART/evil/target"
"$SB" export w64t-export out.txt evil/target >/dev/null 2>&1
[ $? != 0 ]; ck $? "拒绝 dest symlink 落点"
[ ! -e /tmp/w64-pwn ]; ck $? "dest symlink 未被跟随"
"$SB" export w64t-export out.txt exports/w64t-out.txt >/dev/null 2>&1
[ $? != 0 ]; ck $? "拒绝覆盖已存在目标（O_EXCL）"
"$SB" export w64t-export /var/ai/sandbox-artifacts/other/x out.txt \
	>/dev/null 2>&1
[ $? != 0 ]; ck $? "拒绝跨区 src"
"$SB" destroy w64t-export >/dev/null 2>&1
ck $? "产物导出后 destroy rc=0"
"$SB" export w64t-export out.txt exports/w64t-after-destroy.txt \
	>/dev/null 2>&1
ck $? "destroy 后产物仍可导出（产物区保留）"
[ "$(cat "$ART/exports/w64t-after-destroy.txt" 2>/dev/null)" = "ARTIFACT-OK" ]
ck $? "destroy 后导出内容一致"

# ---------------------------------------------------------------- T11
say "T11 无 cgroup 降级告警"
rm -rf /tmp/w64-nocg-dir
err=$(AIKERNEL_SANDBOX_CGROUP_ROOT=/tmp/w64-nocg-dir \
	"$SB" create w64t-degrade 2>&1 >/dev/null)
ck $? "create（无 cgroup v2）rc=0"
echo "$err"
grep -q '不是 cgroup v2' <<< "$err"; ck $? "明确告警 cgroup 不可用"
grep -q '降级' <<< "$err"; ck $? "明确告警降级"
AIKERNEL_SANDBOX_CGROUP_ROOT=/tmp/w64-nocg-dir \
	"$SB" run w64t-degrade -- /bin/true >/dev/null 2>&1
ck $? "无 cgroup 时 run 仍可用"
grep -qx 'cgroup_dir=0' "$BASE/w64t-degrade/meta"
ck $? "meta 记录 cgroup 未启用"
"$SB" destroy w64t-degrade >/dev/null 2>&1

err=$("$SB" create w64t-nocg --no-cgroup 2>&1 >/dev/null)
grep -q '显式禁用' <<< "$err"; ck $? "--no-cgroup 明确告警"
out=$("$SB" run w64t-nocg --no-cgroup -- /bin/sh -c 'echo NO-CGROUP-OK' 2>&1)
[ $? = 0 ]; ck $? "--no-cgroup run rc=0"
grep -qx 'NO-CGROUP-OK' <<< "$out"; ck $? "--no-cgroup 输出正常"
"$SB" destroy w64t-nocg >/dev/null 2>&1

# ---------------------------------------------------------------- T12
say "T12 宿主关键进程未被卷入"
[ "$(cat /sys/fs/cgroup/aik-sandbox/cgroup.procs 2>/dev/null | wc -l)" = 0 ]
ck $? "锚点 cgroup 始终无进程"
echo "PID1 cgroup: $(cat /proc/1/cgroup)"
! grep -q 'aik-sandbox' /proc/1/cgroup; ck $? "PID 1 不在沙盒 cgroup"

# ---------------------------------------------------------------- T13
say "T13 残留检查（目录/挂载/cgroup/进程）"
cleanup
[ -z "$(find "$BASE" -mindepth 1 -maxdepth 1 -name 'w64t-*' 2>/dev/null)" ]
ck $? "$BASE 无测试残留目录"
[ -z "$(find /sys/fs/cgroup/aik-sandbox -mindepth 1 -maxdepth 1 \
	-name 'w64t-*' 2>/dev/null)" ]
ck $? "cgroup 无测试残留"
! pgrep -f 'aik-sandbox run w64t-' >/dev/null 2>&1
ck $? "无测试 run 进程残留"
! grep -q "$BASE/w64t-" /proc/self/mountinfo
ck $? "无测试挂载残留"

# ---------------------------------------------------------------- T14
say "T14 并发寿命 10×3"
"$CDIR/concurrency.sh" 3 10
ck $? "10 并发 × 3 轮 create→run→status→destroy"

# ---------------------------------------------------------------- T15
say "T15 W71 隔离面：fresh procfs + capability 裁剪"
HOSTPID=$$
HOSTCAP=$(awk '/^CapEff:/{print $2}' /proc/self/status)
HOSTNETNS=$(readlink /proc/self/ns/net)
echo "HOST: pid=$HOSTPID CapEff=$HOSTCAP netns=$HOSTNETNS"
"$SB" create w71t-iso --mem-mb 128 >/dev/null 2>&1
out=$(HOSTPID=$HOSTPID "$SB" run w71t-iso -- /bin/sh -c '
	echo SELF_PIDNS=$(readlink /proc/self/ns/pid)
	echo P1_PIDNS=$(readlink /proc/1/ns/pid)
	echo P1_CMD=$(tr "\0" " " < /proc/1/cmdline)
	echo HOSTPID_VISIBLE=$([ -e /proc/$HOSTPID ] && echo yes || echo no)
	echo NUMERIC_PROCS=$(ls /proc | grep -c "^[0-9][0-9]*$")
	echo PS_LINES=$(ps 2>/dev/null | wc -l)
	echo CAPEFF=$(sed -n "s/^CapEff:[[:space:]]*//p" /proc/self/status)
	echo CAPBND=$(sed -n "s/^CapBnd:[[:space:]]*//p" /proc/self/status)
	echo NNP=$(sed -n "s/^NoNewPrivs:[[:space:]]*//p" /proc/self/status)
	echo PROC_AI=$(if [ -r /proc/ai/status ]; then echo yes; else echo no; fi)
	echo SYS_AI=$(if [ -d /sys/kernel/ai ]; then echo yes; else echo no; fi)
	mknod /tmp/w71-node c 1 3 2>/dev/null && echo MKNOD=allowed || echo MKNOD=denied
	mkdir -p /tmp/w71-mnt
	mount -t tmpfs tmpfs /tmp/w71-mnt 2>/dev/null && echo MOUNT=allowed || echo MOUNT=denied
	' 2>&1)
ck $? "隔离面 run rc=0"
echo "$out"
spid=$(sed -n 's/^SELF_PIDNS=//p' <<< "$out")
p1pid=$(sed -n 's/^P1_PIDNS=//p' <<< "$out")
[ -n "$spid" ] && [ "$spid" = "$p1pid" ]; ck $? "沙盒 /proc/1 属于同一 PID namespace（$p1pid）"
grep -qx 'HOSTPID_VISIBLE=no' <<< "$out"; ck $? "宿主 PID $HOSTPID 在沙盒 /proc 不可见"
np=$(sed -n 's/^NUMERIC_PROCS=//p' <<< "$out")
[ -n "$np" ] && [ "$np" -le 8 ]; ck $? "沙盒 /proc 仅本 namespace 进程（$np 个）"
psl=$(sed -n 's/^PS_LINES=//p' <<< "$out")
[ -n "$psl" ] && [ "$psl" -le 8 ]; ck $? "沙盒 ps 只看到自己（$psl 行）"
grep -qx 'CAPEFF=0000000000002000' <<< "$out"
ck $? "CapEff 裁剪为仅 CAP_NET_RAW（0x2000）"
grep -qx 'CAPBND=0000000000002000' <<< "$out"
ck $? "CapBnd 同步裁剪（不可再取得）"
grep -qx 'NNP=1' <<< "$out"; ck $? "PR_SET_NO_NEW_PRIVS=1"
grep -qx 'MKNOD=denied' <<< "$out"; ck $? "CAP_MKNOD 已丢弃（mknod EPERM）"
grep -qx 'MOUNT=denied' <<< "$out"; ck $? "CAP_SYS_ADMIN 已丢弃（mount EPERM）"
grep -qx 'PROC_AI=yes' <<< "$out"; ck $? "/proc/ai 在新 procfs 上可见"
grep -qx 'SYS_AI=yes' <<< "$out"; ck $? "/sys/kernel/ai 在新 sysfs 上可见"
"$SB" destroy w71t-iso >/dev/null 2>&1

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" = 0 ]
