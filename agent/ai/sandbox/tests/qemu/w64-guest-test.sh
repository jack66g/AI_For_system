#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# W64 QEMU 真内核沙箱回归（busybox sh；由 /init 在 AIKernel bzImage 内执行）
# 覆盖：cgroup v2 memory/pids 限额、cgroup 成员、PDEATHSIG、stale 回收、
#       cgroup.kill、--net none、产物导出边界、destroy 幂等、10×3 并发。
# 内核缺 CONFIG_CFS_BANDWIDTH：CPU 配额按降级路径断言（明确告警 + meta 记录）。
# 输出末行: RESULT: PASS=n FAIL=n SKIP=n

SB=/aik-sandbox
BASE=/sandbox
ART=/tmp/w64art
export AIKERNEL_SANDBOX_BASE="$BASE"
export AIKERNEL_SANDBOX_ARTIFACTS="$ART"

PASS=0
FAIL=0
SKIP=0
ok()  { PASS=$((PASS + 1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
ck()  { if [ "$1" = 0 ]; then ok "$2"; else bad "$2"; fi; }
say() { echo; echo "== $* =="; }

cleanup() {
	for n in q1 q4 q5 q6 q6b q7 q7b q8 q9; do
		$SB destroy "$n" >/dev/null 2>&1
	done
	r=1
	while [ $r -le 3 ]; do
		i=1
		while [ $i -le 10 ]; do
			$SB destroy "q9c-$r-$i" >/dev/null 2>&1
			i=$((i + 1))
		done
		r=$((r + 1))
	done
	rm -rf "$ART"
}

cleanup
mkdir -p "$BASE"
echo "=== W64 QEMU START ==="
echo "KERNEL=$(uname -r)"
echo "HOST_CGROUP=$(cat /proc/self/cgroup)"
echo "CGROUP2=$(grep -c cgroup2 /proc/filesystems)"
HOSTPID=$$
HOSTNETNS=$(readlink /proc/self/ns/net)
HOSTCAPEFF=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)
echo "HOST_PID=$HOSTPID HOST_NETNS=$HOSTNETNS HOST_CAPEFF=$HOSTCAPEFF"

# ------------------------------------------------------------------ T1
say "T1 create + memory/pids 限额 + CPU 降级"
out=$($SB create q1 --cpus 0.5 --mem-mb 64 --pids 32 2>&1)
ck $? "create rc=0"
echo "$out"
M=$BASE/q1/meta
CG=/sys/fs/cgroup/aik-sandbox/q1
grep -q '^mem_mb=64$' "$M"; ck $? "meta mem_mb=64"
grep -q '^pids_max=32$' "$M"; ck $? "meta pids_max=32"
grep -q '^mem_limit=1$' "$M"; ck $? "mem_limit=1"
grep -q '^pids_limit=1$' "$M"; ck $? "pids_limit=1"
[ "$(cat "$CG/memory.max" 2>/dev/null)" = "67108864" ]
ck $? "memory.max=64MiB"
[ "$(cat "$CG/pids.max" 2>/dev/null)" = "32" ]
ck $? "pids.max=32"
[ "$(cat "$CG/cgroup.procs" 2>/dev/null | wc -l)" = 0 ]
ck $? "child cgroup 无进程"
[ "$(cat /sys/fs/cgroup/aik-sandbox/cgroup.procs 2>/dev/null | wc -l)" = 0 ]
ck $? "anchor cgroup 无宿主进程"
if [ -f "$CG/cpu.max" ]; then
	[ "$(cat "$CG/cpu.max")" = "50000 100000" ]
	ck $? "cpu.max=50000 100000"
else
	echo "$out" | grep -q CFS_BANDWIDTH; ck $? "明确告警缺 CONFIG_CFS_BANDWIDTH"
	grep -q '^cpu_limit=0$' "$M"; ck $? "meta 记录 CPU 限额降级"
fi

# ------------------------------------------------------------------ T2
say "T2 run 隔离面 + cgroup 成员"
out=$($SB run q1 -- /bin/sh -c '
	echo CG=$(cat /proc/self/cgroup)
	echo HOST=$(hostname)
	echo UID=$(id -u 2>/dev/null || echo 0)
	[ -e /etc/shadow ] && echo SHADOW-VISIBLE || echo NO-SHADOW
	touch /root/probe
	ls /root' 2>&1)
ck $? "run rc=0"
echo "$out"
echo "$out" | grep -q 'CG=0::/aik-sandbox/q1'; ck $? "进程在目标 cgroup"
echo "$out" | grep -q 'HOST=q1'; ck $? "UTS hostname=q1"
echo "$out" | grep -q 'NO-SHADOW'; ck $? "/etc/shadow 不可见"
[ ! -e /root/probe ]; ck $? "宿主 /root 无 probe"
grep -q '^status=exited$' "$M"; ck $? "meta status=exited"
grep -q '^exit_code=0$' "$M"; ck $? "meta exit_code=0"

# ------------------------------------------------------------------ T2b
say "T2b W71 隔离面：fresh procfs + capability 裁剪"
out=$(HOSTPID=$HOSTPID $SB run q1 -- /bin/sh -c '
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
spid=$(echo "$out" | sed -n 's/^SELF_PIDNS=//p')
p1pid=$(echo "$out" | sed -n 's/^P1_PIDNS=//p')
[ -n "$spid" ] && [ "$spid" = "$p1pid" ]; ck $? "沙盒 /proc/1 属于同一 PID namespace（$p1pid）"
echo "$out" | grep -qx 'HOSTPID_VISIBLE=no'; ck $? "宿主 PID $HOSTPID 在沙盒 /proc 不可见"
np=$(echo "$out" | sed -n 's/^NUMERIC_PROCS=//p')
[ -n "$np" ] && [ "$np" -le 8 ]; ck $? "沙盒 /proc 仅本 namespace 进程（$np 个）"
psl=$(echo "$out" | sed -n 's/^PS_LINES=//p')
[ -n "$psl" ] && [ "$psl" -le 8 ]; ck $? "沙盒 ps 只看到自己（$psl 行）"
echo "$out" | grep -qx 'CAPEFF=0000000000002000'; ck $? "CapEff 裁剪为仅 CAP_NET_RAW（0x2000）"
echo "$out" | grep -qx 'CAPBND=0000000000002000'; ck $? "CapBnd 同步裁剪（不可再取得）"
echo "$out" | grep -qx 'NNP=1'; ck $? "PR_SET_NO_NEW_PRIVS=1"
echo "$out" | grep -qx 'MKNOD=denied'; ck $? "CAP_MKNOD 已丢弃（mknod EPERM）"
echo "$out" | grep -qx 'MOUNT=denied'; ck $? "CAP_SYS_ADMIN 已丢弃（mount EPERM）"
echo "$out" | grep -qx 'PROC_AI=yes'; ck $? "/proc/ai 在新 procfs 上可见"
echo "$out" | grep -qx 'SYS_AI=yes'; ck $? "/sys/kernel/ai 在新 sysfs 上可见"

# ------------------------------------------------------------------ T3
say "T3 memory.max（48MB 沙盒写 128MB）"
$SB create q4 --mem-mb 48 --pids 64 >/dev/null 2>&1
CG=/sys/fs/cgroup/aik-sandbox/q4
$SB run q4 -- /bin/sh -c \
	'dd if=/dev/zero of=/tmp/big bs=1048576 count=128 2>/dev/null; echo DD=$?' \
	>/tmp/q4.out 2>&1
rc=$?
oom=$(sed -n 's/^oom_kill //p' "$CG/memory.events" 2>/dev/null)
peak=$(cat "$CG/memory.peak" 2>/dev/null)
echo "MEM rc=$rc oom_kill=$oom memory.peak=$peak"
cat /tmp/q4.out
[ "$oom" -ge 1 ]; ck $? "oom_kill=$oom >=1"
[ "$rc" != 0 ]; ck $? "超限任务非 0 退出（rc=$rc）"
[ "$peak" -le 67108864 ]; ck $? "memory.peak=$peak <=64MiB"

# ------------------------------------------------------------------ T4
say "T4 pids.max（上限 16，尝试 40 个 sleep）"
$SB create q5 --pids 16 --mem-mb 96 >/dev/null 2>&1
CG=/sys/fs/cgroup/aik-sandbox/q5
$SB run q5 -- /bin/sh -c \
	'i=0; while [ $i -lt 40 ]; do sleep 2 >/dev/null 2>&1 & i=$((i+1)); done; wait' \
	>/dev/null 2>&1
rc=$?
peak=$(cat "$CG/pids.peak" 2>/dev/null)
echo "PIDS rc=$rc pids.peak=$peak"
[ "$peak" -ge 8 ] && [ "$peak" -le 17 ]; ck $? "pids.peak=$peak 受 pids.max 限制"

# ------------------------------------------------------------------ T5
say "T5 --net none（新 netns、仅 lo、lo up）"
$SB create q6 --net none --mem-mb 64 >/dev/null 2>&1
out=$($SB run q6 -- /bin/sh -c '
	echo NETS=$(ls /sys/class/net | tr "\n" ",")
	echo FLAGS=$(cat /sys/class/net/lo/flags)
	echo NS=$(readlink /proc/self/ns/net)
	echo IFACES=$(( $(tail -n +3 /proc/net/dev | wc -l) ))
	ping -c1 -W1 127.0.0.1 >/dev/null 2>&1 && echo PING=ok || echo PING=fail' 2>&1)
ck $? "net none run rc=0"
echo "$out"
echo "$out" | grep -q 'NETS=lo,'; ck $? "lo 存在"
netline=$(echo "$out" | sed -n 's/^NETS=//p')
bad=$(echo "$netline" | tr ',' '\n' | grep -v '^$' | grep -v '^lo$' | grep -vc '^sit0$')
[ "$bad" = 0 ]; ck $? "仅 lo/sit0（无物理网卡，其余=$bad）"
flags=$(echo "$out" | sed -n 's/^FLAGS=//p')
[ -n "$flags" ] && [ $((flags & 1)) = 1 ]; ck $? "lo IFF_UP（$flags）"
ns=$(echo "$out" | sed -n 's/^NS=//p')
[ -n "$ns" ] && [ "$ns" != "$HOSTNETNS" ]; ck $? "新 net namespace（$ns != 宿主 $HOSTNETNS）"
echo "$out" | grep -qx 'PING=ok'; ck $? "CAP_NET_RAW 保留：沙盒内 ping 127.0.0.1 成功"

say "T5b 默认 host 网络"
$SB create q6b --mem-mb 64 >/dev/null 2>&1
out=$($SB run q6b -- /bin/sh -c \
	'echo NS=$(readlink /proc/self/ns/net)' 2>&1)
n1=$(echo "$out" | sed -n 's/^NS=//p')
[ -n "$n1" ] && [ "$n1" = "$HOSTNETNS" ]; ck $? "默认沿用宿主 netns（$n1）"

# ------------------------------------------------------------------ T6
say "T6 PDEATHSIG：wrapper 被 SIGKILL → 沙盒 init 立即死亡"
$SB create q7 --mem-mb 64 >/dev/null 2>&1
$SB run q7 -- /bin/sleep 300 >/dev/null 2>&1 &
rp=$!
M=$BASE/q7/meta
i=0
while [ $i -lt 20 ]; do
	grep -q '^status=running$' "$M" 2>/dev/null && break
	sleep 1
	i=$((i + 1))
done
grep -q '^status=running$' "$M"; ck $? "run 进入 running"
wrapper=$(sed -n 's/^pid=//p' "$M")
child=$(sed -n 's/^child_pid=//p' "$M")
echo "CRASH wrapper=$wrapper child=$child"
kill -9 "$wrapper" 2>/dev/null
wait "$rp" 2>/dev/null
sleep 1
if [ -e "/proc/$child" ]; then
	st=$(cat "/proc/$child/stat" 2>/dev/null)
	case "$st" in
	*" Z "*) ok "沙盒 init 已成为僵尸（已被 SIGKILL）" ;;
	*) bad "沙盒 init 仍存活" ;;
	esac
else
	ok "沙盒 init 已消失（PDEATHSIG 生效）"
fi
out=$($SB status 2>&1)
echo "$out"
echo "$out" | grep -q 'q7.*stale'; ck $? "status 标记 stale"
[ ! -d "$BASE/q7" ]; ck $? "目录已回收"
[ ! -d /sys/fs/cgroup/aik-sandbox/q7 ]; ck $? "cgroup 已回收"

# ------------------------------------------------------------------ T7
say "T7 cgroup.kill 回收孤儿"
$SB create q7b --mem-mb 64 >/dev/null 2>&1
CG=/sys/fs/cgroup/aik-sandbox/q7b
rm -f /tmp/w64-orphan.pid
( sleep 300 & echo $! > /tmp/w64-orphan.pid; wait ) &
wp=$!
i=0
while [ $i -lt 20 ]; do
	[ -s /tmp/w64-orphan.pid ] && break
	sleep 1
	i=$((i + 1))
done
hp=$(cat /tmp/w64-orphan.pid)
if echo "$hp" > "$CG/cgroup.procs"; then
	ok "测试孤儿进程已移入目标 cgroup"
	printf 'name=q7b\npid=999999\nstarted=1\ncpus=1.00\nmem_mb=64\npids_max=256\ncpu_limit=0\nmem_limit=1\npids_limit=1\nnet=host\ncgroup_dir=1\nstatus=running\n' \
		> "$BASE/q7b/meta"
	sleep 1
	out=$($SB status 2>&1)
	echo "$out"
	echo "$out" | grep -q 'q7b.*孤儿'; ck $? "status 识别 cgroup 孤儿"
	sleep 1
	if [ -e "/proc/$hp" ]; then
		st=$(cat "/proc/$hp/stat" 2>/dev/null)
		case "$st" in
		*" Z "*) ok "孤儿已被 cgroup.kill 杀死（僵尸待父回收）" ;;
		*) bad "孤儿仍存活" ;;
		esac
	else
		ok "孤儿已被 cgroup.kill 杀死"
	fi
	wait "$wp" 2>/dev/null
	[ ! -d "$CG" ]; ck $? "孤儿 cgroup 已删除"
	[ ! -e "$BASE/q7b" ]; ck $? "孤儿目录已删除"
else
	bad "移入 cgroup 失败"
	kill -9 "$hp" 2>/dev/null
	wait "$wp" 2>/dev/null
fi

# ------------------------------------------------------------------ T8
say "T8 destroy 幂等 + 活跃 run 强制回收"
$SB create q8 --mem-mb 64 >/dev/null 2>&1
$SB destroy q8 >/dev/null 2>&1; ck $? "第一次 destroy rc=0"
$SB destroy q8 >/dev/null 2>&1; ck $? "第二次 destroy rc=0（幂等）"
[ ! -e "$BASE/q8" ]; ck $? "目录已清除"
$SB create q8 --mem-mb 64 >/dev/null 2>&1
$SB run q8 -- /bin/sleep 300 >/dev/null 2>&1 &
rp=$!
M=$BASE/q8/meta
i=0
while [ $i -lt 20 ]; do
	grep -q '^status=running$' "$M" 2>/dev/null && break
	sleep 1
	i=$((i + 1))
done
$SB destroy q8 >/dev/null 2>&1; ck $? "活跃 run 时 destroy rc=0"
wait "$rp" 2>/dev/null
[ ! -e "$BASE/q8" ]; ck $? "活跃 run 目录已清除"
[ ! -d /sys/fs/cgroup/aik-sandbox/q8 ]; ck $? "活跃 run cgroup 已清除"

# ------------------------------------------------------------------ T9
say "T9 产物导出（相对/绝对/逃逸/覆盖）"
$SB create q9 --mem-mb 64 >/dev/null 2>&1
$SB run q9 -- /bin/sh -c '
	D=/var/ai/sandbox-artifacts/q9
	echo ART-OK > $D/out.txt
	ln -s /etc/shadow $D/esc' >/dev/null 2>&1
ck $? "沙盒内写产物"
[ "$(cat "$ART/q9/out.txt" 2>/dev/null)" = "ART-OK" ]; ck $? "宿主可见产物"
$SB export q9 out.txt exports/q9.txt >/dev/null 2>&1
ck $? "export 相对路径 rc=0"
[ "$(cat "$ART/exports/q9.txt" 2>/dev/null)" = "ART-OK" ]; ck $? "导出内容一致"
$SB export q9 /var/ai/sandbox-artifacts/q9/out.txt \
	/var/ai/sandbox-artifacts/exports/q9-abs.txt >/dev/null 2>&1
ck $? "export 绝对 canonical 路径 rc=0"
[ "$(cat "$ART/exports/q9-abs.txt" 2>/dev/null)" = "ART-OK" ]
ck $? "绝对路径导出内容一致"
$SB export q9 esc exports/esc.txt >/dev/null 2>&1
[ $? != 0 ]; ck $? "拒绝 src symlink 逃逸"
[ ! -e "$ART/exports/esc.txt" ]; ck $? "逃逸目标未生成"
$SB export q9 out.txt /tmp/outside >/dev/null 2>&1
[ $? != 0 ]; ck $? "拒绝 dest 越界"
$SB export q9 out.txt exports/q9.txt >/dev/null 2>&1
[ $? != 0 ]; ck $? "拒绝覆盖已存在目标"
$SB destroy q9 >/dev/null 2>&1
$SB export q9 out.txt exports/q9-after.txt >/dev/null 2>&1
ck $? "destroy 后产物仍可导出"

# ------------------------------------------------------------------ T10
say "T10 并发寿命 10×3"
cfail=0
r=1
while [ $r -le 3 ]; do
	pids=""
	i=1
	while [ $i -le 10 ]; do
		(
			n="q9c-$r-$i"
			$SB create "$n" --cpus 0.5 --mem-mb 64 --pids 32 >/dev/null 2>&1 &&
			$SB run "$n" -- /bin/sh -c 'echo hi; sleep 1' >/dev/null 2>&1 &&
			$SB status >/dev/null 2>&1 &&
			$SB destroy "$n" >/dev/null 2>&1
		) &
		pids="$pids $!"
		i=$((i + 1))
	done
	for p in $pids; do
		wait "$p" || cfail=$((cfail + 1))
	done
	echo "round $r cfail=$cfail"
	r=$((r + 1))
done
[ "$cfail" = 0 ]; ck $? "30/30 生命周期成功"
rd=$(ls "$BASE" 2>/dev/null | grep -c '^q9c-')
rmnt=$(grep -c "$BASE/q9c-" /proc/self/mountinfo 2>/dev/null)
rcg=$(ls /sys/fs/cgroup/aik-sandbox 2>/dev/null | grep -c '^q9c-')
anchor=$(cat /sys/fs/cgroup/aik-sandbox/cgroup.procs 2>/dev/null | wc -l)
echo "RESIDUAL dir=$rd mount=$rmnt cgroup=$rcg anchor_procs=$anchor"
[ "$rd" = 0 ]; ck $? "无目录残留"
[ "$rmnt" = 0 ]; ck $? "无挂载残留"
[ "$rcg" = 0 ]; ck $? "无 cgroup 残留"
[ "$anchor" = 0 ]; ck $? "anchor cgroup 无进程"

# ------------------------------------------------------------------ T11
say "T11 最终残留检查"
cleanup
rd=$(ls "$BASE" 2>/dev/null | grep -c '^q')
rmnt=$(grep -c "$BASE/q" /proc/self/mountinfo 2>/dev/null)
rcg=$(ls /sys/fs/cgroup/aik-sandbox 2>/dev/null | grep -c '^q')
echo "FINAL dir=$rd mount=$rmnt cgroup=$rcg"
[ "$rd" = 0 ]; ck $? "$BASE 无测试残留"
[ "$rmnt" = 0 ]; ck $? "无挂载残留"
[ "$rcg" = 0 ]; ck $? "无 cgroup 残留"

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
echo "=== W64 QEMU END ==="
