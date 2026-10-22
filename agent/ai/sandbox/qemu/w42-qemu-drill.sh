#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# w42-qemu-drill.sh - W42 隔离区真内核演练（AIKernel bzImage @ qemu TCG）
# 红线沿用 qemu-drill.sh：-nic none 无外联、无 -drive 零盘面、沙盒用完即扔。
# 用法: bash w42-qemu-drill.sh [超时秒，默认 240]
set -u
AI_DIR=/home/jack66g/linux-6.18.39/agent/ai
BZIMAGE=/home/jack66g/linux-6.18.39/arch/x86/boot/bzImage
LOG=/tmp/w42-qemu-serial.log
TIMEOUT="${1:-240}"

bash "$(dirname "$0")/w42-build-initramfs.sh" || exit 2

rm -f "$LOG"
echo "w42-qemu-drill: bzImage=$BZIMAGE timeout=${TIMEOUT}s"
qemu-system-x86_64 \
	-accel tcg,thread=multi -cpu max -m 512M -smp 2 \
	-display none -vga none -nic none \
	-serial "file:$LOG" -no-reboot \
	-kernel "$BZIMAGE" \
	-initrd /tmp/w42-initramfs.cpio.gz \
	-append "console=ttyS0,115200 panic=-1" >/dev/null 2>&1 &
QPID=$!

t0=$(date +%s)
done_mark=0
while :; do
	now=$(date +%s)
	[ $((now - t0)) -ge "$TIMEOUT" ] && break
	if ! kill -0 "$QPID" 2>/dev/null; then echo "(qemu exited)"; break; fi
	grep -q "W42 QEMU DRILL END" "$LOG" 2>/dev/null && { done_mark=1; sleep 3; break; }
	sleep 2
done
kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true

echo "=== 串口日志演练段 ==="
sed -n "/W42 QEMU DRILL START/,/W42 QEMU DRILL END/p" "$LOG" || echo "(未捕捉到演练段)"
echo "=== 判定 ==="
P=0; F=0
ck(){ if grep -q "$2" "$LOG" 2>/dev/null; then P=$((P+1)); echo "PASS: $1"; else F=$((F+1)); echo "FAIL: $1"; fi; }
ck "q1 内核接受隔离区(create)"        "create: sbq 就绪"
ck "q2 clone(NS|PID|UTS) 真内核成功"  "SB_HOST=sbq"
ck "q3 AIKERNEL_SANDBOX 注入"         "SB_ENV=sbq"
ck "q4 tmpfs 空根视图"                "SB_ROOT:"
ck "q5 pivot_root 后 /etc/shadow 不可见" "SHADOW_READ_RC=1"
ck "q6 沙盒写 /root 落 tmpfs 宿主无泄漏" "HOST_LEAK=NO"
ck "q7 /usr ro bind 写拒绝"           "USR_W_RC=1"
ck "q8 /sys ro bind 写拒绝"           "SYS_W_RC=1"
ck "q9 /proc 可读"                    "PROC_READ_RC=0"
ck "q10 destroy 焚毁"                 "destroy: sbq"
ck "q11 演练完整跑完"                 "W42 QEMU DRILL END"
echo "=== qemu 演练结果: PASS=$P FAIL=$F ==="
[ "$done_mark" = 1 ] || echo "(注意: 未见 END 标记，可能超时截断)"
[ "$F" = 0 ]
