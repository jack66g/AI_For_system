#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# W64 QEMU 真内核沙箱演练（不接触生产 VM）
#   构建最小 initramfs（busybox + 新 aik-sandbox + 静态 init 回收器），
#   启动 AIKernel bzImage（TCG，-nic none，无盘），跑 guest 回归脚本，
#   解析 PASS/FAIL 并把串口日志归档到 fix-w64/qemu/。
#
# 用法: bash w64-qemu-drill.sh [超时秒=300]
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
AI_DIR=/home/jack66g/linux-6.18.39/agent/ai
BZIMAGE=/home/jack66g/linux-6.18.39/arch/x86/boot/bzImage
ROOT=/tmp/w64-qemu-initramfs
INITRAMFS=/tmp/w64-initramfs.cpio.gz
LOG=/tmp/w64-qemu-serial.log
TIMEOUT="${1:-300}"
EV="${W64_EVIDENCE:-$HOME/mbedtls-trim-evidence/logs/fix-w64/qemu}"
mkdir -p "$EV"

[ -x "$AI_DIR/aik-sandbox" ] || { echo "缺少 $AI_DIR/aik-sandbox"; exit 2; }
[ -f "$BZIMAGE" ] || { echo "缺少 $BZIMAGE"; exit 2; }

echo "== 构建 initramfs =="
rm -rf "$ROOT"
mkdir -p "$ROOT/usr/bin" "$ROOT/usr/sbin" "$ROOT/proc" "$ROOT/sys" \
	 "$ROOT/dev" "$ROOT/etc" "$ROOT/tmp" "$ROOT/sandbox" "$ROOT/root" \
	 "$ROOT/usr/lib" "$ROOT/var"
cp /usr/bin/busybox "$ROOT/usr/bin/"
for app in sh mount umount ls cat touch echo grep sleep mkdir mknod ln rm \
	   dd sed awk tr cut wc readlink hostname uname id tail kill ps ping; do
	ln -sf busybox "$ROOT/usr/bin/$app"
done
ln -sf usr/bin "$ROOT/bin"
ln -sf usr/sbin "$ROOT/sbin"
ln -sf usr/lib "$ROOT/lib"
gcc -static -O2 -o "$ROOT/init" "$HERE/w64-init.c" || exit 2
cp "$AI_DIR/aik-sandbox" "$ROOT/aik-sandbox"
cp "$HERE/w64-guest-test.sh" "$ROOT/w64-test.sh"
chmod 755 "$ROOT/init" "$ROOT/aik-sandbox" "$ROOT/w64-test.sh"
printf 'root:$6$w64dummy:19000:0:99999:7:::\n' > "$ROOT/etc/shadow"
chmod 600 "$ROOT/etc/shadow"
printf 'nameserver 127.0.0.1\n' > "$ROOT/etc/resolv.conf"
( cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip > "$INITRAMFS" )
echo "initramfs: $INITRAMFS ($(stat -c%s "$INITRAMFS") bytes)"
sha256sum "$AI_DIR/aik-sandbox" "$INITRAMFS" | tee "$EV/qemu-input-sha256.txt"

echo "== 启动 QEMU（bzImage=$BZIMAGE, timeout=${TIMEOUT}s） =="
rm -f "$LOG"
qemu-system-x86_64 \
	-accel tcg,thread=multi -cpu max -m 512M -smp 2 \
	-display none -vga none -nic none \
	-serial "file:$LOG" -no-reboot \
	-kernel "$BZIMAGE" \
	-initrd "$INITRAMFS" \
	-append "console=ttyS0,115200 panic=-1 kunit.enable=0" >/dev/null 2>&1 &
QPID=$!

t0=$(date +%s)
done_mark=0
while :; do
	now=$(date +%s)
	[ $((now - t0)) -ge "$TIMEOUT" ] && break
	if ! kill -0 "$QPID" 2>/dev/null; then
		echo "(qemu exited)"
		break
	fi
	grep -q "W64 QEMU END" "$LOG" 2>/dev/null && { done_mark=1; sleep 3; break; }
	sleep 2
done
kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true
cp "$LOG" "$EV/qemu-serial.log" 2>/dev/null || true

echo "=== 串口日志沙箱段 ==="
sed -n "/W64 QEMU START/,/W64 QEMU END/p" "$LOG" || echo "(未捕捉到演练段)"
echo "=== 判定 ==="
P=$(grep -c '^PASS:' "$LOG" 2>/dev/null || true)
F=$(grep -c '^FAIL:' "$LOG" 2>/dev/null || true)
RES=$(grep '^RESULT:' "$LOG" 2>/dev/null | tail -1)
# QEMU 可能在两次轮询之间已 poweroff：以日志里的 END 标记为准
if grep -q "W64 QEMU END" "$LOG" 2>/dev/null; then
	done_mark=1
fi
echo "PASS=$P FAIL=$F"
echo "RESULT_LINE: ${RES:-none}"
grep '^FAIL:' "$LOG" 2>/dev/null || true
if [ "$done_mark" = 1 ] && [ "$F" = 0 ]; then
	echo "VERDICT: ALL PASS"
	exit 0
fi
echo "VERDICT: FAIL（日志 $EV/qemu-serial.log）"
exit 1
