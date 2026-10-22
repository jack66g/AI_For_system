#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# w42-build-initramfs.sh - W42 qemu 真内核演练用最小 initramfs
# 内容：usrmerge 布局（/usr/bin/busybox + /bin→usr/bin 等符号链接，
#       使沙盒的 /usr ro bind 在 initramfs 根上同样成立）+ 静态
#       aik-sandbox + /etc/shadow 假文件（验证沙盒不可见）+ /init 演练脚本
# 产物：/tmp/w42-initramfs.cpio.gz
set -e
AI_DIR=/home/jack66g/linux-6.18.39/agent/ai
ROOT=/tmp/w42-initramfs

rm -rf "$ROOT"
mkdir -p "$ROOT/usr/bin" "$ROOT/usr/sbin" "$ROOT/sbin" "$ROOT/proc" \
	 "$ROOT/sys" "$ROOT/dev" "$ROOT/etc" "$ROOT/sandbox" "$ROOT/root"

cp /usr/bin/busybox "$ROOT/usr/bin/"
for app in sh mount umount ls cat touch echo grep sleep poweroff \
	   uname hostname mkdir mknod ln rm sync cut tr; do
	ln -sf busybox "$ROOT/usr/bin/$app"
done
# usrmerge 符号链接（与宿主布局一致：沙盒 tmpfs 根上也建同样链接）
ln -sf usr/bin "$ROOT/bin"
ln -sf usr/sbin "$ROOT/sbin"
ln -sfn usr/lib "$ROOT/lib" 2>/dev/null || mkdir -p "$ROOT/usr/lib" && ln -sfn usr/lib "$ROOT/lib"

cp "$AI_DIR/aik-sandbox" "$ROOT/aik-sandbox"
chmod 755 "$ROOT/aik-sandbox"

# 假 shadow：沙盒内必须不可见
echo "root:$6$w42dummy:19000:0:99999:7:::" > "$ROOT/etc/shadow"
chmod 600 "$ROOT/etc/shadow"
# 演练用 DNS/CA 白名单文件（存在即可，内容不重要）
cp /etc/resolv.conf "$ROOT/etc/resolv.conf" 2>/dev/null || echo "nameserver 10.0.2.3" > "$ROOT/etc/resolv.conf"

cat > "$ROOT/init" <<'EOF'
#!/bin/sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || /bin/busybox mdev -s
echo "=== W42 QEMU DRILL START ==="
echo "KERNEL=$(uname -r) ARCH=$(uname -m)"
echo "--- [1] create"
/aik-sandbox create sbq
echo "--- [2] run: 视图+身份"
/aik-sandbox run sbq -- /bin/sh -c 'echo SB_HOST=$(hostname); echo SB_ENV=$AIKERNEL_SANDBOX; echo SB_ROOT:; ls /'
echo "--- [3] run: 敏感面"
/aik-sandbox run sbq -- /bin/sh -c 'ls /etc/shadow; echo SHADOW_SEEN_RC=$?; cat /etc/shadow; echo SHADOW_READ_RC=$?'
echo "--- [4] run: 只写 tmpfs"
/aik-sandbox run sbq -- /bin/sh -c 'echo probe > /root/w42probe; echo ROOT_W_RC=$?; ls /root'
echo "HOSTSIDE_PROBE_CHECK: probe 不可能出现在 initramfs 的 /root（沙盒写的是 tmpfs）"
ls /root/w42probe 2>/dev/null && echo "HOST_LEAK=YES" || echo "HOST_LEAK=NO"
echo "--- [5] run: ro 面"
/aik-sandbox run sbq -- /bin/sh -c 'touch /usr/w42x; echo USR_W_RC=$?; touch /sys/w42x; echo SYS_W_RC=$?; cat /proc/uptime >/dev/null; echo PROC_READ_RC=$?; cat /proc/ai/status >/dev/null 2>&1; echo PROC_AI_RC=$?'
echo "--- [6] status"
/aik-sandbox status
echo "--- [7] destroy + 复查"
/aik-sandbox destroy sbq
ls /sandbox/ | wc -l
echo "=== W42 QEMU DRILL END ==="
poweroff -f
while :; do sleep 1; done
EOF
chmod 755 "$ROOT/init"

cd "$ROOT"
find . | cpio -o -H newc --quiet | gzip > /tmp/w42-initramfs.cpio.gz
echo "OK: /tmp/w42-initramfs.cpio.gz ($(stat -c%s /tmp/w42-initramfs.cpio.gz) bytes)"
