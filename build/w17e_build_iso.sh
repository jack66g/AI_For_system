#!/bin/bash
# W17e: build 0.1.0-alpha.17.5 ISO（run as root on L1）——系统演化五棒出厂
set -e
VERSION=0.1.0-alpha.17.5
BZ=/home/jack66g/linux-k2/arch/x86/boot/bzImage
ISODIR=/home/jack66g/w17-isodir
ISO=/home/jack66g/AIKernel-${VERSION}-x86_64.iso
TAR=/home/jack66g/w17-rootfs-factory.tar
CFG=/home/jack66g/w6i-tools/grub-iso.cfg
INITRD=/home/jack66g/w6i-initrd.img

echo "== kernel =="
md5sum "$BZ"; file "$BZ" | head -1
grep -q "$VERSION" "$CFG" || { echo "grub cfg not at 17.5"; exit 1; }
[ -f "$INITRD" ] || { echo "initrd missing"; exit 1; }

echo "== factory tar =="
rm -f "$TAR"
tar -C /home/jack66g/w7i-rootfs -cf "$TAR" .
chmod 644 "$TAR"; sync
tar -xOf "$TAR" ./etc/motd | grep -q "$VERSION" || { echo "motd not 17.5"; exit 1; }
tar -xOf "$TAR" ./etc/aikernel/ISO-SNAPSHOT-K17.txt | tail -2
if tar -tf "$TAR" | grep -q 'var/lib/ollama/models/.*blob'; then
    echo "factory tar contains ollama blobs"; exit 1; fi
# W17e 四新面断言（系统演化五棒）
for f in usr/local/bin/occ usr/local/bin/aikctl usr/local/bin/aik-compat \
         usr/local/bin/aik-gcm usr/local/sbin/aipd \
         etc/systemd/system/aikernel-aipd.service \
         etc/aikernel/aipd.conf \
         usr/bin/qemu-aarch64-static usr/bin/qemu-arm-static \
         usr/bin/python3.10 usr/lib/python3.10; do
    tar -tf "$TAR" | grep -q "$f" || { echo "missing in tar: $f"; exit 1; }
done
# E2E 修后断言：出厂 aipd.conf 必须是守护正典键集（Lane-B 先写键
# SHADOW_DIR/DECISIONS_SOURCE 在盘上真机轮 exit 1——2026-11-16 实锤）
tar -xOf "$TAR" ./etc/aikernel/aipd.conf | grep -q "^SHADOW_DIR" && {
    echo "factory aipd.conf still carries Lane-B keys"; exit 1; }
echo "conf-keyset-ok"

echo "== ISO tree =="
rm -rf "$ISODIR"
mkdir -p "$ISODIR/boot/grub"
cp "$BZ" "$ISODIR/boot/bzImage"
cp "$INITRD" "$ISODIR/boot/initrd.img"
cp "$TAR" "$ISODIR/rootfs-factory.tar"
cp "$CFG" "$ISODIR/boot/grub/grub.cfg"
md5sum "$ISODIR/boot/bzImage" "$ISODIR/boot/initrd.img" "$ISODIR/rootfs-factory.tar" "$ISODIR/boot/grub/grub.cfg"

echo "== grub-mkrescue =="
grub-mkrescue -o "$ISO" "$ISODIR" 2>&1 | tail -3
ls -la "$ISO"; md5sum "$ISO"; stat -c%s "$ISO"
echo ISO_BUILT_17_5
