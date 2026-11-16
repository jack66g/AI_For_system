#!/bin/bash
# W17G: build 0.1.0-alpha.17.7 ISO（run as root on L1）——M2/P2/E1'/G1 进厂
# 内核升 #82（AIPD=6；bzImage d553ca24 与 M2 内核轮同件——config_hash 不变）
set -e
VERSION=0.1.0-alpha.17.7
BZ=/home/jack66g/linux-k2/arch/x86/boot/bzImage
ISODIR=/home/jack66g/w17-isodir
ISO=/home/jack66g/AIKernel-${VERSION}-x86_64.iso
TAR=/home/jack66g/w17-rootfs-factory.tar
CFG=/home/jack66g/w6i-tools/grub-iso.cfg
INITRD=/home/jack66g/w6i-initrd.img

echo "== kernel =="
md5sum "$BZ"; file "$BZ" | head -1
[ "$(md5sum "$BZ" | cut -d" " -f1)" = "7b35b41fb86f2c1c20e1fd57053e3d5e" ] \
    || { echo "bzImage not #82 final (7b35b41f... m2k/m2v 已验件)"; exit 1; }
grep -q "$VERSION" "$CFG" || { echo "grub cfg not at 17.7"; exit 1; }
[ -f "$INITRD" ] || { echo "initrd missing"; exit 1; }

echo "== factory tar =="
rm -f "$TAR"
tar -C /home/jack66g/w7i-rootfs -cf "$TAR" .
chmod 644 "$TAR"; sync
tar -xOf "$TAR" ./etc/motd | grep -q "$VERSION" || { echo "motd not 17.7"; exit 1; }
tar -xOf "$TAR" ./etc/aikernel/ISO-SNAPSHOT-K17.txt | tail -2
if tar -tf "$TAR" | grep -q 'var/lib/ollama/models/.*blob'; then
    echo "factory tar contains ollama blobs"; exit 1; fi
# W17G 面断言（六件+v5 wrapper+正典 conf；python3.10=17.5 已带保持）
for f in usr/local/bin/occ usr/local/bin/aikctl usr/local/bin/aik-compat \
         usr/local/bin/aik-gcm usr/local/sbin/aipd \
         usr/local/bin/aik-console \
         etc/systemd/system/aikernel-aipd.service \
         etc/aikernel/aipd.conf \
         usr/bin/qemu-aarch64-static usr/bin/qemu-arm-static \
         usr/bin/python3.10 usr/lib/python3.10; do
    tar -tf "$TAR" | grep -q "$f" || { echo "missing in tar: $f"; exit 1; }
done
# P2 修断言：aik-console 必须 v5（串口 stty+循环+取证）
tar -xOf "$TAR" ./usr/local/bin/aik-console | \
    grep -q "stty rows 24 cols 80" || {
    echo "aik-console not v5"; exit 1; }
# O-1 断言：aik-console 必须 v6（rc71 断链回 login 面）
tar -xOf "$TAR" ./usr/local/bin/aik-console | \
    grep -q "occ-logout" || {
    echo "aik-console not v6"; exit 1; }
# aipd.conf 键集正典性（Lane-B 键拒绝沿用）+ 注释态 canary 面在文件
tar -xOf "$TAR" ./etc/aikernel/aipd.conf | grep -q "^SHADOW_DIR" && {
    echo "factory aipd.conf still carries Lane-B keys"; exit 1; }
tar -xOf "$TAR" ./etc/aikernel/aipd.conf | grep -q "CANARY_ENABLED" || {
    echo "aipd.conf missing canary face"; exit 1; }
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
echo ISO_BUILT_17_7
