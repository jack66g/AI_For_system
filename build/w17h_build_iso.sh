#!/bin/bash
# W17H: build 0.1.0-alpha.17.8 ISO（run as root on L1）——P1 安全五项+
# P2 功能七项进厂。内核沿用 #82（bzImage 7b35b41f…；PSI 翻案零内核改动）
set -e
VERSION=0.1.0-alpha.17.8
BZ=/home/jack66g/linux-k2/arch/x86/boot/bzImage
ISODIR=/home/jack66g/w17-isodir
ISO=/home/jack66g/AIKernel-${VERSION}-x86_64.iso
TAR=/home/jack66g/w17-rootfs-factory.tar
CFG=/home/jack66g/w6i-tools/grub-iso.cfg
INITRD=/home/jack66g/w6i-initrd.img

echo "== kernel =="
md5sum "$BZ"; file "$BZ" | head -1
[ "$(md5sum "$BZ" | cut -d" " -f1)" = "7b35b41fb86f2c1c20e1fd57053e3d5e" ] \
    || { echo "bzImage not #82 final"; exit 1; }
grep -q "$VERSION" "$CFG" || { echo "grub cfg not at 17.8"; exit 1; }
[ -f "$INITRD" ] || { echo "initrd missing"; exit 1; }

echo "== factory tar =="
rm -f "$TAR"
tar -C /home/jack66g/w7i-rootfs -cf "$TAR" .
chmod 644 "$TAR"; sync
tar -xOf "$TAR" ./etc/motd | grep -q "$VERSION" || { echo "motd not 17.8"; exit 1; }
tar -xOf "$TAR" ./etc/aikernel/ISO-SNAPSHOT-K17.txt | tail -2
if tar -tf "$TAR" | grep -q 'var/lib/ollama/models/.*blob'; then
    echo "factory tar contains ollama blobs"; exit 1; fi
# 17.7 既有面 + 17.8 新面在位断言
for f in usr/local/bin/occ usr/local/bin/aikctl usr/local/bin/aik-compat \
         usr/local/bin/aik-gcm usr/local/sbin/aipd \
         usr/local/bin/aik-console usr/local/sbin/aistreamd \
         etc/systemd/system/aikernel-aipd.service etc/aikernel/aipd.conf \
         usr/bin/qemu-aarch64-static usr/bin/qemu-arm-static \
         usr/bin/python3.10 usr/lib/python3.10 \
         etc/ssh/sshd_config etc/ssh/sshd_config.d/50-aik-hardening.conf \
         etc/apt/apt.conf.d/51-aik-upgrade-policy \
         etc/aikernel/aistreamd.conf \
         usr/local/sbin/aik-log-trim etc/systemd/system/aik-log-trim.timer \
         etc/systemd/system/timers.target.wants/aik-log-trim.timer \
         usr/local/bin/busybox usr/local/bin/crond usr/local/bin/crontab \
         usr/local/bin/fdisk etc/systemd/system/aik-cron.service \
         etc/systemd/system/multi-user.target.wants/aik-cron.service \
         usr/local/sbin/aik-backup usr/local/sbin/aikernel-health.sh \
         etc/systemd/system/aikernel-api.service; do
    tar -tf "$TAR" | grep -q "$f" || { echo "missing in tar: $f"; exit 1; }
done
# P1 断言：硬化键 + u-u 显式禁用 + man 已删
tar -xOf "$TAR" ./etc/ssh/sshd_config.d/50-aik-hardening.conf | \
    grep -q "PermitRootLogin prohibit-password" || {
    echo "sshd hardening missing"; exit 1; }
tar -xOf "$TAR" ./etc/apt/apt.conf.d/51-aik-upgrade-policy | \
    grep -q 'Unattended-Upgrade "0"' || {
    echo "u-u disable decision missing"; exit 1; }
if tar -tf "$TAR" | grep -q '\./usr/share/man/'; then
    echo "C-P2c: man pages still in tar"; exit 1; fi
# P1e/P2e 断言：health 三闸+告警出口
tar -xOf "$TAR" ./usr/local/sbin/aikernel-health.sh | \
    grep -q "HEAL_GRACE_SEC" || { echo "health gates missing"; exit 1; }
# P2b 断言：crond 前台化
tar -xOf "$TAR" ./etc/systemd/system/aik-cron.service | \
    grep -q "crond -f -S -l 8" || { echo "crond not -f"; exit 1; }
# P2a 断言：occ 带结构化网络工具（旗控）
tar -xOf "$TAR" ./usr/local/bin/occ | strings 2>/dev/null | \
    grep -q "config_write_network" || {
    echo "occ lacks config_write_network"; exit 1; }
# PROV_PUBKEY 注入态（在/不在均合法——在则必须是单行公钥）
if tar -tf "$TAR" | grep -q '\./root/.ssh/authorized_keys'; then
    tar -xOf "$TAR" ./root/.ssh/authorized_keys | wc -l | grep -q '^1$' || {
        echo "authorized_keys must be single line"; exit 1; }
    tar -xOf "$TAR" ./root/.ssh/authorized_keys | \
        grep -qE '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-)' || {
        echo "authorized_keys not a public key line"; exit 1; }
    echo "prov-key: present (single line)"
else
    echo "prov-key: absent (install-time nbd seeding required)"
fi
# O-1 断言：aik-console v6
tar -xOf "$TAR" ./usr/local/bin/aik-console | grep -q "occ-logout" || {
    echo "aik-console not v6"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aik-console | \
    grep -q "OCC_NETCFG_TOOLS=1" || {
    echo "aik-console missing netcfg flag"; exit 1; }
echo "conf-keyset-ok"

echo "== ISO tree =="
rm -rf "$ISODIR"
mkdir -p "$ISODIR/boot/grub"
cp "$BZ" "$ISODIR/boot/bzImage"
cp "$INITRD" "$ISODIR/boot/initrd.img"
cp "$TAR" "$ISODIR/rootfs-factory.tar"
cp "$CFG" "$ISODIR/boot/grub/grub.cfg"
md5sum "$ISODIR/boot/bzImage" "$ISODIR/boot/initrd.img" \
       "$ISODIR/rootfs-factory.tar" "$ISODIR/boot/grub/grub.cfg"

echo "== grub-mkrescue =="
grub-mkrescue -o "$ISO" "$ISODIR" 2>&1 | tail -3
ls -la "$ISO"; md5sum "$ISO"; stat -c%s "$ISO"
echo ISO_BUILT_17_8
