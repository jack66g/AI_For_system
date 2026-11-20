#!/bin/bash
# W17J: build 0.1.0-alpha.17.9 ISO（run as root on L1）——P-55/O-8/P-56
# 收编。内核沿用 #82（bzImage 7b35b41f…；softdog.ko 同树 9e50cb73…）
set -e
VERSION=0.1.0-alpha.17.9
BZ=/home/jack66g/linux-k2/arch/x86/boot/bzImage
KO=/home/jack66g/linux-k2/drivers/watchdog/softdog.ko
REPO=/home/jack66g/aikernel-repo-alpha11
ISODIR=/home/jack66g/w17-isodir
ISO=/home/jack66g/AIKernel-${VERSION}-x86_64.iso
TAR=/home/jack66g/w17-rootfs-factory.tar
CFG=/home/jack66g/aik-wt-p179/build/w17j-grub-iso.cfg
INITRD=/home/jack66g/w6i-initrd.img

tmd5() { tar -xOf "$TAR" "$1" | md5sum | cut -d" " -f1; }

echo "== kernel =="
md5sum "$BZ"; file "$BZ" | head -1
[ "$(md5sum "$BZ" | cut -d" " -f1)" = "7b35b41fb86f2c1c20e1fd57053e3d5e" ] \
    || { echo "bzImage not #82 final"; exit 1; }
[ "$(md5sum "$KO" | cut -d" " -f1)" = "9e50cb73434ab8ba363127682646fa63" ] \
    || { echo "softdog.ko not same-tree #82 build"; exit 1; }
grep -q "$VERSION" "$CFG" || { echo "grub cfg not at 17.9"; exit 1; }
[ -f "$INITRD" ] || { echo "initrd missing"; exit 1; }

echo "== factory tar =="
rm -f "$TAR"
tar -C /home/jack66g/w7i-rootfs -cf "$TAR" .
chmod 644 "$TAR"; sync
tar -xOf "$TAR" ./etc/motd | grep -q "$VERSION" || { echo "motd not 17.9"; exit 1; }
tar -xOf "$TAR" ./etc/aikernel/ISO-SNAPSHOT-K17.txt | tail -2
tar -xOf "$TAR" ./etc/aikernel/ISO-SNAPSHOT-W82.txt | head -4
if tar -tf "$TAR" | grep -q 'var/lib/ollama/models/.*blob'; then
    echo "factory tar contains ollama blobs"; exit 1; fi
# 既有面 + 17.8.1 新面在位断言
for f in usr/local/bin/occ usr/local/bin/aikctl usr/local/bin/aik-compat \
         usr/local/bin/aik-gcm usr/local/sbin/aipd \
         usr/local/bin/aik-console usr/local/sbin/aistreamd \
         usr/local/sbin/aik-upgrade \
         etc/systemd/system/aikernel-aipd.service etc/aikernel/aipd.conf \
         usr/bin/qemu-aarch64-static usr/bin/qemu-arm-static \
         usr/bin/python3.10 usr/lib/python3.10 \
         etc/ssh/sshd_config etc/ssh/sshd_config.d/50-aik-hardening.conf \
         etc/apt/apt.conf.d/51-aik-upgrade-policy \
         etc/aikernel/aistreamd.conf \
         etc/fonts/fonts.conf etc/sysctl.d/50-aik-console-quiet.conf \
         usr/local/sbin/aik-log-trim etc/systemd/system/aik-log-trim.timer \
         etc/systemd/system/timers.target.wants/aik-log-trim.timer \
         usr/local/bin/busybox usr/local/bin/crond usr/local/bin/crontab \
         usr/local/bin/fdisk etc/systemd/system/aik-cron.service \
         etc/systemd/system/multi-user.target.wants/aik-cron.service \
         usr/local/sbin/aik-backup usr/local/sbin/aikernel-health.sh \
         etc/systemd/system/aikernel-api.service \
         usr/lib/modules/6.18.39/kernel/drivers/watchdog/softdog.ko; do
    tar -tf "$TAR" | grep -q "$f" || { echo "missing in tar: $f"; exit 1; }
done
# P-32 断言：repo 同源（tar 内件 = 仓裸件，出厂即所编）
[ "$(tmd5 ./usr/local/sbin/aistreamd)" = \
  "$(md5sum "$REPO/agent/ai/aistreamd/aistreamd" | cut -d" " -f1)" ] || {
    echo "P-32: aistreamd in tar != repo build"; exit 1; }
[ "$(tmd5 ./usr/local/bin/occ)" = \
  "$(md5sum "$REPO/agent/ai/occ/occ" | cut -d" " -f1)" ] || {
    echo "occ in tar != repo build"; exit 1; }
[ "$(tmd5 ./usr/local/bin/aik-console)" = \
  "$(md5sum "$REPO/factory/usr/local/bin/aik-console" | cut -d" " -f1)" ] || {
    echo "aik-console in tar != factory tree"; exit 1; }
[ "$(tmd5 ./usr/local/sbin/aik-upgrade)" = \
  "$(md5sum "$REPO/factory/usr/local/sbin/aik-upgrade" | cut -d" " -f1)" ] || {
    echo "aik-upgrade in tar != factory tree"; exit 1; }
tar -xOf "$TAR" ./usr/local/sbin/aistreamd | strings 2>/dev/null | \
    grep -q PARQUET_RETENTION_DAYS || {
    echo "P-32: aistreamd binary unaware of new conf key"; exit 1; }
# P-33 断言：softdog 同树件（tar 内 = k2 树产物；merged-usr 物理路径）
[ "$(tmd5 ./usr/lib/modules/6.18.39/kernel/drivers/watchdog/softdog.ko)" = \
   "9e50cb73434ab8ba363127682646fa63" ] || {
    echo "P-33: softdog.ko in tar not same-tree #82"; exit 1; }
# 17.9 新面断言（P-55/O-8/P-56/O-20）
for f in usr/local/bin/aik-ime \
         usr/local/lib/aik-ime/libleveldb.so.1d \
         usr/local/lib/aik-ime/libleveldb.so.1.23.0 \
         usr/local/lib/aik-ime/libyaml-cpp.so.0.7.0 \
         usr/local/lib/aik-ime/libboost_regex.so.1.74.0 \
         usr/local/lib/aik-ime/libicuuc.so.70.1 \
         usr/share/rime-data/essay.txt \
         usr/share/rime-data/build/luna_pinyin.prism.bin \
         usr/share/rime-data/build/luna_pinyin.table.bin \
         root/.fbtermrc; do
    tar -tf "$TAR" | grep -q "$f" || { echo "missing in tar: $f"; exit 1; }
done
tar -xOf "$TAR" ./root/.fbtermrc | grep -q 'input-method=aik-ime' || {
    echo "fbtermrc lacks IME hook"; exit 1; }
tar -xOf "$TAR" ./usr/local/sbin/aipd | strings 2>/dev/null | \
    grep -q aip_shadow_colname || { echo "aipd lacks P-56"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aik-sandbox | strings 2>/dev/null | \
    grep -q which.debianutils || { echo "sandbox lacks O-8"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/occ | strings 2>/dev/null | \
    grep -q OCC_LANG || { echo "occ lacks O-20"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aik-ime | strings 2>/dev/null | \
    grep -q '/usr/local/lib/aik-ime' || { echo "aik-ime lacks RPATH"; exit 1; }
# 出厂件=所编件（factory 树同源）
[ "$(tmd5 ./usr/local/bin/aik-ime)" = \
  "$(md5sum "$REPO/factory/usr/local/bin/aik-ime" | cut -d' ' -f1)" ] || {
    echo "aik-ime in tar != factory tree"; exit 1; }
[ "$(tmd5 ./usr/local/bin/aik-sandbox)" = \
  "$(md5sum "$REPO/agent/ai/sandbox/aik-sandbox" | cut -d' ' -f1)" ] || {
    echo "aik-sandbox in tar != repo build"; exit 1; }
[ "$(tmd5 ./usr/local/sbin/aipd)" = \
  "$(md5sum "$REPO/agent/ai/aipd/aipd" | cut -d' ' -f1)" ] || {
    echo "aipd in tar != repo build"; exit 1; }
echo "p55+o8+p56 anchors ok"

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
# P2a/P47/P48 断言：occ 新面（netcfg+unstuck+marker）
tar -xOf "$TAR" ./usr/local/bin/occ | strings 2>/dev/null | \
    grep -q "config_write_network" || {
    echo "occ lacks config_write_network"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/occ | strings 2>/dev/null | \
    grep -q "unstuck" || { echo "occ lacks unstuck (P-48)"; exit 1; }
# O-1/P-47 断言：aik-console v8（marker 消费链）
tar -xOf "$TAR" ./usr/local/bin/aik-console | grep -q "occ-logout-marker" || {
    echo "aik-console not v8"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aik-console | \
    grep -q "OCC_NETCFG_TOOLS=1" || {
    echo "aik-console missing netcfg flag"; exit 1; }
# W-7/P-34/P-38 断言
tar -xOf "$TAR" ./usr/local/sbin/aik-upgrade | \
    grep -q "userland" || { echo "aik-upgrade lacks userland channel"; exit 1; }
tar -xOf "$TAR" ./etc/fonts/fonts.conf | \
    grep -q "Noto Sans Mono CJK SC" || { echo "P-34 fonts.conf missing"; exit 1; }
tar -xOf "$TAR" ./etc/sysctl.d/50-aik-console-quiet.conf | \
    grep -q "kernel.printk" || { echo "P-38 printk quiet missing"; exit 1; }
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
echo ISO_BUILT_17_9
