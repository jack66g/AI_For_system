#!/bin/bash
# W17N: build ISO（sudo 于 L1）——版本号单点=build/VERSION
# soft 出厂。内核沿用 #82（bzImage 7b35b41f…；softdog.ko 同树 9e50cb73…）
set -e
BZ=/home/jack66g/linux-k2/arch/x86/boot/bzImage
KO=/home/jack66g/linux-k2/drivers/watchdog/softdog.ko
REPO=/home/jack66g/aikernel-repo-alpha11
VERSION=$(cat "$REPO/build/VERSION")
[ -n "$VERSION" ] || { echo "build/VERSION empty"; exit 1; }
ISODIR=/home/jack66g/w17-isodir
ISO=/home/jack66g/AIKernel-${VERSION}-x86_64.iso
TAR=/home/jack66g/w17-rootfs-factory.tar
CFG=/home/jack66g/aikernel-repo-alpha11/build/w17j-grub-iso.cfg
INITRD=/home/jack66g/w6i-initrd.img

tmd5() { tar -xOf "$TAR" "$1" | md5sum | cut -d" " -f1; }

echo "== kernel =="
md5sum "$BZ"; file "$BZ" | head -1
[ "$(md5sum "$BZ" | cut -d" " -f1)" = "7b35b41fb86f2c1c20e1fd57053e3d5e" ] \
    || { echo "bzImage not #82 final"; exit 1; }
[ "$(md5sum "$KO" | cut -d" " -f1)" = "9e50cb73434ab8ba363127682646fa63" ] \
    || { echo "softdog.ko not same-tree #82 build"; exit 1; }
grep -q "$VERSION" "$CFG" || { echo "grub cfg not at $VERSION"; exit 1; }
[ -f "$INITRD" ] || { echo "initrd missing"; exit 1; }

echo "== factory tar =="
rm -f "$TAR"
tar -C /home/jack66g/w7i-rootfs -cf "$TAR" .
chmod 644 "$TAR"; sync
tar -xOf "$TAR" ./etc/motd | grep -q "$VERSION" || { echo "motd not $VERSION"; exit 1; }
# 出厂同源锚前置（未跟踪件；缺失即停，不得静默换件）
[ -f "$REPO/agent/ai/sandbox/aik-sandbox" ] || { echo "aik-sandbox factory anchor missing"; exit 1; }
tar -xOf "$TAR" ./etc/aikernel/ISO-SNAPSHOT-K17.txt | tail -2
tar -xOf "$TAR" ./etc/aikernel/ISO-SNAPSHOT-W82.txt | head -4
if tar -tf "$TAR" | grep -q 'var/lib/ollama/models/.*blob'; then
    echo "factory tar contains ollama blobs"; exit 1; fi
# 既有面全量在位断言（17.7~17.10 沿承 + 17.11 新件）
for f in usr/local/bin/occ usr/local/bin/aikctl usr/local/bin/aik-compat \
         usr/local/bin/aik-gcm usr/local/sbin/aipd \
         usr/local/bin/aik-console usr/local/sbin/aistreamd \
         usr/local/sbin/aik-upgrade usr/local/sbin/aik-reset \
         usr/local/bin/aik-pqdump \
         etc/systemd/system/aikernel-aipd.service etc/aikernel/aipd.conf \
         etc/aikernel/policy.conf \
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
         root/.aikernel/model.toml \
         usr/lib/modules/6.18.39/kernel/drivers/watchdog/softdog.ko; do
    tar -tf "$TAR" | grep -q "$f" || { echo "missing in tar: $f"; exit 1; }
done
# P-60 预建三目录（tar 目录件）+ 系统层共享槽
for d in etc/aikernel/models.d var/ai/work var/log/aik-console; do
    tar -tf "$TAR" | grep -q "$d" || { echo "missing dir in tar: $d"; exit 1; }
done
tar -tf "$TAR" | grep -q 'etc/aikernel/models.d/cloud.toml' || {
    echo "models.d cloud.toml missing"; exit 1; }
tar -xOf "$TAR" ./etc/aikernel/models.d/cloud.toml | \
    grep -q '\[models.cloud\]' || {
    echo "models.d cloud.toml lacks slot"; exit 1; }
# P-32 断言：repo 同源（tar 内件 = 仓裸件，出厂即所编）
[ "$(tmd5 ./usr/local/sbin/aistreamd)" = \
  "$(md5sum "$REPO/agent/ai/aistreamd/aistreamd" | cut -d" " -f1)" ] || {
    echo "P-32: aistreamd in tar != repo build"; exit 1; }
[ "$(tmd5 ./usr/local/bin/occ)" = \
  "$(md5sum "$REPO/agent/ai/occ/occ" | cut -d" " -f1)" ] || {
    echo "occ in tar != repo build"; exit 1; }
[ "$(tmd5 ./usr/local/bin/aikctl)" = \
  "$(md5sum "$REPO/agent/ai/aikctl/aikctl" | cut -d" " -f1)" ] || {
    echo "aikctl in tar != repo build"; exit 1; }
[ "$(tmd5 ./usr/local/bin/aik-pqdump)" = \
  "$(md5sum "$REPO/agent/ai/aistreamd/aik-pqdump" | cut -d" " -f1)" ] || {
    echo "aik-pqdump in tar != repo build"; exit 1; }
[ "$(tmd5 ./usr/local/bin/aik-console)" = \
  "$(md5sum "$REPO/factory/usr/local/bin/aik-console" | cut -d" " -f1)" ] || {
    echo "aik-console in tar != factory tree"; exit 1; }
[ "$(tmd5 ./usr/local/sbin/aik-upgrade)" = \
  "$(md5sum "$REPO/factory/usr/local/sbin/aik-upgrade" | cut -d" " -f1)" ] || {
    echo "aik-upgrade in tar != factory tree"; exit 1; }
[ "$(tmd5 ./usr/local/sbin/aik-reset)" = \
  "$(md5sum "$REPO/factory/usr/local/sbin/aik-reset" | cut -d" " -f1)" ] || {
    echo "aik-reset in tar != factory tree"; exit 1; }
[ "$(tmd5 ./etc/aikernel/policy.conf)" = \
  "$(md5sum "$REPO/factory/etc/aikernel/policy.conf" | cut -d" " -f1)" ] || {
    echo "policy.conf in tar != factory tree"; exit 1; }
tar -xOf "$TAR" ./usr/local/sbin/aistreamd | strings 2>/dev/null | \
    grep -q PARQUET_RETENTION_DAYS || {
    echo "P-32: aistreamd binary unaware of new conf key"; exit 1; }
# P-33 断言：softdog 同树件
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

# ---- 出厂 tar 卫生断言（命中任一条即中止打版；ENG-01）----
# 通配模式在 17.11 的旧 tar 上干跑过：只命中当时尚未清掉的六处异物，
# 对合法出厂件零误伤（11-24）。
TAR_DENY=(
    '^\./opt/w7s(/|$)'
    '^\./opt/aikdesktop/aik-desktop\.service$'
    '^\./usr/local/bin/[^/]*\.pre-[^/]*$'
    '\.(bak|old|orig|rej|dpkg-old|dpkg-dist|ucf-old|swp|tmp)$'
    '/[^/]*~$'
)
# /home 下允许出现的用户：用允许集，不写死打版机用户名
TAR_HOME_ALLOW=aiuser
tar -tf "$TAR" > "$TAR.lst" || { echo "cannot list factory tar"; exit 1; }
for pat in "${TAR_DENY[@]}"; do
    hit=$(grep -E -e "$pat" "$TAR.lst" | head -5)
    if [ -n "$hit" ]; then
        echo "factory tar hygiene: denied pattern [$pat]"; echo "$hit"; rm -f "$TAR.lst"; exit 1
    fi
done
homes=$(sed -n 's#^\./home/\([^/]*\)\(/.*\)\?$#\1#p' "$TAR.lst" | sort -u)
# grep 选不出任何行时返回 1；set -e 下要显式吞掉，否则「只有允许的
# 那个家目录」这一正常情况会让打版直接退出。
for a in $TAR_HOME_ALLOW; do
    homes=$(printf '%s\n' "$homes" | { grep -v -x -F -e "$a" || true; })
done
if [ -n "$homes" ]; then
    echo "factory tar hygiene: stray home directories: $(echo $homes)"; rm -f "$TAR.lst"; exit 1
fi
rm -f "$TAR.lst"
echo "factory tar hygiene ok"

# 17.11.1 新面断言（P-60 收口）
tar -xOf "$TAR" ./usr/local/bin/aik-console | \
    grep -F -q 'HOME=/root USER=root' || { echo "aik-console not v11"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aik-console | \
    grep -F -q 'gate_perm_fix' || { echo "aik-console not v12"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aik-console | \
    grep -F -q 'env $FB_PRE' || {
    echo "aik-console not v12.1 (non-root fb chain via env)"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/occ | LC_ALL=C grep -aF -q '登录凭据不可读' || {
    echo "occ lacks gate unreadable-credentials screen"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/occ | strings 2>/dev/null | \
    grep -q 'allow-w2' || { echo "occ lacks W2 decision audit"; exit 1; }
echo "17.11.1 anchors ok"

# 17.11 新面断言（P-2 全量+D-3① 双面+P-60）
tar -xOf "$TAR" ./usr/local/bin/aik-console | \
    grep -F -q '/var/ai/work/$t_user' || {
    echo "aik-console not v10 (workdir pre-seed)"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aikctl | \
    grep -q 'policy set' || { echo "aikctl lacks policy"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aikctl | \
    grep -q 'session list' || { echo "aikctl lacks session"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aikctl | \
    grep -q 'quota get' || { echo "aikctl lacks quota"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aikctl | \
    grep -q 'audit tail' || { echo "aikctl lacks audit"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/aikctl | \
    grep -q -- '--from-gate' || { echo "aikctl lacks from-gate"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/occ | strings 2>/dev/null | \
    grep -q '/etc/aikernel/models.d' || { echo "occ lacks models.d chain"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/occ | strings 2>/dev/null | \
    grep -q '/var/ai/work' || { echo "occ lacks workdir const"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/occ | \
    LC_ALL=C grep -aqF '本机未开 root 门' || {
    echo "occ lacks /su=root door"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/occ | \
    LC_ALL=C grep -aqF '用户名或密码不正确' || {
    echo "occ lacks gate ghost"; exit 1; }
tar -xOf "$TAR" ./usr/local/bin/occ | strings 2>/dev/null | \
    grep -qF '%63[^:]:%*[^:]:%u:%u' || {
    echo "occ lacks per-user policy"; exit 1; }
tar -xOf "$TAR" ./etc/aikernel/aistreamd.conf | \
    grep -q '^SENSE_REDACT=soft$' || {
    echo "aistreamd.conf not factory soft"; exit 1; }
tar -xOf "$TAR" ./etc/aikernel/policy.conf | \
    grep -q '\[user:' || { echo "policy.conf lacks [user:] sample"; exit 1; }
tar -xOf "$TAR" ./usr/local/sbin/aik-reset | \
    grep -q 'sense_redact = "soft"' || {
    echo "aik-reset template not soft"; exit 1; }
tar -xOf "$TAR" ./root/.aikernel/model.toml | \
    grep -q 'sense_redact = "soft"' || {
    echo "model.toml lacks exposure-side soft"; exit 1; }
tar -xOf "$TAR" ./root/.aikernel/model.toml | \
    grep -q '^\[api\]$' || { echo "model.toml lacks [api]"; exit 1; }
echo "p2+d3 anchors ok"

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
# O-1/P-47 断言：aik-console v8 面（沿承）+ v9 面
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
echo "ISO_BUILT $VERSION"
