#!/bin/bash
# W73/W77d: build alpha.12.0 ISO from the freshly refreshed factory tar (no model blobs).
# Run as root on L1 (e.g. ~/aikernel-longterm/aik-sudo.sh bash ~/w73-build-iso.sh).
set -e
VERSION=0.1.0-alpha.12.0
BZ=/home/jack66g/linux-6.18.39/arch/x86/boot/bzImage
ISODIR=/home/jack66g/w6i-isodir
ISO=/home/jack66g/AIKernel-${VERSION}-x86_64.iso
TAR=/home/jack66g/w7i-rootfs-factory.tar
CFG=/home/jack66g/w6i-tools/grub-iso.cfg
INITRD=/home/jack66g/w6i-initrd.img

echo "== kernel =="
md5sum "$BZ"
[ "$(md5sum "$BZ" | cut -d' ' -f1)" = "a50cafa6285bbef0f0a2011923481d8f" ] || {
    echo "kernel md5 mismatch (expected #59 a50cafa6)"; exit 1; }
file "$BZ" | head -1
grep -q "0.1.0-alpha.12.0" "$CFG" || { echo "grub cfg not at 12.0"; exit 1; }
[ -f "$INITRD" ] || { echo "initrd missing"; exit 1; }
[ "$(md5sum "$INITRD" | cut -d' ' -f1)" = "e826546c15d76ce4fc67dc8823c23d92" ] || {
    echo "initrd md5 mismatch (expected e826546c)"; exit 1; }

echo "== factory tar =="
rm -f "$TAR"
tar -C /home/jack66g/w7i-rootfs -cf "$TAR" .
chmod 644 "$TAR"
sync
md5sum "$TAR"
ls -la "$TAR"
tar -tf "$TAR" | grep -q '^\./opt/aikdesktop/server.py$' || {
    echo "desktop server missing from factory"; exit 1; }
tar -tf "$TAR" | grep -q '^\./etc/systemd/system/aik-desktop.service$' || {
    echo "desktop unit missing from factory"; exit 1; }
tar -xOf "$TAR" ./etc/motd | grep -q '0.1.0-alpha.12.0' || {
    echo "motd not at 12.0"; exit 1; }
tar -xOf "$TAR" ./usr/local/share/aikernel/tools.json | grep -q '"tool_count": 156' || {
    echo "tools not 156 (W77d: 151+5 model_*)"; exit 1; }
# W77d：工厂树不得捆绑任何模型权重 blob（预装 1.5B 已移除）
if tar -tf "$TAR" | grep -q 'var/lib/ollama/models/.*blob'; then
    echo "factory tar contains ollama model blobs (must be empty)"; exit 1; fi
tar -xOf "$TAR" ./usr/local/share/aikernel/model-catalog.json | grep -q 'spark-x2.5:4b' || {
    echo "model-catalog.json missing from factory"; exit 1; }
[ "$(tar -xOf "$TAR" ./usr/local/bin/aikernel-shell | md5sum | cut -d' ' -f1)" \
    = 784cc0f014409cfdd8186f95c557dcd0 ] || {
    echo "shell binary md5 mismatch"; exit 1; }
[ "$(tar -xOf "$TAR" ./usr/local/sbin/aikernel-api | md5sum | cut -d' ' -f1)" \
    = e007a7d9d9e8cd9e81ec977d92bd9056 ] || {
    echo "api md5 mismatch"; exit 1; }

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
grub-mkrescue -o "$ISO" "$ISODIR" 2>&1 | tail -5
ls -la "$ISO"
md5sum "$ISO"
stat -c%s "$ISO"
echo ISO_BUILT
