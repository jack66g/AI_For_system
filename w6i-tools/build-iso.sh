#!/bin/bash
# AIKernel ISO 构建脚本 (VM 侧执行)
# 用法: build-iso.sh [bzImage路径]  (默认现役内核)
set -e
BZ=${1:-/home/jack66g/linux-6.18.39/arch/x86/boot/bzImage}
ISODIR=/home/jack66g/w6i-isodir
ISO=/home/jack66g/AIKernel-0.1.0-alpha-x86_64.iso

echo "== 内核: $BZ =="
file "$BZ" | head -1

rm -rf "$ISODIR"
mkdir -p "$ISODIR/boot/grub"
cp "$BZ"                     "$ISODIR/boot/bzImage"
cp /home/jack66g/w6i-initrd.img "$ISODIR/boot/initrd.img"
cp /home/jack66g/w6i-rootfs-factory.tar "$ISODIR/rootfs-factory.tar"
cp /home/jack66g/w6i-tools/grub-iso.cfg "$ISODIR/boot/grub/grub.cfg"

grub-mkrescue -o "$ISO" "$ISODIR" 2>&1 | tail -3
ls -la "$ISO"
md5sum "$ISO"
echo ISO_BUILT
