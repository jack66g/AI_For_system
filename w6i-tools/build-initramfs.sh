#!/bin/bash
# AIKernel 安装器 initramfs 构建脚本 (VM 侧执行)
# busybox-static 骨架 + 动态工具(mkfs.ext4/sfdisk/blkid/grub-install 工具链) + GRUB i386-pc 模块
# v2: 补齐 grub-install/grub-probe/grub-bios-setup/grub-mkrelpath/grub-editenv
#     (安装器 GRUB 步骤改用真 grub-install, 修复手工 dd core.img 的 prefix bug)
# v3(W12): EFI 工具链 —— x86_64-efi GRUB 模块全集 + mkfs.vfat(dosfstools)
#     + efibootmgr(grub-install x86_64-efi 内部依赖), 支持安装器双跑
#     i386-pc/x86_64-efi
set -e
W=/home/jack66g/w6i-initramfs
IMG=/home/jack66g/w6i-initrd.img

rm -rf "$W"
mkdir -p "$W/bin" "$W/sbin" "$W/lib" "$W/usr/lib/grub" "$W/proc" "$W/sys" "$W/dev" "$W/media" "$W/mnt" "$W/tmp" "$W/etc" "$W/run"

# busybox + 全 applet 软链(跳过 busybox 自身, 防 ln 自引用报错)
cp /bin/busybox "$W/bin/busybox"
( cd "$W/bin" && for a in $(./busybox --list); do [ "$a" = "busybox" ] && continue; ln -sf busybox "$a"; done )

# 动态二进制 + 依赖库拍平到 /lib
copy_with_libs() {
  b="$1"
  cp -L "$b" "$W/sbin/$(basename "$b")"
  for lib in $(ldd "$b" | awk '$3 ~ /^\// {print $3}'); do
    cp -L "$lib" "$W/lib/"
  done
  echo "  + $(basename "$b") ($(ldd "$b" | grep -c '^\s*lib') libs)"
}
copy_with_libs /sbin/mkfs.ext4
copy_with_libs /sbin/sfdisk
copy_with_libs /sbin/blkid
copy_with_libs /usr/bin/grub-mkimage
# grub-install 工具链(ELF): 真安装器路径, 替代手工 dd(修复 prefix 解析 bug)
copy_with_libs /usr/sbin/grub-install
copy_with_libs /usr/sbin/grub-probe
copy_with_libs /usr/sbin/grub-bios-setup
copy_with_libs /usr/bin/grub-mkrelpath
copy_with_libs /usr/bin/grub-editenv
# W12 EFI 工具链
copy_with_libs /sbin/mkfs.vfat
copy_with_libs /usr/bin/efibootmgr
cp -L /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$W/lib/"
# glibc ELF 解释器固定路径 /lib64/... — 动态二进制 exec 的硬依赖
mkdir -p "$W/lib64"
ln -sf ../lib/ld-linux-x86-64.so.2 "$W/lib64/ld-linux-x86-64.so.2"

# 防 busybox applet 软链遮蔽真实工具(PATH /bin 先于 /sbin)
# (busybox 自带 mkfs.vfat applet, 必须摘掉让位 dosfstools 真件)
for a in mkfs.ext4 mkfs.vfat sfdisk blkid grub-install grub-probe grub-bios-setup grub-mkimage grub-mkrelpath grub-editenv efibootmgr; do
  rm -f "$W/bin/$a"
done

# GRUB BIOS 模块全集(装到目标盘 /boot/grub/i386-pc)
cp -a /usr/lib/grub/i386-pc "$W/usr/lib/grub/"
# W12: GRUB EFI 模块全集(x86_64-efi 目标的 grub-install 需要)
cp -a /usr/lib/grub/x86_64-efi "$W/usr/lib/grub/"

# init 脚本
cp /home/jack66g/w6i-tools/init "$W/init"
chmod +x "$W/init"

# 预置设备节点(devtmpfs 兜底)
mknod "$W/dev/console" c 5 1 2>/dev/null || true
mknod "$W/dev/null" c 1 3 2>/dev/null || true

rm -f "$IMG"
( cd "$W" && find . | cpio -o -H newc --quiet | gzip -1 ) > "$IMG"
ls -la "$IMG"
echo INITRAMFS_BUILT