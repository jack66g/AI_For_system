#!/bin/bash
# AIKernel 出厂 rootfs 导出脚本（I 线）
# 前置：/mnt/aik-ro 已以 ro,noload 挂载原始 raw
# 产物：~/w6i-rootfs/（导出树，已出厂化）+ ~/w6i-rootfs-factory.tar
set -u
exec > /home/jack66g/w6i-tools/export.log 2>&1
set -x

SRC=/mnt/aik-ro
DST=/home/jack66g/w6i-rootfs
TAR=/home/jack66g/w6i-rootfs-factory.tar

rm -rf "$DST"
mkdir -p "$DST"

# ---- 1. rsync 导出（排除运行时垃圾，原件零写入）----
sudo rsync -aHAX --numeric-ids \
  --exclude='/swapfile' \
  --exclude='/var/log/*' \
  --exclude='/root/.aikernel/sessions/*' \
  --exclude='/tmp/*' \
  --exclude='/var/tmp/*' \
  --exclude='/run/*' \
  "$SRC/" "$DST/"
echo "RSYNC_RC=$?"

# ---- 2. 出厂化处理 ----
# 2.1 删 onboarding 标志（新机首启必须触发 onboarding）
sudo rm -f "$DST/etc/aikernel/.onboarded"
# 2.2 清空 machine-id（留空文件，systemd 首启重生成）
sudo sh -c ": > '$DST/etc/machine-id'"
if [ -f "$DST/var/lib/dbus/machine-id" ]; then
  sudo sh -c ": > '$DST/var/lib/dbus/machine-id'"
fi
# 2.3 删 SSH 主机密钥（新机首启自动重生成）
sudo sh -c "rm -f '$DST'/etc/ssh/ssh_host_*"
# 2.4 清 bash 历史
sudo sh -c ": > '$DST/root/.bash_history'"
# 2.5 清随机种子（避免镜像间重复）
if [ -f "$DST/var/lib/systemd/random-seed" ]; then
  sudo sh -c ": > '$DST/var/lib/systemd/random-seed'"
fi
# 2.6 清空日志目录残留（rsync 排除了内容，确认无隐藏文件）
sudo find "$DST/var/log" -mindepth 1 -delete
sudo find "$DST/tmp" "$DST/var/tmp" -mindepth 1 -delete 2>/dev/null
sudo find "$DST/run" -mindepth 1 -delete 2>/dev/null

echo "FACTORY_DONE"

# ---- 3. 重打 tar ----
rm -f "$TAR"
sudo tar -C "$DST" -cf "$TAR" .
sync
ls -la "$TAR"
du -sh "$DST"
echo "EXPORT_DONE"
