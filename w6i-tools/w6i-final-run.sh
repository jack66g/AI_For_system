#!/bin/bash
# AIKernel 最终交付主控脚本 (VM 侧执行, I2)
# 用法: w6i-final-run.sh rebuild <bzImage路径>   重打最终 ISO(覆盖同名) 并记录内核版本
#       w6i-final-run.sh phaseA                 全新 qcow2 + CD 安装(喂一次 y)
#       w6i-final-run.sh phaseB                 从盘引导 + 启动 nohup 全流程驱动
set -u
ISO=/home/jack66g/AIKernel-0.1.0-alpha-x86_64.iso
TOOLS=/home/jack66g/w6i-tools
EV=/home/jack66g/w6i-evidence
QDISK=/home/jack66g/w6i-final.qcow2
FIFO=/tmp/w6i-final.fifo

rebuild() {
  local BZ=$1
  [ -f "$BZ" ] || { echo "ERR no bzImage: $BZ"; exit 1; }
  echo "== bzImage 版本行 =="
  file "$BZ" | head -1 | tee -a $EV/final-iso-info.txt
  echo "== 重打 ISO (grub-mkrescue) =="
  "$TOOLS/build-iso.sh" "$BZ" 2>&1 | tee -a $EV/final-iso-info.txt
  echo "== 终态核对 =="
  ls -la "$ISO"; md5sum "$ISO" | tee -a $EV/final-iso-info.txt
}

phaseA() {
  # 纪律: 全新 qcow2, 旧试装盘已删
  [ -f "$QDISK" ] && { echo "ERR $QDISK 已存在, 先清理"; exit 1; }
  qemu-img create -f qcow2 "$QDISK" 20G
  "$TOOLS/run-nested.sh" start install "$ISO" "$QDISK" "$EV/final-phaseA-install.log" "$FIFO"
  nohup bash "$TOOLS/w6i-final-phaseA-driver.sh" > /dev/null 2>&1 &
  echo "PHASEA_STARTED driver_pid=$!"
}

phaseB() {
  "$TOOLS/run-nested.sh" start disk "" "$QDISK" "$EV/final-phaseB-boot.log" "$FIFO"
  echo "PHASEB_STARTED 启动全流程驱动(noHup)..."
  nohup bash "$TOOLS/w6i-final-driver.sh" > /dev/null 2>&1 &
  echo "DRIVER_PID=$!"
}

case "${1:-}" in
  rebuild) shift; rebuild "$@";;
  phaseA)  phaseA;;
  phaseB)  phaseB;;
  *) echo "usage: $0 rebuild <bzImage> | phaseA | phaseB"; exit 1;;
esac
