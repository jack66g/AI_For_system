#!/bin/bash
# 嵌套 qemu 试装驱动脚本 (VM 侧执行)
# 用法:
#   run-nested.sh start <install|disk> <iso> <disk.qcow2> <log> <fifo>  启动
#   run-nested.sh stop                                                  停止
# 串口输入: echo y > <fifo>   串口日志: <log>
set -u
CMD=${1:-start}

case "$CMD" in
start)
  PHASE=$2; ISO=$3; DISK=$4; LOG=$5; FIFO=$6
  # 清理旧实例
  [ -f /tmp/nq-qemu.pid ] && kill "$(cat /tmp/nq-qemu.pid)" 2>/dev/null
  [ -f /tmp/nq-holder.pid ] && kill "$(cat /tmp/nq-holder.pid)" 2>/dev/null
  sleep 1
  rm -f "$FIFO"; mkfifo "$FIFO"
  # holder 保持 FIFO 写端常开(防 qemu stdin EOF 退出)
  nohup bash -c "sleep infinity > '$FIFO'" >/dev/null 2>&1 &
  echo $! > /tmp/nq-holder.pid
  sleep 0.5
  if [ "$PHASE" = install ]; then
    BOOTARG="-boot d -cdrom $ISO"
  else
    BOOTARG=""
  fi
  nohup qemu-system-x86_64 -m 4096 -cpu max -smp 2 -nographic \
    $BOOTARG -drive file="$DISK",format=qcow2,if=virtio \
    < "$FIFO" > "$LOG" 2>&1 &
  echo $! > /tmp/nq-qemu.pid
  echo "NESTED_STARTED phase=$PHASE pid=$(cat /tmp/nq-qemu.pid)"
  ;;
stop)
  [ -f /tmp/nq-qemu.pid ] && kill "$(cat /tmp/nq-qemu.pid)" 2>/dev/null
  [ -f /tmp/nq-holder.pid ] && kill "$(cat /tmp/nq-holder.pid)" 2>/dev/null
  rm -f /tmp/nq-qemu.pid /tmp/nq-holder.pid
  echo NESTED_STOPPED
  ;;
*) echo "usage: run-nested.sh start|stop ..."; exit 1;;
esac
