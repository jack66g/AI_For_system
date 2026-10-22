#!/bin/bash
# phaseA 安装期串口驱动 (nohup): 等确认提示 -> 喂 y -> 等安装完成 -> 标记
set -u
LOG=/home/jack66g/w6i-evidence/final-phaseA-install.log
FIFO=/tmp/w6i-final.fifo
EV=/home/jack66g/w6i-evidence
DRV=$EV/final-driver.log
log(){ echo "[$(date +%H:%M:%S)] [phaseA] $*" >> "$DRV"; }
raw(){ tr -d "\r" < "$LOG" 2>/dev/null; }
wait_for(){ local t=0; while [ "$t" -lt "$2" ]; do raw | grep -q "$1" && return 0; sleep 5; t=$((t+5)); done; return 1; }

log "phaseA driver start"
wait_for "确认安装到" 420 || { log "FAIL no-confirm-prompt"; touch $EV/PHASEA-FAIL; exit 1; }
sleep 2
printf "y" > "$FIFO"; printf "\r" > "$FIFO"
log "confirmed y"
wait_for "AIKernel 安装完成" 1500 || { log "FAIL install-not-complete"; touch $EV/PHASEA-FAIL; exit 1; }
log "install complete marker seen"
touch $EV/PHASEA-OK
exit 0
