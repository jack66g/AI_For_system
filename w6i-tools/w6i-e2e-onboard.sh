#!/bin/bash
# onboarding 脚本化驱动: 等日志锚点 -> 逐字喂行; 全程留痕
# 用法: nohup w6i-e2e-onboard.sh <phase> &   phase: onboard|ask|shell-ev
set -u
LOG=~/w6i-evidence/e2e7-phaseB-boot.log
FIFO=/tmp/w6i-e2e.fifo
DRV=~/w6i-evidence/onboard-driver.log
log(){ echo "[$(date +%H:%M:%S)] $*" >> "$DRV"; }
send(){ ~/w6i-tools/w6i-send.sh "$FIFO" "$1" 40; log "SENT len=${#1}"; }
wait_for(){
  local t=0
  while [ "$t" -lt "$2" ]; do
    tr -d "\r" < "$LOG" 2>/dev/null | grep -q "$1" && return 0
    sleep 5; t=$(( t + 5 ))
  done
  return 1
}
mark(){ touch ~/w6i-evidence/"$1"; }

PH="${1:-onboard}"
if [ "$PH" = "onboard" ]; then
  log "== onboard start =="
  wait_for "onboarding>" 1800 || { log "FAIL no-onboarding-prompt"; mark ONBOARD-FAIL; exit 1; }
  sleep 3; send "setup-password"
  wait_for "请输入新密码" 60 || { log "FAIL no-passwd-prompt1"; mark ONBOARD-FAIL; exit 1; }
  sleep 2; send "Aikernel@2026"
  wait_for "请再次输入确认" 60 || { log "FAIL no-passwd-prompt2"; mark ONBOARD-FAIL; exit 1; }
  sleep 2; send "Aikernel@2026"
  wait_for "密码设置成功" 90 || { log "FAIL passwd-not-set"; mark ONBOARD-FAIL; exit 1; }
  wait_for "第二步" 60 || { log "FAIL no-model-select"; mark ONBOARD-FAIL; exit 1; }
  sleep 3; send "1"
  wait_for "Switched to local provider" 300 || { log "FAIL local-provider-not-switched"; mark ONBOARD-FAIL; exit 1; }
  wait_for "ai\[" 120 || { log "FAIL no-ai-prompt"; mark ONBOARD-FAIL; exit 1; }
  log "ONBOARD_OK"; mark ONBOARD-OK; exit 0
fi

if [ "$PH" = "ask" ]; then
  log "== ask start =="
  sleep 3; send "ask 用一句话介绍你自己"
  # 成功判定: 提示符 usage% 从 0 变为非 0 (真实推理 token 计量)
  wait_for "ai\[[^]]*:[1-9][0-9]*%\]" 600 || { log "ASK_TIMEOUT(非致命)"; mark ASK-TIMEOUT; exit 2; }
  log "ASK_OK"; mark ASK-OK; exit 0
fi

if [ "$PH" = "shell-ev" ]; then
  log "== shell evidence start =="
  sleep 3; send "shell"
  wait_for "root@" 60 || { log "FAIL no-shell"; mark SHELL-FAIL; exit 1; }
  sleep 2; send "ls -la /etc/aikernel/.onboarded && cat /etc/aikernel/.onboarded && systemctl is-active ollama aikernel-memory && uname -a && free -m | head -2"
  sleep 12
  send "exit"
  wait_for "ai\[" 60 || log "WARN no-ai-back"
  log "SHELL_EV_DONE"; mark SHELL-EV-OK; exit 0
fi
