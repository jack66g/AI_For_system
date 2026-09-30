#!/bin/bash
# AIKernel 最终试装全流程驱动 (nohup 后台, I2)
# 串口锚点驱动: onboarding(含回车试探) -> setup-password -> 选本地模型 -> ai 提示符 -> ask 闭环 -> shell 取证
# 全程留痕: final-driver.log; 终态标记: FINAL-OK / FINAL-FAIL
set -u
LOG=/home/jack66g/w6i-evidence/final-phaseB-boot.log
FIFO=/tmp/w6i-final.fifo
EV=/home/jack66g/w6i-evidence
DRV=$EV/final-driver.log
SEND=/home/jack66g/w6i-tools/w6i-send.sh

log(){ echo "[$(date +%H:%M:%S)] $*" >> "$DRV"; }
send(){ "$SEND" "$FIFO" "$1" 40; log "SENT len=${#1}: ${1:0:40}"; }
_raw(){ tr -d "\r" < "$LOG" 2>/dev/null; }

wait_for(){
  # wait_for <锚点(支持grep正则)> <超时秒> -> 0/1
  local t=0
  while [ "$t" -lt "$2" ]; do
    _raw | grep -q "$1" && return 0
    sleep 5; t=$(( t + 5 ))
  done
  return 1
}

PH="onboard"
log "== FINAL DRIVER start =="
mark_fail(){ touch $EV/FINAL-FAIL; log "FAIL $*"; exit 1; }

# ---- 1. 等 onboarding 横幅 (TCG 引导+ollama 冷启动, 给足 8 分钟) ----
wait_for "初始化引导" 480 || mark_fail "no-onboarding-banner"
log "onboarding banner seen"
sleep 5

# ---- 2. 等 onboarding> 提示符, 期间每 100s 盲喂回车试探(定位前任 e2e5 卡点) ----
ok=0
for i in 1 2 3 4 5 6; do
  _raw | grep -q "onboarding> " && { ok=1; break; }
  log "probe#$i no prompt yet, send ENTER"
  printf "\r" > "$FIFO"
  sleep 100
done
[ "$ok" = 1 ] || mark_fail "no-onboarding-prompt-after-probes"
sleep 3
log "onboarding> prompt OK"

# ---- 3. setup-password 强制设密 ----
send "setup-password"
wait_for "请输入" 120 || mark_fail "no-passwd-prompt1"
sleep 2; send "Aikernel@2026"
wait_for "请再次" 120 || mark_fail "no-passwd-prompt2"
sleep 2; send "Aikernel@2026"
wait_for "密码设置成功" 180 || mark_fail "passwd-not-set"
log "password set OK"

# ---- 4. 第二步: 选本地模型 (菜单 1 = local) ----
wait_for "第二步" 120 || mark_fail "no-model-select"
sleep 3; send "1"
wait_for "Switched to local" 420 || mark_fail "local-provider-not-switched"
log "local provider switched"
wait_for "ai\[" 300 || mark_fail "no-ai-prompt"
log "ai prompt OK"
touch $EV/FINAL-ONBOARD-OK

# ---- 5. (加分) 本地 ask 闭环: 提示符 usage% 0 -> 非零 = 真实推理计量 ----
sleep 3; send "ask 用一句话介绍你自己"
if wait_for "ai\[[^]]*:[1-9][0-9]*%\]" 600; then
  log "ASK_OK"; touch $EV/FINAL-ASK-OK
else
  log "ASK_TIMEOUT(非致命)"; touch $EV/FINAL-ASK-TIMEOUT
fi

# ---- 6. shell 取证 ----
sleep 3; send "shell"
wait_for "root@" 120 || { log "FAIL no-shell-ev"; touch $EV/FINAL-FAIL; exit 1; }
sleep 2
send "echo ===FINAL-EV-START===; uname -a; systemctl is-active ollama aikernel-memory; ls -la /etc/aikernel/.onboarded; cat /etc/aikernel/.onboarded; free -m | head -2; df -h / | tail -1; echo ===FINAL-EV-END==="
sleep 20
send "exit"
wait_for "ai\[" 90 || log "WARN no-ai-back"
log "SHELL_EV_DONE"
touch $EV/FINAL-OK
log "== FINAL DRIVER done OK =="
