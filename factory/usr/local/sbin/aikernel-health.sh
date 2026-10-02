#!/bin/sh
# aikernel-health.sh - AIKernel 健康自愈检查（W11）
# 由 aikernel-health.timer（每 5 分钟）触发的 aikernel-health.service（oneshot）调用。
# 检查：ollama / aikernel-memory(SME) / ssh 三服务 active + 根分区使用率 <90%。
# 异常处置：systemctl try-restart 对应服务 + logger 写 journal（tag=aikernel-health）。
TAG=aikernel-health
FAIL=0

exec >"/tmp/aikernel-health-last.log" 2>&1
echo "[aikernel-health] start $(date '+%F %T')"

check_service() {
    svc="$1"
    state="$(systemctl is-active "$svc" 2>/dev/null)"
    if [ "$state" = "active" ]; then
        echo "[ok]   $svc active"
    else
        echo "[fail] $svc state=$state -> try-restart"
        logger -t "$TAG" -p daemon.warning "ALERT: $svc state=$state, try-restart"
        systemctl try-restart "$svc" 2>&1
        FAIL=$((FAIL + 1))
    fi
}

check_service ollama.service
check_service aikernel-memory.service
check_service ssh.service

USE="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
if [ -n "$USE" ] && [ "$USE" -ge 90 ]; then
    echo "[fail] root partition usage ${USE}% >= 90%"
    logger -t "$TAG" -p daemon.warning "ALERT: root partition usage ${USE}% >= 90%"
    FAIL=$((FAIL + 1))
else
    echo "[ok]   root partition usage ${USE}%"
fi

if [ "$FAIL" -eq 0 ]; then
    logger -t "$TAG" "health check PASS (services=3, root_usage=${USE}%)"
    echo "[aikernel-health] PASS"
else
    logger -t "$TAG" -p daemon.err "health check FAIL (${FAIL} item(s)), remediation attempted"
    echo "[aikernel-health] FAIL (${FAIL})"
fi
exit 0
