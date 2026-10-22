#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# aikernel-health.sh - AIKernel 健康自愈检查（W29 扩面版；兼容 W11 输出语义）
# 由 aikernel-health.timer（每 5 分钟）触发的 aikernel-health.service（oneshot）调用。
#
# 检查面（每项可经下方开关独立禁用，1=启用 0=禁用）：
#   CHECK_IN_SERVICE  三服务 systemd active：ollama / aikernel-memory / ssh（W11 原有）
#   CHECK_SME_HTTP    SME REST 探活：http://127.0.0.1:8000/health（3s 超时，须含 "ok"）
#   CHECK_API_HTTP    aikernel-api 探活：http://127.0.0.1:8761（3s 超时，任意 HTTP 应答=活）
#   CHECK_PROC_AI     /proc/ai 九项在位抽查
#   CHECK_MEM         内存水位：MemAvailable < 200MB 记 WARN（不计入 FAIL）
#   CHECK_JRN         journal 错误增量抽查（近 5 分钟 err+ 条数超阈值记 WARN）
#   CHECK_DISK        根分区使用率 <90%（W11 原有）
#
# 处置语义（W29 自恢复闭环）：
#   可自动恢复类失败（服务 inactive/dead、探活不通）→ 自动 start/try-restart，
#   journal 标记 AUTO-HEAL 行；同一检查项连续 3 轮失败 → 升级 FAIL 告警行
#   （journal daemon.err + wall 终端广播）。恢复后 journal 标记 RECOVERED。
#   注意：本脚本不做远程转发（远程告警属 P2-3，另行交付）。
#
# 状态文件：/run/aikernel-health/<检查名>.cnt（tmpfs，整机重启清零）
# 输出：/tmp/aikernel-health-last.log（最新一轮）+ journal（tag=aikernel-health）
TAG=aikernel-health
STATEDIR=/run/aikernel-health
FAIL=0
WARN=0

# ---- 检查项开关（禁用把对应值置 0）----
CHECK_IN_SERVICE=1
CHECK_SME_HTTP=1
CHECK_API_HTTP=1
CHECK_PROC_AI=1
CHECK_MEM=1
CHECK_JRN=1
CHECK_DISK=1

exec >"/tmp/aikernel-health-last.log" 2>&1
echo "[aikernel-health] start $(date '+%F %T')"
mkdir -p "$STATEDIR" 2>/dev/null

# bump_fail <检查名> : 连续失败计数 +1，达到 3 升级告警（此后每轮持续告警）
bump_fail() {
    name="$1"
    cnt=$(( $(cat "$STATEDIR/$name.cnt" 2>/dev/null || echo 0) + 1 ))
    echo "$cnt" > "$STATEDIR/$name.cnt"
    if [ "$cnt" -eq 3 ]; then
        echo "[alert] $name 连续 3 轮失败，升级告警"
        logger -t "$TAG" -p daemon.err "FAIL-ALERT: $name 连续 3 轮失败（连续失败计数=$cnt），请人工介入"
        wall "aikernel-health: $name 连续 3 轮失败，请检查（journalctl -t $TAG）" 2>/dev/null
    elif [ "$cnt" -gt 3 ]; then
        logger -t "$TAG" -p daemon.err "FAIL-ALERT: $name 持续失败（连续失败计数=$cnt）"
    fi
}

# clear_fail <检查名> : 恢复，清零计数；曾达 3 轮则记 RECOVERED
clear_fail() {
    name="$1"
    if [ -f "$STATEDIR/$name.cnt" ]; then
        prev=$(cat "$STATEDIR/$name.cnt" 2>/dev/null || echo 0)
        rm -f "$STATEDIR/$name.cnt"
        [ "$prev" -ge 3 ] && logger -t "$TAG" "RECOVERED: $name 此前连续 ${prev} 轮失败，现已恢复"
    fi
}

note_fail() { FAIL=$((FAIL + 1)); bump_fail "$1"; }
note_warn() { WARN=$((WARN + 1)); }

# ---- 1. 三服务 systemd active（W11 原有三项，处置升级为 start + AUTO-HEAL）----
check_service() {
    svc="$1"
    state="$(systemctl is-active "$svc" 2>/dev/null)"
    if [ "$state" = "active" ]; then
        echo "[ok]   $svc active"
        clear_fail "svc:$svc"
    else
        echo "[fail] $svc state=$state -> AUTO-HEAL: start"
        logger -t "$TAG" -p daemon.warning "AUTO-HEAL: $svc state=$state, systemctl start"
        systemctl start "$svc" 2>&1
        after="$(systemctl is-active "$svc" 2>/dev/null)"
        if [ "$after" = "active" ]; then
            echo "[heal] $svc 已自动拉起"
            logger -t "$TAG" "AUTO-HEAL: $svc 自动拉起成功"
            clear_fail "svc:$svc"
        else
            echo "[fail] $svc 自动拉起后仍 $after"
            logger -t "$TAG" -p daemon.err "AUTO-HEAL: $svc 自动拉起失败（仍 $after）"
            note_fail "svc:$svc"
        fi
    fi
}

# ---- 2. SME REST 探活 ----
check_sme_http() {
    body="$(curl -s -m 3 http://127.0.0.1:8000/health 2>/dev/null)"
    if echo "$body" | grep -q '"ok"'; then
        echo "[ok]   SME REST 127.0.0.1:8000/health ok"
        clear_fail "sme-http"
    else
        echo "[fail] SME REST 127.0.0.1:8000/health 无有效应答 -> AUTO-HEAL: try-restart aikernel-memory"
        logger -t "$TAG" -p daemon.warning "AUTO-HEAL: SME REST 探活失败，try-restart aikernel-memory.service"
        systemctl try-restart aikernel-memory.service 2>&1
        sleep 3
        body2="$(curl -s -m 3 http://127.0.0.1:8000/health 2>/dev/null)"
        if echo "$body2" | grep -q '"ok"'; then
            echo "[heal] SME REST 已自动恢复"
            logger -t "$TAG" "AUTO-HEAL: SME REST 重启后恢复"
            clear_fail "sme-http"
        else
            echo "[fail] SME REST 处置后仍不通"
            note_fail "sme-http"
        fi
    fi
}

# ---- 3. aikernel-api 探活（Bearer 鉴权下任意 HTTP 应答即视为存活）----
check_api_http() {
    # E 波(W30)：探测感知 model.toml [api]（tls=true 走 https 自签 -k）；
    # bind 非回环时 [warn] 提示必须配 TLS+token（不强制改防火墙）
    _api_tls="$(awk '/^\[api\]/{f=1;next} /^\[/{f=0} f && $1=="tls"{print $3;exit}' "$HOME/.aikernel/model.toml" 2>/dev/null)"
    _api_bind="$(awk '/^\[api\]/{f=1;next} /^\[/{f=0} f && $1=="bind"{gsub(/"/,"",$3);print $3;exit}' "$HOME/.aikernel/model.toml" 2>/dev/null)"
    _api_scheme="http"; [ "$_api_tls" = "true" ] && _api_scheme="https"
    code="$(curl -sk -m 3 -o /dev/null -w '%{http_code}' "$_api_scheme://127.0.0.1:8761/" 2>/dev/null)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
        echo "[ok]   aikernel-api 127.0.0.1:8761 应答 $_api_scheme http=$code"
        case "$_api_bind" in
            ""|127.0.0.1|localhost|::1) ;;
            *) echo "[warn] aikernel-api 绑定非回环($_api_bind)：对外暴露必须配 TLS+token（nft 基线默认 drop 仅放行 22）" ;;
        esac
        clear_fail "api-http"
    else
        echo "[fail] aikernel-api 127.0.0.1:8761 无应答 -> AUTO-HEAL: try-restart aikernel-api"
        logger -t "$TAG" -p daemon.warning "AUTO-HEAL: aikernel-api 探活失败，try-restart aikernel-api.service"
        systemctl try-restart aikernel-api.service 2>&1
        sleep 2
        code2="$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8761/ 2>/dev/null)"
        if [ -n "$code2" ] && [ "$code2" != "000" ]; then
            echo "[heal] aikernel-api 已自动恢复"
            logger -t "$TAG" "AUTO-HEAL: aikernel-api 重启后恢复"
            clear_fail "api-http"
        else
            echo "[fail] aikernel-api 处置后仍无应答"
            note_fail "api-http"
        fi
    fi
}

# ---- 4. /proc/ai 九项在位抽查 ----
check_proc_ai() {
    MISS=0
    for f in chains control decisions hitrate latency sched status telemetry vfs; do
        if [ ! -e "/proc/ai/$f" ]; then
            echo "[fail] /proc/ai/$f 缺失"
            MISS=$((MISS + 1))
        fi
    done
    if [ "$MISS" -eq 0 ]; then
        echo "[ok]   /proc/ai 九项在位（9/9）"
        clear_fail "proc-ai"
    else
        # 内核态缺失无法用户态自愈，仅计数告警
        logger -t "$TAG" -p daemon.err "FAIL: /proc/ai 缺失 $MISS 项（内核态，需换核/重启，无用户态自愈手段）"
        note_fail "proc-ai"
    fi
}

# ---- 5. 内存水位（WARN-only）----
check_mem() {
    AVAIL_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null)
    if [ -n "$AVAIL_KB" ]; then
        AVAIL_MB=$((AVAIL_KB / 1024))
        if [ "$AVAIL_MB" -lt 200 ]; then
            echo "[warn] 可用内存 ${AVAIL_MB}MB < 200MB"
            logger -t "$TAG" -p daemon.warning "WARN: MemAvailable ${AVAIL_MB}MB < 200MB"
            note_warn
        else
            echo "[ok]   可用内存 ${AVAIL_MB}MB"
        fi
    else
        echo "[warn] 无法读取 MemAvailable"
        note_warn
    fi
}

# ---- 6. journal 错误增量抽查（WARN-only，轻量）----
check_jrn() {
    N=$(journalctl -q -p err --since "-5 min" --no-pager 2>/dev/null | wc -l)
    if [ -n "$N" ] && [ "$N" -gt 50 ]; then
        echo "[warn] 近 5 分钟 journal err+ 日志 $N 条（>50）"
        logger -t "$TAG" -p daemon.warning "WARN: 近 5 分钟 journal err+ 条数 $N > 50"
        note_warn
    else
        echo "[ok]   近 5 分钟 journal err+ 日志 ${N:-0} 条"
    fi
}

# ---- 7. 根分区（W11 原有）----
check_disk() {
    USE="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
    if [ -n "$USE" ] && [ "$USE" -ge 90 ]; then
        echo "[fail] root partition usage ${USE}% >= 90%"
        logger -t "$TAG" -p daemon.warning "ALERT: root partition usage ${USE}% >= 90%"
        note_fail "disk"
    else
        echo "[ok]   root partition usage ${USE}%"
        clear_fail "disk"
    fi
}

[ "$CHECK_IN_SERVICE" = "1" ] && {
    check_service ollama.service
    check_service aikernel-memory.service
    check_service ssh.service
}
[ "$CHECK_SME_HTTP" = "1" ] && check_sme_http
[ "$CHECK_API_HTTP" = "1" ] && check_api_http
[ "$CHECK_PROC_AI"  = "1" ] && check_proc_ai
[ "$CHECK_MEM"      = "1" ] && check_mem
[ "$CHECK_JRN"      = "1" ] && check_jrn
[ "$CHECK_DISK"     = "1" ] && check_disk

AVAIL_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null)
AVAIL_MB=$(( ${AVAIL_KB:-0} / 1024 ))

if [ "$FAIL" -eq 0 ]; then
    logger -t "$TAG" "health check PASS (checks=7 fail=0 warn=$WARN root_usage=${USE:-NA}% mem_avail=${AVAIL_MB}MB)"
    echo "[aikernel-health] PASS (warn=$WARN)"
    exit 0
else
    logger -t "$TAG" -p daemon.err "health check FAIL ($FAIL item(s) fail, $WARN warn), remediation attempted"
    echo "[aikernel-health] FAIL ($FAIL) (warn=$WARN)"
    exit 0
fi
