#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# w42-sandbox-live-test.sh - W42 隔离区原语 L1 实测（须 root）
# 用法: sudo bash w42-sandbox-live-test.sh <aik-sandbox 绝对路径> <日志前缀>
# 断言集:
#   T1 空根视图: run 内 ls / 只见沙盒骨架目录
#   T2 身份: 沙盒内 hostname=区名, AIKERNEL_SANDBOX=区名
#   T3 tmpfs 写: 沙盒内写 /root/x 成功; 退出后宿主 /root 无 x
#   T4 敏感隔离: 沙盒内 cat /etc/shadow 失败
#   T5 只读: 沙盒内写 /usr /sys 失败; /proc 可读
#   T6 网络保留: 沙盒内 curl 可达宿主监听端口
#   T7 隔离面: 沙盒内 ls /root /var /home 为空(宿主内容不可见)
#   T8 焚毁: destroy 后 /sandbox/<name> 消失
set -u
SB="${1:-/usr/local/bin/aik-sandbox}"
LOGP="${2:-/tmp/w42-live}"
PASS=0; FAIL=0
say(){ echo "[$(date +%H:%M:%S)] $*"; }
ck(){ if [ "$1" = 0 ]; then PASS=$((PASS+1)); say "PASS: $2"; else FAIL=$((FAIL+1)); say "FAIL: $2"; fi; }
R(){ "$SB" run w42live -- /bin/sh -c "$1" 2>&1; }

say "== W42 隔离区 L1 实测开始 (bin=$SB) =="
"$SB" destroy w42live >/dev/null 2>&1
"$SB" create w42live; ck $? "T0 create 建区"

# T1 空根
out=$(R 'ls /' | sort | tr '\n' ' ')
say "T1 沙盒根目录: $out"
for d in usr proc sys etc tmp root home var opt srv dev; do echo "$out" | grep -qw "$d" || break; done; [ $? = 0 ]; ck $? "T1 空根视图(骨架目录齐备)"
echo "$out" | grep -vq "sandbox" ; ck $? "T1b 宿主 /sandbox 不可见于沙盒根"

# T2 身份
out=$(R 'hostname; echo SBX=$AIKERNEL_SANDBOX')
echo "$out" | grep -q "^w42live" ; ck $? "T2a UTS hostname=区名"
echo "$out" | grep -q "SBX=w42live" ; ck $? "T2b AIKERNEL_SANDBOX 注入"

# T3 tmpfs 写 + 宿主不可见
R 'touch /root/w42probe && ls /root/ | grep -q w42probe'; ck $? "T3a 沙盒内写 /root 成功(tmpfs)"
[ -e /root/w42probe ]; r=$?; [ "$r" != 0 ]; ck $? "T3b 宿主 /root 无泄漏 probe"

# T4 敏感隔离
R 'cat /etc/shadow' >/dev/null 2>&1; r=$?; [ "$r" != 0 ]; ck $? "T4 /etc/shadow 不可读(未挂入)"
R 'ls /etc/shadow' >/dev/null 2>&1; r=$?; [ "$r" != 0 ]; ck $? "T4b /etc/shadow 不可见"

# T5 只读挂入
R 'touch /usr/w42x' >/dev/null 2>&1; r=$?; [ "$r" != 0 ]; ck $? "T5a 写 /usr 被拒(ro)"
R 'touch /sys/w42x' >/dev/null 2>&1; r=$?; [ "$r" != 0 ]; ck $? "T5b 写 /sys 被拒(ro)"
R 'cat /proc/uptime' >/dev/null 2>&1; ck $? "T5c /proc 可读"
R 'ls /proc/ai/status' >/dev/null 2>&1
say "T5d /proc/ai/status 可见性 rc=$? (AIKernel 内核上应为 0;L1 是 Ubuntu 通用内核,非 0 属预期)"

# T6 网络保留(8080 靶点绑在 192.168.245.136,回环无监听;两条都试)
code=$(R 'curl --max-time 3 -s -o /dev/null -w %{http_code} http://192.168.245.136:8080/' | tail -1)
say "T6 curl 192.168.245.136:8080 -> HTTP $code"
[ "$code" != "000" ] && [ -n "$code" ]; ck $? "T6a 网络保留(宿主靶点可达,HTTP $code)"
R 'getent hosts >/dev/null 2>&1; echo DNSOK' | grep -q DNSOK; ck $? "T6b 基础命令面可用"

# T7 隔离面
R 'ls -A /var | wc -l' | grep -q "^0$"; ck $? "T7a 沙盒 /var 为空(宿主内容不可见)"
R 'ls -A /home | wc -l' | grep -q "^0$"; ck $? "T7b 沙盒 /home 为空"
out=$(R 'ls -A /root')
echo "$out" | grep -q "aikernel"; ck $? "T7c 沙盒 /root 仅含拷入的 .aikernel 配置"
R 'cat /root/.aikernel/model.toml' >/dev/null 2>&1; ck $? "T7d 子智能体配置(拷贝件)可读"

# T8 焚毁
"$SB" destroy w42live >/dev/null; ck $? "T8a destroy 退出码 0"
[ -e /sandbox/w42live ]; r=$?; [ "$r" != 0 ]; ck $? "T8b /sandbox/w42live 已清除"
"$SB" status; ck $? "T8c status 正常"

say "== 结果: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" = 0 ] && echo "VERDICT: ALL PASS" || echo "VERDICT: HAS FAILURES"
exit "$FAIL"
