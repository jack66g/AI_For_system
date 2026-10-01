#!/bin/bash
# guest 内诊断脚本(经 ssh stdin 送入)
echo "===IDENT==="; hostname; uname -r; uptime
echo "===SVCS==="; systemctl is-active ollama aikernel-memory ssh
echo "===FAILED-UNITS==="; systemctl --failed --no-legend | head -10
echo "===OLLAMA-STATUS==="; systemctl status ollama --no-pager -l | head -15
echo "===OLLAMA-JOURNAL==="; journalctl -u ollama -b --no-pager | tail -25
echo "===LISTEN==="; ss -tlnp | grep -E "11434|8000|22" || echo "no-listen"
echo "===PROCS==="; ps aux | grep -E "aikernel|ollama|sme|start-sme" | grep -v grep | cut -c1-130
echo "===AIKSHELL==="; ps -o pid,pcpu,etime,rss,args -p $(pgrep -f aikernel-shell | head -1) 2>/dev/null | cut -c1-140
echo "===MEM-SVC-JOURNAL==="; journalctl -u aikernel-memory -b --no-pager | tail -10
echo "===DISK==="; df -h / | tail -1; free -m | sed -n 2p
echo "===ONBOARDED==="; ls -la /etc/aikernel/.onboarded 2>&1
