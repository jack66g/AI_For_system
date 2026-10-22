#!/usr/bin/env python3
"""Read-only stability collector: polls the production VM every 300s and
appends one JSON line per sample. Runs on L1, never writes to the VM."""
import datetime
import json
import subprocess
import time
from pathlib import Path

VM = "root@192.168.245.138"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
       "-o", "ConnectTimeout=10", VM]
OUT = Path.home() / "aikernel-longterm/evidence/stability.jsonl"
PID = Path.home() / "aikernel-longterm/evidence/stability.pid"
INTERVAL = 300

REMOTE = r'''
echo "TS=$(date +%s)"
echo "UP=$(cut -d. -f1 /proc/uptime)"
echo "LOAD=$(cat /proc/loadavg)"
echo "MEM=$(free -m | awk 'NR==2{print $2","$3","$7}')"
echo "SWAP=$(free -m | awk 'NR==3{print $2","$3}')"
echo "DISK=$(df -Pm / | awk 'NR==2{print $2","$3","$4","$5}')"
echo "FAILED=$(systemctl --failed --no-legend --no-pager | wc -l)"
echo "SERV=$(for s in aikernel-api aikernel-memory ollama ssh; do printf '%s=%s,' $s $(systemctl is-active $s); done)"
echo "RSS=$(ps -eo rss,comm | awk '$2=="ai"||$2=="aikernel-shell"||$2=="aik-sandbox"{s+=$1} END{print s+0}')"
echo "NPROC=$(pgrep -c -f '/usr/local/bin/ai|aik-sandbox' || true)"
echo "TRACESZ=$(du -sk /var/log/aikernel/trace 2>/dev/null | awk '{print $1}')"
echo "DMESG=$(dmesg | grep -Eic 'BUG:|WARNING:|Oops|Out of memory|oom-kill|general protection' || true)"
echo "JERR=$(journalctl -k -p err --since '-6 min' --no-pager 2>/dev/null | wc -l)"
echo "LISTEN=$(ss -ltn 2>/dev/null | tail -n +2 | wc -l)"
echo "STATS=$(tr '\n' '|' < /proc/ai/stats 2>/dev/null | head -c 600)"
'''


def sample():
    p = subprocess.run(SSH + [REMOTE], capture_output=True, text=True, timeout=120)
    rec = {"host": "aikernel-vm", "wall": datetime.datetime.now().isoformat(timespec="seconds")}
    for line in p.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            rec[k.strip()] = v.strip()
    if p.returncode != 0:
        rec["collector_error"] = (p.stderr or p.stdout)[-400:]
    return rec


def main():
    PID.write_text(str(__import__("os").getpid()))
    with OUT.open("a", encoding="utf-8") as f:
        while True:
            try:
                rec = sample()
            except Exception as e:  # keep the collector alive
                rec = {"wall": datetime.datetime.now().isoformat(timespec="seconds"),
                       "collector_error": repr(e)}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
