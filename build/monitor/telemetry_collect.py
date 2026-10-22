#!/usr/bin/env python3
"""Read-only kernel AI telemetry sampler for the soak window.

Runs on L1, polls the production VM's /proc/ai/status every 300s and appends
one JSON line. Kept separate from stability_collect.py so the running soak
collector is never restarted or disturbed.
"""
import datetime
import json
import os
import subprocess
import time
from pathlib import Path

VM = "root@192.168.245.138"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
       "-o", "ConnectTimeout=10", VM]
OUT = Path.home() / "aikernel-longterm/evidence/telemetry.jsonl"
PID = Path.home() / "aikernel-longterm/evidence/telemetry.pid"
INTERVAL = 300

REMOTE = r'''
python3 - <<'PY'
import hashlib
import re
p = "/proc/ai/status"
try:
    text = open(p, encoding="utf-8", errors="replace").read()
except OSError as e:
    print("ERROR=%s" % e)
    raise SystemExit(0)
out = {}
for key in ("runtime_state", "enabled", "telemetry_format"):
    m = re.search(r"(?m)^%s:\s*(.*)$" % key, text)
    if m:
        out[key.upper()] = m.group(1).strip()
m = re.search(r"(?m)^telemetry_drain:\s*(.*)$", text)
if m:
    out["DRAIN"] = m.group(1).strip()
cpus = re.findall(r"(?m)^cpu(\d+):\s*(.*)$", text)
out["CPUS"] = str(len(cpus))
sums = {"emitted": 0, "dropped": 0, "sampled_skip": 0,
        "resyncs": 0, "predrain_dropped": 0, "adapt_episodes": 0}
gap_max = 0
for _, line in cpus:
    for k in sums:
        m = re.search(r"\b%s=(\d+)" % k, line)
        if m:
            sums[k] += int(m.group(1))
    mh = re.search(r"\bhead=(\d+)", line)
    mt = re.search(r"\btail=(\d+)", line)
    if mh and mt:
        gap = int(mh.group(1)) - int(mt.group(1))
        if gap > gap_max:
            gap_max = gap
for k, v in sums.items():
    out[k.upper()] = str(v)
out["GAP_MAX"] = str(gap_max)
out["STATUS_SHA"] = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
for k, v in out.items():
    print("%s=%s" % (k, v))
PY
'''


def sample():
    p = subprocess.run(SSH + [REMOTE], capture_output=True, text=True,
                       timeout=60)
    rec = {"host": "aikernel-vm",
           "wall": datetime.datetime.now().isoformat(timespec="seconds")}
    for line in p.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            rec[k.strip()] = v.strip()
    if p.returncode != 0:
        rec["collector_error"] = (p.stderr or p.stdout)[-400:]
    return rec


def main():
    PID.write_text(str(os.getpid()))
    with OUT.open("a", encoding="utf-8") as f:
        while True:
            try:
                rec = sample()
            except Exception as e:
                rec = {"wall": datetime.datetime.now().isoformat(
                    timespec="seconds"), "collector_error": repr(e)}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
