#!/usr/bin/env python3
"""Summarize the LTP-1 soak window from stability.jsonl + telemetry.jsonl."""
import json
import os
import sys

BASE = os.path.expanduser("~/aikernel-longterm/evidence")
STAB = os.path.join(BASE, "stability.jsonl")
TEL = os.path.join(BASE, "telemetry.jsonl")
start = sys.argv[1] if len(sys.argv) > 1 else "1970-01-01T00:00:00"


def rows(path):
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if (r.get("wall") or "") >= start:
            out.append(r)
    return out


stab = rows(STAB)
if not stab:
    print("no stability samples after", start)
    raise SystemExit(1)

reboots = 0
failed = 0
dmesg = 0
rss = []
down = {}
prev = None
for r in stab:
    try:
        up = int(r.get("UP") or 0)
    except ValueError:
        up = 0
    if prev is not None and up < prev:
        reboots += 1
    prev = up
    if r.get("FAILED") not in (None, "0"):
        failed += 1
    if int(r.get("DMESG") or 0) > 0:
        dmesg += 1
    try:
        rss.append(int(r.get("RSS") or 0))
    except ValueError:
        pass
    for item in (r.get("SERV") or "").split(","):
        if "=" in item:
            name, state = item.split("=", 1)
            if state and state != "active":
                down[name] = down.get(name, 0) + 1

print("# Soak summary")
print("- window: %s .. %s" % (stab[0].get("wall"), stab[-1].get("wall")))
print("- stability samples: %d (expected 5 min cadence)" % len(stab))
print("- uptime resets (reboots): %d" % reboots)
print("- samples with failed units: %d" % failed)
print("- samples with dmesg WARN/BUG/OOM: %d" % dmesg)
print("- service down samples: %s" % (down or "none"))
print("- RSS KB min/max: %s / %s" % (min(rss) if rss else "-",
                                     max(rss) if rss else "-"))

tel = rows(TEL)
tel_ok = True
if tel:
    def worst(key):
        vals = []
        for r in tel:
            try:
                vals.append(int(r.get(key) or 0))
            except ValueError:
                pass
        return max(vals) if vals else None

    dropped = worst("DROPPED")
    resyncs = worst("RESYNCS")
    predrain = worst("PREDRAIN_DROPPED")
    tel_ok = all(v in (None, 0) for v in (dropped, resyncs, predrain))
    drains = sorted({r.get("DRAIN") for r in tel if r.get("DRAIN")})
    print("- telemetry samples: %d (%s .. %s)" %
          (len(tel), tel[0].get("wall"), tel[-1].get("wall")))
    print("- telemetry max dropped/resyncs/predrain_dropped: %s / %s / %s" %
          (dropped, resyncs, predrain))
    print("- telemetry drain modes: %s" % (drains or "-"))
else:
    print("- telemetry samples: 0 (telemetry_collect.py not running)")

verdict = (reboots == 0 and failed == 0 and dmesg == 0 and not down and tel_ok)
print("- verdict: %s" % ("PASS" if verdict else "REVIEW"))
