#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Idempotent SME corpus upsert (W66).

Updates the 167 generated corpus records (8 domain headers + 151 tool
records + 8 combo recipes) in place, identified by metadata rather than id:

  tool          -> metadata.kind=tool, metadata.name=<tool name>
  domain-header -> metadata.kind=domain-header, metadata.sub=<domain>
  combo         -> metadata.kind=combo, metadata.name=<combo name>

Rules:
  * active match  -> PATCH only when text/tags/metadata/importance differ;
  * archived match -> POST /memories/{id}/restore then PATCH;
  * no match       -> POST /memories (append).

Nothing is deleted or archived. Re-running after a successful run reports
patched=0 restored=0 appended=0 (idempotent), which is the W66 acceptance
criterion. No API key is written anywhere; if the service uses one, read it
from SME_API_AUTH_TOKEN in the environment.

Usage:
  python3 sme_seed_upsert.py --seed sme-seed-w51.jsonl \
      [--base http://127.0.0.1:8000] [--dry-run] [--report out.json]
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

FIELDS = ("text", "tags", "metadata", "importance", "source")


def call(base, method, path, body=None, timeout=60):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    token = os.environ.get("SME_API_AUTH_TOKEN", "")
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base + path, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError("%s %s -> HTTP %s: %s"
                           % (method, path, exc.code, detail)) from exc


def identity(meta):
    meta = meta or {}
    kind = meta.get("kind")
    if kind == "tool" and meta.get("name"):
        return ("tool", meta["name"])
    if kind == "domain-header" and meta.get("sub"):
        return ("domain-header", meta["sub"])
    if kind == "combo" and meta.get("name"):
        return ("combo", meta["name"])
    return None


def norm(value):
    """Stable comparison for JSON-shaped fields."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", required=True)
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report", default="")
    args = ap.parse_args()

    records = [json.loads(line) for line in
               open(args.seed, encoding="utf-8") if line.strip()]
    export = call(args.base, "GET", "/export", timeout=120)
    active = {}
    archived = {}
    dup = []
    for m in export.get("memories", []):
        key = identity(m.get("metadata"))
        if key is None:
            continue
        table = archived if m.get("archived") else active
        if key in table:
            dup.append({"key": list(key), "id": m.get("id"),
                        "where": "archived" if m.get("archived") else "active"})
        table[key] = m

    stats = {"records": len(records), "patched": 0, "restored": 0,
             "appended": 0, "unchanged": 0, "duplicate_active": dup,
             "details": []}
    for rec in records:
        key = identity(rec.get("metadata"))
        if key is None:
            raise RuntimeError("seed record without identity: %r"
                               % (rec.get("metadata") or {}))
        cur = active.get(key)
        detail = {"key": list(key), "action": None, "id": None}
        if cur is None:
            old = archived.get(key)
            if old is not None:
                detail["action"] = "restore"
                detail["id"] = old.get("id")
                stats["restored"] += 1
                cur = dict(old)
                cur["archived"] = False
                if not args.dry_run:
                    call(args.base, "POST",
                         "/memories/%s/restore" % old["id"], body={})
            else:
                detail["action"] = "append"
                stats["appended"] += 1
                if not args.dry_run:
                    created = call(args.base, "POST", "/memories", {
                        "text": rec["text"],
                        "metadata": rec.get("metadata") or {},
                        "tags": rec.get("tags") or [],
                        "importance": rec.get("importance", 0.5),
                        "source": rec.get("source", "aikernel-corpus"),
                    })
                    detail["id"] = created.get("id")
                stats["details"].append(detail)
                continue

        changed = {}
        for field in FIELDS:
            want = rec.get(field)
            have = cur.get(field)
            if field == "importance":
                if abs(float(want or 0.0) - float(have or 0.0)) > 1e-9:
                    changed[field] = want
            elif norm(want) != norm(have):
                changed[field] = want
        if changed:
            detail["action"] = "patch"
            detail["id"] = cur.get("id")
            detail["fields"] = sorted(changed)
            stats["patched"] += 1
            if not args.dry_run:
                call(args.base, "PATCH", "/memories/%s" % cur["id"], changed)
        elif detail["action"] is None:
            detail["action"] = "unchanged"
            stats["unchanged"] += 1
        stats["details"].append(detail)

    # Verify the post-state.
    if not args.dry_run:
        after = call(args.base, "GET", "/export", timeout=120)
        counts = {}
        seen = {}
        for m in after.get("memories", []):
            key = identity(m.get("metadata"))
            if key is None or m.get("archived"):
                continue
            counts[key[0]] = counts.get(key[0], 0) + 1
            seen[key] = seen.get(key, 0) + 1
        stats["active_counts"] = counts
        stats["active_dups"] = [list(k) for k, v in seen.items() if v > 1]
        expect = {"tool": 151, "domain-header": 8, "combo": 8}
        stats["active_expected"] = (counts == expect)
    stats["ok"] = (not stats["duplicate_active"] and not stats.get("active_dups")
                   and stats.get("active_expected", True))
    out = json.dumps(stats, ensure_ascii=False, indent=1)
    print(out)
    if args.report:
        open(args.report, "w", encoding="utf-8").write(out + "\n")
    return 0 if stats["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
