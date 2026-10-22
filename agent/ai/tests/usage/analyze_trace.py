#!/usr/bin/env python3
"""analyze_trace.py - validate AIKernel trace JSONL and compute M1/M2/M3/M5.

Read-only. Consumes run_usage.py results.json plus the trace copies stored
under <evidence>/traces/<scenario-id>/. Never talks to the VM.

Metrics
  M1 scenario success rate      - from results.json pass/fail
  M2 end-to-end wall time       - P95, overall and regular-only
  M3 tool-call success rate     - trace tool_call status ok / total
  M5 trace completeness/redact  - turn_start/turn_end pairing, session_end,
                                  event_seq monotonicity, JSON parse errors,
                                  and secret-pattern leaks (sk-, Bearer,
                                  api_key JSON, crypt hashes)

Exit code: 0 always unless --strict is given and a target is missed.
"""
import argparse
import datetime
import json
import re
import sys
from pathlib import Path

SK_PAT = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
BEARER_PAT = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")
HASH_PAT = re.compile(r"\$[0-9a-z]\$[^\s\"\\]{20,}")
APIKEY_PAT = re.compile(r"(?i)\"(api[_-]?key|token|secret)\"\s*:\s*\"([^\"]{12,})\"")

SECRET_PATTERNS = [
    ("sk_key", SK_PAT),
    ("bearer", BEARER_PAT),
    ("crypt_hash", HASH_PAT),
    ("api_key_json", APIKEY_PAT),
]


def redact_hits(text):
    """Return (hit_count_by_kind, sanitized_text)."""
    counts = {}
    for kind, pat in SECRET_PATTERNS:
        n = len(pat.findall(text))
        if n:
            counts[kind] = n
            text = pat.sub("[REDACTED]", text)
    return counts, text


def load_results(path):
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(obj, list):
        return {"meta": {}, "scenarios": obj}
    return obj


def read_jsonl(path):
    events = []
    errors = []
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append({"line": lineno, "error": str(e)[:160]})
            continue
        if not isinstance(ev, dict):
            errors.append({"line": lineno, "error": "not an object"})
            continue
        events.append(ev)
    return events, errors, text


def scenario_input_texts(rec):
    """Expected question texts for trace-vs-input comparison."""
    texts = []
    for item in rec.get("inputs_sent") or []:
        if item.get("prefix"):
            texts.append(item["prefix"])
    if rec.get("prompt"):
        texts.append(rec["prompt"][:40])
    rp = rec.get("resume_prompt")
    if rp:
        texts.append(rp[:40])
    return [t for t in texts if t]


def analyze_trace_file(path, expected_prefixes):
    events, parse_errors, raw = read_jsonl(path)
    out = {
        "file": Path(path).name,
        "events": len(events),
        "parse_errors": parse_errors,
        "session_start": 0,
        "session_end": 0,
        "turn_start": 0,
        "turn_end": 0,
        "turn_starts": [],
        "turn_ends": [],
        "open_turns": [],
        "model_request": 0,
        "model_response": 0,
        "tool_call": 0,
        "tool_ok": 0,
        "tool_fail": 0,
        "tool_denied": 0,
        "tool_error": 0,
        "route_activate": 0,
        "policy_deny": 0,
        "policy_allow": 0,
        "question_match": 0,
        "question_mismatch": 0,
        "seq_gap": 0,
        "redaction": {},
        "session": None,
        "session_id": None,
    }
    prev_seq = 0
    for ev in events:
        name = ev.get("event")
        if name == "session_start":
            out["session_start"] += 1
            out["session"] = ev.get("session")
            out["session_id"] = ev.get("session_id")
        elif name == "session_end":
            out["session_end"] += 1
        elif name == "turn_start":
            out["turn_start"] += 1
            turn = ev.get("turn")
            out["turn_starts"].append(turn)
            q = ev.get("question") or ""
            ok = any(q.startswith(p) or p[:20] in q for p in expected_prefixes)
            if ok:
                out["question_match"] += 1
            elif expected_prefixes:
                out["question_mismatch"] += 1
        elif name == "turn_end":
            out["turn_end"] += 1
            out["turn_ends"].append(ev.get("turn"))
        elif name == "model_request":
            out["model_request"] += 1
        elif name == "model_response":
            out["model_response"] += 1
        elif name == "tool_call":
            out["tool_call"] += 1
            status = ev.get("status")
            if status == "ok":
                out["tool_ok"] += 1
            elif status == "denied":
                out["tool_denied"] += 1
            elif status == "error":
                out["tool_error"] += 1
            else:
                out["tool_fail"] += 1
        elif name == "route_activate":
            out["route_activate"] += 1
        elif name == "policy_decision":
            if ev.get("decision") in ("deny", "denied", "reject", "rejected"):
                out["policy_deny"] += 1
            elif ev.get("decision") in ("allow", "allowed"):
                out["policy_allow"] += 1
        seq = ev.get("event_seq")
        if isinstance(seq, int):
            if prev_seq and seq != prev_seq + 1:
                out["seq_gap"] += 1
            prev_seq = seq
    starts = set(out["turn_starts"])
    ends = set(out["turn_ends"])
    out["open_turns"] = sorted(starts - ends)
    out["unmatched_ends"] = sorted(ends - starts)
    counts, _ = redact_hits(raw)
    out["redaction"] = counts
    out["complete"] = (
        not out["parse_errors"]
        and out["session_start"] >= 1
        and out["session_end"] >= 1
        and out["open_turns"] == []
        and out["seq_gap"] == 0
        and not out["redaction"]
    )
    return out


def p95(values):
    vals = sorted(v for v in values if isinstance(v, (int, float)))
    if not vals:
        return None
    k = max(1, int(round(0.95 * len(vals) + 0.4999)))
    k = min(k, len(vals))
    return round(vals[k - 1], 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--results", required=True)
    ap.add_argument("--trace-root", required=True)
    ap.add_argument("--out", default="")
    ap.add_argument("--md", default="")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--min-success", type=float, default=0.95)
    ap.add_argument("--max-p95", type=float, default=60.0)
    ap.add_argument("--min-tool", type=float, default=0.98)
    args = ap.parse_args()

    results = load_results(args.results)
    recs = results.get("scenarios", [])
    trace_root = Path(args.trace_root)

    per_scenario = []
    all_traces = []
    tool_totals = {"tool_call": 0, "tool_ok": 0, "tool_denied": 0,
                   "tool_fail": 0, "tool_error": 0, "route_activate": 0,
                   "policy_deny": 0}
    redaction_total = {}
    question_total = {"match": 0, "mismatch": 0}

    for rec in recs:
        sid = rec.get("id", "?")
        prefixes = scenario_input_texts(rec)
        meta_by_file = {m.get("file"): m for m in rec.get("trace_meta") or []}
        files = rec.get("trace_rel") or []
        rows = []
        for rel in files:
            path = trace_root / rel
            if not path.is_file():
                rows.append({"file": rel, "missing": True, "complete": False})
                continue
            meta = meta_by_file.get(Path(rel).name)
            # Sub-agent traces have their own questions; only compare
            # turn_start.question against the scenario input for the
            # matching session.
            row_prefixes = prefixes if (meta is None or
                                        meta.get("session_match")) else []
            row = analyze_trace_file(path, row_prefixes)
            rows.append(row)
            all_traces.append(row)
            for k in tool_totals:
                tool_totals[k] += row.get(k, 0)
            for kind, n in row["redaction"].items():
                redaction_total[kind] = redaction_total.get(kind, 0) + n
            question_total["match"] += row["question_match"]
            question_total["mismatch"] += row["question_mismatch"]
        complete = bool(rows) and all(r.get("complete") for r in rows)
        per_scenario.append({
            "id": sid,
            "category": rec.get("category"),
            "status": rec.get("status"),
            "duration_s": rec.get("duration_s"),
            "regular": rec.get("regular", True),
            "trace_count": len(rows),
            "traces": rows,
            "trace_complete": complete,
            "questions_match": all(r.get("question_mismatch", 0) == 0 for r in rows),
        })

    executed = [r for r in recs if r.get("status") in ("pass", "fail", "error")]
    passed = sum(1 for r in executed if r.get("status") == "pass")
    m1 = {
        "executed": len(executed),
        "passed": passed,
        "success_rate": round(passed / len(executed), 4) if executed else None,
        "by_category": {},
    }
    for r in executed:
        cat = r.get("category", "?")
        b = m1["by_category"].setdefault(cat, {"total": 0, "passed": 0})
        b["total"] += 1
        b["passed"] += 1 if r.get("status") == "pass" else 0
    for b in m1["by_category"].values():
        b["rate"] = round(b["passed"] / b["total"], 4) if b["total"] else None

    durations = [r.get("duration_s") for r in recs
                 if r.get("status") in ("pass", "fail") and r.get("duration_s")]
    regular = [r.get("duration_s") for r in recs
               if r.get("status") in ("pass", "fail") and r.get("duration_s")
               and r.get("regular", True)]
    m2 = {
        "p95_all_s": p95(durations),
        "p95_regular_s": p95(regular),
        "max_s": round(max(durations), 1) if durations else None,
        "count": len(durations),
    }

    total_calls = tool_totals["tool_call"]
    effective = total_calls - tool_totals["tool_denied"]
    m3 = {
        "tool_calls": total_calls,
        "ok": tool_totals["tool_ok"],
        "fail": tool_totals["tool_fail"],
        "denied": tool_totals["tool_denied"],
        "error": tool_totals["tool_error"],
        "success_rate": round(tool_totals["tool_ok"] / total_calls, 4) if total_calls else None,
        "success_rate_excl_denied": round(tool_totals["tool_ok"] / effective, 4) if effective else None,
        "route_activations": tool_totals["route_activate"],
        "policy_denies": tool_totals["policy_deny"],
    }

    complete_traces = sum(1 for t in all_traces if t.get("complete"))
    m5 = {
        "traces": len(all_traces),
        "complete_traces": complete_traces,
        "completeness_rate": round(complete_traces / len(all_traces), 4) if all_traces else None,
        "open_turn_traces": sum(1 for t in all_traces if t.get("open_turns")),
        "missing_session_end": sum(1 for t in all_traces if t.get("session_end", 0) == 0),
        "parse_error_traces": sum(1 for t in all_traces if t.get("parse_errors")),
        "seq_gap_traces": sum(1 for t in all_traces if t.get("seq_gap")),
        "redaction_leaks": sum(redaction_total.values()),
        "redaction_by_kind": redaction_total,
        "question_match": question_total["match"],
        "question_mismatch": question_total["mismatch"],
        "question_match_rate": (
            round(question_total["match"] /
                  (question_total["match"] + question_total["mismatch"]), 4)
            if (question_total["match"] + question_total["mismatch"]) else None),
    }

    analysis = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "results": str(Path(args.results).resolve()),
        "trace_root": str(trace_root.resolve()),
        "metrics": {"M1": m1, "M2": m2, "M3": m3, "M5": m5},
        "scenarios": per_scenario,
    }

    out = args.out or str(Path(args.results).with_name("analysis.json"))
    Path(out).write_text(json.dumps(analysis, ensure_ascii=False, indent=1),
                         encoding="utf-8")

    md = ["## W62 trace analysis", "",
          "| metric | value |", "|---|---|",
          "| M1 success | %s/%s (%s) |" % (m1["passed"], m1["executed"],
                                           m1["success_rate"]),
          "| M2 P95 all | %ss |" % m2["p95_all_s"],
          "| M2 P95 regular | %ss |" % m2["p95_regular_s"],
          "| M3 tool success | %s/%s (%s), excl denied %s |" % (
              m3["ok"], m3["tool_calls"], m3["success_rate"],
              m3["success_rate_excl_denied"]),
          "| M5 trace complete | %s/%s (%s) |" % (
              m5["complete_traces"], m5["traces"], m5["completeness_rate"]),
          "| M5 redaction leaks | %s |" % m5["redaction_leaks"],
          "| M5 question match | %s/%s |" % (
              m5["question_match"],
              m5["question_match"] + m5["question_mismatch"]),
          ""]
    md.append("| scenario | status | dur(s) | traces | complete | tools ok/deny/fail |")
    md.append("|---|---|---|---|---|---|")
    for s in per_scenario:
        t = s["traces"]
        ok = sum(r.get("tool_ok", 0) for r in t)
        den = sum(r.get("tool_denied", 0) for r in t)
        fail = sum(r.get("tool_fail", 0) + r.get("tool_error", 0) for r in t)
        md.append("| %s | %s | %s | %s | %s | %s/%s/%s |" % (
            s["id"], s["status"], s["duration_s"], s["trace_count"],
            s["trace_complete"], ok, den, fail))
    md_text = "\n".join(md) + "\n"
    if args.md:
        Path(args.md).write_text(md_text, encoding="utf-8")

    print(json.dumps({"M1": m1, "M2": m2, "M3": m3, "M5": m5},
                     ensure_ascii=False, indent=1))
    print("analysis written: %s" % out)

    if args.strict:
        bad = []
        if m1["success_rate"] is not None and m1["success_rate"] < args.min_success:
            bad.append("M1")
        if m2["p95_regular_s"] is not None and m2["p95_regular_s"] > args.max_p95:
            bad.append("M2")
        if m3["success_rate_excl_denied"] is not None and \
                m3["success_rate_excl_denied"] < args.min_tool:
            bad.append("M3")
        if m5["completeness_rate"] is not None and m5["completeness_rate"] < 1.0:
            bad.append("M5-complete")
        if m5["redaction_leaks"]:
            bad.append("M5-redaction")
        if bad:
            print("STRICT FAIL: %s" % ",".join(bad), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
