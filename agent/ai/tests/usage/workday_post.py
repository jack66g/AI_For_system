#!/usr/bin/env python3
"""Post-process a workday_session.py run: trace-authoritative durations,
corrected memory check, compaction/context statistics, tool-failure classes
and the W66 comparison. Read-only over the evidence directory."""
import json
import re
import statistics
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else \
    Path.home() / "mbedtls-trim-evidence/logs/fix-w70-workday"
W66 = Path.home() / "mbedtls-trim-evidence/logs/fix-w66/usage-full"


def pct(vals, p):
    vals = sorted(v for v in vals if isinstance(v, (int, float)))
    if not vals:
        return None
    k = max(1, int(round(p * len(vals) + 0.4999)))
    return round(vals[min(k, len(vals)) - 1], 1)


def load_trace_turns():
    ends = {}
    for f in (OUT / "traces").glob("*/*.jsonl"):
        phase = f.parent.name
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event") == "turn_end":
                ends[(phase, e.get("turn"))] = e
    return ends


def main():
    res = json.loads((OUT / "results.json").read_text(encoding="utf-8"))
    ends = load_trace_turns()
    rows = []
    records = {r["id"]: r for r in res["turn_records"]}
    for p in res["per_turn"]:
        phase = "phase%s" % p["phase"]
        end = ends.get((phase, p.get("trace_turn")))
        trace_dur = round(end["duration_ms"] / 1000.0, 1) if end else None
        trace_rounds = end.get("rounds") if end else None
        trace_reason = end.get("end_reason") if end else None
        ans = p.get("answer_chars") or 0
        status = p.get("status")
        if trace_reason == "max_rounds":
            status = "max_rounds"
        rec = records.get(p["id"], {})
        p2 = dict(p)
        p2.update({"warn_pct_max": rec.get("warn_pct_max"),
                   "compact_check_pct_max": rec.get("compact_check_pct_max"),
                   "prompt_pct_after": rec.get("prompt_pct_after"),
                   "rounds_stdout": rec.get("rounds_stdout"),
                   "compact_events": rec.get("compact_events", 0)})
        p2.update({"trace_duration_s": trace_dur, "trace_rounds": trace_rounds,
                   "trace_end_reason": trace_reason, "status_corrected": status,
                   "final_answer": status == "ok" and ans > 0})
        rows.append(p2)

    roundtrip = sum(1 for r in rows if r["turn_complete"])
    final = sum(1 for r in rows if r["final_answer"])
    trace_durs = [r["trace_duration_s"] for r in rows if r["trace_duration_s"]]
    measured = [r["duration_s"] for r in rows if r["duration_s"]]
    compact = [r for r in rows if r.get("compact_events")]
    noncompact = [r for r in rows if not r.get("compact_events")]

    # compaction details from the per-turn stdout slices
    comp = []
    for r in compact:
        txt = (OUT / "turns" / (r["id"] + ".out")).read_text(
            encoding="utf-8", errors="replace")
        m = re.search(r"\[compact\] before=(\d+) after=(\d+) attempt=(\S+) "
                      r"target=(\d+) kept=(\d+) summary=(\d+)", txt)
        chk = re.search(r"\[compact\] check attempt=\S+ used=(\d+) "
                        r"budget=(\d+) pct=(\d+)%", txt)
        pre = re.search(r"compact: compressing session '([^']+)' "
                        r"\((\d+) messages, (\d+) bytes\)", txt)
        row = {"id": r["id"], "trace_duration_s": r["trace_duration_s"]}
        if m:
            row.update({"before": int(m.group(1)), "after": int(m.group(2)),
                        "target": int(m.group(4)), "kept": int(m.group(5)),
                        "summary": int(m.group(6))})
        if chk:
            row.update({"check_used": int(chk.group(1)),
                        "check_budget": int(chk.group(2)),
                        "check_pct": int(chk.group(3))})
        if pre:
            row.update({"messages": int(pre.group(2)),
                        "bytes": int(pre.group(3))})
        comp.append(row)

    warn = [r["warn_pct_max"] for r in rows if r.get("warn_pct_max")]
    cpct = [r["compact_check_pct_max"] for r in rows
            if r.get("compact_check_pct_max")]
    ppct = [r["prompt_pct_after"] for r in rows if r.get("prompt_pct_after")]

    tools = res["all_tools"]
    tool_ok = sum(1 for t in tools if t["status"] == "ok")
    tool_den = sum(1 for t in tools if t["status"] == "denied")
    tool_fail = len(tools) - tool_ok - tool_den

    def classify(t):
        s = (t.get("result") or "")
        name = t["tool"]
        if t["status"] == "denied":
            if "E_PARAM_PATH" in s and "/etc/" in s:
                return "expected: /etc path denial (T15)"
            if "E_PARAM_PATH" in s:
                return "expected: other path denial"
            return "policy denial"
        if "E_PARAM_WHOLE_COMMAND" in s:
            return "model contract: whole command string"
        if "E_PARAM_UNKNOWN_KEY" in s:
            return "model contract: unknown arg key"
        if "E_PARAM_SUBCOMMAND" in s:
            return "w69 allowlist: read-only subcommand rejected"
        if "E_PARAM_META_ARG" in s:
            return "model contract: shell metachar"
        if "No such file or directory" in s and "/proc/pressure" in s:
            return "env: /proc/pressure absent (PSI)"
        if "No such file or directory" in s and "/boot/config" in s:
            return "env: no kernel config file"
        if "No such file or directory" in s and "/proc/config.gz" in s:
            return "env: no /proc/config.gz"
        if "unrecognized option" in s:
            return "env/tool: dmesg option unsupported"
        if "missing operand" in s:
            return "model contract: missing operand"
        if "cannot access" in s and ("/sandbox/w70-sb-01" in s or
                                     "/etc/aik-w70-denied" in s):
            return "expected: verify absence"
        if "命令退出码 1" in s:
            return "expected: grep no-match verification"
        return "other/unknown"

    from collections import Counter
    classes = Counter(classify(t) for t in tools if t["status"] != "ok")
    details = {}
    for t in tools:
        if t["status"] != "ok":
            k = classify(t)
            details.setdefault(k, []).append(
                {"turn": t.get("turn"), "tool": t["tool"],
                 "status": t["status"], "args": t["args"][:160],
                 "result": t["result"][:160]})

    # corrected memory check: searches only after the successful delete
    del_idx = next((i for i, t in enumerate(tools)
                    if t["tool"] == "memory_delete" and t["status"] == "ok"), None)
    post = []
    residue = False
    if del_idx is not None:
        for t in tools[del_idx + 1:]:
            if t.get("turn") != "T17":
                continue
            if t["tool"].startswith("memory_search"):
                post.append({"tool": t["tool"], "args": t["args"][:100],
                             "result": t["result"][:200]})
                if "W70-WORKDAY-42" in t["result"].split('"results"', 1)[-1]:
                    residue = True
    mem = {"add_ok": any(t["tool"] == "memory_add" and t["status"] == "ok"
                         for t in tools),
           "delete_ok": del_idx is not None,
           "post_delete_searches": post,
           "marker_in_post_delete_results": residue}

    try:
        w66a = json.loads((W66 / "analysis.json").read_text(encoding="utf-8"))
        w66r = json.loads((W66 / "results.json").read_text(encoding="utf-8"))
        w66 = {"scenarios": len(w66r["scenarios"]),
               "pass": sum(1 for r in w66r["scenarios"]
                           if r["status"] == "pass"),
               "M2": w66a["metrics"]["M2"], "M3": w66a["metrics"]["M3"],
               "M5": w66a["metrics"]["M5"]}
    except Exception as exc:
        w66 = {"error": repr(exc)}

    ctx = {
        "warn_pct_max": max(warn) if warn else None,
        "compact_check_pct_max": max(cpct) if cpct else None,
        "prompt_cumulative_pct_max": max(ppct) if ppct else None,
        "precompact_max_tokens": max((c.get("before") or 0) for c in comp) if comp else None,
        "history_budget_tokens": comp[0].get("check_budget") if comp else None,
        "precompact_max_budget_pct": (
            round(100.0 * max(c.get("before", 0) for c in comp) /
                  comp[0]["check_budget"], 1) if comp and comp[0].get("check_budget")
            else None),
        "precompact_max_ctx_pct": (
            round(100.0 * max(c.get("before", 0) for c in comp) / 32768, 1)
            if comp else None),
    }

    out = {
        "generated_at": __import__("datetime").datetime.now().isoformat(
            timespec="seconds"),
        "turns": {"expected": len(rows), "roundtrip": roundtrip,
                  "final_answer": final},
        "latency": {
            "trace_p50_s": pct(trace_durs, 0.50),
            "trace_p95_s": pct(trace_durs, 0.95),
            "trace_max_s": round(max(trace_durs), 1) if trace_durs else None,
            "measured_p95_s": pct(measured, 0.95),
            "measured_max_s": round(max(measured), 1) if measured else None,
            "compact_median_s": round(statistics.median(
                [r["trace_duration_s"] for r in compact
                 if r["trace_duration_s"]]), 1) if compact else None,
            "noncompact_median_s": round(statistics.median(
                [r["trace_duration_s"] for r in noncompact
                 if r["trace_duration_s"]]), 1) if noncompact else None,
        },
        "compaction": {"turns": len(compact), "ids": [r["id"] for r in compact],
                       "details": comp},
        "context": ctx,
        "tools": {"calls": len(tools), "ok": tool_ok, "denied": tool_den,
                  "fail": tool_fail,
                  "success_rate": round(tool_ok / len(tools), 4) if tools else None,
                  "success_rate_excl_denied": round(
                      tool_ok / (len(tools) - tool_den), 4)
                  if len(tools) - tool_den else None,
                  "failure_classes": dict(classes),
                  "failure_details": details},
        "memory": mem,
        "checks": {"context": res["metrics"]["context_checks"],
                   "control_drift": res["metrics"]["control_drift"],
                   "verify": res["verify"],
                   "trace_complete": res["metrics"]["trace_complete"],
                   "question_match_rate": res["metrics"]["question_match_rate"],
                   "stuck_turns": res["metrics"]["stuck_turns"]},
        "w66": w66,
        "per_turn": [
            {k: r.get(k) for k in ("id", "phase", "trace_duration_s",
                                   "duration_s", "answer_chars", "status_corrected",
                                   "trace_end_reason", "trace_rounds",
                                   "compact_events", "warn_pct_max",
                                   "compact_check_pct_max", "prompt_pct_after",
                                   "check_pass", "check_reasons", "final_answer")}
            for r in rows],
    }
    (OUT / "post_analysis.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    lines = ["# W70 post analysis", "",
             "| id | dur(trace) | dur(measured) | chars | rounds | compact | warn% | compact% | end | final |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["id"], r["trace_duration_s"], r["duration_s"],
            r["answer_chars"], r["trace_rounds"], r["compact_events"],
            r["warn_pct_max"], r["compact_check_pct_max"],
            r["trace_end_reason"], r["final_answer"]))
    lines += ["", "## compaction", "", "```json",
              json.dumps(comp, ensure_ascii=False, indent=1), "```",
              "", "## context", "", "```json",
              json.dumps(ctx, ensure_ascii=False, indent=1), "```",
              "", "## tool failure classes", "", "```json",
              json.dumps(dict(classes), ensure_ascii=False, indent=1), "```",
              "", "## memory", "", "```json",
              json.dumps(mem, ensure_ascii=False, indent=1)[:4000], "```"]
    (OUT / "post_analysis.md").write_text("\n".join(lines) + "\n",
                                           encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=1)[:8000])


if __name__ == "__main__":
    main()
