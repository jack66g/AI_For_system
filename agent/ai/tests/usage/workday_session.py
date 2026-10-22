#!/usr/bin/env python3
"""W70 workday: one 20-turn interactive long session against the production VM.

Design
  - Phase 1: T01-T10 in one `ai` REPL process, then `exit` (session persisted).
  - Phase 2: T11-T20 after restarting `ai --session w70-workday` (resume/continue).
  - Every turn waits for the next prompt, records wall time, output size,
    `[round N]`, compact markers, context percentage and trace events.
  - Trace files are copied after each phase (the VM keeps only ~20 files).
  - All writes stay under /tmp/aik-w70-workday* or /sandbox/w70-sb-*; the
    one /etc write attempt (T15) is expected to be denied and is verified.

Run only after ~/aikernel-longterm/evidence/w69-round2-done exists (the script
waits by default, 30 s poll, 90 min cap).

Evidence: ~/mbedtls-trim-evidence/logs/fix-w70-workday/
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_usage as ru  # noqa: E402

DEFAULT_TURNS = HERE / "workday_turns.json"
DEFAULT_OUT = Path.home() / "mbedtls-trim-evidence/logs/fix-w70-workday"
MARKER = Path.home() / "aikernel-longterm/evidence/w69-round2-done"
W66_DIR = Path.home() / "mbedtls-trim-evidence/logs/fix-w66/usage-full"
VM = os.environ.get("W70_VM", "root@192.168.245.138")
BASE = "/tmp/aik-w70-workday-harness"
HOME = BASE + "/home"
WORK = "/tmp/aik-w70-workday"
TRACE_DIR = "/var/log/aikernel/trace"
SESSION = "w70-workday"

PROMPT_RE = ru.PROMPT_RE
ANSWER_RE = ru.ANSWER_RE
STOP_RE = re.compile(r"AI:|ask: max rounds limit|ask: model call failed|Error:|ERROR:")
WARN_RE = re.compile(r"context budget (\d+)% used")
COMPACT_PCT_RE = re.compile(
    r"\[compact\] check attempt=\d+/\d+ used=\d+ budget=\d+ pct=(\d+)%")
COMPACT_EVENT_RE = re.compile(
    r"auto-compact|history auto-compacted|compact: compressing session|"
    r"compact: done|history replaced by summary")
ROUND_RE = re.compile(r"\[round (\d+)\]")
PCT_RE = re.compile(r"ai\[[^\]]*:(\d+)%[^\]]*\]>")


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def norm(s):
    return re.sub(r"\s+", " ", s or "").strip()


class Log:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.f = self.path.open("a", encoding="utf-8")

    def __call__(self, msg):
        line = "[%s] %s" % (now(), msg)
        print(line, flush=True)
        self.f.write(line + "\n")
        self.f.flush()


class VmTransport(ru.SshTransport):
    """SSH transport with W70 paths and a clean session reset."""

    def prepare(self):
        cmd = (
            "set -e; mkdir -p %s/.aikernel %s %s; "
            "if [ ! -e /root/.aikernel/model.toml ]; then echo NO_MODEL; exit 3; fi; "
            "ln -sfn /root/.aikernel/model.toml %s/.aikernel/model.toml; "
            "ln -sfn /root/.aikernel/provider.toml %s/.aikernel/provider.toml"
            % (HOME, BASE, WORK, HOME, HOME))
        r = self.run(cmd, 60)
        if r.returncode != 0:
            raise RuntimeError("VM prepare failed: %s" % (r.stderr or r.stdout)[-300:])

    def reset_session(self, session):
        self.run("rm -f %s/.aikernel/sessions/%s.jsonl "
                 "%s/.aikernel/sessions/%s.lock" %
                 (HOME, shlex.quote(session), HOME, shlex.quote(session)), 30)

    def verify_path(self, path, kind, needle=None):
        return super().verify_path(path, kind, needle)

    def file_nonempty(self, path):
        r = self.run("test -s %s && echo yes || echo no" % shlex.quote(path), 30)
        return r.stdout.strip().endswith("yes")

    def cleanup(self):
        self.run("rm -rf %s %s" % (BASE, WORK), 60)
        self.run("rm -rf /sandbox/w70-sb-01", 30)


class Workday:
    def __init__(self, transport, turns, session, evidence, log, phase_timeout_pad=180):
        self.t = transport
        self.turns = turns
        self.session = session
        self.ev = Path(evidence)
        self.log = log
        self.phase_timeout_pad = phase_timeout_pad
        self.trace_meta = []
        self.turn_records = []
        self.phase_runs = []
        self.leaks = {}

    # ---- command -----------------------------------------------------
    def build_cmd(self, phase_turns):
        total = sum(int(x.get("timeout_s", 180)) for x in phase_turns)
        total += self.phase_timeout_pad
        if getattr(self.t, "name", "") == "local":
            home = str(self.t.root / "home")
            cwd = str(self.t.work)
        else:
            home = HOME
            cwd = "/root"
        return ("cd %s && HOME=%s AIKERNEL_ASSUME_YES=1 NO_COLOR=1 "
                "AIKERNEL_LANG=en TERM=xterm timeout --foreground %d "
                "ai --session %s --no-onboarding 2>&1"
                % (shlex.quote(cwd), shlex.quote(home), total,
                   shlex.quote(self.session))), total

    def env(self):
        if getattr(self.t, "name", "") == "local":
            return self.t.env
        return os.environ.copy()

    # ---- phase -------------------------------------------------------
    def run_phase(self, phase_no, phase_turns):
        cmd, phase_timeout = self.build_cmd(phase_turns)
        self.log("phase %d start: %d turns, process cap %ds" %
                 (phase_no, len(phase_turns), phase_timeout))
        before = set(self.t.list_traces())
        sess = ru.PtySession(self.t.argv(cmd, tty=True), self.env(),
                             phase_timeout + 120)
        phase = {"phase": phase_no, "started": now(), "turns": [],
                 "aborted": False, "rc": None, "startup_ok": False,
                 "initial_pct": None, "stderr": []}
        try:
            sess.pos = 0
            st = sess.read_until(PROMPT_RE, timeout=120)
            if st != "match":
                phase["startup_error"] = st
                phase["aborted"] = True
                self.log("phase %d startup failed: %s" % (phase_no, st))
            else:
                phase["startup_ok"] = True
                pcts = PCT_RE.findall(sess.clean)
                phase["initial_pct"] = int(pcts[-1]) if pcts else None
                self.log("phase %d initial context pct=%s" %
                         (phase_no, phase["initial_pct"]))
                last_pct = phase["initial_pct"]
                for turn in phase_turns:
                    rec = self.ask(sess, turn, last_pct)
                    phase["turns"].append(rec["id"])
                    self.turn_records.append(rec)
                    if rec.get("prompt_pct_after") is not None:
                        last_pct = rec["prompt_pct_after"]
                    self.log("%s %s %.1fs out=%d rounds=%s compact=%s ctx=%s%%" % (
                        turn["id"], rec["status"], rec["duration_s"],
                        rec["answer_chars"], rec.get("rounds_stdout"),
                        rec.get("compact_events", 0),
                        rec.get("prompt_pct_after")))
                    if rec["status"] == "stuck":
                        phase["aborted"] = True
                        self.log("%s stuck; aborting phase" % turn["id"])
                        break
        finally:
            if not sess.eof:
                try:
                    sess.pos = len(sess.clean)
                    sess.send(b"exit\r")
                    sess.read_until(idle=2, timeout=25)
                except Exception:
                    pass
            phase["rc"] = sess.finish()
            phase["ended"] = now()
            tail = sess.clean[-2000:]
            phase["tail"] = ru.sanitize(tail)[0]
            self.phase_runs.append(phase)
            self.log("phase %d end rc=%s aborted=%s" %
                     (phase_no, phase["rc"], phase["aborted"]))
        self.copy_traces(before, "phase%d" % phase_no)

    def ask(self, sess, turn, pct_before):
        prompt = turn["prompt"]
        timeout = int(turn.get("timeout_s", 180))
        sess.pos = len(sess.clean)
        start = len(sess.clean)
        t0 = time.time()
        started = now()
        payload = b"\x1b[200~" + prompt.encode("utf-8") + b"\x1b[201~"
        sess.send(payload)
        time.sleep(0.15)
        sess.send(b"\r")
        st = sess.read_until(PROMPT_RE, timeout=timeout, after=STOP_RE)
        dur = round(time.time() - t0, 1)
        out = sess.clean[start:]
        status = "ok"
        if st != "match":
            if PROMPT_RE.search(out):
                status = "no_answer_marker"
            else:
                # try the W65 cancellation path before declaring the turn stuck
                sess.pos = len(sess.clean)
                sess.send(b"\x03")
                st2 = sess.read_until(PROMPT_RE, timeout=25)
                status = "cancelled" if st2 == "match" else "stuck"
                dur = round(time.time() - t0, 1)
                out = sess.clean[start:]
        if status == "ok" and "AI:" not in out:
            status = ("max_rounds" if "max rounds limit" in out
                      else "no_answer_marker")
        rec = self.parse_turn(turn, out, dur, status, pct_before, sess, started)
        scen_dir = self.ev / "turns"
        scen_dir.mkdir(parents=True, exist_ok=True)
        safe, hits = ru.sanitize(out)
        for k, v in hits.items():
            self.leaks[k] = self.leaks.get(k, 0) + v
        (scen_dir / ("%s.out" % turn["id"])).write_text(
            "PROMPT: %s\nSTATUS: %s\nDURATION: %ss\n\n%s\n" %
            (prompt, status, dur, safe), encoding="utf-8")
        return rec

    def parse_turn(self, turn, out, dur, status, pct_before, sess, started):
        clean = out
        answer = self.extract_answer(clean, turn["prompt"])
        pcts = PCT_RE.findall(clean)
        post_pct = int(pcts[-1]) if pcts else None
        warns = [int(x) for x in WARN_RE.findall(clean)]
        cpcts = [int(x) for x in COMPACT_PCT_RE.findall(clean)]
        rounds = [int(x) for x in ROUND_RE.findall(clean)]
        compact_events = len(COMPACT_EVENT_RE.findall(clean))
        checks = self.check_turn(turn, answer)
        safe_excerpt, excerpt_hits = ru.sanitize(answer[:1200])
        for k, v in excerpt_hits.items():
            self.leaks[k] = self.leaks.get(k, 0) + v
        rec = {
            "id": turn["id"],
            "phase": turn.get("phase"),
            "prompt": turn["prompt"],
            "started": started,
            "duration_s": dur,
            "status": status,
            "output_chars": len(clean),
            "answer_chars": len(answer),
            "answer_excerpt": safe_excerpt,
            "answer_sha256_16": hashlib.sha256(
                answer.encode("utf-8", "replace")).hexdigest()[:16],
            "prompt_pct_before": pct_before,
            "prompt_pct_after": post_pct,
            "warn_pct_max": max(warns) if warns else None,
            "compact_check_pct_max": max(cpcts) if cpcts else None,
            "compact_events": compact_events,
            "compacted": compact_events > 0,
            "rounds_stdout": max(rounds) if rounds else 0,
            "checks": checks,
            "check_pass": checks["pass"],
            "check_reasons": checks["reasons"],
        }
        return rec

    def extract_answer(self, out, prompt):
        idx = out.rfind("AI:")
        ans = out[idx + 3:] if idx >= 0 else ""
        ans = re.sub(r"ai\[[^\]]*\]>\s*$", "", ans).strip()
        ans = ans.replace(prompt, "")
        if prompt[:40]:
            ans = ans.replace(prompt[:40], "")
        return ans.strip()

    def check_turn(self, turn, answer):
        exp = turn.get("checks") or {}
        low = answer.lower()
        reasons = []
        if exp.get("expect_any"):
            if not any(x.lower() in low for x in exp["expect_any"]):
                reasons.append("expect_any:missing")
        if exp.get("must_not_contain"):
            hit = [x for x in exp["must_not_contain"] if x.lower() in low]
            if hit:
                reasons.append("must_not_contain:%s" % ",".join(hit))
        if exp.get("min_answer_chars") and len(answer) < int(exp["min_answer_chars"]):
            reasons.append("min_answer_chars:%d<%d" %
                           (len(answer), int(exp["min_answer_chars"])))
        return {"pass": not reasons, "reasons": reasons}

    # ---- traces ------------------------------------------------------
    def copy_traces(self, before, phase_name):
        after = set(self.t.list_traces())
        new = sorted(after - before)
        self.log("%s: new traces %s" % (phase_name, new))
        d = self.ev / "traces" / phase_name
        d.mkdir(parents=True, exist_ok=True)
        for name in new:
            raw = None
            for attempt in range(3):
                try:
                    raw = self.t.read_trace(name)
                    break
                except Exception as exc:
                    if attempt == 2:
                        self.log("trace read failed %s: %r" % (name, exc))
                    time.sleep(0.5)
            if raw is None:
                continue
            sess, sess_id = ru.first_line_session(raw)
            clean, hits = ru.sanitize(raw)
            for k, v in hits.items():
                self.leaks[k] = self.leaks.get(k, 0) + v
            (d / name).write_text(clean, encoding="utf-8")
            self.trace_meta.append({
                "phase": phase_name, "file": name, "session": sess,
                "session_id": sess_id, "session_match": sess == self.session,
                "bytes": len(raw), "redacted": hits,
                "rel": str(Path("traces") / phase_name / name),
            })

    # ---- verification ------------------------------------------------
    def verify(self):
        out = {}
        out["file_morning"] = self.t.verify_path(WORK + "/morning.txt", "present")
        out["file_morning_nonempty"] = getattr(
            self.t, "file_nonempty", lambda p: False)(WORK + "/morning.txt")
        out["file_notes"] = self.t.verify_path(WORK + "/notes.md", "present")
        out["file_notes_nonempty"] = getattr(
            self.t, "file_nonempty", lambda p: False)(WORK + "/notes.md")
        out["sandbox_absent"] = self.t.verify_path("/sandbox/w70-sb-01", "absent")
        out["etc_absent"] = self.t.verify_path("/etc/aik-w70-denied.txt", "absent")
        return out


# ---------------------------------------------------------------------------
# trace analysis
# ---------------------------------------------------------------------------
def read_events(path):
    events, errors = [], []
    for lineno, line in enumerate(Path(path).read_text(
            encoding="utf-8", errors="replace").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append({"line": lineno, "error": str(exc)[:120]})
            continue
        if isinstance(ev, dict):
            events.append(ev)
    return events, errors


def gather_analysis(workday, turns, ev):
    files = {}
    for meta in workday.trace_meta:
        if not meta.get("session_match"):
            continue
        path = Path(ev) / meta["rel"]
        events, errors = read_events(path)
        starts = [e.get("turn") for e in events if e.get("event") == "turn_start"]
        ends = [e.get("turn") for e in events if e.get("event") == "turn_end"]
        seq = [e.get("event_seq") for e in events if isinstance(e.get("event_seq"), int)]
        gaps = sum(1 for a, b in zip(seq, seq[1:]) if b != a + 1)
        files[meta["file"]] = {
            "meta": meta, "events": events, "errors": errors,
            "session_start": sum(1 for e in events if e.get("event") == "session_start"),
            "session_end": sum(1 for e in events if e.get("event") == "session_end"),
            "open_turns": sorted(set(starts) - set(ends)),
            "seq_gaps": gaps,
            "complete": (sum(1 for e in events if e.get("event") == "session_start") >= 1
                         and sum(1 for e in events if e.get("event") == "session_end") >= 1
                         and not (set(starts) - set(ends)) and gaps == 0 and not errors),
        }

    starts = []
    for fname, f in files.items():
        for idx, e in enumerate(f["events"]):
            if e.get("event") == "turn_start":
                starts.append((fname, idx, e))

    def find_start(prompt):
        q = norm(prompt)
        for fname, idx, e in starts:
            eq = norm(e.get("question"))
            if not eq:
                continue
            if eq == q or eq.startswith(q[:60]) or q.startswith(eq[:60]):
                return fname, idx, e
        return None

    per_turn = []
    all_tools = []
    question_mismatch = 0
    for turn in turns:
        rec = next((r for r in workday.turn_records if r["id"] == turn["id"]), {})
        hit = find_start(turn["prompt"])
        row = {
            "id": turn["id"], "phase": turn.get("phase"),
            "duration_s": rec.get("duration_s"), "status": rec.get("status"),
            "answer_chars": rec.get("answer_chars"),
            "rounds_stdout": rec.get("rounds_stdout"),
            "compact_events": rec.get("compact_events"),
            "prompt_pct_after": rec.get("prompt_pct_after"),
            "check_pass": rec.get("check_pass"),
            "check_reasons": rec.get("check_reasons"),
            "trace_found": bool(hit), "trace_file": None,
            "rounds": None, "end_reason": None, "trace_duration_s": None,
            "tools_ok": 0, "tools_fail": 0, "tools_denied": 0,
            "tool_names": [], "route_activations": 0,
            "policy_denials": 0, "turn_complete": False,
        }
        if hit:
            fname, idx, ts = hit
            turn_no = ts.get("turn")
            row["trace_file"] = fname
            row["trace_turn"] = turn_no
            end = None
            for e in files[fname]["events"][idx:]:
                if e.get("event") == "turn_end" and e.get("turn") == turn_no:
                    end = e
                    break
            if end:
                row["turn_complete"] = True
                row["rounds"] = end.get("rounds")
                row["end_reason"] = end.get("end_reason")
                if isinstance(end.get("duration_ms"), (int, float)):
                    row["trace_duration_s"] = round(end["duration_ms"] / 1000.0, 1)
            tools = []
            for e in files[fname]["events"][idx:]:
                if e.get("event") == "turn_start" and e.get("turn") == turn_no + 1:
                    break
                if e.get("event") == "tool_call":
                    tools.append(e)
            for e in tools:
                st = e.get("status")
                if st == "ok":
                    row["tools_ok"] += 1
                elif st == "denied":
                    row["tools_denied"] += 1
                else:
                    row["tools_fail"] += 1
                name = e.get("tool") or ""
                if name and name not in row["tool_names"]:
                    row["tool_names"].append(name)
                all_tools.append({
                    "turn": turn["id"], "tool": name, "status": st,
                    "args": ru.sanitize((e.get("args") or "")[:300])[0],
                    "result": ru.sanitize((e.get("result") or "")[:300])[0],
                })
            row["route_activations"] = sum(
                1 for e in files[fname]["events"][idx:]
                if e.get("event") == "route_activate")
            row["policy_denials"] = sum(
                1 for e in files[fname]["events"][idx:]
                if e.get("event") == "policy_decision"
                and str(e.get("decision", "")).lower() in ("deny", "denied"))
        else:
            question_mismatch += 1
        per_turn.append(row)

    return files, per_turn, all_tools, question_mismatch


def p50_p95(vals):
    vals = sorted(v for v in vals if isinstance(v, (int, float)))
    if not vals:
        return None, None

    def pick(p):
        k = max(1, int(round(p * len(vals) + 0.4999)))
        return round(vals[min(k, len(vals)) - 1], 1)
    return pick(0.50), pick(0.95)


def comparison():
    try:
        a = json.loads((W66_DIR / "analysis.json").read_text(encoding="utf-8"))
        r = json.loads((W66_DIR / "results.json").read_text(encoding="utf-8"))
        m = a["metrics"]
        return {
            "source": str(W66_DIR),
            "scenarios": len(r.get("scenarios", [])),
            "M1": m.get("M1"),
            "M2": m.get("M2"),
            "M3": m.get("M3"),
            "M5": m.get("M5"),
        }
    except Exception as exc:
        return {"error": repr(exc)}


def evaluate_turn20(turn, rec, all_tools):
    names = sorted({t["tool"] for t in all_tools if t.get("tool")})
    low = (rec.get("answer_excerpt") or "").lower()
    hit = [n for n in names if n.lower() in low]
    return {"distinct_tools": names, "mentioned": hit,
            "pass": len(hit) >= 3}


def memory_check(all_tools):
    add_ok = any(t["tool"] == "memory_add" and t["status"] == "ok"
                 for t in all_tools)
    del_idx = next((i for i, t in enumerate(all_tools)
                    if t["tool"] == "memory_delete" and t["status"] == "ok"), None)
    delete_ok = del_idx is not None
    residue = False
    post_searches = 0
    if del_idx is not None:
        for t in all_tools[del_idx + 1:]:
            if t.get("turn") != "T17":
                continue
            if t["tool"].startswith("memory_search"):
                post_searches += 1
                if "W70-WORKDAY-42" in (t.get("result") or ""):
                    # ignore the echo of the query itself
                    body = (t.get("result") or "").split('"results"', 1)[-1]
                    if "W70-WORKDAY-42" in body:
                        residue = True
    return {"add_ok": add_ok, "delete_ok": delete_ok,
            "post_delete_searches": post_searches,
            "marker_in_post_delete_search": residue}


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------
SELFTEST_TURNS = [
    {"id": "S01", "phase": 1, "timeout_s": 60,
     "prompt": "这个系统是什么？", "checks": {"expect_any": ["AIKernel"]}},
    {"id": "S02", "phase": 1, "timeout_s": 60,
     "prompt": "7*6 等于几？只回答数字。", "checks": {"expect_any": ["42"]}},
    {"id": "S03", "phase": 2, "timeout_s": 60,
     "prompt": "2+2 等于几？只回答数字。", "checks": {"expect_any": ["4"]}},
]


def run_self_test(out, log):
    root = Path(tempfile.mkdtemp(prefix="w70-selftest-"))
    bin_dir = root / "bin"
    bin_dir.mkdir()
    mock = bin_dir / "ai"
    mock.write_text(ru.MOCK_AI, encoding="utf-8")
    mock.chmod(0o755)
    transport = ru.LocalTransport(root, root / "traces-out")
    transport.prepare()
    sd = Path(out) / "self-test"
    sd.mkdir(parents=True, exist_ok=True)
    workday = Workday(transport, SELFTEST_TURNS, "w70-selftest", sd, log)
    transport.reset_session = lambda s: None
    workday.run_phase(1, [t for t in SELFTEST_TURNS if t["phase"] == 1])
    workday.run_phase(2, [t for t in SELFTEST_TURNS if t["phase"] == 2])
    files, per_turn, all_tools, qmismatch = gather_analysis(
        workday, SELFTEST_TURNS, sd)
    completed = sum(1 for r in per_turn
                    if r["turn_complete"] and r["status"] in ("ok", "no_answer_marker"))
    checks = {
        "completed_3_of_3": completed == 3,
        "trace_files_complete": bool(files) and all(f["complete"] for f in files.values()),
        "question_match_3_of_3": qmismatch == 0,
        "two_phases": len(workday.phase_runs) == 2,
    }
    ok = all(checks.values())
    payload = {"checks": checks, "completed": completed,
               "files": {k: v["complete"] for k, v in files.items()},
               "per_turn": per_turn, "turns": workday.turn_records}
    (Path(out) / "self-test" / "self-test.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    log("SELF-TEST %s %s" % ("PASS" if ok else "FAIL", json.dumps(checks)))
    shutil.rmtree(root, ignore_errors=True)
    return 0 if ok else 1


# ---------------------------------------------------------------------------
def wait_marker(path, timeout_s, log):
    t0 = time.time()
    while True:
        if Path(path).exists():
            elapsed = round(time.time() - t0, 1)
            content = Path(path).read_text(encoding="utf-8", errors="replace")[:500]
            log("marker present after %.1fs: %s" % (elapsed, content.strip()))
            return True, elapsed, content
        if time.time() - t0 >= timeout_s:
            log("marker wait timeout after %ds" % timeout_s)
            return False, round(time.time() - t0, 1), ""
        log("waiting for %s (%ds/%ds)" %
            (path, int(time.time() - t0), timeout_s))
        time.sleep(30)


def vm_info(t, log):
    info = {}
    cmds = {
        "ai_version": "ai --version 2>&1",
        "uname": "uname -a",
        "ai_md5": "md5sum /usr/local/bin/ai",
        "ctx_len": "grep -E '^ctx_len|^session|^lang' /root/.aikernel/model.toml",
        "date_utc": "date -u +%Y-%m-%dT%H:%M:%SZ",
        "trace_count": "ls -1 %s/*.jsonl 2>/dev/null | wc -l" % TRACE_DIR,
    }
    for key, cmd in cmds.items():
        r = t.run(cmd, 30)
        info[key] = (r.stdout or r.stderr).strip()[:500]
    log("VM: %s | %s" % (info.get("ai_version"), info.get("ai_md5")))
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--turns", default=str(DEFAULT_TURNS))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--session", default=SESSION)
    ap.add_argument("--vm", default=VM)
    ap.add_argument("--marker", default=str(MARKER))
    ap.add_argument("--skip-marker-wait", action="store_true")
    ap.add_argument("--marker-timeout", type=int, default=5400)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--keep-remote", action="store_true")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    log = Log(out / "run.log")
    log("W70 workday start session=%s" % args.session)

    if args.self_test:
        return run_self_test(out, log)

    marker_ok, marker_wait, marker_content = (True, 0.0, "")
    if not args.skip_marker_wait:
        marker_ok, marker_wait, marker_content = wait_marker(
            args.marker, args.marker_timeout, log)
    else:
        marker_ok = Path(args.marker).exists()
        marker_content = Path(args.marker).read_text(encoding="utf-8",
                                                     errors="replace")[:500] \
            if marker_ok else ""
        log("skip marker wait; present=%s" % marker_ok)

    spec = json.loads(Path(args.turns).read_text(encoding="utf-8"))
    turns = spec["turns"]
    if args.limit:
        turns = turns[:args.limit]

    transport = VmTransport(args.vm)
    transport.prepare()
    transport.reset_session(args.session)
    info = vm_info(transport, log)
    workday = Workday(transport, turns, args.session, out, log)
    workday.vm_info = info
    workday.marker = {"present": marker_ok, "wait_s": marker_wait,
                      "content": marker_content}
    ctl_before = ru.parse_control(
        transport.run("cat /proc/ai/control 2>/dev/null || true", 30).stdout)

    phase1 = [t for t in turns if t.get("phase") == 1]
    phase2 = [t for t in turns if t.get("phase") == 2]
    try:
        if phase1:
            workday.run_phase(1, phase1)
        if phase2 and not (args.limit and len(turns) <= len(phase1)):
            workday.run_phase(2, phase2)
    finally:
        pass

    files, per_turn, all_tools, qmismatch = gather_analysis(workday, turns, out)
    verify = workday.verify()
    ctl_after = ru.parse_control(
        transport.run("cat /proc/ai/control 2>/dev/null || true", 30).stdout)
    drift = {k: [ctl_before.get(k), ctl_after.get(k)]
             for k in set(ctl_before) & set(ctl_after)
             if ctl_before[k] != ctl_after[k]}

    roundtrip = sum(1 for r in per_turn
                    if r["turn_complete"] and r["status"] in
                    ("ok", "no_answer_marker", "max_rounds"))
    completed = sum(1 for r in per_turn
                    if r["turn_complete"] and r["status"] == "ok"
                    and (r.get("answer_chars") or 0) > 0)
    stuck = sum(1 for r in workday.turn_records if r["status"] == "stuck")
    durations = [r.get("trace_duration_s") or r.get("duration_s")
                 for r in per_turn
                 if (r.get("trace_duration_s") or r.get("duration_s"))
                 and r["status"] in ("ok", "no_answer_marker", "max_rounds")]
    p50, p95 = p50_p95(durations)
    compact_turns = [r["id"] for r in workday.turn_records if r.get("compacted")]
    ctx_vals = [v for r in workday.turn_records
                for v in (r.get("prompt_pct_after"), r.get("warn_pct_max"),
                          r.get("compact_check_pct_max")) if isinstance(v, int)]
    tool_total = len(all_tools)
    tool_ok = sum(1 for t in all_tools if t["status"] == "ok")
    tool_denied = sum(1 for t in all_tools if t["status"] == "denied")
    tool_fail = tool_total - tool_ok - tool_denied
    trace_complete = all(f["complete"] for f in files.values()) if files else False
    context_checks = {
        r["id"]: {"pass": r["check_pass"], "reasons": r["check_reasons"]}
        for r in per_turn if r["id"] in ("T11", "T19")
    }
    t20 = evaluate_turn20(
        next(t for t in turns if t["id"] == "T20"),
        next((r for r in workday.turn_records if r["id"] == "T20"), {}),
        all_tools) if any(t["id"] == "T20" for t in turns) else None
    mem = memory_check(all_tools)

    metrics = {
        "turns_expected": len(turns),
        "turns_roundtrip": roundtrip,
        "roundtrip_rate": round(roundtrip / len(turns), 4) if turns else None,
        "turns_completed": completed,
        "completion_rate": round(completed / len(turns), 4) if turns else None,
        "stuck_turns": stuck,
        "latency_p50_s": p50,
        "latency_p95_s": p95,
        "latency_max_s": round(max(durations), 1) if durations else None,
        "compact_turns": len(compact_turns),
        "compact_turn_ids": compact_turns,
        "compact_events_total": sum(r.get("compact_events", 0)
                                    for r in workday.turn_records),
        "max_context_pct": max(ctx_vals) if ctx_vals else None,
        "turns_ctx_gt80": sum(1 for r in workday.turn_records
                              if (r.get("prompt_pct_after") or 0) > 80),
        "turns_ctx_gt100": sum(1 for r in workday.turn_records
                               if (r.get("prompt_pct_after") or 0) > 100),
        "tool_calls": tool_total,
        "tool_ok": tool_ok,
        "tool_fail": tool_fail,
        "tool_denied": tool_denied,
        "tool_success_rate": round(tool_ok / tool_total, 4) if tool_total else None,
        "tool_success_rate_excl_denied": (
            round(tool_ok / (tool_total - tool_denied), 4)
            if tool_total - tool_denied else None),
        "trace_files": len(files),
        "trace_complete": trace_complete,
        "trace_complete_rate": round(
            sum(1 for f in files.values() if f["complete"]) / len(files), 4)
            if files else None,
        "trace_question_mismatch": qmismatch,
        "question_match_rate": round(
            (len(per_turn) - qmismatch) / len(per_turn), 4) if per_turn else None,
        "context_checks": context_checks,
        "context_loss": any(not v["pass"] for v in context_checks.values()),
        "control_drift": drift,
        "turn20": t20,
        "memory_check": mem,
    }

    w66 = comparison()
    payload = {
        "meta": {
            "generated_at": now(),
            "session": args.session,
            "vm": info,
            "marker": workday.marker,
            "evidence": str(out),
            "turns_file": str(args.turns),
        },
        "metrics": metrics,
        "verify": verify,
        "turn_records": workday.turn_records,
        "per_turn": per_turn,
        "phase_runs": workday.phase_runs,
        "trace_meta": workday.trace_meta,
        "trace_files": {k: {"complete": v["complete"],
                            "session_start": v["session_start"],
                            "session_end": v["session_end"],
                            "open_turns": v["open_turns"],
                            "seq_gaps": v["seq_gaps"],
                            "errors": v["errors"]}
                        for k, v in files.items()},
        "all_tools": all_tools,
        "leaks": workday.leaks,
        "w66_comparison": w66,
    }
    body, body_hits = ru.sanitize(json.dumps(payload, ensure_ascii=False, indent=1))
    for k, v in body_hits.items():
        workday.leaks[k] = workday.leaks.get(k, 0) + v
    (out / "results.json").write_text(body, encoding="utf-8")
    with (out / "turns.jsonl").open("w", encoding="utf-8") as f:
        for r in workday.turn_records:
            line, hits = ru.sanitize(json.dumps(r, ensure_ascii=False))
            for k, v in hits.items():
                workday.leaks[k] = workday.leaks.get(k, 0) + v
            f.write(line + "\n")

    # human summary
    lines = ["# W70 workday session summary", "",
             "- session: `%s`" % args.session,
             "- VM: %s" % info.get("ai_version"),
             "- marker: present=%s wait=%ss" % (marker_ok, marker_wait),
             "- turns: %d/%d complete, stuck=%d, compact_turns=%d" % (
                 completed, len(turns), stuck, len(compact_turns)),
             "- latency P50/P95/max: %s / %s / %s s" % (
                 p50, p95, metrics["latency_max_s"]),
             "- max context: %s%%; >80%% turns: %d; >100%% turns: %d" % (
                 metrics["max_context_pct"], metrics["turns_ctx_gt80"],
                 metrics["turns_ctx_gt100"]),
             "- tools: %d ok / %d fail / %d denied (%.2f%%, excl denied %.2f%%)" % (
                 tool_ok, tool_fail, tool_denied,
                 100 * (metrics["tool_success_rate"] or 0),
                 100 * (metrics["tool_success_rate_excl_denied"] or 0)),
             "- trace complete: %s (%s files), question mismatch: %d" % (
                 trace_complete, len(files), qmismatch),
             "- context checks: %s" % json.dumps(context_checks, ensure_ascii=False),
             "- control drift: %s" % json.dumps(drift, ensure_ascii=False),
             "", "## Turns", "",
             "| id | phase | status | dur(s) | chars | rounds | compact | ctx% | tools ok/fail/deny | check |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in per_turn:
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s/%s/%s | %s |" % (
            r["id"], r["phase"], r["status"], r["duration_s"],
            r["answer_chars"], r["rounds"], r["compact_events"],
            r["prompt_pct_after"], r["tools_ok"], r["tools_fail"],
            r["tools_denied"], "PASS" if r["check_pass"] else "FAIL"))
    lines += ["", "## W66 usage-full comparison", "",
              "W66: 50 fresh scenarios, 48/50, M2 regular P95 %s s, M3 %s, M5 %s" % (
                  (w66.get("M2") or {}).get("p95_regular_s"),
                  (w66.get("M3") or {}).get("success_rate"),
                  (w66.get("M5") or {}).get("completeness_rate")),
              "Workday: 20 turns in one session, P95 %s s, tool success %s, trace %s" % (
                  p95, metrics["tool_success_rate"], trace_complete),
              "", "## Verification", "",
              "```json", json.dumps(verify, ensure_ascii=False, indent=1), "```"]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(metrics, ensure_ascii=False, indent=1))
    log("workday done: %s/%s turns, stuck=%d, p95=%s" % (
        completed, len(turns), stuck, p95))

    if not args.keep_remote and not args.self_test:
        transport.cleanup()
        log("remote temp dirs cleaned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
