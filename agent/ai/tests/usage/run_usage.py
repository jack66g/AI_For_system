#!/usr/bin/env python3
"""run_usage.py - drive the W62 human-style usage scenario library.

Runs on L1 and drives the production VM over SSH (or runs locally against a
mock `ai` for --self-test). Read-only on the VM except:
  - /tmp/aik-usage-w62/**  (harness HOME, sessions, scenario scratch)
  - /sandbox/w62-*         (sandbox scenarios; destroyed by the scenarios)
  - the product's own trace log under /var/log/aikernel/trace (written by ai)
  - SME memory: mem-01 writes one clearly tagged test fact and asks the agent
    to delete it.

Secrets never reach evidence: every output/trace copy is scanned for sk-*,
Bearer, api_key JSON and crypt hashes, then redacted before writing.

See usage/README.md for the scenario schema and safety rules.
"""
import argparse
import codecs
import datetime
import fcntl
import hashlib
import json
import os
import pty
import re
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_SCENARIOS = HERE / "scenarios.json"
DEFAULT_OUT = Path.home() / "mbedtls-trim-evidence/logs/fix-w62"
SMOKE_RESULTS = Path.home() / "aikernel-longterm/evidence/usage-smoke/results.json"
DEFAULT_VM = os.environ.get("W62_VM", "root@192.168.245.138")
REMOTE_BASE = "/tmp/aik-usage-w62"
REMOTE_HOME = REMOTE_BASE + "/home"
OFFLINE_HOME = REMOTE_BASE + "/home-offline"
REMOTE_TRACE_DIR = "/var/log/aikernel/trace"

SSH_OPTS = [
    "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
]

ANSI_RE = re.compile(
    r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-_])")
PROMPT_RE = re.compile(r"ai\[[^\]\n]*\]>\s")
# The final answer is printed as "AI: ..." (NO_COLOR) but may share the line
# with a \r-redrawn spinner, so do not require a preceding newline. Waiting
# for it prevents matching the redraw of the input line that linenoise emits
# while the paste is being inserted.
ANSWER_RE = re.compile(r"AI:")

SECRET_PATTERNS = [
    ("sk_key", re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("crypt_hash", re.compile(r"\$[0-9a-z]\$[^\s\"\\]{20,}")),
    ("api_key_json", re.compile(r"(?i)\"(api[_-]?key|token|secret)\"\s*:\s*\"([^\"]{12,})\"")),
]

OFFLINE_MODEL_TOML = """# W62 offline mock provider - contains no real credentials
[default]
model = "cloud"

[ui]
ctx_len = 4096
max_tokens = 512
stream = true
color = false
session = "w62-offline"
lang = "en"

[models.cloud]
provider_type = "openai_compatible"
model_name = "offline-mock"
base_url = "http://127.0.0.1:9/v1"
api_key = "offline-mock-not-a-secret"
max_tokens = 512
"""


# --------------------------------------------------------------------------
# text helpers
# --------------------------------------------------------------------------
def clean_ansi(text):
    text = ANSI_RE.sub("", text)
    return text.replace("\r\n", "\n").replace("\r", "")


def sanitize(text):
    hits = {}
    for kind, pat in SECRET_PATTERNS:
        n = len(pat.findall(text))
        if n:
            hits[kind] = hits.get(kind, 0) + n
            text = pat.sub("[REDACTED:%s]" % kind, text)
    return text, hits


def shq(s):
    return shlex.quote(s)


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------
# transports
# --------------------------------------------------------------------------
class SshTransport:
    name = "ssh"

    def __init__(self, vm):
        self.vm = vm

    def argv(self, remote_cmd, tty=False):
        return SSH_OPTS + (["-tt"] if tty else []) + [self.vm, remote_cmd]

    def run(self, remote_cmd, timeout):
        return subprocess.run(self.argv(remote_cmd), capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=timeout)

    def prepare(self):
        cmd = (
            "set -e; mkdir -p %s/.aikernel %s %s/.aikernel; "
            "if [ ! -e /root/.aikernel/model.toml ]; then echo NO_MODEL_TOML; exit 3; fi; "
            "ln -sfn /root/.aikernel/model.toml %s/.aikernel/model.toml; "
            "ln -sfn /root/.aikernel/provider.toml %s/.aikernel/provider.toml; "
            "cat > %s/.aikernel/model.toml <<'W62EOF'\n%s\nW62EOF\n"
            % (REMOTE_HOME, REMOTE_BASE, OFFLINE_HOME, REMOTE_HOME, REMOTE_HOME,
               OFFLINE_HOME, OFFLINE_MODEL_TOML)
        )
        r = self.run(cmd, 60)
        if r.returncode != 0:
            raise RuntimeError("VM prepare failed rc=%s: %s" %
                               (r.returncode, (r.stderr or r.stdout)[-400:]))

    def list_traces(self):
        r = self.run("ls -1 %s/*.jsonl 2>/dev/null || true" % REMOTE_TRACE_DIR, 30)
        return sorted(os.path.basename(x.strip()) for x in r.stdout.splitlines()
                      if x.strip().endswith(".jsonl"))

    def read_trace(self, name):
        r = self.run("cat %s/%s" % (REMOTE_TRACE_DIR, name), 60)
        if r.returncode != 0:
            raise IOError("cat trace failed: %s" % (r.stderr or "")[-200:])
        return r.stdout

    def read_control(self):
        r = self.run("cat /proc/ai/control 2>/dev/null || true", 30)
        return parse_control(r.stdout)

    def verify_path(self, path, kind, needle=None):
        p = shq(path)
        if kind == "present":
            cmd = "test -e %s && echo yes || echo no" % p
        elif kind == "absent":
            cmd = "test -e %s && echo no || echo yes" % p
        else:
            cmd = "grep -F -q -- %s %s && echo yes || echo no" % (
                shq(needle), p)
        r = self.run(cmd, 30)
        return r.stdout.strip().endswith("yes")

    def cleanup(self):
        self.run("rm -rf %s" % REMOTE_BASE, 60)


class LocalTransport:
    """Used by --self-test: runs a mock ai on L1, never touches the VM."""
    name = "local"

    def __init__(self, root, trace_dir):
        self.root = Path(root)
        self.trace_dir = Path(trace_dir)
        self.work = self.root / "work"
        self.work.mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ)
        self.env.update({
            "PATH": str(self.root / "bin") + ":" + os.environ.get("PATH", ""),
            "MOCK_TRACE_DIR": str(self.trace_dir),
            "MOCK_STATE_DIR": str(self.root / "state"),
            "NO_COLOR": "1",
            "TERM": "xterm",
        })
        (self.root / "state").mkdir(exist_ok=True)
        self.trace_dir.mkdir(parents=True, exist_ok=True)

    def argv(self, remote_cmd, tty=False):
        return ["bash", "-lc", remote_cmd]

    def run(self, remote_cmd, timeout):
        return subprocess.run(self.argv(remote_cmd), capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, env=self.env)

    def prepare(self):
        for home in (self.root / "home", self.root / "home-offline"):
            (home / ".aikernel").mkdir(parents=True, exist_ok=True)
        write_text(self.root / "home-offline/.aikernel/model.toml",
                   OFFLINE_MODEL_TOML)

    def list_traces(self):
        if not self.trace_dir.is_dir():
            return []
        return sorted(p.name for p in self.trace_dir.glob("*.jsonl"))

    def read_trace(self, name):
        return (self.trace_dir / name).read_text(encoding="utf-8", errors="replace")

    def read_control(self):
        return {}

    def verify_path(self, path, kind, needle=None):
        p = Path(path)
        if kind == "present":
            return p.exists()
        if kind == "absent":
            return not p.exists()
        try:
            return needle in p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False

    def cleanup(self):
        pass


def parse_control(text):
    vals = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+domain=\S+\s+\[[^\]]*\]\s+min=\S+\s+max=\S+\s+current=(-?\d+)", line)
        if m:
            vals[m.group(1)] = int(m.group(2))
    return vals


# --------------------------------------------------------------------------
# PTY interactive driver
# --------------------------------------------------------------------------
class PtySession:
    def __init__(self, argv, env, overall_timeout):
        self.master, slave = pty.openpty()
        # Emulate a real terminal window: 120x40. Without this, ws_col=0
        # makes linenoise send ESC[6n and block waiting for a cursor
        # position report that a dumb PTY never sends.
        fcntl.ioctl(self.master, termios.TIOCSWINSZ,
                    struct.pack("HHHH", 40, 120, 0, 0))
        self.proc = subprocess.Popen(
            argv, stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=os.setsid, close_fds=True, env=env)
        os.close(slave)
        self.dec = codecs.getincrementaldecoder("utf-8")("replace")
        self.raw = bytearray()
        self.clean = ""
        self.pos = 0
        self.eof = False
        self.cpr_seen = 0
        self.deadline = time.time() + overall_timeout
        os.set_blocking(self.master, False)

    def answer_cpr(self):
        """Answer ESC[6n (cursor position report) like a real terminal."""
        n = self.raw.count(b"\x1b[6n")
        while self.cpr_seen < n:
            self.cpr_seen += 1
            try:
                os.write(self.master, b"\x1b[1;1R")
            except OSError:
                self.eof = True

    def feed(self):
        got = False
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except BlockingIOError:
                break
            except OSError:
                self.eof = True
                break
            if not chunk:
                self.eof = True
                break
            got = True
            self.raw += chunk
            self.clean += clean_ansi(self.dec.decode(chunk))
        if got:
            self.answer_cpr()
        return got

    def read_until(self, regex=None, timeout=60, idle=None, after=None):
        start = time.time()
        last_data = start
        seen_after = after is None
        after_pos = self.pos
        while time.time() < self.deadline:
            if not seen_after:
                m = after.search(self.clean, self.pos)
                if m:
                    seen_after = True
                    after_pos = m.end()
            if regex is not None and seen_after:
                base = after_pos if after is not None else self.pos
                m = regex.search(self.clean, base)
                if m:
                    self.pos = m.end()
                    return "match"
            if idle is not None and time.time() - last_data >= idle:
                return "idle"
            if time.time() - start >= timeout:
                return "timeout"
            r, _, _ = select.select([self.master], [], [], 0.1)
            if r:
                if self.feed():
                    last_data = time.time()
            elif self.eof:
                return "eof"
        return "timeout"

    def send(self, data):
        if self.eof:
            return False
        try:
            os.write(self.master, data)
            return True
        except OSError:
            self.eof = True
            return False

    def finish(self):
        rc = None
        end = time.time() + 15
        while time.time() < end:
            rc = self.proc.poll()
            if rc is not None:
                break
            self.feed()
            time.sleep(0.1)
        if rc is None:
            self.send(b"\x04")
            try:
                rc = self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                except OSError:
                    pass
                try:
                    rc = self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                    except OSError:
                        pass
                    rc = self.proc.wait(timeout=5)
                if rc is not None and rc < 0:
                    rc = 124
        self.feed()
        try:
            os.close(self.master)
        except OSError:
            pass
        return rc


def expand_action_text(act):
    if act.get("type") == "paste_lines":
        tpl = act.get("template", "line-{i:03d}: alpha bravo charlie")
        lines = [tpl.format(i=i + 1) for i in range(int(act.get("count", 50)))]
        if act.get("tail"):
            lines.append(act["tail"])
        return "\n".join(lines)
    return act.get("text", "")


def run_interactive(transport, remote_cmd, actions, overall_timeout, env=None):
    argv = transport.argv(remote_cmd, tty=True)
    sess = PtySession(argv, env or (getattr(transport, "env", None) or os.environ.copy()),
                      overall_timeout)
    errors = []
    sent = []
    try:
        # initial prompt
        sess.pos = len(sess.clean)
        st = sess.read_until(PROMPT_RE, timeout=min(90, overall_timeout))
        if st != "match":
            errors.append("initial_prompt:%s" % st)
        for act in actions:
            typ = act.get("type")
            if typ in ("paste", "send", "paste_lines"):
                text = expand_action_text(act)
                if typ in ("paste", "paste_lines"):
                    payload = b"\x1b[200~" + text.encode("utf-8") + b"\x1b[201~"
                else:
                    payload = text.encode("utf-8")
                sess.pos = len(sess.clean)
                if not sess.send(payload):
                    errors.append("send_failed:%s" % typ)
                    break
                if act.get("submit", True):
                    time.sleep(0.15)
                    sess.send(b"\r")
                    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
                    sent.append({"bytes": len(text.encode("utf-8")),
                                 "sha256_16": digest,
                                 "prefix": text[:40]})
                    if act.get("auto_wait", True):
                        t = int(act.get("timeout_s", 180))
                        use_after = ANSWER_RE if act.get(
                            "after_answer",
                            not text.lstrip().startswith("/")) else None
                        st = sess.read_until(PROMPT_RE, timeout=t,
                                             after=use_after)
                        if st != "match":
                            errors.append("wait_prompt_after_send:%s" % st)
                            break
            elif typ == "key":
                key = act.get("key", "")
                if key == "ctrl-c":
                    sess.send(b"\x03")
                elif key == "ctrl-d":
                    sess.send(b"\x04")
                else:
                    errors.append("unknown_key:%s" % key)
            elif typ == "sleep":
                time.sleep(float(act.get("seconds", 1)))
            elif typ == "wait_prompt":
                sess.pos = len(sess.clean)
                st = sess.read_until(PROMPT_RE, timeout=int(act.get("timeout_s", 60)))
                if st != "match":
                    errors.append("wait_prompt:%s" % st)
            elif typ == "wait_idle":
                st = sess.read_until(idle=float(act.get("seconds", 3)),
                                     timeout=int(act.get("timeout_s", 60)))
                if st not in ("idle", "eof"):
                    errors.append("wait_idle:%s" % st)
            else:
                errors.append("unknown_action:%s" % typ)
        if not sess.eof:
            sess.pos = len(sess.clean)
            sess.send(b"exit\r")
            sess.read_until(idle=2, timeout=20)
    finally:
        rc = sess.finish()
    return {
        "rc": rc if rc is not None else -1,
        "output_raw": sess.raw.decode("utf-8", "replace"),
        "output_clean": sess.clean,
        "errors": errors,
        "sent": sent,
        "eof": sess.eof,
    }


# --------------------------------------------------------------------------
# one-shot driver
# --------------------------------------------------------------------------
def run_oneshot(transport, remote_cmd, timeout):
    t0 = time.time()
    try:
        r = transport.run(remote_cmd, timeout=timeout + 90)
        return {"rc": r.returncode, "output_raw": r.stdout,
                "output_clean": clean_ansi(r.stdout + r.stderr),
                "errors": [], "sent": [], "duration_s": None,
                "timed_out": False}
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return {"rc": 124, "output_raw": out,
                "output_clean": clean_ansi(out),
                "errors": ["harness_timeout"], "sent": [],
                "timed_out": True}


def scenario_session(scn):
    raw = "w62-%s" % scn["id"]
    return re.sub(r"[^A-Za-z0-9._-]", "-", raw)[:64]


def scenario_home(scn, transport):
    if scn.get("home_mode") == "offline":
        return (str(transport.root / "home-offline")
                if transport.name == "local" else OFFLINE_HOME)
    return (str(transport.root / "home")
            if transport.name == "local" else REMOTE_HOME)


def scenario_cwd(transport):
    return str(getattr(transport, "work", "/root"))


def build_oneshot_cmd(scn, prompt, session, transport):
    t = int(scn.get("timeout_s", 180))
    home = scenario_home(scn, transport)
    cwd = scenario_cwd(transport)
    yes = 1 if scn.get("assume_yes", True) else 0
    flags = "--session %s" % shq(session)
    if scn.get("plan"):
        flags += " --plan"
    return ("cd %s && HOME=%s AIKERNEL_ASSUME_YES=%d NO_COLOR=1 "
            "AIKERNEL_LANG=en timeout %d ai -p %s %s 2>&1"
            % (shq(cwd), shq(home), yes, t, shq(prompt), flags))


def build_interactive_cmd(scn, session, transport):
    t = int(scn.get("timeout_s", 240))
    home = scenario_home(scn, transport)
    yes = 1 if scn.get("assume_yes", True) else 0
    flags = "--session %s --no-onboarding" % shq(session)
    if scn.get("plan"):
        flags += " --plan"
    cwd = scenario_cwd(transport)
    # --foreground: keep ai in the pty's foreground process group, otherwise
    # tty.setraw()/read() in the child raise SIGTTOU/SIGTTIN.
    # TERM must not be "dumb": linenoise treats dumb terminals as unsupported
    # and falls back to linenoiseNoTTY (canonical echo, one ask per pasted
    # line). A real TERM enables raw mode and bracketed paste.
    return ("cd %s && HOME=%s AIKERNEL_ASSUME_YES=%d NO_COLOR=1 "
            "AIKERNEL_LANG=en TERM=xterm timeout --foreground %d ai %s 2>&1"
            % (shq(cwd), shq(home), yes, t, flags))


# --------------------------------------------------------------------------
# trace parsing / expectations
# --------------------------------------------------------------------------
def extract_facts(trace_texts):
    tools = []
    turns_start = 0
    turns_end = 0
    events = 0
    parse_errors = 0
    for text in trace_texts:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            events += 1
            name = ev.get("event")
            if name == "turn_start":
                turns_start += 1
            elif name == "turn_end":
                turns_end += 1
            elif name == "tool_call":
                tools.append({
                    "tool": ev.get("tool") or "",
                    "status": ev.get("status") or "",
                    "ok": bool(ev.get("ok")),
                    "args": ev.get("args") or "",
                })
    return {"tools": tools, "turns_start": turns_start,
            "turns_end": turns_end, "events": events,
            "parse_errors": parse_errors}


def check_safe_shell(cmd, allow_sandbox=True):
    patterns = [
        r"^rm -rf /tmp/aik-usage-w62(/[A-Za-z0-9._/-]+)?$",
        r"^mkdir -p /tmp/aik-usage-w62(/[A-Za-z0-9._/-]+)?$",
    ]
    if allow_sandbox:
        patterns.append(r"^rm -rf /sandbox/w62-[A-Za-z0-9._-]+$")
    return any(re.match(p, cmd) for p in patterns)


def verify_scenario(transport, scn, base_tmp):
    spec = scn.get("verify") or {}
    out = {}
    ok = True
    for p in spec.get("remote_present", []):
        r = transport.verify_path(p, "present")
        out["present:" + p] = r
        ok = ok and r
    for p in spec.get("remote_absent", []):
        r = transport.verify_path(p, "absent")
        out["absent:" + p] = r
        ok = ok and r
    for pair in spec.get("remote_grep", []):
        path, needle = pair
        r = transport.verify_path(path, "grep", needle)
        out["grep:%s=%s" % (path, needle)] = r
        ok = ok and r
    return ok, out


def expected_tool_names(scn):
    return list((scn.get("expect") or {}).get("tools_any") or [])


def evaluate(scn, rec, facts, verify_ok, verify_out, control_before,
             control_after, trace_count, leak_hits):
    exp = scn.get("expect") or {}
    reasons = []
    checks = {}
    text = rec.get("answer_text") or rec.get("output_clean") or ""
    low = text.lower()

    missing = [s for s in exp.get("must_contain", []) if s.lower() not in low]
    checks["must_contain_missing"] = missing
    if missing:
        reasons.append("must_contain_missing:%s" % ",".join(missing))

    anyneed = exp.get("must_contain_any") or []
    if anyneed and not any(s.lower() in low for s in anyneed):
        checks["must_contain_any_missing"] = anyneed
        reasons.append("must_contain_any_missing")

    banned = [s for s in exp.get("must_not_contain", []) if s.lower() in low]
    checks["must_not_contain_hit"] = banned
    if banned:
        reasons.append("must_not_contain_hit:%s" % ",".join(banned))

    need_tools = expected_tool_names(scn)
    seen = {t["tool"] for t in facts["tools"]}
    if need_tools:
        hit = [t for t in need_tools if t in seen]
        checks["tools_hit"] = hit
        if not hit:
            reasons.append("tools_any_missing:%s" % ",".join(need_tools))

    if exp.get("exit_ok", True) and rec.get("rc") != 0:
        reasons.append("rc=%s" % rec.get("rc"))

    if exp.get("max_turns") is not None and \
            facts["turns_start"] > int(exp["max_turns"]):
        reasons.append("turns>%s(%s)" % (exp["max_turns"], facts["turns_start"]))
    if exp.get("min_turns") is not None and \
            facts["turns_start"] < int(exp["min_turns"]):
        reasons.append("turns<%s(%s)" % (exp["min_turns"], facts["turns_start"]))

    for rule in exp.get("no_success_tool_args", []):
        tool = rule.get("tool")
        needles = rule.get("args_contains") or []
        for t in facts["tools"]:
            if t["tool"] != tool or t["status"] != "ok":
                continue
            if all(n in t["args"] for n in needles):
                reasons.append("forbidden_success:%s%s" % (tool, needles))
                break

    if exp.get("control_unchanged"):
        for key in exp["control_unchanged"]:
            b = control_before.get(key)
            a = control_after.get(key)
            checks["control:" + key] = [b, a]
            if b is not None and a is not None and a != b:
                reasons.append("control_changed:%s(%s->%s)" % (key, b, a))

    # Any control value drift is a policy violation for a read-only suite.
    if not scn.get("allow_control_change"):
        common = set(control_before) & set(control_after)
        for key in sorted(common):
            if control_before[key] != control_after[key]:
                reasons.append("control_drift:%s(%s->%s)" % (
                    key, control_before[key], control_after[key]))

    if trace_count == 0:
        reasons.append("no_trace")
    if leak_hits:
        reasons.append("secret_pattern_in_output:%s" % leak_hits)

    if not verify_ok:
        reasons.append("verify_failed")

    if rec.get("action_errors"):
        reasons.append("interactive:%s" % ",".join(rec["action_errors"]))

    checks.update({"verify": verify_out, "trace_count": trace_count,
                   "leak_hits": leak_hits})
    return (len(reasons) == 0), reasons, checks


# --------------------------------------------------------------------------
# trace copy
# --------------------------------------------------------------------------
def first_line_session(text):
    line = text.splitlines()[0] if text else ""
    try:
        ev = json.loads(line)
        return ev.get("session"), ev.get("session_id")
    except Exception:
        return None, None


def copy_traces(transport, names, scen_dir, sid):
    metas = []
    texts = []
    leak_total = {}
    for name in names:
        raw = None
        for attempt in range(3):
            try:
                raw = transport.read_trace(name)
                break
            except Exception as e:
                if attempt == 2:
                    metas.append({"file": name, "error": str(e)[:120]})
                    break
                time.sleep(0.5)
        if raw is None:
            continue
        sess, sess_id = first_line_session(raw)
        clean, hits = sanitize(raw)
        for k, n in hits.items():
            leak_total[k] = leak_total.get(k, 0) + n
        rel = Path("traces") / sid / name
        write_text(scen_dir.parent.parent / rel, clean)
        texts.append(raw)
        metas.append({"file": name, "session": sess, "session_id": sess_id,
                      "session_match": sess == sid, "bytes": len(raw),
                      "redacted": hits, "rel": str(rel)})
    return texts, metas, leak_total


# --------------------------------------------------------------------------
# core runner
# --------------------------------------------------------------------------
def ensure_evidence(out):
    for sub in ("raw", "traces"):
        (Path(out) / sub).mkdir(parents=True, exist_ok=True)


def wait_for_smoke(path, max_wait=2700):
    path = Path(path)
    t0 = time.time()
    while True:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, list) and data:
                    print("[smoke] results.json ready: %d scenarios" % len(data),
                          flush=True)
                    return True
            except Exception:
                pass
        if time.time() - t0 >= max_wait:
            print("[smoke] timeout waiting for %s" % path, flush=True)
            return False
        print("[smoke] waiting for %s (%ds)" % (path, int(time.time() - t0)),
              flush=True)
        time.sleep(15)


def run_suite(scenarios, transport, out, only=None, categories=None,
              keep_remote=False, verbose=True):
    out = Path(out)
    ensure_evidence(out)
    results = []
    total = len(scenarios)
    for idx, scn in enumerate(scenarios, 1):
        sid = scn["id"]
        if only and sid not in only:
            continue
        if categories and scn.get("category") not in categories:
            continue
        session = scenario_session(scn)
        scen_dir = out / "traces" / session
        scen_dir.mkdir(parents=True, exist_ok=True)
        print("[%d/%d] %s (%s, %s)" % (idx, total, sid, scn.get("category"),
                                       scn.get("mode")), flush=True)
        # setup (validated)
        for cmd in scn.get("setup") or []:
            if not check_safe_shell(cmd):
                raise SystemExit("unsafe setup command in %s: %s" % (sid, cmd))
            transport.run(cmd, 60)
        before = set(transport.list_traces())
        control_before = transport.read_control()
        t0 = time.time()
        rec = {"id": sid, "category": scn.get("category"),
               "mode": scn.get("mode"), "prompt": scn.get("prompt"),
               "timeout_s": scn.get("timeout_s"),
               "regular": scn.get("regular", True),
               "session": session, "started": now_iso(),
               "home_mode": scn.get("home_mode", "default"),
               "plan": bool(scn.get("plan")),
               "assume_yes": scn.get("assume_yes", True)}
        try:
            if scn.get("mode") == "interactive":
                cmd = build_interactive_cmd(scn, session, transport)
                actions = scn.get("inputs") or [
                    {"type": "paste", "text": scn["prompt"], "submit": True,
                     "timeout_s": scn.get("timeout_s", 180)}]
                r = run_interactive(transport, cmd, actions,
                                    int(scn.get("timeout_s", 240)) + 120)
                rec["cmd"] = cmd
            elif scn.get("mode") == "oneshot_resume":
                first = run_oneshot(
                    transport, build_oneshot_cmd(scn, scn["prompt"], session,
                                                 transport),
                    int(scn.get("timeout_s", 240)))
                second = run_oneshot(
                    transport,
                    build_oneshot_cmd(scn, scn["resume_prompt"], session,
                                      transport),
                    int(scn.get("timeout_s", 240)))
                r = {"rc": second["rc"] if first["rc"] == 0 else first["rc"],
                     "output_raw": first["output_raw"] + "\n--- RESUME ---\n" +
                                   second["output_raw"],
                     "output_clean": first["output_clean"] + "\n--- RESUME ---\n" +
                                      second["output_clean"],
                     "errors": first["errors"] + second["errors"],
                     "sent": [{"prefix": scn["prompt"][:40],
                               "bytes": len(scn["prompt"].encode()),
                               "sha256_16": hashlib.sha256(
                                   scn["prompt"].encode()).hexdigest()[:16]},
                              {"prefix": scn["resume_prompt"][:40],
                               "bytes": len(scn["resume_prompt"].encode()),
                               "sha256_16": hashlib.sha256(
                                   scn["resume_prompt"].encode()).hexdigest()[:16]}],
                     "resume_rc": second["rc"], "first_rc": first["rc"]}
                rec["cmd"] = build_oneshot_cmd(scn, scn["prompt"], session,
                                               transport) + \
                    " ; " + build_oneshot_cmd(scn, scn["resume_prompt"],
                                              session, transport)
            else:
                cmd = build_oneshot_cmd(scn, scn["prompt"], session, transport)
                r = run_oneshot(transport, cmd, int(scn.get("timeout_s", 180)))
                rec["cmd"] = cmd
        except Exception as e:
            r = {"rc": -1, "output_raw": "", "output_clean": "",
                 "errors": ["harness:%r" % e], "sent": []}
            rec["cmd"] = rec.get("cmd", "")
        duration = round(time.time() - t0, 1)
        time.sleep(0.5)
        after = set(transport.list_traces())
        new = sorted(after - before)
        texts, metas, leaks = copy_traces(transport, new, scen_dir, session)
        control_after = transport.read_control()

        facts = extract_facts(texts)
        # For interactive transcripts, drop echoed input so assertions only
        # see the assistant's answer.
        answer_text = r["output_clean"]
        if scn.get("mode") in ("interactive", "oneshot_resume"):
            for item in r.get("sent") or []:
                pref = item.get("prefix")
                if pref:
                    answer_text = answer_text.replace(pref, "[INPUT]")
        rec.update({
            "rc": r["rc"],
            "duration_s": duration,
            "finished": now_iso(),
            "trace_files": new,
            "trace_meta": metas,
            "trace_rel": [m["rel"] for m in metas if m.get("rel")],
            "trace_count": len(new),
            "trace_session_matches": sum(1 for m in metas if m.get("session_match")),
            "output_raw_sanitized": None,
            "output_clean": answer_text,
            "answer_text": answer_text,
            "output_bytes": len(r["output_raw"]),
            "output_sha256": hashlib.sha256(
                r["output_raw"].encode("utf-8", "replace")).hexdigest(),
            "action_errors": r.get("errors") or [],
            "inputs_sent": r.get("sent") or [],
            "tools": facts["tools"],
            "turns_start": facts["turns_start"],
            "turns_end": facts["turns_end"],
            "trace_events": facts["events"],
            "trace_parse_errors": facts["parse_errors"],
            "control_before": control_before,
            "control_after": control_after,
            "output_leak_hits": leaks,
        })
        if "resume_rc" in r:
            rec["first_rc"] = r["first_rc"]
            rec["resume_rc"] = r["resume_rc"]

        verify_ok, verify_out = verify_scenario(transport, scn, REMOTE_BASE)
        passed, reasons, checks = evaluate(
            scn, rec, facts, verify_ok, verify_out, control_before,
            control_after, len(new), leaks)
        rec["status"] = "pass" if passed else "fail"
        rec["failure_reasons"] = reasons
        rec["checks"] = checks
        rec["verify"] = verify_out

        # raw output (sanitized)
        safe_out, out_hits = sanitize(r["output_raw"])
        if out_hits:
            rec["output_leak_hits"] = {
                k: rec["output_leak_hits"].get(k, 0) + v
                for k, v in out_hits.items()}
        write_text(out / "raw" / ("%s.out" % sid),
                   "PROMPT: %s\nCMD: %s\nRC: %s\nDURATION: %ss\n"
                   "TRACES: %s\nSTATUS: %s\nREASONS: %s\n\n%s\n" % (
                       scn.get("prompt", ""), rec.get("cmd", ""), r["rc"],
                       duration, ",".join(new), rec["status"],
                       ";".join(reasons), safe_out))
        rec["out_file"] = str(Path("raw") / ("%s.out" % sid))
        rec["out_excerpt"] = answer_text[:2000]
        rec.pop("output_clean", None)
        rec.pop("answer_text", None)
        results.append(rec)
        print("    -> %s rc=%s %.1fs traces=%s reasons=%s" % (
            rec["status"], r["rc"], duration, len(new),
            ",".join(reasons) or "-"), flush=True)

        # cleanup (validated); always runs
        for cmd in scn.get("cleanup") or []:
            if not check_safe_shell(cmd):
                print("    !! unsafe cleanup skipped: %s" % cmd, flush=True)
                continue
            transport.run(cmd, 60)

    meta = {
        "generated_at": now_iso(),
        "transport": transport.name,
        "scenario_count": len(results),
        "source": str(DEFAULT_SCENARIOS),
    }
    payload = {"meta": meta, "scenarios": results}
    write_text(out / "results.json",
               json.dumps(payload, ensure_ascii=False, indent=1))
    print("[done] %d scenarios, pass=%d" % (
        len(results), sum(1 for r in results if r["status"] == "pass")),
        flush=True)
    return payload


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------
MOCK_AI = r'''#!/usr/bin/env python3
"""Mock ai for W62 harness self-test. No VM, no network, no API key."""
import json, os, sys, time

TRACE_DIR = os.environ.get("MOCK_TRACE_DIR", "/tmp/w62-mock-traces")
STATE_DIR = os.environ.get("MOCK_STATE_DIR", "/tmp/w62-mock-state")
os.makedirs(TRACE_DIR, exist_ok=True)
os.makedirs(STATE_DIR, exist_ok=True)
SESS = "default"
PROMPT = None
PLAN = False
SEQ = [0]
TURN = [0]
SESSION_ID = "mock-%d" % os.getpid()
TF = None


def emit(name, **kw):
    SEQ[0] += 1
    ev = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "mono_ms": int(time.time() * 1000),
          "session_id": SESSION_ID, "session": SESS, "turn": TURN[0],
          "event_seq": SEQ[0], "event": name}
    ev.update(kw)
    with open(TF, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")


def start():
    global TF
    TF = os.path.join(TRACE_DIR, "trace-mock-%d-%d.jsonl" % (int(time.time()), os.getpid()))
    emit("session_start", model="mock", provider="mock", pid=os.getpid(),
         uid=0, version="mock", config={"ctx_len": 4096})


def end(reason="mock_exit"):
    emit("session_end", reason=reason)


def answer(text):
    low = text.lower()
    if "/plan" in low:
        return "__PLAN__"
    if "/unplan" in low:
        return "__UNPLAN__"
    if "2+2" in low or "2 + 2" in low:
        return "4"
    if "7*6" in low:
        return "42"
    if "12+30" in low:
        return "1. 42\n2. 42\n3. 99"
    if "line-" in low and ("多少行" in text):
        return "100"
    if "77123" in text:
        st = os.path.join(STATE_DIR, SESS + ".txt")
        open(st, "w").write("77123")
        return "好的，已记住 77123。"
    if "数字是多少" in text:
        st = os.path.join(STATE_DIR, SESS + ".txt")
        return open(st).read() if os.path.exists(st) else "不知道"
    if "BLUE-OTTER-77" in text:
        open(os.path.join(STATE_DIR, SESS + ".txt"), "w").write("BLUE-OTTER-77")
        return "记住了。"
    if "口令是什么" in text:
        st = os.path.join(STATE_DIR, SESS + ".txt")
        return open(st).read() if os.path.exists(st) else "不知道"
    if "写入" in text:
        return "plan mode: write denied" if PLAN else "would write"
    return "AIKernel mock answer: ok"


def ask(text):
    global PLAN
    TURN[0] += 1
    emit("turn_start", question=text)
    emit("model_request", message_count=1, tools=[], tool_count=0)
    if "SLOW" in text:
        print("working on it...", flush=True)
        while True:
            ch = os.read(0, 1)
            if not ch:
                break
            if ch == b"\x03":
                print("\n^C", flush=True)
                emit("turn_end", duration_ms=100, rounds=1, end_reason="interrupted")
                return
        emit("turn_end", duration_ms=100, rounds=1, end_reason="eof")
        return
    if PLAN and "写入" in text:
        emit("policy_decision", gate="PLAN", decision="deny",
             reason="plan_mode", tool="exec_run", confirm_source=None, args="{}", uid=0)
        emit("tool_call", tool="exec_run", channel="exec", risk="W1",
             args="{}", status="denied", ok=False, exit_code=-1, result="denied")
        reply = "plan mode: write denied"
    else:
        reply = answer(text)
        if reply == "__PLAN__":
            PLAN = True
            reply = "Entered plan (read-only research) mode: writes disabled."
        elif reply == "__UNPLAN__":
            PLAN = False
            reply = "Exited plan mode."
        elif "AIKernel" in text or "系统是什么" in text:
            emit("policy_decision", gate="W1", decision="allow",
                 reason="policy_allow", tool="exec_run",
                 confirm_source=None, args="{}", uid=0)
            emit("tool_call", tool="exec_run", channel="exec", risk="R",
                 args="{}", status="ok", ok=True, exit_code=0,
                 result="mock ok")
            reply = "AIKernel mock answer: AIKernel is a kernel AI shell."
        emit("model_response", content=reply)
    print("AI: " + reply, flush=True)
    emit("turn_end", duration_ms=10, rounds=1, end_reason="completed")


def main():
    global SESS, PROMPT, PLAN
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-p", "--prompt") and i + 1 < len(args):
            PROMPT = args[i + 1]; i += 2; continue
        if a in ("--session", "-s") and i + 1 < len(args):
            SESS = args[i + 1]; i += 2; continue
        if a in ("--plan", "-P"):
            PLAN = True; i += 1; continue
        if a in ("--no-onboarding", "-y", "--yes"):
            i += 1; continue
        if a.startswith("-"):
            if a in ("--ctx", "--max-tokens") and i + 1 < len(args):
                i += 2; continue
            i += 1; continue
        i += 1
    start()
    try:
        if os.environ.get("HOME", "").find("offline") >= 0:
            TURN[0] += 1
            emit("turn_start", question=PROMPT or "")
            emit("error", phase="model", code="offline", message="model unavailable")
            emit("turn_end", duration_ms=5, rounds=0, end_reason="model_error")
            print("ERROR: model unavailable (offline mock)", flush=True)
            end("single_shot_exit")
            return 1
        if PROMPT is not None:
            ask(PROMPT)
            end("single_shot_exit")
            return 0
        import termios, tty
        tty.setraw(0)
        print("AIKernel mock shell", flush=True)
        paste = False
        while True:
            print("ai[mock:?]> ", end="", flush=True)
            raw = b""
            pbuf = b""
            paste = False
            while True:
                ch = os.read(0, 1)
                if not ch:
                    end("repl_exit"); return 0
                if paste:
                    if ch == b"\x1b":
                        rest = os.read(0, 5)
                        if rest == b"[201~":
                            paste = False
                            raw += pbuf
                            pbuf = b""
                            continue
                        pbuf += rest
                        continue
                    pbuf += ch
                    continue
                if ch == b"\x1b":
                    rest = os.read(0, 5)
                    if rest == b"[200~":
                        paste = True
                        pbuf = b""
                        continue
                    raw += rest
                    continue
                if ch == b"\x04":
                    end("repl_exit"); return 0
                if ch == b"\x03":
                    print("\n^C", flush=True)
                    raw = b""
                    break
                if ch in (b"\r", b"\n"):
                    break
                raw += ch
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            print()
            if line == "exit":
                end("repl_exit"); return 0
            ask(line)
    finally:
        pass


if __name__ == "__main__":
    sys.exit(main())
'''


def self_test_scenarios():
    return [
        {"id": "st-01-oneshot", "category": "self-test", "mode": "oneshot",
         "prompt": "这个系统是什么？", "timeout_s": 60, "regular": True,
         "expect": {"must_contain": ["AIKernel"], "must_not_contain": [],
                    "tools_any": [], "exit_ok": True},
         "setup": [], "cleanup": []},
        {"id": "st-02-multiline", "category": "self-test", "mode": "interactive",
         "prompt": "多行粘贴", "timeout_s": 90, "regular": True,
         "inputs": [{"type": "paste", "text": "第一行\n第二行\n7*6 等于几？",
                     "submit": True, "timeout_s": 60}],
         "expect": {"must_contain": ["42"], "must_not_contain": [],
                    "tools_any": [], "exit_ok": True, "max_turns": 1},
         "setup": [], "cleanup": []},
        {"id": "st-03-plan", "category": "self-test", "mode": "oneshot",
         "prompt": "写入 /tmp/x", "timeout_s": 60, "regular": True,
         "plan": True,
         "expect": {"must_contain": ["plan"], "must_not_contain": [],
                    "tools_any": [], "exit_ok": True},
         "setup": [], "cleanup": []},
        {"id": "st-04-ctrl-c", "category": "self-test", "mode": "interactive",
         "prompt": "Ctrl-C 中断", "timeout_s": 90, "regular": True,
         "inputs": [
             {"type": "paste", "text": "SLOW 请分析一切", "submit": True,
              "auto_wait": False},
             {"type": "sleep", "seconds": 0.8},
             {"type": "key", "key": "ctrl-c"},
             {"type": "wait_prompt", "timeout_s": 20},
             {"type": "paste", "text": "2+2 等于几？只回答数字。",
              "submit": True, "timeout_s": 30}],
         "expect": {"must_contain": ["4"], "must_not_contain": [],
                    "tools_any": [], "exit_ok": True},
         "setup": [], "cleanup": []},
        {"id": "st-05-resume", "category": "self-test", "mode": "oneshot_resume",
         "prompt": "我的口令是 BLUE-OTTER-77", "resume_prompt": "口令是什么？",
         "timeout_s": 120, "regular": True,
         "expect": {"must_contain": ["BLUE-OTTER-77"], "must_not_contain": [],
                    "tools_any": [], "exit_ok": True},
         "setup": [], "cleanup": []},
        {"id": "st-06-offline", "category": "self-test", "mode": "oneshot",
         "prompt": "查看负载", "timeout_s": 60, "regular": True,
         "home_mode": "offline",
         "expect": {"must_contain": [], "must_contain_any": ["unavailable"],
                    "must_not_contain": [], "tools_any": [], "exit_ok": False},
         "setup": [], "cleanup": []},
    ]


def run_self_test(out):
    root = Path(tempfile.mkdtemp(prefix="w62-selftest-"))
    bin_dir = root / "bin"
    bin_dir.mkdir()
    mock = bin_dir / "ai"
    write_text(mock, MOCK_AI)
    mock.chmod(0o755)
    transport = LocalTransport(root, root / "traces-out")
    transport.prepare()
    evid = Path(out) / "self-test"
    evid.mkdir(parents=True, exist_ok=True)
    log = []
    ok = True
    try:
        payload = run_suite(self_test_scenarios(), transport, evid,
                            keep_remote=True, verbose=False)
        results_path = evid / "results.json"
        analysis_path = evid / "analysis.json"
        analysis_md = evid / "analysis.md"
        r = subprocess.run(
            [sys.executable, str(HERE / "analyze_trace.py"),
             "--results", str(results_path),
             "--trace-root", str(evid),
             "--out", str(analysis_path), "--md", str(analysis_md)],
            capture_output=True, text=True)
        log.append("analyzer rc=%s\n%s\n%s" % (r.returncode, r.stdout, r.stderr))
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        metrics = analysis["metrics"]
        checks = {
            "M1_all_pass": metrics["M1"]["success_rate"] == 1.0,
            "M3_all_ok": metrics["M3"]["success_rate_excl_denied"] == 1.0,
            "M5_complete": metrics["M5"]["completeness_rate"] == 1.0,
            "M5_no_leak": metrics["M5"]["redaction_leaks"] == 0,
            "M5_questions": metrics["M5"]["question_match_rate"] == 1.0,
        }
        ok = all(checks.values()) and r.returncode == 0
        log.append("checks: %s" % json.dumps(checks, ensure_ascii=False))
        log.append("metrics: %s" % json.dumps(metrics, ensure_ascii=False))
        for rec in payload["scenarios"]:
            log.append("%s %s reasons=%s turns=%s traces=%s" % (
                rec["id"], rec["status"], rec["failure_reasons"],
                rec["turns_start"], rec["trace_count"]))
    except Exception as e:
        ok = False
        log.append("self-test exception: %r" % e)
    finally:
        try:
            transport.cleanup()
        except Exception:
            pass
        shutil.rmtree(root, ignore_errors=True)
    log_text = "W62 self-test %s\n%s\n" % ("PASS" if ok else "FAIL", "\n".join(log))
    write_text(Path(out) / "self-test.log", log_text)
    print(log_text)
    return 0 if ok else 1


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def load_scenarios(path):
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    scns = obj["scenarios"] if isinstance(obj, dict) else obj
    seen = set()
    for s in scns:
        for key in ("id", "category", "prompt", "mode", "timeout_s", "expect"):
            if key not in s:
                raise SystemExit("scenario %s missing %s" % (s.get("id"), key))
        if s["id"] in seen:
            raise SystemExit("duplicate scenario id %s" % s["id"])
        seen.add(s["id"])
        exp = s["expect"]
        for key in ("must_contain", "must_not_contain", "tools_any", "exit_ok"):
            if key not in exp:
                raise SystemExit("scenario %s missing expect.%s" % (s["id"], key))
        for cmd in (s.get("setup") or []) + (s.get("cleanup") or []):
            if not check_safe_shell(cmd):
                raise SystemExit("unsafe command in %s: %s" % (s["id"], cmd))
    return scns


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scenarios", default=str(DEFAULT_SCENARIOS))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--transport", choices=["ssh", "local"], default="ssh")
    ap.add_argument("--vm", default=DEFAULT_VM)
    ap.add_argument("--only", default="")
    ap.add_argument("--category", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--skip-smoke-wait", action="store_true")
    ap.add_argument("--no-analyze", action="store_true")
    ap.add_argument("--keep-remote", action="store_true")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return run_self_test(args.out)

    scenarios = load_scenarios(args.scenarios)
    if args.list:
        for s in scenarios:
            print("%-10s %-12s %-10s %ss" % (s["id"], s["category"],
                                             s["mode"], s["timeout_s"]))
        print("total: %d" % len(scenarios))
        return 0

    only = set(x.strip() for x in args.only.split(",") if x.strip())
    cats = set(x.strip() for x in args.category.split(",") if x.strip())
    if args.transport == "ssh" and not args.skip_smoke_wait:
        if not wait_for_smoke(SMOKE_RESULTS):
            print("WARNING: proceeding without smoke completion", flush=True)

    if args.transport == "ssh":
        transport = SshTransport(args.vm)
    else:
        root = Path(tempfile.mkdtemp(prefix="w62-local-"))
        transport = LocalTransport(root, root / "traces-out")
    transport.prepare()
    try:
        payload = run_suite(scenarios, transport, args.out, only=only,
                            categories=cats, keep_remote=args.keep_remote)
    finally:
        if not args.keep_remote:
            try:
                transport.cleanup()
            except Exception as e:
                print("cleanup warning: %r" % e, flush=True)

    results_path = Path(args.out) / "results.json"
    if not args.no_analyze:
        rc = subprocess.call(
            [sys.executable, str(HERE / "analyze_trace.py"),
             "--results", str(results_path),
             "--trace-root", str(args.out),
             "--out", str(Path(args.out) / "analysis.json"),
             "--md", str(Path(args.out) / "analysis.md")] +
            (["--strict"] if args.strict else []))
        return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
