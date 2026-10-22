# W62 usage scenario library and harness

Human-style, repeatable end-to-end scenarios for the AIKernel `ai` shell.
The harness runs on L1 and drives the production VM over SSH; `--self-test`
runs the whole pipeline locally against a mock `ai` (no VM, no network, no API
key).

## Files

| file | purpose |
|---|---|
| `scenarios.json` | 50 scenarios in 10 PLAN §4 categories |
| `run_usage.py` | one-shot / interactive (PTY) / session-resume driver, evidence writer |
| `analyze_trace.py` | trace JSONL validator + M1/M2/M3/M5 metrics |
| `README.md` | this file |

## Quick start

```bash
# on L1
cd /home/jack66g/linux-6.18.39/agent/ai/tests/usage
python3 run_usage.py --list                 # list scenarios
python3 run_usage.py --self-test            # local mock, no VM/API
python3 run_usage.py                        # all 50 against the VM
python3 run_usage.py --only cog-01,file-01  # subset
python3 run_usage.py --category network
```

Default evidence directory: `~/mbedtls-trim-evidence/logs/fix-w62/`.
Before a real run the harness waits (up to 45 min) for
`~/aikernel-longterm/evidence/usage-smoke/results.json` so the W62 smoke run
and this suite do not hammer the VM concurrently. Use `--skip-smoke-wait` to
override.

Exit code: 0 when the suite finished (regardless of scenario pass/fail);
`--strict` makes the analyzer exit 1 when M1/M2/M3/M5 targets are missed.
`--self-test` exits 0 only when every self-check passes.

## Scenario schema

Required fields:

```json
{
  "id": "file-01",
  "category": "file|cognitive|diagnostic|network|service|memory|sandbox|permission|robustness|combo",
  "prompt": "natural-language user request",
  "mode": "oneshot|interactive|oneshot_resume",
  "timeout_s": 180,
  "expect": {
    "must_contain": ["all of these substrings"],
    "must_not_contain": ["none of these substrings"],
    "tools_any": ["at least one of these tool names in trace tool_call"],
    "exit_ok": true
  },
  "setup": [],
  "cleanup": []
}
```

Optional fields:

| field | meaning |
|---|---|
| `regular` | include in the “regular task” M2 P95 (default true) |
| `plan` | start `ai` with `--plan` (read-only plan mode) |
| `assume_yes` | default true; false leaves W2 confirmation at default-deny |
| `home_mode` | `default` (real config via symlink) or `offline` (mock provider at 127.0.0.1:9, no real key) |
| `inputs` | interactive actions, see below |
| `resume_prompt` | second prompt for `oneshot_resume` (same `--session`) |
| `verify.remote_present` / `remote_absent` / `remote_grep` | post-run filesystem assertions, read-only |
| `expect.must_contain_any` | at least one of the list |
| `expect.max_turns` / `min_turns` | trace `turn_start` count bounds |
| `expect.no_success_tool_args` | fail if a tool call succeeded with all listed args substrings |
| `expect.control_unchanged` | `/proc/ai/control` keys that must not move |
| `note` | free text for the report |

Interactive `inputs` actions:

```json
{"type": "paste", "text": "...", "submit": true, "timeout_s": 120}
{"type": "send", "text": "/plan", "submit": true}
{"type": "paste_lines", "count": 100, "template": "line-{i:03d}: ...", "tail": "...", "submit": true}
{"type": "key", "key": "ctrl-c"}
{"type": "sleep", "seconds": 1.5}
{"type": "wait_prompt", "timeout_s": 30}
{"type": "wait_idle", "seconds": 3}
```

`paste` and `paste_lines` are sent as a real terminal bracketed paste
(`ESC[200~ ... ESC[201~`) followed by Enter, which is what the linenoise
paste path expects. After a submitting action the driver waits for the next
`ai[...]> ` prompt unless `auto_wait` is false. At the end it sends `exit`.

Assertions run on cleaned output with ANSI removed; for interactive transcripts
the echoed input is replaced by `[INPUT]` so an answer cannot be “found” in the
user's own paste.

Every scenario runs with an isolated `--session w62-<id>`. Sessions, history,
audit logs and offline config live under `/tmp/aik-usage-w62/home*` (HOME is
redirected; `model.toml`/`provider.toml` are **symlinked**, never copied, so no
key material is written by the harness). The directory is removed at the end.

## Transports

* `ssh` (default): `ssh root@192.168.245.138`, one-shot via
  `cd /root && HOME=... AIKERNEL_ASSUME_YES=1 NO_COLOR=1 timeout N ai -p '<prompt>' --session ... 2>&1`;
  interactive via `ssh -tt` + a local PTY (`pty.openpty` + `select`), Ctrl-C as
  `0x03`, 8 KB paste as bracketed paste.
* `local`: only used by `--self-test`. A Python mock `ai` implements the subset
  of the CLI needed to exercise one-shot, PTY paste, Ctrl-C, plan mode,
  session resume, a model-unavailable provider and trace emission.

## Trace analysis

`run_usage.py` discovers new files in `/var/log/aikernel/trace/` around each
scenario, copies them (sanitized) to `traces/<id>/`, then invokes
`analyze_trace.py`.

Trace events validated: `session_start`, `turn_start`, `turn_end`,
`model_request`, `model_response`, `tool_call`, `route_activate`,
`policy_decision`, `session_end`, `event_seq` monotonicity.

| metric | definition | target |
|---|---|---|
| M1 | scenarios passed / executed | ≥95% |
| M2 | wall time P95, all and regular-only | ≤60s regular |
| M3 | `tool_call` status ok / total; separate rate excluding policy denials | ≥98% |
| M5 | traces with session_start/end, all turns closed, monotonic seq, no parse errors, no secret patterns; plus input/trace question match rate | 100% / 0 leaks |

Secret scan patterns: `sk-…`, `Bearer …`, `"api_key"/"token"/"secret": "…"`,
`$6$`/`$5$`/`$1$`/`$y$` crypt hashes. Matches are redacted before anything is
written to evidence; counts are recorded in `results.json` and
`analysis.json`.

## Safety boundaries

* VM is read-only apart from `/tmp/aik-usage-w62/**`, `/sandbox/w62-*`
  (created/destroyed by sandbox scenarios), product trace logs, and one SME
  test fact in `mem-01` (the prompt asks the agent to delete it).
* `setup`/`cleanup` commands are validated by `check_safe_shell()`; only
  `rm -rf /tmp/aik-usage-w62/...`, `mkdir -p /tmp/aik-usage-w62/...` and
  `rm -rf /sandbox/w62-...` are accepted. Anything else aborts the run.
* Destructive prompts run only with `--plan` (svc-03, perm-02) or with
  `assume_yes: false` (perm-01); success-side-effect rules
  (`no_success_tool_args`) and `/proc/ai/control` before/after snapshots prove
  nothing changed.
* `file-04` deliberately targets `/etc/aik-w62-denied.txt` but the harness
  never writes there; it only verifies absence. If it ever appears, that is a
  P0 finding and the file is left untouched for inspection.
* No API key is read, copied or logged. `rob-04` uses a synthetic offline
  provider config with a dummy key.
* At the end the harness removes `/tmp/aik-usage-w62` on the VM. It never
  restarts services, edits config or touches kernel files.

## Evidence layout

```
~/mbedtls-trim-evidence/logs/fix-w62/
├── results.json          # per-scenario rc, duration, checks, trace meta, excerpt
├── analysis.json/md      # M1/M2/M3/M5 and per-scenario trace table
├── raw/<id>.out          # sanitized raw output + command + reasons
├── traces/<id>/*.jsonl   # sanitized trace copies
├── run.log               # console log (when redirected)
└── self-test.log         # --self-test log
```

`results.json` `meta.transport` distinguishes the mock run from the VM run.
