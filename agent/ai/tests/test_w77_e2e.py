#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""W77 end-to-end evidence: routing/offline/failover/degradation.

Uses tests/mock_w77_llm.py (no real qwen; soak-window constraint). Run from
the agent/ai directory after `make`:

    python3 tests/test_w77_e2e.py --agent-dir . --out /tmp/w77-e2e.json

Scenarios:
  offline_intent, dns_failure, cloud_500, cloud_429, network_drop,
  local_failure, session_preserved, local_p95, local_ctx_tools, stream_local
"""
import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MOCK = HERE / "mock_w77_llm.py"


class Mock:
    def __init__(self, mode="ok", reply="mock-ok", latency_ms=0,
                 toolcall_once=False):
        self.mode = mode
        self.reply = reply
        self.latency_ms = latency_ms
        self.toolcall_once = toolcall_once
        self.proc = None
        self.port = None
        self.log = None

    def start(self, log):
        self.log = str(log)
        self.proc = subprocess.Popen(
            [sys.executable, str(MOCK), "--port", "0", "--mode", self.mode,
             "--reply", self.reply, "--latency-ms", str(self.latency_ms),
             "--log", self.log] +
            (["--toolcall-once"] if self.toolcall_once else []),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = self.proc.stdout.readline().strip()
        if not line.startswith("PORT="):
            raise RuntimeError("mock did not print port: %r" % line)
        self.port = int(line.split("=", 1)[1])
        for _ in range(50):
            try:
                import urllib.request
                urllib.request.urlopen(
                    "http://127.0.0.1:%d/__health" % self.port, timeout=1)
                return self
            except Exception:
                time.sleep(0.05)
        raise RuntimeError("mock health failed")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None


def write_config(home, cloud_url, local_url, ctx=32768, stream=False):
    d = home / ".aikernel"
    d.mkdir(parents=True, exist_ok=True)
    (d / "model.toml").write_text(f"""[default]
model = "cloud"

[local]
enabled = true
base_url = "{local_url}"
model = "qwen2.5:1.5b"
timeout_ms = 60000
api_key = ""

[ui]
ctx_len = {ctx}
max_tokens = 512
stream = {"true" if stream else "false"}
local_api = "native"
color = false
verbose = false
session = "default"

[route]
mode = "auto"
privacy = false
prefer_local = true
failover = true
offline_intents = true
local_ctx = 32768
local_p95_ms = 8000
switch_budget_ms = 2000
probe_timeout_ms = 400

[models.cloud]
provider_type = "openai_compatible"
model_name = "mock-cloud"
base_url = "{cloud_url}"
api_key = ""

[models.local]
provider_type = "local"
model_name = "qwen2.5:1.5b"
base_url = "{local_url}"
api_key = ""
""", encoding="utf-8")


def read_jsonl(path):
    if not Path(path).exists():
        return []
    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def run_ai(agent_dir, home, question, env_extra=None, timeout=60):
    env = dict(os.environ)
    env.update({
        "HOME": str(home),
        "AIKERNEL_TRACE_DIR": str(home / "trace"),
        "AIKERNEL_OFFLINE_NO_EXEC": "1",
        "AIKERNEL_ROUTE": "auto",
    })
    for k in ("AIKERNEL_CLOUD_DOWN", "AIKERNEL_LOCAL_DOWN",
              "AIKERNEL_PRIVACY", "AIKERNEL_OFFLINE_INTENTS"):
        env.pop(k, None)
    if env_extra:
        env.update(env_extra)
    t0 = time.time()
    p = subprocess.run([str(Path(agent_dir) / "ai"), "-p", question],
                       cwd=agent_dir, env=env, capture_output=True,
                       text=True, timeout=timeout)
    elapsed = (time.time() - t0) * 1000.0
    return {
        "rc": p.returncode,
        "out": (p.stdout or "") + (p.stderr or ""),
        "elapsed_ms": elapsed,
        "route": read_jsonl(home / "trace" / "route.jsonl"),
        "session": read_jsonl(home / ".aikernel" / "sessions" /
                              "default.jsonl"),
        "plans": read_jsonl(home / ".aikernel" / "offline" /
                            "plans.jsonl"),
    }


def no_key(text):
    bad = ("api_key", "sk-", "Authorization", "base_url")
    return all(b not in text for b in bad)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-dir", default=".")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    agent_dir = Path(args.agent_dir).resolve()
    if not (agent_dir / "ai").exists():
        print("missing ai binary in %s" % agent_dir, file=sys.stderr)
        return 2

    base = Path(tempfile.mkdtemp(prefix="w77-e2e-"))
    results = {"pass": 0, "fail": 0, "checks": [], "scenarios": {}}

    def check(cond, name, detail=""):
        results["pass" if cond else "fail"] += 1
        results["checks"].append({"name": name, "ok": bool(cond),
                                  "detail": detail})
        print(("PASS: " if cond else "FAIL: ") + name +
              (("  [%s]" % detail) if detail and not cond else ""))

    try:
        # ---------- 1) offline intent, no model servers ----------
        home = base / "offline"
        write_config(home, "http://127.0.0.1:1", "http://127.0.0.1:1")
        r = run_ai(agent_dir, home, "内存使用情况")
        route_events = [e.get("event") for e in r["route"]]
        check(r["rc"] == 0 and "[offline] intent=memory" in r["out"] and
              "MemTotal=" in r["out"], "offline: memory 意图不依赖模型")
        check(route_events == ["route_offline"], "offline: 只写 route_offline")
        check(len(r["session"]) == 2 and
              r["session"][0]["role"] == "user" and
              r["session"][1]["role"] == "assistant",
              "offline: 会话 user+assistant 落盘")
        results["scenarios"]["offline_intent"] = r

        # ---------- 2) DNS failure -> local ----------
        home = base / "dns"
        write_config(home, "http://no-such-host.invalid:9",
                     "http://127.0.0.1:18978")
        local = Mock("ok", "local-answer").start(base / "dns-local.log")
        write_config(home, "http://no-such-host.invalid:9",
                     "http://127.0.0.1:%d" % local.port)
        r = run_ai(agent_dir, home, "请分析这段代码的设计并给出方案")
        dec = [e for e in r["route"] if e.get("event") == "route_decision"]
        check(r["rc"] == 0 and "local-answer" in r["out"],
              "dns: 云端 DNS 失败仍得本地回答")
        check(dec and dec[-1]["decision"] == "local" and
              dec[-1]["reason"] in ("cloud_down", "network_or_dns"),
              "dns: 决策 local/cloud_down",
              json.dumps(dec[-1], ensure_ascii=False) if dec else "none")
        check(r["elapsed_ms"] < 2000, "dns: 端到端 <2s",
              "%.0fms" % r["elapsed_ms"])
        check(no_key(json.dumps(r["route"])), "dns: trace 不含密钥")
        results["scenarios"]["dns_failure"] = {
            "elapsed_ms": r["elapsed_ms"], "decision": dec[-1] if dec else None}
        local.stop()

        # ---------- 3) cloud 500 -> local ----------
        home = base / "c500"
        cloud = Mock("500").start(base / "c500-cloud.log")
        local = Mock("ok", "local-answer").start(base / "c500-local.log")
        write_config(home, "http://127.0.0.1:%d" % cloud.port,
                     "http://127.0.0.1:%d" % local.port)
        r = run_ai(agent_dir, home, "请分析这段代码的设计并给出方案")
        switches = [e for e in r["route"] if e.get("event") == "route_switch"]
        check(r["rc"] == 0 and "local-answer" in r["out"] and
              "已切换到本地模型" in r["out"], "cloud500: 自动切本地并回答")
        check(any(s.get("from") == "cloud" and s.get("to") == "local"
                  for s in switches), "cloud500: route_switch 事件")
        check(all(0 <= s.get("switch_ms", 9999) < 2000 for s in switches),
              "cloud500: switch_ms <2s",
              json.dumps(switches, ensure_ascii=False))
        check(r["elapsed_ms"] < 2000, "cloud500: 端到端 <2s",
              "%.0fms" % r["elapsed_ms"])
        local_logs = read_jsonl(base / "c500-local.log")
        check(len(local_logs) >= 1 and local_logs[-1].get("num_ctx") == 32768,
              "cloud500: 本地 32768 上下文",
              json.dumps(local_logs[-1] if local_logs else {}, ensure_ascii=False))
        check(len(local_logs) >= 1 and local_logs[-1].get("tools", 0) >= 1,
              "cloud500: 本地请求携带 tools（qwen2.5 工具调用面）")
        results["scenarios"]["cloud_500"] = {
            "elapsed_ms": r["elapsed_ms"], "switch": switches,
            "local_request": local_logs[-1] if local_logs else None,
            "cloud_requests": len(read_jsonl(base / "c500-cloud.log"))}
        cloud.stop(); local.stop()

        # ---------- 4) cloud 429 -> local ----------
        home = base / "c429"
        cloud = Mock("429").start(base / "c429-cloud.log")
        local = Mock("ok", "local-answer").start(base / "c429-local.log")
        write_config(home, "http://127.0.0.1:%d" % cloud.port,
                     "http://127.0.0.1:%d" % local.port)
        r = run_ai(agent_dir, home, "请分析这段代码的设计并给出方案")
        switches = [e for e in r["route"] if e.get("event") == "route_switch"]
        check(r["rc"] == 0 and "local-answer" in r["out"] and
              switches and switches[-1].get("reason") == "http_429",
              "cloud429: 限流切换本地（reason=http_429）",
              json.dumps(switches, ensure_ascii=False))
        results["scenarios"]["cloud_429"] = {
            "elapsed_ms": r["elapsed_ms"], "switch": switches}
        cloud.stop(); local.stop()

        # ---------- 5) connection drop (timeout-class) ----------
        home = base / "drop"
        cloud = Mock("drop").start(base / "drop-cloud.log")
        local = Mock("ok", "local-answer").start(base / "drop-local.log")
        write_config(home, "http://127.0.0.1:%d" % cloud.port,
                     "http://127.0.0.1:%d" % local.port)
        r = run_ai(agent_dir, home, "请分析这段代码的设计并给出方案")
        switches = [e for e in r["route"] if e.get("event") == "route_switch"]
        check(r["rc"] == 0 and "local-answer" in r["out"] and switches,
              "drop: 连接中断（超时同类）切本地",
              json.dumps(switches, ensure_ascii=False))
        results["scenarios"]["network_drop"] = {
            "elapsed_ms": r["elapsed_ms"], "switch": switches}
        cloud.stop(); local.stop()

        # ---------- 5b) true read timeout (cloud 30s) -> local ----------
        home = base / "timeout"
        cloud = Mock("ok", "slow-cloud", latency_ms=32000).start(
            base / "timeout-cloud.log")
        local = Mock("ok", "local-answer").start(base / "timeout-local.log")
        write_config(home, "http://127.0.0.1:%d" % cloud.port,
                     "http://127.0.0.1:%d" % local.port)
        r = run_ai(agent_dir, home, "请分析这段代码的设计并给出方案",
                   timeout=90)
        switches = [e for e in r["route"] if e.get("event") == "route_switch"]
        check(r["rc"] == 0 and "local-answer" in r["out"] and switches,
              "timeout: 云端读超时后切本地",
              json.dumps(switches, ensure_ascii=False))
        check(all(0 <= s.get("switch_ms", 9999) < 2000 for s in switches),
              "timeout: 失败检测后的切换 <2s",
              json.dumps(switches, ensure_ascii=False))
        results["scenarios"]["cloud_timeout"] = {
            "elapsed_ms": r["elapsed_ms"], "switch": switches}
        cloud.stop(); local.stop()

        # ---------- 6) both fail: explicit degradation + session ----------
        home = base / "degrade"
        cloud = Mock("500").start(base / "deg-cloud.log")
        local = Mock("500").start(base / "deg-local.log")
        write_config(home, "http://127.0.0.1:%d" % cloud.port,
                     "http://127.0.0.1:%d" % local.port)
        r = run_ai(agent_dir, home, "请分析这段代码的设计并给出方案")
        check(r["rc"] != 0 and "能力受限" in r["out"] and
              "离线查询仍可用" in r["out"], "degrade: 明确离线/能力受限")
        check("D2+ 写操作仍需 W74 lease/确认" in r["out"],
              "degrade: D2+ 不绕过声明")
        check(len(r["session"]) == 2 and
              r["session"][1]["role"] == "assistant" and
              "能力受限" in r["session"][1]["content"],
              "degrade: 失败消息落会话（不丢会话）")
        check(any(e.get("status") == "degraded" for e in r["plans"]),
              "degrade: 计划缓存记录 degraded")
        # same HOME: follow-up offline intent keeps history
        r2 = run_ai(agent_dir, home, "内存使用情况")
        check(r2["rc"] == 0 and len(r2["session"]) >= 4 and
              "[offline] intent=memory" in r2["out"],
              "session: 失败后离线意图继续，历史保留")
        results["scenarios"]["local_failure"] = {
            "rc": r["rc"], "out_tail": r["out"][-600:],
            "session_len": len(r["session"])}
        cloud.stop(); local.stop()

        # ---------- 7) local P95 (mock 50ms) ----------
        home = base / "p95"
        local = Mock("ok", "local-answer", latency_ms=50).start(
            base / "p95-local.log")
        write_config(home, "http://127.0.0.1:1",
                     "http://127.0.0.1:%d" % local.port)
        samples = []
        for _ in range(20):
            r = run_ai(agent_dir, home, "你好",
                       env_extra={"AIKERNEL_ROUTE": "local"})
            samples.append(r["elapsed_ms"])
            if r["rc"] != 0:
                break
        p95 = statistics.quantiles(samples, n=20)[18] if len(samples) >= 20 \
            else max(samples)
        check(len(samples) == 20 and p95 <= 8000,
              "p95: 本地 mock P95 <=8s", "p95=%.0fms" % p95)
        check(len(read_jsonl(base / "p95-local.log")) >= 20,
              "p95: 20 次本地请求全部到达")
        results["scenarios"]["local_p95"] = {
            "samples": len(samples), "p95_ms": p95,
            "median_ms": statistics.median(samples),
            "min_ms": min(samples), "max_ms": max(samples)}
        local.stop()

        # ---------- 8) local streaming + context/tools ----------
        home = base / "stream"
        local = Mock("ok", "local-answer").start(base / "stream-local.log")
        write_config(home, "http://127.0.0.1:1",
                     "http://127.0.0.1:%d" % local.port, stream=True)
        r = run_ai(agent_dir, home, "你好",
                   env_extra={"AIKERNEL_ROUTE": "local"})
        logs = read_jsonl(base / "stream-local.log")
        check(r["rc"] == 0 and "local-answer" in r["out"] and
              any(x.get("stream") for x in logs),
              "stream: 本地流式路径可用")
        check(logs and logs[-1].get("num_ctx") == 32768 and
              logs[-1].get("tools", 0) >= 1,
              "stream: num_ctx=32768 + tools")
        results["scenarios"]["stream_local"] = {
            "stream_requests": sum(1 for x in logs if x.get("stream"))}
        local.stop()

        # ---------- 8b) local native tool_calls loop (exec_run) ----------
        home = base / "tools"
        local = Mock("ok", "local-answer", toolcall_once=True).start(
            base / "tools-local.log")
        write_config(home, "http://127.0.0.1:1",
                     "http://127.0.0.1:%d" % local.port)
        r = run_ai(agent_dir, home, "你好，做个自我介绍",
                   env_extra={"AIKERNEL_ROUTE": "local"})
        logs = read_jsonl(base / "tools-local.log")
        check(r["rc"] == 0 and "local-answer" in r["out"] and
              ("exec_run" in r["out"] or "Linux" in r["out"]),
              "tools: 本地原生 tool_calls 执行闭环",
              r["out"][-400:])
        check(len(logs) >= 2 and logs[0].get("tools", 0) >= 1 and
              logs[0].get("num_ctx") == 32768,
              "tools: 第二轮请求带工具结果 + 32768 ctx")
        results["scenarios"]["local_tools"] = {
            "requests": len(logs), "rc": r["rc"]}
        local.stop()

        # ---------- 9) trace completeness over all scenarios ----------
        all_events = []
        for p in base.rglob("route.jsonl"):
            all_events.extend(read_jsonl(p))
        decisions = [e for e in all_events if e.get("event") ==
                     "route_decision"]
        required = ("mode", "decision", "reason", "latency_ms", "provider",
                    "model")
        check(decisions and all(all(k in e for k in required)
                                for e in decisions),
              "trace: route_decision 字段完整",
              json.dumps(decisions[:1], ensure_ascii=False))
        check(no_key(json.dumps(all_events)), "trace: 全部 trace 无密钥")

        results["trace_events"] = len(all_events)
        results["decision_events"] = len(decisions)
        results["switch_events"] = sum(
            1 for e in all_events if e.get("event") == "route_switch")
    finally:
        shutil.rmtree(base, ignore_errors=True)

    print(json.dumps({k: v for k, v in results.items()
                      if k != "scenarios"}, ensure_ascii=False, indent=2))
    if args.out:
        Path(args.out).write_text(
            json.dumps(results, ensure_ascii=False, indent=2),
            encoding="utf-8")
    return 0 if results["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
