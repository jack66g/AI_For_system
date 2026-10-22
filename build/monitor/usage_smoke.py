#!/usr/bin/env python3
"""W62 smoke: run real one-shot user scenarios against the production VM.

Read-only except scenario 6/11 which use /tmp and the sandbox.
Evidence: ~/aikernel-longterm/evidence/usage-smoke/
"""
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

VM = "root@192.168.245.138"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
       "-o", "ConnectTimeout=10", VM]
OUT = Path.home() / "aikernel-longterm/evidence/usage-smoke"
OUT.mkdir(parents=True, exist_ok=True)

SCEN = [
    ("cognitive-01", "这个系统是什么？我该怎么使用它？", 180),
    ("diag-02", "查看系统负载、内存和根分区使用率，给出简要结论", 180),
    ("net-03", "列出当前监听端口，并指出哪些是对外服务", 180),
    ("logs-04", "检查最近 10 分钟有没有内核错误或服务失败", 180),
    ("procs-05", "列出占用内存最高的 5 个进程", 180),
    ("file-06", "在 /tmp/aik-usage-1 下创建 hello.c，编译运行并给出输出", 240),
    ("memory-07", "搜索长期记忆里关于 AIKernel 稳定化计划的内容", 180),
    ("disk-08", "找出 /var/log 下最大的 3 个文件并说明能否清理", 180),
    ("services-09", "当前有哪些 AI 相关服务在运行？各自监听什么端口？", 180),
    ("combo-10", "请说明 exec_run 与 procfs_read_status 的区别，各举一个使用场景", 180),
    ("sandbox-11", "创建一个隔离区，在里面运行 uname -a，然后销毁它", 240),
]


def trace_files():
    r = subprocess.run(SSH + ["ls -1t /var/log/aikernel/trace/ 2>/dev/null | head -5"],
                       capture_output=True, text=True, timeout=60)
    return [x for x in r.stdout.split() if x.endswith(".jsonl")]


def main():
    only = sys.argv[1:] or None
    results = []
    for idx, (name, prompt, timeout) in enumerate(SCEN):
        if only and name not in only:
            continue
        before = set(trace_files())
        t0 = time.time()
        remote = ("cd /root && AIKERNEL_ASSUME_YES=1 NO_COLOR=1 timeout %d ai -p %s 2>&1"
                  % (timeout, shlex.quote(prompt)))
        try:
            p = subprocess.run(SSH + [remote], capture_output=True, text=True,
                               timeout=timeout + 60)
            rc, out, err = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            rc = 124
            out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            err = "ssh-harness-timeout"
        dur = round(time.time() - t0, 1)
        after = trace_files()
        new_traces = [t for t in after if t not in before]
        slug = name
        (OUT / f"{idx:02d}-{slug}.out").write_text(
            "PROMPT: %s\nRC: %s\nDURATION: %ss\nTRACE: %s\n\n%s\n\nSTDERR:\n%s\n"
            % (prompt, rc, dur, ",".join(new_traces), out, err), encoding="utf-8")
        rec = {"idx": idx, "name": name, "prompt": prompt, "rc": rc,
               "duration_s": dur, "out_len": len(out), "traces": new_traces,
               "timeout_s": timeout}
        results.append(rec)
        print(json.dumps(rec, ensure_ascii=False), flush=True)
    (OUT / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=1),
                                      encoding="utf-8")
    ok = sum(1 for r in results if r["rc"] == 0)
    print("DONE ok=%d/%d" % (ok, len(results)), flush=True)


if __name__ == "__main__":
    main()
