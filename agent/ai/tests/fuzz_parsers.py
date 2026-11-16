#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fuzz_parsers.py — G1 解析器 fuzz（run_all 第 68 门）。
三族目标 × 确定性种子变异（位翻/截断/键重复/乱字节）：
  A. aikctl dataset list —— 变异 parquet 字节（读者 thrift/footer 容错）
  B. aipd --check-conf   —— 变异 conf 行（键值域解析器）
  C. aikctl audit verify —— 变异 jsonl 节点行（72B 节点解析）
判定：每例退出码 ∈ {0,1,2} 且 stderr 无 Traceback、无段杀（rc≥128/
信号）——崩溃=红；人话报错=绿（诚实失败非崩溃）。"""
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "..")
AIKCTL = os.path.join(AGENT, "aikctl", "aikctl")
AIPD = os.path.join(AGENT, "aipd", "aipd")
CASES_PER_TARGET = int(os.environ.get("FUZZ_CASES", "40"))
SEED = 20261117


def mutate(data, rng):
    if not data:
        return b"\x00" * 8
    b = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op = rng.randint(0, 3)
        i = rng.randrange(len(b))
        if op == 0:
            b[i] ^= 1 << rng.randrange(8)
        elif op == 1:
            b[i] = rng.randrange(256)
        elif op == 2 and len(b) > 8:
            del b[i:i + rng.randint(1, 16)]
        else:
            b.insert(i, rng.randrange(256))
    return bytes(b[:max(1, len(b) - rng.randint(0, 32))])


def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=30)
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
        return r.returncode, out
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def crashfree(rc, out):
    return rc in (0, 1, 2) and "Traceback" not in out


def main():
    rng = random.Random(SEED)
    tmp = tempfile.mkdtemp(prefix="fuzz-")
    bad = []
    total = 0
    try:
        # ---- A. parquet 读者 ----
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
            base = os.path.join(tmp, "a.parquet")
            t = pa.table({"timestamp_ns": [1, 2], "pid": [1, 2],
                          "data": ["x", "y"]})
            pq.write_table(t, base)
            seed = open(base, "rb").read()
            have_a = True
        except ImportError:
            have_a = False
        if have_a:
            for i in range(CASES_PER_TARGET):
                p = os.path.join(tmp, "a%d.parquet" % i)
                with open(p, "wb") as f:
                    f.write(mutate(seed, rng))
                rc, out = run([sys.executable, AIKCTL, "dataset", "list",
                               "--layer", "curated", "--root", tmp])
                total += 1
                if not crashfree(rc, out):
                    bad.append(("parquet", i, rc, out[-160:]))
        # ---- B. aipd conf ----
        base_conf = ("FEAT_SOURCE=mock\nPOLL_HZ=10\nSHADOW=1\n"
                     "CANARY_ENABLED=0\nCANARY_ROLLBACK_MS=30000\n")
        for i in range(CASES_PER_TARGET):
            c = os.path.join(tmp, "c.conf")
            with open(c, "wb") as f:
                f.write(mutate(base_conf.encode(), rng))
            rc, out = run([AIPD, "--check-conf", "--conf", c])
            total += 1
            if not crashfree(rc, out):
                bad.append(("aipd_conf", i, rc, out[-160:]))
        # ---- C. audit jsonl 节点 ----
        node = ('{"seq":1,"ts":123,"kind":1,"flags":0,"prev":"ab",'
                '"self_hash":"cd","data":"0000000000000000"}\n')
        for i in range(CASES_PER_TARGET):
            j = os.path.join(tmp, "n.jsonl")
            with open(j, "wb") as f:
                f.write(b'{"meta":"k"}\n' + mutate(node.encode(), rng))
            rc, out = run([sys.executable, AIKCTL, "audit", "verify",
                           "-e", j])
            total += 1
            if not crashfree(rc, out):
                bad.append(("audit_jsonl", i, rc, out[-160:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for t in bad[:5]:
        print("CRASH %s #%d rc=%s :: %s" % t)
    print("FUZZ_SUMMARY cases=%d crash=%d %s"
          % (total, len(bad), "PASS" if not bad else "FAIL"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
