#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_corpus_aliases.py - W55 P4：SME 语料口语别名自检。

实机缺陷：query「记忆库统计」在 352 条新旧混合语料里 top3 被旧点号
条目占据（memory_stats 排第 5）。修复：单件文本补口语别名、区头补
同义问法；memory_stats 别名行重复 3 次以对抗旧条目词频密度。

本测试不依赖 SME 服务，只校验出厂 seed 的静态契约（145 条、
memory_* 全带别名、memory_stats 必备问法齐全）。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED = os.path.join(ROOT, "tools", "sme-seed-w51.jsonl")

MUST = ["记忆库统计", "记忆数量", "记忆条数", "统计信息", "数据库统计"]


def main() -> int:
    with open(SEED, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
    fails = 0

    def check(cond, msg):
        nonlocal fails
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        if not cond:
            fails += 1

    print("==== test_corpus_aliases: W55 P4 ====")
    check(len(records) == 167, "seed 为 167 条（区头 8 + 单件 151 + 配方 8）")
    kinds = {}
    for rec in records:
        kind = (rec.get("metadata") or {}).get("kind")
        kinds[kind] = kinds.get(kind, 0) + 1
    check(kinds == {"domain-header": 8, "tool": 151, "combo": 8},
          "kind 分布 = %r" % kinds)

    tools = [r for r in records if (r.get("metadata") or {}).get("kind") == "tool"]
    mem_tools = [r for r in tools
                 if (r["metadata"].get("name") or "").startswith("memory_")]
    check(len(mem_tools) == 30, "memory_* 单件 = 30（实际 %d）" % len(mem_tools))
    missing = [r["metadata"]["name"] for r in mem_tools
               if "常见问法/口语别名" not in r["text"]]
    check(not missing, "30 件 memory_* 均含口语别名行（缺 %r）" % missing)

    ms = [r for r in mem_tools if r["metadata"].get("name") == "memory_stats"]
    check(len(ms) == 1, "memory_stats 单件存在")
    if ms:
        text = ms[0]["text"]
        for word in MUST:
            check(word in text, "memory_stats 含问法「%s」" % word)
        check(text.count("常见问法/口语别名") == 3,
              "memory_stats 别名行重复 3 次（抗旧条目词频密度）")
        check("GET /stats" in text, "memory_stats 仍保留接口说明 GET /stats")

    header = [r for r in records
              if (r.get("metadata") or {}).get("kind") == "domain-header" and
              (r.get("metadata") or {}).get("sub") == "memory"]
    check(len(header) == 1, "memory 区头存在")
    if header:
        check("常见同义问法" in header[0]["text"], "memory 区头含同义问法行")
        for word in ("记忆库统计", "记忆数量", "数据库统计"):
            check(word in header[0]["text"], "memory 区头含「%s」" % word)

    print("RESULT: %s" % ("PASS" if fails == 0 else "FAIL (%d)" % fails))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
