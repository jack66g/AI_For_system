#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
test_audit_occ_capabilities.py - audit_occ_capabilities.py 的最小自检（AIF-01b）

测什么
------
纯逻辑（只用临时目录里现写的小样本，不依赖实测证据）：
  1. 探测清单解析：注释行、空行跳过；格式不对要报错
  2. 实测 TSV 解析：元信息与数据行；输出首行和环境配置不入库；格式不对要报错
  3. 清单对行：同文重复的条目按先后各归各的；子集能对；顺序不对、清单里没有的要报错
  4. 现行静态判定的解析：cat 按路径、aikctl 按子命令，与对象读面同一种解析；
     实测更正登记（RULE_FIXES）与现行静态表一致
  5. 逐行判读：九种判定；(a)(b1)(b2)(c) 标记；注记钉住的结果变了，注记要自动失效
  6. 多份 TSV 并库：来源按采集时间排序，每批独立求值，JSON 往返不改变结果
依赖树内文件（探测清单、入库基线 JSON/MD）：
  7. 基线里的实测层自洽：拿原始行按现行规则重算，与基线里存的判读逐字段相同；
     分类与零字节判读合乎定义；证据出处齐全；对象级汇总自洽
  8. 入库 MD 与 JSON 同源：由基线 JSON 重渲染，与入库 MD 逐字节相同
  9. --check 通过（不带 TSV，实测层取自入库基线）；带了不是基线那份的 TSV 必须失败

用法
----
  python3 agent/ai/tools/test_audit_occ_capabilities.py
退出码：0 全过；1 有失败。不联网、不调 sudo、不跑 occ / aik-sandbox，只写临时目录。
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "audit_occ_capabilities.py")
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))


def load_mod():
    spec = importlib.util.spec_from_file_location("audit_occ_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_main(mod, args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = mod.main(args)
    return rc, out.getvalue()


def raises(fn, *a):
    try:
        fn(*a)
    except mod.ReachError as exc:
        return str(exc)
    return None


def tsv_text(rows, ts="2026-01-01T00:00:00+0000", columns=None, env=False):
    """rows 每项是 TSV 的 7 列：判定 命令 rc seconds 字节 occ_view 首行。"""
    columns = columns or mod.TSV_COLUMNS
    L = ["# occ_reach_probe\t%s" % ts,
         "# host=h\tkernel=6.18.39\tuid=0",
         "# aik_sandbox=/x/aik-sandbox\tsize=1111080",
         "# zone=z\tworkdir=/tmp/w\ttimeout=10s\tonly=all"]
    if env:
        L.append("# env AIKERNEL_SANDBOX_NET=none（会改变沙箱视图，对照静态表时请注意）")
    L.append("# columns: " + columns)
    L.append(columns.replace(" ", "\t"))
    for r in rows:
        L.append("\t".join(str(x) for x in r))
    return "\n".join(L) + "\n"


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def row(label, cmd, rc, nb):
    return {"label": label, "cmd": cmd, "rc": rc, "out_bytes": nb, "n": 0,
            "occ_view": "ok", "seconds": 0.01, "first_line": "x",
            "static_at_capture": label, "src": 0}


PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        sys.stdout.write("PASS %s\n" % name)
    else:
        FAIL += 1
        sys.stdout.write("FAIL %s%s\n" % (name, ("：" + detail) if detail else ""))


def expect_error(name, exc_text, needle):
    check(name, exc_text is not None and needle in (exc_text or ""),
          "应报错，实际=%r" % exc_text)


LIST_TXT = 'PROBE_LIST=(\n\t"ok"$\'\\t\'"echo ok"\n\t"no"$\'\\t\'"dpkg-query -W"\n' \
           '\t# 注释行\n\n\t"no"$\'\\t\'"dpkg-query -W"\n\t"view"$\'\\t\'"ls -la /"\n)\n'
ECHO = ("ok", "echo ok", 0, "0.01", 2, "ok", "ok")

mod = load_mod()
tmp = tempfile.mkdtemp(prefix="occ-audit-test-")
try:
    # ---- 1. 探测清单解析 ----
    ents = mod.parse_probe_list(LIST_TXT)
    check("1a 清单解析：条目与序号",
          [(e["n"], e["label"], e["cmd"]) for e in ents]
          == [(0, "ok", "echo ok"), (1, "no", "dpkg-query -W"),
              (2, "no", "dpkg-query -W"), (3, "view", "ls -la /")], repr(ents))
    expect_error("1b 清单解析：格式不对要报错",
                 raises(mod.parse_probe_list, 'PROBE_LIST=(\n\t"ok"\t"x"\n)\n'), "解析不了")
    expect_error("1c 清单解析：找不到清单要报错",
                 raises(mod.parse_probe_list, "# nothing here\n"), "找不到")
    probe = os.path.join(HERE, "occ_reach_probe.sh")
    with open(probe, encoding="utf-8") as f:
        real = mod.parse_probe_list(f.read())
    check("1d 真实清单：判定只取四种、命令非空、序号连续",
          all(e["label"] in mod.REACH_LABELS and e["cmd"] for e in real)
          and [e["n"] for e in real] == list(range(len(real))), "len=%d" % len(real))
    n_of = {}
    for e in real:
        n_of.setdefault(e["cmd"], e["n"])
    historical_only = {
        "curl -s -m 5 http://127.0.0.1:8091/api/stats",
        "curl -s -m 5 http://127.0.0.1:8091/api/theme",
        "aikctl session list", "cat /proc/ai/decisions", "cat /proc/ai/chains",
        "cat /sys/kernel/ai/model_out",
    }
    candidates = [e for e in real if e["cmd"] not in historical_only]
    listing = subprocess.check_output(["bash", probe, "--list"], text=True).splitlines()
    check("1e 可执行清单只排除历史六条，顺序保持",
          len(real) - len(candidates) == 6
          and listing == [e["label"] + "\t" + e["cmd"] for e in candidates])
    only = subprocess.check_output(
        ["bash", probe, "--only", "cat,curl,aikctl", "--list"], text=True).splitlines()
    check("1f --only 只在可执行集合内选择首 token",
          only == [entry for entry in listing
                   if entry.split("\t", 1)[1].split()[0] in {"cat", "curl", "aikctl"}])

    # ---- 2. TSV 解析 ----
    p = os.path.join(tmp, "a.tsv")
    write(p, tsv_text([
        ECHO,
        ("ok", "ifconfig -a", 0, "0.01", 20, "ok",
         "fixture-host-id 配置样例 fixture-token")], env=True))
    meta, rows = mod.parse_reach_tsv(p)
    check("2a TSV 元信息", (meta["collected_at"], meta["uid"], meta["kernel"],
                          meta["timeout"], meta["filtered"], meta["sandbox_size"],
                          meta["rows"], len(meta["sha256"]))
          == ("2026-01-01T00:00:00+0000", "0", "6.18.39", "10s", False, 1111080, 2, 64),
          repr(meta))
    check("2b TSV：置了会改视图的环境变量要记下来",
          meta["env_overrides"] is True and "env" not in meta, repr(meta))
    check("2c TSV：数据行字段",
          (rows[0]["cmd"], rows[0]["rc"], rows[0]["out_bytes"], rows[0]["occ_view"],
           rows[0]["static_at_capture"], rows[0]["seconds"])
          == ("echo ok", 0, 2, "ok", "ok", 0.01), repr(rows[0]))
    check("2d TSV：首行、主机名、文件名和配置值均不保留",
          all("first_line" not in r and "fixture-" not in repr(r) for r in rows)
          and "file" not in meta and "host" not in meta and "AIKERNEL_SANDBOX_NET" not in repr(meta))
    with open(p, "rb") as f:
        check("2e TSV：sha256 是整份文件字节的摘要",
              meta["sha256"] == mod.hashlib.sha256(f.read()).hexdigest())
    bad = os.path.join(tmp, "bad.tsv")
    cases = [
        ("2f 列名行缺失", tsv_text([ECHO], columns="something else here"), "列名行"),
        ("2g 少一列", tsv_text([ECHO]) + "ok\techo ok\t0\t2\tok\tok\n", "不是 7 列"),
        ("2h rc 不是数", tsv_text([("ok", "echo ok", "zero", "0.01", 2, "ok", "ok")]), "不是有效计数"),
        ("2i occ_view 不认识", tsv_text([("ok", "echo ok", 0, "0.01", 2, "weird", "ok")]), "不认识"),
        ("2j 没有数据行", tsv_text([]), "没有数据行"),
    ]
    for name, text, needle in cases:
        write(bad, text)
        expect_error(name, raises(mod.parse_reach_tsv, bad), needle)
    expect_error("2k 文件不存在", raises(mod.parse_reach_tsv, os.path.join(tmp, "missing.tsv")),
                 "读不了")
    marker = "fixture-sensitive-not-real"
    for column in (0, 5):
        malformed = list(ECHO)
        malformed[column] = marker
        write(bad, tsv_text([malformed]))
        err = raises(mod.parse_reach_tsv, bad)
        check("2l 未知标签报错不回显列 %d" % column,
              bool(err) and "bad.tsv" in err and "第 7 行" in err and marker not in err)

    # ---- 3. 清单对行 ----
    def al(entries, rows, filename):
        defaults = {entry["cmd"]: entry["label"] for entry in entries}
        return mod.align_reach(entries, [
            dict(row, static_at_capture=row.get("static_at_capture", defaults.get(row["cmd"])))
            for row in rows
        ], filename)

    duplicate = [{"cmd": "cat /proc/swaps", "label": label, "n": n}
                 for n, label in enumerate(("view", "ok"))]
    check("3b2 同命令不同标签按采集标签匹配",
          al(duplicate, [{"cmd": "cat /proc/swaps", "static_at_capture": "ok"}], "f")[0][0]["n"] == 1)
    check("3a 对行：同文重复条目按先后各归各的",
          [e["n"] for e, _ in al(ents, [{"cmd": "echo ok"}, {"cmd": "dpkg-query -W"},
                                        {"cmd": "dpkg-query -W"}, {"cmd": "ls -la /"}], "f")]
          == [0, 1, 2, 3])
    check("3b 对行：--only 过滤出的子集也能对",
          [e["n"] for e, _ in al(ents, [{"cmd": "dpkg-query -W"}, {"cmd": "ls -la /"}], "f")]
          == [1, 3])
    expect_error("3c 对行：清单里没有的命令要报错",
                 raises(al, ents, [{"cmd": "echo ok"}, {"cmd": "reboot"}], "f"), "对不上")
    expect_error("3d 对行：顺序与清单不一致要报错",
                 raises(al, ents, [{"cmd": "ls -la /"}, {"cmd": "echo ok"}], "f"), "对不上")
    write(bad, tsv_text([("ok", marker, 0, "0.01", 2, "ok", "")]))
    err = raises(mod.collect_reach, REPO, [bad])
    check("3e 不匹配的命令只报来源与条号",
          bool(err) and "bad.tsv" in err and "第 1 条数据" in err and marker not in err)

    # ---- 4. 现行静态判定 ----
    sv = mod.static_verdict_of
    check("4a cat 按路径求值", sv("cat /proc/meminfo")[0] == "ok" and "按路径" in sv("cat /proc/meminfo")[1],
          repr(sv("cat /proc/meminfo")))
    check("4b 普通命令取命令表", (sv("ps -eo pid,ppid,stat,comm"), sv("lsblk -J"))
          == (("no", ""), ("ok", "")), repr((sv("ps -eo pid,ppid,stat,comm"), sv("lsblk -J"))))
    check("4c aikctl 按子命令（长的优先）",
          [sv(x)[0] for x in ("aikctl session list", "aikctl policy get --json",
                              "aikctl policy get sudoers")] == ["no", "ok", "no"],
          repr([sv(x) for x in ("aikctl session list", "aikctl policy get --json",
                                "aikctl policy get sudoers")]))
    check("4d 静态表里没有的命令", sv("no-such-command --x")[0] is None)
    check("4d2 具体 ip 子命令优先，sudoers 样例档位与沙箱读面分开",
          sv("ip netns list")[0] == "no" and mod.classify_bash("aikctl policy get sudoers") == "W2")
    fixes_ok = bool(mod.RULE_FIXES)
    for n, before, after, _why in mod.RULE_FIXES:
        note = mod.REACH_NOTE_1710.get((before, mod.SBX[n]["sample"]))
        fixes_ok = fixes_ok and (mod.SBX[n]["verdict"] == after and before != after
                                 and note is not None and note.get("when") is not None)
    check("4e 实测更正登记（RULE_FIXES）：改后就是现行判定、改前确实不同、"
          "每条更正背后都有钉住了实测结果的判读",
          fixes_ok,
          repr([(n, before, after, mod.SBX.get(n, {}).get("verdict"))
                for n, before, after, _why in mod.RULE_FIXES]))

    # ---- 5. 逐行判读（换上小号的静态表与判读注记，结论不随真表变动）----
    saved = mod.SBX, mod.REACH_NOTES
    try:
        mod.SBX = {"echo": {"verdict": "ok"}, "who": {"verdict": "no"},
                   "ethtool": {"verdict": "no"}}
        notes = {
            ("ok", "who"): mod._note((0, 5), "ok", "host", why="钉在 rc=0、5 字节上"),
            ("no", "who"): mod._note((0, 0), "empty", why="零字节", empty="blocked"),
        }
        mod.REACH_NOTES = {mod.CAPTURE_1710: notes}

        def J(label, cmd, rc, nb):
            return mod.judge_reach(row(label, cmd, rc, nb), mod.CAPTURE_1710)

        j = J("ok", "echo ok", 0, 2)
        check("5a 非空成功输出仍须判读", (j["m"], j["data"], j["cls"], j["trunc"])
              == ("unreviewed", "none", [], False), repr(j))
        notes[("ok", "echo ok")] = mod._note((0, 9000), "ok", "host")
        check("5b 已判读且超 8KB", J("ok", "echo ok", 0, 9000)["trunc"] is True)
        recent = mod.judge_reach(row("ok", "who", 0, 5), mod.CAPTURE_17111)
        check("5b2 新采集同字节数也不沿用历史注记", recent["m"] == "unreviewed")
        check("5c rc=1 → fail，静态 ok → 类 a",
              (lambda d: (d["m"], d["cls"]))(J("ok", "echo ok", 1, 40)) == ("fail", ["a"]))
        check("5d rc=2 → fail", J("ok", "echo ok", 2, 0)["m"] == "fail")
        check("5e rc=127 → missing", J("no", "ethtool eth0", 127, 70)["m"] == "missing")
        check("5f rc=137 → timeout", J("ok", "echo ok", 137, 0)["m"] == "timeout")
        check("5g rc=100 → error", J("ok", "echo ok", 100, 584)["m"] == "error")
        j = J("ok", "who", 0, 5)
        check("5h 注记生效：静态 no、实测读到 → b1", (j["m"], j["data"], j["cls"])
              == ("ok", "host", ["b1"]), repr(j))
        j = J("no", "who", 0, 0)
        check("5i 零字节且静态 no → b2 + c，判读为被挡",
              (j["m"], j["empty"], j["cls"]) == ("empty", "blocked", ["b2", "c"]), repr(j))
        j = J("ok", "echo ok", 0, 0)
        check("5j 零字节且静态 ok → a + c，没有判读就是未定",
              (j["m"], j["empty"], j["cls"]) == ("empty", "undetermined", ["a", "c"]), repr(j))
        j = J("no", "ethtool eth0", 0, 0)
        check("5k 零字节且静态 no → b2 + c，没有判读就是未定", (j["m"], j["empty"], j["cls"])
              == ("empty", "undetermined", ["b2", "c"]), repr(j))
        j = J("ok", "who", 0, 9)
        check("5l 结果与注记钉的不一样 → 注记失效、不套用",
              (j["stale"], j["m"], j["empty"], j["why"] != "") == (True, "unreviewed", "", True),
              repr(j))
        j = J("view", "ls -la /", 0, 754)
        check("5m 视图探针不参与分类", (j["m"], j["cls"], j["snow"]) == ("view", [], None), repr(j))
    finally:
        mod.SBX, mod.REACH_NOTES = saved

    # ---- 6. 多份 TSV：同一命令在两份采集里保留独立证据 ----
    a = os.path.join(tmp, "old.tsv")
    b = os.path.join(tmp, "new.tsv")
    uptime = ("ok", "uptime", 0, "0.01", 68, "ok", "load")
    write(a, tsv_text([ECHO, uptime, ("no", "who", 0, "0.01", 0, "ok", "")],
                      ts="2026-01-01T00:00:00+0000"))
    write(b, tsv_text([("ok", "echo ok", 1, "0.01", 30, "sb_fail", "boom"), uptime],
                      ts="2026-02-01T00:00:00+0000"))
    mixed = mod.collect_reach(REPO, [b, a])                 # 故意把新的放前面
    old, new = mixed["sources"]
    check("6a 来源按采集时间排新旧",
          [s["collected_at"][:10] for s in (old, new)] == ["2026-01-01", "2026-02-01"])
    rep = mod.build_report(REPO, "no")
    saved_notes = mod.REACH_NOTES
    try:
        mod.REACH_NOTES = {old["sha256"]: {("ok", "uptime"): mod._note((0, 68), "ok")}}
        mixed["derived"] = mod.derive_reach(mixed, rep["objects"]["root"])
    finally:
        mod.REACH_NOTES = saved_notes
    d1, d2 = mixed["derived"]["captures"]
    s1, s2 = d1["summary"], d2["summary"]
    r1, r2 = dict(s1["observed"]), dict(s2["observed"])
    check("6b 重复探针在两个来源独立记录",
          mixed["rows"][r1[n_of["echo ok"]]]["rc"] == 0
          and mixed["rows"][r2[n_of["echo ok"]]]["rc"] == 1)
    check("6c 只有编号覆盖取跨批并集",
          mixed["derived"]["pending"] == [n for n in range(len(real)) if n not in (r1.keys() | r2.keys())])
    check("6d 新批对象结论不借用旧批；相同返回码和长度也不能复用注记",
          d1["objects"]["RES-02"]["v"] == "read" and d2["objects"]["RES-02"]["v"] == "unresolved")
    check("6d2 不同批次的差异列表独立",
          s1["a"] == [] and s1["b2"] == [n_of["who"]] and s1["c"] == [n_of["who"]]
          and s2["a"] == [n_of["echo ok"]] and s2["b1"] == s2["b2"] == s2["c"] == [])
    expect_error("6d3 拒绝重复导入同一份采集", raises(mod.collect_reach, REPO, [a, a]), "重复")
    pub = mod.reach_public(mixed)
    check("6e 实测层只写公开来源、计数与逐批紧凑判读",
          sorted(pub) == ["derived", "probe_list", "rows", "schema", "sources"]
          and sorted(pub["derived"]) == ["captures", "notes_sha256", "pending", "rows"]
          and len(pub["derived"]["rows"][0]) == 7)
    again = json.loads(json.dumps(pub, ensure_ascii=False))
    d = mod.diff_json(again, pub)
    check("6f 判读结果过 JSON 往返不变", d == [], "; ".join(d[:3]))

    # ---- 7–9. 树内的入库基线 ----
    bj = os.path.join(REPO, "agent", "ai", "docs", "OCC-CAPABILITY-BASELINE.json")
    bm = os.path.join(REPO, "agent", "ai", "docs", "OCC-CAPABILITY-BASELINE.md")
    with open(bj, encoding="utf-8") as f:
        base = json.load(f)
    check("7a 基线里有实测层", isinstance(base.get("reach"), dict))
    if isinstance(base.get("reach"), dict):
        stored = base["reach"]
        reach = mod.reach_from_baseline(REPO, stored)
        reach["derived"] = mod.derive_reach(reach, rep["objects"]["root"])
        pub2 = mod.reach_public(reach)
        d = mod.diff_json(stored, pub2)
        check("7b 原始行按现行规则重算 == 基线里存的判读", d == [], "; ".join(d[:3]))
        rows, drows = reach["rows"], reach["derived"]["rows"]
        for index, capture in enumerate(reach["derived"]["captures"]):
            S, O = capture["summary"], capture["summary"]["obj"]
            rs = {n: rows[i] for n, i in S["observed"]}
            ds = {n: drows[i] for n, i in S["observed"]}
            tag = "7[%d]" % index
            zero = sorted(n for n, r in rs.items()
                          if r["rc"] == 0 and r["out_bytes"] == 0 and r["label"] != "view")
            check(tag + "c 类 c 等于非视图探针的零长度成功行",
                  S["c"] == zero and sorted(n for n, _ in S["empty"]) == zero)
            check(tag + "d 判定总数与该批数据行数一致",
                  sum(S["m"].values()) + S["n_view"] == reach["sources"][index]["rows"]
                  and set(S["m"]) == set(mod.M_OF) - {"view"})
            rc0 = sorted(n for n, r in rs.items()
                         if ds[n]["snow"] == "no" and r["rc"] == 0
                         and ds[n]["m"] not in mod.UNDETERMINED)
            check(tag + "e 类别与静态判定、返回码和数据判定一致",
                  sorted(S["b1"] + S["b2"]) == rc0
                  and all(ds[n]["m"] in mod.READABLE for n in S["b1"])
                  and all(ds[n]["m"] not in mod.READABLE for n in S["b2"])
                  and S["a"] == sorted(n for n, row in ds.items()
                                      if row["snow"] in ("ok", "partial")
                                      and row["m"] not in (*mod.READABLE, *mod.UNDETERMINED)
                                      and row["empty"] != "na"))
            check(tag + "f 未定零长度记录有补测说明",
                  all(ds[n]["todo"] for n, code in S["empty"] if code == "undetermined"))
            check(tag + "g 摘要下既有注记全部匹配返回值和长度", not S["stale"])
            check(tag + "i 只含本批次编号且按清单递增",
                  all(r["src"] == index and "first_line" not in r for r in rs.values())
                  and list(rs) == sorted(rs) and len(rs) == len(set(rs)))
            check(tag + "j 对象级汇总自洽",
                  O["static_reachable"] == sum(1 for o in rep["objects"]["root"]
                                               if o["read_any"] and o["status"] != "n/a")
                  and sum(len(O[k]) for k in ("read", "partial", "untested", "unreadable",
                                               "unresolved")) == O["static_reachable"]
                  and sum(len(O[k]) for k in ("confirmed", "orphan", "reopened"))
                  == O["applicable"] - O["static_reachable"]
                  and O["applicable"] + len(O["na"]) == len(rep["objects"]["root"]))
        check("7h 两批原始 SHA-256、时间、UID、超时和数量齐全",
              len(stored["sources"]) == 2
              and {s["sha256"] for s in stored["sources"]} == set(mod.CAPTURE_VERSIONS)
              and all(s["collected_at"] and s["uid"] == "0" and s["timeout"]
                      for s in stored["sources"])
              and sum(s["rows"] for s in stored["sources"]) == len(stored["rows"]))
        fresh = next(cap for s, cap in zip(stored["sources"], reach["derived"]["captures"])
                     if s["sha256"] == mod.CAPTURE_17111)
        fresh_rows = fresh["summary"]["observed"]
        fresh_objs = fresh["objects"]
        check("7k 新批 69 条都有该摘要下的人工注记",
              len(fresh_rows) == len(mod.REACH_NOTE_17111) == 69
              and all((rows[i]["label"], rows[i]["cmd"]) in mod.REACH_NOTE_17111 for _, i in fresh_rows))
        check("7l 空表、沙箱视图、硬件元数据与对象部分有证各自按含义判读",
              fresh_objs["DT-02"]["v"] == "unresolved"
              and fresh_objs["DISK-02"]["v"] == "unresolved"
              and fresh_objs["HW-05"]["v"] == "unresolved"
              and fresh_objs["AI-06"]["v"] == "partial"
              and fresh_objs["ID-05"]["v"] == "partial")
        with open(bm, encoding="utf-8", newline="") as f:
            want = f.read()
        md = mod.render_markdown(dict(rep, reach=reach))
        first = next((i + 1 for i, (x, y) in enumerate(zip(md.split("\n"), want.split("\n")))
                      if x != y), -1)
        check("8 入库 MD 与 JSON 同源（由基线重渲染逐字节相同）", md == want,
              "行数 现在=%d 入库=%d，首个差异在第 %d 行" % (len(md.split("\n")),
                                                   len(want.split("\n")), first))
    rc_, out = run_main(mod, ["--check", "--repo", REPO])
    check("9 --check 通过（不带 TSV，实测层取自入库基线）",
          rc_ == 0 and "OCC CHECK PASS" in out and "reach:" in out, out.strip()[:300])
    rc_, out = run_main(mod, ["--check", "--repo", REPO, "--reach-tsv", a])
    check("9b 带 --reach-tsv 但 TSV 不是基线那份 → 必须失败",
          rc_ == 1 and "OCC CHECK FAIL" in out and "reach." in out, out[:300])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

sys.stdout.write("\n%d passed, %d failed\n" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
