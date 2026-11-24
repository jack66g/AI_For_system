#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
test_audit_occ_capabilities.py - audit_occ_capabilities.py 的最小自检（AIF-01b）

测什么
------
纯逻辑（只用临时目录里现写的小样本，不依赖实测证据）：
  1. 探测清单解析：注释行、空行跳过；格式不对要报错
  2. 实测 TSV 解析：元信息与数据行；MAC、非回环 IPv4 入库前掩掉；格式不对要报错
  3. 清单对行：同文重复的条目按先后各归各的；子集能对；顺序不对、清单里没有的要报错
  4. 现行静态判定的解析：cat 按路径、aikctl 按子命令，与对象读面同一种解析
  5. 逐行判读：九种判定；(a)(b1)(b2)(c) 标记；注记钉住的结果变了，注记要自动失效
  6. 多份 TSV 并库：来源按采集时间排新旧，同一条目取最新一次；结果过 JSON 往返不变
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
    with open(os.path.join(HERE, "occ_reach_probe.sh"), encoding="utf-8") as f:
        real = mod.parse_probe_list(f.read())
    check("1d 真实清单：判定只取四种、命令非空、序号连续",
          all(e["label"] in mod.REACH_LABELS and e["cmd"] for e in real)
          and [e["n"] for e in real] == list(range(len(real))), "len=%d" % len(real))
    n_of = {}
    for e in real:
        n_of.setdefault(e["cmd"], e["n"])

    # ---- 2. TSV 解析 ----
    p = os.path.join(tmp, "a.tsv")
    write(p, tsv_text([
        ECHO,
        ("ok", "ifconfig -a", 0, "0.01", 20, "ok",
         "eth0 HWaddr 00:0C:29:19:B2:4E from 192.168.1.9 to 127.0.0.1")], env=True))
    meta, rows = mod.parse_reach_tsv(p)
    check("2a TSV 元信息", (meta["collected_at"], meta["uid"], meta["kernel"],
                          meta["timeout"], meta["only"], meta["sandbox_size"],
                          meta["file"], meta["rows"], len(meta["sha256"]))
          == ("2026-01-01T00:00:00+0000", "0", "6.18.39", "10s", "all", 1111080, "a.tsv", 2, 64),
          repr(meta))
    check("2b TSV：置了会改视图的环境变量要记下来",
          meta["env"] == ["AIKERNEL_SANDBOX_NET=none"], repr(meta["env"]))
    check("2c TSV：数据行字段",
          (rows[0]["cmd"], rows[0]["rc"], rows[0]["out_bytes"], rows[0]["occ_view"],
           rows[0]["static_at_capture"], rows[0]["first_line"], rows[0]["seconds"])
          == ("echo ok", 0, 2, "ok", "ok", "ok", 0.01), repr(rows[0]))
    check("2d TSV：MAC 与非回环 IPv4 掩掉，回环地址保留",
          rows[1]["first_line"] == "eth0 HWaddr XX:XX:XX:XX:XX:XX from x.x.x.x to 127.0.0.1",
          repr(rows[1]["first_line"]))
    with open(p, "rb") as f:
        check("2e TSV：sha256 是整份文件字节的摘要",
              meta["sha256"] == mod.hashlib.sha256(f.read()).hexdigest())
    bad = os.path.join(tmp, "bad.tsv")
    cases = [
        ("2f 列名行缺失", tsv_text([ECHO], columns="something else here"), "列名行"),
        ("2g 少一列", tsv_text([ECHO]) + "ok\techo ok\t0\t2\tok\tok\n", "不是 7 列"),
        ("2h rc 不是数", tsv_text([("ok", "echo ok", "zero", "0.01", 2, "ok", "ok")]), "不是数"),
        ("2i occ_view 不认识", tsv_text([("ok", "echo ok", 0, "0.01", 2, "weird", "ok")]), "不认识"),
        ("2j 没有数据行", tsv_text([]), "没有数据行"),
    ]
    for name, text, needle in cases:
        write(bad, text)
        expect_error(name, raises(mod.parse_reach_tsv, bad), needle)
    expect_error("2k 文件不存在", raises(mod.parse_reach_tsv, os.path.join(tmp, "missing.tsv")),
                 "读不了")

    # ---- 3. 清单对行 ----
    al = mod.align_reach
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

    # ---- 5. 逐行判读（换上小号的静态表与判读注记，结论不随真表变动）----
    saved = mod.SBX, mod.REACH_NOTE
    try:
        mod.SBX = {"echo": {"verdict": "ok"}, "who": {"verdict": "no"},
                   "ethtool": {"verdict": "no"}}
        mod.REACH_NOTE = {
            ("ok", "who"): mod._note((0, 5), "ok", "host", why="钉在 rc=0、5 字节上"),
            ("no", "who"): mod._note((0, 0), "empty", why="零字节", empty="blocked"),
        }

        def J(label, cmd, rc, nb):
            return mod.judge_reach(row(label, cmd, rc, nb))

        j = J("ok", "echo ok", 0, 2)
        check("5a 读到宿主数据", (j["m"], j["data"], j["cls"], j["trunc"])
              == ("ok", "host", [], False), repr(j))
        check("5b 读到但超 8KB", J("ok", "echo ok", 0, 9000)["trunc"] is True)
        check("5c rc=1 → fail，静态 ok → 类 a",
              (lambda d: (d["m"], d["cls"]))(J("ok", "echo ok", 1, 40)) == ("fail", ["a"]))
        check("5d rc=2 → fail", J("ok", "echo ok", 2, 0)["m"] == "fail")
        check("5e rc=127 → missing", J("no", "ethtool eth0", 127, 70)["m"] == "missing")
        check("5f rc=137 → timeout", J("ok", "echo ok", 137, 0)["m"] == "timeout")
        check("5g rc=100 → error", J("ok", "echo ok", 100, 584)["m"] == "error")
        j = J("no", "who", 0, 5)
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
              (j["stale"], j["m"], j["empty"], j["why"] != "") == (True, "ok", "", True),
              repr(j))
        j = J("view", "ls -la /", 0, 754)
        check("5m 视图探针不参与分类", (j["m"], j["cls"], j["snow"]) == ("view", [], None), repr(j))
    finally:
        mod.SBX, mod.REACH_NOTE = saved

    # ---- 6. 多份 TSV 并库（用树内的真实探测清单）----
    a = os.path.join(tmp, "old.tsv")
    b = os.path.join(tmp, "new.tsv")
    write(a, tsv_text([ECHO, ("no", "who", 0, "0.01", 0, "ok", "")], ts="2026-01-01T00:00:00+0000"))
    write(b, tsv_text([("ok", "echo ok", 1, "0.01", 30, "sb_fail", "boom"),
                       ("ok", "uptime", 0, "0.01", 68, "ok", "load")],
                      ts="2026-02-01T00:00:00+0000"))
    mixed = mod.collect_reach(REPO, [b, a])                 # 故意把新的放前面
    check("6a 来源按采集时间排新旧",
          [s["collected_at"][:10] for s in mixed["sources"]] == ["2026-01-01", "2026-02-01"]
          and [s["file"] for s in mixed["sources"]] == ["old.tsv", "new.tsv"], repr(mixed["sources"]))
    rep = mod.build_report(REPO, "no")
    mixed["derived"] = mod.derive_reach(mixed, rep["objects"]["root"])
    S = mixed["derived"]["summary"]
    lat = dict(S["latest"])
    R = mixed["rows"]
    e = R[lat[n_of["echo ok"]]]
    check("6b 同一条目取最新一次（echo ok 在新的一份里 rc=1）", (e["rc"], e["src"]) == (1, 1), repr(e))
    check("6c 两次采集都留档，没采到的条目进待补测清单",
          len(R) == 4 and S["pending"] == [n for n in range(len(real)) if n not in lat],
          "rows=%d" % len(R))
    check("6d 分类用的是最新一次：echo ok → a，who → b2 + c，uptime 不入类",
          S["a"] == [n_of["echo ok"]] and S["b2"] == [n_of["who"]] and S["b1"] == []
          and S["c"] == [n_of["who"]]
          and all(n_of["uptime"] not in S[k] for k in ("a", "b1", "b2", "c")), repr(
              {k: S[k] for k in ("a", "b1", "b2", "c")}))
    pub = mod.reach_public(mixed)
    check("6e 写回基线的实测层只含来源、原始行、紧凑判读",
          sorted(pub) == ["derived", "probe_list", "rows", "schema", "sources"]
          and sorted(pub["derived"]) == ["notes_sha256", "rows", "summary"]
          and len(pub["derived"]["rows"][0]) == 7, repr(sorted(pub)))
    # 基线里的存档是 JSON 来的：判读结果过一遍 JSON 再回来必须不变，否则 --check 会误报
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
        S, O = reach["derived"]["summary"], reach["derived"]["summary"]["obj"]
        lat = dict(S["latest"])
        rows, drows = reach["rows"], reach["derived"]["rows"]
        m_of = dict((x["n"], x["m"]) for x in drows)
        zero = sorted(n for n, i in lat.items()
                      if rows[i]["rc"] == 0 and rows[i]["out_bytes"] == 0)
        check("7c 类 c 恰为 rc=0 且零字节的条目，且每条都带着判读",
              S["c"] == zero and sorted(n for n, _ in S["empty"]) == zero
              and all(code for _, code in S["empty"]), repr((S["c"], S["empty"])))
        all_m = set(mod.M_OF) - {"view"}
        check("7d 九种判定的计数 = 已采的命令条目数（视图探针另计）",
              sum(S["m"].values()) + S["n_view"] == len(lat)
              and set(S["m"]) == all_m, repr((S["m"], S["n_view"], len(lat))))
        rc0 = sorted(n for n in lat if drows[lat[n]]["snow"] == "no" and rows[lat[n]]["rc"] == 0)
        check("7e 类 b 恰为「静态判 no 且 rc=0」的条目，读到的归 b1、没读到的归 b2",
              sorted(S["b1"] + S["b2"]) == rc0
              and all(m_of[n] in mod.READABLE for n in S["b1"])
              and all(m_of[n] not in mod.READABLE for n in S["b2"])
              and S["a"] == sorted(n for n in lat
                                   if drows[lat[n]]["snow"] in ("ok", "partial")
                                   and m_of[n] not in mod.READABLE),
              repr((S["a"], S["b1"], S["b2"])))
        undetermined = [n for n, code in S["empty"] if code == "undetermined"]
        check("7f 零字节里标「未定」的都带了补测动作",
              all(drows[lat[n]]["todo"] for n in undetermined), repr(undetermined))
        check("7g 注记没有失效的（失效 = 实测结果变了、判读要人重看）", S["stale"] == [],
              repr(S["stale"]))
        check("7h 证据出处齐全：文件名、sha256、行数、采集时间、身份、超时",
              bool(stored["sources"])
              and all(len(s["sha256"]) == 64 and s["rows"] > 0 and s["collected_at"]
                      and s["uid"] == "0" and s["timeout"] for s in stored["sources"])
              and sum(s["rows"] for s in stored["sources"]) == len(stored["rows"]),
              repr(stored["sources"]))
        check("7i 各来源的 sha256 互不相同、同一来源内序号递增、没有超清单范围的序号",
              len(set(s["sha256"] for s in stored["sources"])) == len(stored["sources"])
              and all(stored["rows"][i]["n"] < stored["rows"][i + 1]["n"]
                      for i in range(len(stored["rows"]) - 1)
                      if stored["rows"][i]["src"] == stored["rows"][i + 1]["src"])
              and all(0 <= x["n"] < stored["probe_list"]["entries"] for x in stored["rows"]))
        check("7j 对象级汇总自洽",
              O["static_reachable"] == sum(1 for o in rep["objects"]["root"]
                                           if o["read_any"] and o["status"] != "n/a")
              and (len(O["read"]) + len(O["partial"]) + len(O["untested"])
                   + len(O["unreadable"]) + len(O["unresolved"])) == O["static_reachable"]
              and (len(O["confirmed"]) + len(O["orphan"]) + len(O["reopened"]))
              == O["applicable"] - O["static_reachable"]
              and O["applicable"] + len(O["na"]) == len(rep["objects"]["root"]),
              repr({k: (len(v) if isinstance(v, list) else v) for k, v in O.items()}))
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
