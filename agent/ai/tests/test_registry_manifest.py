#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
test_registry_manifest.py - W48 防呆断言自测（F1 形状漂移）

对 gen_registry.py 的逐名清单 + SHA-256 锚点做四种篡改：
  1. rename：改一个工具名（总数不变）
  2. delete：删一个工具（总数 -1）
  3. add：加一个工具（总数 +1）
  4. swap：删一个再加一个（总数不变，最接近 W47 F1 的真实漂移）
每种都必须 rc=2（SystemExit(2)），并打印多/少/改名 diff。
原样运行必须 rc=0（产物写临时目录，不碰正典）。
"""
import contextlib
import importlib.util
import io
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, "..", "tools", "gen_registry.py")


def load_mod():
    spec = importlib.util.spec_from_file_location("gen_registry_w48",
                                                  GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_main(mod, outdir):
    old_argv = sys.argv
    sys.argv = [GEN, "--out-dir", outdir]
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            mod.main()
        rc = 0
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else 1
    finally:
        sys.argv = old_argv
    return rc, err.getvalue()


def main():
    mod = load_mod()
    outdir = tempfile.mkdtemp(prefix="w48-manifest-")
    orig_build = mod.build_tools
    fails = 0

    def check(name, fn, want_rc, want_substr):
        nonlocal fails
        mod.build_tools = fn
        rc, err = run_main(mod, outdir)
        ok = (rc == want_rc) and (want_substr in err)
        print(("ok: " if ok else "FAIL: ") + name +
              " (rc=%d, expect=%d)" % (rc, want_rc))
        if not ok:
            fails += 1
            sys.stderr.write(err[-2000:] + "\n")

    # 原样：必须通过（证明锚点与当前生成结果一致）
    check("原样生成通过", orig_build, 0, "")

    # 1. rename：总数不变，靠逐名清单发现
    def renamed(procfs, sysfs):
        ts = orig_build(procfs, sysfs)
        ts[0]["name"] = "x_w48_renamed"
        return ts

    check("改名一个工具 → rc=2", renamed, 2, "工具名清单与锚点不一致")

    # 2. delete：总数断言先命中
    def deleted(procfs, sysfs):
        ts = orig_build(procfs, sysfs)
        return ts[:-1]

    check("删一个工具 → rc=2", deleted, 2, "主表工具数")

    # 3. add：总数断言先命中
    def added(procfs, sysfs):
        ts = orig_build(procfs, sysfs)
        t = dict(ts[-1])
        t["name"] = "x_w48_added"
        return ts + [t]

    check("加一个工具 → rc=2", added, 2, "主表工具数")

    # 4. swap：-1+1 总数不变，必须由逐名清单抓住（F1 复发形态）
    def swapped(procfs, sysfs):
        ts = orig_build(procfs, sysfs)
        ts = ts[:-1]
        t = dict(ts[0])
        t["name"] = "x_w48_swapped"
        return ts + [t]

    check("删一加一（总数不变）→ rc=2", swapped, 2,
          "工具名清单与锚点不一致")

    shutil.rmtree(outdir, ignore_errors=True)
    print("== test_registry_manifest: %s ==" %
          ("ALL PASS" if fails == 0 else "FAIL (%d)" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
