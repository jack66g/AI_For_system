#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_t9e_entry.py - T9e 出厂入口换代静态门（repo 侧，零 rootfs 依赖）

背景（OPENCODE-PLAN §0 用户裁定 #1 / T9e 交付 A）：aikernel-shell 出厂
移除，默认入口 = occ。本测试守两处 repo 正典不回退：

  1) agent/ai/build-rootfs.sh —— .profile 模板的控制台 exec 链必须指向
     /usr/local/bin/occ，且不再安装/执行 aikernel-shell 与 ai；
     新镜像从该脚本构建，exec 链回退 = 全新构建的镜像入口错位。
  2) agent/ai/tests/run_all.sh —— 依赖真 ai 二进制的两个 clarify e2e
     （test_clarify_gate / test_api_clarify_e2e）必须已从口径中退役
     （防静默加回：退役是 T9e 分母换代的一部分）。

rootfs 侧的 .profile 实装由 qsmoke contentcheck 断言（T9e D 棒），此处
只守 repo 正典。退出码 0=全过，1=有 FAIL。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.dirname(HERE)                       # agent/ai
BUILD_ROOTFS = os.path.join(AGENT, "build-rootfs.sh")
RUN_ALL = os.path.join(HERE, "run_all.sh")

RESULTS = []


def check(cond, name, detail=""):
    RESULTS.append((bool(cond), name, detail))
    print(("PASS: " if cond else "FAIL: ") + name +
          (("  [" + str(detail) + "]") if (not cond and detail) else ""))


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def main():
    # ---- 1) build-rootfs.sh exec 链 / 安装段 ----
    if not os.path.exists(BUILD_ROOTFS):
        check(False, "build-rootfs-sh-exists", BUILD_ROOTFS)
    else:
        s = read(BUILD_ROOTFS)
        check("exec /usr/local/bin/occ" in s,
              "rootfs-template-exec-occ")
        check("[ -x /usr/local/bin/occ ]" in s,
              "rootfs-template-guard-occ")
        check("exec /usr/local/bin/aikernel-shell" not in s,
              "rootfs-template-no-shell-exec")
        check("exec /usr/local/bin/ai " not in s and
              'exec /usr/local/bin/ai\n' not in s,
              "rootfs-template-no-ai-exec")
        check('install -D -m755 "$SRC/agent/ai/occ/occ"' in s,
              "rootfs-install-occ")
        check('"$MNT/usr/local/bin/aikernel-shell"' not in s,
              "rootfs-no-shell-install")
        check('"$MNT/usr/local/bin/ai"' not in s,
              "rootfs-no-ai-install")

    # ---- 2) run_all 退役口径 ----
    if not os.path.exists(RUN_ALL):
        check(False, "run-all-exists", RUN_ALL)
    else:
        r = read(RUN_ALL)
        # 注释里允许出现退役项名字（记账说明）；只禁 spec 列表项（带 tests/ 前缀）
        check("tests/test_clarify_gate.py" not in r,
              "run-all-retired-clarity-gate")
        check("tests/test_api_clarify_e2e.py" not in r,
              "run-all-retired-api-clarify-e2e")
        check("tests/test_api_clarify.py" in r,
              "run-all-kept-mock-clarify")
        check("test_t9e_entry.py" in r,
              "run-all-has-t9e-entry")

    fails = [n for ok, n, _ in RESULTS if not ok]
    print("test_t9e_entry: %d pass, %d fail" %
          (len(RESULTS) - len(fails), len(fails)))
    if fails:
        print("FAILED: %s" % " ".join(fails))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
