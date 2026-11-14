#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""k10_patch_series.py — K10.3 补丁系列生成器（KERNEL-K10A-DESIGN 续）。

用法: k10_patch_series.py [--base DIR] [--check-only]
  --base   对照基线（默认 ~/linux-6.18.39 = alpha-11 出厂基线，非
           vanilla；vanilla 上游系列=登记尾账，tarball 到位后 --base 换指）
  产物: 仓库根 patches/<系列>/NNNN-<名>.patch + 每系列 cover-letter +
        SERIES.md 总目 + integrity 报告（overlay↔树逐字节一致核对）。
  --check-only: 只跑 integrity（不写 patches/，门禁用）。
"""
import argparse
import os
import subprocess
import sys

REPO = "/home/jack66g/aikernel-repo-alpha11"
OV = REPO + "/kernel-overlays"
TREE = "/home/jack66g/linux-k2"
OUT = REPO + "/patches"

SERIES = [
    ("0000-init", "init/"),
    ("0001-kernel-core", "kernel/"),
    ("0002-mm", "mm/"),
    ("0003-crypto", "crypto/"),
    ("0004-security", "security/"),
    ("0005-block", "block/"),
    ("0006-fs", "fs/"),
    ("0007-net", "net/"),
    ("0008-virt", "virt/"),
    ("0009-drivers", "drivers/"),
    ("0010-include", "include/"),
    ("0011-arch", "arch/"),
    ("0099-misc", ""),
]


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def series_of(rel):
    for name, prefix in SERIES:
        if prefix and rel.startswith(prefix):
            return name
    return "0099-misc"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.path.expanduser("~/linux-6.18.39"))
    ap.add_argument("--check-only", action="store_true")
    args = ap.parse_args()
    base = args.base
    if not os.path.isdir(base):
        print("FAIL: 基线不存在 %s" % base)
        return 2

    files = []
    for root, _d, fns in os.walk(OV):
        for fn in fns:
            if fn.endswith(".md") or fn == "MANIFEST.sha256":
                continue    # overlays 自带文档/清单非覆盖目标
            files.append(os.path.relpath(os.path.join(root, fn), OV))
    files.sort()

    # integrity：overlay ↔ 构建树逐字节（K5 陈旧树目录教训的制度化）
    integ_bad = []
    for rel in files:
        r = sh("cmp -s %s/%s %s/%s" % (OV, rel, TREE, rel))
        if r.returncode != 0:
            integ_bad.append(rel)
    print("INTEGRITY overlay↔tree: %d/%d 一致%s"
          % (len(files) - len(integ_bad), len(files),
             "" if not integ_bad else "；漂移: " + ",".join(integ_bad[:6])))
    if integ_bad:
        return 1
    if args.check_only:
        print("K10-SERIES: PASS（仅核对）")
        return 0

    # 生成
    n_patch = n_same = 0
    idx = {}
    if os.path.isdir(OUT):
        sh("rm -rf %s" % OUT)
    for rel in files:
        s = series_of(rel)
        bpath = os.path.join(base, rel)
        if not os.path.isfile(bpath):
            print("WARN: 基线缺 %s → 该文件以「新增文件」全量入系" % rel)
        r = sh("diff -u -L a/%s -L b/%s %s %s"
               % (rel, rel, bpath if os.path.isfile(bpath) else "/dev/null",
                  OV + "/" + rel))
        if r.returncode > 1:
            print("DIFF-FAIL %s: %s" % (rel, r.stderr[:80]))
            return 1
        if r.returncode == 0:
            n_same += 1        # 与基线一致（基线已含同内容）→ 不入系
            continue
        idx[s] = idx.get(s, 0) + 1
        d = os.path.join(OUT, s)
        os.makedirs(d, exist_ok=True)
        name = "%04d-%s.patch" % (idx[s], rel.replace("/", "-"))
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            f.write(r.stdout)
        n_patch += 1
        # 系列清单（cover 素材）
        with open(os.path.join(d, "files.txt"), "a", encoding="utf-8") as f:
            f.write("%s\t%s\n" % (name, rel))

    # cover letters + 总目
    total = 0
    with open(os.path.join(OUT, "SERIES.md"), "w", encoding="utf-8") as top:
        top.write("# AIKernel K 轨补丁系列（K10.3 生成物）\n\n"
                  "- 基线：`%s`（alpha-11 出厂基线，**非 vanilla**；\n"
                  "  vanilla 上游系列=登记尾账，tarball 到位后 --base 换指再生）\n"
                  "- 源：kernel-overlays/（%d 文件；与基线同内容 %d 不入系）\n"
                  "- 再生：`python3 AIKernel/scripts/k10_patch_series.py`\n"
                  "- integrity：overlay↔构建树逐字节一致（--check-only 门禁位）\n\n"
                  % (base, len(files), n_same))
        for s, _p in SERIES:
            d = os.path.join(OUT, s)
            if not os.path.isdir(d):
                continue
            n = idx.get(s, 0)
            total += n
            top.write("- **%s**：%d 补丁\n" % (s, n))
            with open(os.path.join(d, "cover-letter"), "w",
                      encoding="utf-8") as c:
                c.write("AIKernel %s 系列（%d 补丁）\n"
                        "================================\n"
                        "问题：AIKernel %s 面的内核侧挂钩/插桩（KTB §WP 各波）。\n"
                        "方案：kernel-overlays/ 覆盖式文件（本目录为对基线的\n"
                        "  导出 diff；逐文件=逐补丁，可独立回退=恢复基线文件）。\n"
                        "测试：KUnit 真机 not-ok=0/k0_truth/checkpatch/\n"
                        "  config_check + 各波 rig（见 T9-LOG 对应波次）。\n"
                        "风险：与上游同文件演化冲突（overlay 模型固有）；\n"
                        "  回退=按补丁逆放或恢复基线文件后重建。\n"
                        "明细：files.txt\n" % (s, n, s.split("-", 1)[1]))
    print("K10-SERIES: %d 补丁 / %d 系列 / 基线同内容 %d / overlay %d"
          % (total, len(idx), n_same, len(files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
