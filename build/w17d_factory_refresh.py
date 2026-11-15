#!/usr/bin/env python3
"""W17d: ORCH E1-E10 波 rootfs 刷新 17.3 → 17.4（root 跑在 L1）。

ORCH-DESIGN 十棒全量进厂：occ 主从编排（任务数据面 v3/进程隔离运行
时/Task+recall 工具/验收环机械判/压缩双闸蒸馏/记忆分层/预算记账/
/tasks 面板/orch_drill 回路/真模型实战修复波两轮）。w17c 同型最小
刷新：occ strip 换件+版本 bump+快照注记；aik-console/auto-fbterm
17.3 已就位不动。
"""
import hashlib
import os
import shutil
import subprocess

ROOT = "/home/jack66g/w7i-rootfs"
REPO = "/home/jack66g/aikernel-repo-alpha11"
OCC = REPO + "/agent/ai/occ/occ"
CFG = "/home/jack66g/w6i-tools/grub-iso.cfg"
OLD, NEW = "0.1.0-alpha.17.3", "0.1.0-alpha.17.4"


def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def install_stripped(rel, src):
    tmp = "/tmp/w17d_strip.bin"
    shutil.copyfile(src, tmp)
    r = subprocess.run(["strip", tmp], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    r = subprocess.run(["file", tmp], capture_output=True, text=True)
    assert "not stripped" not in r.stdout, r.stdout
    dst = ROOT + rel
    if os.path.lexists(dst):
        os.unlink(dst)
    shutil.copyfile(tmp, dst)
    os.chmod(dst, 0o755)
    os.chown(dst, 0, 0)
    print("install %s md5=%s size=%d" % (rel, md5(dst),
                                         os.path.getsize(dst)))


# 1) occ（ORCH E1-E10 + 修复波两轮；strip W4A 铁律）
install_stripped("/usr/local/bin/occ", OCC)

# 2) 版本串 17.3 → 17.4
for rel in ("/etc/motd", "/root/README.md"):
    p = ROOT + rel
    s = open(p, encoding="utf-8").read()
    if OLD in s:
        open(p, "w", encoding="utf-8").write(s.replace(OLD, NEW))
        print("bump", rel)
s = open(CFG, encoding="utf-8").read()
if OLD in s:
    open(CFG, "w", encoding="utf-8").write(s.replace(OLD, NEW))
    print("grub-iso.cfg bumped")

# 3) 断言（17.3 结构保持）
prof = open(ROOT + "/root/.profile", encoding="utf-8").read()
assert "exec /usr/local/bin/aik-console" in prof
assert not os.path.exists(ROOT + "/etc/profile.d/auto-fbterm.sh")
snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-K17.txt"
open(snap, "a", encoding="utf-8").write(
    "orch-e1..e10: master-worker orchestration (task schema v3 + "
    "process-isolated runtime + task/recall tools + mechanical "
    "verdict + compact/distill + memory layers + budget + /tasks "
    "panel + orch_drill loop + real-model drill fixwaves). "
    "version=%s\n" % NEW)
print("W17D_OK")
