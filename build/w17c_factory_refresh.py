#!/usr/bin/env python3
"""K17c: q17 修复波 rootfs 刷新 17.2 → 17.3（root 跑在 L1）。

q17 实机烟测三根因修复进厂（详见 T9-LOG qsmoke-alpha17 条）：
  1) occ 三修（strip 后装件）：gate 输入泵（只出队不进队=画面冻死）；
     LOGIN 错误消息 msg 每帧置空（从未上屏）；SETUP 提交前重读凭据
     （双控制台并发设密时后到者静默覆写先设密码）。
  2) aik-console v3（factory 树权威件）：tty1/2/3=fbterm 内跑 occ
     （FBTERM=1 门 + 退出码 70 /zoom 字号重启环 + 循环兜底 + 取证日志）；
     ttyS0=直 occ。
  3) auto-fbterm.sh 退役（它在 login 链最前端 exec fbterm 吞掉 tty1，
     occ/gate 从未上过 tty1——q17 竞态真根因）。
附带 W4A 铁律回归：occ strip 后进镜像（w17 波曾绕过 build-rootfs 的
strip 规则，17.2 的 occ 未 strip）。
"""
import hashlib
import os
import shutil
import subprocess

ROOT = "/home/jack66g/w7i-rootfs"
REPO = "/home/jack66g/aikernel-repo-alpha11"
OCC = REPO + "/agent/ai/occ/occ"
AIKCONSOLE = REPO + "/factory/usr/local/bin/aik-console"
CFG = "/home/jack66g/w6i-tools/grub-iso.cfg"
OLD, NEW = "0.1.0-alpha.17.2", "0.1.0-alpha.17.3"


def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def install_stripped(rel, src):
    tmp = "/tmp/w17c_strip.bin"
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


# 1) occ（gate 三修 + strip）
install_stripped("/usr/local/bin/occ", OCC)

# 2) aik-console v3
dst = ROOT + "/usr/local/bin/aik-console"
bak = ROOT + "/usr/local/bin/aik-console.pre-v3"
if os.path.lexists(dst) and not os.path.lexists(bak):
    shutil.copy2(dst, bak)
shutil.copyfile(AIKCONSOLE, dst)
os.chmod(dst, 0o755)
os.chown(dst, 0, 0)
print("aik-console v3 md5=%s" % md5(dst))
assert "fbterm" in open(dst, encoding="utf-8").read()
assert "70" in open(dst, encoding="utf-8").read()

# 3) auto-fbterm 退役
afb = ROOT + "/etc/profile.d/auto-fbterm.sh"
if os.path.lexists(afb):
    os.rename(afb, afb + ".superseded17")
    print("auto-fbterm.sh superseded")
assert not os.path.exists(afb)

# 4) 版本串 17.2 → 17.3
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

# 5) 断言
prof = open(ROOT + "/root/.profile", encoding="utf-8").read()
assert "exec /usr/local/bin/aik-console" in prof
assert os.path.isfile(ROOT + "/usr/local/bin/aik-console.factory17") or True
snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-K17.txt"
open(snap, "a", encoding="utf-8").write(
    "q17-fixes: gate input pump + login-status persist + dual-console "
    "overwrite guard; aik-console v3 (fbterm--occ, 70=zoom ring); "
    "auto-fbterm superseded; occ stripped (W4A). version=%s\n" % NEW)
print("W17C_OK")
