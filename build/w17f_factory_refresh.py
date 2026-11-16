#!/usr/bin/env python3
"""W17f: 三棒 rootfs 刷新 17.5 → 17.6（root 跑在 L1）。

M2 金丝雀（aipd 下发/A-B/签名表+aikctl aipd 子族）+ occ 串口 P2 修
（resize 0 兜底进 occ 二进制；aik-console v5=串口 stty+循环+取证）+
E1'（dataset card/replay 进 aikctl）进厂。w17e 同型最小刷新：换件
strip+版本 bump+快照注记；q17 结构不动。内核同波升 #82（AIPD=6，
bzImage d553ca24——build_iso 侧取树内现役件）。"""
import hashlib
import os
import shutil
import subprocess

ROOT = "/home/jack66g/w7i-rootfs"
REPO = "/home/jack66g/aikernel-repo-alpha11"
CFG = "/home/jack66g/w6i-tools/grub-iso.cfg"
OLD, NEW = "0.1.0-alpha.17.5", "0.1.0-alpha.17.6"


def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def install_stripped(rel, src):
    tmp = "/tmp/w17f_strip.bin"
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


def install_plain(rel, src):
    """文本件/脚本直拷（python/shell 件 strip 不适用）。"""
    dst = ROOT + rel
    if os.path.lexists(dst):
        os.unlink(dst)
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o755)
    os.chown(dst, 0, 0)
    print("install %s md5=%s size=%d" % (rel, md5(dst),
                                         os.path.getsize(dst)))


# 1) 六件（aikctl/aik-console/occ 走 plain——occ strip 后 TUI 输入路径
#    在 GRUB 真路径下死〔w17f 验尸实锤：同盘同内核，strip=INPUT-DEAD/
#    未 strip=INPUT-OK〕；W4A 铁律=逐件实证，occ 不 strip）
install_plain("/usr/local/bin/occ", REPO + "/agent/ai/occ/occ")
install_plain("/usr/local/bin/aikctl", REPO + "/agent/ai/aikctl/aikctl")
install_stripped("/usr/local/bin/aik-compat",
                 REPO + "/agent/ai/aik-compat")
install_stripped("/usr/local/bin/aik-gcm", REPO + "/agent/ai/aik-gcm")
install_stripped("/usr/local/sbin/aipd", REPO + "/agent/ai/aipd/aipd")
# P2 修：aik-console v5（串口 stty 24x80+循环兜底+取证；occ resize 0
# 兜底已编进上面 occ 二进制）
install_plain("/usr/local/bin/aik-console",
              REPO + "/factory/usr/local/bin/aik-console")

# 2) aipd unit+conf（M2 版：Description 增金丝雀句；conf=正典+注释态
#    canary 五键——影子期不 armed，promote→default 仍为拍板项）
for rel, src in (
        ("/etc/systemd/system/aikernel-aipd.service",
         REPO + "/factory/etc/systemd/system/aikernel-aipd.service"),
        ("/etc/aikernel/aipd.conf",
         REPO + "/factory/etc/aikernel/aipd.conf")):
    dst = ROOT + rel
    if os.path.lexists(dst):
        os.unlink(dst)
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o644)
    os.chown(dst, 0, 0)
    print("install %s" % rel)
assert not os.path.exists(ROOT + "/etc/systemd/system/"
                          "multi-user.target.wants/aikernel-aipd.service")

# 3) 版本串 17.5 → 17.6
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

# 4) 断言（结构保持 + 本波新面）
prof = open(ROOT + "/root/.profile", encoding="utf-8").read()
assert "exec /usr/local/bin/aik-console" in prof
assert not os.path.exists(ROOT + "/etc/profile.d/auto-fbterm.sh")
akc = open(ROOT + "/usr/local/bin/aik-console",
           encoding="utf-8").read()
assert "stty rows 24 cols 80" in akc and "tty=serial" in akc, \
    "aik-console v5 marker missing"
conf = open(ROOT + "/etc/aikernel/aipd.conf", encoding="utf-8").read()
repo_conf = open(REPO + "/factory/etc/aikernel/aipd.conf",
                 encoding="utf-8").read()
assert conf == repo_conf, "aipd.conf twin drift"
assert "CANARY_ENABLED" in conf and "^CANARY_ENABLED" not in conf
snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-K17.txt"
open(snap, "a", encoding="utf-8").write(
    "m2+occ-serial-p2+e1g1: aipd canary (ACT_BATCH agent=6, auto "
    "rollback, AIPTBL signed table, aikctl aipd release) + occ serial "
    "resize-0 fix + aik-console v5 + dataset card/replay + CI/fuzz/SBOM. "
    "kernel #82 (AI_AGENT_AIPD=6). version=%s\n" % NEW)
print("W17F_OK")
