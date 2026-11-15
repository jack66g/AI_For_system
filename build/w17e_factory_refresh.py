#!/usr/bin/env python3
"""W17e: 系统演化五棒 rootfs 刷新 17.4 → 17.5（root 跑在 L1）。

系统演化波进厂：C1 兼容 probe/classify（aikctl compat scan+aik-compat
probe 面+verneed）+ C2 shim 编译器（plan/promote/CLI 面）+ C3 L3 qemu
双态/L4 诚实面/L5 module 人工门 + L1 数据三层（评分/curated/加密导出
dataset 面）+ M1 aipd 影子守护（装不 enable）。w17d 同型最小刷新：
换件 strip+版本 bump+快照注记；aik-console/q17 结构不动。
新件：aikctl（升版含 module/hw/dataset 子族）、aik-compat、aik-gcm、
aipd（/usr/local/sbin）+unit+conf、qemu-{aarch64,arm}-static（C3 L3
双态在场景；wrapper 形态不需 binfmt 注册）。
"""
import hashlib
import os
import shutil
import subprocess

ROOT = "/home/jack66g/w7i-rootfs"
REPO = "/home/jack66g/aikernel-repo-alpha11"
CFG = "/home/jack66g/w6i-tools/grub-iso.cfg"
OLD, NEW = "0.1.0-alpha.17.4", "0.1.0-alpha.17.5"


def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def install_stripped(rel, src):
    tmp = "/tmp/w17e_strip.bin"
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
    """文本件/脚本直拷（aikctl=python 单文件脚本，strip 不适用）。"""
    dst = ROOT + rel
    if os.path.lexists(dst):
        os.unlink(dst)
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o755)
    os.chown(dst, 0, 0)
    print("install %s md5=%s size=%d" % (rel, md5(dst),
                                         os.path.getsize(dst)))


# 1) 五件（W4A strip 铁律仅适用 ELF：未 strip 布局在 AIKernel 内核上
#    SIGSEGV；aikctl=python 脚本走 install_plain）
install_stripped("/usr/local/bin/occ", REPO + "/agent/ai/occ/occ")
install_plain("/usr/local/bin/aikctl", REPO + "/agent/ai/aikctl/aikctl")
install_stripped("/usr/local/bin/aik-compat",
                 REPO + "/agent/ai/aik-compat")
install_stripped("/usr/local/bin/aik-gcm", REPO + "/agent/ai/aik-gcm")
install_stripped("/usr/local/sbin/aipd", REPO + "/agent/ai/aipd/aipd")

# 2) C3 L3 双态在场景：qemu-user 静态翻译器（发行版预构建件原样拷入，
#    不 strip——非本仓构建产物；wrapper 形态不需 binfmt_misc 注册）
for q in ("qemu-aarch64-static", "qemu-arm-static"):
    src = "/usr/bin/" + q
    dst = ROOT + "/usr/bin/" + q
    assert os.path.isfile(src), src + " missing on L1"
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o755)
    os.chown(dst, 0, 0)
    print("install /usr/bin/%s md5=%s size=%d" % (q, md5(dst),
                                                  os.path.getsize(dst)))

# 3) M1 aipd 出厂三件之二三：unit+conf（[5.6] 裁定：不 enable）
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
# 不 enable 断言（AIPD-M1-DESIGN §2.2：影子期手动起，M2 拍板）
assert not os.path.exists(ROOT + "/etc/systemd/system/"
                          "multi-user.target.wants/aikernel-aipd.service")

# 4) 版本串 17.4 → 17.5
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

# 5) 断言（17.4 结构保持）
prof = open(ROOT + "/root/.profile", encoding="utf-8").read()
assert "exec /usr/local/bin/aik-console" in prof
assert not os.path.exists(ROOT + "/etc/profile.d/auto-fbterm.sh")
snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-K17.txt"
open(snap, "a", encoding="utf-8").write(
    "sys-evo-c1..c3+l1+m1: compat probe/classify + shim compiler + "
    "L3 qemu dual-state/L4 honest hw/L5 module gate + data three "
    "layers (value scoring/curated/corpus GCM + aikctl dataset) + "
    "aipd shadow daemon (installed, not enabled). "
    "version=%s\n" % NEW)
print("W17E_OK")
