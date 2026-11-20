#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W17J: rootfs 刷新 0.1.0-alpha.17.8.1 → 17.9（17.9 打版；run as root on L1）。

本版收编清单（HEAD=7408674+O-8/P-55 工树）：
  P-55: aik-ime 中文输入法全套入厂——/usr/local/bin/aik-ime（RPATH 版，
        自寻 /usr/local/lib/aik-ime 随包 .so×9）+ /usr/share/rime-data
        （官方 yaml+essay.txt〔排序修复：nihao→你好〕+L1 预编 build/*.bin
        〔首启 0.17s 不重编〕）+ /root/.fbtermrc 挂 input-method=aik-ime
        （出厂即有 Ctrl+Space 中英切换；140 真机三验铁证在案）
  O-8:  aik-sandbox 出厂件重编——沙箱 /etc/alternatives 补挂 awk/which
        两单文件 bind（链断头修复，零二进制变化；w64 check 112 PASS
        〔L1 环境项 2 FAIL 历史同款〕）
  P-56: aipd 重编（影子 parquet 尾列 source→producer+撞名 FATAL 自检）
  O-20 A1+A2: occ（双语表 573 条+OCC_LANG//lang；A3 余量不打）
  occ 全量（7408674：P-55 client 源+O-20+P-56 面零变化二进制重编）
内核沿用 #82（零内核改动）。"""
import hashlib
import os
import shutil
import subprocess

ROOT = "/home/jack66g/w7i-rootfs"
REPO = "/home/jack66g/aikernel-repo-alpha11"
CFG = "/home/jack66g/aik-wt-p179/build/w17j-grub-iso.cfg"
K2 = "/home/jack66g/linux-k2"
KREL = "6.18.39"
SOFTDOG_REL = "/lib/modules/%s/kernel/drivers/watchdog/softdog.ko" % KREL
BZ_MD5 = "7b35b41fb86f2c1c20e1fd57053e3d5e"
SOFTDOG_MD5 = "9e50cb73434ab8ba363127682646fa63"
OLD, NEW = "0.1.0-alpha.17.8.1", "0.1.0-alpha.17.9"
PROV_PUBKEY = "/home/jack66g/prov.pubkey"


def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def install_file(rel, src, mode):
    dst = ROOT + rel
    if os.path.lexists(dst):
        os.unlink(dst)
    shutil.copyfile(src, dst)
    os.chmod(dst, mode)
    os.chown(dst, 0, 0)
    print("install %s md5=%s" % (rel, md5(dst)))


def install_link(rel, target):
    dst = ROOT + rel
    if os.path.lexists(dst):
        os.unlink(dst)
    os.symlink(target, dst)
    os.lchown(dst, 0, 0)
    print("link %s -> %s" % (rel, target))


F = REPO + "/factory"

# 0) P-33 前置门：#82 树一致性（bzImage md5 硬锚=本树即出厂树；
#    softdog 必须产自同一次构建的树，17.8 失配即跨树件）
bz = K2 + "/arch/x86/boot/bzImage"
assert md5(bz) == BZ_MD5, "linux-k2 bzImage not #82 final (7b35b41f)"
ko = K2 + "/drivers/watchdog/softdog.ko"
assert md5(ko) == SOFTDOG_MD5, "k2 softdog.ko drifted (expect 9e50cb73)"
print("P33 gate: bzImage+softdog same-tree #82 verified")

# 1) 二进制重装面（P-32 核心：conf 刷新键、二进制必须同刷）
install_file("/usr/local/bin/occ", REPO + "/agent/ai/occ/occ", 0o755)
install_file("/usr/local/sbin/aistreamd",
             REPO + "/agent/ai/aistreamd/aistreamd", 0o755)
install_file("/usr/local/bin/aik-console",
             F + "/usr/local/bin/aik-console", 0o755)

# 2) 17.7 既有件在位断言（本波不动）
for rel in ("/usr/local/bin/aikctl", "/usr/local/bin/aik-compat",
            "/usr/local/bin/aik-gcm", "/usr/local/sbin/aipd"):
    assert os.path.isfile(ROOT + rel), "missing legacy file: " + rel

# 3) conf/出厂面收编（aistreamd.conf 与二进制同刷；17.8 后积压件）
install_file("/etc/aikernel/aistreamd.conf",
             F + "/etc/aikernel/aistreamd.conf", 0o644)
install_file("/usr/local/sbin/aik-upgrade",
             F + "/usr/local/sbin/aik-upgrade", 0o755)
install_file("/etc/fonts/fonts.conf", F + "/etc/fonts/fonts.conf", 0o644)
install_file("/etc/sysctl.d/50-aik-console-quiet.conf",
             F + "/etc/sysctl.d/50-aik-console-quiet.conf", 0o644)

# 3b) 17.9 收编面刷件（P-55 全套+O-8 沙箱+P-56 aipd）
install_file("/usr/local/sbin/aipd", REPO + "/agent/ai/aipd/aipd", 0o755)
install_file("/usr/local/bin/aik-sandbox",
             REPO + "/agent/ai/sandbox/aik-sandbox", 0o755)
install_file("/usr/local/bin/aik-ime", F + "/usr/local/bin/aik-ime", 0o755)
install_file("/root/.fbtermrc", F + "/root/.fbtermrc", 0o644)

def _copytree(src, dst):
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    for root, dirs, files in os.walk(dst):
        os.chown(root, 0, 0)
        for fn in files:
            os.chown(os.path.join(root, fn), 0, 0)

_copytree(F + "/usr/share/rime-data", ROOT + "/usr/share/rime-data")
_copytree(F + "/usr/local/lib/aik-ime", ROOT + "/usr/local/lib/aik-ime")
n_rime = sum(len(fs) for _, _, fs in os.walk(ROOT + "/usr/share/rime-data"))
n_so = sum(len(fs) for _, _, fs in os.walk(ROOT + "/usr/local/lib/aik-ime"))
print("p55 staged: rime-data %d files, bundled .so %d" % (n_rime, n_so))

# 4) P-33 softdog 同树进厂
install_file(SOFTDOG_REL, ko, 0o644)

# 5) P-32 断言：conf/二进制一致（chroot 走真解析器，正反双向）
r = subprocess.run(
    ["chroot", ROOT, "/usr/local/sbin/aistreamd",
     "--check-conf", "--conf", "/etc/aikernel/aistreamd.conf"],
    capture_output=True, text=True)
assert r.returncode == 0, \
    "P-32: aistreamd conf/binary mismatch: %s%s" % (r.stdout, r.stderr)
pois = ROOT + "/tmp/w17i-pois.conf"
with open(pois, "w", encoding="utf-8") as fh:
    fh.write("SME_URL=http://127.0.0.1:8000\nBOGUS_KEY_W17I=1\n")
r = subprocess.run(
    ["chroot", ROOT, "/usr/local/sbin/aistreamd",
     "--check-conf", "--conf", "/tmp/w17i-pois.conf"],
    capture_output=True, text=True)
os.unlink(pois)
assert r.returncode != 0, "P-32: --check-conf lost teeth (bogus key passed)"
print("P32 check-conf two-way: good conf=rc0 / poisoned conf=rc!=0")

# 6) P-33 断言：模块配套（md5 已由安装打印；vermagic/dep/load 四面）
vr = subprocess.run(["modinfo", "-F", "vermagic", ROOT + SOFTDOG_REL],
                    capture_output=True, text=True)
assert vr.stdout.strip().startswith(KREL), \
    "softdog vermagic mismatch: " + vr.stdout
assert md5(ROOT + SOFTDOG_REL) == SOFTDOG_MD5, "installed softdog drifted"
dep = open(ROOT + "/lib/modules/%s/modules.dep" % KREL,
           encoding="utf-8").read()
assert "softdog.ko:" in dep, "modules.dep lacks softdog"
mld = ROOT + "/etc/modules-load.d"
mls = ""
for fn in sorted(os.listdir(mld)):
    p = os.path.join(mld, fn)
    # 只读真文件（modules.conf→../modules 是悬空历史符号链接，非本面）
    if os.path.isfile(p):
        mls += open(p, encoding="utf-8").read()
assert "softdog" in mls, "modules-load.d lacks softdog"
print("P33 softdog: md5=%s vermagic=[%s]"
      % (SOFTDOG_MD5, vr.stdout.strip()))

# 7) 新面字符串锚（17.8 后积压波的出厂证明）
occbin = open(ROOT + "/usr/local/bin/occ", "rb").read()
assert b"config_write_network" in occbin, "occ lacks netcfg tool"
assert b"OCC_NETCFG_TOOLS" in occbin
assert b"unstuck" in occbin, "occ lacks P-48 unstuck"
assert b"aik-occ-exit" in occbin, "occ lacks P-47 exit marker"
console = open(ROOT + "/usr/local/bin/aik-console",
               encoding="utf-8").read()
assert "occ-logout-marker" in console, "aik-console not v8"
assert "OCC_NETCFG_TOOLS=1" in console, "console missing netcfg flag"
upg = open(ROOT + "/usr/local/sbin/aik-upgrade",
           encoding="utf-8").read()
assert "userland" in upg, "aik-upgrade lacks W-7 userland channel"
fonts = open(ROOT + "/etc/fonts/fonts.conf", encoding="utf-8").read()
assert "Noto Sans Mono CJK SC" in fonts, "P-34 CJK prefer missing"
quiet = open(ROOT + "/etc/sysctl.d/50-aik-console-quiet.conf",
             encoding="utf-8").read()
assert "kernel.printk" in quiet, "P-38 printk quiet missing"
ret = open(ROOT + "/etc/aikernel/aistreamd.conf",
           encoding="utf-8").read()
assert "PARQUET_RETENTION_DAYS=7" in ret

# 7b) 17.9 新面锚
aipdbin = open(ROOT + "/usr/local/sbin/aipd", "rb").read()
assert b"producer" in aipdbin, "aipd lacks P-56 producer"
assert b"aip_shadow_colname" in aipdbin, "aipd lacks P-56 API"
assert b"OCC_LANG" in occbin, "occ lacks O-20 lang"
assert b"tui_lang" in occbin, "occ lacks O-20 table"
sbx = open(ROOT + "/usr/local/bin/aik-sandbox", "rb").read()
assert b"which.debianutils" in sbx, "aik-sandbox lacks O-8 fixups"
assert b"mawk" in sbx, "aik-sandbox lacks O-8 awk"
imebin = open(ROOT + "/usr/local/bin/aik-ime", "rb").read()
assert b"/usr/local/lib/aik-ime" in imebin, "aik-ime lacks RPATH"
assert b"FBTERM_IM_SOCKET" in imebin, "aik-ime not fbterm IM protocol"
imerc = open(ROOT + "/root/.fbtermrc", encoding="utf-8").read()
assert "input-method=aik-ime" in imerc, "fbtermrc lacks IME hook"
assert os.path.isfile(ROOT + "/usr/share/rime-data/essay.txt"), "essay"
assert os.path.isfile(
    ROOT + "/usr/share/rime-data/build/luna_pinyin.prism.bin"), "prism"
assert os.path.isfile(
    ROOT + "/usr/share/rime-data/build/luna_pinyin.table.bin"), "table"
assert os.path.islink(
    ROOT + "/usr/local/lib/aik-ime/libleveldb.so.1d"), "so symlink"
print("17.9 anchors: aipd P-56 / occ O-20 / sandbox O-8 / "
      "aik-ime+rpath / rime essay+prebuilt / fbtermrc")

# 8) 沿用面在位断言（w17h 面不动，只验不装）
hard = open(ROOT + "/etc/ssh/sshd_config.d/50-aik-hardening.conf",
            encoding="utf-8").read()
assert "PermitRootLogin prohibit-password" in hard
assert "PasswordAuthentication no" in hard, "hardening keys missing"
trim = open(ROOT + "/usr/local/sbin/aik-log-trim",
            encoding="utf-8").read()
assert "KEEP_DAYS=14" in trim and "MAX_BYTES" in trim
health = open(ROOT + "/usr/local/sbin/aikernel-health.sh",
              encoding="utf-8").read()
assert "HEAL_GRACE_SEC" in health and "WEBHOOK_URL" in health
cron = open(ROOT + "/etc/systemd/system/aik-cron.service",
            encoding="utf-8").read()
assert "crond -f -S -l 8" in cron, "crond not foreground"
assert os.access(ROOT + "/usr/local/bin/busybox", os.X_OK)
assert os.path.islink(ROOT + "/usr/local/bin/crontab")
r = subprocess.run([ROOT + "/usr/local/bin/busybox", "--list"],
                   capture_output=True, text=True)
assert "crond" in r.stdout and "crontab" in r.stdout \
    and "fdisk" in r.stdout, "busybox applets missing"
assert not os.path.exists(ROOT + "/usr/share/man"), \
    "C-P2c: man pages should be deleted"
uup = ROOT + "/etc/apt/apt.conf.d/51-aik-upgrade-policy"
assert 'Unattended-Upgrade "0"' in open(uup, encoding="utf-8").read()

# 9) PROV_PUBKEY（可选——演示机首启 ssh 接管通道；sshd 已密钥制）
if os.path.isfile(PROV_PUBKEY):
    key = open(PROV_PUBKEY, encoding="utf-8").read().strip()
    assert key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")), \
        "prov.pubkey not a public key line"
    assert "\n" not in key, "prov.pubkey must be a single line"
    d = ROOT + "/root/.ssh"
    os.makedirs(d, exist_ok=True)
    with open(d + "/authorized_keys", "w", encoding="utf-8") as fh:
        fh.write(key + "\n")
    os.chmod(d, 0o700)
    os.chmod(d + "/authorized_keys", 0o600)
    os.chown(d, 0, 0)
    os.chown(d + "/authorized_keys", 0, 0)
    print("prov pubkey injected (md5=%s...)"
          % md5(d + "/authorized_keys")[:8])
else:
    print("NOTE: no prov.pubkey — ssh 首启接管需装后 nbd 预种")

# 10) 版本串 17.8 → 17.8.1
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

# 11) P-33 溯源修正：ISO-SNAPSHOT-W82.txt 重写（旧件误写 #62 a667e916…）
head = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"],
                      capture_output=True, text=True).stdout.strip()
bzsize = os.path.getsize(bz)
snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-W82.txt"
with open(snap, "w", encoding="utf-8") as fh:
    fh.write(
        "version=%s-w82-20261118\n"
        "kernel=6.18.39 #82 %s (%d bytes)\n"
        "softdog.ko=%s (same-tree linux-k2 #82; vermagic \"%s\")\n"
        "userland=main@%s\n"
        "tools=230 channels=26 seed=247\n"
        "built=2026-11-18 on L1\n"
        "correction=2026-11-18: prior entry erroneously said #62 "
        "a667e9160b23036a859ebc8a70aae62b (provenance drift); the "
        "factory kernel is and was #82 = bzImage md5 above\n"
        % (NEW, BZ_MD5, bzsize, SOFTDOG_MD5,
           vr.stdout.strip(), head))
print("W82 snapshot corrected (was #62-drift, now #82 same-tree)")

# 12) K17 快照追加本波账
snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-K17.txt"
with open(snap, "a", encoding="utf-8") as fh:
    fh.write(
        "17.9: P-55 aik-ime IME factory suite (rime essay+prebuilt, "
        "bundled .so, fbtermrc) + O-8 sandbox alternatives fixups + "
        "P-56 aipd producer + O-20 A1+A2 occ. kernel #82 unchanged. "
        "version=%s\n" % NEW)
    fh.write(
        "p32+p33: aistreamd binary+conf co-refresh with chroot "
        "--check-conf two-way assertion (17.8 unknown-key crash loop "
        "root-caused) + softdog.ko same-tree #82 + W82 snapshot "
        "provenance fix + occ (unstuck/exit-marker/console-stability) "
        "+ aik-console v8 + aik-upgrade userland channel + fontconfig "
        "CJK + printk quiet. kernel #82 unchanged. version=%s\n" % NEW)
print("W17J_OK")
