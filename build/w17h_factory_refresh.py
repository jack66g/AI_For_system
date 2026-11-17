#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W17H: rootfs 刷新 0.1.0-alpha.17.7 → 17.8（P1 安全五项+P2 功能七项
进厂；run as root on L1）。

本波收编清单（两棒代码波的全部出厂面）：
  P1: sshd 纯净基线+50-aik-hardening（幽灵转正）/51-aik-upgrade-policy
      （u-u 显式禁用）/aistreamd.conf 保留键/aik-log-trim 三件
  P1e: aikernel-health.sh 三闸版（含 C-P2e 告警出口）
  P2: busybox+crond/crontab/fdisk 链/aik-cron.service（-f 前台）/
      aik-backup 扩面版/aik-console（OCC_NETCFG_TOOLS=1）/
      aikernel-api.service（同旗）/occ 新二进制（config_write_network）
  可选：PROV_PUBKEY=/home/jack66g/prov.pubkey 注入 root authorized_keys
  （ssh 已硬化为密钥制——这是演示机首启 ssh 接管通道；缺文件=跳过+注记）
内核沿用 #82（AIPD=6，bzImage 7b35b41f…——本波零内核改动，PSI 翻案
已证生产核在位）。"""
import hashlib
import os
import shutil
import subprocess

ROOT = "/home/jack66g/w7i-rootfs"
REPO = "/home/jack66g/aikernel-repo-alpha11"
CFG = "/home/jack66g/w6i-tools/grub-iso.cfg"
OLD, NEW = "0.1.0-alpha.17.7", "0.1.0-alpha.17.8"
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

# 1) occ 二进制（plain——W4A 铁律：occ 不 strip；17.8 唯一重装二进制）
install_file("/usr/local/bin/occ", REPO + "/agent/ai/occ/occ", 0o755)

# 2) 17.7 既有六件在位断言（本波不动）
for rel in ("/usr/local/bin/aikctl", "/usr/local/bin/aik-compat",
            "/usr/local/bin/aik-gcm", "/usr/local/sbin/aipd",
            "/usr/local/bin/aik-console",
            "/usr/local/sbin/aistreamd"):
    assert os.path.isfile(ROOT + rel), "missing 17.7 file: " + rel

# 3) P1/P2 出厂面收编
install_file("/usr/local/bin/aik-console", F + "/usr/local/bin/aik-console", 0o755)
install_file("/etc/ssh/sshd_config", F + "/etc/ssh/sshd_config", 0o644)
install_file("/etc/ssh/sshd_config.d/50-aik-hardening.conf",
             F + "/etc/ssh/sshd_config.d/50-aik-hardening.conf", 0o644)
install_file("/etc/apt/apt.conf.d/51-aik-upgrade-policy",
             F + "/etc/apt/apt.conf.d/51-aik-upgrade-policy", 0o644)
if os.path.exists(ROOT + "/etc/apt/apt.conf.d/50unattended-upgrades"):
    os.unlink(ROOT + "/etc/apt/apt.conf.d/50unattended-upgrades")
    print("removed ghost 50unattended-upgrades")
install_file("/etc/aikernel/aistreamd.conf",
             F + "/etc/aikernel/aistreamd.conf", 0o644)
install_file("/usr/local/sbin/aik-log-trim",
             F + "/usr/local/sbin/aik-log-trim", 0o755)
install_file("/etc/systemd/system/aik-log-trim.service",
             F + "/etc/systemd/system/aik-log-trim.service", 0o644)
install_file("/etc/systemd/system/aik-log-trim.timer",
             F + "/etc/systemd/system/aik-log-trim.timer", 0o644)
install_link("/etc/systemd/system/timers.target.wants/aik-log-trim.timer",
             "../aik-log-trim.timer")
install_file("/usr/local/bin/busybox", F + "/usr/local/bin/busybox", 0o755)
install_link("/usr/local/bin/crond", "busybox")
install_link("/usr/local/bin/crontab", "busybox")
install_link("/usr/local/bin/fdisk", "busybox")
install_file("/etc/systemd/system/aik-cron.service",
             F + "/etc/systemd/system/aik-cron.service", 0o644)
install_link("/etc/systemd/system/multi-user.target.wants/aik-cron.service",
             "../aik-cron.service")
install_file("/usr/local/sbin/aik-backup",
             F + "/usr/local/sbin/aik-backup", 0o755)
install_file("/usr/local/sbin/aikernel-health.sh",
             F + "/usr/local/sbin/aikernel-health.sh", 0o755)
install_file("/etc/systemd/system/aikernel-api.service",
             F + "/etc/systemd/system/aikernel-api.service", 0o644)

# 4) PROV_PUBKEY（可选——演示机首启 ssh 接管通道；sshd 已密钥制）
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
    print("prov pubkey injected (md5=%s...)" % md5(d + "/authorized_keys")[:8])
else:
    print("NOTE: no prov.pubkey — ssh 首启接管需装后 nbd 预种")

# 5) 版本串 17.7 → 17.8
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

# 6) 断言（本波新面）
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
console = open(ROOT + "/usr/local/bin/aik-console",
               encoding="utf-8").read()
assert "OCC_NETCFG_TOOLS=1" in console, "console missing netcfg flag"
cron = open(ROOT + "/etc/systemd/system/aik-cron.service",
            encoding="utf-8").read()
assert "crond -f -S -l 8" in cron, "crond not foreground"
assert os.access(ROOT + "/usr/local/bin/busybox", os.X_OK)
assert os.path.islink(ROOT + "/usr/local/bin/crontab")
r = subprocess.run([ROOT + "/usr/local/bin/busybox", "--list"],
                   capture_output=True, text=True)
assert "crond" in r.stdout and "crontab" in r.stdout and "fdisk" in r.stdout, \
    "busybox applets missing"
occbin = open(ROOT + "/usr/local/bin/occ", "rb").read()
assert b"config_write_network" in occbin, "occ lacks netcfg tool"
assert b"OCC_NETCFG_TOOLS" in occbin
assert not os.path.exists(ROOT + "/usr/share/man"), \
        "C-P2c: man pages should be deleted"
uup = ROOT + "/etc/apt/apt.conf.d/51-aik-upgrade-policy"
assert 'Unattended-Upgrade "0"' in open(uup, encoding="utf-8").read()
ret = open(ROOT + "/etc/aikernel/aistreamd.conf", encoding="utf-8").read()
assert "PARQUET_RETENTION_DAYS=7" in ret

snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-K17.txt"
with open(snap, "a", encoding="utf-8") as fh:
    fh.write(
        "p1+p2: sshd hardening (prohibit-password/key-only) + u-u "
        "explicit-disable + bounded logs (log-trim timer) + health "
        "three-gate (grace/cooldown/free-gate, SME death-loop fix) + "
        "alert webhook + crond (busybox -f) + backup home/data options "
        + "+ fdisk applet + occ config_write_network (OCC_NETCFG_TOOLS) "
        "+ man dead-weight removed. kernel #82 unchanged. version=%s\n"
        % NEW)
print("W17H_OK")
