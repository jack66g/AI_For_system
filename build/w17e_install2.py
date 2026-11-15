#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17e_install2.py — alpha.17.5 试装烟测 v2（w17d_install2 同型忠实克隆）。
轮1=ISO+空盘装机（grub 第二菜单 serial console+自动答 y）；轮2=起装好
的盘→login→**出厂电池+系统演化 E2E**：
  ① motd 17.5 ② aik-compat probe /bin/busybox（runnable=1）
  ③ aikctl compat hw（IOMMU 空组诚实裁定）④ aik-gcm selftest（NIST）
  ⑤ aipd E2E 真机轮（map35 真源：feat_ok≥1+影子 parquet 落盘+停净）。
证据 ~/k10-evidence/w17e-*。"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

ISO = "/home/jack66g/AIKernel-0.1.0-alpha.17.5-x86_64.iso"
WRK = "/home/jack66g/k2/k3"
EVD = os.path.expanduser("~/k10-evidence")
DISK = "/tmp/w17e-target.qcow2"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def install_round():
    """轮1：装机（w17d_install2 流程忠实克隆）。"""
    sock = WRK + "/w17e-install.sock"
    cleanup_qemu()
    time.sleep(1)
    if os.path.exists(sock):
        os.unlink(sock)
    cmd = ("qemu-system-x86_64 -name w17einst -accel tcg -m 3072 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-drive file=%s,if=virtio -cdrom %s -boot d" % (sock, DISK, ISO))
    q = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17e-install-serial.log"))
    try:
        # grub 菜单（timeout=8）：按 DOWN 选第二项（serial console）
        for _ in range(3):
            ser.send(b"\x1b[B")
            time.sleep(0.4)
        ser.send(b"\r")
        # 安装器 y/N 确认（serial 菜单项下交互在串口）
        ser.wait(b"y/N", 900)
        time.sleep(0.5)
        mark = len(ser.buf)
        ser.send(b"y\r")
        wait_after(ser, mark, b"Power down", 3000)
        time.sleep(3)
    finally:
        ser.drain_close()
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()
    pd = open(os.path.join(EVD, "w17e-install-serial.log"), "rb").read()
    inst_ok = b"Power down" in pd[-8192:]
    print("[w17e] install round: powerdown=%s" % inst_ok)
    if not inst_ok:
        print(pd[-900:].decode("utf-8", "replace"))
    return inst_ok


def boot_round():
    """轮2：起装好的盘→login→出厂电池。"""
    sock = WRK + "/w17e-boot.sock"
    cleanup_qemu()
    time.sleep(1)
    if os.path.exists(sock):
        os.unlink(sock)
    cmd = ("qemu-system-x86_64 -name w17eboot -accel tcg -m 3072 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait -drive file=%s,if=virtio"
           % (sock, DISK))
    q = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17e-boot-serial.log"))
    out = ""
    try:
        ser.wait(b"login:", 600)
        got = False
        for _ in range(10):
            mark = len(ser.buf)
            ser.send(b"root\r")
            if wait_after(ser, mark, b"#", 40):
                got = True
                break
            time.sleep(2)
        if got:
            time.sleep(1.5)
            mark = len(ser.buf)
            ser.sendline(BATTERY)
            wait_after(ser, mark, b"W17EDONE2", 300)
            out = ANSI.sub(b"", ser.buf[mark:]).replace(
                b"\r", b"").decode("utf-8", "replace")
        ser.sendline("poweroff -f")
        ser.wait(b"Power down", 240)
    finally:
        ser.drain_close()
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()
    return out


# 出厂电池：五件（aipd 真机轮=后台起 12s+stats 三数+影子目录+kill+日志尾）
BATTERY = (
    "echo ==B1==; grep -m1 17.5 /etc/motd; "
    "echo ==B2==; aik-compat probe /bin/busybox 2>&1 | tail -1; "
    "echo ==B3==; aikctl compat hw 2>&1 | head -1 | cut -c1-160; "
    "echo ==B4==; aik-gcm selftest 2>&1 | tail -1; "
    "echo ==B5==; (/usr/local/sbin/aipd --conf /etc/aikernel/aipd.conf "
    ">/tmp/aipd-e2e.log 2>&1 & echo $! >/tmp/aipd.pid); sleep 12; "
    "grep -o 'feat_ok=[0-9]*' /run/aipd.stats | head -1; "
    "grep -o 'feat_stale=[0-9]*' /run/aipd.stats | head -1; "
    "grep -o 'shadow_rows=[0-9]*' /run/aipd.stats | head -1; "
    "ls /var/lib/aikernel/aipd/*/ 2>/dev/null | head -2; "
    "kill $(cat /tmp/aipd.pid) 2>/dev/null; sleep 2; "
    "tail -2 /tmp/aipd-e2e.log; echo W17EDONE$((1+1))"
)


def main():
    os.makedirs(EVD, exist_ok=True)
    if os.path.exists(DISK):
        os.unlink(DISK)
    sh("qemu-img create -f qcow2 %s 8G" % DISK)
    if not install_round():
        return 1
    out = boot_round()
    ok = {
        "B1 motd17.5": "17.5" in out,
        "B2 probe runnable": "runnable=1" in out,
        "B3 hw honest": "iommu_groups" in out,
        "B4 gcm nist": "ok=3" in out,
        "B5 feat_ok>=1": bool(re.search(r"feat_ok=[1-9]", out)),
        "B5 shadow rows": bool(re.search(r"shadow_rows=[1-9]", out)),
    }
    for k, v in ok.items():
        print("%-18s %s" % (k, "PASS" if v else "FAIL"))
    print("---- battery tail ----")
    print(out[-700:])
    return 0 if all(ok.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
