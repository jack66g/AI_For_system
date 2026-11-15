#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17d_install2.py — alpha.17.4 试装烟测 v2：选 grub 第二菜单
（serial console——交互落串口）+自动答安装 y/N。轮2 起盘验。"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

ISO = "/home/jack66g/AIKernel-0.1.0-alpha.17.4-x86_64.iso"
WRK = "/home/jack66g/k2/k3"
EVD = os.path.expanduser("~/k10-evidence")
DISK = "/tmp/w17d-target.qcow2"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def main():
    os.makedirs(EVD, exist_ok=True)
    if os.path.exists(DISK):
        os.unlink(DISK)
    sh("qemu-img create -f qcow2 %s 8G" % DISK)
    cleanup_qemu()
    time.sleep(1)
    sock = WRK + "/w17d-install.sock"
    if os.path.exists(sock):
        os.unlink(sock)
    cmd = ("qemu-system-x86_64 -name w17dinst -accel tcg -m 3072 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-drive file=%s,if=virtio -cdrom %s -boot d" % (sock, DISK, ISO))
    q = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17d-install-serial.log"))
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
    pd = open(os.path.join(EVD, "w17d-install-serial.log"), "rb").read()
    inst_ok = b"Power down" in pd[-8192:]
    print("[w17d] install round: powerdown=%s" % inst_ok)
    if not inst_ok:
        print(pd[-900:].decode("utf-8", "replace"))
        return 1

    # 轮2：起装好的盘（grub 已装；console 序由安装器 grub.cfg——等 login）
    sock = WRK + "/w17d-boot.sock"
    cleanup_qemu()
    time.sleep(1)
    if os.path.exists(sock):
        os.unlink(sock)
    cmd = ("qemu-system-x86_64 -name w17dboot -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-drive file=%s,if=virtio" % (sock, DISK))
    q = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17d-boot-serial.log"))
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
            ser.sendline("grep -m1 17.4 /etc/motd; "
                         "OCC_SESSIONS_DIR=/tmp/sm OCC_DB=/tmp/sm.db "
                         "occ tasks 2>&1 | tail -2; "
                         "echo SMOKEDONE$((1+1))")
            wait_after(ser, mark, b"SMOKEDONE2", 120)
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
    ok17 = "17.4" in out
    oktasks = "(0 tasks)" in out
    print("[w17d] boot round: motd17.4=%s occ_tasks=%s" % (ok17, oktasks))
    print("---- battery tail ----")
    print(out[-500:])
    return 0 if (ok17 and oktasks) else 1


if __name__ == "__main__":
    sys.exit(main())
