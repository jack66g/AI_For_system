#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17nd.py — 17.11 B6 不渲染验尸：起盘→等 autologin+120s→VGA screendump
→PPM 转 PNG→退。看 tty1 究竟停在哪一帧（bash/gate/occ TUI/黑屏）。"""
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, cleanup_qemu  # noqa: E402

WRK = "/home/jack66g/k2/k3"
EVD = os.path.expanduser("~/k10-evidence")
DISK = "/tmp/w17n-target.qcow2"
MON = WRK + "/w17nd-mon.sock"
SOCK = WRK + "/w17nd-serial.sock"


def main():
    subprocess.run('pkill -f "[q]emu-system.*w17n"', shell=True)
    cleanup_qemu()
    time.sleep(1.5)
    for p in (SOCK, MON):
        if os.path.exists(p):
            os.unlink(p)
    cmd = ("qemu-system-x86_64 -name w17nd -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-monitor unix:%s,server,nowait "
           "-drive file=%s,if=virtio" % (SOCK, MON, DISK))
    q = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(SOCK, os.path.join(EVD, "w17nd-serial.log"))
    try:
        ser.wait(b"automatic login", 600)
        print("autologin seen, settling 120s...")
        time.sleep(120)
        mon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        mon.connect(MON)
        mon.setblocking(False)
        time.sleep(1)
        try:
            mon.recv(4096)
        except BlockingIOError:
            pass
        mon.sendall(b"screendump /tmp/w17nd-tty1.ppm\n")
        time.sleep(3)
        mon.sendall(b"info status\n")
        time.sleep(1)
        try:
            print(mon.recv(4096).decode("utf-8", "replace")[-200:])
        except BlockingIOError:
            pass
        mon.close()
    finally:
        ser.drain_close()
        subprocess.run('pkill -f "[q]emu-system.*w17n"', shell=True)
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()
    from PIL import Image
    img = Image.open("/tmp/w17nd-tty1.ppm")
    img.save("/tmp/w17nd-tty1.png")
    print("saved /tmp/w17nd-tty1.png %s" % (img.size,))
    return 0


if __name__ == "__main__":
    sys.exit(main())
