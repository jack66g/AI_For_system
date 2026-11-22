#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17ng.py — admin 章手动分步驱动（大间隔+步步 screendump）：
gate→unlock(90s)→TUI 帧→/shell(20s)→帧→y(12s)→帧→sudo 行(12s)→帧
→密码(30s)→帧→串口收。磁盘=run6 留盘（.last=admin，gate LOGIN 态）。"""
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

WRK = "/home/jack66g/k2/k3"
EVD = os.path.expanduser("~/k10-evidence")
DISK = "/tmp/w17n-target.qcow2"
MON = WRK + "/w17ng-mon.sock"
SOCK = WRK + "/w17ng-serial.sock"


def main():
    subprocess.run('pkill -f "[q]emu-system.*w17n"', shell=True)
    cleanup_qemu()
    time.sleep(2)
    for p in (SOCK, MON):
        if os.path.exists(p):
            os.unlink(p)
    cmd = ("qemu-system-x86_64 -name w17ng -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-monitor unix:%s,server,nowait "
           "-drive file=%s,if=virtio" % (SOCK, MON, DISK))
    q = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(SOCK, os.path.join(EVD, "w17ng-serial.log"))
    mon = None

    def shot(name):
        mon.sendall(("screendump /tmp/w17ng-%s.ppm\n" % name).encode())
        time.sleep(3)

    def key(k, gap=0.15):
        mon.sendall(("sendkey %s\n" % k).encode())
        time.sleep(gap)

    def type_line(text):
        M = {" ": "spc", "/": "slash", ".": "dot", "-": "minus"}
        for ch in text:
            key(M.get(ch, ch))
        key("ret", 0.4)

    try:
        ser.wait(b"automatic login", 600)
        wait_after(ser, len(ser.buf), rb"\+--", 300)
        time.sleep(15)
        mon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        mon.connect(MON)
        mon.setblocking(False)
        time.sleep(1)
        try:
            mon.recv(4096)
        except BlockingIOError:
            pass
        print("step: password")
        type_line("aik12345")
        time.sleep(90)
        shot("1-after-unlock-90s")
        print("step: /shell")
        type_line("/shell")
        time.sleep(20)
        shot("2-after-shell-cmd-20s")
        print("step: y")
        type_line("y")
        time.sleep(12)
        shot("3-after-y-12s")
        print("step: sudo line")
        type_line("sudo -S sh /root/mu2.sh")
        time.sleep(12)
        shot("4-after-sudo-12s")
        print("step: password")
        type_line("aik12345")
        time.sleep(40)
        shot("5-after-pw-40s")
        mark = len(ser.buf)
        time.sleep(5)
        print("serial new bytes:", len(ser.buf) - mark)
    finally:
        ser.drain_close()
        subprocess.run('pkill -f "[q]emu-system.*w17n"', shell=True)
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()
    from PIL import Image
    for n in ("1-after-unlock-90s", "2-after-shell-cmd-20s",
              "3-after-y-12s", "4-after-sudo-12s", "5-after-pw-40s"):
        p = "/tmp/w17ng-%s.ppm" % n
        if os.path.exists(p):
            Image.open(p).save("/tmp/w17ng-%s.png" % n)
            print("saved", n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
