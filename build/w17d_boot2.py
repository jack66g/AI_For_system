#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17d_boot2.py — 17.4 试装盘轮2 独立跑：boot→login→motd+occ tasks。"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

WRK = "/home/jack66g/k2/k3"
EVD = os.path.expanduser("~/k10-evidence")
DISK = "/tmp/w17d-target.qcow2"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")

os.makedirs(EVD, exist_ok=True)
cleanup_qemu()
time.sleep(1)
sock = WRK + "/w17d-boot.sock"
if os.path.exists(sock):
    os.unlink(sock)
cmd = ("qemu-system-x86_64 -name w17dboot -accel tcg -m 2048 -smp 2 "
       "-display none -nic none -no-reboot "
       "-serial unix:%s,server,nowait -drive file=%s,if=virtio"
       % (sock, DISK))
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
sys.exit(0 if (ok17 and oktasks) else 1)
