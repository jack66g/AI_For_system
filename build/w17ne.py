#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17ne.py — 修案直验：盘上 model.toml 补 [models.cloud] 骨架→起盘
→sendkey 密码→gate→TUI→/shell→bat.sh→串口 ==B1==。"""
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
MON = WRK + "/w17ne-mon.sock"
SOCK = WRK + "/w17ne-serial.sock"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]") if False else None

CLOUD = ('[models.cloud]\n'
         'provider_type = "openai_compatible"\n'
         'api_key = ""\n')


def patch_disk():
    subprocess.run("sudo umount /mnt/w17d 2>/dev/null; "
                   "sudo qemu-nbd -d /dev/nbd1 2>/dev/null; true",
                   shell=True)
    mt = "/mnt/w17d/root/.aikernel/model.toml"
    script = (
        "sudo qemu-nbd -c /dev/nbd1 " + DISK + " && sleep 2 && "
        "sudo partx -u /dev/nbd1 2>/dev/null; "
        "sudo mount /dev/nbd1p2 /mnt/w17d && "
        "sudo mkdir -p /mnt/w17d/root/.aikernel && "
        "(sudo grep -q '\\[models.cloud\\]' " + mt + " || "
        "echo '[models.cloud]' | sudo tee -a " + mt + " >/dev/null) && "
        "(sudo grep -q 'provider_type' " + mt + " || "
        "echo 'provider_type = \"openai_compatible\"' | sudo tee -a " + mt +
        " >/dev/null) && "
        "(sudo grep -q '^api_key = \"\"$' " + mt + " || "
        "echo 'api_key = \"\"' | sudo tee -a " + mt + " >/dev/null) && "
        "echo ---tail--- && sudo tail -4 " + mt + " && "
        "sudo sync && sudo umount /mnt/w17d && sudo qemu-nbd -d /dev/nbd1")
    r = subprocess.run(script, shell=True, capture_output=True, text=True)
    print(r.stdout[-400:])
    assert r.returncode == 0, r.stderr[-400:]


def main():
    patch_disk()
    subprocess.run('pkill -f "[q]emu-system.*w17n"', shell=True)
    cleanup_qemu()
    time.sleep(1.5)
    for p in (SOCK, MON):
        if os.path.exists(p):
            os.unlink(p)
    cmd = ("qemu-system-x86_64 -name w17ne -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-monitor unix:%s,server,nowait "
           "-drive file=%s,if=virtio" % (SOCK, MON, DISK))
    q = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(SOCK, os.path.join(EVD, "w17ne-serial.log"))
    try:
        ser.wait(b"automatic login", 600)
        wiz = wait_after(ser, len(ser.buf), rb"\+--", 300)
        print("GATE_RENDER:", wiz)
        if not wiz:
            return 1
        time.sleep(15)
        mon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        mon.connect(MON)
        mon.setblocking(False)
        time.sleep(1)
        try:
            mon.recv(4096)
        except BlockingIOError:
            pass

        def key(k, gap=0.12):
            mon.sendall(("sendkey %s\n" % k).encode())
            time.sleep(gap)

        def type_line(text):
            M = {" ": "spc", "/": "slash", ".": "dot", "-": "minus"}
            for ch in text:
                key(M.get(ch, ch))
            key("ret")

        for attempt in range(4):
            type_line("aik12345")
            time.sleep(25)
            type_line("/shell")
            time.sleep(8)
            type_line("sh /root/bat.sh")
            mark = len(ser.buf)
            if wait_after(ser, mark, b"==B1==", 90):
                print("B1_ON_SERIAL: True (attempt %d)" % (attempt + 1))
                wait_after(ser, mark, b"W17IDONE2", 900)
                out = ser.buf[mark:].replace(b"\r", b"").decode(
                    "utf-8", "replace")
                with open(os.path.join(EVD, "w17ne-battery.txt"), "w") as fh:
                    fh.write(out)
                print(out[-600:])
                return 0
            print("attempt %d no B1" % (attempt + 1))
        return 1
    finally:
        try:
            ser.sendline("poweroff -f")
            ser.wait(b"Power down", 60)
        except Exception:
            pass
        ser.drain_close()
        subprocess.run('pkill -f "[q]emu-system.*w17n"', shell=True)
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()


if __name__ == "__main__":
    sys.exit(main())
