#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17e_boot.py — 17.5 起盘 E2E（w17d_boot2 同型+battery 扩展）。
盘=/tmp/w17e-target.qcow2（install 轮已装完；安装器末次重启手势=
E10 登记尾巴，起盘成功即安装真证明）。电池五件：motd 17.5/
aik-compat probe/aikctl hw/aik-gcm NIST/aipd map35 真机轮。
证据 ~/k10-evidence/w17e-boot-serial.log。"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

WRK = "/home/jack66g/k2/k3"
EVD = os.path.expanduser("~/k10-evidence")
DISK = "/tmp/w17e-target.qcow2"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")

BATTERY = (
    "echo ==B1==; grep -m1 17.5 /etc/motd; "
    # B2 整合修：factory rootfs 无 busybox（Ubuntu base 只 coreutils）——
    # 探 /bin/sh（dash 动态链）runnable=1 语义同。
    "echo ==B2==; aik-compat probe /bin/sh 2>&1 | tail -1; "
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

os.makedirs(EVD, exist_ok=True)
cleanup_qemu()
time.sleep(1)
sock = WRK + "/w17e-boot.sock"
if os.path.exists(sock):
    os.unlink(sock)
cmd = ("qemu-system-x86_64 -name w17eboot -accel tcg -m 2048 -smp 2 "
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
print("---- battery ----")
print(out[-800:])
sys.exit(0 if all(ok.values()) else 1)
