#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17n_boot.py — 17.11 出厂装机 E2E + P-2 多用户台架章（w17m 机制克隆）。

三轮：
  轮1=ISO 装机（serial 菜单2+Y/n+Press ENTER）
  轮2=起盘→VGA sendkey 以预填 root 登录（gate 双框：用户名框预填
      console-gate.last+缺省焦点密码框——直接打密码+Enter 即登录，
      tui_gate.c:517/641 契约）→occ(root)→/shell→bat.sh（B1-B8 电池
      +M1 P-60 三目录+M2 SENSE 双面+M3 aikctl user add alice 供给）
  轮3=nbd 翻 console-gate.last=admin→起盘→打密码=admin 登录→v9 出厂
      归位（aikctl user add admin --wheel --from-gate）+v10 预建
      /var/ai/work/admin→occ(admin uid≠0)→/shell（CONFIRMED 弹框 y）
      →sudo -S mu2.sh（A1-A7：身份/预建/家目录/诚实缺席/policy/
      SENSE 暴露面 journal）
驱动面=VGA（QEMU monitor sendkey）+出面=串口（载荷自重定向 ttyS0，
w17m 正典）；证据 ~/k10-evidence/w17n-*。"""
import crypt
import io
import os
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

ISO = "/home/jack66g/AIKernel-0.1.0-alpha.17.11-x86_64.iso"
WRK = "/home/jack66g/k2/k3"
EVD = os.path.expanduser("~/k10-evidence")
DISK = "/tmp/w17n-target.qcow2"
MON = WRK + "/w17n-mon.sock"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")

sys.stdout.reconfigure(line_buffering=True)
PHASE_T0 = [0.0]


def phase(tag):
    print("== phase %-14s t=%.1fs ==" % (tag, time.time() - PHASE_T0[0]))


def bench_kill():
    subprocess.run('pkill -f "[q]emu-system.*w17n"', shell=True)


B7GEN = (
    "import json,time\n"
    "f=open('/root/b7.fifo','w')\n"
    "seq=0\n"
    "def add(psi):\n"
    "    global seq\n"
    "    seq+=1\n"
    "    f.write(json.dumps({'seq':seq,"
    "'ts':time.clock_gettime_ns(time.CLOCK_MONOTONIC),"
    "'lat_ewma_ns':1000000,'iowait_pct':5,'psi_mem_some':psi,"
    "'cache_misses':0,'valid_bits':15},separators=(',',':'))+'\\n')\n"
    "    f.flush(); time.sleep(1)\n"
    "for _ in range(3): add(100)\n"
    "add(5000)\n"
    "for _ in range(26): add(100)\n"
    "print('B7GEN_DONE')\n")
B7CONF = (
    "FEAT_SOURCE=mock\nFEAT_MOCK_FILE=/root/b7.fifo\nPOLL_HZ=1\n"
    "MODEL_TABLE=builtin\nSHADOW=1\nPARQUET_DIR=/root/b7-pq\n"
    "SHADOW_FLUSH_SEC=2\nSHADOW_FLUSH_ROWS=256\nCOMPARE_ENABLED=0\n"
    "STATS_INTERVAL_SEC=2\nLOG_DEBUG=0\n"
    "STATS_FILE=/run/b7.stats\nPID_FILE=/run/b7.pid\nLOCK_FILE=/run/b7.lock\n"
    "CANARY_ENABLED=1\nCANARY_ROLLBACK_MS=15000\n"
    "CANARY_CONFIRM_SEC=2\nCANARY_MIN_INTERVAL_SEC=1\n")

BAT = ('echo ==B1==; grep -m1 17.11 /etc/motd\necho ==B2==; aik-compat probe /bin/sh 2>&1 | tail -1\necho ==B3==; aikctl compat hw 2>&1 | head -1\necho ==B4==; aik-gcm selftest 2>&1 | tail -1\necho ==B5==; (/usr/local/sbin/aipd --conf /etc/aikernel/aipd.conf >/tmp/aipd-e2e.log 2>&1 &)\nsleep 12; grep -o \'feat_ok=[0-9]*\' /run/aipd.stats | head -1\ngrep -o \'shadow_rows=[0-9]*\' /run/aipd.stats | head -1\nkill -TERM $(cat /run/aipd.pid); sleep 2\ntail -1 /tmp/aipd-e2e.log\necho ==B7==; mkdir -p /root/b7-pq; rm -f /root/b7.fifo\nmkfifo /root/b7.fifo\n(python3 /root/b7gen.py >/root/b7gen.log 2>&1 &)\n(/usr/local/sbin/aipd --conf /root/b7.conf >/root/b7.log 2>&1 &)\nsleep 40; echo AGENTSL=$(grep -c \'name=aipd\' /proc/ai/agents); echo AGRAW=$(head -2 /proc/ai/agents); kill -TERM $(cat /run/b7.pid); sleep 3\ngrep -E \'canary_reg_ok|canary_dispatched|canary_confirmed|canary_rolled_back|canary_errors\' /run/b7.stats\necho AG6N=$(grep -c \'agent=6\' /proc/ai/decisions)\necho AGXN=$(grep -c \'executed=1\' /proc/ai/decisions)\necho SWAP=$(grep \'mm.swappiness\' /proc/ai/control | grep -o \'current=[0-9]*\' | cut -d= -f2)\ntail -2 /root/b7.log\necho ==B8==; s=startup\nfor i in $(seq 1 60); do s=$(systemctl is-system-running)\n[ "$s" = running ] && break; sleep 5; done\necho ISR=$s\necho FAILED=$(systemctl --failed --no-legend | wc -l)\nsystemctl is-active aikernel-streams.service aikernel-api.service aik-cron.service aik-log-trim.timer\necho SOFTDOG=$(lsmod | grep -c softdog)\necho UK=$(journalctl -u aikernel-streams.service --no-pager | grep -ci \'unknown key\')\necho ==M1==; ls -ld /var/ai/work /etc/aikernel/models.d /var/log/aik-console 2>&1 | awk \'{print $1,$3,$4,$NF}\'\necho ==M2==; grep -c \'^SENSE_REDACT=soft$\' /etc/aikernel/aistreamd.conf\ngrep -c \'^sense_redact = "soft"$\' /root/.aikernel/model.toml\njournalctl -u aikernel-streams.service --no-pager | grep -c \'sense_redact=soft\'\necho ==M3==; printf \'aik12345\\n\' | aikctl user add alice --password-stdin >/tmp/uadd.log 2>&1; echo UADD=$?\ngetent passwd alice | cut -d: -f1,3\naikctl user list 2>&1 | head -3\ncut -d: -f1 /etc/aikernel/console-gate\necho W17IDONE$((1+1))\n')

MU2 = (
    "systemctl stop serial-getty@ttyS0 2>/dev/null\n"
    "exec > /dev/ttyS0 2>&1\n"
    "echo ==A1==; echo SU_UID=$SUDO_UID SU_USER=$SUDO_USER; id -un\n"
    "echo ==A2==; ls -ld /var/ai/work/admin\n"
    "echo ==A3==; ls /home/admin/.occ/ 2>&1 | head -2\n"
    "echo ==A4==; ls -ld /var/ai/work/alice 2>&1 | head -1\n"
    "echo ==A5==; getent passwd admin alice | cut -d: -f1,3\n"
    "echo ==A6==; aikctl policy get 2>&1 | grep -ciE 'admin|alice'\n"
    "echo ==A7==; journalctl -u aikernel-api --no-pager"
    " | grep -m1 -o 'sense_redact=[a-z]*'\n"
    "echo W17NADONE$((1+1))\n")


def seed_gate():
    """gate=admin(首行,恒首行契约)+root 两行；.last=root（电池轮以
    root 登录=老肌肉记忆路径）；载荷三件+WD 注入（w17m 正典）。"""
    h = crypt.crypt("aik12345", "$6$w17nsalt$")
    steps = (
        "sudo qemu-nbd -c /dev/nbd1 %s" % DISK,
        "sleep 2 && sudo partx -u /dev/nbd1 2>/dev/null || true",
        "sudo mkdir -p /mnt/w17g",
        "sudo mount /dev/nbd1p2 /mnt/w17g",
        "sudo mkdir -p /mnt/w17g/etc/aikernel /mnt/w17g/var/lib/aikernel",
        "printf 'admin:%s:0\\nroot:%s:0\\n' %s %s"
        " | sudo tee /mnt/w17g/etc/aikernel/console-gate >/dev/null" % (h, h, h, h),
        "sudo chmod 600 /mnt/w17g/etc/aikernel/console-gate",
        "echo root | sudo tee /mnt/w17g/var/lib/aikernel/console-gate.last"
        " >/dev/null",
        "sudo chmod 600 /mnt/w17g/var/lib/aikernel/console-gate.last",
        "sudo cp /tmp/w17n-bat.sh /mnt/w17g/root/bat.sh",
        "sudo cp /tmp/w17n-mu2.sh /mnt/w17g/root/mu2.sh",
        "sudo cp /tmp/w17n-b7gen.py /mnt/w17g/root/b7gen.py",
        "sudo cp /tmp/w17n-b7.conf /mnt/w17g/root/b7.conf",
        "sudo sed -i 's|exec /usr/local/bin/aik-console|export OCC_TUI_WD_MS=0; exec /usr/local/bin/aik-console|' /mnt/w17g/root/.profile",
        "sudo grep -c OCC_TUI_WD_MS /mnt/w17g/root/.profile",
        "sudo sync && sudo umount /mnt/w17g",
        "sudo qemu-nbd -d /dev/nbd1",
    )
    io.open("/tmp/w17n-bat.sh", "w", newline="\n").write(
        "systemctl stop serial-getty@ttyS0 2>/dev/null\n"
        "exec > /dev/ttyS0 2>&1\n" + BAT)
    io.open("/tmp/w17n-mu2.sh", "w", newline="\n").write(MU2)
    io.open("/tmp/w17n-b7gen.py", "w", newline="\n").write(B7GEN)
    io.open("/tmp/w17n-b7.conf", "w", newline="\n").write(B7CONF)
    for s in steps:
        r = subprocess.run(s, shell=True, capture_output=True, text=True)
        assert r.returncode == 0, "%s\n%s" % (s, r.stderr)
    print("gate seeded (admin+root/aik12345, .last=root) + payloads")


def flip_last(user):
    """轮间翻 console-gate.last（轮3=admin 登录=v9 出厂归位+v10 预建）。"""
    steps = (
        "sudo qemu-nbd -c /dev/nbd1 %s" % DISK,
        "sleep 2 && sudo partx -u /dev/nbd1 2>/dev/null || true",
        "sudo mount /dev/nbd1p2 /mnt/w17g",
        "echo %s | sudo tee /mnt/w17g/var/lib/aikernel/console-gate.last"
        " >/dev/null" % user,
        "sudo sync && sudo umount /mnt/w17g",
        "sudo qemu-nbd -d /dev/nbd1",
    )
    for s in steps:
        r = subprocess.run(s, shell=True, capture_output=True, text=True)
        assert r.returncode == 0, "%s\n%s" % (s, r.stderr)
    print("console-gate.last -> %s" % user)


def install_round():
    sock = WRK + "/w17n-install.sock"
    cleanup_qemu()
    bench_kill()
    time.sleep(1)
    for p in (sock, DISK):
        if os.path.exists(p):
            os.unlink(p)
    r = subprocess.run("qemu-img create -f qcow2 %s 20G" % DISK,
                       shell=True, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    cmd = ("qemu-system-x86_64 -name w17ninst -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-drive file=%s,if=virtio -cdrom %s -boot d" % (sock, DISK, ISO))
    q = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17n-install-serial.log"))
    try:
        for _ in range(3):
            ser.send(b"\x1b[B")
            time.sleep(0.4)
        ser.send(b"\r")
        ser.wait(b"Y/n", 900)
        time.sleep(0.5)
        mark = len(ser.buf)
        ser.send(b"y\r")
        ser.wait(b"Press ENTER", 3000)
        time.sleep(1)
        ser.send(b"\r")
        wait_after(ser, mark, b"Power down", 300)
        time.sleep(3)
    finally:
        ser.drain_close()
        cleanup_qemu()
        bench_kill()
        try:
            q.wait(15)
        except Exception:
            q.kill()


def boot_round(tag, drive_line, marker, wait_cmd):
    """起盘→VGA sendkey 登录（gate 预填 .last+焦点密码框=打密码即登录）
    →/shell→（CONFIRMED 弹框 y）→命令→串口 marker。drive_line=登录后
    依次注入的行。返回 (out, b6w, b6t)。"""
    sock = WRK + "/w17n-boot.sock"
    cleanup_qemu()
    bench_kill()
    time.sleep(1.5)
    for p in (sock, MON):
        if os.path.exists(p):
            os.unlink(p)
    cmd = ("qemu-system-x86_64 -name w17nboot -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-monitor unix:%s,server,nowait "
           "-drive file=%s,if=virtio" % (sock, MON, DISK))
    q = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    PHASE_T0[0] = time.time()
    phase("qemu-start[%s]" % tag)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17n-boot-%s-serial.log" % tag))
    out = ""
    b6 = (False, False)
    b1_mark = 0
    try:
        ser.wait(b"automatic login", 600)
        phase("autologin-seen")
        wiz = wait_after(ser, len(ser.buf), rb"\+--", 240)
        print("B6 gate render [%s]:" % tag, wiz)
        assert wiz, "B6 FAIL: gate 未渲染（串口）"
        time.sleep(15)                  # 双 gate 落定
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
            # 只打无 shift 组合字符（驱动行禁用 | & ; > < 等组合键面）
            M = {" ": "spc", "/": "slash", ".": "dot", "-": "minus",
                 "=": "equal"}
            for ch in text:
                key(M.get(ch, ch))
            key("ret")

        main_tui = False
        for attempt in range(8):
            type_line("aik12345")       # gate 预填 .last 用户，密码即登录
            time.sleep(25)              # TUI 冷启（WD-off 后应快）
            for line in drive_line:
                type_line(line)
                time.sleep(8)
            mark = len(ser.buf)
            if wait_after(ser, mark, marker, wait_cmd):
                main_tui = True
                b1_mark = mark
                print("sendkey drive OK [%s attempt %d] - marker on serial"
                      % (tag, attempt + 1))
                break
            print("sendkey attempt %d [%s]: no marker, retry"
                  % (attempt + 1, tag))
        phase("main-tui[%s]" % tag)
        print("B6 main TUI [%s]:" % tag, main_tui)
        b6 = (wiz, main_tui)
        wait_after(ser, b1_mark, wait_done[tag], 600)
        phase("done[%s]" % tag)
        out = ANSI.sub(b"", ser.buf[b1_mark:]).replace(
            b"\r", b"").decode("utf-8", "replace")
        try:
            ser.sendline("poweroff -f")
            ser.wait(b"Power down", 240)
        except Exception:
            pass
    finally:
        ser.drain_close()
        cleanup_qemu()
        bench_kill()
        try:
            q.wait(15)
        except Exception:
            q.kill()
    return out, b6


# 轮2：root 电池（/shell 无弹框，直跑 bat.sh）
ROOT_DRIVE = ["/shell", "sh /root/bat.sh"]
# 轮3：admin（CONFIRMED 弹框 y/n 单键；sudo -S 密码走下一行 stdin——
# 驱动行禁管道：QEMU sendkey 无 shift 组合键面）
ADMIN_DRIVE = ["/shell", "y", "sudo -S sh /root/mu2.sh", "aik12345"]
wait_done = {"root": b"W17IDONE2", "admin": b"W17NADONE2"}


def blk(out, tag, nxt):
    if tag not in out or nxt not in out:
        return ""
    return out.rsplit(tag, 1)[1].rsplit(nxt, 1)[0]


def main():
    os.makedirs(EVD, exist_ok=True)
    if "--boot-only" not in sys.argv:
        print("== install round ==")
        install_round()
        print("== seed gate ==")
        seed_gate()
    if "--install-only" in sys.argv:
        print("INSTALL-ONLY-DONE")
        return 0

    print("== boot round 2: root battery ==")
    out, (b6w, b6t) = boot_round("root", ROOT_DRIVE, b"==B1==", 90)
    with open(os.path.join(EVD, "w17n-battery.txt"), "w") as fh:
        fh.write(out)
    b5 = blk(out, "==B5==", "==B7==")
    b7 = out.rsplit("==B7==", 1)[1].rsplit("==B8==", 1)[0] \
        if "==B8==" in out else ""
    b8 = blk(out, "==B8==", "==M1==")
    m1 = blk(out, "==M1==", "==M2==")
    m2 = blk(out, "==M2==", "==M3==")
    m3 = blk(out, "==M3==", "W17IDONE2")
    b7kv = dict(re.findall(r"(canary_\w+)=(\d+)", b7))
    units_active = sum(1 for ln in b8.splitlines()
                       if ln.strip() == "active")
    m1_lines = [ln for ln in m1.splitlines() if "root root" in ln]
    m2_lines = [ln.strip() for ln in m2.splitlines() if ln.strip()]
    ok = {
        "B1 motd17.11": "17.11" in blk(out, "==B1==", "==B2=="),
        "B2 probe runnable": "runnable=1" in blk(out, "==B2==", "==B3=="),
        "B3 hw honest": "iommu_groups" in blk(out, "==B3==", "==B4=="),
        "B4 gcm nist": "ok=3" in blk(out, "==B4==", "==B5=="),
        "B5 feat_ok>=1": bool(re.search(r"feat_ok=[1-9]", b5)),
        "B5 shadow rows": bool(re.search(r"shadow_rows=[1-9]", b5)),
        "B6 wizard+TUI": b6w and b6t,
        "B7 reg_ok=1": b7kv.get("canary_reg_ok") == "1",
        "B7 dispatch=1": b7kv.get("canary_dispatched") == "1",
        "B7 confirm=1": b7kv.get("canary_confirmed") == "1",
        "B7 rollback=0": b7kv.get("canary_rolled_back") == "0",
        "B7 errors=0": b7kv.get("canary_errors") == "0",
        "B7 agent6 记账": bool(re.search(r"AGENTSL=[1-9]", b7)),
        "B7 agent6 决策": bool(re.search(r"AG6N=[1-9]", b7)
                         and re.search(r"AGXN=[1-9]", b7)),
        "B7 swap=100": "SWAP=100" in b7,
        "B8 ISR=running": "ISR=running" in b8,
        "B8 failed=0": "FAILED=0" in b8,
        "B8 units 4xactive": units_active >= 4,
        "B8 softdog>=1": bool(re.search(r"SOFTDOG=[1-9]", b8)),
        "B8 unknown-key=0": "UK=0" in b8,
        "M1 三目录 root:root": len(m1_lines) >= 3,
        "M2 conf soft": len(m2_lines) >= 1 and m2_lines[0] == "1",
        "M2 model.toml soft": len(m2_lines) >= 2 and m2_lines[1] == "1",
        "M2 streams journal soft": len(m2_lines) >= 3
        and m2_lines[2] != "0",
        "M3 alice 供给 rc0": "UADD=0" in m3,
        "M3 passwd 行": "alice:" in m3,
        "M3 gate 名册": ("admin" in m3 and "root" in m3
                    and "alice" in m3),
    }
    for k, v in ok.items():
        print("%-22s %s" % (k, "PASS" if v else "FAIL"))
    print("---- battery tail ----")
    print(out[-900:])
    if not all(ok.values()):
        return 1

    print("== flip .last=admin ==")
    flip_last("admin")
    print("== boot round 3: admin chapter ==")
    out2, (a6w, a6t) = boot_round("admin", ADMIN_DRIVE, b"==A1==", 90)
    with open(os.path.join(EVD, "w17n-admin.txt"), "w") as fh:
        fh.write(out2)
    a1 = blk(out2, "==A1==", "==A2==")
    a2 = blk(out2, "==A2==", "==A3==")
    a3 = blk(out2, "==A3==", "==A4==")
    a4 = blk(out2, "==A4==", "==A5==")
    a5 = blk(out2, "==A5==", "==A6==")
    a6 = blk(out2, "==A6==", "==A7==")
    a7 = blk(out2, "==A7==", "W17NADONE2")
    su = re.search(r"SU_UID=(\d+)", a1)
    ok2 = {
        "A1 身份真化 SUDO_UID!=0": bool(su and su.group(1) != "0"),
        "A1 归位 SU_USER=admin": "SU_USER=admin" in a1,
        "A2 v10 预建属 admin": bool(re.search(r"admin\s+admin"
                                          r".*work/admin", a2)),
        "A2 v10 权限 0700": "drwx------" in a2,
        "A3 家 .occ 在": ("No such" not in a3 and "无法访问" not in a3),
        "A4 alice 诚实缺席": ("No such" in a4 or "无法访问" in a4),
        "A5 双号在册": ("admin" in a5 and "alice" in a5),
        "A6 policy 载名": bool(re.search(r"^\s*[1-9]\d*\s*$", a6)),
        "A7 SENSE 暴露 soft": "sense_redact=soft" in a7,
        "A 串口 marker": "W17NADONE2" in out2,
    }
    for k, v in ok2.items():
        print("%-22s %s" % (k, "PASS" if v else "FAIL"))
    print("---- admin tail ----")
    print(out2[-700:])
    if all(ok2.values()) and "--keep-disk" not in sys.argv:
        try:
            os.unlink(DISK)
            print("disk cleaned (随跑随清)")
        except OSError:
            pass
    return 0 if all(ok2.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
