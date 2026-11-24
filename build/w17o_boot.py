#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17o_boot.py — 17.11.1 出厂装机 E2E + 真实首启章 + 多用户台架章
（w17n_boot.py 机制克隆；w17n 是 17.11 的验收记录，不再就地改）。

与 w17n 的区别：**凭据文件不再预种**。
w17n 用 nbd 预写一份 0640 root:aik-gate 的 console-gate（admin+root 两行）
再开机——首启缺口（root 向导建出的文件是 0600 root:root，普通用户从此
登录不了）在台架上永远验不到。本脚本：

  轮1  ISO 装机（serial 菜单2+Y/n+Press ENTER）
  种   nbd 只放载荷（bat.sh / fb.sh / mu2a.sh / mu2b.sh / b7*）与 WD 注入；
       **断言凭据文件与 .last 都不存在**（装机后的原样）
  轮FB 真实首启：串口自动登录 root → 首启向导（「首次使用：设置 admin
       密码」）→ VGA sendkey 打密码×2 → root TUI → /shell → fb.sh：
       凭据文件 640 root:aik-gate、只有 admin 一行、哈希 $6$（F1-F6）
  桥1  nbd：向导建的文件**原样追加** root 条目（root 电池轮要以 root 登录；
       真实用户没有这一步）+ .last=root；并记下首启后 .last 的原值
  轮2  root 电池（B1-B8 + M1-M3，同 w17n）
  桥2  nbd：删 .last（=真实用户第二次开机：缺省目标 admin）
  轮3  开机：控制台出厂归位（aikctl user add admin --wheel --from-gate）
       → 降权 → admin 读凭据登录 → /shell → mu2a.sh（A1-A9）
  轮4  root 收账（倒串口）
  桥3  nbd：把凭据文件改回**存量机形态**（0600 root:root，17.10/17.11 就
       是这样）；删掉上一章的结果文件（陈旧文件不得冒充通过）；.last=admin
  轮5  存量机场景：aik-console v12 每轮幂等归一 → admin 照常登录 → mu2a.sh
  轮6  root 收账（倒串口 + v12 归一日志）

驱动面=VGA（QEMU monitor sendkey）+出面=串口（载荷自重定向 ttyS0，
w17m 正典）；root 驱动的载荷末尾 sync + poweroff -f（省掉每轮 240 秒的
死等）。证据 ~/k10-evidence/w17o-*。版本号单点=同目录 VERSION。"""
import os
import re
import socket
import subprocess
import sys
import time

L1 = os.path.expanduser("~")         # 打版机上的家目录（脚本以打版机用户跑，
WRK = L1 + "/k2/k3"                  # sudo 只用于其中的 qemu-nbd 等步骤）
sys.path.insert(0, WRK)
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

VERSION = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "VERSION"), encoding="utf-8").read().strip()
ISO = L1 + "/AIKernel-%s-x86_64.iso" % VERSION
EVD = L1 + "/k10-evidence"
DISK = "/tmp/w17o-target.qcow2"
MON = WRK + "/w17o-mon.sock"
NBD = "/dev/nbd1"
MNT = "/mnt/w17o"
PW = "aik12345"                       # 台架自设测试钥（非真机 gate 密码）
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")
WIZ_RE = "首次使用|First use: set admin password".encode("utf-8")

sys.stdout.reconfigure(line_buffering=True)
PHASE_T0 = [0.0]


def phase(tag):
    print("== phase %-16s t=%.1fs ==" % (tag, time.time() - PHASE_T0[0]))


def bench_kill():
    subprocess.run('pkill -f "[q]emu-system.*w17o"', shell=True)


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

# root 电池（同 w17n；末尾 sync + poweroff -f）
BAT = ('echo ==B1==; grep -m1 ' + VERSION + ' /etc/motd\necho ==B2==; aik-compat probe /bin/sh 2>&1 | tail -1\necho ==B3==; aikctl compat hw 2>&1 | head -1\necho ==B4==; aik-gcm selftest 2>&1 | tail -1\necho ==B5==; (/usr/local/sbin/aipd --conf /etc/aikernel/aipd.conf >/tmp/aipd-e2e.log 2>&1 &)\nsleep 12; grep -o \'feat_ok=[0-9]*\' /run/aipd.stats | head -1\ngrep -o \'shadow_rows=[0-9]*\' /run/aipd.stats | head -1\nkill -TERM $(cat /run/aipd.pid); sleep 2\ntail -1 /tmp/aipd-e2e.log\necho ==B7==; mkdir -p /root/b7-pq; rm -f /root/b7.fifo\nmkfifo /root/b7.fifo\n(python3 /root/b7gen.py >/root/b7gen.log 2>&1 &)\n(/usr/local/sbin/aipd --conf /root/b7.conf >/root/b7.log 2>&1 &)\nsleep 40; echo AGENTSL=$(grep -c \'name=aipd\' /proc/ai/agents); echo AGRAW=$(head -2 /proc/ai/agents); kill -TERM $(cat /run/b7.pid); sleep 3\ngrep -E \'canary_reg_ok|canary_dispatched|canary_confirmed|canary_rolled_back|canary_errors\' /run/b7.stats\necho AG6N=$(grep -c \'agent=6\' /proc/ai/decisions)\necho AGXN=$(grep -c \'executed=1\' /proc/ai/decisions)\necho SWAP=$(grep \'mm.swappiness\' /proc/ai/control | grep -o \'current=[0-9]*\' | cut -d= -f2)\ntail -2 /root/b7.log\necho ==B8==; s=startup\nfor i in $(seq 1 60); do s=$(systemctl is-system-running)\n[ "$s" = running ] && break; sleep 5; done\necho ISR=$s\necho FAILED=$(systemctl --failed --no-legend | wc -l)\nsystemctl is-active aikernel-streams.service aikernel-api.service aik-cron.service aik-log-trim.timer\necho SOFTDOG=$(lsmod | grep -c softdog)\necho UK=$(journalctl -u aikernel-streams.service --no-pager | grep -ci \'unknown key\')\necho ==M1==; ls -ld /var/ai/work /etc/aikernel/models.d /var/log/aik-console 2>&1 | awk \'{print $1,$3,$4,$NF}\'\necho ==M2==; grep -c \'^SENSE_REDACT=soft$\' /etc/aikernel/aistreamd.conf\ngrep -c \'^sense_redact = "soft"$\' /root/.aikernel/model.toml\njournalctl -u aikernel-streams.service --no-pager | grep -c \'sense_redact=soft\'\njournalctl -u aikernel-api.service --no-pager | grep -m1 -o \'sense_redact=[a-z]*\'\necho ==M3==; printf \'aik12345\\n\' | aikctl user add alice --password-stdin >/tmp/uadd.log 2>&1; echo UADD=$?\ngetent passwd alice | cut -d: -f1,3\naikctl user list 2>&1 | head -3\ncut -d: -f1 /etc/aikernel/console-gate\necho W17IDONE$((1+1))\nsync\npoweroff -f\n')

# 真实首启检查（root TUI 里跑）：向导刚建出的凭据文件长什么样
FB = ("#!/bin/sh\n"
      "# 首启检查：凭据文件由向导建出（本脚本不碰它）\n"
      "systemctl stop serial-getty@ttyS0 2>/dev/null\n"
      "exec > /dev/ttyS0 2>&1\n"
      "echo ==F1==; stat -c '%a %u %g' /etc/aikernel/console-gate\n"
      "echo ==F2==; awk -F: '{print $1}' /etc/aikernel/console-gate\n"
      "echo ==F3==; awk -F: '{print substr($2,1,3)}' /etc/aikernel/console-gate\n"
      "echo ==F4==; getent group aik-gate\n"
      "echo ==F5==; ls /var/lib/aikernel/ 2>&1; "
      "cat /var/lib/aikernel/console-gate.last 2>&1\n"
      "echo ==F6==; getent passwd admin >/tmp/w17o-adm.tmp 2>/dev/null; "
      "echo ADMINLOOKUP=$?; cut -d: -f1,3 /tmp/w17o-adm.tmp\n"
      "echo ==F7==; ls /var/log/aik-console/ 2>&1; "
      "grep -h gate-perm /var/log/aik-console/*.log 2>/dev/null | tail -2\n"
      "echo W17OFB$((1+1))\n"
      "sync\n"
      "poweroff -f\n")

# admin 章载荷（无 sudo——出厂无 sudo 二进制，root 收账轮 cat）
MU2A = (
    "#!/bin/sh\n"
    "exec > /home/admin/mu2a.out 2>&1\n"
    "echo ==A1==; id -u; id -un\n"
    "echo ==A2==; ls -ld /var/ai/work/admin\n"
    "echo ==A3==; ls /home/admin/.occ/ 2>&1 | head -2\n"
    "echo ==A4==; ls /var/ai/work/ 2>&1\n"
    "echo ==A5==; getent passwd admin alice | cut -d: -f1,3\n"
    "echo ==A6==; aikctl policy get 2>&1 | head -4\n"
    "echo ==A7==; id -Gn admin\n"
    "echo ==A8==; stat -c %a:%u:%g /etc/aikernel/console-gate\n"
    "echo ==A9==; cat /var/lib/aikernel/console-gate.last 2>&1\n"
    "echo W17NADONE$((1+1))\n"
    "sync\n")
MU2B = (
    "#!/bin/sh\n"
    "# root 收账轮：admin 章结果倒串口 + v12 归一日志 + 凭据文件现状\n"
    "systemctl stop serial-getty@ttyS0 2>/dev/null\n"
    "cat /home/admin/mu2a.out > /dev/ttyS0 2>&1\n"
    "echo ==L1== > /dev/ttyS0\n"
    "grep -h gate-perm /var/log/aik-console/*.log 2>/dev/null "
    "| tail -3 > /dev/ttyS0\n"
    "echo ==L2== > /dev/ttyS0\n"
    "stat -c '%a %u %g' /etc/aikernel/console-gate > /dev/ttyS0\n"
    "echo ROUND4DONE$((1+1)) > /dev/ttyS0\n"
    "sync\n"
    "poweroff -f\n")

# 台架桥（宿主侧跑，sudo；只动台架盘）
ROOT_ENTRY_SH = (
    "#!/bin/sh\n"
    "# bridge 1: append a root entry to the wizard-created gate file in place\n"
    "# (>> keeps owner/mode) so the root battery round can log in as root.\n"
    "# Real users do not have this step.\n"
    "set -e\n"
    "mnt=$1\n"
    "g=$mnt/etc/aikernel/console-gate\n"
    "echo \"after-first-boot: gate $(stat -c '%a %u %g' $g) last="
    "$(cat $mnt/var/lib/aikernel/console-gate.last 2>/dev/null || echo absent)\"\n"
    "if grep -q '^root:' $g; then echo 'root entry already present'; exit 1; fi\n"
    "h=$(awk -F: '$1==\"admin\"{print $2; exit}' $g)\n"
    "[ -n \"$h\" ] || { echo 'no admin hash in gate'; exit 1; }\n"
    "printf 'root:%s:0\\n' \"$h\" >> $g\n"
    "echo root > $mnt/var/lib/aikernel/console-gate.last\n"
    "chmod 600 $mnt/var/lib/aikernel/console-gate.last\n"
    "echo \"bridge1: gate $(stat -c '%a %u %g' $g) names: "
    "$(cut -d: -f1 $g | tr '\\n' ' ')\"\n")
NO_LAST_SH = (
    "#!/bin/sh\n"
    "# bridge 2: remove .last -- a real user's second boot has no such file,\n"
    "# so the console default target is admin.\n"
    "set -e\n"
    "mnt=$1\n"
    "rm -f $mnt/var/lib/aikernel/console-gate.last\n"
    "test ! -e $mnt/var/lib/aikernel/console-gate.last\n"
    "if chroot $mnt getent passwd admin > /dev/null 2>&1; then\n"
    "  echo 'bridge2: admin OS account ALREADY exists (unexpected)'\n"
    "  exit 1\n"
    "fi\n"
    "echo 'bridge2: .last removed; admin OS account absent (console must '\n"
    "     'create it on next boot)'\n")
LEGACY_SH = (
    "#!/bin/sh\n"
    "# bridge 3: simulate a legacy machine (17.10/17.11): gate is 0600\n"
    "# root:root. Remove the previous chapter's result file so a stale file\n"
    "# cannot pass for a fresh one.\n"
    "set -e\n"
    "mnt=$1\n"
    "g=$mnt/etc/aikernel/console-gate\n"
    "chown 0:0 $g\n"
    "chmod 600 $g\n"
    "rm -f $mnt/home/admin/mu2a.out\n"
    "test ! -e $mnt/home/admin/mu2a.out\n"
    "echo admin > $mnt/var/lib/aikernel/console-gate.last\n"
    "chmod 600 $mnt/var/lib/aikernel/console-gate.last\n"
    "echo \"bridge3: gate $(stat -c '%a %u %g' $g) (legacy form); "
    "mu2a.out cleared\"\n")


def run(s):
    r = subprocess.run(s, shell=True, capture_output=True, text=True)
    assert r.returncode == 0, "%s\n%s%s" % (s, r.stdout[-300:], r.stderr[-300:])
    if r.stdout.strip():
        print("   | " + r.stdout.strip().replace("\n", "\n   | "))
    return r.stdout


def with_disk(fn, need_lib=False):
    """挂台架盘根分区执行 fn()（每步 sudo；任一步非 0 即断言失败；必卸载）。
    need_lib：首启之后才用的桥要往 /var/lib/aikernel 写 .last——全新装机上
    这个目录可能还没有（旧台架种载荷时也是先建的）；首启之前不建，保持
    装机后的原样。"""
    subprocess.run("sudo qemu-nbd -d %s 2>/dev/null" % NBD, shell=True,
                   capture_output=True)
    for s in ("sudo qemu-nbd -c %s %s" % (NBD, DISK),
              "sleep 2 && sudo partx -u %s 2>/dev/null || true" % NBD,
              "sudo mkdir -p %s" % MNT,
              "sudo mount /dev/nbd1p2 %s" % MNT):
        run(s)
    if need_lib:
        run("sudo mkdir -p %s/var/lib/aikernel" % MNT)
    try:
        fn()
    finally:
        for s in ("sudo sync && sudo umount %s" % MNT,
                  "sudo qemu-nbd -d %s" % NBD):
            run(s)


def bridge(name, body):
    p = "/tmp/w17o-%s.sh" % name
    with open(p, "w", newline="\n") as fh:
        fh.write(body)
    with_disk(lambda: run("sudo sh %s %s" % (p, MNT)), need_lib=True)


def seed_payloads():
    """只放载荷；**不放**凭据文件（与 w17n 的根本区别）。"""
    ext = {"b7gen": "py", "b7conf": "conf"}
    files = {"bat": "systemctl stop serial-getty@ttyS0 2>/dev/null\n"
                    "exec > /dev/ttyS0 2>&1\n" + BAT,
             "fb": FB, "mu2a": MU2A, "mu2b": MU2B,
             "b7gen": B7GEN, "b7conf": B7CONF}
    for name, body in files.items():
        with open("/tmp/w17o-%s.%s" % (name, ext.get(name, "sh")), "w",
                  newline="\n") as fh:
            fh.write(body)

    def body():
        # 真实首启：凭据文件与 .last 必须不存在（装机后的原样）
        run("sudo test ! -e %s/etc/aikernel/console-gate" % MNT)
        run("sudo test ! -e %s/var/lib/aikernel/console-gate.last" % MNT)
        run("sudo cp /tmp/w17o-bat.sh %s/root/bat.sh" % MNT)
        run("sudo cp /tmp/w17o-fb.sh %s/root/fb.sh" % MNT)
        run("sudo cp /tmp/w17o-mu2a.sh %s/var/tmp/mu2a.sh" % MNT)
        run("sudo chmod 755 %s/var/tmp/mu2a.sh" % MNT)
        run("sudo cp /tmp/w17o-mu2b.sh %s/root/mu2b.sh" % MNT)
        run("sudo cp /tmp/w17o-b7gen.py %s/root/b7gen.py" % MNT)
        run("sudo cp /tmp/w17o-b7conf.conf %s/root/b7.conf" % MNT)
        run("sudo sed -i 's|exec /usr/local/bin/aik-console|export "
            "OCC_TUI_WD_MS=0; exec /usr/local/bin/aik-console|' "
            "%s/root/.profile" % MNT)
        run("sudo grep -c OCC_TUI_WD_MS %s/root/.profile" % MNT)
    with_disk(body)
    print("payloads seeded (NO gate, NO .last)")


def flip_last(user):
    def body():
        run("echo %s | sudo tee %s/var/lib/aikernel/console-gate.last "
            ">/dev/null" % (user, MNT))
        run("sudo chmod 600 %s/var/lib/aikernel/console-gate.last" % MNT)
    with_disk(body, need_lib=True)
    print("console-gate.last -> %s" % user)


def install_round():
    sock = WRK + "/w17o-install.sock"
    cleanup_qemu()
    bench_kill()
    time.sleep(1)
    for p in (sock, DISK):
        if os.path.exists(p):
            os.unlink(p)
    run("qemu-img create -f qcow2 %s 20G" % DISK)
    cmd = ("qemu-system-x86_64 -name w17oinst -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-drive file=%s,if=virtio -cdrom %s -boot d" % (sock, DISK, ISO))
    q = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17o-install-serial.log"))
    try:
        for _ in range(3):
            ser.send(b"\x1b[B")
            time.sleep(0.4)
        ser.send(b"\r")
        assert ser.wait(b"Y/n", 900), "installer menu not reached"
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


def boot_round(tag, drive_line, marker, wait_cmd, pre_sleep=25,
               line_sleep=8, wizard=False, attempts=8):
    """起盘→（首启向导：密码×2 / 常规：gate 预填 .last 用户，密码即登录）
    →TUI→/shell→命令→串口 marker。驱动面=VGA sendkey。
    返回 (out, 向导文案出现, 到达主界面)."""
    sock = WRK + "/w17o-boot.sock"
    cleanup_qemu()
    bench_kill()
    time.sleep(1.5)
    for p in (sock, MON):
        if os.path.exists(p):
            os.unlink(p)
    cmd = ("qemu-system-x86_64 -name w17obookt -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-monitor unix:%s,server,nowait "
           "-drive file=%s,if=virtio" % (sock, MON, DISK))
    q = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    PHASE_T0[0] = time.time()
    phase("qemu-start[%s]" % tag)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17o-boot-%s-serial.log" % tag))
    out = ""
    wizzed = False
    frame = False
    main_tui = False
    b1_mark = 0
    try:
        assert ser.wait(b"automatic login", 600), "no serial autologin"
        phase("autologin-seen")
        mark = len(ser.buf)           # 自动登录之后画的才是 gate/向导
        frame = wait_after(ser, mark, rb"\+--", 240)
        print("gate frame [%s]:" % tag, frame)
        assert frame, "gate frame not rendered on serial"
        if wizard:
            wizzed = wait_after(ser, mark, WIZ_RE, 30)
            print("first-run wizard text [%s]:" % tag, wizzed)
            assert wizzed, "FB FAIL: first-run wizard text not on serial"
        time.sleep(20)                  # 向导/双 gate 落定
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

        if marker is None:
            # 无串口 marker 面（admin 章载荷写文件）：单程驱动+定眠
            type_line(PW)
            time.sleep(pre_sleep)
            for line in drive_line:
                type_line(line)
                time.sleep(line_sleep)
            main_tui = True
            b1_mark = len(ser.buf)
        else:
            for attempt in range(attempts):
                type_line(PW)
                if wizard:              # 首启向导：设置密码 / 确认密码
                    time.sleep(6)
                    type_line(PW)
                time.sleep(pre_sleep)   # TUI 冷启（WD-off 后应快）
                for line in drive_line:
                    type_line(line)
                    time.sleep(line_sleep)
                mark = len(ser.buf)
                if wait_after(ser, mark, marker, wait_cmd):
                    main_tui = True
                    b1_mark = mark
                    print("sendkey drive OK [%s attempt %d]"
                          " - marker on serial" % (tag, attempt + 1))
                    break
                print("sendkey attempt %d [%s]: no marker, retry"
                      % (attempt + 1, tag))
        phase("main-tui[%s]" % tag)
        print("gate frame / main TUI [%s]:" % tag, frame, main_tui)
        if marker is not None:
            wait_after(ser, b1_mark, wait_done[tag], 600)
        else:
            time.sleep(30)              # 结果文件落盘余量（ext4 commit=5s）
        phase("done[%s]" % tag)
        out = ANSI.sub(b"", ser.buf[b1_mark:]).replace(
            b"\r", b"").decode("utf-8", "replace")
        try:
            ser.sendline("poweroff -f")     # root 载荷自己 poweroff；此行兜底
            ser.wait(b"Power down", 240 if marker is not None else 5)
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
    return out, wizzed, main_tui


FB_DRIVE = ["/shell", "sh /root/fb.sh"]
ROOT_DRIVE = ["/shell", "sh /root/bat.sh"]
ADMIN_DRIVE = ["/shell", "sh /var/tmp/mu2a.sh"]
CAT_DRIVE = ["/shell", "sh /root/mu2b.sh"]
wait_done = {"firstboot": b"W17OFB2", "root": b"W17IDONE2",
             "cat3": b"ROUND4DONE2", "cat5": b"ROUND4DONE2"}


def blk(out, tag, nxt):
    if tag not in out or nxt not in out:
        return ""
    return out.rsplit(tag, 1)[1].rsplit(nxt, 1)[0]


def report(ok):
    for k, v in ok.items():
        print("%-32s %s" % (k, "PASS" if v else "FAIL"))
    return all(ok.values())


def admin_checks(out2, pfx=""):
    a1 = blk(out2, "==A1==", "==A2==")
    a2 = blk(out2, "==A2==", "==A3==")
    a3 = blk(out2, "==A3==", "==A4==")
    a4 = blk(out2, "==A4==", "==A5==")
    a5 = blk(out2, "==A5==", "==A6==")
    a6 = blk(out2, "==A6==", "==A7==")
    a7 = blk(out2, "==A7==", "==A8==")
    a8 = blk(out2, "==A8==", "==A9==")
    a9 = blk(out2, "==A9==", "W17NADONE2")
    uid = None
    for ln in a1.splitlines():
        if ln.strip().isdigit():
            uid = re.match(r"^(\d+)$", ln.strip())
            break
    print("%sA7 groups=%r  A8 gate=%r  A9 .last=%r"
          % (pfx, a7.strip(), a8.strip(), a9.strip()))
    return {
        pfx + "A1 身份真化 uid!=0": bool(uid and uid.group(1) != "0"),
        pfx + "A1 归位名=admin": "admin" in a1,
        pfx + "A2 v10 预建属 admin": bool(re.search(r"admin\s+admin"
                                                r".*work/admin", a2)),
        pfx + "A2 v10 权限 0700": "drwx------" in a2,
        pfx + "A3 家 .occ 在": ("No such" not in a3 and "无法访问" not in a3
                            and a3.strip() != ""),
        pfx + "A4 alice 诚实缺席": ("alice" not in a4 and "admin" in a4),
        pfx + "A5 双号在册": ("admin" in a5 and "alice" in a5),
        pfx + "A6 policy 面": ("confirmed" in a6 or "restricted" in a6
                           or "privileged" in a6),
        pfx + "A7 admin 在 aik-gate 组": "aik-gate" in a7,
        pfx + "A8 凭据 0640 root:aik-gate": "640:0:942" in a8,
        pfx + "A 串口 marker": "W17NADONE2" in out2,
    }


def main():
    os.makedirs(EVD, exist_ok=True)
    assert os.path.isfile(ISO), "ISO missing: %s" % ISO
    if "--boot-only" not in sys.argv:
        print("== install round ==")
        install_round()
        print("== seed payloads (no gate) ==")
        seed_payloads()
    if "--install-only" in sys.argv:
        print("INSTALL-ONLY-DONE")
        return 0
    if "--seed-only" in sys.argv:      # 只验种载荷这一步（不开机）
        print("SEED-ONLY-DONE")
        return 0

    # ---------------- 轮 FB：真实首启 ----------------
    print("== boot round FB: real first boot (wizard) ==")
    out_fb, fb_wiz, fb_tui = boot_round(
        "firstboot", FB_DRIVE, b"==F1==", 90, pre_sleep=60, wizard=True,
        attempts=4)
    with open(os.path.join(EVD, "w17o-firstboot.txt"), "w") as fh:
        fh.write(out_fb)
    fb1 = blk(out_fb, "==F1==", "==F2==")
    fb2 = blk(out_fb, "==F2==", "==F3==")
    fb3 = blk(out_fb, "==F3==", "==F4==")
    fb4 = blk(out_fb, "==F4==", "==F5==")
    fb5 = blk(out_fb, "==F5==", "==F6==")
    fb6 = blk(out_fb, "==F6==", "==F7==")
    fb7 = blk(out_fb, "==F7==", "W17OFB2")
    print("---- first-boot raw ----")
    print(out_fb[-1500:])
    ok_fb = {
        "FB 首启向导渲染": bool(fb_wiz),
        "F1 凭据 640 root:aik-gate": "640 0 942" in fb1,
        "F2 只有 admin 一行": fb2.split() == ["admin"],
        "F3 哈希前缀 $6$": "$6$" in fb3,
        "F4 aik-gate 组在": "aik-gate:x:942:" in fb4,
        "F6 admin OS 号尚未建": ("admin:" not in fb6
                                and "ADMINLOOKUP=2" in fb6),
        "F7 首启无归一日志（本就合规）": "gate-perm" not in fb7,
        "FB 到达 root TUI": bool(fb_tui),
    }
    print("---- F5 (.last after first boot) ----")
    print(fb5.strip() or "(empty)")
    good_fb = report(ok_fb)
    if not good_fb:
        return 1

    # ---------------- 桥1：追加 root 条目（电池轮用）----------------
    print("== bridge 1: append root entry (bench-only) ==")
    bridge("root-entry", ROOT_ENTRY_SH)

    # ---------------- 轮2：root 电池 ----------------
    print("== boot round 2: root battery ==")
    out, _, b6t = boot_round("root", ROOT_DRIVE, b"==B1==", 90)
    with open(os.path.join(EVD, "w17o-battery.txt"), "w") as fh:
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
        "B1 motd==VERSION": VERSION in blk(out, "==B1==", "==B2=="),
        "B2 probe runnable": "runnable=1" in blk(out, "==B2==", "==B3=="),
        "B3 hw honest": "iommu_groups" in blk(out, "==B3==", "==B4=="),
        "B4 gcm nist": "ok=3" in blk(out, "==B4==", "==B5=="),
        "B5 feat_ok>=1": bool(re.search(r"feat_ok=[1-9]", b5)),
        "B5 shadow rows": bool(re.search(r"shadow_rows=[1-9]", b5)),
        "B6 gate+TUI": bool(b6t),
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
        "M2 api journal soft": "sense_redact=soft" in m2,
        "M3 alice 供给 rc0": "UADD=0" in m3,
        "M3 passwd 行": "alice:" in m3,
        "M3 gate 名册": ("admin" in m3 and "root" in m3
                    and "alice" in m3),
    }
    good_bat = report(ok)
    print("---- battery tail ----")
    print(out[-900:])
    if not good_bat:
        return 1

    # ---------------- 桥2：删 .last（真实第二次开机）----------------
    print("== bridge 2: remove .last (real second boot) ==")
    bridge("no-last", NO_LAST_SH)

    # ---------------- 轮3：admin 归位 + 登录 ----------------
    print("== boot round 3: admin chapter（载荷写文件，无串口 marker）==")
    boot_round("admin", ADMIN_DRIVE, None, 0, pre_sleep=90, line_sleep=25)
    flip_last("root")
    print("== boot round 4: root cat ==")
    out2, _, _ = boot_round("cat3", CAT_DRIVE, b"==A1==", 90)
    with open(os.path.join(EVD, "w17o-admin.txt"), "w") as fh:
        fh.write(out2)
    ok2 = admin_checks(out2)
    good2 = report(ok2)
    print("---- admin tail ----")
    print(out2[-700:])

    # ---------------- 桥3：存量机形态 ----------------
    print("== bridge 3: legacy gate form (0600 root:root) ==")
    bridge("legacy", LEGACY_SH)

    # ---------------- 轮5/6：存量机场景 ----------------
    print("== boot round 5: legacy-machine admin chapter ==")
    boot_round("legacy", ADMIN_DRIVE, None, 0, pre_sleep=90, line_sleep=25)
    flip_last("root")
    print("== boot round 6: root cat (legacy) ==")
    out5, _, _ = boot_round("cat5", CAT_DRIVE, b"==A1==", 90)
    with open(os.path.join(EVD, "w17o-legacy.txt"), "w") as fh:
        fh.write(out5)
    ok3 = admin_checks(out5, "L ")
    l1 = blk(out5, "==L1==", "==L2==")
    l2 = blk(out5, "==L2==", "ROUND4DONE2")
    print("L1 gate-perm log: %r" % l1.strip()[:300])
    ok3["L1 v12 归一有账（原 600 root:root）"] = (
        "gate-perm normalized to 0644 root:aik-gate" not in l1
        and "gate-perm normalized to 0640 root:aik-gate" in l1
        and "was uid=0 gid=0 mode=600" in l1)
    ok3["L2 归一后 640 root:aik-gate"] = "640 0 942" in l2
    good3 = report(ok3)
    print("---- legacy tail ----")
    print(out5[-900:])

    print("\n==== SUMMARY %s ====" % VERSION)
    print("first-boot chapter : %s" % ("PASS" if good_fb else "FAIL"))
    print("root battery       : %s" % ("PASS" if good_bat else "FAIL"))
    print("admin chapter      : %s" % ("PASS" if good2 else "FAIL"))
    print("legacy-machine     : %s" % ("PASS" if good3 else "FAIL"))
    allok = good_fb and good_bat and good2 and good3
    if allok and "--keep-disk" not in sys.argv:
        try:
            os.unlink(DISK)
            print("disk cleaned (随跑随清)")
        except OSError:
            pass
    print("W17O_%s" % ("PASS" if allok else "FAIL"))
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
