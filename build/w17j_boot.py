#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w17j_boot.py — 17.9 起盘 E2E（w17h_boot 同型+P-32/P-33 扩）。
关键差异：①GRUB 真路径起盘（-kernel 直启=串口伪影，P2 教训）②B6 首启
向导串口渲染=occ P2 修出厂验收 ③B7 aipd 金丝雀真机微钻（agent=6/
下发/confirm 持久——M2 出厂证明）④B8 出厂健康断言（P-32/P-33 补课：
is-system-running=running+四单元 active+失败单元=0+softdog 已挂+
aistreamd journal 零 unknown-key——17.8 崩溃环与模块失配两发现在此
关卡本可拦截）。证据 ~/k10-evidence/w17j-*。"""
import base64
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

ISO = "/home/jack66g/AIKernel-0.1.0-alpha.17.9-x86_64.iso"
WRK = "/home/jack66g/k2/k3"
EVD = os.path.expanduser("~/k10-evidence")
DISK = "/tmp/w17j-target.qcow2"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")

# C-P1d（2026-11-17 翻案）：boot_round 阶段耗时归因打点——离线/低配
# 冷启的时间去向不再靠猜（原「occ catalog/provider 超时」判已被 L1
# 探针推翻：occ 三态首绘 0.2s；分钟级消耗=TCG 冷启+首启 unit 风暴）。
PHASE_T0 = [0.0]


def phase(tag):
    print("== phase %-14s t=%.1fs ==" % (tag, time.time() - PHASE_T0[0]))

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


def b64(s):
    return base64.b64encode(s.encode()).decode()


def seed_gate():
    """w17e 先例：nbd 预种 console-gate（admin/aik12345）——向导设密步
    已由 P2 rig 在 17.5 盘证过（gate 落盘 admin:$6$…）；出厂 E2E 此轮
    测解锁+主 TUI+battery，避开慢启双发竞态（多轮实锤）。"""
    import crypt
    h = crypt.crypt("aik12345", "$6$w17gsalt$")
    steps = (
        "sudo qemu-nbd -c /dev/nbd1 %s" % DISK,
        "sleep 2 && sudo partx -u /dev/nbd1 2>/dev/null || true",
        "sudo mkdir -p /mnt/w17g",
        "sudo mount /dev/nbd1p2 /mnt/w17g",
        "sudo mkdir -p /mnt/w17g/etc/aikernel",
        "echo 'admin:%s:0' | sudo tee /mnt/w17g/etc/aikernel/console-gate"
        " >/dev/null" % h,
        "sudo chmod 600 /mnt/w17g/etc/aikernel/console-gate",
        "sudo sync && sudo umount /mnt/w17g",
        "sudo qemu-nbd -d /dev/nbd1",
    )
    for s in steps:
        r = subprocess.run(s, shell=True, capture_output=True, text=True)
        assert r.returncode == 0, "%s\n%s" % (s, r.stderr)
    print("gate seeded (admin/aik12345)")


def install_round():
    sock = WRK + "/w17j-install.sock"
    cleanup_qemu()
    time.sleep(1)
    if os.path.exists(sock):
        os.unlink(sock)
    if os.path.exists(DISK):
        os.unlink(DISK)
    r = subprocess.run("qemu-img create -f qcow2 %s 20G" % DISK,
                       shell=True, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    cmd = ("qemu-system-x86_64 -name w17iinst -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-drive file=%s,if=virtio -cdrom %s -boot d" % (sock, DISK, ISO))
    q = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17j-install-serial.log"))
    try:
        for _ in range(3):
            ser.send(b"\x1b[B")
            time.sleep(0.4)
        ser.send(b"\r")
        ser.wait(b"y/N", 900)
        time.sleep(0.5)
        mark = len(ser.buf)
        ser.send(b"y\r")
        # E10 尾巴：安装器末次「按回车重启」真等——补 \r 兑现
        ser.wait(b"\xe6\x8c\x89\xe5\x9b\x9e\xe8\xbd\xa6", 3000)
        time.sleep(1)
        ser.send(b"\r")
        wait_after(ser, mark, b"Power down", 300)
        time.sleep(3)
    finally:
        ser.drain_close()
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()


def boot_round():
    """GRUB 真路径起盘（无 -kernel）：向导渲染（B6）→设密→主 TUI→
    /shell→电池 B1-B5+B7+B8。"""
    sock = WRK + "/w17j-boot.sock"
    cleanup_qemu()
    time.sleep(1.5)
    if os.path.exists(sock):
        os.unlink(sock)
    cmd = ("qemu-system-x86_64 -name w17iboot -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait -drive file=%s,if=virtio"
           % (sock, DISK))
    q = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    PHASE_T0[0] = time.time()
    phase("qemu-start")
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "w17j-boot-serial.log"))
    out = ""
    b6 = (False, False)
    try:
        ser.wait(b"automatic login", 600)
        phase("autologin-seen")
        wiz = wait_after(ser, len(ser.buf), rb"\+--", 240)
        print("B6 gate render:", wiz)
        assert wiz, "B6 FAIL: 密码门未渲染（occ 串口）"
        # LOGIN=单密码框；重试环（慢启竞态：表单未就绪则重发，正确发
        # 即解锁；3-fail 冷却由间隔 8s 化解）
        main_tui = False
        # w17g 三轮验尸（盘上库为证）：密码从未被收——预 gate 回显段的
        # 残余字节可污染密码框（追加成错密）→ 3 错冷却循环烧窗。
        # 编排：先 \r 清残场（空提交/失败即清框）再灌正密；锚=空态头
        # 「· occ」（gate 横幅是「· alpha」，横幅「特权模式」不撞）；
        # 窗 600s 的真实去向=TCG 冷启+首启 unit 风暴（C-P1d 探针翻案
        # 后以 phase 打点归因；occ 首绘本身离线 0.2s）。
        m1 = "新对话".encode()
        m2 = "· occ".encode()
        for i in range(300):
            time.sleep(2)
            tail = ser.buf
            if b"deepseek" in tail or m1 in tail or m2 in tail:
                main_tui = True
                break
            if i % 4 == 0:
                ser.send(b"\r")
                time.sleep(1.2)
                ser.send(b"aik12345\r")
        phase("main-tui")
        print("B6 main TUI:", main_tui)
        assert main_tui, "B6 FAIL: 主 TUI 未上串口"
        b6 = (wiz, main_tui)
        ser.send(b"/shell\r")
        time.sleep(8)
        phase("shell-ready")
        mark = len(ser.buf)
        ser.sendline(
            "echo ==B1==; grep -m1 17.9 /etc/motd; "
            "echo ==B2==; aik-compat probe /bin/sh 2>&1 | tail -1; "
            "echo ==B3==; aikctl compat hw 2>&1 | head -1 | cut -c1-120; "
            "echo ==B4==; aik-gcm selftest 2>&1 | tail -1; "
            "echo ==B5==; (/usr/local/sbin/aipd --conf "
            "/etc/aikernel/aipd.conf >/tmp/aipd-e2e.log 2>&1 &); "
            "sleep 12; grep -o 'feat_ok=[0-9]*' /run/aipd.stats | head -1; "
            "grep -o 'shadow_rows=[0-9]*' /run/aipd.stats | head -1; "
            "kill -TERM $(cat /run/aipd.pid); sleep 2; "
            "tail -1 /tmp/aipd-e2e.log; "
            "echo ==B7==; mkdir -p /root/b7-pq; rm -f /root/b7.fifo; "
            "mkfifo /root/b7.fifo; "
            "echo %s | base64 -d > /root/b7gen.py; "
            "echo %s | base64 -d > /root/b7.conf; "
            "(python3 /root/b7gen.py >/root/b7gen.log 2>&1 &); "
            "(/usr/local/sbin/aipd --conf /root/b7.conf "
            ">/root/b7.log 2>&1 &); sleep 40; "
            "kill -TERM $(cat /run/b7.pid); sleep 3; "
            "grep -E 'canary_reg_ok|canary_dispatched|canary_confirmed|"
            "canary_rolled_back|canary_errors' /run/b7.stats; "
            "grep -o 'name=aipd actions=[0-9]*' /proc/ai/agents | head -1; "
            "grep -c 'agent=6' /proc/ai/decisions; "
            "grep -c 'executed=1' /proc/ai/decisions; "
            "grep 'mm.swappiness' /proc/ai/control | grep -o 'current=[0-9]*'; "
            "tail -2 /root/b7.log; "
            "echo ==B8==; s=startup; "
            "for i in $(seq 1 60); do "
            "s=$(systemctl is-system-running); "
            "[ \"$s\" = running ] && break; sleep 5; done; "
            "echo ISR=$s; "
            "echo FAILED=$(systemctl --failed --no-legend | wc -l); "
            "systemctl is-active aikernel-streams.service "
            "aikernel-api.service aik-cron.service aik-log-trim.timer; "
            "echo SOFTDOG=$(lsmod | grep -c softdog); "
            "echo UK=$(journalctl -u aikernel-streams.service --no-pager "
            "| grep -ci 'unknown key'); "
            "echo W17IDONE$((1+1))"
            % (b64(B7GEN), b64(B7CONF)))
        wait_after(ser, mark, b"W17IDONE2", 600)
        phase("battery-done")
        out = ANSI.sub(b"", ser.buf[mark:]).replace(
            b"\r", b"").decode("utf-8", "replace")
        ser.sendline("poweroff -f")
        try:
            ser.wait(b"Power down", 240)
        except Exception:
            pass
    finally:
        ser.drain_close()
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()
    return out, b6


def blk(out, tag, nxt):
    if tag not in out or nxt not in out:
        return ""
    return out.rsplit(tag, 1)[1].rsplit(nxt, 1)[0]


def main():
    os.makedirs(EVD, exist_ok=True)
    # --boot-only：安装/种子已过（B6 轮转用）——盘上 gate 现成
    if "--boot-only" not in sys.argv:
        print("== install round ==")
        install_round()
        print("== seed gate ==")
        seed_gate()
    if "--install-only" in sys.argv:
        print("INSTALL-ONLY-DONE")
        return 0
    print("== boot round (GRUB) ==")
    out, (b6w, b6t) = boot_round()
    with open(os.path.join(EVD, "w17j-battery.txt"), "w") as fh:
        fh.write(out)
    b5 = blk(out, "==B5==", "==B7==")
    b7 = out.rsplit("==B7==", 1)[1].rsplit("==B8==", 1)[0] \
        if "==B8==" in out else out.rsplit("==B7==", 1)[1]
    b8 = blk(out, "==B8==", "W17IDONE2")
    b7kv = dict(re.findall(r"(canary_\w+)=(\d+)", b7))
    cur = re.search(r"mm\.swappiness.*?current=(\d+)", b7)
    nums = [ln.strip() for ln in b7.splitlines() if ln.strip().isdigit()]
    units_active = sum(1 for ln in b8.splitlines()
                       if ln.strip() == "active")
    ok = {
        "B1 motd17.9": "17.9" in blk(out, "==B1==", "==B2=="),
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
        "B7 agent6 记账": "name=aipd actions=" in b7,
        "B7 agent6 决策": len(nums) >= 2 and int(nums[0]) >= 1
                         and int(nums[1]) >= 1,
        "B7 swap=100": cur is not None and cur.group(1) == "100",
        "B8 ISR=running": "ISR=running" in b8,
        "B8 failed=0": "FAILED=0" in b8,
        "B8 units 4xactive": units_active >= 4,
        "B8 softdog>=1": bool(re.search(r"SOFTDOG=[1-9]", b8)),
        "B8 unknown-key=0": "UK=0" in b8,
    }
    for k, v in ok.items():
        print("%-16s %s" % (k, "PASS" if v else "FAIL"))
    print("---- battery tail ----")
    print(out[-900:])
    return 0 if all(ok.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
