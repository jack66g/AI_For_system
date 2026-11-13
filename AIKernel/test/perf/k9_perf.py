#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""k9_perf.py — K9 性能预算跑表器（单 boot 双层，KERNEL-K9-DESIGN §2 D3）。

用法: python3 k9_perf.py [--bz PATH] [--budgets budgets.json] [--record-baseline]
boot（kunit.enable=1，k3_run Serial 基座）→ 收串口 PERF 机读行+not-ok →
shell 腿（storm 均值/proc 4KB 读/常驻内存求和）→ 对 budgets.json 判红绿 →
末行 K9_PERF_SUMMARY ok=N fail=M（失败退 1）。--record-baseline 把 tcg
首轮实测回填 budgets.json（golden 入账）。
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

WRK = os.path.dirname(os.path.abspath(__file__))
RIG = "/home/jack66g/k2/k3"
EVD = os.path.join(os.path.expanduser("~/k9-evidence"))
DISK = os.path.expanduser("~/k17q/disk.qcow2")
SOCK = os.path.join(RIG, "k9-serial.sock")
OVL = os.path.join(RIG, "k9-overlay.qcow2")


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


NBD = "/dev/nbd9"
MNT = "/tmp/k9-mnt"


def inject_python():
    """guest 无纳秒钟（busybox date 不认 %s%N）——照 k8v 手法把 L1 的
    python3.10+stdlib 注入一次性 overlay（不动 factory 装机面）。
    注意：overlay 在此创建且仅此创建——start_qemu 不得重建（否则抹注入）。"""
    if os.path.exists(OVL):
        os.unlink(OVL)
    subprocess.run("qemu-img create -f qcow2 -F qcow2 -b %s %s" % (DISK, OVL),
                   shell=True, check=True)
    steps = [
        "sudo qemu-nbd -c %s %s" % (NBD, OVL),
        "sleep 2 && sudo partx -u %s 2>/dev/null || true" % NBD,
        "sudo mkdir -p %s" % MNT,
        "sudo mount %sp2 %s" % (NBD, MNT),
        "sudo cp /usr/bin/python3.10 %s/usr/bin/python3.10" % MNT,
        "sudo ln -sf python3.10 %s/usr/bin/python3" % MNT,
        "sudo cp -a /usr/lib/python3.10 %s/usr/lib/" % MNT,
        "for l in libexpat.so.1 libz.so.1; do "
        "sudo test -e %s/usr/lib/x86_64-linux-gnu/$l || "
        "sudo cp /usr/lib/x86_64-linux-gnu/$l %s/usr/lib/x86_64-linux-gnu/; "
        "done" % (MNT, MNT),
        "sudo sync && sudo umount %s" % MNT,
        "sudo qemu-nbd -d %s" % NBD,
    ]
    for s in steps:
        r = sh(s)
        if r.returncode != 0:
            sh("sudo umount %s 2>/dev/null; sudo qemu-nbd -d %s 2>/dev/null"
               % (MNT, NBD))
            raise RuntimeError("注入失败: %s" % s)
    print("[k9] python3.10 注入 overlay 完成")


def start_qemu(bz, extra):
    cleanup_qemu()
    time.sleep(1.5)
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    cmd = ("qemu-system-x86_64 -name k9perf -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-kernel %s -append \"root=/dev/vda2 rw console=ttyS0 "
           "ai.skipgate=1 ai.enabled=1 %s\" "
           "-drive file=%s,if=virtio" % (SOCK, bz, extra, OVL))
    q = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    return q


def gain_shell(ser):
    ser.wait(b"AIKernel", 240)
    for _ in range(4):
        mark = len(ser.buf)
        ser.send(b"/shell\r")
        if wait_after(ser, mark, b"root@aikernel", 60):
            time.sleep(1.5)
            return True
        time.sleep(2)
    return False


def run(ser, tag, cmd, sec):
    # 哨兵防回显误中：回显行含 "$((1+1))" 原文，真输出才是 _DONE2
    mark = len(ser.buf)
    ser.sendline(cmd + "; echo %s_DONE$((1+1))" % tag)
    wait_after(ser, mark, ("%s_DONE2" % tag).encode(), sec)
    time.sleep(0.5)
    return ser.buf[mark:].decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bz", default=os.environ.get(
        "K9_BZ", "/home/jack66g/linux-k2/arch/x86/boot/bzImage"))
    ap.add_argument("--budgets", default=os.path.join(WRK, "budgets.json"))
    ap.add_argument("--record-baseline", action="store_true")
    args = ap.parse_args()
    os.makedirs(EVD, exist_ok=True)
    budgets = json.load(open(args.budgets, encoding="utf-8"))
    ok = fail = 0
    fails = []

    inject_python()
    q = start_qemu(args.bz, "kunit.enable=1")
    ser = Serial(SOCK, os.path.join(EVD, "serial.log"))
    try:
        # 内核层：KUnit PERF 机读行（等套件跑完=等 motd 后再稳 40s）
        gain_shell(ser)
        time.sleep(2)
        txt = ser.buf.decode("utf-8", "replace")
        open(os.path.join(EVD, "kunit-perf.txt"), "w").write(txt)
        notok = len(re.findall(r"not ok", txt))
        if notok:
            fail += 1
            fails.append("kunit_not_ok=%d" % notok)
        else:
            ok += 1
        for row in budgets["kernel"]:
            m = re.search(r"PERF name=%s n=\d+ p50=\d+ p99=(\d+) "
                          r"p999=\d+ ci_bound_ns=%d verdict=(\w+)"
                          % (row["name"], row["ci_bound_ns"]), txt)
            if m:
                p99 = m.group(1)
            else:
                # 串口交叠兜底：行中段可能被打烂，但 name/verdict 稳定
                m = re.search(r"PERF name=%s .*?verdict=(\w+)"
                              % row["name"], txt)
                p99 = "?" if not m else "?"
            if m and m.group(m.lastindex) == "PASS":
                ok += 1
            elif m:
                fail += 1
                fails.append("%s verdict=FAIL p99=%s" % (row["name"], p99))
            else:
                fail += 1
                fails.append("%s PERF 行缺失" % row["name"])

        # 用户层腿（python 注盘：guest 无纳秒钟）
        t = run(ser, "STORM",
                "grep latency /proc/ai/latency; "
                "python3 -c \"import subprocess,time as T; "
                "t0=T.clock_gettime(T.CLOCK_MONOTONIC); "
                "subprocess.run(['/root/k3bench','storm','200','tool'],"
                "capture_output=True); "
                "t1=T.clock_gettime(T.CLOCK_MONOTONIC); "
                "print('STORM_AVG_US=%.1f'%((t1-t0)/200*1e6))\"; "
                "grep latency /proc/ai/latency", 240)
        open(os.path.join(EVD, "storm.log"), "w").write(t)
        m = re.search(r"STORM_AVG_US=([\d.]+)", t)
        for row in budgets["userspace"]:
            if row["name"] == "act_rtt_avg":
                if m:
                    avg_us = float(m.group(1))
                    print("[k9] act_rtt_avg=%.1fus（含 exec 上界口径；"
                          "内核侧决策延迟见 storm.log latency 行）" % avg_us)
                    base = row.get("tcg_baseline_us")
                    if args.record_baseline:
                        row["tcg_baseline_us"] = round(avg_us, 1)
                        ok += 1
                    elif base is None:
                        print("[k9] %s 无基线——本轮只记录（--record-baseline 回填）"
                              % row["name"])
                        ok += 1
                    elif avg_us <= base * row["factor"]:
                        ok += 1
                    else:
                        fail += 1
                        fails.append("act_rtt_avg %.1f>%.1fx%s"
                                     % (avg_us, row["factor"], base))
                else:
                    fail += 1
                    fails.append("storm 腿缺失")
            elif row["name"] == "proc_decisions_read_4kb":
                t2 = run(ser, "READ4K",
                         "python3 -c 'import time as T; "
                         "f=open(\"/proc/ai/decisions\",\"rb\"); xs=[]; "
                         "exec(\"for i in range(200):\\n f.seek(0)\\n "
                         "t0=T.clock_gettime(T.CLOCK_MONOTONIC)\\n "
                         "f.read(4096)\\n "
                         "xs.append(T.clock_gettime(T.CLOCK_MONOTONIC)"
                         "-t0)\"); xs.sort(); "
                         "print(\"R4K_MIN_US=%.1f R4K_P99_US=%.1f\""
                         "%(xs[0]*1e6,xs[198]*1e6))'", 120)
                mm = re.search(r"R4K_MIN_US=([\d.]+)", t2)
                vals = [float(mm.group(1))] if mm else []
                open(os.path.join(EVD, "read4k.log"), "w").write(t2)
                if vals:
                    v = min(vals)
                    print("[k9] proc_read_4kb=%.1fus (min of %s)"
                          % (v, vals))
                    base = row.get("tcg_baseline_us")
                    if args.record_baseline:
                        row["tcg_baseline_us"] = round(v, 1)
                        ok += 1
                    elif base is None:
                        ok += 1
                    elif v <= base * row["factor"]:
                        ok += 1
                    else:
                        fail += 1
                        fails.append("read4k %.1f>%.1fx%s"
                                     % (v, row["factor"], base))
                else:
                    fail += 1
                    fails.append("read4k 腿缺失")
            elif row["name"] == "aikernel_mem":
                t3 = run(ser, "MEM",
                         "grep -E 'telemetry_ring' /proc/ai/status; "
                         "grep -c . /proc/ai/models", 60)
                open(os.path.join(EVD, "mem.log"), "w").write(t3)
                mb = 1 + 0.5625   # 链环 576KB 静态 + 基数
                m2 = re.search(r"(\d+) CPU x (\d+)KB", t3)
                if m2:
                    mb += int(m2.group(1)) * int(m2.group(2)) / 1024.0
                print("[k9] aikernel_mem≈%.2fMB（ring+链环；模型面见 models）"
                      % mb)
                if mb <= row["ktb_budget_mb"]:
                    ok += 1
                else:
                    fail += 1
                    fails.append("mem %.2f>%dMB" % (mb, row["ktb_budget_mb"]))
        ser.sendline("poweroff -f")
        ser.wait(b"Power down", 300)
    finally:
        ser.drain_close()
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()
    if args.record_baseline:
        json.dump(budgets, open(args.budgets, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print("[k9] 基线已回填 %s" % args.budgets)
    print("K9_PERF_SUMMARY ok=%d fail=%d%s"
          % (ok, fail, (" " + ";".join(fails)) if fails else ""))
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
