#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""k11_golden.py — K11 全链 golden 跑表器（KERNEL-K11-DESIGN.md D3 两幕）。

幕一（rig）：注盘（k8v 手法：qemu-nbd 注 aikctl+python3.10+aistreamd
  +新 occ+conf）→ boot strong（aichain.seed= kunit.enable=0）→
  occ TUI 内敲 /status（D1 实机内核行截取）→ /shell 落 bash →
  storm 300（意图代理=K3 agent 工具动作）→ aistreamd AS_ONCE+AS_DUMP
  短跑 → aikctl audit verify（rig 内）→ decisions 尾窗+audit 全量+
  parquet base64 导出。
幕二（L1）：断言器——①storm 全成；②链配对（k=1/k=2 节点 decision_id
  集合相等——d= hex 前 8B LE 解码）；③ASDump 每条 id ∈ 内核 ring 尾窗；
  ④parquet 块落盘非空（+pq_dump 行数若可用）；⑤三件套前后一致；
  ⑥红路自证：抽掉一条 k=2 节点→配对断言必须 FAIL（断链即红）。
输出 GOLDEN_SUMMARY。IO 定式=子进程；串口哨兵 $((1+1))。
"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, "/home/jack66g/k2/k3")
from k3_run import Serial, wait_after, cleanup_qemu  # noqa: E402

REPO = "/home/jack66g/aikernel-repo-alpha11"
TREE = "/home/jack66g/linux-k2"
WRK = "/home/jack66g/k2/k3"
EVD = os.path.expanduser("~/k11-evidence")
OVL = WRK + "/k11-overlay.qcow2"
SOCK = WRK + "/k11.sock"
DISK = os.path.expanduser("~/k17q/disk.qcow2")
NBD, NBD_PART, MNT = "/dev/nbd0", "/dev/nbd0p2", "/mnt/k11-inject"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")


def clean(raw):
    """ANSI 剥除 + ONLCR 的 \r 剥除（run4 实抓：跨行正则被 \r 断）。"""
    return ANSI.sub(b"", raw).replace(b"\r", b"").decode("utf-8", "replace")
SEED = "0x11aa22bb"

results = []


def phase(name, ok, note=""):
    results.append((name, ok, note))
    print("[k11] %-30s %s %s" % (name, "PASS" if ok else "FAIL", note),
          flush=True)


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def inject():
    if os.path.exists(OVL):
        os.unlink(OVL)
    sh("qemu-img create -f qcow2 -F qcow2 -b %s %s" % (DISK, OVL))
    conf = ("SME_URL=http://127.0.0.1:8000\n"
            "IMPORTANCE=0.3\n"
            "PARQUET_ENABLED=1\n"
            "PARQUET_DIR=/root/k11/pq\n"
            "PARQUET_FLUSH_SEC=1\n"
            "PARQUET_FLUSH_ROWS=1\n"
            "DECISIONS_ENABLED=1\n"
            "DECISIONS_INTERVAL_SEC=1\n"
            "DECISIONS_SCAN_MAX=2000\n"
            "DECISIONS_BATCH_MAX=1024\n"
            "DECISIONS_WRITE_SME=0\n")
    open("/tmp/k11.conf", "w").write(conf)
    steps = [
        "sudo qemu-nbd -c %s %s" % (NBD, OVL),
        "sleep 2 && sudo partx -u %s 2>/dev/null || true" % NBD,
        "sudo mkdir -p %s" % MNT,
        "sudo mount %s %s" % (NBD_PART, MNT),
        # 目录必须 mount 之后建（mount 前建=被挂载盖住，run1 实抓）
        "sudo mkdir -p %s/root/k11 %s/usr/local/bin" % (MNT, MNT),
        "sudo cp %s/agent/ai/aikctl/aikctl %s/root/k11/aikctl && "
        "sudo chmod 0755 %s/root/k11/aikctl" % (REPO, MNT, MNT),
        "sudo cp /usr/bin/python3.10 %s/usr/bin/python3.10" % MNT,
        "sudo ln -sf python3.10 %s/usr/bin/python3" % MNT,
        "sudo cp -a /usr/lib/python3.10 %s/usr/lib/" % MNT,
        "for l in libexpat.so.1 libz.so.1; do sudo test -e "
        "%s/usr/lib/x86_64-linux-gnu/$l || sudo cp "
        "/usr/lib/x86_64-linux-gnu/$l %s/usr/lib/x86_64-linux-gnu/; done"
        % (MNT, MNT),
        # K11 D2：aistreamd（L1 新编）+ 测试 conf
        "sudo cp %s/agent/ai/aistreamd/aistreamd %s/root/k11/aistreamd"
        % (REPO, MNT),
        "sudo cp /tmp/k11.conf %s/root/k11/k11.conf" % MNT,
        # K11 D1：新 occ（盘上工厂 occ 无内核行）→ /usr/local/bin 与
        # /root 双落（PATH 序防御；一次性 overlay，基盘不动）
        "sudo cp %s/agent/ai/occ/occ %s/usr/local/bin/occ" % (REPO, MNT),
        "sudo cp %s/agent/ai/occ/occ %s/root/occ" % (REPO, MNT),
        "sudo sync && sudo umount %s" % MNT,
        "sudo qemu-nbd -d %s" % NBD,
    ]
    for s in steps:
        r = sh(s)
        if r.returncode != 0:
            sh("sudo umount %s 2>/dev/null; sudo qemu-nbd -d %s 2>/dev/null"
               % (MNT, NBD))
            print("[k11] INJECT-FAIL: %s\n%s" % (s, r.stderr.strip()))
            sys.exit(1)
    print("[k11] inject ok (aikctl+py+aistreamd+occ+conf)")


def boot():
    """boot + TUI /status 截取 + bash 电池。回 (tui_txt, bash_txt)。"""
    cleanup_qemu()
    time.sleep(1)
    cmd = ("qemu-system-x86_64 -name k11 -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-kernel %s/arch/x86/boot/bzImage -append "
           "\"root=/dev/vda2 rw console=ttyS0 ai.skipgate=1 ai.enabled=1 "
           "kunit.enable=0 aichain.seed=%s\" -drive file=%s,if=virtio"
           % (SOCK, TREE, SEED, OVL))
    q = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(SOCK, os.path.join(EVD, "k11-serial.log"))
    tui = bash = None
    try:
        ser.wait(b"AIKernel", 300)
        # TUI 起来后敲 /status（D1 实机内核行）
        if ser.wait(b"\xe8\xbe\x93\xe5\x85\xa5\xe6\xb6\x88\xe6\x81\xaf", 300):
            mark = len(ser.buf)
            ser.send(b"/status\r")
            wait_after(ser, mark, b"kernel=", 30)
            time.sleep(3.5)
            tui = clean(ser.buf[mark:])
        got = False
        for _ in range(12):
            mark = len(ser.buf)
            ser.send(b"/shell\r")
            if wait_after(ser, mark, b"root@aikernel", 20):
                got = True
                break
            time.sleep(2)
        if got:
            time.sleep(1)
            mark = len(ser.buf)
            ser.sendline(
                "cd /root/k11; "
                # run3 实抓：rig 盘自带 aistreamd 常驻（pid=153）持
                # /run/aistreamd.lock——先让位给 AS_ONCE 实例
                "pkill aistreamd; rm -f /run/aistreamd.lock; "
                "/root/k3bench storm 300 tool 2>/dev/null | tail -1; "
                # aikd 角色回填 outcome：真身=/sys/kernel/ai/policy/outcome
                # （ai_policy_kobj 子目录；run2/3 实抓写父路径=O_CREAT 落
                # sysfs 目录 kernfs 拒建=EACCES 假象，CapEff 全满亦拒）
                "grep CapEff /proc/self/status; "
                "echo 1,1,0 > /sys/kernel/ai/policy/outcome 2>&1; "
                "echo BASHRC=$?; "
                "grep -o '^id=[0-9]*' /proc/ai/decisions | cut -d= -f2 | "
                "python3 -c \"import sys; "
                "[open('/sys/kernel/ai/policy/outcome','w')"
                ".write(l.strip()+',1,0') for l in sys.stdin]\"; "
                "echo OBDONE$((1+1)); "
                "AS_ONCE=1 AS_DUMP=1 ./aistreamd --conf /root/k11/k11.conf "
                "2>/root/k11/dump.txt; echo ASDONE$((1+1)); "
                "wc -l < /root/k11/dump.txt; cat /root/k11/dump.txt; "
                "grep -E 'kernel[_]ver|abi[_]ver|config[_]hash' "
                "/proc/ai/status; "
                "python3 /root/k11/aikctl audit export -o /root/k11/a.jsonl "
                ">/dev/null 2>&1; "
                "python3 /root/k11/aikctl audit verify /root/k11/a.jsonl "
                "2>&1 | tail -3; "
                "cat /proc/ai/decisions; "
                "cat /proc/ai/audit; "
                "find /root/k11/pq -name '*.parquet' 2>/dev/null | "
                "while read f; do echo PQBEGIN $f; base64 -w0 $f; echo; "
                "echo PQEND; done; "
                "echo K11ALL$((1+1))")
            wait_after(ser, mark, b"K11ALL2", 600)
            bash = clean(ser.buf[mark:])
        ser.sendline("poweroff -f")
        ser.wait(b"Power down", 240)
    finally:
        ser.drain_close()
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()
    return tui, bash


def chain_ids(text, kind):
    """audit 文本抽指定 kind 节点的 decision_id（d= 前 8B LE）。"""
    ids = set()
    for m in re.finditer(r"k=(\d+) pid=\d+ f=\d+ prev=[0-9a-f]+ "
                         r"h=[0-9a-f]+ d=([0-9a-f]+)", text):
        if int(m.group(1)) != kind:
            continue
        hx = m.group(2)[:16]
        if len(hx) < 16:
            continue
        ids.add(int.from_bytes(bytes.fromhex(hx), "little"))
    return ids


def pair_ok(audit_text):
    new = chain_ids(audit_text, 1)
    out = chain_ids(audit_text, 2)
    return new and new == out, len(new), len(out)


def main():
    os.makedirs(EVD, exist_ok=True)
    inject()
    tui, bash = boot()
    open(os.path.join(EVD, "tui-status.txt"), "w").write(tui or "")
    open(os.path.join(EVD, "bash-battery.txt"), "w").write(bash or "")

    m = re.search(r"STORM_RESULT sent=(\d+).*?ok=(\d+)", bash or "")
    phase("A1 storm 300 全成", m is not None
          and int(m.group(1)) == 300 and int(m.group(2)) == 300)

    # TUI 渲染按面板宽折行（run1/2 实抓：长 notice 后段 chain/agents 段
    # 常被截/另帧）——核心三段存在级断言；链/agents 数值由 bash 面承担
    phase("D1 occ TUI 内核行（核心三段）", tui is not None
          and "kernel=" in tui and "abi=" in tui and "cfg=" in tui)

    ok, n1, n2 = pair_ok(bash or "")
    phase("A2 链 NEW/OUTCOME 配对", ok, "（k1=%d k2=%d）" % (n1, n2))

    verify = re.search(r"(verify[^\n]*|PASS[^\n]*|ok=[^\n]*)",
                       bash or "")
    dump_ids = [int(x) for x in re.findall(r"ASDUMP id=(\d+)", bash or "")]
    ring_ids = set(int(x) for x in re.findall(r"^id=(\d+)", bash or "",
                                              re.M))
    phase("A3 dump⊆内核 ring", len(dump_ids) > 0
          and set(dump_ids) <= ring_ids,
          "（dump=%d ring可见=%d）" % (len(dump_ids), len(ring_ids)))

    pqs = re.findall(r"PQBEGIN (\S+)\n([A-Za-z0-9+/=\n]+?)\nPQEND",
                     bash or "")
    pq_n = 0
    for i, (_f, b64) in enumerate(pqs):
        import base64
        data = base64.b64decode("".join(b64.split()))
        pq_n += 1
        open(os.path.join(EVD, "pq-%d.parquet" % i), "wb").write(data)
    phase("A4 parquet 落盘导出", pq_n > 0, "（%d 块）" % pq_n)

    phase("A5 三件套一致（bash 精确）", bash is not None
          and "config_hash: 6a36fe4a68743a2f" in bash
          and "kernel_ver: 6.18.39" in bash
          and "abi_ver: 1" in bash
          and "OBDONE2" in bash)

    # ⑥ 红路自证：按 id 的 LE hex 前缀精确抽掉其全部 k=2 行 → 配对必红
    outs = sorted(chain_ids(bash or "", 2))
    if outs:
        # d= 为小端字节序（run5 实抓：format 大端串匹配不中=抽行落空）
        vh = outs[0].to_bytes(8, "little").hex()
        tampered = "\n".join(l for l in (bash or "").splitlines()
                             if not (" k=2 " in l and ("d=" + vh) in l))
        ok2, _a, _b = pair_ok(tampered)
        phase("A6 断链即红（抽 k=2 必红）", not ok2,
              "（victim id=%d 抽除后配对=%s）" % (outs[0], ok2))
    else:
        phase("A6 断链即红（抽 k=2 必红）", False, "（无 k=2 行可抽）")

    n_ok = sum(1 for _n, ok, _t in results if ok)
    print("GOLDEN_SUMMARY ok=%d fail=%d" % (n_ok,
                                            len(results) - n_ok),
          flush=True)
    return 0 if n_ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
