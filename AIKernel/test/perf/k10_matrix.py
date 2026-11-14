#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""k10_matrix.py — K10.4 测试矩阵跑表器（K10 末片；KERNEL-K10A-DESIGN §K10.4）。

相位：
  P0 静态四门（k0_truth/config_check/integrity/aikctl selftest）+计时
  P1 KUnit 轮（strong bzImage；not-ok=0）
  P2 三配置矩阵（strong=现役/base=k104_base.frag/off=k104_off.frag）：
     翻转后自证（base：master 在+SECURITY 不在+族<全量；off：master
     不在+族=0）再构建；各 boot+断言（strong：三件套在=指纹等值；
     base：三件套在+audit 无+指纹变；off：/proc/ai 整体无）；结束
     恢复 strong 配置与 bzImage 并对出厂 profile 抽取复位校验
  P3 自研负载点压（strong boot + k3bench storm 500）
  P4 可复现：strong 同源三建 sha256 比对（缺省非确定序=如实登记）
输出 MATRIX_SUMMARY（对 CI<30min 预算报时；flake 需多轮采样=登记）。

首跑（run1，ok=8 fail=7）验尸教训，本版四堵：
  ①frag 参数 [2:] 解析把注释词漏进 scripts/config（bad command rc=1），
    且 -SYM 短写本树 scripts/config 不收（须 --disable SYM）→翻转从未
    生效、四次 boot 全 strong——frag 改纯 --disable 行+翻转后自证，
    不过即 FAIL 不许编；
  ②串口 grep 输出带 ANSI 色码（config_hash 与冒号间插 \x1b[m\x1b[K）→
    断言前统一剥色码；
  ③rig 盘 getty root 自动登录后拉 aikernel-shell TUI 占串口（裸输入
    全被当文本吃进输入框）——/shell=TUI 内建落 bash 命令（run1 实证），
    握手恒发 /shell\r 锚 root@aikernel；off 内核无 AIKernel 横幅→
    不候横幅直候提示符；
  ④config 复位断言 ^CONFIG_AIKERNEL=y 只中总开关→改对
    aikernel_factory.config 族抽取比对。
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
EVD = os.path.expanduser("~/k10-evidence/matrix")
DISK = os.path.expanduser("~/k17q/disk.qcow2")
FACT = REPO + "/configs/aikernel_factory.config"
STRONG_HASH = "6a36fe4a68743a2f"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")

results = []


def phase(name, ok, note=""):
    results.append((name, ok, note))
    print("[matrix] %-28s %s %s" % (name, "PASS" if ok else "FAIL", note),
          flush=True)


def sh(cmd, timeout=3600):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       timeout=timeout)
    return r


def family_y(path):
    r = sh("grep -c '^CONFIG_AIKERNEL.*=y$' %s" % path)
    try:
        return int(r.stdout.strip())
    except ValueError:
        return -1


def frag_args(frag):
    toks = []
    for line in open(frag, encoding="utf-8"):
        if line.lstrip().startswith("#"):
            continue
        toks.extend(line.split())
    return toks


def build(tag, frag=None, expect="strong"):
    """从 strong 快照起建（frag 叠加其上）；翻转后自证再编。
    返回 (ok, 秒, 说明)。"""
    t0 = time.time()
    note = ""
    sh("cp %s/.config.k104strong %s/.config" % (TREE, TREE))
    if frag:
        args = " ".join(frag_args(frag))
        r = sh("%s/scripts/config --file %s/.config %s" % (TREE, TREE, args))
        if r.returncode != 0:
            return False, time.time() - t0, \
                "scripts/config rc=%d 翻转失败" % r.returncode
    sh("cd %s && yes '' | LC_ALL=C make olddefconfig > /dev/null 2>&1"
       % TREE)
    fam = family_y(TREE + "/.config")
    master = sh("grep -c '^CONFIG_AIKERNEL=y$' %s/.config" % TREE)
    master = master.stdout.strip() == "1"
    sec_off = sh("grep -c '^# CONFIG_AIKERNEL_SECURITY is not set$' "
                 "%s/.config" % TREE).stdout.strip() != "0"
    if expect == "strong":
        ok = master and fam == family_y(FACT)
    elif expect == "base":
        ok = master and sec_off and 0 < fam < family_y(FACT)
        note = "（翻后族=%d）" % fam
    else:  # off
        ok = (not master) and fam == 0
        note = "（翻后族=%d）" % fam
    if not ok:
        return False, time.time() - t0, \
            "翻转自证不过 master=%s fam=%d%s" % (master, fam, note)
    sh("rm -f %s/vmlinux.o %s/vmlinux.unstripped" % (TREE, TREE))
    r = sh("cd %s && LC_ALL=C flock /tmp/k8build.lock make -j$(nproc) "
           "bzImage > /tmp/k104_%s_build.log 2>&1" % (TREE, tag))
    ok = r.returncode == 0 and os.path.exists(TREE +
                                               "/arch/x86/boot/bzImage")
    return ok, time.time() - t0, note


def boot_probe(tag, wait_banner=True):
    """boot 当前树 bzImage，回剥色码后的 shell 段文本（None=boot 失败）。
    rig 盘 getty 自动登录后 aikernel-shell TUI 占串口：发 /shell\r
    （TUI 内建落 bash 命令）候 root@aikernel 提示符；off 内核无
    AIKernel 横幅→wait_banner=False。"""
    sock = WRK + "/k104-%s.sock" % tag
    ovl = WRK + "/k104-%s.qcow2" % tag
    cleanup_qemu()
    time.sleep(1.0)
    for f in (sock, ovl):
        if os.path.exists(f):
            os.unlink(f)
    sh("qemu-img create -f qcow2 -F qcow2 -b %s %s" % (DISK, ovl))
    cmd = ("qemu-system-x86_64 -name k104%s -accel tcg -m 2048 -smp 2 "
           "-display none -nic none -no-reboot "
           "-serial unix:%s,server,nowait "
           "-kernel %s/arch/x86/boot/bzImage -append "
           "\"root=/dev/vda2 rw console=ttyS0 ai.skipgate=1 ai.enabled=1 "
           "kunit.enable=0\" -drive file=%s,if=virtio"
           % (tag, sock, TREE, ovl))
    q = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(2)
    ser = Serial(sock, os.path.join(EVD, "%s-serial.log" % tag))
    out = None
    try:
        if wait_banner:
            ser.wait(b"AIKernel", 240)
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
            # 回显防污染：grep 模式用 [_] 括号戏法——echo 行不含
            # kernel_ver 字面串（run4 off 段实抓：断言被命令回显击穿）
            ser.sendline("ls /proc/ai/audit 2>&1 | head -1; "
                         "grep -E 'kernel[_]ver|abi[_]ver|config[_]hash' "
                         "/proc/ai/status 2>/dev/null; "
                         "/root/k3bench storm 500 tool 2>/dev/null "
                         "| tail -1; echo MDONE$((1+1))")
            wait_after(ser, mark, b"MDONE2", 180)
            raw = ser.buf[mark:]
            out = ANSI.sub(b"", raw).decode("utf-8", "replace")
        ser.sendline("poweroff -f")
        ser.wait(b"Power down", 240)
    finally:
        ser.drain_close()
        cleanup_qemu()
        try:
            q.wait(15)
        except Exception:
            q.kill()
    return out


def hash_of(path):
    return sh("sha256sum %s" % path).stdout.split()[0]


def main():
    os.makedirs(EVD, exist_ok=True)
    sh("cp %s/.config %s/.config.k104strong" % (TREE, TREE))
    t_all = time.time()

    # P0 静态四门
    r = sh("bash %s/k0/k0_truth_check.sh %s %s/k0/KERNEL-K0-TRUTH-TABLE.md "
           "%s/AIKernel/ARCHITECTURE.md" % (os.path.expanduser("~"), REPO,
                                            os.path.expanduser("~"), REPO))
    phase("P0 k0_truth", "PASS" in r.stdout)
    r = sh("bash %s/AIKernel/scripts/k10_config_check.sh %s %s/.config"
           % (REPO, REPO, TREE))
    phase("P0 config_check", "K10-CONFIG: PASS" in r.stdout)
    r = sh("python3 %s/AIKernel/scripts/k10_patch_series.py --check-only"
           % REPO)
    phase("P0 integrity",
          re.search(r"\d+/\d+ 一致", r.stdout) is not None
          and "漂移" not in r.stdout)
    r = sh("python3 %s/agent/ai/aikctl/aikctl selftest" % REPO)
    phase("P0 aikctl selftest",
          re.search(r"ok=58( |$)", r.stdout) is not None)

    # P1 KUnit（strong）
    t0 = time.time()
    sh("cd ~/k17q && timeout 480 python3 k4_kunit_boot.py", timeout=600)
    log = open(os.path.expanduser("~/k17q/k4-kunit-serial.log"),
               "rb").read()
    phase("P1 KUnit not-ok=0", b"\nnot ok" not in log,
          "(%.0fs)" % (time.time() - t0))

    # P2 三配置（每建先翻转自证，不过即 FAIL 不 boot）
    ok, dt, note = build("strong0")
    sh("cp %s/arch/x86/boot/bzImage %s/bz0" % (TREE, EVD))
    phase("P2 build strong", ok, "(%.0fs)%s" % (dt, note))
    out = boot_probe("strong")
    m = re.search(r"config_hash: ([0-9a-f]{16})", out or "")
    phase("P2 strong boot+三件套",
          out is not None and "MDONE2" in out
          and "kernel_ver: 6.18.39" in out
          and "abi_ver: 1" in out
          and "config_hash: %s" % STRONG_HASH in out,
          "（实测 %s）" % (m.group(1) if m else "无"))
    ok, dt, note = build("base", REPO + "/configs/k104_base.frag", "base")
    phase("P2 build base", ok, "(%.0fs)%s" % (dt, note))
    out = boot_probe("base") if ok else None
    m = re.search(r"config_hash: ([0-9a-f]{16})", out or "")
    phase("P2 base=三件套在+audit 无+指纹变",
          out is not None and "MDONE2" in out
          and "kernel_ver" in out
          and ("没有那个文件" in out or "No such file" in out)
          and ("config_hash: %s" % STRONG_HASH) not in out,
          "（实测 %s）" % (m.group(1) if m else "无"))
    ok, dt, note = build("off", REPO + "/configs/k104_off.frag", "off")
    phase("P2 build off", ok, "(%.0fs)%s" % (dt, note))
    out = boot_probe("off", wait_banner=False) if ok else None
    phase("P2 off=/proc/ai 整体无", out is not None
          and "MDONE2" in out
          and ("没有那个文件" in out or "No such file" in out)
          and "kernel_ver" not in out)

    # P3 负载点压（strong 复建后 boot_probe 电池内含 storm 500）
    ok, dt, note = build("strong1")
    sh("cp %s/arch/x86/boot/bzImage %s/bzA" % (TREE, EVD))
    phase("P3 build strong 复位", ok, "(%.0fs)%s" % (dt, note))
    out = boot_probe("strong2")
    m = re.search(r"STORM_RESULT sent=(\d+) eagain=(\d+)", out or "")
    phase("P3 storm 500（自研负载）", m is not None
          and int(m.group(1)) >= 400)

    # P4 可复现（同源三建：strong0/strong1 已存 + 再建一枚）
    ok, dt, note = build("strong2")
    sh("cp %s/arch/x86/boot/bzImage %s/bzB" % (TREE, EVD))
    ha, hb, h0 = hash_of(EVD + "/bzA"), hash_of(EVD + "/bzB"), \
        hash_of(EVD + "/bz0")
    phase("P4 三建字节一致（可复现）", ha == hb == h0,
          "(%s/%s/%s——内核构建缺省含非确定序，如实登记)"
          % (h0[:10], ha[:10], hb[:10]))

    # 收尾复位校验：树 config 族与出厂 profile 抽取逐行一致
    # （两侧排序后比对——factory 字母序 vs .config Kconfig 序，run3 实抓）
    sh("grep '^CONFIG_AIKERNEL.*=y$' %s/.config | sort > /tmp/k104_reset.txt"
       % TREE)
    sh("grep '^CONFIG_AIKERNEL.*=y$' %s | sort > /tmp/k104_fact.txt" % FACT)
    r = sh("diff -q /tmp/k104_reset.txt /tmp/k104_fact.txt")
    phase("P2 config 复位 strong", r.returncode == 0,
          "（族 %d 对齐 factory）" % family_y(TREE + "/.config"))

    n_ok = sum(1 for _n, ok, _t in results if ok)
    print("MATRIX_SUMMARY ok=%d fail=%d total=%.0fs（CI 预算 1800s）"
          % (n_ok, len(results) - n_ok, time.time() - t_all), flush=True)
    return 0 if n_ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
