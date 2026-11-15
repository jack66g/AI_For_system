#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C3 台架（COMPAT-C3-DESIGN §4；run_all 第 64 门）。

default（非 root，进门）四账户：
  ①层名（§0 唯一口径）：四 code（ARCH_MISMATCH/ABI_MISMATCH/
    MISSING_ABI_LOADER/LIBC_VERSION_TOO_NEW）样本 reasons[].layer 必须恰
    等于 "L3" 且 detail 不得残留 "L1"。期望按设计册冻结、与 Lane-1
    （compat_tools.c 面）合同联调：其未合入的工树里本账户对真 probe 如实
    红——禁止调期望凑绿或标「合入后转绿」；施工自检期以假 probe 替身
    （/tmp 一次性脚本，不入仓）只验台架自身逻辑，真断言全留整合期主会话
    亲跑（见施工报告）。
  ②L3 缺席态机判：AIK_QEMU_USER_AARCH64=/nonexistent 覆盖 → probe 必
    runnable=0 + ARCH_MISMATCH fatal + adaptable=0 + detail 含 qemu 字样
    （§1.2）；另断言 plan 对 probe JSON 逐字段如实透传（row.probe 与直连
    probe 恰等；Lane-1 新字段 emulators/adapter.layers.L3 按合同读，缺席
    不补造——在场则 verdict 与 adapter 形态随 probe 可适配性走）。
  ③L4 五类 probe 级判定表（aikctl compat hw；真机只读+--fixture 静态
    双路）：缺固件=合成引用不存在固件名→needs(原因含固件)；未知 PCI=
    静态 fixture 输入（edu 形态 1234:11e8，非真挂）——本台架态(无
    IOMMU/VFIO)→needs(原因含 IOMMU)、IOMMU+VFIO 在场 fixture→unknown
    （只读不试绑）；USB=真虚拟节点（root hub）→清单在场+verdict ok；
    显卡 ISA=登记不可测→unknown+原因含不可测；怪 arch=缺席态行（同②）。
  ④L5 门机制全链：propose→list→错短语拒(fail_count=1 入账)→对短语
    批准→install --dry-run（恒不执行，只打印 insmod）→未批准/未知 nonce
    install 拒绝负例→账本 propose/approve/install/refused 四类事件齐+
    xxh64 行链校验(LEDGER_OK)+篡改检出(LEDGER_BREAK)。AIKMODULE_DIR/
    AIKERNEL_CONFIRM_DIR 指临时目录（非 root 零全局副作用；真路径
    /var/lib/aikernel/module 与 /run/aikernel/confirm 仅 --live root 碰）。
--live（root，主会话亲跑，不进 run_all）三面：
  L3 在场态真 aarch64 样本全链（qemu-aarch64-static 真跑出 marker +
    probe adaptable=1+layer=L3+emulators.aarch64 非空 + plan layers.L3
    .emulator 咬合 + apply+verify+rollback 六条复用 c2 rollback6）；
  hw 真机采集（IOMMU 空组=0 诚实裁定断言：caveats 常驻+无驱动绑定设备
    needs 裁定）；L5 真目录 dry-run 全链（含负例；真账本追加式留痕，
    note=c3-bench-live 可溯源）。
样本：手写 aarch64 静态 ELF（write/exit 两条 syscall，170B；字节表照
  /tmp/gen_aarch64_sample.py 冻结抄录，逐指令注释）+ c1 合成器复用
  （synth_elf64/synth_elf32_i386；c1 有 __main__ 门 import 无副作用）；
  c2 复用 rollback6/read_plan_record/run_cmd/resolve_aikctl/write_file。
probe 次序沿 c1/c2：--probe > $AIK_COMPAT_PROBE > PATH；aikctl：--aikctl
  > $AIKCTL > probe 兄弟 aikctl/aikctl > PATH。
前置自检（缺=如实 FAIL 不跳过）：default=aik-compat+aikctl 可用；--live
  另加 euid=0 与 qemu-aarch64-static（缺席→L3 在场态账户如实 FAIL 不
  跳过；default 不需要 qemu——缺席态本就是 env 覆盖出的确定态）。
输出：default 末行 `C3_SAMPLES ok=N fail=M`；--live 另有 C3_L3_CHAIN/
  C3_HW/C3_L5 行随后 C3_SAMPLES。退出码：零 fail（live 另需三面全绿）
  →0，否则 1。禁止调期望凑绿：期望按设计册冻结口径写死。
"""
import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c1_compat_samples import (  # noqa: E402
    synth_elf64, synth_elf32_i386, find_host_loader, probe_once, fatal_codes,
    parse_probe_output, write_file)
from c2_compat_samples import (  # noqa: E402
    resolve_aikctl, rollback6, read_plan_record)


def run_cmd(cmd, timeout):
    """本地版 run_cmd——**勿从 c2 import**：c2 为 L0/L2 判定确定性在
    其 run_cmd 里钉了 AIK_QEMU_USER_*=缺席（C3 整合修，2026-11-15），
    会把 C3 的 L3 在场态账户（B2 透传/live 链）整体翻成缺席态。C3
    自身按账户各自控环境（probe_absence 显式钉缺席；在场态用宿主
    真实 qemu）。"""
    cp = subprocess.run(cmd, capture_output=True, timeout=timeout)
    return cp.returncode, cp.stdout.decode('utf-8', errors='replace')

PROBE_TIMEOUT = 10
PLAN_TIMEOUT = 180
MODULE_TIMEOUT = 60
HW_TIMEOUT = 120
LIVE_APPLY_TIMEOUT = 620
NONCE_RE = re.compile(r'^[0-9a-f]{32}$')
QEMU_AARCH64 = 'qemu-aarch64-static'
MARKER = b'c3-aarch64-ok\n'

# ------------------------------------------------ 手写 aarch64 静态 ELF ----
# 字节表照 /tmp/gen_aarch64_sample.py 冻结抄录（设计册 §1.6；无交叉 gcc，
# 确定性零下载）。布局：ehdr(64B)+phdr(56B)+9 指令(36B)+msg(14B)=170B，
# 单 PT_LOAD @ vaddr 0x400000，入口 0x400078。
AARCH64_CODE = struct.pack(
    '<9I',
    0xD2800020,  # mov  x0, #1              ; fd=stdout
    0xD2A00801,  # movz x1, #0x40, lsl #16  ; x1=0x400000（映基）
    0x91027021,  # add  x1, x1, #0x9C       ; x1=0x40009C=msg 地址
    0xD28001C2,  # mov  x2, #14             ; len=14
    0xD2800808,  # mov  x8, #64             ; __NR_write
    0xD4000001,  # svc  #0                  ; write(1, msg, 14)
    0xD2800000,  # mov  x0, #0              ; exit code=0
    0xD2800BA8,  # mov  x8, #93             ; __NR_exit
    0xD4000001,  # svc  #0                  ; exit(0)
)
MSG = b'c3-aarch64-ok\n'


def aarch64_sample():
    """→ bytes：结构合法 aarch64 静态 ELF（qemu-user 可跑出 marker）。"""
    assert len(AARCH64_CODE) == 36 and len(MSG) == 14
    base = 0x400000
    total = 0x78 + 36 + 14
    ehdr = struct.pack(
        '<16sHHIQQQIHHHHHH',
        b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8,   # ELF64 LE SYSV
        2,            # e_type = ET_EXEC
        183,          # e_machine = EM_AARCH64
        1,            # e_version
        base + 0x78,  # e_entry
        64,           # e_phoff
        0,            # e_shoff
        0,            # e_flags
        64, 56, 1,    # e_ehsize/phentsize/phnum
        0, 0, 0)      # shentsize/shnum/shstrndx
    phdr = struct.pack(
        '<IIQQQQQQ',
        1,            # PT_LOAD
        5,            # R+X
        0,            # p_offset
        base, base,   # p_vaddr/p_paddr
        total, total, # p_filesz/p_memsz
        0x1000)       # p_align
    blob = ehdr + phdr + AARCH64_CODE + MSG
    assert len(ehdr) == 64 and len(phdr) == 56 and len(blob) == total == 170
    return blob


# ------------------------------------------------------------ 账户①层名 ----
# 四 code 样本（§0 更名面全覆盖；期望冻结：layer=="L3" 且 detail 无 "L1"）。
L3_CODE_SAMPLES = [
    ('A1', 'aarch64', lambda: synth_elf64(machine=183),
     ('ARCH_MISMATCH',)),
    ('A2', 'arm', lambda: synth_elf64(machine=40), ('ARCH_MISMATCH',)),
    ('A3', 'i386', synth_elf32_i386, ('ABI_MISMATCH', 'ARCH_MISMATCH')),
    ('A4', 'osabi9', lambda: synth_elf64(machine=62, osabi=9),
     ('ABI_MISMATCH',)),
    ('A5', 'glibc-new',
     lambda: synth_elf64(interp=find_host_loader(), needed=('libc.so.6',),
                         verneed_lib='libc.so.6',
                         verneed_versions=('GLIBC_2.9999',)),
     ('LIBC_VERSION_TOO_NEW',)),
    ('A6', 'no-loader',
     lambda: synth_elf64(interp='/lib/ld-c3missing.so.2',
                         needed=('libc.so.6',)),
     ('MISSING_ABI_LOADER',)),
]


def account_layers(td, probe):
    """账户①：四 code layer=L3 全样本 + detail 零 L1 残留。→ (ok, fail)。"""
    ok = fail = 0
    for sid, name, mk, codes in L3_CODE_SAMPLES:
        why = []
        try:
            p = os.path.join(td, 'lay-' + sid)
            write_file(p, mk(), 0o755)
            pj = probe_once(probe, p)
        except Exception as e:                       # noqa: BLE001 台架如实记账
            why.append('%s: %s' % (type(e).__name__, e))
        else:
            hit = {r.get('code'): r for r in (pj.get('reasons') or [])
                   if isinstance(r, dict)}
            for c in codes:
                r = hit.get(c)
                if r is None:
                    why.append('缺 code %s' % c)
                    continue
                if r.get('layer') != 'L3':
                    why.append('%s.layer=%r 期望 "L3"' % (c, r.get('layer')))
                # 整合修：残留检查只针对旧口径措辞（「L1 翻译」/layer=L1），
                # 不禁裸 "L1"——统一分层后 L1=LD_PRELOAD 同源 shim 是合法
                # 未来层引用（LIBC_VERSION_TOO_NEW 的人工路径文案正指向它，
                # COMPAT-C3-DESIGN §0 唯一口径）。
                d = r.get('detail') or ''
                if 'L1 翻译' in d or 'layer=L1' in d:
                    why.append('%s.detail 残留旧口径: %.80r' % (c, d))
        if why:
            fail += 1
            print('FAIL %s %-10s %s' % (sid, name, ' | '.join(why)[:240]))
        else:
            ok += 1
            print('ok   %s %-10s layer=L3（codes={%s}）无旧口径残留'
                  % (sid, name, ','.join(codes)))
    return ok, fail


# ------------------------------------------------------ 账户② L3 双态 ----
def probe_absence(probe, target):
    """AIK_QEMU_USER_AARCH64=/nonexistent 覆盖 → probe JSON（缺席态）。"""
    env = dict(os.environ, AIK_QEMU_USER_AARCH64='/nonexistent')
    cp = subprocess.run([probe, 'probe', target], capture_output=True,
                        timeout=PROBE_TIMEOUT, env=env)
    return parse_probe_output(cp.stdout)


def absence_checks(pj):
    """缺席态三判据 → [坏因]（§1.2：fatal+adaptable=0+detail 含 qemu）。"""
    bad = []
    if pj.get('runnable'):
        bad.append('竟 runnable=1')
    rs = [r for r in (pj.get('reasons') or []) if isinstance(r, dict)
          and r.get('code') == 'ARCH_MISMATCH']
    if not rs:
        bad.append('缺 ARCH_MISMATCH reason')
    for r in rs:
        if not r.get('fatal'):
            bad.append('ARCH_MISMATCH 竟非 fatal')
        if r.get('adaptable'):
            bad.append('缺席态竟 adaptable=1')
        if 'qemu' not in (r.get('detail') or '').lower():
            bad.append('detail 缺 qemu 字样: %.80r' % (r.get('detail'),))
    return bad


def account_absence(td, probe, aikctl, root):
    """账户②：缺席态机判 + plan 透传诚实。→ (ok, fail)。"""
    ok = fail = 0
    p = os.path.join(td, 'abs-aarch64')
    write_file(p, aarch64_sample(), 0o755)
    # ②a 缺席态机判
    why = []
    try:
        why += absence_checks(probe_absence(probe, p))
    except Exception as e:                           # noqa: BLE001
        why.append('%s: %s' % (type(e).__name__, e))
    if why:
        fail += 1
        print('FAIL B1 %-10s %s' % ('absence', ' | '.join(why)[:240]))
    else:
        ok += 1
        print('ok   B1 %-10s AIK_QEMU_USER_AARCH64=/nonexistent → fatal+'
              'adaptable=0+detail 含 qemu' % 'absence')
    # ②b plan 透传诚实（row.probe 与直连 probe 恰等；可适配性与 verdict
    # 咬合；缺席字段不补造）
    why = []
    try:
        pj2 = probe_once(probe, p)
        jsonl = os.path.join(root, 'plan-c3-abs.jsonl')
        rc, _ = run_cmd([aikctl, 'compat', 'plan', '--probe', probe,
                         '--name', 'c3-abs', '--jsonl', jsonl, p],
                        PLAN_TIMEOUT)
        rec, _summ = read_plan_record(jsonl)
        if rc == 0 and not (pj2.get('runnable') or
                            any(isinstance(r, dict) and r.get('adaptable')
                                for r in (pj2.get('reasons') or []))):
            why.append('不可适配目标 plan 竟 rc=0（静默成功）')
        if rec.get('probe') != pj2:
            why.append('row.probe 与直连 probe JSON 不恰等（透传失真：%s）'
                       % sorted(set(rec.get('probe', {})) ^ set(pj2)))
        adaptable_any = any(isinstance(r, dict) and r.get('adaptable')
                            for r in (pj2.get('reasons') or []))
        if adaptable_any:
            # row.adapter = generate 结果对象（{"ok":true,"adapter":{内层}}，
            # C2 冻结口径）；layers.L3 在内层
            inner = ((rec.get('adapter') or {}).get('adapter')) or {}
            if rec.get('verdict') != 'planned' or not inner:
                why.append('probe 可适配但 verdict=%r adapter=%r'
                           % (rec.get('verdict'),
                              'null' if rec.get('adapter') is None else 'ok'))
            else:
                layers = inner.get('layers') or {}
                if 'L3' not in layers:
                    why.append('adapter.layers 缺 L3（可适配 aarch64 合同）')
                emu = (pj2.get('emulators') or {}).get('aarch64')
                if emu and (layers.get('L3') or {}).get('emulator') != emu:
                    why.append('layers.L3.emulator=%r 不咬合 emulators'
                               '.aarch64=%r'
                               % ((layers.get('L3') or {}).get('emulator'),
                                  emu))
        else:
            if rec.get('verdict') != 'not_adaptable':
                why.append('probe 不可适配但 verdict=%r（应 not_adaptable）'
                           % rec.get('verdict'))
            if rec.get('adapter') is not None:
                why.append('不可适配目标竟有 adapter（零静默成功破防）')
    except Exception as e:                           # noqa: BLE001
        why.append('%s: %s' % (type(e).__name__, e))
    if why:
        fail += 1
        print('FAIL B2 %-10s %s' % ('passthru', ' | '.join(why)[:240]))
    else:
        ok += 1
        print('ok   B2 %-10s plan row.probe 恰等透传；verdict/adapter 随'
              '可适配性咬合' % 'passthru')
    return ok, fail


# ------------------------------------------------- 账户③ L4 五类判定表 ----
EDU_PCI = {'bdf': '0000:00:09.0', 'vendor': '0x1234', 'device': '0x11e8',
           'driver': None}       # qemu edu 形态（未知 PCI ID，静态 fixture）


def hw_run(aikctl, fixture, out_path):
    """aikctl compat hw [--fixture] --jsonl → (rc, meta, rows, summary)。
    末行 C3_HW 为文本汇总（非 JSON），解析按行容错。"""
    cmd = [aikctl, 'compat', 'hw', '--jsonl', out_path]
    if fixture is not None:
        cmd += ['--fixture', fixture]
    rc, _ = run_cmd(cmd, HW_TIMEOUT)
    with open(out_path, 'r', errors='replace') as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    meta, rows, summary = None, [], ''
    for ln in lines:
        try:
            obj = json.loads(ln)
        except ValueError:
            summary = ln
            continue
        if obj.get('meta'):
            meta = obj
        elif obj.get('kind'):
            rows.append(obj)
    return rc, meta, rows, summary


def account_hw(td, aikctl, probe):
    """账户③：L4 五类 probe 级判定表（fixture+真机只读双路）+怪 arch 行。
    → (ok, fail)。"""
    ok = fail = 0

    def record(sid, label, bad):
        nonlocal ok, fail
        if bad:
            fail += 1
            print('FAIL %s %-12s %s' % (sid, label, ' | '.join(bad)[:240]))
        else:
            ok += 1
            print('ok   %s %-12s' % (sid, label))

    # T1+T2+T4：fixture A（edu 未知 PCI + 绑定态 PCI + 不存在固件名 +
    # 合成 DRM 节点；usb 真机）——本台架态（IOMMU=0/VFIO=off）
    fixA = {
        'pci': [dict(EDU_PCI),
                {'bdf': '0000:00:04.0', 'vendor': '0x15ad',
                 'device': '0x07b0', 'driver': 'vmxnet3'}],
        'iommu_groups': 0, 'vfio': False, 'uio': False,
        'dri': ['card0', 'renderD128'],
        'firmware_needed': ['c3-nonexistent-firmware.bin'],
    }
    fixA_path = os.path.join(td, 'hw-fixA.json')
    write_file(fixA_path, json.dumps(fixA).encode(), 0o644)
    try:
        rc, meta, rows, summary = hw_run(aikctl, fixA_path,
                                         os.path.join(td, 'hwA.jsonl'))
    except Exception as e:                           # noqa: BLE001
        record('C1', 'hw-fixtureA', ['%s: %s' % (type(e).__name__, e)])
        return ok, fail + 4
    by = {}
    for r in rows:
        by.setdefault(r['kind'], []).append(r)
    bad = []
    if rc != 0:
        bad.append('hw rc=%d' % rc)
    if not meta or meta.get('iommu_groups') != 0 or not meta.get('caveats'):
        bad.append('meta 坏/缺 caveats: %r' % (meta,))
    edu = [r for r in by.get('pci', []) if r.get('bdf') == EDU_PCI['bdf']]
    if not edu or edu[0].get('verdict') != 'needs_l4_unsupported_here' \
            or 'IOMMU' not in (edu[0].get('reason') or ''):
        bad.append('未知 PCI(fixture/edu) 判定坏: %r' % (edu[:1],))
    bound = [r for r in by.get('pci', []) if r.get('driver')]
    if not bound or any(r.get('verdict') != 'ok' for r in bound):
        bad.append('绑定态 PCI 判定坏: %r' % (bound[:1],))
    fw = [r for r in by.get('firmware_ref', [])
          if r.get('name') == 'c3-nonexistent-firmware.bin']
    if not fw or fw[0].get('verdict') != 'needs_l4_unsupported_here' \
            or fw[0].get('present') is not False \
            or '固件' not in (fw[0].get('reason') or ''):
        bad.append('缺固件判定坏: %r' % (fw[:1],))
    record('C1', 'T1缺固件+T2未知PCI(台架态)', bad)

    usb = by.get('usb') or []
    usb_ok = [r for r in usb if r.get('verdict') == 'ok']
    record('C2', 'T3 USB真虚拟节点', (['真机 usb 清单空/全非 ok: %r'
                                      % [r.get('name') for r in usb[:3]]]
                                     if not usb_ok else []))
    dri = by.get('dri') or []
    record('C3', 'T4 显卡ISA登记不可测',
           ([] if (dri and dri[0].get('verdict') == 'unknown'
                   and '不可测' in (dri[0].get('reason') or ''))
            else ['dri 判定坏: %r' % (dri[:1],)]))

    # T2b：fixture B（IOMMU+VFIO 在场）→ 未知 PCI 只读不试绑=unknown
    fixB = {'pci': [dict(EDU_PCI)], 'iommu_groups': 8, 'vfio': True,
            'uio': True}
    fixB_path = os.path.join(td, 'hw-fixB.json')
    write_file(fixB_path, json.dumps(fixB).encode(), 0o644)
    bad = []
    try:
        rc, meta, rows, summary = hw_run(aikctl, fixB_path,
                                         os.path.join(td, 'hwB.jsonl'))
        edu = [r for r in rows if r.get('kind') == 'pci']
        if rc != 0:
            bad.append('hw rc=%d' % rc)
        if not edu or edu[0].get('verdict') != 'unknown':
            bad.append('IOMMU+VFIO 在场 fixture 未知 PCI 应 unknown: %r'
                       % (edu[:1],))
    except Exception as e:                           # noqa: BLE001
        bad.append('%s: %s' % (type(e).__name__, e))
    record('C4', 'T2b未知PCI(IOMMU在场态)', bad)

    # T5：怪 arch=缺席态（同账户②判据，独立复跑一条）
    p = os.path.join(td, 'hw-aarch64')
    write_file(p, aarch64_sample(), 0o755)
    bad = []
    try:
        bad += absence_checks(probe_absence(probe, p))
    except Exception as e:                           # noqa: BLE001
        bad.append('%s: %s' % (type(e).__name__, e))
    record('C5', 'T5 怪arch缺席态', bad)
    return ok, fail


# ------------------------------------------------------ 账户④ L5 门 ----
# 固定三行风险话术关键内容（设计册 §3 写死；逐条关键短语断言）
RISK_MARKS = ('树外', 'CONFIG_MODULE_SIG=off', 'MODULE_FORCE_UNLOAD')


def account_module(td, aikctl):
    """账户④：L5 门机制全链（临时目录；非 root 零全局副作用）。
    → (ok, fail)。"""
    env = dict(os.environ,
               AIKMODULE_DIR=os.path.join(td, 'l5-module'),
               AIKERNEL_CONFIRM_DIR=os.path.join(td, 'l5-confirm'))
    ko = os.path.join(td, 'c3-fake.ko')
    write_file(ko, b'c3 bench fake ko (not a real module)\n', 0o644)

    def mod(args):
        cp = subprocess.run([aikctl, 'module'] + args, capture_output=True,
                            timeout=MODULE_TIMEOUT, env=env)
        return (cp.returncode, cp.stdout.decode('utf-8', 'replace'),
                cp.stderr.decode('utf-8', 'replace'))

    ok = fail = 0

    def record(sid, label, bad):
        nonlocal ok, fail
        if bad:
            fail += 1
            print('FAIL %s %-16s %s' % (sid, label,
                                        ' | '.join(bad)[:240]))
        else:
            ok += 1
            print('ok   %s %-16s' % (sid, label))

    ledger = os.path.join(td, 'l5-module', 'ledger.jsonl')
    # D1 propose：nonce+md5+三行风险话术+精确短语+pending 落盘+入账
    bad = []
    rc, out, err = mod(['propose', '--ko', ko, '--note', 'c3-bench'])
    m = re.search(r'nonce=([0-9a-f]{32})', out)
    nonce = m.group(1) if m else None
    if rc != 0 or not nonce:
        bad.append('propose rc=%d: %.160s' % (rc, (err or out).strip()))
    else:
        for mk_ in RISK_MARKS:
            if mk_ not in out:
                bad.append('缺风险话术关键短语 %r' % mk_)
        if ('CONFIRM D4 %s' % nonce) not in out:
            bad.append('缺精确确认短语')
        pend = os.path.join(td, 'l5-confirm', 'pending', nonce + '.json')
        try:
            with open(pend) as fh:
                po = json.load(fh)
            if po.get('danger') != 'D4' or po.get('ko') != ko \
                    or not po.get('md5'):
                bad.append('pending 契约字段坏: %r' % sorted(po)[:8])
        except (OSError, ValueError) as e:
            bad.append('pending 读失败: %s' % e)
    record('D1', 'propose', bad)

    if not nonce:
        for sid, label in (('D2', 'list'), ('D3', '错短语拒'),
                           ('D4', '未批准install拒'), ('D5', 'approve'),
                           ('D6', 'install dry-run'), ('D7', '未知nonce拒'),
                           ('D8', '账本四事件'), ('D9', '行链篡改检出')):
            fail += 1
            print('FAIL %s %-16s （D1 未出 nonce，链断）' % (sid, label))
        return ok, fail

    # D2 list
    rc, out, _ = mod(['list'])
    record('D2', 'list', ([] if (rc == 0 and nonce in out
                                 and 'pending=1' in out)
                          else ['rc=%d 缺 nonce/pending=1: %.80r'
                                % (rc, out)]))
    # D3 错短语（大小写变体——逐字节精确判据）→ 拒+fail_count=1 入账
    rc, out, err = mod(['approve', nonce, '--phrase',
                        'confirm d4 %s' % nonce])
    ltxt = ''
    try:
        with open(ledger) as fh:
            ltxt = fh.read()
    except OSError:
        pass
    bad = ([] if (rc != 0 and 'phrase_mismatch' in ltxt
                  and '"fail_count":1' in ltxt)
           else ['rc=%d 短语竟过/账本缺 refused: %.120r' % (rc, err)])
    record('D3', '错短语拒+计数', bad)
    # D4 未批准 install → 一律拒绝（机判负例）
    rc, out, err = mod(['install', nonce])
    try:
        with open(ledger) as fh:
            ltxt = fh.read()
    except OSError:
        ltxt = ''
    bad = ([] if (rc != 0 and 'not_approved_yet' in ltxt)
           else ['rc=%d 未批准竟装载/账本缺负例: %.120r' % (rc, err)])
    record('D4', '未批准install拒', bad)
    # D5 对短语批准
    rc, out, err = mod(['approve', nonce, '--phrase',
                        'CONFIRM D4 %s' % nonce])
    apath = os.path.join(td, 'l5-confirm', 'approved', nonce + '.json')
    ppath = os.path.join(td, 'l5-confirm', 'pending', nonce + '.json')
    bad = ([] if (rc == 0 and os.path.isfile(apath)
                  and not os.path.exists(ppath))
           else ['rc=%d approved 未落/pending 未清: %.120r'
                 % (rc, (err or out).strip())])
    record('D5', 'approve', bad)
    # D6 install --dry-run（恒不执行，只打印 insmod）
    rc, out, err = mod(['install', nonce, '--dry-run'])
    bad = ([] if (rc == 0 and 'insmod' in out and ko in out
                  and 'DRYRUN' in out and '不执行' in out)
           else ['rc=%d 缺 insmod/dry-run 标记: %.160r'
                 % (rc, (out or err).strip())])
    record('D6', 'install dry-run', bad)
    # D7 未知 nonce install 拒
    ghost = 'deadbeef' * 4
    rc, out, err = mod(['install', ghost])
    try:
        with open(ledger) as fh:
            ltxt = fh.read()
    except OSError:
        ltxt = ''
    bad = ([] if (rc != 0 and 'unknown_nonce' in ltxt)
           else ['rc=%d 未知 nonce 竟装载: %.120r' % (rc, err)])
    record('D7', '未知nonce拒', bad)
    # D8 账本四类事件齐（propose/approve/install/refused）+LEDGER_OK
    rc, out, err = mod(['ledger'])
    bad = []
    if rc != 0 or 'LEDGER_OK' not in out:
        bad.append('ledger rc=%d: %.120r' % (rc, (out or err).strip()))
    else:
        for ev, least in (('propose=', 1), ('approve=', 1), ('install=', 1),
                          ('refused=', 3)):
            m2 = re.search(ev + r'(\d+)', out)
            if not m2 or int(m2.group(1)) < least:
                bad.append('账本 %s 计数<%d: %.80r' % (ev, least, out))
    record('D8', '账本四事件+链校验', bad)
    # D9 行链篡改检出：改中段行一字段（JSON 仍合法）→ LEDGER_BREAK rc=2
    bad = []
    tamper_dir = os.path.join(td, 'l5-tamper')
    os.makedirs(tamper_dir, exist_ok=True)
    try:
        with open(ledger) as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        obj = json.loads(lines[1])
        obj['ko'] = '/tampered.ko'
        lines[1] = json.dumps(obj, sort_keys=True, separators=(',', ':'))
        with open(os.path.join(tamper_dir, 'ledger.jsonl'), 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        cp = subprocess.run([aikctl, 'module', 'ledger'], capture_output=True,
                            timeout=MODULE_TIMEOUT,
                            env=dict(env, AIKMODULE_DIR=tamper_dir))
        tout = cp.stdout.decode('utf-8', 'replace')
        if cp.returncode != 2 or 'LEDGER_BREAK' not in tout:
            bad.append('篡改竟过 rc=%d: %.120r' % (cp.returncode, tout))
    except Exception as e:                           # noqa: BLE001
        bad.append('%s: %s' % (type(e).__name__, e))
    record('D9', '行链篡改检出', bad)
    return ok, fail


# ------------------------------------------------------------- preflight ----
def preflight(probe, aikctl, live):
    """→ [FAIL 行]；空=全过。default=probe+aikctl；live 另加 euid/qemu。"""
    bad = []
    for label, b in (('aik-compat(probe)', probe), ('aikctl', aikctl)):
        if os.path.sep in b:
            if not (os.path.isfile(b) and os.access(b, os.X_OK)):
                bad.append('preflight: %s %r 不存在或无执行位' % (label, b))
        elif shutil.which(b) is None:
            bad.append('preflight: PATH 上找不到 %s %r' % (label, b))
    if live:
        if os.geteuid() != 0:
            sudo = subprocess.run(['sudo', '-n', 'true'], capture_output=True)
            bad.append('preflight: --live 需 root（当前 uid=%d；sudo -n '
                       '%s）。重跑: sudo -n python3 %s --live'
                       % (os.geteuid(),
                          '可用' if sudo.returncode == 0 else '不可用',
                          os.path.abspath(__file__)))
        if shutil.which(QEMU_AARCH64) is None:
            bad.append('preflight: 宿主缺 %s（L3 在场态样本将如实 FAIL '
                       '不跳过；装法：apt install qemu-user-static）'
                       % QEMU_AARCH64)
    return bad


# ------------------------------------------------------------------ live ----
def live_l3_chain(aikctl, probe, root, td):
    """L3 在场态真 aarch64 全链 → (过检查数, 总检查数)。"""
    name = 'c3-live-l3'
    checks = []

    def step(label, cond, detail=''):
        checks.append(cond)
        print('%s L3.%-14s %s' % ('ok  ' if cond else 'FAIL', label,
                                  '' if cond else detail[:200]))

    p = os.path.join(td, 'live-aarch64')
    write_file(p, aarch64_sample(), 0o755)
    qemu = shutil.which(QEMU_AARCH64)
    # ① qemu 真跑出 marker
    try:
        cp = subprocess.run([qemu, p], capture_output=True, timeout=30)
        step('qemu-marker', cp.returncode == 0 and cp.stdout == MARKER,
             'rc=%d stdout=%r' % (cp.returncode, cp.stdout[:40]))
    except (OSError, subprocess.TimeoutExpired) as e:
        step('qemu-marker', False, str(e))
    # ② probe 在场态：fatal 保持+adaptable=1+layer=L3+emulators 非空
    try:
        pj = probe_once(probe, p)
        arch = [r for r in (pj.get('reasons') or []) if isinstance(r, dict)
                and r.get('code') == 'ARCH_MISMATCH']
        emu = (pj.get('emulators') or {}).get('aarch64')
        step('probe-adaptable',
             bool(arch) and all(r.get('fatal') and r.get('adaptable')
                                and r.get('layer') == 'L3' for r in arch),
             'arch=%r' % (arch[:1],))
        step('emulators', bool(emu), 'emulators=%r' % (pj.get('emulators'),))
    except Exception as e:                           # noqa: BLE001
        step('probe-adaptable', False, str(e))
        step('emulators', False, str(e))
    # ③ plan：adapter.layers.L3.emulator 咬合 probe emulators（§1.3：
    # contract.argv=["<qemu>","<stage 内目标副本>",...]——argv[1] 是 stage
    # 副本路径，不含宿主路径，断言按合同不检宿主路径）
    try:
        jsonl = os.path.join(root, 'plan-%s.jsonl' % name)
        rc, _ = run_cmd([aikctl, 'compat', 'plan', '--probe', probe,
                         '--name', name, '--jsonl', jsonl, p], PLAN_TIMEOUT)
        rec, summ = read_plan_record(jsonl)
        inner = ((rec.get('adapter') or {}).get('adapter')) or {}
        l3 = (inner.get('layers') or {}).get('L3') or {}
        emu = ((rec.get('probe') or {}).get('emulators')
               or {}).get('aarch64')
        step('plan-layers-L3',
             rc == 0 and rec.get('verdict') == 'planned'
             and l3.get('emulator') == emu and bool(emu),
             'rc=%d verdict=%r L3=%r' % (rc, rec.get('verdict'), l3))
        argv = (inner.get('contract') or {}).get('argv') or []
        step('plan-argv-qemu', bool(argv) and argv[0] == emu
             and len(argv) >= 2 and isinstance(argv[1], str) and argv[1],
             'argv=%r' % (argv,))
    except Exception as e:                           # noqa: BLE001
        step('plan-layers-L3', False, str(e))
        step('plan-argv-qemu', False, str(e))
    # ④ apply+verify→绿才算链
    try:
        rc, out = run_cmd([aikctl, 'compat', 'run', '--yes', '--probe',
                           probe, name], LIVE_APPLY_TIMEOUT)
        step('apply', rc == 0 and '"ok":true' in out,
             'rc=%d %.160r' % (rc, out))
        if rc == 0:
            rc2, out2 = run_cmd([aikctl, 'compat', 'verify', '--probe',
                                 probe, name], 320)
            step('verify', rc2 == 0 and '"ok":true' in out2,
                 'rc=%d %.160r' % (rc2, out2))
        else:
            step('verify', False, 'apply 未绿跳过')
    except Exception as e:                           # noqa: BLE001
        step('apply', False, str(e))
        step('verify', False, str(e))
    # ⑤ rollback 六条（c2 同款；probe 期望=ARCH_MISMATCH fatal 集）
    try:
        n6, bad = rollback6(name, p, frozenset(('ARCH_MISMATCH',)),
                            aikctl, probe, root)
        step('rollback6', n6 == 6, '; '.join(bad)[:200])
    except Exception as e:                           # noqa: BLE001
        step('rollback6', False, str(e))
        try:
            run_cmd([aikctl, 'compat', 'rollback', '--probe', probe, name],
                    LIVE_APPLY_TIMEOUT)
        except Exception:                            # noqa: BLE001
            pass
    n_ok = sum(1 for c in checks if c)
    print('C3_L3_CHAIN ok=%d/%d' % (n_ok, len(checks)))
    return n_ok, len(checks)


def live_hw(aikctl):
    """hw 真机采集（IOMMU 空组诚实裁定）→ (过检查数, 总检查数)。"""
    checks = []

    def step(label, cond, detail=''):
        checks.append(cond)
        print('%s HW.%-14s %s' % ('ok  ' if cond else 'FAIL', label,
                                  '' if cond else detail[:200]))

    try:
        rc, _ = run_cmd([aikctl, 'compat', 'hw', '--jsonl', '/tmp/c3-hw-'
                         'live.jsonl'], HW_TIMEOUT)
        with open('/tmp/c3-hw-live.jsonl') as fh:
            # 整合修：--jsonl 流按 C1 口径末行带文本汇总（非 JSON）——
            # 容错跳过（hw_run 同款），逐行裸 loads 会炸 HW.rc。
            lines = []
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    lines.append(json.loads(ln))
                except ValueError:
                    pass
        meta = next((o for o in lines if o.get('meta')), {})
        rows = [o for o in lines if o.get('kind')]
        step('rc', rc == 0, 'rc=%d' % rc)
        step('iommu-empty-honest',
             meta.get('iommu_groups') == 0 and bool(meta.get('caveats')),
             'meta=%r' % (meta.get('iommu_groups'),))
        unbound = [r for r in rows if r.get('kind') == 'pci'
                   and not r.get('driver')]
        step('unbound-needs',
             all(r.get('verdict') == 'needs_l4_unsupported_here'
                 for r in unbound) if unbound else False,
             '无驱动绑定 PCI 设备缺席（VMware 台架应有）' if not unbound
             else '%r' % (unbound[:1],))
        step('usb-real-nodes', any(r.get('kind') == 'usb' for r in rows),
             'usb 行缺席')
    except Exception as e:                           # noqa: BLE001
        step('rc', False, str(e))
    n_ok = sum(1 for c in checks if c)
    print('C3_HW ok=%d/%d' % (n_ok, len(checks)))
    return n_ok, len(checks)


def live_l5(aikctl, td):
    """L5 真目录（/var/aikernel 真路径）dry-run 全链+负例。
    → (过检查数, 总检查数)。真账本追加式留痕（note=c3-bench-live）。"""
    checks = []

    def step(label, cond, detail=''):
        checks.append(cond)
        print('%s L5.%-14s %s' % ('ok  ' if cond else 'FAIL', label,
                                  '' if cond else detail[:200]))

    ko = os.path.join(td, 'c3-live-fake.ko')
    write_file(ko, b'c3 bench live fake ko (not a real module)\n', 0o644)

    def mod(args):
        cp = subprocess.run([aikctl, 'module'] + args, capture_output=True,
                            timeout=MODULE_TIMEOUT)
        return (cp.returncode, cp.stdout.decode('utf-8', 'replace'),
                cp.stderr.decode('utf-8', 'replace'))

    try:
        rc, out, err = mod(['propose', '--ko', ko, '--note',
                            'c3-bench-live'])
        m = re.search(r'nonce=([0-9a-f]{32})', out)
        nonce = m.group(1) if m else None
        step('propose-realpath', rc == 0 and bool(nonce),
             'rc=%d %.120r' % (rc, (err or out).strip()))
        if nonce:
            rc, _o, _e = mod(['approve', nonce, '--phrase',
                              'CONFIRM D4 %s' % nonce])
            step('approve', rc == 0, 'rc=%d' % rc)
            rc, out, _e = mod(['install', nonce])
            step('install-dryrun',
                 rc == 0 and 'insmod' in out and '不执行' in out,
                 'rc=%d %.120r' % (rc, out))
            ghost = 'feedface' * 4
            rc, _o, _e = mod(['install', ghost])
            step('unknown-nonce-refused', rc != 0, 'rc=%d' % rc)
        else:
            for lb in ('approve', 'install-dryrun', 'unknown-nonce-refused'):
                step(lb, False, '无 nonce')
        rc, out, _e = mod(['ledger'])
        step('ledger-ok', rc == 0 and 'LEDGER_OK' in out,
             'rc=%d %.120r' % (rc, out))
    except Exception as e:                           # noqa: BLE001
        step('propose-realpath', False, str(e))
    n_ok = sum(1 for c in checks if c)
    print('C3_L5 ok=%d/%d' % (n_ok, len(checks)))
    return n_ok, len(checks)


# ------------------------------------------------------------------ main ----
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='c3_compat_samples',
        description='C3 台架（COMPAT-C3-DESIGN §4；default=层名/缺席态/'
                    'L4 判定表/L5 门全链，--live=root 另加真 aarch64 全链+'
                    'hw 真机+L5 真目录）')
    ap.add_argument('--probe', default=None, metavar='BIN',
                    help='aik-compat（默认 $AIK_COMPAT_PROBE 或 PATH）')
    ap.add_argument('--aikctl', default=None, metavar='BIN',
                    help='aikctl（默认 $AIKCTL 或 probe 兄弟 aikctl/aikctl'
                         ' 或 PATH）')
    ap.add_argument('--live', action='store_true',
                    help='root 全链模式（sudo -n 下跑；不进 run_all）')
    ap.add_argument('--keep', action='store_true',
                    help='保留临时目录（排障用）')
    args = ap.parse_args(argv)
    probe = args.probe or os.environ.get('AIK_COMPAT_PROBE') or 'aik-compat'
    aikctl = resolve_aikctl(args.aikctl, probe)
    print('C3 samples probe=%s aikctl=%s mode=%s'
          % (probe, aikctl, 'live' if args.live else 'default'))

    bad = preflight(probe, aikctl, args.live)
    if bad:
        for ln in bad:
            print('FAIL ' + ln)
        print('C3_SAMPLES ok=0 fail=1')
        return 1

    root = tempfile.mkdtemp(prefix='c3-root3-')
    td = tempfile.mkdtemp(prefix='c3-samples3-')
    os.environ['AIKERNEL_COMPAT_ROOT'] = root   # plan 落临时根（同 c2 纪律）
    try:
        ok1, fail1 = account_layers(td, probe)
        ok2, fail2 = account_absence(td, probe, aikctl, root)
        ok3, fail3 = account_hw(td, aikctl, probe)
        ok4, fail4 = account_module(td, aikctl)
        ok = ok1 + ok2 + ok3 + ok4
        fail = fail1 + fail2 + fail3 + fail4
        print('C3_ACCOUNTS layers=%d/%d absence=%d/%d hw=%d/%d module=%d/%d'
              % (ok1, ok1 + fail1, ok2, ok2 + fail2, ok3, ok3 + fail3,
                 ok4, ok4 + fail4))
        if not args.live:
            print('C3_SAMPLES ok=%d fail=%d' % (ok, fail))
            return 0 if fail == 0 else 1
        l3_ok, l3_n = live_l3_chain(aikctl, probe, root, td)
        hw_ok, hw_n = live_hw(aikctl)
        l5_ok, l5_n = live_l5(aikctl, td)
        live_fail = ((l3_n - l3_ok) + (hw_n - hw_ok) + (l5_n - l5_ok))
        print('C3_SAMPLES ok=%d fail=%d' % (ok + l3_ok + hw_ok + l5_ok,
                                            fail + live_fail))
        return 0 if (fail == 0 and live_fail == 0) else 1
    finally:
        if args.keep:
            print('KEEP root=%s samples=%s' % (root, td))
        else:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(td, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
