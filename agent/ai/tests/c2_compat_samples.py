#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C2 双账户台架（COMPAT-C2-DESIGN §1 棒3；run_all 第 63 门）。

沿 test_compat unit/--live 双模式先例：
  default（非 root，进 run_all 第 63 门）
    AIKERNEL_COMPAT_ROOT → mktemp -d（compat 面 adapter/state/audit/台账
    全落临时根，零全局副作用；generate 静态生成不建 workspace）。
    账户①可修类 plan/generate 全链：aikctl compat plan → jsonl 记录
    verdict=planned + adapters/<name>.json 落盘 + manifest 九字段完整率
    100% 机判（逐条在场+类型）+ risk 查表值 + provides 派生子集。
    账户②不可修类拒绝账：plan 必须拒（rc!=0 + verdict=not_adaptable +
    adapter=null + adapters/ 零落盘 = 零静默成功 100%），拒绝输出带
    code/layer 人话（adapter_error 含期望主 code 与 layer=），probe
    fatal 集与期望恰等（c1 冻结判定器语义沿用）。
  --live（root，sudo -n；主会话亲跑，不进 run_all）
    在 default 账户之上加：
    ③apply/verify/rollback 全链成功率（aikctl compat run --yes → verify
      → rollback；判据 chain_ok/Y ≥ 0.8，Y=可修样本数）。
    ④回滚 100% 六条机判：rollback 回 rolled_back:true / state 文件已删 /
      回滚后 verify=NOT_FOUND（尚未 apply + rc=-10）/ 该样本 workspace
      （cmp-<name>）零残留 / /var/lib/aikernel/ws 与 /sandbox 无 c3-*·
      cmp-c3-* 残留 / 宿主零污染（/usr/local/bin 无 c3-* + 回滚后 probe
      目标仍按原样 blocked/runnable）。
    ⑤promote shadow/canary/default 三轮：shadow=只 verify 记台账；
      canary=apply 零宿主写；default=写 /usr/local/bin/c3-promo-launcher
      （唯一宿主写点）→ 台账两态（pre 不存在/存在+md5 两轮）→ rollback
      删除/按 pre 恢复 → 宿主零残留。
    全部名字唯一前缀 c3-*（workspace=cmp-c3-*）；每轮跑完彻底清理
    （含失败路径 finally 回滚+卸载），收尾全局残留清扫零容忍。

样本（23 个：可修 13 + 拒绝 10）逐类照设计册 §1 棒3#2：
  可修=缺解释器脚本（→/bin/sh、→python3、+env 三变体）/缺库 ELF
  （单/双 soname、+env、+显式契约）/INTERPRETER_NOT_EXECUTABLE/
  NOT_EXECUTABLE 副本（单/+env）/env 类（单 env/5 env=risk medium 边界）/
  --arg 传参。
  拒绝=ARCH_MISMATCH（aarch64/arm）/ABI_MISMATCH（i386 双 fatal 集/
  OSABI）/LIBC_VERSION_TOO_NEW/MISSING_ABI_LOADER/ELF_UNPARSEABLE/
  NO_EXEC_FORMAT/MISSING_TARGET/DIRECTORY_TARGET——前八者复用
  c1_compat_samples.py 的 synth_elf64/synth_elf32_i386 合成器（import
  复用；c1 文件有 __main__ 门，import 无副作用）。

manifest 九字段冻结口径：§4.4 十键中 id=适配器名（由文件路径/
ai_compat_valid_name/记录 name 另行机判），九字段=target/layers/
provides/limitations/contract(=§4.4 verify)/rollback/risk/created_by/
trace_id，类型逐条（risk 只允许 low/medium；trace_id null 或串）。

probe 次序沿 c1：--probe > $AIK_COMPAT_PROBE > PATH；aikctl 次序：
--aikctl > $AIKCTL > <probe 目录>/aikctl/aikctl > PATH（run_all 门里
probe=agent/ai/aik-compat → 兄弟路径命中仓内构建件）。

前置自检（缺=如实 FAIL 输出缺什么，不跳过）：default=gcc+aik-compat+
aikctl；--live 另加 euid=0（附 sudo -n 状态与重跑命令）、strace 在场。

输出：default 末行 `C2_PLAN_ACCOUNTS ok=N fail=M`；--live 末行
`C2_SAMPLES ok=N fail=M chain_ok=X/Y rollback6=ok/total`。退出码：
账户零 fail 且（live 另需 chain ≥80%、rollback6 全过、promote 三轮全
绿、全局残留零）→ 0，否则 1。禁止调期望凑绿：期望集按冻结判定器/
查表语义写死，不因实现表现而改。
"""
import argparse
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# import 复用（c1 有 if __name__=="__main__ 门，无副作用）：
# synth_elf64/synth_elf32_i386=合成 ELF；find_host_loader=宿主 loader；
# probe_once/fatal_codes=probe 调用与 fatal 集抽取（§2.2 合同口径）。
from c1_compat_samples import (  # noqa: E402
    synth_elf64, synth_elf32_i386, find_host_loader, probe_once, fatal_codes)

GCC_TIMEOUT = 120
PLAN_TIMEOUT = 180          # aikctl plan 内部 probe+generate 各 120s
APPLY_TIMEOUT = 620         # apply/rollback（aikctl 侧 600）
VERIFY_TIMEOUT = 320        # verify（aikctl 侧 300）
PROMOTE_TIMEOUT = 900       # default 级=apply+verify+写 launcher
WS_ROOT = '/var/lib/aikernel/ws'
SANDBOX_BASE = '/sandbox'
LAUNCHER_DIR = '/usr/local/bin'
PROMO_NAME = 'c3-promo'
PROMO_LAUNCHER = 'c3-promo-launcher'
TOTAL_SAMPLES = 23

# manifest 九字段（§4.4 映射；id=适配器名另判）——键名/冻结类型
NINE_FIELDS = (
    ('target', dict), ('layers', dict), ('provides', list),
    ('limitations', list), ('contract', dict), ('rollback', dict),
    ('risk', str), ('created_by', str), ('trace_id', (str, type(None))),
)


class BuildError(Exception):
    pass


def sh(cmd, timeout=GCC_TIMEOUT):
    cp = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if cp.returncode != 0:
        err = cp.stderr.decode('utf-8', errors='replace').strip()
        raise BuildError('%s rc=%d: %s' % (' '.join(cmd[:4]), cp.returncode,
                                           err.splitlines()[-1] if err else '?'))


def write_file(path, data, mode):
    with open(path, 'wb') as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, mode)


def md5f(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for blk in iter(lambda: f.read(1 << 16), b''):
            h.update(blk)
    return h.hexdigest()


def sweep(roots, patterns=('c3-*', 'cmp-c3-*')):
    """全局残留清扫 → 排序命中列表（c3-* 名与 cmp-c3-* workspace 都抓）。"""
    hits = []
    for d in roots:
        for pat in patterns:
            hits += glob.glob(os.path.join(d, pat))
    return sorted(hits)


# ------------------------------------------------------------ 样本定义 ----
# 可修 13：plan 附加参/期望 risk/期望 provides 子集/probe 期望
# （'RUNNABLE_OK' 或冻结 fatal 集）。risk 期望按冻结查表语义写死：
# L0 规则≤4 且无 usr_overlay 且 install≤1 → low，否则 medium。
def fixable_spec(td):
    libsrc = os.path.join(td, 'libsrc')
    os.makedirs(libsrc, exist_ok=True)
    s = []

    def add(sid, name, build, extra, risk, provides, probe_exp):
        spec = dict(id=sid, name=name, extra=extra, risk=risk,
                    provides=provides, probe=probe_exp, build_error=None)
        try:
            spec['target'] = build()
        except (BuildError, OSError) as e:
            spec['build_error'] = str(e)
            spec['target'] = os.path.join(td, sid.lower())
        s.append(spec)

    def script(fname, body):
        p = os.path.join(td, fname)
        write_file(p, body, 0o755)
        return p

    def build_lib_pair(nid, sonames, main_body):
        """gcc -shared -Wl,-soname 配方（c1 #4/#5、test_compat.c:336 同源）：
        库建于 build<nid>/，app 链接后库移入 libsrc/（链接目录与默认目录
        均不命中 → probe 真缺库；libsrc 副本=--lib-source 真源）。
        main_body 可含 {prints} 占位（各库 banner 函数拼接）。"""
        bdir = os.path.join(td, 'build' + nid)
        os.makedirs(bdir, exist_ok=True)
        sos, calls, decls = [], [], ''
        for i, sn in enumerate(sonames):
            fn = 'c3lib_%s_%s' % (nid, chr(97 + i))
            c = os.path.join(td, 'src%s%s.c' % (nid, chr(97 + i)))
            write_file(c, 'const char *%s(void)\n{ return "%s"; }\n'
                       % (fn, fn), 0o644)
            so = os.path.join(bdir, sn)
            sh(['gcc', '-shared', '-fPIC', '-Wl,-soname,' + sn,
                '-o', so, c])
            sos.append((sn, so))
            calls.append('%s()' % fn)
            decls += 'extern const char *%s(void);\n' % fn
        appc = os.path.join(td, 'app%s.c' % nid)
        # extern 声明必须齐全：缺了=隐式声明把 char* 截成 int，试跑必段错；
        # 多库时 {prints} 逗号并入 %s%s 形参（指针相加=编译错）
        write_file(appc, '#include <stdio.h>\n' + decls +
                   main_body.format(prints=', '.join(calls)), 0o644)
        app = os.path.join(td, 'app' + nid)
        sh(['gcc', '-Wall', '-Werror=implicit-function-declaration',
            '-o', app, appc] + [so for _, so in sos])
        extra, provides = [], set()
        for sn, so in sos:
            keep = os.path.join(libsrc, sn)
            shutil.move(so, keep)
            extra += ['--lib-source', '%s=%s' % (sn, keep)]
            provides.add(sn)
        return app, extra, provides

    add('F01', 'c3-f01',
        lambda: script('f01', '#!/usr/bin/python4.9\necho c3f01ok\n'),
        ['--interpreter-map', '/usr/bin/python4.9=/bin/sh'],
        'medium', {'sh'}, frozenset(('MISSING_INTERPRETER',)))
    add('F02', 'c3-f02',
        lambda: script('f02', '#!/usr/bin/python4.9\nprint("c3f02ok")\n'),
        ['--interpreter-map', '/usr/bin/python4.9=/usr/bin/python3'],
        'medium', {'python3'}, frozenset(('MISSING_INTERPRETER',)))

    def build_f03():
        p = script('f03', '#!/usr/bin/python4.9\n'
                           '[ "$C3_F03" = 1 ] || exit 4\necho c3f03ok\n')
        return p
    add('F03', 'c3-f03', build_f03,
        ['--interpreter-map', '/usr/bin/python4.9=/bin/sh',
         '--env', 'C3_F03=1'],
        'medium', set(), frozenset(('MISSING_INTERPRETER',)))

    def lib_sample(sid, nid, sonames, main_body, extra_env=(),
                   extra_args=(), risk='low'):
        holder = {}

        def build():
            app, extra, provides = build_lib_pair(nid, sonames, main_body)
            for k, v in extra_env:
                extra += ['--env', '%s=%s' % (k, v)]
            holder.update(extra=extra, provides=provides)
            return app
        add(sid, 'c3-' + sid.lower(), build, list(extra_args), risk,
            set(), frozenset(('MISSING_LIBRARY',)))
        if s[-1]['build_error'] is None:   # 构建成功才知 soname 集 → 回填
            s[-1]['extra'] = holder['extra'] + list(extra_args)
            s[-1]['provides'] = holder['provides']
    # main_body 经 .format({prints}) 注入库调用——C 花括号须转义 {{ }}
    lib_sample('F04', 'f04', ('libc3f04.so.1',),
               'int main(void){{printf("%s\\n", {prints});return 0;}}\n')
    lib_sample('F05', 'f05', ('libc3f05a.so.1', 'libc3f05b.so.1'),
               'int main(void){{printf("%s%s\\n", {prints});return 0;}}\n')
    lib_sample('F06', 'f06', ('libc3f06a.so.1', 'libc3f06b.so.1'),
               '#include <stdlib.h>\nint main(void){{if(!getenv("C3_F06"))'
               'return 5;printf("%s%s\\n", {prints});return 0;}}\n',
               extra_env=(('C3_F06', '1'),))
    lib_sample('F11', 'f11', ('libc3f11.so.1',),
               'int main(void){{printf("%s\\n", {prints});return 0;}}\n',
               # 台架自纠：app 实际输出=库函数串 c3lib_f11_a（与 F04 同构，
               # F04 无 contains 断言所以未暴露）；原期望串 c3f11ok 系撰写
               # 笔误，修正为真实输出串。
               extra_args=('--expect-stdout', 'c3lib_f11_a'))

    plain7 = os.path.join(td, 'plain7')
    write_file(plain7, 'c3 plain not exec\n', 0o644)
    # F07 期望口径（C2 整合修后冻结）：INTERPRETER_NOT_EXECUTABLE 分支
    # 原不设 p->interp（惰性适配器缺口，棒3 台架暴露）——整合期已修
    # （cp_check_interp 该分支补设 interp，与 MISSING_INTERPRETER 同款）
    # → interpreter_map 被消费 → 真 L0 path_map 规则 + L2 overlay 原语
    # → provides={'sh'}、risk 查表=medium（与 F01 缺解释器→/bin/sh 同
    # 形态）。期望随修复后的正确合同走，非实测凑绿（2026-11-15）。
    add('F07', 'c3-f07',
        lambda: script('f07', '#!%s\necho c3f07ok\n' % plain7),
        ['--interpreter-map', '%s=/bin/sh' % plain7],
        'medium', {'sh'}, frozenset(('INTERPRETER_NOT_EXECUTABLE',)))
    # F07 --live 重分类（C2 整合裁定）：解释器在 /tmp（系统视图外）→
    # 生成的 path_map 源超域 → apply 的验者防线应人话拒绝（「只允许
    # 系统视图路径」）。这是 L0/L2 的真实边界不是缺陷：/tmp 等不进
    # /usr overlay，L0/L2 结构性无法补位（C3/显式 bind 范围）。零静默
    # 账户算通过；不计入链分母（成功率判据本就只该数可修集）。
    # generate 期早拒（而非 apply 期）登记尾池。
    s[-1]['expect_refusal'] = '只允许系统视图路径'

    def notexec(sid, src, extra):
        def build():
            appc = os.path.join(td, sid.lower() + '.c')
            write_file(appc, src, 0o644)
            app = os.path.join(td, sid.lower())
            sh(['gcc', '-o', app, appc])
            os.chmod(app, 0o644)              # NOT_EXECUTABLE 副本补位
            return app
        add(sid, 'c3-' + sid.lower(), build, extra, 'low', set(),
            frozenset(('NOT_EXECUTABLE',)))
    notexec('F08', '#include <stdio.h>\n'
                   'int main(void){printf("c3f08ok\\n");return 0;}\n', [])
    notexec('F09', '#include <stdio.h>\n#include <stdlib.h>\n'
                   'int main(void){if(!getenv("C3_F09"))return 6;'
                   'printf("c3f09ok\\n");return 0;}\n',
            ['--env', 'C3_F09=1'])

    add('F10', 'c3-f10',
        lambda: script('f10', '#!/bin/sh\n'
                              '[ "$C3_F10" = v1 ] || exit 3\necho c3f10ok\n'),
        ['--env', 'C3_F10=v1'], 'low', set(), 'RUNNABLE_OK')
    add('F12', 'c3-f12',
        lambda: script('f12', '#!/bin/sh\n'
                              '[ "$C3_F12_1$C3_F12_2$C3_F12_3$C3_F12_4'
                              '$C3_F12_5" = "abcde" ] || exit 7\n'
                              'echo c3f12ok\n'),
        sum([['--env', 'C3_F12_%d=%s' % (i, c)]
             for i, c in enumerate('abcde', 1)], []),
        'medium', set(), 'RUNNABLE_OK')       # 5 条 L0 规则 → medium 边界
    add('F13', 'c3-f13',
        lambda: script('f13', '#!/bin/sh\necho "$1"\n'),
        ['--arg', 'c3f13arg', '--expect-stdout', 'c3f13arg'],
        'low', set(), 'RUNNABLE_OK')
    return s


# 拒绝 10：期望 fatal 集（恰等）+ 拒绝输出必含的主 code（generate 按
# reasons 序取首个不可适配 fatal；i386 双 fatal 集沿 c1 #12 冻结口径）。
def reject_spec(td, host_loader):
    def f(n):
        return os.path.join(td, n)

    return [
        dict(id='R01', name='c3-r01', file='r01',
             mk=lambda: write_file(f('r01'), synth_elf64(machine=183), 0o755),
             fatal=frozenset(('ARCH_MISMATCH',)), primary='ARCH_MISMATCH'),
        dict(id='R02', name='c3-r02', file='r02',
             mk=lambda: write_file(f('r02'), synth_elf64(machine=40), 0o755),
             fatal=frozenset(('ARCH_MISMATCH',)), primary='ARCH_MISMATCH'),
        dict(id='R03', name='c3-r03', file='r03',
             mk=lambda: write_file(f('r03'), synth_elf32_i386(), 0o755),
             fatal=frozenset(('ABI_MISMATCH', 'ARCH_MISMATCH')),
             primary='ABI_MISMATCH'),
        dict(id='R04', name='c3-r04', file='r04',
             mk=lambda: write_file(f('r04'),
                                   synth_elf64(machine=62, osabi=9), 0o755),
             fatal=frozenset(('ABI_MISMATCH',)), primary='ABI_MISMATCH'),
        dict(id='R05', name='c3-r05', file='r05',
             mk=lambda: write_file(
                 f('r05'),
                 synth_elf64(interp=host_loader, needed=('libc.so.6',),
                             verneed_lib='libc.so.6',
                             verneed_versions=('GLIBC_2.9999',)), 0o755),
             fatal=frozenset(('LIBC_VERSION_TOO_NEW',)),
             primary='LIBC_VERSION_TOO_NEW'),
        dict(id='R06', name='c3-r06', file='r06',
             mk=lambda: write_file(
                 f('r06'), synth_elf64(interp='/lib/ld-c3missing.so.2',
                                       needed=('libc.so.6',)), 0o755),
             fatal=frozenset(('MISSING_ABI_LOADER',)),
             primary='MISSING_ABI_LOADER'),
        dict(id='R07', name='c3-r07', file='r07',
             mk=lambda: write_file(f('r07'),
                                   b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 11,
                                   0o755),
             fatal=frozenset(('ELF_UNPARSEABLE',)),
             primary='ELF_UNPARSEABLE'),
        dict(id='R08', name='c3-r08', file='r08',
             mk=lambda: write_file(f('r08'), b'c3 sample r08 data\n', 0o755),
             fatal=frozenset(('NO_EXEC_FORMAT',)),
             primary='NO_EXEC_FORMAT'),
        dict(id='R09', name='c3-r09', file='r09', mk=None,   # 不创建
             fatal=frozenset(('MISSING_TARGET',)), primary='MISSING_TARGET'),
        dict(id='R10', name='c3-r10', file='r10',
             mk=lambda: os.mkdir(f('r10')),
             fatal=frozenset(('DIRECTORY_TARGET',)),
             primary='DIRECTORY_TARGET'),
    ]


# ------------------------------------------------------------ 命令面 ----
def resolve_aikctl(explicit, probe):
    """--aikctl > $AIKCTL > probe 兄弟 aikctl/aikctl > PATH。"""
    if explicit:
        return explicit
    env = os.environ.get('AIKCTL')
    if env:
        return env
    if probe:
        cand = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(probe)), 'aikctl', 'aikctl'))
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return 'aikctl'


def run_cmd(cmd, timeout):
    cp = subprocess.run(cmd, capture_output=True, timeout=timeout)
    return cp.returncode, cp.stdout.decode('utf-8', errors='replace')


def run_plan(aikctl, probe, name, target, extra, jsonl):
    cmd = [aikctl, 'compat', 'plan', '--probe', probe, '--name', name,
           '--jsonl', jsonl] + list(extra) + [target]
    return run_cmd(cmd, PLAN_TIMEOUT)


def compat_sub(aikctl, probe, args, timeout):
    return run_cmd([aikctl, 'compat'] + args + ['--probe', probe], timeout)


def read_plan_record(jsonl):
    """→ (record, summary 行)；违约抛 RuntimeError。"""
    with open(jsonl, 'r', errors='replace') as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    if not lines or not lines[0].startswith('{'):
        raise RuntimeError('jsonl 首行非 JSON 记录: %r'
                           % (lines[0][:120] if lines else '(空)',))
    rec = json.loads(lines[0])
    summ = lines[1].strip() if len(lines) > 1 else ''
    return rec, summ


def check_nine(adapter):
    """九字段逐条在场+类型（risk 另验值域）→ (全过?, [坏因])。"""
    bad = []
    for key, typ in NINE_FIELDS:
        if key not in adapter:
            bad.append('缺 %s' % key)
        elif not isinstance(adapter[key], typ):
            bad.append('%s 类型=%s 应 %s' % (
                key, type(adapter[key]).__name__, typ))
    if adapter.get('risk') not in ('low', 'medium'):
        bad.append('risk 值非法 %r' % adapter.get('risk'))
    if adapter.get('created_by') == '':
        bad.append('created_by 空串')
    for key in ('provides', 'limitations'):
        v = adapter.get(key)
        if isinstance(v, list) and any(not isinstance(e, str) for e in v):
            bad.append('%s 含非串元素' % key)
    return (not bad), bad


# ------------------------------------------------------------ 账户①② ----
def plan_accounts(fix, rej, aikctl, probe, root):
    """→ (ok, fail)。可修=plan 全链+九字段；拒绝=必须拒+code/layer 人话。"""
    ok = fail = 0
    for s in fix:
        name, why = s['name'], []
        if s.get('build_error'):
            fail += 1
            print('FAIL %s %-8s 构建失败: %s' % (s['id'], name,
                                                 s['build_error']))
            continue
        jsonl = os.path.join(root, 'plan-%s.jsonl' % name)
        try:
            rc, _ = run_plan(aikctl, probe, name, s['target'], s['extra'],
                             jsonl)
            rec, summ = read_plan_record(jsonl)
            if rc != 0:
                why.append('plan rc=%d' % rc)
            if 'verdict=planned' not in summ:
                why.append('summary 缺 verdict=planned: %r' % summ[:80])
            if rec.get('verdict') != 'planned':
                why.append('verdict=%r' % rec.get('verdict'))
            if rec.get('adapter') is None or rec.get('adapter_error'):
                why.append('adapter=null/error=%r'
                           % (rec.get('adapter_error'),))
            apath = os.path.join(root, 'adapters', '%s.json' % name)
            if not os.path.isfile(apath):
                why.append('adapters/%s.json 未落盘' % name)
            else:
                with open(apath) as fh:
                    adapter = json.load(fh)
                nine_ok, bad = check_nine(adapter)
                if not nine_ok:
                    why.append('九字段: %s' % ';'.join(bad))
                if adapter.get('risk') != s['risk']:
                    why.append('risk=%r 期望 %r' % (adapter.get('risk'),
                                                    s['risk']))
                pv = set(adapter.get('provides') or [])
                if not (s['provides'] or set()) <= pv:
                    why.append('provides %s 缺 %s' % (
                        sorted(pv) or '∅', sorted(s['provides'] - pv)))
        except Exception as e:                     # noqa: BLE001 台架如实记账
            why.append('%s: %s' % (type(e).__name__, e))
        if why:
            fail += 1
            print('FAIL %s %-8s %s' % (s['id'], name, ' | '.join(why)[:300]))
        else:
            ok += 1
            print('ok   %s %-8s planned | risk=%s 九字段 9/9 provides=%s'
                  % (s['id'], name, s['risk'], sorted(s['provides']) or '∅'))
    for s in rej:
        name, why = s['name'], []
        if s.get('build_error'):
            fail += 1
            print('FAIL %s %-8s 构建失败: %s' % (s['id'], name,
                                                 s['build_error']))
            continue
        jsonl = os.path.join(root, 'plan-%s.jsonl' % name)
        try:
            rc, _ = run_plan(aikctl, probe, name, s['target'], [], jsonl)
            rec, summ = read_plan_record(jsonl)
            if rc == 0:
                why.append('plan 竟 rc=0（静默成功）')
            if 'verdict=not_adaptable' not in summ:
                why.append('summary 缺 not_adaptable: %r' % summ[:80])
            if rec.get('verdict') != 'not_adaptable':
                why.append('verdict=%r' % rec.get('verdict'))
            if rec.get('adapter') is not None:
                why.append('adapter 非 null（静默成功）')
            aerr = rec.get('adapter_error') or ''
            if not isinstance(aerr, str) or not aerr:
                why.append('adapter_error 缺')
            else:
                if s['primary'] not in aerr:
                    why.append('拒绝输出缺主 code %s' % s['primary'])
                if 'layer=' not in aerr:
                    why.append('拒绝输出缺 layer= 人话')
            got = frozenset(fatal_codes(rec.get('probe') or {}))
            if got != s['fatal']:
                why.append('fatal 集 {%s}≠{%s}' % (','.join(sorted(got)),
                                                   ','.join(sorted(
                                                       s['fatal']))))
            if os.path.isfile(os.path.join(root, 'adapters',
                                           '%s.json' % name)):
                why.append('adapters/%s.json 落盘（零静默成功破防）' % name)
        except Exception as e:                     # noqa: BLE001
            why.append('%s: %s' % (type(e).__name__, e))
        if why:
            fail += 1
            print('FAIL %s %-8s %s' % (s['id'], name, ' | '.join(why)[:300]))
        else:
            ok += 1
            print('ok   %s %-8s 拒绝 | %s+layer 人话 fatal={%s} 零落盘'
                  % (s['id'], name, s['primary'],
                     ','.join(sorted(s['fatal']))))
    return ok, fail


# ------------------------------------------------------------ live ----
def rollback6(name, target, probe_expect, aikctl, probe, root):
    """回滚六条机判 → (过条数/6, [坏因])。probe 期望同 ①（blocked 仍
    blocked / runnable 仍 runnable = 宿主状态未漂移）。"""
    bad = []
    rc, out = compat_sub(aikctl, probe, ['rollback', name], APPLY_TIMEOUT)
    if rc != 0 or '"rolled_back":true' not in out:
        bad.append('①rolled_back rc=%d %.120s' % (rc, out.strip()))
    spath = os.path.join(root, 'state', '%s.applied.json' % name)
    if os.path.exists(spath):
        bad.append('②state 未删 %s' % spath)
    rc, out = compat_sub(aikctl, probe, ['verify', name], VERIFY_TIMEOUT)
    if rc == 0 or '尚未 apply' not in out or 'rc=-10' not in out:
        bad.append('③verify 回滚后非 NOT_FOUND(rc=-10) rc=%d %.120s'
                   % (rc, out.strip()))
    try:
        ws_left = [e for e in os.listdir(WS_ROOT)
                   if e.startswith('cmp-' + name)]
    except OSError:
        ws_left = ['<%s 不可列>' % WS_ROOT]
    if ws_left:
        bad.append('④workspace 残留 %s' % ws_left[:3])
    left = sweep((WS_ROOT, SANDBOX_BASE))
    if left:
        bad.append('⑤ws/sandbox c3-* 残留 %s'
                   % [os.path.basename(e) for e in left[:4]])
    try:
        pj = probe_once(probe, target)
        got = frozenset(fatal_codes(pj))
        if probe_expect == 'RUNNABLE_OK':
            if not pj.get('runnable'):
                bad.append('⑥回滚后目标竟不可跑 fatal=%s' % sorted(got))
        elif got != probe_expect or pj.get('runnable'):
            bad.append('⑥probe 漂移 fatal=%s runnable=%s'
                       % (sorted(got), pj.get('runnable')))
    except Exception as e:                          # noqa: BLE001
        bad.append('⑥probe 异常 %s' % e)
    if glob.glob(os.path.join(LAUNCHER_DIR, 'c3-*')):
        bad.append('⑥/usr/local/bin 有 c3-* 残留')
    return 6 - len(bad), bad


def live_chain(fix, aikctl, probe, root):
    """③全链 + ④六条（逐样本 apply→verify→rollback；失败路径也兜底回滚）。
    rollback6 分母=真正 apply 成功（有 state）的样本数。"""
    chain_ok = 0
    rb_ok = rb_total = 0
    ref_ok = ref_fail = 0
    for s in fix:
        name, why = s['name'], []
        if s.get('expect_refusal'):
            # L0/L2 边界样本：apply 应人话拒绝——诚实拒绝=零静默账户
            # 通过，不计链分母（见 F07 注）。
            rc, out = compat_sub(aikctl, probe, ['run', '--yes', name],
                                 APPLY_TIMEOUT)
            msg = out or ''
            if rc != 0 and s['expect_refusal'] in msg:
                ref_ok += 1
                print('ok   %s %-8s 诚实拒绝（apply：%.60s）'
                      % (s['id'], name, s['expect_refusal']))
            else:
                ref_fail += 1
                print('FAIL %s %-8s 期望 apply 拒绝（%s）却 rc=%d %.200s'
                      % (s['id'], name, s['expect_refusal'], rc,
                         msg.strip()))
            continue
        try:
            if s.get('build_error'):
                raise BuildError(s['build_error'])
            rc, out = compat_sub(aikctl, probe, ['run', '--yes', name],
                                 APPLY_TIMEOUT)
            if rc != 0 or '"ok":true' not in out:
                why.append('apply rc=%d %.400s' % (rc, out.strip()))
            if os.path.isfile(os.path.join(root, 'state',
                                           '%s.applied.json' % name)):
                rb_total += 1
                vrc, vout = compat_sub(aikctl, probe, ['verify', name],
                                       VERIFY_TIMEOUT)
                if vrc != 0 or '"ok":true' not in vout:
                    why.append('verify rc=%d %.400s' % (vrc, vout.strip()))
                if not why:
                    chain_ok += 1
                    print('ok   %s %-8s 链 apply+verify 绿' % (s['id'], name))
                n6, bad = rollback6(name, s['target'], s['probe'],
                                    aikctl, probe, root)
                if n6 == 6:
                    rb_ok += 1
                    print('ok   %s %-8s 回滚六条 6/6' % (s['id'], name))
                else:
                    why += bad
            else:
                why.append('apply 后无 state')
                compat_sub(aikctl, probe, ['rollback', name], APPLY_TIMEOUT)
        except Exception as e:                      # noqa: BLE001 失败路径兜底
            why.append('%s: %s' % (type(e).__name__, e))
            try:
                compat_sub(aikctl, probe, ['rollback', name], APPLY_TIMEOUT)
            except Exception:                       # noqa: BLE001
                pass
        if why:
            print('FAIL %s %-8s %s' % (s['id'], name, ' | '.join(why)[:320]))
    return chain_ok, rb_ok, rb_total, ref_fail


def promote_rounds(aikctl, probe, root, td):
    """⑤三轮+台账两态+回滚恢复 → 全绿 bool；finally 彻底清理（含失败）。"""
    results = {}
    lpath = os.path.join(LAUNCHER_DIR, PROMO_LAUNCHER)
    led = os.path.join(root, 'promote', '%s.json' % PROMO_NAME)
    target = os.path.join(td, 'promo')

    def load_ledger():
        with open(led) as fh:
            return json.load(fh)

    def no_launcher():
        return not glob.glob(os.path.join(LAUNCHER_DIR, 'c3-*'))

    def step(key, fn):
        try:
            results[key] = bool(fn())
        except Exception as e:                      # noqa: BLE001
            results[key] = False
            print('FAIL promote.%s %s: %s' % (key, type(e).__name__, e))
        if results[key]:
            print('ok   P-%s %s' % (key, PROMO_NAME))
        elif key not in ('rollback_absent',):
            print('FAIL promote.%s（返回假值）' % key)

    def do_plan_apply():
        write_file(target, '#!/usr/bin/python4.9\necho c3promook\n', 0o755)
        rc, _ = run_plan(aikctl, probe, PROMO_NAME, target,
                         ['--interpreter-map', '/usr/bin/python4.9=/bin/sh'],
                         os.path.join(root, 'plan-%s.jsonl' % PROMO_NAME))
        if rc != 0:
            raise RuntimeError('plan rc=%d' % rc)
        rc, out = compat_sub(aikctl, probe, ['run', '--yes', PROMO_NAME],
                             APPLY_TIMEOUT)
        if rc != 0 or '"ok":true' not in out:
            raise RuntimeError('apply rc=%d %.120s' % (rc, out.strip()))
        return True

    def do_shadow():
        rc, out = compat_sub(aikctl, probe,
                             ['promote', '--stage', 'shadow', PROMO_NAME],
                             VERIFY_TIMEOUT)
        if rc != 0 or 'stage=shadow ok=1' not in out:
            raise RuntimeError('rc=%d %.160s' % (rc, out.strip()))
        if not (load_ledger().get('stages', {}).get('shadow', {})
                .get('ok')):
            raise RuntimeError('台账 stages.shadow.ok 非真')
        return no_launcher()                        # shadow 零宿主写

    def do_canary():
        rc, out = compat_sub(aikctl, probe,
                             ['promote', '--stage', 'canary', '--yes',
                              PROMO_NAME], APPLY_TIMEOUT)
        if rc != 0 or 'stage=canary ok=1' not in out:
            raise RuntimeError('rc=%d %.160s' % (rc, out.strip()))
        if not (load_ledger().get('stages', {}).get('canary', {})
                .get('ok')):
            raise RuntimeError('台账 stages.canary.ok 非真')
        return no_launcher()                        # canary 零宿主写

    def do_default_absent():
        rc, out = compat_sub(aikctl, probe,
                             ['promote', '--stage', 'default', '--yes',
                              '--launcher', PROMO_LAUNCHER, PROMO_NAME],
                             PROMOTE_TIMEOUT)
        if rc != 0 or 'stage=default ok=1' not in out:
            raise RuntimeError('rc=%d %.160s' % (rc, out.strip()))
        la = load_ledger().get('launcher') or {}
        if la.get('pre') != {'exists': False}:
            raise RuntimeError('pre 两态非不存在: %r' % (la.get('pre'),))
        if not (os.path.isfile(lpath) and os.access(lpath, os.X_OK)):
            raise RuntimeError('launcher 未落盘/无执行位')
        if md5f(lpath) != la.get('installed_md5'):
            raise RuntimeError('launcher md5 与台账不符')
        return True

    def do_default_existing():
        write_file(lpath, 'c3 pre-existing marker\n', 0o755)
        marker = md5f(lpath)
        rc, out = compat_sub(aikctl, probe,
                             ['promote', '--stage', 'default', '--yes',
                              '--launcher', PROMO_LAUNCHER, PROMO_NAME],
                             PROMOTE_TIMEOUT)
        if rc != 0 or 'stage=default ok=1' not in out:
            raise RuntimeError('rc=%d %.160s' % (rc, out.strip()))
        la = load_ledger().get('launcher') or {}
        pre = la.get('pre') or {}
        if not pre.get('exists') or pre.get('md5') != marker:
            raise RuntimeError('pre 两态非存在+md5: %r' % (pre,))
        if not os.path.isfile(la.get('backup') or ''):
            raise RuntimeError('pre 备份缺失')
        if md5f(lpath) != la.get('installed_md5') or md5f(lpath) == marker:
            raise RuntimeError('launcher 未换成 wrapper')
        rc, out = compat_sub(aikctl, probe, ['rollback', PROMO_NAME],
                             APPLY_TIMEOUT)
        if rc != 0 or '"rolled_back":true' not in out:
            raise RuntimeError('rollback rc=%d %.120s' % (rc, out.strip()))
        if md5f(lpath) != marker:
            raise RuntimeError('pre 内容未按备份恢复（md5 不符）')
        return True

    try:
        step('plan_apply', do_plan_apply)
        step('shadow', do_shadow)
        step('canary', do_canary)
        step('default_absent', do_default_absent)
        n6, bad = rollback6(PROMO_NAME, target,
                            frozenset(('MISSING_INTERPRETER',)),
                            aikctl, probe, root)
        results['rollback_absent'] = n6 == 6 and not os.path.exists(lpath)
        if results['rollback_absent']:
            print('ok   P-rollback_absent %s（六条 6/6+launcher 删）'
                  % PROMO_NAME)
        else:
            print('FAIL promote.rollback_absent %s' % bad)
        step('default_existing', do_default_existing)
    finally:
        # 彻底清理（含失败路径）：幂等回滚 + 删 bench 自建 marker/产物 +
        # 产品回滚未销毁的 workspace 残件（created 标志缺口时兜底，发现
        # 已如实记入 rollback_absent/RESIDUE 行）
        try:
            compat_sub(aikctl, probe, ['rollback', PROMO_NAME], APPLY_TIMEOUT)
        except Exception:                           # noqa: BLE001
            pass
        if os.path.isfile(lpath):
            os.unlink(lpath)
        bench_clean([PROMO_NAME])
    print('C2_PROMOTE plan_apply=%d shadow=%d canary=%d default_absent=%d '
          'rollback_absent=%d default_existing=%d'
          % tuple(int(results.get(k, 0)) for k in
                  ('plan_apply', 'shadow', 'canary', 'default_absent',
                   'rollback_absent', 'default_existing')))
    return all(results.get(k) for k in
               ('plan_apply', 'shadow', 'canary', 'default_absent',
                'rollback_absent', 'default_existing'))


def bench_clean(names):
    """台架自清（失败路径兜底，不动 occ* 等他人目录）：卸载并删除本台架
    名下的 workspace 残件（img/meta//sandbox 挂载目录）与 launcher 文件，
    并解绑挂在 cmp-c3-* 镜像上的残留 loop（promote 回滚 created 标志缺口
    会留 loop）。→ 剩余 c3-* 残留数（0=干净）。"""
    try:
        cp = subprocess.run(['losetup', '-a'], capture_output=True, timeout=30)
        for ln in cp.stdout.decode('utf-8', 'replace').splitlines():
            if '/var/lib/aikernel/ws/cmp-c3-' not in ln:
                continue
            dev = ln.split(':', 1)[0].strip()
            if dev.startswith('/dev/loop'):
                subprocess.run(['losetup', '-d', dev], capture_output=True,
                               timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass
    for n in names:
        ws = 'cmp-' + n
        for p in (os.path.join(WS_ROOT, ws + '.img'),
                  os.path.join(WS_ROOT, ws + '.meta')):
            try:
                if os.path.isfile(p):
                    os.unlink(p)
            except OSError:
                pass
        sd = os.path.join(SANDBOX_BASE, ws)
        try:
            if os.path.ismount(sd):
                subprocess.run(['umount', sd], capture_output=True, timeout=30)
            if os.path.isdir(sd) and not os.path.ismount(sd):
                shutil.rmtree(sd, ignore_errors=True)
        except OSError:
            pass
    return len(sweep((LAUNCHER_DIR, WS_ROOT, SANDBOX_BASE)))


def live_preclean(names, aikctl, probe, root):
    """进场清扫：对全部 c3-* 名做幂等回滚+残件强清（防上次半成品：文件、
    挂载、泄漏 loop——promote 回滚 created 标志缺口的残局也在此收口）。"""
    for n in names:
        try:
            compat_sub(aikctl, probe, ['rollback', n], APPLY_TIMEOUT)
        except Exception:                           # noqa: BLE001
            pass
        for p in (os.path.join(LAUNCHER_DIR, PROMO_LAUNCHER)
                  if n == PROMO_NAME else os.path.join(LAUNCHER_DIR, n),
                  os.path.join(root, 'state', '%s.applied.json' % n),
                  os.path.join(root, 'adapters', '%s.json' % n),
                  os.path.join(root, 'promote', '%s.json' % n)):
            if os.path.isfile(p):
                os.unlink(p)
    bench_clean(names)
    left = sweep((LAUNCHER_DIR, WS_ROOT, SANDBOX_BASE))
    print('C2_PRECLEAN 残留清扫=%d%s' % (
        len(left), ' ' + str([os.path.basename(e) for e in left[:4]])
        if left else '（干净）'))


# ------------------------------------------------------------ preflight ----
def preflight(probe, aikctl, live):
    bad = []
    if shutil.which('gcc') is None:
        bad.append('preflight: 宿主缺 gcc（可修类真造组无法构建）')
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
        if shutil.which('strace') is None:
            bad.append('preflight: 宿主缺 strace（verify 轨迹断言需要）')
    return bad


# ------------------------------------------------------------------ main ----
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='c2_compat_samples',
        description='C2 双账户台架（COMPAT-C2-DESIGN §1 棒3；default=plan/'
                    '拒绝账，--live=root 另加 apply/verify/rollback 链+回滚'
                    '六条+promote 三轮）')
    ap.add_argument('--probe', default=None, metavar='BIN',
                    help='aik-compat（默认 $AIK_COMPAT_PROBE 或 PATH）')
    ap.add_argument('--aikctl', default=None, metavar='BIN',
                    help='aikctl（默认 $AIKCTL 或 probe 兄弟 aikctl/aikctl'
                         ' 或 PATH）')
    ap.add_argument('--live', action='store_true',
                    help='root 全链模式（sudo -n 下跑；不进 run_all）')
    ap.add_argument('--small', action='store_true',
                    help='小规模（--live 冒烟：可修 4+拒绝 2）')
    ap.add_argument('--keep', action='store_true',
                    help='保留临时目录（排障用）')
    args = ap.parse_args(argv)
    probe = args.probe or os.environ.get('AIK_COMPAT_PROBE') or 'aik-compat'
    aikctl = resolve_aikctl(args.aikctl, probe)
    print('C2 samples probe=%s aikctl=%s mode=%s%s'
          % (probe, aikctl, 'live' if args.live else 'default',
             ' small' if args.small else ''))

    bad = preflight(probe, aikctl, args.live)
    if bad:
        for ln in bad:
            print('FAIL ' + ln)
        if args.live:
            print('C2_SAMPLES ok=0 fail=%d chain_ok=0/0 rollback6=0/0'
                  % TOTAL_SAMPLES)
        else:
            print('C2_PLAN_ACCOUNTS ok=0 fail=%d' % TOTAL_SAMPLES)
        return 1

    root = tempfile.mkdtemp(prefix='c3-root-')
    td = tempfile.mkdtemp(prefix='c3-samples-')
    os.environ['AIKERNEL_COMPAT_ROOT'] = root   # aikctl/aik-compat 全继承
    rc = 1
    try:
        fix = fixable_spec(td)
        rej = reject_spec(td, find_host_loader())
        for s in rej:
            s['target'] = os.path.join(td, s['file'])
            s['build_error'] = None
            try:
                if s['mk']:
                    s['mk']()
            except (BuildError, OSError) as e:
                s['build_error'] = str(e)
        if args.small:
            fix, rej = fix[:4], rej[:2]

        if args.live:
            live_preclean([s['name'] for s in fix] +
                          [s['name'] for s in rej] + [PROMO_NAME],
                          aikctl, probe, root)
        ok, fail = plan_accounts(fix, rej, aikctl, probe, root)
        print('C2_PLAN_ACCOUNTS ok=%d fail=%d' % (ok, fail))

        if not args.live:
            return 0 if fail == 0 else 1

        chain_ok, rb_ok, rb_total, ref_fail = live_chain(
            fix, aikctl, probe, root)
        fail += ref_fail
        denom = [x for x in fix if not x.get('expect_refusal')]
        ratio = (chain_ok / len(denom)) if denom else 0.0
        print('C2_CHAIN ok=%d/%d（%.0f%%，判据 ≥80%%: %s）'
              % (chain_ok, len(denom), ratio * 100,
                 '达标' if ratio >= 0.8 else '不达标'))
        promo_ok = promote_rounds(aikctl, probe, root, td)
        left = sweep((WS_ROOT, SANDBOX_BASE))
        n_launch = len(glob.glob(os.path.join(LAUNCHER_DIR, 'c3-*')))
        print('C2_RESIDUE %s=%d %s=%d %s=%d %s'
              % (LAUNCHER_DIR, n_launch, WS_ROOT,
                 len([e for e in left if e.startswith(WS_ROOT)]),
                 SANDBOX_BASE,
                 len([e for e in left if e.startswith(SANDBOX_BASE)]),
                 '零残留' if (not left and not n_launch) else
                 '残留! %s' % [os.path.basename(e) for e in left[:4]]))
        rc = 0 if (fail == 0 and ratio >= 0.8 and rb_total > 0
                   and rb_ok == rb_total and promo_ok and not left
                   and not n_launch) else 1
        # 台架自清（含产品缺口残件）+ 清理证明；rc 按清理前状态判定不变
        left2 = bench_clean([s['name'] for s in fix] + [PROMO_NAME])
        print('C2_CLEAN 清理后 c3-* 残留=%d%s' % (
            left2, '' if left2 == 0 else
            '（仍有残留: %s）' % [os.path.basename(e) for e in
                                 sweep((LAUNCHER_DIR, WS_ROOT,
                                        SANDBOX_BASE))[:4]]))
        print('C2_SAMPLES ok=%d fail=%d chain_ok=%d/%d rollback6=%d/%d'
              % (ok, fail, chain_ok, len(denom), rb_ok, rb_total))
        return rc
    finally:
        if args.keep:
            print('KEEP root=%s samples=%s' % (root, td))
        else:
            shutil.rmtree(root, ignore_errors=True)    # 跑完清理
            shutil.rmtree(td, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
