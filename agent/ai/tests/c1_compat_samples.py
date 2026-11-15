#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C1 兼容分类 20 样本台架（COMPAT-C1-DESIGN §3.3；run_all 第 62 门）。

样本逐行照设计册 §3.3 表格（样本号/造法/期望主类一字不差）；全部在
mktemp -d 现场造（零 git 二进制），跑完清理。判定：
  blocked 样本 = probe 的 fatal code 集合与期望恰等；
  ok 样本（期望主类 RUNNABLE_OK）= runnable=1 且零 fatal。
末行 `C1_SAMPLES ok=N fail=M`；≥18/20 且零构建错误 → rc 0，否则 rc 1。
禁止调期望凑绿：期望来自冻结判定器语义，不因 probe 表现而改。

probe 指定次序：--probe BIN > $AIK_COMPAT_PROBE > PATH 上 aik-compat
（合同 §2.2：`aik-compat probe <abs>` → stdout 一行 probe JSON + 末行
`AIK_COMPAT rc=<0|1|-1> runnable=<0|1>`；解析以 JSON 行为准，第一个
'{' 起 raw_decode；AIK_COMPAT 行做 rc 校验）。

前置自检（缺=如实 FAIL，不跳过）：宿主 gcc、宿主 glibc 且 ≥GLIBC_2.2.5
（样本 16 的宿主假设，写进前置而非期望）、宿主 x86_64（C1 口径）、宿主
ld-linux 存在、probe 可用。

分组：gcc 真造组（1-9）+ 纯 python struct 合成 ELF 组（10-18）+
路径组（19-20）。合成器产结构合法 ELF（PIE 口径 p_vaddr==p_offset；
ehdr/phdrs(PT_LOAD/PT_INTERP/PT_DYNAMIC)/interp 串/dynstr/dynamic 数组
(DT_NEEDED/DT_STRTAB/DT_VERNEED/DT_VERNEEDNUM/DT_NULL)/verneed
(Elf64_Verneed+Vernaux)/shdrs(SHT_STRTAB/SHT_DYNAMIC/SHT_GNU_verneed)）
——判定器是 C 解析器（DT_NEEDED 走 SHT_DYNAMIC×sh_link 路，verneed 走
dynamic/节头双路都在），结构合法是分类的前提；#16 与 #15 同骨架只换
版本号。执行位按样本语义 chmod。

期望集口径：样本 12（ELF32 i386）在 x86_64 宿主上冻结判定器同时触发
ABI_MISMATCH（32 位，compat_tools.c:1172）与 ARCH_MISMATCH（EM_386≠
EM_X86_64，c:1182）——期望 fatal 集=两者恰等（主类=ABI_MISMATCH 照
设计册口径）；其余 blocked 样本期望集=主类单例。
"""
import argparse
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile

PROBE_TIMEOUT = 10            # 单目标 probe 超时（对齐 §3.1）
GCC_TIMEOUT = 120
AIK_COMPAT_LINE_RE = re.compile(r'^AIK_COMPAT rc=(-?\d+) runnable=([01])\s*$')
HOST_LOADER_CANDIDATES = (
    '/lib64/ld-linux-x86-64.so.2',
    '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
    '/lib/ld-linux-x86-64.so.2',
)
LIB_DIRS = (
    '/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu',
    '/lib64', '/usr/lib64', '/lib', '/usr/lib',
)

# ---- 设计册 §3.3 表格（逐行照搬：样本号/样本/造法/期望主类） ----
SPEC = [
    (1, 'ok 动态真程序', 'gcc app.c（链 libc）', 'RUNNABLE_OK'),
    (2, 'ok 静态', 'gcc -static', 'RUNNABLE_OK'),
    (3, 'ok 脚本', '#!/bin/sh', 'RUNNABLE_OK'),
    (4, '缺库 A',
     'gcc -shared -Wl,-soname,libc1a.so.1→链接后删库（test_compat.c:336 配方）',
     'MISSING_LIBRARY'),
    (5, '缺库 B', '同上换名 libc1b.so.1', 'MISSING_LIBRARY'),
    (6, '缺解释器 py', '#!/usr/bin/python4.9', 'MISSING_INTERPRETER'),
    (7, '缺解释器 env', '#!/usr/bin/env c1fake9', 'MISSING_INTERPRETER'),
    (8, '解释器不可执行', 'shebang→非执行文件', 'INTERPRETER_NOT_EXECUTABLE'),
    (9, '目标无执行位', 'chmod -x', 'NOT_EXECUTABLE'),
    (10, 'aarch64', '合成 ELF64 EM=183', 'ARCH_MISMATCH'),
    (11, 'arm', '合成 ELF64 EM=40', 'ARCH_MISMATCH'),
    (12, '32 位', '合成 ELF32 i386', 'ABI_MISMATCH'),
    (13, 'OSABI', '合成 ELF64 EI_OSABI=9(FreeBSD)', 'ABI_MISMATCH'),
    (14, '缺 loader', '合成 PT_INTERP=/lib/ld-c1missing.so.2',
     'MISSING_ABI_LOADER'),
    (15, 'glibc 过新', '合成 verneed GLIBC_2.9999', 'LIBC_VERSION_TOO_NEW'),
    (16, 'glibc 满足', '合成 verneed GLIBC_2.2.5（宿主必 ≥）',
     'RUNNABLE_OK'),
    (17, 'ELF 残缺', 'magic+截断', 'ELF_UNPARSEABLE'),
    (18, '非 ELF 数据', '加执行位的数据文件', 'NO_EXEC_FORMAT'),
    (19, '目标不存在', '/…/nope', 'MISSING_TARGET'),
    (20, '目录', 'mkdir', 'DIRECTORY_TARGET'),
]

# 期望 fatal 集（blocked 样本恰等判定用）。缺省={主类}；12 见模块
# docstring（i386 ELF32 在 x86_64 上 ABI+ARCH 双触发，冻结判定器语义）。
EXPECT_SETS = {
    12: frozenset(('ABI_MISMATCH', 'ARCH_MISMATCH')),
}


def expect_set(n, main):
    return EXPECT_SETS.get(n, frozenset((main,)))


class BuildError(Exception):
    pass


# ------------------------------------------------------------ 合成 ELF ----
def elf_hash(name):
    """SysV ELF hash（vna_hash 用，保结构合法）。"""
    h = 0
    for ch in name.encode('ascii'):
        h = ((h << 4) + ch) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= (~g) & 0xFFFFFFFF
    return h


def _align(x, a):
    return (x + a - 1) & ~(a - 1)


def synth_elf64(machine=62, osabi=0, interp=None, needed=(),
                verneed_lib=None, verneed_versions=()):
    """结构合法 ELF64（PIE 口径 p_vaddr==p_offset）→ bytes。

    machine=EM、interp=PT_INTERP 路径、needed=DT_NEEDED soname 列表、
    verneed_lib/verneed_versions=DT_VERNEED libc 家族要求版本。
    无 interp 且 ELF64 → 判定器判 STATIC_ELF（非 fatal）。
    """
    ident = bytearray(16)
    ident[0:4] = b'\x7fELF'
    ident[4] = 2            # ELFCLASS64
    ident[5] = 1            # ELFDATA2LSB
    ident[6] = 1            # EV_CURRENT
    ident[7] = osabi        # EI_OSABI
    has_dyn = bool(needed or verneed_versions)
    phentsz, shentsz = 56, 64
    phnum = 1 + (1 if interp else 0) + (1 if has_dyn else 0)
    off = 64 + phnum * phentsz

    parts = {}

    if interp:
        blob = interp.encode() + b'\x00'
        parts['interp'] = (off, blob)
        off += len(blob)

    strtab, stroff = bytearray(b'\x00'), {}
    for s in tuple(needed) + ((verneed_lib,) if verneed_lib else ()) \
            + tuple(verneed_versions):
        if s not in stroff:
            stroff[s] = len(strtab)
            strtab += s.encode() + b'\x00'
    if has_dyn:
        off = _align(off, 8)
        parts['dynstr'] = (off, bytes(strtab))
        strtab_off = off
        off += len(strtab)

    if verneed_versions:
        off = _align(off, 8)
        # 真实约定（实测 /bin/sh .gnu.version_r 字节）：Elf64_Verneed
        # 条目 16B（12B 结构+4B 垫），vn_aux=0x10；Vernaux 16B/条，
        # vna_next 步长 16（末条 0），vna_other=版本序号（≥2）。
        auxes = b''.join(
            struct.pack('<IHHII', elf_hash(v), 0, i + 2, stroff[v],
                        16 if i < len(verneed_versions) - 1 else 0)
            for i, v in enumerate(verneed_versions))
        vn = (struct.pack('<HHIHH', 1, len(verneed_versions),
                          stroff[verneed_lib], 16, 0)
              + b'\x00' * 4 + auxes)
        parts['verneed'] = (off, vn)
        verneed_off, verneed_sz = off, len(vn)
        off += verneed_sz

    if has_dyn:
        off = _align(off, 8)
        ents = [(1, stroff[s]) for s in needed]        # DT_NEEDED
        ents.append((5, strtab_off))                   # DT_STRTAB
        if verneed_versions:
            ents.append((0x6ffffffe, verneed_off))     # DT_VERNEED
            ents.append((0x6fffffff, 1))               # DT_VERNEEDNUM=1 库
        ents.append((0, 0))                            # DT_NULL
        blob = b''.join(struct.pack('<qQ', t, v) for t, v in ents)
        parts['dynamic'] = (off, blob)
        dynamic_off, dynamic_sz = off, len(blob)
        off += dynamic_sz

    # shstrtab（节名表——readelf 等独立解析器按名找 .dynamic 等）
    names = ['.shstrtab'] + (['.dynstr', '.dynamic'] if has_dyn else []) \
        + (['.gnu.version_r'] if verneed_versions else [])
    shstroff, shstrtab = {}, bytearray(b'\x00')
    for nm in names:
        shstroff[nm] = len(shstrtab)
        shstrtab += nm.encode() + b'\x00'
    parts['shstrtab'] = (off, bytes(shstrtab))
    off += len(shstrtab)
    shoff = _align(off, 8)

    def shdr(name=0, typ=0, off_=0, size=0, link=0, info=0, align_=1,
             entsz=0):
        return struct.pack('<IIQQQQIIQQ', name, typ, 0, off_, off_, size,
                           link, info, align_, entsz)

    shs = [b'\x00' * shentsz]                        # SHN_UNDEF
    i_dynstr = i_dynamic = i_shstr = None
    if has_dyn:
        i_dynstr = len(shs)
        shs.append(shdr(name=shstroff['.dynstr'], typ=3,
                        off_=parts['dynstr'][0],
                        size=len(parts['dynstr'][1]), entsz=1))  # SHT_STRTAB
        i_dynamic = len(shs)
        shs.append(shdr(name=shstroff['.dynamic'], typ=6, off_=dynamic_off,
                        size=dynamic_sz, link=i_dynstr, align_=8,
                        entsz=16))                    # SHT_DYNAMIC
        if verneed_versions:
            shs.append(shdr(name=shstroff['.gnu.version_r'],
                            typ=0x6ffffffe, off_=verneed_off,
                            size=verneed_sz, link=i_dynstr, info=1,
                            align_=8))                # SHT_GNU_verneed
    i_shstr = len(shs)
    shs.append(shdr(name=shstroff['.shstrtab'], typ=3,
                    off_=parts['shstrtab'][0],
                    size=len(parts['shstrtab'][1]), entsz=1))
    total = shoff + len(shs) * shentsz

    phdrs = [(1, 7, 0, 0, 0, total, total, 0x1000)]   # PT_LOAD RWX 全文件
    if interp:
        o, b = parts['interp']
        phdrs.append((3, 4, o, o, o, len(b), len(b), 1))   # PT_INTERP
    if has_dyn:
        phdrs.append((2, 6, dynamic_off, dynamic_off, dynamic_off,
                      dynamic_sz, dynamic_sz, 8))     # PT_DYNAMIC

    ehdr = (bytes(ident) + struct.pack(
        '<HHIQQQIHHHHHH', 3, machine, 1, 0x80, 64, shoff, 0,
        64, phentsz, phnum, shentsz, len(shs), i_shstr))
    buf = bytearray(total)
    buf[0:len(ehdr)] = ehdr
    for i, ph in enumerate(phdrs):
        buf[64 + i * phentsz:64 + (i + 1) * phentsz] = struct.pack(
            '<IIQQQQQQ', *ph)
    for o, b in parts.values():
        buf[o:o + len(b)] = b
    for i, s in enumerate(shs):
        buf[shoff + i * shentsz:shoff + (i + 1) * shentsz] = s
    return bytes(buf)


def synth_elf32_i386():
    """极简结构合法 ELF32/i386（52B ehdr + 单 NULL shdr；判定器 32 位
    只读 ehdr machine 即 ABI_MISMATCH+ARCH_MISMATCH，DT_NEEDED 不解析）。"""
    ident = bytearray(16)
    ident[0:4] = b'\x7fELF'
    ident[4] = 1            # ELFCLASS32
    ident[5] = 1
    ident[6] = 1
    ident[7] = 0
    ehdr = bytes(ident) + struct.pack(
        '<HHIIIIIHHHHHH', 3, 3, 1, 0x08048000, 0, 52, 0,
        52, 32, 0, 40, 1, 0)
    return ehdr + b'\x00' * 40              # SHN_UNDEF（52B 对齐无垫）


# ------------------------------------------------------------- probe 面 ----
def resolve_probe(explicit):
    if explicit:
        return explicit
    env = os.environ.get('AIK_COMPAT_PROBE')
    if env:
        return env
    return 'aik-compat'


def parse_probe_output(stdout):
    """合同 §2.2 解析：JSON 行为准（第一个 '{' 起）；AIK_COMPAT 行做
    rc 校验。违约抛 RuntimeError。"""
    text = stdout.decode('utf-8', errors='replace') if isinstance(
        stdout, bytes) else stdout
    i = text.find('{')
    if i < 0:
        raise RuntimeError('stdout 无 JSON 行')
    try:
        obj, _ = json.JSONDecoder().raw_decode(text, i)
    except ValueError as e:
        raise RuntimeError('probe JSON 解析失败: %s' % e)
    if not isinstance(obj, dict):
        raise RuntimeError('probe JSON 不是 object')
    line = None
    for ln in reversed(text.splitlines()):
        if ln.strip().startswith('AIK_COMPAT'):
            line = ln.strip()
            break
    m = AIK_COMPAT_LINE_RE.match(line or '')
    if not m:
        raise RuntimeError('缺/坏 AIK_COMPAT 末行: %r' % (line,))
    if int(m.group(1)) == -1:
        raise RuntimeError('probe rc=-1（参数非法；目标须绝对路径）')
    if bool(obj.get('runnable')) != bool(int(m.group(2))):
        raise RuntimeError('AIK_COMPAT 行与 JSON 的 runnable 不一致')
    return obj


def probe_once(probe, target):
    cp = subprocess.run([probe, 'probe', target], capture_output=True,
                        timeout=PROBE_TIMEOUT)
    return parse_probe_output(cp.stdout)


def fatal_codes(pj):
    return sorted({r['code'] for r in pj.get('reasons') or []
                   if isinstance(r, dict) and r.get('fatal')})


# ------------------------------------------------------------ 样本构建 ----
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


APP_C = ('#include <stdio.h>\n'
         'extern const char *c1banner(void);\n'
         'int main(void) { printf("%s\\n", c1banner()); return 0; }\n')
APP_SOLO_C = ('#include <stdio.h>\n'
              'int main(void) { printf("c1 solo\\n"); return 0; }\n')
LIB_C = ('const char *c1banner(void)\n'
         '{ return "c1-sample"; }\n')


def build_samples(td):
    """→ ({样本号: 绝对路径}, {样本号: 构建错误人话})。

    单样本构建失败只记该样本（不拖垮全局）；路径组（19/20）一并给出。
    """
    p, errs = {}, {}

    def path(n, name):
        p[n] = os.path.join(td, name)
        return p[n]

    def try_build(n, fn):
        try:
            fn()
        except (BuildError, OSError) as e:
            errs[n] = str(e)

    try_build(1, lambda: (
        write_file(os.path.join(td, 'app1.c'), APP_SOLO_C, 0o644),
        sh(['gcc', '-o', path(1, 'app1'), os.path.join(td, 'app1.c')])))
    try_build(2, lambda: (
        write_file(os.path.join(td, 'app2.c'), APP_SOLO_C, 0o644),
        sh(['gcc', '-static', '-o', path(2, 'app2'),
            os.path.join(td, 'app2.c')])))

    write_file(path(3, 'script3'), '#!/bin/sh\nexit 0\n', 0o755)

    def build_missing_lib(n, soname):
        libsrc = os.path.join(td, 'lib%d.c' % n)
        write_file(libsrc, LIB_C, 0o644)
        lib = os.path.join(td, soname)
        sh(['gcc', '-shared', '-fPIC', '-Wl,-soname,' + soname,
            '-o', lib, libsrc])
        appsrc = os.path.join(td, 'app%d.c' % n)
        write_file(appsrc, APP_C, 0o644)
        sh(['gcc', '-o', path(n, 'app%d' % n), appsrc, lib])
        os.remove(lib)                     # 链接后删库 → 真缺库

    try_build(4, lambda: build_missing_lib(4, 'libc1a.so.1'))
    try_build(5, lambda: build_missing_lib(5, 'libc1b.so.1'))

    write_file(path(6, 'script6'), '#!/usr/bin/python4.9\nexit 0\n', 0o755)
    write_file(path(7, 'script7'), '#!/usr/bin/env c1fake9\nexit 0\n',
               0o755)

    notexec = os.path.join(td, 'notexec8')
    write_file(notexec, 'i am not an interpreter\n', 0o644)
    write_file(path(8, 'script8'), '#!%s\nexit 0\n' % notexec, 0o755)

    def build_noexec_copy():
        if 1 not in p:
            raise BuildError('样本 1 未产出（无法复制）')
        app9 = path(9, 'app9')
        shutil.copyfile(p[1], app9)
        os.chmod(app9, 0o644)              # chmod -x（样本 9 语义）

    try_build(9, build_noexec_copy)

    host_loader = find_host_loader()

    def put(n, name, data, mode):
        write_file(path(n, name), data, mode)

    put(10, 'elf10-aarch64', synth_elf64(machine=183), 0o755)
    put(11, 'elf11-arm', synth_elf64(machine=40), 0o755)
    put(12, 'elf12-i386', synth_elf32_i386(), 0o755)
    put(13, 'elf13-freebsd', synth_elf64(machine=62, osabi=9), 0o755)
    put(14, 'elf14-no-loader',
        synth_elf64(interp='/lib/ld-c1missing.so.2',
                    needed=('libc.so.6',)), 0o755)
    put(15, 'elf15-glibc-new',
        synth_elf64(interp=host_loader, needed=('libc.so.6',),
                    verneed_lib='libc.so.6',
                    verneed_versions=('GLIBC_2.9999',)), 0o755)
    # 16 与 15 同骨架只换版本号（宿主必 ≥ GLIBC_2.2.5，见 preflight）
    put(16, 'elf16-glibc-ok',
        synth_elf64(interp=host_loader, needed=('libc.so.6',),
                    verneed_lib='libc.so.6',
                    verneed_versions=('GLIBC_2.2.5',)), 0o755)
    put(17, 'elf17-trunc',
        b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 11, 0o755)
    put(18, 'data18', b'c1 sample 18: plain data\n', 0o755)

    p[19] = os.path.join(td, 'nope')       # 不创建（目标不存在）
    os.mkdir(path(20, 'dir20'))            # 目录（无需执行位）
    return p, errs


def find_host_loader():
    for c in HOST_LOADER_CANDIDATES:
        if os.path.isfile(c):
            return c
    return None


# -------------------------------------------------------------- preflight ----
def preflight(probe):
    """→ [FAIL 行]；空=全过。缺 gcc/glibc/ld/非 x86_64/probe 缺席=如实
    FAIL（不跳过）。"""
    bad = []
    if shutil.which('gcc') is None:
        bad.append('preflight: 宿主缺 gcc（gcc 真造组 1-9 无法构建）')
    else:
        try:
            cp = subprocess.run(['gcc', '--version'], capture_output=True,
                                timeout=30)
            if cp.returncode != 0:
                bad.append('preflight: gcc --version rc=%d' % cp.returncode)
        except (OSError, subprocess.TimeoutExpired) as e:
            bad.append('preflight: gcc 不可执行: %s' % e)
    if platform.machine() != 'x86_64':
        bad.append('preflight: 宿主非 x86_64（%s）；C1 口径=x86_64 缺库/'
                   '旧 ABI，期望集按 x86_64 宿主冻结' % platform.machine())
    name, ver = platform.libc_ver(sys.executable)
    if name != 'glibc':
        bad.append('preflight: 宿主 libc=%r 非 glibc（样本 15/16 无从判定）'
                   % name)
    else:
        try:
            if ver and tuple(int(x) for x in ver.split('.')) < (2, 2, 5):
                bad.append('preflight: 宿主 glibc %s < GLIBC_2.2.5'
                           '（样本 16 宿主假设不成立）' % ver)
        except ValueError:
            bad.append('preflight: glibc 版本 %r 无法解析（样本 16 宿主'
                       '假设无法确认）' % ver)
    if not find_host_loader():
        bad.append('preflight: 宿主无 x86_64 ld-linux（%s）'
                   % '/'.join(HOST_LOADER_CANDIDATES))
    if os.path.sep not in probe:
        found = shutil.which(probe)
        if not found:
            bad.append('preflight: PATH 上找不到 probe %r（装 aik-compat'
                       ' 或 --probe/$AIK_COMPAT_PROBE 指定）' % probe)
    elif not (os.path.isfile(probe) and os.access(probe, os.X_OK)):
        bad.append('preflight: probe %r 不存在或无执行位' % probe)
    return bad


# ------------------------------------------------------------------ main ----
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='c1_compat_samples',
        description='C1 兼容分类 20 样本台架（COMPAT-C1-DESIGN §3.3）')
    ap.add_argument('--probe', default=None, metavar='BIN',
                    help='probe 二进制（默认 $AIK_COMPAT_PROBE 或 PATH 上'
                         ' aik-compat）')
    ap.add_argument('--keep', action='store_true',
                    help='保留样本临时目录（排障用）')
    args = ap.parse_args(argv)
    probe = resolve_probe(args.probe)
    print('C1 samples probe=%s' % probe)

    bad = preflight(probe)
    if bad:
        for ln in bad:
            print('FAIL ' + ln)
        print('C1_SAMPLES ok=0 fail=%d' % len(SPEC))
        return 1

    ok = fail = build_errs = 0
    td = tempfile.mkdtemp(prefix='c1-samples-')
    try:
        paths, errs = build_samples(td)

        for n, name, how, main_cls in SPEC:
            if n in errs:
                fail += 1
                build_errs += 1
                print('FAIL %2d %-14s 构建失败: %s' % (n, name, errs[n]))
                continue
            target = paths.get(n)
            if target is None:
                fail += 1
                build_errs += 1
                print('FAIL %2d %-14s 构建失败（未产出）' % (n, name))
                continue
            try:
                pj = probe_once(probe, target)
            except (subprocess.TimeoutExpired, RuntimeError, OSError) as e:
                fail += 1
                print('FAIL %2d %-14s probe 异常: %s' % (n, name, e))
                continue
            got = fatal_codes(pj)
            if main_cls == 'RUNNABLE_OK':
                passed = bool(pj.get('runnable')) and not got
                shown = 'runnable=%s fatal=%s' % (pj.get('runnable'),
                                                  got or '∅')
            else:
                want = expect_set(n, main_cls)
                passed = set(got) == want
                shown = '期望 fatal={%s} 实测 fatal={%s} runnable=%s' % (
                    ','.join(sorted(want)), ','.join(got) or '∅',
                    pj.get('runnable'))
            if passed:
                ok += 1
                print('ok   %2d %-14s %s | %s' % (n, name, main_cls, shown))
            else:
                fail += 1
                print('FAIL %2d %-14s %s | %s' % (n, name, main_cls, shown))
    finally:
        if args.keep:
            print('KEEP %s' % td)
        else:
            shutil.rmtree(td, ignore_errors=True)   # 跑完清理

    print('C1_SAMPLES ok=%d fail=%d' % (ok, fail))
    return 0 if (ok >= 18 and build_errs == 0) else 1


if __name__ == '__main__':
    sys.exit(main())
