#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_aip_table.py — aipd 静态阈值表生成器（AIPD-M1-DESIGN §2.1）。

M1 整合裁定（2026-11-16）：**生成器向已编译合同对齐**——契约冻结于
aip_model.h（struct ai_rule/枚举）与 aip_table.h/aip_table.c
（序列化+摘要），本生成器逐字节遵循：

  序列化 = 每规则 128B 小端：'<IIQqII'（feat,op,lo,hi,action,
           param 视 u32）+ reason UTF-8 NUL 填充至 96B
  摘要   = sha256(全部规则串连；**无头**) → 64 hex 小写常量串
           （Lane-A 手写实现同款——aip_table.c aip_table_serialize/
           aip_sha256；双实现对拍见 --check）

用法：
  gen_aip_table.py [--spec table_spec.json] [--out aip_table.c]
  --check           重生成与现有产物比对（漂移 rc=1）
  --print-contract  打印冻结合同摘要（符号/序列化/摘要算法）

改 schema=改契约（须过主会话拍板升 AIP_TABLE_VER）。
"""
import argparse
import hashlib
import json
import struct
import sys

I64_MIN, I64_MAX = -(2 ** 63), 2 ** 63 - 1
I32_MIN, I32_MAX = -(2 ** 31), 2 ** 31 - 1


class SpecError(Exception):
    pass


def load_spec(path):
    with open(path, 'r', encoding='utf-8') as fh:
        spec = json.load(fh)
    validate(spec)
    return spec


def validate(spec):
    sch = spec.get('schema') or {}
    for key in ('include_model', 'include_table', 'table_symbol',
                'len_symbol', 'ver_symbol', 'digest_symbol',
                'rules_max_macro', 'reason_max', 'rule_ser_struct',
                'digest_algo', 'feat_syms', 'op_syms', 'act_syms'):
        if key not in sch:
            raise SpecError('schema 缺键: %s' % key)
    if sch['digest_algo'] != 'sha256':
        raise SpecError('M1 冻结=sha256（%r）' % sch['digest_algo'])
    if spec.get('version') != 1:
        raise SpecError('version 须=1（AIP_TABLE_VER）')
    rules = spec.get('rules')
    if not isinstance(rules, list) or not rules:
        raise SpecError('rules 须为非空数组')
    if len(rules) > 64:
        raise SpecError('rules 超 AIP_RULES_MAX=64')
    rmax = int(sch['reason_max'])
    seen = set()
    for i, r in enumerate(rules):
        where = 'rules[%d]' % i
        rid = r.get('id')
        if not rid or rid in seen:
            raise SpecError('%s: id 缺失或重复 (%r)' % (where, rid))
        seen.add(rid)
        if r.get('feat') not in sch['feat_syms']:
            raise SpecError('%s: 未知 feat %r' % (where, r.get('feat')))
        if r.get('op') not in sch['op_syms']:
            raise SpecError('%s: 未知 op %r' % (where, r.get('op')))
        if r.get('action') not in sch['act_syms']:
            raise SpecError('%s: 未知 action %r' % (where, r.get('action')))
        for k in ('lo', 'hi', 'param'):
            v = r.get(k)
            if not isinstance(v, int) or isinstance(v, bool):
                raise SpecError('%s: %s 须为整数' % (where, k))
        if not (I64_MIN <= r['lo'] <= I64_MAX
                and I64_MIN <= r['hi'] <= I64_MAX):
            raise SpecError('%s: lo/hi 须在 i64 值域' % where)
        if not (I32_MIN <= r['param'] <= I32_MAX):
            raise SpecError('%s: param 须在 i32 值域' % where)
        if r['op'] == 'AIP_OP_IN_RANGE' and r['lo'] > r['hi']:
            raise SpecError('%s: IN_RANGE lo(%d)>hi(%d)'
                            % (where, r['lo'], r['hi']))
        why = r.get('because') or ''
        blen = len(why.encode('utf-8'))
        if not why:
            raise SpecError('%s: 缺 because（可解释性必需）' % where)
        if blen > rmax - 1:
            raise SpecError('%s: because %dB 超 reason[%d-1] 上限'
                            % (where, blen, rmax))


def canonical_bytes(spec):
    """规则串连字节串（Lane-A aip_table_serialize 同款；顺序参与摘要）。"""
    sch = spec['schema']
    out = []
    for r in spec['rules']:
        out.append(struct.pack(
            sch['rule_ser_struct'],
            sch['feat_syms'][r['feat']],
            sch['op_syms'][r['op']],
            r['lo'], r['hi'],
            sch['act_syms'][r['action']],
            r['param'] & 0xFFFFFFFF)
            + r['because'].encode('utf-8').ljust(int(sch['reason_max']),
                                                 b'\x00'))
    return b''.join(out)


def digest_hex(spec):
    return hashlib.sha256(canonical_bytes(spec)).hexdigest()


def spec_bytes(path):
    with open(path, 'rb') as fh:
        return fh.read()


def _fmt_i64(v):
    return '%dLL' % v if abs(v) > 0x7FFFFFFF else '%d' % v


def render(spec, spec_sha):
    sch = spec['schema']
    rules = spec['rules']
    lines = []
    a = lines.append
    a('/* SPDX-License: GPL-2.0 */')
    a('/*')
    a(' * aip_table.c — aipd 静态阈值表（**生成器产物，勿手改**；')
    a(' * gen_aip_table.py --check 冻结漂移检）。')
    a(' *')
    a(' * 源 spec: table_spec.json sha256=%s' % spec_sha)
    a(' * 契约:   aip_model.h（struct ai_rule/枚举）+ aip_table.h')
    a(' * 序列化: %dB/条 %s + reason[%d] NUL 填充'
      % (struct.calcsize(sch['rule_ser_struct']) + int(sch['reason_max']),
         sch['rule_ser_struct'], sch['reason_max']))
    a(' * 摘要:   sha256(规则串连，无头) = AIP_TABLE_SHA256（自校验）')
    a(' * M1 影子语义: 只产影子记录，无任何 ACT 下发路径。')
    a(' */')
    a('')
    a('#include <stddef.h>')
    a('#include <stdint.h>')
    a('#include <sys/types.h>\t/* ssize_t（aip_table.h 声明依赖） */')
    a('')
    a('#include "%s"' % sch['include_model'])
    a('#include "%s"' % sch['include_table'])
    a('')
    a('const size_t %s = %d;' % (sch['len_symbol'], len(rules)))
    a('const uint32_t %s = AIP_TABLE_VER;'
      % sch['ver_symbol'])
    a('')
    a('const struct ai_rule %s[%s] = {'
      % (sch['table_symbol'], sch['rules_max_macro']))
    for r in rules:
        a('\t{ %s, %s,' % (r['feat'], r['op']))
        a('\t  %s, %s,' % (_fmt_i64(r['lo']), _fmt_i64(r['hi'])))
        a('\t  %s, %d,' % (r['action'], r['param']))
        a('\t  %s },' % _c_str(r['because']))
    a('};')
    a('')
    a('/* sha256(序列化规则串)——aip_table_check 自校验常量 */')
    a('const char %s[] = "%s";'
      % (sch['digest_symbol'], digest_hex(spec)))
    a('')
    return '\n'.join(lines)


def _c_str(text):
    """C 字符串字面量（ASCII 可打印直出；其余 \\xHH 逃逸——Lane-A 手写
    件同风格，逐字节稳定）。"""
    out = []
    for b in text.encode('utf-8'):
        if 0x20 <= b < 0x7F and b not in (0x22, 0x5C):
            out.append(chr(b))
        else:
            out.append('\\x%02x' % b)
    return '"%s"' % ''.join(out)


def main(argv=None):
    import os
    ap = argparse.ArgumentParser(prog='gen_aip_table.py')
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument('--spec', default=os.path.join(here, 'table_spec.json'))
    ap.add_argument('--out', default=os.path.join(here,
                                                  'aip_table_data.c'))
    ap.add_argument('--check', action='store_true',
                    help='重生成与现有产物比对（漂移 rc=1）')
    ap.add_argument('--print-contract', action='store_true')
    args = ap.parse_args(argv)

    spec = load_spec(args.spec)
    if args.print_contract:
        sch = spec['schema']
        print('table=%s len=%s ver=%s sha=%s'
              % (sch['table_symbol'], sch['len_symbol'],
                 sch['ver_symbol'], sch['digest_symbol']))
        print('rule_ser=%s(+reason %dB) digest=%s(规则串,无头)'
              % (sch['rule_ser_struct'], sch['reason_max'],
                 sch['digest_algo']))
        print('sha256=%s rules=%d' % (digest_hex(spec),
                                      len(spec['rules'])))
        return 0
    text = render(spec, hashlib.sha256(
        spec_bytes(args.spec)).hexdigest())
    if args.check:
        try:
            with open(args.out, 'r', encoding='utf-8') as fh:
                cur = fh.read()
        except OSError as e:
            print('gen: 读现有产物失败: %s' % e, file=sys.stderr)
            return 1
        if cur != text:
            print('gen: %s 与 spec 漂移（重生成差异——升表须拍板升 '
                  'AIP_TABLE_VER）' % args.out, file=sys.stderr)
            return 1
        print('gen: %s 与 spec 一致（冻结）' % args.out)
        return 0
    with open(args.out, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(text)
    print('gen: %s 写出（rules=%d sha256=%s）'
          % (args.out, len(spec['rules']), digest_hex(spec)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
