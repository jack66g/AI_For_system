#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_pqwrite.py — P-27e aik-pqdump --write 回归（写侧 C 化）

链路：
  1) --schema 写（六类型全谱+边界值+unicode/转义/空串）→ pyarrow
     oracle 逐列逐值全等 + schema 类型面全等 + aik-pqdump 自家读回环
  2) 首行推断（int→INT64/float→DOUBLE/str→STRING）
  3) 空表（0 行）/单行边界；读写往返（JSONL → --write → 再读）
  4) 坏输入人话 rc=1（坏 JSON/未知列/null/超宽度/空输入无 schema）
  5) e2e：aikctl dataset export 真导出（curated fixture 由 --write 自产）
     ——C 后端产物 created_by=as_parquet 证路 + oracle；AIK_PQDUMP 指空
     强制 pyarrow 回退路同值对拍
  6) aikctl._rebuild_curated_index（模块级直调）C 写 index.parquet + oracle

L1 需 pyarrow（oracle）；aikctl 位于 ../../aikctl/aikctl（仓内布局）。
"""
import calendar
import datetime
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DUMP = os.environ.get('AIK_PQDUMP') or os.path.join(ROOT, 'aik-pqdump')
AIKCTL = os.path.join(os.path.dirname(ROOT), 'aikctl', 'aikctl')

P = 0
F = 0

# 六类型列谱（边界值+unicode+转义+空串）
SPEC = ('i8:INT8,i16:INT16,i32:INT32,i64:INT64,dbl:DOUBLE,s:STRING')
ROWS = [
    {'i8': -128, 'i16': -32768, 'i32': -2147483648, 'i64': -9223372036854775808,
     'dbl': -1.5e-300, 's': ''},
    {'i8': 127, 'i16': 32767, 'i32': 2147483647, 'i64': 9223372036854775807,
     'dbl': 0.5, 's': '中文引号"反斜杠\\换行\n制表\t'},
    {'i8': 0, 'i16': 0, 'i32': 0, 'i64': 0,
     'dbl': 3.141592653589793, 's': 'emoji😀snow☃'},
    {'i8': 1, 'i16': 1, 'i32': 1, 'i64': 1,
     'dbl': 1e300, 's': 'plain ascii'},
]
PA_TY = {'INT8': 'int8', 'INT16': 'int16', 'INT32': 'int32',
         'INT64': 'int64', 'DOUBLE': 'double', 'STRING': 'string'}


def ck(cond, desc):
    global P, F
    if cond:
        P += 1
        print('  ok  ', desc)
    else:
        F += 1
        print('  FAIL', desc)


def write_c(out, jsonl_bytes, schema=SPEC, stdin=True):
    """跑 aik-pqdump --write（stdin 或文件实参两路都覆盖）"""
    if stdin:
        return subprocess.run([DUMP, '--write', '--out', out,
                               '--schema', schema],
                              input=jsonl_bytes, capture_output=True)
    fin = out + '.in.jsonl'
    with open(fin, 'wb') as fh:
        fh.write(jsonl_bytes)
    return subprocess.run([DUMP, '--write', '--out', out, '--schema', schema,
                           fin], capture_output=True)


def main():
    import pyarrow
    import pyarrow.parquet as pq  # oracle（缺席=测试环境问题非产品问题）

    tmp = tempfile.mkdtemp(prefix='pqwrite-t-')
    try:
        jsonl = ''.join(json.dumps(r, ensure_ascii=False) + '\n'
                        for r in ROWS).encode('utf-8')
        jsonl_esc = ''.join(json.dumps(r, ensure_ascii=True) + '\n'
                            for r in ROWS).encode('utf-8')

        # ---- 1) --schema 写：oracle + 自家读回环 ----
        for tag, blob, use_stdin in (('stdin', jsonl, True),
                                     ('file', jsonl, False),
                                     ('ascii-esc', jsonl_esc, True)):
            out = os.path.join(tmp, 'w-%s.parquet' % tag)
            r = write_c(out, blob, stdin=use_stdin)
            ck(r.returncode == 0 and b'wrote rows=' in r.stdout,
               '--write %s rc=0 + 摘要行' % tag)
            if r.returncode != 0:
                print(r.stderr.decode('utf-8', 'replace'))
                continue
            gold = pq.read_table(out).to_pydict()
            want = {k: [row[k] for row in ROWS] for k in ROWS[0]}
            ck(set(gold) == set(want),
               '%s oracle 列集一致（%d 列）' % (tag, len(want)))
            bad = sum(
                1 for k in want for a, b in zip(gold[k], want[k])
                if a != b and not (isinstance(a, float)
                                   and isinstance(b, float) and a == b))
            ck(bad == 0, '%s oracle 逐列逐值全等（%d 值）'
               % (tag, sum(len(v) for v in want.values())))
            # schema 类型面
            names = [p.split(':')[0] for p in SPEC.split(',')]
            tys = [p.split(':')[1] for p in SPEC.split(',')]
            schema_ok = all(
                str(pq.read_table(out).schema.field(n).type) == PA_TY[t]
                for n, t in zip(names, tys))
            ck(schema_ok, '%s oracle schema 类型面（i8/i16/i32/i64/double/'
               'string）' % tag)
            # 自家读者闭环（--bycol）
            mine = json.loads(subprocess.run(
                [DUMP, '--bycol', out], capture_output=True,
                check=True).stdout)
            ck(mine == want, '%s aik-pqdump 读回闭环（--bycol 全等）' % tag)
            # 自家读者闭环（行式 JSONL）
            lines = subprocess.run([DUMP, out], capture_output=True,
                                   check=True).stdout.decode('utf-8')
            got_rows = [json.loads(ln) for ln in
                        lines.splitlines() if ln.strip()]
            ck(got_rows == ROWS, '%s aik-pqdump 读回闭环（JSONL 行式全等）'
               % tag)

        # ---- 2) 首行推断 ----
        out = os.path.join(tmp, 'infer.parquet')
        inf_rows = [{'n': 42, 'f': 2.5, 's': 'x'},
                    {'n': -7, 'f': -0.25, 's': '中文'}]
        r = subprocess.run(
            [DUMP, '--write', '--out', out],
            input=''.join(json.dumps(x) + '\n' for x in
                          inf_rows).encode('utf-8'),
            capture_output=True)
        ck(r.returncode == 0, '推断模式 rc=0')
        if r.returncode == 0:
            tbl = pq.read_table(out)
            ck(str(tbl.schema.field('n').type) == 'int64' and
               str(tbl.schema.field('f').type) == 'double' and
               str(tbl.schema.field('s').type) == 'string',
               '推断类型 int64/double/string')
            ck(tbl.to_pydict() == {k: [x[k] for x in inf_rows]
                                   for k in inf_rows[0]},
               '推断模式 oracle 全等')

        # ---- 3) 空表 / 单行 ----
        out = os.path.join(tmp, 'empty.parquet')
        r = write_c(out, b'', schema=SPEC)
        ck(r.returncode == 0, '空表写 rc=0')
        tbl = pq.read_table(out)
        ck(tbl.num_rows == 0 and len(tbl.schema) == 6 and
           str(tbl.schema.field('i8').type) == 'int8',
           '空表 oracle（0 行 6 列 schema 保真）')
        mine = json.loads(subprocess.run([DUMP, '--bycol', out],
                                         capture_output=True,
                                         check=True).stdout)
        ck(mine == {k: [] for k in ROWS[0]}, '空表自家读回（0 行列集在）')
        out = os.path.join(tmp, 'one.parquet')
        r = write_c(out, json.dumps(ROWS[1]) .encode() + b'\n')
        ck(r.returncode == 0 and
           pq.read_table(out).num_rows == 1 and
           pq.read_table(out).to_pydict() == {k: [ROWS[1][k]]
                                              for k in ROWS[1]},
           '单行边界 oracle')

        # ---- 4) 读写往返：读 JSONL → 再写 → 再读 ----
        src = os.path.join(tmp, 'w-stdin.parquet')
        mid = subprocess.run([DUMP, src], capture_output=True,
                             check=True).stdout
        out = os.path.join(tmp, 'roundtrip.parquet')
        r = subprocess.run([DUMP, '--write', '--out', out, '--schema', SPEC],
                           input=mid, capture_output=True)
        ck(r.returncode == 0 and
           pq.read_table(out).to_pydict() ==
           pq.read_table(src).to_pydict(),
           '读写往返全等（dump→write→oracle）')

        # ---- 5) 坏输入人话 rc=1 ----
        cases = (
            ('bad-json', b'{"i8": 1,\n', SPEC),
            ('null-value', b'{"i8": null}\n', SPEC),
            ('unknown-col', b'{"nope": 1}\n', SPEC),
            ('width-overflow', b'{"i8": 128}\n', SPEC),
            ('float-into-int', b'{"i8": 1.5}\n', SPEC),
            ('no-schema-empty', b'', None),
            ('bool-value', b'{"i8": true}\n', SPEC),
        )
        for tag, blob, spec in cases:
            cmd = [DUMP, '--write', '--out',
                   os.path.join(tmp, 'bad-%s.parquet' % tag)]
            if spec:
                cmd += ['--schema', spec]
            r = subprocess.run(cmd, input=blob, capture_output=True)
            ck(r.returncode == 1 and b'aik-pqdump:' in r.stderr,
               '坏输入 %s → 人话 rc=1' % tag)
        r = subprocess.run([DUMP, '--write'], capture_output=True)
        ck(r.returncode == 1 and b'aik-pqdump:' in r.stderr,
           '缺 --out → 人话 rc=1')

        # ---- 6) e2e：aikctl dataset export（真导出，C 后端路） ----
        if not (os.path.isfile(AIKCTL) and os.access(AIKCTL, os.R_OK)):
            ck(False, 'aikctl 在位（%s）' % AIKCTL)
        else:
            btime = 0
            try:
                with open('/proc/stat') as fh:
                    for ln in fh:
                        if ln.startswith('btime '):
                            btime = int(ln.split()[1])
                            break
            except OSError:
                pass
            today = datetime.datetime.now(datetime.timezone.utc).date()
            day0 = calendar.timegm((today.year, today.month, today.day,
                                    0, 0, 0))
            # 墙钟 ns 落今日（行级过滤口径同 _ts_wall_ns：单调面平移 btime）
            wall = lambda k: (day0 + k) * 1000000000          # noqa: E731
            mono = lambda k: wall(k) - btime * 1000000000      # noqa: E731
            data_root = os.path.join(tmp, 'root')
            day_dir = os.path.join(data_root, 'curated',
                                   today.isoformat())
            os.makedirs(day_dir)
            tcols = ('timestamp_ns', 'pid', 'tgid', 'cpu', 'category',
                     'event_type', 'severity', 'data_len', 'data',
                     'trace_hi', 'trace_lo')
            frows = [
                {'timestamp_ns': mono(3600), 'pid': 4242, 'tgid': 4242,
                 'cpu': 3, 'category': 1, 'event_type': 2, 'severity': 1,
                 'data_len': len('evt 中文 one'.encode()), 'data': 'evt 中文 one',
                 'trace_hi': 0, 'trace_lo': 77},
                {'timestamp_ns': mono(7200), 'pid': 1, 'tgid': 1,
                 'cpu': 0, 'category': 1, 'event_type': 5, 'severity': 0,
                 'data_len': len('evt "two" \\ ok'.encode()),
                 'data': 'evt "two" \\ ok', 'trace_hi': 0, 'trace_lo': 88},
                {'timestamp_ns': mono(60), 'pid': 999999, 'tgid': 999999,
                 'cpu': 7, 'category': 1, 'event_type': 9, 'severity': 2,
                 'data_len': len('three'.encode()), 'data': 'three',
                 'trace_hi': 1, 'trace_lo': 2},
            ]
            fspec = ('timestamp_ns:INT64,pid:INT32,tgid:INT32,cpu:INT16,'
                     'category:INT8,event_type:INT8,severity:INT8,'
                     'data_len:INT16,data:STRING,trace_hi:INT64,'
                     'trace_lo:INT64')
            fjsonl = ''.join(json.dumps({c: r[c] for c in tcols},
                                        ensure_ascii=False) + '\n'
                             for r in frows).encode('utf-8')
            fpq = os.path.join(day_dir, 'sched_0000.parquet')
            r = subprocess.run([DUMP, '--write', '--out', fpq,
                                '--schema', fspec],
                               input=fjsonl, capture_output=True)
            ck(r.returncode == 0, 'curated fixture 由 --write 自产 rc=0')

            def run_export(out, env_dump, fmt='parquet'):
                env = dict(os.environ, AIK_PQDUMP=env_dump)
                return subprocess.run(
                    [sys.executable, AIKCTL, 'dataset', 'export',
                     '--layer', 'curated', '--since', today.isoformat(),
                     '--until', today.isoformat(), '--out', out,
                     '--format', fmt, '--redact', 'off',
                     '--root', data_root],
                    capture_output=True, env=env)

            outc = os.path.join(tmp, 'export-c.parquet')
            r = run_export(outc, DUMP)
            ck(r.returncode == 0 and b'DATASET_EXPORT' in r.stdout,
               'e2e export（C 路）rc=0')
            if r.returncode == 0:
                blob = open(outc, 'rb').read()
                ck(b'aistreamd as_parquet 1.0' in blob,
                   'C 路实证：footer created_by=as_parquet（非 pyarrow）')
                gold = pq.read_table(outc).to_pydict()
                exp_rows = sorted(frows, key=lambda x: x['timestamp_ns'])
                want = {c: [x[c] for x in exp_rows] for c in tcols}
                ck(set(gold) == set(want) and all(
                    gold[c] == want[c] for c in want),
                   'e2e export（C 路）oracle 全等（%d 行 %d 列）'
                   % (len(exp_rows), len(tcols)))
                # 回退路对拍：AIK_PQDUMP 指空 → pyarrow 全程
                outp = os.path.join(tmp, 'export-py.parquet')
                r2 = run_export(outp, os.path.join(tmp, 'no-such-pqdump'))
                ck(r2.returncode == 0 and
                   b'parquet-cpp' in open(outp, 'rb').read(),
                   'e2e export（强制 pyarrow 回退路）rc=0 + created_by')
                if r2.returncode == 0:
                    g2 = pq.read_table(outp).to_pydict()
                    ck(g2 == gold, '两后端产物 oracle 级一致（逐列逐值）')
                # jsonl 格式（无写后端参与）回归
                outj = os.path.join(tmp, 'export.jsonl')
                r3 = run_export(outj, DUMP, fmt='jsonl')
                jrows = [json.loads(ln) for ln in
                         open(outj, encoding='utf-8').read().splitlines()
                         if ln.strip()]
                ck(r3.returncode == 0 and jrows == exp_rows,
                   'e2e export jsonl 格式行内容全等')

            # ---- 7) _rebuild_curated_index 模块直调（C 写 index） ----
            loader = importlib.machinery.SourceFileLoader('aikctl_test',
                                                          AIKCTL)
            spec = importlib.util.spec_from_file_location(
                'aikctl_test', AIKCTL, loader=loader)
            mod = importlib.util.module_from_spec(spec)
            loader.exec_module(mod)
            os.environ['AIK_PQDUMP'] = DUMP
            mod._rebuild_curated_index(data_root)
            ipath = os.path.join(data_root, 'curated', 'index.parquet')
            idx = pq.read_table(ipath).to_pydict()
            ts = [r['timestamp_ns'] for r in exp_rows]
            want_idx = {'file': ['sched_0000.parquet'],
                        'date': [today.isoformat()],
                        'category': [1], 'records': [len(exp_rows)],
                        'start_ts': [min(ts)], 'end_ts': [max(ts)]}
            ck(idx == want_idx, '_rebuild_curated_index（C 写）oracle 全等')
            mine = json.loads(subprocess.run(
                [DUMP, '--bycol', ipath], capture_output=True,
                check=True).stdout)
            ck(mine['file'] == want_idx['file'] and
               mine['records'] == want_idx['records'],
               'index 自家读回闭环')

        print('test_pqwrite: pass=%d fail=%d => %s'
              % (P, F, 'PASS' if F == 0 else 'FAIL'))
        return 1 if F else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
