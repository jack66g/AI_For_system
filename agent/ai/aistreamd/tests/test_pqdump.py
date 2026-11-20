#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_pqdump.py — P-27 aik-pqdump 回归（oracle 对照+fuzz+CLI 面）

链路：tests/pq_dump 向量驱动产 telemetry fixture（as_parquet.c 写入器
真产物）→ aik-pqdump --bycol 解出 → pyarrow oracle 逐列逐值全等 →
坏文件 fuzz 人话 rc=1 → --schema/--limit 面。L1 需 pyarrow（oracle）。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DUMP = os.environ.get('AIK_PQDUMP') or os.path.join(ROOT, 'aik-pqdump')
DRIVER = os.path.join(HERE, 'pq_dump')
VEC = os.path.join(HERE, 'fixtures', 'pqdump_fixture.vec')

P = 0
F = 0


def ck(cond, desc):
    global P, F
    if cond:
        P += 1
        print('  ok  ', desc)
    else:
        F += 1
        print('  FAIL', desc)


def main():
    import pyarrow.parquet as pq  # oracle（缺席=测试环境问题非产品问题）

    tmp = tempfile.mkdtemp(prefix='pqdump-t-')
    root = os.path.join(tmp, 'root')
    try:
        # 1) fixture 生成（真写入器）
        r = subprocess.run([DRIVER, root, VEC], capture_output=True)
        ck(r.returncode == 0, 'pq_dump 向量驱动产 fixture rc=0')
        pqs = []
        for dp, _, fs in os.walk(root):
            for f in fs:
                if f.endswith('.parquet'):
                    pqs.append(os.path.join(dp, f))
        ck(len(pqs) >= 1, 'fixture parquet 生成（%d 件）' % len(pqs))
        if not pqs:
            return 1

        path = pqs[0]

        # 2) oracle 全等
        mine = json.loads(subprocess.run(
            [DUMP, '--bycol', path], capture_output=True,
            check=True).stdout)
        gold = pq.read_table(path).to_pydict()
        ck(set(mine) == set(gold), '列集一致（%d 列）' % len(gold))
        bad = 0
        for c in gold:
            g, m = gold[c], mine.get(c, [])
            if len(g) != len(m):
                bad += 1
                continue
            for gv, mv in zip(g, m):
                if isinstance(gv, bytes):
                    ok = mv == gv.decode('utf-8', 'replace')
                elif isinstance(gv, float):
                    ok = float(mv) == gv
                else:
                    ok = gv == mv
                bad += 0 if ok else 1
        ck(bad == 0, 'oracle 逐列逐值全等（%d 值）'
           % sum(len(v) for v in gold.values()))

        # 3) schema/limit 面
        r = subprocess.run([DUMP, '--schema', path],
                           capture_output=True, text=True)
        ck(r.returncode == 0 and 'num_rows=' in r.stdout,
           '--schema 概要')
        nrows = int(r.stdout.split('num_rows=')[1].split()[0])
        want = min(2, nrows)
        r = subprocess.run([DUMP, '--limit', '2', path],
                           capture_output=True, text=True)
        ck(r.returncode == 0 and
           len(r.stdout.strip().splitlines()) == want,
           '--limit 2 行（nrows=%d 期望 %d）' % (nrows, want))

        # 4) fuzz（截断/坏头/坏尾）人话 rc=1
        d = open(path, 'rb').read()
        for tag, blob in (
            ('trunc', d[:len(d) // 2]),
            ('badmagic', b'XXXX' + d[4:]),
            ('badfooter', d[:-9] + b'\xff\xff\xff\xff' + d[-5:]),
        ):
            fp = os.path.join(tmp, 'fz-%s.parquet' % tag)
            open(fp, 'wb').write(blob)
            r = subprocess.run([DUMP, fp], capture_output=True)
            ck(r.returncode == 1 and b'aik-pqdump:' in r.stderr,
               'fuzz %s → 人话 rc=1' % tag)

        print('test_pqdump: pass=%d fail=%d => %s'
              % (P, F, 'PASS' if F == 0 else 'FAIL'))
        return 1 if F else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
