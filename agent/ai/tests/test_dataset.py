#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_dataset.py - aikctl dataset 子族单测（L1 棒③，DATA-L1-DESIGN §3）

fixture：临时根下 curated 三天目录（cat_*.parquet + index.parquet，
schema 对齐 aistreamd as_parquet.c:325 tel_cols 11 列）+ telemetry
（raw 层 list 用）；行文本植入脱敏探针串（password=sekret / parent=
1 child=42 / addr=10.0.0.7 / decision_id=4711）。

mock SME：线程内 http.server——GET /export 返回三条记忆（curated:v1
窗内 / curated:v1 窗外 / 非 curated tag），DELETE /memories/{id} 记录
调用（smehttp/routes.c 契约）。

断言组：
  A list raw/curated：行数/日期域/体量汇总行
  B export curated：soft 档导出物必无原文（sekret/42/10.0.0.7）+
    pid 列哈希 + decision_id 例外保持；strict 档 drop；off 档须显式
    且打风险行且保原文；parquet 格式读回核对
  C export corpus：.aikcorp+manifest（sha256/rows/key_ref/since/
    until/redaction/created）；aik-gcm dec 逐字节==同窗 soft jsonl
  D delete：raw 拒绝（TTL 人话）；双发确认门（首发只布防不删/带
    --yes 未布防拒/10s 窗内二发真删+SME 窗内匹配批量 DELETE+索引
    重建）；SME 不可达=拒绝删除（诚实优先裁定）
  E pyarrow 缺席 mock：import 失败=人话+指路 pip install pyarrow，rc=1

前置：pyarrow（缺席=SKIP 退出 0——可选依赖不阻断无箭头宿主）+
agent/ai/aik-gcm 已构建。退出码 0=全过，1=有 FAIL。
"""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.dirname(HERE)                       # agent/ai
AIKCTL = os.path.join(AGENT, 'aikctl', 'aikctl')
GCM = os.path.join(AGENT, 'aik-gcm')

try:
    import pyarrow
    import pyarrow.parquet
except ImportError:
    print('SKIP: pyarrow 缺席（dataset 测试需要；pip install pyarrow）')
    sys.exit(0)

RESULTS = []
SME_DELETED = []
SME_MEMS = []


def check(cond, name, detail=''):
    RESULTS.append((bool(cond), name, detail))
    print(('PASS: ' if cond else 'FAIL: ') + name +
          (('  [' + str(detail) + ']') if (not cond and detail) else ''))


def ts_ns(y, m, d, hh=12):
    return int(datetime(y, m, d, hh, tzinfo=timezone.utc).timestamp()
               ) * 1000000000


def tel_schema():
    return pyarrow.schema([
        ('timestamp_ns', pyarrow.int64()), ('pid', pyarrow.int32()),
        ('tgid', pyarrow.int32()), ('cpu', pyarrow.int16()),
        ('category', pyarrow.int8()), ('event_type', pyarrow.int8()),
        ('severity', pyarrow.int8()), ('data_len', pyarrow.int16()),
        ('data', pyarrow.string()), ('trace_hi', pyarrow.int64()),
        ('trace_lo', pyarrow.int64()),
    ])


def write_tel(path, rows):
    cols = {c: [r.get(c) for r in rows] for c in
            ('timestamp_ns', 'pid', 'tgid', 'cpu', 'category',
             'event_type', 'severity', 'data_len', 'data', 'trace_hi',
             'trace_lo')}
    pyarrow.parquet.write_table(
        pyarrow.Table.from_pydict(cols, schema=tel_schema()), path)


def write_index(path, base, entries):
    cols = {'file': [e[0] for e in entries],
            'date': [e[1] for e in entries],
            'category': [e[2] for e in entries],
            'records': [e[3] for e in entries],
            'start_ts': [e[4] for e in entries],
            'end_ts': [e[5] for e in entries]}
    schema = pyarrow.schema([
        ('file', pyarrow.string()), ('date', pyarrow.string()),
        ('category', pyarrow.int8()), ('records', pyarrow.int64()),
        ('start_ts', pyarrow.int64()), ('end_ts', pyarrow.int64()),
    ])
    pyarrow.parquet.write_table(
        pyarrow.Table.from_pydict(cols, schema=schema), path)


class SmeHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):                      # 静默
        pass

    def do_GET(self):
        if self.path == '/export':
            body = json.dumps({'memories': SME_MEMS}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        mid = self.path.rsplit('/', 1)[-1]
        SME_DELETED.append(mid)
        body = json.dumps({'deleted': mid}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_aikctl(args, env_extra=None, unset=()):
    env = dict(os.environ)
    env.setdefault('AIK_GCM', GCM)
    env['AIKCTL_ARM_DIR'] = env.get('AIKCTL_ARM_DIR', ARM_DIR)
    for k in unset:
        env.pop(k, None)
    if env_extra:
        env.update(env_extra)
    p = subprocess.run([sys.executable, AIKCTL] + args, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr


ARM_DIR = ''


def main():
    global ARM_DIR
    if not os.path.isfile(GCM):
        check(False, 'aik-gcm-built', '%s 缺席——先 make aik-gcm' % GCM)
        return 1
    tmp = tempfile.mkdtemp(prefix='aikds-test-')
    ARM_DIR = os.path.join(tmp, 'arm')
    os.makedirs(ARM_DIR)
    root = os.path.join(tmp, 'root')

    # ---- fixture：curated 三天 + telemetry(raw) 一天 ----
    d1 = os.path.join(root, 'curated', '2026-11-01')
    d2 = os.path.join(root, 'curated', '2026-11-02')
    d3 = os.path.join(root, 'curated', '2026-11-03')
    for d in (d1, d2, d3):
        os.makedirs(d)
    rows_d1 = [{'timestamp_ns': ts_ns(2026, 11, 1), 'pid': 5, 'tgid': 5,
                'cpu': 0, 'category': 1, 'event_type': 0, 'severity': 0,
                'data_len': 20, 'data': '[kern] proc comm pid=9 comm=bash',
                'trace_hi': 0, 'trace_lo': 0}]
    rows_d2 = [
        {'timestamp_ns': ts_ns(2026, 11, 2, 1), 'pid': 42, 'tgid': 42,
         'cpu': 1, 'category': 1, 'event_type': 0, 'severity': 0,
         'data_len': 30,
         'data': '[kern] proc fork parent=1 child=42',
         'trace_hi': 0, 'trace_lo': 0},
        {'timestamp_ns': ts_ns(2026, 11, 2, 2), 'pid': 7, 'tgid': 7,
         'cpu': 2, 'category': 2, 'event_type': 1, 'severity': 1,
         'data_len': 40,
         'data': '[auth] login password=sekret user=alice addr=10.0.0.7',
         'trace_hi': 0, 'trace_lo': 0},
        {'timestamp_ns': ts_ns(2026, 11, 2, 3), 'pid': 0, 'tgid': 0,
         'cpu': 0, 'category': 3, 'event_type': 0, 'severity': 0,
         'data_len': 50,
         'data': '[kern] event decision decision_id=4711 executed=2 '
                 'param=mm.swappiness',
         'trace_hi': 1, 'trace_lo': 2},
    ]
    rows_d3 = [{'timestamp_ns': ts_ns(2026, 11, 3), 'pid': 8, 'tgid': 8,
                'cpu': 0, 'category': 1, 'event_type': 0, 'severity': 0,
                'data_len': 20, 'data': '[kern] proc exit pid=8 code=0',
                'trace_hi': 0, 'trace_lo': 0}]
    write_tel(os.path.join(d1, 'cat_0001.parquet'), rows_d1)
    write_tel(os.path.join(d2, 'cat_0001.parquet'), rows_d2)
    write_tel(os.path.join(d3, 'cat_0001.parquet'), rows_d3)
    write_index(os.path.join(root, 'curated', 'index.parquet'), root, [
        ('cat_0001.parquet', '2026-11-01', 1, 1,
         rows_d1[0]['timestamp_ns'], rows_d1[0]['timestamp_ns']),
        ('cat_0001.parquet', '2026-11-02', 1, 3,
         rows_d2[0]['timestamp_ns'], rows_d2[2]['timestamp_ns']),
        ('cat_0001.parquet', '2026-11-03', 1, 1,
         rows_d3[0]['timestamp_ns'], rows_d3[0]['timestamp_ns']),
    ])
    tdir = os.path.join(root, 'telemetry', '2026-11-02')
    os.makedirs(tdir)
    write_tel(os.path.join(tdir, 'cat_0001.parquet'), rows_d2)
    write_index(os.path.join(root, 'telemetry', 'index.parquet'), root, [
        ('cat_0001.parquet', '2026-11-02', 1, 3,
         rows_d2[0]['timestamp_ns'], rows_d2[2]['timestamp_ns']),
    ])

    # ---- mock SME ----
    ts_in = ts_ns(2026, 11, 2, 1) // 1000000          # epoch ms 窗内
    ts_out = ts_ns(2026, 11, 3, 1) // 1000000
    SME_MEMS.extend([
        {'id': 'mem-in', 'tags': ['curated:v1'],
         'metadata': {'ts': ts_in}},
        {'id': 'mem-out', 'tags': ['curated:v1'],
         'metadata': {'ts': ts_out}},
        {'id': 'mem-other', 'tags': ['kernel_evt'],
         'metadata': {'ts': ts_in}},
    ])
    srv = ThreadingHTTPServer(('127.0.0.1', 0), SmeHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    sme = 'http://127.0.0.1:%d' % srv.server_address[1]

    # corpus 密钥（aik-gcm keygen=0600/32B）
    key = os.path.join(tmp, 'corpus.key')
    subprocess.run([GCM, 'keygen', '--key', key], check=True,
                   stdout=subprocess.DEVNULL)
    envk = {'AIK_CORPUS_KEY': key}
    L = ['dataset', 'list']
    E = ['dataset', 'export']
    D = ['dataset', 'delete']
    win = ['--since', '2026-11-02', '--until', '2026-11-02']
    R = ['--root', root]

    # ================= A list =================
    rc, out, err = run_aikctl(L + ['--layer', 'raw'] + R)
    txt = out.decode()
    check(rc == 0 and 'DATASET_LIST layer=raw files=1 rows=3' in txt
          and 'dates=2026-11-02..2026-11-02' in txt, 'list-raw', txt)
    rc, out, err = run_aikctl(L + ['--layer', 'curated'] + R)
    txt = out.decode()
    check(rc == 0 and 'DATASET_LIST layer=curated files=3 rows=5' in txt
          and 'dates=2026-11-01..2026-11-03' in txt, 'list-curated', txt)

    # ================= B export curated =================
    j1 = os.path.join(tmp, 'soft.jsonl')
    rc, out, err = run_aikctl(E + ['--layer', 'curated'] + win +
                              R + ['--out', j1, '--format', 'jsonl'],
                              env_extra=envk)
    body = open(j1, 'rb').read()
    check(rc == 0 and 'DATASET_EXPORT layer=curated' in out.decode(),
          'export-curated-soft-rc0', err[:100])
    check(b'sekret' not in body and b'10.0.0.7' not in body
          and b'child=42' not in body,
          'export-soft-no-original-text')
    lines = [json.loads(x) for x in body.decode().splitlines()]
    check(len(lines) == 3, 'export-soft-rows-3', str(len(lines)))
    login = [r for r in lines if 'password' in r['data']][0]
    check(login['data'] == '[auth] login password=s*** user=alice '
          'addr=1***', 'export-soft-mask-values', login['data'])
    fork = [r for r in lines if 'fork' in r['data']][0]
    check('parent=h:' in fork['data'] and 'child=h:' in fork['data'],
          'export-soft-pid-hash', fork['data'])
    check(fork['pid'] != 42 and fork['pid'] > 0,
          'export-soft-pidcol-hash', str(fork['pid']))
    dec = [r for r in lines if 'decision' in r['data']][0]
    check('decision_id=4711' in dec['data'],
          'export-soft-decision-id-exception', dec['data'])
    # strict：uid 类/addr/password → "-"；pid 类仍 hash
    j2 = os.path.join(tmp, 'strict.jsonl')
    rc, out, err = run_aikctl(E + ['--layer', 'curated'] + win + R +
                              ['--out', j2, '--format', 'jsonl',
                               '--redact', 'strict'], env_extra=envk)
    body2 = open(j2, 'rb').read()
    lines2 = [json.loads(x) for x in body2.decode().splitlines()]
    login2 = [r for r in lines2 if 'password' in r['data']][0]
    check('password=-' in login2['data'] and 'addr=-' in login2['data'],
          'export-strict-drop', login2['data'])
    comm2 = [r for r in lines2 if 'comm=' in r['data']]
    check(not comm2 or 'comm=-' in comm2[0]['data'],
          'export-strict-comm-drop')
    # off：须显式+风险行+原文保留
    j3 = os.path.join(tmp, 'off.jsonl')
    rc, out, err = run_aikctl(E + ['--layer', 'curated'] + win + R +
                              ['--out', j3, '--format', 'jsonl',
                               '--redact', 'off'], env_extra=envk)
    body3 = open(j3, 'rb').read()
    check(rc == 0 and b'password=sekret' in body3 and
          b'child=42' in body3, 'export-off-keeps-original')
    check('风险提示' in err.decode(), 'export-off-risk-line',
          err.decode()[:80])
    # 窗口外日期不进包
    check(b'2026-11-01' not in body and b'proc comm' not in body
          and b'proc exit' not in body, 'export-window-filter')
    # parquet 格式读回
    p1 = os.path.join(tmp, 'soft.parquet')
    rc, out, err = run_aikctl(E + ['--layer', 'curated'] + win + R +
                              ['--out', p1, '--format', 'parquet'],
                              env_extra=envk)
    t = pyarrow.parquet.read_table(p1)
    check(rc == 0 and t.num_rows == 3 and
          b'sekret' not in json.dumps(t.to_pydict()).encode(),
          'export-parquet-roundread', 'rows=%d' % t.num_rows)

    # ================= C export corpus =================
    c1 = os.path.join(tmp, 'corp')
    rc, out, err = run_aikctl(E + ['--layer', 'corpus'] + win + R +
                              ['--out', c1], env_extra=envk)
    pkg = c1 + '.aikcorp'
    man = pkg + '.manifest.json'
    ok = rc == 0 and os.path.isfile(pkg) and os.path.isfile(man)
    check(ok, 'export-corpus-pkg-manifest', err[:100])
    m = json.load(open(man))
    sha = hashlib.sha256(open(pkg, 'rb').read()).hexdigest()
    check(m.get('sha256') == sha and m.get('rows') == 3
          and m.get('since') == '2026-11-02'
          and m.get('until') == '2026-11-02'
          and m.get('key_ref') == 'keyfile:corpus.key'
          and m.get('redaction') == 'soft'
          and 'created' in m, 'export-corpus-manifest-fields',
          json.dumps(m, ensure_ascii=False)[:120])
    check(open(pkg, 'rb').read(8) == b'AIKCORP1', 'export-corpus-magic')
    pb = open(pkg, 'rb').read()
    check(b'sekret' not in pb, 'export-corpus-no-plaintext-leak')
    # 解密逐字节 == 同窗 soft jsonl（设计 §4 corpus 往返门）
    dec = subprocess.run([GCM, 'dec', '--key', key],
                         input=pb, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    check(dec.returncode == 0 and dec.stdout == open(j1, 'rb').read(),
          'export-corpus-dec-bytes-equal-jsonl',
          'rc=%d len=%d vs %d' % (dec.returncode, len(dec.stdout),
                                  os.path.getsize(j1)))
    # 缺密钥负例：指路 keygen
    rc, out, err = run_aikctl(E + ['--layer', 'corpus'] + win + R +
                              ['--out', os.path.join(tmp, 'nokey'),
                               '--key', os.path.join(tmp, 'absent.key')],
                              unset=('AIK_CORPUS_KEY',))
    check(rc == 1 and b'keygen' in err, 'export-corpus-missing-key-rc1',
          err[:100])

    # ================= D delete =================
    rc, out, err = run_aikctl(D + ['--layer', 'raw'] + win + R +
                              ['--sme-url', sme])
    check(rc == 1 and 'TTL' in err.decode() and '拒绝' in err.decode(),
          'delete-raw-refused', err[:100])
    # 双发确认门：首发只布防
    del SME_DELETED[:]
    rc, out, err = run_aikctl(D + ['--layer', 'curated'] + win + R +
                              ['--sme-url', sme])
    txt = out.decode()
    ok = (rc == 1 and '10 秒内重发' in txt and 'nonce' in txt
          and '行数 3' in txt and 'cat_0001.parquet' in txt
          and os.path.isfile(os.path.join(d2, 'cat_0001.parquet'))
          and not SME_DELETED)
    check(ok, 'delete-first-fire-arm-only', txt[-200:])
    # 未布防的 --yes → 拒绝
    arm_files = os.listdir(ARM_DIR)
    for af in arm_files:                             # 清布防
        os.unlink(os.path.join(ARM_DIR, af))
    rc, out, err = run_aikctl(D + ['--layer', 'curated'] + win + R +
                              ['--yes', '--sme-url', sme])
    check(rc == 1 and '未布防' in err.decode(), 'delete-yes-unarmed',
          err[:80])
    # SME 不可达 → 拒绝且文件不动
    rc, out, err = run_aikctl(D + ['--layer', 'curated'] + win + R +
                              ['--sme-url', 'http://127.0.0.1:1'])
    check(rc == 1 and 'SME 不可达' in err.decode()
          and '拒绝' in err.decode()
          and os.path.isfile(os.path.join(d2, 'cat_0001.parquet')),
          'delete-sme-down-refused', err[:120])
    # 二发真删：布防→立即 --yes
    run_aikctl(D + ['--layer', 'curated'] + win + R + ['--sme-url', sme])
    rc, out, err = run_aikctl(D + ['--layer', 'curated'] + win + R +
                              ['--yes', '--sme-url', sme])
    txt = out.decode()
    ok = (rc == 0 and 'DATASET_DELETE' in txt
          and not os.path.exists(os.path.join(d2, 'cat_0001.parquet'))
          and os.path.isfile(os.path.join(d1, 'cat_0001.parquet'))
          and os.path.isfile(os.path.join(d3, 'cat_0001.parquet'))
          and SME_DELETED == ['mem-in']
          and os.listdir(ARM_DIR) == [])
    check(ok, 'delete-second-fire-executes',
          'rc=%d sme=%s' % (rc, SME_DELETED))
    idx = pyarrow.parquet.read_table(
        os.path.join(root, 'curated', 'index.parquet')).to_pydict()
    check(sorted(idx['date']) == ['2026-11-01', '2026-11-03'],
          'delete-index-rebuilt', str(sorted(set(idx['date']))))

    # ================= E pyarrow 缺席 mock =================
    shim = os.path.join(tmp, 'nopyarrow')
    os.makedirs(shim)
    with open(os.path.join(shim, 'pyarrow.py'), 'w') as f:
        f.write('raise ImportError("mocked absent (test shim)")\n')
    env = dict(os.environ)
    env['PYTHONPATH'] = shim + os.pathsep + env.get('PYTHONPATH', '')
    p = subprocess.run([sys.executable, AIKCTL, 'dataset', 'list',
                        '--layer', 'curated', '--root', root], env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check(p.returncode == 1 and b'pip install pyarrow' in p.stderr
          and b'pyarrow' in p.stderr,
          'pyarrow-absent-rc1-pointway',
          p.stderr.decode()[:120])
    # 纯 stdlib 保持：无 pyarrow 环境下 selftest 仍全绿
    p = subprocess.run([sys.executable, AIKCTL, 'selftest'], env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check(p.returncode == 0 and b'cases=58 ok=58' in p.stdout,
          'stdlib-selftest-without-pyarrow', p.stdout[-40:])

    srv.shutdown()
    fail = sum(1 for okk, _, _ in RESULTS if not okk)
    total = len(RESULTS)
    print('\nTEST_DATASET cases=%d ok=%d fail=%d'
          % (total, total - fail, fail))
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if fail else 0



# ---- E1' card/replay（自主施工：导出自动 card + 影子回放双向判定） ----
def _e1_check():
    import importlib.util as _ilu
    ak_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           '..', 'aikctl', 'aikctl')
    tmp = tempfile.mkdtemp(prefix='e1-')
    try:
        import pyarrow as _pa
        import pyarrow.parquet as _pqp
        ok_all = True
        # ① 影子 parquet：50 净行 + 10 投毒行 → FAIL(<0.95)
        rows = {'data_0': [], 'data_1': [], 'data_2': [], 'data_3': [],
                'data_4': [], 'decision_type': []}
        for i in range(50):
            psi = 5000 if i % 2 else 100
            rows['data_0'].append(1000000)
            rows['data_1'].append(5)
            rows['data_2'].append(psi)
            rows['data_3'].append(0)
            rows['data_4'].append(15)
            rows['decision_type'].append(1 if psi > 409 else 0)
        for i in range(10):                      # 投毒：决策列翻转
            rows['data_0'].append(1000000)
            rows['data_1'].append(5)
            rows['data_2'].append(100)
            rows['data_3'].append(0)
            rows['data_4'].append(15)
            rows['decision_type'].append(2)
        bad = os.path.join(tmp, 'shadow_bad.parquet')
        _pqp.write_table(_pa.table(rows), bad)
        r = subprocess.run([sys.executable, ak_path, 'dataset', 'replay',
                            bad], capture_output=True, text=True)
        RESULTS.append((r.returncode == 1 and 'rate=0.8333' in r.stdout
                        and 'FAIL' in r.stdout, 'e1_replay_poison_fail',
                        r.stdout.strip()[-90:]))
        # ② 净表 → PASS
        for i in range(10):
            for k in rows:
                rows[k].pop()
        clean = os.path.join(tmp, 'shadow_clean.parquet')
        _pqp.write_table(_pa.table(rows), clean)
        r = subprocess.run([sys.executable, ak_path, 'dataset', 'replay',
                            clean], capture_output=True, text=True)
        RESULTS.append((r.returncode == 0
                        and 'rate=1.0000' in r.stdout, 'e1_replay_clean',
                        r.stdout.strip()[-90:]))
        # ③ card：最小 curated 根 → export 自动 .card.json + sha 对拍
        from importlib.machinery import SourceFileLoader as _SFL
        aik = _SFL('e1aikctl', ak_path).load_module()
        day = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        cdir = os.path.join(tmp, 'root', 'curated', day)
        os.makedirs(cdir)
        tel = {c: [0] for c in aik.DATASET_TEL_COLS}
        tel['timestamp_ns'] = [int(datetime.now(timezone.utc).timestamp()
                                   * 10**9)]
        tel['pid'] = [4242]
        tel['tgid'] = [4242]
        tel['data'] = ['k:v e1']
        tel['data_len'] = [6]
        _pqp.write_table(_pa.table(tel),
                         os.path.join(cdir, 'telemetry_0001.parquet'))
        out = os.path.join(tmp, 'e1.jsonl')
        r = subprocess.run([sys.executable, ak_path, 'dataset', 'export',
                            '--layer', 'curated', '--since', day,
                            '--until', day, '--out', out,
                            '--root', os.path.join(tmp, 'root')],
                           capture_output=True, text=True)
        cpath = out + '.card.json'
        okc = (r.returncode == 0 and os.path.isfile(cpath))
        if okc:
            card = json.load(open(cpath))
            h = hashlib.sha256(open(out, 'rb').read()).hexdigest()
            okc = (card.get('schema') == 'aikernel.dataset/card/1'
                   and card.get('rows') == 1
                   and card.get('sha256') == h
                   and card.get('time_window_ns') is not None
                   and card.get('license'))
        RESULTS.append((okc, 'e1_export_card', cpath if okc
                        else r.stdout.strip()[-90:]))
        ok_all = all(okk for okk, _, _ in RESULTS[-3:])
        return ok_all
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_e1_check()


if __name__ == '__main__':
    sys.exit(main())
