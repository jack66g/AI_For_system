#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L1 数据三层台架（DATA-L1-DESIGN §4；run_all 第 65 门）。

default（非 root，进门）三账户，判据按设计册 §4 冻结（禁调期望凑绿）：
  ①评分/promotion（账户 S）：AI_MOCK_PROTO=2 + SME_URL 死端口起
    aistreamd 短跑（conf 全 mktemp 临时根，FLUSH_ROWS=1 即时落盘），
    tests/ai_inject 灌混合 fixture 流（25 新异 policy + 5 device
    跨 category + 8 重复行=同 digest 再灌）→ pyarrow 断言 telemetry
    v3 恰 13 列（value/flags 尾列在，缺席=FAIL 不跳过）+ promotion
    率=curated 行数/总行数落 5-15% 带内（权重默认 0.45/0.25/0.05/
    0.15/0.10/0.10、带 [0.50,0.95]：事件路首行 0.45+0.10*1=0.55、
    次行 0.45+0.10*0.5=0.50 恰入带，其后稀有衰减至 <0.50——fixture
    使带内成立=合法调 fixture）+ flags 缺失位如实（事件路缺反差/
    纠正/代价/置信度原料）+ curated/<UTC 今日>/ 落盘 + SME 死端口
    失败计数诚实（终笔 "value final" journal 行 + stats sme_fail/
    ring_used）。
  ②保留（账户 R）：预植 fixture 目录树（2020-01-01 与 锚-9d TTL 过期、
    锚-8d ai 目录 RETENTION_DAYS_AI=30 覆盖宁留、锚-6d 带内、2020-06-01
    异物保护、curated 2020-02-02 过 curated TTL 90d、curated 锚-7d 证
    raw TTL 不误伤；日期按保留锚=boot 日构造——as_pq_retain_root_cfg
    的「今天」取 as_pq_day_from_ts(0,btime)=boot 当日，宿主 uptime 会
    平移 age，实测在案）→ AS_ONCE=1 单事件短跑（冒烟法：单事件即触发
    flush→retain）→ 老目录删/当天在/curated 独立 + journal retain 行。
  ③corpus（账户 C）：pyarrow 造 curated fixture（cat_*.parquet=
    aikctl dataset 读契约——test_dataset.py 同款；行文本植
    password=sekret/token=…/decision_id=4711 探针）→ aikctl dataset
    list/export：soft 档导出物必无原文（password=s***/token=t***、
    decision_id 例外原样、pid 列哈希）；curated parquet 双格式；
    corpus 层 .aikcorp+manifest 双产物（sha256/rows/key_ref/since/
    until/redaction 复核）→ aik-gcm dec 逐字节往返等+篡改负例
    （tag 败 rc=4）→ delete 双发确认门（raw 拒/首发只布防未删/
    --yes 10s 内真删+文件消失+窗外不误删/未布防拒/删后 index 重建）
    + mock SME 侧 curated:v1 窗内恰一匹配批量 DELETE 断言。
    末项 C13=真产物集成探针：对账户① aistreamd 实产根（ai_*.parquet
    命名+真实 index）跑 dataset export——现树如实红（aikctl _cat_files
    只认 cat_* 前缀，aistreamd 写 <cat名>_NNNN.parquet；探勘实证
    rows=0）。期望冻结不因工树态调低：aikctl 侧修读契约后转绿
    （c3 台账户①「如实红」同款纪律；修法属 aikctl 文件=棒④只读）。

灌事件机制口径（验尸在案，as_streams.c:1075）：dispatch 一次一
recv=一 netlink 数据报=一事件，AS_ONCE 单轮 poll 至多消化一报——
多行 fixture 无法在 AS_ONCE 内落齐；账户①改起停式短跑（ai_inject
全部落账后 SIGTERM），退出走与 AS_ONCE 完全相同的 graceful 路径
（flush→retain→终笔 stats→value final 台账行）；AS_ONCE 留给账户②
（单事件=恰好一报，冒烟法同款）。判据零变化。

前置自检（缺=如实 FAIL 不跳过）：pyarrow、aikctl、aik-gcm、
aistreamd、ai_inject。禁止 import c1/c2/c3 台架模块（run_cmd 环境
钉教训）——本台架自带助手。
输出：末行 `L1_BENCH ok=N fail=M`（账户行 L1_ACCOUNTS 随前）。
退出码：零 fail→0 否则 1。
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import pyarrow
    import pyarrow.parquet
except ImportError:                                 # preflight 如实 FAIL
    pyarrow = None

INJECT_TIMEOUT = 30
DAEMON_TIMEOUT = 25
AIKCTL_TIMEOUT = 120
DAY = timedelta(days=1)

# telemetry v3 schema（as_parquet.c:332 tel_cols 13 列——冻结契约）
TEL_COLS = ('timestamp_ns', 'pid', 'tgid', 'cpu', 'category', 'event_type',
            'severity', 'data_len', 'data', 'trace_hi', 'trace_lo',
            'value', 'flags')
# as_value.h AS_VF_* 位域（事件路原料缺失位断言用）
VF_PROMOTED, VF_DEC, VF_MISS_NOV = 1, 2, 4
VF_MISS_DIV, VF_MISS_CORR, VF_MISS_COST, VF_MISS_CONF = 8, 16, 32, 64
VF_MISS_RARE = 128

N_POLICY, N_DEVICE, N_DUP = 25, 5, 8                # 账户① fixture 定数
N_ROWS = N_POLICY + N_DEVICE                        # 落盘行数（重复被去重）


# ------------------------------------------------------------- 助手 ----
def run_cmd(cmd, timeout, env=None):
    cp = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
    return (cp.returncode, cp.stdout.decode('utf-8', 'replace'),
            cp.stderr.decode('utf-8', 'replace'))


def write_file(path, data, mode=0o644):
    with open(path, 'wb') as fh:
        fh.write(data)
    os.chmod(path, mode)


def utc_today():
    return datetime.now(timezone.utc).date()


def boot_anchor_day():
    """aistreamd 保留策略的「今天」锚=启动读 /proc/stat btime 的
    boot 日（as_pq_retain_root_cfg 以 as_pq_day_from_ts(0,btime) 取
    今日——ts=0 落 btime 当日；实测在案）。fixture 日期须按此锚构造，
    否则宿主 uptime 会平移全部 age。缺 /proc/stat → 退真今天。"""
    try:
        with open('/proc/stat') as fh:
            for ln in fh:
                if ln.startswith('btime '):
                    return datetime.fromtimestamp(
                        int(ln.split()[1]), timezone.utc).date()
    except (OSError, ValueError, IndexError):
        pass
    return utc_today()


def ts_ns_at(day, hour=12):
    return int(datetime(day.year, day.month, day.day, hour,
                        tzinfo=timezone.utc).timestamp()) * 1000000000


def read_stats(path):
    st = {}
    try:
        with open(path, 'r', errors='replace') as fh:
            for ln in fh:
                if '=' in ln and not ln.startswith('#'):
                    k, v = ln.strip().split('=', 1)
                    st[k] = v
    except OSError:
        pass
    return st


def stat_int(path, key):
    try:
        return int(read_stats(path).get(key, '0') or '0')
    except ValueError:
        return 0


def wait_stat(path, key, expect, timeout, proc=None):
    """轮询 stats 文件至 key 值 >=expect；proc 给出则周期 SIGUSR1 踢写。"""
    deadline = time.monotonic() + timeout
    last_kick = 0.0
    while time.monotonic() < deadline:
        if stat_int(path, key) >= expect:
            return True
        if proc is not None and time.monotonic() - last_kick > 0.2:
            try:
                proc.send_signal(signal.SIGUSR1)
            except OSError:
                pass
            last_kick = time.monotonic()
        time.sleep(0.05)
    return stat_int(path, key) >= expect


def inject(ai_inject, stats, count, base, prefix, category):
    """tests/ai_inject <stats_file> <count> [base_id] [prefix] [category]
    （参数序照 ai_inject.c 头注核实在案）。"""
    return run_cmd([ai_inject, stats, str(count), str(base), prefix,
                    str(category)], INJECT_TIMEOUT)


def base_conf(root, stats, pid, lock, **over):
    """aistreamd 短跑 conf：全临时根+mock 通道+SME 死端口（账户通用）。"""
    c = {
        'SME_URL': 'http://127.0.0.1:1',
        'SME_RETRY_SEC': '5',
        'RATE_PER_MIN': '100000',
        'DAILY_MAX': '1000000',
        'STREAM_DAILY_MAX': '1000000',
        'DEDUP_WINDOW_MS': '60000',
        'STATS_INTERVAL_SEC': '1',
        'ENABLE_EVENT': '1',
        'ENABLE_PROC': '0', 'ENABLE_NET': '0', 'ENABLE_UEVENT': '0',
        'ENABLE_NFLOG': '0', 'ENABLE_TASKSTATS': '0',
        'AI_MOCK_PROTO': '2',
        'PARQUET_ENABLED': '1',
        'PARQUET_DIR': root,
        'PARQUET_FLUSH_ROWS': '1',
        'STATS_FILE': stats, 'PID_FILE': pid, 'LOCK_FILE': lock,
    }
    c.update(over)
    return ''.join('%s=%s\n' % kv for kv in sorted(c.items())).encode()


def run_daemon(aistreamd, conf_path, log_path, once):
    """起 aistreamd 短跑（once=AS_ONCE 单轮）；stdout/stderr→journal 日志。"""
    env = dict(os.environ)
    if once:
        env['AS_ONCE'] = '1'
    else:
        env.pop('AS_ONCE', None)
    logf = open(log_path, 'wb')
    proc = subprocess.Popen([aistreamd, '--conf', conf_path], stdout=logf,
                            stderr=subprocess.STDOUT, env=env)
    return proc, logf


def stop_daemon(proc):
    """SIGTERM 优雅退出（与 AS_ONCE 同一 graceful 路径）；超时兜底 kill。"""
    if proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(DAEMON_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)


def wait_portid(stats_path, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stat_int(stats_path, 'nl_ai_portid') > 0:
            return True
        time.sleep(0.005)
    return stat_int(stats_path, 'nl_ai_portid') > 0


def is_data_file(nm):
    """布局数据文件（as_parquet.c is_tel_data_file 语义：*_*.parquet
    且非 index）——ai_*/cat_* 两命名通吃。"""
    return (nm.endswith('.parquet') and '_' in nm
            and nm != 'index.parquet')


def read_day_rows(pq, root, sub, day):
    """<root>/<sub>/<day>/ 内布局数据文件逐文件读行（按 ts 稳定排序）。"""
    ddir = os.path.join(root, sub, day.isoformat())
    rows = []
    if not os.path.isdir(ddir):
        return rows
    for name in sorted(os.listdir(ddir)):
        if is_data_file(name):
            cols = pq.read_table(os.path.join(ddir, name)).to_pydict()
            for i in range(len(cols.get('timestamp_ns', []))):
                rows.append({c: cols[c][i] for c in cols})
    rows.sort(key=lambda r: r['timestamp_ns'])
    return rows


def tel_schema13():
    return pyarrow.schema([
        ('timestamp_ns', pyarrow.int64()), ('pid', pyarrow.int32()),
        ('tgid', pyarrow.int32()), ('cpu', pyarrow.int16()),
        ('category', pyarrow.int8()), ('event_type', pyarrow.int8()),
        ('severity', pyarrow.int8()), ('data_len', pyarrow.int16()),
        ('data', pyarrow.string()), ('trace_hi', pyarrow.int64()),
        ('trace_lo', pyarrow.int64()), ('value', pyarrow.float64()),
        ('flags', pyarrow.int64()),
    ])


def write_tel13(path, rows):
    cols = {c: [r.get(c, 0) for r in rows] for c in TEL_COLS}
    pyarrow.parquet.write_table(
        pyarrow.Table.from_pydict(cols, schema=tel_schema13()), path)


def write_idx(path, entries):
    """index.parquet 六列（file=裸文件名——aikctl list 读契约）。"""
    cols = {'file': [e['file'] for e in entries],
            'date': [e['date'] for e in entries],
            'category': [e['category'] for e in entries],
            'records': [e['records'] for e in entries],
            'start_ts': [e['start_ts'] for e in entries],
            'end_ts': [e['end_ts'] for e in entries]}
    schema = pyarrow.schema([
        ('file', pyarrow.string()), ('date', pyarrow.string()),
        ('category', pyarrow.int8()), ('records', pyarrow.int64()),
        ('start_ts', pyarrow.int64()), ('end_ts', pyarrow.int64()),
    ])
    pyarrow.parquet.write_table(
        pyarrow.Table.from_pydict(cols, schema=schema), path)


# ------------------------------------------------- 账户① 评分/promotion ----
def account_score(td, aistreamd, ai_inject):
    """①：混合 fixture 流→13 列/promotion 带内/flags/curated/SME 诚实。
    → (ok, fail)。"""
    ok = fail = 0

    def record(sid, label, bad):
        nonlocal ok, fail
        if bad:
            fail += 1
            print('FAIL %s %-18s %s' % (sid, label,
                                        ' | '.join(bad)[:240]))
        else:
            ok += 1
            print('ok   %s %-18s' % (sid, label))

    root = os.path.join(td, 's1-root')
    os.makedirs(root)
    stats = os.path.join(td, 's1.stats')
    logp = os.path.join(td, 's1.log')
    conf = os.path.join(td, 's1.conf')
    write_file(conf, base_conf(root, stats, os.path.join(td, 's1.pid'),
                               os.path.join(td, 's1.lock')))

    proc, logf = run_daemon(aistreamd, conf, logp, once=False)
    try:
        record('S1', 'daemon 起活(portid)',
               [] if wait_portid(stats, 10) else ['10s 无 nl_ai_portid'])
        # 混合 fixture：25 新异 policy（decision_id/param 唯一）→
        # 5 device（跨 ai_nl category，行文本 action=probe dev=…）→
        # 8 重复行（同 base/prefix=同 digest→去重窗内 suppress）
        seq = [(N_POLICY, 1000, 'l1np', 1, 'policy'),
               (N_DEVICE, 3000, 'l1dv', 3, 'device'),
               (N_DUP, 1000, 'l1np', 1, 'dup')]
        for i, (count, base, prefix, cat, tag) in enumerate(seq):
            rc, _o, err = inject(ai_inject, stats, count, base, prefix, cat)
            record('S%d' % (i + 2), 'inject %s×%d(cat=%d)' % (tag, count,
                                                              cat),
                   [] if rc == 0 else ['ai_inject rc=%d: %.120s'
                                       % (rc, err)])
        got = sum(s[0] for s in seq)
        bad = ([] if (wait_stat(stats, 'event.received', got, 15, proc)
                      and wait_stat(stats, 'event.filtered_dedup', N_DUP,
                                    15, proc))
               else ['received=%d(期 %d) dedup=%d(期 %d)'
                     % (stat_int(stats, 'event.received'), got,
                        stat_int(stats, 'event.filtered_dedup'), N_DUP)])
        record('S5', 'fixture 全落账+去重', bad)
    finally:
        stop_daemon(proc)
        logf.close()
    with open(logp, 'r', errors='replace') as fh:
        journal = fh.read()
    today = utc_today()

    # S6：telemetry v3 恰 13 列（value/flags 尾列在；缺席=FAIL 不跳过）
    rows, names = [], []
    try:
        rows = read_day_rows(pyarrow.parquet, root, 'telemetry', today)
        sdir = os.path.join(root, 'telemetry', today.isoformat())
        for nm in sorted(os.listdir(sdir)) if os.path.isdir(sdir) else []:
            if is_data_file(nm):
                names = pyarrow.parquet.read_schema(
                    os.path.join(sdir, nm)).names
                break
    except Exception as e:                           # noqa: BLE001 如实记账
        record('S6', 'telemetry v3 13 列', ['%s: %s' % (type(e).__name__, e)])
        names = []
    else:
        record('S6', 'telemetry v3 13 列',
               [] if tuple(names) == TEL_COLS
               else ['列集=%r（期 13 列含 value/flags）' % (names,)])

    # S7：promotion 率=curated 行数/总行数 ∈ [5%,15%]（fixture 定数
    # 30 行/首两行入带=6.7%——权重默认下的确定性函数）
    cur_rows = read_day_rows(pyarrow.parquet, root, 'curated', today)
    rate = (len(cur_rows) / len(rows)) if rows else 0.0
    record('S7', 'promotion 率带内',
           ([] if (len(rows) == N_ROWS and len(cur_rows) == 2
                   and 0.05 <= rate <= 0.15)
            else ['rows=%d(期 %d) curated=%d(期 2) rate=%.3f'
                  % (len(rows), N_ROWS, len(cur_rows), rate)]))

    # S8：value/flags 逐行（首行 0.55/次行 0.50 恰达带沿；其后 <0.50；
    # promoted 位与带一致；事件路原料缺失位如实=不缺 novelty/稀有）
    bad = []
    if len(rows) == N_ROWS:
        inband = [r for r in rows if 0.50 <= r['value'] <= 0.95]
        flagged = [r for r in rows if r['flags'] & VF_PROMOTED]
        if len(inband) != 2:
            bad.append('带内 value 行=%d（期 2；首两行 0.55/0.50）'
                       % len(inband))
        if [r['timestamp_ns'] for r in inband] != \
                [r['timestamp_ns'] for r in flagged]:
            bad.append('promoted 位与 [0.50,0.95] 带不一致')
        if abs(rows[0]['value'] - 0.55) > 1e-9 or \
                abs(rows[1]['value'] - 0.50) > 1e-9:
            bad.append('首两行 value=%.4f/%.4f（期 0.55/0.50）'
                       % (rows[0]['value'], rows[1]['value']))
        need = VF_MISS_DIV | VF_MISS_CORR | VF_MISS_COST | VF_MISS_CONF
        for i, r in enumerate(rows):
            if not r['flags'] & need == need:
                bad.append('行 %d 缺失位不全 flags=%#x' % (i, r['flags']))
                break
            if r['flags'] & (VF_MISS_NOV | VF_MISS_RARE | VF_DEC):
                bad.append('行 %d 竟缺 novelty/稀有或标 dec 路 flags=%#x'
                           % (i, r['flags']))
                break
        def _txt(x):
            return x.decode('utf-8', 'replace') if isinstance(x, bytes) \
                else (x or '')
        if not any('action=probe dev=' in _txt(r['data']) for r in rows):
            bad.append('跨 category device 行缺席（fixture cat=3）')
    else:
        bad.append('行数=%d 非定数 %d' % (len(rows), N_ROWS))
    record('S8', 'value/flags 逐行', bad)

    # S9：curated/<UTC 今日>/ 落盘 + 同构数据文件 + index
    cdir = os.path.join(root, 'curated', today.isoformat())
    bad = []
    if not os.path.isdir(cdir):
        bad.append('curated/%s 目录缺席' % today)
    else:
        if not any(is_data_file(nm) for nm in os.listdir(cdir)):
            bad.append('curated 天目录无布局数据文件')
        if not os.path.isfile(os.path.join(root, 'curated',
                                           'index.parquet')):
            bad.append('curated/index.parquet 缺席')
    record('S9', 'curated 目录落盘', bad)

    # S10：SME 死端口失败计数诚实（journal 终笔 value final 行 + stats）
    bad = []
    m = re.search(r'value final: scored=(\d+) promoted=(\d+) '
                  r'curated_mirror_rows=(\d+) curated_mirror_fail_batches'
                  r'=(\d+) sme_nudge_ok=(\d+) sme_nudge_fail=(\d+)',
                  journal)
    if not m:
        bad.append('journal 缺 value final 终笔行: %.160r' % journal[-160:])
    else:
        s, p, mr, fb, no, nf = (int(x) for x in m.groups())
        if (s, p, mr, fb) != (N_ROWS, 2, 2, 0) or (no, nf) != (0, 2):
            bad.append('value final=%r（期 scored=%d promoted=2 mirror='
                       '2/0 nudge=0/2）' % (m.groups(), N_ROWS))
    if stat_int(stats, 'parquet.rows_written') != N_ROWS:
        bad.append('stats rows_written=%d（期 %d）'
                   % (stat_int(stats, 'parquet.rows_written'), N_ROWS))
    if stat_int(stats, 'parquet.errors') != 0:
        bad.append('stats parquet.errors=%d（期 0）'
                   % stat_int(stats, 'parquet.errors'))
    if stat_int(stats, 'sme_fail') < N_ROWS:
        bad.append('stats sme_fail=%d（期 ≥%d 死端口如实计败）'
                   % (stat_int(stats, 'sme_fail'), N_ROWS))
    if stat_int(stats, 'ring_used') != N_ROWS:
        bad.append('stats ring_used=%d（期 %d 常路全入环）'
                   % (stat_int(stats, 'ring_used'), N_ROWS))
    record('S10', 'SME 死端口诚实', bad)
    return ok, fail


# ------------------------------------------------------- 账户② 三层保留 ----
def account_retain(td, aistreamd, ai_inject):
    """②：预植目录树+AS_ONCE 单事件短跑→TTL/当天/curated 独立/异物。
    → (ok, fail)。"""
    ok = fail = 0

    def record(sid, label, bad):
        nonlocal ok, fail
        if bad:
            fail += 1
            print('FAIL %s %-18s %s' % (sid, label,
                                        ' | '.join(bad)[:240]))
        else:
            ok += 1
            print('ok   %s %-18s' % (sid, label))

    root = os.path.join(td, 'r1-root')
    today = utc_today()
    # fixture 日期按保留锚（boot 日，见 boot_anchor_day 注）构造：
    # age=锚-日名——del9/ov8/keep6/cur7 相对锚取边界
    anchor = boot_anchor_day()
    d_old, d_del9 = '2020-01-01', (anchor - 9 * DAY).isoformat()
    d_ov8 = (anchor - 8 * DAY).isoformat()
    d_keep6 = (anchor - 6 * DAY).isoformat()
    d_foreign, d_cur_old = '2020-06-01', '2020-02-02'
    d_cur7 = (anchor - 7 * DAY).isoformat()
    row = [{'timestamp_ns': 0, 'pid': 1, 'tgid': 1, 'cpu': 0, 'category': 4,
            'event_type': 0, 'severity': 0, 'data_len': 8, 'data': '[kern]',
            'trace_hi': 0, 'trace_lo': 0, 'value': 0.0, 'flags': 0}]

    def plant(sub, day, names):
        d = os.path.join(root, sub, day)
        os.makedirs(d, exist_ok=True)
        for nm in names:
            if nm.endswith('.parquet'):
                write_tel13(os.path.join(d, nm), row)
            else:
                write_file(os.path.join(d, nm), b'not layout\n')

    plant('telemetry', d_old, ['ai_0000.parquet', 'net_0000.parquet'])
    plant('telemetry', d_del9, ['net_0000.parquet'])      # age 9>7 → 删
    plant('telemetry', d_ov8, ['ai_0000.parquet'])        # cat 覆盖 30d → 留
    plant('telemetry', d_keep6, ['net_0000.parquet'])     # age 6≤7 → 留
    plant('telemetry', d_foreign, ['ai_0000.parquet', 'README.txt'])
    plant('curated', d_cur_old, ['ai_0000.parquet'])      # curated TTL 90 → 删
    plant('curated', d_cur7, ['ai_0000.parquet'])         # raw 7d 不误伤 → 留

    stats = os.path.join(td, 'r1.stats')
    logp = os.path.join(td, 'r1.log')
    conf = os.path.join(td, 'r1.conf')
    write_file(conf, base_conf(
        root, stats, os.path.join(td, 'r1.pid'), os.path.join(td, 'r1.lock'),
        PARQUET_RETENTION_DAYS='7', CURATED_RETENTION_DAYS='90',
        RETENTION_DAYS_ai='30'))

    proc, logf = run_daemon(aistreamd, conf, logp, once=True)
    try:
        if wait_portid(stats, 10):
            rc, _o, _e = inject(ai_inject, stats, 1, 5000, 'l1rt', 1)
            record('R1', 'AS_ONCE 单事件注入',
                   [] if rc == 0 else ['ai_inject rc=%d' % rc])
        else:
            record('R1', 'AS_ONCE 单事件注入', ['10s 无 portid'])
    finally:
        stop_daemon(proc)
        logf.close()
    with open(logp, 'r', errors='replace') as fh:
        journal = fh.read()

    def alive(sub, day):
        return os.path.isdir(os.path.join(root, sub, day))

    record('R2', 'TTL 过期日删(2020/-9d)',
           [] if not (alive('telemetry', d_old)
                      or alive('telemetry', d_del9))
           else ['2020-01-01 在=%s -9d 在=%s'
                 % (alive('telemetry', d_old), alive('telemetry', d_del9))])
    record('R3', 'cat 覆盖宁留(-8d ai 30d)',
           [] if alive('telemetry', d_ov8)
           else ['%s 竟被删（RETENTION_DAYS_ai=30 目录级覆盖——cat 名'
                 '对文件前缀精确匹配，小写）' % d_ov8])
    record('R4', '带内+异物保护(-6d/2020-06-01)',
           ([] if (alive('telemetry', d_keep6)
                   and alive('telemetry', d_foreign))
            else ['-6d 在=%s 异物日 在=%s'
                  % (alive('telemetry', d_keep6),
                     alive('telemetry', d_foreign))]))
    record('R5', 'curated 独立(旧删/-7d 留)',
           ([] if (not alive('curated', d_cur_old)
                   and alive('curated', d_cur7))
            else ['curated 2020-02-02 在=%s -7d 在=%s'
                  % (alive('curated', d_cur_old),
                     alive('curated', d_cur7))]))
    today_file = os.path.join(root, 'telemetry', today.isoformat(),
                              'ai_0000.parquet')
    bad = ([] if (os.path.isfile(today_file)
                  and stat_int(stats, 'parquet.rows_written') == 1)
           else ['当天 ai_0000 在=%s rows_written=%d'
                 % (os.path.isfile(today_file),
                    stat_int(stats, 'parquet.rows_written'))])
    record('R6', '当天永不删+单行落盘', bad)
    record('R7', 'journal retain 台账',
           ([] if ('purging day %s (ttl' % d_old in journal
                   and 'purging curated day %s' % d_cur_old in journal
                   and 'keep day %s (cat_override' % d_ov8 in journal)
            else ['缺 purging/keep 台账行: %.200r' % journal[:200]]))
    return ok, fail


# ---------------------------------------------------------- 账户③ corpus ----
class _SmeHandler(BaseHTTPRequestHandler):
    memories = []
    deleted = []

    def log_message(self, *a):                       # 静默
        pass

    def do_GET(self):
        if self.path == '/export':
            body = json.dumps({'memories': _SmeHandler.memories}).encode()
        else:
            body = b'{}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        mid = self.path.rsplit('/', 1)[-1]
        _SmeHandler.deleted.append(mid)
        body = json.dumps({'deleted': mid}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def account_corpus(td, aikctl, aik_gcm, s1_root):
    """③：list/export 脱敏/corpus 包往返/delete 双发门+mock SME+S1 真产物
    集成探针。→ (ok, fail)。"""
    ok = fail = 0

    def record(sid, label, bad):
        nonlocal ok, fail
        if bad:
            fail += 1
            print('FAIL %s %-18s %s' % (sid, label,
                                        ' | '.join(bad)[:240]))
        else:
            ok += 1
            print('ok   %s %-18s' % (sid, label))

    today = utc_today()
    yesterday = today - DAY
    root = os.path.join(td, 'c1-root')
    arm = os.path.join(td, 'c1-arm')
    os.makedirs(arm)
    probe_rows = [
        {'timestamp_ns': ts_ns_at(today, 1), 'pid': 4242, 'tgid': 4242,
         'cpu': 0, 'category': 18, 'event_type': 0, 'severity': 0,
         'data_len': 44, 'data': '[auth] login password=sekret '
         'user=alice', 'trace_hi': 0, 'trace_lo': 0, 'value': 0.6,
         'flags': 1},
        {'timestamp_ns': ts_ns_at(today, 2), 'pid': 0, 'tgid': 0, 'cpu': 0,
         'category': 18, 'event_type': 0, 'severity': 0, 'data_len': 40,
         'data': '[cfg] reload token=deadbeef42 ok', 'trace_hi': 0,
         'trace_lo': 0, 'value': 0.3, 'flags': 0},
        {'timestamp_ns': ts_ns_at(today, 3), 'pid': 7, 'tgid': 7, 'cpu': 1,
         'category': 18, 'event_type': 0, 'severity': 0, 'data_len': 46,
         'data': '[kern] event decision decision_id=4711 executed=2 '
         'param=mm.swappiness', 'trace_hi': 0, 'trace_lo': 0,
         'value': 0.8, 'flags': 1},
    ]
    keep_rows = [{'timestamp_ns': ts_ns_at(yesterday), 'pid': 9, 'tgid': 9,
                  'cpu': 0, 'category': 18, 'event_type': 0, 'severity': 0,
                  'data_len': 24, 'data': '[kern] proc exit pid=9 code=0',
                  'trace_hi': 0, 'trace_lo': 0, 'value': 0.1, 'flags': 0}]
    # fixture 文件名=cat_*.parquet（aikctl dataset 读契约，test_dataset.py
    # 同款）；ai_*.parquet 真产物集成走 C13 探针（期望冻结）。
    for sub, day, rows in (('curated', today, probe_rows),
                           ('curated', yesterday, keep_rows)):
        d = os.path.join(root, sub, day.isoformat())
        os.makedirs(d)
        write_tel13(os.path.join(d, 'cat_0000.parquet'), rows)
    write_idx(os.path.join(root, 'curated', 'index.parquet'), [
        {'file': 'cat_0000.parquet', 'date': today.isoformat(),
         'category': 18, 'records': len(probe_rows),
         'start_ts': probe_rows[0]['timestamp_ns'],
         'end_ts': probe_rows[-1]['timestamp_ns']},
        {'file': 'cat_0000.parquet', 'date': yesterday.isoformat(),
         'category': 18, 'records': len(keep_rows),
         'start_ts': keep_rows[0]['timestamp_ns'],
         'end_ts': keep_rows[0]['timestamp_ns']}])
    tdir = os.path.join(root, 'telemetry', today.isoformat())
    os.makedirs(tdir)
    write_tel13(os.path.join(tdir, 'sched_0000.parquet'),
                [dict(keep_rows[0], category=1)])
    write_idx(os.path.join(root, 'telemetry', 'index.parquet'), [
        {'file': 'sched_0000.parquet', 'date': today.isoformat(),
         'category': 1, 'records': 1,
         'start_ts': keep_rows[0]['timestamp_ns'],
         'end_ts': keep_rows[0]['timestamp_ns']}])

    env = dict(os.environ, AIK_GCM=aik_gcm, AIKCTL_ARM_DIR=arm)

    def ds(args, timeout=AIKCTL_TIMEOUT):
        return run_cmd([sys.executable, aikctl] + args, timeout, env=env)

    tstr = today.isoformat()

    # C1：aik-gcm keygen（mktemp keyfile，0600）
    key = os.path.join(td, 'corpus.key')
    rc, _o, err = run_cmd([aik_gcm, 'keygen', '--key', key], 30)
    mode = os.stat(key).st_mode & 0o777 if os.path.isfile(key) else 0
    record('C1', 'aik-gcm keygen 0600',
           ([] if (rc == 0 and os.path.isfile(key) and mode == 0o600)
            else ['rc=%d mode=%o: %.80s' % (rc, mode, err)]))

    # C2：dataset list（fixture 根 curated+raw；另验真 aistreamd 产物根
    # ——rows/dates 走 index 与命名无关；bytes 断言只对契约根）
    rc, out, _e = ds(['dataset', 'list', '--layer', 'curated',
                      '--root', root])
    bad = ([] if (rc == 0 and 'rows=%d' % (len(probe_rows) + len(keep_rows))
                  in out and tstr in out and 'bytes=0' not in out)
           else ['rc=%d %.120r' % (rc, out)])
    rc2, out2, _e = ds(['dataset', 'list', '--layer', 'raw', '--root', root])
    if rc2 != 0 or 'rows=1' not in out2:
        bad.append('raw list rc=%d %.80r' % (rc2, out2))
    if s1_root:
        rc3, out3, _e = ds(['dataset', 'list', '--layer', 'curated',
                            '--root', s1_root])
        if rc3 != 0 or 'rows=2' not in out3:
            bad.append('真产物根 list rc=%d %.80r' % (rc3, out3))
    record('C2', 'dataset list 汇总', bad)

    # C3：export curated jsonl（soft 缺省）——脱敏门
    jout = os.path.join(td, 'cur.jsonl')
    rc, _o, err = ds(['dataset', 'export', '--layer', 'curated',
                      '--since', tstr, '--until', tstr, '--out', jout,
                      '--root', root])
    jbytes = open(jout, 'rb').read() if os.path.isfile(jout) else b''
    bad = ([] if rc == 0 else ['rc=%d %.120r' % (rc, err)])
    for secret in (b'sekret', b'deadbeef42'):
        if secret in jbytes:
            bad.append('导出物泄原文 %r' % secret)
    for expect in (b'password=s***', b'token=d***', b'decision_id=4711'):
        if expect not in jbytes:
            bad.append('缺脱敏/例外形态 %r' % expect)
    jrows = [ln for ln in jbytes.splitlines() if ln.strip()]
    if len(jrows) != len(probe_rows):
        bad.append('jsonl 行=%d（期 %d）' % (len(jrows), len(probe_rows)))
    try:
        j0 = json.loads(jrows[0]) if jrows else {}
        if j0.get('pid') == 4242 or not isinstance(j0.get('pid'), int):
            bad.append('pid 列未哈希: %r' % j0.get('pid'))
    except ValueError as e:
        bad.append('jsonl 首行非 JSON: %s' % e)
    record('C3', 'export soft 脱敏门', bad)

    # C4：export curated parquet 双格式
    pout = os.path.join(td, 'cur.parquet')
    rc, _o, err = ds(['dataset', 'export', '--layer', 'curated',
                      '--format', 'parquet', '--since', tstr,
                      '--until', tstr, '--out', pout, '--root', root])
    bad = []
    try:
        t = pyarrow.parquet.read_table(pout)
        if t.num_rows != len(probe_rows):
            bad.append('parquet 行=%d（期 %d）' % (t.num_rows,
                                                  len(probe_rows)))
        if any('sekret' in (x or '') for x in
               (t.to_pydict().get('data') or [])):
            bad.append('parquet 导出物泄原文')
    except Exception as e:                           # noqa: BLE001
        bad.append('%s: %s（rc=%d %.80s）' % (type(e).__name__, e, rc, err))
    record('C4', 'export parquet 格式', bad)

    # C5：export corpus → .aikcorp+manifest 双产物（sha256/字段复核）
    pkg = os.path.join(td, 'pkg')
    rc, _o, err = ds(['dataset', 'export', '--layer', 'corpus',
                      '--since', tstr, '--until', tstr, '--out', pkg,
                      '--key', key, '--root', root])
    pkgpath = pkg if os.path.isfile(pkg) else pkg + '.aikcorp'
    mpath = pkgpath + '.manifest.json'
    bad = ([] if (rc == 0 and os.path.isfile(pkgpath)
                  and os.path.isfile(mpath))
           else ['rc=%d pkg=%s manifest=%s: %.120r'
                 % (rc, os.path.isfile(pkgpath), os.path.isfile(mpath),
                    err)])
    try:
        with open(mpath) as fh:
            man = json.load(fh)
        with open(pkgpath, 'rb') as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        if man.get('sha256') != digest:
            bad.append('manifest sha256 不符包体')
        if (man.get('rows') != len(probe_rows)
                or man.get('key_ref') != 'keyfile:corpus.key'
                or man.get('since') != tstr or man.get('until') != tstr
                or man.get('redaction') != 'soft'):
            bad.append('manifest 字段坏: %r' % sorted(man)[:8])
    except (OSError, ValueError) as e:
        bad.append('manifest 读败: %s' % e)
    record('C5', 'corpus 包+manifest', bad)

    # C6：aik-gcm dec 逐字节往返等（dec(包)==curated jsonl 导出物）
    dec = os.path.join(td, 'dec.jsonl')
    with open(pkgpath, 'rb') as fi, open(dec, 'wb') as fo:
        cp = subprocess.run([aik_gcm, 'dec', '--key', key], stdin=fi,
                            stdout=fo, stderr=subprocess.PIPE,
                            timeout=30)
    dbytes = open(dec, 'rb').read() if os.path.isfile(dec) else b''
    record('C6', 'aik-gcm dec 往返等',
           ([] if (cp.returncode == 0 and dbytes == jbytes)
            else ['rc=%d |dec|=%d |jsonl|=%d' % (cp.returncode, len(dbytes),
                                                 len(jbytes))]))

    # C7：篡改负例（GCM tag 败=退出码 4 零输出）
    bad = []
    try:
        with open(pkgpath, 'rb') as fh:
            blob = bytearray(fh.read())
        if len(blob) > 64:
            blob[-1] ^= 0xFF                       # 动尾部（tag 区）
            tamp = os.path.join(td, 'tamp.aikcorp')
            write_file(tamp, bytes(blob))
            with open(tamp, 'rb') as fi:
                cp = subprocess.run([aik_gcm, 'dec', '--key', key],
                                    stdin=fi, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=30)
            if not (cp.returncode == 4 and not cp.stdout):
                bad.append('rc=%d stdout=%dB（期 4/0）'
                           % (cp.returncode, len(cp.stdout)))
        else:
            bad.append('包体过短 %d' % len(blob))
    except OSError as e:
        bad.append('%s: %s' % (type(e).__name__, e))
    record('C7', '篡改检出 tag 败', bad)

    # C13：真产物集成探针——账户① aistreamd 实产根 export（期望冻结：
    # curated 2 行必导出；现树 aikctl _cat_files 只认 cat_* 而实产为
    # <cat名>_NNNN.parquet → rows=0 如实红，修 aikctl 读契约后转绿）
    if s1_root:
        rout = os.path.join(td, 'real.jsonl')
        rc, out, _e = ds(['dataset', 'export', '--layer', 'curated',
                          '--since', tstr, '--until', tstr, '--out', rout,
                          '--root', s1_root])
        rbytes = open(rout, 'rb').read() if os.path.isfile(rout) else b''
        rlines = [ln for ln in rbytes.splitlines() if ln.strip()]
        listing = ''
        cday = os.path.join(s1_root, 'curated', tstr)
        if os.path.isdir(cday):
            listing = '实产文件=%r' % sorted(os.listdir(cday))
        record('C13', '真产物导出集成',
               ([] if (rc == 0 and len(rlines) == 2)
                else ['rc=%d rows=%d（期 2；curated 实产 2 行）%s %s'
                      % (rc, len(rlines), listing,
                         out.strip()[:120])]))

    # C8-C12：delete 双发确认门 + mock SME
    _SmeHandler.memories = [
        {'id': 'm-in', 'tags': ['kernel_evt', 'curated:v1'],
         'metadata': {'ts': ts_ns_at(today, 2) // 1000000}},
        {'id': 'm-out', 'tags': ['curated:v1'],
         'metadata': {'ts': ts_ns_at(yesterday, 2) // 1000000}},
        {'id': 'm-other', 'tags': ['kernel_evt'],
         'metadata': {'ts': ts_ns_at(today, 2) // 1000000}},
    ]
    _SmeHandler.deleted = []
    srv = ThreadingHTTPServer(('127.0.0.1', 0), _SmeHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    delbase = ['dataset', 'delete', '--layer', 'curated', '--root', root,
               '--since', tstr, '--until', tstr,
               '--sme-url', 'http://127.0.0.1:%d' % srv.server_address[1]]
    try:
        rc, out, err = ds(['dataset', 'delete', '--layer', 'raw',
                           '--root', root, '--since', tstr,
                           '--until', tstr])
        record('C8', 'delete 拒 raw 层',
               ([] if (rc != 0 and '拒绝' in (out + err))
                else ['rc=%d %.120r' % (rc, err)]))
        rc, out, err = ds(delbase)
        tday = os.path.join(root, 'curated', tstr)
        kept = os.path.isfile(os.path.join(tday, 'cat_0000.parquet'))
        record('C9', '首发只布防未删',
               ([] if (rc == 1 and kept and 'nonce' in out)
                else ['rc=%d 文件在=%s: %.120r' % (rc, kept, out)]))
        rc, out, err = ds(delbase + ['--yes'])
        m = re.search(r'files=(\d+) rows=(\d+) bytes_freed=(\d+) '
                      r'sme_deleted=(\d+)/(\d+)', out)
        bad = ([] if (rc == 0 and m) else ['rc=%d %.160r' % (rc, out)])
        if m:
            f, r, freed, sd, st_ = m.groups()
            if (f, r) != ('1', str(len(probe_rows))):
                bad.append('files/rows=%s/%s（期 1/%d）'
                           % (f, r, len(probe_rows)))
            if int(freed) <= 0:
                bad.append('bytes_freed=%s（期 >0）' % freed)
            if (sd, st_) != ('1', '1'):
                bad.append('sme_deleted=%s/%s（期 1/1 窗内恰一）' % (sd, st_))
        if os.path.isfile(os.path.join(tday, 'cat_0000.parquet')):
            bad.append('--yes 后文件竟在')
        if _SmeHandler.deleted != ['m-in']:
            bad.append('SME DELETE 调用=%r（期 [m-in]）'
                       % _SmeHandler.deleted)
        ydir = os.path.join(root, 'curated', yesterday.isoformat())
        if not os.path.isfile(os.path.join(ydir, 'cat_0000.parquet')):
            bad.append('窗外昨日文件被误删')
        record('C10', '--yes 真删+SME 对应', bad)
        rc, out, _e = ds(delbase + ['--yes'])
        record('C11', '再发无布防拒',
               ([] if rc != 0 else ['rc=%d 竟成功 %.80r' % (rc, out)]))
        rc, out, _e = ds(['dataset', 'list', '--layer', 'curated',
                          '--root', root])
        record('C12', '删后 index 重建',
               ([] if (rc == 0 and 'rows=1' in out
                       and yesterday.isoformat() in out)
                else ['rc=%d %.120r' % (rc, out)]))
    finally:
        srv.shutdown()
        srv.server_close()
    return ok, fail


# ------------------------------------------------------------- preflight ----
def preflight(aikctl, aik_gcm, aistreamd, ai_inject):
    """→ [FAIL 行]；空=全过（缺=如实 FAIL 不跳过）。"""
    bad = []
    if pyarrow is None:
        bad.append('preflight: pyarrow 缺席（13 列断言与 fixture 造表都'
                   '需要；pip install pyarrow）——如实 FAIL 不跳过')
    for label, p, need_x in (('aikctl', aikctl, False),
                             ('aik-gcm', aik_gcm, True),
                             ('aistreamd', aistreamd, True),
                             ('ai_inject', ai_inject, True)):
        if not os.path.isfile(p):
            bad.append('preflight: %s %r 缺席（仓内构建件未 make？）'
                       % (label, p))
        elif need_x and not os.access(p, os.X_OK):
            bad.append('preflight: %s %r 无执行位' % (label, p))
    return bad


# ------------------------------------------------------------------ main ----
def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    agent = os.path.dirname(here)
    ap = argparse.ArgumentParser(
        prog='l1_data_bench',
        description='L1 数据三层台架（DATA-L1-DESIGN §4；评分/promotion+'
                    '三层保留+corpus 三账户）')
    ap.add_argument('--aikctl', default=None,
                    help='aikctl（默认 $AIKCTL 或仓内 ../aikctl/aikctl）')
    ap.add_argument('--aik-gcm', default=None,
                    help='aik-gcm（默认 $AIK_GCM 或仓内 ../aik-gcm）')
    ap.add_argument('--aistreamd', default=None,
                    help='aistreamd（默认 $AISTREAMD 或仓内 '
                         '../aistreamd/aistreamd）')
    ap.add_argument('--ai-inject', dest='ai_inject', default=None,
                    help='ai_inject（默认 $AI_INJECT 或仓内 '
                         '../aistreamd/tests/ai_inject）')
    ap.add_argument('--keep', action='store_true',
                    help='保留临时目录（排障用）')
    args = ap.parse_args(argv)
    aikctl = args.aikctl or os.environ.get('AIKCTL') or \
        os.path.join(agent, 'aikctl', 'aikctl')
    aik_gcm = args.aik_gcm or os.environ.get('AIK_GCM') or \
        os.path.join(agent, 'aik-gcm')
    aistreamd = args.aistreamd or os.environ.get('AISTREAMD') or \
        os.path.join(agent, 'aistreamd', 'aistreamd')
    ai_inject = args.ai_inject or os.environ.get('AI_INJECT') or \
        os.path.join(agent, 'aistreamd', 'tests', 'ai_inject')
    print('L1 bench aikctl=%s aik-gcm=%s' % (aikctl, aik_gcm))
    print('L1 bench aistreamd=%s ai_inject=%s' % (aistreamd, ai_inject))

    bad = preflight(aikctl, aik_gcm, aistreamd, ai_inject)
    if bad:
        for ln in bad:
            print('FAIL ' + ln)
        print('L1_BENCH ok=0 fail=1')
        return 1

    td = tempfile.mkdtemp(prefix='l1-bench-')
    try:
        ok1, fail1 = account_score(td, aistreamd, ai_inject)
        s1_root = os.path.join(td, 's1-root')
        ok2, fail2 = account_retain(td, aistreamd, ai_inject)
        ok3, fail3 = account_corpus(td, aikctl, aik_gcm, s1_root)
        print('L1_ACCOUNTS score=%d/%d retain=%d/%d corpus=%d/%d'
              % (ok1, ok1 + fail1, ok2, ok2 + fail2, ok3, ok3 + fail3))
        ok, fail = ok1 + ok2 + ok3, fail1 + fail2 + fail3
        print('L1_BENCH ok=%d fail=%d' % (ok, fail))
        return 0 if fail == 0 else 1
    finally:
        if args.keep:
            print('KEEP td=%s' % td)
        else:
            shutil.rmtree(td, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
