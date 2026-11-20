#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M2 金丝雀/A-B/签名表/自动回退台架（AIPD-M2-DESIGN §7；run_all 第 67 门）。

六件分账（设计册冻结，禁调期望凑绿）：
  B1 误决策：≥120 标注向量（按 ../aipd/table_spec.json 语义生成：命中/
    边界/信任门跳过/stale 四类，oracle=台架侧按冻结表语义独立实现）灌
    FEAT_SOURCE=mock 跑 aipd → 影子 parquet decision_type 对标签
    **err=0**（判据 err=0 ≤2%，AIPD-M2-DESIGN §7/B1）。
  B2 A/B：同内容 B 表 mismatch=0；shift 变体 mismatch>0——依赖 Lane-A
    CANARY_TABLE 面（conf 键+stats canary_ab_*）。**Lane-A 未合入的树上
    无法跑通属预期**：断言写全，--integration 才跑（集成期主会话亲跑）。
  B3 签名门：翻转规则体 1 字节/截断/坏 magic → aipd 启动 exit 1
    （fail-fast）——同上 --integration（M1 aipd 无 CANARY_TABLE 键）。
  B4 合同：未知 canary 键 exit 1（M1 侧现在即可跑绿——aip_conf 契约
    一切未知键均拒，M2 上 CANARY_BOGUS_KEY 仍未知键同拒）；ENABLED
    缺省=0 时 M1 等价（canary_dispatched=0/影子 executed 全 0）——用
    主仓 main 检出的 M1 aipd 现在跑绿（Lane-A 合入后同 conf 变为
    canary_dispatched=0 显式键，断言两侧兼容）。
  B5 table-verify：python 侧=aikctl aipd table-verify（合法+三种非法
    同裁定）现在自测；C 侧=aipd 加载器行为经 startup（CANARY_TABLE 面）
    —— --integration（B3 共享三种非法表构造）。
  B6 aikctl release/rollback 台账回合：沙箱 AIKERNEL_AIPD_ROOT+沙箱
    conf（--conf 指临时文件），零全局副作用（不碰真 /etc、真 root），
    现在跑绿。

纪律（坑册）：禁止 import 其他台架模块（l1_data_bench run_cmd 环境
钉教训=跨台架 import 历史污染案）——Bench/run_cmd/read_kv_file/
start_aipd/stop_graceful 自 m1_bench.py **复制**（同仓 tests/，非
import），parquet 读取器/临时目录/守卫风格自 l1_data_bench.py 复制；
来源逐段注明。表/AIPTBL 构造自 aipd/table_spec.json + aip_table.h
生成器合同（128B 头+N×128B 规则体）在台架内独立实现。
前置自检缺件=FAIL 不跳过（aipd/aikctl 未构建、缺 pyarrow、
table_spec.json 不可解析=如实红）。
aipd 件解析：--aipd > $AIK_AIPD_BIN > 仓内 ../aipd/aipd（门测当前
构建）；aikctl：--aikctl > $AIKCTL > 仓内 ../aikctl/aikctl。
输出：M2_ACCOUNTS 分账 + 末行 `M2_BENCH ok=N fail=M`（零 fail→rc0）；
默认模式另出 M2_DEFERRED 行如实列集成期待跑清单。
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.dirname(HERE)

B1_ERR_PCT_LIMIT = 2.0             # §7/B1 判据上限（门断言更严：err=0）
B4_N_DECISIONS = 16                # B4b M1 等价短跑行数
START_WAIT_SEC = 20.0              # 等 decisions>=N 上限
SHADOW_NAME_RE = re.compile(r'^shadow_\d{4}\.parquet$')
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*([^\s]+)')
# AIPTBL 头（§4；与 aikctl aipd 子族/aip_table.c 同合同）
TABLE_MAGIC = b'AIPTBL\0\0'
TABLE_VER = 1
TABLE_RULES_MAX = 64
TABLE_HDR_SZ = 128
RULE_SER_SZ = 128
REASON_MAX = 96
# ai_feature_vec 字段序（aip_feat.h 48B 冻结镜像；mock jsonl 同名字段）
FEAT_FIELDS = ('seq', 'ts', 'lat_ewma_ns', 'iowait_pct', 'psi_mem_some',
               'cache_misses', 'valid_bits')
# 特征可信门位（aip_model.h AIP_VALID_*：LAT=bit0/IOWAIT=bit1/PSI=bit2/
# CACHE=bit3；SEQ/TS/VALID_BITS 恒可信——oracle 语义来源）
VALID_BIT_BY_FEAT = {2: 1, 3: 2, 4: 4, 5: 8}

try:
    import pyarrow.parquet          # B1/B4b 深查必需件（缺=preflight FAIL）
except ImportError:
    pyarrow = None


# ------------------------------------------------------------- 助手 ----
# ↓↓↓ 以下五件自 m1_bench.py 复制（同仓 tests/；禁 import 纪律）↓↓↓
class Bench:
    def __init__(self):
        self.ok = 0
        self.fail = 0

    def check(self, name, cond, note=''):
        if cond:
            self.ok += 1
            print('  PASS %s%s' % (name, (' — ' + note) if note else ''))
        else:
            self.fail += 1
            print('  FAIL %s%s' % (name, (' — ' + note) if note else ''))
        return cond


def run_cmd(cmd, timeout, env=None):
    cp = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
    return (cp.returncode, cp.stdout.decode('utf-8', 'replace'),
            cp.stderr.decode('utf-8', 'replace'))


def read_kv_file(path):
    """key=value 行式文件（stats/conf 同语法）→ dict（不可解析行跳过）。"""
    out = {}
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            for ln in fh:
                m = KV_RE.match(ln.strip())
                if m:
                    out[m.group(1)] = m.group(2)
    except OSError:
        pass
    return out


def start_aipd(aipd, conf, tmp, b):
    """起 aipd 守护并等心跳（stats 落盘）；返回 (proc, pid) 或 (None, None)。"""
    log = open(os.path.join(tmp, 'aipd.log'), 'wb')
    try:
        proc = subprocess.Popen([aipd, '--conf', conf], stdout=log,
                                stderr=subprocess.STDOUT)
    except OSError as exc:
        print('  起 aipd 失败: %s' % exc)
        log.close()
        return None, None
    stats = os.path.join(tmp, 'aipd.stats')
    for _ in range(50):                          # ≤10s 等心跳
        if os.path.exists(stats) and proc.poll() is None:
            break
        if proc.poll() is not None:
            print('  aipd 早退 rc=%s（日志尾见 %s）'
                  % (proc.returncode, log.name))
            log.close()
            return None, None
        time.sleep(0.2)
    if not os.path.exists(stats):
        print('  aipd 10s 内未写心跳 stats（日志尾见 %s）' % log.name)
        log.close()
        proc.kill()
        proc.wait()
        return None, None
    pid = None
    try:
        with open(os.path.join(tmp, 'aipd.pid'), encoding='utf-8') as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        pid = proc.pid
    log.close()
    return proc, pid


def stop_graceful(proc, b, name='term_exit'):
    """SIGTERM→≤10s 退出；超时 SIGKILL 兜底且该项记 FAIL。"""
    if proc is None:
        return False
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
        return b.check(name, True, 'TERM 后 %ds 内退出' % 10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return b.check(name, False, 'TERM 10s 不退，已 SIGKILL 兜底')
# ↑↑↑ 自 m1_bench.py 复制止 ↑↑↑


def aikctl_cmd(aikctl):
    """aikctl 调用形（可执行位在=直调；否则 python3 兜底）。"""
    if os.access(aikctl, os.X_OK):
        return [aikctl]
    return [sys.executable, aikctl]


def aikctl_run(aikctl, sub_args, root=None, timeout=60):
    env = dict(os.environ)
    if root is not None:
        env['AIKERNEL_AIPD_ROOT'] = root
    return run_cmd(aikctl_cmd(aikctl) + sub_args, timeout, env=env)


def write_conf(path, tmp, extra=None, poll_hz=10, stats_interval=1):
    """台架 conf（键集沿 m1_bench write_conf=出厂 aipd.conf M1 键；
    extra=canary 键等追加行——M2 面）。全临时根零全局副作用。"""
    lines = [
        '# m2_bench 台架 conf（自动生成）',
        'FEAT_SOURCE=mock',
        'FEAT_MOCK_FILE=%s/mock_feats.jsonl' % tmp,
        'POLL_HZ=%d' % poll_hz,
        'MODEL_TABLE=builtin',
        'SHADOW=1',
        'STATS_INTERVAL_SEC=%d' % stats_interval,
        'PARQUET_DIR=%s/shadow' % tmp,
        'COMPARE_ENABLED=0',
        'STATS_FILE=%s/aipd.stats' % tmp,
        'PID_FILE=%s/aipd.pid' % tmp,
        'LOCK_FILE=%s/aipd.lock' % tmp,
    ]
    lines += list(extra or [])
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(lines) + '\n')


def wait_decisions(stats_path, need, proc, timeout=START_WAIT_SEC):
    """轮询 stats 等 decisions>=need（proc 早退即返 False）。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        kv = read_kv_file(stats_path)
        try:
            if int(kv.get('decisions', '0')) >= need:
                return True
        except ValueError:
            pass
        time.sleep(0.2)
    kv = read_kv_file(stats_path)
    try:
        return int(kv.get('decisions', '0')) >= need
    except ValueError:
        return False


# ------------------------------------------------- 表 spec + oracle ----
def load_spec(path):
    """table_spec.json → rules=[(feat,op,lo,hi,action,param,because)]，
    枚举符号经 spec.schema 符号表解析（schema 冻结契约）。解析失败抛错
    （preflight 捕获=如实 FAIL）。"""
    with open(path, encoding='utf-8') as fh:
        spec = json.load(fh)
    sym = spec.get('schema', {})
    feat_syms = sym.get('feat_syms', {})
    op_syms = sym.get('op_syms', {})
    act_syms = sym.get('act_syms', {})
    rules = []
    for r in spec['rules']:
        rules.append((int(feat_syms[r['feat']]), int(op_syms[r['op']]),
                      int(r['lo']), int(r['hi']),
                      int(act_syms[r['action']]), int(r['param']),
                      r['because']))
    return rules


def feat_value(vec, feat):
    return int(vec[FEAT_FIELDS[feat]])


def feat_trusted(vec, feat):
    """可信门（aip_feat_trusted 语义）：LAT/IOWAIT/PSI/CACHE 要求
    valid_bits 对应位；SEQ/TS/VALID_BITS 恒可信。"""
    bit = VALID_BIT_BY_FEAT.get(feat, 0)
    return bit == 0 or bool(vec['valid_bits'] & bit)


def oracle_decide(vec, rules):
    """台架侧 oracle（冻结表语义独立实现：按序首命中单出+可信门跳过，
    aip_decide 合同 aip_model.h）→ (rule_idx, action)。"""
    for idx, (feat, op, lo, hi, action, _param, _because) in \
            enumerate(rules):
        if not feat_trusted(vec, feat):
            continue
        v = feat_value(vec, feat)
        if (op == 1 and v > lo) or (op == 0 and lo <= v <= hi):
            return idx, action
    return -1, 0


def build_aiptbl(rules, shift=0):
    """按 §4/AIPTBL 合同造表文件字节（台架独立实现=aip_table.h 生成器
    合同同款：'<IIqqII'+reason[96] NUL 填充，全小端；sha256=规则体
    串连摘要入头）。shift≠0 时 GT 规则 lo 平移（B2 变体表同
    gen_aip_table --shift 语义）。"""
    body = b''
    for feat, op, lo, hi, action, param, because in rules:
        if shift and op == 1:
            lo += shift
        reason = because.encode('utf-8')
        if len(reason) > REASON_MAX:
            raise ValueError('reason 超 %dB: %r' % (REASON_MAX, because))
        body += struct.pack('<IIqqII', feat, op, lo, hi, action, param)
        body += reason.ljust(REASON_MAX, b'\0')
    sha = hashlib.sha256(body).hexdigest()
    hdr = TABLE_MAGIC + struct.pack('<HHI', TABLE_VER, 0, len(rules))
    hdr += sha.encode('ascii') + b'\0' + bytes(47)
    assert len(hdr) == TABLE_HDR_SZ
    return hdr + body, sha


def corrupt_body_byte(data):
    """翻转规则体 1 字节（reason 域内——域校验仍合法，专打 sha256 门）。"""
    ba = bytearray(data)
    off = TABLE_HDR_SZ + 32 + 5               # rule[0] reason 域中部
    ba[off] ^= 0x20
    return bytes(ba)


def gen_labeled(rules):
    """≥120 标注向量（oracle 同源定期望）→ [(vec, exp_idx, exp_act, tag)]。
    四类覆盖：grid=命中/边界/优先序（GT 边界值 lo=不中、lo+1=中动态取自
    spec 阈值）；trust=信任门跳过（valid_bits 缺位）；stale=ts=0
    （决策照出，期望 action 不变——AIP_DF_STALE 只标位不吞决策）。"""
    lo = {feat: v for feat, _op, v, _hi, _a, _p, _b in rules}
    psi_lo = lo.get(4, 409)
    lat_lo = lo.get(2, 10_000_000)
    iow_lo = lo.get(3, 20)
    psi_vals = sorted({0, 100, psi_lo, psi_lo + 1, psi_lo + 91,
                       psi_lo + 400, 2048})
    lat_vals = sorted({0, 1_000_000, lat_lo - 1, lat_lo, lat_lo + 1,
                       lat_lo * 5})
    iow_vals = sorted({0, 10, iow_lo, iow_lo + 1, 60, 100})
    mono = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    labeled = []
    seq = 0

    def add(psi, lat, iow, valid, tag, stale=False):
        nonlocal seq
        seq += 1
        vec = {'seq': seq, 'ts': 0 if stale else mono + seq * 1_000_000,
               'lat_ewma_ns': lat, 'iowait_pct': iow,
               'psi_mem_some': psi, 'cache_misses': 0,
               'valid_bits': valid}
        idx, act = oracle_decide(vec, rules)
        labeled.append((vec, idx, act, tag))
    # A. 全可信网格（命中/边界/多命中优先序）
    for psi in psi_vals:
        for lat in lat_vals:
            for iow in iow_vals:
                add(psi, lat, iow, 7, 'grid')
    # B. 信任门跳过（缺位→规则跳过，落到后续规则或无命中）
    for psi in (psi_lo + 91, 100):
        for lat in (lat_lo * 5, 1_000_000):
            for iow in (iow_lo + 1, 10):
                for valid in (0, 3, 5, 6):
                    add(psi, lat, iow, valid, 'trust')
    # C. stale（ts=0=从未发布→stale；决策照出）
    for psi, lat, iow in ((psi_lo + 400, 0, 0), (0, lat_lo * 5, 0),
                          (0, 0, 60), (psi_lo + 400, lat_lo * 5, 60),
                          (100, 5_000_000, 15), (psi_lo + 1, 0, iow_lo + 1)):
        add(psi, lat, iow, 7, 'stale', stale=True)
        add(psi, lat, iow, 7, 'stale', stale=True)
    return labeled


def write_labeled_jsonl(path, labeled):
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        for vec, _idx, _act, _tag in labeled:
            fh.write(json.dumps(vec) + '\n')


# ------------------------------------------------- 影子读取器 ----
# ↓↓↓ parquet 读取器自 l1_data_bench.py read_day_rows 复制改造（禁
# import 纪律）。坑（pyarrow 25 实测）：旧版影子 33 列含两个 source
# 列（dec v3 同构 i8 + 尾列 string）——read_table 对重复列名直接抛
# ArrowInvalid 'Multiple matches'。**P-56 已修（11-20）：尾列改名
# producer，新件可整读**；旧件（修复前产物）仍须走低层
# ParquetFile.read(columns=唯一名列)。挑列读法对两代件通用，保持。↓↓↓
SHADOW_PICK_COLS = ['decision_id', 'trigger_event_id', 'decision_type',
                    'data_5', 'data_6', 'executed']


def read_shadow_rows(shadow_root):
    """>/aipd/<日>/shadow_NNNN.parquet 逐文件读行（按 decision_id 排序）。
    → {seq(trigger_event_id): {actions:set, rule_idx:set, stale:set,
    executed:set}}（EOF 复用行按 seq 归并）。"""
    agg = {}
    base = os.path.join(shadow_root, 'aipd')
    if not os.path.isdir(base):
        return agg
    rows = []
    for day in sorted(os.listdir(base)):
        ddir = os.path.join(base, day)
        if not os.path.isdir(ddir):
            continue
        for name in sorted(os.listdir(ddir)):
            if not SHADOW_NAME_RE.match(name):
                continue
            cols = pyarrow.parquet.ParquetFile(
                os.path.join(ddir, name)).read(
                    columns=SHADOW_PICK_COLS).to_pydict()
            n = len(cols.get('decision_id', []))
            for i in range(n):
                rows.append({
                    'decision_id': cols['decision_id'][i],
                    'trigger_event_id': cols['trigger_event_id'][i],
                    'decision_type': cols['decision_type'][i],
                    'data_5': cols['data_5'][i],
                    'data_6': cols['data_6'][i],
                    'executed': cols['executed'][i],
                })
    rows.sort(key=lambda r: r['decision_id'])
    for r in rows:
        e = agg.setdefault(r['trigger_event_id'],
                           {'actions': set(), 'rule_idx': set(),
                            'stale': set(), 'executed': set()})
        e['actions'].add(r['decision_type'])
        e['rule_idx'].add(r['data_6'])
        e['stale'].add(r['data_5'])
        e['executed'].add(r['executed'])
    return agg
# ↑↑↑ 自 l1_data_bench.py 复制改造止 ↑↑↑


# ------------------------------------------------------- B1 误决策 ----
def acct_b1(aipd, rules, td, b):
    labeled = gen_labeled(rules)
    n = len(labeled)
    print('[B1 误决策] %d 标注向量（grid=%d trust=%d stale=%d）灌 mock '
          '跑 aipd → 影子 decision_type 对标签 err=0'
          % (n, sum(1 for l in labeled if l[3] == 'grid'),
             sum(1 for l in labeled if l[3] == 'trust'),
             sum(1 for l in labeled if l[3] == 'stale')))
    tmp = tempfile.mkdtemp(prefix='m2-b1-', dir=td)
    conf = os.path.join(tmp, 'aipd.conf')
    write_conf(conf, tmp, poll_hz=1000)
    write_labeled_jsonl(os.path.join(tmp, 'mock_feats.jsonl'), labeled)
    proc, _pid = start_aipd(aipd, conf, tmp, b)
    if proc is None:
        b.check('b1_run', False, 'aipd 未能起（前置失败）')
        return None
    got_n = wait_decisions(os.path.join(tmp, 'aipd.stats'), n, proc)
    stop_graceful(proc, b, name='b1_term_exit')
    b.check('b1_decisions', got_n,
            'stats decisions≥%d（%s）'
            % (n, '够' if got_n else read_kv_file(
                os.path.join(tmp, 'aipd.stats')).get('decisions', '?')))
    rows = read_shadow_rows(os.path.join(tmp, 'shadow'))
    b.check('b1_rows', len(rows) >= n,
            '影子行 seq 数=%d（≥%d）' % (len(rows), n))
    err = 0
    idx_err = 0
    stale_err = 0
    for vec, exp_idx, exp_act, _tag in labeled:
        e = rows.get(vec['seq'])
        if e is None:
            err += 1
            idx_err += 1
            stale_err += 1
            continue
        if e['actions'] != {exp_act}:
            err += 1
        if e['rule_idx'] != {exp_idx}:
            idx_err += 1
        want_stale = 1 if vec['ts'] == 0 else 0
        if e['stale'] != {want_stale}:
            stale_err += 1
    err_pct = 100.0 * err / n
    b.check('b1_decision_type_err0', err == 0,
            'err=%d/%d（%.3f%%，判据 ≤%.0f%%——门冻结 err=0）'
            % (err, n, err_pct, B1_ERR_PCT_LIMIT))
    b.check('b1_rule_idx', idx_err == 0, 'data_6 rule_idx 不符=%d'
            % idx_err)
    b.check('b1_stale_bit', stale_err == 0,
            'data_5 stale 位不符=%d（ts=0 期 1，余期 0）' % stale_err)
    # 覆盖面自证（fixture 非退化：四类与全 action 都在场）
    acts = {act for _v, _i, act, _t in labeled}
    idxs = {i for _v, i, _a, _t in labeled}
    want_acts = {a for (_f, _o, _l, _h, a, _p, _r) in rules if a}
    b.check('b1_coverage',
            0 in acts and acts >= want_acts
            and idxs == (set(range(len(rules))) | {-1}),
            'action 集=%s（表动作 %s+NONE）rule_idx 集=%s（逐规则+无命中）'
            % (sorted(acts), sorted(want_acts), sorted(idxs)))
    return None


# ------------------------------------- B2 A/B（--integration） ----
def acct_b2(aipd, rules, td, b, labeled_stream=None):
    print('[B2 A/B] 同内容 B 表 mismatch=0；shift 变体 mismatch>0'
          '（Lane-A CANARY_TABLE 面——集成期跑）')
    labeled = labeled_stream or gen_labeled(rules)[:60]
    n = len(labeled)
    table_same, sha_same = build_aiptbl(rules)
    table_shift, sha_shift = build_aiptbl(rules, shift=300)

    def run_ab(table_bytes, tag):
        tmp = tempfile.mkdtemp(prefix='m2-b2-%s-' % tag, dir=td)
        tpath = os.path.join(tmp, 'b_%s.bin' % tag)
        with open(tpath, 'wb') as fh:
            fh.write(table_bytes)
        conf = os.path.join(tmp, 'aipd.conf')
        write_conf(conf, tmp, poll_hz=1000,
                   extra=['CANARY_ENABLED=0', 'CANARY_TABLE=%s' % tpath])
        write_labeled_jsonl(os.path.join(tmp, 'mock_feats.jsonl'), labeled)
        proc, _pid = start_aipd(aipd, conf, tmp, b)
        if proc is None:
            return None
        ok = wait_decisions(os.path.join(tmp, 'aipd.stats'), n, proc)
        stop_graceful(proc, b, name='b2_term_%s' % tag)
        if not ok:
            b.check('b2_run_%s' % tag, False, 'aipd 未达 decisions≥%d' % n)
            return None
        return read_kv_file(os.path.join(tmp, 'aipd.stats'))

    st = run_ab(table_same, 'same')
    if st is not None:
        tot = _iget(st, 'canary_ab_total')
        mis = _iget(st, 'canary_ab_mismatch')
        b.check('b2_same_mismatch0',
                tot is not None and tot > 0 and mis == 0,
                'ab_total=%s ab_mismatch=%s（同内容期望 0 且有观测）'
                % (tot, mis))
        b.check('b2_table_tag',
                st.get('canary_table') == 'file:%s' % sha_same[:8],
                'canary_table=%s（期 file:%s）'
                % (st.get('canary_table'), sha_same[:8]))
    st2 = run_ab(table_shift, 'shift')
    if st2 is not None:
        tot = _iget(st2, 'canary_ab_total')
        mis = _iget(st2, 'canary_ab_mismatch')
        b.check('b2_shift_mismatch_gt0',
                tot is not None and tot > 0 and mis > 0,
                'ab_total=%s ab_mismatch=%s（shift 变体期望 >0）'
                % (tot, mis))
        # 灵敏性对照：shift 表不等于同内容表（sha 不同）
        b.check('b2_shift_distinct', sha_shift != sha_same,
                'shift sha=%s… != same sha=%s…' % (sha_shift[:8],
                                                   sha_same[:8]))
    return None


def _iget(kv, key):
    try:
        return int(str(kv.get(key)))
    except (TypeError, ValueError):
        return None


# ------------------------------------- B3 签名门（--integration） ----
def acct_b3(aipd, rules, td, b):
    print('[B3 签名门] 翻转体字节/截断/坏 magic → aipd 启动 exit 1'
          '（fail-fast；集成期跑）')
    good, _sha = build_aiptbl(rules)
    cases = [
        ('flip_body', corrupt_body_byte(good)),
        ('truncated', good[:-13]),
        ('bad_magic', b'XIPDBL\0\0' + good[8:]),
    ]
    for tag, data in cases:
        tmp = tempfile.mkdtemp(prefix='m2-b3-%s-' % tag, dir=td)
        tpath = os.path.join(tmp, 'bad_%s.bin' % tag)
        with open(tpath, 'wb') as fh:
            fh.write(data)
        conf = os.path.join(tmp, 'aipd.conf')
        write_conf(conf, tmp, extra=['CANARY_ENABLED=0',
                                     'CANARY_TABLE=%s' % tpath])
        write_labeled_jsonl(os.path.join(tmp, 'mock_feats.jsonl'),
                            gen_labeled(rules)[:8])
        rc, out, err = 0, '', ''
        try:
            rc, out, err = run_cmd([aipd, '--conf', conf], 15)
        except subprocess.TimeoutExpired:
            b.check('b3_%s_exit1' % tag, False,
                    'aipd 15s 未退（期 fail-fast exit 1）')
            continue
        b.check('b3_%s_exit1' % tag, rc == 1,
                'rc=%d%s' % (rc, ('；stderr 尾: ' + err.strip()[-120:])
                             if err.strip() else ''))
    return None


# ------------------------------------------------------- B4 合同 ----
def acct_b4(aipd, rules, td, b, integration=False):
    print('[B4 合同] 未知 canary 键 exit 1；ENABLED 缺省=0 时 M1 等价'
          '（canary_dispatched=0/executed 全 0）')
    tmp = tempfile.mkdtemp(prefix='m2-b4-', dir=td)
    # a) 未知 canary 键拒（M1 契约：一切未知键拒；M2 上 CANARY_BOGUS_KEY
    #    仍不在 §6 键集=同拒。两侧同绿）
    bad_conf = os.path.join(tmp, 'bad.conf')
    write_conf(bad_conf, tmp, extra=['CANARY_BOGUS_KEY=1'])
    try:
        rc, _out, err = run_cmd([aipd, '--conf', bad_conf, '--check-conf'],
                                15)
        b.check('b4_unknown_key_checkconf', rc == 1,
                'rc=%d%s' % (rc, ('；stderr 尾: ' + err.strip()[-120:])
                             if err.strip() else ''))
    except (subprocess.TimeoutExpired, OSError) as exc:
        b.check('b4_unknown_key_checkconf', False, str(exc))
    try:
        rc, _out, _err = run_cmd([aipd, '--conf', bad_conf], 15)
        b.check('b4_unknown_key_startup', rc == 1, '启动 rc=%d' % rc)
    except (subprocess.TimeoutExpired, OSError) as exc:
        b.check('b4_unknown_key_startup', False, str(exc))
    # 好合同自证：--check-conf 对合法 conf rc=0（否则上面红是误红）
    good_conf = os.path.join(tmp, 'good.conf')
    write_conf(good_conf, tmp)
    try:
        rc, _out, _err = run_cmd([aipd, '--conf', good_conf, '--check-conf'],
                                 15)
        b.check('b4_checkconf_ok', rc == 0, 'rc=%d' % rc)
    except (subprocess.TimeoutExpired, OSError) as exc:
        b.check('b4_checkconf_ok', False, str(exc))
    # b) ENABLED 缺省=0 时 M1 等价：无 canary 键 conf 跑 M1/M2 aipd 均应
    #    canary_dispatched=0（M1=键缺席按 0 记）+ 影子 executed 全 0
    labeled = gen_labeled(rules)[:B4_N_DECISIONS]
    tmp2 = tempfile.mkdtemp(prefix='m2-b4b-', dir=td)
    conf = os.path.join(tmp2, 'aipd.conf')
    write_conf(conf, tmp2, poll_hz=1000)
    write_labeled_jsonl(os.path.join(tmp2, 'mock_feats.jsonl'), labeled)
    proc, _pid = start_aipd(aipd, conf, tmp2, b)
    if proc is None:
        b.check('b4_m1_equiv', False, 'aipd 未能起（前置失败）')
        return None
    ok = wait_decisions(os.path.join(tmp2, 'aipd.stats'), len(labeled),
                        proc)
    stop_graceful(proc, b, name='b4_term_exit')
    st = read_kv_file(os.path.join(tmp2, 'aipd.stats'))
    disp = _iget(st, 'canary_dispatched')
    can_nonzero = [k for k in st if k.startswith('canary_')
                   and _iget(st, k) not in (0, None)]
    rows = read_shadow_rows(os.path.join(tmp2, 'shadow'))
    exec_nonzero = [s for e in rows.values() for s in e['executed']
                    if s not in (0, None)]
    b.check('b4_m1_equiv',
            ok and disp in (0, None) and not can_nonzero
            and not exec_nonzero and len(rows) >= len(labeled),
            'decisions 够=%s canary_dispatched=%s canary 非零键=%s '
            'executed 非零=%d 行=%d'
            % (ok, disp, can_nonzero or '无', len(exec_nonzero),
               len(rows)))
    # --integration 附加：canary 键在场且 ENABLED=0 显式——Lane-A 面上
    # 同样 M1 等价（canary_dispatched=0 显式键）
    if integration:
        tmp3 = tempfile.mkdtemp(prefix='m2-b4i-', dir=td)
        conf3 = os.path.join(tmp3, 'aipd.conf')
        table, _sha = build_aiptbl(rules)
        tpath = os.path.join(tmp3, 'b.bin')
        with open(tpath, 'wb') as fh:
            fh.write(table)
        write_conf(conf3, tmp3, poll_hz=1000,
                   extra=['CANARY_ENABLED=0', 'CANARY_TABLE=%s' % tpath])
        write_labeled_jsonl(os.path.join(tmp3, 'mock_feats.jsonl'),
                            gen_labeled(rules)[:B4_N_DECISIONS])
        proc, _pid = start_aipd(aipd, conf3, tmp3, b)
        if proc is None:
            b.check('b4_enabled0_explicit', False, 'aipd 未能起')
            return None
        ok = wait_decisions(os.path.join(tmp3, 'aipd.stats'),
                            B4_N_DECISIONS, proc)
        stop_graceful(proc, b, name='b4i_term_exit')
        st3 = read_kv_file(os.path.join(tmp3, 'aipd.stats'))
        rows3 = read_shadow_rows(os.path.join(tmp3, 'shadow'))
        exec3 = [s for e in rows3.values() for s in e['executed']
                 if s not in (0, None)]
        b.check('b4_enabled0_explicit',
                ok and _iget(st3, 'canary_dispatched') == 0 and not exec3,
                'canary_dispatched=%s executed 非零=%d'
                % (_iget(st3, 'canary_dispatched'), len(exec3)))
    return None


# --------------------------------------------- B5 table-verify ----
def acct_b5(aikctl, rules, td, b, aipd=None, integration=False):
    print('[B5 table-verify] python 侧（aikctl）现在自测；C 侧（aipd '
          '加载器经 startup）%s' % ('集成期跑' if not integration
                                    else '随跑'))
    tmp = tempfile.mkdtemp(prefix='m2-b5-', dir=td)
    good, sha = build_aiptbl(rules)
    ok_path = os.path.join(tmp, 'spec_table.bin')
    with open(ok_path, 'wb') as fh:
        fh.write(good)
    # 合法表
    rc, out, err = aikctl_run(aikctl, ['aipd', 'table-verify', ok_path])
    b.check('b5_py_valid',
            rc == 0 and ('ok=1' in out) and (sha in out),
            'rc=%d sha=%s…%s' % (rc, sha[:8],
                                 ('；stderr: ' + err.strip()[-120:])
                                 if rc else ''))
    # 三种非法（与 C 加载器同裁定：翻转体字节/截断/坏 magic → 拒）
    for tag, data in (('flip', corrupt_body_byte(good)),
                      ('trunc', good[:-13]),
                      ('magic', b'XIPDBL\0\0' + good[8:])):
        p = os.path.join(tmp, 'bad_%s.bin' % tag)
        with open(p, 'wb') as fh:
            fh.write(data)
        rc, _out, err = aikctl_run(aikctl, ['aipd', 'table-verify', p])
        b.check('b5_py_%s_rejected' % tag, rc == 1,
                'rc=%d%s' % (rc, ('；' + err.strip()[-120:])
                             if err.strip() else ''))
    # 缺席文件诚实拒
    rc, _out, _err = aikctl_run(
        aikctl, ['aipd', 'table-verify', os.path.join(tmp, 'nope.bin')])
    b.check('b5_py_missing_rejected', rc == 1, 'rc=%d' % rc)
    if not integration or aipd is None:
        print('  注: C 侧对拍=集成期（Lane-A CANARY_TABLE 加载面合入后）'
              '——同三种非法构造已冻结于本台架（b3 共享）。')
        return None
    # C 侧：CANARY_TABLE=合法表 startup OK + stats canary_table=file:<sha8>
    tmp2 = tempfile.mkdtemp(prefix='m2-b5c-', dir=td)
    conf = os.path.join(tmp2, 'aipd.conf')
    write_conf(conf, tmp2, poll_hz=1000,
               extra=['CANARY_ENABLED=0', 'CANARY_TABLE=%s' % ok_path])
    write_labeled_jsonl(os.path.join(tmp2, 'mock_feats.jsonl'),
                        gen_labeled(rules)[:8])
    proc, _pid = start_aipd(aipd, conf, tmp2, b)
    if proc is None:
        b.check('b5_c_loader_ok', False, 'aipd 未能起（C 加载器拒载?）')
        return None
    time.sleep(1.5)
    st = read_kv_file(os.path.join(tmp2, 'aipd.stats'))
    stop_graceful(proc, b, name='b5c_term_exit')
    b.check('b5_c_loader_ok',
            st.get('canary_table') == 'file:%s' % sha[:8],
            'canary_table=%s（期 file:%s）' % (st.get('canary_table'),
                                               sha[:8]))
    return None


# --------------------------------- B6 aikctl release/rollback ----
def acct_b6(aikctl, rules, td, b):
    print('[B6 release/rollback] 台账回合（沙箱 root+conf，零全局副作用）')
    tmp = tempfile.mkdtemp(prefix='m2-b6-', dir=td)
    root = os.path.join(tmp, 'root')
    conf = os.path.join(tmp, 'etc', 'aipd.conf')
    os.makedirs(os.path.dirname(conf), exist_ok=True)
    table, sha = build_aiptbl(rules)
    ok_path = os.path.join(tmp, 'spec_table.bin')
    with open(ok_path, 'wb') as fh:
        fh.write(table)
    bad, _sha2 = build_aiptbl(rules)
    bad_path = os.path.join(tmp, 'bad_magic.bin')
    with open(bad_path, 'wb') as fh:
        fh.write(b'XIPDBL\0\0' + bad[8:])
    with open(conf, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join([
            '# m2_bench B6 沙箱 conf（镜像出厂 aipd.conf 结构+注释态 '
            'canary 键，§6 双生纪律同款）',
            'FEAT_SOURCE=mock',
            'FEAT_MOCK_FILE=%s/mock.jsonl' % tmp,
            'POLL_HZ=10',
            'MODEL_TABLE=builtin',
            'SHADOW=1',
            'PARQUET_DIR=%s/shadow' % tmp,
            'COMPARE_ENABLED=0',
            'STATS_INTERVAL_SEC=1',
            'STATS_FILE=%s/aipd.stats' % tmp,
            'PID_FILE=%s/aipd.pid' % tmp,
            'LOCK_FILE=%s/aipd.lock' % tmp,
            '# ---- 金丝雀（M2 出厂注释态） ----',
            '#CANARY_ENABLED=0',
            '#CANARY_TABLE=',
        ]) + '\n')
    with open(os.path.join(tmp, 'mock.jsonl'), 'w',
              encoding='utf-8', newline='\n') as fh:
        for vec, _i, _a, _t in gen_labeled(rules)[:4]:
            fh.write(json.dumps(vec) + '\n')

    def conf_bytes():
        with open(conf, 'rb') as fh:
            return fh.read()

    def active_kv():
        out = {}
        for ln in conf_bytes().decode('utf-8').splitlines():
            s = ln.strip()
            if s and not s.startswith('#') and '=' in s:
                k, v = s.split('=', 1)
                out[k.strip()] = v.strip()
        return out

    def ledger():
        try:
            with open(os.path.join(root, 'release.json'),
                      encoding='utf-8') as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    sha8 = sha[:8]
    dest = os.path.join(root, 'tables', 'spec_table-%s.bin' % sha8)
    # ① 无 --yes 拒（W2 硬门；conf/tables 零写）
    c0 = conf_bytes()
    rc, _out, err = aikctl_run(aikctl, ['aipd', 'release', ok_path,
                                        '--stage', 'shadow',
                                        '--conf', conf], root=root)
    b.check('b6_no_yes_refused', rc == 2,
            'rc=%d%s' % (rc, ('；' + err.strip().splitlines()[-1][:100])
                         if err.strip() else ''))
    b.check('b6_no_yes_nowrite',
            conf_bytes() == c0 and not os.path.exists(dest),
            'conf 零写+tables 未落')
    # ② 坏表拒（verify 先行——表/台账/conf 零写）
    rc, _out, _err = aikctl_run(aikctl, ['aipd', 'release', bad_path,
                                         '--stage', 'shadow', '--yes',
                                         '--conf', conf], root=root)
    b.check('b6_corrupt_rejected',
            rc == 1 and not os.path.exists(dest) and ledger() is None,
            'rc=%d dest=%s ledger=%s' % (rc, os.path.exists(dest),
                                         ledger() is not None))
    # ③ release shadow
    rc, out, _err = aikctl_run(aikctl, ['aipd', 'release', ok_path,
                                        '--stage', 'shadow', '--yes',
                                        '--conf', conf], root=root)
    kv = active_kv()
    led = ledger()
    mode = (os.stat(dest).st_mode & 0o777) if os.path.exists(dest) else -1
    b.check('b6_release_shadow',
            rc == 0 and os.path.isfile(dest) and mode == 0o600
            and kv.get('CANARY_TABLE') == dest
            and kv.get('CANARY_ENABLED') == '0',
            'rc=%d dest=%s mode=%o CANARY_TABLE=%s ENABLED=%s'
            % (rc, os.path.exists(dest), mode, kv.get('CANARY_TABLE'),
               kv.get('CANARY_ENABLED')))
    b.check('b6_ledger_shadow',
            led is not None
            and led.get('schema') == 'aikernel.aipd/release/1'
            and led.get('stage') == 'shadow'
            and led.get('name') == 'spec_table'
            and led.get('table_sha256') == sha
            and len(led.get('history', [])) >= 1,
            'schema=%s stage=%s sha=%s… history=%d'
            % (led.get('schema'), led.get('stage'),
               (led.get('table_sha256') or '?')[:8],
               len((led or {}).get('history', []))))
    txt = conf_bytes().decode('utf-8')
    b.check('b6_pre_comment_kept',
            '# pre ' in txt and '#CANARY_TABLE=' in txt,
            'pre 行注释在场+原注释态行保留')
    # ④ release canary（ENABLED=1；台账 stage 变更+history 追加）
    rc, _out, _err = aikctl_run(aikctl, ['aipd', 'release', ok_path,
                                         '--stage', 'canary', '--yes',
                                         '--conf', conf], root=root)
    kv = active_kv()
    led = ledger()
    b.check('b6_release_canary',
            rc == 0 and kv.get('CANARY_ENABLED') == '1'
            and kv.get('CANARY_TABLE') == dest
            and led.get('stage') == 'canary'
            and len(led.get('history', [])) >= 2,
            'rc=%d ENABLED=%s stage=%s history=%d'
            % (rc, kv.get('CANARY_ENABLED'), led.get('stage'),
               len(led.get('history', []))))
    # ⑤ 同内容重发布=同 dest（sha8 派生名幂等）
    rc, out2, _err = aikctl_run(aikctl, ['aipd', 'release', ok_path,
                                         '--stage', 'canary', '--yes',
                                         '--conf', conf], root=root)
    dest2 = re.search(r'dest=(\S+)', out2)
    b.check('b6_republish_idempotent',
            rc == 0 and dest2 is not None and dest2.group(1) == dest,
            'dest=%s（期 %s）' % (dest2.group(1) if dest2 else '?', dest))
    # 重复键守卫（aipd conf 契约：重复键=拒——编辑器不得产出重复）
    kv_now = [ln for ln in conf_bytes().decode('utf-8').splitlines()
              if ln.startswith('CANARY_TABLE=')]
    b.check('b6_no_dup_keys', len(kv_now) == 1,
            '活跃 CANARY_TABLE 行=%d（期 1——多次 release 原位改不追加）'
            % len(kv_now))
    # ⑥ rollback 第一发：布防不执行
    c_pre = conf_bytes()
    rc, _out, _err = aikctl_run(aikctl, ['aipd', 'rollback',
                                         '--conf', conf], root=root)
    b.check('b6_rollback_arm',
            rc == 1 and conf_bytes() == c_pre
            and os.path.exists(os.path.join(root, 'rollback.arm.json')),
            'rc=%d conf 不变=%s 布防在场=%s'
            % (rc, conf_bytes() == c_pre,
               os.path.exists(os.path.join(root, 'rollback.arm.json'))))
    # ⑦ rollback --yes：conf 复原 builtin+台账回退+tables 留档
    rc, _out, _err = aikctl_run(aikctl, ['aipd', 'rollback', '--yes',
                                         '--conf', conf], root=root)
    kv = active_kv()
    led = ledger()
    hist_actions = [h.get('action') for h in led.get('history', [])]
    b.check('b6_rollback_restored',
            rc == 0 and kv.get('CANARY_TABLE') == ''
            and kv.get('CANARY_ENABLED') == '0'
            and led.get('stage') == 'builtin'
            and 'rollback' in hist_actions
            and os.path.isfile(dest),
            'rc=%d CANARY_TABLE=%r ENABLED=%s stage=%s rollback 行=%s '
            '表留档=%s'
            % (rc, kv.get('CANARY_TABLE'), kv.get('CANARY_ENABLED'),
               led.get('stage'), 'rollback' in hist_actions,
               os.path.isfile(dest)))
    # ⑧ 未布防 --yes 拒（双发确认门第二面）
    rc, _out, _err = aikctl_run(aikctl, ['aipd', 'rollback', '--yes',
                                         '--conf', conf], root=root)
    b.check('b6_rollback_unarmed_refused', rc == 1, 'rc=%d' % rc)
    # ⑨ status 冒烟（stats 缺席=诚实 rc1；台账/旋钮行在场）
    rc, out, _err = aikctl_run(aikctl, ['aipd', 'status', '--conf', conf],
                               root=root)
    b.check('b6_status_smoke',
            rc == 1 and 'AIPD_STATUS' in out and 'stage=builtin' in out
            and 'ledger:' in out and 'knob:' in out,
            'rc=%d（stats 缺席诚实 1）状态行/台账/旋钮行在场=%s/%s/%s'
            % (rc, 'AIPD_STATUS' in out, 'stage=builtin' in out,
               'knob:' in out))
    return None


# ------------------------------------------------------------- 主 ----
def preflight(aipd, aikctl, spec_path):
    bad = []
    if not (os.path.isfile(aipd) and os.access(aipd, os.X_OK)):
        bad.append('aipd 件缺失或不可执行: %s（agent/ai/aipd/ 未 make？'
                   '——如实 FAIL 不跳过）' % aipd)
    if not os.path.isfile(aikctl):
        bad.append('aikctl 件缺失: %s' % aikctl)
    if pyarrow is None:
        bad.append('pyarrow 缺席（B1/B4 影子深查必需——pip install '
                   'pyarrow）')
    try:
        rules = load_spec(spec_path)
        if not 1 <= len(rules) <= TABLE_RULES_MAX:
            bad.append('table_spec.json rules=%d 越界' % len(rules))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        bad.append('table_spec.json 不可解析（%s）: %s' % (spec_path, exc))
        rules = None
    return bad, rules


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='m2_bench',
        description='M2 金丝雀/A-B/签名表/自动回退台架（AIPD-M2-DESIGN '
                    '§7 B1-B6；B1/B4/B5-python/B6 现在跑，B2/B3/B5-C 依'
                    '赖 Lane-A CANARY_TABLE 面 --integration 跑）')
    ap.add_argument('--aipd', default=None,
                    help='aipd（默认 $AIK_AIPD_BIN 或仓内 ../aipd/aipd）')
    ap.add_argument('--aikctl', default=None,
                    help='aikctl（默认 $AIKCTL 或仓内 ../aikctl/aikctl）')
    ap.add_argument('--integration', action='store_true',
                    help='加跑 B2/B3/B5-C 侧（Lane-A CANARY_TABLE 面合入'
                    '后由主会话亲跑；M1 树上会如实红）')
    ap.add_argument('--keep', action='store_true', help='保留临时目录（排障）')
    args = ap.parse_args(argv)
    aipd = args.aipd or os.environ.get('AIK_AIPD_BIN') or \
        os.path.join(AGENT, 'aipd', 'aipd')
    aikctl = args.aikctl or os.environ.get('AIKCTL') or \
        os.path.join(AGENT, 'aikctl', 'aikctl')
    spec_path = os.path.join(AGENT, 'aipd', 'table_spec.json')
    print('M2 bench aipd=%s aikctl=%s spec=%s（pyarrow=%s '
          'integration=%s）'
          % (aipd, aikctl, spec_path, '有' if pyarrow else '无',
             args.integration))
    bad, rules = preflight(aipd, aikctl, spec_path)
    if bad:
        for ln in bad:
            print('FAIL ' + ln)
        print('M2_BENCH ok=0 fail=1')
        return 1
    per = {}
    td = tempfile.mkdtemp(prefix='m2-bench-')
    try:
        accounts = [
            ('b1', lambda b: acct_b1(aipd, rules, td, b)),
            ('b4', lambda b: acct_b4(aipd, rules, td, b,
                                     integration=args.integration)),
            ('b5', lambda b: acct_b5(aikctl, rules, td, b, aipd=aipd,
                                     integration=args.integration)),
            ('b6', lambda b: acct_b6(aikctl, rules, td, b)),
        ]
        if args.integration:
            accounts[1:1] = [
                ('b2', lambda b: acct_b2(aipd, rules, td, b)),
                ('b3', lambda b: acct_b3(aipd, rules, td, b)),
            ]
        for name, fn in accounts:
            b = Bench()
            try:
                fn(b)
            except Exception as exc:            # noqa: BLE001 —— 如实记账
                b.check('%s_account_crash' % name, False,
                        '账户异常: %r' % exc)
            per[name] = (b.ok, b.fail)
        print('M2_ACCOUNTS ' + ' '.join(
            '%s=%d/%d' % (k, v[0], v[0] + v[1]) for k, v in per.items()))
        if not args.integration:
            print('M2_DEFERRED integration_pending=b2_ab,b3_signature,'
                  'b5_c_side（Lane-A CANARY_TABLE 面合入后主会话亲跑：'
                  'python3 tests/m2_bench.py --integration）')
        ok = sum(v[0] for v in per.values())
        fail = sum(v[1] for v in per.values())
        print('M2_BENCH ok=%d fail=%d' % (ok, fail))
        return 0 if fail == 0 else 1
    finally:
        if args.keep:
            print('KEEP td=%s' % td)
        else:
            shutil.rmtree(td, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
