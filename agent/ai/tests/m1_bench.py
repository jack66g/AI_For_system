#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M1 毫秒级快路径测尺（AIPD-M1-DESIGN §2.3；run_all 第 66 门）。

四件判据（设计册冻结，禁调期望凑绿）：
  ①p99：`aipd bench --n 10000`（mock 源+内置表，自测子命令自足）→
    解析 `AIPD_BENCH` 行的 p99_ns，断言 <1_000_000（1ms；§6 验收）。
  ②CPU：mock 源起 aipd（conf 全 mktemp 临时根，POLL_HZ=10）30s，
    /proc/<pid>/stat utime+stime 前后差折算 CPU%<1（§6 验收；clk_tck
    折算）。附TERM 优雅退出子查（§1.1 TERM 处理冻结）。
  ③不一致率口径：mock 双流 fixture（决策流+对照流各 20 行，decision_id
    对齐，5 行 hook/bias 不一致→期望 mismatch_pct=25.0）喂 aipd 的
    mismatch 计算路径——aipd 无该子命令面时退化为台架自身实现同公式
    （按 decision_id 配对比较 (hook,bias) 元组，unpaired 单列不入分母）
    断言口径一致性，报告/输出明示走了哪条路。注意：这是口径演示，
    真值率=rig/VM E2E 登记（§2.3 原文），本门不冒充真值。
  ④降级演练：起 aipd→SIGKILL→断言 lock 释放（flock 非阻塞可获）/
    stats 终态（SIGKILL 无终笔：最后周期快照静止，3s 双读一致）/
    影子目录无 ACT 痕迹（文件全 shadow_NNNN.parquet 命名+stats 无
    act/executed>0 计数；有 pyarrow 时深查 source 列恒 aipd_shadow）/
    参数面零写（/sys/kernel/ai/policy 只读快照 hash 前后不变——宿主
    无该面则该项如实 SKIP 标注，§2.3 原文）。

前置自检缺件=FAIL 不跳过（aipd 未 make=如实红——Lane-A 未合入的树上
本门如实红，期望冻结不因工树态调低，c3 台同款纪律）。
aipd 件解析：--aipd > $AIK_AIPD_BIN > 仓内 ../aipd/aipd（门测当前构建）。
禁止 import 其他台架模块（run_cmd 环境钉教训）——本台架自带助手。
输出：末行 `M1_BENCH ok=N fail=M`（四件分账 `M1_ACCOUNTS …` 随前）。
退出码：零 fail→0 否则 1。
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.dirname(HERE)

P99_LIMIT_NS = 1_000_000          # 1ms（§6 验收冻结）
CPU_LIMIT_PCT = 1.0               # <1%（§6 验收冻结）
CPU_WINDOW_SEC = 30.0             # §2.3 冻结 30s 窗
N_DECISIONS = 10_000
MISMATCH_ROWS = 20
MISMATCH_DIFF = 5                 # 期望 25.0%
POLICY_SYS = '/sys/kernel/ai/policy'
SHADOW_NAME_RE = re.compile(r'^shadow_\d{4}\.parquet$')
BENCH_LINE_RE = re.compile(r'^AIPD_BENCH\b')
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*([^\s]+)')

try:
    import pyarrow.parquet          # 深查可选件（缺=浅查+注明，非 FAIL）
except ImportError:
    pyarrow = None


# ------------------------------------------------------------- 助手 ----
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


def parse_kv_line(line):
    return dict(KV_RE.findall(line))


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


def proc_ticks(pid):
    """/proc/<pid>/stat utime+stime（字段 14/15，tick）——comm 含空格故
    按最后一个 ')' 切分。"""
    with open('/proc/%d/stat' % pid, encoding='utf-8') as fh:
        s = fh.read()
    rest = s[s.rindex(')') + 2:].split()
    return int(rest[11]) + int(rest[12])       # utime, stime（0 基偏移 13/14−2）


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def write_conf(path, tmp, extra=None):
    """台架 conf（键沿 AIPD-M1-DESIGN §1.1+出厂 aipd.conf；全临时根零
    全局副作用——/run 三件与影子根均指 mktemp 目录）。"""
    lines = [
        '# m1_bench 台架 conf（自动生成）',
        'FEAT_SOURCE=mock',
        'FEAT_MOCK_FILE=%s/mock_feats.jsonl' % tmp,
        'POLL_HZ=10',
        'MODEL_TABLE=builtin',
        'SHADOW=1',
        'STATS_INTERVAL_SEC=%d' % (extra or {}).get('stats_interval', 2),
        # 整合修：守护键集冻结于 aipd.conf 样例（Lane-A）——影子根=
        # PARQUET_DIR（守护写 <PARQUET_DIR>/aipd/<日>/）；对照面键=
        # COMPARE_*（原 SHADOW_DIR/DECISIONS_SOURCE 为 Lane-B 先写键，
        # 未知键守护 exit 1）。
        'PARQUET_DIR=%s/shadow' % tmp,
        'COMPARE_ENABLED=0',
        'STATS_FILE=%s/aipd.stats' % tmp,
        'PID_FILE=%s/aipd.pid' % tmp,
        'LOCK_FILE=%s/aipd.lock' % tmp,
    ]
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(lines) + '\n')


def write_mock_feats(path, n=64):
    """mock 特征流（字段=ai_feature_vec 镜像，AIKernel/senses/ai_features.h
    冻结 schema）；值横跨三规则阈值两侧（影子行会真实产生）。"""
    now = time.time_ns()
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        for i in range(n):
            fh.write(json.dumps({
                'seq': i + 1,
                'ts': now + i * 100_000_000,
                'lat_ewma_ns': (2_000_000 + (i % 12) * 2_000_000),
                'iowait_pct': 5 + (i % 13) * 5,
                'psi_mem_some': 200 + (i % 9) * 250,
                'cache_misses': 0,
                'valid_bits': 7,
                'rsv': 0,
            }) + '\n')


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
    else:
        pass
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


# ------------------------------------------------------- ① p99 ----
def acct_p99(aipd, b):
    print('[①p99] aipd bench --n %d' % N_DECISIONS)
    try:
        rc, out, err = run_cmd([aipd, 'bench', '--n', str(N_DECISIONS)], 120)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return b.check('bench_run', False, str(exc))
    if not b.check('bench_run', rc == 0,
                   'rc=%d%s' % (rc, ('；stderr: ' + err.strip()[:200]) if rc else '')):
        return False
    lines = [l for l in out.splitlines() if BENCH_LINE_RE.match(l.strip())]
    if not b.check('bench_line', bool(lines),
                   '' if lines else '输出无 AIPD_BENCH 行（stdout 尾: %r）'
                   % out.strip()[-200:]):
        return False
    kv = parse_kv_line(lines[-1])
    p99 = kv.get('p99_ns')
    try:
        p99 = int(p99)
    except (TypeError, ValueError):
        return b.check('p99_ns<1ms', False, 'AIPD_BENCH 行缺可解析 p99_ns: %r' % lines[-1])
    return b.check('p99_ns<1ms', p99 < P99_LIMIT_NS,
                   'p99_ns=%d（p50_ns=%s max_ns=%s，限 %d）'
                   % (p99, kv.get('p50_ns', '?'), kv.get('max_ns', '?'), P99_LIMIT_NS))


# ------------------------------------------------------- ② CPU ----
def acct_cpu(aipd, td, b):
    print('[②CPU] mock 源起 aipd，%gs 窗 utime+stime 折算 <%.0f%%'
          % (CPU_WINDOW_SEC, CPU_LIMIT_PCT))
    tmp = tempfile.mkdtemp(prefix='m1-cpu-', dir=td)
    conf = os.path.join(tmp, 'aipd.conf')
    write_conf(conf, tmp)
    write_mock_feats(os.path.join(tmp, 'mock_feats.jsonl'))
    proc, pid = start_aipd(aipd, conf, tmp, b)
    if proc is None:
        return b.check('cpu<1%', False, 'aipd 未能起（②前置失败）')
    try:
        try:
            clk = os.sysconf('SC_CLK_TCK')
        except (ValueError, OSError):
            clk = 100
        t0 = time.monotonic()
        ticks0 = proc_ticks(pid)
        time.sleep(CPU_WINDOW_SEC)
        ticks1 = proc_ticks(pid)
        wall = time.monotonic() - t0
        cpu_pct = (ticks1 - ticks0) / clk / wall * 100.0
        b.check('cpu<1%', cpu_pct < CPU_LIMIT_PCT,
                'utime+stime %dtick/%.1fs（clk_tck=%d）→ %.3f%%'
                % (ticks1 - ticks0, wall, clk, cpu_pct))
    except (OSError, ProcessLookupError) as exc:
        b.check('cpu<1%', False, '采样失败: %s' % exc)
    finally:
        stop_graceful(proc, b)
    return None


# ------------------------------------------------- ③ 不一致率口径 ----
def mismatch_bench_side(dec_path, ref_path):
    """台架侧同公式（与 aipd 滚动窗口径一致，冻结）：
    按 decision_id 配对（两侧都在=compared），(hook,bias) 元组不等=
    mismatched；mismatch_pct=100*mismatched/compared；unpaired 单列
    不入分母（缺失≠不一致，诚实分账）。"""
    def load(path):
        d = {}
        with open(path, encoding='utf-8') as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    r = json.loads(ln)
                    d[int(r['decision_id'])] = (int(r['hook']), int(r['bias']))
        return d
    dec, ref = load(dec_path), load(ref_path)
    common = set(dec) & set(ref)
    mismatched = sum(1 for k in common if dec[k] != ref[k])
    pct = 100.0 * mismatched / len(common) if common else 0.0
    unpaired = len(set(dec) - common) + len(set(ref) - common)
    return pct, len(common), mismatched, unpaired


def mismatch_via_aipd(aipd, dec_path, ref_path):
    """喂 aipd 的 mismatch 计算路径（§2.3 主路）。子命令面未冻结——
    先探 --help，再按两种参数形尝试；任一形产出可解析 mismatch_pct
    即用之，全部失败返回 None（退化为台架侧）。"""
    try:
        rc, out, err = run_cmd([aipd, 'mismatch', '--help'], 10)
        if rc != 0 or 'mismatch' not in (out + err).lower():
            return None
    except (subprocess.TimeoutExpired, OSError):
        return None
    for flags in (('--decisions', '--reference'), ('--a', '--b')):
        try:
            rc, out, err = run_cmd([aipd, 'mismatch', flags[0], dec_path,
                                    flags[1], ref_path], 30)
        except (subprocess.TimeoutExpired, OSError):
            continue
        m = re.search(r'mismatch_pct\s*[=:]\s*([0-9]+(?:\.[0-9]+)?)',
                      out + err)
        if rc == 0 and m:
            return float(m.group(1)), ' '.join(flags)
    return None


def acct_mismatch(aipd, td, b):
    print('[③不一致率口径] mock 双流 fixture（%d 行，%d 不一致→期望 %.1f%%）'
          % (MISMATCH_ROWS, MISMATCH_DIFF,
             100.0 * MISMATCH_DIFF / MISMATCH_ROWS))
    tmp = tempfile.mkdtemp(prefix='m1-mm-', dir=td)
    dec_path = os.path.join(tmp, 'decisions.jsonl')
    ref_path = os.path.join(tmp, 'reference.jsonl')
    diff_idx = set(range(3, 3 + MISMATCH_DIFF))          # i=3..7（id 2003..2007）不一致
    with open(dec_path, 'w', encoding='utf-8', newline='\n') as dec, \
         open(ref_path, 'w', encoding='utf-8', newline='\n') as ref:
        for i in range(MISMATCH_ROWS):
            did = 2000 + i
            row = {'decision_id': did, 'hook': 4 if i % 2 else 3,
                   'bias': 1 if i % 2 else 20, 'source': 'aipd_shadow'}
            dec.write(json.dumps(row) + '\n')
            if i in diff_idx:
                row = dict(row, hook=(row['hook'] + 1) % 5,
                           bias=row['bias'] + 1, source='kernel')
            else:
                row = dict(row, source='kernel')
            ref.write(json.dumps(row) + '\n')

    expected = 100.0 * MISMATCH_DIFF / MISMATCH_ROWS
    via = mismatch_via_aipd(aipd, dec_path, ref_path) if os.access(aipd, os.X_OK) else None
    if via is not None:
        got, flags = via
        path = 'aipd 子命令面（%s）' % flags
    else:
        got, compared, mismatched, unpaired = mismatch_bench_side(dec_path, ref_path)
        path = ('台架退化实现（aipd 无 mismatch 子命令面）——口径演示，'
                '真值=rig/VM E2E 登记（AIPD-M1-DESIGN §2.3）')
        b.check('mm_pairing', compared == MISMATCH_ROWS and unpaired == 0,
                'compared=%d unpaired=%d（fixture 全配对）' % (compared, unpaired))
        b.check('mm_mismatched', mismatched == MISMATCH_DIFF,
                'mismatched=%d（期望 %d）' % (mismatched, MISMATCH_DIFF))
    b.check('mm_pct=25.0', abs(got - expected) < 0.005,
            'mismatch_pct=%.3f（路=%s）' % (got, path))
    print('  口径路: %s' % path)
    return None


# ------------------------------------------------- ④ 降级演练 ----
def policy_snapshot():
    """/sys/kernel/ai/policy 只读快照 hash（缺面→None=SKIP 如实标注）。"""
    if not os.path.isdir(POLICY_SYS):
        return None
    h = hashlib.sha256()
    for root, _dirs, files in sorted(os.walk(POLICY_SYS)):
        for f in sorted(files):
            p = os.path.join(root, f)
            try:
                with open(p, 'rb') as fh:
                    h.update(p.encode() + b'\0' + fh.read() + b'\0')
            except OSError:
                h.update(p.encode() + b'\0<unreadable>\0')
    return h.hexdigest()


def shadow_act_scan(shadow_dir, stats_kv, b):
    """影子目录无 ACT 痕迹：①全部文件 shadow_NNNN.parquet 命名（§1.4
    布局）；②stats 无 act/executed>0 计数；③有 pyarrow 时深查 source
    列恒 aipd_shadow 且 executed/act_sent 类列无真值。"""
    stray, parquets = [], []
    if os.path.isdir(shadow_dir):
        for root, _dirs, files in os.walk(shadow_dir):
            for f in files:
                (parquets if SHADOW_NAME_RE.match(f) else stray).append(
                    os.path.join(root, f))
    b.check('drill_no_stray_files', not stray,
            '影子根异物: %s' % (stray[:3] or '无'))
    act_kv = {k: v for k, v in stats_kv.items()
              if re.search(r'act_|executed', k) and str(v).isdigit() and int(v) > 0}
    b.check('drill_no_act_counters', not act_kv, 'stats act 计数: %s' % (act_kv or '全 0/无'))
    if pyarrow is not None and parquets:
        src_bad, exec_bad = [], []
        for p in parquets:
            try:
                tab = pyarrow.parquet.read_table(p)
            except Exception as exc:                    # noqa: BLE001
                src_bad.append('%s:%s' % (os.path.basename(p), exc))
                continue
            cols = tab.column_names
            if 'source' in cols:
                vals = set(tab.column('source').to_pylist())
                if vals - {'aipd_shadow'}:
                    src_bad.append('%s source=%s' % (os.path.basename(p), vals))
            for c in cols:
                if re.search(r'executed|act_sent|acted', c):
                    vs = tab.column(c).to_pylist()
                    if any(v is True or v == 1 for v in vs):
                        exec_bad.append('%s.%s' % (os.path.basename(p), c))
        b.check('drill_shadow_source', not src_bad, str(src_bad[:3] or 'source 恒 aipd_shadow'))
        b.check('drill_no_executed_true', not exec_bad, str(exec_bad[:3] or '无 executed/act 真值'))
    else:
        print('  注: 影子深查跳过（%s；parquet=%d）'
              % ('无 pyarrow' if pyarrow is None else '无 parquet 件', len(parquets)))
    return None


def acct_drill(aipd, td, b):
    print('[④降级演练] 起→SIGKILL→lock/stats 终态/影子无 ACT/参数面零写')
    tmp = tempfile.mkdtemp(prefix='m1-drill-', dir=td)
    conf = os.path.join(tmp, 'aipd.conf')
    write_conf(conf, tmp, extra={'stats_interval': 1})
    write_mock_feats(os.path.join(tmp, 'mock_feats.jsonl'))
    pol0 = policy_snapshot()
    if pol0 is None:
        print('  SKIP policy_plane（宿主无 %s——§2.3 原文：如实标注跳过）' % POLICY_SYS)
    proc, pid = start_aipd(aipd, conf, tmp, b)
    if proc is None:
        b.check('drill_kill', False, 'aipd 未能起（④前置失败）')
        return None
    stats_path = os.path.join(tmp, 'aipd.stats')
    lock_path = os.path.join(tmp, 'aipd.lock')
    shadow_dir = os.path.join(tmp, 'shadow')
    # 驻留 ≥2 个心跳周期+采样若干轮：让影子建议真实产生并（若配置）
    # 落盘——「无 ACT 痕迹」断言才有实料可查（非空转绿）。
    time.sleep(3.5)
    proc.send_signal(signal.SIGKILL)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    b.check('drill_kill', not alive(pid), 'SIGKILL 后进程消失')

    # lock 释放：flock 非阻塞可获（fd 关闭即释放，双实例语义的地基）
    released = False
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            released = True
        except OSError:
            released = False
        finally:
            os.close(fd)
    except OSError:
        released = False
    b.check('drill_lock_released', released, 'flock LOCK_EX|LOCK_NB 可获')

    # stats 终态：SIGKILL 无终笔——最后周期快照静止（3s 双读一致）
    s1 = read_kv_file(stats_path)
    with open(stats_path, 'rb') as fh:
        raw1 = fh.read()
    time.sleep(3)
    with open(stats_path, 'rb') as fh:
        raw2 = fh.read()
    b.check('drill_stats_terminal', bool(s1) and raw1 == raw2,
            'stats 存在且 3s 静止（%d 键）' % len(s1))

    shadow_act_scan(shadow_dir, s1, b)

    if pol0 is not None:
        b.check('drill_policy_unchanged', policy_snapshot() == pol0,
                '%s 快照 hash 前后一致（零写）' % POLICY_SYS)
    return None


# ------------------------------------------------------------- 主 ----
def preflight(aipd):
    bad = []
    if not (os.path.isfile(aipd) and os.access(aipd, os.X_OK)):
        bad.append('aipd 件缺失或不可执行: %s（Lane-A agent/ai/aipd/ 未 make？'
                   '——如实 FAIL 不跳过）' % aipd)
    return bad


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='m1_bench',
        description='M1 毫秒级快路径测尺（AIPD-M1-DESIGN §2.3；p99/CPU/'
                    '不一致率口径/降级演练 四件）')
    ap.add_argument('--aipd', default=None,
                    help='aipd（默认 $AIK_AIPD_BIN 或仓内 ../aipd/aipd）')
    ap.add_argument('--keep', action='store_true', help='保留临时目录（排障）')
    args = ap.parse_args(argv)
    aipd = args.aipd or os.environ.get('AIK_AIPD_BIN') or \
        os.path.join(AGENT, 'aipd', 'aipd')
    print('M1 bench aipd=%s（pyarrow 深查=%s）' % (aipd, '有' if pyarrow else '无'))

    bad = preflight(aipd)
    if bad:
        for ln in bad:
            print('FAIL ' + ln)
        print('M1_BENCH ok=0 fail=1')
        return 1

    per = {}
    td = tempfile.mkdtemp(prefix='m1-bench-')
    try:
        for name, fn in (('p99', lambda b: acct_p99(aipd, b)),
                         ('cpu', lambda b: acct_cpu(aipd, td, b)),
                         ('mismatch', lambda b: acct_mismatch(aipd, td, b)),
                         ('drill', lambda b: acct_drill(aipd, td, b))):
            b = Bench()
            fn(b)
            per[name] = (b.ok, b.fail)
        print('M1_ACCOUNTS ' + ' '.join(
            '%s=%d/%d' % (k, v[0], v[0] + v[1]) for k, v in per.items()))
        ok = sum(v[0] for v in per.values())
        fail = sum(v[1] for v in per.values())
        print('M1_BENCH ok=%d fail=%d' % (ok, fail))
        return 0 if fail == 0 else 1
    finally:
        if args.keep:
            print('KEEP td=%s' % td)
        else:
            shutil.rmtree(td, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
