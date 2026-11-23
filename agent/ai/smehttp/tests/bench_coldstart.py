#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
bench_coldstart.py - AIF-06 记忆服务（aikd）冷启规模基线

（开发/测试工具链，Python；出厂件本体仍是 C 的 aikd，本脚本不进镜像。）

量什么
------
「冷启」= 进程启动（Popen）到 `GET /health` 首次成功。aikd 的启动序
（agent/ai/smehttp/main.c）：读配置 → aik_engine_new → 快照存在则**同步**
aik_engine_load（main.c:412-438）→ 绑定监听（:464）→ --import-seed 种子
差量导入（:501-508）→ 打印 LISTENING（:521）→ serve 循环。加载/导入全部
完成后才有第一个响应，所以「冷启耗时」= 加载（或种子导入）+ exec/动态
链接。另记「监听就绪」= connect() 首次成功的时刻：口径 a 下它紧跟加载
完成，口径 b 下它紧跟进程起来（之后才是种子导入）。

三种口径
--------
  a   开启持久化（persistence.enabled=true，WAL）且已有 N 条快照可加载：
      走同步 aik_engine_load 路径（json[.gz] 快照 + npz 向量边车）。
  b   出厂口径：persistence.enabled=false + `--import-seed`（N 条种子，
      空库首启）。storage.autosave 取仓内 smeconfig 默认值 true
      （每 100 次写操作存一次快照；种子导入是逐条 aik_engine_add）。
  b0  对照：同 b 但 storage.autosave=false——剥离「导入途中反复存盘」
      的成本，看纯导入耗时。

每档重复 --reps 次取中位数；记录 RSS 峰值（/proc/<pid>/status 的
VmHWM，取到 /health 成功那一刻的高水位）与快照文件大小。

怎么造数（不需 root、不依赖任何 Python 包，只用标准库）
------------------------------------------------------
  a  ：持久化配置下起一个 aikd，`POST /import` 分块灌入 N 条
       （服务端请求体上限 8 MiB，http.c 头注；本脚本每块 ≤6 MiB）。
       WAL 开启时 aik_engine_import 结束即 checkpoint（engine.c
       aik_engine_import 尾部），落 engine.json.gz + 向量边车。
  b/b0：同一批文本另存成 JSONL 作 `--import-seed`（seed.c 逐行 JSON，
       至少含 text）。

文本是合成数据：长度按出厂种子文件实测分布取对数正态
（/usr/local/share/aikernel/sme-seed.jsonl：min 735 / 中位 1284 /
max 6076 字节），内容为运维词表的随机拼接。文本长度只影响口径 b/b0
的导入耗时（要算哈希嵌入），不影响口径 a 的加载耗时（向量在 npz 里）。

用法
----
  python3 agent/ai/smehttp/tests/bench_coldstart.py                 # 全量
  python3 agent/ai/smehttp/tests/bench_coldstart.py --sizes 500,1000 --reps 1   # 冒烟
  python3 agent/ai/smehttp/tests/bench_coldstart.py --modes a,b --json /tmp/x.json

退出码：0 全部成功；1 有任一档失败或超时（结果仍会输出）；2 参数错误。
临时数据在 /tmp 下自建自清（--keep 保留），临时起的 aikd 进程用完即杀
（只杀本脚本 Popen 出来的 pid）。

实测记录（2026-11-24，打版机 L1：i9-13900HX 宿主上的 8 vCPU / 7.9GB 虚机，
同期另有 3 路智能体在构建，loadavg 1–2；aikd 由 agent/ai/smehttp -j1 构建，
sha256 713b508b…）。冷启秒数为中位数，括号内是次数；RSS 是 VmHWM。

  口径 a（持久化开 + 快照加载）
    1 千    0.02 s    14 MiB   快照 0.8 MiB   （3 次）
    1 万    0.35 s   117 MiB   快照 7.8 MiB   （3 次）
    10 万  20.49 s  1175 MiB   快照 79.2 MiB  （3 次；20.42–21.04）
    15 万  造数失败：分块 /import 第 34 块返回 500（引擎失败），最后一个
           成功检查点 128,231 条；根因未定位
  口径 b0（持久化关 + --import-seed，autosave=false）
    1 千    1.84 s    12 MiB   （3 次）
    1 万   19.48 s    91 MiB   （3 次）
    2 万   47.75 s   181 MiB   （1 次）
    5 万  386.30 s   457 MiB   （1 次）
    10 万  >2100 s 未完成（35 分钟时人工终止）
  口径 b（出厂口径：持久化关 + --import-seed，autosave 取默认 true）
    1 千    2.25 s    25 MiB   （3 次）
    1 万   56.37 s   231 MiB   （3 次）
    2 万  198.16 s   485 MiB   （1 次）

读法：a 的加载耗时随 N 超线性（1 万→10 万涨 58 倍），按该段斜率外推 30 秒
约在 12 万条、60 秒约在 18 万条（外推，未实测）；出厂口径 b 的 30/60 秒线
落在实测区间内（约 6–7 千 / 约 1 万条种子）。出厂种子 248 条，导入成本
不到 1 秒。
"""

import argparse
import hashlib
import http.client
import json
import math
import os
import platform
import random
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_AIKD = os.path.abspath(os.path.join(HERE, "..", "aikd"))
DEFAULT_STATIC = os.path.abspath(os.path.join(HERE, "..", "static"))
IMPORT_CHUNK_BYTES = 6 * 1024 * 1024      # 服务端请求体上限 8 MiB
MODES = ("a", "b", "b0")
MODE_DESC = {
    "a": "持久化开（WAL）+ 已有快照可加载",
    "b": "出厂口径：持久化关 + --import-seed（autosave 默认 true）",
    "b0": "对照：持久化关 + --import-seed（autosave=false）",
}
TEXT_MEDIAN_BYTES = 1284                  # 出厂种子文件实测中位长度

CJK_POOL = [
    "进程调度", "内存压力", "输入输出", "网络接口", "防火墙规则", "系统服务",
    "定时任务", "磁盘分区", "文件系统", "内核模块", "安全策略", "日志审计",
    "资源配额", "命名空间", "沙箱隔离", "证书轮换", "备份恢复", "升级回滚",
    "电源管理", "传感器读数", "启动耗时", "依赖版本", "路由表项", "连接跟踪",
    "地址解析", "带宽限制", "缓存命中", "异常回滚", "会话跟踪", "租约签发",
    "主机名", "时区时钟", "用户账户", "用户组", "登录会话", "主密钥", "仓库源",
    "可用更新", "块设备", "逻辑卷", "磁盘健康", "网卡链路", "域名解析",
    "压力失速", "调频策略", "交换分区", "块层统计", "预读窗口", "单元文件",
]
ASCII_POOL = [
    "aikctl", "occ", "aikd", "aik-sandbox", "systemd", "networkd", "procfs",
    "sysfs", "netlink", "cgroup", "journal", "quota", "lease", "policy",
    "session", "audit", "snapshot", "checkpoint", "wal", "engine", "region",
    "vector", "hashing", "retrieval", "topk", "recall", "trace", "export",
    "import", "verify", "rollback", "rotate", "mount", "socket", "timer",
    "unit", "nftables", "dpkg", "journalctl", "resolvectl", "lsblk",
]
HEADS = ["本区负责", "何时来本区", "常见同义问法", "本区工具", "相关对象", "注意事项"]


# ---------------------------------------------------------------------------
# 合成文本
# ---------------------------------------------------------------------------

def make_text(rng, n, idx):
    """一条合成记忆（UTF-8 字节数对数正态，中位 1284，夹在 [600, 4000]）。"""
    target = int(min(4000, max(600, rng.lognormvariate(
        math.log(TEXT_MEDIAN_BYTES), 0.35))))
    out = ["[bench n=%d idx=%d] 冷启基线合成记忆" % (n, idx)]
    size = 0
    k = 0
    while size < target:
        words = []
        for _ in range(rng.randint(4, 12)):
            if rng.random() < 0.6:
                words.append(rng.choice(CJK_POOL))
            else:
                words.append(rng.choice(ASCII_POOL))
        line = "%s：%s。" % (HEADS[k % len(HEADS)], "、".join(words))
        out.append(line)
        size += len(("\n" + line).encode("utf-8"))
        k += 1
    return "\n".join(out)


def make_items(n):
    """N 条记忆对象（字段只取 AddMemoryRequest 里有的：text/metadata/tags/
    importance/source——routes.c 头注）。随机种子固定=可复现。"""
    rng = random.Random(0xA1F06 + n)
    return [{"text": make_text(rng, n, i),
             "metadata": {"kind": "bench", "n": n, "idx": i},
             "tags": ["bench"],
             "importance": 0.6,
             "source": "bench"} for i in range(n)]


def iter_import_bodies(items):
    """把记忆对象切成 ≤6 MiB 的 {"memories":[...]} 请求体（bytes）。"""
    parts = []
    size = 2
    for it in items:
        s = json.dumps(it, ensure_ascii=False)
        parts.append(s)
        size += len(s.encode("utf-8")) + 1
        if size >= IMPORT_CHUNK_BYTES:
            yield ('{"memories":[' + ",".join(parts) + "]}").encode("utf-8")
            parts = []
            size = 2
    if parts:
        yield ('{"memories":[' + ",".join(parts) + "]}").encode("utf-8")


# ---------------------------------------------------------------------------
# HTTP / 进程小件
# ---------------------------------------------------------------------------

def http_json(port, method, path, body=None, timeout=60.0):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, raw


def post_bytes(port, path, data, timeout):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.putrequest("POST", path)
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(data)))
    conn.endheaders()
    conn.send(data)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, raw


def wait_health(port, proc, max_wait_s, t0):
    """轮询到 /health 首次成功。返回 (t_listen, t_health, memories)——均为
    相对 t0 的秒。监听未起（connect 被拒）时 2ms 一轮；连上后只发一个
    请求并等到回应（种子导入期间连接会被内核排进 backlog，不重连）。"""
    deadline = t0 + max_wait_s
    while True:
        if proc.poll() is not None:
            raise RuntimeError("aikd 提前退出 rc=%d" % proc.returncode)
        now = time.perf_counter()
        if now > deadline:
            raise TimeoutError("等待 /health 超过 %ds" % max_wait_s)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(min(0.2, max(0.01, deadline - now)))
        try:
            s.connect(("127.0.0.1", port))
        except (ConnectionRefusedError, socket.timeout, OSError):
            s.close()
            time.sleep(0.002)
            continue
        t_listen = time.perf_counter()
        s.settimeout(max(1.0, deadline - t_listen))
        try:
            s.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                      b"Connection: close\r\n\r\n")
            buf = b""
            t_health = None
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if t_health is None and b"\r\n\r\n" in buf:
                    t_health = time.perf_counter()
        finally:
            s.close()
        ok_200 = (buf.startswith(b"HTTP/1.1 200")
                  or buf.startswith(b"HTTP/1.0 200"))
        if t_health is None or not ok_200:
            raise RuntimeError("/health 首答异常：%r" % buf[:200])
        _head, _, body = buf.partition(b"\r\n\r\n")
        try:
            obj = json.loads(body.decode("utf-8"))
        except ValueError:
            raise RuntimeError("/health 响应体不是 JSON：%r" % body[:200])
        if obj.get("status") != "ok":
            raise RuntimeError("/health status=%r" % obj.get("status"))
        return t_listen - t0, t_health - t0, int(obj.get("memories", -1))


def read_status(pid):
    out = {}
    try:
        with open("/proc/%d/status" % pid, "r", encoding="ascii",
                  errors="replace") as f:
            for line in f:
                if line.startswith(("VmHWM:", "VmRSS:")):
                    k, v = line.split(":", 1)
                    out[k] = int(v.strip().split()[0])      # kB
    except OSError:
        pass
    return out


def dir_stat(path):
    """{相对路径: (bytes, mtime_ns)}——只数普通文件。"""
    out = {}
    for root, _dirs, files in os.walk(path):
        for name in files:
            p = os.path.join(root, name)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            st = os.stat(p)
            out[os.path.relpath(p, path)] = (st.st_size, st.st_mtime_ns)
    return out


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def child_env():
    """不继承会改配置的环境变量（main.c：SME_* / AIKD_DATA_DIR）。"""
    return {k: v for k, v in os.environ.items()
            if not k.startswith("SME_") and k != "AIKD_DATA_DIR"}


class Bench:
    def __init__(self, args):
        self.a = args
        self.workdir = args.workdir or tempfile.mkdtemp(
            prefix="aik-bench-coldstart-", dir="/tmp")
        self.rng_port = random.Random()
        self.procs = set()
        self.stopped = False
        self.rows = []
        self.items = {}
        self.seed_written = {}
        self.gen_info = {}
        self.log("workdir=%s" % self.workdir)

    def log(self, msg):
        sys.stderr.write("[%s] %s\n"
                         % (datetime.now().strftime("%H:%M:%S"), msg))
        sys.stderr.flush()

    # ---- 端口：先自己 bind 一下确认空闲（18000+ 随机，避开 8000） ----
    def pick_port(self):
        for _ in range(200):
            p = self.a.port_base + self.rng_port.randrange(self.a.port_span)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
            finally:
                s.close()
        raise RuntimeError("找不到空闲端口（port_base=%d）" % self.a.port_base)

    def spawn(self, argv_tail, log_path):
        fh = open(log_path, "wb")
        t0 = time.perf_counter()
        proc = subprocess.Popen([self.a.aikd] + argv_tail, stdout=fh,
                                stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL,
                                env=child_env())
        self.procs.add(proc)
        return proc, t0, fh

    def stop(self, proc, fh=None):
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        self.procs.discard(proc)
        if fh:
            fh.close()
        return proc.returncode

    def cleanup(self):
        for proc in list(self.procs):
            try:
                self.stop(proc)
            except Exception:
                pass
        if self.workdir and os.path.isdir(self.workdir) \
                and not self.a.keep:
            shutil.rmtree(self.workdir, ignore_errors=True)
            self.log("已清理 %s" % self.workdir)

    # ---- 配置 ----
    def write_config(self, path, port, storage, autosave, wal_enabled,
                     wal_path):
        cfg = {
            "embedding": {"provider": "hashing",
                          "model": "text-embedding-3-small", "dim": 64,
                          "base_url": "", "api_key": ""},
            "storage": {"path": storage, "autosave": autosave,
                        "autosave_interval": 100, "compress": True,
                        "backend": "json"},
            "persistence": {"enabled": wal_enabled, "wal_path": wal_path,
                            "checkpoint_every": 10, "sync_mode": "fsync",
                            "group_window_ms": 15},
            "api": {"host": "127.0.0.1", "port": port, "auth_token": ""},
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=1)

    def get_items(self, n):
        if n not in self.items:
            self.log("生成 %d 条合成记忆…" % n)
            self.items[n] = make_items(n)
        return self.items[n]

    def seed_path(self, n):
        if n not in self.seed_written:
            path = os.path.join(self.workdir, "seed-%d.jsonl" % n)
            with open(path, "w", encoding="utf-8") as f:
                for it in self.get_items(n):
                    f.write(json.dumps(it, ensure_ascii=False) + "\n")
            self.seed_written[n] = path
        return self.seed_written[n]

    def release_n(self, n):
        """一档量完：释放内存里的合成数据与 /tmp 下的落盘（数字已记进 rows）。"""
        self.items.pop(n, None)
        p = self.seed_written.pop(n, None)
        if p:
            try:
                os.remove(p)
            except OSError:
                pass
        shutil.rmtree(os.path.join(self.workdir, "a-%d" % n),
                      ignore_errors=True)

    # ---- 口径 a：造快照 + 冷启 ----
    def run_a(self, n, reps):
        base = os.path.join(self.workdir, "a-%d" % n)
        data = os.path.join(base, "data")
        os.makedirs(data, exist_ok=True)
        cfg = os.path.join(base, "sme.config.json")
        storage = os.path.join(data, "engine.json")
        wal = os.path.join(data, "wal.jsonl")
        port = self.pick_port()
        self.write_config(cfg, port, storage, True, True, wal)
        self.log("[a n=%d] 造数：持久化开，分块 /import" % n)
        proc, t0, fh = self.spawn(
            ["--config", cfg, "--host", "127.0.0.1", "--port", str(port),
             "--static-dir", self.a.static_dir],
            os.path.join(base, "gen.log"))
        nchunks = 0
        imported = 0
        gen_rss = {}
        t_gen = None
        try:
            wait_health(port, proc, 60, t0)
            t_gen = time.perf_counter()
            for body in iter_import_bodies(self.get_items(n)):
                nchunks += 1
                st, raw = post_bytes(port, "/import", body, 3600)
                if st != 200:
                    raise RuntimeError("/import 第 %d 块失败（此前已导入 %d 条）-> %d %r"
                                       % (nchunks, imported, st, raw[:200]))
                imported += int(json.loads(raw.decode("utf-8"))["imported"])
            _st, raw = http_json(port, "GET", "/health")
            mem = int(json.loads(raw.decode("utf-8"))["memories"])
            gen_rss = read_status(proc.pid)
            if mem != n or imported != n:
                raise RuntimeError("造数后 memories=%d imported=%d != %d"
                                   % (mem, imported, n))
        finally:
            gen_rc = self.stop(proc, fh)
        self.gen_info[str(n)] = {
            "chunks": nchunks, "imported": imported, "exit_rc": gen_rc,
            "gen_s": (round(time.perf_counter() - t_gen, 2)
                      if t_gen is not None else None),
            "rss_hwm_kb": gen_rss.get("VmHWM")}
        self.log("[a n=%d] 造数完成：%d 块 %.1fs VmHWM=%.1fMiB"
                 % (n, nchunks, self.gen_info[str(n)]["gen_s"] or 0,
                    (gen_rss.get("VmHWM") or 0) / 1024.0))
        if gen_rc != 0:
            raise RuntimeError("造数进程退出码 %d" % gen_rc)
        snap0 = dir_stat(data)
        for r in range(reps):
            if self.stopped:
                break
            port = self.pick_port()
            row = self.time_once(
                ["--config", cfg, "--host", "127.0.0.1", "--port", str(port),
                 "--static-dir", self.a.static_dir],
                port, n, os.path.join(base, "cold-%d.log" % r))
            row["mode"] = "a"
            row["snapshot"] = {k: v[0] for k, v in snap0.items()}
            row["snapshot_unchanged"] = (dir_stat(data) == snap0)
            self.rows.append(row)

    # ---- 口径 b / b0 ----
    def run_b(self, n, reps, autosave):
        mode = "b" if autosave else "b0"
        seed = self.seed_path(n)
        for r in range(reps):
            if self.stopped:
                break
            base = os.path.join(self.workdir, "%s-%d-%d" % (mode, n, r))
            data = os.path.join(base, "data")
            os.makedirs(data, exist_ok=True)
            cfg = os.path.join(base, "sme.config.json")
            port = self.pick_port()
            self.write_config(cfg, port, os.path.join(data, "engine.json"),
                              autosave, False, "")
            log = os.path.join(base, "cold.log")
            row = self.time_once(
                ["--config", cfg, "--host", "127.0.0.1", "--port", str(port),
                 "--static-dir", self.a.static_dir,
                 "--import-seed", seed], port, n, log)
            row["mode"] = mode
            snap = dir_stat(data)
            row["snapshot"] = {k: v[0] for k, v in snap.items()}
            # 量完即删，/tmp 不积压（数字已记进 row）
            shutil.rmtree(base, ignore_errors=True)
            self.rows.append(row)

    def time_once(self, argv_tail, port, n, log):
        proc, t0, fh = self.spawn(argv_tail, log)
        try:
            t_listen, t_health, mem = wait_health(port, proc, self.a.max_wait_s,
                                                  t0)
            rss = read_status(proc.pid)
            err = None
            if mem != n:
                err = "memories=%d != %d" % (mem, n)
        except Exception as exc:                     # 记录后继续下一档
            t_listen = t_health = None
            rss = {}
            err = "%s: %s" % (type(exc).__name__, exc)
            self.log("失败：%s" % err)
        finally:
            rc = self.stop(proc, fh)
        own = False
        try:
            with open(log, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            own = ("LISTENING %d" % port) in text
            seed_lines = [ln.strip() for ln in text.splitlines()
                          if ln.startswith("[aikd-seed]")]
        except OSError:
            seed_lines = []
        if err is None and not own:
            err = "日志里没有 LISTENING %d（端口被别的进程占了？）" % port
        row = {"n": n, "t_listen_s": t_listen, "t_health_s": t_health,
               "rss_hwm_kb": rss.get("VmHWM"), "rss_rss_kb": rss.get("VmRSS"),
               "exit_rc": rc, "error": err, "seed_lines": seed_lines[:3]}
        if err is None:
            self.log("ok：listen=%.3fs health=%.3fs VmHWM=%.1fMiB"
                     % (t_listen, t_health, (rss.get("VmHWM") or 0) / 1024.0))
        return row


# ---------------------------------------------------------------------------
# 汇总 / 外推
# ---------------------------------------------------------------------------

def fit_powerlaw(points):
    """t = c * n**b 的最小二乘（log-log）。points=[(n, t)]。"""
    xs = [math.log(n) for n, _t in points]
    ys = [math.log(t) for _n, t in points]
    k = len(xs)
    mx = sum(xs) / k
    my = sum(ys) / k
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    if sxx == 0 or k < 2:
        return None
    b = sxy / sxx
    a = my - b * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else 1.0
    return {"b": b, "c": math.exp(a), "r2": r2}


def n_at(fit, seconds):
    if not fit or fit["b"] <= 0:
        return None
    return (seconds / fit["c"]) ** (1.0 / fit["b"])


def fmt_n(v):
    """条数的紧凑写法（不带单位「条」）：1 万以上用万，1 亿以上用科学计数。"""
    if v is None:
        return "-"
    if v >= 1e8:
        return "%.3g" % v
    return "%.4g万" % (v / 1e4) if v >= 1e4 else "%.4g" % v


def extrap_sane(ex):
    """斜率被固定开销主导（指数 < 0.5）或外推到 10 亿条以上时不给数。"""
    return (ex and 0.5 <= ex["exponent"] <= 4.0 and ex["n_at_30s"]
            and ex["n_at_60s"] and ex["n_at_60s"] < 1e9)


def summarize(rows):
    out = {}
    for mode in MODES:
        sel = [r for r in rows if r["mode"] == mode and r["error"] is None]
        by_n = {}
        for r in sel:
            by_n.setdefault(r["n"], []).append(r)
        for n, rs in sorted(by_n.items()):
            ts = [r["t_health_s"] for r in rs]
            tl = [r["t_listen_s"] for r in rs]
            hw = [r["rss_hwm_kb"] for r in rs if r["rss_hwm_kb"]]
            snaps = rs[-1].get("snapshot") or {}
            out["%s/%d" % (mode, n)] = {
                "mode": mode, "n": n, "reps": len(rs),
                "t_health_s": [round(t, 3) for t in ts],
                "median_s": round(statistics.median(ts), 3),
                "min_s": round(min(ts), 3), "max_s": round(max(ts), 3),
                "t_listen_median_s": round(statistics.median(tl), 3),
                "rss_hwm_median_kb": (statistics.median(hw) if hw else None),
                "snapshot_total_bytes": sum(snaps.values()),
                "snapshot_files": snaps,
            }
    return out


def extrapolate(summary):
    out = {}
    for mode in MODES:
        pts = sorted((s["n"], s["median_s"]) for s in summary.values()
                     if s["mode"] == mode)
        if len(pts) < 2:
            continue
        fit = fit_powerlaw(pts)
        if not fit:
            continue
        out[mode] = {
            "points": [{"n": n, "median_s": t} for n, t in pts],
            "exponent": round(fit["b"], 3),
            "coef": fit["c"],
            "r2": round(fit["r2"], 4),
            "n_at_30s": n_at(fit, 30.0),
            "n_at_60s": n_at(fit, 60.0),
            "largest_measured_n": pts[-1][0],
            "largest_measured_median_s": pts[-1][1],
            "note": "外推：t = c * N^b 对各档中位数做 log-log 最小二乘；"
                    "超出实测区间的 N 仅为外推值",
        }
    return out


def render_markdown(rep):
    L = []
    L.append("# AIF-06 aikd 冷启规模基线")
    L.append("")
    L.append("- 生成时间：%s；主机 %s；内核 %s" % (
        rep["generated_at"], rep["host"]["hostname"], rep["host"]["kernel"]))
    L.append("- aikd：`%s`（%d 字节，sha256 %s…）" % (
        rep["aikd"]["path"], rep["aikd"]["size"], rep["aikd"]["sha256"][:16]))
    L.append("- 配置口径：hashing 嵌入 dim 64、json 后端、compress=true、"
             "监听 127.0.0.1:18000+ 随机端口。")
    L.append("- 冷启 = Popen 到 `GET /health` 首次成功；每档 %d 次取中位数。"
             % rep["params"]["reps"])
    L.append("- 合成文本：长度对数正态（中位 %d B），内容为运维词表随机拼接。"
             % TEXT_MEDIAN_BYTES)
    L.append("")
    L.append("| 口径 | N | 冷启中位 (s) | 最小/最大 (s) | 监听就绪中位 (s) | "
             "RSS 峰值中位 (MiB) | 快照文件 (MiB) |")
    L.append("|---|---:|---:|---:|---:|---:|---:|")
    ordered = sorted(rep["summary"].values(),
                     key=lambda s: (MODES.index(s["mode"]), s["n"]))
    for s in ordered:
        L.append("| %s：%s | %s | **%.2f** | %.2f / %.2f | %.2f | %s | %s |" % (
            s["mode"], MODE_DESC[s["mode"]], format(s["n"], ","),
            s["median_s"], s["min_s"], s["max_s"], s["t_listen_median_s"],
            ("%.1f" % (s["rss_hwm_median_kb"] / 1024.0))
            if s["rss_hwm_median_kb"] else "-",
            ("%.1f" % (s["snapshot_total_bytes"] / 1048576.0))))
    L.append("")
    L.append("## 外推（log-log 幂律拟合，非实测）")
    L.append("")
    for mode in MODES:
        ex = rep["extrapolation"].get(mode)
        if not ex:
            continue
        L.append("- %s：t = %.3g × N^%.2f（R² %.3f，实测到 N=%s 中位 %.1fs）；%s" % (
            mode, ex["coef"], ex["exponent"], ex["r2"],
            format(ex["largest_measured_n"], ","),
            ex["largest_measured_median_s"],
            ("**外推** 冷启 30s ≈ %s 条、60s ≈ %s 条"
             % (fmt_n(ex["n_at_30s"]), fmt_n(ex["n_at_60s"])))
            if extrap_sane(ex) else
            "样本太少或斜率被固定开销主导，不给外推值"))
    fails = [r for r in rep["rows"] if r["error"]]
    if fails:
        L.append("")
        L.append("## 失败/超时档")
        for r in fails:
            L.append("- %s n=%s：%s" % (r["mode"], format(r["n"], ","),
                                       r["error"]))
    return "\n".join(L) + "\n"


def host_info():
    mem = {}
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as f:
            for line in f:
                if line.startswith(("MemTotal:", "MemAvailable:")):
                    k, v = line.split(":", 1)
                    mem[k] = int(v.strip().split()[0]) // 1024   # MiB
    except OSError:
        pass
    cpu = ""
    try:
        with open("/proc/cpuinfo", "r", encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return {"hostname": platform.node(), "kernel": platform.release(),
            "cpu": cpu, "ncpu": os.cpu_count(),
            "mem_total_mib": mem.get("MemTotal"),
            "mem_available_mib": mem.get("MemAvailable")}


def parse_sizes(text):
    out = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            v = int(part)
        except ValueError:
            raise ValueError("非法档位 %r" % part)
        if v < 1 or v > 5000000:
            raise ValueError("档位 %d 超出 [1, 5000000]" % v)
        out.add(v)
    if not out:
        raise ValueError("至少给一个档位")
    return sorted(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="AIF-06 aikd 冷启规模基线（纯标准库，无需 root）")
    ap.add_argument("--aikd", default=DEFAULT_AIKD, help="aikd 二进制")
    ap.add_argument("--static-dir", default=DEFAULT_STATIC,
                    help="aikd --static-dir（缺省源码树 smehttp/static）")
    ap.add_argument("--sizes", default="1000,10000,100000",
                    help="记忆条数档位，逗号分隔")
    ap.add_argument("--reps", type=int, default=3, help="每档重复次数")
    ap.add_argument("--modes", default="a,b,b0",
                    help="口径，逗号分隔：a=持久化+快照加载；"
                         "b=出厂口径种子导入；b0=对照（autosave=false）")
    ap.add_argument("--workdir", default="", help="临时目录（缺省 /tmp 自建）")
    ap.add_argument("--json", default="", help="结果 JSON 落盘路径")
    ap.add_argument("--keep", action="store_true", help="保留临时目录")
    ap.add_argument("--max-wait-s", type=float, default=3600,
                    help="单次冷启等待上限（秒）")
    ap.add_argument("--port-base", type=int, default=18000,
                    help="监听端口段起点（避开 8000）")
    ap.add_argument("--port-span", type=int, default=1000,
                    help="监听端口段长度")
    args = ap.parse_args(argv)

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    bad = [m for m in modes if m not in MODES]
    if bad:
        ap.error("--modes 含未知口径 %r（可选 a/b/b0）" % bad)
    try:
        sizes = parse_sizes(args.sizes)
    except ValueError as exc:
        ap.error(str(exc))
    if args.reps < 1:
        ap.error("--reps 至少为 1")
    if not (os.path.isfile(args.aikd) and os.access(args.aikd, os.X_OK)):
        sys.stderr.write("bench_coldstart: aikd 不存在或不可执行：%s\n"
                         % args.aikd)
        return 2
    if not os.path.isdir(args.static_dir):
        ap.error("--static-dir 不存在：%s" % args.static_dir)

    b = Bench(args)
    load0 = os.getloadavg()
    t_start = time.perf_counter()

    def on_sig(_signum, _frame):
        b.stopped = True

    signal.signal(signal.SIGINT, on_sig)
    signal.signal(signal.SIGTERM, on_sig)

    try:
        for n in sizes:
            for mode in modes:
                if b.stopped:
                    break
                try:
                    if mode == "a":
                        b.run_a(n, args.reps)
                    elif mode == "b":
                        b.run_b(n, args.reps, True)
                    else:
                        b.run_b(n, args.reps, False)
                except Exception as exc:             # 记档后继续下一口径
                    b.log("口径 %s n=%d 失败：%s: %s"
                          % (mode, n, type(exc).__name__, exc))
                    b.rows.append({"mode": mode, "n": n, "error":
                                   "%s: %s" % (type(exc).__name__, exc)})
            b.release_n(n)
    finally:
        b.cleanup()

    summary = summarize(b.rows)
    rep = {
        "schema": "aif06-coldstart-bench/1",
        "generated_at": datetime.now().astimezone().strftime(
            "%Y-%m-%dT%H:%M:%S%z"),
        "aikd": {"path": os.path.abspath(args.aikd),
                 "size": os.path.getsize(args.aikd),
                 "sha256": sha256_file(args.aikd)},
        "host": host_info(),
        "params": {"sizes": sizes, "reps": args.reps, "modes": modes,
                   "text_median_bytes": TEXT_MEDIAN_BYTES,
                   "import_chunk_bytes": IMPORT_CHUNK_BYTES,
                   "max_wait_s": args.max_wait_s},
        "gen": b.gen_info,
        "summary": summary,
        "extrapolation": extrapolate(summary),
        "rows": b.rows,
        "loadavg_start": load0,
        "loadavg_end": os.getloadavg(),
        "wall_s": round(time.perf_counter() - t_start, 1),
        "interrupted": b.stopped,
        "workdir_kept": args.keep,
    }
    print(render_markdown(rep))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1)
        b.log("结果 JSON 已写入 %s" % args.json)
    fails = [r for r in b.rows if r["error"]]
    if fails or b.stopped:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
