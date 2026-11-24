#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
test_factory_config.py - 记忆层「出厂配置」验证（MEM-FACTORY / ENG-14 前置）

证明（或证伪）并入主仓的记忆层改动在**出厂配置**下可安全随下一版出厂。
出厂配置指镜像内的 sme.config.json（0600 root，调用方先复制成可读副本）+
出厂种子 sme-seed.jsonl + 仓内 static。四组用例：

  A 出厂配置启动：GET /config（source=file / config_file / groups / presets）、
    GET /stats、中文检索（分词生效）、出厂显式键与仓内默认值的差异（只列
    键名与敏感标记，不打印值）。
  B 热重建 + 落盘 + 重启：写中文记忆 → POST /config/preset 触发
    aik_engine_rebuild → 断言 AIKD_DATA_DIR 下快照文件出现（出厂
    storage.compress=true 时实际名是 engine.json.gz，不是 engine.json）、
    内容含全部记忆 → SIGTERM 干净退出（rc=0）→ 同数据目录重启，断言预设
    配置与记忆还在。persistence.enabled=false 的落盘语义按代码核：
    最后一次 checkpoint 之后的写入不在快照里（B12 记录边界）。
  C /config/reset 在不可写目录：不可写时干净失败（200 ok:false + 可读
    错误、记忆不丢、配置文件与快照不变）；恢复可写后 reset 成功
    （source=defaults、配置文件被删、引擎重建）；外加两个变体——配置文件
    本身 0444（目录可写）、以及目录可写但工作目录/数据目录不可写
    （reset 先删配置再重建，重建失败时配置文件已丢，记录为上游同序行为）。
  D 种子导入数值校验：importance=2.0 的坏种子经 --import-seed 必须非零
    退出且不监听；POST /import 坏值整批 422（value_error，定位到条目与
    字段）；好种子导入成功且重启不翻倍。
  E MEM-02d 边界：纯默认下注册表 item 默认值已对齐 DOM（llm.model /
    llm.temperature 取上游 ed5378a，modified 不再误报；llm.base_url 按
    上游保持 ''，仍 modified=true）；坏配置文件在装载入口被注册表校验器
    拒绝（非零退出、不监听、stderr 只带键名+原因）；PUT /config 同样
    拒绝越界值。

不依赖 root：C 组默认以当前用户运行，用 0555 目录模拟「不可写」；若以
root 运行，则目录 root 属主 + setpriv --reuid=nobody 降权运行（任务书的
主口径）。两种模式都会打印实际采用的那一种。

只动标准库；临时目录自建自清（--keep 保留），只杀本脚本 Popen 的进程。
不读、不打印配置内容：GET /config 的转录只记结构（source / 组数 / 预设
键 / modified 键名），不记任何取值。

用法
----
  python3 agent/ai/smehttp/tests/test_factory_config.py \\
      --aikd agent/ai/smehttp/aikd \\
      --config /tmp/sme-factory/sme.config.json \\
      --seed ~/w7i-rootfs/usr/local/share/aikernel/sme-seed.jsonl \\
      --static agent/ai/smehttp/static \\
      --evidence /tmp/memfact-evidence

退出码：0 全部 PASS；1 有 FAIL 或异常；2 参数/环境错误。
"""

import argparse
import gzip
import hashlib
import http.client
import json
import os
import platform
import pwd
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

SENSITIVE_RE = re.compile(r"(?:^|\.)(?:[A-Za-z0-9_]*(?:api_key|auth_token|secret|password))$")
BODY_TRUNC = 600
PRESET_KEYS = ["chat", "kb_dynamic", "kb_static", "robot", "minimal", "united_static"]
PRESET_COUNTS = [17, 25, 25, 18, 17, 29]


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def file_meta(path):
    if not os.path.exists(path):
        return None
    st = os.stat(path)
    return {"size": st.st_size, "mtime_ns": st.st_mtime_ns,
            "sha256": sha256_file(path)}


def read_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def snapshot_doc(path):
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    return read_json(path)


def find_snapshot(data_dir):
    """storage.compress=true 时落 engine.json.gz，compress=false 时 engine.json。"""
    for name in ("engine.json.gz", "engine.json"):
        p = os.path.join(data_dir, name)
        if os.path.exists(p):
            return p
    return None


def dotted_keys(doc, prefix=""):
    out = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            out.extend(dotted_keys(v, (prefix + "." if prefix else "") + k))
    elif isinstance(doc, list):
        out.append(prefix)
    else:
        out.append(prefix)
    return out


def tail(path, limit=800):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return ""
    text = data.decode("utf-8", "replace").strip()
    return text[-limit:]


def force_rmtree(path):
    """C 组会把目录改成 0555：先恢复可写再删，普通用户口径也能自清。"""
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for name in dirs + files:
            try:
                os.chmod(os.path.join(root, name), 0o700)
            except OSError:
                pass
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
    shutil.rmtree(path, ignore_errors=True)


class Checker:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.failures = []

    def _emit(self, kind, name, detail=""):
        line = "%-4s %s" % (kind, name)
        if detail:
            line += " :: " + detail
        print(line, flush=True)

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            self._emit("PASS", name, detail)
        else:
            self.failed += 1
            self.failures.append(name + ((" :: " + detail) if detail else ""))
            self._emit("FAIL", name, detail)
        return ok

    def eq(self, name, got, want, detail=""):
        extra = "got %r want %r" % (got, want)
        if detail:
            extra = extra + " " + detail
        return self.check(name, got == want, extra)

    def info(self, name, detail=""):
        self._emit("INFO", name, detail)


# ---------------------------------------------------------------------------
# 服务进程
# ---------------------------------------------------------------------------
class Server:
    def __init__(self, ctx, tag, cfg_path, data_dir, cwd, port=0):
        self.ctx = ctx
        self.tag = tag
        self.cfg_path = cfg_path
        self.data_dir = data_dir
        self.cwd = cwd
        self.port_arg = port
        self.proc = None
        self.port = None
        self.listen_s = None
        self.cold_s = None
        self.out_path = os.path.join(ctx.log_dir, tag + ".out.log")
        self.err_path = os.path.join(ctx.log_dir, tag + ".err.log")
        self._outf = None
        self._errf = None

    def cmd(self):
        cmd = []
        if self.ctx.drop_priv:
            cmd += ["setpriv", "--reuid=nobody", "--regid=nogroup",
                    "--clear-groups", "--"]
        cmd += [self.ctx.aikd, "--config", self.cfg_path,
                "--import-seed", self.ctx.seed,
                "--static-dir", self.ctx.static,
                "--port", str(self.port_arg)]
        return cmd

    def env(self):
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "HOME": self.cwd,
            "TMPDIR": self.ctx.tmp,
            "AIKD_DATA_DIR": self.data_dir,
        }
        return env

    def start(self, timeout):
        os.makedirs(self.log_dir_ok(), exist_ok=True)
        self._outf = open(self.out_path, "wb")
        self._errf = open(self.err_path, "wb")
        t0 = time.monotonic()
        self.proc = subprocess.Popen(self.cmd(), cwd=self.cwd, env=self.env(),
                                     stdin=subprocess.DEVNULL,
                                     stdout=self._outf, stderr=self._errf,
                                     start_new_session=True)
        deadline = t0 + timeout
        while time.monotonic() < deadline:
            rc = self.proc.poll()
            if rc is not None:
                raise RuntimeError("%s: aikd exited rc=%d before LISTENING; stderr=%s"
                                   % (self.tag, rc, tail(self.err_path)))
            text = tail(self.out_path, 4096)
            if "LISTENING " in text:
                line = [l for l in text.splitlines() if l.startswith("LISTENING ")][-1]
                self.port = int(line.split()[1])
                self.listen_s = time.monotonic() - t0
                break
            time.sleep(0.02)
        if self.port is None:
            raise RuntimeError("%s: no LISTENING within %.1fs; stderr=%s"
                               % (self.tag, timeout, tail(self.err_path)))
        # 冷启动 = Popen 到首个 /health 200（种子导入在监听前完成，含在内）
        while time.monotonic() < deadline:
            try:
                status, body = self.request("GET", "/health", timeout=2.0)
                if status == 200:
                    self.cold_s = time.monotonic() - t0
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.02)
        if self.cold_s is None:
            raise RuntimeError("%s: /health not ready within %.1fs" % (self.tag, timeout))
        return self

    def log_dir_ok(self):
        return self.ctx.log_dir

    def request(self, method, path, body=None, timeout=30.0):
        data = None
        headers = {"Connection": "close"}
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
        finally:
            conn.close()
        obj = None
        try:
            obj = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            obj = None
        self.ctx.record_http(self.tag, method, path, body, status, obj, raw)
        return status, obj

    def get_json(self, path, want=200):
        status, obj = self.request("GET", path)
        if status != want:
            raise RuntimeError("%s: GET %s -> %d" % (self.tag, path, status))
        return obj

    def post_json(self, path, body, want=200):
        status, obj = self.request("POST", path, body)
        if status != want:
            raise RuntimeError("%s: POST %s -> %d %r" % (self.tag, path, status, obj))
        return obj

    def health(self):
        return self.get_json("/health")["memories"]

    def stop(self, timeout=30.0):
        if self.proc is None:
            return None
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
                raise RuntimeError("%s: SIGTERM did not stop aikd in %.0fs"
                                   % (self.tag, timeout))
        rc = self.proc.returncode
        if self._outf:
            self._outf.close()
            self._outf = None
        if self._errf:
            self._errf.close()
            self._errf = None
        return rc

    def kill_if_alive(self):
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.kill()
                self.proc.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for f in (self._outf, self._errf):
            if f:
                f.close()
        self._outf = self._errf = None


# ---------------------------------------------------------------------------
# 运行上下文
# ---------------------------------------------------------------------------
class Ctx:
    def __init__(self, args):
        self.args = args
        self.tmp = tempfile.mkdtemp(prefix="aikd-factory-", dir=args.tmpdir)
        os.chmod(self.tmp, 0o755)
        self.log_dir = os.path.join(self.tmp, "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        self.evidence = args.evidence or os.path.join(self.tmp, "evidence")
        os.makedirs(self.evidence, exist_ok=True)
        self.transcript_path = os.path.join(self.evidence, "http-transcript.jsonl")
        self._transcript = open(self.transcript_path, "w", encoding="utf-8")
        self.measure = {}
        self.factory_config = os.path.abspath(args.config)
        self.factory_config_sha = sha256_file(self.factory_config)
        self.factory_config_size = os.path.getsize(self.factory_config)
        self.seed_src = os.path.abspath(os.path.expanduser(args.seed))
        self.static_src = os.path.abspath(os.path.expanduser(args.static))
        self.aikd_src = os.path.abspath(args.aikd)

        self.privileged = os.geteuid() == 0
        self.drop_priv = False
        if self.privileged:
            try:
                pwd.getpwnam("nobody")
                if shutil.which("setpriv"):
                    self.drop_priv = True
                else:
                    raise RuntimeError("root run requested but setpriv not found")
            except KeyError:
                raise RuntimeError("root run requested but user 'nobody' missing")
        # 降权时子进程要能读到二进制/静态目录/种子：全部拷到临时目录
        self.stage = os.path.join(self.tmp, "stage")
        os.makedirs(self.stage, exist_ok=True)
        os.chmod(self.stage, 0o755)
        self.aikd = os.path.join(self.stage, "aikd")
        shutil.copy2(self.aikd_src, self.aikd)
        os.chmod(self.aikd, 0o755)
        self.aikd_sha = sha256_file(self.aikd)
        self.aikd_size = os.path.getsize(self.aikd)
        self.static = os.path.join(self.stage, "static")
        shutil.copytree(self.static_src, self.static, dirs_exist_ok=True)
        for root, dirs, files in os.walk(self.static):
            os.chmod(root, 0o755)
            for f in files:
                os.chmod(os.path.join(root, f), 0o644)
        self.seed = os.path.join(self.stage, "sme-seed.jsonl")
        shutil.copy2(self.seed_src, self.seed)
        os.chmod(self.seed, 0o644)
        self.seed_sha = sha256_file(self.seed)
        with open(self.seed, "rb") as f:
            self.seed_n = sum(1 for line in f if line.strip())
        self.servers = []

    # -- 证据 -------------------------------------------------------------
    def record_http(self, tag, method, path, req_body, status, obj, raw):
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "tag": tag,
                 "method": method, "path": path, "status": status}
        if path == "/config" and method == "GET" and isinstance(obj, dict):
            items = cfg_items(obj)
            entry["body"] = {
                "source": obj.get("source"),
                "config_file": obj.get("config_file"),
                "groups": len(obj.get("groups") or []),
                "presets": [p.get("key") for p in obj.get("presets") or []],
                "modified_keys": [p for p, it in items.items() if it.get("modified")],
                "sensitive_set": [p for p, it in items.items() if it.get("set") is not None],
                "_note": "config values redacted by policy",
            }
        elif obj is not None:
            text = json.dumps(obj, ensure_ascii=False)
            entry["body"] = text[:BODY_TRUNC] + ("..." if len(text) > BODY_TRUNC else "")
        else:
            entry["body"] = raw.decode("utf-8", "replace")[:BODY_TRUNC]
        if req_body is not None:
            entry["request"] = json.dumps(req_body, ensure_ascii=False)[:BODY_TRUNC]
        self._transcript.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._transcript.flush()

    def stage_config(self, group, name="sme.config.json"):
        d = os.path.join(self.tmp, group, "cfg")
        os.makedirs(d, exist_ok=True)
        # preset save / reset 都在这目录里 rename/unlink：默认让它对服务身份可写
        self.set_dir_mode(d, True)
        dst = os.path.join(d, name)
        shutil.copy2(self.factory_config, dst)
        os.chmod(dst, 0o644)
        return dst

    def start_server(self, tag, cfg, data, cwd, port=0, timeout=None):
        srv = Server(self, tag, cfg, data, cwd, port)
        srv.start(timeout or self.args.timeout)
        self.servers.append(srv)
        return srv

    def new_dir(self, group, name, writable=True):
        d = os.path.join(self.tmp, group, name)
        os.makedirs(d, exist_ok=True)
        self.set_dir_mode(d, writable)
        return d

    def set_dir_mode(self, path, writable):
        if self.privileged and self.drop_priv:
            uid = pwd.getpwnam("nobody").pw_uid
            gid = pwd.getpwnam("nobody").pw_gid
            if writable:
                os.chown(path, uid, gid)
                os.chmod(path, 0o755)
            else:
                os.chown(path, 0, 0)
                os.chmod(path, 0o555)
        else:
            os.chmod(path, 0o755 if writable else 0o555)

    def set_tree_mode(self, path, writable, file_mode=None):
        self.set_dir_mode(path, writable)
        if file_mode is not None:
            for name in os.listdir(path):
                p = os.path.join(path, name)
                if os.path.isfile(p):
                    if self.privileged and self.drop_priv:
                        os.chown(p, 0, 0)
                    os.chmod(p, file_mode)

    def factory_explicit(self):
        doc = read_json(self.factory_config)
        keys = [k for k in dotted_keys(doc) if not k.startswith("_help")]
        return doc, keys

    def finish(self):
        for srv in self.servers:
            srv.kill_if_alive()
        self._transcript.close()
        summary = {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "host": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "aikd": {"path_basename": os.path.basename(self.aikd_src),
                     "size": self.aikd_size, "sha256": self.aikd_sha},
            "factory_config": {"size": self.factory_config_size,
                               "sha256": self.factory_config_sha,
                               "_note": "content not copied or logged"},
            "factory_seed": {"records": self.seed_n, "sha256": self.seed_sha},
            "drop_priv": self.drop_priv,
            "measurements": self.measure,
            "tmp": self.tmp,
        }
        with open(os.path.join(self.evidence, "summary.json"), "w",
                  encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2, sort_keys=True)
        logs = os.path.join(self.evidence, "server-logs")
        os.makedirs(logs, exist_ok=True)
        for name in os.listdir(self.log_dir):
            shutil.copy2(os.path.join(self.log_dir, name),
                         os.path.join(logs, name))
        return summary

    def cleanup(self):
        if not self.args.keep:
            force_rmtree(self.tmp)


# ---------------------------------------------------------------------------
# 配置文档读取（只在内存中用值做断言；落盘/打印只留结构）
# ---------------------------------------------------------------------------
def cfg_items(cfg_doc):
    out = {}
    for group in cfg_doc.get("groups") or []:
        for item in group.get("items") or []:
            if "path" in item:
                out[item["path"]] = item
    return out


def cval(items, path):
    return items[path]["value"]


def is_sensitive(path):
    return bool(SENSITIVE_RE.search(path))


# ---------------------------------------------------------------------------
# A 组：出厂配置启动
# ---------------------------------------------------------------------------
def group_a(ctx, ck):
    ck.info("A0 aikd sha256=%s size=%d" % (ctx.aikd_sha[:16], ctx.aikd_size))
    cfg = ctx.stage_config("a")
    data = ctx.new_dir("a", "data")
    cwd = ctx.new_dir("a", "cwd")
    srv = ctx.start_server("a1-factory", cfg, data, cwd)
    try:
        ctx.measure["a.listen_s"] = round(srv.listen_s, 3)
        ctx.measure["a.cold_start_s"] = round(srv.cold_s, 3)
        ck.info("A1 cold_start=%.3fs listen=%.3fs port=%d"
                % (srv.cold_s, srv.listen_s, srv.port))
        ck.check("A1 seed records > 0", ctx.seed_n > 0, "records=%d" % ctx.seed_n)
        ck.eq("A2 /health memories == seed records", srv.health(), ctx.seed_n)

        stats = srv.get_json("/stats")
        top = {"memories", "regions", "splits", "merges", "consolidations",
               "compressions", "graph_edges", "provider", "policy"}
        ck.check("A3 /stats top-level keys", top.issubset(set(stats.keys())),
                 "missing=%s" % sorted(top - set(stats.keys())))
        memstats = stats.get("memories") or {}
        ck.eq("A3 /stats memories.total", memstats.get("total"), ctx.seed_n)
        ck.eq("A3 /stats memories.active", memstats.get("active"), ctx.seed_n)
        ck.check("A3 /stats provider hashing",
                 str(stats.get("provider", "")).startswith("hashing"),
                 str(stats.get("provider")))
        regions = stats.get("regions") or {}
        ck.check("A3 /stats regions.count > 0", regions.get("count", 0) > 0,
                 "regions=%s" % regions.get("count"))
        ctx.measure["a.provider"] = stats.get("provider")
        ctx.measure["a.regions"] = regions.get("count")
        ctx.measure["a.memories_total"] = memstats.get("total")
        pol = stats.get("policy") or {}
        ck.eq("A3 /stats policy.decay_enabled (factory true)",
              pol.get("decay_enabled"), True)

        cfgdoc = srv.get_json("/config")
        ck.eq("A4 /config source", cfgdoc.get("source"), "file")
        ck.eq("A4 /config config_file", os.path.realpath(cfgdoc.get("config_file", "")),
              os.path.realpath(cfg))
        groups = cfgdoc.get("groups") or []
        ck.eq("A4 /config non-empty groups", len(groups), 9,
              "10 group definitions, visualization has no registered items")
        presets = cfgdoc.get("presets") or []
        ck.eq("A4 /config presets count", len(presets), 6)
        ck.eq("A4 /config preset keys", [p.get("key") for p in presets], PRESET_KEYS)
        ck.eq("A4 /config preset value counts", [p.get("count") for p in presets],
              PRESET_COUNTS)
        ck.info("A4 groups: %s" % ",".join(g.get("key") for g in groups))

        items = cfg_items(cfgdoc)
        ck.eq("A5 /config item count", len(items), 101,
              "registry size (config_items_data.h)")
        expect = {
            "embedding.provider": "hashing",
            "embedding.dim": 64,
            "retrieval.cjk_bigram": True,
            "retrieval.top_k": 10,
            "region.auto_evolve": True,
            "policy.decay_enabled": True,
            "reinforcement.ebbinghaus_half_life_days": 7.0,
            "ranking.semantic": 0.4,
            "persistence.enabled": False,
            "storage.autosave": True,
            "storage.autosave_interval": 25,
            "storage.compress": True,
            "api.host": "127.0.0.1",
            "api.auth_token": "",
            "llm.model": "gpt-4o-mini",
            "llm.temperature": 0.3,
            "memory.consolidate_every": 8,
        }
        for path, want in expect.items():
            if path not in items:
                ck.check("A5 factory value " + path, False, "path missing")
                continue
            ck.eq("A5 factory value " + path, items[path].get("value"), want)
        ck.eq("A5 storage.path follows AIKD_DATA_DIR", cval(items, "storage.path"),
              os.path.join(data, "engine.json"))
        ck.check("A5 api.auth_token not set", items["api.auth_token"].get("set", False) is False,
                 "empty secret must not be masked/set")

        status, body = srv.request("GET", "/memories/stats")
        ck.info("A6 GET /memories/stats -> %d" % status,
                "no such route (task-book expectation); engine stats is GET /stats")
        ck.info("A6 recorded: /memories/{id} treats 'stats' as an id", "intent covered by /stats A3")

        status, body = srv.request("POST", "/memories/search", {"text": "进程调度"})
        ck.eq("A7 CJK search status", status, 200)
        ck.check("A7 CJK search hits > 0 (cjk_bigram works)",
                 bool(body) and body.get("count", 0) > 0,
                 "count=%s" % (body or {}).get("count"))

        fdoc, fkeys = ctx.factory_explicit()
        ck.check("A8 factory config explicit keys > 0", len(fkeys) > 0,
                 "explicit_keys=%d sections=%d" % (len(fkeys), len(fdoc)))
        ctx.measure["a.factory_explicit_keys"] = len(fkeys)
        sens = [k for k in fkeys if is_sensitive(k)]
        ck.info("A8 factory sensitive keys=%d: %s" % (len(sens), ",".join(sens) or "-"))
        ck.info("A8 factory config size=%d sha256=%s"
                % (ctx.factory_config_size, ctx.factory_config_sha))

        # 出厂文件里的取值 vs 仓内注册表默认值（只比、只列键名）
        diff, unregistered, equal = [], [], 0
        for key in fkeys:
            if key == "seed":
                equal += 1          # seed 是标量特例，from_json 单独覆盖
                continue
            if key not in items:
                unregistered.append(key)
                continue
            if items[key].get("value") != items[key].get("default"):
                diff.append(key)
            else:
                equal += 1
        mod = [p for p, it in items.items() if it.get("modified")]
        ctx.measure["a.factory_vs_default_diff"] = diff
        ctx.measure["a.factory_unregistered"] = unregistered
        ctx.measure["a.engine_modified_keys"] = mod
        ck.check("A8 factory keys differing from registry item defaults > 0",
                 len(diff) > 0,
                 "%d keys: %s" % (len(diff), ",".join(diff)))
        ck.info("A8 factory keys equal to registry item defaults=%d unregistered/ignored=%d"
                % (equal, len(unregistered)),
                "unregistered: %s" % (",".join(unregistered) or "-"))
        ck.info("A8 engine modified=true keys=%d: %s" % (len(mod), ",".join(mod)))
        ck.check("A8 llm.model/temperature are factory-explicit",
                 "llm.model" in fkeys and "llm.temperature" in fkeys,
                 "MEM-02d values come from the factory file")

        rc = srv.stop()
        ck.eq("A9 SIGTERM exit code", rc, 0)
        ctx.measure["a.stop_rc"] = rc
    finally:
        srv.kill_if_alive()


# ---------------------------------------------------------------------------
# B 组：热重建 + 落盘 + 重启
# ---------------------------------------------------------------------------
def group_b(ctx, ck):
    cfg = ctx.stage_config("b")
    data = ctx.new_dir("b", "data")
    cwd = ctx.new_dir("b", "cwd")
    srv = ctx.start_server("b1", cfg, data, cwd)
    srv2 = None
    try:
        ck.eq("B1 start memories == seed", srv.health(), ctx.seed_n)
        ctx.measure["b.cold_start_s"] = round(srv.cold_s, 3)
        ck.info("B1 cold_start=%.3fs" % srv.cold_s)

        ids = []
        for i, text in enumerate([
                "memfact-1125 出厂配置热重建 第一条 中文记忆",
                "memfact-1125 出厂配置热重建 第二条 batch-verify",
                "memfact-1125 出厂配置热重建 第三条 落盘检查"]):
            status, body = srv.request("POST", "/memories", {"text": text})
            ck.eq("B2 POST /memories #%d status" % (i + 1), status, 200)
            ids.append(body.get("id"))
        ck.eq("B2 memories after 3 writes", srv.health(), ctx.seed_n + 3)
        pre = find_snapshot(data)
        pre_meta = file_meta(pre) if pre else None
        ck.check("B3 autosave snapshot exists before rebuild", pre is not None,
                 "storage.autosave_interval=25 -> seed import alone triggers saves")
        if pre:
            pre_doc = snapshot_doc(pre)
            ck.info("B3 pre-rebuild snapshot %s memories=%d size=%d"
                    % (os.path.basename(pre), len(pre_doc.get("memories") or []),
                       pre_meta["size"]))
            ctx.measure["b.pre_rebuild_snapshot"] = {
                "name": os.path.basename(pre), "size": pre_meta["size"],
                "sha256": pre_meta["sha256"],
                "memories": len(pre_doc.get("memories") or [])}

        preset = srv.post_json("/config/preset", {"key": "united_static"})
        ck.eq("B4 preset ok", preset.get("ok"), True)
        ck.eq("B4 preset applied count", len(preset.get("applied") or []), 29)

        snap = find_snapshot(data)
        ck.check("B5 snapshot written under AIKD_DATA_DIR", snap is not None,
                 "data dir listing=%s" % sorted(os.listdir(data)))
        ck.check("B5 factory storage.compress=true -> engine.json.gz (not engine.json)",
                 snap is not None and snap.endswith("engine.json.gz")
                 and not os.path.exists(os.path.join(data, "engine.json")),
                 snap or "")
        if snap:
            meta = file_meta(snap)
            ctx.measure["b.snapshot"] = {"name": os.path.basename(snap),
                                         "size": meta["size"],
                                         "mtime_ns": meta["mtime_ns"],
                                         "sha256": meta["sha256"]}
            ck.info("B5 snapshot %s size=%d sha256=%s"
                    % (os.path.basename(snap), meta["size"], meta["sha256"]))
            ck.check("B5 rebuild rewrote the snapshot",
                     pre_meta is None or meta["sha256"] != pre_meta["sha256"],
                     "pre=%s post=%s"
                     % (pre_meta and pre_meta["sha256"][:16], meta["sha256"][:16]))
            doc = snapshot_doc(snap)
            mems = doc.get("memories") or []
            ck.eq("B5 snapshot memory count", len(mems), ctx.seed_n + 3)
            snap_ids = {m.get("id") for m in mems}
            ck.check("B5 snapshot contains the 3 new memories",
                     set(ids).issubset(snap_ids),
                     "missing=%s" % sorted(set(ids) - snap_ids))
            sc = doc.get("config") or {}
            ck.eq("B5 snapshot embeds preset config (decay_enabled)",
                  (sc.get("policy") or {}).get("decay_enabled"), False)
            ck.eq("B5 snapshot embeds AIKD_DATA_DIR storage.path",
                  (sc.get("storage") or {}).get("path"),
                  os.path.join(data, "engine.json"))

        ck.check("B6 config file rewritten by preset", os.path.exists(cfg))
        fdoc = read_json(cfg)
        ck.eq("B6 config file policy.decay_enabled",
              (fdoc.get("policy") or {}).get("decay_enabled"), False)
        ck.eq("B6 config file retrieval.keyword_candidates",
              (fdoc.get("retrieval") or {}).get("keyword_candidates"), 20)
        ck.eq("B6 config file ranking.semantic",
              (fdoc.get("ranking") or {}).get("semantic"), 1.0)
        ck.check("B6 config file keeps api keys empty (not printed)",
                 (fdoc.get("llm") or {}).get("api_key") == ""
                 and (fdoc.get("embedding") or {}).get("api_key") == "", "")

        cfgdoc = srv.get_json("/config")
        items = cfg_items(cfgdoc)
        ck.eq("B7 /config source after preset", cfgdoc.get("source"), "file")
        ck.eq("B7 /config decay_enabled", cval(items, "policy.decay_enabled"), False)
        ck.eq("B7 /config keyword_candidates", cval(items, "retrieval.keyword_candidates"), 20)
        ck.eq("B7 /config storage.path still under AIKD_DATA_DIR",
              cval(items, "storage.path"), os.path.join(data, "engine.json"))

        status, body = srv.request("POST", "/memories",
                                   {"text": "memfact-1125 重建之后才写的那一条"})
        ck.eq("B8 POST after rebuild status", status, 200)
        post_id = body.get("id")
        ck.eq("B8 memories after post-rebuild write", srv.health(), ctx.seed_n + 4)

        rc = srv.stop()
        ck.eq("B9 SIGTERM exit code", rc, 0)

        srv2 = ctx.start_server("b2-restart", cfg, data, cwd)
        ctx.measure["b.restart_cold_start_s"] = round(srv2.cold_s, 3)
        ck.info("B10 restart cold_start=%.3fs" % srv2.cold_s)
        n = srv2.health()
        ck.eq("B10 restart memories == last checkpoint", n, ctx.seed_n + 3)
        for i, mid in enumerate(ids):
            status, _ = srv2.request("GET", "/memories/" + mid)
            ck.eq("B10 pre-rebuild memory #%d survives restart" % (i + 1), status, 200)
        status, _ = srv2.request("GET", "/memories/" + post_id)
        ck.eq("B11 post-rebuild write is NOT on disk (persistence off)", status, 404)
        ck.info("B11 boundary: only checkpoint state survives restart",
                "seed=%d + pre-rebuild 3 = %d; post-rebuild 1 not saved"
                % (ctx.seed_n, ctx.seed_n + 3))

        cfgdoc = srv2.get_json("/config")
        items = cfg_items(cfgdoc)
        ck.eq("B12 restart source", cfgdoc.get("source"), "file")
        ck.eq("B12 restart preset config kept (decay_enabled)",
              cval(items, "policy.decay_enabled"), False)
        ck.eq("B12 restart preset config kept (keyword_candidates)",
              cval(items, "retrieval.keyword_candidates"), 20)
        ck.eq("B12 restart storage.path follows AIKD_DATA_DIR",
              cval(items, "storage.path"), os.path.join(data, "engine.json"))
        ck.eq("B12 restart presets count", len(cfgdoc.get("presets") or []), 6)
        rc = srv2.stop()
        ck.eq("B13 second SIGTERM exit code", rc, 0)
    finally:
        srv.kill_if_alive()
        if srv2 is not None:
            srv2.kill_if_alive()


# ---------------------------------------------------------------------------
# C 组：/config/reset 在不可写目录
# ---------------------------------------------------------------------------
def _prepare_c_data(ctx, group, memories):
    """起一台可写服务器：写 memories 条 + preset chat 触发 checkpoint，停。"""
    cfg = ctx.stage_config(group)
    data = ctx.new_dir(group, "data")
    cwd = ctx.new_dir(group, "cwd")
    srv = ctx.start_server(group + "-setup", cfg, data, cwd)
    try:
        ids = []
        for i in range(memories):
            status, body = srv.request("POST", "/memories",
                                       {"text": "memfact-1125 %s 准备快照 第%d条" % (group, i + 1)})
            if status != 200:
                raise RuntimeError("setup add failed: %d" % status)
            ids.append(body.get("id"))
        srv.post_json("/config/preset", {"key": "chat"})
        n = srv.health()
        rc = srv.stop()
        if rc != 0:
            raise RuntimeError("setup SIGTERM rc=%d" % rc)
    finally:
        srv.kill_if_alive()
    snap = find_snapshot(data)
    if not snap:
        raise RuntimeError("setup: no snapshot in %s" % data)
    return cfg, data, cwd, ids, n, file_meta(snap)


def group_c(ctx, ck):
    ck.info("C0 unwritable mode",
            ("root-owned 0555 + setpriv --reuid=nobody" if ctx.drop_priv
             else "owner 0555 with same-user server (no root)"))

    # ---- C1 准备快照 -----------------------------------------------------
    cfg, data, cwd, prep_ids, prep_n, prep_meta = _prepare_c_data(ctx, "c1", 4)
    ck.eq("C1 setup snapshot memory count", prep_n, ctx.seed_n + 4)
    ck.info("C1 setup snapshot %s size=%d sha256=%s"
            % (os.path.basename(find_snapshot(data)), prep_meta["size"],
               prep_meta["sha256"][:16]))
    ctx.measure["c.prep_snapshot"] = {"size": prep_meta["size"],
                                      "sha256": prep_meta["sha256"]}

    # ---- C2 目录不可写 ---------------------------------------------------
    cfg_dir = os.path.dirname(cfg)
    ctx.set_tree_mode(data, False, file_mode=0o644)
    ctx.set_tree_mode(cfg_dir, False, file_mode=0o644)
    ctx.set_dir_mode(cwd, True)
    srv = ctx.start_server("c2-readonly", cfg, data, cwd)
    try:
        ck.eq("C2 read-only dirs still load snapshot", srv.health(), ctx.seed_n + 4)
        status, body = srv.request("POST", "/memories",
                                   {"text": "memfact-1125 reset 前新写的一条"})
        ck.eq("C3 POST /memories on read-only data dir status", status, 200)
        reset_id = body.get("id")
        ck.eq("C3 memories before reset", srv.health(), ctx.seed_n + 5)

        status, body = srv.request("POST", "/config/reset")
        ck.eq("C4 reset(unwritable) HTTP status", status, 200)
        ck.eq("C4 reset(unwritable) ok", (body or {}).get("ok"), False)
        err = ((body or {}).get("errors") or {}).get("_global", "")
        ck.check("C4 reset(unwritable) returns readable error",
                 "删除配置文件" in err, err[:200])
        ctx.measure["c.reset_unwritable"] = {"http": status,
                                             "ok": (body or {}).get("ok"),
                                             "error": err}
        ck.eq("C4 reset did not delete config file", os.path.exists(cfg), True)
        ck.eq("C4 reset did not lose memories", srv.health(), ctx.seed_n + 5)
        ck.check("C4 server still alive", srv.proc.poll() is None, "")
        snap_now = find_snapshot(data)
        ck.eq("C4 snapshot unchanged", file_meta(snap_now)["sha256"], prep_meta["sha256"])
        cfgdoc = srv.get_json("/config")
        ck.eq("C4 source unchanged", cfgdoc.get("source"), "file")

        # ---- C5 恢复可写后 reset 成功 -----------------------------------
        ctx.set_tree_mode(data, True)
        ctx.set_tree_mode(cfg_dir, True)
        status, body = srv.request("POST", "/config/reset")
        ck.eq("C5 reset(writable) HTTP status", status, 200)
        ck.eq("C5 reset(writable) ok", (body or {}).get("ok"), True)
        ck.eq("C5 config file deleted", os.path.exists(cfg), False)
        ck.eq("C5 memories survive reset", srv.health(), ctx.seed_n + 5)
        cfgdoc = srv.get_json("/config")
        items = cfg_items(cfgdoc)
        ck.eq("C5 source defaults", cfgdoc.get("source"), "defaults")
        ck.eq("C5 default storage.path", cval(items, "storage.path"), "data/engine.json")
        ck.eq("C5 default persistence.enabled", cval(items, "persistence.enabled"), False)
        ck.eq("C5 presets still exposed", len(cfgdoc.get("presets") or []), 6)
        # AIKD_DATA_DIR 只在启动时重放：reset 的 checkpoint 落 CWD 相对路径
        reset_snap = os.path.join(cwd, "data", "engine.json.gz")
        ck.check("C5 reset checkpoint went to CWD-relative default path",
                 os.path.exists(reset_snap),
                 "expected at %s" % reset_snap)
        if os.path.exists(reset_snap):
            meta = file_meta(reset_snap)
            ctx.measure["c.reset_checkpoint"] = {"path": "cwd/data/engine.json.gz",
                                                 "size": meta["size"],
                                                 "sha256": meta["sha256"]}
            doc = snapshot_doc(reset_snap)
            ck.eq("C5 reset checkpoint holds in-memory memories",
                  len(doc.get("memories") or []), ctx.seed_n + 5)
            ck.info("C5 reset checkpoint written outside AIKD_DATA_DIR",
                    "size=%d sha256=%s (AIKD_DATA_DIR is a startup-only override)"
                    % (meta["size"], meta["sha256"][:16]))
        status, body = srv.request("POST", "/memories",
                                   {"text": "memfact-1125 reset 之后新写的一条"})
        ck.eq("C6 POST after reset status", status, 200)
        rc = srv.stop()
        ck.eq("C6 SIGTERM exit code", rc, 0)

        # ---- C7 重启：AIKD_DATA_DIR 快照旧于 reset checkpoint ------------
        srv3 = ctx.start_server("c7-restart", cfg, data, cwd)
        try:
            n = srv3.health()
            ck.eq("C7 restart after reset memories == old AIKD_DATA_DIR snapshot",
                  n, ctx.seed_n + 4)
            cfgdoc = srv3.get_json("/config")
            ck.eq("C7 restart source defaults (config file gone)",
                  cfgdoc.get("source"), "defaults")
            ck.eq("C7 restart storage.path follows AIKD_DATA_DIR",
                  cval(cfg_items(cfgdoc), "storage.path"),
                  os.path.join(data, "engine.json"))
            ck.info("C7 data loss on restart after reset",
                    "2 memories written after the C1 checkpoint are gone; "
                    "1 of them is inside the reset checkpoint at cwd/data, "
                    "which the next AIKD_DATA_DIR start does not read")
            ctx.measure["c.restart_after_reset_memories"] = n
            ctx.measure["c.reset_era_ids_lost"] = [reset_id]
            rc = srv3.stop()
            ck.eq("C7 SIGTERM exit code", rc, 0)
        finally:
            srv3.kill_if_alive()
    finally:
        srv.kill_if_alive()

    # ---- C8 变体：配置目录可写、配置文件本身 0444 ------------------------
    cfg8 = ctx.stage_config("c8")
    os.chmod(cfg8, 0o444)
    data8 = ctx.new_dir("c8", "data")
    cwd8 = ctx.new_dir("c8", "cwd")
    srv8 = ctx.start_server("c8-file0444", cfg8, data8, cwd8)
    try:
        ck.eq("C8 start memories", srv8.health(), ctx.seed_n)
        status, _ = srv8.request("POST", "/memories",
                                 {"text": "memfact-1125 配置文件只读变体"})
        ck.eq("C8 POST status", status, 200)
        status, body = srv8.request("POST", "/config/reset")
        ck.eq("C8 reset with 0444 config file: HTTP", status, 200)
        ck.eq("C8 reset with 0444 config file: ok", (body or {}).get("ok"), True)
        ck.eq("C8 config file deleted (unlink follows dir perms)", os.path.exists(cfg8), False)
        cfgdoc = srv8.get_json("/config")
        ck.eq("C8 source defaults", cfgdoc.get("source"), "defaults")
        ck.eq("C8 memories kept", srv8.health(), ctx.seed_n + 1)
        ck.info("C8 note",
                "file mode 0444 does not protect the file; unlink needs dir write")
        rc = srv8.stop()
        ck.eq("C8 SIGTERM exit code", rc, 0)
    finally:
        srv8.kill_if_alive()

    # ---- C9 变体：配置目录可写但 CWD/数据目录不可写 --------------------
    cfg9, data9, cwd9, prep9_ids, prep9_n, prep9_meta = _prepare_c_data(ctx, "c9", 2)
    ck.eq("C9 setup snapshot memories", prep9_n, ctx.seed_n + 2)
    os.chmod(cfg9, 0o444)
    ctx.set_tree_mode(data9, False, file_mode=0o644)
    ctx.set_dir_mode(cwd9, False)
    srv9 = ctx.start_server("c9-partial", cfg9, data9, cwd9)
    try:
        ck.eq("C9 read-only start memories", srv9.health(), ctx.seed_n + 2)
        status, _ = srv9.request("POST", "/memories",
                                 {"text": "memfact-1125 reset 部分失败变体"})
        ck.eq("C9 POST status", status, 200)
        ck.eq("C9 memories before reset", srv9.health(), ctx.seed_n + 3)
        status, body = srv9.request("POST", "/config/reset")
        ck.eq("C9 reset HTTP status", status, 200)
        ck.eq("C9 reset ok", (body or {}).get("ok"), False)
        err = ((body or {}).get("errors") or {}).get("_global", "")
        ck.check("C9 reset reports checkpoint failure", "落盘失败" in err, err[:200])
        ck.eq("C9 config file already deleted (not atomic)",
              os.path.exists(cfg9), False)
        ck.eq("C9 engine keeps old config (storage.path)",
              cval(cfg_items(srv9.get_json("/config")), "storage.path"),
              os.path.join(data9, "engine.json"))
        ck.eq("C9 memories intact", srv9.health(), ctx.seed_n + 3)
        ck.eq("C9 snapshot unchanged",
              file_meta(find_snapshot(data9))["sha256"], prep9_meta["sha256"])
        ck.info("C9 note",
                "config file is unlinked before rebuild; a failed checkpoint "
                "leaves the config gone (upstream server.py reset has same order)")
        ctx.measure["c.reset_partial_failure"] = {"http": status,
                                                  "ok": (body or {}).get("ok"),
                                                  "error": err}
        rc = srv9.stop()
        ck.eq("C9 SIGTERM exit code", rc, 0)
    finally:
        srv9.kill_if_alive()


# ---------------------------------------------------------------------------
# D 组：种子导入数值校验
# ---------------------------------------------------------------------------
def _run_exit_expected(ctx, tag, cfg, data, cwd, seed_path, timeout=120):
    out_path = os.path.join(ctx.log_dir, tag + ".out.log")
    err_path = os.path.join(ctx.log_dir, tag + ".err.log")
    cmd = []
    if ctx.drop_priv:
        cmd += ["setpriv", "--reuid=nobody", "--regid=nogroup",
                "--clear-groups", "--"]
    cmd += [ctx.aikd, "--config", cfg, "--import-seed", seed_path,
            "--static-dir", ctx.static, "--port", "0"]
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
           "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "HOME": cwd,
           "TMPDIR": ctx.tmp, "AIKD_DATA_DIR": data}
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        proc = subprocess.run(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                              stdout=out, stderr=err, timeout=timeout)
    return proc.returncode, out_path, err_path


def group_d(ctx, ck):
    # ---- D1 坏种子：--import-seed 必须先失败退出 -------------------------
    bad_dir = os.path.join(ctx.tmp, "d1")
    os.makedirs(bad_dir, exist_ok=True)
    os.chmod(bad_dir, 0o755)
    bad_seed = os.path.join(bad_dir, "bad-seed.jsonl")
    with open(bad_seed, "w", encoding="utf-8") as f:
        f.write(json.dumps({"text": "memfact-1125 坏种子对照 好条目",
                            "importance": 0.5}, ensure_ascii=False) + "\n")
        f.write(json.dumps({"text": "memfact-1125 坏种子 importance=2.0",
                            "importance": 2.0}, ensure_ascii=False) + "\n")
    os.chmod(bad_seed, 0o644)
    cfg = ctx.stage_config("d1")
    data = ctx.new_dir("d1", "data")
    cwd = ctx.new_dir("d1", "cwd")
    rc, out_path, err_path = _run_exit_expected(ctx, "d1-badseed", cfg, data, cwd, bad_seed)
    out_text = tail(out_path, 4000)
    err_text = tail(err_path, 4000)
    ck.check("D1 bad seed exits non-zero", rc != 0, "rc=%d" % rc)
    ck.check("D1 bad seed never listens", "LISTENING " not in out_text, "")
    ck.check("D1 bad seed reports import-seed failure", "import-seed" in err_text,
             err_text[-200:])
    ck.check("D1 bad seed batch rejected 422", "422" in err_text,
             err_text[-200:])
    ck.check("D1 bad seed imports nothing to disk",
             find_snapshot(data) is None, "data=%s" % sorted(os.listdir(data)))
    ck.info("D1 bad seed: rc=%d stdout=%r"
            % (rc, (out_text.splitlines() or [""])[0][:120]))
    ctx.measure["d.bad_seed"] = {"rc": rc,
                                 "listening": "LISTENING " in out_text,
                                 "error_tail": err_text[-200:]}

    # ---- D2 POST /import 数值校验 + 好种子幂等 ---------------------------
    cfg2 = ctx.stage_config("d2")
    data2 = ctx.new_dir("d2", "data")
    cwd2 = ctx.new_dir("d2", "cwd")
    srv = ctx.start_server("d2-import", cfg2, data2, cwd2)
    srv2 = None
    try:
        base = srv.health()
        ck.eq("D2 start memories == seed", base, ctx.seed_n)

        status, body = srv.request("POST", "/import",
                                   {"memories": [{"text": "memfact-1125 import 坏值",
                                                  "importance": 2.0}]})
        ck.eq("D2 /import importance=2.0 status", status, 422)
        det = (body or {}).get("detail") or [{}]
        ck.eq("D2 /import detail[0].type", det[0].get("type"), "value_error")
        ck.eq("D2 /import detail[0].loc", det[0].get("loc"),
              ["body", "memories", 0, "importance"])
        ck.eq("D2 /import did not change memory count", srv.health(), base)

        status, body = srv.request("POST", "/import",
                                   {"memories": [{"text": "memfact-1125 import 负权重",
                                                  "weight": -1}]})
        ck.eq("D2 /import weight=-1 status", status, 422)
        ck.eq("D2 /import weight=-1 field",
              (((body or {}).get("detail") or [{}])[0]).get("loc"),
              ["body", "memories", 0, "weight"])

        status, body = srv.request("POST", "/import",
                                   {"memories": [{"text": "memfact-1125 import 边界值",
                                                  "importance": 1.0}]})
        ck.eq("D2 /import importance=1.0 boundary status", status, 200)
        ck.eq("D2 /import boundary imported", (body or {}).get("imported"), 1)
        ck.eq("D2 /import boundary memory count", srv.health(), base + 1)

        # 幂等：先触发一次 checkpoint，再同目录重启，种子差集应为 0
        srv.post_json("/config/preset", {"key": "chat"})
        rc = srv.stop()
        ck.eq("D3 first stop rc", rc, 0)
        ctx.measure["d.first_start_cold_s"] = round(srv.cold_s, 3)
        first_out = tail(os.path.join(ctx.log_dir, "d2-import.out.log"), 4000)
        ck.check("D3 first start imported the seed",
                 "missing=%d" % ctx.seed_n in first_out,
                 " | ".join(l for l in first_out.splitlines() if "aikd-seed" in l))

        srv2 = ctx.start_server("d3-restart", cfg2, data2, cwd2)
        ck.eq("D3 restart memories unchanged (no doubling)", srv2.health(), ctx.seed_n + 1)
        second_out = tail(os.path.join(ctx.log_dir, "d3-restart.out.log"), 4000)
        ck.check("D3 restart seed diff is zero",
                 ("missing=0" in second_out)
                 or ("corpus already complete, skip" in second_out),
                 " | ".join(l for l in second_out.splitlines() if "aikd-seed" in l))
        ck.info("D3 restart cold_start=%.3fs" % srv2.cold_s)
        ctx.measure["d.restart_cold_start_s"] = round(srv2.cold_s, 3)
        rc = srv2.stop()
        ck.eq("D3 second stop rc", rc, 0)
    finally:
        srv.kill_if_alive()
        if srv2 is not None:
            srv2.kill_if_alive()


# ---------------------------------------------------------------------------
# E 组：MEM-02d 边界（配置取值校验在哪些入口生效）
# ---------------------------------------------------------------------------
def group_e(ctx, ck):
    # E1 纯默认（无配置文件）：DOM 默认值与注册表 item 默认值是否一致
    data = ctx.new_dir("e1", "data")
    cwd = ctx.new_dir("e1", "cwd")
    absent = os.path.join(ctx.tmp, "e1", "no-such-config.json")
    srv = ctx.start_server("e1-defaults", absent, data, cwd)
    try:
        ck.eq("E1 defaults source", srv.get_json("/config").get("source"), "defaults")
        cfgdoc = srv.get_json("/config")
        items = cfg_items(cfgdoc)
        ck.eq("E1 DOM default llm.model", cval(items, "llm.model"), "gpt-4o-mini")
        ck.eq("E1 DOM default llm.temperature", cval(items, "llm.temperature"), 0.3)
        ck.eq("E1 registry item default llm.model", items["llm.model"].get("default"), "gpt-4o-mini")
        ck.eq("E1 registry item default llm.temperature",
              items["llm.temperature"].get("default"), 0.3)
        ck.eq("E1 llm.model flagged modified under pure defaults",
              items["llm.model"].get("modified"), False)
        ck.eq("E1 llm.temperature flagged modified under pure defaults",
              items["llm.temperature"].get("modified"), False)
        ck.eq("E1 llm.base_url modified stays true (upstream ed5378a)",
              items["llm.base_url"].get("modified"), True)
        ck.info("E1 note",
                "registry item defaults for llm.model/temperature follow "
                "upstream ed5378a and match AIK_CONFIG_DEFAULT_JSON; "
                "llm.base_url keeps registry default '' (upstream), so its "
                "modified flag stays true")
        rc = srv.stop()
        ck.eq("E1 SIGTERM exit code", rc, 0)
    finally:
        srv.kill_if_alive()

    # E2 装载入口校验：坏值拒绝启动（MEM-02d 移植上游 _validate_field）
    cfg = ctx.stage_config("e2")
    doc = read_json(cfg)
    doc["llm"]["temperature"] = 99
    with open(cfg, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    os.chmod(cfg, 0o644)
    data = ctx.new_dir("e2", "data")
    cwd = ctx.new_dir("e2", "cwd")
    srv = Server(ctx, "e2-outofrange", cfg, data, cwd)
    start_err = None
    try:
        srv.start(8.0)
    except RuntimeError as exc:
        start_err = str(exc)
    finally:
        srv.kill_if_alive()
    ck.check("E2 bad config refuses to start", start_err is not None,
             "aikd started with llm.temperature=99")
    ck.check("E2 bad config exits non-zero with key+reason",
             start_err is not None and "rc=1" in start_err
             and "config llm.temperature: 不能大于 2" in start_err,
             start_err or "")
    out_text = ""
    try:
        with open(srv.out_path, "r", encoding="utf-8", errors="replace") as fh:
            out_text = fh.read()
    except OSError:
        pass
    ck.check("E2 bad config prints no LISTENING", "LISTENING" not in out_text,
             out_text[-200:])

    # 写路径回归：好配置正常启动，PUT /config 同值仍被拒（200 ok:false）
    cfg2 = ctx.stage_config("e2-good")
    os.chmod(cfg2, 0o644)
    data2 = ctx.new_dir("e2good", "data")
    cwd2 = ctx.new_dir("e2good", "cwd")
    srv2 = ctx.start_server("e2-good", cfg2, data2, cwd2)
    try:
        status, body = srv2.request("PUT", "/config",
                                    {"values": {"llm.temperature": 99},
                                     "save": False})
        ck.eq("E2 PUT status", status, 200)
        ck.eq("E2 PUT ok", (body or {}).get("ok"), False)
        errs = (body or {}).get("errors") or {}
        ck.check("E2 PUT rejects out-of-range value", "llm.temperature" in errs,
                 "errors=%s" % ",".join(errs.keys()))
        ctx.measure["e.put_reject"] = {"errors": list(errs.keys())}
        ck.info("E2 MEM-02d boundary",
                "config-file load goes through the registry validator and "
                "refuses to listen; PUT /config rejects the same value")
        rc = srv2.stop()
        ck.eq("E2 SIGTERM exit code", rc, 0)
    finally:
        srv2.kill_if_alive()


GROUPS = {"a": group_a, "b": group_b, "c": group_c, "d": group_d, "e": group_e}


def main(argv):
    ap = argparse.ArgumentParser(description="出厂配置记忆层验证")
    ap.add_argument("--aikd", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                   "..", "aikd"))
    ap.add_argument("--config", required=True,
                    help="出厂配置的可读副本（调用方用 sudo cp 到临时目录）")
    ap.add_argument("--seed", required=True, help="出厂 sme-seed.jsonl")
    ap.add_argument("--static", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                     "..", "static"))
    ap.add_argument("--evidence", default=None, help="证据目录（缺省 <tmp>/evidence）")
    ap.add_argument("--tmpdir", default=None)
    ap.add_argument("--only", default="a,b,c,d,e", help="只跑指定组，逗号分隔")
    ap.add_argument("--timeout", type=float, default=180.0, help="单次启动超时秒")
    ap.add_argument("--port", type=int, default=0,
                    help="0=内核选端口；固定值建议 18800-18899")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args(argv)

    for path, label in ((args.aikd, "--aikd"), (args.config, "--config"),
                        (args.seed, "--seed"), (args.static, "--static")):
        if not os.path.exists(path):
            print("ERROR %s not found: %s" % (label, path), file=sys.stderr)
            return 2
    if args.port and not (18800 <= args.port <= 18899):
        print("ERROR --port must be 0 or 18800-18899", file=sys.stderr)
        return 2

    ctx = Ctx(args)
    ck = Checker()
    started = time.monotonic()
    try:
        print("INFO tmp=%s evidence=%s" % (ctx.tmp, ctx.evidence), flush=True)
        print("INFO factory config size=%d sha256=%s"
              % (ctx.factory_config_size, ctx.factory_config_sha), flush=True)
        print("INFO factory seed records=%d sha256=%s"
              % (ctx.seed_n, ctx.seed_sha[:16]), flush=True)
        wanted = [g.strip().lower() for g in args.only.split(",") if g.strip()]
        for g in wanted:
            fn = GROUPS.get(g)
            if fn is None:
                print("ERROR unknown group %s" % g, file=sys.stderr)
                return 2
            print("INFO ===== group %s =====" % g.upper(), flush=True)
            try:
                fn(ctx, ck)
            except Exception as exc:  # noqa: BLE001 - 一组崩了不遮住其它组
                ck.check("EXCEPTION group %s %s" % (g.upper(), type(exc).__name__),
                         False, str(exc)[:400])
                args.keep = True
    finally:
        summary = ctx.finish()
        ctx.cleanup()

    elapsed = time.monotonic() - started
    print("INFO  elapsed=%.1fs" % elapsed)
    print("INFO  summary=%s" % os.path.join(ctx.evidence, "summary.json"))
    print("RESULT %d passed, %d failed" % (ck.passed, ck.failed))
    for f in ck.failures:
        print("FAILED " + f)
    return 0 if ck.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
