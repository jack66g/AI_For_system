#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# aikd_lib.py - AI Kernel Daemon 公共库（B 轨，数据计划 P7 / 二十一节）
#
# 功能：
#   1. NETLINK_AI 遥测记录解析（对齐 struct ai_telemetry_record，23B 头 +
#      原始数据，全量零脱敏）
#   2. /proc/ai/decisions、/proc/ai/chains 文本记录解析（对齐 ai_procfs.c
#      输出格式）
#   3. Parquet 落盘（pyarrow；schema 固定并文档化，见 README.md）
#   4. 回读校验（verify：抽查类别一致性）
#
# 数据原则（all-ai）：Parquet 落盘数据保留原始内容，不脱敏、不哈希、
# 不截断（data 列原样保留二进制）。
#
# 目录结构（对齐数据计划 23.3）：
#   /var/lib/aikernel/
#   ├── telemetry/YYYY-MM-DD/<cat>_NNNN.parquet + index.parquet
#   ├── decisions/YYYY-MM-DD/decisions.parquet
#   ├── decisions/chains_YYYY-MM-DD.parquet
#   └── models/    （训练模型，既有）
#
# 依赖：python3 + pyarrow（pip install pyarrow）。

import os
import re
import struct
import sys
import socket
import datetime
import glob

# ---- NETLINK_AI 常量（对齐 include/uapi/linux/ai_netlink.h） ----

NETLINK_AI = 31
AI_CMD_SENSE = 16
AI_CMD_ACT = 17
AI_NL_SENSE_CPU_ALL = 0xFFFFFFFF
AI_NL_SENSE_MAX_RECORDS = 4096
AI_NL_FORMAT_RAW = 0
AI_NL_PAYLOAD_MAX = 64 * 1024

# 遥测记录头（packed 23B）：
#   u64 timestamp_ns, u32 pid, u32 tgid, u16 cpu,
#   u8 category, u8 event_type, u8 severity, u16 data_len
TEL_HEADER = struct.Struct("=QIIHBBBH")

# 事件编号上界（对齐 enum ai_event_type：AI_EV_MAX=104）
AI_EV_MAX_MAX = 104
AI_TELEMETRY_MAX_DATA_LEN = 4096
TEL_HEADER_LEN = 23

# 决策记录字段名（/proc/ai/decisions 与 chains 同一格式）
DECISION_RE = re.compile(
    r"id=(\d+) trig_ts=(\d+) trig_evid=0x([0-9a-fA-F]+) "
    r"dec_ts=(\d+) type=(\d+) data=(.*?) exec_ts=(\d+) outcome_ts=(\d+) "
    r"outcome=(\d+) delta=(-?\d+) ver=(\d+) conf=(\d+) domain=(\d+) "
    r"src=(\d+) executed=(\d+) safety_clamped=(\d+)")

# 大类名（文件命名用，对齐 enum ai_category）
CAT_NAMES = {
    1: "sched", 2: "mm", 3: "io", 4: "net", 5: "user_input",
    6: "process", 7: "fs", 8: "security", 9: "interrupt", 10: "lock",
    11: "time", 12: "power", 13: "virt", 14: "bpf", 15: "user_behavior",
    16: "hw", 17: "kconfig", 18: "ai",
}

DEFAULT_ROOT = "/var/lib/aikernel"
DEFAULT_POLL_SEC = 5


# ---- 记录解析 ----

def parse_telemetry_records(data: bytes, start: int = 0):
    """解析 raw 二进制流 → [(header_dict, raw_payload_bytes), ...]。

    data 为 NETLINK_AI SENSE 应答记录区（或 ingest 的 telemetry.bin）。
    返回 (records, consumed)。传输损坏（serial 丢字节等）导致字段不可信
    的记录会以 1 字节步进重同步（跳过损坏字节），resynced 计数回填到
    records 之外（调用方可通过返回元组的第三个元素查看）。

    NETLINK_AI 通道（run 模式）不丢字节；resync 主要服务离线导入的
    serial 转储文件。
    """
    records = []
    resynced = 0
    pos = start
    n = len(data)
    while pos + TEL_HEADER_LEN <= n:
        hdr = TEL_HEADER.unpack_from(data, pos)
        (timestamp_ns, pid, tgid, cpu, category, event_type,
         severity, data_len) = hdr
        if pos + TEL_HEADER_LEN + data_len > n:
            break  # 尾部残记录：留待下次（netlink 语义与内核一致）
        # 字段可信性校验（防御传输损坏的误对齐记录）：
        # 对齐内核侧约束 —— 类别 1..18、事件 1..103、长度 0..4096、
        # pid/tgid 有符号 32 位、cpu 合法
        if not (1 <= category <= 18 and 1 <= event_type < AI_EV_MAX_MAX and
                data_len <= AI_TELEMETRY_MAX_DATA_LEN and
                0 <= pid <= 0x7FFFFFFF and 0 <= tgid <= 0x7FFFFFFF and
                cpu < 4096):
            pos += 1      # 1 字节步进重同步（跳过损坏字节）
            resynced += 1
            continue
        payload = data[pos + TEL_HEADER_LEN: pos + TEL_HEADER_LEN + data_len]
        records.append(({
            "timestamp_ns": timestamp_ns,
            "pid": pid,
            "tgid": tgid,
            "cpu": cpu,
            "category": category,
            "event_type": event_type,
            "severity": severity,
            "data_len": data_len,
        }, payload))
        pos += TEL_HEADER_LEN + data_len
    return records, pos, resynced


def parse_decision_line(line: str):
    """解析 /proc/ai/decisions|chains 的一行 → dict 或 None。"""
    m = DECISION_RE.match(line.strip())
    if not m:
        return None
    g = m.groups()
    data_raw = g[5].split(":") if g[5] else []
    data = [int(x) for x in data_raw]
    while len(data) < 8:
        data.append(0)
    return {
        "decision_id": int(g[0]),
        "trigger_ts": int(g[1]),
        "trigger_event_id": int(g[2], 16),
        "decision_ts": int(g[3]),
        "decision_type": int(g[4]),
        "data_0": data[0], "data_1": data[1], "data_2": data[2],
        "data_3": data[3], "data_4": data[4], "data_5": data[5],
        "data_6": data[6], "data_7": data[7],
        "exec_ts": int(g[6]),
        "outcome_ts": int(g[7]),
        "outcome": int(g[8]),
        "metric_delta": int(g[9]),
        "model_version": int(g[10]),
        "confidence": int(g[11]),
        "domain": int(g[12]),
        "source": int(g[13]),
        "executed": int(g[14]),
        "safety_clamped": int(g[15]),
    }


# ---- Parquet schema（固定，AI 训练直接消费；文档见 README.md） ----

def schema_telemetry():
    import pyarrow as pa
    return pa.schema([
        pa.field("timestamp_ns", pa.int64()),
        pa.field("pid", pa.int32()),
        pa.field("tgid", pa.int32()),
        pa.field("cpu", pa.int16()),
        pa.field("category", pa.int8()),
        pa.field("event_type", pa.int8()),
        pa.field("severity", pa.int8()),
        pa.field("data_len", pa.int16()),
        pa.field("data", pa.binary()),          # 原始数据全量零脱敏
    ])


def schema_decision():
    import pyarrow as pa
    return pa.schema([
        pa.field("decision_id", pa.int64()),
        pa.field("trigger_ts", pa.int64()),
        pa.field("trigger_event_id", pa.int64()),
        pa.field("decision_ts", pa.int64()),
        pa.field("decision_type", pa.int8()),
        pa.field("data_0", pa.int64()), pa.field("data_1", pa.int64()),
        pa.field("data_2", pa.int64()), pa.field("data_3", pa.int64()),
        pa.field("data_4", pa.int64()), pa.field("data_5", pa.int64()),
        pa.field("data_6", pa.int64()), pa.field("data_7", pa.int64()),
        pa.field("exec_ts", pa.int64()),
        pa.field("outcome_ts", pa.int64()),
        pa.field("outcome", pa.int8()),
        pa.field("metric_delta", pa.int64()),
        pa.field("model_version", pa.int32()),
        pa.field("confidence", pa.int8()),
        pa.field("domain", pa.int8()),
        pa.field("source", pa.int8()),
        pa.field("executed", pa.int8()),
        pa.field("safety_clamped", pa.int8()),
    ])


def schema_index():
    import pyarrow as pa
    return pa.schema([
        pa.field("file", pa.string()),
        pa.field("date", pa.string()),
        pa.field("category", pa.int8()),
        pa.field("records", pa.int64()),
        pa.field("start_ts", pa.int64()),
        pa.field("end_ts", pa.int64()),
    ])


# ---- 落盘 ----

def ensure_root(root: str):
    for sub in ("telemetry", "decisions", "models"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)


def _cat_name(category: int) -> str:
    return CAT_NAMES.get(category, "cat%02d" % category)


_BTIME = None


def _boot_time():
    """宿主开机时间（CLOCK_MONOTONIC 0 点）→ wall-clock 秒；失败 None。"""
    global _BTIME
    if _BTIME is None:
        _BTIME = 0
        try:
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("btime "):
                        _BTIME = int(line.split()[1])
                        break
        except OSError:
            pass
    return _BTIME or None


def _ts_to_day(ts_ns: int) -> datetime.datetime:
    """单调时间戳 → 按天目录的 UTC 日期。

    内核遥测时间戳为 CLOCK_MONOTONIC（开机相对）；用宿主 btime 还原
    wall-clock。btime 不可用时退回“今天”（离线导入场景），保证
    按天目录有意义。
    """
    bt = _boot_time()
    if bt:
        sec = bt + ts_ns / 1e9
        return datetime.datetime.fromtimestamp(sec, datetime.timezone.utc)
    return datetime.datetime.now(datetime.timezone.utc)


def _day_dir(root: str, sub: str, dt: datetime.datetime) -> str:
    d = os.path.join(root, sub, dt.strftime("%Y-%m-%d"))
    os.makedirs(d, exist_ok=True)
    return d


def _next_seq(d: str, prefix: str) -> int:
    seq = 0
    for f in glob.glob(os.path.join(d, prefix + "_*.parquet")):
        m = re.search(r"_(\d+)\.parquet$", f)
        if m:
            seq = max(seq, int(m.group(1)) + 1)
    return seq


def write_telemetry(root: str, records):
    """按天/按类别落盘 Parquet。records = [(hdr_dict, payload_bytes), ...]。

    每天每类别一个文件（chunk 上限 65536 条，超出开新序号文件）。
    返回写入条数。
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    by_cat = {}
    for hdr, payload in records:
        by_cat.setdefault(hdr["category"], []).append((hdr, payload))

    total = 0
    for category, items in sorted(by_cat.items()):
        items.sort(key=lambda x: x[0]["timestamp_ns"])
        d = _day_dir(root, "telemetry",
                     _ts_to_day(items[0][0]["timestamp_ns"]))
        prefix = _cat_name(category)
        seq = _next_seq(d, prefix)

        for i in range(0, len(items), 65536):
            chunk = items[i:i + 65536]
            if i > 0:
                seq = _next_seq(d, prefix)
            table = pa.table({
                "timestamp_ns": [h["timestamp_ns"] for h, _ in chunk],
                "pid": [h["pid"] for h, _ in chunk],
                "tgid": [h["tgid"] for h, _ in chunk],
                "cpu": [h["cpu"] for h, _ in chunk],
                "category": [h["category"] for h, _ in chunk],
                "event_type": [h["event_type"] for h, _ in chunk],
                "severity": [h["severity"] for h, _ in chunk],
                "data_len": [h["data_len"] for h, _ in chunk],
                "data": [p for _, p in chunk],
            }, schema=schema_telemetry())
            path = os.path.join(d, "%s_%04d.parquet" % (prefix, seq))
            pq.write_table(table, path, compression="snappy")
            seq += 1
            total += len(chunk)
    if total:
        _update_index(root)
    return total


def write_decisions(root: str, decisions):
    """决策记录落盘：decisions/YYYY-MM-DD/decisions.parquet（按决策时间分日）。"""
    if not decisions:
        return 0
    import pyarrow as pa
    import pyarrow.parquet as pq

    d = _day_dir(root, "decisions", _ts_to_day(decisions[0]["decision_ts"]))
    table = pa.table({k: [x[k] for x in decisions]
                      for k in schema_decision().names},
                     schema=schema_decision())
    path = os.path.join(d, "decisions.parquet")
    pq.write_table(table, path, compression="snappy")
    return len(decisions)


def write_chains(root: str, chains):
    """因果链落盘：decisions/chains_YYYY-MM-DD.parquet（按链首时间分日）。"""
    if not chains:
        return 0
    import pyarrow as pa
    import pyarrow.parquet as pq

    dt = _ts_to_day(chains[0]["trigger_ts"])
    d = _day_dir(root, "decisions", dt)
    table = pa.table({k: [x[k] for x in chains]
                      for k in schema_decision().names},
                     schema=schema_decision())
    path = os.path.join(d, "chains_%s.parquet" % dt.strftime("%Y-%m-%d"))
    pq.write_table(table, path, compression="snappy")
    return len(chains)


def _update_index(root: str):
    """重建 telemetry/index.parquet（文件→日期→类别→行数→时间范围）。"""
    import pyarrow as pa
    import pyarrow.parquet as pq

    files = []
    for f in glob.glob(os.path.join(root, "telemetry", "*", "*_*.parquet")):
        if f.endswith("index.parquet"):
            continue
        try:
            t = pq.read_table(f, columns=["timestamp_ns", "category"])
        except Exception:
            continue
        cat = t.column("category").to_pylist()
        ts = t.column("timestamp_ns").to_pylist()
        date = os.path.basename(os.path.dirname(f))
        files.append({
            "file": os.path.relpath(f, root),
            "date": date,
            "category": max(cat) if cat else 0,
            "records": len(cat),
            "start_ts": min(ts) if ts else 0,
            "end_ts": max(ts) if ts else 0,
        })
    table = pa.table({k: [x[k] for x in files]
                      for k in schema_index().names},
                     schema=schema_index())
    pq.write_table(table, os.path.join(root, "telemetry", "index.parquet"),
                   compression="snappy")


# ---- 校验（回读） ----

def readback_telemetry(root: str, day: str = None):
    """回读全部（或指定日）telemetry Parquet → 记录列表。"""
    import pyarrow.parquet as pq

    pattern = os.path.join(root, "telemetry", day or "*", "*_*.parquet")
    records = []
    for f in sorted(glob.glob(pattern)):
        if f.endswith("index.parquet"):
            continue
        t = pq.read_table(f)
        for i in range(t.num_rows):
            col = lambda n: t.column(n)[i].as_py()  # noqa: E731
            hdr = {
                "timestamp_ns": col("timestamp_ns"),
                "pid": col("pid"),
                "tgid": col("tgid"),
                "cpu": col("cpu"),
                "category": col("category"),
                "event_type": col("event_type"),
                "severity": col("severity"),
                "data_len": col("data_len"),
            }
            payload = t.column("data")[i].as_py() or b""
            records.append((hdr, payload))
    return records


def readback_decisions(root: str, day: str = None):
    import pyarrow.parquet as pq

    out = []
    for f in sorted(glob.glob(os.path.join(
            root, "decisions", day or "*", "decisions.parquet"))):
        t = pq.read_table(f)
        for i in range(t.num_rows):
            out.append({k: t.column(k)[i].as_py()
                        for k in schema_decision().names})
    return out


def readback_chains(root: str, day: str = None):
    import pyarrow.parquet as pq

    out = []
    for f in sorted(glob.glob(os.path.join(
            root, "decisions", "*", "chains_*.parquet")) +
                    glob.glob(os.path.join(
            root, "decisions", "chains_*.parquet"))):
        if day and day not in f:
            continue
        t = pq.read_table(f)
        for i in range(t.num_rows):
            out.append({k: t.column(k)[i].as_py()
                        for k in schema_decision().names})
    return out


# ---- NETLINK_AI 客户端（run 模式） ----

def netlink_sense(max_records=AI_NL_SENSE_MAX_RECORDS, timeout=2.0):
    """AI_CMD_SENSE 拉取全部 CPU 遥测 → [(hdr, payload), ...]。"""
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AI)
    try:
        sock.settimeout(timeout)
        req = struct.pack("=IIII", AI_NL_SENSE_CPU_ALL, max_records,
                          AI_NL_FORMAT_RAW, 0)
        nlmsg_type = AI_CMD_SENSE
        hdr = struct.pack("=IHHII", 16 + len(req), nlmsg_type, 0, 1, 0)
        sock.send(hdr + req)
        data = sock.recv(AI_NL_PAYLOAD_MAX + 4096)
        # 校验 ack 头：records/bytes/ai_err/reserved
        if len(data) < 16:
            return [], -1
        records_n, bytes_n, ai_err, _ = struct.unpack("=IIiI", data[:16])
        if ai_err != 0:
            return [], ai_err
        records, _ = parse_telemetry_records(data, 16)
        return records, 0
    except socket.timeout:
        return [], 0
    finally:
        sock.close()


