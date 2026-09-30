#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# AIKernel RAG 知识库：接口文档生成 + 向量索引构建 + ai_rag_query 检索
# Prompt 14 (B 轨) / 数据计划 22.1-22.3 / 重构总纲 Phase 0 任务 0.4/0.5
#
# 用法:
#   python3 build_index.py --extract              # 生成 AIKernel_Docs/ 12 个接口文档
#   python3 build_index.py --index [--small]      # 构建 4 个 faiss 索引 + metadata.json
#   python3 build_index.py --query "文本" [--top-k 5] [--scope all|docs|interfaces|source_code|history]
#   python3 build_index.py --verify               # 5 组验收查询

import argparse
import json
import math
import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
KROOT = os.path.dirname(os.path.dirname(ROOT))          # linux-6.18.39/
DOCS_DIR = os.path.join(KROOT, "AIKernel_Docs")
EMB_DIR = os.path.join(ROOT, "embeddings")
METADATA = os.path.join(ROOT, "metadata.json")
CORPUS = os.path.join(ROOT, "corpus.jsonl")

DIM = 1024
CHUNK_SIZE = 800
OVERLAP = 120
SCOPES = ["docs", "interfaces", "source_code", "history"]
SMALL_SCOPES = ["interfaces", "history"]

HDR = """# {title}

> **文档类别：** {category}｜**生成方式：** {generator}｜**生成日期：** 2026-08-13
> **条目格式：** 本文件条目遵循《agent/00_AI_函数调用接口指南.md》接口登记规范，
> 每条含「路径/类型/范围/默认值/含义/AI 控制用途/相关源码/相关内核符号」八字段，
> AI 自动化解析必需。文档更新流程：代码改造完成 → 更新本文件对应条目 → 重建索引。
>

"""

TEMPLATE = """### {name}

- **路径：** {path}
- **类型：** {typ}
- **范围：** {rng}
- **默认值：** {default}
- **含义：** {meaning}
- **AI 控制用途：** {ai_use}
- **相关源码：** {src}
- **相关内核符号：** {sym}

"""

TABLE_HDR = """| 名称 | 类型 | 范围/默认值 | 含义 | AI 控制用途 | 相关源码 | 相关内核符号 |
|------|------|-------------|------|-------------|----------|--------------|
"""


def esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def rel(path):
    # Windows 兼容：统一为 POSIX 斜杠，保证语料/文档内路径与 Linux 生成格式一致
    return os.path.relpath(path, KROOT).replace(os.sep, "/")


def walk_files(root, exts):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            if any(fn.endswith(e) for e in exts):
                yield os.path.join(dirpath, fn)


# ---------------- faiss 读写垫片（Windows 兼容） ----------------
# faiss 的 C++ FileIOWriter/Reader 用 ANSI fopen，非 ASCII（如中文用户名）路径会
# "No such file or directory"。非 ASCII 路径时经 ASCII 临时目录中转，
# move/copy 走 Python Unicode API。

_FAISS_TMP = None


def _is_ascii(s):
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def _faiss_tmpdir():
    global _FAISS_TMP
    if _FAISS_TMP is None:
        cands = [os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Windows", "Temp"),
                 os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, ".faiss_tmp")]
        for c in cands:
            try:
                os.makedirs(c, exist_ok=True)
                probe = os.path.join(c, "faiss_probe_%d" % os.getpid())
                with open(probe, "w"):
                    pass
                os.remove(probe)
                _FAISS_TMP = c
                break
            except OSError:
                continue
        if _FAISS_TMP is None:
            _FAISS_TMP = ""
    return _FAISS_TMP or None


def faiss_write(idx, path):
    import faiss
    if os.name != "nt" or _is_ascii(path):
        faiss.write_index(idx, path)
        return
    tmp = _faiss_tmpdir()
    tpath = os.path.join(tmp, "faiss_%d_%s" % (os.getpid(), os.path.basename(path)))
    faiss.write_index(idx, tpath)
    shutil.move(tpath, path)


def faiss_read(path):
    import faiss
    if os.name != "nt" or _is_ascii(path):
        return faiss.read_index(path)
    tmp = _faiss_tmpdir()
    tpath = os.path.join(tmp, "faiss_%d_%s" % (os.getpid(), os.path.basename(path)))
    shutil.copyfile(path, tpath)
    try:
        return faiss.read_index(tpath)
    finally:
        try:
            os.remove(tpath)
        except OSError:
            pass


# ---------------- 稳定哈希嵌入（零外部模型，确定性可复现） ----------------

def stable_hash(s):
    h = 1469598103934665603
    for b in s.encode("utf-8", "ignore"):
        h = ((h ^ b) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


TOKEN_RE = re.compile(r"[a-zA-Z0-9_./\-]+|[\u4e00-\u9fff]+")
CJK_RE = re.compile(r"[\u4e00-\u9fff]+")


def tokenize(text):
    toks = []
    for m in TOKEN_RE.finditer(text.lower()):
        t = m.group()
        if CJK_RE.fullmatch(t):
            if len(t) == 1:
                toks.append(t)
            else:
                toks.extend(t[i:i + 2] for i in range(len(t) - 1))
        else:
            toks.append(t)
            for part in re.split(r"[./_\-]", t):
                if len(part) > 1:
                    toks.append(part)
            if len(t) > 2 and not t.startswith("."):
                toks.append(t[:4])
    return toks


def embed(chunk_text, df, n_docs):
    counts = Counter(tokenize(chunk_text))
    vec = {}
    for tok, tf in counts.items():
        h = stable_hash(tok) % DIM
        idf = math.log(1.0 + n_docs / (1.0 + df.get(tok, 0)))
        vec[h] = vec.get(h, 0.0) + tf * idf
    norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
    return {k: v / norm for k, v in vec.items()}


# ---------------- 文档生成（A 轨：12 个接口文档） ----------------

def gen_00_syscalls():
    tbl = os.path.join(KROOT, "arch/x86/entry/syscalls/syscall_64.tbl")
    rows = []
    with open(tbl, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                rows.append((parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else ""))

    defs = {}
    for path in walk_files(KROOT, (".c",)):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in re.finditer(r"SYSCALL_DEFINE\d+\((\w+),", text):
            name = m.group(1)
            if name not in defs:
                defs[name] = (rel(path), text.count("\n", 0, m.start()) + 1)
    common = {
        "read": "从文件描述符读取数据", "write": "向文件描述符写入数据",
        "open": "打开文件", "openat": "打开文件（带路径解析选项）", "close": "关闭文件描述符",
        "mmap": "内存映射", "munmap": "解除内存映射", "brk": "调整堆（brk）边界",
        "fork": "创建子进程", "vfork": "创建子进程（共享地址空间）", "clone": "按标志创建任务",
        "execve": "执行程序", "exit": "退出进程", "wait4": "等待子进程状态",
        "kill": "向进程发送信号", "tkill": "向线程发送信号", "signal": "设置信号处理",
        "sigsuspend": "挂起等待信号", "sigaction": "查询/设置信号处理", "sigprocmask": "设置信号屏蔽集",
        "getpid": "获取进程 PID", "gettid": "获取线程 TID", "getppid": "获取父进程 PID",
        "sched_yield": "让出 CPU", "sched_setparam": "设置调度参数", "sched_getparam": "读取调度参数",
        "sched_setscheduler": "设置调度策略", "nice": "调整进程 nice 值",
        "setpriority": "设置进程优先级", "getpriority": "读取进程优先级",
        "setsockopt": "设置套接字选项", "getsockopt": "读取套接字选项",
        "socket": "创建套接字", "bind": "绑定地址", "listen": "监听", "accept": "接受连接",
        "connect": "连接", "sendto": "发送报文", "recvfrom": "接收报文",
        "sendmsg": "发送消息", "recvmsg": "接收消息", "shutdown": "关闭连接",
        "socketpair": "创建成对套接字", "setsid": "创建新会话", "getrlimit": "读取资源限制",
        "setrlimit": "设置资源限制", "prlimit64": "按 PID 设置/读取资源限制",
        "stat": "读取文件状态", "fstat": "读取文件状态（按 fd）", "lstat": "读取符号链接状态",
        "readlink": "读取符号链接", "chdir": "切换工作目录", "fchdir": "切换工作目录（按 fd）",
        "mkdir": "创建目录", "rmdir": "删除目录", "unlink": "删除文件", "unlinkat": "删除目录项",
        "rename": "重命名", "chmod": "修改权限", "fchmod": "修改权限（按 fd）",
        "chown": "修改属主", "fchown": "修改属主（按 fd）", "lseek": "调整文件偏移",
        "fsync": "刷盘", "fdatasync": "刷数据盘", "sync": "全局刷盘",
        "getdents64": "读取目录项", "readdir": "读取目录项（旧）", "dup": "复制 fd", "dup2": "复制 fd 到指定号",
        "pipe": "创建管道", "pipe2": "创建管道（带标志）", "select": "多路复用等待",
        "poll": "多路复用等待", "epoll_create1": "创建 epoll 实例", "epoll_ctl": "控制 epoll 事件",
        "epoll_wait": "等待 epoll 事件", "ioctl": "设备控制命令", "fcntl": "文件控制",
        "flock": "文件锁", "readahead": "预读", "fadvise64": "文件访问模式建议",
        "madvise": "内存访问建议", "mlock": "锁页", "munlock": "解锁页",
        "mlockall": "锁定全部内存", "munlockall": "解锁全部内存",
        "mprotect": "修改内存保护", "mremap": "重映射内存",
        "gettimeofday": "读取时间", "clock_gettime": "读取时钟", "nanosleep": "纳秒睡眠",
        "clock_nanosleep": "时钟睡眠", "getcpu": "读取当前 CPU", "sched_getaffinity": "读取 CPU 亲和",
        "sched_setaffinity": "设置 CPU 亲和", "sysinfo": "系统信息",
        "uname": "系统版本信息", "getuid": "读取 UID", "setuid": "设置 UID",
        "getgid": "读取 GID", "setgid": "设置 GID", "getgroups": "读取组列表",
        "umask": "设置文件创建掩码", "alarm": "定时闹钟", "pause": "挂起进程",
        "access": "检查访问权限", "faccessat": "检查访问权限（按路径）",
        "truncate": "截断文件", "ftruncate": "截断文件（按 fd）", "link": "创建硬链接",
        "symlink": "创建符号链接", "mount": "挂载文件系统", "umount2": "卸载文件系统",
        "chroot": "切换根目录", "setpgid": "设置进程组", "getpgid": "读取进程组",
        "pivot_root": "切换根/挂载点", "reboot": "重启", "swapon": "启用交换设备",
        "swapoff": "停用交换设备", "syslog": "内核日志接口", "kexec_load": "装载新内核",
        "ptrace": "进程跟踪", "prctl": "进程控制", "perf_event_open": "性能事件",
        "bpf": "BPF 程序控制", "userfaultfd": "用户态缺页", "io_uring_setup": "io_uring 初始化",
        "io_uring_enter": "io_uring 提交/完成", "io_uring_register": "io_uring 注册资源",
        "membarrier": "内存屏障", "rseq": "可重启序列", "landlock_create_ruleset": "Landlock 规则集",
        "seccomp": "安全计算模式", "getrandom": "获取随机数", "mseal": "内存密封",
    }
    out = HDR.format(title="00 系统调用接口", category="系统调用（x86-64，含 x32/common）",
                     generator="arch/x86/entry/syscalls/syscall_64.tbl + SYSCALL_DEFINE 扫描")
    out += "> 条目总数：%d（表 nr=%s 起）。\n\n" % (len(rows), rows[0][0] if rows else "-")
    for nr, abi, name, entry in rows:
        f, ln = defs.get(name, ("-", "-"))
        meaning = common.get(name, "Linux 系统调用（详见 man 2 %s）" % name)
        ai_use = ("AI 可通过 syscall 触发/拦截%s行为（进程/文件/内存/网络/调度）" % meaning) if name else "仅占位"
        sym = entry if entry != "-" else "sys_" + name
        out += TEMPLATE.format(
            name="syscall %s (nr=%s)" % (name, nr), path="int $%s (%s, %s)" % (nr, abi, name),
            typ="系统调用", rng="nr %s；参数/返回见签名" % nr, default="-",
            meaning=meaning, ai_use=ai_use, src="%s:%s" % (f, ln), sym=sym)
    return out


def gen_01_sysfs():
    pat = re.compile(r"(?:DEVICE_ATTR(?:_RO|_RW|_WO)?|__ATTR(?:_RO|_RW|_WO)?)\((\w+)")
    rows = {}
    for path in walk_files(KROOT, (".c",)):
        for m in pat.finditer(open(path, encoding="utf-8", errors="ignore").read()):
            rows.setdefault(m.group(1), []).append(rel(path))
    out = HDR.format(title="01 sysfs 接口", category="/sys/ 下全部 device_attribute/kobj_attribute",
                     generator="全源码 DEVICE_ATTR/__ATTR 宏扫描（含 AIKernel /sys/kernel/ai/）")
    out += "> 条目总数：%d。\n\n" % len(rows)
    for name, files in sorted(rows.items()):
        out += TEMPLATE.format(
            name=name, path="/sys/（设备/类上下文）%s" % name,
            typ="sysfs 属性（device_attribute/kobj_attribute）",
            rng="按属性实现（show/store 定义）", default="-",
            meaning="sysfs 属性节点 %s（show 读 / store 写，权限由属性决定）" % name,
            ai_use="AI 通过读写该属性感知/控制系统行为（路径由设备挂载点决定）",
            src="、".join(dedup(files[:3])), sym="%s_show / %s_store" % (name, name))
    return out


def gen_02_procfs():
    sysctls = []
    for root in ("kernel", "mm", "net", "fs", "ipc"):
        for path in walk_files(os.path.join(KROOT, root), (".c",)):
            text = open(path, encoding="utf-8", errors="ignore").read()
            reg = {}
            for rm in re.finditer(r"register_sysctl(?:_init)?\(\s*\"([^\"]+)\",\s*(\w+)", text):
                reg[rm.group(2)] = rm.group(1)
            table = None
            for m in re.finditer(r"struct\s+ctl_table\s+(\w+)\s*\[", text):
                table = m.group(1)
            for m in re.finditer(r"\.procname\s*=\s*\"([a-zA-Z0-9_.]+)\"", text):
                line = text.count("\n", 0, m.start()) + 1
                if table and table in reg:
                    parent = reg[table]
                elif table:
                    parent = table[:-6] if table.endswith("_table") else table
                    if root == "net":
                        parent = "net/" + parent
                else:
                    parent = ""
                mode = re.search(r"\.mode\s*=\s*(\d+)", text[m.end():m.end() + 200])
                sysctls.append((parent + "/" + m.group(1) if parent else m.group(1),
                                m.group(1), rel(path), line,
                                mode.group(1) if mode else "0644"))
    procs = []
    pid_entries = []
    for path in walk_files(KROOT, (".c",)):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in re.finditer(r"proc_create(?:_data)?\(\s*\"([a-zA-Z0-9_.]+)\",\s*(\d+)", text):
            line = text.count("\n", 0, m.start()) + 1
            procs.append((m.group(1), rel(path), line, m.group(2)))
        if path.startswith(os.path.join(KROOT, "fs", "proc")):
            for m in re.finditer(r"\b(?:REG|ONE|INF|DIR|LNK)\(\s*\"([a-zA-Z0-9_.]+)\",\s*([A-Z_|0-9]+)", text):
                line = text.count("\n", 0, m.start()) + 1
                pid_entries.append((m.group(1), rel(path), line, m.group(2)))
    out = HDR.format(title="02 procfs 接口", category="/proc/ 与 /proc/sys/ 全部",
                     generator="kernel/sysctl.c 体系 struct ctl_table(.procname) + proc_create + fs/proc pid_entry 表 + AIKernel /proc/ai/")
    out += "> sysctl 条目：%d；proc_create 条目：%d；/proc/PID 条目：%d。\n\n" % (len(sysctls), len(procs), len(pid_entries))
    seen = set()
    for full, name, f, ln, mode in sorted(sysctls):
        if full in seen:
            continue
        seen.add(full)
        out += TEMPLATE.format(
            name="/proc/sys/%s" % full, path="/proc/sys/%s" % full,
            typ="sysctl（%s）" % mode, rng="按 ctl_table 定义（min/max/maxlen）", default="见 ctl_table .extra1/.extra2",
            meaning="sysctl 控制项 %s（定义于 %s）" % (name, f),
            ai_use="AI 可读/写该 sysctl 控制系统行为（对应内核全局变量）",
            src="%s:%s" % (f, ln), sym=".data 指向的内核变量")
    for name, f, ln, mode in sorted(procs):
        out += TEMPLATE.format(
            name="/proc/%s" % name, path="/proc/%s" % name,
            typ="proc 文件（%s）" % mode, rng="按 proc_ops 实现", default="-",
            meaning="/proc/%s 节点（定义于 %s，读写由 proc_ops 决定）" % (name, f),
            ai_use="AI 通过该节点感知内核状态/下发控制",
            src="%s:%s" % (f, ln), sym="proc_ops (%s)" % name)
    pid_gloss = {
        "oom_score_adj": "进程 OOM 分数调整（-1000~1000，越低越优先保留，-1000 免 OOM）",
        "oom_score": "进程当前 OOM 分数（只读，由内核按内存占用/adj 计算）",
        "oom_adj": "旧式 OOM 调整（-17~15，已弃用，写 oom_score_adj 更佳）",
        "sched": "进程调度属性（sched_getscheduler/sched_setscheduler 操作）",
        "nice": "进程 nice 值（-20~19）",
        "stat": "进程状态统计（ps 数据源）",
        "status": "进程状态详情（含内存/信号/能力）",
        "maps": "进程虚拟内存映射表",
        "smaps": "进程内存映射细目（RSS/PSS）",
        "environ": "进程环境变量",
        "cmdline": "进程命令行",
        "cgroup": "进程所属 cgroup 路径",
        "comm": "进程命令行名（可写）",
        "uid_map": "用户命名空间 UID 映射",
        "numa_maps": "进程 NUMA 映射",
    }
    for name, f, ln, mode in sorted(set(pid_entries)):
        gloss = pid_gloss.get(name, "进程级接口（%s）" % name)
        out += TEMPLATE.format(
            name="/proc/PID/%s" % name, path="/proc/PID/%s" % name,
            typ="proc PID 条目（%s）" % mode, rng="按 pid_entry 操作实现", default="-",
            meaning="/proc/<PID>/%s：%s（定义于 %s）" % (name, gloss, f),
            ai_use="AI 按 PID 感知/控制进程（OOM 分数/调度/内存/文件）",
            src="%s:%s" % (f, ln), sym="pid_entry %s" % name)
    return out


def gen_03_debugfs():
    pat = re.compile(r"debugfs_create_(\w+)\(\s*\"(\w+)\"")
    rows = []
    for path in walk_files(KROOT, (".c",)):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in pat.finditer(text):
            rows.append((m.group(2), m.group(1), rel(path), text.count("\n", 0, m.start()) + 1))
    out = HDR.format(title="03 debugfs 接口", category="/sys/kernel/debug/ 全部调试接口",
                     generator="全源码 debugfs_create_* 调用扫描")
    out += "> 条目总数：%d。\n\n" % len(rows)
    for name, typ, f, ln in sorted(rows):
        out += TEMPLATE.format(
            name=name, path="/sys/kernel/debug/<子系统>/%s" % name,
            typ="debugfs（%s）" % typ, rng="-", default="-",
            meaning="调试文件 %s（debugfs_create_%s）" % (name, typ),
            ai_use="AI 调试/观测内核内部状态（需挂载 debugfs）",
            src="%s:%s" % (f, ln), sym="debugfs_create_%s" % typ)
    return out


def gen_04_exports():
    pat = re.compile(r"EXPORT_SYMBOL(_GPL)?(_NS)?\(\s*(\w+)\s*\)")
    rows = []
    for path in walk_files(KROOT, (".c",)):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in pat.finditer(text):
            rows.append((m.group(3), "EXPORT_SYMBOL%s%s" % (m.group(1) or "", m.group(2) or ""),
                         rel(path), text.count("\n", 0, m.start()) + 1))
    out = HDR.format(title="04 内核导出符号", category="全部 EXPORT_SYMBOL(_GPL)(_NS) 导出",
                     generator="全源码 EXPORT_SYMBOL 遍历（含 AIKernel/agent 导出）")
    out += "> 条目总数：%d（按符号+文件去重）。\n\n" % len(dedup(rows))
    out += TABLE_HDR
    for sym, macro, f, ln in dedup(rows):
        out += "| %s | 内核导出 | - | %s（%s） | AI 可在模块/内核侧调用该符号 | %s:%s | %s |\n" % (
            esc(sym), esc(macro), esc(f.split("/")[0]), esc(f), ln, esc(sym))
    return out


def gen_05_kconfig():
    pat = re.compile(r"^config\s+(\w+)\s*\n(.*?)(?=^\s*(?:config|menuconfig|choice|endmenu|menu|endif|endchoice)\b)", re.M | re.S)
    out = HDR.format(title="05 Kconfig 选项", category="全部内核配置选项（含 AIKernel/ 新增）",
                     generator="全局 Kconfig 解析（type/default/depends/help）")
    rows = []
    for path in walk_files(KROOT, ("Kconfig",)):
        if "tools/" in path or "scripts/" in path:
            continue
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in pat.finditer(text):
            name = m.group(1)
            body = m.group(2)
            typ = next(iter(re.findall(r"^\s*(bool|tristate|int|hex|string)\b", body, re.M)), "-")
            dflt = next(iter(re.findall(r"^\s*default\s+(.+)", body, re.M)), "-")
            dep = next(iter(re.findall(r"^\s*depends\s+on\s+(.+)", body, re.M)), "-")
            help = next(iter(re.findall(r"^\s*help\s*\n\s*(.+?)\s*$", body, re.M | re.S)), "-")
            help = help.split("\n")[0] if help != "-" else "-"
            rows.append((name, typ, dflt, dep, help, rel(path)))
    out += "> 条目总数：%d。\n\n" % len(rows)
    out += TABLE_HDR
    for name, typ, dflt, dep, help_, f in rows:
        out += "| %s | %s | %s | %s | %s | %s | CONFIG_%s |\n" % (
            esc(name), esc(typ), esc(dflt), esc(dep), esc(help_), esc(f), esc(name))
    return out


def gen_06_module_params():
    pat = re.compile(r"module_param(?:_named|_array|_cb)?\(([^)]*)\)")
    rows = []
    for path in walk_files(KROOT, (".c",)):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in pat.finditer(text):
            args = [a.strip() for a in m.group(1).split(",")]
            rows.append((args[0], ", ".join(args[1:]), rel(path), text.count("\n", 0, m.start()) + 1))
    out = HDR.format(title="06 模块参数", category="全部 module_param（含 array/named/cb）",
                     generator="全源码 module_param 遍历")
    out += "> 条目总数：%d。\n\n" % len(dedup(rows))
    out += TABLE_HDR
    for name, args, f, ln in dedup(rows):
        out += "| %s | 模块参数 | %s | - | AI 可经模块参数控制该驱动/子系统行为 | %s:%s | %s |\n" % (
            esc(name), esc(args), esc(f), ln, esc(name))
    return out


def gen_07_netlink():
    hdr = open(os.path.join(KROOT, "include/uapi/linux/netlink.h"), encoding="utf-8", errors="ignore").read()
    fams = re.findall(r"^#define\s+(NETLINK_\w+)\s+(\d+)", hdr, re.M)
    used = {}
    for path in walk_files(KROOT, (".c",)):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for fam in [f[0] for f in fams]:
            if re.search(r"netlink_kernel_create\([^)]*%s" % fam, text, re.S):
                used.setdefault(fam, []).append(rel(path))
    known = {
        "NETLINK_ROUTE": "路由/链路/邻居/地址管理", "NETLINK_UNUSED": "未使用",
        "NETLINK_USERSOCK": "用户态保留", "NETLINK_FIREWALL": "防火墙（已废弃）",
        "NETLINK_INET_DIAG": "socket 诊断（ss）", "NETLINK_NFLOG": "netfilter 日志",
        "NETLINK_XFRM": "IPsec/加密", "NETLINK_SELINUX": "SELinux 事件",
        "NETLINK_ISCSI": "iSCSI", "NETLINK_AUDIT": "审计", "NETLINK_FIB_LOOKUP": "FIB 查询",
        "NETLINK_CONNECTOR": "内核连接器", "NETLINK_NETFILTER": "netfilter",
        "NETLINK_IP6_FW": "IPv6 防火墙", "NETLINK_DNRTMSG": "DECnet",
        "NETLINK_KOBJECT_UEVENT": "设备事件（udev）", "NETLINK_GENERIC": "通用 netlink（genl）",
        "NETLINK_SCSITRANSPORT": "SCSI 传输", "NETLINK_ECRYPTFS": "eCryptfs",
        "NETLINK_RDMA": "RDMA", "NETLINK_CRYPTO": "crypto 用户态",
        "NETLINK_SMC": "SMC", "NETLINK_IIO": "IIO 传感器",
    }
    out = HDR.format(title="07 netlink 协议族", category="全部 netlink 家族（含 NETLINK_AI）",
                     generator="include/uapi/linux/netlink.h + netlink_kernel_create 使用点")
    out += "> 条目总数：%d。\n\n" % len(fams)
    for fam, nr in fams:
        meaning = known.get(fam, "netlink 协议族（nr=%s）" % nr)
        out += TEMPLATE.format(
            name=fam, path="AF_NETLINK protocol %s (netlink family %s)" % (fam, nr),
            typ="netlink 家族", rng="family nr=%s（< MAX_LINKS=32）" % nr, default="-",
            meaning=meaning, ai_use="AI 可经该家族与内核通信（GENL 通用协议族适合 AI 扩展）",
            src="、".join(dedup(used.get(fam, [])[:2])) or "net/netlink/",
            sym="netlink_kernel_create(%s)" % fam)
    return out


def gen_08_bpf():
    bpf = open(os.path.join(KROOT, "include/uapi/linux/bpf.h"), encoding="utf-8", errors="ignore").read()
    fns = re.findall(r"FN\((\w+),\s*(\d+)(?:,\s*##ctx)?\)", bpf)
    protos = {}
    for m in re.finditer(r"^\s*\*?\s*((?:long|int)\s+(\w+)\([^()\n]*\))\s*$", bpf, re.M):
        protos[m.group(2)] = m.group(1)
    out = HDR.format(title="08 BPF 辅助函数", category="include/uapi/linux/bpf.h 全部 bpf helper",
                     generator="__BPF_FUNC_MAPPER(FN) 宏表 + 原型注释（含 AIKernel 新增 helper）")
    out += "> 条目总数：%d。\n\n" % len(fns)
    for name, nr in fns:
        proto = protos.get(name, "-")
        out += TEMPLATE.format(
            name="bpf_helper %s (id=%s)" % (name, nr), path="BPF_FUNC_%s (id %s)" % (name.upper(), nr),
            typ="BPF helper", rng="id=%s（稳定 ABI）" % nr, default="-",
            meaning="BPF 辅助函数 %s" % name, ai_use="AI 程序（BPF）内调用该 helper 感知/控制系统",
            src="include/uapi/linux/bpf.h", sym="%s（%s）" % (name, proto))
    return out


def _ioc_value(d, typ, nr, size):
    nr &= 0xFF
    typ &= 0xFF
    size &= 0x3FFF
    return (d << 30) | (size << 16) | (typ << 8) | nr


def gen_09_ioctl():
    rows = []
    for path in walk_files(os.path.join(KROOT, "include/uapi"), (".h",)):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in re.finditer(r"#define\s+(\w+)\s+", text):
            after = text[m.end():m.end() + 400]
            am = re.search(r"_IO(C)?(R|W|RW|)(\d*)?\(([^)]*)\)", after, re.S)
            if not am:
                continue
            args = [a.strip() for a in am.group(4).split(",")]
            if len(args) < 2:
                continue
            d = {"R": 2, "W": 4, "RW": 6, "": 0}.get(am.group(2) or "", 0)
            nr = args[1] if len(args) > 1 else "0"
            size = args[2] if len(args) > 2 else "0"
            rows.append((m.group(1), am.group(2) or "-", args[0], nr, size, rel(path),
                         text.count("\n", 0, m.start()) + 1))
    out = HDR.format(title="09 ioctl 命令", category="include/uapi/ 全部 ioctl 命令码",
                     generator="_IO/_IOR/_IOW/_IOWR 宏扫描（asm-generic 布局：dir<<30|size<<16|type<<8|nr）")
    out += "> 条目总数：%d。\n\n" % len(dedup(rows))
    out += TABLE_HDR
    for name, d, typ, nr, size, f, ln in dedup(rows):
        out += "| %s | ioctl（dir=%s） | type=%s nr=%s size=%s | %s | AI 可经 ioctl 控制该设备 | %s:%s | %s |\n" % (
            esc(name), esc(d), esc(typ), esc(nr), esc(size), esc(f), ln, esc(name), esc(name))
    return out


def gen_10_structs():
    targets = {
        "task_struct": "include/linux/sched.h", "mm_struct": "include/linux/mm_types.h",
        "vm_area_struct": "include/linux/mm_types.h", "page": "include/linux/mm_types.h",
        "file": "include/linux/fs.h", "inode": "include/linux/fs.h",
        "super_block": "include/linux/fs.h", "dentry": "include/linux/dcache.h",
        "sock": "include/net/sock.h", "socket": "include/linux/net.h",
        "net_device": "include/linux/netdevice.h", "sk_buff": "include/linux/skbuff.h",
        "request": "include/linux/blk-mq.h", "ctl_table": "include/linux/sysctl.h",
        "ai_runtime": "agent/ai/include/ai_runtime.h",
        "ai_telemetry_event": "AIKernel/core/ai_telemetry.h",
    }
    oktype = re.compile(r"^(?:(?:unsigned|signed|const|volatile|static|restrict)\s+)*(?:__u\d+|u\d+|s\d+|atomic\w*|raw_spinlock_t|spinlock_t|rwlock_t|mutex|wait_queue_head_t|ktime_t|gfp_t|pgoff_t|loff_t|sector_t|pid_t|umode_t|uid_t|gid_t|dev_t|mode_t|size_t|ssize_t|fmode_t|refcount_t|sockptr_t|hlist_node|list_head|rb_node|work_struct|callback_head|seqcount_t|rcu_segcblist_t|irq_flags_t|kernfs_node|u8|u16|u32|u64|s8|s16|s32|s64|bool|char|int|long|short|float|double|void|struct|enum|union|\w+_t)[\w\s\*]*$")
    field = re.compile(r"^\s*(?P<type>[\w\s\*]+?)\s+(?P<name>\w+)\s*;(?P<cmt>/\*[^*]*\*/)?\s*$", re.M)
    out = HDR.format(title="10 关键数据结构", category="关键结构体及其字段索引",
                     generator="include/linux/{sched.h,mm_types.h,fs.h,dcache.h,net.h,sock.h,netdevice.h,skbuff.h,blk-mq.h,sysctl.h} + AIKernel 字段级提取")
    out += "> 结构体数量：%d。\n\n" % len(targets)
    for name, f in targets.items():
        p = os.path.join(KROOT, f)
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8", errors="ignore").read()
        m = re.search(r"struct\s+%s\s*\{" % name, text)
        if not m:
            continue
        line0 = text.count("\n", 0, m.start()) + 1
        clean = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        m2 = re.search(r"struct\s+%s\s*\{" % name, clean)
        depth, end = 0, m2.end()
        for i in range(m2.end(), len(clean)):
            if clean[i] == "{":
                depth += 1
            elif clean[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        seg = clean[m2.start():end]
        out += "### struct %s\n\n- **路径：** %s（struct %s）\n- **类型：** 内核数据结构\n- **范围：** -\n- **默认值：** -\n- **含义：** 内核关键结构体（定义于 %s:%s）\n- **AI 控制用途：** 字段是 AI 感知/控制的基础（经 ai_telemetry/ai_policy 访问）\n- **相关源码：** %s:%s\n- **相关内核符号：** struct %s\n\n" % (
            name, f, name, f, line0, f, line0, name)
        out += "| 字段 | 类型 | 注释 |\n|------|------|------|\n"
        n = 0
        for fm in field.finditer(seg):
            if not oktype.match(fm.group("type").strip()):
                continue
            n += 1
            out += "| %s | %s | %s |\n" % (esc(fm.group("name")), esc(fm.group("type").strip()),
                                           esc(fm.group("cmt") or "-"))
        out += "\n"
    return out


def gen_11_bootparams():
    setup = {}
    for path in walk_files(KROOT, (".c",)):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in re.finditer(r"(?:__setup|early_param)\(" + r'"(\w[\w.\-]*)",\s*(\w+)', text):
            setup.setdefault(m.group(1), []).append((rel(path), m.group(2),
                                                     text.count("\n", 0, m.start()) + 1))
    doc = open(os.path.join(KROOT, "Documentation/admin-guide/kernel-parameters.txt"),
               encoding="utf-8", errors="ignore").read()
    entries = []
    for m in re.finditer(r"^\s+([a-zA-Z0-9_.\-]+)(?:=|\s).*?$", doc, re.M):
        name = m.group(1)
        start = m.end()
        nxt = re.search(r"^\s+[a-zA-Z0-9_.\-]+(?:=|\s).*?$", doc[start:], re.M)
        desc = doc[start:start + (nxt.start() if nxt else 300)].strip()
        desc = " ".join(desc.split())[:220]
        entries.append((name, desc))
    rows = sorted(set(entries))
    out = HDR.format(title="11 内核启动参数", category="全部 __setup/early_param 参数（含 ai.*）",
                     generator="Documentation/admin-guide/kernel-parameters.txt + 源码 __setup/early_param + AIKernel ai.*")
    out += "> 条目总数：%d（参数表）＋源码登记 %d。\n\n" % (len(rows), len(setup))
    for name, desc in rows:
        s = setup.get(name, [("-", "-", "-")])[0]
        out += TEMPLATE.format(
            name=name, path="内核启动参数 %s=" % name, typ="启动参数",
            rng="-", default="（未提供则用内核默认）",
            meaning=desc or "内核启动参数 %s（见 Documentation/admin-guide/kernel-parameters.txt）" % name,
            ai_use="AI 可在启动参数中预置行为（需重启生效）",
            src="%s:%s" % (s[0], s[2]) if s[0] != "-" else "Documentation/admin-guide/kernel-parameters.txt",
            sym=s[1] if s[0] != "-" else "-")
    for name, lst in sorted(setup.items()):
        if name not in set(e[0] for e in rows):
            for f, fn, ln in lst:
                out += TEMPLATE.format(
                    name=name, path="内核启动参数 %s=" % name, typ="启动参数（__setup/early_param）",
                    rng="-", default="-", meaning="内核启动参数 %s" % name,
                    ai_use="AI 可在启动参数中预置行为", src="%s:%s" % (f, ln), sym=fn)
    return out


def gen_12_errno():
    out = HDR.format(title="12 错误码索引", category="全部 errno + enum ai_error",
                     generator="include/uapi/asm-generic/errno*.h + AIKernel/core/ai_types.h enum ai_error")
    total = 0
    for f in ("include/uapi/asm-generic/errno-base.h", "include/uapi/asm-generic/errno.h"):
        p = os.path.join(KROOT, f)
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8", errors="ignore").read()
        for m in re.finditer(r"#define\s+(E[A-Z0-9]+)\s+(\d+)\s*(?:/\*([^*]*)\*/)?", text):
            total += 1
            out += TEMPLATE.format(
                name=m.group(1), path="errno %s" % m.group(1), typ="errno 错误码",
                rng="值=%s（< 4096）" % m.group(2), default="-",
                meaning=(m.group(3) or "Linux errno（见 man 3 errno）").strip(),
                ai_use="AI 决策/接口返回值对照（ai_error_to_errno 映射用）",
                src=f, sym=m.group(1))
    at = open(os.path.join(KROOT, "AIKernel/core/ai_types.h"), encoding="utf-8", errors="ignore").read()
    ai = open(os.path.join(KROOT, "agent/ai/include/ai_types.h"), encoding="utf-8", errors="ignore").read()
    for f, text in (( "AIKernel/core/ai_types.h", at), ("agent/ai/include/ai_types.h", ai)):
        for m in re.finditer(r"AI_ERR_\w+\s*=\s*(-?\d+)\s*[,}]\s*(?:/\*\s*([^*]*?)\s*\*/)?", text):
            total += 1
            out += TEMPLATE.format(
                name=m.group(0).split("=")[0].strip(), path="enum ai_error %s" % m.group(0).split("=")[0].strip(),
                typ="ai_error 错误码", rng="值=%s" % m.group(1), default="-",
                meaning=(m.group(2) or "AI 子系统错误码").strip(),
                ai_use="AI 接口统一返回码（0=成功，负值=错误）",
                src=f, sym=m.group(0).split("=")[0].strip())
    out += "> errno 总数：%d。\n\n" % total
    return out


DOCS = [
    ("00_系统调用接口.md", gen_00_syscalls),
    ("01_sysfs接口.md", gen_01_sysfs),
    ("02_procfs接口.md", gen_02_procfs),
    ("03_debugfs接口.md", gen_03_debugfs),
    ("04_内核导出符号.md", gen_04_exports),
    ("05_Kconfig选项.md", gen_05_kconfig),
    ("06_模块参数.md", gen_06_module_params),
    ("07_netlink协议族.md", gen_07_netlink),
    ("08_BPF辅助函数.md", gen_08_bpf),
    ("09_ioctl命令.md", gen_09_ioctl),
    ("10_关键数据结构.md", gen_10_structs),
    ("11_内核启动参数.md", gen_11_bootparams),
    ("12_错误码索引.md", gen_12_errno),
]


def extract_docs():
    os.makedirs(DOCS_DIR, exist_ok=True)
    for fn, gen in DOCS:
        t0 = time.time()
        out = gen()
        path = os.path.join(DOCS_DIR, fn)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)
        n = out.count("### ") + out.count("| ")
        print("[extract] %s  %d 行  %.1fs" % (fn, out.count("\n"), time.time() - t0))
    return len(DOCS)


# ---------------- 索引构建（B 轨） ----------------

def scope_files(scope):
    if scope == "docs":
        files = []
        for root in ("Documentation", "Project_Documentation"):
            files += [p for p in walk_files(os.path.join(KROOT, root), (".rst", ".txt", ".md"))]
        return files
    if scope == "interfaces":
        return [p for p in walk_files(DOCS_DIR, (".md",))]
    if scope == "source_code":
        files = []
        for root in ("AIKernel", "agent"):
            files += [p for p in walk_files(os.path.join(KROOT, root), (".c", ".h"))
                      if "/third_party/" not in rel(p)]
        for root in ("kernel", "mm", "net", "fs", "ipc", "block", "security",
                     "arch/x86", "include", "init", "drivers", "sound", "crypto"):
            p = os.path.join(KROOT, root)
            if os.path.isdir(p):
                files += [f for f in walk_files(p, (".c", ".h")) if "/Documentation/" not in rel(f)]
        return files
    if scope == "history":
        files = [p for p in walk_files(os.path.join(KROOT, "Kernel_Modification_Log"), (".md",))]
        files += [p for p in walk_files(os.path.join(KROOT, "AIKernel_Design"), (".md",))]
        files += [p for p in walk_files(os.path.join(KROOT, "agent/ai/docs"), (".md",))]
        for fn in ("AIKernel_AI重构计划.md", "AIKernel_数据源与日志系统计划.md"):
            p = os.path.join(os.path.dirname(KROOT), fn)
            if os.path.exists(p):
                files.append(p)
        return files
    return []


def chunk_file(path):
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return []
    if not text:
        return []
    lines = text.splitlines(keepends=True)
    chunks, buf, start = [], [], 1
    size = 0
    for i, line in enumerate(lines, 1):
        if len(line) > CHUNK_SIZE:
            if buf:
                chunks.append((rel(path), start, i - 1, "".join(buf)))
                buf, size = [], 0
            rest = line
            while len(rest) > CHUNK_SIZE:
                chunks.append((rel(path), i, i, rest[:CHUNK_SIZE]))
                rest = rest[CHUNK_SIZE - OVERLAP:]
            buf, size, start = [rest], len(rest), i
            continue
        buf.append(line)
        size += len(line)
        if size >= CHUNK_SIZE:
            chunks.append((rel(path), start, i, "".join(buf)))
            ov, osz = [], 0
            for l in reversed(buf):
                if osz + len(l) > OVERLAP:
                    break
                ov.insert(0, l)
                osz += len(l)
            buf, size, start = list(ov), osz, i - len(ov) + 1 if ov else i + 1
    if buf:
        chunks.append((rel(path), start, len(lines), "".join(buf)))
    return chunks


def build_scope(scope, base=0):
    t0 = time.time()
    files = scope_files(scope)
    chunks = []
    for f in files:
        chunks += chunk_file(f)
    df = Counter()
    for _, _, _, text in chunks:
        df.update(set(tokenize(text)))
    n_docs = max(1, len(chunks))
    idx = None
    import faiss
    idx = faiss.IndexFlatIP(DIM)
    records = []
    for i, (src, s, e, text) in enumerate(chunks):
        cid = base + i
        vec = embed(text, df, n_docs)
        v = [vec.get(i, 0.0) for i in range(DIM)]
        import numpy as np
        idx.add(np.array([v], dtype="float32"))
        records.append({"id": cid, "source": src, "start_line": s,
                        "end_line": e, "scope": scope, "text": text})
    if idx is not None and idx.ntotal:
        faiss_write(idx, os.path.join(EMB_DIR, "%s.faiss" % scope))
    print("[index] %s  %d 块  索引 %d 向量  %.1fs" % (scope, len(chunks), idx.ntotal if idx else 0, time.time() - t0))
    return records


def build_index(small=False, only=None):
    import numpy as np
    import faiss
    os.makedirs(EMB_DIR, exist_ok=True)
    scopes_meta = []
    kept = []
    base = 0
    if only and os.path.exists(CORPUS):
        with open(CORPUS, encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                if r["scope"] != only:
                    kept.append(r)
        if kept:
            base = max(r["id"] for r in kept) + 1
        scopes_meta = sorted({r["scope"] for r in kept} | {only})
        if only not in scopes_meta:
            scopes_meta.append(only)
    scopes = [only] if only else (SMALL_SCOPES if small else SCOPES)
    all_records = []
    for s in scopes:
        recs = build_scope(s, base=base if only else len(all_records))
        all_records += recs
    all_records += kept
    all_records.sort(key=lambda r: r["id"])
    if not only:
        scopes_meta = scopes
    meta = {
        "version": 1, "dim": DIM, "chunk_size": CHUNK_SIZE, "overlap": OVERLAP,
        "created": "2026-08-13", "embedding": "local-hashing-tfidf(dim=%d)" % DIM,
        "scopes": scopes_meta, "total_chunks": len(all_records),
        "chunks": [{k: r[k] for k in ("id", "source", "start_line", "end_line", "scope")} for r in all_records],
    }
    with open(METADATA, "w", encoding="utf-8", newline="\n") as f:
        json.dump(meta, f, ensure_ascii=False)
    with open(CORPUS, "w", encoding="utf-8", newline="\n") as f:
        for r in all_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("[index] metadata.json + corpus.jsonl 写入（total=%d）" % len(all_records))
    return len(all_records)


# ---------------- 检索（ai_rag_query） ----------------

class RagEngine:
    def __init__(self, small=False):
        self.small = small
        self.scopes = SMALL_SCOPES if small else SCOPES
        self.records = {}
        self.df = Counter()
        self.postings = defaultdict(dict)
        self.indexes = {}
        self.avgdl = {}
        import faiss
        self.faiss = faiss
        if os.path.exists(CORPUS):
            with open(CORPUS, encoding="utf-8") as f:
                for line in f:
                    r = json.loads(line)
                    self.records[r["id"]] = r
                    for tok in set(tokenize(r["text"])):
                        self.postings[tok][r["id"]] = self.postings[tok].get(r["id"], 0) + 1
        for s in self.scopes:
            p = os.path.join(EMB_DIR, "%s.faiss" % s)
            if os.path.exists(p):
                self.indexes[s] = faiss_read(p)
        self.avgdl = 400.0

    def _bm25(self, toks, rec):
        score, n = 0.0, len(self.records)
        dl = len(rec["text"])
        for t in set(toks):
            tf = self.postings.get(t, {}).get(rec["id"], 0)
            if not tf:
                continue
            df = len(self.postings.get(t, {}))
            idf = math.log(1.0 + (n - df + 0.5) / (df + 0.5))
            score += idf * tf * 2.0 / (tf + 2.0 * (0.25 + 0.75 * dl / self.avgdl))
        return score

    def _exact(self, q, rec):
        qn = " ".join(q.lower().split())
        t = rec["text"].lower()
        if qn and qn in t:
            return 3.0
        qs = re.sub(r"\W+", "", qn)
        ts = re.sub(r"\W+", "", t)
        if qs and qs in ts:
            return 1.5
        return 0.0

    def search_scope(self, scope, vec, toks, top_k, q):
        import numpy as np
        cand = set()
        cos = {}
        for t in toks:
            cand.update(self.postings.get(t, {}))
        idx = self.indexes.get(scope)
        if idx is not None and idx.ntotal:
            qv = np.array([vec], dtype="float32")
            scores, ids = idx.search(qv, min(64, idx.ntotal))
            for sc, i in zip(scores[0], ids[0]):
                if i >= 0:
                    cand.add(int(i))
                    cos[int(i)] = float(sc)
        out = []
        for cid in cand:
            rec = self.records.get(cid)
            if rec is None or rec.get("scope") != scope:
                continue
            out.append((self._bm25(toks, rec) + self._exact(q, rec) + cos.get(cid, 0.0) * 0.2, rec))
        out.sort(key=lambda x: -x[0])
        return out[:top_k]


def ai_rag_query(query, top_k=5, scopes=None, small=False):
    """AIKernel RAG 检索接口（用户态 aikd 代理，Prompt 14）。

    参数:
      query : str   自然语言或关键字查询
      top_k : int   每库返回条数（默认 5）
      scopes: list|None  限定检索库（docs/interfaces/source_code/history，默认全库）
      small : bool  使用小范围测试索引
    返回:
      list[dict]  Top-K 片段，每片含
      {score, source(文件:行号), start_line, end_line, text, scope}
      （来源带文件:行号，AI 可直接溯源）；错误时返回 []。
    """
    if not query or not isinstance(query, str):
        return []
    engine = RagEngine(small=small)
    if scopes is None:
        scopes = engine.scopes
    scopes = [s for s in scopes if s in engine.scopes]
    toks = tokenize(query)
    df = Counter({t: len(engine.postings.get(t, {})) for t in toks})
    n_docs = max(1, len(engine.records))
    qv = embed(query, df, n_docs)
    import numpy as np
    v = np.array([qv.get(i, 0.0) for i in range(DIM)], dtype="float32")
    results, seen = [], set()
    for s in scopes:
        for sc, rec in engine.search_scope(s, v, toks, top_k, query):
            if rec["id"] in seen:
                continue
            seen.add(rec["id"])
            results.append({
                "score": round(sc, 4),
                "source": "%s:%d" % (rec["source"], rec["start_line"]),
                "start_line": rec["start_line"], "end_line": rec["end_line"],
                "text": rec["text"][:500], "scope": rec["scope"]})
    results.sort(key=lambda x: -x["score"])
    return results


def verify_queries():
    cases = [
        "swappiness",
        "如何调整进程的 OOM 分数",
        "哪个系统调用可以发送信号",
        "netlink 协议族 AI",
        "cgroup 控制器",
    ]
    for q in cases:
        res = ai_rag_query(q, top_k=5)
        print("\n=== 查询: %s ===" % q)
        for r in res[:5]:
            print("  [%.4f] %s (%s)" % (r["score"], r["source"], r["scope"]))
            print("         %s" % " ".join(r["text"].split())[:120])


def main():
    ap = argparse.ArgumentParser(description="AIKernel RAG 知识库构建与检索")
    ap.add_argument("--extract", action="store_true", help="重新生成 AIKernel_Docs/ 12 个接口文档")
    ap.add_argument("--index", action="store_true", help="构建向量索引（默认全量；--small 小范围）")
    ap.add_argument("--only", default=None, help="只重建指定库（docs/interfaces/source_code/history）")
    ap.add_argument("--small", action="store_true", help="小范围模式（interfaces+history，临时索引目录）")
    ap.add_argument("--query", metavar="TEXT", help="RAG 检索查询")
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--scope", default=None, help="限定库：docs/interfaces/source_code/history/all")
    ap.add_argument("--verify", action="store_true", help="运行 5 组验收查询")
    args = ap.parse_args()

    if args.small:
        global EMB_DIR, METADATA, CORPUS, ROOT
        tmp = os.path.join(tempfile.gettempdir(), "opencode", "rag_small")
        os.makedirs(os.path.join(tmp, "embeddings"), exist_ok=True)
        EMB_DIR, METADATA, CORPUS = os.path.join(tmp, "embeddings"), os.path.join(tmp, "metadata.json"), os.path.join(tmp, "corpus.jsonl")
        print("[small] 临时索引目录: %s" % tmp)

    if args.extract:
        n = extract_docs()
        print("[done] AIKernel_Docs/ 生成 %d 个文档" % n)
    if args.index:
        if args.only:
            global SCOPES
            SCOPES = [args.only]
        n = build_index(small=args.small, only=args.only)
        print("[done] 索引构建完成（%d 块）" % n)
    if args.query:
        scopes = None if args.scope in (None, "all") else [args.scope]
        res = ai_rag_query(args.query, top_k=args.top_k, scopes=scopes, small=args.small)
        for r in res:
            print("[%.4f] %s (%s)" % (r["score"], r["source"], r["scope"]))
            print("       %s" % " ".join(r["text"].split())[:160])
        print("[done] %d 条结果" % len(res))
    if args.verify:
        verify_queries()
    if not (args.extract or args.index or args.query or args.verify):
        ap.print_help()


if __name__ == "__main__":
    main()
