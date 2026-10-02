#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
gen_registry.py - AIKernel Agent 工具注册表生成器（v2）

生成 Ask 工具调用闭环使用的 tools.json（OpenAI function-calling 格式的
工具清单 + 通道专属路由字段），并输出生成报告（工具总数、分通道计数、
分风险级计数）。

v2 相对 v1 的机制升级：
  1. risk 字段全量标注：R（只读）/ W1（低危写）/ W2（高危写），
     每个工具必带；executor 与后续权限分级按此消费；
  2. exec 白名单单源化：exec.run 工具内嵌 "exec":{"default_timeout",
     "commands":[{command,bin,args_template,timeout,risk,path_check,
     args0}]}，executor 启动时从 tools.json 加载并以其为唯一权威
     （bin 配错即拒绝该命令），本文件与 C 内置表不再双源；
  3. ACT 工具 description 显式声明按 domain 广播的副作用；
  4. 新通道 netlink-sense（AI_CMD_SENSE 拉遥测）；
  5. 增补工具：/sys/kernel/ai/stats 7 节点、ai_cgroup 4 节点、
     /proc/ai/telemetry 写 2 个、SME 记忆面 10 个。

来源（按优先级）：
  a. QEMU 实测采集：--dump <registry-dump.txt>（内核启动后 init 脚本导出
     /proc/ai 与 /sys/kernel/ai 的实际节点清单），解析后生成 procfs-read
     工具（并校验 sysfs 可写节点）；
  b. 内核源码静态梳理（AIKernel/vfs/ai_vfs_procfs.c、core/ai_sysfs.c、
     core/ai_sysfs_stats.c、core/ai_cgroup.c、core/ai_procfs.c 及各子系统
     ai_control_register 调用点）——默认表，dump 缺失时兜底。

产出：
  tools.json          C 侧注册表（含 channel 路由字段 + risk + exec 单源表）
  tools.openai.json   纯 OpenAI function-calling 格式（可直接喂 API 调试）
  tools_report.txt    生成报告（总数 + 分通道 + 分风险级）
  stdout              报告摘要

用法：
  python3 tools/gen_registry.py [--dump registry-dump.txt] [--out-dir DIR]
"""

import argparse
import datetime
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# 通道常量
# ---------------------------------------------------------------------------
CH_PROC = "procfs-read"
CH_SYSFS = "sysfs-write"
CH_NETLINK = "netlink-act"
CH_NLSENSE = "netlink-sense"
CH_EXEC = "exec"
CH_MEMORY = "memory"
CH_SHELL = "shell"

RISK_R = "R"        # 只读
RISK_W1 = "W1"      # 低危写
RISK_W2 = "W2"      # 高危写

# ACT 定向说明（v3：写进每个 netlink-act 工具 description，
# ask 的 system prompt 工具摘要读 description，自动透出给模型。
# v2 起 ACT 载荷携带 param 定向参数名，本执行器按注册表 param 填写，
# 内核只定向执行本参数，同域其他参数不再被广播污染）
ACT_BROADCAST_WARN = "该操作仅定向作用于本参数（v2 按参数名定向下发，不影响同域其他参数）。"


def obj_schema(properties=None, required=None):
    """OpenAI JSON Schema object 构造器"""
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
    }


# ---------------------------------------------------------------------------
# b. 内核源码静态梳理的默认表
# ---------------------------------------------------------------------------

# /proc/ai 节点（AIKernel/vfs/ai_vfs_procfs.c: proc_create 权限位 + 语义）
DEFAULT_PROCFS = [
    ("/proc/ai/status", 0o444, "内核 AI 子系统运行状态总览（enabled/模型/内存/统计开关）"),
    ("/proc/ai/decisions", 0o400, "决策记录 ring 快照（4096 条，含 decision/outcome 全字段）"),
    ("/proc/ai/chains", 0o400, "因果链视图（trigger_event_id → decision_id → outcome）"),
    ("/proc/ai/control", 0o444, "可控制参数表（23 个参数的 name/domain/min/max/current/default）"),
    ("/proc/ai/latency", 0o444, "决策/感知延迟统计（执行耗时直方图）"),
    ("/proc/ai/hitrate", 0o444, "策略命中率统计（attempts/hits）"),
    ("/proc/ai/telemetry", 0o644, "遥测 ring 转储（全类别事件记录；读，写见 procfs.write.*）"),
    ("/proc/ai/sched/stats", 0o444, "调度域遥测统计（AI 采样器累计）"),
    ("/proc/ai/sched/classify", 0o644, "调度分类接口（AI 识别的任务分类结果）"),
    ("/proc/ai/vfs/stats", 0o444, "VFS/B 轨遥测统计（挂载/文件锁/poll/错误）"),
    ("/proc/ai/vfs/rates", 0o444, "VFS 事件速率统计"),
]

# /sys/kernel/ai/stats 只读统计（AIKernel/core/ai_sysfs_stats.c
# ai_stats_attrs[] 实名清单，7 个；节点名以内核源码为准）
SYSFS_STATS = [
    ("telemetry_emitted", "遥测已发射事件计数（全 CPU 合计）"),
    ("telemetry_dropped", "遥测丢弃事件计数（ring 满等）"),
    ("telemetry_sampled_skip", "遥测采样跳过计数"),
    ("decisions_total", "决策总尝试数（策略匹配计数）"),
    ("decisions_hit", "决策命中数"),
    ("decisions_hitrate_permille", "决策命中率（千分比）"),
    ("runtime_state", "Runtime 状态机当前值"),
]

# ai_cgroup 接口文件（AIKernel/core/ai_cgroup.c）。QEMU guest 实测
# （2026-09-28）：cgroup 根下仅 ai.inferences 暴露（RO，骨架期只读
# 计数）；ai.max_inferences / ai.max_tops / ai.mem_limit_mb 未出现在
# /sys/fs/cgroup（内核侧未接线到可见节点）——按"不存在就跳过"原则
# 不注册，待内核暴露后补录。
CGROUP_FILES = [
    ("inferences", "cgroup AI 已发起推理计数（RO）"),
]

# /sys/kernel/ai 可写节点（AIKernel/core/ai_sysfs.c，"一个文件一个值"）
# 每项: (相对路径, 说明, 参数描述, 参数 schema)
DEFAULT_SYSFS = [
    ("enabled", "AI 子系统总开关（1/0；写 1 会幂等拉起 Runtime）",
     "开关值", obj_schema({"value": {"type": "string", "description": "1=启用 0=停用"}},
                         ["value"])),
    ("model_load", "加载 AIKWMDL v1 格式模型（AIKernel/tools 或 ~/w1k-model/gen_model.py 可生成），旧 echo 语义已废",
     "模型名", obj_schema({"value": {"type": "string", "description": "模型名或路径"}},
                          ["value"])),
    ("model_unload", "按名卸载模型",
     "模型名", obj_schema({"value": {"type": "string", "description": "模型名"}},
                          ["value"])),
    ("policy/think", "触发一次内核决策闭环（格式: event_id,domain,type,value[,pid]"
     "；走 ai_runtime_think 全流程，等价第 2 决策来源）",
     "决策输入", obj_schema({"value": {"type": "string",
                                       "description": "格式: <event_id>,<domain>,<type>,<value>[,<pid>]"}},
                            ["value"])),
    ("policy/outcome", "上报决策结果（决策闭环第 4 步，格式: decision_id,outcome,metric_delta）",
     "结果上报", obj_schema({"value": {"type": "string",
                                        "description": "格式: <decision_id>,<outcome 0-4>,<metric_delta>"}},
                            ["value"])),
    ("policy/global_enable", "决策执行全局闸门（关闭后 ai_policy_execute 单分支拒绝）",
     "开关值", obj_schema({"value": {"type": "string", "description": "1=允许决策执行 0=全局拒绝"}},
                          ["value"])),
    ("policy/max_impact_pct", "安全边界：决策参数最大影响幅度（百分比）",
     "幅度", obj_schema({"value": {"type": "integer", "description": "最大影响幅度百分比"}},
                        ["value"])),
    ("policy/rollback", "按 decision_id 回退决策（恢复决策前快照值）",
     "决策 ID", obj_schema({"value": {"type": "string", "description": "decision_id"}},
                           ["value"])),
    ("policy/refresh", "同步策略目录（扫描策略注册表，幂等新建 <name> 开关文件）",
     "无参数写触发", obj_schema({"value": {"type": "string", "description": "任意非空内容触发"}},
                               ["value"])),
    ("policy/chain_dir", "因果链 CSV 导出根目录",
     "目录路径", obj_schema({"value": {"type": "string", "description": "导出目录绝对路径"}},
                            ["value"])),
]

# /proc/ai/telemetry 写接口（AIKernel/core/ai_procfs.c
# ai_proc_telemetry_write：strcmp "format=raw"/"format=human"/"reset"）
# 每项: (工具名, value 枚举, 风险级, 说明)
TELEMETRY_WRITES = [
    ("procfs.write.telemetry_format", ["format=raw", "format=human"],
     RISK_W1, "切换遥测输出格式：format=raw（原始定长记录）或 "
              "format=human（文本行，默认）。影响后续读 "
              "/proc/ai/telemetry 与 SENSE 输出"),
    ("procfs.write.telemetry_reset", ["reset"],
     RISK_W2, "清空全部遥测/决策 ring（需 CAP_SYS_ADMIN；记录不可恢复，"
              "慎用——如需留档先在 procfs 侧导出）"),
]

# 可控制参数表（AIKernel/core/ai_control.c + 各子系统 ai_control_register）
# 每项: (参数名, 域, task 参数?, min, max, 默认, 说明)
NETLINK_PARAMS = [
    ("sched.nice", 1, True, -20, 19, 0,
     "设置进程 nice 值（实时生效；data[0]=pid data[1]=value）"),
    ("sched.affinity", 1, True, 0, 255, 0,
     "设置进程 CPU 亲和（掩码/编号，实时生效；同上 data 约定）"),
    ("sched.oom_score", 1, True, -1000, 1000, 0,
     "设置进程 oom_score_adj（实时生效；同上 data 约定）"),
    ("sched.timeslice", 1, False, 1, 1000, 20,
     "调度时间片参数（EEVDF base_slice，单位 0.1ms；安全限幅+快照+记录）"),
    ("mm.swappiness", 2, False, 0, 100, 60,
     "内存换页倾向 swappiness（实时生效，经 mm/vmscan.c 门控访问器）"),
    ("mm.readahead", 2, False, 0, 4096, 128,
     "预读窗口 KB（写全部 bdi ra_pages，与 /sys/class/bdi/*/readahead_kb 同源，实时生效）"),
    ("mm.thp", 2, False, 0, 2, 1,
     "透明大页模式（0=never 1=madvise 2=always，实时生效）"),
    ("mm.reclaim_prio", 2, False, 0, 100, 60,
     "回收优先级（映射 /proc/sys/vm/vfs_cache_pressure）"),
    ("io.priority", 3, False, 0, 7, 4,
     "I/O 优先级（实时生效）"),
    ("io.bandwidth", 3, False, 0, 100, 100,
     "写回带宽比 max_ratio（百分比；0=恢复默认 100；与 /sys/class/bdi/*/max_ratio 同源，实时生效）"),
    ("net.cwnd", 4, False, 1, 4096, 256,
     "TCP 拥塞窗口参数（仅作用于 ai_cca 拥塞控制算法的连接）"),
    ("net.rto", 4, False, 1, 10000, 200,
     "TCP 重传超时参数 ms（实时生效）"),
    ("net.qdisc", 4, False, 0, 2, 0,
     "诚实保留 reserved：运行时 graft（dev_graft_qdisc）实测冻结网络栈，无安全实现路径；仅支持查询"),
    ("net.nftables", 4, False, 0, 1, 0,
     "AIKernel 自有 netfilter LOCAL_OUT 采集钩子开关（真注册/真计数），非 nft chain"),
    ("power.freq", 6, False, 0, 10000, 0,
     "aiguard 频率上限万分比（如 3000=30%；经 aiguard governor 真实钳制；"
     "QEMU 无 cpufreq 时作用于请求表，实机直接生效）"),
    ("power.cstate", 6, False, 0, 10, 0,
     "CPU DMA 延迟容忍（单位 ×100us；经 PM QoS /dev/cpu_dma_latency 真实生效）"),
    ("power.wakeup", 6, False, 0, 1, 1,
     "调度唤醒事件采集开关（sched_wakeup tracepoint 探针门控：0=停采 1=采集）"),
    ("sec.lsm_override", 5, False, 0, 1, 0,
     "AIKernel 自家 LSM 执行档位（0=observe 只观测 1=enforce 按规则拦截；默认 0）"),
    ("sec.seccomp", 5, False, 0, 1, 0,
     "向 AIKernel LSM 决策表注入/解除目标 pid 的 deny 规则（lsm=ai 启用时真实拦截），非 seccomp BPF"),
    ("sec.audit", 5, False, 0, 1, 0,
     "AIKernel 审计采集开关（0=停采、事件在 gate 直接丢弃 1=采集关联）"),
    ("proc.signal", 12, True, 0, 64, 0,
     "向目标进程投递信号（data[0]=pid data[1]=信号号；kthread/init 受保护拒绝，实时生效）"),
    ("proc.freeze", 12, True, 0, 1, 0,
     "冻结/解冻目标进程（data[0]=pid data[1]=1 冻结 SIGSTOP / 0 解冻 SIGCONT，实时生效）"),
    ("proc.rlimit", 12, True, 0, 1000000, 0,
     "设置目标进程资源软限（data[0]=pid data[1]=软限值 data[2]=资源号 res，"
     "prlimit64 语义仅改 cur，实时生效）"),
    ("ai.decision_inject", 5, False, 0, 1, 0,
     "AI 决策注入全局总开关：开启后内核 5 个决策挂点（OOM 评分/vruntime 加权/唤醒抢占/"
     "预读窗口/回收优先级）按 per-hook 使能真实生效启发式偏置；默认关=与原生行为一致"),
    ("ai.decision_oom", 2, False, 0, 1, 0,
     "OOM 受害者评分偏置使能（交互式保护/批处理加压，badness ±200；需先开 decision_inject）"),
    ("ai.decision_sched", 1, False, 0, 1, 0,
     "调度决策注入使能（vruntime 加权 ±10% + 唤醒抢占提示，成对开关；需先开 decision_inject）"),
    ("ai.decision_mm", 2, False, 0, 1, 0,
     "内存决策注入使能（预读窗口 ±1 档 + 回收扫描优先级 ±1，成对开关；需先开 decision_inject）"),
]

# 带附加数据槽的参数：schema 额外参数（executor 按 data[index] 填充）
EXTRA_PROPS = {
    "proc.rlimit": ("res", {
        "type": "integer",
        "description": "rlimit 资源号（内核 RLIMIT_* 常量：7=NOFILE 9=STACK "
                       "4=CORE…；缺省 7）",
        "minimum": 0, "maximum": 15,
    }),
}

# ---------------------------------------------------------------------------
# exec 白名单（v2 单源表）
#
# 每条: dict(command, risk, bin, timeout, path_check, args_template, args0)
#   - bin: 绝对路径，executor 运行时唯一权威（tools.json 内嵌），access
#     失败即拒绝该命令——改 json 即生效，无需重编译；
#   - timeout: 秒，0 = 工具级 default_timeout(30)；
#   - path_check: W1 文件类，写目标绝对路径限 /root /tmp /var/ai；
#   - args0: 首参动词二级白名单（systemctl 按动词分级 R/W2）。
#
# 明确不收录（评审决策）：rm chmod chown mkfs fdisk find awk renice——
# rm/chmod/chown 不可逆改系统态超出 W1 语义；mkfs/fdisk 可毁盘；
# find/awk 具任意执行面（-exec / system()），白名单机制约束不住；
# renice 与 sched.nice ACT 能力重复。如需，走 sysfs/netlink 受控通道。
# ---------------------------------------------------------------------------

EXEC_DEFAULT_TIMEOUT = 30


def ex(cmd, risk, bin=None, timeout=0, path_check=False,
       args_template=None, args0=None):
    """构造单条 exec.commands 条目"""
    e = {"command": cmd, "risk": risk, "bin": bin or f"/usr/bin/{cmd}"}
    if timeout:
        e["timeout"] = timeout
    if path_check:
        e["path_check"] = True
    if args_template:
        e["args_template"] = args_template
    if args0:
        e["args0"] = [{"verb": v, "risk": r} for v, r in args0]
    return e


EXEC_COMMANDS = [
    # ---- R 级（只读诊断）----
    # 11 个基线 + 18 个 v2 新增（journalctl 单列：带 --no-pager 模板）
    *[ex(c, RISK_R) for c in (
        "ls", "cat", "head", "tail", "grep", "ps", "free", "df",
        "uname", "uptime", "date",
        "dmesg", "ip", "ss", "stat", "wc", "sort", "uniq",
        "cut", "which", "whereis", "lsblk", "du", "lscpu", "vmstat",
        "pidof", "pgrep", "id",
    )],
    ex("journalctl", RISK_R, timeout=60,
       args_template=["--no-pager"], bin="/usr/bin/journalctl"),
    # curl/ollama：W4A onboarding 期 AI 诊断的最小补充（只读面）
    ex("curl", RISK_R, timeout=60),
    ex("ollama", RISK_R, timeout=60, bin="/usr/local/bin/ollama"),
    # systemctl：只读子命令 R，启停子命令 W2（首参二级白名单）
    ex("systemctl", RISK_W2, timeout=60,
       args_template=["--no-pager"],
       args0=[("status", RISK_R), ("list-units", RISK_R),
              ("is-active", RISK_R), ("is-enabled", RISK_R),
              ("start", RISK_W2), ("stop", RISK_W2),
              ("restart", RISK_W2)]),
    # W10-A 运维四件套 AI 接入：防火墙（W2 高危写）与时间状态（R）；journalctl 上方已有
    ex("nft", RISK_W2, timeout=30, bin="/usr/sbin/nft"),
    ex("timedatectl", RISK_R, timeout=30, bin="/usr/bin/timedatectl"),
    # W11 网络细控 AI 接入：tc 流量整形/优先级（W2 高危写，真改网络行为）
    ex("tc", RISK_W2, timeout=30, bin="/usr/sbin/tc"),
    # ---- W1 级（低危写；写目标绝对路径限 /root /tmp /var/ai）----
    # 8 个直接注册；tar/gzip/traceroute 单列：自定义超时
    *[ex(c, RISK_W1, path_check=True) for c in (
        "ping", "mkdir", "touch", "cp", "mv", "ln", "sed", "tee",
    )],
    ex("tar", RISK_W1, path_check=True, timeout=120),
    ex("gzip", RISK_W1, path_check=True, timeout=120),
    ex("traceroute", RISK_W1, timeout=60),
    # ---- W2 级（高危写）----
    ex("kill", RISK_W2),
    ex("apt", RISK_W2, timeout=300),
    ex("dpkg", RISK_W2, timeout=300),
    ex("passwd", RISK_W2, bin="/usr/bin/passwd"),
]

EXEC_ENUM = [c["command"] for c in EXEC_COMMANDS]


# ---------------------------------------------------------------------------
# 工具构造器
# ---------------------------------------------------------------------------

def tool_procfs(path, desc):
    rel = path[len("/proc/ai/"):].replace("/", "_")
    return {
        "name": "procfs.read." + rel,
        "channel": CH_PROC,
        "risk": RISK_R,
        "description": f"读取 {path}（只读）：{desc}",
        "path": path,
        "parameters": obj_schema(),
    }


def tool_readfile(name, path, desc):
    """通用只读文件工具（/sys/kernel/ai/stats、/sys/fs/cgroup/ai.*）"""
    return {
        "name": name,
        "channel": CH_PROC,
        "risk": RISK_R,
        "description": f"读取 {path}（只读）：{desc}",
        "path": path,
        "parameters": obj_schema(),
    }


def tool_sysfs(rel, desc, desc_short, schema):
    name = "sysfs.write." + rel.replace("/", "_")
    return {
        "name": name,
        "channel": CH_SYSFS,
        "risk": RISK_W1,
        "description": f"写 /sys/kernel/ai/{rel}（需 CAP_SYS_ADMIN，"
                       f"决策进内核决策 ring/因果链）：{desc}",
        "path": "/sys/kernel/ai/" + rel,
        "parameters": schema,
    }


def tool_writefile(name, path, value_desc, risk, desc, schema):
    """写固定文件工具（/proc/ai/telemetry 的 format=/reset）"""
    return {
        "name": name,
        "channel": CH_SYSFS,   # 复用"写注册表固定节点 value"通道
        "risk": risk,
        "description": f"{desc}（写 {path}，value 取 {value_desc}）",
        "path": path,
        "parameters": schema,
    }


def tool_netlink(name, domain, task, vmin, vmax, default, desc):
    """23 个可控参数每个一个工具，如 netlink.act.sched.nice(pid,value)"""
    props = {}
    required = ["value"]
    if task:
        props["pid"] = {
            "type": "integer", "description": "目标进程 PID（>0）",
            "minimum": 1,
        }
        required = ["pid", "value"]
    props["value"] = {
        "type": "integer",
        "description": f"参数值（域 [{min(vmin, vmax)}, {max(vmin, vmax)}]，"
                       f"内核默认 {default}，客户端与内核双层钳制）",
        "minimum": min(vmin, vmax),
        "maximum": max(vmin, vmax),
    }
    props["confidence"] = {
        "type": "integer", "description": "模型置信度 0-100（默认 50）",
        "minimum": 0, "maximum": 100,
    }
    extra = EXTRA_PROPS.get(name)
    if extra:
        props[extra[0]] = extra[1]
        required.append(extra[0])
    clamp_note = ("（默认安全钳制可能拦截翻转，需临时调 "
                  "/sys/kernel/ai/policy/max_impact_pct）") if (vmin, vmax) == (0, 1) else ""
    return {
        "name": "netlink.act." + name,
        "channel": CH_NETLINK,
        "risk": RISK_W2,
        "description": f"NETLINK_AI ACT 下发可控参数 {name}：{desc}"
                       f"{clamp_note} "
                       f"{ACT_BROADCAST_WARN}"
                       "值域由客户端钳制 + 内核安全边界双层兜底。",
        "param": name,
        "domain": domain,
        "task_param": task,
        "value_min": vmin,
        "value_max": vmax,
        "parameters": obj_schema(props, required),
    }


def tool_netlink_sense():
    """netlink.sense：AI_CMD_SENSE 拉内核遥测（只读）"""
    return {
        "name": "netlink.sense",
        "channel": CH_NLSENSE,
        "risk": RISK_R,
        "description": "NETLINK_AI SENSE 拉取内核感知遥测（AI_CMD_SENSE，"
                       "只读，要求 AI 子系统已启用）：按 CPU 读取遥测记录，"
                       "human 格式返回遥测文本，raw 格式返回二进制流统计",
        "parameters": obj_schema({
            "cpu": {"type": "string",
                    "description": "\"all\" 或 CPU 编号（如 \"0\"）",
                    "default": "all"},
            "count": {"type": "integer",
                      "description": "最多拉取记录数（1-4096）",
                      "minimum": 1, "maximum": 4096, "default": 128},
            "format": {"type": "string",
                       "description": "输出格式（默认 human）",
                       "enum": ["raw", "human"], "default": "human"},
        }),
    }


def tool_exec_run():
    """exec.run：白名单命令执行（单源表内嵌 tools.json）。
    工具级不设 risk——exec 的风险按命令分级，逐命令见 exec.commands"""
    return {
        "name": "exec.run",
        "channel": CH_EXEC,
        "description": "执行白名单 shell 命令（fork+execv 不经 shell）。"
                       "白名单/可执行路径/超时/风险分级单源于本工具内嵌的 "
                       "exec.commands（R 只读诊断 / W1 低危写（目标限 "
                       "/root /tmp /var/ai）/ W2 高危写）；参数含 shell "
                       "元字符或超长整条拒绝；默认 30 秒超时后 SIGKILL；"
                       "stdin 接 /dev/null（无参 cat 不会挂起）",
        "exec": {
            "default_timeout": EXEC_DEFAULT_TIMEOUT,
            "commands": EXEC_COMMANDS,
        },
        "parameters": obj_schema(
            {
                "command": {"type": "string", "description": "命令名（白名单内）",
                            "enum": EXEC_ENUM},
                "args": {"type": "array",
                         "description": "命令参数列表（如 [\"-h\"]；含元字符/"
                                        "超 256 字符整条拒绝）",
                         "items": {"type": "string"}},
            },
            ["command"]),
    }


def tool_mem(name, risk, desc, props=None, required=None):
    """SME 记忆面工具构造器（端点对照 sme/api/server.py）"""
    return {
        "name": name,
        "channel": CH_MEMORY,
        "risk": risk,
        "description": desc,
        "parameters": obj_schema(props or {}, required or []),
    }


def tool_shell_drop():
    """AI 应用户请求降入维护 shell（方案 A：executor 层 fork/exec bash，
    复用 cmd_shell 内置动作语义；exit 返回后结果回填 ask 闭环）"""
    return {
        "name": "sys.shell",
        "channel": CH_SHELL,
        "risk": RISK_W1,
        "description": "替用户降入交互式维护 shell（bash）。仅当用户明确"
                       "请求打开 shell / 进入命令行时调用（如「帮我打开一个 "
                       "shell」）；用户输入 exit 退出后本工具返回，再把控制"
                       "权交还对话。审计行记录「AI 应请求开启 shell」。",
        "parameters": obj_schema({}, []),
    }


def memory_tools():
    """v2 SME 面 13 工具（原 3 + 新 10）"""
    id_param = {"id": {"type": "string",
                       "description": "记忆 ID（如 m_xxxx）"}}
    return [
        tool_mem("memory.search", RISK_R,
                 "系统接口/参数/用法问题必先查本工具：凡涉及 AIKernel 系统"
                 "接口、/proc/ai 与 /sys/kernel/ai 节点、内核参数、netlink/"
                 "procfs/sysfs 操作方式、工具用法的问题（怎么调、如何查看、"
                 "如何配置），必须先用本工具检索 SME 记忆库（含 "
                 "aikernel-interface 接口语料），依据命中结果再回答或行动，"
                 "不要凭空猜测接口用法。SME 语义检索（POST /memories/search，"
                 "两段式+混合检索），返回命中记忆 JSON 原文",
                 {"text": {"type": "string", "description": "查询文本"},
                  "top_k": {"type": "integer",
                            "description": "返回条数上限（默认 3）",
                            "minimum": 1, "maximum": 20}},
                 ["text"]),
        tool_mem("memory.add", RISK_W1,
                 "写入一条记忆到 SME（POST /memories），供后续 ask 检索",
                 {"text": {"type": "string", "description": "记忆文本"},
                  "metadata": {"type": "string",
                               "description": "可选元数据 JSON 对象字符串"}},
                 ["text"]),
        tool_mem("memory.stats", RISK_R,
                 "查询 SME 记忆库统计（GET /stats，含记忆数/Region 数/"
                 "graph 边数）"),
        tool_mem("memory.get", RISK_R,
                 "按 ID 读取单条记忆全文（GET /memories/{id}）",
                 dict(id_param), ["id"]),
        tool_mem("memory.hit", RISK_W1,
                 "Ebbinghaus 强化：命中计数 +1、检索权重上调"
                 "（POST /memories/{id}/hit）；对检索命中的记忆及时调用",
                 dict(id_param), ["id"]),
        tool_mem("memory.archive", RISK_W1,
                 "归档记忆（POST /memories/{id}/archive）：默认检索不可见，"
                 "不删除",
                 dict(id_param), ["id"]),
        tool_mem("memory.restore", RISK_W1,
                 "恢复归档记忆（POST /memories/{id}/restore）",
                 dict(id_param), ["id"]),
        tool_mem("memory.facts_multi_hop", RISK_R,
                 "知识图谱多跳查询（POST /facts/multi_hop）：按文本找实体"
                 "并沿关系跳转；factgraph 模块未启用时返回 enabled=false",
                 {"text": {"type": "string", "description": "实体查询文本"},
                  "top_k": {"type": "integer", "description": "上限（默认 10）",
                            "minimum": 1, "maximum": 50}},
                 ["text"]),
        tool_mem("memory.regions_search", RISK_R,
                 "空间区域检索（POST /regions/search）：返回最相关 Region",
                 {"text": {"type": "string", "description": "查询文本"},
                  "top_k": {"type": "integer", "description": "区域上限（默认 5）",
                            "minimum": 1, "maximum": 20}},
                 ["text"]),
        tool_mem("memory.consolidate", RISK_W2,
                 "触发记忆巩固（POST /consolidate）：聚类生成摘要记忆，"
                 "会新增派生记忆（created 数组）"),
        tool_mem("memory.compress", RISK_W2,
                 "触发记忆压缩（POST /compress）：生成压缩摘要，会新增"
                 "派生记忆"),
        tool_mem("memory.export", RISK_R,
                 "全量导出记忆库 JSON（GET /export）落盘到 /tmp 文件，"
                 "返回文件路径与预览",
                 {"path": {"type": "string",
                           "description": "导出文件路径（默认 "
                                          "/tmp/sme-export.json）"}}),
        tool_mem("memory.metrics", RISK_R,
                 "观测指标摘要（GET /metrics，Module 10；telemetry 未启用"
                 "时返回 enabled=false）"),
    ]


def build_tools(procfs_table, sysfs_table):
    tools = []
    tools.extend(tool_procfs(p, d) for p, _perm, d in procfs_table)

    # /sys/kernel/ai/stats 7 节点（只读统计）
    tools.extend(tool_readfile(f"procfs.read.stats.{attr}",
                               f"/sys/kernel/ai/stats/{attr}", d)
                 for attr, d in SYSFS_STATS)

    # ai_cgroup 4 节点（只读；RW 语义经 sysfs 侧工具另行接线）
    tools.extend(tool_readfile(f"procfs.read.cgroup.{attr}",
                               f"/sys/fs/cgroup/ai.{attr}", d)
                 for attr, d in CGROUP_FILES)

    tools.extend(tool_sysfs(rel, d, ds, sch)
                 for rel, d, ds, sch in sysfs_table)

    # /proc/ai/telemetry 写 2 个
    tools.extend(tool_writefile(name, "/proc/ai/telemetry", venum, risk, d,
                                obj_schema({"value": {
                                    "type": "string",
                                    "description": f"固定取值: {'/'.join(venum)}",
                                    "enum": venum}},
                                           ["value"]))
                 for name, venum, risk, d in TELEMETRY_WRITES)

    tools.extend(tool_netlink(*p) for p in NETLINK_PARAMS)
    tools.append(tool_netlink_sense())
    # W11 网络细控：内核连接跟踪表查询（NF_CONNTRACK_PROCFS=y 时内核原生
    # 导出 /proc/net/nf_conntrack；procfs-read 通道零依赖直读内核态数据，
    # 比引入用户态 conntrack 工具包更诚实）
    tools.append(tool_readfile(
        "procfs.read.net_nf_conntrack", "/proc/net/nf_conntrack",
        "内核连接跟踪表（nf_conntrack：每条连接的源/目的地址与端口、协议、"
        "状态与超时；查「当前有哪些网络连接/谁连着我/连接数多少」用它；"
        "补充手段：exec ss 查套接字级连接"))
    tools.append(tool_exec_run())
    tools.extend(memory_tools())
    tools.append(tool_shell_drop())
    return tools


# ---------------------------------------------------------------------------
# a. QEMU dump 解析（registry-dump.txt）
# ---------------------------------------------------------------------------

DUMP_SECTIONS = ("### cat /proc/ai/control", "### ls /sys/kernel/ai",
                 "### ls /proc/ai", "### find /proc/ai")


def parse_dump(text):
    """解析 init 脚本导出的 dump（分段标记：### <命令> ###）
    返回 (proc 文件列表, sysfs 顶层条目列表)"""
    proc_files, sysfs_entries = [], []
    section = None
    for line in text.splitlines():
        line = line.rstrip("\n")
        m = re.match(r"^###\s+(.+?)\s+###\s*$", line)
        if m:
            cmd = m.group(1)
            section = ("proc" if "/proc/ai" in cmd else
                       "sysfs" if "/sys/kernel/ai" in cmd else None)
            continue
        if section == "proc":
            if line.startswith("/proc/ai/") and " -> " not in line:
                proc_files.append(line.strip())
        elif section == "sysfs":
            if line.strip():
                sysfs_entries.append(line.strip())
    return proc_files, sysfs_entries


def merge_dump(tools, proc_files):
    """dump 中发现而默认表未覆盖的 /proc/ai 文件 → 追加通用读取工具"""
    known = {t["path"] for t in tools if t["channel"] == CH_PROC}
    added = []
    for f in proc_files:
        if f in known:
            continue
        rel = f[len("/proc/ai/"):]
        tools.append({
            "name": "procfs.read." + rel.replace("/", "_"),
            "channel": CH_PROC,
            "risk": RISK_R,
            "description": f"读取 {f}（QEMU 实测采集到的节点；默认表未"
                           f"收录，语义请结合节点名判断）",
            "path": f,
            "parameters": obj_schema(),
        })
        added.append(f)
    return added


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="AIKernel 工具注册表生成器")
    ap.add_argument("--dump", help="QEMU 实测 dump 文件（registry-dump.txt）")
    ap.add_argument("--out-dir", default=".",
                    help="输出目录（默认当前目录）")
    args = ap.parse_args()

    procfs_table = list(DEFAULT_PROCFS)
    tools = build_tools(procfs_table, DEFAULT_SYSFS)
    dump_added = []
    if args.dump:
        with open(args.dump, "r", encoding="utf-8", errors="replace") as fh:
            proc_files, _sys = parse_dump(fh.read())
        dump_added = merge_dump(tools, proc_files)

    # ---- tools.json（C 侧注册表） ----
    now = datetime.datetime.now().isoformat(timespec="seconds")
    counts = {}
    risk_counts = {}
    for t in tools:
        counts[t["channel"]] = counts.get(t["channel"], 0) + 1
        # exec.run 无工具级 risk（按命令分级，单列统计）
        rk = t.get("risk") or "exec按命令"
        risk_counts[rk] = risk_counts.get(rk, 0) + 1

    exec_tiers = {"R": 0, "W1": 0, "W2": 0}
    for c in EXEC_COMMANDS:
        exec_tiers[c["risk"]] = exec_tiers.get(c["risk"], 0) + 1

    registry = {
        "version": 2,
        "generator": "agent/ai/tools/gen_registry.py",
        "generated_at": now,
        "source": "QEMU dump + AIKernel 内核源码静态梳理" if args.dump
                  else "AIKernel 内核源码静态梳理",
        "tool_count": len(tools),
        "channel_counts": counts,
        "risk_counts": risk_counts,
        "exec_command_tiers": exec_tiers,
        "tools": tools,
    }
    out_json = os.path.join(args.out_dir, "tools.json")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(registry, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    # ---- tools.openai.json（纯 OpenAI function-calling 格式） ----
    openai_tools = [
        {"type": "function",
         "function": {"name": t["name"], "description": t["description"],
                      "parameters": t["parameters"]}}
        for t in tools
    ]
    out_openai = os.path.join(args.out_dir, "tools.openai.json")
    with open(out_openai, "w", encoding="utf-8") as fh:
        json.dump(openai_tools, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    # ---- 报告 ----
    lines = [
        "AIKernel Agent 工具注册表生成报告（v2）",
        f"生成时间: {now}",
        f"来源: {registry['source']}",
        (f"QEMU dump 追加节点: {len(dump_added)} 个" if args.dump
         else "QEMU dump: 未提供（使用内核源码默认表）"),
        "",
        f"工具总数: {len(tools)}",
        "分通道计数:",
    ]
    for ch in (CH_PROC, CH_SYSFS, CH_NETLINK, CH_NLSENSE, CH_EXEC,
               CH_MEMORY, CH_SHELL):
        lines.append(f"  {ch:<14} {counts.get(ch, 0)}")
    lines.append("分风险级计数:")
    for rk in (RISK_R, RISK_W1, RISK_W2):
        lines.append(f"  {rk:<14} {risk_counts.get(rk, 0)}")
    if risk_counts.get("exec按命令"):
        lines.append(f"  {'exec按命令':<10} {risk_counts['exec按命令']}"
                     "（exec.run，逐命令见 exec.commands）")
    lines.append(f"exec 白名单命令数: {len(EXEC_COMMANDS)} "
                 f"(R={exec_tiers['R']} W1={exec_tiers['W1']} "
                 f"W2={exec_tiers['W2']})；单源: tools.json exec.commands")
    if dump_added:
        lines.append("")
        lines.append("dump 追加的 /proc/ai 节点:")
        lines.extend(f"  {f}" for f in dump_added)
    report = "\n".join(lines) + "\n"

    out_report = os.path.join(args.out_dir, "tools_report.txt")
    with open(out_report, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(report, file=sys.stderr)
    print(f"OK: {out_json}", file=sys.stderr)
    print(f"OK: {out_openai}", file=sys.stderr)


if __name__ == "__main__":
    main()
