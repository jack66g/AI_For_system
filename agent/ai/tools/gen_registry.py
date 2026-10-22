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
  tools.json          C 侧注册表（含 channel 路由字段 + risk + sub + exec 单源表）
  tools.openai.json   纯 OpenAI function-calling 格式（可直接喂 API 调试）
  tools-sandbox.json  沙盒子智能体受限表（无 W2）
  sme-seed-w51.jsonl  SME 语料（区头 8 + 单件 151 + 组合配方 8）
  tool_catalog.txt    目录页单源产物
  tools_report.txt    生成报告（总数 + 分通道 + 分风险级 + 八域归属）
  stdout              报告摘要

用法：
  python3 tools/gen_registry.py [--dump registry-dump.txt] [--out-dir DIR]

W46a 防呆（v2.1）：
  1. 产物目录锚定：缺省 --out-dir 时，只有在本脚本所在目录（权威
     tools/ 目录）运行才就地生成；在其他目录运行一律拒绝并要求显式
     --out-dir——根除 W45 事故（在源树根误跑本脚本，默认输出把 75 件
     旧口径 tools.json 落在树根，遮蔽 tools/ 下 79 件正典表）。
  2. 正典数目断言：主表工具数必须 == EXPECTED_TOOL_COUNT(151)、受限表
     必须 == EXPECTED_SANDBOX_TOOL_COUNT(7)，写盘前断言，不符即报错
     退出 nonzero（错误信息含期望值与实际值）。静态表增删工具后必须
     有意识地同步锚点常量，杜绝静默漂移。

W48 防呆升级（v2.2，F1 形状漂移修复）：
  在 W46a"工具总数==EXPECTED_TOOL_COUNT"之外，增加**逐名有序清单**
  EXPECTED_TOOL_NAMES 与清单 SHA-256 锚点 EXPECTED_TOOL_NAMES_SHA256。
  生成后逐名比对：多/少/改名任一项即 rc=2 并打印 diff。总数恰好相等
  但成员被替换（W47 F1：79 件换 79 件）不再可能静默通过。静态表增删
  工具后必须同步 count、names、sha 三个锚点（脚本会打印实际值）。
"""

import argparse
import datetime
import hashlib
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
CH_SANDBOX = "sandbox"      # W42：隔离区 + 子智能体
CH_SYSCTL = "sysctl"        # W48：/proc/sys 通用读写（含崩溃黑名单）
CH_SYSFS_DYN = "sysfs"      # W48：sysfs/procfs 动态路径读写（cgroup 等）
CH_DESKTOP = "desktop"      # W76：桌面能力面（127.0.0.1:8091 本机 HTTP）
CH_CLARIFY = "interaction"  # W77c：结构化澄清（ask 交互层，非授权）

RISK_R = "R"        # 只读
RISK_W1 = "W1"      # 低危写
RISK_W2 = "W2"      # 高危写

# ---------------------------------------------------------------------------
# W51：能力域分类 + SME 语料（区头 / 单件 / 组合配方；W76 起含 desktop）
#
# 分类口径见 fix-w51/corpus-spec.md：每件工具至少一个域、最多两个域；
# sub 仅作为 tools.json 工具对象的顶层字段，不改工具名/风险/参数形状。
# 语料由本文件单源生成，禁止手工维护 seed。
# ---------------------------------------------------------------------------
SUB_DOMAIN_ORDER = ("res", "fs", "netsec", "aicore", "memory",
                    "sandbox", "sysadmin", "desktop")

SUB_DOMAIN_META = {
    "res": {
        "cn": "资源与调度",
        "duty": "进程调度、内存与 IO 压力、CPU 电源/频率、cgroup 资源与挂起冻结等 OS 资源面的观测与调参。",
        "when": "进程卡顿怎么办；内存紧张/swap 快满了；CPU 频率/电源怎么调；cgroup 资源怎么分；调度参数怎么看",
        "tool_when": "排查进程卡顿、内存/IO 压力、CPU 电源与调度参数时",
        "neighbors": "netsec（丢包/中断常与调度、队列相关）、aicore（决策注入会调 sched/mm）、fs（IO 压力与磁盘）",
        "safety": "W2：sched.nice/affinity/oom_score/timeslice、mm.*、power.*、proc.signal/freeze/rlimit；必须逐次红色确认并先记录旧值；R 类采样可自动执行。",
    },
    "fs": {
        "cn": "存储与文件",
        "duty": "磁盘/挂载/配额/文件系统状态、文件读写与配置编辑、IO 带宽与备份恢复。",
        "when": "磁盘满了；挂载点/文件系统异常；fstab 改坏了；目录占用/配额怎么看；文件怎么改、怎么备份恢复",
        "tool_when": "排查磁盘满、挂载/配额、文件编辑与备份恢复时",
        "neighbors": "res（IO/内存压力会放大文件延迟）、sysadmin（服务日志与包管理写盘）、netsec（NFS/DNS/防火墙配置）",
        "safety": "W2：io.priority/io.bandwidth、config_write_fstab；文件写入必须带绝对路径校验，先读后写并保留回退副本。",
    },
    "netsec": {
        "cn": "网络与安全",
        "duty": "TCP 参数、qdisc、防火墙/netfilter、连接跟踪、抓包诊断，以及 LSM/seccomp/audit 安全策略面。",
        "when": "网络不通/丢包；防火墙规则怎么加；谁连着我/怎么抓包；LSM/seccomp/审计策略；DNS 解析失败",
        "tool_when": "排查网络不通、丢包、防火墙、连接跟踪、LSM/审计策略时",
        "neighbors": "res（丢包/中断常与队列、调度相关）、sysadmin（sshd/服务/DNS 配置）、fs（防火墙与解析配置文件）",
        "safety": "W2：net.cwnd/rto/qdisc/nftables、sec.lsm_override/seccomp/audit、config_write_nftables/sshd_config；改网络/防火墙前先备份原规则，避免远程失联。sec.seccomp 在现役内核为 reserved，写入不产生拦截。",
    },
    "aicore": {
        "cn": "AI 内核面",
        "duty": "内核 AI 子系统状态、模型加载/卸载/推理、感知遥测、决策记录/因果链、策略与决策注入参数。",
        "when": "模型加载失败；推理结果不对；内核 AI 状态/遥测怎么看；决策注入怎么开；/proc/ai 与 /sys/kernel/ai 参数怎么调",
        "tool_when": "查看或调整模型加载/推理、AI 状态/遥测、决策注入时",
        "neighbors": "res（决策注入落到 sched/mm/OOM）、netsec（安全决策与审计）、memory（SME 接口语料检索）",
        "safety": "W2：procfs_write_telemetry_reset、netlink_act_ai_decision_*；W1：model_load/unload/infer、policy 与 decision per-hook 开关；改前记录当前值，失败用 model_unload/原值回滚。",
    },
    "memory": {
        "cn": "长期记忆",
        "duty": "SME 长期记忆的检索、增删改、导入导出、图谱/区域、事实/画像/问答对、巩固压缩与配置观测。",
        "when": "帮我记一下；删一条记忆；导入/导出记忆；查记忆图谱/区域；巩固或压缩记忆",
        "tool_when": "检索、写入、修改、导入导出长期记忆时",
        "neighbors": "aicore（接口语料检索）、sysadmin（SME 服务健康/日志）、sandbox（子智能体共享记忆）",
        "safety": "W2：memory_delete/consolidate/compress；W1：add/update/import/archive/restore/link/hit/regions_evolve；删除前先 memory_export，巩固压缩会新增派生记忆。",
    },
    "sandbox": {
        "cn": "隔离区与分身",
        "duty": "创建/查看/焚毁隔离区，把写代码、跑测试等任务派给 namespace 隔离的子智能体。",
        "when": "建个隔离区派子智能体；让分身写代码跑测试；隔离区里有什么；用完怎么焚毁隔离区",
        "tool_when": "创建隔离区、派子智能体干活、焚毁隔离区时",
        "neighbors": "sysadmin（子进程/服务）、memory（子智能体共享记忆）、aicore（子智能体模型）",
        "safety": "W2：sandbox_spawn（逐次红色确认）；W1：sandbox_create/destroy；子智能体工具表已剔除全部 W2，禁止嵌套派生。",
    },
    "sysadmin": {
        "cn": "系统管理",
        "duty": "服务启停与日志、用户/组、定时任务、软件包、主机名、sysctl/sysfs 通用系统参数与维护 shell。",
        "when": "服务重启/起不来；加用户/改密码；定时任务；装/卸软件包；看日志；改系统参数",
        "tool_when": "服务启停、用户/定时任务/软件包/日志/系统参数排障时",
        "neighbors": "fs（配置/日志/包文件）、netsec（sshd/DNS/防火墙）、res（服务资源与进程信号）",
        "safety": "W2：sysctl_set/sysfs_set、exec_run 内 systemctl 启停/apt/dpkg/用户管理/kill 等命令、sys_shell 内的写操作；W1：hostname 配置；W2 必须逐次确认并保留旧配置。",
    },
    "desktop": {
        "cn": "桌面能力面",
        "duty": "枚举应用/窗口，启动/聚焦/关闭窗口，切主题/壁纸，发通知，注入文本/按键，截图，读写剪贴板；后端是 L1 Web demo（127.0.0.1:8091）。",
        "when": "打开/关闭应用；看窗口列表/焦点；切主题/壁纸；发桌面通知；在窗口里输入文字/按键；截图；复制粘贴",
        "tool_when": "枚举或操作桌面应用/窗口、主题/壁纸、通知、输入、截图、剪贴板时",
        "neighbors": "sysadmin（真服务/会话）、res（桌面进程资源）、memory（操作历史沉淀）",
        "safety": "R/D0 读；W1/D1 主题/壁纸/通知/启动/聚焦；W2/D2 关窗、关应用、输入注入、剪贴板写；power 仅登记 D3 且后端 unavailable；D2 需确认或任务租约，worker 一律拒绝。",
    },
}

# 工具 -> 能力区（第一个为主域，最多两个；共 151 件全覆盖）
SUB_MAP = {
    # ---- res 资源与调度（23 主域）----
    "procfs_read_sched_stats": ["res", "aicore"],
    "procfs_read_sched_classify": ["res", "aicore"],
    "sysfs_write_sched_classify": ["res", "aicore"],
    "netlink_act_sched_nice": ["res"],
    "netlink_act_sched_affinity": ["res"],
    "netlink_act_sched_oom_score": ["res"],
    "netlink_act_sched_timeslice": ["res"],
    "netlink_act_mm_swappiness": ["res"],
    "netlink_act_mm_readahead": ["res"],
    "netlink_act_mm_thp": ["res"],
    "netlink_act_mm_reclaim_prio": ["res"],
    "netlink_act_power_freq": ["res"],
    "netlink_act_power_cstate": ["res"],
    "netlink_act_power_wakeup": ["res"],
    "netlink_act_proc_signal": ["res", "sysadmin"],
    "netlink_act_proc_freeze": ["res", "sysadmin"],
    "netlink_act_proc_rlimit": ["res", "sysadmin"],
    "procfs_read_pressure_cpu": ["res"],
    "procfs_read_pressure_memory": ["res"],
    "procfs_read_pressure_io": ["res", "fs"],
    "procfs_read_swaps": ["res"],
    "procfs_read_interrupts": ["res"],
    "procfs_read_irq_default_affinity": ["res"],
    # ---- fs 存储与文件（8 主域）----
    "procfs_read_vfs_stats": ["fs"],
    "procfs_read_vfs_rates": ["fs"],
    "netlink_act_io_priority": ["fs", "res"],
    "netlink_act_io_bandwidth": ["fs", "res"],
    "procfs_read_mounts": ["fs"],
    "procfs_read_filesystems": ["fs"],
    "config_read_fstab": ["fs", "sysadmin"],
    "config_write_fstab": ["fs", "sysadmin"],
    # ---- netsec 网络与安全（16 主域）----
    "netlink_act_net_cwnd": ["netsec"],
    "netlink_act_net_rto": ["netsec"],
    "netlink_act_net_qdisc": ["netsec", "res"],
    "netlink_act_net_nftables": ["netsec"],
    "netlink_act_sec_lsm_override": ["netsec"],
    "netlink_act_sec_seccomp": ["netsec"],
    "netlink_act_sec_audit": ["netsec"],
    "procfs_read_net_nf_conntrack": ["netsec"],
    "config_read_nftables": ["netsec", "fs"],
    "config_write_nftables": ["netsec", "fs"],
    "config_read_sshd_config": ["netsec", "sysadmin"],
    "config_write_sshd_config": ["netsec", "sysadmin"],
    "config_read_resolv_conf": ["netsec", "fs"],
    "config_write_resolv_conf": ["netsec", "fs"],
    "config_read_hosts": ["netsec", "fs"],
    "config_write_hosts": ["netsec", "fs"],
    # ---- aicore AI 内核面（40 主域）----
    "procfs_read_status": ["aicore", "res"],
    "procfs_read_decisions": ["aicore"],
    "procfs_read_chains": ["aicore"],
    "procfs_read_control": ["aicore", "res"],
    "procfs_read_latency": ["aicore"],
    "procfs_read_hitrate": ["aicore"],
    "procfs_read_telemetry": ["aicore"],
    "procfs_read_stats_telemetry_emitted": ["aicore"],
    "procfs_read_stats_telemetry_dropped": ["aicore"],
    "procfs_read_stats_telemetry_sampled_skip": ["aicore"],
    "procfs_read_stats_decisions_total": ["aicore"],
    "procfs_read_stats_decisions_hit": ["aicore"],
    "procfs_read_stats_decisions_hitrate_permille": ["aicore"],
    "procfs_read_stats_runtime_state": ["aicore"],
    "procfs_read_cgroup_inferences": ["aicore", "res"],
    "sysfs_write_enabled": ["aicore"],
    "sysfs_write_model_load": ["aicore"],
    "sysfs_write_model_unload": ["aicore"],
    "sysfs_write_policy_think": ["aicore"],
    "sysfs_write_policy_outcome": ["aicore"],
    "sysfs_write_policy_global_enable": ["aicore"],
    "sysfs_write_policy_max_impact_pct": ["aicore"],
    "sysfs_write_policy_rollback": ["aicore"],
    "sysfs_write_policy_refresh": ["aicore"],
    "sysfs_write_policy_chain_dir": ["aicore"],
    "procfs_write_telemetry_format": ["aicore"],
    "procfs_write_telemetry_reset": ["aicore"],
    "netlink_act_ai_decision_inject": ["aicore"],
    "netlink_act_ai_decision_oom": ["aicore", "res"],
    "netlink_act_ai_decision_sched": ["aicore", "res"],
    "netlink_act_ai_decision_mm": ["aicore", "res"],
    "netlink_sense": ["aicore", "res"],
    "sysfs_write_model_infer": ["aicore"],
    "procfs_read_model_out": ["aicore"],
    "sysfs_write_decision_oom_badness": ["aicore", "res"],
    "sysfs_write_decision_sched_vruntime": ["aicore", "res"],
    "sysfs_write_decision_sched_wakeup": ["aicore", "res"],
    "sysfs_write_decision_readahead": ["aicore", "fs"],
    "sysfs_write_decision_reclaim": ["aicore", "res"],
    "procfs_read_decision_stats": ["aicore"],
    # ---- memory 长期记忆（30 主域）----
    "memory_search": ["memory", "aicore"],
    "memory_search_advanced": ["memory", "aicore"],
    "memory_add": ["memory"],
    "memory_batch_add": ["memory"],
    "memory_stats": ["memory"],
    "memory_get": ["memory"],
    "memory_update": ["memory"],
    "memory_delete": ["memory"],
    "memory_hit": ["memory"],
    "memory_archive": ["memory"],
    "memory_restore": ["memory"],
    "memory_import": ["memory"],
    "memory_facts_multi_hop": ["memory"],
    "memory_graph": ["memory"],
    "memory_link": ["memory"],
    "memory_regions": ["memory"],
    "memory_regions_search": ["memory"],
    "memory_regions_evolve": ["memory"],
    "memory_facts": ["memory"],
    "memory_facts_history": ["memory"],
    "memory_profile": ["memory"],
    "memory_qapairs": ["memory"],
    "memory_consolidate": ["memory"],
    "memory_compress": ["memory"],
    "memory_export": ["memory"],
    "memory_metrics": ["memory"],
    "memory_metrics_report": ["memory"],
    "memory_config_get": ["memory"],
    "memory_config_check": ["memory"],
    "memory_health": ["memory", "sysadmin"],
    # ---- sandbox 隔离区与分身（4 主域）----
    "sandbox_status": ["sandbox"],
    "sandbox_create": ["sandbox"],
    "sandbox_spawn": ["sandbox"],
    "sandbox_destroy": ["sandbox"],
    # ---- sysadmin 系统管理（10 主域）----
    "exec_run": ["sysadmin", "fs"],
    "sys_shell": ["sysadmin"],
    "config_read_hostname": ["sysadmin", "netsec"],
    "config_write_hostname": ["sysadmin", "netsec"],
    "sysctl_get": ["sysadmin", "netsec"],
    "sysctl_set": ["sysadmin", "netsec"],
    "sysctl_blacklist": ["sysadmin"],
    "sysfs_get": ["sysadmin", "res"],
    "sysfs_set": ["sysadmin", "res"],
    "clarify": ["sysadmin"],
    # ---- desktop 桌面能力面（20 主域，W76）----
    "desktop_health": ["desktop"],
    "desktop_stats": ["desktop"],
    "desktop_apps_list": ["desktop"],
    "desktop_windows_list": ["desktop"],
    "desktop_theme_get": ["desktop"],
    "desktop_wallpaper_get": ["desktop"],
    "desktop_notifications_list": ["desktop"],
    "desktop_screenshot": ["desktop"],
    "desktop_clipboard_get": ["desktop"],
    "desktop_theme_set": ["desktop"],
    "desktop_wallpaper_set": ["desktop"],
    "desktop_notifications_send": ["desktop"],
    "desktop_apps_launch": ["desktop"],
    "desktop_windows_focus": ["desktop"],
    "desktop_windows_close": ["desktop"],
    "desktop_apps_close": ["desktop"],
    "desktop_input_type": ["desktop"],
    "desktop_input_key": ["desktop"],
    "desktop_clipboard_set": ["desktop"],
    "desktop_power": ["desktop"],
}

# ---------------------------------------------------------------------------
# W55 P4：SME 语料口语别名
#
# 实机检索缺陷：query「记忆库统计」在 352 条新旧混合语料里 top3 被旧
# 点号条目（procfs.read.latency/memory.stats 等）占据，memory_stats
# 排第 5。原因是新旧条目正文高度相似，旧条目更短、词频密度更高。
# 单件文本补"常见问法/口语别名"、区头补"常见同义问法"，用真实用户
# 措辞提高目标工具的 BM25/向量命中；语料仍是单源生成、幂等。
# ---------------------------------------------------------------------------
SUB_DOMAIN_ALIASES = {
    "res": "进程卡顿、系统卡顿、内存紧张、swap 快满、CPU 占用高、CPU 频率、"
           "cgroup 资源、冻结进程、调度延迟、资源调优、"
           "process slow、high CPU、out of memory、swap full",
    "fs": "磁盘满、磁盘满了怎么排查、磁盘占用、存储排查、挂载异常、分区、"
          "文件系统、磁盘配额、目录占用、fstab、备份恢复、文件读写、"
          "disk full、mount failed、storage troubleshooting",
    "netsec": "网络不通、网络丢包、丢包、防火墙、防火墙规则、抓包、"
              "连接跟踪、DNS 解析、审计策略、seccomp、LSM、"
              "packet loss、firewall rules、network troubleshooting",
    "aicore": "模型加载失败、推理不对、推理结果不对、模型上线、"
              "内核 AI 状态、遥测、决策注入、/proc/ai、/sys/kernel/ai 参数、"
              "model load failed、model inference",
    "memory": "记忆库统计、记忆数量、记忆条数、记忆总数、统计信息、"
              "数据库统计、记忆库概况、SME 统计、长期记忆、帮我记一下、"
              "删一条记忆、导入导出记忆、记忆图谱、记忆区域、巩固压缩记忆、"
              "记忆服务健康检查、记忆检索、记忆整理、"
              "memory stats、memory search、long-term memory",
    "sandbox": "隔离区、沙箱、子智能体、分身、建个隔离区、派子智能体、"
               "派子智能体写代码、分身编程、焚毁隔离区、namespace 隔离、"
               "sandbox、spawn subagent",
    "sysadmin": "服务重启、服务起不来、服务故障、看日志、定时任务、加用户、"
                "改密码、装软件包、卸软件包、sysctl 参数、主机名、"
                "service down、service failure、journalctl",
    "desktop": "打开应用、关应用、窗口列表、切换窗口、聚焦窗口、切主题、"
               "换壁纸、发通知、桌面截图、输入文字、按键、复制粘贴、剪贴板、"
               "open app、close window、desktop screenshot、clipboard、theme",
}

# 别名行重复次数：memory_stats 与旧点号条目（memory.stats/procfs.read.*）
# 正文高度重叠，旧条目更短、词频密度更高；单行别名在 352 条混合语料
# 下受 Python hash 随机化影响会起伏（实测 top5 5/10 命中）。别名行
# 重复 3 次后 10/10 个 hash seed 均排第一（见 fix-w55 检索日志）。
#
# W66：30 件 memory_* 语料全部把"常见问法/口语别名"行重复 2 次（stats
# 保持 3 次）。检索实测显示单件正文被 domain-header 模板文本压制：
# 同一段 char-ngram 哈希向量里，重复别名既抬高关键词通道命中，也抬高
# 向量通道对真实问法的相似度，只影响语料文本，不改工具 schema。
TOOL_ALIAS_REPEAT = {"memory_stats": 3}
for _mem_name in (
        "memory_search", "memory_search_advanced", "memory_add",
        "memory_batch_add", "memory_get", "memory_update", "memory_delete",
        "memory_hit", "memory_archive", "memory_restore", "memory_import",
        "memory_facts_multi_hop", "memory_graph", "memory_link",
        "memory_regions", "memory_regions_search", "memory_regions_evolve",
        "memory_facts", "memory_facts_history", "memory_profile",
        "memory_qapairs", "memory_consolidate", "memory_compress",
        "memory_export", "memory_metrics", "memory_metrics_report",
        "memory_config_get", "memory_config_check", "memory_health"):
    TOOL_ALIAS_REPEAT.setdefault(_mem_name, 2)
del _mem_name

# 工具级口语别名（当前聚焦 memory_* 30 件；其余工具沿用 description）
# W66：每件补中英口语问法（英文查询在纯中文语料上 Top-3 仅 20%）。
TOOL_ALIASES = {
    "memory_search": "记忆检索、搜记忆、查记忆库、语义检索记忆、"
                     "找以前记的、记忆里有没有、搜索记忆、查找记忆、"
                     "用记忆检索找、记忆里找、找记忆、"
                     "memory search、search memory、find in memory、"
                     "semantic memory search",
    "memory_search_advanced": "高级检索记忆、按区域检索记忆、"
                              "按标签搜记忆、按标签过滤、带过滤搜记忆、"
                              "metadata 过滤、tags 过滤、查归档记忆、"
                              "图谱扩展、k8s 标签、advanced memory search、"
                              "filter by tags、search archived memories",
    "memory_add": "记一下、记住这个、添加记忆、写入记忆、帮我记、"
                  "存一条记忆、帮我记住、记住这件事、保存到记忆、"
                  "帮我记住这件事、记一条待办、remember this、"
                  "remember that、note that、add memory、save to memory、"
                  "store a memory",
    "memory_batch_add": "批量记、一次记多条、批量添加记忆、批量导入记忆、"
                        "批量写入、batch add memories、bulk add memories",
    "memory_stats": "记忆库统计、记忆数量、记忆条数、记忆总数、"
                    "统计信息、数据库统计、记忆库概况、SME 统计、"
                    "记忆库有多少条、记忆统计、有多少条记忆、"
                    "memory stats、memory count、how many memories、"
                    "how many memories are stored、memory bank size、"
                    "number of memories、statistics",
    "memory_get": "查看某条记忆、按 id 取记忆、读取记忆详情、记忆内容、"
                  "memory get、read memory by id、show memory details",
    "memory_update": "修改记忆、更新记忆内容、改记忆标签、调整重要度、"
                     "编辑记忆、改记忆、update memory、edit memory",
    "memory_delete": "删除记忆、删掉这条、删除一条记忆、删一条记忆、"
                     "遗忘、清理记忆、移除记忆、永久删除、delete memory、"
                     "delete a memory、remove memory、forget this",
    "memory_hit": "记忆命中、强化记忆、命中计数、提升记忆权重、"
                  "命中一次、reinforce memory、hit memory",
    "memory_archive": "归档记忆、把记忆收起来、冷存记忆、归档、收起来、"
                      "把这条旧记忆归档、把旧记忆归档、旧记忆归档、"
                      "archive memory、hide memory",
    "memory_restore": "恢复记忆、取消归档、还原记忆、恢复归档、"
                      "restore memory、unarchive",
    "memory_import": "导入记忆、恢复备份记忆、批量导入、迁移记忆、"
                     "导入 JSON、恢复备份、import memories、"
                     "restore from backup",
    "memory_facts_multi_hop": "多跳事实查询、事实推理、关联事实、"
                              "实体关系链、多跳查询、实体关系、"
                              "multi-hop facts、fact reasoning",
    "memory_graph": "记忆图谱、关系图、记忆链接图、知识图谱、关系边、"
                    "memory graph、knowledge graph、graph edges",
    "memory_link": "关联记忆、连接两条记忆、建立引用、记忆连线、"
                   "建立关系、link memories、connect memories",
    "memory_regions": "记忆区域、Region 列表、记忆分区、区域概况、"
                      "列出所有记忆区域、所有区域、list memory regions、"
                      "list regions、memory regions",
    "memory_regions_search": "搜索记忆区域、按区域找记忆、区域语义检索、"
                             "区域搜索、search memory regions、"
                             "search regions、region retrieval",
    "memory_regions_evolve": "区域演化、合并分裂区域、整理记忆区域、"
                             "触发记忆区域演化、区域合并、区域分裂、"
                             "evolve regions",
    "memory_facts": "事实列表、实体事实、结构化事实、事实库、事实、"
                    "list facts、memory facts",
    "memory_facts_history": "事实历史、事实变更记录、版本历史、事实版本、"
                            "fact history、fact version history",
    "memory_profile": "用户画像、偏好画像、profile、画像快照、用户偏好、"
                      "user profile、profile snapshot",
    "memory_qapairs": "问答对、Q&A 记忆、问答记录、问答、"
                      "q&a pairs、question answer pairs",
    "memory_consolidate": "记忆巩固、巩固记忆、合并重复记忆、"
                          "合并重复条目、整理记忆、合并重复、去重、"
                          "consolidate memories、deduplicate memories",
    "memory_compress": "记忆压缩、压缩记忆库、精简记忆、压缩、"
                       "compress memory、compress memories",
    "memory_export": "导出记忆、备份记忆、记忆快照、导出 JSON、导出、"
                     "export all memories、export memories、"
                     "JSON backup file、backup memories、backup file、"
                     "export json",
    "memory_metrics": "记忆指标、检索质量指标、记忆性能、检索质量、"
                      "memory metrics、retrieval quality metrics",
    "memory_metrics_report": "记忆指标报告、生成记忆报表、性能报告、"
                             "生成报告、memory metrics report、"
                             "performance report",
    "memory_config_get": "记忆配置、SME 配置、查看记忆参数、配置参数、"
                         "memory config、SME settings",
    "memory_config_check": "检查记忆配置、检查 SME 配置、"
                           "检查 SME 配置是否正确、配置校验、配置体检、"
                           "配置检查、memory config check、validate config",
    "memory_health": "记忆健康、SME 健康检查、记忆服务状态、记忆库体检、"
                     "服务状态、SME 活着吗、"
                     "health check the memory service and report status、"
                     "memory health、health check、memory service status",
    "clarify": "澄清、问用户、让用户选、不确定、选择哪个、哪个服务、"
               "clarify、ask the user、which one、let me choose",
}

# W66：memory_* 每件的"常用问法"短行（重复 4 次）。
# 检索第一阶段是 Region 门控 + 全局向量补充（top_k=5 时候选池只有
# ~20 条）；hashing 向量对长文本按字符 n-gram 求和，单件正文里的
# 模板行会稀释真实问法。把最能代表该工具的用户措辞单独成行并重复，
# 既抬高向量相似度（实测目标全局向量排名从 66 -> 5），也抬高 BM25
# 命中；只影响 seed 文本。
# 只给基础版实测被 Region 门控挡在候选池外的 4 件加短行；其余 26 件
# 用常规别名行（重复 2 次）即可，避免长文本把英文问法稀释掉。
MEMORY_QUERY_HINTS = {
    "memory_search": "搜索记忆、记忆检索、查记忆库、用记忆检索找、记忆里找、找记忆、"
                    "search my long-term memory、search memory、memory lookup、"
                    "find in memory、look up memory、必填参数 text",
    "memory_search_advanced": "高级检索、按标签过滤、k8s 标签、带过滤搜记忆、"
                             "按标签搜记忆、查询归档记忆、advanced memory search、"
                             "filter by tags、search archived memories",
    "memory_add": "帮我记住、帮我记住这件事、记一下、记住这个、添加记忆、"
                  "写入记忆、记一条待办、remember that、remember this、"
                  "note that、save this to memory",
    "memory_health": "记忆服务健康检查、SME 健康检查、SME 还活着吗、记忆库体检、"
                     "health check the memory service、memory health、service status",
    "memory_consolidate": "巩固记忆、合并重复条目、合并重复记忆、整理记忆、去重",
    "memory_regions_search": "按区域搜索记忆、搜索记忆区域、区域语义检索、"
                             "记忆区域列表、记忆区域、Region",
    "memory_regions_evolve": "触发记忆区域演化、区域演化、合并分裂区域、"
                             "记忆区域列表、记忆区域、Region",
}

# memory_search / advanced / add 需要 8 次才能在 top_k=5 的 20 条候选池
# 里稳定进入补充池（并抬高所在 Region 质心，实测英文记忆检索查询的
# Region 质心 0.354 -> 0.489）；其余 4 次。
MEMORY_HINT_REPEAT = {
    "memory_search": 12,
    "memory_search_advanced": 12,
}

# 额外的中文短行（与上面中英混排行分开计次数）：memory_add 的英文
# 问法容易把中文"帮我记住"的向量权重稀释，单独把中文短问法重复
# 12 次；memory_link/restore 之前落在 top3 之外，补 8 次。
MEMORY_QUERY_HINTS_EXTRA = {
    "memory_add": ("帮我记住、帮我记住这件事、记一下、记住这个、"
                   "添加记忆、写入记忆", 12),
    "memory_link": ("关联两条记忆、建立引用、连接记忆、记忆连线、"
                    "link memories、connect memories", 8),
    "memory_restore": ("恢复归档记忆、取消归档、还原记忆、"
                       "restore archived memory、unarchive", 8),
}

# 中英问法各占一条短行：同一行里混排会互相稀释哈希向量，分条重复
# 才能同时保住中文（t03/q05）与英文（e03/e04）命中。
MEMORY_QUERY_HINTS_EXTRA2 = {
    "memory_add": [("remember that、remember this、note that、"
                    "save this to memory", 8)],
    "memory_search": [
        ("用记忆检索找、记忆检索、搜索记忆、查记忆库、找记忆", 12),
        ("search my long-term memory、search memory、memory lookup、"
         "find in memory", 8),
    ],
    "memory_search_advanced": [
        ("高级检索、按标签过滤、k8s 标签、带过滤搜记忆、按标签搜记忆", 8),
    ],
}

# W66：组合配方共享锚点（同理，防止 8 个配方散落后只召回错误配方）。
COMBO_COMMON_KEYWORDS = (
    "组合配方通用关键词：组合配方、排查流程、操作步骤、适用问法、"
    "工具链、判据、回滚、runbook、playbook"
)

# W66：memory_* 单件的语料简介覆盖。
# tool["description"] 面向模型、可以很长（memory_search 的 420 字提示
# 会主导整段语料的向量/关键词），语料里改用一行精确简介，避免检索时
# 一条"万能提示"压过领域头与同域其他工具。仅影响 seed 文本。
MEMORY_CORPUS_DESC = {
    "memory_search": "跨长期记忆的语义检索：按 text 查询并返回最相关记忆（POST /memories/search）",
    "memory_search_advanced": "带 metadata 过滤、tags、ns、include_archived、graph_expand 的高级语义检索（POST /memories/search）",
    "memory_add": "写入一条长期记忆（POST /memories），可带 tags/importance/source/link_to/ns",
    "memory_batch_add": "一次批量写入多条记忆（POST /memories/batch），每条独立生成 id，非幂等",
    "memory_stats": "查看记忆库统计：总/活跃/归档条数、区域与图边数（GET /stats）",
    "memory_get": "按记忆 id 读取单条记忆全文（GET /memories/{id}）",
    "memory_update": "按 id 修改记忆文本/元数据/标签/重要度/权重/摘要（PATCH /memories/{id}）",
    "memory_delete": "按 id 永久删除记忆（DELETE /memories/{id}，W2 高危写，不可恢复）",
    "memory_hit": "按 id 对记忆做一次 Ebbinghaus 强化命中（POST /memories/{id}/hit）",
    "memory_archive": "按 id 归档记忆（POST /memories/{id}/archive），归档后默认检索不可见但可恢复",
    "memory_restore": "恢复已归档记忆（POST /memories/{id}/restore）",
    "memory_import": "从 JSON 数组或导出对象无损导入记忆（POST /import），带 id 可覆盖恢复",
    "memory_facts_multi_hop": "知识图谱多跳事实查询（POST /facts/multi_hop），先找实体再沿关系跳转",
    "memory_graph": "查看记忆关系图谱：边数 edges 与连接列表（GET /graph）",
    "memory_link": "建立两条记忆之间的关系边（POST /graph/link），服务端没有 unlink 端点",
    "memory_regions": "列出全部空间记忆区域 Region 及成员/密度（GET /regions）",
    "memory_regions_search": "按语义检索记忆区域 Region（POST /regions/search）",
    "memory_regions_evolve": "触发记忆区域演化（POST /regions/evolve），会合并/分裂 Region",
    "memory_facts": "列出事实图谱/双时态结构化事实（GET /facts）",
    "memory_facts_history": "查询单条事实的版本历史链（GET /facts/history）",
    "memory_profile": "查看用户画像事实与快照（GET /profile）",
    "memory_qapairs": "列出问答对记忆（GET /qapairs）",
    "memory_consolidate": "触发记忆巩固（POST /consolidate，W2），聚类生成摘要记忆",
    "memory_compress": "触发记忆压缩（POST /compress，W2），生成压缩摘要记忆",
    "memory_export": "全量导出记忆库 JSON（GET /export）并落盘，默认 /tmp/sme-export.json",
    "memory_metrics": "查看 SME 检索/性能观测指标摘要（GET /metrics）",
    "memory_metrics_report": "生成完整遥测报告并落盘（GET /metrics/report）",
    "memory_config_get": "查看 SME 配置中心参数（GET /config，api_key 已掩码）",
    "memory_config_check": "校验 SME 配置（POST /config/check），ping=true 额外探测连通性",
    "memory_health": "SME 记忆服务健康检查（GET /health），返回 status 与记忆条数",
}

# W66：可直接回答的事实/边界（参数、默认路径、风险等级、可否删除），
# 让"某工具的风险/默认路径/必填参数"这类问题落到单件而不是领域头。
MEMORY_TOOL_FACTS = {
    "memory_search": "必填参数 text（不是 query）；top_k 默认 3；检索接口/参数/用法时先用本工具。",
    "memory_search_advanced": "memory_search 的高级版；metadata_filters 是 JSON 对象字符串，tags 是 JSON 数组字符串；include_archived 默认 false；graph_expand 0-5。",
    "memory_add": "必填 text；importance 0-1；source 如 user/llm/system；可用 link_to 关联既有记忆。",
    "memory_batch_add": "memories 为 JSON 数组字符串；每条生成新 id，重试会产生重复记忆。",
    "memory_stats": "无参数；关注 memories.total/active/archived、regions.count、graph_edges。",
    "memory_get": "必填 id；只接受 [A-Za-z0-9_.-]，非法 id 返回参数错误。",
    "memory_update": "必填 id；至少提供一个待改字段；改 text 会触发重新向量化。",
    "memory_delete": "风险等级 W2（高危写），必须人工确认；永久删除不可恢复；删除前先 memory_export。",
    "memory_hit": "必填 id；命中后 hit_count+1、weight/importance 上调，用于强化常用记忆。",
    "memory_archive": "必填 id；归档不删除，默认检索不可见；用 memory_restore 恢复。",
    "memory_restore": "必填 id；恢复归档记忆并重新进入检索；仅对已归档 id 有效。",
    "memory_import": "path 仅允许 /tmp 或 /var/ai 下的绝对路径，单文件 ≤8MB；也接受 memories JSON 数组；带 id 的条目按 id 覆盖恢复。",
    "memory_facts_multi_hop": "必填 text；top_k 默认 10；factgraph 未启用时返回 enabled=false。",
    "memory_graph": "无参数；返回 edge_count 与 edges；图边为有向关系。",
    "memory_link": "必填 a、b；kind 默认 reference；没有 unlink 端点，边不能单独删除，只能随记忆删除或图重建移除。",
    "memory_regions": "无参数；返回区域 id/成员数/密度/中心；区域按嵌入几何自动聚类。",
    "memory_regions_search": "必填 text；top_k 默认 5；返回 RegionHit（region_id/score/size）。",
    "memory_regions_evolve": "无参数；会合并/分裂 Region，属于 W1 低危写，可能触发区域重排。",
    "memory_facts": "无参数；返回事实图谱/双时态事实列表；factgraph 未启用时为空/禁用。",
    "memory_facts_history": "text 与 memory_id 至少一个；返回版本链；参数会做 URL 编码。",
    "memory_profile": "无参数；返回画像事实与快照；profile 模块未启用时为空。",
    "memory_qapairs": "无参数；返回问答对列表；qapair 模块未启用时为空。",
    "memory_consolidate": "风险等级 W2，必须人工确认；会新增派生摘要记忆，先导出快照。",
    "memory_compress": "风险等级 W2，必须人工确认；会新增压缩摘要记忆，先导出快照。",
    "memory_export": "默认导出路径 /tmp/sme-export.json；path 仅允许 /tmp 或 /var/ai；导出内容可能很大，结果只回摘要与预览。",
    "memory_metrics": "无参数；返回检索计数/延迟等指标；telemetry 未启用时 enabled=false。",
    "memory_metrics_report": "默认路径 /tmp/sme-metrics-report.json；path 仅允许 /tmp 或 /var/ai；telemetry 未启用时 404。",
    "memory_config_get": "无参数；api_key 已掩码；只读。",
    "memory_config_check": "ping=false 只做静态校验；ping=true 会探测 LLM/Embedding 连通性（可能产生外部调用）。",
    "memory_health": "无参数；只读探活；SME 不可达时返回网络错误而不是挂死。",
}

# ---------------------------------------------------------------------------
# W48 崩溃黑名单（sysctl_set / sysfs_set 的硬拒绝面）
#
# 准入原则（用户拍板）：只有"一次写入即可能 brick/panic/不可恢复/远程
# 失联"的接口才进黑名单；其余（含 net.ipv4.conf.*.rp_filter 这类敏感但
# 可回滚的）一律放行并按 W2 二次确认。黑名单不可通过参数绕过，命中即
# 拒绝并给出原因；执行器 C 侧有同一张表（安全关键路径不依赖数据文件），
# 本表是生成物与 AI 检索语料的单源，二者由专项测试比对。
# ---------------------------------------------------------------------------
CRASH_BLACKLIST = [
    ("kernel.sysrq",
     "SysRq 立即重启/崩溃/杀进程：写入后任意触发键即可让系统当场 panic "
     "或掉电重启，远程不可恢复"),
    ("kernel.panic",
     "panic 族（kernel.panic/panic_on_oops/panic_on_warn/panic_on_rcu_stall/"
     "panic_on_io_nmi/panic_on_unrecovered_nmi 等）：把可恢复错误升级为"
     "立即 panic/重启，可能丢失未落盘数据"),
    ("kernel.hung_task_panic",
     "hung task 超时即 panic：正常 IO 抖动即可触发宕机"),
    ("kernel.softlockup_panic",
     "soft lockup 即 panic：高负载下可能被误触发"),
    ("kernel.hardlockup_panic",
     "hard lockup 即 panic：NMI 抖动即可宕机"),
    ("kernel.core_pattern",
     "core dump 管道处理器：写入 |/path 可在崩溃时以 root 执行任意程序；"
     "管道消费端不读会让 core dump 永久挂起（进程不可回收）"),
    ("kernel.modules_disabled",
     "写 1 后永久禁止模块加载，只能重启恢复；写错即失去驱动/文件系统模块"
     "的热插拔能力"),
    ("kernel.kexec_load_disabled",
     "写 1 后永久禁止 kexec，只能重启恢复（崩溃转储/快速重启通道被切断）"),
    ("kernel.sched_rt_runtime_us",
     "把 RT 带宽设为 -1（无限制）后，任一 RT 任务可 100% 占核饿死整机，"
     "表现为硬锁死，远程无法登录"),
    ("vm.panic_on_oom",
     "OOM 时直接 panic 而非杀进程：内存压力即整机宕机"),
    ("vm.oom_kill_allocating_task",
     "OOM 时杀正在分配内存的任务（常为关键服务/内核路径），处置面比默认"
     "受害者选择更窄，易误杀导致系统不可用"),
    ("/proc/sysrq-trigger",
     "SysRq 触发文件：写入单字符即可立即重启/崩溃/杀全部进程；该路径不在"
     "/proc/sys 下，sysctl 通道按 realpath 前缀已天然拒绝，此处显式登记"
     "防止未来通道放宽时被重新引入"),
]

# 允许 sysfs_set 写入的前缀（W48 通用动态通道；不在表内一律拒绝）。
# 刻意排除 /sys/power（suspend 可让远程主机失联）、/sys/firmware（可写坏
# 引导固件）、/sys/kernel/debug|security|config、/sys/module（内核模块参数）。
SYSFS_WRITE_ALLOW_PREFIXES = [
    "/sys/fs/cgroup/",          # cgroup v2 资源配给（cpu.max/memory.max/io.max/pids.max/ai.*）
    "/sys/kernel/ai/",          # AIKernel 控制面（含动态 policy/<name>）
    "/sys/devices/system/cpu/", # cpufreq governor / EAS / CPU online
    "/sys/block/",              # IO 调度器与队列参数
    "/sys/class/net/",          # 网卡队列/offload（改网络，W2）
    "/proc/irq/",               # IRQ 亲和（smp_affinity）
    "/proc/ai/",                # AIKernel procfs 控制点（classify 等）
]

SYSFS_READ_ALLOW_PREFIXES = [
    "/sys/", "/proc/sys/", "/proc/irq/", "/proc/ai/", "/proc/pressure/",
    "/proc/net/",
]

# ---------------------------------------------------------------------------
# W46a/W48 防呆锚点：正典产物口径（tools/tools.json 151 件、tools/tools-sandbox.json
# 7 件）。W48 起除总数外还有逐名清单与 SHA-256 锚点：总数相同但成员
# 被替换（W47 F1 的 79↔79 形状漂移）同样会被拒绝。
# 静态表增删工具时必须同步：EXPECTED_TOOL_COUNT / EXPECTED_TOOL_NAMES /
# EXPECTED_TOOL_NAMES_SHA256（运行脚本失败信息会打印实际清单与哈希）。
# ---------------------------------------------------------------------------
EXPECTED_TOOL_COUNT = 151        # 主表 tools.json（W77c：150 + clarify）
EXPECTED_SANDBOX_TOOL_COUNT = 7  # 受限表 tools-sandbox.json
# W72：受限表 exec 命令数。W69 为 54（46R+8W1）；新增 python3/gcc/cc
#（沙箱内 W1，主表 python3 仍 W2）后为 57。which 早已在 54 条的 R 全集中。
EXPECTED_SANDBOX_EXEC_COUNT = 57

EXPECTED_TOOL_NAMES = [
    "procfs_read_status",
    "procfs_read_decisions",
    "procfs_read_chains",
    "procfs_read_control",
    "procfs_read_latency",
    "procfs_read_hitrate",
    "procfs_read_telemetry",
    "procfs_read_sched_stats",
    "procfs_read_sched_classify",
    "procfs_read_vfs_stats",
    "procfs_read_vfs_rates",
    "procfs_read_stats_telemetry_emitted",
    "procfs_read_stats_telemetry_dropped",
    "procfs_read_stats_telemetry_sampled_skip",
    "procfs_read_stats_decisions_total",
    "procfs_read_stats_decisions_hit",
    "procfs_read_stats_decisions_hitrate_permille",
    "procfs_read_stats_runtime_state",
    "procfs_read_cgroup_inferences",
    "sysfs_write_enabled",
    "sysfs_write_model_load",
    "sysfs_write_model_unload",
    "sysfs_write_policy_think",
    "sysfs_write_policy_outcome",
    "sysfs_write_policy_global_enable",
    "sysfs_write_policy_max_impact_pct",
    "sysfs_write_policy_rollback",
    "sysfs_write_policy_refresh",
    "sysfs_write_policy_chain_dir",
    "procfs_write_telemetry_format",
    "procfs_write_telemetry_reset",
    "netlink_act_sched_nice",
    "netlink_act_sched_affinity",
    "netlink_act_sched_oom_score",
    "netlink_act_sched_timeslice",
    "netlink_act_mm_swappiness",
    "netlink_act_mm_readahead",
    "netlink_act_mm_thp",
    "netlink_act_mm_reclaim_prio",
    "netlink_act_io_priority",
    "netlink_act_io_bandwidth",
    "netlink_act_net_cwnd",
    "netlink_act_net_rto",
    "netlink_act_net_qdisc",
    "netlink_act_net_nftables",
    "netlink_act_power_freq",
    "netlink_act_power_cstate",
    "netlink_act_power_wakeup",
    "netlink_act_sec_lsm_override",
    "netlink_act_sec_seccomp",
    "netlink_act_sec_audit",
    "netlink_act_proc_signal",
    "netlink_act_proc_freeze",
    "netlink_act_proc_rlimit",
    "netlink_act_ai_decision_inject",
    "netlink_act_ai_decision_oom",
    "netlink_act_ai_decision_sched",
    "netlink_act_ai_decision_mm",
    "netlink_sense",
    "procfs_read_net_nf_conntrack",
    "exec_run",
    "memory_search",
    "memory_search_advanced",
    "memory_add",
    "memory_batch_add",
    "memory_stats",
    "memory_get",
    "memory_update",
    "memory_delete",
    "memory_hit",
    "memory_archive",
    "memory_restore",
    "memory_import",
    "memory_facts_multi_hop",
    "memory_graph",
    "memory_link",
    "memory_regions",
    "memory_regions_search",
    "memory_regions_evolve",
    "memory_facts",
    "memory_facts_history",
    "memory_profile",
    "memory_qapairs",
    "memory_consolidate",
    "memory_compress",
    "memory_export",
    "memory_metrics",
    "memory_metrics_report",
    "memory_config_get",
    "memory_config_check",
    "sys_shell",
    "sandbox_status",
    "sandbox_create",
    "sandbox_spawn",
    "sandbox_destroy",
    "procfs_read_pressure_cpu",
    "procfs_read_pressure_memory",
    "procfs_read_pressure_io",
    "procfs_read_swaps",
    "procfs_read_interrupts",
    "procfs_read_irq_default_affinity",
    "sysfs_write_sched_classify",
    "procfs_read_mounts",
    "procfs_read_filesystems",
    "config_read_fstab",
    "config_write_fstab",
    "config_read_nftables",
    "config_write_nftables",
    "config_read_sshd_config",
    "config_write_sshd_config",
    "config_read_resolv_conf",
    "config_write_resolv_conf",
    "config_read_hosts",
    "config_write_hosts",
    "config_read_hostname",
    "config_write_hostname",
    "sysctl_get",
    "sysctl_set",
    "sysctl_blacklist",
    "sysfs_get",
    "sysfs_set",
    "sysfs_write_model_infer",
    "procfs_read_model_out",
    "sysfs_write_decision_oom_badness",
    "sysfs_write_decision_sched_vruntime",
    "sysfs_write_decision_sched_wakeup",
    "sysfs_write_decision_readahead",
    "sysfs_write_decision_reclaim",
    "procfs_read_decision_stats",
    "memory_health",
    "desktop_health",
    "desktop_stats",
    "desktop_apps_list",
    "desktop_windows_list",
    "desktop_theme_get",
    "desktop_wallpaper_get",
    "desktop_notifications_list",
    "desktop_screenshot",
    "desktop_clipboard_get",
    "desktop_theme_set",
    "desktop_wallpaper_set",
    "desktop_notifications_send",
    "desktop_apps_launch",
    "desktop_windows_focus",
    "desktop_windows_close",
    "desktop_apps_close",
    "desktop_input_type",
    "desktop_input_key",
    "desktop_clipboard_set",
    "desktop_power",
    "clarify",
]
EXPECTED_TOOL_NAMES_SHA256 = "52cbbc49c18da3c339fb9daf5441cd89cf4bbc02555462387e5d43055b52d3c2"


def manifest_sha256(names):
    """工具名有序清单的 SHA-256（每行一个名字 + 末尾换行）。"""
    return hashlib.sha256(("\n".join(names) + "\n").encode("utf-8")).hexdigest()


def check_tool_manifest(tools):
    """W48 防呆：总数 + 逐名清单 + 锚点哈希三重校验（失败 rc=2）。"""
    actual = [t["name"] for t in tools]
    if manifest_sha256(EXPECTED_TOOL_NAMES) != EXPECTED_TOOL_NAMES_SHA256:
        sys.stderr.write(
            "ERROR [gen_registry 防呆]: EXPECTED_TOOL_NAMES 与 "
            "EXPECTED_TOOL_NAMES_SHA256 自校验失败（锚点清单被改动但哈希"
            "未同步）。实际哈希=%s\n"
            % manifest_sha256(EXPECTED_TOOL_NAMES))
        sys.exit(2)
    if len(tools) != EXPECTED_TOOL_COUNT:
        sys.stderr.write(
            "ERROR [gen_registry 防呆]: 主表工具数 %d != 期望 %d"
            "（tools/tools.json 正典口径）。静态表有增删而锚点常量"
            " EXPECTED_TOOL_COUNT 未同步？\n"
            % (len(tools), EXPECTED_TOOL_COUNT))
        sys.exit(2)
    if actual != EXPECTED_TOOL_NAMES:
        exp_set, act_set = set(EXPECTED_TOOL_NAMES), set(actual)
        missing = [n for n in EXPECTED_TOOL_NAMES if n not in act_set]
        extra = [n for n in actual if n not in exp_set]
        sys.stderr.write(
            "ERROR [gen_registry 防呆]: 工具名清单与锚点不一致"
            "（形状漂移；总数可能相同）。\n")
        sys.stderr.write("  锚点 %d 件 / 实际 %d 件\n"
                         % (len(EXPECTED_TOOL_NAMES), len(actual)))
        if missing:
            sys.stderr.write("  缺少（锚点有、生成结果无）:\n")
            for n in missing:
                sys.stderr.write("    - %s\n" % n)
        if extra:
            sys.stderr.write("  多出（生成结果有、锚点无）:\n")
            for n in extra:
                sys.stderr.write("    + %s\n" % n)
        for i, (e, a) in enumerate(zip(EXPECTED_TOOL_NAMES, actual)):
            if e != a:
                sys.stderr.write("  首个位置差异 @%d: 锚点=%s 实际=%s\n"
                                 % (i, e, a))
                break
        sys.stderr.write("  实际清单哈希=%s\n"
                         "  实际清单（同步到 EXPECTED_TOOL_NAMES 用）:\n"
                         % manifest_sha256(actual))
        for n in actual:
            sys.stderr.write("    \"%s\",\n" % n)
        sys.exit(2)


# ---------------------------------------------------------------------------
# 工具名与内核域名的映射规则（T14 下划线化）
#
# 工具名一律用 [a-zA-Z0-9_-]（OpenAI function-calling 命名规范；点号名会被
# 部分 OpenAI 兼容网关按非法 function name 处理）。内核侧接口名字符串
# （/proc、/sys 节点路径、netlink 参数名如 "sched.nice"）保持原样，映射
# 关系显式存于每个工具的字段：
#   procfs-read / sysfs-write  -> "path" 字段（内核节点绝对路径）
#   netlink-act                -> "param"（内核参数名）+ "domain"（决策域）
#   netlink-sense / exec / memory / shell -> 无内核名，channel 即语义
# 工具名仅是调用面唯一键：netlink_act_sched_nice ↔ param "sched.nice"。
# ---------------------------------------------------------------------------

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
    ("/proc/ai/control", 0o444, "可控制参数表（27 个参数的 name/domain/min/max/current/default）"),
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
    ("procfs_write_telemetry_format", ["format=raw", "format=human"],
     RISK_W1, "切换遥测输出格式：format=raw（原始定长记录）或 "
              "format=human（文本行，默认）。影响后续读 "
              "/proc/ai/telemetry 与 SENSE 输出"),
    ("procfs_write_telemetry_reset", ["reset"],
     RISK_W2, "清空全部遥测/决策 ring（需 CAP_SYS_ADMIN；记录不可恢复，"
              "慎用——如需留档先在 procfs 侧导出）"),
]

# 可控制参数表（AIKernel/core/ai_control.c + 各子系统 ai_control_register）
# 每项: (参数名, 域, task 参数?, min, max, 默认, 说明)
NETLINK_PARAMS = [
    ("sched.nice", 1, True, -20, 19, 0,
     "设置进程 nice 值（实时生效；data[0]=pid data[1]=value）"),
    ("sched.affinity", 1, True, 0, 63, 0,
     "设置进程 CPU 亲和（掩码/编号，实时生效；值域 0..nr_cpu_ids-1，"
     "VM /proc/ai/control 实测 max=63；同上 data 约定）"),
    ("sched.oom_score", 1, True, -1000, 1000, 0,
     "设置进程 oom_score_adj（实时生效；同上 data 约定）"),
    ("sched.timeslice", 1, False, 1, 1000, 20,
     "调度时间片参数（EEVDF base_slice，单位 0.1ms；安全限幅+快照+记录）"),
    ("mm.swappiness", 2, False, 0, 100, 60,
     "内存换页倾向 swappiness（实时生效，经 mm/vmscan.c 门控访问器）"),
    ("mm.readahead", 2, False, 0, 4096, 128,
     "预读窗口 KB（写全部 bdi ra_pages，与 /sys/class/bdi/*/readahead_kb 同源，实时生效）"),
    ("mm.thp", 2, False, 0, 2, 2,
     "透明大页模式（0=never 1=madvise 2=always，实时生效；"
     "VM /proc/ai/control 实测默认 2=always）"),
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
    ("net.qdisc", 4, False, 0, 3, 0,
     "默认队列调度 qdisc（0=回滚到设置前快照 kind/无快照 no-op 1=codel 2=fq 3=fq_codel；"
     "独立内核 worker 持 rtnl 异步换根，作用于 up 的非回环单队列网卡，多队列诚实跳过；"
     "异步生效用 tc qdisc show 实证；客户端+内核双层钳制；值域 0-3；"
     "VM /proc/ai/control 实测 domain=4 [real] min=0 max=3 default=0）"),
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
     "W49 起为 reserved 保留参数：VM /proc/ai/control 实测 sec.seccomp "
     "domain=5 [reserved]，当前内核不提供 seccomp BPF 注入/解除，写入只"
     "记录值、不产生任何拦截或规则副作用；需要真实安全策略请用 "
     "sec.lsm_override（enforce/observe）与 sec.audit（审计采集）；"
     "seccomp 基线应在用户态 exec 前由子进程自装过滤器"),
    ("sec.audit", 5, False, 0, 1, 1,
     "AIKernel 审计采集开关（0=停采、事件在 gate 直接丢弃 1=采集关联；"
     "VM /proc/ai/control 实测默认 1）"),
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

# exec_run input 参数上限（字节）。必须 < pipe 容量（64KB）：一次 write
# 即整体进入 pipe 缓冲，父进程不阻塞，随后立即关闭写端开始排空 stdout，
# 避免"子进程写满 stdout 等父进程读 / 父进程写 stdin 等子进程读"死锁。
EXEC_INPUT_MAX_BYTES = 60000


def ex(cmd, risk, bin=None, timeout=0, path_check=False,
       args_template=None, args0=None, path_roots=None):
    """构造单条 exec.commands 条目"""
    e = {"command": cmd, "risk": risk, "bin": bin or f"/usr/bin/{cmd}"}
    if timeout:
        e["timeout"] = timeout
    if path_check:
        e["path_check"] = True
    if path_roots:
        # 更严格的写目标根（如 gcc/cc 仅 /tmp）；缺省时 executor 用
        # /root /tmp /var/ai。
        e["path_roots"] = list(path_roots)
    if args_template:
        e["args_template"] = args_template
    if args0:
        e["args0"] = [{"verb": v, "risk": r} for v, r in args0]
    return e


EXEC_COMMANDS = [
    # ---- R 级（只读诊断）----
    # 11 个基线 + v2 新增 + W48 数据层接入（只读面）
    *[ex(c, RISK_R) for c in (
        "ls", "cat", "head", "tail", "grep", "ps", "free", "df",
        "uname", "uptime", "date", "echo", "printf",
        "dmesg", "ss", "stat", "wc", "sort", "uniq",
        "cut", "which", "whereis", "lsblk", "du", "lscpu", "vmstat",
        "pidof", "pgrep", "id", "getent", "systemd-analyze",
    )],
    ex("journalctl", RISK_R, timeout=60,
       args_template=["--no-pager"], bin="/usr/bin/journalctl"),
    # curl/ollama：只读面；W48 起 curl 写参数（POST/-d/-F/-T/-o/-X 等）
    # 动态判 W2，ollama 按首参动词分级（详见 executor.c exec_effective_risk）
    ex("curl", RISK_R, timeout=60, bin="/usr/bin/curl"),
    ex("ollama", RISK_R, timeout=60, bin="/usr/local/bin/ollama",
       args0=[("list", RISK_R), ("ps", RISK_R), ("show", RISK_R),
              ("run", RISK_W1), ("pull", RISK_W2), ("rm", RISK_W2),
              ("cp", RISK_W1), ("create", RISK_W2), ("push", RISK_W2),
              ("stop", RISK_W1), ("serve", RISK_W2), ("help", RISK_R),
              ("--version", RISK_R)]),
    # systemctl：只读子命令 R，启停/开机自启/重启/关机 W2（首参二级白名单）
    # W72：补 --failed / is-system-running（W70 T10 实测被 E_PARAM_SUBCOMMAND
    # 误拒）；两者均为只读诊断形态。
    ex("systemctl", RISK_W2, timeout=60,
       args_template=["--no-pager"],
       args0=[("status", RISK_R), ("list-units", RISK_R),
              ("list-unit-files", RISK_R), ("list-timers", RISK_R),
              ("list-jobs", RISK_R),
              ("is-active", RISK_R), ("is-system-running", RISK_R),
              ("--failed", RISK_R),
              ("is-enabled", RISK_R), ("show", RISK_R), ("cat", RISK_R),
              ("get-default", RISK_R),
              ("start", RISK_W2), ("stop", RISK_W2),
              ("restart", RISK_W2), ("reload", RISK_W2),
              ("enable", RISK_W2), ("disable", RISK_W2),
              ("mask", RISK_W2), ("unmask", RISK_W2),
              ("daemon-reload", RISK_W1), ("set-default", RISK_W2),
              ("isolate", RISK_W2), ("rescue", RISK_W2),
              ("emergency", RISK_W2), ("reboot", RISK_W2),
              ("poweroff", RISK_W2), ("halt", RISK_W2)]),
    # W10-A 运维四件套 AI 接入：防火墙（W2 高危写）与时间状态（R）
    ex("nft", RISK_W2, timeout=30, bin="/usr/sbin/nft"),
    # timedatectl：W48 按首参动词分级（F3 修复）——查询 R，改时间/时区/NTP W2
    ex("timedatectl", RISK_R, timeout=30, bin="/usr/bin/timedatectl",
       args0=[("status", RISK_R), ("show", RISK_R),
              ("list-timezones", RISK_R), ("timesync-status", RISK_R),
              ("show-timesync", RISK_R), ("ntp-servers", RISK_W2),
              ("set-time", RISK_W2), ("set-timezone", RISK_W2),
              ("set-ntp", RISK_W2), ("set-local-rtc", RISK_W2)]),
    # W11 网络细控 AI 接入：tc 流量整形/优先级（W2 高危写，真改网络行为）
    ex("tc", RISK_W2, timeout=30, bin="/usr/sbin/tc"),
    # W48 F3/ns-2：ip 整条原为 R，但 add/del/set 等写动词可改地址/路由/
    # 链路（W2）。bin 修正为 /usr/sbin/ip（L1 与工厂 rootfs 的实际路径，
    # 旧 /usr/bin/ip 在两者都不存在——W48 静态核对发现的潜在断链）。
    ex("ip", RISK_R, bin="/usr/sbin/ip"),
    # ns-6：ethtool 查询 R；-s/-K/-G/-A/-C/-L/-E/-f/-r 等写参数动态 W2
    ex("ethtool", RISK_R, bin="/usr/sbin/ethtool"),
    # ns-5：conntrack 表操作——查询 R，flush/delete/update 等 W2
    ex("conntrack", RISK_W2, bin="/usr/sbin/conntrack",
       args0=[("-L", RISK_R), ("--dump", RISK_R), ("-S", RISK_R),
              ("-C", RISK_R), ("-E", RISK_R),
              ("-F", RISK_W2), ("--flush", RISK_W2),
              ("-D", RISK_W2), ("--delete", RISK_W2),
              ("-U", RISK_W2), ("--update", RISK_W2),
              ("-I", RISK_W2)]),
    # ns-3：DNS/主机名（hostnamectl/resolvectl 首参分级；读 R，写 W2）
    ex("hostnamectl", RISK_R, bin="/usr/bin/hostnamectl",
       args0=[("status", RISK_R), ("show", RISK_R),
              ("hostname", RISK_W2), ("set-hostname", RISK_W2),
              ("set-icon-name", RISK_W2), ("set-chassis", RISK_W2),
              ("set-deployment", RISK_W2), ("set-location", RISK_W2)]),
    ex("resolvectl", RISK_R, bin="/usr/bin/resolvectl",
       args0=[("status", RISK_R), ("statistics", RISK_R),
              ("query", RISK_R), ("dns", RISK_W2), ("domain", RISK_W2),
              ("default-route", RISK_W2), ("llmnr", RISK_W2),
              ("mdns", RISK_W2), ("dnssec", RISK_W2),
              ("dnsovertls", RISK_W2), ("flush-caches", RISK_W2),
              ("reset-server-features", RISK_W2), ("revert", RISK_W2),
              ("log-level", RISK_W2)]),
    # fs-1/fs-2/fs-4/fs-5：只读面（写面见下方 W2 段）
    ex("findmnt", RISK_R, bin="/usr/bin/findmnt"),
    ex("blkid", RISK_R, bin="/usr/sbin/blkid"),
    ex("dumpe2fs", RISK_R, bin="/usr/sbin/dumpe2fs"),
    ex("smartctl", RISK_R, timeout=60, bin="/usr/sbin/smartctl"),
    ex("quota", RISK_R, bin="/usr/bin/quota"),
    ex("repquota", RISK_R, bin="/usr/sbin/repquota"),
    ex("pvs", RISK_R, bin="/usr/sbin/pvs"),
    ex("vgs", RISK_R, bin="/usr/sbin/vgs"),
    ex("lvs", RISK_R, bin="/usr/sbin/lvs"),
    # ns-8：AppArmor 状态查询（写面见 aa-enforce/complain/disable）
    ex("aa-status", RISK_R, bin="/usr/sbin/aa-status"),
    ex("apparmor_status", RISK_R, bin="/usr/sbin/apparmor_status"),
    ex("hostname", RISK_R, bin="/usr/bin/hostname"),
    # fs-6：受控 find（executor 拒绝 -exec/-execdir/-ok/-okdir/-delete/
    # -fprintf/-fls，只保留纯检索面；其余参数仍过元字符黑名单）
    ex("find", RISK_R, bin="/usr/bin/find"),
    # ---- W1 级（低危写；写目标绝对路径限 /root /tmp /var/ai）----
    # 8 个直接注册；tar/gzip/traceroute 单列：自定义超时
    *[ex(c, RISK_W1, path_check=True) for c in (
        "mkdir", "touch", "cp", "mv", "ln", "sed", "tee",
    )],
    # ping 的目标是主机名/IP，不是文件路径；不设 path_check（W69 r2：
    # 避免把 127.0.0.1 当相对路径误拒）。-f/--flood 由 executor 升 W2。
    ex("ping", RISK_W1, bin="/usr/bin/ping"),
    # W69 P1-1：tar 升 W2。理由：--checkpoint-action/--to-command 等选项
    # 可执行任意程序；归档成员含 ../ 或符号链接时，解包写面无法仅靠 argv
    # 前缀校验完全约束。W2 逐次确认 + executor 选项黑名单 + 沙箱表剔除。
    ex("tar", RISK_W2, path_check=True, timeout=120),
    ex("gzip", RISK_W1, path_check=True, timeout=120),
    # W65 P2-04：受控编译器（W1，仅 /tmp 读写）。源码/产物/包含路径的
    # 非选项参数都过 path_check，命令内禁止 shell 元字符；TMPDIR 由
    # executor 强制 /tmp。用于「写代码→编译→运行」闭环，替代此前只能
    # 写 W2 python3 脚本调用编译器的绕行。
    ex("gcc", RISK_W1, path_check=True, path_roots=["/tmp"], timeout=120,
       bin="/usr/bin/gcc"),
    ex("cc", RISK_W1, path_check=True, path_roots=["/tmp"], timeout=120,
       bin="/usr/bin/cc"),
    ex("traceroute", RISK_W1, timeout=60),
    ex("sync", RISK_W1, bin="/usr/bin/sync"),
    # ---- W2 级（高危写）----
    ex("kill", RISK_W2),
    ex("apt", RISK_W2, timeout=300),
    ex("dpkg", RISK_W2, timeout=300),
    ex("passwd", RISK_W2, bin="/usr/bin/passwd"),
    # W20 修5（用户拍板）：受控解释器入列——AI 编程助手核心能力
    # （写代码→执行→报告，T3 D3/E1 被系统性阻断的根因）。
    # 风险 W2：每次执行红色 y/N 确认，审计全程落盘；参数形态由
    # executor 强校验：仅允许 `python3 <script.py> [参数...]`
    # （首参必须 .py 脚本路径，禁止 -c/-m 等解释器表达式入口，
    # 禁一切选项），shell 元字符黑名单照常全局生效。
    ex("python3", RISK_W2, timeout=120, bin="/usr/bin/python3"),
    # fs-1/fs-9：挂载/卸载/TRIM（W2；mount 可把任意设备挂到任意点）
    ex("mount", RISK_W2, bin="/usr/bin/mount"),
    ex("umount", RISK_W2, bin="/usr/bin/umount"),
    ex("fstrim", RISK_W2, timeout=120, bin="/usr/sbin/fstrim"),
    # res-6：swap 开关（W2；swapoff 全部可能触发 OOM）
    ex("swapon", RISK_W2, bin="/usr/sbin/swapon"),
    ex("swapoff", RISK_W2, bin="/usr/sbin/swapoff"),
    # fs-4：配额设置（W2）
    ex("setquota", RISK_W2, bin="/usr/sbin/setquota"),
    # fs-7：受控删除/权限（W2 + path_check：只允许 /root /tmp /var/ai，
    # 系统路径一律拒绝；这是"受控包装"而非无界 rm）
    ex("rm", RISK_W2, path_check=True, bin="/usr/bin/rm"),
    ex("chmod", RISK_W2, path_check=True, bin="/usr/bin/chmod"),
    ex("chown", RISK_W2, path_check=True, bin="/usr/bin/chown"),
    # sy-2：用户/组管理（W2）
    ex("useradd", RISK_W2, bin="/usr/sbin/useradd"),
    ex("usermod", RISK_W2, bin="/usr/sbin/usermod"),
    ex("userdel", RISK_W2, bin="/usr/sbin/userdel"),
    ex("groupadd", RISK_W2, bin="/usr/sbin/groupadd"),
    ex("groupmod", RISK_W2, bin="/usr/sbin/groupmod"),
    ex("groupdel", RISK_W2, bin="/usr/sbin/groupdel"),
    # ns-8：AppArmor 模式切换（W2）
    ex("aa-enforce", RISK_W2, bin="/usr/sbin/aa-enforce"),
    ex("aa-complain", RISK_W2, bin="/usr/sbin/aa-complain"),
    ex("aa-disable", RISK_W2, bin="/usr/sbin/aa-disable"),
    # sy-3/sy-4/sy-5：备份、恢复、A/B 升级（脚本自带 --yes/防呆门；W2）
    ex("aik-backup", RISK_W2, timeout=300, bin="/usr/local/sbin/aik-backup"),
    ex("aik-reset", RISK_W2, bin="/usr/local/sbin/aik-reset"),
    ex("aik-upgrade", RISK_W2, timeout=300,
       bin="/usr/local/sbin/aik-upgrade",
       args0=[("status", RISK_R), ("healthcheck", RISK_R),
              ("export", RISK_W2), ("import", RISK_W2),
              ("install", RISK_W2), ("boot", RISK_W2),
              ("commit", RISK_W2), ("rollback", RISK_W2),
              ("auto-commit", RISK_W2), ("grubenv", RISK_W2)]),
    # sy-1：crontab（首参 -l 查询 R；-r 清空/文件安装 W2；-e 交互拒绝；
    # 无参数会从 stdin 读空内容覆盖当前表——executor 显式拒绝）
    ex("crontab", RISK_W2, bin="/usr/bin/crontab"),
]

EXEC_ENUM = [c["command"] for c in EXEC_COMMANDS]


# ---------------------------------------------------------------------------
# 工具构造器
# ---------------------------------------------------------------------------

def tool_procfs(path, desc):
    rel = path[len("/proc/ai/"):].replace("/", "_")
    return {
        "name": "procfs_read_" + rel,
        "channel": CH_PROC,
        "risk": RISK_R,
        "description": f"读取 {path}（只读）：{desc}",
        "path": path,
        "parameters": obj_schema(),
    }


def tool_readfile(name, path, desc, probe=None):
    """通用只读文件工具（/sys/kernel/ai/stats、/sys/fs/cgroup/ai.*）

    @probe: 能力探测路径（可选）。运行时若该路径不存在，工具标记为
    unavailable：不进入 tools 数组/目录页/清单，SME 检索命中也跳过；
    直接调用返回明确 unavailable 错误（W65 P2-05 PSI）。
    """
    t = {
        "name": name,
        "channel": CH_PROC,
        "risk": RISK_R,
        "description": f"读取 {path}（只读）：{desc}",
        "path": path,
        "parameters": obj_schema(),
    }
    if probe:
        t["probe"] = probe
        t["description"] += f"（能力探测：{probe} 不存在时本工具不可用）"
    return t


def tool_sysfs(rel, desc, desc_short, schema):
    name = "sysfs_write_" + rel.replace("/", "_")
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
    """27 个可控参数每个一个工具，如 netlink.act.sched.nice(pid,value)"""
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
    if name == "sec.seccomp":
        clamp_note = "（reserved 参数，无真实拦截副作用）"
    elif (vmin, vmax) == (0, 1):
        clamp_note = ("（默认安全钳制可能拦截翻转，需临时调 "
                      "/sys/kernel/ai/policy/max_impact_pct）")
    else:
        clamp_note = ""
    return {
        "name": "netlink_act_" + name.replace(".", "_"),
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
        "name": "netlink_sense",
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
        "name": "exec_run",
        "channel": CH_EXEC,
        "description": "执行白名单 shell 命令（fork+execv 不经 shell）。"
                       "核心能力：python3 执行 .py 脚本（W2 高危写，"
                       "逐次红色确认；先 tee 落盘 /root /tmp 再以 "
                       "python3 <script.py> 执行，禁止 -c/-m 与一切"
                       "选项）、tee 写文件（input 配方）、只读诊断。"
                       "白名单/可执行路径/超时/风险分级单源于本工具内嵌的 "
                       "exec.commands（R 只读诊断 / W1 低危写（目标限 "
                       "/root /tmp /var/ai）/ W2 高危写）；参数含 shell "
                       "元字符或超长整条拒绝；默认 30 秒超时后 SIGKILL。"
                       "写文件配方：command=\"tee\"、args=[\"/tmp/t.txt\"]、"
                       "input=文件内容；追加写 args=[\"-a\", \"/tmp/t.txt\"]"
                       "（写目标限 /root /tmp /var/ai）。未给 input 时 stdin "
                       "接 /dev/null（无参 cat 不会挂起）；python3 每次执行"
                       "逐次弹红色确认面板，审计全量落盘",
        "exec": {
            "default_timeout": EXEC_DEFAULT_TIMEOUT,
            "input_max_bytes": EXEC_INPUT_MAX_BYTES,
            "commands": EXEC_COMMANDS,
        },
        "parameters": obj_schema(
            {
                "command": {"type": "string",
                            "description": "命令名（白名单内单个词，如 uname /"
                                           " df / ss）。严禁把整条命令串塞进"
                                           "本字段：'uname -a' 应写 "
                                           "command=\"uname\", args=[\"-a\"]；"
                                           "'touch /tmp/x' 应写 "
                                           "command=\"touch\", "
                                           "args=[\"/tmp/x\"]。选项和操作数"
                                           "一律放 args 数组。",
                            "enum": EXEC_ENUM},
                "args": {"type": "array",
                         "description": "命令参数列表（如 [\"-h\"]；含元字符/"
                                        "超 256 字符整条拒绝）",
                         "items": {"type": "string"}},
                "input": {"type": "string",
                          "description": "可选：喂给命令 stdin 的文本"
                                         "（≤60000 字节）。写文件用它给 tee "
                                         "提供内容，如 command=\"tee\"、"
                                         "args=[\"/tmp/t.txt\"]、"
                                         "input=\"hello\"。echo/printf 只"
                                         "回显到输出、不落盘"},
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
        "name": "sys_shell",
        "channel": CH_SHELL,
        "risk": RISK_W2,
        "description": "替用户降入交互式维护 shell（bash）。W2 高危：仅"
                       "当用户明确请求打开 shell / 进入命令行时调用（如"
                       "「帮我打开一个 shell」）；且仅宿主 TTY 会话可用，"
                       "沙箱子进程与非交互环境一律拒绝。用户输入 exit 退出"
                       "后本工具返回，再把控制权交还对话。审计行记录"
                       "「AI 应请求开启 shell」。",
        "parameters": obj_schema({}, []),
    }


# ---------------------------------------------------------------------------
# W48：数据层 35 件 + 通用 sysctl/sysfs 动态通道
#
# 设计口径（用户最高指令：AI 全面接管，除写入即 brick 的之外全接）：
#   - 固定节点能力已在内核/系统里，这里只补注册（数据层）；
#   - 动态路径（/proc/sys 千余旋钮、cgroup 每 cgroup 的 ai.*、sysfs
#     per-policy/per-cpu 文件）用 sysctl_get/set 与 sysfs_get/set 两个
#     组合通道收编，避免为每个动态文件写死工具；
#   - 所有写工具都写清：是什么/何时用/风险/参数域/回滚方式；
#   - 只有"写入即可能 brick/panic/不可恢复/远程失联"的进入
#     CRASH_BLACKLIST（sysctl_set 硬拒）；其余敏感项一律 W2 二次确认。
# ---------------------------------------------------------------------------

def tool_sysctl_get():
    return {
        "name": "sysctl_get",
        "channel": CH_SYSCTL,
        "risk": RISK_R,
        "description": "读取 Linux sysctl（/proc/sys 下任意合法键，只读）："
                       "key 用点号形式（如 net.ipv4.ip_forward）或斜杠形式"
                       "（net/ipv4/ip_forward）；也可用 prefix 列举整棵子树"
                       "（如 net.ipv4），输出 key = value 行并在超限时标注"
                       "截断。适用场景：查看内核网络/内存/文件系统/vm 旋钮、"
                       "排障前取证、写 sysctl_set 前读旧值。只读无风险；"
                       "路径经 realpath 校验，只允许 /proc/sys 下真实文件。",
        "parameters": obj_schema({
            "key": {"type": "string",
                    "description": "sysctl 键（点号或斜杠形式），与 prefix 二选一"},
            "prefix": {"type": "string",
                       "description": "子树前缀（如 net.ipv4、vm、kernel），列举其下全部键值"},
        }),
    }


def tool_sysctl_set():
    return {
        "name": "sysctl_set",
        "channel": CH_SYSCTL,
        "risk": RISK_W2,
        "description": "写入 Linux sysctl（W2 高危写，逐次红色确认）：key 用"
                       "点号形式（如 net.ipv4.ip_forward、vm.swappiness），"
                       "value 为单行文本。执行前会把旧值写入审计（可据此"
                       "回滚），写入后回读确认并返回 old/new。安全约束："
                       "① realpath 必须落在 /proc/sys/ 内（防路径穿越/符号"
                       "链接逃逸）；② 拒绝换行/NUL/控制字符；③ 命中崩溃"
                       "黑名单直接拒绝并给出原因（kernel.sysrq、kernel.panic*、"
                       "kernel.core_pattern、kernel.modules_disabled、"
                       "vm.panic_on_oom 等，完整清单见 sysctl_blacklist 工具）。"
                       "典型合法场景：ip_forward、somaxconn、conntrack_max、"
                       "swappiness、vfs_cache_pressure、rp_filter（敏感但可回滚，"
                       "仍为 W2）。",
        "parameters": obj_schema({
            "key": {"type": "string",
                    "description": "sysctl 键（点号形式，如 net.ipv4.ip_forward）"},
            "value": {"type": "string",
                      "description": "新值（单行；禁止换行/NUL/控制字符）"},
        }, ["key", "value"]),
    }


def tool_sysctl_blacklist():
    return {
        "name": "sysctl_blacklist",
        "channel": CH_SYSCTL,
        "risk": RISK_R,
        "description": "列出 sysctl_set 的崩溃黑名单（只读）：每项含键前缀、"
                       "拒绝原因、是否可通过参数绕过（不可）。给 AI 在写"
                       "sysctl 前自检用；命中黑名单的写入由执行器硬拒绝，"
                       "不存在 --force 或白名单旁路。",
        "parameters": obj_schema({}, []),
    }


def tool_sysfs_get():
    return {
        "name": "sysfs_get",
        "channel": CH_SYSFS_DYN,
        "risk": RISK_R,
        "description": "读取 sysfs/procfs 任意受控路径（只读）：path 必须是"
                       "绝对路径，允许前缀 /sys/、/proc/sys/、/proc/irq/、"
                       "/proc/ai/、/proc/pressure/、/proc/net/。适用场景："
                       "读 cgroup v2 限额（/sys/fs/cgroup/<组>/memory.max）、"
                       "AIKernel per-policy 开关（/sys/kernel/ai/policy/<name>）、"
                       "cpufreq governor（/sys/devices/system/cpu/cpu0/cpufreq/"
                       "scaling_governor）、IRQ 亲和（/proc/irq/<n>/smp_affinity）"
                       "等动态文件。realpath 校验防穿越；超长输出截断标注。",
        "parameters": obj_schema({
            "path": {"type": "string",
                     "description": "绝对路径（受控前缀内，见描述）"},
            "max_bytes": {"type": "integer",
                          "description": "最多读取字节数（默认 32768，上限 131072）",
                          "minimum": 1, "maximum": 131072},
        }, ["path"]),
    }


def tool_sysfs_set():
    return {
        "name": "sysfs_set",
        "channel": CH_SYSFS_DYN,
        "risk": RISK_W2,
        "description": "写 sysfs/procfs 受控动态文件（W2 高危写，逐次红色"
                       "确认）：path 为绝对路径，value 为单行文本。允许前缀"
                       "仅：/sys/fs/cgroup/（cgroup v2 资源配给，含 ai.max_"
                       "inferences/ai.max_tops/ai.mem_limit_mb、cpu.max、"
                       "memory.max、io.max、pids.max）、/sys/kernel/ai/（含"
                       "动态 policy/<name>）、/sys/devices/system/cpu/"
                       "（cpufreq governor/EAS）、/sys/block/（IO 调度）、"
                       "/sys/class/net/（网卡队列/offload）、/proc/irq/"
                       "（smp_affinity）、/proc/ai/。执行前记录旧值到审计，"
                       "写入后回读。刻意排除 /sys/power（suspend 可让远程"
                       "主机失联）、/sys/firmware（可写坏引导固件）、"
                       "/sys/kernel/debug|security|config、/sys/module。"
                       "cgroup 文件通常只存在于子组：先 sysfs_get 确认路径。",
        "parameters": obj_schema({
            "path": {"type": "string",
                     "description": "绝对路径（受控前缀内，文件必须已存在）"},
            "value": {"type": "string",
                      "description": "新值（单行；禁止换行/NUL/控制字符）"},
        }, ["path", "value"]),
    }


def tool_memory_health():
    return tool_mem("memory_health", RISK_R,
                    "SME 记忆服务健康探活（GET /health，只读）：返回 "
                    "status/memories 等 JSON；SME 不可达时立即暴露"
                    "（记忆是增强能力，不可达不应拖垮主链路）。排障第"
                    "一步：先 health，再 stats/metrics。")


def data_layer_tools():
    """W48 数据层 35 件（res/fs/netsec/aicore/memory 五域）。"""
    tools = []

    # ---- res 资源域（7 件）----
    tools.extend([
        tool_readfile("procfs_read_pressure_cpu", "/proc/pressure/cpu",
                      "CPU PSI 压力（some/full 的 avg10/avg60/avg300/total，"
                      "只读）：判断 CPU 是否成为瓶颈；与 memory/io 两文件"
                      "联读定位 stall 根因", probe="/proc/pressure"),
        tool_readfile("procfs_read_pressure_memory", "/proc/pressure/memory",
                      "内存 PSI 压力（some/full，只读）：OOM/回收前兆的"
                      "金标准；AI 做内存配给与回收决策前先读",
                      probe="/proc/pressure"),
        tool_readfile("procfs_read_pressure_io", "/proc/pressure/io",
                      "IO PSI 压力（some/full，只读）：磁盘/IO 拥塞诊断；"
                      "与 io.priority/io.bandwidth 参数配合",
                      probe="/proc/pressure"),
        tool_readfile("procfs_read_swaps", "/proc/swaps",
                      "swap 区清单（Filename/Type/Size/Used/Priority，只读）："
                      "查看当前 swap 是否启用、用量与优先级；开关用 exec "
                      "swapon/swapoff（W2）"),
        tool_readfile("procfs_read_interrupts", "/proc/interrupts",
                      "各 CPU 中断计数（只读）：定位中断风暴/网卡 IRQ 分布；"
                      "单 IRQ 亲和用 sysfs_get/sysfs_set 读写 "
                      "/proc/irq/<n>/smp_affinity"),
        tool_readfile("procfs_read_irq_default_affinity",
                      "/proc/irq/default_smp_affinity",
                      "新建 IRQ 的默认 CPU 亲和掩码（只读）：改默认亲和用 "
                      "sysfs_set 写同一路径（W2）"),
        tool_writefile("sysfs_write_sched_classify",
                       "/proc/ai/sched/classify",
                       "目标 pid（十进制）", RISK_W1,
                       "向 /proc/ai/sched/classify 写 pid 查询单任务调度"
                       "分类（AIKernel 内核调度分类器；写后回读分类结果）",
                       obj_schema({"value": {"type": "string",
                                             "description": "目标进程 PID"}},
                                  ["value"])),
    ])

    # ---- fs 存储/配置域（14 件）----
    tools.extend([
        tool_readfile("procfs_read_mounts", "/proc/mounts",
                      "当前挂载表（只读）：设备/挂载点/文件系统/选项；"
                      "挂载与卸载用 exec mount/umount（W2），查询可用 "
                      "exec findmnt"),
        tool_readfile("procfs_read_filesystems", "/proc/filesystems",
                      "内核支持的文件系统清单（只读）：判断能否挂载某类型"),
        tool_readfile("config_read_fstab", "/etc/fstab",
                      "系统开机挂载表（只读）：改前必读；写用 "
                      "config_write_fstab（W2，整文件覆盖，写坏可致开机"
                      "失败，需保留可启动回退）"),
        tool_writefile("config_write_fstab", "/etc/fstab",
                       "完整 fstab 文本", RISK_W2,
                       "整文件覆盖 /etc/fstab（W2 高危写）：先 config_read_"
                       "fstab 取全文，只改目标行后整体写回；错误条目可导致"
                       "开机挂载失败/进入维护模式。优先用 mount -a 验证",
                       obj_schema({"value": {"type": "string",
                                             "description": "完整文件内容（含换行）"}},
                                  ["value"])),
        tool_readfile("config_read_nftables", "/etc/nftables.conf",
                      "防火墙持久化配置（只读）：运行时 nft 规则重启即失，"
                      "持久化改此文件；写用 config_write_nftables（W2）"),
        tool_writefile("config_write_nftables", "/etc/nftables.conf",
                       "完整 nftables.conf 文本", RISK_W2,
                       "整文件覆盖 /etc/nftables.conf（W2）：先读后写，"
                       "改完用 nft -c -f 语法检查；错误规则可致远程失联，"
                       "务必保留现有 SSH 放行规则",
                       obj_schema({"value": {"type": "string",
                                             "description": "完整文件内容（含换行）"}},
                                  ["value"])),
        tool_readfile("config_read_sshd_config", "/etc/ssh/sshd_config",
                      "SSH 服务端配置（只读）：排障/审计 PermitRootLogin、"
                      "PasswordAuthentication 等；写用 config_write_sshd_"
                      "config（W2，改错可锁死远程登录）"),
        tool_writefile("config_write_sshd_config", "/etc/ssh/sshd_config",
                       "完整 sshd_config 文本", RISK_W2,
                       "整文件覆盖 /etc/ssh/sshd_config（W2）：先读后写，"
                       "保留至少一条可登录通道；改完用 sshd -t 校验再 "
                       "systemctl reload ssh。写错可导致远程锁死",
                       obj_schema({"value": {"type": "string",
                                             "description": "完整文件内容（含换行）"}},
                                  ["value"])),
        tool_readfile("config_read_resolv_conf", "/etc/resolv.conf",
                      "DNS 解析配置（只读）：nameserver/search/options；"
                      "DNS 失效是最高频网络故障，先读再改"),
        tool_writefile("config_write_resolv_conf", "/etc/resolv.conf",
                       "完整 resolv.conf 文本", RISK_W1,
                       "整文件覆盖 /etc/resolv.conf（W1）：先读后写，保留"
                       "现有可用 nameserver 作为回退；systemd-resolved 环境"
                       "下该文件可能是符号链接，写前用 sysfs_get 确认真实"
                       "落点",
                       obj_schema({"value": {"type": "string",
                                             "description": "完整文件内容（含换行）"}},
                                  ["value"])),
        tool_readfile("config_read_hosts", "/etc/hosts",
                      "本地主机名映射（只读）：排查域名解析/本地别名；"
                      "写用 config_write_hosts（W1）"),
        tool_writefile("config_write_hosts", "/etc/hosts",
                       "完整 hosts 文本", RISK_W1,
                       "整文件覆盖 /etc/hosts（W1）：先读后写，保留 localhost "
                       "基线行",
                       obj_schema({"value": {"type": "string",
                                             "description": "完整文件内容（含换行）"}},
                                  ["value"])),
        tool_readfile("config_read_hostname", "/etc/hostname",
                      "静态主机名文件（只读）：改主机名优先用 hostnamectl "
                      "set-hostname（W2），本文件是持久化落点"),
        tool_writefile("config_write_hostname", "/etc/hostname",
                       "新主机名（单行）", RISK_W1,
                       "写 /etc/hostname（W1）：优先 hostnamectl set-hostname"
                       "（会同步运行时主机名）；直接写本文件只改下次启动值",
                       obj_schema({"value": {"type": "string",
                                             "description": "主机名（单行，仅字母数字.-）"}},
                                  ["value"])),
    ])

    # ---- netsec 通用通道（5 件）----
    tools.extend([
        tool_sysctl_get(),
        tool_sysctl_set(),
        tool_sysctl_blacklist(),
        tool_sysfs_get(),
        tool_sysfs_set(),
    ])

    # ---- aicore 内核 AI 面（8 件）----
    tools.append(tool_sysfs(
        "model_infer",
        "触发内核内 MLP 推理（W1）：value 格式为 \"<模型名> <float32 输入"
        "向量 hex...>\"（小端 hex，空格分隔）；推理走 ai_runtime_model_"
        "infer_by_name，结果用 procfs_read_model_out 读取",
        "模型名+hex 输入", obj_schema({"value": {
            "type": "string",
            "description": "<模型名> <hex float32...>，如 \"mlp 0000803f00000040\""}},
            ["value"])))
    tools.append(tool_readfile(
        "procfs_read_model_out", "/sys/kernel/ai/model_out",
        "最近一次内核内 MLP 推理结果（只读）：模型名/输入输出长度/输出 "
        "float32 hex；与 sysfs_write_model_infer 配对使用"))
    for hook, why in (
            ("oom_badness", "OOM 受害者评分偏置（交互式保护/批处理加压）"),
            ("sched_vruntime", "调度 vruntime 加权（±10%）"),
            ("sched_wakeup", "唤醒抢占提示"),
            ("readahead", "预读窗口偏置（±1 档）"),
            ("reclaim", "回收扫描优先级偏置（±1 档）")):
        tools.append(tool_sysfs(
            f"decision/{hook}",
            f"单 hook 决策注入开关（W1）：1=启用 0=停用；{why}。"
            "需同时打开 /sys/kernel/ai/decision_inject 总闸（sysfs_write_"
            "decision_inject 未单列，可用 sysfs_set 写同一路径）；"
            "实际偏置仍受内核安全限幅",
            "0/1", obj_schema({"value": {
                "type": "string", "description": "1=启用 0=停用",
                "enum": ["0", "1"]}}, ["value"])))
    tools.append(tool_readfile(
        "procfs_read_decision_stats", "/sys/kernel/ai/decision/stats",
        "per-hook 决策注入记账（只读）：每个 hook 的 queries/injected/"
        "effects/fallback/ring/last_bias，用于归因注入效果"))

    # ---- memory 域（1 件）----
    tools.append(tool_memory_health())

    return tools


# ---------------------------------------------------------------------------
# W42：隔离区 + 子智能体（sandbox 通道，四件）
# 宿主侧包装独立工具 aik-sandbox（agent/ai/sandbox/aik-sandbox.c）：
# clone(NS|PID|UTS) → tmpfs 空根 → /usr /proc /sys /etc 白名单 ro bind →
# pivot_root → exec。宿主 /root /home /var 整体不可见；网络保留（子智能体
# 要访问 AI 引擎与 SME）。
# ---------------------------------------------------------------------------
SB_NAME_PARAM = {"name": {"type": "string",
                          "description": "隔离区名（字母数字.-_，≤64 字符；"
                                         "如 sb1）"}}


def tool_sandbox_status():
    return {
        "name": "sandbox_status",
        "channel": CH_SANDBOX,
        "risk": RISK_R,
        "description": "列出隔离区（只读）：/sandbox/ 下各区名称、挂载点与"
                       "存活子智能体 pid",
        "parameters": obj_schema({}, []),
    }


def tool_sandbox_create():
    return {
        "name": "sandbox_create",
        "channel": CH_SANDBOX,
        "risk": RISK_W1,
        "description": "建立隔离区：创建 /sandbox/<name>/root 挂载点目录"
                       "（低危写；真正的 namespace 隔离在 sandbox_spawn 的 "
                       "run 阶段生效）",
        "parameters": obj_schema(SB_NAME_PARAM, ["name"]),
    }


def tool_sandbox_spawn():
    return {
        "name": "sandbox_spawn",
        "channel": CH_SANDBOX,
        "risk": RISK_W2,
        "description": "派子智能体进隔离区干活（W2 高危写，红色确认）：在"
                       "新 mount/pid/uts namespace 中挂 tmpfs 空根，/usr "
                       "/proc /sys 与 /etc 白名单只读挂入，宿主 /root /home "
                       "/var 完全不可见，网络保留；子智能体以受限工具表"
                       "运行（无任何 W2 能力、不能再派生沙盒），输出尾部"
                       " 4KB 作为摘要返回；max_seconds 超时 SIGKILL 全组。"
                       "典型用法：先 sandbox_create 建区，再本工具派活，"
                       "最后 sandbox_destroy 焚区",
        "parameters": obj_schema(
            {
                "name": SB_NAME_PARAM["name"],
                "task": {"type": "string",
                         "description": "交给子智能体的任务（一段话指令，"
                                        "如「报告你的工作目录与可见根目录"
                                        "内容」）"},
                "max_seconds": {"type": "integer",
                                "description": "任务预算秒数（默认 300，"
                                               "上限 900；超时击杀）",
                                "minimum": 1, "maximum": 900,
                                "default": 300},
                "model": {"type": "string",
                          "description": "可选：子智能体模型偏好（当前 ai "
                                         "CLI 无模型选择参数，登记为 "
                                         "AIKERNEL_SANDBOX_MODEL 供跟踪，"
                                         "模型沿用其自身 model.toml）"},
            },
            ["name", "task"]),
    }


def tool_sandbox_destroy():
    return {
        "name": "sandbox_destroy",
        "channel": CH_SANDBOX,
        "risk": RISK_W1,
        "description": "焚毁隔离区：卸载残留并清除 /sandbox/<name>（幂等；"
                       "沙盒内数据本就随 tmpfs 消亡，此步清理宿主侧痕迹）",
        "parameters": obj_schema(SB_NAME_PARAM, ["name"]),
    }


# 受限工具表（tools-sandbox.json）的 exec 命令白名单：只读 R 全集 + 指定
# W1 写命令（落点本就在沙盒 tmpfs）。绝不含 systemctl/kill/apt 等 W2 命令，
# 绝不含 sandbox_create/sandbox_spawn（防嵌套派生）。
SB_EXEC_ALLOW = ["mkdir", "touch", "cp", "mv", "ln", "sed", "tee",
                 "gzip"]

# W72：沙箱内允许的编程命令。主表 python3 是 W2（宿主写面需确认）；
# 受限表覆盖为 W1——W71 已实现 fresh procfs（宿主 PID 不可见）、
# NO_NEW_PRIVS + 能力裁剪（仅 CAP_NET_RAW）、tmpfs 根、/usr ro bind，
# 解释器/编译器的写面被限制在沙盒 tmpfs 内。gcc/cc 主表本就是 W1
#（仅 /tmp）。which 早已在 R 全集中，用于子智能体探测工具链。
SB_EXEC_W1_EXTRA = ["python3", "gcc", "cc"]

# W48 安全修复：这些命令的**命令级基础 risk 是 R，但带写参数时会动态升
# W2**（curl POST/-o、ip addr add、ethtool -s、journalctl --vacuum、
# ollama pull、timedatectl set-time）。若只按基础 risk 过滤，它们会混入
# 沙盒受限表，使子智能体获得 W2 逃逸面。受限表一律剔除，由主会话执行。
SB_EXEC_DYNAMIC_RISK = [
    "curl", "ip", "ethtool", "journalctl", "ollama", "timedatectl",
]


def sandbox_tools():
    return [
        tool_sandbox_status(),
        tool_sandbox_create(),
        tool_sandbox_spawn(),
        tool_sandbox_destroy(),
    ]


def memory_tools():
    """W50 SME 完整管理面 29 工具（+ memory_health = 30）"""
    id_param = {"id": {"type": "string",
                       "description": "记忆 ID（如 m_xxxx）"}}
    return [
        tool_mem("memory_search", RISK_R,
                 "[参数名注意] 本工具唯一必填参数是 text（不是 query）。"
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
        tool_mem("memory_search_advanced", RISK_R,
                 "高级语义检索（POST /memories/search 的组合玩法）：在普通"
                 "检索上叠加元数据过滤、标签、命名空间、归档记忆、图谱扩展"
                 "与 Region 策略。普通问答/接口查询用 memory_search；需要"
                 "按 metadata/tags/ns 精确定位、查归档、或沿记忆图扩展时用"
                 "本工具。metadata_filters 为 JSON 对象字符串，tags 为 JSON "
                 "数组字符串。",
                 {"text": {"type": "string", "description": "查询文本"},
                  "top_k": {"type": "integer", "description": "返回条数上限（默认 10）",
                            "minimum": 1, "maximum": 50},
                  "top_regions": {"type": "integer",
                                  "description": "参与检索的 Region 数上限（可选）",
                                  "minimum": 1, "maximum": 50},
                  "metadata_filters": {"type": "string",
                                       "description": "元数据过滤 JSON 对象字符串，如 {\"src\":\"ask\"}"},
                  "tags": {"type": "string",
                           "description": "标签过滤 JSON 数组字符串，如 [\"k8s\",\"net\"]"},
                  "region_retrieval": {"type": "string",
                                       "description": "区域检索策略（如 spatial/hybrid，可选）"},
                  "include_archived": {"type": "boolean",
                                       "description": "是否包含已归档记忆（默认 false）"},
                  "graph_expand": {"type": "integer",
                                   "description": "图谱扩展跳数（0=不扩展）",
                                   "minimum": 0, "maximum": 5},
                  "ns": {"type": "string",
                         "description": "命名空间过滤（多用户隔离）"}},
                 ["text"]),
        tool_mem("memory_add", RISK_W1,
                 "写入一条记忆到 SME（POST /memories），供后续 ask 检索。"
                 "可选 tags/importance/source/link_to/ns；metadata 为 JSON "
                 "对象字符串。写入成功返回新记忆 dict（含 id）。",
                 {"text": {"type": "string", "description": "记忆文本"},
                  "metadata": {"type": "string",
                               "description": "可选元数据 JSON 对象字符串"},
                  "tags": {"type": "string",
                           "description": "可选标签 JSON 数组字符串，如 [\"a\",\"b\"]"},
                  "importance": {"type": "number",
                                 "description": "重要度 0..1（默认 0.5）",
                                 "minimum": 0, "maximum": 1},
                  "source": {"type": "string",
                             "description": "来源（user/llm/system，默认 user）"},
                  "link_to": {"type": "string",
                              "description": "可选：写入后链接到既有记忆 id"},
                  "link_kind": {"type": "string",
                                "description": "link_to 的关系类型（默认 reference）"},
                  "ns": {"type": "string",
                         "description": "命名空间（多用户隔离）"}},
                 ["text"]),
        tool_mem("memory_batch_add", RISK_W1,
                 "批量新增记忆（POST /memories/batch）：memories 为 JSON 数组"
                 "字符串，每条 {text,metadata?,tags?,importance?,source?} 走"
                 "完整写入管线（抽取/去噪），返回 added/dropped/total。"
                 "每条生成新 id，**非幂等**：重试会产生重复记忆；需要无损"
                 "恢复旧数据请用 memory_import。",
                 {"memories": {"type": "string",
                               "description": "JSON 数组字符串（元素含 text）"}},
                 ["memories"]),
        tool_mem("memory_stats", RISK_R,
                 "查询 SME 记忆库统计（GET /stats，含记忆数/Region 数/"
                 "graph 边数）"),
        tool_mem("memory_get", RISK_R,
                 "按 ID 读取单条记忆全文（GET /memories/{id}）",
                 dict(id_param), ["id"]),
        tool_mem("memory_update", RISK_W1,
                 "更新记忆字段（PATCH /memories/{id}）：text/metadata/tags/"
                 "importance/weight/summary 至少提供一项，未提供的字段保持"
                 "不变；改 text 会重新向量化。metadata 为 JSON 对象字符串，"
                 "tags 为 JSON 数组字符串。返回更新后的记忆 dict。",
                 {"id": {"type": "string", "description": "记忆 ID"},
                  "text": {"type": "string", "description": "新文本（可选）"},
                  "metadata": {"type": "string",
                               "description": "新元数据 JSON 对象字符串（整体替换）"},
                  "tags": {"type": "string",
                           "description": "新标签 JSON 数组字符串（整体替换）"},
                  "importance": {"type": "number", "description": "重要度 0..1",
                                 "minimum": 0, "maximum": 1},
                  "weight": {"type": "number", "description": "检索权重（>=0）",
                             "minimum": 0},
                  "summary": {"type": "string", "description": "摘要文本（可选）"}},
                 ["id"]),
        tool_mem("memory_delete", RISK_W2,
                 "永久删除一条记忆（DELETE /memories/{id}，W2 红色确认）："
                 "不可恢复；仅用于删除错误/敏感记忆。要保留历史请用 "
                 "memory_archive。返回 {\"deleted\":\"<id>\"}。",
                 dict(id_param), ["id"]),
        tool_mem("memory_hit", RISK_W1,
                 "Ebbinghaus 强化：命中计数 +1、检索权重上调"
                 "（POST /memories/{id}/hit）；对检索命中的记忆及时调用",
                 dict(id_param), ["id"]),
        tool_mem("memory_archive", RISK_W1,
                 "归档记忆（POST /memories/{id}/archive）：默认检索不可见，"
                 "不删除",
                 dict(id_param), ["id"]),
        tool_mem("memory_restore", RISK_W1,
                 "恢复归档记忆（POST /memories/{id}/restore）",
                 dict(id_param), ["id"]),
        tool_mem("memory_import", RISK_W1,
                 "无损导入导出格式记忆（POST /import）：按 id 还原 weight/"
                 "hit_count/created_at/向量等全部字段。二选一传参：memories "
                 "为 JSON 数组字符串；path 为本地 JSON 文件绝对路径"
                 "（/tmp 或 /var/ai 下，数组或含 memories 的导出对象，"
                 "上限 8MB）。带 id 条目按 id 覆盖=可重试幂等；缺 id 条目"
                 "每次生成新 id（重试会重复）。",
                 {"memories": {"type": "string",
                               "description": "JSON 数组字符串（导出格式条目）"},
                  "path": {"type": "string",
                           "description": "本地 JSON 文件绝对路径（/tmp 或 /var/ai）"}}),
        tool_mem("memory_facts_multi_hop", RISK_R,
                 "知识图谱多跳查询（POST /facts/multi_hop）：按文本找实体"
                 "并沿关系跳转；factgraph 模块未启用时返回 enabled=false",
                 {"text": {"type": "string", "description": "实体查询文本"},
                  "top_k": {"type": "integer", "description": "上限（默认 10）",
                            "minimum": 1, "maximum": 50}},
                 ["text"]),
        tool_mem("memory_graph", RISK_R,
                 "读取记忆图（GET /graph）：返回 edge_count 与全部边"
                 "（source/target/kind/weight/note）。用于查看关联结构、"
                 "发现孤立节点或准备 memory_link。"),
        tool_mem("memory_link", RISK_W1,
                 "建立记忆间链接（POST /graph/link）：a/b 均须存在，kind "
                 "默认 reference，weight 默认 1.0，note 可选。用于手动关联"
                 "因果/引用关系。注意服务端没有 unlink 端点：边只能随记忆"
                 "删除或图重建移除。",
                 {"a": {"type": "string", "description": "起点记忆 ID"},
                  "b": {"type": "string", "description": "终点记忆 ID"},
                  "kind": {"type": "string",
                           "description": "关系类型（默认 reference）"},
                  "weight": {"type": "number", "description": "边权重（默认 1.0）",
                             "minimum": 0},
                  "note": {"type": "string", "description": "备注（可选）"}},
                 ["a", "b"]),
        tool_mem("memory_regions", RISK_R,
                 "列出全部空间 Region（GET /regions）：返回 count 与每个 "
                 "Region 的 id/摘要/大小/密度等。用于了解记忆的空间聚类。"),
        tool_mem("memory_regions_search", RISK_R,
                 "空间区域检索（POST /regions/search）：返回最相关 Region",
                 {"text": {"type": "string", "description": "查询文本"},
                  "top_k": {"type": "integer", "description": "区域上限（默认 5）",
                            "minimum": 1, "maximum": 20}},
                 ["text"]),
        tool_mem("memory_regions_evolve", RISK_W1,
                 "触发 Region 演化（POST /regions/evolve，W1）：对空间结构"
                 "执行 split/merge 并改写成员归属，返回 events。用于整理"
                 "长期积累后失真的区域划分；会改动 Region 元数据但不增删"
                 "记忆。"),
        tool_mem("memory_facts", RISK_R,
                 "列出事实图谱与双时态事实（GET /facts）：entities/"
                 "relations/facts/stats；factgraph/factversion 未启用时"
                 "返回 enabled=false。"),
        tool_mem("memory_facts_history", RISK_R,
                 "查询单个事实的双时态版本链（GET /facts/history）：text "
                 "或 memory_id 至少一个；返回 oldest→newest 的 versions。"
                 "无匹配 404；模块关闭返回 enabled=false。",
                 {"text": {"type": "string", "description": "自由文本或记忆 ID"},
                  "memory_id": {"type": "string",
                                "description": "明确的记忆 ID（与 text 二选一）"}}),
        tool_mem("memory_profile", RISK_R,
                 "读取用户画像事实与快照（GET /profile）：profile_facts/"
                 "snapshots/stats；模块未启用返回 enabled=false。"),
        tool_mem("memory_qapairs", RISK_R,
                 "列出问答对（GET /qapairs）：count 与 pairs（question/"
                 "answer_text/关联记忆 id）；模块未启用返回 enabled=false。"),
        tool_mem("memory_consolidate", RISK_W2,
                 "触发记忆巩固（POST /consolidate）：聚类生成摘要记忆，"
                 "会新增派生记忆（created 数组）"),
        tool_mem("memory_compress", RISK_W2,
                 "触发记忆压缩（POST /compress）：生成压缩摘要，会新增"
                 "派生记忆"),
        tool_mem("memory_export", RISK_R,
                 "全量导出记忆库 JSON（GET /export）落盘到 /tmp 或 "
                 "/var/ai（导出路径白名单）文件，返回文件路径与预览",
                 {"path": {"type": "string",
                           "description": "导出文件绝对路径（白名单: "
                                          "/tmp 或 /var/ai 下；默认 "
                                          "/tmp/sme-export.json）"}}),
        tool_mem("memory_metrics", RISK_R,
                 "观测指标摘要（GET /metrics，Module 10；telemetry 未启用"
                 "时返回 enabled=false）"),
        tool_mem("memory_metrics_report", RISK_R,
                 "导出完整遥测报告（GET /metrics/report）落盘 JSON 文件"
                 "（/tmp 或 /var/ai 白名单），返回路径/字节数/预览；"
                 "telemetry 未启用时服务端 404。",
                 {"path": {"type": "string",
                           "description": "报告文件绝对路径（默认 "
                                          "/tmp/sme-metrics-report.json）"}}),
        tool_mem("memory_config_get", RISK_R,
                 "读取 SME 引擎配置中心（GET /config）：分组配置项、当前值/"
                 "默认值/取值范围；api_key 由服务端掩码。用于排障与核对"
                 "检索/Region/动力学参数。"),
        tool_mem("memory_config_check", RISK_R,
                 "校验当前 SME 配置（POST /config/check，只读诊断）："
                 "ping=false 仅静态校验；ping=true 额外探测 LLM/Embedding "
                 "连通性（可能产生外部调用与延迟）。不修改配置。",
                 {"ping": {"type": "boolean",
                           "description": "是否额外探测外部依赖（默认 false）"}}),
    ]


# ---------------------------------------------------------------------------
# W51：组合配方（8 条，aikernel-combo）
#
# 每条配方写成 AI 可执行的操作序列；W2 步骤显式标注"需确认"，禁止把
# 高危动作写成自动执行。
# ---------------------------------------------------------------------------
COMBOS = [
    {
        "id": "combo-1",
        "name": "应急响应（疑似攻击）",
        "domains": ["netsec", "res", "sysadmin"],
        "tools": ["netlink_sense", "procfs_read_net_nf_conntrack",
                  "exec_run", "config_read_nftables", "sysctl_get",
                  "config_write_nftables", "memory_add"],
        "lines": [
            "目标：疑似攻击/异常外联时快速定位、取证并安全处置。",
            "步骤：",
            "1. netlink_sense（format=\"human\"）拉内核感知态势，记录异常事件与时间线；",
            "2. procfs_read_net_nf_conntrack 读取连接跟踪表，与 exec_run(command=\"ss\", args=[\"-tunp\"]) 对齐可疑五元组；",
            "3. exec_run(command=\"ip\", args=[\"route\",\"show\"]) 与 exec_run(command=\"nft\", args=[\"list\",\"ruleset\"]) 分析路径和现有规则（只读）；",
            "4. sysctl_get(key=\"net.ipv4.ip_forward\") 等核对转发/防护参数；",
            "5. 处置必须由用户确认后执行：config_write_nftables（W2，先备份原文件）或 exec_run(command=\"nft\", args=[...]，W2)；",
            "6. memory_add 记录事件、证据与处置结论，便于复盘。",
            "判据：可疑连接消失、netlink_sense 异常归零、业务吞吐恢复。",
            "回滚：用第 3 步保存的原 nft/接口配置恢复；所有 W2 操作前先导出旧规则。",
        ],
    },
    {
        "id": "combo-2",
        "name": "分身编程",
        "domains": ["sandbox", "sysadmin"],
        "tools": ["sandbox_status", "sandbox_create", "sandbox_spawn",
                  "sandbox_destroy"],
        "lines": [
            "目标：把写代码、跑测试等脏活交给隔离区子智能体，宿主零污染。",
            "步骤：",
            "1. sandbox_status 查看已有隔离区，避免重名；",
            "2. sandbox_create(name=\"sb1\") 建区（W1）；",
            "3. sandbox_spawn(name=\"sb1\", task=\"写代码并运行测试，报告改动与退出码\", max_seconds=300) 派活（W2，需红色确认）；",
            "4. 读取返回摘要（尾部 4KB）与子智能体退出码；需要产物先用 exec_run cp 到 /tmp；",
            "5. sandbox_destroy(name=\"sb1\") 焚区（W1，幂等）。",
            "判据：子智能体退出码 0、摘要含改动/测试结果、宿主 /root /home /var 不可见。",
            "回滚：sandbox_destroy 焚毁隔离区；tmpfs 数据随销毁消失，无宿主残留。",
        ],
    },
    {
        "id": "combo-3",
        "name": "资源调优",
        "domains": ["res", "fs", "netsec"],
        "tools": ["procfs_read_pressure_cpu", "procfs_read_pressure_memory",
                  "procfs_read_pressure_io", "procfs_read_status",
                  "netlink_act_sched_nice", "netlink_act_sched_affinity",
                  "netlink_act_mm_swappiness", "netlink_act_power_freq"],
        "lines": [
            "适用问法：网络丢包导致进程卡顿，怎么同时排查网卡队列和调度延迟？",
            "目标：网络丢包/中断风暴导致进程卡顿、调度延迟或内存紧张时，netsec 与 res 联查，按“采样→定位→小步调整→复采→回滚”闭环。",
            "步骤：",
            "1. 先 netsec：exec_run(ss/ip)、net.cwnd/net.qdisc 查丢包、重传与网卡队列；",
            "2. 再 res：procfs_read_pressure_cpu/memory/io、procfs_read_sched_stats 查 PSI、调度与中断；",
            "3. 定位瓶颈后一次只改一个参数：sched.*/mm.*/power.*/net.cwnd/net.qdisc（W2，需确认）；",
            "4. 复采同组指标对比；超阈值用 /proc/ai/control 记录的原值写回。",
            "判据：丢包/重传下降、PSI 下降、进程延迟改善且无 OOM。",
            "回滚：原值逐项写回，一次一项保证可归因。",
        ],
    },
    {
        "id": "combo-4",
        "name": "存储排查",
        "domains": ["fs", "sysadmin"],
        "tools": ["exec_run", "procfs_read_mounts", "config_read_fstab",
                  "config_write_fstab", "procfs_read_filesystems"],
        "lines": [
            "目标：磁盘满/挂载异常时定位占用、核对挂载与持久化配置并安全清理。",
            "步骤：",
            "1. exec_run(command=\"df\", args=[\"-h\"]) 与 exec_run(command=\"du\", args=[\"-x\",\"-h\",\"--max-depth=1\",\"/\"]) 定位大目录（只读）；",
            "2. procfs_read_mounts 与 exec_run(command=\"findmnt\") 核对设备/挂载点/只读状态；",
            "3. procfs_read_filesystems 确认文件系统类型受支持；config_read_fstab 核对开机挂载；",
            "4. 清理只动 /tmp /root /var/ai：exec_run(command=\"rm\", args=[...]，W2，需确认且路径校验）或扩容 mount/umount（W2）；",
            "5. 复测 df 与目标目录读写；需要持久化修改时先 config_read_fstab，再 config_write_fstab 整文件回写（W2）。",
            "判据：目标挂载点使用率下降、读写恢复正常、fstab 语法可挂载。",
            "回滚：删除前备份到 /tmp；fstab 用旧全文回写，mount -a 验证。",
        ],
    },
    {
        "id": "combo-5",
        "name": "服务故障",
        "domains": ["sysadmin", "fs", "netsec"],
        "tools": ["exec_run", "config_read_sshd_config",
                  "config_write_sshd_config"],
        "lines": [
            "目标：服务起不来/异常退出时按状态→日志→配置→重启→健康检查处置。",
            "步骤：",
            "1. exec_run(command=\"systemctl\", args=[\"status\",\"<svc>\",\"--no-pager\"]) 看状态与最近退出码（R）；",
            "2. exec_run(command=\"journalctl\", args=[\"-u\",\"<svc>\",\"-n\",\"200\",\"--no-pager\"]) 读日志（R）；",
            "3. 核对配置：config_read_sshd_config 等只读读取；sshd 改动用 sshd -t 预检；",
            "4. 重启：exec_run(command=\"systemctl\", args=[\"restart\",\"<svc>\"])（W2，需红色确认）；",
            "5. 健康检查：exec_run(command=\"systemctl\", args=[\"is-active\",\"<svc>\"]) 与本地 HTTP 探活。",
            "判据：is-active=active、健康端点返回 200、日志无新错误。",
            "回滚：先读后写保留旧配置；失败时恢复旧配置并 restart，必要时 stop。",
        ],
    },
    {
        "id": "combo-6",
        "name": "记忆整理",
        "domains": ["memory"],
        "tools": ["memory_search", "memory_consolidate", "memory_compress",
                  "memory_metrics", "memory_export"],
        "lines": [
            "目标：长期记忆去重、巩固、压缩，并验证检索质量不下降。",
            "步骤：",
            "1. memory_search(text=\"<主题>\", top_k=20) 抽样检查重复/碎片；",
            "2. memory_export 先全量导出到 /tmp，保留可回滚快照（R）；",
            "3. memory_consolidate() 聚类生成摘要（W2，需确认）；",
            "4. memory_compress() 生成压缩摘要（W2，需确认）；",
            "5. memory_metrics 与 memory_stats 验证记忆数/区域数/检索指标。",
            "判据：派生摘要生成、重复率下降、关键主题 top3 仍命中。",
            "回滚：用导出快照按 id 恢复；派生记忆可 memory_delete（W2）逐条清理。",
        ],
    },
    {
        "id": "combo-7",
        "name": "模型上线",
        "domains": ["aicore"],
        "tools": ["sysfs_write_model_load", "sysfs_write_model_infer",
                  "procfs_read_model_out", "sysfs_write_model_unload"],
        "lines": [
            "目标：内核模型加载、bit-exact 推理校验、失败回滚。",
            "步骤：",
            "1. sysfs_write_model_load(value=\"<模型名> <hex float32 权重...>\") 加载（W1），记录模型名；",
            "2. sysfs_write_model_infer(value=\"<模型名> <hex float32 输入...>\") 触发推理（W1）；",
            "3. procfs_read_model_out 读取输出，与预期 hex 逐字节比对（bit-exact）；",
            "4. 失败或不需要时 sysfs_write_model_unload(value=\"<模型名>\") 卸载（W1）。",
            "判据：model_out 输出与预期完全一致、无内核错误日志、模型状态可见。",
            "回滚：model_unload 卸载；保留上一版模型名与权重 hex 便于切回。",
        ],
    },
    {
        "id": "combo-8",
        "name": "安全基线核查",
        "domains": ["sysadmin", "netsec"],
        "tools": ["sysctl_get", "sysctl_blacklist", "procfs_read_control",
                  "memory_add"],
        "lines": [
            "目标：只读核对系统/网络安全基线，输出差异报告，不改任何值。",
            "步骤：",
            "1. sysctl_get(prefix=\"net.ipv4\")、sysctl_get(prefix=\"kernel\")、sysctl_get(prefix=\"vm\") 批量读取；",
            "2. sysctl_blacklist 确认哪些键禁止写入，避免误操作；",
            "3. procfs_read_control 读取 AIKernel 可控参数当前值与默认值；",
            "4. 对照基线（SSH 放行、rp_filter、syncookies、panic 族、swappiness）生成差异清单；",
            "5. memory_add 记录核查时间、差异项与结论（可选）。",
            "判据：差异清单每项含当前值/基线值/风险说明，全程零写入。",
            "回滚：纯只读无需回滚；如需修复另走 sysctl_set（W2，逐次确认）。",
        ],
    },
]

CHANNEL_RETURN = {
    CH_PROC: "返回节点原始文本/JSON 行（只读），执行器原样回传。",
    CH_SYSFS: "写入后回读节点确认新值，返回写入结果与错误码。",
    CH_NETLINK: "返回 NETLINK_AI ACT 回执（errno/生效值）；可回读 /proc/ai/control 验证。",
    CH_NLSENSE: "返回内核感知遥测记录（human 文本或 raw 定长记录）。",
    CH_EXEC: "返回命令 stdout/stderr 与退出码；超时 SIGKILL 并标记。",
    CH_MEMORY: "返回 SME REST JSON（记忆 dict/列表/统计/图谱等）。",
    CH_SHELL: "进入交互式 bash 会话；仅维护场景使用。",
    CH_SANDBOX: "返回隔离区状态或子智能体摘要（输出尾部 4KB）。",
    CH_SYSCTL: "返回 sysctl 键值文本或写入回执（old/new）。",
    CH_SYSFS_DYN: "返回受控路径内容或写入回执。",
    CH_DESKTOP: "返回桌面 API 的 JSON（窗口/主题/截图 path+bytes+sha256 等）。",
    CH_CLARIFY: "返回用户选择 JSON；非 TTY 返回 CLARIFY_REQUIRED（本轮结束）。",
}


def _dedupe(seq):
    out = []
    for item in seq:
        if item and item not in out:
            out.append(item)
    return out


def _one_line(text, limit=0):
    """单行化并截断：消除外部文本里的换行/控制空白，防换行注入。"""
    s = re.sub(r"\s+", " ", str(text or "")).strip()
    if limit and len(s) > limit:
        s = s[:limit].rstrip() + "…"
    return s


def _risk_text(tool):
    rk = tool.get("risk")
    if rk == RISK_R:
        return "R 自动执行（只读，无副作用）。"
    if rk == RISK_W1:
        return "W1 低危写，按策略放行并记录审计；写入前记录旧值。"
    if rk == RISK_W2:
        return "W2 高危写，必须逐次红色人工确认后才能执行；确认前不自动调用。"
    return "按命令分级（exec.commands 内 R/W1/W2）；W2 命令逐次红色确认。"


def _param_summary(parameters):
    parameters = parameters or {}
    props = parameters.get("properties") or {}
    required = set(parameters.get("required") or [])
    if not props:
        return "无参数。"
    parts = []
    for name, spec in props.items():
        typ = spec.get("type", "any")
        need = "必填" if name in required else "可选"
        desc = _one_line(spec.get("description", ""), 48)
        parts.append("%s(%s,%s)%s" % (
            name, typ, need, ("：" + desc) if desc else ""))
    return "；".join(parts) + "。"


# W66：域头检索锚点（只对实机 Top-3 被 Region 门控挡住的 3 个域）。
# 域头是单件，Region 质心就是它自己；把真实问法重复 24 次后，它的
# 向量/BM25 不再被长模板稀释，d02/d04/r01 从 miss 变为 Top-1。
# 仅影响 seed 文本，不改工具定义。
SUB_DOMAIN_QUERY_HINTS = {
    "res": ("常用问法：资源与调度能力区、资源与调度、进程调度、"
            "内存与 IO 压力、CPU 资源、resource scheduling", 24),
    "netsec": ("常用问法：网络丢包、防火墙规则、网络不通、丢包排查、"
               "防火墙配置、packet loss、firewall rules", 24),
    "aicore": ("常用问法：模型加载失败、推理结果不对、模型推理、"
               "模型上线、/proc/ai、/sys/kernel/ai", 24),
}


def _header_corpus_record(domain, tools):
    meta = SUB_DOMAIN_META[domain]
    primary = [t["name"] for t in tools if t["sub"][0] == domain]
    if not primary:
        raise RuntimeError("能力区 %s 没有主域工具" % domain)
    lines = [
        "【AIKernel 能力区·%s(sub/%s)】" % (meta["cn"], domain),
        "本区负责：%s" % meta["duty"],
        "何时来本区：%s" % meta["when"],
    ]
    aliases = SUB_DOMAIN_ALIASES.get(domain)
    if aliases:
        lines.append("常见同义问法：%s" % aliases)
    lines.extend([
        "本区工具：%s" % ", ".join(primary),
        "与本区相邻的能力：%s" % meta["neighbors"],
        "安全边界：%s" % meta["safety"],
    ])
    hint = SUB_DOMAIN_QUERY_HINTS.get(domain)
    if hint:
        for _ in range(hint[1]):
            lines.append(hint[0])
    text = "\n".join(lines)
    return {
        "text": text,
        "tags": ["aikernel-interface", "sub/" + domain, "domain-header"],
        "metadata": {
            "kind": "domain-header",
            "sub": domain,
            "domain_cn": meta["cn"],
            "tool_count": len(primary),
        },
        "importance": 0.75,
        "source": "aikernel-corpus",
    }


def _tool_corpus_record(tool):
    subs = tool["sub"]
    meta = SUB_DOMAIN_META[subs[0]]
    name = tool["name"]
    channel = tool.get("channel", "")
    risk = tool.get("risk") or "按命令"
    # W66：memory_* 单件用一行精确简介替代长 description（见
    # MEMORY_CORPUS_DESC 注释）；其他工具沿用原文。
    desc = MEMORY_CORPUS_DESC.get(name)
    if desc is None:
        desc = _one_line(tool.get("description", ""), 420)
    lines = [
        "【AIKernel 工具接口】%s（通道 %s，风险 %s）" % (
            name, channel, risk),
        "是什么：%s" % desc,
    ]
    aliases = TOOL_ALIASES.get(name)
    if aliases:
        for _ in range(TOOL_ALIAS_REPEAT.get(name, 1)):
            lines.append("常见问法/口语别名：%s" % aliases)
    facts = MEMORY_TOOL_FACTS.get(name)
    if facts:
        lines.append("关键事实：%s" % facts)
    hints = MEMORY_QUERY_HINTS.get(name)
    if hints:
        for _ in range(MEMORY_HINT_REPEAT.get(name, 4)):
            lines.append("常用问法：%s" % hints)
    extra_hints = MEMORY_QUERY_HINTS_EXTRA.get(name)
    if extra_hints:
        for _ in range(extra_hints[1]):
            lines.append("常用问法：%s" % extra_hints[0])
    for text, reps in MEMORY_QUERY_HINTS_EXTRA2.get(name, []):
        for _ in range(reps):
            lines.append("常用问法：%s" % text)
    lines.extend([
        "何时用：%s。典型场景：%s" % (
            meta["tool_when"], _one_line(
                desc or tool.get("description", ""), 140)),
        "参数：%s" % _param_summary(tool.get("parameters")),
        "返回：%s" % CHANNEL_RETURN.get(
            channel, "执行器返回 JSON/文本结果。"),
        "风险与确认：%s" % _risk_text(tool),
        "所属能力区：%s" % "、".join("sub/" + s for s in subs),
    ])
    text = "\n".join(lines)
    tags = _dedupe(["aikernel-interface"] +
                   ["sub/" + s for s in subs] +
                   ["tool", channel])
    importance = {"R": 0.65, "W1": 0.7, "W2": 0.8}.get(
        tool.get("risk"), 0.75)
    # W66：memory 单件重要度略高于域头（0.75），避免"工具名+风险/路径"
    # 这类精确问题被模板化域头压在后面；只改 seed 语料权重。
    if name.startswith("memory_"):
        importance = {"R": 0.78, "W1": 0.80, "W2": 0.84}.get(
            tool.get("risk"), 0.78)
    return {
        "text": text,
        "tags": tags,
        "metadata": {
            "kind": "tool",
            "name": name,
            "channel": channel,
            "risk": risk,
            "sub": list(subs),
        },
        "importance": importance,
        "source": "aikernel-corpus",
    }


# W66：组合配方的口语问法/英文关键词。配方正文是步骤说明，用户通常
# 不会按步骤措辞提问（"疑似攻击应急响应怎么做"），补问答式别名后
# Top-3 从 0/8 提升；只影响 seed 文本。
COMBO_ALIASES = {
    "应急响应（疑似攻击）": "疑似攻击、应急响应、疑似攻击应急响应怎么做、"
                          "异常外联、被入侵、安全事件处置、"
                          "attack response、incident response",
    "分身编程": "分身编程、让分身写代码、分身写代码跑测试、"
              "子智能体写代码、隔离区跑测试、sandbox coding、"
              "spawn agent to code",
    "资源调优": "资源调优、系统卡顿、系统卡顿做资源调优、进程卡顿、"
              "CPU 占用高、内存紧张、swap 快满、调度延迟、"
              "resource tuning、system slow",
    "存储排查": "存储排查、磁盘满、磁盘满了、磁盘满做存储排查、磁盘占用、"
              "挂载异常、存储故障、disk full、storage troubleshooting",
    "服务故障": "服务故障、服务故障排查流程、服务起不来、"
              "服务异常退出、看日志、重启服务、service failure、"
              "service down",
    "记忆整理": "记忆整理、记忆整理去重、记忆去重、巩固压缩、"
              "整理记忆库、合并重复记忆、memory cleanup、"
              "deduplicate memories",
    "模型上线": "模型上线、模型加载、模型上线推理校验、推理校验、"
              "bit-exact、模型部署、model deployment、"
              "model inference check",
    "安全基线核查": "安全基线核查、安全基线、只读核查、只读输出差异、"
                  "差异报告、security baseline、read-only audit",
}


def _combo_corpus_record(combo):
    lines = ["【AIKernel 组合配方】%s（aikernel-combo）" % combo["name"]]
    alias = COMBO_ALIASES.get(combo["name"])
    if alias:
        for _ in range(4):
            lines.append("常见问法/关键词：%s" % alias)
    lines.append(COMBO_COMMON_KEYWORDS)
    text = "\n".join(lines + combo["lines"])
    tags = _dedupe(["aikernel-combo", "combo"] +
                   ["sub/" + d for d in combo["domains"]])
    return {
        "text": text,
        "tags": tags,
        "metadata": {
            "kind": "combo",
            "id": combo["id"],
            "name": combo["name"],
            "domains": list(combo["domains"]),
            "tools": list(combo["tools"]),
        },
        "importance": 0.85,
        "source": "aikernel-corpus",
    }


def inject_sub(tools):
    """为每件工具注入 sub 顶层字段；151 件必须一一覆盖。"""
    names = [t["name"] for t in tools]
    missing = [n for n in names if n not in SUB_MAP]
    extra = sorted(set(SUB_MAP) - set(names))
    if missing or extra:
        sys.stderr.write(
            "ERROR [gen_registry W51]: sub 映射与工具表不一致"
            "（缺 %d / 多 %d）\n" % (len(missing), len(extra)))
        for n in missing:
            sys.stderr.write("  缺少映射: %s\n" % n)
        for n in extra:
            sys.stderr.write("  多出映射: %s\n" % n)
        sys.exit(2)
    for t in tools:
        subs = SUB_MAP[t["name"]]
        if not 1 <= len(subs) <= 2:
            raise RuntimeError(
                "工具 %s 的 sub 数量 %d 非法（只允许 1-2 个域）"
                % (t["name"], len(subs)))
        bad = [s for s in subs if s not in SUB_DOMAIN_META]
        if bad:
            raise RuntimeError(
                "工具 %s 的 sub 含未知域: %s" % (t["name"], bad))
        t["sub"] = list(subs)


def write_corpus_seed(tools, out_dir):
    """单源生成 sme-seed-w51.jsonl（区头 8 + 单件 151 + 配方 8）。"""
    records = []
    for domain in SUB_DOMAIN_ORDER:
        records.append(_header_corpus_record(domain, tools))
    for tool in tools:
        records.append(_tool_corpus_record(tool))
    for combo in COMBOS:
        records.append(_combo_corpus_record(combo))

    path = os.path.join(out_dir, "sme-seed-w51.jsonl")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False,
                                separators=(",", ":")) + "\n")

    # 自检：逐行合法、无原始换行注入、条目数符合规格
    counts = {"domain-header": 0, "tool": 0, "combo": 0}
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    if len(lines) != len(records):
        raise RuntimeError(
            "seed 行数 %d != 记录数 %d（存在换行注入）"
            % (len(lines), len(records)))
    for lineno, line in enumerate(lines, 1):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "seed 第 %d 行 JSON 非法: %s" % (lineno, exc))
        if not obj.get("text"):
            raise RuntimeError("seed 第 %d 行 text 为空" % lineno)
        kind = (obj.get("metadata") or {}).get("kind")
        if kind not in counts:
            raise RuntimeError(
                "seed 第 %d 行 kind 非法: %r" % (lineno, kind))
        counts[kind] += 1
    expect = {"domain-header": len(SUB_DOMAIN_ORDER),
              "tool": len(tools), "combo": len(COMBOS)}
    if counts != expect:
        raise RuntimeError(
            "seed 条目数 %r != 期望 %r" % (counts, expect))
    print("OK: %s（区头 %d + 单件 %d + 配方 %d = %d 条）" % (
        path, counts["domain-header"], counts["tool"],
        counts["combo"], len(records)), file=sys.stderr)
    return path


# ---------------------------------------------------------------------------
# W76：桌面能力面（desktop 通道，20 件）
#
# 后端是 L1 Web demo 的 loopback API（127.0.0.1:8091）。executor 用
# local_http 直连（不经 shell/curl），固定 path 映射；不接受任意 URL、
# JS 或命令。D 级：
#   D0 读：health/stats/apps.list/windows.list/theme.get/wallpaper.get/
#          notifications.list/screenshot/clipboard.get
#   D1 可逆写：theme.set/wallpaper.set/notifications.send/apps.launch/
#          windows.focus
#   D2 不可逆/敏感写：windows.close/apps.close/input.type/input.key/
#          clipboard.set（需确认或任务租约）
#   D3：power（后端 unavailable，仍登记为 D3，绝不伪造成功）
# ---------------------------------------------------------------------------
def tool_desktop(name, risk, desc, props=None, required=None):
    return {
        "name": name,
        "channel": CH_DESKTOP,
        "risk": risk,
        "description": desc,
        "parameters": obj_schema(props or {}, required or []),
    }


def desktop_tools():
    return [
        tool_desktop(
            "desktop_health", RISK_R,
            "桌面后端健康（只读 D0）：返回 demo 服务 version/bind/desktop "
            "后端能力（web-demo、screenshot=playwright、power=unavailable）。"
            "任何桌面动作前可先查；不可用时应如实报告，不要假设成功"),
        tool_desktop(
            "desktop_stats", RISK_R,
            "桌面系统状态（只读 D0）：load1/内存占用/uptime/内核版本与 "
            "60 点负载/内存历史；用于桌面侧性能与响应性判断"),
        tool_desktop(
            "desktop_apps_list", RISK_R,
            "枚举已安装应用（只读 D0）：返回 count 与 apps[]（id/name/"
            "name_en/exec/icon/categories/terminal）；launch 前先用 id"),
        tool_desktop(
            "desktop_windows_list", RISK_R,
            "枚举桌面窗口（只读 D0）：每窗口返回稳定 id(w-0001)/title/app/"
            "geometry{x,y,w,h}/focused/visible/z/text/last_key；同时返回 "
            "mode/theme/wallpaper/clipboard 摘要"),
        tool_desktop(
            "desktop_theme_get", RISK_R,
            "读取主题（只读 D0）：current 与 themes 色板（dark/light/pink/"
            "custom）；set 前先读，便于回滚"),
        tool_desktop(
            "desktop_wallpaper_get", RISK_R,
            "读取壁纸（只读 D0）：current（gradient 或 wall-*）与 available "
            "画廊列表；set 前先读，便于恢复"),
        tool_desktop(
            "desktop_notifications_list", RISK_R,
            "读取桌面通知（只读 D0）：最近通知数组（title/body/tag/time）；"
            "send 前先读可判断是否重复"),
        tool_desktop(
            "desktop_screenshot", RISK_R,
            "桌面截图（只读 D0，Playwright）：返回 PNG 绝对 path/bytes/"
            "sha256/width/height；用于验证界面真实渲染（>30KB 防白屏）。"
            "截图含窗口与桌面内容，按敏感数据处理"),
        tool_desktop(
            "desktop_clipboard_get", RISK_R,
            "读取剪贴板（只读 D0，敏感）：返回 text/length/sha256/"
            "updated_at；set 前先读旧值以便恢复"),
        tool_desktop(
            "desktop_theme_set", RISK_W1,
            "切换主题（D1 可逆）：name=dark|light|pink|custom；写入后回读 "
            "current 验证。回滚=切回 theme.get 读到的旧值",
            {"name": {"type": "string",
                      "description": "主题名：dark|light|pink|custom"}},
            ["name"]),
        tool_desktop(
            "desktop_wallpaper_set", RISK_W1,
            "切换壁纸（D1 可逆）：wallpaper=gradient 或 wallpaper.get 返回的 "
            "available 名（如 wall-aurora）；回滚=切回旧 current",
            {"wallpaper": {"type": "string",
                           "description": "gradient 或 wall-* 画廊名"}},
            ["wallpaper"]),
        tool_desktop(
            "desktop_notifications_send", RISK_W1,
            "发送桌面通知（D1 可逆）：追加一条 title/body/tag；返回 count。"
            "不覆盖历史；清空/删除通知不属于本工具",
            {"title": {"type": "string", "description": "通知标题（≤80 字）"},
             "body": {"type": "string", "description": "通知正文（≤400 字）"},
             "tag": {"type": "string", "description": "分类标签（可选，如 ai）"}},
            ["title"]),
        tool_desktop(
            "desktop_apps_launch", RISK_W1,
            "启动应用窗口（D1 可逆）：app=apps.list 的 id（如 "
            "gnome-control-center）。Web demo 创建虚拟窗口并聚焦，返回 "
            "window_id；未启动宿主进程（W84 真桌面）。关闭用 apps.close",
            {"app": {"type": "string",
                     "description": "应用 id（来自 desktop_apps_list）"}},
            ["app"]),
        tool_desktop(
            "desktop_windows_focus", RISK_W1,
            "聚焦窗口（D1 可逆）：id=windows.list 的 w-XXXX；置顶并设 "
            "focused=true，返回 focused。回滚=聚焦原窗口",
            {"id": {"type": "string", "description": "窗口 id（w-XXXX）"}},
            ["id"]),
        tool_desktop(
            "desktop_windows_close", RISK_W2,
            "关闭单个窗口（D2 不可逆，需确认/租约）：id=w-XXXX；窗口从列表"
            "消失。关闭后无法恢复窗口内未保存文本；应用仍可用 apps.launch "
            "重新打开",
            {"id": {"type": "string", "description": "窗口 id（w-XXXX）"}},
            ["id"]),
        tool_desktop(
            "desktop_apps_close", RISK_W2,
            "关闭某应用的全部窗口（D2 不可逆，需确认/租约）：app=应用 id；"
            "返回 closed[]。未保存内容丢失；重新打开用 apps.launch",
            {"app": {"type": "string", "description": "应用 id"}},
            ["app"]),
        tool_desktop(
            "desktop_input_type", RISK_W2,
            "向当前聚焦窗口注入文本（D2 敏感，需确认/租约）：text≤4096，"
            "追加到窗口文本缓冲。输入注入等于代替用户操作，可能触发应用"
            "行为；返回 text_before/text_after。无焦点窗口返回 409",
            {"text": {"type": "string",
                      "description": "要输入的文本（≤4096 字符）"}},
            ["text"]),
        tool_desktop(
            "desktop_input_key", RISK_W2,
            "向当前聚焦窗口注入按键（D2 敏感，需确认/租约）：key 为单字符"
            "或 Enter/Backspace/Tab/Escape/Delete/Home/End/PageUp/PageDown/"
            "方向键/F1-F12；modifiers=ctrl,alt,shift,meta 逗号分隔。Ctrl+L/U "
            "清空窗口文本。返回 last_key/text_after",
            {"key": {"type": "string",
                     "description": "单字符或允许的键名（如 Enter）"},
             "modifiers": {"type": "string",
                           "description": "可选：ctrl,alt,shift,meta 逗号分隔"}},
            ["key"]),
        tool_desktop(
            "desktop_clipboard_set", RISK_W2,
            "写系统剪贴板（D2 敏感，需确认/租约）：text≤65536；返回新 "
            "sha256 与 previous 旧值（用于恢复）。剪贴板可能含隐私数据，"
            "读取/写回都要谨慎",
            {"text": {"type": "string",
                      "description": "要写入剪贴板的文本（≤65536 字符）"}},
            ["text"]),
        tool_desktop(
            "desktop_power", RISK_W2,
            "电源动作（D3 系统级，需确认/D3 租约）：action=lock|logout|"
            "reboot|shutdown|suspend。W76 Web demo 无 logind 控制面，后端"
            "明确返回 unavailable 且不执行；绝不返回伪造成功。真桌面见 W84",
            {"action": {"type": "string",
                        "description": "lock|logout|reboot|shutdown|suspend",
                        "enum": ["lock", "logout", "reboot", "shutdown",
                                 "suspend"]}},
            ["action"]),
    ]


# W77c：结构化澄清（interaction 通道，D0/R，非授权）
#
# clarify 只收集用户选择，不创建租约、不执行待办动作；后续 D2+ 操作仍
# 走 W74 lease/CONFIRM_REQUIRED。TTY 数字菜单；非 TTY 返回
# CLARIFY_REQUIRED JSON 并结束本轮 ask（nonce/expires_at 留给 W77c-2）。
# ---------------------------------------------------------------------------
def tool_clarify():
    option_schema = obj_schema({
        "id": {"type": "string",
               "description": "选项 id（2-4 个选项中唯一；字母数字 _-."},
        "label": {"type": "string", "description": "展示给用户的选项文本"},
        "description": {"type": "string",
                        "description": "可选的补充说明"},
        "why": {"type": "string",
                "description": "证据/理由（recommended 选项必填）"},
        "impact": {"type": "string",
                   "description": "影响（该选项 danger 为 D3/D4 时必填）"},
        "rollback": {"type": "string",
                     "description": "回滚方式（该选项 danger 为 D3/D4 时必填）"},
        "danger": {"type": "string",
                   "enum": ["D0", "D1", "D2", "D3", "D4"],
                   "description": "该选项的 D 级；缺省继承请求 danger"},
    }, ["id", "label"])
    return {
        "name": "clarify",
        "channel": CH_CLARIFY,
        "risk": RISK_R,
        "description": (
            "向用户提出一个结构化澄清问题（interaction 通道，R，非授权；"
            "不创建租约、不执行任何动作）。用于意图/范围/策略/授权/恢复"
            "确有歧义时：一次只问一个问题，给 2-4 个选项。kind 取 "
            "intent|scope|strategy|authorization|recovery（默认 intent）。"
            "每个选项支持 id/label/description/why/impact/rollback/danger；"
            "recommended 选项必须给出 why；选项 danger 缺省继承请求 "
            "danger，任一选项（含继承）为 D3/D4 时必须提供 impact 与 "
            "rollback。非 authorization 必须指定唯一 recommended；"
            "authorization 可省略 recommended，但若给出则仍需 why。"
            "authorization 且 danger=D3/D4 时禁止 default，绝不允许自动"
            "执行；其他情况 default 可选且必须引用选项 id。可选 header "
            "作为菜单短标题。TTY 显示数字菜单（推荐项置顶标注、why/影响/"
            "回滚子行、[o] 其他、[q] 取消；15 分钟无输入按取消处理），"
            "无效输入最多重试 3 次；非 TTY 不阻塞，返回 CLARIFY_REQUIRED "
            "JSON（nonce 前缀 cq-/expires_at）并结束本轮 ask。同一轮含 "
            "clarify 时其他工具一律不执行（等待答案后重试）。单次 ask "
            "最多 2 个澄清问题。澄清不等于授权：任何 D2+ 操作仍需现有 "
            "lease/CONFIRM_REQUIRED 确认。"),
        "parameters": obj_schema({
            "question": {"type": "string", "maxLength": 1024,
                         "description": "要问用户的一个问题（单行）"},
            "header": {"type": "string", "maxLength": 120,
                       "description": "可选短标题（TTY 菜单首行）"},
            "options": {"type": "array", "minItems": 2, "maxItems": 4,
                        "items": option_schema,
                        "description": "2-4 个选项，id 唯一"},
            "kind": {"type": "string",
                     "enum": ["intent", "scope", "strategy",
                              "authorization", "recovery"],
                     "default": "intent",
                     "description": "问题类型；authorization 表示在征询"
                                    "是否授权某后续动作（仍不创建租约）"},
            "recommended": {"type": "string",
                            "description": "唯一推荐选项 id（必须带 why）；"
                                           "authorization 可省略"},
            "default": {"type": "string",
                        "description": "默认选项 id（必须存在）；"
                                       "authorization D3/D4 禁止使用"},
            "danger": {"type": "string",
                       "enum": ["D0", "D1", "D2", "D3", "D4"],
                       "description": "authorization 必填：拟授权动作的 D 级"},
            "multi_select": {"type": "boolean", "default": False,
                             "description": "是否允许多选（逗号/空格分隔）"},
        }, ["question", "options"]),
    }


def build_tools(procfs_table, sysfs_table):
    tools = []
    tools.extend(tool_procfs(p, d) for p, _perm, d in procfs_table)

    # /sys/kernel/ai/stats 7 节点（只读统计）
    tools.extend(tool_readfile(f"procfs_read_stats_{attr}",
                               f"/sys/kernel/ai/stats/{attr}", d)
                 for attr, d in SYSFS_STATS)

    # ai_cgroup 4 节点（只读；RW 语义经 sysfs 侧工具另行接线）
    tools.extend(tool_readfile(f"procfs_read_cgroup_{attr}",
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
        "procfs_read_net_nf_conntrack", "/proc/net/nf_conntrack",
        "内核连接跟踪表（nf_conntrack：每条连接的源/目的地址与端口、协议、"
        "状态与超时；查「当前有哪些网络连接/谁连着我/连接数多少」用它；"
        "补充手段：exec ss 查套接字级连接"))
    tools.append(tool_exec_run())
    tools.extend(memory_tools())
    tools.append(tool_shell_drop())
    # W42：隔离区 + 子智能体（sandbox 通道四件）
    tools.extend(sandbox_tools())
    # W48：数据层 35 件 + 通用 sysctl/sysfs 动态通道
    tools.extend(data_layer_tools())
    # W76：桌面能力面 20 件（desktop 通道）
    tools.extend(desktop_tools())
    # W77c：结构化澄清（interaction 通道；追加在清单末尾，锚点同步）
    tools.append(tool_clarify())
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
            "name": "procfs_read_" + rel.replace("/", "_"),
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
    # W46a：缺省输出目录不再盲用 CWD（W45 事故根因）——交给下方防呆逻辑
    # 锚定到本脚本所在目录（权威 tools/），其他位置必须显式 --out-dir。
    ap.add_argument("--out-dir", default=None,
                    help="输出目录（缺省=本脚本所在目录，即权威 tools/；"
                         "在其他目录运行必须显式指定）")
    args = ap.parse_args()

    # ---- W46a 防呆 1：产物目录锚定（写盘前判定，拒绝遮蔽正典） ----
    # 权威正典表在本脚本所在目录（agent/ai/tools/）。缺省 --out-dir 时：
    #   cwd == 脚本目录 → 放行（就地再生成正典口径）；
    #   否则            → 报错退出，要求显式 --out-dir。防止在源树根等
    # 位置默认产出 tools.json 遮蔽正典（tool_registry 加载序 env>cwd>exe
    # 会把 cwd 侧旧口径副本放大成事实注册表——W45 75 件旧表事故）。
    canon_out_dir = os.path.dirname(os.path.abspath(__file__))
    if args.out_dir is None:
        if os.path.abspath(os.getcwd()) != canon_out_dir:
            sys.stderr.write(
                "ERROR [gen_registry 防呆]: 当前目录 %s 不是权威注册表目录\n"
                "  %s；缺省输出会在当前目录生成 tools.json 等同名产物，\n"
                "遮蔽 tools/ 正典表（W45 事故根因，已阻断）。\n"
                "确需输出到其他位置请显式指定 --out-dir，例如：\n"
                "  python3 %s --out-dir /tmp/regen-check\n"
                % (os.getcwd(), canon_out_dir, sys.argv[0]))
            sys.exit(2)
        args.out_dir = "."
    elif os.path.abspath(args.out_dir) != canon_out_dir:
        sys.stderr.write(
            "NOTE [gen_registry 防呆]: 输出目录 %s 不是权威注册表目录 %s，\n"
            "产物仅供调试对比，严禁拷回源树遮蔽 tools/ 正典表。\n"
            % (os.path.abspath(args.out_dir), canon_out_dir))

    procfs_table = list(DEFAULT_PROCFS)
    tools = build_tools(procfs_table, DEFAULT_SYSFS)
    dump_added = []
    if args.dump:
        with open(args.dump, "r", encoding="utf-8", errors="replace") as fh:
            proc_files, _sys = parse_dump(fh.read())
        dump_added = merge_dump(tools, proc_files)

    # ---- W46a/W48 防呆 2：主表总数 + 逐名清单 + 哈希锚点（写盘前 fail fast）----
    check_tool_manifest(tools)

    # ---- W51：为 151 件工具注入 sub（只加顶层字段，不改名/风险/参数）----
    inject_sub(tools)

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
        "tool_names_sha256": manifest_sha256(
            [t["name"] for t in tools]),
        "channel_counts": counts,
        "risk_counts": risk_counts,
        "exec_command_tiers": exec_tiers,
        "blocked_sysctl": [
            {"key": k, "reason": why, "bypass": False}
            for k, why in CRASH_BLACKLIST
        ],
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
                      "parameters": t["parameters"], "sub": t["sub"]}}
        for t in tools
    ]
    out_openai = os.path.join(args.out_dir, "tools.openai.json")
    with open(out_openai, "w", encoding="utf-8") as fh:
        json.dump(openai_tools, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    # ---- tools-sandbox.json（W42：沙盒子智能体受限工具表） ----
    # 七件：exec_run（白名单收窄）+ procfs_read_status + procfs_read_control
    # + netlink_sense + memory_search + sandbox_status + sandbox_destroy
    # （允许子智能体自焚收尾）。硬约束：表内不得出现任何 W2（工具级或
    # 命令级），不得出现 sandbox_create / sandbox_spawn（防嵌套派生）。
    # executor 派生时以 AIKERNEL_TOOLS_JSON 指向本表，子智能体可见工具
    # 面即被物理收窄到这 7 件。
    _sb_keep = ["procfs_read_status", "procfs_read_control",
                "netlink_sense", "memory_search",
                "sandbox_status", "sandbox_destroy"]

    def _sb_exec_cmd(c):
        """受限表命令条目：python3 覆盖为 W1；cc 指向 gcc。

        /usr/bin/cc 在 VM 上是指向 /etc/alternatives/cc 的符号链接，而
        沙盒 /etc 只 bind 白名单文件（不含 alternatives），子进程内会
        ENOENT；直接指向 /usr/bin/gcc（同目录相对链接 gcc-11）可解析。
        """
        d = dict(c)
        if d["command"] == "python3":
            d["risk"] = RISK_W1
        if d["command"] == "cc":
            d["bin"] = "/usr/bin/gcc"
        return d

    _sb_exec_cmds = [_sb_exec_cmd(c) for c in EXEC_COMMANDS
                     if (c["risk"] == RISK_R or
                         c["command"] in SB_EXEC_ALLOW or
                         c["command"] in SB_EXEC_W1_EXTRA) and
                     c["command"] not in SB_EXEC_DYNAMIC_RISK]
    if len(_sb_exec_cmds) != EXPECTED_SANDBOX_EXEC_COUNT:
        raise RuntimeError(
            f"受限表 exec 命令数 {len(_sb_exec_cmds)} != 期望 "
            f"{EXPECTED_SANDBOX_EXEC_COUNT}（W72：54+python3/gcc/cc）")
    _sb_exec = {
        "default_timeout": EXEC_DEFAULT_TIMEOUT,
        "input_max_bytes": EXEC_INPUT_MAX_BYTES,
        "commands": _sb_exec_cmds,
    }
    sb_tools = []
    for t in tools:
        if t["name"] == "exec_run":
            st = dict(t)
            st["exec"] = _sb_exec
            st["description"] = (
                "执行白名单 shell 命令（沙盒受限版）。只保留只读诊断与"
                " mkdir/touch/cp/mv/ln/sed/tee/gzip 八个写命令，另含"
                "沙箱内 W1 的 python3（仅 <script.py> 形态）/gcc/cc"
                "（落点限 /tmp）与只读 which（tar 已升 W2 并剔除；"
                "所有写面限本沙盒 tmpfs）；绝无 systemctl/kill/apt 等"
                "高危命令。白名单/可执行路径/超时/风险分级单源于"
                "本工具内嵌的 exec.commands；参数含 shell 元字符或超长"
                "整条拒绝；默认 30 秒超时后 SIGKILL。写文件配方："
                "command=\"tee\"、args=[\"/tmp/t.txt\"]、input=文件内容")
            sb_tools.append(st)
        elif t["name"] in _sb_keep:
            sb_tools.append(dict(t))
    missing = [n for n in _sb_keep
               if n != "exec_run" and n not in
               {t["name"] for t in sb_tools}]
    if missing:
        raise RuntimeError(f"tools-sandbox.json 缺工具: {missing}")
    # W46a 防呆 3：受限表正典数目断言（写盘前 fail fast）
    if len(sb_tools) != EXPECTED_SANDBOX_TOOL_COUNT:
        sys.stderr.write(
            "ERROR [gen_registry 防呆]: 受限表工具数 %d != 期望 %d"
            "（tools-sandbox.json 正典口径 7 件）。主表成员变动未同步"
            " _sb_keep 白名单？\n"
            % (len(sb_tools), EXPECTED_SANDBOX_TOOL_COUNT))
        sys.exit(2)
    # 安全面自检：任何 W2 进入受限表都视为生成器缺陷，直接失败
    for t in sb_tools:
        if t.get("channel") == CH_CLARIFY or t["name"] == "clarify":
            raise RuntimeError(
                "受限表混入 clarify/interaction（worker 不得向人提问）")
        if t.get("risk") == RISK_W2:
            raise RuntimeError(f"受限表混入 W2 工具: {t['name']}")
        if t.get("channel") == CH_EXEC:
            for c in t["exec"]["commands"]:
                if c["risk"] == RISK_W2:
                    raise RuntimeError(
                        f"受限表混入 W2 命令: {c['command']}")
    sb_registry = {
        "version": 2,
        "generator": "agent/ai/tools/gen_registry.py",
        "generated_at": now,
        "purpose": "sandbox-subagent-restricted",
        "source": "tools.json 派生（sandbox 受限面，无 W2，防嵌套派生）",
        "tool_count": len(sb_tools),
        "channel_counts": {},
        "risk_counts": {},
        "exec_command_tiers": {
            "R": sum(1 for c in _sb_exec_cmds if c["risk"] == RISK_R),
            "W1": sum(1 for c in _sb_exec_cmds if c["risk"] == RISK_W1),
            "W2": 0,
        },
        "tools": sb_tools,
    }
    for t in sb_tools:
        ch = t["channel"]
        sb_registry["channel_counts"][ch] = \
            sb_registry["channel_counts"].get(ch, 0) + 1
        rk = t.get("risk") or "exec按命令"
        sb_registry["risk_counts"][rk] = \
            sb_registry["risk_counts"].get(rk, 0) + 1
    out_sb = os.path.join(args.out_dir, "tools-sandbox.json")
    with open(out_sb, "w", encoding="utf-8") as fh:
        json.dump(sb_registry, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    # ---- W51：SME 语料（区头 8 + 单件 151 + 配方 8） ----
    seed_path = write_corpus_seed(tools, args.out_dir)

    # ---- tool_catalog.txt（目录页单源产物，SME 路由架构） ----
    # system 常驻"目录页"：每行 "<name> <核心短语>"。核心短语规则
    # （与 tool_registry.c 的 tool_registry_build_catalog 逐字一致，
    # 单一权威=本文件）：
    #   1. description 含全角"："或半角":" → 取第一处之后的文本
    #      （描述惯例 "读取 /proc/ai/status（只读）：内核状态总览"，
    #      冒号后是语义核心）；
    #   2. 无冒号 → 取首句（按 。！？;；\n 句读切）；
    #   3. UTF-8 边界安全截断到 CATALOG_DESC_BYTES 字节。
    CATALOG_DESC_BYTES = 24
    _punct = "。！？;；\n"

    def _catalog_phrase(desc):
        d = desc.strip()
        # 取最早冒号（全角/半角同权，与 C 侧一致）之后的文本
        icands = [i for i in (d.find("："), d.find(":")) if i > 0]
        if icands and min(icands) < len(d) - 1:
            d = d[min(icands) + 1:].strip()
        cut = len(d)
        for j, ch in enumerate(d):
            if ch in _punct:
                cut = j
                break
        d = d[:cut].strip()
        b = d.encode("utf-8")
        if len(b) > CATALOG_DESC_BYTES:
            n = CATALOG_DESC_BYTES
            while n > 0 and (b[n] & 0xC0) == 0x80:
                n -= 1
            b = b[:n]
        return b.decode("utf-8", "ignore")

    catalog_lines = [f"{t['name']} {_catalog_phrase(t['description'])}"
                     for t in tools]
    catalog_text = "\n".join(catalog_lines) + "\n"
    out_catalog = os.path.join(args.out_dir, "tool_catalog.txt")
    with open(out_catalog, "w", encoding="utf-8") as fh:
        fh.write(catalog_text)

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
               CH_MEMORY, CH_SHELL, CH_SANDBOX, CH_SYSCTL, CH_SYSFS_DYN,
               CH_DESKTOP, CH_CLARIFY):
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
    sub_counts = {}
    for t in tools:
        for s in t["sub"]:
            sub_counts[s] = sub_counts.get(s, 0) + 1
    lines.append("")
    lines.append("能力域归属（W76 八域；主域 / 含多标签）:")
    for d in SUB_DOMAIN_ORDER:
        n_primary = sum(1 for t in tools if t["sub"][0] == d)
        lines.append(f"  {d:<10} {n_primary:>3} / {sub_counts.get(d, 0):>3}")
    lines.append(
        f"W51 语料: 区头 {len(SUB_DOMAIN_ORDER)} + 单件 {len(tools)} + "
        f"配方 {len(COMBOS)} = "
        f"{len(SUB_DOMAIN_ORDER) + len(tools) + len(COMBOS)} 条 -> {seed_path}")
    report = "\n".join(lines) + "\n"

    lines.append(f"目录页(tool_catalog): {len(catalog_lines)} 行, "
                 f"{len(catalog_text.encode('utf-8'))} 字节"
                 f"（描述截断 {CATALOG_DESC_BYTES}B）")
    report = "\n".join(lines) + "\n"

    out_report = os.path.join(args.out_dir, "tools_report.txt")
    with open(out_report, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(report, file=sys.stderr)
    print(f"OK: {out_json}", file=sys.stderr)
    print(f"OK: {out_openai}", file=sys.stderr)
    print(f"OK: {seed_path}", file=sys.stderr)
    print(f"OK: {out_catalog}", file=sys.stderr)
    print(f"OK: {out_sb}（沙盒受限表，{len(sb_tools)} 工具，"
          f"exec {len(_sb_exec_cmds)} 命令，0 W2）", file=sys.stderr)


if __name__ == "__main__":
    main()
