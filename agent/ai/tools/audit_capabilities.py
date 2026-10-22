#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
audit_capabilities.py - AIKernel W75 read-only observability/capability auditor.

Purpose
-------
Build a reproducible object matrix (state x read path x write path x semantic
level x risk x evidence x gap) for the AIKernel Agent, and compute coverage
numbers from evidence rather than hand-written claims.

Guarantees
----------
* Read-only: reads files, executes `test -e`/`command -v` style probes and
  HTTP GETs only. It never writes to system paths, never POSTs, never starts
  or stops services, never installs packages.
* Deterministic: object catalog order is fixed; all lists are sorted. The only
  volatile JSON fields are `generated_at` and `host.uptime_seconds`.
* Self-contained: no third-party Python modules.

Definitions (also printed in --markdown)
----------------------------------------
read path      : a registered tool, whitelisted exec command, readable file,
                 VM node, or read-only HTTP API that can reach the object.
direct read    : a read path that does not need W2 confirmation or an
                 arbitrary-code escape (dedicated R tool / R command / file /
                 GET API).
semantic level : `semantic` = typed object model (JSON with stable fields,
                 graph/fact relations); `structured` = documented JSON/CSV/
                 key=value or stable machine-parsable fields; `raw` = free-form
                 text or ad-hoc lines. Shell/python escape is never counted as
                 structured/semantic.
write path     : a registered W1/W2 tool, whitelisted W1/W2 command, or an
                 existing POST API. A shell/script escape is reported
                 separately and is a gap, not a first-class capability.

Usage
-----
  python3 tools/audit_capabilities.py --json
  python3 tools/audit_capabilities.py --markdown matrix
  python3 tools/audit_capabilities.py --markdown gaps
  python3 tools/audit_capabilities.py --check
  python3 tools/audit_capabilities.py --json --vm-host root@192.168.245.138

Exit codes: 0 ok; 1 --check failed; 2 bad invocation.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from collections import Counter, OrderedDict
from datetime import datetime, timezone

SCHEMA = "aik-w75-audit/1"
EXPECTED_TOOLS = 151
EXPECTED_SANDBOX_TOOLS = 7
EXPECTED_DOMAINS = 8
EXPECTED_DESKTOP_TOOLS = 20
EXPECTED_SEED_COUNT = 167
EXPECTED_SEED_KINDS = {"domain-header": 8, "tool": 151, "combo": 8}
EXPECTED_TOOL_NAMES_SHA256 = "52cbbc49c18da3c339fb9daf5441cd89cf4bbc02555462387e5d43055b52d3c2"
READ_TARGET = 95.0
SEMANTIC_TARGET = 50.0

CHANNEL_CASE = {
    "procfs-read": "TOOL_CH_PROCFS_READ",
    "sysfs-write": "TOOL_CH_SYSFS_WRITE",
    "netlink-act": "TOOL_CH_NETLINK_ACT",
    "netlink-sense": "TOOL_CH_NETLINK_SENSE",
    "exec": "TOOL_CH_EXEC",
    "memory": "TOOL_CH_MEMORY",
    "shell": "TOOL_CH_SHELL",
    "sandbox": "TOOL_CH_SANDBOX",
    "sysctl": "TOOL_CH_SYSCTL",
    "sysfs": "TOOL_CH_SYSFS_DYN",
    "desktop": "TOOL_CH_DESKTOP",
    "interaction": "TOOL_CH_CLARIFY",
}

# ---------------------------------------------------------------------------
# Gap registry. Every object references zero or more of these IDs.
# ---------------------------------------------------------------------------
GAPS = [
    {"id": "G-001", "priority": "P2", "object": "租约/授权（W74 已落地；残余硬化）",
     "current": "W74 已落地：租约 JSON 存于 /var/lib/aikernel/leases/*.json，确认存于 /run/aikernel/confirm；/lease list|show|issue|revoke|confirm 为 Principal root+TTY 命令；AI 可 cat JSON、用 --lease 加载，但无 lease_request/自签工具。残余：B-044 进行中 D3 不能中止/回滚；B-045 root AI 可经 python3/apt 改写租约存储；B-046 无密码学签名/TOCTOU；B-047 D4 工具未注册；B-048 danger 表未外化；B-049 gate 先记 ALLOW 后路径拒绝；B-050 旧 ai_policy_gate_reason 兼容 API；B-051 同 UID 可改自己的 audit.log",
     "why": "能力缺口已关闭：租约/确认/D0-D4 映射均在，D2+ 有 lease_id；剩余是 Principal-only 写、无签名/独立 broker 与审计/回滚硬化，不阻断 alpha.10 的“有租约”目标，但须作为残余风险跟踪",
     "wave": "W74b/W83/W86",
     "acceptance": "lease_request（AI 申请/Principal 审批）；Ed25519/TPM 签名或独立 broker；D3 中止/回滚；D4 工具注册；红队用例通过"},
    {"id": "G-002", "priority": "P0", "status": "closed", "object": "桌面窗口/输入/截图/剪贴板（W76 已关闭）",
     "current": "W76 已关闭：20 件 desktop_* 注册；desktop_windows_list/focus/close、desktop_input_type/key、desktop_screenshot、desktop_clipboard_get/set 均有实现；10/10（含输入后截图/清理 12/12）桌面任务、test_desktop_tools 56/0。残余 W76-R1：Web demo 虚拟窗口 ≠ 真 OS 桌面（W84）",
     "why": "原缺口是 AI 无窗口/输入/截图/剪贴板接口；W76 已提供一等工具、D0-D3、租约/审计与结构化返回，缺口的“无接口”前提不再成立",
     "wave": "W76", "acceptance": "已验收：10/10 + 12/12；windows/input/screenshot/clipboard 各 1 个只读+1 个受控写用例通过"},
    {"id": "G-003", "priority": "P1", "object": "trace/训练导出/会话",
     "current": "trace JSONL 与 session JSONL 可由 cat 读取；`ai trace stats|dump|export` 仅 CLI，无 Agent 工具",
     "why": "AI 只能逐行读原始 JSONL，不能按 session/turn 聚合；训练导出无法由 AI 触发",
     "wave": "W82", "acceptance": "trace.stats/session/export 三个工具返回 JSON；export 产物可被训练管线直接消费"},
    {"id": "G-004", "priority": "P1", "object": "文件 ACL",
     "current": "getfacl/setfacl 在 L1 存在但不在 exec 白名单；Agent 只能通过 python3/sys_shell 逃逸",
     "why": "ACL 是文件权限的一等状态，当前对 AI 是黑箱；无法审计“谁能读这个文件”",
     "wave": "W84", "acceptance": "acl_get(path) 返回 owner/group/entries JSON；acl_set 为 D2 并保留回滚"},
    {"id": "G-005", "priority": "P1", "object": "文件 xattr",
     "current": "getfattr/setfattr 在 L1/VM 均缺失；Agent 只能 python3 os.listxattr 逃逸",
     "why": "SELinux/AppArmor/用户扩展属性不可见；安全标签与自定义元数据无法审计",
     "wave": "W84", "acceptance": "xattr_list/get/set 工具；set 为 D2；未知属性名明确报错"},
    {"id": "G-006", "priority": "P1", "object": "文件属性 chattr/lsattr",
     "current": "lsattr/chattr 在 L1 存在但不在白名单；VM 未验证 chattr",
     "why": "immutable/append-only 等属性直接影响 AI 写入可行性，当前不可见",
     "wave": "W84", "acceptance": "file.attrs_get 显示 flags；attrs_set 为 D2/D3 且拒绝 immutable 自锁"},
    {"id": "G-007", "priority": "P1", "object": "磁盘配额",
     "current": "quota/repquota 二进制在 L1 与生产 VM 均缺失；setquota 也缺失",
     "why": "无法读用户/组配额与超限状态；多用户磁盘治理是黑箱",
     "wave": "W84", "acceptance": "quota.get(user/group) 返回 blocks/inodes soft/hard；缺失时明确 unavailable"},
    {"id": "G-008", "priority": "P1", "object": "SMART/磁盘健康",
     "current": "smartctl 已注册为 R 命令但 L1/VM 均无二进制；无替代语义接口",
     "why": "磁盘故障前兆（重映射/待定扇区/温度）对 AI 不可见；只能等 IO 错误",
     "wave": "W85", "acceptance": "disk.smart(dev) 返回 health/attrs JSON；无 SMART 设备明确 unavailable"},
    {"id": "G-009", "priority": "P1", "object": "包管理状态/仓库",
     "current": "无 package 域；已安装包只能 cat /var/lib/dpkg/status（原始大文本）或 dpkg -l（W2 确认）；仓库只能 cat sources.list",
     "why": "包状态/仓库是系统配置的一等对象，当前没有结构化视图，读取还被 W2 化",
     "wave": "W84", "acceptance": "package.list/search/info/repos 返回 JSON；读操作 R，安装/卸载 W2"},
    {"id": "G-010", "priority": "P1", "object": "可用更新",
     "current": "`apt list --upgradable` 为 W2；无 R 读路径，无缓存/时间戳语义",
     "why": "“系统是否落后/是否有安全更新”是最高频运维问题，却不能免确认读取",
     "wave": "W84", "acceptance": "package.updates 返回可升级包/安全等级/缓存年龄 JSON，R 级"},
    {"id": "G-011", "priority": "P1", "object": "systemd unit 配置/drop-in",
     "current": "config_write_* 只覆盖 fstab/nftables/sshd/resolv/hosts/hostname；unit 文件只能 sys_shell",
     "why": "AI 能重启服务却不能安全地编辑 unit/drop-in；写路径只剩交互 shell，不可审计/无回滚",
     "wave": "W84", "acceptance": "service.unit_get/set 带 diff 预览、校验、原子替换与回滚；D2/D3 分级"},
    {"id": "G-012", "priority": "P1", "object": "sudoers/policy",
     "current": "sudoers 仅 root 可 cat；policy.conf 仅原始文本；无写入工具（visudo 只能 shell）；W74 只解决了租约，不解决 sudoers/policy 的结构化读写",
     "why": "D4 身份/授权状态仍不可结构化读取，修改无预览/无回滚；与已落地的 lease 面分离，属于 policy 管理缺口",
     "wave": "W84", "acceptance": "identity.policy_get 返回结构化规则；policy_set 为 D4，强制确认+回滚"},
    {"id": "G-013", "priority": "P1", "object": "SSH 密钥",
     "current": "authorized_keys/host key 仅 cat/ls/stat；无 key 管理工具；ssh-keygen 只能 shell",
     "why": "无法枚举指纹/注释/有效期，无法安全轮换；密钥是 D4 资产",
     "wave": "W83", "acceptance": "ssh.keys_list 返回指纹/类型/注释；rotate 为 D4 且保留旧 key 回滚窗口"},
    {"id": "G-014", "priority": "P1", "object": "PSI",
     "current": "3 个 PSI 工具已注册且带 probe；生产 VM /proc/pressure 不存在，工具 unavailable；L1 有 PSI",
     "why": "生产内核缺 CONFIG_PSI 或 psi=0，内存/IO 压力前兆在生产环境不可读",
     "wave": "W78", "acceptance": "生产内核启用 PSI；3 工具在 VM 返回 some/full 数据；回归 50 场景"},
    {"id": "G-015", "priority": "P1", "status": "closed", "object": "桌面写路径/租约（W76 已关闭）",
     "current": "W76 已关闭：theme/wallpaper/notifications/apps/windows/input/clipboard 写均为一等 desktop_*；D1/D2 + W74 lease/确认 + 回读/previous 恢复/影响提示；curl 不再是唯一路径。desktop_power D3 仍 501 → 由 G-033 单独跟踪",
     "why": "原缺口是桌面写没有一等工具/路由/租约语义；W76 已把写路径注册进 tools.json/目录页/SME 语料，并接入 W74 gate；剩余敏感性风险为 W76-R2（W83）",
     "wave": "W76", "acceptance": "已验收：desktop_theme_set 等工具注册；输入/写为 D1/D2；回读/previous 恢复；GET 保持 R"},
    {"id": "G-016", "priority": "P1", "object": "沙箱子会话 trace",
     "current": "sandbox_spawn 子进程 trace 未回收；父只拿到 stdout 尾部 4KB",
     "why": "子智能体的工具调用/拒绝/错误没有进入父 trace，训练与审计链断裂",
     "wave": "W80", "acceptance": "子会话 trace 合并到父 session 或独立可检索；tool_call 100% 可关联 parent_turn"},
    {"id": "G-017", "priority": "P2", "object": "KUnit/测试结果",
     "current": "/sys/kernel/debug/kunit 不存在（VM debugfs 已挂载但无 kunit 节点）；只能 dmesg grep",
     "why": "内核测试结果无结构化读取接口，AI 无法判断回归",
     "wave": "W78", "acceptance": "kunit.results 返回 suite/case/pass/fail JSON；无测试时明确空态"},
    {"id": "G-018", "priority": "P2", "object": "LVM",
     "current": "pvs/vgs/lvs 在 L1/VM 均缺失；只能 lsblk 看 dm 映射与 /sys/block",
     "why": "PV/VG/LV 拓扑、剩余空间、快照不可结构化读取",
     "wave": "W85", "acceptance": "storage.lvm 返回 pv/vg/lv JSON；缺失 lvm 工具时明确 unavailable"},
    {"id": "G-019", "priority": "P2", "object": "网卡链路诊断",
     "current": "ethtool 在 L1 存在但生产 VM 缺失；只能 sysfs/ip 原始字段",
     "why": "速率/双工/错误计数/环参数不可读，链路故障诊断退化",
     "wave": "W85", "acceptance": "net.link_info(if) 返回 speed/duplex/errors/rings JSON"},
    {"id": "G-020", "priority": "P2", "object": "conntrack 用户态工具",
     "current": "conntrack 二进制在 VM 缺失；procfs_read_net_nf_conntrack 仍可读表",
     "why": "无法按条件查询/统计连接跟踪，只能全表 cat",
     "wave": "W85", "acceptance": "net.conntrack_query 支持 proto/src/dst/state 过滤，返回 JSON"},
    {"id": "G-021", "priority": "P2", "object": "AppArmor/LSM 状态",
     "current": "aa-status/apparmor_status 在 VM 缺失；只能读 /sys/kernel/security/apparmor 原始文件",
     "why": "LSM 执行档位与 profile 命中不可结构化读取",
     "wave": "W83", "acceptance": "security.lsm_status 返回 profiles/mode JSON；与 sec.lsm_override 关联"},
    {"id": "G-022", "priority": "P2", "object": "包依赖/版本",
     "current": "只能解析 /var/lib/dpkg/status 原始文本或 dpkg -s（W2）",
     "why": "依赖树/版本约束无法查询，升级影响分析只能靠模型读大文本",
     "wave": "W84", "acceptance": "package.depends(name) 返回 depends/rdepends/conflicts 图"},
    {"id": "G-023", "priority": "P2", "object": "硬件清单/传感器",
     "current": "无 lspci/lsusb/sensors 工具；只能用 sysfs_get 读 /sys/class/{drm,hwmon,thermal,power_supply}",
     "why": "设备型号/驱动/温度/风扇/电池只能逐文件 raw 读取，没有设备对象",
     "wave": "W85", "acceptance": "hardware.inventory/sensors 返回 JSON；无设备明确空态"},
    {"id": "G-024", "priority": "P2", "object": "文件完整性/校验和",
     "current": "sha256sum/md5sum 不在白名单；只能 python3 hashlib 逃逸",
     "why": "无法做发布产物/配置漂移的 D0 校验，供应链验证不可用",
     "wave": "W83", "acceptance": "file.hash(path,algo) 返回 hex/size；大文件限流"},
    {"id": "G-025", "priority": "P2", "object": "登录会话",
     "current": "loginctl/who 不在白名单；只能 ps + /proc/<pid>/loginuid 推断",
     "why": "会话/座位/空闲/远程来源不可结构化读取",
     "wave": "W84", "acceptance": "session.list 返回 user/tty/seat/remote/idle JSON"},
    {"id": "G-026", "priority": "P2", "object": "cron",
     "current": "crontab 在 VM 缺失且 /var/spool/cron/crontabs 不存在；系统 cron 只能 cat /etc/crontab",
     "why": "用户定时任务不可枚举/不可写；调度视图不完整",
     "wave": "W84", "acceptance": "schedule.list 合并 cron+timers；cron.set 为 D2 且校验"},
    {"id": "G-027", "priority": "P3", "object": "设备树",
     "current": "/sys/firmware/devicetree 在 x86 不存在；当前平台 N/A",
     "why": "ARM/真机启用后设备树是硬件拓扑主源，当前无读取工具",
     "wave": "W85", "acceptance": "hardware.devicetree 在 ARM 目标返回节点树；x86 返回 N/A"},
    {"id": "G-028", "priority": "P2", "object": "防火墙运行时规则",
     "current": "nft 整命令为 W2，`nft list ruleset` 也需确认；config_read_nftables 只读持久化文件",
     "why": "运行时规则与持久化配置可能漂移，D0 读取缺失",
     "wave": "W84", "acceptance": "firewall.rules_get 返回 runtime+persistent 差异 JSON，R 级"},
    {"id": "G-029", "priority": "P2", "object": "/proc/ai/control 参数",
     "current": "27 个参数按行返回 name/domain/min/max/current/default 文本；无 JSON/类型 schema",
     "why": "AI 要自己解析文本才能构造 netlink 写；类型/枚举/单位不明确",
     "wave": "W82", "acceptance": "ai.params 返回 JSON schema（type/unit/enum/range/current）"},
    {"id": "G-030", "priority": "P3", "object": "文档/注册表漂移",
     "current": "ARCHITECTURE-MATRIX 仍写 55 个沙箱命令（实际 57）、tools.json 旧 sha/生成时间；gen_registry 文档仍写 EXPECTED_TOOL_COUNT(151)",
     "why": "文档漂移会让后续波次基于错误口径验收",
     "wave": "W81", "acceptance": "脚本 --check 断言文档计数与注册表一致；CI 失败即阻断"},
    {"id": "G-031", "priority": "P3", "object": "能力探测",
     "current": "只有 3/150 工具带 probe（PSI 三件套）；desktop_* 及其余节点依赖工具无 probe，节点缺失时报“通道不可用”而非“能力不可用”",
     "why": "AI 无法区分“内核没这功能”和“路径写错/权限不足/桌面服务停机”，容易误判",
     "wave": "W81", "acceptance": "每个 procfs-read/sysfs-write/desktop 工具有 probe；unavailable 有原因码"},
    {"id": "G-032", "priority": "P2", "object": "全局",
     "current": "进程/文件/网络/包/硬件对象没有进入 SME 世界模型；只有工具语料与运维记忆",
     "why": "全知的下一层是“可推理”：当前 AI 能读状态但不能回答跨对象因果（如“哪个 cgroup 的 IO 压力导致 nginx 慢”）",
     "wave": "W82", "acceptance": "对象/关系/时序进入 SME；Top-3 语义检索 ≥98%；可解释命中"},
    {"id": "G-033", "priority": "P3", "object": "桌面电源",
     "current": "desktop_power D3 已注册，但 /api/power 返回 501 unavailable；不执行关机/重启/锁屏；工具如实失败，不伪造成功。G-033 保持开放",
     "why": "电源动作 D3 需要 logind/会话绑定与回滚；W76 只完成工具登记与 D3 门禁，后端未接",
     "wave": "W84", "acceptance": "desktop_power 走 logind + D3 确认；有回滚/取消；501 变为真实执行"},
    {"id": "G-034", "priority": "P3", "object": "命名空间",
     "current": "ip netns list 可用；lsns 不在白名单；只能读 /proc/<pid>/ns/* 的 inode",
     "why": "无法按 namespace 类型/ID 聚合进程与资源",
     "wave": "W84", "acceptance": "namespace.list 返回 type/id/members JSON"},
    {"id": "G-035", "priority": "P2", "status": "closed", "object": "桌面应用启动（W76 已关闭）",
     "current": "W76 已关闭：desktop_apps_list/launch/close 注册；10-task 01/05 启动 libreoffice-calc 并关闭窗口成功；返回窗口/应用状态",
     "why": "应用枚举/启动/关闭已是一等工具（D0/D1/D2），不再只能 exec_run curl 拼 POST",
     "wave": "W76", "acceptance": "已验收：desktop_apps.launch/close 成功返回窗口；D1/D2 分级"},
    {"id": "G-036", "priority": "P2", "object": "语义化覆盖（全局）",
     "current": "structured+semantic 68/97 = 70.1%；typed semantic 仅 10/97 = 10.3%；26 个对象仍是 raw 文本",
     "why": "能读不等于能推理：进程/文件/网络/包/硬件仍是自由文本，缺少 schema、单位、枚举与对象关系；W82 无法做跨对象因果",
     "wave": "W82", "acceptance": "核心 97 对象 structured+ ≥95%；关键 30 对象 typed ≥60%；检索答案可引用 typed 字段与关系"},
]

SHELL_ONLY = [
    ("getfacl/setfacl", "ACL 读写", "L1 有二进制，不在白名单", "G-004"),
    ("getfattr/setfattr", "xattr 读写", "L1/VM 均缺二进制", "G-005"),
    ("lsattr/chattr", "文件属性", "L1 有二进制，不在白名单", "G-006"),
    ("quota/repquota/setquota", "配额", "L1/VM 均缺二进制", "G-007"),
    ("smartctl", "SMART", "已注册 R，但 L1/VM 均缺二进制", "G-008"),
    ("pvs/vgs/lvs", "LVM", "已注册 R，但 L1/VM 均缺二进制", "G-018"),
    ("ethtool", "网卡链路", "L1 有，VM 缺失", "G-019"),
    ("conntrack", "连接跟踪", "VM 缺失（L1 有）", "G-020"),
    ("aa-status/apparmor_status", "LSM", "VM 缺失（L1 有）", "G-021"),
    ("lsof", "打开文件", "L1 有，VM 缺失，且不在白名单; /proc/<pid>/fd 可替代", "-"),
    ("loginctl/who", "登录会话", "L1 有，不在白名单；ps/proc 可替代", "G-025"),
    ("lsns", "命名空间", "L1 有，不在白名单；ip netns/proc 可替代", "G-034"),
    ("sensors", "温度/风扇", "L1/VM 均无；只能 sysfs raw", "G-023"),
    ("lspci/lsusb", "PCI/USB 清单", "未注册；只能 sysfs raw", "G-023"),
    ("sha256sum/md5sum", "文件校验", "不在白名单；python3 可替代", "G-024"),
    ("visudo", "sudoers 编辑", "只能 shell；D4", "G-012"),
    ("/lease issue|revoke|confirm", "租约签发/撤销/确认", "Principal root+TTY；AI 无工具（lease_request 未实现）", "G-001"),
    ("ssh-keygen", "SSH 密钥轮换", "只能 shell；D4", "G-013"),
    ("ai trace stats|dump|export", "trace 查询/训练导出", "CLI 内置命令，不在 exec 白名单", "G-003"),
    ("add-apt-repository", "仓库管理", "未注册；apt W2 不能等价", "G-009"),
    ("systemctl edit", "unit drop-in", "systemctl W2 但 edit 交互式；无结构化写", "G-011"),
    ("parted/fdisk/mdadm/cryptsetup", "分区/RAID/加密", "未注册", "-"),
    ("dd", "块设备/镜像", "未注册", "-"),
]

# W76 残余风险：不占用 W75 G 编号，不计入缺口数。
W76_RISKS = [
    ("W76-R1", "Web demo 虚拟窗口 ≠ 真 OS 窗口/进程；不启动宿主应用", "P1",
     "W84 接 greetd/cage/真 WM；文档明确 backend=web-demo-virtual-window"),
    ("W76-R2", "输入注入/截图/剪贴板敏感；8091 loopback 无鉴权，本机任意 uid 可调", "P1",
     "W83 加会话令牌/跨用户隔离；W84 绑定用户会话；读取不脱敏需审计"),
    ("W76-R3", "截图依赖 Playwright/chromium（~/.cache/ms-playwright）单点", "P2",
     "加 probe/自检；缺失必须 503，不伪造；W81 锁版本"),
    ("W76-R4", "8091 demo 单点停机 → 桌面工具 E_DESKTOP_UNAVAILABLE", "P2",
     "W84 系统桌面服务化；Agent 侧保留明确不可用码"),
]

INVISIBLE = [
    ("桌面电源（desktop_power）", "工具已注册 D3，但 /api/power 返回 501 unavailable；不执行关机/重启/锁屏", "G-033"),
    ("trace 聚合/训练导出", "`ai trace` CLI 内置，Agent 只能 cat JSONL", "G-003"),
    ("KUnit 结果", "debugfs 节点不存在；只能 dmesg raw", "G-017"),
    ("授权租约（AI 写）", "W74 已落地租约 JSON 与 /lease（Principal root+TTY）；AI 只能读 JSON/--lease 加载，无 lease_request/自签工具", "G-001"),
    ("PSI（生产 VM）", "工具已注册但 /proc/pressure 缺失", "G-014"),
    ("conntrack/ethtool/aa-status/smartctl 等", "已注册或存在二进制，但生产 VM 缺失", "G-018/G-019/G-020/G-021/G-008"),
]

# ---------------------------------------------------------------------------
# Object catalog. Token grammar:
#   tool:NAME        registered Agent tool
#   cmd:NAME         whitelisted exec command
#   file:PATH        readable file/API surface (host or VM)
#   vmfile:PATH      production VM node
#   api:GET /path    desktop demo read-only HTTP GET
#   apiw:POST /path  desktop demo write endpoint (static route check)
#   escape:python3|sys_shell  arbitrary-code only path (reported as gap)
#   principal:CMD    Principal-only root+TTY CLI (implemented in source; not Agent tool)
# ---------------------------------------------------------------------------


def O(oid, cls, name, read, write, sem, risk, evidence, gap="-", notes="",
      status="", write_na=False):
    return {
        "id": oid, "class": cls, "name": name,
        "read": list(read), "write": list(write), "semantic": sem,
        "risk": risk, "evidence": evidence, "gap": gap, "notes": notes,
        "status": status, "write_na": write_na,
    }


OBJECTS = [
    # ---------------- 进程/线程/调度 ----------------
    O("PROC-01", "进程/线程/调度", "进程枚举与属性",
      ["cmd:ps", "file:/proc/1/status", "file:/proc/1/cmdline"],
      ["cmd:kill", "tool:netlink_act_proc_signal"], "raw", "D0/D2",
      "exec_run ps -eo pid,ppid,stat,comm; cat /proc/<pid>/status"),
    O("PROC-02", "进程/线程/调度", "线程",
      ["cmd:ps", "file:/proc/1/task"],
      ["tool:netlink_act_proc_signal"], "raw", "D0/D2",
      "exec_run ps -T -p <pid>; ls /proc/<pid>/task"),
    O("PROC-03", "进程/线程/调度", "调度属性与内核控制",
      ["file:/proc/1/sched", "file:/proc/1/stat", "cmd:ps"],
      ["tool:netlink_act_sched_nice", "tool:netlink_act_sched_affinity",
       "tool:netlink_act_sched_oom_score", "tool:netlink_act_sched_timeslice",
       "tool:netlink_act_proc_signal", "tool:netlink_act_proc_freeze",
       "tool:netlink_act_proc_rlimit"], "structured", "D0/D2",
      "cat /proc/<pid>/sched; netlink_act_sched_nice(pid,value)"),
    O("PROC-04", "进程/线程/调度", "进程内存/IO/文件描述符",
      ["file:/proc/1/smaps", "file:/proc/1/io", "file:/proc/1/fd", "cmd:ls"],
      ["tool:netlink_act_proc_rlimit"], "structured", "D0/D2",
      "cat /proc/<pid>/smaps; cat /proc/<pid>/io; ls -l /proc/<pid>/fd"),
    O("PROC-05", "进程/线程/调度", "进程 cgroup 归属",
      ["file:/proc/1/cgroup", "tool:sysfs_get"],
      ["tool:sysfs_set"], "structured", "D0/D2",
      "cat /proc/<pid>/cgroup; sysfs_get /sys/fs/cgroup/<path>/cgroup.procs"),

    # ---------------- CPU/内存/PSI/IO ----------------
    O("RES-01", "CPU/内存/PSI/IO", "CPU 拓扑/型号",
      ["cmd:lscpu", "file:/proc/cpuinfo", "tool:sysfs_get"],
      ["tool:sysfs_set"], "structured", "D0/D2",
      "exec_run lscpu -J; sysfs_get /sys/devices/system/cpu/online"),
    O("RES-02", "CPU/内存/PSI/IO", "CPU 使用率/负载",
      ["file:/proc/stat", "cmd:uptime", "cmd:vmstat"],
      [], "structured", "D0", "cat /proc/stat; uptime; vmstat 1 2", write_na=True),
    O("RES-03", "CPU/内存/PSI/IO", "CPU 频率/调频",
      ["tool:sysfs_get", "file:/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"],
      ["tool:sysfs_set"], "structured", "D0/D2",
      "sysfs_get /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
    O("RES-04", "CPU/内存/PSI/IO", "内存/swap",
      ["cmd:free", "file:/proc/meminfo", "tool:procfs_read_swaps"],
      ["tool:sysctl_set", "tool:netlink_act_mm_swappiness"], "structured", "D0/D2",
      "exec_run free -b; cat /proc/meminfo; procfs_read_swaps"),
    O("RES-05", "CPU/内存/PSI/IO", "PSI 压力（CPU/内存/IO）",
      ["tool:procfs_read_pressure_cpu", "tool:procfs_read_pressure_memory",
       "tool:procfs_read_pressure_io"],
      [], "structured", "D0", "procfs_read_pressure_cpu; 生产 VM /proc/pressure 缺失",
      gap="G-014", write_na=True),
    O("RES-06", "CPU/内存/PSI/IO", "块 IO 统计",
      ["file:/proc/diskstats", "cmd:vmstat", "tool:sysfs_get"],
      ["tool:netlink_act_io_priority"], "structured", "D0/D2",
      "cat /proc/diskstats; sysfs_get /sys/block/<dev>/stat"),
    O("RES-07", "CPU/内存/PSI/IO", "IO 调参（预读/优先级/带宽）",
      ["tool:sysfs_get", "tool:procfs_read_vfs_stats"],
      ["tool:netlink_act_io_bandwidth", "tool:netlink_act_io_priority"],
      "structured", "D0/D2", "sysfs_get /sys/class/bdi/<dev>/read_ahead_kb"),

    # ---------------- cgroup ----------------
    O("CG-01", "cgroup", "cgroup v2 层级/限额",
      ["tool:sysfs_get", "file:/sys/fs/cgroup/cgroup.controllers"],
      ["tool:sysfs_set"], "structured", "D0/D2",
      "sysfs_get /sys/fs/cgroup/<path>/{memory.max,cpu.max,cgroup.procs}"),
    O("CG-02", "cgroup", "cgroup 统计/AI 推理计数",
      ["tool:procfs_read_cgroup_inferences", "tool:sysfs_get"],
      ["tool:sysfs_set"], "structured", "D0/D2",
      "procfs_read_cgroup_inferences; sysfs_get /sys/fs/cgroup/<path>/memory.current"),

    # ---------------- 文件/目录/元数据/ACL/xattr ----------------
    O("FS-01", "文件/目录/元数据/ACL/xattr", "文件内容读取",
      ["cmd:cat", "cmd:head", "cmd:tail", "cmd:grep"],
      ["cmd:tee", "cmd:sed"], "raw", "D0/D1",
      "exec_run cat/head/tail/grep <path>; tee W1 限 /root /tmp /var/ai"),
    O("FS-02", "文件/目录/元数据/ACL/xattr", "目录枚举",
      ["cmd:ls", "cmd:find"],
      ["cmd:mkdir", "cmd:cp", "cmd:mv"], "structured", "D0/D1",
      "exec_run find <dir> -maxdepth 1 -printf '%y %m %u %g %s %p\\n'"),
    O("FS-03", "文件/目录/元数据/ACL/xattr", "元数据/链接",
      ["cmd:stat", "cmd:ls"],
      ["cmd:chmod", "cmd:chown", "cmd:ln"], "structured", "D0/D2",
      "exec_run stat <path>; ls -l <path>"),
    O("FS-04", "文件/目录/元数据/ACL/xattr", "文件写入/编辑",
      ["cmd:cat"],
      ["cmd:tee", "cmd:sed", "cmd:python3"], "raw", "D0/D2",
      "tee 限 /root /tmp /var/ai; python3 为 W2"),
    O("FS-05", "文件/目录/元数据/ACL/xattr", "删除/重命名",
      ["cmd:ls", "cmd:stat"],
      ["cmd:rm", "cmd:mv"], "structured", "D0/D2",
      "exec_run rm/mv <path>; W2 确认"),
    O("FS-06", "文件/目录/元数据/ACL/xattr", "文件 ACL",
      ["escape:python3"],
      ["escape:sys_shell"], "raw", "D0/D2",
      "仅 python3 os.getxattr(system.posix_acl_access) / shell getfacl；无白名单命令",
      gap="G-004"),
    O("FS-07", "文件/目录/元数据/ACL/xattr", "扩展属性 xattr",
      ["escape:python3"],
      ["escape:python3"], "raw", "D0/D2",
      "仅 python3 os.listxattr；getfattr/setfattr 缺失", gap="G-005"),
    O("FS-08", "文件/目录/元数据/ACL/xattr", "文件属性 chattr/lsattr",
      ["escape:sys_shell"],
      ["escape:sys_shell"], "raw", "D0/D2",
      "仅 shell lsattr/chattr；不在 exec 白名单", gap="G-006"),
    O("FS-09", "文件/目录/元数据/ACL/xattr", "文件完整性/校验和",
      ["escape:python3"],
      [], "raw", "D0", "仅 python3 hashlib；无 sha256sum 白名单命令",
      gap="G-024", write_na=True),
    O("FS-10", "文件/目录/元数据/ACL/xattr", "磁盘配额",
      [], [], "none", "D0/D3",
      "quota/repquota 在 L1/VM 均缺二进制；无 AI 读路径", gap="G-007"),

    # ---------------- 磁盘/分区/文件系统/SMART ----------------
    O("DISK-01", "磁盘/分区/文件系统/SMART", "块设备/分区",
      ["cmd:lsblk", "cmd:blkid", "file:/proc/partitions"],
      ["cmd:mount", "cmd:umount"], "structured", "D0/D2",
      "exec_run lsblk -J; blkid -o export"),
    O("DISK-02", "磁盘/分区/文件系统/SMART", "文件系统/挂载",
      ["cmd:findmnt", "file:/proc/mounts", "cmd:dumpe2fs"],
      ["cmd:mount", "cmd:umount", "tool:config_write_fstab"],
      "structured", "D0/D3", "findmnt -J; cat /proc/mounts; dumpe2fs -h <dev>"),
    O("DISK-03", "磁盘/分区/文件系统/SMART", "SMART/磁盘健康",
      ["cmd:smartctl"], [], "none", "D0",
      "smartctl -a <dev> 已注册 R，但 L1/VM 无二进制", gap="G-008", write_na=True),
    O("DISK-04", "磁盘/分区/文件系统/SMART", "LVM/逻辑卷",
      ["cmd:lsblk", "tool:sysfs_get"], [], "structured", "D0",
      "lsblk -J 可看 dm 映射；pvs/vgs/lvs 缺失", gap="G-018", write_na=True),
    O("DISK-05", "磁盘/分区/文件系统/SMART", "磁盘用量/inode",
      ["cmd:df", "cmd:du", "cmd:find"], [], "structured", "D0",
      "exec_run df -P; du -x -d1; find", write_na=True),
    O("DISK-06", "磁盘/分区/文件系统/SMART", "TRIM/软 RAID/dm",
      ["file:/proc/mdstat", "cmd:lsblk", "tool:sysfs_get"],
      ["cmd:fstrim"], "structured", "D0/D1",
      "cat /proc/mdstat; lsblk; fstrim -v <mount>"),

    # ---------------- systemd/服务/日志/启动 ----------------
    O("SYS-01", "systemd/服务/日志/启动", "units/服务状态",
      ["cmd:systemctl", "file:/run/systemd/system", "file:/etc/systemd/system"],
      ["cmd:systemctl"], "structured", "D0/D3",
      "systemctl list-units --no-pager; systemctl show <unit> -p ..."),
    O("SYS-02", "systemd/服务/日志/启动", "失败单元",
      ["cmd:systemctl"], ["cmd:systemctl"], "structured", "D0/D3",
      "systemctl --failed --no-legend; systemctl restart <unit>"),
    O("SYS-03", "systemd/服务/日志/启动", "journal 日志",
      ["cmd:journalctl", "file:/var/log/journal"],
      ["cmd:journalctl"], "structured", "D0/D2",
      "journalctl -o json --no-pager -n 100; --vacuum-* 为 W1"),
    O("SYS-04", "systemd/服务/日志/启动", "内核日志/dmesg",
      ["cmd:dmesg", "file:/dev/kmsg"], ["cmd:dmesg"], "raw", "D0/D2",
      "exec_run dmesg --color=never; -c/--clear 为 W2"),
    O("SYS-05", "systemd/服务/日志/启动", "启动链 A/B/内核参数",
      ["cmd:aik-upgrade", "cmd:ls", "file:/proc/cmdline", "file:/boot/grub/grubenv"],
      ["cmd:aik-upgrade"], "structured", "D0/D3",
      "aik-upgrade status (R verb); ls /boot; cat /proc/cmdline"),
    O("SYS-06", "systemd/服务/日志/启动", "启动耗时",
      ["cmd:systemd-analyze"], [], "structured", "D0",
      "systemd-analyze; systemd-analyze blame", write_na=True),
    O("SYS-07", "systemd/服务/日志/启动", "timers/计划任务总览",
      ["cmd:systemctl", "file:/etc/cron.d"],
      ["cmd:systemctl"], "structured", "D0/D3",
      "systemctl list-timers --no-pager; ls /etc/cron.d"),
    O("SYS-08", "systemd/服务/日志/启动", "unit 配置/drop-in",
      ["cmd:cat", "file:/etc/systemd/system"],
      ["escape:sys_shell"], "raw", "D0/D2",
      "仅 cat 读；写只能 sys_shell/systemctl edit，无结构化写工具",
      gap="G-011"),

    # ---------------- 网络 ----------------
    O("NET-01", "网络/接口/地址/路由/DNS/防火墙/命名空间", "接口/链路/网卡诊断",
      ["cmd:ip", "cmd:ethtool", "tool:sysfs_get"],
      ["cmd:ip", "tool:sysfs_set"], "structured", "D0/D2",
      "ip -j link; ethtool <if>; sysfs_get /sys/class/net/<if>/statistics",
      gap="G-019"),
    O("NET-02", "网络/接口/地址/路由/DNS/防火墙/命名空间", "地址/路由",
      ["cmd:ip", "file:/proc/net/route"],
      ["cmd:ip"], "structured", "D0/D2",
      "ip -j addr; ip -j route; cat /proc/net/route"),
    O("NET-03", "网络/接口/地址/路由/DNS/防火墙/命名空间", "连接/套接字",
      ["cmd:ss", "file:/proc/net/tcp", "file:/proc/net/udp"],
      ["cmd:conntrack"], "structured", "D0/D2",
      "ss -tunap; cat /proc/net/tcp"),
    O("NET-04", "网络/接口/地址/路由/DNS/防火墙/命名空间", "conntrack 连接跟踪",
      ["tool:procfs_read_net_nf_conntrack", "file:/proc/net/nf_conntrack"],
      ["cmd:conntrack"], "structured", "D0/D2",
      "procfs_read_net_nf_conntrack; conntrack -L（VM 缺失）", gap="G-020"),
    O("NET-05", "网络/接口/地址/路由/DNS/防火墙/命名空间", "DNS 解析配置",
      ["cmd:resolvectl", "tool:config_read_resolv_conf"],
      ["tool:config_write_resolv_conf", "cmd:resolvectl"], "structured", "D0/D2",
      "resolvectl status; config_read_resolv_conf"),
    O("NET-06", "网络/接口/地址/路由/DNS/防火墙/命名空间", "防火墙/LSM 策略",
      ["tool:config_read_nftables", "cmd:aa-status", "file:/sys/kernel/security/apparmor"],
      ["tool:config_write_nftables", "cmd:nft"], "raw", "D0/D3",
      "config_read_nftables; nft list ruleset（W2）；aa-status（VM 缺失）",
      gap="G-021/G-028"),
    O("NET-07", "网络/接口/地址/路由/DNS/防火墙/命名空间", "网络命名空间",
      ["cmd:ip", "file:/proc/1/ns/net"],
      ["cmd:ip"], "structured", "D0/D2",
      "ip netns list; ls -l /proc/<pid>/ns/net; ip netns add（W2）",
      gap="G-034"),
    O("NET-08", "网络/接口/地址/路由/DNS/防火墙/命名空间", "接口配置/qdisc",
      ["cmd:ip", "file:/sys/class/net"],
      ["cmd:tc", "cmd:ip", "tool:sysfs_set"], "structured", "D0/D3",
      "ip -d link; tc qdisc show（W2）；sysfs_set /sys/class/net/..."),

    # ---------------- 用户/组/会话/sudo/policy ----------------
    O("ID-01", "用户/组/会话/sudo/policy/租约", "用户账户",
      ["cmd:getent", "file:/etc/passwd"],
      ["cmd:useradd", "cmd:usermod", "cmd:userdel"], "structured", "D0/D3",
      "getent passwd; cat /etc/passwd"),
    O("ID-02", "用户/组/会话/sudo/policy/租约", "组/成员",
      ["cmd:getent", "file:/etc/group"],
      ["cmd:groupadd", "cmd:groupmod", "cmd:groupdel"], "structured", "D0/D3",
      "getent group; cat /etc/group"),
    O("ID-03", "用户/组/会话/sudo/policy/租约", "登录会话",
      ["cmd:ps", "file:/proc/1/loginuid"],
      [], "raw", "D0", "ps -eo user,tty,stat,comm; cat /proc/<pid>/loginuid",
      gap="G-025", write_na=True),
    O("ID-04", "用户/组/会话/sudo/policy/租约", "sudoers",
      ["file:/etc/sudoers", "cmd:cat"],
      ["escape:sys_shell"], "raw", "D0/D4",
      "cat /etc/sudoers（root-only）；visudo 只能 shell", gap="G-012"),
    O("ID-05", "用户/组/会话/sudo/policy/租约", "授权策略/租约",
      ["file:/etc/aikernel/policy.conf", "cmd:cat", "file:/etc/aikernel/tools.json",
       "principal:/lease list|show", "principal:--lease"],
      ["principal:/lease issue|revoke|confirm"], "structured", "D0/D4",
      "cat /var/lib/aikernel/leases/*.json（R，raw JSON）；/lease list|show（Principal root+TTY）；--lease <id> 加载；W74 已落地",
      gap="G-001/G-012"),
    O("ID-06", "用户/组/会话/sudo/policy/租约", "SSH 服务配置",
      ["tool:config_read_sshd_config"],
      ["tool:config_write_sshd_config"], "structured", "D0/D3",
      "config_read_sshd_config; config_write_sshd_config（W2）"),
    O("ID-07", "用户/组/会话/sudo/policy/租约", "SSH authorized_keys",
      ["file:/root/.ssh/authorized_keys", "cmd:ls"],
      ["escape:sys_shell"], "raw", "D0/D4",
      "ls -l /root/.ssh; cat authorized_keys（root-only）；ssh-keygen 只能 shell",
      gap="G-013"),
    O("ID-08", "用户/组/会话/sudo/policy/租约", "SSH 主机密钥状态",
      ["cmd:ls", "cmd:stat", "file:/etc/ssh/ssh_host_ed25519_key.pub"],
      ["escape:sys_shell"], "structured", "D0/D4",
      "ls -l /etc/ssh/ssh_host_*; stat；仅状态，不读私钥",
      gap="G-013"),

    # ---------------- 包管理 ----------------
    O("PKG-01", "包管理/仓库/版本/依赖/更新", "已安装包",
      ["file:/var/lib/dpkg/status", "cmd:dpkg"],
      ["cmd:dpkg"], "raw", "D0/D3",
      "cat /var/lib/dpkg/status（原始）；dpkg -l（W2）", gap="G-009"),
    O("PKG-02", "包管理/仓库/版本/依赖/更新", "仓库/源",
      ["file:/etc/apt/sources.list", "file:/etc/apt/sources.list.d"],
      ["cmd:apt"], "raw", "D0/D3",
      "cat /etc/apt/sources.list; ls /etc/apt/sources.list.d", gap="G-009"),
    O("PKG-03", "包管理/仓库/版本/依赖/更新", "可用更新",
      ["cmd:apt"], ["cmd:apt"], "raw", "D0/D3",
      "apt list --upgradable（整体 W2，无 R 路径）", gap="G-010"),
    O("PKG-04", "包管理/仓库/版本/依赖/更新", "安装/卸载/升级",
      ["cmd:dpkg"], ["cmd:apt", "cmd:dpkg"], "raw", "D0/D3",
      "apt install/remove/upgrade（W2，300s）", gap="G-009"),
    O("PKG-05", "包管理/仓库/版本/依赖/更新", "依赖/版本/内核模块",
      ["file:/var/lib/dpkg/status", "cmd:dpkg", "cmd:uname"],
      [], "raw", "D0", "dpkg -s <pkg>（W2）；cat /var/lib/dpkg/status；uname -r",
      gap="G-022", write_na=True),

    # ---------------- 硬件 ----------------
    O("HW-01", "硬件/CPU/GPU/温度/电源/设备树", "CPU 硬件",
      ["cmd:lscpu", "file:/proc/cpuinfo", "tool:sysfs_get"],
      ["tool:sysfs_set"], "structured", "D0/D2",
      "lscpu -J; sysfs_get /sys/devices/system/cpu/cpu0/topology"),
    O("HW-02", "硬件/CPU/GPU/温度/电源/设备树", "GPU/显示",
      ["tool:sysfs_get", "file:/sys/class/drm"],
      [], "raw", "D0", "sysfs_get /sys/class/drm/card0/device/...",
      gap="G-023", write_na=True),
    O("HW-03", "硬件/CPU/GPU/温度/电源/设备树", "温度/风扇",
      ["tool:sysfs_get", "file:/sys/class/hwmon", "file:/sys/class/thermal"],
      [], "raw", "D0", "sysfs_get /sys/class/hwmon/hwmon0/temp1_input; thermal_zone*/temp",
      gap="G-023", write_na=True),
    O("HW-04", "硬件/CPU/GPU/温度/电源/设备树", "电源/电池",
      ["tool:sysfs_get", "file:/sys/class/power_supply"],
      [], "raw", "D0", "sysfs_get /sys/class/power_supply/ACAD/online; capacity/status",
      write_na=True),
    O("HW-05", "硬件/CPU/GPU/温度/电源/设备树", "PCI/USB/设备树",
      ["tool:sysfs_get", "file:/sys/bus/pci/devices", "cmd:ls"],
      [], "raw", "D0", "ls /sys/bus/pci/devices; /sys/firmware/devicetree（x86 N/A）",
      gap="G-023/G-027", write_na=True),

    # ---------------- 内核 AI 遥测 ----------------
    O("AI-01", "内核 AI 遥测 /proc/ai/*、netlink、KUnit", "/proc/ai/status",
      ["tool:procfs_read_status", "vmfile:/proc/ai/status"],
      ["tool:sysfs_write_enabled"], "structured", "D0/D1",
      "procfs_read_status; cat /proc/ai/status（VM #59 实测）"),
    O("AI-02", "内核 AI 遥测 /proc/ai/*、netlink、KUnit", "/proc/ai/control 参数表",
      ["tool:procfs_read_control", "vmfile:/proc/ai/control"],
      ["tool:netlink_act_sched_nice", "tool:netlink_act_mm_swappiness",
       "tool:netlink_act_io_priority", "tool:netlink_act_net_cwnd",
       "tool:netlink_act_power_freq"], "structured", "D0/D2",
      "procfs_read_control；27 参数文本行", gap="G-029"),
    O("AI-03", "内核 AI 遥测 /proc/ai/*、netlink、KUnit", "决策/因果链",
      ["tool:procfs_read_decisions", "tool:procfs_read_chains",
       "vmfile:/proc/ai/decisions"],
      ["tool:netlink_act_ai_decision_inject"], "structured", "D0/D2",
      "procfs_read_decisions; procfs_read_chains"),
    O("AI-04", "内核 AI 遥测 /proc/ai/*、netlink、KUnit", "遥测/netlink SENSE",
      ["tool:procfs_read_telemetry", "tool:netlink_sense"],
      ["tool:procfs_write_telemetry_format", "tool:procfs_write_telemetry_reset"],
      "structured", "D0/W1/W2", "procfs_read_telemetry; netlink_sense"),
    O("AI-05", "内核 AI 遥测 /proc/ai/*、netlink、KUnit", "AI 统计计数",
      ["tool:procfs_read_stats_telemetry_emitted",
       "tool:procfs_read_stats_decisions_total",
       "tool:procfs_read_stats_runtime_state", "tool:procfs_read_hitrate"],
      [], "structured", "D0", "procfs_read_stats_*; procfs_read_hitrate",
      write_na=True),
    O("AI-06", "内核 AI 遥测 /proc/ai/*、netlink、KUnit", "内核模型加载/推理",
      ["tool:procfs_read_model_out", "tool:procfs_read_status"],
      ["tool:sysfs_write_model_load", "tool:sysfs_write_model_unload",
       "tool:sysfs_write_model_infer"], "structured", "D0/D1",
      "procfs_read_model_out; sysfs_write_model_infer（W1）"),
    O("AI-07", "内核 AI 遥测 /proc/ai/*、netlink、KUnit", "策略/回滚",
      ["tool:procfs_read_decision_stats", "tool:procfs_read_hitrate"],
      ["tool:sysfs_write_policy_global_enable", "tool:sysfs_write_policy_rollback",
       "tool:sysfs_write_policy_think", "tool:sysfs_write_policy_outcome"],
      "structured", "D0/W1", "procfs_read_decision_stats; policy/* 写 W1"),
    O("AI-08", "内核 AI 遥测 /proc/ai/*、netlink、KUnit", "KUnit/内核测试",
      ["cmd:dmesg", "file:/sys/kernel/debug/kunit"],
      [], "raw", "D0", "dmesg | grep -i kunit; ls /sys/kernel/debug/kunit（VM 空）",
      gap="G-017", write_na=True),

    # ---------------- SME/trace/训练 ----------------
    O("MEM-01", "SME 记忆/trace/训练导出", "SME 健康/统计",
      ["tool:memory_health", "tool:memory_stats"],
      [], "semantic", "D0", "memory_health; memory_stats", write_na=True),
    O("MEM-02", "SME 记忆/trace/训练导出", "记忆 CRUD/检索",
      ["tool:memory_search", "tool:memory_search_advanced", "tool:memory_get"],
      ["tool:memory_add", "tool:memory_batch_add", "tool:memory_update",
       "tool:memory_delete", "tool:memory_hit", "tool:memory_archive",
       "tool:memory_restore", "tool:memory_import"], "semantic", "D0/W1/W2",
      "memory_search; memory_add; memory_delete（W2）"),
    O("MEM-03", "SME 记忆/trace/训练导出", "事实图谱/多跳",
      ["tool:memory_facts", "tool:memory_graph", "tool:memory_facts_multi_hop",
       "tool:memory_facts_history"],
      ["tool:memory_link"], "semantic", "D0/W1",
      "memory_facts; memory_graph; memory_facts_multi_hop"),
    O("MEM-04", "SME 记忆/trace/训练导出", "Region 空间聚类",
      ["tool:memory_regions", "tool:memory_regions_search"],
      ["tool:memory_regions_evolve"], "semantic", "D0/W1",
      "memory_regions; memory_regions_search"),
    O("MEM-05", "SME 记忆/trace/训练导出", "QA/画像/指标/配置",
      ["tool:memory_qapairs", "tool:memory_profile", "tool:memory_metrics",
       "tool:memory_config_get", "tool:memory_config_check"],
      [], "semantic", "D0", "memory_qapairs; memory_profile; memory_metrics",
      write_na=True),
    O("MEM-06", "SME 记忆/trace/训练导出", "trace JSONL 文件",
      ["file:/var/log/aikernel/trace", "file:~/.aikernel/trace", "cmd:cat"],
      [], "structured", "D0", "cat/head/tail trace-*.jsonl; root path /var/log/aikernel/trace",
      gap="G-003", write_na=True),
    O("MEM-07", "SME 记忆/trace/训练导出", "训练导出",
      ["escape:python3"], ["escape:python3"], "raw", "D0/D2",
      "无 trace.export 工具；只能 python3 解析 JSONL 重组训练行", gap="G-003"),
    O("MEM-08", "SME 记忆/trace/训练导出", "会话历史",
      ["file:~/.aikernel/sessions", "file:/var/log/aikernel/sessions", "cmd:cat"],
      [], "structured", "D0", "cat ~/.aikernel/sessions/*.jsonl；无 session 工具",
      gap="G-003", write_na=True),

    # ---------------- 沙箱 ----------------
    O("SB-01", "沙箱", "隔离区列表/状态/资源限额",
      ["tool:sandbox_status", "file:/sandbox", "tool:sysfs_get"],
      ["tool:sandbox_create", "tool:sysfs_set"], "structured", "D0/D2",
      "sandbox_status; ls /sandbox; sysfs_get /sys/fs/cgroup/..."),
    O("SB-02", "沙箱", "沙箱资源限制",
      ["tool:sandbox_status", "tool:sysfs_get", "file:/sys/fs/cgroup"],
      ["tool:sysfs_set"], "structured", "D0/D2",
      "sandbox_status 显示 cgroup/限额; sysfs_get cgroup cpu.max/memory.max"),
    O("SB-03", "沙箱", "隔离区产物/残留",
      ["tool:sandbox_status", "cmd:ls"],
      ["tool:sandbox_destroy"], "structured", "D0/D1",
      "sandbox_status; ls -la /sandbox/<name>"),
    O("SB-04", "沙箱", "spawn/destroy 生命周期",
      ["tool:sandbox_status"],
      ["tool:sandbox_spawn", "tool:sandbox_destroy"], "structured", "D0/W1/W2",
      "sandbox_spawn（W2）; sandbox_destroy（W1）"),
    O("SB-05", "沙箱", "子智能体工具面/子会话 trace",
      ["file:/usr/local/share/aikernel/tools-sandbox.json", "tool:sandbox_status"],
      [], "structured", "D0", "cat tools-sandbox.json; sandbox_status",
      gap="G-016", write_na=True),

    # ---------------- 桌面 ----------------
    O("DT-01", "桌面", "桌面健康/统计",
      ["tool:desktop_health", "tool:desktop_stats"],
      [], "semantic", "D0", "desktop_health; desktop_stats; GET /api/health|stats",
      write_na=True),
    O("DT-02", "桌面", "应用枚举/启动/关闭",
      ["tool:desktop_apps_list"],
      ["tool:desktop_apps_launch", "tool:desktop_apps_close"], "semantic", "D0/D1/D2",
      "desktop_apps_list/launch/close（51 apps；10-task 01/05）"),
    O("DT-03", "桌面", "窗口",
      ["tool:desktop_windows_list"],
      ["tool:desktop_windows_focus", "tool:desktop_windows_close"], "structured", "D0/D1/D2",
      "desktop_windows_list/focus/close；id/geometry/focused/visible/z/text（10-task 04/05）"),
    O("DT-04", "桌面", "主题/壁纸",
      ["tool:desktop_theme_get", "tool:desktop_wallpaper_get"],
      ["tool:desktop_theme_set", "tool:desktop_wallpaper_set"], "semantic", "D0/D1",
      "desktop_theme_get/set; desktop_wallpaper_get/set；回读/恢复（10-task 02/03）"),
    O("DT-05", "桌面", "通知",
      ["tool:desktop_notifications_list"],
      ["tool:desktop_notifications_send"], "semantic", "D0/D1",
      "desktop_notifications_list/send；追加不覆盖历史（10-task 09）"),
    O("DT-06", "桌面", "输入注入（键鼠）",
      [], ["tool:desktop_input_type", "tool:desktop_input_key"], "none", "D2",
      "desktop_input_type/key（D2）；读无“输入历史”对象，窗口文本经 desktop_windows_list 观察（10-task 07/08）"),
    O("DT-07", "桌面", "截图",
      ["tool:desktop_screenshot"], [], "structured", "D0",
      "desktop_screenshot；path/bytes/sha256/width/height，>30KB/colors 防白屏（10-task 06/07b）",
      write_na=True),
    O("DT-08", "桌面", "剪贴板",
      ["tool:desktop_clipboard_get"],
      ["tool:desktop_clipboard_set"], "structured", "D0/D2",
      "desktop_clipboard_get/set；previous 恢复（10-task 10）"),
    O("DT-09", "桌面", "聊天/会话/电源",
      ["api:GET /api/chat/history", "api:GET /api/chat/sessions"],
      ["apiw:POST /api/chat"], "semantic", "D0/D3",
      "chat 仍 exec_run curl（有效 W2）；desktop_power D3 已注册但 /api/power 501 unavailable，不计有效写；G-033 保持开放",
      gap="G-033"),

    # ---------------- 时间/NTP/cron ----------------
    O("TIME-01", "时间/NTP/cron/timers/SSH", "时钟/NTP",
      ["cmd:timedatectl", "file:/etc/timezone"],
      ["cmd:timedatectl"], "structured", "D0/D3",
      "timedatectl show; timedatectl timesync-status; set-* 为 W2"),
    O("TIME-02", "时间/NTP/cron/timers/SSH", "用户 crontab",
      ["cmd:crontab", "file:/var/spool/cron/crontabs"],
      ["cmd:crontab"], "raw", "D0/D2",
      "crontab -l（W2；VM 二进制缺失、spool 不存在）", gap="G-026"),
    O("TIME-03", "时间/NTP/cron/timers/SSH", "系统 cron/timers",
      ["cmd:ls", "file:/etc/crontab", "file:/etc/cron.d", "cmd:systemctl"],
      [], "structured", "D0", "cat /etc/crontab; ls /etc/cron.d; systemctl list-timers",
      gap="G-026"),
]


# ---------------------------------------------------------------------------
# Probing helpers
# ---------------------------------------------------------------------------

def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def which_bin(path, name):
    if path and os.path.isfile(path) and os.access(path, os.X_OK):
        return True
    found = shutil.which(name)
    return bool(found and os.access(found, os.X_OK))


def principal_impl(root, val):
    """W74 Principal-only lease CLI: implemented in source, not an Agent tool."""
    base = [
        os.path.join(root, "policy", "ai_lease.c"),
        os.path.join(root, "policy", "ai_lease.h"),
        os.path.join(root, "shell", "commands", "cmd_lease.c"),
    ]
    if not all(os.path.isfile(p) for p in base):
        return False
    if val == "--lease":
        return "--lease" in read_text(os.path.join(root, "shell", "aikernel_main.c"))
    reg = read_text(os.path.join(root, "shell", "commands", "commands_registry.c"))
    return "cmd_lease" in reg or '"lease"' in reg


def api_get(url, timeout=2.0):
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(1024)
            return 200 <= r.status < 300, r.status
    except Exception as e:
        code = getattr(e, "code", None)
        return False, code


def vm_probe(host, files, bins, timeout=8):
    """One read-only SSH call: test -e paths, test -x bins. No writes."""
    if not host:
        return set(), set(), False
    script = []
    for p in sorted(set(files)):
        q = shlex.quote(p)
        script.append("if [ -e %s ]; then echo 'F|%s|1'; else echo 'F|%s|0'; fi"
                      % (q, p.replace("|", "_"), p.replace("|", "_")))
    for name, path in sorted(set(bins.items())):
        q = shlex.quote(path)
        script.append("if [ -x %s ]; then echo 'B|%s|1'; else echo 'B|%s|0'; fi"
                      % (q, name.replace("|", "_"), name.replace("|", "_")))
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
           host, "bash", "-s"]
    try:
        p = subprocess.run(cmd, input="\n".join(script) + "\n",
                           text=True, capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return set(), set(), False
    vm_files, vm_bins = set(), set()
    for line in p.stdout.splitlines():
        parts = line.split("|")
        if len(parts) == 3 and parts[2] == "1":
            if parts[0] == "F":
                vm_files.add(parts[1])
            elif parts[0] == "B":
                vm_bins.add(parts[1])
    return vm_files, vm_bins, p.returncode == 0


# ---------------------------------------------------------------------------
# Source / registry scan
# ---------------------------------------------------------------------------

def scan_registry(root):
    tools_path = os.path.join(root, "tools", "tools.json")
    sandbox_path = os.path.join(root, "tools", "tools-sandbox.json")
    openai_path = os.path.join(root, "tools", "tools.openai.json")
    doc = json.load(open(tools_path, encoding="utf-8"))
    sb = json.load(open(sandbox_path, encoding="utf-8"))
    tools = doc.get("tools", [])
    sb_tools = sb.get("tools", [])
    channels = Counter(t.get("channel") for t in tools)
    risks = Counter(t.get("risk", "exec按命令" if t.get("channel") == "exec" else "?")
                    for t in tools)
    domains = Counter(t["sub"][0] for t in tools if t.get("sub"))
    all_domains = sorted({s for t in tools for s in t.get("sub", [])})
    names = [t["name"] for t in tools]
    tool_names_sha256 = hashlib.sha256(("\n".join(names) + "\n").encode("utf-8")).hexdigest()
    desktop_tools = [t for t in tools if t.get("channel") == "desktop"]
    dup = sorted({n for n in names if names.count(n) > 1})
    seed_path = os.path.join(root, "tools", "sme-seed-w51.jsonl")
    seed_count = 0
    seed_kinds = Counter()
    seed_errors = []
    try:
        with open(seed_path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError as exc:
                    seed_errors.append("line %d: %s" % (lineno, exc))
                    continue
                seed_count += 1
                seed_kinds[(rec.get("metadata") or {}).get("kind")] += 1
    except OSError as exc:
        seed_errors.append(str(exc))
    exec_cmds = []
    for t in tools:
        if t.get("channel") == "exec":
            exec_cmds = t.get("exec", {}).get("commands", [])
    sb_cmds = []
    for t in sb_tools:
        if t.get("channel") == "exec":
            sb_cmds = t.get("exec", {}).get("commands", [])
    openai_count = 0
    try:
        od = json.load(open(openai_path, encoding="utf-8"))
        if isinstance(od, list):
            openai_count = len(od)
        elif isinstance(od, dict):
            openai_count = len(od.get("tools", []))
        else:
            openai_count = 0
    except (OSError, ValueError):
        pass

    src = read_text(os.path.join(root, "tools", "executor.c"))
    impl_diff = []
    for t in tools:
        ch = t.get("channel")
        if ch not in CHANNEL_CASE:
            impl_diff.append({"tool": t["name"], "reason": "unknown channel"})
            continue
        if ch == "procfs-read" and not t.get("path"):
            impl_diff.append({"tool": t["name"], "reason": "missing path"})
        if ch == "sysfs-write" and not t.get("path"):
            impl_diff.append({"tool": t["name"], "reason": "missing path"})
        if ch == "netlink-act" and not t.get("param"):
            impl_diff.append({"tool": t["name"], "reason": "missing param"})
        if ch == "exec" and not t.get("exec", {}).get("commands"):
            impl_diff.append({"tool": t["name"], "reason": "missing exec.commands"})
    for ch, case in CHANNEL_CASE.items():
        if ("case " + case) not in src:
            impl_diff.append({"tool": "*", "reason": "executor missing " + case})
    for t in tools:
        if t.get("channel") == "memory" and t["name"] not in src:
            impl_diff.append({"tool": t["name"], "reason": "memory handler not referenced"})
    for t in tools:
        if t.get("channel") == "sandbox" and t["name"] not in src:
            impl_diff.append({"tool": t["name"], "reason": "sandbox handler not referenced"})
    for t in tools:
        if t.get("channel") == "sysctl" and t["name"] not in src:
            impl_diff.append({"tool": t["name"], "reason": "sysctl handler not referenced"})
    for t in desktop_tools:
        if t["name"] not in src:
            impl_diff.append({"tool": t["name"], "reason": "desktop handler not referenced"})

    return {
        "tools_path": tools_path,
        "sandbox_path": sandbox_path,
        "tools_sha256": sha256_file(tools_path),
        "sandbox_sha256": sha256_file(sandbox_path),
        "seed_path": seed_path,
        "seed_sha256": sha256_file(seed_path),
        "seed_count": seed_count,
        "seed_kinds": dict(sorted((str(k), v) for k, v in seed_kinds.items())),
        "seed_errors": seed_errors,
        "generated_at": doc.get("generated_at", ""),
        "tool_count": len(tools),
        "declared_tool_count": doc.get("tool_count"),
        "tool_names_sha256": tool_names_sha256,
        "desktop_tool_count": len(desktop_tools),
        "sandbox_tool_count": len(sb_tools),
        "openai_tool_count": openai_count,
        "domains": all_domains,
        "domain_count": len(all_domains),
        "primary_domain_counts": dict(sorted(domains.items())),
        "channel_counts": dict(sorted(channels.items())),
        "risk_counts": dict(sorted(risks.items())),
        "exec_command_count": len(exec_cmds),
        "sandbox_command_count": len(sb_cmds),
        "exec_commands": exec_cmds,
        "sandbox_commands": sb_cmds,
        "tools": tools,
        "sandbox_tools": sb_tools,
        "duplicate_names": dup,
        "implementation_diff": impl_diff,
    }


def scan_curl_risk(root):
    """Read tests/exec_risk_cases.tsv and count curl write/deny shapes.

    This is evidence that curl's effective risk is command-line dependent
    (exec_dyn_scan), not the top-level registry risk `R`.
    """
    path = os.path.join(root, "tests", "exec_risk_cases.tsv")
    text = read_text(path)
    flags = ["-d", "--data", "--data-raw", "--data-binary", "--json",
             "-F", "--form", "--form-string", "-T", "--upload-file",
             "-X", "--request", "-o", "--output", "-D", "--dump-header",
             "-c", "--cookie-jar"]
    counts = Counter()
    covered = set()
    present = False
    for line in text.splitlines():
        parts = line.split("	")
        if len(parts) >= 4 and parts[0] == "curl":
            present = True
            counts[parts[2]] += 1
            if parts[2] in ("W2", "DENY"):
                for fl in flags:
                    if fl in parts[1]:
                        covered.add(fl)
    return {"path": path, "present": present, "w2": counts.get("W2", 0),
            "deny": counts.get("DENY", 0), "r": counts.get("R", 0),
            "write_flags": sorted(covered)}


def scan_source(root):
    dirs = ["runtime/netlink", "trace", "memory", "sandbox", "shell/commands",
            "docs", "tools"]
    out = {}
    for d in dirs:
        p = os.path.join(root, d)
        try:
            files = sorted(os.listdir(p))
        except OSError:
            files = []
        out[d] = {
            "files": len(files),
            "c_files": len([f for f in files if f.endswith(".c")]),
            "h_files": len([f for f in files if f.endswith(".h")]),
            "py_files": len([f for f in files if f.endswith(".py")]),
        }
    out["docs_claims"] = scan_doc_claims(root)
    out["desktop"] = scan_desktop(root)
    out["curl_risk"] = scan_curl_risk(root)
    return out


def scan_doc_claims(root):
    claims = {}
    arch = read_text(os.path.join(root, "docs", "ARCHITECTURE-MATRIX.md"))
    gen = read_text(os.path.join(root, "tools", "gen_registry.py"))
    claims["arch_mentions_97_commands"] = "97 命令" in arch or "97 条命令" in arch
    claims["arch_mentions_55_sandbox_commands"] = "55 命令" in arch
    claims["arch_mentions_16_missing"] = "16 个二进制" in arch
    claims["arch_mentions_130_130"] = "130/130" in arch
    m = re.search(r"sha256\s*`?([0-9a-f]{64})", arch)
    claims["arch_tools_sha256"] = m.group(1) if m else ""
    m = re.search(r"生成时间\s*([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]+)", arch)
    claims["arch_generated_at"] = m.group(1) if m else ""
    claims["gen_docstring_79"] = "EXPECTED_TOOL_COUNT(79)" in gen
    return claims


def scan_desktop(root):
    candidates = [
        os.path.join(root, "..", "..", "..", "fix-w48gui", "img1"),
        os.path.expanduser("~/fix-w48gui/img1"),
        "/home/jack66g/fix-w48gui/img1",
    ]
    for p in candidates:
        sp = os.path.join(p, "server.py")
        if os.path.isfile(sp):
            text = read_text(sp)
            gets = sorted(set(re.findall(r'path == "(/api/[^"]+)"', text)))
            posts = sorted(set(re.findall(r'u\.path == "(/api/[^"]+)"', text)))
            return {"path": os.path.abspath(p), "server_py": True,
                    "get_routes": gets, "post_routes": posts,
                    "has_windows": "windows" in text.lower(),
                    "has_clipboard": "clipboard" in text.lower(),
                    "has_input": ("input" in text.lower() and "/api/input" in text),
                    "has_screenshot_api": "/api/screenshot" in text}
    return {"path": "", "server_py": False, "get_routes": [], "post_routes": [],
            "has_windows": False, "has_clipboard": False, "has_input": False,
            "has_screenshot_api": False}


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

class Evaluator:
    def __init__(self, root, reg, src, vm_files, vm_bins, desktop):
        self.root = root
        self.reg = reg
        self.src = src
        self.vm_files = vm_files
        self.vm_bins = vm_bins
        self.desktop = desktop
        self.tools = {t["name"]: t for t in reg["tools"]}
        self.exec_map = {}
        for c in reg["exec_commands"]:
            self.exec_map[c["command"]] = c
        # Commands whose base risk is R but whose args0 subcommands include
        # writes (systemctl/timedatectl/hostnamectl/resolvectl/conntrack...).
        self.args0_write = {}
        self.args0_read = {}
        for name, c in self.exec_map.items():
            verbs = c.get("args0", []) or []
            self.args0_write[name] = any(v.get("risk") in ("W1", "W2") for v in verbs)
            self.args0_read[name] = any(v.get("risk") == "R" for v in verbs)
        # exec_dyn_scan in executor.c marks these as writes even though the
        # registry-level risk is R (ip/ethtool).
        self.dyn_write = {"ip": "W2", "ethtool": "W1", "journalctl": "W1", "dmesg": "W2"}
        self.host_api = {}
        self.tool_paths = {}
        for t in reg["tools"]:
            if t.get("path"):
                self.tool_paths[t["name"]] = t["path"]
        for t in reg["sandbox_tools"]:
            if t.get("path"):
                self.tool_paths[t["name"]] = t["path"]

    def host_file(self, path):
        p = os.path.expanduser(path)
        exists = os.path.exists(p)
        readable = os.access(p, os.R_OK)
        rootonly = False
        if exists and not readable:
            try:
                mode = os.stat(p).st_mode & 0o777
                rootonly = mode & 0o077 == 0
            except OSError:
                pass
        return exists, readable, rootonly, p

    def eval_read(self, token):
        kind, _, val = token.partition(":")
        if kind == "tool":
            t = self.tools.get(val)
            if not t:
                return {"token": token, "ok": False, "live": False,
                        "tier": "absent", "detail": "not registered"}
            risk = t.get("risk", "")
            tier = "direct" if risk == "R" else "gated"
            live = True
            detail = "registered risk=" + (risk or "-")
            path = t.get("path")
            if path:
                he, hr, hro, _ = self.host_file(path)
                ve = path in self.vm_files
                live = hr or hro or ve
                detail += "; node=" + ("vm" if ve else "host" if he else "absent")
            probe = t.get("probe")
            if probe:
                he, hr, hro, _ = self.host_file(probe)
                ve = probe in self.vm_files
                if not (hr or hro or ve):
                    live = False
            if t.get("channel") == "sandbox":
                live = which_bin("/usr/local/bin/aik-sandbox", "aik-sandbox") or ("aik-sandbox" in self.vm_bins)
            return {"token": token, "ok": True, "live": live, "tier": tier,
                    "detail": detail}
        if kind == "cmd":
            c = self.exec_map.get(val)
            if not c:
                return {"token": token, "ok": False, "live": False,
                        "tier": "absent", "detail": "not whitelisted"}
            present = which_bin(c.get("bin", ""), val) or (val in self.vm_bins)
            risk = c.get("risk", "?")
            direct = (risk == "R") or self.args0_read.get(val, False)
            tier = "direct" if direct else "gated"
            return {"token": token, "ok": present, "live": present, "tier": tier,
                    "detail": "risk=%s bin=%s present=%s" % (risk, c.get("bin", ""), present)}
        if kind == "file":
            he, hr, hro, p = self.host_file(val)
            ve = val in self.vm_files
            ok = he or ve
            live = hr or hro or ve
            return {"token": token, "ok": ok, "live": live, "tier": "direct",
                    "detail": "host exists=%s readable=%s rootonly=%s vm=%s" % (he, hr, hro, ve)}
        if kind == "vmfile":
            ve = val in self.vm_files
            return {"token": token, "ok": ve, "live": ve, "tier": "direct",
                    "detail": "vm exists=%s" % ve}
        if kind == "api":
            path = val.split(" ", 1)[1] if " " in val else val
            if path not in self.host_api:
                self.host_api[path] = api_get("http://127.0.0.1:8091" + path)
            ok, code = self.host_api[path]
            return {"token": token, "ok": ok, "live": ok, "tier": "direct",
                    "detail": "GET %s -> %s" % (path, code)}
        if kind == "escape":
            if val == "python3":
                c = self.exec_map.get("python3")
                present = bool(c) and (which_bin(c.get("bin", ""), "python3") or "python3" in self.vm_bins)
                return {"token": token, "ok": present, "live": present,
                        "tier": "escape", "detail": "W2 arbitrary code"}
            if val == "sys_shell":
                t = self.tools.get("sys_shell")
                return {"token": token, "ok": bool(t), "live": bool(t),
                        "tier": "escape", "detail": "interactive host TTY only"}
            return {"token": token, "ok": False, "live": False, "tier": "absent",
                    "detail": "unknown escape"}
        if kind == "principal":
            ok = principal_impl(self.root, val)
            return {"token": token, "ok": ok, "live": ok, "tier": "gated",
                    "detail": "Principal-only root+TTY; implemented=%s; not an Agent tool" % ok}
        return {"token": token, "ok": False, "live": False, "tier": "absent",
                "detail": "unknown token"}

    def eval_write(self, token):
        kind, _, val = token.partition(":")
        if kind == "tool":
            t = self.tools.get(val)
            if not t:
                return {"token": token, "ok": False, "tier": "absent",
                        "detail": "not registered"}
            risk = t.get("risk", "")
            if risk not in ("W1", "W2"):
                return {"token": token, "ok": False, "tier": "read-only",
                        "detail": "risk=%s" % risk}
            return {"token": token, "ok": True, "tier": "direct" if risk == "W1" else "gated",
                    "detail": "risk=%s" % risk}
        if kind == "cmd":
            c = self.exec_map.get(val)
            if not c:
                return {"token": token, "ok": False, "tier": "absent",
                        "detail": "not whitelisted"}
            present = which_bin(c.get("bin", ""), val) or (val in self.vm_bins)
            risk = c.get("risk", "?")
            eff = risk
            if eff not in ("W1", "W2") and self.args0_write.get(val, False):
                eff = "W2"
            if val in self.dyn_write:
                eff = self.dyn_write[val]
            ok = present and eff in ("W1", "W2")
            return {"token": token, "ok": ok, "tier": "direct" if eff == "W1" else "gated",
                    "detail": "risk=%s effective=%s present=%s" % (risk, eff, present)}
        if kind == "apiw":
            # Static route check only; never POST in the audit.
            path = val.split(" ", 1)[1] if " " in val else val
            routes = self.desktop.get("post_routes", [])
            ok = path in routes
            return {"token": token, "ok": ok, "tier": "direct",
                    "detail": "POST route present=%s" % ok}
        if kind == "escape":
            if val == "python3":
                c = self.exec_map.get("python3")
                present = bool(c) and (which_bin(c.get("bin", ""), "python3") or "python3" in self.vm_bins)
                return {"token": token, "ok": present, "tier": "escape",
                        "detail": "W2 arbitrary code"}
            if val == "sys_shell":
                return {"token": token, "ok": "sys_shell" in self.tools,
                        "tier": "escape", "detail": "interactive host TTY only"}
        if kind == "principal":
            ok = principal_impl(self.root, val)
            return {"token": token, "ok": ok, "tier": "principal",
                    "detail": "Principal-only root+TTY; AI has no lease_request/self-issue tool"}
        return {"token": token, "ok": False, "tier": "absent",
                "detail": "unknown token"}

    def eval_object(self, o):
        reads = [self.eval_read(x) for x in o["read"]]
        writes = [self.eval_write(x) for x in o["write"]]
        read_ok = any(r["ok"] for r in reads)
        read_live = any(r["ok"] and r["live"] for r in reads)
        read_direct = any(r["ok"] and r["tier"] == "direct" for r in reads)
        read_gated = any(r["ok"] and r["tier"] == "gated" for r in reads)
        read_escape = any(r["ok"] and r["tier"] == "escape" for r in reads)
        level = o["semantic"]
        if not read_ok:
            level = "none"
        elif level in ("structured", "semantic") and not (read_direct or read_gated):
            level = "raw"
        write_ok = any(w["ok"] and w["tier"] != "principal" for w in writes)
        write_direct = any(w["ok"] and w["tier"] not in ("escape", "principal") for w in writes)
        write_escape = any(w["ok"] and w["tier"] == "escape" for w in writes)
        write_principal = any(w["ok"] and w["tier"] == "principal" for w in writes)
        return {
            "id": o["id"], "class": o["class"], "name": o["name"],
            "read_spec": o["read"], "write_spec": o["write"],
            "read": reads, "write": writes,
            "read_any": read_ok, "read_live": read_live,
            "read_direct": read_direct, "read_gated": read_gated,
            "read_escape": read_escape,
            "semantic_level": level, "semantic_declared": o["semantic"],
            "write_any": write_ok, "write_direct": write_direct,
            "write_escape": write_escape, "write_principal": write_principal,
            "risk": o["risk"], "evidence": o["evidence"],
            "gap": o["gap"], "notes": o["notes"], "status": o["status"],
            "write_na": o["write_na"],
        }


# ---------------------------------------------------------------------------
# Findings / doc drift
# ---------------------------------------------------------------------------

def build_findings(reg, src, host_missing, vm_missing, vm_reachable, ev):
    f = []
    arch = src["docs_claims"]
    if reg["tool_count"] != EXPECTED_TOOLS:
        f.append({"id": "F-001", "kind": "registry", "severity": "P0",
                  "detail": "tools.json count %s != expected %s" % (reg["tool_count"], EXPECTED_TOOLS)})
    if reg["sandbox_tool_count"] != EXPECTED_SANDBOX_TOOLS:
        f.append({"id": "F-002", "kind": "registry", "severity": "P0",
                  "detail": "tools-sandbox count %s != expected %s" % (reg["sandbox_tool_count"], EXPECTED_SANDBOX_TOOLS)})
    if reg["domain_count"] != EXPECTED_DOMAINS:
        f.append({"id": "F-003", "kind": "registry", "severity": "P0",
                  "detail": "domain count %s != %s" % (reg["domain_count"], EXPECTED_DOMAINS)})
    if reg["implementation_diff"]:
        f.append({"id": "F-004", "kind": "implementation", "severity": "P1",
                  "detail": "registered/implementation diff: %s" % reg["implementation_diff"]})
    if reg["duplicate_names"]:
        f.append({"id": "F-005", "kind": "registry", "severity": "P1",
                  "detail": "duplicate tool names: %s" % reg["duplicate_names"]})
    if host_missing:
        f.append({"id": "F-006", "kind": "binary", "severity": "P1",
                  "detail": "host (L1) missing %d/%d exec binaries: %s"
                            % (len(host_missing), reg["exec_command_count"], ", ".join(host_missing))})
    if vm_missing:
        f.append({"id": "F-007", "kind": "binary", "severity": "P1",
                  "detail": "production VM missing %d/%d exec binaries: %s"
                            % (len(vm_missing), reg["exec_command_count"], ", ".join(vm_missing))})
    if arch.get("arch_mentions_55_sandbox_commands") and reg["sandbox_command_count"] != 55:
        f.append({"id": "F-008", "kind": "doc-drift", "severity": "P3",
                  "detail": "ARCHITECTURE-MATRIX says 55 sandbox commands; actual %d" % reg["sandbox_command_count"]})
    if arch.get("arch_tools_sha256") and arch["arch_tools_sha256"] != reg["tools_sha256"]:
        f.append({"id": "F-009", "kind": "doc-drift", "severity": "P3",
                  "detail": "ARCHITECTURE-MATRIX tools.json sha256=%s actual=%s" % (arch["arch_tools_sha256"], reg["tools_sha256"])})
    if arch.get("arch_generated_at") and arch["arch_generated_at"].replace(" ", "T") not in reg["generated_at"]:
        f.append({"id": "F-010", "kind": "doc-drift", "severity": "P3",
                  "detail": "ARCHITECTURE-MATRIX generated_at=%s actual=%s" % (arch["arch_generated_at"], reg["generated_at"])})
    if arch.get("gen_docstring_79"):
        f.append({"id": "F-011", "kind": "doc-drift", "severity": "P3",
                  "detail": "gen_registry.py docstring still asserts EXPECTED_TOOL_COUNT(79); constant is 151"})
    probes = [t for t in reg["tools"] if t.get("probe")]
    if len(probes) < reg["tool_count"]:
        f.append({"id": "F-012", "kind": "observability", "severity": "P3",
                  "detail": "only %d/%d tools declare a capability probe (%s)" % (len(probes), reg["tool_count"], ", ".join(t["name"] for t in probes))})
    desktop_names = {t["name"] for t in reg["tools"]
                     if t.get("channel") == "desktop"}
    if not {"desktop_windows_list", "desktop_windows_focus",
            "desktop_windows_close"} <= desktop_names:
        f.append({"id": "F-013", "kind": "desktop", "severity": "P1",
                  "detail": "desktop windows tools missing; AI cannot enumerate/focus/close windows"})
    if not {"desktop_clipboard_get", "desktop_clipboard_set"} <= desktop_names:
        f.append({"id": "F-014", "kind": "desktop", "severity": "P1",
                  "detail": "desktop clipboard tools missing"})
    if not {"desktop_input_type", "desktop_input_key"} <= desktop_names:
        f.append({"id": "F-015", "kind": "desktop", "severity": "P1",
                  "detail": "desktop input tools missing"})
    if not vm_reachable:
        f.append({"id": "F-016", "kind": "probe", "severity": "P3",
                  "detail": "--vm-host not reachable or not supplied; VM-specific live checks skipped"})
    else:
        for probe in sorted({t["probe"] for t in reg["tools"] if t.get("probe")}):
            if probe not in ev.vm_files:
                f.append({"id": "F-019", "kind": "probe", "severity": "P2",
                          "detail": "probe unavailable on production VM: %s" % probe})
    # exec_run top-level risk anomaly
    er = [t for t in reg["tools"] if t["name"] == "exec_run"]
    if er and "risk" not in er[0]:
        f.append({"id": "F-017", "kind": "schema", "severity": "P3",
                  "detail": "exec_run has no top-level risk key; effective risk is command-level (intentional but breaks uniform schema)"})
    # Desktop writes have first-class desktop_* tools since W76.
    curl = src.get("curl_risk", {})
    if not desktop_names:
        f.append({"id": "F-018", "kind": "desktop", "severity": "P1",
                  "detail": "desktop writes have no first-class desktop_* tools; "
                            "AI path would be exec_run curl. "
                            "curl write shapes are effective W2 via exec_dyn_scan; "
                            "tests/exec_risk_cases.tsv has %d curl W2 + %d DENY cases (flags: %s); GET remains R."
                            % (curl.get("w2", 0), curl.get("deny", 0),
                               ", ".join(curl.get("write_flags", [])) or "n/a")})
    return f


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(evald):
    applicable = [o for o in evald if o["status"] not in ("future", "n/a")]
    read_any = sum(1 for o in applicable if o["read_any"])
    read_live = sum(1 for o in applicable if o["read_live"])
    read_direct = sum(1 for o in applicable if o["read_direct"])
    sem_structured = sum(1 for o in applicable if o["semantic_level"] in ("structured", "semantic"))
    sem_high = sum(1 for o in applicable if o["semantic_level"] == "semantic")
    write_app = [o for o in applicable if not o["write_na"]]
    write_any = sum(1 for o in write_app if o["write_any"])
    write_direct = sum(1 for o in write_app if o["write_direct"])
    write_escape = sum(1 for o in write_app if o["write_escape"] and not o["write_direct"])
    total = len(applicable)
    pct = lambda n, d: round(100.0 * n / d, 1) if d else 0.0
    open_gaps = [g for g in GAPS if g.get("status") != "closed"]
    closed_gaps = [g for g in GAPS if g.get("status") == "closed"]
    gaps = Counter(g["priority"] for g in open_gaps)
    return {
        "objects_total": len(evald),
        "objects_applicable": total,
        "read_any": read_any,
        "read_any_pct": pct(read_any, total),
        "read_live": read_live,
        "read_live_pct": pct(read_live, total),
        "read_direct": read_direct,
        "read_direct_pct": pct(read_direct, total),
        "semantic_structured": sem_structured,
        "semantic_structured_pct": pct(sem_structured, total),
        "semantic_high": sem_high,
        "semantic_high_pct": pct(sem_high, total),
        "write_applicable": len(write_app),
        "write_any": write_any,
        "write_any_pct": pct(write_any, len(write_app)),
        "write_direct": write_direct,
        "write_direct_pct": pct(write_direct, len(write_app)),
        "write_escape_only": write_escape,
        "write_principal_only": sum(1 for o in write_app
                                    if o["write_principal"] and not o["write_any"]),
        "implementation_diff_count": 0,
        "gap_total": len(open_gaps),
        "gap_closed": len(closed_gaps),
        "gap_closed_ids": [g["id"] for g in closed_gaps],
        "gap_p0": gaps.get("P0", 0),
        "gap_p1": gaps.get("P1", 0),
        "gap_p2": gaps.get("P2", 0),
        "gap_p3": gaps.get("P3", 0),
        "read_absent_objects": [o["id"] for o in applicable if not o["read_any"]],
        "semantic_raw_objects": [o["id"] for o in applicable
                                 if o["read_any"] and o["semantic_level"] == "raw"],
    }


# ---------------------------------------------------------------------------
# Markdown renderers
# ---------------------------------------------------------------------------

def cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def token_md(r):
    mark = {"direct": "ok", "gated": "gated", "escape": "shell-escape",
            "principal": "principal-only",
            "absent": "ABSENT", "read-only": "read-only"}.get(r["tier"], r["tier"])
    live = r.get("live", r["ok"])
    if r["ok"] and live:
        state = mark
    elif r["ok"] and not live:
        state = mark + "/unavailable"
    else:
        state = "ABSENT"
    return "`%s` [%s]" % (cell(r["token"]), state)


def render_matrix(meta, evald, metrics):
    lines = []
    lines.append("# AIKernel W75 全知/全能对象矩阵")
    lines.append("")
    lines.append("> 由 `agent/ai/tools/audit_capabilities.py` 只读扫描生成；"
                 "生成时间 %s；审计主机 `%s`；VM 探测 `%s`。"
                 % (meta["generated_at"], meta["host"]["hostname"], meta["host"]["vm_host"] or "未启用"))
    lines.append("> 矩阵不手填：对象目录、路径判定、覆盖计数、缺口引用均来自脚本。"
                 "口径见 §1；每次重跑覆盖本文件即视为刷新。")
    lines.append("")
    lines.append("## 1. 口径")
    lines.append("")
    lines.append("- **读路径**：已注册工具 / exec 白名单命令 / 可读文件 / 只读 HTTP API / 生产 VM 节点，任一可达即算。")
    lines.append("- **直连读**：不需要 W2 确认、不依赖任意代码逃逸的读路径（R 工具 / R 命令 / 文件 / GET API）。")
    lines.append("- **语义化**：`semantic`（typed JSON/对象模型/图关系）或 `structured`（JSON/CSV/key=value/稳定机器可解析字段）；"
                 "`raw` 为自由文本；`shell-escape` 一律不计为结构化。")
    lines.append("- **写路径**：已注册 W1/W2 工具、白名单 W1/W2 命令、或存在的 POST API；shell/脚本逃逸单独标注。")
    lines.append("- **Principal-only**：`/lease issue|revoke|confirm` 等 root+TTY 命令，存在但不是 Agent 工具；计入读/写语义但不计入 AI 写覆盖。")
    lines.append("- **风险**：D0 纯信息 / D1 可逆本地 / D2 不可逆本地 / D3 系统级 / D4 身份与启动链。")
    lines.append("")
    lines.append("## 2. 覆盖总览（脚本计算）")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|---|---:|")
    lines.append("| 对象总数（适用） | %d |" % metrics["objects_applicable"])
    lines.append("| 读路径覆盖（含 W2/逃逸） | %d/%d = **%.1f%%** |"
                 % (metrics["read_any"], metrics["objects_applicable"], metrics["read_any_pct"]))
    lines.append("| 直连读覆盖（R 工具/命令/文件/API） | %d/%d = **%.1f%%** |"
                 % (metrics["read_direct"], metrics["objects_applicable"], metrics["read_direct_pct"]))
    lines.append("| 实测存活读路径 | %d/%d = **%.1f%%** |"
                 % (metrics["read_live"], metrics["objects_applicable"], metrics["read_live_pct"]))
    lines.append("| 结构化+语义化覆盖 | %d/%d = **%.1f%%** |"
                 % (metrics["semantic_structured"], metrics["objects_applicable"], metrics["semantic_structured_pct"]))
    lines.append("| 其中 semantic（typed 对象模型） | %d/%d = **%.1f%%** |"
                 % (metrics["semantic_high"], metrics["objects_applicable"], metrics["semantic_high_pct"]))
    lines.append("| 写路径覆盖（可写对象） | %d/%d = **%.1f%%** |"
                 % (metrics["write_any"], metrics["write_applicable"], metrics["write_any_pct"]))
    lines.append("| 写路径 but shell-escape only | %d |" % metrics["write_escape_only"])
    lines.append("| 写路径 but Principal-only（非 AI） | %d |" % metrics["write_principal_only"])
    lines.append("| 缺口总数（open） / P0 / P1 / P2 / P3 | %d / %d / %d / %d / %d |"
                 % (metrics["gap_total"], metrics["gap_p0"], metrics["gap_p1"],
                    metrics["gap_p2"], metrics["gap_p3"]))
    lines.append("| 已关闭缺口（W76） | %d（%s） |"
                 % (metrics["gap_closed"], ", ".join(metrics["gap_closed_ids"]) or "无"))
    lines.append("| 工具 / 域 / desktop 工具 | %d / %d / %d |"
                 % (meta["registry"]["tool_count"], meta["registry"]["domain_count"],
                    meta["registry"]["desktop_tool_count"]))
    lines.append("| SME seed/corpus | %d（%s） |"
                 % (meta["registry"]["seed_count"],
                    ", ".join("%s=%d" % (k, v) for k, v in meta["registry"]["seed_kinds"].items())))
    lines.append("| 工具名清单 SHA-256 | `%s` |" % meta["registry"]["tool_names_sha256"])
    lines.append("")
    if metrics["read_any_pct"] < READ_TARGET:
        lines.append("**未达 95%% 读覆盖。** 无读路径对象：%s。原因见各对象缺口与 §4。"
                     % (", ".join(metrics["read_absent_objects"]) or "无"))
        lines.append("")
    else:
        lines.append("读路径覆盖达到 95% 目标；但直连/语义化覆盖仍低于目标，缺口见 "
                     "`CAPABILITY-GAPS.md`。")
        lines.append("")
    lines.append("## 3. 对象矩阵")
    lines.append("")
    lines.append("| 对象类 | 对象 | 读路径（工具/命令/API/文件） | 写路径 | 语义化程度 | 风险/D 级 | 证据命令 | 缺口 ID |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for o in evald:
        reads = "<br>".join(token_md(r) for r in o["read"]) or "—"
        writes = "<br>".join(token_md(r) for r in o["write"]) or "—"
        sem = o["semantic_level"]
        if sem in ("structured", "semantic") and not (o["read_direct"] or o["read_gated"]):
            sem = "raw (shell-escape only)"
        if o["status"]:
            sem += " (%s)" % o["status"]
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            cell(o["class"]), cell(o["name"]), reads, writes, cell(sem),
            cell(o["risk"]), cell(o["evidence"]), cell(o["gap"])))
    lines.append("")
    lines.append("## 4. 未达项与说明")
    lines.append("")
    lines.append("- 读路径为 ABSENT 的对象：%s。"
                 % (", ".join(metrics["read_absent_objects"]) or "无"))
    lines.append("- 语义化仍为 raw 的对象：%s。"
                 % (", ".join(metrics["semantic_raw_objects"]) or "无"))
    lines.append("- `shell-escape` 表示只能通过 `python3`（W2）或 `sys_shell`（交互 TTY）访问，"
                 "不是一等能力；对应 gap 见 `CAPABILITY-GAPS.md`。")
    lines.append("- VM 节点证据：`%s`。" % ("; ".join(sorted(meta["host"]["vm_evidence"])) or "未采集"))
    lines.append("")
    lines.append("<!-- TOTAL_OBJECTS: %d -->" % metrics["objects_applicable"])
    lines.append("<!-- READ_ANY: %d -->" % metrics["read_any"])
    lines.append("<!-- READ_DIRECT: %d -->" % metrics["read_direct"])
    lines.append("<!-- SEMANTIC_STRUCTURED: %d -->" % metrics["semantic_structured"])
    lines.append("<!-- WRITE_ANY: %d -->" % metrics["write_any"])
    return "\n".join(lines) + "\n"


def render_gaps(meta, metrics, findings):
    lines = []
    lines.append("# AIKernel W75 能力缺口清单")
    lines.append("")
    lines.append("> 由 `agent/ai/tools/audit_capabilities.py` 生成；生成时间 %s。"
                 "优先级：P0 阻断 alpha.10 / P1 日常使用阻断 / P2 功能正确性 / P3 体验与文档。"
                 % meta["generated_at"])
    lines.append("")
    lines.append("## 1. 汇总")
    lines.append("")
    lines.append("| 优先级 | 数量（open） |")
    lines.append("|---|---:|")
    for p in ("P0", "P1", "P2", "P3"):
        lines.append("| %s | %d |" % (p, sum(1 for g in GAPS
                                            if g["priority"] == p and g.get("status") != "closed")))
    lines.append("| 已关闭（W76） | %d |" % sum(1 for g in GAPS if g.get("status") == "closed"))
    lines.append("")
    lines.append("- G-001 已由 W74 落地（租约 JSON、`/lease` Principal CLI、`--lease` 加载、D0-D4 gate）；"
                 "条目保留为**残余硬化（P2）**，不再计为 P0 能力缺口。")
    lines.append("- G-002/G-015/G-035 已由 W76 关闭（20 件 `desktop_*`、D0-D3、租约/审计、10/10+12/12）；"
                 "G-033（电源 501）保持开放。")
    lines.append("")
    lines.append("## 2. 缺口清单（open）")
    lines.append("")
    lines.append("| gap_id | 对象/能力 | 现状 | 为什么是黑箱/缺口 | 建议波次 | 验收样例 |")
    lines.append("|---|---|---|---|---|---|")
    for g in sorted([x for x in GAPS if x.get("status") != "closed"],
                    key=lambda x: (x["priority"], x["id"])):
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            g["id"], cell(g["object"]), cell(g["current"]), cell(g["why"]),
            g["wave"], cell(g["acceptance"])))
    lines.append("")
    lines.append("## 2.1 已关闭（W76）")
    lines.append("")
    lines.append("| gap_id | 对象/能力 | 关闭依据 | 残余风险 |")
    lines.append("|---|---|---|---|")
    for g in sorted([x for x in GAPS if x.get("status") == "closed"], key=lambda x: x["id"]):
        residual = {"G-002": "W76-R1（Web demo≠真 OS 桌面，W84）",
                    "G-015": "W76-R2（输入/截图/剪贴板敏感，W83）",
                    "G-035": "-"}.get(g["id"], "-")
        lines.append("| %s | %s | %s | %s |" % (
            g["id"], cell(g["object"]), cell(g["current"]), cell(residual)))
    lines.append("")
    lines.append("## 2.2 W76 残余风险（不占用 W75 G 编号，不计入缺口数）")
    lines.append("")
    lines.append("| ID | 风险 | 级别 | 建议 |")
    lines.append("|---|---|---|---|")
    for rid, risk, level, advice in W76_RISKS:
        lines.append("| %s | %s | %s | %s |" % (rid, cell(risk), level, cell(advice)))
    lines.append("")
    lines.append("## 3. 只有 shell / 任意代码能做的事（含完全不可用项）")
    lines.append("")
    lines.append("这些操作在系统里合法，但没有进入工具注册表；AI 只能通过 W2 `python3` 或交互 `sys_shell` 触达，"
                 "不可检索、不可复用、不可审计。标注“缺二进制”的项连 shell 也不可用。")
    lines.append("")
    lines.append("| 命令/操作 | 能力 | 现状 | 缺口 |")
    lines.append("|---|---|---|---|")
    for cmd, cap, state, gap in SHELL_ONLY:
        lines.append("| %s | %s | %s | %s |" % (cell(cmd), cell(cap), cell(state), gap))
    lines.append("")
    lines.append("## 4. 存在但 AI 看不到的接口")
    lines.append("")
    lines.append("| 对象/接口 | 现状 | 缺口 |")
    lines.append("|---|---|---|")
    for name, state, gap in INVISIBLE:
        lines.append("| %s | %s | %s |" % (cell(name), cell(state), gap))
    lines.append("")
    lines.append("## 5. 注册/实现/二进制差异")
    lines.append("")
    impl = [f for f in findings if f["kind"] in ("registry", "implementation", "binary", "schema")]
    lines.append("- 注册/实现差异：0（%d/%d 工具均有通道实现，desktop %d/%d；`--check` 断言）。"
                 % (meta["registry"]["tool_count"], meta["registry"]["tool_count"],
                    meta["registry"]["desktop_tool_count"],
                    meta["registry"]["desktop_tool_count"]))
    if not impl:
        lines.append("- 未发现注册但无实现的工具。")
    for f in impl:
        lines.append("- **%s** (%s): %s" % (f["id"], f["severity"], f["detail"]))
    lines.append("")
    lines.append("## 6. 文档漂移与风险发现")
    lines.append("")
    for f in findings:
        if f["kind"] in ("doc-drift", "risk", "observability", "desktop", "probe"):
            lines.append("- **%s** (%s/%s): %s" % (f["id"], f["kind"], f["severity"], f["detail"]))
    lines.append("")
    lines.append("<!-- GAP_TOTAL: %d -->" % len(GAPS))
    lines.append("<!-- GAP_P0: %d -->" % metrics["gap_p0"])
    lines.append("<!-- GAP_P1: %d -->" % metrics["gap_p1"])
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="AIKernel W75 read-only capability auditor")
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    help="agent/ai repository root")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--markdown", choices=["matrix", "gaps", "all"], help="emit markdown section")
    ap.add_argument("--check", action="store_true", help="recompute and assert counts/coverage")
    ap.add_argument("--vm-host", default="", help="optional SSH target for production VM node probes")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.repo)
    if not args.json and not args.markdown and not args.check:
        args.markdown = "all"

    t0 = time.time()
    reg = scan_registry(root)
    src = scan_source(root)
    desktop = src["desktop"]

    # Collect VM probe targets from tokens. `vm_bins` holds only commands
    # CONFIRMED present on the VM; `vm_bin_targets` is the probe map.
    vm_files, vm_bins = set(), set()
    vm_bin_targets = {}
    for o in OBJECTS:
        for tok in list(o["read"]) + list(o["write"]):
            kind, _, val = tok.partition(":")
            if kind == "vmfile":
                vm_files.add(val)
    for c in reg["exec_commands"]:
        vm_bin_targets[c["command"]] = c.get("bin", "")
    for t in reg["tools"]:
        if t.get("path"):
            vm_files.add(t["path"])
        if t.get("probe"):
            vm_files.add(t["probe"])

    vm_reachable = False
    if args.vm_host:
        vm_files, vm_bins, vm_reachable = vm_probe(args.vm_host, vm_files, vm_bin_targets)

    ev = Evaluator(root, reg, src, vm_files, vm_bins, desktop)
    evald = [ev.eval_object(o) for o in OBJECTS]
    metrics = compute_metrics(evald)
    metrics["implementation_diff_count"] = len(reg["implementation_diff"])

    host_missing = []
    for c in reg["exec_commands"]:
        if not which_bin(c.get("bin", ""), c["command"]):
            host_missing.append(c["command"])
    vm_missing = []
    if vm_reachable:
        for c in reg["exec_commands"]:
            if c["command"] not in vm_bins:
                vm_missing.append(c["command"])

    findings = build_findings(reg, src, host_missing, vm_missing, vm_reachable, ev)

    vm_evidence = []
    for p in ("/proc/ai/status", "/proc/ai/control", "/proc/ai/decisions",
              "/sys/kernel/ai/enabled", "/sys/fs/cgroup/ai.inferences"):
        if p in vm_files:
            vm_evidence.append("vm:" + p)
    for p in ("/proc/ai/status", "/proc/ai/control", "/sys/kernel/ai/enabled"):
        if os.path.exists(p):
            vm_evidence.append("host:" + p)

    meta = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": {
            "hostname": socket.gethostname(),
            "kernel": os.uname().release,
            "uptime_seconds": round(float(open("/proc/uptime").read().split()[0]), 0)
            if os.path.exists("/proc/uptime") else None,
            "vm_host": args.vm_host,
            "vm_reachable": vm_reachable,
            "vm_evidence": vm_evidence,
        },
        "registry": {k: v for k, v in reg.items() if k not in ("tools", "sandbox_tools")},
        "source": src,
        "commands": {
            "exec_total": reg["exec_command_count"],
            "host_present": reg["exec_command_count"] - len(host_missing),
            "host_missing": host_missing,
            "vm_present": (reg["exec_command_count"] - len(vm_missing)) if vm_reachable else None,
            "vm_missing": vm_missing if vm_reachable else None,
            "sandbox_total": reg["sandbox_command_count"],
            "sandbox_missing_host": [c["command"] for c in reg["sandbox_commands"]
                                     if not which_bin(c.get("bin", ""), c["command"])],
        },
        "metrics": metrics,
        "gaps": GAPS,
        "findings": findings,
        "objects": evald,
    }

    if args.check:
        errors = []
        if reg["tool_count"] != EXPECTED_TOOLS:
            errors.append("tool_count %d != %d" % (reg["tool_count"], EXPECTED_TOOLS))
        if reg["sandbox_tool_count"] != EXPECTED_SANDBOX_TOOLS:
            errors.append("sandbox_tool_count %d != %d" % (reg["sandbox_tool_count"], EXPECTED_SANDBOX_TOOLS))
        if reg["domain_count"] != EXPECTED_DOMAINS:
            errors.append("domain_count %d != %d" % (reg["domain_count"], EXPECTED_DOMAINS))
        if reg["desktop_tool_count"] != EXPECTED_DESKTOP_TOOLS:
            errors.append("desktop_tool_count %d != %d"
                          % (reg["desktop_tool_count"], EXPECTED_DESKTOP_TOOLS))
        if reg["tool_names_sha256"] != EXPECTED_TOOL_NAMES_SHA256:
            errors.append("tool_names_sha256 %s != %s"
                          % (reg["tool_names_sha256"], EXPECTED_TOOL_NAMES_SHA256))
        if reg["seed_count"] != EXPECTED_SEED_COUNT:
            errors.append("seed_count %d != %d" % (reg["seed_count"], EXPECTED_SEED_COUNT))
        if reg["seed_kinds"] != EXPECTED_SEED_KINDS:
            errors.append("seed_kinds %r != %r" % (reg["seed_kinds"], EXPECTED_SEED_KINDS))
        if reg["seed_errors"]:
            errors.append("seed parse errors: %s" % "; ".join(reg["seed_errors"]))
        if reg["implementation_diff"]:
            errors.append("implementation_diff=%d" % len(reg["implementation_diff"]))
        if len(OBJECTS) < 60:
            errors.append("object catalog too small: %d" % len(OBJECTS))
        if metrics["read_any_pct"] < READ_TARGET:
            errors.append("read coverage %.1f%% < %.1f%% (absent: %s)"
                          % (metrics["read_any_pct"], READ_TARGET,
                             ",".join(metrics["read_absent_objects"])))
        if metrics["semantic_structured_pct"] < SEMANTIC_TARGET:
            errors.append("structured+semantic coverage %.1f%% < %.1f%%"
                          % (metrics["semantic_structured_pct"], SEMANTIC_TARGET))
        ids = {o["id"] for o in OBJECTS}
        if len(ids) != len(OBJECTS):
            errors.append("duplicate object ids")
        gap_ids = {g["id"] for g in GAPS}
        for o in OBJECTS:
            if not o["evidence"]:
                errors.append("object %s has no evidence" % o["id"])
            for g in [x.strip() for x in re.split(r"[,/]", o["gap"]) if x.strip() != "-"]:
                if g not in gap_ids:
                    errors.append("object %s references unknown gap %s" % (o["id"], g))
        closed_ids = {g["id"] for g in GAPS if g.get("status") == "closed"}
        if closed_ids != {"G-002", "G-015", "G-035"}:
            errors.append("closed gaps %r != expected G-002/G-015/G-035" % sorted(closed_ids))
        if any(g["id"] == "G-033" and g.get("status") == "closed" for g in GAPS):
            errors.append("G-033 must remain open (desktop_power backend 501)")
        if errors:
            print("W75 CHECK FAIL")
            for e in errors:
                print(" - " + e)
            return 1
        print("W75 CHECK PASS")
        print("objects=%d read_any=%d/%d (%.1f%%) direct=%d (%.1f%%) "
              "semantic_structured=%d (%.1f%%) write=%d/%d (%.1f%%) "
              "gaps=%d (P0=%d P1=%d P2=%d P3=%d closed=%d) "
              "tools=%d domains=%d desktop=%d seed=%d"
              % (metrics["objects_applicable"], metrics["read_any"],
                 metrics["objects_applicable"], metrics["read_any_pct"],
                 metrics["read_direct"], metrics["read_direct_pct"],
                 metrics["semantic_structured"], metrics["semantic_structured_pct"],
                 metrics["write_any"], metrics["write_applicable"],
                 metrics["write_any_pct"], metrics["gap_total"],
                 metrics["gap_p0"], metrics["gap_p1"], metrics["gap_p2"],
                 metrics["gap_p3"], metrics["gap_closed"],
                 reg["tool_count"], reg["domain_count"],
                 reg["desktop_tool_count"], reg["seed_count"]))
        return 0

    if args.json:
        print(json.dumps(meta, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.markdown:
        if args.markdown in ("matrix", "all"):
            print(render_matrix(meta, evald, metrics))
        if args.markdown in ("gaps", "all"):
            print(render_gaps(meta, metrics, findings))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
