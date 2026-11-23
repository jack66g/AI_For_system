#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
audit_occ_capabilities.py - AIF-01「出厂 AI 真实视角」能力审计

量什么
------
旧审计 `audit_capabilities.py` 量的是 tools.json 注册表（237 件工具、27 个
通道），而那 237 件的执行器 tools/executor.c 只链进旧的 aikernel-shell
（agent/ai/Makefile:169），后者已不在出厂入口。出厂 AI 的默认入口是 occ：
自带 10 件通用工具（9 件默认 + 出厂置位 OCC_NETCFG_TOOLS=1 的
config_write_network），运行时不读 tools.json。

本脚本复用旧审计的 97 对象目录与 36 条缺口登记（import 同目录的
audit_capabilities，不复制第二份），按「出厂 AI 视角」对每个对象重新求值：
可达读面（occ 宿主工具 / 沙箱命令 / aikctl 子命令 / 回环 HTTP）、是否免
确认、语义级别、可达写面。

纯静态：不执行任何系统命令、不连任何主机（旧模块里的 HTTP 探测被本脚本
替身为恒失败）。只读仓库文件。

出厂身份矩阵（两种身份）
------------------------
  root   控制台 root 路径（aik-console 目标=root/号缺席）与 aikernel-api
         服务（unit 无 User= → root；apic 以 `occ -p` 调起）。档位
         PRIVILEGED：W1 免确认，W2 控制台需交互确认；headless（API）
         默认拒绝（未传 --allow-w2）。
  admin  控制台默认目标（aik-console v9：缺省 admin，setpriv 降权，wheel
         组）。档位 CONFIRMED：W1 免确认，W2 一律拒绝（须 /su）。宿主文件
         读面受常规权限约束；沙箱命令依赖 `sudo -n aik-sandbox`——仓内
         build-rootfs.sh 与出厂树均未见 sudo 二进制与 sudoers 规则，缺省
         按「不可达」计（--admin-sandbox ok 可改）。

求值规则
--------
  可达        读面在结构上存在且不被沙箱视图/权限挡住即算（同旧口径
              read_any=登记即算）；另标 partial（只看到沙箱自身/一部分
              数据）与 cond（依赖运行态：服务在跑、内核节点存在）。
  免确认      R / W1 的读面。W2 读面只有 root 控制台经交互确认才可达。
  语义级别    取可达读面的最佳形态，且不高于旧申报级别
              （自由文本=raw；稳定列/键值/JSON=structured；带类型的对象
              模型=semantic）。
  写面        W1=免确认直写；W2=root 控制台确认后可写、admin 不可写。

用法
----
  python3 agent/ai/tools/audit_occ_capabilities.py --json
  python3 agent/ai/tools/audit_occ_capabilities.py --markdown
  python3 agent/ai/tools/audit_occ_capabilities.py --write-baseline
  python3 agent/ai/tools/audit_occ_capabilities.py --check

退出码：0 成功；1 --check 与入库基线不一致或源码事实漂移；2 参数错误。
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import audit_capabilities as OLD      # noqa: E402  97 对象/36 缺口目录只此一份

SCHEMA = "aik-occ-audit/1"
BASELINE_REL = os.path.join("docs", "OCC-CAPABILITY-BASELINE.json")

SB = "aik-sandbox.c"
TC = "tools.c"
EV_PIDNS = SB + ":2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程）"
EV_NORUN = SB + ":824-859（根骨架无 /run）"
EV_NOVAR = SB + ":826-829（/var、/tmp、/home 为 tmpfs 空目录）"
EV_NOETC = SB + ":274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂）"
EV_NODEV = SB + ":283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]）"
EV_NOCAP = SB + ":1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS）"
EV_NET = SB + ":24-25,92,2397-2414（默认保留宿主网络）"
EV_PROC = SB + ":11-12,2301-2304（/proc 新挂只读，全局节点可读）"
EV_SYS = SB + ":2157-2164（/sys 新挂只读，全局节点可见）"
EV_USR = SB + ":2155（/usr 只读 bind，非递归）"
EV_ETCHK = SB + ":2166-2187,2196-2216（/etc 白名单 + /etc/aikernel 整目录 + awk/which 链修复）"
EV_W2 = TC + ":3424-3430（首 token 命中 W2 硬表）"
EV_ABSENT = "出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制"
EV_INFER = "推断（静态求值，未在沙箱内实测）"

RANK = {"none": 0, "raw": 1, "structured": 2, "semantic": 3}

# ---------------------------------------------------------------------------
# occ 十件工具逐件事实
# ---------------------------------------------------------------------------
OCC_TOOLS = [
    ("read", "R", "宿主", "带行号文本", "任意可读文件；无路径域限制；单文件 ≤4MB、含 NUL 拒读、"
     "默认 500 行/次、结果截 8KB", "免确认",
     TC + ":750-815,496-574；occ_tools.h:84-85"),
    ("glob", "R", "宿主", "路径清单", "任意可读目录；≤200 项、深度 24、无元数据", "免确认",
     TC + ":1159-1161,1234-1347"),
    ("grep", "R", "宿主", "文件:行号:行", "任意可读文件/目录；朴素字节子串；≤100 行、"
     "单文件 ≤4MB、二进制跳过", "免确认", TC + ":1351-1352,1417-1456"),
    ("bash", "W1/W2", "沙箱", "stdout+stderr 合流 + [exit=N]", "仅沙箱视图；采集 ≤1MB、"
     "截 8KB、默认 60s；一调用一区", "W1 免确认；W2 root 控制台需确认，admin/API 拒绝",
     "occ_tools/sandbox.c:18-22,403-601；occ_tools/" + TC + ":3422-3564,3591-3596,3712-3740"),
    ("write", "W1/W2", "宿主", "一句结果文本", "目标域=工作目录∪/tmp∪/var/ai∪$HOME（越界 W2；"
     "~/.occ 恒拒）；≤512KB；写前快照", "域内免确认；越界同 W2 规则",
     TC + ":447-471,845-867,869-928"),
    ("edit", "W1/W2", "宿主", "一句结果文本", "同 write 域；oldString 唯一命中或 replaceAll；"
     "写前快照", "同 write", TC + ":932-1045"),
    ("rm", "W1/W2", "宿主", "一句结果文本", "同 write 域；仅普通文件与空目录；不落快照",
     "同 write", TC + ":1049-1088"),
    ("mv", "W1/W2", "宿主", "一句结果文本", "两端同 write 域；不覆盖已有目标、跨设备报错",
     "同 write", TC + ":1090-1131"),
    ("mkdir", "W1/W2", "宿主", "一句结果文本", "同 write 域；-p 语义", "同 write",
     TC + ":1133-1155"),
    ("config_write_network", "R/W2", "宿主", "show=关键行清单；write/remove=结果+生效指引",
     "固定写 /etc/systemd/network/70-static-<iface>.network；出厂置位才注册",
     "show 免确认；write/remove 恒 W2",
     TC + ":253-314,2967-3115,3632-3643；aik-console:155-157,203；aikernel-api.service:12"),
]

# ---------------------------------------------------------------------------
# 沙箱内命令可达表（静态推断）。
# 字段：命令、只读样例、判定、输出形态、原因、依据
# 判定：ok=能跑且拿到宿主真实数据；partial=能跑但只见沙箱自身/一部分；
#       no=跑不起来或拿不到宿主数据
# ---------------------------------------------------------------------------
def _C(name, sample, verdict, form, why, ev):
    return (name, sample, verdict, form, why, ev)


_COMMON = "通用文本工具，对管道与沙箱可见文件可用"
_SBXONLY = "只见沙箱视图（/usr、/etc 白名单、/proc、/sys、工作区）；宿主 /etc /var /root /home 不可见"
_DBUS = "走 systemd 私有 socket / D-Bus（/run 缺）"
_RW = "只能写沙箱 tmpfs（/tmp、工作区、产物区），退出即焚"

SANDBOX_COMMANDS = [
    # ---- 进程/资源 ----
    _C("ps", "ps -eo pid,ppid,stat,comm", "no", "raw", "宿主进程不可见（只见 sh 与 ps 自己）", EV_PIDNS),
    _C("top", "top -b -n 1", "no", "raw", "同 ps", EV_PIDNS),
    _C("pidof", "pidof systemd", "no", "raw", "同 ps", EV_PIDNS),
    _C("pgrep", "pgrep -a sshd", "no", "raw", "同 ps", EV_PIDNS),
    _C("pkill", "pkill systemd", "no", "raw", "同 ps；且 W2 硬表", EV_PIDNS + "；" + EV_W2),
    _C("kill", "kill -0 1", "no", "raw", "同 ps（沙箱内 1 号是 sh 自己）；且 W2 硬表", EV_PIDNS + "；" + EV_W2),
    _C("uptime", "uptime", "ok", "raw", "/proc/uptime、/proc/loadavg 为全局节点", EV_PROC),
    _C("free", "free -b", "ok", "structured", "/proc/meminfo 全局；固定列输出", EV_PROC),
    _C("vmstat", "vmstat 1 2", "ok", "structured", "/proc/stat、/proc/meminfo、/proc/vmstat 全局", EV_PROC),
    _C("vmstat -d", "vmstat -d", "ok", "structured", "/proc/diskstats 全局", EV_PROC),
    _C("lscpu", "lscpu -J", "ok", "structured", "/sys/devices/system/cpu + /proc/cpuinfo", EV_SYS + "；" + EV_PROC),
    _C("uname", "uname -r", "ok", "raw", "内核信息全局；-n 是沙箱区名（UTS 隔离）", SB + ":2307-2309"),
    _C("hostname", "hostname", "partial", "raw", "UTS namespace：sethostname(区名)，不是宿主名", SB + ":2832,2307-2309"),
    _C("date", "date +%s", "partial", "raw", "时钟全局正确；/etc/localtime 不在白名单 → 时区恒 UTC", EV_NOETC),
    _C("dmesg", "dmesg --color=never", "ok", "raw", "/dev/kmsg 不在白名单 → util-linux 回退 klogctl(2)；"
       "kernel.dmesg_restrict=0 时无需 CAP_SYSLOG。出厂树 etc/sysctl.d/10-kernel-hardening.conf 未改该项"
       "（:23-25 注释掉，基础镜像件）；AIKernel 内核树 .config 未设 CONFIG_SECURITY_DMESG_RESTRICT（默认 0）；"
       "L1 的 Ubuntu 内核是 1——须真机核 /proc/sys/kernel/dmesg_restrict",
       EV_NODEV + "；" + EV_INFER),
    _C("sysctl", "sysctl -a", "ok", "structured", "/proc/sys 只读可读；写因只读挂载 + 无 CAP_SYS_ADMIN 失败", EV_PROC),
    _C("slabtop", "slabtop -o -s c", "ok", "structured", "/proc/slabinfo（uid 0 属主可读）", EV_INFER),
    _C("lsns", "lsns", "no", "structured", "/proc/<pid>/ns 只见沙箱 pid；/run/netns 缺", EV_PIDNS + "；" + EV_NORUN),
    _C("lslocks", "lslocks", "ok", "structured", "/proc/locks 全局", EV_PROC),
    _C("lsipc", "lsipc", "ok", "structured", "/proc/sysvipc/*（未隔离 IPC namespace）", SB + ":2832"),
    _C("lsmem", "lsmem", "ok", "structured", "/sys/devices/system/memory 全局", EV_SYS),
    _C("lslogins", "lslogins", "no", "structured", "/var/log/wtmp、/var/run/utmp 缺", EV_NOVAR + "；" + EV_NORUN),
    _C("strace", "strace -c true", "partial", "raw", "只能跟踪沙箱内自己起的进程", EV_PIDNS),
    # ---- systemd/日志/启动 ----
    _C("systemctl", "systemctl list-units --no-pager", "no", "structured", _DBUS, EV_NORUN),
    _C("journalctl", "journalctl -n 20 --no-pager", "no", "structured", "/var/log/journal、/run/journal 缺", EV_NOVAR + "；" + EV_NORUN),
    _C("systemd-analyze", "systemd-analyze time", "no", "raw", "time/blame 要连 systemd manager", _DBUS),
    _C("systemd-cgls", "systemd-cgls --no-pager", "no", "structured", "/sys/fs/cgroup 在新 sysfs 里是空目录（cgroup2 是独立文件系统，沙箱内未挂）", EV_SYS),
    _C("systemd-cgtop", "systemd-cgtop -n 1", "no", "structured", "同 systemd-cgls", EV_SYS),
    _C("systemd-detect-virt", "systemd-detect-virt", "ok", "raw", "CPUID / /sys/class/dmi，不需 manager", EV_SYS),
    _C("bootctl", "bootctl status", "no", "structured", "/boot 不在沙箱视图", SB + ":826-829"),
    _C("hostnamectl", "hostnamectl", "no", "structured", _DBUS, EV_NORUN),
    _C("timedatectl", "timedatectl show", "no", "structured", _DBUS, EV_NORUN),
    _C("localectl", "localectl status", "no", "raw", _DBUS, EV_NORUN),
    _C("loginctl", "loginctl list-sessions", "no", "structured", _DBUS, EV_NORUN),
    _C("networkctl", "networkctl status", "no", "structured", "systemd-networkd 私有 socket（/run 缺）", EV_NORUN),
    _C("resolvectl", "resolvectl status", "no", "structured", "systemd-resolved 私有 socket（/run 缺）", EV_NORUN),
    _C("udevadm", "udevadm info /sys/class/net", "no", "raw", "/run/udev/control 缺", EV_NORUN),
    _C("aik-upgrade", "aik-upgrade status", "no", "raw", "依赖 /boot/aik-slot-state、/boot/grub、/var/log/aik-upgrade.log（均在沙箱视图外）", SB + ":826-829；aik-upgrade:51-53"),
    # ---- 网络 ----
    _C("ip", "ip -j addr", "ok", "structured", "netlink RTM_GET* 无需能力；宿主网络保留；写操作需 CAP_NET_ADMIN → EPERM", EV_NET + "；" + EV_NOCAP),
    _C("ss", "ss -tunl", "ok", "structured", "/proc/net/* + sock_diag；-p 的进程名要遍历宿主 /proc/<pid>/fd → 进程列恒空", EV_NET + "；" + EV_PIDNS),
    _C("ping", "ping -c 2 127.0.0.1", "ok", "raw", "能力集保留 CAP_NET_RAW", EV_NOCAP),
    _C("traceroute", "traceroute -n -m 5 127.0.0.1", "ok", "raw", "busybox 版走 UDP 探针，无需能力", EV_NET),
    _C("arping", "arping -c 1 127.0.0.1", "ok", "raw", "CAP_NET_RAW 在能力集内", EV_NOCAP),
    _C("ifconfig", "ifconfig -a", "ok", "structured", "SIOCGIFCONF 读，无需能力（busybox）", EV_NET),
    _C("route", "route -n", "ok", "structured", "/proc/net/route（busybox）", EV_NET),
    _C("netstat", "netstat -tunl", "ok", "structured", "/proc/net/*（busybox）", EV_NET),
    _C("nstat", "nstat -az", "ok", "structured", "/proc/net/snmp、netstat、stat/* 全局计数", EV_NET),
    _C("rtstat", "rtstat", "ok", "structured", "/proc/net/stat/rt_cache 全局", EV_NET),
    _C("ctstat", "ctstat", "ok", "structured", "/proc/net/stat/nf_conntrack 全局", EV_NET),
    _C("lnstat", "lnstat -c 1", "ok", "structured", "/proc/net/stat/lnstat 全局", EV_NET),
    _C("nslookup", "nslookup 127.0.0.1", "ok", "raw", "/etc/resolv.conf 在 /etc 白名单", EV_ETCHK),
    _C("curl", "curl -s -m 5 http://127.0.0.1:8000/health", "ok", "structured", "宿主网络 + 根证书在白名单；"
       "-d/-T/-F/-o/-O 等形态判 W2", EV_NET + "；" + EV_ETCHK + "；" + TC + ":3536-3561"),
    _C("wget", "wget -q -O - http://127.0.0.1:8000/health", "ok", "raw", "同 curl；-O 判 W2", EV_NET + "；" + TC + ":3547-3551"),
    _C("nc", "nc -z -w 2 127.0.0.1 22", "ok", "raw", "TCP 连接探针，无需能力（busybox）", EV_NET),
    _C("nft", "nft list ruleset", "no", "structured", "NETLINK_NETFILTER 全部请求需 CAP_NET_ADMIN；且 W2 硬表", EV_NOCAP + "；" + EV_W2),
    _C("tc", "tc -j qdisc show", "ok", "structured", "netlink RTM_GETQDISC 读无需能力；写需 CAP_NET_ADMIN", EV_NET + "；" + EV_NOCAP),
    _C("ethtool", "ethtool eth0", "no", "structured", EV_ABSENT, "出厂树 usr/bin 列表"),
    _C("conntrack", "conntrack -L", "no", "structured", EV_ABSENT, "出厂树 usr/bin 列表"),
    _C("sshd", "sshd -T", "no", "structured", "要 /etc/ssh/sshd_config 与主机密钥（均不在白名单）", EV_NOETC),
    # ---- 存储 ----
    _C("lsblk", "lsblk -J", "ok", "structured", "/sys/block + /proc/partitions 全局；udev 库 /run/udev 缺 → 少 vendor/serial 等细节", EV_SYS + "；" + EV_NORUN),
    _C("findmnt", "findmnt -J", "partial", "structured", "只列沙箱自己的挂载表", SB + ":2089-2304"),
    _C("df", "df -P", "partial", "structured", "只见沙箱挂载点；/usr 是宿主根分区的 bind → 其容量/用量可见，宿主其余挂载不可见", SB + ":2120-2156"),
    _C("du", "du -x -d1 /var", "no", "structured", "宿主目录不可见（/var 为空）", EV_NOVAR),
    _C("blkid", "blkid -o export", "no", "structured", "无块设备节点", EV_NODEV),
    _C("dumpe2fs", "dumpe2fs -h /dev/sda1", "no", "structured", "无块设备节点", EV_NODEV),
    _C("mount", "mount", "no", "structured", "需 CAP_SYS_ADMIN；且 W2 硬表", EV_NOCAP + "；" + EV_W2),
    _C("umount", "umount /x", "no", "structured", "需 CAP_SYS_ADMIN；且 W2 硬表", EV_NOCAP + "；" + EV_W2),
    _C("fstrim", "fstrim -v /", "no", "structured", "需设备节点与 CAP_SYS_ADMIN", EV_NODEV + "；" + EV_NOCAP),
    _C("swapon", "swapon --show", "no", "structured", "需 CAP_SYS_ADMIN；且 W2 硬表", EV_NOCAP + "；" + EV_W2),
    _C("swapoff", "swapoff -a", "no", "structured", "需 CAP_SYS_ADMIN；且 W2 硬表", EV_NOCAP + "；" + EV_W2),
    _C("fdisk", "fdisk -l", "no", "structured", "无块设备节点；且 W2 硬表", EV_NODEV + "；" + EV_W2),
    _C("smartctl", "smartctl -a /dev/sda", "no", "structured", "无块设备节点；直读盘还要 CAP_SYS_RAWIO/CAP_SYS_ADMIN", EV_NODEV + "；" + EV_NOCAP),
    _C("wdctl", "wdctl", "no", "raw", "无 /dev/watchdog 节点", EV_NODEV),
    _C("lsattr", "lsattr /usr/local/bin/occ", "partial", "raw", _SBXONLY, EV_USR),
    # ---- 包管理 ----
    _C("dpkg", "dpkg-query -W", "no", "structured", "/var/lib/dpkg/status 缺", EV_NOVAR),
    _C("dpkg-query", "dpkg-query -W", "no", "structured", "/var/lib/dpkg/status 缺", EV_NOVAR),
    _C("dpkg-query", "dpkg-query -W", "no", "structured", "/var/lib/dpkg/status 缺", EV_NOVAR),
    _C("dpkg-query", "dpkg-query -W", "no", "structured", "/var/lib/dpkg/status 缺", EV_NOVAR),
    _C("apt", "apt list --installed", "no", "structured", "/var/lib/dpkg、/var/lib/apt、/etc/apt 缺", EV_NOVAR + "；" + EV_NOETC),
    # ---- 用户/会话/认证 ----
    _C("id", "id", "no", "raw", "无 /etc/passwd、/etc/group → 名字解析全失败", EV_NOETC),
    _C("getent", "getent passwd", "no", "structured", "无 /etc/passwd、/etc/group", EV_NOETC),
    _C("who", "who", "no", "structured", "/var/run/utmp 缺", EV_NORUN),
    _C("w", "w -h", "no", "structured", "/var/run/utmp 缺", EV_NORUN),
    _C("last", "last -n 5", "no", "structured", "/var/log/wtmp 缺", EV_NOVAR),
    _C("passwd", "passwd -S root", "no", "structured", "无 /etc/passwd、/etc/shadow 与 PAM 配置", EV_NOETC),
    _C("useradd", "useradd -D", "no", "raw", "无 /etc/passwd、/etc/login.defs", EV_NOETC),
    _C("usermod", "usermod -L x", "no", "raw", "同 useradd", EV_NOETC),
    _C("userdel", "userdel x", "no", "raw", "同 useradd", EV_NOETC),
    _C("groupadd", "groupadd x", "no", "raw", "同 useradd（无 /etc/group、/etc/login.defs）", EV_NOETC),
    _C("groupmod", "groupmod -n y x", "no", "raw", "同 groupadd", EV_NOETC),
    _C("groupdel", "groupdel x", "no", "raw", "同 groupadd", EV_NOETC),
    _C("crontab", "crontab -l", "no", "raw", "/var/spool/cron/crontabs 缺，且按用户名找 spool 要 /etc/passwd", EV_NOVAR + "；" + EV_NOETC),
    _C("sha256sum", "sha256sum /etc/aikernel/policy.conf", "partial", "raw", "只能算沙箱可见树的文件", EV_USR),
    # ---- AIKernel 自带 ----
    _C("aikctl", "aikctl policy get --json", "ok", "structured", "python3 在 /usr 只读面；逐子命令依赖见 §8", EV_USR),
    _C("aik-sandbox", "aik-sandbox status", "no", "structured", "宿主 /sandbox 不在沙箱视图 → 恒「尚无隔离区」", SB + ":2701-2818"),
    _C("aik-backup", "aik-backup --dry-run", "no", "raw", "依赖 /var/backups、/var/lib/aikernel（沙箱视图外）", EV_NOVAR + "；" + EV_INFER),
    _C("aik-reset", "aik-reset --help", "no", "raw", "写面工具，不属于读面", EV_INFER),
    _C("ollama", "ollama list", "ok", "structured", "客户端走 127.0.0.1:11434（宿主网络保留）", EV_NET + "；" + EV_INFER),
    _C("occ", "occ --help", "ok", "raw", "可在沙箱内嵌套起 occ（model.toml/provider.toml 被拷入 /root/.aikernel）", SB + ":2260-2270"),
    _C("python3", "python3 -c 'print(1)'", "ok", "raw", "任意代码，但受沙箱视图与能力集约束", EV_USR),
    # ---- 通用工具（旧白名单里也有，逐条给判定） ----
    _C("ls", "ls /sys/class/net", "partial", "raw", _SBXONLY, EV_USR),
    _C("cat", "cat /proc/meminfo", "partial", "structured", _SBXONLY + "；/proc、/sys 全局节点可读", EV_PROC),
    _C("head", "head -n 5 /proc/meminfo", "ok", "raw", _COMMON, EV_PROC),
    _C("tail", "tail -n 5 /proc/meminfo", "ok", "raw", _COMMON, EV_PROC),
    _C("grep", "grep -c Mem /proc/meminfo", "ok", "raw", _COMMON, EV_PROC),
    _C("sort", "sort /proc/meminfo", "ok", "raw", _COMMON, EV_PROC),
    _C("uniq", "sort /proc/meminfo | uniq -c", "ok", "raw", _COMMON, EV_PROC),
    _C("cut", "cut -d: -f1 /proc/meminfo", "ok", "raw", _COMMON, EV_PROC),
    _C("wc", "wc -l /proc/meminfo", "ok", "raw", _COMMON, EV_PROC),
    _C("sed", "sed -n 1,3p /proc/meminfo", "ok", "raw", _COMMON, EV_PROC),
    _C("tee", "cat /proc/meminfo | tee /tmp/m", "ok", "raw", _RW, SB + ":2111-2114"),
    _C("echo", "echo ok", "ok", "raw", _COMMON, EV_USR),
    _C("printf", "printf ok", "ok", "raw", _COMMON, EV_USR),
    _C("which", "which awk", "ok", "raw", "/etc/alternatives/which 链被单文件 bind 修复", EV_ETCHK),
    _C("whereis", "whereis ls", "ok", "raw", "只查 PATH 与固定目录", EV_USR),
    _C("find", "find /sys/class/net -maxdepth 1", "partial", "raw", _SBXONLY, EV_USR),
    _C("stat", "stat /usr/local/bin/occ", "partial", "structured", _SBXONLY, EV_USR),
    _C("mkdir", "mkdir -p /tmp/d", "partial", "raw", _RW, SB + ":2111-2114"),
    _C("touch", "touch /tmp/f", "partial", "raw", _RW, SB + ":2111-2114"),
    _C("cp", "cp /etc/hosts /tmp/h", "partial", "raw", _RW, SB + ":2111-2114"),
    _C("mv", "mv /tmp/a /tmp/b", "partial", "raw", _RW, SB + ":2111-2114"),
    _C("ln", "ln -s /etc/hosts /tmp/h", "partial", "raw", _RW, SB + ":2111-2114"),
    _C("rm", "rm /tmp/f", "partial", "raw", _RW + "；-r/-f 递归形态判 W2", SB + ":2111-2114"),
    _C("chmod", "chmod 644 /tmp/f", "partial", "raw", _RW + "；世界可写模式判 W2", SB + ":2111-2114"),
    _C("chown", "chown 0:0 /tmp/f", "no", "raw", "无 CAP_CHOWN；递归形态判 W2", EV_NOCAP),
    _C("tar", "tar -cf /tmp/t.tar /etc/hosts", "ok", "raw", _COMMON, EV_USR),
    _C("gzip", "gzip -c /etc/hosts > /tmp/h.gz", "ok", "raw", _COMMON, EV_USR),
    _C("sync", "sync", "ok", "raw", "sync(2) 不需能力（全局副作用）", EV_INFER),
    _C("gcc", "gcc --version", "no", "raw", EV_ABSENT, "出厂树 usr/bin 列表"),
    _C("cc", "cc --version", "no", "raw", EV_ABSENT, "出厂树 usr/bin 列表"),
]
# 旧白名单里出厂根本没有的二进制（逐条一条，方便对照）
for _n in ("quota", "repquota", "setquota", "pvs", "vgs", "lvs", "aa-status",
           "apparmor_status", "aa-enforce", "aa-complain", "aa-disable"):
    SANDBOX_COMMANDS.append(_C(_n, _n + " --help", "no", "raw", EV_ABSENT,
                               "出厂树 usr/bin、usr/sbin 列表"))
SANDBOX_COMMANDS.sort(key=lambda c: c[0])
SBX = {c[0]: {"sample": c[1], "verdict": c[2], "form": c[3], "why": c[4],
              "ev": c[5]} for c in SANDBOX_COMMANDS}

# occ W2 硬表（tools.c:3424-3430）与 systemctl 写动词（3431-3434）
W2_HARD = {"mkfs", "fdisk", "sfdisk", "parted", "wipefs", "blockdev", "dd",
           "reboot", "shutdown", "poweroff", "halt", "init", "telinit",
           "swapon", "swapoff", "mount", "umount", "kill", "killall",
           "killall5", "pkill", "iptables", "nft", "chattr"}
W2_SYSTEMCTL = {"stop", "disable", "mask", "kill", "isolate", "emergency",
                "rescue"}
CURL_W2 = (" -d", "--data", " -T", "--upload-file", " -F", "--form",
           "--post", "-X POST", "-X PUT", "-X PATCH")


def classify_bash(cmd):
    """镜像 tools.c w2_bash_hit 的命令级风险（粘贴形态 + 首行首 token 的
    硬表；够审计表里的样例命令用）。返回 "W1" 或 "W2"。"""
    if "\n" in cmd or "sudo" in cmd:
        return "W2"
    if "| sh" in cmd or "|sh" in cmd or "| bash" in cmd or "|bash" in cmd:
        return "W2"
    if cmd.count("&&") + cmd.count(";") >= 2:
        return "W2"
    toks = cmd.split()
    first = toks[0] if toks else ""
    if first.startswith("mkfs.") or first in W2_HARD:
        return "W2"
    if first == "rm" and (" -r" in cmd or " -R" in cmd or "-fr" in cmd
                          or "-rf" in cmd or "--recursive" in cmd):
        return "W2"
    if first == "systemctl":
        return "W2" if len(toks) > 1 and toks[1] in W2_SYSTEMCTL else "W1"
    if first == "chown" and (" -R" in cmd or "--recursive" in cmd):
        return "W2"
    if first in ("curl", "wget"):
        if " -o " in cmd or " -O" in cmd:
            return "W2"
        if any(f in cmd for f in CURL_W2):
            return "W2"
    return "W1"


# ---------------------------------------------------------------------------
# aikctl 读类子命令在沙箱内的可达性（静态推断）。沙箱内以 uid 0 跑
# python3（/usr 只读面）；可用与否全看依赖文件是否在沙箱视图内。
# 子命令 → (判定, 输出形态, 原因, 依据)
# ---------------------------------------------------------------------------
AIKCTL_SUBS = {
    "audit status": ("ok", "structured", "读 /proc/ai/audit 首行 + /sys/kernel/ai/chain/*（全局节点）", "aikctl:668-679"),
    "audit export": ("ok", "structured", "逐节点读 /proc/ai/audit → jsonl 到 stdout", "aikctl:572-587"),
    "policy get": ("ok", "structured", "/etc/aikernel 整目录在 /etc 白名单；但 /etc/passwd、/etc/group 缺 → "
                    "「每人生效档推演」拿不到 uid 与组成员", "aikctl:4610-4656,4588-4607"),
    "policy get sudoers": ("no", "structured", "/etc/sudoers 不在白名单", "aikctl:4773-4800"),
    "session list": ("no", "structured", "/var/run/utmp 缺 → 恒报「无会话」（假阴性）", "aikctl:5081-5092"),
    "quota get": ("no", "structured", "出厂无 quota 二进制 → unavailable（与宿主同态，非沙箱问题）", "aikctl:5127-5155"),
    "user list": ("partial", "structured", "console-gate 在 /etc/aikernel 只读面（沙箱内 uid 0 可读 0600 的口令哈希）；"
                  "OS 号对照要 /etc/passwd → 全部显示号缺席", "aikctl:4149-4165"),
    "compat hw": ("partial", "structured", "/sys/bus/pci|usb、/sys/kernel/iommu_groups 可见；/dev/dri 缺", "aikctl:2014-2069"),
    "abi": ("no", "raw", "NETLINK_AI socket 要 CAP_SYS_ADMIN", "aikctl:1080-1124"),
    "audit tail": ("no", "raw", "~/.aikernel/audit.log 不在沙箱（/root 只有两份 toml 拷贝）", "aikctl:5259-5265"),
    "module list": ("no", "structured", "/var/lib/aikernel/module 缺", "aikctl:2235,2444-2462"),
    "aipd status": ("no", "structured", "/run/aipd.stats、/var/lib/aikernel/aipd 缺", "aikctl:3420-3423"),
}

# ---------------------------------------------------------------------------
# 对象 → 出厂读面映射用的构造器
#   R 宿主 occ read   G 宿主 occ glob   S 沙箱命令   K aikctl   C 回环 HTTP GET
#   N occ config_write_network show
# ---------------------------------------------------------------------------
def R(target, form, ev, root_only=False, cond="", partial=False):
    return {"kind": "occ:read", "target": target, "form": form, "ev": ev,
            "root_only": root_only, "cond": cond, "partial": partial,
            "verdict": "ok"}


def G(pattern, root, form, ev, root_only=False, cond="", partial=False):
    return {"kind": "occ:glob", "target": "%s :: %s" % (root, pattern),
            "form": form, "ev": ev, "root_only": root_only, "cond": cond,
            "partial": partial, "verdict": "ok"}


_SB_ETC_REAL = ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
                "/etc/aikernel/")


def _cat_verdict(cmd):
    """`cat <路径>` 在沙箱里能否读到真实数据。返回 (判定, 依据)。"""
    toks = cmd.split()
    path = toks[1] if len(toks) > 1 else ""
    if re.match(r"^/proc/(\d+|self|thread-self)(/|$)", path):
        return "no", EV_PIDNS + "（/proc/<pid> 指向沙箱自己的进程）"
    if path in ("/proc/mounts", "/proc/self/mountinfo"):
        return "partial", SB + ":2089-2304（mountinfo 是沙箱自己的挂载表）"
        return "no", EV_PIDNS + "；" + SB + ":2089-2304（mountinfo 是沙箱自己的挂载表）"
    if path.startswith("/proc/"):
        return "ok", EV_PROC
    if path.startswith("/sys/fs/cgroup/"):
        return "no", EV_SYS + "（cgroup2 是独立文件系统，沙箱内未挂 → 空目录）"
    if path.startswith("/sys/kernel/debug/") or \
            path.startswith("/sys/kernel/security/"):
        return "no", EV_SYS + "（debugfs/securityfs 是独立文件系统，沙箱内未挂）"
    if path.startswith("/sys/"):
        return "ok", EV_SYS
    if path.startswith(_SB_ETC_REAL):
        return "ok", EV_ETCHK
    if path.startswith("/tmp/") or path.startswith("/var/ai/"):
        return "partial", SB + ":2244-2258（沙箱内 /tmp 是空 tmpfs；只有工作区与产物区是真数据）"
    return "no", EV_NOVAR + "；" + EV_NOETC + "（该路径不在沙箱视图）"


def S(cmd, form=None, ev="", cond="", partial=None, verdict=None):
    """沙箱命令读面。verdict/partial 显式给出时覆盖命令表默认
    （例：`ip netns list` 比 `ip` 的表项更窄）。"""
    name = cmd.split()[0]
    if name not in SBX:
        raise KeyError("沙箱命令表缺 %r（%s）" % (name, cmd))
    row = SBX[name]
    if verdict is None:
        verdict = row["verdict"]
        if name == "cat":
            verdict, why = _cat_verdict(cmd)
            if not ev:
                ev = why
    if partial is None:
        partial = (verdict == "partial")
    return {"kind": "sb", "target": cmd, "form": form or row["form"],
            "ev": ev or row["ev"], "root_only": False, "cond": cond,
            "partial": partial, "verdict": verdict}


def K(sub, form=None, ev=""):
    if sub not in AIKCTL_SUBS:
        raise KeyError("aikctl 子命令表缺 %r" % sub)
    verdict, dform, why, dev = AIKCTL_SUBS[sub]
    return {"kind": "aikctl", "target": "aikctl " + sub, "form": form or dform,
            "ev": ev or (dev + "；" + why), "root_only": False,
            "cond": "", "partial": verdict == "partial", "verdict": verdict}


def C(url, form, ev, cond=""):
    return {"kind": "curl", "target": "curl -s " + url, "form": form, "ev": ev,
            "root_only": False, "cond": cond, "partial": False, "verdict": "ok"}


def N(form, ev):
    return {"kind": "occ:netcfg", "target": "config_write_network action=show",
            "form": form, "ev": ev, "root_only": False, "cond": "",
            "partial": False, "verdict": "ok"}


EV_READ = TC + ":750-815（read 无路径域限制）"
EV_GLOB = TC + ":1234-1347（glob 走宿主目录；200 项上限 1159,1216-1219）"
EV_READ0 = TC + ":515-552（procfs/sysfs 零尺寸文件流式读）"
EV_SMEAPI = "aikernel-memory.service:8；smehttp/routes.c:7-36（GET /health /stats /export /regions /graph /config）"
EV_DTAPI = "aik-desktop.service:3,12；desktop/desktopd.c:247-626（GET /api/health /stats /apps /windows /theme /wallpaper /notifs /clipboard /chat/*）"
EV_TRACE = "occ_tools/occ_tools.h:16-18,43-44（trace 落 ~/.occ/trace/<session>.jsonl）"
EV_NETCFG = TC + ":2977-3035（show 读 /etc/systemd/network/*.network 关键行）"
COND_NODE = "依赖运行态：内核节点存在"
COND_SVC = "依赖运行态：服务在跑"
COND_TOKEN = "依赖运行态：api.auth_token 为空或沙箱内可取"


# ---------------------------------------------------------------------------
# 对象 → 出厂读面映射。每条带证据（file:line）。标记含义：
#   root_only  仅 root 身份读得到（文件权限）      cond   依赖运行态
#   partial    只看到沙箱自身/一部分数据
# ---------------------------------------------------------------------------
def X(target, ev):
    """结构性缺席：写明为什么在出厂视角下没有读面。"""
    return {"kind": "absent", "target": target, "form": "none", "ev": ev,
            "root_only": False, "cond": "", "partial": False, "verdict": "no"}


_AI = "依赖运行态：AIKernel 内核节点存在（/proc/ai、/sys/kernel/ai）"
_SME = COND_SVC + "；" + COND_TOKEN
_AI_EV = "tools.json（procfs_read_* 的 path 字段）；" + EV_PROC
_ZONE_W = TC + ":447-471（写域=工作目录∪/tmp∪/var/ai∪$HOME；越界判 W2 见 :3577-3590）"


def CS(path):
    return C("http://127.0.0.1:8000" + path, "structured", EV_SMEAPI, _SME)


def CD(path):
    return C("http://127.0.0.1:8091" + path, "structured", EV_DTAPI, COND_SVC)


READ_MAP = {
    # ---- 进程/线程/调度 ----
    "PROC-01": [
        G("*", "/proc", "raw", EV_GLOB + "；宿主进程数超过约 190 项即截断", partial=True),
        R("/proc/1/status", "structured", EV_READ + "；须逐 pid 读", partial=True),
        S("ps -eo pid,ppid,stat,comm"),
    ],
    "PROC-02": [
        G("task/*", "/proc/1", "raw", EV_GLOB),
        R("/proc/1/status", "structured", EV_READ + "（Threads: 字段）"),
    ],
    "PROC-03": [
        R("/proc/1/sched", "structured", EV_READ + "（键 : 值行）"),
        R("/proc/1/stat", "structured", EV_READ),
        S("ps -eo pid,ni,pri,comm"),
    ],
    "PROC-04": [
        R("/proc/1/smaps", "structured", EV_READ + "；0400 属主 root", root_only=True),
        R("/proc/1/io", "structured", EV_READ + "；0400 属主 root", root_only=True),
        G("fd/*", "/proc/1", "raw", EV_GLOB + "；0500 属主 root", root_only=True),
    ],
    "PROC-05": [R("/proc/1/cgroup", "structured", EV_READ),
                S("cat /sys/fs/cgroup/cgroup.procs")],
    # ---- CPU/内存/PSI/IO ----
    "RES-01": [S("lscpu -J"), S("cat /proc/cpuinfo"),
               R("/proc/cpuinfo", "structured", EV_READ0)],
    "RES-02": [S("cat /proc/stat"), S("uptime"), S("vmstat 1 2"),
               R("/proc/stat", "structured", EV_READ0)],
    "RES-03": [S("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", cond=COND_NODE),
               R("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "structured",
                 EV_READ0, cond=COND_NODE)],
    "RES-04": [S("free -b"), S("cat /proc/meminfo"), S("cat /proc/swaps"),
               R("/proc/meminfo", "structured", EV_READ0)],
    "RES-05": [S("cat /proc/pressure/cpu", cond=COND_NODE),
               S("cat /proc/pressure/memory", cond=COND_NODE),
               S("cat /proc/pressure/io", cond=COND_NODE),
               R("/proc/pressure/memory", "structured", EV_READ0, cond=COND_NODE)],
    "RES-06": [S("cat /proc/diskstats"), S("vmstat -d"), S("cat /sys/block/sda/stat"),
               R("/proc/diskstats", "structured", EV_READ0),
               R("/sys/block/sda/stat", "structured", EV_READ0)],
    "RES-07": [S("cat /sys/class/bdi/8:0/read_ahead_kb", cond=COND_NODE),
               R("/proc/sys/vm/readahead", "structured", EV_READ0),
               R("/sys/class/bdi/8:0/read_ahead_kb", "structured", EV_READ0, cond=COND_NODE)],
    # ---- cgroup ----
    "CG-01": [S("cat /sys/fs/cgroup/cgroup.controllers"),
              R("/sys/fs/cgroup/cgroup.controllers", "structured", EV_READ0),
              R("/sys/fs/cgroup/system.slice/memory.max", "structured",
                EV_READ0 + "（根 cgroup 没有 memory.max，须指到非根 cgroup）"),
              R("/sys/fs/cgroup/system.slice/cpu.max", "structured", EV_READ0)],
    "CG-02": [R("/sys/fs/cgroup/system.slice/memory.current", "structured", EV_READ0),
              R("/sys/fs/cgroup/system.slice/memory.stat", "structured", EV_READ0),
              S("cat /sys/fs/cgroup/memory.current")],
    # ---- 文件/目录/元数据/ACL/xattr ----
    "FS-01": [R("/etc/hostname", "raw", EV_READ)],
    "FS-02": [G("*", "/etc/systemd/system", "raw", EV_GLOB + "（只有路径，无类型/权限/属主/大小）")],
    "FS-03": [G("ssh_host_*", "/etc/ssh", "raw", EV_GLOB + "（只有文件名：存在性与名字，无 mode/属主/大小/时间）", partial=True),
              S("stat /usr/local/bin/occ")],
    "FS-04": [R("/etc/hostname", "raw", EV_READ)],
    "FS-05": [G("*", "/etc/cron.d", "raw", EV_GLOB)],
    "FS-06": [X("getfacl", "出厂树无 getfacl/setfacl；沙箱 stat 只见沙箱可见树")],
    "FS-07": [X("getfattr", "出厂树无 getfattr/setfattr")],
    "FS-08": [S("lsattr /usr/local/bin/occ")],
    "FS-09": [S("sha256sum /etc/aikernel/policy.conf")],
    "FS-10": [S("quota --help"), K("quota get")],
    # ---- 磁盘/分区/文件系统/SMART ----
    "DISK-01": [S("lsblk -J"), S("cat /proc/partitions"),
                R("/proc/partitions", "structured", EV_READ0), S("blkid -o export")],
    "DISK-02": [R("/etc/fstab", "raw", EV_READ),
                R("/proc/mounts", "structured", EV_READ0 + "（宿主挂载表）"),
                S("cat /proc/mounts"), S("dumpe2fs -h /dev/sda1")],
    "DISK-03": [S("smartctl -a /dev/sda")],
    "DISK-04": [S("lsblk -J"),
                R("/sys/block/dm-0/dm/name", "structured", EV_READ0, cond=COND_NODE)],
    "DISK-05": [S("df -P"), S("du -x -d1 /var")],
    "DISK-06": [S("cat /proc/mdstat"), S("lsblk -J"),
                R("/proc/mdstat", "structured", EV_READ0)],
    # ---- systemd/服务/日志/启动 ----
    "SYS-01": [G("*.service", "/etc/systemd/system", "raw", EV_GLOB + "（只有 unit 文件名，无 active/failed 状态）", partial=True),
               G("*", "/run/systemd/system", "raw", EV_GLOB + "（运行态生成物）", cond=COND_SVC, partial=True),
               S("systemctl list-units --no-pager")],
    "SYS-02": [S("systemctl --failed --no-legend")],
    "SYS-03": [G("*", "/var/log/journal", "raw", EV_GLOB + "；/var/log/journal 2750 root:systemd-journal；日志本体二进制，occ read 拒读", root_only=True, partial=True),
               R("/tmp/sme.log", "raw", EV_READ + "；aikernel-memory.service:9-10 把 aikd 标准输出/错误追加到这里"),
               S("journalctl -o json --no-pager -n 100")],
    "SYS-04": [S("dmesg --color=never",
                 cond="依赖运行态：kernel.dmesg_restrict=0（沙箱无 CAP_SYSLOG）")],
    "SYS-05": [S("cat /proc/cmdline"), R("/proc/cmdline", "structured", EV_READ0),
               G("*", "/boot", "raw", EV_GLOB, partial=True),
               R("/boot/grub/grubenv", "raw", EV_READ + "；/boot/grub 属 root", root_only=True, partial=True),
               S("aik-upgrade status")],
    "SYS-06": [S("systemd-analyze time")],
    "SYS-07": [G("*.timer", "/etc/systemd/system", "raw", EV_GLOB + "（只有文件名，无下次触发时间）", partial=True),
               G("*", "/etc/cron.d", "raw", EV_GLOB),
               S("systemctl list-timers --no-pager")],
    "SYS-08": [G("*.d/*.conf", "/etc/systemd/system", "raw", EV_GLOB),
               R("/etc/systemd/system/aikernel-api.service", "raw", EV_READ)],
    # ---- 网络 ----
    "NET-01": [S("ip -j link"), S("cat /sys/class/net/eth0/statistics/rx_bytes"),
               R("/sys/class/net/eth0/operstate", "structured", EV_READ0),
               R("/sys/class/net/eth0/statistics/rx_bytes", "structured", EV_READ0),
               S("ethtool eth0")],
    "NET-02": [S("ip -j addr"), S("ip -j route"), S("cat /proc/net/route"),
               R("/proc/net/route", "structured", EV_READ0)],
    "NET-03": [S("ss -tunl"), S("cat /proc/net/tcp"),
               R("/proc/net/tcp", "structured", EV_READ0)],
    "NET-04": [S("cat /proc/net/nf_conntrack", cond=COND_NODE),
               R("/proc/net/nf_conntrack", "structured", EV_READ0, cond=COND_NODE),
               S("conntrack -L")],
    "NET-05": [S("cat /etc/resolv.conf"), R("/etc/resolv.conf", "structured", EV_READ),
               S("nslookup 127.0.0.1"), S("resolvectl status")],
    "NET-06": [R("/etc/nftables.conf", "raw", EV_READ), S("nft list ruleset"),
               S("cat /sys/kernel/security/apparmor/profiles"),
               R("/sys/kernel/security/apparmor/profiles", "raw",
                 EV_READ0 + "；securityfs 属 root", root_only=True,
                 cond="依赖运行态：securityfs 已挂载")],
    "NET-07": [G("*", "/run/netns", "raw", EV_GLOB, cond="依赖运行态：存在具名 netns", partial=True),
               S("ip netns list", verdict="no",
                 ev="沙箱无 /var/run/netns（" + SB + ":824-859）→ 恒空表")],
    "NET-08": [S("ip -d -j link"), S("cat /sys/class/net/eth0/mtu"),
               N("structured", EV_NETCFG),
               R("/etc/systemd/network/80-wired.network", "structured", EV_READ)],
    # ---- 用户/组/会话/sudo/策略/租约 ----
    "ID-01": [R("/etc/passwd", "raw", EV_READ), S("getent passwd"), S("cat /etc/passwd")],
    "ID-02": [R("/etc/group", "raw", EV_READ), S("getent group")],
    "ID-03": [S("who"), S("ps -eo user,tty,stat,comm"), K("session list"),
              R("/proc/1/loginuid", "raw", EV_READ + "；须逐 pid glob+read，且无 tty/来源/空闲", partial=True)],
    "ID-04": [R("/etc/sudoers", "raw",
                EV_READ + "；0440 root:root（出厂暂存树不含该文件，由基础镜像提供）", root_only=True),
              K("policy get sudoers")],
    "ID-05": [R("/etc/aikernel/policy.conf", "raw", EV_READ),
              K("policy get", ev="aikctl:4610-4656；" + EV_ETCHK),
              G("*.json", "/var/lib/aikernel/leases", "raw",
                EV_GLOB + "；docs/W74-LEASE.md（租约 JSON 存放处）", cond="依赖运行态：存在租约文件"),
              R("/etc/aikernel/tools.json", "structured", EV_READ + "；266KB，须分页窗口读")],
    "ID-06": [R("/etc/ssh/sshd_config", "raw", EV_READ),
              G("*", "/etc/ssh/sshd_config.d", "raw", EV_GLOB)],
    "ID-07": [R("/root/.ssh/authorized_keys", "raw", EV_READ + "；/root 0700", root_only=True)],
    "ID-08": [G("ssh_host_*", "/etc/ssh", "raw", EV_GLOB + "（只有文件名）", partial=True),
              R("/etc/ssh/ssh_host_ed25519_key.pub", "raw", EV_READ)],
    # ---- 包管理 ----
    "PKG-01": [R("/var/lib/dpkg/status", "raw",
                 EV_READ + "；151KB，单次窗口 8KB/500 行 → 约 30 次分页"),
               S("dpkg-query -W")],
    "PKG-02": [R("/etc/apt/sources.list", "raw", EV_READ,
                 cond="依赖基础镜像提供该文件（出厂暂存树不含）"),
               G("*", "/etc/apt/sources.list.d", "raw", EV_GLOB),
               R("/etc/apt/apt.conf.d/51-aik-upgrade-policy", "raw", EV_READ)],
    "PKG-03": [S("apt list --upgradable")],
    "PKG-04": [S("dpkg-query -W")],
    "PKG-05": [R("/var/lib/dpkg/status", "raw", EV_READ + "；分页"), S("uname -r")],
    # ---- 硬件 ----
    "HW-01": [S("lscpu -J"), R("/proc/cpuinfo", "structured", EV_READ0)],
    "HW-02": [G("*", "/sys/class/drm", "raw", EV_GLOB, cond=COND_NODE),
              S("cat /sys/class/drm/card0/status", cond=COND_NODE)],
    "HW-03": [G("*", "/sys/class/hwmon", "raw", EV_GLOB, cond=COND_NODE),
              S("cat /sys/class/thermal/thermal_zone0/temp", cond=COND_NODE),
              S("cat /sys/class/hwmon/hwmon0/temp1_input", cond=COND_NODE)],
    "HW-04": [G("*", "/sys/class/power_supply", "raw", EV_GLOB, cond=COND_NODE),
              S("cat /sys/class/power_supply/ACAD/online", cond=COND_NODE)],
    "HW-05": [G("*", "/sys/bus/pci/devices", "raw", EV_GLOB),
              S("cat /sys/bus/pci/devices/0000:00:02.0/vendor"), K("compat hw")],
    # ---- 内核 AI 遥测 ----
    "AI-01": [S("cat /proc/ai/status", cond=_AI), R("/proc/ai/status", "structured", _AI_EV, cond=_AI)],
    "AI-02": [S("cat /proc/ai/control", cond=_AI), R("/proc/ai/control", "structured", _AI_EV, cond=_AI)],
    "AI-03": [S("cat /proc/ai/decisions", cond=_AI), S("cat /proc/ai/chains", cond=_AI),
              R("/proc/ai/decisions", "structured", _AI_EV, cond=_AI)],
    "AI-04": [S("cat /proc/ai/telemetry", cond=_AI),
              R("/proc/ai/telemetry", "structured", _AI_EV, cond=_AI)],
    "AI-05": [S("cat /proc/ai/hitrate", cond=_AI), S("cat /proc/ai/latency", cond=_AI),
              S("cat /sys/kernel/ai/stats/telemetry_emitted", cond=_AI),
              S("cat /sys/kernel/ai/stats/decisions_total", cond=_AI),
              S("cat /sys/kernel/ai/stats/runtime_state", cond=_AI),
              R("/proc/ai/hitrate", "structured", _AI_EV, cond=_AI),
              R("/sys/kernel/ai/stats/telemetry_emitted", "structured", _AI_EV, cond=_AI)],
    "AI-06": [S("cat /sys/kernel/ai/model_out", cond=_AI), S("cat /proc/ai/status", cond=_AI),
              R("/sys/kernel/ai/model_out", "structured", _AI_EV, cond=_AI)],
    "AI-07": [S("cat /sys/kernel/ai/decision/stats", cond=_AI), S("cat /proc/ai/hitrate", cond=_AI),
              R("/sys/kernel/ai/decision/stats", "structured", _AI_EV, cond=_AI)],
    "AI-08": [S("dmesg --color=never",
                cond="依赖运行态：kernel.dmesg_restrict=0（沙箱无 CAP_SYSLOG）"),
              S("cat /sys/kernel/debug/kunit/results")],
    # ---- SME/trace/训练 ----
    "MEM-01": [CS("/health"), CS("/stats")],
    "MEM-02": [CS("/export"), C("http://127.0.0.1:8000/memories/<id>", "structured", EV_SMEAPI, _SME)],
    "MEM-03": [CS("/graph"), CS("/facts")],
    "MEM-04": [CS("/regions")],
    "MEM-05": [CS("/qapairs"), CS("/profile"), CS("/metrics"), CS("/config")],
    "MEM-06": [G("*.jsonl", "$HOME/.occ/trace", "raw", EV_TRACE),
               R("$HOME/.occ/trace/<session>.jsonl", "structured", EV_TRACE + "；JSON 行")],
    "MEM-07": [X("trace.export", "出厂无导出工具（occ 无 task/recall 之外的 SME 工具）")],
    "MEM-08": [X("~/.occ/sessions.db",
                 "occ_core/occ_session.h:6-8,145（会话库是 sqlite 二进制）；" + TC + ":571-574,776-780（read 拒读含 NUL 文件）")],
    # ---- 沙箱 ----
    "SB-01": [S("aik-sandbox status")],
    "SB-02": [X("沙箱 cgroup",
                SB + ":1327-1358（宿主侧 cgroup 锚点）；bash 工具一调用一区（occ_tools/sandbox.c:18-22），AI 无法在自己那一次调用期间从宿主侧读它")],
    "SB-03": [G("*", "/var/ai/sandbox-artifacts", "raw", EV_GLOB + "；产物根 0700 root（" + SB + ":546-562）", root_only=True)],
    "SB-04": [X("sandbox_create/spawn/destroy", "occ 无对应工具；生命周期只在 bash 工具内部隐式发生（occ_tools/sandbox.c:518-599）")],
    "SB-05": [R("/usr/local/share/aikernel/tools-sandbox.json", "structured",
                EV_READ + "；出厂未置 OCC_ORCH_TOOLS，无子智能体通道", partial=True)],
    # ---- 桌面 ----
    "DT-01": [CD("/api/health"), CD("/api/stats")],
    "DT-02": [CD("/api/apps")],
    "DT-03": [CD("/api/windows")],
    "DT-04": [CD("/api/theme"), CD("/api/wallpaper")],
    "DT-05": [CD("/api/notifs")],
    "DT-06": [],
    "DT-07": [C("http://127.0.0.1:8091/api/screenshot", "structured",
                EV_DTAPI + "；unit 设 AIK_DESKTOP_SCREENSHOT=0", COND_SVC + "且截图开启")],
    "DT-08": [CD("/api/clipboard")],
    "DT-09": [CD("/api/chat/history"), CD("/api/chat/sessions")],
    # ---- 时间/NTP/cron ----
    "TIME-01": [S("date"),
                G("synchronized", "/run/systemd/timesync", "raw",
                  EV_GLOB + "（文件存在=已同步）", cond="依赖运行态：systemd-timesyncd 在用"),
                S("timedatectl show")],
    "TIME-02": [],
    "TIME-03": [G("*", "/etc/cron.d", "raw", EV_GLOB),
                G("*.timer", "/etc/systemd/system", "raw", EV_GLOB + "（只有文件名，无下次触发时间）", partial=True),
                R("/etc/crontab", "raw", EV_READ, cond="依赖基础镜像提供该文件"),
                S("systemctl list-timers --no-pager")],
}

# ---------------------------------------------------------------------------
# 对象 → 出厂写面。条目：(通道, 动作, 档, 依据)
#   通道 occ=宿主工具（两种身份都有）；sb/curl=沙箱命令（admin 缺省不可达）
#   档 W1=免确认；W2=root 控制台确认后可写、admin 拒绝
# ---------------------------------------------------------------------------
WRITE_MAP = {
    "FS-01": [("occ", "write/edit（域内）", "W1", _ZONE_W),
              ("occ", "write/edit（越界目标）", "W2", _ZONE_W)],
    "FS-02": [("occ", "mkdir/mv", "W1", TC + ":1090-1155")],
    "FS-03": [("sb", "chmod（仅沙箱可见树）", "W1", EV_USR)],
    "FS-04": [("occ", "write/edit（域内）", "W1", _ZONE_W),
              ("occ", "write/edit（越界目标）", "W2", _ZONE_W)],
    "FS-05": [("occ", "rm/mv", "W1", TC + ":1049-1131")],
    # DISK-02 的 fstab 写面由旧目录的 config_write_fstab.path 派生（见 derived_writes）
    "AI-02": [("curl", "POST http://127.0.0.1:8761/act（aikernel-api 受控参数写，限 control 27 参数；"
                        "需 Bearer token，curl -d 判 W2；依赖 aikernel-api 在跑）", "W2",
               "apic/apiv2.c（POST /act）；" + TC + ":3536-3561")],
    "SYS-08": [("occ", "write/edit unit 与 drop-in（不 daemon-reload）", "W2", _ZONE_W)],
    "NET-05": [("occ", "edit /etc/resolv.conf", "W2", _ZONE_W)],
    "NET-06": [("occ", "edit /etc/nftables.conf（只改持久化文件，不进运行时）", "W2", _ZONE_W)],
    "NET-08": [("occ", "config_write_network write/remove", "W2", TC + ":3632-3643")],
    "ID-04": [("occ", "edit /etc/sudoers（不经 visudo 校验）", "W2", _ZONE_W)],
    "ID-05": [("occ", "edit /etc/aikernel/policy.conf", "W2", _ZONE_W)],
    "ID-06": [("occ", "edit /etc/ssh/sshd_config（不 reload sshd）", "W2", _ZONE_W)],
    "ID-07": [("occ", "write $HOME/.ssh/authorized_keys（落在 $HOME 域内）", "W1",
               TC + ":3264-3290,447-471")],
    "TIME-03": [("occ", "edit /etc/crontab", "W2", _ZONE_W)],
    "MEM-02": [("curl", "POST /memories、DELETE /memories/<id>（curl -d 判 W2）", "W2",
                TC + ":3536-3561")],
    "MEM-04": [("curl", "POST /regions/evolve", "W2", TC + ":3536-3561")],
    "DT-02": [("curl", "POST /api/apps/launch|close", "W2", TC + ":3536-3561")],
    "DT-03": [("curl", "POST /api/windows/focus|close", "W2", TC + ":3536-3561")],
    "DT-04": [("curl", "POST /api/theme|/api/wallpaper", "W2", TC + ":3536-3561")],
    "DT-05": [("curl", "POST /api/notifs", "W2", TC + ":3536-3561")],
    "DT-08": [("curl", "POST /api/clipboard", "W2", TC + ":3536-3561")],
    "DT-09": [("curl", "POST /api/chat", "W2", TC + ":3536-3561")],
}

# ---------------------------------------------------------------------------
# Top 15：最该先接通的工具/对象。排序依据 = 场景库命中数优先
# （agent/ai/tests/usage/scenarios.json，50 条人工场景），其下按排障链位置
# （服务→日志→进程→磁盘→包→会话→启动→网络策略→时间）与当前不可达程度。
# ---------------------------------------------------------------------------
TOP15 = [
    (1, "systemctl：服务状态 / 失败单元 / 定时器列表", "SYS-01,SYS-02,SYS-07",
     "svc-01,svc-02,svc-04,diag-05,combo-05",
     "沙箱无 /run/systemd/private；宿主侧只能 glob 出 unit 文件名，active/failed 状态零可达",
     "做成 occ 宿主侧原生只读工具：systemctl show / list-units --failed / list-timers，JSON 输出"),
    (2, "journalctl / dmesg：日志读面", "SYS-03,SYS-04",
     "diag-05,svc-02",
     "沙箱无 /var/log/journal；journal 是二进制，occ read 拒读——journal 内容零可达；"
     "dmesg 取决于 kernel.dmesg_restrict（沙箱无 CAP_SYSLOG，须真机核）",
     "原生只读工具：journalctl -o json，带 unit/priority/since 过滤与行数上限"),
    (3, "宿主进程枚举与资源占用（ps/top/smaps）", "PROC-01,PROC-02,PROC-04",
     "diag-02,combo-01",
     "PID namespace 里只见沙箱自己；宿主侧只能 glob /proc（200 项截断）再逐个 read",
     "原生只读工具：按 /proc 聚合 pid/ppid/rss/cpu/comm，支持排序与 top-N"),
    (4, "磁盘占用大户与文件元数据（du/stat）", "DISK-05,FS-03",
     "diag-03,file-03,combo-02,combo-05",
     "沙箱看不到宿主 /var、/var/log；occ 无 stat/ls -l，glob 只给文件名",
     "原生只读工具：du（限深度）与 stat；先解「/var/log 谁最大」"),
    (5, "dpkg/apt：已装包与可升级", "PKG-01,PKG-03,PKG-05", "-",
     "场景库未覆盖；装机与安全更新是常规项。/var/lib/dpkg 不在沙箱；apt list --upgradable 完全不可达",
     "原生只读工具：dpkg-query -W 与 apt list --upgradable（宿主侧执行）"),
    (6, "登录会话（who/w/loginctl）", "ID-03", "-",
     "场景库未覆盖；utmp/wtmp 不在沙箱，aikctl session list 在沙箱里恒报无会话（假阴性）",
     "原生只读工具：把 aikctl session list 的 utmp 解析搬到宿主侧"),
    (7, "systemd-analyze：启动耗时", "SYS-06", "diag-04",
     "要连 systemd manager", "原生只读工具：systemd-analyze time/blame"),
    (8, "nft：运行时规则与防火墙状态", "NET-06", "net-05,combo-03",
     "NETLINK_NETFILTER 需 CAP_NET_ADMIN；nft 还是 W2 硬表命令",
     "原生只读工具：nft -j list ruleset（宿主侧只读动词，免确认）"),
    (9, "timedatectl：NTP 同步与时区", "TIME-01", "-",
     "场景库未覆盖；证书/日志对时排障项。沙箱里 date 时区恒 UTC，NTP 状态零可达",
     "原生只读工具：timedatectl show -p 属性子集"),
    (10, "aikctl 五族读面原生化（policy/session/quota/user/audit）", "ID-04,ID-05,ID-03,FS-10,AI-01",
     "-",
     "aikctl 只能经沙箱 bash 调；/etc/sudoers、/var/run/utmp、/var/lib 不在沙箱视图；旧审计脚本 0 处提及 aikctl",
     "宿主侧原生工具封装 aikctl 的纯解析逻辑（或按子命令白名单挂入所需只读文件）"),
    (11, "cgroup 限额与用量聚合（systemd-cgtop）", "CG-01,CG-02", "diag-01,combo-01",
     "沙箱内 /sys/fs/cgroup 是空目录；宿主侧只能逐文件 read，无法枚举聚合",
     "原生只读工具：按 slice/service 聚合 memory.current/cpu.stat/pids.current"),
    (12, "recall / 记忆工具（OCC_ORCH_TOOLS）", "MEM-02,MEM-03", "-",
     "场景库 memory 类 5 条走的是旧 memory_* 工具；出厂未置 OCC_ORCH_TOOLS，recall 不注册；"
     "回环 SME 的检索是 POST（curl -d 判 W2）",
     "评估出厂置位 OCC_ORCH_TOOLS=1，或给 recall 单列开关"),
    (13, "aik-upgrade status：启动槽状态", "SYS-05", "-",
     "场景库未覆盖；出厂专属运维项。依赖 /boot 与 /var/lib，沙箱里输出误导性空结果",
     "原生只读工具：宿主侧执行 aik-upgrade status"),
    (14, "conntrack 计数与查询", "NET-04", "combo-03",
     "/proc/net/nf_conntrack 依赖内核节点；conntrack 工具出厂未装",
     "先在真机确认节点；原生只读工具做计数/过滤"),
    (15, "文件校验和（sha256sum，宿主文件）", "FS-09", "-",
     "场景库未覆盖；发布物核对项。沙箱里 sha256sum 只见沙箱可见树",
     "原生只读工具：file.hash(path)（G-024 的验收口径）"),
]

OLD_DEFECTS = [
    "量的不是出厂入口：97 对象矩阵的读面取自 tools.json 注册表，而执行器 executor.c 只链进 aikernel-shell"
    "（agent/ai/Makefile:169），occ 的 Makefile 不编它（agent/ai/occ/Makefile:105-106）。",
    "`--vm-host` 的用法示例直接指向生产机（audit_capabilities.py:35），且探测用 "
    "StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null（:844-846）——照文档敲就会弱校验连生产。",
    "覆盖率随审计机变化：`cmd:` 读/写路径的 ok 取决于审计机上有没有该二进制（:1157-1162、:1218-1227），"
    "不是被审系统的属性。",
    "0 处提及 aikctl：user/policy/session/quota/audit 五族对其完全不可见。",
    "`principal:` 记号（/lease list|show）不是 Agent 工具，却按 gated 读面计入 read_gated 并保住 structured 级别（:1193-1196、:1262）。",
    "`scan_desktop` 候选路径里写死了一条开发机家目录绝对路径（:1054-1058；主会话 2026-11-24 已删）。",
    "文案与阈值不一致：READ_TARGET=92.0（:64），矩阵文案却写「未达 95% 读覆盖」（:1505-1506）。",
    "docs/CAPABILITY-GAPS.md 没跟上脚本：文档生成时间 2026-10-24，G-024 行仍写「只能 python3 hashlib 逃逸」，"
    "而脚本里的 G-024 已改成「python3 已摘除」（脚本 :258 对文档 :43）。",
]

LIMITATIONS = [
    "全部是静态推断：没有任何一条在沙箱里实测过（组装沙箱需要特权）。用 agent/ai/tools/occ_reach_probe.sh 在真机逐条实测后回填。",
    "admin 身份的沙箱命令缺省按不可达计：仓内 build-rootfs.sh 与出厂树都没有 sudo 二进制与放行 aik-sandbox 的 sudoers 规则；"
    "另有一处疑似缺陷——aik-sandbox.c 没有任何 setuid 代码，经 sudo 组装后沙箱内进程是 uid 0，"
    "而 per-user 工作区是 0700 属 admin（occ_tools/sandbox.c:318-336），无 CAP_DAC_OVERRIDE 的 uid 0 进不去该目录，`cd <workdir>` 可能直接失败。",
    "回环 HTTP（SME 8000、desktop 8091）读面依赖服务在跑且鉴权可过；出厂 /opt/sme/data/sme.config.json 含凭据位，未读，"
    "api.auth_token 取值未知。",
    "occ 的 read/glob 输出截 8KB、glob 200 项上限，大文件/大目录的「可达」只是理论上可达，实际要多次分页。",
    "内核节点类（/proc/pressure、cpufreq、nf_conntrack、/sys/class/hwmon）是否存在于出厂内核未在真机核对。",
    "dmesg 在沙箱里能不能读取决于 kernel.dmesg_restrict：出厂 sysctl.d/10-kernel-hardening.conf 没改该项，"
    "AIKernel 内核树 .config 未设 CONFIG_SECURITY_DMESG_RESTRICT（默认 0），但 L1 的 Ubuntu 内核是 1——须真机核。",
]


# ===========================================================================
# 求值
# ===========================================================================
IDENTS = ("root", "admin")
HOME_OF = {"root": "/root", "admin": "/home/admin"}
INV = {v: k for k, v in RANK.items()}

P_SB = "agent/ai/sandbox/aik-sandbox.c"
P_TC = "agent/ai/occ/occ_tools/tools.c"
P_TH = "agent/ai/occ/occ_tools/occ_tools.h"
P_OS = "agent/ai/occ/occ_tools/sandbox.c"
P_OC = "agent/ai/occ/occ.c"
P_API = "agent/ai/apic/apiask.c"
P_CONSOLE = "factory/usr/local/bin/aik-console"
P_UNIT = "factory/etc/systemd/system/aikernel-api.service"
P_POLICY = "factory/etc/aikernel/policy.conf"
P_TOOLS = "agent/ai/tools/tools.json"
P_SCEN = "agent/ai/tests/usage/scenarios.json"

OBJ = {o["id"]: o for o in OLD.OBJECTS}
_MISSING = [i for i in OBJ if i not in READ_MAP]
_EXTRA = [i for i in READ_MAP if i not in OBJ]
if _MISSING or _EXTRA:
    raise SystemExit("READ_MAP 与旧对象目录不一致：缺 %r 多 %r" % (_MISSING, _EXTRA))


def read_text(repo, rel):
    try:
        with open(os.path.join(repo, rel), "r", encoding="utf-8",
                  errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def old_view(root):
    """旧入口注册表口径，同机复算（纯静态：HTTP 探测替身为恒失败）。"""
    reg = OLD.scan_registry(root)
    saved = OLD.api_get
    OLD.api_get = lambda url, timeout=2.0: (False, None)
    try:
        stub = {"post_routes": []}
        ev = OLD.Evaluator(root, reg, stub, set(), set(), stub)
        evald = [ev.eval_object(o) for o in OLD.OBJECTS]
    finally:
        OLD.api_get = saved
    return reg, {o["id"]: o for o in evald}, OLD.compute_metrics(evald)


# ---------------------------------------------------------------------------
# 源码事实：把求值所依赖的代码事实钉住。源码漂移 → --check 失败。
# ---------------------------------------------------------------------------
def _block(src, head):
    m = re.search(re.escape(head) + r"(.*?)NULL", src, re.S)
    return m.group(1) if m else ""


def source_facts(repo):
    sb = read_text(repo, P_SB)
    tc = read_text(repo, P_TC)
    th = read_text(repo, P_TH)
    osb = read_text(repo, P_OS)
    oc = read_text(repo, P_OC)
    api = read_text(repo, P_API)
    con = read_text(repo, P_CONSOLE)
    unit = read_text(repo, P_UNIT)
    pol = read_text(repo, P_POLICY)
    facts = []

    def F(fid, desc, ok, detail=""):
        facts.append({"id": fid, "desc": desc, "ok": bool(ok), "detail": detail})

    F("F01", "沙箱 clone 标志含 NEWNS|NEWPID|NEWUTS",
      re.search(r"CLONE_NEWNS \| CLONE_NEWPID \| CLONE_NEWUTS", sb) is not None, P_SB)
    names = sorted(re.findall(r'"/etc/([^"]+)"', _block(sb, "SB_ETC_FILES[]")))
    F("F02", "/etc 白名单恰为 4 个文件",
      names == ["hosts", "nsswitch.conf", "resolv.conf",
                "ssl/certs/ca-certificates.crt"], repr(names))
    names = re.findall(r'"(\w+)"', _block(sb, "SB_DEV_MUST[]"))
    F("F03", "/dev 必挂集为 null/zero/random/urandom",
      names == ["null", "zero", "random", "urandom"], repr(names))
    F("F04", "能力只保留 CAP_NET_RAW",
      re.search(r"#define SB_CAP_KEEP_MASK\s+\(1ULL << SB_CAP_NET_RAW\)", sb)
      is not None)
    F("F05", "沙箱网络默认 host", "网络隔离（默认 host" in sb)
    F("F06", "aik-sandbox.c 无任何 setuid/setgid 调用（非 root 经 sudo 组装后沙箱内仍是 uid 0）",
      re.search(r"\b(setuid|setgid|setresuid|setresgid|setgroups)\s*\(", sb) is None)
    flat = _block(sb, "static const char *const flat[]")
    F("F07", "根骨架含 tmp/home/var/opt/srv，且不含 /run",
      '"usr", "proc", "sys", "etc", "tmp", "home",' in flat
      and '"var", "opt", "srv", "dev", ".old"' in flat
      and '"run"' not in flat)
    F("F19", "/etc/aikernel 整目录只读挂入", 'bind_ro("/etc/aikernel", path, 0);' in sb)
    F("F20", "/proc 是新挂的只读 procfs",
      re.search(r'mount\("proc", "/proc", "proc",\s*MS_RDONLY', sb) is not None)
    F("F22", "model.toml/provider.toml 被拷入沙箱 /root/.aikernel",
      '%s/root/.aikernel/model.toml' in sb
      and '%s/root/.aikernel/provider.toml' in sb)

    m = re.search(r"static const occ_tool_def TOOLS\[\] = \{(.*?)\n\};", tc, re.S)
    n_tools = len(re.findall(r"\{ OCC_T_\w+,", m.group(1))) if m else -1
    F("F08", "occ 默认工具恰 9 件", n_tools == 9, "TOOLS[] 条目数=%d" % n_tools)
    hard = set(re.findall(r'"([\w.]+)"', _block(tc, "static const char *hard[]")))
    F("F09", "W2 硬表含 nft/kill/mount/dd/reboot",
      {"nft", "kill", "mount", "dd", "reboot"} <= hard)
    if "static int tool_read(" in tc and "/* ---- write ---- */" in tc:
        body = tc[tc.index("static int tool_read("):tc.index("/* ---- write ---- */")]
        F("F10", "read 工具无路径域守卫，单文件上限 4MB",
          "occ_write_target_ok(" not in body and "w2_path_safe(" not in body
          and "read_whole(abs, 4 * 1024 * 1024" in body)
    else:
        F("F10", "read 工具无路径域守卫，单文件上限 4MB", False, "tool_read 函数体定位失败")
    F("F11", "结果 8KB / glob 200 项 / grep 100 行上限",
      "#define OCC_TOOL_OUT_MAX 8192" in th and "#define GLOB_MAX_RESULTS 200" in tc
      and "#define GREP_MAX_LINES 100" in tc)
    F("F12", "occ bash = create → run --rw-path <workdir> -- /bin/sh -c → destroy",
      all(s in osb for s in ('"--rw-path"', '"/bin/sh"', '"create"', '"destroy"',
                             "cd %s && { %s ; }")))
    F("F13", "W2 门：非 PRIVILEGED 档一律拒绝",
      "if (g->tier != OCC_W2_TIER_PRIVILEGED)" in tc
      and "#define OCC_W2_TIER_PRIVILEGED 0" in th
      and "#define OCC_W2_TIER_CONFIRMED  1" in th)
    F("F21", "写域=工作目录∪/tmp∪/var/ai∪$HOME，~/.occ 恒拒",
      'occ_path_is_under(abs, "/tmp")' in tc and 'occ_path_is_under(abs, "/var/ai")' in tc
      and "if (occ_abs_under_home_occ(abs))" in tc)
    F("F23", "W2 档位取自 policy（按 uid）；headless 须显式 --allow-w2",
      "ai_policy_mode_for_uid(getuid())" in oc and '"--allow-w2"' in oc)
    F("F14", "出厂 policy：root=privileged / wheel=confirmed / default=restricted",
      re.search(r"\[root\]\s*\nmode\s*=\s*privileged", pol) is not None
      and re.search(r"\[wheel\]\s*\nmode\s*=\s*confirmed", pol) is not None
      and re.search(r"\[default\]\s*\nmode\s*=\s*restricted", pol) is not None)
    F("F15", "aik-console 置 OCC_NETCFG_TOOLS=1、未置 OCC_ORCH_TOOLS、setpriv 降权；"
             "api unit 同样置位且无 User=（root）",
      "OCC_NETCFG_TOOLS=1" in con and "OCC_ORCH_TOOLS" not in con
      and "setpriv" in con and "Environment=OCC_NETCFG_TOOLS=1" in unit
      and "OCC_ORCH_TOOLS" not in unit
      and re.search(r"^User=", unit, re.M) is None)
    F("F16", "出厂 API 以 `occ -p` 调起 occ，且不带 --allow-w2",
      'argv[1] = (char *)"-p";' in api and "--allow-w2" not in api
      and "ExecStart=/usr/local/sbin/aikernel-api" in unit)
    F("F17", "出厂树入口目录无 /usr/local/bin/ai（aikernel-shell 已退出出厂入口）",
      not os.path.exists(os.path.join(repo, "factory/usr/local/bin/ai")))
    return facts


# ---------------------------------------------------------------------------
# 工具计数
# ---------------------------------------------------------------------------
def factory_tools(repo, reg):
    tools = reg["tools"]
    occ_reg = sorted(t["name"] for t in tools if t.get("channel") == "occ")
    defines = dict(re.findall(r'#define (OCC_T_\w+)\s+"(\w+)"',
                              read_text(repo, P_TH)))
    tc = read_text(repo, P_TC)
    m = re.search(r"static const occ_tool_def TOOLS\[\] = \{(.*?)\n\};", tc, re.S)
    default = [defines[k] for k in re.findall(r"\{ (OCC_T_\w+),", m.group(1))
               if k in defines] if m else []
    factory = default + ["config_write_network"]     # 出厂 OCC_NETCFG_TOOLS=1
    reach_reg = sorted(set(occ_reg) & set(factory))
    unreach = [t for t in tools if t["name"] not in reach_reg]
    chan = {}
    for t in unreach:
        chan[t.get("channel") or "?"] = chan.get(t.get("channel") or "?", 0) + 1
    xs = {"ok": 0, "partial": 0, "no": 0, "unclassified": []}
    for c in reg["exec_commands"]:
        v = SBX.get(c["command"], {}).get("verdict")
        if v is None:
            xs["unclassified"].append(c["command"])
        else:
            xs[v] += 1
    return {
        "registry_total": len(tools),
        "registry_channels": reg["domain_count"] and len(set(
            t.get("channel") for t in tools)),
        "registry_occ_channel": occ_reg,
        "factory_tools_total": len(factory),
        "factory_tools": factory,
        "factory_reachable_registry": reach_reg,
        "factory_unreachable_registry_count": len(unreach),
        "factory_unreachable_by_channel": dict(sorted(chan.items())),
        "registry_exec_whitelist": len(reg["exec_commands"]),
        "registry_exec_in_sandbox": xs,
    }


# ---------------------------------------------------------------------------
# 逐对象求值
# ---------------------------------------------------------------------------
def eval_path(p, ident, admin_sandbox):
    kind = p["kind"]
    if kind == "absent":
        return False, "absent", "R"
    if kind in ("occ:read", "occ:glob"):
        if p["root_only"] and ident == "admin":
            return False, "perm", "R"
        return True, "ok", "R"
    if kind == "occ:netcfg":
        return True, "ok", "R"
    if ident == "admin" and admin_sandbox == "no":
        return False, "no-sandbox", "W1"
    if p["verdict"] == "no":
        return False, "no", "W1"
    risk = classify_bash(p["target"]) if kind in ("sb", "curl") else "W1"
    if risk == "W2" and ident != "root":
        return False, "w2-denied", "W2"
    return True, ("gated" if risk == "W2" else "ok"), risk


TOOLMAP = {}


def derived_writes(oid):
    """旧目录写记号里走 sysfs/sysctl 节点的工具，在出厂视角下对应 occ
    write/edit 直接写同一节点（write/edit 用 fopen "wb"，对文件类型无限制，
    与 shell 重定向 `echo x > /sys/...` 同理；推断，未实测）。"""
    out = []
    for tok in OBJ[oid]["write"]:
        kind, _, val = tok.partition(":")
        if kind != "tool":
            continue
        t = TOOLMAP.get(val)
        if not t:
            continue
        if val == "sysfs_set":
            out.append(("occ", "write/edit <sysfs/procfs 受控节点>（无受控前缀校验）",
                        "W2", "tools.json:sysfs_set（path 由调用方给）；" + TC + ":869-1045"))
        elif val == "sysctl_set":
            out.append(("occ", "write /proc/sys/<key>（sysctl）", "W2",
                        "tools.json:sysctl_set；" + TC + ":869-928"))
        elif t.get("channel") == "sysfs-write" and t.get("path"):
            out.append(("occ", "write %s" % t["path"], "W2",
                        "tools.json:%s.path；%s:869-928" % (val, TC)))
    return out


def eval_object(oid, oldo, ident, admin_sandbox):
    o = OBJ[oid]
    paths = []
    for p in READ_MAP[oid]:
        q = dict(p)
        q["target"] = q["target"].replace("$HOME", HOME_OF[ident])
        q["reach"], q["state"], q["risk"] = eval_path(q, ident, admin_sandbox)
        paths.append(q)
    reach = [p for p in paths if p["reach"]]
    declared = o["semantic"]
    if not reach:
        level = "none"
    else:
        best = max(RANK[p["form"]] for p in reach)
        level = INV[min(RANK[declared], best)] if declared != "none" else INV[best]
    writes = []
    manual = WRITE_MAP.get(oid, [])
    manual_paths = " ".join(m[1] for m in manual)
    derived = [d for d in derived_writes(oid)
               if d[1].split()[-1] not in manual_paths]      # 同一文件只留一条
    for kind, target, tier, ev in manual + derived:
        if kind != "occ" and ident == "admin" and admin_sandbox == "no":
            ok, state = False, "no-sandbox"
        elif tier == "W2" and ident != "root":
            ok, state = False, "w2-denied"
        else:
            ok, state = True, ("gated" if tier == "W2" else "direct")
        writes.append({"kind": kind, "target": target, "tier": tier, "ev": ev,
                       "reach": ok, "state": state})
    wreach = [w for w in writes if w["reach"]]
    return {
        "id": oid, "name": o["name"], "class": o["class"], "status": o["status"],
        "gap": o["gap"], "write_na": o["write_na"],
        "old_level": oldo["semantic_level"], "old_read_any": oldo["read_any"],
        "old_read_direct": oldo["read_direct"],
        "declared": declared,
        "paths": paths,
        "read_any": bool(reach),
        "read_direct": any(p["risk"] in ("R", "W1") for p in reach),
        "read_gated": any(p["risk"] == "W2" for p in reach),
        "only_partial": bool(reach) and all(p["partial"] for p in reach),
        "only_cond": bool(reach) and all(p["cond"] for p in reach),
        "level": level,
        "writes": writes,
        "write_any": bool(wreach),
        "write_direct": any(w["state"] == "direct" for w in wreach),
        "write_gated_only": bool(wreach) and all(w["state"] == "gated" for w in wreach),
    }


def pct(n, d):
    return round(100.0 * n / d, 1) if d else 0.0


def compute(evd):
    app = [o for o in evd if o["status"] != "n/a"]
    na = [o["id"] for o in evd if o["status"] == "n/a"]
    ra = [o for o in app if o["read_any"]]
    wapp = [o for o in app if not o["write_na"]]
    sem = [o for o in app if o["level"] in ("structured", "semantic")]
    return {
        "objects_total": len(evd), "objects_applicable": len(app), "na_ids": na,
        "read_any": len(ra), "read_any_pct": pct(len(ra), len(app)),
        "read_direct": sum(1 for o in app if o["read_direct"]),
        "read_direct_pct": pct(sum(1 for o in app if o["read_direct"]), len(app)),
        "read_gated": sum(1 for o in app if o["read_gated"]),
        "read_only_partial": sorted(o["id"] for o in ra if o["only_partial"]),
        "read_only_cond": sorted(o["id"] for o in ra if o["only_cond"]),
        "semantic_structured": len(sem),
        "semantic_structured_pct": pct(len(sem), len(app)),
        "semantic_high": sum(1 for o in app if o["level"] == "semantic"),
        "semantic_high_pct": pct(sum(1 for o in app if o["level"] == "semantic"), len(app)),
        "semantic_raw_objects": sorted(o["id"] for o in ra if o["level"] == "raw"),
        "read_absent_objects": sorted(o["id"] for o in app if not o["read_any"]),
        "lost_with_old_tool": sorted(o["id"] for o in app
                                     if o["old_read_any"] and not o["read_any"]),
        "level_downgraded": sorted(o["id"] for o in ra if o["declared"] != "none"
                                   and RANK[o["level"]] < RANK[o["old_level"]]),
        "write_applicable": len(wapp),
        "write_any": sum(1 for o in wapp if o["write_any"]),
        "write_any_pct": pct(sum(1 for o in wapp if o["write_any"]), len(wapp)),
        "write_direct": sum(1 for o in wapp if o["write_direct"]),
        "write_direct_pct": pct(sum(1 for o in wapp if o["write_direct"]), len(wapp)),
        "write_gated_only": sorted(o["id"] for o in wapp if o["write_gated_only"]),
    }


def split_gap(s):
    return [x.strip() for x in re.split(r"[,/]", s or "")
            if x.strip() and x.strip() != "-"]


FACTORY_REACH = set()


def tok_verdict(tok):
    """旧读记号在出厂 root 视角下有没有等价读面。返回 (状态, 备注)：
    ok / partial（只见一部分）/ cond（依赖运行态）/ no。"""
    kind, _, val = tok.partition(":")
    if kind == "tool":
        t = TOOLMAP.get(val)
        if not t:
            return "no", "未注册"
        ch = t.get("channel")
        if val in FACTORY_REACH:
            return "ok", ""
        if ch == "procfs-read" or (ch == "sysfs-write" and t.get("path")):
            return "ok", "读同一节点"
        if ch == "sysfs":
            return "partial", "只能逐文件 read"
        if ch == "exec":
            return "partial", "换成沙箱 bash，逐命令见命令表"
        if val.startswith("config_read_"):
            return "ok", "occ read 同一配置文件"
        if val.startswith("memory_"):
            return "cond", "curl 回环 SME"
        if val.startswith("desktop_"):
            return "cond", "curl 回环 desktopd"
        return "no", ""
    if kind == "cmd":
        return SBX.get(val, {}).get("verdict", "no"), ""
    return "no", ""


def classify_gaps(oldmap, views):
    """两条线：① 缺口名下对象的旧一等读工具（tool:/cmd:）逐件在出厂 root
    视角下有没有等价读面；② 对象逐项 旧级别 → 出厂级别。"""
    out = []
    for g in OLD.GAPS:
        if g.get("status") == "closed":
            continue
        ids = [o["id"] for o in OLD.OBJECTS if g["id"] in split_gap(o["gap"])]
        rmap = {o["id"]: o for o in views["root"]["objects"]}
        detail, labels, toks = [], [], {}
        for i in ids:
            if OBJ[i]["status"] == "n/a":
                continue
            r = rmap[i]
            detail.append("%s %s→%s" % (
                i, "读/" + oldmap[i]["semantic_level"] if oldmap[i]["read_any"]
                else "无读面",
                ("读/" + r["level"]) if r["read_any"] else "不可达"))
            if oldmap[i]["read_any"] and not r["read_any"]:
                labels.append("unreachable")
            elif not r["read_any"]:
                labels.append("absent-both")
            elif RANK[r["level"]] < RANK[oldmap[i]["semantic_level"]]:
                labels.append("degraded")
            else:
                labels.append("reachable")
            for tok in OBJ[i]["read"]:
                if tok.startswith(("tool:", "cmd:")) and tok not in toks:
                    toks[tok] = tok_verdict(tok)
        n = len(toks)
        n_no = sum(1 for v in toks.values() if v[0] == "no")
        if not toks:
            cls = "file-only"
        elif n_no == n:
            cls = "unreachable"
        elif n_no * 2 >= n:
            cls = "mostly-unreachable"
        elif n_no:
            cls = "partly-unreachable"
        else:
            cls = "reachable"
        if cls == "reachable" and "unreachable" in labels:
            cls = "partly-unreachable"      # 工具有等价，但某个对象整体丢了
        out.append({
            "id": g["id"], "priority": g["priority"], "object": g["object"],
            "class": cls, "n_tools": n, "n_unreachable": n_no,
            "toks": [[k, v[0]] for k, v in sorted(toks.items())],
            "obj_labels": sorted(set(labels)), "detail": detail,
        })
    return out


CLASS_DESC = {
    "unreachable": "有读工具但对出厂 AI 不可达（名下一等读工具全部没有等价读面）",
    "degraded": "出厂可达但语义降级（自由文本/只剩一部分）",
    "reachable": "出厂可达且级别不降",
    "absent-both": "旧口径与出厂口径都没有读面（二进制/节点缺席类）",
    "mostly-unreachable": "缺口名下的一等读工具过半在出厂没有等价读面",
    "partly-unreachable": "缺口名下的一等读工具有少数在出厂没有等价读面",
    "file-only": "缺口名下对象没有一等读工具（只有文件/逃逸/Principal 记号）",
    "non-read": "非读面缺口（写面/探测/文档/全局语义），不按读面归类",
}


def mapping_sha():
    blob = json.dumps({"READ_MAP": READ_MAP,
                       "WRITE_MAP": {k: [list(x) for x in v] for k, v in WRITE_MAP.items()},
                       "SBX": SBX, "AIKCTL_SUBS": AIKCTL_SUBS,
                       "OCC_TOOLS": OCC_TOOLS, "TOP15": TOP15,
                       "W2_HARD": sorted(W2_HARD)},
                      ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def build_report(repo, admin_sandbox):
    reg, oldmap, old_metrics = old_view(root=os.path.join(repo, "agent", "ai"))
    TOOLMAP.clear()
    TOOLMAP.update({t["name"]: t for t in reg["tools"]})
    views = {}
    for ident in IDENTS:
        evd = [eval_object(oid, oldmap[oid], ident, admin_sandbox) for oid in OBJ]
        views[ident] = {"metrics": compute(evd), "objects": evd}
    tools = factory_tools(repo, reg)
    FACTORY_REACH.clear()
    FACTORY_REACH.update(tools["factory_tools"])
    facts = source_facts(repo)
    scen = set()
    try:
        with open(os.path.join(repo, P_SCEN), "r", encoding="utf-8") as f:
            scen = {s["id"] for s in json.load(f)["scenarios"]}
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return {
        "schema": SCHEMA,
        "params": {"admin_sandbox": admin_sandbox},
        "tools": tools,
        "views": {i: views[i]["metrics"] for i in IDENTS},
        "objects": {i: views[i]["objects"] for i in IDENTS},
        "gaps": classify_gaps(oldmap, views),
        "sandbox_commands": SANDBOX_COMMANDS,
        "aikctl_subs": AIKCTL_SUBS,
        "occ_tools": OCC_TOOLS,
        "top15": TOP15,
        "old_view": old_metrics,
        "source_facts": facts,
        "scenario_ids_missing": sorted({s for t in TOP15 for s in t[3].split(",")
                                         if s != "-" and s not in scen}),
        "mapping_sha256": mapping_sha(),
    }


def core_of(rep):
    return {
        "params": rep["params"],
        "tools": {k: v for k, v in rep["tools"].items()},
        "views": rep["views"],
        "gaps_class": {g["id"]: g["class"] for g in rep["gaps"]},
        "top15": [t[1] for t in TOP15],
        "mapping_sha256": rep["mapping_sha256"],
    }


# ===========================================================================
# 渲染
# ===========================================================================
def cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def pmark(p):
    m = "W2" if p["risk"] == "W2" else "ok"
    if p["partial"]:
        m += "~"
    if p["cond"]:
        m += "?"
    return m


def paths_md(obj, limit=3):
    rs = [p for p in obj["paths"] if p["reach"]]
    if not rs:
        return "—"
    out = []
    for p in rs[:limit]:
        t = p["target"]
        if len(t) > 60:
            t = t[:57] + "…"
        out.append("`%s` [%s]" % (cell(t), pmark(p)))
    if len(rs) > limit:
        out.append("+%d" % (len(rs) - limit))
    return "<br>".join(out)


def writes_md(obj, limit=2):
    rs = [w for w in obj["writes"] if w["reach"]]
    if not rs:
        return "—"
    return "<br>".join("`%s` [%s]" % (cell(w["target"][:40]),
                                      "W2" if w["state"] == "gated" else "W1")
                       for w in rs[:limit])


def lv(o):
    if not o["read_any"]:
        return "不可达"
    s = "读/" + o["level"]
    if o["only_partial"]:
        s += "（仅部分）"
    if o["only_cond"]:
        s += "（依赖运行态）"
    return s


def render_markdown(rep):
    L = []
    tv = rep["tools"]
    rv = rep["views"]
    ov = rep["old_view"]
    rmap = {o["id"]: o for o in rep["objects"]["root"]}
    amap = {o["id"]: o for o in rep["objects"]["admin"]}
    L.append("# 出厂 AI 真实视角能力基线（OCC-CAPABILITY-BASELINE）")
    L.append("")
    L.append("> 由 `agent/ai/tools/audit_occ_capabilities.py --markdown` 生成，不手填；"
             "对象目录与缺口登记 import 自旧审计 `audit_capabilities.py`。"
             "全部为静态推断（未在沙箱内实测）；实测用 `agent/ai/tools/occ_reach_probe.sh`。")
    L.append("")
    L.append("## 1. 口径")
    L.append("")
    L.append("- **为什么重算**：旧审计量的是 tools.json 注册表（%d 件、%d 个通道），其执行器只链进"
             "已退出出厂入口的 aikernel-shell。出厂入口是 occ，运行时不读 tools.json。"
             % (tv["registry_total"], tv["registry_channels"]))
    L.append("- **出厂工具面**：%d 件（%s）。注册表里只有 %d 件在出厂可达（%s），"
             "**%d 件注册表工具对出厂 AI 不可达**。"
             % (tv["factory_tools_total"], "、".join(tv["factory_tools"]),
                len(tv["factory_reachable_registry"]), "、".join(tv["factory_reachable_registry"]),
                tv["factory_unreachable_registry_count"]))
    L.append("- **两种身份**：root（控制台 root 路径与 aikernel-api 服务）与 admin（控制台默认目标，wheel 组）。"
             "W2：root 控制台需交互确认，admin 与 headless API 一律拒绝。")
    L.append("- **admin 的沙箱命令缺省按不可达计**（仓内无 sudo 二进制与放行 aik-sandbox 的 sudoers 规则）。")
    L.append("- **读面标记**：`ok`=免确认；`W2`=须确认（仅 root 控制台）；`~`=只见沙箱自身/一部分数据；"
             "`?`=依赖运行态。语义级别不高于旧申报级别（自由文本=raw）。")
    L.append("- **可达**=结构上存在且不被沙箱视图/权限挡住（同旧口径「登记即算」），不代表节点此刻存在。")
    L.append("")
    L.append("## 2. 汇总：旧入口注册表口径 vs 出厂 AI 口径")
    L.append("")
    L.append("| 指标 | 旧入口注册表口径（同机复算） | 出厂 root | 出厂 admin |")
    L.append("|---|---:|---:|---:|")
    n_old = ov["objects_applicable"]
    n_root = rv["root"]["objects_applicable"]
    n_adm = rv["admin"]["objects_applicable"]

    def line(title, k, kp, den):
        return ("| %s | %d/%d = %.1f%% | **%d/%d = %.1f%%** | **%d/%d = %.1f%%** |"
                % (title, ov[k], den, ov[kp], rv["root"][k], den, rv["root"][kp],
                   rv["admin"][k], den, rv["admin"][kp]))

    L.append(line("可读对象 read_any", "read_any", "read_any_pct", n_old))
    L.append(line("免确认读 read_direct", "read_direct", "read_direct_pct", n_old))
    L.append("| 须确认才可达的读面（对象数） | — | %d | %d |"
             % (rv["root"]["read_gated"], rv["admin"]["read_gated"]))
    L.append(line("带类型语义 semantic", "semantic_high", "semantic_high_pct", n_old))
    L.append(line("结构化+语义", "semantic_structured", "semantic_structured_pct", n_old))
    L.append("| 原始文本 raw 对象数 | %d | %d | %d |"
             % (len(ov["semantic_raw_objects"]), len(rv["root"]["semantic_raw_objects"]),
                len(rv["admin"]["semantic_raw_objects"])))
    L.append("| 不可达对象数 | %d | **%d** | **%d** |"
             % (len(ov["read_absent_objects"]), len(rv["root"]["read_absent_objects"]),
                len(rv["admin"]["read_absent_objects"])))
    L.append("| 仅部分可见（partial）对象数 | — | %d | %d |"
             % (len(rv["root"]["read_only_partial"]), len(rv["admin"]["read_only_partial"])))
    L.append("| 仅依赖运行态（cond）对象数 | — | %d | %d |"
             % (len(rv["root"]["read_only_cond"]), len(rv["admin"]["read_only_cond"])))
    L.append(line("可写对象 write_any", "write_any", "write_any_pct", ov["write_applicable"]))
    L.append(line("免确认直写 write_direct", "write_direct", "write_direct_pct",
                  ov["write_applicable"]))
    L.append("| 仅确认后可写的对象数 | — | %d | %d |"
             % (len(rv["root"]["write_gated_only"]), len(rv["admin"]["write_gated_only"])))
    L.append("| 注册表工具可达数 | %d/%d | %d/%d | %d/%d |"
             % (tv["registry_total"], tv["registry_total"],
                len(tv["factory_reachable_registry"]), tv["registry_total"],
                len(tv["factory_reachable_registry"]), tv["registry_total"]))
    L.append("")
    L.append("- 分母：读面 %d 个适用对象（另 %d 个 n/a 不入分母：%s）；写面 %d 个可写对象。"
             % (n_old, len(rv["root"]["na_ids"]), "、".join(rv["root"]["na_ids"]),
                ov["write_applicable"]))
    L.append("- 旧口径「同机复算」在本机静态求值（HTTP 探测替身为恒失败），与任务书引用的 11-23 重跑数字"
             "（可读 97.8% / 可直读 94.4% / 可写 91.3% / 带类型 10.0% / 结构化 74.4% / raw 22）可能有个位数出入。")
    L.append("- 出厂 root 不可达对象：%s。" % ("、".join(rv["root"]["read_absent_objects"]) or "无"))
    L.append("- 出厂 admin 不可达对象：%s。" % ("、".join(rv["admin"]["read_absent_objects"]) or "无"))
    L.append("- 旧口径有读工具、出厂 root 不可达：%s。"
             % ("、".join(rv["root"]["lost_with_old_tool"]) or "无"))
    L.append("- 出厂 root 语义降级（级别低于旧口径）：%d 个。"
             % len(rv["root"]["level_downgraded"]))
    L.append("- 写面里的 `write/edit <sysfs/procfs 节点>` 是推断：occ write/edit 用 fopen \"wb\" 写宿主任意路径，"
             "对控制节点同样成立（同 shell 重定向 `echo x > /sys/...`），未实测；越界恒 W2。")
    L.append("- 回环 HTTP（curl）拿到的 JSON 记 structured：semantic 只给一等带类型的工具。")
    L.append("")
    L.append("## 3. 对象矩阵（97 对象）")
    L.append("")
    L.append("| 对象 | 旧口径 | 出厂 root 读面 | 出厂 admin 读面 | 出厂 root 写面 |")
    L.append("|---|---|---|---|---|")
    for oid in OBJ:
        o = rmap[oid]
        old = ("读/" + o["old_level"]) if o["old_read_any"] else (
            "n/a" if o["status"] == "n/a" else "无读面")
        if o["status"] == "n/a":
            old += "（n/a）"
        L.append("| %s %s | %s | %s | %s | %s |" % (
            oid, cell(o["name"]), old, paths_md(o), paths_md(amap[oid]), writes_md(o)))
    L.append("")
    L.append("## 4. 旧口径的原始文本（raw）对象在出厂视角下的状况")
    L.append("")
    L.append("| 对象 | 旧级别 | 出厂 root | 出厂 admin | 出厂读面 |")
    L.append("|---|---|---|---|---|")
    for oid in ov["semantic_raw_objects"]:
        o = rmap[oid]
        L.append("| %s %s | raw | %s | %s | %s |" % (
            oid, cell(o["name"]), lv(o), lv(amap[oid]), paths_md(o, 2)))
    L.append("")
    L.append("## 5. 33 个登记缺口的归类")
    L.append("")
    cnt = {}
    for g in rep["gaps"]:
        cnt[g["class"]] = cnt.get(g["class"], 0) + 1
    L.append("| 归类 | 条数 | 含义 |")
    L.append("|---|---:|---|")
    order = ("unreachable", "mostly-unreachable", "partly-unreachable",
             "reachable", "file-only")
    for cls in order:
        if cls in cnt:
            L.append("| %s | %d | %s |" % (cls, cnt[cls], CLASS_DESC[cls]))
    L.append("")
    L.append("归类按缺口名下对象的一等读工具（旧记号 `tool:`/`cmd:`）逐件看在出厂 root 视角下有没有"
             "等价读面：ok=有；partial=只见一部分；cond=依赖运行态；no=没有。")
    L.append("")
    L.append("**有读工具但对出厂 AI 不可达**（一等读工具全部或过半没有出厂等价读面）：%s。"
             % ("、".join(g["id"] for g in rep["gaps"]
                          if g["class"] in ("unreachable", "mostly-unreachable")) or "无"))
    L.append("")
    L.append("| 缺口 | 优先级 | 一等读工具[出厂是否有等价] | 对象逐项（旧 → 出厂 root） | 归类 |")
    L.append("|---|---|---|---|---|")
    for g in sorted(rep["gaps"], key=lambda x: (order.index(x["class"]), x["priority"],
                                                x["id"])):
        tk = "、".join("%s[%s]" % (k.split(":", 1)[1], v) for k, v in g["toks"]) or "（无）"
        L.append("| %s %s | %s | %s | %s | %s |" % (
            g["id"], cell(g["object"]), g["priority"], cell(tk),
            cell("；".join(g["detail"]) or "（无适用读面对象）"), g["class"]))
    L.append("")
    L.append("## 6. occ 十件工具逐件")
    L.append("")
    L.append("| 工具 | 风险 | 执行面 | 输出 | 能触达什么 | 确认门 | 依据 |")
    L.append("|---|---|---|---|---|---|---|")
    for t in OCC_TOOLS:
        L.append("| %s | %s | %s | %s | %s | %s | %s |" % tuple(cell(x) for x in t))
    L.append("")
    L.append("- `read` 的路径限制现状：**没有路径域限制**（只在 `occ_write_target_ok`/`w2_path_safe` 里管写面）；"
             "上限是单文件 4MB、含 NUL 拒读、默认 500 行/次、结果截 8KB。root 身份下这意味着 /etc/shadow、"
             "SSH 私钥、/etc/aikernel/api-token 等凭据文件在结构上都读得到。")
    L.append("- 宿主工具与沙箱看到的是两套文件系统，只有 bash 的工作目录是共享的（`--rw-path`）："
             "`write /tmp/x` 写的是宿主 /tmp，`bash cat /tmp/x` 看的是沙箱里的空 tmpfs。")
    L.append("- `write` 的域含整个 $HOME：root 身份下 $HOME=/root，写 /root/.bashrc、/root/.ssh/authorized_keys "
             "都是 W1（免确认）。")
    L.append("- `bash` 的退出码歧义（推断，未实测）：aik-sandbox 把沙箱内命令的退出码原样透传"
             "（aik-sandbox.c:107-108），而 occ 把 exit=1/2 一律当成「bash 沙箱执行失败」并把工具 rc 置 -1"
             "（occ_tools/sandbox.c:570-575）——`grep` 无匹配、`systemctl`、`ss` 等一切返回 1 的命令都会被"
             "记成工具错误；两条路径在 occ 侧无法区分。")
    L.append("")
    L.append("## 7. 沙箱内命令可达表（静态推断，共 %d 条）" % len(SANDBOX_COMMANDS))
    L.append("")
    L.append("判定：ok=能跑且拿到宿主真实数据；partial=能跑但只见沙箱自身/一部分；no=跑不起来或拿不到宿主数据。")
    L.append("")
    L.append("| 命令 | 只读样例 | 判定 | 形态 | 原因 | 依据 |")
    L.append("|---|---|---|---|---|---|")
    for c in SANDBOX_COMMANDS:
        L.append("| %s | `%s` | %s | %s | %s | %s |" % (
            c[0], cell(c[1]), c[2], c[3], cell(c[4]), cell(c[5])))
    L.append("")
    xs = tv["registry_exec_in_sandbox"]
    L.append("旧注册表 exec 白名单 %d 条命令 × 出厂沙箱：ok %d / partial %d / no %d%s。"
             % (tv["registry_exec_whitelist"], xs["ok"], xs["partial"], xs["no"],
                ("；未归类：" + "、".join(xs["unclassified"])) if xs["unclassified"] else ""))
    L.append("")
    L.append("## 8. aikctl 读类子命令在沙箱内的可达性")
    L.append("")
    L.append("| 子命令 | 判定 | 形态 | 原因 | 依据 |")
    L.append("|---|---|---|---|---|")
    for sub in sorted(AIKCTL_SUBS):
        v, form, why, ev = AIKCTL_SUBS[sub]
        L.append("| `aikctl %s` | %s | %s | %s | %s |" % (sub, v, form, cell(why), cell(ev)))
    L.append("")
    L.append("## 9. Top 15：最该先接通的工具/对象")
    L.append("")
    L.append("排序依据：先看场景库命中数（`agent/ai/tests/usage/scenarios.json`，50 条人工场景，"
             "诊断/服务/网络/文件/组合类），同分按排障链位置（服务→日志→进程→磁盘→包→会话→启动→"
             "网络策略→时间），再看当前不可达程度。场景库未覆盖的按装机与排障常规项排在命中场景之后。")
    L.append("")
    L.append("| # | 工具/对象 | 对象 | 命中场景 | 出厂现状 | 建议（喂 AIF-02） |")
    L.append("|---:|---|---|---|---|---|")
    for rank, title, objs, scen, status, action in TOP15:
        L.append("| %d | %s | %s | %s | %s | %s |" % (
            rank, cell(title), objs, scen, cell(status), cell(action)))
    L.append("")
    L.append("## 10. 旧审计脚本的缺陷（只记不改）")
    L.append("")
    for d in OLD_DEFECTS:
        L.append("- %s" % d)
    L.append("")
    L.append("## 11. 局限与待复核")
    L.append("")
    for d in LIMITATIONS:
        L.append("- %s" % d)
    L.append("")
    L.append("## 12. 源码事实钉子（--check 逐条核对）")
    L.append("")
    L.append("| ID | 事实 | 状态 |")
    L.append("|---|---|---|")
    for f in sorted(rep["source_facts"], key=lambda x: x["id"]):
        L.append("| %s | %s | %s |" % (f["id"], cell(f["desc"]), "成立" if f["ok"] else "**漂移**"))
    L.append("")
    L.append("<!-- MAPPING_SHA256: %s -->" % rep["mapping_sha256"])
    return "\n".join(L) + "\n"


# ===========================================================================
# 主入口
# ===========================================================================
def diff_core(a, b, path=""):
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append("%s.%s：基线多出" % (path, k))
            elif k not in b:
                out.append("%s.%s：基线缺" % (path, k))
            else:
                out.extend(diff_core(a[k], b[k], "%s.%s" % (path, k)))
    elif a != b:
        out.append("%s：现在=%r 基线=%r" % (path, a, b))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="AIF-01 出厂 AI 真实视角能力审计（纯静态）")
    ap.add_argument("--repo", default=os.path.abspath(os.path.join(
        HERE, "..", "..", "..")), help="仓库根（含 agent/ai 与 factory/）")
    ap.add_argument("--admin-sandbox", choices=("no", "ok"), default="no",
                    help="admin 身份的沙箱命令是否可达（缺省 no）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--markdown", action="store_true", help="输出基线报告 Markdown")
    ap.add_argument("--write-baseline", action="store_true",
                    help="把当前结果写成入库基线 docs/OCC-CAPABILITY-BASELINE.json")
    ap.add_argument("--check", action="store_true", help="与入库基线比对，不一致即失败")
    args = ap.parse_args(argv)

    repo = os.path.abspath(args.repo)
    if not os.path.isfile(os.path.join(repo, P_TOOLS)):
        sys.stderr.write("audit_occ_capabilities: %s 下找不到 %s\n" % (repo, P_TOOLS))
        return 2
    rep = build_report(repo, args.admin_sandbox)
    bpath = os.path.join(repo, "agent", "ai", BASELINE_REL)

    if args.write_baseline:
        doc = {"schema": SCHEMA,
               "generated_at": datetime.now().astimezone().strftime(
                   "%Y-%m-%dT%H:%M:%S%z"),
               "core": core_of(rep), "old_view": rep["old_view"],
               "source_facts": rep["source_facts"]}
        os.makedirs(os.path.dirname(bpath), exist_ok=True)
        with open(bpath, "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
            f.write("\n")
        print("OCC BASELINE WRITTEN %s" % bpath)
        return 0

    if args.check:
        errors = []
        if not os.path.isfile(bpath):
            errors.append("入库基线不存在：%s" % bpath)
        else:
            with open(bpath, "r", encoding="utf-8") as f:
                base = json.load(f)
            errors.extend(diff_core(base.get("core", {}), core_of(rep)))
        for f in rep["source_facts"]:
            if not f["ok"]:
                errors.append("源码事实漂移 %s：%s" % (f["id"], f["desc"]))
        if rep["scenario_ids_missing"]:
            errors.append("Top 15 引用了场景库里没有的场景：%s"
                          % "、".join(rep["scenario_ids_missing"]))
        if errors:
            print("OCC CHECK FAIL")
            for e in errors:
                print(" - " + e)
            return 1
        r = rep["views"]["root"]
        a = rep["views"]["admin"]
        print("OCC CHECK PASS")
        print("root: read_any=%d/%d (%.1f%%) direct=%d (%.1f%%) semantic=%d (%.1f%%) "
              "structured+=%d (%.1f%%) write=%d/%d (%.1f%%) absent=%d"
              % (r["read_any"], r["objects_applicable"], r["read_any_pct"],
                 r["read_direct"], r["read_direct_pct"], r["semantic_high"],
                 r["semantic_high_pct"], r["semantic_structured"],
                 r["semantic_structured_pct"], r["write_any"],
                 r["write_applicable"], r["write_any_pct"],
                 len(r["read_absent_objects"])))
        print("admin: read_any=%d/%d (%.1f%%) direct=%d (%.1f%%) semantic=%d (%.1f%%) "
              "structured+=%d (%.1f%%) write=%d/%d (%.1f%%) absent=%d"
              % (a["read_any"], a["objects_applicable"], a["read_any_pct"],
                 a["read_direct"], a["read_direct_pct"], a["semantic_high"],
                 a["semantic_high_pct"], a["semantic_structured"],
                 a["semantic_structured_pct"], a["write_any"],
                 a["write_applicable"], a["write_any_pct"],
                 len(a["read_absent_objects"])))
        print("tools: registry=%d factory=%d reachable_registry=%d unreachable_registry=%d"
              % (rep["tools"]["registry_total"], rep["tools"]["factory_tools_total"],
                 len(rep["tools"]["factory_reachable_registry"]),
                 rep["tools"]["factory_unreachable_registry_count"]))
        print("source_facts=%d ok=%d" % (len(rep["source_facts"]),
                                         sum(1 for f in rep["source_facts"] if f["ok"])))
        return 0

    if args.json:
        print(json.dumps(rep, ensure_ascii=False, sort_keys=True, indent=1))
        return 0
    if args.markdown:
        sys.stdout.write(render_markdown(rep))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
