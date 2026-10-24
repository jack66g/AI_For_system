# AIKernel W75 全知/全能对象矩阵

> 由 `agent/ai/tools/audit_capabilities.py` 只读扫描生成；生成时间 2026-10-24T15:11:38+0800；审计主机 `jack66g-virtual-machine`；VM 探测 `root@192.168.245.138`。
> 矩阵不手填：对象目录、路径判定、覆盖计数、缺口引用均来自脚本。口径见 §1；每次重跑覆盖本文件即视为刷新。

## 1. 口径

- **读路径**：已注册工具 / exec 白名单命令 / 可读文件 / 只读 HTTP API / 生产 VM 节点，任一可达即算。
- **直连读**：不需要 W2 确认、不依赖任意代码逃逸的读路径（R 工具 / R 命令 / 文件 / GET API）。
- **语义化**：`semantic`（typed JSON/对象模型/图关系）或 `structured`（JSON/CSV/key=value/稳定机器可解析字段）；`raw` 为自由文本；`shell-escape` 一律不计为结构化。
- **写路径**：已注册 W1/W2 工具、白名单 W1/W2 命令、或存在的 POST API；shell/脚本逃逸单独标注。
- **Principal-only**：`/lease issue|revoke|confirm` 等 root+TTY 命令，存在但不是 Agent 工具；计入读/写语义但不计入 AI 写覆盖。
- **风险**：D0 纯信息 / D1 可逆本地 / D2 不可逆本地 / D3 系统级 / D4 身份与启动链。

## 2. 覆盖总览（脚本计算）

| 指标 | 数值 |
|---|---:|
| 对象总数（适用） | 97 |
| 读路径覆盖（含 W2/逃逸） | 94/97 = **96.9%** |
| 直连读覆盖（R 工具/命令/文件/API） | 87/97 = **89.7%** |
| 实测存活读路径 | 94/97 = **96.9%** |
| 结构化+语义化覆盖 | 68/97 = **70.1%** |
| 其中 semantic（typed 对象模型） | 10/97 = **10.3%** |
| 写路径覆盖（可写对象） | 69/75 = **92.0%** |
| 写路径 but shell-escape only | 8 |
| 写路径 but Principal-only（非 AI） | 1 |
| 缺口总数（open） / P0 / P1 / P2 / P3 | 33 / 0 / 13 / 15 / 5 |
| 已关闭缺口（W76） | 3（G-002, G-015, G-035） |
| 工具 / 域 / desktop 工具 | 156 / 9 / 20 |
| SME seed/corpus | 173（combo=8, domain-header=9, tool=156） |
| 工具名清单 SHA-256 | `1999f820a09887a66ca3f1878b1fc76523fcb911929e6ed4cfbc61c67e3afe81` |

读路径覆盖达到 95% 目标；但直连/语义化覆盖仍低于目标，缺口见 `CAPABILITY-GAPS.md`。

## 3. 对象矩阵

| 对象类 | 对象 | 读路径（工具/命令/API/文件） | 写路径 | 语义化程度 | 风险/D 级 | 证据命令 | 缺口 ID |
|---|---|---|---|---|---|---|---|
| 进程/线程/调度 | 进程枚举与属性 | `cmd:ps` [ok]<br>`file:/proc/1/status` [ok]<br>`file:/proc/1/cmdline` [ok] | `cmd:kill` [gated]<br>`tool:netlink_act_proc_signal` [gated] | raw | D0/D2 | exec_run ps -eo pid,ppid,stat,comm; cat /proc/<pid>/status | - |
| 进程/线程/调度 | 线程 | `cmd:ps` [ok]<br>`file:/proc/1/task` [ok] | `tool:netlink_act_proc_signal` [gated] | raw | D0/D2 | exec_run ps -T -p <pid>; ls /proc/<pid>/task | - |
| 进程/线程/调度 | 调度属性与内核控制 | `file:/proc/1/sched` [ok]<br>`file:/proc/1/stat` [ok]<br>`cmd:ps` [ok] | `tool:netlink_act_sched_nice` [gated]<br>`tool:netlink_act_sched_affinity` [gated]<br>`tool:netlink_act_sched_oom_score` [gated]<br>`tool:netlink_act_sched_timeslice` [gated]<br>`tool:netlink_act_proc_signal` [gated]<br>`tool:netlink_act_proc_freeze` [gated]<br>`tool:netlink_act_proc_rlimit` [gated] | structured | D0/D2 | cat /proc/<pid>/sched; netlink_act_sched_nice(pid,value) | - |
| 进程/线程/调度 | 进程内存/IO/文件描述符 | `file:/proc/1/smaps` [ok]<br>`file:/proc/1/io` [ok]<br>`file:/proc/1/fd` [ok]<br>`cmd:ls` [ok] | `tool:netlink_act_proc_rlimit` [gated] | structured | D0/D2 | cat /proc/<pid>/smaps; cat /proc/<pid>/io; ls -l /proc/<pid>/fd | - |
| 进程/线程/调度 | 进程 cgroup 归属 | `file:/proc/1/cgroup` [ok]<br>`tool:sysfs_get` [ok] | `tool:sysfs_set` [gated] | structured | D0/D2 | cat /proc/<pid>/cgroup; sysfs_get /sys/fs/cgroup/<path>/cgroup.procs | - |
| CPU/内存/PSI/IO | CPU 拓扑/型号 | `cmd:lscpu` [ok]<br>`file:/proc/cpuinfo` [ok]<br>`tool:sysfs_get` [ok] | `tool:sysfs_set` [gated] | structured | D0/D2 | exec_run lscpu -J; sysfs_get /sys/devices/system/cpu/online | - |
| CPU/内存/PSI/IO | CPU 使用率/负载 | `file:/proc/stat` [ok]<br>`cmd:uptime` [ok]<br>`cmd:vmstat` [ok] | — | structured | D0 | cat /proc/stat; uptime; vmstat 1 2 | - |
| CPU/内存/PSI/IO | CPU 频率/调频 | `tool:sysfs_get` [ok]<br>`file:/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` [ABSENT] | `tool:sysfs_set` [gated] | structured | D0/D2 | sysfs_get /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor | - |
| CPU/内存/PSI/IO | 内存/swap | `cmd:free` [ok]<br>`file:/proc/meminfo` [ok]<br>`tool:procfs_read_swaps` [ok] | `tool:sysctl_set` [gated]<br>`tool:netlink_act_mm_swappiness` [gated] | structured | D0/D2 | exec_run free -b; cat /proc/meminfo; procfs_read_swaps | - |
| CPU/内存/PSI/IO | PSI 压力（CPU/内存/IO） | `tool:procfs_read_pressure_cpu` [ok]<br>`tool:procfs_read_pressure_memory` [ok]<br>`tool:procfs_read_pressure_io` [ok] | — | structured | D0 | procfs_read_pressure_cpu; 生产 VM /proc/pressure 缺失 | G-014 |
| CPU/内存/PSI/IO | 块 IO 统计 | `file:/proc/diskstats` [ok]<br>`cmd:vmstat` [ok]<br>`tool:sysfs_get` [ok] | `tool:netlink_act_io_priority` [gated] | structured | D0/D2 | cat /proc/diskstats; sysfs_get /sys/block/<dev>/stat | - |
| CPU/内存/PSI/IO | IO 调参（预读/优先级/带宽） | `tool:sysfs_get` [ok]<br>`tool:procfs_read_vfs_stats` [ok] | `tool:netlink_act_io_bandwidth` [gated]<br>`tool:netlink_act_io_priority` [gated] | structured | D0/D2 | sysfs_get /sys/class/bdi/<dev>/read_ahead_kb | - |
| cgroup | cgroup v2 层级/限额 | `tool:sysfs_get` [ok]<br>`file:/sys/fs/cgroup/cgroup.controllers` [ok] | `tool:sysfs_set` [gated] | structured | D0/D2 | sysfs_get /sys/fs/cgroup/<path>/{memory.max,cpu.max,cgroup.procs} | - |
| cgroup | cgroup 统计/AI 推理计数 | `tool:procfs_read_cgroup_inferences` [ok]<br>`tool:sysfs_get` [ok] | `tool:sysfs_set` [gated] | structured | D0/D2 | procfs_read_cgroup_inferences; sysfs_get /sys/fs/cgroup/<path>/memory.current | - |
| 文件/目录/元数据/ACL/xattr | 文件内容读取 | `cmd:cat` [ok]<br>`cmd:head` [ok]<br>`cmd:tail` [ok]<br>`cmd:grep` [ok] | `cmd:tee` [ok]<br>`cmd:sed` [ok] | raw | D0/D1 | exec_run cat/head/tail/grep <path>; tee W1 限 /root /tmp /var/ai | - |
| 文件/目录/元数据/ACL/xattr | 目录枚举 | `cmd:ls` [ok]<br>`cmd:find` [ok] | `cmd:mkdir` [ok]<br>`cmd:cp` [ok]<br>`cmd:mv` [ok] | structured | D0/D1 | exec_run find <dir> -maxdepth 1 -printf '%y %m %u %g %s %p\n' | - |
| 文件/目录/元数据/ACL/xattr | 元数据/链接 | `cmd:stat` [ok]<br>`cmd:ls` [ok] | `cmd:chmod` [gated]<br>`cmd:chown` [gated]<br>`cmd:ln` [ok] | structured | D0/D2 | exec_run stat <path>; ls -l <path> | - |
| 文件/目录/元数据/ACL/xattr | 文件写入/编辑 | `cmd:cat` [ok] | `cmd:tee` [ok]<br>`cmd:sed` [ok]<br>`cmd:python3` [gated] | raw | D0/D2 | tee 限 /root /tmp /var/ai; python3 为 W2 | - |
| 文件/目录/元数据/ACL/xattr | 删除/重命名 | `cmd:ls` [ok]<br>`cmd:stat` [ok] | `cmd:rm` [gated]<br>`cmd:mv` [ok] | structured | D0/D2 | exec_run rm/mv <path>; W2 确认 | - |
| 文件/目录/元数据/ACL/xattr | 文件 ACL | `escape:python3` [shell-escape] | `escape:sys_shell` [shell-escape] | raw | D0/D2 | 仅 python3 os.getxattr(system.posix_acl_access) / shell getfacl；无白名单命令 | G-004 |
| 文件/目录/元数据/ACL/xattr | 扩展属性 xattr | `escape:python3` [shell-escape] | `escape:python3` [shell-escape] | raw | D0/D2 | 仅 python3 os.listxattr；getfattr/setfattr 缺失 | G-005 |
| 文件/目录/元数据/ACL/xattr | 文件属性 chattr/lsattr | `escape:sys_shell` [shell-escape] | `escape:sys_shell` [shell-escape] | raw | D0/D2 | 仅 shell lsattr/chattr；不在 exec 白名单 | G-006 |
| 文件/目录/元数据/ACL/xattr | 文件完整性/校验和 | `escape:python3` [shell-escape] | — | raw | D0 | 仅 python3 hashlib；无 sha256sum 白名单命令 | G-024 |
| 文件/目录/元数据/ACL/xattr | 磁盘配额 | — | — | none | D0/D3 | quota/repquota 在 L1/VM 均缺二进制；无 AI 读路径 | G-007 |
| 磁盘/分区/文件系统/SMART | 块设备/分区 | `cmd:lsblk` [ok]<br>`cmd:blkid` [ok]<br>`file:/proc/partitions` [ok] | `cmd:mount` [gated]<br>`cmd:umount` [gated] | structured | D0/D2 | exec_run lsblk -J; blkid -o export | - |
| 磁盘/分区/文件系统/SMART | 文件系统/挂载 | `cmd:findmnt` [ok]<br>`file:/proc/mounts` [ok]<br>`cmd:dumpe2fs` [ok] | `cmd:mount` [gated]<br>`cmd:umount` [gated]<br>`tool:config_write_fstab` [gated] | structured | D0/D3 | findmnt -J; cat /proc/mounts; dumpe2fs -h <dev> | - |
| 磁盘/分区/文件系统/SMART | SMART/磁盘健康 | `cmd:smartctl` [ABSENT] | — | none | D0 | smartctl -a <dev> 已注册 R，但 L1/VM 无二进制 | G-008 |
| 磁盘/分区/文件系统/SMART | LVM/逻辑卷 | `cmd:lsblk` [ok]<br>`tool:sysfs_get` [ok] | — | structured | D0 | lsblk -J 可看 dm 映射；pvs/vgs/lvs 缺失 | G-018 |
| 磁盘/分区/文件系统/SMART | 磁盘用量/inode | `cmd:df` [ok]<br>`cmd:du` [ok]<br>`cmd:find` [ok] | — | structured | D0 | exec_run df -P; du -x -d1; find | - |
| 磁盘/分区/文件系统/SMART | TRIM/软 RAID/dm | `file:/proc/mdstat` [ok]<br>`cmd:lsblk` [ok]<br>`tool:sysfs_get` [ok] | `cmd:fstrim` [gated] | structured | D0/D1 | cat /proc/mdstat; lsblk; fstrim -v <mount> | - |
| systemd/服务/日志/启动 | units/服务状态 | `cmd:systemctl` [ok]<br>`file:/run/systemd/system` [ok]<br>`file:/etc/systemd/system` [ok] | `cmd:systemctl` [gated] | structured | D0/D3 | systemctl list-units --no-pager; systemctl show <unit> -p ... | - |
| systemd/服务/日志/启动 | 失败单元 | `cmd:systemctl` [ok] | `cmd:systemctl` [gated] | structured | D0/D3 | systemctl --failed --no-legend; systemctl restart <unit> | - |
| systemd/服务/日志/启动 | journal 日志 | `cmd:journalctl` [ok]<br>`file:/var/log/journal` [ok] | `cmd:journalctl` [ok] | structured | D0/D2 | journalctl -o json --no-pager -n 100; --vacuum-* 为 W1 | - |
| systemd/服务/日志/启动 | 内核日志/dmesg | `cmd:dmesg` [ok]<br>`file:/dev/kmsg` [ok] | `cmd:dmesg` [gated] | raw | D0/D2 | exec_run dmesg --color=never; -c/--clear 为 W2 | - |
| systemd/服务/日志/启动 | 启动链 A/B/内核参数 | `cmd:aik-upgrade` [ok]<br>`cmd:ls` [ok]<br>`file:/proc/cmdline` [ok]<br>`file:/boot/grub/grubenv` [ok] | `cmd:aik-upgrade` [gated] | structured | D0/D3 | aik-upgrade status (R verb); ls /boot; cat /proc/cmdline | - |
| systemd/服务/日志/启动 | 启动耗时 | `cmd:systemd-analyze` [ok] | — | structured | D0 | systemd-analyze; systemd-analyze blame | - |
| systemd/服务/日志/启动 | timers/计划任务总览 | `cmd:systemctl` [ok]<br>`file:/etc/cron.d` [ok] | `cmd:systemctl` [gated] | structured | D0/D3 | systemctl list-timers --no-pager; ls /etc/cron.d | - |
| systemd/服务/日志/启动 | unit 配置/drop-in | `cmd:cat` [ok]<br>`file:/etc/systemd/system` [ok] | `escape:sys_shell` [shell-escape] | raw | D0/D2 | 仅 cat 读；写只能 sys_shell/systemctl edit，无结构化写工具 | G-011 |
| 网络/接口/地址/路由/DNS/防火墙/命名空间 | 接口/链路/网卡诊断 | `cmd:ip` [ok]<br>`cmd:ethtool` [ok]<br>`tool:sysfs_get` [ok] | `cmd:ip` [gated]<br>`tool:sysfs_set` [gated] | structured | D0/D2 | ip -j link; ethtool <if>; sysfs_get /sys/class/net/<if>/statistics | G-019 |
| 网络/接口/地址/路由/DNS/防火墙/命名空间 | 地址/路由 | `cmd:ip` [ok]<br>`file:/proc/net/route` [ok] | `cmd:ip` [gated] | structured | D0/D2 | ip -j addr; ip -j route; cat /proc/net/route | - |
| 网络/接口/地址/路由/DNS/防火墙/命名空间 | 连接/套接字 | `cmd:ss` [ok]<br>`file:/proc/net/tcp` [ok]<br>`file:/proc/net/udp` [ok] | `cmd:conntrack` [ABSENT] | structured | D0/D2 | ss -tunap; cat /proc/net/tcp | - |
| 网络/接口/地址/路由/DNS/防火墙/命名空间 | conntrack 连接跟踪 | `tool:procfs_read_net_nf_conntrack` [ok]<br>`file:/proc/net/nf_conntrack` [ok] | `cmd:conntrack` [ABSENT] | structured | D0/D2 | procfs_read_net_nf_conntrack; conntrack -L（VM 缺失） | G-020 |
| 网络/接口/地址/路由/DNS/防火墙/命名空间 | DNS 解析配置 | `cmd:resolvectl` [ok]<br>`tool:config_read_resolv_conf` [ok] | `tool:config_write_resolv_conf` [ok]<br>`cmd:resolvectl` [gated] | structured | D0/D2 | resolvectl status; config_read_resolv_conf | - |
| 网络/接口/地址/路由/DNS/防火墙/命名空间 | 防火墙/LSM 策略 | `tool:config_read_nftables` [ok]<br>`cmd:aa-status` [ok]<br>`file:/sys/kernel/security/apparmor` [ok] | `tool:config_write_nftables` [gated]<br>`cmd:nft` [gated] | raw | D0/D3 | config_read_nftables; nft list ruleset（W2）；aa-status（VM 缺失） | G-021/G-028 |
| 网络/接口/地址/路由/DNS/防火墙/命名空间 | 网络命名空间 | `cmd:ip` [ok]<br>`file:/proc/1/ns/net` [ABSENT] | `cmd:ip` [gated] | structured | D0/D2 | ip netns list; ls -l /proc/<pid>/ns/net; ip netns add（W2） | G-034 |
| 网络/接口/地址/路由/DNS/防火墙/命名空间 | 接口配置/qdisc | `cmd:ip` [ok]<br>`file:/sys/class/net` [ok] | `cmd:tc` [gated]<br>`cmd:ip` [gated]<br>`tool:sysfs_set` [gated] | structured | D0/D3 | ip -d link; tc qdisc show（W2）；sysfs_set /sys/class/net/... | - |
| 用户/组/会话/sudo/policy/租约 | 用户账户 | `cmd:getent` [ok]<br>`file:/etc/passwd` [ok] | `cmd:useradd` [gated]<br>`cmd:usermod` [gated]<br>`cmd:userdel` [gated] | structured | D0/D3 | getent passwd; cat /etc/passwd | - |
| 用户/组/会话/sudo/policy/租约 | 组/成员 | `cmd:getent` [ok]<br>`file:/etc/group` [ok] | `cmd:groupadd` [gated]<br>`cmd:groupmod` [gated]<br>`cmd:groupdel` [gated] | structured | D0/D3 | getent group; cat /etc/group | - |
| 用户/组/会话/sudo/policy/租约 | 登录会话 | `cmd:ps` [ok]<br>`file:/proc/1/loginuid` [ok] | — | raw | D0 | ps -eo user,tty,stat,comm; cat /proc/<pid>/loginuid | G-025 |
| 用户/组/会话/sudo/policy/租约 | sudoers | `file:/etc/sudoers` [ok/unavailable]<br>`cmd:cat` [ok] | `escape:sys_shell` [shell-escape] | raw | D0/D4 | cat /etc/sudoers（root-only）；visudo 只能 shell | G-012 |
| 用户/组/会话/sudo/policy/租约 | 授权策略/租约 | `file:/etc/aikernel/policy.conf` [ok]<br>`cmd:cat` [ok]<br>`file:/etc/aikernel/tools.json` [ok]<br>`principal:/lease list\|show` [gated]<br>`principal:--lease` [gated] | `principal:/lease issue\|revoke\|confirm` [principal-only] | structured | D0/D4 | cat /var/lib/aikernel/leases/*.json（R，raw JSON）；/lease list\|show（Principal root+TTY）；--lease <id> 加载；W74 已落地 | G-001/G-012 |
| 用户/组/会话/sudo/policy/租约 | SSH 服务配置 | `tool:config_read_sshd_config` [ok] | `tool:config_write_sshd_config` [gated] | structured | D0/D3 | config_read_sshd_config; config_write_sshd_config（W2） | - |
| 用户/组/会话/sudo/policy/租约 | SSH authorized_keys | `file:/root/.ssh/authorized_keys` [ABSENT]<br>`cmd:ls` [ok] | `escape:sys_shell` [shell-escape] | raw | D0/D4 | ls -l /root/.ssh; cat authorized_keys（root-only）；ssh-keygen 只能 shell | G-013 |
| 用户/组/会话/sudo/policy/租约 | SSH 主机密钥状态 | `cmd:ls` [ok]<br>`cmd:stat` [ok]<br>`file:/etc/ssh/ssh_host_ed25519_key.pub` [ok] | `escape:sys_shell` [shell-escape] | structured | D0/D4 | ls -l /etc/ssh/ssh_host_*; stat；仅状态，不读私钥 | G-013 |
| 包管理/仓库/版本/依赖/更新 | 已安装包 | `file:/var/lib/dpkg/status` [ok]<br>`cmd:dpkg` [gated] | `cmd:dpkg` [gated] | raw | D0/D3 | cat /var/lib/dpkg/status（原始）；dpkg -l（W2） | G-009 |
| 包管理/仓库/版本/依赖/更新 | 仓库/源 | `file:/etc/apt/sources.list` [ok]<br>`file:/etc/apt/sources.list.d` [ok] | `cmd:apt` [gated] | raw | D0/D3 | cat /etc/apt/sources.list; ls /etc/apt/sources.list.d | G-009 |
| 包管理/仓库/版本/依赖/更新 | 可用更新 | `cmd:apt` [gated] | `cmd:apt` [gated] | raw | D0/D3 | apt list --upgradable（整体 W2，无 R 路径） | G-010 |
| 包管理/仓库/版本/依赖/更新 | 安装/卸载/升级 | `cmd:dpkg` [gated] | `cmd:apt` [gated]<br>`cmd:dpkg` [gated] | raw | D0/D3 | apt install/remove/upgrade（W2，300s） | G-009 |
| 包管理/仓库/版本/依赖/更新 | 依赖/版本/内核模块 | `file:/var/lib/dpkg/status` [ok]<br>`cmd:dpkg` [gated]<br>`cmd:uname` [ok] | — | raw | D0 | dpkg -s <pkg>（W2）；cat /var/lib/dpkg/status；uname -r | G-022 |
| 硬件/CPU/GPU/温度/电源/设备树 | CPU 硬件 | `cmd:lscpu` [ok]<br>`file:/proc/cpuinfo` [ok]<br>`tool:sysfs_get` [ok] | `tool:sysfs_set` [gated] | structured | D0/D2 | lscpu -J; sysfs_get /sys/devices/system/cpu/cpu0/topology | - |
| 硬件/CPU/GPU/温度/电源/设备树 | GPU/显示 | `tool:sysfs_get` [ok]<br>`file:/sys/class/drm` [ok] | — | raw | D0 | sysfs_get /sys/class/drm/card0/device/... | G-023 |
| 硬件/CPU/GPU/温度/电源/设备树 | 温度/风扇 | `tool:sysfs_get` [ok]<br>`file:/sys/class/hwmon` [ok]<br>`file:/sys/class/thermal` [ok] | — | raw | D0 | sysfs_get /sys/class/hwmon/hwmon0/temp1_input; thermal_zone*/temp | G-023 |
| 硬件/CPU/GPU/温度/电源/设备树 | 电源/电池 | `tool:sysfs_get` [ok]<br>`file:/sys/class/power_supply` [ok] | — | raw | D0 | sysfs_get /sys/class/power_supply/ACAD/online; capacity/status | - |
| 硬件/CPU/GPU/温度/电源/设备树 | PCI/USB/设备树 | `tool:sysfs_get` [ok]<br>`file:/sys/bus/pci/devices` [ok]<br>`cmd:ls` [ok] | — | raw | D0 | ls /sys/bus/pci/devices; /sys/firmware/devicetree（x86 N/A） | G-023/G-027 |
| 内核 AI 遥测 /proc/ai/*、netlink、KUnit | /proc/ai/status | `tool:procfs_read_status` [ok]<br>`vmfile:/proc/ai/status` [ok] | `tool:sysfs_write_enabled` [ok] | structured | D0/D1 | procfs_read_status; cat /proc/ai/status（VM #59 实测） | - |
| 内核 AI 遥测 /proc/ai/*、netlink、KUnit | /proc/ai/control 参数表 | `tool:procfs_read_control` [ok]<br>`vmfile:/proc/ai/control` [ok] | `tool:netlink_act_sched_nice` [gated]<br>`tool:netlink_act_mm_swappiness` [gated]<br>`tool:netlink_act_io_priority` [gated]<br>`tool:netlink_act_net_cwnd` [gated]<br>`tool:netlink_act_power_freq` [gated] | structured | D0/D2 | procfs_read_control；27 参数文本行 | G-029 |
| 内核 AI 遥测 /proc/ai/*、netlink、KUnit | 决策/因果链 | `tool:procfs_read_decisions` [ok]<br>`tool:procfs_read_chains` [ok]<br>`vmfile:/proc/ai/decisions` [ok] | `tool:netlink_act_ai_decision_inject` [gated] | structured | D0/D2 | procfs_read_decisions; procfs_read_chains | - |
| 内核 AI 遥测 /proc/ai/*、netlink、KUnit | 遥测/netlink SENSE | `tool:procfs_read_telemetry` [ok]<br>`tool:netlink_sense` [ok] | `tool:procfs_write_telemetry_format` [ok]<br>`tool:procfs_write_telemetry_reset` [gated] | structured | D0/W1/W2 | procfs_read_telemetry; netlink_sense | - |
| 内核 AI 遥测 /proc/ai/*、netlink、KUnit | AI 统计计数 | `tool:procfs_read_stats_telemetry_emitted` [ok]<br>`tool:procfs_read_stats_decisions_total` [ok]<br>`tool:procfs_read_stats_runtime_state` [ok]<br>`tool:procfs_read_hitrate` [ok] | — | structured | D0 | procfs_read_stats_*; procfs_read_hitrate | - |
| 内核 AI 遥测 /proc/ai/*、netlink、KUnit | 内核模型加载/推理 | `tool:procfs_read_model_out` [ok]<br>`tool:procfs_read_status` [ok] | `tool:sysfs_write_model_load` [ok]<br>`tool:sysfs_write_model_unload` [ok]<br>`tool:sysfs_write_model_infer` [ok] | structured | D0/D1 | procfs_read_model_out; sysfs_write_model_infer（W1） | - |
| 内核 AI 遥测 /proc/ai/*、netlink、KUnit | 策略/回滚 | `tool:procfs_read_decision_stats` [ok]<br>`tool:procfs_read_hitrate` [ok] | `tool:sysfs_write_policy_global_enable` [ok]<br>`tool:sysfs_write_policy_rollback` [ok]<br>`tool:sysfs_write_policy_think` [ok]<br>`tool:sysfs_write_policy_outcome` [ok] | structured | D0/W1 | procfs_read_decision_stats; policy/* 写 W1 | - |
| 内核 AI 遥测 /proc/ai/*、netlink、KUnit | KUnit/内核测试 | `cmd:dmesg` [ok]<br>`file:/sys/kernel/debug/kunit` [ABSENT] | — | raw | D0 | dmesg \| grep -i kunit; ls /sys/kernel/debug/kunit（VM 空） | G-017 |
| SME 记忆/trace/训练导出 | SME 健康/统计 | `tool:memory_health` [ok]<br>`tool:memory_stats` [ok] | — | semantic | D0 | memory_health; memory_stats | - |
| SME 记忆/trace/训练导出 | 记忆 CRUD/检索 | `tool:memory_search` [ok]<br>`tool:memory_search_advanced` [ok]<br>`tool:memory_get` [ok] | `tool:memory_add` [ok]<br>`tool:memory_batch_add` [ok]<br>`tool:memory_update` [ok]<br>`tool:memory_delete` [gated]<br>`tool:memory_hit` [ok]<br>`tool:memory_archive` [ok]<br>`tool:memory_restore` [ok]<br>`tool:memory_import` [ok] | semantic | D0/W1/W2 | memory_search; memory_add; memory_delete（W2） | - |
| SME 记忆/trace/训练导出 | 事实图谱/多跳 | `tool:memory_facts` [ok]<br>`tool:memory_graph` [ok]<br>`tool:memory_facts_multi_hop` [ok]<br>`tool:memory_facts_history` [ok] | `tool:memory_link` [ok] | semantic | D0/W1 | memory_facts; memory_graph; memory_facts_multi_hop | - |
| SME 记忆/trace/训练导出 | Region 空间聚类 | `tool:memory_regions` [ok]<br>`tool:memory_regions_search` [ok] | `tool:memory_regions_evolve` [ok] | semantic | D0/W1 | memory_regions; memory_regions_search | - |
| SME 记忆/trace/训练导出 | QA/画像/指标/配置 | `tool:memory_qapairs` [ok]<br>`tool:memory_profile` [ok]<br>`tool:memory_metrics` [ok]<br>`tool:memory_config_get` [ok]<br>`tool:memory_config_check` [ok] | — | semantic | D0 | memory_qapairs; memory_profile; memory_metrics | - |
| SME 记忆/trace/训练导出 | trace JSONL 文件 | `file:/var/log/aikernel/trace` [ABSENT]<br>`file:~/.aikernel/trace` [ok]<br>`cmd:cat` [ok] | — | structured | D0 | cat/head/tail trace-*.jsonl; root path /var/log/aikernel/trace | G-003 |
| SME 记忆/trace/训练导出 | 训练导出 | `escape:python3` [shell-escape] | `escape:python3` [shell-escape] | raw | D0/D2 | 无 trace.export 工具；只能 python3 解析 JSONL 重组训练行 | G-003 |
| SME 记忆/trace/训练导出 | 会话历史 | `file:~/.aikernel/sessions` [ok]<br>`file:/var/log/aikernel/sessions` [ABSENT]<br>`cmd:cat` [ok] | — | structured | D0 | cat ~/.aikernel/sessions/*.jsonl；无 session 工具 | G-003 |
| 沙箱 | 隔离区列表/状态/资源限额 | `tool:sandbox_status` [ok]<br>`file:/sandbox` [ok]<br>`tool:sysfs_get` [ok] | `tool:sandbox_create` [ok]<br>`tool:sysfs_set` [gated] | structured | D0/D2 | sandbox_status; ls /sandbox; sysfs_get /sys/fs/cgroup/... | - |
| 沙箱 | 沙箱资源限制 | `tool:sandbox_status` [ok]<br>`tool:sysfs_get` [ok]<br>`file:/sys/fs/cgroup` [ok] | `tool:sysfs_set` [gated] | structured | D0/D2 | sandbox_status 显示 cgroup/限额; sysfs_get cgroup cpu.max/memory.max | - |
| 沙箱 | 隔离区产物/残留 | `tool:sandbox_status` [ok]<br>`cmd:ls` [ok] | `tool:sandbox_destroy` [ok] | structured | D0/D1 | sandbox_status; ls -la /sandbox/<name> | - |
| 沙箱 | spawn/destroy 生命周期 | `tool:sandbox_status` [ok] | `tool:sandbox_spawn` [gated]<br>`tool:sandbox_destroy` [ok] | structured | D0/W1/W2 | sandbox_spawn（W2）; sandbox_destroy（W1） | - |
| 沙箱 | 子智能体工具面/子会话 trace | `file:/usr/local/share/aikernel/tools-sandbox.json` [ok]<br>`tool:sandbox_status` [ok] | — | structured | D0 | cat tools-sandbox.json; sandbox_status | G-016 |
| 桌面 | 桌面健康/统计 | `tool:desktop_health` [ok]<br>`tool:desktop_stats` [ok] | — | semantic | D0 | desktop_health; desktop_stats; GET /api/health\|stats | - |
| 桌面 | 应用枚举/启动/关闭 | `tool:desktop_apps_list` [ok] | `tool:desktop_apps_launch` [ok]<br>`tool:desktop_apps_close` [gated] | semantic | D0/D1/D2 | desktop_apps_list/launch/close（51 apps；10-task 01/05） | - |
| 桌面 | 窗口 | `tool:desktop_windows_list` [ok] | `tool:desktop_windows_focus` [ok]<br>`tool:desktop_windows_close` [gated] | structured | D0/D1/D2 | desktop_windows_list/focus/close；id/geometry/focused/visible/z/text（10-task 04/05） | - |
| 桌面 | 主题/壁纸 | `tool:desktop_theme_get` [ok]<br>`tool:desktop_wallpaper_get` [ok] | `tool:desktop_theme_set` [ok]<br>`tool:desktop_wallpaper_set` [ok] | semantic | D0/D1 | desktop_theme_get/set; desktop_wallpaper_get/set；回读/恢复（10-task 02/03） | - |
| 桌面 | 通知 | `tool:desktop_notifications_list` [ok] | `tool:desktop_notifications_send` [ok] | semantic | D0/D1 | desktop_notifications_list/send；追加不覆盖历史（10-task 09） | - |
| 桌面 | 输入注入（键鼠） | — | `tool:desktop_input_type` [gated]<br>`tool:desktop_input_key` [gated] | none | D2 | desktop_input_type/key（D2）；读无“输入历史”对象，窗口文本经 desktop_windows_list 观察（10-task 07/08） | - |
| 桌面 | 截图 | `tool:desktop_screenshot` [ok] | — | structured | D0 | desktop_screenshot；path/bytes/sha256/width/height，>30KB/colors 防白屏（10-task 06/07b） | - |
| 桌面 | 剪贴板 | `tool:desktop_clipboard_get` [ok] | `tool:desktop_clipboard_set` [gated] | structured | D0/D2 | desktop_clipboard_get/set；previous 恢复（10-task 10） | - |
| 桌面 | 聊天/会话/电源 | `api:GET /api/chat/history` [ok]<br>`api:GET /api/chat/sessions` [ok] | `apiw:POST /api/chat` [ABSENT] | semantic | D0/D3 | chat 仍 exec_run curl（有效 W2）；desktop_power D3 已注册但 /api/power 501 unavailable，不计有效写；G-033 保持开放 | G-033 |
| 时间/NTP/cron/timers/SSH | 时钟/NTP | `cmd:timedatectl` [ok]<br>`file:/etc/timezone` [ok] | `cmd:timedatectl` [gated] | structured | D0/D3 | timedatectl show; timedatectl timesync-status; set-* 为 W2 | - |
| 时间/NTP/cron/timers/SSH | 用户 crontab | `cmd:crontab` [gated]<br>`file:/var/spool/cron/crontabs` [ok/unavailable] | `cmd:crontab` [gated] | raw | D0/D2 | crontab -l（W2；VM 二进制缺失、spool 不存在） | G-026 |
| 时间/NTP/cron/timers/SSH | 系统 cron/timers | `cmd:ls` [ok]<br>`file:/etc/crontab` [ok]<br>`file:/etc/cron.d` [ok]<br>`cmd:systemctl` [ok] | — | structured | D0 | cat /etc/crontab; ls /etc/cron.d; systemctl list-timers | G-026 |

## 4. 未达项与说明

- 读路径为 ABSENT 的对象：FS-10, DISK-03, DT-06。
- 语义化仍为 raw 的对象：PROC-01, PROC-02, FS-01, FS-04, FS-06, FS-07, FS-08, FS-09, SYS-04, SYS-08, NET-06, ID-03, ID-04, ID-07, PKG-01, PKG-02, PKG-03, PKG-04, PKG-05, HW-02, HW-03, HW-04, HW-05, AI-08, MEM-07, TIME-02。
- `shell-escape` 表示只能通过 `python3`（W2）或 `sys_shell`（交互 TTY）访问，不是一等能力；对应 gap 见 `CAPABILITY-GAPS.md`。
- VM 节点证据：`vm:/proc/ai/control; vm:/proc/ai/decisions; vm:/proc/ai/status; vm:/sys/fs/cgroup/ai.inferences; vm:/sys/kernel/ai/enabled`。

<!-- TOTAL_OBJECTS: 97 -->
<!-- READ_ANY: 94 -->
<!-- READ_DIRECT: 87 -->
<!-- SEMANTIC_STRUCTURED: 68 -->
<!-- WRITE_ANY: 69 -->

