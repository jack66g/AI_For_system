# 出厂 AI 真实视角能力基线（OCC-CAPABILITY-BASELINE）

> 由 `agent/ai/tools/audit_occ_capabilities.py --markdown` 生成，不手填；对象目录与缺口登记 import 自旧审计 `audit_capabilities.py`。
> §1–§12 是静态推断（求值规则见 §1）；§13 起是出厂机实测层（静态规则已按实测更正 5 条，见 §15.7）。

## 1. 口径

- **为什么重算**：旧审计量的是 tools.json 注册表（237 件、27 个通道），其执行器只链进已退出出厂入口的 aikernel-shell。出厂入口是 occ，运行时不读 tools.json。
- **出厂工具面**：10 件（read、write、edit、glob、grep、bash、rm、mv、mkdir、config_write_network）。注册表里只有 6 件在出厂可达（bash、edit、glob、grep、read、write），**231 件注册表工具对出厂 AI 不可达**。
- **两种身份**：root（控制台 root 路径与 aikernel-api 服务）与 admin（控制台默认目标，wheel 组）。W2：root 控制台需交互确认，admin 与 headless API 一律拒绝。
- **admin 的沙箱命令缺省按不可达计**（仓内无 sudo 二进制与放行 aik-sandbox 的 sudoers 规则）。
- **读面标记**：`ok`=免确认；`W2`=须确认（仅 root 控制台）；`~`=只见沙箱自身/一部分数据；`?`=依赖运行态。语义级别不高于旧申报级别（自由文本=raw）。
- **可达**=结构上存在且不被沙箱视图/权限挡住（同旧口径「登记即算」），不代表节点此刻存在。

## 2. 汇总：旧入口注册表口径 vs 出厂 AI 口径

| 指标 | 旧入口注册表口径（同机复算） | 出厂 root | 出厂 admin |
|---|---:|---:|---:|
| 可读对象 read_any | 88/90 = 97.8% | **81/90 = 90.0%** | **60/90 = 66.7%** |
| 免确认读 read_direct | 85/90 = 94.4% | **81/90 = 90.0%** | **60/90 = 66.7%** |
| 须确认才可达的读面（对象数） | — | 0 | 0 |
| 带类型语义 semantic | 9/90 = 10.0% | **0/90 = 0.0%** | **0/90 = 0.0%** |
| 结构化+语义 | 67/90 = 74.4% | **49/90 = 54.4%** | **33/90 = 36.7%** |
| 原始文本 raw 对象数 | 21 | 32 | 27 |
| 不可达对象数 | 2 | **9** | **30** |
| 仅部分可见（partial）对象数 | — | 8 | 6 |
| 仅依赖运行态（cond）对象数 | — | 29 | 16 |
| 可写对象 write_any | 63/69 = 91.3% | **38/69 = 55.1%** | **5/69 = 7.2%** |
| 免确认直写 write_direct | 58/69 = 84.1% | **6/69 = 8.7%** | **5/69 = 7.2%** |
| 仅确认后可写的对象数 | — | 32 | 0 |
| 注册表工具可达数 | 237/237 | 6/237 | 6/237 |

- 分母：读面 90 个适用对象（另 7 个 n/a 不入分母：FS-06、FS-07、FS-09、FS-10、MEM-07、DT-06、TIME-02）；写面 69 个可写对象。
- 旧口径「同机复算」在本机静态求值（HTTP 探测替身为恒失败），与任务书引用的 11-23 重跑数字（可读 97.8% / 可直读 94.4% / 可写 91.3% / 带类型 10.0% / 结构化 74.4% / raw 22）可能有个位数出入。
- 出厂 root 不可达对象：DISK-03、MEM-08、PKG-03、PKG-04、SB-01、SB-02、SB-04、SYS-02、SYS-06。
- 出厂 admin 不可达对象：AI-08、DISK-03、DISK-05、DT-01、DT-02、DT-03、DT-04、DT-05、DT-07、DT-08、DT-09、FS-08、ID-04、ID-07、MEM-01、MEM-02、MEM-03、MEM-04、MEM-05、MEM-08、PKG-03、PKG-04、PROC-04、SB-01、SB-02、SB-03、SB-04、SYS-02、SYS-04、SYS-06。
- 旧口径有读工具、出厂 root 不可达：MEM-08、PKG-03、PKG-04、SB-01、SB-02、SB-04、SYS-02、SYS-06。
- 出厂 root 语义降级（级别低于旧口径）：22 个。
- 写面里的 `write/edit <sysfs/procfs 节点>` 是推断：occ write/edit 用 fopen "wb" 写宿主任意路径，对控制节点同样成立（同 shell 重定向 `echo x > /sys/...`），未实测；越界恒 W2。
- 回环 HTTP（curl）拿到的 JSON 记 structured：semantic 只给一等带类型的工具。

## 3. 对象矩阵（97 对象）

| 对象 | 旧口径 | 出厂 root 读面 | 出厂 admin 读面 | 出厂 root 写面 |
|---|---|---|---|---|
| PROC-01 进程枚举与属性 | 读/raw | `/proc :: *` [ok~]<br>`/proc/1/status` [ok~] | `/proc :: *` [ok~]<br>`/proc/1/status` [ok~] | — |
| PROC-02 线程 | 读/raw | `/proc/1 :: task/*` [ok]<br>`/proc/1/status` [ok] | `/proc/1 :: task/*` [ok]<br>`/proc/1/status` [ok] | — |
| PROC-03 调度属性与内核控制 | 读/structured | `/proc/1/sched` [ok]<br>`/proc/1/stat` [ok] | `/proc/1/sched` [ok]<br>`/proc/1/stat` [ok] | — |
| PROC-04 进程内存/IO/文件描述符 | 读/structured | `/proc/1/smaps` [ok]<br>`/proc/1/io` [ok]<br>`/proc/1 :: fd/*` [ok] | — | — |
| PROC-05 进程 cgroup 归属 | 读/structured | `/proc/1/cgroup` [ok] | `/proc/1/cgroup` [ok] | `write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| RES-01 CPU 拓扑/型号 | 读/structured | `lscpu -J` [ok]<br>`cat /proc/cpuinfo` [ok]<br>`/proc/cpuinfo` [ok] | `/proc/cpuinfo` [ok] | `write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| RES-02 CPU 使用率/负载 | 读/structured | `cat /proc/stat` [ok]<br>`uptime` [ok]<br>`vmstat 1 2` [ok]<br>+1 | `/proc/stat` [ok] | — |
| RES-03 CPU 频率/调频 | 读/structured | `cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` [ok?]<br>`/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` [ok?] | `/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` [ok?] | `write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| RES-04 内存/swap | 读/structured | `free -b` [ok]<br>`cat /proc/meminfo` [ok]<br>`cat /proc/swaps` [ok]<br>+1 | `/proc/meminfo` [ok] | `write /proc/sys/<key>（sysctl）` [W2] |
| RES-05 PSI 压力（CPU/内存/IO） | 读/structured | `cat /proc/pressure/cpu` [ok?]<br>`cat /proc/pressure/memory` [ok?]<br>`cat /proc/pressure/io` [ok?]<br>+1 | `/proc/pressure/memory` [ok?] | — |
| RES-06 块 IO 统计 | 读/structured | `cat /proc/diskstats` [ok]<br>`vmstat -d` [ok]<br>`cat /sys/block/sda/stat` [ok]<br>+2 | `/proc/diskstats` [ok]<br>`/sys/block/sda/stat` [ok] | — |
| RES-07 IO 调参（预读/优先级/带宽） | 读/structured | `cat /sys/class/bdi/8:0/read_ahead_kb` [ok?]<br>`/proc/sys/vm/readahead` [ok]<br>`/sys/class/bdi/8:0/read_ahead_kb` [ok?] | `/proc/sys/vm/readahead` [ok]<br>`/sys/class/bdi/8:0/read_ahead_kb` [ok?] | — |
| CG-01 cgroup v2 层级/限额 | 读/structured | `/sys/fs/cgroup/cgroup.controllers` [ok]<br>`/sys/fs/cgroup/system.slice/memory.max` [ok]<br>`/sys/fs/cgroup/system.slice/cpu.max` [ok] | `/sys/fs/cgroup/cgroup.controllers` [ok]<br>`/sys/fs/cgroup/system.slice/memory.max` [ok]<br>`/sys/fs/cgroup/system.slice/cpu.max` [ok] | `write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| CG-02 cgroup 统计/AI 推理计数 | 读/structured | `/sys/fs/cgroup/system.slice/memory.current` [ok]<br>`/sys/fs/cgroup/system.slice/memory.stat` [ok] | `/sys/fs/cgroup/system.slice/memory.current` [ok]<br>`/sys/fs/cgroup/system.slice/memory.stat` [ok] | `write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| FS-01 文件内容读取 | 读/raw | `/etc/hostname` [ok] | `/etc/hostname` [ok] | `write/edit（域内）` [W1]<br>`write/edit（越界目标）` [W2] |
| FS-02 目录枚举 | 读/structured | `/etc/systemd/system :: *` [ok] | `/etc/systemd/system :: *` [ok] | `mkdir/mv` [W1] |
| FS-03 元数据/链接 | 读/structured | `/etc/ssh :: ssh_host_*` [ok~]<br>`stat /usr/local/bin/occ` [ok~] | `/etc/ssh :: ssh_host_*` [ok~] | `chmod（仅沙箱可见树）` [W1] |
| FS-04 文件写入/编辑 | 读/raw | `/etc/hostname` [ok] | `/etc/hostname` [ok] | `write/edit（域内）` [W1]<br>`write/edit（越界目标）` [W2] |
| FS-05 删除/重命名 | 读/structured | `/etc/cron.d :: *` [ok] | `/etc/cron.d :: *` [ok] | `rm/mv` [W1] |
| FS-06 文件 ACL | n/a（n/a） | — | — | — |
| FS-07 扩展属性 xattr | n/a（n/a） | — | — | — |
| FS-08 文件属性 chattr/lsattr | 读/raw | `lsattr /usr/local/bin/occ` [ok~] | — | — |
| FS-09 文件完整性/校验和 | n/a（n/a） | `sha256sum /etc/aikernel/policy.conf` [ok~] | — | — |
| FS-10 磁盘配额 | n/a（n/a） | — | — | — |
| DISK-01 块设备/分区 | 读/structured | `lsblk -J` [ok]<br>`cat /proc/partitions` [ok]<br>`/proc/partitions` [ok] | `/proc/partitions` [ok] | — |
| DISK-02 文件系统/挂载 | 读/structured | `/etc/fstab` [ok]<br>`/proc/mounts` [ok]<br>`cat /proc/mounts` [ok~] | `/etc/fstab` [ok]<br>`/proc/mounts` [ok] | `write /etc/fstab` [W2] |
| DISK-03 SMART/磁盘健康 | 无读面 | — | — | — |
| DISK-04 LVM/逻辑卷 | 读/structured | `lsblk -J` [ok]<br>`/sys/block/dm-0/dm/name` [ok?] | `/sys/block/dm-0/dm/name` [ok?] | — |
| DISK-05 磁盘用量/inode | 读/structured | `df -P` [ok~] | — | — |
| DISK-06 TRIM/软 RAID/dm | 读/structured | `cat /proc/mdstat` [ok]<br>`lsblk -J` [ok]<br>`/proc/mdstat` [ok] | `/proc/mdstat` [ok] | — |
| SYS-01 units/服务状态 | 读/structured | `/etc/systemd/system :: *.service` [ok~]<br>`/run/systemd/system :: *` [ok~?] | `/etc/systemd/system :: *.service` [ok~]<br>`/run/systemd/system :: *` [ok~?] | — |
| SYS-02 失败单元 | 读/structured | — | — | — |
| SYS-03 journal 日志 | 读/structured | `/var/log/journal :: *` [ok~]<br>`/tmp/sme.log` [ok] | `/tmp/sme.log` [ok] | — |
| SYS-04 内核日志/dmesg | 读/raw | `dmesg --color=never` [ok?] | — | — |
| SYS-05 启动链 A/B/内核参数 | 读/structured | `cat /proc/cmdline` [ok]<br>`/proc/cmdline` [ok]<br>`/boot :: *` [ok~]<br>+1 | `/proc/cmdline` [ok]<br>`/boot :: *` [ok~] | — |
| SYS-06 启动耗时 | 读/structured | — | — | — |
| SYS-07 timers/计划任务总览 | 读/structured | `/etc/systemd/system :: *.timer` [ok~]<br>`/etc/cron.d :: *` [ok] | `/etc/systemd/system :: *.timer` [ok~]<br>`/etc/cron.d :: *` [ok] | — |
| SYS-08 unit 配置/drop-in | 读/raw | `/etc/systemd/system :: *.d/*.conf` [ok]<br>`/etc/systemd/system/aikernel-api.service` [ok] | `/etc/systemd/system :: *.d/*.conf` [ok]<br>`/etc/systemd/system/aikernel-api.service` [ok] | `write/edit unit 与 drop-in（不 daemon-reloa` [W2] |
| NET-01 接口/链路/网卡诊断 | 读/structured | `ip -j link` [ok]<br>`cat /sys/class/net/eth0/statistics/rx_bytes` [ok]<br>`/sys/class/net/eth0/operstate` [ok]<br>+1 | `/sys/class/net/eth0/operstate` [ok]<br>`/sys/class/net/eth0/statistics/rx_bytes` [ok] | `write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| NET-02 地址/路由 | 读/structured | `ip -j addr` [ok]<br>`ip -j route` [ok]<br>`cat /proc/net/route` [ok]<br>+1 | `/proc/net/route` [ok] | — |
| NET-03 连接/套接字 | 读/structured | `ss -tunl` [ok]<br>`cat /proc/net/tcp` [ok]<br>`/proc/net/tcp` [ok] | `/proc/net/tcp` [ok] | — |
| NET-04 conntrack 连接跟踪 | 读/structured | `cat /proc/net/nf_conntrack` [ok?]<br>`/proc/net/nf_conntrack` [ok?] | `/proc/net/nf_conntrack` [ok?] | — |
| NET-05 DNS 解析配置 | 读/structured | `cat /etc/resolv.conf` [ok]<br>`/etc/resolv.conf` [ok]<br>`nslookup 127.0.0.1` [ok] | `/etc/resolv.conf` [ok] | `edit /etc/resolv.conf` [W2] |
| NET-06 防火墙/LSM 策略 | 读/raw | `/etc/nftables.conf` [ok]<br>`/sys/kernel/security/apparmor/profiles` [ok?] | `/etc/nftables.conf` [ok] | `edit /etc/nftables.conf（只改持久化文件，不进运行时）` [W2] |
| NET-07 网络命名空间 | 读/structured | `/run/netns :: *` [ok~?] | `/run/netns :: *` [ok~?] | — |
| NET-08 接口配置/qdisc | 读/structured | `ip -d -j link` [ok]<br>`cat /sys/class/net/eth0/mtu` [ok]<br>`config_write_network action=show` [ok]<br>+1 | `config_write_network action=show` [ok]<br>`/etc/systemd/network/80-wired.network` [ok] | `config_write_network write/remove` [W2]<br>`write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| ID-01 用户账户 | 读/structured | `/etc/passwd` [ok] | `/etc/passwd` [ok] | — |
| ID-02 组/成员 | 读/structured | `/etc/group` [ok] | `/etc/group` [ok] | — |
| ID-03 登录会话 | 读/raw | `/proc/1/loginuid` [ok~] | `/proc/1/loginuid` [ok~] | — |
| ID-04 sudoers | 读/raw | `/etc/sudoers` [ok] | — | `edit /etc/sudoers（不经 visudo 校验）` [W2] |
| ID-05 授权策略/租约 | 读/structured | `/etc/aikernel/policy.conf` [ok]<br>`aikctl policy get` [ok]<br>`/var/lib/aikernel/leases :: *.json` [ok?]<br>+1 | `/etc/aikernel/policy.conf` [ok]<br>`/var/lib/aikernel/leases :: *.json` [ok?]<br>`/etc/aikernel/tools.json` [ok] | `edit /etc/aikernel/policy.conf` [W2] |
| ID-06 SSH 服务配置 | 读/structured | `/etc/ssh/sshd_config` [ok]<br>`/etc/ssh/sshd_config.d :: *` [ok] | `/etc/ssh/sshd_config` [ok]<br>`/etc/ssh/sshd_config.d :: *` [ok] | `edit /etc/ssh/sshd_config（不 reload sshd）` [W2] |
| ID-07 SSH authorized_keys | 读/raw | `/root/.ssh/authorized_keys` [ok] | — | `write $HOME/.ssh/authorized_keys（落在 $HOM` [W1] |
| ID-08 SSH 主机密钥状态 | 读/structured | `/etc/ssh :: ssh_host_*` [ok~]<br>`/etc/ssh/ssh_host_ed25519_key.pub` [ok] | `/etc/ssh :: ssh_host_*` [ok~]<br>`/etc/ssh/ssh_host_ed25519_key.pub` [ok] | — |
| PKG-01 已安装包 | 读/raw | `/var/lib/dpkg/status` [ok] | `/var/lib/dpkg/status` [ok] | — |
| PKG-02 仓库/源 | 读/raw | `/etc/apt/sources.list` [ok?]<br>`/etc/apt/sources.list.d :: *` [ok]<br>`/etc/apt/apt.conf.d/51-aik-upgrade-policy` [ok] | `/etc/apt/sources.list` [ok?]<br>`/etc/apt/sources.list.d :: *` [ok]<br>`/etc/apt/apt.conf.d/51-aik-upgrade-policy` [ok] | — |
| PKG-03 可用更新 | 读/raw | — | — | — |
| PKG-04 安装/卸载/升级 | 读/raw | — | — | — |
| PKG-05 依赖/版本/内核模块 | 读/raw | `/var/lib/dpkg/status` [ok]<br>`uname -r` [ok] | `/var/lib/dpkg/status` [ok] | — |
| HW-01 CPU 硬件 | 读/structured | `lscpu -J` [ok]<br>`/proc/cpuinfo` [ok] | `/proc/cpuinfo` [ok] | `write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| HW-02 GPU/显示 | 读/raw | `/sys/class/drm :: *` [ok?]<br>`cat /sys/class/drm/card0/status` [ok?] | `/sys/class/drm :: *` [ok?] | — |
| HW-03 温度/风扇 | 读/raw | `/sys/class/hwmon :: *` [ok?]<br>`cat /sys/class/thermal/thermal_zone0/temp` [ok?]<br>`cat /sys/class/hwmon/hwmon0/temp1_input` [ok?] | `/sys/class/hwmon :: *` [ok?] | — |
| HW-04 电源/电池 | 读/raw | `/sys/class/power_supply :: *` [ok?]<br>`cat /sys/class/power_supply/ACAD/online` [ok?] | `/sys/class/power_supply :: *` [ok?] | — |
| HW-05 PCI/USB/设备树 | 读/raw | `/sys/bus/pci/devices :: *` [ok]<br>`cat /sys/bus/pci/devices/0000:00:02.0/vendor` [ok]<br>`aikctl compat hw` [ok~] | `/sys/bus/pci/devices :: *` [ok] | — |
| AI-01 /proc/ai/status | 读/structured | `cat /proc/ai/status` [ok?]<br>`/proc/ai/status` [ok?] | `/proc/ai/status` [ok?] | `write /sys/kernel/ai/enabled` [W2] |
| AI-02 /proc/ai/control 参数表 | 读/structured | `cat /proc/ai/control` [ok?]<br>`/proc/ai/control` [ok?] | `/proc/ai/control` [ok?] | `POST http://127.0.0.1:8761/act（aikernel-` [W2] |
| AI-03 决策/因果链 | 读/structured | `cat /proc/ai/decisions` [ok?]<br>`cat /proc/ai/chains` [ok?]<br>`/proc/ai/decisions` [ok?] | `/proc/ai/decisions` [ok?] | — |
| AI-04 遥测/netlink SENSE | 读/structured | `cat /proc/ai/telemetry` [ok?]<br>`/proc/ai/telemetry` [ok?] | `/proc/ai/telemetry` [ok?] | `write /proc/ai/telemetry` [W2]<br>`write /proc/ai/telemetry` [W2] |
| AI-05 AI 统计计数 | 读/structured | `cat /proc/ai/hitrate` [ok?]<br>`cat /proc/ai/latency` [ok?]<br>`cat /sys/kernel/ai/stats/telemetry_emitted` [ok?]<br>+4 | `/proc/ai/hitrate` [ok?]<br>`/sys/kernel/ai/stats/telemetry_emitted` [ok?] | — |
| AI-06 内核模型加载/推理 | 读/structured | `cat /sys/kernel/ai/model_out` [ok?]<br>`cat /proc/ai/status` [ok?]<br>`/sys/kernel/ai/model_out` [ok?] | `/sys/kernel/ai/model_out` [ok?] | `write /sys/kernel/ai/model_load` [W2]<br>`write /sys/kernel/ai/model_unload` [W2] |
| AI-07 策略/回滚 | 读/structured | `cat /sys/kernel/ai/decision/stats` [ok?]<br>`cat /proc/ai/hitrate` [ok?]<br>`/sys/kernel/ai/decision/stats` [ok?] | `/sys/kernel/ai/decision/stats` [ok?] | `write /sys/kernel/ai/policy/global_enabl` [W2]<br>`write /sys/kernel/ai/policy/rollback` [W2] |
| AI-08 KUnit/内核测试 | 读/raw | `dmesg --color=never` [ok?] | — | — |
| MEM-01 SME 健康/统计 | 读/semantic | `curl -s http://127.0.0.1:8000/health` [ok?]<br>`curl -s http://127.0.0.1:8000/stats` [ok?] | — | — |
| MEM-02 记忆 CRUD/检索 | 读/semantic | `curl -s http://127.0.0.1:8000/export` [ok?]<br>`curl -s http://127.0.0.1:8000/memories/<id>` [ok?] | — | `POST /memories、DELETE /memories/<id>（cur` [W2] |
| MEM-03 事实图谱/多跳 | 读/semantic | `curl -s http://127.0.0.1:8000/graph` [ok?]<br>`curl -s http://127.0.0.1:8000/facts` [ok?] | — | — |
| MEM-04 Region 空间聚类 | 读/semantic | `curl -s http://127.0.0.1:8000/regions` [ok?] | — | `POST /regions/evolve` [W2] |
| MEM-05 QA/画像/指标/配置 | 读/semantic | `curl -s http://127.0.0.1:8000/qapairs` [ok?]<br>`curl -s http://127.0.0.1:8000/profile` [ok?]<br>`curl -s http://127.0.0.1:8000/metrics` [ok?]<br>+1 | — | — |
| MEM-06 trace JSONL 文件 | 读/structured | `/root/.occ/trace :: *.jsonl` [ok]<br>`/root/.occ/trace/<session>.jsonl` [ok] | `/home/admin/.occ/trace :: *.jsonl` [ok]<br>`/home/admin/.occ/trace/<session>.jsonl` [ok] | — |
| MEM-07 训练导出 | n/a（n/a） | — | — | — |
| MEM-08 会话历史 | 读/structured | — | — | — |
| SB-01 隔离区列表/状态/资源限额 | 读/structured | — | — | `write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| SB-02 沙箱资源限制 | 读/structured | — | — | `write/edit <sysfs/procfs 受控节点>（无受控前缀校验）` [W2] |
| SB-03 隔离区产物/残留 | 读/structured | `/var/ai/sandbox-artifacts :: *` [ok] | — | — |
| SB-04 spawn/destroy 生命周期 | 读/structured | — | — | — |
| SB-05 子智能体工具面/子会话 trace | 读/structured | `/usr/local/share/aikernel/tools-sandbox.json` [ok~] | `/usr/local/share/aikernel/tools-sandbox.json` [ok~] | — |
| DT-01 桌面健康/统计 | 读/semantic | `curl -s http://127.0.0.1:8091/api/health` [ok?]<br>`curl -s http://127.0.0.1:8091/api/stats` [ok?] | — | — |
| DT-02 应用枚举/启动/关闭 | 读/semantic | `curl -s http://127.0.0.1:8091/api/apps` [ok?] | — | `POST /api/apps/launch\|close` [W2] |
| DT-03 窗口 | 读/structured | `curl -s http://127.0.0.1:8091/api/windows` [ok?] | — | `POST /api/windows/focus\|close` [W2] |
| DT-04 主题/壁纸 | 读/semantic | `curl -s http://127.0.0.1:8091/api/theme` [ok?]<br>`curl -s http://127.0.0.1:8091/api/wallpaper` [ok?] | — | `POST /api/theme\|/api/wallpaper` [W2] |
| DT-05 通知 | 读/semantic | `curl -s http://127.0.0.1:8091/api/notifs` [ok?] | — | `POST /api/notifs` [W2] |
| DT-06 输入注入（键鼠） | n/a（n/a） | — | — | — |
| DT-07 截图 | 读/structured | `curl -s http://127.0.0.1:8091/api/screenshot` [ok?] | — | — |
| DT-08 剪贴板 | 读/structured | `curl -s http://127.0.0.1:8091/api/clipboard` [ok?] | — | `POST /api/clipboard` [W2] |
| DT-09 聊天/会话/电源 | 无读面 | `curl -s http://127.0.0.1:8091/api/chat/history` [ok?]<br>`curl -s http://127.0.0.1:8091/api/chat/sessions` [ok?] | — | `POST /api/chat` [W2] |
| TIME-01 时钟/NTP | 读/structured | `date` [ok~]<br>`/run/systemd/timesync :: synchronized` [ok?] | `/run/systemd/timesync :: synchronized` [ok?] | — |
| TIME-02 用户 crontab | 读/raw（n/a） | — | — | — |
| TIME-03 系统 cron/timers | 读/structured | `/etc/cron.d :: *` [ok]<br>`/etc/systemd/system :: *.timer` [ok~]<br>`/etc/crontab` [ok?] | `/etc/cron.d :: *` [ok]<br>`/etc/systemd/system :: *.timer` [ok~]<br>`/etc/crontab` [ok?] | `edit /etc/crontab` [W2] |

## 4. 旧口径的原始文本（raw）对象在出厂视角下的状况

| 对象 | 旧级别 | 出厂 root | 出厂 admin | 出厂读面 |
|---|---|---|---|---|
| PROC-01 进程枚举与属性 | raw | 读/raw（仅部分） | 读/raw（仅部分） | `/proc :: *` [ok~]<br>`/proc/1/status` [ok~] |
| PROC-02 线程 | raw | 读/raw | 读/raw | `/proc/1 :: task/*` [ok]<br>`/proc/1/status` [ok] |
| FS-01 文件内容读取 | raw | 读/raw | 读/raw | `/etc/hostname` [ok] |
| FS-04 文件写入/编辑 | raw | 读/raw | 读/raw | `/etc/hostname` [ok] |
| FS-08 文件属性 chattr/lsattr | raw | 读/raw（仅部分） | 不可达 | `lsattr /usr/local/bin/occ` [ok~] |
| SYS-04 内核日志/dmesg | raw | 读/raw（依赖运行态） | 不可达 | `dmesg --color=never` [ok?] |
| SYS-08 unit 配置/drop-in | raw | 读/raw | 读/raw | `/etc/systemd/system :: *.d/*.conf` [ok]<br>`/etc/systemd/system/aikernel-api.service` [ok] |
| NET-06 防火墙/LSM 策略 | raw | 读/raw | 读/raw | `/etc/nftables.conf` [ok]<br>`/sys/kernel/security/apparmor/profiles` [ok?] |
| ID-03 登录会话 | raw | 读/raw（仅部分） | 读/raw（仅部分） | `/proc/1/loginuid` [ok~] |
| ID-04 sudoers | raw | 读/raw | 不可达 | `/etc/sudoers` [ok] |
| ID-07 SSH authorized_keys | raw | 读/raw | 不可达 | `/root/.ssh/authorized_keys` [ok] |
| PKG-01 已安装包 | raw | 读/raw | 读/raw | `/var/lib/dpkg/status` [ok] |
| PKG-02 仓库/源 | raw | 读/raw | 读/raw | `/etc/apt/sources.list` [ok?]<br>`/etc/apt/sources.list.d :: *` [ok]<br>+1 |
| PKG-03 可用更新 | raw | 不可达 | 不可达 | — |
| PKG-04 安装/卸载/升级 | raw | 不可达 | 不可达 | — |
| PKG-05 依赖/版本/内核模块 | raw | 读/raw | 读/raw | `/var/lib/dpkg/status` [ok]<br>`uname -r` [ok] |
| HW-02 GPU/显示 | raw | 读/raw（依赖运行态） | 读/raw（依赖运行态） | `/sys/class/drm :: *` [ok?]<br>`cat /sys/class/drm/card0/status` [ok?] |
| HW-03 温度/风扇 | raw | 读/raw（依赖运行态） | 读/raw（依赖运行态） | `/sys/class/hwmon :: *` [ok?]<br>`cat /sys/class/thermal/thermal_zone0/temp` [ok?]<br>+1 |
| HW-04 电源/电池 | raw | 读/raw（依赖运行态） | 读/raw（依赖运行态） | `/sys/class/power_supply :: *` [ok?]<br>`cat /sys/class/power_supply/ACAD/online` [ok?] |
| HW-05 PCI/USB/设备树 | raw | 读/raw | 读/raw | `/sys/bus/pci/devices :: *` [ok]<br>`cat /sys/bus/pci/devices/0000:00:02.0/vendor` [ok]<br>+1 |
| AI-08 KUnit/内核测试 | raw | 读/raw（依赖运行态） | 不可达 | `dmesg --color=never` [ok?] |

## 5. 33 个登记缺口的归类

| 归类 | 条数 | 含义 |
|---|---:|---|
| unreachable | 5 | 有读工具但对出厂 AI 不可达（名下一等读工具全部没有等价读面） |
| mostly-unreachable | 4 | 缺口名下的一等读工具过半在出厂没有等价读面 |
| partly-unreachable | 2 | 缺口名下的一等读工具有少数在出厂没有等价读面 |
| reachable | 12 | 出厂可达且级别不降 |
| file-only | 10 | 缺口名下对象没有一等读工具（只有文件/逃逸/Principal 记号） |

归类按缺口名下对象的一等读工具（旧记号 `tool:`/`cmd:`）逐件看在出厂 root 视角下有没有等价读面：ok=有；partial=只见一部分；cond=依赖运行态；no=没有。

**有读工具但对出厂 AI 不可达**（一等读工具全部或过半没有出厂等价读面）：G-008、G-009、G-010、G-016、G-021、G-022、G-025、G-026、G-028。

| 缺口 | 优先级 | 一等读工具[出厂是否有等价] | 对象逐项（旧 → 出厂 root） | 归类 |
|---|---|---|---|---|
| G-008 SMART/磁盘健康 | P1 | smartctl[no] | DISK-03 无读面→不可达 | unreachable |
| G-009 包管理状态/仓库 | P1 | dpkg[no] | PKG-01 读/raw→读/raw；PKG-02 读/raw→读/raw；PKG-04 读/raw→不可达 | unreachable |
| G-010 可用更新 | P1 | apt[no] | PKG-03 读/raw→不可达 | unreachable |
| G-016 沙箱子会话 trace | P1 | sandbox_status[no] | SB-05 读/structured→读/structured | unreachable |
| G-025 登录会话 | P2 | ps[no] | ID-03 读/raw→读/raw | unreachable |
| G-021 AppArmor/LSM 状态 | P2 | aa-status[no]、config_read_nftables[ok] | NET-06 读/raw→读/raw | mostly-unreachable |
| G-022 包依赖/版本 | P2 | dpkg[no]、uname[ok] | PKG-05 读/raw→读/raw | mostly-unreachable |
| G-026 cron | P2 | ls[partial]、systemctl[no] | TIME-03 读/structured→读/raw | mostly-unreachable |
| G-028 防火墙运行时规则 | P2 | aa-status[no]、config_read_nftables[ok] | NET-06 读/raw→读/raw | mostly-unreachable |
| G-003 trace/训练导出/会话 | P1 | cat[partial] | MEM-06 读/structured→读/structured；MEM-08 读/structured→不可达 | partly-unreachable |
| G-019 网卡链路诊断 | P2 | ethtool[no]、ip[ok]、sysfs_get[partial] | NET-01 读/structured→读/structured | partly-unreachable |
| G-011 systemd unit 配置/drop-in | P1 | cat[partial] | SYS-08 读/raw→读/raw | reachable |
| G-012 sudoers/policy | P1 | cat[partial] | ID-04 读/raw→读/raw；ID-05 读/structured→读/structured | reachable |
| G-013 SSH 密钥 | P1 | ls[partial]、stat[partial] | ID-07 读/raw→读/raw；ID-08 读/structured→读/raw | reachable |
| G-014 PSI | P1 | procfs_read_pressure_cpu[ok]、procfs_read_pressure_io[ok]、procfs_read_pressure_memory[ok] | RES-05 读/structured→读/structured | reachable |
| G-001 租约/授权（W74 已落地；残余硬化） | P2 | cat[partial] | ID-05 读/structured→读/structured | reachable |
| G-017 KUnit/测试结果 | P2 | dmesg[ok] | AI-08 读/raw→读/raw | reachable |
| G-018 LVM | P2 | lsblk[ok]、sysfs_get[partial] | DISK-04 读/structured→读/structured | reachable |
| G-020 conntrack 用户态工具 | P2 | procfs_read_net_nf_conntrack[ok] | NET-04 读/structured→读/structured | reachable |
| G-023 硬件清单/传感器 | P2 | ls[partial]、sysfs_get[partial] | HW-02 读/raw→读/raw；HW-03 读/raw→读/raw；HW-05 读/raw→读/raw | reachable |
| G-029 /proc/ai/control 参数 | P2 | procfs_read_control[ok] | AI-02 读/structured→读/structured | reachable |
| G-027 设备树 | P3 | ls[partial]、sysfs_get[partial] | HW-05 读/raw→读/raw | reachable |
| G-034 命名空间 | P3 | ip[ok] | NET-07 读/structured→读/raw | reachable |
| G-004 文件 ACL | P1 | （无） | （无适用读面对象） | file-only |
| G-005 文件 xattr | P1 | （无） | （无适用读面对象） | file-only |
| G-006 文件属性 chattr/lsattr | P1 | （无） | FS-08 读/raw→读/raw | file-only |
| G-007 磁盘配额 | P1 | （无） | （无适用读面对象） | file-only |
| G-024 文件完整性/校验和 | P2 | （无） | （无适用读面对象） | file-only |
| G-032 全局 | P2 | （无） | （无适用读面对象） | file-only |
| G-036 语义化覆盖（全局） | P2 | （无） | （无适用读面对象） | file-only |
| G-030 文档/注册表漂移 | P3 | （无） | （无适用读面对象） | file-only |
| G-031 能力探测 | P3 | （无） | （无适用读面对象） | file-only |
| G-033 桌面电源 | P3 | （无） | DT-09 无读面→读/structured | file-only |

## 6. occ 十件工具逐件

| 工具 | 风险 | 执行面 | 输出 | 能触达什么 | 确认门 | 依据 |
|---|---|---|---|---|---|---|
| read | R | 宿主 | 带行号文本 | 任意可读文件；无路径域限制；单文件 ≤4MB、含 NUL 拒读、默认 500 行/次、结果截 8KB | 免确认 | tools.c:750-815,496-574；occ_tools.h:84-85 |
| glob | R | 宿主 | 路径清单 | 任意可读目录；≤200 项、深度 24、无元数据 | 免确认 | tools.c:1159-1161,1234-1347 |
| grep | R | 宿主 | 文件:行号:行 | 任意可读文件/目录；朴素字节子串；≤100 行、单文件 ≤4MB、二进制跳过 | 免确认 | tools.c:1351-1352,1417-1456 |
| bash | W1/W2 | 沙箱 | stdout+stderr 合流 + [exit=N] | 仅沙箱视图；采集 ≤1MB、截 8KB、默认 60s；一调用一区 | W1 免确认；W2 root 控制台需确认，admin/API 拒绝 | occ_tools/sandbox.c:18-22,403-601；occ_tools/tools.c:3422-3564,3591-3596,3712-3740 |
| write | W1/W2 | 宿主 | 一句结果文本 | 目标域=工作目录∪/tmp∪/var/ai∪$HOME（越界 W2；~/.occ 恒拒）；≤512KB；写前快照 | 域内免确认；越界同 W2 规则 | tools.c:447-471,845-867,869-928 |
| edit | W1/W2 | 宿主 | 一句结果文本 | 同 write 域；oldString 唯一命中或 replaceAll；写前快照 | 同 write | tools.c:932-1045 |
| rm | W1/W2 | 宿主 | 一句结果文本 | 同 write 域；仅普通文件与空目录；不落快照 | 同 write | tools.c:1049-1088 |
| mv | W1/W2 | 宿主 | 一句结果文本 | 两端同 write 域；不覆盖已有目标、跨设备报错 | 同 write | tools.c:1090-1131 |
| mkdir | W1/W2 | 宿主 | 一句结果文本 | 同 write 域；-p 语义 | 同 write | tools.c:1133-1155 |
| config_write_network | R/W2 | 宿主 | show=关键行清单；write/remove=结果+生效指引 | 固定写 /etc/systemd/network/70-static-<iface>.network；出厂置位才注册 | show 免确认；write/remove 恒 W2 | tools.c:253-314,2967-3115,3632-3643；aik-console:155-157,203；aikernel-api.service:12 |

- `read` 的路径限制现状：**没有路径域限制**（只在 `occ_write_target_ok`/`w2_path_safe` 里管写面）；上限是单文件 4MB、含 NUL 拒读、默认 500 行/次、结果截 8KB。root 身份下这意味着 /etc/shadow、SSH 私钥、/etc/aikernel/api-token 等凭据文件在结构上都读得到。
- 宿主工具与沙箱看到的是两套文件系统，只有 bash 的工作目录是共享的（`--rw-path`）：`write /tmp/x` 写的是宿主 /tmp，`bash cat /tmp/x` 看的是沙箱里的空 tmpfs。
- `write` 的域含整个 $HOME：root 身份下 $HOME=/root，写 /root/.bashrc、/root/.ssh/authorized_keys 都是 W1（免确认）。
- `bash` 的退出码歧义（AIF-09 夹具确认）：aik-sandbox 把沙箱内命令的退出码原样透传（aik-sandbox.c:107-108），而 occ 把 exit=1/2 一律当成「bash 沙箱执行失败」并把工具 rc 置 -1（occ_tools/sandbox.c:570-575）——`grep` 无匹配、`systemctl`、`ss` 等一切返回 1 的命令都会被记成工具错误；两条路径在 occ 侧无法区分。

## 7. 沙箱内命令可达表（静态推断，共 141 条）

判定：ok=能跑且拿到宿主真实数据；partial=能跑但只见沙箱自身/一部分；no=跑不起来或拿不到宿主数据。

| 命令 | 只读样例 | 判定 | 形态 | 原因 | 依据 |
|---|---|---|---|---|---|
| aa-complain | `aa-complain --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| aa-disable | `aa-disable --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| aa-enforce | `aa-enforce --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| aa-status | `aa-status --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| aik-backup | `aik-backup --dry-run` | no | raw | 依赖 /var/backups、/var/lib/aikernel（沙箱视图外） | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录）；推断（静态求值，未在沙箱内实测） |
| aik-reset | `aik-reset --help` | no | raw | 写面工具，不属于读面 | 推断（静态求值，未在沙箱内实测） |
| aik-sandbox | `aik-sandbox status` | no | structured | 宿主 /sandbox 不在沙箱视图 → 恒「尚无隔离区」 | aik-sandbox.c:2701-2818 |
| aik-upgrade | `aik-upgrade status` | no | raw | 依赖 /boot/aik-slot-state、/boot/grub、/var/log/aik-upgrade.log（均在沙箱视图外） | aik-sandbox.c:826-829；aik-upgrade:51-53 |
| aikctl | `aikctl policy get --json` | ok | structured | python3 在 /usr 只读面；逐子命令依赖见 §8 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| apparmor_status | `apparmor_status --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| apt | `apt list --installed` | no | structured | /var/lib/dpkg、/var/lib/apt、/etc/apt 缺 | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录）；aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| arping | `arping -c 1 127.0.0.1` | ok | raw | CAP_NET_RAW 在能力集内 | aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS） |
| blkid | `blkid -o export` | no | structured | 无块设备节点 | aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]） |
| bootctl | `bootctl status` | no | structured | /boot 不在沙箱视图 | aik-sandbox.c:826-829 |
| cat | `cat /proc/meminfo` | partial | structured | 只见沙箱视图（/usr、/etc 白名单、/proc、/sys、工作区）；宿主 /etc /var /root /home 不可见；/proc、/sys 全局节点可读 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| cc | `cc --version` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin 列表 |
| chmod | `chmod 644 /tmp/f` | partial | raw | 只能写沙箱 tmpfs（/tmp、工作区、产物区），退出即焚；世界可写模式判 W2 | aik-sandbox.c:2111-2114 |
| chown | `chown 0:0 /tmp/f` | no | raw | 无 CAP_CHOWN；递归形态判 W2 | aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS） |
| conntrack | `conntrack -L` | no | structured | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin 列表 |
| cp | `cp /etc/hosts /tmp/h` | partial | raw | 只能写沙箱 tmpfs（/tmp、工作区、产物区），退出即焚 | aik-sandbox.c:2111-2114 |
| crontab | `crontab -l` | no | raw | /var/spool/cron/crontabs 缺，且按用户名找 spool 要 /etc/passwd | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录）；aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| ctstat | `ctstat` | ok | structured | /proc/net/stat/nf_conntrack 全局 | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| curl | `curl -s -m 5 http://127.0.0.1:8000/health` | ok | structured | 宿主网络 + 根证书在白名单；-d/-T/-F/-o/-O 等形态判 W2 | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络）；aik-sandbox.c:2166-2187,2196-2216（/etc 白名单 + /etc/aikernel 整目录 + awk/which 链修复）；tools.c:3536-3561 |
| cut | `cut -d: -f1 /proc/meminfo` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| date | `date +%s` | partial | raw | 时钟全局正确；/etc/localtime 不在白名单 → 时区恒 UTC | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| df | `df -P` | partial | structured | 只见沙箱挂载点；/usr 是宿主根分区的 bind → 其容量/用量可见，宿主其余挂载不可见 | aik-sandbox.c:2120-2156 |
| dmesg | `dmesg --color=never` | ok | raw | /dev/kmsg 不在白名单 → util-linux 回退 klogctl(2)；kernel.dmesg_restrict=0 时无需 CAP_SYSLOG。出厂树 etc/sysctl.d/10-kernel-hardening.conf 未改该项（:23-25 注释掉，基础镜像件）；AIKernel 内核树 .config 未设 CONFIG_SECURITY_DMESG_RESTRICT（默认 0）；L1 的 Ubuntu 内核是 1——须真机核 /proc/sys/kernel/dmesg_restrict | aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]）；推断（静态求值，未在沙箱内实测） |
| dpkg | `dpkg-query -W` | no | structured | /var/lib/dpkg/status 缺 | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| dpkg-query | `dpkg-query -W` | no | structured | /var/lib/dpkg/status 缺 | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| dpkg-query | `dpkg-query -W` | no | structured | /var/lib/dpkg/status 缺 | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| dpkg-query | `dpkg-query -W` | no | structured | /var/lib/dpkg/status 缺 | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| du | `du -x -d1 /var` | no | structured | 宿主目录不可见（/var 为空） | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| dumpe2fs | `dumpe2fs -h /dev/sda1` | no | structured | 无块设备节点 | aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]） |
| echo | `echo ok` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| ethtool | `ethtool eth0` | no | structured | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin 列表 |
| fdisk | `fdisk -l` | no | structured | 无块设备节点；且 W2 硬表 | aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]）；tools.c:3424-3430（首 token 命中 W2 硬表） |
| find | `find /sys/class/net -maxdepth 1` | partial | raw | 只见沙箱视图（/usr、/etc 白名单、/proc、/sys、工作区）；宿主 /etc /var /root /home 不可见 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| findmnt | `findmnt -J` | partial | structured | 只列沙箱自己的挂载表 | aik-sandbox.c:2089-2304 |
| free | `free -b` | ok | structured | /proc/meminfo 全局；固定列输出 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| fstrim | `fstrim -v /` | no | structured | 需设备节点与 CAP_SYS_ADMIN | aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]）；aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS） |
| gcc | `gcc --version` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin 列表 |
| getent | `getent passwd` | no | structured | 无 /etc/passwd、/etc/group | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| grep | `grep -c Mem /proc/meminfo` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| groupadd | `groupadd x` | no | raw | 同 useradd（无 /etc/group、/etc/login.defs） | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| groupdel | `groupdel x` | no | raw | 同 groupadd | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| groupmod | `groupmod -n y x` | no | raw | 同 groupadd | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| gzip | `gzip -c /etc/hosts > /tmp/h.gz` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| head | `head -n 5 /proc/meminfo` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| hostname | `hostname` | partial | raw | UTS namespace：sethostname(区名)，不是宿主名 | aik-sandbox.c:2832,2307-2309 |
| hostnamectl | `hostnamectl` | no | structured | 走 systemd 私有 socket / D-Bus（/run 缺） | aik-sandbox.c:824-859（根骨架无 /run） |
| id | `id` | no | raw | 无 /etc/passwd、/etc/group → 名字解析全失败 | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| ifconfig | `ifconfig -a` | ok | structured | SIOCGIFCONF 读，无需能力（busybox） | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| ip | `ip -j addr` | ok | structured | netlink RTM_GET* 无需能力；宿主网络保留；写操作需 CAP_NET_ADMIN → EPERM | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络）；aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS） |
| journalctl | `journalctl -n 20 --no-pager` | no | structured | /var/log/journal、/run/journal 缺 | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录）；aik-sandbox.c:824-859（根骨架无 /run） |
| kill | `kill -0 1` | no | raw | 同 ps（沙箱内 1 号是 sh 自己）；且 W2 硬表 | aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程）；tools.c:3424-3430（首 token 命中 W2 硬表） |
| last | `last -n 5` | no | structured | /var/log/wtmp 缺 | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| ln | `ln -s /etc/hosts /tmp/h` | partial | raw | 只能写沙箱 tmpfs（/tmp、工作区、产物区），退出即焚 | aik-sandbox.c:2111-2114 |
| lnstat | `lnstat -c 1` | ok | structured | /proc/net/stat/lnstat 全局 | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| localectl | `localectl status` | no | raw | 走 systemd 私有 socket / D-Bus（/run 缺） | aik-sandbox.c:824-859（根骨架无 /run） |
| loginctl | `loginctl list-sessions` | no | structured | 走 systemd 私有 socket / D-Bus（/run 缺） | aik-sandbox.c:824-859（根骨架无 /run） |
| ls | `ls /sys/class/net` | partial | raw | 只见沙箱视图（/usr、/etc 白名单、/proc、/sys、工作区）；宿主 /etc /var /root /home 不可见 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| lsattr | `lsattr /usr/local/bin/occ` | partial | raw | 只见沙箱视图（/usr、/etc 白名单、/proc、/sys、工作区）；宿主 /etc /var /root /home 不可见 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| lsblk | `lsblk -J` | ok | structured | /sys/block + /proc/partitions 全局；udev 库 /run/udev 缺 → 少 vendor/serial 等细节 | aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见）；aik-sandbox.c:824-859（根骨架无 /run） |
| lscpu | `lscpu -J` | ok | structured | /sys/devices/system/cpu + /proc/cpuinfo | aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见）；aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| lsipc | `lsipc` | ok | structured | /proc/sysvipc/*（未隔离 IPC namespace） | aik-sandbox.c:2832 |
| lslocks | `lslocks` | no | structured | /proc/locks 按读取端 procfs 所属的 PID 命名空间过滤：属主进程不在本命名空间就不显示 → 沙箱里列得出的是沙箱自己进程的锁，宿主进程的锁看不见（AIF-01b 出厂机实测 rc=0 零字节后更正，原判 ok） | aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程）；linux-6.18.39 fs/locks.c:2892-2898（locks_show） |
| lslogins | `lslogins` | no | structured | /var/log/wtmp、/var/run/utmp 缺 | aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录）；aik-sandbox.c:824-859（根骨架无 /run） |
| lsmem | `lsmem` | no | structured | 出厂内核 .config 未设 CONFIG_MEMORY_HOTPLUG → 没有 /sys/devices/system/memory；宿主上同样没有，不是沙箱挡的（AIF-01b 出厂机实测 rc=1 后更正，原判 ok） | .config（# CONFIG_MEMORY_HOTPLUG is not set）；linux-6.18.39 drivers/base/Makefile（memory.o 仅在该选项下编译） |
| lsns | `lsns` | no | structured | /proc/<pid>/ns 只见沙箱 pid；/run/netns 缺 | aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程）；aik-sandbox.c:824-859（根骨架无 /run） |
| lvs | `lvs --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| mkdir | `mkdir -p /tmp/d` | partial | raw | 只能写沙箱 tmpfs（/tmp、工作区、产物区），退出即焚 | aik-sandbox.c:2111-2114 |
| mount | `mount` | partial | structured | 不带参数的 mount 只列挂载表（读操作，不需能力）：只见沙箱自己的挂载表，同 findmnt；挂载/卸载动作才需 CAP_SYS_ADMIN；首 token 命中 W2 硬表（AIF-01b 出厂机实测 rc=0 后更正，原判 no） | aik-sandbox.c:2089-2304；tools.c:3424-3430（首 token 命中 W2 硬表） |
| mv | `mv /tmp/a /tmp/b` | partial | raw | 只能写沙箱 tmpfs（/tmp、工作区、产物区），退出即焚 | aik-sandbox.c:2111-2114 |
| nc | `nc -z -w 2 127.0.0.1 22` | ok | raw | TCP 连接探针，无需能力（busybox） | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| netstat | `netstat -tunl` | ok | structured | /proc/net/*（busybox） | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| networkctl | `networkctl status` | no | structured | systemd-networkd 私有 socket（/run 缺） | aik-sandbox.c:824-859（根骨架无 /run） |
| nft | `nft list ruleset` | no | structured | NETLINK_NETFILTER 全部请求需 CAP_NET_ADMIN；且 W2 硬表 | aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS）；tools.c:3424-3430（首 token 命中 W2 硬表） |
| nslookup | `nslookup 127.0.0.1` | ok | raw | /etc/resolv.conf 在 /etc 白名单 | aik-sandbox.c:2166-2187,2196-2216（/etc 白名单 + /etc/aikernel 整目录 + awk/which 链修复） |
| nstat | `nstat -az` | ok | structured | /proc/net/snmp、netstat、stat/* 全局计数 | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| occ | `occ --help` | ok | raw | 可在沙箱内嵌套起 occ（model.toml/provider.toml 被拷入 /root/.aikernel） | aik-sandbox.c:2260-2270 |
| ollama | `ollama list` | ok | structured | 客户端走 127.0.0.1:11434（宿主网络保留） | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络）；推断（静态求值，未在沙箱内实测） |
| passwd | `passwd -S root` | no | structured | 无 /etc/passwd、/etc/shadow 与 PAM 配置 | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| pgrep | `pgrep -a sshd` | no | raw | 同 ps | aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| pidof | `pidof systemd` | no | raw | 同 ps | aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| ping | `ping -c 2 127.0.0.1` | ok | raw | 能力集保留 CAP_NET_RAW | aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS） |
| pkill | `pkill systemd` | no | raw | 同 ps；且 W2 硬表 | aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程）；tools.c:3424-3430（首 token 命中 W2 硬表） |
| printf | `printf ok` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| ps | `ps -eo pid,ppid,stat,comm` | no | raw | 宿主进程不可见（只见 sh 与 ps 自己） | aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| pvs | `pvs --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| python3 | `python3 -c 'print(1)'` | ok | raw | 任意代码，但受沙箱视图与能力集约束 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| quota | `quota --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| repquota | `repquota --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| resolvectl | `resolvectl status` | no | structured | systemd-resolved 私有 socket（/run 缺） | aik-sandbox.c:824-859（根骨架无 /run） |
| rm | `rm /tmp/f` | partial | raw | 只能写沙箱 tmpfs（/tmp、工作区、产物区），退出即焚；-r/-f 递归形态判 W2 | aik-sandbox.c:2111-2114 |
| route | `route -n` | ok | structured | /proc/net/route（busybox） | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| rtstat | `rtstat` | ok | structured | /proc/net/stat/rt_cache 全局 | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| sed | `sed -n 1,3p /proc/meminfo` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| setquota | `setquota --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| sha256sum | `sha256sum /etc/aikernel/policy.conf` | partial | raw | 只能算沙箱可见树的文件 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| slabtop | `slabtop -o -s c` | ok | structured | /proc/slabinfo（uid 0 属主可读） | 推断（静态求值，未在沙箱内实测） |
| smartctl | `smartctl -a /dev/sda` | no | structured | 无块设备节点；直读盘还要 CAP_SYS_RAWIO/CAP_SYS_ADMIN | aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]）；aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS） |
| sort | `sort /proc/meminfo` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| ss | `ss -tunl` | ok | structured | /proc/net/* + sock_diag；-p 的进程名要遍历宿主 /proc/<pid>/fd → 进程列恒空 | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络）；aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| sshd | `sshd -T` | no | structured | 要 /etc/ssh/sshd_config 与主机密钥（均不在白名单） | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| stat | `stat /usr/local/bin/occ` | partial | structured | 只见沙箱视图（/usr、/etc 白名单、/proc、/sys、工作区）；宿主 /etc /var /root /home 不可见 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| strace | `strace -c true` | partial | raw | 只能跟踪沙箱内自己起的进程 | aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| swapoff | `swapoff -a` | no | structured | 需 CAP_SYS_ADMIN；且 W2 硬表 | aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS）；tools.c:3424-3430（首 token 命中 W2 硬表） |
| swapon | `swapon --show` | ok | structured | --show 读 /proc/swaps（全局节点）列已启用的 swap，不需能力；swapon/swapoff 动作才需 CAP_SYS_ADMIN；首 token 命中 W2 硬表（AIF-01b 出厂机实测 rc=0、读到宿主 swap 清单后更正，原判 no） | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读）；tools.c:3424-3430（首 token 命中 W2 硬表） |
| sync | `sync` | ok | raw | sync(2) 不需能力（全局副作用） | 推断（静态求值，未在沙箱内实测） |
| sysctl | `sysctl -a` | ok | structured | /proc/sys 只读可读；写因只读挂载 + 无 CAP_SYS_ADMIN 失败 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| systemctl | `systemctl list-units --no-pager` | no | structured | 走 systemd 私有 socket / D-Bus（/run 缺） | aik-sandbox.c:824-859（根骨架无 /run） |
| systemd-analyze | `systemd-analyze time` | no | raw | time/blame 要连 systemd manager | 走 systemd 私有 socket / D-Bus（/run 缺） |
| systemd-cgls | `systemd-cgls --no-pager` | no | structured | /sys/fs/cgroup 在新 sysfs 里是空目录（cgroup2 是独立文件系统，沙箱内未挂） | aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| systemd-cgtop | `systemd-cgtop -n 1` | no | structured | 同 systemd-cgls | aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| systemd-detect-virt | `systemd-detect-virt` | ok | raw | CPUID / /sys/class/dmi，不需 manager | aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| tail | `tail -n 5 /proc/meminfo` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| tar | `tar -cf /tmp/t.tar /etc/hosts` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| tc | `tc -j qdisc show` | ok | structured | netlink RTM_GETQDISC 读无需能力；写需 CAP_NET_ADMIN | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络）；aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS） |
| tee | `cat /proc/meminfo \| tee /tmp/m` | ok | raw | 只能写沙箱 tmpfs（/tmp、工作区、产物区），退出即焚 | aik-sandbox.c:2111-2114 |
| timedatectl | `timedatectl show` | no | structured | 走 systemd 私有 socket / D-Bus（/run 缺） | aik-sandbox.c:824-859（根骨架无 /run） |
| top | `top -b -n 1` | partial | raw | 能跑：汇总行（时间/运行时长/负载/CPU/内存/swap）取自 /proc 全局节点，是宿主数据；进程表只见沙箱自己（同 ps）；用户数因无 utmp 恒为 0（AIF-01b 出厂机实测 rc=0 后更正，原判 no） | aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程）；aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读）；aik-sandbox.c:824-859（根骨架无 /run） |
| touch | `touch /tmp/f` | partial | raw | 只能写沙箱 tmpfs（/tmp、工作区、产物区），退出即焚 | aik-sandbox.c:2111-2114 |
| traceroute | `traceroute -n -m 5 127.0.0.1` | ok | raw | busybox 版走 UDP 探针，无需能力 | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| udevadm | `udevadm info /sys/class/net` | no | raw | /run/udev/control 缺 | aik-sandbox.c:824-859（根骨架无 /run） |
| umount | `umount /x` | no | structured | 需 CAP_SYS_ADMIN；且 W2 硬表 | aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS）；tools.c:3424-3430（首 token 命中 W2 硬表） |
| uname | `uname -r` | ok | raw | 内核信息全局；-n 是沙箱区名（UTS 隔离） | aik-sandbox.c:2307-2309 |
| uniq | `sort /proc/meminfo \| uniq -c` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| uptime | `uptime` | ok | raw | /proc/uptime、/proc/loadavg 为全局节点 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| useradd | `useradd -D` | no | raw | 无 /etc/passwd、/etc/login.defs | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| userdel | `userdel x` | no | raw | 同 useradd | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| usermod | `usermod -L x` | no | raw | 同 useradd | aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| vgs | `vgs --help` | no | raw | 出厂树 usr/bin、usr/sbin、usr/local/bin 均无此二进制 | 出厂树 usr/bin、usr/sbin 列表 |
| vmstat | `vmstat 1 2` | ok | structured | /proc/stat、/proc/meminfo、/proc/vmstat 全局 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| vmstat -d | `vmstat -d` | ok | structured | /proc/diskstats 全局 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| w | `w -h` | no | structured | /var/run/utmp 缺 | aik-sandbox.c:824-859（根骨架无 /run） |
| wc | `wc -l /proc/meminfo` | ok | raw | 通用文本工具，对管道与沙箱可见文件可用 | aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| wdctl | `wdctl` | no | raw | 无 /dev/watchdog 节点 | aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]） |
| wget | `wget -q -O - http://127.0.0.1:8000/health` | ok | raw | 同 curl；-O 判 W2 | aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络）；tools.c:3547-3551 |
| whereis | `whereis ls` | ok | raw | 只查 PATH 与固定目录 | aik-sandbox.c:2155（/usr 只读 bind，非递归） |
| which | `which awk` | ok | raw | /etc/alternatives/which 链被单文件 bind 修复 | aik-sandbox.c:2166-2187,2196-2216（/etc 白名单 + /etc/aikernel 整目录 + awk/which 链修复） |
| who | `who` | no | structured | /var/run/utmp 缺 | aik-sandbox.c:824-859（根骨架无 /run） |

旧注册表 exec 白名单 99 条命令 × 出厂沙箱：ok 31 / partial 16 / no 52。

## 8. aikctl 读类子命令在沙箱内的可达性

| 子命令 | 判定 | 形态 | 原因 | 依据 |
|---|---|---|---|---|
| `aikctl abi` | no | raw | NETLINK_AI socket 要 CAP_SYS_ADMIN | aikctl:1080-1124 |
| `aikctl aipd status` | no | structured | /run/aipd.stats、/var/lib/aikernel/aipd 缺 | aikctl:3420-3423 |
| `aikctl audit export` | ok | structured | 逐节点读 /proc/ai/audit → jsonl 到 stdout | aikctl:572-587 |
| `aikctl audit status` | ok | structured | 读 /proc/ai/audit 首行 + /sys/kernel/ai/chain/*（全局节点） | aikctl:668-679 |
| `aikctl audit tail` | no | raw | ~/.aikernel/audit.log 不在沙箱（/root 只有两份 toml 拷贝） | aikctl:5259-5265 |
| `aikctl compat hw` | partial | structured | /sys/bus/pci\|usb、/sys/kernel/iommu_groups 可见；/dev/dri 缺 | aikctl:2014-2069 |
| `aikctl module list` | no | structured | /var/lib/aikernel/module 缺 | aikctl:2235,2444-2462 |
| `aikctl policy get` | ok | structured | /etc/aikernel 整目录在 /etc 白名单；但 /etc/passwd、/etc/group 缺 → 「每人生效档推演」拿不到 uid 与组成员 | aikctl:4610-4656,4588-4607 |
| `aikctl policy get sudoers` | no | structured | /etc/sudoers 不在白名单 | aikctl:4773-4800 |
| `aikctl quota get` | no | structured | 出厂无 quota 二进制 → unavailable（与宿主同态，非沙箱问题） | aikctl:5127-5155 |
| `aikctl session list` | no | structured | /var/run/utmp 缺 → 恒报「无会话」（假阴性） | aikctl:5081-5092 |
| `aikctl user list` | partial | structured | console-gate 在 /etc/aikernel 只读面（沙箱内 uid 0 可读 0600 的口令哈希）；OS 号对照要 /etc/passwd → 全部显示号缺席 | aikctl:4149-4165 |

## 9. Top 15：最该先接通的工具/对象

排序依据：先看场景库命中数（`agent/ai/tests/usage/scenarios.json`，50 条人工场景，诊断/服务/网络/文件/组合类），同分按排障链位置（服务→日志→进程→磁盘→包→会话→启动→网络策略→时间），再看当前不可达程度。场景库未覆盖的按装机与排障常规项排在命中场景之后。

| # | 工具/对象 | 对象 | 命中场景 | 出厂现状 | 建议（喂 AIF-02） |
|---:|---|---|---|---|---|
| 1 | systemctl：服务状态 / 失败单元 / 定时器列表 | SYS-01,SYS-02,SYS-07 | svc-01,svc-02,svc-04,diag-05,combo-05 | 沙箱无 /run/systemd/private；宿主侧只能 glob 出 unit 文件名，active/failed 状态零可达 | 做成 occ 宿主侧原生只读工具：systemctl show / list-units --failed / list-timers，JSON 输出 |
| 2 | journalctl / dmesg：日志读面 | SYS-03,SYS-04 | diag-05,svc-02 | 沙箱无 /var/log/journal；journal 是二进制，occ read 拒读——journal 内容零可达；dmesg 取决于 kernel.dmesg_restrict（沙箱无 CAP_SYSLOG，须真机核） | 原生只读工具：journalctl -o json，带 unit/priority/since 过滤与行数上限 |
| 3 | 宿主进程枚举与资源占用（ps/top/smaps） | PROC-01,PROC-02,PROC-04 | diag-02,combo-01 | PID namespace 里只见沙箱自己；宿主侧只能 glob /proc（200 项截断）再逐个 read | 原生只读工具：按 /proc 聚合 pid/ppid/rss/cpu/comm，支持排序与 top-N |
| 4 | 磁盘占用大户与文件元数据（du/stat） | DISK-05,FS-03 | diag-03,file-03,combo-02,combo-05 | 沙箱看不到宿主 /var、/var/log；occ 无 stat/ls -l，glob 只给文件名 | 原生只读工具：du（限深度）与 stat；先解「/var/log 谁最大」 |
| 5 | dpkg/apt：已装包与可升级 | PKG-01,PKG-03,PKG-05 | - | 场景库未覆盖；装机与安全更新是常规项。/var/lib/dpkg 不在沙箱；apt list --upgradable 完全不可达 | 原生只读工具：dpkg-query -W 与 apt list --upgradable（宿主侧执行） |
| 6 | 登录会话（who/w/loginctl） | ID-03 | - | 场景库未覆盖；utmp/wtmp 不在沙箱，aikctl session list 在沙箱里恒报无会话（假阴性） | 原生只读工具：把 aikctl session list 的 utmp 解析搬到宿主侧 |
| 7 | systemd-analyze：启动耗时 | SYS-06 | diag-04 | 要连 systemd manager | 原生只读工具：systemd-analyze time/blame |
| 8 | nft：运行时规则与防火墙状态 | NET-06 | net-05,combo-03 | NETLINK_NETFILTER 需 CAP_NET_ADMIN；nft 还是 W2 硬表命令 | 原生只读工具：nft -j list ruleset（宿主侧只读动词，免确认） |
| 9 | timedatectl：NTP 同步与时区 | TIME-01 | - | 场景库未覆盖；证书/日志对时排障项。沙箱里 date 时区恒 UTC，NTP 状态零可达 | 原生只读工具：timedatectl show -p 属性子集 |
| 10 | aikctl 五族读面原生化（policy/session/quota/user/audit） | ID-04,ID-05,ID-03,FS-10,AI-01 | - | aikctl 只能经沙箱 bash 调；/etc/sudoers、/var/run/utmp、/var/lib 不在沙箱视图；旧审计脚本 0 处提及 aikctl | 宿主侧原生工具封装 aikctl 的纯解析逻辑（或按子命令白名单挂入所需只读文件） |
| 11 | cgroup 限额与用量聚合（systemd-cgtop） | CG-01,CG-02 | diag-01,combo-01 | 沙箱内 /sys/fs/cgroup 是空目录；宿主侧只能逐文件 read，无法枚举聚合 | 原生只读工具：按 slice/service 聚合 memory.current/cpu.stat/pids.current |
| 12 | recall / 记忆工具（OCC_ORCH_TOOLS） | MEM-02,MEM-03 | - | 场景库 memory 类 5 条走的是旧 memory_* 工具；出厂未置 OCC_ORCH_TOOLS，recall 不注册；回环 SME 的检索是 POST（curl -d 判 W2） | 评估出厂置位 OCC_ORCH_TOOLS=1，或给 recall 单列开关 |
| 13 | aik-upgrade status：启动槽状态 | SYS-05 | - | 场景库未覆盖；出厂专属运维项。依赖 /boot 与 /var/lib，沙箱里输出误导性空结果 | 原生只读工具：宿主侧执行 aik-upgrade status |
| 14 | conntrack 计数与查询 | NET-04 | combo-03 | /proc/net/nf_conntrack 依赖内核节点；conntrack 工具出厂未装 | 先在真机确认节点；原生只读工具做计数/过滤 |
| 15 | 文件校验和（sha256sum，宿主文件） | FS-09 | - | 场景库未覆盖；发布物核对项。沙箱里 sha256sum 只见沙箱可见树 | 原生只读工具：file.hash(path)（G-024 的验收口径） |

## 10. 旧审计脚本的缺陷（只记不改）

- 量的不是出厂入口：97 对象矩阵的读面取自 tools.json 注册表，而执行器 executor.c 只链进 aikernel-shell（agent/ai/Makefile:169），occ 的 Makefile 不编它（agent/ai/occ/Makefile:105-106）。
- `--vm-host` 的用法示例直接指向生产机（audit_capabilities.py:35），且探测用 StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null（:844-846）——照文档敲就会弱校验连生产。
- 覆盖率随审计机变化：`cmd:` 读/写路径的 ok 取决于审计机上有没有该二进制（:1157-1162、:1218-1227），不是被审系统的属性。
- 0 处提及 aikctl：user/policy/session/quota/audit 五族对其完全不可见。
- `principal:` 记号（/lease list|show）不是 Agent 工具，却按 gated 读面计入 read_gated 并保住 structured 级别（:1193-1196、:1262）。
- `scan_desktop` 候选路径里写死了一条开发机家目录绝对路径（:1054-1058；主会话 2026-11-24 已删）。
- 文案与阈值不一致：READ_TARGET=92.0（:64），矩阵文案却写「未达 95% 读覆盖」（:1505-1506）。
- docs/CAPABILITY-GAPS.md 没跟上脚本：文档生成时间 2026-10-24，G-024 行仍写「只能 python3 hashlib 逃逸」，而脚本里的 G-024 已改成「python3 已摘除」（脚本 :258 对文档 :43）。

## 11. 局限与待复核

- 实测层只覆盖探测清单里采过的条目（194 行），且只在一台出厂配方测试机上以 root 身份采过（单条超时 10s）；对象读面里没被采到的仍是静态推断——未测的对象见 §16，待采条目见 §17。网卡名、磁盘名、内核节点这类运行态因机而异，个别路径的结论不通用。
- admin 身份的沙箱命令缺省按不可达计：仓内 build-rootfs.sh 与出厂树都没有 sudo 二进制与放行 aik-sandbox 的 sudoers 规则；另有一处疑似缺陷——aik-sandbox.c 没有任何 setuid 代码，经 sudo 组装后沙箱内进程是 uid 0，而 per-user 工作区是 0700 属 admin（occ_tools/sandbox.c:318-336），无 CAP_DAC_OVERRIDE 的 uid 0 进不去该目录，`cd <workdir>` 可能直接失败。
- 回环 HTTP（SME 8000、desktop 8091）读面依赖服务在跑且鉴权可过；出厂 /opt/sme/data/sme.config.json 含凭据位，未读，api.auth_token 取值未知。
- occ 的 read/glob 输出截 8KB、glob 200 项上限，大文件/大目录的「可达」只是理论上可达，实际要多次分页。
- 内核节点依赖硬件、挂载视图和启动配置。17.11.1 样例核对了 PSI、conntrack 与部分缺失节点，见 §14。
- dmesg 在沙箱里能不能读取决于 kernel.dmesg_restrict：出厂 sysctl.d/10-kernel-hardening.conf 没改该项，AIKernel 内核树 .config 未设 CONFIG_SECURITY_DMESG_RESTRICT（默认 0）。旧批读到内核日志，17.11.1 批次未复测该命令。

## 12. 源码事实钉子（--check 逐条核对）

| ID | 事实 | 状态 |
|---|---|---|
| F01 | 沙箱 clone 标志含 NEWNS\|NEWPID\|NEWUTS | 成立 |
| F02 | /etc 白名单恰为 4 个文件 | 成立 |
| F03 | /dev 必挂集为 null/zero/random/urandom | 成立 |
| F04 | 能力只保留 CAP_NET_RAW | 成立 |
| F05 | 沙箱网络默认 host | 成立 |
| F06 | aik-sandbox.c 无任何 setuid/setgid 调用（非 root 经 sudo 组装后沙箱内仍是 uid 0） | 成立 |
| F07 | 根骨架含 tmp/home/var/opt/srv，且不含 /run | 成立 |
| F08 | occ 默认工具恰 9 件 | 成立 |
| F09 | W2 硬表含 nft/kill/mount/dd/reboot | 成立 |
| F10 | read 工具无路径域守卫，单文件上限 4MB | 成立 |
| F11 | 结果 8KB / glob 200 项 / grep 100 行上限 | 成立 |
| F12 | occ bash = create → run --rw-path <workdir> -- /bin/sh -c → destroy | 成立 |
| F13 | W2 门：非 PRIVILEGED 档一律拒绝 | 成立 |
| F14 | 出厂 policy：root=privileged / wheel=confirmed / default=restricted | 成立 |
| F15 | aik-console 置 OCC_NETCFG_TOOLS=1、未置 OCC_ORCH_TOOLS、setpriv 降权；api unit 同样置位且无 User=（root） | 成立 |
| F16 | 出厂 API 以 `occ -p` 调起 occ，且不带 --allow-w2 | 成立 |
| F17 | 出厂树入口目录无 /usr/local/bin/ai（aikernel-shell 已退出出厂入口） | 成立 |
| F19 | /etc/aikernel 整目录只读挂入 | 成立 |
| F20 | /proc 是新挂的只读 procfs | 成立 |
| F21 | 写域=工作目录∪/tmp∪/var/ai∪$HOME，~/.occ 恒拒 | 成立 |
| F22 | model.toml/provider.toml 被拷入沙箱 /root/.aikernel | 成立 |
| F23 | W2 档位取自 policy（按 uid）；headless 须显式 --allow-w2 | 成立 |

## 13. 实测层

| 批次 | 采集 SHA-256 | 文件字节 | 采集行 | 时间 | UID | 内核 | 沙箱件字节 | 超时 |
|---|---|---:|---:|---|---:|---|---:|---|
| 17.10 · 采集 1 | `00c0c8d274e6a7b7f64ca92a68def46ddb283e8227bc81eb8b27805c5b274a90` | 9828 | 125 | 2026-11-23T18:19:36+0000 | 0 | 6.18.39 | 1111080 | 10s |
| 17.11.1 · 采集 2 | `b591fb1fe45466499e9330233b1593eb2e3c9660867bb8ccb89789312183245d` | 8172 | 69 | 2026-11-24T11:53:45+0000 | 0 | 6.18.39 | 1111080 | 10s |

- 两批均通过 root 直接进入沙箱，使用 create → run --rw-path → destroy。证据只说明实际样例的沙箱读面。下表的 W1/W2 来自 occ 源码静态判定。这两批未经过真实 occ 确认门，也未验证普通用户、API 或模型调用。
- 首行、配置值、主机标识及原始证据留在 L1。公开行只保留命令模板、退出码、计数与人工概述。人工判断绑定原始 TSV 摘要与该行的返回结果。
- 采集列 `out_bytes` 来自 shell `${#out}`，可能按字符计数。长度大于 8192 时必然超过 occ 的 8 KiB 输出限额，较短的多字节输出不能据此认定未截断。
- 退出码到 occ 文本的映射：`ok`=rc=0：输出 + `[exit=0]`，工具 rc=0；`sb_fail`=rc=1/2：`ERROR: bash 沙箱执行失败（aik-sandbox exit=N）：` + 输出，内部返回 -1，工具结果 rc=1；`tool_error`=rc 为其它值（127 / 100 / 137 …）：输出 + `[exit=N]`，工具 rc=0。采集行的标签是据此推定，AIF-09 记录了 1/2 与包装器故障的歧义。
- 对象分母取本报告静态目录的 90 个适用对象。每批按与目标对象相符的数据判定，可读表示相应数据类型已证，整份输出、全部读面与其他机器运行态另需核验。


## 14. 各批命令和判读

清单编号从 0 开始。静态列是现行样例读面预期，采集标签与之有出入时同时显示。W2 样例的数据来自直接沙箱取证，产品中须以控制台档位和实际确认裁决为准。

### 17.10 · 采集 1

| # | 命令 | 静态预期 | occ 档 | rc | 耗时 s | 长度 | 判读 | 依据与限制 |
|---:|---|---|---|---:|---:|---:|---|---|
| 0 | `ls -la /` | — | W1 | 0 | 0.017 | 754 | 视图探针 | 沙箱根不是宿主根：挂的是 tmpfs 骨架（源码 sb_make_root 建的 usr/proc/sys/etc/tmp/home/var/opt/srv/dev 与 bin/sbin/lib 链；首行 total 4） aik-sandbox.c:826-829 |
| 1 | `ls -la /etc` | — | W1 | 0 | 0.018 | 359 | 视图探针 | /etc 是白名单式的，只有几个小文件（首行 total 16）；全文见证据文件 aik-sandbox.c:2166-2187,2196-2216（/etc 白名单 + /etc/aikernel 整目录 + awk/which 链修复） |
| 2 | `ls -la /dev` | — | W1 | 0 | 0.029 | 378 | 视图探针 | /dev 里只有几个字符设备节点（首行 total 0；源码必挂的只有 null/zero/random/urandom），没有块设备与看门狗节点——同批 fdisk -l 零输出、wdctl 报没有可用设备 aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]） |
| 3 | `ls -ld /run /boot /var/log /var/lib/dpkg /etc/passwd /etc/systemd/system` | — | W1 | 2 | 0.021 | 347 | 视图探针 | rc=2，首行是 /run 不存在；347 字节约合 6 行同构报错——六条路径都不在沙箱视图【推断：只留了首行】 aik-sandbox.c:824-859（根骨架无 /run）；aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录）；aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| 4 | `id` | — | W1 | 0 | 0.016 | 20 | 视图探针 | 沙箱内进程是 uid 0；用户名/组名解析不出来（无 /etc/passwd、/etc/group） aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| 5 | `grep -E '^(CapEff\|CapBnd\|NoNewPrivs):' /proc/self/status` | — | W1 | 0 | 0.017 | 63 | 视图探针 | CapEff=0000000000002000：有效能力只剩 CAP_NET_RAW aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS） |
| 6 | `cat /proc/1/comm` | — | W1 | 0 | 0.015 | 2 | 视图探针 | 沙箱里的 1 号进程是 sh：独立 PID 命名空间，宿主进程不可见 aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| 7 | `cat /proc/self/mountinfo` | — | W1 | 0 | 0.016 | 1919 | 视图探针 | 1919 字节：沙箱自己的挂载表 aik-sandbox.c:2089-2304 |
| 8 | `hostname` | — | W1 | 0 | 0.015 | 13 | 视图探针 | UTS 隔离：主机名是隔离区名，不是宿主名 aik-sandbox.c:2307-2309 |
| 9 | `aa-complain --help` | no | W1 | 127 | 0.014 | 73 | rc=127·没有这个命令 | — |
| 10 | `aa-disable --help` | no | W1 | 127 | 0.02 | 72 | rc=127·没有这个命令 | — |
| 11 | `aa-enforce --help` | no | W1 | 127 | 0.015 | 72 | rc=127·没有这个命令 | — |
| 12 | `aa-status --help` | no | W1 | 127 | 0.017 | 71 | rc=127·没有这个命令 | — |
| 13 | `aik-upgrade status` | no | W1 | 0 | 0.029 | 386 | rc=0·不是宿主数据 | 报告照常打印但全是空壳：槽状态文件、grubenv、/boot 内核清单、userland 状态都不在沙箱视图，输出的是「(no state file)」「last install: (none)」；只有 /proc/cmdline 一段是真数据【推断：按脚本源码复算，386 字节吻合】 factory/usr/local/sbin/aik-upgrade:486-527（cmd_status） |
| 14 | `aikctl policy get --json` | ok | W1 | 0 | 0.099 | 735 | 输出来源或含义待证 | — |
| 15 | `apparmor_status --help` | no | W1 | 127 | 0.021 | 77 | rc=127·没有这个命令 | — |
| 16 | `apt list --installed` | no | W1 | 100 | 0.034 | 584 | 其它非零退出 | apt 在缺 /var/lib/dpkg、/etc/apt 的沙箱里以 100 退出 aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录）；aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| 17 | `arping -c 1 127.0.0.1` | ok | W1 | 2 | 0.018 | 48 | rc=1/2 | arping 的缺省接口是 eth0；同批网卡枚举的首行是另一个接口，arping 报缺省接口不存在。规则依据的前提（能力集里有 CAP_NET_RAW）根本没被检验到，判定未定 首行报告缺省接口不存在；同批 `ls /sys/class/net` 为对照 arping -c 1 -I lo 127.0.0.1（清单补测第 1 组） |
| 18 | `blkid -o export` | no | W1 | 2 | 0.017 | 0 | rc=1/2 | — |
| 19 | `bootctl status` | no | W1 | 0 | 0.025 | 178 | rc=0·不是宿主数据 | rc=0，但首行就是「Couldn't find EFI system partition」：/boot 不在沙箱视图 |
| 20 | `cat /proc/meminfo` | partial → ok（命令表 partial、按路径 ok） | W1 | 0 | 0.016 | 1446 | 读到宿主数据 | 清单上的 partial 是命令表对 cat 这个通用工具的判定；按路径求值 /proc/* 为 ok（对象矩阵 RES-04 标的就是 [ok]）。实测 1446 字节宿主内存数据 |
| 21 | `cc --version` | no | W1 | 127 | 0.015 | 64 | rc=127·没有这个命令 | — |
| 22 | `conntrack -L` | no | W1 | 127 | 0.018 | 71 | rc=127·没有这个命令 | — |
| 23 | `crontab -l` | no | W1 | 1 | 0.027 | 22 | rc=1/2 | — |
| 24 | `ctstat` | ok | W1 | 137 | 10.004 | 0 | 超时被杀 | 不带 -c 的 ctstat 不会自己退出，10 秒超时被杀、零输出：数据面没被检验。打版机上（iproute2 5.15.0）不带 -c 同样不退出；出厂机的版本没采集 ctstat -c 1；ls /proc/net/stat |
| 25 | `curl -s -m 5 http://127.0.0.1:8000/health` | ok | W1 | 0 | 0.03 | 31 | 读到宿主数据 | SME 回环健康接口返回 status=ok 与记忆条数 |
| 26 | `cut -d: -f1 /proc/meminfo` | ok | W1 | 0 | 0.017 | 585 | 输出来源或含义待证 | — |
| 27 | `date +%s` | partial | W1 | 0 | 0.017 | 10 | 读到一部分 | 只给 epoch，与采集时间吻合；「时区恒 UTC」这个样例检验不到 date |
| 28 | `df -P` | partial | W1 | 0 | 0.016 | 179 | 读到一部分 | 179 字节 = 表头 + 2 行【按字节数推断】：只见沙箱挂载点（/ 与 /usr bind）。宿主根分区的容量/用量看得到，其余挂载看不到 |
| 29 | `dmesg --color=never` | ok | W1 | 0 | 0.018 | 42197 | 读到宿主数据，超过 8 KiB | 42197 字节、首行是内核版本行：整条启动日志都读得到。该机 kernel.dmesg_restrict=0，静态标的「依赖运行态」在该机成立 |
| 30 | `dpkg-query -W` | no | W1 | 0 | 0.02 | 0 | rc=0·零字节，被沙箱视图挡了 | /var/lib/dpkg/status 不在沙箱视图（视图探针 ls -ld 报不存在）→ 空表 + rc=0；宿主上明明装着包，AI 分不清「没装包」与「看不见」 aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| 31 | `dpkg-query -W` | no | W1 | 0 | 0.017 | 0 | rc=0·零字节，被沙箱视图挡了 | /var/lib/dpkg/status 不在沙箱视图（视图探针 ls -ld 报不存在）→ 空表 + rc=0；宿主上明明装着包，AI 分不清「没装包」与「看不见」 aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| 32 | `dpkg-query -W` | no | W1 | 0 | 0.021 | 0 | rc=0·零字节，被沙箱视图挡了 | /var/lib/dpkg/status 不在沙箱视图（视图探针 ls -ld 报不存在）→ 空表 + rc=0；宿主上明明装着包，AI 分不清「没装包」与「看不见」 aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| 33 | `dpkg-query -W` | no | W1 | 0 | 0.019 | 0 | rc=0·零字节，被沙箱视图挡了 | /var/lib/dpkg/status 不在沙箱视图（视图探针 ls -ld 报不存在）→ 空表 + rc=0；宿主上明明装着包，AI 分不清「没装包」与「看不见」 aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录） |
| 34 | `du -x -d1 /var` | no | W1 | 0 | 0.018 | 16 | rc=0·不是宿主数据 | 输出「0 /var/ai」是沙箱空 tmpfs /var 里的产物区空目录，不是宿主 /var 的占用 aik-sandbox.c:152（SB_ARTIFACT_CANON） |
| 35 | `dumpe2fs -h /dev/sda1` | no | W1 | 2 | 0.021 | 139 | rc=1/2 | — |
| 36 | `echo ok` | ok | W1 | 0 | 0.017 | 2 | 输出来源或含义待证 | — |
| 37 | `ethtool eth0` | no | W1 | 127 | 0.014 | 69 | rc=127·没有这个命令 | — |
| 38 | `fdisk -l` | no | W2 | 0 | 0.016 | 0 | rc=0·零字节，被沙箱视图挡了 | /dev 里没有块设备节点（视图探针 ls -la /dev：total 0）→ 什么都不列、rc=0；宿主上明明有盘，AI 分不清「没有盘」与「看不见」 aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]） |
| 39 | `find /sys/class/net -maxdepth 1` | partial | W1 | 0 | 0.015 | 75 | 读到一部分 | 命令能跑；样例路径在 /sys，列出的是宿主的网卡目录（首行是 /sys/class/net 自身） |
| 40 | `findmnt -J` | partial | W1 | 0 | 0.032 | 4199 | 读到一部分 | 沙箱自己的挂载表（JSON，4199 字节） |
| 41 | `free -b` | ok | W1 | 0 | 0.017 | 206 | 读到宿主数据 | 全局 /proc/meminfo 的内存表头 |
| 42 | `gcc --version` | no | W1 | 127 | 0.013 | 65 | rc=127·没有这个命令 | — |
| 43 | `getent passwd` | no | W1 | 0 | 0.014 | 0 | rc=0·零字节，被沙箱视图挡了 | /etc/passwd 不在白名单 → 一条也查不到、rc=0；AI 分不清「没有用户」与「看不见」 aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| 44 | `grep -c Mem /proc/meminfo` | ok | W1 | 0 | 0.015 | 1 | 输出来源或含义待证 | — |
| 45 | `head -n 5 /proc/meminfo` | ok | W1 | 0 | 0.017 | 139 | 输出来源或含义待证 | — |
| 46 | `hostname` | partial | W1 | 0 | 0.018 | 13 | rc=0·不是宿主数据 | 输出的是隔离区名（UTS 隔离），不是宿主名 |
| 47 | `hostnamectl` | no | W1 | 1 | 0.018 | 117 | rc=1/2 | — |
| 48 | `id` | no | W1 | 0 | 0.017 | 20 | rc=0·不是宿主数据 | 打印的是沙箱自己的身份（uid=0 gid=0 groups=0），用户名/组名解析不出来：无 /etc/passwd、/etc/group |
| 49 | `ifconfig -a` | ok | W1 | 0 | 0.017 | 1199 | 读到宿主数据 | 首行的接口标题与共享网络命名空间的输出相符 aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| 50 | `ip -j addr` | ok | W1 | 0 | 0.016 | 1335 | 读到宿主数据 | 共享网络命名空间的地址 JSON 数组 |
| 51 | `journalctl -n 20 --no-pager` | no | W1 | 0 | 0.016 | 45 | rc=0·不是宿主数据 | rc=0，但只有一句「No journal files were found.」：/var/log/journal、/run/journal 都不在沙箱视图 |
| 52 | `kill -0 1` | no | W2 | 0 | 0.011 | 0 | rc=0·零字节，不适用：成功本来就没有输出 | 信号权限检查成功，但对象是沙箱自己的 1 号进程 sh，不是宿主 PID 1——假成功 aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| 53 | `last -n 5` | no | W1 | 1 | 0.015 | 58 | rc=1/2 | — |
| 54 | `lnstat -c 1` | ok | W1 | 1 | 0.014 | 2163 | 读到宿主数据 | rc=1 却有 2163 字节数据（首行是 nf_conntrack 的表头）：iproute2 的 lnstat -c 采完一次就返回 1（打版机 iproute2 5.15.0 复现 rc=1 且有数据）。数据读到了，但 occ 会把它标成「沙箱执行失败」 推断（静态求值，未在沙箱内实测）；occ_tools/sandbox.c:570-575（AIF-09） |
| 55 | `localectl status` | no | W1 | 1 | 0.018 | 117 | rc=1/2 | — |
| 56 | `loginctl list-sessions` | no | W1 | 1 | 0.018 | 117 | rc=1/2 | — |
| 57 | `ls /sys/class/net` | partial | W1 | 0 | 0.016 | 15 | 读到一部分 | 首行确认读到一个宿主接口，其余行没有保留 |
| 58 | `lsattr /usr/local/bin/occ` | partial | W1 | 0 | 0.015 | 41 | 读到一部分 | 命令能跑，对象是 /usr 只读面上的真实宿主文件；宿主其余目录看不到 |
| 59 | `lsblk -J` | ok | W1 | 0 | 0.02 | 1280 | 输出来源或含义待证 | — |
| 60 | `lscpu -J` | ok | W1 | 0 | 0.017 | 4430 | 输出来源或含义待证 | — |
| 61 | `lsipc` | ok | W1 | 0 | 0.016 | 1078 | 输出来源或含义待证 | — |
| 62 | `lslocks` | ok → no | W1 | 0 | 0.019 | 0 | rc=0·零字节，被沙箱视图挡了 | /proc/locks 按读取端 procfs 的 PID 命名空间过滤：属主进程不在本命名空间就不显示。沙箱是独立 PID 命名空间里新挂的 procfs，列得出的是沙箱自己进程的锁，宿主进程的锁看不见 linux-6.18.39 fs/locks.c:2892-2898（locks_show）；aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） 宿主侧对照：同一时刻在宿主上跑 lslocks，应有锁 |
| 63 | `lslogins` | no | W1 | 1 | 0.016 | 50 | rc=1/2 | — |
| 64 | `lsmem` | ok → no | W1 | 1 | 0.017 | 72 | rc=1/2 | 出厂内核 .config 未设 CONFIG_MEMORY_HOTPLUG → 没有 /sys/devices/system/memory。宿主上同样没有（memory.o 只在该选项下编译），不是沙箱挡的【推断：出厂内核按仓内 .config 编，凭内核版本串一致判断；补测 ls /sys/devices/system 可直接看】 .config（# CONFIG_MEMORY_HOTPLUG is not set）；linux-6.18.39 drivers/base/Makefile:16 |
| 65 | `lsns` | no | W1 | 0 | 0.018 | 745 | rc=0·不是宿主数据 | 【推断：只留了表头】lsns 读的是沙箱里看得见的进程的 /proc/<pid>/ns，列出的是沙箱自己进程的命名空间，不是宿主的命名空间清单；occ 会显示成功 |
| 66 | `lvs --help` | no | W1 | 127 | 0.012 | 65 | rc=127·没有这个命令 | — |
| 67 | `mount` | no → partial | W2 | 0 | 0.016 | 1515 | 读到一部分 | 不带参数的 mount 是列挂载表，是读操作、不需要 CAP_SYS_ADMIN；列出的是沙箱自己的挂载表（首行 tmpfs on /），同 findmnt |
| 68 | `nc -z -w 2 127.0.0.1 22` | ok | W1 | 1 | 0.017 | 440 | rc=1/2 | 该机的 nc 不支持 -z（首行 nc: invalid option -- 'z'）：样例命令本身跑不起来。TCP 连接能力没被检验——同批 curl/wget 连回环端口都成功 occ_tools/sandbox.c:576-582（非 0/1/2 的退出码原样写进结果） nc -h（看是哪一版 nc）；nc -w 2 127.0.0.1 8000 </dev/null |
| 69 | `netstat -tunl` | ok | W1 | 0 | 0.015 | 933 | 输出来源或含义待证 | — |
| 70 | `networkctl status` | no | W1 | 1 | 0.016 | 55 | rc=1/2 | — |
| 71 | `nft list ruleset` | no | W2 | 1 | 0.016 | 42 | rc=1/2 | Operation not permitted (you must be root)：uid 是 0 但没有 CAP_NET_ADMIN aik-sandbox.c:1955-1996（能力裁到 CAP_NET_RAW，NO_NEW_PRIVS） |
| 72 | `nslookup 127.0.0.1` | ok | W1 | 0 | 0.014 | 83 | 读到一部分 | 首行确认了应答解析器，未确认宿主 DNS 配置全貌 |
| 73 | `nstat -az` | ok | W1 | 0 | 0.018 | 17442 | 输出来源或含义待证 | — |
| 74 | `ollama list` | ok | W1 | 0 | 0.03 | 31 | 接口返回空清单，未观察到对象 | 返回模型列表表头，未观察到模型条目 |
| 75 | `passwd -S root` | no | W1 | 1 | 0.016 | 40 | rc=1/2 | — |
| 76 | `pgrep -a sshd` | no | W1 | 1 | 0.017 | 0 | rc=1/2 | — |
| 77 | `pidof systemd` | no | W1 | 1 | 0.014 | 0 | rc=1/2 | — |
| 78 | `ping -c 2 127.0.0.1` | ok | W1 | 0 | 1.024 | 310 | 输出来源或含义待证 | — |
| 79 | `printf ok` | ok | W1 | 0 | 0.014 | 2 | 输出来源或含义待证 | — |
| 80 | `ps -eo pid,ppid,stat,comm` | no | W1 | 0 | 0.019 | 76 | rc=0·不是宿主数据 | 76 字节 = 表头 + 2 行【按字节数推断】：只有沙箱里的 sh 和 ps 自己，看不到宿主进程；occ 会显示成功 aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| 81 | `pvs --help` | no | W1 | 127 | 0.016 | 65 | rc=127·没有这个命令 | — |
| 82 | `python3 -c 'print(1)'` | ok | W1 | 0 | 0.025 | 1 | 输出来源或含义待证 | — |
| 83 | `quota --help` | no | W1 | 127 | 0.016 | 67 | rc=127·没有这个命令 | — |
| 84 | `repquota --help` | no | W1 | 127 | 0.019 | 70 | rc=127·没有这个命令 | — |
| 85 | `resolvectl status` | no | W1 | 1 | 0.024 | 45 | rc=1/2 | — |
| 86 | `route -n` | ok | W1 | 0 | 0.018 | 341 | 输出来源或含义待证 | — |
| 87 | `rtstat` | ok | W1 | 137 | 10.007 | 1231 | 超时被杀 | 同 ctstat，不会自己退出；被杀前已输出 1231 字节，首行是 rt_cache 的表头——数据面是通的，坏的是样例写法 rtstat -c 1 |
| 88 | `sed -n 1,3p /proc/meminfo` | ok | W1 | 0 | 0.135 | 83 | 输出来源或含义待证 | — |
| 89 | `setquota --help` | no | W1 | 127 | 0.013 | 70 | rc=127·没有这个命令 | — |
| 90 | `sha256sum /etc/aikernel/policy.conf` | partial | W1 | 0 | 0.015 | 91 | 读到一部分 | 命令能跑，对象是 /etc 白名单里的真实宿主文件；宿主其余文件看不到 |
| 91 | `slabtop -o -s c` | ok | W1 | 0 | 0.018 | 13897 | 输出来源或含义待证 | — |
| 92 | `smartctl -a /dev/sda` | no | W1 | 2 | 0.02 | 197 | rc=1/2 | — |
| 93 | `sort /proc/meminfo` | ok | W1 | 0 | 0.017 | 1446 | 输出来源或含义待证 | — |
| 94 | `ss -tunl` | ok | W1 | 0 | 0.022 | 813 | 读到宿主数据 | 共享网络命名空间的监听表 |
| 95 | `sshd -T` | no | W1 | 1 | 0.02 | 47 | rc=1/2 | — |
| 96 | `stat /usr/local/bin/occ` | partial | W1 | 0 | 0.017 | 390 | 读到一部分 | 命令能跑，对象是 /usr 只读面上的真实宿主文件；宿主其余目录看不到 |
| 97 | `strace -c true` | partial | W1 | 0 | 0.027 | 1143 | 读到一部分 | 能跑，只能跟踪沙箱里自己起的进程 |
| 98 | `swapon --show` | no → ok | W2 | 0 | 0.019 | 59 | 读到宿主数据 | 59 字节 = 表头 + 1 行：读到宿主的 swap 清单（一个 swap 文件）。--show 读 /proc/swaps，不需要 CAP_SYS_ADMIN【推断：行内容是按打版机 util-linux 2.37.2 的输出格式复算出来的（出厂机的版本没采集；表头 SIZE 后单空格 + 28 字节一行，只有 file 型条目对得上），全文待补测】 带 --keep 重采一次取全文 |
| 99 | `sysctl -a` | ok | W1 | 0 | 0.041 | 42246 | 输出来源或含义待证 | — |
| 100 | `systemctl list-units --no-pager` | no | W1 | 1 | 0.016 | 117 | rc=1/2 | — |
| 101 | `systemd-analyze time` | no | W1 | 1 | 0.021 | 117 | rc=1/2 | — |
| 102 | `systemd-cgls --no-pager` | no | W1 | 1 | 0.017 | 129 | rc=1/2 | — |
| 103 | `systemd-cgtop -n 1` | no | W1 | 1 | 0.018 | 58 | rc=1/2 | — |
| 104 | `systemd-detect-virt` | ok | W1 | 0 | 0.022 | 6 | 输出来源或含义待证 | — |
| 105 | `tail -n 5 /proc/meminfo` | ok | W1 | 0 | 0.017 | 139 | 输出来源或含义待证 | — |
| 106 | `tc -j qdisc show` | ok | W1 | 0 | 0.025 | 290 | 输出来源或含义待证 | — |
| 107 | `timedatectl show` | no | W1 | 1 | 0.027 | 117 | rc=1/2 | — |
| 108 | `top -b -n 1` | no → partial | W1 | 0 | 0.168 | 603 | 读到一部分 | 首行含运行时长与负载，取自 /proc 全局节点；进程表只列沙箱进程，用户数因无 utmp 恒为 0 |
| 109 | `traceroute -n -m 5 127.0.0.1` | ok | W1 | 0 | 0.014 | 108 | 输出来源或含义待证 | — |
| 110 | `udevadm info /sys/class/net` | no | W1 | 0 | 0.016 | 63 | rc=0·不是宿主数据 | 只回显 syspath（P: /class/net），没有任何属性：udev 库（/run/udev）不在沙箱视图 |
| 111 | `uname -r` | ok | W1 | 0 | 0.016 | 7 | 读到宿主数据 | 首行与宿主内核版本一致 |
| 112 | `sort /proc/meminfo \| uniq -c` | ok | W1 | 0 | 0.02 | 1862 | 输出来源或含义待证 | — |
| 113 | `uptime` | ok | W1 | 0 | 0.018 | 68 | 读到宿主数据 | 全局运行时长与负载 |
| 114 | `useradd -D` | no | W1 | 0 | 0.019 | 83 | rc=0·不是宿主数据 | /etc 白名单里没有 login.defs，打印的只能是二进制内置缺省值（首行 GROUP=100），与宿主配置无关：看着像配置，其实不是 |
| 115 | `vgs --help` | no | W1 | 127 | 0.015 | 65 | rc=127·没有这个命令 | — |
| 116 | `vmstat 1 2` | ok | W1 | 0 | 1.018 | 325 | 读到宿主数据 | 全局虚拟内存统计表头 |
| 117 | `vmstat -d` | ok | W1 | 0 | 0.015 | 959 | 读到宿主数据 | 全局磁盘 IO 统计表头 |
| 118 | `w -h` | no | W1 | 0 | 0.018 | 0 | rc=0·零字节，被沙箱视图挡了 | 同 who：读不到 /var/run/utmp，恒为空、rc=0 aik-sandbox.c:824-859（根骨架无 /run） 宿主侧对照：同一时刻在宿主上跑 who / w |
| 119 | `wc -l /proc/meminfo` | ok | W1 | 0 | 0.019 | 16 | 输出来源或含义待证 | — |
| 120 | `wdctl` | no | W1 | 1 | 0.021 | 65 | rc=1/2 | — |
| 121 | `wget -q -O - http://127.0.0.1:8000/health` | ok | W2 | 0 | 0.026 | 31 | 输出来源或含义待证 | — |
| 122 | `whereis ls` | ok | W1 | 0 | 0.017 | 15 | 输出来源或含义待证 | — |
| 123 | `which awk` | ok | W1 | 0 | 0.015 | 12 | 输出来源或含义待证 | — |
| 124 | `who` | no | W1 | 0 | 0.015 | 0 | rc=0·零字节，被沙箱视图挡了 | /run 不在沙箱视图 → 读不到 /var/run/utmp，恒为空、rc=0；AI 分不清「没人登录」与「看不见」。宿主当时有没有登录会话没采集 aik-sandbox.c:824-859（根骨架无 /run） 宿主侧对照：同一时刻在宿主上跑 who / w |

### 17.11.1 · 采集 2

| # | 命令 | 静态预期 | occ 档 | rc | 耗时 s | 长度 | 判读 | 依据与限制 |
|---:|---|---|---|---:|---:|---:|---|---|
| 125 | `arping -c 1 -I lo 127.0.0.1` | ok | W1 | 2 | 0.026 | 35 | rc=1/2 | 诊断指出 lo 不支持 ARP。该样例不能验证其他接口上的能力 |
| 126 | `nc -h` | — | W1 | 1 | 0.019 | 440 | 视图探针 | 返回选项诊断，证明可启动 nc；未测试传输 |
| 127 | `nc -w 2 127.0.0.1 8000 </dev/null` | ok | W1 | 0 | 0.017 | 0 | rc=0·零字节，不适用：成功本来就没有输出 | 无请求体的连接测试没有输出。服务数据另由本批 /stats 提供 |
| 128 | `ctstat -c 1` | ok | W1 | 1 | 0.017 | 0 | rc=1/2 | 单次模式返回 1 且零输出，无法区分采样终止和视图缺失 |
| 129 | `rtstat -c 1` | ok | W1 | 1 | 0.017 | 615 | 输出来源或含义待证 | 退出 1 且有输出，留存首行不能确认是有效路由缓存统计 |
| 130 | `ls /proc/net/stat` | — | W1 | 0 | 0.016 | 43 | 视图探针 | 列出共享网络命名空间的统计目录项 aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| 131 | `ls /sys/devices/system` | — | W1 | 0 | 0.016 | 55 | 视图探针 | 获得设备系统目录枚举，单取首行不足以证明目录无某项 aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| 132 | `cat /proc/locks` | — | W1 | 0 | 0.021 | 0 | 视图探针 | 沙箱 PID 视图中的锁表无输出，宿主锁状态未知 aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| 133 | `cat /proc/swaps` | — | W1 | 0 | 0.016 | 99 | 视图探针 | 全局 swap 表头及额外内容，作为沙箱视图旁证 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 134 | `ls -ld /etc/localtime /etc/timezone` | — | W1 | 2 | 0.017 | 122 | 视图探针 | 首行缺 localtime；结合 /etc 挂载白名单解释 date 的时区差异 aik-sandbox.c:2166-2187,2196-2216（/etc 白名单 + /etc/aikernel 整目录 + awk/which 链修复） |
| 135 | `ls /dev` | — | W1 | 0 | 0.023 | 41 | 视图探针 | 列出隔离区最小设备目录，设备节点范围由源码界定 aik-sandbox.c:283-288（/dev 仅 null/zero/random/urandom[+full/tty/console]） |
| 136 | `cat /proc/cpuinfo` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.018 | 2414 | 读到宿主数据 | 首行包含处理器条目，来自全局 CPU 信息 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 137 | `cat /proc/stat` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.016 | 1143 | 读到宿主数据 | 首行含 CPU 总计数 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 138 | `cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` | ok（命令表 partial、按路径 ok） | W1 | 1 | 0.015 | 85 | rc=1/2 | 该虚机的指定 cpufreq 节点缺失，未确认其他硬件上的存在性 |
| 139 | `cat /proc/swaps` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.015 | 99 | 读到一部分 | 全局 swap 列表有表头与记录。内存总量等其余指标本批未采 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 140 | `cat /proc/pressure/cpu` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.015 | 99 | 读到宿主数据 | CPU PSI 首行含 avg10 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 141 | `cat /proc/pressure/memory` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.02 | 93 | 读到宿主数据 | 内存 PSI 首行含 avg10 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 142 | `cat /proc/pressure/io` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.016 | 105 | 读到宿主数据 | IO PSI 首行含 avg10 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 143 | `cat /proc/diskstats` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.019 | 695 | 读到宿主数据 | 全局块设备 IO 统计含设备条目 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 144 | `cat /sys/block/sda/stat` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.016 | 152 | 读到宿主数据 | 指定块设备的内核统计数值行 aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| 145 | `cat /sys/class/bdi/8:0/read_ahead_kb` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.014 | 4 | 读到一部分 | 读到单个后备设备的预读数值，带宽和优先级未测 aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| 146 | `cat /proc/partitions` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.012 | 145 | 读到宿主数据 | 全局分区表有表头与额外条目 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 147 | `cat /proc/mounts` | partial | W1 | 0 | 0.015 | 1394 | rc=0·不是宿主数据 | 首行是沙箱 tmpfs 根，返回该进程的挂载视图，缺宿主挂载表 aik-sandbox.c:2089-2118,2272-2304 |
| 148 | `cat /proc/mdstat` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.019 | 39 | 读到一部分 | 只得到全局 MD 状态与无活动阵列的标准空状态，未观察设备条目、TRIM 或 dm 状态 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 149 | `cat /proc/cmdline` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.016 | 132 | 读到一部分 | 读到全局启动参数，未采 A/B 槽状态、启动器环境或安装记录 aik-sandbox.c:11-12,2301-2304（/proc 新挂只读，全局节点可读） |
| 150 | `ip -j link` | ok | W1 | 0 | 0.016 | 739 | 读到宿主数据 | 返回含接口记录的链路 JSON，来自共享网络命名空间 aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| 151 | `cat /sys/class/net/eth0/statistics/rx_bytes` | ok（命令表 partial、按路径 ok） | W1 | 1 | 0.016 | 71 | rc=1/2 | 硬编码接口名的节点缺失，不能据此判其它接口不可读 |
| 152 | `ip -j route` | ok | W1 | 0 | 0.019 | 386 | 读到一部分 | 共享网络命名空间有路由记录，本批未直接读 IP 地址清单 aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| 153 | `cat /proc/net/route` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.017 | 511 | 读到一部分 | 路由表有表头与记录，本批未直接读 IP 地址清单 aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| 154 | `cat /proc/net/tcp` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.017 | 10799 | 读到一部分，超过 8 KiB | 共享网络命名空间的 TCP 表有记录，未测其他协议，且输出超过工具限额 aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| 155 | `cat /proc/net/nf_conntrack` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.014 | 15572 | 读到宿主数据，超过 8 KiB | 首行含协议和连接记录，确认全局 conntrack 节点可读；工具会截断长输出 aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| 156 | `cat /etc/resolv.conf` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.015 | 929 | 读到一部分 | 首行标识系统解析 stub 配置；上游 resolver 和服务状态尚未实测 aik-sandbox.c:2166-2187,2196-2216（/etc 白名单 + /etc/aikernel 整目录 + awk/which 链修复） |
| 157 | `ip -d -j link` | ok | W1 | 0 | 0.015 | 1356 | 读到一部分 | 返回共享网络命名空间的详细链路配置，未确认持久化配置及全部 qdisc 状态 aik-sandbox.c:24-25,92,2397-2414（默认保留宿主网络） |
| 158 | `cat /sys/class/net/eth0/mtu` | ok（命令表 partial、按路径 ok） | W1 | 1 | 0.015 | 55 | rc=1/2 | 硬编码接口名的 MTU 节点缺失，其他接口待核 |
| 159 | `cat /sys/bus/pci/devices/0000:00:02.0/vendor` | ok（命令表 partial、按路径 ok） | W1 | 1 | 0.017 | 74 | rc=1/2 | 指定 BDF 下 vendor 节点缺失，样例不能代表全部 PCI 设备 |
| 160 | `cat /sys/class/drm/card0/status` | ok（命令表 partial、按路径 ok） | W1 | 1 | 0.022 | 59 | rc=1/2 | 指定节点缺失，DRM status 常位于连接器目录，不能据此判定 GPU 不存在 |
| 161 | `cat /sys/class/thermal/thermal_zone0/temp` | ok（命令表 partial、按路径 ok） | W1 | 1 | 0.025 | 69 | rc=1/2 | 指定温区节点缺失，其他温区和传感器未测 |
| 162 | `cat /sys/class/hwmon/hwmon0/temp1_input` | ok（命令表 partial、按路径 ok） | W1 | 1 | 0.023 | 67 | rc=1/2 | 指定 hwmon 温度节点缺失，不能代表所有传感器或风扇 |
| 163 | `cat /sys/class/power_supply/ACAD/online` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.02 | 1 | 读到一部分 | 读到 AC 供电状态一位数，未采电池面 aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| 164 | `cat /proc/ai/status` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.019 | 1843 | 读到宿主数据 | 首行运行状态与 seq 读入口一致。可证状态面与模型状态侧证，未采模型原始输出 AIKernel/senses/ai_procfs.c:111 |
| 165 | `cat /proc/ai/control` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.019 | 1781 | 读到宿主数据 | 首行形态为参数名与 domain、范围、当前值字段，取自内核 control 查询器 AIKernel/senses/ai_procfs.c:375 |
| 168 | `cat /proc/ai/hitrate` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.016 | 28 | 读到宿主数据 | 单行尝试、命中、比例统计，对策略与回滚仅为计数旁证 AIKernel/senses/ai_procfs.c:436 |
| 169 | `cat /proc/ai/latency` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.018 | 86 | 读到宿主数据 | 首行含决策与尝试计数，和延迟 seq 读面一致 AIKernel/senses/ai_procfs.c:407 |
| 170 | `cat /sys/kernel/ai/stats/telemetry_emitted` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.019 | 7 | 读到宿主数据 | 读到全局发出事件计数，不消费事件环 AIKernel/senses/ai_sysfs_stats.c:61 |
| 171 | `cat /sys/kernel/ai/stats/decisions_total` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.019 | 1 | 读到宿主数据 | 读到全局决策计数，不采集决策内容 AIKernel/senses/ai_sysfs_stats.c:88 |
| 172 | `cat /sys/kernel/ai/stats/runtime_state` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.015 | 1 | 读到宿主数据 | 读到全局运行状态枚举数值 AIKernel/senses/ai_sysfs_stats.c:118 |
| 174 | `cat /sys/kernel/ai/decision/stats` | ok（命令表 partial、按路径 ok） | W1 | 0 | 0.017 | 705 | 读到一部分 | 首行和统计入口一致，读到策略计数，未验证回滚记录或行为 AIKernel/senses/ai_sysfs.c:959 |
| 175 | `date` | partial | W1 | 0 | 0.016 | 28 | 读到一部分 | 读到时钟和 UTC 视图；结合同批本地时区路径缺失，NTP 状态未证 aik-sandbox.c:2166-2187,2196-2216（/etc 白名单 + /etc/aikernel 整目录 + awk/which 链修复） |
| 176 | `curl -s -m 5 http://127.0.0.1:8000/stats` | ok | W1 | 0 | 0.021 | 606 | 读到宿主数据 | 片段含记忆计数结构，与 SME stats 响应吻合；未采其他数据接口 agent/ai/smehttp/routes.c:1065 |
| 177 | `curl -s -m 5 http://127.0.0.1:8091/api/health` | ok | W1 | 0 | 0.018 | 334 | 读到宿主数据 | 片段含成功、服务和版本字段，与桌面健康路由吻合 agent/ai/desktop/desktopd.c:247 |
| 178 | `curl -s -m 5 http://127.0.0.1:8091/api/stats` | ok | W1 | 0 | 0.02 | 181 | 读到宿主数据 | 返回含资源统计和历史字段的对象；路由读资源面同时更新内存历史 agent/ai/desktop/desktopd.c:361 |
| 179 | `curl -s -m 5 http://127.0.0.1:8091/api/apps` | ok | W1 | 0 | 0.02 | 24 | 接口返回空清单，未观察到对象 | 返回有效的 0 项应用清单；缓存缺席也会产生空数组，不能据此判定宿主没有应用 agent/ai/desktop/desktopd.c:341；agent/ai/desktop/dtapps.c:588 |
| 180 | `curl -s -m 5 http://127.0.0.1:8091/api/theme` | ok | W1 | 0 | 0.02 | 1412 | 读到一部分 | 返回主题对象；加载器可能补默认设置并写回，未证实际配置或壁纸来源 agent/ai/desktop/desktopd.c:352；agent/ai/desktop/dttheme.c:90,163-181 |
| 181 | `aikctl policy get` | ok | W1 | 0 | 0.119 | 312 | 读到一部分 | 输出进入策略文件已解析分支；沙箱缺 NSS 账号组文件，不能证真实档位与租约 agent/ai/aikctl/aikctl:4610 |
| 182 | `aikctl compat hw` | partial | W1 | 0 | 0.093 | 2183 | 输出来源或含义待证 | 首行只证探测元数据，后续设备行未保留，PCI/USB 读面仍待证 agent/ai/aikctl/aikctl:2042,2113 |
| 184 | `aikctl policy get sudoers` | no | W2 | 1 | 0.136 | 24 | rc=1/2 | sudoers 读取分支报告缺项；文件不在沙箱 /etc 白名单 agent/ai/aikctl/aikctl:4773；aik-sandbox.c:2166-2187,2196-2216（/etc 白名单 + /etc/aikernel 整目录 + awk/which 链修复） |
| 185 | `ps -eo pid,ni,pri,comm` | no | W1 | 0 | 0.014 | 61 | rc=0·不是宿主数据 | 虽有进程表头和输出，沙箱 procfs 只列该 PID 命名空间 aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| 186 | `cat /sys/fs/cgroup/cgroup.procs` | no（命令表 partial、按路径 no） | W1 | 1 | 0.017 | 59 | rc=1/2 | 指定 cgroup 节点缺失，沙箱只挂 sysfs aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| 187 | `cat /sys/fs/cgroup/cgroup.controllers` | no（命令表 partial、按路径 no） | W1 | 1 | 0.016 | 65 | rc=1/2 | 指定控制器入口缺失，沙箱未单挂 cgroupfs aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| 188 | `cat /sys/fs/cgroup/memory.current` | no（命令表 partial、按路径 no） | W1 | 1 | 0.018 | 61 | rc=1/2 | 指定内存 cgroup 节点缺失，不能观察宿主 cgroup 用量 aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| 189 | `systemctl list-timers --no-pager` | no | W1 | 1 | 0.017 | 117 | rc=1/2 | 隔离区不是以 systemd 为 PID 1，计时器运行状态不可读 aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程）；aik-sandbox.c:824-859（根骨架无 /run） |
| 190 | `systemctl --failed --no-legend` | no | W1 | 1 | 0.02 | 117 | rc=1/2 | 同批 systemd 总线诊断对应隔离区，未得到失败服务清单 aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程）；aik-sandbox.c:824-859（根骨架无 /run） |
| 191 | `apt list --upgradable` | no | W1 | 100 | 0.032 | 584 | 其它非零退出 | 返回 APT 失败码；沙箱不挂宿主包状态和仓库配置，首行没有保留有效列表 aik-sandbox.c:826-829（/var、/tmp、/home 为 tmpfs 空目录）；aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| 192 | `cat /sys/kernel/security/apparmor/profiles` | no（命令表 partial、按路径 no） | W1 | 1 | 0.017 | 70 | rc=1/2 | 沙箱未挂 securityfs，该路径缺失 aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |
| 193 | `ip netns list` | no（命令表 ok、按具体参数 no） | W1 | 0 | 0.017 | 0 | rc=0·零字节，被沙箱视图挡了 | 未挂宿主具名 netns 目录；零输出只能说明沙箱目录视图 aik-sandbox.c:824-859（根骨架无 /run） |
| 194 | `cat /etc/passwd` | no（命令表 partial、按路径 no） | W1 | 1 | 0.016 | 43 | rc=1/2 | 沙箱 /etc 白名单不含账号文件 aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| 195 | `getent group` | no | W1 | 0 | 0.015 | 0 | rc=0·零字节，被沙箱视图挡了 | 沙箱 /etc 白名单不含组文件；没有输出不等于宿主无组 aik-sandbox.c:274-281（/etc 白名单仅 4 文件；passwd/group/sudoers 不挂） |
| 196 | `ps -eo user,tty,stat,comm` | no | W1 | 0 | 0.018 | 82 | rc=0·不是宿主数据 | 表头是进程清单，且仅来自隔离 PID 视图，不能确认宿主登录会话 aik-sandbox.c:2832-2835,2301-2304（CLONE_NEWPID + 新挂 procfs：只见沙箱自身进程） |
| 197 | `cat /sys/kernel/debug/kunit/results` | no（命令表 partial、按路径 no） | W1 | 1 | 0.016 | 63 | rc=1/2 | 沙箱未挂 debugfs，该路径缺失；未测宿主测试状态 aik-sandbox.c:2157-2164（/sys 新挂只读，全局节点可见） |

## 15. 当批差异与既有静态修订

- a：静态可读样例在该批未返回所需数据；错误参数和依赖节点缺失均在行注记中说明。
- b1：静态判不可读，实测有相符数据；b2：静态判不可读，退出 0 但没有相符数据。
- c：退出 0 且长度为 0；可能因为样例只检查连接，也可能因为视图缺失。

| 批次 | a | b1 | b2 | c | 零长度涉及对象 | 非零但读到数据 |
|---|---|---|---|---|---|---|
| 17.10 · 采集 1 | 5（#17、#24、#46、#68、#87） | 0（—） | 19（#13、#19、#30、#31、#32、#33、#34、#38、#43、#48、#51、#52、#62、#65、#80、#110、#114、#118、#124） | 10（#30、#31、#32、#33、#38、#43、#52、#62、#118、#124） | ID-01、ID-03、PKG-01、PKG-04 | #54 |
| 17.11.1 · 采集 2 | 10（#125、#128、#138、#147、#151、#158、#159、#160、#161、#162） | 0（—） | 4（#185、#193、#195、#196） | 3（#127、#193、#195） | ID-02、NET-07 | — |

以下静态修订沿用 17.10 审计，保留既有 W2 和运行态约束。

| 命令 | 改前 | 改后 | 依据 |
|---|---|---|---|
| `lsmem` | ok | no | 出厂机实测 rc=1：没有 /sys/devices/system/memory。出厂内核 .config 未设 CONFIG_MEMORY_HOTPLUG，宿主上同样没有——不是沙箱挡的，是这条命令在出厂内核上本来就跑不了 |
| `lslocks` | ok | no | 出厂机实测 rc=0、零字节。/proc/locks 按读取端 procfs 所属的 PID 命名空间过滤（linux-6.18.39 fs/locks.c:2892-2898），沙箱里列得出的是沙箱自己进程的锁——原先当成「/proc 全局节点」是错的 |
| `mount` | no | partial | 出厂机实测 rc=0、1515 字节：不带参数的 mount 是列挂载表，读操作、不需要 CAP_SYS_ADMIN；列的是沙箱自己的挂载表（同 findmnt）——原先把「挂载动作要能力」错套到了只读的列表上 |
| `swapon` | no | ok | 出厂机实测 rc=0、59 字节（表头 + 1 行）：--show 读 /proc/swaps（全局节点）列出宿主的 swap，不需要 CAP_SYS_ADMIN——同上，错把 swapon 动作的前提套到了 --show 上 |
| `top` | no | partial | 出厂机实测 rc=0、603 字节，首行是宿主的运行时长与负载：汇总行是宿主数据，进程表只见沙箱自己——原先「同 ps」判成 no，漏了汇总行 |

## 16. 对象级判定（每个版本独立）

| 批次 | 适用对象 | 静态可读 | 数据已证 | 部分已证 | 实测不可读 | 未定 | 未测 | 静态不可达已印证 | 静态不可达待证 | 静态不可达却测得 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 17.10 · 采集 1 | 90 | 81 | 9 | 4 | 0 | 6 | 62 | 3 | 6 | 0 |
| 17.11.1 · 采集 2 | 90 | 81 | 12 | 14 | 0 | 6 | 49 | 2 | 7 | 0 |

对象对照只匹配同一参数；例外是已核对的回环超时选项和策略读取的输出格式。视图探针、同命令的其他样例和未走过的宿主工具均不填充缺失证据。

| 对象 | 17.10 · 采集 1 | 17.11.1 · 采集 2 |
|---|---|---|
| PROC-01 进程枚举与属性 | 未测<br>`ps -eo pid,ppid,stat,comm` [rc=0·不是宿主数据] | 未测 |
| PROC-02 线程 | 未测 | 未测 |
| PROC-03 调度属性与内核控制 | 未测 | 未测<br>`ps -eo pid,ni,pri,comm` [rc=0·不是宿主数据] |
| PROC-04 进程内存/IO/文件描述符 | 未测 | 未测 |
| PROC-05 进程 cgroup 归属 | 未测 | 未测<br>`cat /sys/fs/cgroup/cgroup.procs` [rc=1/2] |
| RES-01 CPU 拓扑/型号 | 未定：另有未测或未判读的路径<br>`lscpu -J` [输出来源或含义待证] | 实测读到<br>`cat /proc/cpuinfo` [读到宿主数据] |
| RES-02 CPU 使用率/负载 | 实测读到<br>`uptime` [读到宿主数据]<br>`vmstat 1 2` [读到宿主数据] | 实测读到<br>`cat /proc/stat` [读到宿主数据] |
| RES-03 CPU 频率/调频 | 未测 | 未定：另有未测或未判读的路径<br>`cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` [rc=1/2] |
| RES-04 内存/swap | 实测读到<br>`free -b` [读到宿主数据]<br>`cat /proc/meminfo` [读到宿主数据] | 实测读到（仅一部分）<br>`cat /proc/swaps` [读到一部分] |
| RES-05 PSI 压力（CPU/内存/IO） | 未测 | 实测读到<br>`cat /proc/pressure/cpu` [读到宿主数据]<br>`cat /proc/pressure/memory` [读到宿主数据]<br>`cat /proc/pressure/io` [读到宿主数据] |
| RES-06 块 IO 统计 | 实测读到<br>`vmstat -d` [读到宿主数据] | 实测读到<br>`cat /proc/diskstats` [读到宿主数据]<br>`cat /sys/block/sda/stat` [读到宿主数据] |
| RES-07 IO 调参（预读/优先级/带宽） | 未测 | 实测读到（仅一部分）<br>`cat /sys/class/bdi/8:0/read_ahead_kb` [读到一部分] |
| CG-01 cgroup v2 层级/限额 | 未测 | 未测<br>`cat /sys/fs/cgroup/cgroup.controllers` [rc=1/2] |
| CG-02 cgroup 统计/AI 推理计数 | 未测 | 未测<br>`cat /sys/fs/cgroup/memory.current` [rc=1/2] |
| FS-01 文件内容读取 | 未测 | 未测 |
| FS-02 目录枚举 | 未测 | 未测 |
| FS-03 元数据/链接 | 实测读到（仅一部分）<br>`stat /usr/local/bin/occ` [读到一部分] | 未测 |
| FS-04 文件写入/编辑 | 未测 | 未测 |
| FS-05 删除/重命名 | 未测 | 未测 |
| FS-06 文件 ACL | n/a | n/a |
| FS-07 扩展属性 xattr | n/a | n/a |
| FS-08 文件属性 chattr/lsattr | 实测读到（仅一部分）<br>`lsattr /usr/local/bin/occ` [读到一部分] | 未测 |
| FS-09 文件完整性/校验和 | n/a<br>`sha256sum /etc/aikernel/policy.conf` [读到一部分] | n/a |
| FS-10 磁盘配额 | n/a<br>`quota --help` [rc=127·没有这个命令] | n/a |
| DISK-01 块设备/分区 | 未定：另有未测或未判读的路径<br>`lsblk -J` [输出来源或含义待证]<br>`blkid -o export` [rc=1/2] | 实测读到<br>`cat /proc/partitions` [读到宿主数据] |
| DISK-02 文件系统/挂载 | 未测<br>`dumpe2fs -h /dev/sda1` [rc=1/2] | 未定：另有未测或未判读的路径<br>`cat /proc/mounts` [rc=0·不是宿主数据] |
| DISK-03 SMART/磁盘健康 | 不可达·实测确认<br>`smartctl -a /dev/sda` [rc=1/2] | 不可达·未测 |
| DISK-04 LVM/逻辑卷 | 未定：另有未测或未判读的路径<br>`lsblk -J` [输出来源或含义待证] | 未测 |
| DISK-05 磁盘用量/inode | 实测读到（仅一部分）<br>`df -P` [读到一部分]<br>`du -x -d1 /var` [rc=0·不是宿主数据] | 未测 |
| DISK-06 TRIM/软 RAID/dm | 未定：另有未测或未判读的路径<br>`lsblk -J` [输出来源或含义待证] | 实测读到（仅一部分）<br>`cat /proc/mdstat` [读到一部分] |
| SYS-01 units/服务状态 | 未测<br>`systemctl list-units --no-pager` [rc=1/2] | 未测 |
| SYS-02 失败单元 | 不可达·未测 | 不可达·实测确认<br>`systemctl --failed --no-legend` [rc=1/2] |
| SYS-03 journal 日志 | 未测 | 未测 |
| SYS-04 内核日志/dmesg | 实测读到<br>`dmesg --color=never` [读到宿主数据] | 未测 |
| SYS-05 启动链 A/B/内核参数 | 未测<br>`aik-upgrade status` [rc=0·不是宿主数据] | 实测读到（仅一部分）<br>`cat /proc/cmdline` [读到一部分] |
| SYS-06 启动耗时 | 不可达·实测确认<br>`systemd-analyze time` [rc=1/2] | 不可达·未测 |
| SYS-07 timers/计划任务总览 | 未测 | 未测<br>`systemctl list-timers --no-pager` [rc=1/2] |
| SYS-08 unit 配置/drop-in | 未测 | 未测 |
| NET-01 接口/链路/网卡诊断 | 未测<br>`ethtool eth0` [rc=127·没有这个命令] | 实测读到<br>`ip -j link` [读到宿主数据]<br>`cat /sys/class/net/eth0/statistics/rx_bytes` [rc=1/2] |
| NET-02 地址/路由 | 实测读到<br>`ip -j addr` [读到宿主数据] | 实测读到（仅一部分）<br>`ip -j route` [读到一部分]<br>`cat /proc/net/route` [读到一部分] |
| NET-03 连接/套接字 | 实测读到<br>`ss -tunl` [读到宿主数据] | 实测读到（仅一部分）<br>`cat /proc/net/tcp` [读到一部分] |
| NET-04 conntrack 连接跟踪 | 未测<br>`conntrack -L` [rc=127·没有这个命令] | 实测读到<br>`cat /proc/net/nf_conntrack` [读到宿主数据] |
| NET-05 DNS 解析配置 | 实测读到（仅一部分）<br>`nslookup 127.0.0.1` [读到一部分]<br>`resolvectl status` [rc=1/2] | 实测读到（仅一部分）<br>`cat /etc/resolv.conf` [读到一部分] |
| NET-06 防火墙/LSM 策略 | 未测<br>`nft list ruleset` [rc=1/2] | 未测<br>`cat /sys/kernel/security/apparmor/profiles` [rc=1/2] |
| NET-07 网络命名空间 | 未测 | 未测<br>`ip netns list` [rc=0·零字节] |
| NET-08 接口配置/qdisc | 未测 | 实测读到（仅一部分）<br>`ip -d -j link` [读到一部分]<br>`cat /sys/class/net/eth0/mtu` [rc=1/2] |
| ID-01 用户账户 | 未测<br>`getent passwd` [rc=0·零字节] | 未测<br>`cat /etc/passwd` [rc=1/2] |
| ID-02 组/成员 | 未测 | 未测<br>`getent group` [rc=0·零字节] |
| ID-03 登录会话 | 未测<br>`who` [rc=0·零字节] | 未测<br>`ps -eo user,tty,stat,comm` [rc=0·不是宿主数据] |
| ID-04 sudoers | 未测 | 未测<br>`aikctl policy get sudoers` [rc=1/2] |
| ID-05 授权策略/租约 | 未定：另有未测或未判读的路径<br>`aikctl policy get` [输出来源或含义待证] | 实测读到（仅一部分）<br>`aikctl policy get` [读到一部分] |
| ID-06 SSH 服务配置 | 未测 | 未测 |
| ID-07 SSH authorized_keys | 未测 | 未测 |
| ID-08 SSH 主机密钥状态 | 未测 | 未测 |
| PKG-01 已安装包 | 未测<br>`dpkg-query -W` [rc=0·零字节] | 未测 |
| PKG-02 仓库/源 | 未测 | 未测 |
| PKG-03 可用更新 | 不可达·未测 | 不可达·实测确认<br>`apt list --upgradable` [其它非零退出] |
| PKG-04 安装/卸载/升级 | 不可达·实测确认<br>`dpkg-query -W` [rc=0·零字节] | 不可达·未测 |
| PKG-05 依赖/版本/内核模块 | 实测读到<br>`uname -r` [读到宿主数据] | 未测 |
| HW-01 CPU 硬件 | 未定：另有未测或未判读的路径<br>`lscpu -J` [输出来源或含义待证] | 未测 |
| HW-02 GPU/显示 | 未测 | 未定：另有未测或未判读的路径<br>`cat /sys/class/drm/card0/status` [rc=1/2] |
| HW-03 温度/风扇 | 未测 | 未定：另有未测或未判读的路径<br>`cat /sys/class/thermal/thermal_zone0/temp` [rc=1/2]<br>`cat /sys/class/hwmon/hwmon0/temp1_input` [rc=1/2] |
| HW-04 电源/电池 | 未测 | 实测读到（仅一部分）<br>`cat /sys/class/power_supply/ACAD/online` [读到一部分] |
| HW-05 PCI/USB/设备树 | 未测 | 未定：另有未测或未判读的路径<br>`cat /sys/bus/pci/devices/0000:00:02.0/vendor` [rc=1/2]<br>`aikctl compat hw` [输出来源或含义待证] |
| AI-01 /proc/ai/status | 未测 | 实测读到<br>`cat /proc/ai/status` [读到宿主数据] |
| AI-02 /proc/ai/control 参数表 | 未测 | 实测读到<br>`cat /proc/ai/control` [读到宿主数据] |
| AI-03 决策/因果链 | 未测 | 未测 |
| AI-04 遥测/netlink SENSE | 未测 | 未测 |
| AI-05 AI 统计计数 | 未测 | 实测读到<br>`cat /proc/ai/hitrate` [读到宿主数据]<br>`cat /proc/ai/latency` [读到宿主数据]<br>`cat /sys/kernel/ai/stats/telemetry_emitted` [读到宿主数据]<br>`cat /sys/kernel/ai/stats/decisions_total` [读到宿主数据]<br>`cat /sys/kernel/ai/stats/runtime_state` [读到宿主数据] |
| AI-06 内核模型加载/推理 | 未测 | 实测读到（仅一部分）<br>`cat /proc/ai/status` [读到一部分] |
| AI-07 策略/回滚 | 未测 | 实测读到（仅一部分）<br>`cat /sys/kernel/ai/decision/stats` [读到一部分]<br>`cat /proc/ai/hitrate` [读到一部分] |
| AI-08 KUnit/内核测试 | 实测读到<br>`dmesg --color=never` [读到宿主数据] | 未测<br>`cat /sys/kernel/debug/kunit/results` [rc=1/2] |
| MEM-01 SME 健康/统计 | 实测读到<br>`curl -s http://127.0.0.1:8000/health` [读到宿主数据] | 实测读到<br>`curl -s http://127.0.0.1:8000/stats` [读到宿主数据] |
| MEM-02 记忆 CRUD/检索 | 未测 | 未测 |
| MEM-03 事实图谱/多跳 | 未测 | 未测 |
| MEM-04 Region 空间聚类 | 未测 | 未测 |
| MEM-05 QA/画像/指标/配置 | 未测 | 未测 |
| MEM-06 trace JSONL 文件 | 未测 | 未测 |
| MEM-07 训练导出 | n/a | n/a |
| MEM-08 会话历史 | 不可达·未测 | 不可达·未测 |
| SB-01 隔离区列表/状态/资源限额 | 不可达·未测 | 不可达·未测 |
| SB-02 沙箱资源限制 | 不可达·未测 | 不可达·未测 |
| SB-03 隔离区产物/残留 | 未测 | 未测 |
| SB-04 spawn/destroy 生命周期 | 不可达·未测 | 不可达·未测 |
| SB-05 子智能体工具面/子会话 trace | 未测 | 未测 |
| DT-01 桌面健康/统计 | 未测 | 实测读到<br>`curl -s http://127.0.0.1:8091/api/health` [读到宿主数据]<br>`curl -s http://127.0.0.1:8091/api/stats` [读到宿主数据] |
| DT-02 应用枚举/启动/关闭 | 未测 | 未定：另有未测或未判读的路径<br>`curl -s http://127.0.0.1:8091/api/apps` [接口返回空清单，未观察到对象] |
| DT-03 窗口 | 未测 | 未测 |
| DT-04 主题/壁纸 | 未测 | 实测读到（仅一部分）<br>`curl -s http://127.0.0.1:8091/api/theme` [读到一部分] |
| DT-05 通知 | 未测 | 未测 |
| DT-06 输入注入（键鼠） | n/a | n/a |
| DT-07 截图 | 未测 | 未测 |
| DT-08 剪贴板 | 未测 | 未测 |
| DT-09 聊天/会话/电源 | 未测 | 未测 |
| TIME-01 时钟/NTP | 未测<br>`timedatectl show` [rc=1/2] | 实测读到（仅一部分）<br>`date` [读到一部分] |
| TIME-02 用户 crontab | n/a | n/a |
| TIME-03 系统 cron/timers | 未测 | 未测<br>`systemctl list-timers --no-pager` [rc=1/2] |

## 17. 跨批清单覆盖

历史清单编号并集 194/198。此处只统计命令覆盖，不生成跨版本对象结论。

当前执行集合见 `occ_reach_probe.sh --list`。桌面 `/api/stats` 与 `/api/theme` 因副作用停用，既有结果保留供复算。会话清单、内核决策、因果链及模型原始输出也已排除。

| 历史清单# | 未采条目 |
|---:|---|
| 166 | `cat /proc/ai/decisions` |
| 167 | `cat /proc/ai/chains` |
| 173 | `cat /sys/kernel/ai/model_out` |
| 183 | `aikctl session list` |

<!-- MAPPING_SHA256: ddb0109c73f1245d95705bab093d6c3d90334b7597046ca8392caff460f35f43 -->
