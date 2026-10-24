# AIKernel W75 能力缺口清单

> 由 `agent/ai/tools/audit_capabilities.py` 生成；生成时间 2026-10-24T15:11:38+0800。优先级：P0 阻断 alpha.10 / P1 日常使用阻断 / P2 功能正确性 / P3 体验与文档。

## 1. 汇总

| 优先级 | 数量（open） |
|---|---:|
| P0 | 0 |
| P1 | 13 |
| P2 | 15 |
| P3 | 5 |
| 已关闭（W76） | 3 |

- G-001 已由 W74 落地（租约 JSON、`/lease` Principal CLI、`--lease` 加载、D0-D4 gate）；条目保留为**残余硬化（P2）**，不再计为 P0 能力缺口。
- G-002/G-015/G-035 已由 W76 关闭（20 件 `desktop_*`、D0-D3、租约/审计、10/10+12/12）；G-033（电源 501）保持开放。

## 2. 缺口清单（open）

| gap_id | 对象/能力 | 现状 | 为什么是黑箱/缺口 | 建议波次 | 验收样例 |
|---|---|---|---|---|---|
| G-003 | trace/训练导出/会话 | trace JSONL 与 session JSONL 可由 cat 读取；`ai trace stats\|dump\|export` 仅 CLI，无 Agent 工具 | AI 只能逐行读原始 JSONL，不能按 session/turn 聚合；训练导出无法由 AI 触发 | W82 | trace.stats/session/export 三个工具返回 JSON；export 产物可被训练管线直接消费 |
| G-004 | 文件 ACL | getfacl/setfacl 在 L1 存在但不在 exec 白名单；Agent 只能通过 python3/sys_shell 逃逸 | ACL 是文件权限的一等状态，当前对 AI 是黑箱；无法审计“谁能读这个文件” | W84 | acl_get(path) 返回 owner/group/entries JSON；acl_set 为 D2 并保留回滚 |
| G-005 | 文件 xattr | getfattr/setfattr 在 L1/VM 均缺失；Agent 只能 python3 os.listxattr 逃逸 | SELinux/AppArmor/用户扩展属性不可见；安全标签与自定义元数据无法审计 | W84 | xattr_list/get/set 工具；set 为 D2；未知属性名明确报错 |
| G-006 | 文件属性 chattr/lsattr | lsattr/chattr 在 L1 存在但不在白名单；VM 未验证 chattr | immutable/append-only 等属性直接影响 AI 写入可行性，当前不可见 | W84 | file.attrs_get 显示 flags；attrs_set 为 D2/D3 且拒绝 immutable 自锁 |
| G-007 | 磁盘配额 | quota/repquota 二进制在 L1 与生产 VM 均缺失；setquota 也缺失 | 无法读用户/组配额与超限状态；多用户磁盘治理是黑箱 | W84 | quota.get(user/group) 返回 blocks/inodes soft/hard；缺失时明确 unavailable |
| G-008 | SMART/磁盘健康 | smartctl 已注册为 R 命令但 L1/VM 均无二进制；无替代语义接口 | 磁盘故障前兆（重映射/待定扇区/温度）对 AI 不可见；只能等 IO 错误 | W85 | disk.smart(dev) 返回 health/attrs JSON；无 SMART 设备明确 unavailable |
| G-009 | 包管理状态/仓库 | 无 package 域；已安装包只能 cat /var/lib/dpkg/status（原始大文本）或 dpkg -l（W2 确认）；仓库只能 cat sources.list | 包状态/仓库是系统配置的一等对象，当前没有结构化视图，读取还被 W2 化 | W84 | package.list/search/info/repos 返回 JSON；读操作 R，安装/卸载 W2 |
| G-010 | 可用更新 | `apt list --upgradable` 为 W2；无 R 读路径，无缓存/时间戳语义 | “系统是否落后/是否有安全更新”是最高频运维问题，却不能免确认读取 | W84 | package.updates 返回可升级包/安全等级/缓存年龄 JSON，R 级 |
| G-011 | systemd unit 配置/drop-in | config_write_* 只覆盖 fstab/nftables/sshd/resolv/hosts/hostname；unit 文件只能 sys_shell | AI 能重启服务却不能安全地编辑 unit/drop-in；写路径只剩交互 shell，不可审计/无回滚 | W84 | service.unit_get/set 带 diff 预览、校验、原子替换与回滚；D2/D3 分级 |
| G-012 | sudoers/policy | sudoers 仅 root 可 cat；policy.conf 仅原始文本；无写入工具（visudo 只能 shell）；W74 只解决了租约，不解决 sudoers/policy 的结构化读写 | D4 身份/授权状态仍不可结构化读取，修改无预览/无回滚；与已落地的 lease 面分离，属于 policy 管理缺口 | W84 | identity.policy_get 返回结构化规则；policy_set 为 D4，强制确认+回滚 |
| G-013 | SSH 密钥 | authorized_keys/host key 仅 cat/ls/stat；无 key 管理工具；ssh-keygen 只能 shell | 无法枚举指纹/注释/有效期，无法安全轮换；密钥是 D4 资产 | W83 | ssh.keys_list 返回指纹/类型/注释；rotate 为 D4 且保留旧 key 回滚窗口 |
| G-014 | PSI | 3 个 PSI 工具已注册且带 probe；生产 VM /proc/pressure 不存在，工具 unavailable；L1 有 PSI | 生产内核缺 CONFIG_PSI 或 psi=0，内存/IO 压力前兆在生产环境不可读 | W78 | 生产内核启用 PSI；3 工具在 VM 返回 some/full 数据；回归 50 场景 |
| G-016 | 沙箱子会话 trace | sandbox_spawn 子进程 trace 未回收；父只拿到 stdout 尾部 4KB | 子智能体的工具调用/拒绝/错误没有进入父 trace，训练与审计链断裂 | W80 | 子会话 trace 合并到父 session 或独立可检索；tool_call 100% 可关联 parent_turn |
| G-001 | 租约/授权（W74 已落地；残余硬化） | W74 已落地：租约 JSON 存于 /var/lib/aikernel/leases/*.json，确认存于 /run/aikernel/confirm；/lease list\|show\|issue\|revoke\|confirm 为 Principal root+TTY 命令；AI 可 cat JSON、用 --lease 加载，但无 lease_request/自签工具。残余：B-044 进行中 D3 不能中止/回滚；B-045 root AI 可经 python3/apt 改写租约存储；B-046 无密码学签名/TOCTOU；B-047 D4 工具未注册；B-048 danger 表未外化；B-049 gate 先记 ALLOW 后路径拒绝；B-050 旧 ai_policy_gate_reason 兼容 API；B-051 同 UID 可改自己的 audit.log | 能力缺口已关闭：租约/确认/D0-D4 映射均在，D2+ 有 lease_id；剩余是 Principal-only 写、无签名/独立 broker 与审计/回滚硬化，不阻断 alpha.10 的“有租约”目标，但须作为残余风险跟踪 | W74b/W83/W86 | lease_request（AI 申请/Principal 审批）；Ed25519/TPM 签名或独立 broker；D3 中止/回滚；D4 工具注册；红队用例通过 |
| G-017 | KUnit/测试结果 | /sys/kernel/debug/kunit 不存在（VM debugfs 已挂载但无 kunit 节点）；只能 dmesg grep | 内核测试结果无结构化读取接口，AI 无法判断回归 | W78 | kunit.results 返回 suite/case/pass/fail JSON；无测试时明确空态 |
| G-018 | LVM | pvs/vgs/lvs 在 L1/VM 均缺失；只能 lsblk 看 dm 映射与 /sys/block | PV/VG/LV 拓扑、剩余空间、快照不可结构化读取 | W85 | storage.lvm 返回 pv/vg/lv JSON；缺失 lvm 工具时明确 unavailable |
| G-019 | 网卡链路诊断 | ethtool 在 L1 存在但生产 VM 缺失；只能 sysfs/ip 原始字段 | 速率/双工/错误计数/环参数不可读，链路故障诊断退化 | W85 | net.link_info(if) 返回 speed/duplex/errors/rings JSON |
| G-020 | conntrack 用户态工具 | conntrack 二进制在 VM 缺失；procfs_read_net_nf_conntrack 仍可读表 | 无法按条件查询/统计连接跟踪，只能全表 cat | W85 | net.conntrack_query 支持 proto/src/dst/state 过滤，返回 JSON |
| G-021 | AppArmor/LSM 状态 | aa-status/apparmor_status 在 VM 缺失；只能读 /sys/kernel/security/apparmor 原始文件 | LSM 执行档位与 profile 命中不可结构化读取 | W83 | security.lsm_status 返回 profiles/mode JSON；与 sec.lsm_override 关联 |
| G-022 | 包依赖/版本 | 只能解析 /var/lib/dpkg/status 原始文本或 dpkg -s（W2） | 依赖树/版本约束无法查询，升级影响分析只能靠模型读大文本 | W84 | package.depends(name) 返回 depends/rdepends/conflicts 图 |
| G-023 | 硬件清单/传感器 | 无 lspci/lsusb/sensors 工具；只能用 sysfs_get 读 /sys/class/{drm,hwmon,thermal,power_supply} | 设备型号/驱动/温度/风扇/电池只能逐文件 raw 读取，没有设备对象 | W85 | hardware.inventory/sensors 返回 JSON；无设备明确空态 |
| G-024 | 文件完整性/校验和 | sha256sum/md5sum 不在白名单；只能 python3 hashlib 逃逸 | 无法做发布产物/配置漂移的 D0 校验，供应链验证不可用 | W83 | file.hash(path,algo) 返回 hex/size；大文件限流 |
| G-025 | 登录会话 | loginctl/who 不在白名单；只能 ps + /proc/<pid>/loginuid 推断 | 会话/座位/空闲/远程来源不可结构化读取 | W84 | session.list 返回 user/tty/seat/remote/idle JSON |
| G-026 | cron | crontab 在 VM 缺失且 /var/spool/cron/crontabs 不存在；系统 cron 只能 cat /etc/crontab | 用户定时任务不可枚举/不可写；调度视图不完整 | W84 | schedule.list 合并 cron+timers；cron.set 为 D2 且校验 |
| G-028 | 防火墙运行时规则 | nft 整命令为 W2，`nft list ruleset` 也需确认；config_read_nftables 只读持久化文件 | 运行时规则与持久化配置可能漂移，D0 读取缺失 | W84 | firewall.rules_get 返回 runtime+persistent 差异 JSON，R 级 |
| G-029 | /proc/ai/control 参数 | 27 个参数按行返回 name/domain/min/max/current/default 文本；无 JSON/类型 schema | AI 要自己解析文本才能构造 netlink 写；类型/枚举/单位不明确 | W82 | ai.params 返回 JSON schema（type/unit/enum/range/current） |
| G-032 | 全局 | 进程/文件/网络/包/硬件对象没有进入 SME 世界模型；只有工具语料与运维记忆 | 全知的下一层是“可推理”：当前 AI 能读状态但不能回答跨对象因果（如“哪个 cgroup 的 IO 压力导致 nginx 慢”） | W82 | 对象/关系/时序进入 SME；Top-3 语义检索 ≥98%；可解释命中 |
| G-036 | 语义化覆盖（全局） | structured+semantic 68/97 = 70.1%；typed semantic 仅 10/97 = 10.3%；26 个对象仍是 raw 文本 | 能读不等于能推理：进程/文件/网络/包/硬件仍是自由文本，缺少 schema、单位、枚举与对象关系；W82 无法做跨对象因果 | W82 | 核心 97 对象 structured+ ≥95%；关键 30 对象 typed ≥60%；检索答案可引用 typed 字段与关系 |
| G-027 | 设备树 | /sys/firmware/devicetree 在 x86 不存在；当前平台 N/A | ARM/真机启用后设备树是硬件拓扑主源，当前无读取工具 | W85 | hardware.devicetree 在 ARM 目标返回节点树；x86 返回 N/A |
| G-030 | 文档/注册表漂移 | ARCHITECTURE-MATRIX 仍写 55 个沙箱命令（实际 57）、tools.json 旧 sha/生成时间；gen_registry 文档仍写 EXPECTED_TOOL_COUNT(151) | 文档漂移会让后续波次基于错误口径验收 | W81 | 脚本 --check 断言文档计数与注册表一致；CI 失败即阻断 |
| G-031 | 能力探测 | 只有 3/150 工具带 probe（PSI 三件套）；desktop_* 及其余节点依赖工具无 probe，节点缺失时报“通道不可用”而非“能力不可用” | AI 无法区分“内核没这功能”和“路径写错/权限不足/桌面服务停机”，容易误判 | W81 | 每个 procfs-read/sysfs-write/desktop 工具有 probe；unavailable 有原因码 |
| G-033 | 桌面电源 | desktop_power D3 已注册，但 /api/power 返回 501 unavailable；不执行关机/重启/锁屏；工具如实失败，不伪造成功。G-033 保持开放 | 电源动作 D3 需要 logind/会话绑定与回滚；W76 只完成工具登记与 D3 门禁，后端未接 | W84 | desktop_power 走 logind + D3 确认；有回滚/取消；501 变为真实执行 |
| G-034 | 命名空间 | ip netns list 可用；lsns 不在白名单；只能读 /proc/<pid>/ns/* 的 inode | 无法按 namespace 类型/ID 聚合进程与资源 | W84 | namespace.list 返回 type/id/members JSON |

## 2.1 已关闭（W76）

| gap_id | 对象/能力 | 关闭依据 | 残余风险 |
|---|---|---|---|
| G-002 | 桌面窗口/输入/截图/剪贴板（W76 已关闭） | W76 已关闭：20 件 desktop_* 注册；desktop_windows_list/focus/close、desktop_input_type/key、desktop_screenshot、desktop_clipboard_get/set 均有实现；10/10（含输入后截图/清理 12/12）桌面任务、test_desktop_tools 56/0。残余 W76-R1：Web demo 虚拟窗口 ≠ 真 OS 桌面（W84） | W76-R1（Web demo≠真 OS 桌面，W84） |
| G-015 | 桌面写路径/租约（W76 已关闭） | W76 已关闭：theme/wallpaper/notifications/apps/windows/input/clipboard 写均为一等 desktop_*；D1/D2 + W74 lease/确认 + 回读/previous 恢复/影响提示；curl 不再是唯一路径。desktop_power D3 仍 501 → 由 G-033 单独跟踪 | W76-R2（输入/截图/剪贴板敏感，W83） |
| G-035 | 桌面应用启动（W76 已关闭） | W76 已关闭：desktop_apps_list/launch/close 注册；10-task 01/05 启动 libreoffice-calc 并关闭窗口成功；返回窗口/应用状态 | - |

## 2.2 W76 残余风险（不占用 W75 G 编号，不计入缺口数）

| ID | 风险 | 级别 | 建议 |
|---|---|---|---|
| W76-R1 | Web demo 虚拟窗口 ≠ 真 OS 窗口/进程；不启动宿主应用 | P1 | W84 接 greetd/cage/真 WM；文档明确 backend=web-demo-virtual-window |
| W76-R2 | 输入注入/截图/剪贴板敏感；8091 loopback 无鉴权，本机任意 uid 可调 | P1 | W83 加会话令牌/跨用户隔离；W84 绑定用户会话；读取不脱敏需审计 |
| W76-R3 | 截图依赖 Playwright/chromium（~/.cache/ms-playwright）单点 | P2 | 加 probe/自检；缺失必须 503，不伪造；W81 锁版本 |
| W76-R4 | 8091 demo 单点停机 → 桌面工具 E_DESKTOP_UNAVAILABLE | P2 | W84 系统桌面服务化；Agent 侧保留明确不可用码 |

## 3. 只有 shell / 任意代码能做的事（含完全不可用项）

这些操作在系统里合法，但没有进入工具注册表；AI 只能通过 W2 `python3` 或交互 `sys_shell` 触达，不可检索、不可复用、不可审计。标注“缺二进制”的项连 shell 也不可用。

| 命令/操作 | 能力 | 现状 | 缺口 |
|---|---|---|---|
| getfacl/setfacl | ACL 读写 | L1 有二进制，不在白名单 | G-004 |
| getfattr/setfattr | xattr 读写 | L1/VM 均缺二进制 | G-005 |
| lsattr/chattr | 文件属性 | L1 有二进制，不在白名单 | G-006 |
| quota/repquota/setquota | 配额 | L1/VM 均缺二进制 | G-007 |
| smartctl | SMART | 已注册 R，但 L1/VM 均缺二进制 | G-008 |
| pvs/vgs/lvs | LVM | 已注册 R，但 L1/VM 均缺二进制 | G-018 |
| ethtool | 网卡链路 | L1 有，VM 缺失 | G-019 |
| conntrack | 连接跟踪 | VM 缺失（L1 有） | G-020 |
| aa-status/apparmor_status | LSM | VM 缺失（L1 有） | G-021 |
| lsof | 打开文件 | L1 有，VM 缺失，且不在白名单; /proc/<pid>/fd 可替代 | - |
| loginctl/who | 登录会话 | L1 有，不在白名单；ps/proc 可替代 | G-025 |
| lsns | 命名空间 | L1 有，不在白名单；ip netns/proc 可替代 | G-034 |
| sensors | 温度/风扇 | L1/VM 均无；只能 sysfs raw | G-023 |
| lspci/lsusb | PCI/USB 清单 | 未注册；只能 sysfs raw | G-023 |
| sha256sum/md5sum | 文件校验 | 不在白名单；python3 可替代 | G-024 |
| visudo | sudoers 编辑 | 只能 shell；D4 | G-012 |
| /lease issue\|revoke\|confirm | 租约签发/撤销/确认 | Principal root+TTY；AI 无工具（lease_request 未实现） | G-001 |
| ssh-keygen | SSH 密钥轮换 | 只能 shell；D4 | G-013 |
| ai trace stats\|dump\|export | trace 查询/训练导出 | CLI 内置命令，不在 exec 白名单 | G-003 |
| add-apt-repository | 仓库管理 | 未注册；apt W2 不能等价 | G-009 |
| systemctl edit | unit drop-in | systemctl W2 但 edit 交互式；无结构化写 | G-011 |
| parted/fdisk/mdadm/cryptsetup | 分区/RAID/加密 | 未注册 | - |
| dd | 块设备/镜像 | 未注册 | - |

## 4. 存在但 AI 看不到的接口

| 对象/接口 | 现状 | 缺口 |
|---|---|---|
| 桌面电源（desktop_power） | 工具已注册 D3，但 /api/power 返回 501 unavailable；不执行关机/重启/锁屏 | G-033 |
| trace 聚合/训练导出 | `ai trace` CLI 内置，Agent 只能 cat JSONL | G-003 |
| KUnit 结果 | debugfs 节点不存在；只能 dmesg raw | G-017 |
| 授权租约（AI 写） | W74 已落地租约 JSON 与 /lease（Principal root+TTY）；AI 只能读 JSON/--lease 加载，无 lease_request/自签工具 | G-001 |
| PSI（生产 VM） | 工具已注册但 /proc/pressure 缺失 | G-014 |
| conntrack/ethtool/aa-status/smartctl 等 | 已注册或存在二进制，但生产 VM 缺失 | G-018/G-019/G-020/G-021/G-008 |

## 5. 注册/实现/二进制差异

- 注册/实现差异：0（156/156 工具均有通道实现，desktop 20/20；`--check` 断言）。
- **F-006** (P1): host (L1) missing 15/97 exec binaries: conntrack, smartctl, quota, repquota, pvs, vgs, lvs, traceroute, setquota, aa-enforce, aa-complain, aa-disable, aik-backup, aik-reset, aik-upgrade
- **F-007** (P1): production VM missing 16/97 exec binaries: ethtool, conntrack, smartctl, quota, repquota, pvs, vgs, lvs, aa-status, apparmor_status, traceroute, setquota, aa-enforce, aa-complain, aa-disable, crontab
- **F-017** (P3): exec_run has no top-level risk key; effective risk is command-level (intentional but breaks uniform schema)

## 6. 文档漂移与风险发现

- **F-008** (doc-drift/P3): ARCHITECTURE-MATRIX says 55 sandbox commands; actual 57
- **F-009** (doc-drift/P3): ARCHITECTURE-MATRIX tools.json sha256=6bc7584fe9f912d2b3b4c5b0930ee65db825d9c6e42f978ce4768e0cb901a450 actual=1928f757df941ec113540a31e4c9f3c023ad36bf1a4aefb1f6e268052396e822
- **F-010** (doc-drift/P3): ARCHITECTURE-MATRIX generated_at=2026-10-20 17:13 actual=2026-10-23T04:13:48
- **F-012** (observability/P3): only 3/156 tools declare a capability probe (procfs_read_pressure_cpu, procfs_read_pressure_memory, procfs_read_pressure_io)
- **F-019** (probe/P2): probe unavailable on production VM: /proc/pressure

<!-- GAP_TOTAL: 36 -->
<!-- GAP_P0: 0 -->
<!-- GAP_P1: 13 -->

