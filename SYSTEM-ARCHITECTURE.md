# AIKernel 全系统总架构（SYSTEM-ARCHITECTURE）

> 版本：**0.1.0-alpha.13.0（进行中，W78）** · 日期：2026-10-26
> 本文目标：新人 30 分钟读懂整个系统——三层 AI 面 + 服务面的全景、每层职责与入口、
> 能力-权限-审计链路、入门阅读顺序、当前边界（诚实清单）。
> **权威声明**：本文是导览，不是正典。任何数字/接口与代码、`agent/ai/tools/tools.json`
> 冲突时，以代码与 tools.json 为准（下文数字均标注了实读来源；标 ⭐ 的为本次实读复核）。

---

## §1 系统理念

（口径与 `aikernel-longterm/MASTER-PLAN.md` §0 一致，此处照录）

- **AI 是系统的最高执政者 / 最高领导人，人是授权者**。权力来源不是"进程是 root"，
  而是 Principal（人）签发的显式租约 + 系统审计（`agent/ai/docs/W74-LEASE.md`）。
- **系统为 AI 服务**：内核与用户态的一切感知/执行面都是 AI 的器官；"系统只是辅助
  AI，AI 即是系统"。
- **安全是防"意图被篡改/注入/伪造"，不是限制 AI 能力**：闸门拦截的是冒充、越权与
  提示注入，而非给 AI 的手脚上枷锁。
- **本地/云端模型同权同工具**：provider 差异只影响路由模式（见 §4），不影响能力面。
- **危险指令处理链**：AI 识别 → 系统暂停 → 向授权者确认。D4 级操作即使有租约也必须
  精确短语确认，永不自动放行（W74-LEASE §1）。

## §2 三层 AI 面 + 服务面全景

```
┌─────────────────────────────────────────────────────────────────────┐
│ 第 3 层  用户态 agent/ai —— 智能与授权                              │
│   aikernel-shell（静态 ELF，⭐ 4,565,960 B ≈ 4.4MB）                │
│   REPL 注册命令 20 个（18 业务 + help/exit；chat 为 ask 别名）⭐    │
│   162 工具 / 9 域 / 14 通道（⭐ tools.json 实数，W78 新增           │
│   stream 六件事件流：event_listen / proc_watch /                    │
│   taskstats_sample / nflog_dump / net_monitor / udev_monitor）      │
│   SME 检索激活（常驻 8 件、上限 32、autonomous/pre_retrieve 双模式）│
│   lease D0-D4 闸门链 + clarify 2.0（7 规则+评分探测器）             │
├─────────────────────────────────────────────────────────────────────┤
│ 第 2 层  in-kernel AIKernel/ 子系统 —— 汇聚与钳制                   │
│   ⭐ 19,332 行 .c（不含 test/）+ 9,058 行 .h                       │
│   core/ 中枢：遥测 per-CPU 无锁 ring（<100ns 预算）、决策执行        │
│   ai_policy_execute、可控参数表（⭐ 静态注册 24 个参数名，           │
│   sched/mm/net/io/power/sec/ai.decision 七族；W78A 报告口径 27，     │
│   运行时以 /sys/kernel/ai/control 清单为准）、因果链、               │
│   sysfs/procfs/cgroup                                              │
│   接口面：/sys/kernel/ai/* · /proc/ai/* · NETLINK_AI=31             │
│   （SENSE/ACT/REG/EVENT）· ai.* 启动参数 · ai cgroup 控制器          │
│   W78（内核 #60）：DEBUG_INFO_BTF / PSI / FANOTIFY / INET_DIAG 家族 │
│   / SCHED_CLASS_EXT 编入出厂 .config；grub 出厂命令行追加 lsm=ai     │
│   （w6i-tools/init:270,274）；psi.c 与 kernel/sched/ext.c overlay    │
│   由休眠转活跃                                                     │
├─────────────────────────────────────────────────────────────────────┤
│ 第 1 层  kernel-overlays 埋点层 —— 采集与放行                       │
│   152 个 .c 埋点文件（总目录 168 文件；⭐ W78 README 表：            │
│   145 active / 7 dormant），主线文件体内插 1-3 行 ai_* 调用，        │
│   零物理拆分；遥测发射为主 + 3 处门控行为修改                        │
│   （oom badness / sched 注入 / readahead 档位，总闸                 │
│   /sys/kernel/ai/decision_inject，关=与原生逐位一致）               │
│   + include/linux/ai_accessors.h（AI 写内核状态唯一入口）           │
├─────────────────────────────────────────────────────────────────────┤
│ 服务面  systemd（出厂 rootfs，factory/etc/systemd/system/）         │
│   六个 AI 服务：aikernel-api 127.0.0.1:8761（Bearer）·              │
│   aikernel-memory 127.0.0.1:8000（SME REST）· sme-seed（首启差异     │
│   导入 oneshot）· ollama 127.0.0.1:11434 · aik-desktop               │
│   127.0.0.1:8091（Web Demo）· aik-tls-gateway 127.0.0.1:8443→8761   │
│   （mTLS 网关，出厂 disabled，证书就位前不启动）⭐                  │
│   + 10 个 timers（4 件 AIKernel：aikernel-backup / health /          │
│   aik-disk-check / aikernel-upgrade-commit；6 件系统例行：           │
│   apt-daily / apt-daily-upgrade / dpkg-db-backup / e2scrub_all /     │
│   fstrim / motd-news）⭐                                            │
└─────────────────────────────────────────────────────────────────────┘
```

三层职责一句话：**第 1 层采集与放行，第 2 层汇聚与钳制，第 3 层智能与授权**
（用户态另含 `core/ai_core.c` 一个内核侧文本页模块，见 §3.3 注）。

## §3 每层详解：职责 · 接口 · 文件入口 · 验证命令

### 3.1 第 1 层 kernel-overlays（仓库 `aikernel-repo-alpha11/kernel-overlays/`）

- **职责**：在干净 Linux 6.18.39 主线文件体内插 1-3 行 `ai_*` 调用（遥测发射），
  另有 3 处门控行为修改与 7 个 `include/linux/ai_accessors.h` 门控访问器。
  默认"计数+放行"，决策注入总闸关闭时不改变原生行为。
- **接口清单**（对第 2 层）：遥测发射函数族（`ai_*_telemetry_*`）、门控访问器
  （AI 写内核状态的唯一入口）、`include/linux/ai_netlink.h` 等 UAPI。
- **文件入口**：`kernel-overlays/README.md`（侵入面总表 + W78 active/dormant 表）、
  `MANIFEST.sha256`（逐文件 sha256 清单，152 .c + 16 其他）。
- **现成验证**：`cd kernel-overlays && sha256sum -c MANIFEST.sha256`；
  active/dormant 以 README 表为准（W78 起 psi.c、sched/ext.c 转 active）。

### 3.2 第 2 层 AIKernel/（内核树 `linux-6.18.39/AIKernel/`）

- **职责**：感知-决策-执行承接层。core/ 中枢（模型注册与推理提交、策略引擎与决策
  ring、安全边界 global_enable/max_impact/rollback、可控参数表、因果链、遥测 ring、
  进程分类槽表）+ sched/mm/net/vfs/io/power/interrupt/lock/time/security/virt/bpf
  等子域（模块地图见 `AIKernel/ARCHITECTURE.md` §1）。
- **接口清单**：`/sys/kernel/ai/*`（policy/stats/decision）、`/proc/ai/*`
  （status/sched/vfs…）、NETLINK_AI=31（SENSE 免权限 / ACT / REG / EVENT 异步推送）、
  `ai.*` 内核启动参数、ai cgroup 控制器、KUnit 6 套件。
- **W78 变化**（内核 #60，bzImage ⭐ 19,305,472 B / md5 026e33b7…，0 warning）：
  - .config 新开 DEBUG_INFO_BTF(+DWARF5)/PSI/FANOTIFY/INET_DIAG 家族/SCHED_CLASS_EXT，
    关 DEBUG_INFO_NONE（config.diff 35 行）；
  - grub 模板出厂命令行追加 `lsm=ai` → AI LSM 真实注册
    （dmesg "AI LSM (name=ai id=114) registered, 256 model slots, 64 rule slots"，
    默认放行 + 决策表接管）；
  - sched_ext 编入未激活（/sys/kernel/sched_ext/state=disabled）。
- **文件入口**：`AIKernel/ARCHITECTURE.md`（内核侧滚动架构与波次记录，头部有 W78
  状态注记）、`AIKernel/core/`。
- **现成验证**：VM 内 `cat /proc/ai/status`、`ls /sys/kernel/ai/`、
  `cat /proc/pressure/{cpu,memory,io}`（PSI W78 起存在）、
  `agent/ai` 里 `netlink sense`（NETLINK_AI 通道实测）。

### 3.3 第 3 层 agent/ai（用户态，`agent/ai/`）

- **职责**：智能与授权。REPL/ask 循环 → LLM（本地 ollama / 云端 provider，同权同
  工具）→ 工具注册表 → 执行器 → 闸门 → 审计。五层速览见
  `agent/ai/docs/ARCHITECTURE.md`（入口 REPL / 命令层 / Runtime-Provider /
  注册-执行-权限 / 追踪-会话-沙箱）。
- **接口清单**：
  - REPL 20 个注册命令（⭐ commands_registry.c：help exit status config chat ask
    model network netlink session compact setup-password shell lang plan unplan tools
    sandbox trace lease；其中 chat 为 ask 别名，纯界面类 help/exit 之外业务命令 18 个）；
  - 162 工具 / 9 域（aicore/memory/res/desktop/netsec/sysadmin/fs/model/sandbox）
    / 14 通道（⭐ tools.json channel_counts：procfs-read 36 / sysfs-write 25 /
    netlink-act 27 / netlink-sense 1 / **stream 6（W78 新）** / exec 1 / memory 30 /
    shell 1 / sandbox 4 / sysctl 3 / sysfs 2 / desktop 20 / model 5 / interaction 1）；
  - stream 六件 = "被推即应"事件面：NETLINK_AI EVENT 异步推送、进程事件、任务延迟
    记账、NFLOG 包级证据、rtnetlink 拓扑变化、udev 插拔（内核侧 CONNECTOR/
    TASKSTATS/NFLOG 等早已 =y，W78 前零消费者）。
- **W78 变化**：mbedtls TLS 服务端回开（`config/mbedtls-trim.h:46`，
  MBEDTLS_SSL_SRV_C 恢复，tests/test_tls_srv.c 回环 mTLS 回归）+ 新增
  `cloud/tls_gateway/aik_tls_gateway.py`（mTLS 网关 8443→8761，python3 标准库 ssl，
  服务端 unit `aik-tls-gateway.service` 出厂 disabled）——授权远程模型/操作者安全
  接入 AI 的唯一入站通道。
- **文件入口**：`agent/ai/docs/ARCHITECTURE.md` + `ARCHITECTURE-MATRIX.md`
  （能力→检索→执行→权限→追踪矩阵）、`tools/tools.json`（**工具单一正典**）、
  `tools/tool_registry.c`、`tools/executor.c`、`policy/ai_lease.c`。
  注：`agent/ai/core/ai_core.c` 是挂在 agent 目录下的**内核侧**模块（/proc/aikernel
  文本页，Kconfig AI_AGENT），不是用户态代码。
- **现成验证**：`./aikernel-shell` 进 REPL → `status` / `tools` / `lease list`；
  `python3 -c "import json;print(json.load(open('tools/tools.json'))['tool_count'])"`。

### 3.4 服务面（出厂 rootfs）

| 服务 | 端口（loopback） | 作用 | 出厂状态 |
|---|---|---|---|
| aikernel-api | 8761 | Remote AI API（Bearer 认证） | enabled |
| aikernel-memory | 8000 | SME 记忆引擎 REST | enabled |
| sme-seed | — | 首启接口语料差异导入（oneshot） | enabled |
| ollama | 11434 | 本地推理引擎（alpha.12 起不预装模型） | enabled |
| aik-desktop | 8091 | 桌面 Web Demo（W76） | enabled |
| aik-tls-gateway | 8443→8761 | mTLS 入站网关（W78） | **disabled**（缺证书即退，证书在 /etc/aikernel/tls/） |

配套基础设施服务：dbus / ssh / nftables / systemd-networkd / systemd-resolved。
验证：VM 内 `systemctl status aikernel-api` / `ss -tlnp | grep -E "8761|8000|11434|8091"`。

## §4 能力-权限-审计链路（一次 ask 的完整路径）

```
用户 ask（REPL / 8761 API / mTLS 8443 网关）
  → 路由激活：常驻 8 件 R 级工具（cmd_ask.c:243，W77c 含 clarify）+
     SME 检索命中扩入（上限 32，ASK_ROUTER_MAX_ACTIVE cmd_ask.c:264）；
     双模式：cloud=autonomous（模型自主检索目录页）、
     local=pre_retrieve（框架先检索再注入，cmd_ask.c:2034）
  → clarify 2.0：7 规则 + 评分探测器，歧义时结构化反问而非猜
  → lease 闸门（policy/ai_lease.c）：Principal 租约校验
     （scope/ceiling/expiry/revocation）→ D0 只读 / D1 可逆本地变更自动放行；
     D2 任务租约内自动、无租约需确认；D3 必须人工确认；D4 永不自动放行
     （精确短语确认）；沙箱 worker 仅 D0/D1；plan 只读优先于租约；
     过期/越界/校验失败一律 fail-closed
  → 执行器（tools/executor.c）按 14 通道分发：procfs-read / sysfs-write /
     netlink-act / netlink-sense / stream（W78）/ exec（白名单单源 tools.json）/
     memory / shell / sandbox / sysctl / sysfs / desktop / model / interaction
  → 内核侧承接：sysfs/NETLINK_AI ACT → ai_policy_execute → 可控参数表
     （/sys/kernel/ai/control）或第 1 层门控访问器真实生效
  → 审计落盘：写前读旧值→审计→写→回读，~/.aikernel/audit.log 追加
     （executor.c:297，含 lease/danger/confirm 字段）；全轨迹另见
     ~/.aikernel/trace/（JSONL，schema 见 agent/ai/docs/trace-schema.md）
```

## §5 入门阅读顺序

1. **本文**（SYSTEM-ARCHITECTURE.md）——30 分钟全景；
2. `AIKernel/ARCHITECTURE.md` —— 内核侧正典（模块地图/接口面/波次记录）；
3. `agent/ai/docs/ARCHITECTURE.md` → `ARCHITECTURE-MATRIX.md` —— 用户态正典
   （五层结构/能力-通道矩阵）；
4. `agent/ai/tools/tools.json` —— 162 工具单一正典（名字/通道/风险/参数）；
5. `aikernel-longterm/MASTER-PLAN.md` —— 理念与长线路线；波次细节在
   `aikernel-longterm/reports/`，缺陷账本 `aikernel-longterm/BUGS.md`。

另：`AIKernel_Docs/`（本树顶层）13 份接口导表是 2026-08-13 静态扫描的**冻结快照**
（74 工具旧口径），仅历史参考，见该目录 FREEZE.md——不要当作当前接口面。

## §6 当前边界（诚实清单）

- **W76 桌面是 Web Demo**：aik-desktop 8091 是浏览器演示面，不是完整桌面环境。
- **语义全知 70.1%**（W75 全知审计 B-036）：97 对象读路径 96.9%、结构化+语义 70.1%，
  提升至 W82 目标；账本见 `aikernel-longterm/BUGS.md` B-036。
- **多令牌 lsm= 清单只认首个**（W78 实测发现）：`lsm=selinux,ai` 仅 selinux 生效、
  `lsm=ai,selinux` 仅 ai 生效 → 已 adopt **单令牌 `lsm=ai`**（w6i-tools/init:270,274）；
  多 LSM 并存列入后续项。
- **加密私钥 PEM 解析被 B3 裁剪**：PKCS5/PKCS12 加密容器与写侧裁剪，明文 EC/RSA
  私钥可解析（mbedtls-trim.h W78 注记）——网关私钥为明文 600 存放。
- 工具/命令数以 tools.json 与 commands_registry.c 实时为准（本文件数字为
  2026-10-26 W78 时点实读）。

---
*本文由 W78 文档波（棒3-F）建立；修改请同步更新 §2 图中数字与 §6 边界。*
