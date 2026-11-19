# AIKernel 全系统总架构

> 版本：**0.1.0-alpha.17.8.1** · 内核 **Linux 6.18.39 #82（出厂）** · 日期：2026-11-19
> 本文是**唯一的系统总介绍**：读完这一份就能知道 AIKernel 是什么、由哪几层组成、
> 能力与权限怎么走、当前边界在哪。
>
> **权威声明**：本文是导览，不是正典。任何数字/接口与代码、`agent/ai/tools/tools.json`
> 冲突时，**以代码与 tools.json 为准**（本文 2026-11-19 回填 alpha.17.8.1 基线；
> 部分分层数字/表格仍为 2026-10-31 实读，标 ⭐ 处以 tools.json 与代码为准）。
>
> 阅读顺序：本文 → `BUILD.md`（怎么构建）→ `SECURITY.md`（安全模型）
> → `AIKernel/ARCHITECTURE.md`（内核侧细节）→ `agent/ai/docs/ARCHITECTURE-MATRIX.md`（能力矩阵）。

---

## §1 系统理念

- **AI 是系统的最高执政者，人是授权者。** 权力来源不是"进程是 root"，而是 Principal（人）
  签发的显式租约 + 系统审计。
- **系统为 AI 服务**：内核与用户态的一切感知/执行面都是 AI 的器官。
  "系统只是辅助 AI，AI 即是系统"。
- **安全是防"意图被篡改/注入/伪造"，不是限制 AI 能力**：闸门拦的是冒充、越权、提示注入，
  不是给 AI 的手脚上枷锁。危险能力可以存在，但必须**默认关 + 可审计 + 需授权 + 开启后真实可用**。
- **本地与云端模型同权**：同一套工具、租约、审计，provider 只影响路由，不影响能力面。
- **验收标准是"可回滚"，不是"不出事"**：允许不稳定，禁止不可恢复的失败。
- **危险指令处理链**：AI 识别 → 系统暂停 → 向授权者确认。D4 级即使有租约也必须精确短语确认。

## §2 全景：三层 AI 面 + 服务面

```
┌──────────────────────────────────────────────────────────────────────┐
│ 第 3 层  用户态 agent/ai —— 智能与授权                                │
│   occ TUI（出厂默认入口）· aikernel-shell（REPL/clarify 2.0）        │
│   ⭐ 237 工具 / 27 通道 / seed 248（occ 通道 6 工具）                 │
│   lease D0–D4 闸门链 + W2 写域确认门 · 审计落盘 · trace JSONL         │
├──────────────────────────────────────────────────────────────────────┤
│ 第 2 层  in-kernel AIKernel/ 子系统 —— 汇聚与钳制                     │
│   ⭐ 22,629 行 .c + 9,140 行 .h                                       │
│   遥测 per-CPU 无锁 ring（<100ns 预算）· 决策引擎 · 可控参数表        │
│   接口：/sys/kernel/ai/* · /proc/ai/* · NETLINK_AI=31                │
│         （SENSE / ACT / REG / EVENT）· ai cgroup · KUnit              │
│   AI LSM：file_open / file_permission / socket_connect /             │
│           socket_sendmsg / ptrace_access_check / task_kill           │
├──────────────────────────────────────────────────────────────────────┤
│ 第 1 层  kernel-overlays 埋点层 —— 采集与放行                         │
│   ⭐ 169 个 overlay 文件（152 个 .c），主线文件体内插 1–3 行 ai_* 调用 │
│   遥测发射为主 + 少量门控行为修改（总闸关 = 与原生逐位一致）           │
│   + include/linux/ai_accessors.h（AI 写内核状态的唯一入口）           │
├──────────────────────────────────────────────────────────────────────┤
│ 服务面  systemd（出厂 rootfs）                                        │
│   aikernel-api 8761（Bearer）· aikernel-memory 8000（SME REST）·      │
│   ollama 11434 · aik-desktop 8091（Web Demo）· sme-seed（oneshot）·   │
│   autocondensed 8762（上下文压缩判官 REST）· aistreamd（事件流）·     │
│   aik-tls-gateway 8443→8761（mTLS，出厂 disabled）                   │
└──────────────────────────────────────────────────────────────────────┘
```

三层职责一句话：**第 1 层采集与放行，第 2 层汇聚与钳制，第 3 层智能与授权。**

## §3 每层详解

### 3.1 第 1 层：kernel-overlays（仓库 `kernel-overlays/`）

- **做什么**：在干净 Linux 6.18.39 主线文件体内插 1–3 行 `ai_*` 调用（遥测发射为主），
  另有少量门控行为修改与 `include/linux/ai_accessors.h` 门控访问器。
  默认"计数 + 放行"；决策注入总闸关闭时**不改变原生行为**。
- **可复现性**：`build/apply-overlays.sh <clean-tree>` 会把 overlay 复制进干净源码并逐文件校验
  `kernel-overlays/MANIFEST.sha256`。alpha.14.0 验证结果：169 个文件全部匹配，
  干净重建与开发树零差异。
- **验证**：`cd kernel-overlays && sha256sum -c MANIFEST.sha256`。

### 3.2 第 2 层：in-kernel `AIKernel/`

- **做什么**：感知—决策—执行承接层。中枢为遥测 ring、策略引擎、安全边界
  （global_enable / max_impact / rollback）、可控参数表、因果链；子域覆盖
  sched / mm / net / vfs / io / power / interrupt / lock / time / security / virt / bpf。
- **接口面**：`/sys/kernel/ai/*`、`/proc/ai/*`、NETLINK_AI=31（SENSE/ACT/REG/EVENT）、
  `ai.*` 启动参数、ai cgroup 控制器、KUnit 套件。
- **W80（内核 #61）新增**：
  - config 新开 `OVERLAY_FS`、`NETFILTER_ADVANCED` + `NETFILTER_NETLINK_QUEUE`、
    `BPF_LSM`、`CGROUP_BPF`（实测新增 8 个 `=y`，0 个被关）；
  - AI LSM 扩到**任务级 workspace 标签**（LSM blob，fork 继承）+ **三维规则**
    （pid > label > path_prefix）+ `socket_connect` / `socket_sendmsg` /
    `file_permission` 三个新 hook；
  - 修正多令牌 `lsm=` 只注册首个的问题（真根因是 `MAX_LSM_COUNT` 未计入内建 `ai`，
    修在 `include/linux/lsm_count.h`）；
  - qemu 实测：`lsm=selinux,ai,bpf` → `capability,selinux,ai,bpf` 四个同时注册。
- **文件入口**：`AIKernel/ARCHITECTURE.md`（内核侧滚动架构）、`AIKernel/security/ai_lsm.c`。

### 3.3 第 3 层：用户态 `agent/ai/`

五层速览：

1. **入口 / REPL**：`shell/aikernel_main.c`、`shell/shell.c`
2. **命令层**：`shell/commands/`（`cmd_ask.c` 为核心）
3. **Runtime / Provider**：`runtime/`、`provider/`、`cloud/`、`local/`
4. **注册 / 执行 / 权限**：`tools/tool_registry.c`、`tools/executor.c`、`policy/ai_lease.c`
5. **追踪 / 会话 / 沙箱**：`trace/ai_trace.c`、`~/.aikernel/{trace,sessions}`、`sandbox/aik-sandbox.c`

⭐ 能力面（`tools/tools.json` 实数）：**237 工具 / 27 通道**（2026-11-19 复核；
下表通道分布为 2026-10-31 实读快照，17.x 增量见下方「近期演进」）：

| 通道 | 数量 | 通道 | 数量 | 通道 | 数量 |
|---|---|---|---|---|---|
| procfs-read | 36 | memory | 30 | netlink-act | 27 |
| sysfs-write | 25 | desktop | 20 | macro | 13 |
| netadmin | 7 | stream | 6 | workspace | 6 |
| sched | 5 | model | 5 | bpf | 4 |
| sandbox | 4 | sysctl | 3 | sysfs | 2 |
| exec / shell / interaction / netlink-sense | 各 1 | | | | |

9 个能力域（多归属）：aicore 56 / res 51 / netsec 36 / memory 30 / sysadmin 29 /
fs 23 / desktop 20 / sandbox 10 / model 6。

**W79 新增**：`workspace` 通道（loop+ext4 持久盘，一个文件就是一个盘，跨调用持久、
幂等销毁、崩溃一致性与 quota 回滚已实现）；`sched` 通道（双调度台：10 个可写旋钮、
`sched.mode` 切换与快照、A/B 对照 harness）。

**W80 新增**：`bpf` 通道（裸 `bpf()` 系统调用加载/查询/卸载，无 libbpf；
`nfqueue_pump` 走裸 nfnetlink，把包交用户态判决）。

**近期演进（alpha.17.x，2026-11）**：出厂默认交互入口从 aikernel-shell 切换为 **occ TUI**
（aikernel-shell 源码仍在树内，不再随 ISO 出厂）；能力面增至 **237 工具 / 27 通道**，
新增 `occ` 通道六工具（read / write / edit / glob / grep / bash，occ 会话内工具面）与
`compat` / `appprofile` / `netchain` / `range` / `device` 等通道；静态 IP 工具
`config_write_network` 经 `OCC_NETCFG_TOOLS=1` 旗控注册（默认清单零变化）。
occ 面自带 **W2 写域确认门**（越界写须确认）、/su 提权档位、undo/redo 快照
（sha256 sidecar + DB manifest 对账外部锚）、会话自动压缩（判官服务见 §3.4）与
`occ unstuck` 解僵命令。

**文件入口**：`agent/ai/docs/ARCHITECTURE-MATRIX.md`（能力→检索→执行→权限→追踪矩阵）、
`tools/tools.json`（**工具单一正典**）、`policy/ai_lease.c`。
注：`agent/ai/core/ai_core.c` 是挂在 agent 目录下的**内核侧**模块，不是用户态代码。

### 3.4 服务面（出厂 rootfs）

| 服务 | 端口（loopback） | 作用 | 出厂状态 |
|---|---|---|---|
| aikernel-api | 8761 | Remote AI API（Bearer 认证） | enabled |
| aikernel-memory | 8000 | SME 记忆引擎 REST | enabled |
| autocondensed | 8762 | 上下文压缩判官 REST（/health /check /judge /begin /commit 等 12 端点；T9d 起改号 8762，8761 让给 aikernel-api） | enabled |
| aistreamd（aikernel-streams） | — | 常驻事件流→SME 记忆（telemetry parquet 落盘） | enabled |
| sme-seed | — | 首启语料差异导入（oneshot） | enabled |
| ollama | 11434 | 本地推理引擎（不预装模型） | enabled |
| aik-desktop | 8091 | 桌面 Web Demo（非完整桌面） | enabled |
| aik-tls-gateway | 8443→8761 | mTLS 入站网关（证书就位才启动） | disabled |

（另有 aik-cron、aik-log-trim+timer、aikernel-health+timer、aikernel-backup+timer、
aikernel-upgrade-commit+timer 等运维单元，见 `factory/etc/systemd/system/` 与
`factory/README.md`。）

## §4 一次 ask 的完整路径（能力—权限—审计）

```
用户 ask（REPL / 8761 API / 8443 mTLS 网关）
  → 路由激活：常驻 R 级工具 + SME 检索命中扩入（上限 32）；cloud=autonomous / local=pre_retrieve
  → clarify 2.0：歧义时结构化反问，而不是猜
  → lease 闸门：D0 只读 / D1 可逆自动 / D2 租约内自动、无租约需确认 /
                D3 必须人工确认 / D4 永不自动（精确短语）；
                沙箱 worker 仅 D0/D1；过期、越界、校验失败一律 fail-closed
  → 执行器按 19 通道分发；exec 通道走白名单（单源 tools.json）
  → 内核承接：sysfs / NETLINK_AI ACT → 策略引擎 → 可控参数表 / 门控访问器
  → 审计：写前读旧值 → 审计 → 写 → 回读；~/.aikernel/audit.log + trace JSONL
```

**近期演进——occ 的 W2 写域确认门三态（alpha.17.7 起，2026-11-19 P-52 分层后现状）**：
occ 工具面对越界写（写域外路径、chmod 使世界可写等）设 W2 确认门，放行与否三态：
①**问**——默认：弹出确认面板（y/Enter 执行、n/Esc 取消），命中判定为语义级
（`w2_chmod_hit`：数字模式 other-write 位 / 符号 o+w / +x 落世界可写文件=两步等效 777；
curl/wget 外发旗标同表）；②**豁免**——本次会话经 confirm/allow_w2 确认后置位
`w2_confirmed`，特权档越界写豁免（`~/.occ` 红线仍双保险）；③**硬拒**——受限档
tier 闸直接拒绝，不弹面板（档位决定要不要问）。与 lease D0–D4 链并行：
lease 管内核/系统面动作的授权分级，W2 门管文件写域的越界确认。

## §5 当前边界（诚实清单）

- **装机盘默认不带 bpf LSM**（B-105）：ISO 光盘引导为 `lsm=ai,bpf`，但安装器写入目标盘的
  grub 仍是 `lsm=ai`。装机后 BPF LSM 程序可加载但 hook 不生效（工具会告警，不假成功）。
- **contentcheck 的 LSM 断言测错对象**（B-106）：在 `chroot` 里读 `/sys`，读到的是 Live
  环境而非装机盘配置，恒真；已记入缺陷账本。
- **MCE 埋点在 noinstr 路径调 snprintf**（B-104）：`do_machine_check` 是 `noinstr`，
  objtool 报警；属既有债，待改为延迟发射。
- **W76 桌面是 Web Demo**：8091 是浏览器演示面，不是完整桌面环境，真实 GUI 控制面未做。
- **语义全知 70.1%**（B-036）：97 个对象读路径 96.9%，但"结构化 + 语义"仅 70.1%。
- **AI LSM 规则维度刚扩展**：label 与 path_prefix 规则已在内核就绪，但用户态规则注入
  ABI 尚未开放（当前只有 `sec.ws_label` + KUnit）。
- **加密私钥 PEM 解析被裁剪**：明文 EC/RSA 私钥可解析，加密容器不支持。
- 工具/通道数以 `tools.json` 实时为准；能力面主数字已按 2026-11-19 复核（237 工具 / 27 通道），
  分层表格与部分行数仍为 2026-10-31 实读快照。

## §6 关键文件在哪

| 想知道 | 看这里 |
|---|---|
| 怎么构建 | `BUILD.md` |
| 安全模型与红线 | `SECURITY.md` |
| 内核子系统细节 | `AIKernel/ARCHITECTURE.md` |
| 能力/通道/风险矩阵 | `agent/ai/docs/ARCHITECTURE-MATRIX.md` |
| 工具单一正典 | `agent/ai/tools/tools.json` |
| 内核改动清单 | `kernel-overlays/MANIFEST.sha256` + `README.md` |
| 前端入口 | `README.md` |

---
*本文 2026-10-31 由三份分散文档（原 SYSTEM-ARCHITECTURE.md / agent/ai/docs/ARCHITECTURE.md /
README 概览段）合并而成。修改时请同步 §2 图内数字与 §5 边界。*
