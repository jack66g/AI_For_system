# AIKernel 架构矩阵：能力 → 检索 → 执行 → 权限 → 追踪

> 状态注记（2026-10-23，alpha.12.0）： 本文为 W68 系统逻辑收口快照（130 工具/7 域/10 通道）。当前注册表 **156 工具/9 域/11 通道**（W76 +desktop 域 20、W77c +clarify、W77d +model 域 5）；工具数与 sha 以 `tools/tools.json` 为准，后续演进见 `~/aikernel-longterm/reports/`。

状态：W68 系统逻辑收口（2026-10-20），W69B 整理入仓。
源码基线：`agent/ai` 用户态 AI Shell；`tools/tools.json` 130 工具（由
`tools/gen_registry.py` 生成，生成时间 2026-10-20 17:13，sha256
`6bc7584fe9f912d2b3b4c5b0930ee65db825d9c6e42f978ce4768e0cb901a450`；
生成器重跑后 hash 会变化，以文件本身为准）。
生产 VM 为 `aikernel` 6.18.39；部署状态以证据目录为准，本文只描述源码结构。

## 1. 端到端数据流

```mermaid
flowchart TD
  U["用户：PTY REPL / ai -p / API"] --> R["REPL<br/>shell/aikernel_main.c"]
  R --> C["命令层<br/>cmd_ask / cmd_* / cmd_compact"]
  C --> RT["Runtime<br/>provider + backend"]
  RT -->|model_request: messages + tools[]| M[("云端 OpenAI-compatible<br/>或本地 Ollama")]
  M -->|content / tool_calls| C

  C --> ROUTER["路由<br/>autonomous 初始 7 工具<br/>pre_retrieve / memory_search 命中激活"]
  ROUTER --> SME[("SME 127.0.0.1:8000")]
  SME -->|tools_hit| ACT["激活集合<br/>tools.json 130 取子集"]
  ACT --> REG["注册表<br/>tools.json（单源）"]

  C --> EXEC["tool_executor_run<br/>统一入口"]
  REG --> EXEC
  EXEC --> PLAN{"Plan 只读门<br/>非 R 一律拒绝"}
  PLAN -->|R| POL["UID 策略门<br/>policy.conf: privileged/confirmed/restricted<br/>effective risk R/W1/W2"]
  PLAN -->|W1/W2| DENY1["PLAN_DENY<br/>仅 audit"]
  POL -->|W2| CONF{"W2 二次确认<br/>--yes / assume_yes / TTY y/N"}
  CONF -->|拒绝| DENY2["DENY<br/>policy_decision"]
  CONF -->|允许| CH
  POL -->|R/W1| CH

  CH{"channel 10 选 1"}
  CH --> PR["procfs-read 36<br/>固定 path 直读"]
  CH --> SW["sysfs-write 25<br/>固定 path 直写"]
  CH --> NA["netlink-act 27<br/>NETLINK_AI=31 定向 param"]
  CH --> NS["netlink-sense 1"]
  CH --> EX["exec 1 工具 / 97 命令<br/>fork+execv，白名单 + path_check"]
  CH --> ME["memory 30<br/>SME REST"]
  CH --> SH["shell 1<br/>交互 bash（W1）"]
  CH --> SB["sandbox 4<br/>aik-sandbox"]
  CH --> SC["sysctl 3<br/>/proc/sys + 崩溃黑名单"]
  CH --> SD["sysfs 2<br/>动态路径 + realpath 前缀"]

  PR --> K[("/proc /sys /etc 节点")]
  SW --> K
  NA --> NL["内核 ai_control / 策略动作"]
  NS --> NL
  EX --> PROC["子进程（继承 root，stdout/stderr 采集）"]
  ME --> SME
  SC --> PS[("/proc/sys")]
  SD --> K
  SB --> AB["aik-sandbox<br/>NS|PID|UTS + cgroup v2"]
  AB --> SUB["子 ai -p<br/>tools-sandbox.json 受限表"]

  EXEC --> TR[("trace JSONL<br/>~/.aikernel/trace<br/>max 20 文件")]
  POL --> TR
  C --> TR
  RT --> TR
  R --> TR
  C --> SESS[("会话文件<br/>~/.aikernel/sessions")]
  C --> CTX["上下文预算 / 压缩<br/>ctx_len 8192，80% 触发 compact"]

  classDef danger fill:#ffe0e0,stroke:#c00,color:#900;
  class EX,SH danger;
```

## 2. 分层职责

| 层 | 代码入口 | 职责 | 关键输出 |
|---|---|---|---|
| 入口 / REPL | `shell/aikernel_main.c`、`shell/shell.c` | PTY REPL、`ai -p`、粘贴合并、UI | 用户命令、trace 根事件 |
| 命令层 | `shell/commands/cmd_ask.c`、`cmd_*`、`ask_context.c`、`ask_compact.c` | 会话、模型、trace、网络、沙箱、压缩 | provider 调用、工具调用 |
| Runtime / Provider | `runtime/runtime.c`、`provider/provider_core.c`、`cloud/`、`local/`、`runtime/communication/` | 云端/本地 Provider、流式解析、降级 | model_request / model_response |
| 检索 / 路由 | `memory/sme_client.c`、`runtime/runtime.c`、`tools/tools.json` | autonomous 初始 7 工具；SME 命中激活集合 | 激活工具子集 |
| 注册表 | `tools/tool_registry.c`、`tools/tools.json` | 130 工具单一正典、schema、别名、受限表 | 工具定义 / 加载校验 |
| 执行 / 权限 | `tools/executor.c`、`policy/ai_user_policy.c` | plan 只读门、UID 策略门、W2 二次确认、effective risk | tool_call / policy_decision |
| 执行通道 | procfs / sysfs / netlink / exec / memory / shell / sandbox / sysctl | 10 个 channel 的实际落地 | 内核节点、子进程、SME 结果 |
| 追踪 / 会话 | `trace/ai_trace.c`、`~/.aikernel/trace`、`~/.aikernel/sessions` | JSONL 审计、会话持久化、训练导出 | trace 事件、会话文件 |

## 3. 能力域矩阵

| 能力域（工具数） | 检索入口（SME 语料） | 执行通道 / 代表工具 | 权限门 | 追踪事件 |
|---|---|---|---|---|
| res 资源与调度（23） | 区头 `sub/res` + 工具记录 | netlink-act 14（sched/mm/power/proc）W2；procfs-read 8 R；sysfs-write 1 W1 | plan 拒 W；W2 二次确认；客户端 value_min/max 钳制 | tool_call + policy_decision(W2) |
| fs 存储与文件（8） | 区头 `sub/fs` | procfs-read 5；netlink-act 2（io.*）W2；sysfs-write 1 | W1 写路径限 `/root /tmp /var/ai`；W2 确认 | 同上 |
| netsec 网络与安全（16） | 区头 `sub/netsec` | netlink-act 7（net/sec）W2；sysctl/sysfs 动态；procfs 5 | sysctl 崩溃黑名单硬拒；W2 确认；sysfs realpath 前缀 | 同上 |
| aicore AI 内核面（40） | 区头 `sub/aicore` | procfs-read 17；sysfs-write 18；netlink-act 4；netlink-sense 1 | 固定节点 W1/W2；模型/策略写需 root | 同上 |
| memory 长期记忆（30） | 区头 `sub/memory` | memory 30 → SME REST | R 自动；W1 9；W2 3（delete/consolidate/compress） | tool_call；SME 失败额外 degraded |
| sandbox 隔离区（4） | 区头 `sub/sandbox` | sandbox 4 → `aik-sandbox run/create/destroy/status` | spawn W2 确认；子智能体仅 7 工具、55 命令 | tool_call；子会话 trace 未回收 |
| sysadmin 系统管理（9） | 区头 `sub/sysadmin` | exec_run 1（97 命令）、sys_shell 1、sysctl 3、sysfs 2、config 2 | effective risk：命令级 W1/W2；W1 path_check；W2 确认；sys_shell 仅 W1 | tool_call(risk 恒 W1) + policy_decision(effective) |

## 4. 执行通道矩阵

| channel | 工具数 | 权限/风险 | 说明 |
|---|---:|---|---|
| procfs-read | 36 | R | 固定 path 直读 `/proc /sys /etc` 节点 |
| sysfs-write | 25 | W1/W2 | 固定 path 直写；写操作需 root |
| netlink-act | 27 | 多为 W2 | `NETLINK_AI=31`，定向 param；客户端范围钳制 |
| netlink-sense | 1 | R | 内核事件/状态感知 |
| exec | 1 工具 / 97 命令 | W1/W2（effective） | `fork+execv`，命令白名单 + path_check |
| memory | 30 | R/W1/W2 | SME REST；delete/consolidate/compress 为 W2 |
| shell | 1 | W1 | 交互 bash；已知权限面风险（见 §5） |
| sandbox | 4 | W2（spawn） | `aik-sandbox` + NS/PID/UTS + cgroup v2 |
| sysctl | 3 | W1/W2 | `/proc/sys`；崩溃黑名单硬拒 |
| sysfs | 2 | W1/W2 | 动态路径 + realpath 前缀校验 |
| model | 5 | R/W1/W2 | 模型目录/推荐（D0）、基准（D1）、安装/卸载（D2，ai_lease_gate）；W77d，单源引擎 `shell/commands/model_lifecycle.c` |
| desktop | 20 | D0-D3 | 20 件 desktop_*（W76），见 docs/W76-DESKTOP.md |
| clarify | 1 | D0 | 澄清交互（W77c/2.0），仅 ask 交互层执行 |

合计（W68 快照）130 工具（36+25+27+1+1+30+1+4+3+2）；当前另加 desktop 20 + clarify 1 + model 5 = **156**。

## 5. 关键结论（W68）

- **实现覆盖完整**：130/130 工具均有实现函数；SME 语料 130/130；`tools.json`、
  `tools.openai.json`、`tool_catalog.txt`、受限表名称与描述一致。
- **实际执行覆盖不足**：50 个场景只执行 27/130 工具；121/130 至少被下发过；
  9 个从未下发（3 个 PSI 被 probe 过滤 + 6 个配置/网络参数）。
- **exec 可用性缺口**：97 条命令中 16 个二进制在 VM 不存在（9 R + 1 W1 + 6 W2）；
  受限表 55 条中 8 个不存在；能力探测只覆盖 3 个 PSI 工具。
- **权限面存在 W1 逃逸**：`sed e`/`sed w`、`tar --checkpoint-action=exec`、
  `ln` 符号链接 + `tee` 可绕过 W1 路径校验与 W2 确认；`sys_shell` 仍标 W1。
- **追踪缺口**：plan 拒绝无 `policy_decision` 事件；`turn_end`/`session_end`
  缺 status；沙箱子会话 trace 未回收。
- **构建/文档漂移**已在 W68 §5.2、§8 列出，修复工作归 W69 及后续波次。

## 6. 单一正典与清理约定

W69B 清理后，以下路径是唯一有效副本（旧的根目录副本、`.pre-*` 快照、
旧二进制已归档）：

| 内容 | 正典路径 |
|---|---|
| 中/英双语字符串表 | `i18n/lang.c` |
| 语言枚举/接口 | `include/ai_lang.h` |
| config 命令实现 | `shell/commands/cmd_config.c`（`CMD_DIR := shell/commands`） |
| REPL 主入口 | `shell/aikernel_main.c` |
| 工具表 | `tools/tools.json`（根 `tools.json` 等为符号链接，单一正典） |
| 工具表生成器 | `tools/gen_registry.py` |

构建产物（`built-in.a`、`modules.order`、`.cmd`、`tools/__pycache__`）不提交、
不手工维护，由构建/生成器重建。

## 7. 证据索引（不复制大段证据）

- W68 报告：`~/aikernel-longterm/reports/W68.md`（§5 死代码/构建链、§9 证据索引）
- W68 证据：`~/mbedtls-trim-evidence/logs/fix-w68/`
  - `tools-matrix.csv`、`exec-commands.csv`、`w68_deadcode.txt`、
    `w68_compile_check.txt`、`W68-architecture.md`
- W69B 清理证据：`~/mbedtls-trim-evidence/logs/fix-w69b/`
  - `removed/`（按相对路径归档的被删文件）
  - `evidence/sha256-before.txt`、`inventory-before.txt`、`refcheck.txt`、
    `disk-before.txt`、`disk-after.txt`
- Trace schema：`docs/trace-schema.md`
