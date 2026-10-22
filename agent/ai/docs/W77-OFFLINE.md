# W77 本地大脑与离线模式 — 设计/路由表/降级矩阵

- 日期：2026-10-21
- 范围：`agent/ai` 用户态；不部署/不重启生产 VM
- 结论：断网核心意图 30/30（100%）由确定性离线层回答；云 500/429/DNS/连接中断后自动切本地；真实 qwen 评测待 soak 后

## 1. 为什么这样设计

宪法要求“AI 是最高执政者，断网也不能变成只会报错”。W77 把“用哪个模型”从
隐式默认升级为显式、可解释、可审计的选择：

- **离线意图层**先处理确定性 D0 查询（状态/内存/磁盘/负载/服务/文件/沙箱/记忆/
  租约/计划/配置/路由/网络/内核/uptime），完全不发模型请求；
- **模型路由**只处理需要推理/对话的请求：auto 按任务类型/延迟/隐私/成本选择，
  local/cloud 可强制；云失败自动切本地；
- **降级 UX** 遇到两者都不可用时明确“离线/能力受限”，给可执行的离线替代，
  不伪装成功、不丢会话；
- **D2+ 动作仍走 W74 lease/确认**：路由层只切换 provider，不触碰 executor 的
  危险分级与租约闸门；离线不绕过。

## 2. 路由模式与配置

生效模式优先级：`AIKERNEL_ROUTE` 环境变量 > `model.toml [route].mode` > `auto`。

| 模式 | 行为 | 失败语义 |
|---|---|---|
| `auto` | 按任务/延迟/隐私/成本选择；云失败切本地 | 本地不可用→明确离线降级 |
| `local` | 强制本地（qwen2.5:1.5b） | 本地失败→明确降级，不静默上云 |
| `cloud` | 强制云 | 云失败仍可按 failover 切本地；本地不可用→明确降级 |

`[route]` 段（`~/.aikernel/model.toml`）：

```toml
[route]
mode = "auto"              # auto|local|cloud
privacy = false            # true=隐私任务强制本地，绝不出网
prefer_local = true        # auto 下运维/短任务优先本地
failover = true            # 云失败自动切本地
offline_intents = true     # 启用离线意图层
local_ctx = 32768          # 本地上下文上限（硬上限 32768）
local_p95_ms = 8000        # 本地延迟预算（诊断/选择依据）
switch_budget_ms = 2000    # 切换预算（实测 0-3ms）
probe_timeout_ms = 400     # 本地/云端 TCP 预探测超时
cloud_down_ttl_ms = 60000  # 云失败记忆 TTL（后续 ask 直接走本地）
```

环境变量：

- `AIKERNEL_ROUTE=auto|local|cloud`：覆盖 mode；
- `AIKERNEL_PRIVACY=1|local`：隐私优先，本地不可用则离线，绝不发云；
- `AIKERNEL_OFFLINE_INTENTS=0|1|force`：关闭/开启/强制离线意图；
- `AIKERNEL_CLOUD_DOWN=1` / `AIKERNEL_LOCAL_DOWN=1`：故障注入（测试）；
- `AIKERNEL_LOCAL_UP=1`：本地可用性测试覆盖（单测）。

## 3. 决策表（auto）

按优先级从上到下：

| 条件 | 目标 | reason | 说明 |
|---|---|---|---|
| privacy=1 且本地可用 | local | `privacy_local` | 隐私绝对优先，即使 forced cloud |
| privacy=1 且本地不可用 | offline | `privacy_local_unavailable` | 不静默发云 |
| mode=local | local | `forced_local` | 显式选择 |
| mode=cloud 且云已知不可用 + failover + 本地可用 | local | `cloud_failover` | 显式云仍允许故障切换 |
| mode=cloud | cloud | `forced_cloud` | 显式选择 |
| 估算 prompt > 24000 tokens | cloud | `context_needs_cloud` | 本地 32768 窗口的一半 |
| 重推理（代码/方案/分析/调试） | cloud | `reasoning_cloud` | 本地慢/云不可用→本地→离线 |
| 重推理 + 云不可用 + 本地可用 | local | `cloud_down` | |
| 重推理 + 云不可用 + 本地不可用 | offline | `cloud_and_local_down` | |
| 普通对话 + 云可用 + 本地可用且不慢 | local | `latency_local` | prefer_local 默认开 |
| 普通对话 + 云可用 + 本地慢/不可用 | cloud | `default_cloud` | |
| 运维任务 + 本地可用 + prefer_local | local | `operational_local` | 断网核心运维 |
| 运维任务 + 云不可用 + 本地可用 | local | `cloud_down` | |
| 运维任务 + 云/本地都不可用 | offline | `cloud_and_local_down` | |

可用性探测：本地 TCP 探测缓存 3s；云端 TCP 预探测缓存 30s（auto 模式）；
云失败记忆 TTL 60s（网络/认证/429/5xx/超时）。云端探测只做 TCP，不发送
业务请求；`https://` 目标退化为“未知可达”，不误判。

## 4. 失败语义

| 场景 | 行为 | 证据 |
|---|---|---|
| 云 HTTP 400/422/未知协议错误 | 先切文本 JSON 工具协议重试一次（不切模型） | `test_router_*` / e2e |
| 云 HTTP 429 | 自动切本地，trace reason=`http_429` | e2e 193ms |
| 云 HTTP 500/502/503/504 | 自动切本地，trace reason=`http_500` 等 | e2e 195ms |
| DNS 失败/连接拒绝 | auto 预探测/请求失败后切本地 | e2e 165.9ms |
| 读超时 | 云客户端 30s 超时后切本地；**切换本身 0ms** | e2e 30.3s 总时长 |
| 云认证失败 | 自动切本地 | `test_w77_route` |
| 本地 429/500/502/503/504 | 100ms 退避重试一次；仍失败→明确降级 | e2e local_failure |
| 本地网络失败 | 明确降级，不静默上云 | e2e |
| 云+本地均不可用 | `[offline]` 能力受限文案 + 离线替代 + 会话落盘 | e2e degrade |
| 隐私任务 + 本地不可用 | 离线，不发云 | `test_w77_route` |
| D2+ 动作 | 仍由 executor + W74 lease gate 判定 | `test_w77_offline_gate` 18/0 |

“切换 <2s”口径：从检测到失败到本地 provider 配置生效。实测 `switch_ms=0`
（配置级切换，不做网络握手）；端到端 500/429/DNS 场景 165.9-194.9ms。云读超时
的总失败检测时间受云客户端固定 30s 限制（见未解风险）。

## 5. 离线意图层

实现：`local/offline_intent.c`。只读 D0，无写路径；答案同时输出人类可读文本
与机器可读 JSON，头部固定：

```
[offline] intent=<name> source=<source> age=<cache_age_ms>ms latency=<ms>ms
```

| intent | 数据来源 | 输出要点 |
|---|---|---|
| status | /proc/uptime,loadavg,meminfo + statvfs + systemctl | uptime/load/mem/disk%/failed units/cpu |
| memory | /proc/meminfo | MemTotal/Free/Available/Buffers/Cached/Swap |
| disk | statvfs | /、/home、/var、/tmp total/free/used% |
| load | /proc/loadavg + /proc/*/status | loadavg + top RSS 进程 |
| service | systemctl is-active | 指定服务状态；无 systemd 如实 unavailable |
| services | systemctl --failed --plain | 失败 unit 列表 |
| logs | dmesg err/warn | 最近 20 行内核错误 |
| file | stat/lstat | 类型/大小/权限/owner uid/gid/mtime/目录项/行数；**不输出正文** |
| sandbox | AIKERNEL_SANDBOX_BASE（默认 /sandbox） | 沙箱名 + meta mtime/size |
| lease | AIKERNEL_LEASE / AIKERNEL_LEASE_DIR | 当前租约 id、存储数量、D2+ 仍需租约声明 |
| memory_query | SME /memories/search | 结果原文 JSON；SME 不可用→明确降级到“最近计划” |
| plan | ~/.aikernel/offline/plans.jsonl | 最近 5 条任务（问题/路由/状态/轮数/工具/detail） |
| route | route.jsonl | 路由状态文本 + 最后一条 route trace |
| config | model.toml 摘要 | 默认模型/本地模型/base_url/路由/ctx；不含 key |
| network | getifaddrs + /proc/net/route + /etc/resolv.conf | 接口/地址/默认网关/DNS |
| kernel | uname + /proc/version | 内核 release/version/machine |
| uptime | /proc/uptime | 秒/小时 |

识别保护：含动作词（修复/重启/安装/删除/创建/修改/写脚本）或重推理问法
（分析/设计/为什么/如何）不命中，交给模型，避免离线层越权或答非所问。

缓存：每次 ask（成功/降级/离线）追加一条计划摘要到
`~/.aikernel/offline/plans.jsonl`（0600，>1MB 轮转）；“最近计划”带缓存年龄。

## 6. 路由 trace

`$AIKERNEL_TRACE_DIR/route.jsonl`（默认 `~/.aikernel/trace/route.jsonl`），
0600、单行 JSON、>8MB 轮转为 route.1.jsonl。不写 base_url/api_key/密钥。

字段：

- `route_decision`：`ts, mono_ms, event, mode, decision, reason, task, privacy,
  provider, model, latency_ms, decide_ms, cloud_health, local_up,
  local_probe_ms, switch_ms`
- `route_switch`：`ts, event, from, to, reason, provider, model, latency_ms,
  switch_ms`
- `route_offline`：`ts, event, decision=offline, reason=intent:<name>, intent,
  source, cache_age_ms, latency_ms, provider="-", model="-"`

云→本切换同时镜像到主 trace 的 `degraded` 事件（component=route）。

样例见 `fix-w77/trace-sample.jsonl`。

## 7. 文件/接口

新增：

- `runtime/ai_route.c`：模式/任务分类/决策/探测/失败归类/健康记忆/apply/failover/trace；
- `local/offline_intent.c/.h`：离线意图匹配、采集、计划缓存；
- `tests/test_w77_route.c`、`tests/test_w77_offline.c`、
  `tests/test_w77_offline_gate.c`、`tests/w77_intents.tsv`、
  `tests/mock_w77_llm.py`、`tests/test_w77_e2e.py`。

修改：

- `include/ai_config.h`：`ai_route_config`、`AI_LOCAL_CTX_MAX=32768`；
- `include/ai_runtime.h`：路由选择/失败语义 API、`last_error/last_status_code/last_was_local`；
- `runtime/runtime.c`：本地 ctx 钳制、HTTP status 提取、失败字段；
- `config/config_manager.c`：`[route]` 解析/保存/env 覆盖；
- `shell/commands/cmd_ask.c`：离线意图前置、路由 apply、云→本切换、本地重试、明确降级、计划缓存；
- `Makefile`/`tests/Makefile`：新模块/测试编入。

未改：`tools/tools.json`、executor、desktop、W74 lease 核心、`cloud/**`、`trace/**`。

## 8. 未解风险（如实）

1. **真实 qwen 未评测**：soak 期间遵守派发词，仅用 mock/录制；L1 已有
   `qwen2.5:1.5b` 权重（~941MB）但 ollama 未启动。计划见
   `fix-w77/qwen-eval-plan.md`。
2. **qwen2.5:1.5b 能力上限**：1.5B 对复杂多步工具调用/长上下文推理有限；
   mock 通过不代表真实模型 100%。核心运维意图已做成模型无关，降低依赖。
3. **云读超时总失败检测 30s**：云客户端超时不可由本波文件集修改；切换本身
   0ms，但“从发起到切走”在真超时场景约 30s。W80 混沌/云客户端可调超时。
4. **非流式云错误 status 丢失**：cloud backend 只回 error.message；本波在
   runtime 用数字边界推断 429/5xx（并兼容 "HTTP status N"）。若服务端错误
   文本不含状态码，会退化为通用 `api_error`，但仍会切本地（API 错误）。
5. **mock 与实测差异**：mock 的延迟、流式分片、工具调用格式是简化仿真；
   P95 108.6ms 是 mock 数字，不是 qwen 实测。
6. **SME 依赖**：记忆查询离线时若 SME 不可用，只能给“不可用 + 最近计划”；
   不能凭空生成记忆。
7. **本地 provider 未在 VM 部署**：本波未部署/重启生产 VM；VM 实际
   `[local].enabled`/ollama 服务状态部署后需门禁复核。
