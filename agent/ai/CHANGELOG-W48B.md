# CHANGELOG-W48B：AI 全轨迹日志系统

日期：2026-10-12 起实施（2026-10-19 验收）
范围：`agent/ai/`（L1 权威树）

## 1. 交付内容

新增 AI 全轨迹日志（JSONL），记录一次运行从会话到工具调用的完整因果链，
面向训练（SFT/DPO）、回放与审计；所有字符串字段统一脱敏，密钥不落盘。

事件类型：`session_start/end`、`turn_start/end`、`model_request/response`、
`route_activate`、`tool_call`、`policy_decision`、`degraded`、`error`。

## 2. 改动文件

新增：

| 文件 | 行数 | 说明 |
|---|---:|---|
| `include/ai_trace.h` | 167 | 公共 API：配置、事件发射、时间/哈希 |
| `trace/ai_trace.c` | 1619 | 核心实现：单例/单写/脱敏/轮转/降级 |
| `shell/commands/cmd_trace.c` | 679 | `trace stats/dump/export`（训练导出） |
| `tests/test_trace.c` | 569 | 75 断言：JSON/脱敏/截断/轮转/并发/降级 |
| `docs/trace-schema.md` | — | 事件 schema、配置、脱敏、训练导出格式 |

修改（均为追加式接入，不改既有协议/行为）：

| 文件:行 | 内容 |
|---|---|
| `shell/commands/cmd_ask.c:78,580-731,993,1301-1320,1404,1598,1774` | 会话/回合起点，工具调用全量轨迹（含 denied 判定/退出码），SME 路由激活，SME/云端降级 |
| `runtime/runtime.c:17,281-310` | 模型请求/响应事件（request_id 配对、耗时、usage、HTTP 状态），云端不可达 error/degraded |
| `shell/aikernel_main.c:35,724,802-803,880-881` | 启动初始化、退出 session_end/shutdown |
| `policy/ai_user_policy.c:35,707-745` | W1/W2/确认判定 → policy_decision（ALLOW/DENY/CONFIRM + 确认来源） |
| `shell/commands/commands_registry.c:158-166` | 注册 `trace` 命令 |
| `include/ai_commands.h:34-35` | `cmd_trace` 声明 |
| `Makefile:345-356` | `trace/ai_trace.c` + `cmd_trace.c` 编入 ai/aikernel-shell |
| `tests/Makefile:17-20,43-45,104-108` | 新增 test_trace；policy 相关测试补链 ai_trace |
| `tests/test_plan_mode.c`（测试健壮性） | `strstr(out,"plan")==NULL` → `strstr(out,"ERROR: plan")==NULL`：原断言会把 `systemctl status` 进程树中的 `test_plan_mode` 自身误判为 plan 闸门拦截（预先存在的环境性误报） |

新文件均带 `// SPDX-License-Identifier: GPL-2.0`；源文件 UTF-8。

## 3. 配置

`~/.aikernel/trace.toml`（可选，缺失用默认值）：

```toml
[trace]
enabled = true
dir = "~/.aikernel/trace"
max_file_mb = 64
max_files = 20
include_model_text = true
max_payload_kb = 64
```

环境变量覆盖：`AIKERNEL_TRACE_ENABLED/DIR/MAX_FILE_MB/MAX_FILES/INCLUDE_TEXT/MAX_PAYLOAD_KB`。
root 默认目录 `/var/log/aikernel/trace/`；非 root `~/.aikernel/trace/`。

## 4. 安全与可靠性

- 每行一次 `write()`（O_APPEND），进程内互斥；并发不交错。
- 打开/写入失败：stderr 警告一次后静默丢弃，主流程不阻断。
- 统一脱敏：`sk-*`、`Bearer *`、`api_key/token/password/secret/authorization`
  键值；单测注入 6 类假密钥断言原文不落盘。
- 非法 UTF-8 字节替换 U+FFFD；每行可被标准 JSON 解析器解析。
- 轮转 `*.jsonl → *.1.jsonl …`，`max_files` 生效；空文件退出时自动删除。
- 目录/文件 0700/0600；文件权限不依赖 umask。

## 5. 验证结果

### 构建
`make clean && make -j1`：BUILD_EXIT=0，编译器 warning/error = **0**
（静态链接 glibc 的 `getaddrinfo` 链接器提示为既有现象，不计入编译告警）。

### 单测
`tests/test_trace`：**75 断言，0 失败**。覆盖：
- init/配置默认值/目录创建；
- 全事件类型逐行 JSON 合法、头字段齐全、`event_seq`/`mono_ms`/`ts` 单调；
- 脱敏（sk-、Bearer、api_key=、token=、password、args 内 token）；
- 100 KB 结果截断到 64 KB，`result_truncated/result_bytes` 正确；
- 轮转（1 MB × 3 文件上限）；
- 8 线程 × 25 事件并发写：202 行全部可解析、seq 唯一；
- 不可写目录 → 降级（is_enabled=0，事件 no-op，不崩溃）。

全量回归：12/12 套测试通过（原 11 套 + test_trace）。

### 集成（真实 `ai` 二进制 + 两回合 + 工具调用）
环境：L1，临时 HOME，OpenAI 兼容 mock 端点（127.0.0.1:19443），
`printf '第一轮…\n第二轮…\n' | ./ai -N`（单进程两会话回合）。

- 事件 18 条：`session_start 1 / turn_start 2 / model_request 4 /
  model_response 4 / policy_decision 2 / tool_call 2 / turn_end 2 /
  session_end 1`。
- `turn=1,2` 成对；`session_id` 全一致；`seq/ts/mono` 严格单调。
- 两次 `tool_call` 均为 `exec_run`，`status=ok`、`exit_code=0`、结果全文。
- 模型请求 tools 名列表 5 个（非全文）；usage token 累计 440/64。
- 临时 HOME 中 `api_key` 假值未出现在轨迹文件（key_leak=False）。
- `trace stats`：sessions=1, events=18, turns=2, requests=4, tool_calls=2。
- `trace dump --format json`：18 个对象，Python `json` 解析通过。
- `trace export`：2 行，`{messages,tools_used,outcome}` 正确
  （`turn 1/2, ["exec_run"], completed`）。

### 性能
10 回合批量、5 组重复（本地 mock 端点，排除网络差异）：

| rep | trace on (ms) | trace off (ms) |
|---|---:|---:|
| 1 | 1993 | 2052 |
| 2 | 1993 | 1931 |
| 3 | 1955 | 1991 |
| 4 | 1993 | 2012 |
| 5 | 1972 | 2011 |

中位数：on 1993 ms / off 2011 ms → 开销在测量噪声内（<1%），
满足 <5% 要求。日志体积：2 回合会话 31.5 KB；10 回合 201–313 KB
（随历史重放增长，约 31 KB/回合）。

## 6. 产物 md5

| 文件 | md5 |
|---|---|
| `ai` = `aikernel-shell` | `673cbf514aa4e10b193b59621c7b648b` |
| `include/ai_trace.h` | `480aaec4d91d663e62be15b7ad3f7866` |
| `trace/ai_trace.c` | `1668dfdd6ce534fefae7895f99f2cdb7` |
| `shell/commands/cmd_trace.c` | `cb075c512c60c74d13da6e2ac4b79d68` |
| `tests/test_trace.c` | `c4664c991444b45b096531af2d2c703a` |
| `docs/trace-schema.md` | `16cbfa02cad53d13fb562e424f975458` |

## 7. 已知限制

- `PLAN` 只读闸门的拒绝仍由 executor 既有 audit 行承载；W1/W2
  policy_decision 已全覆盖（含确认来源）。如需 PLAN 事件，可在
  executor 闸门处追加一行 `ai_trace_policy_decision("PLAN",...)`。
- 集成 mock 端点为 autonomous 路由，未触发 `route_activate`；
  该事件由单测覆盖（memory_search 与 pre_retrieve 两条路径）。
- `session_end.events` 为不含本行的累计值（文档已注明）。

## 8. 清理

- L1 `/tmp/w48b-*`、mock server、临时 HOME 已删除；mock 进程已终止
  （19443 端口确认关闭）。
- 测试临时目录（`/tmp/aik-trace-test-*`）由测试自清理；
  `agent/ai/tools/__pycache__` 已删除。
- 证据留存：`~/mbedtls-trim-evidence/logs/fix-w48/B-*.{jsonl,txt,log}`。
- 进度：`~/mbedtls-trim-evidence/logs/fix-w48/B-progress.txt`。
- 未引入任何临时脚本/未提交文件。
