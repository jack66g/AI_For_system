# AIKernel AI 全轨迹日志（W48B）

状态：W48B 交付（2026-10-12 起实施，2026-10-19 验收）
模块：`agent/ai/trace/ai_trace.c`、`agent/ai/include/ai_trace.h`
命令：`trace stats|dump|export`（`ai` / `aikernel-shell` 内置）
单测：`agent/ai/tests/test_trace.c`

## 1. 目标与边界

记录 AI 一次完整运行的因果链，供训练（SFT/DPO）、回放与审计：

```
session_start
  turn_start
    model_request → model_response
    route_activate（SME 检索命中工具）
    tool_call（args / 结果 / 耗时 / 退出码）
    policy_decision（W1/W2/PLAN 闸门）
    degraded（SME/云端不可达等）
    error（关键阶段错误）
  turn_end
session_end
```

- 一行一事件（JSONL），每行可独立解析；UTF-8。
- 不做隐私裁剪：对话文本、工具参数、结果按配置保留全文。
- 密钥类**绝不落盘**：所有字段统一脱敏（见 §6）。
- 内核无关、纯用户态；写入失败永不阻断主流程。

## 2. 配置

路径优先级：`AIKERNEL_TRACE_CONFIG` → `$HOME/.aikernel/trace.toml` →
`/etc/aikernel/trace.toml` → 内置默认值。配置缺失/解析失败仍可用
（默认开启，目录按 uid 选择）。

```toml
[trace]
enabled = true                 # 默认 true
dir = "~/.aikernel/trace"      # 默认：非 root 为 ~/.aikernel/trace/，
                               #       root 为 /var/log/aikernel/trace/
max_file_mb = 64               # 单文件上限（默认 64 MB）
max_files = 20                 # 轮转保留文件数（默认 20）
include_model_text = true      # 是否记录模型输入/输出全文（默认 true）
max_payload_kb = 64            # 单字段载荷上限（默认 64 KB）
```

环境变量覆盖（最高优先级，便于测试/临时采样）：

| 变量 | 含义 |
|---|---|
| `AIKERNEL_TRACE_ENABLED` | 0/1 开关 |
| `AIKERNEL_TRACE_DIR` | 输出目录 |
| `AIKERNEL_TRACE_MAX_FILE_MB` | 单文件上限 |
| `AIKERNEL_TRACE_MAX_FILES` | 轮转保留数 |
| `AIKERNEL_TRACE_INCLUDE_TEXT` | 模型全文开关 |
| `AIKERNEL_TRACE_MAX_PAYLOAD_KB` | 单字段上限 |

初始化：`ai_trace_init(config_path, flags)`；`AI_TRACE_FLAG_DISABLE`
强制关闭。未配置时使用默认值；目录创建/文件打开失败向 stderr 警告
一次后静默降级（`ai_trace_is_enabled()==0`）。

## 3. 文件与轮转

- 文件名：`trace-YYYYMMDD-HHMMSS-<pid>-<instance>.jsonl`，含日期。
- 打开方式：`O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC`，权限 `0600`。
- 每行在内存完整拼装后**一次 `write()`**；进程内 pthread 互斥，
  并发写不交错（多线程/多进程均不会出现半行）。
- 按大小轮转：`<base>.jsonl` → `<base>.1.jsonl` → `<base>.2.jsonl` …
  超过 `max_files` 删除最旧；初始化时清理目录内过旧轨迹文件
  （最近 5 秒内活跃文件不删）。

## 4. 公共头字段（每行必有）

| 字段 | 类型 | 说明 |
|---|---|---|
| `ts` | string | ISO8601 + 毫秒 + 时区，如 `2026-10-19T22:57:56.610+0800` |
| `mono_ms` | int | `CLOCK_MONOTONIC` 毫秒（单调，跨行可比较） |
| `session_id` | string | 进程级会话 ID：`s-YYYYMMDDTHHMMSS-<pid>-<n>` |
| `session` | string | UI 会话名（默认 `default`） |
| `turn` | int | 轮号（session 级事件为 0） |
| `event_seq` | int | 进程内单调事件序号（从 1 开始） |
| `event` | string | 事件类型 |

## 5. 事件 schema

### session_start
| 字段 | 说明 |
|---|---|
| `model` / `provider` | 生效模型/Provider 类型 |
| `pid` / `uid` / `version` | 进程、用户、schema 版本（`1.0`） |
| `config` | `{ctx_len, max_tokens, stream, routing}`；routing 为 `autonomous` / `pre_retrieve` |
| `tools_hash` | `tools.json` 内容 FNV-1a 64 指纹（工具表版本） |
| `schema_version` | 整数，当前 1 |

### session_end
`reason`, `duration_ms`, `turns`, `model_requests`, `tool_calls`,
`degraded`, `errors`, `events`（不含本行）。

### turn_start / turn_end
- start：`turn`, `question`（完整问题文本）
- end：`turn`, `duration_ms`, `rounds`, `end_reason`
  （`completed` / `model_error` / `max_rounds` / `no_result` /
  `no_tool_executed`）

### model_request
| 字段 | 说明 |
|---|---|
| `provider` / `model` | Provider 与 API 模型名 |
| `request_id` | `req-<session_id>-<n>`，与响应配对 |
| `stream` | 是否流式请求 |
| `message_count` / `est_tokens` | 消息条数、估算 token（字节/3） |
| `tools` | 本次请求 tools 数组的**工具名列表**（非全文） |
| `tool_count` | 工具数 |
| `messages` | 数组：`{role, content, tool_call_id?, tool_name?, tool_calls?}`；content 为全文（受 `include_model_text` / `max_payload_kb` 约束） |

### model_response
`request_id`, `content`（全文）, `tool_calls`
（`[{id,name,arguments}]`，arguments 完整）, `tool_call_count`,
`has_tool_calls`, `finish_reason`, `elapsed_ms`, `prompt_tokens`,
`completion_tokens`, `total_tokens`, `http_status`。
`content_truncated` / `arguments_truncated` 仅在截断时出现。

### route_activate
`trigger_token`（`memory_search` / `pre_retrieve`）, `tools_hit`
（本次新激活工具名）, `tool_count_hit`, `active_before`, `active_after`。

### tool_call
| 字段 | 说明 |
|---|---|
| `tool` / `channel` / `risk` | 工具名、通道、风险级（R/W1/W2） |
| `args` | 完整参数 JSON（脱敏后） |
| `start_ts` / `duration_ms` | 开始时间与耗时 |
| `status` | `ok` / `fail` / `denied` / `error` |
| `ok` | 布尔 |
| `exit_code` | exec 通道子进程退出码（成功 0；未知 -1） |
| `result_bytes` | 结果原始字节数 |
| `result` | 输出全文，超过 `max_payload_kb` 截断 |
| `result_truncated` | 截断时出现 |

### policy_decision
`gate`（`W1`/`W2`/`PLAN`）, `decision`（`ALLOW`/`DENY`/`CONFIRM`）,
`reason`（`policy_allow`/`user_refused`/`policy_tier`/
`needs_confirmation_no_tty`/`plan_read_only`—PLAN 由 executor 记录）,
`tool`, `confirm_source`（`auto`/`interactive`/`assume_yes`/`none`）,
`args`, `uid`。W1/W2 判定在 `policy/ai_user_policy.c` 统一记录。
  W74 起扩展可选字段：`lease_id`、`danger`（D0-D4）、`confirmation`
  （none/interactive/ephemeral/lease/approved_file）、`pending_nonce`、
  `lease_source`；`tool_call` 亦新增 `danger` 与 `lease_id`。

### degraded
`component`（`sme`/`cloud`）, `reason_code`
（`unavailable`/`http_error`/`unreachable`/`tools_unsupported`）, `detail`。

### error
`phase`（如 `model_request`）, `code`（`ai_error_string` 文本）, `message`。

W77 起模型路由决策写独立文件 `$AIKERNEL_TRACE_DIR/route.jsonl`
（`route_decision`/`route_switch`/`route_offline` 事件；0600、>8MB 轮转；
不写 base_url/api_key），见 `docs/W77-OFFLINE.md` §6。

## 6. 脱敏规则

所有字符串字段在 JSON 转义前统一经过 `trace_redact()`：

| 模式 | 替换 |
|---|---|
| `sk-[A-Za-z0-9_-]{16,}` | `***` |
| `Bearer <token>` | `Bearer ***` |
| `api_key` / `api-key` / `apikey` 后跟 `:`/`=`/引号的值 | `***`（保留引号/分隔符结构） |
| `access_token` / `refresh_token` / `auth_token` / `token` 同上 | `***` |
| `password` / `passwd` / `secret` / `authorization` 同上 | `***` |

规则是"键 + 分隔符 + 值"的窄匹配，普通英文单词（如 `token budget`）
不会被误伤。测试 `tests/test_trace.c` 注入 6 类假密钥并断言原文不落盘。

非法 UTF-8 字节在写入前替换为 U+FFFD，保证每行是合法 UTF-8/JSON。

## 7. 查询与训练导出

```bash
# 统计（会话/事件/工具分布/token）
trace stats

# 按会话导出原始事件（jsonl 或 json 数组）
trace dump --session <id|name> --format jsonl
trace dump --session <id|name> --format json --out /tmp/session.json

# 训练用扁平化导出（一行一回合）
trace export --since 2026-10-01 --until 2026-10-31 --out train.jsonl
```

`trace export` 行格式：

```json
{
  "session_id": "s-...",
  "turn": 1,
  "ts": "2026-10-19T22:57:56.610+0800",
  "messages": [
    {"role": "user", "content": "用户原始问题"},
    {"role": "assistant", "content": "最终回答"}
  ],
  "tools_used": ["exec_run"],
  "outcome": "completed",
  "duration_ms": 204
}
```

- 每行一个完整回合，可直接作为 SFT 样本（messages）或 DPO 的
  chosen/rejected 来源（`outcome` + 工具序列）。
- `--since/--until` 支持 `YYYY-MM-DD` 或完整 ISO 时间前缀比较。
- `--session` 可按 session_id 或 UI 会话名过滤。

## 8. 性能与可靠性

- 事件写入为一次 `write()`；正常对话（每回合 ~10 事件）开销在
  测量噪声内（10 回合批量实测：开/关 trace 均约 2.0 s，
  差异 <1%，要求 <5%）。
- 单文件默认 64 MB；典型 2 回合会话约 16 KB（随历史增长，
  10 回合约 200–310 KB）。
- 打开/写入失败：stderr 警告一次后静默丢弃事件，主流程不受影响；
  `ai_trace_is_enabled()` 变为 0。
- 日志目录/文件权限 `0700`/`0600`，不含 API Key（脱敏 + 配置本身
  不写入事件）。

## 9. 回放说明

事件按 `event_seq` 排序即为完整因果链；`turn` 聚合一个用户回合，
`request_id` 关联模型请求/响应，`tool_call.args/result` 可重放工具
执行（注意权限与副作用），`policy_decision` 记录当时的闸门结论。
