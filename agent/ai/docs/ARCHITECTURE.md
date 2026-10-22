# AIKernel 架构文档入口

状态：W69B 建立（2026-10-20）。
适用：`agent/ai` 用户态 AI Shell（含 `core/ai_core.c` 内核侧模块）。

## 从这里开始

| 文档 | 内容 |
|---|---|
| [架构矩阵](ARCHITECTURE-MATRIX.md) | 能力 → 检索 → 执行 → 权限 → 追踪；分层职责、7 能力域、10 执行通道、W68 结论、单一正典与证据索引 |
| [Trace schema](trace-schema.md) | 全轨迹 JSONL 事件、导出、脱敏、配置 |
| [W48 死代码清理记录](../README-dead-code-w48.md) | 历史代码卫生与删除规则 |

仓库外证据（只读引用，不复制进仓库）：

- W68 系统逻辑收口报告：`~/aikernel-longterm/reports/W68.md`
- W68 证据目录：`~/mbedtls-trim-evidence/logs/fix-w68/`
- W69B 清理报告：`~/aikernel-longterm/reports/W69B.md`
- W69B 归档与被删文件：`~/mbedtls-trim-evidence/logs/fix-w69b/removed/`

## 五层速览

1. **入口 / REPL**：`shell/aikernel_main.c`、`shell/shell.c`。
2. **命令层**：`shell/commands/`（`cmd_ask.c` 为核心，`cmd_*` 为子命令）。
3. **Runtime / Provider**：`runtime/`、`provider/`、`cloud/`、`local/`；
   流式解析在 `runtime/communication/`。
4. **注册 / 执行 / 权限**：`tools/tool_registry.c`、`tools/executor.c`、
   `policy/ai_user_policy.c`；工具表单一正典为 `tools/tools.json`（130 工具）。
5. **追踪 / 会话 / 沙箱**：`trace/ai_trace.c`、`~/.aikernel/{trace,sessions}`、
   `sandbox/aik-sandbox.c`。

详细数据流、能力域与通道矩阵见 [ARCHITECTURE-MATRIX.md](ARCHITECTURE-MATRIX.md)。
