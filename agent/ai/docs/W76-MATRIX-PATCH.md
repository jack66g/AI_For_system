# W76 → W75 矩阵补丁（供主会话合并，不直接改 W75 文件）

- 日期：2026-10-20
- 依据：W76 实现与验收（`reports/W76.md`、`fix-w76/`）
- 使用方式：主会话在 W75 重跑/合并时采用下列行变更；**不要**用本文件覆盖 `docs/OBSERVABILITY-MATRIX.md` / `docs/CAPABILITY-GAPS.md`。

## 1. 行级变更（桌面 9 对象）

| ID | 对象 | W75 现状 | W76 后 | 证据/工具 |
|---|---|---|---|---|
| DT-01 | 桌面健康/统计 | `api:GET /api/health|stats`，semantic，D0 | 不变（另有 `desktop_health/stats`） | 工具已注册 D0 |
| DT-02 | 应用枚举 | `api:GET /api/apps`；launch/close 仅 in-progress 路由 | 读 `desktop_apps_list` D0；写 `desktop_apps_launch` D1 / `desktop_apps_close` D2 | 10-task 01/05 |
| DT-03 | 窗口 | **读 ABSENT**、写 ABSENT（仅 in-progress GET） | 读 `desktop_windows_list` **D0**；写 `desktop_windows_focus` **D1**、`desktop_windows_close` **D2**；返回稳定 id/geometry/focused/visible/z/text | 10-task 04/05；`/api/windows` |
| DT-04 | 主题/壁纸 | 读 GET；写仅 `exec_run curl`（有效 W2） | 读不变；写 `desktop_theme_set` / `desktop_wallpaper_set` **D1**；可回读、可恢复 | 10-task 02/03 |
| DT-05 | 通知 | 读 GET；写仅 curl W2 | 读 `desktop_notifications_list` D0；写 `desktop_notifications_send` **D1**（追加，不覆盖历史） | 10-task 09 |
| DT-06 | 输入注入（键鼠） | **读/写 ABSENT**（仅 in-progress POST） | 写 `desktop_input_type` / `desktop_input_key` **D2**；窗口文本可经 `desktop_windows_list` 观察 | 10-task 07/08；DOM 断言 |
| DT-07 | 截图 | `escape:python3` raw，shell-escape | 读 `desktop_screenshot` **D0**，返回 path/bytes/sha256/width/height；不再需要 python3 逃逸 | 10-task 06/07b |
| DT-08 | 剪贴板 | `escape:python3` raw，shell-escape | 读 `desktop_clipboard_get` **D0**；写 `desktop_clipboard_set` **D2**；返回 previous 便于恢复 | 10-task 10 |
| DT-09 | 聊天/会话/电源 | 读 chat；写 chat curl W2；power 演示回执 | chat 不变；`desktop_power` **D3 已注册但后端 501 unavailable**——**不要**把它计为可用写路径；G-033 保持开放 | 工具层 501 用例 |

### 覆盖计数建议（W75 重跑口径）

- 桌面读路径：DT-03 由 ABSENT → 直连 D0；DT-06 读仍无“注入历史”对象（窗口文本可观察，建议标 `structured` 而非 `semantic`）；DT-07/DT-08 由 shell-escape → 直连结构化 D0。
- 桌面写路径：DT-02/03/04/05/06/07/08 均有 `desktop_*` 一等工具；DT-09 power 仍 unavailable，不计入有效写。
- “仅 shell/脚本可写”桌面项应从 2 项（截图/剪贴板写）降为 0；DT-09 仍为 unavailable 而非 shell。
- 全局：tools 130 → **150**；域 7 → **8**（desktop）；seed 145 → **166**（区头 8 + 单件 150 + 配方 8）；`tools.json` sha **1bd96543…**。
- W75 `tools/audit_capabilities.py` 的 `EXPECTED_TOOLS=130`、`EXPECTED_DOMAINS=7`、seed 断言与报告数字需要主会话同步到 150/8/166 后重跑；本次未改该脚本/W75 文档。

## 2. 缺口关闭建议

### G-002 桌面窗口/输入/截图/剪贴板 — **建议关闭（W76 完成）**

验收映射：

- `desktop_windows_list/focus/close` 全部注册并有实现；窗口 id/geometry/focused/visible 结构化。
- `desktop_input_type/key` D2；输入后窗口状态与 Playwright DOM 双验证。
- `desktop_screenshot` D0，path/bytes/sha256；>30KB 且 colors>100 防白屏。
- `desktop_clipboard_get/set` D0/D2，previous 恢复。
- 遗留：Web demo 不是真 OS 桌面（W84）；这属于实现形态，不再是“AI 无接口”的缺口。

### G-015 桌面写路径/租约 — **建议关闭（主题/壁纸/通知/窗口/输入/剪贴板）**

- 写路径全部进入注册表/目录页/SME 语料，有 D1/D2、lease/确认、影响描述与回滚提示。
- `desktop_power` D3 已登记，但后端 501 unavailable；**不要**用 W76 关闭 G-033（电源演示/真 logind）。
- 回滚：theme/wallpaper 回读旧值；notifications 原列表；clipboard previous；window close 不可逆（D2 明示）；power 未执行（no-op）。

## 3. 新增风险/建议登记（不占用 W75 既有 G 编号）

| 建议 ID | 风险 | 级别 | 建议 |
|---|---|---|---|
| W76-R1 | Web demo 虚拟窗口 ≠ 真 OS 窗口/进程 | P1 | W84 接 greetd/cage/真 WM；W76 文档明确“不启动宿主进程” |
| W76-R2 | 输入注入/截图/剪贴板敏感，loopback 无鉴权（本机任意 uid 可调 8091） | P1 | W83 加会话令牌/跨用户隔离；W84 绑定用户会话 |
| W76-R3 | Playwright/chromium 单点依赖（`~/.cache/ms-playwright`） | P2 | 加 probe/自检；缺失 503，不伪造；W81 锁版本 |
| W76-R4 | 8091 demo 单点停机 → 桌面工具不可用 | P2 | W84 系统桌面服务化；Agent 侧已有 `E_DESKTOP_UNAVAILABLE` |

## 4. 证据

- `fix-w76/desktop-10tasks.log` / `.json`（10/10 + 07b/清理）
- `fix-w76/test_desktop_tools.log`（56/0）
- `fix-w76/trace-sample/`（D0-D3 policy_decision + audit）
- `fix-w76/api-transcript.txt`（每个端点请求/响应）
- `fix-w76/tests-full.log`（30/30 RC=0，0 warning）
- `fix-w76/manifest.log`（150/150 ALL PASS）、`corpus.log`（166 PASS）
- `fix-w76/offline-without-demo.log`（停 8091 后核心测试 98/0、56/0）
- `fix-w76/shots/01-desktop-window.png`、`02-after-input.png`
