# W76 桌面能力面 v1

> 状态注记（2026-10-23，alpha.12.0）： desktop 能力面在 alpha.12.0 未变（20 工具）。本文合计数 150 工具/8 域/seed166 为 W76 时点快照；当前注册表 156/9/173（W77c +clarify、W77d +model 域 5 工具）。

- 日期：2026-10-20
- 范围：L1 Web demo（`~/fix-w48gui/img1`，127.0.0.1:8091）+ Agent `desktop` 通道
- 状态：实现完成；10 桌面任务 + 工具层/租约/全量回归通过
- 关联：`agent/ai/docs/W74-LEASE.md`、`reports/W76.md`、`fix-w76/`、`docs/W76-MATRIX-PATCH.md`

## 1. 结论

桌面从“AI 只能 `exec_run curl` 拼 HTTP”升级为**一等能力面**：

- 20 件 `desktop_*` 工具，独立 `desktop` 通道；总工具数 130 → **150**，能力域 7 → **8**。
- D0 读 / D1 可逆写 / D2 敏感写 / D3 电源，全部走 W74 `ai_lease_gate`。
- executor 用 `local_http`（POSIX socket）直连 loopback，**不经 shell/curl**；模型不能传 URL/路径/JS/命令。
- 窗口、应用、主题、壁纸、通知、截图、输入、剪贴板均有结构化 API 与工具；10/10 桌面任务无人类鼠标完成。
- 电源不再返回“演示回执”：后端明确 `501 unavailable`，工具如实失败。

## 2. API（L1 demo，仅 127.0.0.1:8091）

| 方法 | 路径 | 说明 | 风险 |
|---|---|---|---|
| GET | `/api/health` | 服务/桌面后端能力（power=unavailable） | D0 |
| GET | `/api/windows` | 窗口列表：id/title/app/geometry/focused/visible/z/text/last_key；附 mode/theme/wallpaper/clipboard 摘要 | D0 |
| POST | `/api/windows/focus` | `{"id":"w-0001"}` 置顶并聚焦 | D1 |
| POST | `/api/windows/close` | `{"id":"w-0001"}` 关闭单窗 | D2 |
| GET | `/api/apps` | 51 个 .desktop 应用（id/name/exec/icon/...） | D0 |
| POST | `/api/apps/launch` | `{"app":"libreoffice-calc"}` 创建虚拟窗口并聚焦 | D1 |
| POST | `/api/apps/close` | `{"app":"..."}` 或 `{"id":"w-..."}` 关闭应用全部窗口 | D2 |
| GET/POST | `/api/theme` | 读主题 / `{"name":"dark|light|pink|custom"}` | D0/D1 |
| GET/POST | `/api/wallpaper` | 读壁纸 / `{"wallpaper":"gradient|wall-*"}` | D0/D1 |
| GET/POST | `/api/notifs` | 读列表 / `{"title","body","tag"}` 追加；`{"notifs":[...]}` 兼容整表替换 | D0/D1 |
| POST | `/api/input` | `{"type":"type","text":...}` 或 `{"type":"key","key":"Enter","modifiers":"ctrl"}`，写入当前焦点窗口 | D2 |
| GET | `/api/screenshot` | Playwright 截当前桌面；返回 path/bytes/sha256/width/height | D0 |
| GET/POST | `/api/clipboard` | 读 / `{"text":...}` 写；返回 previous 便于恢复 | D0/D2 |
| POST | `/api/power` | `lock|logout|reboot|shutdown|suspend`；**501 unavailable**，不执行 | D3 |

约束与校验：

- `BIND_HOST = 127.0.0.1`；远程 UI 用 `ssh -L 8091:127.0.0.1:8091 jack66g@192.168.245.136`。
- 固定 JSON 形状；app id `[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}`，window id `w-\d{4,10}`，theme `[a-z0-9_-]{1,32}`，wallpaper `[A-Za-z0-9._-]{1,64}`。
- 输入：text ≤4096 字符；key 白名单（单字符 / Enter / Backspace / Tab / Escape / Delete / Home / End / PageUp / PageDown / 方向键 / F1-F12）；modifiers 仅 ctrl/alt/shift/meta；Ctrl+L/U 清空窗口文本。
- 剪贴板 ≤65536；通知 title ≤80 / body ≤400；不执行任意 JS、不拼命令、不访问任意 URL。
- 无焦点窗口输入返回 409；未知 app/window 返回 404；参数非法 400。
- 截图串行锁，单次约 1.2s；Playwright chromium 目前位于 `~/.cache/ms-playwright/chromium-1243`（`/dev/shm/ms-playwright` 不存在时自动回落默认）。
- `data/desktop.json` 与截图文件落盘为 **0600**（窗口文本/剪贴板/画面属敏感数据）。

## 3. Agent 工具（20 件，`desktop` 通道）

| 工具 | 风险 | D 级 | 参数 | 后端 |
|---|---|---|---|---|
| `desktop_health` | R | D0 | — | GET /api/health |
| `desktop_stats` | R | D0 | — | GET /api/stats |
| `desktop_apps_list` | R | D0 | — | GET /api/apps |
| `desktop_windows_list` | R | D0 | — | GET /api/windows |
| `desktop_theme_get` | R | D0 | — | GET /api/theme |
| `desktop_wallpaper_get` | R | D0 | — | GET /api/wallpaper |
| `desktop_notifications_list` | R | D0 | — | GET /api/notifs |
| `desktop_screenshot` | R | D0 | — | GET /api/screenshot |
| `desktop_clipboard_get` | R | D0 | — | GET /api/clipboard |
| `desktop_theme_set` | W1 | D1 | `name` | POST /api/theme |
| `desktop_wallpaper_set` | W1 | D1 | `wallpaper` | POST /api/wallpaper |
| `desktop_notifications_send` | W1 | D1 | `title`,`body`,`tag` | POST /api/notifs |
| `desktop_apps_launch` | W1 | D1 | `app` | POST /api/apps/launch |
| `desktop_windows_focus` | W1 | D1 | `id` | POST /api/windows/focus |
| `desktop_windows_close` | W2 | D2 | `id` | POST /api/windows/close |
| `desktop_apps_close` | W2 | D2 | `app` | POST /api/apps/close |
| `desktop_input_type` | W2 | D2 | `text` | POST /api/input |
| `desktop_input_key` | W2 | D2 | `key`,`modifiers` | POST /api/input |
| `desktop_clipboard_set` | W2 | D2 | `text` | POST /api/clipboard |
| `desktop_power` | W2 | D3 | `action` | POST /api/power（501） |

- 逻辑名 `desktop.apps.list` ↔ wire 名 `desktop_apps_list`（OpenAI function 名不允许点号）。
- `policy/ai_lease.c` 的 `ai_danger_classify` 对 `desktop_*` 显式映射；未知 `desktop_*` 写 fail-closed 到 D2；`desktop_power` 固定 D3。
- `tools/gen_registry.py` 生成 `tools.json` / `tools.openai.json` / `tools-sandbox.json`（仍 7 件、0 W2）/ `sme-seed-w51.jsonl`（区头 8 + 单件 150 + 配方 8 = 166）/ `tool_catalog.txt`。
- manifest 锚点：`tool_count=150`，`tool_names_sha256=1bd96543717678eb86b82afcf720f314f504356b193aaf775aafcfa71f6a80f1`。

## 4. 风险与确认语义

| D | 行为 | W76 工具 |
|---|---|---|
| D0 | 自动（租约过期/撤销也不阻断读） | 9 件读工具 |
| D1 | 自动（记审计） | theme/wallpaper/notifications/apps.launch/windows.focus |
| D2 | NONE：确认；`-y` 短租约（1h，D2 上限）放行；显式 D2 租约放行；worker 一律拒绝 | windows.close/apps.close/input.type/input.key/clipboard.set |
| D3 | NONE/`-y` 都要确认；显式 D3 租约放行；后端仍 501 时工具失败 | desktop_power |

- 非 TTY 返回 `ERROR: DENIED: CONFIRM_REQUIRED {...}`（nonce 5 分钟），Principal 用 `/lease confirm <nonce> yes|no`；调用方带 `AIKERNEL_CONFIRM_NONCE` 重试。
- 显式租约 scope `desktop`（或 `*`）且 ceiling 足够；D3 需要 D3 ceiling。
- 每笔调用写 `policy_decision`（danger/lease_id/confirmation）与 `~/.aikernel/audit.log` 行尾 `lease=... danger=... confirm=...`。

## 5. 10 个桌面任务（L1，全程无人类鼠标）

证据：`fix-w76/desktop-10tasks.log`、`desktop-10tasks.json`、`shots/01-desktop-window.png`、`shots/02-after-input.png`、`api-transcript.txt`。

| # | 任务 | 结果 | 关键证据 |
|---|---|---|---|
| 01 | 启动应用 | PASS | `libreoffice-calc` → `w-0004`，focused=true，backend=web-demo-virtual-window |
| 02 | 切主题 | PASS | light → GET current=light；恢复 dark |
| 03 | 切壁纸 | PASS | wall-aurora → GET current=wall-aurora；恢复 gradient |
| 04 | 聚焦窗口 | PASS | focus w-0004；focused=true，z 3>2，第二窗 focused=false |
| 05 | 关闭窗口 | PASS | close w-0005；列表消失，w-0004 保留 |
| 06 | 截图 | PASS | 325,376 B；sha256；14,366 色（非白屏）；文件 sha 一致 |
| 07 | 输入文本 | PASS | `W76-AI-typed-11328`；API 窗口 text 与 Playwright DOM 完全一致 |
| 07b | 输入后截图 | PASS | sha 变化，328,442 B |
| 08 | 按键 | PASS | Backspace 18→17，Enter +`\n`，Ctrl+U 清空；DOM text=`` |
| 09 | 发通知 | PASS | 5→6→5；末条 title=W76 验收；恢复原列表 |
| 10 | 剪贴板读写/恢复 | PASS | 写 38 字符，sha256 回读一致，previous/恢复长度 0 |
| 11 | 清理 | PASS | 窗口 0→0；theme=dark；wallpaper=gradient；通知/剪贴板恢复 |

> 08 第一次运行是**测试脚本问题**：Ctrl+U 后窗口文本为空，Playwright 默认等待 `visible` 把空 `.win-body` 判为 hidden。改为 `state="attached"` 后 API 与 DOM 均通过；不是产品输入失败。

## 6. 工具层测试

`agent/ai/tests/test_desktop_tools.c`（56 PASS / 0 FAIL，独立 mock HTTP，不需要 8091）：

- 注册表 150 / desktop 20 / 每件 risk / sub=desktop / channel 字符串映射。
- 20 件 D0/D1/D2/D3 全表；未知 `desktop_*` 写 → D2。
- D0/D1 NONE 自动放行并实际发 HTTP；D2 NONE → CONFIRM_REQUIRED 且 0 次后端请求。
- D2 `-y` 短租约放行；显式 D2 租约放行；D3 超出 D2 ceiling → `lease_ceiling_denied`。
- D3 NONE/`-y` 都确认；显式 D3 放行后后端 501 → `E_DESKTOP_HTTP_501` + `available=false`（不伪造成功）。
- 非法 theme/app/window id 参数拒绝；引号/换行 JSON 转义；后端不可达 `E_DESKTOP_UNAVAILABLE`；非 loopback `E_DESKTOP_URL`。
- trace sample：`fix-w76/trace-sample/trace/*.jsonl` 含 D0/D1/D2/D3 的 `policy_decision`，字段 danger/lease_id/confirmation；`audit.log` 行尾含 lease/danger/confirm。

全量：`make -C agent/ai/tests test` = 30 个 C 测试 + `test_make_deps.sh`，RC=0，0 warning；`test_registry_manifest.py` ALL PASS（150/150）；`test_corpus_aliases.py` RESULT PASS（166 条）。

## 7. 卸载/停用

1. 停 demo：`cd ~/fix-w48gui/img1 && bash run.sh stop`。8091 关闭后 `ai --help` rc=0、`ai --lease /nonexistent` rc=1 fail-closed、`test_lease_gate` 98/0、`test_desktop_tools` 56/0（mock，不依赖 8091）。
2. 恢复 demo：`bash run.sh start`；health 返回 127.0.0.1 / IMG-6-W76。
3. 移除能力：从 `tools/gen_registry.py` 去掉 `desktop_tools()` 调用（或回退 tools.json 到 130 件快照）→ 重新生成 + 重编 `ai`；`desktop` executor 代码保持休眠，不影响其他通道。
4. 回退 demo 源：`fix-w76/*.orig`（server.py/app.js/index.html/style.css）拷回；本波只在 L1 demo 与 agent 树改文件。

## 8. 未解风险

- **Web demo 不是真 OS 桌面**：窗口是服务端虚拟状态，不启动宿主进程；真窗口管理器/会话见 W84。
- **输入注入权限/隐私**：`desktop_input_*` 等于代替用户操作；D2 只保证“有确认/租约”，不保证“目标窗口就是用户以为的那个”。多用户/远程会话需要 W83/W84 的会话绑定。
- **截图/剪贴板敏感数据**：截图含全部窗口内容；剪贴板可能含密钥。工具按 D0/D2 分级并写审计，但读取本身不脱敏；证据只存 sha256/长度，不存旧剪贴板内容。
- **Playwright 依赖**：截图依赖 chromium（~/.cache/ms-playwright）；缺失时明确 503 `playwright_unavailable`，不伪造空图。`/dev/shm/ms-playwright` 在本次环境已不存在，代码会自动回落。
- **8091 单点**：demo 停则桌面工具 `E_DESKTOP_UNAVAILABLE`；AI 核心与其他工具不受影响，但桌面能力不可用。
- **loopback 无鉴权**：127.0.0.1:8091 对本机任意 uid 可达；当前依赖本机信任 + Agent 侧租约。跨用户隔离/令牌认证留 W83。
- **电源不可用**：W76 明确 501，不执行；接 logind 留 W84（当前 `logind_seats` 目录存在也不代表可安全操作）。
- **虚拟窗口语义有限**：无真实应用进程、无菜单/对话框、无拖拽；只覆盖枚举/启动/聚焦/关闭/文本输入。
