# factory/ — 出厂系统资产（alpha.12.0 收编）

本目录对应 guest rootfs 的绝对路径：`factory/etc/...` ↔ `/etc/...`，`factory/usr/...` ↔ `/usr/...`。只收编**项目自有**资产，不包含发行版文件、运行时密钥或 rootfs 镜像。

## systemd 单元（15 件）

| 文件 | 作用 |
|---|---|
| `aikernel-api.service` | 远程 AI API（127.0.0.1:8761，Bearer；token 安装时生成） |
| `autocondense.service` | 上下文压缩服务 autocondensed（127.0.0.1:**8762**，T9d 改号——8761 让给 aikernel-api，撞端口坑清偿） |
| `aikernel-health.service` / `.timer` | 健康自愈（5min 一轮） |
| `aikernel-memory.service` | SME 记忆引擎 REST（127.0.0.1:8000） |
| `aikernel-backup.service` / `.timer` | A/B 备份 |
| `aikernel-upgrade-commit.service` / `.timer` | A/B 升级健康门提交 |
| `aik-disk-check.service` / `.timer` | 磁盘水位检查 |
| `aik-desktop.service` | Web 桌面 demo（127.0.0.1:8091） |
| `ollama.service` | 本地模型引擎（127.0.0.1:11434；出厂不预装模型，按需 `aik model install`） |
| `sme-seed.service` | 首启 seed 幂等导入 |
| `ssh-keygen.service` | 开机补齐缺失 SSH host key |

## autocondense 三件套（T9d 随 occ 首次进厂）

| 件 | 出厂形态 | 说明 |
|---|---|---|
| `autocondensed` | `autocondense.service` → `/usr/local/sbin/autocondensed --port 8762` | 常驻 REST（/health /check /judge /begin /commit … 12 端点）；显式 `--port 8762` 保证旧 config.json 残留也不撞 8761 |
| `autocondense-hook` | `/usr/local/sbin/aik-ac-hook`（本目录收编的 shell 转发脚本，755） | 宿主钩子入口：`aik-ac-hook <Event> < in.json`；异常静默 exit 0（钩子绝不拖垮宿主） |
| `autocondense-mcp` | 由发布脚本装到 `/usr/local/sbin/`（stdio，无单元） | MCP 7 工具 `condense_*`，宿主按需拉起 |

三件二进制源在 `agent/ai/autocondense/`（`make -C autocondense all`），与 `aikernel-api` 同样**不在本目录重复**，由发布脚本安装。
出厂部署门：`agent/ai/occ/tests/t9d_factory_gate.sh`（独立断言，可迁移进 qsmoke contentcheck：`bash t9d_factory_gate.sh --root "$CHROOT"`）。

## /usr/local/sbin

- `aik-backup`、`aik-cert-gen`、`aik-reset`、`aik-token`、`aik-upgrade`、`aikernel-health.sh`、`aik-ac-hook`
- `aikernel-api` **不在本目录重复**：源在 `agent/ai/api/aikernel-api`，由发布脚本安装到 `/usr/local/sbin/`。
- `autocondensed` / `autocondense-mcp` / `autocondense-hook` 同上：源在 `agent/ai/autocondense/`，发布脚本安装。

## /usr/local/share/aikernel

- `tools.json` / `tools.openai.json` / `tools-sandbox.json` / `tool_catalog.txt`（156/9/20、7 工具）
- `sme-seed.jsonl`（173 行）、`sme-seed.sh`（差量幂等导入）
- `model-catalog.json`（`aik model` 目录源，6 条目，硬件门控推荐）

## /etc 配置

`motd`、`nftables.conf`、`default/locale`、`apt/apt.conf.d/*`、`systemd/journald.conf`、`systemd/timesyncd.conf`、`systemd/network/80-wired.network`、`ssh/sshd_config`、`aikernel/policy.conf`。

## 桌面

`desktop/` 是 Web demo 源码；安装到 `/opt/aikdesktop`，unit 为 `factory/etc/systemd/system/aik-desktop.service`。apps-catalog.json 等四件（apps-catalog/desktop/notifs/pin.json）为静态种子数据，随仓库 `desktop/data/` 收编（T7e 起）；运行时可写态由服务在 StateDirectory 生成。

## 秘密与安全

- 本目录不含 `model.toml`、API token、SSH host key 或任何私钥。`aik-token` 在安装/运维时生成。
- `ssh/sshd_config` 是当前出厂基线（允许 root/密码登录），**不是最终安全配置**；W83 需重新评估。
- API token 存储位：`~/.aikernel/model.toml [api] token`（默认，600）或 `/etc/aikernel/api-token`（600）。

## 启用关系

`multi-user.target.wants`：`aikernel-api`、`autocondense`、`aikernel-memory`、`ollama`、`sme-seed`、`ssh-keygen`、`aik-desktop`、`nftables`、`systemd-networkd`、`systemd-resolved`、`systemd-timesyncd`、`ssh`。
`timers.target.wants`：`aikernel-health.timer`、`aikernel-backup.timer`、`aikernel-upgrade-commit.timer`、`aik-disk-check.timer`。

修改流程：改构建机 rootfs → ISO/qemu 实测 → 按相同相对路径收编回本目录；不要只改本目录当构建层。
