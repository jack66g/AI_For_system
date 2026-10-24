# factory/ — 出厂系统资产（alpha.12.0 收编）

本目录对应 guest rootfs 的绝对路径：`factory/etc/...` ↔ `/etc/...`，`factory/usr/...` ↔ `/usr/...`。只收编**项目自有**资产，不包含发行版文件、运行时密钥或 rootfs 镜像。

## systemd 单元（14 件）

| 文件 | 作用 |
|---|---|
| `aikernel-api.service` | 远程 AI API（127.0.0.1:8761，Bearer；token 安装时生成） |
| `aikernel-health.service` / `.timer` | 健康自愈（5min 一轮） |
| `aikernel-memory.service` | SME 记忆引擎 REST（127.0.0.1:8000） |
| `aikernel-backup.service` / `.timer` | A/B 备份 |
| `aikernel-upgrade-commit.service` / `.timer` | A/B 升级健康门提交 |
| `aik-disk-check.service` / `.timer` | 磁盘水位检查 |
| `aik-desktop.service` | Web 桌面 demo（127.0.0.1:8091） |
| `ollama.service` | 本地模型引擎（127.0.0.1:11434；出厂不预装模型，按需 `aik model install`） |
| `sme-seed.service` | 首启 seed 幂等导入 |
| `ssh-keygen.service` | 开机补齐缺失 SSH host key |

## /usr/local/sbin

- `aik-backup`、`aik-cert-gen`、`aik-reset`、`aik-token`、`aik-upgrade`、`aikernel-health.sh`
- `aikernel-api` **不在本目录重复**：源在 `agent/ai/api/aikernel-api`，由发布脚本安装到 `/usr/local/sbin/`。

## /usr/local/share/aikernel

- `tools.json` / `tools.openai.json` / `tools-sandbox.json` / `tool_catalog.txt`（156/9/20、7 工具）
- `sme-seed.jsonl`（173 行）、`sme-seed.sh`（差量幂等导入）
- `model-catalog.json`（`aik model` 目录源，6 条目，硬件门控推荐）

## /etc 配置

`motd`、`nftables.conf`、`default/locale`、`apt/apt.conf.d/*`、`systemd/journald.conf`、`systemd/timesyncd.conf`、`systemd/network/80-wired.network`、`ssh/sshd_config`、`aikernel/policy.conf`。

## 桌面

`desktop/` 是 Web demo 源码；安装到 `/opt/aikdesktop`，unit 为 `factory/etc/systemd/system/aik-desktop.service`。运行时 `data/` 由服务生成，不入库。

## 秘密与安全

- 本目录不含 `model.toml`、API token、SSH host key 或任何私钥。`aik-token` 在安装/运维时生成。
- `ssh/sshd_config` 是当前出厂基线（允许 root/密码登录），**不是最终安全配置**；W83 需重新评估。
- API token 存储位：`~/.aikernel/model.toml [api] token`（默认，600）或 `/etc/aikernel/api-token`（600）。

## 启用关系

`multi-user.target.wants`：`aikernel-api`、`aikernel-memory`、`ollama`、`sme-seed`、`ssh-keygen`、`aik-desktop`、`nftables`、`systemd-networkd`、`systemd-resolved`、`systemd-timesyncd`、`ssh`。
`timers.target.wants`：`aikernel-health.timer`、`aikernel-backup.timer`、`aikernel-upgrade-commit.timer`、`aik-disk-check.timer`。

修改流程：改构建机 rootfs → ISO/qemu 实测 → 按相同相对路径收编回本目录；不要只改本目录当构建层。
