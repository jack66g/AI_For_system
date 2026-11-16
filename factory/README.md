# factory/ — 出厂系统资产（alpha.12.0 收编）

本目录对应 guest rootfs 的绝对路径：`factory/etc/...` ↔ `/etc/...`，`factory/usr/...` ↔ `/usr/...`。只收编**项目自有**资产，不包含发行版文件、运行时密钥或 rootfs 镜像。

## systemd 单元（18 件）

| 文件 | 作用 |
|---|---|
| `aikernel-api.service` | 远程 AI API（127.0.0.1:8761，Bearer；token 安装时生成） |
| `autocondense.service` | 上下文压缩服务 autocondensed（127.0.0.1:**8762**，T9d 改号——8761 让给 aikernel-api，撞端口坑清偿） |
| `aikernel-health.service` / `.timer` | 健康自愈（5min 一轮；C-P1e 三闸=宽限/冷却/内存闸；C-P2e 告警出口=webhook+标志文件） |
| `aikernel-memory.service` | SME 记忆引擎 REST（127.0.0.1:8000） |
| `aikernel-backup.service` / `.timer` | A/B 备份（C-P2d：`--with-home`/`--with-data` 可选用户数据面，分族保留） |
| `aikernel-upgrade-commit.service` / `.timer` | A/B 升级健康门提交 |
| `aik-disk-check.service` / `.timer` | 磁盘水位检查 |
| `aik-log-trim.service` / `.timer` | 文件日志有界化（C-P1c，2026-11-17：追加日志 >8M 保尾 4M；telemetry 天目录保 14 天） |
| `aik-cron.service` | cron 守护（C-P2b：busybox crond；用户通道=`crontab` 命令，spool=/var/spool/cron/crontabs） |
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

- `aik-backup`、`aik-cert-gen`、`aik-reset`、`aik-token`、`aik-upgrade`、`aikernel-health.sh`、`aik-ac-hook`、`aik-log-trim`（C-P1c）
- `busybox`（C-P2b/g，2026-11-17：L1 静态 busybox v1.30.1 入厂）+ 同目录
  `crond`/`crontab`/`fdisk` 符号链（分区面 D2 路径：`fdisk -l`/`fdisk /dev/vda`
  经 busybox applet 提供；parted/LVM 评估在案 P3）
- 静态 IP 工具（C-P2a，2026-11-17）：occ 第九工具 config_write_network
  （OCC_NETCFG_TOOLS=1 旗控注册——差分红线：默认清单零变化；出厂在
  aik-console 三处调用与 aikernel-api.service 置位）。write/remove/show
  三动作，目标恒 /etc/systemd/network/70-static-<iface>.network（先于
  出厂 80-wired 生效=静态覆盖 DHCP，删文件即回）；全参校验；W2 门。
- 告警出口（C-P2e）：`/etc/aikernel/health-alert.conf` 写
  `WEBHOOK_URL=http://host/path` 即开（缺省=仅 journal+wall）；
  FAIL-ALERT 升级/RECOVERED 各发一次 JSON POST；本地标志
  `/run/aikernel-health/alert-<item>.flag`
- `aikernel-api` **不在本目录重复**：源在 `agent/ai/api/aikernel-api`，由发布脚本安装到 `/usr/local/sbin/`。
- `autocondensed` / `autocondense-mcp` / `autocondense-hook` 同上：源在 `agent/ai/autocondense/`，发布脚本安装。

## /usr/local/share/aikernel

- `tools.json` / `tools.openai.json` / `tools-sandbox.json` / `tool_catalog.txt`（156/9/20、7 工具）
- `sme-seed.jsonl`（173 行）、`sme-seed.sh`（差量幂等导入）
- `model-catalog.json`（`aik model` 目录源，6 条目，硬件门控推荐）

## /etc 配置

`motd`、`nftables.conf`、`default/locale`、`apt/apt.conf.d/51-aik-upgrade-policy`、`systemd/journald.conf`、`systemd/timesyncd.conf`、`systemd/network/80-wired.network`、`ssh/sshd_config`（纯净基线）+ `ssh/sshd_config.d/50-aik-hardening.conf`（硬化，C-P1a）、`aikernel/policy.conf`。

## 桌面

`desktop/` 是 Web demo 源码；安装到 `/opt/aikdesktop`，unit 为 `factory/etc/systemd/system/aik-desktop.service`。apps-catalog.json 等四件（apps-catalog/desktop/notifs/pin.json）为静态种子数据，随仓库 `desktop/data/` 收编（T7e 起）；运行时可写态由服务在 StateDirectory 生成。

## 秘密与安全

- 本目录不含 `model.toml`、API token、SSH host key 或任何私钥。`aik-token` 在安装/运维时生成。
- SSH 出厂硬化（C-P1a/W83，2026-11-17 落地）：`sshd_config`=纯净基线，硬化集中
  `ssh/sshd_config.d/50-aik-hardening.conf`（prohibit-password+密钥制+防爆破键组）；
  控制台 gate/TUI 不受影响。首启公钥注入：17.8 起 build 侧 PROV_PUBKEY（可选）。
- unattended-upgrades **显式禁用**（C-P1b 决策，2026-11-17）：`apt/apt.conf.d/51-aik-upgrade-policy`
  ——自研开机链经不起 apt 无人值守升级；升级走 aik-upgrade（A/B+金丝雀）与 AI 通道
  （W2 门+undo）。对标 Ubuntu Server 的差异为安全取舍，非能力缺失。
- API token 存储位：`~/.aikernel/model.toml [api] token`（默认，600）或 `/etc/aikernel/api-token`（600）。

## 启用关系

`multi-user.target.wants`：`aikernel-api`、`autocondense`、`aikernel-memory`、`ollama`、`sme-seed`、`ssh-keygen`、`aik-desktop`、`nftables`、`systemd-networkd`、`systemd-resolved`、`systemd-timesyncd`、`ssh`、`aik-cron`。
`timers.target.wants`：`aikernel-health.timer`、`aikernel-backup.timer`、`aikernel-upgrade-commit.timer`、`aik-disk-check.timer`、`aik-log-trim.timer`。

修改流程：改构建机 rootfs → ISO/qemu 实测 → 按相同相对路径收编回本目录；不要只改本目录当构建层。
