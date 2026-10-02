# factory/ — 出厂系统资产（w7i-rootfs 收编）

本目录是 AIKernel 出厂 rootfs（guest 内 `/`）中**自有出厂资产**的权威收编层，
全部文件从构建机 `~/w7i-rootfs/` 对应路径原样收集（2026-10-02，v1.4 / alpha.4 快照）。
路径结构保持 rootfs 内的绝对路径映射：`factory/etc/...` ↔ guest `/etc/...`。

## 与 build-rootfs.sh 的分工

`agent/ai/build-rootfs.sh` 是 **L1 底座构建脚本**（debootstrap jammy minbase +
分区/挂载/三件套部署，W4A 时代），其中内联生成的
`aikernel-memory.service`、`ollama.service`、`/root/.aikernel/*.toml` 等是**初版**。
后续波次（W5–W12）对出厂资产的演进一律直接落在 `~/w7i-rootfs/`，
本目录即其权威快照；**重装/重建 rootfs 时以本目录覆盖为准**。

## 收编清单

### /etc/systemd/system/（自定义单元，7 件）

| 文件 | 作用 |
| --- | --- |
| `aikernel-api.service` | 远程 AI API（127.0.0.1:8761，Bearer 鉴权，token 见 `/etc/aikernel/api-token`） |
| `aikernel-health.service` | 健康自愈一轮检查（ollama/SME/ssh 三服务 + 根分区使用率） |
| `aikernel-health.timer` | 上述服务定时器（OnBootSec=2min，之后每 5min 一轮） |
| `aikernel-memory.service` | SME 记忆引擎 REST（127.0.0.1:8000，oneshot+RemainAfterExit） |
| `ollama.service` | 本地 LLM 引擎（127.0.0.1:11434，Restart=always） |
| `sme-seed.service` | 首启 SME 种子（按 text 差量导入接口语料，幂等） |
| `ssh-keygen.service` | 开机补齐缺失 SSH host key（`ssh-keygen -A`） |

### /usr/local/sbin/（2 件）

- `aikernel-api` — 远程 AI API 服务端（python3，Tools = `/usr/local/share/aikernel/tools.json`）
- `aikernel-health.sh` — 健康检查脚本（被 `aikernel-health.service` 调用，日志 `/tmp/aikernel-health-last.log`）

### /usr/local/share/aikernel/（4 件）

- `tools.json` / `tools.openai.json` — 75 工具注册表（与 `agent/ai/tools.json` 同源同版）
- `sme-seed.jsonl` — 首启接口语料种子（164 条，tag=aikernel-interface）
- `sme-seed.sh` — 差量导入脚本（v2：按 text 去重，天然幂等，可随版本升级）

### /etc/ 直下（1 件）与 /etc/systemd/（3 件）

- `nftables.conf` — 出厂防火墙基线（loopback + 已建立连接放行，其余入栈默认策略）
- `systemd/journald.conf` — 持久化日志（Storage=persistent 等）
- `systemd/timesyncd.conf` — NTP 出厂对时（NTP 池）
- `systemd/network/80-wired.network` — networkd 有线网 DHCP（配合 systemd-networkd）

## 启用关系（出厂 systemctl enable 状态）

multi-user.target.wants：`aikernel-api`、`aikernel-memory`、`ollama`、`sme-seed`、
`ssh-keygen`、`nftables`、`systemd-networkd`、`systemd-resolved`、
`systemd-timesyncd`、`ssh`。
timers.target.wants：`aikernel-health.timer`。

## 更新流程

改出厂资产 → 直接改构建机 `~/w7i-rootfs/` 内对应文件（并用 ISO 实测）→
按本目录相同相对路径收编回来并提交。勿只改本目录（本目录是收编层，不是构建层）。
