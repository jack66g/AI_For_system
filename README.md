# AIKernel — AI 主体接管 Linux 的控制系统

> 版本：**0.1.0-alpha.13.0**（2026-10-26 源码快照；W78：事件流 + 宏工具 + netadmin + mbedtls TLS 服务端 + mTLS 网关 + lsm=ai + 内核 BTF/PSI/FANOTIFY/INET_DIAG/SCHED_EXT）
> 基础内核：Linux **6.18.39**（#60，GPL-2.0）
> 仓库定位：可审计的源码基线，不包含 ISO、rootfs 镜像、构建产物、证据日志或任何密钥。

AIKernel 把 Linux 内核作为被管理对象，由 AI 控制台（`agent/ai`）通过统一能力总线、租约/确认/审计和本地/云端双通道执行操作。AI 是系统的执政者，人是授权者；安全机制用于防止意图被篡改、注入或伪造，而不是给 AI 的能力设上限。

## 当前状态

alpha.13.0 已通过发布门禁（qemu install/diskboot/contentcheck/deskcheck 全绿）并部署到生产 VM（服务级零重启，boot_id 前后一致）：

- W78 能力面：**六条事件流**（event_listen/proc_watch/taskstats_sample/nflog_dump/net_monitor/udev_monitor，NETLINK_AI EVENT/CONNECTOR/TASKSTATS/NFLOG/rtnetlink/udev）+ **13 宏工具**（psi_snapshot/kernel_ai_healthcheck/诊断/基线/sysctl 快照恢复/调度/ip_ban_verified/process_quarantine 等）+ **7 netadmin 工具**（net_iface/addr/route/link/nft_txn）；mbedtls SSL 服务端回开（+14 符号 +20.7KB）+ `cloud/tls_gateway` mTLS 网关（8443→8761，出厂 disabled）
- 全量回归：tests/run_all **45 pass / 0 fail**（新增 test_streams/test_macros/test_net_admin/test_tls_srv/test_tls_gateway）；能力审计 **W75 CHECK PASS**（gaps P0=0）
- qemu（alpha.13.0 ISO，内核 #60）：install **6/6**、diskboot **7/7**（k60+lsm=ai+softdog）、contentcheck **56/56**、deskcheck **15/15**；#60 七项验证全绿（PSI 三文件、lsm=ai 生效、INET_DIAG rtt 明细、fanotify fd、sched_ext 编入未激活）
- 注册表：**182 工具 / 9 域 / 16 通道 / 20 desktop**（W78 新增 26 工具，通道 13→16：+stream/macro/netadmin），seed **199**；0 未授权 D3/D4
- 发布件：shell `487b21b6f974ed78a20353449991b477`、API `e007a7d9d9e8cd9e81ec977d92bd9056`（v3，未变）、factory tar `064b7ce1cc0d431acd2c5a2ff92ed19e`、ISO `ab6a98e7cebf6f147e10059ef5345d20`（752,271,360 B）、内核 #60 bzImage `026e33b75af0661d5a8f9313414abe51`
- 生产 VM：用户态服务级部署（shell/sandbox/tools.json 182/seed 199 双份/tls-gateway unit disabled），`ai --version` = 0.1.0-alpha.13.0，api restart 后 active、failed_units=0
- alpha.12.0 基线（W78 未重跑）：M1 50/50、M3/M5 100%、workday 20/20、clarify C 单测 188/0 + gate 31/31；模型生命周期与云端优先引导延续（`aik model *` + 5 个 `model_*` 总线工具）

已知限制（如实记录）：

- 生产 VM 内核仍 #59（#60 A/B 切换待批）：psi_snapshot 在 VM 降级（/proc/pressure 不存在）、event_listen 等内核依赖事件面暂不可用；ISO 与 qemu 验证盘已是 #60。
- `lsm=` 出厂单令牌 `lsm=ai`：多令牌清单实测仅第一个生效（selinux,ai→仅 selinux；ai,selinux→仅 ai），多 LSM 并存列入后续项。
- TLS 服务端私钥须明文 PEM 且权限 600（PKCS5/PKCS12 已裁，加密私钥不可解析）；纯客户端链路不受影响。
- 出厂不预装本地模型（alpha.12 起）：本地模型按需 `aik model install`（D2 确认，装后验证、失败如实上报）；推荐目录 6 条（星火 X2.5-4B/1.7B/X2.6-4B、qwen3:8b、qwen2.5:7b、llama3.1:8b，硬件门控）。B-059 已随预装移除关闭。
- W76 桌面是 Web demo，不是真 OS 桌面；截图 503、power 501 为当前边界。
- 语义全知审计 70.1%、typed 10.3%（B-036），交 W82。
- 尚无 CI/密钥托管（W81）；生产 VM 的 cloud key 需按 B-075 轮换。

## 仓库结构

```
SYSTEM-ARCHITECTURE.md  全系统总览（W78 新增；快照口径 162 工具/14 通道，工具数以 agent/ai/tools/tools.json 为准）
AIKernel/            内核侧 AI 子系统（感知/决策/执行/遥测/KUnit 测试）
agent/ai/            用户态 AI 控制台（aikernel-shell/ask/工具/租约/API/沙箱/测试）
kernel-overlays/     对干净 Linux 6.18.39 的全部项目改动（168 个文件 + 清单 + active/dormant 状态表）
.config              内核配置（alpha.13.0；#60：BTF/PSI/FANOTIFY/INET_DIAG/SCHED_CLASS_EXT 开）
factory/             出厂 rootfs 自有资产（systemd 单元、sbin、seed、配置）
desktop/             Web 桌面 demo 源码（不含运行时 data/）
build/               发布/部署/监控脚本（含 apply-overlays.sh）
w6i-tools/           ISO 安装/打包线（init、grub、导出脚本）
docs/                架构/清理审计/发布说明
```

`kernel-overlays/` 是完整侵入面：包括 `Makefile`/`Kconfig`/`Kbuild` 顶层接入、约 160 个上游内核源文件的 AI 钩子，以及 W48 对 `sch_fq`/`sch_codel`/`sch_fq_codel` 的死代码清理。完整清单与逐文件 SHA-256 见 `kernel-overlays/MANIFEST.sha256`。

## 构建

从零构建见 [`docs/BUILD.md`](docs/BUILD.md)。最短路径：

```bash
# 1) 干净内核树
tar -xf linux-6.18.39.tar.xz
bash build/apply-overlays.sh "$PWD/linux-6.18.39"
cp .config linux-6.18.39/.config

# 2) 内核（期望 #60；二进制 md5 受构建路径/时间戳影响）
cd linux-6.18.39 && make -j"$(nproc)"

# 3) 用户态控制台（Makefile 已加 .NOTPARALLEL）
cd ../agent/ai && make -j1

# 4) 注册表/能力自检
cd ../agent/ai && python3 tools/audit_capabilities.py --check
```

## 许可证与来源

- 基础内核：[Linux 6.18.39](https://www.kernel.org/)，GPL-2.0，版权归 Linus Torvalds 与 Linux 内核社区。
- `AIKernel/`、`agent/ai/`、`kernel-overlays/` 中的项目改动、`factory/`、`desktop/`、`build/`、`w6i-tools/` 为原创代码，延续 GPL-2.0；文件头保留 SPDX 标识。
- 第三方 `agent/ai/third_party/mbedtls` 保留上游许可证与目录结构。

## 安全

仓库不包含任何密钥、密码或 token。`/root/.aikernel/model.toml`、`/etc/aikernel/api-token`、VM 备份、ISO 和证据目录都不入库。细节与当前安全边界见 [`SECURITY.md`](SECURITY.md)。

## 历史

alpha.10 及更早的发布记录、门禁证据和缺陷账本保存在项目工作区 `longterm/`（不随源码仓库提交）。本仓库自 alpha.11.0 起作为源码基线，当前快照 alpha.13.0（W78：事件流/宏工具/netadmin/mTLS 网关，内核 #60 BTF/PSI/FANOTIFY/INET_DIAG/SCHED_EXT；历史接口导表 AIKernel_Docs 冻结在源树，见 docs/AIKERNEL-DOCS-FREEZE.md）。
