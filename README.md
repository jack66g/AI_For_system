# AIKernel — AI 主体接管 Linux 的控制系统

> 版本：**0.1.0-alpha.11.0**（2026-10-22 源码快照）
> 基础内核：Linux **6.18.39**（#59，GPL-2.0）
> 仓库定位：可审计的源码基线，不包含 ISO、rootfs 镜像、构建产物、证据日志或任何密钥。

AIKernel 把 Linux 内核作为被管理对象，由 AI 控制台（`agent/ai`）通过统一能力总线、租约/确认/审计和本地/云端双通道执行操作。AI 是系统的执政者，人是授权者；安全机制用于防止意图被篡改、注入或伪造，而不是给 AI 的能力设上限。

## 当前状态

alpha.11.0 已通过发布门禁并部署到生产 VM（不重启）：

- 50 场景：**M1 50/50**，M3 契约 **100%**，M5 **100%**，P95 all **30.5s** / regular **23.7s**
- workday：**20/20**，stuck 0，无连续压缩，T11/T19 上下文回忆通过
- Clarify 专项：**23/23**，漏问 0、不必要询问 0、推荐接受 3/3、澄清后成功 3/3
- qemu：install **6/6**、diskboot **6/6**、contentcheck 全 PASS、deskcheck **15/15**
- 注册表：**151 工具 / 8 域 / 20 desktop**，seed **167**；0 未授权 D3/D4
- 发布件：shell `adb71f65c7e60fdcba2ce88da9093546`、API `e007a7d9d9e8cd9e81ec977d92bd9056`（v3）、factory `5f26e2bfe1a7658aea81f90953ea778a`、ISO `550c003da0da875b3350ac87aab80fb6`

已知限制（如实记录）：

- 真实 qwen2.5:1.5b 的工具调用能力仍不达标（B-059）；当前 1.5B 是占位/可替换模型，不代表最终本地能力。
- W77d 本地模型生命周期（install/benchmark/switch/rollback/remove）尚未实现。
- W76 桌面是 Web demo，不是真 OS 桌面；截图 503、power 501 为当前边界。
- 语义全知审计 70.1%、typed 10.3%（B-036），交 W82。
- 尚无 CI/密钥托管（W81）；生产 VM 的 cloud key 需按 B-075 轮换。

## 仓库结构

```
AIKernel/            内核侧 AI 子系统（感知/决策/执行/遥测/KUnit 测试）
agent/ai/            用户态 AI 控制台（aikernel-shell/ask/工具/租约/API/沙箱/测试）
kernel-overlays/     对干净 Linux 6.18.39 的全部项目改动（168 个文件 + 清单）
.config              alpha.11.0 的内核配置
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

# 2) 内核（期望 #59；二进制 md5 受构建路径/时间戳影响）
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

alpha.10 及更早的发布记录、门禁证据和缺陷账本保存在项目工作区 `longterm/`（不随源码仓库提交）。本仓库自 alpha.11.0 起作为源码基线。
