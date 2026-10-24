# AIKernel — AI 主体接管 Linux 的控制系统

> 版本：**0.1.0-alpha.12.0**（2026-10-23 源码快照；W77d/e：云端优先引导 + 模型生命周期 + 询问意识 2.0）
> 基础内核：Linux **6.18.39**（#59，GPL-2.0）
> 仓库定位：可审计的源码基线，不包含 ISO、rootfs 镜像、构建产物、证据日志或任何密钥。

AIKernel 把 Linux 内核作为被管理对象，由 AI 控制台（`agent/ai`）通过统一能力总线、租约/确认/审计和本地/云端双通道执行操作。AI 是系统的执政者，人是授权者；安全机制用于防止意图被篡改、注入或伪造，而不是给 AI 的能力设上限。

## 当前状态

alpha.12.0 已通过发布门禁（qemu install/diskboot/contentcheck/deskcheck 全绿）并部署到生产 VM（服务级，不重启）：

- 50 场景：**M1 50/50**，M3 契约 **100%**，M5 **100%**，P95 all **30.5s** / regular **23.7s**
- workday：**20/20**，stuck 0，无连续压缩，T11/T19 上下文回忆通过
- Clarify 专项（2.0）：C 单测 **188 pass/0 fail**（33 用例）、gate **9 场景 31/31**（漏问 0、乱问 0、推荐接受 3/3），API 不回退（33+21 check）
- qemu：install **6/6**、diskboot **6/6**、contentcheck **49/49**、deskcheck **15/15**
- 注册表：**156 工具 / 9 域 / 20 desktop**（新增 model 域 5 工具），seed **173**；0 未授权 D3/D4
- 模型生命周期：`aik model catalog/recommend/install/remove/switch/rollback/benchmark` + 5 个 `model_*` 总线工具（install/remove=D2 lease，云端大模型可代用户安装）
- 发布件：shell `784cc0f014409cfdd8186f95c557dcd0`、API `e007a7d9d9e8cd9e81ec977d92bd9056`（v3，未变）、factory tar `8aae5ee68574a04e43eeed4a6674c081`、ISO `27bdfe30b6cf0ccfee675d1ffbbc240b`（706,706,304 B）

已知限制（如实记录）：

- 出厂不预装本地模型（alpha.12 起）：本地模型按需 `aik model install`（D2 确认，装后验证、失败如实上报）；推荐目录 6 条（星火 X2.5-4B/1.7B/X2.6-4B、qwen3:8b、qwen2.5:7b、llama3.1:8b，硬件门控）。B-059 已随预装移除关闭。
- W76 桌面是 Web demo，不是真 OS 桌面；截图 503、power 501 为当前边界。
- 语义全知审计 70.1%、typed 10.3%（B-036），交 W82。
- 尚无 CI/密钥托管（W81）；生产 VM 的 cloud key 需按 B-075 轮换。

## 仓库结构

```
AIKernel/            内核侧 AI 子系统（感知/决策/执行/遥测/KUnit 测试）
agent/ai/            用户态 AI 控制台（aikernel-shell/ask/工具/租约/API/沙箱/测试）
kernel-overlays/     对干净 Linux 6.18.39 的全部项目改动（168 个文件 + 清单）
.config              内核配置（alpha.12.0；内核侧与 alpha.11.0 相同，#59）
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

alpha.10 及更早的发布记录、门禁证据和缺陷账本保存在项目工作区 `longterm/`（不随源码仓库提交）。本仓库自 alpha.11.0 起作为源码基线，当前快照 alpha.12.0（不再预装本地模型，工厂树无模型权重与 root 残渣）。
