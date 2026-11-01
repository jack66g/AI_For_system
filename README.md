# AIKernel — AI 主体接管 Linux 的控制系统

> 版本：**0.1.0-alpha.14.0** · 内核 **Linux 6.18.39 #61**（GPL-2.0）
> 仓库定位：可审计的**纯源码基线**——不包含 ISO、rootfs 镜像、构建产物、证据日志或任何密钥。

AIKernel 把 Linux 内核当作被管理对象：AI 通过统一能力总线、租约/确认/审计，
直接感知并改变内核与用户态状态。**AI 是系统的执政者，人是授权者；安全机制防的是
"意图被篡改/注入/伪造"，不是给 AI 的能力设上限。**

**先读这一份**：👉 [`SYSTEM-ARCHITECTURE.md`](SYSTEM-ARCHITECTURE.md) —— 全系统总介绍
（三层架构、230 工具面、一次 ask 的完整路径、当前边界）。

## 当前状态（alpha.14.0 基线 + W81/W82 增补，未发版）

- **内核 #61**：`bzImage` 19,489,792 B，md5 `e4f6dbeac8eeb006abcb17c0871cf9e8`，0 error。
  新增 `OVERLAY_FS` / `NETFILTER_ADVANCED`+`NFQUEUE` / `BPF_LSM` / `CGROUP_BPF` 共 8 个 `=y`。
- **AI LSM 扩展**：任务级 workspace 标签（blob、fork 继承）+ 三维规则
  （pid > label > path_prefix）+ `socket_connect` / `socket_sendmsg` / `file_permission`
  三个新 hook。修掉多令牌 `lsm=` 只注册首个的根因（`MAX_LSM_COUNT` 未计入内建 `ai`）。
- **能力面**：⭐ **230 工具 / 26 通道 / 9 能力域 / seed 247**，单一正典 `agent/ai/tools/tools.json`。
  （alpha.14.0 发版时为 197/19/214；W81 新增网络意图编译、命中闭环、应用画像、工作区网络、攻击链关联与靶场，共 +18 工具 / +4 通道）
  W79 加 `workspace`（loop+ext4 持久盘）与 `sched`（双调度台）；W80 加 `bpf`
  （裸 `bpf()` 加载器 + nfqueue 判决）；W82 加 `appctl` 控制面适配器与
  画像→策略（`app_policy_generate` R/D1 只生成，`app_policy_apply` W2/D3
  fail-closed：本机无 `ai` LSM 时明确拒绝并报实际 LSM 列表）；W82 V5.1/V5.2
  加 `device` 通道（USB 枚举/识别 R/D0，`dev_bind` W2/D3 先快照后写、
  失败自动回滚，`dev_restore` W2/D2 按快照恢复；根 hub/class=9/多接口
  一律拒绝）；W82 V5.3/V5.4 加 `dev_adapt`（W2/D3，四级递进：在树 new_id →
  driver_override → 通用类驱动 → 参数 quirk，每级读回验证、失败回滚）与
  `dev_task`（W1/D1，异步 status/log/cancel，取消即恢复到任务前驱动）；
  W82 V1.8 把 `aik-sandbox` 收敛为 workspace 的 tmpfs backend（单一销毁路径，
  `sandbox_*` 保留为薄适配层）。
- **回归**：`tests/run_all` **58/58**；能力审计 PASS（gaps P0=0）。
- **qemu**：install **6/6**、diskboot **7/7**、contentcheck **58/58**、deskcheck **15/15**。
  真内核实测 `lsm=selinux,ai,bpf` → `capability,selinux,ai,bpf`；overlay CoW 挂载成功。
- **发布件**：ISO `2f2c6cde7fea1618d2af1f1d5205d9cc`（753,551,360 B）、
  shell `e48c198dee8fe2d3589c58efb7310f74`。

## 已知限制（如实记录）

- **生产 VM 仍是内核 #59**：alpha.14.0 只在 qemu 验证，尚未 A/B 升级到生产。
- **装机盘默认不带 bpf LSM**（B-105）：光盘引导是 `lsm=ai,bpf`，安装器写入目标盘的 grub 仍是
  `lsm=ai`，装机后 BPF LSM 程序可加载但不生效（工具会告警，不假成功）。
- **contentcheck 的 LSM 断言测错对象**（B-106）：在 `chroot` 里读 `/sys`，读到的是 Live 环境。
- **MCE 埋点在 noinstr 路径调 snprintf**（B-104）：objtool 报警，属既有债。
- **W76 桌面是 Web Demo**：8091 是浏览器演示面，真实 GUI 控制面未做。
- **语义全知 70.1%**（B-036）：读路径 96.9%，但"结构化 + 语义"仅 70.1%。
- 尚无 CI / 产物签名；生产 VM 的 cloud key 需按 B-075 轮换。

## 仓库结构

```
SYSTEM-ARCHITECTURE.md  全系统总介绍（唯一导览：三层架构 + 能力面 + 边界）
BUILD.md                从零构建（含 -j3 内核 / -j1 用户态的约束与原因）
SECURITY.md             安全模型与红线
AIKernel/               内核侧 AI 子系统（感知/决策/执行/遥测/KUnit）
agent/ai/               用户态 AI 控制台（shell/ask/工具/租约/API/沙箱/测试）
kernel-overlays/        对干净 Linux 6.18.39 的全部项目改动（169 个文件 + 逐文件 SHA-256）
.config                 内核配置（#61）
factory/                出厂 rootfs 自有资产（systemd 单元、sbin、seed、配置）
desktop/                Web 桌面 demo 源码（不含运行时 data/）
build/                  发布/部署/监控脚本（含 apply-overlays.sh）
w6i-tools/              ISO 安装/打包线（init、grub、导出脚本）
docs/                   能力矩阵、清理审计、轨迹 schema、文档冻结说明
```

`kernel-overlays/` 是完整侵入面：顶层 `Makefile`/`Kconfig`/`Kbuild` 接入 + 152 个上游内核
源文件的 AI 钩子（遥测为主，少量门控行为修改）。清单见 `kernel-overlays/MANIFEST.sha256`，
可用 `build/apply-overlays.sh` 在干净源码上重建并逐文件校验。

## 构建（最短路径）

```bash
# 1) 干净内核树 + overlay
tar -xf linux-6.18.39.tar.xz
bash build/apply-overlays.sh "$PWD/linux-6.18.39"
cp .config linux-6.18.39/.config

# 2) 内核（7G 内存机器必须 -j3；-j8 会被 OOM 静默杀掉）
cd linux-6.18.39 && make -j3

# 3) 用户态控制台（Makefile 已加 .NOTPARALLEL）
cd ../agent/ai && make -j1

# 4) 自检
python3 tools/audit_capabilities.py --check
bash tests/run_all.sh
```

完整说明（依赖、模块、ISO 打包）见 [`BUILD.md`](BUILD.md)。

## 许可证与来源

- 基础内核：[Linux 6.18.39](https://www.kernel.org/)，GPL-2.0。
- `AIKernel/`、`agent/ai/`、`kernel-overlays/`、`factory/`、`desktop/`、`build/`、`w6i-tools/`
  为项目原创代码，延续 GPL-2.0，文件头保留 SPDX 标识。
- 第三方 `agent/ai/third_party/mbedtls` 保留上游许可证与目录结构。

## 安全

仓库**不包含任何密钥、密码或 token**。`/root/.aikernel/model.toml`、`/etc/aikernel/api-token`、
VM 备份、ISO、证据目录与 trace 都不入库。安全模型与红线见 [`SECURITY.md`](SECURITY.md)。

## 历史

alpha.10 及更早的发布记录、门禁证据与缺陷账本保存在项目工作区（不随源码仓库提交）。
本仓库自 alpha.11.0 起作为源码基线；alpha.11.0 / 12.0 / 13.0 三个 tag 已随一次历史清洗
重新指向（见 SECURITY.md 的凭据处理说明）。
