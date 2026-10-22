# 构建与验证

本文描述如何从**干净 Linux 6.18.39** 重建 alpha.11.0 的源码树。发布 ISO/rootfs 的完整重建还涉及构建机路径和 root 权限，脚本在 `build/`、`w6i-tools/` 中作为参考保留。

## 1. 环境

发布构建使用：

- Ubuntu 22.04（构建机）
- GCC 11.4.0、GNU ld 2.38
- GNU make、Python 3.10
- `grub-mkrescue`（ISO）、QEMU（装机/盘引导冒烟，可选）
- 建议 8 vCPU / 8 GiB 内存 / ≥10 GiB 空闲磁盘

Linux 内核 6.18.39 从 <https://cdn.kernel.org/pub/linux/kernel/v6.x/> 获取。不要使用发行版内核源码替换。

## 2. 内核

```bash
tar -xf linux-6.18.39.tar.xz
bash build/apply-overlays.sh "$PWD/linux-6.18.39"
cp .config linux-6.18.39/.config

cd linux-6.18.39
make -j"$(nproc)"
```

`build/apply-overlays.sh` 会按 `kernel-overlays/MANIFEST.sha256` 逐文件复制并校验。**不要**用 `rsync -a kernel-overlays/` 整目录覆盖：`kernel-overlays/README.md` 与 `MANIFEST.sha256` 是仓库元数据，不属于内核树。

发布内核标识：

```text
Linux version 6.18.39 (jack66g@jack66g-virtual-machine) ... #59 SMP PREEMPT_DYNAMIC Tue Oct 20 20:46:18 CST 2026
```

如果需要相同的构建号/时间戳：

```bash
make -j"$(nproc)" KBUILD_BUILD_VERSION=59 \
  KBUILD_BUILD_TIMESTAMP="Tue Oct 20 20:46:18 CST 2026"
```

`bzImage` 的 md5 会受构建路径、调试信息和版本横幅影响；**源码/overlay 的 SHA-256 才是权威口径**。发布机上的参考 md5 为 `a50cafa6285bbef0f0a2011923481d8f`（#59，路径 `/home/jack66g/linux-6.18.39`）。

顶层接入已在 overlay 中：

- `Makefile`：`core-y += AIKernel/`
- `Kconfig`：`source "agent/Kconfig"`、`source "AIKernel/Kconfig"`
- `Kbuild`：`obj-$(CONFIG_AI_AGENT) += agent/`

## 3. 用户态控制台

```bash
cd agent/ai
make -j1          # Makefile 已设置 .NOTPARALLEL，禁止并发构建
```

产物：

- `aikernel-shell`（静态链接，`--version` 应为 `0.1.0-alpha.11.0`）
- `ai`（指向 `aikernel-shell` 的符号链接）
- `aik-sandbox`（沙箱子智能体二进制）

安装（可选）：

```bash
sudo make install
```

`tools.json`、`tools.openai.json`、`tools-sandbox.json`、`tool_catalog.txt` 在仓库根是 **指向 `tools/` 的符号链接**，保持单源；不要在根目录放同名实体副本，否则会遮蔽正典表。Windows 检出请使用 WSL/Linux 或开启符号链接支持。

## 4. 测试与审计

```bash
make -C tests -j1                       # 构建 35 个测试目标
bash tests/run_all.sh                   # 当前全量 runner（C 33 + Python + audit）

# 或单独运行：
python3 tests/test_api_clarify.py
python3 tests/test_clarify_gate.py --agent-dir .
python3 tests/test_api_clarify_e2e.py --agent-dir .
python3 tools/audit_capabilities.py --check
```

期望：注册表 **151 工具 / 8 域 / 20 desktop**，sandbox **7 工具 / 57 命令**，seed **167**；`audit_capabilities.py --check` PASS。

2026-10-23 干净导出验证结果：C 单元测试 **33/33**（clarify 121、lease 89、lease_gate 98、w77 53/31/18、desktop 56、trace 75 等），API mock **33/33**，clarify gate **23/23**，真 shell API E2E **21/21**，`audit_capabilities.py --check` PASS。

注意：`run-w48-tests.sh` 是 W48 时代的历史 runner，其 `CORE` 源列表没有包含后来新增的 `local/` 依赖，会在 `test_ask_autocompact`/`test_compact_loop` 上出现 BUILD-FAIL；当前全量构建/运行以 `tests/Makefile` + `tests/run_all.sh` 为准。`test_sysctl_tools` 需要 root，非 root 环境会跳过。

50 场景 / workday 运行器依赖生产 VM 的 cloud key 与模型，不在仓库内提供。场景文件在 `agent/ai/tests/usage/scenarios.json`；运行方法见该目录 `README.md`。

## 5. 出厂资产与 ISO

`factory/` 是 rootfs 自有资产的**收编层**，路径对应 guest 根：

```text
factory/etc/...      -> guest /etc/...
factory/usr/...      -> guest /usr/...
```

`desktop/` 是 Web 桌面 demo 源码；安装到 `/opt/aikdesktop`，unit 在 `factory/etc/systemd/system/aik-desktop.service`。

ISO 打包线在 `w6i-tools/`（`init` 安装器、`grub-iso.cfg`、`build-iso.sh`、`export-rootfs.sh`）。`build/w73-build-iso.sh`、`build/w73_factory_refresh.py` 是 alpha.11.0 的发布脚本，含构建机绝对路径（`/home/jack66g/...`）和 root 操作，移植时按环境改路径，不要直接在生产 VM 上运行。

## 6. 发布校验清单

- [ ] `agent/ai/aikernel-shell --version` = `0.1.0-alpha.11.0`
- [ ] `tools.json` 151 工具、8 域、20 desktop；`tools-sandbox.json` 7 工具
- [ ] `sme-seed.jsonl` 167 行
- [ ] `agent/ai/api/aikernel-api` 为 v3（tagged stderr event + `/clarify`）
- [ ] `audit_capabilities.py --check` PASS
- [ ] 无 `model.toml`、token、私钥、ISO、`.o`、测试 ELF 进入仓库
- [ ] 生产 VM 部署不重启；只重启 `aikernel-api`，检查 `/health` 与 `/clarify` 404 基线

## 7. 已知不可复现项

- `bzImage`/`vmlinux` 的字节级 md5 依赖构建路径、时间戳、工具链；源码树用 overlay SHA 校验。
- factory tar / ISO 含时间戳与构建机路径；发布记录中的 md5 仅用于该次产物。
- 真实 qwen2.5:1.5b 的工具能力评测依赖 VM 上的 Ollama 模型与 cloud key，不在本仓库。
