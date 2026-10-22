# 清理与死代码审计（alpha.11.0 源码基线）

日期：2026-10-23
范围：L1 正典树 `/home/jack66g/linux-6.18.39`、`agent/ai`、导出树
原则：**先证明再删除**。本轮只清理仓库中的构建产物/二进制/证据，不删除任何无法证明未被构建或测试引用的源码。

## 1. 已确认清掉的死代码（W48 及更早）

| 对象 | 证据 | 状态 |
|---|---|---|
| `agent/ai/cmd_session.c`、`agent/ai/ui_common.c`（根副本） | 从未参与编译；正典在 `shell/commands/cmd_session.c`、`shell/ui_common.c`；全树无 include | 已删除（W48） |
| `agent/ai/cloud/tls/tls_manager.{c,h}` | 0 调用方；仍在 Makefile 链接但不可达 | 已删除 |
| `agent/ai/config/certs/cert_manager.{c,h}` | 0 调用方；TLS 校验后来在 `http_client.c` 内实现 | 已删除 |
| `cmd_onboarding.c` 的 `w4a_layout_probe[8192]` | 零引用；`nm` 证明二进制中不存在，-O2 丢弃 | 已删除 |
| `net/sched/sch_fq.c` 的 `EXPORT_SYMBOL(fq_qdisc_ops)` | 0 调用方；W48 恢复 `static` | 已删除导出 |
| `sch_codel.c` / `sch_fq_codel.c` 的 ops 导出 | 无外部调用；W48 同批复核改为 `static` | 已清理 |

## 2. 本轮仓库清理（只清产物，不动源码）

从源码基线中排除：

- 所有 ELF：`aikernel-shell`、`aik-sandbox`、`tests/test_*`、`tests/w10b_tls_probe*`、`demo_sandbox_chain`、`sandbox/tests/aik-sandbox`
- 所有 `.o`、`.a`、`.cmd`、`.order`、`.mod*`、`Module.symvers`、`built-in.a`
- `build/`、`__pycache__/`、`*.pyc`
- ISO、factory tar、rootfs、VM 备份、trace、证据日志、`longterm/`
- `model.toml`、api-token、私钥、host key、任何 `.aikernel/` 运行时状态

导出树检查：**1033 个文件、47 MiB、0 个 ELF**（文档写入前）。测试源码、测试夹具、KUnit、qemu 脚本、`third_party/mbedtls` 源码全部保留。

## 3. 当前“疑似未引用”C 文件（只报告，不删除）

用 Makefile/测试脚本的 basename 扫描，`agent/ai` 有 104 个 `.c`，其中 6 个没有直接出现在文本 Makefile 中：

| 文件 | 实际构建方式 | 结论 |
|---|---|---|
| `core/ai_core.c` | `core/Makefile` 通过 `obj-$(CONFIG_AIKERNEL_CORE) += ai_core.o` 构建 | 活 |
| `sandbox/tests/qemu/w64-init.c` | qemu drill 脚本直接 `gcc` | 活（测试） |
| `tests/test_registry_shadow.c` | `run-w48-tests.sh` 显式编译 | 活（测试） |
| `tests/test_risk_grading.c` | `run-w48-tests.sh` 显式编译 | 活（测试） |
| `tests/test_truncate.c` | `tests/Makefile` 的规则变量/模式规则构建 | 活（测试） |
| `tests/w10b_tls_probe.c` | 测试脚本显式编译（含 ASAN 变体） | 活（测试） |

因此**本轮不建议删除任何源码**。需要清理时，按 W48 的方法：调用方计数 + `nm` 符号实证 + 干净构建 + 全量测试，四者齐全再删。

## 4. 内核 overlay 清单修正

旧仓库 `kernel-overlays/` 只有 10 个文件，已确认**不完整**：alpha.11.0 的内核有约 80 个上游目标文件引用 AI 符号，覆盖 block/mm/sched/crypto/security/fs/drivers/arch 等。当前清单：

- **168 个文件**：11 arch、8 block、12 drivers、20 fs、6 include、2 init、45 kernel、1 lib、27 mm、23 net、5 samples、4 security、1 virt，加顶层 `Makefile`/`Kconfig`/`Kbuild`
- 逐文件 SHA-256：`kernel-overlays/MANIFEST.sha256`
- 应用工具：`build/apply-overlays.sh`（复制后逐文件校验）

没有这 168 个文件，干净 6.18.39 构建出的内核会缺少 AI 遥测/决策钩子，不能代表 alpha.11.0。

## 5. 基线验证

- 从 9/30 源码快照回灌被覆盖的 29 个项目文件；其中 19 个对应目标文件重建后与 10/20 发布构建**逐字节一致**
- 全量内核链接成功，`bzImage #59`；新旧 `System.map` 符号名集合一致；差异仅为版本横幅时间串导致的 `.rodata` 地址后移
- 顶层 `Makefile`/`Kconfig`/`Kbuild` 接入行已恢复
- `agent/ai`、`AIKernel/`、factory、desktop、构建脚本均从正典树导出，未改生产 VM
- 干净导出构建：`aikernel-shell --version` = `0.1.0-alpha.11.0`，`aik-sandbox` md5 与发布件一致；`tests/Makefile` 35 个测试目标全部编译
- 测试：C 单元 **33/33**（clarify 121、lease 89、lease_gate 98、w77 53/31/18、desktop 56、trace 75 等）、API mock **33/33**、clarify gate **23/23**、E2E **21/21**、审计 PASS
- 旧 `run-w48-tests.sh` 的 `CORE` 列表未包含后来的 `local/` 依赖，对 `test_ask_autocompact`/`test_compact_loop` 报 BUILD-FAIL；这是 runner 过时，不是产品代码。当前 runner 为 `agent/ai/tests/run_all.sh`；`test_sysctl_tools` 需要 root。

## 6. 建议

1. 以后每波结束跑一次 `build/apply-overlays.sh` + `audit_capabilities.py --check`，防止 overlay 清单再次漂移。
2. 死代码清理单独成波，不与功能波混合；每次删除都留 `orig/` 与 `nm` 证据。
3. `agent/ai/third_party/mbedtls` 保留 library/include 与许可证（9.6 MiB）；上游生成的 `tests/seedfile`（64B）不入库，避免把生成数据当源码。
4. 不要把 L1 的构建产物或 `longterm/` 证据复制进源码仓库；发布件（ISO/factory tar）只放发布存储。

## 7. W77f 工厂树残渣清理（2026-10-23）

- 移除出厂 root/ 的 W2-W7 开发残渣：rafile(209MB)、ssh_hog/ssh_dd/ai_act_flip 测试二进制、
  t3-* 证据、01_oom~07_reclaim 演示脚本、w4a-* 时代脚本、root/ 下陈旧 tools.json 副本、
  乱名垃圾文件（"复位/写盘/），"等）、persistence-proof、aikctl 重复副本、aik2 旧二进制。
- 安全修复：出厂树不再携带 root/.ssh/authorized_keys（此前随 ISO 分发同一把 key）；
  qsmoke contentcheck 新增 root_authkeys=0 断言。
- 工厂树 1.6G → 692M；ISO 1.94G → 706MB（模型 941M + 残渣 212M 移除）。
- run_all.sh 收敛到 agent/ai/tests/（删除仓库根 tests/ 重复副本）。
