# AIKernel 树宪章（TREE CHARTER）

> **地位**：本文件规定「什么可以进这棵树」。它不是教程，是准入法。
> **配套门禁**：`agent/ai/tools/check_tree.sh`——第 4 节的每个检查项与它一一对应，任一项 FAIL 即退出码非 0；
> 已挂进 `agent/ai/tests/run_all.sh`，门名 `tree-charter`。
> **口径**：出厂运行时全 C；开发 / 测试 / 构建工具链允许 Python。
> **初版**：2026-11-24（ENG-01 / ENG-02）。第 3、5 节的数字均为当日实测；改动树之后请连同实测数字一起更新。

## 0. 一句话

整个系统要像 Linux 内核一样自洽于一棵干净的单树：树里只有源码、构建配方、锁定清单、文档、测试和开发机工具的正式版。
凡是能由树里的东西重新生成的、或者只对某一台机器成立的，都不进树。

## 1. 准入规则

### 1.1 可以进树的只有这几类

| 类别 | 含义 | 现有正例 |
|---|---|---|
| 源码 | C / Python / Shell 源文件、内核 overlay、补丁 | `agent/ai/**/*.c`、`kernel-overlays/`、`patches/` |
| 构建配方 | Makefile、Kbuild、现役的构建与打版脚本 | `agent/ai/Makefile`、`build/w17n_*` |
| 锁定清单 | 记录「名字 / 版本 / 来源 / 哈希」，用来把树外的字节钉死 | `kernel-overlays/MANIFEST.sha256` |
| 文档 | 设计、口径、操作说明 | `SYSTEM-ARCHITECTURE.md`、`docs/` |
| 测试 | 测试源码、夹具、台架 | `agent/ai/**/tests/test_*.c`、`*.py` |
| 开发机工具的正式版 | 有维护主、输出确定、被文档或门禁引用 | `agent/ai/tools/gen_registry.py`、`audit_capabilities.py` |

### 1.2 不进树

1. **构建产物**：ELF、`.o`、`.a`、`.d`、`obj/`、`__pycache__/`。
2. **运行报告**：测试或生成器每次跑都会重写的文本产物。
3. **一次性调试脚本**：为某一次打版 / 验尸写的驱动脚本。
4. **任何凭据**：私钥、令牌、带 key 的配置。
5. **环境地址**：打版机绝对路径、实验网段、生产机 IP（正则见 `check_tree.sh` 的 `RE_HOME` / `RE_NET`）。
6. **未锁定的生成物**：由别的东西生成、却没有生成器或没有一致性门的文件。

二进制入库的唯一例外是「同源锚」：出厂在役、ISO 所装件必须等于库内件的 ELF。现役清单冻结在 `check_tree.sh` 的
`ELF_ALLOW`（14 项），只减不增；要新增必须先由主会话裁定并登记归属任务。

### 1.3 每个真值只在一处

对树里任何一个文件问三个问题：

1. 它是不是由树里别的东西生成的？是 → 生成器在哪、一致性门在哪。
2. 它是不是另一份的副本？是 → 哪一份是真值、靠什么机械地保持一致。
3. 都不是 → 它自己就是真值：它是唯一的吗。

「带生成器与门的生成物」允许被跟踪，但要同时满足三条：

- 生成器在树里，可重跑；
- 有机械的一致性门（`--check`、或安装侧的 md5 / sha 断言）比对生成物与源；
- 提交时生成物与生成器同步更新。

正例：`agent/ai/tools/tools.json` 族（生成器 `gen_registry.py`，门 `audit_capabilities.py --check`）。
其余一律是引用：符号链接（`agent/ai/tools.json -> tools/tools.json`）、文档引用、安装副本。

### 1.4 版本号只在 `VERSION` 一个文件里定义

**尚未建立**，登记 ENG-04。现状：版本串散落在 32 个被跟踪文件里（根文档、出厂 motd、各世代打版脚本……）。

### 1.5 出厂镜像里的每个字节都能在树里找到出处

出处分三类，缺一不可：

- 由树内源码加配方构建；
- 由锁定清单钉死的树外件（名字 / 版本 / 来源 / 哈希）；
- 基础镜像件（包名加版本的清单）。

现状不满足，见第 5 节 ENG-05、ENG-07。

## 2. 目标布局（提案；物理搬迁是 ENG-03）

| 目标目录 | 现路径 | 说明 |
|---|---|---|
| `kernel/` | `AIKernel/` + `kernel-overlays/` + `patches/` + 单一 `.config` | 内核态全部；现在 `.config` 与 `configs/` 三件并存 |
| `user/` | `agent/ai/*` | C 用户态；`user/sme/` 归拢 smehttp、engine、retrieval、space、store、memory、smeconfig |
| `scripts/` | `factory/usr/local/{bin,sbin}/*.sh` 等 | 系统脚本源码，不再放在镜像树路径下 |
| `factory/` | `factory/etc/` | 出厂配置源；不再放预编译件 |
| `packaging/` | `build/w17n_*`、`w6i-tools/` | 只留现役世代 |
| `third_party/` | `agent/ai/third_party/` + `agent/ai/third_party_ui/` | vendored 源码 + 第三方二进制锁定清单 |
| `tools/` | `agent/ai/tools/` 的生成器与审计器 | 开发机工具 |
| `tests/` | `agent/ai/tests/run_all.sh` | 聚合入口 |
| `docs/` | `docs/` + 根目录文档 + `agent/ai/docs/` + `AIKernel/*.md` | 文档 |

搬迁原则：一次只搬一个顶层目录；用 `git mv` 保留历史；搬迁提交不改内容；每搬一步 `check_tree.sh` 与 `run_all.sh` 全绿。

## 3. 当前真实布局的目录职责表（实测）

合计 1861 个被跟踪文件、约 130.6 MiB；其中 `factory/` 60.9 MiB（46.6%）、`agent/ai/third_party/` 17.1 MiB（13.1%）。

### 3.1 根文件与顶层目录

| 路径 | 文件数 | 职责 | 是否合规 |
|---|---:|---|---|
| `.gitignore` | 1 | 忽略规则，全仓唯一一份（嵌套件仅限上游 mbedtls 七件与 smehttp 一件） | 合规 |
| `.gitattributes` | 1 | 文本归一化（LF）与二进制标记 | 合规 |
| `.config` | 1 | 内核配置，与 `configs/` 并存 | 不合规：多源，ENG-04 |
| `README.md` `SYSTEM-ARCHITECTURE.md` `SECURITY.md` `BUILD.md` | 4 | 总览 / 全系统架构 / 安全说明 / 构建说明 | 合规（内含环境地址，记在债务基线，ENG-08） |
| `LICENSE` | 1 | GPL-2.0 | 合规 |
| `MANIFEST.sha256` | 1 | 顶层哈希清单：1448 条中 350 条失效（main@ccfc5f8 实测） | 不合规，ENG-10 |
| `SOURCE-MANIFEST.json` | 1 | 发版流水账（notes 型，无文件哈希面） | 不合规，ENG-10 |
| `AIKernel/` | 134 | 内核态 AI 框架源码：subsys 53、senses 18、core 17、test 18、actuators 9、boundary 8、reflex 4、scripts 2、tools 1、Kconfig / Kbuild / Makefile / 文档 5 | 合规；目标并入 `kernel/`，ENG-03 |
| `agent/` | 1141 | `Kconfig` + `Makefile` 2 件，`agent/ai/` 1139 件（见 3.2） | 合规；目标 `user/`，ENG-03 |
| `kernel-overlays/` | 174 | 对干净内核的完整侵入面（与内核树同相对路径）+ `MANIFEST.sha256` 172 条全绿 | 合规（锁定清单的正例） |
| `patches/` | 163 | 由 overlay 生成的补丁系列（12 个分组 + `SERIES.md`），生成器 `AIKernel/scripts/k10_patch_series.py` | 与 overlay 是同一真值的两种表达，缺再生成一致性门 |
| `factory/` | 97 | 出厂配置源：etc 40、usr/local 37、usr/share 18、root 1、README 1 | 部分不合规：预编译件与字典 ENG-07；脚本放镜像树路径 ENG-03；配置多份 ENG-04 |
| `desktop/` | 70 | Web 桌面 demo 包：static 60、data 4、unit、`run.sh`、`theme.json` 等 | 基本合规；`server.py` 已退出出厂面（现役为 desktopd），属陈旧源码 |
| `build/` | 55 | 打版脚本世代：refresh 12、build_iso 10、boot 8、install2 2；另 deploy 4、monitor 4、通用件 15 | 不合规，ENG-03 |
| `configs/` | 3 | 内核配置片段（`aikernel_factory.config` + k104 两件 frag） | 不合规：多源，ENG-04 |
| `w6i-tools/` | 11 | w6i 世代的 initramfs / ISO / 引导工具 | 不合规（旧世代），ENG-03 |
| `docs/` | 3 | 文档冻结说明、清理审计、本宪章 | 合规 |

### 3.2 `agent/ai/`（1139 件）

| 路径 | 文件数 | 职责 | 是否合规 |
|---|---:|---|---|
| `occ/` | 164 | 默认入口 occ：TUI、工具、子智能体运行时 | 含同源锚 ELF `occ/occ`（ENG-07 待迁） |
| `aistreamd/` | 55 | 事件流守护 aistreamd（parquet 落盘） | 含同源锚 ELF（ENG-07 待迁） |
| `aipd/` | 34 | AI 策略守护 aipd | 含同源锚 ELF（ENG-07 待迁） |
| `autocondense/` | 21 | 上下文压缩守护三件 | 合规 |
| `apic/` | 13 | aikernel-api 的 C 守护 | 合规 |
| `aikctl/` | 7 | 控制台 CLI aikctl（Python） | 树内合规；但它装进了出厂镜像，见 5.12 |
| `aikd/` | 4 | 遥测→Parquet 数据管道的 Python 参考实现（`aikd`、`aikd_lib.py`），已被 `aistreamd/` 的 C 版取代 | 陈旧源码（保留作参考）；**与出厂的 `/usr/local/sbin/aikd`（C 版 SME 守护，`smehttp/` 的第二链接名）同名不同物**，命名整理归 ENG-12 |
| `aikime/` | 11 | 输入法引擎 aik-ime 源码 | 合规 |
| `api/` | 1 | `aikernel-api` 的 Python 启动脚本 | 陈旧源码（现役是 `apic/`），待核 |
| `tools/` | 32 | 注册表生成器、能力审计器、执行器、本门禁 | 合规（生成物有门） |
| `tests/` | 105 | 单测源码、`run_all.sh`、台架 | 合规 |
| `third_party/` | 418 | vendored：mbedtls、sqlite3 等 | 合规；目标 `third_party/`，ENG-03 |
| `third_party_ui/` | 3 | linenoise | 同上 |
| `include/` | 87 | 公共头文件 | 合规 |
| `shell/` | 35 | aikernel-shell 命令 | 合规（aikernel-shell 已退出出厂面） |
| `store/` 15、`smehttp/` 12、`retrieval/` 12、`engine/` 7、`smeconfig/` 7、`space/` 7、`memory/` 5 | 65 | SME 七件 | 合规；目标归拢 `user/sme/`，ENG-03 |
| `runtime/` | 13 | JSON / 类型 / netlink 等运行时工具 | 合规 |
| `desktop/` | 14 | desktopd 与桌面工具 | 合规 |
| `docs/` | 10 | 设计文档 | 合规；目标 `docs/`，ENG-03 |
| `sandbox/` | 10 | aik-sandbox 源码与测试 | 合规 |
| `cloud/` | 5 | 云端 provider、TLS 网关、工具名映射 | 合规 |
| `local/` | 6 | 本地 provider（ollama） | 合规 |
| `tlsgw/` | 7 | TLS 网关测试 | 合规 |
| `policy/` 2、`core/` 2、`config/` 1、`i18n/` 1、`provider/` 1、`trace/` 1 | 8 | 策略、核心、配置、语言切换、provider、审计日志 | 合规 |
| `Makefile` `Kbuild` `Kconfig` | 3 | 构建配方 | 合规 |
| `build-rootfs.sh` `run-w48-tests.sh` | 2 | 脚本 | 合规；目标 `packaging/`，ENG-03 |
| `tools.json` `tools.openai.json` `tool_catalog.txt` | 3 | 指向 `tools/` 的符号链接（引用） | 合规（引用的正例） |
| `tools-sandbox.json` | 1 | 受限工具表副本，与 `tools/` 下同名件并存 | 不合规：多份，ENG-04 |
| `CHANGELOG-W48B.md` `README-dead-code-w48.md` | 2 | 文档 | 合规；目标 `docs/`，ENG-03 |

## 4. 提交前检查清单

机器门（`bash agent/ai/tools/check_tree.sh`，几秒跑完，`run_all.sh` 已挂为第一道门）：

| # | 门名 | 检查什么 | FAIL 了怎么修 |
|---|---|---|---|
| 1 | `tracked-artifacts` | 没有被跟踪的 `.d` / `.o` / `.pyc`，`obj/` 下没有被跟踪文件 | `git rm --cached` |
| 2 | `elf-whitelist` | 被跟踪的 ELF 只在 `ELF_ALLOW` 内（索引与工作区两个视图都查）；白名单无失效项 | 出库；确需入库先裁定再加白名单 |
| 3 | `debt-baseline` | 环境地址不新增：出现新文件、或某文件命中数上升即 FAIL；下降则提示收紧基线 | 清零归 ENG-08；基线只降不升 |
| 4 | `secrets` | 五类密钥模式零命中；豁免精确到文件，能钉字面量的钉死哈希 | 立即出库并轮换 |
| 5 | `run-reports` | 运行报告不得被跟踪 | `git rm --cached`，并在 `.gitignore` 第六节登记 |
| 6 | `junk-names` | 被跟踪文件名里无 `.log` `.tmp` `.orig` `.rej` `.swp`、不以 `~` 结尾 | 删除 |
| 7 | `ignore-selftest` | 忽略规则语义哨兵全过（57 条应忽略 / 27 条不得忽略）；嵌套 `.gitignore` 只许白名单内的 | 改仓根 `.gitignore`，按类别写 |
| 8 | `untracked-products` | `git status` 可见的未跟踪文件里没有构建产物 | 是产物就补类别规则，不是就删 |
| 9 | `no-tracked-ignored` | 没有被跟踪文件被 `.gitignore` 命中（本仓零特例） | 调规则顺序，或出库 |

人要做的事：

1. `git add` 写明清单，不用 `git add -A` / `git add .`。
2. 提交消息用 `git commit -F <消息文件>`。
3. 动了生成物的源，就连生成物一起重新生成并提交，跑一遍它的一致性门。
4. 新的构建产物落在了既有的类别规则之外：补**类别**规则，并在 `check_tree.sh` 的哨兵里加一条，不写「某个具体文件」的规则。
5. 新的测试 / 探针可执行文件：源码带扩展名，产物不带扩展名——规则自动生效，不必改 `.gitignore`。

## 5. 已知违规清单（实测，各挂任务编号）

| # | 违规 | 实测证据 | 归属 |
|---|---|---|---|
| 5.1 | 出厂 rootfs 权威树在仓外 | `build/w17n_build_iso.sh:28` 直接对仓外目录打包；镜像 `etc/` + `usr/local/` 可读文件 276 个，仓内 `factory/` 只跟踪 97 个；项目件 `etc/ai/*.bin`、`ISO-SNAPSHOT-*`、`sysctl.d/99-aikernel.conf`、`modules-load.d/aik-softdog.conf` 在树里没有出处 | ENG-05 |
| 5.2 | factory 预编译第三方件与字典入库 | 11 个 ELF 共 40.0 MiB（`usr/local/bin/aik-ime`、`busybox`、`usr/local/lib/aik-ime/` 9 个 `.so`）；`usr/share/rime-data` 18 件约 20 MiB | ENG-07 |
| 5.3 | build/ 世代脚本 | refresh 12、build_iso 10、boot 8、install2 2；现役只有 w17n 三件 | ENG-03 |
| 5.4 | 两份同名 `aistreamd.conf` 取值相反 | `agent/ai/aistreamd/aistreamd.conf` 对 `factory/etc/aikernel/aistreamd.conf`：`HOTPLUG_ENABLED` 0 对 1、`PARQUET_ENABLED` 0 对 1；共有键 34 个，另有 16 键只在源码侧、2 键只在出厂侧 | ENG-04 |
| 5.5 | `tools.json` 族多份且互不一致 | 五个产物族各有 2–3 份实体、内容互不一致：`tools.json`、`tools.openai.json`、`tools-sandbox.json`、`tool_catalog.txt`、`sme-seed*.jsonl`。出厂镜像实装的 `/etc/aikernel/tools.json` 与仓内任何一份都不同 | ENG-04 |
| 5.6 | 语言表生成器不在仓内 | `agent/ai/occ/occ_tui/tui_lang_tab.h` 头注声明由 `gen_lang_tab.py` / `mk_tab_delta.py` / `mk_tab_p2a.py` 生成，三者均未被跟踪 | ENG-04 |
| 5.7 | 打版机家目录散脚本 | 家目录顶层 `*.sh` / `*.py` 共 103 个 | ENG-13 |
| 5.8 | 顶层 `MANIFEST.sha256` 失效 | 以 main@ccfc5f8 计：1448 条中 350 条 FAILED（83 条文件不存在、267 条哈希不符）；91 条指向已不再跟踪的路径；544 个被跟踪文件不在清单内。对照：`kernel-overlays/MANIFEST.sha256` 172 条全绿 | ENG-10 |
| 5.9 | 打版链依赖未入库的构建产物 | `build/w17n_factory_refresh.py:91-92` 与 `build/w17n_build_iso.sh:79-81` 取用 `agent/ai/aistreamd/aik-pqdump`，该件未跟踪；`aik-sandbox` 同类且更糟——make 目标把产物输出到 `agent/ai/aik-sandbox`（`agent/ai/Makefile:337-341`），打版链却取 `agent/ai/sandbox/aik-sandbox`（refresh:161-162、build_iso:127-129），两处文件大小不同（1,111,040 对 1,111,080）。**11-25 ENG-14 定谳：这是「旧构建 vs 新构建」而非两条配方**——当前源码重编 = 1,111,080B / md5 6ad156b1，与出厂件、旧锚三者同一件；1,111,040B 是 O-8 修复前的陈旧构建。刷新脚本与打 ISO 已改取 Makefile 产物 `agent/ai/aik-sandbox`，旧 `sandbox/` 锚退役 | ENG-07、ENG-14 |
| 5.10 | 版本号多处定义、`VERSION` 不存在 | 见 1.4 | ENG-04 |

本棒新发现、待主会话编号：

- **5.11** `agent/ai/tests/tls_test_certs.h` 是入库的私钥夹具（自签名测试证书链，可由 `tests/tls_certs_regen.sh` 再生）。门禁按文件豁免；建议改为测试期生成。
- **5.12** 出厂镜像的 `/usr/local/bin/aikctl` 是 Python 脚本，依赖镜像内的 `/usr/bin/python3.10`——该二进制不属于任何 dpkg 包（孤儿件）。与「出厂运行时全 C」口径不符。
- **5.13** `agent/ai/smehttp/.gitignore`（仅 `/aikd` 一条）待并回仓根；并入后从 `check_tree.sh` 的 `NESTED_GITIGNORE_OK` 删除。

### 5.14 止血记录（ENG-01 本棒）

- **出库 40 件**：`.d` 25、`aipd/tests/` 测试 ELF 11、`sandbox/aik-sandbox` 1、运行报告 3（`tools/tools_report.txt`、`tools_report.txt`、`occ/tests/orch_b2_report.txt`）。
- **删除 3 件**一次性调试脚本：`build/w17nd.py`、`w17ne.py`、`w17ng.py`。
- **保留未动**：`tools/tool_catalog.txt`（部署脚本与 preflight 以 md5 当冻结基线比对，属「带门的生成物」）；三件同源锚 ELF；factory 的 11 件预编译件。
- **合并后的遗留动作**：主仓检出本提交时会删掉工作区里的 `agent/ai/sandbox/aik-sandbox` 与 `aipd/tests/test_*`。现役 make 目标（`agent/ai/Makefile:337-341`）把 aik-sandbox 输出到 `agent/ai/aik-sandbox`，而旧打版链曾取 `agent/ai/sandbox/aik-sandbox`。**11-25 ENG-14 已修**：刷新脚本与 build_iso 改取 Makefile 产物 `agent/ai/aik-sandbox`，旧 `sandbox/` 锚退役；打版前只需 `make -C agent/ai aik-sandbox` 重建。

## 6. 基线与豁免的维护

| 文件 / 常量 | 作用 | 怎么改 |
|---|---|---|
| `agent/ai/tools/check_tree_debt_baseline.txt` | 环境地址债务基线：路径、命中数合计、两类各多少处 | 只用 `bash agent/ai/tools/check_tree.sh --update-debt-baseline` 收紧；它只降不升，新债务写不进去 |
| `ELF_ALLOW` | 现役入库 ELF 白名单（14 项） | 只减不增；迁出制品库后同步删除 |
| `SECRET_ALLOW` | 密钥扫描豁免（3 条，精确到文件） | 新增必须写明理由；能钉字面量哈希的必须钉 |
| `NESTED_GITIGNORE_OK` | 允许存在的嵌套 `.gitignore`（8 件） | 只减不增 |
| `MUST_IGNORE` / `MUST_TRACK` | 忽略规则哨兵（57 / 27 条） | 新增一类产物时两边各加哨兵 |
| `RUN_REPORTS` | 不得被跟踪的运行报告（3 件） | 判定为运行报告的才加；冻结基线不加 |
