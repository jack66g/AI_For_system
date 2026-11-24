# DSK-01 · 组件与卸载契约

规格草案，供 DSK-06/07 落地。普通桌面是出厂文字控制台；桌面一是固定可视化客户端；桌面二是由 AI 生成描述文件的画布。DEC-08 冻结现有 Web 演示。DEC-09 先走文字原型再做纯 C 帧缓冲底座。DEC-10 要求桌面一、二均为可选安装件。引用基线为 `b436d06`。

## 请用户核对

1. 建议按用户选择“普通桌面 / 桌面一 / 桌面二”，出厂选择普通桌面。系统级启停由机主决定，单个图形客户端崩溃只让该席位回到普通桌面。
2. 建议桌面二依赖桌面一以保留编辑、授权和确认入口。卸载桌面一前由用户明确决定是否一并卸载桌面二。
3. 建议桌面卸载默认保留个人配置与画布原稿，清除选项仅处理明确列出的组件自有状态。
4. DEC-10 与冻结演示的安装记录存在张力。建议 DSK-07 新版出厂守卫覆盖冻结演示的已安装运行件，独立源代码保留作参考；已安装机器上的演示数据随其独立迁移项处理。

## 1. 归属与依赖

现役是整包。下表定义拆分后的所有权和引用证据。路径是已确认的现有位置，新增位置明确列于另表。目录前缀只表示允许分布范围，真正删除和覆盖看签名清单逐件记录；共享父目录可以拆给多个包。权限随属主与组件清单保全。

| 归属 | 基线文件与路径 | unit 或运行入口 | 状态与证据 |
|---|---|---|---|
| `aik-core` 必需 | 现有 `/usr/local/bin/occ`（当前合一程序）、`aikctl`、`aik-sandbox`、`aik-pqdump`，`/usr/local/sbin/{aistreamd,aipd,aikd,aikernel-api,autocondensed,aik-upgrade,aik-reset}`；`/etc/aikernel` 的 policy、模型层、streams 与 aipd 配置；内核 AI 面随内核槽走 | `aikernel-streams.service`、`aikernel-aipd.service`、`aikernel-memory.service`、`aikernel-api.service`、`autocondense.service`；备份、健康、升级提交、日志修整和盘检为核心维护单元 | `~/.occ/sessions.db`、快照、会话回放材料，系统审计、模型配置、SME 数据、W-7 事务历史。占位路径在 `agent/ai/occ/occ.c:26–33`、`agent/ai/occ/occ_tools/occ_tools.h:19,43`、`factory/etc/systemd/system/aikernel-memory.service:8`、`factory/usr/local/sbin/aik-upgrade:615–620`。已刷件与权限见 `build/w17n_factory_refresh.py:105–129,174–187`，服务入口见相应 unit 的 ExecStart（streams:11、aipd:12、API:13、autocondense:13），维护单元见 `factory/README.md:9–21,77–80` |
| `aik-console` 必需 | `/usr/local/bin/aik-console`、发行版 fbterm、`/root/.fbtermrc` 模板、`/usr/local/bin/aik-ime`、`/usr/local/lib/aik-ime/`、`/usr/share/rime-data/`、`/etc/ld.so.conf.d/aik-ime.conf`、字体及控制台静音配置 | getty/登录席位 → aik-console；tty1 等进 fbterm 链，`ttyS*` 直接进 occ | UI 视图字号、偏好、`/var/log/aik-console`、登录提示状态。登录凭据和认证审计单列为共享保护资产。证据 `factory/usr/local/bin/aik-console:85–106,244–255,313–331`、`factory/root/.fbtermrc:1–3`、`build/w17n_factory_refresh.py:174–208`、`build/w17n_build_iso.sh:104–118` |
| 冻结 Web 演示 | `/opt/aikdesktop` 下运行件与静态数据；`/etc/systemd/system/aik-desktop.service` | 旧 unit 以独立账户监听回环，`/api/windows` 为 Web 界面数据 | `/var/lib/aikdesktop`。已核旧安装器落运行件、unit、状态目录与启用链接（`build/w76b_install_desktop.py:159–187`），以及 `factory/etc/systemd/system/aik-desktop.service:1–29`、`agent/ai/desktop/desktopd.c:566`、`factory/README.md:64,77–79`。不归入新桌面，现役镜像中的完整成员需 DSK-07 从 tar 实测 |
| `aik-desktop` 可选 | 桌面一，目前无新组件安装件 | 新固定客户端，消费 occ 协议 | 界面布局呈现和窗口位置等私有状态；核心会话主权归 `aik-core` |
| `aik-canvas` 可选 | 桌面二，目前无新组件安装件 | 新画布渲染与用户侧订阅代理 | 用户模板、绑定、显式授权记录、画布设置与固定状态；核心审计归 `aik-core` |

拆分后 `aik-core` 无桌面反向依赖；`aik-console → aik-core`、`aik-desktop → aik-core + aik-console`、`aik-canvas → aik-desktop + aik-core`。版本约束写成区间和所需协议能力；不满足即拒装或提示升级。桌面渲染与核心保护目录之间以 [occ 服务协议](DSK-OCC-PROTOCOL-v0.md) 和 [画布协议](DSK-CANVAS-PROTOCOL-v0.md) 交互。核心出现故障时图形客户端应退出到文字前端并显示服务不可用；控制台仍能给出登录和本地恢复入口。普通桌面优先有可用的控制台维护路径，不能依赖图形功能更新。

### 新增位置与目录边界

| 组件 | 只读程序、资产与配置 | unit（拟定） | 私有状态范围 |
|---|---|---|---|
| `aik-core` | `/usr/local/libexec/aikernel/core/` 的 occd 与协议实现，现有公共 occ 入口保留兼容；`/etc/aikernel/core.d/` | `aik-occd@.service` 或可验证按 UID 启动器 | `/var/lib/aikernel/core/`、`/run/aikernel/occ/<uid>/`，保留基线会话、审计位置直到受控迁移 |
| `aik-console` | `/usr/local/libexec/aikernel/console/`，文字客户端/托管器；`/etc/aikernel/console.d/` | `aik-console@.service` 或现役登录席位入口 | `/var/lib/aikernel/console/` 和用户的 `$XDG_STATE_HOME/aikernel/console/`；席位运行态 `/run/aikernel/console/` |
| `aik-desktop` | `/usr/local/libexec/aikernel/desktop/`，`/usr/local/share/aikernel/desktop/`，`/etc/aikernel/desktop.d/` | `aik-visual-desktop@.service`，静态启动模板，由席位托管器调度；名称与旧演示区分 | `/var/lib/aikernel/desktop/`、`$XDG_STATE_HOME/aikernel/desktop/`、`/run/aikernel/desktop/` |
| `aik-canvas` | `/usr/local/libexec/aikernel/canvas/`，`/usr/local/share/aikernel/canvas/` 模板，`/etc/aikernel/canvas.d/` | `aik-canvas@.service`，由席位启动；用户画布工厂缺省停用 | `/var/lib/aikernel/canvas/`、`$XDG_STATE_HOME/aikernel/canvas/`、`/run/aikernel/canvas/` |

`XDG_STATE_HOME` 未设置时取认证用户 `~/.local/state`，已配置时在当前身份下检查受控目录与属主。系统级卸载不会扫描任意 HOME 或容器挂载。选择清除的用户状态需要明确列出 UID、目录归属、卷以及保存期限，再用该 UID 的受限清理入口执行；离线用户保留，等待其下次批准清理。系统状态与用户可扩展配置不要混在安装文件清单。会话与审计不受任何桌面事务影响，按核心的独立保留规则清理。

### 待定归属与迁移

- `occ` 当前合一二进制在拆出服务前由核心单独拥有；文本前端分离后单独入 `aik-console`。`~/.occ` 内未知文件逐项验明归属后才迁移，初期原目录整体按核心保护资产看待。
- `console-gate.last` 当前全局，按 CON-11 的席位修复迁成受保护的分席位提示状态。根账号门、认证审计交给核心或已认可的登录辅助进程，组件复位均保护这些文件。基线定义见 `factory/usr/local/bin/aik-console:93–96`。
- 底层 getty 配置、字体包及 fbterm 的包管理归属须对 ISO 和基础系统的正式清单完成对账，发现共享件则由基础层拥有，组件只能声明运行依赖。【未核】整包内逐件 dpkg 所属。
- 17.11.1 从 `b436d06` 打版后，洁净换装实测 `/opt/aikdesktop/desktopd` 可执行，`/var/lib/aikdesktop/` 与旧单元均在，`aik-desktop.service` 已启用且运行。现有卫生门只拦其中一份旧 service 副本（`build/w17n_build_iso.sh:138–156`）。归档内的完整成员及启用链接形态待 DSK-07 对照 tar。

## 2. 制品与安装

沿用 W-7 用户态渠道 `aik-upgrade install userland` 的逐件清单、校验和回滚。现格式为 tar.gz 内的 `manifest.tsv`（sha256、mode、owner:group、type、path）和 `files/`，详见 `factory/usr/local/sbin/aik-upgrade:606–620`。新增组件元数据 `component.json`，列出 `format,id,version,arch,required,depends,capabilities,manifest_sha256,units,owned_state,factory_templates`。组件类型严格枚举，元数据与件清单一起由发布信任链签名，声明所有权不得越出组件路径预置界线。内部命令不接受任意安装后钩子；保持安装包数据、程序与管理器的执行边界。离线用同一组包、依赖、签名和索引，在本机拥有预装信任材料时校验。安装后默认停用可选件，用户从控制台切换席位后开启。

先获取版本清单与可信制品，检查依赖、路径冲突、签名/清单绑定、包内容大小、成员类型、链接目标及逐件散列。无论在线离线都在接触目标路径前验完。核验安装目录每一级防越界，暂存目录属 root；对包格式的扩展需先更新安全解包验证并禁止链路重定向。开始事务后锁全局组件索引，备份旧文件和启用态，按 W-7 安装与复验，原子提交组件记录。首次安装的运行时状态由组件以正确 UID 初始化。有效打印收据展示组件、版本、件数、所需能力和事务 ID。安装中断恢复规则见 §3。DEC-03 制品库提供可按组件、架构、版本检索的签名摘要与发布来源；ENG-05 提供核心/控制台出厂锁定清单；ENG-07 提供逐件散列与可追溯构建配方。源树只留配方、文档、锁定清单和测试（`docs/TREE-CHARTER.md:20–47`）。

## 3. 卸载、回滚与复位

- **依赖检查。** 拒绝卸载任何必需件。被可选件依赖时显示反向依赖并拒绝单件卸载；明确选择级联的事务先卸 `aik-canvas`，后卸 `aik-desktop`。事务前确认文字席位入口和占用情况。
- **停席位。** 如当前模式受影响，先切回文字链，保证可重获操作通路。撤销桌面连接的驱动权和确认权，等待进程收口、停止 unit，撤下激活链接。保留普通控制台和核心；同一 UID 中其他会话继续按服务规则处理。
- **移除文件。** 依据已验证的安装记录逐件核查当前类型、属主与摘要；本地改过的配置明确列出，按“保留并隔离”缺省处理。禁止清除共享父目录中的他件。服务缓存和注册索引重新生成，提交前验证 unit 与可选包记录一致。
- **保留或清除状态。** 默认保留组件所有的系统与用户状态目录，撤去自动恢复标记。明确清除时先把列出的状态移动至事务暂存隔离，终态提交且保留期结束才物理删除，报出清除结果。只用已经核验的目录句柄操作。恢复或重新安装个人画布前，以旧 manifest 和当前权限重审。
- **中途失败。** 持久化事务 ID、计划、旧 manifest、旧 unit/模式、逐件变更和墓碑。修改文件前先刷盘备份；异常时从日志判断是回滚还是完成提交后的清理。回滚按相反顺序恢复文件、链接和状态，再按安全策略重启；恢复失败保持普通桌面、禁用有冲突组件并记录准确阶段，支持同 ID 重试。组件回滚选对应事务而非全机“最近一次”。
- **组件复位。** 停组件后备份它自己的状态，校验模板后原子写入并恢复权限，重建索引并审计。恢复默认普通桌面，或让单个画布回组件模板且保持停用。会话、审计、模型、系统账号、凭据、网络、SME、内核都走各自的核心管理口。核心保留现有独立数据面复位路径，不把普通桌面复位转成全局擦除。

给机主的查询接口设为 `aik-upgrade status components`（显示已安装/启用/残留/事务态）、`aik-upgrade uninstall component <id> [--purge-state]`、`aik-reset --component <id>`。这些是拟新增 CLI 形式。与现有脚本对接点：

| 入口 | 基线 | DSK-06 追加 |
|---|---|---|
| `aik-upgrade` | `factory/usr/local/sbin/aik-upgrade:879–937` 装前验证、备份、逐件应用、失败恢复；:939–952 从最近一个 W-7 备份回滚；:962–983 主分发 | 在展开安装包前验证可信制品摘要与根元数据种类，在安装预检与 manifest 解析时核对签名成员范围，装完前提交归属索引。沿同一事务机制加 uninstall 分支、依赖图、选择事务 ID 的回滚。保留既有散件格式用于老调用，阻止旧入口覆盖归属已登记的可选件 |
| `aik-reset` | `factory/usr/local/sbin/aik-reset:111–146,164–193` 解析整机选项后转交备份、轮换 API token、归档旧会话、按需清 SME | 增加 `--component` 并在整机确认与第一项副作用之前分流，组件范围内持久事务。组件分支与 `--keep-cloud/--wipe-sme` 混用为参数错误。保留原整机入口的契约 |

## 4. 恢复到普通桌面

`/etc/aikernel/console.d/default-mode.conf` 由核心/控制台接口写入，为系统默认模式 `console/desktop/canvas`，出厂是 `console`。每 UID 持久选择置入控制台自己的用户状态，经可信 UI 确认修改。席位监督器登录后按“本次临时选择 → 已安装且允许的个人选择 → 系统缺省 → console”解析。串口始终提供文字入口。卸载、版本不符、启动失败、心跳连续丢失、进程结束或 VT 接管失败时释放图形资源、停止相应 scope，再进既有文字客户端。连续失败记录本次席位回退锁，避免重启环；用户可以从文字链确认后重试启用。所有回退按实际认证 UID 建连接，保留当前会话与历史。

回退成功须同时满足：文字登录及两个语言档可用、VGA 和串口入口可访问、旧的会话和审计仍在、核心守护及协议监听正常、无可选包 unit 进程或启动链接、没有当前选中已卸载包的有效模式。静态显示能回到文字仅是第一个观测点。

## 5. DSK-06/07 验收

| 编号 | 操作 | 判据 |
|---|---|---|
| 06-1 | 全新安装桌面一，再装桌面二；另做离线安装 | 包摘要、签名、依赖和所有权可查；安装后未自动接管登录；个人启用后服务连接 UID 正确 |
| 06-2 | 伪造清单、改件、符号链越界、装包路径碰撞、架构错、依赖不符 | 每类在写目标前被拒；已装组件、系统状态和已知散列一致 |
| 06-3 | 从活动的画布席位启动卸载，分别覆盖保留状态、清除状态、依赖拒绝、显式级联、必需件拒绝四类边界 | 提示与实际归属一致，文字席位正常；默认保留用户原稿。清除只作用于明确 UID 的桌面状态，核心会话、模型与审计字节保全 |
| 06-4 | 分别在备份、更新文件、更新 unit、更新状态、提交阶段注入失败与重启 | 无未记录半装态，日志能判定恢复动作；幂等重试；恢复后的 unit、文件散列和有效默认模式一致 |
| 06-5 | 复位桌面一、单画布、整画布组件，覆盖用户无模板与模板损坏 | 作用域内恢复经过校验的模板，失败保留旧状态。整机 token、配置、会话及记忆散列未变 |
| 06-6 | 模拟退出、挂死、掉帧缓冲和失去核心 socket | 资源交还文字席位，用户能登入、中文输入和看历史。串口始终可恢复，回退不重启核心守护 |
| 06-7 | 双可选件卸载后跑既有 pty、协议差分、全量门禁 | 普通桌面与出厂默认一致；会话可读、审计连续，全部既有测试通过 |
| 07-1 | 对 ISO 内根文件系统 tar 的清单校验 | 必需件及已锁定内容命中；桌面一、二的 units、二进制、默认模式、pkg manifest、缓存路径和 enable 链接零命中；正反样本覆盖路径规范化 |
| 07-2 | 在出厂证据中验证冻结演示路径和 unit | 源码可保留，默认 ISO 无 Web 演示运行件、状态和启用链接。旧设备的演示私有数据按迁移计划保留 |
| 07-3 | 新 ISO 首启与第二次登录跑台架 | 普通文字链是实际默认；中文候选可用；席位没有可选件依赖。用明确构建 ID 和件摘要核验 |
| 07-4 | 把已签可选件装到洁净镜像，再卸掉 | 主仓验证可选组件清单保持真实；回到 07-3 的结果 |

DSK-07 在 `build/w17n_build_iso.sh:104–118,138–167` 同一 tar 断言阶段加入包所有权驱动的必需/禁入清单校验，检查实际归档成员和 unit 链接的相对规范路径。使用已存在的台架启动链验运行态，不靠静态字符串推定登录结果。

## 未决问题

- DSK-03 选定 per-UID 监督器实现，DSK-06 据此冻结 unit 的真实名字及失败回退入口。
- DSK-07 按实际发布物做旧 Web demo 归属与迁移盘点。17.11.1 的启用态已实测，完整归档内容待对账。
- ENG-05/07 提供基础包/共享件的精确归属与锁定清单后，替换本契约中暂列为基础层的文件前缀。
