# 记忆层上游基线（MEM-06）

> **本文件是记忆层「跟上游」的唯一权威记录**：C 版各模块钉在上游哪个提交、
> 已移植什么、还有什么没移植、对照向量钉在哪、移植前先读什么。
> **每次同步后更新本文件。**
>
> 上游 = `jack66g/spatial-memory-engine`，是**参考实现**；本仓是它的 C 版。
> 移植方式一律「读上游代码与文档 → 用 C 重写」，出厂运行时不引入 Python
> （硬约束 H1 / DEC-05）。上游是参考，不是依赖。

## 1. 上游提交链

| 提交 | 日期 | 内容 | 与本仓的关系 |
|---|---|---|---|
| `5a6604d`（+未提交改动） | 2026-09-28 | 出厂树 `/opt/sme` 的来源：配置中心 97 项 / 5 预设 | 配置层注册表与默认值的原始 pin |
| `1f635e7` | 2026-10-10 | namespaces 全链路对齐；两项帮助文案 | 出厂树保留的是这一版的文案 |
| `98071d9` | 2026-11-01 | 配置层新增 4 个键；scoped memory 加固 | 4 键 → MEM-01c 已补 |
| `e72bc75` | 2026-11-01 | 全量对拍（T4）时钉的基线 | 多数模块仍钉在这里 |
| `ed5378a` | 2026-11-20 | 大型测试战役、28 项修复、跨进程写锁、预设扩充。`sme/` 下 14 个文件 +680/−221 | 已移植小项见 §3，逐项审计见 §4 |
| `cba0f29` | 2026-11-21 | 测试归档与实验边界说明。`sme/` 与 `ed5378a` **零差异**（改动全在 `experiment/`） | 无需移植 |

## 2. C 版各模块当前基线（2026-11-24）

| 模块 | 钉在 | 本仓相对上游的有意偏离 | 对照向量 |
|---|---|---|---|
| `retrieval/text.c` 分词 | `ed5378a`（MEM-01a） | 混合书写系统的 run 切法不同；纯 CJK / 纯拉丁 / 空输入与 `e72bc75` 逐 token 相同 | `text/` 已重录到 `ed5378a` |
| `retrieval` 其余（BM25 / 排序 / PPR / 嵌入） | `e72bc75` | — | 未动 |
| `space/space.c` | `ed5378a`（MEM-01b） | 演化候选结转、merge 后剪边；既有 38 步重放结果不变 | 未动 |
| `smeconfig`（白名单 / 默认值 / 注册表） | `e72bc75` + 出厂树 | 4 个键已补（MEM-01c）；namespaces 两项帮助文案保留出厂树旧措辞；预设仍是 5 个 | `config/` 三个文件已重录（恰多 4 键） |
| `engine` | `e72bc75` + MEM-02a / 02b / 10 | 热重建后立即存盘；反序列化入口数值校验；新增与更新文本、数值校验 | 未动 |
| `smehttp` | 同 `engine` | `/import`、`/import/file` 先整批校验；单条新增、批量新增、PATCH 的非法写入字段返回 422 | 未动 |
| `storage` / `wal` / `sqlite` / `embed` / `api` / `ac` / `mcp` | `e72bc75`（T4） | — | 未动 |

## 3. 已移植

MEM-10 提交号为施工工树来源，主仓合入以审核记录为准。

| 项 | 上游依据 | 主仓提交 | 回归测试 |
|---|---|---|---|
| MEM-01a 混合词分词 | `sme/utils.py::tokenize` | `9d3a8e4` | `retrieval/tests/test_text.c` 自包含段 |
| MEM-01b 演化候选结转 + merge 剪边 | `sme/space/region_manager.py` | `154a274` | `space/tests/test_space.c` 自包含段 |
| MEM-01c 配置层补 4 键 | `sme/config.py`、`sme/config_items.py` | `71f85b0` | `smeconfig/tests/test_config*.c`、`engine/tests/test_engine.c` 段 4 |
| MEM-02a 热重建后立即存盘 | `sme/api/server.py::rebuild_engine_with` | `5358978` | `engine/tests/test_rebuild.c`、`smehttp/tests/test_http.c` 17–18 |
| MEM-02b 导入数值校验 | `sme/models.py::_validate_memory_numbers` | `12ac54b` + `f7ffa5a` | `engine/tests/test_engine.c` 段 5、`smehttp/tests/test_http.c` 19、`retrieval/tests/test_ranker.c` 段 5 |
| MEM-10 更新拒绝空白文本 | `sme/memory_manager.py::update_memory` | `278e29a` | `engine/tests/test_engine.c` 段 3a |
| MEM-10 写入拒绝非法 UTF-8 | `sme/memory_manager.py::_check_encodable_text` | `ef928ed` | `engine/tests/test_engine.c` 段 3a、`smehttp/tests/test_http.c` 写入用例 |
| MEM-10 写入数值校验 | `sme/memory_manager.py::_clamp01`、`sme/api/server.py` 的写入请求模型 | `03ba23d` | `engine/tests/test_engine.c` 段 3a、`smehttp/tests/test_http.c` 单条、批量、PATCH |

## 4. 上游差异逐项审计（MEM-10）

按 `git diff e72bc75 ed5378a -- sme/` 的 14 个变更文件核对。行号以
`ed5378a` 为准，注明旧版的除外。a 为已移植或已有同等行为，b 为应移植，
c 为不吸收，d 为待定。§3 的三项 MEM-10 修复实施后归 a。

| 上游依据 | 行为变更 | 归类与 C 版处置 |
|---|---|---|
| `api/server.py:91–104` `AddMemoryRequest` | 单条和批量新增的 importance 必须有限且在 [0,1] | a · `03ba23d`，`smehttp/routes.c::validate_add` 一并覆盖单条和批量 |
| `api/server.py:117–125` `UpdateMemoryRequest` | PATCH 的 importance 同界，weight 必须有限且非负，null 保留原值 | a · `03ba23d`，`smehttp/routes.c::validate_update` |
| `api/server.py:92–94,118,455–477` `create_app` | Python 校验详情中的 NaN、无限值转可序列化形式，保证 422 能送达 | c · Python 全局异常包装不移植。C 的 JSON parser 先拒裸字面量，写入数值错误复用 MEM-02b 的 `field_input`，指数溢出的输入值以字符串回填 |
| `api/server.py:254–259,325–334` `_embedding_identity` | 非空库的热重建身份闸门纳入 mrl_dim | a · C 在 `8ec4de4` 的热重建已纳入，`engine/tests/test_rebuild.c` 有 mrl_dim 拒绝且旧库保留回归 |
| `api/server.py:349–359` `rebuild_engine_with` | 关闭 WAL 的热重建迁移后立即存盘，失败不发布新引擎 | a · MEM-02a `5358978` |
| `api/server.py:738–739` `create_app` 的 PATCH 路由 | SDK 缺失 ID 改抛 ValueError 后，HTTP 同时接住两种异常并返回 404 | a · C 的 `aik_engine_update` 返回 1 表示未找到，由路由映射 404。现役回归保存既有错误体文案 |
| `config.py:330–356,423–428` `_validate_field/from_dict` | 配置反序列化复用注册表校验，豁免 null 与内部维护间隔 | d · MEM-02d。C 配置中心的 PUT 已逐项校验，文件加载仍有独立的兼容契约。方案一只在新配置入口按注册表拒绝，保住旧快照。方案二让文件和快照一起校验，需要验证在役配置及重录配置、快照对照 |
| `config_items.py:72` `ITEMS` | LLM 模型的注册表默认值由空字符串改为 `gpt-4o-mini`。Python dataclass 在 `e72bc75` 已是此值 | d · MEM-02d。保留 C 出厂空模型，或只对显式启用的模型配置采用上游默认，后者要一起验证离线启停与配置对照 |
| `config_items.py:81` `ITEMS` | 温度的注册表默认值由 0.6 改为 0.3。Python dataclass 在 `e72bc75` 已是 0.3 | d · MEM-02d。保留当前配置，或单独统一温度默认值并重录配置对照 |
| `config_items.py:517–528`（旧版 517、528 各一份 `_is_blank`） | 删除重复的等价 Python 绑定 | c · C 配置层无该重复定义，配置语义不变 |
| `config_items.py:690–714` `kb_dynamic` | 八项排序权重全部显式设置，合计 1.0，预设 20 → 25 个键 | b · MEM-02c，配置和排序分数对照一起换 |
| `config_items.py:725–749` `kb_static` | 静态知识库预设应用同一权重归一，20 → 25 个键 | b · MEM-02c，同上，单独验预设 |
| `config_items.py:804–843` `united_static` | 预设 06 停用动力学，采用 BM25 主导候选及纯语义排序权重。共 29 键 | b · MEM-02c，需要更新预设与检索对照 |
| `config_items.py:844–880` `semantic_first` | 预设 07 为真 embedding 的 minmax 融合口径调参。共 26 键 | c · 现役 C 只有 hashing，维持既定决定 |
| `engine.py:143–145,867–894` `save` | 保存按路径跨进程加锁，恢复库检查上次同步的谱系后才发布并推进谱系 | c · C 出厂架构采用单进程单写者，沿承 §7.3 |
| `engine.py:897–899` `_recovery_path` | 绝对路径、平台大小写规则与 .json/.json.gz 归一化用于写者谱系匹配 | c · 新函数服务上行谱系。C 保留现役快照/WAL 路径语义 |
| `engine.py:944–956` `load/_load_locked` | 读操作获得与保存互斥的跨进程锁，并记录恢复库的写者谱系 | c · 同一单写者边界。存储层文件锁格式不随 C 版引入 |
| `engine.py:956–1144` `_load_locked` | 将旧 load 的后端探测、配置重绑、向量空间、几何恢复、归档、WAL replay 和维护流程移入锁内函数 | c · 这些步骤在该 diff 中为搬移，平行重建几何也在旧版。C 的加载热区另见 MEM-09 |
| `engine.py:1047` `_load_locked`（旧版 1000） | 恢复后把 query_prefix 赋给 embedding 实例的原有语句随缩进搬移 | c · 上游无新行为，C 的配置键已补，hashing 保持忽略前缀。真模型供应方接入时另验（MEM-05） |
| `engine.py:675–680` `search` | top_k 拒绝 bool、字符串和非整数浮点，整数值浮点归一为 int | a · C SDK 参数就是 int，HTTP 的 `json_as_int` 在现役基线已接受整数值浮点并拒绝另外三类，未改入口 |
| `mcp_server.py:41–45` | 配置的 SME_MCP_PORT 不是整数时改用清晰的启动错误 | c · C MCP 客户端/服务另有传输契约，按 §7.3 不跟 Python MCP 入口 |
| `memory_manager.py:39–48,102` `_check_encodable_text/add_memory` | 写入前拒绝不可转成 UTF-8 的孤立代理码位 | a · `ef928ed`，C 新增、批量新增、更新共用严格 UTF-8 检查，非法文本不会被回显到 HTTP 错误 |
| `memory_manager.py:78–83,111` `_clamp01/add_memory` | SDK 新增先拒绝非有限 importance，再把有限值夹取至 [0,1] | a · `03ba23d`，保留 C SDK 有限越界值夹取语义 |
| `memory_manager.py:129` `add_many` | SDK 批量新增也先拒绝非有限值，再夹取 importance | a · C 批量 HTTP 共用单条校验与写入函数，整批先验证。C 无独立 Python 式 add_many SDK |
| `memory_manager.py:160–165` `update_memory` | SDK 不允许用空白或不可编码文本覆盖旧内容 | a · `278e29a`、`ef928ed`，旧内容与版本保持 |
| `memory_manager.py:188–193` `update_memory` | 更新 importance、weight 拒绝非有限值，有限值原夹取不变 | a · `03ba23d`，分配阶段校验，提交前不改字段或版本 |
| `memory_manager.py:291–293` `require` | SDK 缺失 ID 由 KeyError 改成 ValueError | c · C 用稳定的返回码区分缺失和内部失败，HTTP 仍返回 404。错误正文与旧向量保持一致 |
| `models.py:22–41,143` `_validate_memory_numbers` | 反序列化拒绝负 hit_count、负或非有限 weight、非法 importance 及非有限热度字段和时间戳 | a · MEM-02b `12ac54b`、`f7ffa5a`。C 导入整批校验，快照与 WAL 同走反序列化口 |
| `models.py:29–30,128` `_validate_memory_numbers` | hit_count 须是原生整数，bool、分数及字符串类型也拒绝 | d · MEM-02b 的 C 兼容分支目前允许有限的小数截断，非数值按默认。方案一只收严新导入，须验证旧导出与 MEM-08。方案二连快照/WAL 一起收严，需要对照向量、旧库兼容和失败恢复测试 |
| `modules/extraction.py:33–37` `QUESTION_WORDS` | 删去已有的「为啥」「为什么」重复项，识别条件不变 | c · 出厂 C 的抽取扩展不在实施范围 |
| `modules/profile.py:65–68` `UserProfile` | 画像标签去重后排序，使快照与导出稳定 | c · 画像扩展在出厂 C 未启用。接入画像时按存储/导出对照验证 |
| `retrieval/rerank.py:62–73` `Reranker` | CrossEncoder 重排同时更新 hit.score 和 breakdown.final 为四位小数，尾部不改 | c · C 出厂没有这条 CrossEncoder 路径。将来启用会改变检索分数对照 |
| `space/region_manager.py:276–278` `RegionManager` 合并分支 | 删被吸收区域时剪掉指向它的区域边 | a · MEM-01b `154a274` |
| `space/region_manager.py:333–357` 演化拆分 | 拆分单轮到上限时让未遍历的候选滚入下轮 | a · MEM-01b `154a274` |
| `space/region_manager.py:361–395` 演化吸收 | 吸收小区域到上限时也保留未遍历候选 | a · MEM-01b `154a274` |
| `storage/snapshot.py:216–251` `_cleanup_embeddings` | 清理孤儿代时参考被引用 sidecar 的 mtime，保留可能在途的更新代 | c · 针对多写者竞争，C 当前仅一个写者并已保留普通和 gzip 清单共同引用。若开放多写者，须整体验证并发发布与回收 |
| `storage/xlock.py:1–145` | 新增跨进程加锁与谱系协议 | c · 既定单进程单写者，§7.3 |
| `utils.py:120,129–154` `tokenize` | 拉丁段保留整词，CJK 段切单字及可选二元 | a · MEM-01a `9d3a8e4`，`text/` 对照已重录 |

相关任务的证据：

- MEM-02c 的 namespaces 两项帮助文案来自更早的 `98071d9`，本段 diff 中无
  改动。与两套知识库预设及 06 一起改配置对照。
- MEM-04 的鉴权入口在 `api/server.py` 的本段 diff 中无变更。
- MEM-08/09 的线索：上游 load 的几何恢复并行化在 `e72bc75` 已有，改名搬移
  无法解释 C 版超线性。C 的 `aik_engine_load` 仍逐条调 `npz_row`，后者逐 ID
  比较至首次命中，也保留了线性查找的静态证据。该审计未做负载归因。导入
  失败的精确原因仍归 MEM-08。

## 5. 对照向量

- 位置：共享树 `$AIK_PARITY_VECTORS`，缺省 `$HOME/aikernel-longterm/parity/vectors`
  （打版机上、仓外）。记忆层门禁读它——**换基线必须连它一起换**，否则旧代码
  或新代码必有一边对不上。
- 旧基线备份：共享树旁 `vectors-baseline-e72bc75-20261124/`（被替换的 4 个文件
  与原 `SHA256SUMS`）。

| 向量 | 钉在 | 录制器 | 上次重录 |
|---|---|---|---|
| `text/text.vectors.json` | `ed5378a` | `parity/rec/record_text.py` | 2026-11-24（sha256 `984978e9…`） |
| `config/groups_default.json`、`groups_mutated.json`、`config_file.expected.txt` | `e72bc75` + 4 键；namespaces 文案 = 出厂树 | `parity/rec/record_config.py`（参考树须参数化） | 2026-11-24 |
| `config/presets.json` | 5 预设 | 同上 | 未动 |
| 其余目录 | `e72bc75` / T4 | 各自录制器 | 未动 |

独立复核（2026-11-24，主会话，不由施工智能体自证）：

- 同一录制器对 `e72bc75` 重录，与旧共享件逐字节相同（sha256 `03e791a3…`）
  ——录制器与主机环境没漂；对 `ed5378a` 重录，与新件逐字节相同。
- 配置向量：旧 → 新恰多 4 个键，既有项零变化、顺序不变；新件与上游 `e72bc75`
  的输出只差两处 namespaces 帮助文案（出厂树旧措辞）。
- 与上游 `ed5378a` 的输出相比另有两处默认值不同（`llm.model`、`llm.temperature`）
  ——即 §4 的 MEM-02d。

## 6. 移植前先读什么

1. 上游提交说明 + `git diff <旧基线>..<新基线> -- sme/`。**只看 `sme/`**；
   `experiment/` 是测试调参期的产物，只当回归参考，不当规格。
2. 上游 README / docs 里对应的小节（配置项、预设、HTTP 路由）。
3. 本文件 §2：C 版该模块现在钉在哪、已有哪些有意偏离。
4. 任务书 §7.2 / §7.3：这一项该不该吸收。

## 7. 怎么移植

1. **物化参考树**：`git archive <提交号> sme | tar -x -C <临时目录>`——按提交号
   物化。**不要依赖本地插件仓的工作区**：它会被更新到上游最新（2026-11-24 已不在
   `e72bc75`）。不往参考树写任何东西（`python -B`、`PYTHONDONTWRITEBYTECODE=1`）。
2. 用 C 重写。回归测试的期望值取**上游实现的实际输出**，不是 C 的输出。
3. 只有动到对拍面（分词、排序、配置输出、存储格式）才重录向量，顺序是：
   先证明录制器对**旧**基线能逐字节复现现役向量（管线可信），再录新基线；
   备份旧件；更新 §5。
4. 代码头注写明「自 <旧基线> 起在此处有意偏离，依据上游 <新基线>」。
5. 亲跑五套：`make -C agent/ai/<模块> test`，模块 = `engine` `retrieval`
   `smeconfig` `space` `smehttp`。**总测试脚本 `tests/run_all.sh` 不含这五套**，
   「run_all 全绿」不代表记忆层没坏。
6. 更新本文件与任务书对应行。

## 8. 对照节奏

季度对照一次（下次 2027-02 下旬）；上游版本号变化或 `sme/` 有新提交时提前。
