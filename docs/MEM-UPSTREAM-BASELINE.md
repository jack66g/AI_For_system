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
| `ed5378a` | 2026-11-20 | 大型测试战役、28 项修复、跨进程写锁、预设扩充。`sme/` 下 14 个文件 +680/−221 | 已移植 5 项（§3），其余见 §4 |
| `cba0f29` | 2026-11-21 | 测试归档与实验边界说明。`sme/` 与 `ed5378a` **零差异**（改动全在 `experiment/`） | 无需移植 |

## 2. C 版各模块当前基线（2026-11-24）

| 模块 | 钉在 | 本仓相对上游的有意偏离 | 对照向量 |
|---|---|---|---|
| `retrieval/text.c` 分词 | `ed5378a`（MEM-01a） | 混合书写系统的 run 切法不同；纯 CJK / 纯拉丁 / 空输入与 `e72bc75` 逐 token 相同 | `text/` 已重录到 `ed5378a` |
| `retrieval` 其余（BM25 / 排序 / PPR / 嵌入） | `e72bc75` | — | 未动 |
| `space/space.c` | `ed5378a`（MEM-01b） | 演化候选结转、merge 后剪边；既有 38 步重放结果不变 | 未动 |
| `smeconfig`（白名单 / 默认值 / 注册表） | `e72bc75` + 出厂树 | 4 个键已补（MEM-01c）；namespaces 两项帮助文案保留出厂树旧措辞；预设仍是 5 个 | `config/` 三个文件已重录（恰多 4 键） |
| `engine` | `e72bc75` + MEM-02a / 02b | 热重建后立即存盘；反序列化入口数值校验 | 未动 |
| `smehttp` | 同 `engine` | `/import`、`/import/file` 导入前校验，非法值整批 422（上游是未捕获异常 500） | 未动 |
| `storage` / `wal` / `sqlite` / `embed` / `api` / `ac` / `mcp` | `e72bc75`（T4） | — | 未动 |

## 3. 已移植（提交号为主仓）

| 项 | 上游依据 | 主仓提交 | 回归测试 |
|---|---|---|---|
| MEM-01a 混合词分词 | `sme/utils.py::tokenize` | `9d3a8e4` | `retrieval/tests/test_text.c` 自包含段 |
| MEM-01b 演化候选结转 + merge 剪边 | `sme/space/region_manager.py` | `154a274` | `space/tests/test_space.c` 自包含段 |
| MEM-01c 配置层补 4 键 | `sme/config.py`、`sme/config_items.py` | `71f85b0` | `smeconfig/tests/test_config*.c`、`engine/tests/test_engine.c` 段 4 |
| MEM-02a 热重建后立即存盘 | `sme/api/server.py::rebuild_engine_with` | `5358978` | `engine/tests/test_rebuild.c`、`smehttp/tests/test_http.c` 17–18 |
| MEM-02b 导入数值校验 | `sme/models.py::_validate_memory_numbers` | `12ac54b` + `f7ffa5a` | `engine/tests/test_engine.c` 段 5、`smehttp/tests/test_http.c` 19、`retrieval/tests/test_ranker.c` 段 5 |

## 4. 上游差异里尚未移植的（如实）

| 上游改动（`e72bc75` → `ed5378a`） | 处置 |
|---|---|
| 预设 06（静态检索·UNITED）、知识库预设权重归一（`kb_dynamic` / `kb_static` 各 20 → 25 键） | 06 → MEM-02c（待办） |
| 预设 07（真模型·语义优先） | 不吸收：C 版只有哈希嵌入，面向真模型 |
| `config.py::_validate_field`；`llm.model` 默认 `''` → `'gpt-4o-mini'`、`llm.temperature` 默认 `0.6` → `0.3` | **待定（MEM-02d）**：出厂默认纯离线，改默认模型要连同出厂配置一起看 |
| namespaces 两项帮助文案（`98071d9` 后的新措辞） | 并入 MEM-02c 一起处理 |
| `engine.py`（`_recovery_path`、`_load_locked`、`top_k` 类型容错、`query_prefix` 生效，以及围绕写锁的重构） | **未逐项审** → MEM-10 |
| `memory_manager.py`（`_check_encodable_text`、`_clamp01`）、`retrieval/rerank.py`、`storage/snapshot.py`（`_cleanup_embeddings`） | **未逐项审** → MEM-10 |
| `storage/xlock.py`（跨进程写锁） | 不吸收：C 版单进程单写者 |
| `mcp_server.py`、`modules/extraction.py`、`modules/profile.py` | 未逐项审 → MEM-10 一并过 |

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
