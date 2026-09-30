# AIKernel RAG 与数据/日志系统治理说明

> 维护人：AIKernel 数据清理专员 ｜ 落款日期：2026-09-27
> **本文档只治理数据（语料、索引、遥测、决策记录、构建产物、日志），不治理代码。** 任何 .c/.h/.py/Makefile/Kconfig 的修改流程见重构总纲与接口登记规范，不在本文档范围内。

本目录（`AIKernel/rag/`）承载 AIKernel 的向量检索（RAG）知识库：接口文档生成、向量索引构建与 `ai_rag_query` 检索，核心脚本是 `build_index.py`（Prompt 14 / 数据计划 22.1-22.3 / 重构总纲 Phase 0 任务 0.4/0.5）。运行期数据落盘由 `agent/ai/aikd/`（aikd 守护进程 + `aikd_lib.py`）完成。

## 一、向量检索系统现状

### 1. 四个检索 scope（`build_index.py` 中 `SCOPES`）

| scope | 摄入来源（`scope_files()`） | 说明 |
|-------|------------------------------|------|
| `docs` | `linux-6.18.39/Documentation/`、`linux-6.18.39/Project_Documentation/` 下 `.rst/.txt/.md` | 内核与项目文档 |
| `interfaces` | `linux-6.18.39/AIKernel_Docs/` 下 `.md`（由 `--extract` 生成） | AI 函数调用接口文档，机器可解析 |
| `source_code` | `AIKernel/`、`agent/` 下 `.c/.h`（排除 `third_party/`），以及 `kernel/ mm/ net/ fs/ ipc/ block/ security/ arch/x86/ include/ init/ drivers/ sound/ crypto/` 的 `.c/.h` | 源码切片，块大小 800 行、重叠 120 行 |
| `history` | `Kernel_Modification_Log/`、`AIKernel_Design/`、`agent/ai/docs/` 下 `.md`，外加项目根 `AIKernel_AI重构计划.md`、`AIKernel_数据源与日志系统计划.md` | 改造历史与设计决策 |

`--small` 模式只构建 `SMALL_SCOPES = ["interfaces", "history"]`。

### 2. 产物清单

| 产物 | 路径 | 生成方式 |
|------|------|----------|
| 接口文档（12 个） | `linux-6.18.39/AIKernel_Docs/` | `--extract` |
| 语料（分块全文） | `AIKernel/rag/corpus.jsonl` | `--index` |
| 索引元数据 | `AIKernel/rag/metadata.json` | `--index`（含 scopes、total_chunks、每块 id/source/start_line/end_line/scope） |
| 向量索引（faiss，DIM=1024，IndexFlatIP） | `AIKernel/rag/embeddings/<scope>.faiss`（4 个） | `--index` |

### 3. 如何重建索引

```bash
cd linux-6.18.39/AIKernel/rag
python3 build_index.py --extract                    # 第 1 步：生成 AIKernel_Docs/ 12 个接口文档
python3 build_index.py --index [--small]            # 第 2 步：构建 4 个 faiss 索引 + corpus.jsonl + metadata.json
python3 build_index.py --verify                     # 验收：5 组固定查询
python3 build_index.py --query "文本" [--top-k 5] [--scope all|docs|interfaces|source_code|history]
```

依赖：`faiss-cpu`、`numpy`。**embedding 为脚本内置的确定性哈希 TF-IDF**（`build_index.py` 的 `stable_hash`/`tokenize`/`embed`，DIM=1024，零外部模型、零网络），无需下载任何嵌入模型。Windows 下建议 `PYTHONUTF8=1` 运行（避免控制台编码问题）。aikd 侧亦预留了增量更新挂钩：`agent/ai/aikd/aikd.conf` 的 `RAG_SCRIPT` 键指向本脚本（当前为空 = 不触发）。

### 4. 当前状态（2026-09-27，已构建并验证）

**已于 2026-09-27 完成真实构建与检索验证**（Windows + Python 3.10.6 + faiss-cpu 1.15.1 + numpy 1.26.2）：

- **`--extract`**：内核树 `AIKernel_Docs/` 生成 **13 个文档**（00 系统调用 419 条 / 01 sysfs 4735 条 / 02 procfs sysctl 804+proc 62+/proc/PID 105 条 / 03 debugfs 3073 条 / 04 导出符号 36904 条 / 05 Kconfig / 06 模块参数 / 07 netlink 35 条 / 08 BPF helper 214 条 / 09 ioctl / 10 数据结构 15 个 / 11 启动参数 3259+ 条 / 12 错误码 162 条），与 `AIKernel_MD文档库/AIKernel_Docs/`（8-13 旧生成）逐文件 diff：小差异文件仅剩 1-30 行差异，原因＝旧库 HDR 引用的是生成机绝对路径（当前脚本为相对路径）＋ 8-13 后源码行号漂移与新增条目（如 `/proc/adv`）；04/05/06/09 大差异主体为 ext4/NTFS 目录遍历顺序不同（排序后 diff 由 6.5 万行降至 552/83/10/2 行，即真实内容变化仅几十条导出符号/Kconfig 行号）。
- **`--index`**（全量 4 scope，总耗时约 11.3 分钟，总块数 **1,794,319**）：

| scope | 块数 | faiss 文件 | 耗时 |
|-------|------|-----------|------|
| docs | 44,414 | 182 MB（`docs.faiss`） | 21 s |
| interfaces | 16,554 | 68 MB（`interfaces.faiss`） | 7 s |
| source_code | 1,733,351 | 7.10 GB（`source_code.faiss`） | 647 s |
| history | **0**（见下） | 无 | <1 s |

  `corpus.jsonl` 1.82 GB、`metadata.json` 242 MB（dim=1024，IndexFlatIP）。**history 为 0 不是故障**：其语料源 `Kernel_Modification_Log/`、`AIKernel_Design/`、`agent/ai/docs/` 及项目根两个计划 md 目前均不存在（历史文档已归档至项目根 `AIKernel_MD文档库/`，脚本按设计只找内核树内路径）；待这些登记目录恢复后重建即可补上。
- **检索验证（10 组查询，单次查询 <3 s）**：`swappiness`→`AIKernel/mm/ai_mm.h` 的 `ai_vmscan_swappiness_get/set`（强）；`OOM 分数`→`AIKernel_Docs/02_procfs接口.md` 的 `oom_score_adj` 条目（强）；`netlink 协议族 AI`→`AIKernel/net/ai_netlink.c` 的 `NETLINK_AI netlink_kernel_create`（强）；`cgroup 控制器`→`AIKernel/core/ai_cgroup.c`（强）；`读取内核遥测`→`agent/ai/runtime/netlink/ai_netlink_client.h`（强）；`内存水位`→DAMON `lru_sort.rst` 水位参数（相关）；`CPU 调度亲和性`→workqueue 亲和性作用域（相关）。**弱命中 2 组**：`限流AI推理`、`下发网络QoS决策`——语料中对应内容（ai_cgroup"推理预算/TOPS"、ai_net 字节配额）存在且换同义关键词（"推理 资源限制 预算"、"网络带宽配额"）即可命中，属哈希嵌入无语义的词面失配（见已知限制）。
- **如何重建**：按第 3 节命令。Windows 注意：① 必须先 `pip install faiss-cpu numpy`；② `PYTHONUTF8=1 python build_index.py ...`；③ faiss 的 C++ fopen 不支持非 ASCII 路径（本机用户目录含中文），脚本已内置 ASCII 临时目录中转垫片（`faiss_write`/`faiss_read`）；④ 全量重建约 12 分钟，产物峰值约 9.3 GB 磁盘。
- **已知限制（如实记录）**：
  1. embedding 是**哈希 TF-IDF 而非语义模型**：同义改写（"限流"↔"推理预算"）检索不到，只能词面/子词匹配；检索打分 = BM25 + 精确串 + 余弦×0.2 混合。后续接入真语义模型时 DIM 变化需整体重建并改 `DIM`。
  2. `RagEngine` 每次实例化全量加载 corpus（1.79M 块，实测加载约 242-248 s，峰值内存约十余 GB），`--query` 每次冷启动都付一次加载成本；`verify` 的 5 组查询各自重建引擎（官方路径一次约 21 分钟）。常驻服务化（aikd 挂钩）可摊销。
  3. source_code 含 drivers/sound 全量（1.73M 块、7.1 GB 索引），若只需 AIKernel 相关源码可接受更大 `--small`/`--only` 粒度，但当前脚本 scope 划分固定。
  4. 本脚本本次在 Windows 修了 5 处兼容 bug（`rel()` 斜杠统一、`fs/proc` 混合分隔符、`/third_party//Documentation/` 排除失效、CRLF→LF、faiss 非 ASCII 路径垫片），均为环境兼容修复，未改检索算法与 scope 逻辑。

## 二、"对训练模型有用的数据"白名单（必须保留）

以下数据是 AI 模型训练/检索的直接养料，任何清理动作不得触碰：

1. **接口文档**（`AIKernel_Docs/`，`--extract` 生成）：每条目遵循《agent/00_AI_函数调用接口指南.md》登记规范，含**八字段**——「路径 / 类型 / 范围 / 默认值 / 含义 / AI 控制用途 / 相关源码 / 相关内核符号」，AI 自动化解析必需。文档更新流程：代码改造完成 → 更新对应条目 → 重建索引。
2. **遥测 parquet**（数据根 `ROOT=/var/lib/aikernel` 下 `telemetry/`）：`telemetry/YYYY-MM-DD/<cat>_NNNN.parquet` 分日分类滚动，外加汇总索引 `telemetry/index.parquet`（文件→日期→类别→行数→时间范围）。来源为 NETLINK_AI 遥测（对齐 `struct ai_telemetry_record`）。
3. **决策与因果链 parquet**（数据根下 `decisions/`）：`decisions/YYYY-MM-DD/decisions.parquet`（/proc/ai/decisions 解析落盘）与 `decisions/chains_YYYY-MM-DD.parquet`（/proc/ai/chains 因果链，按链首时间分日）。
4. **Kconfig 与修改登记**：各子系统 `Kconfig`（AI 可调项的权威登记，同样遵循八字段规范）与 `Kernel_Modification_Log/`、`AIKernel_Design/` 等修改/设计登记文档——它们同时是 `history` scope 的语料。

数据根目录布局由 `aikd_lib.py` 的 `ensure_dirs()` 创建，含 `telemetry/ decisions/ rag_kb/ models/` 四个子目录（`rag_kb/`、`models/` 为 RAG 知识库与模型缓存预留位）。

## 三、垃圾黑名单与保留策略

| 类别 | 判定 | 策略 |
|------|------|------|
| 构建中间产物（bzImage/config 变体） | `Build_Output/Kernel/` 内除最新一对外的所有 `bzImage_prompt*`、`config_prompt*`、`System.map_*`、通用 `bzImage`/`config` | **只保留最新成功构建的一对**（1 个 bzImage + 1 个配套 config，≤2 个文件）。已于 2026-09-27 执行：删除 41 个变体（约 152MB），保留 `bzImage_prompt15_y` + `config_prompt15_y`。详见 `Build_Output/README.md` |
| 过期二进制 | 编译时间早于其后源码/配置变更的用户态二进制（如 2026-08-01 构建的 `agent/ai/ai`、`agent/ai/aikernel-shell`，其后 Kconfig 08-03 修改、aikd 08-14 新增） | 删除（已执行），用 `cd agent/ai && make all` 随时重建；二进制不是数据，不属于白名单 |
| 临时日志 | 一次性调试输出、构建日志、会话残留 | 用完即删，不进入 `Logs/` 长期保存；确需归档的日志按日期命名后归入 `Build_Output/Logs/` 并定期清理 |
| 重复索引 | `embeddings/` 中同一 scope 的旧版本索引、与语料不同步的 faiss 文件 | **索引必须从最新语料整体重建，禁止堆积旧索引**；重建时先清空 `embeddings/` 再生成，`metadata.json`/`corpus.jsonl` 同步覆盖，保证三者同批次一致 |
| parquet 分日目录 | `telemetry/YYYY-MM-DD/`、`decisions/YYYY-MM-DD/` 历史日期目录 | **按日期滚动保留**：近期分日目录在线保留供检索/回放，超期目录归档或删除。训练数据保留窗口由使用者在 `agent/ai/aikd/aikd.conf` 控制（数据根 `ROOT`、轮询周期 `POLL_SEC` 等；保留策略键由使用者按需增补并在该文件注释登记） |
| Python 运行残留 | `__pycache__/`、`*.pyc` | 不入库不提交，`agent/ai/aikd/Makefile` 的 `make clean` 会清除 |

> 2026-09-27 全树扫描结论：`linux-6.18.39/` 内无任何 `*.o / *.cmd / *.log / *.bak / *.orig / *~ / *.pyc` 残留（含隐藏目录），`agent/ai/build/` 仅为空目录骨架，无需清理。

## 四、治理边界重申

- 本文档**只治理数据，不治理代码**：删除/保留决策只针对语料、索引、parquet、构建产物、二进制、日志与空目录占位。
- 源码（.c/.h/.py）、Makefile/Kbuild/Kconfig 一律不在数据清理范围内；对其的任何变更走代码审查与修改登记流程。
- `AIKernel_MD文档库/`（项目根）为人工维护的文档总库，非本脚本产物，不属于本目录治理对象。
