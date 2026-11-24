# 记忆层出厂配置验证（MEM-FACTORY-1125）

> 分支 `wt-memfact-1125`，起点 `fc2482f`。本文每个数字都是本路亲跑；
> 没跑的一律写「未跑」，推断的标【推断】。出厂配置的**内容**不落本文、
> 不进日志、不进提交：只列键名、敏感标记与结构计数。

## 1. 结论

- **三项必测全部通过**：出厂配置能启动（248 条种子、6 预设）；热重建会
  立即落盘、同数据目录重启后配置与记忆都在；`/config/reset` 在不可写
  目录下**干净失败**（HTTP 200 `{"ok":false}`、可读错误、配置/快照/记忆
  一个不动），恢复可写后 reset 成功回 `source=defaults`。
- **无阻塞项**：并入主仓的记忆层改动（MEM-01a/01b/01c、02a、02b、02c）
  在出厂配置下可以随 17.12 出厂；另有 3 条中/低优先偏离（§6 F1–F4）建议
  主会话裁定，但都不影响「出厂启动 / 热重建落盘 / 重启保留 / reset 安全
  失败」这四条。
- 测试脚本 `agent/ai/smehttp/tests/test_factory_config.py` 两种口径各
  **161 断言全过**（root + `setpriv --reuid=nobody`、普通用户 0555 目录），
  单轮约 10 s。

## 2. 被测对象与怎么跑

被测二进制：`agent/ai/smehttp/aikd`（`make -C agent/ai/smehttp -j1 all`
构建；本路实测 sha256 `fc47ce5a…714f`，1,662,864 B）。出厂配置与种子来自出厂树；配置是 0600 root，跑前复制成可读副本，**跑完
由调用方删除副本**（测试脚本只读它，不复制进证据/提交）：

```bash
# 1) 复制出厂配置（0600 root）到可读副本；跑完删除
sudo mkdir -p /tmp/sme-factory
sudo cp <出厂树>/opt/sme/data/sme.config.json /tmp/sme-factory/sme.config.json
sudo chown "$USER" /tmp/sme-factory/sme.config.json && chmod 600 /tmp/sme-factory/sme.config.json

# 2) 重编
make -C agent/ai/smehttp -j1 all

# 3) 普通用户口径（C 组用 0555 目录模拟不可写）
python3 agent/ai/smehttp/tests/test_factory_config.py \
  --aikd agent/ai/smehttp/aikd \
  --config /tmp/sme-factory/sme.config.json \
  --seed <出厂树>/usr/local/share/aikernel/sme-seed.jsonl \
  --static agent/ai/smehttp/static \
  --evidence <证据目录>/run-user

# 4) root 口径（C 组用 root 属主目录 + setpriv 降权到 nobody；任务书主口径）
sudo python3 agent/ai/smehttp/tests/test_factory_config.py \
  --aikd agent/ai/smehttp/aikd \
  --config /tmp/sme-factory/sme.config.json \
  --seed <出厂树>/usr/local/share/aikernel/sme-seed.jsonl \
  --static agent/ai/smehttp/static \
  --evidence <证据目录>/run-root
```

脚本只用标准库：自建临时目录、`--port 0`（内核选端口；固定值限
18800–18899）、启动/请求超时、SIGTERM 收尾、失败退出非零；会把自己
Popen 的进程杀干净。`--only a,b,c,d,e` 可单跑一组，`--keep` 保留临时
目录。脚本把二进制/种子/静态目录复制进自己的临时目录，所以 root 口径
下降权后的 nobody 也能读。

## 3. 测了什么（A–E 组）

| 组 | 覆盖 | 关键断言 |
|---|---|---|
| A | 出厂配置启动 | `source=file`、`config_file` 一致、9 个非空分组、6 个预设（17/25/25/18/17/29 项）、`/stats` 可用、中文检索命中、出厂显式键与注册表默认值对比 |
| B | 热重建 + 落盘 + 重启 | 写 3 条中文记忆 → `POST /config/preset {"key":"united_static"}` → 快照文件出现且含全部 251 条 → 配置文件被改写 → SIGTERM rc=0 → 同数据目录重启，251 条与预设配置都在 |
| C | `/config/reset` 在不可写目录 | 只读目录下 reset 返回 `ok:false` + 可读错误、配置/快照/记忆不变、进程不崩；恢复可写后 reset 成功；另测 0444 配置文件、以及配置目录可写但 CWD/数据目录不可写的变体 |
| D | 种子导入数值校验 | `importance=2.0` 坏种子 `--import-seed` 非零退出且不监听；`POST /import` 坏值整批 422；好种子导入成功且重启不翻倍 |
| E | MEM-02d 边界 | 纯默认下两套默认值表是否一致；配置文件装载是否做取值校验；`PUT /config` 是否拒绝越界值 |

## 4. 实测数字

### 4.1 出厂基线与启动（A 组，root 口径）

| 项 | 实测 |
|---|---|
| 出厂配置 | 12,059 B，sha256 `51abd8b7…1031`；显式键 130 个（不含 `_help`）；其中密钥类 3 个（`embedding.api_key`、`llm.api_key`、`api.auth_token`），GET /config 均未下发掩码（=未设置） |
| 出厂种子 | 248 条，sha256 `2ddc73fa…8b25` |
| 冷启动（Popen → 首个 `/health` 200，含种子导入） | **1.036 s**（监听就绪 1.035 s） |
| 就绪后 `GET /health` | `{"status":"ok","memories":248}` |
| `GET /stats` | provider `hashing-d64-w3`、memories.total=248、regions.count=106、policy.decay_enabled=true |
| `GET /config` | `source=file`；groups=9（10 个分组定义，`visualization` 无注册项被丢弃）；presets=6：`chat,kb_dynamic,kb_static,robot,minimal,united_static` |
| 中文检索 | `POST /memories/search {"text":"进程调度"}` → 200，count=10（cjk_bigram 分词生效） |
| 注册表规模 | `GET /config` 共下发 101 个可配置项（与 `config_items_data.h` 头注一致） |
| 出厂显式键对比 | 130 个显式键中：90 个是注册表项、39 个不在注册表、1 个是 `seed` 特例；与**默认 DOM** 相比只有 2 个真正不同：`storage.path`、`storage.autosave_interval`（25 vs 100）——见 §6 F6 |
| 注册表 item 默认值 vs 默认 DOM | `GET /config` 里 5 个 `modified=true`：`llm.base_url`、`llm.model`、`llm.temperature`、`storage.path`、`storage.autosave_interval`；前三个是两套默认表不一致造成的（§6 F4） |

`GET /memories/stats`：**404** `{"detail":"memory not found"}`——本版与上游
都没有这个路由，`/memories/{id}` 会把 `stats` 当 id。引擎统计走
`GET /stats`（`agent/ai/smehttp/http.c:781`、`http.c:823`）。

### 4.2 热重建 + 落盘 + 重启（B 组）

| 项 | 实测 |
|---|---|
| 冷启动 | 1.034 s |
| 重建前快照 | `engine.json.gz`，250 条，197,246 B，sha256 `cdc37292…7adb`（**首次启动种子导入本身就会写快照**：出厂 `storage.autosave_interval=25`，248 条种子逐条 add 会触发约 10 次 autosave） |
| 预设 | `POST /config/preset {"key":"united_static"}` → 200 `{"ok":true,"applied":[…29 项…]}` |
| 重建后快照 | `engine.json.gz`，**251 条**，**207,192 B**，sha256 `c4223b89…74ff`；`engine.json`（未压缩）**不存在**——出厂 `storage.compress=true`，实际落盘名是 `<AIKD_DATA_DIR>/engine.json.gz` |
| 快照内容 | 含 3 条新记忆 id；内嵌 `policy.decay_enabled=false`、`retrieval.keyword_candidates=20`、`storage.path=<AIKD_DATA_DIR>/engine.json` |
| 配置文件 | 被 preset 改写；`policy.decay_enabled=false`、`retrieval.keyword_candidates=20`、`ranking.semantic=1.0`；`api_key` 仍为空 |
| SIGTERM | rc=0 |
| 重启冷启动（有快照） | **0.082 s** |
| 重启后记忆 | **251 条**（248 种子 + 重建前 3 条）；3 条按 id 均可 GET |
| 重启后配置 | `source=file`，`decay_enabled=false`、`keyword_candidates=20`、`storage.path=<AIKD_DATA_DIR>/engine.json`、6 预设 |
| `persistence.enabled=false` 的边界 | 重建**之后**再写 1 条（内存 252），SIGTERM 后重启 → **251**，该条 404。即：只保留最后一次 checkpoint 的状态；重启不重放「checkpoint 之后的写入」（`agent/ai/engine/engine.c:4544` 起的 MEM-02a checkpoint 语义、`main.c:397` 起的 load 路径） |

### 4.3 `/config/reset`（C 组）

准备阶段：写 4 条 + `preset chat` 触发 checkpoint，快照 252 条、
203,605 B、sha256 `a960c60f…5dbd`；再起一台只读目录的服务。

| 场景 | 结果 |
|---|---|
| 数据/配置目录 root 属主 0555、服务以 `nobody` 运行 | 启动正常（快照可读，252 条）；写 1 条后 253 条；`POST /config/reset` → **HTTP 200** `{"ok":false,"errors":{"_global":"删除配置文件 <tmp>/c1/cfg/sme.config.json 失败：Permission denied"}}`；配置文件仍在、快照 sha256 不变、记忆仍 **253** 条、`source` 仍 `file`、进程存活 |
| 恢复目录可写后再 reset | **HTTP 200** `{"ok":true}`；配置文件被删；`source=defaults`；记忆仍 253 条；`storage.path` 回默认 `data/engine.json`、`persistence.enabled=false`、6 预设仍在 |
| 同场景重启 | 252 条（见 F1：reset 的 checkpoint 落在 `<CWD>/data/engine.json.gz`，204,369 B、sha256 `3cf2be23…0a23`；下一次带 `AIKD_DATA_DIR` 的启动不读它） |
| 变体：配置目录可写、配置文件本身 0444 | reset **成功**（200 `{"ok":true}`），配置文件被删、`source=defaults`、记忆 249 条不丢——`unlink` 只看目录写权限，0444 不保护文件 |
| 变体：配置目录可写、CWD 与数据目录不可写 | reset 先删配置、再重建，checkpoint 落盘失败：**HTTP 200** `{"ok":false,"errors":{"_global":"persistence 关闭模式下 checkpoint 落盘失败，引擎保持原配置：engine: mkdir data failed: Permission denied"}}`；**配置文件已被删**、旧引擎/记忆（251 条）/快照都不动（见 F2） |

### 4.4 种子导入数值校验（D 组）

| 项 | 实测 |
|---|---|
| 坏种子（`importance=2.0`，2 行） | `--import-seed` 启动 → **rc=1**，stdout 只有 `[aikd-seed] seed=2 existing=0 missing=2`，**没有 LISTENING**；stderr `internal /memories/batch -> 422: {"detail":[{"type":"value_error","loc":["body","memories",1,"importance"],"msg":"Value error, importance must be finite in [0,1]","input":2.0,…}]}`；数据目录没有快照 |
| `POST /import` `importance=2.0` | **422** `value_error`，loc `["body","memories",0,"importance"]`；记忆数不变 |
| `POST /import` `weight=-1` | **422**，loc `["body","memories",0,"weight"]` |
| `POST /import` `importance=1.0` 边界 | 200 `{"imported":1}`，记忆数 +1 |
| 好种子幂等 | 首启 `missing=248`；`preset chat` 落一次 checkpoint 后重启 → `missing=0` / `corpus already complete, skip`，记忆数不变（不翻倍）；重启冷启动 **0.103 s** |

### 4.5 MEM-02d 边界（E 组）

| 项 | 实测 |
|---|---|
| 纯默认（无配置文件）`llm.model` / `llm.temperature` | **`gpt-4o-mini` / `0.3`**（来自 `AIK_CONFIG_DEFAULT_JSON`） |
| 注册表 item 默认值 | **`""` / `0.6`**（`config_items_data.h:38`、`:47`） |
| 纯默认下 `modified` 标记 | `llm.model`、`llm.temperature` 均为 **true**（两套默认表不一致，§6 F4） |
| 配置文件写 `llm.temperature=99` | 服务**能启动**、值 **99 生效**（`GET /config` 回 99）→ 装载入口不做取值校验 |
| `PUT /config {"values":{"llm.temperature":99}}` | 200 `{"ok":false,"errors":{"llm.temperature":"不能大于 2"}}` → 写路径有校验 |

结论（照任务书口径）：上游 `_validate_field`（`sme/config.py:330`，由
`from_dict` 在 `:426` 调用）**在装载入口没有移植**；本版只有 `/config`
PUT 与预设应用走注册表校验（`aik_config_item_validate`）。所以本版应写
「**配置取值校验不在装载入口**」，而不是「完全没有校验」。

## 5. 三项核心问题逐条回答

1. **热重建能否落盘：能。** `POST /config/preset` 后 `<AIKD_DATA_DIR>` 下
   出现 `engine.json.gz`（207,192 B，sha256 `c4223b89…`），内容含重建前
   全部 251 条记忆与预设配置。注意两点：出厂 `storage.compress=true`，
   实际文件名是 `engine.json.gz` 而不是任务书写的 `engine.json`；出厂
   `storage.autosave_interval=25`，种子导入本身已写过快照。
2. **重启是否保留：保留最后一次 checkpoint 的状态。** SIGTERM rc=0；同
   数据目录重启 0.082 s 就绪，251 条与预设配置都在。`persistence.enabled=false`
   时，最后一次 checkpoint 之后写入的 1 条不在快照里（重启 404）——这是
   代码注释写明的语义，不是缺陷。
3. **`/config/reset` 在不可写目录：干净失败且不丢数据。** HTTP 200
   `ok:false` + `删除配置文件 … 失败：Permission denied`；配置、快照、
   记忆都不动，进程不崩。恢复可写后 reset 成功（`source=defaults`、配置
   文件被删、引擎重建、环境变量重放）。**但有两个偏离**：AIKD_DATA_DIR
   不参与 reset 后的落盘（F1）；reset 先删配置再重建，重建失败时配置已
   丢（F2，上游同序）。

## 6. 缺陷 / 偏离 / 风险

**F1（中，C 版特有）：`/config/reset` 的 checkpoint 不重放 AIKD_DATA_DIR。**
`AIKD_DATA_DIR` 只在启动时覆写 `storage.path`
（`agent/ai/smehttp/main.c:287`，调用点 `:403`、`:448`）；reset 走
`aik_config_defaults` + env 重放，不调用它（`routes_config.c:1377-1430`），
默认 `storage.path=data/engine.json` 是相对路径。于是 reset 的完整状态
checkpoint 落到 `<CWD>/data/engine.json.gz`；下一次带 `AIKD_DATA_DIR` 的
启动仍读旧快照，reset 前后写入的记忆在重启后丢失（实测 C4 写 1 条、
reset 后 253 条，重启回到 252 条，其中 1 条就在 reset checkpoint 里）。
复现：`AIKD_DATA_DIR=<d>` 起服务 → 写记忆 → `POST /config/preset` 落一次
checkpoint → 再写 1 条 → `POST /config/reset` → SIGTERM → 同 `AIKD_DATA_DIR`
重启 → `GET /health` 少 1 条；`<CWD>/data/engine.json.gz` 里却有它。
工厂 unit 不设 `AIKD_DATA_DIR`（见 F8），所以工厂部署不走这条分支；
受影响的是所有用 `AIKD_DATA_DIR` 的启动方式（本测试、工具链）。

**F2（低，上游同序）：reset 不是原子的——先删配置，再重建。**
`routes_config.c:1393` 的 `unlink` 在 `:1415` 的 `aik_engine_rebuild`
之前；重建的 checkpoint 落盘失败（rc=2）时返回 `ok:false`，但配置文件
已经没了（实测 C9：`checkpoint 落盘失败…mkdir data failed: Permission
denied`，配置目录可写、CWD/数据目录不可写）。上游
`reference/sme/api/server.py:641-652` 是同样的顺序，属继承行为；建议
入厂前决定是否在 C 侧改成「先重建成功再删配置」或失败时回滚配置文件。

**F3（低）：配置文件装载没有取值校验（MEM-02d 的 `_validate_field` 未移植）。**
`aik_config_from_json` / `overlay_section` 只做 `hasattr` 白名单
（`agent/ai/smeconfig/config.c:256-286`），不校验类型/范围/枚举；上游在
`from_dict` 里逐字段 `_validate_field`（`reference/sme/config.py:330`、
`:426`）。实测：配置文件写 `llm.temperature=99`（注册表上限 2）服务照常
启动并生效；同一值走 `PUT /config` 被拒（`errors.llm.temperature=
"不能大于 2"`）。出厂配置本身合法，所以不影响本次出厂；但「坏配置文件
拒绝启动」这条上游行为本版没有。按任务书口径记：**配置取值校验不在本版
（装载入口）**。

**F4（低）：两套默认值表不一致，`GET /config` 在纯默认下误报 modified。**
`AIK_CONFIG_DEFAULT_JSON`（`agent/ai/smeconfig/config_default.h:45-47`）
给 `llm.base_url/model/temperature` = OpenAI URL / `gpt-4o-mini` / `0.3`；
注册表 item 表（`config_items_data.h:32/38/41/47`）仍是 `""`/`""`/`""`/`0.6`。
纯默认启动时 `GET /config` 把 `llm.base_url`、`llm.model`、
`llm.temperature` 标成 `modified=true`，会误导运维；MEM-02d 行与
`docs/MEM-UPSTREAM-BASELINE.md` §2「`llm.model` 空=不用 LLM」的说法也
与本版默认 DOM 不符。建议二选一：把 item 表对齐 DOM，或把 DOM 回退到
item 表并把 MEM-02d 重新登记。

**F5（信息）：`GET /memories/stats` 不存在。** 任务书期望的这条路由本版
与上游都没有；`/memories/{id}` 会把 `stats` 当 id 返回 404
（`http.c:823`）。统计用 `GET /stats`（`http.c:781`）。

**F6（信息，安全）：出厂配置 130 个显式键里 39 个不在注册表，但取值全部
等于默认 DOM。** 逐个比对（默认 DOM 从 `config_default.h` 解析）：39 个
未注册键无一与默认值不同；`memory.*` 7 个键不在默认 DOM、但等于注册表
item 默认值。即出厂配置没有「写了却被静默丢掉的不同取值」。
`visualization` 分组 5 个键没有注册项，`GET /config` 只下发 9 个分组。

**F7（信息）：出厂 `storage.autosave_interval=25`（仓内默认 100）。**
首启种子导入 248 条会写约 10 次快照（250 条时 197 KB）。仓内
`bench_coldstart.py` 头注按「默认 100」描述出厂口径，与出厂配置不符；
冷启动实测 1.0 s（含这些 autosave），不影响出厂，但口径文档应更正。

**F8（信息【推断】）：工厂 unit 没有 `WorkingDirectory` / `AIKD_DATA_DIR`。**
`factory/etc/systemd/system/aikernel-memory.service` 以 root 运行、
`CWD=/`；配置里 `storage.path=/opt/sme/data/engine.json`。`/config/reset`
后配置文件被删，默认 `storage.path=data/engine.json` 解析为 `/data/engine.json`
【推断：按 CWD=/ 推】，引擎把库迁到 `/data`；`aik-reset` 只清
`/opt/sme/data/engine.json*`，旧快照会成为孤儿。机制（CWD 相对默认路径）
是实测的（C5/C7），`/data` 具体路径未在真实 unit 下跑（未跑 QEMU/镜像）。

## 7. 证据与复核

- 证据：`<证据目录>/run-root`、`<证据目录>/run-user`，各含
  `summary.json`（含 aikd/配置/种子的 sha256、逐项 measurement）、
  `http-transcript.jsonl`（`GET /config` 只记结构，不含取值）、
  `server-logs/`（aikd stdout/stderr）、以及 `<证据目录>/memfact-root.log`、
  `memfact-user.log` 两份控制台输出。不复制配置副本、不复制 engine.json。
- 主会话亲跑一行：

  ```bash
  python3 agent/ai/smehttp/tests/test_factory_config.py \
    --config /tmp/sme-factory/sme.config.json \
    --seed <出厂树>/usr/local/share/aikernel/sme-seed.jsonl \
    --static agent/ai/smehttp/static --evidence <证据目录>/verify
  ```

  期望末行 `RESULT 161 passed, 0 failed`；root 口径同命令加 `sudo`。
- 该看的断言：`A2 /health memories == seed records`、`A4 /config presets
  count`、`B5 snapshot written under AIKD_DATA_DIR`、`B10 restart memories
  == last checkpoint`、`C4 reset(unwritable) ok`、`C5 reset(writable) ok`、
  `D1 bad seed exits non-zero`、`D2 /import importance=2.0 status`。

## 8. 未做 / 边界

- 未跑 `tests/run_all.sh`、QEMU/串口、真模型；未在 17.12 真机镜像上跑
  （F8 的 `/data` 路径为推断）。
- 未测并发/多进程写（C 版单进程单写者，不在本任务范围）。
- 未改产品代码；本文的 F1–F4 只报告，不修。
- 与 MEM-02d 的边界：`_validate_field` 等价的**装载入口**取值校验不在本
  版；写路径（PUT /config、preset）已有注册表校验。默认值部分——
  `AIK_CONFIG_DEFAULT_JSON` 已经是 `gpt-4o-mini`/`0.3`，注册表 item 表
  仍停在 `""`/`0.6`（F4）。
