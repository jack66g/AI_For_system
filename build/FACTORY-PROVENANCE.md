# 出厂「即所编」对账（ENG-14）

本文件说明出厂树的**一方件清单模型**、**比较口径**与**复现步骤**，并登记
已知欠账。程序的单一清单在 `build/factory_manifest.py`（下称"清单模块"），
刷新脚本 `build/w17n_factory_refresh.py` 与打 ISO 脚本
`build/w17n_build_iso.sh` 都只读它，不再各自维护文件列表。

## 1. 清单模型

每个出厂件一条记录，字段：

| 字段 | 含义 |
|---|---|
| `path` | 出厂树内安装路径（绝对路径） |
| `kind` | `elf` / `script` / `asset`（asset=数据资产，只记账） |
| `src` | 仓内安装源（构建产物路径，或 `factory/` 下被跟踪的资产）；空 = 无仓内安装源 |
| `recipe` | 产生 `src` 的构建命令（只作记录/提示；刷新脚本不代跑 make） |
| `postprocess` | `none` 或 `strip`，安装与对账都按同一后处理执行 |
| `mode` | 安装权限位 |
| `installer` | `refresh`（刷新脚本从仓装）或 `none`（无安装器，记 NO_RECIPE） |
| `commit_paths` | 计算"源最后修改提交"用的仓内路径集合 |
| `rebuild_src` | 可选：第二份构建产物，仅作对账佐证，不安装 |
| `note` | 非显然选择的理由 |

清单一共 28 条：26 条由刷新脚本从仓装（含 aikd 的三个 static 资产），
2 条 NO_RECIPE（见 §6）。

## 2. 比较口径

- **主判据是 md5**：出厂树件 vs 仓内件，按同一 `postprocess` 处理后的字节。
  `postprocess=strip` 时，清单模块把仓内产物**复制到临时文件**再 strip；
  **绝不就地 strip 仓内产物**（旧 `agent/ai/build-rootfs.sh` 的就地 strip
  不再沿用）。
- **脚本**按文本 md5 比，状态记 `SCRIPT`；`asset` 按字节 md5 比。
- **ELF 漂移要分类**：md5 不等时，清单模块逐节比较（ELF64 节头），并给出
  "仅 build-id/调试节/符号表不同（code-identical）"还是"代码节真不同"。
  这是为了区分三种原因：
  1. strip 后处理差异（例如拿未 strip 件直接比）；
  2. 构建路径差异——`-g` 记录 `DW_AT_comp_dir`，gold 的 BuildID 在链接时
     对含调试节的内容取哈希，所以同一份源码在**不同绝对路径**下编译会得到
     不同 BuildID/md5，而 `.text/.rodata/.data` 完全相同；
  3. 真漂移——代码节不同。
- **溯源源提交**：`--write` 记录每件 `src_last_commit`，并对
  `src` 不在 `factory/` 下的件，用出厂树快照里的最后刷新提交
  （`ISO-SNAPSHOT-W82.txt` 的 `refresh_commit=`；旧文件为 `userland=`）做
  `git cat-file blob <rev>:<path>` 比对，标注"出厂件 == 该提交的 blob"。
- **NO_RECIPE 件**只记出厂 md5/大小/时间，不判红；刷新脚本仍保留其原行为，
  但快照与清单里逐件写明。

## 3. 安装器与刷新流程

`build/w17n_factory_refresh.py` 的二进制/脚本重装面已改为清单驱动：

1. 只装 `installer=="refresh"` 的件；
2. 装前要求仓内产物存在，缺失即停并打印对应 `recipe`（不在刷新脚本里
   代跑 make——刷新以 root 运行，代跑会把仓内产物变成 root 所有）；
3. 装后逐件断言 `md5(出厂件) == md5(postprocess(仓内件))`；
4. 在出厂树写 `/etc/aikernel/FACTORY-MANIFEST.txt`（完整清单，含
   NO_RECIPE 逐件 md5）；
5. `ISO-SNAPSHOT-W82.txt` 不再写"`userland=main@<提交>`"暗示整棵树同源，
   改为 `refresh_commit=` + 清单计数 + `norecipe=` 逐件行。

`--check` 是零写入模式：只按清单核对出厂树与仓内件，DRIFT/MISSING 退出
非零。打 ISO 时 `build/w17n_build_iso.sh` 在打包前调用
`factory_manifest.py --audit`，有漂移/缺件即中止。

## 4. 复现步骤（主会话在打 ISO 时执行）

1. 在仓根构建全部待刷新件（示例；按清单 `recipe` 字段逐条执行）：
   - `make -C agent/ai occ`
   - `make -C agent/ai aik-sandbox`
   - `make -C agent/ai aik-compat` / `aik-gcm`
   - `make -C agent/ai/smehttp -j1 all`（出 `aikd`）
   - `make -C agent/ai/aistreamd`、`make -C agent/ai/aistreamd aik-pqdump`
   - `make -C agent/ai/aipd`
   - `make -C agent/ai/tlsgw -j1 all`
   - `make -C agent/ai/autocondense -j1 all`
   - `make -C agent/ai/aikime`（依赖 `~/p55-poc` 的 librime）
2. 只读核对：`python3 build/factory_manifest.py --audit`
   （默认 `<出厂树>` = `$AIK_FACTORY_ROOT` 或 `~/w7i-rootfs`）。
3. 装：`sudo python3 build/w17n_factory_refresh.py`（写完再跑一次
   `--audit` 应全 MATCH；NO_RECIPE 件不计红）。
4. `python3 build/factory_manifest.py --check-installed`：受管目录里出现
   清单外的一方件必须报红；第三方/基座件只走显式白名单（理由在代码里）。

## 5. 实测事实（2026-11-25，L1；数字均为实跑）

### 5.1 `aik-sandbox`：两份件的定谳

- 现行 Makefile（`agent/ai/Makefile` 的 `$(SB_BIN)`）产物在
  **`agent/ai/aik-sandbox`**；`agent/ai/sandbox/aik-sandbox` 只是旧链的
  未跟踪"出厂同源锚"。
- 当前源码（fc2482f）重编 `make -C agent/ai aik-sandbox` 得到
  **1,111,080B / md5 6ad156b18be24435bbb7b8c8cb07c9e7 / BuildID
  9354c6d6873cbe518c68a6e104576dd9a514f3ac**，与出厂件、与旧锚
  **三者同一件**。
- 旧件 `agent/ai/aik-sandbox`（1,111,040B / 11-15）是 O-8 沙箱链修复前
  （源最后改于 7b3ee64，11-20）的陈旧构建。
- 结论：出厂件由现行配方从工作区编出；两份不一致是"旧构建 vs 新构建"，
  不是两条配方。清单改为取 Makefile 产物路径，打 ISO 脚本同步改掉旧锚
  断言。

### 5.2 `aikd`：出厂件是 11-04 旧件，记忆层五项不在

- 出厂 `/usr/local/sbin/aikd`：456,936B，md5
  `0dfa53cd255d6a57067a9e6dde650d8f`，mtime 11-04 00:25，属主
  `jack66g:jack66g`（唯一一件非 root 属主的出厂一方件，属旧链拷贝痕迹）。
- 仓内按 `agent/ai/smehttp/Makefile` 的 `aikd` 目标重编（fc2482f）：
  未 strip 1,662,856B；按出厂口径 strip 后 **465,128B**，与出厂件仍差
  8,192B（两页），`.text/.rodata` 等代码节不同 → 真漂移。
- 记忆层五项（MEM-01a/01b/01c/02a/02b）的字符串证据：
  - MEM-01c 的配置键顺序串
    `candidate_window,fusion,keyword_candidates,min_similarity,`
    出厂 **0** / 重编 **1**；
  - MEM-02a 的
    `persistence 关闭模式下 checkpoint 落盘失败`
    出厂 **0** / 重编 **1**；
  - MEM-02b 的
    `importance must be finite in [0,1]`、`hit_count must be a
    non-negative integer`、`weight must be a finite non-negative number`
    出厂 **0** / 重编 **1~2**。
  - MEM-01a/01b 是纯行为修复、无新增产品字符串（重编件也无
    `mem01b merge:` 等测试串）；【推断】不在出厂件里——依据是出厂件
    构建时间（11-04）早于两个提交（11-24 14:57），且其余三项标记全缺。
- 结论：出厂件不含五项。清单已把 `aikd` 列为 `refresh` 从仓装；何时真换装
  由 MEM 出厂台架另定（本任务只记账）。

### 5.3 `aik-compat` / `aik-gcm`

- 出厂件分别是 **strip 后**的 1,135,672B / 1,246,072B。
- 在仓根路径按配方重编并 strip：md5 与出厂件**逐字节相同**
  （`a306c59f...` / `82530812...`），readelf BuildID 也相同
  （`4409f1f2...` / `811065bf...`）。
- 在另一路径（工树）重编：strip 后 size 完全相同，但 BuildID 与 md5 不同，
  `.text/.rodata/.data` 逐节相同——即 §2 的构建路径噪声。
- 结论：无真漂移；之前的"大小不同"是拿未 strip 件与 strip 件比。
  清单把 `strip` 写成显式后处理。

### 5.4 `aikctl`：两个来源不是同一物

- `agent/ai/aikctl/aikctl`：Python 脚本，249,877B，md5
  `9655b40052ba2b0c6e1b452bc65586ec`，跟踪入库；出厂
  `/usr/local/bin/aikctl` 与它同一件。**这是 P-2 的现役 CLI（正源）**。
- 出厂 `/usr/bin/aikctl`：ELF 995,952B（9-29），是**另一个程序**——C 版
  内核 netlink CLI；其源码在仓外的内核构建树 `tools/ai/`，本仓
  `tools/` 目录已不存在，`git log -- tools/ai/aikctl` 为空。
- `agent/ai/build-rootfs.sh:152-154` 仍引用 `$SRC/tools/ai/aikctl`
  （`$SRC` 指向内核构建树），属旧链残留；与刷新脚本的
  `agent/ai/aikctl/aikctl` 不是同一内容、不同用途。
- 结论：刷新用 Python 版（已在清单）；`/usr/bin/aikctl` 记 NO_RECIPE，
  待 ENG-05/07 决定清理或补配方。

### 5.5 其余件（在仓根路径的实测状态）

- `occ`：出厂件 == `b436d06` 的 blob；HEAD 已因 CON-10（`bf0113f`）更新，
  故对 HEAD 报 DRIFT。刷新后会一致。
- `aistreamd` / `aipd` / `aikctl` / `aik-console` / `aik-pqdump` /
  `aik-ime` / 8 个维护脚本：与出厂件一致。
- `autocondensed` / `autocondense-mcp` / `autocondense-hook` /
  `aik-tls-gateway`：出厂件是旧链 strip 的结果；在仓根路径重编并 strip 后
  与出厂件逐字节相同（前三者）；`aik-tls-gateway` 在仓内**尚未构建**
  （对账报 MISSING，刷新前须 `make -C agent/ai/tlsgw -j1 all`）。
- `aikernel-api`：仓内配方产 `aikerneld-api`，无安装步；出厂件是 11-12
  构建（早于 `c79638a` 把 K3 agent 自报 0→`AI_AGENT_APIC(4)`），对 HEAD
  反汇编可看到这一常量差异。受 #82 内核冻结约束，**不随刷新换装**，
  记 NO_RECIPE。
- `/usr/local/share/aikd/static/{app.css,app.js,index.html}`：aikd 的
  `--static-dir` 页面资产。出厂件与仓根**工作区**逐件 md5 相同
  （`a492757b...` / `878759d0...` / `40aeac33...`）；注意仓内 blob 是 LF、
  仓根工作区与出厂件是 CRLF（`git diff` 干净，属工作区行尾形态）。
  自 ENG-14 起三件由刷新脚本从 `agent/ai/smehttp/static/` 安装（0644），
  仓内 static 以后更新会随刷新进厂，不再静默落后。

## 6. NO_RECIPE 欠账清单（留给 ENG-05 / ENG-07）

| 件 | 出厂 md5 | 现状 | 建议 |
|---|---|---|---|
| `/usr/local/sbin/aikernel-api` | `fe7cead77e261c5c062c94f55fb98b38` | apic 源码可编，但无安装步；出厂件为 11-12 旧构建 | 补安装步并明确与 #82 内核/K3 agent-id 的配对；换装前须台架验证 |
| `/usr/bin/aikctl` | `04b609a9e03250a4ddc5854bd2cf60d1` | 旧 C 版 netlink CLI，源码不在本仓 | 决定退役或把源码收回仓内并补配方 |

**recipe-drift（基座链断点，refresh 链不受影响）**：
`agent/ai/build-rootfs.sh:152,154` 仍引用 `$SRC/tools/ai/aikctl`，而本仓
没有 `tools/` 目录（`git ls-files tools/ai` 为空），`$SRC` 指向的是仓外
内核构建树。从零跑一遍基座链会在 strip/install 这两行失败；现役刷新链
不读该路径（清单取 `agent/ai/aikctl/aikctl`，md5
`9655b40052ba2b0c6e1b452bc65586ec`，与出厂 `/usr/local/bin/aikctl` 同值）。
本任务边界只到 `build/`，`build-rootfs.sh` 的这条死引用留给 ENG-05/07。

第三/四方件（`busybox` 及 109 个 applet 符号链接、`ollama`、
`/usr/local/lib/aik-ime/*`、`/usr/local/lib/ollama/*`）走
`--check-installed` 的显式白名单，理由写在清单模块的 `WHITELIST` 里。

## 7. 已知限制

1. **构建路径敏感**：带 `-g` 的件在不同绝对路径下重编会得到不同
   BuildID/md5（`.text/.rodata/.data` 相同）。对账在仓根路径执行时才有
   逐字节意义；换路径跑出的 DRIFT 请看"code-identical"注记，不要据此改
   数字。
2. **刷新不代跑构建**：刷新脚本只装已存在的仓内产物；缺失即停并打印
   `recipe`。打 ISO 前必须先完成 §4 第 1 步。
3. **`aikd` 换装时机**：清单/刷新已具备从仓装能力，但记忆层五项须先过
   出厂台架（`/opt/sme/data/sme.config.json` 启动、热重建存盘、
   `/config/reset` 在不可写工作目录下的行为），再由主会话决定真跑。
4. **`aikernel-api` 与内核配对**：K3 agent-id 改动依赖内核侧枚举；#82
   冻结期间不换装（H6）。
