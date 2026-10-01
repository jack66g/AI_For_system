# AIKernel 架构文档

> 适用代码基线：linux-6.18.39 + AIKernel/（本文档基于对源码的静态核实撰写，
> 全部实现状态标注均给出代码级证据；文档撰写日：2026-09-27）。

> **编译验证（2026-09-28，VMware Ubuntu 22.04 / gcc 11.4）：**
> - 内核全量：bzImage 编译通过，AIKernel 51 个目标文件**零警告**；
> - y/n 门控矩阵 7/7 通过（VFS/MM/SECURITY/NET/NETLINK/USRIFACE/AIKERNEL 全关均正常）；
> - agent/ai `make all` 通过：netlink 客户端 + 本地 provider（2026-09-27 新增代码）零警告；
> - 勘误：拆分遗漏的 `ai_vfs_inode_veto` 跨文件可见性（static 未升级）已修复；
> - Windows 树存在 NTFS 大小写限制（13 对 netfilter 文件无法并存），见
>   `linux-6.18.39/.casefix/README.md`；**权威构建树为虚拟机内 `~/linux-6.18.39`**。

> **AI 闭环与 L1 落地（2026-09-28 晚，全部实测）：**
> - 可控参数 23 个，**7 个真实生效**（+io.priority/mm.thp/net.rto，均有系统调用级回读证据）；
>   12 项 config 解锁（MEMCG/TUN/VETH/BRIDGE/USER_NS/FUSE/FQ/CODEL/HTB/NF_TABLES/BFQ/THP）；
> - **AI 工具闭环**：agent/ai 新增 ask 命令（tools 注册表 v2 **69 工具** = procfs-read 19 +
>   sysfs-write 12 + netlink-act 23 + netlink-sense 1 + exec 1 + memory 13，agent/ai/tools/tools.json，
>   risk 分级 R27/W15/W26）+ tool_calls/文本降级双解析 + 五通道自动执行器；E2E 实证：真实 qwen2.5:1.5b 经
>   NETLINK_AI 下发 sched.nice=5 → 内核 executed=4 真实执行；SME 记忆读写全通；
> - **P0 正确性修复**：exec 通道 30s 超时+stdin 重定向（原可无限卡死）、参数元字符整条拒绝
>   （原静默丢弃改语义）、netlink-act 客户端值域钳制、ACT 域广播警告进工具描述与 system prompt；
> - **P1 终端界面**：linenoise 行编辑 REPL + SSE 流式（本地真流式/云端缓冲解析）+
>   会话持久化（~/.aikernel/sessions/*.jsonl，session new/list/switch）+ 参数三层可调
>   （启动参数/env/TOML [ui] 段；本地经 /api/chat options.num_ctx 传真实窗口并按 /api/show 钳制；
>   修复了此前每次 ask 都在 Ollama 默认 ~2048 窗口静默截断的问题）+ usage 真值回填 +
>   折叠式工具卡片 + spinner + ai 单发/交互双入口；
> - **P2 权限分级**：policy/ai_user_policy 模块（uid→/etc/aikernel/policy.conf 档位：
>   root=privileged（W2 需 y/N 再校验）/wheel=confirmed/default=restricted（W2 拒绝）），
>   自测 21/21；executor 闸门单点接入；审计全量落 ~/.aikernel/audit.log；
>   aiuser 演示账号就位（非 root 下内核 CAP_SYS_ADMIN 通道实测拒绝）；
>   行内注释解析 bug 已修（曾致 root 误判 restricted）；
> - **P3 注册表 v2**：exec 白名单单源化（tools.json 权威，实测改 json 即拒）；
> - **P4 rootfs 生态**：DNS 修复（resolved+静态 resolv.conf）、busybox 静态件（wget/vi/less）、
>   apt 清华源四件套、hostfwd ssh（宿主 ssh -p 2222 直达 guest）、kunit.enable=0；
> - **SME 记忆引擎**（用户插件 github.com/jack66g/spatial-memory-engine）：
>   REST 127.0.0.1:8000 常驻，18250 条记忆（接口文档 13 份新语料 18239 块重建，
>   旧路径条目绝迹），持久化/强化动力学实测；语料重建后接口文档路径条目全部修正
>   （/proc/ai/*、/sys/kernel/ai/*、ai.* 启动参数补录），sme-export 18239 块就绪；
> - **L1 纯命令行系统落地**：8G ext4 持久 rootfs（Ubuntu 22.04 minbase）+ 内核侧
>   ip=dhcp + getty autologin + SME systemd 自启（aikernel-memory.service）；
>   QEMU virtio 启动实测：AIKernel 全子系统 ready、自动登录 root@aikernel、
>   guest 内 SME 自启（/health 18250 条）、持久化文件跨重启验证
>   （PERSIST-VERIFIED）；启动器 ~/run-aikernel.sh，快照 l1-rootfs-verified-20260928；
> - KUnit 测试决策噪声已消除（CONFIG_AIKERNEL_KUNIT_TEST=n）；内核 SENSE 单 CPU
>   查询 bug 已修（cpu_to=cpu+1，原恒假返回 0 条）；权威运行镜像
>   VM 内 ~/linux-6.18.39/arch/x86/boot/bzImage（#12，含 SENSE 修复）。
>
> 主线定位：**AI（本地模型或云端大模型）是主体，内核是被管理的对象**。
> AIKernel 是内核侧的"感知-决策-执行"承接层：全量感知数据外流（A/B 轨遥测）、
> 决策入口内收（sysfs/netlink/可控参数表），AI 外层程序据此闭环。

---

## 1. 模块地图（AIKernel/ 17 个子目录）

| 目录 | 职责（一句话，源自代码与头部注释） |
|------|------|
| `core/` | AI Runtime 中枢：模型注册与推理提交（ai_runtime）、决策策略引擎与决策 ring（ai_policy）、安全边界（ai_policy_safety：global_enable/max_impact/rollback）、可控参数表（ai_control）、因果链（ai_causal）、遥测 ring buffer 核心（ai_telemetry）、进程分类槽表与 A 轨 Hook（ai_proc*）、用户态控制面（ai_sysfs*：/sys/kernel/ai/、ai_procfs：/proc/ai/）、启动装配（ai_startup）、cgroup 接入（ai_cgroup） |
| `sched/` | 调度子系统 AI 化：进程分类（AI负载/交互式/批处理）、时间片与 vruntime 预测（占位启发式）、`ai_sched_*_hook` 空实现挂接点 + /proc/ai/sched 统计（ai_sched_procfs） |
| `mm/` | 内存管理 AI 化：页访问/碎片/KSM 收益预测、`ai_mm_*_hook` 空实现（fault/readahead/reclaim/workingset/alloc/thp/ksm/oom/cma）、`mm.swappiness` 立即生效参数（经 mm/vmscan.c 门控访问器）、第2类内存感知发射辅助（ai_mm_telemetry_alloc/reclaim）、AI 内存区预留骨架（ai_zone） |
| `net/` | 网络 AI 化：NETLINK_AI 协议族（ai_netlink：AI_CMD_SENSE/ACT/REG）、AI 网络核心（ai_net：流量分类/攻击检测/9 个 Hook 空实现 + 子事件采样门控 + socket 字节表）、第4类复杂解析发射（ai_net_telemetry）、HTTP/TLS 内容识别（ai_net_scan）、AI TCP 拥塞控制 ai_cca（ai_tcp_cca） |
| `vfs/` | 文件系统 AI 化：8 个 AI Hook 空实现（dcache/inode/path/writeback/epoll/aio/dax/rw）+ dentry 复用预测 + 子事件采样率表（ai_vfs）、第7类文件/路径/挂载/锁/poll/错误发射辅助（ai_vfs_telemetry*）、/proc/ai/vfs 统计（ai_vfs_procfs） |
| `io/` | 块层与字符设备 AI 化：块层 Hook + AI I/O 调度器类 ai_bfq（简化 deadline 语义族）+ 字符设备 Hook（ai_block/ai_bfq/ai_char） |
| `security/` | 安全 AI 大脑：AI LSM 模块（行为建模滑动基线 + 规则表 + 异常评估 + LSM 钩子 file_open/task_kill/ptrace + ai_sec_* 接入点，ai_lsm）、第8类安全事件发射（ai_lsm_telemetry）、审计关联与攻击链（ai_audit） |
| `interrupt/` | 中断管理 AI 化：irq/softirq 感知（per-CPU softirq 起止时间戳槽位）与中断负载统计（ai_irq） |
| `lock/` | 同步与锁优化：spin/mutex/rwsem 争用埋点（spin 1/256 采样，中断上下文安全）与锁统计（ai_lock） |
| `time/` | 时间管理 AI 化：定时器/hrtimer/clocksource 感知发射（ai_time） |
| `power/` | 电源管理 AI 化：AI cpufreq governor `aiguard`（仅显式 echo 才生效，ai_cpufreq）+ 亮度/空闲/能耗模型 Hook（ai_power） |
| `virt/` | 虚拟化 AI 化：VM Exit/内存气球/virtio 前后端感知（ai_virt/ai_virtio，vcpu_run 热路径仅 per-CPU inc + 分支） |
| `bpf/` | BPF/Tracing/Perf 协同：AI 决策挂钩 fmod_ret + `BPF_MAP_TYPE_AI_MODEL` map（模型张量驻留内核，ai_bpf/ai_map） |
| `rag/` | **用户态** RAG 知识库工具：`build_index.py` 生成 12 个接口文档 → 构建 faiss 向量索引 → `ai_rag_query()` Python 检索（供 AI 外层/知识库流程使用，不进入内核） |
| `test/` | KUnit 测试：ai_runtime/ai_policy/ai_causal/ai_telemetry 四个模块的单测 |
| `docs/` | 空目录（预留，无源码） |
| `tools/` | 空目录（预留，无源码） |

构建入口：顶层 `AIKernel/Makefile`（`obj-$(CONFIG_AIKERNEL) += core/` 等逐目录递归）；
总开关 `CONFIG_AIKERNEL` 与各子模块开关（`CONFIG_AIKERNEL_RUNTIME/TELEMETRY/NET/MM/…`）
**全部 default n**（AIKernel/Kconfig），默认配置零 .o 产物。

---

## 2. AI 主体调用链（逐环节实现状态）

设计主线：**AI 主体**（云端 OpenAI 兼容服务 / 本地模型）经
**RAG 检索**拿到接口文档语料 → 选择接口 → 通过 **sysfs / procfs / netlink**
进入内核 → 内核 A 轨 Hook/可控参数表执行。逐环节核实如下：

```
[AI 主体]
  agent/ai/shell/{main.c,shell.c,aikernel_main.c}
    └─ commands: cmd_chat/cmd_model/cmd_network/cmd_status/cmd_config/
         cmd_netlink（NETLINK_AI 直连：sense/act/reg）                     【已实现（8 命令，待编译验证）】
  agent/ai/runtime/runtime.c + runtime/communication/{communication.c,backend/}
    └─ Backend 抽象（cloud/local/lan/enterprise 路由）                   【已实现（抽象层）】
        ├─ cloud_backend.c → cloud/provider_openai_compatible.c
        │    + cloud/http/http_client.c（HTTPS，config/certs）            【已实现】
        └─ local_backend.c → local/provider_local.c + local_chat.c
             + local_http.c（OpenAI 兼容本地端点，model use local|cloud
             运行时切换）                                                【已实现（2026-09-27，待编译验证）】
  agent/ai/aikd/{aikd,aikd_lib.py}（守护进程，落盘 + 解析 /proc/ai/*）     【已实现（Python）】
[RAG 检索]
  AIKernel/rag/build_index.py
    --extract 生成接口文档 → --index 构建 faiss 索引 → ai_rag_query() 检索 【已实现并验证（2026-09-27 已真实构建索引）】
[接口文档 → 接口选择]
  13 个接口文档语料（build_index.py --extract 产物，内核树 AIKernel_Docs/）【已实现（用户态）】
[内核入口]
  (1) /sys/kernel/ai/（core/ai_sysfs.c，CONFIG_AIKERNEL_USRIFACE）
        enabled/model_load/model_unload；policy/{refresh,switch,global_enable,
        max_impact,rollback}；think（感知→决策→执行触发面，ai_sysfs.c:350）、
        outcome（结果上报，ai_sysfs.c:414）；stats/ 只读视图               【已实现（内核侧）】
        ——agent 侧目前无任何代码写 /sys/kernel/ai/*（grep agent/ai 无命中）
        → 该入口"内核就绪、外层接线未做"                                  【部分实现】
  (2) /proc/ai/（core/ai_procfs.c:499-509：status/decisions/chains/control/
        latency/hitrate/telemetry，决策日志 0400 仅特权可读）              【已实现】
        ——aikd_lib.py 读取解析 /proc/ai/decisions、/proc/ai/chains        【已实现】
  (3) NETLINK_AI 协议族（net/ai_netlink.c，CONFIG_AIKERNEL_NETLINK）
        AI_CMD_SENSE（拉取 ring 感知数据）/ AI_CMD_ACT（CAP_SYS_ADMIN 校验后
        下发决策）/ AI_CMD_REG（回调注册骨架）                            【已实现（内核侧）】
        ——用户态客户端共两处：aikd_lib.py:437（Python，仅 SENSE）；
        agent/ai/runtime/netlink/ai_netlink_client.c（C，SENSE/ACT/REG 全量，
        18 组 _Static_assert 钉扎 uapi 布局，shell 命令 netlink，待编译验证）
                                                                      【已实现（2026-09-27 接线）】
  (4) agent/ai/interface/（/dev/ai、netlink interface 预留）              【仅 Makefile，未实现】
[本地/云双模型]
  cloud：provider_openai_compatible.c + mbedTLS HTTPS                     【已实现】
  local：local/provider_local.c + local_chat.c + local_http.c（OpenAI 兼容
        本地端点，兼容 Ollama/llama.cpp/LM Studio，shell 命令 model use
        local|cloud 运行时切换，配置 [local] 段）                         【已实现（2026-09-27，待编译验证）】
[RAG 检索（已构建）]
  2026-09-27 已真实构建：AIKernel_Docs/ 13 文档 + 4 scope faiss 索引
  （docs 44k 块/interfaces 16k 块/source_code 1.73M 块/history 0），
  哈希 TF-IDF 嵌入（无语义精度限制，见 rag/README.md）                    【已实现并验证】
[内核内执行]
  ai_policy 决策执行器 → ai_control 可控参数表（mm.swappiness、sched.nice、
  sched.affinity、proc.oom_score 均真实生效，注册参数共 17 个）→ A 轨 Hook
  决策点                                                                  【已实现（4 参数真实生效；
                                                            其余参数接口预留，接线后续步骤）】
[系统调用内核侧入口]
  ai_proc_classify_hook(ai_proc.h:494)/ai_proc_*_hook 均为内核函数；不存在
  名为 ai_rag_query 的内核接口——ai_rag_query 仅是 rag/build_index.py 的
  Python 函数                                                             【已核实】
```

### 2.1 两个疑点的核实结论

| 疑点 | 结论 | 证据 |
|------|------|------|
| 内核侧 `ai_rag_query()` | **不存在于内核源码**。`ai_rag_query` 是 `AIKernel/rag/build_index.py:860` 的用户态 Python 函数（faiss 向量检索），内核 `.c/.h` 中零命中。旧文档若声称"内核侧 ai_rag_query 接口"属文档先行 | `grep -rn "ai_rag_query" AIKernel --include=*.c --include=*.h` → 0 命中；`grep -n "def ai_rag_query" rag/build_index.py` → 第 860 行 |
| agent 侧 `aikctl` 工具 | **已实现，位于 `tools/ai/`**（aikctl.c / aikctl_kernel.c / aikctl_netlink.c / aikctl.h / Makefile，NETLINK_AI 用户态控制工具，含已编译二进制 aikctl）。注：初版核实时 grep 范围只覆盖 agent/ 与 AIKernel/，漏掉了 tools/，经复查修正 | `ls tools/ai/` + `grep -rln aikctl tools/` |

---

## 3. 上游埋点对照表（为何不物理拆分）

上游共 **149 个文件**含 AIKernel 埋点引用（`grep -rln` 核实，覆盖 kernel/、
mm/、fs/、drivers/、arch/x86/entry、net/、block/、io_uring/、security/、lib/ 等），
全部通过
`#include "AIKernel/...头文件"` + 调用空实现 Hook / 遥测发射函数接入。
**上游文件一律不做物理拆分**：这些文件（如 kernel/sched/core.c 11010 行、
mm/vmscan.c 8001 行）是主线社区高频修改文件，任何行级重组都会让每一次
上游同步（git pull / 补丁移植）变成人工冲突解决——埋点必须保持"最小侵入
插入"（在既有函数体内加 1~3 行调用，或 #include 一个 AIKernel 头）。
AI 从下表"接管点"列处接管决策。

| 上游文件（行数） | 埋点函数 / 钩子 | 为什么不物理拆分 | AI 从哪里接管决策 |
|---|---|---|---|
| kernel/sched/core.c（11010） | `ai_sched_context_switch_hook` / `ai_sched_pick_next_hook` / `ai_telemetry_sched_*`（switch/wakeup/latency…） | 调度核心是主线改动最频繁文件之一；埋点为单行调用插入 | `ai_sched_pick_next_hook` 的 pick_next 决策点（空实现=原选核逻辑；AI 预测替换占位启发式） |
| mm/vmscan.c（8001） | `ai_mm_reclaim_hook` / `ai_vmscan_swappiness_get/set` / `ai_mm_emit_kswapd_wake` / `ai_mm_emit_direct_reclaim` / `ai_mm_emit_shrink_lru` / `ai_mm_emit_page_cache_evict` | 回收路径主线重构频繁（MBPF/multigen LRU 演进）；埋点保持插入式 | `ai_mm_reclaim_hook`（扫描参数建议，空实现=不修改）；`ai_vmscan_swappiness_set`（swappiness 立即生效，真实生效路径） |
| kernel/fork.c（3304） | `ai_proc_classify_hook` / `ai_telemetry_process_fork` / `ai_telemetry_process_kthread` / `ai_telemetry_ns_change` / `ai_telemetry_cgroup_attach` | copy_process 是生命周期核心，行级重组会毒化所有 fork 相关补丁 | `ai_proc_classify_hook` 返回值写入分类槽表（fork 插入；分类即调度/资源策略输入） |
| fs/exec.c（2246） | `ai_proc_exec_hook` / `ai_telemetry_exec_command` / `ai_telemetry_shell_command` / `ai_telemetry_script_exec` / `ai_telemetry_app_launch` / `ai_telemetry_user_active` 等 | exec 路径与 LSM/binfmt 交织，属于安全敏感高频修改区 | `ai_proc_exec_hook`（按新程序路径特征更新分类 + app 启动记录；AI 预测后续替换占位启发式） |
| kernel/exit.c | `ai_proc_slot_remove` / `ai_proc_slot_get` / `ai_telemetry_process_exit` / `ai_telemetry_app_lifetime` | do_exit 涉及锁顺序语义，保持最小插入 | 槽表删除时机（进程分类生命周期收口） |
| kernel/signal.c | `ai_proc_signal_hook` / `ai_telemetry_signal_generate/deliver/abnormal` / `ai_telemetry_app_crash` | `__send_signal_locked` 热路径且信号语义 delicate | `ai_proc_signal_hook` 返回 0=放行（AI 信号过滤/降权决策表预留接管点） |
| kernel/futex/waitwake.c | `ai_proc_futex_hook` / `ai_telemetry_futex_wait/wake` | futex 队列逻辑精细，行级改动风险高 | `ai_proc_futex_hook` 返回 0=原逻辑（AI 任务 futex 优先级调整预留接管点） |
| arch/x86/entry/syscall_64.c | `ai_telemetry_syscall_entry` / `ai_telemetry_syscall_exit` | 系统调用入口是全内核最热路径，汇编相邻、绝对性能敏感；采样判定（默认 1/256）已在被调函数内 | 采样命中 → 全量参数留痕；频率/序列/错误簇统计供 AI 行为建模 |
| drivers/input/input.c（2769） | `ai_proc_input_event` | input_handle_event 是所有输入设备汇聚点，逐字节热路径 | per-CPU 输入状态机（键盘序列/组合键/鼠标/触摸）驱动用户行为感知 |
| drivers/tty/n_tty.c | `ai_proc_tty_input_focus` / `ai_telemetry_tty_input` / `ai_telemetry_tty_output` | tty 缓冲路径紧贴行规程语义 | 8 槽 tty 焦点窗口表 → user_focus_window 事件（前台应用识别） |
| kernel/seccomp.c | `ai_sec_seccomp_hook` / `ai_telemetry_seccomp_filter/kill` | seccomp 过滤器检查在 syscall 热路径上 | `ai_sec_seccomp_hook` 输出 action 建议（空实现=不改判定；AI 分析进程行为后接管） |
| mm/page_alloc.c（7741） | `ai_mm_alloc_hook` / `ai_mm_emit_page_alloc/free/failure/latency` | 分配器热路径（每秒百万次），只能加分支最少的埋点 | `ai_mm_alloc_hook` 返回 migratetype（空实现=原样返回；AI 分配策略预留） |
| mm/slub.c（10164） | `ai_mm_emit_slab_alloc/free/grow/shrink/fragmentation` | slab 快路径同理 | 遥测外流（slab 碎片率 → AI 内存压力建模） |

> 拆分原则落点：上游文件零拆分；**项目自有文件**（AIKernel/ 内）按逻辑内聚
> 拆分，见第 5 节。

---

## 4. 解耦原则：三种机制

### 4.1 Hook 空实现默认放行（A 轨）

所有 AI 决策点在内核内只留**签名 + 空实现**：函数体只做
"计数 + 原样放行"（返回值不改变内核默认行为）。
例：`ai_sched_pick_next_hook` 原样返回默认选核结果；
`ai_proc_futex_hook` 返回 0；`ai_mm_reclaim_hook` 不修改扫描参数；
`ai_sec_seccomp_hook` 不改 action。AI 决策介入 = 未来把空实现替换为
"查询决策表/模型输出"，调用点（上游埋点）无需再动。
配套：每个 Hook 都有决策统计计数（`ai_*_stats`/`*_hook_calls`），
经 /proc/ai/stats、/sys/kernel/ai/stats/ 外流，供 AI 主体评估影响面。

### 4.2 A 轨 / B 轨条件编译

- **A 轨（控制轨）**：Hook + 决策框架 + 可控参数表，门控
  `CONFIG_AIKERNEL_RUNTIME`（及各子域开关 NET/MM/SCHED/…）。
- **B 轨（感知轨）**：类型化遥测发射辅助（第 1~18 类事件），门控
  `CONFIG_AIKERNEL_TELEMETRY`；发射一律"先 `ai_telemetry_sample_take()`
  采样判定 → 命中才构建 payload → `ai_telemetry_emit_direct()` 直写
  per-CPU ring（无锁 <100ns）"。
- 两轨可独立开关、独立编译：仅开 RUNTIME 时遥测代码整体不存在；仅开
  TELEMETRY 时 Hook 不存在。跨轨引用（如 `ai_telemetry_process_fork`
  读取分类槽表）在函数体内用 `#ifdef CONFIG_AIKERNEL_RUNTIME` 局部包裹
  （ai_proc_telemetry.c 内 process_fork），保证任意组合可编译。
  文件级落点：`core/ai_proc.c` 仅含 A 轨、`core/ai_proc_input.c` 等
  五个 B 轨文件整文件处于 TELEMETRY 门控内。

### 4.3 n 配置 static inline 空函数 stub

每个公共头文件对"开关=n"提供 **static inline 空函数兜底**（同一签名，
返回中性值：放行/0/AI_ERR_NOT_FOUND/false），调用点无需 #ifdef 包裹即可
编译，编译器把空函数整体优化掉 → 零开销零回归。
落点（拆分后保持原样，位于原头文件）：
- `core/ai_proc.h`：`#else /* !CONFIG_AIKERNEL_RUNTIME */` 与
  `#else /* !CONFIG_AIKERNEL_TELEMETRY */` 两段 stub（约 40 个空函数）；
- `core/ai_telemetry.h`：TELEMETRY=n 时核心 API stub 10 个
  （`ai_telemetry_emit`/`sample_take`/`emit_direct` 等）+ 16/17 类
  类型化 stub 8 个（101 个子类包装在 wrappers 中转发到 stub，整体优化掉）；
- `net/ai_net.h`：NET=n 时 stub（`ai_net_sample_take` 返回 false 等）；
- `vfs/ai_vfs.h`、`mm/ai_mm.h`、`security/ai_lsm.h` 等同模式。
- 例外说明：`net/ai_net.h` 在 n 配置下调用点本就以 `#ifdef` 剔除，
  其 stub 为防御性兜底（头文件注释自述）。

---

## 5. 项目自有长文件拆分记录（本次解耦）

拆分原则：只拆 AIKernel/ 自有文件；函数体逐字搬移；原 static 符号仅在
跨文件需要时提升为非 static 并放入模块内部头（`*_internal.h`）；
原公共头对外接口不变；Kconfig 不动；Makefile 新 .o 接在原 CONFIG 门控下。

| 原文件（行数） | 拆分后 | 拆分逻辑 |
|---|---|---|
| core/ai_proc.c（1907） | ai_proc.c 278（A 轨槽表+Hook）/ ai_proc_input.c 555（tty/键鼠/触摸/焦点）/ ai_proc_syscall.c 238（syscall 采样+模式）/ ai_proc_telemetry.c 494（exec+进程/信号/凭证/cgroup/futex）/ ai_proc_user.c 203（会话/应用/GPU）/ ai_proc_sampler.c 346（1s 采样器+init）+ ai_proc_internal.h | A/B 轨 + 事件类别内聚；共享 per-CPU（ai_payload_stage、syscall 频率/序列）经内部头 |
| core/ai_proc.h（880） | ai_proc.h 482 + ai_proc_payload.h 420 | payload 结构段拆出，ai_proc.h include 之；A 轨结构与全部函数声明/stub 留原位 |
| vfs/ai_vfs.c（1222） | ai_vfs.c 296（Hook+决策框架+采样率表）/ ai_vfs_telemetry.c 622（文件/目录/路径发射）/ ai_vfs_telemetry_fs.c 404（挂载/锁/epoll/inotify/fs_error）+ ai_vfs_internal.h | Hook 决策与发射分离；路径填充/发射计数/统计 per-CPU 经内部头共享 |
| net/ai_net.c（1141） | ai_net.c 392（A 轨核心+采样门控+字节表+init）/ ai_net_telemetry.c 589（复杂解析发射）/ ai_net_scan.c 263（HTTP/TLS 识别）+ ai_net_internal.h | 内容扫描独立成文件；sock_addr4 经内部头共享；module_param 留 ai_net.c（保 KBUILD_MODNAME=ai_net） |
| net/ai_net.h（881） | ai_net.h 623 + ai_net_payload.h 278 | 枚举+payload 结构拆出；API 与 n-stub 留原位 |
| mm/ai_mm.c（913） | ai_mm.c 232（A 轨决策框架+init）/ ai_mm_telemetry_alloc.c 316（分配/slab/缺页）/ ai_mm_telemetry_reclaim.c 430（回收/THP/OOM/错误） | 无跨文件 static 共享，无需内部头 |
| security/ai_lsm.c（862） | ai_lsm.c 500（LSM 主体：模型/规则/钩子/注册）/ ai_lsm_telemetry.c 394（第8类发射，能力名表随迁） | LSM 行为与遥测分离；无内部头 |
| core/ai_sysfs.c（670） | ai_sysfs.c 574（控制节点+init）/ ai_sysfs_stats.c 137（stats/ 只读视图）+ ai_sysfs_internal.h | 仅 ai_stats_group 一个符号提升共享 |
| core/ai_telemetry.h（837） | ai_telemetry.h 576 + ai_telemetry_wrappers.h 281 | 101 子类 static inline 包装拆出；核心 API 与 stub 留原位 |

不拆的文件：其余全部 .c ≤583 行、.h ≤648 行（阈值：.c>900 必拆、
600~900 鼓励、.h>800 必拆）。其中 core/ai_telemetry.c（583）、
sched/ai_sched.c（569）、io/ai_block.c（562）接近但未过 900 必拆线，
且单文件内聚强（如 ai_telemetry.c 的 ring buffer 读写/采样率/统计
共享同一组 per-CPU 状态），拆分会制造跨文件 static 提升，故保留。

---

## 6. 实现状态总表（快速索引）

| 能力 | 状态 | 证据 |
|---|---|---|
| 遥测 ring buffer + 采样门控 | 已实现 | core/ai_telemetry.c（583 行）、ai_telemetry.h |
| A 轨 Hook（sched/mm/net/vfs/security/proc/futex/signal/seccomp/irq/lock/time/power/virt/bpf/io） | 已实现（空实现=放行 + 计数） | 各子系统 *_hook 函数与上游埋点 |
| 决策策略引擎/决策 ring/因果链 | 已实现 | core/ai_policy.c、ai_causal.c；/proc/ai/decisions、/proc/ai/chains |
| 可控参数表 | 部分实现 | 4 参数真实生效：mm.swappiness（ai_mm.c:47 经 vmscan 访问器）、sched.nice/affinity、proc.oom_score（ai_control.c:262-338）；注册参数共 17 个，其余 apply=NULL 接口预留 |
| /sys/kernel/ai/ 控制面（think/outcome/policy/stats） | 内核已实现；agent 侧未接线 | core/ai_sysfs.c；agent/ai 无 /sys 调用 |
| /proc/ai/ 状态面 | 已实现（aikd 消费） | core/ai_procfs.c:499-509；aikd_lib.py:123 |
| NETLINK_AI（SENSE/ACT/REG） | 内核已实现；用户态客户端三处：tools/ai/aikctl（CLI）、agent/ai/runtime/netlink/ai_netlink_client.c（2026-09-27 接线，待编译验证）、aikd_lib.py（仅 SENSE） | net/ai_netlink.c；tools/ai/aikctl_netlink.c；agent/ai/shell/commands/cmd_netlink.c |
| 云端 provider（OpenAI 兼容 HTTPS） | 已实现 | agent/ai/cloud/provider_openai_compatible.c + http/http_client.c |
| 本地 provider（OpenAI 兼容本地端点） | 已实现（2026-09-27，待编译验证） | agent/ai/local/provider_local.c + local_chat.c + local_http.c；local_backend.c 重写 |
| RAG（接口文档→faiss→检索） | 已实现并验证（2026-09-27 已构建索引，哈希 TF-IDF 嵌入） | rag/build_index.py（ai_rag_query:860）、rag/embeddings/、内核树 AIKernel_Docs/ |
| aikctl CLI | 已实现 | tools/ai/aikctl{,_kernel,_netlink}.c（编译产物 tools/ai/aikctl） |
| KUnit 测试 | 已实现（4 个模块） | test/ai_{runtime,policy,causal,telemetry}_test.c |

## guest 内 W2 确认→内核执行 连体测试证据（2026-09-29）

### 测试方法

L1 AIKernel guest（内核 6.18.39 #12，qemu hostfwd 2222）内人工交互编排采用 **tmux**：
`tmux new-session -d -s w2 'AIKERNEL_TOOLS_JSON=/root/tools.json SME_URL=http://10.0.2.2:8000 HOME=/root /usr/local/bin/aikernel-shell --no-stream --session w2final 2>&1 | tee /root/w2-shell.log'`
起 REPL（提示符 `ai[qwen2.5:0%]>`），宿主侧用 `tmux send-keys` 模拟人工打字、`tmux capture-pane -p` 截屏取证。
（tmux 是必须的：linenoise 的 `\x1b[6n` 光标位置查询会干扰 expect 式编排，tmux 伪终端可正常消化。）
mock（L4 假 LLM，VM 127.0.0.1:11436 `/tmp/mock_w2c.py`）机制：消息历史无 `role=tool` 时返回工具调用
`netlink.act.sched.nice {"pid":1,"value":3}`，有则返回最终文字。

### 命令序列（y 路径）

1. `ask 把 pid 1 的 nice 调到 3` → mock 即时应答 TOOL_CALL → shell 弹出 W2 再校验界面；
2. 人工 `y` + Enter → 工具执行、audit 落行、模型第 2 轮；
3. 内核侧取证：`cat /proc/ai/control` 与测试前基线 diff、`cat /proc/ai/decisions`、`dmesg`。

### y 路径证据（确认→执行→内核生效）

W2 红色再校验界面（w2-shell.log 原文，含 ANSI 色码 `\x1b[1;31m` 粗体红）：

```
[第 1 轮] [W2 高影响操作 需要确认]
  工具: netlink.act.sched.nice
  参数: {"pid": 1, "value": 3}
  影响: NETLINK_AI ACT 下发可控参数 sched.nice：设置进程 nice 值（实时生效；data
[0]=pid data[1]=value） 注意：ACT 按 domain 广播，同域其他参数可能受影响。值域由
客户端钳制 + 内核安全边界双层兜底。
确认执行? [y/N] y
```

按 `y` 后（w2-shell.log 原文）：

```
[audit] tool=netlink.act.sched.nice channel=netlink-act args={"pid": 1, "value": 3} result=ok
  └─ netlink.act.sched.nice({"pid": 1, "value": 3}) · OK · OK: ACT 已下发 domain=1 param=sched.nice value=3 confidence=50 pid=1 | executed=4 hit=yes
```

内核侧证据（guest，测试前基线 03:24:43 vs 测试后 03:30:06）：

```
diff /proc/ai/control（基线 → y 后）:
< sched.nice domain=1 [real] min=-20 max=19 current=0 default=0
> sched.nice domain=1 [real] min=-20 max=19 current=3 default=0      ← 本次 W2 目标，真实生效
< sched.oom_score domain=1 [real] min=-1000 max=1000 current=0 default=0
> sched.oom_score domain=1 [real] min=-1000 max=1000 current=3 default=0   ← 域广播副作用（见问题2）
< sched.timeslice domain=1 [reserved] min=1 max=1000 current=20 default=20
> sched.timeslice domain=1 [reserved] min=1 max=1000 current=1 default=20  ← 变化来源未明（见问题2）

/proc/ai/decisions（新增唯一一条）:
id=1 trig_ts=3314211024018 trig_evid=0x0000 dec_ts=3314211062731 type=1 data=1:3:0:0:0:0:0:0
exec_ts=3314211651268 outcome_ts=0 outcome=2 delta=0 ver=0 conf=50 domain=1 src=0 executed=4 safety_clamped=1
```

`data=1:3` 即 domain=1 value=3，`executed=4` 与工具回显一致，内核决策链真实记录。

### n 路径证据（再校验拦截）

新开会话 `w2n`（mock 对含 tool 历史的会话恒返 FINAL，故拒绝路径须全新会话）重复同一 ask，
确认界面出现后按 `n`（w2-shell-n.log 原文，FAIL 为 `\x1b[31m` 红）：

```
确认执行? [y/N] n
  (模型请求 1 个工具调用)
  └─ netlink.act.sched.nice({"pid": 1, "value": 3}) · FAIL · ERROR: 权限分级拦截（tool=netlink.act.sched.nice risk=W2）。普通用户执行 W2 需
```

内核侧取证（按 n 后 vs 按 n 前）：

```
diff /proc/ai/control（y 后 → n 后）: NO_DIFF          ← 参数零变化
/proc/ai/decisions: 仍只有 id=1 一条                    ← 拒绝未产生新 ACT
dmesg: 无新增 act 相关行
```

**结论：再校验按 n 确实拦住了执行，内核状态分毫未动。** 但拒绝文案显示的是 policy 闸门的
"权限分级拦截（risk=W2）"而非"用户已拒绝"语义，且行尾止于"需"疑似截断（见问题4）。

### mock 证据（/tmp/mock_w2c.log 增量）

```
POST /api/show len 24
POST /api/chat len 59693
  -> TOOL_CALL stream: False          ← 第 1 轮：模型发工具调用
POST /api/chat len 59960
  JSON-ERR UnicodeDecodeError('utf-8', b'{"model":"qwen2.5:1.5b","messages":[{"role":"syste   ← 第 2 轮请求体解析失败
```

### 结论

**W2 闭环打通：guest 内 REPL 发 ask → 本地模型（mock 强制）发 W2 工具调用 → 红色 y/N 再校验 →
y 确认 → NETLINK_AI ACT 下发 → 内核真实执行（sched.nice current 0→3，decisions id=1 落账）；
n 拒绝路径内核零变化，拦截有效。** 模型第 2 轮最终文字因 L4 层编码问题未显示（见问题1），
不影响"确认→内核执行"主链路的验证结论。

### 发现的问题（仅记录，未修）

1. **第 2 轮请求体含非法 UTF-8 序列**：工具结果回传给 mock 的 POST（len 59960）触发
   `UnicodeDecodeError`（历史上 5 组同型请求 4 组失败仅 1 组成功）。连锁：mock 的 JSON-ERR 分支
   `has_tool=True` 后引用未赋值的 `body.get("stream")` 抛 NameError，连接被异常关闭（无 HTTP 响应），
   shell 侧表现为第 2 轮静默结束、无最终回复。疑似 shell 构造第 2 轮请求时 Content-Length/编码处理有误
   （工具结果含中文时高发）。
2. **ACT 域广播副作用**：sched.nice 写入时同域 `sched.oom_score` 被一并置 3（与工具描述警告一致，
   行为符合设计）；但 `[reserved]` 的 `sched.timeslice` current 也从 20 变为 1，来源未明，建议排查。
3. **ACT 执行无 dmesg 现场痕迹**：内核侧执行证据只能靠 `/proc/ai/control` 与 `/proc/ai/decisions`，
   建议在执行路径加 printk/ratelimited 日志增强可观测性。
4. **n 路径拒绝文案**：显示"权限分级拦截（tool=... risk=W2）。普通用户执行 W2 需"——是 policy 闸门
   错误而非"用户拒绝"语义，行尾疑似截断，建议区分"用户再校验拒绝"与"策略档位不足"两种文案并补全。
5. **ask 偶发 Network error**：`Error: No response from local service (timeout or connection lost)`，
   疑似 mock 异常关闭连接后 shell 复用了坏连接（keep-alive），重发即恢复。
6. **REPL 内 help 命令无响应**：tmux send-keys 场景下 `help`+Enter 后提示符原样返回、无输出。

### 证据文件清单

- guest 内 `/root/w2-e2e-evidence/`：`baseline.txt`（基线：control 全量+dmesg+sessions）、
  `w2-confirm-yprompt.txt`（y 确认界面截屏）、`w2-y-evidence.txt`（y 路径内核证据+control diff+decisions），
  `w2-confirm-nprompt.txt`（n 确认界面截屏）、`w2-n-evidence.txt`（n 路径内核证据）、
  `/root/w2-shell.log`、`/root/w2-shell-n.log`（两路 shell 全程输出，含 ANSI 色码）
- VM `~/w2-e2e-evidence/`：以上全部拉回副本 + `/tmp/mock_w2c.log` 增量记录

---

## ACT 域广播 v2 定向协议（2026-09-29，T3）

### 问题（改造前实测）

ACT 按 domain 广播：agent 设 `mm.swappiness=40` 一次下发 `executed=4`，同域
`readahead/reclaim_prio` 被同值污染（上文 T2 章节实测 sched 域同场景 `oom_score` 亦被污染为 3）。

### 设计（改动 9 文件，两树 md5 一致；备份 VM `~/t3-backup/`）

- **UAPI**：`struct ai_nl_act` 追加 `char param[24]`（88B→112B；`AI_NL_ACT_PARAM_LEN=24`、
  `AI_NL_ACT_V1_LEN=88` 兼容基准）。
- **内核**：`ai_netlink.c` 按 `nlmsg_len` 长度兼容解析（≥88 接受、≥112 才读 param、88~111 按
  v1 广播、param 强制 NUL 结尾否则 -EINVAL）；`ai_policy.c` 新增 `ai_policy_param_match()`
  （全名/末段短名匹配，param 空=广播），过滤置于域匹配之后。向后兼容：旧 88B 客户端零改动可用。
- **agent**：`ai_netlink_client.{c,h}` 断言同步 `sizeof==112`、`offsetof(param)==88`；
  `executor.c` 从注册表每工具的 `"param"` 字段单源填参（工具名剥前缀为回退路径，超长拒绝不截断）；
  `tools.json` 23 处 description 改"该操作仅定向作用于本参数"。模型侧 schema 零改动。
- 18 组 `_Static_assert` 全部同步；-Wall -Wextra 零新增警告。

### 验证（guest E2E，证据 VM `~/t3-e2e-evidence/`；L1 = bzImage #13 + agent sha256 d42f4a9d...）

1. **定向路径 PASS**：mock 强制 `netlink.act.sched.nice(pid=1,value=3)`，W2 确认 y 后
   `OK: ACT 已下发 domain=1 param=sched.nice value=3 ... executed=1 hit=yes`；
   控制表 `sched.nice 0→3`，同域 `affinity=0 / oom_score=0 / timeslice=20` 全部原值（零污染）；
   decisions `executed=1 safety_clamped=0`。
2. **广播兼容回归 PASS**（旧 88B 客户端 aikctl 未改动，作为对照组）：
   `aikctl act mm swappiness 40` → `executed=4`，`swappiness 60→40` 且
   `readahead 128→40、reclaim_prio 60→40` 被同值污染（广播语义完整保留，同时实锤 v2 定向的必要性）。
3. **布局/解析单测**（VM `~/t3-test/`，直 include 内核 UAPI 复刻解析规则）：15/15 全过
   （v1 88B→广播、v2 112B→定向、无 NUL→-EINVAL、80B 拒绝、100B 中间长度安全广播不越界、6 种匹配规则）。
4. **KUnit（记录方案）**：`CONFIG_AIKERNEL_KUNIT_TEST is not set`——套件未编入 #13，
   保留阶段 A 编译验证 + 用户态单测三态覆盖（`policy_param_target_test`）。

### 遗留与流程建议

- 如需内核内 KUnit 证据，需开启 `CONFIG_AIKERNEL_KUNIT_TEST` 重编新 bzImage。
- `ai_decision_record` 未记录 param 名（可选增强）。
- **qemu kill 时机坑（已复现）**：guest 内写文件后立即 kill qemu，page cache 未刷盘可致文件头
  清零（大小不变、Exec format error）。固化流程：guest 内 sha256 对账 + `sync` 后再关机/kill。
- **注册表加载路径钉死**：guest 环境 `AIKERNEL_TOOLS_JSON=/etc/aikernel/tools.json` 优先级最高
  （env > cwd > exe 目录），覆盖注册表需三处同步：`/etc/aikernel/tools.json`、`/root/tools.json`、
  `/usr/local/share/aikernel/`。
- `agent/ai/tools.json`（agent 根下旧格式 48 工具遗留文件）已于 2026-09-29 删除（cwd 搜索会静默误载，
  发布前审计 A3 blocker）；现行注册表是 `agent/ai/tools/tools.json`（69 工具新格式）。

---

## T1 清理 + T2fix 七问题修复 + 发布前审计（2026-09-29）

### T1 清理（主控执行，两树同步）

- VM /tmp 删 15 个测试驱动/日志（保留 `mock_w2c.py`/`.log`）；Git Bash /tmp 删 15 个旧脚本
  （保留 `mock_w2c_v3.py` 权威源）。
- `Build_Output/Kernel/bzImage_verified_AIKERNEL-y` + config 已删（过时基线）；
  `bzImage_prompt15_y` + config 归档至 `AIKernel_MD文档库/99_Archive/kernel-baselines/`。
- `agent/ai/build/` 13 个空目录已删；`_fix_tmp/` 已清除（其 http_client.c 9/28 工作稿归档）。
- 死代码 `communication_status()` 已删（communication.{c,h}，全库无调用方且文案过时）。
- **保留**：`tools/ai/aikctl`（88B 旧客户端，T3 兼容对照组）；`openai_stream`/`local_stream` 桩
  （已注册能力桩，删则空指针，归 T4 真实现云流式时一并处理）。

### T2fix 七问题修复（L1 = bzImage #15 + agent sha256 a528a7b9...；证据 VM ~/t2fix-evidence/ 14 文件）

1. **中文工具结果非法 UTF-8（根因修正）**：不是 Content-Length（local_http 一直按 strlen 字节且
   Connection: close），而是 `TOOL_EXEC_OUT_MAX` 等定长字节截断把多字节 UTF-8 切成半截。新增
   `ai_json_utf8_floor`（截断点回退）+ `ai_json_utf8_sanitize`（非法字节→U+FFFD）出口防线，
   接入 ai_json_escape 与 executor/cmd_ask 全部截断点；回归 17/17，guest 5 轮中文 ask 零 JSON-ERR。
2. **n 拒绝文案**：新增 `ai_policy_gate_reason`（区分用户拒绝/策略拒绝）；截断根因是折叠卡片
   `first[96]` 按字节截断，接 floor+'…'。实测：`已按您的选择（n）拒绝执行：netlink.act.sched.nice`。
3. **ask 偶发 Network error**：`local_http_post` 连接级失败（send 失败/空响应）关坏连接重建重试一次；
   test_http_retry PASS（首轮 accept 后 close、次轮 200）。
4. **REPL help 无响应**：管道下 stdout 全缓冲（linenoise 走 stderr 所以提示符正常）→
   启动时 `setvbuf(stdout, NULL, _IOLBF, 0)`。
5. **ACT 执行 dmesg 痕迹**：ai_policy.c 执行后 `pr_info_ratelimited`（动作/domain/param/data/
   executed/failed，匹配过滤之后）。实测：`AIKernel: policy act 'sched.nice' domain=1
   param='sched.nice' data0=1 data1=3 executed=1 failed=0`。
6. **timeslice 20→1 根因（已修）**：v1 广播 `decision_data[0]` 二义性——TASK 参数解释为 pid、
   全局参数解释为值，mock 广播 `{"pid":1,"value":3}` 时 reserved 的 timeslice 把 pid=1 当值写入
   （恰在硬范围 [1,1000] 内合法通过）。修复：广播(param 空)+非 REAL 参数返回 AI_ERR_NOT_FOUND 跳过；
   实测 88B 广播后 timeslice 保持 20，dmesg `executed=3 failed=1 (handler fail)`。
7. **假状态横幅**：`/proc/aikernel` 删除无依据的 "Cloud Provider: Ready"（provider 配置在用户态，
   内核无从验证），改为 "Agent Providers: managed by aikernel-shell"；启动横幅按实际配置输出
   `Configured (端点/模型)` 或 `Not configured`，零网络探测。

### 发布前审计（只读，报告独立成文）

`AIKernel_MD文档库/AIKernel_发布前审计_未实现与虚标清单_20260929.md`：
A 类 Blocker 4 条 / B 类缺口 7 条 / C 类设计预留 9 条（内核 80 个 ai_*_hook 空挂接点清点、
16 个 reserved 参数名单、agent Kconfig 开关虚设等），含宣传口径红线（能说/不能说清单）。

---

## 发布前虚标清零会战（2026-09-29 深夜，三波）

用户指令："全部把工具接好，不能是虚假的"。三波完成：第一波双线并行（内核侧 reserved 参数
real 化 / agent 侧桩清零），第二波 guest 集成 E2E，主控补修 proc.* 注册表缺陷。

### 第一波 K（内核侧）：15/16 reserved→real，L1 = bzImage #26

16 个 reserved 参数 **15 个 real 化**（每个均为 control current + 内核真实状态双证据；
证据 VM `~/w1k-evidence/`，备份 `~/w1k-backup/`）：

| 参数 | 真实机制（摘要） |
|---|---|
| proc.signal | send_sig_info 真投递（kthread/init 拒绝）；SIGTERM 实测进程真死 |
| proc.freeze | SIGSTOP/SIGCONT 冻结解冻；ps 状态 T↔S |
| proc.rlimit | data[2]=资源号 + kernel/sys.c `ai_sys_prlimit_set`（prlimit64 语义仅改 cur）；NOFILE 1024→2048 实测 |
| mm.readahead | backing-dev.c 访问器写全部 bdi ra_pages（readahead_kb 同源） |
| mm.reclaim_prio | 映射 vfs_cache_pressure（dcache.c 访问器） |
| sched.timeslice | EEVDF base_slice 映射（value 单位 0.1ms） |
| net.cwnd | ai_cca 拥塞避免出口+ssthresh 钳制；128MB 回环传输 clamp_hits 0→1022 |
| net.nftables | AIKernel 自有 netfilter LOCAL_OUT 采集钩子（真注册/真计数），如实语义 |
| io.bandwidth | bdi max_ratio 写回带宽比（0=恢复默认） |
| sec.lsm_override | AIKernel 自家 LSM enforce/observe 档位 |
| sec.seccomp | TASK 基线收紧=ai_lsm deny 规则注入/解除（如实语义，非 seccomp BPF） |
| sec.audit | ai_audit 采集真开关（关后 gate 直接丢弃） |
| power.freq | aiguard 频率上限万分比（get_next_freq 真实钳制；QEMU 无 cpufreq 如实标注） |
| power.cstate | PM QoS cpu_dma_latency（/dev/cpu_dma_latency 同源） |
| power.wakeup | sched_wakeup tracepoint 探针采集门控 |

**唯一诚实保留 reserved：net.qdisc**——dev_graft_qdisc 在策略执行上下文实测冻结网络栈
（代码级+运行级证据），无安全实现路径；如需真 graft 须独立内核线程+mq 设备守卫。
**最终控制表：22 real + 1 reserved。**

独立项：
- **model_load 真推理（审计 B2 销账）**：新 `AIKernel/core/ai_model_mlp.c`——AIKWMDL v1
  格式（magic+层数+维度+float32 权重），Q31 定点 MLP 前向（内核禁浮点），echo 推理彻底删除；
  `/sys/kernel/ai/model_infer`+`model_out` 推理面；内核输出与 Q31 逐位模拟 **bit-exact**、
  与 float64 参考误差 0.0。模型生成器 `gen_model.py`（8→16→4 ReLU，884B）。
- **KUnit 编入**：CONFIG_AIKERNEL_KUNIT_TEST=y，5 suite **29/29 全绿**
  （ai_runtime 4/ai_telemetry 6/ai_policy 8/ai_control 9/ai_causal 2，TAP 证据齐全）。
- **SENSE 指定 CPU 回归 PASS**：cpu=0/1 各回 8/32 条真实遥测（修复前恒 0）。

改动 33 文件（含 host 侧最小侵入：kernel/sys.c、kernel/sched/fair.c、mm/backing-dev.c、
fs/dcache.c、net/sched/sch_fq.c 去 static+EXPORT），两树 md5 一致。

### 第一波 A（agent 侧）：10 项桩/虚标清零 + 附带修 4 个真崩溃 bug

证据 VM `~/w1a-evidence/`，改动 30 文件两树一致：
1. **云通道真·增量流式（审计 A1 销账）**：http_client 新增 `https_post_stream`（chunked
   增量解码状态机），cloud_backend→openai_stream 全链真流式；实测 token 时间戳跨度 199.7ms
   递增到达（整体缓冲会 ≈0ms）；CAP_STREAM 名副其实。
2. **Kconfig 三开关真接线（审计 A4 销账）**：Makefile 读 .config 条件编译 + 10 处 #ifdef；
   nm 矩阵证明 LOCAL/STREAM/CLOUD 单关时对应符号清零，全开功能完好。
3. provider_local 死桩删除，ops.stream 转调真实现（无双轨）。
4. interface/ 空壳诚实移除（含 Kbuild/Kconfig 行）。
5. chat 重写为 ask 薄封装别名（行为差异清零）。
6. config set 持久化闭环（原子写 tmp+rename，7 键全覆盖，未知键显式报错）。
7. compact 实测通过（8 行 1256B→1 行 414B 含摘要；修复压缩后 token 预算虚报）。
8. Tab 补全（linenoise completion callback：命令名+config set 键名）。
9. Ctrl+O 折叠切换（linenoise key-hook 最小扩展，`|V` 标记即时反馈，verbose 联动）。
10. executor.h 注释如实化 / ai_user_policy.c NUL 字节修复（policy 自测 21/21 零警告）/
    status 显示 Channels (compiled in) 如实编译态。

附带修复 4 个真 bug：①**policy 层静态链接 NSS 调用 SIGSEGV**（getgrouplist→libnss_systemd，
改为解析 /etc/passwd+/etc/group——修复前 ask 工具闸门在静态链接下必崩）；②ai_json_utf8_sanitize
贴边跨页写；③local_stream 失败回退 double-free；④NUL 字节（同 10）。

### 第二波集成（W2I）：guest E2E 8 项全 PASS

证据 VM `~/w2i-evidence/`（01-10 + tools/）：tools.json 8 条文案落地（请求体抓取验证）、
新 agent 部署、W2 y/n、六通道真调用（procfs/sysfs/netlink-sense 128 条/exec/memory.hit）、
6 个新 real 参数双证据、model_load bit-exact、流式两通道（native+OpenAI 兼容）逐段增长、
终端功能（Tab/Ctrl+O/chat 别名/config 持久化/status 如实）、KUnit TAP 补证 29 用例全绿。

### 主控补修：proc.* 注册表缺陷（发现于 W2I）

W2I 揪出：`gen_registry.py` 把 proc.signal/proc.freeze 标 `task=False`（schema 无 pid 属性，
模型调用丢 pid 空转）；且 proc.* 等 10 个已 real 化参数的描述仍是"接口预留"过期文案。主控修复：
- task 标志 False→True（signal/freeze/rlimit 三个 TASK 参数 schema 均带必填 pid）。
- **proc.rlimit 第三槽支持**：schema 增必填 `res`（资源号，缺省 7=NOFILE），
  executor 按 `data[2]` 填充（内核 ai_proc_rlimit_apply_ex 布局）。
- 10 处过期"接口预留"描述全部改为真实机制描述。
- 重生成注册表（69 工具不变）→ 重编 agent（sha256 c39398a4）→ guest 部署 + 注册表三处同步
  （/etc/aikernel、/root、/usr/local/share/aikernel，sha256 一致）。
- **受控冒烟全 PASS**（参数化 mock 精准注入工具调用，证据 VM `~/w2fix3-evidence/`）：
  - proc.signal：`{pid:687,value:15}` → y → 进程真死 + dmesg `data0=687 data1=15 executed=1`。
  - proc.rlimit：`{pid:806,value:2048,res:7}` → y → `/proc/806/limits` NOFILE 1024→**2048**。
  - proc.freeze：抬 max_impact_pct=100 后 `{pid:1330,value:1}` → 状态 S→**T**；
    `{value:0}` → T→**S**（默认 50 档会钳制 [0..1] 翻转，为文档化设计行为）。

### 发布态口径（更新）

- 可说：**22/23 可控参数真实生效**（唯一例外 net.qdisc 有代码级不可行证据且描述如实）、
  69 工具注册表全通道可用、云/本地双通道真增量流式、KUnit 29 用例内核内自证、
  模型下发真实推理（Q31 bit-exact）、W2 再校验、80 个决策挂点预埋。
- 仍不可说："AI 接管调度/OOM 决策"（决策=确定性启发式+挂点预留）；power.freq 在 QEMU 内
  无 cpufreq 可观测（实机即生效）；80 个 ai_*_hook 中 77 个为空挂接点（设计预留，非缺陷）。

---

## W3 决策挂点通电（2026-09-29 深夜，bzImage #27）

用户指令："先做一个开关默认关闭，把功能完善；后续有数据/模型后经同一接口接上"。

### 架构：决策源接口化 + 三层开关 + 硬钳制 + 异常回退 + 全量记账

- **决策源接口**（`AIKernel/core/ai_decision.{h,c}`，第二阶段模型接入点）：
  `ai_decision_query(hook, ctx)` 现实现为启发式 v1（读 per-task 分类槽，争用/越界一律回退 0
  并计 fallback）；**第二阶段模型决策只需 `ai_decision_set_source(推理函数)` 注入**，
  消费挂点/开关/钳制/记账零改动。越界返回值被查询层按编译期常量 clamp。
- **开关三层（默认全关，关=与原生内核行为一致）**：全局 `/sys/kernel/ai/decision_inject`；
  每挂点 `/sys/kernel/ai/decision/{oom_badness,sched_vruntime,sched_wakeup,readahead,reclaim}`；
  值域编译期硬钳制（OOM ±200 / vruntime ±100‰ / 抢占布尔 / 预读 ±1 档 / 扫描优先级 ±1）。
- **记账**：`/sys/kernel/ai/decision/stats`（queries/injected/effects/fallback/ring/last_bias
  每挂点）+ `/proc/ai/decisions` ring（src=4 启发式，1s 节流）。

### 五个挂点（关/开/关三段证据全闭环，证据 VM `~/w3k-evidence/`）

| 挂点 | 决策语义 | 实测效果 |
|---|---|---|
| OOM 评分偏置 | 交互式 badness −200 / 批处理 +200 | 同尺寸两 hog 关=逐位相等；开=∓134 显示值；**真 OOM 受害者翻转**（ssh_hog→gzip_hog→ssh_hog 三段） |
| vruntime 加权 | 交互式减免/批处理推迟 ±100‰·\|v−V\|，永不跨越加权均值 | 批处理独占下交互 sleeper 唤醒等待 **−21%**（670→529ms），复关回落 |
| 唤醒抢占提示 | 交互式 wakee 取消批处理 curr 片保护 | 生效 11,717 次，与上项合并收益 |
| 预读窗口 | 交互 ×2 / 批 ÷2（钳 1 档） | effects 0→22，ring `8→16`/`8→4` |
| 回收扫描优先级 | priority ±1 即刻还原 | 批处理风暴 5,558 次生效；交互 +1 在 DEF_PRIORITY 上限被钳（钳制语义诚实生效） |

### ACT 参数与注册表（AI 打开自己的大脑开关）

4 个 REAL ACT 参数注册（`ai_decision.c:312-318`）：`ai.decision_inject`(域5) /
`ai.decision_oom`(域2) / `ai.decision_sched`(域1) / `ai.decision_mm`(域2)，全 0/1 默认 0，
控制表 **26 real + 1 reserved**。注册表已扩到 **74 工具**（gen_registry + 生成，两树 md5 一致，
guest 三处 sha256 9a6a7b9e 一致）。受控冒烟 PASS：mock 注入 `netlink.act.ai.decision_inject
{value:1}` → W2 y → sysfs 翻 1 + dmesg `policy act 'ai.decision_inject' ... executed=1`
（抬 max_impact_pct 流程后还原）。

### 内核与测试

bzImage #27（运行时横幅 #28=compile.h 计数差 1 既有行为）；KUnit **6 套件 37/37 全绿**
（新增 ai_decision 8 用例：钳制/开关门控/源注入等）。改动 14 文件两树一致，host 侧仅
oom_kill.c/fair.c/vmscan.c 三处最小侵入（readahead 零 host 改动）。

### 口径更新（W3 后）

- 新可说：**"5 个内核决策挂点已通电——AI 可经自己的工具开启（默认关），真实影响 OOM 受害者
  选择、调度公平性与内存回收；决策接口已留好，模型训练好后经 `ai_decision_set_source()` 即插
  即用"**。
- 仍不可说："AI 接管调度/OOM 决策"——决策现为启发式 v1（确定性、可审计），模型决策属第二阶段
  （采集→训练→离线验证→set_source 注入）。

---

## 成品交付：SME 统一检索 + 内核稳定化 + ISO 安装盘（2026-10-01，W7 三线）

### W7S · SME 统一检索闭环（P1，替代 RAG）

- **RAG 整体移除**（用户决策：SME 通用记忆插件即检索层，砍掉 TF-IDF 半成品）：
  两树 AIKernel/rag/ 删除、agent rag 命令与白名单清理、GitHub 同步（b29ce18）。
- **SME 新版 API（v1.3.0+）核验**：agent sme_client 13 端点零失配；新增 /memories/batch
  用于灌入（搜索请求体字段为 text）。
- **接口语料 154 条入库**：74 工具全 schema + 27 参数（含 4 个 ai.decision_*）+ docs/02 参考
  + 6 条高频问答，tag=aikernel-interface；喂料脚本 `w7s_gen_corpus.py`。
- **RAG 遗留大清理**：基线 18250 条中 18239 条 RAG 时代 chunk 归档（可恢复不删），
  **活记忆收敛到 165 条高密度语料**；裸检索验收 top1 双命中（"怎么调进程优先级"→0.78
  问答条目）。
- **检索引导**：memory.search description + ask/onboarding 行为准则（"接口类问题先查再答"）；
  **ask prompt 压缩 13758→4568 token**（tools schema 压缩，1.5b 方差显著降低）。
- **AI 驱动 shell 跳转（方案 A）**：sys.shell 工具（AI 应请求降入 bash，istty 保护+
  "AI 应请求开启 shell"审计）；REPL 直敲路径保留。**tty2 暗门**：getty@tty2 密码登录
  （灾备，宣传口径不提）。
- **闭环验证**：链路每一环独立实证——模型自主调 memory.search（capture）、自主选
  netlink.act.sched.nice 触发 W2（audit `result=CONFIRM=yes`）、内核真实生效
  （pid 1 nice 0→10，decisions_total 0→1）；audit 历史含 09-29 完整参数闭环 4 次铁证。
  1.5b 当日完整参数闭环 0/12 为模型能力上限（换 7b+/云端预期显著改善，schema 已压缩到位）。

### W7K · 内核稳定化（P2，bzImage #32）

- **Bug1 kswapd shrink_folio_list NULL deref**：根因修复；10 分钟 grow 风暴压测
  （swapcache 匿名页回收崩溃路径全打击，pswpout +488070）零 Oops（修复前可复现）。
- **Bug2 用户进程启动期布局敏感 SIGSEGV**：判定**外部因素（构建链），内核无责**——
  证据链：ai_zone 无 memblock 挂接不改内存 map、熵源挂点纯遥测、exec 路径全在成功后；
  未垫探针二进制 #32 上 5 次冷启动 rc=0 零 Oops（垫探针保留为构建期保险）。
- 回归全绿：KUnit 6 套件 37/37；rootfs 副本完整启动（26 real+1 reserved）；
  W3 决策挂点零回归（reclaim 挂点恰在 Bug1 崩溃路径上满负荷工作）。
- 版本行：`#32 SMP PREEMPT_DYNAMIC Thu Oct 1 02:38:14 CST 2026`；两树同步。

### W7I · ISO 安装盘交付（P3）

- **出厂态修正**（S 线演示态→真机自含）：ollama.service / aikernel-memory.service 恢复
  enable、model.toml 回 127.0.0.1:11434、SME_URL 回 127.0.0.1:8000、
  **SME 首启种子三件套**（sme-seed.jsonl 154 条 + 幂等 sme-seed.sh + sme-seed.service），
  新机器首启自动获得接口语料；计划外修复：S 线演示 SME 数据库混入出厂 rootfs，返工重打。
- **终装 E2E 全过**（全新 qcow2）：安装（一次 y/N，30 秒）→ 从盘 GRUB 引导 → 三服务自启
  → autologin 直进 AI 终端 → onboarding（AI 生成欢迎词→强制设密→选本地）→ `ai[...]>`
  → sme-seed `added:154` + memory.search 命中接口语料（**"AI 了如指掌"在新装机器成立**）。
- **交付物**：`C:\Users\黄小乐\Desktop\AIKernel_rescue\AIKernel-0.1.0-alpha-x86_64.iso`
  （1.94 GiB，md5 `ffb23d3d...` 双侧一致，内核 #32）。
- 遗留：EFI/UEFI 引导未做（BIOS/MBR 单路径）；TCG 下完整 ask 分钟级不可行（真机原生速度
  无此约束），演示用 onboarding/短对话。

### 发布口径（W7 后）

- 可说：**"纯 AI 终端系统：开机第一眼是 AI 控制台，AI 对话完成初始化与一切操作（含进入
  传统 shell），自带系统记忆检索（自然语言查接口即执行），27 参数 26 真实生效，W2 二次
  校验，KUnit 37 用例内核自证；ISO 安装盘装机即用（内置 ollama+模型+接口语料种子）"**。
- 仍不说："AI 接管调度/OOM 决策"（启发式 v1）；"语义检索"（SME 检索能力随插件演进）；
  EFI 引导；1.5b 工具闭环成功率（演示建议 onboarding/短对话或更强模型）。

---

## W10 成品化双线：启动崩溃元凶定案 + 运维四件套（2026-10-02，ISO v1.2）

### W10-B · 清理执行 + TLS 真校验 + 启动崩溃元凶定案

- **死代码执行删除（4 项实锤）**：tls_manager/cert_manager 死模块、sch_fq `fq_qdisc_ops`
  恢复 static（EXPORT 零调用方）、8KB 布局垫（nm 实证从未进二进制）。agent clean 重建
  **gcc 警告 0**（存量 3 条一并清零：write 返回值 2 处修复）。
- **W=1 全绿**：ai_causal.c format-truncation 根修（含栈上 day[16]→[24] 调用点）+
  ai_startup.c 分段拼接同性质修复；`make W=1 AIKernel/` 零 error 零警告。
- **TLS 真校验（安全关键）**：`tls_conf_verify()` 加载系统 CA 包
  `/etc/ssl/certs/ca-certificates.crt` + VERIFY_REQUIRED，https 无降级开关；四场景验证：
  明文 http 正常 / https 打明文端点拒绝 / 自签证书报 "CN mismatch / not signed by trusted
  CA" / **真网 `https://api.github.com` 系统 CA 校验通过**。顺手修两个接云必踩 bug：
  分段 body 单次 read 丢失、非 chunked 响应被 strip_chunked 清空。
- **启动 SIGSEGV 元凶定案（修正 W7K"构建链外部因素"结论）**：Ubuntu 22.04
  **ld.bfd 2.38 链接器 bug**——init-first.o 的 `__libc_argc/__libc_argv/__environ` 三处
  PC32 重定位编码为真实地址-0x20（argc 写进 `_dl_platform` → `_dl_non_dynamic_init`
  解引用崩溃）。修复：Makefile `LDFLAGS := -fuse-ld=gold`，clean 重建 5/5 rc=0。
  8KB 垫悬案终结（从未生效 + 不再需要）。
- 仓库卫生：tests ELF 移出跟踪（~1.1MB）、pyc/tools_report 忽略、w6i-tools 收敛 GitHub
  单一权威、文档口径 73→74 统一；GitHub `378397b..f5027b4`（5 组提交）；两树 8 核心文件
  md5 三方（VM=Windows=GitHub）一致。

### W10-A · 运维四件套进出厂 + ISO v1.2（内核 #35）

- **四件套**（systemd 正道 + 出厂 rootfs 固化）：①sshd——ssh-keygen.service 首启再生
  host key + PasswordAuthentication yes（onboarding 强制设的密码即 ssh 密码，设计闭环），
  E2E 实测密码登录成功；②systemd-timesyncd + 阿里云 NTP，`timedatectl` 真同步成功；
  ③journald Storage=persistent + 200M 上限，跨重启 `journalctl --boot=-1` 可读；④nftables
  基线（input drop，放行 lo/established/icmp/ssh22）+ **11434/8000 出厂即绑 127.0.0.1**
  零暴露面。附加：unattended-upgrades（仅 security 源）、/root/README.md 产品一页。
- **计划外修复两阻断**：装出的系统原本无 DHCP 客户端（networkd 未启用）→ networkd +
  80-wired.network 补齐；dbus 单元文件全丢 → 重装。无此二补 ssh/NTP 全不可达。
- **AI 接入三件套**：exec 白名单 47→49（nft=W2、timedatectl=R，单源重生成 diff 干净）；
  SME 语料 154→157（防火墙/日志/时间三条，裸检索 top1 命中）；行为准则确认覆盖。
- **内核 #35**：#34 全部驱动 + NF_TABLES_INET/IPV4/IPV6 + NFT_CT（防火墙地基；
  NAT/LIMIT/LOG 类细控仍需下波补内核选项）。ISO v1.2：1.77GiB（apt 索引出厂即清，比
  v1.1 小），md5 `40d9cc00...` 双侧一致。
- 遗留：完整 ask 闭环 TCG 下不可演示（20 分钟/轮，真机或云端模型无此约束）；出厂 SME
  快照与 seed 解耦（P3-3）；UEFI 未做。

### 口径（W10 后）

运维四件套落地后，系统具备"可挂机"基线（远程 ssh / NTP 真同步 / 日志可回溯 / 防火墙
默认 drop + 安全自动更新）；完整 ask 闭环的演示依赖云端模型或 7b+ 本地模型（1.5b+TCG
为已知天花板，非代码缺陷）。
