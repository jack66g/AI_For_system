# AIKernel — AI 主体接管 Linux 的控制系统

> 版本：0.1.0-alpha.5 / v1.5（2026-10-03 快照）

## v1.5 发行说明（2026-10-03）

- **发行物**：`AIKernel-0.1.0-alpha.5-x86_64.iso`（1.90GB，md5 `64407bb510976e6ccd1195f0e15c9d08`，内核 #37），BIOS+UEFI 双引导装机即用。
- **SME 路由架构（本版核心新特性）**：75 工具不再全量进请求，改为 SME 空间记忆检索驱动的动态激活——会话级默认激活 5 工具，检索命中经 `router_activate_from_sme` 扩入请求 tools 数组；云端 autonomous（目录页+检索指引，模型自主 memory_search）/ 本地 pre_retrieve（框架预检索 top5）双驱动。请求 tools 数组 15584B→1004B（-94%），system 10922B→5016B（-54%）。效果：云端 12 题 **12/12**（基线 7/12），本地 qwen2.5:1.5b prompt_eval **8681→1437 tokens（-82.5%）**，keep=4 截断消失，接口语料 75/75 覆盖（首启种子 193 条）。
- **75 工具全下划线名**（如 `netlink_act_sched_nice`）：点号名违反主流 API 工具名规范触发云端 400；内核域名字符串作为工具 schema 的 `param` 字段显式映射保留。注册表单源 `agent/ai/tools/gen_registry.py`，同时生成 `tools.json` 与目录页 `tool_catalog.txt`（3614B）。
- **TLS 根因修正（勘误）**：此前"mbedTLS 握手失败"系误诊；真根因是 `http_client.c` 未处理 `mbedtls_ssl_write` 部分写（>16384B 请求静默截断后返回正数），已修 `write_all_tls`/`write_all_plain` 六发送点；`VERIFY_REQUIRED` 证书校验无降级保持。
- **agent 修复**（摘要）：会话序列化拼接协议（孤儿 tool_calls 400 根因）、并行 tool_calls 响应组语义、十连发排队 10/10、4KB 输入、历史裁剪预算制（工具对不拆散）、num_predict 1024 可配置、工具结果 64KB 截断+30s 超时、轮数上限 8、W2 非终端通道（`--yes`/`AIKERNEL_ASSUME_YES`/结构化 NEED_CONFIRM）、SSE streaming、exec_run input 参数（tee 写文件配方）。
- **完善度口径**：上轮终评 6.8/10，本版建议按 **7.5~8/10** 理解——云端体验到位，本地受 1.5b 模型物理上限；决策仍为启发式 v1（"AI 接管调度/OOM 决策"不可说），检索为 SME 空间记忆检索。详见 `AIKernel/ARCHITECTURE.md` 末章。

## 来源标注（上传 GitHub 时请保留本节）

- **基础内核**：[Linux Kernel 6.18.39](https://www.kernel.org/)，版权归 Linus Torvalds 与
  Linux 内核社区所有，依 **GPL-2.0** 授权。本仓库中的所有改动延续 GPL-2.0。
- **AIKernel 子系统**（`linux-6.18.39/AIKernel/`，17 个内核子目录：core/sched/mm/net/vfs/
  io/security/interrupt/lock/time/power/virt/bpf/test 等）与 **agent 用户态 AI 控制台**
  （`linux-6.18.39/agent/`）为原创代码，GPL-2.0，文件头含 SPDX 标识。
- 对上游内核的修改均为**最小侵入**（条件 include + 访问器 + 挂接点），主要落点：
  `mm/vmscan.c`、`mm/oom_kill.c`、`mm/backing-dev.c`、`mm/readahead.c`、`fs/dcache.c`、
  `kernel/sched/fair.c`、`kernel/sys.c`、`net/sched/sch_fq.c`（可全库 grep `ai_` 定位）。

## 这是什么

AI 作为主体、Linux 内核作为被管理对象的控制系统：

- **AIKernel 内核侧**：感知-决策-执行承接层。27 个可控参数（26 真实生效）、NETLINK_AI(31)
  协议（SENSE/ACT/REG，v2 支持按参数名定向下发）、/proc/ai/* 与 /sys/kernel/ai/* 全量面、
  5 个已通电的 AI 决策挂点（OOM 评分偏置/vruntime 加权/唤醒抢占/预读/回收优先级，
  默认关、可由 AI 经工具开启）、决策源接口化（`ai_decision_set_source()` 预留模型接入）、
  模型下发真推理（Q31 定点 MLP）、内核内 KUnit 37 用例。
- **agent 用户态控制台**（aikernel-shell，C 静态链接）：REPL + ask 工具闭环（**75 工具**
  注册表，五通道：netlink/procfs/sysfs/exec/memory）、W2 危险操作 y/N 再校验、权限分级、
  会话持久化、本地/云端双通道真增量流式、AI onboarding 首启引导、维护 shell 逃生口。
- **出厂系统**：内置 Ollama + qwen2.5:1.5b 本地 AI 栈、SME 记忆引擎（首启语料种子幂等导入）、
  健康自愈定时器（aikernel-health，5min 一轮）、远程 AI API（127.0.0.1:8761，Bearer token
  安装时随机生成）、nftables 基线防火墙、networkd/timesyncd/journald 出厂配置——
  全部清单见 [`factory/README.md`](factory/README.md)。
- **发行形态**：ISO 安装盘（GRUB → 安装器 → 装完离线即用）。
  **v1.4（0.1.0-alpha.4）起支持 BIOS + UEFI 双引导**：安装器对目标盘做 ESP FAT32 512M +
  ext4 根双分区，grub-install 双跑（i386-pc 到 MBR + x86_64-efi 到 ESP，含
  `\EFI\BOOT\BOOTX64.EFI` fallback，无 NVRAM 场景 OVMF 亦可引导）。

## 从哪里开始读

- `AIKernel/ARCHITECTURE.md` — 架构、实现状态、全部验证证据链（本仓库最权威文档）
- `agent/ai/tools/tools.json` — 75 工具注册表（能力清单）
- `agent/ai/` — 用户态控制台源码；`AIKernel/` — 内核侧源码
- `factory/` — 出厂系统资产（systemd 单元、本地 AI 栈、健康自愈、API、种子语料）
- `w6i-tools/` — ISO 打包线（initrd/init 安装器、build-iso.sh、双引导 grub 配置）

## 构建与验证

详见 `AIKernel/ARCHITECTURE.md` 头部与各章节（内核 config、bzImage 构建、guest E2E 证据、
KUnit 运行方式）。
