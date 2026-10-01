# AIKernel — AI 主体接管 Linux 的控制系统

> 版本：0.1.0-alpha（2026-09-30 快照）
> 源码包：`AIKernel-src-6.18.39-20260930.tar.gz`（本文件同目录）

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
- **agent 用户态控制台**（aikernel-shell，C 静态链接）：REPL + ask 工具闭环（74 工具注册表，
  五通道：netlink/procfs/sysfs/exec/memory）、W2 危险操作 y/N 再校验、权限分级、会话持久化、
  本地/云端双通道真增量流式、AI onboarding 首启引导、维护 shell 逃生口。
- **发行形态**：ISO 安装盘（GRUB → 安装器 → 内置 Ollama + qwen2.5:1.5b，装完离线即用）。

## 从哪里开始读

- `AIKernel/ARCHITECTURE.md` — 架构、实现状态、全部验证证据链（本仓库最权威文档）
- `agent/ai/tools/tools.json` — 74 工具注册表（能力清单）
- `agent/ai/` — 用户态控制台源码；`AIKernel/` — 内核侧源码

## 构建与验证

详见 `AIKernel/ARCHITECTURE.md` 头部与各章节（内核 config、bzImage 构建、guest E2E 证据、
KUnit 运行方式）。
