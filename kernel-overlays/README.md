# kernel-overlays — AIKernel 对上游 Linux 内核的修改文件

本目录保存 AIKernel 对**干净上游内核 linux-6.18.39** 的全部修改文件，保持与内核源码树相同的相对路径。

## 用法

1. 从 https://cdn.kernel.org/pub/linux/kernel/v6.x/ 下载 `linux-6.18.39.tar.xz` 并解压；
2. 将本目录下的所有文件按相对路径覆盖到内核树中（例如 `kernel-overlays/mm/vmscan.c` → `linux-6.18.39/mm/vmscan.c`）；
3. 将仓库根目录的 `.config` 复制为内核树根的 `.config`；
4. 正常 `make` 即可编译出带 AIKernel 子系统的内核。

## 修改文件清单（每个文件用 `grep -n "ai_" <file>` 可定位全部改动点）

| 文件 | 改动原因 |
|------|----------|
| `mm/vmscan.c` | LRU 回收优先级挂点：按 AI 策略对 shrink_lruvec 的扫描优先级 ±1 微调（W3 决策挂点之一） |
| `mm/oom_kill.c` | OOM 评分偏置：oom_badness 按交互/批处理分类注入 ±200 oom_score 量纲偏置，实现受控的受害者翻转 |
| `mm/backing-dev.c` | 回写阻塞设备跟踪：为 AI 内存子系统暴露 backing device 状态查询接口 |
| `mm/readahead.c` | 页面预读挂点：按 AI 策略对 readahead 窗口 ×2/÷2 一档动态调整 |
| `fs/dcache.c` | dentry 缓存挂点：AI 内存子系统对 dcache 回收的观测与优先级控制 |
| `kernel/sched/fair.c` | CFS 调度挂点：vruntime 加权（±100‰，永不跨越加权均值）、唤醒抢占提示、place_entity 决策注入（交互唤醒等待实测 -21%） |
| `kernel/sys.c` | 系统调用入口挂点：AI 策略对进程分类信息的获取入口 |
| `net/sched/sch_fq.c` | FQ 网络调度挂点：AI 策略对网络包调度流的优先级干预预留 |
| `include/linux/ai_accessors.h` | 新增文件：AIKernel 内核侧统一访问器（AI 策略读取/决策查询的内联接口） |
| `include/uapi/linux/ai_netlink.h` | 新增文件：AI netlink 用户态-内核态通信协议 UAPI 头（策略下发/事件上报） |

## 说明

- 以上 8 个修改文件 + 2 个新增文件即 AIKernel 对上游内核的**全部**侵入面；其余功能全部位于内核树 `AIKernel/` 子目录（见仓库根 `AIKernel/ARCHITECTURE.md`）。
- 所有挂点默认"计数+放行"，决策注入总开关默认关闭（`/sys/kernel/ai/decision_inject`），不影响原生行为。
- 基础内核版本：**Linux 6.18.39**。许可证：GPL-2.0（见仓库根 LICENSE）。
