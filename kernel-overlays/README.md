# kernel-overlays — AIKernel 对干净 Linux 6.18.39 的全部改动

本目录是内核侧的**完整侵入面**（alpha.11.0 建立；alpha.12.0 内核未变，仍 #59），不是旧的 10 文件清单。共 **172 个文件**，保持与内核源码树相同的相对路径：

| 目录 | 文件数 | 说明 |
|---|---:|---|
| `arch/` | 11 | x86 entry/kernel/kvm 的 syscall、CFI、NMI/MCE、kprobes、KVM 钩子 |
| `block/` | 8 | BIO、blk-mq、io-cost、throttle、wbt、elevator、genhd 遥测 |
| `drivers/` | 12 | base、char/random、cpufreq、cpuidle、input、thermal、tty、vfio、virtio |
| `fs/` | 20 | VFS、dcache、aio、epoll、exec、ext4、inotify、namespace、proc 等 |
| `include/` | 8 | `ai_accessors.h`、`ai_netlink.h` 等 UAPI/内部头 + `cgroup_subsys.h`（SUBSYS(ai)） |
| `init/` | 2 | 启动/initramfs 模型预加载 |
| `kernel/` | 45 | sched、fork/exit/signal、time、irq、locking、bpf、trace、audit、seccomp、events 等 |
| `lib/` | 1 | ubsan 钩子 |
| `mm/` | 27 | 分配/回收/THP/compaction/slub/oom/readahead 等 |
| `net/` | 23 | TCP、qdisc、netfilter、XDP、GRO/NAPI、conntrack 等 |
| `samples/` | 7 | `Kconfig`/`Makefile` 接线（source 行 + obj-$ 三行）+ `ai/` 5 个示例 |
| `security/` | 4 | capability、keys、LSM 遥测 |
| `virt/` | 1 | KVM 主路径 |
| 顶层 | 3 | `Makefile`、`Kconfig`、`Kbuild` 接入 |

另含 K2a（2026-11-04）正典入册的 3 处树外编辑：`include/linux/cgroup_subsys.h`（`SUBSYS(ai)` cgroup 控制器注册）、`samples/Kconfig`（`source "samples/ai/Kconfig"`）、`samples/Makefile`（3 行 `obj-$(CONFIG_SAMPLE_AI_*) += ai/`）——此前长期存在于 #62 树内但未入 MANIFEST（K1a/K1cd 发现，重建会静默缺 ai cgroup 控制器与 SAMPLE_AI 接线）。

另含 W48 的死代码清理：`net/sched/sch_fq.c` 恢复 `static`/去掉无用导出，`sch_codel.c`、`sch_fq_codel.c` 的 ops 改为 `static`。

## 应用

```bash
bash ../build/apply-overlays.sh /path/to/linux-6.18.39
cp ../.config /path/to/linux-6.18.39/.config
```

脚本按 `MANIFEST.sha256` 逐个复制并校验；**不要**用 `rsync -a` 整目录覆盖，`README.md`/`MANIFEST.sha256` 不是内核文件。

## 校验

```bash
cd kernel-overlays
sha256sum -c MANIFEST.sha256
```

## 说明

- 所有挂点默认“计数+放行”，决策注入总开关默认关闭（`/sys/kernel/ai/decision_inject`），不改变原生内核行为。
- 基础版本固定为 Linux 6.18.39；升级内核时不要直接套用本目录，需按钩子逐个移植。
- GPL-2.0；文件头保留 SPDX。

## active / dormant 状态（W78，2026-10-26）

按当前 .config（BTF/PSI/FANOTIFY/INET_DIAG/SCHED_CLASS_EXT 已开）实测标注。
「休眠」= overlay 文件存在但其所依赖的 CONFIG 未开、永不参与编译——
审计侵入面时应只看 active 行；启用对应 CONFIG 后埋点自动转活跃
（W78 实例：psi.c 与 sched/ext.c 均由休眠转活跃）。

总计：active 145 / dormant 7（.c 文件）

| 文件 | 状态 | 依据 | 备注 |
|---|---|---|---|
| arch/x86/entry/syscall_64.c | active | — |
| arch/x86/kernel/cfi.c | active | — |
| arch/x86/kernel/cpu/mce/core.c | active | — |
| arch/x86/kernel/kprobes/core.c | active | — |
| arch/x86/kernel/kprobes/ftrace.c | active | — |
| arch/x86/kernel/kprobes/opt.c | active | — |
| arch/x86/kernel/nmi.c | active | — |
| arch/x86/kernel/traps.c | active | — |
| arch/x86/kvm/irq.c | active | — |
| arch/x86/kvm/mmu/mmu.c | active | — |
| arch/x86/kvm/vmx/vmx.c | dormant | CONFIG_KVM 未开 | 休眠埋点，随 config 启用 |
| block/bio.c | active | — |
| block/blk-iocost.c | active | — |
| block/blk-merge.c | active | — |
| block/blk-mq.c | active | — |
| block/blk-throttle.c | active | — |
| block/blk-wbt.c | active | — |
| block/elevator.c | active | — |
| block/genhd.c | active | — |
| drivers/base/dd.c | active | — |
| drivers/base/platform.c | active | — |
| drivers/char/random.c | active | — |
| drivers/cpufreq/cpufreq.c | active | — |
| drivers/cpuidle/governors/menu.c | active | — |
| drivers/input/input.c | active | — |
| drivers/thermal/thermal_core.c | active | — |
| drivers/tty/n_tty.c | active | — |
| drivers/tty/tty_io.c | active | — |
| drivers/tty/tty_ldisc.c | active | — |
| drivers/vfio/vfio_iommu_type1.c | active | — |
| drivers/virtio/virtio_balloon.c | dormant | CONFIG_VIRTIO_BALLOON 未开 | 休眠埋点，随 config 启用 |
| fs/aio.c | active | — |
| fs/char_dev.c | active | — |
| fs/dax.c | active | — |
| fs/dcache.c | active | — |
| fs/eventpoll.c | active | — |
| fs/exec.c | active | — |
| fs/ext4/super.c | active | — |
| fs/file_table.c | active | — |
| fs/fs-writeback.c | active | — |
| fs/inode.c | active | — |
| fs/locks.c | active | — |
| fs/namei.c | active | — |
| fs/namespace.c | active | — |
| fs/notify/inotify/inotify_fsnotify.c | active | — |
| fs/open.c | active | — |
| fs/proc/base.c | active | — |
| fs/proc/proc_sysctl.c | active | — |
| fs/read_write.c | active | — |
| fs/stat.c | active | — |
| fs/super.c | active | — |
| init/initramfs.c | active | — |
| init/main.c | active | — |
| kernel/audit.c | active | — |
| kernel/bpf/helpers.c | active | — |
| kernel/bpf/syscall.c | active | — |
| kernel/bpf/verifier.c | active | — |
| kernel/dma/mapping.c | active | — |
| kernel/events/core.c | active | — |
| kernel/exit.c | active | — |
| kernel/fork.c | active | — |
| kernel/futex/waitwake.c | active | — |
| kernel/irq/affinity.c | active | — |
| kernel/irq/manage.c | active | — |
| kernel/kcsan/report.c | active | — |
| kernel/kprobes.c | active | — |
| kernel/locking/lockdep.c | dormant | CONFIG_PROVE_LOCKING 未开 | 休眠埋点，随 config 启用 |
| kernel/locking/mutex.c | active | — |
| kernel/locking/rwsem.c | active | — |
| kernel/locking/spinlock.c | active | — |
| kernel/module/main.c | active | — |
| kernel/power/energy_model.c | active | — |
| kernel/power/qos.c | active | — |
| kernel/power/wakelock.c | active | — |
| kernel/rcu/update.c | active | — |
| kernel/sched/core.c | active | — |
| kernel/sched/deadline.c | active | — |
| kernel/sched/ext.c | active | CONFIG_SCHED_CLASS_EXT=y | W78 开 BTF+SCHED_CLASS_EXT 后转活跃 |
| kernel/sched/fair.c | active | — |
| kernel/sched/isolation.c | active | — |
| kernel/sched/pelt.c | active | — |
| kernel/sched/psi.c | active | — |
| kernel/sched/rt.c | active | — |
| kernel/sched/syscalls.c | active | — |
| kernel/seccomp.c | active | — |
| kernel/signal.c | active | — |
| kernel/softirq.c | active | — |
| kernel/sys.c | active | — |
| kernel/time/clocksource.c | active | — |
| kernel/time/hrtimer.c | active | — |
| kernel/time/tick-sched.c | active | — |
| kernel/time/timer.c | active | — |
| kernel/trace/trace.c | active | — |
| kernel/trace/trace_events_filter.c | active | — |
| kernel/trace/trace_functions.c | active | — |
| kernel/watchdog.c | active | — |
| kernel/workqueue.c | active | — |
| lib/ubsan.c | active | — |
| mm/backing-dev.c | active | — |
| mm/cma.c | active | — |
| mm/compaction.c | active | — |
| mm/filemap.c | active | — |
| mm/huge_memory.c | active | — |
| mm/hugetlb.c | active | — |
| mm/kasan/report.c | active | — |
| mm/kfence/report.c | dormant | CONFIG_KFENCE 未开 | 休眠埋点，随 config 启用 |
| mm/khugepaged.c | active | — |
| mm/kmsan/report.c | dormant | CONFIG_KMSAN 未开 | 休眠埋点，随 config 启用 |
| mm/ksm.c | dormant | CONFIG_KSM 未开 | 休眠埋点，随 config 启用 |
| mm/memory-failure.c | active | — |
| mm/memory.c | active | — |
| mm/migrate.c | active | — |
| mm/oom_kill.c | active | — |
| mm/page-writeback.c | active | — |
| mm/page_alloc.c | active | — |
| mm/readahead.c | active | — |
| mm/shrinker.c | active | — |
| mm/slub.c | active | — |
| mm/usercopy.c | active | — |
| mm/vmpressure.c | active | — |
| mm/vmscan.c | active | — |
| mm/workingset.c | active | — |
| net/core/dev.c | active | — |
| net/core/filter.c | active | — |
| net/core/gro.c | active | — |
| net/core/neighbour.c | active | — |
| net/core/xdp.c | active | — |
| net/dns_resolver/dns_query.c | active | — |
| net/ipv4/ip_input.c | active | — |
| net/ipv4/route.c | active | — |
| net/ipv4/tcp.c | active | — |
| net/ipv4/tcp_cong.c | active | — |
| net/ipv4/tcp_input.c | active | — |
| net/ipv4/tcp_ipv4.c | active | — |
| net/ipv4/tcp_output.c | active | — |
| net/ipv4/udp.c | active | — |
| net/netfilter/core.c | active | — |
| net/netfilter/nf_conntrack_core.c | active | — |
| net/netfilter/nf_nat_core.c | active | — |
| net/sched/sch_api.c | active | — |
| net/sched/sch_codel.c | active | — |
| net/sched/sch_fq.c | active | — |
| net/sched/sch_fq_codel.c | active | — |
| net/sched/sch_generic.c | active | — |
| net/socket.c | active | — |
| samples/ai/ai_bpf_helper_sample.c | active | — |
| samples/ai/ai_io_scheduler_sample.c | active | — |
| samples/ai/ai_sched_policy_sample.c | active | — |
| security/commoncap.c | active | — |
| security/keys/key.c | active | — |
| security/keys/keyctl.c | active | — |
| virt/kvm/kvm_main.c | dormant | CONFIG_KVM 未开 | 休眠埋点，随 config 启用 |
