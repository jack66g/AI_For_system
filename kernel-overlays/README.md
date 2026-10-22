# kernel-overlays — AIKernel 对干净 Linux 6.18.39 的全部改动

本目录是 alpha.11.0 内核的**完整侵入面**，不是旧的 10 文件清单。共 **168 个文件**，保持与内核源码树相同的相对路径：

| 目录 | 文件数 | 说明 |
|---|---:|---|
| `arch/` | 11 | x86 entry/kernel/kvm 的 syscall、CFI、NMI/MCE、kprobes、KVM 钩子 |
| `block/` | 8 | BIO、blk-mq、io-cost、throttle、wbt、elevator、genhd 遥测 |
| `drivers/` | 12 | base、char/random、cpufreq、cpuidle、input、thermal、tty、vfio、virtio |
| `fs/` | 20 | VFS、dcache、aio、epoll、exec、ext4、inotify、namespace、proc 等 |
| `include/` | 6 | `ai_accessors.h`、`ai_netlink.h` 等 UAPI/内部头 |
| `init/` | 2 | 启动/initramfs 模型预加载 |
| `kernel/` | 45 | sched、fork/exit/signal、time、irq、locking、bpf、trace、audit、seccomp、events 等 |
| `lib/` | 1 | ubsan 钩子 |
| `mm/` | 27 | 分配/回收/THP/compaction/slub/oom/readahead 等 |
| `net/` | 23 | TCP、qdisc、netfilter、XDP、GRO/NAPI、conntrack 等 |
| `samples/ai/` | 5 | 内核侧 AI 示例（Kconfig/Makefile/3 个 sample） |
| `security/` | 4 | capability、keys、LSM 遥测 |
| `virt/` | 1 | KVM 主路径 |
| 顶层 | 3 | `Makefile`、`Kconfig`、`Kbuild` 接入 |

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
