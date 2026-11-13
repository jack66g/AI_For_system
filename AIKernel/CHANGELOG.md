# AIKernel CHANGELOG

## 2026-11 · WP-K5 空钩治理：删除账（15 钩）

> 判决依据：`work/refactor/KERNEL-K5-DESIGN.md` §3 逐钩判决表（终判）；
> K4 效果波实锤（sched 族 0-for-2、mm 族 0-for-3——五钩终判全 OFF，
> 「有个位置能挂」不构成实现理由）与 K0/K0b 总账。
> 删除内容统一为：AIKernel 实现体 + EXPORT 行 + 头文件双桩
> （EXPERIMENTAL C 版声明与 static inline off 桩）+ overlay 调用行 +
> 恒等配套与死计数项。保留：11 真实/观测钩、2 sec 真体钩
> （seccomp/key，仍居 CONFIG_AIKERNEL_EXPERIMENTAL 门下）、
> ai_cca CCA 本体、`ai` 电梯本体、io.priority/io.bandwidth 真面。

| # | 钩子 | 挂接点（实现 / 调用） | 删除理由 | 复活路径 |
|---|---|---|---|---|
| 1 | ai_load_balance_hook | ai_sched.c（原 :119）/ kernel/sched/fair.c sched_balance_rq | 纯桩（计数+恒 proceed=true）；sched 族 K4 0-for-2（vruntime/wakeup 双 OFF） | KERNEL-K5-DESIGN §3#1；K6/K7 有了可验收四件套再立 |
| 2 | ai_sched_rt_admission_hook | ai_sched.c（原 :132）/ rt.c enqueue_task_rt + deadline.c enqueue_task_dl（返回值被丢弃） | 实现须改调用点=最高风险；RT/DL 准入误伤实时任务 | KERNEL-K5-DESIGN §3#2 |
| 3 | ai_mm_fault_hook | ai_mm.c（原 :200）/ memory.c do_anonymous_page + do_fault | mm 族 K4 0-for-3；高频路径开销风险 | KERNEL-K5-DESIGN §3#3 |
| 4 | ai_mm_workingset_hook | ai_mm.c（原 :243）/ workingset.c workingset_refault | 同链路 readahead 零收益旁证 | KERNEL-K5-DESIGN §3#4 |
| 5 | ai_mm_alloc_hook | ai_mm.c（原 :251）/ page_alloc.c rmqueue | 预测函数恒 0 占位前科 | KERNEL-K5-DESIGN §3#5 |
| 6 | ai_mm_thp_hook | ai_mm.c（原 :260）/ khugepaged.c collapse 成功路径 | 同上；**级联核验**：mm.thp 参数 apply 另有真路径（ai_mm_thp_apply→ai_thp_flags_set，实现在 mm/huge_memory.c overlay 门控访问器）→ 参数与注册保留，仅删钩 | KERNEL-K5-DESIGN §3#6 |
| 7 | ai_net_cong_hook | ai_net.c（原 :181）/ AIKernel 内部 ai_tcp_cca.c tcp_ai_cong_avoid | 台架 `-nic none` 无验收环境；ai_cca CCA 本体（reno 族）保留 | KERNEL-K5-DESIGN §3#7 |
| 8 | ai_net_cong_ssthresh_hook | ai_net.c（原 :187）/ ai_tcp_cca.c tcp_ai_ssthresh | 同上 | KERNEL-K5-DESIGN §3#8 |
| 9 | ai_io_dispatch_hook | ai_block.c（原 :42）/ block/blk-mq.c blk_mq_dispatch_rq_list + samples/ai/ai_io_scheduler_sample.c（演示件连带删） | io 族与 io.priority/bandwidth 真面冗余 | KERNEL-K5-DESIGN §3#9 |
| 10 | ai_io_merge_hook | ai_block.c（原 :49）/ block/blk-merge.c ll_back_merge_fn + ll_front_merge_fn；恒等配套 ai_io_predict_merge 同删 | 同上 | KERNEL-K5-DESIGN §3#10 |
| 11 | ai_io_wbt_hook | ai_block.c（原 :56）/ block/blk-wbt.c blk_mq_timeout_io；恒等配套 ai_io_adjust_wbt 同删 | 写回带宽已由 io.bandwidth（bdi max_ratio）承载 | KERNEL-K5-DESIGN §3#11 |
| 12 | ai_io_throttle_hook | ai_block.c（原 :63）/ block/blk-throttle.c tg_within_iops_limit + tg_within_bps_limit | 原生 blk-cgroup throttling 完整承载 | KERNEL-K5-DESIGN §3#12 |
| 13 | ai_io_sched_hook | ai_block.c（原 :70）/ AIKernel 内部 io/ai_bfq.c ai_sched_pick（`ai` 电梯本体保留，空咨询点撤除） | 空咨询点无消费者 | KERNEL-K5-DESIGN §3#13 |
| 14 | ai_sec_cap_hook | ai_lsm.c（原 :947）/ security/commoncap.c cap_capable | 体=恒等 return ret；能力面已由 ai LSM 6×-EPERM 承载 | KERNEL-K5-DESIGN §3#14；K8 审计链若需再立 |
| 15 | ai_sec_crypto_hook | ai_lsm.c（原 :968）/ 调用点 crypto/api.c:652（**勘误**：K0 真相表「crypto/api.c 未埋点」判词错误——repo 无 crypto overlay 故历次仓库侧 grep 零命中，K5 构建门禁实抓 implicit-declaration；新增 kernel-overlays/crypto/api.c overlay 摘除该行，遥测 ai_telemetry_crypto_request 保留） | 空桩喂点零价值死重 | KERNEL-K5-DESIGN §3#15（含勘误） |

连带清理：

- per-CPU 计数死项：`ai_net_hook_cnt[3]` 收缩为标量（槽 1/2 随 cong 双钩死，
  槽 0 为 ai_net_nf_hook 活引用保留）；`struct ai_net_stats.hook_calls[3]` →
  `nf_hook_calls`；`struct ai_io_stats` 五个 `*_hook_calls` 死字段删除
  （disk_stats/disk_errors 计数保留）；`struct ai_mm_stats` 四对
  fault/workingset/alloc/thp 计数字段删除（readahead 对保留）。
  sched 域 `ai_sched_stats` 的 lb/rt/dl 计数字段保留——ai_sched_procfs.c
  仍有活读出（值恒 0）。
- 恒等配套：ai_io_predict_merge / ai_io_adjust_wbt（体+EXPORT+双桩）。
- samples/ai：SAMPLE_AI_IO_SCHEDULER Kconfig 条目、Makefile obj 行、
  ai_io_scheduler_sample.c 整文件连带删除；目录内其余两个 sample 保留。
- Kconfig：AIKERNEL_EXPERIMENTAL 门控保留（sec 两钩仍在门下），help 文案
  改写为 sec seccomp/key 两钩现状（17→2）。
- kernel-overlays/MANIFEST.sha256：按现有格式重算被改文件并移除已删
  sample 条目。
