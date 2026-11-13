# AIKernel CHANGELOG

## 2026-11 · WP-K8 审计链与不可篡改：sec 两钩做深 + aikctl 用户面（施工 B 部分）

> 依据：`work/refactor/KERNEL-K8-DESIGN.md` §2 D6/D7、§3、§4 施工 B。
> 内核审计链核心（`security/ai_chain.{c,h}` 节点流/xxh64/genesis/anchor/
> seed/verify、/proc/ai/audit、/sys/kernel/ai/chain/、`test/ai_chain_test.c`、
> 决策/agent/model/runtime/audit 六处接线）为**施工 A 交付**，本条不记。
> 台架 `~/k2/k3/k8v.py`（宿主侧，仓库外）随本波交付。

**AIKernel/security/ai_lsm.c**（sec 两钩做深，门控不翻）：

- key 钩（`ai_sec_key_hook`）：strength 三档既往算出即弃，K8 起算完即调
  `ai_chain_key_event(type, desc, plen, strength)` 入链 KEY_EVENT 节点
  （desc 打 xxh64 短摘要）；调用点紧邻 key.c overlay 既有
  `ai_telemetry_key_create`（遥测+链双记）。
- seccomp 钩（`ai_sec_seccomp_hook`）：超阈升格才入链、不逐 syscall——
  信号选模型现成异常分 `m->anomaly`（0~100 滑动窗偏离比；不选
  `count_seccomp`：该槽 base=NULL 无基线，挂过滤器任务每 syscall 过钩，
  裸计数无正常画像参照），阈值 60/100，超阈且距上次入链 ≥1s（全局
  atomic64 cmpxchg 限频）才发射一条 `ai_chain_seccomp_anomaly(nr, anom)`。
- 两钩体接线仍在 `CONFIG_AIKERNEL_EXPERIMENTAL` 门内（默认 n，门不翻）；
  链发射器本身未门控（D6 口径，可 KUnit 代位证明）。

**agent/ai/aikctl/aikctl**（新建，python3 纯 stdlib 单文件，可执行）：
`selftest`（纯 python XXH64 官方算法向量自检含 `xxh64(b"")==0xef46db3751d8e999`
+ 合成 5 节点链篡改检出）、`audit export [-o]`（读 /proc/ai/audit 逐节点
重算自检落 jsonl，首行 meta 含 genesis boot_cookie/node_count/head）、
`audit verify FILE [--anchors]`（逐节点重算+seq 连续性，首个失配打印
`TAMPER index= seq= field=` 退 2；锚行链断退 3）、`audit anchor`
（anchors.jsonl 0600 追加式 sha256 行链）、`audit seed`（锚末行 head_hash
写 /sys/kernel/ai/chain/seed 续链）、`audit status`。aikd 零改；
build-rootfs.sh 陈旧 aikctl 引用与 /usr/bin/aikctl 旧装机件不碰（登记）。

**AIKernel/ARCHITECTURE.md**：§3 seccomp 行与 §4.1 sec 两钩描述更新为
已接线审计链（门控仍 EXPERIMENTAL）；新增 §4.5 K8 审计链小节。

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

## K9 性能预算与基准（2026-11-14）
- 新增 ai_perf_test KUnit 套（record_write/chain_append/telemetry_emit p99 升级/decision_query，机读 PERF 行+CI 宽界）；
- AIKernel/test/perf/{budgets.json,k9_perf.py}：十行预算表单一事实源（absolute/baseline/registered 三模；HW 口径存证不冒充）+单 boot 双层跑表器（门禁件，超界退非零）。
