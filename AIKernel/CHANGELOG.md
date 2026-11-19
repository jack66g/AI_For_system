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

## K10a 工程化首切片（2026-11-14）
- /proc/ai/status 尾部追加版本三件套 kernel_ver/abi_ver/config_hash（27 符号运行时 xxh64 指纹，只增不改）；
- uapi 追加 AI_ABI_VERSION=1（属性只增不改/文本只追加/系列升号三纪律入注）；
- configs/aikernel_factory.config 出厂 profile 单文件 +
  AIKernel/scripts/k10_config_check.sh 三方校验器（profile↔树↔
  代码行为证据；=y 零行为证据=开着没用 FAIL）。

## K10.1 目录与分层重组（2026-11-14）
- 六层落地：senses（感知与出口 25 文件）/actuators（参数·事务·回滚·配额 8）/reflex（定点模型 3）/boundary（security 迁入 7）/subsys×11（sched·mm·io·net·vfs·power·interrupt·lock·time·virt·bpf）/core 瘦身至中枢 15；89 git mv、295 处 include 相对路径重写（202 初轮+93 盲区修正——迁出者回指未迁文件类）、132 个 overlays 反引同步、顶层+子 Makefile 重排。
- 等价性判据（K10a 尺子自证）：构建绿+KUnit not-ok=0+**config_hash 逐位不变 6a36fe4a68743a2f**+k0_truth 48-48+config_check 三方一致。

## K10b REG ABI 版本协商（2026-11-14）
- uapi AI_REG_ATTR_ABI=10（客户端版本 > 服务端 AI_ABI_VERSION 拒 -EPROTONOSUPPORT，≤ 容忍向前兼容）；struct ai_nl_reg_ack 文档化冻结（ai_err/count 前 8B K3 兼容 + abi_ver/rsv 追加）；
- aikctl 新增 abi 子命令：UNREG+ABI attr 零副作用双探（真 socket 全链含 CAP 闸），真机 ver=1 回显 PASS / ver=99 -93 拒 PASS。

## K10.3 补丁系列（2026-11-14）
- AIKernel/scripts/k10_patch_series.py 生成器 + patches/ 138 补丁/12 系列导出（基线=alpha-11 出厂树；vanilla 上游系列登记尾账）；每系列 cover-letter（问题/方案/测试/风险/回退）+ files.txt 明细 + SERIES.md 总目；
- integrity 门禁位：--check-only（overlay↔构建树逐字节，173/173）；
- W=1 全 AIKernel 零告警 + sparse C=1 零告警（smatch 未装=登记）。

## K10.4 测试矩阵（2026-11-14，K10 收口）
- AIKernel/test/perf/k10_matrix.py 跑表器 + configs/k104_{base,off}.frag（scripts/config 纯参数行，# 注释跳过）：P0 静态四门→P1 KUnit→P2 三配置（strong/base/off 翻转后自证再编，boot 断言：strong 三件套指纹等值/base 三件套在+audit 无+指纹变/off /proc/ai 整树缺席）→P3 storm 500→P4 同源三建 sha256 比对+config 复位 factory 抽取比对；全程计时对 CI<30min 预算。
- 矩阵实抓四跨配置缺陷（真 config 组合从未编译过=潜伏爆点，全修）：subsys/power/ai_power.h #else 桩区缺 K4/K7 四访问器桩（POWER=n 跨族隐式声明）；subsys/net/ai_net.h AI 侧五访问器声明门 RUNTIME 而实现门 NET 错位（声明内嵌 NET 门+#else 零值桩）；ai_net.h 桩体 return AI_OK 为全树不存在幽灵宏（改字面 0）；off 片须点名 --disable AIKERNEL_AGENT（agent/ai/Kconfig 遗留六家族不依赖总开关，五子随父级联）。
- base 实测 config_hash=e95e704364d361b5 ≠ strong 6a36fe4a68743a2f（K10a 指纹首次实战区分配置）；P4 三建字节一致 FAIL=内核构建缺省非确定序（预期如实登记；可复现构建全套钉死=尾账）。

## K11 用户态闭环联调（2026-11-14，K 轨 K0–K11 收齐）
- occ /status 追加 AIKernel 内核观测行（三件套+audit 首行链统计+agents 行数/actions+models 首行；缺段省段、非 AIKernel 主机整行静默零扰动）——rig 真机 TUI 渲染实证；
- aistreamd：启动三件套快照 env 事件行落 telemetry parquet + AS_ONCE 单轮/AS_DUMP 逐字段 dump 测试口径（常驻零开销）；
- AIKernel/test/perf/k11_golden.py 全链 golden 两幕器（rig 注盘：aikctl+python3.10+aistreamd+新 occ+conf）——终跑 GOLDEN_SUMMARY ok=7 fail=0（storm300 全成/链 NEW/OUTCOME 按 decision_id 配对 300:300/ASDump⊆内核 ring/parquet 4 块导出/三件套一致/抽一条 OUTCOME 配对必红=断链即红自证）；
- 真 finding：tool 动作 outcome 回填=用户态职责（生产 aikd 经 sysfs，rig 无角色=断链；golden 以生产同款面 /sys/kernel/ai/policy/outcome 回填闭环）；outcome attr 真身在 policy/ 子目录（父路径 O_CREAT=EACCES 假象）；rig 盘 occ TUI 占串口（/shell 内建落 bash）；rig 自带 aistreamd 常驻持锁；ONLCR \r 断跨行正则；audit d= 小端字节序。内核侧零改动。

## alpha.17.7→17.8 出厂波（2026-11-16~17，w17g/w17h：S 红队收尾 + P1 安全 + P2 功能）

> 依据：git 52cb976 / 4d468d7 / 2b6b032 / e3fc3ab / 700ff11（17.7）与 f32ed8a / 99accfa / aca6cf7 / 6538b1a / f89fd83（17.8）。

- alpha.17.7 进厂（w17g）：occ rc71、aik-console v6、W2 确认门、/su 提权、occ 快照校验全件出厂（700ff11）。
- occ undo/redo 快照完整性校验：内容快照随写 `.sha256` sidecar，恢复前比对、被篡改即 fail-closed 拒恢复并保持现状；legacy 无 sidecar 快照照旧兼容（S-FINDING-01）。
- 红队钻证台架 `redteam_drill.py` 五类攻击场景挂 run_all 门（s1）；curl/wget 外发旗标纳入 W2 确认表、test_w2gate +7（s2）。
- sshd 出厂硬化：密钥制登录（prohibit-password）、MaxAuthTries 4、LoginGraceTime 30、MaxStartups 6:30:60 等，sshd -T 树断言八键过（C-P1a）。
- unattended-upgrades 显式禁用：无人值守 apt 升级让位自研受控通道（aik-upgrade），APT::Periodic 两键=0（C-P1b）。
- 文件日志有界：aistreamd.conf 保留键显式（7/90 天）；新增 aik-log-trim+service+timer——追加日志 >8M 保尾 4M、telemetry 天目录保 14 天（C-P1c）。
- health 自愈安全三闸：重启冷却（同一检查项至多 3600s 一次）+启动宽限窗（1800s 内 try-restart 不杀加载期进程）+内存闸（MemAvailable<400MB 不重启/拉起）——根治 SME「重启→重头加载→再被杀」死亡环与压力下整机冻机（C-P1e）。
- cron 守护进厂：busybox crond 前台 + aik-cron.service（multi-user 启用），crontab 真机触发实证；fdisk 经 busybox applet 成文（C-P2b/g）。
- 备份扩面：aik-backup --with-home/--with-data 三族分立、各 KEEP=7 互不挤占（默认面不变）（C-P2d）。
- 告警出口：health-alert.conf 可配 WEBHOOK_URL，FAIL 升级与 RECOVERED 各发一次 JSON POST（不逐轮轰炸）（C-P2e）。
- 静态 IP 工具 config_write_network（occ 面，write/remove/show 三动作、恒 W2 确认、字典序静态覆盖 DHCP、删文件即回 DHCP；OCC_NETCFG_TOOLS=1 旗控注册——默认工具清单与请求字节零变化）（C-P2a）。
- rootfs man 死重删除：/usr/share/man 1897 页 8.8M（rootfs 无 man 二进制纯死重），ISO 瘦身 6.6M（C-P2c）。
- alpha.17.8 ISO 出厂：449,536,000B，md5 0aa1beba5d70a1f2a11b2619ca8a737e；内核 #82 沿用（PSI 翻案零内核改动）；QEMU install+boot 钻证+ssh 电池 12/15 PASS（三项为 17.7 期已知伪影）（w17h）。

## 真机首日修复波：控制台 UX / /su / undo 完整性 / aik-upgrade（2026-11-17）

> 依据：git 4db3bda / b5694f1 / a412dbf / e06f719 / 714d868 / 7279102 / 6bcba2d。

- 控制台 CJK 字体修复：fontconfig 最小骨架进厂（prefer Noto Sans Mono CJK SC），登录框乱码/半字消除（P-34）。
- printk 静默：kernel.printk=3 4 1 3，内核 err 不再上屏覆画 TUI（journal 全量保留）；aik-console 启动清屏除历史残影（P-38）。
- occ /models 浮层离线修复：空注册表照常开浮层+离线提示行（dim），不再「卡一下→画面一闪→回主界面」（P-35）。
- 浮层选中修复：初始光标落首个可选条目（提示行不可选）+SGR7 反色高亮条（fbterm 256 色丢底色的绕开）；出厂色板精修（P-42/P-39）。
- /su 档位流转修复：堵死无密码重提权路径——「已特权」唯一事实源=密码验证成功置位，降权后重提权必过密码框；footer 档标即时刷新；密码框错拒即清输入残留；su elevate/delevate 三态入审计日志（P-45）。
- undo 快照 ABSENT 墓碑完整性校验：非规范墓碑必须有 `.sha256` sidecar 且比对通过，否则 fail-closed 拒动（P-49）。
- undo/redo 快照 manifest 对账（DB 外部锚，P-49 审计三开口收口）：写侧快照落 occ_snap 表 manifest 行；undo 消费侧四规则——anchored 条目比内容字节 sha 与 DB 期望（重造 sidecar 无效）、FS 全缺=删标记如实上报、同 path 见于他 msg=搬目录判死、无 manifest 行=legacy 原路；redo 对称锚（捕获全集落 redo_json，消费前 kind+sha 双比对）；schema v3→v4 幂等迁移（P-50）。
- aik-upgrade 用户态散件安装通道：install userland 逐件 sha256 校验全过才动手+现值备份+`.new` 原子 mv+装后复验+任一步失败自动回滚+审计落 /var/log/aik-upgrade.log；userland-rollback；打包器 build/w7_userland_pkg.sh（六件收集+model.toml 单源一致性断言，漂移拒出包）（W-7）。

## fbterm 稳定遏制与 alpha.17.8.1 出厂线收口（2026-11-18）

> 依据：git 5751afe / 4c35d64 / 41f91fa / 6356480 / c3236d9 / d66c71c / 893bd6b / ee5e6d3。

- 控制台整帧原子刷+输出看门狗：一帧字节全部积进缓冲、flush 尾一次 drain（旧逐格碎片刷 2500+ 次 write/帧填满 64KB pty 即永久冻结）；drain 总时限缺省 15s，超时即楔死实锤走 rc=72 统一收口链；aik-console 循环 2s 重启整链（P-41/P-44）。
- 体量心跳：每拍 57444B 全 SGR 空参重置探针（零字形零视觉、避开 fbterm 数字解析崩溃路径、BSS 懒生成）——空闲态楔死 ~25s 检出；v1 CUP 回跟踪小探针被 64KB pty 缓冲整吞的盲区由 v2 收口、旧探针删净（P-41/P-44 补棒+44c）。
- 看门狗击毙 fbterm：楔死实锤后 kill(ppid, SIGKILL)（FBTERM env 门卫仅 fb 分支）——fbterm 吞子进程退出码（occ exit(72) 转手变 0）与真楔死不读 pty（aik-console wait 永挂）双重谜底一并收口；137 线索位必亮，真楔死从「永久冻结」变 ~25s 检出+即时击毙+2s 重启回门（P-41/P-44d/e）。
- occ /exit 注销链终触发：退出码出带外写 /run/aik-occ-exit（读后即焚；70=/zoom 非终局不写防污染）；aik-console v8 据此走真注销链——「退出即注销」自 v6 写下首次真实触发（P-47）。
- occ unstuck 轻量解僵：楔死/强杀后会话卡 status=running 挡 undo——`occ unstuck --session <id>` 单点改库 running→interrupted，零上下文重放零模型调用，幂等诚实（P-48）。
- 17.8.1 出厂线收口（conf/二进制一致）：refresh 时 aistreamd 二进制+conf 同刷（17.8 教训=只刷 conf 不刷二进制→unknown-key 崩溃环 115 重启）；chroot --check-conf 双向断言（好 conf=rc0/毒 conf=rc≠0）；ISO 内四件（aistreamd/occ/aik-console/aik-upgrade）与仓裸件 md5 全等断言（P-32）。
- softdog 同树进厂：refresh 前置门 bzImage md5 7b35b41f+k2 树 softdog.ko（9e50cb73）进厂+vermagic/modules.dep/modules-load 断言+lsmod 运行时证明；ISO-SNAPSHOT-W82.txt 溯源修正（旧件误写 #62→#82 真值）（P-33）。
- aistreamd 二进制入库——出厂同源锚：17.8.1 ISO 所装件=库内件，tag 可复现（occ 先例）（P-32 附）。
- 17.8 后积压出厂面一并收编：occ（unstuck/exit-marker/控制台稳定棒）、aik-console v8、aik-upgrade（W-7 通道）、fonts.conf（P-34 CJK）、50-aik-console-quiet.conf（P-38）。
- alpha.17.8.1 ISO 出厂：449,699,840B，md5 e705bc82d823305b348bd01821a68fa1；QEMU install+boot 钻证+ssh 电池 17/21 PASS（4 FAIL=17.8 原班已知伪影，零新增）+B8 五项全绿。

## W2 写域分层与测试台架（2026-11-19）

> 依据：git 3866269 / f9237f5 / 0061f13 / f1a6eef。

- W2 写域分层（J-7=A 拍板「必须对齐我」）：w2_chmod_hit 语义级命中替代「chmod 777」字面匹配——数字模式 other-write 位、符号 o/a/无前缀授 w、+x 落世界可写文件=两步等效 777（stat 判 S_IWOTH），u/g 档与 644/755 不命中；occ_tool_ctx.w2_confirmed——W2 门确认（confirm/allow_w2）后置位，特权档越界写豁免（~/.occ 红线原样双保险）；受限档 tier 闸硬拒（档位决定要不要问）；确认面板 y/n 单键应答（P-52）。
- 测试：新 occ_tui/tests/test_w2_confirm_pty（PTY+真 occ+mock LLM，49 断言：y/Enter/n/Esc/超时/写侧双门端到端）；test_w2gate 扩 14 例（chmod 全家族正反例+豁免端到端）；既有断言零删除（P-52）。
- w2_chmod_hit token 剥首尾标点：模型惯加分号/echo 尾——标点粘在路径 token 上 stat ENOENT、两步绕过检测漏放；收 token 即剥 `;,&|()` 引号与反引号，补回归用例（P-52 A 轮真机回归）。
- c2/c3 台架 PATH 回退通道加固：probe 裸名回退撞 aikctl compat_resolve_probe isfile 合同（预检过而 plan 拒跑的表象定因）——PATH 回退命中时 shutil.which 落绝对路径（P-53）。
- TUI 实链自动压缩台架 test_ac_pty：真 occ TUI（pty）+三路 mock LLM（对话/工具回投/digest 填表）+mock 判官（test_ac.c 协议移植，恒判 COMPRESS_NOW）——断言 AC 请求序列、会话摘要落库 system 行、digest 填表、换窗后 turn 连续性；自动压缩首次具备确定性实链台架（此前仅单测 mock 与真机观察）（P-54）。
