// SPDX-License-Identifier: GPL-2.0
/*
 * ai_hooks_test.c - K5 空钩治理后 13 保留钩 KUnit 套件
 * （KERNEL-K5-DESIGN §4 测试刀：分类/异常/强度启发式 + 指标出口存在性）
 *
 * 保留钩口径（K5 后）：11 真实/观测
 * （ai_mm_readahead_hook、ai_proc_classify/exec、ai_lock_spin_hook(_done)、
 * ai_bpf_ftrace/kprobe/verifier、ai_net_nf_hook、ai_telemetry_nf_hook、
 * ai_telemetry_pelt_se_sample）+ 2 sec 门控真体（seccomp/key，
 * CONFIG_AIKERNEL_EXPERIMENTAL；真机 KUnit 构建树 EXPERIMENTAL=n →
 * 该段自动跳过）。删除账与复活路径见 AIKernel/CHANGELOG.md（WP-K5）。
 *
 * 覆盖：
 *   - ai_proc_classify_hook：NULL 早退 / kthread（clone 参数与 PF_KTHREAD
 *     两路）/ RT（prio∈[0,100)）/ DL（prio<0）/ 默认批处理 / 交互式父
 *     继承——经零值 task_struct + 手填 flags/prio 构造（thread_pid=NULL
 *     → task_pid_nr 解析为 0，槽表断言用 pid 0）；
 *   - ai_proc_exec_hook：路径启发式三档（sh/vi/top→交互、make/gcc→批、
 *     /llm//infer→AI 负载）+ path=NULL 鲁棒；
 *   - ai_net_detect_anomaly：构造 IP+TCP skb（data 即网络头，LOCAL_OUT
 *     形态）——SYN 无 ACK→syn 计数、RST→retrans、纯 ACK→只进样本、
 *     NULL/UDP 早退不崩；ai_net_nf_hook 恒等放行 + nf_hook_calls 计数；
 *   - ai_sec_key_hook：强度启发式三档（<8→0 / <16→1 / >=16→2）边界值
 *     + 无出参直调安全（EXPERIMENTAL×SECURITY 双门控包裹）；
 *   - 指标出口存在性（每个保留钩至少一条断言）：proc/lock/bpf/mm/net
 *     五族以对应 ai_*_stats(_read) 计数读取函数代位，遥测族（nf/pelt）
 *     以 ai_telemetry_stats per-CPU 读取代位，/sys/kernel/ai/stats 目录
 *     出口用 kern_path 存在性验证；
 *   - ai_mm_readahead_hook：三层开关默认关（前置断言 per-hook enable=0）
 *     → 原样返回 nr_to_read + readahead_hook_calls 计数出口。
 *
 * 退出还原：清理 fake 槽（pid 0）与 current 槽位。
 * 计数断言口径：全系统共享计数器（其它 CPU 的真实活动并发累加），
 * 故正向路径用 >=、不做「不变」等值硬断言（W63 偶发教训）。
 */
#include <kunit/test.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/rt.h>
#include <linux/sched/deadline.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/namei.h>
#include <linux/path.h>

#include "../core/ai_types.h"
#include "../core/ai_proc.h"
#include "../core/ai_telemetry.h"
#include "../core/ai_decision.h"

/* ==================================================================
 * 进程分类钩（CONFIG_AIKERNEL_RUNTIME）
 * ==================================================================
 */
#ifdef CONFIG_AIKERNEL_RUNTIME

/* class_peek 是 trylock 快路径：锁争用返回 -1（设计语义），短暂重试
 * 取确定值（ai_decision_test 同法） */
static int peek_class(int pid)
{
	int cls;
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		cls = ai_proc_class_peek(pid);
		if (cls != -1)
			return cls;
		usleep_range(50, 100);
	}
	return -1;
}

/* 零值 task_struct + 手填判定字段：classify_hook 只读 flags/prio 与
 * task_pid_nr(p)（thread_pid=NULL → pid_alive 假 → 解析为 0），其余
 * 字段零值不触碰。槽表断言以 pid 0 落位。 */
static struct task_struct *fake_task(struct kunit *test, int prio,
				     unsigned int flags)
{
	struct task_struct *p = kunit_kzalloc(test, sizeof(*p), GFP_KERNEL);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p);
	p->prio = prio;
	p->flags = flags;
	return p;
}

static void proc_classify_null_and_kthread_test(struct kunit *test)
{
	struct kernel_clone_args args;
	struct task_struct *fake;

	/* p=NULL 早退：缺省批处理，不触槽表 */
	KUNIT_EXPECT_EQ(test, ai_proc_classify_hook(NULL, NULL),
			AI_PROC_CLASS_BATCH);

	/* clone 参数 kthread=1 → KERNEL（prio 为普通 CFS 档不改判） */
	memset(&args, 0, sizeof(args));
	args.kthread = 1;
	fake = fake_task(test, 120, 0);
	KUNIT_EXPECT_EQ(test, ai_proc_classify_hook(fake, &args),
			AI_PROC_CLASS_KERNEL);
	KUNIT_EXPECT_EQ(test, peek_class(0), AI_PROC_CLASS_KERNEL);

	/* flags PF_KTHREAD → KERNEL（args 不带 kthread/io_thread 位） */
	fake = fake_task(test, 120, PF_KTHREAD);
	KUNIT_EXPECT_EQ(test, ai_proc_classify_hook(fake, &args),
			AI_PROC_CLASS_KERNEL);

	ai_proc_slot_remove(0);
}

static void proc_classify_rt_dl_batch_test(struct kunit *test)
{
	struct kernel_clone_args args;
	struct task_struct *fake;
	pid_t me = task_pid_nr(current);

	/* 父（current）先标批处理：关闭交互继承分支，RT/DL/默认三分支可见
	 * （/usr/bin/grep 命中 exec 模式表的批处理档） */
	ai_proc_exec_hook(current, "/usr/bin/grep");
	KUNIT_ASSERT_EQ(test, peek_class(me), AI_PROC_CLASS_BATCH);

	memset(&args, 0, sizeof(args));

	/* RT：prio∈[0,MAX_RT_PRIO) → rt_task 命中 */
	fake = fake_task(test, 50, 0);
	KUNIT_EXPECT_EQ(test, ai_proc_classify_hook(fake, &args),
			AI_PROC_CLASS_AI_LOAD);
	KUNIT_EXPECT_EQ(test, peek_class(0), AI_PROC_CLASS_AI_LOAD);

	/* DL：prio<0（MAX_DL_PRIO 以下）→ dl_task 命中 */
	fake = fake_task(test, -1, 0);
	KUNIT_EXPECT_EQ(test, ai_proc_classify_hook(fake, &args),
			AI_PROC_CLASS_AI_LOAD);

	/* 其余：CFS 档无继承 → 默认批处理（占位启发式兜底档） */
	fake = fake_task(test, 120, 0);
	KUNIT_EXPECT_EQ(test, ai_proc_classify_hook(fake, &args),
			AI_PROC_CLASS_BATCH);
	KUNIT_EXPECT_EQ(test, peek_class(0), AI_PROC_CLASS_BATCH);

	ai_proc_slot_remove(0);
	ai_proc_slot_remove(me);
}

static void proc_classify_interactive_inherit_test(struct kunit *test)
{
	struct kernel_clone_args args;
	struct task_struct *fake;
	pid_t me = task_pid_nr(current);

	/* 交互式父进程（/bin/sh exec 档）→ CFS 档子进程继承交互式 */
	ai_proc_exec_hook(current, "/bin/sh");
	KUNIT_ASSERT_EQ(test, peek_class(me), AI_PROC_CLASS_INTERACTIVE);

	memset(&args, 0, sizeof(args));
	fake = fake_task(test, 120, 0);
	KUNIT_EXPECT_EQ(test, ai_proc_classify_hook(fake, &args),
			AI_PROC_CLASS_INTERACTIVE);
	KUNIT_EXPECT_EQ(test, peek_class(0), AI_PROC_CLASS_INTERACTIVE);

	ai_proc_slot_remove(0);
	ai_proc_slot_remove(me);
}

static void proc_exec_paths_test(struct kunit *test)
{
	pid_t me = task_pid_nr(current);

	/* shell 族 → 交互式（前台工具树） */
	ai_proc_exec_hook(current, "/bin/sh");
	KUNIT_EXPECT_EQ(test, peek_class(me), AI_PROC_CLASS_INTERACTIVE);
	ai_proc_exec_hook(current, "/usr/bin/vi");
	KUNIT_EXPECT_EQ(test, peek_class(me), AI_PROC_CLASS_INTERACTIVE);
	ai_proc_exec_hook(current, "/usr/bin/top");
	KUNIT_EXPECT_EQ(test, peek_class(me), AI_PROC_CLASS_INTERACTIVE);

	/* 构建族 → 批处理 */
	ai_proc_exec_hook(current, "/bin/make");
	KUNIT_EXPECT_EQ(test, peek_class(me), AI_PROC_CLASS_BATCH);
	ai_proc_exec_hook(current, "/usr/bin/gcc");
	KUNIT_EXPECT_EQ(test, peek_class(me), AI_PROC_CLASS_BATCH);

	/* 推理族 → AI 负载 */
	ai_proc_exec_hook(current, "/srv/llm/infer-server");
	KUNIT_EXPECT_EQ(test, peek_class(me), AI_PROC_CLASS_AI_LOAD);

	/* path=NULL：保留原分类、刷新 app 启动记录不崩 */
	ai_proc_exec_hook(current, NULL);
	KUNIT_EXPECT_EQ(test, peek_class(me), AI_PROC_CLASS_AI_LOAD);

	ai_proc_slot_remove(me);
}

static void proc_stats_outlet_test(struct kunit *test)
{
	struct kernel_clone_args args;
	struct task_struct *fake;
	struct ai_proc_stats before, after;

	/* 分类/exec 两钩的指标出口：ai_proc_stats() 读取成功且计数随
	 * 调用单调推进（全系统共享计数 → >= 断言）。注意 classify 的
	 * NULL 早退发生在计数之前——须用 fake 任务驱动 classify_count */
	memset(&args, 0, sizeof(args));
	fake = fake_task(test, 120, 0);
	KUNIT_ASSERT_EQ(test, ai_proc_stats(&before), AI_OK);
	ai_proc_classify_hook(fake, &args);
	ai_proc_exec_hook(current, "/bin/sh");
	KUNIT_ASSERT_EQ(test, ai_proc_stats(&after), AI_OK);
	KUNIT_EXPECT_GE(test, after.classify_count, before.classify_count + 1);
	KUNIT_EXPECT_GE(test, after.exec_count, before.exec_count + 1);

	ai_proc_slot_remove(0);
	ai_proc_slot_remove(task_pid_nr(current));
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

/* ==================================================================
 * 预读钩（CONFIG_AIKERNEL_MM）
 * ==================================================================
 */
#ifdef CONFIG_AIKERNEL_MM

#include "../mm/ai_mm.h"

static void mm_readahead_hook_and_stats_test(struct kunit *test)
{
	struct ai_mm_stats before, after;
	unsigned long out;
	int i;

	/* 前置：决策注入 per-hook 开关默认关（三层开关的第三层；
	 * ai_decision_get_hook_enable 在 RUNTIME=n 下退 0 桩，同为 0）。
	 * 关=与原生行为一致 → 恒等返回。ractl 本钩不解引用。 */
	KUNIT_ASSERT_EQ(test,
			ai_decision_get_hook_enable(AI_HOOK_MM_READAHEAD), 0);

	out = ai_mm_readahead_hook(NULL, 8, 2);
	KUNIT_EXPECT_EQ(test, out, 8UL);

	/* 指标出口：readahead_hook_calls 随调用推进（页缓存回读活动
	 * 并发累加 → >= 断言） */
	ai_mm_stats_read(&before);
	for (i = 0; i < 4; i++)
		ai_mm_readahead_hook(NULL, 128, 0);
	ai_mm_stats_read(&after);
	KUNIT_EXPECT_GE(test, after.readahead_hook_calls,
			before.readahead_hook_calls + 4);
}

#endif /* CONFIG_AIKERNEL_MM */

/* ==================================================================
 * 锁观测钩（CONFIG_AIKERNEL_LOCK）
 * ==================================================================
 */
#ifdef CONFIG_AIKERNEL_LOCK

#include "../lock/ai_lock.h"

static DEFINE_RAW_SPINLOCK(hooks_test_lock);

static void lock_spin_hooks_and_stats_test(struct kunit *test)
{
	struct ai_lock_stats before, mid, after;
	u64 sampled0;
	unsigned int i;

	/* spin_hook 出口：spin_hook_calls 随调用单调推进（真机锁争用
	 * 活动并发累加 → >= 断言） */
	ai_lock_stats_read(&before);
	for (i = 0; i < 300; i++)
		ai_lock_spin_hook(&hooks_test_lock);
	ai_lock_stats_read(&mid);
	KUNIT_EXPECT_GE(test, mid.spin_hook_calls,
			before.spin_hook_calls + 300);

	/* 1/256 采样开窗：per-CPU 计数每 256 次必命中 1 次，有界循环内
	 * 必然推进 spin_sampled（跨 CPU 分摊时鸽笼保证单 CPU 聚集 >=256） */
	sampled0 = mid.spin_sampled;
	for (i = 0; i < 8192; i++) {
		ai_lock_spin_hook(&hooks_test_lock);
		if ((i & 63) == 0) {
			ai_lock_stats_read(&after);
			if (after.spin_sampled > sampled0)
				break;
		}
	}
	ai_lock_stats_read(&after);
	KUNIT_ASSERT_GT(test, after.spin_sampled, sampled0);

	/* 采样窗口结算：同锁 done 关窗并走 emit_spin 出口计数；窗口在
	 * this_cpu 槽，两次调用间不睡眠（同 CPU 概率~1，防中断抢占偶发
	 * 用非致命 EXPECT）；重复 done 幂等安全 */
	ai_lock_spin_hook_done(&hooks_test_lock);
	ai_lock_spin_hook_done(&hooks_test_lock);
	ai_lock_stats_read(&after);
	KUNIT_EXPECT_GE(test, after.emit_spin, 1U);
}

#endif /* CONFIG_AIKERNEL_LOCK */

/* ==================================================================
 * BPF 观测钩（CONFIG_AIKERNEL_BPF）
 * ==================================================================
 */
#ifdef CONFIG_AIKERNEL_BPF

#include "../bpf/ai_bpf.h"

static void bpf_observation_hooks_and_stats_test(struct kunit *test)
{
	struct ai_bpf_stats before, after;

	/* ftrace/kprobe/verifier 三观测钩：零值参数直调安全（体只计数 +
	 * 遥测发射，不触碰参数内容），各自独立计数出口 */
	ai_bpf_stats_read(&before);
	ai_bpf_ftrace_hook(0, 0, NULL);
	ai_bpf_kprobe_hook(NULL, 0, 0);
	ai_bpf_verifier_hook(0, 0, 0, 0, 0);
	ai_bpf_stats_read(&after);
	KUNIT_EXPECT_GE(test, after.ftrace_hook_calls,
			before.ftrace_hook_calls + 1);
	KUNIT_EXPECT_GE(test, after.kprobe_hook_calls,
			before.kprobe_hook_calls + 1);
	KUNIT_EXPECT_GE(test, after.verifier_hook_calls,
			before.verifier_hook_calls + 1);
}

#endif /* CONFIG_AIKERNEL_BPF */

/* ==================================================================
 * 网络 nf 钩与异常检测（CONFIG_AIKERNEL_NET）
 * ==================================================================
 */
#ifdef CONFIG_AIKERNEL_NET

#include "../net/ai_net.h"

/* 构造 IP+TCP 测试包：data 即网络头（LOCAL_OUT 形态，异常检测与
 * ai_telemetry_nf_hook 的读取路径同构）；network/transport 头偏移
 * 就位后 skb_network_header_len()=20 */
static struct sk_buff *build_ip_skb(struct kunit *test, u8 protocol,
				    bool syn, bool rst)
{
	struct sk_buff *skb = alloc_skb(128, GFP_KERNEL);
	struct iphdr *iph;
	struct tcphdr *th;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, skb);
	iph = skb_put(skb, sizeof(*iph) + sizeof(*th));
	memset(iph, 0, sizeof(*iph) + sizeof(*th));
	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = protocol;
	th = (struct tcphdr *)(iph + 1);
	th->syn = syn ? 1 : 0;
	th->rst = rst ? 1 : 0;
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	return skb;
}

static void net_nf_hook_and_anomaly_test(struct kunit *test)
{
	struct ai_net_stats st[2];   /* [0]=操作前 [1]=操作后 */
	struct sk_buff *skb;

	/* nf 钩：恒等放行（NULL skb 走早退）+ nf_hook_calls 计数出口 */
	ai_net_stats_read(&st[0]);
	KUNIT_EXPECT_EQ(test, ai_net_nf_hook(NULL, NULL, NF_ACCEPT), NF_ACCEPT);
	ai_net_stats_read(&st[1]);
	KUNIT_EXPECT_GE(test, st[1].nf_hook_calls, st[0].nf_hook_calls + 1);

	/* 异常 SYN（无 ACK）→ syn 计数与样本计数推进 */
	ai_net_stats_read(&st[0]);
	skb = build_ip_skb(test, IPPROTO_TCP, true, false);
	ai_net_detect_anomaly(skb, NF_ACCEPT);
	kfree_skb(skb);
	ai_net_stats_read(&st[1]);
	KUNIT_EXPECT_GE(test, st[1].anomaly_syn_pkts,
			st[0].anomaly_syn_pkts + 1);
	KUNIT_EXPECT_GE(test, st[1].anomaly_samples,
			st[0].anomaly_samples + 1);

	/* RST → retrans 计数推进 */
	ai_net_stats_read(&st[0]);
	skb = build_ip_skb(test, IPPROTO_TCP, false, true);
	ai_net_detect_anomaly(skb, NF_ACCEPT);
	kfree_skb(skb);
	ai_net_stats_read(&st[1]);
	KUNIT_EXPECT_GE(test, st[1].anomaly_retrans_pkts,
			st[0].anomaly_retrans_pkts + 1);

	/* 正常流量（纯 ACK）：样本推进；异常两计数不因本输入推进
	 * （并发旁路流量只会多计 → 异常合计等值用非致命 EXPECT 容忍） */
	ai_net_stats_read(&st[0]);
	skb = build_ip_skb(test, IPPROTO_TCP, false, false);
	ai_net_detect_anomaly(skb, NF_ACCEPT);
	kfree_skb(skb);
	ai_net_stats_read(&st[1]);
	KUNIT_EXPECT_GE(test, st[1].anomaly_samples,
			st[0].anomaly_samples + 1);
	KUNIT_EXPECT_EQ(test,
			st[1].anomaly_syn_pkts + st[1].anomaly_retrans_pkts,
			st[0].anomaly_syn_pkts + st[0].anomaly_retrans_pkts);

	/* 早退路径不崩：NULL skb / 非 TCP（UDP 只进样本不进异常分支） */
	ai_net_detect_anomaly(NULL, NF_ACCEPT);
	skb = build_ip_skb(test, IPPROTO_UDP, false, false);
	ai_net_detect_anomaly(skb, NF_ACCEPT);
	kfree_skb(skb);
}

static void telemetry_nf_hook_outlet_test(struct kunit *test)
{
	struct ai_telemetry_cpu_stats tst;
	int cpu;

	/* 第4类 nf 遥测钩：NULL skb/state 直调安全（采样通过即发射零
	 * 字段 payload，跳过亦合法——调用安全与出口断言分开验证） */
	ai_telemetry_nf_hook(NULL, NULL, NF_ACCEPT);

	/* 指标出口代位：遥测 per-CPU 计数可读（TELEMETRY=n 时 0 桩
	 * 恒 AI_OK，断言同样成立）；get_cpu 防迁移（DEBUG_PREEMPT 口径） */
	cpu = get_cpu();
	KUNIT_EXPECT_EQ(test, ai_telemetry_stats(cpu, &tst), AI_OK);
	put_cpu();
}

#endif /* CONFIG_AIKERNEL_NET */

/* ==================================================================
 * PELT 采样钩出口（CONFIG_AIKERNEL_TELEMETRY）
 * ==================================================================
 */
#ifdef CONFIG_AIKERNEL_TELEMETRY

static void pelt_se_sample_outlet_test(struct kunit *test)
{
	struct ai_telemetry_cpu_stats tst;
	int cpu;

	/* 覆盖面注记：ai_telemetry_pelt_se_sample 的发射路径需要
	 * update_curr() 在场的真 se/cfs_rq（调度器内部容器，模块侧不可
	 * 构造；且 1/64 限频门以真实运行计数推进，盲调会在命中拍解引用
	 * 传入指针）——本用例不驱动钩体（本体由 update_curr 全量流真实
	 * 驱动，sched/ai_sched.c），只断言其唯一指标出口（遥测
	 * per-CPU 计数）可读。 */
	cpu = get_cpu();
	KUNIT_EXPECT_EQ(test, ai_telemetry_stats(cpu, &tst), AI_OK);
	put_cpu();
}

#endif /* CONFIG_AIKERNEL_TELEMETRY */

/* ==================================================================
 * sysfs stats 出口存在性（CONFIG_AIKERNEL_USRIFACE；
 * test/ 在 AIKernel/Makefile 目录序末位 → 套件运行时节点已建）
 * ==================================================================
 */
#if IS_ENABLED(CONFIG_AIKERNEL_USRIFACE)

static void sysfs_stats_outlets_test(struct kunit *test)
{
	struct path p;
	int rc;

	/* K5 勘误（KUnit 实抓）：套件在内核 init 期执行，早于用户态挂
	 * /sys——kern_path 对已注册 kernfs 节点也返回 -ENOENT。节点真实
	 * 存在性由台架轮（K3 rig 六轮已证 /sys/kernel/ai/stats 可读）承载；
	 * 本用例仅在 /sys 已挂载的环境（如未来 sysfs 挂载后注入的跑法）
	 * 才做路径断言，否则 SKIP（环境条件化，非期望放水）。 */
	rc = kern_path("/sys", LOOKUP_DIRECTORY, &p);
	if (rc) {
		kunit_skip(test, "sysfs 未挂载（KUnit 早于用户态 init）");
		return;
	}
	path_put(&p);
	rc = kern_path("/sys/kernel/ai/stats/telemetry_emitted",
		       LOOKUP_FOLLOW, &p);
	KUNIT_EXPECT_EQ(test, rc, 0);
	if (!rc)
		path_put(&p);
	rc = kern_path("/sys/kernel/ai/stats/decisions_total",
		       LOOKUP_FOLLOW, &p);
	KUNIT_EXPECT_EQ(test, rc, 0);
	if (!rc)
		path_put(&p);
}

#endif /* CONFIG_AIKERNEL_USRIFACE */

/* ==================================================================
 * sec 密钥强度钩（真体居 EXPERIMENTAL 门下；实现在 SECURITY 门内的
 * ai_lsm.c → 双条件兜底，任一 =n 时 0 值桩不具断言意义，自动跳过）
 * ==================================================================
 */
#if defined(CONFIG_AIKERNEL_EXPERIMENTAL) && defined(CONFIG_AIKERNEL_SECURITY)

#include "../security/ai_lsm.h"

static void sec_key_hook_strength_test(struct kunit *test)
{
	u8 s = 0xFF;

	/* 三档启发式（载荷长度）：<8 弱=0 / <16 中=1 / >=16 强=2 */
	ai_sec_key_hook("user", "desc", 0, &s);
	KUNIT_EXPECT_EQ(test, s, 0);
	ai_sec_key_hook("user", "desc", 7, &s);
	KUNIT_EXPECT_EQ(test, s, 0);
	ai_sec_key_hook("user", "desc", 8, &s);	/* 档位边界：8 起为中 */
	KUNIT_EXPECT_EQ(test, s, 1);
	ai_sec_key_hook("user", "desc", 15, &s);
	KUNIT_EXPECT_EQ(test, s, 1);
	ai_sec_key_hook("user", "desc", 16, &s);/* 档位边界：16 起为强 */
	KUNIT_EXPECT_EQ(test, s, 2);
	ai_sec_key_hook("user", "desc", 4096, &s);
	KUNIT_EXPECT_EQ(test, s, 2);

	/* 无出参直调安全（strength=NULL 早退） */
	ai_sec_key_hook("user", "desc", 32, NULL);
}

#endif /* EXPERIMENTAL && SECURITY */

/* ==================================================================
 * 套件装配（各段按子模块开关兜底：部分配置编译为空套件）
 * ==================================================================
 */

static struct kunit_case hooks_test_cases[] = {
#ifdef CONFIG_AIKERNEL_RUNTIME
	KUNIT_CASE(proc_classify_null_and_kthread_test),
	KUNIT_CASE(proc_classify_rt_dl_batch_test),
	KUNIT_CASE(proc_classify_interactive_inherit_test),
	KUNIT_CASE(proc_exec_paths_test),
	KUNIT_CASE(proc_stats_outlet_test),
#endif
#ifdef CONFIG_AIKERNEL_MM
	KUNIT_CASE(mm_readahead_hook_and_stats_test),
#endif
#ifdef CONFIG_AIKERNEL_LOCK
	KUNIT_CASE(lock_spin_hooks_and_stats_test),
#endif
#ifdef CONFIG_AIKERNEL_BPF
	KUNIT_CASE(bpf_observation_hooks_and_stats_test),
#endif
#ifdef CONFIG_AIKERNEL_NET
	KUNIT_CASE(net_nf_hook_and_anomaly_test),
	KUNIT_CASE(telemetry_nf_hook_outlet_test),
#endif
#ifdef CONFIG_AIKERNEL_TELEMETRY
	KUNIT_CASE(pelt_se_sample_outlet_test),
#endif
#if IS_ENABLED(CONFIG_AIKERNEL_USRIFACE)
	KUNIT_CASE(sysfs_stats_outlets_test),
#endif
#if defined(CONFIG_AIKERNEL_EXPERIMENTAL) && defined(CONFIG_AIKERNEL_SECURITY)
	KUNIT_CASE(sec_key_hook_strength_test),
#endif
	{}
};

static struct kunit_suite hooks_test_suite = {
	.name = "ai_hooks",
	.test_cases = hooks_test_cases,
};

kunit_test_suite(hooks_test_suite);
MODULE_LICENSE("GPL v2");
