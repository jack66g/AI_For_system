// SPDX-License-Identifier: GPL-2.0
/*
 * ai_bpf_helper_sample.c - BPF AI helper 示例（samples/ai/）
 *
 * 用途：演示"BPF 程序如何调用 AIKernel 的 AI helper"接入模板。
 * AIKernel 提供两个 BPF helper（实现于 kernel/bpf/helpers.c，核心在
 * AIKernel/bpf/ai_bpf.c）：
 *   bpf_ai_query(model_id, input, input_len, output, output_len)
 *       —— BPF 程序内调 AI 推理（走 AI PMU ai_inference 计数）；
 *   bpf_ai_telemetry(category, event_type, data, len)
 *       —— BPF 程序内发遥测（走 AI PMU ai_telemetry_write 计数）。
 *
 * 本示例是一个**BPF 程序源码模板**（bpftool/clang 编译加载）+ 内核侧
 * 配套演示模块（演示 core 函数 ai_bpf_query/ai_bpf_telemetry 的调用姿势
 * 与 AI PMU 发射 ai_telemetry_perf_ai）。
 *
 * 一、BPF 程序侧（示例 BPF 程序，clang -target bpf 编译）：
 *
 *   #include <linux/bpf.h>
 *   #include <bpf/bpf_helpers.h>
 *
 *   // 一段示例 BPF 程序：网络包经过时让 AI 推理一次并上报遥测
 *   SEC("xdp")
 *   int sample_ai_xdp(struct xdp_md *ctx)
 *   {
 *       char input[16] = "ai-sample";
 *       char output[16] = {};
 *       long rc = bpf_ai_query(1, input, sizeof(input), output,
 *                              sizeof(output));
 *       if (rc > 0)
 *           bpf_ai_telemetry(4, 87, output, rc);   // 4=net 87=PERF 事件
 *       return XDP_PASS;
 *   }
 *   char _license[] SEC("license") = "GPL";
 *
 * 加载（bpftool，需 5.0+ 内核支持 BPF_MAP_TYPE_AI_MODEL）：
 *   bpftool prog load sample_ai_xdp.o /sys/fs/bpf/sample_ai_xdp
 *   bpftool net attach xdp sample_ai_xdp dev eth0
 *
 * 二、内核模块侧（本文件）：演示 core 函数与 PMU 发射的直接调用。
 *
 * 构建（在内核树根）：
 *   make CONFIG_SAMPLE_AI_BPF_HELPER=m samples/ai/ai_bpf_helper_sample.ko
 * 加载 / 验证：
 *   insmod ai_bpf_helper_sample.ko
 *   aikctl sense 14            （看到 BPF 类遥测记录）
 *   perf stat -e ai_inference   （或 ai/telemetry_write/）
 *
 * 注意：本示例是"接入模板"；真实模型与真实 BPF 程序请仿照
 * AIKernel/bpf/ 与 kernel/bpf/helpers.c 的 bpf_ai_* 实现。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "../AIKernel/bpf/ai_bpf.h"
#include "../AIKernel/core/ai_telemetry.h"
#include "../AIKernel/core/ai_types.h"

/*
 * AI PMU 事件常量（对齐 AIKernel/bpf/ai_bpf.h + kernel/events/core.c）：
 *   ai/inference（config=1）  ai/decision（config=2）
 *   ai/telemetry_write（config=3）
 */
extern void ai_telemetry_perf_ai(u32 event_id, u64 nr, u64 latency_ns);

static int __init sample_bpf_helper_init(void)
{
	char input[16] = "ai-sample-input";
	char output[16] = { 0 };
	long rc;

	/*
	 * 演示 1：ai_bpf_query() —— BPF helper bpf_ai_query 的核心实现。
	 * model_id=0 表示"未加载模型"，实现返回 -ENOENT 或内置兜底；
	 * 加载模型后可看到成功路径（AI PMU ai_inference 计数 + 遥测）。
	 */
	rc = ai_bpf_query(0, input, sizeof(input), output, sizeof(output));
	pr_info("sample: ai_bpf_query(model=0) -> %ld\n", rc);

	/*
	 * 演示 2：ai_bpf_telemetry() —— BPF helper bpf_ai_telemetry 核心。
	 * 发射第 14 类（BPF/Tracing/Perf）遥测记录，数据全量零脱敏。
	 */
	rc = ai_bpf_telemetry(AI_CAT_BPF, AI_EV_BPF_PROG, input,
			      sizeof(input));
	pr_info("sample: ai_bpf_telemetry(cat=14) -> %ld\n", rc);

	/*
	 * 演示 3：ai_telemetry_perf_ai() —— AI PMU 事件发射。
	 * 事件 1=ai_inference（推理次数/耗时）。无 perf 监听时
	 * static_key 单分支 ≈1ns 零开销。
	 */
	ai_telemetry_perf_ai(1, 1, 1200);   /* 1 次推理，1200ns */
	pr_info("sample: AI PMU ai/inference emitted\n");
	return 0;
}

static void __exit sample_bpf_helper_exit(void)
{
	pr_info("sample: AI BPF helper sample unloaded\n");
}

module_init(sample_bpf_helper_init);
module_exit(sample_bpf_helper_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("AIKernel sample: BPF AI helper integration");
