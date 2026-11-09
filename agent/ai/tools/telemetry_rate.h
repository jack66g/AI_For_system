/* SPDX-License-Identifier: GPL-2.0 */
/*
 * telemetry_rate.h - I-2：/proc/ai/telemetry 采样率写口工具面
 * （procfs_write_telemetry_rate；REVIEW3-REPORT §A-1 激活）
 *
 * 内核面（只读对齐，本文件零内核改动）：
 *   - 写口：/proc/ai/telemetry 写 "rate=cat:ev:N"（ai_procfs.c:485-493
 *     前置 "rate=" 分派 → ai_telemetry_rate_cmd（ai_telemetry.c:721-760）
 *     解析 "cat:ev:N"；cat∈[1,18]、ev∈[1,AI_EV_MAX=104)、N∈[0,65535]
 *     （内核对 N>65535 钳 65535；本工具越界直接人话报错不代钳——
 *     需 65535 请显式写）。写口前置 capable(CAP_SYS_ADMIN)
 *     （ai_procfs.c:472，K2b 加固）。
 *   - 读回面：/proc/ai/status 每_cpuN 段列**非默认**采样率行
 *     "  sample_rate[cat=%u ev=%u]=%u"（ai_procfs.c:108-122；全默认时
 *     打 "  sample_rate: all full (1)"）。注意内核循环只到 17 类
 *     （c <= AI_CAT_KCONFIG）——18 类（AI 自观测）写了也不出现在
 *     status 读回里，工具如实注记。
 *
 * 枚举表与默认率表出处（REVIEW3-REPORT §A-1，L1 实读核实）：
 *   - 18 大类 AI_CAT_*（ai_telemetry.h:64-81）；子类 ev 上界=各类
 *     枚举末值（ai_telemetry.h:88-215，AI_EV_MAX=104）。
 *   - 默认率表：全类全事件 1（全量），仅三处限频（ai_telemetry.c:114-116
 *     常量 + :421-427 初始化）：HW.DEVICE(16.01)=1/16、HW.DMA(16.04)=1/64、
 *     KCONFIG.SYSCTL(17.02)=1/16。（源里另有 AI_TEL_PLATFORM_SAMPLE=16
 *     常量但未入默认表——按初始化代码如实三处。）
 *   - 语义：N=0 丢弃该事件全部后续样本；N=1 全量；N>1 每 N 条记 1 条。
 *     率表易失（无持久化，重启即默认）；恢复出厂默认=按默认表回写
 *     （其余 cat:ev 写 1）。
 */
#ifndef _TELEMETRY_RATE_H
#define _TELEMETRY_RATE_H

#include <stddef.h>

/* 工具名（gen_registry 注册名；executor 按名特路由到本面） */
#define TEL_RATE_TOOL_NAME	"procfs_write_telemetry_rate"

/* 内核常量对齐（ai_telemetry.h / ai_telemetry.c） */
#define TEL_RATE_CAT_MIN	1
#define TEL_RATE_CAT_MAX	18
#define TEL_RATE_N_MAX		65535

/* 大类枚举行（cat → 名/ev 上界；ai_telemetry.h:64-81/88-215） */
struct tel_rate_cat {
	unsigned cat;
	const char *name;	/* 大类短名（人话报错用） */
	unsigned ev_max;	/* 该类合法 ev 上界（含） */
	const char *desc;	/* 一句话说明 */
};

extern const struct tel_rate_cat tel_rate_cats[TEL_RATE_CAT_MAX];
extern const size_t tel_rate_cats_n;

/* 默认率表（非 1 的三处；REVIEW3-REPORT §A-1 / ai_telemetry.c:421-427） */
struct tel_rate_default {
	unsigned cat, ev, rate;
};
extern const struct tel_rate_default tel_rate_defaults[];
extern const size_t tel_rate_defaults_n;

/*
 * tel_rate_parse - 解析并校验 "cat:ev:N"（可带 "rate=" 前缀，可带首尾
 * 空白；内部空白拒绝）。0=成功（cat/ev/n 出参填充）；-1=失败（err 收到
 * 人话原因，容量 errcap）。
 */
int tel_rate_parse(const char *value, unsigned *cat, unsigned *ev,
		   unsigned *n, char *err, size_t errcap);

/*
 * tel_rate_status_find - 在 status 文本面按 (cat,ev) 找非默认率行。
 * 1=找到（*rate 填充）；0=未找到（全默认或该条已是 1）；-1=读失败。
 */
int tel_rate_status_find(const char *status_path, unsigned cat, unsigned ev,
			 unsigned *rate);

/*
 * tel_rate_run - 工具执行体（executor 特路由调用；value=用户原值，
 * write_path=/proc/ai/telemetry（测试可指临时文件），status_path=
 * /proc/ai/status（同上））。
 * 返回 AI_OK/AI_ERR_*（ai_types.h）；*out 收到人话结果（调用方 free）。
 */
int tel_rate_run(const char *value, const char *write_path,
		 const char *status_path, char **out);

#endif /* _TELEMETRY_RATE_H */
