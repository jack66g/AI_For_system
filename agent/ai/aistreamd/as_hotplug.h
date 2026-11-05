/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_hotplug.h - K3d-2 热插拔事件 → AI 四级流水线（I-9 MVP，只建议）
 *
 * 四级（sense → infer → decide → act）：
 *   1) sense   分类器（hp_classify）：uevent 路 action ∈ {add,remove,
 *      online,offline} 进；NETLINK_AI EVENT 路 category ∈ {3,4,5}
 *      （AS_AI_NL_EV_DEVICE/CPU_HOTPLUG/HW_ERROR——uapi AI_NL_EV_* 空间
 *      「只追加不重排」约定下的预留映射契约，L1 经 K3c mock 通道注入，
 *      qemu 真内核收口轮接真推送）进；其余事件不进。
 *   2) infer   模型前向：HOTPLUG_MODEL 未配 → status=skipped_unconfigured
 *      （流水线其余照走）；已配 → 写 /sys/kernel/ai/model_infer
 *      "name hex..."（float32 小端，K3b 核对契约）+ 读 model_out；
 *      /sys/kernel/ai 不存在且 HOTPLUG_INFER_MOCK=1 → 确定性 mock
 *      （journal 明示 TEST ONLY）。单次 >2s → 放弃该事件
 *      （infer_timeout++，不阻塞流水线）。
 *   3) decide  组装 advisory 记录（JSONL，固定字段序冻结，见
 *      as_hotplug.c hp_record）；think 闭环接口位 as_hp_think() 预留
 *      （MVP 恒返回 0 → decision_id=null，绝不写 think sysfs）。
 *   4) act     **永远不存在**。advisory 的 "executed" 字段恒为字面量
 *      false（见 hp_record 的硬编码 "false"）。C7 红线：设备移除/下线类
 *      动作永不自动执行；任何未来自动化需单独立项过 I 轨登记。
 *
 * 落盘：追加 HOTPLUG_LOG（默认 /var/log/aikernel/hotplug-advisories.jsonl，
 * 0600，父目录不存在则创建 0700）。advisory 受专用配额实例约束（复用
 * as_quota 配额器；hotplug.daily_max 默认 200，日限与每源路日限同值）。
 *
 * 可观测：as_stats hotplug.* 计数（seen/infer_ok/infer_timeout/
 * infer_skipped/advisory_written/dropped_noquota + enabled）。
 * 关停：SIGTERM 随主守护优雅退出（as_hotplug_close flush+close）。
 */
#ifndef _AS_HOTPLUG_H
#define _AS_HOTPLUG_H

#include "as_conf.h"
#include "as_event.h"
#include "as_quota.h"
#include "as_stats.h"

/* NETLINK_AI EVENT 通道热插拔 category（AI_NL_EV_* 追加空间预留契约）。
 * 现网内核 EVENT 通道只推 1/2（policy/model）；3/4/5 是本流水线与未来
 * 内核侧 glue 的约定值（uapi "只追加不重排"），qemu 收口轮随 uapi 一起
 * 正式化。勿与遥测 18 大类（AI_CAT_*）混用——两个命名空间（摸底发现：
 * AI_CAT_SCHED=1 与 AI_NL_EV_POLICY=1 撞号）。 */
#define AS_AI_NL_EV_DEVICE	3	/* code: 0=probe 1=remove，param=dev 名 */
#define AS_AI_NL_EV_CPU_HOTPLUG	4	/* code: 1=online 0=offline，param=cpu 号 */
#define AS_AI_NL_EV_HW_ERROR	5	/* param="cpu,bank"（MCE 16.03 对齐） */

/* infer 超时（规格写死 2s） */
#define AS_HP_INFER_TIMEOUT_MS	2000

/* advisory JSONL 单行上限（devpath 400 + rationale 余量） */
#define AS_HP_LINE_MAX		2048

/* 热插拔事件类型（advisory JSON 的 event.type，冻结） */
enum as_hp_type {
	AS_HP_NONE = 0,
	AS_HP_DEV_ADD,		/* uevent add */
	AS_HP_DEV_REMOVE,	/* uevent remove */
	AS_HP_DEV_ONLINE,	/* uevent online（如 memory 块） */
	AS_HP_DEV_OFFLINE,	/* uevent offline */
	AS_HP_DEV_PROBE,	/* AI 16.01 action=0 */
	AS_HP_DEV_UNPROBE,	/* AI 16.01 action=1 */
	AS_HP_CPU_ONLINE,	/* AI 01.07 online=1 */
	AS_HP_CPU_OFFLINE,	/* AI 01.07 online=0 */
	AS_HP_MCE,		/* AI 16.03 */
};

struct as_hp_event {
	enum as_hp_type type;
	long long ts_real_ms;	/* 取自 as_event.ts_real_ms */
	const char *source;	/* "uevent" | "ai-netlink" */
	char dev[400];		/* 设备路/名（DEV_* 类） */
	char subsystem[64];	/* uevent SUBSYSTEM / AI drv 名 */
	int cpu;		/* CPU/MCE 类：-1=未知 */
	int bank;		/* MCE bank；-1=未知 */
	char payload_digest[17];/* = as_event.digest_hex */
};

/* infer 结果（status 字符串冻结进 JSONL） */
struct as_hp_infer {
	int ok;			/* 1=status "ok"/"mock"；0=其余 */
	const char *status;	/* ok|mock|skipped_unconfigured|skipped_noiface|error */
	char out_digest[17];	/* 输出向量 FNV-1a64（16 hex；无输出=""） */
	long long latency_ns;
};

struct as_hotplug {
	struct as_conf *conf;
	struct as_stats *stats;
	struct as_quota quota;		/* advisory 专用配额实例 */
	int log_fd;			/* advisory JSONL（-1=未开） */
	int sysfs_present;		/* /sys/kernel/ai/model_infer 存在 */
	long long infer_timeout_ms;	/* 默认 AS_HP_INFER_TIMEOUT_MS（测试可调） */

	/* ---- TEST ONLY hooks（单测注入慢 mock 用；生产恒 NULL/0） ---- */
	int test_sleep_ms;		/* mock infer 人为延迟（超时路径单测） */
};

/* 初始化（quota + sysfs 探测 + SIGALRM 处理器；enabled=0 时不开文件）。
 * 返回 0；-1 仅配额内存失败（文件打不开=journal 告警降级，不致命）。 */
int as_hotplug_init(struct as_hotplug *hp, struct as_conf *c,
		    struct as_stats *st);

/* flush + close advisory 文件（SIGTERM 优雅退出路径调用） */
void as_hotplug_close(struct as_hotplug *hp);

/*
 * as_hotplug_tap - 管道主入口（on_event 首位调用，先于 K3c 去重）。
 * 非热插拔事件零副作用直接返回；hotplug.enabled=0 时零开销返回。
 */
void as_hotplug_tap(struct as_hotplug *hp, const struct as_event *ev);

/*
 * as_hp_classify - 分类器（纯函数；单测冻结 fixture）。
 * 返回 0=是热插拔事件（*out 填充）；1=不是（*out 不动）。
 */
int as_hp_classify(const struct as_event *ev, struct as_hp_event *out);

/*
 * as_hp_record_build - advisory JSONL 行构造（纯函数；单测逐字节冻结）。
 * 固定字段序：{"ts":..,"event":{..},"infer":{..},"suggestion":{..},
 * "executed":false,"decision_id":null}。executed 恒为字面量 false
 * （C7 红线：设备移除/下线类动作永不自动执行；act 级不存在）。
 * decision_id 传 0 → JSON null（think 闭环未接的 MVP 形态）。
 * 返回行长（含 '\n'）；-1=缓冲不足（调用方丢弃并告警，不写半行）。
 */
int as_hp_record_build(const struct as_hp_event *h,
		       const struct as_hp_infer *ir, const char *model,
		       unsigned long long decision_id, char *buf, size_t cap);

/*
 * as_hp_think - think 闭环接口位（qemu 收口轮接真
 * /sys/kernel/ai/policy/think "<event_id>,<domain>,<type>,<value>" 并回读
 * decision_id）。MVP 恒返回 0（advisory.decision_id=null）且**绝不写**
 * think sysfs——只建议模式的红线之一：本模块不存在任何执行路径。
 */
unsigned long long as_hp_think(const struct as_hotplug *hp,
			       const struct as_hp_event *h,
			       const struct as_hp_infer *ir);

#endif /* _AS_HOTPLUG_H */
