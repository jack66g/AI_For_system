/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_canary.h - AIPD-M2 金丝雀：REG 绑定 + ACT_BATCH 单元组下发 +
 * ARMED 观察（confirm / 到期回退）+ outcome 回填（设计册 §2）
 *
 * 结构纪律（test_canary.c 无内核全跑的根基）：
 *   - 状态推进核心 = 纯函数（映射/闸门/outcome 判定）+ 状态机
 *     aip_canary_decide_point()，全部内核面 IO（netlink/sysfs/proc）
 *     经 struct aip_canary_io 函数表注入——生产实现在本 .c（真
 *     netlink/真文件），测试装桩（tests/test_canary.c）。
 *   - CANARY_ENABLED=0：aip_canary_decide_point() 首行即返回（零计数
 *     零输出）——守护行为与 M1 逐字节等价。
 *
 * 生命周期（§2.1/§2.2/§2.3）：
 *   open（ENABLED=1 时 client_open+REG；失败=journal ERROR+reg_ok=0
 *   诚实降级继续跑影子）→ 每 poll：decide_point（先 ARMED 结算，后
 *   闸门→映射→下发→ARMED 记账）→ close。
 *
 * ARMED 结算（§2.3，节拍=CONFIRM_SEC 上限）：
 *   - condition abated（最新鲜向量上 B 表决策不再命中）→ 写
 *     /sys/kernel/ai/policy/confirm <id> → outcome 回填 → confirmed++
 *     → IDLE；
 *   - 到期未消且 /proc/ai/control 该旋钮 current==pre（K2 定时器已
 *     恢复）→ outcome FAILED → rolled_back++ → IDLE；current 仍非 pre
 *     （未恢复/被钳后应用）→ 继续等（下拍再查）。
 *
 * outcome 映射（§2.4；K11 同款面 /sys/kernel/ai/policy/outcome）：
 *   abated→SUCCESS(1)；safety_clamped→PARTIAL(2)；到期回退→FAILED(3)；
 *   特征恶化（delta 同向变差）→WORSE(4)。优先级 FAILED>WORSE>PARTIAL
 *   >SUCCESS（回滚率与误决策两个验收门取最坏信号，诚实面）。
 */
#ifndef _AIP_CANARY_H
#define _AIP_CANARY_H

#include <stdint.h>

#include "aip_conf.h"
#include "aip_feat.h"
#include "aip_model.h"

/* AI_AGENT_AIPD 镜像（§1 uapi 冻结=6，TOOL=5 后插；本头文件兜底——
 * 生产编译亦用 netlink/ai_netlink_client.h 的枚举/镜像 define） */
#ifndef AI_AGENT_AIPD
#define AI_AGENT_AIPD		6
#endif

/* ---- outcome（内核 AI_OUTCOME_* 同值；§2.4） ---- */
#define AIP_CANARY_OUT_SUCCESS	1
#define AIP_CANARY_OUT_PARTIAL	2	/* safety_clamped=1 */
#define AIP_CANARY_OUT_FAILED	3	/* 到期回退 */
#define AIP_CANARY_OUT_WORSE	4	/* 特征恶化 */

/* ---- §3 冻结映射（三行白名单硬编码；action 域不扩） ---- */

enum aip_knob_formula {
	AIP_KNOB_F_PARAM = 0,	/* value = clamp(param) */
	AIP_KNOB_F_PCT = 1,	/* value = clamp(cur*(100+param)/100, 1, 1000)
				 * ——cur 读 /proc/ai/control（表注「M2 冻结
				 * 精确面」：百分比档=在当前值上抬 param%） */
};

struct aip_knob_def {
	uint32_t action;		/* enum aip_act */
	const char *knob;		/* 内核参数全名（≤23+NUL） */
	uint8_t domain;			/* 内核策略域（SCHED=1 MM=2） */
	int64_t min, max, def;		/* 内核注册值域（探勘实证，纵深防御
					 * 前置 clamp；真值以 /proc/ai/control
					 * 为准） */
	int formula;			/* enum aip_knob_formula */
};

/* 动作白名单表（§3 三行；硬编码冻结——表 action 域不扩的对应面） */
extern const struct aip_knob_def aip_canary_whitelist[3];
#define AIP_CANARY_WHITELIST_N	3

/* ---- 纯函数（单测冻结口径） ---- */

/* i64 钳（静态 inline——映射/测试共用） */
static inline int64_t aip_canary_clamp_i64(int64_t v, int64_t lo, int64_t hi)
{
	return v < lo ? lo : (v > hi ? hi : v);
}

/*
 * aip_canary_lookup - action→白名单行。0=命中（*kdef 填行拷贝）；
 * -1=action 不在白名单（防未来表扩域越权下发——调用方 errors++ 诚实计）。
 */
int aip_canary_lookup(uint32_t action, struct aip_knob_def *kdef);

/*
 * aip_canary_map_value - 冻结公式求下发值（§3）。
 *   F_PARAM：value = clamp(param, min, max)；
 *   F_PCT  ：value = clamp(cur*(100+param)/100, max(min,1), max)，
 *            cur=下发前 /proc/ai/control current（乘加溢出防御：中间
 *            量走 int64，param 先钳 ±90 防绕 big 数）。
 * 0=成功（*value 填）；-1=参数非法。
 */
int aip_canary_map_value(const struct aip_knob_def *kdef, int32_t param,
			 int64_t cur, int64_t *value);

/* lookup+map_value 合并（单测便捷面；cur 仅 F_PCT 用）。0/-1 同上。 */
int aip_canary_map_op(uint32_t action, int32_t param, int64_t cur,
		      struct aip_knob_def *kdef, int64_t *value);

/*
 * aip_canary_outcome - 结算 outcome 判定（§2.4，优先级
 * FAILED>WORSE>PARTIAL>SUCCESS）。至少一支为真才有意义；全假返回 0
 * （UNKNOWN——调用方不应到达）。
 */
int aip_canary_outcome(int rolled_back, int safety_clamped, int worse,
		       int abated);

/* ---- 下发闸门（§2.2 三 skip 纯判定） ---- */

enum aip_canary_gate {
	AIP_GATE_NONE = 0,	/* 不活跃（未 ENABLED/REG 失败）或 action
				 * ==NONE——不计数不下发 */
	AIP_GATE_DISPATCH,
	AIP_GATE_SKIP_STALE,	/* 特征 stale：不可信快照不下发 */
	AIP_GATE_SKIP_BUSY,	/* ARMED 中：K2 单槽 -EBUSY 语义前置规避 */
	AIP_GATE_SKIP_INTERVAL,/* 距上次下发 < CANARY_MIN_INTERVAL_SEC */
};

/*
 * aip_canary_gate - 闸门判定（纯）。since_last_ms=now-上次下发 ms
 * （从未下发=LLONG_MAX 语义由大值表达）；min_interval_ms=conf 秒×1000。
 * 严格小于才 skip（==边界=放行）。
 */
enum aip_canary_gate aip_canary_gate(int active, int armed, int stale,
				     uint32_t action,
				     long long since_last_ms,
				     long long min_interval_ms);

/* ---- 可注入 IO 边（生产=真 netlink/sysfs/proc；测试=桩） ---- */

struct aip_canary_req {
	char knob[24];			/* 参数名（非空 NUL 结尾 ≤23） */
	int64_t value;			/* 钳前请求值 */
	uint8_t domain;			/* 策略域 */
	uint32_t auto_rollback_ms;	/* K2 arm 窗（0=不 arm） */
	uint64_t trace_lo;		/* =trigger seq（§2.2 TRACE_LO） */
	uint64_t intent_id;		/* =rule_idx（§2.2 INTENT） */
};

struct aip_canary_ack {
	unsigned long long decision_id;	/* ack 回带（uapi:292） */
	unsigned executed;		/* 成功子项数 */
	int ai_err;			/* 内核策略层负 errno（0=OK；
					 * -EAGAIN=blast 拒，token 有效） */
	unsigned long long token;	/* blast token（0=未触发） */
};

struct aip_canary_io {
	void *ctx;
	/* 读 /proc/ai/control：knob 行 current= 值。0/-1。 */
	int (*read_control)(void *ctx, const char *knob, int64_t *cur);
	/* 读 /proc/ai/decisions：id 行 safety_clamped 位。返回 0/1；
	 * -1=行缺失/读失败（调用方 errors++ 后按 0 处理）。 */
	int (*read_safety_clamped)(void *ctx,
				   unsigned long long decision_id);
	/* 写 /sys/kernel/ai/policy/confirm 十进制 id。0/-1。 */
	int (*write_confirm)(void *ctx, unsigned long long decision_id);
	/* 写 /sys/kernel/ai/policy/outcome "<id>,<o>,<delta>"。0/-1。 */
	int (*write_outcome)(void *ctx, unsigned long long decision_id,
			     unsigned outcome, int64_t delta);
	/*
	 * 单次 ACT_BATCH（AI_CMD_ACT_BATCH 单元组；confirm_token=重试
	 * 携带，首发恒 0）。返回 0=收到 ack（结果看 ack 字段）；
	 * -1=传输/解析失败。-EAGAIN 两段式重试一次由状态机驱动
	 * （纯逻辑可测），非本层。
	 */
	int (*send_batch)(void *ctx, const struct aip_canary_req *req,
			  unsigned long long confirm_token,
			  struct aip_canary_ack *ack);
};

/* ---- 状态机 ---- */

enum aip_canary_state {
	AIP_CANARY_IDLE = 0,
	AIP_CANARY_ARMED = 1,
};

struct aip_canary {
	int enabled;			/* conf 副本（0=decide_point 直退） */
	int reg_ok;			/* REG 成功（active=enabled&&reg_ok） */
	enum aip_canary_state state;
	long long rollback_ms, confirm_sec_ms, min_interval_ms;

	/* ARMED 批记账（§2.2 ack.executed>0 时填） */
	unsigned long long armed_id;
	struct aip_knob_def armed_kdef;
	int64_t armed_pre;		/* 下发前 current（回退对拍基准） */
	int64_t armed_value;
	int64_t armed_feat0;		/* 下发时触发特征值（delta 基准） */
	uint32_t armed_feat;		/* 触发规则特征枚举（结算取值面） */
	uint32_t armed_action;
	long long armed_deadline_ms;	/* dispatch_now + rollback_ms */
	long long next_settle_ms;	/* 结算节拍（CONFIRM_SEC） */
	long long last_dispatch_ms;

	/* 计数（stats 面；CANARY_ENABLED=0 恒 0——M1 等价） */
	long long dispatched, confirmed, rolled_back, errors;
	long long skip_stale, skip_busy, skip_interval;
	long long ab_total, ab_mismatch;

	struct aip_canary_io io;	/* 注入 IO 边 */
};

/*
 * aip_canary_open - 初始化 + （ENABLED=1）netlink client open + REG。
 *   ENABLED=0：零动作零输出（M1 等价），io 装生产实现但永不触达。
 *   ENABLED=1：REG 成功（AI_OK 且 ack ai_err==AI_OK）→ reg_ok=1；
 *   失败（无 AI 内核/ai.enable=0/权限）→ journal 恰一条 ERROR +
 *   reg_ok=0，**不退出**（诚实降级：影子继续，§2.1）。
 * REG 载荷仅 flags=0（uapi ai_nl_reg 无 agent/abi 字段）；agent 绑定
 * 经每批 AI_DEC_ATTR_AGENT=AI_AGENT_AIPD 携带（K3 自报面），ABI=1 由
 * ai_netlink_client.h 布局 _Static_assert 钉死——与设计册 §2.1 语义
 * 等价的实现面（记录于施工报告）。
 */
void aip_canary_open(struct aip_canary *c, const struct aip_conf *conf);

/* close：幂等（关 netlink client；无 armed 批善后——K2 定时器即失联
 * 回退，设计 §0 裁定）。 */
void aip_canary_close(struct aip_canary *c);

/*
 * aip_canary_decide_point - 决策点钩子（aipd 主循环，§2.2；与
 * shadow_feed/cmp_shadow 并列）。
 *   v=最新鲜向量；d=B 表决策（含 flags/feat_val/rule_idx）；
 *   trig_feat=触发规则特征枚举（d 命中时=rules[d->rule_idx].feat，
 *   无命中 0）；now_ms=单调毫秒。
 *   *executed 置 1 当且仅当本轮实发（ack.executed>0 且记账 ARMED）——
 *   aip_shadow executed 位的唯一置 1 源。
 *   ARMED 结算先于新下发（§2.3）；-EAGAIN token 两段重试一次在此
 *   驱动（§2.2）。
 */
void aip_canary_decide_point(struct aip_canary *c, const struct aip_fvec *v,
			     const struct aip_decision *d, uint32_t trig_feat,
			     long long now_ms, int *executed);

#endif /* _AIP_CANARY_H */
