/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_canary.c - M2 金丝雀单测：§3 映射纯函数 + §2 状态机（IO 桩注入，
 * 无内核全跑）+ §2.4 outcome 优先级 + §2.2 闸门/EAGAIN 两段重试。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "aip_canary.h"
#include "aip_conf.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

/* ================= IO 桩 ================= */

struct stub_step {
	int rc;				/* send_batch 返回值 */
	struct aip_canary_ack ack;
};

struct stub_io {
	/* /proc/ai/control 表 */
	struct { char knob[24]; long long cur; } ctl[4];
	int nctl;
	/* /proc/ai/decisions safety_clamped */
	unsigned long long sc_id;
	int sc_val, sc_rc;		/* sc_rc=-1=读失败 */
	/* confirm/outcome 捕获（rc 可注错） */
	unsigned long long confirm_id;
	int confirm_calls, confirm_rc;
	unsigned long long outcome_id;
	unsigned outcome_val;
	long long outcome_delta;
	int outcome_calls, outcome_rc;
	/* ACT_BATCH 脚本 */
	struct stub_step script[4];
	int nscript, ncall;
	struct aip_canary_req last_req;
	unsigned long long last_token;
};

static int stub_read_control(void *ctx, const char *knob, int64_t *cur)
{
	struct stub_io *s = ctx;

	for (int i = 0; i < s->nctl; i++)
		if (strcmp(s->ctl[i].knob, knob) == 0) {
			*cur = s->ctl[i].cur;
			return 0;
		}
	return -1;
}

static int stub_read_sc(void *ctx, unsigned long long id)
{
	struct stub_io *s = ctx;

	if (s->sc_rc < 0)
		return -1;
	return id == s->sc_id ? s->sc_val : 0;
}

static int stub_write_confirm(void *ctx, unsigned long long id)
{
	struct stub_io *s = ctx;

	s->confirm_calls++;
	s->confirm_id = id;
	return s->confirm_rc;
}

static int stub_write_outcome(void *ctx, unsigned long long id,
			      unsigned outcome, int64_t delta)
{
	struct stub_io *s = ctx;

	s->outcome_calls++;
	s->outcome_id = id;
	s->outcome_val = outcome;
	s->outcome_delta = (long long)delta;
	return s->outcome_rc;
}

static int stub_send_batch(void *ctx, const struct aip_canary_req *req,
			   unsigned long long token,
			   struct aip_canary_ack *ack)
{
	struct stub_io *s = ctx;
	const struct stub_step *st;

	if (s->ncall >= s->nscript) {
		printf("FAIL: stub_send_batch: script exhausted\n");
		fails++;
		return -1;
	}
	st = &s->script[s->ncall++];
	s->last_req = *req;
	s->last_token = token;
	if (st->rc != 0)
		return st->rc;
	*ack = st->ack;
	return 0;
}

static void stub_install(struct aip_canary *c, struct stub_io *s)
{
	memset(s, 0, sizeof(*s));
	c->io.ctx = s;
	c->io.read_control = stub_read_control;
	c->io.read_safety_clamped = stub_read_sc;
	c->io.write_confirm = stub_write_confirm;
	c->io.write_outcome = stub_write_outcome;
	c->io.send_batch = stub_send_batch;
}

static void stub_ctl(struct stub_io *s, const char *knob, long long cur)
{
	snprintf(s->ctl[s->nctl].knob, sizeof(s->ctl[0].knob), "%s", knob);
	s->ctl[s->nctl].cur = cur;
	s->nctl++;
}

/* ================= 状态机测试脚手架 =================
 * 手工构造 canary（不走 aip_canary_open=不触真 netlink）；时标基
 * T0=1000000ms，rollback=100ms（conf 下限），confirm 节拍=1s，
 * interval=1s。 */

#define T0		1000000LL
#define ROLLBACK_MS	100LL
#define CADENCE_MS	1000LL

static void canary_test_init(struct aip_canary *c, struct stub_io *s,
			     int reg_ok)
{
	memset(c, 0, sizeof(*c));
	c->enabled = 1;
	c->reg_ok = reg_ok;
	c->state = AIP_CANARY_IDLE;
	c->rollback_ms = ROLLBACK_MS;
	c->confirm_sec_ms = CADENCE_MS;
	c->min_interval_ms = CADENCE_MS;
	stub_install(c, s);
}

static void mk_hit(struct aip_decision *d, uint32_t action, int32_t param,
		   int64_t feat_val, int64_t rule_idx)
{
	memset(d, 0, sizeof(*d));
	d->action = action;
	d->param = param;
	d->feat_val = feat_val;
	d->rule_idx = rule_idx;
	d->flags = AIP_DF_HIT;
}

static void mk_nohit(struct aip_decision *d)
{
	memset(d, 0, sizeof(*d));
	d->rule_idx = -1;
}

static void mk_vec(struct aip_fvec *v, uint32_t psi)
{
	memset(v, 0, sizeof(*v));
	v->seq = 7;
	v->ts = 123456789;
	v->psi_mem_some = psi;
	v->iowait_pct = 5;
	v->valid_bits = 0xF;
}

/* 脚本一步=ack executed=1 id=<id> */
static void stub_step_ok(struct stub_io *s, unsigned long long id)
{
	s->script[s->nscript].rc = 0;
	s->script[s->nscript].ack.ai_err = 0;
	s->script[s->nscript].ack.executed = 1;
	s->script[s->nscript].ack.decision_id = id;
	s->nscript++;
}

int main(void)
{
	struct aip_canary c;
	struct stub_io s;
	struct aip_decision d;
	struct aip_fvec v;
	struct aip_knob_def kdef;
	int64_t val;
	int exec;

	/* ================= 1) §3 映射纯函数 ================= */
	CHECK(aip_canary_lookup(AIP_ACT_RECLAIM_AGGRESSIVE, &kdef) == 0 &&
	      strcmp(kdef.knob, "mm.swappiness") == 0 && kdef.min == 0 &&
	      kdef.max == 100 && kdef.def == 60 &&
	      kdef.formula == AIP_KNOB_F_PARAM,
	      "lookup RECLAIM -> mm.swappiness");
	CHECK(aip_canary_lookup(AIP_ACT_SCHED_COMPENSATE, &kdef) == 0 &&
	      strcmp(kdef.knob, "sched.timeslice") == 0 && kdef.min == 1 &&
	      kdef.max == 1000 && kdef.def == 20 &&
	      kdef.formula == AIP_KNOB_F_PCT,
	      "lookup SCHED -> sched.timeslice (PCT)");
	CHECK(aip_canary_lookup(AIP_ACT_READAHEAD_BOOST, &kdef) == 0 &&
	      strcmp(kdef.knob, "mm.readahead") == 0 && kdef.max == 4096 &&
	      kdef.formula == AIP_KNOB_F_PARAM,
	      "lookup READAHEAD -> mm.readahead");
	CHECK(aip_canary_lookup(0, &kdef) != 0 &&
	      aip_canary_lookup(4, &kdef) != 0 &&
	      aip_canary_lookup(99, &kdef) != 0,
	      "whitelist rejects NONE/unknown/远期 action");

	CHECK(aip_canary_map_op(AIP_ACT_RECLAIM_AGGRESSIVE, 100, 0, &kdef,
				&val) == 0 && val == 100,
	      "swappiness value=param(100)");
	CHECK(aip_canary_map_op(AIP_ACT_READAHEAD_BOOST, 512, 0, &kdef,
				&val) == 0 && val == 512,
	      "readahead value=param(512)");
	CHECK(aip_canary_map_op(AIP_ACT_READAHEAD_BOOST, 5000, 0, &kdef,
				&val) == 0 && val == 4096,
	      "readahead param clamp high");
	/* sched.timeslice=clamp(cur*(100+param)/100,1,1000) */
	CHECK(aip_canary_map_op(AIP_ACT_SCHED_COMPENSATE, 10, 20, &kdef,
				&val) == 0 && val == 22,
	      "timeslice 20*(100+10)/100=22");
	CHECK(aip_canary_map_op(AIP_ACT_SCHED_COMPENSATE, 20, 990, &kdef,
				&val) == 0 && val == 1000,
	      "timeslice clamp high 990*1.2=1188->1000");
	CHECK(aip_canary_map_op(AIP_ACT_SCHED_COMPENSATE, -50, 5, &kdef,
				&val) == 0 && val == 2,
	      "timeslice 5*(100-50)/100=2");
	CHECK(aip_canary_map_op(AIP_ACT_SCHED_COMPENSATE, -90, 5, &kdef,
				&val) == 0 && val == 1,
	      "timeslice 5*10/100=0->clamp 1");
	CHECK(aip_canary_map_op(AIP_ACT_SCHED_COMPENSATE, -100, 20, &kdef,
				&val) == 0 && val == 2,
	      "timeslice param=-100 钳 -90：20*10/100=2");

	/* ================= 2) §2.4 outcome 优先级 ================= */
	CHECK(aip_canary_outcome(1, 1, 1, 1) == AIP_CANARY_OUT_FAILED,
	      "outcome FAILED wins all");
	CHECK(aip_canary_outcome(0, 1, 1, 1) == AIP_CANARY_OUT_WORSE,
	      "outcome WORSE > PARTIAL/SUCCESS");
	CHECK(aip_canary_outcome(0, 1, 0, 1) == AIP_CANARY_OUT_PARTIAL,
	      "outcome PARTIAL > SUCCESS");
	CHECK(aip_canary_outcome(0, 0, 0, 1) == AIP_CANARY_OUT_SUCCESS,
	      "outcome abated->SUCCESS");
	CHECK(aip_canary_outcome(0, 0, 0, 0) == 0,
	      "outcome nothing->UNKNOWN(0)");

	/* ================= 3) §2.2 闸门纯函数 ================= */
	CHECK(aip_canary_gate(0, 0, 0, 1, 999999, 0) == AIP_GATE_NONE,
	      "gate inactive->NONE");
	CHECK(aip_canary_gate(1, 0, 0, 0, 999999, 0) == AIP_GATE_NONE,
	      "gate action NONE->NONE");
	CHECK(aip_canary_gate(1, 0, 1, 1, 999999, 0) == AIP_GATE_SKIP_STALE,
	      "gate stale first");
	CHECK(aip_canary_gate(1, 0, 1, 1, 999999, 0) == AIP_GATE_SKIP_STALE,
	      "gate stale even while armed");
	CHECK(aip_canary_gate(1, 1, 0, 1, 999999, 0) == AIP_GATE_SKIP_BUSY,
	      "gate armed->BUSY");
	CHECK(aip_canary_gate(1, 0, 0, 1, 500, 1000) ==
	      AIP_GATE_SKIP_INTERVAL, "gate interval <");
	CHECK(aip_canary_gate(1, 0, 0, 1, 1000, 1000) ==
	      AIP_GATE_DISPATCH, "gate interval == boundary dispatch");

	/* ================= 4) M1 等价：ENABLED=0 ================= */
	{
		struct aip_conf conf;

		aip_conf_defaults(&conf);
		CHECK(conf.canary_enabled == 0 &&
		      conf.canary_rollback_ms == 30000 &&
		      conf.canary_confirm_sec == 10 &&
		      conf.canary_min_interval_sec == 30 &&
		      conf.canary_table[0] == '\0',
		      "canary conf defaults (§6)");
	}
	canary_test_init(&c, &s, 1);
	c.enabled = 0;
	stub_ctl(&s, "mm.swappiness", 60);
	stub_step_ok(&s, 1);
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	mk_vec(&v, 500);
	exec = -1;
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	CHECK(exec == 0 && s.ncall == 0 && c.dispatched == 0 &&
	      c.skip_stale == 0 && c.skip_busy == 0 &&
	      c.skip_interval == 0 && c.errors == 0,
	      "ENABLED=0: 零计数零下发（M1 等价）");

	/* ================= 5) S1 下发→ARMED 记账 ================= */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	stub_step_ok(&s, 77);
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	mk_vec(&v, 500);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	CHECK(exec == 1 && c.state == AIP_CANARY_ARMED &&
	      c.dispatched == 1 && c.armed_id == 77 &&
	      c.armed_pre == 60 && c.armed_value == 100 &&
	      c.armed_feat0 == 500 &&
	      c.armed_feat == AIP_F_PSI_MEM_SOME,
	      "S1 dispatch -> ARMED 记账");
	CHECK(strcmp(s.last_req.knob, "mm.swappiness") == 0 &&
	      s.last_req.value == 100 &&
	      s.last_req.auto_rollback_ms == ROLLBACK_MS &&
	      s.last_req.trace_lo == v.seq &&
	      s.last_req.intent_id == 0 &&
	      s.last_req.domain == 2,	/* MM 域（§3 表） */
	      "S1 req 字段（knob/value/rollback/trace/intent/domain）");
	CHECK(c.armed_deadline_ms == T0 + ROLLBACK_MS &&
	      c.next_settle_ms == T0 + CADENCE_MS,
	      "S1 deadline/next_settle");

	/* ================= 6) S2 abated→confirm→SUCCESS ================= */
	s.ctl[0].cur = 100;		/* 内核已应用 value */
	mk_nohit(&d);
	mk_vec(&v, 100);		/* psi 消散 */
	s.sc_id = 77; s.sc_val = 0; s.sc_rc = 0;
	aip_canary_decide_point(&c, &v, &d, 0, T0 + CADENCE_MS, &exec);
	CHECK(exec == 0 && c.state == AIP_CANARY_IDLE &&
	      c.confirmed == 1 && s.confirm_calls == 1 &&
	      s.confirm_id == 77 && s.outcome_calls == 1 &&
	      s.outcome_id == 77 && s.outcome_val == 1 &&
	      s.outcome_delta == 100 - 500,
	      "S2 abated -> confirm + outcome SUCCESS delta=-400");

	/* S7 interval 闸：结算后 999ms（<1000ms 间隔）再触发 */
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	mk_vec(&v, 500);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME,
				T0 + CADENCE_MS - 1, &exec);
	CHECK(exec == 0 && c.skip_interval == 1 && s.ncall == 1,
	      "S7 距上次下发<interval -> skip_interval");

	/* ================= 7) S3 到期回退→FAILED ================= */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	stub_step_ok(&s, 78);
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 600, 0);
	mk_vec(&v, 600);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	CHECK(exec == 1 && c.state == AIP_CANARY_ARMED,
	      "S3 dispatch armed");
	/* 未消+未恢复（cur 仍=value）：继续等 */
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 600, 0);
	mk_vec(&v, 600);
	s.ctl[0].cur = 100;
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME,
				T0 + CADENCE_MS, &exec);
	CHECK(c.state == AIP_CANARY_ARMED && s.outcome_calls == 0,
	      "S3 未消未回退 -> 继续等");
	/* 到期+恢复（cur==pre）→ FAILED（middle 拍已把结算节拍重排
	 * 至 T0+2×CADENCE——此拍到达才结算；传 no-hit 决策——settle
	 * 回 IDLE 后同拍 gate 会按反馈闭环再下发，非本节断言面） */
	s.ctl[0].cur = 60;
	mk_nohit(&d);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME,
				T0 + 2 * CADENCE_MS, &exec);
	CHECK(c.state == AIP_CANARY_IDLE && c.rolled_back == 1 &&
	      s.confirm_calls == 0 && s.outcome_calls == 1 &&
	      s.outcome_val == 3,
	      "S3 到期 current==pre -> FAILED + rolled_back");

	/* ================= 8) S4 abated+safety_clamped→PARTIAL ======== */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	stub_step_ok(&s, 79);
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	mk_vec(&v, 500);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	mk_nohit(&d);
	mk_vec(&v, 100);
	s.ctl[0].cur = 100;
	s.sc_id = 79; s.sc_val = 1; s.sc_rc = 0;
	aip_canary_decide_point(&c, &v, &d, 0, T0 + CADENCE_MS, &exec);
	CHECK(c.state == AIP_CANARY_IDLE && c.confirmed == 1 &&
	      s.outcome_val == 2,
	      "S4 safety_clamped -> PARTIAL");

	/* ================= 9) S5 特征恶化→WORSE ================= */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	stub_step_ok(&s, 80);
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	mk_vec(&v, 500);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	mk_nohit(&d);
	mk_vec(&v, 700);		/* 触发特征比 feat0 更差 */
	s.ctl[0].cur = 100;
	s.sc_id = 80; s.sc_val = 0; s.sc_rc = 0;
	aip_canary_decide_point(&c, &v, &d, 0, T0 + CADENCE_MS, &exec);
	CHECK(c.state == AIP_CANARY_IDLE && s.outcome_val == 4 &&
	      s.outcome_delta == 200,
	      "S5 delta=+200 同向变差 -> WORSE");

	/* ================= 10) S8 ARMED 中 skip_busy / stale ========= */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	stub_step_ok(&s, 81);
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	mk_vec(&v, 500);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	/* 未到结算节拍：ARMED 中再触发 -> skip_busy */
	mk_hit(&d, AIP_ACT_SCHED_COMPENSATE, 10, 20000000, 1);
	aip_canary_decide_point(&c, &v, &d, AIP_F_LAT_EWMA_NS,
				T0 + 100, &exec);
	CHECK(exec == 0 && c.skip_busy == 1 && s.ncall == 1,
	      "S8 ARMED 中再触发 -> skip_busy");
	/* stale 命中 -> skip_stale（优先于 busy） */
	mk_hit(&d, AIP_ACT_SCHED_COMPENSATE, 10, 20000000, 1);
	d.flags |= AIP_DF_STALE;
	aip_canary_decide_point(&c, &v, &d, AIP_F_LAT_EWMA_NS,
				T0 + 200, &exec);
	CHECK(c.skip_stale == 1 && c.skip_busy == 1,
	      "S8 stale 优先于 busy 计 skip_stale");

	/* ================= 11) S9/S10 传输失败/零执行 ================= */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "sched.timeslice", 20);
	s.script[0].rc = -1;
	s.nscript = 1;
	mk_hit(&d, AIP_ACT_SCHED_COMPENSATE, 10, 20000000, 1);
	aip_canary_decide_point(&c, &v, &d, AIP_F_LAT_EWMA_NS, T0, &exec);
	CHECK(exec == 0 && c.errors == 1 && c.state == AIP_CANARY_IDLE,
	      "S9 传输失败 -> errors++ 保持 IDLE");
	CHECK(s.last_req.value == 22,
	      "S9 下发值=sched.timeslice 20*1.1=22（pre 读作公式基）");

	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	s.script[0].rc = 0;
	s.script[0].ack.ai_err = 0;
	s.script[0].ack.executed = 0;	/* 零执行 ack */
	s.nscript = 1;
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	CHECK(exec == 0 && c.errors == 1 && c.state == AIP_CANARY_IDLE,
	      "S10 ack.executed==0 -> errors++ 不 ARMED");

	/* ================= 12) S11 -EAGAIN 两段重试 ================= */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	s.script[0].rc = 0;
	s.script[0].ack.ai_err = -EAGAIN;
	s.script[0].ack.token = 0xbeefULL;
	s.script[0].ack.executed = 0;
	s.script[1].rc = 0;
	s.script[1].ack.ai_err = 0;
	s.script[1].ack.executed = 1;
	s.script[1].ack.decision_id = 99;
	s.nscript = 2;
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	mk_vec(&v, 500);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	CHECK(exec == 1 && s.ncall == 2 && s.last_token == 0xbeefULL &&
	      c.state == AIP_CANARY_ARMED && c.armed_id == 99,
	      "S11 EAGAIN -> token 重试一次 -> ARMED(id=99)");

	/* 重试仍 EAGAIN -> errors（只重试一次） */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	s.script[0].ack.ai_err = -EAGAIN;
	s.script[0].ack.token = 1;
	s.script[0].rc = 0;
	s.script[1] = s.script[0];
	s.nscript = 2;
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	CHECK(exec == 0 && c.errors == 1 && s.ncall == 2 &&
	      c.state == AIP_CANARY_IDLE,
	      "S11b 重试仍 EAGAIN -> errors++（恰一次重试）");

	/* ================= 13) S12 REG 降级=零计数 ================= */
	canary_test_init(&c, &s, 0);	/* enabled 但 reg_ok=0 */
	stub_ctl(&s, "mm.swappiness", 60);
	stub_step_ok(&s, 1);
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	CHECK(exec == 0 && s.ncall == 0 && c.dispatched == 0 &&
	      c.skip_stale == 0 && c.skip_busy == 0 &&
	      c.skip_interval == 0 && c.errors == 0,
	      "S12 reg 失败=不活跃：零计数零下发（影子继续）");

	/* ================= 14) S13 dispatch 前 pre 读失败 ============= */
	canary_test_init(&c, &s, 1);
	stub_step_ok(&s, 1);		/* ctl 表空=read 失败 */
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	CHECK(exec == 0 && c.errors == 1 && s.ncall == 0,
	      "S13 pre 读失败 -> errors++ 不下发");

	/* ================= 15) S14 confirm 失败重试 ================= */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	stub_step_ok(&s, 82);
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	mk_vec(&v, 500);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	s.confirm_rc = -1;
	mk_nohit(&d);
	mk_vec(&v, 100);
	s.ctl[0].cur = 100;
	s.sc_id = 82; s.sc_val = 0; s.sc_rc = 0;
	aip_canary_decide_point(&c, &v, &d, 0, T0 + CADENCE_MS, &exec);
	CHECK(c.state == AIP_CANARY_ARMED && c.errors == 1 &&
	      c.confirmed == 0 && s.outcome_calls == 0,
	      "S14 confirm 写失败 -> 保持 ARMED 计 errors");
	s.confirm_rc = 0;
	aip_canary_decide_point(&c, &v, &d, 0, T0 + 2 * CADENCE_MS, &exec);
	CHECK(c.state == AIP_CANARY_IDLE && c.confirmed == 1 &&
	      s.outcome_val == 1,
	      "S14b 下拍重试 confirm 成功 -> SUCCESS");

	/* ================= 16) 结算期 control 读失败 ================ */
	canary_test_init(&c, &s, 1);
	stub_ctl(&s, "mm.swappiness", 60);
	stub_step_ok(&s, 83);
	mk_hit(&d, AIP_ACT_RECLAIM_AGGRESSIVE, 100, 500, 0);
	mk_vec(&v, 500);
	aip_canary_decide_point(&c, &v, &d, AIP_F_PSI_MEM_SOME, T0, &exec);
	s.nctl = 0;			/* 结算读失败 */
	mk_nohit(&d);
	aip_canary_decide_point(&c, &v, &d, 0, T0 + CADENCE_MS, &exec);
	CHECK(c.state == AIP_CANARY_ARMED && c.errors == 1 &&
	      c.confirmed == 0,
	      "S15 结算 control 读失败 -> errors++ 继续等");

	if (fails) {
		printf("test_canary: %d failures (%d checks)\n", fails,
		       checks);
		return 1;
	}
	printf("test_canary: OK (%d checks)\n", checks);
	return 0;
}
