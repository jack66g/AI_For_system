/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_canary.c - AIPD-M2 金丝雀实现（设计册 §2/§3）
 *
 * 纯核（lookup/map_value/outcome/gate）+ 状态机（decide_point：先
 * ARMED 结算后闸门下发）+ 生产 IO（真 netlink ACT_BATCH 单元组、
 * /proc/ai/control、/proc/ai/decisions、policy confirm/outcome）。
 * 测试经 struct aip_canary_io 换桩（test_canary.c）——本文件不持
 * 任何全局可变状态（除生产 netlink client 单例）。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netlink/ai_netlink_client.h"

#include "aip_canary.h"
#include "aip_util.h"

/* ================= §3 冻结映射（三行白名单硬编码） =================
 * 值域/默认=内核注册实证（ai_mm.c:420/425、ai_sched.c:700）：
 *   mm.swappiness  MM=2   0..100   def 60   value=param
 *   sched.timeslice SCHED=1 1..1000 def 20  value=clamp(cur*(100+param)/100)
 *   mm.readahead   MM=2   0..4096  def 128  value=param
 * 全部 AI_CTRL_F_REAL，内核端硬 clamp（纵深防御第二层）；本表=第一层。
 * sec.* 旋钮零接触（§3 边界裁定）。 */
const struct aip_knob_def aip_canary_whitelist[3] = {
	{ AIP_ACT_RECLAIM_AGGRESSIVE, "mm.swappiness", 2,
	  0, 100, 60, AIP_KNOB_F_PARAM },
	{ AIP_ACT_SCHED_COMPENSATE, "sched.timeslice", 1,
	  1, 1000, 20, AIP_KNOB_F_PCT },
	{ AIP_ACT_READAHEAD_BOOST, "mm.readahead", 2,
	  0, 4096, 128, AIP_KNOB_F_PARAM },
};

/* ================= 纯函数 ================= */

int aip_canary_lookup(uint32_t action, struct aip_knob_def *kdef)
{
	for (int i = 0; i < AIP_CANARY_WHITELIST_N; i++) {
		if (aip_canary_whitelist[i].action == action) {
			*kdef = aip_canary_whitelist[i];
			return 0;
		}
	}
	return -1;
}

int aip_canary_map_value(const struct aip_knob_def *kdef, int32_t param,
			 int64_t cur, int64_t *value)
{
	int64_t lo, v;

	if (!kdef || !value || !kdef->knob)
		return -1;
	if (kdef->formula == AIP_KNOB_F_PARAM) {
		v = (int64_t)param;
	} else if (kdef->formula == AIP_KNOB_F_PCT) {
		int64_t pct = (int64_t)param;

		/* 中间量防溢出：param 先钳 ±90（表内现值 10——越界=表
		 * 越权，按边界档执行并如实 clamp） */
		pct = aip_canary_clamp_i64(pct, -90, 90);
		v = cur * (100 + pct) / 100;
	} else {
		return -1;
	}
	/* F_PCT 下界=max(min,1) 已由注册值域（1..1000）保证；统一钳 */
	lo = kdef->min;
	if (lo < 1)
		lo = 1;
	*value = aip_canary_clamp_i64(v, lo, kdef->max);
	return 0;
}

int aip_canary_map_op(uint32_t action, int32_t param, int64_t cur,
		      struct aip_knob_def *kdef, int64_t *value)
{
	if (aip_canary_lookup(action, kdef) != 0)
		return -1;
	return aip_canary_map_value(kdef, param, cur, value);
}

int aip_canary_outcome(int rolled_back, int safety_clamped, int worse,
		       int abated)
{
	if (rolled_back)
		return AIP_CANARY_OUT_FAILED;
	if (worse)
		return AIP_CANARY_OUT_WORSE;
	if (safety_clamped)
		return AIP_CANARY_OUT_PARTIAL;
	if (abated)
		return AIP_CANARY_OUT_SUCCESS;
	return 0;
}

enum aip_canary_gate aip_canary_gate(int active, int armed, int stale,
				     uint32_t action,
				     long long since_last_ms,
				     long long min_interval_ms)
{
	if (!active || action == AIP_ACT_NONE)
		return AIP_GATE_NONE;
	if (stale)
		return AIP_GATE_SKIP_STALE;
	if (armed)
		return AIP_GATE_SKIP_BUSY;
	if (since_last_ms < min_interval_ms)
		return AIP_GATE_SKIP_INTERVAL;
	return AIP_GATE_DISPATCH;
}

/* ================= 生产 IO（netlink/sysfs/proc 薄包装） ================= */

/* 生产 ctx：netlink client 单例（open 时分配生命周期=进程） */
struct aip_canary_nlctx {
	struct ai_nl_client cli;
	int in_use;
};

static struct aip_canary_nlctx g_nl;

static int canary_io_read_control(void *ctx, const char *knob, int64_t *cur)
{
	FILE *f;
	char line[512];

	(void)ctx;
	f = fopen("/proc/ai/control", "r");
	if (!f)
		return -1;
	/* 行格式（ai_procfs.c ai_proc_control_show）：
	 *   "<name> domain=<u> [real]|[reserved] min=<ll> max=<ll> "
	 *   "current=<ll> default=<ll>" */
	while (fgets(line, sizeof(line), f)) {
		char name[64], kind[32];
		unsigned dom;
		long long mn, mx, cv, dv;

		if (sscanf(line, "%63s domain=%u %31s min=%lld max=%lld "
			   "current=%lld default=%lld",
			   name, &dom, kind, &mn, &mx, &cv, &dv) != 7)
			continue;
		if (strcmp(name, knob) != 0)
			continue;
		fclose(f);
		*cur = cv;
		return 0;
	}
	fclose(f);
	return -1;
}

static int canary_io_read_safety_clamped(void *ctx,
					 unsigned long long decision_id)
{
	FILE *f;
	char line[1024];
	char idp[64];

	(void)ctx;
	f = fopen("/proc/ai/decisions", "r");
	if (!f)
		return -1;
	snprintf(idp, sizeof(idp), "id=%llu ", decision_id);
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, idp, strlen(idp)) != 0)
			continue;
		{
			const char *p = strstr(line, "safety_clamped=");

			fclose(f);
			if (!p)
				return -1;
			return atoi(p + 15) == 1 ? 1 : 0;
		}
	}
	fclose(f);
	return -1;
}

static int canary_io_write_confirm(void *ctx, unsigned long long decision_id)
{
	char buf[32];
	int fd, len;

	(void)ctx;
	len = snprintf(buf, sizeof(buf), "%llu\n", decision_id);
	if (len <= 0 || (size_t)len >= sizeof(buf))
		return -1;
	fd = open("/sys/kernel/ai/policy/confirm", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	/* sysfs store 成功可返 0<count（K2 confirm 实测返 0）；
	 * 负值=内核 -errno 映射——只按负值判败（rig 真机实锤）。 */
	if (write(fd, buf, (size_t)len) < 0) {
		int er = errno;
		close(fd);
		errno = er;
		return -1;
	}
	close(fd);
	return 0;
}

static int canary_io_write_outcome(void *ctx, unsigned long long decision_id,
				   unsigned outcome, int64_t delta)
{
	char buf[96];
	int fd, len;

	(void)ctx;
	/* 内核 ai_outcome_store sscanf "%llu,%u,%lld"（K11 同款面） */
	len = snprintf(buf, sizeof(buf), "%llu,%u,%lld", decision_id,
		       outcome, (long long)delta);
	if (len <= 0 || (size_t)len >= sizeof(buf))
		return -1;
	fd = open("/sys/kernel/ai/policy/outcome", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	/* sysfs store 成功可返 0<count（K2 confirm 实测返 0）；
	 * 负值=内核 -errno 映射——只按负值判败（rig 真机实锤）。 */
	if (write(fd, buf, (size_t)len) < 0) {
		int er = errno;
		close(fd);
		errno = er;
		return -1;
	}
	close(fd);
	return 0;
}

/*
 * 单次 ACT_BATCH（单元组）。AI_BATCH opts：AUTO_ROLLBACK_MS=conf 窗、
 * AGENT=AI_AGENT_AIPD（K3 自报面——REG 载荷无 agent 字段的补偿承载）、
 * TRACE_LO=trigger seq、INTENT=rule_idx（§2.2）；TRACE_HI=0 内核铸造。
 * confirm_token 透传（两段重试由状态机驱动）。
 */
static int canary_io_send_batch(void *ctx, const struct aip_canary_req *req,
				unsigned long long confirm_token,
				struct aip_canary_ack *ack)
{
	struct aip_canary_nlctx *nl = ctx;
	struct ai_nl_batch_op op;
	struct ai_nl_batch_opts opts;
	struct ai_nl_batch_ack a;
	int kern_err = 0, rc;

	memset(&op, 0, sizeof(op));
	snprintf(op.param, sizeof(op.param), "%s", req->knob);
	op.value = (__u64)req->value;
	op.pid = 0;			/* 全局 REAL 旋钮（§9.3 作用域） */
	memset(&opts, 0, sizeof(opts));
	opts.auto_rollback_ms = req->auto_rollback_ms;
	opts.agent = AI_AGENT_AIPD;
	opts.confirm_token = confirm_token;
	opts.intent_id = req->intent_id;
	opts.trace_lo = req->trace_lo;

	memset(&a, 0, sizeof(a));
	rc = ai_nl_send_act_batch(&nl->cli, &op, 1, &opts, &a, &kern_err);
	if (rc != AI_OK) {
		aip_warn_ratelimit("canary-batch", 60000,
				   "canary ACT_BATCH rc=%d kern_err=%d: %s",
				   rc, kern_err,
				   ai_nl_errno_hint(kern_err) ?
				   ai_nl_errno_hint(kern_err) :
				   strerror(errno));
		return -1;
	}
	ack->decision_id = a.decision_id;
	ack->executed = a.executed;
	ack->ai_err = a.ai_err;
	ack->token = a.token;
	return 0;
}

static const struct aip_canary_io aip_canary_io_prod = {
	NULL,
	canary_io_read_control,
	canary_io_read_safety_clamped,
	canary_io_write_confirm,
	canary_io_write_outcome,
	canary_io_send_batch,
};

/* ================= 生命周期 ================= */

void aip_canary_open(struct aip_canary *c, const struct aip_conf *conf)
{
	memset(c, 0, sizeof(*c));
	c->io = aip_canary_io_prod;
	c->io.ctx = &g_nl;
	c->enabled = conf->canary_enabled ? 1 : 0;
	c->rollback_ms = conf->canary_rollback_ms;
	c->confirm_sec_ms = conf->canary_confirm_sec * 1000;
	c->min_interval_ms = conf->canary_min_interval_sec * 1000;
	c->state = AIP_CANARY_IDLE;
	if (!c->enabled)
		return;			/* M1 等价：零输出零动作 */

	if (ai_nl_client_open(&g_nl.cli) != AI_OK) {
		/* 诚实降级（§2.1）：恰一条 ERROR + reg_ok=0 + 存活 */
		aip_log("ERROR: canary REG degraded: NETLINK_AI client open "
			"failed (no AI kernel?) — shadow continues, "
			"canary_reg_ok=0");
		c->reg_ok = 0;
		return;
	}
	g_nl.in_use = 1;
	{
		__s32 ai_err = 0;
		__u32 count = 0;
		int kern_err = 0;
		int rc = ai_nl_send_reg(&g_nl.cli, 0, &ai_err, &count,
					&kern_err);

		if (rc == AI_OK && ai_err == AI_OK) {
			c->reg_ok = 1;
			aip_log("canary: REG ok (agent=%d via per-batch "
				"attr, registered=%u)", AI_AGENT_AIPD,
				count);
		} else {
			aip_log("ERROR: canary REG degraded: rc=%d ai_err=%d "
				"kern_err=%d (%s) — shadow continues, "
				"canary_reg_ok=0",
				rc, ai_err, kern_err,
				ai_nl_errno_hint(kern_err) ?
				ai_nl_errno_hint(kern_err) :
				strerror(errno));
			c->reg_ok = 0;
		}
	}
}

void aip_canary_close(struct aip_canary *c)
{
	if (g_nl.in_use) {
		ai_nl_client_close(&g_nl.cli);
		g_nl.in_use = 0;
	}
	c->reg_ok = 0;
}

/* ================= 状态机 ================= */

/* 结算时触发特征现值−feat0（§2.3；取值失败=0 delta=诚实降档） */
static int64_t settle_delta(const struct aip_canary *c,
			    const struct aip_fvec *v)
{
	int64_t now_val = 0;

	if (aip_feat_value(v, c->armed_feat, &now_val) != 0)
		return 0;
	return now_val - c->armed_feat0;
}

/* §2.3 ARMED 观察（节拍 CONFIRM_SEC 上限；由 decide_point 每拍先调） */
static void canary_settle(struct aip_canary *c, const struct aip_fvec *v,
			  const struct aip_decision *d, long long now_ms)
{
	int64_t cur = 0;
	int abated;

	if (c->state != AIP_CANARY_ARMED || now_ms < c->next_settle_ms)
		return;
	if (c->io.read_control(c->io.ctx, c->armed_kdef.knob, &cur) != 0) {
		c->errors++;
		aip_warn_ratelimit("canary-settle-ctl", 60000,
				   "canary settle: read %s failed: %s",
				   c->armed_kdef.knob, strerror(errno));
		c->next_settle_ms = now_ms + c->confirm_sec_ms;
		return;
	}
	abated = !(d->flags & AIP_DF_HIT);
	if (now_ms >= c->armed_deadline_ms && cur == c->armed_pre) {
		/* 到期未消 + K2 定时器已恢复（current==pre）→ FAILED */
		int64_t delta = settle_delta(c, v);

		if (c->io.write_outcome(c->io.ctx, c->armed_id,
					AIP_CANARY_OUT_FAILED, delta) != 0) {
			c->errors++;
			aip_warn_ratelimit("canary-outcome", 60000,
					   "canary outcome write failed: %s",
					   strerror(errno));
		}
		c->rolled_back++;
		aip_log("canary: decision=%llu rolled back (deadline, "
			"current=%lld==pre=%lld) — FAILED delta=%lld",
			c->armed_id, (long long)cur, (long long)c->armed_pre,
			(long long)delta);
		c->state = AIP_CANARY_IDLE;
		/* M2 防抖（rig v4/v5 实锤）：回退落拍常在持续命中行上，
		 * settle→IDLE 同拍 gate 会立即再下发——冷却戳前移
		 * 5×min_interval（未来戳→interval 负差=skip），兼作
		 * dispatch/rollback 反复抽动的 §6.2 安全节流 */
		c->last_dispatch_ms = now_ms + 5 * c->min_interval_ms;
		return;
	}
	if (!abated) {
		/* 未消且未回退：继续等（current 仍非 pre=未恢复/钳后应用） */
		c->next_settle_ms = now_ms + c->confirm_sec_ms;
		return;
	}
	/* condition abated → confirm → outcome 回填（§2.3/§2.4） */
	{
		int clamped = c->io.read_safety_clamped(c->io.ctx,
							c->armed_id);
		int64_t delta = settle_delta(c, v);
		int worse = delta > 0;	/* psi/iowait/lat 低=好：delta>0=恶化 */
		int outcome = aip_canary_outcome(0, clamped > 0, worse, 1);

		if (clamped < 0) {
			c->errors++;	/* 行缺失/读失败：按 0 结算+计数 */
			clamped = 0;
		}
		if (c->io.write_confirm(c->io.ctx, c->armed_id) != 0) {
			c->errors++;
			aip_warn_ratelimit("canary-confirm", 60000,
					   "canary confirm write failed: %s",
					   strerror(errno));
			c->next_settle_ms = now_ms + c->confirm_sec_ms;
			return;		/* confirm 未达：下拍重试 */
		}
		if (c->io.write_outcome(c->io.ctx, c->armed_id, outcome,
					delta) != 0) {
			c->errors++;	/* confirm 已持久；链上缺笔=计数 */
			aip_warn_ratelimit("canary-outcome", 60000,
					   "canary outcome write failed: %s",
					   strerror(errno));
		}
		c->confirmed++;
		aip_log("canary: decision=%llu confirmed outcome=%d "
			"delta=%lld (value=%lld persists, K2 native)",
			c->armed_id, outcome, (long long)delta,
			(long long)c->armed_value);
		c->state = AIP_CANARY_IDLE;
	}
}

void aip_canary_decide_point(struct aip_canary *c, const struct aip_fvec *v,
			     const struct aip_decision *d, uint32_t trig_feat,
			     long long now_ms, int *executed)
{
	struct aip_knob_def kdef;
	struct aip_canary_req req;
	struct aip_canary_ack ack;
	int64_t cur = 0, value = 0;
	enum aip_canary_gate g;

	*executed = 0;
	if (!c->enabled)
		return;

	/* §2.3：ARMED 结算先于新下发 */
	canary_settle(c, v, d, now_ms);

	g = aip_canary_gate(c->enabled && c->reg_ok,
			    c->state == AIP_CANARY_ARMED,
			    (d->flags & AIP_DF_STALE) != 0, d->action,
			    now_ms - c->last_dispatch_ms, c->min_interval_ms);
	switch (g) {
	case AIP_GATE_SKIP_STALE:
		c->skip_stale++;
		return;
	case AIP_GATE_SKIP_BUSY:
		c->skip_busy++;
		return;
	case AIP_GATE_SKIP_INTERVAL:
		c->skip_interval++;
		return;
	case AIP_GATE_NONE:
		return;
	case AIP_GATE_DISPATCH:
		break;
	}

	/* §3 映射（白名单+冻结公式；cur 兼作 pre 快照） */
	if (aip_canary_lookup(d->action, &kdef) != 0) {
		c->errors++;
		aip_warn_ratelimit("canary-wl", 60000,
				   "canary: action=%u outside whitelist "
				   "(table/frozen-map desync?)",
				   d->action);
		return;
	}
	if (c->io.read_control(c->io.ctx, kdef.knob, &cur) != 0) {
		c->errors++;
		aip_warn_ratelimit("canary-pre", 60000,
				   "canary: read %s current failed: %s",
				   kdef.knob, strerror(errno));
		return;
	}
	if (aip_canary_map_value(&kdef, d->param, cur, &value) != 0) {
		c->errors++;
		return;
	}

	memset(&req, 0, sizeof(req));
	snprintf(req.knob, sizeof(req.knob), "%s", kdef.knob);
	req.value = value;
	req.domain = kdef.domain;
	req.auto_rollback_ms = (uint32_t)c->rollback_ms;
	req.trace_lo = v->seq;
	req.intent_id = (uint64_t)d->rule_idx;

	memset(&ack, 0, sizeof(ack));
	if (c->io.send_batch(c->io.ctx, &req, 0, &ack) != 0) {
		c->errors++;
		return;
	}
	/* -EAGAIN(blast) → token 两段式重试一次（§2.2；k2batch 样例） */
	if (ack.ai_err == -EAGAIN && ack.token != 0) {
		struct aip_canary_ack retry;
		unsigned long long token = ack.token;

		memset(&retry, 0, sizeof(retry));
		if (c->io.send_batch(c->io.ctx, &req, token, &retry) != 0) {
			c->errors++;
			return;
		}
		ack = retry;
	}
	if (ack.ai_err != 0 || ack.executed == 0) {
		c->errors++;
		aip_warn_ratelimit("canary-exec", 60000,
				   "canary batch not executed (ai_err=%d "
				   "executed=%u)", ack.ai_err, ack.executed);
		return;
	}

	/* ARMED 记账（§2.2） */
	c->state = AIP_CANARY_ARMED;
	c->armed_id = ack.decision_id;
	c->armed_kdef = kdef;
	c->armed_pre = cur;
	c->armed_value = value;
	c->armed_feat0 = d->feat_val;
	c->armed_feat = trig_feat;
	c->armed_action = d->action;
	c->armed_deadline_ms = now_ms + c->rollback_ms;
	c->next_settle_ms = now_ms + c->confirm_sec_ms;
	c->last_dispatch_ms = now_ms;
	c->dispatched++;
	*executed = 1;
	aip_log("canary: dispatched %s=%lld (pre=%lld action=%u "
		"decision=%llu rollback=%lldms)",
		kdef.knob, (long long)value, (long long)cur, d->action,
		ack.decision_id, c->rollback_ms);
}
