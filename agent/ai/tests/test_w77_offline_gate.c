// SPDX-License-Identifier: GPL-2.0
/*
 * test_w77_offline_gate.c - W77：离线/本地路由不绕过 W74 租约
 *
 * 证明：AIKERNEL_ROUTE=local/cloud/auto 与离线意图层只影响“用哪个
 * 模型”，D 级决策完全由 ai_lease_decide 决定：
 *   - NONE：D1 自动、D2/D3 CONFIRM、D4 CONFIRM_D4（非 root DENY）；
 *   - -y（ephemeral）：D2 ALLOW、D3 CONFIRM；
 *   - 同一动作在 local/cloud/auto 三种路由下结论一致（0 绕过）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "policy/ai_lease.h"
#include "policy/ai_user_policy.h"

static int g_pass, g_fail;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (cond)
		g_pass++;
	else
		g_fail++;
}

static void action(struct ai_lease_action *a, enum ai_danger d)
{
	memset(a, 0, sizeof(*a));
	a->tool = "file_delete";
	a->domain = "fs:/tmp";
	a->target = "/tmp/w77-test";
	a->args_json = "{\"path\":\"/tmp/w77-test\"}";
	a->risk_str = "W2";
	a->risk = AI_RISK_W1;      /* 外层档位放行，决策只看 D 级/租约 */
	a->danger = d;
	a->is_exec = 1;
}

static enum ai_lease_decision decide(enum ai_lease_mode mode,
				     enum ai_danger danger)
{
	struct ai_lease_ctx ctx;
	struct ai_lease_action act;
	struct ai_lease_verdict v;

	memset(&ctx, 0, sizeof(ctx));
	ctx.mode = mode;
	if (mode == AI_LEASE_MODE_EPHEMERAL) {
		snprintf(ctx.lease.lease_id, sizeof(ctx.lease.lease_id),
			 "L-test");
		ctx.lease.risk_ceiling = AI_D2;
		ctx.lease.expires_at = (long long)time(NULL) + 600;
		ctx.lease.has_issued_at = 1;
		ctx.lease.issued_at = (long long)time(NULL);
	}
	action(&act, danger);
	memset(&v, 0, sizeof(v));
	ai_lease_decide(&ctx, getuid(), &act, (long long)time(NULL), &v);
	return v.decision;
}

static void matrix_for(const char *route)
{
	char name[256];

	setenv("AIKERNEL_ROUTE", route, 1);
	snprintf(name, sizeof(name), "route=%s: D1 自动", route);
	expect(decide(AI_LEASE_MODE_NONE, AI_D1) == AI_LEASE_ALLOW, name);
	snprintf(name, sizeof(name), "route=%s: D2 需确认（离线不绕过）",
		 route);
	expect(decide(AI_LEASE_MODE_NONE, AI_D2) == AI_LEASE_CONFIRM, name);
	snprintf(name, sizeof(name), "route=%s: D3 需确认", route);
	expect(decide(AI_LEASE_MODE_NONE, AI_D3) == AI_LEASE_CONFIRM, name);
	snprintf(name, sizeof(name), "route=%s: D4 强确认/非 root 拒绝",
		 route);
	{
		enum ai_lease_decision d = decide(AI_LEASE_MODE_NONE, AI_D4);

		expect(d == AI_LEASE_CONFIRM_D4 || d == AI_LEASE_DENY,
		       name);
	}
	snprintf(name, sizeof(name), "route=%s: -y D2 放行", route);
	expect(decide(AI_LEASE_MODE_EPHEMERAL, AI_D2) == AI_LEASE_ALLOW,
	       name);
	snprintf(name, sizeof(name), "route=%s: -y D3 仍确认", route);
	expect(decide(AI_LEASE_MODE_EPHEMERAL, AI_D3) == AI_LEASE_CONFIRM,
	       name);
}

int main(void)
{
	matrix_for("auto");
	matrix_for("local");
	matrix_for("cloud");
	unsetenv("AIKERNEL_ROUTE");

	printf("== test_w77_offline_gate: %d PASS, %d FAIL ==\n",
	       g_pass, g_fail);
	return g_fail ? 1 : 0;
}
