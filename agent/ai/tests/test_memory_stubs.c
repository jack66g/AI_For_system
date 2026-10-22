// SPDX-License-Identifier: GPL-2.0
/*
 * test_memory_stubs.c - W66 记忆降级/边界回归的依赖桩
 *
 * 只桩 netlink 与策略闸门；SME 客户端用真实现（sme_client.c +
 * local_http.c），这样测试覆盖真实的连接失败/超时/HTTP 错误语义。
 */
#include <stddef.h>
#include <sys/types.h>

#include "netlink/ai_netlink_client.h"
#include "policy/ai_user_policy.h"

int ai_nl_client_open(struct ai_nl_client *cli)
{
	(void)cli;
	return -1;
}

void ai_nl_client_close(struct ai_nl_client *cli)
{
	(void)cli;
}

int ai_nl_send_act(struct ai_nl_client *cli, const struct ai_nl_act *req,
		   struct ai_nl_act_ack *ack, int *kern_err)
{
	(void)cli; (void)req; (void)ack; (void)kern_err;
	return -1;
}

int ai_nl_send_sense(struct ai_nl_client *cli,
		     __u32 cpu, __u32 max_records, __u32 format,
		     struct ai_nl_sense_ack *ack,
		     void *stream, size_t stream_cap, size_t *stream_len,
		     int *kern_err)
{
	(void)cli; (void)cpu; (void)max_records; (void)format; (void)ack;
	(void)stream; (void)stream_cap; (void)stream_len; (void)kern_err;
	return -1;
}

const char *ai_nl_errno_hint(int errno_val)
{
	(void)errno_val;
	return "(stub)";
}

int ai_policy_init(const char *conf_path)
{
	(void)conf_path;
	return 0;
}

int ai_policy_gate_reason(uid_t uid, const char *tool_name,
			  enum ai_tool_risk risk, const char *impact_desc,
			  const char *args_json,
			  enum ai_policy_gate_result *result)
{
	(void)uid; (void)tool_name; (void)risk; (void)impact_desc;
	(void)args_json;
	if (result)
		*result = AI_GATE_ALLOW;
	return 1;
}

/* W74：ai_lease.c 链接所需的策略符号（本测试不启用租约上下文） */
enum ai_policy_mode ai_policy_mode_for_uid(uid_t uid)
{
	(void)uid;
	return AI_POLICY_MODE_PRIVILEGED;
}

enum ai_policy_verdict ai_policy_check(uid_t uid, enum ai_tool_risk risk)
{
	(void)uid;
	return risk == AI_RISK_W2 ? AI_POLICY_NEED_CONFIRM :
				    AI_POLICY_ALLOW_AUTO;
}

int ai_policy_audit_ex(uid_t uid, enum ai_policy_mode mode,
		       const char *tool, const char *args,
		       const char *result, const char *lease_id,
		       const char *danger, const char *confirm_source)
{
	(void)uid; (void)mode; (void)tool; (void)args; (void)result;
	(void)lease_id; (void)danger; (void)confirm_source;
	return 0;
}

static int g_stub_plan_mode;

void ai_policy_set_plan_mode(int on)
{
	g_stub_plan_mode = on ? 1 : 0;
}

int ai_policy_get_plan_mode(void)
{
	return g_stub_plan_mode;
}
