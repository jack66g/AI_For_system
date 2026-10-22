// SPDX-License-Identifier: GPL-2.0
/*
 * test_sandbox_stubs.c - W42 test_sandbox_tools 的依赖桩
 *
 * test_sandbox_tools 链接 executor.c/tool_registry.c 真实现，但它们引用
 * 的内核 netlink 客户端、SME 记忆客户端与策略闸门不属于本测试面：
 *   - netlink/sme：单测环境无 AIKernel 内核与 SME 服务，桩返回"通道不可用"；
 *   - ai_policy_gate_reason：W2 闸门策略层不在本测试范围（已有独立回归），
 *     桩恒放行，让 sandbox_spawn 的 W2 工具能走到执行段。
 */
#include <stddef.h>
#include <string.h>

#include "netlink/ai_netlink_client.h"
#include "memory/sme_client.h"
#include "policy/ai_user_policy.h"

/* ---- netlink 桩 ---- */

int ai_nl_client_open(struct ai_nl_client *cli)
{
	(void)cli;
	return -1;                      /* 通道不可用 */
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

/* ---- SME 记忆客户端桩（全部返回"不可用"） ---- */

#define SB_STUB_SME(name) \
int name(char *out, size_t n) \
{ \
	(void)n; \
	if (out) \
		strcpy(out, "{\"stub\":true}"); \
	return -1; \
}

SB_STUB_SME(sme_health)
SB_STUB_SME(sme_stats)
SB_STUB_SME(sme_consolidate)
SB_STUB_SME(sme_compress)
SB_STUB_SME(sme_metrics)

int sme_add(const char *text, const char *meta_json, char *out, size_t n)
{
	(void)text; (void)meta_json; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_search(const char *text, int top_k, char *out, size_t n)
{
	(void)text; (void)top_k; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_memory_get(const char *memory_id, char *out, size_t n)
{
	(void)memory_id; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_memory_hit(const char *memory_id, char *out, size_t n)
{
	(void)memory_id; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_memory_archive(const char *memory_id, char *out, size_t n)
{
	(void)memory_id; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_memory_restore(const char *memory_id, char *out, size_t n)
{
	(void)memory_id; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_facts_multi_hop(const char *text, int top_k, char *out, size_t n)
{
	(void)text; (void)top_k; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_regions_search(const char *text, int top_k, char *out, size_t n)
{
	(void)text; (void)top_k; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_export(const char *save_path, char *out, size_t n)
{
	(void)save_path; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

/* ---- 策略闸门桩：恒放行 ---- */

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
