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

/* ---- W50：扩展记忆管理面桩（同一"不可用"语义） ---- */

#define SB_STUB_SME_ARG1(name, type1, a1) \
int name(type1 a1, char *out, size_t n) \
{ \
	(void)a1; (void)n; \
	if (out) \
		strcpy(out, "{\"stub\":true}"); \
	return -1; \
}

#define SB_STUB_SME_ARG2(name, type1, a1, type2, a2) \
int name(type1 a1, type2 a2, char *out, size_t n) \
{ \
	(void)a1; (void)a2; (void)n; \
	if (out) \
		strcpy(out, "{\"stub\":true}"); \
	return -1; \
}

SB_STUB_SME_ARG1(sme_memory_delete, const char *, memory_id)
SB_STUB_SME_ARG1(sme_memories_batch, const char *, memories_json)
SB_STUB_SME_ARG1(sme_import, const char *, memories_json)
SB_STUB_SME_ARG1(sme_import_path, const char *, path)
SB_STUB_SME_ARG1(sme_metrics_report, const char *, save_path)
SB_STUB_SME_ARG1(sme_config_check, int, ping)
SB_STUB_SME_ARG2(sme_facts_history, const char *, text,
		  const char *, memory_id)

int sme_add_ex(const struct sme_add_opts *o, char *out, size_t n)
{
	(void)o; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_search_ex(const struct sme_search_opts *o, char *out, size_t n)
{
	(void)o; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_memory_update(const char *memory_id, const struct sme_update_opts *o,
		      char *out, size_t n)
{
	(void)memory_id; (void)o; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

int sme_graph_link(const char *a, const char *b, const char *kind,
		   int has_weight, double weight, const char *note,
		   char *out, size_t n)
{
	(void)a; (void)b; (void)kind; (void)has_weight; (void)weight;
	(void)note; (void)n;
	if (out)
		strcpy(out, "{\"stub\":true}");
	return -1;
}

SB_STUB_SME(sme_graph)
SB_STUB_SME(sme_regions)
SB_STUB_SME(sme_regions_evolve)
SB_STUB_SME(sme_facts)
SB_STUB_SME(sme_profile)
SB_STUB_SME(sme_qapairs)
SB_STUB_SME(sme_config)

/* ---- 策略闸门桩：恒放行 ----
 * （demo_sandbox_chain 用真实现 policy/ai_user_policy.c，编译时
 *  -DW42_REAL_POLICY 跳过本段，避免重定义） */
#ifndef W42_REAL_POLICY

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

/* W43ï¼plan åªè¯»æ¨¡å¼æ¡©ï¼ç¶æä½ï¼é»è®¤å³ââä¸çå®ç­ç¥æ¨¡ååååä¹ï¼executor.c é¸é¨æ¥è¯¢ï¼æ¬æµè¯é¢é»è®¤ä¸è¿ planï¼è¡ä¸ºä¸ W42 ä¸è´ï¼ */
static int g_stub_plan_mode;

void ai_policy_set_plan_mode(int on)
{
	g_stub_plan_mode = on ? 1 : 0;
}

int ai_policy_get_plan_mode(void)
{
	return g_stub_plan_mode;
}

#endif /* W42_REAL_POLICY */
