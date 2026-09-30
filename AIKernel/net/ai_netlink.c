// SPDX-License-Identifier: GPL-2.0
/*
 * ai_netlink.c - NETLINK_AI 协议族内核端（AI Runtime 与内核高速指令通道）
 *
 * 命令（见 include/uapi/linux/ai_netlink.h）：
 *   AI_CMD_SENSE - 拉取感知数据：从指定（或全部）CPU ring buffer 读出最近
 *                  N 条记录（N=载荷携带，上限 4096），raw/human 双格式回传
 *   AI_CMD_ACT   - 下发决策指令：校验 CAP_SYS_ADMIN 后记录决策日志并执行
 *                  对应决策域策略（ai_policy_execute）；v2 载荷尾部携带
 *                  定向参数名 param（非空=按参数名定向 apply，空/旧 88B
 *                  消息=按 domain 广播，向后兼容）
 *   AI_CMD_REG   - 注册回调：登记发起方 portid（骨架，异步推送预留）
 *
 * 权限：SENSE 无权限要求（感知数据流与 /proc/ai/telemetry 一致）；ACT/REG
 * 经 netlink_net_capable()（内部走 LSM 的 security_capable）。
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/ai_netlink.h>
#include "../core/ai_types.h"
#include "../core/ai_startup.h"
#include "../core/ai_telemetry.h"
#include "../core/ai_policy.h"

static struct sock *ai_nl_sock;

/* ---- REG 回调登记表（骨架：登记 portid，异步推送预留） ---- */

#define AI_NL_REG_MAX  32

static u32 ai_nl_reg_list[AI_NL_REG_MAX];
static unsigned int ai_nl_reg_count;
static DEFINE_SPINLOCK(ai_nl_reg_lock);

static int ai_nl_reg_add(u32 portid)
{
	unsigned long flags;
	unsigned int i;
	int rc = AI_OK;

	spin_lock_irqsave(&ai_nl_reg_lock, flags);
	for (i = 0; i < ai_nl_reg_count; i++) {
		if (ai_nl_reg_list[i] == portid) {
			spin_unlock_irqrestore(&ai_nl_reg_lock, flags);
			return AI_OK;   /* 幂等 */
		}
	}
	if (ai_nl_reg_count >= AI_NL_REG_MAX)
		rc = AI_ERR_BUSY;
	else
		ai_nl_reg_list[ai_nl_reg_count++] = portid;
	spin_unlock_irqrestore(&ai_nl_reg_lock, flags);
	return rc;
}

/* ---- 应答发送 ---- */

static void ai_nl_reply(struct sk_buff *req_skb, u32 cmd,
			const void *payload, size_t payload_len)
{
	struct nlmsghdr *nlh, *req = nlmsg_hdr(req_skb);
	struct sk_buff *skb;
	int rc;

	skb = nlmsg_new(payload_len, GFP_KERNEL);
	if (!skb)
		return;

	nlh = nlmsg_put(skb, NETLINK_CB(req_skb).portid, req->nlmsg_seq,
			cmd, payload_len, 0);
	if (!nlh) {
		kfree_skb(skb);
		return;
	}
	if (payload_len)
		memcpy(nlmsg_data(nlh), payload, payload_len);

	rc = netlink_unicast(ai_nl_sock, skb, NETLINK_CB(req_skb).portid, 0);
	if (rc < 0)
		pr_debug("AIKernel: netlink reply to %u failed (%d)\n",
			 NETLINK_CB(req_skb).portid, rc);
}

/* ---- AI_CMD_SENSE ---- */

static int ai_nl_sense(struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	const struct ai_nl_sense *req = nlmsg_data(nlh);
	struct ai_nl_sense_ack *ack;
	struct nlmsghdr *r;
	struct sk_buff *reply;
	void *tmp;
	size_t pos = 0;
	u32 records = 0;
	u32 max_records, cpu_from, cpu_to;
	int cpu;

	if (nlmsg_len(nlh) < sizeof(*req))
		return -EINVAL;
	if (!ai_startup_get_enabled())
		return -EPERM;   /* AI_ERR_DISABLED */

	max_records = req->max_records;
	if (max_records == 0 || max_records > AI_NL_SENSE_MAX_RECORDS)
		return -EINVAL;
	if (req->format != AI_NL_FORMAT_RAW &&
	    req->format != AI_NL_FORMAT_HUMAN)
		return -EINVAL;

	tmp = kmalloc(AI_NL_PAYLOAD_MAX, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	reply = nlmsg_new(AI_NL_PAYLOAD_MAX, GFP_KERNEL);
	if (!reply) {
		kfree(tmp);
		return -ENOMEM;
	}
	r = nlmsg_put(reply, NETLINK_CB(skb).portid, nlh->nlmsg_seq,
		      AI_CMD_SENSE, 0, 0);
	if (!r) {
		kfree_skb(reply);
		kfree(tmp);
		return -ENOMEM;
	}
	ack = skb_put(reply, sizeof(*ack));

	if (req->cpu == AI_NL_SENSE_CPU_ALL) {
		cpu_from = 0;
		cpu_to = nr_cpu_ids;
	} else {
		cpu_from = req->cpu;
		cpu_to = req->cpu + 1;   /* 修复：区间 [cpu, cpu+1)，原 cpu==cpu_to 恒假导致单 CPU 查询永远 0 条 */
		if (cpu_from >= nr_cpu_ids) {
			kfree_skb(reply);
			kfree(tmp);
			return -EINVAL;
		}
	}

	for (cpu = cpu_from; cpu < cpu_to && records < max_records; cpu++) {
		size_t n = 0, i;

		if (ai_telemetry_read(cpu, tmp, AI_NL_PAYLOAD_MAX, &n) != AI_OK ||
		    n == 0)
			continue;

		for (i = 0; i < n && records < max_records;) {
			struct ai_telemetry_record *rec =
				(struct ai_telemetry_record *)((u8 *)tmp + i);
			size_t rec_total = AI_TELEMETRY_HEADER_LEN + rec->data_len;
			void *dst;
			size_t take;

			if (rec_total > n - i)
				break;   /* 尾部残记录：留待下次拉取 */

			if (req->format == AI_NL_FORMAT_RAW) {
				take = rec_total;
				if (pos + sizeof(*ack) + take > AI_NL_PAYLOAD_MAX)
					break;
				dst = skb_put(reply, take);
				memcpy(dst, (u8 *)tmp + i, take);
			} else {
				char line[192];
				size_t shown =
					min_t(unsigned int, rec->data_len, 16);
				size_t ln, k;

				ln = snprintf(line, sizeof(line),
					      "ts=%llu pid=%u tgid=%u cpu=%u cat=%u ev=%u sev=%u len=%u data=",
					      rec->timestamp_ns, rec->pid,
					      rec->tgid, rec->cpu, rec->category,
					      rec->event_type, rec->severity,
					      rec->data_len);
				for (k = 0; k < shown; k++)
					ln += snprintf(line + ln, sizeof(line) - ln,
						       "%02x",
						       *((u8 *)rec +
							 AI_TELEMETRY_HEADER_LEN + k));
				if (rec->data_len > shown)
					ln += snprintf(line + ln,
						       sizeof(line) - ln, "...");
				line[ln++] = '\n';
				take = ln;
				if (pos + sizeof(*ack) + take > AI_NL_PAYLOAD_MAX)
					break;
				dst = skb_put(reply, take);
				memcpy(dst, line, take);
			}
			pos += take;
			records++;
			i += rec_total;
		}
	}
	kfree(tmp);

	ack->records = records;
	ack->bytes = (u32)pos;
	ack->ai_err = AI_OK;
	ack->reserved = 0;
	r->nlmsg_len = (u8 *)skb_tail_pointer(reply) - (u8 *)r;

	{
		int rc = netlink_unicast(ai_nl_sock, reply,
					 NETLINK_CB(skb).portid, 0);

		if (rc < 0)
			pr_debug("AIKernel: SENSE reply failed (%d)\n", rc);
	}
	return 0;
}

/* ---- AI_CMD_ACT ---- */

/*
 * 载荷长度兼容（v2）：param 为 v2 追加到 struct ai_nl_act 尾部的定向
 * 参数名。按消息实际长度（nlmsg_len）解析：
 *   - >= AI_NL_ACT_V1_LEN（88B，v1 旧布局）即接受：旧客户端消息无
 *     param 尾部，视为 param 空 = 按 domain 广播（向后兼容）；
 *   - >= sizeof(struct ai_nl_act)（112B，v2 布局）才读取 param，
 *     且要求 NUL 结尾（畸形消息 -EINVAL）。
 * 介于两者之间的长度按 v1 处理（param 缺失 = 广播），不静默读越界。
 */
static int ai_nl_act(struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	const struct ai_nl_act *req = nlmsg_data(nlh);
	struct ai_nl_act_ack ack;
	struct ai_policy_ctx ctx;
	int executed;

	if (nlmsg_len(nlh) < AI_NL_ACT_V1_LEN)
		return -EINVAL;
	if (!ai_startup_get_enabled())
		return -EPERM;   /* AI_ERR_DISABLED */
	if (!netlink_net_capable(skb, CAP_SYS_ADMIN))
		return -EACCES;
	if (req->domain > AI_POLICY_DOMAIN_PROC || req->confidence > 100)
		return -EINVAL;

	memset(&ctx, 0, sizeof(ctx));
	ctx.trigger_ts = ktime_get_ns();
	ctx.trigger_event_id = req->trigger_event_id;
	ctx.decision_type = (u8)req->decision_type;
	ctx.domain = (enum ai_policy_domain)req->domain;
	ctx.confidence = req->confidence;
	ctx.model_version = req->model_version;
	memcpy(ctx.decision_data, req->data, sizeof(ctx.decision_data));
	ctx.source = AI_DEC_SRC_NETLINK;

	/* v2 定向参数名：仅当消息携带完整 param 尾部时解析（见函数头注释） */
	if (nlmsg_len(nlh) >= sizeof(*req)) {
		if (strnlen(req->param, AI_NL_ACT_PARAM_LEN) ==
		    AI_NL_ACT_PARAM_LEN)
			return -EINVAL;   /* param 未 NUL 结尾：畸形消息 */
		if (strscpy(ctx.param, req->param, sizeof(ctx.param)) < 0)
			return -EINVAL;   /* 超出策略层容量（防御，长度恒等不应触发） */
	}

	executed = ai_policy_execute(&ctx, NULL);

	/* 决策记录由 execute 写入 ring（decision_id 在 ctx 回填）；
	 * 本路径 outcome 为未知（结果观测由 AI 外层程序经 outcome 接口上报） */

	ack.executed = executed > 0 ? (u32)executed : 0;
	ack.hit = executed > 0 ? 1 : 0;
	ack.ai_err = executed < 0 ? executed : AI_OK;
	ack.reserved = 0;
	ai_nl_reply(skb, AI_CMD_ACT, &ack, sizeof(ack));
	return 0;
}

/* ---- AI_CMD_REG ---- */

static int ai_nl_reg(struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	const struct ai_nl_reg *req = nlmsg_data(nlh);
	struct {
		__s32 ai_err;
		__u32 count;
	} ack;
	int rc;

	if (nlmsg_len(nlh) < sizeof(*req))
		return -EINVAL;
	if (!ai_startup_get_enabled())
		return -EPERM;   /* AI_ERR_DISABLED */
	if (!netlink_net_capable(skb, CAP_SYS_ADMIN))
		return -EACCES;

	rc = ai_nl_reg_add(NETLINK_CB(skb).portid);
	if (rc != AI_OK)
		return ai_error_to_errno(rc);
	pr_info("AIKernel: NETLINK_AI callback registered (portid=%u, total=%u)\n",
		NETLINK_CB(skb).portid, ai_nl_reg_count);

	ack.ai_err = AI_OK;
	ack.count = (u32)ai_nl_reg_count;
	ai_nl_reply(skb, AI_CMD_REG, &ack, sizeof(ack));
	return 0;
}

/* ---- 入口 ---- */

static int ai_netlink_handle(struct sk_buff *skb, struct nlmsghdr *nlh,
			     struct netlink_ext_ack *extack)
{
	switch (nlh->nlmsg_type) {
	case AI_CMD_SENSE:
		return ai_nl_sense(skb, nlh);
	case AI_CMD_ACT:
		return ai_nl_act(skb, nlh);
	case AI_CMD_REG:
		return ai_nl_reg(skb, nlh);
	default:
		return -EINVAL;
	}
}

static void ai_netlink_rcv(struct sk_buff *skb)
{
	netlink_rcv_skb(skb, ai_netlink_handle);
}

static int __init ai_netlink_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = ai_netlink_rcv,
	};

	if (!ai_startup_get_enabled())
		return 0;   /* ai.enabled=0 启动：协议族不创建 */

	ai_nl_sock = netlink_kernel_create(&init_net, NETLINK_AI, &cfg);
	if (!ai_nl_sock) {
		pr_err("AIKernel: NETLINK_AI socket creation failed\n");
		return -EIO;
	}
	pr_info("AIKernel: NETLINK_AI (%d) ready\n", NETLINK_AI);
	return 0;
}
subsys_initcall(ai_netlink_init);

static void __exit ai_netlink_exit(void)
{
	if (ai_nl_sock)
		netlink_kernel_release(ai_nl_sock);
	ai_nl_sock = NULL;
}
module_exit(ai_netlink_exit);
