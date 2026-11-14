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
 *   AI_CMD_ACT2  - 下发决策指令（K1，KERNEL-K1-DESIGN D1/§3）：nlattr
 *                  载荷（AI_DEC_ATTR_*，必备 DOMAIN+TYPE+PARAM，可携带
 *                  统一 trace/intent/expected）；ack 回带 decision_id+
 *                  trace（struct ai_nl_act2_ack）
 *   AI_CMD_REG   - 注册/注销异步事件推送（登记发起方 portid）
 *   AI_CMD_EVENT - 内核 → 用户异步事件推送（策略执行/模型生命周期）
 *
 * 权限：SENSE/ACT/REG 均经 netlink_net_capable(CAP_SYS_ADMIN)（SENSE 为
 * K2b K1B-13 收紧：遥测流零脱敏，与 ACT/REG 同权；出厂 root 形态不变）。
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
#include <linux/notifier.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/ai_netlink.h>
#include "ai_netlink.h"
#include "../core/ai_types.h"
#include "../core/ai_startup.h"
#include "../core/ai_telemetry.h"
#include "../core/ai_policy.h"
#include "../actuators/ai_agent.h"

static struct sock *ai_nl_sock;
static DEFINE_SPINLOCK(ai_nl_sock_lock);

/*
 * w63：内核 netlink socket 的取/放引用。push_event 可能在任意上下文
 * （策略执行/模型生命周期）与 ai_netlink_exit() 的 release 并发；只检查
 * 全局指针非空存在"检查后释放"窗口。持锁 sock_hold 保证 unicast 期间
 * socket 存活，release 侧在锁内摘除指针后 netlink_kernel_release()。
 * 处理函数（SENSE/ACT/REG）由 netlink 输入路径在持有 socket 引用时调用，
 * 回复路径同样显式取引用以防御 exit 竞争。
 */
static struct sock *ai_nl_sock_get(void)
{
	struct sock *sk;
	unsigned long flags;

	spin_lock_irqsave(&ai_nl_sock_lock, flags);
	sk = ai_nl_sock;
	if (sk)
		sock_hold(sk);
	spin_unlock_irqrestore(&ai_nl_sock_lock, flags);
	return sk;
}

static void ai_nl_sock_put(struct sock *sk)
{
	if (sk)
		sock_put(sk);
}

/* ---- REG 回调登记表 + 异步事件推送（W49 ai-6/7） ---- */

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

static void ai_nl_reg_del(u32 portid)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&ai_nl_reg_lock, flags);
	for (i = 0; i < ai_nl_reg_count; i++) {
		if (ai_nl_reg_list[i] != portid)
			continue;
		memmove(&ai_nl_reg_list[i], &ai_nl_reg_list[i + 1],
			(ai_nl_reg_count - i - 1) * sizeof(ai_nl_reg_list[0]));
		ai_nl_reg_count--;
		break;
	}
	spin_unlock_irqrestore(&ai_nl_reg_lock, flags);
}

static unsigned int ai_nl_reg_count_get(void)
{
	unsigned long flags;
	unsigned int n;

	spin_lock_irqsave(&ai_nl_reg_lock, flags);
	n = ai_nl_reg_count;
	spin_unlock_irqrestore(&ai_nl_reg_lock, flags);
	return n;
}

/*
 * w63：socket 销毁通知（NETLINK_URELEASE）。
 *
 * 登记表只存 portid，没有 socket 引用。进程退出/close(fd) 而不发 UNREG
 * 时，旧实现只能等下一次 push 的 -ECONNREFUSED/-ESRCH 惰性摘除：
 *   - 长时间无事件推送 → 死槽长期占用（32 槽上限，反复重启的消费者
 *     最终 AI_CMD_REG 返回 BUSY）；
 *   - 更糟的是 portid 可能被新 socket 复用，登记表会把内核事件投递给
 *     并非注册者的新 socket（信息错投）。
 * netlink_release() 在 socket 解绑后同步调用 blocking notifier，这里按
 * (protocol, net) 过滤后立即摘除。此回调只取 ai_nl_reg_lock，不做 skb
 * 分配/不取 netlink_table_lock（af_netlink.c 的锁序要求）。
 */
static int ai_nl_urelease(u32 portid, int protocol, struct net *net)
{
	if (protocol != NETLINK_AI || net != &init_net)
		return NOTIFY_DONE;
	if (ai_nl_reg_count_get())   /* 空表快速返回（绝大多数 socket 关闭） */
		ai_nl_reg_del(portid);
	/* K3：socket 关闭解绑角色（D1 生命周期；幂等）。防 w63 同款死槽：
	 * 不解绑则 portid 复用后新 socket 被旧角色记账/限额。 */
	ai_agent_unbind(portid);
	return NOTIFY_DONE;
}

static int ai_nl_netlink_notify(struct notifier_block *nb,
				unsigned long state, void *ptr)
{
	struct netlink_notify *n = ptr;

	if (state != NETLINK_URELEASE)
		return NOTIFY_DONE;
	return ai_nl_urelease(n->portid, n->protocol, n->net);
}

static struct notifier_block ai_nl_notifier = {
	.notifier_call = ai_nl_netlink_notify,
};

/* ---- 应答发送 ---- */

static void ai_nl_reply(struct sk_buff *req_skb, u32 cmd,
			const void *payload, size_t payload_len)
{
	struct nlmsghdr *nlh, *req = nlmsg_hdr(req_skb);
	struct sk_buff *skb;
	struct sock *sk;
	int rc;

	sk = ai_nl_sock_get();
	if (!sk)
		return;

	skb = nlmsg_new(payload_len, GFP_KERNEL);
	if (!skb) {
		ai_nl_sock_put(sk);
		return;
	}

	nlh = nlmsg_put(skb, NETLINK_CB(req_skb).portid, req->nlmsg_seq,
			cmd, payload_len, 0);
	if (!nlh) {
		kfree_skb(skb);
		ai_nl_sock_put(sk);
		return;
	}
	if (payload_len)
		memcpy(nlmsg_data(nlh), payload, payload_len);

	rc = netlink_unicast(sk, skb, NETLINK_CB(req_skb).portid, 0);
	ai_nl_sock_put(sk);
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
	s32 first_err = AI_OK;   /* w63：不再吞掉 telemetry read 错误 */
	int cpu;

	if (nlmsg_len(nlh) < sizeof(*req))
		return -EINVAL;
	if (!ai_startup_get_enabled())
		return -EPERM;   /* AI_ERR_DISABLED */
	/* K2b 修复 K1B-13（Med-3）：SENSE 遥测流含全系统进程行为原始数据
	 * （syscall 参数/路径/网络地址，零脱敏），与 ACT/REG 同权——补
	 * CAP_SYS_ADMIN 闸。出厂单用户 root 形态行为不变（root 恒过）；
	 * 多用户/不可信容器形态下阻断未特权读取。遥测字段级脱敏代价高，
	 * 登记"多用户形态上线前再议"。 */
	if (!netlink_net_capable(skb, CAP_SYS_ADMIN))
		return -EACCES;

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
		size_t rem, cap;
		int rrc;

		/*
		 * K7 D2：按剩余回传容量限读（原实现整块 AI_NL_PAYLOAD_MAX
		 * 读出即消费，超出部分 kfree 静默丢——:292 旧注释"留待下次
		 * 拉取"不实：tail 已推进，无下次）。
		 *   - raw：cap = 剩余字节（读出即可逐条交付）；
		 *   - human：单条记录 ≥ 44B 渲染为单行 ≤ 192B，cap 按比例
		 *     缩放保证读出的记录全部可交付（cap/44*192 ≤ rem）；
		 *   - cap 放不下一条最小记录时停止读该 CPU——记录留在环内
		 *     （交排空线程按 drain_discards 计额），不过读。
		 */
		rem = AI_NL_PAYLOAD_MAX - sizeof(*ack) - pos;
		cap = rem;
		if (req->format != AI_NL_FORMAT_RAW)
			cap = rem / AI_TELEMETRY_HUMAN_LINE_MAX *
			      AI_TELEMETRY_HEADER_LEN;
		if (cap < AI_TELEMETRY_HEADER_LEN)
			break;   /* 后续 CPU 剩余更少：整段终止 */

		rrc = ai_telemetry_read(cpu, tmp, cap, &n);
		if (rrc != AI_OK) {
			if (first_err == AI_OK)
				first_err = rrc;
			continue;
		}
		if (!n)
			continue;

		for (i = 0; i < n && records < max_records;) {
			struct ai_telemetry_record *rec =
				(struct ai_telemetry_record *)((u8 *)tmp + i);
			size_t rec_total = AI_TELEMETRY_HEADER_LEN + rec->data_len;
			void *dst;
			size_t take;

			if (rec_total > n - i)
				break;   /* 防御：read 只拷完整记录，理论不可达 */

			if (req->format == AI_NL_FORMAT_RAW) {
				take = rec_total;
				if (pos + sizeof(*ack) + take > AI_NL_PAYLOAD_MAX)
					break;
				dst = skb_put(reply, take);
				memcpy(dst, (u8 *)tmp + i, take);
			} else {
				/* K7 D1：共享渲染器（与 /proc/ai/telemetry
				 * human 同一份实现，两路字节级 golden；
				 * 行上限 192B=AI_TELEMETRY_HUMAN_LINE_MAX） */
				char line[AI_TELEMETRY_HUMAN_LINE_MAX];

				take = ai_telemetry_format_human(rec, line,
								 sizeof(line));
				if (!take ||
				    pos + sizeof(*ack) + take > AI_NL_PAYLOAD_MAX)
					break;
				dst = skb_put(reply, take);
				memcpy(dst, line, take);
			}
			pos += take;
			records++;
			i += rec_total;
		}
		/* K7 D2：读出但未交付的记录（max_records 截断/防御 break）
		 * 计 sense_overread_dropped——诚实计账替代旧的静默丢弃 */
		if (i < n)
			ai_telemetry_note_sense_overread(
				cpu, ai_telemetry_count_records((u8 *)tmp + i,
								n - i));
	}
	kfree(tmp);

	ack->records = records;
	ack->bytes = (u32)pos;
	ack->ai_err = first_err;
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

	/* K3（KERNEL-K3-DESIGN D3）：配额准入——dispatch 内、execute 之前。
	 * v1 载荷无 agent 字段=自报恒 0；绑定 socket 的角色覆盖防借道
	 * legacy ACT 逃逸。超额=ack -EAGAIN（零 ring 写入，blast 拒绝
	 * 同形态）；白名单外自报 -EINVAL。 */
	{
		u32 role = AI_AGENT_KERNEL;
		int err = ai_agent_admit(skb, AI_AGENT_KERNEL, &role);

		if (err == -EAGAIN) {
			memset(&ack, 0, sizeof(ack));
			ack.ai_err = -EAGAIN;
			ai_nl_reply(skb, AI_CMD_ACT, &ack, sizeof(ack));
			return 0;
		}
		if (err)
			return err;
		ctx.agent_id = role;	/* 绑定覆盖；未绑定恒 0=v1 原语义 */
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

/* ---- AI_CMD_ACT2（K1：nlattr 载荷，KERNEL-K1-DESIGN §3/D1） ---- */

/*
 * ACT2 属性 policy 表：长度/范围全在表内（PARAM ≤24 含 NUL；
 * DATA 恰 64B=8×u64（EXACT_LEN）；CONFIDENCE 0-100（RANGE）；
 * 数值属性定长）。EXPECTED 用 NLA_S64（负值合法：恶化预期）。
 */
static const struct nla_policy ai_nl_act2_policy[AI_DEC_ATTR_MAX + 1] = {
	[AI_DEC_ATTR_DOMAIN]	= { .type = NLA_U8 },
	[AI_DEC_ATTR_TYPE]	= { .type = NLA_U32 },
	[AI_DEC_ATTR_PARAM]	= { .type = NLA_NUL_STRING,
	/* K1 勘误（真机 KUnit 抓获）：NLA_NUL_STRING 的 .len=不含尾 NUL
	 * 的最大字符数——.len=24 放行 24 字符+NUL(25B)，与 v1 param[24]
	 * 及 uapi 注释（≤23 字符+NUL）不符，收紧为 23。 */
				   .len = AI_NL_ACT_PARAM_LEN - 1 },
	[AI_DEC_ATTR_DATA]	= NLA_POLICY_EXACT_LEN(64),
	[AI_DEC_ATTR_CONFIDENCE]	= NLA_POLICY_RANGE(NLA_U8, 0, 100),
	[AI_DEC_ATTR_MODEL_VER]	= { .type = NLA_U32 },
	[AI_DEC_ATTR_TRIG_EVID]	= { .type = NLA_U64 },
	[AI_DEC_ATTR_TRACE_HI]	= { .type = NLA_U64 },
	[AI_DEC_ATTR_TRACE_LO]	= { .type = NLA_U64 },
	[AI_DEC_ATTR_INTENT]	= { .type = NLA_U64 },
	[AI_DEC_ATTR_PARENT]	= { .type = NLA_U64 },
	[AI_DEC_ATTR_AGENT]	= { .type = NLA_U32 },
	[AI_DEC_ATTR_EXPECTED]	= { .type = NLA_S64 },
};

/**
 * ai_nl_act2_parse() - ACT2 nlattr 载荷解析（可测助手，K1）
 * @head: attr 区起点（nlmsg_attrdata(nlh, 0)，无 family 头）
 * @rem: attr 区长度（nlmsg_attrlen(nlh, 0)）
 * @ctx: 输出——全零基线 + attr 字段；trigger_ts/source 由调用方补
 *
 * 必备 DOMAIN+TYPE+PARAM，缺任一 -EINVAL；畸形 attr 由 policy 表全拒
 * （长度/范围违规，负错误码）。测试直调：ai_netlink_test.c。
 */
int ai_nl_act2_parse(const struct nlattr *head, int rem,
		     struct ai_policy_ctx *ctx)
{
	struct nlattr *tb[AI_DEC_ATTR_MAX + 1];
	int err;

	memset(ctx, 0, sizeof(*ctx));

	/* K1 勘误2（真机 KUnit :249 抓获）：deprecated 校验不强制定宽属性
	 * 载荷长度（NLA_U8 带 4B 载荷被放行）。ACT2 是新 ABI，一律走
	 * 严格校验 nla_parse()（NL_VALIDATE_STRICT，genl 现行口径）。 */
	err = nla_parse(tb, AI_DEC_ATTR_MAX, head, rem,
			   ai_nl_act2_policy, NULL);
	if (err)
		return err;

	/* 必备三元组：缺任一拒绝（不静默缺省；PARAM 空串合法=广播） */
	if (!tb[AI_DEC_ATTR_DOMAIN] || !tb[AI_DEC_ATTR_TYPE] ||
	    !tb[AI_DEC_ATTR_PARAM])
		return -EINVAL;

	ctx->domain = (enum ai_policy_domain)nla_get_u8(
				tb[AI_DEC_ATTR_DOMAIN]);
	ctx->decision_type = (u8)nla_get_u32(tb[AI_DEC_ATTR_TYPE]);
	if (strscpy(ctx->param, nla_data(tb[AI_DEC_ATTR_PARAM]),
		    sizeof(ctx->param)) < 0)
		return -EINVAL;   /* 防御：policy 已限长，恒不触发 */
	if (tb[AI_DEC_ATTR_DATA])
		memcpy(ctx->decision_data, nla_data(tb[AI_DEC_ATTR_DATA]),
		       sizeof(ctx->decision_data));
	if (tb[AI_DEC_ATTR_CONFIDENCE])
		ctx->confidence = nla_get_u8(tb[AI_DEC_ATTR_CONFIDENCE]);
	if (tb[AI_DEC_ATTR_MODEL_VER])
		ctx->model_version = nla_get_u32(tb[AI_DEC_ATTR_MODEL_VER]);
	if (tb[AI_DEC_ATTR_TRIG_EVID])
		ctx->trigger_event_id = (u32)nla_get_u64(
				tb[AI_DEC_ATTR_TRIG_EVID]);
	if (tb[AI_DEC_ATTR_TRACE_HI])
		ctx->trace_hi = nla_get_u64(tb[AI_DEC_ATTR_TRACE_HI]);
	if (tb[AI_DEC_ATTR_TRACE_LO])
		ctx->trace_lo = nla_get_u64(tb[AI_DEC_ATTR_TRACE_LO]);
	if (tb[AI_DEC_ATTR_INTENT])
		ctx->intent_id = nla_get_u64(tb[AI_DEC_ATTR_INTENT]);
	if (tb[AI_DEC_ATTR_PARENT])
		ctx->parent_id = nla_get_u64(tb[AI_DEC_ATTR_PARENT]);
	if (tb[AI_DEC_ATTR_AGENT])
		ctx->agent_id = nla_get_u32(tb[AI_DEC_ATTR_AGENT]);
	if (tb[AI_DEC_ATTR_EXPECTED])
		ctx->expected = nla_get_s64(tb[AI_DEC_ATTR_EXPECTED]);
	return 0;
}

/*
 * ACT2 处理器：与 v1 同闸（startup enabled + CAP_SYS_ADMIN +
 * domain 钳制；confidence 已由 RANGE policy 拒 101+）。attrs→ctx
 * （trigger_ts=ktime_get_ns、source=NETLINK）→ ai_policy_execute_trace
 * （可写 ctx：铸造结果回读）→ ack 单播（decision_id+trace 回带）。
 * 本路径 outcome 恒未知（同 v1 ACT，结果观测由 AI 外层上报）。
 */
static int ai_nl_act2(struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	struct ai_nl_act2_ack ack;
	struct ai_policy_ctx ctx;
	int executed;
	int err;

	if (!ai_startup_get_enabled())
		return -EPERM;   /* AI_ERR_DISABLED */
	if (!netlink_net_capable(skb, CAP_SYS_ADMIN))
		return -EACCES;

	err = ai_nl_act2_parse(nlmsg_attrdata(nlh, 0),
			       nlmsg_attrlen(nlh, 0), &ctx);
	if (err)
		return err;
	if (ctx.domain > AI_POLICY_DOMAIN_PROC)
		return -EINVAL;   /* 与 v1 同闸：domain 钳制 */

	/* K3（KERNEL-K3-DESIGN D3）：配额准入——解析/校验链之后、execute
	 * 之前。入参出参同址（admit 先读后写）：绑定 socket 的角色覆盖
	 * 自报 agent；未绑定自报白名单外 → -EINVAL；超额 → ack -EAGAIN
	 * （零 ring 写入，blast 拒绝同形态；decision_id/trace 诚实零）。 */
	err = ai_agent_admit(skb, ctx.agent_id, &ctx.agent_id);
	if (err == -EAGAIN) {
		memset(&ack, 0, sizeof(ack));
		ack.ai_err = -EAGAIN;
		ai_nl_reply(skb, AI_CMD_ACT2, &ack, sizeof(ack));
		return 0;
	}
	if (err)
		return err;

	ctx.trigger_ts = ktime_get_ns();
	ctx.source = AI_DEC_SRC_NETLINK;

	executed = ai_policy_execute_trace(&ctx, NULL);

	ack.executed = executed > 0 ?
		(u8)min_t(int, executed, U8_MAX) : 0;
	ack.hit = executed > 0 ? 1 : 0;
	ack.ai_err = executed < 0 ? executed : AI_OK;
	ack.decision_id = ctx.decision_id;   /* execute 内补铸回读 */
	ack.trace_hi = ctx.trace_hi;
	ack.trace_lo = ctx.trace_lo;
	ai_nl_reply(skb, AI_CMD_ACT2, &ack, sizeof(ack));
	return 0;
}

/* ---- AI_CMD_ACT_BATCH（K2：嵌套 nlattr 批量事务，KERNEL-K2-DESIGN
 * §3/D1；AIKernel 首个嵌套面——严格轨+元组数上限+重复名拒三重防线） ---- */

/*
 * 批级 policy（严格 nla_parse）：OPS=NLA_NESTED（可重复——tb[] 只留
 * 末项，元组遍历走下方 nla_for_each_attr 原始流）；表尺寸覆盖到
 * AI_DEC_ATTR_AGENT(12)（复用号），NULL 项（含 VALUE/PID）= 严格轨拒收。
 */
static const struct nla_policy ai_nl_batch_policy[AI_DEC_ATTR_MAX + 1] = {
	[AI_BATCH_ATTR_OPS]		= { .type = NLA_NESTED },
	[AI_BATCH_ATTR_AUTO_ROLLBACK_MS]	= { .type = NLA_U32 },
	[AI_BATCH_ATTR_CONFIRM_TOKEN]	= { .type = NLA_U64 },
	/* 批级复用 AI_DEC_ATTR_*（8/9/10/12） */
	[AI_DEC_ATTR_TRACE_HI]		= { .type = NLA_U64 },
	[AI_DEC_ATTR_TRACE_LO]		= { .type = NLA_U64 },
	[AI_DEC_ATTR_INTENT]		= { .type = NLA_U64 },
	[AI_DEC_ATTR_AGENT]		= { .type = NLA_U32 },
};

/* 元组内严格表（nla_parse_nested_deprecated，overlays 同款先例） */
static const struct nla_policy ai_nl_batch_tuple_policy[AI_DEC_ATTR_MAX + 1] = {
	[AI_DEC_ATTR_PARAM]	= { .type = NLA_NUL_STRING,
				   .len = AI_NL_ACT_PARAM_LEN - 1 },
	[AI_DEC_ATTR_VALUE]	= { .type = NLA_U64 },
	[AI_DEC_ATTR_PID]	= { .type = NLA_U32 },
};

int ai_nl_act_batch_parse(const struct nlattr *head, int rem,
			  struct ai_nl_batch_req *req)
{
	struct nlattr *tb[AI_DEC_ATTR_MAX + 1];
	struct nlattr *stream = (struct nlattr *)head;
	struct nlattr *nla;
	int err, rem2;

	memset(req, 0, sizeof(*req));

	/* 批级：严格轨（NL_VALIDATE_STRICT，K1 act2 同口径）——
	 * 未知 attr / OPS 缺 NLA_F_NESTED / 定长属性长度违规全拒 */
	err = nla_parse(tb, AI_DEC_ATTR_MAX, head, rem,
			ai_nl_batch_policy, NULL);
	if (err)
		return err;

	if (tb[AI_BATCH_ATTR_AUTO_ROLLBACK_MS])
		req->opts.auto_rollback_ms =
			nla_get_u32(tb[AI_BATCH_ATTR_AUTO_ROLLBACK_MS]);
	if (tb[AI_BATCH_ATTR_CONFIRM_TOKEN])
		req->opts.token =
			nla_get_u64(tb[AI_BATCH_ATTR_CONFIRM_TOKEN]);
	if (tb[AI_DEC_ATTR_TRACE_HI])
		req->opts.trace_hi =
			nla_get_u64(tb[AI_DEC_ATTR_TRACE_HI]);
	if (tb[AI_DEC_ATTR_TRACE_LO])
		req->opts.trace_lo =
			nla_get_u64(tb[AI_DEC_ATTR_TRACE_LO]);
	if (tb[AI_DEC_ATTR_INTENT])
		req->opts.intent_id =
			nla_get_u64(tb[AI_DEC_ATTR_INTENT]);
	if (tb[AI_DEC_ATTR_AGENT])
		req->opts.agent_id =
			nla_get_u32(tb[AI_DEC_ATTR_AGENT]);

	/* 元组：原始 attr 流逐个 OPS（可重复）→ 元组内 nested 解析 */
	nla_for_each_attr(nla, stream, rem, rem2) {
		struct nlattr *ttb[AI_DEC_ATTR_MAX + 1];

		if (nla_type(nla) != AI_BATCH_ATTR_OPS)
			continue;
		if (req->n_ops >= AI_BATCH_MAX_OPS)
			return -EINVAL;	/* 元组数 > 27 */
		err = nla_parse_nested_deprecated(ttb, AI_DEC_ATTR_MAX,
							  nla,
							  ai_nl_batch_tuple_policy,
							  NULL);
		if (err)
			return err;
		if (!ttb[AI_DEC_ATTR_PARAM] || !ttb[AI_DEC_ATTR_VALUE])
			return -EINVAL;	/* PARAM/VALUE 必备 */
		req->ops[req->n_ops].param =
			nla_data(ttb[AI_DEC_ATTR_PARAM]);
		req->ops[req->n_ops].value =
			nla_get_u64(ttb[AI_DEC_ATTR_VALUE]);
		req->ops[req->n_ops].pid = ttb[AI_DEC_ATTR_PID] ?
			nla_get_u32(ttb[AI_DEC_ATTR_PID]) : 0;
		req->n_ops++;
	}
	if (!req->n_ops)
		return -EINVAL;	/* 1 ≤ 元组数 */
	return 0;
}

/*
 * ACT_BATCH 处理器：与 ACT2 同闸（startup enabled + CAP_SYS_ADMIN）；
 * 无 DOMAIN（param 全名自带域，Pass1 查表校验）。结果一律回 ack
 * 单播（-EAGAIN 形态带 radius+token 供两段式重试；解析/权限错误
 * 走 netlink 错误返回，不回 ack）。
 */
static int ai_nl_act_batch(struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	struct ai_nl_batch_req req;
	struct ai_nl_batch_ack ack;
	int err;

	if (!ai_startup_get_enabled())
		return -EPERM;
	if (!netlink_net_capable(skb, CAP_SYS_ADMIN))
		return -EACCES;

	err = ai_nl_act_batch_parse(nlmsg_attrdata(nlh, 0),
				   nlmsg_attrlen(nlh, 0), &req);
	if (err)
		return err;

	/* K3（KERNEL-K3-DESIGN D3）：整批为一个动作计数单位——解析拒绝链
	 * 之后、批执行之前 admit（拒绝=整批 -EAGAIN，ack 结构零改：
	 * radius/token=0=未触发语义）；绑定角色覆盖批级自报 agent。 */
	err = ai_agent_admit(skb, req.opts.agent_id, &req.opts.agent_id);
	if (err == -EAGAIN) {
		memset(&ack, 0, sizeof(ack));
		ack.first_fail_idx = -1;
		ack.ai_err = -EAGAIN;
		ai_nl_reply(skb, AI_CMD_ACT_BATCH, &ack, sizeof(ack));
		return 0;
	}
	if (err)
		return err;

	ai_policy_execute_batch(req.ops, req.n_ops, &req.opts, &ack);
	ai_nl_reply(skb, AI_CMD_ACT_BATCH, &ack, sizeof(ack));
	return 0;
}

/* ---- AI_CMD_REG ---- */

/*
 * K3（KERNEL-K3-DESIGN D1）：REG 属性 policy 表——消息 = 定长头 +
 * 可选 attr 区（AGENT=8/CGROUP=9，uapi 冻结契约）。旧客户端纯头
 * （零 attr）零改动兼容；携带 attr 则严格轨（nla_parse）全拒未知项。
 * CGROUP 长度上限=槽存储容量-1（超长拒收不截断——审计路径静默变形
 * 比拒绝更糟）。
 */
static const struct nla_policy ai_nl_reg_policy[AI_REG_ATTR_MAX + 1] = {
	[AI_REG_ATTR_AGENT]	= { .type = NLA_U32 },
	[AI_REG_ATTR_CGROUP]	= { .type = NLA_NUL_STRING,
				   .len = AI_AGENT_CG_LEN - 1 },
};

static int ai_nl_reg(struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	const struct ai_nl_reg *req = nlmsg_data(nlh);
	struct nlattr *reg_tb[AI_REG_ATTR_MAX + 1] = {};
	struct {
		__s32 ai_err;
		__u32 count;
	} ack;
	u32 portid = NETLINK_CB(skb).portid;
	u32 agent = 0;
	const char *cgroup = NULL;
	int attrs_len;
	bool has_agent = false;
	int rc = AI_OK;
	int err;

	if (nlmsg_len(nlh) < sizeof(*req))
		return -EINVAL;
	if (!portid)
		return -EINVAL;   /* w63：portid 0 = 内核自身，不允许登记 */
	if (!ai_startup_get_enabled())
		return -EPERM;   /* AI_ERR_DISABLED */
	if (!netlink_net_capable(skb, CAP_SYS_ADMIN))
		return -EACCES;
	/* flags 只定义 UNREG；reserved 必须为 0，保留前向兼容校验 */
	if ((req->flags & ~AI_NL_REG_F_UNREG) || req->reserved)
		return -EINVAL;

	/* K3：定长头后可选 nlattr 区（长度闸已保 attrs_len >= 0） */
	attrs_len = nlmsg_len(nlh) - (int)sizeof(*req);
	if (attrs_len > 0) {
		err = nla_parse(reg_tb, AI_REG_ATTR_MAX,
				(struct nlattr *)((u8 *)req + sizeof(*req)),
				attrs_len, ai_nl_reg_policy, NULL);
		if (err)
			return err;
		if (reg_tb[AI_REG_ATTR_AGENT]) {
			has_agent = true;
			agent = nla_get_u32(reg_tb[AI_REG_ATTR_AGENT]);
		}
		if (reg_tb[AI_REG_ATTR_CGROUP])
			cgroup = nla_data(reg_tb[AI_REG_ATTR_CGROUP]);
	}
	/* UNREG 携带 AGENT 属矛盾请求（解绑不挑角色，见下）拒收；
	 * CGROUP 仅随 AGENT 生效，单独携带同样拒收 */
	if (has_agent && (req->flags & AI_NL_REG_F_UNREG))
		return -EINVAL;
	if (cgroup && !has_agent)
		return -EINVAL;

	if (req->flags & AI_NL_REG_F_UNREG) {
		ai_nl_reg_del(portid);
		/* K3：注销同时解绑角色（幂等；该 socket 已声明退出） */
		ai_agent_unbind(portid);
		pr_info("AIKernel: NETLINK_AI callback unregistered (portid=%u, total=%u)\n",
			portid, ai_nl_reg_count_get());
	} else {
		rc = ai_nl_reg_add(portid);
		if (rc != AI_OK)
			return ai_error_to_errno(rc);
		if (has_agent) {
			/* K3：角色绑定/改绑（白名单/防 0 逃逸校验在 bind
			 * 内，越界 -EINVAL、角色被占 -EBUSY）。绑定失败
			 * 时事件登记保留先行成功状态（URELEASE 兜底回收，
			 * 客户端按错误码自行处置）。 */
			rc = ai_agent_bind(portid, agent, cgroup);
			if (rc)
				return rc;
		}
		pr_info("AIKernel: NETLINK_AI callback registered (portid=%u, total=%u)\n",
			portid, ai_nl_reg_count_get());
	}

	ack.ai_err = AI_OK;
	ack.count = (u32)ai_nl_reg_count_get();
	ai_nl_reply(skb, AI_CMD_REG, &ack, sizeof(ack));
	return 0;
}

/*
 * 异步事件推送（W49 ai-6/7）：把内核侧事件投递给所有已注册 portid。
 * - 先在 spinlock 内把 portid 快照到栈上，锁外逐条构造/单播，避免在
 *   自旋锁内做 skb 分配与 netlink 处理；
 * - 接收方已关闭（-ECONNREFUSED/-ESRCH）时惰性摘除该 portid，防止死槽；
 * - GFP_ATOMIC + MSG_DONTWAIT：允许从策略执行/遥测等可能处于原子上下文
 *   的调用点进入。
 */
/*
 * K1 D7：推送统一核心——56B 基础载荷（struct ai_nl_event）+ 可选 16B
 * trace 尾巴（struct ai_nl_event_tail）= 72B。policy 事件带记录 trace；
 * 环境事件（model/hotplug）不带尾巴 = 56B 原样（trace 0:0 = 无意图
 * 归属，诚实零），两个导出壳见下。逐 portid 单播骨架（w63 生命周期 /
 * 死端口惰性摘除）与原实现逐行保持。
 */
static int ai_nl_push_event_common(u32 category, u32 severity, u64 event_id,
				   s32 code, const char *param,
				   const struct ai_nl_event_tail *tail)
{
	struct ai_nl_event ev;
	u32 portids[AI_NL_REG_MAX];
	unsigned int n, i;
	unsigned long flags;
	size_t payload_len = sizeof(ev) + (tail ? sizeof(*tail) : 0);
	struct sock *sk;

	if (!ai_startup_get_enabled())
		return AI_ERR_DISABLED;
	/* w63：持引用发送，避免与 ai_netlink_exit() 的 release 竞争 */
	sk = ai_nl_sock_get();
	if (!sk)
		return AI_ERR_DISABLED;

	memset(&ev, 0, sizeof(ev));
	ev.ts = ktime_get_ns();
	ev.category = category;
	ev.severity = severity;
	ev.event_id = event_id;
	ev.code = code;
	if (param)
		strscpy(ev.param, param, sizeof(ev.param));

	spin_lock_irqsave(&ai_nl_reg_lock, flags);
	n = ai_nl_reg_count;
	memcpy(portids, ai_nl_reg_list, n * sizeof(portids[0]));
	spin_unlock_irqrestore(&ai_nl_reg_lock, flags);

	for (i = 0; i < n; i++) {
		struct nlmsghdr *nlh;
		struct sk_buff *skb;
		int rc;

		skb = nlmsg_new(payload_len, GFP_ATOMIC);
		if (!skb)
			break;   /* 内存压力：丢弃本事件（注册者仍可轮询 SENSE） */

		nlh = nlmsg_put(skb, 0, 0, AI_CMD_EVENT, payload_len, 0);
		if (!nlh) {
			kfree_skb(skb);
			continue;
		}
		memcpy(nlmsg_data(nlh), &ev, sizeof(ev));
		if (tail)
			memcpy((u8 *)nlmsg_data(nlh) + sizeof(ev), tail,
			       sizeof(*tail));

		rc = netlink_unicast(sk, skb, portids[i],
				     MSG_DONTWAIT);
		if (rc < 0) {
			pr_debug("AIKernel: EVENT push to %u failed (%d)\n",
				 portids[i], rc);
			if (rc == -ECONNREFUSED || rc == -ESRCH)
				ai_nl_reg_del(portids[i]);
		}
	}

	ai_nl_sock_put(sk);
	return AI_OK;
}

/* K1 D7：薄壳——56B 原样（符号不碎；model/hotplug 调用者零改动） */
int ai_netlink_push_event(u32 category, u32 severity, u64 event_id,
			  s32 code, const char *param)
{
	return ai_nl_push_event_common(category, severity, event_id, code,
				       param, NULL);
}
EXPORT_SYMBOL_GPL(ai_netlink_push_event);

/**
 * ai_netlink_push_event_trace() - 同 push_event，载荷带 trace 尾（72B）
 * @trace_hi/@trace_lo: 统一 trace（policy 事件=决策记录的 trace；
 * 环境事件请继续用 ai_netlink_push_event()，56B 原样）。
 */
int ai_netlink_push_event_trace(u32 category, u32 severity, u64 event_id,
				s32 code, const char *param,
				u64 trace_hi, u64 trace_lo)
{
	struct ai_nl_event_tail tail = {
		.trace_hi = trace_hi,
		.trace_lo = trace_lo,
	};

	return ai_nl_push_event_common(category, severity, event_id, code,
				       param, &tail);
}
EXPORT_SYMBOL_GPL(ai_netlink_push_event_trace);

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/*
 * w63 KUnit 钩子：登记表/销毁通知的可测包装（均为内部 static 函数）。
 * 用于验证 add/del 幂等与容量、NETLINK_URELEASE 按 (protocol, net) 过滤
 * 清理死槽。测试文件：AIKernel/test/ai_netlink_test.c。
 */
int ai_netlink_test_reg_add(u32 portid)
{
	return ai_nl_reg_add(portid);
}

void ai_netlink_test_reg_del(u32 portid)
{
	ai_nl_reg_del(portid);
}

unsigned int ai_netlink_test_reg_count(void)
{
	return ai_nl_reg_count_get();
}

void ai_netlink_test_reg_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ai_nl_reg_lock, flags);
	ai_nl_reg_count = 0;
	spin_unlock_irqrestore(&ai_nl_reg_lock, flags);
}

void ai_netlink_test_urelease(u32 portid, int protocol, struct net *net)
{
	ai_nl_urelease(portid, protocol, net);
}
#endif /* CONFIG_AIKERNEL_KUNIT_TEST */

/* ---- 入口 ---- */

static int ai_netlink_handle(struct sk_buff *skb, struct nlmsghdr *nlh,
			     struct netlink_ext_ack *extack)
{
	switch (nlh->nlmsg_type) {
	case AI_CMD_SENSE:
		return ai_nl_sense(skb, nlh);
	case AI_CMD_ACT:
		return ai_nl_act(skb, nlh);
	case AI_CMD_ACT2:
		return ai_nl_act2(skb, nlh);
	case AI_CMD_ACT_BATCH:
		return ai_nl_act_batch(skb, nlh);
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
	struct sock *sk;
	unsigned long flags;
	int rc;

	if (!ai_startup_get_enabled())
		return 0;   /* ai.enabled=0 启动：协议族不创建 */

	sk = netlink_kernel_create(&init_net, NETLINK_AI, &cfg);
	if (!sk) {
		pr_err("AIKernel: NETLINK_AI socket creation failed\n");
		return -EIO;
	}

	rc = netlink_register_notifier(&ai_nl_notifier);
	if (rc)
		pr_warn("AIKernel: netlink URELEASE notifier registration failed (%d); stale portid cleanup degraded\n",
			rc);

	spin_lock_irqsave(&ai_nl_sock_lock, flags);
	ai_nl_sock = sk;
	spin_unlock_irqrestore(&ai_nl_sock_lock, flags);

	pr_info("AIKernel: NETLINK_AI (%d) ready\n", NETLINK_AI);
	return 0;
}
subsys_initcall(ai_netlink_init);

static void __exit ai_netlink_exit(void)
{
	struct sock *sk;
	unsigned long flags;

	/* w63：先摘 notifier，再摘 socket 指针并 release；在途 push 自带
	 * sock 引用，release 会等其 sock_put 后再真正释放。 */
	netlink_unregister_notifier(&ai_nl_notifier);

	spin_lock_irqsave(&ai_nl_sock_lock, flags);
	sk = ai_nl_sock;
	ai_nl_sock = NULL;
	spin_unlock_irqrestore(&ai_nl_sock_lock, flags);
	if (sk)
		netlink_kernel_release(sk);

	spin_lock_irqsave(&ai_nl_reg_lock, flags);
	ai_nl_reg_count = 0;
	spin_unlock_irqrestore(&ai_nl_reg_lock, flags);
}
module_exit(ai_netlink_exit);
