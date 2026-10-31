/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net_intent.h - W81 V3.1 网络意图 ↔ nft 规则双向编译（TOOL_CH_NETINTENT）
 *
 * 件目（四件）：
 *   1. nft_intent_compile   自然语言意图 → nft 规则集 + 行级 diff + 语法预检
 *                           （R/D0：只读，绝不写内核规则）
 *   2. nft_intent_apply     编译结果下发（W2/D3：走 executor 通用租约闸门，
 *                           需显式授权）+ 快照回滚凭据 + 60 秒自动回滚定时器
 *   3. nft_intent_confirm   窗口内确认（取消自动回滚）/ 立即回滚（W2/D3）
 *   4. nft_ruleset_summarize 现网规则 → 人话摘要（R/D0：只读 nft -j list）
 *
 * 链路复用：正向不另起执行路径，预检/应用/抽查全部走 net_admin.c 导出的
 * ai_nft_run_file()/ai_nft_list_args()（与 W78 nft_txn 同一有界 fork/execv +
 * 超时实现），预检 → 应用 → 抽查 → 留回滚凭据四步与 nft_txn 完全一致。
 *
 * 安全边界：
 *   - 意图语法封闭（只接受端口/协议/方向/默认策略），绝不把模型给的原文
 *     拼进 nft 文件——生成文本由解析结果格式化而来，注入面为零；
 *   - 默认拒绝且未放行 22/tcp 时 apply 一律拒绝（除非 allow_lockout=true
 *     显式认账），防把操作者关在门外；
 *   - apply 后 fork 一个 setsid 看门狗：arm_seconds（默认 60）内没有
 *     confirm 决定，则自动 delete/恢复快照表并留日志；
 *   - 本模块只动自己创建的一张表（默认 inet aik_intent），不 flush ruleset、
 *     不碰其他表、不删任何非本表对象。
 */
#ifndef _AI_NET_INTENT_H
#define _AI_NET_INTENT_H

#include <stddef.h>

#define NI_MAX_RULES	32
#define NI_TABLE_LEN	16
#define NI_TEXT_MAX	16384
#define NI_PORT_MIN	1
#define NI_PORT_MAX	65535
#define NI_ARM_DEFAULT	60	/* 自动回滚窗口：出厂 60 秒 */
#define NI_ARM_MIN	10	/* 下限：不允许把保护窗关成 0 */
#define NI_ARM_MAX	600

enum ni_action { NI_ALLOW = 0, NI_DENY };
enum ni_proto { NI_PROTO_TCP = 0, NI_PROTO_UDP, NI_PROTO_ICMP };
enum ni_dir { NI_DIR_IN = 0, NI_DIR_OUT };
enum ni_policy { NI_POLICY_DROP = 0, NI_POLICY_ACCEPT };

struct ni_rule {
	enum ni_action act;
	enum ni_proto proto;
	int lo;			/* 端口下界；ICMP 恒 0 */
	int hi;			/* 端口上界；ICMP 恒 0 */
};

/* 解析后的完整意图（纯数据：编译与单测共用） */
struct ni_intent {
	struct ni_rule rule[NI_MAX_RULES];
	int rule_n;
	enum ni_dir dir;
	enum ni_policy policy;
	int has_policy;		/* 1=意图里显式给了默认策略 */
	int implicit_allow;	/* 1=端口前没动词，按允许处理（会在输出里标注） */
	int has_icmp;
	char table[NI_TABLE_LEN];
};

/* 纯函数（导出供单测） */
int ni_parse_intent(const char *intent, const char *allow_ports,
		    const char *deny_ports, const char *default_policy,
		    const char *proto, const char *dir, const char *table,
		    struct ni_intent *out, char *err, size_t errcap);
int ni_compile(const struct ni_intent *in, char *buf, size_t cap);
int ni_diff(const char *old_text, const char *new_text, char *buf, size_t cap);
void ni_digest(const char *text, char out[17]);
int ni_summarize(const char *json, const char *only_table, char *buf,
		 size_t cap, char *err, size_t errcap);
int ni_valid_table(const char *name);

/* 执行器入口（executor.c 的 TOOL_CH_NETINTENT 分发调用） */
int exec_net_intent_channel(const void *tool, const char *args_json, char **out);

#endif /* _AI_NET_INTENT_H */
