/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net_hit.h - W81 V3.2 规则命中观测闭环（TOOL_CH_NETINTENT，两件）
 *
 *   1. net_hit_watch   start/stop/status 合一的后台采样器：
 *                      start  → 采样（默认 5s）→ 窗口判定（默认 60s 内某条
 *                               drop 规则命中 ≥ N 包）→ 三档响应 + 审计
 *                      status → 运行态/采样态/升级规则剩余 TTL/降级规则/审计尾
 *                      stop   → 停采样器 + 撤升级规则 + 恢复降级规则
 *   2. net_hit_policy  阈值配置（get/set）：threshold/window/interval/
 *                      cooldown/chain/handle/escalate_src/escalate_ttl
 *
 * 三档响应（按风险分级，判定在 policy/ai_lease.c）：
 *   alert    （D1）只写 audit.log + events.jsonl + 快照，绝不动规则
 *   escalate （D3）追加一条带 TTL 的严格规则（源地址隔离 drop），到期自动撤
 *   degrade  （D3）把命中的 drop/reject 规则降级为只记日志（counter+log），
 *                  stop/重启清理时按原动作恢复
 *
 * 生命周期：start 分叉出 setsid 后台进程（父进程只做 nft 可用性探测与
 * 单例锁握手，不阻塞会话）；stop 先 SIGTERM 等自清理，超时才 SIGKILL 并
 * 由 stop 自己按持久化记录清残；进程被杀后留下 state=running + 死 pid，
 * status 标 orphan，下次 start/stop 先撤升级规则/恢复降级规则再继续。
 *
 * 安全边界：
 *   - 只读 nft -j list ruleset / nft -a list chain；响应动作只针对
 *     start 时显式给出的 inet <table>（表名白名单），绝不 flush ruleset；
 *   - escalate 的源地址串严格校验（只允许 IPv4/IPv6 字面量与 /前缀），
 *     注入面为零；降级用的规则文本来自 nft 自身输出且先 nft -c 预检；
 *   - 宿主默认 netns 实测禁止：live 测试要求 AIK_TEST_NETNS=1 且位于
 *     ip netns aiktest 内，否则 REFUSE。
 */
#ifndef _AI_NET_HIT_H
#define _AI_NET_HIT_H

#include <stddef.h>

#define NH_LEVEL_ALERT		"alert"
#define NH_LEVEL_ESCALATE	"escalate"
#define NH_LEVEL_DEGRADE	"degrade"

/* 每条被观测规则的滑动窗口样本数上限（window/interval 超过即拒绝） */
#define NH_HIST			256

struct nh_cfg {
	char table[16];
	char chain[64];		/* 空 = 任意链 */
	long handle;		/* 0 = 任意规则 */
	int threshold;		/* 窗口内命中包数阈值 */
	int window;		/* 判定窗口（秒） */
	int interval;		/* 采样周期（秒） */
	int cooldown;		/* 同一规则再次触发的最小间隔（秒） */
	char level[16];		/* alert/escalate/degrade（start 时显式给出） */
	char esc_src[64];	/* escalate 隔离源（IPv4/IPv6 或前缀） */
	int esc_ttl;		/* escalate 临时规则 TTL（秒） */
};

struct nh_hist {
	long ts[NH_HIST];
	long d[NH_HIST];
	int n;
	int head;
};

/* 纯函数（导出供单测） */
void nh_cfg_default(struct nh_cfg *c);
int nh_cfg_parse(const char *json, struct nh_cfg *c, char *err, size_t ecap);
int nh_cfg_check(struct nh_cfg *c, char *err, size_t ecap);
int nh_src_valid(const char *s);
int nh_chain_valid(const char *s);
int nh_level_valid(const char *s);
void nh_hist_add(struct nh_hist *h, long ts, long d);
long nh_hist_sum(const struct nh_hist *h, long now, int window);
int nh_should_fire(long sum, int threshold, long now, long last_fire,
		   int cooldown);

/* nft 文本解析（降级路径）：从 nft -a list chain 原文里取指定 handle
 * 的单行规则，拆出 match 部分与动作；多行/跳转/含语句分隔符一律拒绝。 */
int nh_parse_rule_text(const char *listing, long handle, char *match,
		       size_t mcap, char *action, size_t acap, char *err,
		       size_t ecap);
int nh_parse_handle_by_comment(const char *listing, const char *comment,
			       long *handle);

/* 状态目录：AIKERNEL_NFT_HIT_DIR 优先；root /run/aik-nft-hit；
 * 非 root /tmp/aik-nft-hit-<uid>。返回 0 表示目录可写。 */
int nh_hit_dir(char *out, size_t cap);

/* 执行器入口（net_intent.c 的 TOOL_CH_NETINTENT 分发调用） */
int exec_net_hit_tool(const char *name, const char *args_json, char **out);

#endif /* _AI_NET_HIT_H */
