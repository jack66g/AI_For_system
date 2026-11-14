/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_sme.h - occ × SME 长期记忆绑定（T9d，OPENCODE-PLAN §8）
 *
 * 零配置：客户端直连 aikd:8000（smehttp 36 路由正典，复用 memory/
 * sme_client.c——T4 已 C 化，本模块不重写 HTTP/JSON 细节）。
 *
 *   注入：新会话首条消息后 search（首条消息 + 会话名，top_k=8，
 *         tag 过滤 ["occ","user"]）→ 命中段落以 `〈记忆〉` 块进
 *         system prompt（AI 开口就「记得」）。
 *   写回：会话里程碑（用户说「记住」/AI 总结段）→ POST /memories
 *         （tags 含 occ_session，importance 0.5；**会话级 20 条配额**，
 *         读不限）。配额计数落会话侧目录 <sid>.smeq（跨进程一致）。
 *   降级：SME 不可达 → 状态 `@sme:off` 诚实降级，不阻塞对话（绝不
 *         静默空结果）。
 *
 * 环境开关（T9d 契约）：
 *   OCC_SME=off     整体禁用（A/B 实证的「无记忆」腿）
 *   SME_URL         基地址（sme_client 既有约定，缺省 http://127.0.0.1:8000）
 *   OCC_BIND        auto|on|off —— 绑定总闸（见 occ_ac.h 同名段）
 *
 * 线程合同：与 occ_loop_run 同线程调用（worker），内部静态状态无锁；
 * 不可在两个线程并发调用本模块。
 */
#ifndef _OCC_SME_H
#define _OCC_SME_H

#include <stddef.h>

/* 会话级写回配额（§8.3：写回限速，读不限） */
#define OCC_SME_SESSION_QUOTA 20

/* 检索条数上限（§8.1：top_k=8） */
#define OCC_SME_TOP_K 8

/* 检索 tag 过滤（§8.1：tag 过滤 occ/user；服务端为「任一命中」语义） */
#define OCC_SME_SEARCH_TAGS "[\"occ\",\"user\"]"

/* 写回 tags（§8.2 tag=occ_session；附 occ/user 使检索过滤可见） */
#define OCC_SME_WRITE_TAGS "[\"occ\",\"user\",\"occ_session\"]"

/* 写回 importance（§8.2 固定 0.5） */
#define OCC_SME_WRITE_IMPORTANCE 0.5

/* 注入块定界符（system prompt 内；A/B 实证与测试按此断言） */
#define OCC_SME_BLOCK_HEAD "〈记忆〉"
#define OCC_SME_BLOCK_TAIL "〈/记忆〉"

/*
 * occ_sme_enabled - 是否启用（env OCC_SME=off → 0）。缺省启用（零配置）。
 */
int occ_sme_enabled(void);

/*
 * occ_sme_status - 状态文本（ NOTICE用）：
 *   "@sme:on"  最近一次检索/写回成功
 *   "@sme:off" 最近一次调用失败或从未成功过（含服务不可达）
 *   "@sme:?"   尚未发生任何调用（unknown）
 * 返回静态缓冲（下次调用覆盖）。
 */
const char *occ_sme_status(void);

/*
 * occ_sme_lookup - 语义检索并组装注入块。
 * @query: 首条用户消息 + 会话名（调用方拼好）
 * 返回：heap 块 `〈记忆〉\n- …\n〈/记忆〉\n`；无命中/不可达/禁用 → NULL
 *       （NULL 不代表错误——降级由状态位体现，调用方不阻塞）。
 * 命中段落逐条截断 400 字节、整块封顶 6000 字节（防 system 膨胀）。
 */
char *occ_sme_lookup(const char *query);

/*
 * occ_sme_remember - 里程碑写回（POST /memories，tag=occ_session，
 * importance 0.5，会话级 20 条配额）。
 * @session_id: 配额按会话计
 * @title:      会话名（并入记忆文本，可 NULL）
 * @text:       记忆正文（必填，非空）
 * 返回：1=已写入；0=跳过（禁用/配额尽/文本空——不是错误）；
 *       -1=调用失败（SME 不可达等，状态转 off）。
 */
int occ_sme_remember(const char *session_id, const char *title,
		     const char *text);

/*
 * occ_sme_quota_left - 会话剩余写回配额（0..OCC_SME_SESSION_QUOTA）。
 * 文件缺失/不可读按 0 已用处理（=满额）。
 */
int occ_sme_quota_left(const char *session_id);

/* 单测直置状态（生产勿调用）：0=unknown 1=on 2=off；返回旧值。 */
int occ_sme_test_set_state(int v);

/* ---- E6 记忆分层（ORCH §6 拍板 5/8） ---- */
#define OCC_SME_LAYER_GLOBAL "g:"
#define OCC_SME_LAYER_PROJECT "p:"
#define OCC_SME_LAYER_TASK "t:"
#define OCC_SME_TAG_TASK "occ_task"	/* t: 层独占族（主检索不可见） */
#define OCC_SME_TAG_FAILED "occ_failed"	/* failed/rejected 降权族 */

struct sme_search_opts;
struct sme_add_opts;

/* 桥抽象：记忆读写可换/外接（默认=sme_client HTTP；测试注桩） */
struct occ_mem_bridge {
	int (*search)(struct sme_search_opts *o, char *resp, size_t cap);
	int (*add)(struct sme_add_opts *o, char *resp, size_t cap);
};
void occ_sme_set_bridge(const struct occ_mem_bridge *b);

/* 分层写回：layer="g:"/"p:"/"t:<task_id>"（NULL→g:）；status=
 * NULL/"ok"/"failed"/"rejected"（failed/rejected→occ_failed 族
 * +importance 0.3+metadata.status=防污染）。返回 1=写入 0=跳过
 * （配额/禁用）-1=失败。 */
int occ_sme_remember_ex(const char *session_id, const char *title,
			const char *text, const char *layer,
			const char *status);

/* 分层检索：layer_filter 逗号表——"g:,p:"（=基线，缺省）；"t:<tid>"
 * 触发任务层附加检索（命中优先排前）；"failed" 检索降权族。合并
 * top_k=OCC_SME_TOP_K、首 64 字符去重。返回 〈记忆〉 块（free）。 */
char *occ_sme_lookup_ex(const char *query, const char *layer_filter);



#endif /* _OCC_SME_H */
