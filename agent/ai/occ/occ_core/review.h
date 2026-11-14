/* SPDX-License-Identifier: GPL-2.0 */
/*
 * review.h - occ 验收环（ORCH-DESIGN §8 棒 E4；§4 验收环【拍板 2】）
 *
 * 三件套（§8 E4 行）：
 *   1) verdict 机械判解析器——§4「机械判优先」：子智能体交付 verdict
 *      固定表头（标准条目→结果→证据路径→自评）；解析器=逐行状态+文件
 *      存在+md5sum 对照，全过才进主会话复核位。不接受自报数字（W153+T9e
 *      计数错数链教训产品化——「报告自称完成」永不为 pass 依据）。
 *   2) 整改词渲染——§3 整改词模板六要素（未达标准/差距/证据/整改要求/
 *      剩余机会）逐项写死。
 *   3) 验收环驱动——rework 计数/升级三路调对路（回炉/升级人工/终止；
 *      状态迁移本身在 E1 occ_task_verdict，本层负责机械判→调对路→
 *      渲染对应文案）。
 *
 * 机械判报告格式（§4 固定表头；子智能体写往结果文件——E3
 * OCC_TASK_RESULT_FILE 通道）：
 *
 *   # VERDICT
 *   | criterion | result | evidence | self |
 *   | <验收标准条目原文> | pass | <机检令牌> | <自评（判卷永不读）> |
 *
 * 机检令牌（evidence 列合法取值；其余一律按不可机检拒信）：
 *   exit:0                 终局退出码 0（对照 occ_task_event result 行）
 *   file:<path>            文件存在（stat）
 *   md5:<path>=<32hex>     文件 md5sum 对照（小写十六进制）
 *   contains:<path>:<子串> 断言行/自检命令输出在文件内容中（§8 E4
 *                         实现要点：结果文件里的自检命令输出/断言行）
 *   <绝对路径>             裸绝对路径按 file: 处理；相对路径按 base_dir
 *                         归一
 *
 * 规则名（→机检实现映射表见 review.c 各规则注释；均带 §4 原文出处）：
 *   R-EXIT     终局退出码（§4「退出码」）
 *   R-REPORT   结果文件在场且非空（§4「子智能体交付」）
 *   R-HEADER   # VERDICT 标记+固定表头（§4「固定表头」）
 *   R-NOSELF   零机检证据行恒拒——仅自称完成不采信（§4「不接受自报
 *              数字」；防转述验收）
 *   R-COVERAGE 验收标准逐条有对应行（§4「逐行状态」标准条目↔行对齐）
 *   R-ROWPASS  行行 result=pass（§4「全过才进主会话复核位」）
 *   R-EVIDENCE 证据可机检且文件真实在场（§4「文件存在」）
 *   R-MD5      md5sum 对照一致（§4「md5sum 对照」）
 *   R-CONTAINS 断言子串真实命中（§8 E4 实现要点「断言行/自检输出」）
 *
 * 与底座的关系：只读消费 E1（occ_task_get/events/verdict/note）；
 * 不动 task.c/session.c 核心状态机（挂点接线在 orch.c/tools.c）。
 * 线程合同：非线程安全（occ 主环单线程调用）。
 */
#ifndef _OCC_REVIEW_H
#define _OCC_REVIEW_H

#include <stddef.h>

#include "occ_session.h"
#include "task.h"

/* 规则名常量（occ_review_verdict.rule[] 取值） */
#define OCC_RV_R_EXIT		"R-EXIT"
#define OCC_RV_R_REPORT		"R-REPORT"
#define OCC_RV_R_HEADER		"R-HEADER"
#define OCC_RV_R_NOSELF		"R-NOSELF"
#define OCC_RV_R_COVERAGE	"R-COVERAGE"
#define OCC_RV_R_ROWPASS	"R-ROWPASS"
#define OCC_RV_R_EVIDENCE	"R-EVIDENCE"
#define OCC_RV_R_MD5		"R-MD5"
#define OCC_RV_R_CONTAINS	"R-CONTAINS"

#define OCC_RV_MAX_HITS		24	/* 单次判卷记录的失败规则上限 */
#define OCC_RV_DETAIL_MAX	176	/* 每条失败详情字节上限 */
#define OCC_RV_RULE_MAX		16	/* 规则名容量 */
#define OCC_RV_BRIEF_MAX	2048	/* 整改词/升级词渲染缓冲建议值 */

/* 机械判结果（occ_review_parse 输出；occ_review_run 回填给调用方） */
typedef struct occ_review_verdict {
	int pass;		/* 1=全规则过（机械判 pass） */
	int n_hit;		/* 失败规则条数（0..OCC_RV_MAX_HITS） */
	char rule[OCC_RV_MAX_HITS][OCC_RV_RULE_MAX];
	char detail[OCC_RV_MAX_HITS][OCC_RV_DETAIL_MAX];
} occ_review_verdict;

void occ_review_verdict_init(occ_review_verdict *v);

/*
 * occ_review_parse - 机械判核心（纯函数：无 DB、无子进程、无全局态
 * ——fixture 直接喂报告文本即可测验收环纯逻辑，§9 测试策略）。
 *
 *   report            子报告全文（结果文件内容；NULL/空 → R-REPORT）
 *   result_event_json 终局 result 事件 payload JSON（orch collect 落
 *                     的 {"end":..,"exit_code":..}；NULL/解析失败 →
 *                     R-EXIT）
 *   base_dir          相对证据路径归一基目录（可 NULL=按原样）
 *   acceptance        brief 验收标准条目数组（可 NULL/0=跳过 R-COVERAGE）
 *   n_acc             条目数（>64 截断）
 *   out               判卷结果（非 NULL 必填）
 */
void occ_review_parse(const char *report, const char *result_event_json,
		      const char *base_dir,
		      const char *const *acceptance, size_t n_acc,
		      occ_review_verdict *out);

/*
 * occ_review_render_rework - 整改词渲染（§3 整改词模板六要素逐项写死；
 * 判卷失败 → 回炉路径）。attempt=本次失败后的第几次（=rework_count），
 * max=rework_max。judge_rejected=1 表示机械判全过但裁判抽查否决
 * （§4 抽查亲跑强制——差距=裁判表态原文）。返回写入字节数（截断安全）。
 */
size_t occ_review_render_rework(const occ_review_verdict *v,
				int judge_rejected, const char *judge_note,
				int attempt, int max,
				char *buf, size_t buflen);

/*
 * occ_review_render_escalate - 超限升级词渲染（三路之「升级人工」：
 * 换智能体/拆任务/上抛用户——§4；子智能体永不直接对话用户）。attempts=
 * 已用回炉次数（>max）。
 */
size_t occ_review_render_escalate(const occ_review_verdict *v,
				  int judge_rejected, const char *judge_note,
				  int attempts, int max,
				  char *buf, size_t buflen);

/*
 * occ_review_run - 验收环驱动（DB 面；task 须 in_review——E1 verdict
 * 状态机门槛）。流程：
 *   brief 验收标准+最后 result 事件+结果文件 → occ_review_parse 机械判
 *   → 机械判 fail：judge_pass 强制无效（防转述：不接受报告/裁判转述
 *     自称完成）→ occ_task_verdict(0)（E1 按计数分路 rework/escalated）
 *   → 机械判 pass：judge_pass=1 → occ_task_verdict(1)（done）；
 *     judge_pass=0 → occ_task_verdict(0)（裁判否决也回炉/超限升级）
 *   → 回读终态，渲染整改词/升级词（done 则空串）+ 回写任务事件
 *     （kind='return'：judge 表态 + rework_brief/escalate_brief 审计）
 *
 * opts 可 NULL（=无结果文件、裁判弃权——机械判 fail 路径仍可走）。
 * 出参 out_v/out_brief/out_state 均可 NULL 不取。返回 0 成功；-1=err
 * 人话（任务不存在/非 in_review/库错——调用方如实上抛，不静默）。
 */
typedef struct occ_review_opts {
	const char *result_path;	/* 结果文件（可 NULL） */
	const char *base_dir;		/* 相对证据基目录（可 NULL） */
	const char *judge_note;		/* 主会话表态原文（可 NULL） */
	int judge_pass;			/* 表态位（机械判过才生效） */
} occ_review_opts;

int occ_review_run(occ_db *db, const char *task_id,
		   const occ_review_opts *opts,
		   occ_review_verdict *out_v,
		   char *out_brief, size_t brieflen,
		   char *out_state, size_t statelen,
		   char *err, size_t errlen);

/*
 * occ_review_prenote - 终局机械预判（orch.c 挂点：子进程终局收口即
 * 判一次卷，结果落 kind='return' 审计事件 payload
 * {"action":"machine_verdict",...}——不动状态机、不影响裁判后续
 * 裁决；read_result/裁判可提前看到机械判结论）。best effort：任何
 * 失败（任务读不回/库错）静默返回 -1，绝不阻断运行时收口。产品路径
 * 只读文件+查库，零子进程。
 */
int occ_review_prenote(occ_db *db, const char *task_id,
		       const char *result_path);

/* 文件 md5（小写十六进制 32 位）——机检 R-MD5 底座；0 成功 */
int occ_review_md5_file(const char *path, char *hex, size_t hexlen);

#endif /* _OCC_REVIEW_H */
