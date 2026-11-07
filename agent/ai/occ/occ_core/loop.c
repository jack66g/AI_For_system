/* SPDX-License-Identifier: GPL-2.0 */
/*
 * loop.c - occ agent 环（T9a3 最小环 + T9b1 工具环激活）
 *
 * 环实现见 occ_loop.h 头注。b1 环语义（OPENCODE-PLAN §6）：
 *
 *   轮 A（无未应答调用）：组装上下文（system + 库内窗口全量 + 六件套
 *       工具定义）→ LLM 流式 → assistant 消息落库（携带 toolCall 时
 *       interim=1：status 保持 running）
 *   轮 B（存在未应答调用——新落库的或崩溃残留的）：逐个执行（occ_tools：
 *       快照→执行→trace→occ_toolcall 行+tool 结果消息单事务落库）→
 *       回到轮 A（上下文从库重读=回灌，durable：先落库再回灌）
 *   终止：模型无工具调用收口 / 步数上限（OCC_LOOP_MAX_STEPS，LLM 轮+
 *       执行批合计；上限批的工具仍执行以闭合上下文）/ OutputLimit
 *       （finish=length）续跑至多 OCC_LOOP_MAX_LEN_CONT 次 /
 *       LLM 失败（status=error，可 recover）
 *
 * durable：一切状态先落 SQLite 再前进；kill -9 任意时刻库中无半条消息。
 * occ --recover 对 status∈{running,error} 的会话：尾=user → 重放该环；
 * 尾=tool 或尾=assistant(toolCall 未全应答) → 续跑（先执行 pending 再
 * LLM 轮）。窗口裁剪仍是后续棒（occ_window 恒 native 全量）。
 *
 * 有意差异（PLAN §6 在案）：opencode 每 tool-call 并发 fiber → occ
 * 顺序执行+每工具超时（终端场景收益低、可审计性高）。
 */
#define _POSIX_C_SOURCE 200809L
#include "occ_loop.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "occ_revert.h"
#include "occ_sysprompt.h"
#include "occ_tools.h"

/* 中断续传注记（OCD §7.1 runner 同语义；b2 headless 版） */
#define OCC_CONT_NOTE \
	"（上一轮回复被中断，请从中断处继续，不要重复已完成的内容。）\n"

/* occ 系统提示（b1 工具版；定义在此唯一实例，头文件 extern） */
const char OCC_SYSTEM_PROMPT[] =
	"你是 AIKernel 系统内置的编码助手 occ。你运行在 AIKernel（一个内置 "
	"AI 能力的类 Linux 操作系统）上，任务是协助用户完成编程、系统管理"
	"与信息处理。回答要求：\n"
	"1. 使用简体中文，直接、准确、可操作；不确定就明说，不编造。\n"
	"2. 代码给出关键片段与必要说明，不冗长铺垫。\n"
	"3. 你可以直接调用工具完成任务：read 读文件（行窗 offset/limit）、"
	"write 写整文件、edit 精确字符串替换（oldString 唯一或 replaceAll）、"
	"glob 找文件、grep 搜文本、bash 在沙箱中执行命令（gcc 编译、运行程"
	"序等）。多步任务请连续调用工具直到完成，再用中文总结结果；工具报"
	"错时读取错误信息修正后重试或如实报告。bash 在 aik-sandbox 隔离区"
	"内执行：工作目录已读写挂入，宿主其余路径不可见。\n"
	"4. 会话历史完整保留，可引用此前内容与工具结果。";

/* ---- 步数/续跑上限（PLAN §6） ---- */
#define OCC_LOOP_MAX_STEPS 24
#define OCC_LOOP_MAX_LEN_CONT 2

/* ---- dynbuf ---- */

typedef struct {
	char *buf;
	size_t len, cap;
	int oom;
} dbuf;

static void db_append(dbuf *d, const char *s, size_t n)
{
	if (d->oom || !n)
		return;
	if (d->len + n + 1 > d->cap) {
		size_t nc = d->cap ? d->cap : 256;
		char *nb;

		while (d->len + n + 1 > nc)
			nc *= 2;
		nb = realloc(d->buf, nc);
		if (!nb) {
			d->oom = 1;
			return;
		}
		d->buf = nb;
		d->cap = nc;
	}
	memcpy(d->buf + d->len, s, n);
	d->len += n;
	d->buf[d->len] = '\0';
}

static void db_append_str(dbuf *d, const char *s)
{
	if (s)
		db_append(d, s, strlen(s));
}

/* ---- 事件收集器 ---- */

typedef struct {
	dbuf text;
	dbuf reasoning;
	occ_usage usage;
	char finish[24];
	int have_finish;
	int llm_error;
	char last_error[256];		/* 最近 OCC_EV_ERROR 的 err 文本 */
	/* tool_call 收集（b1：期望路径；按 idx 槽位累积 args 增量） */
	struct {
		char id[128];
		char name[128];
		dbuf args;
	} calls[16];
	int ncalls;
	occ_loop_opts *opts;		/* stream_out / reasoning_out */
} loop_ev_ctx;

static void ev_ctx_reset_keep_opts(loop_ev_ctx *c);

static void ev_cb(const occ_event *ev, void *ud)
{
	loop_ev_ctx *c = ud;

	switch (ev->type) {
	case OCC_EV_TEXT_DELTA:
		if (c->opts && c->opts->stream_out && ev->text) {
			fputs(ev->text, c->opts->stream_out);
			fflush(c->opts->stream_out);	/* headless 流式 */
		}
		db_append_str(&c->text, ev->text);
		break;
	case OCC_EV_REASONING_DELTA:
		if (c->opts && c->opts->reasoning_out && ev->text) {
			fputs(ev->text, c->opts->reasoning_out);
			fflush(c->opts->reasoning_out);
		}
		db_append_str(&c->reasoning, ev->text);
		break;
	case OCC_EV_TOOL_START:
		if (ev->idx >= 0 && ev->idx < (int)(sizeof(c->calls) /
		    sizeof(c->calls[0]))) {
			if (ev->idx + 1 > c->ncalls)
				c->ncalls = ev->idx + 1;
			if (ev->id)
				snprintf(c->calls[ev->idx].id,
					 sizeof(c->calls[ev->idx].id),
					 "%s", ev->id);
			if (ev->name)
				snprintf(c->calls[ev->idx].name,
					 sizeof(c->calls[ev->idx].name),
					 "%s", ev->name);
		}
		break;
	case OCC_EV_TOOL_ARGS:
		if (ev->idx >= 0 && ev->idx < c->ncalls)
			db_append_str(&c->calls[ev->idx].args, ev->args);
		break;
	case OCC_EV_USAGE:
		c->usage = ev->usage;	/* 流末最终值覆盖 */
		break;
	case OCC_EV_FINISH:
		snprintf(c->finish, sizeof(c->finish), "%s",
			 ev->finish ? ev->finish : "");
		c->have_finish = 1;
		break;
	case OCC_EV_ERROR:
		c->llm_error = 1;
		if (ev->err)
			snprintf(c->last_error, sizeof(c->last_error),
				 "%s", ev->err);
		if (c->opts && c->opts->stream_out)
			fflush(c->opts->stream_out);
		break;
	case OCC_EV_RESET:
		/*
		 * 传输层自动重试：上一尝试的部分输出作废（对齐 opencode
		 * 重试即重置 UI）。清空已累积 text/reasoning/calls/usage/
		 * finish；重试通告走 stderr（headless 的「UI 重置位」；
		 * stdout 已流出的字节无法收回——如实差异在报告）。
		 */
		ev_ctx_reset_keep_opts(c);
		if (ev->err)
			fprintf(stderr, "occ: %s\n", ev->err);
		break;
	default:
		break;
	}
}

/*
 * needsContinuation（PLAN §6，b1 激活）：收集到 tool_call（finish 依
 * 厂商可能为 tool-calls 或 stop——opencode 按「有调用即执行」语义，
 * 照做）→ 执行工具后续环。
 */
static int needs_continuation(const loop_ev_ctx *c)
{
	return c->ncalls > 0;
}

/* ---- forwarder→direct 兜底（occ_smoke.c 先例，驱动层策略） ---- */

static int is_loopback(const char *url)
{
	return url && (strstr(url, "127.0.0.1") || strstr(url, "localhost"));
}

/* 重置事件收集器（保留 opts；occ_smoke 先例：失败尝试的传输错误事件
 * 不混入成功输出） */
static void ev_ctx_reset_keep_opts(loop_ev_ctx *c)
{
	occ_loop_opts *keep = c->opts;
	int k;

	for (k = 0; k < (int)(sizeof(c->calls) / sizeof(c->calls[0])); k++)
		free(c->calls[k].args.buf);
	free(c->text.buf);
	free(c->reasoning.buf);
	memset(c, 0, sizeof(*c));
	c->opts = keep;
}

static void ev_ctx_free(loop_ev_ctx *c)
{
	int k;

	for (k = 0; k < (int)(sizeof(c->calls) / sizeof(c->calls[0])); k++)
		free(c->calls[k].args.buf);
	free(c->text.buf);
	free(c->reasoning.buf);
	memset(c, 0, sizeof(*c));
}

/* ---- 上下文组装：库内消息 → occ_msg 数组（b1：含 tool 角色回放 +
 * assistant 工具调用历史回放）。b2：被撤（reverted=1）与 system 注记
 * 行不进请求——注记已在 add_user 前折叠进 user 文本（opencode
 * messagesFromRevert 同语义） ---- */

static int build_msgs(const occ_msg_row *rows, size_t n, occ_msg **out,
		      occ_tool_call **scratch, size_t *nv_out)
{
	occ_msg *m;
	size_t i, j, total = 0, used = 0, vis = 0;
	occ_tool_call *sc = NULL;

	for (i = 0; i < n; i++) {
		if (rows[i].reverted || !strcmp(rows[i].role, "system"))
			continue;
		vis++;
		if (!strcmp(rows[i].role, "assistant"))
			total += rows[i].ncalls;
	}
	m = calloc(vis ? vis : 1, sizeof(*m));
	if (!m)
		return -1;
	if (total) {
		sc = calloc(total, sizeof(*sc));
		if (!sc) {
			free(m);
			return -1;
		}
	}
	for (i = 0, j = 0; i < n; i++) {
		if (rows[i].reverted || !strcmp(rows[i].role, "system"))
			continue;
		if (!strcmp(rows[i].role, "assistant")) {
			m[j].role = OCC_ROLE_ASSISTANT;
			m[j].text = rows[i].text ? rows[i].text : "";
			m[j].reasoning = rows[i].reasoning;
			if (rows[i].ncalls) {
				size_t k;

				m[j].calls = &sc[used];
				m[j].ncalls = rows[i].ncalls;
				for (k = 0; k < rows[i].ncalls; k++) {
					sc[used].id = rows[i].calls[k].id ?
						      rows[i].calls[k].id : "";
					sc[used].name = rows[i].calls[k].tool ?
							rows[i].calls[k].tool :
							"";
					sc[used].arguments =
						rows[i].calls[k].arguments ?
						rows[i].calls[k].arguments :
						"{}";
					used++;
				}
			}
		} else if (!strcmp(rows[i].role, "tool")) {
			m[j].role = OCC_ROLE_TOOL;
			m[j].text = rows[i].text ? rows[i].text : "";
			m[j].tool_call_id = rows[i].tool_call_id ?
					    rows[i].tool_call_id : "";
		} else {
			m[j].role = OCC_ROLE_USER;
			m[j].text = rows[i].text ? rows[i].text : "";
		}
		j++;
	}
	*out = m;
	*scratch = sc;
	if (nv_out)
		*nv_out = vis;
	return 0;
}

void occ_loop_result_free(occ_loop_result *r)
{
	if (!r)
		return;
	free(r->text);
	free(r->reasoning);
	memset(r, 0, sizeof(*r));
}

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || !errlen)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* ---- 轮 B：pending 调用逐个执行（顺序+每工具超时，有意差异在案）；
 * durable 落库在 occ_tool_exec 内单事务 ---- */

/* ---- b2：user 文本组装——undo 注记折叠 + 中断续传注记 ----
 * 独立 system 注记不进请求（anthropic 只在顶层收 system 且不许连续
 * user；openai 亦无 system 中置位）——add_user 前折叠进 user 文本。
 * 返回注记 id 列表：调用方在 add_user 成功后删除（失败则保留下次再
 * 折叠，不丢注记）。 */
static int compose_user_text(occ_db *db, const char *sess_id,
			     const char *prompt, int was_interrupted,
			     char **out_text, char ***note_ids,
			     size_t *n_notes, char *err, size_t errlen)
{
	occ_msg_row *rows = NULL;
	size_t n = 0, i, nn = 0;
	char **ids = NULL;
	dbuf buf;

	memset(&buf, 0, sizeof(buf));
	*out_text = NULL;
	*note_ids = NULL;
	*n_notes = 0;
	if (occ_msg_list(db, sess_id, &rows, &n, err, errlen))
		return -1;
	ids = calloc(n ? n : 1, sizeof(*ids));
	if (!ids) {
		occ_msg_rows_free(rows, n);
		set_err(err, errlen, "compose_user_text: oom");
		return -1;
	}
	for (i = 0; i < n; i++) {
		if (strcmp(rows[i].role, "system") || rows[i].reverted)
			continue;
		if (rows[i].text && rows[i].text[0]) {
			db_append_str(&buf, rows[i].text);
			db_append_str(&buf, "\n\n");
		}
		ids[nn] = strdup(rows[i].id);
		if (!ids[nn]) {
			size_t k;

			occ_msg_rows_free(rows, n);
			for (k = 0; k < nn; k++)
				free(ids[k]);
			free(ids);
			free(buf.buf);
			set_err(err, errlen, "compose_user_text: oom");
			return -1;
		}
		nn++;
	}
	occ_msg_rows_free(rows, n);
	if (was_interrupted)
		db_append_str(&buf, OCC_CONT_NOTE);
	db_append_str(&buf, prompt);
	if (buf.oom || !buf.buf) {
		size_t k;

		for (k = 0; k < nn; k++)
			free(ids[k]);
		free(ids);
		free(buf.buf);
		set_err(err, errlen, "compose_user_text: oom");
		return -1;
	}
	*out_text = buf.buf;
	*note_ids = ids;
	*n_notes = nn;
	return 0;
}

/*
 * 执行一批未应答调用（顺序+每工具超时，有意差异在案）。b2 中断安全点：
 * 中断若在 LLM 轮即已置位（flag_at_start）→ 该批整体执行以闭合上下文
 * （OpenAI 工具应答不变量）；执行中才观察到中断 → 当前工具完成后停，
 * 剩余调用以「未执行」合成结果闭合（绝不留无应答的 tool_call）。
 * 返回实际执行数。
 */
static size_t exec_pending(occ_db *db, const char *sess_id,
			   const occ_toolcall_part *calls, size_t ncalls,
			   const char *asst_msg_id, const occ_loop_opts *opts)
{
	occ_tool_ctx tc;
	size_t i;
	char cwd[4096];
	char ebuf[128];
	int flag_at_start = occ_interrupt_flag;

	memset(&tc, 0, sizeof(tc));
	tc.db = db;
	tc.session_id = sess_id;
	tc.msg_id = asst_msg_id;
	tc.timeout_ms = 0;			/* 缺省（env 可配） */
	if (opts && opts->workdir && opts->workdir[0]) {
		tc.workdir = opts->workdir;
	} else if (getcwd(cwd, sizeof(cwd))) {
		tc.workdir = cwd;
	}
	for (i = 0; i < ncalls; i++) {
		occ_tool_result r;

		if (i > 0 && !flag_at_start && occ_interrupt_flag)
			break;			/* 安全点：当前工具完成后停 */
		occ_tool_exec(&tc, calls[i].tool ? calls[i].tool : "",
			      calls[i].id ? calls[i].id : "",
			      calls[i].arguments ?
			      calls[i].arguments : "{}", &r);
		/* 工具意外失败=错误文本已作为 tool 结果回灌模型（不崩） */
		occ_tool_result_free(&r);
	}
	for (; i < ncalls; i++) {
		/* 合成闭合（b2）：中断跳过的调用补 tool 应答 */
		occ_tool_record(db, sess_id, asst_msg_id,
				calls[i].tool ? calls[i].tool : "",
				calls[i].arguments ? calls[i].arguments : "{}",
				"未执行（用户中断）——安全点停止跳过该调用",
				1, 0, calls[i].id ? calls[i].id : "",
				NULL, 0, NULL, 0, ebuf, sizeof(ebuf));
	}
	return i;
}

/* pending 数组释放 */
static void pend_free(occ_toolcall_part *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		free(p[i].id);
		free(p[i].tool);
		free(p[i].arguments);
	}
	free(p);
}

int occ_loop_run(occ_db *db, const occ_provider *p, const char *session_id,
		 const occ_loop_opts *opts, occ_loop_result *res,
		 char *err, size_t errlen)
{
	occ_loop_opts def_opts;
	occ_session_row sess;
	occ_msg_row *rows = NULL;
	size_t nmsgs = 0;
	occ_msg *req_msgs = NULL;
	occ_tool_call *req_calls = NULL;
	occ_llm_req req;
	loop_ev_ctx ctx;
	occ_llm_call_fn call_fn;
	char *llm_err = NULL;
	char mid[OCC_ID_LEN];
	char dbuf_err[160];
	int steps = 0, len_conts = 0, total_calls = 0;
	int rc = OCC_LOOP_OK;
	int replayed = 0;
	int interrupted = 0;			/* b2：SIGINT 安全点停 */
	size_t i;
	const occ_tool_def *tdefs;
	size_t ntools = 0;

	memset(&ctx, 0, sizeof(ctx));		/* goto out 清理路径安全 */
	if (res)
		memset(res, 0, sizeof(*res));
	if (!db || !p) {
		set_err(err, errlen, "occ_loop_run: bad args");
		return OCC_LOOP_EARGS;
	}
	if (!opts) {
		memset(&def_opts, 0, sizeof(def_opts));
		opts = &def_opts;
	}
	tdefs = occ_tool_defs(&ntools);

	/* 1) 会话：新建或续接 */
	if (!session_id) {
		if (occ_session_create(db, p->model, &sess, err, errlen)) {
			rc = OCC_LOOP_EARGS;
			goto out;
		}
	} else {
		int g = occ_session_get(db, session_id, &sess, err, errlen);

		if (g <= 0) {
			set_err(err, errlen,
				"occ_loop_run: session %s not found",
				session_id);
			rc = OCC_LOOP_EARGS;
			goto out;
		}
		snprintf(sess.id, sizeof(sess.id), "%s", session_id);
	}

	/* b2：工具工作目录落库（undo 相对路径解析与执行时同口径） */
	if (opts->workdir && opts->workdir[0]) {
		if (occ_session_set_workdir(db, sess.id, opts->workdir,
					    dbuf_err, sizeof(dbuf_err)))
			fprintf(stderr, "occ: workdir 落库失败（%s）\n",
				dbuf_err);
	}

	/* 2) 输入消息落库（或重放/续跑判定） */
	if (opts->prompt && opts->prompt[0]) {
		char *utext = NULL;
		char **nids = NULL;
		size_t nn = 0;
		int was_int = !strcmp(sess.status, OCC_ST_INTERRUPTED);

		/*
		 * b2：undo 注记折叠 + 中断续传注记（OCD §7.1 runner 同
		 * 语义）——注记并入本轮 user 文本，不留独立 system 行。
		 */
		if (compose_user_text(db, sess.id, opts->prompt, was_int,
				      &utext, &nids, &nn, err, errlen)) {
			rc = OCC_LOOP_EARGS;
			goto out;
		}
		/* 用户重发即认（OCD §7.3 提交语义）：撤销落地，此后不可
		 * 再 redo（stage 行与 _redo 段清除，注记已折叠留档）。 */
		occ_revert_commit(db, sess.id, NULL);
		if (occ_msg_add_user(db, sess.id, utext, mid, sizeof(mid),
				     err, errlen)) {
			free(utext);
			for (i = 0; i < nn; i++)
				free(nids[i]);
			free(nids);
			rc = OCC_LOOP_EARGS;
			goto out;
		}
		free(utext);
		/* 注记已进 user 文本 → 删注记行（失败仅警告：下次再折） */
		for (i = 0; i < nn; i++) {
			if (occ_msg_delete(db, nids[i], dbuf_err,
					   sizeof(dbuf_err)))
				fprintf(stderr, "occ: 删注记失败（%s）\n",
					dbuf_err);
			free(nids[i]);
		}
		free(nids);
	} else {
		/*
		 * 重放/续跑（occ --recover）：running（kill -9 中断）/
		 * error（上次 LLM 失败）/ interrupted（b2 SIGINT 安全点停）。
		 * 合法形态：尾=user（环未跑过 LLM）/ 尾=tool /
		 * 尾=assistant(toolCall 未全应答)。
		 */
		occ_msg_row last;
		int has = occ_msg_last(db, sess.id, &last, err, errlen);
		int ok_tail = 0;

		if (has < 0) {
			rc = OCC_LOOP_EARGS;
			goto out;
		}
		if ((!strcmp(sess.status, OCC_ST_RUNNING) ||
		     !strcmp(sess.status, OCC_ST_ERROR) ||
		     !strcmp(sess.status, OCC_ST_INTERRUPTED)) && has > 0) {
			if (!strcmp(last.role, "user")) {
				ok_tail = 1;	/* 重放整环 */
			} else if (!strcmp(last.role, "tool")) {
				ok_tail = 1;	/* 续跑（轮 A） */
			} else if (!strcmp(last.role, "assistant")) {
				occ_toolcall_part *pend = NULL;
				size_t npend = 0;

				if (occ_msg_pending_calls(db, sess.id,
						&pend, &npend, NULL, 0,
						err, errlen) < 0) {
					occ_msg_row_free(&last);
					rc = OCC_LOOP_EARGS;
					goto out;
				}
				ok_tail = npend > 0;	/* 续跑（先轮 B） */
				pend_free(pend, npend);
			}
		}
		if (!ok_tail) {
			set_err(err, errlen,
				"occ_loop_run: no in-flight turn to replay"
				" (status=%s last=%s)",
				sess.status, has > 0 ? last.role : "none");
			occ_msg_row_free(&last);
			rc = OCC_LOOP_EARGS;
			goto out;
		}
		occ_msg_row_free(&last);
		replayed = 1;
		fprintf(stderr, "occ: replaying interrupted turn from db\n");
	}

	/* 3) 环（b1 激活：轮 A=LLM / 轮 B=工具执行，上下文每轮从库重读） */
	call_fn = opts->llm_call;
	for (;;) {
		occ_toolcall_part *pend = NULL;
		size_t npend = 0;
		char asst_id[OCC_ID_LEN];

		if (rows) {
			occ_msg_rows_free(rows, nmsgs);
			rows = NULL;
			nmsgs = 0;
		}
		if (occ_msg_list(db, sess.id, &rows, &nmsgs, err, errlen)) {
			rc = OCC_LOOP_EARGS;
			goto out;
		}
		if (occ_msg_pending_calls(db, sess.id, &pend, &npend,
					  asst_id, sizeof(asst_id),
					  err, errlen) < 0) {
			rc = OCC_LOOP_EARGS;
			goto out;
		}
		if (npend > 0) {
			/* 轮 B：执行未应答调用（新落库或崩溃残留；b2 中断
			 * 安全点与合成闭合在 exec_pending 内） */
			total_calls += (int)exec_pending(db, sess.id, pend,
							 npend, asst_id,
							 opts);
			pend_free(pend, npend);
			steps++;
			if (occ_interrupt_flag) {
				/* b2：安全点停——状态 interrupted（可
				 * retry/续接/recover），尾态=tool 无 pending */
				set_err(err, errlen,
					"interrupted by user (safe point after"
					" tool batch)");
				occ_session_set_status(db, sess.id,
							OCC_ST_INTERRUPTED,
							dbuf_err,
							sizeof(dbuf_err));
				interrupted = 1;
				rc = OCC_LOOP_OK;
				goto fill_res;
			}
			if (steps >= OCC_LOOP_MAX_STEPS) {
				/* 步数上限：该批已执行（上下文闭合）收口 */
				set_err(err, errlen,
					"step limit %d reached; turn closed"
					" (tool calls executed=%d)",
					OCC_LOOP_MAX_STEPS, total_calls);
				occ_session_set_status(db, sess.id,
							OCC_ST_ACTIVE,
							dbuf_err,
							sizeof(dbuf_err));
				if (res)
					res->steps_capped = 1;
				rc = OCC_LOOP_OK;
				goto fill_res;
			}
			continue;		/* 轮 A：库重读后 LLM */
		}
		pend_free(pend, npend);

		/* b2 安全点：无待执行调用且已被中断 → 停在 LLM 轮前
		 *（尾态保持可重放：user/tool/收口 assistant） */
		if (occ_interrupt_flag) {
			set_err(err, errlen,
				"interrupted by user (safe point before LLM"
				" round)");
			occ_session_set_status(db, sess.id,
						OCC_ST_INTERRUPTED, dbuf_err,
						sizeof(dbuf_err));
			interrupted = 1;
			rc = OCC_LOOP_OK;
			goto fill_res;
		}

		/* 轮 A：LLM */
		free(req_msgs);
		free(req_calls);
		req_msgs = NULL;
		req_calls = NULL;
		{
			size_t nv = 0;

			if (build_msgs(rows, nmsgs, &req_msgs, &req_calls,
				       &nv)) {
				set_err(err, errlen, "occ_loop_run: msgs oom");
				rc = OCC_LOOP_EARGS;
				goto out;
			}
			memset(&req, 0, sizeof(req));
			req.proto = p->proto;
			req.model = p->model;
			req.system = OCC_SYSTEM_PROMPT;
			req.msgs = req_msgs;
			req.nmsgs = nv;		/* b2：过滤被撤/注记后可见数 */
			req.tools = tdefs;			/* b1：六件套 */
			req.ntools = ntools;
		}

		ev_ctx_reset_keep_opts(&ctx);		/* 每轮新收集器 */
		ctx.opts = (occ_loop_opts *)opts;
		if (call_fn) {
			if (call_fn(p, &req, ev_cb, &ctx, &llm_err) != 0 ||
			    ctx.llm_error) {
				if (occ_interrupt_flag)
					goto llm_interrupted;
				goto llm_fail;
			}
		} else {
			if (occ_llm_call(p, &req, ev_cb, &ctx, &llm_err) ||
			    ctx.llm_error) {
				if (occ_interrupt_flag)
					goto llm_interrupted;
				if (is_loopback(p->base_url) &&
				    p->proto == OCC_PROTO_OPENAI_COMPAT) {
					occ_provider d;

					/* 重置收集器后 direct 重试
					 *（occ_smoke 先例） */
					free(llm_err);
					llm_err = NULL;
					ev_ctx_reset_keep_opts(&ctx);
					ctx.opts = (occ_loop_opts *)opts;
					memset(&d, 0, sizeof(d));
					snprintf(d.name, sizeof(d.name),
						 "%s", p->name);
					d.proto = p->proto;
					snprintf(d.model, sizeof(d.model),
						 "%s", p->model);
					snprintf(d.base_url,
						 sizeof(d.base_url), "%s",
						 "https://api.deepseek.com/v1");
					d.api_key = p->api_key;/* 借用不转移 */
					if (occ_llm_call(&d, &req, ev_cb,
							 &ctx, &llm_err) ||
					    ctx.llm_error) {
						if (occ_interrupt_flag)
							goto llm_interrupted;
						goto llm_fail;
					}
				} else {
					goto llm_fail;
				}
			}
		}
		free(llm_err);
		llm_err = NULL;

		/* assistant 落库（携带 toolCall → interim=1，status=running）*/
		{
			occ_usage u = ctx.usage;
			int est = 0;
			occ_tool_call tc[16];
			size_t i;

			if (!u.present) {
				/* len/4 估算兜底（a3 口径；b2 起按可见
				 * 消息——被撤/注记不计） */
				long long in_est = occ_tokens_estimate_len(
					OCC_SYSTEM_PROMPT);
				size_t j;

				for (j = 0; j < req.nmsgs; j++)
					in_est += occ_tokens_estimate_len(
						req_msgs[j].text ?
						req_msgs[j].text : "");
				u.present = 1;
				u.input = in_est;
				u.output = occ_tokens_estimate_output(
					ctx.text.buf ? ctx.text.buf : "");
				u.cache_read = 0;
				u.cache_write = 0;
				est = 1;
			}
			for (i = 0; (int)i < ctx.ncalls && i < 16; i++) {
				tc[i].id = ctx.calls[i].id;
				tc[i].name = ctx.calls[i].name;
				tc[i].arguments = ctx.calls[i].args.buf ?
						  ctx.calls[i].args.buf : "{}";
			}
			if (occ_msg_add_assistant_ex(db, sess.id,
					ctx.text.buf ? ctx.text.buf : "",
					ctx.reasoning.buf, tc,
					(size_t)ctx.ncalls, &u, est,
					ctx.finish,
					ctx.ncalls > 0 ? 1 : 0,
					mid, sizeof(mid), err, errlen)) {
				rc = OCC_LOOP_EARGS;
				goto out;
			}
			if (res) {
				res->usage = u;
				occ_tokens_set_usage(&res->tokens, &u);
				res->usage_est = est;
				snprintf(res->assistant_msg_id,
					 sizeof(res->assistant_msg_id),
					 "%s", mid);
			}
		}

		if (needs_continuation(&ctx)) {
			steps++;
			if (steps >= OCC_LOOP_MAX_STEPS) {
				/* 上限：仍执行该批（闭合上下文）后收口
				 * ——迭代顶部 pending 路径完成执行并收口 */
				set_err(err, errlen,
					"step limit %d reached; executing"
					" final tool batch then closing",
					OCC_LOOP_MAX_STEPS);
				if (res)
					res->steps_capped = 1;
				continue;
			}
			continue;		/* 轮 B：执行刚落库的调用 */
		}

		/* OutputLimit 续跑（finish=length 且有正文，至多 2 次） */
		if (!strcmp(ctx.finish, "length") && ctx.text.buf &&
		    ctx.text.buf[0] && len_conts < OCC_LOOP_MAX_LEN_CONT) {
			len_conts++;
			steps++;
			if (steps >= OCC_LOOP_MAX_STEPS) {
				set_err(err, errlen,
					"step limit %d reached during output"
					" continuation", OCC_LOOP_MAX_STEPS);
				occ_session_set_status(db, sess.id,
							OCC_ST_ACTIVE,
							dbuf_err,
							sizeof(dbuf_err));
				if (res)
					res->steps_capped = 1;
				rc = OCC_LOOP_OK;
				goto fill_res;
			}
			continue;
		}
		break;				/* 收口 */
	}

	rc = OCC_LOOP_OK;
	goto fill_res;
llm_interrupted:
	/*
	 * b2：中断优先于错误——LLM 轮被 SIGINT 终止（含传输层重试退避
	 * 中被打断）：丢弃本次尝试的部分输出（不落库，避免半截 assistant
	 * 污染上下文），status=interrupted（尾态保持可重放/retry）。
	 */
	ev_ctx_reset_keep_opts(&ctx);
	ctx.opts = (occ_loop_opts *)opts;
	free(llm_err);
	llm_err = NULL;
	set_err(err, errlen, "interrupted by user (LLM round aborted)");
	occ_session_set_status(db, sess.id, OCC_ST_INTERRUPTED, dbuf_err,
			       sizeof(dbuf_err));
	interrupted = 1;
	rc = OCC_LOOP_OK;
	goto fill_res;
llm_fail:
	set_err(err, errlen, "llm: %s",
		llm_err ? llm_err :
		ctx.last_error[0] ? ctx.last_error : "stream error");
	free(llm_err);
	llm_err = NULL;
	occ_session_set_status(db, sess.id, OCC_ST_ERROR, dbuf_err,
			       sizeof(dbuf_err));
	if (opts->stream_out && !ctx.llm_error)
		fputc('\n', opts->stream_out);
	rc = OCC_LOOP_ELLM;
	goto out;
fill_res:
	if (res) {
		snprintf(res->session_id, sizeof(res->session_id), "%s",
			 sess.id);
		res->text = ctx.text.buf ? strdup(ctx.text.buf) : NULL;
		res->reasoning = ctx.reasoning.buf ?
				 strdup(ctx.reasoning.buf) : NULL;
		snprintf(res->finish, sizeof(res->finish), "%s", ctx.finish);
		res->unexpected_toolcalls = total_calls;
		res->llm_error = 0;
		res->rounds = steps;
		res->interrupted = interrupted;
		if (interrupted) {
			/* 中断轮不冒充收口产物（正文已流式输出/已丢弃） */
			free(res->text);
			free(res->reasoning);
			res->text = NULL;
			res->reasoning = NULL;
			res->assistant_msg_id[0] = '\0';
			res->finish[0] = '\0';
		}
	}
	if (replayed && rc == OCC_LOOP_OK && !interrupted)
		fprintf(stderr, "occ: recovered turn completed\n");
out:
	free(req_msgs);
	free(req_calls);
	if (rows)
		occ_msg_rows_free(rows, nmsgs);
	ev_ctx_free(&ctx);
	free(llm_err);
	return rc;
}
