// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_lease.c - /lease 命令（W74 授权租约管理）
 *
 * 子命令：
 *   list                         只读：列出 id/principal/ceiling/scope/expiry
 *   show <id>                    只读：显示单个租约
 *   issue --scope <csv> --ceiling D2 --mission <text> --ttl <sec>
 *                                仅 root + TTY；生成 L-YYYYMMDD-<4hex>，
 *                                要求人工输入 "ISSUE <id>" 才落盘
 *   revoke <id>                  仅 root + TTY；要求 "REVOKE <id>"
 *   pending                      列出等待确认的 nonce
 *   confirm <nonce> yes|no       仅 root + TTY，批准/拒绝非 TTY 请求
 *   confirm <nonce> CONFIRM D4 <nonce>
 *                                D4 必须精确短语（不接受脚本 yes）
 *
 * 设计：模型不能自签租约——本命令只由 Principal（root+TTY）使用；
 * 工具面没有 lease.issue/lease.revoke 可调用工具。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_lang.h"
#include "ai_trace.h"
#include "policy/ai_user_policy.h"
#include "policy/ai_lease.h"

static int lease_root_tty(void)
{
	return getuid() == 0 && isatty(STDIN_FILENO);
}

static void trim_nl(char *s)
{
	size_t n;

	if (!s)
		return;
	n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
			 isspace((unsigned char)s[n - 1])))
		s[--n] = '\0';
}

static int read_phrase(char *buf, size_t cap)
{
	if (!fgets(buf, (int)cap, stdin))
		return -1;
	trim_nl(buf);
	return 0;
}

static void scope_join(const struct ai_lease *l, char *buf, size_t cap)
{
	size_t off = 0;
	int i;

	buf[0] = '\0';
	for (i = 0; i < l->scope_count; i++)
		off += (size_t)snprintf(buf + off, off < cap ? cap - off : 0,
					"%s%s", i ? "," : "", l->scope[i]);
}

static void lease_audit_trace(const char *op, const char *id,
			      const char *result, const char *nonce,
			      const char *decision)
{
	uid_t uid = getuid();
	enum ai_policy_mode mode = ai_policy_mode_for_uid(uid);

	ai_policy_audit_ex(uid, mode, op, id, result, id, "D4",
			   "interactive");
	ai_trace_policy_decision_ex("W2", decision, op, op, "interactive",
				    id, id, "D4", "interactive", nonce,
				    "cmd_lease");
}

static int lease_list(void)
{
	struct ai_lease items[64];
	int n = 0, i;
	char err[AI_LEASE_ERR_MAX] = "";

	if (ai_lease_store_list(items, 64, &n, err, sizeof(err)) != 0) {
		printf(tr(TR_LEASE_STORE_ERR), err);
		return AI_ERR_STORAGE;
	}
	if (n == 0) {
		printf("%s", tr(TR_LEASE_LIST_EMPTY));
		return AI_OK;
	}
	printf("%s", tr(TR_LEASE_LIST_HDR));
	for (i = 0; i < n; i++) {
		char scopes[512];

		scope_join(&items[i], scopes, sizeof(scopes));
		printf(tr(TR_LEASE_LIST_ROW), items[i].lease_id,
		       items[i].principal,
		       ai_danger_name(items[i].risk_ceiling),
		       (long long)items[i].expires_at,
		       items[i].revoked ? "yes" : "no", scopes);
	}
	return AI_OK;
}

static int lease_show(const char *id)
{
	char dir[512];
	char err[AI_LEASE_ERR_MAX] = "";
	struct ai_lease l;
	uid_t owner = 0;
	char scopes[512];

	if (!ai_lease_id_valid(id)) {
		printf("%s", tr(TR_LEASE_DENY_LOAD));
		return AI_ERR_INVALID_ARG;
	}
	ai_lease_store_dir(dir, sizeof(dir));
	if (ai_lease_load(dir, id, getuid(), (long long)time(NULL),
			  &l, &owner, err, sizeof(err)) != 0) {
		printf(tr(TR_LEASE_STORE_ERR), err);
		return AI_ERR_NOT_FOUND;
	}
	scope_join(&l, scopes, sizeof(scopes));
	printf(tr(TR_LEASE_SHOW_FMT), l.lease_id, l.principal, l.subject,
	       ai_danger_name(l.risk_ceiling), l.mission,
	       (long long)l.issued_at, (long long)l.expires_at,
	       l.revoked ? "yes" : "no", scopes);
	return AI_OK;
}

static int lease_issue_cmd(int argc, char **argv)
{
	const char *scope = NULL, *ceiling = NULL, *mission = NULL;
	long ttl = 0;
	char id[AI_LEASE_ID_MAX];
	char phrase[256];
	char path[PATH_MAX];
	char err[AI_LEASE_ERR_MAX] = "";
	int i;

	if (!lease_root_tty()) {
		printf("%s", tr(TR_LEASE_ROOT_TTY));
		return AI_ERR_API;
	}
	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--scope") == 0 && i + 1 < argc)
			scope = argv[++i];
		else if (strcmp(argv[i], "--ceiling") == 0 && i + 1 < argc)
			ceiling = argv[++i];
		else if (strcmp(argv[i], "--mission") == 0 && i + 1 < argc)
			mission = argv[++i];
		else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc)
			ttl = strtol(argv[++i], NULL, 10);
		else {
			printf("%s", tr(TR_LEASE_CMD_USAGE));
			return AI_ERR_INVALID_ARG;
		}
	}
	if (!scope || !ceiling || !mission || ttl <= 0) {
		printf("%s", tr(TR_LEASE_CMD_USAGE));
		return AI_ERR_INVALID_ARG;
	}
	if (ai_lease_new_id(id, sizeof(id)) != 0) {
		printf(tr(TR_LEASE_ERR_LOAD), "无法生成 lease_id");
		return AI_ERR_GENERIC;
	}
	printf(tr(TR_LEASE_ISSUE_PROMPT), id, scope, ceiling, ttl, id);
	fflush(stdout);
	if (read_phrase(phrase, sizeof(phrase)) != 0 || phrase[0] == '\0') {
		printf("%s", tr(TR_LEASE_ISSUE_BAD));
		return AI_ERR_API;
	}
	{
		char req[160];

		snprintf(req, sizeof(req), "ISSUE %s", id);
		if (strcmp(phrase, req) != 0) {
			printf("%s", tr(TR_LEASE_ISSUE_BAD));
			lease_audit_trace("lease.issue", id, "PHRASE_MISMATCH",
					  NULL, "DENY");
			return AI_ERR_API;
		}
	}
	if (ai_lease_issue(scope, ceiling, mission, ttl, getuid(),
			   id, sizeof(id), path, sizeof(path),
			   err, sizeof(err)) != 0) {
		printf(tr(TR_LEASE_STORE_ERR), err);
		lease_audit_trace("lease.issue", id, "FAIL", NULL, "DENY");
		return AI_ERR_STORAGE;
	}
	printf(tr(TR_LEASE_ISSUED), id, path);
	lease_audit_trace("lease.issue", id, "ISSUE", NULL, "ALLOW");
	return AI_OK;
}

static int lease_revoke_cmd(int argc, char **argv)
{
	char phrase[256];
	char req[160];
	char err[AI_LEASE_ERR_MAX] = "";
	const char *id;

	if (!lease_root_tty()) {
		printf("%s", tr(TR_LEASE_ROOT_TTY));
		return AI_ERR_API;
	}
	if (argc < 3)
		goto usage;
	id = argv[2];
	if (!ai_lease_id_valid(id)) {
		printf("%s", tr(TR_LEASE_DENY_LOAD));
		return AI_ERR_INVALID_ARG;
	}
	printf(tr(TR_LEASE_REVOKE_PROMPT), id, id);
	fflush(stdout);
	if (read_phrase(phrase, sizeof(phrase)) != 0)
		goto bad;
	snprintf(req, sizeof(req), "REVOKE %s", id);
	if (strcmp(phrase, req) != 0)
		goto bad;
	if (ai_lease_revoke(id, getuid(), err, sizeof(err)) != 0) {
		printf(tr(TR_LEASE_STORE_ERR), err);
		lease_audit_trace("lease.revoke", id, "FAIL", NULL, "DENY");
		return AI_ERR_STORAGE;
	}
	printf(tr(TR_LEASE_REVOKED), id);
	lease_audit_trace("lease.revoke", id, "REVOKE", NULL, "ALLOW");
	return AI_OK;
bad:
	printf("%s", tr(TR_LEASE_REVOKE_BAD));
	lease_audit_trace("lease.revoke", id, "PHRASE_MISMATCH", NULL,
			  "DENY");
	return AI_ERR_API;
usage:
	printf("%s", tr(TR_LEASE_CMD_USAGE));
	return AI_ERR_INVALID_ARG;
}

static int lease_confirm_cmd(int argc, char **argv)
{
	const char *nonce;
	char phrase[256];
	enum ai_danger danger;
	char err[AI_LEASE_ERR_MAX] = "";
	int yes;

	if (!lease_root_tty()) {
		printf("%s", tr(TR_LEASE_ROOT_TTY));
		return AI_ERR_API;
	}
	if (argc < 4)
		goto usage;
	nonce = argv[2];
	if (ai_lease_confirm_pending_danger(nonce, &danger,
					    err, sizeof(err)) != 0) {
		printf(tr(TR_LEASE_STORE_ERR), err);
		return AI_ERR_NOT_FOUND;
	}
	/* 把 argv[3..] 拼成短语（D4 短语本身含空格） */
	phrase[0] = '\0';
	for (int i = 3; i < argc; i++) {
		size_t off = strlen(phrase);

		snprintf(phrase + off, sizeof(phrase) - off, "%s%s",
			 off ? " " : "", argv[i]);
	}
	if (danger == AI_D4) {
		char req[160];

		snprintf(req, sizeof(req), "CONFIRM D4 %s", nonce);
		if (strcmp(phrase, req) != 0) {
			printf("%s", tr(TR_LEASE_D4_MISMATCH));
			lease_audit_trace("lease.confirm", nonce,
					  "PHRASE_MISMATCH", nonce, "DENY");
			return AI_ERR_API;
		}
		yes = 1;
	} else {
		if (strcmp(phrase, "yes") == 0)
			yes = 1;
		else if (strcmp(phrase, "no") == 0)
			yes = 0;
		else {
			printf("%s", tr(TR_LEASE_CMD_USAGE));
			return AI_ERR_INVALID_ARG;
		}
	}
	if (ai_lease_confirm_approve(nonce, yes, phrase,
				     err, sizeof(err)) != 0) {
		printf(tr(TR_LEASE_STORE_ERR), err);
		lease_audit_trace("lease.confirm", nonce, "FAIL", nonce,
				  "DENY");
		return AI_ERR_STORAGE;
	}
	if (yes)
		printf(tr(TR_LEASE_CONFIRM_OK), nonce, "yes");
	else
		printf(tr(TR_LEASE_CONFIRM_NO), nonce);
	lease_audit_trace("lease.confirm", nonce,
			  yes ? "CONFIRM=yes" : "CONFIRM=no", nonce,
			  yes ? "ALLOW" : "DENY");
	return AI_OK;
usage:
	printf("%s", tr(TR_LEASE_CMD_USAGE));
	return AI_ERR_INVALID_ARG;
}

static int lease_pending_cmd(void)
{
	char buf[16384];
	char err[AI_LEASE_ERR_MAX] = "";

	if (ai_lease_confirm_pending_list(buf, sizeof(buf),
					  err, sizeof(err)) != 0) {
		printf(tr(TR_LEASE_STORE_ERR), err);
		return AI_ERR_STORAGE;
	}
	if (!buf[0])
		printf("%s", tr(TR_LEASE_PENDING_EMPTY));
	else
		printf("%s", buf);
	return AI_OK;
}

int cmd_lease(void *shell, int argc, char **argv)
{
	(void)shell;

	if (argc < 2) {
		printf("%s", tr(TR_LEASE_CMD_USAGE));
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(argv[1], "list") == 0)
		return lease_list();
	if (strcmp(argv[1], "show") == 0) {
		if (argc < 3) {
			printf("%s", tr(TR_LEASE_CMD_USAGE));
			return AI_ERR_INVALID_ARG;
		}
		return lease_show(argv[2]);
	}
	if (strcmp(argv[1], "issue") == 0)
		return lease_issue_cmd(argc, argv);
	if (strcmp(argv[1], "revoke") == 0)
		return lease_revoke_cmd(argc, argv);
	if (strcmp(argv[1], "pending") == 0)
		return lease_pending_cmd();
	if (strcmp(argv[1], "confirm") == 0)
		return lease_confirm_cmd(argc, argv);
	printf(tr(TR_LEASE_UNKNOWN_SUB), argv[1]);
	printf("%s", tr(TR_LEASE_CMD_USAGE));
	return AI_ERR_INVALID_ARG;
}
