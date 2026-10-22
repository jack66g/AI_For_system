// SPDX-License-Identifier: GPL-2.0
/*
 * tool_registry.c - AI 工具注册表实现（加载 tools.json + 请求体生成）
 *
 * tools.json 由 tools/gen_registry.py 生成，结构：
 * {
 *   "version": 1,
 *   "tools": [
 *     {"name":"procfs.read.status","channel":"procfs-read",
 *      "description":"...","path":"/proc/ai/status",
 *      "parameters":{"type":"object","properties":{...},"required":[]}},
 *     {"name":"netlink.act.sched.nice","channel":"netlink-act",
 *      "param":"sched.nice","domain":1,"task_param":true,
 *      "value_min":-20,"value_max":19, "parameters":{...}},
 *     ...
 *   ]
 * }
 * 解析基于 ai_json_util 的区间扫描；parameters schema 原文截取保存
 * （构造请求体时原样透传，保证与 gen_registry.py 产出一致）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "ai_toolname_map.h"

enum tool_channel tool_channel_from_str(const char *s)
{
	if (!s)
		return TOOL_CH_UNKNOWN;
	if (strcmp(s, "procfs-read") == 0)
		return TOOL_CH_PROCFS_READ;
	if (strcmp(s, "sysfs-write") == 0)
		return TOOL_CH_SYSFS_WRITE;
	if (strcmp(s, "netlink-act") == 0)
		return TOOL_CH_NETLINK_ACT;
	if (strcmp(s, "netlink-sense") == 0)
		return TOOL_CH_NETLINK_SENSE;
	if (strcmp(s, "exec") == 0)
		return TOOL_CH_EXEC;
	if (strcmp(s, "memory") == 0)
		return TOOL_CH_MEMORY;
	if (strcmp(s, "shell") == 0)
		return TOOL_CH_SHELL;
	if (strcmp(s, "sandbox") == 0)
		return TOOL_CH_SANDBOX;
	if (strcmp(s, "sysctl") == 0)
		return TOOL_CH_SYSCTL;
	if (strcmp(s, "sysfs") == 0)
		return TOOL_CH_SYSFS_DYN;
	if (strcmp(s, "desktop") == 0)
		return TOOL_CH_DESKTOP;
	if (strcmp(s, "interaction") == 0)
		return TOOL_CH_CLARIFY;
	if (strcmp(s, "model") == 0)
		return TOOL_CH_MODEL;
	return TOOL_CH_UNKNOWN;
}

static const char *channel_str(enum tool_channel ch)
{
	static const char *const names[] = {
		"procfs-read", "sysfs-write", "netlink-act", "netlink-sense",
		"exec", "memory", "shell", "sandbox", "sysctl", "sysfs",
		"desktop", "interaction", "model", "unknown",
	};

	if (ch < 0 || ch > TOOL_CH_UNKNOWN)
		return names[TOOL_CH_UNKNOWN];
	return names[ch];
}

/* ---- 参数解析 ---- */

static void tool_param_free(struct tool_param *p)
{
	int i;

	if (!p)
		return;
	free(p->name);
	free(p->type);
	free(p->desc);
	free(p->default_val);
	for (i = 0; i < p->enum_count; i++)
		free(p->enum_vals[i]);
	free(p->enum_vals);
	memset(p, 0, sizeof(*p));
}

/* 解析单个参数对象 {"name":..,"type":..,"description":..,...} */
static int parse_tool_param(const char *tok, size_t tlen,
			    struct tool_param *p)
{
	const char *v;
	size_t vl;
	int vt;

	memset(p, 0, sizeof(*p));

	if (ai_json_obj_get(tok, tlen, "name", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		p->name = ai_json_strdup_str(v, vl);
	if (ai_json_obj_get(tok, tlen, "type", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		p->type = ai_json_strdup_str(v, vl);
	if (ai_json_obj_get(tok, tlen, "description", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		p->desc = ai_json_strdup_str(v, vl);
	if (ai_json_obj_get(tok, tlen, "default", &v, &vl, &vt) == 1) {
		if (vt == AI_JSON_STR)
			p->default_val = ai_json_strdup_str(v, vl);
		else
			p->default_val = strndup(v, vl);
	}
	if (ai_json_obj_get(tok, tlen, "minimum", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_NUM) {
		p->min = ai_json_ll(v, vl);
		p->has_min = 1;
	}
	if (ai_json_obj_get(tok, tlen, "maximum", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_NUM) {
		p->max = ai_json_ll(v, vl);
		p->has_max = 1;
	}

	/* enum: [str, str, ...] */
	if (ai_json_obj_get(tok, tlen, "enum", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_ARR) {
		int i;

		for (i = 0; ; i++) {
			const char *et;
			size_t el;
			int ety;
			char *sv;
			char **ne;

			if (ai_json_arr_get(v, vl, i, &et, &el, &ety) != 1)
				break;
			if (ety != AI_JSON_STR)
				continue;
			sv = ai_json_strdup_str(et, el);
			if (!sv)
				break;
			ne = realloc(p->enum_vals,
				     sizeof(char *) *
				     (size_t)(p->enum_count + 1));
			if (!ne) {
				free(sv);
				break;
			}
			p->enum_vals = ne;
			p->enum_vals[p->enum_count++] = sv;
		}
	}

	if (!p->name) {
		tool_param_free(p);
		return AI_ERR_PARSE;
	}
	return AI_OK;
}

/* 解析 parameters schema：保存原文 + 展开 properties/required */
static int parse_parameters(struct ai_tool *tool, const char *tok,
			    size_t tlen)
{
	const char *v;
	size_t vl;
	int vt;
	int i;

	/* schema 原文（构造请求体原样透传） */
	tool->parameters_json = strndup(tok, tlen);
	if (!tool->parameters_json)
		return AI_ERR_MEMORY;

	/* properties: {name: {...}, ...}（成员名即参数名，对象内也带 name） */
	if (ai_json_obj_get(tok, tlen, "properties", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_OBJ) {
		for (i = 0; ; i++) {
			const char *pt;
			size_t pl;
			int pty;
			struct tool_param p;
			struct tool_param *np;
			int rc;

			if (ai_json_obj_member(v, vl, i, NULL, NULL,
					       &pt, &pl, &pty) != 1)
				break;
			if (pty != AI_JSON_OBJ)
				continue;
			rc = parse_tool_param(pt, pl, &p);
			if (rc != AI_OK)
				continue;
			np = realloc(tool->params,
				     sizeof(*np) *
				     (size_t)(tool->param_count + 1));
			if (!np) {
				tool_param_free(&p);
				return AI_ERR_MEMORY;
			}
			tool->params = np;
			tool->params[tool->param_count++] = p;
		}
	}

	/* required: [name, ...] → 回填 required 标志 */
	if (ai_json_obj_get(tok, tlen, "required", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_ARR) {
		for (i = 0; ; i++) {
			const char *rt;
			size_t rl;
			int rty;
			char *name;
			int j;

			if (ai_json_arr_get(v, vl, i, &rt, &rl, &rty) != 1)
				break;
			if (rty != AI_JSON_STR)
				continue;
			name = ai_json_strdup_str(rt, rl);
			if (!name)
				break;
			for (j = 0; j < tool->param_count; j++) {
				if (strcmp(tool->params[j].name, name) == 0)
					tool->params[j].required = 1;
			}
			free(name);
		}
	}

	return AI_OK;
}

/* ---- 工具解析 ---- */

static void tool_free(struct ai_tool *t)
{
	int i, j;

	if (!t)
		return;
	free(t->name);
	free(t->desc);
	free(t->path);
	free(t->param);
	free(t->risk);
	for (i = 0; i < t->sub_count; i++)
		free(t->sub[i]);
	free(t->sub);
	free(t->probe);
	free(t->parameters_json);
	for (i = 0; i < t->exec_cmd_count; i++) {
		struct tool_exec_cmd *c = &t->exec_cmds[i];

		free(c->command);
		free(c->bin);
		free(c->risk);
		for (j = 0; j < c->args_template_n; j++)
			free(c->args_template[j]);
		free(c->args_template);
		for (j = 0; j < c->args0_count; j++) {
			free(c->args0_enum[j]);
			if (c->args0_risk)
				free(c->args0_risk[j]);
		}
		free(c->args0_enum);
		free(c->args0_risk);
		for (j = 0; j < c->path_root_count; j++)
			free(c->path_roots[j]);
		free(c->path_roots);
	}
	free(t->exec_cmds);
	for (i = 0; i < t->param_count; i++)
		tool_param_free(&t->params[i]);
	free(t->params);
	memset(t, 0, sizeof(*t));
}

/* 解析字符串数组 token 为 malloc 向量（元素 malloc） */
static int parse_str_array(const char *arr_tok, size_t arr_len,
			   char ***outv, int *outn)
{
	int i;

	*outv = NULL;
	*outn = 0;
	for (i = 0; ; i++) {
		const char *et;
		size_t el;
		int ety;
		char *s;
		char **nv;

		if (ai_json_arr_get(arr_tok, arr_len, i, &et, &el, &ety) != 1)
			break;
		if (ety != AI_JSON_STR)
			continue;
		s = ai_json_strdup_str(et, el);
		if (!s)
			break;
		nv = realloc(*outv, sizeof(char *) * (size_t)(*outn + 1));
		if (!nv) {
			free(s);
			break;
		}
		*outv = nv;
		(*outv)[(*outn)++] = s;
	}
	return AI_OK;
}

/* 解析 args0 数组：[{"verb":"status","risk":"R"}, ...]（systemctl 类） */
static int parse_args0(const char *arr_tok, size_t arr_len,
		       struct tool_exec_cmd *c)
{
	int i;

	c->args0_enum = NULL;
	c->args0_risk = NULL;
	c->args0_count = 0;
	for (i = 0; ; i++) {
		const char *ot;
		size_t ol;
		int oty;
		const char *v;
		size_t vl;
		int vt;
		char *verb = NULL, *risk = NULL;
		char **ne, **nr;

		if (ai_json_arr_get(arr_tok, arr_len, i, &ot, &ol, &oty) != 1)
			break;
		if (oty != AI_JSON_OBJ)
			continue;
		if (ai_json_obj_get(ot, ol, "verb", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_STR)
			verb = ai_json_strdup_str(v, vl);
		if (ai_json_obj_get(ot, ol, "risk", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_STR)
			risk = ai_json_strdup_str(v, vl);
		if (!verb) {
			free(verb);
			free(risk);
			continue;
		}
		ne = realloc(c->args0_enum,
			     sizeof(char *) * (size_t)(c->args0_count + 1));
		nr = realloc(c->args0_risk,
			     sizeof(char *) * (size_t)(c->args0_count + 1));
		if (!ne || !nr) {
			free(verb);
			free(risk);
			free(ne);
			free(nr);
			break;
		}
		c->args0_enum = ne;
		c->args0_risk = nr;
		c->args0_enum[c->args0_count] = verb;
		c->args0_risk[c->args0_count] = risk;   /* 可 NULL */
		c->args0_count++;
	}
	return AI_OK;
}

/*
 * parse_exec_block - 解析 exec 工具内嵌的 "exec" 单源白名单（v2）
 * {"default_timeout":30,"commands":[{"command","bin","args_template",
 *   "timeout","risk","path_check","args0":[...]}, ...]}
 */
static int parse_exec_block(struct ai_tool *t, const char *tok, size_t tlen)
{
	const char *cmds_tok;
	size_t cmds_len;
	int cmds_ty;
	int i;

	if (ai_json_obj_get(tok, tlen, "default_timeout", &cmds_tok,
			    &cmds_len, &cmds_ty) == 1 && cmds_ty == AI_JSON_NUM)
		t->exec_default_timeout = (int)ai_json_ll(cmds_tok, cmds_len);

	if (ai_json_obj_get(tok, tlen, "input_max_bytes", &cmds_tok,
			    &cmds_len, &cmds_ty) == 1 && cmds_ty == AI_JSON_NUM)
		t->exec_input_max = (int)ai_json_ll(cmds_tok, cmds_len);

	if (ai_json_obj_get(tok, tlen, "commands", &cmds_tok, &cmds_len,
			    &cmds_ty) != 1 || cmds_ty != AI_JSON_ARR)
		return AI_OK;

	for (i = 0; ; i++) {
		const char *ct;
		size_t cl;
		int cty;
		const char *v;
		size_t vl;
		int vt;
		struct tool_exec_cmd c;
		struct tool_exec_cmd *nc;
		int j;

		if (ai_json_arr_get(cmds_tok, cmds_len, i, &ct, &cl,
				    &cty) != 1)
			break;
		if (cty != AI_JSON_OBJ)
			continue;
		memset(&c, 0, sizeof(c));
		if (ai_json_obj_get(ct, cl, "command", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_STR)
			c.command = ai_json_strdup_str(v, vl);
		if (ai_json_obj_get(ct, cl, "bin", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_STR)
			c.bin = ai_json_strdup_str(v, vl);
		if (ai_json_obj_get(ct, cl, "risk", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_STR)
			c.risk = ai_json_strdup_str(v, vl);
		if (ai_json_obj_get(ct, cl, "timeout", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_NUM)
			c.timeout = (int)ai_json_ll(v, vl);
		if (ai_json_obj_get(ct, cl, "path_check", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_BOOL)
			c.path_check = (strncmp(v, "true", 4) == 0) ? 1 : 0;
		if (ai_json_obj_get(ct, cl, "args_template", &v, &vl,
				    &vt) == 1 && vt == AI_JSON_ARR)
			parse_str_array(v, vl, &c.args_template,
					&c.args_template_n);
		if (ai_json_obj_get(ct, cl, "args0", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_ARR)
			parse_args0(v, vl, &c);
		/* W65：更严格的写目标根（可选；如 gcc/cc 仅 /tmp） */
		if (ai_json_obj_get(ct, cl, "path_roots", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_ARR)
			parse_str_array(v, vl, &c.path_roots,
					&c.path_root_count);

		if (!c.command) {
			free(c.bin);
			free(c.risk);
			for (j = 0; j < c.args_template_n; j++)
				free(c.args_template[j]);
			free(c.args_template);
			for (j = 0; j < c.path_root_count; j++)
				free(c.path_roots[j]);
			free(c.path_roots);
			continue;       /* 跳过坏条目，不整体失败 */
		}
		nc = realloc(t->exec_cmds,
			     sizeof(*nc) * (size_t)(t->exec_cmd_count + 1));
		if (!nc) {
			free(c.command);
			free(c.bin);
			free(c.risk);
			for (j = 0; j < c.args_template_n; j++)
				free(c.args_template[j]);
			free(c.args_template);
			for (j = 0; j < c.path_root_count; j++)
				free(c.path_roots[j]);
			free(c.path_roots);
			return AI_ERR_MEMORY;
		}
		t->exec_cmds = nc;
		t->exec_cmds[t->exec_cmd_count++] = c;
	}
	return AI_OK;
}

static int parse_tool(const char *tok, size_t tlen, struct ai_tool *t)
{
	const char *v;
	size_t vl;
	int vt;
	char *ch;
	int rc;

	memset(t, 0, sizeof(*t));

	if (ai_json_obj_get(tok, tlen, "name", &v, &vl, &vt) != 1 ||
	    vt != AI_JSON_STR) {
		return AI_ERR_PARSE;
	}
	t->name = ai_json_strdup_str(v, vl);

	if (ai_json_obj_get(tok, tlen, "description", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		t->desc = ai_json_strdup_str(v, vl);
	if (!t->desc)
		t->desc = strdup("");

	if (ai_json_obj_get(tok, tlen, "channel", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR) {
		ch = ai_json_strdup_str(v, vl);
		t->channel = tool_channel_from_str(ch);
		free(ch);
	} else {
		t->channel = TOOL_CH_UNKNOWN;
	}

	if (ai_json_obj_get(tok, tlen, "path", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		t->path = ai_json_strdup_str(v, vl);
	if (ai_json_obj_get(tok, tlen, "param", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		t->param = ai_json_strdup_str(v, vl);
	if (ai_json_obj_get(tok, tlen, "domain", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_NUM)
		t->domain = (int)ai_json_ll(v, vl);
	if (ai_json_obj_get(tok, tlen, "task_param", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_BOOL)
		t->task_param = (strncmp(v, "true", 4) == 0) ? 1 : 0;
	if (ai_json_obj_get(tok, tlen, "value_min", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_NUM) {
		t->value_min = ai_json_ll(v, vl);
		t->has_value_min = 1;
	}
	if (ai_json_obj_get(tok, tlen, "value_max", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_NUM) {
		t->value_max = ai_json_ll(v, vl);
		t->has_value_max = 1;
	}
	if (ai_json_obj_get(tok, tlen, "risk", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		t->risk = ai_json_strdup_str(v, vl);

	/* W74：能力域数组 "sub": ["fs","sysadmin"]（只读元数据） */
	if (ai_json_obj_get(tok, tlen, "sub", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_ARR)
		parse_str_array(v, vl, &t->sub, &t->sub_count);

	/* W65 P2-05：能力探测路径（可选）。不存在则标记不可用。 */
	t->available = 1;
	if (ai_json_obj_get(tok, tlen, "probe", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR) {
		t->probe = ai_json_strdup_str(v, vl);
		if (t->probe && access(t->probe, F_OK) != 0)
			t->available = 0;
	}

	if (ai_json_obj_get(tok, tlen, "exec", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_OBJ) {
		rc = parse_exec_block(t, v, vl);
		if (rc != AI_OK) {
			tool_free(t);
			return rc;
		}
	}

	if (ai_json_obj_get(tok, tlen, "parameters", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_OBJ) {
		rc = parse_parameters(t, v, vl);
		if (rc != AI_OK) {
			tool_free(t);
			return rc;
		}
	}

	if (!t->name) {
		tool_free(t);
		return AI_ERR_PARSE;
	}
	return AI_OK;
}

/* ---- W69：注册表头部完整性校验（纯 C SHA-256，无外部依赖） ---- */
struct w69_sha256 {
	uint32_t h[8];
	uint64_t len;
	unsigned char buf[64];
	size_t buflen;
};

static uint32_t w69_rotr(uint32_t x, unsigned int n)
{
	return (x >> n) | (x << (32 - n));
}

static void w69_sha256_block(struct w69_sha256 *c, const unsigned char *p)
{
	static const uint32_t k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};
	uint32_t w[64];
	uint32_t a, b, cc, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++) {
		w[i] = ((uint32_t)p[i * 4] << 24) |
		       ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) |
		       (uint32_t)p[i * 4 + 3];
	}
	for (i = 16; i < 64; i++) {
		uint32_t s0 = w69_rotr(w[i - 15], 7) ^
			      w69_rotr(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = w69_rotr(w[i - 2], 17) ^
			      w69_rotr(w[i - 2], 19) ^
			      (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
	e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
	for (i = 0; i < 64; i++) {
		uint32_t s1 = w69_rotr(e, 6) ^ w69_rotr(e, 11) ^
			      w69_rotr(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t t1 = h + s1 + ch + k[i] + w[i];
		uint32_t s0 = w69_rotr(a, 2) ^ w69_rotr(a, 13) ^
			      w69_rotr(a, 22);
		uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
		uint32_t t2 = s0 + maj;

		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
	c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void w69_sha256_init(struct w69_sha256 *c)
{
	c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85;
	c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
	c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
	c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
	c->len = 0;
	c->buflen = 0;
}

static void w69_sha256_update(struct w69_sha256 *c, const void *data, size_t n)
{
	const unsigned char *p = data;

	c->len += n;
	while (n > 0) {
		size_t take = 64 - c->buflen;

		if (take > n)
			take = n;
		memcpy(c->buf + c->buflen, p, take);
		c->buflen += take;
		p += take;
		n -= take;
		if (c->buflen == 64) {
			w69_sha256_block(c, c->buf);
			c->buflen = 0;
		}
	}
}

static void w69_sha256_final(struct w69_sha256 *c, unsigned char out[32])
{
	uint64_t bits = c->len * 8;
	int i;

	c->buf[c->buflen++] = 0x80;
	if (c->buflen > 56) {
		while (c->buflen < 64)
			c->buf[c->buflen++] = 0;
		w69_sha256_block(c, c->buf);
		c->buflen = 0;
	}
	while (c->buflen < 56)
		c->buf[c->buflen++] = 0;
	for (i = 7; i >= 0; i--)
		c->buf[c->buflen++] = (unsigned char)(bits >> (i * 8));
	w69_sha256_block(c, c->buf);
	for (i = 0; i < 8; i++) {
		out[i * 4] = (unsigned char)(c->h[i] >> 24);
		out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
		out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
		out[i * 4 + 3] = (unsigned char)c->h[i];
	}
}

static void w69_sha256_hex(const void *data, size_t n, char out[65])
{
	struct w69_sha256 c;
	unsigned char d[32];
	int i;

	w69_sha256_init(&c);
	w69_sha256_update(&c, data, n);
	w69_sha256_final(&c, d);
	for (i = 0; i < 32; i++)
		sprintf(out + i * 2, "%02x", d[i]);
	out[64] = 0;
}

/* 按 channel 校验必填字段（W68 P2-8） */
static int tool_fields_validate(const struct ai_tool *t, char **err)
{
	switch (t->channel) {
	case TOOL_CH_PROCFS_READ:
	case TOOL_CH_SYSFS_WRITE:
		if (!t->path || t->path[0] != '/') {
			if (asprintf(err, "工具 %s（%s）缺少绝对 path 字段",
				     t->name, channel_str(t->channel)) < 0)
				*err = NULL;
			return AI_ERR_PARSE;
		}
		break;
	case TOOL_CH_NETLINK_ACT:
		if (!t->param || !t->param[0]) {
			if (asprintf(err, "工具 %s（netlink-act）缺少 param "
				     "字段", t->name) < 0)
				*err = NULL;
			return AI_ERR_PARSE;
		}
		break;
	case TOOL_CH_EXEC:
		if (!t->exec_cmds || t->exec_cmd_count <= 0) {
			if (asprintf(err, "工具 %s（exec）缺少非空 "
				     "exec.commands 白名单", t->name) < 0)
				*err = NULL;
			return AI_ERR_PARSE;
		}
		break;
	case TOOL_CH_CLARIFY:
		/* W77c：question/options 的语义校验在 ask_clarify.c 执行
		 * （2-4 选项、id 唯一、recommended/default 规则），注册表
		 * 只承载 schema，不需要通道专属字段。 */
		break;
	case TOOL_CH_UNKNOWN:
		if (asprintf(err, "工具 %s 的 channel 未知", t->name) < 0)
			*err = NULL;
		return AI_ERR_PARSE;
	default:
		break;
	}
	return AI_OK;
}

/* 头部校验：version / tool_count / tool_names_sha256（存在即校验） */
static int tool_manifest_validate(const char *tok, size_t tlen,
				  const struct tool_registry *reg, char **err)
{
	const char *v;
	size_t vl;
	int vt;
	long long ver = -1;
	long long cnt = -1;
	char *sha = NULL;
	int rc = AI_OK;
	int i;

	if (ai_json_obj_get(tok, tlen, "version", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_NUM)
		ver = ai_json_ll(v, vl);
	if (ver >= 0 && ver != 1 && ver != 2) {
		if (asprintf(err, "tools.json version=%lld 不受支持（仅 1/2）",
			     ver) < 0)
			*err = NULL;
		rc = AI_ERR_PARSE;
		goto out;
	}
	if (ai_json_obj_get(tok, tlen, "tool_count", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_NUM) {
		cnt = ai_json_ll(v, vl);
		if (cnt != reg->tool_count) {
			if (asprintf(err, "tools.json 头部 tool_count=%lld 与"
				     "实际解析 %d 件不一致（表损坏或被截断）",
				     cnt, reg->tool_count) < 0)
				*err = NULL;
			rc = AI_ERR_PARSE;
			goto out;
		}
	}
	if (ai_json_obj_get(tok, tlen, "tool_names_sha256", &v, &vl,
			    &vt) == 1 && vt == AI_JSON_STR) {
		size_t total = 0;
		size_t off = 0;
		char *joined;
		char hex[65];

		sha = ai_json_strdup_str(v, vl);
		if (!sha || strlen(sha) != 64) {
			if (asprintf(err, "tools.json tool_names_sha256 格式"
				     "非法（应为 64 位十六进制）") < 0)
				*err = NULL;
			rc = AI_ERR_PARSE;
			goto out;
		}
		for (i = 0; i < reg->tool_count; i++)
			total += strlen(reg->tools[i].name) + 1;
		joined = malloc(total + 1);
		if (!joined) {
			if (asprintf(err, "内存不足（manifest 校验）") < 0)
				*err = NULL;
			rc = AI_ERR_MEMORY;
			goto out;
		}
		for (i = 0; i < reg->tool_count; i++) {
			size_t nl = strlen(reg->tools[i].name);

			memcpy(joined + off, reg->tools[i].name, nl);
			off += nl;
			joined[off++] = '\n';
		}
		joined[off] = 0;
		w69_sha256_hex(joined, off, hex);
		free(joined);
		if (strcmp(sha, hex) != 0) {
			if (asprintf(err, "tools.json tool_names_sha256 不匹配"
				     "（头部 %s / 实际 %s）：工具名清单被改动"
				     "或文件损坏", sha, hex) < 0)
				*err = NULL;
			rc = AI_ERR_PARSE;
			goto out;
		}
	}
out:
	free(sha);
	return rc;
}

static int registry_has_w2(const struct tool_registry *reg)
{
	int i, j;

	for (i = 0; i < reg->tool_count; i++) {
		const struct ai_tool *t = &reg->tools[i];

		if (t->risk && strcmp(t->risk, TOOL_RISK_W2) == 0)
			return 1;
		for (j = 0; j < t->exec_cmd_count; j++) {
			if (t->exec_cmds[j].risk &&
			    strcmp(t->exec_cmds[j].risk, TOOL_RISK_W2) == 0)
				return 1;
		}
	}
	return 0;
}

/* ---- 加载 ---- */

void tool_registry_free(struct tool_registry *reg)
{
	int i;

	if (!reg)
		return;
	for (i = 0; i < reg->tool_count; i++)
		tool_free(&reg->tools[i]);
	free(reg->tools);
	free(reg->source_path);
	memset(reg, 0, sizeof(*reg));
}

/* 读整个文件到 malloc 缓冲 */
static int read_file(const char *path, char **out)
{
	FILE *fp;
	long sz;
	char *buf;

	fp = fopen(path, "rb");
	if (!fp)
		return AI_ERR_NOT_FOUND;
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return AI_ERR_STORAGE;
	}
	sz = ftell(fp);
	if (sz <= 0 || sz > 16 * 1024 * 1024) {
		fclose(fp);
		return AI_ERR_STORAGE;
	}
	rewind(fp);
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(fp);
		return AI_ERR_MEMORY;
	}
	if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
		free(buf);
		fclose(fp);
		return AI_ERR_STORAGE;
	}
	buf[sz] = '\0';
	fclose(fp);
	*out = buf;
	return AI_OK;
}

/* exe 目录定位（/proc/self/exe 失败返回 -1） */
static int exe_dir(char *buf, size_t n)
{
	ssize_t r;
	char *slash;

	r = readlink("/proc/self/exe", buf, n - 1);
	if (r <= 0)
		return -1;
	buf[r] = '\0';
	slash = strrchr(buf, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	return 0;
}

int tool_registry_load(struct tool_registry *reg, char **err)
{
	static const char *const rel_paths[] = {
		"./tools.json",
		"tools/tools.json",
		/* W43：生产布局兜底（/usr/local/bin 下运行、任意 cwd） */
		"/usr/local/share/aikernel/tools.json",
		NULL,
	};
	char *text = NULL;
	char path[PATH_MAX];
	char *cand = NULL;
	int i;

	if (!reg || !err)
		return AI_ERR_INVALID_ARG;
	*err = NULL;
	memset(reg, 0, sizeof(*reg));

	/* 1) 环境变量显式指定：W69 P1-2 fail-closed——文件缺失/不可读
	 * 直接失败，绝不回退到 130 主表（沙箱子进程会因此获得 W2）。 */
	{
		const char *env = getenv("AIKERNEL_TOOLS_JSON");

		if (env && env[0]) {
			int erc = read_file(env, &text);

			if (erc != AI_OK) {
				if (asprintf(err, "AIKERNEL_TOOLS_JSON=%s "
					     "加载失败（%s）；显式指定注册表时"
					     "禁止回退主表（fail-closed）", env,
					     erc == AI_ERR_NOT_FOUND ?
					     "文件缺失或为空" : "读取失败") < 0)
					*err = NULL;
				return erc == AI_ERR_NOT_FOUND ?
				       AI_ERR_NOT_FOUND : AI_ERR_STORAGE;
			}
			cand = strdup(env);
			goto found;
		}
	}

	/* 2) 相对 cwd 的常规位置 */
	for (i = 0; rel_paths[i]; i++) {
		if (read_file(rel_paths[i], &text) == AI_OK) {
			cand = strdup(rel_paths[i]);
			goto found;
		}
	}

	/* 3) exe 同目录 / 同目录 tools/ 下（QEMU initramfs 场景） */
	if (exe_dir(path, sizeof(path)) == 0) {
		size_t dlen = strlen(path);

		snprintf(path + dlen, sizeof(path) - dlen, "/tools.json");
		if (read_file(path, &text) == AI_OK) {
			cand = strdup(path);
			goto found;
		}
		snprintf(path + dlen, sizeof(path) - dlen,
			 "/tools/tools.json");
		if (read_file(path, &text) == AI_OK) {
			cand = strdup(path);
			goto found;
		}
	}

	*err = strdup("未找到 tools.json（先运行 tools/gen_registry.py 生成，"
		      "或用 AIKERNEL_TOOLS_JSON 指定路径）");
	return AI_ERR_NOT_FOUND;

found:
	/* 解析根对象 */
	{
		const char *root_tok = NULL;
		size_t root_len = 0;
		int root_type = AI_JSON_NONE;
		const char *p = text;
		const char *v;
		size_t vl;
		int vt;

		if (ai_json_scan_value(&p, text + strlen(text), &root_tok,
				       &root_len, &root_type) != 0 ||
		    root_type != AI_JSON_OBJ) {
			*err = strdup("tools.json 不是合法 JSON 对象");
			free(text);
			return AI_ERR_PARSE;
		}

		if (ai_json_obj_get(root_tok, root_len, "tools", &v, &vl,
				    &vt) != 1 || vt != AI_JSON_ARR) {
			*err = strdup("tools.json 缺少 tools 数组");
			free(text);
			return AI_ERR_PARSE;
		}

		for (i = 0; ; i++) {
			const char *tt;
			size_t tl;
			int tty;
			struct ai_tool t;
			struct ai_tool *nt;

			if (ai_json_arr_get(v, vl, i, &tt, &tl, &tty) != 1)
				break;
			if (tty != AI_JSON_OBJ)
				continue;
			if (parse_tool(tt, tl, &t) != AI_OK) {
				if (asprintf(err, "tools.json 第 %d 个工具条目"
					     "解析失败（name/channel 等必填"
					     "字段缺失）", i + 1) < 0)
					*err = NULL;
				free(text);
				free(cand);
				tool_registry_free(reg);
				return AI_ERR_PARSE;
			}
			if (tool_fields_validate(&t, err) != AI_OK) {
				tool_free(&t);
				free(text);
				free(cand);
				tool_registry_free(reg);
				return AI_ERR_PARSE;
			}
			nt = realloc(reg->tools,
				     sizeof(*nt) *
				     (size_t)(reg->tool_count + 1));
			if (!nt) {
				tool_free(&t);
				tool_registry_free(reg);
				*err = strdup("内存不足");
				free(text);
				return AI_ERR_MEMORY;
			}
			reg->tools = nt;
			reg->tools[reg->tool_count++] = t;
		}

		/* W69 P2-8：头部 count/hash/version 校验（root_tok 作用域内） */
		if (tool_manifest_validate(root_tok, root_len, reg, err) !=
		    AI_OK) {
			free(text);
			free(cand);
			tool_registry_free(reg);
			return AI_ERR_PARSE;
		}
	}
	/* W69 P1-2：沙箱子进程加载到任何 W2（工具级或命令级）即拒绝启动，
	 * 即使 AIKERNEL_TOOLS_JSON 缺失/被回退也 fail-closed。 */
	{
		const char *zone = getenv("AIKERNEL_SANDBOX");

		if (zone && zone[0] && registry_has_w2(reg)) {
			if (asprintf(err, "沙箱子进程（AIKERNEL_SANDBOX=%s）"
				     "加载的注册表 %s 含 W2 工具/命令，拒绝"
				     "启动（应使用 tools-sandbox.json）",
				     zone, cand ? cand : "?") < 0)
				*err = NULL;
			free(text);
			free(cand);
			tool_registry_free(reg);
			return AI_ERR_PARSE;
		}
	}
	reg->source_path = cand;
	free(text);

	/* W41 bug2: 注册表装载完成后播种云端工具名映射表
	 * （点号→下划线出站，查表还原入站；无点号时全部恒等）。
	 * 冲突条目跳过并告警——映射对该工具退化为透传。 */
	{
		const char **names = malloc(sizeof(char *) *
					   (size_t)reg->tool_count);
		int i;
		int skipped_names = 0;

		if (names) {
			for (i = 0; i < reg->tool_count; i++)
				names[i] = reg->tools[i].name;
			skipped_names = ai_toolname_map_seed(
				(const char *const *)names, reg->tool_count);
			free(names);
		}
		if (skipped_names > 0)
			fprintf(stderr,
				"toolname_map: %d 个点号工具名因线缆名冲突"
				"跳过映射（该工具出站保留本名）\n",
				skipped_names);
	}

	if (reg->tool_count == 0) {
		*err = strdup("tools.json 中没有可用工具");
		tool_registry_free(reg);
		return AI_ERR_PARSE;
	}
	return AI_OK;
}

const struct ai_tool *tool_registry_find(const struct tool_registry *reg,
					 const char *name)
{
	int i;

	if (!reg || !name)
		return NULL;
	for (i = 0; i < reg->tool_count; i++) {
		if (strcmp(reg->tools[i].name, name) == 0)
			return &reg->tools[i];
	}
	return NULL;
}

/* W7S-T2：从已解析 params 重建最小 parameters schema——丢弃参数描述/
 * minimum/maximum/default，保留 name/type/required/enum（exec 白名单）。
 * tools.json 缩进原文直接透传时 74 工具 ≈ 13KB（约 5k token），是 ask
 * prompt 的最大头（ollama 默认 ctx 截断 + 本地小模型行为退化）。紧凑
 * 重建后约 3KB。失败返回 NULL（调用方回退 "{}"）。 */
static char *params_min_json(const struct ai_tool *t)
{
	size_t cap = 96;
	char *out;
	size_t off = 0;
	int i, j;
	int nreq = 0;

	if (!t)
		return NULL;
	for (i = 0; i < t->param_count; i++) {
		const struct tool_param *p = &t->params[i];

		cap += (p->name ? strlen(p->name) : 2) * 6 + 48;
		cap += (p->type ? strlen(p->type) : 6) * 6 + 16;
		for (j = 0; j < p->enum_count; j++)
			cap += (p->enum_vals[j] ?
				strlen(p->enum_vals[j]) : 2) * 6 + 8;
	}
	out = malloc(cap);
	if (!out)
		return NULL;

#define PMJ_CLAMP() do { if (off > cap - 1) off = cap - 1; } while (0)

	off += (size_t)snprintf(out + off, cap - off,
				"{\"type\":\"object\",\"properties\":{");
	PMJ_CLAMP();
	for (i = 0; i < t->param_count; i++) {
		const struct tool_param *p = &t->params[i];
		char *en = ai_json_escape(p->name ? p->name : "");

		if (!en) {
			free(out);
			return NULL;
		}
		off += (size_t)snprintf(out + off, cap - off,
					"%s\"%s\":{\"type\":\"%s\"",
					i > 0 ? "," : "", en,
					p->type ? p->type : "string");
		PMJ_CLAMP();
		free(en);
		if (p->enum_count > 0) {
			off += (size_t)snprintf(out + off, cap - off,
						",\"enum\":[");
			PMJ_CLAMP();
			for (j = 0; j < p->enum_count; j++) {
				char *ee = ai_json_escape(p->enum_vals[j] ?
							  p->enum_vals[j] : "");

				if (!ee) {
					free(out);
					return NULL;
				}
				off += (size_t)snprintf(out + off, cap - off,
							"%s\"%s\"",
							j > 0 ? "," : "", ee);
				PMJ_CLAMP();
				free(ee);
			}
			off += (size_t)snprintf(out + off, cap - off, "]");
			PMJ_CLAMP();
		}
		off += (size_t)snprintf(out + off, cap - off, "}");
		PMJ_CLAMP();
		if (p->required)
			nreq++;
	}
	off += (size_t)snprintf(out + off, cap - off, "}");
	PMJ_CLAMP();
	if (nreq > 0) {
		off += (size_t)snprintf(out + off, cap - off, ",\"required\":[");
		PMJ_CLAMP();
		for (i = 0, j = 0; i < t->param_count; i++) {
			const struct tool_param *p = &t->params[i];
			char *en;

			if (!p->required)
				continue;
			en = ai_json_escape(p->name ? p->name : "");
			if (!en)
				continue;
			off += (size_t)snprintf(out + off, cap - off,
						"%s\"%s\"", j > 0 ? "," : "", en);
			PMJ_CLAMP();
			free(en);
			j++;
		}
		off += (size_t)snprintf(out + off, cap - off, "]");
		PMJ_CLAMP();
	}
	off += (size_t)snprintf(out + off, cap - off, "}");
	PMJ_CLAMP();

	return out;
}

static char *build_tools_json_impl(const struct tool_registry *reg,
				   const char *const *names, int name_count)
{
	size_t cap;
	char *out;
	size_t off = 0;
	int i;

	if (!reg || reg->tool_count <= 0)
		return NULL;

	/* 先估算容量：escape 后长度（膨胀上界 6x：控制字符 \uXXXX）+
	 * 每工具固定骨架。W4A 修复：原估算按原文长度累计，escape 膨胀
	 * 或骨架超预算时 snprintf 截断返回期望长度，off 累计越过 cap 后
	 * cap-off 发生 size_t 下溢，后续 snprintf 以巨尺寸写入越界
	 * （堆损坏，症状为远处 gettext/plural 链 SIGSEGV）。 */
	cap = 64;
	for (i = 0; i < reg->tool_count; i++)
		cap += (strlen(reg->tools[i].name) +
			strlen(reg->tools[i].desc) +
			(reg->tools[i].parameters_json ?
			 strlen(reg->tools[i].parameters_json) : 2)) * 6 +
		       256;

	out = malloc(cap);
	if (!out)
		return NULL;

	off += (size_t)snprintf(out + off, cap - off, "[");
	if (off > cap - 1)
		off = cap - 1;
	for (i = 0; i < reg->tool_count; i++) {
		const struct ai_tool *t = &reg->tools[i];
		char wire_name[AI_TOOLNAME_WIRE_MAX + 1];
		/* W65 P2-05：能力探测不可用的工具不进入请求数组
		 * （如内核未启用 PSI 时 /proc/pressure 下的节点）。 */
		if (!t->available)
			continue;
		/* W41 bug2: 出站线缆名点→下划线（无点号恒等，不改本名） */
		const char *out_name = ai_toolname_sanitize(t->name,
						    wire_name,
						    sizeof(wire_name));
		char *esc_name = ai_json_escape(out_name);
		/* W7S-T2：desc 80 字节截断（与 summarize 同款，UTF-8 边界
		 * 安全）——tools.json 里的完整描述经此路径原样进 prompt，
		 * 74 工具累计 ~7k token，为 prompt 超限主因之一。 */
		char dtmp[96];
		const char *desc = t->desc ? t->desc : "";
		size_t dlen = strlen(desc);
		char *esc_desc;
		/* W7S-T2：最小 parameters schema（见 params_min_json 注释） */
		char *pjson = params_min_json(t);
		int k, selected = 1;

		/* SME 路由过滤：names 非空时只输出已激活集合中的工具
		 * （会话级激活集合由 cmd_ask 维护，检索命中动态扩入） */
		if (names && name_count > 0) {
			selected = 0;
			for (k = 0; k < name_count; k++) {
				if (names[k] &&
				    strcmp(names[k], t->name) == 0) {
					selected = 1;
					break;
				}
			}
		}
		if (!selected) {
			free(esc_name);
			free(pjson);
			continue;
		}

		if (dlen > 80) {
			dlen = ai_json_utf8_floor(desc, 80);
			memcpy(dtmp, desc, dlen);
			dtmp[dlen] = '\0';
			desc = dtmp;
		}
		esc_desc = ai_json_escape(desc);

		if (!esc_name || !esc_desc) {
			free(esc_name);
			free(esc_desc);
			free(pjson);
			free(out);
			return NULL;
		}
		off += (size_t)snprintf(out + off, cap - off,
			"%s{\"type\":\"function\",\"function\":{"
			"\"name\":\"%s\",\"description\":\"%s\","
			"\"parameters\":%s}}",
			i > 0 ? "," : "", esc_name, esc_desc,
			pjson ? pjson :
			(t->parameters_json ? t->parameters_json : "{}"));
		if (off > cap - 1)
			off = cap - 1;
		free(esc_name);
		free(esc_desc);
		free(pjson);
	}
	off += (size_t)snprintf(out + off, cap - off, "]");

	return out;
}

char *tool_registry_build_tools_json(const struct tool_registry *reg)
{
	return build_tools_json_impl(reg, NULL, 0);
}

char *tool_registry_build_tools_json_filtered(const struct tool_registry *reg,
					      const char *const *names,
					      int name_count)
{
	if (!names || name_count <= 0)
		return build_tools_json_impl(reg, NULL, 0);
	return build_tools_json_impl(reg, names, name_count);
}

char *tool_registry_build_catalog(const struct tool_registry *reg)
{
	size_t cap;
	char *out;
	size_t off = 0;
	int i;

	if (!reg || reg->tool_count <= 0)
		return NULL;

	/* 目录页：每行 "<name> <核心短语>"。核心短语规则与
	 * gen_registry.py 的 tool_catalog.txt 生成逐字一致（单一权威
	 * 在 gen_registry.py）：desc 含"："/":"取其后文本，无则取整段
	 * 按句读（。！？;；）截首句，再 UTF-8 边界安全截 24 字节。 */
#define AI_CATALOG_DESC_BYTES 24

	cap = 128;
	for (i = 0; i < reg->tool_count; i++)
		cap += strlen(reg->tools[i].name) +
		       strlen(reg->tools[i].desc) + 64;

	out = malloc(cap);
	if (!out)
		return NULL;

	for (i = 0; i < reg->tool_count; i++) {
		const struct ai_tool *t = &reg->tools[i];
		const char *desc = t->desc ? t->desc : "";
		const char *phrase = desc;
		const char *colon = NULL;
		const char *p;
		char tmp[128];
		size_t plen;

		/* W65 P2-05：不可用工具不进入目录页 */
		if (!t->available)
			continue;

		/* 冒号优先（全角/半角，取第一处之后的文本） */
		for (p = desc; *p; p++) {
			if ((*p & 0x80) == 0 && *p == ':') {
				colon = p;
				break;
			}
			if ((unsigned char)p[0] == 0xEF &&
			    (unsigned char)p[1] == 0xBC &&
			    (unsigned char)p[2] == 0x9A) { /* "：" */
				colon = p;
				break;
			}
		}
		if (colon && colon[0] &&
		    ((colon[0] & 0x80) == 0 ? colon[1] : colon[3])) {
			phrase = ((colon[0] & 0x80) == 0) ?
				 colon + 1 : colon + 3;
		}
		while (*phrase == ' ')
			phrase++;

		/* 句读截首段：ASCII ';' '\n' 单字节；中文句读 ！？；
		 * 为三字节 UTF-8（EF BC 81/9F/9B），"。"为 E3 80 82。
		 * 注意全角冒号"："（EF BC 9A）不是句读——否则"安全边界：
		 * 决策参数"这类冒号后短语会被二次截断（与 gen_registry.py
		 * 的 _punct 集合对齐：。！？;；\n，无冒号） */
		plen = strlen(phrase);
		for (p = phrase; *p; p++) {
			if ((*p & 0x80) == 0) {
				if (*p == ';' || *p == '\n') {
					plen = (size_t)(p - phrase);
					break;
				}
				continue;
			}
			/* "。" E3 80 82 */
			if ((unsigned char)p[0] == 0xE3 &&
			    (unsigned char)p[1] == 0x80 &&
			    (unsigned char)p[2] == 0x82) {
				plen = (size_t)(p - phrase);
				break;
			}
			/* ！=EF BC 81 ；=EF BC 9B ？=EF BC 9F */
			if ((unsigned char)p[0] == 0xEF &&
			    (unsigned char)p[1] == 0xBC) {
				unsigned char c3 = (unsigned char)p[2];

				if (c3 == 0x81 || c3 == 0x9B ||
				    c3 == 0x9F) {
					plen = (size_t)(p - phrase);
					break;
				}
			}
		}
		if (plen >= sizeof(tmp))
			plen = sizeof(tmp) - 1;
		memcpy(tmp, phrase, plen);
		tmp[plen] = '\0';
		/* 去尾空格 */
		while (plen > 0 && tmp[plen - 1] == ' ')
			tmp[--plen] = '\0';

		/* UTF-8 边界安全截 28 字节 */
		plen = strlen(tmp);
		if (plen > AI_CATALOG_DESC_BYTES)
			plen = ai_json_utf8_floor(tmp,
						  AI_CATALOG_DESC_BYTES);

		off += (size_t)snprintf(out + off, cap - off, "%s %.*s\n",
					t->name, (int)plen, tmp);
		if (off > cap - 1)
			off = cap - 1;
	}

	/* W65 P2-05：全部工具不可用时也要返回合法空串（原实现 malloc
	 * 后未写 NUL，unavailable 过滤可能让循环零次执行）。 */
	if (off >= cap)
		off = cap - 1;
	out[off] = '\0';
	return out;
#undef AI_CATALOG_DESC_BYTES
}

static char *summarize_impl(const struct tool_registry *reg,
			    const char *const *names, int name_count)
{
	size_t cap = 4096;
	char *out;
	size_t off = 0;
	int i, j;

	if (!reg || reg->tool_count <= 0)
		return NULL;

	/* W7S：描述 80 字节截断（UTF-8 边界安全）——TCG 环境下 74 工具全量
	 * 描述会把 ask 首轮 prompt 撑到 ~6.5k token，prefill 逼近 8k ctx
	 * 且耗时 15 分钟级；截断后 ~5k token，语义锚（名称/通道/风险/首句）
	 * 保留。完整描述仍在 tools.json（executor 按 name 路由不受影响）。 */
	for (i = 0; i < reg->tool_count; i++)
		cap += (strlen(reg->tools[i].name) +
			strlen(reg->tools[i].desc)) * 6 + 256;

	out = malloc(cap);
	if (!out)
		return NULL;

	for (i = 0; i < reg->tool_count; i++) {
		const struct ai_tool *t = &reg->tools[i];
		char dtmp[96];
		const char *desc;
		size_t dlen;
		int k, selected = 1;

		/* W65 P2-05：不可用工具不进入文本清单 */
		if (!t->available)
			continue;

		/* SME 路由过滤（同 build_tools_json_impl）：names 非空时
		 * 只输出激活集合中的工具 */
		if (names && name_count > 0) {
			selected = 0;
			for (k = 0; k < name_count; k++) {
				if (names[k] &&
				    strcmp(names[k], t->name) == 0) {
					selected = 1;
					break;
				}
			}
		}
		if (!selected)
			continue;

		/* W7S：80 字节 UTF-8 安全描述截断（见函数头注释） */
		desc = t->desc ? t->desc : "";
		dlen = strlen(desc);
		if (dlen > 80) {
			dlen = ai_json_utf8_floor(desc, 80);
			memcpy(dtmp, desc, dlen);
			dtmp[dlen] = '\0';
			desc = dtmp;
		}

#define AI_SUM_CLAMP() \
		do { if (off > cap - 1) off = cap - 1; } while (0)

		/* v2：摘要带风险级（exec 通道按命令分级，工具级标 EXEC*）。
		 * W4A：每个 snprintf 后钳制 off——截断时返回期望长度，
		 * 不钳制则 cap-off 发生 size_t 下溢 → 越界写堆 */
		if (t->risk)
			off += (size_t)snprintf(out + off, cap - off,
						"- %s [%s/%s] %s",
						t->name, channel_str(t->channel),
						t->risk, desc);
		else
			off += (size_t)snprintf(out + off, cap - off,
						"- %s [%s] %s",
						t->name, channel_str(t->channel),
						desc);
		AI_SUM_CLAMP();
		if (t->param_count > 0) {
			off += (size_t)snprintf(out + off, cap - off,
						" | 参数: ");
			AI_SUM_CLAMP();
			for (j = 0; j < t->param_count; j++) {
				const struct tool_param *p = &t->params[j];

				off += (size_t)snprintf(out + off, cap - off,
					"%s%s(%s%s)", j > 0 ? ", " : "",
					p->name, p->type ? p->type : "string",
					p->required ? ",必填" : "");
				AI_SUM_CLAMP();
			}
		} else {
			off += (size_t)snprintf(out + off, cap - off,
						" | 参数: 无");
			AI_SUM_CLAMP();
		}
		off += (size_t)snprintf(out + off, cap - off, "\n");
		AI_SUM_CLAMP();
#undef AI_SUM_CLAMP
	}

	/* W65 P2-05：过滤后可能零条，必须显式 NUL 终止 */
	if (off >= cap)
		off = cap - 1;
	out[off] = '\0';
	return out;
}

char *tool_registry_summarize(const struct tool_registry *reg)
{
	return summarize_impl(reg, NULL, 0);
}

char *tool_registry_summarize_filtered(const struct tool_registry *reg,
				       const char *const *names,
				       int name_count)
{
	if (!names || name_count <= 0)
		return summarize_impl(reg, NULL, 0);
	return summarize_impl(reg, names, name_count);
}

void tool_registry_count_by_channel(const struct tool_registry *reg,
				    int *counts)
{
	int i;

	memset(counts, 0, sizeof(int) * (TOOL_CH_UNKNOWN + 1));
	if (!reg)
		return;
	for (i = 0; i < reg->tool_count; i++)
		counts[reg->tools[i].channel]++;
}
