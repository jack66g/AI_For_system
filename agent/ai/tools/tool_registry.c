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

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"

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
	return TOOL_CH_UNKNOWN;
}

static const char *channel_str(enum tool_channel ch)
{
	static const char *const names[] = {
		"procfs-read", "sysfs-write", "netlink-act", "netlink-sense",
		"exec", "memory", "shell", "unknown",
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

		if (!c.command) {
			free(c.bin);
			free(c.risk);
			for (j = 0; j < c.args_template_n; j++)
				free(c.args_template[j]);
			free(c.args_template);
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

	/* 1) 环境变量显式指定 */
	{
		const char *env = getenv("AIKERNEL_TOOLS_JSON");

		if (env && env[0] && read_file(env, &text) == AI_OK) {
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
			if (parse_tool(tt, tl, &t) != AI_OK)
				continue;       /* 跳过坏条目，不整体失败 */
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
	}

	reg->source_path = cand;
	free(text);

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

char *tool_registry_build_tools_json(const struct tool_registry *reg)
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
		char *esc_name = ai_json_escape(t->name);
		char *esc_desc = ai_json_escape(t->desc ? t->desc : "");

		if (!esc_name || !esc_desc) {
			free(esc_name);
			free(esc_desc);
			free(out);
			return NULL;
		}
		off += (size_t)snprintf(out + off, cap - off,
			"%s{\"type\":\"function\",\"function\":{"
			"\"name\":\"%s\",\"description\":\"%s\","
			"\"parameters\":%s}}",
			i > 0 ? "," : "", esc_name, esc_desc,
			t->parameters_json ? t->parameters_json : "{}");
		if (off > cap - 1)
			off = cap - 1;
		free(esc_name);
		free(esc_desc);
	}
	off += (size_t)snprintf(out + off, cap - off, "]");

	return out;
}

char *tool_registry_summarize(const struct tool_registry *reg)
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

	return out;
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
