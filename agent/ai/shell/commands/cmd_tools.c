// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_tools.c - tools 命令实现（W43：工具面清单）
 *
 * 数据源=工具注册表（tool_registry_load：AIKERNEL_TOOLS_JSON →
 * ./tools.json → tools/tools.json → /usr/local/share/aikernel 兜底）。
 * 输出：编号、名、通道、risk、一句话描述（描述取首行）；支持按
 * 工具名/通道名/风险级子串过滤（大小写不敏感）。
 * 与 ask 的工具面同源同表——这里看到的即模型可用的（受闸门约束的
 * 执行范围另由 risk/plan 态/uid 档位决定，清单如实展示注册表）。
 */
#define _GNU_SOURCE             /* strcasestr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_lang.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"

/* 通道枚举 → 展示名（与 audit 线命名一致） */
static const char *ch_name(enum tool_channel ch)
{
	switch (ch) {
	case TOOL_CH_PROCFS_READ:	return "procfs-read";
	case TOOL_CH_SYSFS_WRITE:	return "sysfs-write";
	case TOOL_CH_NETLINK_ACT:	return "netlink-act";
	case TOOL_CH_NETLINK_SENSE:	return "netlink-sense";
	case TOOL_CH_EXEC:		return "exec";
	case TOOL_CH_MEMORY:		return "memory";
	case TOOL_CH_SHELL:		return "shell";
	case TOOL_CH_SANDBOX:		return "sandbox";
	default:			return "unknown";
	}
}

/* 过滤词匹配：工具名/通道名子串（大小写不敏感）或风险级全等 */
static int tool_match(const struct ai_tool *t, const char *f)
{
	const char *ch;

	if (t->name && strcasestr(t->name, f))
		return 1;
	if (t->risk && strcasecmp(t->risk, f) == 0)
		return 1;
	ch = ch_name(t->channel);
	return ch && strcasestr(ch, f);
}

/*
 * cmd_tools - 列出工具面
 * 用法: /tools [channel|关键词]
 */
int cmd_tools(void *shell, int argc, char **argv)
{
	struct tool_registry reg;
	char *err = NULL;
	const char *filter = argc >= 2 ? argv[1] : NULL;
	int i;
	int hits = 0;

	(void)shell;

	if (tool_registry_load(&reg, &err) != AI_OK) {
		printf("tools: %s\n", err ? err : "注册表加载失败");
		free(err);
		return AI_ERR_NOT_FOUND;
	}

	printf("%s", tr(TR_TOOLS_HDR));
	for (i = 0; i < reg.tool_count; i++) {
		const struct ai_tool *t = &reg.tools[i];
		char desc1[96];
		const char *d = t->desc ? t->desc : "";
		const char *nl = strchr(d, '\n');
		size_t dl = nl ? (size_t)(nl - d) : strlen(d);

		if (filter && !tool_match(t, filter))
			continue;
		if (dl >= sizeof(desc1))
			dl = sizeof(desc1) - 1;
		/* UTF-8 safe truncation: floor back to a char boundary
		 * (never cut inside a multibyte sequence, T2 discipline) */
		dl = (size_t)ai_json_utf8_floor(d, dl);
		memcpy(desc1, d, dl);
		desc1[dl] = '\0';
		printf(tr(TR_TOOLS_ROW), i + 1, t->name, ch_name(t->channel),
		       t->risk ? t->risk : "-", desc1);
		hits++;
	}

	if (hits == 0) {
		printf(tr(TR_TOOLS_EMPTY), filter ? filter : "-");
	} else {
		printf(tr(TR_TOOLS_TOTAL), hits, reg.tool_count);
		if (filter)
			printf(tr(TR_TOOLS_FILTER), filter);
	}

	tool_registry_free(&reg);
	return AI_OK;
}
