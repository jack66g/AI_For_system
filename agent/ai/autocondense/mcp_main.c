/* SPDX-License-Identifier: GPL-2.0 */
/* autocondense-mcp：MCP stdio 薄代理入口。 */
#include "autocondense/acmcp.h"

int main(int argc, char **argv)
{
	(void)argc;
	return acmcp_run(argv[0]);
}
