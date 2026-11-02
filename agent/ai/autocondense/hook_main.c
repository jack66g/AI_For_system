/* SPDX-License-Identifier: GPL-2.0 */
/* autocondense-hook：宿主钩子适配器入口（argv[1] = 事件名）。 */
#include "autocondense/achook.h"

#include <stddef.h>

int main(int argc, char **argv)
{
	return achook_run(argc > 1 ? argv[1] : NULL);
}
