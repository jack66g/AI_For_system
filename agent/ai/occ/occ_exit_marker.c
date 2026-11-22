/* SPDX-License-Identifier: GPL-2.0 */
/* occ_exit_marker.c - P-47/P-2a：终局退出 marker 路径/写面（纯 libc） */
#include <stdio.h>
#include <string.h>

#include "occ_exit_marker.h"

#define EXIT_MARKER_PATH_MAX 320
#define EXIT_MARKER_RUN_PREFIX "/run/"
#define EXIT_MARKER_TMP_PREFIX "/tmp/"

const char *occ_exit_marker_path(char *buf, size_t buflen, uid_t uid,
				 const char *env_override)
{
	if (env_override && env_override[0]) {
		/* 测试显式覆盖：整路径照用（P-47 M1-M3 契约不变） */
		snprintf(buf, buflen, "%s", env_override);
		return buf;
	}
	if (uid == 0)
		snprintf(buf, buflen, "%s", "/run/aik-occ-exit");
	else
		snprintf(buf, buflen, "/run/aik-occ-exit.%u", (unsigned)uid);
	return buf;
}

int occ_exit_marker_write(uid_t uid, int code, const char *env_override,
			  char *path_out, size_t path_out_len)
{
	char p[EXIT_MARKER_PATH_MAX];
	char fb[EXIT_MARKER_PATH_MAX];
	const char *use = p;
	FILE *fp;

	occ_exit_marker_path(p, sizeof(p), uid, env_override);
	fp = fopen(p, "w");
	if (!fp && strncmp(p, EXIT_MARKER_RUN_PREFIX,
			   sizeof(EXIT_MARKER_RUN_PREFIX) - 1) == 0) {
		/* /run 不可写回落 /tmp 同名（env 显式路径不回落——
		 * 老口径：显式给路径就认这一条） */
		snprintf(fb, sizeof(fb), "%s%s", EXIT_MARKER_TMP_PREFIX,
			 p + sizeof(EXIT_MARKER_RUN_PREFIX) - 1);
		use = fb;
		fp = fopen(fb, "w");
	}
	if (path_out && path_out_len)
		snprintf(path_out, path_out_len, "%s", use);
	if (!fp)
		return -1;
	fprintf(fp, "%d\n", code);
	if (fflush(fp) != 0 || fclose(fp) != 0)
		return -1;
	return 0;
}
