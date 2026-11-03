// SPDX-License-Identifier: GPL-2.0
/*
 * dtstatic.c - 静态资源服务:unquote → normpath 双 root 防穿越、
 * 内建 mimetypes 表(以 T6a 录制实测为准:.js=text/javascript、
 * .xyz=chemical/x-xyz、未命中=application/octet-stream)、
 * Cache-Control: public, max-age=300。
 */
#define _POSIX_C_SOURCE 200809L

#include "desktop/dtstatic.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "desktop/dtcore.h"

struct mime_entry {
	const char *ext;
	const char *type;
};

/* 表以 static 向量 20 步为准;其余为 Python3.10+Ubuntu mime.types 的常见项
 * (树内实际可请求扩展:html/css/js/svg/png/json/py)。 */
static const struct mime_entry MIME_TABLE[] = {
	{ "html", "text/html" },
	{ "htm", "text/html" },
	{ "css", "text/css" },
	{ "js", "text/javascript" },     /* L1 实测(3.12 前内建表为
					    application/javascript,以录制为准) */
	{ "mjs", "text/javascript" },
	{ "json", "application/json" },
	{ "png", "image/png" },
	{ "svg", "image/svg+xml" },
	{ "jpg", "image/jpeg" },
	{ "jpeg", "image/jpeg" },
	{ "webp", "image/webp" },
	{ "gif", "image/gif" },
	{ "ico", "image/vnd.microsoft.icon" },
	{ "xpm", "image/x-xpixmap" },
	{ "xyz", "chemical/x-xyz" },     /* L1 /etc/mime.types 实测 */
	{ "txt", "text/plain" },
	{ "py", "text/x-python" },
	{ "xml", "application/xml" },
	{ "pdf", "application/pdf" },
};
#define N_MIME ((int)(sizeof(MIME_TABLE) / sizeof(MIME_TABLE[0])))

const char *dt_guess_type(const char *path)
{
	const char *dot = strrchr(path, '.');
	char ext[16];
	size_t n;

	if (!dot || !dot[1])
		return "application/octet-stream";
	n = strlen(dot + 1);
	if (n == 0 || n >= sizeof(ext))
		return "application/octet-stream";
	for (size_t i = 0; i < n; i++) {
		char c = dot[1 + i];

		ext[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
	}
	ext[n] = '\0';
	for (int i = 0; i < N_MIME; i++)
		if (strcmp(MIME_TABLE[i].ext, ext) == 0)
			return MIME_TABLE[i].type;
	return "application/octet-stream";
}

int dt_static_lookup(const char *rel_raw, char **body, size_t *body_len,
		     const char **ctype)
{
	char *rel = dt_unquote(rel_raw);
	const char *roots[2];
	int nroots = 1;
	int rc = -1;

	if (!rel)
		return -1;
	roots[0] = g_cfg.static_dir;
	if (strncmp(rel, "icons/", 6) == 0) {
		roots[1] = g_cfg.state_root;
		nroots = 2;
	}
	for (int i = 0; i < nroots && rc != 0; i++) {
		char full[DT_PATH_MAX];
		size_t rlen = strlen(roots[i]);

		dt_normpath_join(full, sizeof(full), roots[i], rel);
		/* full == root 或 startswith(root + "/") 才放行 */
		if (!(strcmp(full, roots[i]) == 0 ||
		      (strncmp(full, roots[i], rlen) == 0 &&
		       full[rlen] == '/')))
			continue;
		if (!dt_is_file(full))
			continue;
		{
			size_t n = 0;
			char *data = dt_read_file(full, &n);

			if (!data)
				continue; /* OSError → 试下一个 root */
			*body = data;
			*body_len = n;
			*ctype = dt_guess_type(full);
			rc = 0;
		}
	}
	free(rel);
	return rc;
}
