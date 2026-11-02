/* SPDX-License-Identifier: GPL-2.0 */
/*
 * routes_extra.c - T4e 追加路由：multipart 导入 / 可视化 / 配置 UI
 *
 *   POST /import/file   multipart/form-data 的 file 字段（JSON）
 *   GET  /visualize     记忆空间 PNG（C 版 PCA 散点渲染，matplotlib 替代）
 *   GET  /               配置 UI index.html
 *   GET  /static/<file>  配置 UI 静态资源（目录由 --static-dir 指定）
 *
 * 参考对齐 sme/api/server.py：
 *   - import_file：字段缺失/非 multipart → 422 Pydantic missing（loc
 *     ["body","file"]）；JSON 解析失败 → 400 {"detail":"invalid file: …"}；
 *     顶层对象取 .memories，顶层数组原样，其余空；返回 {"imported":n}。
 *   - visualize：空间为空（没有带向量的活跃记忆）→ 501
 *     {"error":"no memories with embeddings to visualize"}；否则 image/png。
 *     C 版不依赖 matplotlib：把向量 PCA 投影到二维画散点/区域质心/图边，
 *     输出合法 PNG（尺寸取 visualization.figure_size × dpi）。
 *   - 静态资源：/ 返回 index.html；/static/<file> 只允许单段安全文件名，
 *     ..、/、\ 一律 404 {"detail":"Not Found"}（参考 StaticFiles 同结果）。
 *
 * 限制（写进 T4e 报告）：JSON 解析错误文案对 offset=0 的场景与 CPython
 * 一致（"Expecting value: line 1 column 1 (char 0)"），其他位置给
 * store_json 的 "offset=N: reason"；非 UTF-8 上传返回 400 但文案不同。
 */
#define _POSIX_C_SOURCE 200809L

#include "smehttp/http.h"

#include "engine/engine.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>

/* ------------------------------------------------------------------ */
/* 小工具                                                             */
/* ------------------------------------------------------------------ */
static void respond_error(aik_http_response *resp, int status,
			  const char *detail)
{
	aik_http_response_detail(resp, status, detail);
}

static void respond_500(aik_http_response *resp)
{
	aik_http_response_detail(resp, 500, "Internal Server Error");
}

static void respond_missing_file(aik_http_response *resp)
{
	/* FastAPI/Starlette 对缺失 UploadFile 的 422 精确形状 */
	static const char body[] =
		"{\"detail\":[{\"type\":\"missing\",\"loc\":[\"body\",\"file\"],"
		"\"msg\":\"Field required\",\"input\":null}]}";
	char *copy = malloc(sizeof(body));

	if (!copy) {
		respond_500(resp);
		return;
	}
	memcpy(copy, body, sizeof(body));
	aik_http_response_bytes(resp, 422, "application/json", copy,
				sizeof(body) - 1);
}

/* 大小写不敏感子串（不依赖 GNU strcasestr） */
static const char *ci_strstr(const char *hay, const char *needle)
{
	size_t nlen = strlen(needle);
	const char *p;

	if (!hay || nlen == 0)
		return hay;
	for (p = hay; *p; p++) {
		if (strncasecmp(p, needle, nlen) == 0)
			return p;
	}
	return NULL;
}

static const unsigned char *find_sub(const unsigned char *hay, size_t hlen,
				     const char *needle, size_t nlen,
				     size_t from)
{
	size_t i;

	if (!hay || nlen == 0 || from >= hlen)
		return NULL;
	for (i = from; i + nlen <= hlen; i++) {
		if (memcmp(hay + i, needle, nlen) == 0)
			return hay + i;
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* multipart/form-data：取 name="file" 的 part                        */
/* ------------------------------------------------------------------ */
static int ci_prefix(const char *s, const char *prefix)
{
	size_t n = strlen(prefix);

	return s && strncasecmp(s, prefix, n) == 0;
}

/*
 * 返回 1=找到（out/outlen 指向 req->body 内部），0=没有 file 字段，
 * -1=Content-Type 不是 multipart（与 0 同样按 missing 处理）。
 */
static int multipart_file(const aik_http_request *req, const char **out,
			  size_t *outlen)
{
	const unsigned char *body = (const unsigned char *)req->body;
	size_t blen = req->body_len;
	const char *bparam;
	char boundary[256];
	size_t bl;
	char delim[300];
	size_t dlen;
	size_t pos;
	const unsigned char *p;

	*out = NULL;
	*outlen = 0;
	if (!body || !req->content_type ||
	    !ci_prefix(req->content_type, "multipart/form-data"))
		return -1;
	bparam = ci_strstr(req->content_type, "boundary=");
	if (!bparam)
		return -1;
	bparam += 9;
	if (*bparam == '"') {
		const char *end = strchr(bparam + 1, '"');

		if (!end)
			return -1;
		bl = (size_t)(end - (bparam + 1));
		if (bl >= sizeof(boundary))
			return -1;
		memcpy(boundary, bparam + 1, bl);
		boundary[bl] = '\0';
	} else {
		const char *end = bparam;

		while (*end && *end != ';' && *end != ',' && *end != ' ')
			end++;
		bl = (size_t)(end - bparam);
		if (bl >= sizeof(boundary))
			return -1;
		memcpy(boundary, bparam, bl);
		boundary[bl] = '\0';
	}
	if (bl == 0)
		return -1;
	snprintf(delim, sizeof(delim), "--%s", boundary);
	dlen = strlen(delim);
	p = find_sub(body, blen, delim, dlen, 0);
	if (!p)
		return 0;
	pos = (size_t)(p - body) + dlen;
	for (;;) {
		const unsigned char *hdr_end;
		const unsigned char *content;
		const unsigned char *next;
		size_t hlen;
		char *hdrs;
		int has_name = 0;

		/* 分隔符后：-- 结尾 或 CRLF */
		if (pos + 2 <= blen && body[pos] == '-' && body[pos + 1] == '-')
			return 0;
		if (pos + 2 <= blen && body[pos] == '\r' && body[pos + 1] == '\n')
			pos += 2;
		else if (pos + 1 <= blen && body[pos] == '\n')
			pos += 1;
		else
			return 0;
		hdr_end = find_sub(body + pos, blen - pos, "\r\n\r\n", 4, 0);
		if (!hdr_end)
			return 0;
		hlen = (size_t)(hdr_end - (body + pos));
		hdrs = malloc(hlen + 1);
		if (!hdrs)
			return 0;
		memcpy(hdrs, body + pos, hlen);
		hdrs[hlen] = '\0';
		if (ci_strstr(hdrs, "content-disposition:") &&
		    ci_strstr(hdrs, "name=\"file\""))
			has_name = 1;
		free(hdrs);
		content = hdr_end + 4;
		next = find_sub(body, blen, delim, dlen,
				(size_t)(content - body));
		if (!next)
			return 0;
		if (has_name) {
			size_t clen = (size_t)(next - content);

			/* 去掉 content 末尾的 CRLF */
			if (clen >= 2 && content[clen - 2] == '\r' &&
			    content[clen - 1] == '\n')
				clen -= 2;
			else if (clen >= 1 && content[clen - 1] == '\n')
				clen -= 1;
			*out = (const char *)content;
			*outlen = clen;
			return 1;
		}
		pos = (size_t)(next - body) + dlen;
	}
}

static int valid_utf8(const unsigned char *s, size_t n)
{
	size_t i = 0;

	while (i < n) {
		unsigned char c = s[i];

		if (c < 0x80) {
			i++;
		} else if ((c & 0xe0) == 0xc0) {
			if (i + 1 >= n || (s[i + 1] & 0xc0) != 0x80)
				return 0;
			i += 2;
		} else if ((c & 0xf0) == 0xe0) {
			if (i + 2 >= n || (s[i + 1] & 0xc0) != 0x80 ||
			    (s[i + 2] & 0xc0) != 0x80)
				return 0;
			i += 3;
		} else if ((c & 0xf8) == 0xf0) {
			if (i + 3 >= n || (s[i + 1] & 0xc0) != 0x80 ||
			    (s[i + 2] & 0xc0) != 0x80 ||
			    (s[i + 3] & 0xc0) != 0x80)
				return 0;
			i += 4;
		} else {
			return 0;
		}
	}
	return 1;
}

void aik_http_route_import_file(aik_http_server *s,
				const aik_http_request *req,
				aik_http_response *resp)
{
	const char *data = NULL;
	size_t len = 0;
	aik_json *root;
	const aik_json *items;
	long long imported = 0;
	aik_json *out;
	char err[512];

	if (multipart_file(req, &data, &len) != 1) {
		respond_missing_file(resp);
		return;
	}
	if (!valid_utf8((const unsigned char *)data, len)) {
		respond_error(resp, 400, "invalid file: invalid UTF-8");
		return;
	}
	root = aik_json_parse(data, len, err, sizeof(err));
	if (!root) {
		const char *colon = strstr(err, "offset=");
		char detail[600];

		if ((!data || len == 0) ||
		    (colon && strncmp(colon, "offset=0", 8) == 0)) {
			respond_error(resp, 400,
				      "invalid file: Expecting value: line 1 "
				      "column 1 (char 0)");
			return;
		}
		snprintf(detail, sizeof(detail), "invalid file: %s", err);
		respond_error(resp, 400, detail);
		return;
	}
	if (aik_json_typeof(root) == AIK_JSON_ARR) {
		items = root;
	} else if (aik_json_typeof(root) == AIK_JSON_OBJ) {
		items = aik_json_get(root, "memories");
		if (!items) {
			aik_json *empty = aik_json_new_arr();

			if (!empty) {
				aik_json_free(root);
				respond_500(resp);
				return;
			}
			items = empty;
		} else if (aik_json_typeof(items) != AIK_JSON_ARR) {
			aik_json_free(root);
			respond_500(resp);
			return;
		}
	} else {
		aik_json *empty = aik_json_new_arr();

		if (!empty) {
			aik_json_free(root);
			respond_500(resp);
			return;
		}
		items = empty;
	}
	if (aik_engine_import(aik_http_server_engine(s), items, &imported,
			      err, sizeof(err)) != 0) {
		aik_json_free(root);
		respond_500(resp);
		return;
	}
	out = aik_json_new_obj();
	if (!out ||
	    aik_json_obj_put(out, "imported",
			     aik_json_new_int(imported)) != 0) {
		aik_json_free(out);
		aik_json_free(root);
		respond_500(resp);
		return;
	}
	aik_json_free(root);
	aik_http_response_json(resp, 200, out);
}

/* ------------------------------------------------------------------ */
/* PNG 编码 + 绘图                                                    */
/* ------------------------------------------------------------------ */
struct canvas {
	int w;
	int h;
	unsigned char *rgb;
};

static void blend_px(struct canvas *c, int x, int y, int r, int g, int b,
		     double alpha)
{
	unsigned char *p;
	double ia;

	if (x < 0 || y < 0 || x >= c->w || y >= c->h)
		return;
	p = c->rgb + ((size_t)y * (size_t)c->w + (size_t)x) * 3;
	ia = 1.0 - alpha;
	p[0] = (unsigned char)(r * alpha + p[0] * ia + 0.5);
	p[1] = (unsigned char)(g * alpha + p[1] * ia + 0.5);
	p[2] = (unsigned char)(b * alpha + p[2] * ia + 0.5);
}

static void draw_disc(struct canvas *c, double cx, double cy, double rad,
		      int r, int g, int b, double alpha)
{
	int x0 = (int)floor(cx - rad);
	int x1 = (int)ceil(cx + rad);
	int y0 = (int)floor(cy - rad);
	int y1 = (int)ceil(cy + rad);
	int x, y;

	for (y = y0; y <= y1; y++) {
		for (x = x0; x <= x1; x++) {
			double dx = x + 0.5 - cx;
			double dy = y + 0.5 - cy;

			if (dx * dx + dy * dy <= rad * rad)
				blend_px(c, x, y, r, g, b, alpha);
		}
	}
}

static void draw_line(struct canvas *c, int x0, int y0, int x1, int y1,
		      int r, int g, int b, double alpha)
{
	int dx = abs(x1 - x0);
	int dy = -abs(y1 - y0);
	int sx = x0 < x1 ? 1 : -1;
	int sy = y0 < y1 ? 1 : -1;
	int err = dx + dy;

	for (;;) {
		blend_px(c, x0, y0, r, g, b, alpha);
		if (x0 == x1 && y0 == y1)
			break;
		{
			int e2 = 2 * err;

			if (e2 >= dy) {
				err += dy;
				x0 += sx;
			}
			if (e2 <= dx) {
				err += dx;
				y0 += sy;
			}
		}
	}
}

static void be32(unsigned char *p, unsigned long v)
{
	p[0] = (unsigned char)((v >> 24) & 0xff);
	p[1] = (unsigned char)((v >> 16) & 0xff);
	p[2] = (unsigned char)((v >> 8) & 0xff);
	p[3] = (unsigned char)(v & 0xff);
}

static int png_chunk(unsigned char *out, size_t *off, const char *type,
		     const unsigned char *data, size_t len)
{
	unsigned long crc;

	be32(out + *off, (unsigned long)len);
	memcpy(out + *off + 4, type, 4);
	if (len && data)
		memcpy(out + *off + 8, data, len);
	crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, (const Bytef *)(out + *off + 4), (uInt)(len + 4));
	be32(out + *off + 8 + len, crc);
	*off += len + 12;
	return 0;
}

/* 成功返回 malloc 的 PNG；失败 NULL（err 可选） */
static unsigned char *encode_png(const struct canvas *c, size_t *outlen)
{
	size_t row = 1 + (size_t)c->w * 3;
	size_t rawlen = row * (size_t)c->h;
	unsigned char *raw = malloc(rawlen);
	uLongf zlen = compressBound((uLong)rawlen);
	unsigned char *z = malloc(zlen ? zlen : 1);
	size_t total;
	unsigned char *png;
	size_t off = 0;
	unsigned char ihdr[13];
	int y;

	if (!raw || !z) {
		free(raw);
		free(z);
		return NULL;
	}
	for (y = 0; y < c->h; y++) {
		raw[(size_t)y * row] = 0;
		memcpy(raw + (size_t)y * row + 1,
		       c->rgb + (size_t)y * (size_t)c->w * 3,
		       (size_t)c->w * 3);
	}
	if (compress2(z, &zlen, raw, (uLong)rawlen, 6) != Z_OK) {
		free(raw);
		free(z);
		return NULL;
	}
	free(raw);
	total = 8 + 25 + 12 + (size_t)zlen + 12;
	png = malloc(total);
	if (!png) {
		free(z);
		return NULL;
	}
	memcpy(png, "\x89PNG\r\n\x1a\n", 8);
	off = 8;
	be32(ihdr, (unsigned long)c->w);
	be32(ihdr + 4, (unsigned long)c->h);
	ihdr[8] = 8;		/* bit depth */
	ihdr[9] = 2;		/* truecolor RGB */
	ihdr[10] = 0;
	ihdr[11] = 0;
	ihdr[12] = 0;
	png_chunk(png, &off, "IHDR", ihdr, sizeof(ihdr));
	png_chunk(png, &off, "IDAT", z, (size_t)zlen);
	png_chunk(png, &off, "IEND", NULL, 0);
	free(z);
	*outlen = off;
	return png;
}

/* ------------------------------------------------------------------ */
/* PCA 2D 投影                                                        */
/* ------------------------------------------------------------------ */
struct vpoint {
	const aik_memory *m;
	int dim;
	double x;
	double y;
};

static void pca_project(struct vpoint *pts, size_t n, int dim, double *mean,
			double *basis)
{
	double *v = calloc((size_t)dim, sizeof(double));
	double *w = calloc((size_t)dim, sizeof(double));
	size_t i;
	int d, iter;

	if (!v || !w) {
		free(v);
		free(w);
		return;
	}
	for (d = 0; d < dim; d++) {
		double s = 0.0;

		for (i = 0; i < n; i++)
			s += pts[i].m->embedding[d];
		mean[d] = s / (double)n;
	}
	/* 第一主成分：幂迭代 */
	for (d = 0; d < dim; d++)
		v[d] = 1.0 / sqrt((double)dim);
	for (iter = 0; iter < 30; iter++) {
		double norm = 0.0;

		memset(w, 0, (size_t)dim * sizeof(double));
		for (i = 0; i < n; i++) {
			const double *e = pts[i].m->embedding;
			double dot = 0.0;

			for (d = 0; d < dim; d++)
				dot += (e[d] - mean[d]) * v[d];
			for (d = 0; d < dim; d++)
				w[d] += dot * (e[d] - mean[d]);
		}
		for (d = 0; d < dim; d++)
			norm += w[d] * w[d];
		norm = sqrt(norm);
		if (norm < 1e-12)
			break;
		for (d = 0; d < dim; d++)
			v[d] = w[d] / norm;
	}
	memcpy(basis, v, (size_t)dim * sizeof(double));
	/* 第二主成分：对 deflate 后的算符再幂迭代 */
	for (d = 0; d < dim; d++)
		v[d] = (d == 0) ? 1.0 : 0.0;
	for (iter = 0; iter < 30; iter++) {
		double norm = 0.0;
		double proj = 0.0;

		memset(w, 0, (size_t)dim * sizeof(double));
		for (i = 0; i < n; i++) {
			const double *e = pts[i].m->embedding;
			double dot = 0.0;

			for (d = 0; d < dim; d++)
				dot += (e[d] - mean[d]) * v[d];
			for (d = 0; d < dim; d++)
				w[d] += dot * (e[d] - mean[d]);
		}
		for (d = 0; d < dim; d++)
			proj += w[d] * basis[d];
		for (d = 0; d < dim; d++)
			w[d] -= proj * basis[d];
		for (d = 0; d < dim; d++)
			norm += w[d] * w[d];
		norm = sqrt(norm);
		if (norm < 1e-12)
			break;
		for (d = 0; d < dim; d++)
			v[d] = w[d] / norm;
	}
	memcpy(basis + dim, v, (size_t)dim * sizeof(double));
	for (i = 0; i < n; i++) {
		const double *e = pts[i].m->embedding;
		double x = 0.0, y = 0.0;

		for (d = 0; d < dim; d++) {
			double c = e[d] - mean[d];

			x += c * basis[d];
			y += c * basis[dim + d];
		}
		pts[i].x = x;
		pts[i].y = y;
	}
	free(v);
	free(w);
}

static void project_one(const double *vec, int dim, const double *mean,
			const double *basis, double *x, double *y)
{
	int d;
	double px = 0.0, py = 0.0;

	*x = 0.0;
	*y = 0.0;
	if (!vec)
		return;
	for (d = 0; d < dim; d++) {
		double c = vec[d] - mean[d];

		px += c * basis[d];
		py += c * basis[dim + d];
	}
	*x = px;
	*y = py;
}

static const int PALETTE[10][3] = {
	{ 31, 119, 180 }, { 255, 127, 14 }, { 44, 160, 44 },
	{ 214, 39, 40 }, { 148, 103, 189 }, { 140, 86, 75 },
	{ 227, 119, 194 }, { 127, 127, 127 }, { 188, 189, 34 },
	{ 23, 190, 207 }
};

static int region_color(const char *rid)
{
	unsigned long h = 2166136261UL;

	if (!rid)
		return 7;
	while (*rid) {
		h ^= (unsigned char)*rid++;
		h *= 16777619UL;
	}
	return (int)(h % 10);
}

static void read_figure(const aik_config *cfg, int *w, int *h)
{
	const aik_json *dom = aik_config_dom(cfg);
	const aik_json *vz = aik_json_get(dom, "visualization");
	const aik_json *fs = aik_json_get(vz, "figure_size");
	double fw = 12.0, fh = 9.0, dpi = 120.0;

	if (fs && aik_json_typeof(fs) == AIK_JSON_ARR &&
	    aik_json_count(fs) >= 2) {
		fw = aik_json_num(aik_json_at(fs, 0));
		fh = aik_json_num(aik_json_at(fs, 1));
	}
	if (vz) {
		const aik_json *d = aik_json_get(vz, "dpi");

		if (d && aik_json_typeof(d) != AIK_JSON_NULL)
			dpi = aik_json_num(d);
	}
	if (fw <= 0.1 || fw > 40.0)
		fw = 12.0;
	if (fh <= 0.1 || fh > 40.0)
		fh = 9.0;
	if (dpi <= 10.0 || dpi > 600.0)
		dpi = 120.0;
	*w = (int)(fw * dpi + 0.5);
	*h = (int)(fh * dpi + 0.5);
	if (*w < 200)
		*w = 200;
	if (*h < 200)
		*h = 200;
	if (*w > 2000)
		*w = 2000;
	if (*h > 2000)
		*h = 2000;
}

void aik_http_route_visualize(aik_http_server *s,
			      const aik_http_request *req,
			      aik_http_response *resp)
{
	aik_engine *e = aik_http_server_engine(s);
	aik_config *cfg = aik_http_server_config(s);
	size_t total = aik_engine_memory_count(e);
	struct vpoint *pts;
	size_t n = 0;
	size_t i;
	int dim = 0;
	double *mean, *basis;
	struct canvas c;
	unsigned char *png;
	size_t pnglen = 0;

	(void)req;
	pts = calloc(total ? total : 1, sizeof(*pts));
	if (!pts) {
		respond_500(resp);
		return;
	}
	for (i = 0; i < total; i++) {
		const aik_memory *m = aik_engine_memory_at(e, i);

		if (!m || m->archived || !m->embedding || m->dim <= 0)
			continue;
		if (dim && m->dim != dim)
			continue;
		dim = m->dim;
		pts[n].m = m;
		pts[n].dim = m->dim;
		n++;
	}
	if (n == 0 || dim <= 0) {
		static const char msg[] =
			"{\"error\":\"no memories with embeddings to "
			"visualize\"}";
		char *copy = malloc(sizeof(msg));

		free(pts);
		if (!copy) {
			respond_500(resp);
			return;
		}
		memcpy(copy, msg, sizeof(msg));
		aik_http_response_bytes(resp, 501, "application/json", copy,
					sizeof(msg) - 1);
		return;
	}
	mean = calloc((size_t)dim, sizeof(double));
	basis = calloc((size_t)dim * 2, sizeof(double));
	if (!mean || !basis) {
		free(mean);
		free(basis);
		free(pts);
		respond_500(resp);
		return;
	}
	pca_project(pts, n, dim, mean, basis);
	read_figure(cfg, &c.w, &c.h);
	c.rgb = malloc((size_t)c.w * (size_t)c.h * 3);
	if (!c.rgb) {
		free(mean);
		free(basis);
		free(pts);
		respond_500(resp);
		return;
	}
	memset(c.rgb, 0xff, (size_t)c.w * (size_t)c.h * 3);

	/* 缩放（坐标范围取记忆点；留 8% 边距） */
	{
		double minx = pts[0].x, maxx = pts[0].x;
		double miny = pts[0].y, maxy = pts[0].y;
		double spanx, spany;
		int margin_x = c.w / 12 + 1;
		int margin_y = c.h / 12 + 1;

		for (i = 1; i < n; i++) {
			if (pts[i].x < minx)
				minx = pts[i].x;
			if (pts[i].x > maxx)
				maxx = pts[i].x;
			if (pts[i].y < miny)
				miny = pts[i].y;
			if (pts[i].y > maxy)
				maxy = pts[i].y;
		}
		spanx = maxx - minx;
		spany = maxy - miny;
		if (spanx < 1e-12)
			spanx = 1.0;
		if (spany < 1e-12)
			spany = 1.0;

		/* 图边（记忆图）：先画，点在上层 */
		{
			aik_json *graph = NULL;

			if (aik_engine_graph(e, &graph, NULL, 0) == 0) {
				const aik_json *edges =
					aik_json_get(graph, "edges");
				size_t ne = aik_json_count(edges);

				for (i = 0; i < ne; i++) {
					const aik_json *x =
						aik_json_at(edges, i);
					const char *src = aik_json_str(
						aik_json_get(x, "source"));
					const char *dst = aik_json_str(
						aik_json_get(x, "target"));
					size_t a, b;
					int ax, ay, bx, by;

					for (a = 0; a < n; a++)
						if (src && strcmp(
						    pts[a].m->id, src) == 0)
							break;
					for (b = 0; b < n; b++)
						if (dst && strcmp(
						    pts[b].m->id, dst) == 0)
							break;
					if (a >= n || b >= n)
						continue;
					ax = margin_x + (int)((pts[a].x - minx) /
						spanx * (c.w - 2 * margin_x));
					ay = c.h - margin_y -
					     (int)((pts[a].y - miny) / spany *
						   (c.h - 2 * margin_y));
					bx = margin_x + (int)((pts[b].x - minx) /
						spanx * (c.w - 2 * margin_x));
					by = c.h - margin_y -
					     (int)((pts[b].y - miny) / spany *
						   (c.h - 2 * margin_y));
					draw_line(&c, ax, ay, bx, by, 200,
						  200, 200, 0.8);
				}
			}
			aik_json_free(graph);
		}
		for (i = 0; i < n; i++) {
			const int *col =
				PALETTE[region_color(pts[i].m->region_id)];
			int x = margin_x + (int)((pts[i].x - minx) / spanx *
						 (c.w - 2 * margin_x));
			int y = c.h - margin_y - (int)((pts[i].y - miny) /
						       spany *
						       (c.h - 2 * margin_y));

			draw_disc(&c, x, y, 2.5, col[0], col[1], col[2],
				  0.75);
		}
		/* Region 质心：黑星（用小十字近似，避免字体依赖） */
		{
			aik_json *regions = NULL;

			if (aik_engine_regions(e, &regions, NULL, 0) == 0) {
				const aik_json *arr =
					aik_json_get(regions, "regions");
				size_t nr = aik_json_count(arr);

				for (i = 0; i < nr; i++) {
					const aik_json *r = aik_json_at(arr, i);
					const aik_json *cen =
						aik_json_get(r, "centroid");
					int cd = (int)aik_json_count(cen);
					double rx, ry;
					int px, py;

					if (cd != dim)
						continue;
					{
						double *tmp =
							malloc((size_t)dim *
							       sizeof(double));
						int k;
						const aik_json *node;

						if (!tmp)
							continue;
						for (k = 0; k < dim; k++) {
							node = aik_json_at(
								cen, (size_t)k);
							tmp[k] =
								aik_json_num(node);
						}
						project_one(tmp, dim, mean,
							    basis, &rx, &ry);
						free(tmp);
					}
					px = margin_x +
					     (int)((rx - minx) / spanx *
						   (c.w - 2 * margin_x));
					py = c.h - margin_y -
					     (int)((ry - miny) / spany *
						   (c.h - 2 * margin_y));
					draw_line(&c, px - 4, py, px + 4, py,
						  0, 0, 0, 1.0);
					draw_line(&c, px, py - 4, px, py + 4,
						  0, 0, 0, 1.0);
				}
			}
			aik_json_free(regions);
		}
	}
	png = encode_png(&c, &pnglen);
	free(c.rgb);
	free(mean);
	free(basis);
	free(pts);
	if (!png) {
		respond_500(resp);
		return;
	}
	aik_http_response_bytes(resp, 200, "image/png", (char *)png, pnglen);
}

/* ------------------------------------------------------------------ */
/* 配置 UI 静态资源                                                   */
/* ------------------------------------------------------------------ */
static const char *mime_for(const char *name)
{
	const char *dot = strrchr(name, '.');

	if (!dot)
		return "application/octet-stream";
	if (strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0)
		return "text/html; charset=utf-8";
	if (strcasecmp(dot, ".css") == 0)
		return "text/css; charset=utf-8";
	if (strcasecmp(dot, ".js") == 0)
		return "text/javascript; charset=utf-8";
	if (strcasecmp(dot, ".json") == 0)
		return "application/json";
	if (strcasecmp(dot, ".png") == 0)
		return "image/png";
	if (strcasecmp(dot, ".svg") == 0)
		return "image/svg+xml";
	if (strcasecmp(dot, ".ico") == 0)
		return "image/x-icon";
	return "application/octet-stream";
}

static char *read_whole(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	char *buf = NULL;
	size_t cap = 0, n = 0;

	if (!f)
		return NULL;
	for (;;) {
		size_t got;

		if (n + 65536 > cap) {
			size_t ncap = cap ? cap * 2 : 65536;
			char *nb = realloc(buf, ncap);

			if (!nb) {
				free(buf);
				fclose(f);
				return NULL;
			}
			buf = nb;
			cap = ncap;
		}
		got = fread(buf + n, 1, cap - n, f);
		n += got;
		if (got == 0)
			break;
	}
	fclose(f);
	*len = n;
	return buf ? buf : malloc(1);
}

/* 只允许单段安全文件名；返回 0 合法 */
static int safe_name(const char *name)
{
	const char *p;

	if (!name || !*name)
		return -1;
	if (strstr(name, ".."))
		return -1;
	for (p = name; *p; p++) {
		if (*p == '/' || *p == '\\' || *p == ':' || *p == '\0')
			return -1;
	}
	return 0;
}

static void serve_file(aik_http_server *s, const char *name,
		       aik_http_response *resp)
{
	const char *dir = aik_http_server_static_dir(s);
	char path[1200];
	char *data;
	size_t len = 0;

	if (!dir || !*dir || safe_name(name) != 0) {
		respond_error(resp, 404, "Not Found");
		return;
	}
	if (snprintf(path, sizeof(path), "%s/%s", dir, name) >=
	    (int)sizeof(path)) {
		respond_error(resp, 404, "Not Found");
		return;
	}
	data = read_whole(path, &len);
	if (!data) {
		respond_error(resp, 404, "Not Found");
		return;
	}
	aik_http_response_bytes(resp, 200, mime_for(name), data, len);
}

void aik_http_route_index(aik_http_server *s, const aik_http_request *req,
			  aik_http_response *resp)
{
	(void)req;
	serve_file(s, "index.html", resp);
}

void aik_http_route_static(aik_http_server *s, const aik_http_request *req,
			   aik_http_response *resp)
{
	const char *name = req->path + 8;	/* "/static/" */

	serve_file(s, name, resp);
}
