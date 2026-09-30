// SPDX-License-Identifier: GPL-2.0
/*
 * ai_json_util.c - 极简 JSON 扫描工具集实现
 *
 * 设计要点见 ai_json_util.h。核心是三个扫描原语：
 *   scan_string：处理 \" \\ \uXXXX 等转义，定位闭引号；
 *   scan_value ：递归处理嵌套对象/数组（深度上限 32，防失控输入）；
 *   obj/arr 迭代：基于上述两个原语按结构遍历。
 * 全程只读，不修改输入缓冲区。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_json_util.h"

/* 递归深度上限：工具协议 JSON 最深不过 4 层，留足余量 */
#define AI_JSON_MAX_DEPTH 32

const char *ai_json_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' ||
			   *p == '\n'))
		p++;
	return p;
}

/* 扫描字符串 token（含两侧引号）；成功返回闭引号后一位置，失败 NULL */
static const char *scan_string(const char *p, const char *end)
{
	p = ai_json_skip_ws(p, end);
	if (p >= end || *p != '"')
		return NULL;
	p++;
	while (p < end) {
		if (*p == '\\') {
			p += 2;         /* 转义对整体跳过（\uXXXX 亦然） */
			continue;
		}
		if (*p == '"')
			return p + 1;
		p++;
	}
	return NULL;
}

/* 带 depth 守卫的内部递归实现（防失控输入的嵌套深度） */
static int scan_value_depth(const char **pp, const char *end,
			    const char **tok, size_t *tlen, int *type,
			    int depth);

int ai_json_scan_value(const char **pp, const char *end,
		       const char **tok, size_t *tlen, int *type)
{
	return scan_value_depth(pp, end, tok, tlen, type, 0);
}

/* 带 depth 守卫的内部递归实现（防失控输入的嵌套深度） */
static int scan_value_depth(const char **pp, const char *end,
			    const char **tok, size_t *tlen, int *type,
			    int depth)
{
	const char *p;
	const char *start;
	int t = AI_JSON_NONE;

	if (depth > AI_JSON_MAX_DEPTH)
		return -1;

	p = ai_json_skip_ws(*pp, end);
	if (p >= end)
		return -1;
	start = p;

	switch (*p) {
	case '"': {
		const char *e = scan_string(p, end);

		if (!e)
			return -1;
		p = e;
		t = AI_JSON_STR;
		break;
	}
	case '{':
	case '[': {
		char close = (*p == '{') ? '}' : ']';

		t = (*p == '{') ? AI_JSON_OBJ : AI_JSON_ARR;
		p++;
		p = ai_json_skip_ws(p, end);
		if (p < end && *p == close) {
			p++;            /* 空对象/空数组 */
			break;
		}
		for (;;) {
			/* 对象成员：先 key 字符串；数组元素：直接值 */
			if (close == '}') {
				p = scan_string(p, end);
				if (!p)
					return -1;
				p = ai_json_skip_ws(p, end);
				if (p >= end || *p != ':')
					return -1;
				p++;
			}
			if (scan_value_depth(&p, end, NULL, NULL,
					     NULL, depth + 1) != 0)
				return -1;
			p = ai_json_skip_ws(p, end);
			if (p < end && *p == ',') {
				p++;
				continue;
			}
			if (p < end && *p == close) {
				p++;
				break;
			}
			return -1;
		}
		break;
	}
	case 't':   /* true */
	case 'f':   /* false */
		if (end - p >= 5 && strncmp(p, "true", 4) == 0) {
			p += 4;
			t = AI_JSON_BOOL;
		} else if (end - p >= 5 && strncmp(p, "false", 5) == 0) {
			p += 5;
			t = AI_JSON_BOOL;
		} else {
			return -1;
		}
		break;
	case 'n':   /* null */
		if (end - p >= 4 && strncmp(p, "null", 4) == 0) {
			p += 4;
			t = AI_JSON_NULL;
		} else {
			return -1;
		}
		break;
	default:    /* 数字（含负号） */
		if (*p == '-' || *p == '+' || (*p >= '0' && *p <= '9')) {
			t = AI_JSON_NUM;
			p++;
			while (p < end && ((*p >= '0' && *p <= '9') ||
					   *p == '.' || *p == 'e' || *p == 'E' ||
					   *p == '-' || *p == '+'))
				p++;
		} else {
			return -1;
		}
		break;
	}

	if (tok)
		*tok = start;
	if (tlen)
		*tlen = (size_t)(p - start);
	if (type)
		*type = t;
	*pp = p;
	return 0;
}

/*
 * 结构迭代公共体：定位第 index 个成员/元素。
 * close=='}' 时按 "key:value" 对迭代并匹配 key；close==']' 时按元素计数。
 */
static int iterate_container(const char *obj, size_t obj_len, char close,
			     int index, const char *key,
			     const char **out, size_t *out_len, int *out_type)
{
	const char *p = obj;
	const char *end = obj + obj_len;

	if (obj_len == 0 || *p != (close == '}' ? '{' : '['))
		return -1;
	p++;

	p = ai_json_skip_ws(p, end);
	if (p < end && *p == close)
		return 0;               /* 空容器 */

	for (;;) {
		const char *ktok = NULL;
		size_t ktlen = 0;
		const char *vtok;
		size_t vtlen;
		int vtype;

		if (close == '}') {
			/* 取 key 字符串 token（含两侧引号） */
			const char *e = scan_string(p, end);

			if (!e)
				return -1;
			ktok = ai_json_skip_ws(p, end);
			ktlen = (size_t)(e - ktok);   /* 含两侧引号 */
			p = e;
			p = ai_json_skip_ws(p, end);
			if (p >= end || *p != ':')
				return -1;
			p++;
		}

		if (ai_json_scan_value(&p, end, &vtok, &vtlen, &vtype) != 0)
			return -1;

		if (close == '}') {
			/* key 匹配（key token 含引号，做原样前缀比较） */
			size_t klen = strlen(key);
			int hit;

			/* key token 形如 "name"：比较去引号内容 */
			hit = (ktlen == klen + 2) &&
			      ktok[0] == '"' &&
			      ktok[ktlen - 1] == '"' &&
			      memcmp(ktok + 1, key, klen) == 0;
			if (hit) {
				if (out)
					*out = vtok;
				if (out_len)
					*out_len = vtlen;
				if (out_type)
					*out_type = vtype;
				return 1;
			}
		} else {
			if (index == 0) {
				if (out)
					*out = vtok;
				if (out_len)
					*out_len = vtlen;
				if (out_type)
					*out_type = vtype;
				return 1;
			}
			index--;
		}

		p = ai_json_skip_ws(p, end);
		if (p < end && *p == ',') {
			p++;
			continue;
		}
		if (p < end && *p == close)
			return 0;
		return -1;
	}
}

int ai_json_obj_get(const char *obj, size_t obj_len, const char *key,
		    const char **val, size_t *val_len, int *type)
{
	if (!obj || !key)
		return -1;
	return iterate_container(obj, obj_len, '}', 0, key, val, val_len, type);
}

int ai_json_obj_member(const char *obj, size_t obj_len, int index,
		       const char **key, size_t *key_len,
		       const char **val, size_t *val_len, int *type)
{
	const char *p = obj;
	const char *end = obj + obj_len;
	int idx = 0;

	if (!obj || obj_len == 0 || index < 0)
		return -1;
	if (*p != '{')
		return -1;
	p++;

	p = ai_json_skip_ws(p, end);
	if (p < end && *p == '}')
		return 0;               /* 空对象 */

	for (;;) {
		const char *ktok;
		size_t ktlen;
		const char *vtok;
		size_t vtlen;
		int vtype;

		{
			const char *e = scan_string(p, end);

			if (!e)
				return -1;
			ktok = ai_json_skip_ws(p, end);
			ktlen = (size_t)(e - ktok);   /* 含两侧引号 */
			p = e;
			p = ai_json_skip_ws(p, end);
			if (p >= end || *p != ':')
				return -1;
			p++;
		}

		if (ai_json_scan_value(&p, end, &vtok, &vtlen, &vtype) != 0)
			return -1;

		if (idx == index) {
			if (key)
				*key = ktok;
			if (key_len)
				*key_len = ktlen;
			if (val)
				*val = vtok;
			if (val_len)
				*val_len = vtlen;
			if (type)
				*type = vtype;
			return 1;
		}
		idx++;

		p = ai_json_skip_ws(p, end);
		if (p < end && *p == ',') {
			p++;
			continue;
		}
		if (p < end && *p == '}')
			return 0;
		return -1;
	}
}

int ai_json_arr_get(const char *arr, size_t arr_len, int index,
		    const char **elem, size_t *elem_len, int *type)
{
	if (!arr || index < 0)
		return -1;
	return iterate_container(arr, arr_len, ']', index, NULL,
				 elem, elem_len, type);
}

char *ai_json_strdup_str(const char *val, size_t val_len)
{
	const char *p;
	const char *end;
	char *out;
	char *d;

	if (!val || val_len < 2 || val[0] != '"' || val[val_len - 1] != '"')
		return NULL;

	/* 去引号后上界：全部为单字节转义时最多 1:1 */
	out = malloc(val_len);
	if (!out)
		return NULL;
	d = out;

	p = val + 1;
	end = val + val_len - 1;
	while (p < end) {
		if (*p != '\\') {
			*d++ = *p++;
			continue;
		}
		p++;
		if (p >= end)
			break;
		switch (*p) {
		case '"':  *d++ = '"';  p++; break;
		case '\\': *d++ = '\\'; p++; break;
		case '/':  *d++ = '/';  p++; break;
		case 'b':  *d++ = '\b'; p++; break;
		case 'f':  *d++ = '\f'; p++; break;
		case 'n':  *d++ = '\n'; p++; break;
		case 'r':  *d++ = '\r'; p++; break;
		case 't':  *d++ = '\t'; p++; break;
		case 'u': {
			unsigned int cp = 0;
			int i;

			p++;
			for (i = 0; i < 4 && p < end; i++, p++) {
				char c = *p;
				unsigned int v;

				if (c >= '0' && c <= '9')
					v = (unsigned int)(c - '0');
				else if (c >= 'a' && c <= 'f')
					v = (unsigned int)(c - 'a' + 10);
				else if (c >= 'A' && c <= 'F')
					v = (unsigned int)(c - 'A' + 10);
				else
					goto fail;
				cp = cp * 16 + v;
			}
			/* 代理对：高代理后接 \uDC00-\uDFFF 合成为码点 */
			if (cp >= 0xD800 && cp <= 0xDBFF &&
			    end - p >= 6 && p[0] == '\\' && p[1] == 'u') {
				unsigned int lo = 0;
				int ok = 1;

				for (i = 0; i < 4; i++) {
					char c = p[2 + i];
					unsigned int v;

					if (c >= '0' && c <= '9')
						v = (unsigned int)(c - '0');
					else if (c >= 'a' && c <= 'f')
						v = (unsigned int)(c - 'a' + 10);
					else if (c >= 'A' && c <= 'F')
						v = (unsigned int)(c - 'A' + 10);
					else { ok = 0; break; }
					lo = lo * 16 + v;
				}
				if (ok && lo >= 0xDC00 && lo <= 0xDFFF) {
					cp = 0x10000 +
					     ((cp - 0xD800) << 10) +
					     (lo - 0xDC00);
					p += 6;
				}
			}
			/* 码点 → UTF-8 */
			if (cp < 0x80) {
				*d++ = (char)cp;
			} else if (cp < 0x800) {
				*d++ = (char)(0xC0 | (cp >> 6));
				*d++ = (char)(0x80 | (cp & 0x3F));
			} else if (cp < 0x10000) {
				*d++ = (char)(0xE0 | (cp >> 12));
				*d++ = (char)(0x80 | ((cp >> 6) & 0x3F));
				*d++ = (char)(0x80 | (cp & 0x3F));
			} else {
				*d++ = (char)(0xF0 | (cp >> 18));
				*d++ = (char)(0x80 | ((cp >> 12) & 0x3F));
				*d++ = (char)(0x80 | ((cp >> 6) & 0x3F));
				*d++ = (char)(0x80 | (cp & 0x3F));
			}
			break;
		}
		default:
			*d++ = *p++;
			break;
		}
	}
	*d = '\0';
	return out;

fail:
	free(out);
	return NULL;
}

long long ai_json_ll(const char *val, size_t val_len)
{
	char buf[32];
	long long v;

	if (!val || val_len == 0 || val_len >= sizeof(buf))
		return 0;
	memcpy(buf, val, val_len);
	buf[val_len] = '\0';
	v = strtoll(buf, NULL, 10);
	return v;
}

/*
 * UTF-8 卫生（T2 问题 1 根因修复）：
 * 工具结果按定长字节截断（TOOL_EXEC_OUT_MAX 等）可能把多字节字符切成
 * 半截；exec.run cat 二进制/异编码文件更会引入任意非法字节。这些字节
 * 原样进 JSON 请求体 → 服务端 UnicodeDecodeError 拒收 → agent 静默无
 * 最终回复。两道防线：
 *   1. ai_json_utf8_floor：所有定长截断点用，截断不落在序列中间；
 *   2. ai_json_utf8_sanitize：ai_json_escape 出口统一清洗，无论上游
 *      来源如何，转义输出必为合法 UTF-8。
 */

/* 首字节 → 序列总长；非法首字节返回 0 */
static size_t utf8_seq_len(unsigned char c)
{
	if (c < 0x80)
		return 1;
	if ((c & 0xE0) == 0xC0)
		return 2;
	if ((c & 0xF0) == 0xE0)
		return 3;
	if ((c & 0xF8) == 0xF0)
		return 4;
	return 0;
}

size_t ai_json_utf8_floor(const char *s, size_t len)
{
	size_t i = len;
	size_t limit = len >= 3 ? len - 3 : 0;

	/* s[len] 若是 continuation 字节（10xxxxxx）说明切在字符中间，
	 * 向前回退到该字符首字节；UTF-8 最长 4 字节，最多回退 3 步 */
	while (i > limit &&
	       ((unsigned char)s[i] & 0xC0) == 0x80)
		i--;
	return i;
}

char *ai_json_utf8_sanitize(const char *src)
{
	const unsigned char *s = (const unsigned char *)src;
	size_t cap;
	char *out;
	char *d;

	if (!src)
		return NULL;

	/* 上界：每字节替换为一个 3 字节 U+FFFD */
	cap = strlen(src) * 3 + 4;
	out = malloc(cap);
	if (!out)
		return NULL;
	d = out;

	while (*s) {
		size_t n = utf8_seq_len(*s);
		unsigned int cp = 0;
		int valid = 1;
		size_t k;
		size_t need;

		if (n == 0) {
			/* 非法首字节 */
			valid = 0;
		} else {
			for (k = 1; k < n; k++) {
				if ((s[k] & 0xC0) != 0x80) {
					valid = 0;      /* continuation 缺失/截断 */
					break;
				}
			}
			if (valid) {
				switch (n) {
				case 2:
					cp = (unsigned int)(s[0] & 0x1F) << 6 |
					     (unsigned int)(s[1] & 0x3F);
					if (cp < 0x80)
						valid = 0;      /* overlong */
					break;
				case 3:
					cp = (unsigned int)(s[0] & 0x0F) << 12 |
					     (unsigned int)(s[1] & 0x3F) << 6 |
					     (unsigned int)(s[2] & 0x3F);
					if (cp < 0x800)
						valid = 0;      /* overlong */
					else if (cp >= 0xD800 && cp <= 0xDFFF)
						valid = 0;      /* 代理区 */
					break;
				case 4:
					cp = (unsigned int)(s[0] & 0x07) << 18 |
					     (unsigned int)(s[1] & 0x3F) << 12 |
					     (unsigned int)(s[2] & 0x3F) << 6 |
					     (unsigned int)(s[3] & 0x3F);
					if (cp < 0x10000 || cp > 0x10FFFF)
						valid = 0;      /* overlong/超界 */
					break;
				}
			}
		}

		need = valid ? n : 3;
		/* 写前容量防线：上界估算在合法/非法混合场景可能贴边
		 * （真实 core 证据：大消息内容 + mmap 块页尾 → d 抵达
		 * 块尾跨页写 SIGSEGV），不足即扩容，替换语义不变 */
		if ((size_t)(d - out) + need + 1 > cap) {
			size_t used = (size_t)(d - out);
			char *nb = realloc(out, cap * 2 + 16);

			if (!nb) {
				free(out);
				return NULL;
			}
			out = nb;
			d = nb + used;
			cap = cap * 2 + 16;
		}

		if (valid) {
			memcpy(d, s, n);
			d += n;
			s += n;
		} else {
			/* U+FFFD（EF BF BD），只消费 1 字节保守前进 */
			*d++ = (char)0xEF;
			*d++ = (char)0xBF;
			*d++ = (char)0xBD;
			s++;
		}
	}
	*d = '\0';
	return out;
}

char *ai_json_escape(const char *src)
{
	size_t cap;
	char *out;
	char *d;
	const unsigned char *s;
	char *clean;

	/* 出口防线：先清洗非法 UTF-8（T2 问题 1），再转义 */
	clean = ai_json_utf8_sanitize(src);
	if (!clean)
		return NULL;
	src = clean;

	cap = strlen(src) * 6 + 1;
	out = malloc(cap);
	if (!out) {
		free(clean);
		return NULL;
	}

	d = out;
	for (s = (const unsigned char *)src; *s; s++) {
		switch (*s) {
		case '"':  *d++ = '\\'; *d++ = '"';  break;
		case '\\': *d++ = '\\'; *d++ = '\\'; break;
		case '\b': *d++ = '\\'; *d++ = 'b';  break;
		case '\f': *d++ = '\\'; *d++ = 'f';  break;
		case '\n': *d++ = '\\'; *d++ = 'n';  break;
		case '\r': *d++ = '\\'; *d++ = 'r';  break;
		case '\t': *d++ = '\\'; *d++ = 't';  break;
		default:
			if (*s < 0x20) {
				snprintf(d, 7, "\\u%04x", *s);
				d += 6;
			} else {
				*d++ = (char)*s;
			}
			break;
		}
	}
	*d = '\0';
	free(clean);
	return out;
}
