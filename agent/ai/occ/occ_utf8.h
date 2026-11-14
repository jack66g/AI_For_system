/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_utf8.h - UTF-8 校验/净化共用件（ORCH-E10 虫②两层防线共享实现）
 *
 * header-only static inline：occ_tools（bash 工具结果源端净化）与
 * occ_llm（请求体出口兜底）两面零链接面变化共享同一实现。
 *
 * 判定口径（严格）：ASCII 与 2-4 字节合法序列；拒绝裸续字节、
 * overlong（C0/C1 起字节与 E0/F0 界限下越）、U+D800-DFFF 代理区
 * 与 >U+10FFFF（ED/F4 界限上越）。
 * 合法输入逐字节原样透传（差分 62/62 红线：合法请求字节零变化）。
 * 净化=每个非法序列的最大子部替换一枚 U+FFFD（EF BF BD——Unicode
 * 推荐口径：截断/续位中断/界限违例的整个最大子部合并为一枚，被中
 * 断处的下一字节重新独立判读）。
 */
#ifndef _OCC_UTF8_H
#define _OCC_UTF8_H

#include <stddef.h>

/*
 * occ_utf8_valid - 全串预检：合法 UTF-8 返回 1。
 * 合法输入走调用方免拷贝快路（语义与性能双保险）。
 */
static inline int occ_utf8_valid(const char *src, size_t n)
{
	size_t i = 0;

	if (!src)
		return 0;
	while (i < n) {
		unsigned char c = (unsigned char)src[i];
		size_t need, k;

		if (c < 0x80) {
			i++;
			continue;
		}
		if (c >= 0xC2 && c <= 0xDF)
			need = 2;
		else if (c >= 0xE0 && c <= 0xEF)
			need = 3;
		else if (c >= 0xF0 && c <= 0xF4)
			need = 4;
		else
			return 0;	/* 裸续字节/overlong 起字节 */
		if (i + need > n)
			return 0;	/* 尾部截断 */
		for (k = 1; k < need; k++) {
			unsigned char cc = (unsigned char)src[i + k];

			if ((cc & 0xC0) != 0x80)
				return 0;
			/* E0/ED/F0/F4 界限：overlong、代理区、
			 * >U+10FFFF 各自的非法次字节 */
			if ((c == 0xE0 && k == 1 && cc < 0xA0) ||
			    (c == 0xED && k == 1 && cc > 0x9F) ||
			    (c == 0xF0 && k == 1 && cc < 0x90) ||
			    (c == 0xF4 && k == 1 && cc > 0x8F))
				return 0;
		}
		i += need;
	}
	return 1;
}

/*
 * occ_utf8_sanitize - 净化拷贝：src 的 n 字节 → dst（dstcap 含结尾
 * NUL 位）。合法序列逐字节透传；每个非法序列的最大子部替换一枚
 * U+FFFD（口径见头注）。返回写入字节数（不含结尾 NUL）；dst 恒
 * NUL 收尾。缓冲不足时停在完整字符边界（绝不写半个多字节字符）。
 * 入参非法返回 0。
 */
static inline size_t occ_utf8_sanitize(const char *src, size_t n,
				       char *dst, size_t dstcap)
{
	static const char rep[3] = { (char)0xEF, (char)0xBF, (char)0xBD };
	size_t i = 0, w = 0;

	if (!src || !dst || dstcap == 0)
		return 0;
	while (i < n) {
		unsigned char c = (unsigned char)src[i];
		size_t need = 0, k, sub;

		if (c < 0x80)
			need = 1;
		else if (c >= 0xC2 && c <= 0xDF)
			need = 2;
		else if (c >= 0xE0 && c <= 0xEF)
			need = 3;
		else if (c >= 0xF0 && c <= 0xF4)
			need = 4;
		if (need == 1) {			/* ASCII 透传 */
			if (w + 1 > dstcap - 1)
				break;
			dst[w++] = src[i];
			i++;
			continue;
		}
		if (need == 0) {
			/* 裸续字节/overlong 起字节：单字节最大子部 */
			if (w + 3 > dstcap - 1)
				break;
			dst[w++] = rep[0];
			dst[w++] = rep[1];
			dst[w++] = rep[2];
			i++;
			continue;
		}
		/* 多字节序列：先收集续位完好的最大子部（sub 字节） */
		sub = 1;
		while (sub < need && i + sub < n &&
		       ((unsigned char)src[i + sub] & 0xC0) == 0x80)
			sub++;
		if (sub == need) {
			unsigned char c1 = (unsigned char)src[i + 1];
			int ill = (c == 0xE0 && c1 < 0xA0) ||
				  (c == 0xED && c1 > 0x9F) ||
				  (c == 0xF0 && c1 < 0x90) ||
				  (c == 0xF4 && c1 > 0x8F);

			if (!ill) {		/* 合法序列：原样透传 */
				if (w + need > dstcap - 1)
					break;
				for (k = 0; k < need; k++)
					dst[w++] = src[i + k];
				i += need;
				continue;
			}
			/* 界限违例（overlong/代理/超界）：全序列为
			 * 最大子部——sub 已=need，统一走下方一枚 FFFD */
		}
		/* 截断（尾部续位不足）或续位中断或界限违例：
		 * 最大子部（lead+已收续位）合并替换一枚 U+FFFD；
		 * 中断处的下一字节回到循环头独立判读 */
		if (w + 3 > dstcap - 1)
			break;
		dst[w++] = rep[0];
		dst[w++] = rep[1];
		dst[w++] = rep[2];
		i += sub;
	}
	dst[w] = '\0';
	return w;
}

#endif /* _OCC_UTF8_H */
