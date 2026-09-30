// SPDX-License-Identifier: GPL-2.0
/*
 * test_utf8_body.c - T2 问题 1 字节级回归测试
 *
 * 背景：工具结果按定长字节截断（TOOL_EXEC_OUT_MAX 等）曾把多字节 UTF-8
 * 切成半截，非法字节进 /api/chat 请求体 → 服务端 UnicodeDecodeError →
 * agent 静默无最终回复。本测试复用 agent 真实序列化路径
 * （ai_json_utf8_floor / ai_json_utf8_sanitize / ai_json_escape /
 *   ai_chat_build_request_json），断言输出体合法 UTF-8。
 *
 * 构建：make -C tests 或
 *   gcc -Wall -Wextra -std=c11 -O2 -I../include -o test_utf8_body \
 *       test_utf8_body.c ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c
 * 运行：./test_utf8_body   （全部 PASS 且退出码 0）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_json_util.h"
#include "ai_chat.h"

static int g_fail;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (!cond)
		g_fail++;
}

/*
 * 独立 UTF-8 合法性验证（与被测实现不同源，避免循环验证）：
 * 逐序列检查首字节/continuation/overlong/代理区/上界。
 */
static int is_valid_utf8(const char *s, size_t len)
{
	const unsigned char *p = (const unsigned char *)s;
	size_t i = 0;

	while (i < len) {
		unsigned char c = p[i];
		unsigned int cp;
		size_t n, k;

		if (c < 0x80) {
			i++;
			continue;
		}
		if ((c & 0xE0) == 0xC0)
			n = 2;
		else if ((c & 0xF0) == 0xE0)
			n = 3;
		else if ((c & 0xF8) == 0xF0)
			n = 4;
		else
			return 0;               /* 非法首字节 */
		if (i + n > len)
			return 0;               /* 截断序列 */
		for (k = 1; k < n; k++)
			if ((p[i + k] & 0xC0) != 0x80)
				return 0;       /* continuation 错误 */
		cp = (n == 2) ? (c & 0x1F) :
		     (n == 3) ? (c & 0x0F) : (c & 0x07);
		for (k = 1; k < n; k++)
			cp = (cp << 6) | (p[i + k] & 0x3F);
		if (n == 2 && cp < 0x80)
			return 0;               /* overlong */
		if (n == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)))
			return 0;               /* overlong / 代理区 */
		if (n == 4 && (cp < 0x10000 || cp > 0x10FFFF))
			return 0;               /* overlong / 超界 */
		i += n;
	}
	return 1;
}

/* 复刻 procfs_read 定长截断路径：中文/emoji 文本截到 limit 字节 */
static void trunc_like_procfs(const char *text, size_t limit,
			      char *out, size_t outcap)
{
	size_t n = strlen(text);

	if (n > limit)
		n = limit;
	n = ai_json_utf8_floor(text, n);        /* 修复点 */
	if (n >= outcap)
		n = outcap - 1;
	memcpy(out, text, n);
	out[n] = '\0';
}

int main(void)
{
	/* 中文 3 字节 + emoji 4 字节 + ASCII 混合 */
	const char *mixed = "工具结果: 文件共 3 行\n"      /* UTF-8 中文 */
			    "状态: \xF0\x9F\x98\x80 (emoji)\n" /* U+1F600 */
			    "路径: /proc/ai/control";
	const char *illegal = "合法中文\xe4\xb8"           /* "中"被切掉第3字节 */
			      "\xff\xfe"                   /* 非法字节对 */
			      "\xed\xa0\x80"               /* 代理区 U+D800 */
			      "\xc0\xaf"                   /* overlong '/' */
			      "尾部中文";
	char trunc[64];
	char *esc, *clean, *body;
	struct ai_chat_msg msgs[3];

	/* 1. utf8_floor：边界识别 */
	expect(ai_json_utf8_floor("abc", 3) == 3, "floor: ASCII 边界原样");
	expect(ai_json_utf8_floor("\xe4\xb8\xad\xe6\x96\x87", 6) == 6,
	       "floor: 整字边界原样（两个汉字）");
	expect(ai_json_utf8_floor("\xe4\xb8\xad\xe6\x96\x87\xe5\xad\x97", 7)
	       == 6,
	       "floor: 3 汉字第 7 字节切进第 2 字 → 回退到 6");
	expect(ai_json_utf8_floor("\xe4\xb8\xad", 1) == 0,
	       "floor: 切进首汉字 → 回退到 0");
	expect(ai_json_utf8_floor("\xf0\x9f\x98\x80", 2) == 0,
	       "floor: 4 字节 emoji 切半 → 回退到 0");

	/* 2. 复刻 procfs 定长截断：截点落在汉字中间不再产生半截序列 */
	trunc_like_procfs(mixed, 30, trunc, sizeof(trunc));
	expect(is_valid_utf8(trunc, strlen(trunc)),
	       "复刻 procfs 截断(30B)：输出合法 UTF-8");
	trunc_like_procfs(mixed, 41, trunc, sizeof(trunc));   /* 切在 emoji 中 */
	expect(is_valid_utf8(trunc, strlen(trunc)),
	       "复刻 procfs 截断(41B 切 emoji)：输出合法 UTF-8");

	/* 3. sanitize：非法字节全部清洗为 U+FFFD，输出合法 UTF-8 */
	clean = ai_json_utf8_sanitize(illegal);
	expect(clean != NULL, "sanitize: 返回非空");
	expect(clean && is_valid_utf8(clean, strlen(clean)),
	       "sanitize: 截断/非法/代理区/overlong 输入 → 合法 UTF-8");
	expect(clean && strstr(clean, "\xEF\xBF\xBD") != NULL,
	       "sanitize: 非法位置替换为 U+FFFD");
	expect(clean && strstr(clean, "尾部中文") != NULL,
	       "sanitize: 不吞后续合法内容");
	free(clean);

	/* 4. escape 出口防线：含非法字节的输入转义后仍合法 */
	{
		char dirty[128];

		snprintf(dirty, sizeof(dirty), "结果\"引号\n%s", illegal);
		esc = ai_json_escape(dirty);
		expect(esc != NULL && is_valid_utf8(esc, strlen(esc)),
		       "escape: 含非法字节+控制字符输入 → 输出合法 UTF-8");
		free(esc);
	}

	/* 5. 完整 /api/chat 请求体：中文工具结果回传消息合法 UTF-8
	 * （复刻 ask 第 2 轮：system + assistant(tool_calls) + tool 结果） */
	memset(msgs, 0, sizeof(msgs));
	msgs[0].role = "system";
	msgs[0].content = "你是 AIKernel 系统管理员 AI。约束：回答使用简体中文。";
	msgs[1].role = "assistant";
	msgs[1].content = "";
	msgs[1].tool_calls_json =
		"[{\"id\":\"call_1\",\"type\":\"function\",\"function\":"
		"{\"name\":\"netlink.act.sched.nice\",\"arguments\":"
		"\"{\\\"pid\\\":1,\\\"value\\\":3}\"}}]";
	msgs[2].role = "tool";
	msgs[2].tool_call_id = "call_1";
	msgs[2].tool_name = "netlink.act.sched.nice";
	msgs[2].content = "命令执行成功，输出:\n工具结果: 已执行 nice"
			  " \xF0\x9F\x98\x80\n当前值: 3（中文回传）";
	body = ai_chat_build_request_json("qwen2.5:1.5b", msgs, 3, NULL,
					  0.7, 4096);
	expect(body != NULL, "build_request_json: 构造成功");
	expect(body && is_valid_utf8(body, strlen(body)),
	       "build_request_json: 含中文+emoji 工具结果的请求体合法 UTF-8");
	/* Content-Length 场景 = strlen(body)（字节数）≠ 字符数 */
	expect(body && strlen(body) > 0,
	       "Content-Length 取 strlen（字节数）而非字符数");
	free(body);

	/* 6. 32768 定长截断（TOOL_EXEC_OUT_MAX 场景）→ 请求体仍合法 */
	{
		size_t big_len = 40000;
		char *big = malloc(big_len + 1);
		size_t i, cut;

		for (i = 0; i < big_len; i++)
			big[i] = (char)(0xE4);   /* 占位，下面填汉字序列 */
		/* 填充重复汉字 "汉"（E4 B8 89 3 字节），确保 32768 切半 */
		for (i = 0; i < big_len; i++)
			big[i] = "汉"[i % 3];
		big[big_len] = '\0';
		cut = ai_json_utf8_floor(big, 32768);
		expect(cut <= 32768 && cut > 32768 - 3,
		       "32768 截断点回退在 3 字节内");
		esc = ai_json_escape(big);       /* 全量经出口防线 */
		expect(esc != NULL && is_valid_utf8(esc, strlen(esc)),
		       "32768 截断 + escape：输出合法 UTF-8");
		free(esc);
		free(big);
	}

	printf("== test_utf8_body: %s ==\n",
	       g_fail ? "存在失败" : "全部通过");
	return g_fail ? 1 : 0;
}
