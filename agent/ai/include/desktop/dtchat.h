/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dtchat.h - 聊天主流程(T6c):9 条正则意图表 + ACTION_ALIASES、
 * match_open_app(打开/启动 + 19 组中文别名 + _OPEN_STOP 泛指词拦截)、
 * call_llm(model.toml 现读 → forwarder/direct 双尝试,cloud/http 底座)、
 * 上下文组装(服务端持久历史优先)、[[...]] 动作抽取、demo_reply,
 * 以及 POST /api/chat 与 GET /api/chat?fallback= 两个路由。
 *
 * 对齐 desktop/server.py:181-413(parse_intents/match_open_app/
 * demo_reply/call_llm)与 2031-2150(_handle_chat)。正则语义对齐
 * Python re:中文按码点、re.I 只作用 ASCII 字母、(?<![A-Za-z0-9_]) 环视、
 * `.` 不跨 \n、`$` 容忍单个尾随 \n。
 */
#ifndef _AIK_DESKTOP_DTCHAT_H
#define _AIK_DESKTOP_DTCHAT_H

#include <stddef.h>

#include "store/store_json.h"
#include "desktop/dthttp.h"

/* ---------------- 读侧(T6b 自 desktopd.c 移入,行为不变) ---------------- */

/* read_model_conf:~/.aikernel/model.toml 的 [models.cloud] 三字段;
 * 失败 → 三个 null + 日志。api_key 只进内存,绝不落日志。 */
void dt_read_model_conf(aik_json *conf);

/* read_proc_stats:/proc/loadavg+meminfo+uptime+uname;异常分支填默认 */
aik_json *dt_read_proc_stats(void);

/* Python round(x, 1) 等价(nearbyint 半偶) */
double dt_py_round1(double x);

/* Python str.lower() 近似(ASCII tolower;中文无大小写) */
char *dt_utf8_lower(const char *s);

/* ---------------- 意图与动作 ---------------- */

/* parse_intents:9 条规则表序去重 + [:4];返回动作数组(调用者释放) */
aik_json *dt_parse_intents(const char *text);

/* match_open_app:打开/启动正则 + 别名表 + 精确名/子串;未命中 NULL */
aik_json *dt_match_open_app(const char *text, const aik_json *apps);

/* json.dumps(v, sort_keys=True) 等价规范签名(去重判等用;单射) */
char *dt_canon_sig(const aik_json *v);

/* \[\[(.+?)\]\](DOTALL 首个)抽取:标签段从 reply 就地剔除(*plen 收缩),
 * 含 action 键的候选按 canon 签名去重后 append 到 actions(保持键序)。
 * 返回 1 = 命中标签。 */
int dt_chat_extract_tag(char *reply, size_t *plen, aik_json *actions);

/* ---------------- LLM ---------------- */

/* llm_endpoint:rstrip('/') 后以 /v1 结尾 → +"/chat/completions",
 * 否则 +"/v1/chat/completions"(返回 malloc) */
char *dt_llm_endpoint(const char *base_url);

/* call_llm:无 api_key → 直接 NULL(不发起任何请求);请求体键序
 * model,messages,temperature,max_tokens,stream(ensure_ascii 转义,
 * python json.dumps 默认形态);取 choices[0].message.content。
 * 成功返回 {"text","endpoint","model"},失败 NULL。 */
aik_json *dt_call_llm(const aik_json *messages);

/* 请求体构造(单测断言 ensure_ascii 键序用) */
char *dt_llm_body_build(const char *model, const aik_json *messages);

/* ---------------- 上下文与应答 ---------------- */

/* server.py:2069-2080:system + 服务端持久历史(最近 20 条 user/assistant,
 * content 真值过滤,每条截 800 码点)优先,否则客户端 history 末 6 条,
 * 再 + 当前 message。*crash=1 → 等价未捕获异常(调用方关连接)。 */
aik_json *dt_chat_context(const char *sid, const aik_json *history,
			  const char *message, int *crash);

/* demo_reply:内置应答器(嵌 read_proc_stats 实况;VM 关 = 固定文案);
 * 返回 malloc 串。actions 可为 NULL(等价空表)。 */
char *dt_demo_reply(const char *message, const aik_json *actions,
		    long long apps_count);

/* 系统提示原文(server.py:2056-2068;单测断言 467 码点) */
const char *dt_chat_sys_prompt(void);

/* ---------------- 路由(0 正常;-1 未捕获异常等价关连接) ---------------- */

int dt_route_chat_post(struct dt_req *req, struct dt_resp *r);
int dt_route_chat_fallback(struct dt_req *req, struct dt_resp *r);

#endif /* _AIK_DESKTOP_DTCHAT_H */
