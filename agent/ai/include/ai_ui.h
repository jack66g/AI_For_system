/*
 * ai_ui.h - 终端 UI 公共层接口（颜色 / 计数格式化 / 会话存储 / spinner）
 *
 * 面向 shell 层（aikernel_main REPL、cmd_ask、cmd_session、cmd_config）
 * 的公共显示与状态设施：
 *   - ANSI 颜色：统一开关判断（config [ui].color + NO_COLOR 环境变量），
 *     关闭时所有 ui_c() 返回空串，输出零污染；
 *   - token 计数人性化格式（1234 -> "1.2k"）与上下文预算百分比；
 *   - 会话持久化：~/.aikernel/sessions/<name>.jsonl，每行一条消息 JSON
 *     （role/content/tool_calls/tool 结果/时间戳），ask 闭环跨次历史；
 *   - spinner：ask 等待模型期间的 braille 转轮线程（首 token 到达即停）。
 */
#ifndef _AI_UI_H
#define _AI_UI_H

#include <stddef.h>
#include "ai_chat.h"

/* ---- ANSI 颜色 ---- */

#define UI_C_RESET  "\033[0m"
#define UI_C_CYAN   "\033[36m"
#define UI_C_DIM    "\033[2m"
#define UI_C_YELLOW "\033[33m"
#define UI_C_RED    "\033[31m"
#define UI_C_GREEN  "\033[32m"

/*
 * ui_color_enabled - 颜色总开关
 * config [ui].color 为开 且 NO_COLOR 环境变量为空时返回 1。
 * @cfg_color: 配置中的 color 开关（1/0）
 */
int ui_color_enabled(int cfg_color);

/*
 * ui_c - 取颜色转义串（颜色关闭时返回 ""，printf 安全）
 * @cfg_color: 配置中的 color 开关
 * @code:      UI_C_* 宏
 */
const char *ui_c(int cfg_color, const char *code);

/* ---- 计数格式化与预算 ---- */

/*
 * ui_fmt_tokens - token 数人性化格式（1234 -> "1.2k"，0 -> "0"）
 * @buf/len: 输出缓冲
 * @n:       token 数
 */
void ui_fmt_tokens(char *buf, size_t len, long n);

/*
 * ui_ctx_percent - 上下文预算占用百分比（0-100+，钳到 999）
 */
int ui_ctx_percent(long used, long ctx_len);

/* ---- 会话存储 ---- */

/* 会话目录与文件名的合法性上限 */
#define UI_SESSION_NAME_MAX  64

/*
 * struct ui_session_rec - 会话文件中的一条消息记录
 * 所有字符串指针在 append 调用期间只需保持有效（内部会转义写出）。
 */
struct ui_session_rec {
	const char *role;             /* "user"/"assistant"/"tool" */
	const char *content;          /* 文本内容（可 NULL） */
	const char *tool_call_id;     /* role=tool 时的调用 ID（可 NULL） */
	const char *tool_name;        /* 工具名（tool 消息附加信息，可 NULL） */
	const char *tool_calls_json;  /* assistant 原生 tool_calls JSON 数组
				       * （已渲染，可 NULL） */
	long ts;                      /* Unix 时间戳（秒） */
};

/*
 * ui_session_dir - 取会话存储目录（~/.aikernel/sessions，自动创建）
 * 返回: AI_OK 成功；目录创建失败返回 AI_ERR_STORAGE
 */
int ui_session_dir(char *buf, size_t len);

/*
 * ui_session_path - 取指定会话的 jsonl 文件路径
 * @name: 会话名（合法字符：字母数字 - _ .，防路径穿越）
 * 返回: AI_OK 成功；名字非法返回 AI_ERR_INVALID_ARG
 */
int ui_session_path(const char *name, char *buf, size_t len);

/*
 * ui_session_valid_name - 会话名合法性检查（1=合法）
 */
int ui_session_valid_name(const char *name);

/*
 * ui_session_exists - 会话文件是否存在（1=存在）
 */
int ui_session_exists(const char *name);

/*
 * ui_session_append - 向会话追加一条消息记录（写透落盘）
 * @name: 会话名；@rec: 记录
 * 返回: AI_OK 成功；AI_ERR_* 失败（调用方打印告警但不中断 ask）
 */
int ui_session_append(const char *name, const struct ui_session_rec *rec);

/*
 * ui_session_load - 从会话文件加载历史到消息数组
 * @name:   会话名
 * @msgs:   输出消息数组（调用者 free(*msgs)；其中 content 等
 *          malloc 字符串由 @strings 收集，统一释放）
 * @nmsgs:  输出条数
 * @strings:输出字符串所有权池（调用者 free 各元素与数组本身）
 * @nstr:   输出池长度
 * 返回: AI_OK 成功（文件不存在视为空历史返回 AI_OK）；
 *       AI_ERR_PARSE 单行损坏（跳过该行继续，不致命）
 */
int ui_session_load(const char *name, struct ai_chat_msg **msgs, int *nmsgs,
		    char ***strings, int *nstr);

/*
 * ui_session_list - 枚举全部会话名（按名字排序）
 * @names:  输出数组（调用者 free 各元素与数组）
 * @count:  输出数量
 * 返回: AI_OK 成功；目录不存在返回 0 个
 */
int ui_session_list(char ***names, int *count);

/*
 * ui_session_clear - 清空会话（重置为空文件；用于 compact 覆盖）
 */
int ui_session_clear(const char *name);

/*
 * ui_session_delete - 删除会话文件
 */
int ui_session_delete(const char *name);

/*
 * ui_session_count - 会话消息条数（文件不存在返回 0）
 */
int ui_session_count(const char *name);

/* ---- spinner（braille 转轮，ask 等待模型期间显示阶段文案） ---- */

/*
 * ui_spinner_start - 启动 spinner 线程
 * @stage: 阶段文案（如 "thinking..." / "calling procfs.read..."），
 *         内部会复制。重复调用只更新文案（线程已存在则复用）。
 */
void ui_spinner_start(const char *stage);

/*
 * ui_spinner_stop - 停止 spinner（清除轮转行，光标回到行首）
 * 幂等；颜色关闭时同样清除该行。
 */
void ui_spinner_stop(void);

/*
 * ui_spinner_set_stage - 更新阶段文案（线程安全，如切换到工具调用）
 */
void ui_spinner_set_stage(const char *stage);

#endif /* _AI_UI_H */
