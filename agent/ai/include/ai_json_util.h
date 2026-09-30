/*
 * ai_json_util.h - 极简 JSON 扫描工具集（Ask 工具调用协议共用）
 *
 * 为什么不引入完整 JSON 库：AIKernel Agent 保持零第三方依赖的既有风格
 * （mbedTLS 除外），而工具调用闭环只需要"定位 key / 遍历数组 / 取字符串
 * 数值"这三类操作。本模块以区间（[指针, 长度)）为中心提供只读扫描：
 *   - 不复制、不建树：调用者拿到值 token 的区间再决定怎么消费；
 *   - 正确跳过字符串内的转义与嵌套结构（括号/引号计数）；
 *   - tools.json、chat/completions 响应、模型产出的 arguments 对象
 *     三处共用，避免各写一份简易提取器漂移。
 *
 * 约定：所有 token 区间包含定界符（字符串含两侧双引号，对象含花括号，
 * 数组含方括号），便于原样回填（如 parameters schema 原样透传）。
 */
#ifndef _AI_JSON_UTIL_H
#define _AI_JSON_UTIL_H

#include <stddef.h>

/* JSON 值类型（ai_json_scan_value 的出参） */
#define AI_JSON_NONE 0
#define AI_JSON_STR  1
#define AI_JSON_NUM  2
#define AI_JSON_BOOL 3
#define AI_JSON_NULL 4
#define AI_JSON_OBJ  5
#define AI_JSON_ARR  6

/*
 * ai_json_skip_ws - 跳过空白（空格/\t/\r/\n）
 * 返回: 第一个非空白位置（可能 == end）
 */
const char *ai_json_skip_ws(const char *p, const char *end);

/*
 * ai_json_scan_value - 扫描一个完整 JSON 值
 * @pp:   输入输出，扫描起始位置（成功后推进到值结束之后）
 * @end:  扫描边界（不含）
 * @tok:  出参（可 NULL），值 token 起始（含定界符）
 * @tlen: 出参（可 NULL），值 token 长度
 * @type: 出参（可 NULL），AI_JSON_* 类型
 * 返回: 0 成功；-1 语法错误/越界
 */
int ai_json_scan_value(const char **pp, const char *end,
		       const char **tok, size_t *tlen, int *type);

/*
 * ai_json_obj_get - 在对象 token 内取顶层成员
 * @obj:     对象 token 起始（'{' 开头）
 * @obj_len: 对象 token 长度
 * @key:     成员名（不需要引号）
 * @val:     出参，值 token 起始
 * @val_len: 出参，值 token 长度
 * @type:    出参（可 NULL），AI_JSON_* 类型
 * 返回: 1 找到；0 无此 key；-1 语法错误
 */
int ai_json_obj_get(const char *obj, size_t obj_len, const char *key,
		    const char **val, size_t *val_len, int *type);

/*
 * ai_json_obj_member - 按序遍历对象成员（带成员名）
 * @obj/@obj_len: 对象 token 区间
 * @index:        成员序号（0 起，按出现顺序）
 * @key:          出参（可 NULL），成员名 token（含引号）
 * @key_len:      出参（可 NULL），成员名 token 长度
 * @val/@val_len/@type: 出参，成员值 token
 * 返回: 1 找到；0 越界（遍历结束）；-1 语法错误
 */
int ai_json_obj_member(const char *obj, size_t obj_len, int index,
		       const char **key, size_t *key_len,
		       const char **val, size_t *val_len, int *type);

/*
 * ai_json_arr_get - 在数组 token 内按下标取元素
 * @arr:     数组 token 起始（'[' 开头）
 * @arr_len: 数组 token 长度
 * @index:   下标（0 起）
 * @elem:    出参，元素 token 起始
 * @elem_len: 出参，元素 token 长度
 * @type:    出参（可 NULL），AI_JSON_* 类型
 * 返回: 1 找到；0 越界；-1 语法错误
 */
int ai_json_arr_get(const char *arr, size_t arr_len, int index,
		    const char **elem, size_t *elem_len, int *type);

/*
 * ai_json_strdup_str - 字符串值 token → 去转义的 C 字符串
 * @val: 字符串 token 起始（'"' 开头，含定界符）
 * @val_len: token 长度
 * 返回: malloc 字符串（调用者需 free）；非字符串/失败返回 NULL。
 *       \uXXXX 正确解码为 UTF-8（含基本代理对）。
 */
char *ai_json_strdup_str(const char *val, size_t val_len);

/*
 * ai_json_escape - 将 C 字符串转义为可嵌入 JSON 字符串字面量的形式
 * 处理：双引号、反斜杠、\b \f \n \r \t 与其余 <0x20 控制字符（\u00XX）；
 * >=0x80 字节（UTF-8 多字节）原样保留（与 local_chat.c json_escape 一致）。
 * 返回: malloc 转义串（调用者需 free），失败返回 NULL。
 */
char *ai_json_escape(const char *src);

/*
 * ai_json_ll - 数值 token → long long
 * 返回: 解析值；非法 token 返回 0（调用者应以类型判断先行）
 */
long long ai_json_ll(const char *val, size_t val_len);

/*
 * ai_json_utf8_floor - 把定长截断点 len 向下调整到 UTF-8 字符边界
 * @s:   缓冲区（至少 len 字节可读，s[len] 允许越界读 1 字节需调用方保证
 *       NUL 结尾或可安全访问——本实现实际只读 s[len] 之前内容即可）
 * @len: 期望截断长度
 * 返回: 调整后的安全长度（<= len），保证 s[0..返回值) 不切断多字节序列。
 *
 * 用途：procfs/exec/遥测等工具结果按定长字节截断时，避免把 3 字节汉字
 * 或 4 字节 emoji 切成半截产生非法 UTF-8（T2 实测：截断字节进请求体 →
 * 服务端 UnicodeDecodeError → 静默无回复）。对 ASCII 与已对齐输入零开销。
 */
size_t ai_json_utf8_floor(const char *s, size_t len);

/*
 * ai_json_utf8_sanitize - 深拷贝并把非法 UTF-8 字节序列替换为 U+FFFD
 * @src: NUL 结尾输入（可含任意二进制字节）
 * 返回: malloc 的合法 UTF-8 字符串（调用者需 free），失败返回 NULL。
 *
 * 规则（W3C 解码惯例的简化实现）：
 *   - 合法序列（含 4 字节增补平面，如 emoji）原样保留；
 *   - 非法首字节 / 截断序列 / overlong / 代理区 / >U+10FFFF → 单字节
 *     消费并替换为一个 U+FFFD（EF BF BD），绝不吞掉后续合法内容。
 *
 * 用途：JSON 转义前的最终防线——工具结果可能来自任意文件/命令输出，
 * 不能假设输入是合法 UTF-8；转义层保证"转义保留合法 UTF-8、清洗非法
 * 字节"，从源头杜绝请求体非法编码。
 */
char *ai_json_utf8_sanitize(const char *src);

#endif /* _AI_JSON_UTIL_H */
