/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acconfig.h - autocondense 配置模型 / 校验 / 深合并 / 加载保存 / 通用文件工具
 *
 * T5b 逐语义复刻 ref-autocondense/config.py（308 行）：
 *   - Config / SMEConfig 默认值与 asdict 键序（to_dict）；
 *   - validate_config_dict：未知键拒绝 + 类型检查（bool 不是 int！），
 *     中文错误文案逐字（config.py:190-230）；
 *   - deep_merge：override 优先，嵌套 dict 递归；
 *   - load_config：缺失给默认 / 损坏 quarantine 后回落默认 / 深合并 +
 *     加载期 sanitize（未知或类型不符键丢弃）；
 *   - save_config：json.dumps(to_dict, indent=2) + "\n" 原子写。
 *
 * 另提供注入时钟（冻结 epoch，测试与服务重放共用）与 Python
 * json.dumps 两种分隔形态的序列化（indent=2 / 默认 ", " ": "）。
 *
 * 本模块依赖 store/store_json.h（JSON DOM），零第三方依赖，C11。
 */
#ifndef _AIK_AUTOCONDENSE_ACCONFIG_H
#define _AIK_AUTOCONDENSE_ACCONFIG_H

#include "store/store_json.h"

#include <stddef.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* 注入时钟（T5-DESIGN §5：冻结时钟 epoch=1775000000，TZ=Asia/Shanghai） */
/* ------------------------------------------------------------------ */

/*
 * ac_time_set_now - 冻结时钟为给定 epoch 秒（小数部分为毫秒）
 *
 * 之后 ac_now()/ac_now_exact() 一直返回该值，直到 ac_time_unset_now()。
 * 非线程安全（测试与单写者服务内约定串行设置）。
 */
void ac_time_set_now(double epoch_seconds);
void ac_time_unset_now(void);

/* 当前 epoch 秒（冻结或系统时钟），错误返回 (time_t)-1 */
time_t ac_now(void);

/* 当前时间带毫秒（sec 整秒，msec 0-999）*/
void ac_now_exact(long long *sec, int *msec);

/* 本地时间 ISO 文本（datetime.now().isoformat(timespec="seconds") 等价）：
 * "YYYY-MM-DDTHH:MM:SS"（含 NUL 恰 20 字节，建议缓冲 32）*/
int ac_iso_now(char *buf, size_t buflen);

/* 毫秒版（timespec="milliseconds"）："YYYY-MM-DDTHH:MM:SS.mmm"（建议 32）*/
int ac_iso_ms_now(char *buf, size_t buflen);

/* 快照文件名时间戳：strftime("%Y%m%d-%H%M%S")（建议 32）*/
int ac_stamp_now(char *buf, size_t buflen);

/* epoch → 本地 ISO 秒文本（建议 32）*/
int ac_iso_epoch(time_t t, char *buf, size_t buflen);

/*
 * ac_parse_iso - 解析 "YYYY-MM-DDTHH:MM:SS[.fff]"（'T' 或 ' ' 分隔）
 *
 * datetime.fromisoformat 子集（向量只用秒精度、无时区）。成功返回 0。
 */
int ac_parse_iso(const char *s, time_t *out);

/* ------------------------------------------------------------------ */
/* 配置模型                                                            */
/* ------------------------------------------------------------------ */

/* float 字段被赋过整数值时保留整数形态（Python setattr 原样保存，
 * to_dict 经 asdict 原样序列化：json.dumps(1) → "1" 而非 "1.0"）*/
typedef struct {
	int enabled;
	char *base_url;		/* 堆串，缺省 "http://127.0.0.1:8000" */
	double timeout_s;
	int timeout_s_is_int;
	long long timeout_s_int;
	char **tags;		/* 堆串数组 */
	size_t n_tags;
	double importance;
	int importance_is_int;
	long long importance_int;
	int split_segments;
	long long max_segments;
	int dedup;
	double dedup_threshold;
	int dedup_threshold_is_int;
	long long dedup_threshold_int;
} ac_sme_config;

typedef struct {
	int port;
	char *host;		/* 缺省 "127.0.0.1" */
	int enabled;
	int cooldown_minutes;
	int turns_threshold;
	double water_threshold;
	int water_threshold_is_int;
	long long water_threshold_int;
	long long usable_context_tokens;
	long long task_min_rounds;
	long long judge_defer_turns;
	long long judge_defer_max_turns;
	long long restore_max_chars;
	long long restore_top_n;
	long long restore_reread_files;
	int delta_mode;
	long long delta_merge_every;
	long long idle_signal_rounds;
	ac_sme_config sme;
} ac_config;

/* 内置默认值（不含环境变量；结构可为全零，函数内部分配成员）*/
void ac_sme_config_default(ac_sme_config *c);
void ac_config_default(ac_config *c);

/* AUTOCONDENSE_PORT 环境变量覆盖（default_config_dict(use_env=True)）*/
void ac_config_default_env(ac_config *c);

/* 释放成员（不释放结构本身）；零化结构可重复初始化 */
void ac_sme_config_cleanup(ac_sme_config *c);
void ac_config_cleanup(ac_config *c);

/* to_dict：asdict 键序（Config 16 键 + sme 9 键），失败返回 NULL */
aik_json *ac_sme_config_to_dict(const ac_sme_config *c);
aik_json *ac_config_to_dict(const ac_config *c);

/*
 * apply_dict：就地深应用（sme 为对象时递归合并而非整体替换）。
 * 仅认已知键，未知键忽略（调用方应先 validate/sanitize）；
 * float 字段接受 INT 并保留整数形态。成功返回 0。
 */
int ac_sme_config_apply_dict(ac_sme_config *c, const aik_json *d);
int ac_config_apply_dict(ac_config *c, const aik_json *d);

/* ------------------------------------------------------------------ */
/* 校验 / 深合并 / 加载期净化                                          */
/* ------------------------------------------------------------------ */

/*
 * ac_validate_config_dict - 校验待合并片段，返回中文错误 STR 的 ARR
 *
 * 空 ARR = 合法。非对象（含 NULL）→ ["配置必须是 JSON 对象"]。
 * 文案与 config.py:190-230 逐字（"xx 应为布尔值/整数/数字/字符串/数组"、
 * "未知配置项：k"、"sme 应为对象"、"未知配置项：sme.k"）。
 */
aik_json *ac_validate_config_dict(const aik_json *data);

/* deep_merge：返回新 DOM；override 嵌套 dict 递归合并，其余整体覆盖 */
aik_json *ac_deep_merge(const aik_json *base, const aik_json *override);

/* 加载期净化：丢掉未知/类型不符键（load_config 内部步骤之一）*/
aik_json *ac_sanitize_config_dict(const aik_json *d);

/* ------------------------------------------------------------------ */
/* 磁盘 IO                                                             */
/* ------------------------------------------------------------------ */

/*
 * ac_atomic_write_text - 原子写：先写 <name>.tmp-<pid> 再 rename 覆盖
 *
 * 自动 mkdir -p 父目录；失败清理临时文件。成功返回 0。
 */
int ac_atomic_write_text(const char *path, const char *buf, size_t len);

/*
 * ac_quarantine_corrupt - 坏文件改名 <name>.corrupt-<YYYYMMDD-HHMMSS>
 *
 * 返回 malloc 的新路径（调用者 free），文件不存在或失败返回 NULL。
 */
char *ac_quarantine_corrupt(const char *path);

/*
 * ac_load_config - 读 <data_dir>/config.json 装入 *out（先 cleanup）
 *
 * 缺失 → 默认（含环境变量端口）；损坏 → quarantine 后默认；
 * 否则 default_env 深合并 stored 再 sanitize 再 apply。返回 0。
 */
int ac_load_config(const char *data_dir, ac_config *out);

/* 原子写 <data_dir>/config.json：to_dict indent=2 + "\n"。返回 0 */
int ac_save_config(const char *data_dir, const ac_config *cfg);

/* ------------------------------------------------------------------ */
/* JSON 序列化形态（Python json.dumps 等价）                           */
/* ------------------------------------------------------------------ */

/*
 * ac_json_dump_indent - json.dumps(v, ensure_ascii=False, indent=N)
 *
 * N 为 1-8；返回 malloc 的 NUL 结尾缓冲（不含尾换行）。失败 NULL。
 * 空对象 "{}"、空数组 "[]"；数字走 aik_json_dtoa / 整数直出。
 */
char *ac_json_dump_indent(const aik_json *v, int indent);

/*
 * ac_json_dump_default - json.dumps(v, ensure_ascii=False)（无 indent）
 *
 * 分隔符 ", " 与 ": "（sessions.jsonl 每行 / delta-state.json 用）。
 */
char *ac_json_dump_default(const aik_json *v);

/* 读整个文件（二进制）；返回 malloc 缓冲 + *len；失败 NULL。
 * 数据为不受信输入：调用方自行解析/校验，本函数不执行其中任何内容。*/
char *ac_read_file(const char *path, size_t *len);

/* mkdir -p（含中间目录）；已存在且为目录返回 0 */
int ac_mkdir_p(const char *path);

#endif /* _AIK_AUTOCONDENSE_ACCONFIG_H */
