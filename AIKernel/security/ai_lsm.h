// SPDX-License-Identifier: GPL-2.0
/*
 * ai_lsm.h - AIKernel 安全子系统唯一接入头（AI 安全大脑）
 *
 * 门控 CONFIG_AIKERNEL_SECURITY（default n）。
 * 本头文件承载：
 *   A 轨：AI LSM 钩子 + 行为建模/异常检测决策框架 + ai_sec_* Hook 原型
 *          （seccomp/capable/keys/crypto 的 AI 决策接入点，空实现 = 原样放行）
 *   B 轨：第8类 安全事件感知（数据计划 8.1~8.8）全部 payload 结构 + 发射辅助
 *
 * 零脱敏：凭证变更、密钥描述、审计记录、能力检查全部原始记录——AI 判断敌我唯一依据。
 * 决策日志默认仅特权可读（AI 全量可见，外部用户需授权）。
 *
 * CONFIG_AIKERNEL_SECURITY=n 时全部接口为 static inline 空函数/空结构，零开销零回归
 * （seccomp/commoncap/keys/crypto/audit/内存检测路径的预处理产物与基线一致）。
 */

#ifndef _AIKERNEL_AI_LSM_H
#define _AIKERNEL_AI_LSM_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <linux/seccomp.h>
#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"

/* ---- 常量 ---- */

#define AI_SEC_NAME_LEN		16	/* hook_name/comm/stack_name 等 */
#define AI_SEC_SUBJ_LABEL_LEN	32
#define AI_SEC_OBJ_LABEL_LEN	64
#define AI_SEC_DETAIL_LEN	64
#define AI_SEC_AV_LEN		16
#define AI_SEC_SYSCALL_NAME_LEN	32
#define AI_SEC_CAP_NAME_LEN	32
#define AI_SEC_ALGO_NAME_LEN	64
#define AI_SEC_KEY_TYPE_LEN	32
#define AI_SEC_KEY_DESC_LEN	128
#define AI_SEC_BUGTYPE_LEN	40
#define AI_SEC_FILE_LEN		64
#define AI_SEC_RACE_INFO_LEN	64
/* 路径长度上限 200：全部安全事件 payload ≤ 233B（23B 头 + 256B
 * procfs human 模式单次 chunk 内可容纳，保证 /proc/ai/telemetry 流式
 * 读取不因超长记录而停滞——Prompt 02 读路径的既有 chunk 语义） */
#define AI_SEC_PATH_LEN		200

/* AI LSM 可插拔注册信息（名称/ID 与 security 框架对接） */
#define AI_LSM_NAME		"ai"
#define AI_LSM_ID		114	/* uapi LSM_ID_ 100~113 已用，114 为下一空号 */

/* 行为模型表与决策表容量（无分配，spinlock 保护） */
#define AI_LSM_MODEL_SLOTS	256
#define AI_LSM_RULE_MAX		64

/* ---- 第8类子事件枚举（payload 首字节 type，对齐数据计划 8.1~8.8） ---- */

enum ai_sec_sub_event {
	AI_SEC_LSM_CHECK = 1,		/* 8.1 LSM 权限检查（全量） */
	AI_SEC_LSM_DENY,		/* 8.1 LSM 拒绝 */
	AI_SEC_LSM_POLICY_LOAD,		/* 8.1 策略加载 */
	AI_SEC_SECCOMP_FILTER,		/* 8.2 seccomp 过滤器安装 */
	AI_SEC_SECCOMP_KILL,		/* 8.2 seccomp 拦截 */
	AI_SEC_CAP_SET,			/* 8.3 能力变更 */
	AI_SEC_CAP_CHECK_DENIED,	/* 8.3 能力拒绝 */
	AI_SEC_AUDIT_SYSCALL,		/* 8.4 审计系统调用 */
	AI_SEC_AUDIT_PATH,		/* 8.4 审计文件路径 */
	AI_SEC_AUDIT_ANOMALY,		/* 8.4 审计异常 */
	AI_SEC_KEY_CREATE,		/* 8.5 密钥创建 */
	AI_SEC_KEY_READ,		/* 8.5 密钥读取 */
	AI_SEC_KEY_REVOKE,		/* 8.5 密钥撤销 */
	AI_SEC_CRYPTO_REQUEST,		/* 8.6 加密请求 */
	AI_SEC_CRYPTO_ERROR,		/* 8.6 加密错误 */
	AI_SEC_KMSAN_DETECT,		/* 8.7 KMSAN 报告 */
	AI_SEC_UBSAN_DETECT,		/* 8.7 UBSAN 报告 */
	AI_SEC_KCSAN_DETECT,		/* 8.7 KCSAN 数据竞争 */
	AI_SEC_CFI_VIOLATION,		/* 8.8 CFI 违规 */
	AI_SEC_USERCOPY_VIOLATION,	/* 8.8 hardened usercopy 违规 */
	AI_SEC_STACK_OVERFLOW,		/* 8.8 栈溢出 */
};

/* ---- 第8类 payload 结构（全量原始零脱敏） ---- */

/* 8.1 LSM */
struct ai_sec_lsm_check_payload {
	u8 type;			/* AI_SEC_LSM_CHECK */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	char hook_name[AI_SEC_NAME_LEN];
	char subject_label[AI_SEC_SUBJ_LABEL_LEN];
	char object_label[AI_SEC_OBJ_LABEL_LEN];
	int result;
	char detail[AI_SEC_DETAIL_LEN];
};

struct ai_sec_lsm_deny_payload {
	u8 type;			/* AI_SEC_LSM_DENY */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	char hook_name[AI_SEC_NAME_LEN];
	char subject_label[AI_SEC_SUBJ_LABEL_LEN];
	char object_label[AI_SEC_OBJ_LABEL_LEN];
	char av[AI_SEC_AV_LEN];
	char detail[AI_SEC_DETAIL_LEN];
};

struct ai_sec_lsm_policy_load_payload {
	u8 type;			/* AI_SEC_LSM_POLICY_LOAD */
	char lsm_module[AI_SEC_NAME_LEN];
	u32 policy_version;
	u32 policy_size;
};

/* 8.2 Seccomp（filter_bpf_prog 为变长原始 insns，见发射辅助注释） */
struct ai_sec_seccomp_filter_payload {
	u8 type;			/* AI_SEC_SECCOMP_FILTER */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	u32 insn_count;			/* BPF 指令总数 */
	u32 insns_bytes;		/* 实际记录的原始字节数（≤4096） */
	unsigned long insns[0];		/* 原始 BPF 指令（零脱敏，ring 上限 4096B） */
};

struct ai_sec_seccomp_kill_payload {
	u8 type;			/* AI_SEC_SECCOMP_KILL */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	s32 syscall_nr;
	char syscall_name[AI_SEC_SYSCALL_NAME_LEN];
	u32 action;			/* SECCOMP_RET_KILL_PROCESS/THREAD */
};

/* 8.3 能力 */
struct ai_sec_cap_set_payload {
	u8 type;			/* AI_SEC_CAP_SET */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	char cap_name[AI_SEC_CAP_NAME_LEN];
	u64 old_effective;		/* 原 effective 掩码（全量） */
	u64 new_effective;		/* 新 effective 掩码（全量） */
};

struct ai_sec_cap_check_denied_payload {
	u8 type;			/* AI_SEC_CAP_CHECK_DENIED */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	char cap_name[AI_SEC_CAP_NAME_LEN];
	char syscall_name[AI_SEC_SYSCALL_NAME_LEN];
};

/* 8.4 审计 */
struct ai_sec_audit_syscall_payload {
	u8 type;			/* AI_SEC_AUDIT_SYSCALL */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	s32 syscall_nr;
	char syscall_name[AI_SEC_SYSCALL_NAME_LEN];
	u8 success;
	s64 exit_code;
};

struct ai_sec_audit_path_payload {
	u8 type;			/* AI_SEC_AUDIT_PATH */
	u32 pid;
	char full_path[AI_SEC_PATH_LEN];
	u32 rec_type;			/* 审计记录类型 */
};

struct ai_sec_audit_anomaly_payload {
	u8 type;			/* AI_SEC_AUDIT_ANOMALY */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	char anomaly_type[AI_SEC_NAME_LEN];
	char full_detail[128];
};

/* 8.5 密钥 */
struct ai_sec_key_payload {
	u8 type;			/* AI_SEC_KEY_CREATE/READ/REVOKE */
	u32 uid;
	char key_type[AI_SEC_KEY_TYPE_LEN];
	char key_description[AI_SEC_KEY_DESC_LEN];
};

/* 8.6 加密 */
struct ai_sec_crypto_payload {
	u8 type;			/* AI_SEC_CRYPTO_REQUEST/ERROR */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	char algo_name[AI_SEC_ALGO_NAME_LEN];
	u32 algo_type;			/* CRYPTO_ALG_* */
	u32 mask;
	char error_type[AI_SEC_NAME_LEN];	/* ERROR 时填充 */
};

/* 8.7 内存安全检测 */
struct ai_sec_kmsan_payload {
	u8 type;			/* AI_SEC_KMSAN_DETECT */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	u64 address;
	u32 size;
	char bug_type[AI_SEC_BUGTYPE_LEN];
	u64 alloc_stack;		/* origin 栈顶帧地址（训练金矿） */
};

struct ai_sec_ubsan_payload {
	u8 type;			/* AI_SEC_UBSAN_DETECT */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	char bug_type[AI_SEC_BUGTYPE_LEN];
	char file[AI_SEC_FILE_LEN];
	u32 line;
};

struct ai_sec_kcsan_payload {
	u8 type;			/* AI_SEC_KCSAN_DETECT */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	char data_race_info[AI_SEC_RACE_INFO_LEN];
	u64 stack1;			/* 本线程栈帧 */
	u64 stack2;			/* 对端栈帧（无=0） */
};

/* 8.8 内核加固违规 */
struct ai_sec_cfi_payload {
	u8 type;			/* AI_SEC_CFI_VIOLATION */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	u64 target_address;
	s32 expected_type;
};

struct ai_sec_usercopy_payload {
	u8 type;			/* AI_SEC_USERCOPY_VIOLATION */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	u64 src;
	u64 dst;
	u64 size;
	u8 direction;			/* 0=to_user 1=from_user */
	char name[AI_SEC_NAME_LEN];
	char detail[AI_SEC_DETAIL_LEN];
};

struct ai_sec_stack_overflow_payload {
	u8 type;			/* AI_SEC_STACK_OVERFLOW */
	u32 pid;
	char comm[AI_SEC_NAME_LEN];
	u64 guard_page_touch;
	char stack_name[AI_SEC_NAME_LEN];
};

#ifdef CONFIG_AIKERNEL_SECURITY

/* ---- A 轨：ai_sec_* Hook（空实现 = 原样放行，语义不变） ---- */

/**
 * ai_sec_seccomp_hook() - AI 分析进程行为，建议 seccomp 规则
 * @syscall_nr: 本次系统调用号
 * @sd:        seccomp 数据（可为 NULL）
 * @action:    seccomp 动作（AI 可修改，默认原样）
 *
 * 由 kernel/seccomp.c __seccomp_filter() 调用；本步空实现只更新行为模型。
 */
void ai_sec_seccomp_hook(int syscall_nr, const struct seccomp_data *sd,
			 u32 *action);

/**
 * ai_sec_cap_hook() - AI 评估能力授予风险
 * @cred: 被检查的凭证
 * @ns:   目标用户命名空间
 * @cap:  能力号
 * @ret:  原生检查结果
 *
 * 由 security/commoncap.c cap_capable() 调用；返回修改后的结果
 * （空实现返回原 ret，语义不变）。
 */
int ai_sec_cap_hook(const struct cred *cred, struct user_namespace *ns,
		    int cap, int ret);

/**
 * ai_sec_key_hook() - AI 评估密钥强度
 * @type:    密钥类型
 * @desc:    密钥描述
 * @plen:    载荷长度
 * @strength: 强度评估输出（0=弱 1=中 2=强）
 *
 * 由 security/keys/key.c __key_create_or_update() 成功路径调用；只评估不改。
 */
void ai_sec_key_hook(const char *type, const char *desc, size_t plen,
		     u8 *strength);

/**
 * ai_sec_crypto_hook() - AI 按负载选择加密算法
 * @alg_name: 算法名（AI 可改为更优算法名，默认原样）
 * @type:     算法类型
 * @mask:     类型掩码
 *
 * 由 crypto/api.c crypto_alloc_tfm_node() 调用；本步空实现不改。
 */
void ai_sec_crypto_hook(const char **alg_name, u32 type, u32 mask);

/**
 * ai_sec_syscall_name() - 系统调用号转名称（低频事件专用）
 * @nr:   系统调用号
 * @buf:  输出缓冲
 * @size: 缓冲大小
 *
 * 经 sys_call_table + kallsyms_lookup_address 解析，失败回退 "sys_<nr>"。
 */
void ai_sec_syscall_name(int nr, char *buf, size_t size);

/* ---- 决策框架：行为建模与异常检测 ---- */

/**
 * ai_lsm_rule_add() - 添加 AI 决策规则（subject pid → allow/deny）
 * @pid:    目标进程
 * @deny:   true=拒绝 false=放行
 * @detail: 规则说明（决策日志用）
 *
 * 返回 AI_OK 或负错误码（表满 AI_ERR_NO_MEMORY）。
 */
int ai_lsm_rule_add(u32 pid, bool deny, const char *detail);

/**
 * ai_lsm_rule_del() - 删除某 pid 的全部规则
 * @pid: 目标进程
 *
 * 返回 AI_OK 或 AI_ERR_NOT_FOUND。
 */
int ai_lsm_rule_del(u32 pid);

/**
 * ai_lsm_rule_clear() - 清空决策表（并发射 lsm_policy_load）
 *
 * 返回 AI_OK。
 */
int ai_lsm_rule_clear(void);

/**
 * ai_lsm_enforce_get() - AIKernel 自家 LSM 执行档位（sec.lsm_override 参数）
 * false=observe（默认：规则命中仅记录放行） true=enforce（规则命中拦截）
 */
bool ai_lsm_enforce_get(void);
int ai_lsm_enforce_set(bool on);

/**
 * ai_lsm_rule_count() - 决策规则表当前条数（观测面）
 */
u32 ai_lsm_rule_count(void);

/**
 * ai_lsm_eval_anomaly() - 行为偏离判定
 * @pid:      目标进程
 * @out_score: 异常分 0~100（0=正常 100=极可疑）
 *
 * 基于滑动均值偏差启发式（Z-score）；AI 推理接入点（后续步骤填充）。
 * 返回 AI_OK 或 AI_ERR_NOT_FOUND（无模型）。
 */
int ai_lsm_eval_anomaly(u32 pid, u8 *out_score);

/**
 * ai_lsm_stats_read() - 读取行为模型与决策统计
 * @buf:    输出缓冲（text 格式）
 * @len:    缓冲容量
 * @out_len: 实际字节数
 *
 * 供 AI Runtime / 用户态读取（默认仅特权可读）。
 * 返回 AI_OK 或负错误码。
 */
int ai_lsm_stats_read(char *buf, size_t len, size_t *out_len);

/* ---- B 轨：8.1 LSM 事件发射 ---- */

void ai_telemetry_lsm_check(const char *hook_name, const char *subject_label,
			    const char *object_label, int result,
			    const char *detail);
void ai_telemetry_lsm_deny(const char *hook_name, const char *subject_label,
			   const char *object_label, const char *av,
			   const char *detail);
void ai_telemetry_lsm_policy_load(const char *module, u32 version, u32 size);

/* ---- B 轨：8.2 Seccomp 事件发射 ---- */

void ai_telemetry_seccomp_filter(u32 insn_count, const unsigned long *insns,
				 size_t insns_bytes);
void ai_telemetry_seccomp_kill(s32 syscall_nr, u32 action);

/* ---- B 轨：8.3 能力事件发射 ---- */

void ai_telemetry_cap_set(u64 old_effective, u64 new_effective);
void ai_telemetry_cap_check_denied(int cap);

/* ---- B 轨：8.5 密钥事件发射 ---- */

void ai_telemetry_key_create(const char *type, const char *desc, u32 uid);
void ai_telemetry_key_read(const char *desc, u32 uid);
void ai_telemetry_key_revoke(const char *desc, u32 uid);

/* ---- B 轨：8.6 加密事件发射 ---- */

void ai_telemetry_crypto_request(const char *alg_name, u32 type, u32 mask);
void ai_telemetry_crypto_error(const char *alg_name, const char *error_type);

/* ---- B 轨：8.7 内存安全检测发射 ---- */

void ai_telemetry_kmsan_detect(u64 address, u32 size, const char *bug_type,
			       u64 alloc_stack);
void ai_telemetry_ubsan_detect(const char *bug_type, const char *file,
			       u32 line);
void ai_telemetry_kcsan_detect(const char *data_race_info, u64 stack1,
			       u64 stack2);

/* ---- B 轨：8.8 内核加固违规发射 ---- */

void ai_telemetry_cfi_violation(u64 target_address, s32 expected_type);
void ai_telemetry_usercopy_violation(u64 src, u64 dst, u64 size, u8 direction,
				     const char *name, const char *detail);
void ai_telemetry_stack_overflow(u64 guard_page_touch, const char *stack_name);

#else /* !CONFIG_AIKERNEL_SECURITY */

static inline void ai_sec_seccomp_hook(int syscall_nr,
				       const struct seccomp_data *sd,
				       u32 *action) { }
static inline int ai_sec_cap_hook(const struct cred *cred,
				  struct user_namespace *ns, int cap, int ret)
{ return ret; }
static inline void ai_sec_key_hook(const char *type, const char *desc,
				   size_t plen, u8 *strength)
{ if (strength) *strength = 0; }
static inline void ai_sec_crypto_hook(const char **alg_name, u32 type,
				      u32 mask) { }
static inline void ai_sec_syscall_name(int nr, char *buf, size_t size)
{ if (buf && size) buf[0] = '\0'; }

static inline int ai_lsm_rule_add(u32 pid, bool deny, const char *detail)
{ return AI_OK; }
static inline int ai_lsm_rule_del(u32 pid) { return AI_OK; }
static inline int ai_lsm_rule_clear(void) { return AI_OK; }
static inline bool ai_lsm_enforce_get(void) { return false; }
static inline int ai_lsm_enforce_set(bool on) { return AI_OK; }
static inline u32 ai_lsm_rule_count(void) { return 0; }
static inline int ai_lsm_eval_anomaly(u32 pid, u8 *out_score)
{ if (out_score) *out_score = 0; return AI_OK; }
static inline int ai_lsm_stats_read(char *buf, size_t len, size_t *out_len)
{ if (out_len) *out_len = 0; return AI_OK; }

static inline void ai_telemetry_lsm_check(const char *h, const char *s,
					  const char *o, int r, const char *d) { }
static inline void ai_telemetry_lsm_deny(const char *h, const char *s,
					 const char *o, const char *av,
					 const char *d) { }
static inline void ai_telemetry_lsm_policy_load(const char *m, u32 v, u32 s) { }
static inline void ai_telemetry_seccomp_filter(u32 c, const unsigned long *i,
					       size_t b) { }
static inline void ai_telemetry_seccomp_kill(s32 nr, u32 action) { }
static inline void ai_telemetry_cap_set(u64 o, u64 n) { }
static inline void ai_telemetry_cap_check_denied(int cap) { }
static inline void ai_telemetry_key_create(const char *t, const char *d,
					   u32 u) { }
static inline void ai_telemetry_key_read(const char *d, u32 u) { }
static inline void ai_telemetry_key_revoke(const char *d, u32 u) { }
static inline void ai_telemetry_crypto_request(const char *a, u32 t,
					       u32 m) { }
static inline void ai_telemetry_crypto_error(const char *a,
					     const char *e) { }
static inline void ai_telemetry_kmsan_detect(u64 a, u32 s, const char *b,
					     u64 st) { }
static inline void ai_telemetry_ubsan_detect(const char *b, const char *f,
					     u32 l) { }
static inline void ai_telemetry_kcsan_detect(const char *i, u64 s1,
					     u64 s2) { }
static inline void ai_telemetry_cfi_violation(u64 t, s32 e) { }
static inline void ai_telemetry_usercopy_violation(u64 s, u64 d, u64 sz,
						   u8 dir, const char *n,
						   const char *dt) { }
static inline void ai_telemetry_stack_overflow(u64 a, const char *n) { }

#endif /* CONFIG_AIKERNEL_SECURITY */

#endif /* _AIKERNEL_AI_LSM_H */
