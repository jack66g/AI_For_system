// SPDX-License-Identifier: GPL-2.0
/*
 * ai_lsm_telemetry.c - AIKernel 第8类安全事件发射辅助（自 ai_lsm.c 拆分）
 *
 * 职责一句话：LSM 检查/拒绝、策略加载、seccomp 过滤/拦截、能力授予/拒绝、
 * 密钥创建读取吊销、加密请求/错误、kmsan/ubsan/kcsan/cfi/usercopy/栈溢出
 * 等第8类事件的类型化发射（全量原始零脱敏）。
 *
 * 拆分说明：函数体自原 ai_lsm.c（862 行）逐字搬移；能力名表
 * ai_sec_cap_names/ai_sec_cap_name（仅本文件使用）与 ai_sec_key_emit 保持
 * static 随迁本文件；ai_sec_syscall_name 为 ai_lsm.h 公共接口。
 * 门控：随 ai_lsm.o 在 CONFIG_AIKERNEL_SECURITY 下构建（与拆分前一致）。
 */

#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/minmax.h>
#include <linux/kernel.h>
#include <uapi/linux/lsm.h>
#include <asm/syscall.h>
#include "ai_lsm.h"
#include "../core/ai_control.h"

/* ==================================================================
 * 能力名表（内核已移除 cap_to_name，自建常量表，x86_64 0~40 全量）
 * ================================================================== */

static const char * const ai_sec_cap_names[] = {
	"cap_chown", "cap_dac_override", "cap_dac_read_search",
	"cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid",
	"cap_setpcap", "cap_linux_immutable", "cap_net_bind_service",
	"cap_net_broadcast", "cap_net_admin", "cap_net_raw", "cap_ipc_lock",
	"cap_ipc_owner", "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot",
	"cap_sys_ptrace", "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot",
	"cap_sys_nice", "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config",
	"cap_mknod", "cap_lease", "cap_audit_write", "cap_audit_control",
	"cap_setfcap", "cap_mac_override", "cap_mac_admin", "cap_syslog",
	"cap_wake_alarm", "cap_block_suspend", "cap_audit_read",
	"cap_perfmon", "cap_bpf", "cap_checkpoint_restore",
};

static const char *ai_sec_cap_name(int cap)
{
	if (cap >= 0 && cap < ARRAY_SIZE(ai_sec_cap_names))
		return ai_sec_cap_names[cap];
	return "cap_unknown";
}

/* ==================================================================
 * 第8类事件发射（全量原始零脱敏）
 * ================================================================== */

void ai_telemetry_lsm_check(const char *hook_name, const char *subject_label,
			    const char *object_label, int result,
			    const char *detail)
{
	struct ai_sec_lsm_check_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_LSM))
		return;
	p.type = AI_SEC_LSM_CHECK;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	strscpy(p.hook_name, hook_name ? hook_name : "?", sizeof(p.hook_name));
	strscpy(p.subject_label, subject_label ? subject_label : "?",
		sizeof(p.subject_label));
	strscpy(p.object_label, object_label ? object_label : "?",
		sizeof(p.object_label));
	p.result = result;
	strscpy(p.detail, detail ? detail : "", sizeof(p.detail));
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_LSM, AI_SEV_NORMAL,
				 &p, sizeof(p));
}

void ai_telemetry_lsm_deny(const char *hook_name, const char *subject_label,
			   const char *object_label, const char *av,
			   const char *detail)
{
	struct ai_sec_lsm_deny_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_LSM))
		return;
	p.type = AI_SEC_LSM_DENY;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	strscpy(p.hook_name, hook_name ? hook_name : "?", sizeof(p.hook_name));
	strscpy(p.subject_label, subject_label ? subject_label : "?",
		sizeof(p.subject_label));
	strscpy(p.object_label, object_label ? object_label : "?",
		sizeof(p.object_label));
	strscpy(p.av, av ? av : "", sizeof(p.av));
	strscpy(p.detail, detail ? detail : "", sizeof(p.detail));
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_LSM, AI_SEV_CRITICAL,
				 &p, sizeof(p));
}

void ai_telemetry_lsm_policy_load(const char *module, u32 version, u32 size)
{
	struct ai_sec_lsm_policy_load_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_LSM))
		return;
	p.type = AI_SEC_LSM_POLICY_LOAD;
	strscpy(p.lsm_module, module ? module : "?", sizeof(p.lsm_module));
	p.policy_version = version;
	p.policy_size = size;
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_LSM, AI_SEV_NORMAL,
				 &p, sizeof(p));
}

void ai_telemetry_seccomp_filter(u32 insn_count, const unsigned long *insns,
				 size_t insns_bytes)
{
	struct ai_sec_seccomp_filter_payload *p;
	u16 hdr_len = sizeof(struct ai_sec_seccomp_filter_payload);
	u16 emit_len;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_SECCOMP))
		return;

	/* 边界：payload 总长 ≤ 233B（human 模式 chunk 语义，见 ai_lsm.h
	 * AI_SEC_PATH_LEN 注释）；insns 为原始指令样本，insn_count 全量。 */
	emit_len = hdr_len;
	if (insns_bytes > 200)
		insns_bytes = 200;
	emit_len += insns_bytes;
	if (emit_len > AI_TELEMETRY_MAX_DATA_LEN)
		emit_len = AI_TELEMETRY_MAX_DATA_LEN;

	/* 过滤器安装为进程上下文低频路径，允许一次性分配（失败则只记头部） */
	p = kmalloc(emit_len, GFP_KERNEL);
	if (!p)
		return;
	p->type = AI_SEC_SECCOMP_FILTER;
	p->pid = current ? current->pid : 0;
	strscpy(p->comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p->comm));
	p->insn_count = insn_count;
	p->insns_bytes = emit_len - hdr_len;
	if (insns && insns_bytes)
		memcpy(p->insns, insns, p->insns_bytes);

	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_SECCOMP, AI_SEV_NORMAL,
				 p, emit_len);
	kfree(p);
}

void ai_telemetry_seccomp_kill(s32 syscall_nr, u32 action)
{
	struct ai_sec_seccomp_kill_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_SECCOMP))
		return;
	p.type = AI_SEC_SECCOMP_KILL;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	p.syscall_nr = syscall_nr;
	ai_sec_syscall_name(syscall_nr, p.syscall_name,
			    sizeof(p.syscall_name));
	p.action = action;
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_SECCOMP, AI_SEV_CRITICAL,
				 &p, sizeof(p));
}

void ai_telemetry_cap_set(u64 old_effective, u64 new_effective)
{
	struct ai_sec_cap_set_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_CAPABILITY))
		return;
	p.type = AI_SEC_CAP_SET;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	strscpy(p.cap_name,
		ai_sec_cap_name(fls64(old_effective ^ new_effective) - 1),
		sizeof(p.cap_name));
	p.old_effective = old_effective;
	p.new_effective = new_effective;
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_CAPABILITY,
				 AI_SEV_IMPORTANT, &p, sizeof(p));
}

void ai_telemetry_cap_check_denied(int cap)
{
	struct ai_sec_cap_check_denied_payload p;
	s32 nr;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_CAPABILITY))
		return;
	p.type = AI_SEC_CAP_CHECK_DENIED;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	strscpy(p.cap_name, ai_sec_cap_name(cap), sizeof(p.cap_name));
	nr = current ? syscall_get_nr(current, current_pt_regs()) : -1;
	ai_sec_syscall_name(nr, p.syscall_name, sizeof(p.syscall_name));
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_CAPABILITY,
				 AI_SEV_CRITICAL, &p, sizeof(p));
}

static void ai_sec_key_emit(u8 sub, const char *type, const char *desc,
			    u32 uid)
{
	struct ai_sec_key_payload p;

	p.type = sub;
	p.uid = uid;
	strscpy(p.key_type, type ? type : "?", sizeof(p.key_type));
	strscpy(p.key_description, desc ? desc : "?", sizeof(p.key_description));
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_KEY, AI_SEV_IMPORTANT,
				 &p, sizeof(p));
}

void ai_telemetry_key_create(const char *type, const char *desc, u32 uid)
{
	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_KEY))
		return;
	ai_sec_key_emit(AI_SEC_KEY_CREATE, type, desc, uid);
}

void ai_telemetry_key_read(const char *desc, u32 uid)
{
	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_KEY))
		return;
	ai_sec_key_emit(AI_SEC_KEY_READ, NULL, desc, uid);
}

void ai_telemetry_key_revoke(const char *desc, u32 uid)
{
	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_KEY))
		return;
	ai_sec_key_emit(AI_SEC_KEY_REVOKE, NULL, desc, uid);
}

void ai_telemetry_crypto_request(const char *alg_name, u32 type, u32 mask)
{
	struct ai_sec_crypto_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_CRYPTO))
		return;
	p.type = AI_SEC_CRYPTO_REQUEST;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	strscpy(p.algo_name, alg_name ? alg_name : "?", sizeof(p.algo_name));
	p.algo_type = type;
	p.mask = mask;
	p.error_type[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_CRYPTO, AI_SEV_NORMAL,
				 &p, sizeof(p));
}

void ai_telemetry_crypto_error(const char *alg_name, const char *error_type)
{
	struct ai_sec_crypto_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_CRYPTO))
		return;
	p.type = AI_SEC_CRYPTO_ERROR;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	strscpy(p.algo_name, alg_name ? alg_name : "?", sizeof(p.algo_name));
	p.algo_type = 0;
	p.mask = 0;
	strscpy(p.error_type, error_type ? error_type : "unknown",
		sizeof(p.error_type));
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_CRYPTO, AI_SEV_IMPORTANT,
				 &p, sizeof(p));
}

void ai_telemetry_kmsan_detect(u64 address, u32 size, const char *bug_type,
			       u64 alloc_stack)
{
	struct ai_sec_kmsan_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_MEM_DETECT))
		return;
	p.type = AI_SEC_KMSAN_DETECT;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	p.address = address;
	p.size = size;
	strscpy(p.bug_type, bug_type ? bug_type : "unknown",
		sizeof(p.bug_type));
	p.alloc_stack = alloc_stack;
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_MEM_DETECT,
				 AI_SEV_CRITICAL, &p, sizeof(p));
}

void ai_telemetry_ubsan_detect(const char *bug_type, const char *file,
			       u32 line)
{
	struct ai_sec_ubsan_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_MEM_DETECT))
		return;
	p.type = AI_SEC_UBSAN_DETECT;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	strscpy(p.bug_type, bug_type ? bug_type : "unknown",
		sizeof(p.bug_type));
	strscpy(p.file, file ? file : "?", sizeof(p.file));
	p.line = line;
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_MEM_DETECT,
				 AI_SEV_CRITICAL, &p, sizeof(p));
}

void ai_telemetry_kcsan_detect(const char *data_race_info, u64 stack1,
			       u64 stack2)
{
	struct ai_sec_kcsan_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_MEM_DETECT))
		return;
	p.type = AI_SEC_KCSAN_DETECT;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	strscpy(p.data_race_info, data_race_info ? data_race_info : "?",
		sizeof(p.data_race_info));
	p.stack1 = stack1;
	p.stack2 = stack2;
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_MEM_DETECT,
				 AI_SEV_CRITICAL, &p, sizeof(p));
}

void ai_telemetry_cfi_violation(u64 target_address, s32 expected_type)
{
	struct ai_sec_cfi_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_HARDENING))
		return;
	p.type = AI_SEC_CFI_VIOLATION;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	p.target_address = target_address;
	p.expected_type = expected_type;
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_HARDENING,
				 AI_SEV_CRITICAL, &p, sizeof(p));
}

void ai_telemetry_usercopy_violation(u64 src, u64 dst, u64 size, u8 direction,
				     const char *name, const char *detail)
{
	struct ai_sec_usercopy_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_HARDENING))
		return;
	p.type = AI_SEC_USERCOPY_VIOLATION;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	p.src = src;
	p.dst = dst;
	p.size = size;
	p.direction = direction;
	strscpy(p.name, name ? name : "?", sizeof(p.name));
	strscpy(p.detail, detail ? detail : "", sizeof(p.detail));
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_HARDENING,
				 AI_SEV_CRITICAL, &p, sizeof(p));
}

void ai_telemetry_stack_overflow(u64 guard_page_touch, const char *stack_name)
{
	struct ai_sec_stack_overflow_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_HARDENING))
		return;
	p.type = AI_SEC_STACK_OVERFLOW;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	p.guard_page_touch = guard_page_touch;
	strscpy(p.stack_name, stack_name ? stack_name : "?",
		sizeof(p.stack_name));
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_HARDENING,
				 AI_SEV_CRITICAL, &p, sizeof(p));
}
