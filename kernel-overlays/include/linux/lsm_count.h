/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2023 Google LLC.
 */

#ifndef __LINUX_LSM_COUNT_H
#define __LINUX_LSM_COUNT_H

#include <linux/args.h>

#ifdef CONFIG_SECURITY

/*
 * Macros to count the number of LSMs enabled in the kernel at compile time.
 */

/*
 * Capabilities is enabled when CONFIG_SECURITY is enabled.
 */
#if IS_ENABLED(CONFIG_SECURITY)
#define CAPABILITIES_ENABLED 1,
#else
#define CAPABILITIES_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_SELINUX)
#define SELINUX_ENABLED 1,
#else
#define SELINUX_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_SMACK)
#define SMACK_ENABLED 1,
#else
#define SMACK_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_APPARMOR)
#define APPARMOR_ENABLED 1,
#else
#define APPARMOR_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_TOMOYO)
#define TOMOYO_ENABLED 1,
#else
#define TOMOYO_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_YAMA)
#define YAMA_ENABLED 1,
#else
#define YAMA_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_LOADPIN)
#define LOADPIN_ENABLED 1,
#else
#define LOADPIN_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_LOCKDOWN_LSM)
#define LOCKDOWN_ENABLED 1,
#else
#define LOCKDOWN_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_SAFESETID)
#define SAFESETID_ENABLED 1,
#else
#define SAFESETID_ENABLED
#endif

#if IS_ENABLED(CONFIG_BPF_LSM)
#define BPF_LSM_ENABLED 1,
#else
#define BPF_LSM_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_LANDLOCK)
#define LANDLOCK_ENABLED 1,
#else
#define LANDLOCK_ENABLED
#endif

#if IS_ENABLED(CONFIG_IMA)
#define IMA_ENABLED 1,
#else
#define IMA_ENABLED
#endif

#if IS_ENABLED(CONFIG_EVM)
#define EVM_ENABLED 1,
#else
#define EVM_ENABLED
#endif

#if IS_ENABLED(CONFIG_SECURITY_IPE)
#define IPE_ENABLED 1,
#else
#define IPE_ENABLED
#endif

/*
 * AIKernel 的 ai LSM（AIKernel/security/ai_lsm.c）不在上游 Kconfig 计数里，
 * 但它同样通过 security_add_hooks() 占用每 hook 的静态调用槽位与
 * ordered_lsms[] 表项。若不计数，lsm=selinux,ai 这类多令牌启动参数会在
 * append_ordered_lsm() 处因 last_lsm == MAX_LSM_COUNT 被 WARN 丢弃，
 * 只剩第一个 LSM（B-097）。启用 CONFIG_AIKERNEL_SECURITY 时补 1 个槽位；
 * 关闭时宏为空，与原生一致（lsm= 缺省顺序不受影响）。
 */
#if IS_ENABLED(CONFIG_AIKERNEL_SECURITY)
#define AIKERNEL_LSM_ENABLED 1,
#else
#define AIKERNEL_LSM_ENABLED
#endif

/*
 *  There is a trailing comma that we need to be accounted for. This is done by
 *  using a skipped argument in __COUNT_LSMS
 */
#define __COUNT_LSMS(skipped_arg, args...) COUNT_ARGS(args...)
#define COUNT_LSMS(args...) __COUNT_LSMS(args)

#define MAX_LSM_COUNT			\
	COUNT_LSMS(			\
		CAPABILITIES_ENABLED	\
		SELINUX_ENABLED		\
		SMACK_ENABLED		\
		APPARMOR_ENABLED	\
		TOMOYO_ENABLED		\
		YAMA_ENABLED		\
		LOADPIN_ENABLED		\
		LOCKDOWN_ENABLED	\
		SAFESETID_ENABLED	\
		BPF_LSM_ENABLED		\
		LANDLOCK_ENABLED	\
		IMA_ENABLED		\
		EVM_ENABLED		\
		IPE_ENABLED		\
		AIKERNEL_LSM_ENABLED)

#else

#define MAX_LSM_COUNT 0

#endif /* CONFIG_SECURITY */

#endif  /* __LINUX_LSM_COUNT_H */
