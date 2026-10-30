/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bpf_tools.h - W80 用户态 BPF loader + nfqueue 消费者（bpf 通道，四件）
 *
 * 设计约束（重要）：
 *   - 不引 libbpf / libnetfilter_queue，只走 bpf() 系统调用与
 *     NETLINK_NETFILTER(12) 原始报文；
 *   - 不解析 ELF：从文件加载只支持自定义 "AIKBPF01" 格式（头部 + raw
 *     instructions）；内置样例编译进 C（手写指令数组）；
 *   - 程序 fd 由本进程持有（g_progs 表），进程退出/卸载即释放——
 *     这既是"零残留"的实现，也让 bpf_prog_list 能看到本进程加载的程序；
 *   - 内核能力（CONFIG_BPF_LSM / CONFIG_NETFILTER_NETLINK_QUEUE /
 *     unprivileged_bpf_disabled / vmlinux BTF）一律真探测并如实回报，
 *     不用配置/常量猜测成功。
 *
 * 工具（4 件，channel=bpf）：
 *   bpf_prog_load    (W2) 从内置样例或 AIKBPF01 文件加载；可选附着
 *   bpf_prog_list    (R)  遍历内核 prog id，列 id/type/name/tag
 *   bpf_prog_unload  (W1) 按 id 卸载本进程加载的程序（fd 关闭 + 复验）
 *   nfqueue_pump     (W2) 绑定 NFQUEUE，收包打印五元组并按策略 verdict
 *
 * 风险分级说明：任务书正文写"加载 W2 / 卸载 W1 / 查询 R"，工具清单处
 * 又把 unload 标成 W2；本实现采用正文口径（unload=W1）：它只能关闭本
 * 进程自己持有的 fd，是清理动作，不放大能力。
 */
#ifndef _AI_BPF_TOOLS_H
#define _AI_BPF_TOOLS_H

#include <stddef.h>
#include <linux/bpf.h>

/* ---- 执行器入口（executor.c 的 TOOL_CH_BPF 分发调用） ---- */
int exec_bpf_channel(const void *tool, const char *args_json, char **out);

/* ---- 系统探测（真读文件，导出供单测/诊断） ---- */
struct ai_bpf_probe {
	int unpriv_bpf_disabled;	/* 0/1/2；-1=读不到 */
	int btf_vmlinux;		/* 1=存在 */
	long long btf_size;		/* 字节数；0=不存在 */
	int cfg_bpf_lsm;		/* 1=y 2=m 0=not set -1=未知 */
	int cfg_nfqueue;		/* 同上（CONFIG_NETFILTER_NETLINK_QUEUE） */
	int lsm_bpf_active;		/* 1=活动 LSM 列表含 bpf；0=不含；-1=未知 */
	char lsm_list[160];		/* /sys/kernel/security/lsm 原文 */
	int kallsyms_bpf_lsm;		/* 1=/proc/kallsyms 有 bpf_lsm_file_open */
	int kallsyms_nfqnl;		/* 1=/proc/kallsyms 有 nfqnl_recv_config */
};

void ai_bpf_probe_system(struct ai_bpf_probe *p);
const char *ai_bpf_errno_name(int err);

/* ---- 最小 BTF 解析（不依赖 libbpf；只认 BTF 格式，不解析 ELF） ---- */

/* 在 vmlinux BTF 字节流中找 BTF_KIND_FUNC 名为 name 的 type id。
 * 成功 0（*type_id 回填），失败 -1。 */
int ai_bpf_btf_find_func(const void *buf, size_t len, const char *name,
			 unsigned int *type_id);

/* 在 vmlinux BTF 中找 struct_name 的成员 member 的字节偏移。
 * 成功 0（*offset 回填），失败 -1。 */
int ai_bpf_btf_member_offset(const void *buf, size_t len,
			     const char *struct_name, const char *member,
			     unsigned int *offset);

/* ---- 指令构造（纯函数，导出供单测） ---- */

/* 最小 TRACEPOINT 程序：r0=0; exit（2 条）。返回 malloc 数组。 */
struct bpf_insn *ai_bpf_build_minimal(int *cnt);

/* LSM file_open 前缀拒绝程序：
 *   file = ctx->args[0]; path = &file->f_path;
 *   len = bpf_d_path(path, buf, 128); if (len < 0) return 0;
 *   若 buf 以 prefix 开头 → return -EPERM；否则 return 0。
 * f_path_off 来自 BTF（struct file 成员 f_path 的字节偏移）。
 * prefix 长度 1..32 字节（不含 NUL）。返回 malloc 数组；失败 NULL。 */
struct bpf_insn *ai_bpf_build_deny_path(const char *prefix, int f_path_off,
					int *cnt);

/* 自定义文件格式（"AIKBPF01"）：小端、紧接 insn_cnt 条 8 字节指令。 */
#define AI_BPF_FILE_MAGIC "AIKBPF01"
struct ai_bpf_file_hdr {
	char magic[8];
	__u32 prog_type;		/* enum bpf_prog_type */
	__u32 expected_attach_type;	/* enum bpf_attach_type */
	__u32 attach_btf_id;		/* LSM 必需；0=按 name 自动解析 */
	__u32 insn_cnt;
	char name[16];			/* NUL 结尾 */
	char license[16];		/* NUL 结尾；LSM 必须 GPL */
	__u32 reserved[4];
};

#endif /* _AI_BPF_TOOLS_H */
