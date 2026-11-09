// SPDX-License-Identifier: GPL-2.0
/*
 * bpf_tools.c - W80 用户态 BPF loader + nfqueue 消费者（bpf 通道）
 *
 * 目标（任务书 W80 棒 2-B）：
 *   1. 让 AI 能加载/查询/卸载 BPF 程序，不引 libbpf：直接 bpf() 系统调用
 *      （x86_64 __NR_bpf=321），封装 BPF_PROG_LOAD / BPF_PROG_GET_NEXT_ID /
 *      BPF_PROG_GET_FD_BY_ID / BPF_OBJ_GET_INFO_BY_FD / BPF_LINK_CREATE；
 *   2. 一个真 LSM 程序：手写指令挂 lsm/file_open，路径前缀命中返回 -EPERM；
 *   3. nfqueue 消费者：NETLINK_NETFILTER(12) 原始 NFQNL_MSG_CONFIG/PACKET/
 *      VERDICT，不引 libnetfilter_queue，硬超时 + 包数上限。
 *
 * 关键实现口径：
 *   - 不解析 ELF：文件加载只认自定义 "AIKBPF01"（头部 + raw insns）。
 *     L1 无 clang -target bpf（`command -v clang` 空），本棒的样例全部是
 *     手写指令数组（见 ai_bpf_build_*）。
 *   - LSM 的 attach_btf_id 不能猜：内核要求指向 bpf_lsm_file_open 的 BTF
 *     FUNC id（security/bpf/hooks.c + kernel/bpf/bpf_lsm.c 的 BTF_ID 集）。
 *     内核带 CONFIG_DEBUG_INFO_BTF 时读 /sys/kernel/btf/vmlinux，用本文件
 *     的最小 BTF 解析器取 FUNC id 与 struct file.f_path 偏移；解析失败
 *     一律报错，绝不使用硬编码偏移。
 *   - 路径判断用 bpf_d_path（helper 147）拿完整路径串，再按前缀逐字节
 *     比较；这样命中语义是"路径前缀"，不是 inode/文件名。
 *   - 程序 fd 由本进程持有：进程退出 fd 关闭 → 内核自动回收（零残留）。
 *     bpf_prog_unload 关闭 fd 后用 BPF_PROG_GET_FD_BY_ID 复验是否真的
 *     从内核消失；仍被其他引用持有时如实报"未完全卸载"。
 *   - 加载失败不伪造：EPERM 时把 unprivileged_bpf_disabled 的真值贴出来；
 *     CONFIG_BPF_LSM=n 时直接说"内核未编 BPF_LSM，等 #61"，不含糊。
 *
 * 证据见 ~/aikernel-longterm/evidence/w80/bpf/ 与报告 W80-BPF.md。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <linux/bpf.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "tools/bpf_tools.h"

#ifndef __NR_bpf
# if defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__i386__)
#  define __NR_bpf 357
# else
#  error "未知架构：请补充 __NR_bpf"
# endif
#endif

#ifndef __NR_perf_event_open
# if defined(__x86_64__)
#  define __NR_perf_event_open 298
# elif defined(__aarch64__)
#  define __NR_perf_event_open 241
# else
#  define __NR_perf_event_open 336
# endif
#endif

#define AI_BPF_MAX_PROGS	8
#define AI_BPF_LOG_SIZE		(64 * 1024)
#define AI_BPF_FILE_MAX		(1024 * 1024)
#define AI_BPF_INSN_MAX		4096
#define AI_BPF_PREFIX_MAX	32
#define AI_BPF_LIST_MAX		128
#define AI_BPF_READ_MAX		(64 * 1024 * 1024)

#define AI_NFQ_TIMEOUT_MIN	100
#define AI_NFQ_TIMEOUT_MAX	60000
#define AI_NFQ_PKTS_MIN		1
#define AI_NFQ_PKTS_MAX		1000
#define AI_NFQ_ACK_MS		3000
#define AI_NFQ_MAXLEN		1024
#define AI_NFQ_PAYLOAD_MAX	65535

#ifndef ENOTSUPP
# define ENOTSUPP 524
#endif

/* ------------------------------------------------------------------ */
/* 小工具                                                              */
/* ------------------------------------------------------------------ */

struct sbuf {
	char *p;
	size_t len;
	size_t cap;
};

static int sb_init(struct sbuf *b)
{
	b->cap = 2048;
	b->len = 0;
	b->p = malloc(b->cap);
	if (!b->p)
		return -1;
	b->p[0] = '\0';
	return 0;
}

static void sb_free(struct sbuf *b)
{
	free(b->p);
	b->p = NULL;
	b->len = b->cap = 0;
}

static int sb_ensure(struct sbuf *b)
{
	if (b->p)
		return 0;
	return sb_init(b);
}

static int sb_add(struct sbuf *b, const char *fmt, ...)
{
	va_list ap, ap2;
	int need;
	size_t cap;

	if (!b->p)
		return -1;
	va_start(ap, fmt);
	va_copy(ap2, ap);
	need = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (need < 0) {
		va_end(ap2);
		return -1;
	}
	if (b->len + (size_t)need + 1 > b->cap) {
		char *np;

		cap = b->cap * 2;
		while (cap < b->len + (size_t)need + 1)
			cap *= 2;
		np = realloc(b->p, cap);
		if (!np) {
			va_end(ap2);
			return -1;
		}
		b->p = np;
		b->cap = cap;
	}
	vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap2);
	va_end(ap2);
	b->len += (size_t)need;
	return 0;
}

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || !errlen)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* 从 arguments JSON 取字符串（malloc；不存在 NULL） */
static char *jstr(const char *args_json, const char *key)
{
	const char *v;
	size_t vl;
	int vt;

	if (!args_json || !args_json[0])
		return NULL;
	if (ai_json_obj_get(args_json, strlen(args_json), key,
			    &v, &vl, &vt) != 1)
		return NULL;
	if (vt == AI_JSON_STR)
		return ai_json_strdup_str(v, vl);
	return strndup(v, vl);
}

static long long jll(const char *args_json, const char *key, long long def)
{
	const char *v;
	size_t vl;
	int vt;

	if (!args_json || !args_json[0])
		return def;
	if (ai_json_obj_get(args_json, strlen(args_json), key,
			    &v, &vl, &vt) == 1 && vt == AI_JSON_NUM)
		return ai_json_ll(v, vl);
	return def;
}

static int jbool(const char *args_json, const char *key, int def)
{
	const char *v;
	size_t vl;
	int vt;

	if (!args_json || !args_json[0])
		return def;
	if (ai_json_obj_get(args_json, strlen(args_json), key,
			    &v, &vl, &vt) != 1)
		return def;
	if (vt == AI_JSON_BOOL)
		return v[0] == 't';
	if (vt == AI_JSON_NUM)
		return ai_json_ll(v, vl) != 0;
	return def;
}

const char *ai_bpf_errno_name(int err)
{
	switch (err) {
	case 0: return "OK";
	case EPERM: return "EPERM";
	case EACCES: return "EACCES";
	case EINVAL: return "EINVAL";
	case ENOENT: return "ENOENT";
	case ENOSPC: return "ENOSPC";
	case EBADF: return "EBADF";
	case ENOMEM: return "ENOMEM";
	case E2BIG: return "E2BIG";
	case EOPNOTSUPP: return "EOPNOTSUPP";
	case ENOTSUPP: return "ENOTSUPP";
	case EMLINK: return "EMLINK";
	default: return "?";
	}
}

static int bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

/* ------------------------------------------------------------------ */
/* 系统能力探测（全部真读文件）                                        */
/* ------------------------------------------------------------------ */

static int read_small_file(const char *path, char *buf, size_t cap)
{
	int fd;
	ssize_t n;

	if (!cap)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return (int)n;
}

static int read_int_file(const char *path, int *out)
{
	char buf[64];
	char *end;
	long v;

	if (read_small_file(path, buf, sizeof(buf)) < 0)
		return -1;
	errno = 0;
	v = strtol(buf, &end, 10);
	if (errno || end == buf)
		return -1;
	*out = (int)v;
	return 0;
}

/* 读内核 config：/boot/config-$(uname -r) 与 /lib/modules/.../config。
 * 返回 1=y、2=m、0=not set、-1=读不到。 */
static int probe_kernel_cfg(const char *key)
{
	char path[512];
	char line[512];
	struct utsname u;
	FILE *fp;
	int val = -1;
	size_t klen = strlen(key);

	if (uname(&u) != 0)
		return -1;
	snprintf(path, sizeof(path), "/boot/config-%s", u.release);
	fp = fopen(path, "r");
	if (!fp) {
		snprintf(path, sizeof(path), "/lib/modules/%s/config",
			 u.release);
		fp = fopen(path, "r");
	}
	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		if (strlen(line) <= klen)
			continue;
		if (strncmp(line, key, klen) != 0)
			continue;
		if (line[klen] == '=') {
			if (line[klen + 1] == 'y')
				val = 1;
			else if (line[klen + 1] == 'm')
				val = 2;
			else
				val = 0;
			break;
		}
		if (line[klen] == ' ' && strstr(line, "is not set")) {
			val = 0;
			break;
		}
	}
	fclose(fp);
	return val;
}

static int kallsyms_has(const char *sym)
{
	FILE *fp = fopen("/proc/kallsyms", "r");
	char line[512];
	int found = 0;

	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, sym)) {
			found = 1;
			break;
		}
	}
	fclose(fp);
	return found;
}

void ai_bpf_probe_system(struct ai_bpf_probe *p)
{
	struct stat st;

	memset(p, 0, sizeof(*p));
	p->unpriv_bpf_disabled = -1;
	(void)read_int_file("/proc/sys/kernel/unprivileged_bpf_disabled",
			    &p->unpriv_bpf_disabled);
	if (stat("/sys/kernel/btf/vmlinux", &st) == 0 && S_ISREG(st.st_mode)) {
		p->btf_vmlinux = 1;
		p->btf_size = (long long)st.st_size;
	}
	p->cfg_bpf_lsm = probe_kernel_cfg("CONFIG_BPF_LSM");
	p->cfg_nfqueue = probe_kernel_cfg("CONFIG_NETFILTER_NETLINK_QUEUE");
	p->lsm_bpf_active = -1;
	if (read_small_file("/sys/kernel/security/lsm", p->lsm_list,
			    sizeof(p->lsm_list)) >= 0) {
		p->lsm_bpf_active =
			strstr(p->lsm_list, "bpf") != NULL ? 1 : 0;
	}
	p->kallsyms_bpf_lsm = kallsyms_has("bpf_lsm_file_open");
	p->kallsyms_nfqnl = kallsyms_has("nfqnl_recv_config");
}

static const char *cfg_state(int v)
{
	if (v == 1)
		return "y";
	if (v == 2)
		return "m";
	if (v == 0)
		return "n（未编）";
	return "未知";
}

/* 一行能力探测（每个工具输出都带，拒绝"看起来成功"） */
static void probe_line(struct sbuf *b, const struct ai_bpf_probe *p)
{
	sb_add(b, "内核探测: unprivileged_bpf_disabled=%d",
	       p->unpriv_bpf_disabled);
	if (p->unpriv_bpf_disabled == 2)
		sb_add(b, "（非特权永久禁用；root/CAP_BPF 不受影响）");
	else if (p->unpriv_bpf_disabled == 1)
		sb_add(b, "（非特权默认禁用；root/CAP_BPF 不受影响）");
	sb_add(b, " vmlinux_btf=%s", p->btf_vmlinux ? "存在" : "缺失");
	if (p->btf_vmlinux)
		sb_add(b, "(%lld B)", p->btf_size);
	sb_add(b, " CONFIG_BPF_LSM=%s", cfg_state(p->cfg_bpf_lsm));
	sb_add(b, " active_lsm_bpf=%s",
	       p->lsm_bpf_active < 0 ? "未知" :
	       p->lsm_bpf_active ? "是" : "否");
	sb_add(b, " CONFIG_NETFILTER_NETLINK_QUEUE=%s\n",
	       cfg_state(p->cfg_nfqueue));
}

static const char *prog_type_name(__u32 t)
{
	switch (t) {
	case BPF_PROG_TYPE_TRACEPOINT: return "TRACEPOINT";
	case BPF_PROG_TYPE_LSM: return "LSM";
	case BPF_PROG_TYPE_KPROBE: return "KPROBE";
	case BPF_PROG_TYPE_SOCKET_FILTER: return "SOCKET_FILTER";
	case BPF_PROG_TYPE_XDP: return "XDP";
	case BPF_PROG_TYPE_SCHED_CLS: return "SCHED_CLS";
	case BPF_PROG_TYPE_TRACING: return "TRACING";
	case BPF_PROG_TYPE_PERF_EVENT: return "PERF_EVENT";
	default: return "OTHER";
	}
}

/* ------------------------------------------------------------------ */
/* 最小 BTF 解析（BTF 是独立格式，不是 ELF；无第三方库）               */
/* ------------------------------------------------------------------ */

#define AI_BTF_MAGIC		0xeb9f
#define AI_BTF_KIND_INT		1
#define AI_BTF_KIND_PTR		2
#define AI_BTF_KIND_ARRAY	3
#define AI_BTF_KIND_STRUCT	4
#define AI_BTF_KIND_UNION	5
#define AI_BTF_KIND_ENUM	6
#define AI_BTF_KIND_FWD		7
#define AI_BTF_KIND_TYPEDEF	8
#define AI_BTF_KIND_VOLATILE	9
#define AI_BTF_KIND_CONST	10
#define AI_BTF_KIND_RESTRICT	11
#define AI_BTF_KIND_FUNC	12
#define AI_BTF_KIND_FUNC_PROTO	13
#define AI_BTF_KIND_VAR		14
#define AI_BTF_KIND_DATASEC	15
#define AI_BTF_KIND_FLOAT	16
#define AI_BTF_KIND_DECL_TAG	17
#define AI_BTF_KIND_TYPE_TAG	18
#define AI_BTF_KIND_ENUM64	19

struct ai_btf_hdr {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;
	__u32 type_off;
	__u32 type_len;
	__u32 str_off;
	__u32 str_len;
};

struct ai_btf_type {
	__u32 name_off;
	__u32 info;
	__u32 size_type;
};

struct ai_btf_member {
	__u32 name_off;
	__u32 type;
	__u32 offset;
};

static int btf_kind(__u32 info)
{
	return (int)((info >> 24) & 0x1f);
}

static int btf_vlen(__u32 info)
{
	return (int)(info & 0xffff);
}

/* 单条 type 的 payload 字节数；未知 kind 返回 -1（拒绝猜测） */
static long btf_payload_len(int kind, int vlen)
{
	switch (kind) {
	case AI_BTF_KIND_INT: return 4;
	case AI_BTF_KIND_PTR:
	case AI_BTF_KIND_FWD:
	case AI_BTF_KIND_TYPEDEF:
	case AI_BTF_KIND_VOLATILE:
	case AI_BTF_KIND_CONST:
	case AI_BTF_KIND_RESTRICT:
	case AI_BTF_KIND_FUNC:
	case AI_BTF_KIND_FLOAT:
	case AI_BTF_KIND_TYPE_TAG: return 0;
	case AI_BTF_KIND_ARRAY: return 12;
	case AI_BTF_KIND_STRUCT:
	case AI_BTF_KIND_UNION: return (long)vlen * 12;
	case AI_BTF_KIND_ENUM: return (long)vlen * 8;
	case AI_BTF_KIND_FUNC_PROTO: return (long)vlen * 8;
	case AI_BTF_KIND_VAR: return 4;
	case AI_BTF_KIND_DATASEC: return (long)vlen * 12;
	case AI_BTF_KIND_DECL_TAG: return 4;
	case AI_BTF_KIND_ENUM64: return (long)vlen * 12;
	default: return -1;
	}
}

/* 校验头部并给出 type/str 段指针；成功 0 */
static int btf_setup(const void *buf, size_t len, const struct ai_btf_hdr **hout,
		     const unsigned char **tstart, const unsigned char **tend,
		     const char **strs, size_t *strlen_out)
{
	const struct ai_btf_hdr *h = buf;
	size_t need;

	if (!buf || len < sizeof(*h))
		return -1;
	if (h->magic != AI_BTF_MAGIC)
		return -1;
	if (h->hdr_len < sizeof(*h))
		return -1;
	need = (size_t)h->hdr_len + h->type_off + h->type_len;
	if (need > len)
		return -1;
	need = (size_t)h->hdr_len + h->str_off + h->str_len;
	if (need > len)
		return -1;
	*hout = h;
	*tstart = (const unsigned char *)buf + h->hdr_len + h->type_off;
	*tend = *tstart + h->type_len;
	*strs = (const char *)buf + h->hdr_len + h->str_off;
	*strlen_out = h->str_len;
	return 0;
}

static const char *btf_str(const char *strs, size_t strlen_, __u32 off)
{
	if (off >= strlen_)
		return NULL;
	if (!memchr(strs + off, '\0', strlen_ - off))
		return NULL;
	return strs + off;
}

int ai_bpf_btf_find_func(const void *buf, size_t len, const char *name,
			 unsigned int *type_id)
{
	const struct ai_btf_hdr *h;
	const unsigned char *p, *end;
	const char *strs;
	size_t strlen_;
	unsigned char *kinds = NULL;
	long max_ids;
	__u32 id = 0;
	__u32 cand_id = 0, cand_proto = 0;
	int found = 0;

	if (!name || !type_id)
		return -1;
	if (btf_setup(buf, len, &h, &p, &end, &strs, &strlen_) != 0)
		return -1;
	max_ids = (long)(end - p) / 12 + 2;
	kinds = calloc((size_t)max_ids, 1);
	if (!kinds)
		return -1;
	while (p + sizeof(struct ai_btf_type) <= end) {
		struct ai_btf_type t;
		long pay;
		int kind;
		const char *nm;

		memcpy(&t, p, sizeof(t));
		kind = btf_kind(t.info);
		pay = btf_payload_len(kind, btf_vlen(t.info));
		if (pay < 0)
			break;
		if (p + sizeof(t) + pay > end)
			break;
		id++;
		if ((long)id < max_ids)
			kinds[id] = (unsigned char)kind;
		nm = btf_str(strs, strlen_, t.name_off);
		if (!cand_id && kind == AI_BTF_KIND_FUNC && nm &&
		    strcmp(nm, name) == 0) {
			cand_id = id;
			cand_proto = t.size_type;
		}
		p += sizeof(t) + pay;
	}
	/* FUNC 引用的 FUNC_PROTO 可能在 FUNC 之后才出现——整段扫完再判 */
	if (cand_id && cand_proto > 0 && (long)cand_proto < max_ids &&
	    kinds[cand_proto] == AI_BTF_KIND_FUNC_PROTO) {
		*type_id = cand_id;
		found = 1;
	}
	free(kinds);
	return found ? 0 : -1;
}

int ai_bpf_btf_member_offset(const void *buf, size_t len,
			     const char *struct_name, const char *member,
			     unsigned int *offset)
{
	const struct ai_btf_hdr *h;
	const unsigned char *p, *end;
	const char *strs;
	size_t strlen_;

	if (!struct_name || !member || !offset)
		return -1;
	if (btf_setup(buf, len, &h, &p, &end, &strs, &strlen_) != 0)
		return -1;
	while (p + sizeof(struct ai_btf_type) <= end) {
		struct ai_btf_type t;
		long pay;
		int kind;
		const char *nm;

		memcpy(&t, p, sizeof(t));
		kind = btf_kind(t.info);
		pay = btf_payload_len(kind, btf_vlen(t.info));
		if (pay < 0)
			break;
		if (p + sizeof(t) + pay > end)
			break;
		nm = btf_str(strs, strlen_, t.name_off);
		if ((kind == AI_BTF_KIND_STRUCT || kind == AI_BTF_KIND_UNION) &&
		    nm && strcmp(nm, struct_name) == 0) {
			const unsigned char *m = p + sizeof(t);
			int i, vlen = btf_vlen(t.info);

			for (i = 0; i < vlen; i++) {
				struct ai_btf_member mem;
				const char *mname;

				memcpy(&mem, m + (size_t)i * 12, 12);
				mname = btf_str(strs, strlen_, mem.name_off);
				if (mname && strcmp(mname, member) == 0) {
					/* 低 24 位是 bit 偏移（kflag 时高 8
					 * 位是 bitfield 宽度） */
					*offset = (mem.offset & 0xffffff) / 8;
					return 0;
				}
			}
			return -1;	/* struct 找到但成员不存在 */
		}
		p += sizeof(t) + pay;
	}
	return -1;
}

/* 读 vmlinux BTF 到内存；返回 0 并回填 buf/len（调用者 free） */
static int read_vmlinux_btf(void **buf, size_t *len, char *err,
			    size_t errlen)
{
	const char *path = "/sys/kernel/btf/vmlinux";
	struct stat st;
	void *p;
	int fd;
	ssize_t n;
	size_t off = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		set_err(err, errlen,
			"打不开 %s（%s）；无 vmlinux BTF 无法解析 LSM "
			"attach_btf_id（需要 CONFIG_DEBUG_INFO_BTF=y）",
			path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) != 0) {
		set_err(err, errlen, "fstat(%s) 失败：%s", path,
			strerror(errno));
		close(fd);
		return -1;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    st.st_size > AI_BPF_READ_MAX) {
		set_err(err, errlen, "%s 大小非法（%lld B）", path,
			(long long)st.st_size);
		close(fd);
		return -1;
	}
	p = malloc((size_t)st.st_size);
	if (!p) {
		set_err(err, errlen, "内存不足（BTF %lld B）",
			(long long)st.st_size);
		close(fd);
		return -1;
	}
	while (off < (size_t)st.st_size) {
		n = read(fd, (char *)p + off, (size_t)st.st_size - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			set_err(err, errlen, "读 %s 失败：%s", path,
				n == 0 ? "提前 EOF" : strerror(errno));
			free(p);
			close(fd);
			return -1;
		}
		off += (size_t)n;
	}
	close(fd);
	*buf = p;
	*len = (size_t)st.st_size;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 手写 BPF 指令构造                                                   */
/* ------------------------------------------------------------------ */

#define AI_BPF_LDX_DW		0x79	/* ldxdw dst, [src+off] */
#define AI_BPF_LDX_B		0x71	/* ldxb  dst, [src+off] */
#define AI_BPF_MOV64_REG	0xbf
#define AI_BPF_MOV64_IMM	0xb7
#define AI_BPF_ADD64_IMM	0x07
#define AI_BPF_JNE_REG		0x5d
#define AI_BPF_JNE_IMM		0x55
#define AI_BPF_JSLT_IMM		0xc5
#define AI_BPF_CALL		0x85
#define AI_BPF_EXIT		0x95
#define AI_BPF_LD_IMM64		0x18

static struct bpf_insn mk_insn(int code, int dst, int src, int off, int imm)
{
	struct bpf_insn i;

	memset(&i, 0, sizeof(i));
	i.code = (unsigned char)code;
	i.dst_reg = (unsigned char)(dst & 0xf);
	i.src_reg = (unsigned char)(src & 0xf);
	i.off = (short)off;
	i.imm = imm;
	return i;
}

struct bpf_insn *ai_bpf_build_minimal(int *cnt)
{
	struct bpf_insn *v;

	if (!cnt)
		return NULL;
	v = calloc(2, sizeof(*v));
	if (!v)
		return NULL;
	v[0] = mk_insn(AI_BPF_MOV64_IMM, BPF_REG_0, 0, 0, 0);
	v[1] = mk_insn(AI_BPF_EXIT, 0, 0, 0, 0);
	*cnt = 2;
	return v;
}

/* 追加一条 64 位立即数（两条 insn） */
static int emit_imm64(struct bpf_insn *v, int n, int dst, unsigned long long imm)
{
	v[n] = mk_insn(AI_BPF_LD_IMM64, dst, 0, 0,
		       (int)(imm & 0xffffffffU));
	v[n + 1] = mk_insn(0, 0, 0, 0, (int)(imm >> 32));
	return n + 2;
}

struct bpf_insn *ai_bpf_build_deny_path(const char *prefix, int f_path_off,
					int *cnt)
{
	int plen, cap, n = 0, i, off;
	int jumps[64];
	int nj = 0;
	int allow_idx;
	struct bpf_insn *v;
	unsigned long long chunk;

	if (!cnt || !prefix)
		return NULL;
	plen = (int)strlen(prefix);
	if (plen < 1 || plen > AI_BPF_PREFIX_MAX)
		return NULL;
	if (f_path_off < 0 || f_path_off > 0x10000)
		return NULL;
	cap = 32 + (plen / 8) * 4 + (plen % 8) * 2;
	v = calloc((size_t)cap, sizeof(*v));
	if (!v)
		return NULL;

	/* r6 = ctx[0]（LSM 上下文 = 参数数组，args[0]=struct file *） */
	v[n++] = mk_insn(AI_BPF_LDX_DW, BPF_REG_6, BPF_REG_1, 0, 0);
	/* r6 = &file->f_path */
	v[n++] = mk_insn(AI_BPF_ADD64_IMM, BPF_REG_6, 0, 0, f_path_off);
	/* bpf_d_path(&file->f_path, r10 - 128, 128) */
	v[n++] = mk_insn(AI_BPF_MOV64_REG, BPF_REG_1, BPF_REG_6, 0, 0);
	v[n++] = mk_insn(AI_BPF_MOV64_REG, BPF_REG_2, BPF_REG_10, 0, 0);
	v[n++] = mk_insn(AI_BPF_ADD64_IMM, BPF_REG_2, 0, 0, -128);
	v[n++] = mk_insn(AI_BPF_MOV64_IMM, BPF_REG_3, 0, 0, 128);
	v[n++] = mk_insn(AI_BPF_CALL, 0, 0, 0, BPF_FUNC_d_path);
	/* if (len < 0) goto allow */
	jumps[nj++] = n;
	v[n++] = mk_insn(AI_BPF_JSLT_IMM, BPF_REG_0, 0, 0, 0);

	/* 8 字节整块比较 */
	for (off = 0; off + 8 <= plen; off += 8) {
		memcpy(&chunk, prefix + off, 8);
		n = emit_imm64(v, n, BPF_REG_1, chunk);
		v[n++] = mk_insn(AI_BPF_LDX_DW, BPF_REG_2, BPF_REG_10,
				 -128 + off, 0);
		jumps[nj++] = n;
		v[n++] = mk_insn(AI_BPF_JNE_REG, BPF_REG_1, BPF_REG_2, 0, 0);
	}
	/* 余下字节逐个比较（不读越过 NUL 的栈字节） */
	for (i = off; i < plen; i++) {
		v[n++] = mk_insn(AI_BPF_LDX_B, BPF_REG_2, BPF_REG_10,
				 -128 + i, 0);
		jumps[nj++] = n;
		v[n++] = mk_insn(AI_BPF_JNE_IMM, BPF_REG_2, 0, 0,
				 (unsigned char)prefix[i]);
	}
	/* 命中：return -EPERM */
	v[n++] = mk_insn(AI_BPF_MOV64_IMM, BPF_REG_0, 0, 0, -EPERM);
	v[n++] = mk_insn(AI_BPF_EXIT, 0, 0, 0, 0);
	allow_idx = n;
	v[n++] = mk_insn(AI_BPF_MOV64_IMM, BPF_REG_0, 0, 0, 0);
	v[n++] = mk_insn(AI_BPF_EXIT, 0, 0, 0, 0);

	for (i = 0; i < nj; i++) {
		int from = jumps[i];

		v[from].off = (short)(allow_idx - (from + 1));
	}
	*cnt = n;
	return v;
}

/* ------------------------------------------------------------------ */
/* 本进程已加载程序登记表（fd 持有 → 进程退出即回收，零残留）          */
/* ------------------------------------------------------------------ */

struct ai_bpf_loaded {
	int used;
	int fd;
	int link_fd;
	__u32 id;
	__u32 type;
	char name[BPF_OBJ_NAME_LEN + 1];
	char tag[BPF_TAG_SIZE * 2 + 1];
	char sample[24];
	int attached;
};

static struct ai_bpf_loaded g_progs[AI_BPF_MAX_PROGS];

static struct ai_bpf_loaded *reg_find_id(__u32 id)
{
	int i;

	for (i = 0; i < AI_BPF_MAX_PROGS; i++)
		if (g_progs[i].used && g_progs[i].id == id)
			return &g_progs[i];
	return NULL;
}

static void reg_clear(struct ai_bpf_loaded *e)
{
	if (!e)
		return;
	if (e->link_fd >= 0)
		close(e->link_fd);
	if (e->fd >= 0)
		close(e->fd);
	memset(e, 0, sizeof(*e));
	e->fd = -1;
	e->link_fd = -1;
}

static void tag_hex(const __u8 *tag, char *out, size_t n)
{
	int i;

	for (i = 0; i < BPF_TAG_SIZE && (size_t)(i * 2 + 2) < n; i++)
		snprintf(out + i * 2, n - i * 2, "%02x", tag[i]);
	out[BPF_TAG_SIZE * 2] = '\0';
}

static int prog_info(int fd, struct bpf_prog_info *info)
{
	union bpf_attr attr;

	memset(info, 0, sizeof(*info));
	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = (__u32)fd;
	attr.info.info_len = sizeof(*info);
	attr.info.info = (unsigned long long)(unsigned long)info;
	return bpf_sys(BPF_OBJ_GET_INFO_BY_FD, &attr);
}

static int prog_get_id(int fd, __u32 *id)
{
	struct bpf_prog_info info;

	if (prog_info(fd, &info) != 0)
		return -1;
	*id = info.id;
	return 0;
}

static int get_fd_by_id(__u32 id)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_id = id;
	attr.open_flags = 0;
	return bpf_sys(BPF_PROG_GET_FD_BY_ID, &attr);
}

/* ------------------------------------------------------------------ */
/* 附着：LSM → BPF_LINK_CREATE(BPF_LSM_MAC)；TRACEPOINT → perf + link    */
/* ------------------------------------------------------------------ */

static int read_tp_id(const char *group, const char *name, long *id)
{
	char path[512];
	char buf[64];
	char *end;
	long v;
	const char *roots[] = {
		"/sys/kernel/tracing/events",
		"/sys/kernel/debug/tracing/events",
	};
	size_t i;

	for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s/%s/id", roots[i],
			 group, name);
		if (read_small_file(path, buf, sizeof(buf)) < 0)
			continue;
		errno = 0;
		v = strtol(buf, &end, 10);
		if (!errno && end != buf && v > 0) {
			*id = v;
			return 0;
		}
	}
	return -1;
}

static int perf_event_open_tp(long tp_id)
{
	struct perf_event_attr pe;

	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_TRACEPOINT;
	pe.size = sizeof(pe);
	pe.config = (unsigned long long)tp_id;
	pe.sample_period = 1;
	pe.wakeup_events = 1;
	return (int)syscall(__NR_perf_event_open, &pe, -1, 0, -1,
			    PERF_FLAG_FD_CLOEXEC);
}

static int link_create(int prog_fd, int target_fd, __u32 attach_type,
		       __u32 target_btf_id)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.target_fd = (__u32)target_fd;
	attr.link_create.attach_type = attach_type;
	attr.link_create.target_btf_id = target_btf_id;
	return bpf_sys(BPF_LINK_CREATE, &attr);
}

/* 把 group/name 拆开并校验（只允许字母数字下划线） */
static int split_tp(const char *spec, char *group, size_t glen,
		    char *name, size_t nlen)
{
	const char *slash;
	size_t i, gl, nl;

	slash = spec ? strchr(spec, '/') : NULL;
	if (!slash || strchr(slash + 1, '/'))
		return -1;
	gl = (size_t)(slash - spec);
	nl = strlen(slash + 1);
	if (gl == 0 || nl == 0 || gl >= glen || nl >= nlen)
		return -1;
	for (i = 0; i < gl; i++) {
		char c = spec[i];

		if (!(isalnum((unsigned char)c) || c == '_'))
			return -1;
	}
	for (i = 0; i < nl; i++) {
		char c = slash[1 + i];

		if (!(isalnum((unsigned char)c) || c == '_'))
			return -1;
	}
	memcpy(group, spec, gl);
	group[gl] = '\0';
	memcpy(name, slash + 1, nl + 1);
	return 0;
}

/* ------------------------------------------------------------------ */
/* bpf_prog_load                                                       */
/* ------------------------------------------------------------------ */

static void sanitize_prog_name(const char *in, char *out, size_t n)
{
	size_t i, o = 0;

	for (i = 0; in && in[i] && o + 1 < n && o < BPF_OBJ_NAME_LEN; i++) {
		char c = in[i];

		if (isalnum((unsigned char)c) || c == '_')
			out[o++] = c;
		else if (c == '-' || c == '.')
			out[o++] = '_';
	}
	out[o] = '\0';
	if (!o)
		snprintf(out, n, "aik_bpf");
}

static const char *load_fail_hint(int err, const struct ai_bpf_probe *p,
				  __u32 type)
{
	if (err == EPERM || err == EACCES) {
		if (p->unpriv_bpf_disabled == 2)
			return "权限不足：当前进程无 CAP_BPF/CAP_SYS_ADMIN。"
			       "unprivileged_bpf_disabled=2 表示非特权永久"
			       "禁用 bpf()（root 或带 CAP_BPF 的进程不受影响）";
		return "权限不足：BPF_PROG_LOAD 需要 CAP_BPF/CAP_SYS_ADMIN"
		       "（本进程 uid 非 root 或容器缺少 capability）";
	}
	if (type == BPF_PROG_TYPE_LSM) {
		if (p->cfg_bpf_lsm == 0 ||
		    (p->cfg_bpf_lsm < 0 && p->kallsyms_bpf_lsm == 0))
			return "内核未编 BPF_LSM（CONFIG_BPF_LSM=n；"
			       "/proc/kallsyms 无 bpf_lsm_file_open）：当前内核"
			       "（#60）不支持 BPF LSM 程序，需 #61；本次加载"
			       "预期失败，未做任何伪造";
		if (p->kallsyms_bpf_lsm == 0 && p->lsm_bpf_active == 0)
			return "内核编了 BPF_LSM，但活动 LSM 列表不含 bpf"
			       "（启动参数需要 lsm=...,bpf）；程序无法生效";
	}
	if (err == EINVAL)
		return "内核拒绝该程序（EINVAL：prog type/attach_btf_id/"
		       "指令/verifier 校验不通过，详见 verifier log）";
	if (err == ENOTSUPP || err == EOPNOTSUPP)
		return "内核不支持该操作（EOPNOTSUPP）";
	return "BPF_PROG_LOAD 失败";
}

/* 从 AIKBPF01 文件加载；成功返回 insns（malloc）与元数据 */
static int load_from_file(const char *path, struct bpf_insn **insns_out,
			  int *cnt_out, __u32 *type_out, __u32 *eat_out,
			  __u32 *btf_out, char *name_out, size_t nlen,
			  char *license_out, size_t llen,
			  char *err, size_t errlen)
{
	struct ai_bpf_file_hdr h;
	struct stat st;
	__u8 *raw = NULL;
	struct bpf_insn *insns = NULL;
	size_t want, off = 0;
	ssize_t n;
	int fd;

	if (path[0] != '/') {
		set_err(err, errlen, "file 必须是绝对路径（收到 %s）", path);
		return -1;
	}
	if (strstr(path, "..")) {
		set_err(err, errlen, "file 路径不允许包含 ..");
		return -1;
	}
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		set_err(err, errlen, "打不开文件 %s：%s", path,
			strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		set_err(err, errlen, "%s 不是普通文件", path);
		close(fd);
		return -1;
	}
	if (st.st_size < (off_t)sizeof(h) ||
	    st.st_size > AI_BPF_FILE_MAX) {
		set_err(err, errlen, "文件大小 %lld 非法（需 %zu..%d B）",
			(long long)st.st_size, sizeof(h), AI_BPF_FILE_MAX);
		close(fd);
		return -1;
	}
	raw = malloc((size_t)st.st_size);
	if (!raw) {
		set_err(err, errlen, "内存不足");
		close(fd);
		return -1;
	}
	while (off < (size_t)st.st_size) {
		n = read(fd, raw + off, (size_t)st.st_size - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			set_err(err, errlen, "读 %s 失败：%s", path,
				n == 0 ? "提前 EOF" : strerror(errno));
			goto fail;
		}
		off += (size_t)n;
	}
	close(fd);
	fd = -1;
	memcpy(&h, raw, sizeof(h));
	if (memcmp(h.magic, AI_BPF_FILE_MAGIC, 8) != 0) {
		set_err(err, errlen,
			"magic 不是 AIKBPF01（本 loader 不解析 ELF；"
			"自定义格式见 bpf_tools.h）");
		goto fail;
	}
	if (h.insn_cnt == 0 || h.insn_cnt > AI_BPF_INSN_MAX) {
		set_err(err, errlen, "insn_cnt=%u 非法（1..%d）",
			h.insn_cnt, AI_BPF_INSN_MAX);
		goto fail;
	}
	want = sizeof(h) + (size_t)h.insn_cnt * sizeof(struct bpf_insn);
	if (want != (size_t)st.st_size) {
		set_err(err, errlen,
			"文件长度 %zu != 头(%zu)+%u 条指令(%zu)",
			(size_t)st.st_size, sizeof(h), h.insn_cnt,
			(size_t)h.insn_cnt * sizeof(struct bpf_insn));
		goto fail;
	}
	if (!memchr(h.name, '\0', sizeof(h.name)) ||
	    !memchr(h.license, '\0', sizeof(h.license)) ||
	    h.license[0] == '\0') {
		set_err(err, errlen, "name/license 必须 NUL 结尾且 license 非空");
		goto fail;
	}
	if (h.prog_type != BPF_PROG_TYPE_LSM &&
	    h.prog_type != BPF_PROG_TYPE_TRACEPOINT) {
		set_err(err, errlen,
			"prog_type=%u 不支持（本 loader 只支持 LSM=29 / "
			"TRACEPOINT=5）", h.prog_type);
		goto fail;
	}
	insns = malloc((size_t)h.insn_cnt * sizeof(*insns));
	if (!insns) {
		set_err(err, errlen, "内存不足（%u 条指令）", h.insn_cnt);
		goto fail;
	}
	memcpy(insns, raw + sizeof(h),
	       (size_t)h.insn_cnt * sizeof(*insns));
	snprintf(name_out, nlen, "%.*s", (int)sizeof(h.name) - 1, h.name);
	snprintf(license_out, llen, "%.*s", (int)sizeof(h.license) - 1,
		 h.license);
	*insns_out = insns;
	*cnt_out = (int)h.insn_cnt;
	*type_out = h.prog_type;
	*eat_out = h.expected_attach_type;
	*btf_out = h.attach_btf_id;
	free(raw);
	return 0;
fail:
	if (fd >= 0)
		close(fd);
	free(raw);
	free(insns);
	return -1;
}

static int cmd_prog_load(const char *args_json, char **out)
{
	struct ai_bpf_probe probe;
	struct bpf_insn *insns = NULL;
	int insn_cnt = 0;
	__u32 prog_type = 0, expected_attach = 0, attach_btf_id = 0;
	char prog_name[BPF_OBJ_NAME_LEN + 1] = "aik_bpf";
	char license[32] = "GPL";
	char *sample = NULL, *file = NULL, *prefix = NULL, *tps = NULL;
	char *type_s = NULL;
	int attach;
	int rc, err = 0, fd = -1;
	int ret = AI_OK;
	__u32 prog_id = 0, i;
	char verifier[AI_BPF_LOG_SIZE];
	char errbuf[512];
	struct sbuf b;
	struct ai_bpf_loaded *slot = NULL;
	int sample_is_deny = 0;
	void *btf = NULL;
	size_t btf_len = 0;

	memset(&b, 0, sizeof(b));

	*out = NULL;
	ai_bpf_probe_system(&probe);
	sample = jstr(args_json, "sample");
	file = jstr(args_json, "file");
	prefix = jstr(args_json, "prefix");
	tps = jstr(args_json, "tracepoint");
	type_s = jstr(args_json, "prog_type");
	attach = jbool(args_json, "attach", 1);

	if (sample && file) {
		*out = strdup("ERROR[E_PARAM_CONFLICT]: sample 与 file 只能给一个");
		goto out_free;
	}
	if (!sample && !file) {
		*out = strdup("USAGE: bpf_prog_load 需要 sample=minimal|deny_path "
			      "或 file=/abs/path/x.bpf（AIKBPF01 自定义格式）");
		goto out_free;
	}
	if (sample) {
		if (strcmp(sample, "minimal") == 0) {
			prog_type = BPF_PROG_TYPE_TRACEPOINT;
			insns = ai_bpf_build_minimal(&insn_cnt);
			snprintf(prog_name, sizeof(prog_name), "aik_min");
		} else if (strcmp(sample, "deny_path") == 0) {
			unsigned int btf_id, fp_off;
			const char *pfx = prefix && prefix[0] ? prefix :
					  "/tmp/aikbpf";

			prog_type = BPF_PROG_TYPE_LSM;
			expected_attach = BPF_LSM_MAC;
			sample_is_deny = 1;
			if (read_vmlinux_btf(&btf, &btf_len, errbuf,
					     sizeof(errbuf)) != 0) {
				sb_ensure(&b);
				sb_add(&b, "ERROR: %s\n", errbuf);
				probe_line(&b, &probe);
				*out = b.p;
				goto out_free;
			}
			if (ai_bpf_btf_find_func(btf, btf_len,
						 "bpf_lsm_file_open",
						 &btf_id) != 0) {
				sb_ensure(&b);
				sb_add(&b, "ERROR: vmlinux BTF 中找不到 "
				       "bpf_lsm_file_open 的 FUNC 定义——%s；"
				       "拒绝用猜测的 attach_btf_id 加载\n",
				       probe.kallsyms_bpf_lsm == 0 ?
				       "内核未编 BPF_LSM（/proc/kallsyms 也无 "
				       "bpf_lsm_file_open；#60 预期如此，需 #61）" :
				       "BTF 不完整（kallsyms 有该符号）");
				sb_add(&b, "权限说明: 本次失败与 "
				       "unprivileged_bpf_disabled=%d 无关"
				       "（root/CAP_BPF 不受该开关限制）；"
				       "根因是内核未编 BPF_LSM。\n",
				       probe.unpriv_bpf_disabled);
				probe_line(&b, &probe);
				*out = b.p;
				goto out_free;
			}
			if (ai_bpf_btf_member_offset(btf, btf_len, "file",
						     "f_path", &fp_off) != 0) {
				sb_ensure(&b);
				sb_add(&b, "ERROR: vmlinux BTF 中找不到 "
				       "struct file.f_path 成员偏移；拒绝用"
				       "硬编码偏移加载\n");
				probe_line(&b, &probe);
				*out = b.p;
				goto out_free;
			}
			attach_btf_id = btf_id;
			insns = ai_bpf_build_deny_path(pfx, (int)fp_off,
						       &insn_cnt);
			if (!insns) {
				*out = strdup("ERROR[E_PARAM_RANGE]: prefix "
					      "长度必须 1..32 字节");
				goto out_free;
			}
			sanitize_prog_name("aik_deny", prog_name,
					   sizeof(prog_name));
			sb_ensure(&b);
			sb_add(&b, "LSM 解析: attach_btf_id=%u"
			       "（bpf_lsm_file_open）f_path_off=%u "
			       "prefix=\"%s\"\n", btf_id, fp_off, pfx);
		} else {
			*out = strdup("ERROR[E_PARAM_ENUM]: sample 只支持 "
				      "minimal | deny_path");
			goto out_free;
		}
	} else {
		char fname[BPF_OBJ_NAME_LEN + 1];
		char fl[32];
		__u32 ftype, feat, fbtf;

		if (load_from_file(file, &insns, &insn_cnt, &ftype, &feat,
				   &fbtf, fname, sizeof(fname), fl, sizeof(fl),
				   errbuf, sizeof(errbuf)) != 0) {
			sb_ensure(&b);
			sb_add(&b, "ERROR[E_PARAM]: 文件加载失败：%s\n",
			       errbuf);
			probe_line(&b, &probe);
			*out = b.p;
			goto out_free;
		}
		prog_type = ftype;
		expected_attach = feat;
		attach_btf_id = fbtf;
		sanitize_prog_name(fname, prog_name, sizeof(prog_name));
		snprintf(license, sizeof(license), "%s", fl);
		if (prog_type == BPF_PROG_TYPE_LSM && attach_btf_id == 0) {
			unsigned int btf_id;

			if (read_vmlinux_btf(&btf, &btf_len, errbuf,
					     sizeof(errbuf)) != 0 ||
			    ai_bpf_btf_find_func(btf, btf_len,
						 "bpf_lsm_file_open",
						 &btf_id) != 0) {
				sb_ensure(&b);
				sb_add(&b, "ERROR: 文件是 LSM 程序但头里 "
				       "attach_btf_id=0，且无法从 vmlinux BTF "
				       "解析 bpf_lsm_file_open（%s）\n",
				       errbuf[0] ? errbuf : "BTF 中无此 FUNC");
				probe_line(&b, &probe);
				*out = b.p;
				goto out_free;
			}
			attach_btf_id = btf_id;
		}
		if (prog_type == BPF_PROG_TYPE_LSM &&
		    expected_attach != BPF_LSM_MAC) {
			expected_attach = BPF_LSM_MAC;
		}
		if (type_s) {
			__u32 want = strcmp(type_s, "lsm") == 0 ?
				     BPF_PROG_TYPE_LSM :
				     strcmp(type_s, "tracepoint") == 0 ?
				     BPF_PROG_TYPE_TRACEPOINT : 0;

			if (want == 0 || want != prog_type) {
				sb_ensure(&b);
				sb_add(&b, "ERROR[E_PARAM_CONFLICT]: 文件头 "
				       "prog_type=%u 与参数 prog_type=%s 不"
				       "一致（头为准，不覆盖）\n",
				       prog_type, type_s);
				probe_line(&b, &probe);
				*out = b.p;
				goto out_free;
			}
		}
		sb_ensure(&b);
		sb_add(&b, "文件加载: %s（%d 条指令，prog_type=%s）\n",
		       file, insn_cnt, prog_type_name(prog_type));
	}
	if (!insns) {
		*out = strdup("ERROR: 指令构造失败（内存不足）");
		goto out_free;
	}

	/* ---- 真正下发 BPF_PROG_LOAD ---- */
	memset(verifier, 0, sizeof(verifier));
	{
		union bpf_attr attr;

		memset(&attr, 0, sizeof(attr));
		attr.prog_type = prog_type;
		attr.insn_cnt = (__u32)insn_cnt;
		attr.insns = (unsigned long long)(unsigned long)insns;
		attr.license = (unsigned long long)(unsigned long)license;
		attr.log_buf = (unsigned long long)(unsigned long)verifier;
		attr.log_size = sizeof(verifier);
		attr.log_level = 1;
		attr.expected_attach_type = expected_attach;
		attr.attach_btf_id = attach_btf_id;
		snprintf((char *)attr.prog_name, BPF_OBJ_NAME_LEN, "%s",
			 prog_name);
		rc = bpf_sys(BPF_PROG_LOAD, &attr);
		if (rc < 0)
			err = errno;
	}
	if (rc < 0) {
		sb_ensure(&b);
		sb_add(&b, "ERROR: BPF_PROG_LOAD 失败：%s (errno=%d %s)\n",
		       strerror(err), err, ai_bpf_errno_name(err));
		sb_add(&b, "原因: %s\n", load_fail_hint(err, &probe, prog_type));
		sb_add(&b, "程序: type=%s name=%s insns=%d license=%s",
		       prog_type_name(prog_type), prog_name, insn_cnt,
		       license);
		if (sample_is_deny)
			sb_add(&b, " attach_btf_id=%u（bpf_lsm_file_open）",
			       attach_btf_id);
		sb_add(&b, "\n");
		probe_line(&b, &probe);
		if (verifier[0]) {
			sb_add(&b, "verifier log（尾部 1200B）:\n");
			{
				size_t vl = strlen(verifier);

				sb_add(&b, "%s\n",
				       vl > 1200 ? verifier + vl - 1200 :
				       verifier);
			}
		}
		*out = b.p;
		if (!*out)
			*out = strdup("ERROR: BPF_PROG_LOAD 失败（无详情）");
		goto out_free;
	}
	fd = rc;
	if (prog_get_id(fd, &prog_id) != 0) {
		close(fd);
		*out = strdup("ERROR: 程序已加载但读取 prog_id 失败，已关闭 fd");
		goto out_free;
	}

	/* 登记（fd 由本进程持有） */
	for (i = 0; i < AI_BPF_MAX_PROGS; i++)
		if (!g_progs[i].used) {
			slot = &g_progs[i];
			break;
		}
	if (!slot) {
		close(fd);
		sb_ensure(&b);
		sb_add(&b, "ERROR: 本进程最多同时持有 %d 个 BPF 程序，"
		       "已自动卸载刚加载的 prog_id=%u（先 bpf_prog_unload 释放）\n",
		       AI_BPF_MAX_PROGS, prog_id);
		probe_line(&b, &probe);
		*out = b.p;
		goto out_free;
	}
	memset(slot, 0, sizeof(*slot));
	slot->used = 1;
	slot->fd = fd;
	slot->link_fd = -1;
	slot->id = prog_id;
	slot->type = prog_type;
	snprintf(slot->name, sizeof(slot->name), "%s", prog_name);
	snprintf(slot->sample, sizeof(slot->sample), "%s",
		 sample ? sample : "file");

	/* ---- 附着（可选） ---- */
	if (attach) {
		if (prog_type == BPF_PROG_TYPE_LSM) {
			int lfd = link_create(fd, 0, BPF_LSM_MAC, 0);
			int lerr = errno;

			if (lfd < 0) {
				sb_ensure(&b);
				sb_add(&b, "ERROR: LSM 程序已加载（prog_id=%u）"
				       "但 BPF_LINK_CREATE(BPF_LSM_MAC) 失败："
				       "%s (errno=%d)；已自动卸载，零残留\n",
				       prog_id, strerror(lerr), lerr);
				sb_add(&b, "提示: attach 需要活动 LSM 含 bpf"
				       "（lsm=...,bpf）且 CONFIG_BPF_LSM=y\n");
				probe_line(&b, &probe);
				reg_clear(slot);
				*out = b.p;
				goto out_free;
			}
			slot->link_fd = lfd;
			slot->attached = 1;
		} else if (prog_type == BPF_PROG_TYPE_TRACEPOINT) {
			char group[64], tpname[64];
			const char *auto_tp[] = {
				"syscalls/sys_enter_openat",
				"sched/sched_switch",
				"raw_syscalls/sys_enter",
			};
			long tp_id = -1;
			int pfd, lfd, lerr = 0;

			if (tps) {
				if (split_tp(tps, group, sizeof(group),
					     tpname, sizeof(tpname)) != 0 ||
				    read_tp_id(group, tpname, &tp_id) != 0) {
					sb_ensure(&b);
					sb_add(&b, "ERROR: tracepoint=%s 无"
					       "法解析（格式 group/name，且"
					       "tracefs 未挂载或该点不存在）；"
					       "程序已自动卸载\n", tps);
					probe_line(&b, &probe);
					reg_clear(slot);
					*out = b.p;
					goto out_free;
				}
			} else {
				size_t k;

				for (k = 0; k < sizeof(auto_tp) /
					     sizeof(auto_tp[0]); k++) {
					if (split_tp(auto_tp[k], group,
						     sizeof(group), tpname,
						     sizeof(tpname)) == 0 &&
					    read_tp_id(group, tpname,
						       &tp_id) == 0)
						break;
				}
			}
			if (tp_id < 0) {
				sb_ensure(&b);
				sb_add(&b, "ERROR: 找不到可附着的 tracepoint"
				       "（tracefs 未挂载或 syscalls/sched "
				       "tracepoint 未编）；程序已自动卸载。"
				       "可传 tracepoint=group/name 或 attach=false\n");
				probe_line(&b, &probe);
				reg_clear(slot);
				*out = b.p;
				goto out_free;
			}
			pfd = perf_event_open_tp(tp_id);
			if (pfd < 0) {
				lerr = errno;
				sb_ensure(&b);
				sb_add(&b, "ERROR: perf_event_open("
				       "tracepoint %s/%s id=%ld) 失败：%s"
				       " (errno=%d)；程序已自动卸载\n",
				       group, tpname, tp_id, strerror(lerr),
				       lerr);
				probe_line(&b, &probe);
				reg_clear(slot);
				*out = b.p;
				goto out_free;
			}
			lfd = link_create(fd, pfd, BPF_PERF_EVENT, 0);
			lerr = errno;
			close(pfd);
			if (lfd < 0) {
				sb_ensure(&b);
				sb_add(&b, "ERROR: BPF_LINK_CREATE("
				       "BPF_PERF_EVENT) 失败：%s (errno=%d)；"
				       "程序已自动卸载\n",
				       strerror(lerr), lerr);
				probe_line(&b, &probe);
				reg_clear(slot);
				*out = b.p;
				goto out_free;
			}
			slot->link_fd = lfd;
			slot->attached = 1;
		}
	}

	/* ---- 成功输出（复用前面已建好的 sbuf 或新建） ---- */
	if (!b.p) {
		if (sb_ensure(&b) != 0) {
			reg_clear(slot);
			*out = strdup("ERROR: 内存不足");
			goto out_free;
		}
	}
	sb_add(&b, "已加载 BPF 程序（fd 由本进程持有；进程退出或 "
	       "bpf_prog_unload 即释放，零残留）\n");
	sb_add(&b, "prog_id=%u fd=%d type=%s(%u) name=%s insns=%d "
	       "license=%s\n", prog_id, fd, prog_type_name(prog_type),
	       prog_type, prog_name, insn_cnt, license);
	sb_add(&b, "attach=%s", slot->attached ?
	       (prog_type == BPF_PROG_TYPE_LSM ? "lsm(BPF_LSM_MAC)" :
		"perf_event(BPF_PERF_EVENT)") : "未附着（attach=false）");
	if (slot->attached && slot->link_fd >= 0)
		sb_add(&b, " link_fd=%d", slot->link_fd);
	sb_add(&b, "\n");
	if (sample_is_deny)
		sb_add(&b, "deny_path: 路径前缀 \"%s\" 命中时 lsm/file_open "
		       "返回 -EPERM（-1）\n", prefix && prefix[0] ? prefix :
		       "/tmp/aikbpf");
	probe_line(&b, &probe);
	if (prog_type == BPF_PROG_TYPE_LSM && probe.lsm_bpf_active == 0)
		sb_add(&b, "警告: 活动 LSM 列表不含 bpf（%s）——程序已加载%s，"
		       "但 lsm/file_open 当前不会被调用，实际不生效；需要启动"
		       "参数 lsm=...,bpf（留给 #61 验证）\n", probe.lsm_list,
		       slot->attached ? "并附着" : "");
	if (sample_is_deny && probe.cfg_bpf_lsm == 0)
		sb_add(&b, "注意: 当前内核 CONFIG_BPF_LSM=n；本次加载本应"
		       "失败，若成功说明探测口径需要复核\n");
	*out = b.p;
	b.p = NULL;
	sb_free(&b);

out_free:
	if (b.p && b.p != *out)
		sb_free(&b);
	/* 结果文本判定错误类别（参数错误 vs 内核/环境错误）；
	 * 成功文本不含 "ERROR"，失败文本一定含。 */
	if (*out && ret == AI_OK &&
	    (strstr(*out, "ERROR") || strncmp(*out, "USAGE", 5) == 0)) {
		if (strstr(*out, "ERROR[E_PARAM") ||
		    strncmp(*out, "USAGE", 5) == 0)
			ret = AI_ERR_INVALID_ARG;
		else
			ret = AI_ERR_API;
	}
	free(sample);
	free(file);
	free(prefix);
	free(tps);
	free(type_s);
	free(insns);
	free(btf);
	return ret;
}

/* ------------------------------------------------------------------ */
/* bpf_prog_list                                                       */
/* ------------------------------------------------------------------ */

static int cmd_prog_list(const char *args_json, char **out)
{
	struct ai_bpf_probe probe;
	struct sbuf b;
	__u32 id = 0;
	__u32 last_id = 0;
	int n = 0, listed = 0;
	int rc = AI_OK;

	memset(&b, 0, sizeof(b));

	(void)args_json;
	*out = NULL;
	ai_bpf_probe_system(&probe);
	if (sb_ensure(&b) != 0) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	probe_line(&b, &probe);

	for (;;) {
		union bpf_attr attr;
		struct bpf_prog_info info;
		struct ai_bpf_loaded *mine;
		int fd;
		char tag[BPF_TAG_SIZE * 2 + 1];
		char name[BPF_OBJ_NAME_LEN + 1];

		memset(&attr, 0, sizeof(attr));
		attr.start_id = id;
		if (bpf_sys(BPF_PROG_GET_NEXT_ID, &attr) != 0) {
			int err = errno;

			if (err == ENOENT) {
				if (n == 0) {
					sb_add(&b, "未发现已加载的 BPF 程序"
					       "（列表为空）\n");
					*out = b.p;
					return AI_OK;
				}
				break;
			}
			sb_add(&b, "ERROR: BPF_PROG_GET_NEXT_ID 失败：%s"
			       " (errno=%d %s)\n", strerror(err), err,
			       ai_bpf_errno_name(err));
			sb_add(&b, "原因: %s\n", err == EPERM || err == EACCES ?
			       "枚举内核 BPF 程序需要 CAP_BPF/CAP_SYS_ADMIN；"
			       "非 root 在当前内核（unprivileged_bpf_disabled="
			       "2）无法枚举" : "内核拒绝了该查询");
			sb_add(&b, "可用: sudo ai，或先 bpf_prog_load 再 list"
			       "（本进程加载的程序不依赖全局枚举）\n");
			*out = b.p;
			return AI_ERR_API;
		}
		id = attr.next_id;
		if (id <= 0 || (n > 0 && id == last_id)) {
			sb_add(&b, "WARN: BPF_PROG_GET_NEXT_ID 返回非递增 id="
			       "%u，停止枚举（防死循环）\n", id);
			break;
		}
		last_id = id;
		fd = get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			sb_add(&b, "WARN: id=%u 在枚举与取 fd 之间消失（%s）\n",
			       id, strerror(errno));
			continue;
		}
		if (prog_info(fd, &info) != 0) {
			int err = errno;

			close(fd);
			if (err == ENOENT)
				continue;
			sb_add(&b, "ERROR: id=%u OBJ_GET_INFO_BY_FD 失败：%s"
			       " (errno=%d)\n", id, strerror(err), err);
			*out = b.p;
			return AI_ERR_API;
		}
		close(fd);
		tag_hex(info.tag, tag, sizeof(tag));
		memcpy(name, info.name, BPF_OBJ_NAME_LEN);
		name[BPF_OBJ_NAME_LEN] = '\0';
		for (char *q = name; *q; q++)
			if (!isprint((unsigned char)*q))
				*q = '?';
		mine = reg_find_id(info.id);
		sb_add(&b, "prog_id=%u type=%s(%u) name=%s tag=%s "
		       "created_by_uid=%u mine=%s", info.id,
		       prog_type_name(info.type), info.type, name, tag,
		       info.created_by_uid, mine ? "yes" : "no");
		if (mine)
			sb_add(&b, " fd=%d attached=%d", mine->fd,
			       mine->attached);
		sb_add(&b, "\n");
		n++;
		listed++;
		if (listed >= AI_BPF_LIST_MAX) {
			sb_add(&b, "…（超过 %d 条，已截断；只显示前 %d 条）\n",
			       AI_BPF_LIST_MAX, AI_BPF_LIST_MAX);
			break;
		}
	}
	if (n > 0)
		sb_add(&b, "共 %d 个已加载 BPF 程序（mine=yes 为本进程持有，"
		       "其余为系统/其他进程；本工具只能卸载 mine=yes）\n", n);
	*out = b.p;
	return rc;
}

/* ------------------------------------------------------------------ */
/* bpf_prog_unload                                                     */
/* ------------------------------------------------------------------ */

static int cmd_prog_unload(const char *args_json, char **out)
{
	struct ai_bpf_probe probe;
	long long id = jll(args_json, "id", -1);
	struct ai_bpf_loaded *e;
	struct sbuf b;
	int fd;

	memset(&b, 0, sizeof(b));

	*out = NULL;
	ai_bpf_probe_system(&probe);
	if (id < 1) {
		*out = strdup("USAGE: bpf_prog_unload 需要 id（正整数，"
			      "取自 bpf_prog_load 的 prog_id 或 bpf_prog_list）");
		return AI_ERR_INVALID_ARG;
	}
	e = reg_find_id((__u32)id);
	if (!e) {
		sb_ensure(&b);
		sb_add(&b, "ERROR: prog_id=%lld 不是本进程加载的程序，"
		       "拒绝卸载\n", id);
		sb_add(&b, "原因: 卸载靠关闭本进程持有的 prog fd 实现；"
		       "关闭他方程序的 fd 既无权限也做不到（bpf_prog_list "
		       "里 mine=no 的条目只能查询）\n");
		probe_line(&b, &probe);
		*out = b.p;
		return AI_ERR_NOT_FOUND;
	}
	/* 先解附着，再关 prog fd */
	if (e->link_fd >= 0) {
		close(e->link_fd);
		e->link_fd = -1;
		e->attached = 0;
	}
	close(e->fd);
	e->fd = -1;
	memset(e, 0, sizeof(*e));
	e->fd = -1;
	e->link_fd = -1;

	/* 复验：fd 关闭后程序应已从内核消失（无其他引用时） */
	fd = get_fd_by_id((__u32)id);
	if (fd >= 0) {
		int err = errno;

		close(fd);
		sb_ensure(&b);
		sb_add(&b, "ERROR: prog_id=%lld 的 fd 已关闭，但程序仍可从"
		       "内核取到（被其他 fd/链接引用持有），未完全卸载"
		       "（errno=%d）\n", id, err);
		probe_line(&b, &probe);
		*out = b.p;
		return AI_ERR_GENERIC;
	}
	if (errno != ENOENT) {
		sb_ensure(&b);
		sb_add(&b, "ERROR: 复验 prog_id=%lld 时 BPF_PROG_GET_FD_BY_ID "
		       "返回 %s (errno=%d)；无法确认是否已卸载\n", id,
		       strerror(errno), errno);
		probe_line(&b, &probe);
		*out = b.p;
		return AI_ERR_GENERIC;
	}
	sb_ensure(&b);
	sb_add(&b, "已卸载 prog_id=%lld：关闭 prog fd 并复验"
	       "（BPF_PROG_GET_FD_BY_ID → ENOENT），程序已从内核移除\n", id);
	probe_line(&b, &probe);
	*out = b.p;
	return AI_OK;
}

/* ------------------------------------------------------------------ */
/* nfqueue_pump（NETLINK_NETFILTER 12，原始报文）                       */
/* ------------------------------------------------------------------ */

struct ai_nlattr {
	__u16 nla_len;
	__u16 nla_type;
};

#define AI_NLA_ALIGNTO	4
#define AI_NLA_ALIGN(len) (((len) + AI_NLA_ALIGNTO - 1) & \
			   ~(AI_NLA_ALIGNTO - 1))
#define AI_NLA_HDRLEN	((int)AI_NLA_ALIGN(sizeof(struct ai_nlattr)))
#define AI_NLA_TYPE_MASK 0x3fff

#define AI_NFNL_SUBSYS_QUEUE	3
#define AI_NFQ_MSG_PACKET	0
#define AI_NFQ_MSG_VERDICT	1
#define AI_NFQ_MSG_CONFIG	2

#define AI_NFQ_CFG_CMD_NONE	0
#define AI_NFQ_CFG_CMD_BIND	1
#define AI_NFQ_CFG_CMD_UNBIND	2
#define AI_NFQ_CFG_CMD_PF_BIND	3
#define AI_NFQ_CFG_CMD_PF_UNBIND 4

#define AI_NFQ_COPY_NONE	0
#define AI_NFQ_COPY_PACKET	2

#define AI_NFQA_PACKET_HDR	1
#define AI_NFQA_VERDICT_HDR	2
#define AI_NFQA_PAYLOAD		10
#define AI_NFQA_CFG_CMD		1
#define AI_NFQA_CFG_PARAMS	2
#define AI_NFQA_CFG_QUEUE_MAXLEN 3

#define AI_NF_DROP	0
#define AI_NF_ACCEPT	1

static __u16 g_nlseq;

static void nla_put(char *buf, int *off, int maxlen, __u16 type,
		    const void *data, int len)
{
	struct ai_nlattr *a;
	int total = AI_NLA_HDRLEN + len;
	int aligned = AI_NLA_ALIGN(total);

	if (*off + aligned > maxlen)
		return;
	a = (struct ai_nlattr *)(buf + *off);
	a->nla_len = (__u16)total;
	a->nla_type = type;
	if (len)
		memcpy(buf + *off + AI_NLA_HDRLEN, data, (size_t)len);
	memset(buf + *off + total, 0, (size_t)(aligned - total));
	*off += aligned;
}

static int nfq_send(int fd, __u16 msg_type, __u8 family, __u16 res_id,
		    int flags, const void *a1, int a1len,
		    __u16 a1type, const void *a2, int a2len, __u16 a2type,
		    __u32 *seq_out)
{
	char buf[2048];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nfgenmsg *nfg;
	struct sockaddr_nl sa;
	int off;
	ssize_t n;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	nlh->nlmsg_type = (__u16)((AI_NFNL_SUBSYS_QUEUE << 8) | msg_type);
	nlh->nlmsg_flags = (__u16)flags;
	nlh->nlmsg_seq = ++g_nlseq;
	nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(res_id);
	off = (int)nlh->nlmsg_len;
	if (a1 && a1len > 0)
		nla_put(buf, &off, sizeof(buf), a1type, a1, a1len);
	if (a2 && a2len > 0)
		nla_put(buf, &off, sizeof(buf), a2type, a2, a2len);
	nlh->nlmsg_len = (__u32)off;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	n = sendto(fd, buf, nlh->nlmsg_len, 0,
		   (struct sockaddr *)&sa, sizeof(sa));
	if (n < 0)
		return -errno;
	if (seq_out)
		*seq_out = nlh->nlmsg_seq;
	return 0;
}

/* 等 seq 的 ACK；返回 0=ACK，-1=内核错误（*kerr 填 -errno），
 * -2=超时/无 ACK */
static int nfq_wait_ack(int fd, __u32 seq, int timeout_ms, int *kerr)
{
	long long deadline;
	char buf[8192];

	if (kerr)
		*kerr = 0;
	{
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		deadline = (long long)ts.tv_sec * 1000 +
			   ts.tv_nsec / 1000000 + timeout_ms;
	}
	for (;;) {
		struct pollfd pfd;
		long long now;
		struct timespec ts;
		int pr, rem;
		ssize_t n;
		struct nlmsghdr *nlh;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		now = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
		rem = (int)(deadline - now);
		if (rem <= 0)
			return -2;
		pfd.fd = fd;
		pfd.events = POLLIN;
		pr = poll(&pfd, 1, rem);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			return -2;
		}
		if (pr == 0)
			return -2;
		n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -2;
		}
		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned)n);
		     nlh = NLMSG_NEXT(nlh, n)) {
			struct nlmsgerr *e;

			if (nlh->nlmsg_type != NLMSG_ERROR)
				continue;	/* 忽略过渡期 packet */
			if (nlh->nlmsg_seq != seq)
				continue;
			e = (struct nlmsgerr *)NLMSG_DATA(nlh);
			if (e->error == 0)
				return 0;
			if (kerr)
				*kerr = -e->error;
			return -1;
		}
	}
}

/* 配置消息（带 ACK）：nfg_family=nfgenmsg.nfgen_family（PF_BIND 用 AF_*，
 * BIND/UNBIND 用 AF_UNSPEC）；pf=NFQA_CFG_CMD.pf（仅 PF_[UN]BIND 有用） */
static int nfq_config(int fd, __u16 cmd, __u8 nfg_family, __u8 pf,
		      __u16 res_id,
		      const struct nfqnl_msg_config_params *params,
		      __u32 maxlen, int want_ack, int *kerr)
{
	struct nfqnl_msg_config_cmd c;
	struct {
		__u32 maxlen;
	} ml;
	int rc;
	__u32 seq = 0;

	memset(&c, 0, sizeof(c));
	c.command = (__u8)cmd;
	c.pf = htons((__u16)pf);
	ml.maxlen = htonl(maxlen);
	rc = nfq_send(fd, AI_NFQ_MSG_CONFIG, nfg_family, res_id,
		      NLM_F_REQUEST | (want_ack ? NLM_F_ACK : 0),
		      &c, sizeof(c), AI_NFQA_CFG_CMD,
		      params, params ? (int)sizeof(*params) : 0,
		      AI_NFQA_CFG_PARAMS, &seq);
	if (rc < 0) {
		if (kerr)
			*kerr = -rc;
		return -1;
	}
	if (!want_ack)
		return 0;
	rc = nfq_wait_ack(fd, seq, AI_NFQ_ACK_MS, kerr);
	if (rc == 0 && maxlen && params) {
		/* 单独的 maxlen 配置（尽力而为，失败不改判） */
		__u32 s2 = 0;

		rc = nfq_send(fd, AI_NFQ_MSG_CONFIG, nfg_family, res_id,
			      NLM_F_REQUEST | NLM_F_ACK, NULL, 0, 0,
			      &ml, sizeof(ml), AI_NFQA_CFG_QUEUE_MAXLEN,
			      &s2);
		if (rc == 0)
			(void)nfq_wait_ack(fd, s2, AI_NFQ_ACK_MS, NULL);
		return 0;
	}
	return rc;
}

static const struct ai_nlattr *nla_find(const void *data, int len, int type)
{
	const char *p = data;
	int rem = len;

	while (rem >= AI_NLA_HDRLEN) {
		const struct ai_nlattr *a = (const struct ai_nlattr *)p;
		int alen = a->nla_len;

		if (alen < AI_NLA_HDRLEN || alen > rem)
			break;
		if ((a->nla_type & AI_NLA_TYPE_MASK) == type)
			return a;
		rem -= AI_NLA_ALIGN(alen);
		p += AI_NLA_ALIGN(alen);
	}
	return NULL;
}

static int nla_data_len(const struct ai_nlattr *a)
{
	return (int)a->nla_len - AI_NLA_HDRLEN;
}

static const void *nla_data(const struct ai_nlattr *a)
{
	return (const char *)a + AI_NLA_HDRLEN;
}

static void fmt_ipv4(const unsigned char *p, char *out, size_t n)
{
	struct in_addr a;

	memcpy(&a, p, 4);
	if (!inet_ntop(AF_INET, &a, out, (socklen_t)n))
		snprintf(out, n, "?");
}

static void fmt_ipv6(const unsigned char *p, char *out, size_t n)
{
	struct in6_addr a;

	memcpy(&a, p, 16);
	if (!inet_ntop(AF_INET6, &a, out, (socklen_t)n))
		snprintf(out, n, "?");
}

/* 解析五元组；成功 0，失败 -1 */
static int parse_tuple(const unsigned char *p, int len, int family,
		       char *out, size_t outlen)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	char proto[16];
	unsigned int sport = 0, dport = 0;
	int ihl, proto_num;

	if (family == AF_INET) {
		if (len < 20)
			return -1;
		ihl = (p[0] & 0x0f) * 4;
		if ((p[0] >> 4) != 4 || ihl < 20 || len < ihl)
			return -1;
		proto_num = p[9];
		fmt_ipv4(p + 12, src, sizeof(src));
		fmt_ipv4(p + 16, dst, sizeof(dst));
	} else if (family == AF_INET6) {
		if (len < 40)
			return -1;
		if ((p[0] >> 4) != 6)
			return -1;
		proto_num = p[6];
		fmt_ipv6(p + 8, src, sizeof(src));
		fmt_ipv6(p + 24, dst, sizeof(dst));
		ihl = 40;
	} else {
		snprintf(out, outlen, "family=%d raw_len=%d", family, len);
		return 0;
	}
	if (proto_num == 6 || proto_num == 17) {
		if (len >= ihl + 4) {
			sport = ((unsigned int)p[ihl] << 8) | p[ihl + 1];
			dport = ((unsigned int)p[ihl + 2] << 8) |
				p[ihl + 3];
		}
	}
	if (proto_num == 6) {
		snprintf(proto, sizeof(proto), "TCP");
	} else if (proto_num == 17) {
		snprintf(proto, sizeof(proto), "UDP");
	} else if (proto_num == 1) {
		snprintf(proto, sizeof(proto), "ICMP");
	} else if (proto_num == 58) {
		snprintf(proto, sizeof(proto), "ICMPv6");
	} else {
		snprintf(proto, sizeof(proto), "%d", proto_num);
	}
	if (sport || dport)
		snprintf(out, outlen, "%s %s:%u -> %s:%u len=%d", proto,
			 src, sport, dst, dport, len);
	else
		snprintf(out, outlen, "%s %s -> %s len=%d", proto, src, dst,
			 len);
	return 0;
}

static const char *nfq_unavail_hint(int kerr,
				    const struct ai_bpf_probe *p)
{
	int cfg = p ? p->cfg_nfqueue : -1;
	int sym = p ? p->kallsyms_nfqnl : -1;

	if (kerr == ENOTSUPP || kerr == EOPNOTSUPP || kerr == ENOENT ||
	    kerr == ENOPROTOOPT)
		return "本内核未编 nfqueue（CONFIG_NETFILTER_NETLINK_QUEUE=n），"
		       "需 #61";
	if (kerr == EPERM || kerr == EACCES)
		return "权限不足：绑定 NFQUEUE 需要 root/CAP_NET_ADMIN";
	if (kerr == EINVAL && (cfg == 0 || (cfg < 0 && sym == 0)))
		return "本内核未编 nfqueue（CONFIG_NETFILTER_NETLINK_QUEUE=n，"
		       "/proc/kallsyms 无 nfqnl_recv_config），内核返回 "
		       "EINVAL；需 #61";
	if (kerr == EINVAL)
		return "内核拒绝 NFQUEUE 配置（EINVAL）：nfqueue 子系统"
		       "不可用或报文不被接受";
	return "nfqueue 绑定失败";
}

static int cmd_nfqueue_pump(const char *args_json, char **out)
{
	struct ai_bpf_probe probe;
	long long queue = jll(args_json, "queue", 0);
	long long timeout_ms = jll(args_json, "timeout_ms", 3000);
	long long max_packets = jll(args_json, "max_packets", 10);
	char *policy = jstr(args_json, "policy");
	char *family_s = jstr(args_json, "family");
	int family = AF_INET;
	int fd = -1, rc;
	int kerr = 0;
	struct sbuf b;
	int received = 0, verdicts = 0;
	int verdict = AI_NF_ACCEPT;
	long long deadline;
	struct nfqnl_msg_config_params params;
	struct sockaddr_nl sa;

	memset(&b, 0, sizeof(b));

	*out = NULL;
	ai_bpf_probe_system(&probe);
	if (queue < 0 || queue > 65535) {
		*out = strdup("ERROR[E_PARAM_RANGE]: queue 必须在 0..65535");
		free(policy);
		free(family_s);
		return AI_ERR_INVALID_ARG;
	}
	if (timeout_ms < AI_NFQ_TIMEOUT_MIN ||
	    timeout_ms > AI_NFQ_TIMEOUT_MAX) {
		*out = strdup("ERROR[E_PARAM_RANGE]: timeout_ms 必须在 "
			      "100..60000（硬上限，防挂死）");
		free(policy);
		free(family_s);
		return AI_ERR_INVALID_ARG;
	}
	if (max_packets < AI_NFQ_PKTS_MIN ||
	    max_packets > AI_NFQ_PKTS_MAX) {
		*out = strdup("ERROR[E_PARAM_RANGE]: max_packets 必须在 "
			      "1..1000（硬上限）");
		free(policy);
		free(family_s);
		return AI_ERR_INVALID_ARG;
	}
	if (policy && policy[0]) {
		if (strcmp(policy, "accept") == 0)
			verdict = AI_NF_ACCEPT;
		else if (strcmp(policy, "drop") == 0)
			verdict = AI_NF_DROP;
		else {
			*out = strdup("ERROR[E_PARAM_ENUM]: policy 只支持 "
				      "accept | drop");
			free(policy);
			free(family_s);
			return AI_ERR_INVALID_ARG;
		}
	}
	if (family_s && family_s[0]) {
		if (strcmp(family_s, "ipv4") == 0)
			family = AF_INET;
		else if (strcmp(family_s, "ipv6") == 0)
			family = AF_INET6;
		else {
			*out = strdup("ERROR[E_PARAM_ENUM]: family 只支持 "
				      "ipv4 | ipv6");
			free(policy);
			free(family_s);
			return AI_ERR_INVALID_ARG;
		}
	}
	free(policy);
	free(family_s);

	if (sb_ensure(&b) != 0) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	probe_line(&b, &probe);
	if (probe.cfg_nfqueue == 0)
		sb_add(&b, "注意: 内核 config 显示 CONFIG_NETFILTER_NETLINK_"
		       "QUEUE=n；仍尝试绑定以取得真实 errno\n");

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
		    NETLINK_NETFILTER);
	if (fd < 0) {
		int err = errno;

		sb_add(&b, "ERROR: socket(AF_NETLINK, NETLINK_NETFILTER=12) "
		       "失败：%s (errno=%d)\n", strerror(err), err);
		sb_add(&b, "原因: %s\n", nfq_unavail_hint(err, &probe));
		*out = b.p;
		return AI_ERR_GENERIC;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		int err = errno;

		sb_add(&b, "ERROR: bind(netlink) 失败：%s (errno=%d)\n",
		       strerror(err), err);
		close(fd);
		*out = b.p;
		return AI_ERR_GENERIC;
	}

	/* PF_UNBIND：无 handler 时内核会报错，忽略；PF_BIND 才是必需 */
	(void)nfq_config(fd, AI_NFQ_CFG_CMD_PF_UNBIND, AF_UNSPEC,
			 (__u8)family, 0, NULL, 0, 1, NULL);
	rc = nfq_config(fd, AI_NFQ_CFG_CMD_PF_BIND, AF_UNSPEC,
			(__u8)family, 0, NULL, 0, 1, &kerr);
	if (rc != 0 && rc != -2) {
		sb_add(&b, "ERROR: NFQNL_CFG_CMD_PF_BIND(%s) 失败：%s "
		       "(errno=%d)\n", family == AF_INET ? "AF_INET" :
		       "AF_INET6", strerror(kerr), kerr);
		sb_add(&b, "原因: %s\n", nfq_unavail_hint(kerr, &probe));
		sb_add(&b, "本次未绑定任何队列，socket 已关闭（零残留）\n");
		close(fd);
		*out = b.p;
		return AI_ERR_GENERIC;
	}
	if (rc == -2) {
		sb_add(&b, "ERROR: NFQNL_CFG_CMD_PF_BIND 无 ACK（%d ms 超时）\n",
		       AI_NFQ_ACK_MS);
		sb_add(&b, "原因: %s\n", nfq_unavail_hint(ENOTSUPP, &probe));
		close(fd);
		*out = b.p;
		return AI_ERR_GENERIC;
	}

	memset(&params, 0, sizeof(params));
	params.copy_range = htonl(AI_NFQ_PAYLOAD_MAX);
	params.copy_mode = AI_NFQ_COPY_PACKET;
	rc = nfq_config(fd, AI_NFQ_CFG_CMD_BIND, AF_UNSPEC, AF_UNSPEC,
			(__u16)queue, &params, AI_NFQ_MAXLEN, 1, &kerr);
	if (rc != 0 && rc != -2) {
		sb_add(&b, "ERROR: NFQNL_CFG_CMD_BIND(queue=%lld) 失败：%s "
		       "(errno=%d)\n", queue, strerror(kerr), kerr);
		sb_add(&b, "原因: %s\n", nfq_unavail_hint(kerr, &probe));
		sb_add(&b, "socket 已关闭，未留下队列 handler（零残留）\n");
		close(fd);
		*out = b.p;
		return AI_ERR_GENERIC;
	}
	if (rc == -2) {
		sb_add(&b, "ERROR: NFQNL_CFG_CMD_BIND 无 ACK（%d ms 超时）\n",
		       AI_NFQ_ACK_MS);
		sb_add(&b, "原因: %s\n", nfq_unavail_hint(ENOTSUPP, &probe));
		close(fd);
		*out = b.p;
		return AI_ERR_GENERIC;
	}

	sb_add(&b, "已绑定 NFQUEUE queue=%lld family=%s copy_range=%d "
	       "maxlen=%d；等待 %lld ms / 最多 %lld 包，policy=%s\n",
	       queue, family == AF_INET ? "ipv4" : "ipv6",
	       AI_NFQ_PAYLOAD_MAX, AI_NFQ_MAXLEN, timeout_ms, max_packets,
	       verdict == AI_NF_ACCEPT ? "accept" : "drop");
	sb_add(&b, "注意: 本工具不安装 nft/iptables 规则；没有规则的队列"
	       "收不到包（会等到超时，这是预期而非故障）\n");

	{
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		deadline = (long long)ts.tv_sec * 1000 +
			   ts.tv_nsec / 1000000 + timeout_ms;
	}
	while (received < (int)max_packets) {
		struct pollfd pfd;
		struct timespec ts;
		long long now;
		int rem, pr;
		char buf[65536 + 512];
		ssize_t n;
		struct nlmsghdr *nlh;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		now = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
		rem = (int)(deadline - now);
		if (rem <= 0)
			break;
		pfd.fd = fd;
		pfd.events = POLLIN;
		pr = poll(&pfd, 1, rem);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (pr == 0)
			break;
		n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned)n);
		     nlh = NLMSG_NEXT(nlh, n)) {
			const struct nfgenmsg *nfg;
			const struct ai_nlattr *a;
			const struct nfqnl_msg_packet_hdr *ph;
			struct nfqnl_msg_verdict_hdr vh;
			char tuple[256];
			int alen, plen;

			if (nlh->nlmsg_type == NLMSG_ERROR ||
			    nlh->nlmsg_type == NLMSG_DONE ||
			    nlh->nlmsg_type == NLMSG_OVERRUN)
				continue;
			if ((nlh->nlmsg_type & 0xff) != AI_NFQ_MSG_PACKET ||
			    (nlh->nlmsg_type >> 8) != AI_NFNL_SUBSYS_QUEUE)
				continue;
			nfg = (const struct nfgenmsg *)NLMSG_DATA(nlh);
			alen = (int)nlh->nlmsg_len - (int)NLMSG_HDRLEN -
			       (int)sizeof(struct nfgenmsg);
			if (alen < 0)
				continue;
			a = nla_find((const char *)nfg + sizeof(*nfg), alen,
				     AI_NFQA_PACKET_HDR);
			if (!a || nla_data_len(a) < (int)sizeof(*ph))
				continue;
			ph = nla_data(a);
			a = nla_find((const char *)nfg + sizeof(*nfg), alen,
				     AI_NFQA_PAYLOAD);
			plen = a ? nla_data_len(a) : 0;
			if (a && plen > 0) {
				if (parse_tuple(nla_data(a), plen,
						nfg->nfgen_family, tuple,
						sizeof(tuple)) != 0)
					snprintf(tuple, sizeof(tuple),
						 "unparsed family=%d len=%d",
						 nfg->nfgen_family, plen);
			} else {
				snprintf(tuple, sizeof(tuple),
					 "no-payload（copy_range=0？）");
			}
			received++;
			memset(&vh, 0, sizeof(vh));
			vh.verdict = htonl((__u32)verdict);
			vh.id = ph->packet_id;
			rc = nfq_send(fd, AI_NFQ_MSG_VERDICT,
				      nfg->nfgen_family, (__u16)queue,
				      NLM_F_REQUEST, &vh, sizeof(vh),
				      AI_NFQA_VERDICT_HDR, NULL, 0, 0, NULL);
			if (rc == 0)
				verdicts++;
			sb_add(&b, "pkt#%d id=%u hook=%u %s -> %s%s\n",
			       received, ntohl(ph->packet_id), ph->hook,
			       tuple,
			       verdict == AI_NF_ACCEPT ? "ACCEPT" : "DROP",
			       rc == 0 ? "" : "（verdict 发送失败）");
			if (received >= (int)max_packets)
				break;
		}
	}

	/* 清理：显式 UNBIND（socket 关闭时内核也会释放 handler） */
	(void)nfq_config(fd, AI_NFQ_CFG_CMD_UNBIND, AF_UNSPEC, AF_UNSPEC,
			 (__u16)queue, NULL, 0, 0, NULL);
	(void)nfq_config(fd, AI_NFQ_CFG_CMD_PF_UNBIND, AF_UNSPEC,
			 (__u8)family, 0, NULL, 0, 0, NULL);
	close(fd);

	if (received == 0)
		sb_add(&b, "结果: 绑定成功，但 %lld ms 内未收到任何包"
		       "（队列没有 nft/iptables 规则引流；如需实测，先加 "
		       "`nft add rule ... queue num %lld` 再重跑）\n",
		       timeout_ms, queue);
	else
		sb_add(&b, "结果: 收到 %d 包，发送 %d 个 verdict（policy=%s），"
		       "已 UNBIND 并关闭 socket（零残留）\n", received,
		       verdicts, verdict == AI_NF_ACCEPT ? "accept" : "drop");
	*out = b.p;
	return AI_OK;
}

/* ------------------------------------------------------------------ */
/* 通道分发                                                            */
/* ------------------------------------------------------------------ */

int exec_bpf_channel(const void *tool, const char *args_json, char **out)
{
	const struct ai_tool *t = tool;

	if (!out)
		return AI_ERR_INVALID_ARG;
	*out = NULL;
	if (!t || !t->name) {
		*out = strdup("ERROR: bpf 工具缺失注册信息");
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(t->name, "bpf_prog_load") == 0)
		return cmd_prog_load(args_json, out);
	if (strcmp(t->name, "bpf_prog_list") == 0)
		return cmd_prog_list(args_json, out);
	if (strcmp(t->name, "bpf_prog_unload") == 0)
		return cmd_prog_unload(args_json, out);
	if (strcmp(t->name, "nfqueue_pump") == 0)
		return cmd_nfqueue_pump(args_json, out);
	*out = strdup("ERROR: 未知 bpf 工具（注册表异常）");
	return AI_ERR_INVALID_ARG;
}
