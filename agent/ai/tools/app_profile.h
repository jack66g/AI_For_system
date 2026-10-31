/* SPDX-License-Identifier: GPL-2.0 */
/*
 * app_profile.h - W81 V4 应用画像三件套（TOOL_CH_APPPROFILE）
 *
 * 件目（三件）：
 *   1. app_profile_static   静态画像（R/D0）："它要什么"
 *      ELF 头（类型/架构/PIE/NX/RELRO/解释器）+ readelf -d 动态依赖
 *      （NEEDED/SONAME/RPATH/RUNPATH/BIND_NOW/TEXTREL，绝不用会执行
 *      加载器的 ldd）+ 动态符号概要 + getcap/security.capability xattr +
 *      setuid/setgid + .desktop（Exec/autostart/sandbox 字段）+ dpkg -S
 *      包来源。缺失工具/非 ELF/权限不足/文件不存在一律降级明说，不崩。
 *   2. app_profile_dynamic  动态画像（W2/D2）："它实际碰了什么"
 *      只在现有 workspace（aik-sandbox：独立 mount/pid/uts namespace、
 *      no_new_privs、能力清空）里跑一次目标程序；程序与参数双重白名单
 *      （只允许 ls/cat/tar -t/curl --version 等无害形态），超时强杀。
 *      文件访问优先用沙盒内 strace（ptrace 子进程，open/openat/
 *      openat2/execve/connect/bind/rename/unlink/... 全量），strace 不
 *      可用时退化为 /proc/<pid>/ 采样（fd + fdinfo flags + maps + 子进程
 *      树 + /proc/net/{tcp,tcp6,udp,udp6} 按 socket inode 归属）。
 *      输出 JSON 事件流。
 *   3. app_profile_diff     差集报告（W1/D1）："偷偷碰了什么"
 *      输入目标路径 + app_profile_dynamic 的 JSON，重新采集静态画像，
 *      输出三栏（要的/用的/偷偷碰的）+ 0-100 风险分 + 放行条件建议。
 *      只读分析：不写 nft、不改权限、不执行任何策略。
 *
 * 安全边界：
 *   - 静态画像全部走有界 fork/execv（无 shell），readelf/dpkg/getcap
 *     超时即杀，输出按尾部环形缓冲截断；
 *   - 动态画像目标必须在系统 bin 目录（/usr/bin、/bin、/usr/sbin、
 *     /sbin、/usr/local/bin、/usr/local/sbin）且命中基名白名单；tar 只
 *     允许列表模式，curl 只允许 --version/--help，sort 禁 -o，date 禁
 *     -s 等参数级闸门；
 *   - 动态执行强制 net=none（新建工作区时），无外发能力；已有工作区
 *     按其元数据如实标注；
 *   - 差集报告只给建议，绝不自动落策略。
 */
#ifndef _AI_APP_PROFILE_H
#define _AI_APP_PROFILE_H

#include <stddef.h>

#define AP_MAX_NEEDED	64
#define AP_MAX_RUNPATH	8
#define AP_PATH_MAX	4096
#define AP_EV_PATH	512
#define AP_MAX_EVENTS	1024
#define AP_TEXT_MAX	(192 * 1024)

/* readelf -d 解析结果（纯数据，编译与单测共用） */
struct ap_dynsec {
	char needed[AP_MAX_NEEDED][128];
	int needed_n;
	char soname[128];
	char rpath[AP_MAX_RUNPATH][512];
	int rpath_n;
	char runpath[AP_MAX_RUNPATH][512];
	int runpath_n;
	int bind_now;
	int pie_flag;
	int textrel;
};

/* readelf --dyn-syms 概要 */
struct ap_symcount {
	int total;
	int func;
	int object;
	int ifunc;
	int tls;
	int notype;
	int undef;
};

/* .desktop 命中结果 */
struct ap_desktop {
	int found;
	int autostart;
	char path[AP_PATH_MAX];
	char name[256];
	char exec[512];
	char tryexec[256];
	char type[64];
	char terminal[16];
	char sandbox[512];
};

/* /proc/net/tcp 行解码结果 */
struct ap_netinfo {
	char proto[8];
	char local[64];
	char remote[64];
	char state[16];		/* ESTABLISHED 需要 12 字节 */
	char inode[24];
};

/* 动态事件类型 */
enum ap_ev_type {
	AP_EV_FILE_READ = 0,
	AP_EV_FILE_WRITE,
	AP_EV_FILE_MMAP,
	AP_EV_PROC_EXEC,
	AP_EV_NET_CONNECT,
	AP_EV_NET_LISTEN,
	AP_EV_NET_UNIX,
};

struct ap_event {
	int type;
	int pid;
	int count;		/* 去重合并次数 */
	char path[AP_EV_PATH];
	char proto[8];
	char local[64];
	char remote[64];
	char state[16];
	long long inode;
	char note[64];
};

/* ===================== 纯函数（导出供单测） ===================== */

const char *ap_elf_type_str(unsigned type);
const char *ap_elf_machine_str(unsigned machine);

/* readelf -d 文本 → struct ap_dynsec；0 成功，-1 失败（err 必填） */
int ap_dyn_parse(const char *txt, struct ap_dynsec *d, char *err,
		 size_t errcap);

/* readelf --dyn-syms 文本 → 概要；0 成功，-1 失败 */
int ap_dynsym_parse(const char *txt, struct ap_symcount *s, char *err,
		    size_t errcap);

/* dpkg -S 文本 → 包名；0 找到，1 未打包，-1 错误 */
int ap_dpkg_s_parse(const char *txt, char *pkg, size_t pkgcap, char *err,
		    size_t errcap);

/* .desktop 文本 → 命中（Exec/TryExec 首 token 基名 == target_base） */
int ap_desktop_parse_text(const char *text, const char *target_base,
			  struct ap_desktop *d);

/* /proc/net/tcp 单行（已按空白切分前的原文）→ 端口/地址解码 */
int ap_procnet_decode(const char *line, const char *proto,
		      struct ap_netinfo *n);

/* 目标可执行文件白名单（realpath 必须落在系统 bin 目录且基名命中） */
int ap_target_allowed(const char *realpath, char *err, size_t errcap);

/* 参数级白名单（tar 只列表、curl 只版本/帮助、sort 禁 -o、date 禁 -s） */
int ap_arg_allowed(const char *base, char *const argv[], int argc, char *err,
		   size_t errcap);

/* strace 单行 → 一个事件；1 产出（out 有效），0 忽略，-1 失败打开 */
int ap_strace_line(const char *line, struct ap_event *out, int *failed);

/* 事件去重追加：1 新增，0 合并（count++），-1 满 */
int ap_event_add(struct ap_event *ev, int *n, int max,
		 const struct ap_event *e);

/* app_profile_dynamic 的 JSON 事件流 → 事件数组 */
int ap_dynamic_json_to_events(const char *json, struct ap_event *ev, int max,
			      int *n, int *truncated, char *err,
			      size_t errcap);

/* ===================== 执行器入口 ===================== */

int exec_app_profile_channel(const void *tool, const char *args_json,
			     char **out);

#endif /* _AI_APP_PROFILE_H */
