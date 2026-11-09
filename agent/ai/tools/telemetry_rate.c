// SPDX-License-Identifier: GPL-2.0
/*
 * telemetry_rate.c - I-2 采样率写口工具面实现
 * （cat:ev 枚举表+默认率表内置、越界人话报错、status 读回校验）
 */
#define _GNU_SOURCE	/* asprintf（executor.c 同款） */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ai_types.h"
#include "telemetry_rate.h"

/* 18 大类：名/ev 上界/一句话（ai_telemetry.h:64-81 大类 + :88-215 子类计数） */
const struct tel_rate_cat tel_rate_cats[TEL_RATE_CAT_MAX] = {
	{ 1,  "sched",        8,  "01 CPU与调度（01.01 上下文切换 … 01.08 调度域）" },
	{ 2,  "mm",          10,  "02 内存管理（02.01 页分配 … 02.10 内存错误）" },
	{ 3,  "io",           6,  "03 I/O与存储（03.01 块层 BIO … 03.06 字符设备）" },
	{ 4,  "net",         10,  "04 网络（04.01 Socket … 04.10 设备级网络）" },
	{ 5,  "user_input",   5,  "05 用户输入（05.01 TTY … 05.05 命令行和执行）" },
	{ 6,  "process",      7,  "06 进程与线程（06.01 生命周期 … 06.07 Futex）" },
	{ 7,  "fs",           6,  "07 文件系统（07.01 VFS … 07.06 文件系统错误）" },
	{ 8,  "security",     8,  "08 安全事件（08.01 LSM … 08.08 内核加固违规）" },
	{ 9,  "interrupt",    5,  "09 中断与异常（09.01 中断 … 09.05 softirq）" },
	{ 10, "lock",         4,  "10 锁竞争与同步（10.01 mutex … 10.04 rtmutex）" },
	{ 11, "time",         4,  "11 时间与定时器（11.01 定时器 … 11.04 延迟）" },
	{ 12, "power",        5,  "12 电源管理（12.01 频率调速 … 12.05 热管理）" },
	{ 13, "virt",         5,  "13 虚拟化（13.01 vCPU … 13.05 半虚拟化）" },
	{ 14, "bpf",          4,  "14 BPF/Tracing/Perf（14.01 BPF 程序 … 14.04 Perf）" },
	{ 15, "user_behavior", 6, "15 用户行为（15.01 会话 … 15.06 GPU/加速器）" },
	{ 16, "hw",           5,  "16 硬件与驱动（16.01 设备 … 16.05 PCI/资源）" },
	{ 17, "kconfig",      3,  "17 内核构建与配置（17.01 配置变更 … 17.03 构建）" },
	{ 18, "ai",           2,  "18 AI 自我观测（18.01 决策 … 18.02 决策结果）" },
};
const size_t tel_rate_cats_n = TEL_RATE_CAT_MAX;

/* 默认率表（全量 1 之外仅三处；ai_telemetry.c:421-427 初始化实测） */
const struct tel_rate_default tel_rate_defaults[] = {
	{ 16, 1, 16 },	/* HW.DEVICE  1/16（AI_TEL_DEVICE_SAMPLE） */
	{ 16, 4, 64 },	/* HW.DMA     1/64（AI_TEL_DMA_SAMPLE） */
	{ 17, 2, 16 },	/* KCONFIG.SYSCTL 1/16（AI_TEL_SYSCTL_SAMPLE） */
};
const size_t tel_rate_defaults_n = sizeof(tel_rate_defaults) /
				   sizeof(tel_rate_defaults[0]);

static const struct tel_rate_cat *cat_lookup(unsigned cat)
{
	if (cat < TEL_RATE_CAT_MIN || cat > TEL_RATE_CAT_MAX)
		return NULL;
	return &tel_rate_cats[cat - 1];
}

/* 默认率查表（未收录=1 全量） */
static unsigned default_rate(unsigned cat, unsigned ev)
{
	for (size_t i = 0; i < tel_rate_defaults_n; i++)
		if (tel_rate_defaults[i].cat == cat &&
		    tel_rate_defaults[i].ev == ev)
			return tel_rate_defaults[i].rate;
	return 1;
}

int tel_rate_parse(const char *value, unsigned *cat, unsigned *ev,
		   unsigned *n, char *err, size_t errcap)
{
	const char *s = value;
	unsigned long long v[3];
	const struct tel_rate_cat *c;

	if (err && errcap)
		err[0] = '\0';
	if (!value) {
		if (err && errcap)
			snprintf(err, errcap, "value 为空（格式 cat:ev:N，如 16:1:64）");
		return -1;
	}
	while (*s == ' ' || *s == '\t')
		s++;
	if (strncmp(s, "rate=", 5) == 0)
		s += 5;
	for (int k = 0; k < 3; k++) {
		char *end;

		if (k > 0) {
			if (*s != ':') {
				if (err && errcap)
					snprintf(err, errcap,
						 "格式错（需三段冒号分隔 cat:ev:N，如 16:1:64）: %s",
						 value);
				return -1;
			}
			s++;
		}
		/* 段内空白/符号拒绝（首段已去首空白；负号走这里一并拒） */
		if (*s < '0' || *s > '9') {
			if (err && errcap)
				snprintf(err, errcap,
					 "第 %d 段不是十进制数字（段内不接受空白/符号）: %s",
					 k + 1, value);
			return -1;
		}
		errno = 0;
		v[k] = strtoull(s, &end, 10);
		if (end == s || errno != 0) {
			if (err && errcap)
				snprintf(err, errcap,
					 "第 %d 段不是十进制数字: %s",
					 k + 1, value);
			return -1;
		}
		s = end;
	}
	while (*s == ' ' || *s == '\t')
		s++;
	if (*s != '\0') {
		if (err && errcap)
			snprintf(err, errcap,
				 "尾部有多余内容（只接受 cat:ev:N 三段）: %s",
				 value);
		return -1;
	}
	c = cat_lookup((unsigned)v[0]);
	if (!c) {
		if (err && errcap)
			snprintf(err, errcap,
				 "未知大类 cat=%llu（有效 %d..%d，18 大类见 ai_telemetry.h:64-81）",
				 v[0], TEL_RATE_CAT_MIN, TEL_RATE_CAT_MAX);
		return -1;
	}
	if (v[1] < 1 || v[1] > c->ev_max) {
		if (err && errcap)
			snprintf(err, errcap,
				 "cat=%u(%s) 的子类 ev=%llu 越界（有效 1..%u，该类 %s）",
				 c->cat, c->name, v[1], c->ev_max, c->desc);
		return -1;
	}
	if (v[2] > TEL_RATE_N_MAX) {
		if (err && errcap)
			snprintf(err, errcap,
				 "采样率 N=%llu 超出 0..%d（0=丢弃该事件全部后续样本，1=全量，N=每 N 条记 1 条；内核会钳到 65535——请显式写 65535）",
				 v[2], TEL_RATE_N_MAX);
		return -1;
	}
	*cat = (unsigned)v[0];
	*ev = (unsigned)v[1];
	*n = (unsigned)v[2];
	return 0;
}

int tel_rate_status_find(const char *status_path, unsigned cat, unsigned ev,
			 unsigned *rate)
{
	FILE *f;
	char line[512];

	f = fopen(status_path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		unsigned rc, re, rr;

		if (sscanf(line, " sample_rate[cat=%u ev=%u]=%u",
			   &rc, &re, &rr) == 3 ||
		    sscanf(line, "sample_rate[cat=%u ev=%u]=%u",
			   &rc, &re, &rr) == 3) {
			if (rc == cat && re == ev) {
				if (rate)
					*rate = rr;
				fclose(f);
				return 1;
			}
		}
	}
	fclose(f);
	return 0;
}

int tel_rate_run(const char *value, const char *write_path,
		 const char *status_path, char **out)
{
	unsigned cat, ev, n;
	char err[320];
	char wbuf[64];
	int fd;
	ssize_t wr;
	int found;
	unsigned rb = 0;
	unsigned def;

	*out = NULL;
	if (tel_rate_parse(value, &cat, &ev, &n, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: %s", err) < 0)
			*out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	def = default_rate(cat, ev);
	snprintf(wbuf, sizeof(wbuf), "rate=%u:%u:%u\n", cat, ev, n);

	fd = open(write_path, O_WRONLY);
	if (fd < 0) {
		const int e = errno;

		int r;

		if (e == ENOENT || e == ENOTDIR)
			r = asprintf(out,
				     "ERROR: 无 %s（非 AIKernel 内核或 ai.enabled=0——读回工具 procfs_read_status 也拿不到）: %s",
				     write_path, strerror(e));
		else if (e == EPERM || e == EACCES)
			r = asprintf(out,
				     "ERROR: 写 %s 被拒: %s（写口需 CAP_SYS_ADMIN，请以 root/sudo 运行）",
				     write_path, strerror(e));
		else
			r = asprintf(out, "ERROR: 打开 %s 失败: %s",
				     write_path, strerror(e));
		if (r < 0)
			*out = NULL;
		return e == ENOENT || e == ENOTDIR ? AI_ERR_NOT_FOUND :
						     AI_ERR_GENERIC;
	}
	wr = write(fd, wbuf, strlen(wbuf));
	if (wr < 0) {
		const int e = errno;

		close(fd);
		int r;

		if (e == EINVAL)
			r = asprintf(out,
				     "ERROR: 内核拒收（cat/ev 越界或 telemetry 未启用——本工具已按枚举表预校验，若仍拒收请对拍 AI_EV_MAX 内核版本）: %s",
				     strerror(e));
		else
			r = asprintf(out, "ERROR: 写 %s 失败: %s", write_path,
				     strerror(e));
		if (r < 0)
			*out = NULL;
		return AI_ERR_GENERIC;
	}
	close(fd);

	/* 读回校验（/proc/ai/status 非默认率行；18 类不在内核列表——如实注记） */
	found = tel_rate_status_find(status_path, cat, ev, &rb);
	{
		const struct tel_rate_cat *c = cat_lookup(cat);
		char verify[384];
		char hint[160];

		verify[0] = '\0';
		if (cat == TEL_RATE_CAT_MAX)
			snprintf(verify, sizeof(verify),
				 "读回：18 类(ai)不在 /proc/ai/status 采样率列表（内核循环只到 17 类，ai_procfs.c:112）——写成功以内核无 -EINVAL 为准");
		else if (found == 1 && rb == n)
			snprintf(verify, sizeof(verify),
				 "读回校验一致：/proc/ai/status sample_rate[cat=%u ev=%u]=%u",
				 cat, ev, rb);
		else if (found == 1)
			snprintf(verify, sizeof(verify),
				 "读回不一致：status sample_rate[cat=%u ev=%u]=%u（请求 %u）——可能有并发写，请复核",
				 cat, ev, rb, n);
		else if (n == 1)
			snprintf(verify, sizeof(verify),
				 "读回校验一致：status 无非默认行（仅列非 1 项）＝该条已回全量 1");
		else if (found == 0)
			snprintf(verify, sizeof(verify),
				 "读回未见非默认行（等效全量 1）与请求 N=%u 不一致——可能有并发写或写被吞，请复核",
				 n);
		else
			snprintf(verify, sizeof(verify),
				 "读回校验跳过：/proc/ai/status 读失败（%s）",
				 strerror(errno));

		hint[0] = '\0';
		if (def != 1 && n != def)
			snprintf(hint, sizeof(hint),
				 "（出厂默认 %u，恢复写 %u:%u:%u）", def, cat,
				 ev, def);
		else if (def == 1 && n != 1)
			snprintf(hint, sizeof(hint),
				 "（出厂默认全量 1，恢复写 %u:%u:1）", cat, ev);
		if (asprintf(out,
			     "OK: 已写 %s <- %s（%u.%02u %s/%s）%s；%s。率表易失：重启即默认，无持久化。",
			     write_path, wbuf, cat, ev,
			     c ? c->name : "?",
			     n == 0 ? "丢弃全部后续样本" :
			     n == 1 ? "全量" : "每 N 条记 1 条",
			     hint, verify) < 0)
			*out = NULL;
	}
	return AI_OK;
}
