/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_feat.c - 特征输入源（map35 裸 bpf() | mock jsonl）
 *
 * map35：k7feat.c 手法——bpf() syscall 契约自搓（NR/命令/attr 偏移），
 * 不引 libbpf/内核 uapi；BPF_MAP_CREATE(type=35) 一次 + 逐 CPU
 * BPF_MAP_LOOKUP_ELEM 轮转取 seq 最新槽。EPERM/ENOSYS/EINVAL（非
 * AI 内核）→ 按 conf 诚实失败或降级 mock（计数+journal 明示）。
 *
 * mock：逐行 jsonl（字段镜像 ai_feature_vec；8 字段缺一=坏行计数跳过）。
 *
 * 新鲜度：aip_feat_is_stale——ts（ktime_get_ns，CLOCK_MONOTONIC 同域）
 * 距今 > 3×采样期（采样期=max(内核 1Hz, 1/POLL_HZ)）。
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "aip_feat.h"
#include "aip_util.h"

/* ---- 偏移锁死（冻结契约 ai_features.h:42-51 / k7feat.c 镜像） ---- */
_Static_assert(sizeof(struct aip_fvec) == 48, "ai_feature_vec==48B");
_Static_assert(offsetof(struct aip_fvec, seq) == 0, "off seq");
_Static_assert(offsetof(struct aip_fvec, ts) == 8, "off ts");
_Static_assert(offsetof(struct aip_fvec, lat_ewma_ns) == 16, "off lat");
_Static_assert(offsetof(struct aip_fvec, iowait_pct) == 24, "off iowait");
_Static_assert(offsetof(struct aip_fvec, psi_mem_some) == 28, "off psi");
_Static_assert(offsetof(struct aip_fvec, cache_misses) == 32, "off cache");
_Static_assert(offsetof(struct aip_fvec, valid_bits) == 40, "off valid");
_Static_assert(offsetof(struct aip_fvec, rsv) == 44, "off rsv");

/* ---- bpf() 系统调用契约（x86_64，k7feat.c 同源自搓） ---- */
#define NR_BPF			321
#define BPF_MAP_CREATE		0
#define BPF_MAP_LOOKUP_ELEM	1
#define BPF_MAP_TYPE_AI_FEATURES	35
#define BPF_ATTR_SZ		128	/* union bpf_attr 128B 全量传 */
#define OFF_MAP_TYPE		0	/* u32 */
#define OFF_KEY_SIZE		4	/* u32 */
#define OFF_VALUE_SIZE		8	/* u32 */
#define OFF_MAX_ENTRIES		12	/* u32 */
#define OFF_MAP_FLAGS		16	/* u32 */
#define OFF_MAP_FD		0	/* u32（lookup 用） */
#define OFF_KEY_PTR		8	/* u64 */
#define OFF_VALUE_PTR		16	/* u64 */

static void kput_u32(void *p, size_t off, uint32_t v)
{
	memcpy((unsigned char *)p + off, &v, sizeof(v));
}

static void kput_u64(void *p, size_t off, uint64_t v)
{
	memcpy((unsigned char *)p + off, &v, sizeof(v));
}

static long bpf_syscall(long cmd, void *attr, uint32_t size)
{
	errno = 0;
	return syscall(NR_BPF, cmd, attr, size);
}

/* 单测锚：attr 打包可复验（k7feat selftest 同口径） */
int aip_feat_pack_create(unsigned char attr[BPF_ATTR_SZ])
{
	memset(attr, 0, BPF_ATTR_SZ);
	kput_u32(attr, OFF_MAP_TYPE, BPF_MAP_TYPE_AI_FEATURES);
	kput_u32(attr, OFF_KEY_SIZE, 4);
	/* value_size/max_entries 传 0：内核钳制为 sizeof(vec)/nr_cpu_ids */
	return 0;
}

static int map35_create(int *fd_out)
{
	unsigned char attr[BPF_ATTR_SZ];
	int fd;

	(void)aip_feat_pack_create(attr);
	fd = (int)bpf_syscall(BPF_MAP_CREATE, attr, sizeof(attr));
	if (fd < 0)
		return -1;
	*fd_out = fd;
	return 0;
}

static int map35_lookup(int fd, uint32_t cpu, struct aip_fvec *out)
{
	unsigned char attr[BPF_ATTR_SZ];
	uint32_t key = cpu;

	memset(attr, 0, sizeof(attr));
	kput_u32(attr, OFF_MAP_FD, (uint32_t)fd);
	kput_u64(attr, OFF_KEY_PTR, (uint64_t)(uintptr_t)&key);
	kput_u64(attr, OFF_VALUE_PTR, (uint64_t)(uintptr_t)out);
	return (int)bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr, sizeof(attr));
}

/* ---- 新鲜度 ---- */

static uint64_t mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int aip_feat_is_stale(uint64_t ts, long long thresh_ns)
{
	uint64_t now = mono_ns();

	if (ts == 0)			/* 从未发布=诚实陈旧 */
		return 1;
	if (thresh_ns <= 0)
		return 0;
	if (now > ts)
		return (now - ts) > (uint64_t)thresh_ns;
	return 1;			/* 时钟回退/未来 ts：如实报陈旧 */
}

/* ---- mock jsonl 解析（极简数值抽取：8 字段全中） ---- */

static int json_num(const char *line, const char *key, uint64_t *out)
{
	char pat[32];
	const char *p;

	if (snprintf(pat, sizeof(pat), "\"%s\":", key) >= (int)sizeof(pat))
		return -1;
	p = strstr(line, pat);
	if (!p)
		return -1;
	p += strlen(pat);
	{
		char *end;
		unsigned long long v;

		errno = 0;
		v = strtoull(p, &end, 10);
		if (errno != 0 || end == p)
			return -1;
		*out = (uint64_t)v;
	}
	return 0;
}

static int json_num_u32(const char *line, const char *key, uint32_t *out)
{
	uint64_t v;

	if (json_num(line, key, &v) != 0 || v > 0xffffffffULL)
		return -1;
	*out = (uint32_t)v;
	return 0;
}

int aip_mock_parse_line(const char *line, struct aip_fvec *out)
{
	struct aip_fvec v;

	if (!line || !out)
		return -1;
	memset(&v, 0, sizeof(v));
	if (json_num(line, "seq", &v.seq) != 0 ||
	    json_num(line, "ts", &v.ts) != 0 ||
	    json_num(line, "lat_ewma_ns", &v.lat_ewma_ns) != 0 ||
	    json_num_u32(line, "iowait_pct", &v.iowait_pct) != 0 ||
	    json_num_u32(line, "psi_mem_some", &v.psi_mem_some) != 0 ||
	    json_num(line, "cache_misses", &v.cache_misses) != 0 ||
	    json_num_u32(line, "valid_bits", &v.valid_bits) != 0)
		return -1;
	*out = v;
	return 0;
}

/* ---- 源生命周期 ---- */

static int mock_open(struct aip_feat_src *f, const char *path, char *err,
		     size_t errcap)
{
	FILE *mf = fopen(path, "r");

	if (!mf) {
		if (err && errcap)
			snprintf(err, errcap, "open mock %s: %s", path,
				 strerror(errno));
		return -1;
	}
	f->mockf = mf;
	return 0;
}

int aip_feat_open(struct aip_feat_src *f, const struct aip_conf *c,
		  char *err, size_t errcap)
{
	memset(f, 0, sizeof(*f));
	f->map_fd = -1;
	f->type = c->feat_source == 1 ? AIP_FEAT_MOCK : AIP_FEAT_MAP35;

	/* 新鲜度阈值：3 × max(内核 1s, 轮询周期) */
	{
		long long poll_ns = 1000000000LL / (c->poll_hz > 0 ?
						    c->poll_hz : 1);
		long long period = poll_ns >
			(long long)AIP_FEAT_KERNEL_PERIOD_NS ?
			poll_ns : (long long)AIP_FEAT_KERNEL_PERIOD_NS;

		f->stale_thresh_ns = 3 * period;
	}

	if (f->type == AIP_FEAT_MOCK) {
		if (mock_open(f, c->feat_mock_file, err, errcap) != 0)
			return -1;
		snprintf(f->mock_path, sizeof(f->mock_path), "%s",
			 c->feat_mock_file);
		return 0;
	}
	/* map35 主路 */
	{
		int fd;

		if (map35_create(&fd) != 0) {
			int e = errno;

			aip_warn_ratelimit("map35-create", 60000,
					   "map35 create: %s (non-AI kernel "
					   "or no CAP_BPF)", strerror(e));
			if (!c->feat_degrade_mock) {
				if (err && errcap)
					snprintf(err, errcap,
						 "BPF_MAP_CREATE(type=35): %s "
						 "(FEAT_DEGRADE_MOCK=0 honest "
						 "fail)", strerror(e));
				return -1;
			}
			if (mock_open(f, c->feat_mock_file, err, errcap) != 0)
				return -1;
			f->type = AIP_FEAT_MOCK;
			f->mock_degraded = 1;
			snprintf(f->mock_path, sizeof(f->mock_path), "%s",
				 c->feat_mock_file);
			aip_log("map35 unavailable — DEGRADED to mock %s "
				"(counted, honest)", c->feat_mock_file);
			return 0;
		}
		f->map_fd = fd;
		f->ncpu = (unsigned)sysconf(_SC_NPROCESSORS_CONF);
		if (f->ncpu == 0)
			f->ncpu = 1;
		return 0;
	}
}

static FILE *mock_file(const struct aip_feat_src *f)
{
	return f->mockf;
}

int aip_feat_poll(struct aip_feat_src *f, struct aip_fvec *out, int *stale)
{
	f->polls++;
	if (!out || !stale)
		return -1;
	memset(out, 0, sizeof(*out));
	*stale = 0;

	if (f->type == AIP_FEAT_MOCK) {
		char line[512];
		FILE *mf = mock_file(f);

		if (!mf) {
			f->errors++;
			return -1;
		}
		if (fgets(line, sizeof(line), mf)) {
			struct aip_fvec v;

			if (aip_mock_parse_line(line, &v) != 0) {
				f->bad_lines++;
				return -1;
			}
			*out = v;
			f->have_line = 1;
			f->last = v;
		} else {
			/* EOF/读失败：复用最后向量（诚实 stale 自判） */
			if (!f->have_line) {
				f->empty_polls++;
				return -1;
			}
			*out = f->last;
		}
		f->ok++;
		*stale = aip_feat_is_stale(out->ts, f->stale_thresh_ns);
		if (*stale)
			f->stale_polls++;
		return 0;
	}

	/* map35：游标轮转扫全部 CPU，取 seq 最大槽 */
	{
		struct aip_fvec best;
		int any = 0;

		memset(&best, 0, sizeof(best));
		for (unsigned i = 0; i < f->ncpu; i++) {
			unsigned cpu = (f->cpu_cursor + i) % f->ncpu;
			struct aip_fvec v;

			memset(&v, 0, sizeof(v));
			if (map35_lookup(f->map_fd, cpu, &v) != 0) {
				if (errno != ENOENT)
					f->errors++;
				continue;	/* 槽缺/读失败：跳过该 CPU */
			}
			if (!any || v.seq > best.seq) {
				best = v;
				any = 1;
			}
		}
		f->cpu_cursor = (f->cpu_cursor + 1) % (f->ncpu ? f->ncpu : 1);
		if (!any) {
			f->empty_polls++;
			return -1;
		}
		*out = best;
		f->ok++;
		*stale = aip_feat_is_stale(out->ts, f->stale_thresh_ns);
		if (*stale)
			f->stale_polls++;
		return 0;
	}
}

void aip_feat_close(struct aip_feat_src *f)
{
	if (f->mockf) {
		fclose(f->mockf);
		f->mockf = NULL;
	}
	if (f->map_fd >= 0) {
		close(f->map_fd);
		f->map_fd = -1;
	}
}
