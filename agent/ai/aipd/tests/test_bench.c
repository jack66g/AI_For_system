/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_bench.c - bench 子命令烟测（AIPD_BENCH 行格式=p99 测点台架合同）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

/* 跑 `./aipd bench --n n` 并解析 AIPD_BENCH 行；0=成功 */
static int run_bench(long n, long *out_n, unsigned long long *p50,
		     unsigned long long *p99, unsigned long long *mx)
{
	char cmd[128];
	FILE *p;
	char line[256];
	int rc;

	snprintf(cmd, sizeof(cmd), "./aipd bench --n %ld", n);
	p = popen(cmd, "r");
	if (!p)
		return -1;
	if (!fgets(line, sizeof(line), p)) {
		pclose(p);
		return -1;
	}
	rc = pclose(p);
	if (rc == -1 || !WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
		return -1;
	if (sscanf(line, "AIPD_BENCH n=%ld p50_ns=%llu p99_ns=%llu "
		   "max_ns=%llu", out_n, p50, p99, mx) != 4)
		return -1;
	return 0;
}

int main(void)
{
	long n;
	unsigned long long p50, p99, mx;

	/* 格式合同：恰一字段序 n/p50/p99/max（Lane-B m1_bench 解析锚） */
	CHECK(run_bench(10000, &n, &p50, &p99, &mx) == 0,
	      "bench 10k runs and parses");
	CHECK(n == 10000, "n echoed");
	CHECK(p50 > 0 && p99 >= p50 && mx >= p99, "latency ordering");
	CHECK(p99 < 100000000ULL, "p99 sanity <100ms");
	if (p99 >= 1000000ULL)			/* 1ms 验收线（门禁复跑提示） */
		printf("NOTE: p99_ns=%llu >= 1ms (gate re-run advised)\n",
		       p99);
	CHECK(run_bench(1, &n, &p50, &p99, &mx) == 0 && n == 1,
	      "bench n=1 minimal");
	{
		int rc = system("./aipd bench --n 0 >/dev/null 2>&1");

		CHECK(rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) != 0,
		      "bench n=0 rejected");
	}

	if (fails) {
		printf("test_bench: %d failures (%d checks)\n", fails,
		       checks);
		return 1;
	}
	printf("test_bench: OK (%d checks)\n", checks);
	return 0;
}
