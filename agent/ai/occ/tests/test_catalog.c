/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_catalog.c - occ 目录快照解析/查询单测（T9a2）
 *
 * 用例：正常解析（字段逐断言）/ 坏 JSON / 缺字段容错 / 无 id 跳过 /
 * 空目录 / find（id+别名+厂商）/ by_provider / search 子串。
 * 真数据冒烟：设 OCC_SNAPSHOT=<真快照路径> 时加载并断言规模（L1 用）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "occ_llm/occ_catalog.h"

static int fails;

#define OK(cond, name) do { \
	if (cond) { printf("ok %s\n", name); } \
	else { printf("FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); fails++; } \
} while (0)

static const char FIXTURE[] =
	"{\"_meta\":{\"format\":\"occ-catalog-snapshot/1\","
	"\"source\":\"https://models.opencode.ai/experimental/v2.0/api.json\","
	"\"fetched_utc\":\"2026-11-06T19:47:43Z\","
	"\"original_sha256\":\"5919dab6a18334592a2021a5ffb3be30cbe173f1de732bf6991d33264fedac59\"},"
	"\"providers\":{"
	"\"anthropic\":{\"name\":\"Anthropic\",\"models\":{"
	"\"claude-sonnet-4-5\":{\"id\":\"claude-sonnet-4-5\","
	"\"canonical_id\":\"anthropic/claude-sonnet-4-5\",\"name\":\"Claude Sonnet 4.5\","
	"\"type\":\"chat\",\"context_limit\":200000,\"max_output\":64000,"
	"\"cost_input_per_m\":3.0,\"cost_output_per_m\":15.0,"
	"\"cost_cache_read\":0.3,\"cost_cache_write\":3.75,"
	"\"tools\":true,\"reasoning\":true,\"release_date\":\"2025-09-29\"},"
	"\"claude-2\":{\"id\":\"claude-2\",\"name\":\"Claude 2\","
	"\"type\":\"chat\",\"status\":\"deprecated\","
	"\"context_limit\":100000,\"max_output\":4000,\"tools\":false}"
	"}},"
	"\"deepseek\":{\"name\":\"DeepSeek\",\"models\":{"
	"\"deepseek-flash\":{\"id\":\"deepseek-flash\","
	"\"canonical_id\":\"deepseek/deepseek-flash\",\"name\":\"DeepSeek Flash\","
	"\"type\":\"chat\",\"context_limit\":128000,\"max_output\":8192,"
	"\"cost_input_per_m\":0.27,\"cost_output_per_m\":1.1,"
	"\"tools\":true,\"reasoning\":false}"
	"}},"
	"\"broken\":{\"name\":\"Broken Co\",\"models\":{"
	"\"no-id\":{\"name\":\"Ghost\"},"
	"\"half\":{\"id\":\"half\",\"type\":\"decision\"}"
	"}}}}";

static const char BAD_JSON[] = "{\"providers\":{{{";
static const char EMPTY_OBJ[] = "{}";
static const char EMPTY_PROVIDERS[] =
	"{\"_meta\":{},\"providers\":{}}";

static char *write_tmp(const char *content)
{
	char tmpl[] = "/tmp/occ-cat-test-XXXXXX";
	int fd = mkstemp(tmpl);
	FILE *f;
	char *path;

	if (fd < 0)
		return NULL;
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		return NULL;
	}
	fputs(content, f);
	fclose(f);
	path = malloc(64);
	if (path)
		snprintf(path, 64, "%s", tmpl);
	return path;
}

static void test_parse_normal(void)
{
	char *p = write_tmp(FIXTURE);
	occ_catalog c;
	const occ_catalog_model *m;

	OK(p != NULL, "fixture-write");
	if (occ_catalog_load(&c, p) == 0) {
		OK(c.nmodels == 4, "count-4");
		OK(c.nskipped == 1, "skip-no-id");
		OK(!strcmp(c.source,
			   "https://models.opencode.ai/experimental/v2.0/api.json"),
		   "meta-source");
		OK(!strcmp(c.original_sha256,
			   "5919dab6a18334592a2021a5ffb3be30cbe173f1de732bf6991d33264fedac59"),
		   "meta-sha256");
		OK(!strcmp(c.fetched_utc, "2026-11-06T19:47:43Z"),
		   "meta-fetched");
		m = occ_catalog_find(&c, "anthropic", "claude-sonnet-4-5");
		OK(m != NULL, "find-exact");
		if (m) {
			OK(m->context_limit == 200000, "ctx-limit");
			OK(m->max_output == 64000, "max-out");
			OK(m->tools == 1 && m->reasoning == 1, "caps");
			OK(m->cost_input_per_m == 3.0, "cost-in");
			OK(m->cost_output_per_m == 15.0, "cost-out");
			OK(m->cost_cache_read == 0.3, "cost-cr");
			OK(m->cost_cache_write == 3.75, "cost-cw");
			OK(m->is_chat == 1, "is-chat");
			OK(m->is_deprecated == 0, "not-deprecated");
			OK(!strcmp(m->provider_name, "Anthropic"),
			   "provider-name");
		}
		/* 别名（canonical_id）命中 */
		m = occ_catalog_find(&c, "deepseek",
				     "deepseek/deepseek-flash");
		OK(m != NULL, "find-alias-canonical");
		/* 厂商过滤不对 → NULL */
		m = occ_catalog_find(&c, "anthropic", "deepseek-flash");
		OK(m == NULL, "find-wrong-provider");
		occ_catalog_free(&c);
	} else {
		OK(0, "parse-normal-load");
	}
	unlink(p);
	free(p);
}

static void test_bad_and_empty(void)
{
	char *p;
	occ_catalog c;

	p = write_tmp(BAD_JSON);
	OK(occ_catalog_load(&c, p) == -1, "bad-json-rejected");
	unlink(p);
	free(p);

	p = write_tmp(EMPTY_OBJ);
	OK(occ_catalog_load(&c, p) == 0 && c.nmodels == 0, "empty-obj-ok");
	occ_catalog_free(&c);
	unlink(p);
	free(p);

	p = write_tmp(EMPTY_PROVIDERS);
	OK(occ_catalog_load(&c, p) == 0 && c.nmodels == 0,
	   "empty-providers-ok");
	occ_catalog_free(&c);
	unlink(p);
	free(p);

	OK(occ_catalog_load(&c, "/nonexistent/occ.json") == -1,
	   "missing-file-rejected");
}

static void test_defaults_and_queries(void)
{
	char *p = write_tmp(FIXTURE);
	occ_catalog c;
	const occ_catalog_model *out[16];
	size_t n;

	if (occ_catalog_load(&c, p) != 0) {
		OK(0, "query-load");
		unlink(p);
		free(p);
		return;
	}
	/* 缺字段条目默认值：half（仅 id+type） */
	{
		const occ_catalog_model *m = occ_catalog_find(&c, "broken",
							      "half");
		OK(m != NULL, "half-found");
		if (m) {
			OK(m->context_limit == 0, "half-default-ctx");
			OK(m->tools == 0, "half-default-tools");
			OK(m->is_chat == 0, "half-is-decision");
			OK(m->is_deprecated == 0, "half-not-deprecated");
			OK(!strcmp(m->canonical_id, "broken/half"),
			   "half-default-alias");
		}
	}
	/* by_provider */
	n = occ_catalog_by_provider(&c, "anthropic", out, 16);
	OK(n == 2, "by-provider-anthropic-2");
	n = occ_catalog_by_provider(&c, NULL, out, 16);
	OK(n == 4, "by-provider-all-4");
	n = occ_catalog_by_provider(&c, "nobody", out, 16);
	OK(n == 0, "by-provider-none");
	/* search 子串（大小写不敏感） */
	n = occ_catalog_search(&c, "SONNET", 0, out, 16);
	OK(n == 1, "search-sonnet");
	n = occ_catalog_search(&c, "claude", 0, out, 16);
	OK(n == 1, "search-claude-excl-deprecated");
	n = occ_catalog_search(&c, "claude", 1, out, 16);
	OK(n == 2, "search-claude-incl-deprecated");
	n = occ_catalog_search(&c, "", 0, out, 16);
	OK(n == 3, "search-empty-all-nondep");
	n = occ_catalog_search(&c, "zzz-not-exist", 1, out, 16);
	OK(n == 0, "search-miss");
	occ_catalog_free(&c);
	unlink(p);
	free(p);
}

static void test_real_snapshot_smoke(void)
{
	const char *snap = getenv("OCC_SNAPSHOT");

	if (!snap || !*snap) {
		printf("ok real-snapshot-smoke (skipped: OCC_SNAPSHOT unset)\n");
		return;
	}
	{
		occ_catalog c;

		if (occ_catalog_load(&c, snap) == 0) {
			OK(c.nmodels > 8000, "real-snapshot-size");
			OK(c.nskipped == 0, "real-snapshot-no-skip");
			OK(occ_catalog_find(&c, "anthropic",
					    "claude-sonnet-4-5") != NULL,
			   "real-find-anthropic");
			OK(occ_catalog_find(&c, "deepseek",
					    "deepseek-flash") != NULL,
			   "real-find-deepseek");
			printf("  real snapshot: %zu models, %zu skipped\n",
			       c.nmodels, c.nskipped);
			occ_catalog_free(&c);
		} else {
			OK(0, "real-snapshot-load");
		}
	}
}

int main(void)
{
	test_parse_normal();
	test_bad_and_empty();
	test_defaults_and_queries();
	test_real_snapshot_smoke();
	if (fails) {
		printf("test_catalog: FAIL(%d)\n", fails);
		return 1;
	}
	printf("test_catalog: ALL GREEN\n");
	return 0;
}
