/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_netlink_batch.c - K2b：客户端库 AI_CMD_ACT_BATCH 嵌套 NLA 编码
 * 单测（L1 可跑，无内核依赖）。
 *
 * 黄金字节与 Python aikernel-api nl_pack_act_batch / C 孪生
 * apic api_nl_pack_act_batch 三方逐字节一致（差分锚：编码漂移即败）。
 * 覆盖：完整嵌套形态（含 pid 元组+rollback+token）、无 pid 单元组、
 * 重复 param 拒收、超 27 拒收、容量不足防御。
 */
#include <stdio.h>
#include <string.h>

#include "ai_types.h"
#include "netlink/ai_netlink_client.h"

static int g_fails;
static int g_checks;

#define CHECK(cond) do { \
	g_checks++; \
	if (!(cond)) { \
		g_fails++; \
		printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

static void hex_of(const unsigned char *p, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++)
		snprintf(out + i * 2, 3, "%02x", p[i]);
}

static void test_pack_golden(void)
{
	unsigned char attrs[AI_BATCH_ATTRS_MAX];
	char hex[AI_BATCH_ATTRS_MAX * 2 + 1];
	struct ai_nl_batch_op ops[2];
	struct ai_nl_batch_opts opts;
	size_t len = 0;
	int rc;

	memset(ops, 0, sizeof(ops));
	strcpy(ops[0].param, "mm.swappiness");
	ops[0].value = 60;
	ops[0].pid = 0;
	strcpy(ops[1].param, "sched.nice");
	ops[1].value = 19;
	ops[1].pid = 4242;
	memset(&opts, 0, sizeof(opts));
	opts.auto_rollback_ms = 5000;
	opts.confirm_token = 0xdeadbeef;

	rc = ai_nl_pack_act_batch(attrs, sizeof(attrs), ops, 2, &opts, &len);
	CHECK(rc == AI_OK);
	CHECK(len == 140);
	hex_of(attrs, len, hex);
	CHECK(strcmp(hex,
		     "24000180120003006d6d2e7377617070696e6573730000000c000e00"
		     "3c00000000000000280001800f00030073636865642e6e69636500000c"
		     "000e00130000000000000008000f009210000008000200881300000c"
		     "000300efbeadde000000000c00080000000000000000000c000900000"
		     "00000000000000c000a00000000000000000008000c0000000000") == 0);
}

static void test_pack_single(void)
{
	unsigned char attrs[AI_BATCH_ATTRS_MAX];
	char hex[AI_BATCH_ATTRS_MAX * 2 + 1];
	struct ai_nl_batch_op ops[1];
	struct ai_nl_batch_opts opts;
	size_t len = 0;

	memset(ops, 0, sizeof(ops));
	strcpy(ops[0].param, "llm.top_k");
	ops[0].value = 40;
	memset(&opts, 0, sizeof(opts));
	CHECK(ai_nl_pack_act_batch(attrs, sizeof(attrs), ops, 1, &opts,
				   &len) == AI_OK);
	CHECK(len == 96);
	hex_of(attrs, len, hex);
	/* 尾部批级 attr：INTENT(0x0a) 12B + AGENT(0x0c) 8B */
	CHECK(strcmp(hex + (len - 20) * 2,
		     "0c000a00000000000000000008000c0000000000") == 0);
	/* 首 attr：OPS|NLA_F_NESTED(0x8001) len=0x24 内嵌 PARAM(28B)+VALUE(12B) */
	CHECK(strncmp(hex, "20000180" "0e000300", 16) == 0);
}

static void test_pack_rejects(void)
{
	unsigned char attrs[AI_BATCH_ATTRS_MAX];
	struct ai_nl_batch_op ops[2];
	struct ai_nl_batch_opts opts;
	struct ai_nl_batch_op big[AI_BATCH_MAX_OPS + 1];
	size_t len = 0;
	size_t i;

	memset(&opts, 0, sizeof(opts));
	memset(ops, 0, sizeof(ops));
	strcpy(ops[0].param, "llm.top_k");
	ops[0].value = 1;
	strcpy(ops[1].param, "llm.top_k");	/* 重复 param */
	ops[1].value = 2;
	CHECK(ai_nl_pack_act_batch(attrs, sizeof(attrs), ops, 2, &opts,
				   &len) == AI_ERR_INVALID_ARG);
	memset(big, 0, sizeof(big));
	for (i = 0; i < AI_BATCH_MAX_OPS + 1; i++) {
		strcpy(big[i].param, "llm.top_k");
		big[i].value = (__u64)i;
	}
	/* 同名 28 个先撞重复 param——改互异名验证 27 上限 */
	for (i = 0; i < AI_BATCH_MAX_OPS + 1; i++)
		snprintf(big[i].param, sizeof(big[i].param), "p%02zu", i);
	CHECK(ai_nl_pack_act_batch(attrs, sizeof(attrs), big,
				   AI_BATCH_MAX_OPS + 1, &opts,
				   &len) == AI_ERR_INVALID_ARG);
	CHECK(ai_nl_pack_act_batch(attrs, sizeof(attrs), big,
				   AI_BATCH_MAX_OPS, &opts,
				   &len) == AI_OK);
	/* 容量不足防御：1B 缓冲必拒 */
	CHECK(ai_nl_pack_act_batch(attrs, 1, big, 1, &opts,
				   &len) == AI_ERR_INVALID_ARG);
	/* n=0 拒收 */
	CHECK(ai_nl_pack_act_batch(attrs, sizeof(attrs), big, 0, &opts,
				   &len) == AI_ERR_INVALID_ARG);
}

int main(void)
{
	test_pack_golden();
	test_pack_single();
	test_pack_rejects();
	if (g_fails) {
		printf("test_netlink_batch: %d FAIL (%d checks)\n",
		       g_fails, g_checks);
		return 1;
	}
	printf("test_netlink_batch: all pass (%d checks)\n", g_checks);
	return 0;
}
