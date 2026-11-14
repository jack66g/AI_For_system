// SPDX-License-Identifier: GPL-2.0
/*
 * ai_mlp_test.c - AIKWMDL v1 MLP 模型 KUnit 测试（K6，KERNEL-K6-DESIGN §3）
 *
 * 覆盖（模型核心为施工 A 并行改动，本套按设计册契约 + K5 勘探现状编写；
 * 对 A 的接口形态假设见各用例注释与施工报告「契约差异清单」）：
 *   - 合法最小模型解析 + 推理数值（手算 Q31 期望值：2 层带偏置/ReLU 网
 *     与 3 层 1→1→1→1 网，全部权重取 Q31 可精确表示的 2 的幂组合，
 *     期望 float32 位级比对，无浮点指令参与断言）；
 *   - 解析拒绝：magic 错 / 层数 0 与 9 / 维度 0 与 1025（in/out 各查）/
 *     相邻层链不衔接 / inf-nan 权重（量化拒绝）；
 *   - 推理硬上限（D2）：budget=1ns 强制超时 → -ETIME 且 output 未被
 *     半途写入（哨兵字节验证不污染）；budget=0=不限恢复成功；
 *   - per-CPU scratch 语义（D2）：KUnit 单线程以「同模型连续不同输入、
 *     结果不被上次污染 + 两模型交替推理互查串扰」代位两 CPU 序列调用；
 *   - 模型统计（D3 契约出参）：hash 加载后非零、bytes 非零、infer_n
 *     推理后 ≥1、timeout_n 强制超时后 ≥1。
 *
 * 测试用合法模型一律在测试内用 kmalloc 内存构造 AIKWMDL1 字节流
 * （mlp_test_build 构造 helper 正反用例复用），不依赖文件系统。
 *
 * CONFIG_AIKERNEL=n 时本文件不参与编译（Makefile 门控）；内部再按
 * CONFIG_AIKERNEL_RUNTIME 兜底，保证子开关关闭时编译为空套件。
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unaligned.h>
#include "../core/ai_types.h"
#include "../reflex/ai_model.h"
#include "../core/ai_runtime.h"

#ifdef CONFIG_AIKERNEL_RUNTIME

/* ---- float32 位级常量（Q31 可精确表示的测试权重/输入） ---- */

#define F32_0_5		0x3F000000u
#define F32_M0_5	0xBF000000u
#define F32_0_25	0x3E800000u
#define F32_M0_25	0xBE800000u
#define F32_0_125	0x3E000000u
#define F32_0_75	0x3F400000u
#define F32_M0_75	0xBF400000u
#define F32_0		0x00000000u
#define F32_INF		0x7F800000u
#define F32_NAN		0x7FC00000u

/* ---- AIKWMDL1 字节流构造 helper（正反用例复用） ---- */

struct mlp_layer_spec {
	u32 in_dim;
	u32 out_dim;
	u32 act;			/* 0=线性 1=ReLU */
	const u32 *w;			/* float32 位模式，out_dim*in_dim 行主序 */
	const u32 *b;			/* float32 位模式，out_dim */
};

/*
 * 按 layer spec 顺序拼出完整 AIKWMDL1 文件字节流（不校验合法性——
 * 反向用例需要「结构非法但字节流可构造」的输入）。
 * 返回 kmalloc 缓冲（调用者 kfree），失败 NULL。*out_len 回填字节数。
 */
static u8 *mlp_test_build(const struct mlp_layer_spec *layers, u32 n_layers,
			  size_t *out_len)
{
	size_t len = 12, off;
	u8 *buf;
	u32 i;

	for (i = 0; i < n_layers; i++)
		len += 12 + ((size_t)layers[i].out_dim * layers[i].in_dim +
			     layers[i].out_dim) * 4;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return NULL;

	memcpy(buf, "AIKWMDL1", 8);
	put_unaligned_le32(n_layers, buf + 8);

	for (off = 12, i = 0; i < n_layers; i++) {
		size_t nw = (size_t)layers[i].out_dim * layers[i].in_dim;

		put_unaligned_le32(layers[i].in_dim, buf + off);
		put_unaligned_le32(layers[i].out_dim, buf + off + 4);
		put_unaligned_le32(layers[i].act, buf + off + 8);
		off += 12;
		memcpy(buf + off, layers[i].w, nw * 4);
		off += nw * 4;
		memcpy(buf + off, layers[i].b, layers[i].out_dim * 4);
		off += layers[i].out_dim * 4;
	}

	*out_len = len;
	return buf;
}

/* 单层头 + 指定维度的最小缓冲（无权重区——维度拒绝用例在权重长度
 * 检查前即被维度检查拒绝，故无需填充权重字节） */
static u8 *mlp_test_shrink_buf(u32 n_layers, u32 in_dim, u32 out_dim,
			       size_t *out_len)
{
	u8 *buf = kmalloc(24, GFP_KERNEL);

	if (!buf)
		return NULL;
	memcpy(buf, "AIKWMDL1", 8);
	put_unaligned_le32(n_layers, buf + 8);
	put_unaligned_le32(in_dim, buf + 12);
	put_unaligned_le32(out_dim, buf + 16);
	put_unaligned_le32(0, buf + 20);
	*out_len = 24;
	return buf;
}

/* ---- 扩展 enumerate 统计读取（施工 A 契约出参探针） ---- */

/*
 * 按名取扩展统计（K6 契约：ai_model_enumerate 追加 hash/bytes/infer_n/
 * last_lat_ns/timeout_n/slot 六个可选出参）。返回 0=找到，-1=不在册。
 */
static int mlp_test_stat(const char *name, u64 *hash, u64 *bytes,
			 u64 *infer_n, u64 *last_lat_ns, u64 *timeout_n,
			 u32 *slot)
{
	char nm[AI_MAX_NAME_LEN];
	unsigned int i;

	for (i = 0; i < 64; i++) {
		u32 ver, src, st, s;
		u64 h, by, in_n, lat, to;

		if (ai_model_enumerate(i, nm, &ver, &src, &st, &h, &by,
				       &in_n, &lat, &to, &s) != AI_OK)
			break;
		if (strcmp(nm, name) != 0)
			continue;
		if (hash)
			*hash = h;
		if (bytes)
			*bytes = by;
		if (infer_n)
			*infer_n = in_n;
		if (last_lat_ns)
			*last_lat_ns = lat;
		if (timeout_n)
			*timeout_n = to;
		if (slot)
			*slot = s;
		return 0;
	}
	return -1;
}

/* ---- 测试网络 ----
 * two_net：2→2（线性，带偏置）→2→1（ReLU，带偏置）
 *   输入 A {0.5, 0.5}    → 0.65625（0x3F280000）
 *   输入 B {-0.5, 0.5}   → 0.34375（0x3EB00000）
 *   输入 G {-0.75, -0.75}→ 负值被 ReLU 钳 0（0x00000000）
 * 手算全部为 Q31 精确值（权重/偏置/输入与各层中间量均为 2 的幂组合，
 * 无量化误差）。W 行主序：W[0]={0.5,-0.25} W[1]={0.125,0.75}。
 */
static const u32 two_w0[4] = { F32_0_5, F32_M0_25, F32_0_125, F32_0_75 };
static const u32 two_b0[2] = { F32_0, F32_0_25 };
static const u32 two_w1[2] = { F32_0_5, F32_0_5 };
static const u32 two_b1[1] = { F32_0_25 };

static const struct mlp_layer_spec two_net[] = {
	{ .in_dim = 2, .out_dim = 2, .act = 0, .w = two_w0, .b = two_b0 },
	{ .in_dim = 2, .out_dim = 1, .act = 1, .w = two_w1, .b = two_b1 },
};

/* tiny_net：1→1→1→1 三层全 0.5 线性（无偏置），x=0.5 → 0.0625 */
static const u32 half_w[1] = { F32_0_5 };
static const u32 zero_b[1] = { F32_0 };

static const struct mlp_layer_spec tiny_net[] = {
	{ .in_dim = 1, .out_dim = 1, .act = 0, .w = half_w, .b = zero_b },
	{ .in_dim = 1, .out_dim = 1, .act = 0, .w = half_w, .b = zero_b },
	{ .in_dim = 1, .out_dim = 1, .act = 0, .w = half_w, .b = zero_b },
};

/* ---- 1：最小合法模型解析 + 3 层推理数值（Q31 手算期望） ---- */

static void mlp_minimal_model_numeric_test(struct kunit *test)
{
	u8 *buf;
	size_t len, olen = 4;
	u8 in[4], out[4];
	u64 lat = 0;
	int rc, id;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	buf = mlp_test_build(tiny_net, 3, &len);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);
	KUNIT_ASSERT_EQ(test, len, 12 + 3 * (12 + 2 * 4));   /* 72 B */

	id = ai_mlp_model_create("kunit-mlp-tiny", buf, len);
	KUNIT_ASSERT_GE(test, id, 1);

	/* x=0.5：0.5→0.25→0.125→0.0625，期望 float32 位级 0x3D800000 */
	put_unaligned_le32(F32_0_5, in);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-tiny", in, sizeof(in),
					    out, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, olen, (size_t)4);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out), 0x3D800000u);

	ai_model_unload_by_name("kunit-mlp-tiny");
	kfree(buf);
}

/* ---- 2：2 层网推理数值（偏置 + 负权 + ReLU 钳零） ---- */

static void mlp_two_layer_numeric_test(struct kunit *test)
{
	u8 *buf;
	size_t len;
	u8 in[8], out[4];
	u64 lat = 0;
	size_t olen;
	int rc, id;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	buf = mlp_test_build(two_net, 2, &len);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);

	id = ai_mlp_model_create("kunit-mlp-two", buf, len);
	KUNIT_ASSERT_GE(test, id, 1);

	/* A {0.5,0.5}：0.125/0.6875 → 0.25+0.0625+0.34375 = 0.65625 */
	put_unaligned_le32(F32_0_5, in);
	put_unaligned_le32(F32_0_5, in + 4);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-two", in, sizeof(in),
					    out, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out), 0x3F280000u);

	/* B {-0.5,0.5}：-0.375/0.5625 → 0.25-0.1875+0.28125 = 0.34375 */
	put_unaligned_le32(F32_M0_5, in);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-two", in, sizeof(in),
					    out, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out), 0x3EB00000u);

	/* G {-0.75,-0.75}：-0.1875/-0.40625 → -0.046875 被 ReLU 钳 0 */
	put_unaligned_le32(F32_M0_75, in);
	put_unaligned_le32(F32_M0_75, in + 4);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-two", in, sizeof(in),
					    out, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out), 0x00000000u);

	ai_model_unload_by_name("kunit-mlp-two");
	kfree(buf);
}

/* ---- 3：解析拒绝（magic/层数/维度/链衔接） ---- */

static void mlp_parse_reject_test(struct kunit *test)
{
	static const u32 cb_w1[6] = { 0, 0, 0, 0, 0, 0 };
	static const u32 cb_b1[2] = { 0, 0 };
	static const u32 inf_w[1] = { F32_INF };
	static const struct mlp_layer_spec chain_break[] = {
		{ .in_dim = 2, .out_dim = 2, .act = 0, .w = two_w0, .b = two_b0 },
		/* in_dim=3 != 上一层 out_dim=2：链不衔接 */
		{ .in_dim = 3, .out_dim = 2, .act = 0, .w = cb_w1, .b = cb_b1 },
	};
	static const struct mlp_layer_spec inf_net = {
		.in_dim = 1, .out_dim = 1, .act = 0, .w = inf_w, .b = zero_b,
	};
	struct {
		const char *desc;
		u8 *buf;
		size_t len;
	} cases[9];
	unsigned int i;
	int rc;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	/* magic 错：合法流首字节改写 */
	cases[0].desc = "bad magic";
	cases[0].buf = mlp_test_build(tiny_net, 3, &cases[0].len);
	if (cases[0].buf)
		cases[0].buf[0] = 'X';

	/* 层数 0 与 9（AI_MLP_MAX_LAYERS=8） */
	cases[1].desc = "layer_count=0";
	cases[1].buf = mlp_test_shrink_buf(0, 1, 1, &cases[1].len);
	cases[2].desc = "layer_count=9";
	cases[2].buf = mlp_test_shrink_buf(9, 1, 1, &cases[2].len);

	/* 维度 0 与 1025（AI_MLP_MAX_DIM=1024；in/out 各查） */
	cases[3].desc = "in_dim=0";
	cases[3].buf = mlp_test_shrink_buf(1, 0, 1, &cases[3].len);
	cases[4].desc = "out_dim=0";
	cases[4].buf = mlp_test_shrink_buf(1, 1, 0, &cases[4].len);
	cases[5].desc = "in_dim=1025";
	cases[5].buf = mlp_test_shrink_buf(1, 1025, 1, &cases[5].len);
	cases[6].desc = "out_dim=1025";
	cases[6].buf = mlp_test_shrink_buf(1, 1, 1025, &cases[6].len);

	/* 链不衔接（完整权重字节流，结构校验期拒绝） */
	cases[7].desc = "chain break";
	cases[7].buf = mlp_test_build(chain_break, 2, &cases[7].len);

	/* inf 权重（量化期拒绝） */
	cases[8].desc = "inf weight";
	cases[8].buf = mlp_test_build(&inf_net, 1, &cases[8].len);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (!cases[i].buf) {
			KUNIT_FAIL(test, "%s: build OOM", cases[i].desc);
			continue;
		}
		rc = ai_mlp_model_create("kunit-mlp-bad", cases[i].buf,
					 cases[i].len);
		KUNIT_EXPECT_LT_MSG(test, rc, 0, "%s", cases[i].desc);
		/* 拒绝后无注册表残留 */
		KUNIT_EXPECT_LT_MSG(test, ai_model_find("kunit-mlp-bad"), 1,
				    "%s: residue", cases[i].desc);
		kfree(cases[i].buf);
	}
}

/* ---- 4：inf/nan 权重量化拒绝（inf 与 nan 各拒） ---- */

static void mlp_inf_nan_weight_reject_test(struct kunit *test)
{
	static const u32 nan_b[1] = { F32_NAN };
	static const struct mlp_layer_spec nan_net = {
		.in_dim = 1, .out_dim = 1, .act = 0,
		.w = half_w, .b = nan_b,
	};
	u8 *buf;
	size_t len;
	int rc;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	/* nan 偏置（e8==0xFF 同族拒绝；inf 权重已在用例 3 覆盖） */
	buf = mlp_test_build(&nan_net, 1, &len);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);
	rc = ai_mlp_model_create("kunit-mlp-nan", buf, len);
	KUNIT_EXPECT_LT(test, rc, 0);
	KUNIT_EXPECT_LT(test, ai_model_find("kunit-mlp-nan"), 1);
	kfree(buf);
}

/* ---- 5：推理硬上限（D2）：budget=1 强制超时，output 不被半途写入 ---- */

static void mlp_budget_timeout_test(struct kunit *test)
{
	u8 *buf;
	size_t len, olen;
	u8 in[8], out[4];
	u64 lat = 0, timeout_n = 0;
	int rc;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	buf = mlp_test_build(two_net, 2, &len);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);
	KUNIT_ASSERT_GE(test,
			ai_mlp_model_create("kunit-mlp-budget", buf, len), 1);

	put_unaligned_le32(F32_0_5, in);
	put_unaligned_le32(F32_0_5, in + 4);

	/* 哨兵值：超时路径不得写 output（D2「不半途写 output」验收锚点） */
	memset(out, 0xA5, sizeof(out));
	olen = sizeof(out);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-budget", in,
					    sizeof(in), out, &olen, &lat, 1);
	KUNIT_EXPECT_EQ(test, rc, -ETIME);
	KUNIT_EXPECT_EQ(test, out[0], 0xA5);
	KUNIT_EXPECT_EQ(test, out[1], 0xA5);
	KUNIT_EXPECT_EQ(test, out[2], 0xA5);
	KUNIT_EXPECT_EQ(test, out[3], 0xA5);

	/* 契约探针（施工 A）：infer 级超时计入模型统计 timeout_n */
	rc = mlp_test_stat("kunit-mlp-budget", NULL, NULL, NULL, NULL,
			   &timeout_n, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_GE(test, timeout_n, 1ULL);

	/* budget=0（不限）恢复成功推理，数值与用例 2 输入 A 一致 */
	olen = sizeof(out);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-budget", in,
					    sizeof(in), out, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out), 0x3F280000u);

	ai_model_unload_by_name("kunit-mlp-budget");
	kfree(buf);
}

/* ---- 6：per-CPU scratch 语义（单线程代位：连续调用不被上次污染） ---- */

static void mlp_percpu_scratch_test(struct kunit *test)
{
	u8 *b1, *b2;
	size_t len1, len2, olen;
	u8 in[8], out4[4];
	u64 lat = 0;
	int rc;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	b1 = mlp_test_build(two_net, 2, &len1);
	b2 = mlp_test_build(tiny_net, 3, &len2);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, b1);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, b2);
	KUNIT_ASSERT_GE(test,
			ai_mlp_model_create("kunit-mlp-s1", b1, len1), 1);
	KUNIT_ASSERT_GE(test,
			ai_mlp_model_create("kunit-mlp-s2", b2, len2), 1);

	/* 同模型连续不同输入：结果不被上一次推理污染 */
	put_unaligned_le32(F32_0_5, in);
	put_unaligned_le32(F32_0_5, in + 4);
	olen = sizeof(out4);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-s1", in, sizeof(in),
					    out4, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out4), 0x3F280000u);

	put_unaligned_le32(F32_M0_75, in);
	put_unaligned_le32(F32_M0_75, in + 4);
	olen = sizeof(out4);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-s1", in, sizeof(in),
					    out4, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out4), 0x00000000u);

	put_unaligned_le32(F32_0_5, in);
	put_unaligned_le32(F32_0_5, in + 4);
	olen = sizeof(out4);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-s1", in, sizeof(in),
					    out4, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out4), 0x3F280000u);

	/* 两模型交替推理：模型间 scratch 串扰检查（s2 为 1→1，输入 4B） */
	put_unaligned_le32(F32_M0_5, in);
	olen = sizeof(out4);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-s2", in, 4,
					    out4, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out4), 0xBD800000u); /* 勘误:(-0.5)·0.5³=-0.0625（原 F32_M0_25 系手算笔误，内核返回正确） */

	put_unaligned_le32(F32_0_5, in);
	put_unaligned_le32(F32_0_5, in + 4);
	olen = sizeof(out4);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-s1", in, sizeof(in),
					    out4, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, get_unaligned_le32(out4), 0x3F280000u);

	ai_model_unload_by_name("kunit-mlp-s1");
	ai_model_unload_by_name("kunit-mlp-s2");
	kfree(b1);
	kfree(b2);
}

/* ---- 7：hash/统计字段（D3 契约：加载后 hash 非零、推理计数可见） ---- */

static void mlp_hash_stats_test(struct kunit *test)
{
	u8 *buf;
	size_t len, olen = 4;
	u8 in[4], out[4];
	u64 lat = 0;
	u64 hash = 0, bytes = 0, infer_n = 0, last_lat = 0, timeout_n = 0;
	u32 slot = 0xFFFFFFFFu;
	int rc;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	buf = mlp_test_build(tiny_net, 3, &len);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);
	KUNIT_ASSERT_GE(test,
			ai_mlp_model_create("kunit-mlp-hash", buf, len), 1);

	rc = mlp_test_stat("kunit-mlp-hash", &hash, &bytes, &infer_n,
			   &last_lat, &timeout_n, &slot);
	KUNIT_EXPECT_EQ(test, rc, 0);
	/* D3 验收锚点：hash 加载后非零（builtin decide 无 hash 不适用本例） */
	KUNIT_EXPECT_NE(test, hash, 0ULL);
	KUNIT_EXPECT_NE(test, bytes, 0ULL);
	KUNIT_EXPECT_EQ(test, slot, 0u);   /* 未 arm/未 active：无槽 */

	put_unaligned_le32(F32_0_5, in);
	rc = ai_runtime_model_infer_by_name("kunit-mlp-hash", in, sizeof(in),
					    out, &olen, &lat, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	rc = mlp_test_stat("kunit-mlp-hash", NULL, NULL, &infer_n, &last_lat,
			   NULL, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_GE(test, infer_n, 1ULL);
	KUNIT_EXPECT_GE(test, last_lat, 0ULL);

	ai_model_unload_by_name("kunit-mlp-hash");
	kfree(buf);
}

static struct kunit_case mlp_test_cases[] = {
	KUNIT_CASE(mlp_minimal_model_numeric_test),
	KUNIT_CASE(mlp_two_layer_numeric_test),
	KUNIT_CASE(mlp_parse_reject_test),
	KUNIT_CASE(mlp_inf_nan_weight_reject_test),
	KUNIT_CASE(mlp_budget_timeout_test),
	KUNIT_CASE(mlp_percpu_scratch_test),
	KUNIT_CASE(mlp_hash_stats_test),
	{}
};

static struct kunit_suite mlp_test_suite = {
	.name = "ai_mlp",
	.test_cases = mlp_test_cases,
};

#else /* !CONFIG_AIKERNEL_RUNTIME */

static struct kunit_suite mlp_test_suite = {
	.name = "ai_mlp",
	.test_cases = {},
};

#endif

kunit_test_suite(mlp_test_suite);
MODULE_LICENSE("GPL v2");
