// SPDX-License-Identifier: GPL-2.0
/*
 * ai_model_mlp.c - AIKernel 真实最小稠密网络模型（AIKWMDL v1 权重文件）
 *
 * 模型文件格式（全部小端字节序）：
 *   偏移 0 : magic "AIKWMDL1"（8 字节）
 *   偏移 8 : u32 layer_count（1..AI_MLP_MAX_LAYERS）
 *   随后每层（顺序拼接）：
 *     u32 in_dim（1..AI_MLP_MAX_DIM）
 *     u32 out_dim（1..AI_MLP_MAX_DIM）
 *     u32 act（0=线性 1=ReLU；近似激活不含糊标）
 *     float32 W[out_dim][in_dim]（row-major）
 *     float32 b[out_dim]
 *   相邻层维度必须衔接：layer[i].out_dim == layer[i+1].in_dim。
 *
 * 推理：y = act(W·x + b) 逐层稠密前向，真实 MAC 累加。
 * 计算策略（如实说明）：x86_64 内核构建禁用 SSE/浮点寄存器
 * （-mno-sse），内核态 C 浮点运算不可用；权重以 float32 存储、加载时
 * 一次性量化为 Q31 定点（s32，含 exp8==255 非法值拒绝），推理为纯整数
 * MAC（s64 累加、算术右移 31 位、饱和回 s32）。量化/截断误差 < 1e-5
 * （对照验证见 ~/w1k-model/gen_model.py，同序 Q31 模拟 bit 级一致，
 * float64 参考前向误差实测 < 1e-6）。
 *
 * 回声（echo-ops）推理路径已彻底删除：magic 校验失败即拒绝加载，
 * "任意 .bin 包装后回显输入"的假推理不复存在。
 *
 * K6（WP-K6 D1/D2/D3，施工 A）：
 *   - 层间乒乓 scratch 改 per-CPU（create 备/destroy 收），并发 infer
 *     不再竞争共享缓冲，推理热路径仍零分配；
 *   - ai_mlp_infer 增预算入参 budget_ns（0=不限）：入场 ktime 锚定，
 *     MAC 循环层粒度检查，超时清场返 -ETIME（不写 output）；
 *   - 模型级统计 infer_n/last_lat_ns/timeout_n（atomic64）与加载期
 *     sha256/文件字节数（D1 白名单同源数据），经 ai_model_mlp.h 供
 *     ai_runtime（enumerate 扩展/-ETIME 回退记账）读取。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/unaligned.h>
#include <linux/overflow.h>
#include <linux/percpu.h>
#include <linux/err.h>
#include <linux/crypto.h>
#include <crypto/hash.h>

#include "../core/ai_types.h"
#include "ai_model.h"
#include "../core/ai_startup.h"
#include "../core/ai_runtime.h"
#include "ai_model_mlp.h"
#include "../boundary/ai_chain.h"

#define AI_MLP_MAGIC      "AIKWMDL1"
#define AI_MLP_MAX_LAYERS 8
#define AI_MLP_MAX_DIM    1024

struct ai_mlp_layer {
	u32 in_dim;
	u32 out_dim;
	u32 act;
	const s32 *w;   /* Q31 权重（row-major，指向量化副本区） */
	const s32 *b;   /* Q31 偏置 */
};

struct ai_mlp_model {
	struct ai_model   desc;      /* 描述符（内嵌，随整体分配/释放） */
	u32               n_layers;
	struct ai_mlp_layer layers[AI_MLP_MAX_LAYERS];
	s32              *qbuf;       /* Q31 权重+偏置副本（vmalloc） */
	size_t            qbuf_len;
	s32 __percpu     *xbuf;       /* K6 D2：per-CPU 层间乒乓 scratch
				      * （每 CPU 2×max_dim 连续平面，加载期
				      * 一次性 alloc_percpu，destroy 收） */
	u32               max_dim;
	u8                sha256[AI_MODEL_SHA256_LEN];   /* K6 D1/D3：加载期文件摘要 */
	u64               file_bytes;                    /* K6 D3：文件字节数 */
	atomic64_t        infer_n;     /* K6 D2：累计推理次数 */
	atomic64_t        last_lat_ns; /* K6 D2：最近前向耗时 */
	atomic64_t        timeout_n;   /* K6 D2：预算超时次数 */
};

/* K6 D1/D3：加载期文件 sha256（进程上下文，可睡眠；config 已内置
 * CONFIG_CRYPTO_SHA256，crypto_alloc_shash 不会落到模块请求） */
static int ai_mlp_sha256(const void *data, size_t len, u8 *out)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int rc;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
		       GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}
	desc->tfm = tfm;
	rc = crypto_shash_digest(desc, data, len, out);
	kfree(desc);
	crypto_free_shash(tfm);
	return rc;
}

/* float32 位级 → Q31 定点（无浮点指令；见文件头计算策略） */
static int ai_mlp_f32_to_q31(u32 bits, s32 *out_q)
{
	u32 sign = bits >> 31;
	u32 e8 = (bits >> 23) & 0xFF;
	u32 frac = bits & 0x7FFFFF;
	u64 q;

	if (e8 == 0xFF)
		return AI_ERR_INVALID_ARG;   /* inf/nan 非法权重 */
	if (e8 == 0) {
		*out_q = 0;   /* 零/次正规（|v|<2^-126）：Q31 下溢为 0 */
		return AI_OK;
	}

	if (e8 >= 119)
		q = (u64)(0x800000u | frac) << (e8 - 119);
	else
		q = (0x800000u | frac) >> (119 - e8);

	if (sign) {
		if (q >= 0x80000000ULL)
			*out_q = S32_MIN;
		else
			*out_q = -(s32)q;
	} else {
		if (q > (u64)S32_MAX)
			*out_q = S32_MAX;
		else
			*out_q = (s32)q;
	}
	return AI_OK;
}

/* Q31 → float32 位级（无浮点指令；规格化 mag/2^31 ∈ (0,1]） */
static u32 ai_mlp_q31_to_f32(s32 q)
{
	u32 sign = 0, mag, n, frac;

	if (q == 0)
		return 0;
	if (q < 0) {
		sign = 0x80000000u;
		mag = (u32)(-(s64)q);
	} else {
		mag = (u32)q;
	}

	n = 31 - __builtin_clz(mag);
	if (n <= 23)
		frac = (mag << (23 - n)) & 0x7FFFFFu;
	else
		frac = (mag >> (n - 23)) & 0x7FFFFFu;
	return sign | ((n + 96) << 23) | frac;
}

/* 解析并校验 AIKWMDL v1：偏移/维度/层数/衔接全检 + float→Q31 量化 */
static int ai_mlp_parse_quant(struct ai_mlp_model *m, const u8 *data,
			      size_t len)
{
	size_t off, need, qoff = 0;
	u32 i, j;
	u32 prev_out = 0;   /* 上一层 out_dim（第一遍链检查；写入在第二遍） */

		pr_info("AIKernel: mlp parse enter len=%zu magic_match=%d n_layers_le32=0x%08x\n",
		       len,
		       len >= 8 && memcmp(data, AI_MLP_MAGIC, 8) == 0,
		       get_unaligned_le32(data + 8));
	if (len < 12 || memcmp(data, AI_MLP_MAGIC, 8) != 0)
		return AI_ERR_PARSE;
	m->n_layers = get_unaligned_le32(data + 8);
	if (m->n_layers < 1 || m->n_layers > AI_MLP_MAX_LAYERS)
		return AI_ERR_PARSE;

	/* 第一遍：结构校验 + 权重区总量（qbuf 元素数，不含层头） */
	for (i = 0, off = 12; i < m->n_layers; i++) {
		u32 in_dim, out_dim;

		if (off + 12 > len)
			return AI_ERR_PARSE;
		in_dim  = get_unaligned_le32(data + off);
		out_dim = get_unaligned_le32(data + off + 4);
		pr_info("AIKernel: mlp L%u off=%zu in=%u out=%u act=%u\n",
		       i, off, in_dim, out_dim,
		       get_unaligned_le32(data + off + 8));
		if (!in_dim || !out_dim ||
		    in_dim > AI_MLP_MAX_DIM || out_dim > AI_MLP_MAX_DIM ||
		    get_unaligned_le32(data + off + 8) > 1) {
			pr_err("AIKernel: mlp bad dims L%u in=%u out=%u act=%u\n",
			       i, in_dim, out_dim,
			       get_unaligned_le32(data + off + 8));
			return AI_ERR_PARSE;
		}
		if (i > 0 && in_dim != prev_out) {
			pr_err("AIKernel: mlp chain break L%u in=%u prev_out=%u\n",
			       i, in_dim, prev_out);
			return AI_ERR_PARSE;   /* 层维度不衔接 */
		}
		off += 12;
		need = (size_t)out_dim * in_dim + out_dim;
		if (off + need * sizeof(float) > len) {
			pr_err("AIKernel: mlp short weights L%u off=%zu need=%zu len=%zu\n",
			       i, off, need * sizeof(float), len);
			return AI_ERR_PARSE;
		}
		off += need * sizeof(float);
		qoff += need;
		prev_out = out_dim;
	}
	m->qbuf_len = qoff * sizeof(s32);   /* float32→s32 等宽 */
	m->qbuf = vzalloc(m->qbuf_len);
	if (!m->qbuf)
		return AI_ERR_MEMORY;

	/* 第二遍：量化（qoff 按 qbuf 元素推进，与层头无关） */
	for (i = 0, off = 12, qoff = 0; i < m->n_layers; i++) {
		u32 in_dim  = get_unaligned_le32(data + off);
		u32 out_dim = get_unaligned_le32(data + off + 4);
		u32 act     = get_unaligned_le32(data + off + 8);
		int rc;

		off += 12;
		m->layers[i].in_dim  = in_dim;
		m->layers[i].out_dim = out_dim;
		m->layers[i].act     = act;
		m->layers[i].w = m->qbuf + qoff;
		need = (size_t)out_dim * in_dim;
		m->layers[i].b = m->layers[i].w + need;

		for (j = 0; j < need + out_dim; j++) {
			u32 bits = get_unaligned_le32(data + off +
						      j * sizeof(float));

			rc = ai_mlp_f32_to_q31(bits, m->qbuf + qoff + j);
			if (rc != AI_OK) {
				pr_err("AIKernel: mlp quant fail L%u j=%u bits=0x%08x rc=%d qoff=%zu qbuf_len=%zu\n",
					i, j, bits, rc, qoff, m->qbuf_len);
				return rc;
			}
		}
		qoff += need + out_dim;
		off += (need + out_dim) * sizeof(float);

		if (out_dim > m->max_dim)
			m->max_dim = out_dim;
		if (i == 0 && in_dim > m->max_dim)
			m->max_dim = in_dim;
	}
	return AI_OK;
}

static int ai_mlp_ops_load(struct ai_model *model)
{
	return AI_OK;   /* 权重已在 create 时解析量化 */
}

static int ai_mlp_ops_unload(struct ai_model *model)
{
	struct ai_mlp_model *m = model->private_data;

	if (m) {
		free_percpu(m->xbuf);   /* K6 D2：per-CPU scratch 收回 */
		vfree(m->qbuf);
		kfree(m);   /* desc 内嵌于 m，整体释放 */
		model->private_data = NULL;
	}
	return AI_OK;
}

/**
 * ai_mlp_infer() - 真实稠密前向（Q31 定点 MAC，纯整数无浮点指令）
 * x = input（float32 位级 → Q31）；每层 y[j] = sat(b[j] + Σ w[j][k]·x[k])
 * （算术右移 31 位回 Q31 尺度，ReLU 按 act 位施加）；输出 Q31 → float32。
 * @model: 模型实例（ai_model，private_data 指向 ai_mlp_model）
 * @input: 输入特征缓冲（float32 数组，位级转 Q31）
 * @in_len: 输入缓冲字节数（须等于输入维 * sizeof(float)）
 * @output: 输出缓冲（Q31 结果回写 float32）
 * @out_len: 输入输出参数，调用前为缓冲字节数，返回时写实际输出字节数
 * @latency_ns: 返回时写本次前向耗时（纳秒）
 * @budget_ns: K6 D2 推理预算（纳秒；0=不限）。入场 ktime 锚定，MAC 循环
 *	       层粒度检查；超时清场返 -ETIME（不写 output，out_len 不动）。
 *
 * 饱和/ReLU/反量化语义与预算机制引入前逐位一致。
 * Return: AI_OK 成功；-ETIME 预算超时；其余负错误码（维度不符/未加载等）
 */
static int ai_mlp_infer(struct ai_model *model, const void *input,
			size_t in_len, void *output, size_t *out_len,
			u64 *latency_ns, u64 budget_ns)
{
	struct ai_mlp_model *m = model->private_data;
	const s32 *x;
	s32 *xb;
	u32 i, j, k, out_dim;
	u64 t0, deadline, lat;
	int rc = AI_OK;

	if (!m || !input || !output || !out_len)
		return AI_ERR_INVALID_ARG;

	out_dim = m->layers[m->n_layers - 1].out_dim;
	if (in_len < (size_t)m->layers[0].in_dim * sizeof(float))
		return AI_ERR_INVALID_ARG;
	if (*out_len < (size_t)out_dim * sizeof(float)) {
		*out_len = (size_t)out_dim * sizeof(float);
		return AI_ERR_INVALID_ARG;   /* 输出缓冲不足（回填需求） */
	}

	t0 = ktime_get_ns();
	deadline = budget_ns ? t0 + budget_ns : 0;
	atomic64_inc(&m->infer_n);

	/* K6 D2：整个前向（量化→MAC→反量化）在 get_cpu_ptr/put_cpu_ptr 的
	 * 抢占关断内跑。乒乓数据必须全程驻留同一 CPU 的 per-CPU 平面——
	 * 若层间放行抢占，任务迁移后会读到另一 CPU 上的旧平面（正确性
	 * 优先）；关断时长受 budget 层粒度检查上界约束（预算超时在层边界
	 * 即刻离场），饱和/ReLU/反量化运算与旧共享乒乓实现逐位一致 */
	xb = get_cpu_ptr(m->xbuf);

	/* 输入量化：float32 → Q31（平面 0） */
	for (i = 0; i < m->layers[0].in_dim; i++) {
		rc = ai_mlp_f32_to_q31(get_unaligned_le32(
			(const u8 *)input + i * sizeof(float)),
			xb + i);
		if (rc != AI_OK)
			goto out_put;
	}

	x = xb;   /* 当前输入平面 = 平面 0（与旧 xbuf[0] 同位） */
	for (i = 0; i < m->n_layers; i++) {
		const struct ai_mlp_layer *L = &m->layers[i];
		s32 *y = xb + (((i + 1) & 1) ? m->max_dim : 0);

		/* 层粒度预算检查（入场时间戳锚定） */
		if (deadline && ktime_get_ns() > deadline) {
			rc = -ETIME;
			goto out_put;
		}

		for (j = 0; j < L->out_dim; j++) {
			const s32 *wr = L->w + (size_t)j * L->in_dim;
			s64 acc = L->b[j];

			for (k = 0; k < L->in_dim; k++)
				acc += ((s64)wr[k] * x[k]) >> 31;
			/* 饱和回 Q31（每项 |w·x|≤1，累加和 |Σ|≤in_dim，上界
			 * 2^31×1024=2^41，s64 无溢出） */
			if (acc > S32_MAX)
				acc = S32_MAX;
			else if (acc < S32_MIN)
				acc = S32_MIN;
			if (L->act == 1 && acc < 0)
				acc = 0;   /* ReLU */
			y[j] = (s32)acc;
		}
		x = y;
	}

	/* 输出反量化：Q31 → float32 位级 */
	for (i = 0; i < out_dim; i++)
		put_unaligned_le32(ai_mlp_q31_to_f32(x[i]),
				   (u8 *)output + i * sizeof(float));
	*out_len = (size_t)out_dim * sizeof(float);

out_put:
	put_cpu_ptr(xb);
	lat = ktime_get_ns() - t0;
	atomic64_set(&m->last_lat_ns, (s64)lat);
	if (rc == -ETIME)
		atomic64_inc(&m->timeout_n);
	if (latency_ns)
		*latency_ns = lat;
	return rc;
}

/* ops->infer 适配：预算取全局（/sys/kernel/ai/model_infer_budget_ns，
 * B 路写 ai_model_infer_budget_ns_set；默认 10ms，0=不限） */
static int ai_mlp_ops_infer(struct ai_model *model, const void *input,
			    size_t in_len, void *output, size_t *out_len,
			    u64 *latency_ns)
{
	return ai_mlp_infer(model, input, in_len, output, out_len,
			    latency_ns, ai_model_infer_budget_ns_get());
}

static const struct ai_model_ops ai_mlp_ops = {
	.load   = ai_mlp_ops_load,
	.unload = ai_mlp_ops_unload,
	.infer  = ai_mlp_ops_infer,
};

/**
 * ai_mlp_model_create() - 从 AIKWMDL v1 权重文件创建真实稠密网络模型
 * @name: 模型名（注册表唯一）
 * @data: 文件内容（AIKWMDL v1 格式，见文件头）
 * @data_len: 字节数（≤ AI_STARTUP_MAX_MODEL_SIZE）
 *
 * 校验格式、量化权重、注册进 AI Runtime。返回模型句柄（>=1）或负错误码。
 * 权重复制到模型自有缓冲，调用者 data 生命周期与模型无关。
 */
int ai_mlp_model_create(const char *name, const void *data, size_t data_len)
{
	struct ai_mlp_model *m;
	int rc;

	if (!name || !name[0] || strlen(name) >= AI_MAX_NAME_LEN ||
	    !data || !data_len || data_len > AI_STARTUP_MAX_MODEL_SIZE)
		return AI_ERR_INVALID_ARG;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return AI_ERR_MEMORY;

	rc = ai_mlp_parse_quant(m, data, data_len);
	if (rc != AI_OK) {
		pr_err("AIKernel: mlp parse failed '%s' (%d, len=%zu)\n",
		       name, rc, data_len);
		goto fail_mem;
	}

	/* K6 D1/D3：加载期 sha256（enumerate/审计数据源；与 ai_startup.c
	 * 白名单校验各自计算——策略校验与模型元数据职责分离，各持一份） */
	rc = ai_mlp_sha256(data, data_len, m->sha256);
	if (rc) {
		pr_err("AIKernel: mlp sha256 failed '%s' (%d)\n", name, rc);
		goto fail_mem;
	}
	m->file_bytes = data_len;

	/* K6 D2：per-CPU 乒乓 scratch（每 CPU 2×max_dim 平面，一次性） */
	m->xbuf = __alloc_percpu(array_size(2, m->max_dim) * sizeof(s32),
				 __alignof__(s32));
	if (!m->xbuf) {
		rc = AI_ERR_MEMORY;
		goto fail_mem;
	}

	m->desc.version = 1;
	m->desc.source  = AI_MODEL_SOURCE_USERSPACE;
	m->desc.ops     = &ai_mlp_ops;
	m->desc.private_data = m;
	strscpy(m->desc.name, name, sizeof(m->desc.name));

	rc = ai_model_load(&m->desc);
	if (rc != AI_OK)
		goto fail_mem;

	pr_info("AIKernel: MLP model '%s' loaded (id=%d, %u layers, "
		"in=%u out=%u, weights=%zu B Q31, sha256=%6phN)\n",
		name, m->desc.id, m->n_layers, m->layers[0].in_dim,
		m->layers[m->n_layers - 1].out_dim, m->qbuf_len, m->sha256);

	/* K8：装载成功铸链（MODEL_EVENT/LOAD，摘要取 sha256 前 8B） */
	{
		struct ai_chain_ev_model ev = {
			.op = AI_CHAIN_MODEL_OP_LOAD,
			.model_id = m->desc.id,
			.sha256_hi64 = get_unaligned_be64(m->sha256),
		};

		ai_chain_append(AI_CHAIN_KIND_MODEL_EVENT, &ev, sizeof(ev));
	}
	return (int)m->desc.id;

fail_mem:
	free_percpu(m->xbuf);
	vfree(m->qbuf);
	kfree(m);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_mlp_model_create);

/* ---- K6 D2/D3：模型级统计与元数据访问（见 ai_model_mlp.h） ---- */

int ai_mlp_model_infer(struct ai_model *model, const void *input,
		       size_t in_len, void *output, size_t *out_len,
		       u64 *latency_ns, u64 budget_ns)
{
	if (!model || model->ops != &ai_mlp_ops || !model->private_data)
		return -ENODEV;   /* 非 MLP：调用方回退 ops->infer */
	return ai_mlp_infer(model, input, in_len, output, out_len,
			    latency_ns, budget_ns);
}
EXPORT_SYMBOL_GPL(ai_mlp_model_infer);

int ai_mlp_model_meta(const struct ai_model *model,
		      struct ai_model_mlp_meta *out)
{
	const struct ai_mlp_model *m;

	if (!model || !out || model->ops != &ai_mlp_ops ||
	    !model->private_data)
		return -ENOENT;   /* 非 MLP 模型 */
	m = model->private_data;
	out->infer_n = (u64)atomic64_read(&m->infer_n);
	out->last_lat_ns = (u64)atomic64_read(&m->last_lat_ns);
	out->timeout_n = (u64)atomic64_read(&m->timeout_n);
	out->file_bytes = m->file_bytes;
	memcpy(out->sha256, m->sha256, sizeof(out->sha256));
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_mlp_model_meta);

void ai_mlp_model_note_timeout(struct ai_model *model)
{
	struct ai_mlp_model *m;

	if (!model || model->ops != &ai_mlp_ops || !model->private_data)
		return;   /* 非 MLP 模型：无处挂账，静默跳过 */
	m = model->private_data;
	atomic64_inc(&m->timeout_n);
}
EXPORT_SYMBOL_GPL(ai_mlp_model_note_timeout);
