/* SPDX-License-Identifier: GPL-2.0 */
/*
 * model_lifecycle.h - W77d 本地模型生命周期引擎（catalog/recommend/
 * install/remove/switch/rollback/benchmark 的无 UI 核心）
 *
 * 使用方：
 *   - shell/commands/cmd_model.c（aik model 子命令，交互确认）
 *   - shell/commands/cmd_onboarding.c（本地模型可选步骤）
 *   - tools/executor.c（model_* 能力总线工具；install/remove 走
 *     ai_lease_gate D2 确认，引擎本身不弹确认）
 *
 * 设计约束：
 *   - 不依赖 shell/runtime；配置经 struct ai_config * 显式传入，
 *     既写内存又由调用方决定何时 ai_config_save；
 *   - HTTP 只走 local/local_http.c（Ollama 原生 /api 系列端点，回环服务）；
 *   - 诚实原则：pull 失败/装后验证失败一律返回错误并清理半成品，
 *     绝不把失败说成成功（W77d 契约 C）；
 *   - 测试确定性：硬件盘点与产物路径支持 AIK_HW_* / AIK_ML_* 环境变量
 *     覆盖（见各函数注释），mock 服务驱动 install 全流程。
 */
#ifndef _AI_MODEL_LIFECYCLE_H
#define _AI_MODEL_LIFECYCLE_H

#include <stddef.h>
#include "ai_config.h"

#define AIK_ML_MAX_TAGS      8
#define AIK_ML_NAME_LEN      64
#define AIK_ML_REF_LEN       160
#define AIK_ML_TEXT_LEN      320
#define AIK_ML_CATALOG_MAX   32
#define AIK_ML_TOP_N         3
#define AIK_ML_BENCH_ROUNDS  3
#define AIK_ML_ERR_LEN       512

/* 目录条目（tools/model-catalog.json 单条） */
struct aik_ml_entry {
	char name[AIK_ML_NAME_LEN];       /* 短名，如 spark-x2.5:4b */
	char ollama_ref[AIK_ML_REF_LEN];  /* ollama pull 引用 */
	double params_b;                   /* 参数量（十亿） */
	long long ctx_tokens;              /* 上下文窗口（token） */
	double disk_gb;                    /* 下载磁盘占用（GB） */
	int ram_min_gb;                    /* 最小内存（GB，硬门控） */
	char gpu_hint[32];                 /* gpu 提示（optional/none/...） */
	char tags[AIK_ML_MAX_TAGS][32];
	int ntags;
	char why[AIK_ML_TEXT_LEN];         /* 为什么推荐 */
	char notes[AIK_ML_TEXT_LEN];       /* 核对来源/注意事项（如实） */
};

/* 硬件盘点结果（/proc/meminfo + statvfs + sysconf + /sys/class/drm） */
struct aik_ml_hw {
	long long mem_total_kb;
	long long mem_avail_kb;
	long long disk_free_mb;            /* / 的可用空间 */
	int cpus;                          /* 逻辑核数 */
	int gpu;                           /* 1=检测到独立显卡 */
	char gpu_desc[64];
};

/* recommend 输出：条目 + 得分 + 给用户的理由行 */
struct aik_ml_scored {
	const struct aik_ml_entry *e;
	int score;
	char reason[AIK_ML_TEXT_LEN];
};

/*
 * aik_ml_catalog_path - 目录文件路径解析
 * 优先级：AIK_ML_CATALOG_PATH 环境变量 >
 * /usr/local/share/aikernel/model-catalog.json（工厂安装位） >
 * tools/model-catalog.json（源码树相对 CWD 的开发位）
 */
const char *aik_ml_catalog_path(void);

/*
 * aik_ml_catalog_load - 解析目录 JSON
 * @path: 文件路径（NULL 取 aik_ml_catalog_path()）
 * @out:  输出数组（调用者分配，容量 max）
 * @max:  数组容量（<= AIK_ML_CATALOG_MAX）
 * @err:  输出失败原因（malloc，调用者 free；成功为 NULL）
 * 返回: >=0 条目数；-1 失败（err 有原因）
 */
int aik_ml_catalog_load(const char *path, struct aik_ml_entry *out,
			int max, char **err);

/*
 * aik_ml_hw_probe - 硬件盘点
 * 读取 /proc/meminfo（MemTotal/MemAvailable）、statvfs("/")、
 * sysconf(_SC_NPROCESSORS_ONLN)、/sys/class/drm 各 cardX/device/vendor
 * （0x10de=NVIDIA / 0x1002=AMD 视为独显）。
 * 测试覆盖：AIK_HW_MEM_TOTAL_KB / AIK_HW_MEM_AVAIL_KB /
 * AIK_HW_DISK_FREE_MB / AIK_HW_CPUS / AIK_HW_GPU 环境变量逐项覆盖。
 */
void aik_ml_hw_probe(struct aik_ml_hw *hw);

/*
 * aik_ml_recommend - 目录过滤 + 排序
 * 硬门控：ram_min_gb <= 总内存 GB；disk_gb*1024 <= 磁盘可用 MB。
 * 得分（确定性）：基础 40 + long-context 20 + agent 12 +
 * recommended-first 8 + ctx(>=1M +10 / >=128K +4 / >=32K +2) +
 * 内存余量充足(+ram_min*2 <= 总内存 GB 则 +6)。
 * 返回: 写入 top 的条数（0=本机没有任何可装条目）
 */
int aik_ml_recommend(const struct aik_ml_entry *cat, int n,
		     const struct aik_ml_hw *hw,
		     struct aik_ml_scored *top, int max_top);

/*
 * aik_ml_install - 安装本地模型（D2：调用方负责确认）
 * 流程：查目录 → 硬件门控预检 → /api/pull 流式下载（verbose 打印
 * 进度）→ 装后验证（/api/show manifest + /api/generate 一次小推理）→
 * 注册 [local].model/enabled=true 与 [models.local] 镜像 → save。
 * 失败：尽力 /api/delete 清理半成品，err 给出原因 + 目录中可装的
 * 替代项；绝不返回成功。
 * 返回: 0 成功；-1 失败（err_out 有原因）
 */
int aik_ml_install(struct ai_config *cfg, const char *name,
		   int verbose, char **err_out);

/*
 * aik_ml_remove - 卸载本地模型（D2：调用方负责确认）
 * force=0 且 name 是当前 [local].model（活动模型）时返回
 * AIK_ML_E_CONFIRM 要求调用方二次确认后带 force=1 重试；
 * 执行 /api/delete → 注销 [local]（enabled=0、model 清空）与
 * [models.local] 镜像 → save。
 */
#define AIK_ML_E_CONFIRM (-2)
int aik_ml_remove(struct ai_config *cfg, const char *name, int force,
		  char **err_out);

/*
 * aik_ml_switch - 切换 [default]（cloud|local|<模型名>）
 * 切换前把当前 [default] 记入 ~/.aikernel/model-state.json
 * （AIK_ML_STATE_PATH 可覆盖）。local 会同步 [models.local] 镜像。
 * 返回: 0 成功；-1 失败（err_out 有原因）
 */
int aik_ml_switch(struct ai_config *cfg, const char *target,
		  char **err_out);

/*
 * aik_ml_rollback - 恢复上一次切换前的 [default]
 * 无历史时返回 -1（err_out 说明）。
 */
int aik_ml_rollback(struct ai_config *cfg, char **err_out);

/*
 * aik_ml_benchmark - 固定提示基准（默认 3 条）
 * @name: 模型名（NULL 取 [local].model）
 * @rounds: 轮数（1-10；<=0 取 AIK_ML_BENCH_ROUNDS）
 * @json_out: 输出结果 JSON（p50/p95/tok_s，调用者缓冲；可 NULL）
 * 结果落 ~/.aikernel/model-bench.json（AIK_ML_BENCH_PATH 可覆盖）。
 * 返回: 0 成功；-1 失败
 */
int aik_ml_benchmark(struct ai_config *cfg, const char *name, int rounds,
		     char *json_out, size_t out_len, char **err_out);

/*
 * aik_ml_installed - 查询模型是否已装（/api/tags 名称匹配）
 * 返回: 1 已装；0 未装；-1 查询失败（err 有原因）
 */
int aik_ml_installed(const char *base_url, const char *ref, char **err);

/*
 * aik_ml_name_in_catalog - 名字（短名或 ollama_ref）是否在目录内
 * 返回: 1 在；0 不在（含目录加载失败）
 */
int aik_ml_name_in_catalog(const char *name);

#endif /* _AI_MODEL_LIFECYCLE_H */
