// SPDX-License-Identifier: GPL-2.0
/*
 * ai_startup.c - AIKernel 启动参数与运行时开关（Prompt 02）
 *
 * 启动参数（__setup 注册，start_kernel() 的 "Booting kernel" 解析阶段生效，
 * 早于 start_kernel() 内 ai_runtime_init() 钩子）：
 *   ai.enabled=0|1     AI 总开关（默认 1；0 启动时 sysfs/procfs/netlink 全部不创建）
 *   ai.model_path=/x   AI 模型目录（默认 /etc/ai/）
 *   ai.log_level=0..3  日志级别（默认 1）
 *
 * 模型加载：
 *   - 内置 echo 模型（"echo"）：infer = 输入原样拷贝到输出（骨架测试用）；
 *   - 文件模型：<model_path>/<name>.bin 读入包装为 echo-ops 模型（source=EMBEDDED），
 *     私有数据持有文件内容（全量原始，不脱敏不截断），unload 时释放。
 *
 * 本文件受 CONFIG_AIKERNEL_USRIFACE 门控；关闭时 ai_startup.h 提供空函数兜底。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/kernel_read_file.h>
#include "ai_startup.h"
#include <linux/namei.h>
#include "ai_model.h"

static struct ai_startup_cfg {
	bool enabled;                          /* ai.enabled */
	char model_path[AI_PATH_MAX];          /* ai.model_path */
	u8   log_level;                        /* ai.log_level 0~3 */
} ai_boot = {
	.enabled    = true,
	.model_path = "/etc/ai/",
	.log_level  = 1,
};

/* ---- 启动参数解析 ---- */

int ai_startup_parse(const char *key, const char *val)
{
	bool bval;
	int ival;

	if (!key)
		return 1;

	if (strcmp(key, "enabled") == 0) {
		if (kstrtobool(val, &bval) != 0)
			return 1;
		ai_boot.enabled = bval;
		pr_info("AIKernel: ai.enabled=%d\n", ai_boot.enabled ? 1 : 0);
		return 0;
	}

	if (strcmp(key, "model_path") == 0) {
		if (!val || !val[0])
			return 1;
		strscpy(ai_boot.model_path, val, sizeof(ai_boot.model_path));
		pr_info("AIKernel: ai.model_path=%s\n", ai_boot.model_path);
		return 0;
	}

	if (strcmp(key, "log_level") == 0) {
		if (!val || kstrtoint(val, 0, &ival) != 0)
			return 1;
		ai_boot.log_level = (u8)clamp_t(int, ival, 0, 3);
		pr_info("AIKernel: ai.log_level=%u\n", ai_boot.log_level);
		return 0;
	}

	return 1;   /* 未知参数：交还上层处理 */
}

static int __init ai_enabled_setup(char *str)
{
	return ai_startup_parse("enabled", str);
}
__setup("ai.enabled=", ai_enabled_setup);

static int __init ai_model_path_setup(char *str)
{
	return ai_startup_parse("model_path", str);
}
__setup("ai.model_path=", ai_model_path_setup);

static int __init ai_log_level_setup(char *str)
{
	return ai_startup_parse("log_level", str);
}
__setup("ai.log_level=", ai_log_level_setup);

bool ai_startup_get_enabled(void)
{
	return ai_boot.enabled;
}
EXPORT_SYMBOL_GPL(ai_startup_get_enabled);

int ai_startup_set_enabled(bool enable)
{
	ai_boot.enabled = enable;
	pr_info("AIKernel: AI %s\n", enable ? "enabled" : "disabled");
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_startup_set_enabled);

const char *ai_startup_get_model_path(void)
{
	return ai_boot.model_path;
}
EXPORT_SYMBOL_GPL(ai_startup_get_model_path);

u8 ai_startup_get_log_level(void)
{
	return ai_boot.log_level;
}
EXPORT_SYMBOL_GPL(ai_startup_get_log_level);

/* ---- 模型加载（AIKWMDL v1 真实权重模型；回声推理已彻底删除） ---- */

static int ai_startup_model_create(const char *name, const void *data,
				   size_t data_len)
{
	/*
	 * 审计 B2 修复：此前任意 .bin 均被包装为 echo-ops（推理=回显输入，
	 * 假成功）。现在模型必须是 AIKWMDL v1 格式（真实稠密网络权重，
	 * ai_model_mlp.c 解析 + Q31 定点真前向），格式校验失败即拒绝加载。
	 */
	if (!data || !data_len)
		return AI_ERR_INVALID_ARG;
	return ai_mlp_model_create(name, data, data_len);
}

int ai_startup_load_model(const char *name)
{
	char path[AI_PATH_MAX];
	void *buf = NULL;
	size_t size = 0;
	ssize_t rd;
	int rc;

	if (!name || !name[0])
		return AI_ERR_INVALID_ARG;
	if (!ai_startup_get_enabled())
		return AI_ERR_DISABLED;

	if (strlen(ai_startup_get_model_path()) + strlen(name) +
	    strlen(AI_STARTUP_MODEL_FILE_SUFFIX) + 1 >= sizeof(path))
		return AI_ERR_INVALID_ARG;
	snprintf(path, sizeof(path), "%s%s%s",
		 ai_startup_get_model_path(), name, AI_STARTUP_MODEL_FILE_SUFFIX);

	/* 6.18 kernel_read_file 语义：buf_size=调用者缓冲容量（必须覆盖文件
	 * 大小，否则 while(copied<buf_size) 不循环=0 字节读入，buf 停留在
	 * 未初始化垃圾却返回 0（假成功））。先 stat 取大小，vmalloc 后按
	 * 容量读取。 */
	{
		struct kstat st;

		struct path kpath;

		rc = kern_path(path, LOOKUP_FOLLOW, &kpath);
		if (!rc) {
			rc = vfs_getattr(&kpath, &st, STATX_BASIC_STATS,
				       AT_STATX_SYNC_AS_STAT);
			path_put(&kpath);
		}
		if (rc || st.size <= 0) {
			pr_err("AIKernel: model file stat failed '%s' (%d)\n",
				path, rc);
			return AI_ERR_NOT_FOUND;
		}
		if ((size_t)st.size > AI_STARTUP_MAX_MODEL_SIZE)
			return AI_ERR_INVALID_ARG;
		size = (size_t)st.size;
		buf = vmalloc(size);
		if (!buf)
			return AI_ERR_MEMORY;
	}
	rd = kernel_read_file_from_path(path, 0, &buf, size, &size,
			READING_POLICY);
	if (rd < 0) {
		pr_err("AIKernel: model file read failed '%s' (%zd)\n",
			path, rd);
		vfree(buf);
		return AI_ERR_NOT_FOUND;
	}
	if ((size_t)rd != size) {
		pr_err("AIKernel: model file short read '%s' (%zd/%zu)\n",
			path, rd, size);
		vfree(buf);
		return AI_ERR_INVALID_ARG;
	}

	rc = ai_startup_model_create(name, buf, size);
	if (rc < 0)
		pr_err("AIKernel: model create failed '%s' (%d)\n", name, rc);
	vfree(buf);   /* MLP create 已复制权重到自有缓冲，buf 所有权不转移 */
	return rc;
}
EXPORT_SYMBOL_GPL(ai_startup_load_model);

int ai_startup_unload_model(const char *name)
{
	if (!name || !name[0])
		return AI_ERR_INVALID_ARG;
	if (!ai_startup_get_enabled())
		return AI_ERR_DISABLED;
	return ai_model_unload_by_name(name);
}
EXPORT_SYMBOL_GPL(ai_startup_unload_model);

/* ---- initramfs 模型预加载（init/initramfs.c 调用） ---- */

void ai_initramfs_model_preload(void)
{
	int id;

	if (!ai_startup_get_enabled())
		return;

	id = ai_startup_load_model(AI_STARTUP_INITRAMFS_MODEL);
	if (id >= 1)
		pr_info("AIKernel: initramfs preloaded model '%s' (id=%d) from %s%s%s\n",
			AI_STARTUP_INITRAMFS_MODEL, id,
			ai_startup_get_model_path(),
			AI_STARTUP_INITRAMFS_MODEL, AI_STARTUP_MODEL_FILE_SUFFIX);
	else
		pr_info("AIKernel: initramfs model preload skipped "
			"(%s%s%s not found)\n",
			ai_startup_get_model_path(),
			AI_STARTUP_INITRAMFS_MODEL, AI_STARTUP_MODEL_FILE_SUFFIX);
}
EXPORT_SYMBOL_GPL(ai_initramfs_model_preload);
