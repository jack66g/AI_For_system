// SPDX-License-Identifier: GPL-2.0
/*
 * model_lifecycle.c - W77d 本地模型生命周期引擎实现
 *
 * 数据流（详见 model_lifecycle.h）。所有 ollama 交互走原生 /api 系列端点：
 *   POST /api/pull     {"name":ref,"stream":true}  → NDJSON 进度行
 *   POST /api/show     {"model":ref}               → manifest（装后验证 1/2）
 *   POST /api/generate {"model":ref,"stream":false}→ 小推理 ping（2/2）
 *   GET  /api/tags                                 → 已装清单
 *   DELETE /api/delete {"model":ref,"name":ref}    → 卸载（新旧版字段
 *     兼容：服务端各取所需，JSON 解码忽略未知字段）
 *
 * 诚实原则（W77d 契约 C）：pull 或装后验证失败 → 尽力 /api/delete
 * 清理半成品 → 返回 -1 并给出目录中本机可装的替代项；绝不报成功。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "ai_config.h"
#include "local/local_http.h"
#include "model_lifecycle.h"

/* ---- 常量 ---- */

#define ML_CATALOG_FACTORY  "/usr/local/share/aikernel/model-catalog.json"
#define ML_CATALOG_DEV      "tools/model-catalog.json"
#define ML_STATE_DEFAULT    "/.aikernel/model-state.json"
#define ML_BENCH_DEFAULT    "/.aikernel/model-bench.json"
#define ML_PULL_TIMEOUT_MS  3600000     /* 多 GB 下载：1 小时上限 */
#define ML_PING_TIMEOUT_MS  120000      /* 装后小推理 */
#define ML_BENCH_TIMEOUT_MS 180000      /* 单条基准 */
#define ML_MAX_FILE         (4 * 1024 * 1024)

static void ml_seterr(char **err, const char *fmt, ...)
{
	va_list ap;
	char buf[AIK_ML_ERR_LEN];

	if (!err)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	free(*err);
	*err = strdup(buf);
}

static long long ml_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static char *ml_read_file(const char *path, size_t max)
{
	FILE *fp = fopen(path, "rb");
	char *buf;
	long sz;

	if (!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (sz <= 0 || (size_t)sz > max) {
		fclose(fp);
		return NULL;
	}
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
		free(buf);
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	buf[sz] = '\0';
	return buf;
}

/* base_url（可含 /v1）→ 服务根（去 /v1、去尾斜杠） */
static void ml_strip_v1(const char *base_url, char *out, size_t len)
{
	size_t n;

	if (!base_url)
		base_url = "";
	n = strlen(base_url);
	while (n > 0 && base_url[n - 1] == '/')
		n--;
	if (n >= 4 && strcmp(base_url + n - 3, "/v1") == 0)
		n -= 3;
	if (n >= len)
		n = len - 1;
	memcpy(out, base_url, n);
	out[n] = '\0';
}

/* ---- 目录 ---- */

const char *aik_ml_catalog_path(void)
{
	const char *env = getenv("AIK_ML_CATALOG_PATH");

	if (env && env[0])
		return env;
	if (access(ML_CATALOG_FACTORY, R_OK) == 0)
		return ML_CATALOG_FACTORY;
	return ML_CATALOG_DEV;
}

/* JSON 字符串字段拷贝（缺失保持空串） */
static void ml_get_str(const char *obj, size_t obj_len, const char *key,
		       char *out, size_t out_len)
{
	const char *val;
	size_t val_len;
	int type;

	if (ai_json_obj_get(obj, obj_len, key, &val, &val_len, &type) == 1 &&
	    type == AI_JSON_STR) {
		char *s = ai_json_strdup_str(val, val_len);

		if (s) {
			snprintf(out, out_len, "%s", s);
			free(s);
			return;
		}
	}
	out[0] = '\0';
}

static double ml_get_num(const char *obj, size_t obj_len, const char *key,
			 double dflt)
{
	const char *val;
	size_t val_len;
	int type;

	if (ai_json_obj_get(obj, obj_len, key, &val, &val_len, &type) == 1 &&
	    type == AI_JSON_NUM) {
		char tok[64];
		size_t n = val_len < sizeof(tok) - 1 ?
			   val_len : sizeof(tok) - 1;

		memcpy(tok, val, n);
		tok[n] = '\0';
		return strtod(tok, NULL);   /* 小数（4.7/8.2/1.7）不被截断 */
	}
	return dflt;
}

static int ml_entry_has_tag(const struct aik_ml_entry *e, const char *tag)
{
	int i;

	for (i = 0; i < e->ntags; i++)
		if (strcmp(e->tags[i], tag) == 0)
			return 1;
	return 0;
}

int aik_ml_catalog_load(const char *path, struct aik_ml_entry *out,
			int max, char **err)
{
	char *text;
	const char *arr = NULL;
	size_t arr_len = 0;
	int type = AI_JSON_NONE, n = 0, i;

	if (!path || !path[0])
		path = aik_ml_catalog_path();
	text = ml_read_file(path, ML_MAX_FILE);
	if (!text) {
		ml_seterr(err, "cannot read catalog %s (%s)",
			  path, strerror(errno));
		return -1;
	}

	/* 兼容两种顶层：{"entries":[...]} 或裸 [...] */
	if (ai_json_obj_get(text, strlen(text), "entries",
			    &arr, &arr_len, &type) != 1 || type != AI_JSON_ARR) {
		const char *p = text;
		const char *end = text + strlen(text);

		p = ai_json_skip_ws(p, end);
		if (!(p < end && *p == '[' &&
		      ai_json_scan_value(&p, end, &arr, &arr_len,
					 &type) == 0 &&
		      type == AI_JSON_ARR)) {
			ml_seterr(err, "catalog %s: no \"entries\" array",
				  path);
			free(text);
			return -1;
		}
	}

	for (i = 0; n < max; i++) {
		const char *elem;
		size_t elem_len;
		struct aik_ml_entry *e = &out[n];

		if (ai_json_arr_get(arr, arr_len, i, &elem, &elem_len,
				    &type) != 1)
			break;
		if (type != AI_JSON_OBJ)
			continue;
		memset(e, 0, sizeof(*e));
		ml_get_str(elem, elem_len, "name", e->name, sizeof(e->name));
		ml_get_str(elem, elem_len, "ollama_ref", e->ollama_ref,
			   sizeof(e->ollama_ref));
		e->params_b = ml_get_num(elem, elem_len, "params_b", 0);
		e->ctx_tokens = (long long)ml_get_num(elem, elem_len,
						      "ctx_tokens", 0);
		e->disk_gb = ml_get_num(elem, elem_len, "disk_gb", 0);
		e->ram_min_gb = (int)ml_get_num(elem, elem_len, "ram_min_gb", 0);
		ml_get_str(elem, elem_len, "gpu_hint", e->gpu_hint,
			   sizeof(e->gpu_hint));
		ml_get_str(elem, elem_len, "why", e->why, sizeof(e->why));
		ml_get_str(elem, elem_len, "notes", e->notes, sizeof(e->notes));
		{
			const char *tags;
			size_t tags_len;

			if (ai_json_obj_get(elem, elem_len, "tags",
					    &tags, &tags_len, &type) == 1 &&
			    type == AI_JSON_ARR) {
				int t;

				for (t = 0; t < AIK_ML_MAX_TAGS; t++) {
					const char *tv;
					size_t tv_len;

					if (ai_json_arr_get(tags, tags_len, t,
							    &tv, &tv_len,
							    &type) != 1)
						break;
					if (type == AI_JSON_STR) {
						char *s = ai_json_strdup_str(
							tv, tv_len);

						if (s) {
							snprintf(e->tags[t],
								 sizeof(e->tags[t]),
								 "%s", s);
							free(s);
							e->ntags++;
						}
					}
				}
			}
		}
		if (!e->name[0] || !e->ollama_ref[0])
			continue;   /* 必填缺失：跳过该条，不中断 */
		n++;
	}
	free(text);
	if (n == 0)
		ml_seterr(err, "catalog %s: 0 usable entries", path);
	return n;
}

/* ---- 硬件盘点 ---- */

static long long ml_env_ll(const char *key, long long dflt)
{
	const char *v = getenv(key);

	if (v && v[0])
		return atoll(v);
	return dflt;
}

void aik_ml_hw_probe(struct aik_ml_hw *hw)
{
	memset(hw, 0, sizeof(*hw));

	/* 内存：/proc/meminfo（与 harness/w77d_inventory.py 同口径） */
	{
		FILE *fp = fopen("/proc/meminfo", "r");
		char line[256];

		if (fp) {
			while (fgets(line, sizeof(line), fp)) {
				/* 行格式 "MemTotal:  16384256 kB" */
				if (strncmp(line, "MemTotal:", 9) == 0)
					hw->mem_total_kb = atoll(line + 9);
				else if (strncmp(line, "MemAvailable:", 13) == 0)
					hw->mem_avail_kb = atoll(line + 13);
			}
			fclose(fp);
		}
	}

	/* 磁盘：根分区可用空间（MB） */
	{
		struct statvfs vfs;

		if (statvfs("/", &vfs) == 0 && vfs.f_bsize > 0)
			hw->disk_free_mb = (long long)vfs.f_bavail *
					   vfs.f_bsize / (1024 * 1024);
	}

	hw->cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);

	/* GPU：/sys/class/drm 各 cardX/device/vendor（0x10de/0x1002=独显） */
	{
		DIR *d = opendir("/sys/class/drm");
		struct dirent *de;

		if (d) {
			while ((de = readdir(d))) {
				char path[256];
				char *text;

				if (strncmp(de->d_name, "card", 4) != 0)
					continue;
				snprintf(path, sizeof(path),
					 "/sys/class/drm/%.200s/device/vendor",
					 de->d_name);
				text = ml_read_file(path, 64);
				if (text) {
					unsigned long vendor = strtoul(text,
								       NULL, 0);

					free(text);
					if (vendor == 0x10deUL ||
					    vendor == 0x1002UL) {
						hw->gpu = 1;
						snprintf(hw->gpu_desc,
							 sizeof(hw->gpu_desc),
							 "%s",
							 vendor == 0x10deUL ?
							 "NVIDIA" : "AMD");
						break;
					}
				}
			}
			closedir(d);
		}
	}

	/* 测试确定性：环境变量逐项覆盖 */
	hw->mem_total_kb = ml_env_ll("AIK_HW_MEM_TOTAL_KB",
				     hw->mem_total_kb);
	hw->mem_avail_kb = ml_env_ll("AIK_HW_MEM_AVAIL_KB",
				     hw->mem_avail_kb);
	hw->disk_free_mb = ml_env_ll("AIK_HW_DISK_FREE_MB",
				     hw->disk_free_mb);
	hw->cpus = (int)ml_env_ll("AIK_HW_CPUS", hw->cpus);
	hw->gpu = ml_env_ll("AIK_HW_GPU", hw->gpu) > 0;
	if (!hw->gpu_desc[0] && hw->gpu)
		snprintf(hw->gpu_desc, sizeof(hw->gpu_desc), "yes");
}

/* ---- 推荐 ---- */

static long long ml_total_gb(const struct aik_ml_hw *hw)
{
	return hw->mem_total_kb > 0 ? hw->mem_total_kb / 1024 / 1024 : 0;
}

int aik_ml_recommend(const struct aik_ml_entry *cat, int n,
		     const struct aik_ml_hw *hw,
		     struct aik_ml_scored *top, int max_top)
{
	struct aik_ml_scored all[AIK_ML_CATALOG_MAX];
	int cnt = 0, i, j;
	long long total_gb = ml_total_gb(hw);

	for (i = 0; i < n && cnt < AIK_ML_CATALOG_MAX; i++) {
		const struct aik_ml_entry *e = &cat[i];
		struct aik_ml_scored *s = &all[cnt];
		int score = 40;

		/* 硬门控：内存 + 磁盘（不满足绝不推荐） */
		if (total_gb > 0 && (long long)e->ram_min_gb > total_gb)
			continue;
		if (hw->disk_free_mb > 0 &&
		    (long long)(e->disk_gb * 1024.0) > hw->disk_free_mb)
			continue;

		if (ml_entry_has_tag(e, "long-context"))
			score += 20;
		if (ml_entry_has_tag(e, "agent"))
			score += 12;
		if (ml_entry_has_tag(e, "recommended-first"))
			score += 8;
		if (e->ctx_tokens >= 1000000)
			score += 10;
		else if (e->ctx_tokens >= 128000)
			score += 4;
		else if (e->ctx_tokens >= 32000)
			score += 2;
		/* 低配机（<8GB）只装得动小模型：参数量惩罚保证小模型靠前 */
		if (total_gb > 0 && total_gb < 8 && e->params_b >= 7)
			score -= 30;
		/* 内存余量充足（最小需求一半以内）加分 */
		if (total_gb > 0 && (long long)e->ram_min_gb * 2 <= total_gb)
			score += 6;

		s->e = e;
		s->score = score;
		snprintf(s->reason, sizeof(s->reason),
			 "%gB params / %lldK ctx / %gGB disk / min-ram %dGB%s%s",
			 e->params_b, e->ctx_tokens / 1000, e->disk_gb,
			 e->ram_min_gb,
			 ml_entry_has_tag(e, "long-context") ?
			 " / native long-context" : "",
			 hw->gpu ? " / dGPU available" : "");
		cnt++;
	}

	/* 稳定插入排序（得分降序，同分保持目录序） */
	for (i = 1; i < cnt; i++) {
		struct aik_ml_scored key = all[i];

		for (j = i - 1; j >= 0 && all[j].score < key.score; j--)
			all[j + 1] = all[j];
		all[j + 1] = key;
	}

	if (cnt > max_top)
		cnt = max_top;
	for (i = 0; i < cnt; i++)
		top[i] = all[i];
	return cnt;
}

/* ---- /api 辅助 ---- */

int aik_ml_installed(const char *base_url, const char *ref, char **err)
{
	char root[400];
	char url[576];
	char *resp = NULL, *errm = NULL;
	int status = 0, rc, found = 0;
	const char *arr;
	size_t arr_len;
	int type, i;

	ml_strip_v1(base_url, root, sizeof(root));
	snprintf(url, sizeof(url), "%s/api/tags", root);
	rc = local_http_get(url, 10000, &resp, &errm, &status);
	if (rc != AI_OK || status != 200) {
		ml_seterr(err, "GET /api/tags failed (%s, status=%d)",
			  errm ? errm : "network", status);
		free(resp);
		free(errm);
		return -1;
	}
	free(errm);
	if (ai_json_obj_get(resp, strlen(resp), "models",
			    &arr, &arr_len, &type) == 1 && type == AI_JSON_ARR) {
		for (i = 0;; i++) {
			const char *elem;
			size_t elem_len;
			char name[256], nm[256];

			if (ai_json_arr_get(arr, arr_len, i, &elem, &elem_len,
					    &type) != 1)
				break;
			ml_get_str(elem, elem_len, "name", name, sizeof(name));
			ml_get_str(elem, elem_len, "model", nm, sizeof(nm));
			/* 精确或前缀匹配（ref "qwen3:8b" 命中
			 * "qwen3:8b-latest"） */
			if ((name[0] &&
			     (strcmp(name, ref) == 0 ||
			      strncmp(name, ref, strlen(ref)) == 0)) ||
			    (nm[0] &&
			     (strcmp(nm, ref) == 0 ||
			      strncmp(nm, ref, strlen(ref)) == 0))) {
				found = 1;
				break;
			}
		}
	}
	free(resp);
	return found;
}

/* /api/pull 流式进度状态（回调行缓冲） */
struct ml_pull_ctx {
	char line[1024];
	size_t fill;
	char last_status[128];
	char pull_error[256];
	int verbose;
};

static void ml_pull_line(struct ml_pull_ctx *pc, const char *line)
{
	const char *val;
	size_t val_len;
	int type;

	if (!(line && line[0]))
		return;
	if (ai_json_obj_get(line, strlen(line), "error",
			    &val, &val_len, &type) == 1 && type == AI_JSON_STR) {
		char *s = ai_json_strdup_str(val, val_len);

		if (s) {
			snprintf(pc->pull_error, sizeof(pc->pull_error), "%s",
				 s);
			free(s);
		}
		return;
	}
	if (ai_json_obj_get(line, strlen(line), "status",
			    &val, &val_len, &type) == 1 && type == AI_JSON_STR) {
		char *s = ai_json_strdup_str(val, val_len);

		if (s) {
			long long done = 0, total = 0;
			const char *v2;
			size_t l2;
			int t2;

			if (ai_json_obj_get(line, strlen(line), "completed",
					    &v2, &l2, &t2) == 1 && t2 == AI_JSON_NUM)
				done = ai_json_ll(v2, l2);
			if (ai_json_obj_get(line, strlen(line), "total",
					    &v2, &l2, &t2) == 1 && t2 == AI_JSON_NUM)
				total = ai_json_ll(v2, l2);
			snprintf(pc->last_status, sizeof(pc->last_status), "%s",
				 s);
			if (pc->verbose) {
				if (total > 0)
					printf("  [pull] %s (%lld/%lld MB)\n",
					       s, done / (1024 * 1024),
					       total / (1024 * 1024));
				else
					printf("  [pull] %s\n", s);
				fflush(stdout);
			}
			free(s);
		}
	}
}

static void ml_pull_cb(void *ud, const char *data, size_t len)
{
	struct ml_pull_ctx *pc = ud;
	size_t i;

	for (i = 0; i < len; i++) {
		if (data[i] == '\n') {
			pc->line[pc->fill] = '\0';
			ml_pull_line(pc, pc->line);
			pc->fill = 0;
		} else if (pc->fill + 1 < sizeof(pc->line)) {
			pc->line[pc->fill++] = data[i];
		}
	}
}

/* 装后验证 1/2：/api/show manifest 存在 */
static int ml_verify_show(const char *root, const char *ref,
			  char *errbuf, size_t errlen)
{
	char body[512];
	char *resp = NULL, *errm = NULL;
	int status = 0, rc;

	snprintf(body, sizeof(body), "{\"model\":\"%s\"}", ref);
	{
		char url[576];

		snprintf(url, sizeof(url), "%s/api/show", root);
		rc = local_http_post(url, "", body, 30000, &resp, &errm,
				     &status);
	}
	free(errm);
	if (rc != AI_OK || status != 200 || !resp || !resp[0]) {
		snprintf(errbuf, errlen,
			 "verify /api/show failed (status=%d)", status);
		free(resp);
		return -1;
	}
	free(resp);
	return 0;
}

/* 装后验证 2/2：/api/generate 一次小推理 */
static int ml_verify_ping(const char *root, const char *ref,
			  char *errbuf, size_t errlen)
{
	char body[640];
	char *resp = NULL, *errm = NULL;
	int status = 0, rc;
	const char *val;
	size_t val_len;
	int type;

	snprintf(body, sizeof(body),
		 "{\"model\":\"%s\",\"prompt\":\"Reply with the single word: OK\",\"stream\":false}",
		 ref);
	{
		char url[576];

		snprintf(url, sizeof(url), "%s/api/generate", root);
		rc = local_http_post(url, "", body, ML_PING_TIMEOUT_MS,
				     &resp, &errm, &status);
	}
	free(errm);
	if (rc != AI_OK || status != 200 || !resp || !resp[0]) {
		snprintf(errbuf, errlen,
			 "verify inference ping failed (status=%d)", status);
		free(resp);
		return -1;
	}
	if (ai_json_obj_get(resp, strlen(resp), "response",
			    &val, &val_len, &type) != 1 || type != AI_JSON_STR) {
		snprintf(errbuf, errlen,
			 "verify inference ping: no response field");
		free(resp);
		return -1;
	}
	free(resp);
	return 0;
}

static int ml_api_delete(const char *root, const char *ref)
{
	char url[576];
	char body[512];
	char *resp = NULL, *errm = NULL;
	int status = 0, rc;

	snprintf(url, sizeof(url), "%s/api/delete", root);
	snprintf(body, sizeof(body), "{\"model\":\"%s\",\"name\":\"%s\"}",
		 ref, ref);
	rc = local_http_request("DELETE", url, "", body, 30000, &resp,
				&errm, &status);
	free(resp);
	free(errm);
	return rc == AI_OK && status >= 200 && status < 300 ? 0 : -1;
}

/* [local].model 赋值（释放旧值） */
static void ml_set_local_model(struct ai_config *cfg, const char *model,
			       int enabled)
{
	char *dup = strdup(model ? model : "");

	if (dup) {
		free(cfg->local.model);
		cfg->local.model = dup;
	}
	cfg->local.enabled = enabled;
}

/* 同步 [models.local] 镜像条目（remove+add，幂等） */
static int ml_sync_local_mirror(struct ai_config *cfg, const char *model)
{
	const char *base = cfg->local.base_url ? cfg->local.base_url : "";

	ai_config_remove_model(cfg, "local");
	return ai_config_add_model(cfg, "local", "local", model, base, "");
}

static const struct aik_ml_entry *ml_find(const struct aik_ml_entry *cat,
					  int n, const char *name)
{
	int i;

	for (i = 0; i < n; i++)
		if (strcmp(cat[i].name, name) == 0 ||
		    strcmp(cat[i].ollama_ref, name) == 0)
			return &cat[i];
	return NULL;
}

/* 失败时给替代建议（本机可装、非当前条目，最多 2 个） */
static void ml_suggest_alts(const struct aik_ml_entry *cat, int n,
			    const struct aik_ml_hw *hw,
			    const struct aik_ml_entry *cur, char *out,
			    size_t out_len)
{
	struct aik_ml_scored top[AIK_ML_TOP_N];
	int cnt = aik_ml_recommend(cat, n, hw, top, AIK_ML_TOP_N);
	int i;
	size_t used = 0;

	out[0] = '\0';
	if (out_len < 8)
		return;
	for (i = 0; i < cnt && used < out_len - 32; i++) {
		if (top[i].e == cur)
			continue;
		used += (size_t)snprintf(out + used, out_len - used, "%s%s",
					 used ? "、" : "", top[i].e->name);
	}
}

int aik_ml_install(struct ai_config *cfg, const char *name, int verbose,
		   char **err_out)
{
	struct aik_ml_entry cat[AIK_ML_CATALOG_MAX];
	struct aik_ml_hw hw;
	const struct aik_ml_entry *e;
	char root[400];
	char body[512];
	struct ml_pull_ctx pc;
	char *resp = NULL, *errm = NULL;
	int status = 0, n, rc;
	char errbuf[AIK_ML_ERR_LEN];

	if (!cfg || !name || !name[0]) {
		ml_seterr(err_out, "install: name required");
		return -1;
	}
	if (!cfg->local.base_url || !cfg->local.base_url[0]) {
		ml_seterr(err_out,
			  "install: [local].base_url not configured");
		return -1;
	}

	n = aik_ml_catalog_load(NULL, cat, AIK_ML_CATALOG_MAX, err_out);
	if (n <= 0)
		return -1;
	e = ml_find(cat, n, name);
	if (!e) {
		ml_seterr(err_out,
			  "model '%s' not in catalog (see: aik model catalog)",
			  name);
		return -1;
	}

	/* 硬件门控预检：内存/磁盘不足直接拒绝（诚实，不装） */
	aik_ml_hw_probe(&hw);
	{
		long long total_gb = ml_total_gb(&hw);

		if (total_gb > 0 && (long long)e->ram_min_gb > total_gb) {
			ml_seterr(err_out,
				  "insufficient RAM: %s needs %dGB, this host has %lldGB",
				  e->name, e->ram_min_gb, total_gb);
			return -1;
		}
		if (hw.disk_free_mb > 0 &&
		    (long long)(e->disk_gb * 1024.0) > hw.disk_free_mb) {
			ml_seterr(err_out,
				  "insufficient disk: %s needs ~%gGB, free %lldMB",
				  e->name, e->disk_gb, hw.disk_free_mb);
			return -1;
		}
	}

	ml_strip_v1(cfg->local.base_url, root, sizeof(root));
	if (verbose) {
		printf("install: pulling %s (~%gGB download) ...\n",
		       e->ollama_ref, e->disk_gb);
		if (e->notes[0])
			printf("  note: %s\n", e->notes);
		fflush(stdout);
	}

	memset(&pc, 0, sizeof(pc));
	pc.verbose = verbose;
	snprintf(body, sizeof(body), "{\"name\":\"%s\",\"stream\":true}",
		 e->ollama_ref);
	{
		char url[576];

		snprintf(url, sizeof(url), "%s/api/pull", root);
		rc = local_http_post_stream(url, "", body, ML_PULL_TIMEOUT_MS,
					    ml_pull_cb, &pc, &resp, &errm,
					    &status);
	}
	if (pc.fill) {
		pc.line[pc.fill] = '\0';
		ml_pull_line(&pc, pc.line);
	}
	if (rc != AI_OK || status != 200 || pc.pull_error[0]) {
		char alts[256];

		ml_suggest_alts(cat, n, &hw, e, alts, sizeof(alts));
		ml_api_delete(root, e->ollama_ref);   /* 清理半成品 */
		ml_seterr(err_out,
			  "pull %s failed: %s (status=%d)%s%s -- partial download cleaned; honest failure, NOT installed",
			  e->ollama_ref,
			  pc.pull_error[0] ? pc.pull_error :
			  (errm ? errm : "network"),
			  status,
			  alts[0] ? " ; alternatives that fit this host: " : "",
			  alts);
		free(resp);
		free(errm);
		return -1;
	}
	free(resp);
	free(errm);

	/* 装后验证：manifest + 一次小推理（失败即失败 + 清理） */
	if (ml_verify_show(root, e->ollama_ref, errbuf, sizeof(errbuf)) != 0 ||
	    ml_verify_ping(root, e->ollama_ref, errbuf, sizeof(errbuf)) != 0) {
		char alts[256];

		ml_suggest_alts(cat, n, &hw, e, alts, sizeof(alts));
		ml_api_delete(root, e->ollama_ref);
		ml_seterr(err_out,
			  "post-install verify failed for %s: %s -- cleaned up (maybe ollama lacks spark2_5 support, see catalog notes)%s%s",
			  e->ollama_ref, errbuf,
			  alts[0] ? " ; alternatives: " : "", alts);
		return -1;
	}

	/* 注册 [local].model/enabled=true 与 [models.local] 镜像，落盘 */
	ml_set_local_model(cfg, e->ollama_ref, 1);
	if (ml_sync_local_mirror(cfg, e->ollama_ref) != AI_OK ||
	    ai_config_save(cfg) != AI_OK) {
		ml_seterr(err_out,
			  "installed but failed to persist model.toml");
		return -1;
	}
	if (verbose)
		printf("install: %s verified (manifest + inference ping OK)\n",
		       e->ollama_ref);
	return 0;
}

int aik_ml_remove(struct ai_config *cfg, const char *name, int force,
		  char **err_out)
{
	struct aik_ml_entry cat[AIK_ML_CATALOG_MAX];
	const struct aik_ml_entry *e;
	char root[400];
	const char *active;
	int n, rc;

	if (!cfg || !name || !name[0]) {
		ml_seterr(err_out, "remove: name required");
		return -1;
	}
	n = aik_ml_catalog_load(NULL, cat, AIK_ML_CATALOG_MAX, err_out);
	if (n <= 0)
		return -1;
	e = ml_find(cat, n, name);
	if (!e) {
		ml_seterr(err_out, "model '%s' not in catalog", name);
		return -1;
	}

	/* 活动模型（[local].model == 待卸载项）需二次确认 */
	active = cfg->local.model ? cfg->local.model : "";
	if (!force && active[0] &&
	    (strcmp(active, e->ollama_ref) == 0 ||
	     strcmp(active, e->name) == 0))
		return AIK_ML_E_CONFIRM;

	ml_strip_v1(cfg->local.base_url, root, sizeof(root));
	rc = ml_api_delete(root, e->ollama_ref);
	if (rc != 0) {
		int listed = aik_ml_installed(root, e->ollama_ref, NULL);

		if (listed == 1) {
			ml_seterr(err_out, "ollama delete failed for %s",
				  e->ollama_ref);
			return -1;
		}
		if (listed < 0) {
			ml_seterr(err_out,
				  "cannot reach ollama to delete %s (service down?)",
				  e->ollama_ref);
			return -1;
		}
		/* listed == 0：本来就不在，幂等成功 */
	}

	/* 注销 [local]（enabled=false、model 清空）与镜像条目 */
	ml_set_local_model(cfg, "", 0);
	ai_config_remove_model(cfg, "local");   /* 若 default 是 local 会清空 */
	if (!cfg->default_model || !cfg->default_model[0]) {
		/* 云端优先兜底：切到第一个 openai_compatible 条目 */
		struct ai_model_config *m;

		for (m = cfg->models_head; m; m = m->next) {
			if (m->provider_type &&
			    strcmp(m->provider_type,
				   "openai_compatible") == 0) {
				ai_config_set_default_model(cfg, m->name);
				break;
			}
		}
	}
	if (ai_config_save(cfg) != AI_OK) {
		ml_seterr(err_out,
			  "removed but failed to persist model.toml");
		return -1;
	}
	return 0;
}

int aik_ml_name_in_catalog(const char *name)
{
	struct aik_ml_entry cat[AIK_ML_CATALOG_MAX];
	int n, hit;

	if (!name || !name[0])
		return 0;
	n = aik_ml_catalog_load(NULL, cat, AIK_ML_CATALOG_MAX, NULL);
	if (n <= 0)
		return 0;
	hit = ml_find(cat, n, name) != NULL;
	return hit;
}

/* ---- switch / rollback（状态文件） ---- */

static void ml_state_path(char *out, size_t len)
{
	const char *env = getenv("AIK_ML_STATE_PATH");
	const char *home = getenv("HOME");

	if (env && env[0]) {
		snprintf(out, len, "%s", env);
		return;
	}
	snprintf(out, len, "%s%s", home ? home : "/root", ML_STATE_DEFAULT);
}

static void ml_bench_path(char *out, size_t len)
{
	const char *env = getenv("AIK_ML_BENCH_PATH");
	const char *home = getenv("HOME");

	if (env && env[0]) {
		snprintf(out, len, "%s", env);
		return;
	}
	snprintf(out, len, "%s%s", home ? home : "/root", ML_BENCH_DEFAULT);
}

/* 取当前实际生效的 default（未设置时按 cloud-first 兜底名） */
static const char *ml_effective_default(const struct ai_config *cfg)
{
	if (cfg->default_model && cfg->default_model[0])
		return cfg->default_model;
	return "cloud";
}

/* 云端兜底名：第一个 openai_compatible 条目名（无则 NULL） */
static const struct ai_model_config *ml_cloud_entry(const struct ai_config *cfg)
{
	const struct ai_model_config *m;

	for (m = cfg->models_head; m; m = m->next)
		if (m->provider_type &&
		    strcmp(m->provider_type, "openai_compatible") == 0)
			return m;
	return NULL;
}

int aik_ml_switch(struct ai_config *cfg, const char *target, char **err_out)
{
	char path[512];
	char resolved[128];
	const char *cur = ml_effective_default(cfg);
	const struct ai_model_config *cloud;
	const char *final_target = target;
	FILE *fp;

	if (!cfg || !target || !target[0]) {
		ml_seterr(err_out,
			  "switch: target required (cloud|local|<name>)");
		return -1;
	}

	/* 目标校验与解析 */
	if (strcmp(target, "local") == 0) {
		if (!cfg->local.model || !cfg->local.model[0]) {
			ml_seterr(err_out,
				  "switch local: no local model installed (aik model install first)");
			return -1;
		}
		if (!cfg->local.enabled)
			cfg->local.enabled = 1;
		if (ml_sync_local_mirror(cfg, cfg->local.model) != AI_OK) {
			ml_seterr(err_out,
				  "switch local: mirror sync failed");
			return -1;
		}
	} else if (strcmp(target, "cloud") == 0) {
		cloud = ml_cloud_entry(cfg);
		if (!cloud) {
			ml_seterr(err_out,
				  "switch cloud: no cloud model configured");
			return -1;
		}
		snprintf(resolved, sizeof(resolved), "%s", cloud->name);
		final_target = resolved;
	} else {
		char *ptype = NULL;

		if (ai_config_get_model(cfg, target, &ptype, NULL, NULL,
					NULL) != AI_OK) {
			ml_seterr(err_out,
				  "switch: model '%s' not found in model.toml",
				  target);
			return -1;
		}
		free(ptype);
	}

	/* 记录上一状态（切换前；同目标切换也记录，状态可追溯） */
	ml_state_path(path, sizeof(path));
	fp = fopen(path, "w");
	if (fp) {
		fprintf(fp,
			"{\"previous\":\"%s\",\"current\":\"%s\",\"changed_at\":%lld}\n",
			cur, final_target, (long long)time(NULL));
		fclose(fp);
	} else {
		ml_seterr(err_out,
			  "switch: cannot write state file %s (%s)",
			  path, strerror(errno));
		return -1;
	}

	if (ai_config_set_default_model(cfg, final_target) != AI_OK) {
		ml_seterr(err_out, "switch: set default '%s' failed",
			  final_target);
		return -1;
	}
	if (ai_config_save(cfg) != AI_OK) {
		ml_seterr(err_out, "switch: persist model.toml failed");
		return -1;
	}
	return 0;
}

int aik_ml_rollback(struct ai_config *cfg, char **err_out)
{
	char path[512];
	char *text;
	const char *val;
	size_t val_len;
	int type;
	char previous[128];
	char *s;

	ml_state_path(path, sizeof(path));
	text = ml_read_file(path, ML_MAX_FILE);
	if (!text) {
		ml_seterr(err_out, "rollback: no previous state (%s)", path);
		return -1;
	}
	if (ai_json_obj_get(text, strlen(text), "previous",
			    &val, &val_len, &type) != 1 || type != AI_JSON_STR) {
		ml_seterr(err_out, "rollback: state file malformed");
		free(text);
		return -1;
	}
	s = ai_json_strdup_str(val, val_len);
	free(text);
	if (!s) {
		ml_seterr(err_out, "rollback: out of memory");
		return -1;
	}
	snprintf(previous, sizeof(previous), "%s", s);
	free(s);
	if (!previous[0]) {
		ml_seterr(err_out, "rollback: previous state empty");
		return -1;
	}

	/* 恢复（local 已不在时不许回；别名解析交给 switch） */
	if (strcmp(previous, "local") == 0 &&
	    (!cfg->local.model || !cfg->local.model[0])) {
		ml_seterr(err_out,
			  "rollback to local: local model no longer installed");
		return -1;
	}
	return aik_ml_switch(cfg, previous, err_out);
}

/* ---- benchmark ---- */

static int ml_cmp_ll(const void *a, const void *b)
{
	long long x = *(const long long *)a;
	long long y = *(const long long *)b;

	return x < y ? -1 : x > y ? 1 : 0;
}

static const char *const g_bench_prompts[AIK_ML_BENCH_ROUNDS] = {
	"用一句话说明 /proc/meminfo 的作用。",
	"列出查看磁盘空间的两个常用命令。",
	"把这句话翻译成英文：系统运行正常。",
};

int aik_ml_benchmark(struct ai_config *cfg, const char *name, int rounds,
		     char *json_out, size_t out_len, char **err_out)
{
	char root[400];
	const char *model;
	char body[768];
	char *resp = NULL;
	long long samples_ms[16];
	long long tokens = 0, gen_ns = 0;
	int nsamples = 0, i, rc;
	const char *val;
	size_t val_len;
	int type;
	char path[512];
	FILE *fp;

	if (!cfg) {
		ml_seterr(err_out, "benchmark: config required");
		return -1;
	}
	if (rounds <= 0)
		rounds = AIK_ML_BENCH_ROUNDS;
	if (rounds > 10)
		rounds = 10;

	model = name && name[0] ? name :
		(cfg->local.model ? cfg->local.model : "");
	if (!model[0]) {
		ml_seterr(err_out,
			  "benchmark: no model given and [local].model empty");
		return -1;
	}
	if (!cfg->local.base_url || !cfg->local.base_url[0]) {
		ml_seterr(err_out,
			  "benchmark: [local].base_url not configured");
		return -1;
	}
	ml_strip_v1(cfg->local.base_url, root, sizeof(root));

	for (i = 0; i < rounds && nsamples < 16; i++) {
		long long t0, dt;
		int status = 0;
		char url[576];
		char *errm = NULL;

		snprintf(body, sizeof(body),
			 "{\"model\":\"%s\",\"prompt\":\"%s\",\"stream\":false}",
			 model, g_bench_prompts[i % AIK_ML_BENCH_ROUNDS]);
		t0 = ml_now_ms();
		resp = NULL;
		snprintf(url, sizeof(url), "%s/api/generate", root);
		rc = local_http_post(url, "", body, ML_BENCH_TIMEOUT_MS,
				     &resp, &errm, &status);
		dt = ml_now_ms() - t0;
		free(errm);
		if (rc != AI_OK || status != 200 || !resp || !resp[0]) {
			ml_seterr(err_out,
				  "benchmark round %d failed (status=%d)",
				  i + 1, status);
			free(resp);
			return -1;
		}
		if (ai_json_obj_get(resp, strlen(resp), "eval_count",
				    &val, &val_len, &type) == 1 &&
		    type == AI_JSON_NUM)
			tokens += ai_json_ll(val, val_len);
		if (ai_json_obj_get(resp, strlen(resp), "eval_duration",
				    &val, &val_len, &type) == 1 &&
		    type == AI_JSON_NUM)
			gen_ns += ai_json_ll(val, val_len);
		free(resp);
		samples_ms[nsamples++] = dt;
	}

	qsort(samples_ms, (size_t)nsamples, sizeof(long long), ml_cmp_ll);
	{
		long long p50 = samples_ms[nsamples / 2];
		long long p95 = samples_ms[nsamples - 1];
		double tok_s = gen_ns > 0 ?
			(double)tokens / ((double)gen_ns / 1e9) : 0.0;

		if (json_out && out_len)
			snprintf(json_out, out_len,
				 "{\"model\":\"%s\",\"rounds\":%d,\"p50_ms\":%lld,\"p95_ms\":%lld,\"tokens\":%lld,\"tok_per_s\":%.2f}",
				 model, nsamples, p50, p95, tokens, tok_s);
		ml_bench_path(path, sizeof(path));
		fp = fopen(path, "w");
		if (fp) {
			fprintf(fp,
				"{\"model\":\"%s\",\"rounds\":%d,\"p50_ms\":%lld,\"p95_ms\":%lld,\"tokens\":%lld,\"tok_per_s\":%.2f,\"samples_ms\":[",
				model, nsamples, p50, p95, tokens, tok_s);
			for (i = 0; i < nsamples; i++)
				fprintf(fp, "%s%lld", i ? "," : "",
					samples_ms[i]);
			fprintf(fp, "]}\n");
			fclose(fp);
		}
	}
	return 0;
}
