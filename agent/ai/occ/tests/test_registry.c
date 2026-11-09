/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_registry.c - T9a2 多 provider 正典 + 运行时注册表单测
 *
 * 覆盖：model.toml 多段读层（直填式/引用式/坏段容错/available 类型表）/
 * resolve 引用链 / 写辅助往返（原子+600+段替换）/ 注册表三方并集 /
 * Favorites/Recent/ByProvider 分组 / fuzzy / ollama 占位 / state.json
 * 读写往返。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "occ_llm/occ_registry.h"

static int fails;

#define OK(cond, name) do { \
	if (cond) { printf("ok %s\n", name); } \
	else { printf("FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); fails++; } \
} while (0)

static char tmpdir[64];

static void rmtree(const char *p)
{
	char cmd[128];
	int rc;

	snprintf(cmd, sizeof(cmd), "rm -rf %s", p);
	/* best effort：残留 /tmp 由系统清理 */
	rc = system(cmd);
	(void)rc;
}

static void write_file(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");

	if (!f)
		return;
	fputs(content, f);
	fclose(f);
}

static const char MODEL_TOML[] =
	"[default]\nmodel = \"cloud\"\n"
	"\n"
	"[models.cloud]\n"
	"provider_type = \"openai_compatible\"\n"
	"model_name = \"deepseek-flash\"\n"
	"base_url = \"http://127.0.0.1:9443\"\n"
	"api_key = \"sk-fixture-cloud\"\n"
	"\n"
	"[models.glm47]\n"
	"provider = \"zhipu\"\n"
	"model_name = \"glm-4.7-flash\"\n"
	"\n"
	"[models.ark]\n"
	"provider_type = \"anthropic\"\n"
	"provider = \"zhipu-ant\"\n"
	"model_name = \"glm-4.7\"\n"
	"base_url = \"https://open.bigmodel.cn/api/anthropic\"\n"
	"\n"
	"[models.badslot]\n"
	"model_name = \"orphan\"\n"
	"\n"
	"[provider.zhipu]\n"
	"type = \"openai_compatible\"\n"
	"base_url = \"https://open.bigmodel.cn/api/paas/v4\"\n"
	"key = \"sk-fixture-zhipu\"\n"
	"\n"
	"[provider.zhipu-ant]\n"
	"type = \"anthropic\"\n"
	"base_url = \"https://open.bigmodel.cn/api/anthropic\"\n"
	"key = \"sk-fixture-zhipu-ant\"\n";

static const char PROVIDER_TOML[] =
	"[providers]\n"
	"available = [\"openai_compatible\", \"local\"]\n"
	"\n"
	"[providers.openai_compatible]\n"
	"type = \"http\"\n"
	"description = \"OpenAI compatible\"\n"
	"supports = [\"chat\"]\n";

static const char CAT_JSON[] =
	"{\"_meta\":{\"source\":\"fixture\",\"original_sha256\":\"abc\"},"
	"\"providers\":{"
	"\"deepseek\":{\"name\":\"DeepSeek\",\"models\":{"
	"\"deepseek-flash\":{\"id\":\"deepseek-flash\",\"name\":\"DeepSeek Flash\","
	"\"type\":\"chat\",\"context_limit\":128000,\"tools\":true}"
	"}},"
	"\"anthropic\":{\"name\":\"Anthropic\",\"models\":{"
	"\"claude-sonnet-4-5\":{\"id\":\"claude-sonnet-4-5\","
	"\"name\":\"Claude Sonnet 4.5\",\"type\":\"chat\","
	"\"context_limit\":200000,\"tools\":true}"
	"}}}}";

static void test_load_all(void)
{
	char path[128];
	occ_provider_config cfg;

	snprintf(path, sizeof(path), "%s/model.toml", tmpdir);
	write_file(path, MODEL_TOML);
	snprintf(path, sizeof(path), "%s/provider.toml", tmpdir);
	write_file(path, PROVIDER_TOML);

	snprintf(path, sizeof(path), "%s/model.toml", tmpdir);
	OK(occ_provider_load_all(&cfg, path,
				 "/nonexistent/provider.toml") == 0,
	   "load-all-ok");
	OK(cfg.nslots == 3, "slots-3");
	OK(cfg.nproviders == 2, "providers-2");
	OK(cfg.malformed == 1, "malformed-1");
	OK(cfg.navailable == 0, "no-provider-toml-no-types");

	/* 引用式槽位字段 */
	{
		const occ_model_slot *s = NULL;
		size_t i;

		for (i = 0; i < cfg.nslots; i++)
			if (!strcmp(cfg.slots[i].id, "glm47"))
				s = &cfg.slots[i];
		OK(s != NULL, "slot-glm47");
		OK(s && !strcmp(s->provider_ref, "zhipu"), "glm47-ref");
		OK(s && !strcmp(s->model, "glm-4.7-flash"), "glm47-model");
	}
	occ_provider_config_free(&cfg);

	/* 带 provider.toml：available 类型表 */
	{
		char ppath[128];

		snprintf(ppath, sizeof(ppath), "%s/provider.toml", tmpdir);
		OK(occ_provider_load_all(&cfg, path, ppath) == 0,
		   "load-all-with-provider-toml");
		OK(cfg.navailable == 2, "available-2");
		OK(!strcmp(cfg.available_types[0], "openai_compatible") &&
		   !strcmp(cfg.available_types[1], "local"),
		   "available-values");
		occ_provider_config_free(&cfg);
	}
}

static void test_resolve(void)
{
	char path[128];
	occ_provider_config cfg;
	occ_provider p;

	snprintf(path, sizeof(path), "%s/model.toml", tmpdir);
	occ_provider_load_all(&cfg, path, NULL);

	/* 直填式（[models.cloud]，与 L1 现有配置同构） */
	OK(occ_provider_resolve(&cfg, "cloud", &p) == 0, "resolve-cloud");
	if (p.api_key) {
		OK(!strcmp(p.model, "deepseek-flash"), "cloud-model");
		OK(!strcmp(p.base_url, "http://127.0.0.1:9443"), "cloud-url");
		OK(p.proto == OCC_PROTO_OPENAI_COMPAT, "cloud-proto");
		OK(!strcmp(p.api_key, "sk-fixture-cloud"), "cloud-key");
		occ_provider_free(&p);
	} else {
		OK(0, "cloud-key-missing");
	}
	/* 引用式（base_url/key 从 [provider.zhipu] 取） */
	OK(occ_provider_resolve(&cfg, "glm47", &p) == 0, "resolve-glm47");
	if (p.api_key) {
		OK(!strcmp(p.base_url,
			   "https://open.bigmodel.cn/api/paas/v4"),
		   "glm47-url-from-provider");
		OK(!strcmp(p.api_key, "sk-fixture-zhipu"),
		   "glm47-key-from-provider");
		OK(p.proto == OCC_PROTO_OPENAI_COMPAT, "glm47-proto");
		occ_provider_free(&p);
	}
	/* 引用式 + 槽位覆盖 base_url + anthropic 协议 */
	OK(occ_provider_resolve(&cfg, "ark", &p) == 0, "resolve-ark");
	if (p.api_key) {
		OK(p.proto == OCC_PROTO_ANTHROPIC, "ark-proto");
		OK(!strcmp(p.base_url,
			   "https://open.bigmodel.cn/api/anthropic"),
		   "ark-url-override");
		OK(!strcmp(p.api_key, "sk-fixture-zhipu-ant"),
		   "ark-key-from-provider");
		occ_provider_free(&p);
	}
	/* 坏段（无类型无引用）不在 slots → resolve 失败 */
	OK(occ_provider_resolve(&cfg, "badslot", &p) == -1,
	   "resolve-badslot-rejected");
	/* 未知槽位 */
	OK(occ_provider_resolve(&cfg, "nope", &p) == -1,
	   "resolve-unknown");
	occ_provider_config_free(&cfg);
}

static void test_write_roundtrip(void)
{
	char path[128];
	occ_provider_config cfg;
	struct stat st;
	occ_model_slot slot;
	occ_provider_def def;
	occ_provider p;

	snprintf(path, sizeof(path), "%s/roundtrip.toml", tmpdir);
	unlink(path);

	/* 1. 新文件写 provider 段 */
	memset(&def, 0, sizeof(def));
	snprintf(def.name, sizeof(def.name), "moonshot");
	snprintf(def.type, sizeof(def.type), "openai_compatible");
	snprintf(def.base_url, sizeof(def.base_url),
		 "https://api.moonshot.cn/v1");
	def.api_key = strdup("sk-fixture-moon");
	OK(occ_provider_toml_add_provider(path, &def) == 0,
	   "add-provider-new-file");
	memset(def.api_key, 0, strlen(def.api_key));
	free(def.api_key);
	OK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600,
	   "add-provider-mode-600");

	/* 2. 写槽位 */
	memset(&slot, 0, sizeof(slot));
	snprintf(slot.id, sizeof(slot.id), "kimi");
	slot.proto = OCC_PROTO_OPENAI_COMPAT;
	snprintf(slot.provider_ref, sizeof(slot.provider_ref), "moonshot");
	snprintf(slot.model, sizeof(slot.model), "kimi-k2");
	slot.api_key = strdup("sk-fixture-kimi");
	OK(occ_provider_toml_add_slot(path, &slot) == 0, "add-slot");
	memset(slot.api_key, 0, strlen(slot.api_key));
	free(slot.api_key);

	/* 3. 读回 */
	OK(occ_provider_load_all(&cfg, path, NULL) == 0, "roundtrip-load");
	OK(cfg.nslots == 1 && cfg.nproviders == 1, "roundtrip-counts");
	OK(occ_provider_resolve(&cfg, "kimi", &p) == 0, "roundtrip-resolve");
	if (p.api_key) {
		OK(!strcmp(p.base_url, "https://api.moonshot.cn/v1"),
		   "kimi-url-from-provider");
		OK(!strcmp(p.model, "kimi-k2"), "kimi-model");
		/* 槽位 key 优先于 provider 段 key */
		OK(!strcmp(p.api_key, "sk-fixture-kimi"), "kimi-key-slot-wins");
		occ_provider_free(&p);
	}
	occ_provider_config_free(&cfg);

	/* 4. 同 id 再写 → 替换不重复 */
	memset(&slot, 0, sizeof(slot));
	snprintf(slot.id, sizeof(slot.id), "kimi");
	slot.proto = OCC_PROTO_OPENAI_COMPAT;
	snprintf(slot.model, sizeof(slot.model), "kimi-latest");
	snprintf(slot.base_url, sizeof(slot.base_url),
		 "https://api.moonshot.cn/v1");
	OK(occ_provider_toml_add_slot(path, &slot) == 0, "add-slot-replace");
	OK(occ_provider_load_all(&cfg, path, NULL) == 0 &&
	   cfg.nslots == 1 && cfg.nproviders == 1, "replace-no-dup");
	OK(occ_provider_resolve(&cfg, "kimi", &p) == 0 &&
	   p.api_key && !strcmp(p.model, "kimi-latest"),
	   "replace-model-updated");
	if (p.api_key)
		occ_provider_free(&p);
	occ_provider_config_free(&cfg);

	/* 5. 既有文件追加新槽位不破坏旧段 */
	memset(&slot, 0, sizeof(slot));
	snprintf(slot.id, sizeof(slot.id), "glm48");
	slot.proto = OCC_PROTO_OPENAI_COMPAT;
	snprintf(slot.model, sizeof(slot.model), "glm-4.8");
	OK(occ_provider_toml_add_slot(path, &slot) == 0, "add-second-slot");
	OK(occ_provider_load_all(&cfg, path, NULL) == 0 &&
	   cfg.nslots == 2 && cfg.nproviders == 1, "second-slot-appended");
	occ_provider_config_free(&cfg);

	/* 6. 值安全：含引号拒收 */
	memset(&slot, 0, sizeof(slot));
	snprintf(slot.id, sizeof(slot.id), "ev\"il");
	slot.proto = OCC_PROTO_OPENAI_COMPAT;
	OK(occ_provider_toml_add_slot(path, &slot) == -1,
	   "unsafe-value-rejected");
}

static void test_registry_views(void)
{
	char path[128];
	occ_provider_config cfg;
	occ_catalog cat;
	occ_registry reg;
	size_t idx[32], n;

	snprintf(path, sizeof(path), "%s/model.toml", tmpdir);
	occ_provider_load_all(&cfg, path, NULL);
	snprintf(path, sizeof(path), "%s/cat.json", tmpdir);
	write_file(path, CAT_JSON);
	occ_catalog_load(&cat, path);

	if (occ_registry_init(&reg) != 0) {
		OK(0, "registry-init");
		return;
	}
	occ_registry_build(&reg, &cfg, &cat);
	/* toml 3 槽位（badslot 容错跳过）+ catalog 2；cloud 槽位分组键
	 * = 槽位名、glm47/ark = provider 引用名——catalog 的
	 * deepseek/deepseek-flash 分组键不同，不去重 */
	OK(reg.nmodels == 5, "union-5");
	OK(occ_registry_find(&reg, "cloud", "deepseek-flash") != NULL,
	   "find-toml-entry");
	OK(occ_registry_find(&reg, "zhipu", "glm-4.7-flash") != NULL,
	   "find-toml-ref-group");
	OK(occ_registry_find(&reg, "anthropic", "claude-sonnet-4-5") != NULL,
	   "find-catalog-entry");

	/* ollama 占位并入 + 去重（返回 added=2：重复 qwen 与 broken 不计） */
	{
		const char tags[] =
			"{\"models\":[{\"name\":\"qwen2.5:1.5b\"},"
			"{\"name\":\"llama3:8b\"},{\"name\":\"qwen2.5:1.5b\"},"
			"{\"broken\":1}]}";

		n = occ_registry_add_ollama(&reg, tags, strlen(tags));
	}
	OK(n == 2, "ollama-added-2");
	OK(reg.nmodels == 7, "ollama-merged-7");
	OK(occ_registry_find(&reg, "ollama", "qwen2.5:1.5b") != NULL,
	   "ollama-entry");
	{
		const occ_reg_model *m = occ_registry_find(&reg, "ollama",
							   "llama3:8b");
		OK(m && m->source == OCC_REG_SRC_OLLAMA, "ollama-source");
		OK(m && !strcmp(m->base_url, "http://127.0.0.1:11434/v1"),
		   "ollama-base-url");
		OK(m && m->proto == OCC_PROTO_OPENAI_COMPAT,
		   "ollama-proto");
	}
	/* 坏 JSON → 0 新增 */
	OK(occ_registry_add_ollama(&reg, "not json", 8) == 0,
	   "ollama-bad-json");
	OK(reg.nmodels == 7, "ollama-bad-no-add");

	/* touch → recents LRU */
	occ_registry_touch(&reg, "anthropic", "claude-sonnet-4-5");
	occ_registry_touch(&reg, "ollama", "llama3:8b");
	occ_registry_touch(&reg, "anthropic", "claude-sonnet-4-5");	/* 提前 */
	n = occ_registry_recents(&reg, idx, 32);
	OK(n == 2, "recents-2");
	OK(n == 2 && !strcmp(reg.models[idx[0]].id, "claude-sonnet-4-5") &&
	   !strcmp(reg.models[idx[0]].provider, "anthropic"),
	   "recents-lru-head");
	/* favorite 后从 recents 视图消失（仍收藏） */
	OK(occ_registry_toggle_favorite(&reg, "ollama", "llama3:8b") == 1,
	   "fav-toggle-on");
	n = occ_registry_recents(&reg, idx, 32);
	OK(n == 1, "recents-excl-favorite");
	n = occ_registry_favorites(&reg, idx, 32);
	OK(n == 1 && !strcmp(reg.models[idx[0]].id, "llama3:8b"),
	   "favorites-1");
	OK(occ_registry_toggle_favorite(&reg, "ollama", "llama3:8b") == 0,
	   "fav-toggle-off");

	/* by_provider 分组序：provider_name 字典序
	 * fixture 组键：Anthropic / ark / cloud / DeepSeek / glm47→zhipu /
	 * zhipu-ant / Ollama（大小写 ASCII 序） */
	n = occ_registry_all_by_provider(&reg, 0, idx, 32);
	OK(n == 7, "all-7");
	if (n == 7) {
		/* ASCII 序：Anthropic < DeepSeek < Ollama < ark < cloud
		 * < zhipu < zhipu-ant */
		OK(!strcmp(reg.models[idx[0]].provider_name, "Anthropic"),
		   "group-order-0-anthropic");
		OK(!strcmp(reg.models[idx[1]].provider, "deepseek"),
		   "group-order-1-deepseek");
		OK(!strcmp(reg.models[idx[2]].provider, "ollama"),
		   "group-order-2-ollama");
		OK(!strcmp(reg.models[idx[6]].provider, "zhipu-ant"),
		   "group-order-last-zhipu-ant");
		/* 同组内按 id 字典序：zhipu 组只 1 条（glm-4.7-flash） */
		OK(!strcmp(reg.models[idx[5]].id, "glm-4.7-flash"),
		   "group-order-zhipu-member");
	}

	/* fuzzy：子串 / 子序列 / 大小写 / 无命中 */
	n = occ_registry_fuzzy(&reg, "claude", 0, idx, 32);
	OK(n == 1, "fuzzy-substring");
	n = occ_registry_fuzzy(&reg, "CLAUDE", 0, idx, 32);
	OK(n == 1, "fuzzy-case-insensitive");
	n = occ_registry_fuzzy(&reg, "cs45", 0, idx, 32);	/* 子序列 */
	OK(n == 1, "fuzzy-subsequence");
	OK(n == 1 && !strcmp(reg.models[idx[0]].id, "claude-sonnet-4-5"),
	   "fuzzy-subsequence-hit");
	n = occ_registry_fuzzy(&reg, "qwen", 0, idx, 32);
	OK(n == 1, "fuzzy-ollama");
	n = occ_registry_fuzzy(&reg, "zzz", 0, idx, 32);
	OK(n == 0, "fuzzy-miss");
	n = occ_registry_fuzzy(&reg, "", 0, idx, 32);
	OK(n == 0, "fuzzy-empty-query");

	occ_provider_config_free(&cfg);
	occ_catalog_free(&cat);
	occ_registry_free(&reg);
}

static void test_state_json(void)
{
	occ_registry reg, reg2;
	char path[128];
	struct stat st;

	snprintf(path, sizeof(path), "%s/state.json", tmpdir);
	unlink(path);

	if (occ_registry_init(&reg) != 0) {
		OK(0, "state-reg-init");
		return;
	}
	occ_registry_touch(&reg, "deepseek", "deepseek-flash");
	occ_registry_touch(&reg, "anthropic", "claude-sonnet-4-5");
	occ_registry_toggle_favorite(&reg, "deepseek", "deepseek-flash");
	OK(occ_state_save(&reg, path) == 0, "state-save");
	OK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600,
	   "state-mode-600");

	if (occ_registry_init(&reg2) != 0) {
		OK(0, "state-reg2-init");
		occ_registry_free(&reg);
		return;
	}
	OK(occ_state_load(&reg2, path) == 0, "state-load");
	OK(reg2.nrecents == 2 && reg2.nfavorites == 1, "state-counts");
	OK(!strcmp(reg2.recents[0], "anthropic/claude-sonnet-4-5") &&
	   !strcmp(reg2.recents[1], "deepseek/deepseek-flash"),
	   "state-recents-order");
	OK(!strcmp(reg2.favorites[0], "deepseek/deepseek-flash"),
	   "state-favorites");

	/* 坏状态文件 → -1（调用方重建） */
	write_file(path, "{broken");
	OK(occ_state_load(&reg2, path) == -1, "state-bad-rejected");
	/* 不存在 → -1（首次运行） */
	snprintf(path, sizeof(path), "%s/nostate.json", tmpdir);
	OK(occ_state_load(&reg2, path) == -1, "state-missing-rejected");
	occ_registry_free(&reg);
	occ_registry_free(&reg2);
}

/* ---- OCC-DEBT：非 chat 标注（is_chat 三态位 + id 特征分类器） ---- */
static void test_nonchat(void)
{
	char path[128];
	occ_provider_config cfg;
	occ_catalog cat;
	occ_registry reg;
	static const char NC_TOML[] =
		"[default]\nmodel = \"cloud\"\n"
		"\n"
		"[models.cloud]\n"
		"provider_type = \"openai_compatible\"\n"
		"model_name = \"deepseek-chat\"\n"
		"base_url = \"http://127.0.0.1:1\"\n"
		"api_key = \"sk-fixture-nc\"\n"
		"\n"
		"[models.emb]\n"
		"provider_type = \"openai_compatible\"\n"
		"model_name = \"text-embedding-3-small\"\n"
		"base_url = \"http://127.0.0.1:1\"\n"
		"api_key = \"sk-fixture-nc\"\n";
	static const char NC_CAT[] =
		"{\"providers\":{\"xx\":{\"name\":\"XX\",\"models\":{"
		"\"chatty\":{\"id\":\"chatty\",\"name\":\"Chatty\","
		"\"type\":\"chat\",\"context_limit\":100},"
		"\"decidy\":{\"id\":\"decidy\",\"name\":\"Decidy\","
		"\"type\":\"decision\"}"
		"}}}}";

	/* 分类器边界：高置信特征命中 */
	OK(occ_reg_nonchat_by_id("text-embedding-3-small") == 1,
	   "nc-embed");
	OK(occ_reg_nonchat_by_id("bge-reranker-v2-m3") == 1, "nc-rerank");
	OK(occ_reg_nonchat_by_id("tts-1-hd") == 1, "nc-tts");
	OK(occ_reg_nonchat_by_id("whisper-large-v3") == 1, "nc-whisper");
	OK(occ_reg_nonchat_by_id("dall-e-3") == 1, "nc-dalle");
	OK(occ_reg_nonchat_by_id("seedream-4-0-250828") == 1, "nc-seedream");
	OK(occ_reg_nonchat_by_id("flux-1-pro") == 1, "nc-flux");
	OK(occ_reg_nonchat_by_id("funasr-Speech-01") == 1, "nc-speech-ci");
	/* 宁缺勿错：多模态对话常见特征不得误杀（快照实测 vision 类全 chat） */
	OK(occ_reg_nonchat_by_id("gpt-4-turbo-vision") == 0, "nc-vision-is-chat");
	OK(occ_reg_nonchat_by_id("deepseek-v4-flash-vision-exp") == 0,
	   "nc-vision-exp-is-chat");
	OK(occ_reg_nonchat_by_id("qwen3guard-gen-8b") == 0, "nc-guard-is-chat");
	OK(occ_reg_nonchat_by_id("deepseek-chat") == 0, "nc-plain-chat");
	OK(occ_reg_nonchat_by_id("qwen2.5:1.5b") == 0, "nc-ollama-chat");
	OK(occ_reg_nonchat_by_id("") == 0 && occ_reg_nonchat_by_id(NULL) == 0,
	   "nc-empty-null");

	/* 三态位传播：目录 type 位；toml id 特征/未知 */
	{
		char tpath[128];

		snprintf(tpath, sizeof(tpath), "%s/nc_model.toml", tmpdir);
		write_file(tpath, NC_TOML);
		snprintf(path, sizeof(path), "%s/nc_cat.json", tmpdir);
		write_file(path, NC_CAT);
		OK(occ_provider_load_all(&cfg, tpath, NULL) == 0, "nc-load-toml");
	}
	OK(occ_catalog_load(&cat, path) == 0, "nc-load-cat");
	if (occ_registry_init(&reg) != 0) {
		OK(0, "nc-reg-init");
		return;
	}
	occ_registry_build(&reg, &cfg, &cat);
	OK(reg.nmodels == 4, "nc-union-4");
	{
		const occ_reg_model *m;

		m = occ_registry_find(&reg, "xx", "chatty");
		OK(m && m->is_chat == 1, "nc-catalog-chat-1");
		m = occ_registry_find(&reg, "xx", "decidy");
		OK(m && m->is_chat == 0, "nc-catalog-decision-0");
		m = occ_registry_find(&reg, "cloud", "deepseek-chat");
		OK(m && m->is_chat == -1, "nc-toml-unknown--1");
		m = occ_registry_find(&reg, "emb", "text-embedding-3-small");
		OK(m && m->is_chat == 0, "nc-toml-embed-0");
	}
	occ_provider_config_free(&cfg);
	occ_catalog_free(&cat);
	occ_registry_free(&reg);
}

int main(void)
{
	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ-reg-test-XXXXXX");
	if (!mkdtemp(tmpdir)) {
		printf("test_registry: FAIL(tmpdir)\n");
		return 1;
	}
	test_load_all();
	test_resolve();
	test_write_roundtrip();
	test_registry_views();
	test_state_json();
	test_nonchat();
	rmtree(tmpdir);
	if (fails) {
		printf("test_registry: FAIL(%d)\n", fails);
		return 1;
	}
	printf("test_registry: ALL GREEN\n");
	return 0;
}
