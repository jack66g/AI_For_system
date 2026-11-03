/* SPDX-License-Identifier: GPL-2.0 */
/*
 * config_default.h - SME 默认配置（生成文件，请勿手改）
 *
 * 来源：Python 参考实现（SME 1.3.0, 出厂树 /opt/sme, git 5a6604d+dirty, config.py md5 b17ee0fc）的
 *       json.dumps(SMEConfig().to_dict(), ensure_ascii=False)
 * 生成命令（在参考实现根目录、只读执行，-B 不落 .pyc）：
 *   python -B -c "import json; from sme.config import SMEConfig; print(json.dumps(SMEConfig().to_dict(), ensure_ascii=False))"
 * Python：3.10.6
 * JSON sha256（UTF-8 字节，原样无换行）：
 *   aa4725917e5801e234d318e62540b09f1b8edf4ae4743b2440c64b7a53cf6781
 * 规模：26 section / 133 键；键序即 Python dict 插入序（seed 永远第一）。
 *
 * 说明：非 ASCII 字节以三位八进制转义写入，源文件保持纯 ASCII；
 * 常量内容与上面 sha256 对应的 JSON 文本逐字节相同。
 */
#ifndef _AIK_SMECONFIG_CONFIG_DEFAULT_H
#define _AIK_SMECONFIG_CONFIG_DEFAULT_H

/* SMECONFIG_DEFAULT_JSON: Python json.dumps(..., ensure_ascii=False) 原样 */
#define AIK_CONFIG_DEFAULT_JSON \
	"{\"seed\": 42, \"embedding\": {\"provider\": \"hashing\", \"model\": \"text-" \
	"embedding-3-small\", \"dim\": 64, \"base_url\": \"\", \"api_key\": \"\", \"b" \
	"atch_size\": 32, \"normalize\": true, \"hash_factors\": 3, \"hash_window\": " \
	"3, \"revision\": \"\", \"mrl_dim\": 0, \"hash_seed\": 0, \"revision_stamp\":" \
	" \"\"}, \"region\": {\"min_region_size\": 3, \"min_join_cosine\": 0.7, \"spl" \
	"it_threshold\": 48, \"max_density\": 120.0, \"merge_distance\": 0.12, \"neig" \
	"hbor_factor\": 1.8, \"auto_evolve\": true, \"evolve_interval\": 40, \"ann_en" \
	"abled\": true, \"ann_min_regions\": 256}, \"retrieval\": {\"top_regions\": 3" \
	", \"region_options\": [1, 3, 5], \"top_k\": 10, \"vector_weight\": 0.6, \"ke" \
	"yword_weight\": 0.3, \"metadata_weight\": 0.1, \"region_dampening\": 0.1, \"" \
	"summary_penalty\": 0.5, \"cjk_bigram\": true, \"candidate_window\": 20, \"fu" \
	"sion\": \"minmax\"}, \"ranking\": {\"semantic\": 0.4, \"importance\": 0.12, " \
	"\"freshness\": 0.1, \"weight\": 0.1, \"decay\": 0.08, \"hit_count\": 0.08, " \
	"\"recency\": 0.06, \"region\": 0.06}, \"policy\": {\"full_memory\": true, \"" \
	"importance_threshold\": 0.25, \"decay_enabled\": true}, \"reinforcement\": {" \
	"\"hit_weight_delta\": 0.1, \"hit_importance_delta\": 0.05, \"max_weight\": 5" \
	".0, \"max_importance\": 1.0, \"min_importance\": 0.0, \"ebbinghaus_half_life" \
	"_days\": 7.0, \"ebbinghaus_power\": 1.2}, \"decay\": {\"half_life_days\": 30" \
	".0, \"max_weight_decay\": 0.85, \"max_importance_decay\": 0.85}, \"consolida" \
	"tion\": {\"similarity_threshold\": 0.5, \"min_group_size\": 3, \"max_group_s" \
	"ize\": 12, \"summary_source\": \"template\"}, \"compression\": {\"age_days_t" \
	"hreshold\": 3.0, \"min_region_compact\": 8, \"summary_source\": \"template\"" \
	"}, \"llm\": {\"base_url\": \"https://api.openai.com/v1\", \"api_key\": \"\"," \
	" \"model\": \"gpt-4o-mini\", \"timeout\": 60.0, \"temperature\": 0.3, \"max_" \
	"tokens\": 1024, \"reasoning_effort\": null, \"extra_headers\": {}}, \"storag" \
	"e\": {\"path\": \"data/engine.json\", \"autosave\": true, \"autosave_interva" \
	"l\": 100, \"compress\": true, \"backend\": \"json\"}, \"maintenance\": {\"ba" \
	"ckground\": false, \"idle_after_s\": 30.0, \"every_s\": 300.0}, \"visualizat" \
	"ion\": {\"projection\": \"pca\", \"figure_size\": [12, 9], \"dpi\": 120, \"c" \
	"olor_map\": \"tab20\", \"show_graph\": true}, \"extraction\": {\"enabled\": " \
	"false, \"mode\": \"llm\", \"store_assistant\": false, \"dedup_threshold\": 0" \
	".92, \"fallback_rules\": true}, \"factversion\": {\"enabled\": false, \"corr" \
	"ect_markers\": [\"\345\205\266\345\256\236\", \"\344\270\215\345\257\271\", " \
	"\"\346\233\264\346\255\243\", \"\347\272\240\346\255\243\", \"\350\257\264" \
	"\351\224\231\", \"\346\220\236\351\224\231\", \"\350\256\260\351\224\231\", " \
	"\"\345\205\266\345\256\236\344\270\215\346\230\257\", \"\346\224\271\344\270" \
	"\200\344\270\213\", \"\344\270\215\346\230\257\347\232\204\", \"\351\224\231" \
	"\344\272\206\"], \"stale_penalty\": 0.3, \"dedup_threshold\": 0.92, \"correc" \
	"tion_threshold\": 0.72}, \"noise\": {\"enabled\": false, \"dup_penalty\": 0." \
	"5, \"template_penalty\": 0.3, \"min_density\": 0.1, \"ngram_window\": 4, \"d" \
	"up_window\": 300}, \"qapair\": {\"enabled\": false, \"max_age_days\": 180.0," \
	" \"answer_top_k\": 3, \"similarity_threshold\": 0.85}, \"factgraph\": {\"ena" \
	"bled\": false, \"extract_mode\": \"llm\", \"max_depth\": 3, \"hop_decay\": 0" \
	".5, \"max_entities\": 50}, \"profile\": {\"enabled\": false, \"snapshot_ever" \
	"y\": 50, \"top_facts\": 20, \"boost_weight\": 0.15}, \"persistence\": {\"ena" \
	"bled\": false, \"wal_path\": \"\", \"checkpoint_every\": 10, \"sync_mode\": " \
	"\"fsync\", \"group_window_ms\": 15}, \"api\": {\"host\": \"127.0.0.1\", \"po" \
	"rt\": 8000, \"auth_token\": \"\"}, \"observability\": {\"enabled\": false, " \
	"\"sample_rate\": 1.0, \"max_events\": 20000}, \"context\": {\"enabled\": fal" \
	"se, \"budget_tokens\": 4096, \"reserve_profile\": 500, \"recent_rounds\": 20" \
	"}, \"namespaces\": {\"enabled\": false, \"default_ns\": \"default\"}, \"rera" \
	"nk\": {\"enabled\": false, \"model\": \"BAAI/bge-reranker-base\", \"top_n\":" \
	" 50}}"

#endif /* _AIK_SMECONFIG_CONFIG_DEFAULT_H */
