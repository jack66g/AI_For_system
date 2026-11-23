/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_models_chain.c - P-2a：models 三层查找链（读面）单测
 *
 * 查找链：$OCC_MODEL_TOML（显式最高，单文件老语义）＞ ~/.aikernel/
 * model.toml（用户层）＞ /etc/aikernel/models.d 下 *.toml（系统层，
 * 按文件名序）。合并语义：模型 id 同名=用户层覆盖系统层（系统层内
 * 后文件覆盖先文件）；其余合并；选择器后层非空覆盖；provider 引用段
 * 同规则；任一层加载失败=跳过该层继续（诚实降级，不整脸崩）；全层
 * 不可读才 -1。无 models.d 目录=现状等价（只走用户层）。
 * 全部走临时目录桩（不碰 /etc、不依赖 env）；T9 例外——直读仓内
 * 出厂件 factory/etc/aikernel/models.d（AIK_REPO_ROOT 可显式指仓根）。
 */
#define _DEFAULT_SOURCE 1		/* mkdtemp（严格 c11 下的 POSIX 面） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "occ_llm/occ_provider.h"

static int fails;

#define CHECK(cond) do { \
	if (!(cond)) { fails++; \
		printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

static void wfile(const char *p, const char *s)
{
	FILE *f = fopen(p, "w");

	if (!f) {
		printf("FAIL wfile %s\n", p);
		exit(1);
	}
	fputs(s, f);
	fclose(f);
}

/* 桩槽位生成器（缓冲归调用方——多段拼接不受静态存储干扰） */
static void slot_toml(char *buf, size_t buflen, const char *id,
		      const char *url)
{
	snprintf(buf, buflen,
		 "[models.%s]\n"
		 "provider_type = \"openai_compatible\"\n"
		 "model_name = \"m-%s\"\n"
		 "base_url = \"%s\"\n"
		 "api_key = \"k-%s\"\n", id, id, url, id);
}

static const occ_model_slot *find_slot(const occ_provider_config *cfg,
				       const char *id)
{
	size_t i;

	for (i = 0; i < cfg->nslots; i++)
		if (!strcmp(cfg->slots[i].id, id))
			return &cfg->slots[i];
	return NULL;
}

static const occ_provider_def *find_def(const occ_provider_config *cfg,
					const char *name)
{
	size_t i;

	for (i = 0; i < cfg->nproviders; i++)
		if (!strcmp(cfg->providers[i].name, name))
			return &cfg->providers[i];
	return NULL;
}

int main(void)
{
	char dir[] = "/tmp/occ-p2a-chain-XXXXXX";
	char user_toml[300], env_toml[300], sysd[300];
	char f1[400], f2[400], f3[400];
	char s1[512], s2[512];
	occ_provider_config cfg;

	if (!mkdtemp(dir)) {
		printf("FAIL mkdtemp\n");
		return 1;
	}
	snprintf(user_toml, sizeof(user_toml), "%s/user.toml", dir);
	snprintf(env_toml, sizeof(env_toml), "%s/env.toml", dir);
	snprintf(sysd, sizeof(sysd), "%s/models.d", dir);
	mkdir(sysd, 0755);
	/* 系统层按文件名序：10-a < 20-b */
	snprintf(f1, sizeof(f1), "%s/10-a.toml", sysd);
	snprintf(f2, sizeof(f2), "%s/20-b.toml", sysd);
	snprintf(f3, sizeof(f3), "%s/30-bad.toml", sysd);
	slot_toml(s1, sizeof(s1), "sys1", "http://sys1/v1");
	slot_toml(s2, sizeof(s2), "sys2", "http://sys2/v1");
	wfile(f1, s1);
	wfile(f2, s2);

	/* ---- T1：无用户层、无 env → 系统层可用（现状外延） ---- */
	occ_provider_config_init(&cfg);
	CHECK(occ_provider_load_user_system(&cfg, NULL, NULL, sysd, NULL) == 0);
	CHECK(cfg.nslots == 2);
	CHECK(find_slot(&cfg, "sys1") && find_slot(&cfg, "sys2"));
	occ_provider_config_free(&cfg);

	/* ---- T2：env 显式最高——整链旁路（单文件老语义） ---- */
	slot_toml(s1, sizeof(s1), "envm", "http://env/v1");
	wfile(env_toml, s1);
	slot_toml(s1, sizeof(s1), "usr1", "http://user/v1");
	wfile(user_toml, s1);
	occ_provider_config_init(&cfg);
	CHECK(occ_provider_load_user_system(&cfg, env_toml, user_toml, sysd,
					    NULL) == 0);
	CHECK(cfg.nslots == 1 && find_slot(&cfg, "envm"));
	CHECK(!find_slot(&cfg, "usr1") && !find_slot(&cfg, "sys1"));
	occ_provider_config_free(&cfg);
	/* env 空串=未设（走链） */
	occ_provider_config_init(&cfg);
	CHECK(occ_provider_load_user_system(&cfg, "", user_toml, sysd,
					    NULL) == 0);
	CHECK(find_slot(&cfg, "usr1") && find_slot(&cfg, "sys1"));
	occ_provider_config_free(&cfg);

	/* ---- T3：同名 id 用户层覆盖系统层；其余合并；选择器合并 ---- */
	wfile(user_toml,
	      "[default]\nmodel = \"usr1\"\n\n"
	      "[models.usr1]\nprovider_type = \"openai_compatible\"\n"
	      "model_name = \"m-usr1\"\nbase_url = \"http://user/v1\"\n"
	      "api_key = \"k-usr1\"\n\n"
	      "[models.sys2]\nprovider_type = \"openai_compatible\"\n"
	      "model_name = \"m-sys2-user\"\nbase_url = \"http://user-ovr/v1\"\n"
	      "api_key = \"k-sys2-user\"\n");
	occ_provider_config_init(&cfg);
	CHECK(occ_provider_load_user_system(&cfg, NULL, user_toml, sysd,
					    NULL) == 0);
	CHECK(cfg.nslots == 3);		/* sys1 + sys2(用户版) + usr1 */
	CHECK(find_slot(&cfg, "sys1"));
	CHECK(find_slot(&cfg, "sys2") &&
	      strcmp(find_slot(&cfg, "sys2")->base_url, "http://user-ovr/v1") == 0);
	CHECK(strcmp(cfg.selector, "usr1") == 0);
	occ_provider_config_free(&cfg);

	/* ---- T4：系统层内文件名序=后文件覆盖先文件 ---- */
	{
		char a2[1024], b2[1024], sh_old[512], sh_new[512];

		slot_toml(s1, sizeof(s1), "sys1", "http://sys1/v1");
		slot_toml(sh_old, sizeof(sh_old), "shared", "http://sys-old/v1");
		snprintf(a2, sizeof(a2), "%s%s", s1, sh_old);
		wfile(f1, a2);
		slot_toml(s2, sizeof(s2), "sys2", "http://sys2/v1");
		slot_toml(sh_new, sizeof(sh_new), "shared", "http://sys-new/v1");
		snprintf(b2, sizeof(b2), "%s%s", s2, sh_new);
		wfile(f2, b2);
		unlink(user_toml);	/* 无用户层：纯系统层序 */
		occ_provider_config_init(&cfg);
		CHECK(occ_provider_load_user_system(&cfg, NULL, user_toml, sysd,
						    NULL) == 0);
		CHECK(cfg.nslots == 3);
		CHECK(find_slot(&cfg, "shared") &&
		      strcmp(find_slot(&cfg, "shared")->base_url,
			     "http://sys-new/v1") == 0);	/* 20-b 覆盖 10-a */
		occ_provider_config_free(&cfg);
		/* 用户层回来：shared 再被用户层覆盖（三层优先级完整链） */
		slot_toml(sh_old, sizeof(sh_old), "shared", "http://user-ovr/v1");
		snprintf(b2, sizeof(b2), "%s%s",
			 "[default]\nmodel = \"shared\"\n", sh_old);
		wfile(user_toml, b2);
		occ_provider_config_init(&cfg);
		CHECK(occ_provider_load_user_system(&cfg, NULL, user_toml, sysd,
						    NULL) == 0);
		CHECK(find_slot(&cfg, "shared") &&
		      strcmp(find_slot(&cfg, "shared")->base_url,
			     "http://user-ovr/v1") == 0);
		CHECK(strcmp(cfg.selector, "shared") == 0);
		occ_provider_config_free(&cfg);
	}

	/* ---- T5：坏层跳过（诚实降级）；全坏才 -1 ---- */
	mkdir(f3, 0755);		/* 目录桩：read 必失败（与 uid 无关） */
	occ_provider_config_init(&cfg);
	CHECK(occ_provider_load_user_system(&cfg, NULL, user_toml, sysd,
					    NULL) == 0);	/* 30-bad 跳过 */
	CHECK(find_slot(&cfg, "sys1") && find_slot(&cfg, "sys2"));
	CHECK(find_slot(&cfg, "shared"));
	occ_provider_config_free(&cfg);
	/* 用户层也不可读 → 仅系统层仍可用 */
	unlink(user_toml);
	occ_provider_config_init(&cfg);
	CHECK(occ_provider_load_user_system(&cfg, NULL, user_toml, sysd,
					    NULL) == 0);
	CHECK(find_slot(&cfg, "sys1"));
	occ_provider_config_free(&cfg);
	/* 全层皆无（空系统目录+无用户层）→ -1 */
	{
		char emptyd[300];

		snprintf(emptyd, sizeof(emptyd), "%s/empty.d", dir);
		mkdir(emptyd, 0755);
		occ_provider_config_init(&cfg);
		CHECK(occ_provider_load_user_system(&cfg, NULL, NULL, emptyd,
						    NULL) == -1);
		CHECK(cfg.nslots == 0);
		occ_provider_config_free(&cfg);
	}

	/* ---- T6：models.d 目录不存在=现状等价（只走用户层） ---- */
	slot_toml(s1, sizeof(s1), "usr1", "http://user/v1");
	wfile(user_toml, s1);
	occ_provider_config_init(&cfg);
	CHECK(occ_provider_load_user_system(&cfg, NULL, user_toml,
					    "/tmp/occ-p2a-none-xxxx", NULL) == 0);
	CHECK(cfg.nslots == 1 && find_slot(&cfg, "usr1"));
	occ_provider_config_free(&cfg);

	/* ---- T7：provider 引用段合并（同名用户层覆盖+异名合并） ---- */
	{
		char p1[600], u3[1500];

		snprintf(p1, sizeof(p1),
			 "[provider.p1]\ntype = \"openai_compatible\"\n"
			 "base_url = \"http://sys-proxy/v1\"\n"
			 "key = \"sys-key\"\n");
		wfile(f1, p1);
		slot_toml(s1, sizeof(s1), "usr1", "http://user/v1");
		snprintf(u3, sizeof(u3),
			 "%s[provider.p1]\ntype = \"openai_compatible\"\n"
			 "base_url = \"http://user-proxy/v1\"\n"
			 "key = \"user-key\"\n"
			 "[provider.p2]\ntype = \"openai_compatible\"\n"
			 "base_url = \"http://user-p2/v1\"\nkey = \"k2\"\n", s1);
		wfile(user_toml, u3);
		occ_provider_config_init(&cfg);
		CHECK(occ_provider_load_user_system(&cfg, NULL, user_toml, sysd,
						    NULL) == 0);
		CHECK(cfg.nproviders == 2);
		CHECK(find_def(&cfg, "p1") &&
		      strcmp(find_def(&cfg, "p1")->base_url,
			     "http://user-proxy/v1") == 0);
		CHECK(find_def(&cfg, "p2"));
		occ_provider_config_free(&cfg);
	}

	/* ---- T8：load_chain 直测——空链 -1、坏内容层不炸 ---- */
	occ_provider_config_init(&cfg);
	CHECK(occ_provider_load_chain(&cfg, NULL, 0, NULL) == -1);
	occ_provider_config_free(&cfg);
	{
		char garb[300];
		const char *paths[2];

		snprintf(garb, sizeof(garb), "%s/garbage", dir);
		wfile(garb, "not a toml at all\n\x01\x02\xff\n[models.]\n");
		paths[0] = garb;
		paths[1] = user_toml;
		occ_provider_config_init(&cfg);
		CHECK(occ_provider_load_chain(&cfg, paths, 2, NULL) == 0);
		CHECK(find_slot(&cfg, "usr1"));
		occ_provider_config_free(&cfg);
	}

	/* ---- T9：仓内出厂件 factory/etc/aikernel/models.d（P-60 修复 2）----
	 * fresh 用户三层链全空 → load_chain -1 硬拒 → occ TUI 槽位解析先于
	 * gate、rc=1 死循环（17.11 装机台架咬出）；修=出厂落系统层共享槽
	 * cloud.toml。系统层目录指向仓内出厂件所在目录、用户层传 NULL →
	 * 链可用（0）且 cloud 槽可解析（base_url 是 resolve 必填项）。
	 * 定位：AIK_REPO_ROOT 显式优先；否则按 cwd 相对回退（make 自
	 * agent/ai/occ 跑=./tests/…，三级上=仓根）。找不到=FAIL（出厂件是
	 * 仓内资产，缺了就该红）。 */
	{
		char cand[1024], cl[1100], line[512];
		const char *root = getenv("AIK_REPO_ROOT");
		static const char *const rel[] = {
			"../../../factory/etc/aikernel/models.d",
			"../../../../factory/etc/aikernel/models.d",
			"factory/etc/aikernel/models.d",
			"../factory/etc/aikernel/models.d",
			NULL
		};
		size_t k;
		int found = 0, saw_base = 0, saw_sec = 0, saw_ptype = 0;
		FILE *lf;
		occ_provider p;

		if (root && root[0]) {
			snprintf(cand, sizeof(cand),
				 "%s/factory/etc/aikernel/models.d", root);
			snprintf(cl, sizeof(cl), "%s/cloud.toml", cand);
			found = access(cl, R_OK) == 0;
		} else {
			for (k = 0; rel[k] && !found; k++) {
				snprintf(cand, sizeof(cand), "%s", rel[k]);
				snprintf(cl, sizeof(cl), "%s/cloud.toml", cand);
				found = access(cl, R_OK) == 0;
			}
		}
		if (!found) {
			printf("FAIL %s:%d factory models.d not found "
			       "(set AIK_REPO_ROOT)\n", __FILE__, __LINE__);
			fails++;
		} else {
			occ_provider_config_init(&cfg);
			CHECK(occ_provider_load_user_system(&cfg, NULL, NULL,
							    cand, NULL) == 0);
			CHECK(find_slot(&cfg, "cloud") != NULL);
			CHECK(strcmp(cfg.selector, "cloud") == 0);
			memset(&p, 0, sizeof(p));
			CHECK(occ_provider_resolve(&cfg, "cloud", &p) == 0);
			CHECK(strcmp(p.name, "cloud") == 0);
			CHECK(p.base_url[0] != '\0');	/* resolve 必填项在 */
			occ_provider_free(&p);
			occ_provider_config_free(&cfg);
			/* 出厂件文本：[models.cloud] 段 + base_url + provider_type */
			lf = fopen(cl, "r");
			CHECK(lf != NULL);
			if (lf) {
				while (fgets(line, sizeof(line), lf)) {
					if (strcmp(line, "[models.cloud]\n") == 0)
						saw_sec = 1;
					if (strncmp(line, "base_url", 8) == 0)
						saw_base = 1;
					if (strncmp(line, "provider_type", 13) == 0)
						saw_ptype = 1;
				}
				fclose(lf);
			}
			CHECK(saw_sec);
			CHECK(saw_base);
			CHECK(saw_ptype);
		}
	}

	/* 清场 */
	{
		char cmd[340];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
		if (system(cmd) != 0)
			printf("FAIL cleanup\n");
	}
	if (fails) {
		printf("test_models_chain: %d FAIL\n", fails);
		return 1;
	}
	printf("test_models_chain: all ok (9 sections)\n");
	return 0;
}
