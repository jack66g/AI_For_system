// SPDX-License-Identifier: GPL-2.0
/*
 * test_acdigest.c - T5c 摘要模块差分测试（acdigest.c）
 *
 * units.vectors.json 全用例输出 JSON 逐字节：
 *   - template：render_template 与向量模板字符串逐字节；
 *   - validate / split / todo_open / reread / merge：函数输出 vs 向量 out；
 *   - restore：向量在 Windows 录制（绝对路径），本地复建同名快照文件后，
 *     期望值中的录制路径按用例 files 逐一替换为本地路径再逐字节比较
 *     （text/full_file/note/指针行中的路径是环境量，其余字节全对齐）；
 *   - 负向对照：对 template/split/restore 各篡改一个期望值，断言比较器
 *     必须检出差异（防止恒真比较）。
 *
 * 运行：TZ=Asia/Shanghai ./tests/test_acdigest
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acdigest.h"

#include "ac_vec.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* 紧凑 dump 相等比较（计入 checks）*/
static void dump_eq(const aik_json *got, const aik_json *want, const char *name)
{
	char *g = got ? ac_dump(got) : NULL;
	char *w = want ? ac_dump(want) : NULL;

	g_ac_checks++;
	if (!g || !w || strcmp(g, w) != 0)
		ac_fail("%s\n  got:  %s\n  want: %s", name,
			g ? g : "(null)", w ? w : "(null)");
	free(g);
	free(w);
}

/* 负向对照：断言两者 dump 必须不同（不计 failed，只计检查）*/
static void dump_differs(const aik_json *got, const aik_json *tampered,
			 const char *name)
{
	char *g = got ? ac_dump(got) : NULL;
	char *w = tampered ? ac_dump(tampered) : NULL;

	g_ac_checks++;
	if (g && w && strcmp(g, w) == 0)
		ac_fail("negative control %s: tampered expectation not detected",
			name);
	free(g);
	free(w);
}

static void str_eq(const char *got, const char *want, const char *name)
{
	g_ac_checks++;
	if (!got || !want || strcmp(got, want) != 0)
		ac_fail("%s\n  got:  %.400s\n  want: %.400s", name,
			got ? got : "(null)", want ? want : "(null)");
}

static char *write_file(const char *dir, const char *name, const char *data)
{
	size_t n = strlen(dir) + strlen(name) + 2;
	char *path = malloc(n);
	FILE *f;

	snprintf(path, n, "%s/%s", dir, name);
	f = fopen(path, "wb");
	if (!f) {
		ac_fail("cannot write %s", path);
		free(path);
		return NULL;
	}
	fwrite(data, 1, strlen(data), f);
	fclose(f);
	return path;
}

/* 深拷贝 */
static aik_json *jcopy(const aik_json *v)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_BOOL:
		return aik_json_new_bool(aik_json_bool(v));
	case AIK_JSON_INT:
		return aik_json_new_int(aik_json_int(v));
	case AIK_JSON_NUM:
		return aik_json_new_num(aik_json_num(v));
	case AIK_JSON_STR:
		return aik_json_new_str(aik_json_str(v) ? aik_json_str(v) : "");
	case AIK_JSON_ARR: {
		aik_json *arr = aik_json_new_arr();
		size_t n = aik_json_count(v);

		for (size_t i = 0; arr && i < n; i++)
			aik_json_arr_push(arr, jcopy(aik_json_at(v, i)));
		return arr;
	}
	case AIK_JSON_OBJ: {
		aik_json *obj = aik_json_new_obj();
		size_t n = aik_json_count(v);

		for (size_t i = 0; obj && i < n; i++)
			aik_json_obj_put(obj, aik_json_key_at(v, i),
					 jcopy(aik_json_val_at(v, i)));
		return obj;
	}
	default:
		return aik_json_new_null();
	}
}

/* STR 值内把 from 全部替换为 to（深度拷贝；restore 路径归一用）*/
static aik_json *subst_str(const aik_json *v, const char *from, const char *to)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_STR: {
		const char *s = aik_json_str(v) ? aik_json_str(v) : "";
		size_t fl = strlen(from), tl = strlen(to), sl = strlen(s);
		size_t cap = sl + tl + 1;
		char *buf = malloc(cap);
		size_t o = 0, i = 0;

		if (!buf)
			return aik_json_new_str(s);
		while (i < sl) {
			if (fl && i + fl <= sl && strncmp(s + i, from, fl) == 0) {
				while (o + tl + 1 > cap) {
					size_t nc = cap * 2 + tl;
					char *g = realloc(buf, nc);

					if (!g) {
						free(buf);
						return aik_json_new_str(s);
					}
					cap = nc;
					buf = g;
				}
				memcpy(buf + o, to, tl);
				o += tl;
				i += fl;
				continue;
			}
			if (o + 2 > cap) {
				size_t nc = cap * 2 + 1;
				char *g = realloc(buf, nc);

				if (!g) {
					free(buf);
					return aik_json_new_str(s);
				}
				cap = nc;
				buf = g;
			}
			buf[o++] = s[i++];
		}
		buf[o] = '\0';
		{
			aik_json *out = aik_json_new_str(buf);

			free(buf);
			return out;
		}
	}
	case AIK_JSON_ARR: {
		aik_json *arr = aik_json_new_arr();
		size_t n = aik_json_count(v);

		for (size_t i = 0; i < n; i++)
			aik_json_arr_push(arr, subst_str(aik_json_at(v, i), from, to));
		return arr;
	}
	case AIK_JSON_OBJ: {
		aik_json *obj = aik_json_new_obj();
		size_t n = aik_json_count(v);

		for (size_t i = 0; i < n; i++)
			aik_json_obj_put(obj, aik_json_key_at(v, i),
					 subst_str(aik_json_val_at(v, i), from, to));
		return obj;
	}
	default:
		return v ? jcopy(v) : aik_json_new_null();
	}
}

static const char *jstr(const aik_json *v, const char *key)
{
	const aik_json *s = aik_json_get(v, key);

	return (s && aik_json_typeof(s) == AIK_JSON_STR) ? aik_json_str(s) : NULL;
}

/* base_tags ARR → C 数组 */
static const char **tags_of(const aik_json *v, size_t *n)
{
	const aik_json *arr = aik_json_get(v, "base_tags");
	size_t cnt = arr ? aik_json_count(arr) : 0;
	const char **out = malloc((cnt ? cnt : 1) * sizeof(*out));

	*n = 0;
	if (!out)
		return NULL;
	for (size_t i = 0; i < cnt; i++) {
		const aik_json *e = aik_json_at(arr, i);

		if (e && aik_json_typeof(e) == AIK_JSON_STR)
			out[(*n)++] = aik_json_str(e);
	}
	return out;
}

/* 录制路径码点数（UTF-8 非续导字节计数）*/
static size_t cp_len(const char *s)
{
	size_t n = 0;

	for (const unsigned char *p = (const unsigned char *)s; *p; p++)
		if ((*p & 0xC0) != 0x80)
			n++;
	return n;
}

/*
 * 建本地快照目录：/tmp/<name>/snap0.md 总码点数 == 最新快照录制路径的
 * 码点数（restore 截断预算对齐用）。返回 malloc 目录路径。
 */
static char *aligned_snap_dir(const aik_json *cases)
{
	const aik_json *c0 = aik_json_at(cases, 0);
	const aik_json *files = aik_json_get(c0, "files");
	const aik_json *f0 = files ? aik_json_at(files, 0) : NULL;
	size_t want = f0 && aik_json_typeof(f0) == AIK_JSON_STR
		? cp_len(aik_json_str(f0)) : 52;
	size_t name_len, base_len;
	char *dir;
	long pid = (long)getpid();
	char pidbuf[24];
	size_t plen;

	snprintf(pidbuf, sizeof(pidbuf), "%ld", pid);
	plen = strlen(pidbuf);
	/* "/tmp/"(5) + name + "/snap0.md"(9) == want */
	if (want < 5 + 9 + plen + 2)
		want = 5 + 9 + plen + 2;
	name_len = want - 5 - 9;
	base_len = strlen("ac-dg-t5c-") + plen + 1;	/* 前缀 + pid + '-' */
	dir = malloc(name_len + 6 + 1);
	if (!dir)
		return NULL;
	memcpy(dir, "/tmp/", 5);
	size_t o = 5;

	memcpy(dir + o, "ac-dg-t5c-", strlen("ac-dg-t5c-"));
	o += strlen("ac-dg-t5c-");
	memcpy(dir + o, pidbuf, plen);
	o += plen;
	(void)base_len;
	if (o < 5 + name_len) {
		dir[o++] = '-';
		while (o < 5 + name_len)
			dir[o++] = 'q';
	}
	dir[o] = '\0';
	if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
		free(dir);
		return NULL;
	}
	return dir;
}

int main(void)
{
	aik_json *units = ac_load_vector("ac/units.vectors.json");

	if (!units)
		return 2;

	/* ---- template ---- */
	{
		char *got = ac_render_template("myproj", "2026-03-31T07:33:20",
					       "plan_done");
		const char *want = jstr(units, "template");

		str_eq(got, want, "template");
		/* 负向对照：篡改期望一个字节必须检出 */
		{
			char *tampered = strdup(want ? want : "");

			if (tampered && strlen(tampered) > 40)
				tampered[40] = (char)(tampered[40] ^ 0x20);
			g_ac_checks++;
			if (tampered && got && strcmp(tampered, got) == 0)
				ac_fail("negative control template: not detected");
			free(tampered);
		}
		free(got);
	}

	/* ---- validate（[ok, errors] 形状）---- */
	{
		const aik_json *cases = aik_json_get(units, "validate");

		for (size_t i = 0; cases && i < aik_json_count(cases); i++) {
			const aik_json *c = aik_json_at(cases, i);
			const char *name = jstr(c, "name");
			const char *md = jstr(c, "md");
			aik_json *errs = ac_validate(md ? md : "");
			aik_json *pair = aik_json_new_arr();

			aik_json_arr_push(pair, aik_json_new_bool(
				aik_json_count(errs) == 0));
			aik_json_arr_push(pair, errs);
			dump_eq(pair, aik_json_get(c, "out"), name ? name : "validate");
			aik_json_free(pair);
		}
	}

	/* ---- split ---- */
	{
		const aik_json *cases = aik_json_get(units, "split");

		for (size_t i = 0; cases && i < aik_json_count(cases); i++) {
			const aik_json *c = aik_json_at(cases, i);
			const char *name = jstr(c, "name");
			const char *md = jstr(c, "md");
			const char *project = jstr(c, "project");
			const char *ts = jstr(c, "ts");
			const char *trigger = jstr(c, "trigger");
			const aik_json *cap = aik_json_get(c, "cap");
			size_t n_tags = 0;
			const char **tags = tags_of(c, &n_tags);
			size_t n_out = 0;
			ac_segment *segs = ac_split_digest(
				md ? md : "", tags, n_tags, project ? project : "",
				ts ? ts : "", trigger ? trigger : "",
				cap && aik_json_typeof(cap) == AIK_JSON_INT,
				cap ? aik_json_int(cap) : 0, &n_out);
			aik_json *got = ac_segments_to_json(segs, n_out);

			dump_eq(got, aik_json_get(c, "out"), name ? name : "split");
			/* 负向对照（仅首个用例）：篡改一段 text 必须检出 */
			if (i == 0) {
				aik_json *tampered = jcopy(aik_json_get(c, "out"));
				const aik_json *seg0 = aik_json_at(tampered, 0);
				const aik_json *txt = aik_json_get(seg0, "text");

				if (txt && aik_json_typeof(txt) == AIK_JSON_STR) {
					char buf[256];

					snprintf(buf, sizeof(buf), "%sX",
						 aik_json_str(txt));
					aik_json_obj_set((aik_json *)seg0, "text",
							 aik_json_new_str(buf));
				}
				dump_differs(got, tampered, "split tampered");
				aik_json_free(tampered);
			}
			ac_segments_free(segs, n_out);
			aik_json_free(got);
			free(tags);
		}
	}

	/* ---- todo_open ---- */
	{
		const aik_json *cases = aik_json_get(units, "todo_open");

		for (size_t i = 0; cases && i < aik_json_count(cases); i++) {
			const aik_json *c = aik_json_at(cases, i);
			const char *md = jstr(c, "md");
			const aik_json *want = aik_json_get(c, "out");
			int got = ac_todo_open(md ? md : "");

			g_ac_checks++;
			if (!want || aik_json_typeof(want) != AIK_JSON_BOOL ||
			    aik_json_bool(want) != got)
				ac_fail("todo_open[%zu]: got %d", i, got);
		}
	}

	/* ---- reread ---- */
	{
		const aik_json *cases = aik_json_get(units, "reread");

		for (size_t i = 0; cases && i < aik_json_count(cases); i++) {
			const aik_json *c = aik_json_at(cases, i);
			const char *md = jstr(c, "md");
			const aik_json *limit = aik_json_get(c, "limit");
			aik_json *got = ac_extract_reread_files(
				md ? md : "",
				limit && aik_json_typeof(limit) == AIK_JSON_INT
					? (int)aik_json_int(limit) : 0);

			dump_eq(got, aik_json_get(c, "out"), "reread");
			aik_json_free(got);
		}
	}

	/* ---- merge ---- */
	{
		const aik_json *cases = aik_json_get(units, "merge");

		for (size_t i = 0; cases && i < aik_json_count(cases); i++) {
			const aik_json *c = aik_json_at(cases, i);
			const char *name = jstr(c, "name");
			const aik_json *texts = aik_json_get(c, "texts");
			size_t n = texts ? aik_json_count(texts) : 0;
			const char **arr = malloc((n ? n : 1) * sizeof(*arr));

			for (size_t k = 0; k < n; k++) {
				const aik_json *t = aik_json_at(texts, k);

				arr[k] = (t && aik_json_typeof(t) == AIK_JSON_STR)
					? aik_json_str(t) : "";
			}
			{
				char *got = ac_merge_delta_chain(arr, n);
				const char *want = jstr(c, "out");

				str_eq(got, want, name ? name : "merge");
				free(got);
			}
			free(arr);
		}
	}

	/* ---- restore ---- */
	{
		const aik_json *cases = aik_json_get(units, "restore");
		const aik_json *good_md = NULL;
		{
			const aik_json *vc = aik_json_get(units, "validate");

			good_md = aik_json_at(vc, 0);
		}
		/*
		 * 截断用例的指针行长度 = 录制路径长度（预算 - reserve 二次打包，
		 * 截断字数随路径长度变化）。本地快照目录长度对齐录制路径的码点
		 * 数（52），使预算推导一致；路径字符串本身仍按用例替换比较。
		 */
	(void)ac_mkdtemp;
		char *dir = aligned_snap_dir(cases);

		if (!dir) {
			ac_fail("snap dir create failed");
			ac_summary("test_acdigest");
			return g_ac_failed ? 1 : 0;
		}
		for (size_t i = 0; cases && i < aik_json_count(cases); i++) {
			const aik_json *c = aik_json_at(cases, i);
			const char *name = jstr(c, "name");
			const aik_json *files = aik_json_get(c, "files");
			const aik_json *maxc = aik_json_get(c, "max_chars");
			const aik_json *rl = aik_json_get(c, "reread_limit");
			const aik_json *merged = aik_json_get(c, "merged_md");
			size_t n = files ? aik_json_count(files) : 0;
			char **local = malloc((n ? n : 1) * sizeof(*local));
			const char **pass = malloc((n ? n : 1) * sizeof(*pass));
			size_t np = 0;

			/* 复建快照文件：snap0 = good md（pack 输入），其余 = 标题行 */
			for (size_t k = 0; k < n; k++) {
				const aik_json *f = aik_json_at(files, k);
				const char *vp = (f && aik_json_typeof(f) == AIK_JSON_STR)
					? aik_json_str(f) : NULL;

				if (!vp)
					continue;
				if (strstr(vp, "snap0.md")) {
					local[np] = write_file(dir, "snap0.md",
						jstr(good_md, "md") ? jstr(good_md, "md") : "");
				} else if (strstr(vp, "snap1.md")) {
					local[np] = write_file(dir, "snap1.md",
						"# 会话快照 · myproj · 2026-03-31T07:33:20 · 触发:plan_done\n");
				} else {
					/* no.md：保持不存在 */
					local[np] = strdup(vp);
				}
				pass[np] = local[np];
				np++;
			}
			{
				aik_json *got = ac_build_restore_payload(
					pass, np,
					maxc && aik_json_typeof(maxc) == AIK_JSON_INT
						? aik_json_int(maxc) : 0,
					rl && aik_json_typeof(rl) == AIK_JSON_INT,
					rl ? aik_json_int(rl) : 0,
					merged && aik_json_typeof(merged) == AIK_JSON_STR,
					merged && aik_json_typeof(merged) == AIK_JSON_STR
						? aik_json_str(merged) : NULL);
				/* 期望值中的录制绝对路径 → 本地路径（逐用例替换）*/
				const aik_json *want_ref = aik_json_get(c, "out");
				aik_json *want = NULL;

				for (size_t k = 0; k < np; k++) {
					const aik_json *f = aik_json_at(files, k);
					const char *vp = aik_json_str(f);
					aik_json *sub = subst_str(want ? want : want_ref,
								  vp, local[k]);

					aik_json_free(want);
					want = sub;
				}
				dump_eq(got, want ? want : want_ref,
					name ? name : "restore");
				/* 负向对照（首个用例）：篡改 truncated 必须检出 */
				if (i == 0) {
					aik_json *tampered = jcopy(want ? want : want_ref);

					aik_json_obj_set(tampered, "truncated",
							 aik_json_new_bool(1));
					dump_differs(got, tampered, "restore tampered");
					aik_json_free(tampered);
				}
				aik_json_free(got);
				aik_json_free(want);
			}
			for (size_t k = 0; k < np; k++)
				free(local[k]);
			free(local);
			free(pass);
		}
		free(dir);
	}

	ac_summary("test_acdigest");
	return g_ac_failed ? 1 : 0;
}
