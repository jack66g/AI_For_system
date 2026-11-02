/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_acstate.c - T5b StateStore 差分测试（acstate.c）
 *
 * 按 parity/vectors/ac/stateops.vectors.json 的 17 组 checks 逐组复现
 * 录制器调用序列（parity/rec/record_ac_state.py）：每个 check 先执行其
 * 对应操作、再断言该步快照，与录制器逐步快照完全同构：
 *   - summary JSON / 索引条目 / 事件列表 与向量逐字节（紧凑 dump 后 strcmp）；
 *   - 最终 6 个磁盘文件与 disk 段逐字节（<DATA_DIR> 替换为实际临时目录，
 *     checks 内的录制器临时路径前缀同步替换）；目录无多余文件。
 * 另测：损坏 sessions-state.json → quarantine 后清空；落盘往返加载等价。
 *
 * 运行：TZ=Asia/Shanghai ./tests/test_acstate（冻结时钟 epoch=1775000000）
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acstate.h"

#include "ac_vec.h"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define FROZEN_EPOCH 1775000000.0
#define RECORDED_DATA_DIR "/tmp/ac-state-qjv24_hc"	/* 录制器临时目录前缀 */
#define CWD "/tmp/ac-state-proj"

static char *path_join2(const char *a, const char *b)
{
	size_t n = strlen(a) + 1 + strlen(b) + 1;
	char *out = malloc(n);

	if (out)
		snprintf(out, n, "%s/%s", a, b);
	return out;
}

static void count_cmp(char *got, char *want, const char *name)
{
	g_ac_checks++;
	if (!got || !want || strcmp(got, want) != 0)
		ac_fail("%s mismatch\n  got:  %s\n  want: %s", name,
			got ? got : "(null)", want ? want : "(null)");
	free(got);
	free(want);
}

/* 期望文本（向量节点紧凑重排 + 录制目录前缀替换），返回 malloc 串 */
static char *expect_text_replaced(const aik_json *v, const char *data_dir)
{
	char *text = ac_dump(v);

	if (!text)
		return NULL;
	size_t nlen = strlen(text);
	size_t plen = strlen(RECORDED_DATA_DIR);
	size_t dlen = strlen(data_dir);
	size_t count = 0;

	for (size_t i = 0; i + plen <= nlen; i++)
		if (memcmp(text + i, RECORDED_DATA_DIR, plen) == 0) {
			count++;
			i += plen - 1;
		}
	if (count == 0 || dlen == plen)
		return text;
	size_t extra = count * (dlen > plen ? dlen - plen : 0);
	char *out = malloc(nlen + extra + 1);

	if (!out) {
		free(text);
		return NULL;
	}
	size_t w = 0;

	for (size_t i = 0; i < nlen;) {
		if (i + plen <= nlen &&
		    memcmp(text + i, RECORDED_DATA_DIR, plen) == 0) {
			memcpy(out + w, data_dir, dlen);
			w += dlen;
			i += plen;
		} else {
			out[w++] = text[i++];
		}
	}
	out[w] = '\0';
	free(text);
	return out;
}

/* 磁盘期望文本：<DATA_DIR> → 实际临时目录 */
static char *disk_expect(const char *text, const char *data_dir)
{
	size_t nlen = strlen(text);
	size_t dlen = strlen(data_dir);
	size_t count = 0;

	for (size_t i = 0; i + 10 <= nlen; i++)
		if (memcmp(text + i, "<DATA_DIR>", 10) == 0) {
			count++;
			i += 9;
		}
	if (count == 0)
		return strdup(text);
	char *out = malloc(nlen + count * dlen + 1);

	if (!out)
		return NULL;
	size_t w = 0;

	for (size_t i = 0; i < nlen;) {
		if (i + 10 <= nlen && memcmp(text + i, "<DATA_DIR>", 10) == 0) {
			memcpy(out + w, data_dir, dlen);
			w += dlen;
			i += 10;
		} else {
			out[w++] = text[i++];
		}
	}
	out[w] = '\0';
	return out;
}

struct strlist {
	char **v;
	size_t n, cap;
};

static void sl_push(struct strlist *l, char *s)
{
	if (l->n == l->cap) {
		l->cap = l->cap ? l->cap * 2 : 16;
		l->v = realloc(l->v, l->cap * sizeof(*l->v));
	}
	l->v[l->n++] = s;
}

static int sl_cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static void walk_dir(const char *root, const char *rel, struct strlist *out)
{
	char *dir = rel[0] ? path_join2(root, rel) : strdup(root);
	DIR *d = opendir(dir);

	if (!d) {
		free(dir);
		return;
	}
	struct dirent *e;

	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			continue;
		char *child = rel[0] ? path_join2(rel, e->d_name)
				     : strdup(e->d_name);
		char *full = path_join2(root, child);
		struct stat sb;

		if (stat(full, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			walk_dir(root, child, out);
			free(child);
		} else {
			sl_push(out, child);
		}
		free(full);
	}
	closedir(d);
	free(dir);
}

static aik_json *parse_text(const char *text)
{
	char err[128];
	aik_json *v = aik_json_parse(text, strlen(text), err, sizeof(err));

	if (!v) {
		fprintf(stderr, "FATAL: fixture parse: %s\n", err);
		exit(2);
	}
	return v;
}

/* summary 列表与向量逐组比对 */
static void compare_sessions(ac_store *st, const aik_json *want, const char *name)
{
	size_t n = 0;
	const ac_session **all = ac_store_all_sessions(st, &n);

	g_ac_checks++;
	if (!all || n != aik_json_count(want)) {
		ac_fail("%s: session count %zu != %zu", name, n,
			aik_json_count(want));
		free(all);
		return;
	}
	aik_json *arr = aik_json_new_arr();

	for (size_t k = 0; k < n; k++) {
		aik_json *s = ac_session_summary(all[k]);

		if (!s || aik_json_arr_push(arr, s) != 0) {
			aik_json_free(s);
			ac_fail("%s: summary build", name);
		}
	}
	count_cmp(ac_dump(arr), ac_dump(want), name);
	aik_json_free(arr);
	free(all);
}

int main(void)
{
	aik_json *vec = ac_load_vector("ac/stateops.vectors.json");

	if (!vec)
		return 2;
	ac_time_set_now(FROZEN_EPOCH);
	unsetenv("AUTOCONDENSE_PORT");

	char *data_dir = ac_mkdtemp("/tmp/ac-state-");

	if (!data_dir) {
		fprintf(stderr, "FATAL: mkdtemp\n");
		return 2;
	}
	ac_config cfg;

	ac_config_default(&cfg);
	ac_store *st = ac_store_open(data_dir, &cfg);

	if (!st) {
		fprintf(stderr, "FATAL: store open\n");
		return 2;
	}
	const aik_json *checks = aik_json_get(vec, "checks");

	if (!checks || aik_json_typeof(checks) != AIK_JSON_ARR) {
		fprintf(stderr, "FATAL: vector has no checks\n");
		return 2;
	}
	size_t nchecks = aik_json_count(checks);

	char h[11];

	if (ac_project_hash(CWD, h) != 0) {
		fprintf(stderr, "FATAL: project hash\n");
		return 2;
	}

	char *path1 = NULL, *path2 = NULL;
	aik_json *entry1 = NULL, *entry2 = NULL, *list1 = NULL, *list2 = NULL;
	aik_json *events = NULL;
	long long delta_val = 0;
	const ac_session *missing = NULL;
	int bump_missing = -1;

	/* 按 checks 顺序：先执行该组操作，再比对（录制器逐步快照同构）*/
	for (size_t i = 0; i < nchecks; i++) {
		const aik_json *c = aik_json_at(checks, i);
		const char *name = aik_json_str(aik_json_get(c, "name"));

		if (!name) {
			ac_fail("check[%zu] has no name", i);
			continue;
		}
		if (strcmp(name, "upsert") == 0) {
			ac_store_upsert(st, "s1", CWD, "/tmp/tr.jsonl", 1, 1000, 0, 0);
		} else if (strcmp(name, "bump2") == 0) {
			ac_store_bump_turn(st, "s1");
			ac_store_bump_turn(st, "s1");
		} else if (strcmp(name, "plan") == 0) {
			aik_json *items = parse_text(
				"[{\"title\":\"a\",\"status\":\"completed\"},"
				"{\"title\":\"b\",\"status\":\"in_progress\"},"
				"{\"title\":\"c\",\"status\":\"pending\"}]");

			ac_store_update_plan(st, "s1", items);
			aik_json_free(items);
		} else if (strcmp(name, "plan_shrink") == 0) {
			ac_store_bump_turn(st, "s1");
			aik_json *items = parse_text(
				"[{\"title\":\"b\",\"status\":\"completed\"}]");

			ac_store_update_plan(st, "s1", items);
			aik_json_free(items);
		} else if (strcmp(name, "activity") == 0) {
			ac_store_mark_activity(st, "s1", AC_ACTIVITY_FILE);
			ac_store_mark_activity(st, "s1", AC_ACTIVITY_FAIL);
		} else if (strcmp(name, "condensing") == 0) {
			ac_store_set_est_tokens(st, "s1", 1, 12345);
			ac_store_set_condensing(st, "s1", 1);
			ac_store_set_begin_mode(st, "s1", "delta");
		} else if (strcmp(name, "judge") == 0) {
			aik_json *verdict = parse_text(
				"{\"task_finished\":true,\"impact\":\"low\","
				"\"safe_to_compress\":true,\"reason\":\"ok\"}");

			ac_store_record_judge(st, "s1", verdict, "APPROVED");
			aik_json_free(verdict);
		} else if (strcmp(name, "defer") == 0) {
			ac_store_set_defer_until_turn(st, "s1", 1, 12);
			ac_store_set_defer_streak(st, "s1", 2);
		} else if (strcmp(name, "snapshot1") == 0) {
			entry1 = ac_store_save_snapshot(st, "快照正文一", "plan_done",
							"s1", 0, &path1);
		} else if (strcmp(name, "snapshot2") == 0) {
			ac_store_write_delta_state(st, h, 1);
			entry2 = ac_store_save_snapshot(st, "快照正文二", "judge",
							"s1", 1, &path2);
		} else if (strcmp(name, "list_snapshots") == 0) {
			list1 = ac_store_list_snapshots(st, h, 0, 0);
		} else if (strcmp(name, "delta_state") == 0) {
			delta_val = ac_store_read_delta_state(st, h);
		} else if (strcmp(name, "after_memid") == 0) {
			ac_store_set_snapshot_memory_id(st, h, path1, "m_abc");
			list2 = ac_store_list_snapshots(st, h, 0, 0);
		} else if (strcmp(name, "clear_completed") == 0) {
			ac_store_clear_completed_plan_items(st, "s1");
		} else if (strcmp(name, "mark_condensed") == 0) {
			ac_store_mark_condensed(st, "s1", "plan_done");
		} else if (strcmp(name, "recent_events") == 0) {
			aik_json *data = parse_text("{\"k\":[1,2]}");

			ac_store_append_event(st, "custom", "s1", CWD, data);
			aik_json_free(data);
			events = ac_store_recent_events(st, 5, 0);
		} else if (strcmp(name, "missing_session") == 0) {
			missing = ac_store_get_session(st, "nope");
			bump_missing = ac_store_bump_turn(st, "nope");
		}

		/* ---- 本组断言 ---- */
		if (strcmp(name, "snapshot1") == 0 || strcmp(name, "snapshot2") == 0) {
			aik_json *entry = (name[8] == '1') ? entry1 : entry2;
			const char *path = (name[8] == '1') ? path1 : path2;

			count_cmp(ac_dump(entry),
				  expect_text_replaced(aik_json_get(c, "entry"),
						       data_dir),
				  "check snapshot entry");
			const char *want = aik_json_str(aik_json_get(c, "path_base"));
			const char *got_base = strrchr(path, '/');

			got_base = got_base ? got_base + 1 : path;
			g_ac_checks++;
			if (!want || strcmp(got_base, want) != 0)
				ac_fail("check %s.path_base got=%s want=%s", name,
					got_base, want ? want : "(null)");
			continue;
		}
		if (strcmp(name, "list_snapshots") == 0) {
			count_cmp(ac_dump(list1),
				  expect_text_replaced(aik_json_get(c, "entries"),
						       data_dir),
				  "check list_snapshots");
			continue;
		}
		if (strcmp(name, "after_memid") == 0) {
			count_cmp(ac_dump(list2),
				  expect_text_replaced(aik_json_get(c, "entries"),
						       data_dir),
				  "check after_memid");
			continue;
		}
		if (strcmp(name, "delta_state") == 0) {
			g_ac_checks++;
			if (delta_val != aik_json_int(aik_json_get(c, "value")))
				ac_fail("check delta_state got=%lld", delta_val);
			continue;
		}
		if (strcmp(name, "recent_events") == 0) {
			count_cmp(ac_dump(events),
				  expect_text_replaced(aik_json_get(c, "events"),
						       data_dir),
				  "check recent_events");
			continue;
		}
		if (strcmp(name, "missing_session") == 0) {
			g_ac_checks++;
			if (missing != NULL)
				ac_fail("check missing_session.get should be null");
			g_ac_checks++;
			if (bump_missing == 0)
				ac_fail("check missing_session.bump should fail");
			continue;
		}
		const aik_json *want_sessions = aik_json_get(c, "sessions");

		if (want_sessions)
			compare_sessions(st, want_sessions, name);
	}

	aik_json_free(entry1);
	aik_json_free(entry2);
	aik_json_free(list1);
	aik_json_free(list2);
	aik_json_free(events);

	/* ---- 磁盘逐字节（含“无多余文件”）---- */
	const aik_json *disk = aik_json_get(vec, "disk");

	if (!disk || aik_json_typeof(disk) != AIK_JSON_OBJ) {
		fprintf(stderr, "FATAL: vector has no disk\n");
		return 2;
	}
	struct strlist actual = { 0 };

	walk_dir(data_dir, "", &actual);
	qsort(actual.v, actual.n, sizeof(*actual.v), sl_cmp);

	g_ac_checks++;
	if (actual.n != aik_json_count(disk))
		ac_fail("disk file count %zu != %zu", actual.n,
			aik_json_count(disk));
	for (size_t i = 0; i < actual.n && i < aik_json_count(disk); i++) {
		const char *want_key = aik_json_key_at(disk, i);

		g_ac_checks++;
		if (strcmp(actual.v[i], want_key) != 0) {
			ac_fail("disk[%zu] name got=%s want=%s", i, actual.v[i],
				want_key);
			continue;
		}
		char *want_text = disk_expect(aik_json_str(aik_json_val_at(disk, i)),
					      data_dir);
		char *fp = path_join2(data_dir, actual.v[i]);
		size_t flen = 0;
		char *got_text = ac_slurp(fp, &flen);

		g_ac_checks++;
		if (!got_text || !want_text || flen != strlen(want_text) ||
		    memcmp(got_text, want_text, flen) != 0)
			ac_fail("disk %s bytes differ (got %zu bytes, want %zu)",
				actual.v[i], flen,
				want_text ? strlen(want_text) : 0);
		free(got_text);
		free(want_text);
		free(fp);
	}
	for (size_t i = 0; i < actual.n; i++)
		free(actual.v[i]);
	free(actual.v);

	/* project_hash / project_name / normalize_status（向量佐证）*/
	{
		g_ac_checks++;
		if (strcmp(h, aik_json_str(aik_json_get(vec, "project_hash"))) != 0)
			ac_fail("project_hash got=%s", h);
		char nm[256];

		ac_project_name(CWD, nm, sizeof(nm));
		g_ac_checks++;
		if (strcmp(nm, "ac-state-proj") != 0)
			ac_fail("project_name got=%s", nm);
		g_ac_checks++;
		if (strcmp(ac_normalize_status("DONE"), "completed") != 0 ||
		    strcmp(ac_normalize_status("In-Progress"), "in_progress") != 0 ||
		    strcmp(ac_normalize_status("whatever"), "pending") != 0 ||
		    strcmp(ac_normalize_status(NULL), "pending") != 0)
			ac_fail("normalize_status");
	}

	ac_store_close(st);
	ac_config_cleanup(&cfg);

	/* ---- 损坏容忍：quarantine 后清空重来 ---- */
	{
		char *dir2 = ac_mkdtemp("/tmp/ac-state-");

		if (!dir2)
			return 2;
		char *p = path_join2(dir2, "sessions-state.json");
		FILE *f = fopen(p, "wb");

		if (f) {
			fwrite("{not json", 1, 9, f);
			fclose(f);
		}
		ac_store *st2 = ac_store_open(dir2, NULL);
		size_t n2 = 0;
		const ac_session **all2 = st2 ? ac_store_all_sessions(st2, &n2) : NULL;

		g_ac_checks++;
		if (!st2 || n2 != 0)
			ac_fail("corrupt store should load 0 sessions (got %zu)", n2);
		free(all2);

		char stamp[32];

		ac_stamp_now(stamp, sizeof(stamp));
		char qpath[512];

		snprintf(qpath, sizeof(qpath), "%s.corrupt-%s", p, stamp);
		g_ac_checks++;
		if (access(qpath, F_OK) != 0)
			ac_fail("quarantine file missing: %s", qpath);
		g_ac_checks++;
		if (access(p, F_OK) == 0)
			ac_fail("corrupt file should be renamed away");
		ac_store_close(st2);
		free(p);
		free(dir2);
	}

	/* ---- 落盘往返：重开加载后 asdict 嵌入等价 ---- */
	{
		ac_store *st3 = ac_store_open(data_dir, NULL);
		const ac_session *s3 = ac_store_get_session(st3, "s1");

		g_ac_checks++;
		if (!s3) {
			ac_fail("reload: session s1 missing");
		} else {
			aik_json *asdict = ac_session_asdict(s3);
			char *sp = path_join2(data_dir, "sessions-state.json");
			size_t sl = 0;
			char *stext = ac_slurp(sp, &sl);
			char *pretty = ac_json_dump_indent(asdict, 2);

			/* 嵌入 sessions-state.json 的形态 = dump_indent 再整体 +4 空格
			 *（sessions→s1 两层各 2 空格）*/
			char *embedded = NULL;

			if (pretty) {
				size_t plen = strlen(pretty);
				size_t extra = 0;

				for (size_t k = 0; k < plen; k++)
					if (pretty[k] == '\n')
						extra++;
				embedded = malloc(plen + extra * 4 + 1);
				if (embedded) {
					size_t w = 0;

					for (size_t k = 0; k < plen; k++) {
						if (pretty[k] == '\n') {
							embedded[w++] = '\n';
							embedded[w++] = ' ';
							embedded[w++] = ' ';
							embedded[w++] = ' ';
							embedded[w++] = ' ';
						} else {
							embedded[w++] = pretty[k];
						}
					}
					embedded[w] = '\0';
				}
			}
			g_ac_checks++;
			if (!stext || !embedded || !strstr(stext, embedded))
				ac_fail("reload: asdict not embedded verbatim in sessions-state.json");
			g_ac_checks++;
			if (s3->turns_since_condense != 0)
				ac_fail("reload: turns_since_condense=%lld",
					s3->turns_since_condense);
			free(embedded);
			free(pretty);
			free(stext);
			free(sp);
			aik_json_free(asdict);
		}
		ac_store_close(st3);
	}

	aik_json_free(vec);
	free(path1);
	free(path2);
	free(data_dir);
	ac_summary("test_acstate");
	return g_ac_failed ? 1 : 0;
}
