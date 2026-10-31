// SPDX-License-Identifier: GPL-2.0
/*
 * test_bpf.c - W80 用户态 BPF loader + nfqueue（bpf 通道）回归
 *
 * 默认（非 root，零副作用）：
 *   - 注册表接线：210 件、bpf 通道 4 件、risk R/W2/W1/W2、sub=netsec、
 *     channel 字符串 bpf 映射、参数边界（unload.id / nfqueue queue/
 *     timeout_ms/max_packets）；
 *   - 系统探测：unprivileged_bpf_disabled / BTF / CONFIG_* 真读且取值合法；
 *   - 最小 BTF 解析：合成 BTF 上找 FUNC bpf_lsm_file_open 与
 *     struct file.f_path 偏移，错误输入必须失败（不猜）；
 *   - 手写指令：minimal 2 条；deny_path 含 bpf_d_path 调用、-EPERM 返回、
 *     所有 LDX 的 imm=0（W80 实机踩过的 "BPF_LDX uses reserved fields"
 *     回归）；非法 prefix 必须拒绝；
 *   - 参数校验：load 缺参/未知 sample/文件不存在、unload 未知 id、
 *     nfqueue 越界与非法枚举，全部明确报错且不产生副作用；
 *   - 非 root 的 list/unload/nfqueue 必须给出诚实错误（EPERM / 未编），
 *     绝无 "总是成功" 的桩。
 *
 * --live（root）：真 bpf() 链路：list → load minimal → list(mine=yes) →
 *   unload → list(消失)；再试 attach（tracepoint perf link）；deny_path
 *   在 #60（CONFIG_BPF_LSM=n）应失败、在 L1（6.8，BPF_LSM=y 但活动 LSM
 *   不含 bpf）可加载但明确告警不生效；nfqueue 绑定失败/成功均如实输出。
 *   全部结束后 list 必须无 mine=yes（零残留）。
 *
 * --nfqueue-e2e（root，手动目标）：临时 nft 表（inet aik_w80，输出链，
 *   仅 UDP dport 47123 → queue 47）引流，子进程发包，父进程 nfqueue_pump
 *   收包并按 drop 回 verdict；结束后删除 nft 表。只用于 L1 证据。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "tools/bpf_tools.h"

static int fails;
static int checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (cond) { \
		printf("ok %s\n", msg); \
	} else { \
		printf("FAIL %s\n", msg); \
		fails++; \
	} \
} while (0)

static int call(const char *tool, const char *args, char **out)
{
	struct ai_tool t;
	int rc;

	memset(&t, 0, sizeof(t));
	t.name = (char *)tool;
	t.channel = TOOL_CH_BPF;
	*out = NULL;
	rc = exec_bpf_channel(&t, args, out);
	return rc;
}

static long extract_prog_id(const char *s)
{
	const char *p;

	if (!s)
		return -1;
	p = strstr(s, "prog_id=");
	if (!p)
		return -1;
	return strtol(p + 8, NULL, 10);
}

/* ------------------------------------------------------------------ */
/* 合成 BTF（最小、独立于 /sys/kernel/btf/vmlinux）                     */
/* ------------------------------------------------------------------ */

struct bt_hdr {
	unsigned short magic;
	unsigned char version;
	unsigned char flags;
	unsigned int hdr_len;
	unsigned int type_off;
	unsigned int type_len;
	unsigned int str_off;
	unsigned int str_len;
};

struct bt_type {
	unsigned int name_off;
	unsigned int info;
	unsigned int size_type;
};

struct bt_member {
	unsigned int name_off;
	unsigned int type;
	unsigned int offset;
};

#define BT_OFF_INT	1
#define BT_OFF_FILE	5
#define BT_OFF_FPATH	10
#define BT_OFF_FUNC	17

static unsigned char *make_btf(size_t *len_out)
{
	const char strs[] = "\0int\0file\0f_path\0bpf_lsm_file_open\0";
	size_t slen = sizeof(strs);
	size_t types_len;
	unsigned char *buf;
	unsigned char *p;
	struct bt_hdr *h;
	struct bt_type t;
	struct bt_member m;
	unsigned int int_size = 32;

	types_len = (12 + 4) + (12 + 12) + 12 + 12;
	*len_out = sizeof(struct bt_hdr) + types_len + slen;
	buf = calloc(1, *len_out);
	if (!buf)
		return NULL;
	h = (struct bt_hdr *)buf;
	h->magic = 0xeb9f;
	h->version = 1;
	h->hdr_len = sizeof(struct bt_hdr);
	h->type_off = 0;
	h->type_len = (unsigned int)types_len;
	h->str_off = (unsigned int)types_len;
	h->str_len = (unsigned int)slen;
	p = buf + sizeof(struct bt_hdr);

	/* id 1: INT "int" */
	t.name_off = BT_OFF_INT;
	t.info = (1u << 24) | 0;	/* BTF_KIND_INT */
	t.size_type = 32;
	memcpy(p, &t, 12);
	p += 12;
	memcpy(p, &int_size, 4);
	p += 4;

	/* id 2: STRUCT "file" { f_path @152*8 bits } */
	t.name_off = BT_OFF_FILE;
	t.info = (4u << 24) | 1;	/* BTF_KIND_STRUCT, vlen=1 */
	t.size_type = 64;
	memcpy(p, &t, 12);
	p += 12;
	m.name_off = BT_OFF_FPATH;	m.type = 1;
	m.offset = 152 * 8;
	memcpy(p, &m, 12);
	p += 12;

	/* id 3: FUNC_PROTO（无参数，返回 int） */
	t.name_off = 0;
	t.info = (13u << 24) | 0;	/* BTF_KIND_FUNC_PROTO */
	t.size_type = 1;
	memcpy(p, &t, 12);
	p += 12;

	/* id 4: FUNC "bpf_lsm_file_open" -> proto 3 */
	t.name_off = BT_OFF_FUNC;
	t.info = (12u << 24) | 0;	/* BTF_KIND_FUNC */
	t.size_type = 3;
	memcpy(p, &t, 12);
	p += 12;

	memcpy(p, strs, slen);
	return buf;
}

static void test_btf(void)
{
	unsigned char *btf;
	size_t len = 0;
	unsigned int id = 0, off = 0;
	unsigned char bad[32];

	btf = make_btf(&len);
	CHECK(btf != NULL, "合成 BTF 构造");
	if (!btf)
		return;
	CHECK(ai_bpf_btf_find_func(btf, len, "bpf_lsm_file_open", &id) == 0 &&
	      id == 4, "BTF 找到 FUNC bpf_lsm_file_open（id=4）");
	CHECK(ai_bpf_btf_member_offset(btf, len, "file", "f_path", &off) == 0 &&
	      off == 152, "BTF struct file.f_path 偏移=152");
	CHECK(ai_bpf_btf_find_func(btf, len, "no_such_func", &id) == -1,
	      "BTF 未知 FUNC 必须失败");
	CHECK(ai_bpf_btf_member_offset(btf, len, "file", "nope", &off) == -1,
	      "BTF 未知成员必须失败");
	CHECK(ai_bpf_btf_member_offset(btf, len, "nope", "f_path", &off) == -1,
	      "BTF 未知 struct 必须失败");
	memset(bad, 0, sizeof(bad));
	CHECK(ai_bpf_btf_find_func(bad, sizeof(bad), "bpf_lsm_file_open",
				   &id) == -1, "坏 magic 必须失败");
	free(btf);
}

/* ------------------------------------------------------------------ */
/* 指令构造                                                            */
/* ------------------------------------------------------------------ */

static void test_insns(void)
{
	struct bpf_insn *v;
	int cnt = 0, i;
	int has_call = 0, has_eprem = 0, ldx_bad = 0, jmp_bad = 0;

	v = ai_bpf_build_minimal(&cnt);
	CHECK(v && cnt == 2, "minimal 指令 2 条");
	if (v) {
		CHECK(v[0].code == 0xb7 && v[1].code == 0x95,
		      "minimal = mov r0,0; exit");
		free(v);
	}

	cnt = 0;
	v = ai_bpf_build_deny_path("/tmp/aikbpf", 152, &cnt);
	CHECK(v != NULL && cnt > 10, "deny_path 指令构造（>10 条）");
	if (!v)
		return;
	for (i = 0; i < cnt; i++) {
		if (v[i].code == 0x85 && v[i].imm == BPF_FUNC_d_path)
			has_call = 1;
		if (v[i].code == 0xb7 && v[i].dst_reg == BPF_REG_0 &&
		    v[i].imm == -EPERM)
			has_eprem = 1;
		if ((v[i].code & 0x07) == 0x01 && v[i].imm != 0)
			ldx_bad = 1;	/* BPF_LDX 的 imm 必须 0 */
		if ((v[i].code & 0x07) == 0x05 && v[i].off != 0) {
			int target = i + 1 + v[i].off;

			if (target < 0 || target >= cnt)
				jmp_bad = 1;
		}
	}
	CHECK(has_call, "deny_path 调用 bpf_d_path（helper 147）");
	CHECK(has_eprem, "deny_path 命中返回 -EPERM");
	CHECK(!ldx_bad, "所有 LDX 的 imm=0（regression: reserved fields）");
	CHECK(!jmp_bad, "所有跳转目标在指令数组内");
	CHECK(ai_bpf_build_deny_path("", 152, &cnt) == NULL,
	      "空 prefix 拒绝");
	{
		char big[40];

		memset(big, 'a', sizeof(big) - 1);
		big[sizeof(big) - 1] = '\0';
		CHECK(ai_bpf_build_deny_path(big, 152, &cnt) == NULL,
		      ">32 字节 prefix 拒绝");
	}
	free(v);
}

/* ------------------------------------------------------------------ */
/* 探测 + 参数校验（非 root 也安全）                                   */
/* ------------------------------------------------------------------ */

static void test_probe(void)
{
	struct ai_bpf_probe p;

	ai_bpf_probe_system(&p);
	CHECK(p.unpriv_bpf_disabled >= -1 && p.unpriv_bpf_disabled <= 2,
	      "unprivileged_bpf_disabled 取值合法");
	CHECK(p.cfg_bpf_lsm >= -1 && p.cfg_bpf_lsm <= 2,
	      "CONFIG_BPF_LSM 探测取值合法");
	CHECK(p.cfg_nfqueue >= -1 && p.cfg_nfqueue <= 2,
	      "CONFIG_NETFILTER_NETLINK_QUEUE 探测取值合法");
	CHECK(strcmp(ai_bpf_errno_name(EPERM), "EPERM") == 0,
	      "errno 名称表 EPERM");
}

static void test_params(void)
{
	char *out = NULL;
	int rc;

	rc = call("bpf_prog_load", "{}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "USAGE"),
	      "load 缺 sample/file → E_PARAM + USAGE");
	free(out);

	out = NULL;
	rc = call("bpf_prog_load", "{\"sample\":\"bogus\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "ERROR[E_PARAM"),
	      "load 未知 sample → E_PARAM");
	free(out);

	out = NULL;
	rc = call("bpf_prog_load",
		  "{\"file\":\"relative.bpf\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "绝对路径"),
	      "load 相对路径文件拒绝");
	free(out);

	out = NULL;
	rc = call("bpf_prog_load",
		  "{\"file\":\"/nonexistent/w80.bpf\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "打不开文件"),
	      "load 不存在文件明确报错");
	free(out);

	out = NULL;
	rc = call("bpf_prog_load",
		  "{\"sample\":\"deny_path\",\"prefix\":"
		  "\"0123456789012345678901234567890123\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "E_PARAM"),
	      "deny_path >32 字节 prefix 拒绝");
	free(out);

	out = NULL;
	rc = call("bpf_prog_unload", "{}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "USAGE"),
	      "unload 缺 id → E_PARAM");
	free(out);

	out = NULL;
	rc = call("bpf_prog_unload", "{\"id\":0}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG, "unload id=0 拒绝");
	free(out);

	out = NULL;
	rc = call("bpf_prog_unload", "{\"id\":999999}", &out);
	CHECK(rc == AI_ERR_NOT_FOUND && out &&
	      strstr(out, "不是本进程加载"), "unload 他方/未知 id 拒绝");
	free(out);

	out = NULL;
	rc = call("nfqueue_pump", "{\"queue\":70000}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "queue"),
	      "nfqueue queue 越界拒绝");
	free(out);

	out = NULL;
	rc = call("nfqueue_pump", "{\"timeout_ms\":50}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "timeout_ms"),
	      "nfqueue timeout 越界拒绝");
	free(out);

	out = NULL;
	rc = call("nfqueue_pump", "{\"max_packets\":0}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "max_packets"),
	      "nfqueue max_packets 越界拒绝");
	free(out);

	out = NULL;
	rc = call("nfqueue_pump", "{\"policy\":\"bogus\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "policy"),
	      "nfqueue policy 非法拒绝");
	free(out);

	out = NULL;
	rc = call("nfqueue_pump", "{\"family\":\"bogus\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "family"),
	      "nfqueue family 非法拒绝");
	free(out);
}

/* ------------------------------------------------------------------ */
/* 注册表接线                                                          */
/* ------------------------------------------------------------------ */

static void test_registry(void)
{
	struct tool_registry reg;
	char *err = NULL;
	int i, n = 0, ok = 1;
	static const char *const want[] = {
		"bpf_prog_load", "bpf_prog_list", "bpf_prog_unload",
		"nfqueue_pump",
	};
	static const char *const wrisk[] = { "W2", "R", "W1", "W2" };

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "tools.json 加载（197 件口径）");
	CHECK(reg.tool_count == 210, "注册表总数 210");
	CHECK(tool_channel_from_str("bpf") == TOOL_CH_BPF,
	      "channel 字符串 bpf 映射到 TOOL_CH_BPF");
	for (i = 0; i < reg.tool_count; i++)
		if (reg.tools[i].channel == TOOL_CH_BPF)
			n++;
	CHECK(n == 4, "bpf 通道恰 4 件");
	for (i = 0; i < 4; i++) {
		const struct ai_tool *t = tool_registry_find(&reg, want[i]);

		if (!t || t->channel != TOOL_CH_BPF || !t->risk ||
		    strcmp(t->risk, wrisk[i]) != 0 || t->sub_count < 1 ||
		    strcmp(t->sub[0], "netsec") != 0)
			ok = 0;
	}
	CHECK(ok, "四件工具 channel/risk W2,R,W1,W2/sub=netsec 齐全");
	{
		const struct ai_tool *t =
			tool_registry_find(&reg, "bpf_prog_unload");
		int j, hit = 0;

		for (j = 0; t && j < t->param_count; j++)
			if (strcmp(t->params[j].name, "id") == 0 &&
			    t->params[j].required && t->params[j].min == 1)
				hit = 1;
		CHECK(hit, "unload.id 必填且 minimum=1");
	}
	{
		const struct ai_tool *t =
			tool_registry_find(&reg, "nfqueue_pump");
		int j, hit = 0;

		for (j = 0; t && j < t->param_count; j++)
			if (strcmp(t->params[j].name, "timeout_ms") == 0 &&
			    t->params[j].max == 60000)
				hit = 1;
		CHECK(hit, "nfqueue timeout_ms maximum=60000（硬上限）");
	}
	{
		const struct ai_tool *t =
			tool_registry_find(&reg, "bpf_prog_list");
		CHECK(t && t->param_count == 0, "list 无参数（R）");
	}
	tool_registry_free(&reg);
	free(err);
}

/* ------------------------------------------------------------------ */
/* 非 root 的诚实失败                                                  */
/* ------------------------------------------------------------------ */

static void test_honest_failures(void)
{
	char *out = NULL;
	int rc;

	out = NULL;
	rc = call("bpf_prog_list", "{}", &out);
	CHECK(out != NULL && strstr(out, "内核探测") != NULL,
	      "list 总是带能力探测行");
	if (geteuid() != 0) {
		CHECK(rc == AI_ERR_API && out &&
		      (strstr(out, "EPERM") || strstr(out, "权限")),
		      "非 root list 如实 EPERM（不伪造列表）");
	} else {
		CHECK(rc == AI_OK && out &&
		      (strstr(out, "prog_id=") || strstr(out, "列表为空")),
		      "root list 返回真实清单或空列表");
	}
	free(out);

	out = NULL;
	rc = call("bpf_prog_load",
		  "{\"sample\":\"minimal\",\"attach\":false}", &out);
	if (geteuid() != 0) {
		CHECK(rc != AI_OK && out &&
		      (strstr(out, "EPERM") || strstr(out, "权限")),
		      "非 root load 如实权限失败");
	} else {
		long id = extract_prog_id(out);

		CHECK(rc == AI_OK && id > 0 &&
		      strstr(out, "type=TRACEPOINT"),
		      "root load minimal 真实成功并给出 prog_id");
		if (id > 0) {
			char args[64];
			char *uout = NULL;

			snprintf(args, sizeof(args), "{\"id\":%ld}", id);
			CHECK(call("bpf_prog_unload", args, &uout) == AI_OK &&
			      uout && strstr(uout, "已卸载"),
			      "root unload 复验 ENOENT 成功");
			free(uout);
		}
	}
	free(out);

	out = NULL;
	rc = call("nfqueue_pump",
		  "{\"queue\":0,\"timeout_ms\":200,\"max_packets\":1}", &out);
	CHECK(out && strstr(out, "内核探测"),
	      "nfqueue 输出带能力探测");
	if (geteuid() != 0) {
		CHECK(rc != AI_OK && out &&
		      (strstr(out, "权限") || strstr(out, "nfqueue")),
		      "非 root nfqueue 如实失败");
	} else {
		CHECK((rc == AI_OK && strstr(out, "已绑定")) ||
		      (rc != AI_OK &&
		       (strstr(out, "未编 nfqueue") || strstr(out, "失败"))),
		      "root nfqueue 绑定成功或明确不支持（无假成功）");
	}
	free(out);
}

/* ------------------------------------------------------------------ */
/* --live / --nfqueue-e2e                                              */
/* ------------------------------------------------------------------ */

static int live_list(const char *title)
{
	char *out = NULL;
	int rc = call("bpf_prog_list", "{}", &out);

	printf("\n== live: %s ==\nrc=%d\n%s\n", title, rc, out ? out : "(null)");
	free(out);
	return rc;
}

static int live_unload(long id)
{
	char args[64];
	char *out = NULL;
	int rc;

	snprintf(args, sizeof(args), "{\"id\":%ld}", id);
	rc = call("bpf_prog_unload", args, &out);
	printf("\n== live: unload id=%ld ==\nrc=%d\n%s\n", id, rc,
	       out ? out : "(null)");
	free(out);
	return rc;
}

/* 走完整执行器（注册表 → 租约闸门 → TOOL_CH_BPF）。bpf_prog_list 是
 * D0/R，非 TTY 也放行；用于证明"注册表里的工具能被执行器路由"。 */
static void live_executor_list(void)
{
	struct tool_registry reg;
	const struct ai_tool *t;
	char *err = NULL;
	char *out = NULL;
	int ok = 0, rc;

	setenv("AIKERNEL_TOOLS_JSON",
	       access("../tools/tools.json", R_OK) == 0 ?
	       "../tools/tools.json" : "tools/tools.json", 1);
	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		printf("\n== live: executor bpf_prog_list ==\nLOAD FAIL: %s\n",
		       err ? err : "?");
		free(err);
		return;
	}
	t = tool_registry_find(&reg, "bpf_prog_list");
	rc = t ? tool_executor_run(t, "{}", &out, &ok) : AI_ERR_NOT_FOUND;
	printf("\n== live: executor bpf_prog_list（注册表路径）==\n"
	       "rc=%d ok=%d\n%s\n", rc, ok, out ? out : "(null)");
	free(out);
	tool_registry_free(&reg);
	free(err);
}

static int live(void)
{
	char *out = NULL;
	int rc, step_fail = 0;
	long id;

	if (geteuid() != 0) {
		printf("SKIP: --live 需要 root（sudo ./test_bpf --live）\n");
		return 0;
	}
	printf("== test_bpf --live（W80 BPF loader，uid=%u）==\n", geteuid());

	live_list("初始 list（真 bpf() 枚举）");
	live_executor_list();

	out = NULL;
	rc = call("bpf_prog_load",
		  "{\"sample\":\"minimal\",\"attach\":false}", &out);
	printf("\n== live: load minimal attach=false ==\nrc=%d\n%s\n", rc,
	       out ? out : "(null)");
	id = extract_prog_id(out);
	if (rc == AI_OK && id > 0) {
		live_list("加载后 list（应出现 mine=yes）");
		if (live_unload(id) != AI_OK)
			step_fail++;
		live_list("卸载后 list（id 应消失）");
	} else {
		printf("FAIL: minimal 加载应成功（BPF_SYSCALL=y）\n");
		step_fail++;
	}
	free(out);

	/* attach 链路（perf_event + BPF_LINK_CREATE）；无 tracefs 时 SKIP */
	out = NULL;
	rc = call("bpf_prog_load",
		  "{\"sample\":\"minimal\",\"attach\":true}", &out);
	printf("\n== live: load minimal attach=true ==\nrc=%d\n%s\n", rc,
	       out ? out : "(null)");
	id = extract_prog_id(out);
	if (rc == AI_OK && id > 0) {
		live_unload(id);
	} else {
		printf("NOTE: attach 链路不可用（tracefs/权限/内核），"
		       "加载失败已自动卸载\n");
	}
	free(out);

	/* LSM deny_path：#60 预期失败；L1 可加载但必须告警不生效 */
	out = NULL;
	rc = call("bpf_prog_load", "{\"sample\":\"deny_path\"}", &out);
	printf("\n== live: load deny_path（LSM）==\nrc=%d\n%s\n", rc,
	       out ? out : "(null)");
	id = extract_prog_id(out);
	if (rc == AI_OK) {
		if (out && !strstr(out, "不生效")) {
			printf("FAIL: 活动 LSM 不含 bpf 时必须明确告警不生效\n");
			step_fail++;
		}
		live_unload(id);
	} else if (!out || !strstr(out, "ERROR")) {
		printf("FAIL: LSM 加载失败必须给出 ERROR 原因\n");
		step_fail++;
	}
	free(out);

	/* nfqueue：#60 预期失败；L1 可绑定但 500ms 内无包 */
	out = NULL;
	rc = call("nfqueue_pump",
		  "{\"queue\":0,\"timeout_ms\":500,\"max_packets\":1}", &out);
	printf("\n== live: nfqueue_pump ==\nrc=%d\n%s\n", rc,
	       out ? out : "(null)");
	if (rc != AI_OK && (!out ||
	    !(strstr(out, "未编 nfqueue") || strstr(out, "权限") ||
	      strstr(out, "失败")))) {
		printf("FAIL: nfqueue 失败必须说明原因\n");
		step_fail++;
	}
	if (rc == AI_OK && (!out || !strstr(out, "未收到"))) {
		printf("NOTE: nfqueue 收到包（出现了引流规则）\n");
	}
	free(out);

	live_list("最终 list（必须无 mine=yes）");
	out = NULL;
	rc = call("bpf_prog_list", "{}", &out);
	if (out && strstr(out, "mine=yes fd=")) {
		printf("FAIL: 仍有 mine=yes 的程序（残留）\n");
		step_fail++;
	}
	free(out);

	printf("\n== live 结果：%s ==\n",
	       step_fail ? "有 FAIL（见上）" : "ALL OK");
	return step_fail ? 1 : 0;
}

static int run_cmd(const char *fmt, ...)
{
	char cmd[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);
	return system(cmd);
}

static int nfqueue_e2e(void)
{
	const char *nft = access("/usr/sbin/nft", X_OK) == 0 ?
			  "/usr/sbin/nft" : "nft";
	char *out = NULL;
	int rc, status = 0;
	pid_t pid;

	if (geteuid() != 0) {
		printf("SKIP: --nfqueue-e2e 需要 root\n");
		return 0;
	}
	run_cmd("%s delete table inet aik_w80 2>/dev/null", nft);
	if (run_cmd("%s add table inet aik_w80", nft) != 0 ||
	    run_cmd("%s 'add chain inet aik_w80 out { type filter hook "
		    "output priority 0; policy accept; }'", nft) != 0 ||
	    run_cmd("%s add rule inet aik_w80 out udp dport 47123 "
		    "queue num 47", nft) != 0) {
		printf("SKIP: nft 规则安装失败（缺 nft_queue 或权限）\n");
		run_cmd("%s delete table inet aik_w80 2>/dev/null", nft);
		return 0;
	}
	printf("== nfqueue-e2e: nft 表 inet aik_w80 已装（UDP 47123 → queue 47）==\n");

	pid = fork();
	if (pid == 0) {
		struct sockaddr_in a;
		int s;

		usleep(400000);	/* 等父进程完成绑定 */
		s = socket(AF_INET, SOCK_DGRAM, 0);
		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_port = htons(47123);
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (s >= 0) {
			(void)sendto(s, "AIKW80", 6, 0, (struct sockaddr *)&a,
				     sizeof(a));
			close(s);
		}
		_exit(0);
	}
	rc = call("nfqueue_pump",
		  "{\"queue\":47,\"timeout_ms\":4000,\"max_packets\":2,"
		  "\"policy\":\"drop\"}", &out);
	if (pid > 0)
		(void)waitpid(pid, &status, 0);
	run_cmd("%s delete table inet aik_w80 2>/dev/null", nft);
	printf("\n== nfqueue-e2e: pump ==\nrc=%d\n%s\n", rc,
	       out ? out : "(null)");
	if (rc != AI_OK || !out || !strstr(out, "pkt#1")) {
		printf("FAIL: 未收到引流包（nfqueue 收包链路未生效）\n");
		free(out);
		return 1;
	}
	if (!strstr(out, "UDP 127.0.0.1:") || !strstr(out, "DROP")) {
		printf("FAIL: 五元组/verdict 不符合预期\n");
		free(out);
		return 1;
	}
	printf("== nfqueue-e2e 结果：ALL OK（真收包 + 五元组 + DROP verdict）==\n");
	free(out);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--live") == 0)
		return live();
	if (argc > 1 && strcmp(argv[1], "--nfqueue-e2e") == 0)
		return nfqueue_e2e();

	printf("==== test_bpf: W80 BPF loader + nfqueue ====\n");
	test_registry();
	test_probe();
	test_btf();
	test_insns();
	test_params();
	test_honest_failures();
	printf("\nRESULT: %s (%d checks, %d failed)\n",
	       fails ? "FAIL" : "PASS", checks, fails);
	return fails ? 1 : 0;
}
