/* SPDX-License-Identifier: GPL-2.0 */
/*
 * review.c - occ 验收环（ORCH-DESIGN §8 棒 E4；§4 验收环【拍板 2】）
 *
 * verdict 判据表（规则 → 机检实现；§4 原文出处标注）：
 *
 *  规则          §4 原文                                        机检实现
 *  ------------ ---------------------------------------------- ------------------------------
 *  R-EXIT       「（可机械判：）退出码」                         occ_task_event 最后 result
 *               （§8 E4 实现要点：退出码）                      行 JSON：end=="exit" 且
 *                                                             exit_code==0；无事件/崩溃
 *                                                             （signal）/非零退出=hit
 *  R-REPORT     「子智能体交付 verdict（固定表头）」             结果文件（E3
 *               §4 第一句                                       OCC_TASK_RESULT_FILE 通道）
 *                                                             在场且非空；缺文件=hit
 *  R-HEADER     「固定表头（标准条目→结果→证据路径→自评）」      报告含 "# VERDICT" 标记行 +
 *                                                             表头行（首列含 criterion）
 *                                                             ；缺任一=hit
 *  R-NOSELF     「不接受自报数字（W153+T9e 计数错数链教训        表头后零数据行=hit——纯
 *               产品化）」+ 任务书「禁止以报告自称完成为         叙述「已完成/达标」永不
 *               pass 依据（防转述验收）」                        构成 pass 依据；自评列
 *                                                             （self）判卷永不读
 *  R-COVERAGE   「逐行状态」（标准条目↔行对齐）                  brief.acceptance 每条在
 *                                                             VERDICT 表有 criterion
 *                                                             精确对应行；缺行=hit
 *  R-ROWPASS    「全过才进主会话复核位」                         表内行行 result 列
 *                                                             ==pass（大小写不敏感）；
 *                                                             任一非 pass=hit
 *  R-EVIDENCE   「文件存在」+「证据路径」                        evidence 列必须机检令牌
 *               （§8 E4 实现要点：自检命令输出/断言行）          （exit:/file:/md5:/contains:/
 *                                                             绝对路径）且目标文件真实
 *                                                             在场（stat）；自由文本
 *                                                             证据/缺文件=hit
 *  R-MD5        「md5sum 对照」                                  md5:<path>=<32hex> 令牌
 *                                                             现算文件 md5（RFC 1321，
 *                                                             本文件内建）对照；不符=hit
 *  R-CONTAINS   §8 E4 实现要点「结果文件里的自检命令输出/        contains:<path>:<子串> 令牌
 *               断言行」                                          ——子串真实在文件内容中
 *
 * 升级三路（§4「rework 计数与升级三路（换智能体/拆任务/上抛用户）」）：
 * 状态迁移/计数全部在 E1 occ_task_verdict（in_review→done/rework/
 * escalated）；本层=机械判 → 调对路 → 渲染 §3 整改词/升级词 → 回写
 * 任务事件（kind='return' 审计）。裁判（主会话）表态仅在机械判通过后
 * 生效——机械判 fail 时 judge_pass 强制无效（防转述验收：主会话也不许
 * 转述子报告自称完成放行，§1「验收=看报告+抽查关键证据亲跑」）。
 *
 * 依赖面：只读消费 E1 task API + aik_json；零子进程、零全局静态态。
 * 挂点接线：orch.c collect（终局机械预判 occ_review_prenote + 可选独立
 * 评审智能体回调）与 occ_tools/tools.c task return（验收环驱动）。
 */
#define _POSIX_C_SOURCE 200809L
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#include "review.h"

#include "store/store_json.h"

/* ============ MD5（RFC 1321；R-MD5「md5sum 对照」底座，零第三方） ============ */

static const uint32_t MD5_K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
static const int MD5_R[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

struct md5_ctx {
	uint32_t st[4];
	uint64_t nbits;
	unsigned char in[64];
	size_t inlen;
};

static uint32_t md5_rotl(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}

static void md5_transform(uint32_t *st, const unsigned char *chunk)
{
	uint32_t w[16];
	uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
	uint32_t f, tmp;
	int i, g;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)chunk[i * 4] |
		       ((uint32_t)chunk[i * 4 + 1] << 8) |
		       ((uint32_t)chunk[i * 4 + 2] << 16) |
		       ((uint32_t)chunk[i * 4 + 3] << 24);
	for (i = 0; i < 64; i++) {
		if (i < 16) {
			f = (b & c) | (~b & d);
			g = i;
		} else if (i < 32) {
			f = (d & b) | (~d & c);
			g = (5 * i + 1) & 15;
		} else if (i < 48) {
			f = b ^ c ^ d;
			g = (3 * i + 5) & 15;
		} else {
			f = c ^ (b | ~d);
			g = (7 * i) & 15;
		}
		tmp = d;
		d = c;
		c = b;
		b = b + md5_rotl(a + f + MD5_K[i] + w[g], MD5_R[i]);
		a = tmp;
	}
	st[0] += a;
	st[1] += b;
	st[2] += c;
	st[3] += d;
}

static void md5_init(struct md5_ctx *m)
{
	m->st[0] = 0x67452301u;
	m->st[1] = 0xefcdab89u;
	m->st[2] = 0x98badcfeu;
	m->st[3] = 0x10325476u;
	m->nbits = 0;
	m->inlen = 0;
}

static void md5_update(struct md5_ctx *m, const unsigned char *p, size_t n)
{
	m->nbits += (uint64_t)n * 8u;
	while (n) {
		size_t take = 64 - m->inlen < n ? 64 - m->inlen : n;

		memcpy(m->in + m->inlen, p, take);
		m->inlen += take;
		p += take;
		n -= take;
		if (m->inlen == 64) {
			md5_transform(m->st, m->in);
			m->inlen = 0;
		}
	}
}

static void md5_final(struct md5_ctx *m, unsigned char out[16])
{
	uint64_t bits = m->nbits;	/* 真实消息长度（pad 前钉死） */
	unsigned char pad[72];
	unsigned char lenb[8];
	size_t need;
	int i;

	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;
	need = (m->inlen < 56) ? (56 - m->inlen) : (120 - m->inlen);
	md5_update(m, pad, need);	/* nbits 暂被污染——只用 bits */
	for (i = 0; i < 8; i++)
		lenb[i] = (unsigned char)((bits >> (8 * i)) & 0xff);
	md5_update(m, lenb, 8);		/* 尾块凑满 64 触发 transform */
	for (i = 0; i < 4; i++) {
		out[i] = (unsigned char)(m->st[0] >> (8 * i));
		out[4 + i] = (unsigned char)(m->st[1] >> (8 * i));
		out[8 + i] = (unsigned char)(m->st[2] >> (8 * i));
		out[12 + i] = (unsigned char)(m->st[3] >> (8 * i));
	}
}

int occ_review_md5_file(const char *path, char *hex, size_t hexlen)
{
	struct md5_ctx m;
	unsigned char digest[16], buf[4096];
	FILE *f;
	size_t got;
	static const char HEX[] = "0123456789abcdef";
	int i;

	if (!path || !path[0] || !hex || hexlen < 33)
		return -1;
	f = fopen(path, "rb");
	if (!f)
		return -1;
	md5_init(&m);
	while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
		md5_update(&m, buf, got);
	if (ferror(f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	md5_final(&m, digest);
	for (i = 0; i < 16; i++) {
		hex[i * 2] = HEX[digest[i] >> 4];
		hex[i * 2 + 1] = HEX[digest[i] & 0x0f];
	}
	hex[32] = '\0';
	return 0;
}

/* ============ 小工具：截断安全追加 / trim / 文件读 ============ */

/* 追加写（vsnprintf 截断安全）；返回新 offset（超 buflen 后自停） */
static size_t snp_cat(char *buf, size_t buflen, size_t off,
		      const char *fmt, ...)
{
	va_list ap;
	int w;

	if (!buf || !buflen || off >= buflen)
		return off;
	va_start(ap, fmt);
	w = vsnprintf(buf + off, buflen - off, fmt, ap);
	va_end(ap);
	if (w < 0)
		return off;
	return off + (size_t)w;
}

static void trim_span(const char **s, size_t *n)
{
	const char *p = *s;
	size_t len = *n;

	while (len && (p[0] == ' ' || p[0] == '\t' || p[0] == '\r'))
		p++, len--;
	while (len && (p[len - 1] == ' ' || p[len - 1] == '\t' ||
		       p[len - 1] == '\r'))
		len--;
	*s = p;
	*n = len;
}

static int span_contains_ci(const char *s, size_t n, const char *needle)
{
	size_t L = strlen(needle);

	if (!L || L > n)
		return 0;
	for (size_t i = 0; i + L <= n; i++)
		if (!strncasecmp(s + i, needle, L))
			return 1;
	return 0;
}

static char *read_file_cap(const char *path, size_t cap)
{
	FILE *f;
	long sz;
	size_t want, got;
	char *buf;

	if (!path || !path[0])
		return NULL;
	f = fopen(path, "rb");
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0) {
		fclose(f);
		return NULL;
	}
	want = (size_t)sz > cap ? cap : (size_t)sz;
	buf = malloc(want + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fseek(f, 0, SEEK_SET) != 0)
		got = 0;
	else
		got = fread(buf, 1, want, f);
	fclose(f);
	buf[got] = '\0';
	return buf;
}

/* ============ 机械判（§4 规则落码；判据表见本文件头注） ============ */

void occ_review_verdict_init(occ_review_verdict *v)
{
	if (!v)
		return;
	memset(v, 0, sizeof(*v));
	v->pass = 1;
}

static void hit(occ_review_verdict *v, const char *rule, const char *fmt, ...)
{
	va_list ap;

	if (!v || v->n_hit >= OCC_RV_MAX_HITS)
		return;
	snprintf(v->rule[v->n_hit], OCC_RV_RULE_MAX, "%s", rule);
	va_start(ap, fmt);
	vsnprintf(v->detail[v->n_hit], OCC_RV_DETAIL_MAX, fmt, ap);
	va_end(ap);
	v->n_hit++;
	v->pass = 0;
}

/* VERDICT 表数据行（表头后） */
struct rv_row {
	char crit[160];
	char res[24];
	char ev[320];
};

#define RV_MAX_ROWS	256
#define RV_MAX_ACC	64

/* R-EXIT（§4「退出码」）：result 事件 end=="exit" && exit_code==0 */
static void check_exit(const char *result_event_json, occ_review_verdict *v)
{
	aik_json *j;
	const aik_json *endv, *codev;
	char perr[96], end[24];
	int have_code = 0;
	long long code = 0;

	if (!result_event_json || !result_event_json[0]) {
		hit(v, OCC_RV_R_EXIT, "无终局 result 事件——退出码不可机检");
		return;
	}
	j = aik_json_parse(result_event_json, strlen(result_event_json),
			   perr, sizeof(perr));
	if (!j) {
		hit(v, OCC_RV_R_EXIT, "终局 result 事件不是合法 JSON");
		return;
	}
	endv = aik_json_get(j, "end");
	codev = aik_json_get(j, "exit_code");
	/* 先取值后释放（aik_json_str 指向 DOM 内部——free 后即悬垂） */
	{
		const char *s = aik_json_str(endv);

		snprintf(end, sizeof(end), "%s", s ? s : "");
	}
	if (codev && (aik_json_typeof(codev) == AIK_JSON_INT ||
		      aik_json_typeof(codev) == AIK_JSON_NUM)) {
		have_code = 1;
		code = aik_json_int(codev);
	}
	aik_json_free(j);
	if (!end[0] || strcmp(end, "exit") != 0)
		hit(v, OCC_RV_R_EXIT, "终局非正常退出（end=%s）——崩溃/取消"
		    "/超时的交付不采信", end[0] ? end : "(缺)");
	else if (!have_code)
		hit(v, OCC_RV_R_EXIT, "终局事件缺 exit_code——退出码不可机检");
	else if (code != 0)
		hit(v, OCC_RV_R_EXIT, "退出码 %lld≠0", code);
}

/* 证据路径归一（相对 → base_dir 下；越界路径原样交 stat 裁决） */
static void resolve_ev_path(const char *path, const char *base_dir,
			    char *out, size_t outlen)
{
	if (!path || !path[0]) {
		if (outlen)
			out[0] = '\0';
		return;
	}
	if (path[0] == '/' || !base_dir || !base_dir[0])
		snprintf(out, outlen, "%s", path);
	else
		snprintf(out, outlen, "%s/%s", base_dir, path);
}

static int file_exists(const char *path)
{
	struct stat st;

	return path && path[0] && stat(path, &st) == 0 ? 1 : 0;
}

/*
 * 单行证据机检（§4「文件存在」「md5sum 对照」；§8 E4 实现要点
 * 「自检命令输出/断言行」）。返回：0=过；1=R-EVIDENCE；2=R-MD5；
 * 3=R-CONTAINS。detail 回填人话（不截断责任在调用方缓冲）。
 */
static int check_evidence(const char *ev, const char *base_dir,
			  char *detail, size_t dlen)
{
	char path[512], hex[40], want[40];
	const char *p, *eq, *colon;
	struct stat st;

	if (!ev || !ev[0]) {
		snprintf(detail, dlen, "证据列为空");
		return 1;
	}
	if (!strncmp(ev, "exit:", 5)) {
		if (atoi(ev + 5) != 0) {
			snprintf(detail, dlen, "exit:%s 自证非零退出", ev + 5);
			return 1;
		}
		return 0;	/* 全局退出码另由 R-EXIT 把关 */
	}
	if (!strncmp(ev, "file:", 5)) {
		resolve_ev_path(ev + 5, base_dir, path, sizeof(path));
		if (!file_exists(path)) {
			snprintf(detail, dlen, "文件不存在：%.80s", path);
			return 1;
		}
		return 0;
	}
	if (!strncmp(ev, "md5:", 4)) {
		char tmp[512];

		p = ev + 4;
		eq = strchr(p, '=');
		if (!eq || eq == p || eq - p >= (int)sizeof(tmp)) {
			snprintf(detail, dlen, "md5 令牌格式应为 "
				 "md5:<path>=<32hex>");
			return 1;
		}
		memcpy(tmp, p, (size_t)(eq - p));
		tmp[eq - p] = '\0';
		snprintf(want, sizeof(want), "%s", eq + 1);
		if (strlen(want) != 32) {
			snprintf(detail, dlen, "md5 期望值非 32 位十六进制");
			return 2;
		}
		resolve_ev_path(tmp, base_dir, path, sizeof(path));
		if (stat(path, &st) != 0) {
			snprintf(detail, dlen, "md5 目标文件不存在：%.80s",
				 path);
			return 1;
		}
		if (occ_review_md5_file(path, hex, sizeof(hex)) != 0) {
			snprintf(detail, dlen, "md5 现算失败：%.80s", path);
			return 1;
		}
		if (strcasecmp(hex, want) != 0) {
			snprintf(detail, dlen, "md5 不符：%.48s 现算=%s"
				 " 声称=%.32s", path, hex, want);
			return 2;
		}
		return 0;
	}
	if (!strncmp(ev, "contains:", 9)) {
		char tmp[512];

		p = ev + 9;
		colon = strchr(p, ':');
		if (!colon || colon == p || colon - p >= (int)sizeof(tmp)) {
			snprintf(detail, dlen, "contains 令牌格式应为 "
				 "contains:<path>:<断言子串>");
			return 1;
		}
		memcpy(tmp, p, (size_t)(colon - p));
		tmp[colon - p] = '\0';
		resolve_ev_path(tmp, base_dir, path, sizeof(path));
		if (!file_exists(path)) {
			snprintf(detail, dlen, "断言目标文件不存在：%.80s",
				 path);
			return 1;
		}
		{
			char *body = read_file_cap(path, 1 << 20);

			if (!body) {
				snprintf(detail, dlen, "断言目标不可读："
					 "%.80s", path);
				return 1;
			}
			if (!strstr(body, colon + 1)) {
				snprintf(detail, dlen, "断言子串未命中："
					 "%.48s 中无「%.32s」", path,
					 colon + 1);
				free(body);
				return 3;
			}
			free(body);
		}
		return 0;
	}
	if (ev[0] == '/') {	/* 裸绝对路径=存在性证据 */
		if (!file_exists(ev)) {
			snprintf(detail, dlen, "文件不存在：%.80s", ev);
			return 1;
		}
		return 0;
	}
	snprintf(detail, dlen, "证据不可机检（须 exit:/file:/md5:/"
		 "contains:/绝对路径令牌）：%.60s", ev);
	return 1;
}

void occ_review_parse(const char *report, const char *result_event_json,
		      const char *base_dir,
		      const char *const *acceptance, size_t n_acc,
		      occ_review_verdict *out)
{
	struct rv_row rows[RV_MAX_ROWS];
	size_t n_rows = 0, i, k;
	int have_marker = 0, have_header = 0, header_seen = 0;
	char detail[OCC_RV_DETAIL_MAX];

	if (!out)
		return;
	occ_review_verdict_init(out);

	/* R-EXIT：终局退出码（§4） */
	check_exit(result_event_json, out);

	/* R-REPORT：交付在场（§4「子智能体交付」） */
	if (!report || !report[0])
		hit(out, OCC_RV_R_REPORT, "结果文件缺失或为空——无可判卷"
		    " 交付");

	/* 扫行：# VERDICT 标记 + 表头 + 数据行（判卷只看表格机检面；
	 * 叙述文本与自评列永不参与 pass 判定——R-NOSELF 防转述） */
	if (report && report[0]) {
		const char *p = report;

		while (*p) {
			const char *nl = strchr(p, '\n');
			size_t llen = nl ? (size_t)(nl - p) : strlen(p);
			const char *line = p;
			size_t ll = llen;

			trim_span(&line, &ll);
			if (!have_marker && ll >= 2 && line[0] == '#' &&
			    span_contains_ci(line, ll, "VERDICT"))
				have_marker = 1;
			if (line[0] == '|') {
				/* 拆 |a|b|c|d| 四列 */
				const char *cells[5];
				size_t lens[5];
				size_t ncell = 0;
				const char *q = line;
				size_t rem = ll;

				while (ncell < 5) {
					const char *pipe;

					if (rem == 0 || *q != '|')
						break;
					pipe = memchr(q + 1, '|', rem - 1);
					cells[ncell] = q + 1;
					lens[ncell] = pipe ? (size_t)(pipe - q - 1) : rem - 1;
					trim_span(&cells[ncell], &lens[ncell]);
					ncell++;
					if (!pipe)
						break;
					rem -= (size_t)(pipe - q) + 1;
					q = pipe;
				}
				if (!header_seen) {
					if (ncell >= 3 &&
					    span_contains_ci(cells[0],
							     lens[0],
							     "criterion")) {
						have_header = 1;
						header_seen = 1;
					}
					/* 表头前的 | 行忽略（前言噪音） */
				} else if (ncell >= 3 &&
					   n_rows < RV_MAX_ROWS) {
					snprintf(rows[n_rows].crit,
						 sizeof(rows[0].crit),
						 "%.*s", (int)lens[0],
						 cells[0]);
					snprintf(rows[n_rows].res,
						 sizeof(rows[0].res),
						 "%.*s", (int)lens[1],
						 cells[1]);
					snprintf(rows[n_rows].ev,
						 sizeof(rows[0].ev),
						 "%.*s", (int)lens[2],
						 cells[2]);
					n_rows++;
				}
			}
			p = nl ? nl + 1 : p + llen;
			if (!nl)
				break;
		}
	}

	/* R-HEADER：固定表头（§4「固定表头」） */
	if (!have_marker || !have_header)
		hit(out, OCC_RV_R_HEADER, "缺 # VERDICT 标记或固定表头行"
		    "（| criterion | result | evidence | self |）");

	/* R-NOSELF：零机检证据行恒拒（§4「不接受自报数字」） */
	if (have_header && have_marker && n_rows == 0)
		hit(out, OCC_RV_R_NOSELF, "VERDICT 表零数据行——仅自称完成"
		    "（叙述/自评）不构成 pass 依据");

	/* R-COVERAGE：验收标准逐条有行（§4「逐行状态」） */
	if (acceptance) {
		size_t na = n_acc > RV_MAX_ACC ? RV_MAX_ACC : n_acc;

		for (i = 0; i < na; i++) {
			const char *e = acceptance[i];
			int found = 0;

			if (!e)
				continue;
			for (k = 0; k < n_rows && !found; k++)
				found = !strcmp(rows[k].crit, e);
			if (!found)
				hit(out, OCC_RV_R_COVERAGE, "验收标准[%zu]"
				    "「%.100s」无对应 VERDICT 行", i, e);
		}
	}

	/* R-ROWPASS + R-EVIDENCE/R-MD5/R-CONTAINS：逐行判（§4「全过才
	 * 进主会话复核位」「文件存在」「md5sum 对照」） */
	for (k = 0; k < n_rows; k++) {
		if (strcasecmp(rows[k].res, "pass") != 0) {
			hit(out, OCC_RV_R_ROWPASS, "行「%.100s」自报 "
			    "result=%s（非 pass）", rows[k].crit,
			    rows[k].res[0] ? rows[k].res : "(空)");
			continue;	/* 自报 fail 的行无需再核证据 */
		}
		{
			int rc = check_evidence(rows[k].ev, base_dir, detail,
						sizeof(detail));

			if (rc == 1)
				hit(out, OCC_RV_R_EVIDENCE, "行「%.100s」："
				    "%s", rows[k].crit, detail);
			else if (rc == 2)
				hit(out, OCC_RV_R_MD5, "行「%.100s」：%s",
				    rows[k].crit, detail);
			else if (rc == 3)
				hit(out, OCC_RV_R_CONTAINS, "行「%.100s」："
				    "%s", rows[k].crit, detail);
		}
	}
}

/* ============ 整改词/升级词渲染（§3 模板六要素） ============ */

static size_t render_std_block(const occ_review_verdict *v,
			       int judge_rejected, const char *judge_note,
			       char *buf, size_t buflen, int attempt, int max,
			       int escalate)
{
	size_t n = 0, i;
	char rules[512];
	size_t ro = 0;
	char gaps[1024];
	size_t go = 0;

	rules[0] = '\0';
	gaps[0] = '\0';
	for (i = 0; i < (size_t)v->n_hit && i < 8; i++)
		ro = snp_cat(rules, sizeof(rules), ro, "%s%s", i ? "、" : "",
			     v->rule[i]);
	for (i = 0; i < (size_t)v->n_hit && i < 6; i++)
		go = snp_cat(gaps, sizeof(gaps), go, "%zu. %s\n", i + 1,
			     v->detail[i]);

	if (escalate)
		n = snp_cat(buf, buflen, n, "【验收超限上抛（回炉 %d/%d 次"
			    "已用尽）】\n", attempt, max);
	else
		n = snp_cat(buf, buflen, n, "【验收不通过 第 %d/%d 次】\n",
			    attempt, max);
	if (judge_rejected) {
		n = snp_cat(buf, buflen, n, "未达标准：机械判全过；裁判抽查"
			    "否决（§4 抽查亲跑强制）\n");
		n = snp_cat(buf, buflen, n, "差距：%.400s\n",
			    judge_note && judge_note[0] ? judge_note :
			    "（裁判未给表态原文）");
		n = snp_cat(buf, buflen, n, "证据：机械判规则未命中失败；"
			    "裁判亲跑证据不采信——见表态原文\n");
		n = snp_cat(buf, buflen, n, "整改要求：按裁判表态逐项整改后"
			    "重新交付（# VERDICT 表与机检令牌保持齐全）\n");
	} else {
		n = snp_cat(buf, buflen, n, "未达标准：机械判未过——命中规"
			    "则：%s\n", rules[0] ? rules : "(无)");
		n = snp_cat(buf, buflen, n, "差距：\n%s", gaps[0] ? gaps :
			    "（详见判卷明细）\n");
		n = snp_cat(buf, buflen, n, "证据：叙述性「自称完成」按 §4 "
			    "不采信——未提供可机检证据（VERDICT 固定表头/"
			    "文件在场/md5 对照/断言行至少其一）\n");
		n = snp_cat(buf, buflen, n, "整改要求：按未达标准逐条补齐："
			    "交付 # VERDICT 表（表头 | criterion | result | "
			    "evidence | self |），每条验收标准一行、"
			    "result=pass、evidence 给 exit:/file:/md5:/"
			    "contains: 机检令牌且证据文件真实在场\n");
	}
	if (escalate)
		n = snp_cat(buf, buflen, n, "处置：升级人工三选一——换智能体"
			    "重派 / 拆解任务 / 上抛用户（子智能体永不直接"
			    "对话用户，§4）\n");
	else
		n = snp_cat(buf, buflen, n, "剩余机会：%d 次，超限将 换智能体"
			    "/拆任务/上抛用户\n", max - attempt);
	return n;
}

size_t occ_review_render_rework(const occ_review_verdict *v,
				int judge_rejected, const char *judge_note,
				int attempt, int max,
				char *buf, size_t buflen)
{
	if (!buf || !buflen)
		return 0;
	buf[0] = '\0';
	if (!v)
		return 0;
	return render_std_block(v, judge_rejected, judge_note, buf, buflen,
				attempt, max, 0);
}

size_t occ_review_render_escalate(const occ_review_verdict *v,
				  int judge_rejected, const char *judge_note,
				  int attempts, int max,
				  char *buf, size_t buflen)
{
	if (!buf || !buflen)
		return 0;
	buf[0] = '\0';
	if (!v)
		return 0;
	return render_std_block(v, judge_rejected, judge_note, buf, buflen,
				attempts, max, 1);
}

/* ============ 验收环驱动（DB 面） ============ */

static void set_rv_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || !errlen)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* kind='return' 审计事件（E3 通道承载 E4 语义；payload 经 aik_json 转义） */
static int rv_note(occ_db *db, const char *tid, const char *action,
		   const char *key, const char *text)
{
	aik_json *o;
	char *txt = NULL;
	size_t tl = 0;
	char e[128];
	int rc;

	o = aik_json_new_obj();
	if (!o ||
	    aik_json_obj_put(o, "action", aik_json_new_str(action)) ||
	    aik_json_obj_put(o, key,
			     text ? aik_json_new_str(text) :
				    aik_json_new_null())) {
		aik_json_free(o);
		return -1;
	}
	if (aik_json_dump(o, &txt, &tl) != 0 || !txt) {
		aik_json_free(o);
		return -1;
	}
	aik_json_free(o);
	rc = occ_task_note(db, tid, txt, e, sizeof(e));
	free(txt);
	return rc;
}

/* 裁决审计 JSON（occ_task.verdict_json + verdict 事件 payload） */
static char *verdict_json_build(const occ_review_verdict *v,
				int machine_pass, int judge_pass,
				int forced, const char *judge_note)
{
	aik_json *o, *arr;
	char *txt = NULL;
	size_t tl = 0, i;

	o = aik_json_new_obj();
	arr = aik_json_new_arr();
	if (!o || !arr)
		goto fail;
	for (i = 0; i < (size_t)v->n_hit; i++) {
		char line[OCC_RV_RULE_MAX + OCC_RV_DETAIL_MAX];

		snprintf(line, sizeof(line), "%s: %s", v->rule[i],
			 v->detail[i]);
		if (aik_json_arr_push(arr, aik_json_new_str(line))) {
			aik_json_free(arr);
			aik_json_free(o);
			return NULL;
		}
	}
	if (aik_json_obj_put(o, "rules", arr)) {
		aik_json_free(arr);	/* 挂入失败=所有权未转移 */
		aik_json_free(o);
		return NULL;
	}
	if (aik_json_obj_put(o, "machine_pass",
			     aik_json_new_bool(machine_pass)) ||
	    aik_json_obj_put(o, "judge_pass", aik_json_new_bool(judge_pass)) ||
	    aik_json_obj_put(o, "forced", aik_json_new_bool(forced)) ||
	    aik_json_obj_put(o, "n_hit", aik_json_new_int(v->n_hit)) ||
	    aik_json_obj_put(o, "judge_note",
			     judge_note && judge_note[0] ?
			     aik_json_new_str(judge_note) :
			     aik_json_new_null()))
		goto fail_unowned;
	if (aik_json_dump(o, &txt, &tl) != 0 || !txt)
		goto fail_unowned;
	aik_json_free(o);
	return txt;
fail:
	aik_json_free(arr);
	aik_json_free(o);
	return NULL;
fail_unowned:
	aik_json_free(o);		/* arr 已挂入 o 随之释放 */
	return NULL;
}

/* brief_json → 验收标准条目（heap strdup 数组；调用方逐项 free） */
static size_t brief_acceptance(const char *brief_json, char ***out)
{
	aik_json *b;
	const aik_json *a;
	char **vec = NULL;
	size_t n = 0, i, k = 0, cap;
	char perr[96];

	*out = NULL;
	if (!brief_json || !brief_json[0])
		return 0;
	b = aik_json_parse(brief_json, strlen(brief_json), perr,
			   sizeof(perr));
	if (!b)
		return 0;
	a = aik_json_get(b, "acceptance");
	if (a && aik_json_typeof(a) == AIK_JSON_ARR) {
		n = aik_json_count(a);
		if (n > RV_MAX_ACC)
			n = RV_MAX_ACC;
		cap = n ? n : 1;
		vec = calloc(cap, sizeof(*vec));
		if (vec)
			for (i = 0; i < n; i++) {
				const char *s = aik_json_str(aik_json_at(a, i));

				if (s && s[0])
					vec[k++] = strdup(s);
			}
	}
	aik_json_free(b);
	*out = vec;
	return k;
}

static void acc_free(char **acc, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(acc[i]);
	free(acc);
}

/* 最后 result 事件 payload（终局摘要；R-EXIT 输入） */
static void last_result_event(occ_db *db, const char *tid,
			      const char **out)
{
	occ_task_event_row *evs = NULL;
	size_t nevs = 0, i;

	*out = NULL;
	if (occ_task_events(db, tid, &evs, &nevs, NULL, 0) != 0)
		return;
	for (i = 0; i < nevs; i++)
		if (!strcmp(evs[i].kind, OCC_TASK_EV_RESULT) &&
		    evs[i].payload_json && evs[i].payload_json[0])
			*out = evs[i].payload_json;
	/* 行集释放后 payload_json 即悬垂——复制一份归调用方所有
	 * （调用方 parse 毕 free）。主会话验尸实抓：UAF 读使正路
	 * R-EXIT 恒判「终局 result 事件不是合法 JSON」。 */
	if (*out) {
		size_t plen = strlen(*out) + 1;
		char *cp = malloc(plen);

		if (!cp) {
			occ_task_event_rows_free(evs, nevs);
			*out = NULL;
			return;
		}
		memcpy(cp, *out, plen);
		occ_task_event_rows_free(evs, nevs);
		*out = cp;
		return;
	}
	occ_task_event_rows_free(evs, nevs);
}

int occ_review_run(occ_db *db, const char *task_id,
		   const occ_review_opts *opts,
		   occ_review_verdict *out_v,
		   char *out_brief, size_t brieflen,
		   char *out_state, size_t statelen,
		   char *err, size_t errlen)
{
	occ_task_row row, row2;
	occ_review_verdict v;
	char **acc = NULL;
	size_t n_acc = 0;
	char *report = NULL, *vj = NULL;
	const char *lre = NULL, *note;
	const char *base_dir, *result_path;
	int machine_pass, judge_pass, act_pass, forced, judge_rejected;

	if (out_brief && brieflen)
		out_brief[0] = '\0';
	if (out_state && statelen)
		out_state[0] = '\0';
	if (!db || !task_id || !task_id[0]) {
		set_rv_err(err, errlen, "occ_review_run: bad args");
		return -1;
	}
	if (occ_task_get(db, task_id, &row, err, errlen) != 1) {
		set_rv_err(err, errlen, "任务 %s 不存在或库错", task_id);
		return -1;
	}
	if (strcmp(row.status, OCC_TASK_ST_IN_REVIEW) != 0) {
		set_rv_err(err, errlen, "任务 %s 当前 %s——验收环仅 "
			   "in_review 可裁决（先 wait 终局）", task_id,
			   row.status);
		occ_task_row_free(&row);
		return -1;
	}
	note = opts && opts->judge_note ? opts->judge_note : "";
	base_dir = opts ? opts->base_dir : NULL;
	result_path = opts ? opts->result_path : NULL;
	judge_pass = opts ? opts->judge_pass : 0;

	/* 裁判表态先落审计（E3 return 通道；机械判无论过否都留痕） */
	if (note[0])
		rv_note(db, task_id, "return", "verdict", note);

	/* 机械判输入三件：终局事件 + 结果文件 + brief 验收标准 */
	last_result_event(db, task_id, &lre);
	if (result_path && result_path[0])
		report = read_file_cap(result_path, 128 * 1024);
	n_acc = brief_acceptance(row.brief_json, &acc);

	occ_review_verdict_init(&v);
	occ_review_parse(report, lre, base_dir, (const char *const *)acc,
			 n_acc, &v);
	free((void *)lre);	/* last_result_event 副本归己，parse 毕释放 */
	lre = NULL;
	machine_pass = v.pass;
	forced = !machine_pass;		/* 防转述：机判 fail 时裁判无放行权 */
	act_pass = machine_pass ? judge_pass : 0;
	judge_rejected = machine_pass && !judge_pass;

	vj = verdict_json_build(&v, machine_pass, judge_pass, forced, note);
	/* 三路分派（E1 状态机按 pass/计数迁 done/rework/escalated） */
	{
		int rc = occ_task_verdict(db, task_id, act_pass,
					  vj ? vj : "", err, errlen);

		free(vj);
		if (rc != 0) {
			acc_free(acc, n_acc);
			free(report);
			occ_task_row_free(&row);
			return -1;
		}
	}
	occ_task_row_free(&row);

	/* 回读终态 → 渲染对应文案（三路：done=终止/结项、rework=回炉、
	 * escalated=升级人工） */
	if (occ_task_get(db, task_id, &row2, err, errlen) != 1) {
		set_rv_err(err, errlen, "裁决已落但任务 %s 读回失败", task_id);
		acc_free(acc, n_acc);
		free(report);
		return -1;
	}
	if (out_state && statelen)
		snprintf(out_state, statelen, "%s", row2.status);
	if (out_v)
		*out_v = v;
	if (!strcmp(row2.status, OCC_TASK_ST_REWORK) && out_brief && brieflen) {
		occ_review_render_rework(&v, judge_rejected, note,
					 row2.rework_count, row2.rework_max,
					 out_brief, brieflen);
		rv_note(db, task_id, "rework_brief", "text", out_brief);
	} else if (!strcmp(row2.status, OCC_TASK_ST_ESCALATED) &&
		   out_brief && brieflen) {
		occ_review_render_escalate(&v, judge_rejected, note,
					   row2.rework_count, row2.rework_max,
					   out_brief, brieflen);
		rv_note(db, task_id, "escalate_brief", "text", out_brief);
	}
	occ_task_row_free(&row2);
	acc_free(acc, n_acc);
	free(report);
	return 0;
}

/* ============ 终局机械预判（orch collect 挂点） ============ */

int occ_review_prenote(occ_db *db, const char *task_id,
		       const char *result_path)
{
	occ_task_row row;
	occ_review_verdict v;
	aik_json *o = NULL, *arr = NULL;
	char **acc = NULL;
	size_t n_acc = 0, i;
	char *report = NULL, *txt = NULL;
	const char *lre = NULL;
	size_t tl = 0;
	char e[128];
	int rc = -1;

	if (!db || !task_id || !task_id[0])
		return -1;
	if (occ_task_get(db, task_id, &row, e, sizeof(e)) != 1)
		return -1;
	last_result_event(db, task_id, &lre);
	if (result_path && result_path[0])
		report = read_file_cap(result_path, 128 * 1024);
	n_acc = brief_acceptance(row.brief_json, &acc);
	occ_review_verdict_init(&v);
	occ_review_parse(report, lre, NULL, (const char *const *)acc,
			 n_acc, &v);
	free((void *)lre);	/* 同上：副本归己，parse 毕释放 */
	lre = NULL;

	o = aik_json_new_obj();
	arr = aik_json_new_arr();
	if (!o || !arr)
		goto out;
	for (i = 0; i < (size_t)v.n_hit; i++)
		if (aik_json_arr_push(arr, aik_json_new_str(v.rule[i])))
			goto out;
	if (aik_json_obj_put(o, "rules", arr)) {
		aik_json_free(arr);	/* 挂入失败=所有权未转移 */
		arr = NULL;
		goto out;
	}
	arr = NULL;			/* 已挂入 o */
	if (aik_json_obj_put(o, "action",
			     aik_json_new_str("machine_verdict")) ||
	    aik_json_obj_put(o, "pass", aik_json_new_bool(v.pass)) ||
	    aik_json_obj_put(o, "n_hit", aik_json_new_int(v.n_hit)))
		goto out;
	if (aik_json_dump(o, &txt, &tl) != 0 || !txt)
		goto out;
	if (occ_task_note(db, task_id, txt, e, sizeof(e)) == 0)
		rc = 0;
out:
	aik_json_free(arr);
	aik_json_free(o);
	free(txt);
	acc_free(acc, n_acc);
	free(report);
	occ_task_row_free(&row);
	return rc;
}
