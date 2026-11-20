/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tools.c - occ 工具面实现（T9b1 六件套 + O-17 文件管理三件；
 * OPENCODE-PLAN §7）
 *
 * read/write/edit/glob/grep 直接实现（朴素、零第三方依赖：fnmatch +
 * 字节子串搜索，不引 PCRE——任务书明示）；bash 经 occ_tools/sandbox.c
 * 的 aik-sandbox 对接（namespace 隔离；不可用即拒）；O-17 rm/mv/
 * mkdir 走宿主面（write 同款域守卫——AI 建得了也删得掉）。
 *
 * 每次执行的副作用链（occ_tool_exec 单入口）：
 *   参数解析 → （write/edit）快照 stage → 执行 → trace JSONL →
 *   （ctx->db 给定）occ_toolcall 行 + tool 结果消息单事务落库
 *   （durable：先落库再回灌——loop 下轮从库重读，OPENCODE-PLAN §6）。
 *
 * 结果文本化：成功=payload（read/grep 带行号等上下文），失败=
 * "ERROR: <人话>"；一律 UTF-8 边界安全截断至 8KB。
 */
#define _GNU_SOURCE
#include "occ_tools.h"
#include "occ_tools_priv.h"
#include "sha256.h"			/* S-FINDING-01：快照 sidecar */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "occ_core/orch.h"			/* E3：task 工具执行面 */
#include "occ_core/occ_sme.h"	/* E6：recall 记忆检索 */
#include "occ_core/review.h"			/* E4：return 走验收环 */
#include "occ_core/occ_ac.h"		/* E5：done→request_compact 闸 */
#include "occ_llm/occ_catalog.h"		/* E7：定价四字段消费点
						 * （task 工具 budget 段
						 * 显示参考——只读查询） */

#include "store/store_json.h"

#include "occ_utf8.h"		/* E10②：UTF-8 校验/净化共用件
				 * （bash 工具结果源端净化与 occ_llm
				 * 请求体出口兜底同一实现） */

#include "occ_tui/tui_lang.h"		/* O-20 A2：语档文案面 */

/* ---- 结果缓冲（occ_tools_priv.h 契约实现） ---- */

void occ_ob_put(occ_obuf *o, const char *s, size_t n)
{
	o->total += n;
	if (o->len + n <= OCC_TOOL_OUT_MAX) {
		memcpy(o->buf + o->len, s, n);
		o->len += n;
	} else {
		size_t room = OCC_TOOL_OUT_MAX > o->len ?
			      OCC_TOOL_OUT_MAX - o->len : 0;

		if (room) {
			size_t keep = n < room ? n : room;
			size_t cut = keep;

			/* UTF-8 边界回退（不切多字节字符） */
			while (cut > 0 &&
			       ((unsigned char)s[cut] & 0xC0) == 0x80)
				cut--;
			if (cut == 0)
				cut = keep;
			memcpy(o->buf + o->len, s, cut);
			o->len += cut;
		}
		o->truncated = 1;
	}
}

void occ_ob_puts(occ_obuf *o, const char *s)
{
	occ_ob_put(o, s, strlen(s));
}

void occ_ob_printf(occ_obuf *o, const char *fmt, ...)
{
	char tmp[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	occ_ob_puts(o, tmp);
}

/* ---- 参数 schema（LLM 请求 tools 定义；键序=此处字面序） ---- */

static const char SCHEMA_READ[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"path\":{\"type\":\"string\",\"description\":\"文件绝对或相对"
	"（工作目录）路径\"},"
	"\"offset\":{\"type\":\"integer\",\"description\":\"起始行号"
	"（1 起；缺省 1）\",\"minimum\":1},"
	"\"limit\":{\"type\":\"integer\",\"description\":\"读取行数上限"
	"（缺省 500）\",\"minimum\":1}"
	"},\"required\":[\"path\"]}";

static const char SCHEMA_WRITE[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"path\":{\"type\":\"string\",\"description\":\"目标文件路径"
	"（限工作目录子树、/tmp、/var/ai、$HOME）\"},"
	"\"content\":{\"type\":\"string\",\"description\":\"完整文件内容"
	"（整文件覆写）\"}"
	"},\"required\":[\"path\",\"content\"]}";

static const char SCHEMA_EDIT[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"path\":{\"type\":\"string\",\"description\":\"目标文件路径\"},"
	"\"oldString\":{\"type\":\"string\",\"description\":\"被替换的精确"
	"字符串（必须在文件中唯一，或配合 replaceAll）\"},"
	"\"newString\":{\"type\":\"string\",\"description\":\"替换后的"
	"字符串\"},"
	"\"replaceAll\":{\"type\":\"boolean\",\"description\":\"true=替换"
	"全部出现；缺省 false（多处命中即报错）\"}"
	"},\"required\":[\"path\",\"oldString\",\"newString\"]}";

static const char SCHEMA_GLOB[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"pattern\":{\"type\":\"string\",\"description\":\"glob 模式："
	"** 跨任意层目录，* 不跨 /；点文件需模式显式以 . 开头"
	"（如 **/.*）\"},"
	"\"path\":{\"type\":\"string\",\"description\":\"搜索根目录"
	"（缺省工作目录）\"}"
	"},\"required\":[\"pattern\"]}";

static const char SCHEMA_GREP[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"pattern\":{\"type\":\"string\",\"description\":\"搜索文本"
	"（朴素字节子串匹配，大小写敏感；中文可用）\"},"
	"\"path\":{\"type\":\"string\",\"description\":\"搜索目标：文件或"
	"目录（缺省工作目录，递归）\"},"
	"\"glob\":{\"type\":\"string\",\"description\":\"仅搜文件名匹配"
	"该 glob 的文件（如 *.c）\"}"
	"},\"required\":[\"pattern\"]}";

static const char SCHEMA_BASH[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"command\":{\"type\":\"string\",\"description\":\"要执行的 shell"
	" 命令（在 aik-sandbox 隔离区内以 /bin/sh -c 运行；工作目录以读写"
	"方式挂入，宿主其余路径不可见；网络保留）\"},"
	"\"workdir\":{\"type\":\"string\",\"description\":\"工作目录"
	"（缺省 occ 启动目录；将以读写方式挂入沙箱，须与沙箱同 uid 属主）\"},"
	"\"timeout\":{\"type\":\"integer\",\"description\":\"超时秒数"
	"（缺省 60，上限同全局配置）\",\"minimum\":1}"
	"},\"required\":[\"command\"]}";

/* O-17 文件管理三件（write 同款宿主面；守卫=occ_write_target_ok 域
 * + w2_confirmed 豁免——mv 两端各查）。v1 诚实限制内嵌 description：
 * AI 读 schema 即知边界，不靠试错。 */
static const char SCHEMA_RM[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"path\":{\"type\":\"string\",\"description\":\"要删除的文件路径"
	"（相对路径按工作目录解析）。仅普通文件与空目录——非空目录报错"
	"（请逐个删除，v1 不做递归删）。目标域=工作目录子树∪/tmp∪/var/ai"
	"∪$HOME（越界须 W2 确认；~/.occ 恒拒）\"}"
	"},\"required\":[\"path\"]}";

static const char SCHEMA_MV[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"src\":{\"type\":\"string\",\"description\":\"源路径（文件或目录；"
	"相对路径按工作目录解析）\"},"
	"\"dst\":{\"type\":\"string\",\"description\":\"目标路径。已存在则"
	"报错（v1 不覆盖已有目标——防误覆盖）；跨设备报错（不做 copy+"
	"unlink，可 read+write 复制后 rm）。两端均须在目标域"
	"（工作目录子树∪/tmp∪/var/ai∪$HOME；越界须 W2 确认；"
	"~/.occ 恒拒）\"}"
	"},\"required\":[\"src\",\"dst\"]}";

static const char SCHEMA_MKDIR[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"path\":{\"type\":\"string\",\"description\":\"要创建的目录路径"
	"（-p 语义：父目录递归创建；已存在=幂等成功）。目标域=工作目录"
	"子树∪/tmp∪/var/ai∪$HOME（越界须 W2 确认；~/.occ 恒拒）\"}"
	"},\"required\":[\"path\"]}";

/* E3 第七工具（ORCH-DESIGN §3 拍板字段集；仅 OCC_ORCH_TOOLS=1 注册）
 * E4：return 动作升级走验收环——机械判（§4）先行，verdict/pass=裁判
 * 表态（机械判过才生效）；fail 出整改词（§3 模板）与三路去向。 */
static const char SCHEMA_TASK[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"action\":{\"type\":\"string\",\"enum\":[\"spawn\",\"status\","
	"\"wait\",\"read_result\",\"return\"],\"description\":\"spawn=建任务"
	"并派发子智能体（可选 task_id=对该回炉任务再派）；status=查任务"
	"状态；wait=限时等待终局；"
	"read_result=读子报告与终局摘要；return=验收表态（触发验收环："
	"机械判→回炉整改词/超限升级/通过结项）\"},"
	"\"brief\":{\"type\":\"object\",\"description\":\"spawn 任务书"
	"（§3 字段集）：goal 目标一句话（必填）；fileset 授权文件集"
	"（必填非空数组，独占声明——并发任务声明同一文件会被拒绝）；"
	"forbidden 禁改清单；deliverables 交付物清单；acceptance 验收标准"
	"（尽量可机械判——file:/md5:/contains:/exit: 机检令牌会被验收环"
	"逐条核对）；selfcheck 自检清单；auth_note 授权说明；"
	"budget 预算配额（可含 wall_ms 墙钟上限毫秒、max_tokens 任务累计"
	"输入+输出 token 上限——超限即熔断取消并升级）；context 必要上下文；"
	"rework_max 回炉上限覆写（1-3，缺省 2）\"},"
	"\"task_id\":{\"type\":\"string\",\"description\":\"目标任务 id"
	"（tsk_…，spawn 返回）：status/wait/read_result/return 必填；"
	"spawn 可选=对该任务回炉再派（仅 rework 态受理工具面再派，"
	"其余态拒绝）\"},"
	"\"timeout_ms\":{\"type\":\"integer\",\"description\":\"wait 限时"
	"毫秒（缺省 2000，上限 120000；到点未终局如实返回未终局而非挂死）\","
	"\"minimum\":100},"
	"\"verdict\":{\"type\":\"string\",\"description\":\"return 动作："
	"主会话（裁判）对结果的表态原文（差距/亲跑抽查依据，记入任务"
	"事件与裁决审计）\"},"
	"\"pass\":{\"type\":\"boolean\",\"description\":\"return 动作："
	"裁判表态位（true=认可；缺省按 verdict 文本推断——含「不通过/"
	"不认可/拒绝」按否决）。仅在机械判通过后生效：机械判 fail 时"
	"强行 pass 无效（防转述验收，§4）\"}"
	"},\"required\":[\"action\"]}";

static const occ_tool_def TOOLS[] = {
	{ OCC_T_READ,  "读取文件内容（带行号，支持行窗 offset/limit）。二进制文件拒绝。", SCHEMA_READ },
	{ OCC_T_WRITE, "整文件写入（覆盖），父目录不存在则递归创建；写前自动快照原文件（可撤销地基）。", SCHEMA_WRITE },
	{ OCC_T_EDIT,  "精确字符串替换：oldString 必须在文件中唯一命中，或 replaceAll=true 全部替换；未命中/多处命中不带 replaceAll 均报错。", SCHEMA_EDIT },
	{ OCC_T_GLOB,  "文件模式匹配（递归，** 跨目录）；返回匹配路径列表。", SCHEMA_GLOB },
	{ OCC_T_GREP,  "文本搜索（字节子串匹配，含中文；返回 文件:行号:行）。", SCHEMA_GREP },
	{ OCC_T_BASH,  "在 aik-sandbox 隔离区（mount/pid/uts namespace，能力裁剪）内执行 shell 命令；沙箱不可用时拒绝执行（绝不裸跑）。", SCHEMA_BASH },
	{ OCC_T_RM,    "删除文件（宿主面，不经沙箱）：仅普通文件与空目录，非空目录报错建议逐个删；越界目标须 W2 确认。", SCHEMA_RM },
	{ OCC_T_MV,    "移动/改名（宿主面，不经沙箱）：rename 语义，不覆盖已有目标，跨设备报错；两端越界须 W2 确认。", SCHEMA_MV },
	{ OCC_T_MKDIR, "创建目录（宿主面，不经沙箱）：-p 语义父目录递归创建，已存在幂等成功；越界目标须 W2 确认。", SCHEMA_MKDIR },
};

/*
 * E3：开关组合表——OCC_ORCH_TOOLS=1 时六件套尾部追加 task。首用拷贝
 * 构造（只读静态源，无并发写面）；默认路径恒返回 TOOLS 原数组（差分
 * /p-smoke 红线：请求字节零变化）。
 */
	/* E6 第八工具：recall（ORCH §6 拍板 2026-11-12 补——模型侧记忆检索；
 * 不依赖 orch 运行时；同 OCC_ORCH_TOOLS 闸） */
static const char SCHEMA_RECALL[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"query\":{\"type\":\"string\",\"description\":\"检索词"
	"（会话名/主题/任务目标等）\"},"
	"\"layer\":{\"type\":\"string\",\"description\":\"层过滤："
	"t:<task_id>=任务层私有记忆；failed=被否决/失败尝试（默认只查"
	"清洁层——防污染）\"}"
	"},\"required\":[\"query\"]}";

/* C-P2a 第九工具：config_write_network（OCC_NETCFG_TOOLS=1 注册）。
 * 结构化写 /etc/systemd/network/70-static-<iface>.network（字典序先于
 * 出厂 80-wired → systemd-networkd 首个匹配生效=静态覆盖 DHCP；删文件
 * 即回 DHCP）。固定路径模式+全参校验——不经 write 工具的自由路径面；
 * write/remove 两动作恒 W2（人工确认门），show 只读。 */
static const char SCHEMA_NETCFG[] =
	"{\"type\":\"object\",\"properties\":{"
	"\"action\":{\"type\":\"string\",\"enum\":[\"write\",\"remove\","
	"\"show\"],\"description\":\"write=写静态配置文件；remove=删该"
	"文件回 DHCP；show=列出现存 .network 关键行\"},"
	"\"iface\":{\"type\":\"string\",\"description\":\"接口名（如 "
	"eth0/enp0s3；write/remove 必填；show 可选=只看该口）\"},"
	"\"address\":{\"type\":\"string\",\"description\":\"静态地址 "
	"CIDR（write 必填，如 192.168.1.10/24，掩码段 0-32）\"},"
	"\"gateway\":{\"type\":\"string\",\"description\":\"网关 IPv4"
	"（可选）\"},"
	"\"dns\":{\"type\":\"string\",\"description\":\"DNS 服务器，"
	"逗号分隔（可选，如 223.5.5.5,1.1.1.1）\"}"
	"},\"required\":[\"action\"]}";

static int occ_netcfg_tools_enabled(void)
{
	const char *e = getenv("OCC_NETCFG_TOOLS");

	return e && e[0] && strcmp(e, "0") != 0;
}

/* def 复用段（TOOLS_ORCH 与 TOOLS_NET 两个旗控组装体共用） */
static void def_task_set(occ_tool_def *d)
{
	d->name = OCC_T_TASK;
	d->description =
		"主从编排（先按 L0/L1/L2 判级决定是否派发）："
		"spawn 提交 brief 任务书派发子智能体（goal 与"
		"非空 fileset 必填；fileset 为独占声明）；"
		"status 查状态；wait 限时等终局；read_result 读"
		"子报告；return 对结果表态。返回结构化 JSON。";
	d->parameters = SCHEMA_TASK;
}

static void def_recall_set(occ_tool_def *d)
{
	d->name = OCC_T_RECALL;
	d->description =
		"长期记忆检索（SME）：按 query 查 〈记忆〉；"
		"layer=t:<task_id> 查任务层私有；"
		"include_failed=true 含失败/被否决尝试"
		"（默认防污染只查清洁层）。";
	d->parameters = SCHEMA_RECALL;
}

static void def_netcfg_set(occ_tool_def *d)
{
	d->name = OCC_T_NETCFG;
	d->description =
		"静态 IP 配置（结构化，W2 确认门）：write 写 "
		"/etc/systemd/network/70-static-<iface>.network（iface+"
		"address CIDR 必填，gateway/dns 可选——全参校验，覆盖出厂 "
		"DHCP）；remove 删文件回 DHCP；show 列现存配置。生效指引"
		"随结果返回。";
	d->parameters = SCHEMA_NETCFG;
}


static occ_tool_def TOOLS_ORCH[11];
static int tools_orch_init;

/* C-P2a：netcfg 旗控组装体（9 基础+netcfg；orch 同开时再补 task/recall） */
static occ_tool_def TOOLS_NET[12];
static int tools_net_init;
static size_t tools_net_n;

const occ_tool_def *occ_tool_defs(size_t *n)
{
	if (occ_netcfg_tools_enabled()) {
		if (!tools_net_init) {
			size_t i, k = 0;

			for (i = 0; i < sizeof(TOOLS) / sizeof(TOOLS[0]); i++)
				TOOLS_NET[k++] = TOOLS[i];
			def_netcfg_set(&TOOLS_NET[k++]);
			if (occ_orch_tools_enabled()) {
				def_task_set(&TOOLS_NET[k++]);
				def_recall_set(&TOOLS_NET[k++]);
			}
			tools_net_n = k;
			tools_net_init = 1;
		}
		if (n)
			*n = tools_net_n;
		return TOOLS_NET;
	}
	if (occ_orch_tools_enabled()) {
		if (!tools_orch_init) {
			size_t i;

			for (i = 0; i < sizeof(TOOLS) / sizeof(TOOLS[0]); i++)
				TOOLS_ORCH[i] = TOOLS[i];
			def_task_set(&TOOLS_ORCH[9]);
			def_recall_set(&TOOLS_ORCH[10]);
			tools_orch_init = 1;
		}
		if (n)
			*n = sizeof(TOOLS_ORCH) / sizeof(TOOLS_ORCH[0]);
		return TOOLS_ORCH;
	}
	if (n)
		*n = sizeof(TOOLS) / sizeof(TOOLS[0]);
	return TOOLS;
}

int occ_tool_is_known(const char *name)
{
	size_t i;

	for (i = 0; i < sizeof(TOOLS) / sizeof(TOOLS[0]); i++)
		if (!strcmp(TOOLS[i].name, name))
			return 1;
	if (occ_orch_tools_enabled() && name &&
	    (!strcmp(OCC_T_TASK, name) || !strcmp(OCC_T_RECALL, name)))
		return 1;	/* E6：recall 同闸入已知面 */
	if (occ_netcfg_tools_enabled() && name &&
	    !strcmp(OCC_T_NETCFG, name))
		return 1;	/* C-P2a：同闸入已知面 */
	return 0;
}

/* ---- 通用小件 ---- */

long long occ_monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

size_t occ_utf8_trunc(const char *src, size_t len, size_t max,
		      char *dst, size_t dstlen)
{
	size_t keep = len <= max ? len : max;

	(void)dstlen;
	if (keep < len) {
		size_t cut = keep;

		while (cut > 0 && ((unsigned char)src[cut] & 0xC0) == 0x80)
			cut--;
		if (cut == 0)
			cut = keep;	/* 防御：整段续字节 */
		keep = cut;
	}
	memcpy(dst, src, keep);
	dst[keep] = '\0';
	return keep;
}

int occ_path_is_under(const char *abs, const char *base)
{
	size_t lb;

	if (!abs || !base || abs[0] != '/' || base[0] != '/')
		return 0;
	lb = strlen(base);
	if (lb > 1 && base[lb - 1] == '/')
		lb--;
	if (!strncmp(abs, base, lb) && abs[lb] == '\0')
		return 1;
	if (lb == 1)
		return 1;			/* base="/" */
	return !strncmp(abs, base, lb) && abs[lb] == '/';
}

/* ~/.occ（会话库/快照区）子树判定——P-45 红线：一律拒绝，任何豁免
 * 不得越过（P-52 刀2 write_guard 的 w2_confirmed 豁免复用同口径）。
 * 抽自 occ_write_target_ok 首步，语义零变化（静态缓存同款）。 */
static int occ_abs_under_home_occ(const char *abs)
{
	static char home_occ[512];
	static int home_occ_init;
	const char *home;

	if (!abs || abs[0] != '/')
		return 0;
	if (!home_occ_init) {
		home = getenv("HOME");
		if (home)
			snprintf(home_occ, sizeof(home_occ), "%s/.occ",
				 home);
		home_occ_init = 1;
	}
	return home_occ[0] && occ_path_is_under(abs, home_occ);
}

int occ_write_target_ok(const char *abs, const char *cwd)
{
	if (!abs || abs[0] != '/')
		return 0;
	if (occ_abs_under_home_occ(abs))
		return 0;			/* 会话库/快照区拒绝 */
	if (occ_path_is_under(abs, "/tmp") ||
	    occ_path_is_under(abs, "/var/ai"))
		return 1;
	/* O-6：$HOME 子树放行（/root 直写/直删——对齐 w2_path_safe 分
	 * 类面已有口径，消「判 W1 却被守卫拒」假阳；HOME 空/非绝对/
	 * 超长跳过（不缓存——getenv 直读，单测可桩 HOME）；~/.occ 首
	 * 步恒拒不豁免） */
	{
		const char *h = getenv("HOME");

		if (h && h[0] == '/' && h[1] &&
		    strlen(h) < 512 &&
		    occ_path_is_under(abs, h))
			return 1;
	}
	if (cwd && cwd[0] == '/' && occ_path_is_under(abs, cwd))
		return 1;
	return 0;
}

/* mkdir -p（忽略已存在） */
static int mkdirs(const char *path)
{
	char buf[4096];
	size_t i, n = strlen(path);

	if (!n || n + 1 > sizeof(buf))
		return -1;
	memcpy(buf, path, n + 1);
	for (i = 1; i < n; i++) {
		if (buf[i] == '/') {
			buf[i] = '\0';
			if (mkdir(buf, 0777) && errno != EEXIST)
				return -1;
			buf[i] = '/';
		}
	}
	if (mkdir(buf, 0777) && errno != EEXIST)
		return -1;
	return 0;
}

/* 读整文件（上限 max 字节；*out heap NUL 结尾） */
static int read_whole(const char *path, size_t max, char **out, size_t *len)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long sz;

	if (!f)
		return -1;
	if (fseek(f, 0, SEEK_END)) {
		fclose(f);
		return -1;
	}
	sz = ftell(f);
	if (sz < 0 || (unsigned long)sz > max) {
		fclose(f);
		errno = EFBIG;
		return -1;
	}
	rewind(f);
	if (sz == 0) {
		/* LT-BUG-003：procfs/sysfs 虚拟文件 stat 尺寸为 0——
		 * fseek/ftell 快路读出空内容假象（实测 /proc/1/comm 报
		 * 「空文件」）；流式读至 EOF。read/edit/grep/bash 出读
		 * 共用本函数，一处修全家。 */
		size_t cap = 8192, n = 0, r;

		buf = malloc(cap + 1);
		if (!buf) {
			fclose(f);
			errno = ENOMEM;
			return -1;
		}
		while (n < max && (r = fread(buf + n, 1, cap - n, f)) > 0) {
			n += r;
			if (n == cap && cap < max) {
				char *nb;
				size_t nc = cap * 2;

				if (nc > max)
					nc = max;
				nb = realloc(buf, nc + 1);
				if (!nb) {
					free(buf);
					fclose(f);
					errno = ENOMEM;
					return -1;
				}
				buf = nb;
				cap = nc;
			}
		}
		buf[n] = '\0';
		fclose(f);
		*out = buf;
		*len = n;
		return 0;
	}
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		errno = ENOMEM;
		return -1;
	}
	if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return -1;
	}
	fclose(f);
	buf[sz] = '\0';
	*out = buf;
	*len = (size_t)sz;
	return 0;
}

static int is_binary(const char *buf, size_t len)
{
	return memchr(buf, '\0', len) != NULL;
}

/* 朴素字节子串搜索（不依赖 GNU memmem） */
static const char *byte_search(const char *hay, size_t hlen,
			       const char *needle, size_t nlen)
{
	if (nlen == 0)
		return hay;
	if (hlen < nlen)
		return NULL;
	for (size_t i = 0; i + nlen <= hlen; i++)
		if (hay[i] == needle[0] && !memcmp(hay + i, needle, nlen))
			return hay + i;
	return NULL;
}

static size_t count_occurrences(const char *hay, size_t hlen,
				const char *needle, size_t nlen)
{
	size_t n = 0;
	size_t off = 0;

	if (!nlen)
		return 0;
	while (off < hlen) {
		const char *hit = byte_search(hay + off, hlen - off,
					      needle, nlen);

		if (!hit)
			break;
		n++;
		off = (size_t)(hit - hay) + nlen;
	}
	return n;
}

/* ---- 参数视图（args JSON → 便捷取值；解析失败按缺失处理） ---- */

typedef struct {
	aik_json *root;			/* NULL=无/坏参数 */
	int bad;			/* E3：原文非空但解析失败（坏 JSON） */
} occ_args;

static void args_init(occ_args *a, const char *args_json)
{
	char err[128];

	a->root = NULL;
	a->bad = 0;
	if (!args_json || !args_json[0] || !strcmp(args_json, "{}"))
		return;
	a->root = aik_json_parse(args_json, strlen(args_json),
				 err, sizeof(err));
	if (!a->root)
		a->bad = 1;
}

static void args_free(occ_args *a)
{
	if (a->root)
		aik_json_free(a->root);
	a->root = NULL;
}

static const char *args_str(const occ_args *a, const char *key)
{
	if (!a->root)
		return NULL;
	return aik_json_str(aik_json_get(a->root, key));
}

static long long args_int(const occ_args *a, const char *key, long long dflt)
{
	const aik_json *v;

	if (!a->root)
		return dflt;
	v = aik_json_get(a->root, key);
	if (!v)
		return dflt;
	if (aik_json_typeof(v) == AIK_JSON_STR)
		return atoll(aik_json_str(v));
	return aik_json_int(v);
}

static int args_bool(const occ_args *a, const char *key)
{
	const aik_json *v;

	if (!a->root)
		return 0;
	v = aik_json_get(a->root, key);
	if (!v)
		return 0;
	if (aik_json_typeof(v) == AIK_JSON_STR)
		return strcasecmp(aik_json_str(v), "true") == 0;
	return aik_json_bool(v);
}

/* 工作目录（优先 ctx，缺省 getcwd；失败 NULL） */
static const char *ctx_cwd(const occ_tool_ctx *ctx, char *buf, size_t buflen)
{
	if (ctx->workdir && ctx->workdir[0]) {
		snprintf(buf, buflen, "%s", ctx->workdir);
		return buf;
	}
	return getcwd(buf, buflen);
}

/* 路径参数 → 绝对路径（相对按工作目录；存在则 realpath 归一，
 * 不存在则父目录归一 + 基名拼接——write 新文件路径）。
 * b2：主体抽出为 occ_resolve_path（revert.c undo 以 session.workdir
 * 同口径解析历史 toolcall 的 file_path）。 */
int occ_resolve_path(const char *workdir, const char *raw,
		     char *out, size_t outlen)
{
	char trial[4200];

	if (!raw || !raw[0])
		return -1;
	if (raw[0] == '/') {
		snprintf(trial, sizeof(trial), "%s", raw);
	} else {
		if (!workdir || !workdir[0])
			return -1;
		snprintf(trial, sizeof(trial), "%s/%s", workdir, raw);
	}
	if (realpath(trial, out))
		return 0;
	{
		/*
		 * 目标不存在（write 新文件等）：向上找最近的现存祖先
		 * （父目录可多级缺失——write 负责递归建），归一后拼回
		 * 缺失后缀。
		 */
		char parent[4200];
		char rp[4200];
		size_t plen, rlen, slen;
		int up;

		snprintf(parent, sizeof(parent), "%s", trial);
		for (up = 0; up < 64; up++) {
			char *slash = strrchr(parent, '/');

			if (!slash || slash == parent)
				return -1;
			*slash = '\0';
			if (realpath(parent, rp))
				break;
		}
		if (up >= 64)
			return -1;
		plen = strlen(parent);
		rlen = strlen(rp);
		slen = strlen(trial) - plen;	/* 含前导 '/' 的后缀 */
		if (rlen + slen + 1 > outlen)
			return -1;
		memcpy(out, rp, rlen);
		memcpy(out + rlen, trial + plen, slen + 1);
	}
	return 0;
}

static int resolve_arg_path(const occ_tool_ctx *ctx, const char *raw,
			    char *out, size_t outlen)
{
	char cwd[4096];

	if (raw && raw[0] != '/')
		return occ_resolve_path(ctx_cwd(ctx, cwd, sizeof(cwd)), raw,
					out, outlen);
	return occ_resolve_path(NULL, raw, out, outlen);
}

/* ---- read ---- */

static int tool_read(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *path = args_str(a, "path");
	char abs[4096];
	char *data = NULL;
	size_t len = 0;
	long long offset = args_int(a, "offset", 1);
	long long limit = args_int(a, "limit", 500);
	size_t lineno = 0, shown = 0;

	if (!path) {
		occ_ob_puts(o, L_("ERROR: read 缺少参数 path"));
		return -1;
	}
	if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
		occ_ob_printf(o, L_("ERROR: read 路径无法解析：%s"), path);
		return -1;
	}
	if (read_whole(abs, 4 * 1024 * 1024, &data, &len)) {
		if (errno == EFBIG) {
			occ_ob_printf(o, L_("ERROR: read %s 过大（上限 4MB）"), abs);
		} else {
			occ_ob_printf(o, L_("ERROR: read %s 失败：%s"), abs, strerror(errno));
		}
		return -1;
	}
	if (is_binary(data, len)) {
		free(data);
		occ_ob_printf(o, L_("ERROR: read %s 拒绝读取二进制文件（%zu 字节，含 NUL）"), abs, len);
		return -1;
	}
	if (offset < 1)
		offset = 1;
	if (limit < 1)
		limit = 1;
	{
		char *p = data;
		char *end = data + len;

		while (p < end) {
			char *nl = memchr(p, '\n', (size_t)(end - p));
			size_t ll = nl ? (size_t)(nl - p) :
					 (size_t)(end - p);

			lineno++;
			if ((long long)lineno >= offset &&
			    (long long)shown < limit) {
				occ_ob_printf(o, "%6zu\t", lineno);
				occ_ob_put(o, p, ll);
				occ_ob_puts(o, "\n");
				shown++;
			}
			p = nl ? nl + 1 : end;
			if ((long long)shown >= limit)
				break;
		}
	}
	free(data);
	if (!shown && lineno)
		occ_ob_printf(o, L_("（%s 共 %zu 行，offset=%lld 超出范围）"), abs, lineno, offset);
	else if (!shown)
		occ_ob_printf(o, L_("（%s 为空文件）"), abs);
	else
		occ_ob_printf(o, L_("（%s 第 %lld-%zu 行，共 %zu 行）"), abs, offset, offset + shown - 1, lineno);
	return 0;
}

/* ---- write ---- */

static int write_guard(const occ_tool_ctx *ctx, const char *abs, occ_obuf *o)
{
	char cwd[4096];
	const char *cwdp = ctx_cwd(ctx, cwd, sizeof(cwd));

	if (occ_write_target_ok(abs, cwdp ? cwdp : ""))
		return 0;
	/* J-7=A（P-52 刀2·病②「双门」）：本次调用已经 W2 门确认/放行
	 * （w2_confirmed——occ_tool_exec 门后置位，含 --allow-w2 显式
	 * 开门）且特权档——越界写放行；~/.occ 红线不豁免（occ_write_
	 * target_ok 首步已拒，此处复判同口径兜底）。受限档仍走下方
	 * 原样硬拒——W2 门与写域校验自此单门贯通，不再「确认了还拒」。 */
	if (ctx->w2_confirmed && ctx->w2 &&
	    ctx->w2->tier == OCC_W2_TIER_PRIVILEGED &&
	    !occ_abs_under_home_occ(abs))
		return 0;
	occ_ob_printf(o, L_("ERROR: 目标 %s 越界：允许域=工作目录子树 ∪ /tmp ∪ /var/ai ∪ $HOME 子树（W1 惯例；~/.occ 一律拒绝）"), abs);
	return -1;
}

static int tool_write(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *path = args_str(a, "path");
	const char *content = args_str(a, "content");
	char abs[4096];
	char snapbuf[512];
	FILE *f;
	size_t clen;

	if (!path || !content) {
		occ_ob_puts(o, L_("ERROR: write 缺少参数 path/content"));
		return -1;
	}
	if (strlen(content) > 512 * 1024) {
		occ_ob_puts(o, L_("ERROR: write content 过大（上限 512KB）"));
		return -1;
	}
	if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
		occ_ob_printf(o, L_("ERROR: write 路径无法解析：%s"), path);
		return -1;
	}
	if (write_guard(ctx, abs, o))
		return -1;
	/* 快照 stage（原文件不存在 → ABSENT 墓碑；/undo 地基，b2 接） */
	occ_snapshot_stage(ctx->db, ctx->snaproot, ctx->session_id,
			   ctx->msg_id, abs, snapbuf, sizeof(snapbuf));
	/* 父目录递归建 */
	{
		char *slash = strrchr(abs, '/');
		char parent[4096];

		if (slash && slash != abs) {
			size_t pl = (size_t)(slash - abs);

			memcpy(parent, abs, pl);
			parent[pl] = '\0';
			if (mkdirs(parent)) {
				occ_ob_printf(o, L_("ERROR: write 建父目录 %s 失败：%s"), parent, strerror(errno));
				return -1;
			}
		}
	}
	f = fopen(abs, "wb");
	if (!f) {
		occ_ob_printf(o, L_("ERROR: write 打开 %s 失败：%s"), abs, strerror(errno));
		return -1;
	}
	clen = strlen(content);
	if (clen && fwrite(content, 1, clen, f) != clen) {
		fclose(f);
		occ_ob_printf(o, L_("ERROR: write %s 写入失败：%s"), abs, strerror(errno));
		return -1;
	}
	if (fclose(f)) {
		occ_ob_printf(o, L_("ERROR: write %s 关闭失败：%s"), abs, strerror(errno));
		return -1;
	}
	occ_ob_printf(o, L_("已写入 %s（%zu 字节）"), abs, clen);
	return 0;
}

/* ---- edit ---- */

static int tool_edit(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *path = args_str(a, "path");
	const char *olds = args_str(a, "oldString");
	const char *news = args_str(a, "newString");
	int all = args_bool(a, "replaceAll");
	char abs[4096];
	char snapbuf[512];
	char *data = NULL, *out = NULL;
	size_t len = 0, olen, nold, nnew, nocc;
	FILE *f;

	if (!path || !olds || !news) {
		occ_ob_puts(o, L_("ERROR: edit 缺少参数 path/oldString/newString"));
		return -1;
	}
	if (!olds[0]) {
		occ_ob_puts(o, L_("ERROR: edit oldString 为空串（必须给出非空精确文本）"));
		return -1;
	}
	if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
		occ_ob_printf(o, L_("ERROR: edit 路径无法解析：%s"), path);
		return -1;
	}
	if (write_guard(ctx, abs, o))
		return -1;
	if (read_whole(abs, 8 * 1024 * 1024, &data, &len)) {
		if (errno == EFBIG) {
			occ_ob_printf(o, L_("ERROR: edit %s 过大（上限 8MB）"), abs);
		} else {
			occ_ob_printf(o, L_("ERROR: edit 读 %s 失败：%s"), abs, strerror(errno));
		}
		return -1;
	}
	if (is_binary(data, len)) {
		free(data);
		occ_ob_printf(o, L_("ERROR: edit %s 拒绝编辑二进制文件（含 NUL 字节）"), abs);
		return -1;
	}
	nold = strlen(olds);
	nnew = strlen(news);
	nocc = count_occurrences(data, len, olds, nold);
	if (!nocc) {
		free(data);
		occ_ob_printf(o, L_("ERROR: edit %s 未找到 oldString（%zu 字节精确文本，0 次命中）"), abs, nold);
		return -1;
	}
	if (nocc > 1 && !all) {
		free(data);
		occ_ob_printf(o, L_("ERROR: edit %s oldString 命中 %zu 处——需改到唯一片段，或 replaceAll=true"), abs, nocc);
		return -1;
	}
	/* 快照 stage（原文件必然存在——上面 read_whole 已证） */
	occ_snapshot_stage(ctx->db, ctx->snaproot, ctx->session_id,
			   ctx->msg_id, abs, snapbuf, sizeof(snapbuf));

	out = malloc(len + (nnew > nold ? (nnew - nold) * nocc : 0) + 1);
	if (!out) {
		free(data);
		occ_ob_puts(o, L_("ERROR: edit 内存不足"));
		return -1;
	}
	{
		char *dst = out;
		size_t off = 0;

		while (off < len) {
			const char *hit = byte_search(data + off, len - off,
						      olds, nold);

			if (!hit) {
				memcpy(dst, data + off, len - off);
				dst += len - off;
				break;
			}
			memcpy(dst, data + off, (size_t)(hit - data) - off);
			dst += (size_t)(hit - data) - off;
			memcpy(dst, news, nnew);
			dst += nnew;
			off = (size_t)(hit - data) + nold;
			if (!all) {
				memcpy(dst, data + off, len - off);
				dst += len - off;
				break;
			}
		}
		*dst = '\0';
		olen = (size_t)(dst - out);
	}
	f = fopen(abs, "wb");
	if (!f) {
		free(data);
		free(out);
		occ_ob_printf(o, L_("ERROR: edit 打开 %s 失败：%s"), abs, strerror(errno));
		return -1;
	}
	if (olen && fwrite(out, 1, olen, f) != olen) {
		fclose(f);
		free(data);
		free(out);
		occ_ob_printf(o, L_("ERROR: edit %s 写入失败：%s"), abs, strerror(errno));
		return -1;
	}
	if (fclose(f)) {
		free(data);
		free(out);
		occ_ob_printf(o, L_("ERROR: edit %s 关闭失败：%s"), abs, strerror(errno));
		return -1;
	}
	free(data);
	free(out);
	occ_ob_printf(o, L_("已编辑 %s：%zu 处替换（%s），文件 %zu → %zu 字节"), abs, nocc, all ? "replaceAll" : L_("唯一命中"), len, olen);
	return 0;
}

/* ---- O-17：文件管理三件 rm/mv/mkdir（write 同款宿主面） ---- */

static int tool_rm(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *path = args_str(a, "path");
	char abs[4096];
	struct stat st;

	if (!path) {
		occ_ob_puts(o, L_("ERROR: rm 缺少参数 path"));
		return -1;
	}
	if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
		occ_ob_printf(o, L_("ERROR: rm 路径无法解析：%s"), path);
		return -1;
	}
	if (write_guard(ctx, abs, o))
		return -1;
	if (lstat(abs, &st)) {
		occ_ob_printf(o, L_("ERROR: rm %s 不存在：%s"), abs, strerror(errno));
		return -1;
	}
	if (S_ISDIR(st.st_mode)) {
		/* v1 诚实限制：仅空目录（非空报错建议逐个删——不做递归） */
		if (rmdir(abs)) {
			occ_ob_printf(o, L_("ERROR: rm %s 非空目录（v1 仅删普通文件与空目录——请逐个删除后再删目录）"), abs);
			return -1;
		}
		occ_ob_printf(o, L_("已删除空目录 %s"), abs);
		return 0;
	}
	if (!S_ISREG(st.st_mode)) {
		occ_ob_printf(o, L_("ERROR: rm %s 非普通文件（符号链接/设备等 v1 不删）"), abs);
		return -1;
	}
	if (unlink(abs)) {
		occ_ob_printf(o, L_("ERROR: rm %s 删除失败：%s"), abs, strerror(errno));
		return -1;
	}
	occ_ob_printf(o, L_("已删除 %s"), abs);
	return 0;
}

static int tool_mv(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *src = args_str(a, "src");
	const char *dst = args_str(a, "dst");
	char sabs[4096], dabs[4096];
	struct stat st;

	if (!src || !dst) {
		occ_ob_puts(o, L_("ERROR: mv 缺少参数 src/dst"));
		return -1;
	}
	if (resolve_arg_path(ctx, src, sabs, sizeof(sabs))) {
		occ_ob_printf(o, L_("ERROR: mv 源路径无法解析：%s"), src);
		return -1;
	}
	if (resolve_arg_path(ctx, dst, dabs, sizeof(dabs))) {
		occ_ob_printf(o, L_("ERROR: mv 目标路径无法解析：%s"), dst);
		return -1;
	}
	/* mv 两端各查（与 write_guard 同构：域 + w2_confirmed 豁免） */
	if (write_guard(ctx, sabs, o) || write_guard(ctx, dabs, o))
		return -1;
	if (lstat(sabs, &st)) {
		occ_ob_printf(o, L_("ERROR: mv 源 %s 不存在：%s"), sabs, strerror(errno));
		return -1;
	}
	if (!lstat(dabs, &st)) {
		/* v1 诚实限制：不覆盖已有目标（防误覆盖——rename(2) 对
		 * 普通文件会静默覆盖，显式拒绝） */
		occ_ob_printf(o, L_("ERROR: mv 目标 %s 已存在（v1 不覆盖——先 rm 再 mv，或换个名字）"), dabs);
		return -1;
	}
	if (rename(sabs, dabs)) {
		if (errno == EXDEV)
			occ_ob_printf(o, L_("ERROR: mv %s → %s 跨设备（v1 不做 copy+unlink——可 read+write 复制后 rm 原件）"), sabs, dabs);
		else
			occ_ob_printf(o, L_("ERROR: mv %s → %s 失败：%s"), sabs, dabs, strerror(errno));
		return -1;
	}
	occ_ob_printf(o, L_("已移动 %s → %s"), sabs, dabs);
	return 0;
}

static int tool_mkdir(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *path = args_str(a, "path");
	char abs[4096];

	if (!path) {
		occ_ob_puts(o, L_("ERROR: mkdir 缺少参数 path"));
		return -1;
	}
	if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
		occ_ob_printf(o, L_("ERROR: mkdir 路径无法解析：%s"), path);
		return -1;
	}
	if (write_guard(ctx, abs, o))
		return -1;
	/* -p 语义：父目录递归建（mkdirs 幂等——EEXIST 不算错） */
	if (mkdirs(abs)) {
		occ_ob_printf(o, L_("ERROR: mkdir %s 创建失败：%s"), abs, strerror(errno));
		return -1;
	}
	occ_ob_printf(o, L_("已创建目录 %s（已存在则幂等成功）"), abs);
	return 0;
}

/* ---- glob ---- */

#define GLOB_MAX_RESULTS 200
#define GLOB_MAX_DEPTH   24
#define GLOB_MAX_COMPS   32

typedef struct {
	char *comps[GLOB_MAX_COMPS];	/* pattern 组件（strdup） */
	size_t ncomps;
	char *results[GLOB_MAX_RESULTS];
	size_t nresults;
	size_t c0;			/* 起始组件索引（LT-BUG-002 锚定） */
	int overflow;
} glob_walk;

static int glob_match_c(const glob_walk *g, size_t ci, size_t ri,
			char **parts, size_t np)
{
	if (ci == g->ncomps)
		return ri == np;
	if (!strcmp(g->comps[ci], "**")) {
		for (size_t k = ri; k <= np; k++)
			if (glob_match_c(g, ci + 1, k, parts, np))
				return 1;
		return 0;
	}
	if (ri < np && !fnmatch(g->comps[ci], parts[ri], FNM_PERIOD))
		return glob_match_c(g, ci + 1, ri + 1, parts, np);
	return 0;
}

/* 递归走查：parts 为当前相对路径组件（heap 拷贝，防 readdir 缓冲复用） */
static void glob_walk_dir(glob_walk *g, const char *dir, char **parts,
			  size_t np, int depth)
{
	DIR *d = opendir(dir);
	struct dirent *de;

	if (!d)
		return;
	if (depth > GLOB_MAX_DEPTH) {
		closedir(d);
		g->overflow = 1;
		return;
	}
	while ((de = readdir(d)) != NULL) {
		char full[4096];
		char *name = strdup(de->d_name);
		struct stat st;

		if (!name)
			continue;
		if (!strcmp(name, ".") || !strcmp(name, "..")) {
			free(name);
			continue;
		}
		snprintf(full, sizeof(full), "%s/%s", dir, name);
		parts[np] = name;
		if (glob_match_c(g, g->c0, 0, parts, np + 1)) {
			if (g->nresults < GLOB_MAX_RESULTS)
				g->results[g->nresults++] = strdup(full);
			else
				g->overflow = 1;
		}
		if (!stat(full, &st) && S_ISDIR(st.st_mode) &&
		    np + 1 < 60)
			glob_walk_dir(g, full, parts, np + 1, depth + 1);
		free(name);
	}
	closedir(d);
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int tool_glob(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *pattern = args_str(a, "pattern");
	const char *path = args_str(a, "path");
	char root[4096];
	glob_walk g;
	char *parts[64];
	char *pbuf;
	char *save = NULL;
	size_t i;

	if (!pattern || !pattern[0]) {
		occ_ob_puts(o, L_("ERROR: glob 缺少参数 pattern"));
		return -1;
	}
	if (path && path[0]) {
		if (resolve_arg_path(ctx, path, root, sizeof(root))) {
			occ_ob_printf(o, L_("ERROR: glob 根目录无法解析：%s"), path);
			return -1;
		}
	} else if (!ctx_cwd(ctx, root, sizeof(root))) {
		occ_ob_puts(o, L_("ERROR: glob 无法确定工作目录"));
		return -1;
	}
	memset(&g, 0, sizeof(g));
	memset(parts, 0, sizeof(parts));
	pbuf = strdup(pattern);
	if (!pbuf) {
		occ_ob_puts(o, L_("ERROR: glob 内存不足"));
		return -1;
	}
	for (char *tok = strtok_r(pbuf, "/", &save); tok;
	     tok = strtok_r(NULL, "/", &save)) {
		if (g.ncomps < GLOB_MAX_COMPS)
			g.comps[g.ncomps++] = strdup(tok);
	}
	/* LT-BUG-002：绝对模式（/ 开头）以 / 为根——修前绝对前导被
	 * 静默当相对组件（如 /var/log 加星号的绝对模式在工作目录下
	 * 永无匹配，报错文案还误导）。并把连续字面前缀组件锚定为
	 * 起点目录
	 * 下钻：朴素走查无剪枝，/ 起步=全盘遍历；字面前缀只可能在
	 * 同一路径下命中，锚定后绝对/相对语义不变。 */
	{
		size_t ci = 0;
		char anchor[4000];
		struct stat st;

		if (pattern[0] == '/')
			snprintf(root, sizeof(root), "/");
		anchor[0] = '\0';
		while (ci < g.ncomps && !strpbrk(g.comps[ci], "*?[")) {
			size_t cl = strlen(g.comps[ci]);
			size_t al = strlen(anchor);

			if ((al ? al + 1 : 0) + cl + 1 > sizeof(anchor))
				break;
			if (al) {
				anchor[al] = '/';
				anchor[al + 1] = '\0';
			}
			strcat(anchor, g.comps[ci]);
			ci++;
		}
		if (anchor[0]) {
			char full[8200];

			if (!strcmp(root, "/"))
				snprintf(full, sizeof(full), "/%s", anchor);
			else
				snprintf(full, sizeof(full), "%s/%s", root,
					 anchor);
			if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
				if (strlen(full) < sizeof(root))
					strcpy(root, full);
				g.c0 = ci;
			} else if (stat(full, &st) == 0 &&
				   S_ISREG(st.st_mode) && ci == g.ncomps) {
				/* 全字面且目标是文件（如 /etc/hostname）：
				 * 最后组件留给匹配 */
				char *sl = strrchr(full, '/');

				if (sl && sl != full) {
					*sl = '\0';
					if (strlen(full) < sizeof(root))
						strcpy(root, full);
					g.c0 = ci - 1;
				}
			} else {
				/* 字面前缀不存在/非目录（且非全字面文件）：
				 * 必然无匹配——快路空结果 */
				occ_ob_printf(o, L_("（%s 下无匹配 %s 的路径）"), root, pattern);
				for (i = 0; i < g.ncomps; i++)
					free(g.comps[i]);
				free(pbuf);
				return 0;
			}
		}
	}
	glob_walk_dir(&g, root, parts, 0, 0);
	qsort(g.results, g.nresults, sizeof(char *), cmp_str);
	for (i = 0; i < g.nresults; i++) {
		occ_ob_puts(o, g.results[i]);
		occ_ob_puts(o, "\n");
		free(g.results[i]);
	}
	for (i = 0; i < g.ncomps; i++)
		free(g.comps[i]);
	free(pbuf);
	if (!g.nresults)
		occ_ob_printf(o, L_("（%s 下无匹配 %s 的路径）"), root, pattern);
	else
		occ_ob_printf(o, L_("（%zu 项%s）"), g.nresults, g.overflow ? L_("，超 200 上限截断") : "");
	return 0;
}

/* ---- grep ---- */

#define GREP_MAX_LINES 100
#define GREP_FILE_MAX  (4 * 1024 * 1024)

static void grep_file(const char *abs, const char *needle,
		      const char *globf, occ_obuf *o, size_t *hits)
{
	char *data = NULL;
	size_t len = 0;
	const char *base = strrchr(abs, '/');
	size_t nlen = strlen(needle);
	size_t lineno = 0;
	char *p, *end;

	base = base ? base + 1 : abs;
	if (globf && globf[0] && fnmatch(globf, base, FNM_PERIOD) != 0)
		return;
	if (read_whole(abs, GREP_FILE_MAX, &data, &len))
		return;				/* 打不开/过大：跳过 */
	if (is_binary(data, len > 4096 ? 4096 : len)) {
		free(data);
		return;				/* 二进制跳过 */
	}
	p = data;
	end = data + len;
	while (p < end && *hits < GREP_MAX_LINES) {
		char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t ll = nl ? (size_t)(nl - p) : (size_t)(end - p);

		lineno++;
		if (byte_search(p, ll, needle, nlen)) {
			occ_ob_printf(o, "%s:%zu:", abs, lineno);
			occ_ob_put(o, p, ll);
			occ_ob_puts(o, "\n");
			(*hits)++;
		}
		p = nl ? nl + 1 : end;
	}
	free(data);
}

static void grep_walk(const char *dir, const char *needle, const char *globf,
		      occ_obuf *o, size_t *hits, int depth)
{
	DIR *d = opendir(dir);
	struct dirent *de;

	if (!d || depth > GLOB_MAX_DEPTH)
		return;
	while ((de = readdir(d)) != NULL && *hits < GREP_MAX_LINES) {
		char full[4096];
		struct stat st;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
		if (stat(full, &st))
			continue;
		if (S_ISDIR(st.st_mode)) {
			grep_walk(full, needle, globf, o, hits, depth + 1);
		} else if (S_ISREG(st.st_mode)) {
			grep_file(full, needle, globf, o, hits);
		}
	}
	closedir(d);
}

static int tool_grep(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *pattern = args_str(a, "pattern");
	const char *path = args_str(a, "path");
	const char *globf = args_str(a, "glob");
	char abs[4096];
	size_t hits = 0;
	struct stat st;

	if (!pattern || !pattern[0]) {
		occ_ob_puts(o, L_("ERROR: grep 缺少参数 pattern"));
		return -1;
	}
	if (path && path[0]) {
		if (resolve_arg_path(ctx, path, abs, sizeof(abs))) {
			occ_ob_printf(o, L_("ERROR: grep 路径无法解析：%s"), path);
			return -1;
		}
	} else if (!ctx_cwd(ctx, abs, sizeof(abs))) {
		occ_ob_puts(o, L_("ERROR: grep 无法确定工作目录"));
		return -1;
	}
	if (stat(abs, &st)) {
		occ_ob_printf(o, L_("ERROR: grep %s 不存在：%s"), abs, strerror(errno));
		return -1;
	}
	if (S_ISREG(st.st_mode)) {
		grep_file(abs, pattern, globf, o, &hits);
	} else if (S_ISDIR(st.st_mode)) {
		grep_walk(abs, pattern, globf, o, &hits, 0);
	} else {
		occ_ob_printf(o, L_("ERROR: grep %s 非普通文件/目录"), abs);
		return -1;
	}
	if (!hits)
		occ_ob_printf(o, L_("（%s 下未匹配到「%s」）"), abs, pattern);
	else
		occ_ob_printf(o, L_("（%zu 行命中%s）"), hits, hits >= GREP_MAX_LINES ? L_("，达 100 行上限截断") : "");
	return 0;
}

/* ---- bash（底座在 sandbox.c） ---- */

int occ_sandbox_bash(const occ_tool_ctx *ctx, const char *command,
		     const char *workdir, long long timeout_ms, void *obuf);

static int tool_bash(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *command = args_str(a, "command");
	const char *workdir = args_str(a, "workdir");
	long long timeout_s = args_int(a, "timeout", 0);
	occ_obuf raw;
	char *clean;
	size_t n;
	int rc;

	if (!command || !command[0]) {
		occ_ob_puts(o, L_("ERROR: bash 缺少参数 command"));
		return -1;
	}
	memset(&raw, 0, sizeof(raw));
	rc = occ_sandbox_bash(ctx, command, workdir,
			      timeout_s > 0 ? timeout_s * 1000 : 0, &raw);
	/*
	 * E10②a 源端净化：沙箱原始输出可能含非法 UTF-8 字节（实战
	 * 毒化链：bash tail -c 咬出坏字节 → 工具结果入库回放 → 请求
	 * 体非法 UTF-8 → 服务端 400 → 主会话死）。进结果缓冲前把每个
	 * 非法字节替换为 U+FFFD；合法输出逐字节零变化。oom 时原样
	 * 尽力（净化不因分配失败阻断工具结果）。
	 */
	clean = malloc(sizeof(raw.buf) * 3);	/* 最坏 1B→3B（FFFD） */
	if (clean) {
		n = occ_utf8_sanitize(raw.buf, raw.len, clean,
				      sizeof(raw.buf) * 3);
		occ_ob_put(o, clean, n);
		free(clean);
	} else {
		occ_ob_put(o, raw.buf, raw.len);
	}
	if (raw.truncated)
		o->truncated = 1;
	o->total = raw.total;	/* 产物量按净化前原始字节记账 */
	return rc;
}

/* ---- task（E3 第七工具；R1=工具层。ORCH-DESIGN §3 派发协议） ---- */

/* E10⑧：wait 限时上限（真模型子会话常超 30s——上调 120s；缺省仍
 * 2000ms，schema minimum 100 同步描述） */
#define OCC_TASK_WAIT_MAX_MS	120000LL

/* 动态字符串（prompt 渲染——任务书全文可超 obuf 8KB 截断域） */
struct sbuf {
	char *buf;
	size_t len, cap;
	int oom;
};

static void sb_putn(struct sbuf *b, const char *s, size_t n)
{
	if (b->oom || !n)
		return;
	if (b->len + n + 1 > b->cap) {
		size_t nc = b->cap ? b->cap : 512;
		char *nb;

		while (b->len + n + 1 > nc)
			nc *= 2;
		nb = realloc(b->buf, nc);
		if (!nb) {
			b->oom = 1;
			return;
		}
		b->buf = nb;
		b->cap = nc;
	}
	memcpy(b->buf + b->len, s, n);
	b->len += n;
	b->buf[b->len] = '\0';
}

static void sb_puts(struct sbuf *b, const char *s)
{
	sb_putn(b, s, strlen(s));
}

static void sb_printf(struct sbuf *b, const char *fmt, ...)
{
	char tmp[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	sb_puts(b, tmp);
}

static void sb_free(struct sbuf *b)
{
	free(b->buf);
	memset(b, 0, sizeof(*b));
}

/* 文件头窗读取（read_result 报告摘要；失败 NULL） */
static char *read_file_head(const char *path, size_t max)
{
	int fd;
	char *buf;
	ssize_t got;

	if (!path || !path[0])
		return NULL;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;
	buf = malloc(max + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}
	got = read(fd, buf, max);
	close(fd);
	if (got < 0) {
		free(buf);
		return NULL;
	}
	/* UTF-8 边界回退（不切多字节） */
	while (got > 0 && ((unsigned char)buf[got] & 0xC0) == 0x80)
		got--;
	buf[got] = '\0';
	return buf;
}

/* aik_json 构造 → 紧凑 dump → obuf（工具返回一律结构化 JSON 文本）。
 * 文本成功写出返回 0；oom → -1（降级人话错误）。 */
static int jout(occ_obuf *o, aik_json *obj)
{
	char *txt = NULL;
	size_t tl = 0;
	int rc = aik_json_dump(obj, &txt, &tl);

	if (rc != 0 || !txt) {
		free(txt);
		occ_ob_puts(o, L_("ERROR: task 结果 JSON 序列化失败（oom）"));
		return -1;
	}
	occ_ob_put(o, txt, tl);
	free(txt);
	return 0;
}

/* ---- E7：预算记账消费点（task 工具 status/read_result 的 budget 段；
 *      显示参考，不精确计费——§10 风险 6「定价仅显示参考」） ---- */

/*
 * task_catalog - 目录快照惰性一次（进程生命期；搜索链与 occ.c
 * app_load_catalog 同源复制——OCC_CATALOG env → cwd →
 * /proc/self/exe 同目录 → 系统安装位。失败保持零值目录=无定价面，
 * 查询自然未命中降级「pricing unavailable」，绝不阻断工具返回）。
 * 只读消费，无写面；不上 free（进程退出回收，同 occ.c cat 生命期）。
 */
static occ_catalog *task_catalog(void)
{
	static occ_catalog cat;
	static int tried;
	char path[1100], exed[1024];
	const char *env;
	ssize_t n;

	if (tried)
		return &cat;
	tried = 1;
	env = getenv("OCC_CATALOG");
	if (env && env[0] && occ_catalog_load(&cat, env) == 0)
		return &cat;
	if (occ_catalog_load(&cat, "models.dev.snapshot.json") == 0)
		return &cat;
	n = readlink("/proc/self/exe", exed, sizeof(exed) - 1);
	if (n > 0) {
		char *slash;

		exed[n] = '\0';
		slash = strrchr(exed, '/');
		if (slash) {
			snprintf(path, sizeof(path),
				 "%s/models.dev.snapshot.json", exed);
			if (occ_catalog_load(&cat, path) == 0)
				return &cat;
		}
	}
	if (occ_catalog_load(
		    &cat,
		    "/usr/local/share/aikernel/models.dev.snapshot.json") == 0)
		return &cat;
	return &cat;		/* 零值目录（nmodels=0）=无定价面 */
}

/*
 * budget_json - budget 段组装（heap JSON obj；oom NULL——调用方降级
 * 略段不炸整体返回）。金额算式（occ_catalog_cost_usd 同式）：
 *
 *   cost_usd_ref = tokens_in × in_per_m / 1e6 + tokens_out × out_per_m / 1e6
 *
 * （单价=catalog 定价四字段 in/out 两档，单位 美元/1M token；
 *   cache_read/write 另档不并入——与 occ_tokens total=in+out 口径
 *   一致）。模型名取子会话 model 列（烧 token 的那一端）；目录未
 *   装载/未命中/子会话缺 → pricing="unavailable"（tokens 仍如实）。
 */
static aik_json *budget_json(occ_db *db, const occ_task_row *trow)
{
	aik_json *b;
	double ipm = 0.0, opm = 0.0;
	char model[96];
	int priced = 0;

	if (!trow)
		return NULL;
	model[0] = '\0';
	if (trow->child_session[0]) {
		occ_session_row srow;

		if (occ_session_get(db, trow->child_session, &srow, NULL,
				    0) == 1)
			snprintf(model, sizeof(model), "%s", srow.model);
	}
	if (model[0])
		priced = occ_catalog_price(task_catalog(), model,
					   &ipm, &opm) == 1;
	b = aik_json_new_obj();
	if (!b)
		return NULL;
	if (aik_json_obj_put(b, "tokens_in",
			     aik_json_new_int(trow->budget_in)) ||
	    aik_json_obj_put(b, "tokens_out",
			     aik_json_new_int(trow->budget_out)) ||
	    aik_json_obj_put(b, "tokens_total", aik_json_new_int(
				     trow->budget_in + trow->budget_out))) {
		aik_json_free(b);
		return NULL;
	}
	if (priced) {
		char cbuf[48];

		/* 量×单价/1M（算式见函数头注；%.6f 美元——显示参考） */
		snprintf(cbuf, sizeof(cbuf), "%.6f",
			 occ_catalog_cost_usd(ipm, opm, trow->budget_in,
					      trow->budget_out));
		if (aik_json_obj_put(b, "model", aik_json_new_str(model)) ||
		    aik_json_obj_put(b, "unit",
				     aik_json_new_str("USD/1M")) ||
		    aik_json_obj_put(b, "in_per_m",
				     aik_json_new_num(ipm)) ||
		    aik_json_obj_put(b, "out_per_m",
				     aik_json_new_num(opm)) ||
		    aik_json_obj_put(b, "cost_usd_ref",
				     aik_json_new_str(cbuf))) {
			aik_json_free(b);
			return NULL;
		}
	} else {
		if (aik_json_obj_put(b, "pricing", aik_json_new_str(
					     "unavailable"))) {
			aik_json_free(b);
			return NULL;
		}
	}
	return b;
}

/* budget 段挂入（oom 降级略段——budget 是显示参考，不炸整体返回） */
static void budget_put(aik_json *obj, occ_db *db, const occ_task_row *trow)
{
	aik_json *bj = budget_json(db, trow);

	if (bj && aik_json_obj_put(obj, "budget", bj) != 0)
		aik_json_free(bj);	/* 未挂入（或挂失败）才独释 */
}

/* 错误 JSON：{"ok":false,"error":…[,"code":…]}；文本写出成功也返回
 * -1——错误响应=工具失败（occ_tool_result.rc=1，trace 口径）。 */
static int jerr(occ_obuf *o, const char *code, const char *fmt, ...)
{
	char msg[512];
	va_list ap;
	aik_json *obj, *s;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	obj = aik_json_new_obj();
	s = aik_json_new_str(msg);
	if (!obj || !s || aik_json_obj_put(obj, "ok",
					   aik_json_new_bool(0)) ||
	    aik_json_obj_put(obj, "error", s)) {
		aik_json_free(obj);
		aik_json_free(s);
		occ_ob_printf(o, L_("ERROR: task %s"), msg);
		return -1;
	}
	if (code && code[0] &&
	    aik_json_obj_put(obj, "code", aik_json_new_str(code))) {
		aik_json_free(obj);
		occ_ob_printf(o, L_("ERROR: task %s"), msg);
		return -1;
	}
	(void)jout(o, obj);
	aik_json_free(obj);
	return -1;
}

static void str_arr_free(char **v, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

/* spawn 错误码 → JSON code 串 */
static const char *spawn_code(int rc)
{
	switch (rc) {
	case OCC_ORCH_ELIMIT:		return "ELIMIT";
	case OCC_ORCH_EBACKOFF:		return "EBACKOFF";
	case OCC_ORCH_EFILESET:		return "EFILESET";
	case OCC_ORCH_ESPAWN:		return "ESPAWN";
	case OCC_ORCH_EDB:		return "EDB";
	case OCC_ORCH_EARGS:		return "EARGS";
	default:			return "EORCH";
	}
}

/* heap 字符串数组 → JSON 数组（brief 列表字段组装） */
static aik_json *arr_from_vec(char **v, size_t n)
{
	aik_json *arr = aik_json_new_arr();
	size_t i;

	if (!arr)
		return NULL;
	for (i = 0; i < n; i++) {
		if (aik_json_arr_push(arr, aik_json_new_str(v[i]))) {
			aik_json_free(arr);
			return NULL;
		}
	}
	return arr;
}

/* ---- task 动作体 ---- */

/* brief 列表字段（fileset 之外的四个可选清单）取值+任务书渲染共用 */
static int brief_list(const aik_json *brief, const char *key, char ***out,
		      size_t *n, const char *label, occ_obuf *o)
{
	const aik_json *arr = aik_json_get(brief, key);
	size_t i, cnt;
	char **vec;

	*out = NULL;
	*n = 0;
	if (!arr)
		return 0;			/* 缺省=无该清单 */
	if (aik_json_typeof(arr) != AIK_JSON_ARR)
		return jerr(o, NULL, L_("brief.%s 须为字符串数组"), label);
	cnt = 0;
	while (aik_json_at(arr, cnt))
		cnt++;
	vec = calloc(cnt ? cnt : 1, sizeof(*vec));
	if (!vec)
		return jerr(o, NULL, L_("内存不足（brief.%s 解析）"), label);
	for (i = 0; i < cnt; i++) {
		const char *s = aik_json_str(aik_json_at(arr, i));

		if (!s) {
			str_arr_free(vec, i);
			return jerr(o, NULL, L_("brief.%s 元素须为字符串"), label);
		}
		vec[i] = strdup(s);
		if (!vec[i]) {
			str_arr_free(vec, i);
			return jerr(o, NULL, L_("内存不足（brief.%s 解析）"), label);
		}
	}
	*out = vec;
	*n = cnt;
	return 0;
}

/* 列表 → 任务书渲染（行式） */
static void sb_list(struct sbuf *b, char **v, size_t n, const char *empty)
{
	size_t i;

	if (!n) {
		sb_puts(b, empty);
		return;
	}
	for (i = 0; i < n; i++)
		sb_printf(b, " %zu. %s\n", i + 1, v[i]);
}

/* task_spawn 中间产物统一清理（fs 只清前 n_have 个——半构状态安全） */
static void spawn_cleanup(char **forb, size_t nforb, char **deliv,
			  size_t ndeliv, char **acc, size_t nacc,
			  char **selfc, size_t nselfc, char **fs, size_t nfs,
			  char *budget_txt, char *brief_txt)
{
	str_arr_free(forb, nforb);
	str_arr_free(deliv, ndeliv);
	str_arr_free(acc, nacc);
	str_arr_free(selfc, nselfc);
	str_arr_free(fs, nfs);
	free(budget_txt);
	free(brief_txt);
}

/*
 * task_respawn - E10④：spawn+task_id 工具面再派（回炉腿）。任务须
 * 处 rework 态（其余态人话拒——含 in_review/done/escalated/pending/
 * dispatched）；走既有 occ_orch_spawn(task_id) C 路（rework→
 * dispatched 状态机 + 新子会话 + 预算熔断检查点全继承）。prompt=
 * 「回炉再派」头 + 可选本轮补充 brief + 原任务书（brief_json——
 * E10⑥ 起含 # VERDICT 报告格式要求）。brief 给了须为对象（内容
 * 不再强制 goal/fileset——回炉的授权面沿原任务）。
 */
static int task_respawn(const occ_tool_ctx *ctx, occ_args *a,
			const char *tid, occ_obuf *o)
{
	const aik_json *brief;
	occ_task_row trow;
	struct sbuf prompt = { NULL, 0, 0, 0 };
	occ_orch_spawn_opts so;
	occ_orch_child *c = NULL;
	char err[256], dbuf[256], stbuf[24];
	char *brief_txt = NULL;
	size_t bl;
	int rc;

	if (occ_task_get(ctx->db, tid, &trow, dbuf, sizeof(dbuf)) != 1)
		return jerr(o, NULL, L_("再派任务 %s 不存在（任务库无此 id）"), tid);
	snprintf(stbuf, sizeof(stbuf), "%s", trow.status);
	if (strcmp(trow.status, OCC_TASK_ST_REWORK)) {
		occ_task_row_free(&trow);
		return jerr(o, NULL, L_("spawn+task_id 仅对 rework（验收不通过待回炉）态任务再派——任务 %s 当前态 %s：新建任务请不带 task_id，终局任务用 read_result/return"), tid, stbuf);
	}
	brief = a->root ? aik_json_get(a->root, "brief") : NULL;
	if (brief && aik_json_typeof(brief) != AIK_JSON_OBJ) {
		occ_task_row_free(&trow);
		return jerr(o, NULL, L_("再派参数 brief 须为对象（本轮补充要求；可省略=按原任务书重派）"));
	}
	if (brief && aik_json_dump(brief, &brief_txt, &bl) != 0)
		brief_txt = NULL;
	sb_puts(&prompt, "【回炉再派（上一轮验收不通过——按整改要求修复）】\n");
	if (brief_txt && brief_txt[0])
		sb_printf(&prompt, "本轮补充要求（brief）：%s\n", brief_txt);
	sb_printf(&prompt, "原任务书：\n%s\n",
		  trow.brief_json ? trow.brief_json : "(无)");
	occ_task_row_free(&trow);
	if (prompt.oom) {
		sb_free(&prompt);
		free(brief_txt);
		return jerr(o, NULL, L_("task spawn 再派任务书组装失败（oom）"));
	}
	memset(&so, 0, sizeof(so));
	so.prompt = prompt.buf;
	so.task_id = tid;		/* rework 再派：任务面复用 */
	so.workdir = ctx->workdir;
	rc = occ_orch_spawn((occ_orch *)ctx->orch, &so, &c, err, sizeof(err));
	sb_free(&prompt);
	free(brief_txt);
	if (rc != OCC_ORCH_OK)
		return jerr(o, spawn_code(rc), "%s", err);
	{
		aik_json *robj = aik_json_new_obj();
		int okk = robj &&
			  aik_json_obj_put(robj, "ok",
					   aik_json_new_bool(1)) == 0 &&
			  aik_json_obj_put(robj, "action",
					   aik_json_new_str("spawn")) == 0 &&
			  aik_json_obj_put(robj, "respawn",
					   aik_json_new_bool(1)) == 0 &&
			  aik_json_obj_put(robj, "task_id",
					   aik_json_new_str(tid)) == 0 &&
			  aik_json_obj_put(robj, "session_id",
					   aik_json_new_str(
						occ_orch_child_session(c))) == 0 &&
			  aik_json_obj_put(robj, "pid",
					   aik_json_new_int(
						occ_orch_child_pid(c))) == 0 &&
			  aik_json_obj_put(robj, "result_file",
					   aik_json_new_str(
						occ_orch_result_path(
						(occ_orch *)ctx->orch,
						tid))) == 0;
		int r2 = okk ? jout(o, robj) : -1;

		if (!okk)
			occ_ob_puts(o, L_("ERROR: task spawn 再派结果组装失败（oom）"));
		aik_json_free(robj);
		return okk ? r2 : -1;
	}
}

static int task_spawn(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const aik_json *brief, *fsj, *budget;
	const char *goal, *auth_note, *context, *s;
	char *budget_txt = NULL, *brief_txt = NULL;
	char **forb = NULL, **deliv = NULL, **acc = NULL, **selfc = NULL;
	char **fs_abs = NULL;
	size_t nfs = 0, nforb = 0, ndeliv = 0, nacc = 0, nselfc = 0;
	size_t i, bl;
	aik_json *bo, *sub;
	struct sbuf prompt = { NULL, 0, 0, 0 };
	occ_orch_spawn_opts so;
	occ_orch_child *c = NULL;
	char err[256], abs[4096];
	long long rework_max = 2, wall_ms = 0, max_tokens = 0;
	int rc;
	const char *rtid = args_str(a, "task_id");

	/* E10④：spawn+task_id=对回炉任务再派（独立路——原 spawn 新建
	 * 路零变化）；未带 task_id 走下方原路 */
	if (rtid && rtid[0]) {
		if (!ctx->session_id || !ctx->session_id[0])
			return jerr(o, NULL, L_("task spawn 需要会话上下文（任务要挂在主会话名下——当前工具执行无 session）"));
		if (!ctx->orch)
			return jerr(o, NULL, L_("编排未启用（occ_tool_ctx.orch 为空或 OCC_ORCH_TOOLS 未开）——task 工具不可用"));
		if (!ctx->db)
			return jerr(o, NULL, L_("编排未启用（库缺失）——task 工具不可用"));
		return task_respawn(ctx, a, rtid, o);
	}
	brief = a->root ? aik_json_get(a->root, "brief") : NULL;
	if (!brief || aik_json_typeof(brief) != AIK_JSON_OBJ)
		return jerr(o, NULL, L_("spawn 缺少参数 brief（任务书对象——字段集：goal/fileset/forbidden/deliverables/acceptance/selfcheck/auth_note/budget/context/rework_max）"));
	goal = aik_json_str(aik_json_get(brief, "goal"));
	if (!goal || !goal[0])
		return jerr(o, NULL, L_("brief.goal 必填（目标一句话）"));
	fsj = aik_json_get(brief, "fileset");
	if (!fsj || aik_json_typeof(fsj) != AIK_JSON_ARR)
		return jerr(o, NULL, L_("brief.fileset 必填（授权文件集数组——独占声明，互斥依据）"));
	while (aik_json_at(fsj, nfs))
		nfs++;
	if (!nfs)
		return jerr(o, NULL, L_("brief.fileset 不能为空数组（独占声明至少一个文件）"));
	auth_note = aik_json_str(aik_json_get(brief, "auth_note"));
	context = aik_json_str(aik_json_get(brief, "context"));
	rework_max = aik_json_int(aik_json_get(brief, "rework_max"));
	if (rework_max == 0)
		rework_max = OCC_TASK_REWORK_MAX_DEF;	/* R2 缺省 2 */
	if (rework_max < 1 || rework_max > OCC_TASK_REWORK_MAX_HI)
		return jerr(o, NULL, L_("brief.rework_max 越界（1-%d；缺省 %d）"), OCC_TASK_REWORK_MAX_HI, OCC_TASK_REWORK_MAX_DEF);
	budget = aik_json_get(brief, "budget");
	if (budget) {
		if (aik_json_typeof(budget) == AIK_JSON_OBJ) {
			wall_ms = aik_json_int(aik_json_get(budget,
							    "wall_ms"));
			/* E7：token 预算上限（budget_in+out 累计超限熔断） */
			max_tokens = aik_json_int(aik_json_get(budget,
							       "max_tokens"));
			if (aik_json_dump(budget, &budget_txt, &bl) != 0)
				budget_txt = NULL;
		} else {
			wall_ms = aik_json_int(budget);
		}
		if (wall_ms < 0)
			wall_ms = 0;
		if (max_tokens < 0)
			max_tokens = 0;
	}
	/* 可选清单（错误即返——人话指出字段） */
	rc = brief_list(brief, "forbidden", &forb, &nforb, "forbidden", o);
	if (!rc)
		rc = brief_list(brief, "deliverables", &deliv, &ndeliv,
				"deliverables", o);
	if (!rc)
		rc = brief_list(brief, "acceptance", &acc, &nacc,
				"acceptance", o);
	if (!rc)
		rc = brief_list(brief, "selfcheck", &selfc, &nselfc,
				"selfcheck", o);
	if (rc) {
		spawn_cleanup(forb, nforb, deliv, ndeliv, acc, nacc,
			      selfc, nselfc, NULL, 0, budget_txt, NULL);
		return -1;
	}
	/* 环境检查（参数校验后置——模型先拿到具体的参数错误） */
	if (!ctx->session_id || !ctx->session_id[0]) {
		spawn_cleanup(forb, nforb, deliv, ndeliv, acc, nacc,
			      selfc, nselfc, NULL, 0, budget_txt, NULL);
		return jerr(o, NULL, L_("task spawn 需要会话上下文（任务要挂在主会话名下——当前工具执行无 session）"));
	}
	if (!ctx->orch) {
		spawn_cleanup(forb, nforb, deliv, ndeliv, acc, nacc,
			      selfc, nselfc, NULL, 0, budget_txt, NULL);
		return jerr(o, NULL, L_("编排未启用（occ_tool_ctx.orch 为空或 OCC_ORCH_TOOLS 未开）——task 工具不可用"));
	}
	/* fileset 归一化（相对路径按工作目录→绝对；互斥登记按归一键） */
	fs_abs = calloc(nfs, sizeof(*fs_abs));
	if (!fs_abs) {
		spawn_cleanup(forb, nforb, deliv, ndeliv, acc, nacc,
			      selfc, nselfc, NULL, 0, budget_txt, NULL);
		return jerr(o, NULL, L_("内存不足（fileset 解析）"));
	}
	for (i = 0; i < nfs; i++) {
		s = aik_json_str(aik_json_at(fsj, i));
		if (!s || !s[0] || resolve_arg_path(ctx, s, abs,
						    sizeof(abs))) {
			spawn_cleanup(forb, nforb, deliv, ndeliv, acc, nacc,
				      selfc, nselfc, fs_abs, i, budget_txt,
				      NULL);
			return jerr(o, NULL, L_("brief.fileset[%zu] 路径无法解析：%.120s"), i, s ? s : L_("(空)"));
		}
		fs_abs[i] = strdup(abs);
		if (!fs_abs[i]) {
			spawn_cleanup(forb, nforb, deliv, ndeliv, acc, nacc,
				      selfc, nselfc, fs_abs, i, budget_txt,
				      NULL);
			return jerr(o, NULL, L_("内存不足（fileset 拷贝）"));
		}
	}

	/* brief_json 组装（§3 拍板字段集，键序=字面序；UTF-8 JSON） */
	bo = aik_json_new_obj();
	if (!bo)
		goto oom;
	if (aik_json_obj_put(bo, "goal", aik_json_new_str(goal)))
		goto oom;
	sub = arr_from_vec(fs_abs, nfs);
	if (!sub || aik_json_obj_put(bo, "fileset", sub)) {
		aik_json_free(sub);
		goto oom;
	}
	sub = arr_from_vec(forb, nforb);
	if (!sub || aik_json_obj_put(bo, "forbidden", sub)) {
		aik_json_free(sub);
		goto oom;
	}
	sub = arr_from_vec(deliv, ndeliv);
	if (!sub || aik_json_obj_put(bo, "deliverables", sub)) {
		aik_json_free(sub);
		goto oom;
	}
	sub = arr_from_vec(acc, nacc);
	if (!sub || aik_json_obj_put(bo, "acceptance", sub)) {
		aik_json_free(sub);
		goto oom;
	}
	sub = arr_from_vec(selfc, nselfc);
	if (!sub || aik_json_obj_put(bo, "selfcheck", sub)) {
		aik_json_free(sub);
		goto oom;
	}
	if ((auth_note && aik_json_obj_put(bo, "auth_note",
					   aik_json_new_str(auth_note))) ||
	    (budget_txt && aik_json_obj_put(bo, "budget",
					    aik_json_new_str(budget_txt))) ||
	    (context && aik_json_obj_put(bo, "context",
					 aik_json_new_str(context))) ||
	    aik_json_obj_put(bo, "rework_max",
			     aik_json_new_int(rework_max)))
		goto oom;
	if (aik_json_dump(bo, &brief_txt, &bl) != 0)
		goto oom;
	aik_json_free(bo);
	bo = NULL;

	/* 任务书渲染（发给 `occ -p` 的指令文本；子进程另经
	 * OCC_TASK_RESULT_FILE 收报告） */
	sb_puts(&prompt, "【子智能体任务书（brief）】\n");
	sb_printf(&prompt, "目标：%s\n", goal);
	sb_puts(&prompt, "授权文件集（独占声明，只许改这些文件）：\n");
	for (i = 0; i < nfs; i++)
		sb_printf(&prompt, " %zu. %s\n", i + 1, fs_abs[i]);
	sb_puts(&prompt, "禁改清单：\n");
	sb_list(&prompt, forb, nforb, "（无）\n");
	sb_puts(&prompt, "交付物：\n");
	sb_list(&prompt, deliv, ndeliv, "（见验收标准）\n");
	sb_puts(&prompt, "验收标准：\n");
	sb_list(&prompt, acc, nacc, "（见目标与交付物）\n");
	sb_puts(&prompt, "自检清单（完成前逐条自查）：\n");
	sb_list(&prompt, selfc, nselfc, "（无）\n");
	if (auth_note && auth_note[0])
		sb_printf(&prompt, "授权说明：%s\n", auth_note);
	if (wall_ms > 0 || max_tokens > 0) {
		sb_puts(&prompt, "预算：");
		if (wall_ms > 0)
			sb_printf(&prompt, "墙钟上限 %lld ms", wall_ms);
		if (wall_ms > 0 && max_tokens > 0)
			sb_puts(&prompt, "；");
		if (max_tokens > 0)
			sb_printf(&prompt, "token 上限 %lld"
				  "（累计输入+输出超限即熔断取消）",
				  max_tokens);
		sb_puts(&prompt, "\n");
	}
	if (context && context[0])
		sb_printf(&prompt, "必要上下文：%s\n", context);
	sb_printf(&prompt, "回炉上限：%lld 次\n", rework_max);
	sb_puts(&prompt, "报告要求：完成后把最终报告写入环境变量 "
		OCC_ORCH_RESULT_ENV " 指向的文件，并在标准输出打印一行完成"
		"摘要。报告须含 # VERDICT 表（| criterion | result | "
		"evidence | self | 固定表头，逐条验收标准一行，result="
		"pass/fail，evidence 用 file:/md5:/contains:/exit: 机检令牌"
		"——验收环逐条机检，无表或自由文本证据不采信）。\n");
	if (prompt.oom) {
		sb_free(&prompt);
		goto oom_soft;
	}
	sb_printf(&prompt, "——brief_json 原文（机器可读）：%s\n",
		  brief_txt ? brief_txt : "{}");

	/* 派发（走 orch 闸：并发 2+退避+文件集互斥） */
	memset(&so, 0, sizeof(so));
	so.prompt = prompt.buf;
	so.parent_session = ctx->session_id;
	so.title = goal;
	so.fileset = (const char *const *)fs_abs;
	so.nfileset = nfs;
	so.timeout_ms = wall_ms;
	so.workdir = ctx->workdir;
	so.rework_max = (int)rework_max;	/* R1：brief 覆写透传（缺省
						 * 2 亦显式传——occ_task
						 * 行与 brief_json 恒一致） */
	so.max_tokens = max_tokens;	/* E7：预算熔断（0=不设限） */
	rc = occ_orch_spawn((occ_orch *)ctx->orch, &so, &c, err, sizeof(err));
	sb_free(&prompt);
	if (rc != OCC_ORCH_OK) {
		spawn_cleanup(forb, nforb, deliv, ndeliv, acc, nacc,
			      selfc, nselfc, fs_abs, nfs, budget_txt,
			      brief_txt);
		return jerr(o, spawn_code(rc), "%s", err);
	}
	/* 成功输出（robj/rf：fileset 数组最后挂入——失败面无双 free） */
	{
		aik_json *robj = aik_json_new_obj();
		aik_json *rf = aik_json_new_arr();
		int okk = robj && rf;

		for (i = 0; okk && i < nfs; i++)
			okk = aik_json_arr_push(rf,
						aik_json_new_str(fs_abs[i])) == 0;
		okk = okk &&
		      aik_json_obj_put(robj, "ok",
				       aik_json_new_bool(1)) == 0 &&
		      aik_json_obj_put(robj, "action",
				       aik_json_new_str("spawn")) == 0 &&
		      aik_json_obj_put(robj, "task_id", aik_json_new_str(
				occ_orch_child_task(c))) == 0 &&
		      aik_json_obj_put(robj, "session_id", aik_json_new_str(
				occ_orch_child_session(c))) == 0 &&
		      aik_json_obj_put(robj, "pid", aik_json_new_int(
				occ_orch_child_pid(c))) == 0 &&
		      aik_json_obj_put(robj, "result_file",
				       aik_json_new_str(occ_orch_result_path(
					(occ_orch *)ctx->orch,
					occ_orch_child_task(c)))) == 0 &&
		      aik_json_obj_put(robj, "rework_max",
				       aik_json_new_int(rework_max)) == 0;
		if (okk && max_tokens > 0)	/* E7：预算上限回显（缺省略） */
			okk = aik_json_obj_put(robj, "max_tokens",
					       aik_json_new_int(max_tokens)) == 0;
		if (!okk || aik_json_obj_put(robj, "fileset", rf) != 0) {
			aik_json_free(rf);	/* 未挂入（或挂失败）才独释 */
			aik_json_free(robj);
			goto oom_soft;
		}
		{
			int r2 = jout(o, robj);

			aik_json_free(robj);
			spawn_cleanup(forb, nforb, deliv, ndeliv, acc, nacc,
				      selfc, nselfc, fs_abs, nfs, budget_txt,
				      brief_txt);
			return r2;
		}
	}
oom:
	if (bo)
		aik_json_free(bo);
	sb_free(&prompt);
oom_soft:
	spawn_cleanup(forb, nforb, deliv, ndeliv, acc, nacc, selfc, nselfc,
		      fs_abs, nfs, budget_txt, brief_txt);
	return jerr(o, NULL, L_("task spawn 组装失败（oom）"));
}

static int task_status(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *tid = args_str(a, "task_id");
	occ_orch_child *c;
	occ_task_row trow;
	char dbuf[256];
	aik_json *obj;

	if (!tid || !tid[0])
		return jerr(o, NULL, L_("status 缺少参数 task_id"));
	if (!ctx->orch || !ctx->db)
		return jerr(o, NULL, L_("编排未启用（orch 运行时/库缺失）——task 工具不可用"));
	c = occ_orch_find_task((occ_orch *)ctx->orch, tid);
	if (c) {
		obj = aik_json_new_obj();
		if (!obj || aik_json_obj_put(obj, "ok",
					     aik_json_new_bool(1)) ||
		    aik_json_obj_put(obj, "action",
				     aik_json_new_str("status")) ||
		    aik_json_obj_put(obj, "task_id", aik_json_new_str(tid)) ||
		    aik_json_obj_put(obj, "state",
				     aik_json_new_str("running")) ||
		    aik_json_obj_put(obj, "pid",
				     aik_json_new_int(occ_orch_child_pid(c))) ||
		    aik_json_obj_put(obj, "session_id",
				     aik_json_new_str(occ_orch_child_session(c)))) {
			aik_json_free(obj);
			return jerr(o, NULL, L_("status 结果组装失败（oom）"));
		}
		/* E7：budget 段（活表路也带账面——在跑期间为最近落账值） */
		if (occ_task_get(ctx->db, tid, &trow, NULL, 0) == 1) {
			budget_put(obj, ctx->db, &trow);
			occ_task_row_free(&trow);
		}
		{
			int r = jout(o, obj);

			aik_json_free(obj);
			return r;
		}
	}
	{
		int g = occ_task_get(ctx->db, tid, &trow, dbuf, sizeof(dbuf));

		if (g != 1) {
			return jerr(o, NULL, L_("任务 %s 不存在（活表与任务库均无）"), tid);
		}
		obj = aik_json_new_obj();
		if (!obj || aik_json_obj_put(obj, "ok", aik_json_new_bool(1)) ||
		    aik_json_obj_put(obj, "action",
				     aik_json_new_str("status")) ||
		    aik_json_obj_put(obj, "task_id", aik_json_new_str(tid)) ||
		    aik_json_obj_put(obj, "state",
				     aik_json_new_str(trow.status)) ||
		    aik_json_obj_put(obj, "child_session",
				     aik_json_new_str(trow.child_session)) ||
		    aik_json_obj_put(obj, "rework_count",
				     aik_json_new_int(trow.rework_count)) ||
		    aik_json_obj_put(obj, "rework_max",
				     aik_json_new_int(trow.rework_max))) {
			occ_task_row_free(&trow);
			aik_json_free(obj);
			return jerr(o, NULL, L_("status 结果组装失败（oom）"));
		}
		budget_put(obj, ctx->db, &trow);	/* E7：budget 段 */
		{
			int r = jout(o, obj);

			aik_json_free(obj);
			occ_task_row_free(&trow);
			return r;
		}
	}
}

static int task_wait(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *tid = args_str(a, "task_id");
	long long tmo = args_int(a, "timeout_ms", 2000);
	long long t0, elapsed;
	occ_orch_child *c;
	occ_orch_result r;
	occ_task_row trow;
	char dbuf[256];
	aik_json *obj;

	if (!tid || !tid[0])
		return jerr(o, NULL, L_("wait 缺少参数 task_id"));
	if (tmo < 100)
		tmo = 100;
	if (tmo > OCC_TASK_WAIT_MAX_MS)
		tmo = OCC_TASK_WAIT_MAX_MS;	/* 主进程不死等 */
	if (!ctx->orch || !ctx->db)
		return jerr(o, NULL, L_("编排未启用（orch 运行时/库缺失）——task 工具不可用"));
	c = occ_orch_find_task((occ_orch *)ctx->orch, tid);
	if (c) {
		int done = 0;

		t0 = occ_monotonic_ms();
		while (occ_monotonic_ms() - t0 < tmo) {
			if (occ_orch_poll(c, &r) == 1) {
				done = 1;
				break;
			}
			{
				struct timespec ts = { 0, 20 * 1000 * 1000 };

				nanosleep(&ts, NULL);
			}
		}
		elapsed = occ_monotonic_ms() - t0;
		if (!done) {
			obj = aik_json_new_obj();
			if (!obj || aik_json_obj_put(obj, "ok",
						     aik_json_new_bool(1)) ||
			    aik_json_obj_put(obj, "action",
					     aik_json_new_str("wait")) ||
			    aik_json_obj_put(obj, "task_id",
					     aik_json_new_str(tid)) ||
			    aik_json_obj_put(obj, "done",
					     aik_json_new_bool(0)) ||
			    aik_json_obj_put(obj, "pid",
					     aik_json_new_int(
						occ_orch_child_pid(c))) ||
			    aik_json_obj_put(obj, "waited_ms",
					     aik_json_new_int(elapsed))) {
				aik_json_free(obj);
				return jerr(o, NULL, L_("wait 结果组装失败（oom）"));
			}
			{
				int rr = jout(o, obj);

				aik_json_free(obj);
				return rr;
			}
		}
		/* 终局：终局摘要 + 任务面落点 */
		{
			const char *ts = "in_review";

			if (occ_task_get(ctx->db, tid, &trow, dbuf,
					 sizeof(dbuf)) == 1) {
				snprintf(dbuf, sizeof(dbuf), "%s", trow.status);
				ts = dbuf;
				occ_task_row_free(&trow);
			}
			obj = aik_json_new_obj();
			if (!obj ||
			    aik_json_obj_put(obj, "ok", aik_json_new_bool(1)) ||
			    aik_json_obj_put(obj, "action",
					     aik_json_new_str("wait")) ||
			    aik_json_obj_put(obj, "task_id",
					     aik_json_new_str(tid)) ||
			    aik_json_obj_put(obj, "done",
					     aik_json_new_bool(1)) ||
			    aik_json_obj_put(obj, "end", aik_json_new_str(
					r.end == OCC_ORCH_END_EXIT ? "exit" :
					r.end == OCC_ORCH_END_SIGNAL ? "signal" :
					r.end == OCC_ORCH_END_CANCELLED ?
					"cancelled" : "timeout")) ||
			    aik_json_obj_put(obj, "exit_code",
					     aik_json_new_int(r.exit_code)) ||
			    aik_json_obj_put(obj, "dur_ms",
					     aik_json_new_int(r.dur_ms)) ||
			    aik_json_obj_put(obj, "reviewed",
					     aik_json_new_bool(r.reviewed)) ||
			    aik_json_obj_put(obj, "task_state",
					     aik_json_new_str(ts))) {
				aik_json_free(obj);
				occ_orch_result_free(&r);
				return jerr(o, NULL, L_("wait 结果组装失败（oom）"));
			}
			{
				int rr = jout(o, obj);

				aik_json_free(obj);
				occ_orch_result_free(&r);
				return rr;
			}
		}
	}
	/* 不在活表：查任务面（已终局）或不存在 */
	{
		int g = occ_task_get(ctx->db, tid, &trow, dbuf, sizeof(dbuf));

		if (g != 1)
			return jerr(o, NULL, L_("任务 %s 不存在（活表与任务库均无）"), tid);
		obj = aik_json_new_obj();
		if (!obj || aik_json_obj_put(obj, "ok", aik_json_new_bool(1)) ||
		    aik_json_obj_put(obj, "action",
				     aik_json_new_str("wait")) ||
		    aik_json_obj_put(obj, "task_id", aik_json_new_str(tid)) ||
		    aik_json_obj_put(obj, "done", aik_json_new_bool(1)) ||
		    aik_json_obj_put(obj, "task_state",
				     aik_json_new_str(trow.status))) {
			occ_task_row_free(&trow);
			aik_json_free(obj);
			return jerr(o, NULL, L_("wait 结果组装失败（oom）"));
		}
		{
			int rr = jout(o, obj);

			aik_json_free(obj);
			occ_task_row_free(&trow);
			return rr;
		}
	}
}

/*
 * result_path_resolve - E10③：结果文件路径跨进程恢复。运行时注册表
 * （进程私有，进程死即失）miss 时查任务事件流 kind='result_file' 兜底
 * （spawn 时持久化落库的登记；回炉再派多条取最近一条；payload=
 * {"path":"…"}）。活表命中或无事件 → 返回活表值（可 NULL/空）。
 * 命中兜底时路径写入调用方缓冲 out 并返回 out。
 */
static const char *result_path_resolve(occ_orch *o, occ_db *db,
				       const char *tid,
				       char *out, size_t outlen)
{
	const char *rp = occ_orch_result_path(o, tid);
	occ_task_event_row *evs = NULL;
	size_t nevs = 0, i;
	char pj[384], perr[64];
	aik_json *v;

	if ((rp && rp[0]) || !db || !tid || !tid[0] || !out || !outlen)
		return rp;
	pj[0] = '\0';
	if (occ_task_events(db, tid, &evs, &nevs, NULL, 0) != 0)
		return rp;
	for (i = 0; i < nevs; i++)
		if (!strcmp(evs[i].kind, OCC_TASK_EV_RESULT_FILE) &&
		    evs[i].payload_json && evs[i].payload_json[0])
			snprintf(pj, sizeof(pj), "%s", evs[i].payload_json);
	occ_task_event_rows_free(evs, nevs);
	if (!pj[0])
		return rp;
	v = aik_json_parse(pj, strlen(pj), perr, sizeof(perr));
	if (v) {
		const char *p = aik_json_str(aik_json_get(v, "path"));

		if (p && p[0])
			snprintf(out, outlen, "%s", p);
		aik_json_free(v);
	}
	return out[0] ? out : rp;
}

static int task_read_result(const occ_tool_ctx *ctx, occ_args *a,
			    occ_obuf *o)
{
	const char *tid = args_str(a, "task_id");
	const char *rp;
	char *report = NULL;
	occ_task_row trow;
	occ_task_event_row *evs = NULL;
	size_t nevs = 0, i;
	const char *last_payload = NULL;
	const char *last_mv = NULL;
	char dbuf[256];
	char rbuf[384];
	aik_json *obj;

	if (!tid || !tid[0])
		return jerr(o, NULL, L_("read_result 缺少参数 task_id"));
	if (!ctx->orch || !ctx->db)
		return jerr(o, NULL, L_("编排未启用（orch 运行时/库缺失）——task 工具不可用"));
	if (occ_task_get(ctx->db, tid, &trow, dbuf, sizeof(dbuf)) != 1)
		return jerr(o, NULL, L_("任务 %s 不存在"), tid);
	/* 结果文件：运行时注册表 → E10③ 事件流兜底（派发进程死后
	 * 跨进程恢复——任务仍可 read_result/return 验收） */
	rbuf[0] = '\0';
	rp = result_path_resolve((occ_orch *)ctx->orch, ctx->db, tid,
				 rbuf, sizeof(rbuf));
	if (rp && rp[0])
		report = read_file_head(rp, 4096);
	/* 终局 result 事件摘要（E2 collect 落的 end/exit_code/stdout_path）
	 * + E4 机械预判（occ_review_prenote 落的 machine_verdict 事件） */
	if (occ_task_events(ctx->db, tid, &evs, &nevs, NULL, 0) == 0) {
		for (i = 0; i < nevs; i++)
			if (evs[i].payload_json) {
				if (!strcmp(evs[i].kind, OCC_TASK_EV_RESULT))
					last_payload = evs[i].payload_json;
				else if (!strcmp(evs[i].kind,
						 OCC_TASK_EV_RETURN) &&
					 strstr(evs[i].payload_json,
						"\"machine_verdict\""))
					last_mv = evs[i].payload_json;
			}
	}
	obj = aik_json_new_obj();
	if (!obj || aik_json_obj_put(obj, "ok", aik_json_new_bool(1)) ||
	    aik_json_obj_put(obj, "action",
			     aik_json_new_str("read_result")) ||
	    aik_json_obj_put(obj, "task_id", aik_json_new_str(tid)) ||
	    aik_json_obj_put(obj, "task_state",
			     aik_json_new_str(trow.status)) ||
	    aik_json_obj_put(obj, "result_file",
			     rp && rp[0] ? aik_json_new_str(rp) :
					   aik_json_new_null()) ||
	    aik_json_obj_put(obj, "report",
			     report ? aik_json_new_str(report) :
				      aik_json_new_null()) ||
	    aik_json_obj_put(obj, "result_event",
			     last_payload ? aik_json_new_str(last_payload) :
					    aik_json_new_null()) ||
	    aik_json_obj_put(obj, "machine_verdict",
			     last_mv ? aik_json_new_str(last_mv) :
				       aik_json_new_null())) {
		occ_task_row_free(&trow);
		occ_task_event_rows_free(evs, nevs);
		aik_json_free(obj);
		free(report);
		return jerr(o, NULL, L_("read_result 结果组装失败（oom）"));
	}
	budget_put(obj, ctx->db, &trow);	/* E7：budget 段（显示参考） */
	{
		int r = jout(o, obj);

		aik_json_free(obj);
		occ_task_row_free(&trow);
		occ_task_event_rows_free(evs, nevs);
		free(report);
		return r;
	}
}

/*
 * task_return - E4 升级：从「note 最小实现」走验收环（§4）。
 *   in_review 态：occ_review_run 机械判（verdict 表逐行+文件在场+
 *   md5 对照+断言行+退出码——判据表见 review.c 头注）→ 三路
 *   （done/rework+整改词/escalated+升级词）；judge 表态 pass 仅在
 *   机械判通过后生效（机械判 fail 强制回炉——防转述验收，报告自称
 *   完成不采信）。其余状态（未终局/已结项）保持 E3 note 语义
 *   （只记表态不动状态机，recorded 如实回显）。
 */
static int task_return(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *tid = args_str(a, "task_id");
	const char *verdict = args_str(a, "verdict");
	const aik_json *passj;
	occ_task_row trow;
	char dbuf[256], stbuf[24];
	char *distill_txt = NULL;	/* E5：蒸馏文（done 时） */
	aik_json *pj, *obj;

	if (!tid || !tid[0])
		return jerr(o, NULL, L_("return 缺少参数 task_id"));
	if (!verdict || !verdict[0])
		return jerr(o, NULL, L_("return 缺少参数 verdict（对结果的表态：通过与否/差距/依据）"));
	if (!ctx->orch || !ctx->db)
		return jerr(o, NULL, L_("编排未启用（orch 运行时/库缺失）——task 工具不可用"));
	if (occ_task_get(ctx->db, tid, &trow, dbuf, sizeof(dbuf)) != 1) {
		return jerr(o, NULL, L_("任务 %s 不存在"), tid);
	}
	snprintf(stbuf, sizeof(stbuf), "%s", trow.status);
	if (!strcmp(trow.status, OCC_TASK_ST_IN_REVIEW)) {
		/* E4 验收环：机械判 → 三路（judge.pass 仅机械判过后生效） */
		occ_review_opts ro;
		occ_review_verdict rv;
		char brief[OCC_RV_BRIEF_MAX];
		char state[24];
		char rbuf[384];
		int jpass = 1;

		passj = a->root ? aik_json_get(a->root, "pass") : NULL;
		if (passj) {
			if (aik_json_typeof(passj) != AIK_JSON_BOOL)
				return jerr(o, NULL, L_("return 参数 pass 须为布尔（表态位：机械判通过后生效）"));
			jpass = aik_json_bool(passj);
		} else if (strstr(verdict, "不通过") ||
			   strstr(verdict, "不认可") ||
			   strstr(verdict, "拒绝") ||
			   strncasecmp(verdict, "fail", 4) == 0) {
			jpass = 0;	/* 表态文本兜底推断（显式 pass 优先） */
		}
		memset(&ro, 0, sizeof(ro));
		/* E10③：机械判的结果文件同走注册表→事件流兜底（跨进程
		 * 恢复后 return 验收环仍可读到报告） */
		rbuf[0] = '\0';
		ro.result_path = result_path_resolve(
			(occ_orch *)ctx->orch, ctx->db, tid, rbuf,
			sizeof(rbuf));
		ro.base_dir = ctx->workdir;
		ro.judge_note = verdict;
		ro.judge_pass = jpass;
		occ_task_row_free(&trow);
		if (occ_review_run(ctx->db, tid, &ro, &rv, brief,
				   sizeof(brief), state, sizeof(state),
				   dbuf, sizeof(dbuf)) != 0)
			return jerr(o, NULL, L_("return 验收环失败：%s"), dbuf[0] ? dbuf : L_("库错"));
		/* E5 闸1+蒸馏：验收通过 → 子会话蒸馏归档 + 主会话请求
		 * 回合收口压缩（defer；force 语义=任务完成触发闸） */
		distill_txt = !strcmp(state, OCC_TASK_ST_DONE) ?
			occ_orch_distill(ctx->db, tid) : NULL;
		if (!strcmp(state, OCC_TASK_ST_DONE))
			occ_ac_request_compact();
		obj = aik_json_new_obj();
		if (!obj ||
		    aik_json_obj_put(obj, "ok", aik_json_new_bool(1)) ||
		    aik_json_obj_put(obj, "action",
				     aik_json_new_str("return")) ||
		    aik_json_obj_put(obj, "task_id", aik_json_new_str(tid)) ||
		    aik_json_obj_put(obj, "event",
				     aik_json_new_str("return")) ||
		    aik_json_obj_put(obj, "recorded",
				     aik_json_new_bool(1)) ||
		    aik_json_obj_put(obj, "state", aik_json_new_str(state)) ||
		    aik_json_obj_put(obj, "machine_pass",
				     aik_json_new_bool(rv.pass)) ||
		    aik_json_obj_put(obj, "judge_pass",
				     aik_json_new_bool(jpass)) ||
		    aik_json_obj_put(obj, "forced_fail",
				     aik_json_new_bool(!rv.pass)) ||
		    aik_json_obj_put(obj, "n_hit",
				     aik_json_new_int(rv.n_hit)) ||
		    aik_json_obj_put(obj, "rework_brief",
				     brief[0] ? aik_json_new_str(brief) :
						aik_json_new_null())) {
			aik_json_free(obj);
			free(distill_txt);
			return jerr(o, NULL, L_("return 结果组装失败（oom）"));
		}
		if (distill_txt) {
			/* 蒸馏实体清单随工具结果进主上下文（两级蒸馏第二级） */
			int pr = aik_json_obj_put(obj, "distill",
						  aik_json_new_str(
							  distill_txt));

			if (pr) {
				aik_json_free(obj);
				free(distill_txt);
				return jerr(o, NULL, L_("return 结果组装失败（oom）"));
			}
		}
		free(distill_txt);
		{
			int r = jout(o, obj);

			aik_json_free(obj);
			return r;
		}
	}
	occ_task_row_free(&trow);
	/* 非 in_review（未终局/已结项）：E3 note 语义保留（只记表态） */
	pj = aik_json_new_obj();
	if (!pj || aik_json_obj_put(pj, "action",
				    aik_json_new_str("return")) ||
	    aik_json_obj_put(pj, "verdict", aik_json_new_str(verdict))) {
		aik_json_free(pj);
		return jerr(o, NULL, L_("return 事件组装失败（oom）"));
	}
	{
		char *txt = NULL;
		size_t tl = 0;
		int rc;

		if (aik_json_dump(pj, &txt, &tl) != 0 || !txt) {
			aik_json_free(pj);
			return jerr(o, NULL, L_("return 事件组装失败（oom）"));
		}
		aik_json_free(pj);
		rc = occ_task_note(ctx->db, tid, txt, dbuf, sizeof(dbuf));
		free(txt);
		if (rc != 0)
			return jerr(o, NULL, L_("return 记录失败：%s"), dbuf[0] ? dbuf : L_("任务不存在或库错"));
	}
	obj = aik_json_new_obj();
	if (!obj || aik_json_obj_put(obj, "ok", aik_json_new_bool(1)) ||
	    aik_json_obj_put(obj, "action",
			     aik_json_new_str("return")) ||
	    aik_json_obj_put(obj, "task_id", aik_json_new_str(tid)) ||
	    aik_json_obj_put(obj, "event", aik_json_new_str("return")) ||
	    aik_json_obj_put(obj, "recorded", aik_json_new_bool(1)) ||
	    aik_json_obj_put(obj, "state",
			     aik_json_new_str(stbuf))) {
		aik_json_free(obj);
		return jerr(o, NULL, L_("return 结果组装失败（oom）"));
	}
	{
		int r = jout(o, obj);

		aik_json_free(obj);
		return r;
	}
}

/* E6 第八工具实现（SCHEMA/声明在前部 TOOLS_ORCH 区） */
static int tool_recall(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *query = args_str(a, "query");
	const char *layer = args_str(a, "layer");
	char lay[160];
	char *blk;

	(void)ctx;
	if (!query || !query[0])
		return jerr(o, NULL, L_("recall 缺少参数 query"));
	if (layer && layer[0])
		snprintf(lay, sizeof(lay), "%.150s", layer);
	else
		lay[0] = '\0';
	blk = occ_sme_lookup_ex(query, lay[0] ? lay : NULL);
	if (!blk)
		return jerr(o, NULL, L_("recall：无命中（或记忆服务不可达）"));
	occ_ob_printf(o, "%s", blk);
	free(blk);
	return 0;
}

static int tool_task(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *action;

	if (a->bad)
		return jerr(o, NULL, L_("task 参数不是合法 JSON（拒绝执行——请给出合法 JSON 参数）"));
	action = args_str(a, "action");
	if (!action || !action[0])
		return jerr(o, NULL, L_("task 缺少参数 action（spawn/status/wait/read_result/return）"));
	if (!strcmp(action, "spawn"))
		return task_spawn(ctx, a, o);
	if (!strcmp(action, "status"))
		return task_status(ctx, a, o);
	if (!strcmp(action, "wait"))
		return task_wait(ctx, a, o);
	if (!strcmp(action, "read_result"))
		return task_read_result(ctx, a, o);
	if (!strcmp(action, "return"))
		return task_return(ctx, a, o);
	return jerr(o, NULL, L_("未知 action「%s」（可用：spawn/status/wait/read_result/return）"), action);
}

/* ---- 快照 stage ---- */

/*
 * b2 mangle 修复：'%'→%25、'/'→%2f、'.'→%2e 百分比编码（单射，单遍
 * 左到右可安全反解）。b1 的 '/'→'_' 使 /tmp/a_b 与 /tmp/a/b 碰撞同名
 * ——同消息两次写这类路径时快照互相覆盖、undo 会恢复错文件（b2 勘察
 * 发现，报告在案）。'.' 必须编码：否则名为 x.ABSENT 的文件快照与
 * x 的墓碑条目同名不可分。b1 旧编码快照与新编码不兼容（b1 快照从未
 * 被消费，无负担）。
 */
void occ_snap_mangle(const char *abs, char *out, size_t outlen)
{
	size_t i, j = 0;

	for (i = 0; abs[i] && j + 6 < outlen; i++) {
		if (abs[i] == '%') {
			out[j++] = '%';
			out[j++] = '2';
			out[j++] = '5';
		} else if (abs[i] == '/') {
			out[j++] = '%';
			out[j++] = '2';
			out[j++] = 'f';
		} else if (abs[i] == '.') {
			out[j++] = '%';
			out[j++] = '2';
			out[j++] = 'e';
		} else {
			out[j++] = abs[i];
		}
	}
	out[j] = '\0';
}

/*
 * occ_snap_unmangle - occ_snap_mangle 的逆（单遍左到右 %XX 解码）。
 * mangle 是单射 ⇒ 逆映射良定。返回 0；outlen 不足截断（返回 -1）。
 * undo 扫描快照目录时把条目名还原为绝对路径。
 */
int occ_snap_unmangle(const char *mangled, char *out, size_t outlen)
{
	size_t i = 0, j = 0;

	if (!mangled || !out || !outlen)
		return -1;
	while (mangled[i]) {
		if (mangled[i] == '%' && mangled[i + 1] && mangled[i + 2]) {
			char hx[3] = { mangled[i + 1], mangled[i + 2], '\0' };
			char *end = NULL;
			long v = strtol(hx, &end, 16);

			if (end && *end == '\0' && j + 1 < outlen) {
				out[j++] = (char)v;
				i += 3;
				continue;
			}
		}
		if (j + 1 >= outlen)
			return -1;
		out[j++] = mangled[i++];
	}
	out[j] = '\0';
	return 0;
}

/* 快照根解析（参数显式 > OCC_SNAPROOT > ~/.occ/snapshots）；buf 静态
 * 或调用方缓冲均可——返回 NULL=无 HOME。b2 起 revert.c 复用。 */
const char *occ_snap_root(char *buf, size_t buflen)
{
	const char *env = getenv("OCC_SNAPROOT");
	const char *home;

	if (env && env[0])
		return env;
	home = getenv("HOME");
	if (!home)
		return NULL;
	if (snprintf(buf, buflen, "%s/.occ/snapshots", home) >= (int)buflen)
		return NULL;
	return buf;
}

/* ===================== C-P2a：config_write_network =====================
 * 目标恒为 <NETCFG_DIR>/70-static-<iface>.network（字典序先于出厂
 * 80-wired.network → systemd-networkd 首个匹配生效：静态覆盖 DHCP；
 * 删文件即回 DHCP）。NETCFG_DIR 可经 OCC_NETCFG_DIR 覆盖=测试沙盒
 * 钩子（OCC_CATALOG 同款惯例，出厂不设）。
 * write/remove 恒 W2（分类器裁定）；show 只读。 */

static const char *netcfg_dir(void)
{
	const char *e = getenv("OCC_NETCFG_DIR");

	return (e && e[0]) ? e : "/etc/systemd/network";
}

static int ip4_valid(const char *s)
{
	unsigned a, b, c, d;
	char extra;
	size_t i;

	if (!s || !*s)
		return 0;
	for (i = 0; s[i]; i++)
		if (!((s[i] >= '0' && s[i] <= '9') || s[i] == '.'))
			return 0;
	if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
		return 0;
	return a <= 255 && b <= 255 && c <= 255 && d <= 255;
}

static int cidr_valid(const char *s, char *ip, size_t ipcap, int *pfx)
{
	const char *slash;
	char pbuf[8];
	size_t pl;
	long v;
	char *end;

	if (!s)
		return 0;
	slash = strchr(s, '/');
	if (!slash || slash == s || !slash[1])
		return 0;
	pl = (size_t)(slash - s);
	if (pl == 0 || pl >= ipcap)
		return 0;
	memcpy(ip, s, pl);
	ip[pl] = '\0';
	if (!ip4_valid(ip))
		return 0;
	pl = strlen(slash + 1);
	if (pl < 1 || pl > 2)
		return 0;
	memcpy(pbuf, slash + 1, pl);
	pbuf[pl] = '\0';
	v = strtol(pbuf, &end, 10);
	if (*end || v < 0 || v > 32)
		return 0;
	*pfx = (int)v;
	return 1;
}

static int iface_valid(const char *s)
{
	size_t i, n;

	if (!s)
		return 0;
	n = strlen(s);
	if (n < 1 || n > 15)
		return 0;
	if (!((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') ||
	      (s[0] >= '0' && s[0] <= '9')))
		return 0;
	for (i = 1; i < n; i++) {
		char c = s[i];

		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == '-'))
			return 0;
	}
	return 1;
}

/* dns 列表校验（逗号分隔 IPv4；空段拒绝） */
static int dns_valid(const char *s)
{
	char buf[256];
	char *tok, *save;
	size_t n;

	if (!s || !*s)
		return 0;
	n = strlen(s);
	if (n >= sizeof(buf))
		return 0;
	memcpy(buf, s, n + 1);
	for (tok = strtok_r(buf, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		if (!ip4_valid(tok))
			return 0;
	}
	return 1;
}

static int tool_netcfg(const occ_tool_ctx *ctx, occ_args *a, occ_obuf *o)
{
	const char *action = args_str(a, "action");
	const char *iface = args_str(a, "iface");
	const char *dir = netcfg_dir();

	if (!action || !action[0]) {
		occ_ob_puts(o, L_("ERROR: config_write_network 缺少 action（write/remove/show）"));
		return -1;
	}
	if (!strcmp(action, "show")) {
		DIR *d = opendir(dir);
		struct dirent *de;
		int found = 0;

		if (!d) {
			occ_ob_printf(o, L_("ERROR: 打开 %s 失败：%s"), dir, strerror(errno));
			return -1;
		}
		occ_ob_printf(o, L_("== %s 现存 .network 配置 =="), dir);
		while ((de = readdir(d)) != NULL) {
			char fp[600];
			char *buf;
			size_t n, i, ls, le;

			if (!strstr(de->d_name, ".network"))
				continue;
			if (iface && iface[0] &&
			    !strstr(de->d_name, iface))
				continue;
			snprintf(fp, sizeof(fp), "%s/%s", dir, de->d_name);
			if (read_whole(fp, 8192, &buf, &n) != 0)
				continue;
			found++;
			occ_ob_printf(o, "-- %s --", de->d_name);
			for (i = 0; i < n;) {
				/* 行窗 [ls,le) */
				ls = i;
				while (i < n && buf[i] != '\n')
					i++;
				le = i;
				if (i < n)
					i++;
				{
					size_t kl = (size_t)(le - ls);
					char save_ch = buf[le];

					buf[le] = '\0';
					if (buf[ls] != '#' &&
					    (strncmp(buf + ls, "Name=", 5) == 0 ||
					     strncmp(buf + ls, "Address=", 8) == 0 ||
					     strncmp(buf + ls, "Gateway=", 8) == 0 ||
					     strncmp(buf + ls, "DNS=", 4) == 0 ||
					     strncmp(buf + ls, "DHCP=", 5) == 0)) {
						if (kl > 100)
							buf[ls + 100] = '\0';
						occ_ob_printf(o, "  %s",
							      buf + ls);
					}
					buf[le] = save_ch;
				}
			}
			free(buf);
		}
		closedir(d);
		if (!found)
			occ_ob_puts(o, L_("（无匹配 .network 文件）"));
		return 0;
	}
	/* write/remove：iface 必填且严格校验（进文件名——拒绝路径花样） */
	if (!iface || !iface_valid(iface)) {
		occ_ob_puts(o, L_("ERROR: iface 非法（[A-Za-z0-9] 开头，[A-Za-z0-9._-]{1,15}，如 eth0/enp0s3）"));
		return -1;
	}
	{
		char path[512];
		char snapbuf[512];

		snprintf(path, sizeof(path), "%s/70-static-%s.network",
			 dir, iface);
		if (!strcmp(action, "remove")) {
			if (unlink(path) != 0) {
				if (errno == ENOENT) {
					occ_ob_printf(o, L_("%s 不存在（本就无静态配置）"), path);
					return 0;
				}
				occ_ob_printf(o, L_("ERROR: 删除 %s 失败：%s"), path, strerror(errno));
				return -1;
			}
			occ_ob_printf(o, L_("已删除 %s。回 DHCP 生效两步：networkctl reload && networkctl reconfigure %s"), path, iface);
			return 0;
		}
		if (strcmp(action, "write")) {
			occ_ob_printf(o, L_("ERROR: 未知 action「%s」（write/remove/show）"), action);
			return -1;
		}
		{
			const char *addr = args_str(a, "address");
			const char *gw = args_str(a, "gateway");
			const char *dns = args_str(a, "dns");
			char ip[48];
			int pfx;
			FILE *f;
			char dnsbuf[256];
			char *tok, *save;

			if (!addr || !cidr_valid(addr, ip, sizeof(ip),
						 &pfx)) {
				occ_ob_puts(o, L_("ERROR: address 非法（需 CIDR 如 192.168.1.10/24，掩码段 0-32）"));
				return -1;
			}
			if (gw && gw[0] && !ip4_valid(gw)) {
				occ_ob_puts(o, L_("ERROR: gateway 非法（IPv4 点分十进制）"));
				return -1;
			}
			if (dns && dns[0] && !dns_valid(dns)) {
				occ_ob_puts(o, L_("ERROR: dns 非法（逗号分隔 IPv4，如 223.5.5.5,1.1.1.1）"));
				return -1;
			}
			/* 快照 stage（undo 地基；与 write 工具同口径） */
			occ_snapshot_stage(ctx->db, ctx->snaproot,
					   ctx->session_id, ctx->msg_id, path,
					   snapbuf, sizeof(snapbuf));
			f = fopen(path, "wb");
			if (!f) {
				occ_ob_printf(o, L_("ERROR: 打开 %s 失败：%s"), path, strerror(errno));
				return -1;
			}
			fprintf(f, "# AIKernel 静态网络（config_write_network"
				" 生成；删本文件即回 DHCP 出厂 80-wired）\n"
				"[Match]\nName=%s\n\n[Network]\nAddress=%s\n",
				iface, addr);
			if (gw && gw[0])
				fprintf(f, "Gateway=%s\n", gw);
			if (dns && dns[0]) {
				snprintf(dnsbuf, sizeof(dnsbuf), "%s", dns);
				for (tok = strtok_r(dnsbuf, ",", &save); tok;
				     tok = strtok_r(NULL, ",", &save))
					fprintf(f, "DNS=%s\n", tok);
			}
			if (fclose(f) != 0) {
				occ_ob_printf(o, L_("ERROR: 关闭 %s 失败：%s"), path, strerror(errno));
				return -1;
			}
			occ_ob_printf(o, L_("已写入 %s。生效两步（经 bash 执行）：networkctl reload && networkctl reconfigure %s；查看 networkctl status %s；撤销=action remove"), path, iface, iface);
		}
	}
	return 0;
}

int occ_snapshot_stage(occ_db *db, const char *snaproot,
		       const char *session_id, const char *msg_id,
		       const char *abs_path, char *buf, size_t buflen)
{
	char dir[4300], dst[12512], mangled[8192];
	char *data = NULL;
	size_t len = 0;
	FILE *f;
	const char *root = (snaproot && snaproot[0]) ? snaproot : NULL;
	static char defroot[512];

	if (!root) {
		root = occ_snap_root(defroot, sizeof(defroot));
		if (!root)
			return -1;
	}
	if (!session_id || !msg_id || !abs_path || abs_path[0] != '/')
		return -1;
	snprintf(dir, sizeof(dir), "%s/%s/%s", root, session_id, msg_id);
	if (mkdirs(dir)) {
		fprintf(stderr, "occ-snap: mkdir %s: %s\n", dir,
			strerror(errno));
		return -1;
	}
	occ_snap_mangle(abs_path, mangled, sizeof(mangled));
	snprintf(dst, sizeof(dst), "%s/%s", dir, mangled);
	if (buf)
		snprintf(buf, buflen, "%s", dst);
	/*
	 * b2 首见即定：同消息内同文件多次 write/edit 时保留最早快照
	 * （=该消息触及前的原状态）——undo 恢复目标是「进入该回合前」，
	 * 覆盖会把快照推进到中间态。recover 重放 write 也依赖此（不把
	 * 快照污染成已写入态）。内容与墓碑任一已存在即跳过。
	 * P-50：早退路径绝不做 manifest 落库——不给旧快照补锚（攻击者
	 * 若已改过旧快照内容，补录=给毒内容盖章；只锚本次亲手写的字节）。
	 */
	{
		char probe[12520];

		snprintf(probe, sizeof(probe), "%s", dst);
		if (!access(probe, F_OK))
			return 0;
		snprintf(probe, sizeof(probe), "%s.ABSENT", dst);
		if (!access(probe, F_OK))
			return 0;
	}
	if (read_whole(abs_path, 64 * 1024 * 1024, &data, &len)) {
		if (errno != ENOENT) {
			fprintf(stderr, "occ-snap: read %s: %s\n", abs_path,
				strerror(errno));
			return -1;
		}
		/* 原文件不存在：ABSENT 墓碑（b2 /undo 据此删除还原） */
		snprintf(dst, sizeof(dst), "%s/%s.ABSENT", dir, mangled);
		f = fopen(dst, "wb");
		if (!f)
			return -1;
		fputs("absent\n", f);
		fclose(f);
		/* P-49（B6 验收线）：墓碑同入完整性校验面——<墓碑>.sha256
		 * 与内容快照 sidecar 同款（undo/redo 消费侧 absent_verify：
		 * 规范形态直通，非规范须 sidecar 对上，否则拒收）。写失败
		 * 不阻断快照本体（退化为 legacy 规范形态校验）。 */
		{
			char hex[OCC_SHA256_HEX + 1];

			if (occ_sha256_hex("absent\n", 7, hex) == 0) {
				FILE *sf;
				char sp[12560];

				snprintf(sp, sizeof(sp), "%s.sha256", dst);
				sf = fopen(sp, "w");
				if (sf) {
					fprintf(sf, "%s\n", hex);
					fclose(sf);
				} else {
					fprintf(stderr, L_("occ-snap: sidecar 写失败（退化为无校验）：%s\n"), sp);
				}
				/* P-50：墓碑 manifest 落库（DB 外部锚——
				 * undo 消费侧对账；落库失败=退化为 legacy
				 * sidecar 校验，不阻断快照本体） */
				if (db) {
					char merr[192];

					if (occ_snap_put(db, msg_id, abs_path,
							 "absent", hex, merr,
							 sizeof(merr)))
						fprintf(stderr, L_("occ-snap: manifest 落库失败（退化为 legacy 校验）：%s\n"), merr);
				} else {
					fputs(L_("occ-snap: manifest 落库失败（退化为 legacy 校验）：无 DB 句柄\n"), stderr);
				}
			}
		}
		return 0;
	}
	f = fopen(dst, "wb");
	if (!f) {
		free(data);
		return -1;
	}
	if (len && fwrite(data, 1, len, f) != len) {
		fclose(f);
		free(data);
		return -1;
	}
	fclose(f);
	/* S-FINDING-01（S-TRACK §5）：快照完整性 sidecar——原内容摘要落
	 * <dst>.sha256（undo/redo 恢复前校验；sidecar 写失败不阻断快照
	 * 本体，stderr 警告=退化为 legacy 无校验语义）。ABSENT 墓碑的
	 * sidecar 在上面墓碑分支随写（P-49，同款语义）。 */
	{
		char hex[OCC_SHA256_HEX + 1];

		if (occ_sha256_hex(data, len, hex) == 0) {
			FILE *sf;
			char sp[12560];

			snprintf(sp, sizeof(sp), "%s.sha256", dst);
			sf = fopen(sp, "w");
			if (sf) {
				fprintf(sf, "%s\n", hex);
				fclose(sf);
			} else {
				fprintf(stderr, L_("occ-snap: sidecar 写失败（退化为无校验）：%s\n"), sp);
			}
			/* P-50：内容快照 manifest 落库（同墓碑分支——sidecar
			 * 与快照同目录=自证，DB 行才是对快照树无写权可用的
			 * 真锚；落库失败退化 legacy，不阻断快照本体） */
			if (db) {
				char merr[192];

				if (occ_snap_put(db, msg_id, abs_path, "snap",
						 hex, merr, sizeof(merr)))
					fprintf(stderr, L_("occ-snap: manifest 落库失败（退化为 legacy 校验）：%s\n"), merr);
			} else {
				fputs(L_("occ-snap: manifest 落库失败（退化为 legacy 校验）：无 DB 句柄\n"), stderr);
			}
		}
	}
	free(data);
	return 0;
}

/* ---- O-9/O-4（UX-O §2）：W2 分类与裁决 ---- */

/* 安全区前缀判定（workdir/$HOME 子树 + /tmp）；abs 已由
 * resolve_arg_path 归一（write/edit 执行面同源——零口径漂移）。 */
static int w2_path_safe(const occ_tool_ctx *ctx, const char *abs)
{
	char base[4096];
	const char *home = getenv("HOME");
	const char *wd = (ctx && ctx->workdir && ctx->workdir[0]) ?
		ctx->workdir : getcwd(base, sizeof(base));

	if (strstr(abs, ".."))
		return 0;	/* 偏执兜底：归一后不应残留 */
	if (wd && wd[0]) {
		size_t l = strlen(wd);

		if (!strncmp(abs, wd, l) &&
		    (abs[l] == '\0' || abs[l] == '/'))
			return 1;
	}
	if (home && home[0]) {
		size_t l = strlen(home);

		if (!strncmp(abs, home, l) &&
		    (abs[l] == '\0' || abs[l] == '/'))
			return 1;
	}
	if (!strcmp(abs, "/tmp") || !strncmp(abs, "/tmp/", 5))
		return 1;
	return 0;
}

static void w2_detail(char *detail, size_t dcap, const char *fmt,
		      const char *a1)
{
	if (detail && dcap)
		snprintf(detail, dcap, fmt, a1);
}

/* O-21（P-52 刀1）：chmod 语义级命中——替代原「chmod 777」字面 strstr
 * （666/o+w 等全 family 不再漏）。前提=cmd 首个空白分隔 token 是 chmod；
 * 数字模式 [0-7]{3,4} 看 other-write 位（644/755 不命中）；符号模式
 * [ugoa]*[+-][rwxXst]+（单子句）：o/a/无前缀授 w 且 +/= 直判命中，
 * 授 x 且 + 时对 chmod 与模式 token 之后各非 '-' 参数逐个 stat——任一
 * 已存在且世界可写=两步等效 777（stat 全败/无 o+w 不命中）。u/g 档
 * 不命中。仅 libc 手写匹配（busybox 语境不引正则）。 */
static int w2_chmod_hit(const char *cmd, char *detail, size_t dcap)
{
	char buf[1024];
	char t120[128];
	char *tok[40];
	char *sp, *t;
	char head[16];
	const char *p = cmd;
	const char *m;
	size_t hn = 0, wi = 0;
	int n = 0, i, mi = -1, others = 0, grant_w = 0, grant_x = 0;
	char op;

	if (strstr(cmd, "chmod 777")) {
		w2_detail(detail, dcap, "chmod 777（世界可写）", NULL);
		return 1;	/* 廉价兜底：字面命中直走（原 strstr 语义） */
	}
	/* 前提：首个空白分隔 token == chmod（跳过前导空白） */
	while (*p == ' ' || *p == '\t')
		p++;
	while (p[hn] && p[hn] != ' ' && p[hn] != '\t' &&
	       hn < sizeof(head) - 1)
		hn++;
	memcpy(head, p, hn);
	head[hn] = '\0';
	if (strcmp(head, "chmod") != 0)
		return 0;
	/* 模式 token = chmod 之后首个非 '-' 开头参数（选项先行的惯序）；
	 * 继续收齐余下 token——两步绕过检测要对模式之后的文件参数 stat */
	snprintf(buf, sizeof(buf), "%s", cmd);
	for (t = strtok_r(buf, " \t", &sp); t && n < 40;
	     t = strtok_r(NULL, " \t", &sp)) {
		size_t tl = strlen(t);

		/* P-52 A6b 真机补（TC155）：`; echo $?` 类尾随标点会粘在
		 * 路径/模式 token 上——stat ENOENT→两步检测漏放。收 token
		 * 即剥首尾 ;,&|()"'
		 * 与反引号（引号包裹路径顺带受益） */
		while (tl > 0 && strchr(";,&|()\"'`", t[tl - 1]))
			t[--tl] = '\0';
		while (*t && strchr(";,&|()\"'`", *t))
			t++;
		if (!*t)
			continue;
		tok[n++] = t;
		if (n > 1 && t[0] != '-' && mi < 0)
			mi = n - 1;
	}
	if (mi < 0)
		return 0;
	m = tok[mi];
	snprintf(t120, sizeof(t120), "%.120s", cmd);
	/* 数字模式：3-4 位纯八进制 */
	if (strlen(m) >= 3 && strlen(m) <= 4) {
		int oct = 1, mode = 0;

		for (i = 0; m[i]; i++) {
			if (m[i] < '0' || m[i] > '7') {
				oct = 0;
				break;
			}
			mode = mode * 8 + (m[i] - '0');
		}
		if (oct) {
			if (mode & 0002) {
				w2_detail(detail, dcap,
					  "chmod 数字模式世界可写（%s）",
					  t120);
				return 1;
			}
			return 0;	/* 644/755 等：数字面干净收场 */
		}
	}
	/* 符号模式：对象前缀 [ugoa]* → 操作 [+-=] → 权限 [rwxXst]+ */
	while (m[wi] == 'u' || m[wi] == 'g' || m[wi] == 'o' ||
	       m[wi] == 'a') {
		if (m[wi] == 'o' || m[wi] == 'a')
			others = 1;
		wi++;
	}
	if (wi == 0)
		others = 1;			/* 无对象前缀=默认 a */
	op = m[wi];
	if (op != '+' && op != '-' && op != '=')
		return 0;
	for (i = 0; m[wi + 1 + i]; i++)
		if (!strchr("rwxXst", m[wi + 1 + i]))
			return 0;	/* 形态不符（非模式 token） */
	if (strchr(m + wi + 1, 'w'))
		grant_w = 1;
	if (strchr(m + wi + 1, 'x'))
		grant_x = 1;
	if (grant_w && others && (op == '+' || op == '=')) {
		w2_detail(detail, dcap, "chmod 符号模式授权他人可写", NULL);
		return 1;
	}
	if (grant_x && others && op == '+') {
		/* 两步绕过检测：+x 落在已世界可写文件上=等效 777 */
		for (i = mi + 1; i < n; i++) {
			struct stat st;

			if (tok[i][0] == '-')
				continue;
			if (stat(tok[i], &st) == 0 &&
			    (st.st_mode & S_IWOTH)) {
				w2_detail(detail, dcap,
					  "对已世界可写文件加执行位"
					  "（两步等效 777）", NULL);
				return 1;
			}
		}
	}
	return 0;
}

/* O-9 命令级 W2 表 + O-4 粘贴形态；命中=1（detail 填理由） */
static int w2_bash_hit(const char *cmd, char *detail, size_t dcap)
{
	static const char *hard[] = {
		"mkfs", "fdisk", "sfdisk", "parted", "wipefs", "blockdev",
		"dd", "reboot", "shutdown", "poweroff", "halt", "init",
		"telinit", "swapon", "swapoff", "mount", "umount",
		"kill", "killall", "killall5", "pkill", "iptables", "nft",
		"chattr", NULL
	};
	static const char *sc_bad[] = {
		"stop", "disable", "mask", "kill", "isolate",
		"emergency", "rescue", NULL
	};
	char buf[1024];
	char *line, *sp;

	if (strchr(cmd, '\n')) {
		w2_detail(detail, dcap, "多行 shell 命令（疑似粘贴——O-4）",
			  NULL);
		return 1;
	}
	if (strstr(cmd, "sudo")) {
		w2_detail(detail, dcap, "含 sudo（疑似粘贴/提权链——O-4）",
			  NULL);
		return 1;
	}
	if (strstr(cmd, "| sh") || strstr(cmd, "|sh") ||
	    strstr(cmd, "| bash") || strstr(cmd, "|bash")) {
		w2_detail(detail, dcap, "管道直接进 shell（curl|sh 形态）",
			  NULL);
		return 1;
	}
	{
		int chains = 0;
		const char *q;

		for (q = cmd; (q = strstr(q, "&&")) != NULL; q += 2)
			chains++;
		for (q = cmd; (q = strchr(q, ';')) != NULL; q++)
			chains++;
		if (chains >= 2) {
			w2_detail(detail, dcap,
				  "长链式命令（&&/; ≥2——疑似粘贴 O-4）",
				  NULL);
			return 1;
		}
	}
	if (w2_chmod_hit(cmd, detail, dcap)) {
		/* O-21（P-52 刀1）：chmod 语义级判定（数字 o+w/符号 o+a 授
		 * w/+x 两步绕过——detail 由 w2_chmod_hit 填） */
		return 1;
	}
	snprintf(buf, sizeof(buf), "%s", cmd);	/* 逐行首 token 对表 */
	for (line = strtok_r(buf, "\n", &sp); line;
	     line = strtok_r(NULL, "\n", &sp)) {
		char tok[32], tok2[32];
		char *p = line;
		size_t n = 0, n2 = 0;
		size_t i;

		while (*p == ' ' || *p == '\t')
			p++;
		while (p[n] && p[n] != ' ' && p[n] != '\t' &&
		       n < sizeof(tok) - 1)
			n++;
		if (!n)
			continue;
		memcpy(tok, p, n);
		tok[n] = '\0';
		for (i = 0; hard[i]; i++) {
			if (!strcmp(tok, hard[i]) ||
			    !strncmp(tok, "mkfs.", 5)) {
				w2_detail(detail, dcap,
					  "高危命令：%s（W2 表命中）", tok);
				return 1;
			}
		}
		if (!strcmp(tok, "rm")) {
			if (strstr(p, " -r") || strstr(p, " -R") ||
			    strstr(p, "-fr") || strstr(p, "-rf") ||
			    strstr(p, "--recursive")) {
				w2_detail(detail, dcap,
					  "递归删除 rm -r/-f", NULL);
				return 1;
			}
			continue;
		}
		if (!strcmp(tok, "systemctl")) {
			const char *r = p + n;

			while (*r == ' ' || *r == '\t')
				r++;
			while (r[n2] && r[n2] != ' ' && r[n2] != '\t' &&
			       n2 < sizeof(tok2) - 1)
				n2++;
			memcpy(tok2, r, n2);
			tok2[n2] = '\0';
			for (i = 0; sc_bad[i]; i++)
				if (!strcmp(tok2, sc_bad[i])) {
					w2_detail(detail, dcap,
						  "systemctl %s（服务面写）",
						  tok2);
					return 1;
				}
			continue;
		}
		if (!strcmp(tok, "chown")) {
			if (strstr(p, " -R") || strstr(p, "--recursive")) {
				w2_detail(detail, dcap, "chown -R 递归改属",
					  NULL);
				return 1;
			}
			continue;
		}
		if (!strcmp(tok, "curl") || !strcmp(tok, "wget")) {
			/* S4（S-TRACK §4）：网络外发=数据泄出面——上传/POST
			 * 旗标一律 W2（-d/--data/-T/--upload-file/-F/--form/
			 * --post 系列与 -X POST|PUT|PATCH）；落盘 -o/-O 同 W2。 */
			static const char *egress[] = {
				" -d", "--data", " -T", "--upload-file",
				" -F", "--form", "--post", "-X POST",
				"-X PUT", "-X PATCH", NULL
			};
			size_t ei;

			if (strstr(p, " -o ") || strstr(p, " -O")) {
				w2_detail(detail, dcap,
					  "%s 落盘（-o/-O）", tok);
				return 1;
			}
			for (ei = 0; egress[ei]; ei++) {
				if (strstr(p, egress[ei])) {
					w2_detail(detail, dcap,
						  "%s 网络外发（上传/POST——"
						  "数据外泄面）", tok);
					return 1;
				}
			}
			continue;
		}
	}
	return 0;
}

const char *occ_w2_classify(const occ_tool_ctx *ctx, const char *name,
			    const char *args_json, char *detail, size_t dcap)
{
	occ_args a;
	const char *r = "R";

	if (detail && dcap)
		detail[0] = '\0';
	if (!name)
		return r;
	args_init(&a, args_json ? args_json : "{}");
	if (!strcmp(name, OCC_T_WRITE) || !strcmp(name, OCC_T_EDIT)) {
		const char *path = args_str(&a, "path");
		char abs[4096];

		r = "W1";
		if (path && path[0] &&
		    resolve_arg_path(ctx, path, abs, sizeof(abs)) == 0 &&
		    !w2_path_safe(ctx, abs)) {
			if (detail && dcap)
				snprintf(detail, dcap,
					 "写目标出安全区（工作目录//$HOME/"
					 "/tmp）：%.90s", abs);
			r = "W2";
		}
	} else if (!strcmp(name, OCC_T_BASH)) {
		const char *cmd = args_str(&a, "command");

		r = "W1";	/* 沙箱面兜底；W2=命令级命中（表/粘贴） */
		if (cmd && cmd[0] && w2_bash_hit(cmd, detail, dcap))
			r = "W2";
	} else if (!strcmp(name, OCC_T_RM) || !strcmp(name, OCC_T_MKDIR) ||
		   !strcmp(name, OCC_T_MV)) {
		/* O-17：目标域判定——与执行面 write_guard 同域
		 * （occ_write_target_ok：workdir∪/tmp∪/var/ai，~/.occ 恒
		 * 拒）。任一端出域即 W2（detail 载目标绝对路径）；域内
		 * W1。不走 write/edit 的 w2_path_safe（$HOME∪/tmp 面）——
		 * 新三件执行面就是 occ_write_target_ok，分类/执行同域，
		 * 免「判 W1 却被守卫拒」的假阳。 */
		int is_mv = strcmp(name, OCC_T_MV) == 0;
		const char *src = args_str(&a, is_mv ? "src" : "path");
		const char *dst = args_str(&a, "dst");
		char abs[4096];
		char cwd[4096];
		const char *cwdp = ctx_cwd(ctx, cwd, sizeof(cwd));

		r = "W1";
		if (src && src[0] &&
		    resolve_arg_path(ctx, src, abs, sizeof(abs)) == 0 &&
		    !occ_write_target_ok(abs, cwdp ? cwdp : "")) {
			if (detail && dcap)
				snprintf(detail, dcap,
					 "%s %s出域（允许域=工作目录∪/tmp∪"
					 "/var/ai∪$HOME）：%.90s", name,
					 is_mv ? "源" : "目标", abs);
			r = "W2";
		}
		if (is_mv && dst && dst[0] &&
		    resolve_arg_path(ctx, dst, abs, sizeof(abs)) == 0 &&
		    !occ_write_target_ok(abs, cwdp ? cwdp : "")) {
			if (detail && dcap)
				snprintf(detail, dcap,
					 "mv 目标出域（允许域=工作目录∪"
					 "/tmp∪/var/ai∪$HOME）：%.90s", abs);
			r = "W2";
		}
	} else if (!strcmp(name, OCC_T_NETCFG)) {
		const char *act = args_str(&a, "action");

		r = "R";
		if (!act || strcmp(act, "show") != 0) {
			if (detail && dcap)
				snprintf(detail, dcap,
					 "改网络配置（%s/70-static-<iface>"
					 ".network——连通性风险）",
					 netcfg_dir());
			r = "W2";
		}
	}
	args_free(&a);
	return r;
}

/* O-18：W2 理由键归一——classify 的 detail 人话文本压成稳定短键
 * （同键=同类风险；「s 本会话同类放行」按键聚合，路径/命令字面差
 * 不分裂键）。按 detail 特征子串归类（覆盖各 detail 生产点：chmod
 * 语义面/写目标出安全区/文件管理出域/网络配置/高危表/粘贴形态）；
 * 未识别=工具名裸键（保守聚合：同工具未知理由同键）。 */
static void w2_reason_key(char *out, size_t cap, const char *name,
			  const char *detail)
{
	const char *d = detail ? detail : "";
	const char *base = name ? name : "?";

	if (strstr(d, "chmod"))
		snprintf(out, cap, "bash-chmod-ow");
	else if (strstr(d, "写目标出安全区"))
		snprintf(out, cap, "write-outzone");
	else if (strstr(d, "网络配置"))
		snprintf(out, cap, "netcfg-write");
	else if (strstr(d, "出域"))
		snprintf(out, cap, "%s-outzone", base);
	else if (strstr(d, "递归删除"))
		snprintf(out, cap, "bash-rm-r");
	else if (strstr(d, "递归改属"))
		snprintf(out, cap, "bash-chown-R");
	else if (strstr(d, "systemctl"))
		snprintf(out, cap, "bash-systemctl");
	else if (strstr(d, "网络外发") || strstr(d, "落盘"))
		snprintf(out, cap, "bash-egress");
	else if (strstr(d, "高危命令"))
		snprintf(out, cap, "bash-hard");
	else if (strstr(d, "多行") || strstr(d, "sudo") ||
		 strstr(d, "管道") || strstr(d, "链式"))
		snprintf(out, cap, "bash-paste");
	else
		snprintf(out, cap, "%s", base);
}

/* O-18：理由键入会话放行表（TUI 面板 s 应答侧调；去重；满 8 槽
 * 移位淘汰最老——会话粒度小表够用）。 */
void occ_w2_ses_allow_add(struct occ_w2_gate *g)
{
	int i;

	if (!g || !g->last_key[0])
		return;
	for (i = 0; i < g->ses_allow_n; i++)
		if (!strcmp(g->ses_allow[i], g->last_key))
			return;			/* 已在表（幂等） */
	if (g->ses_allow_n < (int)(sizeof(g->ses_allow) /
				    sizeof(g->ses_allow[0]))) {
		snprintf(g->ses_allow[g->ses_allow_n],
			 sizeof(g->ses_allow[0]), "%s", g->last_key);
		g->ses_allow_n++;
	} else {
		memmove(g->ses_allow[0], g->ses_allow[1],
			sizeof(g->ses_allow) - sizeof(g->ses_allow[0]));
		snprintf(g->ses_allow[(int)(sizeof(g->ses_allow) /
				     sizeof(g->ses_allow[0])) - 1],
			 sizeof(g->ses_allow[0]), "%s", g->last_key);
	}
}

/* 三态裁决：allow_w2 > tier 闸 > confirm 交互 > headless 拒。
 * 返回 1=放行（o 不动）；0=拒绝（o 填人话错误，denied++）。 */
static int w2_gate_decide(const occ_tool_ctx *c, const char *name,
			  const char *why, occ_obuf *o)
{
	struct occ_w2_gate *g = c->w2;

	if (g->allow_w2)
		return 1;	/* 显式开门（headless --allow-w2） */
	if (g->tier != OCC_W2_TIER_PRIVILEGED) {
		g->denied++;
		occ_ob_printf(o, L_("ERROR: W2 拒绝（%s：%s）——当前档位不允许高危写；/su 提权后重试（policy 见 /etc/aikernel/policy.conf）"), name, why ? why : "?");
		return 0;
	}
	/* O-18：会话放行表命中（本会话同理由键已 s 放行过）→ 直接放行
	 * 不再问（计数；allow_w2/tier 闸语义零变化；headless 表恒空） */
	{
		int i;

		for (i = 0; i < g->ses_allow_n; i++)
			if (!strcmp(g->ses_allow[i], g->last_key)) {
				g->ses_allow_hits++;
				return 1;
			}
	}
	if (g->confirm && g->confirm(g->ud, L_("W2 高危操作确认"), why ? why : "") == 1)
		return 1;
	g->denied++;
	occ_ob_printf(o, L_("ERROR: W2 拒绝（%s：%s）——%s"), name, why ? why : "?", g->confirm ? L_("已按您的选择取消") : L_("headless 默认拒绝（occ -p 需 --allow-w2 显式开门）"));
	return 0;
}

/* ---- 单入口 ---- */

void occ_tool_result_free(occ_tool_result *r)
{
	if (!r)
		return;
	free(r->text);
	memset(r, 0, sizeof(*r));
}

int occ_tool_exec(const occ_tool_ctx *ctx, const char *name,
		  const char *call_id, const char *args_json,
		  occ_tool_result *out)
{
	occ_args a;
	occ_obuf o;
	long long t0, t1;
	int rc = 0;
	char err[160];
	char wd[200];		/* O-9：W2 理由 */
	occ_tool_ctx c;

	if (!ctx || !name || !out)
		return -1;
	memset(out, 0, sizeof(*out));
	memset(&o, 0, sizeof(o));
	c = *ctx;
	if (!c.timeout_ms) {
		const char *e = getenv("OCC_TOOL_TIMEOUT_MS");

		c.timeout_ms = (e && atoll(e) > 0) ? atoll(e) :
			       OCC_TOOL_TIMEOUT_DEF_MS;
	}
	args_init(&a, args_json);
	t0 = occ_monotonic_ms();
	/* O-9/O-4（UX-O §2）：W2 确认门（ctx->w2==NULL=嵌入/测试面
	 * 零行为变化；命中→allow_w2/tier/confirm 三态裁决） */
	if (c.w2 && strcmp(occ_w2_classify(&c, name, args_json,
					   wd, sizeof(wd)), "W2") == 0) {
		/* O-18：归一理由键暂存 gate（decide 查会话放行表与 TUI s
		 * 应答侧入表共用） */
		w2_reason_key(c.w2->last_key, sizeof(c.w2->last_key),
			      name, wd);
		if (!w2_gate_decide(&c, name, wd, &o)) {
			rc = -1;
			goto w2_done;
		}
		/* J-7=A（P-52 刀2）：门已放行（confirm 确认/allow_w2 开
		 * 门）——标记下传 write_guard，特权档越界写豁免放行 */
		c.w2_confirmed = 1;
	}
	if (!strcmp(name, OCC_T_READ)) {
		rc = tool_read(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_WRITE)) {
		rc = tool_write(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_EDIT)) {
		rc = tool_edit(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_GLOB)) {
		rc = tool_glob(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_GREP)) {
		rc = tool_grep(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_BASH)) {
		rc = tool_bash(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_RM)) {
		/* O-17：文件管理三件（宿主面；无开关恒注册） */
		rc = tool_rm(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_MV)) {
		rc = tool_mv(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_MKDIR)) {
		rc = tool_mkdir(&c, &a, &o);
	} else if (!strcmp(name, OCC_T_NETCFG)) {
		/* C-P2a：开关关=未知工具面（差分红线：默认清单零变化） */
		if (!occ_netcfg_tools_enabled()) {
			occ_ob_printf(&o, L_("ERROR: 未知工具「%s」（可用：read/write/edit/glob/grep/bash/rm/mv/mkdir）"), name);
			rc = -1;
		} else {
			rc = tool_netcfg(&c, &a, &o);
		}
	} else if (!strcmp(name, OCC_T_TASK)) {
		/* E3 第七工具：开关关=未知工具面（清单不含 task）；
		 * 开=五动作（内部再校验 ctx->orch） */
		if (!occ_orch_tools_enabled()) {
			occ_ob_printf(&o, L_("ERROR: 未知工具「%s」（可用：read/write/edit/glob/grep/bash/rm/mv/mkdir）"), name);
			rc = -1;
		} else {
			rc = tool_task(&c, &a, &o);
		}
	} else if (!strcmp(name, OCC_T_RECALL)) {
		/* E6 第八工具：开关关=未知工具面；开=记忆检索 */
		if (!occ_orch_tools_enabled()) {
			occ_ob_printf(&o, L_("ERROR: 未知工具「%s」（可用：read/write/edit/glob/grep/bash/rm/mv/mkdir）"), name);
			rc = -1;
		} else {
			rc = tool_recall(&c, &a, &o);
		}
	} else {
		occ_ob_printf(&o, L_("ERROR: 未知工具「%s」（可用：read/write/edit/glob/grep/bash/rm/mv/mkdir%s%s%s）"), name,
			      occ_orch_tools_enabled() ? "/task" : "",
			      occ_orch_tools_enabled() ? "/recall" : "",
			      occ_netcfg_tools_enabled() ?
			      "/config_write_network" : "");
		rc = -1;
	}
w2_done:
	args_free(&a);
	t1 = occ_monotonic_ms();

	if (o.truncated) {
		/* 截断注记：缓冲已满，直接落尾部 slack（buf 容量
		 * MAX+256，len≤MAX，note≤96——必然放得下） */
		char note[96];
		size_t nl = (size_t)snprintf(note, sizeof(note), L_("\n…[truncated %zu B]"), o.total - o.len);

		if (o.len + nl + 1 <= sizeof(o.buf)) {
			memcpy(o.buf + o.len, note, nl + 1);
			o.len += nl;
		}
	}
	if (!o.len)
		occ_ob_puts(&o, L_("（无输出）"));
	out->text = strdup(o.buf[0] ? o.buf : L_("（无输出）"));
	out->rc = rc ? 1 : 0;
	out->dur_ms = t1 - t0;
	out->out_bytes = o.total;

	/* trace（永不阻断；失败仅 stderr 警告一次） */
	occ_trace_tool(c.trace_dir, c.session_id, c.msg_id, name,
		       args_json, out->rc, out->dur_ms, out->out_bytes);

	/* durable：occ_toolcall 行 + tool 结果消息单事务落库
	 * （先落库再回灌——loop 下轮从库重读） */
	if (c.db && c.session_id && c.msg_id) {
		char msg_id[OCC_ID_LEN];

		if (occ_tool_record(c.db, c.session_id, c.msg_id, name,
				    args_json ? args_json : "{}",
				    out->text, out->rc, out->dur_ms,
				    call_id, msg_id, sizeof(msg_id),
				    out->toolcall_id,
				    sizeof(out->toolcall_id),
				    err, sizeof(err)))
			fprintf(stderr, L_("occ-tool: durable record 失败：%s\n"), err);
	}
	return out->rc;
}
