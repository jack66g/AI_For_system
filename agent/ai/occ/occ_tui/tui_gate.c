/* SPDX-License-Identifier: GPL-2.0 */
/* tui_gate.c - T4 控制台登录门：crypt 凭据 + 独立 tui_screen 登录/向导 UI */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int gate_term_restore;
static struct termios gate_term_orig;

#include <crypt.h>

#include "tui_core.h"
#include "tui_input.h"
#include "tui_lang.h"
#include "tui_theme.h"
#include "tui_utf8.h"
#include "tui_gate.h"

#define GATE_USER "admin"
#define GATE_PW_MAX 64
#define GATE_USER_MAX 32		/* P-2a：用户名上限（含 NUL 边界） */
#define GATE_MAX_FAIL 3
#define GATE_COOLDOWN_SEC 10
#define GATE_ENTRY_MAX 256		/* P-2a：条目行数上限（防无界文件） */
#define GATE_CD_SLOTS 8			/* P-2a：冷却内存表槽数（逐用户） */

const char *tui_gate_path(void)
{
	const char *env = getenv("AIK_CONSOLE_GATE");

	if (env && env[0])
		return env;
	return "/etc/aikernel/console-gate";
}

int tui_gate_skipboot_path(const char *cmdline_path)
{
	FILE *f;
	char buf[4096];
	size_t n;

	f = fopen(cmdline_path, "r");
	if (!f)
		return 0;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	return strstr(buf, "ai.skipgate=1") != NULL;
}

int tui_gate_skipboot(void)
{
	return tui_gate_skipboot_path("/proc/cmdline");
}

/* ---- P-2a 多条目纯逻辑面 ----
 * 文件格式：每行 `name:$6$<sha512crypt>:<unix_ts>[:<fails>]`。
 * `#` 注释行与空行忽略；重名首行为准；坏行跳过（不炸整文件）；
 * 老式单行文件（admin 三段）就是 admin 条目（向后兼容）。
 * 内部读函数区分「文件不在」与「文件在无此用户」——UI 面需要
 * （文件消失=复位向导；无此用户=诚实登录失败）。 */
#define GATE_READ_OK		0
#define GATE_READ_NO_FILE	-1	/* 文件不存在（ENOENT/ENOTDIR） */
#define GATE_READ_NO_USER	-2	/* 文件在但无此用户（或全坏行） */
#define GATE_READ_BAD_ARG	-3	/* 参数坏 */
#define GATE_READ_DENIED	-4	/* P-60/D1：文件在却读不出（权限/非普通文件/IO） */

/* P-60/D1（CON-02b）：「读不了」≠「没有」。fopen 失败的 errno 分类——
 * 只有 ENOENT/ENOTDIR 才是「文件不在」（首次使用/管理员删文件=复位，
 * SETUP 向导语义）；EACCES/EPERM（及其它任何读不出）一律 DENIED：
 * 旧口径把它们也报成 NO_FILE，UI 便让读不了凭据的普通用户「设置
 * admin 密码」并吞掉后续键入（142 实机：gate 0600 root:root）。 */
int tui_gate_open_class(int err)
{
	if (err == ENOENT || err == ENOTDIR)
		return TUI_GATE_OPEN_ABSENT;
	return TUI_GATE_OPEN_DENIED;
}

/* 最近一次 GATE_READ_DENIED 的 errno（屏上「原因：」行用；gate 只在
 * 进主 TUI 前的主线程跑——与 gate_term_restore 同款单线程静态） */
static int gate_denied_errno;

/* 解析一行（就地改写 line）。返回 1=有效条目（name、hash 指入 line，
 * ts、fails 出参）；0=注释/空行（跳过）；-1=坏行（跳过）。 */
static int gate_parse_entry(char *line, char **name, char **hash,
			    long long *ts, int *fails)
{
	char *p1, *p2, *p3, *end;
	size_t hl;

	end = line + strlen(line);
	while (end > line && (end[-1] == '\n' || end[-1] == '\r'))
		*--end = '\0';
	if (line[0] == '\0' || line[0] == '#')
		return 0;
	p1 = strchr(line, ':');
	if (!p1)
		return -1;
	*p1++ = '\0';
	p2 = strchr(p1, ':');
	if (!p2)
		return -1;
	*p2++ = '\0';
	p3 = strchr(p2, ':');
	if (p3) {
		*p3++ = '\0';
		if (strchr(p3, ':'))
			return -1;		/* 第 5 段：坏行 */
	}
	if (line[0] == '\0')
		return -1;			/* 空名 */
	hl = strlen(p1);
	if (strncmp(p1, "$6$", 3) != 0 || hl >= TUI_GATE_HASH_LEN)
		return -1;
	*ts = strtoll(p2, NULL, 10);	/* 老口径：时间戳不严格校验 */
	if (p3) {
		char *q;
		long v;

		v = strtol(p3, &q, 10);
		if (*p3 == '\0' || *q != '\0' || v < 0 || v > 9999)
			return -1;
		*fails = (int)v;
	} else {
		*fails = 0;
	}
	*name = line;
	*hash = p1;
	return 1;
}

static int gate_read_user_full(const char *path, const char *user,
			       char hash_out[TUI_GATE_HASH_LEN],
			       long long *ts_out, int *fails_out)
{
	FILE *f;
	char line[512];
	char *name, *hash;
	long long ts;
	int fails;

	if (!path || !path[0] || !user || !user[0] || !hash_out)
		return GATE_READ_BAD_ARG;
	f = fopen(path, "r");
	if (!f) {
		if (tui_gate_open_class(errno) == TUI_GATE_OPEN_ABSENT)
			return GATE_READ_NO_FILE;
		gate_denied_errno = errno;	/* EACCES/EPERM/… */
		return GATE_READ_DENIED;
	}
	while (fgets(line, sizeof(line), f)) {
		if (gate_parse_entry(line, &name, &hash, &ts, &fails) != 1)
			continue;
		if (strcmp(name, user) == 0) {
			strcpy(hash_out, hash);	/* 长度已由解析钳制 */
			if (ts_out)
				*ts_out = ts;
			if (fails_out)
				*fails_out = fails;
			fclose(f);
			return GATE_READ_OK;
		}
	}
	if (ferror(f)) {
		/* fopen 过了但读不出（典型：路径是目录→read EISDIR；或
		 * IO 错）。P-60/D1：这不是「没有文件」——旧口径此处落到
		 * NO_USER，向导入口（tui_gate_read!=0）照样当首次使用。 */
		gate_denied_errno = errno ? errno : EIO;
		fclose(f);
		return GATE_READ_DENIED;
	}
	fclose(f);
	return GATE_READ_NO_USER;
}

/* 内部分类码 → 公开返回值：找到=0；文件在却读不出=TUI_GATE_READ_DENIED；
 * 其余（无此用户/坏文件/参数坏）=-1（既有调用方只判 0/非 0） */
static int gate_public_rc(int rd)
{
	if (rd == GATE_READ_OK)
		return 0;
	return rd == GATE_READ_DENIED ? TUI_GATE_READ_DENIED : -1;
}

int tui_gate_read_user(const char *path, const char *user,
		       char hash_out[TUI_GATE_HASH_LEN], int *fails_out)
{
	return gate_public_rc(gate_read_user_full(path, user, hash_out, NULL,
						  fails_out));
}

/* 老 API 保留：admin 语义委托新多条目面 */
int tui_gate_read(const char *path, char hash[128], long long *ts)
{
	return gate_public_rc(gate_read_user_full(path, GATE_USER, hash, ts,
						  NULL));
}

int tui_gate_hash(const char *pw, char out[128])
{
	static const char cs[] =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	char salt[32];
	unsigned char rnd[8];
	int fd, i;
	char *res;

	if (!pw || !*pw || strlen(pw) > GATE_PW_MAX)
		return -1;
	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0 || read(fd, rnd, sizeof(rnd)) != (ssize_t)sizeof(rnd)) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	close(fd);
	for (i = 0; i < 8; i++)
		salt[i] = cs[rnd[i] % (sizeof(cs) - 1)];
	salt[8] = '\0';
	snprintf(out, 128, "$6$%.8s$", salt);
	res = crypt(pw, out);
	if (!res || strlen(res) >= 128)
		return -1;
	snprintf(out, 128, "%s", res);
	return 0;
}

int tui_gate_verify(const char *pw, const char *hash)
{
	const char *res;
	const volatile unsigned char *a, *b;
	size_t la, lb, i;
	unsigned char d = 0;

	if (!pw || !hash || strncmp(hash, "$6$", 3) != 0)
		return 0;
	res = crypt(pw, hash);
	if (!res)
		return 0;
	a = (const volatile unsigned char *)res;
	b = (const volatile unsigned char *)hash;
	la = strlen(res);
	lb = strlen(hash);
	d |= (unsigned char)(la ^ lb);
	for (i = 0; i < la && i < lb; i++)
		d |= (unsigned char)(a[i] ^ b[i]);
	return d == 0;
}

/* 用户名合法性（写侧与输入侧同一口径）：非空、<GATE_USER_MAX、
 * 可见 ASCII 且不含 ':'、不以 '#' 开头（防注释行歧义）。 */
static int gate_user_valid(const char *user)
{
	size_t i, n;

	if (!user)
		return 0;
	n = strlen(user);
	if (n == 0 || n >= GATE_USER_MAX || user[0] == '#')
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)user[i];

		if (c < 33 || c > 126 || c == ':')
			return 0;
	}
	return 1;
}

static void gate_emit_entry(FILE *f, const char *user, const char *hash,
			    int fails)
{
	if (fails > 0)
		/* 四段：计数入行（读侧第 4 段存取） */
		fprintf(f, "%s:%s:%lld:%d\n", user, hash,
			(long long)time(NULL), fails);
	else
		/* 三段：与老写字节形态一致（fails=0 不落段） */
		fprintf(f, "%s:%s:%lld\n", user, hash, (long long)time(NULL));
}

int tui_gate_write_entry(const char *path, const char *user,
			 const char *hash, int fails)
{
	char tmp[512];
	FILE *in = NULL, *out;
	char line[512];
	int found = 0, nlines = 0;

	if (!path || !path[0] || !gate_user_valid(user) || !hash ||
	    strncmp(hash, "$6$", 3) != 0 ||
	    strlen(hash) >= TUI_GATE_HASH_LEN || fails < 0)
		return -1;
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	in = fopen(path, "r");		/* 不在=新建文件（追加语义） */
	if (!in && tui_gate_open_class(errno) != TUI_GATE_OPEN_ABSENT) {
		/* P-60/D1：既有文件在却读不出（权限/非普通文件/IO）——拒写。
		 * 读不到既有条目就无从「其余行原样保留」，硬写=整文件覆写
		 * 丢他人条目（目录可写时真能写成）。调用方按写失败处理。 */
		return -1;
	}
	out = fopen(tmp, "w");
	if (!out) {
		if (in)
			fclose(in);
		return -1;
	}
	if (in) {
		while (fgets(line, sizeof(line), in)) {
			char work[512], *name, *hash2;
			long long ts2;
			int fails2;
			int r;

			memcpy(work, line, sizeof(work));
			r = gate_parse_entry(work, &name, &hash2, &ts2,
					     &fails2);
			if (!found && r == 1 && strcmp(name, user) == 0) {
				/* 重名首行=更新点；其余重名行原样保留
				 *（读侧首行为准，更新后仍居首） */
				gate_emit_entry(out, user, hash, fails);
				found = 1;
			} else {
				fputs(line, out);
				if (!strchr(line, '\n'))
					fputc('\n', out);	/* 末行无换行 */
			}
			if (++nlines > GATE_ENTRY_MAX) {
				fclose(in);
				fclose(out);
				unlink(tmp);
				return -1;	/* 无界文件拒写（防截断用户数据） */
			}
		}
		/* P-60/D1：既有文件读一半出错（IO）——半份内容不得写回
		 * （与上面「读不出拒写」同一口径：宁拒不丢条目） */
		if (ferror(in)) {
			fclose(in);
			fclose(out);
			unlink(tmp);
			return -1;
		}
		fclose(in);
	}
	if (!found)
		gate_emit_entry(out, user, hash, fails);
	if (fflush(out) != 0 || fclose(out) != 0) {
		unlink(tmp);
		return -1;
	}
	chmod(tmp, 0600);
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

/* 老 API 保留：admin 语义（向导建密）——多条目文件下只动 admin 行 */
int tui_gate_write(const char *path, const char *hash)
{
	return tui_gate_write_entry(path, GATE_USER, hash, 0);
}

/* ---- P-2a：上次成功用户（登录框预填） ---- */
static const char *gate_last_path(void)
{
	const char *env = getenv("AIK_CONSOLE_GATE_LAST");

	if (env && env[0])
		return env;
	return "/var/lib/aikernel/console-gate.last";
}

/* 预填读侧严格净化：仅 [A-Za-z0-9._-] 且 <GATE_USER_MAX——防被改
 * 文件注入控制字节/冒号进输入框；坏内容回落 admin。 */
static void gate_last_read(char out[GATE_USER_MAX])
{
	FILE *f;
	char line[128];
	size_t i;
	int ok = 1;

	f = fopen(gate_last_path(), "r");
	if (f && fgets(line, sizeof(line), f)) {
		char *end = line + strlen(line);

		while (end > line && (end[-1] == '\n' || end[-1] == '\r'))
			*--end = '\0';
		if (line[0] == '\0' || strlen(line) >= GATE_USER_MAX)
			ok = 0;
		for (i = 0; ok && line[i]; i++) {
			char c = line[i];

			if (!((c >= 'a' && c <= 'z') ||
			      (c >= 'A' && c <= 'Z') ||
			      (c >= '0' && c <= '9') ||
			      c == '.' || c == '_' || c == '-'))
				ok = 0;
		}
		if (ok)
			snprintf(out, GATE_USER_MAX, "%s", line);
	} else {
		ok = 0;
	}
	if (f)
		fclose(f);
	if (!ok || !out[0])
		snprintf(out, GATE_USER_MAX, "%s", GATE_USER);
}

/* 尽力而为（/var/lib 不可写不碍登录）；原子写 0600 */
static void gate_last_write(const char *user)
{
	char tmp[512];
	const char *p = gate_last_path();
	FILE *f;

	if (!gate_user_valid(user))
		return;
	snprintf(tmp, sizeof(tmp), "%s.tmp", p);
	f = fopen(tmp, "w");
	if (!f)
		return;
	fprintf(f, "%s\n", user);
	if (fflush(f) != 0 || fclose(f) != 0) {
		unlink(tmp);
		return;
	}
	chmod(tmp, 0600);
	if (rename(tmp, p) != 0)
		unlink(tmp);
}

/* ---- UI ---- */

struct gate_field {
	char buf[GATE_PW_MAX];
	int len;
};

static void draw_center(tui_screen *s, int row, int cols,
			const char *txt, tui_attr a)
{
	/* q17 audit A-5：按显示列居中（字节长度会把 CJK 行整体推右） */
	int c = (cols - (int)tui_utf8_cols(txt)) / 2;

	if (c < 0)
		c = 0;
	tui_screen_puts(s, row, c + 1, txt, a);
}

static void draw_masked(tui_screen *s, int row, int cols,
			const struct gate_field *f, int active)
{
	char stars[GATE_PW_MAX + 3];
	int i, c;
	tui_attr a = tui_thm_attr(TUI_THM_FG, TUI_THM_USER_BG, 0);

	for (i = 0; i < f->len; i++)
		stars[i] = '*';
	stars[f->len] = active ? '_' : ' ';
	stars[f->len + 1] = '\0';
	c = (cols - 40) / 2;
	if (c < 1)
		c = 1;
	tui_screen_puts(s, row, c, "                                      ", a);
	tui_screen_puts(s, row, c, stars, a);
}

/* P-2a：用户名框（明文+光标；与密码框同 40 列几何） */
static void draw_user_field(tui_screen *s, int row, int cols,
			    const struct gate_field *f, int active)
{
	char txt[GATE_PW_MAX + 3];
	int i, c;
	tui_attr a = tui_thm_attr(TUI_THM_FG, TUI_THM_USER_BG, 0);

	for (i = 0; i < f->len; i++)
		txt[i] = f->buf[i];
	txt[f->len] = active ? '_' : ' ';
	txt[f->len + 1] = '\0';
	c = (cols - 40) / 2;
	if (c < 1)
		c = 1;
	tui_screen_puts(s, row, c, "                                      ", a);
	tui_screen_puts(s, row, c, txt, a);
}

static void box_frame(tui_screen *s, int rows, int cols)
{
	int r0 = rows / 2 - 6, r1 = rows / 2 + 5;
	int c0 = (cols - 44) / 2, c1 = c0 + 43, r, c;
	tui_attr border = tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG, 0);
	tui_attr bg = tui_thm_attr(TUI_THM_FG, TUI_THM_BG, 0);

	if (r0 < 0)
		r0 = 0;
	if (c0 < 0)
		c0 = 0;
	for (c = c0; c <= c1 && c < cols; c++) {
		tui_screen_puts(s, r0, c, c == c0 ? "+" :
				(c == c1 ? "+" : "-"), border);
		tui_screen_puts(s, r1, c, c == c0 ? "+" :
				(c == c1 ? "+" : "-"), border);
	}
	for (r = r0 + 1; r < r1 && r < rows; r++) {
		tui_screen_puts(s, r, c0, "|", border);
		tui_screen_puts(s, r, c1, "|", border);
	}
	(void)bg;
}

#define GATE_MODE_SETUP 0
#define GATE_MODE_LOGIN 1
#define GATE_MODE_DENIED 2	/* P-60/D1：凭据在却读不出——诚实报错屏
				 * （绝不进 SETUP）；按键后 TUI_GATE_DENIED 退出 */

/* 读不出原因 → 诚实人话（屏上「原因：」行）。按 errno 分类出固定文案
 * ——不引 strerror（随 locale 漂移，屏宽 44 列也放不下）。 */
static const char *gate_denied_reason(void)
{
	switch (gate_denied_errno) {
	case EACCES:
	case EPERM:
		return L_("权限不足");
	case EISDIR:
		return L_("凭据文件不是普通文件");
	default:
		return L_("读取错误");
	}
}

/* 转「凭据不可读」报错屏前填原因行（入口与中途切换两处共用） */
static void gate_denied_note(char *note, size_t notelen)
{
	snprintf(note, notelen, L_("原因：%s"), gate_denied_reason());
}

/* 单事件字段编辑（字符/退格/Esc/Ctrl-C）。max_len=字段容量；
 * no_colon=用户名字段禁 ':'（文件格式分隔符）。 */
static void gate_field_edit(const tui_event *ev, struct gate_field *f,
			    int max_len, int no_colon, int *quit)
{
	if (ev->key != TUI_KEY_CHAR) {
		if (ev->key == TUI_KEY_BACKSPACE) {
			if (f->len > 0)
				f->len--;
		} else if (ev->key == TUI_KEY_ESCAPE) {
			*quit = 1;
		}
		return;
	}
	if ((ev->mods & TUI_MOD_CTRL) && (ev->ch == 'c' || ev->ch == 'C')) {
		*quit = 1;
		return;
	}
	if (ev->ch >= 32 && ev->ch < 127 && f->len < max_len - 1 &&
	    !(no_colon && ev->ch == ':'))
		f->buf[f->len++] = (char)ev->ch;
}

static int gate_field_input(tui_input *in, struct gate_field *f, int *done,
			    int *quit)
{
	tui_event ev;

	*done = 0;
	*quit = 0;
	if (tui_input_next(in, &ev) <= 0)
		return 0;
	if (ev.type != TUI_EV_KEY)
		return 0;
	if (ev.key == TUI_KEY_RETURN) {
		*done = 1;
		return 0;
	}
	gate_field_edit(&ev, f, GATE_PW_MAX, 0, quit);
	return 0;
}

/* P-2a：LOGIN 双框输入路由。Tab/上/下=切框（与既有键位习惯兼容：
 * 缺省焦点密码框——直接打密码+Enter 即登录，老肌肉记忆不动）；
 * 用户名框 Enter=跳密码框；密码框 Enter=提交。 */
static int gate_login_input(tui_input *in, struct gate_field *uf,
			    struct gate_field *pf, int *focus_user,
			    int *done, int *quit)
{
	tui_event ev;

	*done = 0;
	*quit = 0;
	if (tui_input_next(in, &ev) <= 0)
		return 0;
	if (ev.type != TUI_EV_KEY)
		return 0;
	if (ev.key == TUI_KEY_TAB || ev.key == TUI_KEY_UP ||
	    ev.key == TUI_KEY_DOWN) {
		*focus_user ^= 1;
		return 0;
	}
	if (ev.key == TUI_KEY_RETURN) {
		if (*focus_user) {
			*focus_user = 0;
			return 0;
		}
		*done = 1;
		return 0;
	}
	gate_field_edit(&ev, *focus_user ? uf : pf,
			*focus_user ? GATE_USER_MAX : GATE_PW_MAX,
			*focus_user, quit);
	return 0;
}

/* P-2a：逐用户冷却内存表（非阻塞——A 冷却不牵连 B 登录；
 * 表小固定，溢出挤 0 号（粗粒度可接受）） */
struct gate_cd {
	char name[GATE_USER_MAX];
	uint64_t until;
	int fails;		/* P-60：进程内失败计数（非 root 组只读面） */
};

static int gate_cd_find(const struct gate_cd *tab, const char *name)
{
	int i;

	for (i = 0; i < GATE_CD_SLOTS; i++)
		if (tab[i].name[0] && strcmp(tab[i].name, name) == 0)
			return i;
	return -1;
}

/* P-60：失败计数入内存槽（找位或建位；不动 until——冷却由 arm 管）。
 * 满 8 槽丢计数不炸（冷却表兜底仍在）。 */
static void gate_cd_note(struct gate_cd *tab, const char *name,
			 int fails)
{
	int i = gate_cd_find(tab, name);

	if (i < 0) {
		for (i = 0; i < GATE_CD_SLOTS && tab[i].name[0]; i++)
			;
		if (i == GATE_CD_SLOTS)
			return;
		snprintf(tab[i].name, sizeof(tab[i].name), "%s", name);
		tab[i].until = 0;
	}
	tab[i].fails = fails;
}

static void gate_cd_arm(struct gate_cd *tab, const char *name,
			uint64_t until)
{
	int i = gate_cd_find(tab, name);

	if (i < 0) {
		for (i = 0; i < GATE_CD_SLOTS && tab[i].name[0]; i++)
			;
		if (i == GATE_CD_SLOTS)
			i = 0;
		snprintf(tab[i].name, GATE_USER_MAX, "%s", name);
	}
	tab[i].until = until;
}

/* q17 实机抓获（audit A-1，致命）：gate 只出队（tui_input_next）不进队
 * ——无人调 tui_input_feed，首屏画完即冻死、CPU 空转，掩码/两段确认/
 * 3 错冷却在实机全部不可达（串口日志实证：喂键后零掩码重绘零状态变化）。
 * 补上主 TUI 同源的 poll→read→feed 泵（tui_view.c 输入口径）；
 * EOF/读错按主 TUI 惯例退出（termios 由收尾路径恢复）。 */
static uint64_t gate_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void gate_pump_input(tui_input *in, int *quit)
{
	struct pollfd pfd;
	char buf[256];
	ssize_t r;

	pfd.fd = STDIN_FILENO;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, 30) <= 0)
		return;
	if (!(pfd.revents & (POLLIN | POLLHUP)))
		return;
	r = read(STDIN_FILENO, buf, sizeof(buf));
	if (r > 0)
		(void)tui_input_feed(in, buf, (size_t)r, gate_now_ms());
	else if (r == 0 || (errno != EINTR && errno != EAGAIN))
		*quit = 1;
}

/* P-41/P-44：gate 输出致命（wd -2 / IO -1）——gate 在 view 之前、无会话
 * 无清理链：还原 termios → 人话 stderr → 释放渲染器（含缓冲）→
 * exit(72)。aik-console v7 对 72 循环 2s 重启整链（gate 卡死同治）。 */
static void gate_sink_fatal(tui_renderer *ren, int frc)
{
	if (gate_term_restore) {
		tcsetattr(STDIN_FILENO, TCSANOW, &gate_term_orig);
		gate_term_restore = 0;
	}
	/* 楔死终端上缓冲无保序意义：丢弃并还原 fd flags（防 exit 路径
	 * 再碰非阻塞描述） */
	tui_sink_drain(&ren->sink);
	tui_sink_set_blocking(&ren->sink);
	if (frc == -2)
		fprintf(stderr,
			L_("occ-tui: 输出看门狗 %dms 无消费（fbterm 楔死？）——退出重启\n"),
			ren->sink.wd_ms);
	else
		fputs(L_("occ-tui: 输出 IO 错误（fbterm/pty 消亡？）——退出重启\n"), stderr);
	tui_renderer_destroy(ren);
	/* P-41/P-44d：exit 前击毙楔死的 fbterm 父进程（单点、恰一次；
	 * 时机取舍同 tui_view_run 收口——人话行已落 stderr 文件） */
	tui_out_fatal_kill_parent();
	exit(72);
}

/* 登录框用户名预填（last 文件净化后入框） */
static void gate_user_prefill(struct gate_field *uf)
{
	char pre[GATE_USER_MAX];

	gate_last_read(pre);
	memset(uf, 0, sizeof(*uf));
	uf->len = (int)strlen(pre);
	if (uf->len >= GATE_PW_MAX)
		uf->len = GATE_PW_MAX - 1;
	memcpy(uf->buf, pre, (size_t)uf->len + 1);
}

static int gate_run_ui(int mode, int *unlocked)
{
	tui_sink sink;
	tui_renderer *ren;
	tui_input in;
	tui_screen *s;
	int rows, cols, rc = 1;
	struct gate_field f1, f2;
	struct gate_field uf;		/* P-2a：用户名框（LOGIN） */
	int focus_user = 0;		/* 缺省焦点=密码框（老习惯兼容） */
	int stage = 0;			/* setup: 0=首次输入 1=确认输入 */
	struct gate_cd cd_tab[GATE_CD_SLOTS];
	char hash[TUI_GATE_HASH_LEN];
	char login_note[160] = "";	/* 一次性状态（SETUP→LOGIN 切换说明） */
	char denied_note[160] = "";	/* P-60/D1：凭据不可读原因行（报错屏） */
	int hb_ms;			/* P-41/P-44b：空闲心跳周期（0=禁用） */
	uint64_t hb_next;		/* 下次心跳探针到点 */
	tui_attr title_a = tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG, 0);
	tui_attr txt_a = tui_thm_attr(TUI_THM_FG, TUI_THM_BG, 0);
	tui_attr mut_a = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG, 0);
	tui_attr err_a = tui_thm_attr(TUI_THM_ERROR, TUI_THM_BG, 0);

	*unlocked = 0;
	memset(&cd_tab, 0, sizeof(cd_tab));
	/* T4 勘误（实机抓获）：tty 默认 ECHO+ICANON 会把密码明文回显到屏上
	 * （gate 自绘掩码之外的第二份）——进 UI 前关回显转 raw（同 occ 主
	 * TUI 口径），退出恢复。 */
	{
		struct termios orig, raw;

		if (tcgetattr(STDIN_FILENO, &orig) == 0) {
			raw = orig;
			raw.c_lflag &= ~(unsigned)(ECHO | ICANON | ISIG);
			raw.c_iflag &= ~(unsigned)(IXON | ICRNL);
			raw.c_cc[VMIN] = 1;
			raw.c_cc[VTIME] = 0;
			tcsetattr(STDIN_FILENO, TCSANOW, &raw);
			gate_term_restore = 1;
			gate_term_orig = orig;
		}
	}
	if (tui_term_get_size(STDIN_FILENO, &rows, &cols) != 0) {
		rows = 24;
		cols = 80;
	}
	/* P-41/P-44：fd 缓冲汇+看门狗（同主 TUI 口径——gate 也吃同一个
	 * fbterm 楔死面：整帧一批次，15s 无消费 exit(72) 自愈） */
	if (tui_sink_init_fd_buf(&sink, STDOUT_FILENO) != 0) {
		if (gate_term_restore)
			tcsetattr(STDIN_FILENO, TCSANOW, &gate_term_orig);
		return 1;
	}
	ren = tui_renderer_create(rows, cols, sink);
	if (!ren) {
		/* q17 audit A-2：raw 已置位后的失败路径必须还 termios */
		tui_sink_fini(&sink);
		if (gate_term_restore)
			tcsetattr(STDIN_FILENO, TCSANOW, &gate_term_orig);
		return 1;
	}
	s = tui_renderer_front(ren);
	tui_input_init(&in);

	memset(&f1, 0, sizeof(f1));
	memset(&f2, 0, sizeof(f2));
	memset(&uf, 0, sizeof(uf));
	if (mode == GATE_MODE_LOGIN)
		gate_user_prefill(&uf);
	if (mode == GATE_MODE_DENIED)
		gate_denied_note(denied_note, sizeof(denied_note));
	/* P-41/P-44c：空闲心跳——gate 静止等待输入时零帧输出，wd 无从
	 * 计时（真机实测：静止 gate strace 12s 零 write）；时间基准每
	 * OCC_TUI_HB_MS（缺省 5000，0=禁用，钳位 [0,600000]）发体量
	 * 心跳（56KB SGR 复位拍+cur_attr 重放，零视觉——小探针会被
	 * pty 缓冲整吞检测不出楔死，见 tui_renderer_heartbeat）检测
	 * 消费端。规格原文按「sleep(1)×5 次一跳」计数——本循环实为
	 * ~30ms/迭代（输入泵 poll 30ms），计数会 150ms 一跳刷屏，按
	 * 时间基准实现同一 5s 语义（冷却内环 sleep(1) 同样覆盖）。 */
	hb_ms = 5000;
	{
		const char *e = getenv("OCC_TUI_HB_MS");

		if (e && e[0]) {
			long hv = strtol(e, NULL, 10);

			if (hv >= 0 && hv <= 600000)
				hb_ms = (int)hv;
		}
	}
	hb_next = gate_now_ms() + (uint64_t)hb_ms;
	for (;;) {
		int done = 0, quit = 0;
		const char *status;
		static char status_buf[160];

		if (hb_ms > 0 && gate_now_ms() >= hb_next) {
			int prc = tui_renderer_heartbeat(ren);

			hb_next = gate_now_ms() + (uint64_t)hb_ms;
			if (prc == -2 || prc == -1)
				gate_sink_fatal(ren, prc);
		}
		tui_screen_fill(s, tui_thm_attr(TUI_THM_FG, TUI_THM_BG, 0));
		box_frame(s, rows, cols);
		if (mode == GATE_MODE_SETUP) {
			draw_center(s, rows / 2 - 4, cols,
				    L_("AIKernel 初始化"), title_a);
			draw_center(s, rows / 2 - 3, cols,
				    L_("首次使用：设置 admin 密码（≥6 位）"), mut_a);
			draw_center(s, rows / 2 - 2, cols,
				    stage == 0 ? L_("设置密码：") : L_("确认密码："),
				    txt_a);
			draw_masked(s, rows / 2 - 1, cols,
				    stage == 0 ? &f1 : &f2, 1);
			status = status_buf;
			draw_center(s, rows / 2 + 1, cols, status,
				    status[0] ? err_a : txt_a);
			draw_center(s, rows / 2 + 3, cols,
				    L_("配置云端模型：解锁后 /models"), mut_a);
			draw_center(s, rows / 2 + 4, cols,
				    L_("本地模型：/models 选 ollama"), mut_a);
		} else if (mode == GATE_MODE_LOGIN) {
			/* P-2a：用户名框（预填 last）+密码框双字段；
			 * 布局自上而下：用户标签/用户框/密码标签/掩码框 */
			draw_center(s, rows / 2 - 4, cols,
				    "AIKernel · alpha", title_a);
			draw_center(s, rows / 2 - 3, cols,
				    L_("用户："), txt_a);
			draw_user_field(s, rows / 2 - 2, cols, &uf,
					focus_user);
			draw_center(s, rows / 2 - 1, cols, L_("密码："), txt_a);
			draw_masked(s, rows / 2, cols, &f1, !focus_user);
			if (login_note[0]) {
				snprintf(status_buf, sizeof(status_buf), "%s",
					 login_note);
				login_note[0] = '\0';
			}
			status = status_buf;
			draw_center(s, rows / 2 + 1, cols, status,
				    status[0] ? err_a : txt_a);
			draw_center(s, rows / 2 + 3, cols,
				    L_("Enter 登录 · Tab 切换 · Ctrl-C 退出"), mut_a);
		} else if (mode == GATE_MODE_DENIED) {
			/* P-60/D1（CON-02b）：凭据在却读不出——绝不进 SETUP
			 * （旧口径把读失败当「文件不在」，读不了凭据的普通
			 * 用户被引导「设置 admin 密码」、后续键入被向导吞）。
			 * 诚实报错；任意一键后非零退出——aik-console 记账后
			 * 重启循环，控制台仍处锁定态。 */
			draw_center(s, rows / 2 - 4, cols,
				    "AIKernel · alpha", title_a);
			draw_center(s, rows / 2 - 3, cols,
				    L_("登录凭据不可读——请联系管理员"), err_a);
			draw_center(s, rows / 2 - 2, cols, denied_note, mut_a);
			draw_center(s, rows / 2 + 3, cols,
				    L_("按任意键退出"), mut_a);
		}
		{
			int frc = tui_renderer_flush(ren, rows / 2 - 1,
						     cols / 2);

			if (frc == -2 || frc == -1)
				gate_sink_fatal(ren, frc);
		}
		gate_pump_input(&in, &quit);
		if (quit) {
			rc = 1;
			break;
		}

		if (mode == GATE_MODE_DENIED) {
			tui_event ev;

			/* 报错屏：等任意一键再退（屏可读；不自旋自退——
			 * 否则 2s 重启循环会把报错刷成闪烁） */
			if (tui_input_next(&in, &ev) > 0 && ev.type == TUI_EV_KEY) {
				rc = TUI_GATE_DENIED;
				break;
			}
			continue;
		}

		if (mode == GATE_MODE_SETUP) {
			gate_field_input(&in, stage == 0 ? &f1 : &f2,
					 &done, &quit);
			if (quit) {
				rc = 1;
				break;
			}
			if (done) {
					if (stage == 0) {
						if (f1.len < 6) {
							snprintf(status_buf,
								 sizeof(status_buf),
								 "%s", L_("密码至少 6 位，重输"));
							memset(&f1, 0, sizeof(f1));
						} else {
							stage = 1;
							snprintf(status_buf,
								 sizeof(status_buf),
								 "%s", L_("再输入一次确认"));
						}
					} else {
						if (strcmp(f1.buf, f2.buf) != 0) {
							snprintf(status_buf,
								 sizeof(status_buf),
								 "%s", L_("两次不一致，重新设置"));
							memset(&f1, 0, sizeof(f1));
							memset(&f2, 0, sizeof(f2));
							stage = 0;
						} else {
							/* 提交前复核只读这一次（分类与
							 * 「已被设置」共用同一读——双读留缝） */
							int rrd = tui_gate_read(tui_gate_path(),
									 hash, NULL);

							if (rrd == TUI_GATE_READ_DENIED) {
								/* P-60/D1：凭据在却读不出（如
								 * 另一控制台刚建好 0600）——不
								 * 覆写、也不谎称写入失败：转
								 * 诚实报错屏（写侧对读不出的
								 * 既有文件同样拒写） */
								mode = GATE_MODE_DENIED;
								memset(&f1, 0, sizeof(f1));
								memset(&f2, 0, sizeof(f2));
								stage = 0;
								gate_denied_note(denied_note,
										 sizeof(denied_note));
								continue;
							} else if (rrd == 0) {
								/* q17 覆写探针实机抓获：双
								 * 控制台并发 SETUP，后到者会
								 * 静默覆写先设好的密码。提交
								 * 前重读凭据——已被其他控制
								 * 台设置则不覆写，转 LOGIN。 */
								mode = GATE_MODE_LOGIN;
								memset(&f1, 0, sizeof(f1));
								memset(&f2, 0, sizeof(f2));
								gate_user_prefill(&uf);
								focus_user = 0;
								stage = 0;
								snprintf(login_note,
									 sizeof(login_note),
									 "%s", L_("密码已由其他控制台设置，请登录"));
								continue;
							} else if (tui_gate_hash(f1.buf,
										 hash) == 0 &&
								   tui_gate_write(
									   tui_gate_path(),
									   hash) == 0) {
								gate_last_write(GATE_USER);
								*unlocked = 1;
								rc = 0;
								break;
							} else {
								snprintf(status_buf,
									 sizeof(status_buf),
									 "%s", L_("写入失败（权限？）"));
								memset(&f2, 0, sizeof(f2));
							}
							}
					}
				}
			continue;
		}
		/* LOGIN（P-2a：用户名+密码提交；失败计数按用户行第 4 段
		 * 存取；3 错 10s 冷却逐用户独立——A 冷却不阻塞 B） */
		gate_login_input(&in, &uf, &f1, &focus_user, &done, &quit);
		if (quit) {
			rc = 1;
			break;
		}
		if (done) {
			char uname[GATE_USER_MAX];
			int file_fails = 0;
			int rd;

			memcpy(uname, uf.buf, (size_t)uf.len);
			uname[uf.len] = '\0';
			rd = gate_read_user_full(tui_gate_path(), uname,
						 hash, NULL, &file_fails);
			if (rd == GATE_READ_NO_FILE) {
				/* 文件消失（管理员删除=复位）→ 转向导 */
				mode = GATE_MODE_SETUP;
				memset(&f1, 0, sizeof(f1));
				stage = 0;
				status_buf[0] = '\0';	/* q17 audit A-8 */
				continue;
			}
			if (rd == GATE_READ_DENIED) {
				/* P-60/D1：文件在却读不出（权限/非普通
				 * 文件/IO）→ 诚实报错屏；绝不转 SETUP
				 * （CON-02b：读不了≠没有）。清密码框，
				 * 不留残影。 */
				mode = GATE_MODE_DENIED;
				memset(&f1, 0, sizeof(f1));
				status_buf[0] = '\0';
				gate_denied_note(denied_note,
						 sizeof(denied_note));
				continue;
			}
			if (uf.len == 0) {
				snprintf(status_buf, sizeof(status_buf),
					 "%s", L_("请输入用户名"));
				continue;
			}
			if (rd != GATE_READ_OK) {
				/* 文件在但无此用户：不枚举用户名的统一
				 * 失败文案（计数无处落——不伪造进度） */
				snprintf(status_buf, sizeof(status_buf),
					 "%s", L_("用户名或密码不正确"));
				memset(&f1, 0, sizeof(f1));
				continue;
			}
			{
				int ci = gate_cd_find(cd_tab, uname);
				uint64_t now_ms = gate_now_ms();
				int mem_fails = ci >= 0 ? cd_tab[ci].fails : 0;

				if (ci >= 0) {
					if (now_ms < cd_tab[ci].until) {
						long long left = (long long)
							((cd_tab[ci].until -
							  now_ms + 999) / 1000);

						snprintf(status_buf,
							 sizeof(status_buf),
							 L_("冷却中（%lld 秒后再试）"),
							 left);
						memset(&f1, 0, sizeof(f1));
						continue;
					}
					/* 冷却期满：清该用户计数（文件+
					 * 内存）——冷却后计数清零口径。
					 * P-60：仅真武装过的槽（until>0）走
					 * 此路——gate_cd_note 的纯计数槽
					 * （until=0）不得误触清零。 */
					if (cd_tab[ci].until > 0) {
					cd_tab[ci].name[0] = '\0';
					cd_tab[ci].fails = 0;
					mem_fails = 0;
					(void)tui_gate_write_entry(
						tui_gate_path(), uname,
						hash, 0);
					file_fails = 0;
					}
				}
				/* P-60：有效计数=文件与内存取大——非 root（gate 0640 */
				/* 组只读）文件写不进恒 0，内存计数保 per-boot 锁定； */
				/* root 侧文件持久计数跨重启优先生效 */
				if ((file_fails > mem_fails ? file_fails : mem_fails)
				    >= GATE_MAX_FAIL) {
					/* 文件残留计数≥3（如 gate 进程
					 * 重启）：重启不清锁——重新起算
					 * 10s 冷却（诚实防绕） */
					gate_cd_arm(cd_tab, uname,
						    now_ms + (uint64_t)
						    GATE_COOLDOWN_SEC * 1000u);
					snprintf(status_buf,
						 sizeof(status_buf),
						 L_("尝试过多，冷却 %d 秒…"),
						 GATE_COOLDOWN_SEC);
					memset(&f1, 0, sizeof(f1));
					continue;
				}
				if (f1.len > 0 && tui_gate_verify(f1.buf, hash)) {
					(void)tui_gate_write_entry(
						tui_gate_path(), uname,
						hash, 0);	/* 计数清零 */
					gate_last_write(uname);
					*unlocked = 1;
					rc = 0;
					break;
				}
				{
					int nf = (file_fails > mem_fails ? file_fails : mem_fails)
					    + 1;

					(void)tui_gate_write_entry(
						tui_gate_path(), uname,
						hash, nf);
					gate_cd_note(cd_tab, uname, nf);
					if (nf >= GATE_MAX_FAIL) {
						gate_cd_arm(cd_tab, uname,
							    gate_now_ms() +
							    (uint64_t)
							    GATE_COOLDOWN_SEC *
							    1000u);
						snprintf(status_buf,
							 sizeof(status_buf),
							 L_("尝试过多，冷却 %d 秒…"),
							 GATE_COOLDOWN_SEC);
					} else {
						snprintf(status_buf,
							 sizeof(status_buf),
							 L_("密码不正确（%d/%d）"),
							 nf, GATE_MAX_FAIL);
					}
				}
			}
			memset(&f1, 0, sizeof(f1));
			/* q17 实机抓获：msg 曾是循环顶每帧置空的局部量，
			 * LOGIN 画面前状态就被清空——错误消息从未上过屏。
			 * 改直接写 status_buf（SETUP 口径）。 */
		}
	}
	if (gate_term_restore)
		tcsetattr(STDIN_FILENO, TCSANOW, &gate_term_orig);
	/* P-41/P-44：正常退出同样还原 fd flags（后续 occ 主 TUI 自会重置
	 * 自己的缓冲汇；不留非阻塞描述给无关使用者） */
	tui_sink_set_blocking(&ren->sink);
	tui_renderer_destroy(ren);
	return rc;
}

int tui_gate_enter(void)
{
	char hash[TUI_GATE_HASH_LEN];
	long long ts;
	int unlocked;

	/* 旁路：引导参数（ISO 烟测）或环境标记（pty 集成测试注入；
	 * 物理接触者本可旁路，非漏洞） */
	if (tui_gate_skipboot())
		return 0;
	{
		const char *e = getenv("AIK_CONSOLE_GATE_SKIP");
		if (e && e[0] && strcmp(e, "0") != 0)
			return 0;
	}
	/* admin 条目在=LOGIN（多用户框）；不在=SETUP 向导（仍建 admin）；
	 * P-60/D1：文件在却读不出（权限/非普通文件/IO）=诚实报错屏——
	 * 绝不进 SETUP（旧口径读失败一律当「文件不在」） */
	{
		int rd = tui_gate_read(tui_gate_path(), hash, &ts);

		if (rd == TUI_GATE_READ_DENIED)
			return gate_run_ui(GATE_MODE_DENIED, &unlocked);
		if (rd != 0)
			return gate_run_ui(GATE_MODE_SETUP, &unlocked);
	}
	return gate_run_ui(GATE_MODE_LOGIN, &unlocked);
}
