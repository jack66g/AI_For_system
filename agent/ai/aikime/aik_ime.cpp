// aik-ime — AIKernel 中文输入法 server（fbterm 1.7 IME 协议 × librime）
//
// 拉起：fbterm -i aik-ime（出厂 PATH）或 fbterm -i /usr/local/bin/aik-ime。
// fbterm 每个 shell fork 一个 IM 进程，本进程单实例单 rime 会话。
//
// 协议契约（fbterm-1.7/src/immessage.h 正典，见 im_proto.h）：
//   Connect(raw=0) → FbTermInfo(像素屏参) → [Active → SetWin(贴底 3 行窗)
//   → AckWin → FillRect/DrawText(像素坐标，256 调色板)] → SendKey(UTF-8
//   字节流) → librime → PutText(提交/透传)；Ping↔AckPing；HideUI→
//   AckHideUI；ShowUI→重挂窗；Deactive→SetWin(空)收窗；Disconnect/EOF 退出。
//
// raw=0 的含义：IM 激活期键流=内核 K_UNICODE 翻译后的 UTF-8 字节
// （Ctrl+Space 等 syskey 被 fbterm 抽走不过来；方向键/PgUp/PgDn 以
// CSI 序列到达，本进程自解为 X11 keysym 喂 rime；rime 不吃的键映射回
// 原字节/序列 PutText 透传——IM 常开时英文/回车/退格照常可用）。
//
// env：
//   FBTERM_IM_SOCKET  fbterm 传入的 socketpair fd（必填）
//   AIK_IME_DATA      rime 共享数据目录（缺省 /usr/share/rime-data）
//   AIK_IME_SCHEMA    rime 方案 id（缺省 luna_pinyin）
//   AIK_IME_USERDIR   rime 用户数据目录（缺省 ~/.config/aik-ime）
//   AIK_IME_DEBUG     =1 开 stderr 协议日志

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "im_proto.h"

extern "C" {
#include <rime_api.h>
}

/* ---------- X11 keysym（只取本处用到的，不引 X11 头） ---------- */
#define XK_BACKSPACE 0xff08
#define XK_TAB       0xff09
#define XK_RETURN    0xff0d
#define XK_ESCAPE    0xff1b
#define XK_HOME      0xff50
#define XK_LEFT      0xff51
#define XK_UP        0xff52
#define XK_RIGHT     0xff53
#define XK_DOWN      0xff54
#define XK_PAGE_UP   0xff55
#define XK_PAGE_DOWN 0xff56
#define XK_END       0xff57
#define XK_DELETE    0xffff

/* ---------- 调色板（fbterm 标准 256 色） ---------- */
enum {
	PAL_BG = 0,     /* 黑 */
	PAL_DIM = 8,    /* 灰——状态行 */
	PAL_TXT = 7,    /* 白——正文/候选 */
	PAL_HILITE = 3  /* 黄——高亮候选 */
};

/* ---------- 全局态 ---------- */
static int g_fd = -1;
static int g_dbg = 0;
static struct { unsigned fw, fh, sw, sh; } g_scr = { 8, 16, 0, 0 };
static bool g_im_on = false;
static bool g_win_set = false;

#define DBG(...) do { \
	if (g_dbg) { fprintf(stderr, "aik-ime: " __VA_ARGS__); fputc('\n', stderr); } \
} while (0)

/* ---------- 消息 I/O ---------- */

static int write_full(const void *buf, size_t n)
{
	const char *p = (const char *)buf;
	while (n) {
		ssize_t w = send(g_fd, p, n, MSG_NOSIGNAL);
		if (w < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

/* 阻塞读一条完整消息；EOF/坏帧返回 -1。
 * 帧头+union 前缀（≤sizeof(ImMsg)）入 out；变长载荷（keys/texts）全量
 * 在 body，长度 *body_len——SendKey/PutText 等变长帧只经 body 取载荷。 */
static int read_msg(ImMsg *out, uint8_t *body, size_t body_cap, uint16_t *body_len)
{
	size_t got = 0;
	while (got < IM_HDR_LEN) {
		ssize_t r = recv(g_fd, (char *)out + got, IM_HDR_LEN - got, 0);
		if (r <= 0) {
			if (r < 0 && errno == EINTR) continue;
			return -1;
		}
		got += (size_t)r;
	}

	uint16_t len = out->len;
	if (len < IM_HDR_LEN || len > 16384) return -1;
	uint16_t rest = (uint16_t)(len - IM_HDR_LEN);
	if (rest) {
		if (rest > body_cap) return -1;
		got = 0;
		while (got < rest) {
			ssize_t r = recv(g_fd, (char *)body + got, rest - got, 0);
			if (r <= 0) {
				if (r < 0 && errno == EINTR) continue;
				return -1;
			}
			got += (size_t)r;
		}
		size_t uni = sizeof(ImMsg) - IM_HDR_LEN; /* union 区可拷前缀 */
		memcpy((char *)out + IM_HDR_LEN, body,
		       rest < uni ? rest : uni);
	}
	if (body_len) *body_len = rest;
	return 0;
}

static void send_fixed(ImType t)
{
	ImMsg m;
	memset(&m, 0, sizeof(m));
	m.type = (uint16_t)t;
	m.len = IM_FIXED_LEN;
	write_full(&m, sizeof(m));
	DBG("tx %d (fixed)", (int)t);
}

/* 发 PutText（texts=UTF-8，可为透传控制序列） */
static void send_puttext(const char *s, size_t n)
{
	if (!n) return;
	uint8_t buf[IM_OFF(texts) + 4096];
	if (n > 4096) n = 4096;
	ImMsg *m = (ImMsg *)buf;
	memset(m, 0, IM_HDR_LEN);
	m->type = IM_PUTTEXT;
	m->len = (uint16_t)(IM_OFF(texts) + n);
	memcpy(m->texts, s, n);
	write_full(buf, m->len);
	DBG("tx PutText len=%zu", n);
}

static void send_setwin(ImRect r)
{
	ImMsg m;
	memset(&m, 0, sizeof(m));
	m.type = IM_SETWIN;
	m.len = IM_FIXED_LEN;
	m.win.winid = 0;
	m.win.rect = r;
	write_full(&m, sizeof(m));
	DBG("tx SetWin %ux%u+%u+%u", r.w, r.h, r.x, r.y);
}

static void send_fillrect(unsigned x, unsigned y, unsigned w, unsigned h, uint8_t color)
{
	ImMsg m;
	memset(&m, 0, sizeof(m));
	m.type = IM_FILLRECT;
	m.len = IM_FIXED_LEN;
	m.fillRect.rect.x = x;
	m.fillRect.rect.y = y;
	m.fillRect.rect.w = w;
	m.fillRect.rect.h = h;
	m.fillRect.color = color;
	write_full(&m, sizeof(m));
}

static void send_drawtext(unsigned x, unsigned y, uint8_t fc, uint8_t bc,
                          const char *utf8)
{
	size_t n = utf8 ? strlen(utf8) : 0;
	if (!n) return;
	uint8_t buf[IM_OFF(drawText.texts) + 4096];
	if (n > 4096) n = 4096;
	ImMsg *m = (ImMsg *)buf;
	memset(m, 0, IM_HDR_LEN);
	m->type = IM_DRAWTEXT;
	m->drawText.x = x;
	m->drawText.y = y;
	m->drawText.fc = fc;
	m->drawText.bc = bc;
	memcpy(m->drawText.texts, utf8, n);
	m->len = (uint16_t)(IM_OFF(drawText.texts) + n);
	write_full(buf, m->len);
	DBG("tx DrawText %u,%u [%s]", x, y, utf8);
}

/* SetWin 后等 AckWin（fbterm 侧握手契约）；期间只答 Ping，其余忽略。
 * 2s 超时则照画（防御——丢的只是 VT 切回重绘缓存）。 */
static void wait_ackwin(void)
{
	ImMsg m;
	uint8_t body[8192];
	uint16_t bl;
	struct timeval tv;

	for (int spin = 0; spin < 40; spin++) {
		tv.tv_sec = 0;
		tv.tv_usec = 50 * 1000;
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(g_fd, &fds);
		int r = select(g_fd + 1, &fds, 0, 0, &tv);
		if (r <= 0) continue;
		if (read_msg(&m, body, sizeof(body), &bl) < 0) return;
		if (m.type == IM_ACKWIN) return;
		if (m.type == IM_PING) { send_fixed(IM_ACKPING); continue; }
	}
}

/* ---------- UTF-8 显示列宽（CJK=2，与 fbterm VTerm::charWidth 对齐） ---------- */

static size_t disp_cols(const char *s, size_t n)
{
	size_t cols = 0;
	size_t i = 0;
	while (i < n) {
		unsigned char c = (unsigned char)s[i];
		unsigned cp = 0;
		size_t cl = 1;
		if ((c & 0xe0) == 0xc0 && i + 1 < n) {
			cp = ((c & 0x1f) << 6) | ((unsigned char)s[i + 1] & 0x3f);
			cl = 2;
		} else if ((c & 0xf0) == 0xe0 && i + 2 < n) {
			cp = ((c & 0x0f) << 12) | (((unsigned char)s[i + 1] & 0x3f) << 6)
			   | ((unsigned char)s[i + 2] & 0x3f);
			cl = 3;
		} else if (c >= 0x80) {
			cp = c; /* 坏字节按 1 列 */
		}
		/* CJK 区（常用面：CJK 统一表意+扩展A+全角符号区）按 2 列 */
		if ((cp >= 0x1100 && cp <= 0x115f) ||
		    (cp >= 0x2e80 && cp <= 0xa4cf) ||
		    (cp >= 0xac00 && cp <= 0xd7a3) ||
		    (cp >= 0xf900 && cp <= 0xfaff) ||
		    (cp >= 0xff00 && cp <= 0xff60))
			cols += 2;
		else
			cols += 1;
		i += cl;
	}
	return cols;
}

/* ---------- 键解码：raw=0 字节流 → X11 keysym ---------- */

struct KeyDecode {
	int state;        /* 0=常态 1=ESC 2=CSI */
	char csi[12];
	int csi_len;

	void reset() { state = 0; csi_len = 0; }

	/* 返回 keysym；-1=无键产出（还在攒 CSI / 无意义字节） */
	int feed(unsigned char b)
	{
		if (state == 1 && b != '[' && b != 'O') {
			/* ESC 后非 CSI：先吐 Escape，当前键回到常态重判 */
			state = 0;
			int sym = map_plain(b);
			/* （丢弃二次产出：Esc+可打印键场景里 Escape 优先） */
			return sym > 0 ? sym : XK_ESCAPE;
		}
		if (state == 0) {
			if (b == 0x1b) { state = 1; return -1; }
			return map_plain(b);
		}
		if (state == 1) { /* '[' 或 'O' → 进 CSI */
			state = 2;
			csi_len = 0;
			return -1;
		}
		/* state==2：攒参数/终结符 */
		if (csi_len < (int)sizeof(csi) - 1) csi[csi_len++] = (char)b;
		if (b >= 0x40 && b <= 0x7e) {
			state = 0;
			return map_csi(csi, csi_len);
		}
		if (csi_len >= (int)sizeof(csi) - 1) state = 0; /* 超长=坏帧丢弃 */
		return -1;
	}

	static int map_plain(unsigned char b)
	{
		switch (b) {
		case 0x7f: case 0x08: return XK_BACKSPACE;
		case 0x0d: case 0x0a: return XK_RETURN;
		case 0x09: return XK_TAB;
		default:
			if (b < 0x20) return -1;
			if (b < 0x80) return (int)b; /* 可打印 ASCII=同值 keysym */
			return -1; /* raw=0 下不应有非 ASCII；防御丢弃 */
		}
	}

	static int map_csi(const char *p, int n)
	{
		char fin = p[n - 1];
		switch (fin) {
		case 'A': return XK_UP;
		case 'B': return XK_DOWN;
		case 'C': return XK_RIGHT;
		case 'D': return XK_LEFT;
		case 'H': return XK_HOME;
		case 'F': return XK_END;
		case '~': {
			int v = 0;
			for (int i = 0; i < n - 1; i++)
				if (p[i] >= '0' && p[i] <= '9') v = v * 10 + (p[i] - '0');
			switch (v) {
			case 1: case 7: return XK_HOME;
			case 2: return -1;        /* Insert：丢弃 */
			case 3: return XK_DELETE;
			case 4: case 8: return XK_END;
			case 5: return XK_PAGE_UP;
			case 6: return XK_PAGE_DOWN;
			default: return -1;
			}
		}
		default: return -1;
		}
	}
};

/* keysym→透传串（rime 不吃时经 PutText 发回，保住终端可用性） */
static const char *pass_through(int sym)
{
	static char one[2];
	switch (sym) {
	case XK_BACKSPACE: return "\x7f";
	case XK_TAB:       return "\t";
	case XK_RETURN:    return "\r";
	case XK_ESCAPE:    return "\x1b";
	case XK_LEFT:      return "\x1b[D";
	case XK_RIGHT:     return "\x1b[C";
	case XK_UP:        return "\x1b[A";
	case XK_DOWN:      return "\x1b[B";
	case XK_HOME:      return "\x1b[H";
	case XK_END:       return "\x1b[F";
	case XK_PAGE_UP:   return "\x1b[5~";
	case XK_PAGE_DOWN: return "\x1b[6~";
	case XK_DELETE:    return "\x1b[3~";
	default:
		if (sym >= 0x20 && sym < 0x80) {
			one[0] = (char)sym;
			one[1] = 0;
			return one;
		}
		return NULL;
	}
}

/* ---------- librime 桥 ---------- */

static pthread_t g_init_tid;
static volatile bool g_init_started = false;
static volatile bool g_rime_ready = false;
static RimeSessionId g_sid = 0;
static char g_schema[64] = "luna_pinyin";

static void mkdirs(const char *path)
{
	char tmp[512];
	snprintf(tmp, sizeof(tmp), "%s", path);
	size_t n = strlen(tmp);
	if (n && tmp[n - 1] == '/') tmp[n - 1] = 0;
	for (char *p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			mkdir(tmp, 0700);
			*p = '/';
		}
	}
	mkdir(tmp, 0700);
}

static void *rime_init_thread(void *)
{
	const char *data = getenv("AIK_IME_DATA");
	if (!data || !*data) data = "/usr/share/rime-data";

	char userdir[512];
	const char *ud = getenv("AIK_IME_USERDIR");
	if (ud && *ud) {
		snprintf(userdir, sizeof(userdir), "%s", ud);
	} else {
		const char *home = getenv("HOME");
		if (!home || !*home) home = "/root";
		snprintf(userdir, sizeof(userdir), "%s/.config/aik-ime", home);
	}
	mkdirs(userdir);

	RIME_STRUCT(RimeTraits, traits);
	traits.app_name = "aik-ime";
	traits.shared_data_dir = data;
	traits.user_data_dir = userdir;
	traits.min_log_level = 3;
	RimeSetup(&traits);

	RimeInitialize(NULL);
	RimeStartMaintenance(True);
	RimeJoinMaintenanceThread(); /* 不 join=部署异步=session 建不出（勘探坑） */

	g_rime_ready = true;
	DBG("rime ready (data=%s user=%s)", data, userdir);
	return NULL;
}

/* 后台慢初始化（Connect 必须先发——fbterm 只等 2 秒） */
static void rime_boot(void)
{
	if (g_init_started) return;
	g_init_started = true;
	if (pthread_create(&g_init_tid, NULL, rime_init_thread, NULL) != 0) {
		rime_init_thread(NULL); /* 兜底：同步跑 */
	}
}

static void rime_wait_ready(void)
{
	if (!g_init_started) rime_boot();
	if (!g_rime_ready) pthread_join(g_init_tid, NULL);
}

static void ensure_session(void)
{
	rime_wait_ready();
	if (!g_sid) {
		g_sid = RimeCreateSession();
		if (g_sid) {
			Bool ok = RimeSelectSchema(g_sid, g_schema);
			DBG("session=%lld select %s=%d", (long long)g_sid, g_schema, (int)ok);
		} else {
			DBG("RimeCreateSession FAILED");
		}
	}
}

/* ---------- 候选窗（贴底 3 行） ---------- */

#define WIN_ROWS 3

static unsigned win_y(void)
{
	unsigned fh = g_scr.fh ? g_scr.fh : 16;
	unsigned sh = g_scr.sh ? g_scr.sh : 600;
	unsigned y = sh - WIN_ROWS * fh;
	return y > sh ? 0 : y;
}

static void register_win(void)
{
	ImRect r;
	r.x = 0;
	r.y = win_y();
	r.w = g_scr.sw ? g_scr.sw : 800;
	r.h = WIN_ROWS * (g_scr.fh ? g_scr.fh : 16);
	send_setwin(r);
	wait_ackwin();
	g_win_set = true;
}

static void unregister_win(void)
{
	ImRect r;
	memset(&r, 0, sizeof(r));
	send_setwin(r);
	wait_ackwin();
	g_win_set = false;
}

static void draw_window(void)
{
	if (!g_im_on || !g_win_set) return;

	unsigned fw = g_scr.fw ? g_scr.fw : 8;
	unsigned fh = g_scr.fh ? g_scr.fh : 16;
	unsigned wy = win_y();
	unsigned ww = g_scr.sw ? g_scr.sw : 800;

	/* 清底 */
	send_fillrect(0, wy, ww, WIN_ROWS * fh, PAL_BG);

	/* 取 rime 组合态 */
	char preedit[512] = "";
	char cands[1024] = "";
	int hilite = -1;
	int page_no = 0, last_page = 1;

	if (g_sid) {
		RIME_STRUCT(RimeContext, ctx);
		if (RimeGetContext(g_sid, &ctx)) {
			snprintf(preedit, sizeof(preedit), "%s",
			         ctx.composition.preedit ? ctx.composition.preedit : "");
			int ncand = ctx.menu.num_candidates;
			if (ncand > 9) ncand = 9;
			hilite = ctx.menu.highlighted_candidate_index;
			size_t off = 0;
			for (int i = 0; i < ncand && off + 32 < sizeof(cands); i++) {
				const char *t = ctx.menu.candidates[i].text;
				off += (size_t)snprintf(cands + off, sizeof(cands) - off,
				                        "%d.%s ", i + 1, t ? t : "?");
			}
			page_no = ctx.menu.page_no;
			last_page = ctx.menu.is_last_page ? page_no + 1 : -1;
			RimeFreeContext(&ctx);
		}
	}

	/* 行 0：状态行（有组合态时拼页码） */
	char line0[256];
	if (preedit[0] && last_page < 0)
		snprintf(line0, sizeof(line0), "中文·拼音  ·%d/…", page_no + 1);
	else if (preedit[0])
		snprintf(line0, sizeof(line0), "中文·拼音  ·%d/%d", page_no + 1, last_page);
	else
		snprintf(line0, sizeof(line0), "%s", "中文·拼音  Ctrl+空格 切换");

	send_drawtext(0, wy, PAL_DIM, PAL_BG, line0);

	/* 行 1：preedit */
	send_drawtext(0, wy + fh, PAL_TXT, PAL_BG, preedit);

	/* 行 2：候选行——普通串一次画，高亮段黄字覆盖画 */
	if (cands[0]) {
		send_drawtext(0, wy + 2 * fh, PAL_TXT, PAL_BG, cands);
		if (hilite >= 0) {
			const char *p = cands;
			unsigned px = 0;
			for (int idx = 0; *p; idx++) {
				const char *sp = strchr(p, ' ');
				size_t l = sp ? (size_t)(sp - p) : strlen(p);
				if (idx == hilite) {
					char seg[256];
					if (l < sizeof(seg)) {
						memcpy(seg, p, l);
						seg[l] = 0;
						send_drawtext(px, wy + 2 * fh, PAL_HILITE, PAL_BG, seg);
					}
					break;
				}
				px += (unsigned)(disp_cols(p, l) + 1) * fw; /* 段宽+空格 */
				if (!sp) break;
				p = sp + 1;
			}
		}
	}
}

/* ---------- SendKey 处理 ---------- */

static void handle_sendkey(const char *bytes, uint16_t n)
{
	if (!g_im_on) return;
	ensure_session();

	static KeyDecode kd;
	char commit[2048];

	for (uint16_t i = 0; i < n; i++) {
		int sym = kd.feed((unsigned char)bytes[i]);
		if (sym < 0) continue;

		Bool used = g_sid ? RimeProcessKey(g_sid, sym, 0) : False;

		commit[0] = 0;
		if (g_sid) {
			RIME_STRUCT(RimeCommit, c);
			if (RimeGetCommit(g_sid, &c)) {
				if (c.text && c.text[0])
					snprintf(commit, sizeof(commit), "%s", c.text);
				RimeFreeCommit(&c);
			}
		}

		if (commit[0]) {
			send_puttext(commit, strlen(commit));
		} else if (!used) {
			/* rime 不吃且无提交：透传保终端可用（英文/回车/退格/方向键） */
			const char *pt = pass_through(sym);
			if (pt) send_puttext(pt, strlen(pt));
		}
	}

	draw_window();
}

/* ---------- 主循环 ---------- */

int main(void)
{
	signal(SIGPIPE, SIG_IGN);
	setvbuf(stderr, NULL, _IOLBF, 0);

	const char *dbg = getenv("AIK_IME_DEBUG");
	g_dbg = (dbg && dbg[0] == '1');

	const char *schema = getenv("AIK_IME_SCHEMA");
	if (schema && *schema) snprintf(g_schema, sizeof(g_schema), "%s", schema);

	const char *fds = getenv("FBTERM_IM_SOCKET");
	g_fd = fds ? atoi(fds) : -1;
	if (g_fd < 0) {
		fprintf(stderr, "aik-ime: no FBTERM_IM_SOCKET (not launched by fbterm?)\n");
		return 1;
	}

	/* ① 先握手（fbterm 只等 2 秒） */
	ImMsg m;
	memset(&m, 0, sizeof(m));
	m.type = IM_CONNECT;
	m.len = IM_FIXED_LEN;
	m.raw = 0; /* raw=0：键流=K_UNICODE 翻译后字节 */
	write_full(&m, sizeof(m));
	DBG("tx Connect raw=0");

	/* ② 后台慢初始化（字典部署可分钟级，不挡握手） */
	rime_boot();

	/* ③ 事件循环 */
	static uint8_t body[16384];
	static ImMsg msg;
	uint16_t bl;

	for (;;) {
		if (read_msg(&msg, body, sizeof(body), &bl) < 0) break;

		switch (msg.type) {
		case IM_FBTERMINFO:
			g_scr.fh = msg.info.fontHeight;
			g_scr.fw = msg.info.fontWidth;
			g_scr.sh = msg.info.screenHeight;
			g_scr.sw = msg.info.screenWidth;
			DBG("rx FbTermInfo fw=%u fh=%u sw=%u sh=%u",
			    g_scr.fw, g_scr.fh, g_scr.sw, g_scr.sh);
			break;

		case IM_ACTIVE:
			DBG("rx Active");
			g_im_on = true;
			ensure_session();
			if (g_sid) RimeClearComposition(g_sid);
			register_win();
			draw_window();
			break;

		case IM_DEACTIVE:
			DBG("rx Deactive");
			g_im_on = false;
			if (g_win_set) unregister_win();
			break;

		case IM_SENDKEY:
			DBG("rx SendKey n=%u", bl);
			handle_sendkey((const char *)body, bl);
			break;

		case IM_CURSORPOS:
		case IM_TERMMODE:
			break; /* 贴底窗，忽略 */

		case IM_SHOWUI:
			DBG("rx ShowUI");
			if (g_im_on) {
				register_win();
				draw_window();
			}
			break;

		case IM_HIDEUI:
			DBG("rx HideUI");
			send_fixed(IM_ACKHIDEUI);
			break;

		case IM_PING:
			send_fixed(IM_ACKPING);
			break;

		case IM_DISCONNECT:
			DBG("rx Disconnect");
			return 0;

		default:
			break;
		}
	}

	DBG("eof/err exit");
	return 0;
}
