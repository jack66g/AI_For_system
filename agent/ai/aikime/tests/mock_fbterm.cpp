// mock_fbterm — aik-ime 协议测试器（扮演 fbterm 侧，离台架验证全链）
//
// 用法：AIK_IME_DATA=<rime共享数据目录> tests/mock_fbterm [aik-ime 路径]
// 剧本：Connect 握手 → Active/SetWin/AckWin → SendKey 打拼音 → DrawText
// preedit → PutText 提交（汉字）→ rime 不吃键透传（数字/回车/CSI 方向
// 键）→ Ping↔AckPing → HideUI/ShowUI → Deactive 收空窗 → Disconnect 退零。
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <string>
#include <vector>

#include "im_proto.h"

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, desc) do { \
	if (cond) { g_pass++; printf("  ok   %s\n", desc); } \
	else     { g_fail++; printf("  FAIL %s\n", desc); } \
} while (0)

struct MockFb {
	int fd = -1;
	pid_t pid = -1;
	std::string rbuf;

	// 带超时读一条消息；超时/EOF/坏帧返回 -1
	// 帧头+union 前缀入 m（防变长帧溢出 24B 结构）；载荷全量在 body
	int recv_msg(ImMsg *m, std::string *body, double timeout_s)
	{
		double t0 = (double)clock() / CLOCKS_PER_SEC;
		for (;;) {
			while (rbuf.size() >= IM_HDR_LEN) {
				uint16_t len;
				memcpy(&len, rbuf.data() + 2, 2);
				if (len < IM_HDR_LEN || len > 16384) return -1;
				if (rbuf.size() < len) break;
				size_t uni = len < sizeof(ImMsg) ? len : sizeof(ImMsg);
				memcpy(m, rbuf.data(), uni);
				memset((char *)m + uni, 0, sizeof(ImMsg) - uni);
				if (body) body->assign(rbuf, IM_HDR_LEN, len - IM_HDR_LEN);
				rbuf.erase(0, len);
				return m->type;
			}
			double left = timeout_s - ((double)clock() / CLOCKS_PER_SEC - t0);
			if (left <= 0) return -1;
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(fd, &fds);
			struct timeval tv;
			tv.tv_sec = (long)left;
			tv.tv_usec = (long)((left - tv.tv_sec) * 1e6);
			int r = select(fd + 1, &fds, 0, 0, &tv);
			if (r < 0 && errno == EINTR) continue;
			if (r <= 0) return -1;
			char buf[8192];
			ssize_t n = recv(fd, buf, sizeof(buf), 0);
			if (n <= 0) return -1;
			rbuf.append(buf, (size_t)n);
		}
	}

	// 等指定类型：命中帧经 out/out_body 交出；沿途消息进 sidecar；-1 超时 -2 Disconnect
	int expect(int type, double timeout_s, ImMsg *out = nullptr,
	           std::string *out_body = nullptr,
	           std::vector<ImMsg> *side = nullptr,
	           std::vector<std::string> *side_body = nullptr)
	{
		ImMsg m;
		std::string body;
		for (;;) {
			int t = recv_msg(&m, &body, timeout_s);
			if (t < 0) return -1;
			if (t == type) {
				if (out) *out = m;
				if (out_body) *out_body = body;
				return t;
			}
			if (t == IM_DISCONNECT) return -2;
			if (side) { side->push_back(m); if (side_body) side_body->push_back(body); }
		}
	}

	void send_raw(const void *p, size_t n) { send(fd, p, n, MSG_NOSIGNAL); }

	void send_fixed(int t)
	{
		ImMsg m;
		memset(&m, 0, sizeof(m));
		m.type = (uint16_t)t;
		m.len = IM_FIXED_LEN;
		send_raw(&m, sizeof(m));
	}

	void send_info(unsigned fh, unsigned fw, unsigned sh, unsigned sw)
	{
		ImMsg m;
		memset(&m, 0, sizeof(m));
		m.type = IM_FBTERMINFO;
		m.len = IM_FIXED_LEN;
		m.info.fontHeight = fh;
		m.info.fontWidth = fw;
		m.info.screenHeight = sh;
		m.info.screenWidth = sw;
		send_raw(&m, sizeof(m));
	}

	void send_key(const char *s)
	{
		size_t n = strlen(s);
		char buf[IM_HDR_LEN + 256];
		ImMsg *m = (ImMsg *)buf;
		memset(m, 0, IM_HDR_LEN);
		m->type = IM_SENDKEY;
		m->len = (uint16_t)(IM_HDR_LEN + n);
		memcpy(m->keys, s, n);
		send_raw(buf, m->len);
	}
};

static bool is_hanzi_utf8(const std::string &s)
{
	/* 基面汉字=3 字节(E0..EF)，扩展面（勘探期生僻字数据）=4 字节(F0..F4)
	 * ——断言取「多字节 UTF-8 非空」；打版换官方 prebuilt 后为常用字。 */
	return !s.empty() && (unsigned char)s[0] >= 0xC0;
}

int main(int argc, char **argv)
{
	const char *bin = argc > 1 ? argv[1] : "./aik-ime";
	const char *data = getenv("AIK_IME_DATA");

	printf("mock_fbterm: bin=%s data=%s\n", bin, data ? data : "(default)");

	int fds[2];
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) < 0) { perror("socketpair"); return 1; }

	MockFb fb;
	fb.pid = fork();
	if (fb.pid == 0) {
		close(fds[0]);
		char fdstr[16];
		snprintf(fdstr, sizeof(fdstr), "%d", fds[1]);
		setenv("FBTERM_IM_SOCKET", fdstr, 1);
		char userdir[128];
		snprintf(userdir, sizeof(userdir), "/tmp/aik-ime-mock-%ld", (long)getpid());
		setenv("AIK_IME_USERDIR", userdir, 1);
		execl(bin, bin, (char *)NULL);
		fprintf(stderr, "exec %s failed: %s\n", bin, strerror(errno));
		_exit(127);
	}
	close(fds[1]);
	fb.fd = fds[0];
	signal(SIGPIPE, SIG_IGN);

	int rc = 1;
	ImMsg m;
	std::string body;
	std::vector<ImMsg> side;
	std::vector<std::string> side_body;

	/* 1. 握手：Connect(raw=0) → 发屏参 */
	CHECK(fb.expect(IM_CONNECT, 5, &m, &body) == IM_CONNECT
	      && m.len == IM_FIXED_LEN && m.raw == 0,
	      "Connect 到达，len=24，raw=0");
	fb.send_info(16, 8, 480, 800);

	/* 2. Active → SetWin(贴底3行) → AckWin */
	fb.send_fixed(IM_ACTIVE);
	CHECK(fb.expect(IM_SETWIN, 20, &m, nullptr, &side, &side_body) == IM_SETWIN,
	      "Active→SetWin 到达（首跑含 rime 部署，20s 窗）");
	fb.send_fixed(IM_ACKWIN);
	CHECK(m.len == IM_FIXED_LEN, "SetWin len==sizeof(ImMsg)（v1.5 兼容闸）");
	CHECK(m.win.winid < IM_NR_WINS, "SetWin winid<10");
	CHECK(m.win.rect.h == 3 * 16 && m.win.rect.y == 480 - 48,
	      "SetWin 贴底 3 行（y=432,h=48）");
	CHECK(m.win.rect.x + m.win.rect.w <= 800, "SetWin 宽在屏内");

	/* 3. 初始窗绘制 */
	side.clear(); side_body.clear();
	bool init_draw = fb.expect(IM_DRAWTEXT, 2.0, nullptr, nullptr,
	                           &side, &side_body) == IM_DRAWTEXT;
	for (size_t i = 0; i < side_body.size(); i++)
		if (side[i].type == IM_DRAWTEXT) init_draw = true;
	CHECK(init_draw, "初始窗绘制消息到达（DrawText）");

	/* 4. 拼音输入 → preedit 绘制 */
	fb.send_key("ni");
	side.clear(); side_body.clear();
	bool preedit_seen =
		fb.expect(IM_DRAWTEXT, 5, nullptr, nullptr, &side, &side_body)
		== IM_DRAWTEXT;
	for (size_t i = 0; i < side_body.size(); i++)
		if (side[i].type == IM_DRAWTEXT && side_body[i].find("ni") != std::string::npos)
			preedit_seen = true;
	CHECK(preedit_seen, "preedit 'ni' 上屏（DrawText 含 ni）");

	/* 5. 补全+空格 → 提交汉字（PutText UTF-8 非空） */
	fb.send_key("hao ");
	CHECK(fb.expect(IM_PUTTEXT, 10, &m, &body) == IM_PUTTEXT
	      && is_hanzi_utf8(body),
	      "空格触发提交：PutText=汉字 UTF-8");

	/* 6. 无组合态数字 → 透传 */
	fb.send_key("5");
	CHECK(fb.expect(IM_PUTTEXT, 5, &m, &body) == IM_PUTTEXT
	      && body == "5",
	      "rime 不吃的数字键透传（PutText=5）");

	/* 7. 无组合态回车 → 透传 */
	fb.send_key("\r");
	CHECK(fb.expect(IM_PUTTEXT, 5, &m, &body) == IM_PUTTEXT
	      && body == "\r",
	      "无组合态回车透传（PutText=CR）");

	/* 8. CSI 方向键 → 解码并透传 */
	fb.send_key("\x1b[D");
	CHECK(fb.expect(IM_PUTTEXT, 5, &m, &body) == IM_PUTTEXT
	      && body == "\x1b[D",
	      "CSI Left 解码并透传（PutText=ESC[D）");

	/* 9. Ping 心跳 */
	fb.send_fixed(IM_PING);
	CHECK(fb.expect(IM_ACKPING, 2) == IM_ACKPING, "Ping→AckPing");

	/* 10. HideUI/ShowUI */
	fb.send_fixed(IM_HIDEUI);
	CHECK(fb.expect(IM_ACKHIDEUI, 2) == IM_ACKHIDEUI, "HideUI→AckHideUI");
	fb.send_fixed(IM_SHOWUI);
	CHECK(fb.expect(IM_SETWIN, 3) == IM_SETWIN, "ShowUI→重挂窗 SetWin");
	fb.send_fixed(IM_ACKWIN);

	/* 11. Deactive → 空窗收起 */
	fb.send_fixed(IM_DEACTIVE);
	CHECK(fb.expect(IM_SETWIN, 3, &m) == IM_SETWIN
	      && (m.win.rect.w == 0 || m.win.rect.h == 0),
	      "Deactive→SetWin 空 rect 收窗");
	fb.send_fixed(IM_ACKWIN);

	/* 12. Disconnect → 子进程退出码 0 */
	fb.send_fixed(IM_DISCONNECT);
	int st = -1;
	bool exited = false;
	for (int i = 0; i < 40; i++) {
		if (waitpid(fb.pid, &st, WNOHANG) == fb.pid) { exited = true; break; }
		usleep(100 * 1000);
	}
	CHECK(exited && WIFEXITED(st) && WEXITSTATUS(st) == 0,
	      "Disconnect 后子进程 rc=0");

	printf("mock_fbterm: %d pass, %d fail => %s\n", g_pass, g_fail,
	       g_fail ? "FAIL" : "PASS");
	rc = g_fail ? 1 : 0;
	kill(fb.pid, SIGKILL);
	waitpid(fb.pid, &st, 0);
	return rc;
}
