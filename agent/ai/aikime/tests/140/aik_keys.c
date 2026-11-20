/* aik-keys — uinput 键注入器（P-55 集成验收；140 无 gcc，L1 -static 编）
 * 用法：
 *   aik-keys ctrl-space   注入 Ctrl+Space（fbterm IM toggle）
 *   aik-keys text "nihao " 逐键注入小写字母/数字/空格串
 *   aik-keys enter        回车
 *   aik-keys pgdn|pgup|up|down|left|right|esc|bs
 *   aik-keys ctrl-alt-k   杀 IM（fbterm killIm）
 * 键事件进当前激活 VT（先 chvt 再注入）。 */
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

static int ufd = -1;

static void key_bit(int code)
{
	ioctl(ufd, UI_SET_KEYBIT, code);
}

static void emit(int type, int code, int val)
{
	struct input_event ev;
	memset(&ev, 0, sizeof(ev));
	gettimeofday(&ev.time, NULL);
	ev.type = (unsigned short)type;
	ev.code = (unsigned short)code;
	ev.value = val;
	if (write(ufd, &ev, sizeof(ev)) < 0) perror("write uinput");
}

static void tap(int code)
{
	emit(EV_KEY, code, 1);
	emit(EV_SYN, SYN_REPORT, 0);
	usleep(80 * 1000);
	emit(EV_KEY, code, 0);
	emit(EV_SYN, SYN_REPORT, 0);
	usleep(120 * 1000);
}

static int letter_code(char c)
{
	if (c >= 'a' && c <= 'z') {
		static const int map[26] = {
			KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G, KEY_H, KEY_I,
			KEY_J, KEY_K, KEY_L, KEY_M, KEY_N, KEY_O, KEY_P, KEY_Q, KEY_R,
			KEY_S, KEY_T, KEY_U, KEY_V, KEY_W, KEY_X, KEY_Y, KEY_Z
		};
		return map[c - 'a'];
	}
	if (c >= '1' && c <= '9') return KEY_1 + (c - '1');
	if (c == '0') return KEY_0;
	if (c == ' ') return KEY_SPACE;
	return -1;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s ctrl-space|text STR|enter|pgdn|pgup|up|down|left|right|esc|bs\n", argv[0]);
		return 2;
	}

	ufd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
	if (ufd < 0) { perror("open /dev/uinput"); return 1; }

	ioctl(ufd, UI_SET_EVBIT, EV_KEY);
	ioctl(ufd, UI_SET_EVBIT, EV_SYN);
	key_bit(KEY_LEFTCTRL); key_bit(KEY_LEFTALT); key_bit(KEY_SPACE);
	key_bit(KEY_ENTER); key_bit(KEY_ESC); key_bit(KEY_BACKSPACE);
	key_bit(KEY_UP); key_bit(KEY_DOWN); key_bit(KEY_LEFT); key_bit(KEY_RIGHT);
	key_bit(KEY_PAGEUP); key_bit(KEY_PAGEDOWN); key_bit(KEY_K);
	for (int c = KEY_1; c <= KEY_0; c++) key_bit(c);
	for (int c = KEY_A; c <= KEY_Z; c++) key_bit(c);

	struct uinput_user_dev uidev;
	memset(&uidev, 0, sizeof(uidev));
	snprintf(uidev.name, UINPUT_MAX_NAME_SIZE, "aik-keys");
	uidev.id.bustype = BUS_USB;
	uidev.id.vendor = 0x1;
	uidev.id.product = 0x1;
	uidev.id.version = 1;
	if (write(ufd, &uidev, sizeof(uidev)) < 0) { perror("write setup"); return 1; }
	if (ioctl(ufd, UI_DEV_CREATE) < 0) { perror("UI_DEV_CREATE"); return 1; }
	usleep(200 * 1000); /* 设备注册起效 */

	int rc = 0;
	if (!strcmp(argv[1], "ctrl-space")) {
		emit(EV_KEY, KEY_LEFTCTRL, 1);
		emit(EV_SYN, SYN_REPORT, 0);
		usleep(40 * 1000);
		tap(KEY_SPACE);
		emit(EV_KEY, KEY_LEFTCTRL, 0);
		emit(EV_SYN, SYN_REPORT, 0);
	} else if (!strcmp(argv[1], "ctrl-alt-k")) {
		emit(EV_KEY, KEY_LEFTCTRL, 1); emit(EV_SYN, SYN_REPORT, 0); usleep(30*1000);
		emit(EV_KEY, KEY_LEFTALT, 1); emit(EV_SYN, SYN_REPORT, 0); usleep(30*1000);
		tap(KEY_K);
		emit(EV_KEY, KEY_LEFTALT, 0); emit(EV_SYN, SYN_REPORT, 0);
		emit(EV_KEY, KEY_LEFTCTRL, 0); emit(EV_SYN, SYN_REPORT, 0);
	} else if (!strcmp(argv[1], "text") && argc >= 3) {
		for (const char *p = argv[2]; *p; p++) {
			int code = letter_code(*p);
			if (code < 0) { fprintf(stderr, "skip '%c'\n", *p); rc = 1; continue; }
			tap(code);
		}
	} else if (!strcmp(argv[1], "enter")) {
		tap(KEY_ENTER);
	} else if (!strcmp(argv[1], "esc")) {
		tap(KEY_ESC);
	} else if (!strcmp(argv[1], "bs")) {
		tap(KEY_BACKSPACE);
	} else if (!strcmp(argv[1], "up")) {
		tap(KEY_UP);
	} else if (!strcmp(argv[1], "down")) {
		tap(KEY_DOWN);
	} else if (!strcmp(argv[1], "left")) {
		tap(KEY_LEFT);
	} else if (!strcmp(argv[1], "right")) {
		tap(KEY_RIGHT);
	} else if (!strcmp(argv[1], "pgup")) {
		tap(KEY_PAGEUP);
	} else if (!strcmp(argv[1], "pgdn")) {
		tap(KEY_PAGEDOWN);
	} else {
		fprintf(stderr, "unknown: %s\n", argv[1]);
		rc = 2;
	}

	usleep(100 * 1000);
	ioctl(ufd, UI_DEV_DESTROY);
	close(ufd);
	return rc;
}
