/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
/*
 * test_device_tools - W82 V5.1/V5.2 设备身份 + 绑定控制面单测
 *
 * 默认（非 root，零真实 /sys 写）：
 *   - 纯函数：节点名/根 hub 名校验、类别推断（hub 优先、多接口混类→
 *     other）、最小 ids 表、驱动名/禁用驱动/绑定模式校验；
 *   - 假 sysfs 树（AIKERNEL_USB_SYSFS_ROOT）：复刻 L1 的 8 个节点
 *     （usb1/usb2/1-0:1.0/2-0:1.0/1-2/1-2:1.0/1-1/1-1:1.0），
 *     dev_list 计数/JSON 形状、dev_identify 的 hub/hid 判定；
 *   - 安全闸门：根 hub、虚拟 hub、hub 接口、多接口设备、危险驱动、
 *     未注册驱动、非法 mode 一律拒绝且不落快照、不写任何文件；
 *   - 绑定闭环（假树 + 真实写文件）：override 快照 → 写 override →
 *     unbind → bind → 读回不是目标驱动 → 自动回滚 → 读回原驱动；
 *     写序列/快照路径/回滚结果逐项断言；dev_restore 按快照恢复。
 *
 * --live（必须 root，真写 /sys；只允许 VMware 虚拟鼠标 1-1）：
 *   预检 1-1 = 0e0f:0003、单接口、bInterfaceClass=03、当前 usbhid，
 *   否则拒绝且不做任何写。依次执行任务书 6 步（第 4 步先试 override，
 *   本内核无 driver_override 时如实记录 fail-closed；再用 new_id 做强
 *   制错绑，拿到真实 probe 失败与自动回滚），每步原始输出写 --emit
 *   目录，并对比受保护 hub 节点前后签名。
 *
 * 用法：
 *   ./test_device_tools
 *   sudo ./test_device_tools --live --emit ~/aikernel-longterm/evidence/w82c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "../tools/tool_registry.h"
#include "../tools/device_tools.h"

static int fails;
static int checks;
static int skips;
static const char *g_emit;

#define CHECK(cond, msg) do { \
	checks++; \
	if (cond) { \
		printf("ok %s\n", msg); \
	} else { \
		printf("FAIL %s\n", msg); \
		fails++; \
	} \
} while (0)

#define SKIP(msg, why) do { \
	printf("skip %s（%s）\n", msg, why); \
	skips++; \
} while (0)

/* ------------------------------------------------------------------ */
/* 文件 / 目录小工具                                                    */
/* ------------------------------------------------------------------ */

static int mkdir_p(const char *path)
{
	char tmp[PATH_MAX];
	size_t i;

	snprintf(tmp, sizeof(tmp), "%s", path);
	for (i = 1; tmp[i]; i++) {
		if (tmp[i] != '/')
			continue;
		tmp[i] = '\0';
		if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
			return -1;
		tmp[i] = '/';
	}
	if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

static int wf(const char *pathfmt, const char *arg, const char *content)
{
	char path[PATH_MAX];
	size_t len;
	int fd;

	snprintf(path, sizeof(path), pathfmt, arg);
	len = strlen(content);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		fprintf(stderr, "wf open %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (write(fd, content, len) != (ssize_t)len) {
		fprintf(stderr, "wf write %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int read_text(const char *path, char *out, size_t cap)
{
	int fd;
	ssize_t n;

	if (!out || cap == 0)
		return -1;
	out[0] = '\0';
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, out, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	out[n] = '\0';
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
			 out[n - 1] == ' ' || out[n - 1] == '\t'))
		out[--n] = '\0';
	{
		char *s = out;

		while (*s == ' ' || *s == '\t')
			s++;
		if (s != out)
			memmove(out, s, strlen(s) + 1);
	}
	return 0;
}

static int link_driver(const char *root, const char *node, const char *drv)
{
	char dir[PATH_MAX], target[PATH_MAX], path[PATH_MAX];

	snprintf(dir, sizeof(dir), "%s/devices/%s", root, node);
	snprintf(target, sizeof(target), "%s/drivers/%s", root, drv);
	snprintf(path, sizeof(path), "%s/driver", dir);
	unlink(path);
	return symlink(target, path);
}

static int mkdir_node(const char *root, const char *node)
{
	char dir[PATH_MAX];

	snprintf(dir, sizeof(dir), "%s/devices/%s", root, node);
	return mkdir_p(dir);
}

static int make_driver(const char *root, const char *drv)
{
	char dir[PATH_MAX];

	snprintf(dir, sizeof(dir), "%s/drivers/%s", root, drv);
	if (mkdir_p(dir) != 0)
		return -1;
	wf("%s/bind", dir, "");
	wf("%s/unbind", dir, "");
	wf("%s/new_id", dir, "");
	wf("%s/remove_id", dir, "");
	return 0;
}

static int make_tree(const char *root, int extras)
{
	unlink(root);
	mkdir_p(root);
	if (make_driver(root, "usb") || make_driver(root, "usbhid") ||
	    make_driver(root, "hub") || make_driver(root, "usb-storage"))
		return -1;

	/* 根 hub usb1（UHCI） */
	mkdir_node(root, "usb1");
	wf("%s/devices/usb1/idVendor", root, "1d6b");
	wf("%s/devices/usb1/idProduct", root, "0001");
	wf("%s/devices/usb1/bDeviceClass", root, "09");
	wf("%s/devices/usb1/bNumInterfaces", root, "1");
	wf("%s/devices/usb1/product", root, "UHCI Host Controller");
	wf("%s/devices/usb1/manufacturer", root, "Linux 6.8.0-138-generic uhci_hcd");
	wf("%s/devices/usb1/modalias", root, "usb:v1D6Bp0001d0608dc09dsc00dp00ic09isc00ip00in00");
	link_driver(root, "usb1", "usb");

	/* 根 hub usb2（EHCI） */
	mkdir_node(root, "usb2");
	wf("%s/devices/usb2/idVendor", root, "1d6b");
	wf("%s/devices/usb2/idProduct", root, "0002");
	wf("%s/devices/usb2/bDeviceClass", root, "09");
	wf("%s/devices/usb2/bNumInterfaces", root, "1");
	wf("%s/devices/usb2/product", root, "EHCI Host Controller");
	wf("%s/devices/usb2/manufacturer", root, "Linux 6.8.0-138-generic ehci_hcd");
	wf("%s/devices/usb2/modalias", root, "usb:v1D6Bp0002d0608dc09dsc00dp00ic09isc00ip00in00");
	link_driver(root, "usb2", "usb");

	/* 根 hub 的接口节点（class=9，driver=hub） */
	mkdir_node(root, "1-0:1.0");
	wf("%s/devices/1-0:1.0/bInterfaceClass", root, "09");
	wf("%s/devices/1-0:1.0/modalias", root, "usb:v1D6Bp0001d0608dc09dsc00dp00ic09isc00ip00in00");
	link_driver(root, "1-0:1.0", "hub");

	mkdir_node(root, "2-0:1.0");
	wf("%s/devices/2-0:1.0/bInterfaceClass", root, "09");
	link_driver(root, "2-0:1.0", "hub");

	/* VMware 虚拟 hub 1-2 + 接口 1-2:1.0 */
	mkdir_node(root, "1-2");
	wf("%s/devices/1-2/idVendor", root, "0e0f");
	wf("%s/devices/1-2/idProduct", root, "0002");
	wf("%s/devices/1-2/bDeviceClass", root, "09");
	wf("%s/devices/1-2/bNumInterfaces", root, "1");
	wf("%s/devices/1-2/product", root, "VMware Virtual USB Hub");
	wf("%s/devices/1-2/manufacturer", root, "VMware, Inc.");
	wf("%s/devices/1-2/modalias", root, "usb:v0E0Fp0002d0100dc09dsc00dp00ic09isc00ip00in00");
	link_driver(root, "1-2", "usb");
	mkdir_node(root, "1-2:1.0");
	wf("%s/devices/1-2:1.0/bInterfaceClass", root, "09");
	wf("%s/devices/1-2:1.0/modalias", root, "usb:v0E0Fp0002d0100dc09dsc00dp00ic09isc00ip00in00");
	link_driver(root, "1-2:1.0", "hub");

	/* 安全目标：VMware 虚拟鼠标 1-1 + 接口 1-1:1.0（HID） */
	mkdir_node(root, "1-1");
	wf("%s/devices/1-1/idVendor", root, "0e0f");
	wf("%s/devices/1-1/idProduct", root, "0003");
	wf("%s/devices/1-1/bDeviceClass", root, "00");
	wf("%s/devices/1-1/bNumInterfaces", root, "1");
	wf("%s/devices/1-1/product", root, "VMware Virtual USB Mouse");
	wf("%s/devices/1-1/manufacturer", root, "VMware");
	wf("%s/devices/1-1/modalias", root, "usb:v0E0Fp0003d0103dc00dsc00dp00ic03isc01ip02in00");
	link_driver(root, "1-1", "usb");
	mkdir_node(root, "1-1:1.0");
	wf("%s/devices/1-1:1.0/bInterfaceClass", root, "03");
	wf("%s/devices/1-1:1.0/bInterfaceSubClass", root, "01");
	wf("%s/devices/1-1:1.0/modalias", root, "usb:v0E0Fp0003d0103dc00dsc00dp00ic03isc01ip02in00");
	wf("%s/devices/1-1:1.0/driver_override", root, "");
	link_driver(root, "1-1:1.0", "usbhid");

	if (!extras)
		return 0;

	/* 多接口设备 1-3（两个 HID 接口） */
	mkdir_node(root, "1-3");
	wf("%s/devices/1-3/idVendor", root, "046d");
	wf("%s/devices/1-3/idProduct", root, "c52b");
	wf("%s/devices/1-3/bDeviceClass", root, "00");
	wf("%s/devices/1-3/bNumInterfaces", root, "2");
	wf("%s/devices/1-3/product", root, "Fake Multi Interface Device");
	link_driver(root, "1-3", "usb");
	mkdir_node(root, "1-3:1.0");
	wf("%s/devices/1-3:1.0/bInterfaceClass", root, "03");
	link_driver(root, "1-3:1.0", "usbhid");
	mkdir_node(root, "1-3:1.1");
	wf("%s/devices/1-3:1.1/bInterfaceClass", root, "03");
	link_driver(root, "1-3:1.1", "usbhid");

	/* 单接口但无 driver_override 的设备 3-1（验证 fail-closed） */
	mkdir_node(root, "3-1");
	wf("%s/devices/3-1/idVendor", root, "046d");
	wf("%s/devices/3-1/idProduct", root, "c077");
	wf("%s/devices/3-1/bDeviceClass", root, "00");
	wf("%s/devices/3-1/bNumInterfaces", root, "1");
	link_driver(root, "3-1", "usb");
	mkdir_node(root, "3-1:1.0");
	wf("%s/devices/3-1:1.0/bInterfaceClass", root, "03");
	link_driver(root, "3-1:1.0", "usbhid");
	return 0;
}

static void rm_tree(const char *path)
{
	char cmd[PATH_MAX + 16];

	if (!path || !path[0])
		return;
	if (getenv("AIKERNEL_DEV_KEEP")) {
		printf("keep tree: %s\n", path);
		return;
	}
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: rm -rf %s failed\n", path);
}

/* ------------------------------------------------------------------ */
/* 工具调用                                                             */
/* ------------------------------------------------------------------ */

static int call_dev(const char *name, const char *args, char **out)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.name = (char *)name;
	t.channel = TOOL_CH_DEVICE;
	if (out)
		*out = NULL;
	return exec_device_channel(&t, args, out);
}

static int has(const char *s, const char *needle)
{
	return s && needle && strstr(s, needle) != NULL;
}

/* 轻量 JSON 形状检查：输出里不允许出现尾逗号 ",}"/",]" */
static int json_shape_ok(const char *s)
{
	return s && !strstr(s, ",}") && !strstr(s, ",]");
}

static void free_out(char **out)
{
	free(*out);
	*out = NULL;
}

/* ------------------------------------------------------------------ */
/* 纯函数                                                               */
/* ------------------------------------------------------------------ */

static void test_pure(void)
{
	int ifs_hub[1] = { 9 };
	int ifs_hid[1] = { 3 };
	int ifs_mix[2] = { 3, 8 };
	int ifs_none[1] = { -1 };

	printf("== pure functions ==\n");
	CHECK(dv_node_name_valid("1-1") == 1, "节点名 1-1 合法");
	CHECK(dv_node_name_valid("1-1:1.0") == 1, "节点名 1-1:1.0 合法");
	CHECK(dv_node_name_valid("") == 0, "空节点名拒绝");
	CHECK(dv_node_name_valid("../x") == 0, "含 .. 的节点名拒绝");
	CHECK(dv_node_name_valid(".hidden") == 0, "以 . 开头的节点名拒绝");
	CHECK(dv_node_name_valid("a/b") == 0, "含 / 的节点名拒绝");
	CHECK(dv_node_name_valid("a b") == 0, "含空格的节点名拒绝");

	CHECK(dv_is_root_hub_name("usb1") == 1, "usb1 是根 hub 名");
	CHECK(dv_is_root_hub_name("usb12") == 1, "usb12 是根 hub 名");
	CHECK(dv_is_root_hub_name("usb") == 0, "usb 不是根 hub 名");
	CHECK(dv_is_root_hub_name("usb1x") == 0, "usb1x 不是根 hub 名");
	CHECK(dv_is_root_hub_name("1-1") == 0, "1-1 不是根 hub 名");

	CHECK(strcmp(dv_classify_classes(9, ifs_hid, 1), "hub") == 0,
	      "设备 class=9 优先判 hub");
	CHECK(strcmp(dv_classify_classes(0, ifs_hub, 1), "hub") == 0,
	      "任一接口 class=9 判 hub");
	CHECK(strcmp(dv_classify_classes(0, ifs_hid, 1), "hid") == 0,
	      "单接口 class=3 判 hid");
	CHECK(strcmp(dv_classify_classes(0, ifs_mix, 2), "other") == 0,
	      "多接口异类判 other");
	CHECK(strcmp(dv_classify_classes(8, ifs_none, 0), "storage") == 0,
	      "无接口时回退设备 class");
	CHECK(strcmp(dv_classify_classes(-1, ifs_none, 1), "other") == 0,
	      "未知 class 判 other");

	CHECK(dv_vendor_name("0e0f") && strstr(dv_vendor_name("0e0f"), "VMware"),
	      "厂商表命中 VMware");
	CHECK(dv_product_name("0e0f", "0003") &&
	      strstr(dv_product_name("0e0f", "0003"), "Mouse"),
	      "型号表命中 VMware Mouse");
	CHECK(dv_vendor_name("ffff") == NULL, "未知厂商不猜（NULL）");
	CHECK(dv_product_name("0e0f", "ffff") == NULL, "未知型号不猜（NULL）");

	CHECK(dv_driver_name_valid("usbhid") == 1, "驱动名 usbhid 合法");
	CHECK(dv_driver_name_valid("usb-storage") == 1, "驱动名 usb-storage 合法");
	CHECK(dv_driver_name_valid("") == 0, "空驱动名拒绝");
	CHECK(dv_driver_name_valid("../x") == 0, "含 .. 的驱动名拒绝");
	CHECK(dv_driver_name_valid("a/b") == 0, "含 / 的驱动名拒绝");
	CHECK(dv_driver_forbidden("hub") == 1, "hub 驱动禁止");
	CHECK(dv_driver_forbidden("usb") == 1, "usb 设备级驱动禁止");
	CHECK(dv_driver_forbidden("usbfs") == 1, "usbfs 驱动禁止");
	CHECK(dv_driver_forbidden("usbhid") == 0, "usbhid 驱动允许");
	CHECK(dv_mode_valid("override") == 1, "mode override 合法");
	CHECK(dv_mode_valid("new_id") == 1, "mode new_id 合法");
	CHECK(dv_mode_valid("bind") == 1, "mode bind 合法");
	CHECK(dv_mode_valid("force") == 0, "未知 mode 拒绝");
	CHECK(strcmp(dv_class_cn("hid"), "人机接口(HID)") == 0, "类别中文名 hid");
	CHECK(strcmp(dv_class_cn("unknown-x"), "其他/未分类") == 0,
	      "未知类别中文名兜底");
	CHECK(tool_channel_from_str("device") == TOOL_CH_DEVICE,
	      "channel 字符串 device → TOOL_CH_DEVICE");
}

/* ------------------------------------------------------------------ */
/* 假 sysfs 树：只读 + 安全闸门                                          */
/* ------------------------------------------------------------------ */

static void test_fake_tree(const char *root, const char *state)
{
	char *out = NULL;
	char path[PATH_MAX];
	int rc;

	printf("== fake sysfs: list / identify ==\n");
	rc = call_dev("dev_list", "{\"format\":\"json\"}", &out);
	CHECK(rc == AI_OK && out, "dev_list json 返回 OK");
	CHECK(has(out, "\"schema\":\"aik-usb-list/1\""), "dev_list schema 正确");
	CHECK(has(out, "\"count\":8"), "dev_list 复刻 L1：8 个节点");
	CHECK(has(out, "\"name\":\"usb1\"") && has(out, "\"name\":\"usb2\""),
	      "dev_list 含两个根 hub");
	CHECK(has(out, "\"name\":\"1-2\"") && has(out, "\"name\":\"1-2:1.0\""),
	      "dev_list 含虚拟 hub 及其接口");
	CHECK(has(out, "\"name\":\"1-1\"") && has(out, "\"name\":\"1-1:1.0\""),
	      "dev_list 含虚拟鼠标及其接口");
	CHECK(has(out, "\"id_vendor\":\"0e0f\"") &&
	      has(out, "\"id_product\":\"0003\""), "dev_list 给出 idVendor:idProduct");
	CHECK(has(out, "\"driver\":\"usbhid\""), "dev_list 接口 driver=usbhid");
	CHECK(has(out, "\"is_hub\":true"), "dev_list 标出 hub");
	CHECK(has(out, "\"root_hubs\":2"), "dev_list root_hubs=2");
	CHECK(has(out, "\"hubs\":6"), "dev_list hubs=6（2 根 hub + 2 根 hub 接口 + 虚拟 hub 及其接口）");
	CHECK(json_shape_ok(out), "dev_list JSON 无尾逗号");
	free_out(&out);

	rc = call_dev("dev_list", "{\"format\":\"text\"}", &out);
	CHECK(rc == AI_OK && has(out, "USB 节点 8"), "dev_list text 计数 8");
	free_out(&out);

	rc = call_dev("dev_identify", "{\"device\":\"1-1\"}", &out);
	CHECK(rc == AI_OK && out, "dev_identify 1-1 返回 OK");
	CHECK(has(out, "\"class\":\"hid\""), "identify 1-1 类别 hid");
	CHECK(has(out, "\"ids\":\"0e0f:0003\""), "identify 1-1 ids 0e0f:0003");
	CHECK(has(out, "VMware Virtual USB Mouse"), "identify 1-1 人话名称");
	CHECK(has(out, "\"bindable\":true"), "identify 1-1 可绑定");
	CHECK(has(out, "\"driver\":\"usbhid\""), "identify 接口列表含 usbhid");
	CHECK(has(out, "\"confidence\":\"exact\""), "identify 置信度 exact");
	CHECK(json_shape_ok(out), "identify JSON 无尾逗号");
	free_out(&out);

	rc = call_dev("dev_identify", "{\"device\":\"usb1\"}", &out);
	CHECK(rc == AI_OK && has(out, "\"class\":\"hub\""), "identify usb1=hub");
	CHECK(has(out, "\"bindable\":false"), "identify usb1 不可绑定");
	free_out(&out);

	rc = call_dev("dev_identify", "{\"device\":\"1-2\"}", &out);
	CHECK(rc == AI_OK && has(out, "\"class\":\"hub\""), "identify 1-2=hub");
	free_out(&out);

	rc = call_dev("dev_identify", "{\"device\":\"1-1:1.0\"}", &out);
	CHECK(rc == AI_OK && has(out, "\"kind\":\"interface\""),
	      "identify 1-1:1.0 识别为接口");
	CHECK(has(out, "\"class\":\"hid\""), "identify 1-1:1.0 类别 hid");
	free_out(&out);

	rc = call_dev("dev_identify", "{\"device\":\"9-9\"}", &out);
	CHECK(rc != AI_OK && has(out, "ERROR"), "identify 不存在的设备报错");
	free_out(&out);

	printf("== fake sysfs: safety gates ==\n");
	rc = call_dev("dev_bind", "{\"device\":\"usb1\",\"driver\":\"usbhid\"}", &out);
	CHECK(rc != AI_OK && has(out, "\"error_code\":\"hub_forbidden\""),
	      "根 hub usb1 拒绝（hub_forbidden）");
	CHECK(has(out, "\"changed\":false"), "根 hub 拒绝时 changed=false");
	free_out(&out);
	snprintf(path, sizeof(path), "%s/snapshots/usb1.json", state);
	CHECK(access(path, F_OK) != 0, "根 hub 拒绝后没有快照");

	rc = call_dev("dev_bind", "{\"device\":\"usb2\",\"driver\":\"usbhid\"}", &out);
	CHECK(rc != AI_OK && has(out, "\"error_code\":\"hub_forbidden\""),
	      "根 hub usb2 拒绝");
	free_out(&out);

	rc = call_dev("dev_bind", "{\"device\":\"1-2\",\"driver\":\"usbhid\"}", &out);
	CHECK(rc != AI_OK && has(out, "\"error_code\":\"hub_forbidden\""),
	      "虚拟 hub 1-2 拒绝（class=9）");
	free_out(&out);

	rc = call_dev("dev_bind", "{\"device\":\"1-2:1.0\",\"driver\":\"usbhid\"}", &out);
	CHECK(rc != AI_OK && has(out, "\"error_code\":\"hub_forbidden\""),
	      "hub 接口 1-2:1.0 拒绝");
	free_out(&out);

	rc = call_dev("dev_bind", "{\"device\":\"1-0:1.0\",\"driver\":\"usbhid\"}", &out);
	CHECK(rc != AI_OK && has(out, "\"error_code\":\"hub_forbidden\""),
	      "根 hub 接口 1-0:1.0 拒绝");
	free_out(&out);

	rc = call_dev("dev_bind", "{\"device\":\"1-1\",\"driver\":\"hub\"}", &out);
	CHECK(rc != AI_OK && has(out, "\"error_code\":\"driver_forbidden\""),
	      "目标驱动 hub 拒绝（driver_forbidden）");
	free_out(&out);

	rc = call_dev("dev_bind", "{\"device\":\"1-1\",\"driver\":\"usb\"}", &out);
	CHECK(rc != AI_OK && has(out, "\"error_code\":\"driver_forbidden\""),
	      "目标驱动 usb 拒绝（层级不对）");
	free_out(&out);

	rc = call_dev("dev_bind", "{\"device\":\"1-1\",\"driver\":\"no-such-drv\"}", &out);
	CHECK(rc != AI_OK && has(out, "\"error_code\":\"driver_not_registered\""),
	      "未注册驱动拒绝（不自动 modprobe）");
	free_out(&out);

	rc = call_dev("dev_bind", "{\"device\":\"1-1\",\"driver\":\"usbhid\",\"mode\":\"force\"}", &out);
	CHECK(rc != AI_OK && has(out, "\"error_code\":\"invalid_mode\""),
	      "非法 mode 拒绝");
	free_out(&out);

	rc = call_dev("dev_bind", "{\"device\":\"1-1\",\"driver\":\"usb-storage\",\"dry_run\":true}", &out);
	CHECK(rc == AI_OK && has(out, "\"dry_run\":true"), "dry_run 只报告不写");
	CHECK(has(out, "\"changed\":false") && has(out, "\"saved\":false"),
	      "dry_run 未落快照未改状态");
	free_out(&out);
}

/* ------------------------------------------------------------------ */
/* 假 sysfs 树：绑定失败 → 自动回滚 → 恢复                               */
/* ------------------------------------------------------------------ */

static void test_fake_rollback(const char *root, const char *state)
{
	char *out = NULL;
	char path[PATH_MAX], snap[PATH_MAX], drv[PATH_MAX], ov[PATH_MAX];
	int rc;

	printf("== fake sysfs: bind failure / rollback / restore ==\n");
	rc = call_dev("dev_bind",
		      "{\"device\":\"1-1\",\"driver\":\"usb-storage\",\"mode\":\"override\"}",
		      &out);
	CHECK(rc != AI_OK, "错绑 usb-storage 失败（返回非 OK）");
	CHECK(has(out, "\"error_code\":\"probe_failed\""),
	      "错绑失败原因 probe_failed（驱动接受写但读回不是目标）");
	CHECK(has(out, "\"attempted\":true") && has(out, "\"ok\":true"),
	      "失败后自动回滚且回滚成功");
	CHECK(has(out, "\"message\":\"已恢复到 usbhid\""), "回滚读回 usbhid");
	CHECK(has(out, "\"readback\":{\"driver\":\"usbhid\""),
	      "结果内 readback.driver=usbhid");
	CHECK(has(out, "/drivers/usb-storage/bind"), "写序列含 usb-storage/bind");
	CHECK(has(out, "/drivers/usbhid/unbind"), "写序列含 usbhid/unbind");
	CHECK(has(out, "\"value\":\"1-1:1.0\""), "bind/unbind 写的是接口名 1-1:1.0");
	CHECK(json_shape_ok(out), "bind 失败/回滚 JSON 无尾逗号");
	free_out(&out);

	snprintf(snap, sizeof(snap), "%s/snapshots/1-1.json", state);
	CHECK(access(snap, F_OK) == 0, "快照已落盘");
	{
		char buf[4096];

		CHECK(read_text(snap, buf, sizeof(buf)) == 0 &&
		      has(buf, "\"driver\":\"usbhid\""), "快照记录原驱动 usbhid");
		CHECK(has(buf, "\"iface\":\"1-1:1.0\""), "快照记录接口 1-1:1.0");
	}

	snprintf(drv, sizeof(drv), "%s/drivers/usb-storage/bind", root);
	snprintf(ov, sizeof(ov), "%s/devices/1-1:1.0/driver_override", root);
	{
		char buf[128];

		CHECK(read_text(drv, buf, sizeof(buf)) == 0 &&
		      strcmp(buf, "1-1:1.0") == 0, "bind 文件确实收到 1-1:1.0");
		CHECK(read_text(ov, buf, sizeof(buf)) == 0 && buf[0] == '\0',
		      "回滚后 driver_override 复原为空");
	}

	rc = call_dev("dev_restore", "{\"device\":\"1-1\"}", &out);
	CHECK(rc == AI_OK && has(out, "\"ok\":true"), "dev_restore 成功");
	CHECK(has(out, "\"driver\":\"usbhid\""), "restore 读回 usbhid");
	CHECK(has(out, "\"changed\":false"), "已一致时 restore changed=false");
	CHECK(json_shape_ok(out), "restore JSON 无尾逗号");
	free_out(&out);

	rc = call_dev("dev_bind",
		      "{\"device\":\"1-1:1.0\",\"driver\":\"usbhid\",\"mode\":\"bind\"}",
		      &out);
	CHECK(rc == AI_OK && has(out, "\"changed\":false"),
	      "接口名直传且已绑定：幂等 no-op");
	free_out(&out);

	snprintf(path, sizeof(path), "%s/audit.log", state);
	CHECK(access(path, F_OK) == 0, "审计日志已写入状态目录");
	{
		char buf[8192];

		CHECK(read_text(path, buf, sizeof(buf)) == 0 &&
		      has(buf, "op=dev_bind") && has(buf, "op=rollback_begin") &&
		      has(buf, "op=rollback_end"), "审计含 bind/rollback 记录");
	}
}

/* ------------------------------------------------------------------ */
/* live 模式：真 /sys 六步（硬编码安全目标 1-1）                           */
/* ------------------------------------------------------------------ */

static const char *PROTECTED[] = {
	"usb1", "usb2", "1-0:1.0", "2-0:1.0", "1-2", "1-2:1.0", NULL
};

static int node_sig(const char *node, char *out, size_t cap)
{
	char dir[PATH_MAX], p[PATH_MAX], buf[256], link[PATH_MAX];
	ssize_t n;
	size_t used;

	out[0] = '\0';
	snprintf(dir, sizeof(dir), "/sys/bus/usb/devices/%s", node);
	snprintf(p, sizeof(p), "%s/driver", dir);
	n = readlink(p, link, sizeof(link) - 1);
	if (n > 0) {
		const char *base;

		link[n] = '\0';
		base = strrchr(link, '/');
		snprintf(buf, sizeof(buf), "driver=%s", base ? base + 1 : link);
	} else {
		snprintf(buf, sizeof(buf), "driver=(none)");
	}
	used = strlen(out);
	snprintf(out + used, cap - used, "%s;", buf);
	snprintf(p, sizeof(p), "%s/bDeviceClass", dir);
	if (read_text(p, buf, sizeof(buf)) == 0) {
		used = strlen(out);
		snprintf(out + used, cap - used, "bDeviceClass=%s;", buf);
	}
	snprintf(p, sizeof(p), "%s/bInterfaceClass", dir);
	if (read_text(p, buf, sizeof(buf)) == 0) {
		used = strlen(out);
		snprintf(out + used, cap - used, "bInterfaceClass=%s;", buf);
	}
	snprintf(p, sizeof(p), "%s/driver_override", dir);
	used = strlen(out);
	snprintf(out + used, cap - used, "override=%s",
		 access(p, F_OK) == 0 ? "present" : "absent");
	return 0;
}

static void sigs(char *out, size_t cap)
{
	int i;
	size_t used = 0;

	out[0] = '\0';
	for (i = 0; PROTECTED[i]; i++) {
		char one[512];
		int n;

		node_sig(PROTECTED[i], one, sizeof(one));
		n = snprintf(out + used, cap - used, "%s %s\n",
			     PROTECTED[i], one);
		if (n < 0 || (size_t)n >= cap - used)
			break;
		used += (size_t)n;
	}
}

static void emit(const char *name, const char *cmd, int rc, const char *out)
{
	char path[PATH_MAX];
	FILE *f;

	if (!g_emit)
		return;
	snprintf(path, sizeof(path), "%s/%s", g_emit, name);
	f = fopen(path, "w");
	if (!f)
		return;
	fprintf(f, "CMD: %s\nRC: %d\n\n%s\n", cmd, rc, out ? out : "(null)");
	fclose(f);
}

static int device_attr(const char *dev, const char *attr, char *out,
		       size_t cap)
{
	char p[PATH_MAX];

	snprintf(p, sizeof(p), "/sys/bus/usb/devices/%s/%s", dev, attr);
	return read_text(p, out, cap);
}

static int live_preflight(void)
{
	char vid[32], pid[32], cls[32], nif[32], drv[PATH_MAX], link[PATH_MAX];
	ssize_t n;

	if (geteuid() != 0) {
		printf("REFUSE: --live 需要 root（真写 /sys）\n");
		return -1;
	}
	if (device_attr("1-1", "idVendor", vid, sizeof(vid)) != 0 ||
	    device_attr("1-1", "idProduct", pid, sizeof(pid)) != 0 ||
	    device_attr("1-1", "bNumInterfaces", nif, sizeof(nif)) != 0 ||
	    device_attr("1-1:1.0", "bInterfaceClass", cls, sizeof(cls)) != 0) {
		printf("REFUSE: 找不到 1-1 / 1-1:1.0 或其属性\n");
		return -1;
	}
	if (strcmp(vid, "0e0f") != 0 || strcmp(pid, "0003") != 0 ||
	    strcmp(cls, "03") != 0 || strcmp(nif, "1") != 0) {
		printf("REFUSE: 1-1 不是预期的 VMware 单接口 HID（%s:%s class=%s nif=%s）\n",
		       vid, pid, cls, nif);
		return -1;
	}
	n = readlink("/sys/bus/usb/devices/1-1:1.0/driver", link,
		     sizeof(link) - 1);
	if (n <= 0) {
		printf("REFUSE: 1-1:1.0 当前无驱动，拒绝在不确定状态下开始\n");
		return -1;
	}
	link[n] = '\0';
	snprintf(drv, sizeof(drv), "%s",
		 strrchr(link, '/') ? strrchr(link, '/') + 1 : link);
	if (strcmp(drv, "usbhid") != 0) {
		printf("REFUSE: 1-1:1.0 当前驱动是 %s 而不是 usbhid\n", drv);
		return -1;
	}
	printf("PREFLIGHT OK: 1-1 = %s:%s, 1-1:1.0 class=%s, driver=usbhid\n",
	       vid, pid, cls);
	return 0;
}

static int iface_driver(char *out, size_t cap)
{
	char link[PATH_MAX];
	ssize_t n;

	out[0] = '\0';
	n = readlink("/sys/bus/usb/devices/1-1:1.0/driver", link,
		     sizeof(link) - 1);
	if (n <= 0)
		return 0;
	link[n] = '\0';
	snprintf(out, cap, "%s",
		 strrchr(link, '/') ? strrchr(link, '/') + 1 : link);
	return 0;
}

static void live_cleanup(void)
{
	char drv[64];

	iface_driver(drv, sizeof(drv));
	if (drv[0] && strcmp(drv, "usbhid") != 0) {
		char *out = NULL;
		int rc = call_dev("dev_bind",
				  "{\"device\":\"1-1\",\"driver\":\"usbhid\",\"mode\":\"bind\"}",
				  &out);

		printf("CLEANUP: 当前驱动 %s → 绑回 usbhid rc=%d\n", drv, rc);
		emit("09-cleanup.json", "dev_bind 1-1 usbhid (mode=bind)", rc, out);
		free_out(&out);
	}
}

static int live_run(void)
{
	char *out = NULL;
	char sig_before[4096], sig_after[4096], drv[64], buf[512];
	char audit[16384];
	int rc;

	printf("== LIVE: 1-1 real sysfs (root) ==\n");
	sigs(sig_before, sizeof(sig_before));
	emit("00-preflight-sysfs.txt", "sysfs signature of protected hubs", 0,
	     sig_before);

	/* 1. dev_list */
	rc = call_dev("dev_list", "{\"format\":\"json\"}", &out);
	CHECK(rc == AI_OK && has(out, "\"count\""), "live 1 dev_list OK");
	CHECK(has(out, "\"name\":\"usb1\"") && has(out, "\"name\":\"usb2\""),
	      "live 1 dev_list 含 usb1/usb2");
	CHECK(has(out, "\"name\":\"1-2\"") && has(out, "\"name\":\"1-1:1.0\""),
	      "live 1 dev_list 含 1-2/1-1:1.0");
	emit("01-dev_list.json", "dev_list {format:json}", rc, out);
	free_out(&out);

	/* 2. dev_identify */
	rc = call_dev("dev_identify", "{\"device\":\"1-1\"}", &out);
	CHECK(rc == AI_OK && has(out, "\"class\":\"hid\""),
	      "live 2 identify 1-1 = hid");
	CHECK(has(out, "\"ids\":\"0e0f:0003\"") &&
	      has(out, "VMware Virtual USB Mouse"), "live 2 名称/ids 正确");
	emit("02-dev_identify.json", "dev_identify {device:1-1}", rc, out);
	free_out(&out);

	/* 3. unbind */
	rc = call_dev("dev_bind",
		      "{\"device\":\"1-1\",\"action\":\"unbind\"}", &out);
	CHECK(rc == AI_OK && has(out, "\"ok\":true"), "live 3 unbind 返回 OK");
	CHECK(has(out, "\"readback\":{\"driver\":null"),
	      "live 3 读回 driver 为空");
	CHECK(has(out, "\"device_node_exists\":true"),
	      "live 3 设备节点仍在");
	CHECK(has(out, "\"iface_node_exists\":true"), "live 3 接口节点仍在");
	emit("03-unbind.json", "dev_bind {device:1-1,action:unbind}", rc, out);
	free_out(&out);
	iface_driver(drv, sizeof(drv));
	CHECK(drv[0] == '\0', "live 3 sysfs 侧 1-1:1.0/driver 确实不存在");

	/* 3b. 回到已绑定基线：第 4 步的「失败后恢复原驱动」才有原驱动可恢复 */
	rc = call_dev("dev_bind",
		      "{\"device\":\"1-1\",\"driver\":\"usbhid\",\"mode\":\"bind\"}",
		      &out);
	CHECK(rc == AI_OK && has(out, "\"ok\":true"),
	      "live 3b 基线重新绑定 usbhid");
	CHECK(has(out, "\"readback\":{\"driver\":\"usbhid\""),
	      "live 3b 读回 usbhid");
	emit("03b-rebind-baseline.json",
	     "dev_bind {device:1-1,driver:usbhid,mode:bind}", rc, out);
	free_out(&out);

	/* 4a. override attempt (this kernel may lack driver_override) */
	rc = call_dev("dev_bind",
		      "{\"device\":\"1-1\",\"driver\":\"usb-storage\",\"mode\":\"override\"}",
		      &out);
	CHECK(rc != AI_OK, "live 4a override 错绑失败（预期）");
	CHECK(has(out, "\"error_code\":\"override_unsupported\"") ||
	      (has(out, "\"error_code\":\"probe_failed\"") &&
	       has(out, "\"attempted\":true")),
	      "live 4a 失败原因是 override 不可用或 probe 失败");
	emit("04a-override-attempt.json",
	     "dev_bind {device:1-1,driver:usb-storage,mode:override}", rc, out);
	free_out(&out);

	/* 4b. new_id forced wrong bind → real probe failure → rollback */
	rc = call_dev("dev_bind",
		      "{\"device\":\"1-1\",\"driver\":\"usb-storage\",\"mode\":\"new_id\"}",
		      &out);
	CHECK(rc != AI_OK, "live 4b new_id 错绑失败（预期）");
	CHECK(has(out, "\"error_code\":\"probe_failed\"") ||
	      has(out, "\"error_code\":\"bind_failed\""),
	      "live 4b 错绑失败原因是 probe/bind 失败");
	CHECK(has(out, "\"attempted\":true") && has(out, "\"ok\":true"),
	      "live 4b 自动回滚且回滚成功");
	CHECK(has(out, "\"readback\":{\"driver\":\"usbhid\""),
	      "live 4b 回滚读回 usbhid");
	emit("04b-newid-wrong-bind.json",
	     "dev_bind {device:1-1,driver:usb-storage,mode:new_id}", rc, out);
	free_out(&out);
	iface_driver(drv, sizeof(drv));
	CHECK(strcmp(drv, "usbhid") == 0, "live 4b sysfs 侧驱动已回到 usbhid");

	/* 5. bind back to usbhid (explicit unbind then bind) */
	rc = call_dev("dev_bind",
		      "{\"device\":\"1-1\",\"action\":\"unbind\"}", &out);
	CHECK(rc == AI_OK, "live 5 先撤到未绑定");
	emit("05a-unbind-before-rebind.json",
	     "dev_bind {device:1-1,action:unbind}", rc, out);
	free_out(&out);
	rc = call_dev("dev_bind",
		      "{\"device\":\"1-1\",\"driver\":\"usbhid\",\"mode\":\"bind\"}",
		      &out);
	CHECK(rc == AI_OK && has(out, "\"ok\":true"), "live 5 绑回 usbhid 成功");
	CHECK(has(out, "\"readback\":{\"driver\":\"usbhid\""),
	      "live 5 读回 driver=usbhid");
	CHECK(has(out, "\"input_ok\":true"), "live 5 输入设备重新出现");
	CHECK(has(out, "\"input_device_count\":1") ||
	      has(out, "\"input_device_count\":2"),
	      "live 5 /proc/bus/input/devices 可见该鼠标");
	emit("05b-rebind-usbhid.json",
	     "dev_bind {device:1-1,driver:usbhid,mode:bind}", rc, out);
	free_out(&out);

	/* 6. dev_list after + protected hub comparison */
	rc = call_dev("dev_list", "{\"format\":\"json\"}", &out);
	CHECK(rc == AI_OK && has(out, "\"driver\":\"usbhid\""),
	      "live 6 dev_list 显示 1-1:1.0 已回 usbhid");
	emit("06-dev_list-after.json", "dev_list {format:json}", rc, out);
	free_out(&out);
	sigs(sig_after, sizeof(sig_after));
	CHECK(strcmp(sig_before, sig_after) == 0,
	      "live 6 受保护 hub 节点前后签名完全一致");
	emit("07-protected-hubs-before-after.txt",
	     "hub signature compare", 0,
	     sig_before);
	{
		char path[PATH_MAX];
		FILE *f;

		if (g_emit) {
			snprintf(path, sizeof(path), "%s/07b-protected-hubs-after.txt",
				 g_emit);
			f = fopen(path, "w");
			if (f) {
				fprintf(f, "%s", sig_after);
				fclose(f);
			}
			snprintf(path, sizeof(path), "%s/state/audit.log", g_emit);
			if (read_text(path, audit, sizeof(audit)) == 0)
				emit("08-audit.log", "state/audit.log", 0, audit);
		}
	}

	/* verify input node by /proc/bus/input/devices */
	{
		int found = 0;
		FILE *f;

		f = fopen("/proc/bus/input/devices", "r");
		if (f) {
			while (fgets(buf, sizeof(buf), f)) {
				if (strstr(buf, "VMware Virtual USB Mouse"))
					found = 1;
			}
			fclose(f);
		}
		CHECK(found, "live 5b /proc/bus/input/devices 仍列出该鼠标");
	}

	live_cleanup();
	return 0;
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	char tmp[] = "/tmp/aik-devtest-XXXXXX";
	char tmp2[] = "/tmp/aik-devtest-XXXXXX";
	char state[PATH_MAX];
	int live = 0;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0)
			live = 1;
		else if (strcmp(argv[i], "--emit") == 0 && i + 1 < argc)
			g_emit = argv[++i];
	}

	if (live) {
		if (g_emit) {
			mkdir_p(g_emit);
			snprintf(state, sizeof(state), "%s/state", g_emit);
			mkdir_p(state);
		} else {
			snprintf(state, sizeof(state), "/run/aik-device");
		}
		setenv("AIKERNEL_DEVICE_DIR", state, 1);
		if (live_preflight() != 0)
			return 3;
		live_run();
		printf("\n== test_device_tools: %s (%d checks, %d fails) ==\n",
		       fails ? "FAIL" : "ALL PASS", checks, fails);
		return fails ? 1 : 0;
	}

	if (!mkdtemp(tmp) || !mkdtemp(tmp2)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(state, sizeof(state), "%s/state", tmp);
	mkdir_p(state);
	setenv("AIKERNEL_USB_SYSFS_ROOT", tmp, 1);
	setenv("AIKERNEL_DEVICE_DIR", state, 1);

	if (make_tree(tmp, 0) != 0 || make_tree(tmp2, 1) != 0) {
		fprintf(stderr, "fake tree build failed\n");
		rm_tree(tmp);
		rm_tree(tmp2);
		return 1;
	}

	test_pure();
	test_fake_tree(tmp, state);
	test_fake_rollback(tmp, state);

	/* 第二棵树：多接口/无 override 设备的安全闸门 */
	setenv("AIKERNEL_USB_SYSFS_ROOT", tmp2, 1);
	{
		char *out = NULL;
		int rc = call_dev("dev_bind",
				  "{\"device\":\"1-3\",\"driver\":\"usbhid\"}",
				  &out);

		CHECK(rc != AI_OK &&
		      has(out, "\"error_code\":\"multi_interface_forbidden\""),
		      "第二棵树多接口 1-3 仍拒绝");
		free_out(&out);
		rc = call_dev("dev_identify", "{\"device\":\"3-1\"}", &out);
		CHECK(rc == AI_OK && has(out, "\"bindable\":true"),
		      "3-1 单接口可绑定");
		CHECK(has(out, "\"driver_override_present\":false"),
		      "3-1 明确报告无 driver_override");
		free_out(&out);
		rc = call_dev("dev_bind",
			      "{\"device\":\"3-1\",\"driver\":\"usb-storage\",\"mode\":\"override\"}",
			      &out);
		CHECK(rc != AI_OK &&
		      has(out, "\"error_code\":\"override_unsupported\""),
		      "无 driver_override 时 override fail-closed");
		CHECK(has(out, "\"changed\":false"), "override 不可用时不改状态");
		free_out(&out);
		rc = call_dev("dev_restore", "{\"device\":\"3-1\"}", &out);
		CHECK(rc != AI_OK &&
		      has(out, "\"error_code\":\"snapshot_missing\""),
		      "无快照时 restore 明确拒绝（snapshot_missing）");
		free_out(&out);
	}

	rm_tree(tmp);
	rm_tree(tmp2);
	printf("\n== test_device_tools: %s (%d checks, %d fails, %d skips) ==\n",
	       fails ? "FAIL" : "ALL PASS", checks, fails, skips);
	return fails ? 1 : 0;
}
