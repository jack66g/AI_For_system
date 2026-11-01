// SPDX-License-Identifier: GPL-2.0
/*
 * device_tools.c - W82 V5.1..V5.4 设备身份 + 绑定 + 四级适配（USB 先行）
 *
 * 设计说明见 device_tools.h。本文件分七段：
 *   1) 有界输出缓冲 / JSON 转义 / 内置最小 ids 表 / 纯判定函数
 *   2) sysfs 只读原语（读属性、读 driver 软链、列目录、状态目录、审计）
 *   3) 设备事实收集（设备 + 接口 + hub 判定 + 绑定安全规则）
 *   4) dev_list / dev_identify（只读）
 *   5) 快照（落盘 + 读回）与 dev_bind / dev_restore（写 /sys + 回滚）
 *   6) dev_adapt（四级递进 + 后台 daemon）与 dev_task（status/cancel/log）
 *   7) 通道入口
 *
 * 关键不变量：
 *   - 任何 /sys 写之前 dv_snap_save() 必须已成功（ctx->snapshot_ready）；
 *     dv_ctx_write() 在无快照时直接拒绝并审计（不写）。
 *   - 每次写都进 writes[] 与 audit.log（路径、值、rc、errno）。
 *   - 失败回滚后必须读回校验；校验不通过时结果里 rollback.ok=false 且
 *     error_code 保持失败原因，绝不把回滚失败粉饰成成功。
 *   - 适配任务只有「读回 driver == 目标」且（HID 目标）有输入设备才算该级
 *     成功；四级全失败必须 ok=false 并保证设备回到任务开始前的驱动。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "device_tools.h"

/* ======================================================================
 * 1) 有界缓冲 / 转义 / ids 表 / 纯函数
 * ====================================================================== */

struct dvb {
	char *p;
	size_t len;
	size_t cap;
	int trunc;
};

static void dvb_init(struct dvb *b, char *buf, size_t cap)
{
	b->p = buf;
	b->len = 0;
	b->cap = cap;
	b->trunc = 0;
	if (cap)
		buf[0] = '\0';
}

static void dvb_putc(struct dvb *b, char c)
{
	if (!b || b->trunc)
		return;
	if (b->len + 2 > b->cap) {
		b->trunc = 1;
		return;
	}
	b->p[b->len++] = c;
	b->p[b->len] = '\0';
}

/* dvb_kv_* 一律写尾逗号；对象/数组收口前把最后一个逗号退掉，
 * 保证输出是严格 JSON（无尾逗号）。 */
static void dvb_trim_comma(struct dvb *b)
{
	if (b && !b->trunc && b->len > 0 && b->p[b->len - 1] == ',') {
		b->len--;
		b->p[b->len] = '\0';
	}
}

static void dvb_obj_close(struct dvb *b)
{
	dvb_trim_comma(b);
	dvb_putc(b, '}');
}

static void dvb_arr_close(struct dvb *b)
{
	dvb_trim_comma(b);
	dvb_putc(b, ']');
}

static void dvb_puts(struct dvb *b, const char *s)
{
	size_t n;

	if (!b || b->trunc || !s)
		return;
	n = strlen(s);
	if (b->len + n + 1 > b->cap) {
		b->trunc = 1;
		return;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

static void dvb_printf(struct dvb *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!b || b->trunc)
		return;
	va_start(ap, fmt);
	n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
	va_end(ap);
	if (n < 0) {
		b->trunc = 1;
		return;
	}
	if ((size_t)n >= b->cap - b->len) {
		b->trunc = 1;
		b->len = b->cap - 1;
		b->p[b->len] = '\0';
		return;
	}
	b->len += (size_t)n;
}

static void dvb_json_str(struct dvb *b, const char *s)
{
	const unsigned char *p;

	if (!s) {
		dvb_puts(b, "null");
		return;
	}
	dvb_putc(b, '"');
	for (p = (const unsigned char *)s; *p; p++) {
		switch (*p) {
		case '"':
			dvb_puts(b, "\\\"");
			break;
		case '\\':
			dvb_puts(b, "\\\\");
			break;
		case '\n':
			dvb_puts(b, "\\n");
			break;
		case '\r':
			dvb_puts(b, "\\r");
			break;
		case '\t':
			dvb_puts(b, "\\t");
			break;
		case '\b':
			dvb_puts(b, "\\b");
			break;
		case '\f':
			dvb_puts(b, "\\f");
			break;
		default:
			if (*p < 0x20)
				dvb_printf(b, "\\u%04x", *p);
			else
				dvb_putc(b, (char)*p);
			break;
		}
	}
	dvb_putc(b, '"');
}

static void dvb_kv_str(struct dvb *b, const char *key, const char *val)
{
	dvb_json_str(b, key);
	dvb_putc(b, ':');
	dvb_json_str(b, val);
	dvb_putc(b, ',');
}

static void dvb_kv_bool(struct dvb *b, const char *key, int val)
{
	dvb_json_str(b, key);
	dvb_putc(b, ':');
	dvb_puts(b, val ? "true" : "false");
	dvb_putc(b, ',');
}

static void dvb_kv_int(struct dvb *b, const char *key, long long val)
{
	dvb_json_str(b, key);
	dvb_printf(b, ":%lld,", val);
}

/* ---- 内置最小 ids 表（认不出返回 NULL，绝不猜） ---- */

struct dv_id {
	const char *id;
	const char *name;
};

static const struct dv_id dv_vendors[] = {
	{ "1d6b", "Linux Foundation" },
	{ "0e0f", "VMware, Inc." },
	{ "046d", "Logitech, Inc." },
	{ "8087", "Intel Corp." },
	{ "0bda", "Realtek Semiconductor Corp." },
	{ "05ac", "Apple, Inc." },
	{ "0781", "SanDisk Corp." },
	{ "0951", "Kingston Technology" },
	{ "1a40", "Terminus Technology Inc." },
	{ "04d9", "Holtek Semiconductor, Inc." },
	{ "0461", "Primax Electronics, Ltd" },
	{ "413c", "Dell Computer Corp." },
	{ "17ef", "Lenovo" },
	{ "045e", "Microsoft Corp." },
	{ "1bcf", "Sunplus Innovation Technology Inc." },
	{ "2109", "VIA Labs, Inc." },
	{ "0bc2", "Seagate RSS LLC" },
	{ "1058", "Western Digital Technologies, Inc." },
	{ "04e8", "Samsung Electronics Co., Ltd" },
	{ "2717", "Xiaomi Inc." },
	{ "18d1", "Google Inc." },
	{ "0483", "STMicroelectronics" },
	{ "05e3", "Genesys Logic, Inc." },
	{ "0b05", "ASUSTek Computer, Inc." },
};

static const struct dv_id dv_products[] = {
	{ "1d6b:0001", "1.1 root hub" },
	{ "1d6b:0002", "2.0 root hub" },
	{ "1d6b:0003", "3.0 root hub" },
	{ "0e0f:0002", "VMware Virtual USB Hub" },
	{ "0e0f:0003", "VMware Virtual USB Mouse" },
};

const char *dv_vendor_name(const char *vid)
{
	size_t i;

	if (!vid || !vid[0])
		return NULL;
	for (i = 0; i < sizeof(dv_vendors) / sizeof(dv_vendors[0]); i++)
		if (strcasecmp(vid, dv_vendors[i].id) == 0)
			return dv_vendors[i].name;
	return NULL;
}

const char *dv_product_name(const char *vid, const char *pid)
{
	char key[32];
	size_t i;

	if (!vid || !pid || !vid[0] || !pid[0])
		return NULL;
	snprintf(key, sizeof(key), "%s:%s", vid, pid);
	for (i = 0; i < sizeof(dv_products) / sizeof(dv_products[0]); i++)
		if (strcasecmp(key, dv_products[i].id) == 0)
			return dv_products[i].name;
	return NULL;
}

int dv_node_name_valid(const char *name)
{
	size_t i, n;

	if (!name || !name[0])
		return 0;
	n = strlen(name);
	if (n >= DV_NAME_MAX || name[0] == '.')
		return 0;
	if (strstr(name, ".."))
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)name[i];

		if (isalnum(c) || c == '.' || c == '_' || c == '-' || c == ':')
			continue;
		return 0;
	}
	return 1;
}

int dv_is_root_hub_name(const char *name)
{
	size_t i;

	if (!name || strncmp(name, "usb", 3) != 0)
		return 0;
	if (!name[3])
		return 0;
	for (i = 3; name[i]; i++)
		if (!isdigit((unsigned char)name[i]))
			return 0;
	return 1;
}

static const char *dv_class_single(int cls)
{
	switch (cls) {
	case 1:
		return "audio";
	case 2:
		return "net";
	case 3:
		return "hid";
	case 8:
		return "storage";
	case 9:
		return "hub";
	default:
		return "other";
	}
}

const char *dv_classify_classes(int dev_class, const int *iface_classes,
				int n_ifaces)
{
	int i;

	/* hub 优先：设备级或任一接口 class=9，绝不把 hub 说成别的 */
	if (dev_class == 9)
		return "hub";
	for (i = 0; i < n_ifaces; i++)
		if (iface_classes && iface_classes[i] == 9)
			return "hub";
	if (n_ifaces <= 0)
		return dv_class_single(dev_class);
	if (n_ifaces == 1)
		return dv_class_single(iface_classes[0]);
	/* 多接口：只有全部同类才给该类，否则老实说 other（复合/未归类） */
	for (i = 1; i < n_ifaces; i++)
		if (iface_classes[i] != iface_classes[0])
			return "other";
	return dv_class_single(iface_classes[0]);
}

const char *dv_class_cn(const char *cls)
{
	if (!cls)
		return "其他/未分类";
	if (strcmp(cls, "hub") == 0)
		return "集线器";
	if (strcmp(cls, "hid") == 0)
		return "人机接口(HID)";
	if (strcmp(cls, "storage") == 0)
		return "存储";
	if (strcmp(cls, "net") == 0)
		return "网络";
	if (strcmp(cls, "audio") == 0)
		return "音频";
	return "其他/未分类";
}

int dv_driver_name_valid(const char *drv)
{
	size_t i, n;

	if (!drv || !drv[0])
		return 0;
	n = strlen(drv);
	if (n >= DV_MAX_DRIVER)
		return 0;
	if (strstr(drv, ".."))
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)drv[i];

		if (isalnum(c) || c == '.' || c == '_' || c == '-')
			continue;
		return 0;
	}
	return 1;
}

int dv_driver_forbidden(const char *drv)
{
	if (!drv)
		return 1;
	/* hub：class 9 专用驱动，绑 HID 必炸且可能影响整条总线；
	 * usb/usbfs：设备级驱动，不是接口驱动，层级不对。 */
	return strcmp(drv, "hub") == 0 || strcmp(drv, "usb") == 0 ||
	       strcmp(drv, "usbfs") == 0;
}

int dv_mode_valid(const char *mode)
{
	if (!mode)
		return 0;
	return strcmp(mode, "override") == 0 || strcmp(mode, "new_id") == 0 ||
	       strcmp(mode, "bind") == 0;
}

/* ======================================================================
 * 2) 路径 / 文件原语 / 状态目录 / 审计
 * ====================================================================== */

static int dv_append(char *out, size_t cap, const char *s)
{
	size_t l, n;

	if (!out || !s || cap == 0)
		return -1;
	l = strlen(out);
	n = strlen(s);
	if (l + n + 1 > cap)
		return -1;
	memcpy(out + l, s, n + 1);
	return 0;
}

static int dv_join(char *out, size_t cap, const char *a, const char *b)
{
	if (!out || cap == 0)
		return -1;
	out[0] = '\0';
	if (dv_append(out, cap, a) != 0)
		return -1;
	if (dv_append(out, cap, "/") != 0)
		return -1;
	return dv_append(out, cap, b);
}

static int dv_dir_exists(const char *path)
{
	struct stat st;

	return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int dv_file_exists(const char *path)
{
	return path && access(path, F_OK) == 0;
}

static int dv_read_text_path(const char *path, char *out, size_t cap)
{
	int fd;
	ssize_t n;

	if (!path || !out || cap == 0)
		return -1;
	out[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, out, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	out[n] = '\0';
	while (n > 0 && isspace((unsigned char)out[n - 1]))
		out[--n] = '\0';
	return 0;
}

static int dv_read_attr(const char *dir, const char *attr, char *out,
			size_t cap)
{
	char path[DV_PATH_MAX];

	if (dv_join(path, sizeof(path), dir, attr) != 0)
		return -1;
	return dv_read_text_path(path, out, cap);
}

static int dv_read_int_attr(const char *dir, const char *attr, int base,
			    int *val)
{
	char buf[64];
	char *end;
	long v;

	if (!val)
		return -1;
	if (dv_read_attr(dir, attr, buf, sizeof(buf)) != 0 || !buf[0])
		return -1;
	errno = 0;
	v = strtol(buf, &end, base);
	if (errno != 0 || end == buf || v < 0 || v > 0xffff)
		return -1;
	*val = (int)v;
	return 0;
}

/* driver 软链 → 驱动名；未绑定返回 0 且 out[0]==0 */
static int dv_read_driver(const char *node_dir, char *out, size_t cap)
{
	char path[DV_PATH_MAX], buf[PATH_MAX];
	ssize_t n;
	const char *base;

	if (!out || cap == 0)
		return -1;
	out[0] = '\0';
	if (dv_join(path, sizeof(path), node_dir, "driver") != 0)
		return -1;
	n = readlink(path, buf, sizeof(buf) - 1);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	base = strrchr(buf, '/');
	base = base ? base + 1 : buf;
	snprintf(out, cap, "%s", base);
	return 0;
}

/* driver_override 内容（可能为空串）；present 标记属性是否存在 */
static int dv_read_override(const char *node_dir, char *out, size_t cap,
			    int *present)
{
	char path[DV_PATH_MAX];

	if (present)
		*present = 0;
	if (!out || cap == 0)
		return -1;
	out[0] = '\0';
	if (dv_join(path, sizeof(path), node_dir, "driver_override") != 0)
		return -1;
	if (!dv_file_exists(path))
		return 0;
	if (present)
		*present = 1;
	return dv_read_text_path(path, out, cap);
}

static int dv_write_raw(const char *path, const char *value, int *err_out)
{
	int fd, err;
	size_t len;
	ssize_t w;
	char buf[DV_MAX_OVERRIDE + 8];

	if (err_out)
		*err_out = 0;
	if (!path || !value)
		return -1;
	len = strlen(value);
	if (len + 2 > sizeof(buf)) {
		if (err_out)
			*err_out = EINVAL;
		return -1;
	}
	memcpy(buf, value, len);
	buf[len++] = '\n';
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (err_out)
			*err_out = errno;
		return -1;
	}
	errno = 0;
	w = write(fd, buf, len);
	err = errno;
	/* 假 sysfs 单测树是普通文件，不支持 sysfs 的「整属性替换」语义：
	 * 写短值会留下旧内容尾部。真实 /sys（/sys/...）绝不 truncate；
	 * 只有测试根（非 /sys 前缀）才补一次 ftruncate，模拟 sysfs。 */
	if (w == (ssize_t)len && strncmp(path, "/sys/", 5) != 0) {
		ssize_t tr = ftruncate(fd, (off_t)len);

		(void)tr;
	}
	close(fd);
	if (w != (ssize_t)len) {
		if (err_out)
			*err_out = err ? err : EIO;
		return -1;
	}
	return 0;
}

static int dv_mkdir_one(const char *path)
{
	if (mkdir(path, 0700) == 0)
		return 0;
	if (errno == EEXIST && dv_dir_exists(path))
		return 0;
	return -1;
}

static int dv_state_dir(char *out, size_t cap)
{
	const char *env = getenv("AIKERNEL_DEVICE_DIR");
	char base[DV_PATH_MAX], snaps[DV_PATH_MAX];

	if (env && env[0]) {
		if (env[0] != '/' || strstr(env, ".."))
			return -1;
		snprintf(base, sizeof(base), "%s", env);
	} else if (geteuid() == 0) {
		snprintf(base, sizeof(base), "%s", "/run/aik-device");
	} else {
		snprintf(base, sizeof(base), "/tmp/aik-device-%lu",
			 (unsigned long)geteuid());
	}
	if (dv_mkdir_one(base) != 0)
		return -1;
	if (dv_join(snaps, sizeof(snaps), base, "snapshots") != 0)
		return -1;
	if (dv_mkdir_one(snaps) != 0)
		return -1;
	if (!out || cap == 0)
		return -1;
	snprintf(out, cap, "%s", base);
	return 0;
}

static void dv_audit(const char *fmt, ...)
{
	char dir[DV_PATH_MAX], path[DV_PATH_MAX], line[1024], stamp[32];
	struct tm tm;
	time_t now;
	va_list ap;
	int fd, n;

	if (dv_state_dir(dir, sizeof(dir)) != 0 ||
	    dv_join(path, sizeof(path), dir, "audit.log") != 0)
		return;
	now = time(NULL);
	gmtime_r(&now, &tm);
	strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm);
	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	dprintf(fd, "%s %s\n", stamp, line);
	close(fd);
}

/* 原子写文件（快照用）：tmp + fsync + rename */
static int dv_write_file_atomic(const char *path, const char *data, char *err,
				size_t errcap)
{
	char tmp[DV_PATH_MAX + 32];
	int fd, errn = 0;
	size_t len = strlen(data), off = 0;

	snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		errn = errno;
		goto fail;
	}
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			errn = errno;
			close(fd);
			goto fail;
		}
		off += (size_t)w;
	}
	if (fsync(fd) != 0)
		errn = errno;
	close(fd);
	if (errn == 0 && rename(tmp, path) == 0)
		return 0;
	if (errn == 0)
		errn = errno;
fail:
	if (err)
		snprintf(err, errcap, "写 %s 失败: %s", path,
			 strerror(errn ? errn : EIO));
	unlink(tmp);
	return -1;
}

/* 列目录子项（可选前缀），按名字排序；调用者用 dv_free_children 释放 */
static void dv_free_children(char **arr, int n);
static void dv_readback(const char *root, const char *node_dir, char *drv,
			size_t drvcap, char *ov, size_t ovcap, int *ov_present);

static int dv_list_children(const char *dir, const char *prefix, char ***out,
			    int *out_n)
{
	DIR *d;
	struct dirent *de;
	char **arr = NULL;
	int n = 0, cap = 0, i, j;

	if (out)
		*out = NULL;
	if (out_n)
		*out_n = 0;
	if (!dir || !dv_dir_exists(dir))
		return -1;
	d = opendir(dir);
	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		char *dup;

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		if (prefix && strncmp(de->d_name, prefix, strlen(prefix)) != 0)
			continue;
		if (n == cap) {
			int ncap = cap ? cap * 2 : 8;
			char **tmp = realloc(arr, (size_t)ncap * sizeof(*arr));

			if (!tmp)
				break;
			arr = tmp;
			cap = ncap;
		}
		dup = strdup(de->d_name);
		if (!dup)
			break;
		arr[n++] = dup;
	}
	closedir(d);
	for (i = 0; i < n; i++)
		for (j = i + 1; j < n; j++)
			if (strcmp(arr[i], arr[j]) > 0) {
				char *t = arr[i];

				arr[i] = arr[j];
				arr[j] = t;
			}
	if (!out) {
		dv_free_children(arr, n);
	} else {
		*out = arr;
	}
	if (out_n)
		*out_n = n;
	return 0;
}

static void dv_free_children(char **arr, int n)
{
	int i;

	if (!arr)
		return;
	for (i = 0; i < n; i++)
		free(arr[i]);
	free(arr);
}

static int dv_root_is_real_sysfs(const char *root)
{
	char real[PATH_MAX];

	if (!root || !realpath(root, real))
		return 0;
	return strcmp(real, "/sys") == 0 || strncmp(real, "/sys/", 5) == 0;
}

/* sysfs 根：默认 /sys/bus/usb；AIKERNEL_USB_SYSFS_ROOT 只给单测用。
 * 该环境变量只改变本工具的读取/写路径，不改变写真实 /sys 仍需 root 的
 * 硬约束（见 dv_tool_bind）。非绝对路径、含 ".."、目录不存在一律拒绝。 */
static int dv_sysfs_root(char *out, size_t cap, char *err, size_t errcap)
{
	const char *env = getenv("AIKERNEL_USB_SYSFS_ROOT");
	const char *root;
	struct stat st;

	if (err && errcap)
		err[0] = '\0';
	if (!out || cap == 0)
		return -1;
	root = (env && env[0]) ? env : "/sys/bus/usb";
	if (root[0] != '/' || strstr(root, "..")) {
		if (err)
			snprintf(err, errcap, "USB sysfs 根必须是绝对路径且不含 ..: %s",
				 root);
		return -1;
	}
	if (stat(root, &st) != 0 || !S_ISDIR(st.st_mode)) {
		if (err)
			snprintf(err, errcap, "USB sysfs 根不存在或不是目录: %s",
				 root);
		return -1;
	}
	snprintf(out, cap, "%s", root);
	return 0;
}

/* ======================================================================
 * 3) 设备事实 + 绑定安全规则
 * ====================================================================== */

struct dv_facts {
	char dev[DV_NAME_MAX];		/* 设备节点名（接口名前缀） */
	char node[DV_NAME_MAX];		/* 目标节点（设备或接口） */
	char iface[DV_NAME_MAX];	/* 唯一接口名（多接口时为空） */
	int node_is_iface;
	int node_exists;
	int dev_dir_exists;
	int dev_class;
	int bnum_ifaces;
	int n_iface_dirs;
	char iface_name[DV_MAX_IFACES][DV_NAME_MAX];
	int iface_class[DV_MAX_IFACES];
	int n_iface_classes;
	int iface_class_ok;
	int is_root_hub;
	int is_hub;
	int bindable;
	char driver[DV_MAX_DRIVER];
	char override[DV_MAX_OVERRIDE];
	int override_present;
	char modalias[256];
	char id_vendor[16];
	char id_product[16];
	char product[128];
	char manufacturer[128];
};

static int dv_collect(const char *root, const char *name, struct dv_facts *f,
		      char *err, size_t errcap)
{
	char devices[DV_PATH_MAX], node_dir[DV_PATH_MAX], dev_dir[DV_PATH_MAX];
	char prefix[DV_NAME_MAX + 2];
	char **ifs = NULL;
	int nifs = 0, i, cls;

	if (err && errcap)
		err[0] = '\0';
	if (!f)
		return -1;
	memset(f, 0, sizeof(*f));
	f->dev_class = -1;
	f->bnum_ifaces = -1;
	f->iface_class_ok = 1;
	if (!dv_node_name_valid(name)) {
		if (err)
			snprintf(err, errcap, "非法 USB 节点名: %s",
				 name ? name : "(null)");
		return -1;
	}
	snprintf(f->node, sizeof(f->node), "%s", name);
	if (dv_join(devices, sizeof(devices), root, "devices") != 0 ||
	    dv_join(node_dir, sizeof(node_dir), devices, name) != 0) {
		if (err)
			snprintf(err, errcap, "sysfs 路径过长");
		return -1;
	}
	if (!dv_dir_exists(node_dir)) {
		if (err)
			snprintf(err, errcap, "USB 设备节点不存在: %s",
				 node_dir);
		return -1;
	}
	f->node_exists = 1;
	f->node_is_iface = strchr(name, ':') != NULL;
	{
		const char *colon = strchr(name, ':');
		size_t n = colon ? (size_t)(colon - name) : strlen(name);

		if (n >= sizeof(f->dev))
			n = sizeof(f->dev) - 1;
		memcpy(f->dev, name, n);
		f->dev[n] = '\0';
	}
	if (dv_join(dev_dir, sizeof(dev_dir), devices, f->dev) != 0) {
		if (err)
			snprintf(err, errcap, "sysfs 路径过长");
		return -1;
	}
	f->dev_dir_exists = dv_dir_exists(dev_dir);
	if (f->dev_dir_exists) {
		if (dv_read_attr(dev_dir, "idVendor", f->id_vendor,
				 sizeof(f->id_vendor)) != 0)
			f->id_vendor[0] = '\0';
		if (dv_read_attr(dev_dir, "idProduct", f->id_product,
				 sizeof(f->id_product)) != 0)
			f->id_product[0] = '\0';
		if (dv_read_int_attr(dev_dir, "bDeviceClass", 16,
				     &f->dev_class) != 0)
			f->dev_class = -1;
		if (dv_read_int_attr(dev_dir, "bNumInterfaces", 10,
				     &f->bnum_ifaces) != 0)
			f->bnum_ifaces = -1;
		if (dv_read_attr(dev_dir, "product", f->product,
				 sizeof(f->product)) != 0)
			f->product[0] = '\0';
		if (dv_read_attr(dev_dir, "manufacturer", f->manufacturer,
				 sizeof(f->manufacturer)) != 0)
			f->manufacturer[0] = '\0';
		if (dv_read_attr(dev_dir, "modalias", f->modalias,
				 sizeof(f->modalias)) != 0)
			f->modalias[0] = '\0';
	}

	snprintf(prefix, sizeof(prefix), "%s:", f->dev);
	if (dv_list_children(devices, prefix, &ifs, &nifs) != 0) {
		nifs = 0;
		ifs = NULL;
	}
	f->n_iface_dirs = nifs;
	for (i = 0; i < nifs && i < DV_MAX_IFACES; i++) {
		char idir[DV_PATH_MAX];

		snprintf(f->iface_name[i], DV_NAME_MAX, "%s", ifs[i]);
		cls = -1;
		if (dv_join(idir, sizeof(idir), devices, ifs[i]) == 0 &&
		    dv_read_int_attr(idir, "bInterfaceClass", 16, &cls) == 0) {
			f->iface_class[i] = cls;
		} else {
			f->iface_class_ok = 0;
			f->iface_class[i] = -1;
		}
		f->n_iface_classes = i + 1;
	}
	if (f->node_is_iface)
		snprintf(f->iface, sizeof(f->iface), "%s", name);
	else if (nifs == 1)
		snprintf(f->iface, sizeof(f->iface), "%s", ifs[0]);

	f->is_root_hub = dv_is_root_hub_name(f->dev);
	f->is_hub = f->is_root_hub || f->dev_class == 9;
	for (i = 0; i < f->n_iface_classes; i++)
		if (f->iface_class[i] == 9)
			f->is_hub = 1;

	dv_read_driver(node_dir, f->driver, sizeof(f->driver));
	dv_read_override(node_dir, f->override, sizeof(f->override),
			 &f->override_present);

	/* 绑定安全：非 hub + 单接口 + 有唯一接口节点 */
	f->bindable = 0;
	if (!f->is_hub && !f->is_root_hub && !(f->bnum_ifaces > 1) &&
	    f->n_iface_dirs == 1 && f->iface[0])
		f->bindable = 1;

	dv_free_children(ifs, nifs);
	if (err && errcap)
		err[0] = '\0';
	return 0;
}

/* 绑定/解绑/恢复的真正操作节点是「接口」，不是设备。
 * 设备节点（如 1-1）上只有设备级驱动 usb（usbcore），接口驱动是
 * 1-1:1.0 上的 usbhid；若拿设备节点做 bind/unbind 会解绑整条设备
 * （连带所有接口），这正是本工具必须避免的事故。用户传设备名时，
 * 这里把它解析到唯一接口节点，并从接口目录重读 driver/override。 */
static int dv_op_node(const char *root, struct dv_facts *f)
{
	char devices[DV_PATH_MAX], node_dir[DV_PATH_MAX];

	if (!f || f->node_is_iface || !f->iface[0])
		return 0;
	if (dv_join(devices, sizeof(devices), root, "devices") != 0 ||
	    dv_join(node_dir, sizeof(node_dir), devices, f->iface) != 0)
		return -1;
	snprintf(f->node, sizeof(f->node), "%s", f->iface);
	f->node_is_iface = 1;
	dv_read_driver(node_dir, f->driver, sizeof(f->driver));
	dv_read_override(node_dir, f->override, sizeof(f->override),
			 &f->override_present);
	return 0;
}

/* 绑定前安全闸门：失败填 error_code/msg 并返回 -1（未做任何写） */
static int dv_safety_gate(const struct dv_facts *f, char *code, size_t codecap,
			  char *msg, size_t msgcap)
{
	int i;

	if (!f || !f->node_exists) {
		if (code)
			snprintf(code, codecap, "device_not_found");
		if (msg)
			snprintf(msg, msgcap, "USB 节点不存在");
		return -1;
	}
	if (f->is_root_hub) {
		if (code)
			snprintf(code, codecap, "hub_forbidden");
		if (msg)
			snprintf(msg, msgcap,
				 "拒绝：%s 是根 hub（usbN）。动它会影响整条总线上的所有设备",
				 f->dev);
		return -1;
	}
	if (f->is_hub || f->dev_class == 9) {
		if (code)
			snprintf(code, codecap, "hub_forbidden");
		if (msg)
			snprintf(msg, msgcap,
				 "拒绝：%s 是 hub（bDeviceClass=9 或接口 class=9），不是叶子设备",
				 f->node);
		return -1;
	}
	for (i = 0; i < f->n_iface_classes; i++) {
		if (f->iface_class[i] == 9) {
			if (code)
				snprintf(code, codecap, "hub_forbidden");
			if (msg)
				snprintf(msg, msgcap,
					 "拒绝：接口 %s class=9（hub 接口）",
					 f->iface_name[i]);
			return -1;
		}
	}
	if (f->bnum_ifaces > 1 || f->n_iface_dirs > 1) {
		if (code)
			snprintf(code, codecap, "multi_interface_forbidden");
		if (msg)
			snprintf(msg, msgcap,
				 "拒绝：%s 是多接口设备（bNumInterfaces=%d，接口节点 %d 个）；本版只允许单接口叶子设备",
				 f->node, f->bnum_ifaces, f->n_iface_dirs);
		return -1;
	}
	if (!f->iface[0] || f->n_iface_dirs == 0) {
		if (code)
			snprintf(code, codecap, "interface_not_found");
		if (msg)
			snprintf(msg, msgcap,
				 "拒绝：%s 找不到唯一接口节点（无法绑定）",
				 f->node);
		return -1;
	}
	return 0;
}

/* ======================================================================
 * 4) 渲染辅助 + dev_list / dev_identify
 * ====================================================================== */

static const char *dv_class_of(int cls)
{
	if (cls < 0)
		return "unknown";
	return dv_class_single(cls);
}

static void dv_render_iface_obj(struct dvb *b, const char *root,
				const char *ifname)
{
	char devices[DV_PATH_MAX], dir[DV_PATH_MAX];
	char drv[DV_MAX_DRIVER], ov[DV_MAX_OVERRIDE], mod[256];
	int cls = -1, present = 0;

	drv[0] = '\0';
	ov[0] = '\0';
	mod[0] = '\0';
	if (dv_join(devices, sizeof(devices), root, "devices") == 0 &&
	    dv_join(dir, sizeof(dir), devices, ifname) == 0) {
		if (dv_read_int_attr(dir, "bInterfaceClass", 16, &cls) != 0)
			cls = -1;
		dv_read_driver(dir, drv, sizeof(drv));
		dv_read_override(dir, ov, sizeof(ov), &present);
		if (dv_read_attr(dir, "modalias", mod, sizeof(mod)) != 0)
			mod[0] = '\0';
	}
	dvb_puts(b, "{");
	dvb_kv_str(b, "name", ifname);
	dvb_kv_int(b, "b_interface_class", cls);
	dvb_kv_str(b, "class_name", dv_class_of(cls));
	dvb_kv_str(b, "driver", drv[0] ? drv : NULL);
	dvb_kv_str(b, "driver_override", ov);
	dvb_kv_bool(b, "driver_override_present", present);
	dvb_kv_str(b, "modalias", mod[0] ? mod : NULL);
	dvb_obj_close(b);
}

static int dv_tool_list(const char *args, char **out)
{
	char root[DV_PATH_MAX], err[512];
	char *fmt = NULL, *buf = NULL, **nodes = NULL;
	int n_nodes = 0, i, n_dev = 0, n_if = 0, n_hub = 0, n_root_hub = 0;
	struct dvb b;
	const char *val;
	size_t vlen;
	int type;

	*out = NULL;
	if (ai_json_obj_get(args, strlen(args), "format", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		fmt = ai_json_strdup_str(val, vlen);
	if (dv_sysfs_root(root, sizeof(root), err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: %s", err) < 0)
			*out = NULL;
		free(fmt);
		return AI_ERR_NOT_FOUND;
	}
	{
		char devices[DV_PATH_MAX];

		if (dv_join(devices, sizeof(devices), root, "devices") != 0) {
			free(fmt);
			*out = strdup("ERROR: sysfs 路径过长");
			return AI_ERR_STORAGE;
		}
		dv_list_children(devices, NULL, &nodes, &n_nodes);
	}
	if (fmt && strcmp(fmt, "text") == 0) {
		buf = malloc(DV_OUT_LIMIT);
		if (!buf) {
			dv_free_children(nodes, n_nodes);
			free(fmt);
			*out = strdup("ERROR: 内存不足");
			return AI_ERR_MEMORY;
		}
		dvb_init(&b, buf, DV_OUT_LIMIT);
		for (i = 0; i < n_nodes; i++) {
			struct dv_facts f;
			char nerr[256];

			if (dv_collect(root, nodes[i], &f, nerr,
				       sizeof(nerr)) != 0)
				continue;
			if (f.node_is_iface)
				n_if++;
			else
				n_dev++;
			if (f.is_hub)
				n_hub++;
			if (f.is_root_hub)
				n_root_hub++;
		}
		dvb_printf(&b, "USB 节点 %d（设备 %d / 接口 %d；hub %d，根 hub %d）\n",
			   n_nodes, n_dev, n_if, n_hub, n_root_hub);
		for (i = 0; i < n_nodes; i++) {
			struct dv_facts f;
			char nerr[256];
			const char *hub;

			if (dv_collect(root, nodes[i], &f, nerr,
				       sizeof(nerr)) != 0)
				continue;
			hub = f.is_root_hub ? "hub=root" :
			      f.is_hub ? "hub=yes" : "hub=no";
			if (f.node_is_iface)
				dvb_printf(&b,
					   "%-12s [interface] class=%-2d driver=%-10s override=%s %s\n",
					   f.node,
					   f.n_iface_classes ?
					   f.iface_class[0] : -1,
					   f.driver[0] ? f.driver : "-",
					   f.override_present ?
					   (f.override[0] ? f.override :
					    "(空)") : "(无)", hub);
			else
				dvb_printf(&b,
					   "%-12s [device] %s:%s class=%-2d ifaces=%d driver=%-10s override=%s %s\n",
					   f.node,
					   f.id_vendor[0] ? f.id_vendor : "-",
					   f.id_product[0] ? f.id_product : "-",
					   f.dev_class, f.bnum_ifaces,
					   f.driver[0] ? f.driver : "-",
					   f.override_present ?
					   (f.override[0] ? f.override :
					    "(空)") : "(无)", hub);
		}
		*out = buf;
		dv_free_children(nodes, n_nodes);
		free(fmt);
		return AI_OK;
	}

	buf = malloc(DV_OUT_LIMIT);
	if (!buf) {
		dv_free_children(nodes, n_nodes);
		free(fmt);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	dvb_init(&b, buf, DV_OUT_LIMIT);
	dvb_puts(&b, "{\"schema\":\"aik-usb-list/1\",");
	dvb_kv_str(&b, "sysfs", root);
	dvb_kv_int(&b, "count", n_nodes);
	dvb_puts(&b, "\"nodes\":[");
	for (i = 0; i < n_nodes; i++) {
		struct dv_facts f;
		char nerr[256];

		if (dv_collect(root, nodes[i], &f, nerr, sizeof(nerr)) != 0)
			continue;
		if (i)
			dvb_putc(&b, ',');
		if (f.node_is_iface)
			n_if++;
		else
			n_dev++;
		if (f.is_hub)
			n_hub++;
		if (f.is_root_hub)
			n_root_hub++;

		dvb_puts(&b, "{");
		dvb_kv_str(&b, "name", f.node);
		dvb_kv_str(&b, "kind", f.node_is_iface ? "interface" : "device");
		dvb_kv_bool(&b, "is_hub", f.is_hub);
		dvb_kv_bool(&b, "is_root_hub", f.is_root_hub);
		if (f.node_is_iface) {
			dvb_kv_str(&b, "parent", f.dev);
			dvb_kv_int(&b, "b_interface_class",
				   f.n_iface_classes ? f.iface_class[0] : -1);
			dvb_kv_str(&b, "class_name",
				   f.n_iface_classes ?
				   dv_class_of(f.iface_class[0]) : "unknown");
			dvb_kv_str(&b, "modalias",
				   f.modalias[0] ? f.modalias : NULL);
		} else {
			dvb_kv_str(&b, "id_vendor",
				   f.id_vendor[0] ? f.id_vendor : NULL);
			dvb_kv_str(&b, "id_product",
				   f.id_product[0] ? f.id_product : NULL);
			{
				char ids[32];

				snprintf(ids, sizeof(ids), "%s:%s",
					 f.id_vendor[0] ? f.id_vendor : "?",
					 f.id_product[0] ? f.id_product : "?");
				dvb_kv_str(&b, "ids", ids);
			}
			dvb_kv_int(&b, "b_device_class", f.dev_class);
			dvb_kv_int(&b, "b_num_interfaces", f.bnum_ifaces);
			dvb_kv_str(&b, "modalias",
				   f.modalias[0] ? f.modalias : NULL);
			dvb_kv_str(&b, "product",
				   f.product[0] ? f.product : NULL);
		}
		dvb_kv_str(&b, "driver", f.driver[0] ? f.driver : NULL);
		dvb_kv_str(&b, "driver_override", f.override);
		dvb_kv_bool(&b, "driver_override_present", f.override_present);
		dvb_kv_bool(&b, "bindable", f.bindable);
		if (!f.node_is_iface) {
			int j;

			dvb_puts(&b, "\"interfaces\":[");
			for (j = 0; j < f.n_iface_dirs; j++) {
				if (j)
					dvb_putc(&b, ',');
				dv_render_iface_obj(&b, root, f.iface_name[j]);
			}
			dvb_arr_close(&b); dvb_putc(&b, ',');
		}
		dvb_obj_close(&b);
	}
	dvb_arr_close(&b); dvb_putc(&b, ',');
	dvb_kv_int(&b, "devices", n_dev);
	dvb_kv_int(&b, "interfaces", n_if);
	dvb_kv_int(&b, "hubs", n_hub);
	dvb_kv_int(&b, "root_hubs", n_root_hub);
	dvb_kv_bool(&b, "truncated", b.trunc);
	dvb_puts(&b, "\"schema_ok\":true}");
	*out = buf;
	dv_free_children(nodes, n_nodes);
	free(fmt);
	return AI_OK;
}

static int dv_tool_identify(const char *args, char **out)
{
	char *dev = NULL, *fmt = NULL, root[DV_PATH_MAX], err[512];
	struct dv_facts f;
	const char *cls, *vname, *pname;
	char human[512];
	char *buf;
	struct dvb b;
	int i, first;
	const char *val;
	size_t vlen;
	int type;

	*out = NULL;
	if (ai_json_obj_get(args, strlen(args), "device", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		dev = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "format", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		fmt = ai_json_strdup_str(val, vlen);
	if (!dev || !dev[0]) {
		free(dev);
		free(fmt);
		*out = strdup("ERROR: 缺少 device（如 1-1 或 1-1:1.0）");
		return AI_ERR_INVALID_ARG;
	}
	if (dv_sysfs_root(root, sizeof(root), err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: %s", err) < 0)
			*out = NULL;
		free(dev);
		free(fmt);
		return AI_ERR_NOT_FOUND;
	}
	if (dv_collect(root, dev, &f, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: %s", err) < 0)
			*out = NULL;
		free(dev);
		free(fmt);
		return AI_ERR_NOT_FOUND;
	}

	cls = dv_classify_classes(f.dev_class, f.iface_class,
				  f.n_iface_classes);
	vname = dv_vendor_name(f.id_vendor);
	pname = dv_product_name(f.id_vendor, f.id_product);
	if (f.product[0]) {
		if (f.manufacturer[0])
			snprintf(human, sizeof(human), "%s（%s）", f.product,
				 f.manufacturer);
		else if (vname)
			snprintf(human, sizeof(human), "%s（%s）", f.product,
				 vname);
		else
			snprintf(human, sizeof(human), "%s", f.product);
	} else if (pname) {
		if (vname)
			snprintf(human, sizeof(human), "%s（%s）", pname, vname);
		else
			snprintf(human, sizeof(human), "%s", pname);
	} else if (f.id_vendor[0] && f.id_product[0]) {
		snprintf(human, sizeof(human),
			 "未识别（ids 表无 %s:%s，sysfs 也无 product 字符串）",
			 f.id_vendor, f.id_product);
	} else {
		snprintf(human, sizeof(human),
			 "未识别（无 idVendor/idProduct，sysfs 无 product 字符串）");
	}

	buf = malloc(DV_OUT_LIMIT);
	if (!buf) {
		free(dev);
		free(fmt);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	dvb_init(&b, buf, DV_OUT_LIMIT);

	if (fmt && strcmp(fmt, "text") == 0) {
		dvb_printf(&b, "%s: %s（%s）\n", f.node, cls, dv_class_cn(cls));
		dvb_printf(&b, "  ids: %s:%s（厂商: %s / 型号: %s）\n",
			   f.id_vendor[0] ? f.id_vendor : "?",
			   f.id_product[0] ? f.id_product : "?",
			   vname ? vname : "ids 表未收录",
			   pname ? pname : "ids 表未收录");
		dvb_printf(&b, "  名称: %s\n", human);
		for (i = 0; i < f.n_iface_dirs; i++)
			dvb_printf(&b, "  接口: %s class=%d\n", f.iface_name[i],
				   f.iface_class[i]);
		dvb_printf(&b, "  可绑定: %s\n",
			   f.bindable ? "yes（非 hub 且单接口）" :
			   f.is_hub ? "no（hub，禁止绑定）" :
			   "no（多接口或找不到唯一接口）");
		*out = buf;
		free(dev);
		free(fmt);
		return AI_OK;
	}

	dvb_puts(&b, "{\"schema\":\"aik-usb-identify/1\",");
	dvb_kv_str(&b, "device", f.node);
	dvb_kv_bool(&b, "found", 1);
	dvb_kv_str(&b, "kind", f.node_is_iface ? "interface" : "device");
	{
		char ids[32];

		snprintf(ids, sizeof(ids), "%s:%s",
			 f.id_vendor[0] ? f.id_vendor : "?",
			 f.id_product[0] ? f.id_product : "?");
		dvb_kv_str(&b, "ids", ids);
	}
	dvb_kv_str(&b, "id_vendor", f.id_vendor[0] ? f.id_vendor : NULL);
	dvb_kv_str(&b, "id_product", f.id_product[0] ? f.id_product : NULL);
	dvb_kv_str(&b, "vendor_name", vname);
	dvb_kv_str(&b, "product_name", pname);
	dvb_kv_str(&b, "sysfs_product", f.product[0] ? f.product : NULL);
	dvb_kv_str(&b, "sysfs_manufacturer",
		   f.manufacturer[0] ? f.manufacturer : NULL);
	dvb_kv_str(&b, "class", cls);
	dvb_kv_str(&b, "class_cn", dv_class_cn(cls));
	dvb_kv_str(&b, "human_name", human);
	dvb_kv_str(&b, "confidence",
		   (f.product[0] || pname) ?
		   (strcmp(cls, "other") == 0 ? "class-partial" : "exact") :
		   (vname ? "vendor-only" :
		    (strcmp(cls, "other") == 0 ? "unknown" : "class-only")));
	dvb_puts(&b, "\"class_evidence\":[");
	first = 1;
	if (f.dev_class >= 0) {
		dvb_printf(&b, "\"bDeviceClass=%02x\"", f.dev_class);
		first = 0;
	}
	for (i = 0; i < f.n_iface_dirs; i++) {
		dvb_printf(&b, "%s\"%s bInterfaceClass=%02x\"",
			   first ? "" : ",", f.iface_name[i],
			   f.iface_class[i]);
		first = 0;
	}
	if (first)
		dvb_puts(&b, "\"无 class 属性可读\"");
	dvb_arr_close(&b); dvb_putc(&b, ',');
	dvb_puts(&b, "\"interfaces\":[");
	for (i = 0; i < f.n_iface_dirs; i++) {
		if (i)
			dvb_putc(&b, ',');
		dv_render_iface_obj(&b, root, f.iface_name[i]);
	}
	dvb_arr_close(&b); dvb_putc(&b, ',');
	dvb_kv_bool(&b, "bindable", f.bindable);
	dvb_kv_str(&b, "bindable_reason",
		   f.bindable ? "非 hub 且只有单接口" :
		   f.is_hub ? "hub（根 hub / class=9），禁止绑定" :
		   "多接口或找不到唯一接口节点，禁止绑定");
	dvb_puts(&b, "\"warnings\":[");
	first = 1;
	if (f.is_hub) {
		dvb_puts(&b,
			 "\"hub 设备：任何绑定操作都会被拒绝（避免连带掉下游设备）\"");
		first = 0;
	}
	if (!f.override_present) {
		dvb_printf(&b,
			   "%s\"本内核 %s 无 driver_override 属性：override 模式不可用（会 fail-closed 拒绝）\"",
			   first ? "" : ",", f.node);
		first = 0;
	}
	if (!f.iface_class_ok) {
		dvb_printf(&b, "%s\"部分接口 bInterfaceClass 读不到（如实标注）\"",
			   first ? "" : ",");
		first = 0;
	}
	(void)first;
	dvb_arr_close(&b); dvb_putc(&b, ',');
	dvb_kv_bool(&b, "truncated", b.trunc);
	dvb_puts(&b, "\"schema_ok\":true}");
	*out = buf;
	free(dev);
	free(fmt);
	return AI_OK;
}

/* ======================================================================
 * 5) 快照 + dev_bind / dev_restore
 * ====================================================================== */

struct dv_snap {
	char schema[32];
	char device[DV_NAME_MAX];
	char iface[DV_NAME_MAX];
	char sysfs[DV_PATH_MAX];
	char driver[DV_MAX_DRIVER];
	int bound;
	char override[DV_MAX_OVERRIDE];
	int override_present;
	char new_id[DV_MAX_NEWID];
	char new_id_driver[DV_MAX_DRIVER];
	char taken_at[32];
	char path[DV_PATH_MAX];
};

struct dv_wr {
	char path[DV_PATH_MAX];
	char value[DV_MAX_OVERRIDE];
	int rc;
	int err;
};

struct dv_ctx {
	const char *root;
	const struct dv_facts *f;
	struct dv_snap snap;
	struct dv_wr writes[DV_MAX_WRITES];
	int nwrites;
	int snapshot_ready;
};

static void dv_now(char *out, size_t cap)
{
	struct tm tm;
	time_t now = time(NULL);

	gmtime_r(&now, &tm);
	strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static int dv_snap_path(const char *state, const char *device, char *out,
			size_t cap)
{
	out[0] = '\0';
	if (!dv_node_name_valid(device))
		return -1;
	if (dv_append(out, cap, state) || dv_append(out, cap, "/snapshots/") ||
	    dv_append(out, cap, device) || dv_append(out, cap, ".json"))
		return -1;
	return 0;
}

/* 快照序列化（单源：标准快照与任务快照共用同一份文本） */
static int dv_snap_render(const struct dv_snap *s, char *buf, size_t cap)
{
	struct dvb b;

	if (!s || !buf || cap == 0)
		return -1;
	dvb_init(&b, buf, cap);
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "schema", "aik-usb-snapshot/1");
	dvb_kv_str(&b, "device", s->device);
	dvb_kv_str(&b, "iface", s->iface);
	dvb_kv_str(&b, "sysfs", s->sysfs);
	dvb_kv_str(&b, "driver", s->driver);
	dvb_kv_bool(&b, "bound", s->bound);
	dvb_kv_str(&b, "driver_override", s->override);
	dvb_kv_bool(&b, "driver_override_present", s->override_present);
	dvb_kv_str(&b, "new_id", s->new_id);
	dvb_kv_str(&b, "new_id_driver", s->new_id_driver);
	dvb_kv_str(&b, "taken_at", s->taken_at);
	dvb_puts(&b, "\"schema_ok\":true}");
	if (b.trunc)
		return -1;
	return 0;
}

static int dv_snap_save(const char *state, struct dv_snap *s, char *err,
			size_t errcap)
{
	char buf[4096];

	if (!s || !s->device[0]) {
		if (err)
			snprintf(err, errcap, "快照缺少 device");
		return -1;
	}
	if (dv_snap_path(state, s->device, s->path, sizeof(s->path)) != 0) {
		if (err)
			snprintf(err, errcap, "快照路径非法（device 名不合法）");
		return -1;
	}
	snprintf(s->schema, sizeof(s->schema), "aik-usb-snapshot/1");
	if (!s->taken_at[0])
		dv_now(s->taken_at, sizeof(s->taken_at));
	if (dv_snap_render(s, buf, sizeof(buf)) != 0) {
		if (err)
			snprintf(err, errcap, "快照序列化超长");
		return -1;
	}
	return dv_write_file_atomic(s->path, buf, err, errcap);
}

static int dv_json_get_str(const char *json, size_t len, const char *key,
			   char *out, size_t cap)
{
	const char *val;
	size_t vlen;
	int type;

	if (out && cap)
		out[0] = '\0';
	if (!json || ai_json_obj_get(json, len, key, &val, &vlen, &type) != 1 ||
	    type != AI_JSON_STR)
		return -1;
	{
		char *str = ai_json_strdup_str(val, vlen);

		if (!str)
			return -1;
		if (out && cap)
			snprintf(out, cap, "%s", str);
		free(str);
	}
	return 0;
}

static int dv_json_get_bool(const char *json, size_t len, const char *key,
			    int def)
{
	const char *val;
	size_t vlen;
	int type;

	if (!json || ai_json_obj_get(json, len, key, &val, &vlen, &type) != 1 ||
	    type != AI_JSON_BOOL)
		return def;
	return (vlen > 0 && val[0] == 't') ? 1 : 0;
}

static int dv_snap_parse(const char *content, size_t n, struct dv_snap *s,
			 const char *path, char *err, size_t errcap)
{
	memset(s, 0, sizeof(*s));
	if (dv_json_get_str(content, n, "schema", s->schema,
			    sizeof(s->schema)) != 0 ||
	    strcmp(s->schema, "aik-usb-snapshot/1") != 0) {
		if (err)
			snprintf(err, errcap, "快照 schema 不匹配: %s",
				 path ? path : "(内存)");
		return -1;
	}
	if (dv_json_get_str(content, n, "device", s->device,
			    sizeof(s->device)) != 0 ||
	    dv_json_get_str(content, n, "iface", s->iface,
			    sizeof(s->iface)) != 0 ||
	    dv_json_get_str(content, n, "sysfs", s->sysfs,
			    sizeof(s->sysfs)) != 0 ||
	    dv_json_get_str(content, n, "driver", s->driver,
			    sizeof(s->driver)) != 0 ||
	    dv_json_get_str(content, n, "driver_override", s->override,
			    sizeof(s->override)) != 0 ||
	    dv_json_get_str(content, n, "new_id", s->new_id,
			    sizeof(s->new_id)) != 0 ||
	    dv_json_get_str(content, n, "new_id_driver", s->new_id_driver,
			    sizeof(s->new_id_driver)) != 0 ||
	    dv_json_get_str(content, n, "taken_at", s->taken_at,
			    sizeof(s->taken_at)) != 0) {
		if (err)
			snprintf(err, errcap, "快照字段缺失/损坏: %s",
				 path ? path : "(内存)");
		return -1;
	}
	s->bound = dv_json_get_bool(content, n, "bound", 0);
	s->override_present = dv_json_get_bool(content, n,
					       "driver_override_present", 0);
	if (path)
		snprintf(s->path, sizeof(s->path), "%s", path);
	return 0;
}

static int dv_snap_load_path(const char *path, struct dv_snap *s, char *err,
			     size_t errcap)
{
	char content[DV_SNAP_FILE_MAX];
	ssize_t n;
	int fd;

	if (!path || !path[0] || !s) {
		if (err)
			snprintf(err, errcap, "快照路径为空");
		return -1;
	}
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (err)
			snprintf(err, errcap, "快照不可读（%s）", path);
		return -1;
	}
	n = read(fd, content, sizeof(content) - 1);
	close(fd);
	if (n <= 0) {
		if (err)
			snprintf(err, errcap, "快照文件为空或读取失败: %s", path);
		return -1;
	}
	content[n] = '\0';
	return dv_snap_parse(content, (size_t)n, s, path, err, errcap);
}

static int dv_snap_load(const char *state, const char *device,
			struct dv_snap *s, char *err, size_t errcap)
{
	char path[DV_PATH_MAX];

	if (dv_snap_path(state, device, path, sizeof(path)) != 0) {
		if (err)
			snprintf(err, errcap, "快照路径非法");
		return -1;
	}
	return dv_snap_load_path(path, s, err, errcap);
}

static void dv_ctx_record(struct dv_ctx *ctx, const char *path,
			  const char *value, int rc, int err)
{
	struct dv_wr *w;

	if (ctx->nwrites >= DV_MAX_WRITES)
		return;
	w = &ctx->writes[ctx->nwrites++];
	snprintf(w->path, sizeof(w->path), "%s", path);
	snprintf(w->value, sizeof(w->value), "%s", value ? value : "");
	w->rc = rc;
	w->err = err;
}

/* 所有 /sys 写都走这里：必须先有快照，写后记账 + 审计 */
static int dv_ctx_write(struct dv_ctx *ctx, const char *path,
			const char *value)
{
	int err = 0, rc;

	if (!ctx->snapshot_ready) {
		dv_audit("op=refuse_write path=%s reason=no_snapshot", path);
		return -1;
	}
	rc = dv_write_raw(path, value, &err);
	dv_ctx_record(ctx, path, value, rc, err);
	dv_audit("op=write path=%s value=%s rc=%d errno=%d(%s)", path, value,
		 rc, err, rc ? strerror(err ? err : EIO) : "ok");
	return rc;
}

static int dv_driver_path(char *out, size_t cap, const char *root,
			  const char *driver, const char *attr)
{
	out[0] = '\0';
	if (dv_append(out, cap, root) || dv_append(out, cap, "/drivers/") ||
	    dv_append(out, cap, driver) || dv_append(out, cap, "/") ||
	    dv_append(out, cap, attr))
		return -1;
	return 0;
}

static int dv_ctx_unbind(struct dv_ctx *ctx, const char *driver)
{
	char path[DV_PATH_MAX];

	if (!driver || !driver[0])
		return 0;
	if (dv_driver_path(path, sizeof(path), ctx->root, driver, "unbind") != 0)
		return -1;
	if (!dv_file_exists(path)) {
		dv_audit("op=skip_unbind driver=%s reason=no_unbind_attr",
			 driver);
		return -1;
	}
	return dv_ctx_write(ctx, path, ctx->f->node);
}

static int dv_ctx_bind(struct dv_ctx *ctx, const char *driver)
{
	char path[DV_PATH_MAX];

	if (dv_driver_path(path, sizeof(path), ctx->root, driver, "bind") != 0)
		return -1;
	if (!dv_file_exists(path)) {
		dv_audit("op=skip_bind driver=%s reason=no_bind_attr", driver);
		return -1;
	}
	return dv_ctx_write(ctx, path, ctx->f->node);
}

static int dv_ctx_remove_newid(struct dv_ctx *ctx)
{
	char path[DV_PATH_MAX];

	if (!ctx->snap.new_id[0] || !ctx->snap.new_id_driver[0])
		return 0;
	if (dv_driver_path(path, sizeof(path), ctx->root,
			   ctx->snap.new_id_driver, "remove_id") != 0)
		return -1;
	if (!dv_file_exists(path))
		return -1;
	return dv_ctx_write(ctx, path, ctx->snap.new_id);
}

static int dv_apply_bind(struct dv_ctx *ctx, const char *mode,
			 const char *driver, int do_bind, char *code,
			 size_t codecap, char *msg, size_t msgcap)
{
	char devices[DV_PATH_MAX], node_dir[DV_PATH_MAX], path[DV_PATH_MAX];
	char drvnow[DV_MAX_DRIVER];

	if (dv_join(devices, sizeof(devices), ctx->root, "devices") != 0 ||
	    dv_join(node_dir, sizeof(node_dir), devices, ctx->f->node) != 0) {
		snprintf(code, codecap, "path_error");
		snprintf(msg, msgcap, "sysfs 路径过长");
		return -1;
	}

	if (strcmp(mode, "override") == 0) {
		if (dv_join(path, sizeof(path), node_dir,
			    "driver_override") != 0) {
			snprintf(code, codecap, "path_error");
			return -1;
		}
		if (dv_ctx_write(ctx, path, driver) != 0) {
			snprintf(code, codecap, "override_write_failed");
			snprintf(msg, msgcap, "写 driver_override 失败");
			return -1;
		}
		if (ctx->f->driver[0] &&
		    dv_ctx_unbind(ctx, ctx->f->driver) != 0) {
			snprintf(code, codecap, "unbind_failed");
			snprintf(msg, msgcap, "从原驱动 %s 撤销失败",
				 ctx->f->driver);
			return -1;
		}
		if (dv_ctx_bind(ctx, driver) != 0) {
			snprintf(code, codecap, "bind_failed");
			snprintf(msg, msgcap,
				 "写 %s/bind 失败（目标驱动拒绝绑定或 probe 失败）",
				 driver);
			return -1;
		}
	} else if (strcmp(mode, "new_id") == 0) {
		if (ctx->f->driver[0] &&
		    dv_ctx_unbind(ctx, ctx->f->driver) != 0) {
			snprintf(code, codecap, "unbind_failed");
			snprintf(msg, msgcap, "从原驱动 %s 撤销失败",
				 ctx->f->driver);
			return -1;
		}
		if (dv_driver_path(path, sizeof(path), ctx->root, driver,
				   "new_id") != 0) {
			snprintf(code, codecap, "path_error");
			return -1;
		}
		if (dv_ctx_write(ctx, path, ctx->snap.new_id) != 0) {
			snprintf(code, codecap, "new_id_write_failed");
			snprintf(msg, msgcap, "写 %s/new_id 失败（格式被拒）",
				 driver);
			return -1;
		}
		dv_read_driver(node_dir, drvnow, sizeof(drvnow));
		if (strcmp(drvnow, driver) != 0 && do_bind) {
			if (dv_ctx_bind(ctx, driver) != 0) {
				snprintf(code, codecap, "probe_failed");
				snprintf(msg, msgcap,
					 "目标驱动 %s 接受匹配后 probe 失败（bind 出错，设备保持未绑定）",
					 driver);
				return -1;
			}
		}
	} else {	/* bind */
		if (ctx->f->driver[0] &&
		    dv_ctx_unbind(ctx, ctx->f->driver) != 0) {
			snprintf(code, codecap, "unbind_failed");
			snprintf(msg, msgcap, "从原驱动 %s 撤销失败",
				 ctx->f->driver);
			return -1;
		}
		if (dv_ctx_bind(ctx, driver) != 0) {
			snprintf(code, codecap, "bind_failed");
			snprintf(msg, msgcap,
				 "写 %s/bind 失败（modalias 不匹配或 probe 失败）",
				 driver);
			return -1;
		}
	}

	dv_read_driver(node_dir, drvnow, sizeof(drvnow));
	if (strcmp(drvnow, driver) != 0) {
		snprintf(code, codecap, "probe_failed");
		snprintf(msg, msgcap,
			 "绑定后读回 driver=%s，不是目标 %s（目标驱动 probe 失败）",
			 drvnow[0] ? drvnow : "(空)", driver);
		return -1;
	}
	return 0;
}

/* 回滚到快照：撤错驱动 → 撤 new_id → 还原 override → 绑回原驱动 → 读回 */
static int dv_rollback(struct dv_ctx *ctx, char *msg, size_t msgcap)
{
	char devices[DV_PATH_MAX], node_dir[DV_PATH_MAX], path[DV_PATH_MAX];
	char drv[DV_MAX_DRIVER], ov[DV_MAX_OVERRIDE];
	int ov_present = 0, ok = 1;

	if (dv_join(devices, sizeof(devices), ctx->root, "devices") != 0 ||
	    dv_join(node_dir, sizeof(node_dir), devices, ctx->f->node) != 0) {
		snprintf(msg, msgcap, "回滚失败：sysfs 路径过长");
		return -1;
	}
	dv_audit("op=rollback_begin device=%s iface=%s orig_driver=%s",
		 ctx->snap.device, ctx->snap.iface, ctx->snap.driver);

	dv_read_driver(node_dir, drv, sizeof(drv));
	if (drv[0] && strcmp(drv, ctx->snap.driver) != 0) {
		if (dv_ctx_unbind(ctx, drv) != 0)
			ok = 0;
	}
	(void)dv_ctx_remove_newid(ctx);

	if (ctx->snap.override_present) {
		if (dv_join(path, sizeof(path), node_dir,
			    "driver_override") != 0 ||
		    dv_ctx_write(ctx, path, ctx->snap.override) != 0)
			ok = 0;
	}

	dv_read_driver(node_dir, drv, sizeof(drv));
	if (ctx->snap.driver[0]) {
		if (strcmp(drv, ctx->snap.driver) != 0 &&
		    dv_ctx_bind(ctx, ctx->snap.driver) != 0)
			ok = 0;
	} else if (drv[0]) {
		if (dv_ctx_unbind(ctx, drv) != 0)
			ok = 0;
	}

	dv_readback(ctx->root, node_dir, drv, sizeof(drv), ov, sizeof(ov),
		    &ov_present);
	if (strcmp(drv, ctx->snap.driver) != 0) {
		snprintf(msg, msgcap, "回滚读回 driver=%s，期望 %s",
			 drv[0] ? drv : "(空)",
			 ctx->snap.driver[0] ? ctx->snap.driver : "(空)");
		ok = 0;
	} else if (ctx->snap.override_present &&
		   (!ov_present || strcmp(ov, ctx->snap.override) != 0)) {
		snprintf(msg, msgcap,
			 "回滚读回 driver_override=%s，期望 %s",
			 ov_present ? ov : "(属性缺失)", ctx->snap.override);
		ok = 0;
	} else if (!ctx->snap.override_present && ov_present && ov[0]) {
		snprintf(msg, msgcap,
			 "回滚后 driver_override 仍为 %s，原状态为属性不存在",
			 ov);
		ok = 0;
	} else {
		snprintf(msg, msgcap, "已恢复到 %s",
			 ctx->snap.driver[0] ? ctx->snap.driver : "(未绑定)");
	}
	dv_audit("op=rollback_end ok=%d driver=%s override_present=%d override=%s",
		 ok, drv[0] ? drv : "(空)", ov_present, ov);
	return ok ? 0 : -1;
}

/* HID 功能性检查：/proc/bus/input/devices 里有没有挂在目标设备下的输入节点 */
static int dv_input_probe(const char *root, const char *node_dir, int wait_ms,
			  char *names, size_t namescap, int *count)
{
	char real[PATH_MAX], rel[PATH_MAX], content[256 * 1024];
	int found = 0, tries = 0, prefix_len;
	ssize_t n;

	if (count)
		*count = 0;
	if (names && namescap)
		names[0] = '\0';
	if (!dv_root_is_real_sysfs(root) || !realpath(node_dir, real))
		return 0;
	snprintf(rel, sizeof(rel), "%s",
		 strncmp(real, "/sys", 4) == 0 ? real + 4 : real);
	prefix_len = (int)strlen(rel);

	for (;;) {
		char *p;
		char block_name[256] = "";

		found = 0;
		if (names && namescap)
			names[0] = '\0';
		{
			int fd = open("/proc/bus/input/devices",
				      O_RDONLY | O_CLOEXEC);

			if (fd < 0)
				return 0;
			n = read(fd, content, sizeof(content) - 1);
			close(fd);
			if (n <= 0)
				return 0;
			content[n] = '\0';
		}
		for (p = content; *p; ) {
			char *eol = strchr(p, '\n');
			size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
			char line[512];

			if (linelen >= sizeof(line))
				linelen = sizeof(line) - 1;
			memcpy(line, p, linelen);
			line[linelen] = '\0';
			if (strncmp(line, "N: Name=", 8) == 0) {
				size_t l;

				snprintf(block_name, sizeof(block_name), "%s",
					 line + 8);
				l = strlen(block_name);
				while (l > 0 && (block_name[l - 1] == '"' ||
						 block_name[l - 1] == ' '))
					block_name[--l] = '\0';
				if (block_name[0] == '"')
					memmove(block_name, block_name + 1,
						strlen(block_name));
			} else if (strncmp(line, "S: Sysfs=", 9) == 0) {
				const char *sp = line + 9;

				if (strncmp(sp, rel, (size_t)prefix_len) == 0 &&
				    (sp[prefix_len] == '/' ||
				     sp[prefix_len] == '\0')) {
					if (names && namescap) {
						struct dvb nb;
						size_t used = strlen(names);

						if (used && used + 2 < namescap)
							names[used++] = ',';
						if (used + 1 < namescap) {
							names[used] = '\0';
							dvb_init(&nb, names + used,
								 namescap - used);
							dvb_json_str(&nb,
								     block_name);
						}
					}
					found++;
				}
			}
			if (!eol)
				break;
			p = eol + 1;
		}
		if (found > 0 || wait_ms <= 0 || tries * 100 >= wait_ms)
			break;
		{
			struct timespec ts;

			ts.tv_sec = 0;
			ts.tv_nsec = 100 * 1000 * 1000;
			nanosleep(&ts, NULL);
		}
		tries++;
	}
	if (count)
		*count = found;
	return found;
}

static void dv_readback(const char *root, const char *node_dir, char *drv,
			size_t drvcap, char *ov, size_t ovcap, int *ov_present)
{
	(void)root;
	dv_read_driver(node_dir, drv, drvcap);
	dv_read_override(node_dir, ov, ovcap, ov_present);
}

static int dv_node_exists(const char *root, const char *node)
{
	char devices[DV_PATH_MAX], dir[DV_PATH_MAX];

	if (dv_join(devices, sizeof(devices), root, "devices") != 0 ||
	    dv_join(dir, sizeof(dir), devices, node) != 0)
		return 0;
	return dv_dir_exists(dir);
}

static void dv_emit_writes(struct dvb *b, const struct dv_ctx *ctx)
{
	int i;

	dvb_puts(b, "\"writes\":[");
	for (i = 0; i < ctx->nwrites; i++) {
		if (i)
			dvb_putc(b, ',');
		dvb_puts(b, "{");
		dvb_kv_str(b, "path", ctx->writes[i].path);
		dvb_kv_str(b, "value", ctx->writes[i].value);
		dvb_kv_int(b, "rc", ctx->writes[i].rc);
		dvb_kv_int(b, "errno", ctx->writes[i].err);
		dvb_kv_str(b, "error",
			   ctx->writes[i].rc ?
			   strerror(ctx->writes[i].err ? ctx->writes[i].err :
				    EIO) : NULL);
		dvb_obj_close(b);
	}
	dvb_arr_close(b); dvb_putc(b, ',');
}

static void dv_emit_readback(struct dvb *b, const char *root,
			     const char *device, const char *node, int wait_ms)
{
	char devices[DV_PATH_MAX], node_dir[DV_PATH_MAX];
	char drv[DV_MAX_DRIVER], ov[DV_MAX_OVERRIDE], names[2048];
	int ov_present = 0, count = 0;

	drv[0] = '\0';
	ov[0] = '\0';
	names[0] = '\0';
	if (dv_join(devices, sizeof(devices), root, "devices") == 0 &&
	    dv_join(node_dir, sizeof(node_dir), devices, node) == 0) {
		dv_readback(root, node_dir, drv, sizeof(drv), ov, sizeof(ov),
			    &ov_present);
		dv_input_probe(root, node_dir, wait_ms, names, sizeof(names),
			       &count);
	}
	dvb_puts(b, "{");
	dvb_kv_str(b, "driver", drv[0] ? drv : NULL);
	dvb_kv_str(b, "driver_override", ov_present ? ov : NULL);
	dvb_kv_bool(b, "driver_override_present", ov_present);
	dvb_kv_bool(b, "bound", drv[0] != '\0');
	dvb_kv_bool(b, "device_node_exists", dv_node_exists(root, device));
	dvb_kv_bool(b, "iface_node_exists", dv_node_exists(root, node));
	dvb_puts(b, "\"input_devices\":[");
	dvb_puts(b, names);
	dvb_arr_close(b); dvb_putc(b, ',');
	dvb_kv_int(b, "input_device_count", count);
	dvb_kv_bool(b, "input_ok", count > 0);
	dvb_obj_close(b);
}

static int dv_error_json(char **out, const char *schema, const char *code,
			 const char *fmt, ...)
{
	char *buf = malloc(4096);
	struct dvb b;
	va_list ap;
	char msg[1024];

	if (!buf) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	dvb_init(&b, buf, 4096);
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "schema", schema);
	dvb_kv_bool(&b, "ok", 0);
	dvb_kv_bool(&b, "changed", 0);
	dvb_kv_str(&b, "error_code", code);
	dvb_kv_str(&b, "error", msg);
	dvb_kv_bool(&b, "truncated", b.trunc);
	dvb_puts(&b, "\"schema_ok\":true}");
	*out = buf;
	return AI_ERR_INVALID_ARG;
}

static int dv_emit_bind_result(char **out, const char *schema, int ok,
			       int changed, const char *action, const char *mode,
			       const char *device, const struct dv_facts *f,
			       const struct dv_ctx *ctx,
			       const char *target_driver, const char *code,
			       const char *msg, int rollback_attempted,
			       int rollback_ok, const char *rollback_msg,
			       int dry_run, int wait_ms)
{
	char *buf = malloc(DV_OUT_LIMIT);
	struct dvb b;

	if (!buf) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	dvb_init(&b, buf, DV_OUT_LIMIT);
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "schema", schema);
	dvb_kv_bool(&b, "ok", ok);
	dvb_kv_bool(&b, "changed", changed);
	dvb_kv_bool(&b, "dry_run", dry_run);
	dvb_kv_str(&b, "action", action);
	dvb_kv_str(&b, "mode", mode);
	dvb_kv_str(&b, "device", device);
	dvb_kv_str(&b, "iface", f->iface[0] ? f->iface : NULL);
	dvb_kv_str(&b, "sysfs", ctx->root);
	dvb_kv_str(&b, "target_driver", target_driver);
	dvb_kv_str(&b, "driver_before", f->driver[0] ? f->driver : NULL);
	dvb_kv_bool(&b, "bindable_before", f->bindable);
	dvb_puts(&b, "\"snapshot\":{");
	dvb_kv_bool(&b, "saved", ctx->snapshot_ready);
	dvb_kv_str(&b, "path", ctx->snapshot_ready ? ctx->snap.path : NULL);
	dvb_kv_str(&b, "taken_at",
		   ctx->snap.taken_at[0] ? ctx->snap.taken_at : NULL);
	dvb_kv_str(&b, "driver", ctx->snap.driver);
	dvb_kv_str(&b, "driver_override", ctx->snap.override);
	dvb_kv_bool(&b, "driver_override_present",
		    ctx->snap.override_present);
	dvb_kv_str(&b, "new_id", ctx->snap.new_id);
	dvb_obj_close(&b); dvb_putc(&b, ',');
	dv_emit_writes(&b, ctx);
	dvb_puts(&b, "\"readback\":");
	dv_emit_readback(&b, ctx->root, device, f->node, wait_ms);
	dvb_putc(&b, ',');
	dvb_puts(&b, "\"rollback\":{");
	dvb_kv_bool(&b, "attempted", rollback_attempted);
	dvb_kv_bool(&b, "ok", rollback_attempted ? rollback_ok : 0);
	dvb_kv_str(&b, "message", rollback_msg);
	dvb_obj_close(&b); dvb_putc(&b, ',');
	dvb_kv_str(&b, "error_code", code && code[0] ? code : NULL);
	dvb_kv_str(&b, "error", msg && msg[0] ? msg : NULL);
	dvb_kv_bool(&b, "truncated", b.trunc);
	dvb_puts(&b, "\"schema_ok\":true}");
	*out = buf;
	return ok ? AI_OK : AI_ERR_GENERIC;
}

static int dv_tool_bind(const char *args, char **out)
{
	char root[DV_PATH_MAX], err[512];
	char rmsg[512] = "", state[DV_PATH_MAX];
	char *dev = NULL, *drv = NULL, *mode = NULL, *action = NULL;
	char *snapshot_arg = NULL;
	struct dv_facts f;
	struct dv_ctx ctx;
	int do_bind = 1, dry = 0, wait_ms = 0;
	int rc, ok = 0, changed = 0, rollback_attempted = 0, rollback_ok = 0;
	const char *val;
	size_t vlen;
	int type;

	*out = NULL;
	memset(&ctx, 0, sizeof(ctx));
	memset(&f, 0, sizeof(f));
	if (ai_json_obj_get(args, strlen(args), "device", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		dev = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "driver", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		drv = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "mode", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		mode = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "action", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		action = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "snapshot", &val, &vlen,
			    &type) == 1 && type == AI_JSON_STR)
		snapshot_arg = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "bind", &val, &vlen, &type) == 1
	    && type == AI_JSON_BOOL)
		do_bind = (vlen > 0 && val[0] == 't') ? 1 : 0;
	if (ai_json_obj_get(args, strlen(args), "dry_run", &val, &vlen,
			    &type) == 1 && type == AI_JSON_BOOL)
		dry = (vlen > 0 && val[0] == 't') ? 1 : 0;
	if (!mode)
		mode = strdup("override");
	if (!action)
		action = strdup("bind");

	if (!dev || !dev[0]) {
		rc = dv_error_json(out, "aik-usb-bind/1", "invalid_arg",
				   "缺少 device（如 1-1 或 1-1:1.0）");
		goto out;
	}
	if (dv_sysfs_root(root, sizeof(root), err, sizeof(err)) != 0) {
		rc = dv_error_json(out, "aik-usb-bind/1", "sysfs_unavailable",
				   "%s", err);
		goto out;
	}
	ctx.root = root;
	if (dv_root_is_real_sysfs(root) && geteuid() != 0) {
		rc = dv_error_json(out, "aik-usb-bind/1", "permission_denied",
				   "写 %s 需要 root（当前 uid=%lu），未做任何修改",
				   root, (unsigned long)geteuid());
		goto out;
	}
	if (dv_collect(root, dev, &f, err, sizeof(err)) != 0) {
		rc = dv_error_json(out, "aik-usb-bind/1", "device_not_found",
				   "%s", err);
		goto out;
	}
	if (dv_op_node(root, &f) != 0) {
		rc = dv_error_json(out, "aik-usb-bind/1", "path_error",
				   "解析接口操作节点失败（路径过长）");
		goto out;
	}
	ctx.f = &f;
	ctx.snapshot_ready = 0;
	{
		char gcode[64] = "", gmsg[512] = "";

		if (dv_safety_gate(&f, gcode, sizeof(gcode), gmsg,
				   sizeof(gmsg)) != 0) {
			rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 0,
						 action, mode, f.dev, &f, &ctx,
						 drv, gcode, gmsg, 0, 0, "",
						 dry, 0);
			goto out;
		}
	}

	if (strcmp(action, "unbind") == 0) {
		struct dv_snap *s = &ctx.snap;

		if (!f.driver[0]) {
			rc = dv_emit_bind_result(out, "aik-usb-bind/1", 1, 0,
						 "unbind", mode, f.dev, &f,
						 &ctx, NULL, "", "", 0, 0, "",
						 dry, 0);
			goto out;
		}
		if (dry) {
			rc = dv_emit_bind_result(out, "aik-usb-bind/1", 1, 0,
						 "unbind", mode, f.dev, &f,
						 &ctx, NULL, "", "", 0, 0, "",
						 1, 0);
			goto out;
		}
		if (dv_state_dir(state, sizeof(state)) != 0) {
			rc = dv_error_json(out, "aik-usb-bind/1",
					   "snapshot_failed",
					   "状态目录不可用，无法落快照，未做任何修改");
			goto out;
		}
		snprintf(s->device, sizeof(s->device), "%s", f.dev);
		snprintf(s->iface, sizeof(s->iface), "%s", f.iface);
		snprintf(s->sysfs, sizeof(s->sysfs), "%s", root);
		snprintf(s->driver, sizeof(s->driver), "%s", f.driver);
		s->bound = 1;
		snprintf(s->override, sizeof(s->override), "%s", f.override);
		s->override_present = f.override_present;
		if (dv_snap_save(state, s, err, sizeof(err)) != 0) {
			rc = dv_error_json(out, "aik-usb-bind/1",
					   "snapshot_failed", "%s，未做任何修改",
					   err);
			goto out;
		}
		ctx.snapshot_ready = 1;
		dv_audit("op=dev_bind action=unbind device=%s iface=%s driver=%s",
			 f.dev, f.iface, f.driver);
		if (dv_ctx_unbind(&ctx, f.driver) != 0) {
			rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 0,
						 "unbind", mode, f.dev, &f, &ctx,
						 NULL, "unbind_failed",
						 "写 unbind 失败，未产生修改", 0, 0,
						 "", 0, 0);
			goto out;
		}
		{
			char devices[DV_PATH_MAX], node_dir[DV_PATH_MAX];
			char now[DV_MAX_DRIVER];

			if (dv_join(devices, sizeof(devices), root, "devices") == 0
			    && dv_join(node_dir, sizeof(node_dir), devices,
				       f.node) == 0) {
				dv_read_driver(node_dir, now, sizeof(now));
			} else {
				now[0] = '\0';
			}
			if (now[0]) {
				rollback_attempted = 1;
				rollback_ok = (dv_rollback(&ctx, rmsg,
							   sizeof(rmsg)) == 0);
				rc = dv_emit_bind_result(out, "aik-usb-bind/1",
							 0, 1, "unbind", mode,
							 f.dev, &f, &ctx, NULL,
							 "unbind_ineffective",
							 "unbind 返回成功但读回仍有驱动，已回滚",
							 rollback_attempted,
							 rollback_ok, rmsg, 0,
							 0);
				goto out;
			}
		}
		rc = dv_emit_bind_result(out, "aik-usb-bind/1", 1, 1, "unbind",
					 mode, f.dev, &f, &ctx, NULL, "", "",
					 0, 0, "", 0, 0);
		goto out;
	}

	/* action=bind */
	if (!drv || !drv[0]) {
		rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 0, "bind",
					 mode, f.dev, &f, &ctx, NULL,
					 "invalid_arg",
					 "action=bind 需要 driver（目标驱动名）",
					 0, 0, "", dry, 0);
		goto out;
	}
	if (!dv_driver_name_valid(drv) || dv_driver_forbidden(drv)) {
		rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 0, "bind",
					 mode, f.dev, &f, &ctx, drv,
					 "driver_forbidden",
					 "拒绝：driver 名非法或层级不对（hub/usb/usbfs 一律禁止）",
					 0, 0, "", dry, 0);
		goto out;
	}
	if (!dv_mode_valid(mode)) {
		rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 0, "bind",
					 mode, f.dev, &f, &ctx, drv,
					 "invalid_mode",
					 "mode 只允许 override / new_id / bind",
					 0, 0, "", dry, 0);
		goto out;
	}
	{
		char drvdir[DV_PATH_MAX];

		if (dv_join(drvdir, sizeof(drvdir), root, "drivers") != 0 ||
		    dv_append(drvdir, sizeof(drvdir), "/") != 0 ||
		    dv_append(drvdir, sizeof(drvdir), drv) != 0 ||
		    !dv_dir_exists(drvdir)) {
			rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 0,
						 "bind", mode, f.dev, &f, &ctx,
						 drv, "driver_not_registered",
						 "目标驱动未注册（模块未加载？）。本工具不自动 modprobe",
						 0, 0, "", dry, 0);
			goto out;
		}
	}
	if (strcmp(mode, "override") == 0 && !f.override_present) {
		rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 0, "bind",
					 mode, f.dev, &f, &ctx, drv,
					 "override_unsupported",
					 "本内核 USB 节点没有 driver_override 属性：override 模式不可用（fail-closed）。可改用 mode=bind 或 new_id",
					 0, 0, "", dry, 0);
		goto out;
	}
	if (strcmp(mode, "new_id") == 0) {
		char nidpath[DV_PATH_MAX];

		if (!f.id_vendor[0] || !f.id_product[0]) {
			rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 0,
						 "bind", mode, f.dev, &f, &ctx,
						 drv, "new_id_unknown_ids",
						 "拿不到 idVendor/idProduct，无法写 new_id",
						 0, 0, "", dry, 0);
			goto out;
		}
		if (dv_driver_path(nidpath, sizeof(nidpath), root, drv,
				   "new_id") != 0 ||
		    !dv_file_exists(nidpath)) {
			rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 0,
						 "bind", mode, f.dev, &f, &ctx,
						 drv, "new_id_unsupported",
						 "目标驱动没有 new_id 属性（该驱动不支持动态 id）",
						 0, 0, "", dry, 0);
			goto out;
		}
	}
	if (f.driver[0] && strcmp(f.driver, drv) == 0) {
		rc = dv_emit_bind_result(out, "aik-usb-bind/1", 1, 0, "bind",
					 mode, f.dev, &f, &ctx, drv, "", "",
					 0, 0, "", dry, 0);
		goto out;
	}
	if (dry) {
		rc = dv_emit_bind_result(out, "aik-usb-bind/1", 1, 0, "bind",
					 mode, f.dev, &f, &ctx, drv, "", "",
					 0, 0, "", 1, 0);
		goto out;
	}

	/* ---- 快照（必须先落盘，之后才允许任何写） ---- */
	if (dv_state_dir(state, sizeof(state)) != 0) {
		rc = dv_error_json(out, "aik-usb-bind/1", "snapshot_failed",
				   "状态目录不可用，无法落快照，未做任何修改");
		goto out;
	}
	{
		struct dv_snap *s = &ctx.snap;

		snprintf(s->device, sizeof(s->device), "%s", f.dev);
		snprintf(s->iface, sizeof(s->iface), "%s", f.iface);
		snprintf(s->sysfs, sizeof(s->sysfs), "%s", root);
		snprintf(s->driver, sizeof(s->driver), "%s", f.driver);
		s->bound = f.driver[0] != '\0';
		snprintf(s->override, sizeof(s->override), "%s", f.override);
		s->override_present = f.override_present;
		if (strcmp(mode, "new_id") == 0) {
			snprintf(s->new_id, sizeof(s->new_id), "%s %s",
				 f.id_vendor, f.id_product);
			snprintf(s->new_id_driver, sizeof(s->new_id_driver),
				 "%s", drv);
		}
	}
	if (dv_snap_save(state, &ctx.snap, err, sizeof(err)) != 0) {
		rc = dv_error_json(out, "aik-usb-bind/1", "snapshot_failed",
				   "%s，未做任何修改", err);
		goto out;
	}
	ctx.snapshot_ready = 1;
	dv_audit("op=dev_bind action=bind device=%s iface=%s mode=%s target=%s old_driver=%s",
		 f.dev, f.iface, mode, drv, f.driver[0] ? f.driver : "(空)");

	if (f.iface_class_ok && f.n_iface_classes == 1 &&
	    f.iface_class[0] == 3 && dv_root_is_real_sysfs(root))
		wait_ms = 2500;

	{
		char acode[64] = "", amsg[512] = "";

		if (dv_apply_bind(&ctx, mode, drv, do_bind, acode,
				  sizeof(acode), amsg, sizeof(amsg)) != 0) {
			char fcode[64];

			snprintf(fcode, sizeof(fcode), "%s", acode);
			rollback_attempted = 1;
			rollback_ok = (dv_rollback(&ctx, rmsg,
						   sizeof(rmsg)) == 0);
			rc = dv_emit_bind_result(out, "aik-usb-bind/1", 0, 1,
						 "bind", mode, f.dev, &f, &ctx,
						 drv, fcode, amsg,
						 rollback_attempted, rollback_ok,
						 rmsg, 0, wait_ms);
			goto out;
		}
	}
	if (strcmp(mode, "new_id") == 0) {
		/* 动态 id 用完就撤：绑定保持，避免污染驱动 id 表 */
		if (dv_ctx_remove_newid(&ctx) != 0)
			dv_audit("op=remove_new_id_skipped driver=%s id=%s",
				 ctx.snap.new_id_driver, ctx.snap.new_id);
	}
	ok = 1;
	changed = 1;
	rc = dv_emit_bind_result(out, "aik-usb-bind/1", ok, changed, "bind",
				 mode, f.dev, &f, &ctx, drv, "", "", 0, 0, "",
				 0, wait_ms);
	(void)snapshot_arg;

out:
	free(dev);
	free(drv);
	free(mode);
	free(action);
	free(snapshot_arg);
	return rc;
}

static int dv_tool_restore(const char *args, char **out)
{
	char root[DV_PATH_MAX], err[512], code[64] = "", msg[512] = "";
	char state[DV_PATH_MAX];
	char *dev = NULL, *snapshot_arg = NULL;
	struct dv_facts f;
	struct dv_ctx ctx;
	struct dv_snap snap;
	int dry = 0, wait_ms = 0, rc, changed = 0, verified = 0;
	const char *val;
	size_t vlen;
	int type;

	*out = NULL;
	memset(&ctx, 0, sizeof(ctx));
	memset(&f, 0, sizeof(f));
	memset(&snap, 0, sizeof(snap));
	if (ai_json_obj_get(args, strlen(args), "device", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		dev = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "snapshot", &val, &vlen,
			    &type) == 1 && type == AI_JSON_STR)
		snapshot_arg = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "dry_run", &val, &vlen,
			    &type) == 1 && type == AI_JSON_BOOL)
		dry = (vlen > 0 && val[0] == 't') ? 1 : 0;

	if (!dev || !dev[0]) {
		rc = dv_error_json(out, "aik-usb-restore/1", "invalid_arg",
				   "缺少 device（如 1-1）");
		goto out;
	}
	if (dv_sysfs_root(root, sizeof(root), err, sizeof(err)) != 0) {
		rc = dv_error_json(out, "aik-usb-restore/1",
				   "sysfs_unavailable", "%s", err);
		goto out;
	}
	ctx.root = root;
	if (dv_root_is_real_sysfs(root) && geteuid() != 0) {
		rc = dv_error_json(out, "aik-usb-restore/1",
				   "permission_denied",
				   "写 %s 需要 root（当前 uid=%lu），未做任何修改",
				   root, (unsigned long)geteuid());
		goto out;
	}
	if (dv_collect(root, dev, &f, err, sizeof(err)) != 0) {
		rc = dv_error_json(out, "aik-usb-restore/1",
				   "device_not_found", "%s", err);
		goto out;
	}
	if (dv_op_node(root, &f) != 0) {
		rc = dv_error_json(out, "aik-usb-restore/1", "path_error",
				   "解析接口操作节点失败（路径过长）");
		goto out;
	}
	ctx.f = &f;
	{
		char gcode[64] = "", gmsg[512] = "";

		if (dv_safety_gate(&f, gcode, sizeof(gcode), gmsg,
				   sizeof(gmsg)) != 0) {
			rc = dv_emit_bind_result(out, "aik-usb-restore/1", 0, 0,
						 "restore", NULL, f.dev, &f, &ctx,
						 NULL, gcode, gmsg, 0, 0, "",
						 dry, 0);
			goto out;
		}
	}
	if (snapshot_arg && snapshot_arg[0]) {
		char content[DV_SNAP_FILE_MAX];
		ssize_t n = -1;

		if (snapshot_arg[0] == '@') {
			int fd = open(snapshot_arg + 1, O_RDONLY | O_CLOEXEC);

			if (fd >= 0) {
				n = read(fd, content, sizeof(content) - 1);
				close(fd);
			}
		} else {
			n = (ssize_t)strlen(snapshot_arg);
			if ((size_t)n >= sizeof(content))
				n = sizeof(content) - 1;
			memcpy(content, snapshot_arg, (size_t)n);
		}
		if (n <= 0) {
			rc = dv_error_json(out, "aik-usb-restore/1",
					   "snapshot_invalid",
					   "snapshot 为空或读取失败");
			goto out;
		}
		content[n] = '\0';
		if (dv_snap_parse(content, (size_t)n, &snap, NULL, err,
				  sizeof(err)) != 0) {
			rc = dv_error_json(out, "aik-usb-restore/1",
					   "snapshot_invalid", "%s", err);
			goto out;
		}
	} else {
		if (dv_state_dir(state, sizeof(state)) != 0 ||
		    dv_snap_load(state, f.dev, &snap, err, sizeof(err)) != 0) {
			rc = dv_error_json(out, "aik-usb-restore/1",
					   "snapshot_missing", "%s", err);
			goto out;
		}
	}
	if (strcmp(snap.sysfs, root) != 0) {
		rc = dv_error_json(out, "aik-usb-restore/1",
				   "snapshot_sysfs_mismatch",
				   "快照 sysfs=%s 与当前 %s 不一致（fail-closed）",
				   snap.sysfs, root);
		goto out;
	}
	if (strcmp(snap.device, f.dev) != 0) {
		rc = dv_error_json(out, "aik-usb-restore/1", "snapshot_mismatch",
				   "快照 device=%s 与请求 %s 不一致",
				   snap.device, f.dev);
		goto out;
	}
	ctx.snap = snap;
	ctx.snapshot_ready = 1;

	if (dry) {
		rc = dv_emit_bind_result(out, "aik-usb-restore/1", 1, 0,
					 "restore", NULL, f.dev, &f, &ctx,
					 snap.driver, "", "", 0, 0, "", 1, 0);
		goto out;
	}

	dv_audit("op=dev_restore device=%s iface=%s snapshot=%s target_driver=%s",
		 f.dev, f.iface, snap.path, snap.driver);

	{
		char devices[DV_PATH_MAX], node_dir[DV_PATH_MAX];
		char now[DV_MAX_DRIVER], ov[DV_MAX_OVERRIDE];
		int ov_present = 0;

		if (dv_join(devices, sizeof(devices), root, "devices") != 0 ||
		    dv_join(node_dir, sizeof(node_dir), devices, f.node) != 0) {
			rc = dv_error_json(out, "aik-usb-restore/1",
					   "path_error", "sysfs 路径过长");
			goto out;
		}
		dv_read_driver(node_dir, now, sizeof(now));
		if (now[0] && strcmp(now, snap.driver) != 0) {
			if (dv_ctx_unbind(&ctx, now) != 0) {
				snprintf(code, sizeof(code), "unbind_failed");
				snprintf(msg, sizeof(msg),
					 "从当前驱动 %s 撤销失败", now);
				rc = dv_emit_bind_result(out,
							 "aik-usb-restore/1", 0,
							 0, "restore", NULL, f.dev,
							 &f, &ctx, snap.driver,
							 code, msg, 0, 0, "", 0,
							 0);
				goto out;
			}
			changed = 1;
		}
		(void)dv_ctx_remove_newid(&ctx);
		if (snap.override_present) {
			dv_read_override(node_dir, ov, sizeof(ov), &ov_present);
			if (!ov_present || strcmp(ov, snap.override) != 0) {
				char opath[DV_PATH_MAX];

				if (dv_join(opath, sizeof(opath), node_dir,
					    "driver_override") != 0 ||
				    dv_ctx_write(&ctx, opath,
						 snap.override) != 0) {
					snprintf(code, sizeof(code),
						 "override_restore_failed");
					snprintf(msg, sizeof(msg),
						 "恢复 driver_override 失败");
					rc = dv_emit_bind_result(out,
								 "aik-usb-restore/1",
								 0, changed,
								 "restore",
								 NULL, f.dev, &f,
								 &ctx,
								 snap.driver,
								 code, msg, 0,
								 0, "", 0, 0);
					goto out;
				}
				changed = 1;
			}
		}
		dv_read_driver(node_dir, now, sizeof(now));
		if (snap.driver[0] && strcmp(now, snap.driver) != 0) {
			if (dv_ctx_bind(&ctx, snap.driver) != 0) {
				snprintf(code, sizeof(code), "rebind_failed");
				snprintf(msg, sizeof(msg),
					 "绑回原驱动 %s 失败", snap.driver);
				rc = dv_emit_bind_result(out,
							 "aik-usb-restore/1", 0,
							 changed, "restore",
							 NULL, f.dev, &f, &ctx,
							 snap.driver, code, msg,
							 0, 0, "", 0, 0);
				goto out;
			}
			changed = 1;
		} else if (!snap.driver[0] && now[0]) {
			if (dv_ctx_unbind(&ctx, now) != 0) {
				snprintf(code, sizeof(code), "unbind_failed");
				snprintf(msg, sizeof(msg),
					 "恢复未绑定状态失败（%s）", now);
				rc = dv_emit_bind_result(out,
							 "aik-usb-restore/1", 0,
							 changed, "restore",
							 NULL, f.dev, &f, &ctx,
							 snap.driver, code, msg,
							 0, 0, "", 0, 0);
				goto out;
			}
			changed = 1;
		}

		dv_readback(root, node_dir, now, sizeof(now), ov, sizeof(ov),
			    &ov_present);
		verified = 1;
		if (strcmp(now, snap.driver) != 0)
			verified = 0;
		if (snap.override_present &&
		    (!ov_present || strcmp(ov, snap.override) != 0))
			verified = 0;
		if (!snap.override_present && ov_present && ov[0])
			verified = 0;
		if (!verified) {
			snprintf(code, sizeof(code), "restore_unverified");
			snprintf(msg, sizeof(msg),
				 "读回与快照不一致（driver=%s override=%s）",
				 now[0] ? now : "(空)",
				 ov_present ? ov : "(属性缺失)");
		}
	}
	if (f.iface_class_ok && f.n_iface_classes == 1 &&
	    f.iface_class[0] == 3 && dv_root_is_real_sysfs(root))
		wait_ms = 2500;
	rc = dv_emit_bind_result(out, "aik-usb-restore/1", verified, changed,
				 "restore", NULL, f.dev, &f, &ctx, snap.driver,
				 code, msg, 0, 0, "", 0, wait_ms);

out:
	free(dev);
	free(snapshot_arg);
	return rc;
}

/* ======================================================================
 * 7) W82 V5.3/V5.4：四级递进适配（dev_adapt）+ 异步任务（dev_task）
 *
 * 四级递进（每级都是「尝试 → 读回验证 → 失败回滚 → 记结果 → 下一级」）：
 *   L1 in_tree_new_id  向「已在树」的目标驱动写 new_id 强制匹配后 bind
 *   L2 driver_override 写 driver_override 后 bind（本内核无该属性 → fail-closed）
 *   L3 generic_driver  通用类驱动兜底（uinput / usb-storage / vfio）
 *   L4 param_quirk     目标驱动模块参数 quirk（参数缺失/只读 → 如实失败）
 *
 * 异步模型：dev_adapt 先做完整安全校验 + 落快照 + 建任务目录，再 fork 出
 * daemon（setsid，stdout/stderr 接 daemon.log），父进程立刻返回 task_id。
 * daemon 把进度写 status.json（原子重写）+ progress.jsonl（追加）+ daemon.log。
 * dev_task action=cancel 发 SIGTERM，daemon 在下一个检查点中止；取消路径
 * 与任务收尾都调用 dv_ensure_original()，确保设备回到任务开始前的驱动。
 *
 * 不假成功：只有「读回 driver == 目标」且（HID 目标时）/proc/bus/input/devices
 * 里确有该接口的输入设备，才算该级成功；四级全失败时 ok=false，levels[]
 * 保留每级 rc/errno/verify/rollback 与失败写路径。回滚失败会显式标
 * rollback_ok=false 并停止后续级别（不在未知状态上继续动设备）。
 * ====================================================================== */

#define DV_ADAPT_LEVELS		4
#define DV_ADAPT_SCHEMA		"aik-usb-adapt/1"
#define DV_TASK_SCHEMA		"aik-usb-adapt-task/1"
#define DV_TASK_STATUS_SCHEMA	"aik-usb-task/1"
#define DV_TASK_LOG_SCHEMA	"aik-usb-task-log/1"
#define DV_TASK_ID_MAX		64
#define DV_TASK_STATUS_BUF	(64 * 1024)
#define DV_TASK_LOG_MAX		(256 * 1024)
#define DV_TASK_TAIL_LINES	8
#define DV_REAP_MAX		8

enum {
	DV_TASK_QUEUED = 0,
	DV_TASK_RUNNING,
	DV_TASK_DONE,
	DV_TASK_FAILED,
	DV_TASK_CANCELED,
};

/* 只有 dev_adapt 的 daemon / 前台执行会置位；其它工具路径恒为 0。 */
static volatile sig_atomic_t dv_g_cancel;
static pid_t dv_g_children[DV_REAP_MAX];
static int dv_g_nchildren;

static void dv_cancel_handler(int sig)
{
	(void)sig;
	dv_g_cancel = 1;
}

static const char *dv_state_name(int s)
{
	switch (s) {
	case DV_TASK_QUEUED:
		return "queued";
	case DV_TASK_RUNNING:
		return "running";
	case DV_TASK_DONE:
		return "done";
	case DV_TASK_FAILED:
		return "failed";
	case DV_TASK_CANCELED:
		return "canceled";
	default:
		return "unknown";
	}
}

int dv_task_state_terminal(const char *state)
{
	if (!state)
		return 0;
	return strcmp(state, "done") == 0 || strcmp(state, "failed") == 0 ||
	       strcmp(state, "canceled") == 0;
}

const char *dv_adapt_level_name(int level)
{
	switch (level) {
	case 1:
		return "in_tree_new_id";
	case 2:
		return "driver_override";
	case 3:
		return "generic_driver";
	case 4:
		return "param_quirk";
	default:
		return "unknown";
	}
}

int dv_task_id_valid(const char *id)
{
	size_t i, n;

	if (!id || !id[0])
		return 0;
	n = strlen(id);
	if (n >= DV_TASK_ID_MAX || id[0] == '.')
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)id[i];

		if (isalnum(c) || c == '.' || c == '_' || c == '-')
			continue;
		return 0;
	}
	return 1;
}

struct dv_task_paths {
	char dir[DV_PATH_MAX];
	char status[DV_PATH_MAX];
	char progress[DV_PATH_MAX];
	char log[DV_PATH_MAX];
	char pid[DV_PATH_MAX];
	char snap[DV_PATH_MAX];
};

struct dv_level_rec {
	int level;
	char name[40];
	char driver[DV_MAX_DRIVER];
	char action[40];
	int rc;			/* 0 成功 / -1 失败 / -2 取消 */
	int err;		/* 决定性失败写的 errno（无失败写为 0） */
	int verify;		/* 读回验证是否通过 */
	int rollback_attempted;
	int rollback_ok;
	char code[48];
	char detail[600];
};

struct dv_task {
	struct dv_task_paths paths;
	char id[DV_TASK_ID_MAX];
	char device[DV_NAME_MAX];
	char iface[DV_NAME_MAX];
	char sysfs[DV_PATH_MAX];
	char target[DV_MAX_DRIVER];
	char orig_driver[DV_MAX_DRIVER];
	int orig_override_present;
	char orig_override[DV_MAX_OVERRIDE];
	int state;
	int ok;			/* -1 未知 / 0 失败 / 1 成功 */
	int level;		/* 当前级别 1..4；0 = 尚未开始 */
	int pid;
	int foreground;
	int changed;
	int seq;
	char started_at[32];
	char updated_at[32];
	char finished_at[32];
	char error_code[64];
	char error[600];
	char snapshot[DV_PATH_MAX];
	char cancel_source[32];
	struct dv_level_rec lv[DV_ADAPT_LEVELS];
	int n_lv;
};

static int dv_read_file_bounded(const char *path, char *buf, size_t cap,
				size_t *out_n);

/* ------------------------------------------------------------------ */
/* 任务目录 / 状态文件                                                 */
/* ------------------------------------------------------------------ */

static int dv_tasks_root(char *out, size_t cap)
{
	char state[DV_PATH_MAX], tasks[DV_PATH_MAX];

	if (dv_state_dir(state, sizeof(state)) != 0)
		return -1;
	if (dv_join(tasks, sizeof(tasks), state, "tasks") != 0)
		return -1;
	if (dv_mkdir_one(tasks) != 0)
		return -1;
	snprintf(out, cap, "%s", tasks);
	return 0;
}

static int dv_task_paths_open(const char *id, struct dv_task_paths *p)
{
	char root[DV_PATH_MAX];
	char name[DV_NAME_MAX];

	if (!p || !dv_task_id_valid(id))
		return -1;
	snprintf(name, sizeof(name), "%s", id);
	memset(p, 0, sizeof(*p));
	if (dv_tasks_root(root, sizeof(root)) != 0)
		return -1;
	if (dv_join(p->dir, sizeof(p->dir), root, name) != 0)
		return -1;
	if (dv_mkdir_one(p->dir) != 0)
		return -1;
	if (dv_join(p->status, sizeof(p->status), p->dir, "status.json") != 0 ||
	    dv_join(p->progress, sizeof(p->progress), p->dir,
		    "progress.jsonl") != 0 ||
	    dv_join(p->log, sizeof(p->log), p->dir, "daemon.log") != 0 ||
	    dv_join(p->pid, sizeof(p->pid), p->dir, "pid") != 0 ||
	    dv_join(p->snap, sizeof(p->snap), p->dir, "snapshot.json") != 0)
		return -1;
	return 0;
}

static void dv_task_gen_id(char *out, size_t cap)
{
	struct tm tm;
	time_t now = time(NULL);
	char stamp[32];
	static int counter;

	gmtime_r(&now, &tm);
	strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%SZ", &tm);
	counter++;
	snprintf(out, cap, "t-%s-%ld-%d", stamp, (long)(getpid() % 100000),
		 counter);
}

/* 任务目录里 mtime 最新的那个（dev_task 不传 task_id 时的默认目标） */
static int dv_task_latest(char *out, size_t cap)
{
	char root[DV_PATH_MAX];
	char **kids = NULL;
	int n = 0, i, found = 0;
	time_t best_sec = 0;
	long best_nsec = 0;

	out[0] = '\0';
	if (dv_tasks_root(root, sizeof(root)) != 0)
		return -1;
	if (dv_list_children(root, NULL, &kids, &n) != 0)
		return -1;
	for (i = 0; i < n; i++) {
		char path[DV_PATH_MAX];
		struct stat st;

		if (!dv_task_id_valid(kids[i]))
			continue;
		if (dv_join(path, sizeof(path), root, kids[i]) != 0)
			continue;
		if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
			continue;
		/* 秒级 mtime 在同一秒内会打平（实测踩过），用纳秒比较 */
		if (!found || st.st_mtim.tv_sec > best_sec ||
		    (st.st_mtim.tv_sec == best_sec &&
		     st.st_mtim.tv_nsec > best_nsec)) {
			best_sec = st.st_mtim.tv_sec;
			best_nsec = st.st_mtim.tv_nsec;
			found = 1;
			snprintf(out, cap, "%s", kids[i]);
		}
	}
	dv_free_children(kids, n);
	return found ? 0 : -1;
}

static int dv_read_file_bounded(const char *path, char *buf, size_t cap,
				size_t *out_n)
{
	int fd;
	ssize_t n;

	if (out_n)
		*out_n = 0;
	if (!path || !buf || cap == 0)
		return -1;
	buf[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	if (out_n)
		*out_n = (size_t)n;
	return 0;
}

static long long dv_json_get_int(const char *json, size_t len, const char *key,
				 long long def)
{
	const char *val;
	size_t vlen;
	int type;
	char buf[32], *end;
	long long v;

	if (!json || ai_json_obj_get(json, len, key, &val, &vlen, &type) != 1 ||
	    type != AI_JSON_NUM)
		return def;
	if (vlen >= sizeof(buf))
		return def;
	memcpy(buf, val, vlen);
	buf[vlen] = '\0';
	errno = 0;
	v = strtoll(buf, &end, 10);
	if (errno != 0 || end == buf)
		return def;
	return v;
}

/* 进度事件：progress.jsonl（结构化）+ daemon.log（人读）双写 */
static void dv_task_emit(struct dv_task *t, int level, const char *event,
			 const char *fmt, ...)
{
	char line[2048], human[1024], stamp[32];
	struct dvb b;
	va_list ap;
	int fd, n;
	size_t len;

	if (!t || !t->paths.progress[0])
		return;
	dv_now(stamp, sizeof(stamp));
	t->seq++;
	va_start(ap, fmt);
	vsnprintf(human, sizeof(human), fmt, ap);
	va_end(ap);
	dvb_init(&b, line, sizeof(line));
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "ts", stamp);
	dvb_kv_int(&b, "seq", t->seq);
	dvb_kv_str(&b, "task_id", t->id);
	dvb_kv_int(&b, "level", level);
	dvb_kv_str(&b, "event", event);
	dvb_kv_str(&b, "msg", human);
	dvb_puts(&b, "\"schema_ok\":true}");
	len = strlen(line);
	if (len + 2 >= sizeof(line))
		return;
	line[len++] = '\n';
	line[len] = '\0';
	fd = open(t->paths.progress,
		  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd >= 0) {
		if (write(fd, line, len) != (ssize_t)len) {
			/* 进度写失败不能改变判定，但要留痕 */
			dv_audit("op=adapt_progress_write_failed task=%s",
				 t->id);
		}
		close(fd);
	}
	fd = open(t->paths.log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
		  0600);
	if (fd >= 0) {
		n = dprintf(fd, "%s level=%d event=%s %s\n", stamp, level,
			    event, human);
		(void)n;
		close(fd);
	}
}

static void dv_read_driver_node(const char *root, const char *node, char *out,
				size_t cap)
{
	char devices[DV_PATH_MAX], node_dir[DV_PATH_MAX];

	out[0] = '\0';
	if (dv_join(devices, sizeof(devices), root, "devices") != 0 ||
	    dv_join(node_dir, sizeof(node_dir), devices, node) != 0)
		return;
	dv_read_driver(node_dir, out, cap);
}

static int dv_task_status_write(struct dv_task *t)
{
	char *buf;
	struct dvb b;
	char err[256], drv[DV_MAX_DRIVER];
	int i;

	if (!t || !t->paths.status[0])
		return -1;
	buf = malloc(DV_TASK_STATUS_BUF);
	if (!buf)
		return -1;
	dv_read_driver_node(t->sysfs[0] ? t->sysfs : "/sys/bus/usb",
			    t->iface[0] ? t->iface : t->device, drv,
			    sizeof(drv));
	dv_now(t->updated_at, sizeof(t->updated_at));
	dvb_init(&b, buf, DV_TASK_STATUS_BUF);
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "schema", DV_TASK_SCHEMA);
	dvb_kv_str(&b, "task_id", t->id);
	dvb_kv_str(&b, "device", t->device);
	dvb_kv_str(&b, "iface", t->iface[0] ? t->iface : NULL);
	dvb_kv_str(&b, "sysfs", t->sysfs[0] ? t->sysfs : NULL);
	dvb_kv_str(&b, "target_driver", t->target);
	dvb_kv_str(&b, "status", dv_state_name(t->state));
	dvb_json_str(&b, "ok");
	dvb_putc(&b, ':');
	dvb_puts(&b, t->ok < 0 ? "null" : (t->ok ? "true" : "false"));
	dvb_putc(&b, ',');
	dvb_kv_int(&b, "level", t->level);
	dvb_kv_int(&b, "levels_total", DV_ADAPT_LEVELS);
	dvb_kv_int(&b, "pid", t->pid);
	dvb_kv_bool(&b, "foreground", t->foreground);
	dvb_kv_bool(&b, "changed", t->changed);
	dvb_kv_str(&b, "orig_driver",
		   t->orig_driver[0] ? t->orig_driver : NULL);
	dvb_kv_str(&b, "current_driver", drv[0] ? drv : NULL);
	dvb_kv_str(&b, "started_at", t->started_at);
	dvb_kv_str(&b, "updated_at", t->updated_at);
	dvb_kv_str(&b, "finished_at",
		   t->finished_at[0] ? t->finished_at : NULL);
	dvb_kv_str(&b, "snapshot", t->snapshot[0] ? t->snapshot : NULL);
	dvb_kv_str(&b, "error_code",
		   t->error_code[0] ? t->error_code : NULL);
	dvb_kv_str(&b, "error", t->error[0] ? t->error : NULL);
	dvb_kv_str(&b, "cancel_source",
		   t->cancel_source[0] ? t->cancel_source : NULL);
	dvb_puts(&b, "\"levels\":[");
	for (i = 0; i < t->n_lv; i++) {
		struct dv_level_rec *r = &t->lv[i];

		if (i)
			dvb_putc(&b, ',');
		dvb_puts(&b, "{");
		dvb_kv_int(&b, "level", r->level);
		dvb_kv_str(&b, "name", r->name);
		dvb_kv_str(&b, "driver", r->driver[0] ? r->driver : NULL);
		dvb_kv_str(&b, "action", r->action[0] ? r->action : NULL);
		dvb_kv_int(&b, "rc", r->rc);
		dvb_kv_int(&b, "errno", r->err);
		dvb_kv_bool(&b, "verify", r->verify);
		dvb_kv_bool(&b, "rollback_attempted", r->rollback_attempted);
		dvb_kv_bool(&b, "rollback_ok", r->rollback_ok);
		dvb_kv_str(&b, "code", r->code[0] ? r->code : NULL);
		dvb_kv_str(&b, "detail", r->detail[0] ? r->detail : NULL);
		dvb_obj_close(&b);
	}
	dvb_arr_close(&b);
	dvb_putc(&b, ',');
	dvb_kv_bool(&b, "truncated", b.trunc);
	dvb_puts(&b, "\"schema_ok\":true}");
	if (b.trunc) {
		free(buf);
		return -1;
	}
	i = dv_write_file_atomic(t->paths.status, buf, err, sizeof(err));
	free(buf);
	if (i != 0)
		dv_audit("op=adapt_status_write_failed task=%s err=%s", t->id,
			 err);
	return i;
}

/* 收尾失败：写失败态并返回 -1（供 pipeline 直接 return） */
static int dv_task_fail(struct dv_task *t, const char *code,
			const char *fmt, ...)
{
	va_list ap;

	t->state = DV_TASK_FAILED;
	t->ok = 0;
	snprintf(t->error_code, sizeof(t->error_code), "%s",
		 code && code[0] ? code : "failed");
	va_start(ap, fmt);
	vsnprintf(t->error, sizeof(t->error), fmt, ap);
	va_end(ap);
	if (!t->finished_at[0])
		dv_now(t->finished_at, sizeof(t->finished_at));
	dv_task_status_write(t);
	dv_task_emit(t, t->level, "task_end", "status=failed error_code=%s",
		     t->error_code);
	return -1;
}

/* ------------------------------------------------------------------ */
/* 四级递进的判定原语                                                 */
/* ------------------------------------------------------------------ */

static int dv_driver_exists(const char *root, const char *drv)
{
	char dir[DV_PATH_MAX], sub[DV_PATH_MAX];

	if (!dv_driver_name_valid(drv))
		return 0;
	if (dv_join(sub, sizeof(sub), root, "drivers") != 0 ||
	    dv_join(dir, sizeof(dir), sub, drv) != 0)
		return 0;
	return dv_dir_exists(dir);
}

static int dv_driver_has_attr(const char *root, const char *drv,
			      const char *attr)
{
	char path[DV_PATH_MAX];

	if (dv_driver_path(path, sizeof(path), root, drv, attr) != 0)
		return 0;
	return dv_file_exists(path);
}

static int dv_iface_is_hid(const struct dv_facts *f)
{
	return f->iface_class_ok && f->n_iface_classes == 1 &&
	       f->iface_class[0] == 3;
}

static const char *dv_ctx_fail_path(const struct dv_ctx *ctx)
{
	int i;

	for (i = ctx->nwrites - 1; i >= 0; i--)
		if (ctx->writes[i].rc != 0)
			return ctx->writes[i].path;
	return "";
}

static int dv_ctx_fail_errno(const struct dv_ctx *ctx)
{
	int i;

	for (i = ctx->nwrites - 1; i >= 0; i--)
		if (ctx->writes[i].rc != 0)
			return ctx->writes[i].err;
	return 0;
}

/* 读回验证：driver 必须是目标；HID 目标还要有输入设备（真 sysfs 才查） */
static int dv_adapt_verify(const char *root, const char *node, const char *drv,
			   int want_input, int wait_ms, int *input_count,
			   char *why, size_t whycap)
{
	char devices[DV_PATH_MAX], node_dir[DV_PATH_MAX], now[DV_MAX_DRIVER];
	int cnt = 0;

	now[0] = '\0';
	if (input_count)
		*input_count = 0;
	if (why && whycap)
		why[0] = '\0';
	if (dv_join(devices, sizeof(devices), root, "devices") != 0 ||
	    dv_join(node_dir, sizeof(node_dir), devices, node) != 0) {
		if (why)
			snprintf(why, whycap, "sysfs 路径过长");
		return 0;
	}
	dv_read_driver(node_dir, now, sizeof(now));
	if (strcmp(now, drv) != 0) {
		if (why)
			snprintf(why, whycap, "读回 driver=%s，不是目标 %s",
				 now[0] ? now : "(空)", drv);
		return 0;
	}
	if (want_input) {
		if (dv_input_probe(root, node_dir, wait_ms, NULL, 0, &cnt) <= 0) {
			if (why)
				snprintf(why, whycap,
					 "driver 已是 %s 但 /proc/bus/input/devices 里没有该接口的输入设备",
					 drv);
			return 0;
		}
	}
	if (input_count)
		*input_count = cnt;
	return 1;
}

static int dv_ensure_original(const char *root, struct dv_facts *f,
			      const struct dv_snap *snap, char *msg,
			      size_t msgcap);

/* 统一收尾：验证 → 失败回滚 → 填 level 记录。
 * 返回 1 成功 / 0 失败（已回滚）/ -1 回滚失败（调用方必须停）。 */
static int dv_level_finish(struct dv_ctx *ctx, struct dv_facts *f,
			   struct dv_level_rec *r, const char *drv,
			   int action_ok, const char *code, const char *msg,
			   int wait_ms)
{
	char why[256] = "", rbuf[512] = "";
	int in_count = 0, verify = 0;

	r->verify = 0;
	r->rc = action_ok ? 0 : -1;
	r->err = action_ok ? 0 : dv_ctx_fail_errno(ctx);
	snprintf(r->driver, sizeof(r->driver), "%s", drv);
	if (!action_ok) {
		snprintf(r->code, sizeof(r->code), "%s",
			 code && code[0] ? code : "action_failed");
		snprintf(r->detail, sizeof(r->detail), "%s%s%s",
			 msg ? msg : "",
			 dv_ctx_fail_path(ctx)[0] ? "；失败写 " : "",
			 dv_ctx_fail_path(ctx));
	} else {
		verify = dv_adapt_verify(ctx->root, f->node, drv,
					 dv_iface_is_hid(f) &&
					 strcmp(drv, "usbhid") == 0 &&
					 dv_root_is_real_sysfs(ctx->root),
					 wait_ms, &in_count, why, sizeof(why));
		r->verify = verify;
		if (verify) {
			r->rc = 0;
			r->err = 0;
			r->code[0] = '\0';
			snprintf(r->detail, sizeof(r->detail),
				 "读回 driver=%s%s%s", drv,
				 in_count > 0 ? "，输入设备 " : "",
				 in_count > 0 ? "已出现" : "");
			return 1;
		}
		r->rc = -1;
		r->err = 0;
		snprintf(r->code, sizeof(r->code), "verify_failed");
		snprintf(r->detail, sizeof(r->detail), "写入未报错但验证失败：%s",
			 why);
	}
	/* 失败 → 回滚到任务开始前的状态 */
	r->rollback_attempted = 1;
	r->rollback_ok = (dv_rollback(ctx, rbuf, sizeof(rbuf)) == 0);
	{
		size_t used = strlen(r->detail);

		snprintf(r->detail + used, sizeof(r->detail) - used,
			 "；回滚%s：%s", r->rollback_ok ? "成功" : "失败", rbuf);
	}
	dv_audit("op=adapt_level_failed level=%d driver=%s code=%s rc=%d errno=%d rollback_ok=%d",
		 r->level, drv, r->code, r->rc, r->err, r->rollback_ok);
	return r->rollback_ok ? 0 : -1;
}

/* L1：向「已在树」的目标驱动写 new_id，再 bind */
static int dv_lvl_new_id(struct dv_ctx *ctx, const char *drv, char *code,
			 size_t codecap, char *msg, size_t msgcap)
{
	if (!dv_driver_exists(ctx->root, drv)) {
		snprintf(code, codecap, "driver_not_registered");
		snprintf(msg, msgcap, "目标驱动 %s 未注册（模块未加载？本工具不自动 modprobe）",
			 drv);
		return -1;
	}
	if (!dv_driver_has_attr(ctx->root, drv, "new_id")) {
		snprintf(code, codecap, "new_id_unsupported");
		snprintf(msg, msgcap, "驱动 %s 没有 new_id 属性（不支持动态 id）",
			 drv);
		return -1;
	}
	if (!ctx->f->id_vendor[0] || !ctx->f->id_product[0]) {
		snprintf(code, codecap, "new_id_unknown_ids");
		snprintf(msg, msgcap, "拿不到 idVendor/idProduct，无法写 new_id");
		return -1;
	}
	snprintf(ctx->snap.new_id, sizeof(ctx->snap.new_id), "%s %s",
		 ctx->f->id_vendor, ctx->f->id_product);
	snprintf(ctx->snap.new_id_driver, sizeof(ctx->snap.new_id_driver), "%s",
		 drv);
	if (dv_apply_bind(ctx, "new_id", drv, 1, code, codecap, msg, msgcap) != 0)
		return -1;
	/* 动态 id 用完就撤：绑定保持，避免污染驱动 id 表 */
	if (dv_ctx_remove_newid(ctx) != 0)
		dv_audit("op=adapt_remove_new_id_skipped driver=%s id=%s", drv,
			 ctx->snap.new_id);
	return 0;
}

/* L2：driver_override 强绑（本内核 USB 节点没有该属性 → 零写失败） */
static int dv_lvl_override(struct dv_ctx *ctx, const struct dv_facts *f,
			   const char *drv, char *code, size_t codecap,
			   char *msg, size_t msgcap)
{
	if (!f->override_present) {
		snprintf(code, codecap, "override_unsupported");
		snprintf(msg, msgcap,
			 "目标接口 %s 没有 driver_override 属性（本内核不支持），override 模式不可用，零写",
			 f->node);
		return -1;
	}
	if (!dv_driver_exists(ctx->root, drv)) {
		snprintf(code, codecap, "driver_not_registered");
		snprintf(msg, msgcap, "目标驱动 %s 未注册", drv);
		return -1;
	}
	if (dv_apply_bind(ctx, "override", drv, 1, code, codecap, msg,
			  msgcap) != 0)
		return -1;
	return 0;
}

/* L4：目标驱动模块参数 quirk（只写零掩码，行为不变；写完必恢复旧值） */
static int dv_quirk_param(const char *drv, char *path, size_t pathcap,
			  char *old, size_t oldcap, int *writable)
{
	char mod[2][DV_MAX_DRIVER];
	const char *cands[2];
	int i;

	snprintf(mod[0], sizeof(mod[0]), "%s", drv);
	for (i = 0; mod[0][i]; i++)
		if (mod[0][i] == '-')
			mod[0][i] = '_';
	snprintf(mod[1], sizeof(mod[1]), "%s", drv);
	cands[0] = mod[0];
	cands[1] = mod[1];
	for (i = 0; i < 2; i++) {
		char p[DV_PATH_MAX];

		snprintf(p, sizeof(p), "/sys/module/%s/parameters/quirks",
			 cands[i]);
		if (!dv_file_exists(p))
			continue;
		snprintf(path, pathcap, "%s", p);
		if (old && oldcap) {
			if (dv_read_text_path(p, old, oldcap) != 0)
				old[0] = '\0';
		}
		if (writable)
			*writable = (access(p, W_OK) == 0);
		return 0;
	}
	return -1;
}

static int dv_lvl_quirk(struct dv_ctx *ctx, const char *drv, char *code,
			size_t codecap, char *msg, size_t msgcap)
{
	char path[DV_PATH_MAX], old[256] = "", val[96], code2[48] = "";
	char msg2[300] = "";
	int writable = 0, rc;

	if (!dv_root_is_real_sysfs(ctx->root)) {
		snprintf(code, codecap, "quirk_unsupported");
		snprintf(msg, msgcap, "假 sysfs 测试树不探测模块参数");
		return -1;
	}
	if (dv_quirk_param(drv, path, sizeof(path), old, sizeof(old),
			   &writable) != 0) {
		snprintf(code, codecap, "quirk_param_unavailable");
		snprintf(msg, msgcap,
			 "驱动 %s 没有 quirks 模块参数（查过 /sys/module/%s 与 %s 两种命名）",
			 drv, drv, drv);
		return -1;
	}
	if (!writable) {
		snprintf(code, codecap, "quirk_param_readonly");
		snprintf(msg, msgcap,
			 "%s 只读（当前值 \"%s\"）：参数 quirk 只能在模块加载时生效，重载模块会重启设备，本工具不做",
			 path, old);
		return -1;
	}
	if (!ctx->f->id_vendor[0] || !ctx->f->id_product[0]) {
		snprintf(code, codecap, "quirk_unknown_ids");
		snprintf(msg, msgcap, "拿不到 idVendor/idProduct，无法拼 quirk");
		return -1;
	}
	snprintf(val, sizeof(val), "0x%s:0x%s:0x0", ctx->f->id_vendor,
		 ctx->f->id_product);
	if (dv_ctx_write(ctx, path, val) != 0) {
		snprintf(code, codecap, "quirk_write_failed");
		snprintf(msg, msgcap, "写 %s 失败", path);
		return -1;
	}
	if (dv_driver_has_attr(ctx->root, drv, "new_id")) {
		snprintf(ctx->snap.new_id, sizeof(ctx->snap.new_id), "%s %s",
			 ctx->f->id_vendor, ctx->f->id_product);
		snprintf(ctx->snap.new_id_driver,
			 sizeof(ctx->snap.new_id_driver), "%s", drv);
		rc = dv_apply_bind(ctx, "new_id", drv, 1, code2, sizeof(code2),
				   msg2, sizeof(msg2));
	} else {
		rc = dv_apply_bind(ctx, "bind", drv, 1, code2, sizeof(code2),
				   msg2, sizeof(msg2));
	}
	/* 参数无条件恢复旧值（quirk 只是尝试，不留在系统里） */
	if (dv_ctx_write(ctx, path, old) != 0)
		dv_audit("op=adapt_quirk_restore_failed path=%s old=%s", path,
			 old);
	if (rc != 0) {
		snprintf(code, codecap, "%s", code2[0] ? code2 : "bind_failed");
		snprintf(msg, msgcap, "%s（quirk 已恢复为 \"%s\"）", msg2, old);
		return -1;
	}
	return 0;
}

/* L3：通用类驱动兜底（uinput / usb-storage / vfio），逐个试、逐个回滚 */
static int dv_lvl_generic(const char *root, struct dv_facts *f,
			  const struct dv_snap *snap0, struct dv_task *t,
			  struct dv_level_rec *r)
{
	static const char *cands[] = { "uinput", "usb-storage", "vfio" };
	int i, any = 0, all_rb = 1, last_err = 0;
	char last_code[48] = "", last_msg[400] = "";

	snprintf(r->action, sizeof(r->action), "%s", "generic_driver");
	for (i = 0; i < (int)(sizeof(cands) / sizeof(cands[0])); i++) {
		const char *cand = cands[i];
		struct dv_ctx cc;
		char ccode[48] = "", cmsg[400] = "", rbuf[512] = "", why[256];
		char mode[16];
		int ok, verify, in_count = 0;

		if (dv_g_cancel)
			return -1;
		if (!dv_driver_exists(root, cand)) {
			/* 未注册只是"没试过"，不能覆盖真实尝试过的候选的失败原因 */
			dv_task_emit(t, 3, "candidate_skip",
				     "driver=%s reason=not_registered", cand);
			continue;
		}
		any = 1;
		memset(&cc, 0, sizeof(cc));
		cc.root = root;
		cc.f = f;
		cc.snap = *snap0;
		cc.snapshot_ready = 1;
		snprintf(mode, sizeof(mode), "%s", "bind");
		if (dv_driver_has_attr(root, cand, "new_id") &&
		    f->id_vendor[0] && f->id_product[0]) {
			snprintf(cc.snap.new_id, sizeof(cc.snap.new_id),
				 "%s %s", f->id_vendor, f->id_product);
			snprintf(cc.snap.new_id_driver,
				 sizeof(cc.snap.new_id_driver), "%s", cand);
			snprintf(mode, sizeof(mode), "%s", "new_id");
		}
		ok = (dv_apply_bind(&cc, mode, cand, 1, ccode, sizeof(ccode),
				    cmsg, sizeof(cmsg)) == 0);
		if (ok) {
			verify = dv_adapt_verify(root, f->node, cand, 0, 0,
						 &in_count, why, sizeof(why));
			if (verify) {
				snprintf(r->driver, sizeof(r->driver), "%s",
					 cand);
				snprintf(r->action, sizeof(r->action), "%s",
					 mode);
				r->rc = 0;
				r->err = 0;
				r->verify = 1;
				r->rollback_attempted = 0;
				r->code[0] = '\0';
				snprintf(r->detail, sizeof(r->detail),
					 "通用驱动 %s（mode=%s）绑定并读回成功",
					 cand, mode);
				if (strcmp(mode, "new_id") == 0)
					(void)dv_ctx_remove_newid(&cc);
				return 1;
			}
			snprintf(ccode, sizeof(ccode), "%s", "verify_failed");
			snprintf(cmsg, sizeof(cmsg), "%s", why);
		}
		r->rollback_attempted = 1;
		if (dv_rollback(&cc, rbuf, sizeof(rbuf)) != 0)
			all_rb = 0;
		last_err = dv_ctx_fail_errno(&cc);
		snprintf(last_code, sizeof(last_code), "%s",
			 ccode[0] ? ccode : "bind_failed");
		snprintf(last_msg, sizeof(last_msg), "%s",
			 cmsg[0] ? cmsg : "绑定失败");
		dv_task_emit(t, 3, "candidate_failed",
			     "driver=%s mode=%s rc=-1 errno=%d code=%s rollback=%d",
			     cand, mode, last_err, last_code, all_rb);
		if (!all_rb) {
			snprintf(r->code, sizeof(r->code),
				 "rollback_failed");
			snprintf(r->detail, sizeof(r->detail),
				 "候选 %s 回滚失败（%s），停止后续候选", cand,
				 rbuf);
			r->rollback_attempted = 1;
			r->rollback_ok = 0;
			r->rc = -1;
			r->err = last_err;
			return -1;
		}
	}
	r->rollback_attempted = any ? 1 : 0;
	r->rollback_ok = all_rb;
	r->rc = -1;
	r->err = last_err;
	snprintf(r->code, sizeof(r->code), "%s",
		 any ? (last_code[0] ? last_code : "generic_bind_failed")
		     : "generic_driver_unavailable");
	snprintf(r->detail, sizeof(r->detail), "%s",
		 any ? last_msg
		     : "候选通用驱动 uinput/usb-storage/vfio 都未注册（本工具不自动 modprobe）");
	return 0;
}

/* 测试缝：让「动作已完成、尚未验证/回滚」的窗口可被取消；
 * 默认 0（不延时）。返回 1 表示延时期间收到取消。 */
static int dv_adapt_delay(void)
{
	const char *env = getenv("AIKERNEL_ADAPT_LEVEL_DELAY_MS");
	long ms;

	if (!env || !env[0])
		return 0;
	ms = strtol(env, NULL, 10);
	if (ms <= 0)
		return 0;
	if (ms > 60000)
		ms = 60000;
	while (ms > 0) {
		struct timespec ts;

		if (dv_g_cancel)
			return 1;
		ts.tv_sec = 0;
		ts.tv_nsec = 100 * 1000 * 1000;
		nanosleep(&ts, NULL);
		ms -= 100;
	}
	return dv_g_cancel ? 1 : 0;
}

/* 单级执行：动作 → （测试缝窗口）→ 验证/回滚。返回 1 成功 / 0 失败 / -1 取消 */
static int dv_adapt_level(int level, const char *root, struct dv_facts *f,
			  const struct dv_snap *snap0, struct dv_task *t,
			  struct dv_level_rec *r)
{
	struct dv_ctx ctx;
	char code[48] = "", msg[400] = "";
	const char *drv = t->target;
	int rc = -1, wait_ms = 0;

	/* HID 目标：绑回 usbhid 后输入设备要过一会儿才出现，给它 2.5s 读回窗口 */
	if (dv_iface_is_hid(f) && dv_root_is_real_sysfs(root))
		wait_ms = 2500;
	memset(&ctx, 0, sizeof(ctx));
	ctx.root = root;
	ctx.f = f;
	ctx.snap = *snap0;
	ctx.snapshot_ready = 1;
	memset(r, 0, sizeof(*r));
	r->level = level;
	snprintf(r->name, sizeof(r->name), "%s", dv_adapt_level_name(level));
	snprintf(r->driver, sizeof(r->driver), "%s", drv);

	switch (level) {
	case 1:
		snprintf(r->action, sizeof(r->action), "%s", "new_id");
		rc = dv_lvl_new_id(&ctx, drv, code, sizeof(code), msg,
				   sizeof(msg));
		break;
	case 2:
		snprintf(r->action, sizeof(r->action), "%s",
			 "driver_override+bind");
		rc = dv_lvl_override(&ctx, f, drv, code, sizeof(code), msg,
				     sizeof(msg));
		break;
	case 3:
		return dv_lvl_generic(root, f, snap0, t, r);
	default:
		snprintf(r->action, sizeof(r->action), "%s", "param_quirk+bind");
		rc = dv_lvl_quirk(&ctx, drv, code, sizeof(code), msg,
				  sizeof(msg));
		break;
	}

	if (dv_adapt_delay()) {
		snprintf(r->code, sizeof(r->code), "%s", "canceled");
		snprintf(r->detail, sizeof(r->detail),
			 "取消发生在 %s 级动作之后、验证之前",
			 dv_adapt_level_name(level));
		r->rc = -2;
		r->err = ECANCELED;
		return -1;
	}
	return dv_level_finish(&ctx, f, r, drv, rc == 0, code, msg, wait_ms);
}

static int dv_ensure_original(const char *root, struct dv_facts *f,
			      const struct dv_snap *snap, char *msg,
			      size_t msgcap)
{
	struct dv_ctx ctx;
	char drv[DV_MAX_DRIVER] = "";

	memset(&ctx, 0, sizeof(ctx));
	ctx.root = root;
	ctx.f = f;
	ctx.snap = *snap;
	ctx.snapshot_ready = 1;
	dv_read_driver_node(root, f->node, drv, sizeof(drv));
	if (strcmp(drv, snap->driver) == 0) {
		snprintf(msg, msgcap, "driver=%s 已是任务开始前的值",
			 drv[0] ? drv : "(未绑定)");
		return 0;
	}
	if (dv_rollback(&ctx, msg, msgcap) == 0)
		return 0;
	return -1;
}

/* ------------------------------------------------------------------ */
/* 流水线                                                             */
/* ------------------------------------------------------------------ */

static int dv_adapt_pipeline(struct dv_task *t)
{
	char root[DV_PATH_MAX], err[512], state[DV_PATH_MAX], rmsg[512] = "";
	struct dv_facts f;
	struct dv_snap snap;
	int level, have_snap = 0;

	memset(&f, 0, sizeof(f));
	memset(&snap, 0, sizeof(snap));
	t->pid = t->foreground ? 0 : (int)getpid();
	t->state = DV_TASK_RUNNING;
	t->ok = -1;
	dv_now(t->started_at, sizeof(t->started_at));
	dv_task_status_write(t);
	dv_task_emit(t, 0, "task_start", "device=%s target=%s levels=%d",
		     t->device, t->target, DV_ADAPT_LEVELS);

	if (dv_sysfs_root(root, sizeof(root), err, sizeof(err)) != 0)
		return dv_task_fail(t, "sysfs_unavailable", "%s", err);
	if (dv_root_is_real_sysfs(root) && geteuid() != 0)
		return dv_task_fail(t, "permission_denied",
				    "写 %s 需要 root，未做任何修改", root);
	if (dv_collect(root, t->device, &f, err, sizeof(err)) != 0)
		return dv_task_fail(t, "device_not_found", "%s", err);
	if (dv_op_node(root, &f) != 0)
		return dv_task_fail(t, "path_error", "解析接口操作节点失败");
	{
		char gcode[48] = "", gmsg[400] = "";

		if (dv_safety_gate(&f, gcode, sizeof(gcode), gmsg,
				   sizeof(gmsg)) != 0)
			return dv_task_fail(t, gcode, "%s", gmsg);
	}
	if (!dv_driver_name_valid(t->target) ||
	    dv_driver_forbidden(t->target))
		return dv_task_fail(t, "driver_forbidden",
				    "目标驱动名非法或层级不对（hub/usb/usbfs 一律禁止）");

	snprintf(t->iface, sizeof(t->iface), "%s", f.iface);
	snprintf(t->sysfs, sizeof(t->sysfs), "%s", root);
	snprintf(t->orig_driver, sizeof(t->orig_driver), "%s", f.driver);
	t->orig_override_present = f.override_present;
	snprintf(t->orig_override, sizeof(t->orig_override), "%s", f.override);

	if (dv_state_dir(state, sizeof(state)) != 0)
		return dv_task_fail(t, "snapshot_failed", "状态目录不可用");
	snprintf(snap.device, sizeof(snap.device), "%s", f.dev);
	snprintf(snap.iface, sizeof(snap.iface), "%s", f.iface);
	snprintf(snap.sysfs, sizeof(snap.sysfs), "%s", root);
	snprintf(snap.driver, sizeof(snap.driver), "%s", f.driver);
	snap.bound = f.driver[0] != '\0';
	snprintf(snap.override, sizeof(snap.override), "%s", f.override);
	snap.override_present = f.override_present;
	if (dv_snap_save(state, &snap, err, sizeof(err)) != 0)
		return dv_task_fail(t, "snapshot_failed",
				    "%s，未做任何修改", err);
	have_snap = 1;
	{
		char text[4096];

		if (dv_snap_render(&snap, text, sizeof(text)) == 0 &&
		    dv_write_file_atomic(t->paths.snap, text, err,
					 sizeof(err)) == 0) {
			snprintf(t->snapshot, sizeof(t->snapshot), "%s",
				 t->paths.snap);
		} else {
			dv_audit("op=adapt_task_snapshot_failed task=%s err=%s",
				 t->id, err);
		}
	}
	dv_task_status_write(t);
	dv_task_emit(t, 0, "snapshot",
		     "path=%s driver=%s override_present=%d",
		     snap.path, snap.driver[0] ? snap.driver : "(未绑定)",
		     snap.override_present);

	for (level = 1; level <= DV_ADAPT_LEVELS; level++) {
		struct dv_level_rec *r;
		int rc;

		if (dv_g_cancel)
			goto canceled;
		t->level = level;
		t->n_lv = level;
		r = &t->lv[level - 1];
		dv_task_emit(t, level, "level_start",
			     "name=%s target=%s orig=%s",
			     dv_adapt_level_name(level), t->target,
			     t->orig_driver[0] ? t->orig_driver : "(未绑定)");
		dv_task_status_write(t);
		rc = dv_adapt_level(level, root, &f, &snap, t, r);
		if (rc < 0)
			goto canceled;
		t->n_lv = level;
		dv_task_emit(t, level, "level_end",
			     "rc=%d errno=%d verify=%d rollback=%d code=%s detail=%s",
			     r->rc, r->err, r->verify,
			     r->rollback_ok ? 1 : 0,
			     r->code[0] ? r->code : "-", r->detail);
		dv_task_status_write(t);
		if (rc > 0) {
			t->state = DV_TASK_DONE;
			t->ok = 1;
			t->changed = 1;
			t->error_code[0] = '\0';
			t->error[0] = '\0';
			dv_now(t->finished_at, sizeof(t->finished_at));
			dv_task_status_write(t);
			dv_task_emit(t, level, "task_end",
				     "status=done level=%d driver=%s", level,
				     r->driver);
			return 0;
		}
	}

	/* 四级全失败：确保回到原驱动，再如实报 failed */
	dv_g_cancel = 0;
	if (have_snap) {
		char drv[DV_MAX_DRIVER] = "";

		dv_read_driver_node(root, f.node, drv, sizeof(drv));
		if (strcmp(drv, snap.driver) != 0) {
			if (dv_ensure_original(root, &f, &snap, rmsg,
					       sizeof(rmsg)) != 0)
				dv_audit("op=adapt_final_restore_failed device=%s msg=%s",
					 t->device, rmsg);
			else
				dv_task_emit(t, DV_ADAPT_LEVELS,
					     "final_restore", "%s", rmsg);
		}
	}
	{
		char detail[600];
		int i;

		detail[0] = '\0';
		for (i = 0; i < t->n_lv; i++) {
			char one[160];

			snprintf(one, sizeof(one),
				 "%sL%d(%s) rc=%d errno=%d %s%s",
				 i ? " / " : "", t->lv[i].level,
				 t->lv[i].name, t->lv[i].rc, t->lv[i].err,
				 t->lv[i].code[0] ? t->lv[i].code : "-",
				 t->lv[i].rollback_ok ? " 已回滚" : "");
			if (strlen(detail) + strlen(one) + 1 >= sizeof(detail))
				break;
			memcpy(detail + strlen(detail), one, strlen(one) + 1);
		}
		return dv_task_fail(t, "all_levels_failed",
				    "四级递进全部失败：%s", detail);
	}

canceled:
	dv_g_cancel = 0;	/* 取消后的收尾必须允许写 */
	t->state = DV_TASK_CANCELED;
	t->ok = 0;
	if (!t->cancel_source[0])
		snprintf(t->cancel_source, sizeof(t->cancel_source), "%s",
			 "signal(SIGTERM/SIGINT)");
	dv_task_emit(t, t->level, "cancel", "收到取消请求：中止当前级别并确保设备回到原驱动");
	if (have_snap) {
		char drv[DV_MAX_DRIVER] = "";

		dv_read_driver_node(root, f.node, drv, sizeof(drv));
		if (strcmp(drv, snap.driver) != 0) {
			if (dv_ensure_original(root, &f, &snap, rmsg,
					       sizeof(rmsg)) == 0)
				dv_task_emit(t, t->level, "cancel_restore",
					     "%s", rmsg);
			else
				dv_task_emit(t, t->level,
					     "cancel_restore_failed", "%s",
					     rmsg);
		} else {
			snprintf(rmsg, sizeof(rmsg),
				 "driver=%s 已是任务开始前的值",
				 drv[0] ? drv : "(未绑定)");
		}
	} else {
		snprintf(rmsg, sizeof(rmsg), "尚未落快照，未做过任何写");
	}
	snprintf(t->error_code, sizeof(t->error_code), "%s", "canceled");
	snprintf(t->error, sizeof(t->error),
		 "任务被取消；%s（恢复说明：%s）",
		 t->cancel_source[0] ? t->cancel_source : "cancel 请求",
		 rmsg);
	dv_now(t->finished_at, sizeof(t->finished_at));
	dv_task_status_write(t);
	dv_task_emit(t, t->level, "task_end", "status=canceled restore=%s",
		     rmsg);
	return -1;
}

/* ------------------------------------------------------------------ */
/* 进程辅助                                                           */
/* ------------------------------------------------------------------ */

static void dv_close_fds_from(int low)
{
	long max = sysconf(_SC_OPEN_MAX);
	int fd;

	if (max < 0 || max > 4096)
		max = 4096;
	for (fd = low; fd < (int)max; fd++)
		close(fd);
}

static pid_t dv_reap_children(void)
{
	int i, j = 0;
	pid_t last = 0;

	for (i = 0; i < dv_g_nchildren; i++) {
		pid_t r = waitpid(dv_g_children[i], NULL, WNOHANG);

		if (r == dv_g_children[i]) {
			last = r;
			continue;
		}
		if (r == 0)
			dv_g_children[j++] = dv_g_children[i];
	}
	dv_g_nchildren = j;
	return last;
}

static void dv_remember_child(pid_t pid)
{
	if (dv_g_nchildren >= DV_REAP_MAX)
		return;
	dv_g_children[dv_g_nchildren++] = pid;
}

static int dv_pid_alive(int pid)
{
	char path[64], buf[512], *rp;
	int fd;
	ssize_t n;

	if (pid <= 0)
		return 0;
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	rp = strrchr(buf, ')');
	if (!rp || rp[1] != ' ')
		return 1;
	return rp[2] != 'Z';
}

/* pid 复用防护：/proc/<pid>/cmdline 必须与本进程一致（同一个 agent 可执行体） */
static int dv_pid_cmdline_match(int pid)
{
	char a[512], b[512], path[64];
	int fd;
	ssize_t na, nb;

	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	na = read(fd, a, sizeof(a) - 1);
	close(fd);
	if (na <= 0)
		return 0;
	a[na] = '\0';
	fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	nb = read(fd, b, sizeof(b) - 1);
	close(fd);
	if (nb <= 0)
		return 0;
	b[nb] = '\0';
	return memcmp(a, b, (size_t)(na < nb ? na : nb)) == 0;
}

/* ------------------------------------------------------------------ */
/* JSON 小工具                                                        */
/* ------------------------------------------------------------------ */

static void dv_emit_tail_lines(struct dvb *b, const char *key, const char *text,
			       int max_lines)
{
	int cap = max_lines > 0 ? max_lines : 1;
	char **ring;
	char *buf;
	char *p;
	int n = 0, i, start;

	ring = calloc((size_t)cap, sizeof(*ring));
	buf = strdup(text ? text : "");
	if (!ring || !buf) {
		free(ring);
		free(buf);
		dvb_json_str(b, key);
		dvb_putc(b, ':');
		dvb_puts(b, "[]");
		dvb_putc(b, ',');
		return;
	}
	for (p = buf; p && *p;) {
		char *eol = strchr(p, '\n');
		size_t l;

		if (eol)
			*eol = '\0';
		l = strlen(p);
		while (l > 0 && p[l - 1] == '\r')
			p[--l] = '\0';
		if (l > 0) {
			free(ring[n % cap]);
			ring[n % cap] = strdup(p);
			n++;
		}
		if (!eol)
			break;
		p = eol + 1;
	}
	dvb_json_str(b, key);
	dvb_putc(b, ':');
	dvb_puts(b, "[");
	start = n > cap ? n - cap : 0;
	for (i = start; i < n; i++) {
		if (i > start)
			dvb_putc(b, ',');
		dvb_json_str(b, ring[i % cap] ? ring[i % cap] : "");
	}
	dvb_puts(b, "]");
	dvb_putc(b, ',');
	for (i = 0; i < cap; i++)
		free(ring[i]);
	free(ring);
	free(buf);
}

/* ------------------------------------------------------------------ */
/* dev_adapt：入口                                                    */
/* ------------------------------------------------------------------ */

static int dv_emit_adapt_accept(char **out, struct dv_task *t, int async,
				int pid)
{
	char *buf = malloc(DV_OUT_LIMIT);
	struct dvb b;
	char *status_text = NULL;
	size_t n = 0;

	if (!buf) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	dvb_init(&b, buf, DV_OUT_LIMIT);
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "schema", DV_ADAPT_SCHEMA);
	dvb_kv_bool(&b, "ok", 1);
	dvb_kv_bool(&b, "accepted", 1);
	dvb_kv_str(&b, "task_id", t->id);
	dvb_kv_str(&b, "device", t->device);
	dvb_kv_str(&b, "iface", t->iface[0] ? t->iface : NULL);
	dvb_kv_str(&b, "target_driver", t->target);
	dvb_kv_int(&b, "levels_total", DV_ADAPT_LEVELS);
	dvb_kv_bool(&b, "async", async);
	dvb_kv_int(&b, "pid", pid);
	dvb_kv_str(&b, "status", dv_state_name(t->state));
	dvb_kv_str(&b, "state_dir", t->paths.dir);
	dvb_kv_str(&b, "status_file", t->paths.status);
	dvb_kv_str(&b, "progress_file", t->paths.progress);
	dvb_kv_str(&b, "daemon_log", t->paths.log);
	dvb_kv_str(&b, "hint",
		   async ? "dev_task action=status 看进度 / action=log 看全量日志 / action=cancel 取消并回滚"
			 : "前台执行完成；task 字段即最终 status.json");
	if (!async) {
		status_text = malloc(DV_TASK_STATUS_BUF);
		if (status_text &&
		    dv_read_file_bounded(t->paths.status, status_text,
					 DV_TASK_STATUS_BUF, &n) == 0 &&
		    n > 2 && status_text[0] == '{') {
			dvb_puts(&b, "\"task\":");
			dvb_puts(&b, status_text);
			dvb_putc(&b, ',');
		}
		free(status_text);
	}
	dvb_kv_str(&b, "levels_planned",
		   "in_tree_new_id,driver_override,generic_driver,param_quirk");
	dvb_kv_bool(&b, "truncated", b.trunc);
	dvb_puts(&b, "\"schema_ok\":true}");
	*out = buf;
	return AI_OK;
}

static int dv_tool_adapt(const char *args, char **out)
{
	char root[DV_PATH_MAX], err[512];
	char gcode[48] = "", gmsg[400] = "";
	char *dev = NULL, *drv = NULL;
	struct dv_facts f;
	struct dv_task t;
	struct dv_task_paths p;
	int rc, foreground = 0, pid = 0;
	const char *val;
	size_t vlen;
	int type;

	*out = NULL;
	memset(&t, 0, sizeof(t));
	memset(&f, 0, sizeof(f));
	memset(&p, 0, sizeof(p));
	dv_reap_children();
	if (ai_json_obj_get(args, strlen(args), "device", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		dev = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "driver", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		drv = ai_json_strdup_str(val, vlen);

	if (!dev || !dev[0]) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "invalid_arg",
				     "缺少 device（如 1-1 或 1-1:1.0）");
	}
	if (!drv || !drv[0]) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "invalid_arg",
				     "缺少 driver（四级递进的目标驱动，如 usbhid）");
	}
	if (!dv_node_name_valid(dev)) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "invalid_arg",
				     "device 不是合法 sysfs 节点名");
	}
	if (!dv_driver_name_valid(drv) || dv_driver_forbidden(drv)) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "driver_forbidden",
				     "driver 名非法或层级不对（hub/usb/usbfs 一律禁止）");
	}
	if (dv_sysfs_root(root, sizeof(root), err, sizeof(err)) != 0) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "sysfs_unavailable",
				     "%s", err);
	}
	if (dv_root_is_real_sysfs(root) && geteuid() != 0) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "permission_denied",
				     "写 %s 需要 root（当前 uid=%lu），未做任何修改",
				     root, (unsigned long)geteuid());
	}
	if (dv_collect(root, dev, &f, err, sizeof(err)) != 0) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "device_not_found",
				     "%s", err);
	}
	if (dv_op_node(root, &f) != 0) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "path_error",
				     "解析接口操作节点失败（路径过长）");
	}
	if (dv_safety_gate(&f, gcode, sizeof(gcode), gmsg, sizeof(gmsg)) != 0) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, gcode, "%s", gmsg);
	}
	/* 安全目标已在上面全部通过，建任务目录 */
	dv_task_gen_id(t.id, sizeof(t.id));
	if (dv_task_paths_open(t.id, &p) != 0) {
		free(dev);
		free(drv);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "task_dir_failed",
				     "任务状态目录不可用（%s）", t.id);
	}
	t.paths = p;
	snprintf(t.device, sizeof(t.device), "%s", f.dev);
	snprintf(t.iface, sizeof(t.iface), "%s", f.iface);
	snprintf(t.sysfs, sizeof(t.sysfs), "%s", root);
	snprintf(t.target, sizeof(t.target), "%s", drv);
	snprintf(t.orig_driver, sizeof(t.orig_driver), "%s", f.driver);
	t.orig_override_present = f.override_present;
	snprintf(t.orig_override, sizeof(t.orig_override), "%s", f.override);
	t.state = DV_TASK_QUEUED;
	t.ok = -1;
	dv_now(t.started_at, sizeof(t.started_at));
	dv_task_status_write(&t);
	dv_task_emit(&t, 0, "task_created", "device=%s target=%s pid=%d",
		     t.device, t.target, (int)getpid());

	foreground = (getenv("AIKERNEL_ADAPT_FOREGROUND") &&
		      getenv("AIKERNEL_ADAPT_FOREGROUND")[0] == '1');
	free(dev);
	free(drv);

	if (foreground) {
		t.foreground = 1;
		t.pid = 0;
		dv_audit("op=dev_adapt mode=foreground task=%s device=%s target=%s",
			 t.id, t.device, t.target);
		(void)dv_adapt_pipeline(&t);
		rc = dv_emit_adapt_accept(out, &t, 0, 0);
		return rc;
	}

	fflush(NULL);
	pid = fork();
	if (pid < 0) {
		snprintf(t.error_code, sizeof(t.error_code), "%s", "fork_failed");
		t.state = DV_TASK_FAILED;
		t.ok = 0;
		dv_task_status_write(&t);
		return dv_error_json(out, DV_ADAPT_SCHEMA, "fork_failed",
				     "fork 后台进程失败: %s", strerror(errno));
	}
	if (pid == 0) {
		int fd, nul;

		/* --- 后台 daemon --- */
		setsid();
		dv_close_fds_from(3);
		nul = open("/dev/null", O_RDONLY | O_CLOEXEC);
		fd = open(t.paths.log, O_WRONLY | O_CREAT | O_APPEND |
			  O_CLOEXEC, 0600);
		if (nul >= 0) {
			dup2(nul, 0);
			close(nul);
		}
		if (fd >= 0) {
			dup2(fd, 1);
			dup2(fd, 2);
			close(fd);
		}
		signal(SIGHUP, SIG_IGN);
		signal(SIGTERM, dv_cancel_handler);
		signal(SIGINT, dv_cancel_handler);
		signal(SIGPIPE, SIG_IGN);
		t.pid = (int)getpid();
		t.foreground = 0;
		(void)dv_adapt_pipeline(&t);
		_exit(0);
	}
	/* --- 父进程：立刻返回 task_id --- */
	{
		char pidbuf[32];

		snprintf(pidbuf, sizeof(pidbuf), "%d\n", pid);
		if (dv_write_file_atomic(t.paths.pid, pidbuf, err,
					 sizeof(err)) != 0)
			dv_audit("op=adapt_pid_write_failed task=%s err=%s",
				 t.id, err);
	}
	dv_remember_child((pid_t)pid);
	dv_audit("op=dev_adapt mode=async task=%s device=%s target=%s pid=%d",
		 t.id, t.device, t.target, pid);
	return dv_emit_adapt_accept(out, &t, 1, pid);
}

/* ------------------------------------------------------------------ */
/* dev_task：status / cancel / log                                    */
/* ------------------------------------------------------------------ */

static int dv_task_resolve(const char *id_arg, char *out, size_t cap)
{
	char id[DV_TASK_ID_MAX];

	out[0] = '\0';
	if (id_arg && id_arg[0]) {
		if (!dv_task_id_valid(id_arg))
			return -1;
		snprintf(out, cap, "%s", id_arg);
		return 0;
	}
	if (dv_task_latest(id, sizeof(id)) != 0)
		return -1;
	snprintf(out, cap, "%s", id);
	return 0;
}

static int dv_task_dir_exists(const char *id)
{
	char root[DV_PATH_MAX], dir[DV_PATH_MAX];

	if (!dv_task_id_valid(id))
		return 0;
	if (dv_tasks_root(root, sizeof(root)) != 0)
		return 0;
	if (dv_join(dir, sizeof(dir), root, id) != 0)
		return 0;
	return dv_dir_exists(dir);
}

static int dv_task_read_status(const char *id, char *buf, size_t cap,
			       size_t *n)
{
	struct dv_task_paths p;

	buf[0] = '\0';
	if (dv_task_paths_open(id, &p) != 0)
		return -1;
	return dv_read_file_bounded(p.status, buf, cap, n);
}

static int dv_task_status_cmd(const char *id_arg, char **out)
{
	char id[DV_TASK_ID_MAX], txt[DV_TASK_STATUS_BUF];
	char pidtxt[64] = "";
	char *plog = NULL;
	struct dv_task_paths p;
	size_t n = 0, pn = 0;
	int pid, alive;
	const char *state = NULL;
	char *buf;
	struct dvb b;

	if (dv_task_resolve(id_arg, id, sizeof(id)) != 0) {
		return dv_error_json(out, DV_TASK_STATUS_SCHEMA,
				     "task_not_found",
				     "没有可用的适配任务（先 dev_adapt）");
	}
	if (!dv_task_dir_exists(id)) {
		return dv_error_json(out, DV_TASK_STATUS_SCHEMA,
				     "task_not_found",
				     "任务 %s 不存在（先 dev_adapt）", id);
	}
	if (dv_task_read_status(id, txt, sizeof(txt), &n) != 0 ||
	    n < 3 || txt[0] != '{') {
		return dv_error_json(out, DV_TASK_STATUS_SCHEMA,
				     "status_unreadable",
				     "任务 %s 的 status.json 不存在或损坏", id);
	}
	if (dv_task_paths_open(id, &p) != 0) {
		return dv_error_json(out, DV_TASK_STATUS_SCHEMA,
				     "task_not_found",
				     "任务 %s 目录不可用", id);
	}
	pid = (int)dv_json_get_int(txt, n, "pid", 0);
	if (pid <= 0 && dv_read_file_bounded(p.pid, pidtxt,
					     sizeof(pidtxt), NULL) == 0)
		pid = atoi(pidtxt);
	alive = dv_pid_alive(pid) && dv_pid_cmdline_match(pid);
	{
		static char st[32];

		if (dv_json_get_str(txt, n, "status", st, sizeof(st)) == 0)
			state = st;
	}
	plog = calloc(1, DV_TASK_LOG_MAX);
	if (plog)
		dv_read_file_bounded(p.progress, plog, DV_TASK_LOG_MAX, &pn);
	buf = malloc(DV_OUT_LIMIT);
	if (!buf) {
		free(plog);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	dvb_init(&b, buf, DV_OUT_LIMIT);
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "schema", DV_TASK_STATUS_SCHEMA);
	dvb_kv_bool(&b, "ok", 1);
	dvb_kv_str(&b, "action", "status");
	dvb_kv_str(&b, "task_id", id);
	dvb_kv_str(&b, "state_dir", p.dir);
	dvb_kv_str(&b, "status", state ? state : "unknown");
	dvb_kv_int(&b, "pid", pid);
	dvb_kv_bool(&b, "process_alive", alive);
	dvb_kv_bool(&b, "stale",
		    (state && strcmp(state, "running") == 0 && !alive) ||
		    (state && strcmp(state, "queued") == 0 && !alive));
	dvb_kv_int(&b, "level", (long long)dv_json_get_int(txt, n, "level", 0));
	dvb_kv_int(&b, "levels_total",
		   (long long)dv_json_get_int(txt, n, "levels_total",
					      DV_ADAPT_LEVELS));
	dvb_puts(&b, "\"task\":");
	dvb_puts(&b, txt);
	dvb_putc(&b, ',');
	dv_emit_tail_lines(&b, "progress_tail", plog ? plog : "",
			   DV_TASK_TAIL_LINES);
	free(plog);
	{
		char *logbuf = malloc(DV_TASK_LOG_MAX);

		if (logbuf) {
			dv_read_file_bounded(p.log, logbuf, DV_TASK_LOG_MAX,
					     NULL);
			dv_emit_tail_lines(&b, "daemon_tail", logbuf,
					   DV_TASK_TAIL_LINES);
			free(logbuf);
		} else {
			dvb_puts(&b, "\"daemon_tail\":[],");
		}
	}
	dvb_kv_str(&b, "hint",
		   "action=cancel 取消并回滚；action=log 取全量日志");
	dvb_kv_bool(&b, "truncated", b.trunc);
	dvb_puts(&b, "\"schema_ok\":true}");
	*out = buf;
	return AI_OK;
}

static int dv_task_log_cmd(const char *id_arg, char **out)
{
	char id[DV_TASK_ID_MAX], *prog = NULL, *log = NULL;
	struct dv_task_paths p;
	size_t pn = 0, ln = 0;
	char *buf;
	struct dvb b;
	int fd;
	ssize_t r;
	size_t off;

	if (dv_task_resolve(id_arg, id, sizeof(id)) != 0)
		return dv_error_json(out, DV_TASK_LOG_SCHEMA, "task_not_found",
				     "没有可用的适配任务（先 dev_adapt）");
	if (!dv_task_dir_exists(id) || dv_task_paths_open(id, &p) != 0)
		return dv_error_json(out, DV_TASK_LOG_SCHEMA, "task_not_found",
				     "任务 %s 不存在（先 dev_adapt）", id);
	prog = calloc(1, DV_TASK_LOG_MAX + 1);
	log = calloc(1, DV_TASK_LOG_MAX + 1);
	if (!prog || !log) {
		free(prog);
		free(log);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	/* 全量（有界）读：超限时保留尾部 */
	fd = open(p.progress, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		off = 0;
		while (off < DV_TASK_LOG_MAX &&
		       (r = read(fd, prog + off, DV_TASK_LOG_MAX - off)) > 0)
			off += (size_t)r;
		prog[off] = '\0';
		pn = off;
		close(fd);
	}
	fd = open(p.log, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		off = 0;
		while (off < DV_TASK_LOG_MAX &&
		       (r = read(fd, log + off, DV_TASK_LOG_MAX - off)) > 0)
			off += (size_t)r;
		log[off] = '\0';
		ln = off;
		close(fd);
	}
	buf = malloc(DV_OUT_LIMIT);
	if (!buf) {
		free(prog);
		free(log);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	dvb_init(&b, buf, DV_OUT_LIMIT);
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "schema", DV_TASK_LOG_SCHEMA);
	dvb_kv_bool(&b, "ok", 1);
	dvb_kv_str(&b, "action", "log");
	dvb_kv_str(&b, "task_id", id);
	dvb_kv_str(&b, "state_dir", p.dir);
	dvb_kv_int(&b, "progress_bytes", (long long)pn);
	dvb_kv_int(&b, "daemon_log_bytes", (long long)ln);
	dvb_puts(&b, "\"progress\":[");
	{
		char *nl = prog;
		int first = 1;

		while (nl && *nl) {
			char *eol = strchr(nl, '\n');
			size_t l = eol ? (size_t)(eol - nl) : strlen(nl);

			if (l > 0) {
				char one[2048];

				snprintf(one, sizeof(one), "%.*s", (int)l, nl);
				if (!first)
					dvb_putc(&b, ',');
				dvb_json_str(&b, one);
				first = 0;
			}
			if (!eol)
				break;
			nl = eol + 1;
		}
	}
	dvb_puts(&b, "],");
	dvb_kv_str(&b, "daemon_log", log);
	dvb_kv_bool(&b, "truncated",
		    b.trunc || pn >= DV_TASK_LOG_MAX || ln >= DV_TASK_LOG_MAX);
	dvb_puts(&b, "\"schema_ok\":true}");
	*out = buf;
	free(prog);
	free(log);
	return AI_OK;
}

static int dv_task_cancel_cmd(const char *id_arg, const char *why, char **out)
{
	char id[DV_TASK_ID_MAX], txt[DV_TASK_STATUS_BUF];
	char pidtxt[64] = "";
	struct dv_task_paths p;
	struct dv_snap snap;
	char snap_err[256] = "";
	size_t n = 0;
	int pid = 0, alive = 0, ours = 0, sig = 0, killed = 0;
	int have_snap = 0, restored = -1, i, terminal_before = 0;
	char restore_msg[512] = "";
	char state_buf[32] = "";
	const char *state = state_buf;
	char *buf;
	struct dvb b;

	if (dv_task_resolve(id_arg, id, sizeof(id)) != 0)
		return dv_error_json(out, DV_TASK_STATUS_SCHEMA, "task_not_found",
				     "没有可用的适配任务（先 dev_adapt）");
	if (!dv_task_dir_exists(id))
		return dv_error_json(out, DV_TASK_STATUS_SCHEMA, "task_not_found",
				     "任务 %s 不存在（先 dev_adapt）", id);
	if (dv_task_read_status(id, txt, sizeof(txt), &n) != 0 ||
	    n < 3 || txt[0] != '{')
		return dv_error_json(out, DV_TASK_STATUS_SCHEMA,
				     "status_unreadable",
				     "任务 %s 的 status.json 不存在或损坏", id);
	if (!dv_task_dir_exists(id) || dv_task_paths_open(id, &p) != 0)
		return dv_error_json(out, DV_TASK_STATUS_SCHEMA,
				     "task_not_found",
				     "任务 %s 不存在（先 dev_adapt）", id);
	(void)dv_json_get_str(txt, n, "status", state_buf,
			      sizeof(state_buf));
	pid = (int)dv_json_get_int(txt, n, "pid", 0);
	if (pid <= 0 && dv_read_file_bounded(p.pid, pidtxt,
					     sizeof(pidtxt), NULL) == 0)
		pid = atoi(pidtxt);
	alive = dv_pid_alive(pid);
	ours = alive && dv_pid_cmdline_match(pid);
	terminal_before = state && dv_task_state_terminal(state);
	memset(&snap, 0, sizeof(snap));
	if (dv_snap_load_path(p.snap, &snap, snap_err, sizeof(snap_err)) == 0)
		have_snap = 1;

	/* 已完成且成功：不杀、不回滚（成功结果要保留） */
	if (state && strcmp(state, "done") == 0 &&
	    dv_json_get_int(txt, n, "ok", 0) == 1) {
		buf = malloc(8192);
		if (!buf) {
			*out = strdup("ERROR: 内存不足");
			return AI_ERR_MEMORY;
		}
		dvb_init(&b, buf, 8192);
		dvb_puts(&b, "{");
		dvb_kv_str(&b, "schema", DV_TASK_STATUS_SCHEMA);
		dvb_kv_bool(&b, "ok", 1);
		dvb_kv_str(&b, "action", "cancel");
		dvb_kv_str(&b, "task_id", id);
		dvb_kv_str(&b, "status", "done");
		dvb_kv_bool(&b, "canceled", 0);
		dvb_kv_str(&b, "note",
			   "任务已成功完成，cancel 不回滚成功结果（如需还原请用 dev_restore）");
		dvb_kv_bool(&b, "truncated", b.trunc);
		dvb_puts(&b, "\"schema_ok\":true}");
		*out = buf;
		return AI_OK;
	}

	if (ours) {
		kill(pid, SIGTERM);
		sig = SIGTERM;
		for (i = 0; i < 60; i++) {
			if (!dv_pid_alive(pid))
				break;
			{
				struct timespec ts;

				ts.tv_sec = 0;
				ts.tv_nsec = 100 * 1000 * 1000;
				nanosleep(&ts, NULL);
			}
		}
		if (dv_pid_alive(pid)) {
			kill(pid, SIGKILL);
			sig = SIGKILL;
			killed = 1;
			for (i = 0; i < 30; i++) {
				if (!dv_pid_alive(pid))
					break;
				{
					struct timespec ts;

					ts.tv_sec = 0;
					ts.tv_nsec = 100 * 1000 * 1000;
					nanosleep(&ts, NULL);
				}
			}
		}
		(void)waitpid(pid, NULL, WNOHANG);
	}

	/* 读回：必须回到任务开始前的驱动 */
	if (have_snap) {
		char root[DV_PATH_MAX], err[256];
		struct dv_facts f;

		memset(&f, 0, sizeof(f));
		if (dv_sysfs_root(root, sizeof(root), err, sizeof(err)) == 0 &&
		    dv_collect(root, snap.device, &f, err, sizeof(err)) == 0 &&
		    dv_op_node(root, &f) == 0) {
			char now[DV_MAX_DRIVER] = "";

			dv_read_driver_node(root, f.node, now, sizeof(now));
			if (strcmp(now, snap.driver) == 0) {
				restored = 1;
				snprintf(restore_msg, sizeof(restore_msg),
					 "driver=%s 已是任务开始前的值（无需回滚）",
					 now[0] ? now : "(未绑定)");
			} else {
				dv_g_cancel = 0;
				restored = (dv_ensure_original(root, &f, &snap,
							       restore_msg,
							       sizeof(restore_msg)) == 0);
			}
		} else {
			snprintf(restore_msg, sizeof(restore_msg),
				 "sysfs 不可用/设备已消失，无法校验");
			restored = -1;
		}
	} else {
		snprintf(restore_msg, sizeof(restore_msg),
			 "没有任务快照（%s），无法回滚",
			 snap_err[0] ? snap_err : "snapshot.json 缺失");
	}

	/* 若 daemon 自己没来得及写 canceled（SIGKILL 兜底），由 cancel 侧补写
	 * 一份显式 canceled 状态；原 status.json 原文另存 status.before-cancel.json
	 * （SIGKILL 路径拿不到完整 levels[]，不假装有）。 */
	if (!terminal_before) {
		struct dv_task t;
		char st2[32] = "";
		size_t n2 = 0;
		int daemon_wrote = 0;

		/* daemon 可能已自己写了 canceled（带完整 started_at/levels）：
		 * 先重读，有就保留，不覆盖更完整的状态。 */
		if (dv_task_read_status(id, txt, sizeof(txt), &n2) == 0 &&
		    n2 > 3 &&
		    dv_json_get_str(txt, n2, "status", st2, sizeof(st2)) == 0 &&
		    strcmp(st2, "canceled") == 0)
			daemon_wrote = 1;
		if (daemon_wrote) {
			n = n2;
			goto cancel_status_done;
		}
		char target[64] = "";
		char iface[DV_NAME_MAX] = "";
		char device[DV_NAME_MAX] = "";

		if (dv_task_read_status(id, txt, sizeof(txt), &n) != 0 ||
		    n < 3 || txt[0] != '{')
			txt[0] = '\0';
		{
			if (txt[0])
				(void)dv_json_get_str(txt, n, "target_driver",
						      target, sizeof(target));
			if (have_snap) {
				snprintf(iface, sizeof(iface), "%s", snap.iface);
				snprintf(device, sizeof(device), "%s",
					 snap.device);
			}
		}
		memset(&t, 0, sizeof(t));
		t.paths = p;
		snprintf(t.id, sizeof(t.id), "%s", id);
		snprintf(t.device, sizeof(t.device), "%s", device);
		snprintf(t.iface, sizeof(t.iface), "%s", iface);
		snprintf(t.sysfs, sizeof(t.sysfs), "%s",
			 have_snap ? snap.sysfs : "");
		snprintf(t.target, sizeof(t.target), "%s", target);
		snprintf(t.orig_driver, sizeof(t.orig_driver), "%s",
			 have_snap ? snap.driver : "");
		t.state = DV_TASK_CANCELED;
		t.ok = 0;
		t.pid = pid;
		t.level = (int)dv_json_get_int(txt[0] ? txt : "{}",
					       txt[0] ? n : 2, "level", 0);
		snprintf(t.cancel_source, sizeof(t.cancel_source), "%s",
			 "dev_task/cancel");
		snprintf(t.error_code, sizeof(t.error_code), "%s", "canceled");
		snprintf(t.error, sizeof(t.error),
			 "由 dev_task action=cancel 终止（signal=%s）；%s；"
			 "原状态原文见 %s/status.before-cancel.json",
			 killed ? "SIGKILL" : "SIGTERM", restore_msg, p.dir);
		if (txt[0]) {
			char bak[DV_PATH_MAX];
			char werr[256];

			if (dv_join(bak, sizeof(bak), p.dir,
				    "status.before-cancel.json") == 0)
				(void)dv_write_file_atomic(bak, txt, werr,
							   sizeof(werr));
		}
		dv_now(t.finished_at, sizeof(t.finished_at));
		dv_task_status_write(&t);
		dv_task_emit(&t, t.level, "cancel_by_task",
			     "signal=%s restored=%d msg=%s",
			     killed ? "SIGKILL" : "SIGTERM", restored,
			     restore_msg);
	}
cancel_status_done:

	buf = malloc(DV_OUT_LIMIT);
	if (!buf) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	dvb_init(&b, buf, DV_OUT_LIMIT);
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "schema", DV_TASK_STATUS_SCHEMA);
	dvb_kv_bool(&b, "ok", 1);
	dvb_kv_str(&b, "action", "cancel");
	dvb_kv_str(&b, "task_id", id);
	dvb_kv_str(&b, "status",
		   (terminal_before && state &&
		    strcmp(state, "canceled") != 0) ? state : "canceled");
	dvb_kv_bool(&b, "canceled",
		    terminal_before && state && strcmp(state, "canceled") != 0
			    ? 0 : 1);
	dvb_kv_bool(&b, "already_terminal", terminal_before);
	dvb_kv_int(&b, "pid", pid);
	dvb_kv_bool(&b, "was_alive", alive);
	dvb_kv_bool(&b, "pid_owned", ours);
	dvb_kv_str(&b, "signal",
		   sig == SIGKILL ? "SIGKILL" : (sig == SIGTERM ? "SIGTERM" : NULL));
	dvb_kv_bool(&b, "process_gone", !dv_pid_alive(pid) || pid <= 0);
	dvb_kv_bool(&b, "had_snapshot", have_snap);
	dvb_kv_bool(&b, "restored_ok", restored == 1);
	dvb_kv_str(&b, "restore_message", restore_msg);
	if (have_snap) {
		char now[DV_MAX_DRIVER] = "";

		dv_read_driver_node(snap.sysfs, snap.iface, now, sizeof(now));
		dvb_kv_str(&b, "orig_driver",
			   snap.driver[0] ? snap.driver : NULL);
		dvb_kv_str(&b, "current_driver", now[0] ? now : NULL);
	}
	dvb_kv_str(&b, "reason", why && why[0] ? why : "cancel");
	dvb_kv_bool(&b, "truncated", b.trunc);
	dvb_puts(&b, "\"schema_ok\":true}");
	*out = buf;
	return AI_OK;
}

static int dv_tool_task(const char *args, char **out)
{
	char *action = NULL, *id = NULL, *why = NULL;
	const char *val;
	size_t vlen;
	int type, rc;

	*out = NULL;
	dv_reap_children();
	if (ai_json_obj_get(args, strlen(args), "action", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		action = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "task_id", &val, &vlen,
			    &type) == 1 && type == AI_JSON_STR)
		id = ai_json_strdup_str(val, vlen);
	if (ai_json_obj_get(args, strlen(args), "reason", &val, &vlen, &type) == 1
	    && type == AI_JSON_STR)
		why = ai_json_strdup_str(val, vlen);
	if (!action)
		action = strdup("status");
	if (!action || !action[0]) {
		rc = dv_error_json(out, DV_TASK_STATUS_SCHEMA, "invalid_arg",
				   "action 只允许 status / cancel / log");
		goto out;
	}
	if (strcmp(action, "status") == 0)
		rc = dv_task_status_cmd(id, out);
	else if (strcmp(action, "cancel") == 0)
		rc = dv_task_cancel_cmd(id, why, out);
	else if (strcmp(action, "log") == 0)
		rc = dv_task_log_cmd(id, out);
	else
		rc = dv_error_json(out, DV_TASK_STATUS_SCHEMA, "invalid_arg",
				   "action 只允许 status / cancel / log（收到 %s）",
				   action);
out:
	free(action);
	free(id);
	free(why);
	return rc;
}


/* ======================================================================
 * 6) 通道入口
 * ====================================================================== */

int exec_device_channel(const void *tool_v, const char *args_json, char **out)
{
	const struct ai_tool *tool = tool_v;

	*out = NULL;
	if (!tool || !tool->name || !args_json) {
		*out = strdup("ERROR: device 调用参数为空");
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(tool->name, "dev_list") == 0)
		return dv_tool_list(args_json, out);
	if (strcmp(tool->name, "dev_identify") == 0)
		return dv_tool_identify(args_json, out);
	if (strcmp(tool->name, "dev_bind") == 0)
		return dv_tool_bind(args_json, out);
	if (strcmp(tool->name, "dev_restore") == 0)
		return dv_tool_restore(args_json, out);
	if (strcmp(tool->name, "dev_adapt") == 0)
		return dv_tool_adapt(args_json, out);
	if (strcmp(tool->name, "dev_task") == 0)
		return dv_tool_task(args_json, out);
	*out = strdup("ERROR: 未知 device 工具（注册表异常）");
	return AI_ERR_INVALID_ARG;
}
