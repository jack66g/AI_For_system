// SPDX-License-Identifier: GPL-2.0
/*
 * device_tools.c - W82 V5.1/V5.2 设备身份 + 绑定控制面（USB 先行）
 *
 * 设计说明见 device_tools.h。本文件分六段：
 *   1) 有界输出缓冲 / JSON 转义 / 内置最小 ids 表 / 纯判定函数
 *   2) sysfs 只读原语（读属性、读 driver 软链、列目录、状态目录、审计）
 *   3) 设备事实收集（设备 + 接口 + hub 判定 + 绑定安全规则）
 *   4) dev_list / dev_identify（只读）
 *   5) 快照（落盘 + 读回）与 dev_bind / dev_restore（写 /sys + 回滚）
 *   6) 通道入口
 *
 * 关键不变量：
 *   - 任何 /sys 写之前 dv_snap_save() 必须已成功（ctx->snapshot_ready）；
 *     dv_ctx_write() 在无快照时直接拒绝并审计（不写）。
 *   - 每次写都进 writes[] 与 audit.log（路径、值、rc、errno）。
 *   - 失败回滚后必须读回校验；校验不通过时结果里 rollback.ok=false 且
 *     error_code 保持失败原因，绝不把回滚失败粉饰成成功。
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
#include <sys/stat.h>
#include <sys/types.h>

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

static int dv_snap_save(const char *state, struct dv_snap *s, char *err,
			size_t errcap)
{
	char buf[4096];
	struct dvb b;

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
	dvb_init(&b, buf, sizeof(buf));
	dvb_puts(&b, "{");
	dvb_kv_str(&b, "schema", s->schema);
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
	if (b.trunc) {
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

static int dv_snap_load(const char *state, const char *device,
			struct dv_snap *s, char *err, size_t errcap)
{
	char path[DV_PATH_MAX], content[DV_SNAP_FILE_MAX];
	ssize_t n;
	int fd;

	if (dv_snap_path(state, device, path, sizeof(path)) != 0) {
		if (err)
			snprintf(err, errcap, "快照路径非法");
		return -1;
	}
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (err)
			snprintf(err, errcap, "没有 %s 的快照（%s）", device,
				 path);
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
	*out = strdup("ERROR: 未知 device 工具（注册表异常）");
	return AI_ERR_INVALID_ARG;
}
