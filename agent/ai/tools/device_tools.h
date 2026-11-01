/* SPDX-License-Identifier: GPL-2.0 */
/*
 * device_tools.h - W82 V5.1/V5.2 设备身份 + 绑定控制面（USB 先行，TOOL_CH_DEVICE）
 *
 * 本通道只做 USB，回答两件事：
 *   1. 「这台机器上有什么 USB 设备、它是什么」——dev_list / dev_identify；
 *   2. 「怎么把某个接口绑到指定驱动、失败怎么恢复」——dev_bind / dev_restore。
 *
 * 四件工具：
 *   dev_list     （R/D0）枚举 /sys/bus/usb/devices 全部节点（设备 + 接口），
 *                给出 idVendor:idProduct、modalias、class、driver、
 *                driver_override、is_hub 与接口清单。
 *   dev_identify （R/D0）类别推断（hub/hid/storage/net/audio/other）+ 人话
 *                名称：内置最小 ids 表 + sysfs product/manufacturer 真读；
 *                认不出就报 confidence=unknown，绝不瞎猜。
 *   dev_bind     （W2/D3）把接口绑到指定驱动：mode=override（写
 *                driver_override + bind）、new_id（写 new_id [+ bind]）、
 *                bind（直接 bind，要求 modalias 已匹配）；action=unbind
 *                撤销当前驱动（同样先快照）。任何写之前先落快照，写后读回，
 *                失败自动回滚到原驱动/原 driver_override 并逐项校验。
 *   dev_restore  （W2/D2）按快照恢复原驱动与 driver_override（可显式传
 *                snapshot，或读状态目录里最近一次快照）。
 *
 * 安全边界（硬约束，代码里逐条拒绝）：
 *   - 只允许操作「非 hub 且只有单接口」的设备；根 hub（usbN）、bDeviceClass=9
 *     的设备、任何 class=9 的接口、hub 驱动一律拒绝（动了会连带掉其他设备）。
 *   - 拒绝把接口绑到 hub / usb / usbfs 这类层级不对的驱动。
 *   - 写真实 /sys 必须有 root；没有 root 直接拒绝，不做任何写。
 *   - 每次写 /sys 之前必须已把快照落盘（没有快照就不写）；写后必读回；
 *     任一步失败先恢复再报错，恢复读回不一致时在结果里显式标红。
 *   - 不碰 PCI、不改内核、不重启、不装包；状态只写
 *     /run/aik-device（root）或 /tmp/aik-device-<uid>（非 root）。
 *
 * 测试缝：AIKERNEL_USB_SYSFS_ROOT 可把 sysfs 根指到临时假树（默认
 * /sys/bus/usb）。只有该根不在 /sys 下时非 root 才允许写——真实 /sys 仍
 * 需要 root；这个开关只用于单测，不改变生产路径。
 */
#ifndef _AI_DEVICE_TOOLS_H
#define _AI_DEVICE_TOOLS_H

#include <stddef.h>

#define DV_PATH_MAX		4096
#define DV_NAME_MAX		96
#define DV_MAX_IFACES		16
#define DV_MAX_WRITES		24
#define DV_MAX_DRIVER		64
#define DV_MAX_OVERRIDE		256
#define DV_MAX_NEWID		96
#define DV_OUT_LIMIT		(192 * 1024)
#define DV_SNAP_FILE_MAX	(16 * 1024)

/* 执行器入口（tools.json 中 channel=device 的四件工具）。 */
int exec_device_channel(const void *tool, const char *args_json, char **out);

/* ------------------------------------------------------------------ */
/* 纯函数（单测直接调用；零 IO / 零副作用）                            */
/* ------------------------------------------------------------------ */

/* sysfs 节点名是否安全：非空、<=95 字节、仅 [A-Za-z0-9._:-]、不以 '.' 开头、
 * 不含 ".."。返回 1 合法；0 拒绝。 */
int dv_node_name_valid(const char *name);

/* 是否根 hub 设备名（usb0、usb1、usb12 …）。 */
int dv_is_root_hub_name(const char *name);

/* 类别推断：dev_class 为设备 bDeviceClass（-1 未知），iface_classes 为
 * 各接口 bInterfaceClass。返回静态字符串 "hub"/"hid"/"storage"/"net"/
 * "audio"/"other"（绝不返回 NULL）。多接口且类别不一致 → "other"；
 * 任一接口 class=9 → "hub"（hub 优先，绝不把 hub 误判成别的）。 */
const char *dv_classify_classes(int dev_class, const int *iface_classes,
				int n_ifaces);

/* 内置最小 ids 表：命中返回静态字符串；未命中返回 NULL（不猜）。 */
const char *dv_vendor_name(const char *vid);
const char *dv_product_name(const char *vid, const char *pid);

/* 驱动名合法性：非空、<=63 字节、仅 [A-Za-z0-9._-]、不含 ".."。 */
int dv_driver_name_valid(const char *drv);

/* 层级不对/危险的目标驱动：hub（class 9 驱动）、usb/usbfs（设备级驱动）。
 * 返回 1 表示禁止绑定。 */
int dv_driver_forbidden(const char *drv);

/* 绑定模式：override / new_id / bind。返回 1 合法。 */
int dv_mode_valid(const char *mode);

/* 类别中文名（静态字符串，未知返回 "其他/未分类"）。 */
const char *dv_class_cn(const char *cls);

#endif /* _AI_DEVICE_TOOLS_H */
