// SPDX-License-Identifier: GPL-2.0
/*
 * ai_virtio.c - VirtIO AI 设备类型注册框架（Prompt 10，重构计划 模块12 任务 12.5）
 *
 * 目标：VM 间 AI 通信通道（AI Device Type）。
 * 本步只建注册框架：
 *   - 注册一个 virtio_driver（名字 "ai-virtio"），id_table 匹配本地私有设备 ID
 *     0x2080（VirtIO 规范 64~127 保留给实验扩展，0x2080 为 AIKernel 私有段，
 *     不占用内核 include/uapi/linux/virtio_ids.h 的已分配 ID）；
 *   - probe/remove 空实现：真实设备出现前不分配任何资源；
 *   - 通信协议（请求/响应 VQ、AI 推理透传）由后续 Prompt 填充。
 *
 * 可插拔注册：CONFIG_AIKERNEL_VIRT=n 时本文件不构建 → 驱动不注册 → 零影响。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "ai_virt.h"

/* AIKernel 私有 VirtIO 设备 ID（规范保留段之外的自定义实验段） */
#define AI_VIRTIO_DEVICE_ID	0x2080

static struct virtio_device_id ai_virtio_id_table[] = {
	{ AI_VIRTIO_DEVICE_ID, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static int ai_virtio_probe(struct virtio_device *vdev)
{
	/* 注册框架：AI 通信 VQ 与推理通道协议待后续 Prompt 填充 */
	return 0;
}

static void ai_virtio_remove(struct virtio_device *vdev)
{
}

static struct virtio_driver ai_virtio_driver = {
	.feature_table		= NULL,
	.feature_table_size	= 0,
	.driver.name		= "ai-virtio",
	.driver.owner		= THIS_MODULE,
	.id_table		= ai_virtio_id_table,
	.probe			= ai_virtio_probe,
	.remove			= ai_virtio_remove,
};

module_virtio_driver(ai_virtio_driver);
MODULE_DESCRIPTION("AIKernel VirtIO AI device type (VM-to-VM AI communication channel)");
MODULE_LICENSE("GPL");
