/* SPDX-License-Identifier: GPL-2.0 */
/*
 * workspace_tools.h - W79 持久工作区（workspace 通道，六件工具）
 *
 * "一个文件就是一个盘"：工作区 = 宿主稀疏镜像
 *   /var/lib/aikernel/ws/<name>.img
 * 经 loop 挂 ext4，在 aik-sandbox 的私有 mount/pid/uts namespace 里挂成
 * 根；数据跨 run 持久。默认 tmpfs 沙盒行为不变（sandbox_* 四件零回归）。
 *
 * 工具：
 *   workspace_create   (W1) 建镜像/接 loop/mkfs/根骨架/落元数据
 *   workspace_list     (R)  列工作区（name/backing/size/used/created/status）
 *   workspace_inspect  (R)  详情（镜像/loop/挂载点/cgroup/限额/标签/拓扑）
 *   workspace_run      (W2) 在工作区内跑一条命令（隔离根 = 那个镜像）
 *   workspace_destroy  (W1) 幂等：卸挂载/解 loop/删镜像/删元数据
 *   workspace_quota    (W1) 查看/扩容（v0 只扩不缩）
 *
 * 校验：name 只允许 [A-Za-z0-9_.-]{1,32}（拒绝点开头与 ".."），
 * size 16-8192 MB；ro/rw 路径必须是绝对路径且不得覆盖系统关键面。
 */
#ifndef _AI_WORKSPACE_TOOLS_H
#define _AI_WORKSPACE_TOOLS_H

#include <stddef.h>

/* 纯函数（导出供单测；不触碰文件系统） */
int ai_ws_valid_name(const char *s);
int ai_ws_valid_size_mb(long long mb);
int ai_ws_valid_label(const char *s);

/* 执行器入口（executor.c 的 TOOL_CH_WORKSPACE 分发调用） */
int exec_workspace_channel(const void *tool, const char *args_json,
			   char **out);

#endif /* _AI_WORKSPACE_TOOLS_H */
