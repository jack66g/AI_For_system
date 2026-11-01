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
 *   workspace_net_allow  (W2) 增删工作区网络白名单（net=veth）
 *   workspace_net_status (R)  veth/地址/规则/计数的只读视图
 *
 * 校验：name 只允许 [A-Za-z0-9_.-]{1,32}（拒绝点开头与 ".."），
 * size 16-8192 MB；ro/rw 路径必须是绝对路径且不得覆盖系统关键面。
 */
#ifndef _AI_WORKSPACE_TOOLS_H
#define _AI_WORKSPACE_TOOLS_H

#include <stddef.h>
#include <signal.h>

/* 纯函数（导出供单测；不触碰文件系统） */
int ai_ws_valid_name(const char *s);
int ai_ws_valid_size_mb(long long mb);
int ai_ws_valid_label(const char *s);

/*
 * W81d：工作区网络（net=veth）的纯函数入口。
 * ai_ws_valid_allow 校验/归一化一条白名单（dst=IPv4/IPv6 或 CIDR；
 *   port 0-65535（0=任意）；proto=tcp|udp|icmp|any，NULL 时按 port 推导：
 *   有 port 视为 tcp，无 port 视为 any）。
 * ai_ws_net_names 派生 netns 名（aikws-<name>）、nft 表名（aik_ws_<name>）
 *   与两侧 veth 名（aikv<hash> / aikc<hash>，满足 IFNAMSIZ=16）。
 */
int ai_ws_valid_allow(const char *dst, int port, const char *proto);
void ai_ws_net_names(const char *name, char *ns, size_t ns_cap,
		     char *tbl, size_t tbl_cap, char *host_if, size_t h_cap,
		     char *ws_if, size_t w_cap);

/* 执行器入口（executor.c 的 TOOL_CH_WORKSPACE 分发调用） */
int exec_workspace_channel(const void *tool, const char *args_json,
			   char **out);

/*
 * W81c：应用画像动态画像复用入口（复用 workspace 的隔离执行，不新起
 * 一套 mount/namespace 组装逻辑）。
 *
 * ai_ws_ensure  工作区不存在则以 tmpfs 后端创建（size_mb ≤0 取 64），
 *               存在则直接复用；created 出参 1=本次新建。
 * ai_ws_meta_net 读元数据：net_none/backing（不触碰进程）。
 * ai_ws_destroy 幂等删除（薄封装 workspace_destroy 实现）。
 * ai_ws_run_argv 在工作区内执行 argv（不经 shell 拼接参数）；
 *               timeout 秒到即 SIGKILL 进程组；tail_out 为尾部输出，
 *               exit_code/timed_out/truncated 出参；返回 AI_OK 表示
 *               已执行（即使子进程退出码非 0），失败时 err_out 说明。
 */
int ai_ws_ensure(const char *name, int net_none, long long size_mb,
		 char **out, int *created);
int ai_ws_meta_net(const char *name, int *net_none, char *backing,
		   size_t cap);
int ai_ws_destroy(const char *name, char **out);
int ai_ws_run_argv(const char *name, char *const argv[], int argc,
		   int timeout_s, char **tail_out, int *exit_code,
		   int *timed_out, int *truncated, char **err_out);

/*
 * W82e（V1.8）：sandbox 通道的隔离区 = workspace 的一个 backend。
 *
 * 隔离区（zone）不再是第二套生命周期：它只是 backing=tmpfs 的 workspace。
 * 元数据（<workspace 根>/<name>.meta）、cgroup 路径、产物目录 B-109
 * 清理、销毁路径全部由 workspace 工具统一管理；aik-sandbox 只作为
 * tmpfs 根 + pivot_root 的执行后端。下面五个入口是 sandbox_* 四个工具
 * 的薄适配面——只做「参数翻译 + 委托」，不复制任何生命周期逻辑。
 *
 * ai_ws_zone_name    zone 名 → workspace 名（≤32 且合法时同名；33-64 字符
 *                    的旧名映射为 "<前 23 字符>-<fnv32:08x>"，并在元数据
 *                    记 alias，保证历史 64 字符区名仍可用）。返回 1=合法。
 * ai_ws_zone_create  以 backing=tmpfs 建区（net=host，与 W42 默认一致）；
 *                    名字已被 backing=disk 工作区占用时拒绝（不误伤持久盘）。
 * ai_ws_zone_destroy 唯一销毁路径（委托 ws_destroy_impl）；backing=disk
 *                    的同名工作区拒绝删除，避免 sandbox_destroy 误删持久数据。
 * ai_ws_zone_status  统一状态视图：tmpfs 后端的区表（来自 workspace 元数据）
 *                    + aik-sandbox status 原文（存活 pid/挂载）。
 * ai_ws_zone_run     在区内执行 argv：有元数据时按元数据下发 backing/限额/
 *                    net；无元数据时按 aik-sandbox run 的临时区语义执行。
 *                    cancel_flag 非空时轮询该标志并 SIGKILL 全组。
 */
int ai_ws_zone_name(const char *zone, char *ws, size_t cap);
int ai_ws_zone_create(const char *zone, char **out);
int ai_ws_zone_destroy(const char *zone, char **out);
int ai_ws_zone_status(char **out);
int ai_ws_zone_run(const char *zone, char *const argv[], int argc,
		   int timeout_s, size_t out_max, char *const extra_env[],
		   int extra_env_n, volatile sig_atomic_t *cancel_flag,
		   char **tail_out, int *exit_code, int *timed_out,
		   int *cancelled, int *truncated, char **err_out);

/*
 * 统一子进程采集：setsid + 输出环形尾部（≤out_max）+ 超时 SIGKILL 全组
 * + 可选取消轮询 + 可选环境注入。workspace 与 sandbox 两条通道共用这一份
 * 实现（原先各有一份，V1.8 收口）。
 */
int ai_ws_spawn_capture(char **argv, char *const extra_env[], int extra_env_n,
			int timeout_sec, size_t out_max,
			volatile sig_atomic_t *cancel_flag, char **tail_out,
			int *exit_code, int *timed_out, int *cancelled,
			int *truncated);

#endif /* _AI_WORKSPACE_TOOLS_H */
