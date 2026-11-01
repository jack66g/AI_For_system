/* SPDX-License-Identifier: GPL-2.0 */
/*
 * app_ctl.h - W82 V4.4 应用控制面适配器三件套（TOOL_CH_APPCTL）
 *
 * 从「能画像」升级到「能驱动」：W81 的 app_profile_* 回答一个 APP
 * 「要什么 / 实际碰了什么」，本通道回答「怎么让它干活」：
 *
 *   1. app_ctl_probe   （R/D0，只探测不执行目标动作）
 *      探测 APP 的控制面可用性：
 *        - CLI：可执行文件是否存在（PATH 或绝对路径）、`--help`/`-h`
 *          能否解析出可读输出；
 *        - HTTP：本地回环端口/已知 endpoint 探测（显式 http_ports /
 *          http_urls，或从 `python3 -m http.server` 形态推断端口）；
 *          只连回环，绝不做外网扫描；
 *        - dbus：session bus 是否存在（环境变量/运行时 socket），名字
 *          是否可查（dbus-send NameHasOwner；没有 dbus-send 时如实降级）；
 *        - AT-SPI：只探测环境（AT_SPI_BUS_ADDRESS / atk-bridge /
 *          org.a11y.Bus 归属），明确 implemented=false，不实现控制。
 *   2. app_ctl_call    （W2/D2，单个动作）
 *      backend=cli：fork+execv(argv)，参数逐项传递，绝无 shell 字符串；
 *      backend=http：只允许 http://127.0.0.1|localhost|::1，method/url/
 *      body 显式传入；返回 stdout/stderr/rc/耗时（HTTP 返回状态码/body）。
 *   3. app_ctl_task    （W2/D2，声明式任务）
 *      JSON 任务（steps: 一串 call + assert），顺序执行、逐步断言、
 *      默认失败即停并回报失败步骤与原始 stderr；进度写 progress.jsonl；
 *      支持 action=cancel 从另一进程取消（取消标记 + 进程组 SIGKILL），
 *      结束后清理 pid/cancel 标记，无残留进程。
 *
 * 安全边界（硬约束）：
 *   - 禁止 system()/popen()；CLI 一律 setsid + fork + execv，超时/取消
 *     SIGKILL 整个进程组；子进程 prctl(PR_SET_PDEATHSIG) 防父进程死亡后
 *     留下孤儿。
 *   - HTTP 目标主机只接受 127.0.0.1 / localhost / ::1（解析后再用
 *     getaddrinfo 的 loopback 校验兜底），拒绝 https 与外网地址。
 *   - 每次 call 全量审计到 <state>/audit.log：backend、目标、参数
 *     （密码/token/secret 等敏感值打码）、rc、耗时、超时/取消标记。
 *   - 不写 nft、不改系统配置、不碰生产 VM；状态目录默认 /run/aik-appctl
 *     （root）或 /tmp/aik-appctl-<uid>（非 root），可用 AIKERNEL_APPCTL_DIR
 *     覆盖。
 */
#ifndef _AI_APP_CTL_H
#define _AI_APP_CTL_H

#include <stddef.h>

#define AC_PATH_MAX		4096
#define AC_MAX_ARGV		64
#define AC_MAX_STEPS		32
#define AC_OUT_LIMIT		(256 * 1024)
#define AC_HTTP_BODY_LIMIT	(4 * 1024 * 1024)
#define AC_TASK_ID_MAX		64
#define AC_AUDIT_MAX		8192

/*
 * 状态/审计目录（不存在则 0700 创建）。
 * 返回 0 成功；-1 无法创建/不是目录。
 */
int ac_state_dir(char *out, size_t cap);

/*
 * URL 是否属于允许的回环目标（纯函数，单测用）。
 * 返回 1 允许；0 拒绝（外网/https/畸形/userinfo 冒充等）；-1 参数空。
 * 只接受 http://127.0.0.1[:port][/path]、http://localhost...、
 * http://[::1]... 与 http://::1...（无 userinfo、无 @ 混淆）。
 */
int ac_url_loopback(const char *url);

/* 任务 ID 合法性（纯函数）：[A-Za-z0-9._-]，1..64，禁止 "."/".."。 */
int ac_task_id_valid(const char *id);

/* 参数键是否敏感（纯函数）：password/passwd/token/secret/credential/
 * api-key/apikey/access_key/private-key/auth/cookie/session 等。 */
int ac_key_sensitive(const char *key);

/*
 * 把 argv 渲染成已打码的 JSON 数组字符串（调用者 free）。
 * 规则：--password=x → --password=***；--token x → --token "***"；
 *       KEY=value（KEY 敏感）→ KEY=***。无法分配返回 NULL。
 */
char *ac_mask_argv_json(char *const argv[], int argc);

/* 执行器入口（tools.json 中 channel=appctl 的三件工具）。 */
int exec_app_ctl_channel(const void *tool, const char *args_json, char **out);

#endif /* _AI_APP_CTL_H */
