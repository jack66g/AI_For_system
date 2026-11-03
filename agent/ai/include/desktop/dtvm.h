/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dtvm.h - VM 真系统桥(T6c):AIK_DESKTOP_VM=1 时以 `sshpass -e ssh`
 * 子进程实现 paramiko 等价能力(凭据 ~/.aikernel/vm138.conf,password
 * 只经 SSHPASS 环境变量传递,不进 argv、不落日志):
 *   - vm_ai/vm_aiops/vm_sandbox 快照 = 独立 SSH exec(命令串逐字对齐
 *     server.py:1006-1109/627-655,ConnectTimeout=8);
 *   - status/tools 走懒启动隧道(ssh -N -L 18761:127.0.0.1:8761 子进程
 *     代替 paramiko direct-tcpip),本地 vm_api = http://127.0.0.1:18761
 *     明文 GET + Bearer token(token 每次经独立 SSH 现取,不缓存);
 *   - 空闲 120s 由 housekeeping 关闭(SIGTERM 子进程)。
 * 出厂 disabled 分支由 desktopd.c 内联实现(T6b 已逐字节锁定,不在本
 * 模块);dt_vm_status_snapshot/dt_vm_sandbox_snapshot 自带 disabled
 * 分支供 chat 路径使用。
 *
 * 能力边界(L1 无真 SSH 靶):编译 + 纯函数单测(server.py 同构 fixture)
 * + 命令串构造断言;真 SSH 差分留 T7 qemu(设计 §3 口径)。
 */
#ifndef _AIK_DESKTOP_DTVM_H
#define _AIK_DESKTOP_DTVM_H

#include <stddef.h>

#include "store/store_json.h"

#define DT_VM_DISABLED_REASON \
	"vm_unavailable: local desktop only (AIK_DESKTOP_VM=0)"

/* ---------------- 快照(enabled 路径;desktopd 仅在 VM 开时调 ai/aiops) --- */

aik_json *dt_vm_ai_snapshot(void);
aik_json *dt_vm_aiops_snapshot(void);

/* 双分支(chat VM 附加块 + /api/vm/status enabled 路径) */
aik_json *dt_vm_status_snapshot(void);
aik_json *dt_vm_sandbox_snapshot(void);

/* ---------------- vm_api(GET;POST /act 恒 403 不需要) ------------------- */

/* 经隧道调 aikernel-api:GET http://127.0.0.1:18761<path>。
 * 返回 1 → *data = 上游 JSON(透传,调用者释放);返回 0 → err 填
 * "tunnel failed: <last_err>" / "no token" / "HTTP <code>" / 异常名等价物。 */
int dt_vm_api_get(const char *path, aik_json **data, char *err, size_t errsz);

/* ---------------- 隧道生命周期 ---------------- */

void dt_vm_close(void);
/* vm_housekeeping 30s tick:空闲 > 120s 关闭(desktopd 调) */
void dt_vm_housekeeping_tick(void);

/* ---------------- 纯解析(单测喂 server.py 同构 fixture) ---------------- */

/* /proc/ai 快照解析:0 = 成功(o 填 reachable/ai/load1/mem_pct);
 * -1 = "/proc/ai 不可读"(o 填 {"reachable": false, "error": ...},
 * 调用方需 vm_close)。float 失败等价 ValueError 由 -2 指示(异常形)。 */
int dt_vm_parse_ai(const char *raw, aik_json *o);

/* aiops 快照解析:恒 reachable=true 形态(异常路径不走这里) */
int dt_vm_parse_aiops(const char *raw, aik_json *o);

/* sandbox 空态判定:"total 8" 且 "---MOUNTS---" 且换行 < 8 */
long long dt_vm_sandbox_is_empty(const char *raw);

/* 命令串构造断言用(与 server.py 逐字一致) */
const char *dt_vm_cmd_ai(void);
const char *dt_vm_cmd_aiops(void);
const char *dt_vm_cmd_sandbox(void);
const char *dt_vm_cmd_token(void);

#endif /* _AIK_DESKTOP_DTVM_H */
