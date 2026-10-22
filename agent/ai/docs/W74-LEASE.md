# W74 授权租约与意图保险丝（AIKernel alpha.10）

- 状态：已实现（L1 构建 + 单测/集成测试 + 非破坏性 CLI 探针）
- 范围：`agent/ai/policy`、`tools/executor`、`shell`、`trace`、`i18n`、`tests`
- 不在范围：内核 `AIKernel/**`、`sandbox/**`、`aik-upgrade`、生产 VM 部署

## 1. 设计目标（与 MASTER-PLAN §0/§5 对齐）

AI 是系统最高执政者，人是授权者。权力来源不是“进程是 root”，而是
**Principal 签发的显式租约 + 系统审计**。本波把旧 `-y`/W1/W2/root 的粗粒度
权限升级为：

```
Principal 签发租约 → AI 携带/申请 → scope/ceiling/expiry/revocation 校验
→ D0-D4 分级 → 确认或预授权 → 执行 → trace/audit
```

关键行为：

- D0（只读）与 D1（可逆本地变更）自动执行。
- D2 在任务租约（`-y` 短租约或显式 D2+ 租约）内自动执行；无租约时确认。
- D3 必须人工确认（或显式 D3+ 租约预授权）。
- D4 永不自动放行：即使 D4 租约/批准，也必须精确短语确认。
- 沙箱 worker 只能 D0/D1，D2+ 一律拒绝（即使父租约允许）。
- plan 只读模式优先于租约；租约不能绕过 plan。
- 显式租约越界（scope/ceiling）直接拒绝，交互确认不能绕过。
- 过期/撤销/跨用户/存储校验失败一律 fail-closed（D0 读除外）。

## 2. 代码结构

| 文件 | 作用 |
|---|---|
| `policy/ai_lease.h/.c` | 租约 JSON 解析、安全存储 IO、D0-D4 分类、纯判定、TTY/非 TTY 网关、pending/approve、签发/撤销、live 撤销 |
| `shell/commands/cmd_lease.c` | `/lease list/show/issue/revoke/pending/confirm`（Principal 面） |
| `tools/executor.c` | 统一 lease gate；租约/确认存储写目标硬拒绝；未初始化 ctx 自动进入 NONE |
| `tools/tool_registry.c/.h` | 解析 tools.json `sub` 域名数组（不改工具名/数量） |
| `trace/ai_trace.c`、`include/ai_trace.h` | `policy_decision`/`tool_call` 扩展字段（旧函数保留为 wrapper） |
| `policy/ai_user_policy.c/.h` | `ai_policy_audit_ex` 审计行尾 lease/danger/confirm；旧 gate 仅保留给直接单测/兼容 API |
| `i18n/lang.c`、`include/ai_lang.h` | 中英双语文案与 `--lease/--confirm` 帮助 |
| `tests/test_lease.c` | 解析/存储安全/scope/D0-D4/纯决策矩阵（62 检查） |
| `tests/test_lease_gate.c` | executor 集成、-y、显式租约、非 TTY、live 撤销、写保护（67 检查） |

## 3. 租约格式

```json
{
  "lease_id": "L-20261021-0001",
  "principal": "root",
  "subject": "root-ai",
  "scope": ["sysadmin", "fs:/var:write", "netsec:read"],
  "risk_ceiling": "D2",
  "mission": "排查并修复 nginx 启动失败",
  "issued_at": "2026-10-21T09:00:00+08:00",
  "expires_at": "2026-10-21T23:00:00+08:00",
  "revocable": true,
  "audit": "session-id",
  "revoked": false
}
```

- 必填：`lease_id`、`principal`、`subject`、`scope`（非空数组）、
  `risk_ceiling`（D0-D4）、`mission`、`expires_at`。
- `issued_at` 可选；若存在且比注入的 `now` 超前 >60s 拒绝。
- `expires_at`/`issued_at` 必须带时区（`Z` 或 `±HH:MM`），无时区拒绝。
- `lease_id` 只允许 `[A-Za-z0-9._-]{1,64}`；拒绝 `/`、`..`、空、控制字符。
- 未知字段忽略（向前兼容）。
- `revoked=true` 或同名 `<id>.revoked` 标记 → 拒绝。

## 4. 存储与防伪造

默认路径：

- 租约：`/var/lib/aikernel/leases`（root:root 0700，文件 0600）
- 确认：`/run/aikernel/confirm`（root:root 0700；`pending/`、`approved/`、
  `consumed/`、`denied/` 均 0700，文件 0600）

`AIKERNEL_LEASE_DIR` / `AIKERNEL_CONFIRM_DIR` 可覆盖（测试/独立部署；
覆盖模式下允许目录属主为调用 uid，生产默认要求 root）。

安全规则：

- 目录/文件拒绝符号链接（`O_NOFOLLOW` + `lstat`/`fstat`），要求 0700/0600。
- 文件属主必须是调用 uid 或 root；`principal=root` 的租约只对 uid 0 生效，
  且文件必须 root 属主。
- 非 root principal 必须与调用 uid 的 `/etc/passwd` 用户名一致（跨用户拒绝）。
- 写入使用 `temp + fsync + link/rename + fsync(dir)`；签发不覆盖已有 id。
- 撤销写 `<id>.revoked` 原子标记；`/lease revoke` 仅 root+TTY。
- **live 撤销**：每次 gate 对显式租约检查撤销标记 + 文件 inode/size/mtime
  指纹。观察到撤销后进程内粘滞（删标记也不复活，需要重新签发/重载）。
  文件被改写 → `lease_file_changed` fail-closed。
- executor 所有文件写目标（`tee/cp/mv/ln/sed -i/gcc -o/rm/chmod/chown/tar/
  curl -o/...` 的 W1/W2 realpath 校验）硬拒绝 `/var/lib/aikernel/**`、
  `/run/aikernel/**`、`$HOME/.aikernel/**`、`/root/.aikernel/**`、
  `/var/log/aikernel/**`（含相对路径、`..`、符号链接解析结果）。返回
  `ERROR[E_PARAM_PATH]`，因此模型无法用普通工具伪造 approval 或改写
  审计/trace。审计函数自身用 direct open 写入，不受影响；读仍允许。

## 5. 模式与 CLI

| 模式 | 来源 | 行为 |
|---|---|---|
| NONE | 默认 / 未初始化调用方 | D1 自动；D2/D3 确认；D4 强确认 |
| EPHEMERAL | `-y` / `AIKERNEL_ASSUME_YES` | 本次 ask 的 D2 短租约（1h）；D2 自动；D3 确认；D4 强确认；过期后回落 NONE |
| EXPLICIT | `--lease <id>` / `AIKERNEL_LEASE` | scope+ceiling 校验；D2/D3 在租约内自动；D4 仅人工强确认；越界拒绝；过期/撤销/跨用户拒绝 |

- 显式租约优先于 `-y`；`-y` 不能抬高显式租约 ceiling。
- 显式租约加载失败（不存在/解析错/过期/撤销/跨用户/权限）→ 启动非 0 退出，
  不静默退回无租约。
- `--confirm <nonce>` 设置 `AIKERNEL_CONFIRM_NONCE`（单次消费）。
- `-y` 仍置 `ai_policy_get_assume_yes()=1`（system prompt 文案），但 executor
  不再读取该布尔值做放行；只有 `aikernel_main.c` 用它创建 EPHEMERAL。
- system prompt 与 `-y` 语义同步：只声明 D2 短租约；D3/D4 仍需人工确认；
  工具返回 `CONFIRM_REQUIRED` 时模型应如实转告动作/影响/回滚/nonce 并等待
  `/lease confirm` 或新租约，不重试、不假设已授权；审计来源为
  ephemeral lease，不再写 `CONFIRM=yes(auto)`。

`/lease`（Principal 面，模型无签发工具）：

```
/lease list
/lease show <id>
/lease issue --scope <csv> --ceiling D2 --mission <text> --ttl <sec>
/lease revoke <id>
/lease pending
/lease confirm <nonce> yes|no
/lease confirm <nonce> CONFIRM D4 <nonce>
```

`issue`/`revoke`/`confirm` 仅 root + TTY；`issue` 要输入 `ISSUE <id>`，
`revoke` 要输入 `REVOKE <id>` 才落盘。D4 确认不接受脚本 `yes`。

## 6. Scope 语法

`domain[:subscope][:access]`

- `domain` 匹配动作的任一 `sub` 域（tools.json `sub` + exec 命令语义域）。
- 最后一段是 `read|write|exec|advisory` 时视为 access，否则视为 subscope：
  - `read`：只允许 D0；
  - `advisory`：只允许 D0；
  - `write`：允许写类动作与 exec 类动作（D1-D3，受 ceiling 限制）；
  - `exec`：只允许 exec 类动作；
  - 无 access：不限访问类型（仍受 ceiling 限制）。
- subscope 以 `/` 开头时按**路径边界前缀**匹配：`/var` 匹配 `/var/log/x`，
  不匹配 `/various`；拒绝 `..`。
- subscope 非路径时匹配目标/工具名中的子串（如 `kernel:sched:advisory`）。
- `*` 匹配全部域（签发时 root 显式选择）。

示例：

- `sysadmin`：服务/系统管理类（systemctl 写、mount、sysctl_set 等）
- `fs:/var:write`：`/var` 子树写入/删除
- `netsec:read`：网络只读
- `res`：调度/内存/IO 资源类工具（netlink act 的 sub 为 `res`）

## 7. D0-D4 分类

基础映射：R→D0；W1→D1；W2（或未知风险）→D2。随后按工具名/命令/路径保守升级：

| 级别 | 典型映射 |
|---|---|
| D0 | 所有 R：procfs/sysfs 读、sysctl_get、ps/ss/df、systemctl status、conntrack -L、ip 只读 |
| D1 | W1 低危写：tee/touch/cp/mv/sed（/root /tmp /var/ai）、gcc/cc（/tmp）、sandbox_create/destroy、model_*/sysfs_write_policy_* |
| D2 | W2 普通文件写：tar/rm/chmod/chown（有 path_check）、sandbox_spawn、procfs_write_telemetry_reset |
| D3 | systemctl start/stop/restart/reload/enable/disable/mask/unmask/set-default/isolate/rescue/emergency/reboot/poweroff/halt；nft/tc/conntrack 写；mount/umount/swapon/swapoff/fstrim/setquota；kill；apt/dpkg；crontab；aik-upgrade/aik-backup/aik-reset 写子命令；python3；sys_shell；date -s/--set/--set=/位置参数；hostname -b/-F/位置参数；dmesg -c/-C/--clear/--read-clear/-n/--console-level/-D/-E；smartctl -t/-s/-o/-S/-X；ss -K/--kill；ip/ethtool/nmcli/iptables/ufw 写；hostnamectl/timedatectl/resolvectl set-*；journalctl --vacuum；mkfs/fdisk/parted；dd of=/dev/*；sysctl_set/sysfs_set/config_write_fstab；netlink_act_*（非 sec） |
| D4 | useradd/usermod/userdel/groupadd/groupmod/groupdel/passwd/chpasswd/chage；aa-enforce/aa-complain/aa-disable；netlink_act_sec_lsm_override/seccomp/audit；/etc/sudoers*、/etc/passwd|shadow|group|gshadow、authorized_keys、`**/.ssh/id_*`、`**/.ssh/identity`、`/etc/ssh/ssh_host_*`、`/etc/ssh/sshd_config*`、`/etc/pam.d`、`/etc/security`、`/etc/crypttab`、`/etc/default/grub`、`/etc/grub.d`、`/boot/**`、`/etc/aikernel/policy.conf`；lease issue/revoke/confirm。`known_hosts` 不升 D4。 |

补充口径：

- 命令级 D3 特征只在有效风险为 W2 时升级；沙箱受限表把 `python3/gcc/cc`
  明确标为 W1（沙箱内部执行），保持 D1，worker 可用。
- 主表 `python3` 为 W2 → D3，`-y` 的 D2 短租约不能自动放行。
- 路径型 D4 优先于命令级；D2+ 写 `/etc,/usr,/bin,/sbin,/lib,/var/lib,/home,
  /opt,/proc/sys,/sys,/dev` 升级 D3。
- 租约/确认存储不走 D 级，而由 executor 写目标黑名单直接拒绝（路径层）。

## 8. 判定顺序（`ai_lease_decide`，纯函数，now 注入）

0. D4 + 非 root → 直接 `d4_requires_root` DENY（不给非 root 弹 D4）。
1. 撤销/过期/加载失败状态（D0 除外）。
2. 外层 `ai_policy_check(uid, risk)`：DENY → 拒绝（租约不能提权）。
3. plan 模式：D1+ 拒绝（租约不能绕过）。
4. worker（`AIKERNEL_SANDBOX` 非空）：D2+ 拒绝。
5. D0 → 放行（租约过期/撤销也不阻断读）。
6. EXPLICIT：撤销/过期/principal/属主/scope/ceiling 校验；D4 只升级
   `CONFIRM_D4`（D3 ceiling 可请求人工 D4，D2 ceiling 拒绝）；其它在租约内
   ALLOW。越界返回 `lease_scope_denied`/`lease_ceiling_denied`，不进入交互。
7. EPHEMERAL：未过期且 D2 → ALLOW（confirmation=ephemeral）；D3/D4 确认；
   过期 → 回落 NONE 语义（D1 自动、D2/D3 确认、D4 强确认），reason=
   `ephemeral_expired`。
8. NONE：D1 自动；D2/D3 CONFIRM；D4 CONFIRM_D4。

`verdict` 返回：decision、reason、lease_id、danger、scope_hit、rollback_hint、
confirmation。

## 9. 确认 UX 与非 TTY 协议

### TTY

面板显示：工具、danger、lease_id、影响（工具描述）、回滚提示。

- D2/D3：`y/N`（8s 窗口，超时=拒绝）。
- D4：必须精确输入 `CONFIRM D4 <tool>`；否则拒绝。

### 非 TTY（无租约且 D2+）

首次调用写 pending 并返回一行可解析结果：

```
ERROR: DENIED: CONFIRM_REQUIRED {"status":"CONFIRM_REQUIRED","nonce":"<32hex>",
 "danger":"D3","tool":"...","lease_id":null,"action":"...","impact":"...",
 "rollback":"...","question":"继续？"}
```

- pending 文件：`<confirm>/pending/<nonce>.json`（0600，5 分钟有效），
  字段含 nonce/tool/args_json/danger/lease_id/created_at/expires_at/uid/
  action/impact/rollback。
- Principal 用 `/lease confirm <nonce> yes|no` 写 `approved/<nonce>.json`
  （D4 必须 `CONFIRM D4 <nonce>`）。
- 调用方重试时设置 `AIKERNEL_CONFIRM_NONCE=<nonce>` 或 `--confirm <nonce>`；
  gate 校验 tool、args_json（字节完全一致）、danger、lease_id、uid、过期，
  通过后 `rename` 到 `consumed/`（单次消费）。不匹配/过期/重复 → 拒绝。
- 伪造 approved（args 不同/非 root 属主/非 0600）不被接受。

## 10. Trace / Audit

`policy_decision` 新增可选字段：

- `lease_id`、`danger`、`confirmation`（none/interactive/ephemeral/lease/
  approved_file）、`pending_nonce`、`lease_source`。

`tool_call` 新增 `danger`、`lease_id`。

审计行（`~/.aikernel/audit.log`）行尾追加：

```
 lease=<id> danger=<D> confirm=<source>
```

所有确认结果（TTY/批准文件/拒绝/D4 短语错误）均写 trace + audit。

## 11. 威胁模型与未解风险

已缓解：

- 模型通过普通文件工具伪造 approval：租约/确认目录不可写（executor 硬拒绝）。
- 显式租约越界靠交互绕过：scope/ceiling 在确认前直接拒绝。
- 跨用户借 root 租约：principal/uid/属主三重校验。
- 过期/撤销后继续执行：启动加载 + 每次 gate live 检查 + 进程内粘滞撤销。
- worker 借父租约扩权：D2+ 一律拒绝；plan 优先。
- 非 TTY 静默放行：默认 CONFIRM_REQUIRED；D4 必须人工短语。
- 路径穿越/符号链接写存储：realpath + `..` + 边界前缀 + 黑名单。

未解风险（如实登记）：

1. **root AI 可用 python3/apt 等任意代码通道篡改 `/var/lib/aikernel/leases`
   自签租约**。路径黑名单只挡普通文件工具，挡不住任意代码。W74 的边界是
   “防注入意图/防误操作”，不是“防恶意 root AI”。签名租约/独立 broker 留
   W83/W86。
2. 无密码学签名：租约文件可被 root 改写；文件指纹只检测加载后的变化，
   同一秒内等长改写可能漏检（inode/size/mtime 组合已覆盖常见情形）。
3. TOCTOU：executor 路径检查与实际写入之间仍有窗口；W1 命令白名单、
   `--sandbox`、确认与审计共同兜底。
4. D4 工具尚未进入注册表（useradd/visudo/grub 等只在 exec 语义中分类）；
   正式工具面与 `lease_request` 工具留 W74b/W79。
5. 确认文件依赖文件系统权限与 root 属主；无硬件/TPM 背书。
6. 显式租约加载后若文件被删除 → `lease_file_missing` fail-closed；需要重新
   签发/加载，不会自动恢复。
7. `-y` ephemeral 过期后回落 NONE（D2 会重新询问）；长无人值守任务需要
   显式 D2/D3 租约。
8. 非 root 同一 UID 可改写自己的 `$HOME/.aikernel/audit.log`：DAC 无法阻止
   同 UID 写自己的家目录；root 与 `/var/log/aikernel` 已由路径黑名单保护。
   独立 append-only audit 收集器留 W83。
9. `tee /etc/x` 等动作会先按系统路径升 D3 弹确认，确认后才被路径白名单
   拒绝；安全上不放松（仍拒绝），但 UX 多一次无意义确认。把写路径校验
   提前到确认前留 W74b。
10. R 早退已移除：effective risk=R 但工具名/命令命中 D3/D4 仍升级；
    未命中的纯读命令保持 D0。

## 12. 复现/验证

```
# 构建（串行锁）
flock ~/aik-build.lock bash -lc 'cd /home/jack66g/linux-6.18.39/agent/ai && make'

# 全量测试（29 个二进制，含新增 test_lease/test_lease_gate）
make -C tests test

# 注册表 manifest（130 工具/hash 不变）
python3 tests/test_registry_manifest.py

# CLI
./ai --help | grep -- --lease
./ai --lease /nonexistent -p hi    # 非 0 退出，错误清晰
```

## 13. 后续（W74b/W79/W83/W86）

- `lease_request` 工具：AI 只能申请，Principal 审批；当前为自然语言 + `/lease issue`。
- 租约签名（Ed25519/TPM）与独立 Lease Broker；W83 红队验证。
- D4 工具正式注册（useradd/visudo/grub），但仍只允许人工确认。
- 进行中的 D3 动作在撤销时可回滚（目前是拒绝后续动作；执行中的外部命令
  仍由命令自身完成/超时）。
