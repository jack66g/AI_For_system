# 安全边界与秘密管理

## 仓库不含秘密

本仓库是**源码基线**，不包含：

- 云端 API key、Bearer token、密码、私钥、SSH host key
- `/root/.aikernel/model.toml`（含运行密钥，权限 600，仅在 VM 上）
- `/etc/aikernel/api-token`
- VM 备份、ISO、factory tar、证据日志、trace

`factory/` 只收编出厂资产（unit、脚本、seed、配置），不含任何运行时密钥。`aik-token` 在安装/运维时生成 32 字节随机 token 并写入 600 权限位置，不会把 token 写进仓库。

提交前扫描（示例）：

```bash
grep -rInE 'sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY' .
find . -name 'model.toml' -o -name '*.pem' -o -name '*.key' -o -name 'api-token'
```

测试代码中的 `sk-...`/`token=...` 是脱敏断言夹具，不是真实凭据。

## 运行时授权

- 主 Agent 以 root 运行；危险操作走 W74 租约：D0 只读、D1 低风险、D2 确认、D3 强确认、D4 禁止。
- 50 场景门禁用 `-y D2`，不发全局 D3 lease；`perm-03` 的 D3 `CONFIRM_REQUIRED` 是预期结果。
- worker 子智能体在沙箱内运行，能力集受限；沙箱 fail-closed。
- 本地模型与云端模型使用同一套工具、租约和审计，没有“本地=降级/免审计”的特权。
- API 仅监听 loopback，Bearer 鉴权；`/ask` 与 `/clarify` 使用 `api-` 会话、per-session 锁、`stdin=DEVNULL`，不继承 `confirm/assume` 环境。
- 澄清问题与回答不进入 argv；问题走 `AIKERNEL_PROMPT` 环境，回答走 `AIKERNEL_CLARIFY_SELECT/OTHER`，读取后立即清除。

## 当前已知风险（如实）

1. **sshd 基线**：`factory/etc/ssh/sshd_config` 当前允许 root 登录和密码认证。这是现有出厂基线，W83 安全波次需要重新评估（强制 key/首启改密/禁用 root 密码）。不要把它当作最终安全配置。（出厂 ISO 自 alpha.12.0 起不再携带 `root/.ssh/authorized_keys`——该 key 曾随开发 VM 导出带入工厂树，已移除并有 qsmoke `root_authkeys=0` 断言。）
2. **Web 桌面**：`aik-desktop` 只监听 127.0.0.1:8091，当前没有独立鉴权；截图返回 503、power 501。它不是真 OS 桌面（W84）。
3. **主 Agent root + 注入面**：W74 租约/W83 红队仍在推进；不要把“有租约”理解为“已沙箱化”。
4. **云端密钥**：生产 VM 的 cloud key 在 `model.toml`（600）。B-075 要求轮换并迁移到 secret store；轮换前先备份/确认，避免把 API 锁死。
5. **本地模型（按需安装）**：出厂不预装任何模型（alpha.12 起，B-095/B-096 清理后工厂树无模型权重与 root 残渣）；本地模型经 `aik model install` 按需安装（install/remove=D2 lease），装后连通+小推理验证、失败如实上报；spark2_5 等自定义架构需较新 ollama，目录 notes 已标注预检要求。

## 供应链

- 基础内核来自 kernel.org 6.18.39；overlay 清单逐文件 SHA-256 校验（`build/apply-overlays.sh`）。
- `agent/ai/third_party/mbedtls` 保留上游目录与许可证；裁剪/升级时保持 `include/`、`library/`、许可证完整。
- 发布脚本（`build/`、`w6i-tools/`）含构建机路径和 root 操作，使用前按环境改路径；生产 VM 重启只走 A/B，破坏性演练只在 qemu。

## 报告问题

安全问题不要公开提交 issue；在项目工作区的缺陷账本（`BUGS.md`）登记，或直接联系维护者。不要在报告、日志、提交信息中粘贴真实 key/token/密码。
