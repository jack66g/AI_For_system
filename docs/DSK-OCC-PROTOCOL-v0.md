# DSK-01 · occ 服务协议 v0

规格草案，供 DSK-02/03 实现、DSK-05/08 验证。文中的协议方法和套接字均是本次设计。引用基线为 `b436d06`。

## 请用户核对

1. 建议固定桌面的“固定”限定为布局与组件不可编辑，会话、模型和确认仍可操作。普通桌面与桌面一共用同一份会话。
2. 建议同一用户可同时从普通桌面和桌面一观看一轮，写入权只给一个驱动端。需要换端操作时由持有端释放，运行中的轮先完成或中断。
3. 建议桌面二只发起已登记的动作意图。确认由普通桌面或桌面一的可信交互面承接。

## 1. 传输

使用 Linux `AF_UNIX/SOCK_STREAM`，一行一条 UTF-8 JSON 对象，以 LF 结束。收取端可接受 LF 前一个 CR；拒绝 BOM、非法 UTF-8、字符串内的 NUL、重复键、超过 32 层的嵌套和非完整对象。进程输出和 JSON 线路独立，字符串中的换行必须转义。每行上限 1 MiB，按 LF 前的字节数计，客户端可以协商更小值，最低 64 KiB。读取半包保留到下一次读取，EOF 有半行则丢弃。越界关闭该连接，发送端不可假定请求已失败。

服务地址为 `/run/aikernel/occ/<uid>/occd.sock`。可信启动器按系统 UID 创建目录，目录 0700、套接字 0600；服务运行的 OS UID 与路径 UID 和对端 UID 必须一致（包括 root 服务只接 UID 0）。父目录归系统控制，启动时拒绝符号链接及不符属主的路径；服务以套接字锁或监督器保证每 UID 一个实例。两端验证 UID，客户端验证服务端点归属，服务对每连接用 `SO_PEERCRED` 取得 UID/PID。连接入队、读写缓冲、并发请求及空闲时间皆设定上限。实现默认 32 连接、每连接 16 个在途请求、输出队列 4 MiB，握手 10 s，监视空闲连接可保持。

| 报文 | 固定字段 |
|---|---|
| 请求 | `{id,method,params}`，id 是 1–64 字节 ASCII 关联号，连接内不得重用。params 是对象 |
| 成功 | `{id,result}`，result 是对象 |
| 失败 | `{id,error:{code,message,details,retryable}}`；message 随语言档，程序按 code 处理 |
| 推送 | `{event,sub,seq,body}`；订阅号 sub；seq 为会话域或连接域的十进制字符串，由服务递增并保留高水位 |

第一个请求必须是 `hello`。服务从交集选最高支持版本，返回能力交集、连接标识和基础档。能力列举 `sessions`、`turn-stream`、`history-page`、`confirm-ui`、`tasks`、`recover`、`canvas-actions`、`clip-read`，按方法表可缺；依赖能力的方法无可用能力时返回 `E_UNSUPPORTED`。握手返回的 `role` 只读，由服务导出。请求参数未知字段返回 `E_BAD_PARAMS`；客户端忽略未知响应字段及未订阅的新事件，不能忽略自己依赖的新语义。v0→v1 增加方法、可选字段与协商能力，字段含义、默认权限、事件排序和错误码保持；不兼容语义另起协议主版本，旧行为随原版本保留。

## 2. 身份、登录门与交互权限

现役脚本在启动 occ 之前按 `console-gate.last` 选用户并降权，登录门成功后记录输入名，策略初始化读进程 UID。对照 `factory/usr/local/bin/aik-console:93,129–156`、`agent/ai/occ/occ_tui/tui_gate.c:1199–1205`、`agent/ai/occ/occ.c:4699–4707`；以任务书 CON-11 跟踪现役差异。

**v0 的登录发生在创建连接之前。** TTY/席位监督器向既有或后续代验组件认证，取得账户 UID/GID，校验账户仍有效，以目标身份启动前端并连接同 UID 服务。上次账号只作本席位的提示值。任何用户名变化均回到监督器完成验证及凭据切换，释放旧驱动权、销毁旧连接与短期权限后才开启新会话。用户名、档位、`interactive` 和目标 UID 均不可由请求指定。服务状态、审计 actor 和会话存储与验证成功的实际 UID 一致。TTY 与串口各自维护选中账号及登录生命周期。底层登录凭据留在可信输入面，任何登录消息不得携带密码。

| 身份 | 用法与危险操作 |
|---|---|
| root | 用 UID 0 自己的会话。可信交互端可以处理二次确认；仍受沙箱、工具级规则、审计及实际执行约束 |
| admin | 由现役 UID/组规则得到基础档；未提权时 W2 直接拒绝；读取、会话及工具受自身权限和沙箱可用性约束 |
| 普通用户 | 自有会话和现役受限档允许的操作；沙箱不可用时明确拒绝相关工具，保持实际执行主体 |
| 无头调用方 | OS UID 仍来自对端，只在该 UID 范围内读写或发轮；无交互准许权。来自 HTTP 的会话按已验证主体分区；无法绑定 OS 主体时使用独立受限服务账户 |
| 桌面二 | 用户级画布连接仅拥有其组件的显式授权范围，允许请求提案及读取已授权事件；展示面与可信确认连接由监督器分开 |

基础策略使用 `ai_policy_mode_for_uid`（`agent/ai/policy/ai_user_policy.c:462–487`）；裁决审计参照 `agent/ai/occ/occ_tools/tools.c:3851–3909`。`/su` 只从可信本地交互端开启，当前门的验密交由监督器，成功后签发绑定 UID、连接、席位、有效期的短期策略授予，由服务记录并消耗；不改变会话属主、OS 身份或已有文件权限。注销、断线、超时、`/su 0` 立即收回。启用跨进程授予之前须验证 CON-02/03 的代验边界，否则返回 `E_UNSUPPORTED`。

交互端由可信席位监督器在启动已核定客户端时登记，登记凭据绑定连接与内核确认的进程身份，失效时间随席位。常规套接字上的 `hello`、UID 0 或声明有界面都无法获得交互权。服务端另核对验证过的交互端与待确认操作的会话、来源、席位及确认代次，不支持从 HTTP 或画布注册席位。DSK-03 验证登记交接边界前，跨进程确认入口保持关闭。

## 3. 数据与消息全表

下表每项的“已有”表示有对应语义，报文编码由 DSK-03 统一补。引用简称 `occ.c` = `agent/ai/occ/occ.c`，`session.h` = `agent/ai/occ/occ_core/occ_session.h`，`loop.h` = `agent/ai/occ/occ_core/occ_loop.h`，`tui_view.c` = `agent/ai/occ/occ_tui/tui_view.c`。各结构只通过已认证连接在许可范围内可见。

- `Session` = `{sid,kind,status,title,model_id,created_ms,updated_ms,cwd,tokens_total,tokens_est,rev}`；kind 为 main/child，status 为 active/running/error/interrupted/archived。旧会话 ID 保留，rev 供并发比较，按提交单调递增。
- `Message` = `{mid,sid,role,parts,created_ms,reverted,finish?,usage?,content_ref?}`。角色 user/assistant/tool/system；parts 类型 text/reasoning/toolCall/toolResult，分别用 `text`、`text`、`{call_id,tool,args}`、`{call_id,text,rc}`。限制后可返回观测数据引用。应答引用按 UID/会话/用途校验，从左到右累积序号读取；前端遇未知 part 保留位置。会话和消息域的既有持久字段见 `session.h:74–135`，稳定外部游标和修订号由 DSK-03 补。
- `Usage` = `{input,output,cache_read,cache_write,total,estimated}`，total=input+output，整数计数用十进制字符串，未报值为 null。计量保持 provider 原口径，context 指标单列，避免重复加缓存。对应 `agent/ai/occ/occ_core/occ_tokens.h:18–36`。
- `Model` = `{id,label,provider,kind,available,context_limit}`，provider/kind 只标识可展示元数据，密钥不出线路。上下文、任务、工具、诊断对象中遇独立长文本使用 `content_ref`，每次分片请求仍校验同一授权。
- 带 rev 的变更必须给 `if_rev`；驱动方法除另列外须持有本连接的会话驱动权。列表统一 `{items,next}`，next 是不透明游标，可为 null。ID 由服务器分配，`op_id` 是每 UID、每动作域的客户端幂等标识，重发同一参数返回原结果，参数变更返回 `E_OP_CONFLICT`。

| 请求 | params | result | 来源 |
|---|---|---|---|
| `hello` | `{versions,caps,lang,max_line?}`，lang=zh/en | `{version,caps,max_line,connection,uid,role,base_tier,boot_id}` | 需 DSK-03 补 |
| `session.create` | `{title?,model_id?,cwd?,op_id}` | `{session,driver}` | 已有：`occ.c:3175–3196` 换空窗、`loop.h:137–146` 建库；显式空会话需 DSK-03 补 |
| `session.list` | `{kind?,status?,cursor?,limit?}` | `{items:Session[],next}` | 已有：`occ.c:2402–2473` |
| `session.open` | `{sid,mode}`，mode=watch/drive | `{session,driver,head_mid}` | 已有：`occ.c:3571–3699` 打开会话；归属锁需 DSK-03 补 |
| `session.release` | `{sid}` | `{released}` | 需 DSK-03 补 |
| `session.rename` | `{sid,title,if_rev,op_id}` | `{session}` | 已有：`occ.c:3451–3453`；空标题走现有 AI 标题入口；见 `occ.c:2782–2825` 与覆盖层处理 |
| `session.archive` | `{sid,if_rev,op_id}` | `{session}` | 已有：`occ.c:3197–3256` |
| `session.delete` | `{sid,if_rev,op_id}` | `{sid,op}`，服务先发确认 | 已有：`occ.c:3257–3322` |
| `history.list` | `{sid,before?,limit?,include_reverted?}` | `{items:Message[],next,snapshot_head,truncated}` | 已有：`occ.c:851–946`；稳定锚点需 DSK-03 补 |
| `subscribe` / `unsubscribe` | `{sid?,after_seq?,boot_id?}` / `{sub}` | `{sub,boot_id,seq,snapshot_head}` / `{closed}` | 需 DSK-03 补 |
| `turn.submit` | `{sid,text,op_id,if_rev}` | `{turn_id,user_mid,rev}` | 已有：`occ.c:1186–1223`；轮号、幂等与跨进程持久需要 DSK-03 补 |
| `turn.interrupt` | `{sid,turn_id}` | `{pending,state}` | 已有：`occ.c:1224–1244` |
| `turn.recover` | `{sid,if_rev,op_id}` | `{turn_id,rev}` | 已有：`session.h:41–47`、`loop.h:97–105`；以明确请求接续 |
| `confirm.reply` | `{confirm_id,preview_digest,decision}`，allow/deny/session | `{confirm_id,state}` | 已有：`occ.c:1023–1075` 等应答；全文、绑定与跨进程回包需 DSK-03 补 |
| `content.read` | `{ref,offset,limit}` | `{text,next_offset,bytes,digest}` | 需 DSK-03 补 |
| `model.list` | `{kind?,cursor?,limit?}` | `{items:Model[],next,active_id}` | 已有：`occ.c:2240–2398` |
| `model.select` | `{sid?,id,if_rev?,op_id}` | `{model,rev}` | 已有：`occ.c:3571–3699` 模型选择覆盖层 |
| `status.get` | `{sid?}` | `{session?,model?,context:{used,limit,estimated},tier,capabilities,kernel?}` | 已有：`occ.c:3411–3447` |
| `prefs.lang.get` / `prefs.lang.set` | `{}` / `{lang}` | `{lang}` | 已有：`occ.c:3333–3349`；每连接立即生效，设置保存为用户 UI 缺省供新连接读 |
| `tools.list` | `{sid?,cursor?,limit?}` | `{items:[{name,desc,policy,registered,available}],next}` | 已有：`occ.c:2563–2582` 目录显示；运行可用性由 DSK-03 补 |
| `sandbox.status` | `{sid?}` | `{available,reason?,rw_path_supported,scope}` | 已有：`occ.c:2760–2779` |
| `trace.list` / `lease.list` | 各 `{sid?,cursor?,limit?}` | 分别 `{items:[{trace_id,call_id?,tool,state,created_ms,args_summary?,content_ref?}],next}`、`{tier,items:[{kind,state,scope,mission?,expires_ms?}],next}` | 已有：`occ.c:2585–2639`，只读列表与详情 |
| `task.list` / `task.get` | `{sid,cursor?,limit?}` / `{sid,task_id}` | `{items:[{task_id,state,title,child_sid?,budget?}],next}` / `{task,details}` | 已有：`occ.c:1428–1458,2478–2537` |
| `session.compact` | `{sid,if_rev,op_id}` | `{old_sid,new_sid,op}` | 已有：`occ.c:3462–3528` |
| `session.undo` / `session.redo` | `{sid,if_rev,op_id}` | `{session,changes:[{kind,path,status}],partial}` | 已有：`occ.c:3556–3565`；按既有快照合同与权限复核 |
| `identity.elevate.begin` / `identity.elevate.drop` | `{sid?}` / `{}` | `{challenge_id}` / `{tier}` | 已有：`occ.c:3350–3410,3810–3887`；代验及绑定需 DSK-03 补 |
| `setup.status` / `setup.begin` | `{}` / `{model_id}` | `{model_configured,missing_fields,probe_state}` / `{setup_id,required_fields}` | 已有：`occ.c:1641–1655,2134,3645–3654`；只有可信端可发起 begin，密钥由独立可信配置入口处理，结果发事件 |
| `action.propose` | `{sid,canvas_id,action_id,target,args,op_id}` | `{op,confirm_id}` | 需 DSK-03 补；后续画布能力，见画布协议，拒绝任意未登记目标 |

`model.select` 无 sid 只设用户默认，有 sid 只改目标会话且需空闲；`session.create` 的 cwd 只接受服务按 UID 校验已存在的工作树。每轮 `turn.submit` 沿用会话已登记的 cwd。列表 limit 默认 50、最大 200。驱动者获得的 `driver` 是状态提示，不是可转赠令牌。会话侧栏的显示策略由服务按身份返回，日志和观察接口不得为诊断旁路带出会话标题。

| 事件 | body | 何时发送 / 来源 |
|---|---|---|
| `session.state` | `{sid,rev,status,driver,reason}` | 建立、变更、锁移交或释放；已有：`session.h:74–105`，锁与推送需 DSK-03 补 |
| `history.changed` | `{sid,rev,head_mid,reason}` | 可见历史发生变化，undo/redo 或归档均通知；已有：`session.h:41–57`，事件需 DSK-03 补 |
| `turn.started` | `{sid,turn_id,user_mid,model_id,attempt}` | 用户消息落库后且首次增量前；需 DSK-03 补 |
| `text.delta` / `reasoning.delta` | `{sid,turn_id,attempt,text}` | 同一尝试内按生成顺序追加；已有：`loop.h:66–68,80–85` |
| `turn.reset` | `{sid,turn_id,attempt,next_attempt,reason}` | 旧尝试增量作废，已登记工具结果不回滚；已有：`loop.h:75–77` |
| `tool.started` | `{sid,turn_id,call_id,tool,args_summary}` | 执行判定前；已有：`loop.h:69–70`，调用号与跨度需 DSK-03 补 |
| `tool.finished` | `{sid,turn_id,call_id,status,rc,exit_code?,elapsed_ms,result_preview?,content_ref?}` | 每个 started 配一个，status=done/failed/denied/skipped；rc 是工具返回码，子命令码单列；已有：`loop.h:71–72,85–87`，耗时等需 DSK-03 补 |
| `notice` | `{sid?,turn_id?,code,level,text}` | 重试、重放、落库提示，文本按语言档；已有：`loop.h:73–77` |
| `confirm.requested` | `{sid,turn_id?,call_id?,op?,confirm_id,kind,preview,preview_digest,deadline_ms,choices}` | 只向指定确认端，完整预览前置；已有：`occ.c:1023–1045`，全文及路由需 DSK-03 补 |
| `confirm.closed` | `{confirm_id,state,reason}` | 答复、断线、超时、打断或预览失效；已有：`occ.c:1064–1075`，结构化状态需 DSK-03 补 |
| `turn.usage` | `{sid,turn_id,usage,context?}` | 轮收口前一次，缺失给 null；已有：`loop.h:116–132`，每轮跨模型片段累计口径与协议事件需 DSK-03 补 |
| `turn.finished` | `{sid,turn_id,state,reason,provider_finish?,assistant_mid?,rev,error?}` | 一次终态；已有：`loop.h:116–145`，协议映射需 DSK-03 补 |
| `task.changed` | `{sid,task_id,state,child_sid?,budget?}` | 新任务、态变更、预算变化；已有：`occ.c:2478–2558` 轮询视图，推送需 DSK-03 补 |
| `model.changed` / `identity.changed` / `setup.changed` | 分别 `{sid?,model,context_limit}`、`{tier,expires_ms?,reason}`、`{model_configured,probe_state}` | 相应状态提交时；已有：`occ.c:3339–3410,3780–3896,4104–4142`，事件需 DSK-03 补 |
| `action.finished` | `{op,state,error?,changed_fields}` | 画布动作确认执行、拒绝或执行失败后；需 DSK-03 补 |
| `stream.gap` | `{sid?,after_seq,head_seq,boot_id,reason}` | 历史有间隙时要求重对账；需 DSK-03 补 |

## 4. 驱动权、分页和轮次状态

同一服务给同 UID 的多个连接服务，只读 watch 无需驱动权。同一会话一个 drive，在 `session.open(mode=drive)` 时原子取得；冲突回 `E_SESSION_BUSY`，用户可改 watch。释放或进程离开后，先对进行中的轮请求中断，在安全点结束、确认收口和持久状态写定后再释放。运行中的轮没有强行换端。命令与变更在每会话串行，多个会话可分别运行；容量上限返回 `E_LIMIT`。DSK-02/03 把 PID 全局中断标记、W2 当前档位、选中模型和压缩上下文改为轮或会话上下文，验证 A 轮打断对 B 轮无影响。遗留进程独占模式只能在相应数据库完全切换之前运行，迁移后旧客户端通过服务，避免双写。

取历史首屏时，以当前最大持久消息插入序为 `snapshot_head` 固定边界，`before` 为该快照中“下一页早于第一条”的不透明游标。按消息插入序稳定升序返回，每页取紧邻游标的前 N 条。快照内后到消息不翻入旧页，用事件或新首屏获得。会话删除、撤销等造成旧游标无效，返回 `E_CURSOR_STALE` 并重开。首次订阅回包带采样高水位，之后只发其后的事件。连接中断后在同服务代次可用 `after_seq` 补有限的授权事件；服务重启、超环或溢出时重取历史，对未持久化增量显示失去连续性并等待轮终态。确认内容及答复权不参与重放。

正常轮顺序为持久用户消息→`turn.started`→增量、重试与成对工具事件→`turn.usage`→持久终态→`turn.finished`。单轮工具事件严格按调用号配对，允许并行子调用交错，并按会话 seq 合流；`confirm.requested` 必在相关工具完成之前；新尝试有独立 attempt，收到 reset 后丢弃旧尝试的未收口文本。订阅注册响应先于其任何事件。请求响应只确认接收成功，最终效果以终态为准。状态 reason 定义为 `stop/length/step_cap/interrupted/provider_error/storage_error/permission_denied/config_error`；provider 自有结束字面值单列。中断态保留已写入进展，未执行工具闭合为 skipped，已发生外部副作用按实记录。错误或断电后恢复先对账，操作效果不明时显示 `E_OUTCOME_UNKNOWN`，经人工确认后才重试，不主动重放有副作用工具。

## 5. 确认和审计

后端按权限、档位和工具规则产生确认。服务冻结完整命令、diff 或变更清单，保存摘要与执行输入的绑定。预览 `{format,text?,ref?,bytes,digest}` 使用内联或受控分页，读取者限本次选定的交互连接；显示至完整确认后可答复。超过行上限按 UTF-8 边界分片，无法完整交付或目标变化即撤销。要执行的精确输入与批准的摘要应复核一致。无确认端、超时（缺省 5 min，单调计时）、断线、中断都在执行前拒绝，发关闭事件并记审计。每次答复原子消费确认请求，重复答复得 `E_CONFIRM_STALE`。用户明确选择 `session` 仅给服务标明可记忆的工具和同一 UID/会话的策略范围，受现行 allow/ask/deny 与档位复核；保留现役会话同类记忆放行（`occ.c:3578–3590`），按服务决策的工具范围键和策略代次限定。画布显式确认动作维持逐次审阅。交互通道密码输入与预览保留采用不同路径，审计只存身份、范围、动作摘要、裁决及结果。协议不声称内核链账本当前已通，映射由 AIF-05 后续验收。

## 6. 斜杠命令映射与 TUI 回归

控制器识别 20 个命令名，另有 TUI 自管的 `/help` 与 `/exit`（`tui_view.c:459–509`）。旧 `exit`、`quit`、`:q` 同由前端解释。

| 命令 | 前端行为与服务调用 | 源码 |
|---|---|---|
| /new | 本地进入空态，首条消息前才 create；正在跑的旧轮保持其 sid，驱动权随收口释放 | `occ.c:3175–3196` |
| /clear | archive 后换空态 | `occ.c:3197–3256` |
| /delete | delete → confirm → 换空态 | `occ.c:3257–3322` |
| /theme、/zoom | 前端本地行为，配置归控制台呈现 | `occ.c:3323–3326` |
| /sessions | list、open、subscribe、history.list | `occ.c:3327–3328` |
| /tasks | task.list/get 与 task.changed | `occ.c:3329–3330` |
| /lang、/lang zh、/lang en | prefs.lang.get/set，当前端更新文案与输入法 | `occ.c:3333–3349` |
| /su、/su 0 | identity.elevate.begin/drop，可信输入面和 identity.changed | `occ.c:3350–3410` |
| /status | status.get | `occ.c:3411–3447` |
| /models | model.list/select；对未配模型可 setup.begin。筛选显隐、列表游标属前端 | `occ.c:3449–3450,3950–3995` |
| /rename [title] | session.rename；无参打开输入框 | `occ.c:3451–3453` |
| /tools、/sandbox、/trace、/lease | tools.list、sandbox.status、trace.list、lease.list | `occ.c:3454–3461` |
| /compact | session.compact，依回包切换至新 sid | `occ.c:3462–3528` |
| /shell [args] | 现役文字前端的本地 TTY 行为。轮忙时同旧态拒绝，PTY 与输入归前端 | `occ.c:3529–3554` |
| /undo、/redo | session.undo/redo，回放由 history.changed 驱动 | `occ.c:3556–3565` |
| /help、/exit | 前端本地帮助与注销。注销关闭连接，撤销席位权限 | `tui_view.c:459–509` |

DSK-03 的首个客户端须用现有 pty 和字节差分验证：① 新会话空态与旧轮不归错 sid；② 通告、重试清屏、工具调用配对和退出原因；③ 模型向导探测完成或失败可由 setup.changed 重建，输入与秘密留席位；④ 阻塞屏、确认关闭、取消、重连和两席位不同 UID；⑤ 侧栏分页、任务面板、上下文用量和回放，处理服务重启；⑥ 中文档的候选/提交、Home/End、滚动与缩放仍归呈现端；⑦ 审计失败按原策略可见，管理员不能凭客户端显示获得工具可执行权。

当前 `/ask` 由 `aikernel-api` 受理，读取 question 与 api-* session，走进程级会话锁，成功回 session/answer（`agent/ai/apic/apiask.c:1144–1228,1303–1313`）。迁移在服务侧把它接为无头客户端，保留已有 HTTP 字段和错误映射。未绑定可验证主体的 HTTP 请求不能借用宿主 root 会话。当前 Web demo 有自有聊天与存储（`agent/ai/desktop/dtchat.c:2170–2304`、`agent/ai/desktop/dtstate.c:636–705`），按 DEC-08 冻结。

## 7. 错误码全表

| code | 返回条件 | 客户端处理 |
|---|---|---|
| `E_BAD_FRAME` | 非法编码、JSON、重复字段、半行 | 关闭重接 |
| `E_FRAME_LIMIT` | 超行长或嵌套 | 缩小请求或按分片接口读取 |
| `E_HELLO_REQUIRED` | 首包不是 hello 或握手尚未结束 | 重连握手 |
| `E_VERSION` | 无共同版本 | 显示双方支持范围后停止 |
| `E_UNSUPPORTED` | 方法未知、能力未协商或功能未启用 | 隐藏对应入口 |
| `E_BAD_PARAMS` | 缺字段、值域、类型或枚举错误 | 按 details 修正 |
| `E_AUTH` | 对端凭据或席位校验失败 | 回到可信登录，连接关闭 |
| `E_DENIED` | 无相应身份或策略拒绝 | 显示拒绝，保持状态 |
| `E_NOT_FOUND` | 对象不存在或对该 UID 不可见 | 刷新列表 |
| `E_LIMIT` | 并发、容量或速率上限 | 按 details.retry_after_ms 退避 |
| `E_SESSION_BUSY` | 已被其他连接驱动 | watch 或等待释放 |
| `E_DRIVE_REQUIRED` | 修改时未持锁 | 先尝试 drive |
| `E_TURN_RUNNING` | 命令需空闲轮 | 等轮结束或中断 |
| `E_STALE_REV` | 状态修订已变 | 重取、重审后提交 |
| `E_CURSOR_STALE` | 分页游标失效 | 重开历史首屏 |
| `E_EVENT_GAP` | 无法从指定序号恢复 | 同 stream.gap，重对账 |
| `E_OP_CONFLICT` | 幂等标识与不同请求绑定 | 显示冲突；只有明确新意图才换 ID |
| `E_CONFIRM_REQUIRED` | 当前端无法取得可信交互确认 | 旧请求未执行，经可信端重发意图 |
| `E_CONFIRM_STALE` | 超时、重复答复、主体不符或预览变化 | 关闭确认面，重新预览 |
| `E_STORAGE` | 读写或持久化失败 | 保留可见历史，等修复或查询终态 |
| `E_PROVIDER` | 模型不可用或流协议异常 | 展示可重试性，先查询轮态 |
| `E_SANDBOX` | 执行所需沙箱不可用 | 展示原因并终止具体动作 |
| `E_TIMEOUT` | 读服务或操作等待超限 | 查询状态后决定重试 |
| `E_OUTCOME_UNKNOWN` | 外部效果没有可靠提交记录 | 对账后由用户决定是否重做 |
| `E_INTERNAL` | 服务内部故障 | 记录关联号，查询终态；不自动重做写操作 |

## 未决问题

- DSK-03 随 CON-02/03 设计可信监督器登记与代验接口，现场需核对 tty、SSH 与固定桌面的席位边界。
- 并发先验证控制器上下文隔离、快照与自动压缩，再定生产资源上限。服务内事件环长度与日志留存由台架数据决定。
- 现役模型向导的配置入口与语言状态迁移需要 DSK-02/03 巩固。DSK-08 先经只读原型验证握手、历史、状态与事件流。
