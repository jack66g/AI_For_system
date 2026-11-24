# DSK-01 · 画布协议 v0

规格草案。画布由 AI 经桌面一生成，交给桌面二渲染。普通桌面、桌面一和桌面二共用核心，不共享前端可写目录。引用基线为 `b436d06`。

## 请用户核对

1. 建议允许普通用户在个人设置区添加带类型的设置项，系统级设置项继续由系统登记与授权；画布提交的系统级设置意图可复用既有登记项。
2. 建议进程小窗第一版只挂载同账户应用主动导出的只读卡片，按应用提供的稳定实例标识恢复，进程退出时显示离线。
3. 建议卸下画布组件时默认保留原稿和个人画布数据，再装后保持停用，由用户选回启用项。

## 1. 载体与校验

一个 UTF-8 JSON 对象，一个文件。程序使用仓内 `aik_json_parse` 与基于长度的读取接口（`agent/ai/include/store/store_json.h:35–41`、`agent/ai/store/store_json.c:799–919`）。仓内另有轻量扫描器（`agent/ai/include/ai_json_util.h:20–42`），画布选完整树便于路径与跨引用校验。入口在 parse 前检查重复键、UTF-8/编码、深度与字节限额，之后逐字段做语义校验。标准 JSON，无注释、尾逗号和特殊浮点值。限制 256 KiB、深度 24、每页 64 个组件、全画布 128 个组件、最多 16 页、64 个数据源及 64 个动作。页面与动作参数内容按字节限额计，所有 id 同一类型命名域内唯一。

schema 常量 `aik-canvas/0`。新增实现能力以 `requires` 申报。解析器遇未知 schema、能力、字段或枚举拒绝启用并报告 JSON Pointer。保留唯一扩展容器 `meta.extensions`，键必须有反向域名前缀，该容器仅作展示注释、没有语义。缺字段按表报错或取缺省。整数须精确处于阈值内，浮点值须有限。自由文案 UTF-8，最多 2 KiB；不可渲染控制序列、HTML、终端转义、URI、远程图像、字体或执行字符串。示例用本地时间显示，UTC 时间戳是整数毫秒。

| 对象 | 必填 | 可选及规则 |
|---|---|---|
| 根对象 | `schema,meta,pages,bindings,actions` | `requires` 为能力名数组，默认 []；允许 `sense`、`systemd`、`aikctl`、`occ-events`、`memory`、`files`、`app-view`、`user-settings`、`user-timers`、`sandbox-recipe` |
| `meta` | `id,title,revision` | `description,extensions`；revision=1..2147483647。id 1..64 字节、由小写 ASCII 字母开头，其余可为小写字母、数字、短横 |
| `page` | `id,title,columns,items` | columns=1..12，每页 items 可为空。默认焦点由首个实际可交互组件获得 |
| 组件共有字段 | `id,type,rect` | `label`、`style`（normal/accent/muted/warning，默认 normal）。rect=`[x,y,w,h]`，0 基，x=0..11、y=0..1023，w=1..12，h=1..32；x+w≤columns，y+h≤1024，矩形互不叠盖 |
| 绑定 | `id,source,params,as` | `path` 默认 []，JSON 键与数组索引的序列，最大 12 段；`poll_ms` 默认源对应值；`fallback` 同 as 类型，默认无；as=text/number/bool/series/record；无字符串替换、条件表达式或二次查找 |
| 动作 | `id,target,args` | target 枚举见 §4。args 逐目标校验。每个目标最多一个参数来自 `{"input":"组件id"}`，其余为规定类型的字面值 |
| 值引用 | 二选一 `{literal:v}` 或 `{bind:id}` | 对照组件类型，禁同时给两者。加载时不存在的绑定立即拒绝。类型不符的动态数据给 `C_SOURCE_TYPE` |

| 组件 type | 特有字段 | 规则 |
|---|---|---|
| `card` | `value`；可选 `detail` | 两者为标量值引用，数值可由 style 对应的前端格式显示 |
| `text` | `value` | text 值引用，按纯文字呈现 |
| `button` | `label,action` | 按下发一次意图。等待期间禁重复触发，保持上次结果可见 |
| `input` | `label,input_type`；可选 `initial,min,max,choices` | input_type=text/number/bool/enum。text 用长度界限（默认 0..256），number 用范围界限；enum 另需 1..32 项唯一候选，bool 只认 JSON 布尔。initial 类型一致，未给为未填写。只保存于当前表单，动作执行成功后的持久值由绑定回读 |
| `chart` | `series`；可选 `kind` | series 为 series 值引用，最多 256 个 `{t,y}` 点，按 t 单调排序，kind=line/bar，缺省 line |
| `process-view` | `view`；可选 `pin_action` | view 为 app-view 绑定输出的 record，最多包含 provider、instance、display_name、status、text。纯文字小窗，`pin_action` 只可指向 app.pin |
| `setting` | `setting_key,value,value_type,action`；可选 `choices` | value 为现值标量引用；value_type=text/number/bool/enum。组件提出变更，不产生设置权限。setting_key/action/binding 须对应同一系统登记项，或同一用户画布的完整命名空间；提交值用该 setting 控件当前编辑值 |

## 2. 状态与生命周期

规约路径的 `$STATE` 为用户的 `$XDG_STATE_HOME/aikernel/canvas`，缺省 `~/.local/state/aikernel/canvas`。监督器从认证 UID 的配置解析路径，忽略传入进程伪造的 HOME。目录 0700，文件 0600，拒绝符号链接、越界挂载与不符属主。用户文本放 `$STATE/<id>/revisions/<revision>/canvas.json`，数据放 `$STATE/<id>/data/`，每项限额。软件包内的工厂画布模板在组件可写状态之外，以只读数据发布。

桌面一生成到工作区，用户审阅后交给本地安装入口。安装/升级先解析、验权、检验引用、预览能力变化，再在同一文件系统写新版本和编译后的清单索引，刷新到盘后原子提交目录。manifest 由安装器生成，字段是 `schema,id,revision,sha256,owner_uid,required_caps,authorized_bindings,authorized_actions,enabled,source,installed_at_ms`。授权项由用户和当前策略裁定，导入 JSON 没有写入 manifest 的资格。相同 ID 的较低修订受控回退，相同修订不同摘要返回冲突。更新切换前验证新版本，失败保留原版；能力增量需重新授予。

启用时重新验 manifest 摘要、属主和当前策略，再挂载订阅与读面，默认启动本画布页面。停用时释放订阅、撤销未确认的请求、关闭小窗，保留已提交的个人数据；挂载的个人闹钟停止调度并保留时间。单画布卸载默认移除激活记录和运行时索引，保留个人原稿与数据；用户选择清除时仅删除归属核实的该画布目录内内容。组件卸载、模板复位与事务语义详见 [组件与卸载契约](DSK-COMPONENT-CONTRACT.md)。模板复位备份本画布状态，换回已安装组件的只读模板，默认停用；没有模板标 `C_NO_TEMPLATE`。保留的数据按来源与 owner/ID 查回，重新装载时需复核授权范围。

## 3. 数据绑定与可见性

绑定在认证读者的代理下求值。每次刷新复核当前读权限和 manifest 范围。隐私数据不可从其他用户、root 服务身份或缓存间接读到。输出天花板 32 KiB，序列最多 256 点，record 最多 64 个字段；超过容量标 `C_LIMIT`。成功时间为 `observed_ms`，有权限时可显示上一值及“陈旧”状态；权限收回后立即清空渲染、历史缓存和派生值。类型不符或服务不可用用显式状态与 fallback。fallback 永远标为默认值，避免被当作测量值。画布进入后台后降低或停止轮询。相同权限域的多组件共享一次订阅。

| source | params / 结果 | 刷新与读者身份 | 现有依据或待办 |
|---|---|---|---|
| `sense` | `{what,limit}`；what 先开放 status/latency/hitrate，limit 默认 256、最大 2048 字符；record={what,content,truncated} | 1000..60000 ms，默认 5000；本地核心代理对读者用严格脱敏，未知字段和失效脱敏返回不可用 | `agent/ai/apic/apiv2.c:596–612,666–718`。现有 telemetry 读消费者有状态，先排除自动轮询（`AIKernel/senses/ai_procfs.c:495–517`）；逐 UID 代理待做 |
| `systemd` | `{scope,unit}`；scope=user/system；record={unit,active,substate,since_ms} | 优先状态变更订阅，最多每秒一次，断线重取快照；无推送时默认 5000 ms。系统 unit 只公开管理员明列的非敏感项，用户域只看当前 UID | 服务名可对照 `factory/etc/systemd/system/aikernel-streams.service:11`；绑定适配器待做 |
| `aikctl` | `{view}`；v0 枚举 self-policy / compat-summary；record 为裁定后公开字段，self-policy={uid,tier}，compat-summary={cpu_arch,providers} | 默认 30000 ms，最短 5000；在读者 UID 下执行固定适配器，拒绝任意参数。自看档位，兼容摘要按公开字段出 | `agent/ai/aikctl/aikctl:2113,4610,5701`；C 实现与字段投影待做 |
| `occ.events` | `{session_id,event,field}`；v0 允许 `turn.finished.state`、`turn.usage.usage` 与 `session.state.status`；结果按字段类型 | 订阅驱动，连接后先读快照；最多 2 Hz 更新，收口和断线保留状态。只看当前 UID 已授权 sid，确认预览、参数和思维文本不向渲染器广播 | 订阅与字段列表见 [occ 服务协议](DSK-OCC-PROTOCOL-v0.md)，DSK-03 |
| `memory` | `{query,limit}`；query 1..256 字节，limit 1..5，默认 3；record={count,items:[{excerpt,score}]} | 用户点击刷新，最短间隔 5000 ms；只查代理验证过的个人命名空间，脱敏和控制访问可用才启用 | 后端 `/memories/search` 对照 `agent/ai/smehttp/http.c:777–779`。鉴权与归属依赖 MEM-04，未实现时不可用 |
| `file` | `{path,format}`；格式 text/json；结果按 format 和 as | 默认 5000 ms，最短 1000；只读当前画布 data 目录内普通文件，用目录句柄逐段解析，禁止绝对路径、上跳、链接、设备、套接字和跨挂载；按授权大小读取 | 画布文件代理待做 |
| `app.view` | `{app,slot}`，app 注册名、slot 标准视图名；record 如 process-view | 由同 UID 已登记应用推送，最多 2 Hz；退出/销毁即离线。拒绝 PID、窗口输入转发、屏幕快照和其他 UID 的进程视图 | DSK-05 后续定义发布者；旧 Web demo 窗口记录见 `agent/ai/desktop/desktopd.c:566`，按 DEC-08 冻结 |
| `user.timer` / `user.setting` | 分别 `{key}`，timer 输出 {time,armed}，setting 输出已登记值 | 读本画布的已提交值或系统登记的公开设置投影；提交后推送。时钟只在显示需要时更新 | 受限动作适配器待做 |

不同来源的字段可用 `path:["active"]` 这样的文本键投影。读取失败时 UI 显示 unavailable、stale、denied 或 missing，保留错误码和最后刷新时间；任何上一值只在重新授权后保留。系统信息面交给结构化、可审计的核心读接口，画布自行访问网络、进程、文件和设备的入口全部关闭。

## 4. 动作与设置边界

画布动作只调用 `action.propose`，服务按实际 UID 校验登记清单与类型、锁定预览、通过 `confirm.requested` 交给可信普通桌面或桌面一。渲染器仅能监听本操作 `action.finished`，没有 `confirm.reply`、`turn.submit`、`identity.*`、`model.*`、`session.*`、通用工具、脚本命令行或套接字透传能力。无交互端时请求拒绝。确认前后复核目标及源值版本，变化则重新预览。定时触发和被动读绑定都不能产生动作提案。动作记 UID、画布 ID、目标、值摘要、裁决与可观察结果。

| target | args | 权限与结果 |
|---|---|---|
| `timer.arm` | `{key,time}`，time 为 24 h HH:MM 本地时间 | 管理当前画布的个人一次性提醒；确认时显示具体本地日时刻与时区。渲染器停用则停止调度。到期显示本地提醒；不触发新工具 |
| `service.inspect` | `{scope,unit}` | 以当前 UID 打开允许字段的详情卡，走同一确认与审计入口，不能改服务运行状态 |
| `settings.set` | `{key,value}` | `user.<canvas-id>.<key>` 写当前 UID 专属存储，以 schema 或登记表复核类型。系统设置 key 走核心登记的 typed handler，再按现行策略与接口的能力判断，未登记或越权立即拒绝 |
| `app.pin` | `{app,slot}` | 仅固定同 UID 提供的登记视图，写本画布 pins。进程实例变更必须由登记发布者确认可迁移的槽 |
| `recipe.run` | `{recipe_id,args}` | 只能运行已审核、版本/哈希固定的本地沙箱配方；参数限声明类型，无命令字符串、路径插值与运行时下载。默认无外联、限时限资源，输出为结构化返回；沙箱不可用立即拒绝 |

设置登记向用户展示“个人画布设置”或“系统登记设置”。普通用户添加个人项只建立自有存储的表单映射，值步入 `$STATE/<id>/data/settings.json` 的结构化键，由核心动作代理按 UID 写入，不改系统注册表、sysctl、配置或 units。首次个人值缺省来源为受校验的画布发布默认值；系统项缺省与校验规则只来自系统登记。桌面一生成包含系统 key 的组件只是在系统已有项上加视图；系统新增项需另案，由系统组件声明 schema/typed handler、权限与审计，完成工程验收后登记。root 在画布中的动作也经过交互确认。

沙箱配方无法信任画布声明的文件视图。配方独立注册能力，由服务在当前 UID 的允许工作区与最小挂载范围内执行；拒绝再调用确认端、开子进程绕开限制或访问核心会话和凭据。系统变更如需工程配方交给核心登记项，不用画布文件发命令。

## 5. 四个完整示例及走查

### 5.1 样式闹钟

```json
{
  "schema": "aik-canvas/0",
  "meta": {"id": "tea-alarm", "title": "茶歇提醒", "revision": 1},
  "requires": ["user-timers"],
  "pages": [{"id": "main", "title": "闹钟", "columns": 6, "items": [
    {"id": "when", "type": "input", "label": "提醒时间", "rect": [0,0,3,1], "input_type": "text", "initial": "14:30", "min": 5, "max": 5},
    {"id": "arm", "type": "button", "label": "设置提醒", "rect": [3,0,3,1], "style": "accent", "action": "set-alarm"},
    {"id": "readback", "type": "card", "label": "已设时间", "rect": [0,1,6,1], "value": {"bind": "alarm-time"}}
  ]}],
  "bindings": [{"id": "alarm-time", "source": "user.timer", "params": {"key": "tea"}, "path": ["time"], "as": "text", "fallback": "尚未设置"}],
  "actions": [{"id": "set-alarm", "target": "timer.arm", "args": {"key": "tea", "time": {"input": "when"}}}]
}
```

AI 在桌面一生成，安装为 `$STATE/tea-alarm/revisions/1/canvas.json`，启用时读 `tea` 当前状态。点击后代理在可信端展示本地时间与提醒范围，准许后落盘并发回状态，卡片显示已设时间。停用后解除调度，卸载按选择保留或清除个人闹钟数据。

### 5.2 卡片

```json
{
  "schema": "aik-canvas/0",
  "meta": {"id": "stream-card", "title": "事件流状态", "revision": 1},
  "requires": ["systemd"],
  "pages": [{"id": "main", "title": "服务", "columns": 6, "items": [
    {"id": "health", "type": "card", "label": "事件流", "rect": [0,0,6,2], "value": {"bind": "stream-state"}},
    {"id": "details", "type": "button", "label": "查看状态详情", "rect": [0,2,6,1], "action": "inspect"}
  ]}],
  "bindings": [{"id": "stream-state", "source": "systemd", "params": {"scope": "system", "unit": "aikernel-streams.service"}, "path": ["active"], "as": "text"}],
  "actions": [{"id": "inspect", "target": "service.inspect", "args": {"scope": "system", "unit": "aikernel-streams.service"}}]
}
```

AI 从公开单元登记生成画布，安装到 `$STATE/stream-card/revisions/1/canvas.json`。启用后允许字段变更推到卡片，初始显示实际 active 或不可用。查看详情申请确认，准许后显示该身份可见的细分状态及刷新时间。停用取消订阅，卸载移除该画布，服务继续运行。

### 5.3 新的设置项

```json
{
  "schema": "aik-canvas/0",
  "meta": {"id": "focus-panel", "title": "专注设置", "revision": 1},
  "requires": ["user-settings"],
  "pages": [{"id": "main", "title": "个人画布设置", "columns": 6, "items": [
    {"id": "dense", "type": "setting", "label": "紧凑布局", "rect": [0,0,6,1], "style": "accent", "setting_key": "user.focus-panel.dense", "value": {"bind": "density"}, "value_type": "bool", "action": "change-density"}
  ]}],
  "bindings": [{"id": "density", "source": "user.setting", "params": {"key": "user.focus-panel.dense"}, "as": "bool", "fallback": false}],
  "actions": [{"id": "change-density", "target": "settings.set", "args": {"key": "user.focus-panel.dense", "value": {"input": "dense"}}}]
}
```

AI 在桌面一生成并由用户安装到 `$STATE/focus-panel/revisions/1/canvas.json`。启用时设置区出现一项个人开关；当前值未写入时显示可用缺省。用户选中提交，代理比对键归属与值类型，可信端显示旧值、新值和写入范围。放行后保存个人 JSON，绑定刷新，界面显示新值。一个用户能新增这样的个人设置表单；真实系统级设置由核心拥有，换成未经授权的系统 key 会在安装或提案阶段失败。停用隐藏设置区，卸载按选择保留或清除个人项，其他画布和系统设置继续可见。

### 5.4 进程小窗

```json
{
  "schema": "aik-canvas/0",
  "meta": {"id": "build-window", "title": "构建进度", "revision": 1},
  "requires": ["app-view"],
  "pages": [{"id": "main", "title": "构建器", "columns": 6, "items": [
    {"id": "build", "type": "process-view", "label": "构建器状态", "rect": [0,0,6,4], "view": {"bind": "builder"}, "pin_action": "pin-builder"}
  ]}],
  "bindings": [{"id": "builder", "source": "app.view", "params": {"app": "builder", "slot": "progress"}, "as": "record"}],
  "actions": [{"id": "pin-builder", "target": "app.pin", "args": {"app": "builder", "slot": "progress"}}]
}
```

示例假定 `builder` 已由同账户登记为 `progress` 的发布者。桌面一生成文件，安装到 `$STATE/build-window/revisions/1/canvas.json`。启用时绑定验证提供者 UID 后呈现进度或离线。点击固定通过确认面展示应用、视图槽以及个人固定数据改动，准许后显示固定角标。发布者退出则保留“离线”占位，重新登记同槽后更新。停用取消订阅，卸载移除挂载记录或按选择保留原稿；进程生命周期由应用自身管理。

## 6. 错误码全表

| code | 条件 | 呈现或处理 |
|---|---|---|
| `C_BAD_JSON` | 编码、语法、重复键或文件末尾不完整 | 提示位置并拒绝新版本 |
| `C_VERSION` | schema 不支持 | 保留旧版，指明可读版本 |
| `C_REQUIRED` | 缺字段或运行能力 | 标出 JSON Pointer 与能力 |
| `C_FIELD` | 未知字段、枚举或类型不符 | 标出字段 |
| `C_LIMIT` | 限额超出 | 停止读取或拒绝安装 |
| `C_LAYOUT` | 组件重叠或越界 | 标出页面与组件 |
| `C_REF` | 重复或缺失引用、来源投影不合法 | 拒绝启用 |
| `C_CONFLICT` | 修订、清单摘要或状态发生冲突 | 重读并重新审核 |
| `C_DENIED` | 归属、授权或隐私投影不通过 | 隐藏数据或拒绝动作 |
| `C_SOURCE_UNAVAILABLE` | 服务、文件、导出程序离线 | 显示不可用，按刷新周期恢复 |
| `C_SOURCE_TYPE` | 动态输出与类型不符 | 不更新当前值，提示来源错误 |
| `C_SOURCE_STALE` | 超时、事件缺口或刷新失败 | 标注时间，重新取快照 |
| `C_ACTION_INVALID` | 动作或值不在登记范围 | 拒绝提交 |
| `C_ACTION_DENIED` | 无确认端、确认拒绝、超时或策略阻断 | 关闭等待状态，显示原因 |
| `C_ACTION_FAILED` | 适配器执行失败或结果不确定 | 显示 OCC 原错误码与操作号，必要时查询 |
| `C_STATE_IO` | 安装、提交或复位持久化失败 | 恢复上个版本并提示 |
| `C_NO_TEMPLATE` | 没有可用的工厂模板 | 保留当前状态，提示可停用或卸载 |

## 未决问题

- DSK-05 定视图发布者登记、进程标识稳定性、生命周期与输入法交接。纸面例按只读发布记录验收。
- MEM-04 给出逐主体召回契约；等待该能力时 canvas memory 绑定不可用。
- DSK-03/06 接通动作代理、独立授权清单与审计，并验证更新撤权、异常中断、无头调用和组件复位无越界副作用。
