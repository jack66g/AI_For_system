/*
 * ai_lang.h - UI 层双语（中/英）文案表接口（i18n）
 *
 * 设计：
 *   - 所有用户可见 UI 文案一律经 tr(key) 查表取得，禁止在 .c 中
 *     硬编码中文字符串（W17-H 出厂双语化纪律；协议标记除外，
 *     如会话摘要钉住标记 "[历史摘要]"——跨语言解析一致性优先）。
 *   - 语言来源优先级（lang_init 解析一次，lang_set 运行时切换）：
 *       1. 环境变量 AIKERNEL_LANG（"zh"/"en"，非法值忽略）
 *       2. model.toml [ui] lang = "zh"|"en"（config_manager 解析）
 *       3. 缺省 zh（中文为出厂默认语言）
 *   - 持久化：lang 命令切换时写回 cfg->ui.lang 并 ai_config_save()。
 *   - 模型面 system 提示词同样双语（en 模式下指示模型用英文回答）。
 */
#ifndef _AI_LANG_H
#define _AI_LANG_H

#define AI_LANG_ZH  "zh"
#define AI_LANG_EN  "en"

/*
 * 翻译键枚举（tr() 索引）。
 * 新增文案：此处加键 → i18n/lang.c 两张表各补一条。
 */
enum ai_tr_key {
	/* ---- 横幅/REPL 框架（aikernel_main.c / shell.c） ---- */
	TR_BANNER_KERNEL,		/* 内核版本行 */
	TR_BANNER_AI_STARTING,		/* AI 运行时启动中 */
	TR_BANNER_KAI_READY,		/* 内核 AI 接口就绪 */
	TR_BANNER_CLOUD_CFG,		/* 云端 Provider 已配置(%s) */
	TR_BANNER_CLOUD_NOTCFG,		/* 云端 Provider 未配置 */
	TR_BANNER_LOCAL_CFG,		/* 本地 Provider 已配置(%s) */
	TR_BANNER_LOCAL_NOTCFG,		/* 本地 Provider 未配置 */
	TR_BANNER_NO_KAI,		/* 内核 AI 接口不可用 */
	TR_BANNER_HINT,			/* help/exit 提示 */
	TR_REPL_UNKNOWN,		/* 未知命令 %s */
	TR_REPL_REJECT_LINE,		/* 单行超限 %zu/%d */
	TR_REPL_REJECT_TAIL,		/* 未换行残余超限 %zu/%d */
	TR_REPL_QUEUED,			/* (排队输入) */
	TR_REPL_ASK_HINT,		/* 直说转 ask 首次轻提示（P0-1） */
	TR_VERBOSE_ANNOUNCE,		/* verbose 切换播报 %s %s */
	TR_VERBOSE_EXPANDED,		/* 全展开 */
	TR_VERBOSE_COLLAPSED,		/* 折叠 */
	TR_ERR_CONFIG_INIT,		/* 配置初始化失败 */
	TR_ERR_P_QUESTION,		/* -p 缺问题 */
	TR_USAGE_FMT,			/* 命令行用法 %s %d %d */
	TR_SHELL_FIRST_RUN,		/* 首次运行未配模型（shell.c） */
	TR_SHELL_SUGGEST,		/* 建议命令 model add */

	/* ---- help（cmd_help.c） ---- */
	TR_HELP_TITLE,			/* 子系统标题 */
	TR_HELP_AVAIL,			/* 可用命令 */
	TR_HELP_CMDHDR,			/* 表头：命令 */
	TR_HELP_DESCHDR,		/* 表头：说明 */
	TR_HELP_DETAIL_ONE,		/* 单命令详情 %s %s %s */
	TR_HELP_DETAIL,			/* help <command> 尾提示 */
	TR_HELP_UNKNOWN,		/* 未知命令 %s */

	/* ---- lang 命令（cmd_lang.c） ---- */
	TR_LANG_CURRENT,		/* 当前语言 %s */
	TR_LANG_SWITCHED,		/* 切换完成（双语固定输出） */
	TR_LANG_USAGE,			/* lang 命令用法 */
	TR_LANG_INVALID,		/* 非法语言参数 %s */
	TR_LANG_SAVE_FAIL,		/* 持久化失败警告 */

	/* ---- W2 确认面板与权限（ai_user_policy.c） ---- */
	TR_W2_AUTO_YES,			/* --yes 预授权 %s */
	TR_W2_NO_TTY,			/* 非终端拒绝确认 */
	TR_W2_PANEL,			/* 确认面板 %s %s %s */
	TR_W2_CONFIRM,			/* 确认执行? [y/N] */
	TR_W2_STALE_INPUT,		/* W20 修4：陈旧输入非本确认应答 */
	TR_W2_IMPACT_FALLBACK,		/* 影响描述缺省 (见工具描述) */
	TR_W2_DENY,			/* 权限不足需 root */
	TR_POLICY_CONF_UNREAD,		/* 配置不可读回落 %s %s */
	TR_POLICY_CONF_NO_BRACKET,	/* 段头缺少 ']' %s %d */
	TR_POLICY_CONF_NO_EQ,		/* 缺少 '=' %s %d */
	TR_POLICY_AUDIT_NO_HOME,	/* 无家目录可写审计 */
	TR_POLICY_AUDIT_MKDIR,		/* mkdir 失败 %s %s */
	TR_POLICY_AUDIT_OPEN,		/* open 失败 %s %s */
	TR_POLICY_AUDIT_FLOCK,		/* flock 失败 %s %s */
	TR_POLICY_AUDIT_WRITE,		/* 审计写失败 %s */

	/* ---- onboarding（cmd_onboarding.c） ---- */
	TR_OB_SYS_PROMPT,		/* 引导 system 提示词（模型面） */
	TR_OB_HIDDEN_NEED_TTY,		/* setup-password 需 tty */
	TR_OB_PW_PROMPT1,		/* 请输入新密码 */
	TR_OB_PW_PROMPT2,		/* 请再次输入确认 */
	TR_OB_PW_EMPTY,			/* 密码不能为空 */
	TR_OB_PW_TOO_SHORT,		/* 密码至少 6 位 */
	TR_OB_PW_MISMATCH,		/* 两次输入不一致 */
	TR_OB_PW_SETTING,		/* 正在设置 root 密码 */
	TR_OB_PW_OK,			/* root 密码设置成功 */
	TR_OB_PW_FAIL,			/* 密码设置失败 */
	TR_OB_LOCAL_NO_BASEURL,		/* model.toml 缺 [local].base_url */
	TR_OB_LOCAL_PROBING,		/* 正在探测本地模型服务 %s */
	TR_OB_LOCAL_UNREACH,		/* 本地模型服务不可达 */
	TR_OB_LOCAL_OK,			/* 本地模型服务可达 */
	TR_OB_CLOUD_ASK_URL,		/* 请输入云端 base_url */
	TR_OB_URL_EMPTY,		/* base_url 不能为空 */
	TR_OB_CLOUD_ASK_KEY,		/* 请输入 API Key */
	TR_OB_CLOUD_ASK_MODEL,		/* 请输入模型名 */
	TR_OB_MODEL_EMPTY,		/* 模型名不能为空 */
	TR_OB_PROBING,			/* 正在测试端点连通性 */
	TR_OB_ENDPOINT_UNREACH,		/* 端点不可达 */
	TR_OB_ENDPOINT_OK,		/* 端点可达写配置 */
	TR_OB_WRITE_FAIL,		/* 写入模型配置失败 */
	TR_OB_SWITCH_FAIL,		/* 配置已写入但切换失败 */
	TR_OB_MARK_FAIL,		/* 无法写入 %s（%s） */
	TR_OB_HEAD,			/* === 初始化引导 === */
	TR_OB_HINT1,			/* 流程说明行 */
	TR_OB_HINT2,			/* help/密码说明行 */
	TR_OB_WELCOME_ASK,		/* 开场白指令（模型面） */
	TR_OB_WELCOME_FALLBACK,		/* 开场白降级文案 */
	TR_OB_HELP,			/* 引导命令清单 */
	TR_OB_PW_FIRST,			/* 请先完成密码设置 */
	TR_OB_PW_DONE_ASK,		/* 密码成功后的第二步指令（模型面） */
	TR_OB_PW_DONE_FALLBACK,		/* 密码成功降级文案 */
	TR_OB_PW_FAIL_ASK,		/* 密码失败提醒指令（模型面） */
	TR_OB_PW_FAIL_FALLBACK,		/* 密码失败降级文案 */
	TR_OB_STEP1_CHAT_FALLBACK,	/* 步骤1游离对话拉回 */
	TR_OB_STEP2_HELP,		/* 步骤2帮助 */
	TR_OB_LOCAL_FAIL_ASK,		/* 本地不可达转云端指令（模型面） */
	TR_OB_LOCAL_FAIL_FALLBACK,	/* 本地不可达降级文案 */
	TR_OB_STEP2_CHAT_FALLBACK,	/* 步骤2游离对话拉回 */
	TR_OB_DONE_ASK,			/* 完成祝贺指令（模型面） */
	TR_OB_DONE_FALLBACK,		/* 完成降级文案 */
	TR_OB_DONE,			/* === 初始化完成 === */

	/* ---- ask 主流程（cmd_ask.c） ---- */
	TR_ASK_SYS_IDENTITY,		/* system：身份（模型面） */
	TR_ASK_SYS_RETRIEVAL,		/* system：检索指引（模型面） */
	TR_ASK_SYS_RULES_SHORT,		/* system：精简约束（模型面） */
	TR_ASK_SYS_RULES,		/* system：降级全量约束（模型面） */
	TR_ASK_FALLBACK_RULES,		/* system：降级 JSON 协议（模型面） */
	TR_ASK_SYS_ASSUME_YES,		/* system：assume_yes 预授权（模型面） */
	TR_ASK_SYS_LANGUAGE,		/* system：语言默认（模型面） */
	TR_ASK_TOOLS_LIST_FMT,		/* 可用工具清单 %s%s%s */
	TR_ASK_CATALOG_HDR,		/* 工具目录头 */
	TR_ASK_SENSE_FMT,		/* 遥测注入 %u %.*s */
	TR_ASK_STATUS_FMT,		/* 内核状态紧凑摘要注入 %s（≤2KB） */
	TR_ASK_STATUS_NOTE,		/* sampled_skip/dropped 语义说明（模型面） */
	TR_ASK_STATUS_DROPPED_NOTE,	/* 摘要 dropped 口径 %s=增量后缀 */
	TR_ASK_STATUS_SKIP_NOTE,	/* 摘要 sampled_skip 口径（无参数） */
	TR_ASK_STATUS_DELTA_FMT,	/* 与上次摘要的增量 %llu */
	TR_ASK_MEM_FMT,			/* 记忆注入 %s */
	TR_ASK_UNKNOWN_TOOL,		/* 未知工具 %s（模型面） */
	TR_ASK_EMPTY,			/* (空) */
	TR_ASK_TC_VERBOSE,		/* [工具调用] %s(%s) */
	TR_ASK_TR_VERBOSE,		/* [工具结果%s] %s%s */
	TR_ASK_TRUNCATED,		/* ...(截断) */
	TR_ASK_MORE_LINES,		/* [+%d 行 verbose 查看全文] */
	TR_ASK_NO_EXEC_OUTPUT,		/* (执行器无输出) */
	TR_ASK_LIST_SEP,		/* 列表分隔符 、/, */
	TR_ASK_ROUTER_MERGED,		/* 框架提示激活 %d %s（模型面，native） */
	TR_ASK_ROUTER_MERGED_TEXT,	/* 框架提示激活 %d %s（模型面，文本协议） */
	TR_ASK_ROUTER_ACT_UI,		/* [router] 检索激活 +%d */
	TR_ASK_TOOL_RESULT_FMT,		/* [TOOL %s RESULT] 回填（模型面） */
	TR_ASK_USAGE,			/* ask 用法 */
	TR_ASK_USAGE_EX,		/* ask 示例 */
	TR_ASK_REG_FAIL,		/* 注册表加载失败 */
	TR_ASK_USER_TASK_FMT,		/* 用户任务：%s */
	TR_ASK_HEADER_FMT,		/* ask 头部 %s%d%d%s%d%s%d */
	TR_ROUTE_PRE_LABEL,		/* pre_retrieve 标签 */
	TR_ROUTE_AUTO_LABEL,		/* autonomous 标签 */
	TR_ASK_TRIM_FMT,		/* 历史窗口裁剪 %d%d%d */
	TR_ASK_CTX_SENSE,		/* 上下文: 遥测已注入 */
	TR_ASK_CTX_STATUS,		/* 上下文: 内核状态摘要已注入 */
	TR_ASK_CTX_MEM,			/* 上下文: SME 已注入 top%d */
	TR_ASK_TOOLS_EXPANDED,		/* [router] tools 扩入 %d/%d */
	TR_ASK_ROUND_FMT,		/* [第 %d 轮] */
	TR_ASK_FALLBACK_RETRY,		/* 降级重试提示 */
	TR_ASK_MODEL_FAIL,		/* 模型调用失败 %s */
	TR_ASK_NO_RESULT,		/* 模型未返回结果 */
	TR_ASK_TRUNC_WARN,		/* max_tokens 截断警告 */
	TR_ASK_TC_REQ,			/* 模型请求 %d 个工具调用 */
	TR_ASK_FALLBACK_TC,		/* 降级模式解析到工具调用 */
	TR_ASK_SWITCH_FALLBACK,		/* 切换文本约定模式 */
	TR_ASK_EMPTY_ANSWER,		/* (空回答) */
	TR_ASK_MAX_ROUNDS,		/* 已达最大轮数 %d */
	TR_ASK_CTX_WARN,		/* 上下文预算 %d%% 警告 */
	TR_ASK_TOOL_SUMMARY_FMT,	/* 工具结果摘要标注（模型面）%ld%d%s */
	TR_ASK_TOOL_SUMMARY_UI,		/* 工具结果摘要 UI 提示 %s%s%ld%d%ld%s */
	TR_ASK_AUTOCOMPACT_TRY,		/* 自动压缩尝试提示 %s%s */
	TR_ASK_AUTOCOMPACT,		/* 历史已自动压缩（P0-2b） */
	TR_ASK_AUTOCOMPACT_FAIL,	/* 自动压缩失败 %s%s%s */
	TR_ASK_COMPACT_COOLDOWN,	/* W72 压缩冷却 %s%d%d%s */
	TR_ASK_MAX_ROUNDS_FINAL,	/* W72 触顶后收尾请求 %d */
	TR_ASK_FINAL_HINT,		/* W72 收尾提示（模型面，无参数） */

	/* ---- status（cmd_status.c） ---- */
	TR_ST_STREAMING_FMT,		/* streaming 行 %s */
	TR_ST_SME,			/* memory(SME) 行 */

	/* ---- config（cmd_config.c） ---- */
	TR_CFG_MODEL_LABEL,		/* 模型 标签 */
	TR_CFG_MODEL_FMT,		/* %s（默认 %s） */
	TR_CFG_NOTLOADED,		/* (未加载) */
	TR_CFG_NOTSET,			/* (未设置) */
	TR_CFG_USAGE_FMT,		/* usage 行 %s%s%s%s%d%s%s */
	TR_CFG_EST,			/* (估算) */
	TR_CFG_KEYS_HINT,		/* Keys: 行 */
	TR_CFG_CTX_POSINT,		/* ctx_len 需正整数 */
	TR_CFG_CTX_CLAMP,		/* 窗口钳制 %s%d%d%d */
	TR_CFG_MT_RANGE,		/* max_tokens 范围 */
	TR_CFG_STREAM_VAL,		/* stream 取值 on|off */
	TR_CFG_STREAM_NOCOMP,		/* stream 未编译 */
	TR_CFG_LOCALAPI_VAL,		/* local_api 取值 */
	TR_CFG_BOOL_VAL,		/* %s 取值 on|off */
	TR_CFG_BAD_SESSION,		/* 非法会话名 %s */
	TR_CFG_SESSION_NMSG,		/* session = %s（%d 条） */
	TR_CFG_SET_USAGE,		/* config set 用法 */

	/* ---- shell（cmd_shell.c） ---- */
	TR_SH_NOT_TTY,			/* 非交互终端拒绝 */
	TR_SH_ENTER,			/* 进入维护 shell */
	TR_SH_FORK_FAIL,		/* fork 失败 %s */
	TR_SH_EXEC_FAIL,		/* 无法启动 bash %s */
	TR_SH_START_FAIL,		/* bash 启动失败 */
	TR_SH_RETURN,			/* 已返回 AI 控制台 */

	/* ---- netlink（cmd_netlink.c） ---- */
	TR_NL_HELP_SENSE,		/* help: sense 行 */
	TR_NL_HELP_ACT,			/* help: act 行 */
	TR_NL_HELP_REG,			/* help: reg 行 */
	TR_NL_HELP_COUNT,		/* help: count 行 */
	TR_NL_HELP_HEXDATA,		/* help: hexdata 行 */
	TR_NL_KERN_REJECT,		/* 内核拒绝 %d %s */
	TR_NL_HINT,			/* 提示: %s */
	TR_NL_SEND_FAIL,		/* 传输失败 %s */
	TR_NL_PARSE_FAIL,		/* 应答解析失败 */
	TR_NL_ERR,			/* 错误: %s */
	TR_NL_INIT_FAIL,		/* socket 初始化失败 %s */
	TR_NL_ALLOC_FAIL,		/* 内存分配失败 %u */
	TR_NL_NO_RECORDS,		/* (无记录) */
	TR_NL_ACT_CONFIRM1,		/* 即将向内核下发决策 */
	TR_NL_ACT_CONFIRM2,		/* domain 行 %u%s%u%u%zu */
	TR_NL_ACT_CONFIRM3,		/* CAP_SYS_ADMIN 确认执行 */
	TR_NL_CANCELLED,		/* 已取消 */
	TR_NL_ACK_AIERR,		/* ai_err %d */
	TR_NL_ACK_NO_POLICY,		/* 未命中任何策略 */
	TR_NL_REG_PORTID,		/* Portid %u */
	TR_NL_REG_COUNT,		/* 已登记 portid 数 %u/32 */
	TR_NL_REG_IDEMPOTENT,		/* reg 幂等说明 */
	TR_NL_REG_NOARGS,		/* reg 不接受参数 */

	/* ---- session（cmd_session.c） ---- */
	TR_SES_BAD_NAME,		/* 非法会话名 %s */
	TR_SES_EXISTS_SWITCH,		/* 会话已存在切换 %s */
	TR_SES_CREATE_FAIL,		/* 创建失败 %s */
	TR_SES_CREATED,			/* 已创建并切换 %s */
	TR_SES_LIST_EMPTY,		/* 无会话文件 %s */
	TR_SES_LIST_HDR,		/* 表头行格式 */
	TR_SES_HDR_NAME,		/* 表头：会话 */
	TR_SES_HDR_COUNT,		/* 表头：消息数 */
	TR_SES_RANGE,			/* 序号超范围 1-%d */
	TR_SES_BAD_TARGET,		/* 非法目标 %s */
	TR_SES_ALREADY_IN,		/* 已在会话 %s */
	TR_SES_SWITCHED,		/* 已切换 %s %d */
	TR_SES_LOAD_FAIL,		/* 加载失败 %s */
	TR_SES_SHOW,			/* 会话 %s：%d 条消息 */
	TR_SES_HELP_NEW,		/* help: new */
	TR_SES_HELP_LIST,		/* help: list */
	TR_SES_HELP_SWITCH,		/* help: switch */
	TR_SES_HELP_SAVE,		/* help: save */
	TR_SES_HELP_DELETE,		/* help: delete */
	TR_SES_HELP_SHOW,		/* help: show */
	TR_SES_SAVED,			/* 已落盘 %s %d */
	TR_SES_DEL_CURRENT,		/* 不能删除当前会话 */
	TR_SES_DELETED,			/* 已删除会话 %s */
	TR_SES_DELETE_FAIL,		/* 删除失败 %s */

	/* ---- compact（cmd_compact.c） ---- */
	TR_CMP_LOAD_FAIL,		/* 会话加载失败 %s */
	TR_CMP_EMPTY,			/* 无历史无需压缩 %s */
	TR_CMP_CAP,			/* 历史超限仅压缩 %d%d */
	TR_CMP_TAG_TOOLCALL,		/* [发起工具调用] */
	TR_CMP_TAG_TOOLRESULT,		/* [工具结果] */
	TR_CMP_PROMPT,			/* 压缩指令（模型面） %s */
	TR_CMP_SYS_PROMPT,		/* 摘要助手 system（模型面） */
	TR_CMP_RUNNING,			/* 压缩中 %s%d%zu */
	TR_CMP_SUM_FAIL,		/* 摘要失败 %s */
	TR_CMP_CLEAR_FAIL,		/* 会话清空失败 %s */
	TR_CMP_WRITE_FAIL,		/* 摘要写入失败 %s */
	TR_CMP_FALLBACK,		/* W20 修2：摘要失败降级裁剪 %d 轮 */
	TR_CMP_DONE,			/* 完成压缩 %d 条最近消息%s */
	TR_CMP_TRUNC,			/* W59：摘要失败降级为预算内截断 %s */
	TR_CMP_GUARD,			/* W59：连续压缩上限，仅截断 %s */

	/* ---- W42：隔离区 + 子智能体（executor.c sandbox 通道） ---- */
	TR_SB_CREATED,		/* 隔离区已建立（无参数） */
	TR_SB_SPAWN_START,	/* 子智能体已派入隔离区（无参数） */
	TR_SB_DONE,		/* 沙盒任务结束 %s=区 %d=耗时s %d=派发退出码 %s=状态 */
	TR_SB_TIMEOUT,		/* 沙盒任务超时击杀 %s=区 %d=预算s */
	TR_SB_DESTROYED,	/* 隔离区已焚毁（无参数） */
	TR_SB_TAIL_HDR,		/* 子智能体输出尾部标题（无参数） */
	TR_SB_DESTROY_REMIND,	/* spawn 完成提醒（%s=区名） */

	/* ---- 命令帮助描述（commands_registry 描述的中文对；en 用注册表原文） ---- */
	TR_CMD_HELP,			/* help 描述 */
	TR_CMD_EXIT,			/* exit */
	TR_CMD_STATUS,			/* status */
	TR_CMD_CONFIG,			/* config */
	TR_CMD_CHAT,			/* chat */
	TR_CMD_ASK,			/* ask */
	TR_CMD_MODEL,			/* model */
	TR_CMD_NETWORK,			/* network */
	TR_CMD_NETLINK,			/* netlink */
	TR_CMD_SESSION,			/* session */
	TR_CMD_COMPACT,			/* compact */
	TR_CMD_SETUP_PASSWORD,		/* setup-password */
	TR_CMD_SHELL,			/* shell */
	TR_CMD_LANG,			/* lang */

	/* ---- W43：plan 只读模式 ---- */
	TR_PLAN_ON,		/* 已进入 plan 模式（无参数） */
	TR_PLAN_OFF,		/* 已退出 plan 模式（无参数） */
	TR_PLAN_DENY,		/* plan 拒绝写工具 %s=工具名 %s=风险级 */
	TR_PLAN_SYS_NOTE,	/* plan 模式 system 提示注入段（无参数） */

	/* ---- W43：slash 命令（/tools /session /sandbox） ---- */
	TR_TOOLS_HDR,		/* /tools 表头（无参数） */
	TR_TOOLS_ROW,		/* /tools 行 %d=序号 %s=名 %s=通道 %s=风险 %s=描述 */
	TR_TOOLS_TOTAL,	/* /tools 合计 %d=命中 %d=总数 */
	TR_TOOLS_FILTER,	/* /tools 过滤词 %s */
	TR_TOOLS_EMPTY,	/* /tools 无匹配 %s=过滤词 */
	TR_SANDBOX_USAGE,	/* /sandbox 用法（无参数） */
	TR_REPL_SLASH_UNKNOWN,	/* 未知 slash 命令 %s */
	TR_SES_STATUS_HDR,	/* /session 状态 %s=会话名 %d=条数 */
	TR_SME_REACHABLE,	/* SME 可达（无参数） */
	TR_SME_UNREACHABLE,	/* SME 不可达（无参数） */

	/* ---- W43：SME 失忆降级 ---- */
	TR_SME_DEGRADED_NOTE,	/* 记忆服务不可达附注（工具结果回填用） */

	/* ---- W43：命令描述中文对（tr_cmd_desc） ---- */
	TR_CMD_PLAN,		/* plan */
	TR_CMD_UNPLAN,		/* unplan */
	TR_CMD_TOOLS,		/* tools */
	TR_CMD_SANDBOX,		/* sandbox */

	/* ---- W65：Ctrl-C 取消 / 参数契约自动纠正 / --version ----
	 * 追加在枚举末尾：不移动任何既有键的数值，避免旧 .o 的
	 * tr(KEY) 索引与新表错位（P2 串线事故同类风险）。 */
	TR_ASK_CANCELLED,	/* 生成取消提示 %s %s（颜色） */
	TR_ASK_ARG_REPAIR,	/* 参数自动重试提示 %s %s（颜色） */
	TR_ASK_ARG_REPAIR_HINT,	/* 回填给模型的修复指令（无参数） */
	TR_VERSION_FMT,		/* --version %s=版本 %s=内核 release */

	/* ---- W74：授权租约 / D0-D4 确认 ---- */
	TR_LEASE_PANEL,		/* 确认面板 %s=工具 %s=D级 %s=租约 %s=影响 %s=回滚 */
	TR_LEASE_CONFIRM_YN,	/* 继续执行? [y/N] */
	TR_LEASE_D4_PROMPT,	/* D4 短语提示 %s=工具名 */
	TR_LEASE_D4_MISMATCH,	/* D4 短语不匹配 */
	TR_LEASE_ROLLBACK_D2,	/* D2 回滚提示 */
	TR_LEASE_ROLLBACK_D3,	/* D3 回滚提示 */
	TR_LEASE_ROLLBACK_D4,	/* D4 回滚提示 */
	TR_LEASE_CONFIRM_QUESTION, /* 确认问句（JSON/面板） */
	TR_LEASE_DENY_SCOPE,	/* 租约 scope 越界 */
	TR_LEASE_DENY_CEILING,	/* 租约 ceiling 越界 */
	TR_LEASE_DENY_EXPIRED,	/* 租约过期 */
	TR_LEASE_DENY_REVOKED,	/* 租约撤销 */
	TR_LEASE_DENY_PRINCIPAL, /* principal/属主不匹配 */
	TR_LEASE_DENY_LOAD,	/* 显式租约加载失败 */
	TR_LEASE_DENY_CONFIRM,	/* 确认凭证无效 */
	TR_LEASE_DENY_WORKER,	/* worker D2+ 拒绝 */
	TR_LEASE_DENY_D4_ROOT,	/* D4 仅 root 可确认 */
	TR_LEASE_CONFIRM_REQUIRED, /* 非 TTY 确认指引 */
	TR_LEASE_EPHEMERAL_NOTE, /* -y 短租约告警 */
	TR_LEASE_EXPLICIT_NOTE,	/* 显式租约加载成功 %s=id %s=ceiling %d=scope 数 */
	TR_LEASE_ERR_LOAD,	/* 租约错误 %s=原因 */
	TR_CMD_LEASE,		/* lease 命令描述 */
	TR_LEASE_CMD_USAGE,	/* /lease 用法 */
	TR_LEASE_ROOT_TTY,	/* 仅 root+TTY */
	TR_LEASE_ISSUE_PROMPT,	/* 签发确认 %s=id %s=scope %s=ceiling %ld=ttl %s=id */
	TR_LEASE_ISSUE_BAD,	/* 签发短语不匹配 */
	TR_LEASE_ISSUED,	/* 已签发 %s=id %s=path */
	TR_LEASE_REVOKE_PROMPT, /* 撤销确认 %s=id %s=id */
	TR_LEASE_REVOKE_BAD,	/* 撤销短语不匹配 */
	TR_LEASE_REVOKED,	/* 已撤销 %s=id */
	TR_LEASE_LIST_HDR,	/* list 表头 */
	TR_LEASE_LIST_ROW,	/* list 行 */
	TR_LEASE_LIST_EMPTY,	/* list 空 */
	TR_LEASE_SHOW_FMT,	/* show 详情（多参数） */
	TR_LEASE_PENDING_EMPTY,	/* 无 pending */
	TR_LEASE_PENDING_FMT,	/* pending 行 %s=nonce %s=tool %s=danger */
	TR_LEASE_CONFIRM_OK,	/* 确认已记录 %s=nonce %s=yes/no */
	TR_LEASE_CONFIRM_NO,	/* 已拒绝 %s=nonce */
	TR_LEASE_UNKNOWN_SUB,	/* 未知子命令 %s */
	TR_LEASE_STORE_ERR,	/* 存储错误 %s */

	TR__COUNT
};

/*
 * lang_init - 解析初始语言（AIKERNEL_LANG > cfg_lang > zh）
 * @cfg_lang: model.toml [ui] lang 值（可 NULL/空）
 * 返回: 生效语言（"zh"/"en"）
 */
const char *lang_init(const char *cfg_lang);

/*
 * lang_set - 运行时切换语言（"zh"/"en"；非法值忽略）
 */
void lang_set(const char *lang);

/*
 * lang_get - 当前语言（"zh"/"en"，静态存储不必 free）
 */
const char *lang_get(void);

/*
 * lang_is_zh - 当前是否中文（1=zh，0=en）
 */
int lang_is_zh(void);

/*
 * tr - 查当前语言文案（键越界返回空串防御）
 */
const char *tr(enum ai_tr_key key);

/*
 * tr_cmd_desc - 命令帮助描述翻译（按命令名查 TR_CMD_*）
 * 中文模式返回中文描述；英文模式返回 NULL（调用者回退注册表
 * 原文英文描述，保持单一来源）。未知命令名返回 NULL。
 */
const char *tr_cmd_desc(const char *name);

#endif /* _AI_LANG_H */
