// SPDX-License-Identifier: GPL-2.0
/*
 * lang.c - UI 层双语（中/英）文案表实现（i18n）
 *
 * 两张静态表（t_zh / t_en）+ 语言状态（g_zh）+ tr(key) 查询。
 * 语言来源优先级见 ai_lang.h：AIKERNEL_LANG > model.toml [ui] lang > zh。
 * 纪律（W17-H）：用户可见 UI 文案必须入表，.c 文件禁止硬编码中文
 * 字符串；协议标记（"[历史摘要]" 等跨语言解析锚点）除外。
 *
 * 命令描述：英文以 commands_registry.c 注册表原文为准（单一来源），
 * 中文对在表尾 TR_CMD_* 段；tr_cmd_desc() 按命令名查键。
 */
#include <stdlib.h>
#include <string.h>

#include "ai_lang.h"

/* ---- 语言状态（单线程 REPL，无需加锁） ---- */
static int g_zh = 1;		/* 1=中文（出厂默认），0=英文 */

const char *lang_get(void)
{
	return g_zh ? AI_LANG_ZH : AI_LANG_EN;
}

int lang_is_zh(void)
{
	return g_zh;
}

void lang_set(const char *lang)
{
	if (lang && strcmp(lang, AI_LANG_EN) == 0)
		g_zh = 0;
	else if (lang && strcmp(lang, AI_LANG_ZH) == 0)
		g_zh = 1;
	/* 其他值忽略：保持当前语言 */
}

const char *lang_init(const char *cfg_lang)
{
	const char *env = getenv("AIKERNEL_LANG");

	/* 优先级 1：环境变量（非法值忽略） */
	if (env && env[0] &&
	    (strcmp(env, AI_LANG_ZH) == 0 || strcmp(env, AI_LANG_EN) == 0)) {
		lang_set(env);
		return lang_get();
	}
	/* 优先级 2：model.toml [ui] lang（非法值忽略） */
	if (cfg_lang && cfg_lang[0] &&
	    (strcmp(cfg_lang, AI_LANG_ZH) == 0 ||
	     strcmp(cfg_lang, AI_LANG_EN) == 0)) {
		lang_set(cfg_lang);
		return lang_get();
	}
	/* 优先级 3：缺省中文 */
	lang_set(AI_LANG_ZH);
	return lang_get();
}

/* ---- 中文表 ---- */
static const char *const t_zh[TR__COUNT] = {
	/* 横幅/REPL 框架 */
	[TR_BANNER_KERNEL]		= "内核: Linux %s\n",
	[TR_BANNER_AI_STARTING]		= "AI 运行时启动中...\n",
	[TR_BANNER_KAI_READY]		= "内核 AI 接口        : 就绪\n",
	[TR_BANNER_CLOUD_CFG]		= "云端 Provider       : 已配置 (%s)\n",
	[TR_BANNER_CLOUD_NOTCFG]	= "云端 Provider       : 未配置"
					  " (使用 'model add')\n",
	[TR_BANNER_LOCAL_CFG]		= "本地 Provider       : 已配置 (%s)\n",
	[TR_BANNER_LOCAL_NOTCFG]	= "本地 Provider       : 未配置\n",
	[TR_BANNER_NO_KAI]		= "(内核 AI 接口不可用)\n",
	[TR_BANNER_HINT]		= "输入 'help' 查看命令，'exit' 退出。\n",
	[TR_REPL_UNKNOWN]		= "未知命令: %s\n"
					  "输入 'help' 查看可用命令。\n",
	[TR_REPL_REJECT_LINE]		= "(输入被拒绝: 单行 %zu 字节超过上限"
					  " %d)\n",
	[TR_REPL_REJECT_TAIL]		= "(输入被拒绝: 未换行残余 %zu 字节"
					  "超过上限 %d，已丢弃)\n",
	[TR_REPL_QUEUED]		= "(排队输入)",
	[TR_REPL_ASK_HINT]		= "[对话模式：直接输入即向 AI 提问，"
					  "命令请输 help]\n",
	[TR_VERBOSE_ANNOUNCE]		= "(verbose: %s — 工具卡片将以%s形态显示，"
					  "也可用 config set verbose 切换)\n",
	[TR_VERBOSE_EXPANDED]		= "全展开",
	[TR_VERBOSE_COLLAPSED]		= "折叠",
	[TR_ERR_CONFIG_INIT]		= "错误: 配置初始化失败\n",
	[TR_ERR_P_QUESTION]		= "ai: -p 需要一个问题字符串\n",
	[TR_USAGE_FMT]			= "用法: %s [选项] [命令...]\n"
	"  -p, --prompt <问题>  单发模式：执行一次 ask 后退出\n"
	"  -c, --ctx <N>        上下文 token 预算"
	"（默认 %d，本地按模型上限钳制）\n"
	"  -m, --max-tokens <N> 单次生成上限（默认 %d）\n"
	"  -S, --no-stream      关闭流式输出\n"
	"  -s, --session <name> 指定会话（默认 default）\n"
	"  -C, --no-color       关闭 ANSI 颜色（NO_COLOR 同效）\n"
	"  -N, --no-onboarding  跳过首次初始化引导（维护/救援场景）\n"
	"  -P, --plan           启动即进入 plan 只读调研模式"
	"（等价 /plan）\n"
	"  -y, --yes            本次 ask 的 D2 短租约（1 小时；D3/D4\n"
	"                       仍需确认；环境变量 AIKERNEL_ASSUME_YES 同效）\n"
	"      --lease <id>     使用 Principal 签发的显式租约（加载失败即退出）\n"
	"      --confirm <nonce> 消费 /lease confirm 批准的确认（单次）\n"
	"  -V, --version        显示版本与内核信息\n"
	"  -h, --help           显示本帮助\n",
	[TR_SHELL_FIRST_RUN]		= "未配置 AI Provider。\n"
					  "请先配置一个模型。\n\n",
	[TR_SHELL_SUGGEST]		= "建议命令：\n  model add <name>\n",

	/* help */
	[TR_HELP_TITLE]			= "\nAIKernel - AI 子系统 Shell\n",
	[TR_HELP_AVAIL]			= "可用命令：\n\n",
	[TR_HELP_CMDHDR]		= "命令",
	[TR_HELP_DESCHDR]		= "说明",
	[TR_HELP_DETAIL_ONE]		= "命令: %s\n  %s\n用法: %s\n",
	[TR_HELP_DETAIL]		= "\n输入 'help <命令>' 查看详细用法。\n\n",
	[TR_HELP_UNKNOWN]		= "未知命令: %s\n",

	/* lang */
	[TR_LANG_CURRENT]		= "当前语言: %s（切换: lang zh | lang en）\n",
	[TR_LANG_SWITCHED]		= "语言已切换。Language switched.\n"
					  "→ 中文界面（输入 lang en 切换英文）\n",
	[TR_LANG_USAGE]			= "用法: lang [zh|en]  显示/切换界面语言\n",
	[TR_LANG_INVALID]		= "lang: 未知语言 '%s'（可选 zh | en）\n",
	[TR_LANG_SAVE_FAIL]		= "警告: 语言偏好写回 model.toml 失败，"
					  "重启后可能恢复原语言。\n",

	/* W2 与权限 */
	[TR_W2_AUTO_YES]		= "[W2] %s 已按 --yes/AIKERNEL_ASSUME_YES "
					  "预授权，自动确认\n",
	[TR_W2_NO_TTY]			= "ai_policy: NEED_CONFIRM 高影响操作需要交互"
					  "确认，当前 stdin 非终端、无法弹出"
					  "确认面板，已按安全策略拒绝。请在"
					  "交互会话中操作，或走 /act "
					  "confirm=true 结构化接口\n",
	[TR_W2_PANEL]			= "\033[1;31m[W2 高影响操作 需要确认]\033[0m\n"
					  "\033[1;31m  工具: %s\033[0m\n"
					  "\033[1;31m  参数: %s\033[0m\n"
					  "\033[1;31m  影响: %s\033[0m\n",
	[TR_W2_CONFIRM]			= "确认执行? [y/N] ",
	[TR_W2_STALE_INPUT]		= "[W2] 面板前已有滞留输入：单键应答按预授权/预拒绝判定，"
					  "其他输入行已忽略（本次确认按拒绝处理）\n",
	[TR_W2_IMPACT_FALLBACK]		= "(见工具描述)",
	[TR_W2_DENY]			= "权限不足：该操作需要 root（sudo ai）\n",
	[TR_POLICY_CONF_UNREAD]		= "ai_policy: 配置 %s 不可读（%s），"
					  "回落 restricted 兜底\n",
	[TR_POLICY_CONF_NO_BRACKET]	= "ai_policy: %s:%d 段头缺少 ']'，忽略\n",
	[TR_POLICY_CONF_NO_EQ]		= "ai_policy: %s:%d 缺少 '='，忽略\n",
	[TR_POLICY_AUDIT_NO_HOME]	= "ai_policy: 无家目录可写审计\n",
	[TR_POLICY_AUDIT_MKDIR]		= "ai_policy: mkdir %s: %s\n",
	[TR_POLICY_AUDIT_OPEN]		= "ai_policy: open %s: %s\n",
	[TR_POLICY_AUDIT_FLOCK]		= "ai_policy: flock %s: %s\n",
	[TR_POLICY_AUDIT_WRITE]		= "ai_policy: write 审计失败: %s\n",

	/* onboarding */
	[TR_OB_SYS_PROMPT] =
	"你是 AIKernel OS 的初始化引导助手。你正通过本机控制台引导用户完成"
	"这台机器的首次初始化。你要做三件事：1) 简短自我介绍：你是这台机器"
	"的 AI 控制台，负责系统监控、参数调优和运维辅助；2) 引导用户设置"
	"root 密码：请用户输入命令 setup-password，并说明密码输入不回显、"
	"你不会看到密码内容；3) 引导用户选择 AI 模型来源：回复 1 选择本地"
	"模型（机器内置 ollama），回复 2 选择云端 API。规则：每次回复不超过"
	"3 句话，用中文；不要编造系统状态；涉及系统接口、参数或用法的提问"
	"先查记忆库（memory_search，含 aikernel-interface 接口语料）再回答，"
	"无工具可用时如实说明，不要凭空编造接口；不要透露或询问密码本身。",
	[TR_OB_HIDDEN_NEED_TTY]		= "setup-password: 需要交互终端（tty）"
					  "来安全输入密码。\n",
	[TR_OB_PW_PROMPT1]		= "请输入新密码（输入不回显）: ",
	[TR_OB_PW_PROMPT2]		= "请再次输入确认: ",
	[TR_OB_PW_EMPTY]		= "setup-password: 密码不能为空。\n",
	[TR_OB_PW_TOO_SHORT]		= "setup-password: 密码至少 6 位。\n",
	[TR_OB_PW_MISMATCH]		= "setup-password: 两次输入不一致。\n",
	[TR_OB_PW_SETTING]		= "setup-password: 正在设置 root 密码...\n",
	[TR_OB_PW_OK]			= "setup-password: root 密码设置成功。\n",
	[TR_OB_PW_FAIL]			= "setup-password: 密码设置失败"
					  "（chpasswd 执行出错）。\n",
	[TR_OB_LOCAL_NO_BASEURL]	= "onboarding: model.toml 缺少 "
					  "[local].base_url，无法自动配置"
					  "本地模型。\n",
	[TR_OB_LOCAL_PROBING]		= "onboarding: 正在探测本地模型服务 "
					  "%s ...\n",
	[TR_OB_LOCAL_UNREACH]		= "onboarding: 本地模型服务不可达"
					  "（ollama 未运行或模型未就绪）。\n",
	[TR_OB_LOCAL_OK]		= "onboarding: 本地模型服务可达。\n",
	[TR_OB_CLOUD_ASK_URL]		= "请输入云端 API base_url（如 "
					  "https://api.deepseek.com/v1，"
					  "或内部 OpenAI 兼容端点）:\n> ",
	[TR_OB_URL_EMPTY]		= "onboarding: base_url 不能为空。\n",
	[TR_OB_CLOUD_ASK_KEY]		= "请输入 API Key（输入不落盘、"
					  "不进模型上下文；无则回车跳过）:\n> ",
	[TR_OB_CLOUD_ASK_MODEL]		= "请输入模型名（如 deepseek-chat / "
					  "qwen2.5-7b-instruct）:\n> ",
	[TR_OB_MODEL_EMPTY]		= "onboarding: 模型名不能为空。\n",
	[TR_OB_PROBING]			= "onboarding: 正在测试端点连通性...\n",
	[TR_OB_ENDPOINT_UNREACH]	= "onboarding: 端点不可达，请检查地址/网络"
					  "后重试。\n",
	[TR_OB_ENDPOINT_OK]		= "onboarding: 端点可达，正在写入配置...\n",
	[TR_OB_WRITE_FAIL]		= "onboarding: 写入模型配置失败。\n",
	[TR_OB_SWITCH_FAIL]		= "onboarding: 配置已写入但切换失败，"
					  "可稍后 'model use cloud' 重试。\n",
	[TR_OB_MARK_FAIL]		= "onboarding: 无法写入 %s（%s）。\n",
	[TR_OB_HEAD]			= "\n=== AIKernel 初始化引导 (onboarding) ===\n",
	[TR_OB_HINT1]			= "提示：此流程将引导你设置 root 密码、配置云端"
					  "大模型（必经，含真实连通测试）；本地模型可选。\n",
	[TR_OB_HINT2]			= "      输入 help 可查看引导命令；"
					  "密码绝不经过 AI。\n\n",
	[TR_OB_WELCOME_ASK]		= "请向用户做开场自我介绍，并告诉他第一步是"
					  "设置 root 密码、请在提示符输入 "
					  "setup-password。",
	[TR_OB_WELCOME_FALLBACK]	= "[AI] 你好，我是这台机器的 AI 控制台"
					  "（AIKernel），负责系统监控、参数调优"
					  "与运维辅助。\n"
					  "初始化分两步：先设置 root 密码（输入命令 "
					  "setup-password，输入过程不回显，"
					  "我不会看到密码内容），再选择 AI 模型来源。",
	[TR_OB_HELP]			= "引导命令：\n"
					  "  setup-password  设置 root 密码（关回显，"
					  "两次确认，>=6 位）\n"
					  "  1 | local       选择本地模型\n"
					  "  2 | cloud       选择云端 API\n"
					  "  shell           进入维护 bash（逃生口，"
					  "exit 返回）\n"
					  "  其他任意文字    与引导 AI 对话\n",
	[TR_OB_PW_FIRST]		= "onboarding: 请先完成 root 密码设置"
					  "（输入 setup-password），再选择模型。\n",
	[TR_OB_PW_DONE_ASK]		= "用户已成功设置 root 密码。请引导进入第二步："
					  "配置云端大模型（输入 2 或 cloud 开始）。",
	[TR_OB_PW_DONE_FALLBACK]	= "[AI] root 密码已设置。第二步：配置云端"
					  "大模型（输入 2 或 cloud 开始；本地模型可稍后安装）。",
	[TR_OB_PW_FAIL_ASK]		= "用户的密码设置失败了（为空/不足6位/"
					  "两次不一致/chpasswd 出错）。请提醒他"
					  "重新输入 setup-password 再试。",
	[TR_OB_PW_FAIL_FALLBACK]	= "[AI] 密码未设置成功，"
					  "请重新输入 setup-password 再试一次。",
	[TR_OB_STEP1_CHAT_FALLBACK]	= "[AI] 现在请先输入 setup-password "
					  "设置 root 密码。",
	[TR_OB_STEP2_HELP]		= "输入 2 或 cloud 配置云端大模型（必经，真实"
					  "连通测试通过才算完成）；输入 shell 进入维护 bash。\n",
	[TR_OB_LOCAL_FAIL_ASK]		= "本地模型服务当前不可达。请告诉用户"
					  "可以先改用云端（输入 2），或稍后重启"
					  "机器等 ollama 就绪后重试（输入 1）。",
	[TR_OB_LOCAL_FAIL_FALLBACK]	= "[AI] 本地模型暂时不可用。"
					  "你可以输入 2 改用云端 API，"
					  "或稍后重试输入 1。",
	[TR_OB_STEP2_CHAT_FALLBACK]	= "[AI] 请输入 2 或 cloud 配置云端大模型。",
	[TR_OB_DONE_ASK]		= "初始化全部完成。请简短祝贺用户，"
					  "说明接下来就进入正常控制台，"
					  "可以直接输入 ask 向你提问。",
	[TR_OB_DONE_FALLBACK]		= "[AI] 初始化完成！即将进入 AI 控制台，"
					  "输入 help 查看命令，ask 后跟问题即可"
					  "向我提问。",
	[TR_OB_DONE]			= "\n=== 初始化完成，进入 AI 控制台 ===\n\n",
	[TR_OB_LANG_ASK]		= "界面语言 Interface language: "
					  "1=中文 2=English [1]: ",
	[TR_OB_CLOUD_PRESETS]		= "云端服务商预设（只预填地址，不内置任何 key）：\n"
					  "  1) deepseek      https://api.deepseek.com/v1\n"
					  "  2) qwen(dashscope) https://dashscope.aliyuncs.com/compatible-mode/v1\n"
					  "  3) doubao(ark)   https://ark.cn-beijing.volces.com/api/v3\n"
					  "  4) glm(zhipu)    https://open.bigmodel.cn/api/paas/v4\n"
					  "  5) openai 兼容/自定义\n",
	[TR_OB_CLOUD_PRESET_PROMPT]	= "选择服务商编号 [5]: ",
	[TR_OB_CLOUD_ASK_URL_DFLT]	= "请输入云端 API base_url [%s]: ",
	[TR_OB_CLOUD_LIVE_TEST]		= "onboarding: 正在真实连通测试"
					  "（发送 1-token 补全请求）...\n",
	[TR_OB_CLOUD_LIVE_OK]		= "onboarding: 连通测试通过，正在写入配置...\n",
	[TR_OB_CLOUD_LIVE_FAIL]		= "onboarding: 连通测试失败：%s\n",
	[TR_OB_CLOUD_RETRY_MENU]	= "重试请回车或输入 1；输入 2 跳过"
					  "（跳过则本次引导未完成，下次启动重新引导） [1]: ",
	[TR_OB_CLOUD_SKIPPED]		= "onboarding: 已跳过云端配置。引导未完成"
					  "（不写 %s），下次启动将再次引导。\n",
	[TR_OB_LOCAL_OPTIONAL]		= "本地模型是可选步骤：可稍后用 aik model "
					  "recommend/install，或直接在对话里让 AI 帮你安装。\n"
					  "现在安装请输入 1，跳过请回车 [跳过]: ",
	[TR_OB_LOCAL_TOP3]		= "本机推荐（硬件门控后的 top-3）：\n",
	[TR_OB_LOCAL_PICK]		= "选择要安装的编号 [1]: ",
	[TR_OB_LOCAL_INSTALL_CONFIRM]	= "将下载 %s（约 %gGB，写入磁盘）。确认继续？[y/N]: ",
	[TR_OB_LOCAL_INSTALL_FAIL]	= "安装失败（如实报告）：%s\n",
	[TR_OB_LOCAL_RETRY_MENU]	= "重试请输入 1；回车或输入 2 跳过本地步骤"
					  "（不影响引导完成） [2]: ",
	[TR_OB_LOCAL_SWITCH_ASK]	= "是否切换到本地模型？[y/N]: ",
	[TR_OB_LOCAL_INSTALLED_OK]	= "onboarding: %s 已安装并通过装后验证。\n",
	[TR_OB_LOCAL_NO_FIT]		= "onboarding: 本机内存/磁盘不满足目录中任何"
					  "模型的最低要求，可稍后 aik model catalog 查看。\n",

	/* ask 主流程 */
	[TR_ASK_SYS_IDENTITY] =
	"你是 AIKernel 系统管理员 AI（运行于 AIKernel Shell 的 ask 命令）。"
	"你的职责：通过调用工具完成用户对系统/内核的查询与操作请求。\n\n",
	[TR_ASK_SYS_RETRIEVAL] =
	"\n接口检索指引：\n"
	"你有 memory_search 工具（SME 语义检索，必填参数 text）。凡涉及"
	"系统接口、/proc/ai 与 /sys/kernel/ai 节点、内核参数、操作方式或"
	"工具用法的问题：先用 memory_search 检索（text 用中文关键词，如"
	"「进程优先级 调整」），依据命中内容再回答或行动，不要凭空猜测；"
	"未命中换词重试一次，仍无命中就如实说明。命中点名的工具（如 "
	"netlink_act_sched_nice）下一步可直接调用——框架会自动带上完整定义。"
	"检索激活工具后，若用户任务可直接推进，请立即调用（R/W1 直接做；"
	"W2 通常先确认，若提示词下方已声明 assume_yes 预授权则直接调用），"
	"不要只输出计划。\n",
	[TR_ASK_SYS_RULES_SHORT] =
	"\n约束：\n"
	"1. 只能调用请求 tools 数组中的工具，工具名一字不差；可一次调用"
	"多个。所需工具不在数组中时，先检索记忆库或如实告知，不要调用"
	"不存在的工具。\n"
	"2. 参数必须符合 schema 的名称与类型；不要编造工具结果。\n"
	"3. 执行类请求（调整/设置/冻结/下发/让路等）必须实际调用工具"
	"完成，不要只输出文字；给全必填参数（如 pid、value，用户提到 "
	"pid 就用该值）。\n"
	"4. 需要信息就先调用工具获取，拿到结果后再回答。\n"
	"5. 工具失败如实说明原因，修正参数后重试；默认用用户提问的"
	"语言回答（中文提问用中文），简洁准确。\n"
	"6. python3 执行代码属高影响操作（W2，通常需逐次确认；已声明 "
	"assume_yes 预授权时直接执行）：先把代码写为 .py 脚本"
	"（/root /tmp 下）再以 python3 <script.py> "
	"执行；沙盒/已授权靶场内允许，禁止对外攻击或未授权探测。\n"
	"7. 使用 sandbox_spawn 派活后，如无后续需要必须立即 sandbox_destroy <name> 焚区，不得留下隔离区。\n"
	"8. 排查内核错误、服务失败或“最近 N 分钟”日志时，必须先用 exec_run 执行 dmesg、journalctl 或 systemctl --failed，再结合遥测下结论；procfs/netlink 短窗口遥测不能替代日志，不得据此断言最近 N 分钟无错误。\n"
	"9. sysfs_get 只读 /sys、/proc/sys、/proc/irq、/proc/ai、/proc/pressure、/proc/net；/proc/<pid>/* 与 /etc/* 请用 exec_run（如 ps、cat）或对应专用工具，不要反复用 sysfs_get 试路径。\n"
	"10. 路径类任务必须严格使用用户给出的绝对路径（包括子目录），不要擅自改写到父目录或另起名字；写文件前先创建目标目录。\n"
	"\n询问纪律（何时问用户、何时不问）：\n"
	"1. 先查后问：答案能用只读工具（D0）自己查到的，禁止问用户。\n"
	"2. 只问影响结果的关键歧义：意图/目标/范围不明确、且不同理解会"
	"导致不同动作时才问；影响小或纯偏好的选合理默认并在回答中声明。\n"
	"3. 问必带推荐：每次 clarify 必须带 recommended 与 why；一次只问"
	"一个问题。\n"
	"4. 提问预算：单次任务链最多 2 问；到限后按最佳理解执行，并在"
	"回答开头声明假设（如「我按 X 理解执行，如不符请纠正」）。\n"
	"5. 不重复问：本会话已问过/用户已回答的不再问；用户表达过的偏好"
	"直接沿用。\n"
	"6. 澄清不等于授权：D2+ 危险动作一律走 lease/confirm，绝不用"
	"clarify 替代。\n"
	"7. 明确就执行：指令明确、证据唯一、或紧急诊断中，直接执行不问。\n"
,
	[TR_ASK_SYS_RULES] =
	"\n约束：\n"
	"1. 只能使用上面列出的工具，工具名必须一字不差；一次可以调用多个工具。\n"
	"2. 工具参数必须符合给出的名称与类型；不要调用不存在的工具，"
	"不要编造工具结果。\n"
	"3. 凡涉及系统接口、/proc/ai 与 /sys/kernel/ai 节点、内核参数、"
	"操作方式或工具用法的问题（怎么调、如何查看、如何配置），"
	"必须先用 memory.search 检索记忆库（含 aikernel-interface 接口语料），"
	"依据命中结果再回答或行动，不要凭空猜测接口用法。\n"
	"4. 执行类请求（调整/设置/冻结/下发/让路等）必须实际调用对应工具"
	"完成，不要只输出文字说明或命令示例；调用时必须给全必填参数"
	"（如目标进程 pid、目标取值 value，用户提到 pid 就用该值）。\n"
	"5. 需要信息就先调用工具获取，拿到全部需要的结果后再回答。\n"
	"6. 工具失败时如实说明失败原因，按提示修正参数后重试；"
	"回答默认使用用户提问的语言（中文提问用中文），简洁准确。\n"
	"7. python3 执行代码属高影响操作（W2，通常需逐次确认；已声明 "
	"assume_yes 预授权时直接执行）：先把"
	"代码写为 .py 脚本（/root /tmp 下）再以 python3 <script.py> "
	"执行，禁止 -c 裸表达式；沙盒/已授权靶场内允许，禁止对外攻击"
	"或未授权探测。\n"
	"8. 使用 sandbox_spawn 派活后，如无后续需要必须立即 sandbox_destroy <name> 焚区，不得留下隔离区。\n"
	"9. 排查内核错误、服务失败或“最近 N 分钟”日志时，必须先用 exec_run 执行 dmesg、journalctl 或 systemctl --failed，再结合遥测下结论；procfs/netlink 短窗口遥测不能替代日志，不得据此断言最近 N 分钟无错误。\n"
	"10. sysfs_get 只读 /sys、/proc/sys、/proc/irq、/proc/ai、/proc/pressure、/proc/net；/proc/<pid>/* 与 /etc/* 请用 exec_run（如 ps、cat）或对应专用工具，不要反复用 sysfs_get 试路径。\n"
	"11. 路径类任务必须严格使用用户给出的绝对路径（包括子目录），不要擅自改写到父目录或另起名字；写文件前先创建目标目录。\n"
	"\n询问纪律（何时问用户、何时不问）：\n"
	"1. 先查后问：答案能用只读工具（D0）自己查到的，禁止问用户。\n"
	"2. 只问影响结果的关键歧义：意图/目标/范围不明确、且不同理解会"
	"导致不同动作时才问；影响小或纯偏好的选合理默认并在回答中声明。\n"
	"3. 问必带推荐：每次 clarify 必须带 recommended 与 why；一次只问"
	"一个问题。\n"
	"4. 提问预算：单次任务链最多 2 问；到限后按最佳理解执行，并在"
	"回答开头声明假设（如「我按 X 理解执行，如不符请纠正」）。\n"
	"5. 不重复问：本会话已问过/用户已回答的不再问；用户表达过的偏好"
	"直接沿用。\n"
	"6. 澄清不等于授权：D2+ 危险动作一律走 lease/confirm，绝不用"
	"clarify 替代。\n"
	"7. 明确就执行：指令明确、证据唯一、或紧急诊断中，直接执行不问。\n"
,
	[TR_ASK_FALLBACK_RULES] =
	"\n输出格式（重要，必须严格遵守）：\n"
	"你的每次输出只能是一个 JSON 对象，不要输出任何其他文字：\n"
	"- 需要调用工具时：{\"tool\":\"<工具名>\",\"arguments\":{<参数>}}\n"
	"  （arguments 为参数对象；无参数工具写 {}）\n"
	"- 信息齐全要回答时：{\"answer\":\"<中文回答>\"}\n",
	[TR_ASK_SYS_ASSUME_YES] =
	"\n预授权（-y/AIKERNEL_ASSUME_YES）：仅预授权本次 ask 的 D2 本地"
	"可逆写（1 小时短租约，审计记 ephemeral lease）。D3（服务/网络/"
	"内核参数/电源/包管理/任意代码等）与 D4（用户/密钥/启动链/policy "
	"等）不会自动放行，仍需人工确认或 Principal 显式租约。若工具返回 "
	"CONFIRM_REQUIRED：把动作/影响/回滚/nonce 如实告诉用户，等待 "
	"/lease confirm 或新租约；不要重试同一调用，不要假设已授权。\n",
	[TR_ASK_SYS_LANGUAGE] =
	"\n语言：默认使用用户提问的语言回答；用户用中文提问时，回答必须"
	"使用中文，除非用户明确要求其他语言。\n",
	[TR_ASK_TOOLS_LIST_FMT]		= "%s可用工具清单：\n%s%s%s",
	[TR_ASK_CATALOG_HDR]		= "工具目录（名字 用途）：\n",
	[TR_ASK_SENSE_FMT]		= "最近一次内核遥测（NETLINK_AI SENSE，"
					  "%u 条记录）：\n%.*s\n",
	[TR_ASK_STATUS_FMT]		= "内核状态紧凑摘要（/proc/ai/status，"
					  "≤2KB；完整内容用 procfs_read_status "
					  "工具按需读取）：\n%s\n",
	[TR_ASK_STATUS_NOTE]		= "说明：sampled_skip 是主动降采样"
					  "（正常设计，不是丢失）；dropped 才是"
					  "真实丢失（环满/消费慢），按此判断"
					  "当前环是否溢出。\n",
	[TR_ASK_STATUS_DROPPED_NOTE]	= "（自启动累计；非本次新增%s）",
	[TR_ASK_STATUS_SKIP_NOTE]	= "（主动降采样；非丢失）",
	[TR_ASK_STATUS_DELTA_FMT]	= "；较上次 +%llu",
	[TR_ASK_MEM_FMT]		= "相关记忆（SME 预检索命中，JSON 原文）："
					  "\n%s\n",
	[TR_ASK_UNKNOWN_TOOL]		= "ERROR: 未知工具 '%s'（只能使用工具清单"
					  "中列出的工具）",
	[TR_ASK_EMPTY]			= "(空)",
	[TR_ASK_TC_VERBOSE]		= "  [工具调用] %s(%s)\n",
	[TR_ASK_TR_VERBOSE]		= "  [工具结果%s] %s%s\n",
	[TR_ASK_TRUNCATED]		= " ...(截断)",
	[TR_ASK_MORE_LINES]		= "  %s[+%d 行，verbose on 查看全文]%s\n",
	[TR_ASK_NO_EXEC_OUTPUT]		= "(执行器无输出)",
	[TR_ASK_LIST_SEP]		= "、",
	[TR_ASK_ROUTER_MERGED]		= "%s\n[框架提示] 本次检索已激活 "
					  "%d 个工具：%s。完整定义已加入"
					  "**当前这次请求**的 tools 数组——"
					  "你现在就可以直接调用（R/W1 直接"
					  "执行，W2 先向用户请求确认），不要"
					  "等待下一轮，也不要只输出计划。"
					  "若本条是历史重放、当前 tools 数组"
					  "并未包含这些工具，先重新 memory_search。",
	[TR_ASK_ROUTER_MERGED_TEXT]	= "%s\n[框架提示] 本次检索已激活 "
					  "%d 个工具：%s。你现在就可以按文本"
					  " JSON 约定直接调用（R/W1 直接执行，"
					  "W2 先向用户请求确认），不要等待"
					  "下一轮，也不要只输出计划。若本条"
					  "是历史重放、当前可用工具清单并未"
					  "包含这些工具，先重新 memory_search。",
	[TR_ASK_ROUTER_ACT_UI]		= "  %s[router] 检索激活 +%d 工具"
					  "（已加入随后的请求，当前 %d/%d）%s\n",
	[TR_ASK_TOOL_RESULT_FMT]	= "[TOOL %s RESULT]\n%s\n"
					  "请根据以上工具结果继续（输出 JSON）。",
	[TR_ASK_USAGE]			= "Usage: ask <问题或任务描述>\n",
	[TR_ASK_USAGE_EX]		= "  例: ask 帮我看看这台机器内存多大，"
					  "并记住答案\n",
	[TR_ASK_REG_FAIL]		= "注册表加载失败",
	[TR_ASK_USER_TASK_FMT]		= "%s%s%s用户任务：%s",
	[TR_ASK_HEADER_FMT]		= "模型: %s | 工具: %d/%d 个已激活 | "
					  "路由: %s | 最大轮数: %d | "
					  "会话: %s（%d 条历史）\n",
	[TR_ROUTE_PRE_LABEL]		= "pre_retrieve（框架预检索）",
	[TR_ROUTE_AUTO_LABEL]		= "autonomous（模型自主检索）",
	[TR_ASK_TRIM_FMT]		= "%s历史窗口: 已裁剪最老 %d 轮"
					  "（%d → %d 条，预算上限内"
					  "；compact 可主动压缩）%s\n",
	[TR_ASK_CTX_SENSE]		= "上下文: 内核遥测摘要已注入\n",
	[TR_ASK_CTX_STATUS]		= "上下文: 内核状态紧凑摘要已注入"
					  "（≤2KB）\n",
	[TR_ASK_CTX_MEM]		= "上下文: SME 预检索命中已注入（top%d）\n",
	[TR_ASK_TOOLS_EXPANDED]		= "  %s[router] tools 数组已扩入"
					  "（%d/%d）%s\n",
	[TR_ASK_ROUND_FMT]		= "%s[第 %d 轮]%s ",
	[TR_ASK_FALLBACK_RETRY]		= "  (请求失败，切换为文本约定降级"
					  "模式重试)\n",
	[TR_ASK_MODEL_FAIL]		= "ask: 模型调用失败: %s\n",
	[TR_ASK_NO_RESULT]		= "ask: 模型未返回结果\n",
	[TR_ASK_TRUNC_WARN]		= "%s(已达 max_tokens 生成被截断，"
					  "可 config set max_tokens 调大)%s\n",
	[TR_ASK_TC_REQ]			= "  %s(模型请求 %d 个工具调用)%s\n",
	[TR_ASK_FALLBACK_TC]		= "  %s(降级模式：解析到工具调用)%s\n",
	[TR_ASK_SWITCH_FALLBACK]	= "  %s(模型未用原生 tools，切换为文本"
					  "约定模式)%s\n",
	[TR_ASK_EMPTY_ANSWER]		= "(空回答)",
	[TR_ASK_MAX_ROUNDS]		= "ask: 已达最大轮数上限（%d），强制结束\n",
	[TR_ASK_CTX_WARN]		= "%s[警告] 本次请求上下文预算已用 %d%%"
					  "（按最近一次请求 prompt 计算；"
					  "compact 可压缩历史）%s\n",
	[TR_ASK_TOOL_SUMMARY_FMT]	= "\n[摘要：原 %ld 字节/约 %d 行，"
					  "工具 %s；完整结果可重新调用该工具获取]",
	[TR_ASK_TOOL_SUMMARY_UI]	= "  %s[摘要]%s %s：原 %ld 字节/约 %d 行"
					  "超单条预算，头部 %ld 字节入历史%s\n",
	[TR_ASK_AUTOCOMPACT_TRY]	= "%s[历史占用超预算 80%%，自动压缩中...]%s\n",
	[TR_ASK_AUTOCOMPACT]		= "[历史已自动压缩]\n",
	[TR_ASK_AUTOCOMPACT_FAIL]	= "%s[自动压缩失败(%s)，历史保持原样]%s\n",
	[TR_ASK_COMPACT_COOLDOWN]	= "%s[compact] 距上次压缩仅 %d/%d 轮，"
					  "跳过本轮压缩（历史仍按预算裁剪）%s\n",
	[TR_ASK_MAX_ROUNDS_FINAL]	= "ask: 已达最大轮数上限（%d），禁止继续"
					  "调用工具，正在生成最终结论...\n",
	[TR_ASK_FINAL_HINT]		= "已达到工具调用轮数上限。禁止再调用"
					  "任何工具；请基于以上已有结果给出最终"
					  "结论：已完成什么、未完成什么、关键证据"
					  "或文件路径。若任务未完成，明确说明缺口。",
	[TR_ASK_CLARIFY_MEM_NOTE]	= "[clarify] 已按你此前的选择：%s。"
					  "不再重复提问，请直接沿用该选择继续执行。",
	[TR_ASK_CLARIFY_BUDGET_NOTE]	= "[clarify] 已达提问上限：请按最佳理解"
					  "执行并在回答开头声明假设（如「我按 X "
					  "理解执行，如不符请纠正」）；不要再调用"
					  " clarify。",
	[TR_ASK_CLARIFY_AUTO_NOTE]	= "[clarify] 该澄清已过期，已按推荐项自动"
					  "选择：%s。请按该选择继续执行并声明该假设。",

	/* status */
	[TR_ST_STREAMING_FMT]		= "  streaming   : built-in (delta 逐段"
					  "实时交付; config stream=%s)\n",
	[TR_ST_SME]			= "  memory(SME) : external service "
					  "127.0.0.1:8760 (启用与否见工具描述)\n",

	/* config */
	[TR_CFG_MODEL_LABEL]		= "模型        ",
	[TR_CFG_MODEL_FMT]		= "%s（默认 %s）",
	[TR_CFG_NOTLOADED]		= "(未加载)",
	[TR_CFG_NOTSET]			= "(未设置)",
	[TR_CFG_USAGE_FMT]		= "  上次: %s in / %s out %s| 会话累计: "
					  "%s tok | ctx 预算 %s%d%%%s"
					  "（%s / %s）\n",
	[TR_CFG_EST]			= "(估算) ",
	[TR_CFG_KEYS_HINT]		= "键: ctx_len max_tokens stream "
					  "local_api color verbose session lang\n",
	[TR_CFG_CTX_POSINT]		= "config: ctx_len 需为正整数\n",
	[TR_CFG_CTX_CLAMP]		= "config: 模型 %s 窗口上限 %d，"
					  "ctx_len %d 被钳制为 %d\n",
	[TR_CFG_MT_RANGE]		= "config: max_tokens 需在 1-131072 之间\n",
	[TR_CFG_STREAM_VAL]		= "config: stream 取值 on|off\n",
	[TR_CFG_STREAM_NOCOMP]		= "config: stream 未编译进本二进制"
					  "（CONFIG_AIKERNEL_STREAM_MODE=n），"
					  "保持 off\n",
	[TR_CFG_LOCALAPI_VAL]		= "config: local_api 取值 native|v1\n",
	[TR_CFG_BOOL_VAL]		= "config: %s 取值 on|off\n",
	[TR_CFG_BAD_SESSION]		= "config: 非法会话名 '%s'\n",
	[TR_CFG_SESSION_NMSG]		= "session = %s（%d 条历史消息）\n",
	[TR_CFG_SET_USAGE]		= "Usage: config set <key> <value>\n",

	/* shell */
	[TR_SH_NOT_TTY]			= "shell: 当前环境非交互终端"
					  "（stdin/stdout 被重定向），"
					  "拒绝进入子 shell。\n",
	[TR_SH_ENTER]			= "进入维护 shell（bash）。输入 exit 返回 "
					  "AI 控制台。\n",
	[TR_SH_FORK_FAIL]		= "shell: fork 失败（%s）。\n",
	[TR_SH_EXEC_FAIL]		= "shell: 无法启动 /bin/bash（%s）。\n",
	[TR_SH_START_FAIL]		= "shell: /bin/bash 启动失败。\n",
	[TR_SH_RETURN]			= "已返回 AI 控制台。\n",

	/* netlink */
	[TR_NL_HELP_SENSE]		= "   拉取内核 AI 遥测记录\n",
	[TR_NL_HELP_ACT]		= "                                                  下发决策指令（需 CAP_SYS_ADMIN）\n",
	[TR_NL_HELP_REG]		= "  netlink reg                                     登记本进程 portid（需 CAP_SYS_ADMIN）\n",
	[TR_NL_HELP_COUNT]		= "count:  1~4096（默认 32）\n",
	[TR_NL_HELP_HEXDATA]		= "hexdata: 最多 64 字节，如 \"aabbcc\" 或 \"aa bb cc\"\n",
	[TR_NL_KERN_REJECT]		= "内核拒绝: errno=%d (%s)\n",
	[TR_NL_HINT]			= "提示: %s\n",
	[TR_NL_SEND_FAIL]		= "传输失败: %s\n",
	[TR_NL_PARSE_FAIL]		= "应答解析失败（与内核协议不一致？"
					  "请核对 ai_netlink.h）\n",
	[TR_NL_ERR]			= "错误: %s\n",
	[TR_NL_INIT_FAIL]		= "NETLINK_AI socket 初始化失败: %s\n",
	[TR_NL_ALLOC_FAIL]		= "内存分配失败 (%u 字节)\n",
	[TR_NL_NO_RECORDS]		= "(无记录)\n",
	[TR_NL_ACT_CONFIRM1]		= "即将向内核下发决策:\n",
	[TR_NL_ACT_CONFIRM2]		= "  domain=%u (%s)  decision_type=%u  "
					  "confidence=%u  data=%zu 字节\n",
	[TR_NL_ACT_CONFIRM3]		= "该操作需要 CAP_SYS_ADMIN（root/sudo），"
					  "并会直接影响系统行为。确认执行? [y/N] ",
	[TR_NL_CANCELLED]		= "已取消\n",
	[TR_NL_ACK_AIERR]		= "ai_err:        %d（策略层报错）\n",
	[TR_NL_ACK_NO_POLICY]		= "未命中任何策略（executed=0）\n",
	[TR_NL_REG_PORTID]		= "Portid:           %u（内核分配，同进程固定）\n",
	[TR_NL_REG_COUNT]		= "已登记 portid 数:  %u/32\n",
	[TR_NL_REG_IDEMPOTENT]		= "重复执行 reg 幂等（内核按 portid 去重）\n",
	[TR_NL_REG_NOARGS]		= "netlink reg 不接受参数\n",

	/* session */
	[TR_SES_BAD_NAME]		= "session: 非法会话名 '%s'"
					  "（只允许字母数字 - _ .）\n",
	[TR_SES_EXISTS_SWITCH]		= "session: 会话 '%s' 已存在，切换到它"
					  "（历史保留）\n",
	[TR_SES_CREATE_FAIL]		= "session: 创建失败: %s\n",
	[TR_SES_CREATED]		= "已创建并切换到会话: %s\n",
	[TR_SES_LIST_EMPTY]		= "(无会话文件；ask 时自动以 '%s' 落盘)\n",
	[TR_SES_LIST_HDR]		= "%-3s %-24s %s\n",
	[TR_SES_HDR_NAME]		= "会话",
	[TR_SES_HDR_COUNT]		= "消息数",
	[TR_SES_RANGE]			= "session: 序号超范围（1-%d）\n",
	[TR_SES_BAD_TARGET]		= "session: 非法会话名 '%s'\n",
	[TR_SES_ALREADY_IN]		= "已在会话 '%s'\n",
	[TR_SES_SWITCHED]		= "已切换到会话: %s（%d 条历史消息）\n",
	[TR_SES_LOAD_FAIL]		= "session: 加载失败: %s\n",
	[TR_SES_SHOW]			= "会话 '%s'：%d 条消息\n",
	[TR_SES_HELP_NEW]		= "  session new [name]      新建并切换会话\n",
	[TR_SES_HELP_LIST]		= "  session list            列出会话\n",
	[TR_SES_HELP_SWITCH]		= "  session switch <name|N> 切换会话\n",
	[TR_SES_HELP_SAVE]		= "  session save            确认落盘\n",
	[TR_SES_HELP_DELETE]		= "  session delete <name>   删除会话\n",
	[TR_SES_HELP_SHOW]		= "  session show [n]        查看最近 n 条消息\n",
	[TR_SES_SAVED]			= "会话 '%s' 已落盘（%d 条消息，每轮 ask 自动追加）\n",
	[TR_SES_DEL_CURRENT]		= "session: 不能删除当前会话"
					  "（先 switch 到其他会话）\n",
	[TR_SES_DELETED]		= "已删除会话: %s\n",
	[TR_SES_DELETE_FAIL]		= "session: 删除失败: %s\n",

	/* compact */
	[TR_CMP_LOAD_FAIL]		= "compact: 会话加载失败: %s\n",
	[TR_CMP_EMPTY]			= "compact: 会话 '%s' 无历史，无需压缩\n",
	[TR_CMP_CAP]			= "compact: 历史超过 %d 条，仅压缩最近 %d 条\n",
	[TR_CMP_TAG_TOOLCALL]		= "[发起工具调用] ",
	[TR_CMP_TAG_TOOLRESULT]		= "[工具结果] ",
	[TR_CMP_PROMPT]			= "请把以下 AIKernel Shell 会话历史压缩成一段"
					  "简明的中文摘要"
					  "（保留：用户的目标与偏好、已执行的操作系统"
					  "操作与结果、重要事实如设备参数/代号/结论；"
					  "去掉寒暄与重复），直接输出摘要正文：\n\n%s",
	[TR_CMP_SYS_PROMPT]		= "你是会话摘要助手。只输出摘要正文，"
					  "不要任何前后缀。",
	[TR_CMP_RUNNING]		= "compact: 压缩会话 '%s'（%d 条消息，"
					  "%zu 字节）...\n",
	[TR_CMP_SUM_FAIL]		= "compact: 摘要失败（原会话保持不变）: %s\n",
	[TR_CMP_CLEAR_FAIL]		= "compact: 会话清空失败: %s\n",
	[TR_CMP_WRITE_FAIL]		= "compact: 摘要写入失败: %s\n",
	[TR_CMP_FALLBACK]		= "compact: 摘要失败已降级为逐轮本地裁剪，"
					  "裁掉最老 %d 轮（会话保持可用）\n",
	[TR_CMP_DONE]			= "compact: 完成，历史替换为摘要 + %d 条"
					  "最近消息%s\n",
	[TR_CMP_TRUNC]			= "compact: 摘要不可用，已降级为预算内确定性"
					  "截断%s\n",
	[TR_CMP_GUARD]			= "compact: 连续压缩已达上限，本次仅截断"
					  "历史（不再调用摘要）%s\n",

	/* W42：隔离区 + 子智能体（executor.c sandbox 通道） */
	[TR_SB_CREATED]			= "隔离区已建立（挂载点就绪，run 时挂入"
					  " tmpfs 空根）\n",
	[TR_SB_SPAWN_START]		= "子智能体已派入隔离区（aik-sandbox run，"
					  "受限工具表已注入）\n",
	[TR_SB_DONE]			= "沙盒任务结束：隔离区=%s 耗时=%d 秒 "
					  "dispatcher_exit=%d task_status=%s\n",
	[TR_SB_TIMEOUT]			= "沙盒任务超时，已 SIGKILL 击杀进程组："
					  "隔离区=%s 预算=%d 秒\n",
	[TR_SB_DESTROYED]		= "隔离区已焚毁（沙盒数据随 tmpfs 消亡）\n",
	[TR_SB_TAIL_HDR]		= "子智能体输出尾部（≤4KB）",
	[TR_SB_DESTROY_REMIND]		= "\n提醒：如无后续需要，请立即 sandbox_destroy %s 焚毁隔离区，不要留下宿主残留。\n",

	/* 命令描述（中文对；英文用注册表原文） */
	[TR_CMD_HELP]			= "显示帮助信息",
	[TR_CMD_EXIT]			= "退出 AI Shell",
	[TR_CMD_STATUS]			= "显示当前状态",
	[TR_CMD_CONFIG]			= "查看或修改配置",
	[TR_CMD_CHAT]			= "ask 的别名（同一工具调用循环）",
	[TR_CMD_ASK]			= "AI 工具调用循环（自动执行工具）",
	[TR_CMD_MODEL]			= "管理 AI 模型（add/list/use/remove/test）",
	[TR_CMD_NETWORK]		= "网络诊断（status/test）",
	[TR_CMD_NETLINK]		= "NETLINK_AI 内核通道（sense/act/reg）",
	[TR_CMD_SESSION]		= "管理持久化会话",
	[TR_CMD_COMPACT]		= "摘要压缩当前会话历史",
	[TR_CMD_SETUP_PASSWORD]		= "设置/修改 root 密码（关回显，AI 不可见）",
	[TR_CMD_SHELL]			= "进入 bash 维护 shell（exit 返回），"
					  "或直接对 AI 说：帮我打开一个 shell",
	[TR_CMD_LANG]			= "显示/切换界面语言（zh|en，持久化）",

	/* ---- W43：plan 只读模式 ---- */
	[TR_PLAN_ON]			= "已进入 plan（规划）模式：只读调研，"
					  "写操作已禁用。完成规划后 /unplan 退出。\n",
	[TR_PLAN_OFF]			= "已退出 plan 模式，恢复完整工具权限。\n",
	[TR_PLAN_DENY]			= "ERROR: DENIED: plan 模式：只读调研，写入已禁用"
					  "（工具 %s risk=%s 已拦截）。/unplan 退出"
					  "后可执行。\n",
	[TR_PLAN_SYS_NOTE]		= "\n当前处于 plan（规划）模式：你只能调研与只读，"
					  "禁止执行写操作；产出应为计划/分析，不执行变更。\n",

	/* ---- W43：slash 命令 ---- */
	[TR_TOOLS_HDR]			= "  ID   名字                           通道"
					  "           风险  描述\n",
	[TR_TOOLS_ROW]			= "  %-4d %-28s %-13s %-5s %s\n",
	[TR_TOOLS_TOTAL]		= "命中 %d / 注册表共 %d 件\n",
	[TR_TOOLS_FILTER]		= "过滤词: %s\n",
	[TR_TOOLS_EMPTY]		= "无匹配「%s」的工具，去掉过滤词或换一个试试\n",
	[TR_SANDBOX_USAGE]		= "用法: /sandbox status | create <名> | "
					  "destroy <名>\n（spawn 属 ask 交互职责：请通过 "
					  "ask 让 AI 派发子智能体）\n",
	[TR_REPL_SLASH_UNKNOWN]	= "未知命令: /%s\n输入 /help 查看可用命令。\n",
	[TR_SES_STATUS_HDR]		= "会话: %s\n历史: %d 条\nSME 记忆服务: ",
	[TR_SME_REACHABLE]		= "可达\n",
	[TR_SME_UNREACHABLE]		= "不可达（记忆检索降级：不影响对话，结果如实标注）\n",

	/* ---- W43：SME 失忆降级 ---- */
	[TR_SME_DEGRADED_NOTE]		= "\n[SME 记忆服务不可达，本次无记忆检索结果，"
					  "请基于当前上下文作答]\n",

	/* ---- W43：命令描述中文对 ---- */
	[TR_CMD_PLAN]			= "进入 plan（规划）只读模式（W1/W2 全拒）",
	[TR_CMD_UNPLAN]			= "退出 plan 模式，恢复完整工具权限",
	[TR_CMD_TOOLS]			= "列出工具面（编号/名/通道/风险/描述，支持过滤）",
	[TR_CMD_SANDBOX]		= "手动管理隔离区（status/create/destroy）",

	/* ---- W65：Ctrl-C / 参数自动纠正 / --version ---- */
	[TR_ASK_CANCELLED]		= "%s(已取消本次请求；可直接输入下一条，"
					  "或按 Ctrl-D 退出)%s\n",
	[TR_ASK_ARG_REPAIR]		= "%s(工具参数不合法，已把结构化用法反馈给"
					  "模型并自动重试一次)%s\n",
	[TR_ASK_ARG_REPAIR_HINT]	= "上一条工具调用参数被拒绝（错误码 "
					  "E_PARAM_*）。请按错误里的 USAGE 与 "
					  "AVAILABLE 立即重试一次：command 只放"
					  "单个白名单命令名，选项与操作数放进 "
					  "args 数组，文件内容放进 input；不要"
					  "解释、不要输出计划，直接调用工具。",
	[TR_VERSION_FMT]		= "ai (AIKernel Shell) %s\n内核: Linux %s\n",

	/* ---- W74：授权租约 / D0-D4 ---- */
	[TR_LEASE_PANEL]		= "\033[1;33m[租约/危险动作确认]\033[0m\n"
					  "  工具: %s\n  危险级: %s\n  租约: %s\n"
					  "  影响: %s\n  回滚: %s\n",
	[TR_LEASE_CONFIRM_YN]		= "继续执行? [y/N] ",
	[TR_LEASE_D4_PROMPT]		= "D4 强确认：请精确输入 \"CONFIRM D4 %s\"：",
	[TR_LEASE_D4_MISMATCH]		= "D4 确认短语不匹配，已拒绝。\n",
	[TR_LEASE_ROLLBACK_D2]		= "检查变更前状态/备份并恢复；工具结果会记录执行命令",
	[TR_LEASE_ROLLBACK_D3]		= "使用对应反向操作（如 systemctl 反向动作）或恢复配置备份；必要时重启服务",
	[TR_LEASE_ROLLBACK_D4]		= "按变更预案人工回滚（恢复 sudoers/grub/用户数据库备份）",
	[TR_LEASE_CONFIRM_QUESTION]	= "继续？",
	[TR_LEASE_DENY_SCOPE]		= "租约越界：动作不在 scope 内，已拒绝（不可用交互确认绕过）",
	[TR_LEASE_DENY_CEILING]		= "租约越界：动作危险级超过 risk_ceiling，已拒绝",
	[TR_LEASE_DENY_EXPIRED]		= "租约已过期，D1+ 动作拒绝",
	[TR_LEASE_DENY_REVOKED]		= "租约已撤销，D1+ 动作拒绝",
	[TR_LEASE_DENY_PRINCIPAL]	= "租约 principal/属主与当前用户不匹配，已拒绝",
	[TR_LEASE_DENY_LOAD]		= "显式租约不可用（加载/解析/存储校验失败），已拒绝",
	[TR_LEASE_DENY_CONFIRM]		= "确认凭证无效/过期/已使用或参数不匹配，已拒绝",
	[TR_LEASE_DENY_WORKER]		= "沙箱 worker 默认只能 D0/D1，D2+ 已拒绝",
	[TR_LEASE_DENY_D4_ROOT]		= "D4 动作仅 root 可确认，非 root 用户已拒绝",
	[TR_LEASE_CONFIRM_REQUIRED]	= "需要确认：Principal 可用 /lease pending 查看，"
					  "用 /lease confirm <nonce> 批准；重试时设置 "
					  "AIKERNEL_CONFIRM_NONCE 或 --confirm <nonce>",
	[TR_LEASE_EPHEMERAL_NOTE]	= "注意：--yes 仅生成本次 ask 的 D2 短租约"
					  "（1 小时），D3/D4 仍需确认。\n",
	[TR_LEASE_EXPLICIT_NOTE]	= "已加载显式租约 %s（ceiling=%s，scope=%d 项）\n",
	[TR_LEASE_ERR_LOAD]		= "错误: %s\n",
	[TR_CMD_LEASE]			= "租约管理（list/show/issue/revoke/pending/confirm）",
	[TR_LEASE_CMD_USAGE]		= "用法: /lease list | show <id> | "
					  "issue --scope <csv> --ceiling D2 "
					  "--mission <text> --ttl <sec> | "
					  "revoke <id> | pending | "
					  "confirm <nonce> yes|no"
					  "（D4: CONFIRM D4 <nonce>）\n",
	[TR_LEASE_ROOT_TTY]		= "仅 root + 交互终端可执行该操作。\n",
	[TR_LEASE_ISSUE_PROMPT]		= "将签发租约 %s（scope=%s ceiling=%s ttl=%ld）。"
					  "输入 ISSUE %s 确认：",
	[TR_LEASE_ISSUE_BAD]		= "确认短语不匹配，未签发。\n",
	[TR_LEASE_ISSUED]		= "已签发租约 %s\n路径: %s\n",
	[TR_LEASE_REVOKE_PROMPT]	= "将撤销租约 %s。输入 REVOKE %s 确认：",
	[TR_LEASE_REVOKE_BAD]		= "确认短语不匹配，未撤销。\n",
	[TR_LEASE_REVOKED]		= "已撤销租约 %s\n",
	[TR_LEASE_LIST_HDR]		= "ID\tPRINCIPAL\tCEILING\tEXPIRES\t"
					  "REVOKED\tSCOPE\n",
	[TR_LEASE_LIST_ROW]		= "%s\t%s\t%s\t%lld\t%s\t%s\n",
	[TR_LEASE_LIST_EMPTY]		= "（无租约）\n",
	[TR_LEASE_SHOW_FMT]		= "lease_id: %s\nprincipal: %s\n"
					  "subject: %s\nrisk_ceiling: %s\n"
					  "mission: %s\nissued_at: %lld\n"
					  "expires_at: %lld\nrevoked: %s\n"
					  "scope: %s\n",
	[TR_LEASE_PENDING_EMPTY]	= "（无 pending 确认）\n",
	[TR_LEASE_PENDING_FMT]		= "%s\t%s\t%s\n",
	[TR_LEASE_CONFIRM_OK]		= "确认已记录: %s (%s)\n",
	[TR_LEASE_CONFIRM_NO]		= "已拒绝: %s\n",
	[TR_LEASE_UNKNOWN_SUB]		= "未知 /lease 子命令: %s\n",
	[TR_LEASE_STORE_ERR]		= "租约存储错误: %s\n",
};

/* ---- 英文表 ---- */
static const char *const t_en[TR__COUNT] = {
	/* 横幅/REPL 框架 */
	[TR_BANNER_KERNEL]		= "Kernel: Linux %s\n",
	[TR_BANNER_AI_STARTING]		= "AI Runtime Starting...\n",
	[TR_BANNER_KAI_READY]		= "Kernel AI Interface : Ready\n",
	[TR_BANNER_CLOUD_CFG]		= "Cloud Provider      : Configured (%s)\n",
	[TR_BANNER_CLOUD_NOTCFG]	= "Cloud Provider      : Not configured"
					  " (use 'model add')\n",
	[TR_BANNER_LOCAL_CFG]		= "Local Provider      : Configured (%s)\n",
	[TR_BANNER_LOCAL_NOTCFG]	= "Local Provider      : Not configured\n",
	[TR_BANNER_NO_KAI]		= "(Kernel AI Interface not available)\n",
	[TR_BANNER_HINT]		= "Type 'help' for commands, 'exit' to quit.\n",
	[TR_REPL_UNKNOWN]		= "Unknown command: %s\n"
					  "Type 'help' for available commands.\n",
	[TR_REPL_REJECT_LINE]		= "(Input rejected: line of %zu bytes exceeds"
					  " limit %d)\n",
	[TR_REPL_REJECT_TAIL]		= "(Input rejected: unterminated tail of %zu"
					  " bytes exceeds limit %d, discarded)\n",
	[TR_REPL_QUEUED]		= "(queued input)",
	[TR_REPL_ASK_HINT]		= "[chat mode: plain input goes to the AI;"
					  " type 'help' for commands]\n",
	[TR_VERBOSE_ANNOUNCE]		= "(verbose: %s — tool cards will be shown"
					  " %s; toggle with config set verbose)\n",
	[TR_VERBOSE_EXPANDED]		= "fully expanded",
	[TR_VERBOSE_COLLAPSED]		= "collapsed",
	[TR_ERR_CONFIG_INIT]		= "Error: Failed to initialize config\n",
	[TR_ERR_P_QUESTION]		= "ai: -p requires a question string\n",
	[TR_USAGE_FMT]			= "Usage: %s [options] [command...]\n"
	"  -p, --prompt <question>  One-shot mode: run a single ask, then exit\n"
	"  -c, --ctx <N>            Context token budget"
	" (default %d, clamped to model limit for local)\n"
	"  -m, --max-tokens <N>     Per-generation token cap (default %d)\n"
	"  -S, --no-stream          Disable streaming output\n"
	"  -s, --session <name>     Select session (default: default)\n"
	"  -C, --no-color           Disable ANSI colors (NO_COLOR works too)\n"
	"  -N, --no-onboarding      Skip first-run onboarding (maintenance/rescue)\n"
	"  -P, --plan               Start in plan (read-only research) mode\n"
	"  -y, --yes                Ephemeral D2 lease for this ask (1h;"
	" D3/D4 still\n"
	"                           require confirmation; env"
	" AIKERNEL_ASSUME_YES equivalent)\n"
	"      --lease <id>         Use a Principal-issued explicit lease"
	" (fail-closed)\n"
	"      --confirm <nonce>    Consume a /lease confirm approval"
	" (single use)\n"
	"  -V, --version            Show version and kernel release\n"
	"  -h, --help               Show this help\n",
	[TR_SHELL_FIRST_RUN]		= "No AI Provider Configured.\n"
					  "Please configure a model first.\n\n",
	[TR_SHELL_SUGGEST]		= "Suggested Command:\n  model add <name>\n",

	/* help */
	[TR_HELP_TITLE]			= "\nAIKernel - AI Subsystem Shell\n",
	[TR_HELP_AVAIL]			= "Available commands:\n\n",
	[TR_HELP_CMDHDR]		= "Command",
	[TR_HELP_DESCHDR]		= "Description",
	[TR_HELP_DETAIL_ONE]		= "Command: %s\n  %s\nUsage: %s\n",
	[TR_HELP_DETAIL]		= "\nType 'help <command>' for detailed usage.\n\n",
	[TR_HELP_UNKNOWN]		= "Unknown command: %s\n",

	/* lang */
	[TR_LANG_CURRENT]		= "Current language: %s (switch: lang zh | lang en)\n",
	[TR_LANG_SWITCHED]		= "语言已切换。Language switched.\n"
					  "→ English UI (type 'lang zh' for Chinese)\n",
	[TR_LANG_USAGE]			= "Usage: lang [zh|en]  show/switch UI language\n",
	[TR_LANG_INVALID]		= "lang: unknown language '%s' (choose zh | en)\n",
	[TR_LANG_SAVE_FAIL]		= "Warning: failed to persist language to"
					  " model.toml; it may revert after restart.\n",

	/* W2 与权限 */
	[TR_W2_AUTO_YES]		= "[W2] %s pre-approved via --yes/"
					  "AIKERNEL_ASSUME_YES, auto-confirmed\n",
	[TR_W2_NO_TTY]			= "ai_policy: NEED_CONFIRM requires interactive"
					  " confirmation, but stdin is not a"
					  " terminal; refusing by policy. Run"
					  " in an interactive session, or use"
					  " the /act confirm=true structured"
					  " interface\n",
	[TR_W2_PANEL]			= "\033[1;31m[W2 high-impact operation, confirmation required]\033[0m\n"
					  "\033[1;31m  Tool:   %s\033[0m\n"
					  "\033[1;31m  Args:   %s\033[0m\n"
					  "\033[1;31m  Impact: %s\033[0m\n",
	[TR_W2_CONFIRM]			= "Confirm execution? [y/N] ",
	[TR_W2_STALE_INPUT]		= "[W2] pending input before panel: single-key reply judged as"
					  " pre-approval/pre-decline; other input lines ignored and this"
					  " confirmation treated as declined\n",
	[TR_W2_IMPACT_FALLBACK]		= "(see tool description)",
	[TR_W2_DENY]			= "Permission denied: this operation requires"
					  " root (sudo ai)\n",
	[TR_POLICY_CONF_UNREAD]		= "ai_policy: config %s unreadable (%s),"
					  " falling back to restricted\n",
	[TR_POLICY_CONF_NO_BRACKET]	= "ai_policy: %s:%d section header missing ']',"
					  " ignored\n",
	[TR_POLICY_CONF_NO_EQ]		= "ai_policy: %s:%d missing '=', ignored\n",
	[TR_POLICY_AUDIT_NO_HOME]	= "ai_policy: no home directory for audit log\n",
	[TR_POLICY_AUDIT_MKDIR]		= "ai_policy: mkdir %s: %s\n",
	[TR_POLICY_AUDIT_OPEN]		= "ai_policy: open %s: %s\n",
	[TR_POLICY_AUDIT_FLOCK]		= "ai_policy: flock %s: %s\n",
	[TR_POLICY_AUDIT_WRITE]		= "ai_policy: audit write failed: %s\n",

	/* onboarding */
	[TR_OB_SYS_PROMPT] =
	"You are the initialization onboarding assistant of AIKernel OS. You are"
	" guiding the user through the first-time setup of this machine via the"
	" local console. You must do three things: 1) Briefly introduce yourself:"
	" you are this machine's AI console, responsible for system monitoring,"
	" parameter tuning and operations assistance; 2) Guide the user to set"
	" the root password: ask them to type the command setup-password, and"
	" explain that password input is not echoed and you will never see it;"
	" 3) Guide the user to choose an AI model source: reply 1 for local"
	" models (built-in ollama), reply 2 for a cloud API. Rules: keep each"
	" reply within 3 sentences, answer in English; never fabricate system"
	" state; for questions about system interfaces, parameters or usage,"
	" search the memory store first (memory_search, includes"
	" aikernel-interface corpus) before answering; when no tool is available"
	" say so honestly instead of inventing interfaces; never reveal or ask"
	" for the password itself.",
	[TR_OB_HIDDEN_NEED_TTY]		= "setup-password: an interactive terminal"
					  " (tty) is required to type the password"
					  " safely.\n",
	[TR_OB_PW_PROMPT1]		= "Enter new password (input hidden): ",
	[TR_OB_PW_PROMPT2]		= "Re-enter to confirm: ",
	[TR_OB_PW_EMPTY]		= "setup-password: password must not be empty.\n",
	[TR_OB_PW_TOO_SHORT]		= "setup-password: password must be at least"
					  " 6 characters.\n",
	[TR_OB_PW_MISMATCH]		= "setup-password: the two entries do not"
					  " match.\n",
	[TR_OB_PW_SETTING]		= "setup-password: setting root password...\n",
	[TR_OB_PW_OK]			= "setup-password: root password set"
					  " successfully.\n",
	[TR_OB_PW_FAIL]			= "setup-password: failed to set password"
					  " (chpasswd error).\n",
	[TR_OB_LOCAL_NO_BASEURL]	= "onboarding: model.toml is missing"
					  " [local].base_url; cannot auto-configure"
					  " the local model.\n",
	[TR_OB_LOCAL_PROBING]		= "onboarding: probing local model service"
					  " %s ...\n",
	[TR_OB_LOCAL_UNREACH]		= "onboarding: local model service unreachable"
					  " (ollama not running or model not ready).\n",
	[TR_OB_LOCAL_OK]		= "onboarding: local model service reachable.\n",
	[TR_OB_CLOUD_ASK_URL]		= "Enter the cloud API base_url (e.g."
					  " https://api.deepseek.com/v1, or an"
					  " internal OpenAI-compatible endpoint):\n> ",
	[TR_OB_URL_EMPTY]		= "onboarding: base_url must not be empty.\n",
	[TR_OB_CLOUD_ASK_KEY]		= "Enter the API Key (never stored to disk,"
					  " never sent to the model context;"
					  " press Enter to skip):\n> ",
	[TR_OB_CLOUD_ASK_MODEL]		= "Enter the model name (e.g. deepseek-chat /"
					  " qwen2.5-7b-instruct):\n> ",
	[TR_OB_MODEL_EMPTY]		= "onboarding: model name must not be empty.\n",
	[TR_OB_PROBING]			= "onboarding: testing endpoint connectivity...\n",
	[TR_OB_ENDPOINT_UNREACH]	= "onboarding: endpoint unreachable; check the"
					  " address/network and retry.\n",
	[TR_OB_ENDPOINT_OK]		= "onboarding: endpoint reachable, writing"
					  " configuration...\n",
	[TR_OB_WRITE_FAIL]		= "onboarding: failed to write model"
					  " configuration.\n",
	[TR_OB_SWITCH_FAIL]		= "onboarding: configuration written but the"
					  " switch failed; retry 'model use cloud'"
					  " later.\n",
	[TR_OB_MARK_FAIL]		= "onboarding: cannot write %s (%s).\n",
	[TR_OB_HEAD]			= "\n=== AIKernel onboarding ===\n",
	[TR_OB_HINT1]			= "This flow guides you through: root password, "
					  "cloud model config (required, live-tested), optional "
					  "local model.\n",
	[TR_OB_HINT2]			= "      Type 'help' for onboarding commands;"
					  " the password never goes through the AI.\n\n",
	[TR_OB_WELCOME_ASK]		= "Give the user a brief self-introduction and"
	" tell them the first step is to set the root password by typing"
	" setup-password at the prompt.",
	[TR_OB_WELCOME_FALLBACK]	= "[AI] Hello, I am this machine's AI console"
					  " (AIKernel), handling system monitoring,"
					  " parameter tuning and operations"
					  " assistance.\n"
					  "Setup has two steps: first set the root"
					  " password (type setup-password; input is"
					  " hidden, I will not see it), then choose"
					  " the AI model source.",
	[TR_OB_HELP]			= "Onboarding commands:\n"
					  "  setup-password  set root password"
					  " (hidden, confirmed twice, >=6 chars)\n"
					  "  1 | local       use local model\n"
					  "  2 | cloud       use cloud API\n"
					  "  shell           enter maintenance bash"
					  " (escape hatch, 'exit' to return)\n"
					  "  any other text  chat with the onboarding"
					  " AI\n",
	[TR_OB_PW_FIRST]		= "onboarding: please finish the root password"
					  " setup (type setup-password) before"
					  " choosing a model.\n",
	[TR_OB_PW_DONE_ASK]		= "The user has successfully set the root"
					  " password. Congratulate them and guide"
					  " step two: choose the AI model source —"
					  " reply 1 for local model, reply 2 for"
					  " cloud API.",
	[TR_OB_PW_DONE_FALLBACK]	= "[AI] Root password is set. Step two: choose"
					  " the AI model source — type 1 for local"
					  " model (built-in ollama), type 2 for"
					  " cloud API.",
	[TR_OB_PW_FAIL_ASK]		= "The user's password setup failed (empty/"
					  " under 6 chars/mismatch/chpasswd error)."
					  " Remind them to type setup-password"
					  " again.",
	[TR_OB_PW_FAIL_FALLBACK]	= "[AI] Password was not set. Please type"
					  " setup-password and try again.",
	[TR_OB_STEP1_CHAT_FALLBACK]	= "[AI] Please type setup-password first to"
					  " set the root password.",
	[TR_OB_STEP2_HELP]		= "Type 2 or cloud to configure the cloud model "
					  "(required; must pass the live connectivity test); type "
					  "shell for the maintenance bash.\n",
	[TR_OB_LOCAL_FAIL_ASK]		= "The local model service is currently"
					  " unreachable. Tell the user they can"
					  " switch to cloud for now (type 2), or"
					  " reboot later and retry once ollama is"
					  " ready (type 1).",
	[TR_OB_LOCAL_FAIL_FALLBACK]	= "[AI] The local model is temporarily"
					  " unavailable. You can type 2 to use the"
					  " cloud API instead, or retry with 1"
					  " later.",
	[TR_OB_STEP2_CHAT_FALLBACK]	= "[AI] Please type 2 or cloud to configure "
					  "the cloud model.",
	[TR_OB_DONE_ASK]		= "Initialization is fully complete. Congratulate"
	" the user briefly, explain that the normal console starts now, and that"
	" they can type 'ask' followed by a question at any time.",
	[TR_OB_DONE_FALLBACK]		= "[AI] Initialization complete! Entering the AI"
					  " console. Type 'help' for commands, or"
					  " 'ask' followed by your question.",
	[TR_OB_DONE]			= "\n=== Onboarding complete, entering AI"
					  " console ===\n\n",
	[TR_OB_LANG_ASK]		= "Interface language: 1=中文 2=English [1]: ",
	[TR_OB_CLOUD_PRESETS]		= "Cloud provider presets (URL prefilled only, no keys embedded):\n"
					  "  1) deepseek      https://api.deepseek.com/v1\n"
					  "  2) qwen(dashscope) https://dashscope.aliyuncs.com/compatible-mode/v1\n"
					  "  3) doubao(ark)   https://ark.cn-beijing.volces.com/api/v3\n"
					  "  4) glm(zhipu)    https://open.bigmodel.cn/api/paas/v4\n"
					  "  5) openai-compatible / custom\n",
	[TR_OB_CLOUD_PRESET_PROMPT]	= "Choose provider number [5]: ",
	[TR_OB_CLOUD_ASK_URL_DFLT]	= "Enter the cloud API base_url [%s]: ",
	[TR_OB_CLOUD_LIVE_TEST]		= "onboarding: running live connectivity test (real 1-token completion)...\n",
	[TR_OB_CLOUD_LIVE_OK]		= "onboarding: live test passed, writing config...\n",
	[TR_OB_CLOUD_LIVE_FAIL]		= "onboarding: live test FAILED: %s\n",
	[TR_OB_CLOUD_RETRY_MENU]	= "Enter or 1 = retry; 2 = skip (skip means onboarding incomplete, reruns next boot) [1]: ",
	[TR_OB_CLOUD_SKIPPED]		= "onboarding: cloud config skipped. Onboarding NOT complete (%s not written); it will rerun next boot.\n",
	[TR_OB_LOCAL_OPTIONAL]		= "Local model is OPTIONAL: install later with aik model recommend/install, or just ask the AI to do it.\n"
					  "Type 1 to install now, or press Enter to skip [skip]: ",
	[TR_OB_LOCAL_TOP3]		= "Recommendations for this host (hardware-gated top-3):\n",
	[TR_OB_LOCAL_PICK]		= "Pick a number to install [1]: ",
	[TR_OB_LOCAL_INSTALL_CONFIRM]	= "Will download %s (~%gGB to disk). Continue? [y/N]: ",
	[TR_OB_LOCAL_INSTALL_FAIL]	= "install FAILED (reported honestly): %s\n",
	[TR_OB_LOCAL_RETRY_MENU]	= "Type 1 to retry; Enter or 2 to skip the local step (onboarding still completes) [2]: ",
	[TR_OB_LOCAL_SWITCH_ASK]	= "Switch to the local model now? [y/N]: ",
	[TR_OB_LOCAL_INSTALLED_OK]	= "onboarding: %s installed and verified.\n",
	[TR_OB_LOCAL_NO_FIT]		= "onboarding: no catalog model meets this host's RAM/disk minimums; see aik model catalog later.\n",

	/* ask 主流程 */
	[TR_ASK_SYS_IDENTITY] =
	"You are the AIKernel system administrator AI (running in the ask command"
	" of AIKernel Shell). Your duty: fulfil the user's system/kernel query and"
	" operation requests by calling tools.\n\n",
	[TR_ASK_SYS_RETRIEVAL] =
	"\nInterface retrieval guide:\n"
	"You have the memory_search tool (SME semantic retrieval, required param"
	" text). For any question about system interfaces, /proc/ai and"
	" /sys/kernel/ai nodes, kernel parameters, how to operate, or tool usage:"
	" search with memory_search first (Chinese keywords work well, e.g."
	"「进程优先级 调整」), then answer or act based on hits; never guess;"
	" on a miss retry once with different words, then say honestly if still"
	" nothing. Tools named in hits (e.g. netlink_act_sched_nice) can be called"
	" directly next — the framework attaches their full definitions."
	" After retrieval activates tools, if the user's task can move forward,"
	" call them immediately (R/W1 directly; W2 normally asks for"
	" confirmation, but call directly when assume_yes pre-authorization is"
	" declared below); do not reply with a plan only.\n",
	[TR_ASK_SYS_RULES_SHORT] =
	"\nRules:\n"
	"1. Only call tools present in the request's tools array, names exactly as"
	" given; you may call several at once. If a needed tool is not in the"
	" array, search memory or say so honestly; never call non-existent"
	" tools.\n"
	"2. Arguments must match the schema names and types; never fabricate tool"
	" results.\n"
	"3. For action requests (tune/set/freeze/apply/yield, etc.) you must"
	" actually call the tool to complete them, not just write text; provide"
	" all required arguments (e.g. pid, value — use the exact pid the user"
	" mentions).\n"
	"4. Gather information by calling tools first, then answer.\n"
	"5. If a tool fails, state the cause honestly and retry with corrected"
	" arguments; answer in the user's question language by default, concise"
	" and accurate.\n"
	"6. Running code with python3 is a high-impact operation (W2, normally"
	" confirmed per run; execute directly when assume_yes pre-authorization"
	" is declared): first write the code to a .py file under /root or /tmp,"
	" then run it as python3 <script.py>; allowed inside the"
	" sandbox/authorized range only — no attacking or unauthorized"
	" probing of external targets.\n"
	"7. After sandbox_spawn, if no follow-up is needed you must immediately call sandbox_destroy <name>; never leave a sandbox behind."
	"\n8. To diagnose kernel errors, service failures, or \"last N minutes\" logs, first use exec_run with dmesg, journalctl, or systemctl --failed, then combine with telemetry; a short procfs/netlink telemetry window is not a substitute for logs — never claim there were no errors in the last N minutes based on it."
	"\n9. sysfs_get only reads /sys, /proc/sys, /proc/irq, /proc/ai, /proc/pressure, /proc/net; for /proc/<pid>/* and /etc/* use exec_run (e.g. ps, cat) or the dedicated tool; do not retry sysfs_get with paths outside its scope."
	"\n10. For path tasks, use the exact absolute path the user gave (including subdirectories); do not rewrite it to a parent directory or a different name; create the target directory before writing."
	"\nAsking discipline (when to ask the user, when not to):\n"
	"1. Search before asking: if a read-only tool (D0) can find the answer, never ask the user.\n"
	"2. Ask only about result-changing ambiguity: ask only when intent/target/scope is unclear AND different readings lead to different actions; for minor issues or pure preferences pick a sensible default and state it in the answer.\n"
	"3. Always recommend: every clarify must carry recommended and why; ask one question at a time.\n"
	"4. Question budget: at most 2 questions per task chain; after that act on your best reading and state assumptions at the top of the answer (\"I proceeded assuming X; correct me if wrong\").\n"
	"5. Never re-ask: do not re-ask what was already asked or answered in this session; reuse preferences the user has already expressed.\n"
	"6. Clarify is not authorization: D2+ dangerous actions always go through lease/confirm; never use clarify as a substitute.\n"
	"7. When clear, act: if the instruction is clear, the evidence is unique, or it is an urgent diagnosis, execute without asking.\n"
,
	[TR_ASK_SYS_RULES] =
	"\nRules:\n"
	"1. Only use the tools listed above, names must match exactly; several"
	" calls per turn are allowed.\n"
	"2. Tool arguments must match the given names and types; never call"
	" non-existent tools, never fabricate tool results.\n"
	"3. For any question about system interfaces, /proc/ai and /sys/kernel/ai"
	" nodes, kernel parameters, how to operate, or tool usage (how to call,"
	" how to inspect, how to configure), you must first search the memory"
	" store with memory.search (includes aikernel-interface corpus), then"
	" answer or act based on hits; never guess interface usage.\n"
	"4. For action requests (tune/set/freeze/apply/yield, etc.) you must"
	" actually call the corresponding tool, not just write explanations or"
	" sample commands; provide all required arguments (e.g. target process"
	" pid, target value — use the exact pid the user mentions).\n"
	"5. Gather information by calling tools first; answer only after you have"
	" everything you need.\n"
	"6. If a tool fails, state the cause honestly and retry with corrected"
	" arguments as suggested; answer in English, concise and accurate.\n"
	"7. Running code with python3 is a high-impact operation (W2, normally"
	" confirmed per run; execute directly when assume_yes pre-authorization"
	" is declared): write the code to a .py file under /root or /tmp first,"
	" then run it as python3 <script.py>; bare -c expressions are"
	" forbidden; allowed inside the sandbox/authorized range only — no"
	" attacking or unauthorized probing of external targets.\n"
	"8. After sandbox_spawn, if no follow-up is needed you must immediately call sandbox_destroy <name>; never leave a sandbox behind.\n"
	"\n9. To diagnose kernel errors, service failures, or \"last N minutes\" logs, first use exec_run with dmesg, journalctl, or systemctl --failed, then combine with telemetry; a short procfs/netlink telemetry window is not a substitute for logs — never claim there were no errors in the last N minutes based on it."
	"\n10. sysfs_get only reads /sys, /proc/sys, /proc/irq, /proc/ai, /proc/pressure, /proc/net; for /proc/<pid>/* and /etc/* use exec_run (e.g. ps, cat) or the dedicated tool; do not retry sysfs_get with paths outside its scope."
	"\n11. For path tasks, use the exact absolute path the user gave (including subdirectories); do not rewrite it to a parent directory or a different name; create the target directory before writing."
	"\nAsking discipline (when to ask the user, when not to):\n"
	"1. Search before asking: if a read-only tool (D0) can find the answer, never ask the user.\n"
	"2. Ask only about result-changing ambiguity: ask only when intent/target/scope is unclear AND different readings lead to different actions; for minor issues or pure preferences pick a sensible default and state it in the answer.\n"
	"3. Always recommend: every clarify must carry recommended and why; ask one question at a time.\n"
	"4. Question budget: at most 2 questions per task chain; after that act on your best reading and state assumptions at the top of the answer (\"I proceeded assuming X; correct me if wrong\").\n"
	"5. Never re-ask: do not re-ask what was already asked or answered in this session; reuse preferences the user has already expressed.\n"
	"6. Clarify is not authorization: D2+ dangerous actions always go through lease/confirm; never use clarify as a substitute.\n"
	"7. When clear, act: if the instruction is clear, the evidence is unique, or it is an urgent diagnosis, execute without asking.\n"
,
	[TR_ASK_FALLBACK_RULES] =
	"\nOutput format (important, must be followed strictly):\n"
	"Each of your outputs must be exactly one JSON object, with no other"
	" text:\n"
	"- To call a tool: {\"tool\":\"<tool name>\",\"arguments\":{<args>}}\n"
	"  (arguments is the argument object; parameterless tools take {})\n"
	"- When ready to answer: {\"answer\":\"<answer>\"}\n",
	[TR_ASK_SYS_ASSUME_YES] =
	"\nPre-authorization (-y/AIKERNEL_ASSUME_YES): only D2 local reversible"
	" writes are pre-authorized for this ask (a 1-hour short lease; audit"
	" records an ephemeral lease). D3 (services/network/kernel parameters/"
	" power/package management/arbitrary code) and D4 (users/keys/boot"
	" chain/policy) are NOT auto-approved; they still need human"
	" confirmation or an explicit Principal lease. If a tool returns"
	" CONFIRM_REQUIRED: report the action/impact/rollback/nonce to the user"
	" and wait for /lease confirm or a new lease; do NOT retry the same call"
	" and do not assume it was authorized.\n",
	[TR_ASK_SYS_LANGUAGE] =
	"\nLanguage: answer in the language of the user's question by default;"
	" when the user asks in Chinese, you must answer in Chinese unless the"
	" user explicitly requests another language.\n",
	[TR_ASK_TOOLS_LIST_FMT]		= "%sAvailable tools:\n%s%s%s",
	[TR_ASK_CATALOG_HDR]		= "Tool catalog (name purpose):\n",
	[TR_ASK_SENSE_FMT]		= "Latest kernel telemetry (NETLINK_AI SENSE,"
					  " %u records):\n%.*s\n",
	[TR_ASK_STATUS_FMT]		= "Compact kernel status summary"
					  " (/proc/ai/status, <=2KB; use the "
					  "procfs_read_status tool for the full"
					  " content on demand):\n%s\n",
	[TR_ASK_STATUS_NOTE]		= "Note: sampled_skip is deliberate"
					  " down-sampling (normal by design, not"
					  " loss); dropped is real loss (ring full"
					  " / slow consumer). Judge ring overflow"
					  " by dropped, not sampled_skip.\n",
	[TR_ASK_STATUS_DROPPED_NOTE]	= " (cumulative since startup; not new"
					  " in this turn%s)",
	[TR_ASK_STATUS_SKIP_NOTE]	= " (deliberate down-sampling; not loss)",
	[TR_ASK_STATUS_DELTA_FMT]	= "; +%llu since last summary",
	[TR_ASK_MEM_FMT]		= "Relevant memories (SME pre-retrieval hits,"
					  " raw JSON):\n%s\n",
	[TR_ASK_UNKNOWN_TOOL]		= "ERROR: unknown tool '%s' (only tools listed"
					  " in the tool list may be used)",
	[TR_ASK_EMPTY]			= "(empty)",
	[TR_ASK_TC_VERBOSE]		= "  [tool call] %s(%s)\n",
	[TR_ASK_TR_VERBOSE]		= "  [tool result%s] %s%s\n",
	[TR_ASK_TRUNCATED]		= " ...(truncated)",
	[TR_ASK_MORE_LINES]		= "  %s[+%d lines, verbose on for full text]%s\n",
	[TR_ASK_NO_EXEC_OUTPUT]		= "(executor produced no output)",
	[TR_ASK_LIST_SEP]		= ", ",
	[TR_ASK_ROUTER_MERGED]		= "%s\n[framework notice] This retrieval"
					  " activated %d tools: %s. Their full"
					  " definitions are in THIS request's tools"
					  " array — call them right now (R/W1"
					  " directly, W2 after asking the user for"
					  " confirmation). Do not wait for another"
					  " turn and do not reply with a plan only."
					  " If this notice is replayed history and"
					  " the current tools array does not contain"
					  " them, run memory_search again first.",
	[TR_ASK_ROUTER_MERGED_TEXT]	= "%s\n[framework notice] This retrieval"
					  " activated %d tools: %s. You can call"
					  " them right now using the text JSON"
					  " protocol (R/W1 directly, W2 after"
					  " asking the user for confirmation). Do"
					  " not wait for another turn and do not"
					  " reply with a plan only. If this notice"
					  " is replayed history and the current"
					  " tool list does not contain them, run"
					  " memory_search again first.",
	[TR_ASK_ROUTER_ACT_UI]		= "  %s[router] retrieval activated +%d tools"
					  " (joined the following request, now %d/%d)%s\n",
	[TR_ASK_TOOL_RESULT_FMT]	= "[TOOL %s RESULT]\n%s\n"
					  "Continue based on the tool results above"
					  " (output JSON).",
	[TR_ASK_USAGE]			= "Usage: ask <question or task>\n",
	[TR_ASK_USAGE_EX]		= "  e.g. ask How much RAM does this machine"
					  " have, and remember the answer\n",
	[TR_ASK_REG_FAIL]		= "registry load failed",
	[TR_ASK_USER_TASK_FMT]		= "%s%s%sUser task: %s",
	[TR_ASK_HEADER_FMT]		= "Model: %s | Tools: %d/%d active | Route:"
					  " %s | Max rounds: %d | Session: %s"
					  " (%d history)\n",
	[TR_ROUTE_PRE_LABEL]		= "pre_retrieve (framework pre-retrieval)",
	[TR_ROUTE_AUTO_LABEL]		= "autonomous (model-driven retrieval)",
	[TR_ASK_TRIM_FMT]		= "%sHistory window: trimmed oldest %d turns"
					  " (%d -> %d messages, within budget;"
					  " compact can shrink proactively)%s\n",
	[TR_ASK_CTX_SENSE]		= "Context: kernel telemetry summary"
					  " injected\n",
	[TR_ASK_CTX_STATUS]		= "Context: compact kernel status summary"
					  " injected (<=2KB)\n",
	[TR_ASK_CTX_MEM]		= "Context: SME pre-retrieval hits injected"
					  " (top%d)\n",
	[TR_ASK_TOOLS_EXPANDED]		= "  %s[router] tools array expanded"
					  " (%d/%d)%s\n",
	[TR_ASK_ROUND_FMT]		= "%s[round %d]%s ",
	[TR_ASK_FALLBACK_RETRY]		= "  (request failed, retrying in text-"
					  "protocol fallback mode)\n",
	[TR_ASK_MODEL_FAIL]		= "ask: model call failed: %s\n",
	[TR_ASK_NO_RESULT]		= "ask: model returned no result\n",
	[TR_ASK_TRUNC_WARN]		= "%s(generation truncated at max_tokens;"
					  " raise it via config set max_tokens)%s\n",
	[TR_ASK_TC_REQ]			= "  %s(model requested %d tool calls)%s\n",
	[TR_ASK_FALLBACK_TC]		= "  %s(fallback mode: parsed a tool call)%s\n",
	[TR_ASK_SWITCH_FALLBACK]	= "  %s(model ignored native tools, switching to"
					  " text protocol)%s\n",
	[TR_ASK_EMPTY_ANSWER]		= "(empty answer)",
	[TR_ASK_MAX_ROUNDS]		= "ask: max rounds limit (%d) reached, forcing"
					  " stop\n",
	[TR_ASK_CTX_WARN]		= "%s[warning] this request's context budget"
					  " %d%% used (last request prompt;"
					  " compact can shrink history)%s\n",
	[TR_ASK_TOOL_SUMMARY_FMT]	= "\n[Summary: original %ld bytes / ~%d"
					  " lines, tool %s; re-invoke the tool to"
					  " get the full result]",
	[TR_ASK_TOOL_SUMMARY_UI]	= "  %s[summary]%s %s: original %ld bytes"
					  " / ~%d lines over per-item budget, head"
					  " %ld bytes kept in history%s\n",
	[TR_ASK_AUTOCOMPACT_TRY]	= "%s[history over 80%% of budget,"
					  " auto-compacting...]%s\n",
	[TR_ASK_AUTOCOMPACT]		= "[history auto-compacted]\n",
	[TR_ASK_AUTOCOMPACT_FAIL]	= "%s[auto-compact failed (%s); history"
					  " kept as-is]%s\n",
	[TR_ASK_COMPACT_COOLDOWN]	= "%s[compact] only %d/%d turns since"
					  " last compaction, skipping (history"
					  " still trimmed to budget)%s\n",
	[TR_ASK_MAX_ROUNDS_FINAL]	= "ask: max rounds limit (%d) reached;"
					  " tools disabled, requesting final"
					  " conclusion...\n",
	[TR_ASK_FINAL_HINT]		= "The tool-call round limit has been"
					  " reached. Do not call any more tools;"
					  " give a final conclusion based on the"
					  " results above: what was completed, what"
					  " was not, and key evidence/file paths."
					  " Clearly state any gaps if the task is"
					  " incomplete.",
	[TR_ASK_CLARIFY_MEM_NOTE]	= "[clarify] Continuing with your earlier"
					  " choice: %s. Do not re-ask; reuse that"
					  " choice and proceed.",
	[TR_ASK_CLARIFY_BUDGET_NOTE]	= "[clarify] Question budget reached: act"
					  " on your best understanding and state"
					  " assumptions at the top of the answer"
					  " (e.g. \"I proceeded assuming X; correct"
					  " me if wrong\"); do not call clarify"
					  " again.",
	[TR_ASK_CLARIFY_AUTO_NOTE]	= "[clarify] That clarification expired and"
					  " the recommended option was auto-selected"
					  ": %s. Proceed with it and state this"
					  " assumption.",

	/* status */
	[TR_ST_STREAMING_FMT]		= "  streaming   : built-in (delta live"
					  " delivery; config stream=%s)\n",
	[TR_ST_SME]			= "  memory(SME) : external service"
					  " 127.0.0.1:8760 (see tool descriptions)\n",

	/* config */
	[TR_CFG_MODEL_LABEL]		= "Model       ",
	[TR_CFG_MODEL_FMT]		= "%s (default %s)",
	[TR_CFG_NOTLOADED]		= "(not loaded)",
	[TR_CFG_NOTSET]			= "(not set)",
	[TR_CFG_USAGE_FMT]		= "  Last: %s in / %s out %s| Session total:"
					  " %s tok | ctx budget %s%d%%%s"
					  " (%s / %s)\n",
	[TR_CFG_EST]			= "(estimated) ",
	[TR_CFG_KEYS_HINT]		= "Keys: ctx_len max_tokens stream local_api"
					  " color verbose session lang\n",
	[TR_CFG_CTX_POSINT]		= "config: ctx_len must be a positive"
					  " integer\n",
	[TR_CFG_CTX_CLAMP]		= "config: model %s window limit is %d;"
					  " ctx_len %d clamped to %d\n",
	[TR_CFG_MT_RANGE]		= "config: max_tokens must be 1-131072\n",
	[TR_CFG_STREAM_VAL]		= "config: stream takes on|off\n",
	[TR_CFG_STREAM_NOCOMP]		= "config: streaming is not compiled into this"
					  " binary (CONFIG_AIKERNEL_STREAM_MODE=n),"
					  " staying off\n",
	[TR_CFG_LOCALAPI_VAL]		= "config: local_api takes native|v1\n",
	[TR_CFG_BOOL_VAL]		= "config: %s takes on|off\n",
	[TR_CFG_BAD_SESSION]		= "config: invalid session name '%s'\n",
	[TR_CFG_SESSION_NMSG]		= "session = %s (%d history messages)\n",
	[TR_CFG_SET_USAGE]		= "Usage: config set <key> <value>\n",

	/* shell */
	[TR_SH_NOT_TTY]			= "shell: not an interactive terminal"
					  " (stdin/stdout redirected), refusing to"
					  " enter sub-shell.\n",
	[TR_SH_ENTER]			= "Entering maintenance shell (bash). Type"
					  " exit to return to the AI console.\n",
	[TR_SH_FORK_FAIL]		= "shell: fork failed (%s).\n",
	[TR_SH_EXEC_FAIL]		= "shell: cannot start /bin/bash (%s).\n",
	[TR_SH_START_FAIL]		= "shell: failed to start /bin/bash.\n",
	[TR_SH_RETURN]			= "Returned to the AI console.\n",

	/* netlink */
	[TR_NL_HELP_SENSE]		= "   fetch kernel AI telemetry records\n",
	[TR_NL_HELP_ACT]		= "                                                  apply decision (CAP_SYS_ADMIN required)\n",
	[TR_NL_HELP_REG]		= "  netlink reg                                     register this process's portid (CAP_SYS_ADMIN required)\n",
	[TR_NL_HELP_COUNT]		= "count:  1~4096 (default 32)\n",
	[TR_NL_HELP_HEXDATA]		= "hexdata: up to 64 bytes, e.g. \"aabbcc\" or \"aa bb cc\"\n",
	[TR_NL_KERN_REJECT]		= "kernel rejected: errno=%d (%s)\n",
	[TR_NL_HINT]			= "hint: %s\n",
	[TR_NL_SEND_FAIL]		= "send failed: %s\n",
	[TR_NL_PARSE_FAIL]		= "reply parse failed (kernel protocol mismatch?"
					  " check ai_netlink.h)\n",
	[TR_NL_ERR]			= "error: %s\n",
	[TR_NL_INIT_FAIL]		= "NETLINK_AI socket init failed: %s\n",
	[TR_NL_ALLOC_FAIL]		= "memory allocation failed (%u bytes)\n",
	[TR_NL_NO_RECORDS]		= "(no records)\n",
	[TR_NL_ACT_CONFIRM1]		= "About to apply a decision to the kernel:\n",
	[TR_NL_ACT_CONFIRM2]		= "  domain=%u (%s)  decision_type=%u  "
					  "confidence=%u  data=%zu bytes\n",
	[TR_NL_ACT_CONFIRM3]		= "This requires CAP_SYS_ADMIN (root/sudo) and"
					  " directly affects system behavior."
					  " Confirm execution? [y/N] ",
	[TR_NL_CANCELLED]		= "cancelled\n",
	[TR_NL_ACK_AIERR]		= "ai_err:        %d (policy layer error)\n",
	[TR_NL_ACK_NO_POLICY]		= "no policy matched (executed=0)\n",
	[TR_NL_REG_PORTID]		= "Portid:           %u (kernel-assigned, fixed per process)\n",
	[TR_NL_REG_COUNT]		= "Registered portids: %u/32\n",
	[TR_NL_REG_IDEMPOTENT]		= "Repeated reg is idempotent (kernel dedups by portid)\n",
	[TR_NL_REG_NOARGS]		= "netlink reg takes no arguments\n",

	/* session */
	[TR_SES_BAD_NAME]		= "session: invalid session name '%s'"
					  " (only alphanumerics - _ . allowed)\n",
	[TR_SES_EXISTS_SWITCH]		= "session: session '%s' already exists,"
					  " switching to it (history kept)\n",
	[TR_SES_CREATE_FAIL]		= "session: create failed: %s\n",
	[TR_SES_CREATED]		= "Created and switched to session: %s\n",
	[TR_SES_LIST_EMPTY]		= "(no session files; auto-saved as '%s' on"
					  " ask)\n",
	[TR_SES_LIST_HDR]		= "%-3s %-24s %s\n",
	[TR_SES_HDR_NAME]		= "Session",
	[TR_SES_HDR_COUNT]		= "Messages",
	[TR_SES_RANGE]			= "session: index out of range (1-%d)\n",
	[TR_SES_BAD_TARGET]		= "session: invalid session name '%s'\n",
	[TR_SES_ALREADY_IN]		= "already in session '%s'\n",
	[TR_SES_SWITCHED]		= "Switched to session: %s (%d history"
					  " messages)\n",
	[TR_SES_LOAD_FAIL]		= "session: load failed: %s\n",
	[TR_SES_SHOW]			= "Session '%s': %d messages\n",
	[TR_SES_HELP_NEW]		= "  session new [name]      create and switch\n",
	[TR_SES_HELP_LIST]		= "  session list            list sessions\n",
	[TR_SES_HELP_SWITCH]		= "  session switch <name|N> switch session\n",
	[TR_SES_HELP_SAVE]		= "  session save            flush to disk\n",
	[TR_SES_HELP_DELETE]		= "  session delete <name>   delete session\n",
	[TR_SES_HELP_SHOW]		= "  session show [n]        show last n messages\n",
	[TR_SES_SAVED]			= "Session '%s' saved (%d messages, auto-appended"
					  " on each ask)\n",
	[TR_SES_DEL_CURRENT]		= "session: cannot delete the current session"
					  " (switch to another one first)\n",
	[TR_SES_DELETED]		= "Deleted session: %s\n",
	[TR_SES_DELETE_FAIL]		= "session: delete failed: %s\n",

	/* compact */
	[TR_CMP_LOAD_FAIL]		= "compact: session load failed: %s\n",
	[TR_CMP_EMPTY]			= "compact: session '%s' has no history,"
					  " nothing to compress\n",
	[TR_CMP_CAP]			= "compact: history exceeds %d messages,"
					  " compressing only the most recent %d\n",
	[TR_CMP_TAG_TOOLCALL]		= "[tool call] ",
	[TR_CMP_TAG_TOOLRESULT]		= "[tool result] ",
	[TR_CMP_PROMPT]			= "Compress the following AIKernel Shell session"
					  " history into a concise summary (keep:"
					  " the user's goals and preferences,"
					 " operating-system actions taken and their"
					  " results, key facts such as device"
					  " parameters/identifiers/conclusions; drop:"
					  " pleasantries and repetition). Output only"
					  " the summary text:\n\n%s",
	[TR_CMP_SYS_PROMPT]		= "You are a session summarizer. Output only the"
					  " summary text, with no prefix or suffix.",
	[TR_CMP_RUNNING]		= "compact: compressing session '%s' (%d"
					  " messages, %zu bytes)...\n",
	[TR_CMP_SUM_FAIL]		= "compact: summarization failed (original"
					  " session unchanged): %s\n",
	[TR_CMP_CLEAR_FAIL]		= "compact: failed to clear session: %s\n",
	[TR_CMP_WRITE_FAIL]		= "compact: failed to write summary: %s\n",
	[TR_CMP_FALLBACK]		= "compact: summarization failed, fell back to"
					  " per-turn local trimming, dropped %d oldest"
					  " turns (session stays usable)\n",
	[TR_CMP_DONE]			= "compact: done, history replaced by summary +"
					  " %d recent messages%s\n",
	[TR_CMP_TRUNC]			= "compact: summarization unavailable, degraded"
					  " to deterministic budget truncation%s\n",
	[TR_CMP_GUARD]			= "compact: consecutive compaction limit"
					  " reached; truncating only (no more summary"
					  " requests)%s\n",

	/* W42: sandbox channel (sandbox + sub-agent) */
	[TR_SB_CREATED]			= "sandbox created (mountpoint ready;"
					  " tmpfs empty root mounted on run)\n",
	[TR_SB_SPAWN_START]		= "sub-agent dispatched into sandbox"
					  " (aik-sandbox run, restricted tool"
					  " table injected)\n",
	[TR_SB_DONE]			= "sandbox task finished: sandbox=%s"
					  " elapsed=%ds dispatcher_exit=%d"
					  " task_status=%s\n",
	[TR_SB_TIMEOUT]			= "sandbox task timed out, process group"
					  " SIGKILLed: sandbox=%s budget=%ds\n",
	[TR_SB_DESTROYED]		= "sandbox destroyed (data gone with its"
					  " tmpfs)\n",
	[TR_SB_TAIL_HDR]		= "sub-agent output tail (last 4KB)",
	[TR_SB_DESTROY_REMIND]		= "\nReminder: when no longer needed, immediately call sandbox_destroy %s to burn the sandbox; do not leave host residue.\n",

	/* 命令描述（en 侧留 NULL：回退注册表原文，保持单一来源） */

	/* ---- W43：plan 只读模式 ---- */
	[TR_PLAN_ON]			= "Entered plan (read-only research) mode: writes "
					  "disabled. Use /unplan to exit.\n",
	[TR_PLAN_OFF]			= "Exited plan mode; full tool access restored.\n",
	[TR_PLAN_DENY]			= "ERROR: DENIED: plan mode: read-only research, writes "
					  "disabled (tool %s risk=%s blocked). Use /unplan "
					  "to exit before executing.\n",
	[TR_PLAN_SYS_NOTE]		= "\nYou are in plan (research) mode: research "
					  "and read-only only, no write actions; produce a "
					  "plan/analysis, do not make changes.\n",

	/* ---- W43：slash 命令 ---- */
	[TR_TOOLS_HDR]			= "  ID   Name                           Channel"
					  "       Risk  Description\n",
	[TR_TOOLS_ROW]			= "  %-4d %-28s %-13s %-5s %s\n",
	[TR_TOOLS_TOTAL]		= "%d matched / %d registered\n",
	[TR_TOOLS_FILTER]		= "filter: %s\n",
	[TR_TOOLS_EMPTY]		= "No tools match \"%s\"; drop the filter or try "
					  "another\n",
	[TR_SANDBOX_USAGE]		= "Usage: /sandbox status | create <name> | "
					  "destroy <name>\n(spawn belongs to the ask loop: ask "
					  "the AI to dispatch a sub-agent)\n",
	[TR_REPL_SLASH_UNKNOWN]	= "Unknown command: /%s\nType /help to list "
					  "commands.\n",
	[TR_SES_STATUS_HDR]		= "Session: %s\nHistory: %d messages\nSME memory: ",
	[TR_SME_REACHABLE]		= "reachable\n",
	[TR_SME_UNREACHABLE]		= "unreachable (memory retrieval degraded; "
					  "answers continue, results labeled)\n",

	/* ---- W43：SME 失忆降级 ---- */
	[TR_SME_DEGRADED_NOTE]		= "\n[SME memory service unreachable; no memory "
					  "retrieval this turn; answer from current context]\n",

	/* ---- W43：命令描述（英文模式走注册表原文，此处为完整对照） ---- */
	[TR_CMD_PLAN]			= "Enter plan (read-only research) mode",
	[TR_CMD_UNPLAN]			= "Exit plan mode (full tool access restored)",
	[TR_CMD_TOOLS]			= "List tool registry (filter by channel/keyword)",
	[TR_CMD_SANDBOX]		= "Manage sandboxes (status/create/destroy)",

	/* ---- W65：Ctrl-C / argument auto-repair / --version ---- */
	[TR_ASK_CANCELLED]		= "%s(cancelled; type the next request, or "
					  "Ctrl-D to exit)%s\n",
	[TR_ASK_ARG_REPAIR]		= "%s(invalid tool arguments; structured "
					  "usage fed back to the model and retried "
					  "once)%s\n",
	[TR_ASK_ARG_REPAIR_HINT]	= "The previous tool call was rejected with "
					  "E_PARAM_*. Retry once using the USAGE and "
					  "AVAILABLE list in the error: command is "
					  "one whitelisted command name, options and "
					  "operands go in the args array, file content "
					  "goes in input. Do not explain or output a "
					  "plan; call the tool now.",
	[TR_VERSION_FMT]		= "ai (AIKernel Shell) %s\nKernel: Linux %s\n",

	/* ---- W74: authority leases / D0-D4 ---- */
	[TR_LEASE_PANEL]		= "\033[1;33m[lease / dangerous action confirmation]\033[0m\n"
					  "  Tool:   %s\n  Danger: %s\n  Lease:  %s\n"
					  "  Impact: %s\n  Rollback: %s\n",
	[TR_LEASE_CONFIRM_YN]		= "Continue? [y/N] ",
	[TR_LEASE_D4_PROMPT]		= "D4 strong confirmation: type exactly \"CONFIRM D4 %s\": ",
	[TR_LEASE_D4_MISMATCH]		= "D4 confirmation phrase mismatch, refused.\n",
	[TR_LEASE_ROLLBACK_D2]		= "Restore from pre-change backup if any; the tool result records the command",
	[TR_LEASE_ROLLBACK_D3]		= "Apply the inverse action (e.g. systemctl) or restore config backups; restart the service if needed",
	[TR_LEASE_ROLLBACK_D4]		= "Follow the change plan and restore sudoers/grub/user database backups manually",
	[TR_LEASE_CONFIRM_QUESTION]	= "Continue?",
	[TR_LEASE_DENY_SCOPE]		= "Lease scope violation: action not covered, refused (cannot be bypassed by interactive confirmation)",
	[TR_LEASE_DENY_CEILING]		= "Lease ceiling violation: action exceeds risk_ceiling, refused",
	[TR_LEASE_DENY_EXPIRED]		= "Lease expired: D1+ actions refused",
	[TR_LEASE_DENY_REVOKED]		= "Lease revoked: D1+ actions refused",
	[TR_LEASE_DENY_PRINCIPAL]	= "Lease principal/owner does not match current user, refused",
	[TR_LEASE_DENY_LOAD]		= "Explicit lease unavailable (load/parse/store validation failed), refused",
	[TR_LEASE_DENY_CONFIRM]		= "Confirmation token invalid/expired/used or bound arguments mismatch, refused",
	[TR_LEASE_DENY_WORKER]		= "Sandbox worker allows D0/D1 only; D2+ refused",
	[TR_LEASE_DENY_D4_ROOT]		= "D4 actions can only be confirmed by root; non-root refused",
	[TR_LEASE_CONFIRM_REQUIRED]	= "Confirmation required: Principal can inspect with /lease pending and approve with /lease confirm <nonce>; retry with AIKERNEL_CONFIRM_NONCE or --confirm <nonce>",
	[TR_LEASE_EPHEMERAL_NOTE]	= "Note: --yes creates only a D2 ephemeral lease for this ask (1h); D3/D4 still require confirmation.\n",
	[TR_LEASE_EXPLICIT_NOTE]	= "Loaded explicit lease %s (ceiling=%s, %d scope entries)\n",
	[TR_LEASE_ERR_LOAD]		= "Error: %s\n",
	[TR_CMD_LEASE]			= "Manage authority leases (list/show/issue/revoke/pending/confirm)",
	[TR_LEASE_CMD_USAGE]		= "Usage: /lease list | show <id> | "
					  "issue --scope <csv> --ceiling D2 "
					  "--mission <text> --ttl <sec> | "
					  "revoke <id> | pending | "
					  "confirm <nonce> yes|no"
					  " (D4: CONFIRM D4 <nonce>)\n",
	[TR_LEASE_ROOT_TTY]		= "This operation requires root and an interactive TTY.\n",
	[TR_LEASE_ISSUE_PROMPT]		= "About to issue lease %s (scope=%s ceiling=%s ttl=%ld). Type ISSUE %s to confirm: ",
	[TR_LEASE_ISSUE_BAD]		= "Confirmation phrase mismatch; lease not issued.\n",
	[TR_LEASE_ISSUED]		= "Issued lease %s\nPath: %s\n",
	[TR_LEASE_REVOKE_PROMPT]	= "About to revoke lease %s. Type REVOKE %s to confirm: ",
	[TR_LEASE_REVOKE_BAD]		= "Confirmation phrase mismatch; lease not revoked.\n",
	[TR_LEASE_REVOKED]		= "Revoked lease %s\n",
	[TR_LEASE_LIST_HDR]		= "ID\tPRINCIPAL\tCEILING\tEXPIRES\t"
					  "REVOKED\tSCOPE\n",
	[TR_LEASE_LIST_ROW]		= "%s\t%s\t%s\t%lld\t%s\t%s\n",
	[TR_LEASE_LIST_EMPTY]		= "(no leases)\n",
	[TR_LEASE_SHOW_FMT]		= "lease_id: %s\nprincipal: %s\n"
					  "subject: %s\nrisk_ceiling: %s\n"
					  "mission: %s\nissued_at: %lld\n"
					  "expires_at: %lld\nrevoked: %s\n"
					  "scope: %s\n",
	[TR_LEASE_PENDING_EMPTY]	= "(no pending confirmations)\n",
	[TR_LEASE_PENDING_FMT]		= "%s\t%s\t%s\n",
	[TR_LEASE_CONFIRM_OK]		= "Confirmation recorded: %s (%s)\n",
	[TR_LEASE_CONFIRM_NO]		= "Denied: %s\n",
	[TR_LEASE_UNKNOWN_SUB]		= "Unknown /lease subcommand: %s\n",
	[TR_LEASE_STORE_ERR]		= "Lease store error: %s\n",
};

const char *tr(enum ai_tr_key key)
{
	int k = (int)key;

	if (k < 0 || k >= (int)TR__COUNT)
		return "";
	if (g_zh)
		return t_zh[key] ? t_zh[key] : "";
	/* en 缺项回退中文表（防御：新增键漏译时不至于输出空串） */
	return t_en[key] ? t_en[key] :
	       (t_zh[key] ? t_zh[key] : "");
}

/* ---- 命令帮助描述：命令名 → 翻译键 ---- */
struct cmd_desc_map {
	const char *name;
	enum ai_tr_key key;
};

static const struct cmd_desc_map s_cmd_desc_map[] = {
	{ "help",           TR_CMD_HELP },
	{ "exit",           TR_CMD_EXIT },
	{ "status",         TR_CMD_STATUS },
	{ "config",         TR_CMD_CONFIG },
	{ "chat",           TR_CMD_CHAT },
	{ "ask",            TR_CMD_ASK },
	{ "model",          TR_CMD_MODEL },
	{ "network",        TR_CMD_NETWORK },
	{ "netlink",        TR_CMD_NETLINK },
	{ "session",        TR_CMD_SESSION },
	{ "compact",        TR_CMD_COMPACT },
	{ "setup-password", TR_CMD_SETUP_PASSWORD },
	{ "shell",          TR_CMD_SHELL },
	{ "lang",           TR_CMD_LANG },
	{ "plan",           TR_CMD_PLAN },
	{ "unplan",         TR_CMD_UNPLAN },
	{ "tools",          TR_CMD_TOOLS },
	{ "sandbox",        TR_CMD_SANDBOX },
	{ "lease",          TR_CMD_LEASE },
};

const char *tr_cmd_desc(const char *name)
{
	size_t i;

	if (!name)
		return NULL;
	if (!g_zh)
		return NULL;	/* 英文模式：回退注册表原文 */
	for (i = 0; i < (int)(sizeof(s_cmd_desc_map) /
			      sizeof(s_cmd_desc_map[0])); i++) {
		if (strcmp(s_cmd_desc_map[i].name, name) == 0)
			return t_zh[s_cmd_desc_map[i].key];
	}
	return NULL;
}
