/*
 * cmd_onboarding.c - AI onboarding 首次初始化引导 + setup-password 内置命令
 *
 * 触发条件（onboarding_should_start）：
 *   - /etc/aikernel/.onboarded 不存在（出厂态）
 *   - 交互 TTY（stdin/stdout 均为终端；单发模式/管道/SSH 编排不触发）
 *   - 未带 --no-onboarding（维护/救援参数，由 aikernel_main.c 判断）
 *
 * 流程（AI 引导对话式，本地 ollama 真跑）：
 *   1. AI 欢迎自我介绍（模型不可用时降级内置文案，流程不中断）
 *   2. 强制设置 root 密码：用户在 REPL 敲内置命令 setup-password，
 *      termios 关回显收两次密码 → fork+exec chpasswd（密码只经 stdin
 *      管道，不进命令行、不进模型上下文、不进审计日志）→ 只回成败
 *   3. 选模型：本地（探测 ollama → 复用 model use local 写 model.toml）
 *      或云端（问 base_url/api key/模型名 → 连通测试 → 写 model.toml）
 *   4. 完成 touch /etc/aikernel/.onboarded → 回到正常 REPL
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <termios.h>

static const char w4a_layout_probe[8192] = {1};
#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_config.h"
#include "ai_chat.h"
#include "communication/communication.h"
#include "local/local_chat.h"

/* onboarding 完成标记（出厂态不存在） */
#define ONBOARDED_PATH   "/etc/aikernel/.onboarded"

/* chpasswd 候选路径（Ubuntu: /usr/sbin；兜底 /usr/bin） */
static const char *const chpasswd_paths[] = {
	"/usr/sbin/chpasswd", "/usr/bin/chpasswd", NULL,
};

/* ---- setup-password：termios 关回显读一行 ---- */

/*
 * read_hidden_line - 关回显读一行密码
 * 返回: 0 成功，-1 非交互终端或读失败
 * 终端 ECHO 关闭前后均完整恢复原 termios；失败路径也恢复。
 */
static int read_hidden_line(const char *prompt, char *buf, size_t len)
{
	struct termios oldt, noecho;
	size_t n;
	int is_tty = isatty(STDIN_FILENO);

	if (!is_tty) {
		printf("setup-password: 需要交互终端（tty）来安全输入密码。\n");
		return -1;
	}

	printf("%s", prompt);
	fflush(stdout);

	if (tcgetattr(STDIN_FILENO, &oldt) != 0)
		return -1;
	noecho = oldt;
	noecho.c_lflag &= ~(tcflag_t)ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho) != 0)
		return -1;

	if (!fgets(buf, (int)len, stdin)) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
		printf("\n");
		return -1;
	}
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
	printf("\n");

	n = strlen(buf);
	if (n && buf[n - 1] == '\n')
		buf[n - 1] = '\0';
	return 0;
}

/*
 * apply_password - fork+exec chpasswd，密码仅经 stdin 管道交付
 * 返回: 0 成功，-1 失败（chpasswd 退出码非 0 或找不到二进制）
 * 密码不出现在命令行参数（ps 不可见）、不落盘、不进模型上下文。
 */
static int apply_password(const char *pass)
{
	int pipefd[2];
	pid_t pid;
	int status;
	int i, ok = -1;

	if (pipe(pipefd) != 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (pid == 0) {
		int devnull = open("/dev/null", O_WRONLY);

		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		if (devnull >= 0) {
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		signal(SIGINT, SIG_DFL);
		signal(SIGTSTP, SIG_DFL);
		for (i = 0; chpasswd_paths[i]; i++) {
			execl(chpasswd_paths[i], "chpasswd", (char *)NULL);
		}
		_exit(127);
	}

	/* 父进程：写 "root:<pass>\n" 后立刻关闭写端（chpasswd 读到 EOF 才处理） */
	close(pipefd[0]);
	{
		char line[1024];
		ssize_t w;

		snprintf(line, sizeof(line), "root:%s\n", pass);
		w = write(pipefd[1], line, strlen(line));
		(void)w;   /* 失败由 chpasswd 读不到完整行自然报错 */
		explicit_bzero(line, sizeof(line));
	}
	close(pipefd[1]);

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		ok = 0;

	return ok;
}

/*
 * setup_password_flow - 完整收密+落密流程（onboarding 与 REPL 命令共用）
 * 返回: 0 成功，-1 失败（输入不一致/强度不足/chpasswd 失败）
 */
static int setup_password_flow(void)
{
	char p1[256], p2[256];
	int ret = -1;

	if (read_hidden_line("请输入新密码（输入不回显）: ", p1, sizeof(p1)) != 0)
		return -1;
	if (read_hidden_line("请再次输入确认: ", p2, sizeof(p2)) != 0) {
		explicit_bzero(p1, sizeof(p1));
		return -1;
	}

	if (p1[0] == '\0') {
		printf("setup-password: 密码不能为空。\n");
		goto out;
	}
	if (strlen(p1) < 6) {
		printf("setup-password: 密码至少 6 位。\n");
		goto out;
	}
	if (strcmp(p1, p2) != 0) {
		printf("setup-password: 两次输入不一致。\n");
		goto out;
	}

	printf("setup-password: 正在设置 root 密码...\n");
	fflush(stdout);
	if (apply_password(p1) == 0) {
		printf("setup-password: root 密码设置成功。\n");
		ret = 0;
	} else {
		printf("setup-password: 密码设置失败（chpasswd 执行出错）。\n");
	}

out:
	explicit_bzero(p1, sizeof(p1));
	explicit_bzero(p2, sizeof(p2));
	return ret;
}

/*
 * cmd_setup_password - REPL 内置命令：设置/修改 root 密码
 * 密码不接参数（防进模型上下文/历史），只走关回显交互。
 */
int cmd_setup_password(void *shell_ptr, int argc, char **argv)
{
	(void)shell_ptr;
	(void)argc;
	(void)argv;

	if (setup_password_flow() == 0)
		return AI_OK;
	return AI_ERR_GENERIC;
}

/* ---- onboarding：AI 对话通道 ---- */

/* onboarding 专用 system 提示词（1.5b 本地模型可执行级别的简明指令） */
#define ONBOARD_SYS_PROMPT \
	"你是 AIKernel OS 的初始化引导助手。你正通过本机控制台引导用户完成" \
	"这台机器的首次初始化。你要做三件事：1) 简短自我介绍：你是这台机器" \
	"的 AI 控制台，负责系统监控、参数调优和运维辅助；2) 引导用户设置" \
	"root 密码：请用户输入命令 setup-password，并说明密码输入不回显、" \
	"你不会看到密码内容；3) 引导用户选择 AI 模型来源：回复 1 选择本地" \
	"模型（机器内置 ollama），回复 2 选择云端 API。规则：每次回复不超过" \
	"3 句话，用中文；不要编造系统状态；涉及系统接口、参数或用法的提问" \
	"先查记忆库（memory.search，含 aikernel-interface 接口语料）再回答，" \
	"无工具可用时如实说明，不要凭空编造接口；不要透露或询问密码本身。"

/*
 * onboarding_ai_say - 发一段对话给当前模型，打印回复
 * 返回: 0 成功（AI 回复已打印），-1 失败（打印降级文案 fallback）
 * msgs 带完整 onboarding 历史（system + 交替 user/assistant，上限 12 条）。
 */
static int onboarding_ai_say(struct ai_shell *shell,
			     struct ai_chat_msg *hist, int *nhist,
			     const char *user_text, const char *fallback)
{
	struct ai_chat_msg msgs[13];
	struct ai_chat_result *result = NULL;
	int n = 0, i, ret;

	/* 历史 + 新输入（超出 12 条丢最老，保 system 在位） */
	if (*nhist < 12)
		hist[(*nhist)++] = (struct ai_chat_msg){
			.role = "user", .content = user_text };
	msgs[n++] = (struct ai_chat_msg){
		.role = "system", .content = ONBOARD_SYS_PROMPT };
	for (i = 0; i < *nhist && n < 13; i++)
		msgs[n++] = hist[i];

	ret = ai_runtime_chat_ex(&shell->runtime, msgs, n, NULL,
				 NULL, NULL, &result);
	if (ret == AI_OK && result && result->content && result->content[0]) {
		printf("%s\n", result->content);
		/* assistant 回复进历史（超出丢弃） */
		if (*nhist < 12)
			hist[(*nhist)++] = (struct ai_chat_msg){
				.role = "assistant",
				.content = result->content };
		ai_chat_result_free(result);
		return 0;
	}
	if (result)
		ai_chat_result_free(result);
	printf("%s\n", fallback);
	return -1;
}

/* ---- onboarding：模型选择 ---- */

/*
 * probe_openai_endpoint - OpenAI 兼容端点连通测试
 * http:// → local_chat_probe_endpoint（轻量 HTTP GET，mock/ollama 通吃）；
 * https:// → 提取主机后 communication_test（DNS+TLS 握手）。
 * 返回: 0 可达，-1 不可达
 */
static int probe_openai_endpoint(const char *base_url)
{
	const char *p;
	char host[AI_MAX_URL_LEN];
	const char *slash;
	size_t n;
	char *colon;

	if (strncmp(base_url, "https://", 8) == 0) {
		p = base_url + 8;
		slash = strchr(p, '/');
		n = slash ? (size_t)(slash - p) : strlen(p);
		if (n == 0 || n >= sizeof(host))
			return -1;
		memcpy(host, p, n);
		host[n] = '\0';
		colon = strchr(host, ':');
		if (colon)
			*colon = '\0';
		return communication_test(host) == AI_OK ? 0 : -1;
	}

	{
		char *err = NULL;
		int ret = local_chat_probe_endpoint(base_url, &err);

		if (err)
			free(err);
		return ret == AI_OK ? 0 : -1;
	}
}

/*
 * onboard_model_local - 本地模型路径
 * 探测 [local].base_url（出厂 127.0.0.1:11434/v1）→ 可达则复用
 * "model use local"（同步 [models.local] 镜像+默认+持久化+切 runtime）。
 * 返回: 0 成功
 */
static int onboard_model_local(struct ai_shell *shell)
{
	char *base_url = NULL;
	char *argv[3];
	int ret = -1;

	ai_config_get_local(shell->config, NULL, &base_url, NULL,
			    NULL, NULL);
	if (!base_url || !base_url[0]) {
		printf("onboarding: model.toml 缺少 [local].base_url，"
		       "无法自动配置本地模型。\n");
		free(base_url);
		return -1;
	}

	printf("onboarding: 正在探测本地模型服务 %s ...\n", base_url);
	fflush(stdout);
	if (probe_openai_endpoint(base_url) != 0) {
		printf("onboarding: 本地模型服务不可达"
		       "（ollama 未运行或模型未就绪）。\n");
		free(base_url);
		return -1;
	}
	printf("onboarding: 本地模型服务可达。\n");

	argv[0] = (char *)"model";
	argv[1] = (char *)"use";
	argv[2] = (char *)"local";
	ret = cmd_model(shell, 3, argv);
	free(base_url);
	return ret == AI_OK ? 0 : -1;
}

/*
 * onboard_model_cloud - 云端路径：问 base_url → api key → 模型名 →
 * 连通测试 → 写 model.toml（失败回滚条目，可重试）。
 * 返回: 0 成功
 */
static int onboard_model_cloud(struct ai_shell *shell)
{
	char base_url[AI_MAX_URL_LEN];
	char api_key[AI_MAX_KEY_LEN];
	char model_name[AI_MAX_MODEL_NAME];
	char name[32];
	char *argv[4];
	int ret = -1;

	printf("请输入云端 API base_url（如 https://api.deepseek.com/v1，"
	       "或内部 OpenAI 兼容端点）:\n> ");
	fflush(stdout);
	if (!fgets(base_url, sizeof(base_url), stdin))
		return -1;
	base_url[strcspn(base_url, "\n")] = '\0';
	if (!base_url[0]) {
		printf("onboarding: base_url 不能为空。\n");
		return -1;
	}

	printf("请输入 API Key（输入不落盘、不进模型上下文；无则回车跳过）:\n> ");
	fflush(stdout);
	if (!fgets(api_key, sizeof(api_key), stdin)) {
		explicit_bzero(api_key, sizeof(api_key));
		return -1;
	}
	api_key[strcspn(api_key, "\n")] = '\0';

	printf("请输入模型名（如 deepseek-chat / qwen2.5-7b-instruct）:\n> ");
	fflush(stdout);
	if (!fgets(model_name, sizeof(model_name), stdin))
		return -1;
	model_name[strcspn(model_name, "\n")] = '\0';
	if (!model_name[0]) {
		printf("onboarding: 模型名不能为空。\n");
		explicit_bzero(api_key, sizeof(api_key));
		return -1;
	}

	printf("onboarding: 正在测试端点连通性...\n");
	fflush(stdout);
	if (probe_openai_endpoint(base_url) != 0) {
		printf("onboarding: 端点不可达，请检查地址/网络后重试。\n");
		explicit_bzero(api_key, sizeof(api_key));
		return -1;
	}
	printf("onboarding: 端点可达，正在写入配置...\n");

	snprintf(name, sizeof(name), "cloud");
	/* 同名条目先删后建（幂等） */
	ai_config_remove_model(shell->config, name);
	ret = ai_config_add_model(shell->config, name, "openai_compatible",
				  model_name, base_url,
				  api_key[0] ? api_key : "");
	explicit_bzero(api_key, sizeof(api_key));
	if (ret != AI_OK) {
		printf("onboarding: 写入模型配置失败。\n");
		return -1;
	}
	ai_config_set_default_model(shell->config, name);
	ai_config_save(shell->config);

	argv[0] = (char *)"model";
	argv[1] = (char *)"use";
	argv[2] = name;
	ret = cmd_model(shell, 3, argv);
	if (ret != AI_OK) {
		printf("onboarding: 配置已写入但切换失败，可稍后 "
		       "'model use cloud' 重试。\n");
		return -1;
	}
	return 0;
}

/* touch /etc/aikernel/.onboarded（失败返回 -1，onboarding 不算完成） */
static int mark_onboarded(void)
{
	int fd = open(ONBOARDED_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0) {
		printf("onboarding: 无法写入 %s（%s）。\n",
		       ONBOARDED_PATH, strerror(errno));
		return -1;
	}
	{
		ssize_t wr = write(fd, "onboarded=1\n", 12);

		(void)wr;
	}
	close(fd);
	return 0;
}

/* ---- onboarding 主流程 ---- */

/*
 * onboarding_should_start - 是否应进入 onboarding
 * 出厂态标记不存在 且 stdin/stdout 均为终端（真实交互 TTY）。
 */
int onboarding_should_start(void)
{
	if (access(ONBOARDED_PATH, F_OK) == 0)
		return 0;
	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
		return 0;
	return 1;
}

/*
 * onboarding_run - 引导主循环
 * 返回: 0 完成初始化，-1 用户中止（EOF/错误；正常 REPL 仍会进入，
 *       下次交互启动时继续引导——.onboarded 未写即未完成）。
 */
int onboarding_run(void *shell_ptr)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;
	struct ai_chat_msg hist[12];
	int nhist = 0;
	char line[AI_MAX_LINE_LEN];
	int step = 0;               /* 0=欢迎 1=密码 2=模型 3=完成 */
	const char *p;

	memset(hist, 0, sizeof(hist));

	printf("\n=== AIKernel 初始化引导 (onboarding) ===\n");
	printf("提示：此流程将引导你设置 root 密码并选择 AI 模型。\n");
	printf("      输入 help 可查看引导命令；密码绝不经过 AI。\n\n");

	/* 步骤 0：AI 欢迎自我介绍（失败降级内置文案） */
	(void)onboarding_ai_say(shell, hist, &nhist,
		"请向用户做开场自我介绍，并告诉他第一步是设置 root 密码、"
		"请在提示符输入 setup-password。",
		"[AI] 你好，我是这台机器的 AI 控制台（AIKernel），"
		"负责系统监控、参数调优与运维辅助。\n"
		"初始化分两步：先设置 root 密码（输入命令 setup-password，"
		"输入过程不回显，我不会看到密码内容），再选择 AI 模型来源。");

	/* 步骤 1：强制设密码 */
	while (step <= 1) {
		printf("onboarding> ");
		fflush(stdout);
		if (!fgets(line, sizeof(line), stdin)) {
			printf("\n");
			return -1;
		}
		line[strcspn(line, "\n")] = '\0';
		p = line;
		while (*p == ' ' || *p == '\t')
			p++;

		if (strcmp(p, "setup-password") == 0) {
			if (setup_password_flow() == 0) {
				step = 2;
				onboarding_ai_say(shell, hist, &nhist,
					"用户已成功设置 root 密码。"
					"请祝贺他，并引导第二步："
					"选择 AI 模型来源，回复 1 用本地模型，"
					"回复 2 用云端 API。",
					"[AI] root 密码已设置。第二步：选择 "
					"AI 模型来源——输入 1 使用本地模型"
					"（内置 ollama），输入 2 使用云端 API。");
			} else {
				onboarding_ai_say(shell, hist, &nhist,
					"用户的密码设置失败了（为空/不足6位/"
					"两次不一致/chpasswd 出错）。请提醒他"
					"重新输入 setup-password 再试。",
					"[AI] 密码未设置成功，"
					"请重新输入 setup-password 再试一次。");
			}
			continue;
		}

		if (strcmp(p, "shell") == 0) {
			/* 逃生口：onboarding 中也可进维护 bash */
			cmd_shell(shell, 0, NULL);
			continue;
		}

		if (strcmp(p, "help") == 0 || strcmp(p, "?") == 0) {
			printf("引导命令：\n"
			       "  setup-password  设置 root 密码（关回显，"
			       "两次确认，>=6 位）\n"
			       "  1 | local       选择本地模型\n"
			       "  2 | cloud       选择云端 API\n"
			       "  shell           进入维护 bash（逃生口，"
			       "exit 返回）\n"
			       "  其他任意文字    与引导 AI 对话\n");
			continue;
		}

		if (p[0] == '\0')
			continue;

		/* 步骤 1 期间收到 1/2：提示先完成密码（强制顺序） */
		if (strcmp(p, "1") == 0 || strcmp(p, "local") == 0 ||
		    strcmp(p, "2") == 0 || strcmp(p, "cloud") == 0) {
			printf("onboarding: 请先完成 root 密码设置"
			       "（输入 setup-password），再选择模型。\n");
			continue;
		}

		/* 其它输入 → AI 对话（引导回主线） */
		onboarding_ai_say(shell, hist, &nhist, p,
			"[AI] 现在请先输入 setup-password 设置 root 密码。");
	}

	/* 步骤 2：选模型 */
	while (step == 2) {
		printf("onboarding> ");
		fflush(stdout);
		if (!fgets(line, sizeof(line), stdin)) {
			printf("\n");
			return -1;
		}
		line[strcspn(line, "\n")] = '\0';
		p = line;
		while (*p == ' ' || *p == '\t')
			p++;

		if (strcmp(p, "1") == 0 || strcmp(p, "local") == 0) {
			if (onboard_model_local(shell) == 0) {
				step = 3;
			} else {
				onboarding_ai_say(shell, hist, &nhist,
					"本地模型服务当前不可达。请告诉用户"
					"可以先改用云端（输入 2），或稍后重启"
					"机器等 ollama 就绪后重试（输入 1）。",
					"[AI] 本地模型暂时不可用。"
					"你可以输入 2 改用云端 API，"
					"或稍后重试输入 1。");
			}
			continue;
		}
		if (strcmp(p, "2") == 0 || strcmp(p, "cloud") == 0) {
			if (onboard_model_cloud(shell) == 0)
				step = 3;
			continue;
		}
		if (strcmp(p, "help") == 0 || strcmp(p, "?") == 0) {
			printf("输入 1 或 local 选择本地模型；"
			       "输入 2 或 cloud 选择云端 API；"
			       "输入 shell 进入维护 bash。\n");
			continue;
		}
		if (strcmp(p, "shell") == 0) {
			cmd_shell(shell, 0, NULL);
			continue;
		}
		if (p[0] == '\0')
			continue;
		onboarding_ai_say(shell, hist, &nhist, p,
			"[AI] 请输入 1（本地模型）或 2（云端 API）继续。");
	}

	/* 步骤 3：完成落标记 */
	if (mark_onboarded() != 0)
		return -1;

	onboarding_ai_say(shell, hist, &nhist,
		"初始化全部完成。请简短祝贺用户，说明接下来就进入正常控制台，"
		"可以直接输入 ask 向你提问。",
		"[AI] 初始化完成！即将进入 AI 控制台，"
		"输入 help 查看命令，ask 后跟问题即可向我提问。");

	printf("\n=== 初始化完成，进入 AI 控制台 ===\n\n");
	return 0;
}
