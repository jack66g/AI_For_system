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

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_config.h"
#include "ai_chat.h"
#include "ai_lang.h"
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
		printf("%s", tr(TR_OB_HIDDEN_NEED_TTY));
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

	if (read_hidden_line(tr(TR_OB_PW_PROMPT1), p1, sizeof(p1)) != 0)
		return -1;
	if (read_hidden_line(tr(TR_OB_PW_PROMPT2), p2, sizeof(p2)) != 0) {
		explicit_bzero(p1, sizeof(p1));
		return -1;
	}

	if (p1[0] == '\0') {
		printf("%s", tr(TR_OB_PW_EMPTY));
		goto out;
	}
	if (strlen(p1) < 6) {
		printf("%s", tr(TR_OB_PW_TOO_SHORT));
		goto out;
	}
	if (strcmp(p1, p2) != 0) {
		printf("%s", tr(TR_OB_PW_MISMATCH));
		goto out;
	}

	printf("%s", tr(TR_OB_PW_SETTING));
	fflush(stdout);
	if (apply_password(p1) == 0) {
		printf("%s", tr(TR_OB_PW_OK));
		ret = 0;
	} else {
		printf("%s", tr(TR_OB_PW_FAIL));
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

/* onboarding 专用 system 提示词（1.5b 本地模型可执行级别的简明指令；
 * 双语见 i18n 表 TR_OB_SYS_PROMPT——en 模式指示模型用英文回复） */
#define ONBOARD_SYS_PROMPT tr(TR_OB_SYS_PROMPT)

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
		printf("%s", tr(TR_OB_LOCAL_NO_BASEURL));
		free(base_url);
		return -1;
	}

	printf(tr(TR_OB_LOCAL_PROBING), base_url);
	fflush(stdout);
	if (probe_openai_endpoint(base_url) != 0) {
		printf("%s", tr(TR_OB_LOCAL_UNREACH));
		free(base_url);
		return -1;
	}
	printf("%s", tr(TR_OB_LOCAL_OK));

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

	printf("%s", tr(TR_OB_CLOUD_ASK_URL));
	fflush(stdout);
	if (!fgets(base_url, sizeof(base_url), stdin))
		return -1;
	base_url[strcspn(base_url, "\n")] = '\0';
	if (!base_url[0]) {
		printf("%s", tr(TR_OB_URL_EMPTY));
		return -1;
	}

	printf("%s", tr(TR_OB_CLOUD_ASK_KEY));
	fflush(stdout);
	if (!fgets(api_key, sizeof(api_key), stdin)) {
		explicit_bzero(api_key, sizeof(api_key));
		return -1;
	}
	api_key[strcspn(api_key, "\n")] = '\0';

	printf("%s", tr(TR_OB_CLOUD_ASK_MODEL));
	fflush(stdout);
	if (!fgets(model_name, sizeof(model_name), stdin))
		return -1;
	model_name[strcspn(model_name, "\n")] = '\0';
	if (!model_name[0]) {
		printf("%s", tr(TR_OB_MODEL_EMPTY));
		explicit_bzero(api_key, sizeof(api_key));
		return -1;
	}

	printf("%s", tr(TR_OB_PROBING));
	fflush(stdout);
	if (probe_openai_endpoint(base_url) != 0) {
		printf("%s", tr(TR_OB_ENDPOINT_UNREACH));
		explicit_bzero(api_key, sizeof(api_key));
		return -1;
	}
	printf("%s", tr(TR_OB_ENDPOINT_OK));

	snprintf(name, sizeof(name), "cloud");
	/* 同名条目先删后建（幂等） */
	ai_config_remove_model(shell->config, name);
	ret = ai_config_add_model(shell->config, name, "openai_compatible",
				  model_name, base_url,
				  api_key[0] ? api_key : "");
	explicit_bzero(api_key, sizeof(api_key));
	if (ret != AI_OK) {
		printf("%s", tr(TR_OB_WRITE_FAIL));
		return -1;
	}
	ai_config_set_default_model(shell->config, name);
	ai_config_save(shell->config);

	argv[0] = (char *)"model";
	argv[1] = (char *)"use";
	argv[2] = name;
	ret = cmd_model(shell, 3, argv);
	if (ret != AI_OK) {
		printf("%s", tr(TR_OB_SWITCH_FAIL));
		return -1;
	}
	return 0;
}

/* touch /etc/aikernel/.onboarded（失败返回 -1，onboarding 不算完成） */
static int mark_onboarded(void)
{
	int fd = open(ONBOARDED_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0) {
		printf(tr(TR_OB_MARK_FAIL), ONBOARDED_PATH,
		       strerror(errno));
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

	printf("%s", tr(TR_OB_HEAD));
	printf("%s", tr(TR_OB_HINT1));
	printf("%s", tr(TR_OB_HINT2));

	/* 步骤 0：AI 欢迎自我介绍（失败降级内置文案） */
	(void)onboarding_ai_say(shell, hist, &nhist,
		tr(TR_OB_WELCOME_ASK),
		tr(TR_OB_WELCOME_FALLBACK));

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
					tr(TR_OB_PW_DONE_ASK),
					tr(TR_OB_PW_DONE_FALLBACK));
			} else {
				onboarding_ai_say(shell, hist, &nhist,
					tr(TR_OB_PW_FAIL_ASK),
					tr(TR_OB_PW_FAIL_FALLBACK));
			}
			continue;
		}

		if (strcmp(p, "shell") == 0) {
			/* 逃生口：onboarding 中也可进维护 bash */
			cmd_shell(shell, 0, NULL);
			continue;
		}

		if (strcmp(p, "help") == 0 || strcmp(p, "?") == 0) {
			printf("%s", tr(TR_OB_HELP));
			continue;
		}

		if (p[0] == '\0')
			continue;

		/* 步骤 1 期间收到 1/2：提示先完成密码（强制顺序） */
		if (strcmp(p, "1") == 0 || strcmp(p, "local") == 0 ||
		    strcmp(p, "2") == 0 || strcmp(p, "cloud") == 0) {
			printf("%s", tr(TR_OB_PW_FIRST));
			continue;
		}

		/* 其它输入 → AI 对话（引导回主线） */
		onboarding_ai_say(shell, hist, &nhist, p,
			tr(TR_OB_STEP1_CHAT_FALLBACK));
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
					tr(TR_OB_LOCAL_FAIL_ASK),
					tr(TR_OB_LOCAL_FAIL_FALLBACK));
			}
			continue;
		}
		if (strcmp(p, "2") == 0 || strcmp(p, "cloud") == 0) {
			if (onboard_model_cloud(shell) == 0)
				step = 3;
			continue;
		}
		if (strcmp(p, "help") == 0 || strcmp(p, "?") == 0) {
			printf("%s", tr(TR_OB_STEP2_HELP));
			continue;
		}
		if (strcmp(p, "shell") == 0) {
			cmd_shell(shell, 0, NULL);
			continue;
		}
		if (p[0] == '\0')
			continue;
		onboarding_ai_say(shell, hist, &nhist, p,
			tr(TR_OB_STEP2_CHAT_FALLBACK));
	}

	/* 步骤 3：完成落标记 */
	if (mark_onboarded() != 0)
		return -1;

	onboarding_ai_say(shell, hist, &nhist,
		tr(TR_OB_DONE_ASK),
		tr(TR_OB_DONE_FALLBACK));

	printf("%s", tr(TR_OB_DONE));
	return 0;
}
