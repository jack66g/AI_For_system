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
 *   3. 云端配置（必经，W77d 云端优先）：服务商预设（只预填 base_url，
 *      不内置 key）→ base_url/api_key（关回显）/模型名 → live 1-token
 *      补全连通测试通过才写 model.toml；失败给原因可重试/跳过，
 *      跳过 = 引导未完成（.onboarded 不写）
 *   4. 本地模型（可选）：top-3 推荐（硬件门控）→ 确认 → model install
 *      （多 GB 下载+装后验证）；跳过也正常完成
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
#include "local/local_http.h"
#include "cloud/http/http_client.h"
#include "ai_json_util.h"
#include "model_lifecycle.h"

/* onboarding 完成标记（出厂态不存在；AIK_ONBOARDED_PATH 供测试覆盖） */
static const char *ob_marked_path(void)
{
	const char *env = getenv("AIK_ONBOARDED_PATH");

	return env && env[0] ? env : "/etc/aikernel/.onboarded";
}

/* chpasswd 候选路径（Ubuntu: /usr/sbin；兜底 /usr/bin） */
static const char *const chpasswd_paths[] = {
	"/usr/sbin/chpasswd", "/usr/bin/chpasswd", NULL,
};

/* 测试钩子：AIK_CHPASSWD_BIN 优先（如 /bin/true），避免单测真改 root 密码 */
static const char *chpasswd_bin(int idx)
{
	const char *env;

	if (idx == 0 && (env = getenv("AIK_CHPASSWD_BIN")) && env[0])
		return env;
	return chpasswd_paths[idx];
}

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
		/* 测试/嵌入式路径：上游 onboarding_should_start 已要求真实
		 * TTY；此处降级明读保证可脚本化驱动（不回显关闭不可用） */
		printf("%s", prompt);
		fflush(stdout);
		if (!fgets(buf, (int)len, stdin)) {
			printf("\n");
			return -1;
		}
		buf[strcspn(buf, "\n")] = '\0';
		return 0;
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
		for (i = 0; chpasswd_bin(i); i++) {
			execl(chpasswd_bin(i), "chpasswd", (char *)NULL);
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

/* ---- onboarding：云端配置（必经）与本地模型（可选，W77d 云端优先） ---- */

/* 云端服务商预设：只预填 base_url 模板，绝不内置任何 key */
struct ob_preset {
	const char *label;
	const char *base_url;
};

static const struct ob_preset ob_presets[] = {
	{ "deepseek",                "https://api.deepseek.com/v1" },
	{ "qwen (dashscope compat)", "https://dashscope.aliyuncs.com/compatible-mode/v1" },
	{ "doubao (volcengine ark)", "https://ark.cn-beijing.volces.com/api/v3" },
	{ "glm (zhipu)",             "https://open.bigmodel.cn/api/paas/v4" },
	{ "openai-compatible/custom", "" },
};

#define OB_PRESET_COUNT ((int)(sizeof(ob_presets) / sizeof(ob_presets[0])))
#define OB_CLOUD_SKIP   (-2)   /* 用户跳过云端配置（引导未完成） */

/*
 * read_secret_line - 密钥输入：TTY 关回显；非 TTY（测试/管道）明读
 * 返回: 0 成功，-1 失败
 */
static int read_secret_line(const char *prompt, char *buf, size_t len)
{
	if (isatty(STDIN_FILENO))
		return read_hidden_line(prompt, buf, len);
	printf("%s", prompt);
	fflush(stdout);
	if (!fgets(buf, (int)len, stdin))
		return -1;
	buf[strcspn(buf, "\n")] = '\0';
	return 0;
}

/* live 测试响应聚合（https_post_stream 增量回调） */
struct ob_acc {
	char buf[4096];
	size_t len;
};

static void ob_acc_append(void *ud, const char *data, size_t len)
{
	struct ob_acc *a = ud;

	if (a->len + len < sizeof(a->buf)) {
		memcpy(a->buf + a->len, data, len);
		a->len += len;
		a->buf[a->len] = '\0';
	}
}

/*
 * ob_live_completion_test - 云端 live 连通测试（真实 1-token 补全）
 * POST {base_url}/chat/completions {"model":...,"max_tokens":1,...}；
 * 成功（2xx 有 body）才算通过。失败按 DNS/认证/超时/HTTP 归因。
 * 返回: 0 成功，-1 失败（reason 人类可读原因）
 */
static int ob_live_completion_test(const char *base_url, const char *api_key,
				   const char *model, char *reason,
				   size_t rlen)
{
	char url[AI_MAX_URL_LEN + 32];
	char *mesc = NULL;
	char *body = NULL;
	char *err = NULL;
	int status = 0;
	int rc;
	size_t n = strlen(base_url);
	struct ob_acc acc;

	while (n > 0 && base_url[n - 1] == '/')
		n--;
	if (n == 0 || n + strlen("/chat/completions") >= sizeof(url)) {
		snprintf(reason, rlen, "invalid base_url");
		return -1;
	}
	memcpy(url, base_url, n);
	url[n] = '\0';
	strcat(url, "/chat/completions");

	mesc = ai_json_escape(model);
	if (!mesc) {
		snprintf(reason, rlen, "out of memory");
		return -1;
	}
	if (asprintf(&body,
		     "{\"model\":\"%s\",\"max_tokens\":1,"
		     "\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}",
		     mesc) < 0) {
		free(mesc);
		snprintf(reason, rlen, "out of memory");
		return -1;
	}
	free(mesc);

	memset(&acc, 0, sizeof(acc));
#ifdef CONFIG_AI_CLOUD_PROVIDER
	/* 明文 HTTP 与 TLS 同一路径，带回状态码 */
	rc = https_post_stream(url, api_key && api_key[0] ? api_key : NULL,
			       body, ob_acc_append, &acc, &status, &err);
#else
	{
		/* 云通道未编入：http 形式用 local_http 兜底（测试路径）。
		 * api_key 仅在 CONFIG_AI_CLOUD_PROVIDER 分支随请求发送。 */
		char *resp = NULL;
		int lrc;

		(void)api_key;
		lrc = local_http_post(url, "", body, 30000, &resp, &err,
				      &status);
		rc = lrc == AI_OK ? 0 : -1;
		if (resp) {
			ob_acc_append(&acc, resp, strlen(resp));
			free(resp);
		}
	}
#endif
	free(body);

	if (rc != 0) {
		const char *e = err ? err : "network error";

		if (strstr(e, "timeout") || strstr(e, "Timeout") ||
		    strstr(e, "timed out"))
			snprintf(reason, rlen, "timeout (%s)", e);
		else if (strstr(e, "resolve") || strstr(e, "DNS") ||
			 strstr(e, "Network") || strstr(e, "connect"))
			snprintf(reason, rlen,
				 "DNS/network unreachable (%s)", e);
		else
			snprintf(reason, rlen, "%s", e);
		free(err);
		return -1;
	}
	free(err);
	if (status == 401 || status == 403) {
		snprintf(reason, rlen,
			 "auth failed (HTTP %d): api key invalid or no permission",
			 status);
		return -1;
	}
	if (status == 404) {
		snprintf(reason, rlen,
			 "HTTP 404: check base_url path (e.g. trailing /v1)");
		return -1;
	}
	if (status < 200 || status >= 300) {
		snprintf(reason, rlen, "HTTP %d from endpoint", status);
		return -1;
	}
	if (!acc.len) {
		snprintf(reason, rlen, "empty response (2xx but no body)");
		return -1;
	}
	return 0;
}

/*
 * onboard_model_cloud - 云端配置（必经步骤，W77d 云端优先）
 * 预设（1-5，默认 5）→ base_url（预设可回车取默认）→ api_key（关回显）
 * → 模型名 → live 1-token 补全测试 → 通过才写 model.toml 并切换。
 * 失败给原因，回车/1 重试、2 跳过；跳过返回 OB_CLOUD_SKIP
 * （onboarding 未完成，.onboarded 不写，下次启动重新引导）。
 * 返回: 0 成功；OB_CLOUD_SKIP 用户跳过；-1 EOF/写配置失败
 */
static int onboard_model_cloud(struct ai_shell *shell)
{
	char base_url[AI_MAX_URL_LEN];
	char api_key[AI_MAX_KEY_LEN];
	char model_name[AI_MAX_MODEL_NAME];
	char reason[320];
	char line[64];
	char name[32];
	char *argv[4];
	int attempt, ok = 0;

	for (attempt = 0; attempt < 5 && !ok; attempt++) {
		int preset;

		printf("%s", tr(TR_OB_CLOUD_PRESETS));
		printf("%s", tr(TR_OB_CLOUD_PRESET_PROMPT));
		fflush(stdout);
		if (!fgets(line, sizeof(line), stdin))
			return -1;
		line[strcspn(line, "\n")] = '\0';
		preset = line[0] ? atoi(line) : OB_PRESET_COUNT;
		if (preset < 1 || preset > OB_PRESET_COUNT)
			preset = OB_PRESET_COUNT;

		{
			const char *dflt = ob_presets[preset - 1].base_url;

			if (dflt[0])
				printf(tr(TR_OB_CLOUD_ASK_URL_DFLT), dflt);
			else
				printf("%s", tr(TR_OB_CLOUD_ASK_URL));
			fflush(stdout);
			if (!fgets(base_url, sizeof(base_url), stdin))
				return -1;
			base_url[strcspn(base_url, "\n")] = '\0';
			if (!base_url[0] && dflt[0])
				snprintf(base_url, sizeof(base_url), "%s",
					 dflt);
			if (!base_url[0]) {
				printf("%s", tr(TR_OB_URL_EMPTY));
				continue;
			}
		}

		if (read_secret_line(tr(TR_OB_CLOUD_ASK_KEY), api_key,
				     sizeof(api_key)) != 0)
			return -1;

		printf("%s", tr(TR_OB_CLOUD_ASK_MODEL));
		fflush(stdout);
		if (!fgets(model_name, sizeof(model_name), stdin))
			return -1;
		model_name[strcspn(model_name, "\n")] = '\0';
		if (!model_name[0]) {
			printf("%s", tr(TR_OB_MODEL_EMPTY));
			explicit_bzero(api_key, sizeof(api_key));
			continue;
		}

		printf("%s", tr(TR_OB_CLOUD_LIVE_TEST));
		fflush(stdout);
		if (ob_live_completion_test(base_url, api_key, model_name,
					    reason, sizeof(reason)) == 0) {
			printf("%s", tr(TR_OB_CLOUD_LIVE_OK));
			ok = 1;
			break;
		}
		printf(tr(TR_OB_CLOUD_LIVE_FAIL), reason);
		explicit_bzero(api_key, sizeof(api_key));
		printf("%s", tr(TR_OB_CLOUD_RETRY_MENU));
		fflush(stdout);
		if (!fgets(line, sizeof(line), stdin))
			return -1;
		line[strcspn(line, "\n")] = '\0';
		if (line[0] == '2')
			return OB_CLOUD_SKIP;
		/* 回车/1 → 重试 */
	}
	if (!ok)
		return -1;

	/* live 测试通过才写配置（绝不静默假装配好） */
	snprintf(name, sizeof(name), "cloud");
	ai_config_remove_model(shell->config, name);
	{
		int ret = ai_config_add_model(shell->config, name,
					      "openai_compatible",
					      model_name, base_url,
					      api_key[0] ? api_key : "");

		explicit_bzero(api_key, sizeof(api_key));
		if (ret != AI_OK) {
			printf("%s", tr(TR_OB_WRITE_FAIL));
			return -1;
		}
	}
	ai_config_set_default_model(shell->config, name);
	ai_config_save(shell->config);

	argv[0] = (char *)"model";
	argv[1] = (char *)"use";
	argv[2] = name;
	if (cmd_model(shell, 3, argv) != AI_OK) {
		printf("%s", tr(TR_OB_SWITCH_FAIL));
		return -1;
	}
	return 0;
}

/*
 * onboard_model_local - 本地模型（可选步骤，W77d 重写）
 * 不再"探测 ollama 就用 qwen"：展示 top-3 推荐（硬件门控），确认后
 * aik_ml_install（多 GB 下载 + 装后验证，失败如实报告并清理），
 * 可选切换 local；跳过也正常完成 onboarding。
 * 返回: 0（可选步骤不阻断引导）
 */
static int onboard_model_local(struct ai_shell *shell)
{
	struct aik_ml_entry cat[AIK_ML_CATALOG_MAX];
	struct aik_ml_hw hw;
	struct aik_ml_scored top[AIK_ML_TOP_N];
	char *err = NULL;
	char line[128];
	int n, cnt, i;

	printf("%s", tr(TR_OB_LOCAL_OPTIONAL));
	fflush(stdout);
	if (!fgets(line, sizeof(line), stdin))
		return 0;
	line[strcspn(line, "\n")] = '\0';
	if (line[0] != '1')
		return 0;   /* 默认跳过：本地是可选步骤 */

	for (;;) {
		const struct aik_ml_entry *e;
		int pick;

		n = aik_ml_catalog_load(NULL, cat, AIK_ML_CATALOG_MAX, &err);
		if (n <= 0) {
			printf(tr(TR_OB_LOCAL_INSTALL_FAIL),
			       err ? err : "catalog unavailable");
			free(err);
			return 0;
		}
		aik_ml_hw_probe(&hw);
		cnt = aik_ml_recommend(cat, n, &hw, top, AIK_ML_TOP_N);
		if (cnt == 0) {
			printf("%s", tr(TR_OB_LOCAL_NO_FIT));
			return 0;
		}
		printf("%s", tr(TR_OB_LOCAL_TOP3));
		for (i = 0; i < cnt; i++)
			printf("  %d. %-18s %s\n      %s\n", i + 1,
			       top[i].e->name, top[i].e->ollama_ref,
			       top[i].e->why);
		printf("%s", tr(TR_OB_LOCAL_PICK));
		fflush(stdout);
		if (!fgets(line, sizeof(line), stdin))
			return 0;
		line[strcspn(line, "\n")] = '\0';
		pick = line[0] ? atoi(line) : 1;
		if (pick < 1 || pick > cnt)
			pick = 1;
		e = top[pick - 1].e;

		printf(tr(TR_OB_LOCAL_INSTALL_CONFIRM), e->name, e->disk_gb);
		fflush(stdout);
		if (!fgets(line, sizeof(line), stdin))
			return 0;
		if (!(line[0] == 'y' || line[0] == 'Y')) {
			printf("install cancelled; onboarding continues.\n");
			return 0;
		}

		if (aik_ml_install(shell->config, e->name, 1, &err) == 0) {
			printf(tr(TR_OB_LOCAL_INSTALLED_OK), e->ollama_ref);
			printf("%s", tr(TR_OB_LOCAL_SWITCH_ASK));
			fflush(stdout);
			if (fgets(line, sizeof(line), stdin) &&
			    (line[0] == 'y' || line[0] == 'Y')) {
				char *av[3];

				av[0] = (char *)"model";
				av[1] = (char *)"use";
				av[2] = (char *)"local";
				if (cmd_model(shell, 3, av) == AI_OK)
					printf("switched to local model.\n");
			}
			return 0;
		}
		/* 失败如实报告；可重试或跳过本地步骤（引导仍完成） */
		printf(tr(TR_OB_LOCAL_INSTALL_FAIL), err ? err : "unknown");
		free(err);
		err = NULL;
		printf("%s", tr(TR_OB_LOCAL_RETRY_MENU));
		fflush(stdout);
		if (!fgets(line, sizeof(line), stdin) || line[0] != '1')
			return 0;
	}
}

/* touch /etc/aikernel/.onboarded（失败返回 -1，onboarding 不算完成） */
static int mark_onboarded(void)
{
	const char *path = ob_marked_path();
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0) {
		printf(tr(TR_OB_MARK_FAIL), path,
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
	if (access(ob_marked_path(), F_OK) == 0)
		return 0;
	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
		return 0;
	return 1;
}

/*
 * onboarding_run - 引导主循环（W77d 云端优先）
 * 语言 → setup-password → 云端配置（必经，live 测试）→ 本地模型
 * （可选）→ 完成。云端跳过 = 引导未完成（返回 -1，不写 .onboarded），
 * 下次启动重新引导；本地步骤失败/跳过不影响完成。
 * 返回: 0 完成初始化，-1 用户中止或未完成（正常 REPL 仍进入）
 */
int onboarding_run(void *shell_ptr)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;
	struct ai_chat_msg hist[12];
	int nhist = 0;
	char line[AI_MAX_LINE_LEN];
	int step = 0;   /* 0=语言 1=密码 2=云端(必经) 3=本地(可选) 4=完成 */
	const char *p;

	memset(hist, 0, sizeof(hist));

	printf("%s", tr(TR_OB_HEAD));

	/* 步骤 0：界面语言（zh 缺省；选 en 后续文案即切换） */
	printf("%s", tr(TR_OB_LANG_ASK));
	fflush(stdout);
	if (fgets(line, sizeof(line), stdin)) {
		line[strcspn(line, "\n")] = '\0';
		if (strcmp(line, "2") == 0 || strcmp(line, "en") == 0 ||
		    strcmp(line, "English") == 0) {
			lang_set(AI_LANG_EN);
			if (shell->config) {
				free(shell->config->ui.lang);
				shell->config->ui.lang = strdup(AI_LANG_EN);
				ai_config_save(shell->config);
			}
		} else {
			lang_set(AI_LANG_ZH);
			if (shell->config) {
				free(shell->config->ui.lang);
				shell->config->ui.lang = strdup(AI_LANG_ZH);
				ai_config_save(shell->config);
			}
		}
	}

	printf("%s", tr(TR_OB_HINT1));
	printf("%s", tr(TR_OB_HINT2));

	/* 欢迎自我介绍（失败降级内置文案） */
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

		/* 步骤 1 期间收到 2/cloud：提示先完成密码（强制顺序） */
		if (strcmp(p, "2") == 0 || strcmp(p, "cloud") == 0 ||
		    strcmp(p, "1") == 0 || strcmp(p, "local") == 0) {
			printf("%s", tr(TR_OB_PW_FIRST));
			continue;
		}

		/* 其它输入 → AI 对话（引导回主线） */
		onboarding_ai_say(shell, hist, &nhist, p,
			tr(TR_OB_STEP1_CHAT_FALLBACK));
	}

	/* 步骤 2：云端配置（必经；跳过=引导未完成，不写 .onboarded） */
	while (step == 2) {
		int rc;

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

		if (strcmp(p, "2") == 0 || strcmp(p, "cloud") == 0) {
			rc = onboard_model_cloud(shell);
			if (rc == 0) {
				step = 3;
			} else if (rc == OB_CLOUD_SKIP) {
				printf(tr(TR_OB_CLOUD_SKIPPED),
				       ob_marked_path());
				return -1;   /* 未完成：不写 .onboarded */
			}
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

	/* 步骤 3：本地模型（可选；任何结果都进入完成） */
	while (step == 3) {
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

		if (strcmp(p, "shell") == 0) {
			cmd_shell(shell, 0, NULL);
			continue;
		}
		if (strcmp(p, "help") == 0 || strcmp(p, "?") == 0) {
			printf("%s", tr(TR_OB_STEP2_HELP));
			continue;
		}
		/* 任意输入（含空回车）进入本地模型可选步骤 */
		(void)onboard_model_local(shell);
		step = 4;
	}

	/* 步骤 4：完成落标记 */
	if (mark_onboarded() != 0)
		return -1;

	onboarding_ai_say(shell, hist, &nhist,
		tr(TR_OB_DONE_ASK),
		tr(TR_OB_DONE_FALLBACK));

	printf("%s", tr(TR_OB_DONE));
	return 0;
}
