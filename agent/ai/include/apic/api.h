/* SPDX-License-Identifier: GPL-2.0 */
/*
 * api.h - T7b aikernel-api(参考 agent/ai/api/aikernel-api,1,148 行 Python)
 * 全量 C 化共享声明。
 *
 * 差分口径:冻结 epoch 1775000000 / TZ Asia/Shanghai(录制 shim 等价旗标
 * --frozen-now/--frozen-random);secrets.token_hex(16) 定序 "%032x" 计数器
 * (从 1 起,调用序:_do_ask session(未带)先、tag 后;_do_clarify tag)。
 *
 * 模块:
 *   apihttp.c - HTTP/1.1 壳(线程/keep-alive/恒 Content-Length/501/414/
 *               bad-syntax 模板/超长体不排空 desync 语义/异常=关连接)
 *   aikapi.c  - main(旗标/配置/监听/LISTENING 行)+ 路由分发 + 鉴权 + 审计
 *   apiask.c  - /ask /clarify(ai 子进程/事件通道/pending 探针/选择归一)
 *   apiv2.c   - /tools /params /sense /act
 *   apinl.c   - NETLINK_AI v2 ai_nl_act 构包/收包(对齐 "=QIIHBBBH" 族)
 *
 * 复用 T6 基建(源码只读引用编译,不拷贝不改动):
 *   ../desktop/dtcore.c(冻结时钟/sbuf/UTF-8 码点/strip/文件)
 *   ../desktop/dtjson.c(python 默认分隔符 JSON dump + DOM 构造)
 *   ../store/libaikstore.a(aik_json DOM/解析/紧凑 dump)
 */
#ifndef _AIK_APIC_API_H
#define _AIK_APIC_API_H

#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

/* fortify 下 write 返回值必须消费;审计/execpipe 等丢弃场景统一走此 */
static inline ssize_t api_write_discard(int fd, const void *buf, size_t n)
{
	ssize_t r = write(fd, buf, n);

	return r;
}

#include "store/store_json.h"

#define API_PATH_MAX 4096
#define API_CFG_PATH 8192

/* ---------------- 常量(与参考逐一同名同值) ---------------- */
#define API_BIND_HOST "127.0.0.1"
#define API_BIND_PORT 8761
#define API_TOKEN_FILE "/etc/aikernel/api-token"
#define API_CONTROL_PROC "/proc/ai/control"
#define API_AUDIT_LOG "/var/log/ai-audit.log"
#define API_VERSION 3
#define API_EVENT_PREFIX "AIKERNEL_EVENT"
#define API_SESSION_PREFIX "api-"
#define API_SESSION_MAX 96
#define API_NONCE_MAX 60
#define API_CLARIFY_MAX_OPTIONS 4
#define API_CLARIFY_MAX_TEXT 512
#define API_SESSION_LOCK_MAX 256
#define API_SENSE_DEFAULT_LIMIT 8192
#define API_SENSE_MAX_LIMIT 65536
#define API_TOOLS_DESC_MAX 160
#define API_ASK_TIMEOUT_DEFAULT 300
#define API_MAX_BODY (1 << 20)
#define API_SERVER_HDR "AIKernelAPI/3.0"
#define API_TOOLS_JSON_DEFAULT "/usr/local/share/aikernel/tools.json"
#define API_AI_BIN_DEFAULT "/usr/local/bin/ai"

/* NETLINK_AI(协议族 31 / AI_CMD_ACT=17) */
#define NETLINK_AI 31
#define AI_CMD_ACT 17
#define NLM_F_REQUEST_AI 0x01
#define NLMSG_ERROR_AI 0x2
#define AI_NL_ACT_PARAM_LEN 24
#define AI_NL_ACT_SIZE 112	/* "<QIBBHI4x8Q24s" */
#define AI_NL_ACT_ACK_SIZE 16	/* "<IIiI" */

/* ---------------- 全局配置(aikapi.c) ---------------- */
struct api_cfg {
	char toml_file[API_CFG_PATH];
	char ai_bin[API_CFG_PATH];
	char tools_json[API_CFG_PATH];
	long long ask_timeout;	/* 秒 */
	int frozen;		/* --frozen-now/--frozen-random */
	long long frozen_epoch;
};

extern struct api_cfg g_api;

/* 冻结时钟:time.time() 语义(冻结时为整数 epoch) */
long long api_time(void);
/* secrets.token_hex(16):冻结定序 "%032x"%计数器;否则 /dev/urandom */
void api_token_hex16(char out[33]);

/* ---------------- HTTP 壳(apihttp.c) ---------------- */
struct api_http_req {
	const char *method;
	const char *target;	/* 原始 request-target(含 query,未解码) */
	const char *path;	/* '?' 前部分(未解码) */
	const char *query;	/* '?' 后部分(未解码;无则 "") */
	const char *authorization; /* 首个 Authorization 头原值;无则 NULL */
	const char *content_length; /* 首个 Content-Length 头原值;无则 NULL */
	/* 连接读取器(端点按需读体;不读则残留在流里 = py 语义) */
	void *conn;
};

struct api_http_resp {
	int status;
	char *body;		/* malloc */
	size_t body_len;
	int unread_body;	/* 响应未消费请求体(超长 400 分支) */
};

/* 端点读体:返回 malloc 缓冲(NUL 结尾便于解析,len 为真实长度);
 * *rc:0=读到 CL 字节;-1=CL 非法(int() ValueError);-2=CL>1MiB;
 * -3=读体中断(对端断)。n==0 → "{}"。 */
char *api_http_read_body(struct api_http_req *req, size_t *out_len,
			 int *rc);

int api_http_serve(const char *host, int port);
/* 分体:listen(成功后再打 listening/LISTENING 行)→ accept 循环 */
int api_http_listen(const char *host, int port);
int api_http_accept_loop(void);

/* aikapi.c 提供:全路由分发;返回 0 正常,负值语义见实现 */
int api_dispatch(struct api_http_req *req, struct api_http_resp *resp);
/* 鉴权:0=通过;1=已写 401/403 响应 */
int api_auth_check(struct api_http_req *req, struct api_http_resp *resp);

/* ---------------- 响应构造便捷(aikapi.c) ---------------- */
void api_resp_json(struct api_http_resp *r, int status,
		   const aik_json *body);
/* err_body(err, message, extra...) → _err */
struct aik_json *api_err_body(const char *err, const char *message);

/* ---------------- 审计(aikapi.c) ---------------- */
void api_audit_line(const char *tool, const aik_json *args,
		    const char *result);

/* ---------------- TOML [api](aikapi.c) ---------------- */
/* 解析 [api] 段;aik_json OBJ(字符串/布尔/整数,键序=出现序) */
aik_json *api_parse_toml_section(const char *text);
aik_json *api_load_config(void);
/* token 优先级:model.toml [api] token > /etc/aikernel/api-token */
char *api_effective_token(void);

/* ---------------- 小工具(各模块) ---------------- */
int api_valid_session(const char *s);   /* ^api-[A-Za-z0-9._-]{1,96}$ */
int api_valid_nonce(const char *s);     /* ^cq-[A-Za-z0-9._-]{1,60}$ */
int api_py_int(const char *s, long long *out);       /* int(x) */
int api_py_int0(const char *s, long long *out);      /* int(x, 0) */
int api_utf8_decode_replace(const char *in, size_t n,
			    char **out, size_t *out_len);
/* python "utf-8 codec can't decode ..." 消息(供 500 分支) */
int api_utf8_errmsg(const char *in, size_t n, char *buf, size_t cap);
/* /proc/ai/control 行解析(返回 0=匹配) */
int api_parse_control_line(const char *line, char *name, size_t name_cap,
			   long long *domain, long long *lo,
			   long long *hi, long long *cur,
			   long long *def);
int api_is_task_param(const char *name);
/* 读文件(全文) */
char *api_read_file(const char *path, size_t *out_len, int *os_errno);
/* "[Errno %d] %s: '%s'"(python OSError str) */
void api_oserr_str(char *buf, size_t cap, int e, const char *path);

/* ---------------- apiask.c ---------------- */
int api_do_ask(struct api_http_req *req, struct api_http_resp *resp);
int api_do_clarify(struct api_http_req *req, struct api_http_resp *resp);

/* pending 探针状态 */
#define API_PENDING_INVALID 0
#define API_PENDING_UNKNOWN 1
#define API_PENDING_CONSUMED 2
#define API_PENDING_EXPIRED 3
#define API_PENDING_OK 4

int api_read_pending(const char *nonce, aik_json **doc_out);
/* state → (http code, err, msg);pending → code 0 */
int api_pending_state_error(int state, const char **err,
			    const char **msg);
/* 事件校验:返回 NULL 或错误文案 */
const char *api_validate_clarify_event(const aik_json *ev);
/* 渲染人类可读 answer(malloc) */
char *api_render_clarify_answer(const aik_json *ev, const char *session);
/* normalize_selection:0=ok;非 0 → *errc 指向错误文案 */
int api_normalize_selection(const aik_json *doc,
			    const aik_json *selection,
			    const aik_json *other,
			    aik_json **tokens_out, char **other_out,
			    const char **errc);
/* 解析 stderr 事件行:*ev_out=NULL 且 *err_out=NULL → 无事件;
 * *err_out 非 NULL → 协议错误文案;返回 0 正常 */
int api_parse_tagged_event(const char *stderr_text, size_t len,
			   const char *tag, aik_json **ev_out,
			   const char **err_out);
/* ai 子进程运行(返回 0=跑完,*rc_out 退出码;1=超时;2=ENOENT;-1=io 错) */
int api_run_ai(char *const argv[], const char *extra_env_kv[],
	       long long timeout_s, char **stdout_out, size_t *stdout_len,
	       char **stderr_out, size_t *stderr_len, int *rc_out);

/* ---------------- apiv2.c ---------------- */
int api_do_health(struct api_http_req *req, struct api_http_resp *resp);
int api_do_tools(struct api_http_req *req, struct api_http_resp *resp,
		 const char *channel, const char *risk);
int api_do_params(struct api_http_req *req, struct api_http_resp *resp,
		  const char *name);
int api_do_sense(struct api_http_req *req, struct api_http_resp *resp,
		 const char *what, const char *limit);
int api_do_act(struct api_http_req *req, struct api_http_resp *resp);

/* query(k 首值,空值丢弃;parse_qs 语义) */
char *api_query_get(const char *query, const char *key);

/* ---------------- apinl.c ---------------- */
/* 打包 v2 ai_nl_act(112B,LE) */
int api_nl_pack_act(unsigned char out[AI_NL_ACT_SIZE],
		    long long domain, int confidence, const char *param,
		    long long data0, long long data1);
/* 解包 ai_nl_act_ack;payload<16B → NULL */
aik_json *api_nl_unpack_act_ack(const unsigned char *payload, size_t n);
/* 发 AI_CMD_ACT:ack(JSON,可 NULL)/err(malloc 文案,可 NULL) */
int api_nl_act(const char *param, long long value, long long pid,
	       aik_json **ack_out, char **err_out);

#endif /* _AIK_APIC_API_H */
