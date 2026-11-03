/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/tlsgw/tlsgw.h - T7c aik-tls-gateway C 移植共享声明
 *
 * 参考 = agent/ai/cloud/tls_gateway/aik_tls_gateway.py(257 行,md5 0af1029d..,
 * 工厂真身 = 仓库版,L1 亲验)。行为规格表见 work/refactor/T7C-PROGRESS.md §A。
 *
 * 分层:
 *   tlsgwcore.c  - 纯逻辑 + 后端明文 TCP 客户端(无 TLS;单测直接覆盖)
 *   tlsgwserv.c  - 服务端单请求/连接处理(流抽象;单测可用内存/裸 fd 流)
 *   tlsgw.c      - mbedTLS 服务端 + 监听/线程/信号/main
 */
#ifndef AIK_TLSGW_H
#define AIK_TLSGW_H

#include <stdio.h>
#include <stddef.h>

#define GW_VERSION "aik-tls-gateway 1.0 (W78)"
#define GW_SERVER_HDR "aik-tls-gw/1.0 aik-tls-gateway-c/1.0" /* Server 值:白名单项 */
#define GW_MAXLINE (64 * 1024)	    /* py _MAXLINE=65536;readline(_MAXLINE+1) */
#define GW_MAXHEADERS 100	    /* py _MAXHEADERS */
#define GW_MAX_BODY (64LL * 1024 * 1024)  /* MAX_BODY */
#define GW_BACKEND_TIMEOUT_SEC 60

struct dt_sbuf;

/* ---------------- 配置(env 同名同义) ---------------- */
struct gw_cfg {
	char listen[256];
	char backend[256];
	char tls_dir[4096];
	char server_crt[4352];
	char server_key[4352];
	char ca_crt[4352];
};

typedef const char *(*gw_getenv_fn)(void *ctx, const char *name);
void gw_cfg_from_env(struct gw_cfg *c, gw_getenv_fn fn, void *ctx);
/* LISTEN 解析: 0=ok; -1=rsplit/int 失败(host:port 格式错) */
int gw_parse_listen(const char *listen, char *host, size_t cap, int *port);

/* die: stderr "aik-tls-gateway: <msg>\n" + 退出(退出码 1 由调用方) */
void gw_die_msg(FILE *out, const char *msg);
int gw_first_missing_cert(const struct gw_cfg *c, char *out, size_t cap);
void gw_missing_cert_msg(const char *path, char *out, size_t cap);
void gw_listen_bad_msg(const char *val, char *out, size_t cap);
void gw_listen_fail_msg(const char *listen, int err, char *out, size_t cap);

/* ---------------- py 语义小工具 ---------------- */
void gw_py_repr_str(struct dt_sbuf *sb, const char *s);
void gw_py_repr_bytes(struct dt_sbuf *sb, const unsigned char *b, size_t n);
void gw_int10_errmsg(struct dt_sbuf *sb, const char *literal);
void gw_int16_errmsg(struct dt_sbuf *sb, const unsigned char *lit, size_t n);
/* chunk 尺寸行解析(py int(line.split(b";")[0].strip() or b"0", 16)):
 * 0=ok(*size;空 token → 0);-1=坏 hex(errmsg = py ValueError str) */
int gw_chunk_parse_line(const char *line, long long *size, char *errmsg,
			size_t cap);
const char *gw_oserr_detail(int err);	/* "[Errno N] <strerror>" / "timed out" */
const char *gw_remote_disconnected(void);
const char *gw_reason_phrase(int code);
void gw_http_date(char *buf, size_t cap);

/* ---------------- 请求行(py3.10.12 parse_request) ---------------- */
#define GW_PARSE_OK 0
#define GW_PARSE_BLANK (-5)		/* 空行:静默关连接 */
#define GW_PARSE_BAD_SYNTAX (-1)	/* 400 Bad request syntax (%r) */
#define GW_PARSE_BAD_VERSION (-2)	/* 400 Bad request version (%r) */
#define GW_PARSE_HTTP2 (-3)		/* 505 Invalid HTTP version (%s) */
#define GW_PARSE_NOT_GET09 (-4)		/* 400 Bad HTTP/0.9 request type (%r) */

struct gw_reqline {
	char method[64];
	char target[GW_MAXLINE + 1];	/* 折叠后 self.path(gh-87389 //折叠) */
	char last_word[512];		/* 错误消息用(版本词/方法) */
	char rawline[GW_MAXLINE + 1];	/* rstrip('\r\n') 后原文(日志/消息用) */
	int close_conn;			/* 初始 close_connection */
	int version_11;
	int version_09;			/* 两词(HTTP/0.9 形态) */
};

int gw_parse_request_line(char *line, struct gw_reqline *h);

/* ---------------- 头列表(有序;同形同名后者覆盖前者值,保位) ---------------- */
struct gw_hlist {
	char **names;
	char **vals;
	size_t n;
	size_t cap;
};

void gw_hlist_init(struct gw_hlist *h);
void gw_hlist_free(struct gw_hlist *h);
int gw_hlist_set(struct gw_hlist *h, const char *name, const char *val);
const char *gw_hlist_get_ci(const struct gw_hlist *h, const char *name);
int gw_hlist_has_ci(const struct gw_hlist *h, const char *name);
int gw_is_hop_by_hop(const char *name);
/* 转发头构造:剥逐跳+Host(大小写不敏感),注入 Host/XFF/XFP/XCCN */
int gw_build_forward(const struct gw_hlist *client, struct gw_hlist *out,
		     const char *backend_str, const char *peer_ip,
		     const char *cn);
/* 后端请求字节(py3.10.12 putrequest/_send_request 次序,亲读源码冻结) */
char *gw_build_backend_request(const char *method, const char *target,
			       const struct gw_hlist *fwd,
			       const unsigned char *body, size_t blen,
			       size_t *out_len);

/* ---------------- JSON(json.dumps 默认参数:分隔符 ", "/": "、ensure_ascii) ---------------- */
char *gw_json_kv2(const char *k1, const char *v1, const char *k2,
		  const char *v2, size_t *out_len);
int gw_healthz_target(const char *target);	/* self.path == "/healthz" */

/* ---------------- 流抽象(TLS=tlsgw.c;单测=内存/裸fd) ---------------- */
struct gw_stream {
	void *ctx;
	/* >=0 读到字节数;0=EOF;-1=超时;-2=错误 */
	int (*read)(void *ctx, unsigned char *buf, size_t n);
	/* 0=全部写出;-1=错误 */
	int (*write)(void *ctx, const unsigned char *buf, size_t n);
};

struct gw_reader {
	struct gw_stream s;
	unsigned char *buf;	/* 外部提供 */
	size_t cap;
	size_t len;
	size_t pos;
	int eof;
};

void gw_reader_init(struct gw_reader *r, struct gw_stream *s,
		    unsigned char *buf, size_t cap);
int gw_reader_fill(struct gw_reader *r);
/* py readline(size) 语义:至多 cap 字节(含结尾 \n 当落在 cap 内);
 * malloc 行返回;EOF 且零字节 → NULL(*eof=1);EOF 短行 → 返回已有 */
char *gw_reader_readline(struct gw_reader *r, size_t cap, size_t *out_len,
			 int *eof);
/* 返回拷贝到的字节数(EOF 短读 < n) */
int gw_reader_read_exact(struct gw_reader *r, unsigned char *out, size_t n);

/* ---------------- 服务端单请求/连接处理 ---------------- */
struct gw_serve {
	/* 输入 */
	struct gw_stream *io;	/* 客户端双向流 */
	const struct gw_cfg *cfg;
	char backend_host[320];
	int backend_port;
	const char *peer_ip;	/* X-Forwarded-For + 日志 */
	const char *cn;		/* X-Client-Cert-CN + 日志(可空串) */
	FILE *log;		/* stderr(可 NULL 关日志) */
	/* 连接级 */
	struct gw_reader rd;
	unsigned char rdbuf[GW_MAXLINE + 8192];
};

/* 返回 1=继续(keep-alive);0=对端关闭;-1=本侧关(错误已回/静默) */
int gw_serve_conn(struct gw_serve *sv);

/* ---------------- 后端明文 TCP 客户端 ---------------- */
struct gw_be {
	int fd;
	struct gw_stream st;
	struct gw_reader rd;
	unsigned char rdbuf[65536];
	int status;
	char reason[256];
	struct gw_hlist hdrs;
	long long content_length;	/* -1 = 无 CL 头 */
	int chunked;			/* 后端响应体 chunked */
	long long chunk_rem;		/* 当前 chunk 剩余 */
	long long consumed;		/* CL 模式已读 */
	int body_done;
	int saw_last_chunk;
	int be_timeout;			/* 读超时(60s) */
	int be_err;			/* 读 errno */
};

/* 0=ok;-1=失败(*errmsg 填 py OSError detail);-2=BADSTATUS(未捕获 → 关连接) */
int gw_be_connect(struct gw_be *be, const char *host, int port, int timeout,
		  char *errmsg, size_t errcap);
int gw_be_send_request(struct gw_be *be, const char *bytes, size_t len,
		       char *errmsg, size_t errcap);
/* 响应头解析;0=ok;-1=502 detail;-2=BADSTATUS(未捕获) */
int gw_be_read_head(struct gw_be *be, char *errmsg, size_t errcap);
/* 读体:>=1 字节数;0=体完;-1=错误(relay 阶段未捕获 → 关连接) */
int gw_be_read_body(struct gw_be *be, unsigned char *out, size_t want);
void gw_be_close(struct gw_be *be);

#endif /* AIK_TLSGW_H */
