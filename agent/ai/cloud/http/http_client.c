/*
 * http_client.c - AIKernel HTTPS Client 实现
 *
 * 基于 mbedTLS 的自有 HTTPS 客户端。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#include "http_client.h"

/* ---- mbedTLS 全局上下文 ---- */

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static int g_initialized = 0;

/* ---- Timeout 配置 ---- */

static int g_connect_timeout = 30;
static int g_read_timeout = 30;

void https_init(void)
{
	if (g_initialized) return;
	mbedtls_entropy_init(&g_entropy);
	mbedtls_ctr_drbg_init(&g_ctr_drbg);
	mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func,
		&g_entropy, (const unsigned char *)"AIKernel-HTTPS-Client", 21);
	g_initialized = 1;
}

void https_cleanup(void)
{
	if (!g_initialized) return;
	mbedtls_ctr_drbg_free(&g_ctr_drbg);
	mbedtls_entropy_free(&g_entropy);
	g_initialized = 0;
}

/* ---- URL 解析 ---- */

struct url_info { char host[256]; char path[512]; int port; int use_tls; };

static int parse_url(const char *url, struct url_info *info)
{
	const char *p;
	memset(info, 0, sizeof(*info));

	if (strncmp(url, "https://", 8) == 0) { info->use_tls = 1; info->port = 443; p = url + 8; }
	else if (strncmp(url, "http://", 7) == 0) { info->use_tls = 0; info->port = 80; p = url + 7; }
	else return -1;

	{
		const char *slash = strchr(p, '/');
		const char *colon = strchr(p, ':');
		int len;
		if (colon && (!slash || colon < slash)) {
			len = colon - p;
			if (len >= (int)sizeof(info->host)) len = sizeof(info->host) - 1;
			memcpy(info->host, p, len); info->host[len] = '\0';
			info->port = atoi(colon + 1);
			p = slash ? slash : p + strlen(p);
		} else if (slash) {
			len = slash - p;
			if (len >= (int)sizeof(info->host)) len = sizeof(info->host) - 1;
			memcpy(info->host, p, len); info->host[len] = '\0';
			p = slash;
		} else {
			len = strlen(p);
			if (len >= (int)sizeof(info->host)) len = sizeof(info->host) - 1;
			memcpy(info->host, p, len); info->host[len] = '\0';
			p += len;
		}
	}

	if (*p == '/') strncpy(info->path, p, sizeof(info->path) - 1);
	else { info->path[0] = '/'; info->path[1] = '\0'; }
	return 0;
}

/* ---- TCP 连接 ---- */

static int tcp_connect(const char *host, int port)
{
	int sock;
	struct addrinfo hints, *res, *rp;
	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;
	for (rp = res; rp; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock < 0) continue;
		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
		close(sock);
	}
	freeaddrinfo(res);
	if (!rp) return -1;
	{ struct timeval tv;
	  tv.tv_sec = g_read_timeout; tv.tv_usec = 0;
	  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	  tv.tv_sec = g_connect_timeout; tv.tv_usec = 0;
	  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)); }
	return sock;
}

/* ---- HTTP 请求构建 ---- */

static char *build_http_request(const char *host, const char *path,
	const char *api_key, const char *json_body, size_t *req_len)
{
	size_t cap = strlen(json_body) + strlen(api_key) + strlen(host)
		+ strlen(path) + 1024;
	char *req = malloc(cap);
	if (!req) return NULL;
	int n = snprintf(req, cap,
		"POST %s HTTP/1.1\r\nHost: %s\r\n"
		"Content-Type: application/json\r\n"
		"Authorization: Bearer %s\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n\r\n%s",
		path, host, api_key, strlen(json_body), json_body);
	if (n < 0 || (size_t)n >= cap) { free(req); return NULL; }
	*req_len = n;
	return req;
}

/* ---- Chunked Transfer Encoding 解码 ---- */

/*
 * strip_chunked - 解码 HTTP chunked transfer encoding
 * 格式: <hex-size>\r\n<data>\r\n... 0\r\n\r\n
 * 原地修改，返回干净数据的起始指针。
 */
static char *strip_chunked(char *body)
{
	char *src = body, *dst = body;

	while (*src) {
		unsigned int chunk_size = 0;

		/* 解析 hex 大小 */
		while (*src && *src != '\r' && *src != '\n') {
			char c = *src;
			chunk_size <<= 4;
			if (c >= '0' && c <= '9')      chunk_size += c - '0';
			else if (c >= 'a' && c <= 'f') chunk_size += c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') chunk_size += c - 'A' + 10;
			else break;
			src++;
		}
		while (*src == '\r' || *src == '\n') src++;

		if (chunk_size == 0) break;

		/* 复制 chunk 数据到 dst */
		memmove(dst, src, chunk_size);
		dst += chunk_size;
		src += chunk_size;
		while (*src == '\r' || *src == '\n') src++;
	}
	*dst = '\0';
	return body;
}

/* ---- HTTPS POST 主函数 ---- */

int https_post(const char *url, const char *api_key, const char *json_body,
	char **response, char **error_msg)
{
	struct url_info uinfo;
	int sock = -1, ret = -1;
	char *err_buf = NULL;
	*response = NULL;
	if (error_msg) *error_msg = NULL;
	if (!g_initialized) {
		if (error_msg) *error_msg = strdup("HTTPS not initialized");
		return -1;
	}
	if (parse_url(url, &uinfo) != 0) {
		if (error_msg) *error_msg = strdup("Invalid URL format");
		return -1;
	}
	sock = tcp_connect(uinfo.host, uinfo.port);
	if (sock < 0) {
		if (error_msg) *error_msg = strdup("Network unavailable: cannot connect");
		return -1;
	}

	if (uinfo.use_tls) {
		mbedtls_ssl_context ssl;
		mbedtls_ssl_config conf;
		mbedtls_ssl_init(&ssl);
		mbedtls_ssl_config_init(&conf);
		mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
		mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
		mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);
		mbedtls_ssl_setup(&ssl, &conf);
		mbedtls_ssl_set_hostname(&ssl, uinfo.host);
		mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send,
			mbedtls_net_recv, NULL);

		/* TLS 握手 */
		{ int tls_ret;
		  while ((tls_ret = mbedtls_ssl_handshake(&ssl)) != 0) {
			if (tls_ret != MBEDTLS_ERR_SSL_WANT_READ &&
			    tls_ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				char err[256];
				mbedtls_strerror(tls_ret, err, sizeof(err));
				err_buf = malloc(512);
				snprintf(err_buf, 512, "TLS handshake failed: %s", err);
				if (error_msg) *error_msg = err_buf; else free(err_buf);
				goto tls_cleanup;
			}
		  }
		}

		/* 构建并发送请求 */
		{ size_t req_len;
		  char *req = build_http_request(uinfo.host, uinfo.path,
			api_key, json_body, &req_len);
		  if (!req) {
			if (error_msg) *error_msg = strdup("Failed to build HTTP request");
			goto tls_cleanup;
		  }
		  { int w;
		    while ((w = mbedtls_ssl_write(&ssl, (unsigned char *)req, req_len)) <= 0) {
			if (w != MBEDTLS_ERR_SSL_WANT_WRITE && w != MBEDTLS_ERR_SSL_WANT_READ) {
				free(req);
				if (error_msg) *error_msg = strdup("TLS write failed");
				goto tls_cleanup;
			}
		    }
		  }
		  free(req);
		}

		/* 读取响应 —— 使用 64KB 初始缓冲避免频繁 realloc */
		{ char *resp = calloc(1, 65536);
		  size_t resp_size = 0, resp_cap = 65536;
		  if (!resp) goto tls_cleanup;
		  while (1) {
			char buf[8192];
			int r = mbedtls_ssl_read(&ssl, (unsigned char *)buf, sizeof(buf)-1);
			if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
			if (r <= 0) break;
			if (resp_size + r + 1 > resp_cap) {
				resp_cap = resp_size + r + 8192;
				char *t = realloc(resp, resp_cap);
				if (!t) { free(resp); resp = NULL; break; }
				resp = t;
			}
			memcpy(resp + resp_size, buf, r);
			resp_size += r;
			resp[resp_size] = '\0';
		  }
		  if (resp) {
			char *body = strstr(resp, "\r\n\r\n");
			if (body) {
				body += 4;
				body = strip_chunked(body);
				*response = strdup(body);
			} else { *response = resp; resp = NULL; }
			free(resp);
			ret = 0;
		  }
		}
	tls_cleanup:
		mbedtls_ssl_free(&ssl);
		mbedtls_ssl_config_free(&conf);
	} else {
		/* HTTP 非加密 */
		size_t req_len;
		char *req = build_http_request(uinfo.host, uinfo.path,
			api_key, json_body, &req_len);
		if (req) {
			write(sock, req, req_len);
			char *resp = malloc(65536);
			if (resp) {
				ssize_t n = read(sock, resp, 65535);
				if (n > 0) {
					resp[n] = '\0';
					char *body = strstr(resp, "\r\n\r\n");
					if (body) {
						body += 4;
						body = strip_chunked(body);
						*response = strdup(body);
					} else { *response = resp; resp = NULL; }
					ret = 0;
				}
				free(resp);
			}
			free(req);
		}
	}

	if (sock >= 0) close(sock);
	return ret;
}

/* ---- Timeout 设置 ---- */

void https_set_timeout(int connect_timeout, int read_timeout)
{
if (connect_timeout > 0)
	g_connect_timeout = connect_timeout;
if (read_timeout > 0)
	g_read_timeout = read_timeout;
}

/* ---- HTTPS GET ---- */

static char *build_get_request(const char *host, const char *path, size_t *req_len)
{
size_t cap = strlen(host) + strlen(path) + 256;
char *req = malloc(cap);
if (!req) return NULL;
int n = snprintf(req, cap,
	"GET %s HTTP/1.1\r\nHost: %s\r\n"
	"User-Agent: AIKernel/1.0\r\n"
	"Accept: */*\r\n"
	"Connection: close\r\n\r\n",
	path, host);
if (n < 0 || (size_t)n >= cap) { free(req); return NULL; }
*req_len = n;
return req;
}

int https_get(const char *url, char **response, char **error_msg)
{
struct url_info uinfo;
int sock = -1, ret = -1;
char *err_buf = NULL;

*response = NULL;
if (error_msg) *error_msg = NULL;

if (!g_initialized) {
	if (error_msg) *error_msg = strdup("HTTPS not initialized");
	return -1;
}
if (parse_url(url, &uinfo) != 0) {
	if (error_msg) *error_msg = strdup("Invalid URL format");
	return -1;
}

sock = tcp_connect(uinfo.host, uinfo.port);
if (sock < 0) {
	if (error_msg) *error_msg = strdup("Network unavailable: cannot connect");
	return -1;
}

if (uinfo.use_tls) {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);
	mbedtls_ssl_setup(&ssl, &conf);
	mbedtls_ssl_set_hostname(&ssl, uinfo.host);
	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send,
		mbedtls_net_recv, NULL);

	/* TLS 握手 */
	{ int tls_ret;
	  while ((tls_ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (tls_ret != MBEDTLS_ERR_SSL_WANT_READ &&
		    tls_ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			char err[256];
			mbedtls_strerror(tls_ret, err, sizeof(err));
			err_buf = malloc(512);
			snprintf(err_buf, 512, "TLS handshake failed: %s", err);
			if (error_msg) *error_msg = err_buf; else free(err_buf);
			goto get_tls_cleanup;
		}
	  }
	}

	/* 构建并发送 GET 请求 */
	{ size_t req_len;
	  char *req = build_get_request(uinfo.host, uinfo.path, &req_len);
	  if (!req) {
		if (error_msg) *error_msg = strdup("Failed to build HTTP request");
		goto get_tls_cleanup;
	  }
	  { int w;
	    while ((w = mbedtls_ssl_write(&ssl, (unsigned char *)req, req_len)) <= 0) {
		if (w != MBEDTLS_ERR_SSL_WANT_WRITE && w != MBEDTLS_ERR_SSL_WANT_READ) {
			free(req);
			if (error_msg) *error_msg = strdup("TLS write failed");
			goto get_tls_cleanup;
		}
	    }
	  }
	  free(req);
	}

	/* 读取响应 */
	{ char *resp = calloc(1, 65536);
	  size_t resp_size = 0, resp_cap = 65536;
	  if (!resp) goto get_tls_cleanup;
	  
	  while (1) {
		char buf[8192];
		int r = mbedtls_ssl_read(&ssl, (unsigned char *)buf, sizeof(buf)-1);
		if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
		if (r <= 0) break;
		if (resp_size + r + 1 > resp_cap) {
			resp_cap = resp_size + r + 8192;
			char *t = realloc(resp, resp_cap);
			if (!t) { free(resp); resp = NULL; break; }
			resp = t;
		}
		memcpy(resp + resp_size, buf, r);
		resp_size += r;
		resp[resp_size] = '\0';
	  }
	  if (resp) {
		char *body = strstr(resp, "\r\n\r\n");
		if (body) {
			body += 4;
			body = strip_chunked(body);
			*response = strdup(body);
		} else { *response = resp; resp = NULL; }
		free(resp);
		ret = 0;
	  }
	}
get_tls_cleanup:
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
} else {
	size_t req_len;
	char *req = build_get_request(uinfo.host, uinfo.path, &req_len);
	if (req) {
		write(sock, req, req_len);
		char *resp = malloc(65536);
		if (resp) {
			ssize_t n = read(sock, resp, 65535);
			if (n > 0) {
				resp[n] = '\0';
				char *body = strstr(resp, "\r\n\r\n");
				if (body) {
					body += 4;
					body = strip_chunked(body);
					*response = strdup(body);
				} else { *response = resp; resp = NULL; }
				ret = 0;
			}
			free(resp);
		}
		free(req);
	}
}

if (sock >= 0) close(sock);
return ret;
}

/* ---- 增量流式 POST（SSE 传输底座） ----
 * 受 CONFIG_AI_STREAM_MODE 门控（Kconfig AIKERNEL_STREAM_MODE）：
 * 流式未编入时本段无调用方，一并裁剪（不留死代码）。 */

#ifdef CONFIG_AI_STREAM_MODE

/* chunked 解码状态机状态 */
#define CHUNK_ST_SIZE   0   /* 累积 chunk 大小行（至 '\n'） */
#define CHUNK_ST_DATA   1   /* 交付 chunk 数据 */
#define CHUNK_ST_CRLF   2   /* 数据后的 CRLF 分隔 */
#define CHUNK_ST_DONE   3   /* 终止块已遇（正常结束） */

struct chunk_decoder {
	int state;
	size_t rem;             /* 当前 chunk 剩余字节 */
	char hexbuf[32];        /* 大小行拼装（';' 后扩展丢弃） */
	size_t hexlen;
	int overflow;           /* 大小行超长防御标志 */
};

/* TLS/明文统一的读原语：>0 数据，0 对端正常关闭，<0 错误 */
struct stream_io {
	int sock;
	mbedtls_ssl_context *ssl;   /* NULL = 明文 HTTP */
};

static int sread(struct stream_io *io, char *buf, size_t len)
{
	if (io->ssl) {
		int r = mbedtls_ssl_read(io->ssl, (unsigned char *)buf, len);

		if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			return 0;
		if (r == MBEDTLS_ERR_SSL_WANT_READ ||
		    r == MBEDTLS_ERR_SSL_WANT_WRITE)
			return r;
		return r;   /* >0 数据；其余负值为错误 */
	}
	return (int)recv(io->sock, buf, len, 0);
}

/* "HTTP/1.1 200 OK" → 200；解析失败返回 0 */
static int hdr_status_code(const char *hdr)
{
	const char *sp = strchr(hdr, ' ');

	return sp ? atoi(sp + 1) : 0;
}

/* 头部是否声明 chunked（大小写不敏感，多头/多值均容忍） */
static int hdr_is_chunked(const char *hdr)
{
	const char *p = hdr;

	while ((p = strcasestr(p, "transfer-encoding")) != NULL) {
		const char *colon = strchr(p, ':');
		const char *eol = strchr(p, '\n');

		if (colon && eol && colon < eol) {
			const char *v = colon + 1;

			while (v < eol && (*v == ' ' || *v == '\t'))
				v++;
			if ((size_t)(eol - v) >= 7 &&
			    strncasecmp(v, "chunked", 7) == 0)
				return 1;
		}
		p += strlen("transfer-encoding");
	}
	return 0;
}

/*
 * chunked_feed - 喂入一段原始网络字节，解码出的 payload 立即回调
 * 返回 0 继续，1 = 遇终止块（正常结束），负值 = 大小行非法
 */
static int chunked_feed(struct chunk_decoder *d, const char **pdata,
			size_t *plen, http_data_cb on_data, void *ud)
{
	const char *p = *pdata;
	size_t n = *plen;
	int ret = 0;

	while (n > 0 && d->state != CHUNK_ST_DONE) {
		switch (d->state) {
		case CHUNK_ST_SIZE:
			while (n > 0 && d->state == CHUNK_ST_SIZE) {
				char c = *p++;

				n--;
				if (c == '\n') {
					unsigned int sz = 0;
					size_t i;
					int bad = d->overflow;
					int hexn = d->hexlen < sizeof(d->hexbuf) ?
						   (int)d->hexlen :
						   (int)sizeof(d->hexbuf);

					if (!bad) {
						for (i = 0; i < (size_t)hexn; i++) {
							char h = d->hexbuf[i];

							if (h == '\r' || h == ';')
								break;
							sz <<= 4;
							if (h >= '0' && h <= '9')
								sz += (unsigned)(h - '0');
							else if (h >= 'a' && h <= 'f')
								sz += (unsigned)(h - 'a' + 10);
							else if (h >= 'A' && h <= 'F')
								sz += (unsigned)(h - 'A' + 10);
							else { bad = 1; break; }
						}
					}
					d->hexlen = 0;
					d->overflow = 0;
					if (bad)
						return -1;
					if (sz == 0) {
						d->state = CHUNK_ST_DONE;
						ret = 1;
						break;
					}
					d->rem = sz;
					d->state = CHUNK_ST_DATA;
				} else if (c != '\r') {
					if (d->hexlen < sizeof(d->hexbuf))
						d->hexbuf[d->hexlen++] = c;
					else
						d->overflow = 1;
				}
			}
			break;
		case CHUNK_ST_DATA: {
			size_t take = n < d->rem ? n : d->rem;

			if (take > 0 && on_data)
				on_data(ud, p, take);
			p += take;
			n -= take;
			d->rem -= take;
			if (d->rem == 0)
				d->state = CHUNK_ST_CRLF;
			break;
		}
		case CHUNK_ST_CRLF:
			/* 帧分隔 CRLF：宽限跳过（大小行以 hex 起始，无误吞） */
			while (n > 0 && (p[0] == '\r' || p[0] == '\n')) {
				p++;
				n--;
			}
			if (n > 0)
				d->state = CHUNK_ST_SIZE;
			break;
		default:
			return -1;
		}
	}

	*pdata = p;
	*plen = n;
	return ret;
}

int https_post_stream(const char *url, const char *api_key,
		      const char *json_body,
		      http_data_cb on_data, void *ud,
		      int *status_code, char **error_msg)
{
	struct url_info uinfo;
	struct stream_io io;
	int sock = -1, ret = -1;
	char *err_buf = NULL;
	char *hdr = NULL;
	size_t hdr_len = 0, hdr_cap = 8192;
	int chunked = 0;
	struct chunk_decoder cd;

	memset(&io, 0, sizeof(io));

	if (status_code)
		*status_code = 0;
	if (error_msg)
		*error_msg = NULL;

	if (!on_data || !json_body) {
		if (error_msg)
			*error_msg = strdup("Invalid arguments");
		return -1;
	}
	if (!g_initialized) {
		if (error_msg)
			*error_msg = strdup("HTTPS not initialized");
		return -1;
	}
	if (parse_url(url, &uinfo) != 0) {
		if (error_msg)
			*error_msg = strdup("Invalid URL format");
		return -1;
	}

	sock = tcp_connect(uinfo.host, uinfo.port);
	if (sock < 0) {
		if (error_msg)
			*error_msg = strdup("Network unavailable: cannot connect");
		return -1;
	}

	if (uinfo.use_tls) {
		mbedtls_ssl_context ssl;
		mbedtls_ssl_config conf;
		int done = 0;

		mbedtls_ssl_init(&ssl);
		mbedtls_ssl_config_init(&conf);
		mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
		mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
		mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);
		mbedtls_ssl_setup(&ssl, &conf);
		mbedtls_ssl_set_hostname(&ssl, uinfo.host);
		mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send,
			mbedtls_net_recv, NULL);

		/* TLS 握手 */
		{ int tls_ret;
		  while ((tls_ret = mbedtls_ssl_handshake(&ssl)) != 0) {
			if (tls_ret != MBEDTLS_ERR_SSL_WANT_READ &&
			    tls_ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				char err[256];

				mbedtls_strerror(tls_ret, err, sizeof(err));
				if (error_msg) {
					err_buf = malloc(512);
					if (err_buf)
						snprintf(err_buf, 512,
							 "TLS handshake failed: %s",
							 err);
					*error_msg = err_buf;
				}
				goto ps_tls_cleanup;
			}
		  }
		}

		/* 构建并发送请求 */
		{ size_t req_len;
		  char *req = build_http_request(uinfo.host, uinfo.path,
			api_key, json_body, &req_len);

		  if (!req) {
			if (error_msg)
				*error_msg = strdup("Failed to build HTTP request");
			goto ps_tls_cleanup;
		  }
		  { int w;
		    while ((w = mbedtls_ssl_write(&ssl, (unsigned char *)req,
						  req_len)) <= 0) {
			if (w != MBEDTLS_ERR_SSL_WANT_WRITE &&
			    w != MBEDTLS_ERR_SSL_WANT_READ) {
				free(req);
				if (error_msg)
					*error_msg = strdup("TLS write failed");
				goto ps_tls_cleanup;
			}
		    }
		  }
		  free(req);
		}

		io.sock = sock;
		io.ssl = &ssl;

		/* 收集响应头（可能跨多个读到达；先收后查——malloc 内存
		 * 未初始化，不能先 strstr） */
		hdr = calloc(1, hdr_cap);
		if (!hdr)
			goto ps_tls_cleanup;
		while (!strstr(hdr, "\r\n\r\n")) {
			char buf[4096];
			int r = sread(&io, buf, sizeof(buf));
			size_t avail;

			if (r == MBEDTLS_ERR_SSL_WANT_READ ||
			    r == MBEDTLS_ERR_SSL_WANT_WRITE)
				continue;
			if (r <= 0) {
				if (error_msg)
					*error_msg = strdup("Connection closed before HTTP header");
				goto ps_tls_cleanup;
			}
			avail = hdr_len + (size_t)r + 1;
			if (avail > hdr_cap) {
				char *t;

				while (hdr_cap < avail)
					hdr_cap *= 2;
				t = realloc(hdr, hdr_cap);
				if (!t)
					goto ps_tls_cleanup;
				hdr = t;
			}
			memcpy(hdr + hdr_len, buf, (size_t)r);
			hdr_len += (size_t)r;
			hdr[hdr_len] = '\0';
			/* 收到数据后再查头终止符 */
			if (strstr(hdr, "\r\n\r\n"))
				break;
		}

		if (status_code)
			*status_code = hdr_status_code(hdr);
		chunked = hdr_is_chunked(hdr);
		memset(&cd, 0, sizeof(cd));

		/* 头部终止符之后的残留字节即 body 首段 */
		{ const char *body = strstr(hdr, "\r\n\r\n") + 4;
		  size_t bn = hdr_len - (size_t)(body - hdr);

		  if (bn > 0) {
			if (chunked) {
				if (chunked_feed(&cd, &body, &bn,
						 on_data, ud) < 0) {
					if (error_msg)
						*error_msg = strdup("Malformed chunked encoding");
					goto ps_tls_cleanup;
				}
			} else if (cd.state != CHUNK_ST_DONE) {
				on_data(ud, body, bn);
			}
		  }
		}

		/* 主循环：逐段读、逐段交付（真增量） */
		while (!done) {
			char buf[8192];
			int r = sread(&io, buf, sizeof(buf));

			if (r == MBEDTLS_ERR_SSL_WANT_READ ||
			    r == MBEDTLS_ERR_SSL_WANT_WRITE)
				continue;
			if (r <= 0)
				break;      /* 对端关闭 / 错误 → 流结束 */
			{
				const char *bp = buf;
				size_t bn = (size_t)r;

				if (chunked) {
					int cr = chunked_feed(&cd, &bp, &bn,
							      on_data, ud);

					if (cr < 0) {
						if (error_msg)
							*error_msg = strdup("Malformed chunked encoding");
						goto ps_tls_cleanup;
					}
					if (cr == 1)
						done = 1;   /* 终止块 */
				} else {
					on_data(ud, bp, bn);
				}
			}
		}
		ret = 0;
ps_tls_cleanup:
		mbedtls_ssl_free(&ssl);
		mbedtls_ssl_config_free(&conf);
	} else {
		/* 明文 HTTP */
		size_t req_len;
		char *req = build_http_request(uinfo.host, uinfo.path,
			api_key, json_body, &req_len);
		int done = 0;

		if (!req) {
			if (error_msg)
				*error_msg = strdup("Failed to build HTTP request");
			close(sock);
			free(hdr);
			return -1;
		}
		if (write(sock, req, req_len) < 0) {
			free(req);
			if (error_msg)
				*error_msg = strdup("Socket write failed");
			close(sock);
			free(hdr);
			return -1;
		}
		free(req);

		io.sock = sock;
		io.ssl = NULL;

		/* 收集响应头（先收后查——malloc 内存未初始化，不能先 strstr） */
		hdr = calloc(1, hdr_cap);
		if (!hdr) {
			close(sock);
			return -1;
		}
		while (!strstr(hdr, "\r\n\r\n")) {
			char buf[4096];
			int r = sread(&io, buf, sizeof(buf));
			size_t avail;

			if (r <= 0) {
				if (error_msg)
					*error_msg = strdup("Connection closed before HTTP header");
				close(sock);
				free(hdr);
				return -1;
			}
			avail = hdr_len + (size_t)r + 1;
			if (avail > hdr_cap) {
				char *t;

				while (hdr_cap < avail)
					hdr_cap *= 2;
				t = realloc(hdr, hdr_cap);
				if (!t) {
					close(sock);
					free(hdr);
					return -1;
				}
				hdr = t;
			}
			memcpy(hdr + hdr_len, buf, (size_t)r);
			hdr_len += (size_t)r;
			hdr[hdr_len] = '\0';
			/* 收到数据后再查头终止符 */
			if (strstr(hdr, "\r\n\r\n"))
				break;
		}

		if (status_code)
			*status_code = hdr_status_code(hdr);
		chunked = hdr_is_chunked(hdr);
		memset(&cd, 0, sizeof(cd));

		/* 头部终止符之后的残留字节即 body 首段 */
		{ const char *body = strstr(hdr, "\r\n\r\n") + 4;
		  size_t bn = hdr_len - (size_t)(body - hdr);

		  if (bn > 0) {
			if (chunked) {
				if (chunked_feed(&cd, &body, &bn,
						 on_data, ud) < 0) {
					if (error_msg)
						*error_msg = strdup("Malformed chunked encoding");
					close(sock);
					free(hdr);
					return -1;
				}
			} else {
				on_data(ud, body, bn);
			}
		  }
		}

		/* 主循环 */
		while (!done) {
			char buf[8192];
			int r = sread(&io, buf, sizeof(buf));
			const char *bp;
			size_t bn;

			if (r < 0)
				break;      /* 错误/超时 → 流结束 */
			if (r == 0)
				break;      /* 对端关闭 → 正常结束 */
			bp = buf;
			bn = (size_t)r;
			if (chunked) {
				int cr = chunked_feed(&cd, &bp, &bn,
						      on_data, ud);

				if (cr < 0) {
					if (error_msg)
						*error_msg = strdup("Malformed chunked encoding");
					close(sock);
					free(hdr);
					return -1;
				}
				if (cr == 1)
					done = 1;
			} else {
				on_data(ud, bp, bn);
			}
		}
		close(sock);
		free(hdr);
		return 0;
	}

	if (hdr)
		free(hdr);
	if (sock >= 0)
		close(sock);
	return ret;
}

#endif /* CONFIG_AI_STREAM_MODE */
