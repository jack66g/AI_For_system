// SPDX-License-Identifier: GPL-2.0
/*
 * ai_net_scan.c - AIKernel HTTP/TLS 内容识别（自 ai_net.c 拆分）
 *
 * 职责一句话：TX 路径解析 TCP 数据段首部 HTTP 请求行（method/url/Host）或
 * TLS ClientHello（SNI）、RX 路径解析 HTTP 响应状态码，带越界检查，
 * 采样通过后零脱敏发射。
 *
 * 拆分说明：函数体自原 ai_net.c（1141 行）逐字搬移；http 方法表/
 * strncaseeq/http_scan/tls_scan 仅本文件使用保持 static；IPv4 五元组提取
 * ai_net_sock_addr4 经 ai_net_internal.h 共享（定义在 ai_net_telemetry.c）。
 * 门控：随 ai_net.o 在 CONFIG_AIKERNEL_NET 下构建（与拆分前一致）。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ktime.h>
#include <linux/netfilter.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <net/xdp.h>
#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include "ai_net.h"
#include "../core/ai_control.h"

#ifdef CONFIG_INET
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#endif

#ifdef CONFIG_NF_CONNTRACK
#include <net/netfilter/nf_conntrack.h>
#endif
#ifdef CONFIG_NF_NAT
#include <net/netfilter/nf_nat.h>
#endif
#ifdef CONFIG_NF_CONNTRACK_ACCT
#include <net/netfilter/nf_conntrack_acct.h>
#endif
#include "ai_net_internal.h"

/*
 * ---- HTTP/TLS 识别（采样，基础实现；零脱敏） ----
 * TX 路径：TCP 数据段首部解析 HTTP 请求行（method/url/Host）或 TLS ClientHello（SNI）；
 * RX 路径：解析 HTTP 响应状态码。所有解析带越界检查，失败不发射。
 */

static const char *const ai_net_http_methods[] = {
	"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT",
};

static bool ai_net_strncaseeq(const char *a, const char *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		char ca = a[i], cb = b[i];

		if (ca >= 'A' && ca <= 'Z')
			ca += 'a' - 'A';
		if (cb >= 'A' && cb <= 'Z')
			cb += 'a' - 'A';
		if (ca != cb)
			return false;
	}
	return true;
}

static void ai_net_http_scan(struct sock *sk, struct sk_buff *skb,
			     const char *buf, u32 len, u32 plen, bool is_tx)
{
	struct ai_net_pl_http_request pl;
	u32 i;

	(void)sk;
	(void)skb;

	if (!is_tx) {
		/* 响应：HTTP/1.x DDD */
		if (len < 12 || memcmp(buf, "HTTP/1.", 7))
			return;
		if (buf[8] != ' ')
			return;
		if (buf[9] < '0' || buf[9] > '9' ||
		    buf[10] < '0' || buf[10] > '9' ||
		    buf[11] < '0' || buf[11] > '9')
			return;
		if (!ai_net_sample_take(AI_NET_SUB_HTTP_REQUEST))
			return;
		memset(&pl, 0, sizeof(pl));
		pl.type = AI_NET_SUB_HTTP_REQUEST;
		pl.status_code = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 +
				 (buf[11] - '0');
		pl.bytes = plen;
		pl.pid = task_tgid_nr(current);
		strscpy(pl.comm, current->comm, sizeof(pl.comm));
		strscpy(pl.method, "HTTP", sizeof(pl.method));
		ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_HTTP_TLS,
					 AI_SEV_NORMAL, &pl, sizeof(pl));
		return;
	}

	/* 请求：METHOD SP URL SP HTTP/1.x，随后 \r\nHost: <h> */
	for (i = 0; i < ARRAY_SIZE(ai_net_http_methods); i++) {
		size_t mlen = strlen(ai_net_http_methods[i]);
		u32 j, k;

		if (len < mlen + 2 || memcmp(buf, ai_net_http_methods[i], mlen) ||
		    buf[mlen] != ' ')
			continue;
		if (!ai_net_sample_take(AI_NET_SUB_HTTP_REQUEST))
			return;
		memset(&pl, 0, sizeof(pl));
		pl.type = AI_NET_SUB_HTTP_REQUEST;
		pl.bytes = plen;
		pl.pid = task_tgid_nr(current);
		strscpy(pl.comm, current->comm, sizeof(pl.comm));
		strscpy(pl.method, ai_net_http_methods[i], sizeof(pl.method));
		/* URL: 到下一个 SP 或 CR */
		for (j = mlen + 1; j < len && buf[j] != ' ' && buf[j] != '\r';
		     j++)
			;
		k = min_t(u32, j - (mlen + 1), sizeof(pl.url) - 1);
		memcpy(pl.url, buf + mlen + 1, k);
		/* Host: 头（大小写不敏感搜索） */
		for (j = 0; j + 6 < len; j++) {
			if (buf[j] == '\r' && buf[j + 1] == '\n' &&
			    j + 8 < len && ai_net_strncaseeq(buf + j + 2, "host:",
							     5)) {
				u32 hs = j + 7;
				u32 he;

				if (buf[hs] == ' ')
					hs++;
				for (he = hs; he < len && buf[he] != '\r' &&
				     buf[he] != '\n'; he++)
					;
				k = min_t(u32, he - hs, sizeof(pl.host) - 1);
				memcpy(pl.host, buf + hs, k);
				break;
			}
		}
		ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_HTTP_TLS,
					 AI_SEV_NORMAL, &pl, sizeof(pl));
		return;
	}
}

static void ai_net_tls_scan(struct sock *sk, struct sk_buff *skb,
			    const char *buf, u32 len)
{
	struct ai_net_pl_tls_handshake pl;
	u32 pos, exts, ext_total;

	if (len < 44)
		return;
	if (buf[0] != 0x16)		/* TLS Handshake record */
		return;
	if ((buf[1] != 0x03) || (buf[2] < 0x01 || buf[2] > 0x04))
		return;
	if (buf[5] != 0x01)		/* ClientHello */
		return;
	/* 严格校验：legacy_version 必须为合法 TLS 版本，握手长度必须非零 */
	if (buf[9] != 0x03 || buf[10] < 0x01 || buf[10] > 0x04)
		return;
	if (!buf[6] && !buf[7] && !buf[8])
		return;
	if (!ai_net_sample_take(AI_NET_SUB_TLS_HANDSHAKE))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_NET_SUB_TLS_HANDSHAKE;
	pl.version = (buf[9] << 8) | buf[10];
	pl.pid = task_tgid_nr(current);
	strscpy(pl.comm, current->comm, sizeof(pl.comm));
#ifdef CONFIG_INET
	if (sk && sk->sk_family == AF_INET)
		ai_net_sock_addr4(sk, NULL, &pl.dst_addr, NULL, &pl.dst_port);
	else if (skb && skb->protocol == htons(ETH_P_IP)) {
		const struct iphdr *iph = ip_hdr(skb);
		const struct tcphdr *th;

		pl.dst_addr = iph->daddr;
		if (skb->len >= sizeof(struct tcphdr)) {
			th = (const struct tcphdr *)skb->data;
			pl.dst_port = ntohs(th->dest);
		}
	}
#endif
	/* cipher suites: 2B 长度 + 条目（首个即选用套件） */
	pos = 43;			/* 11 + 32(random) */
	if (pos >= len)
		goto out;
	pos += 1 + buf[pos];		/* session_id */
	if (pos + 2 > len)
		goto out;
	pos += 2;			/* cipher_suites 长度字段 */
	if (pos + 2 <= len)
		pl.cipher_suite = (buf[pos] << 8) | buf[pos + 1];
	pos += 2;
	if (pos >= len)
		goto out;
	pos += 1 + buf[pos];		/* compression */
	if (pos + 2 > len)
		goto out;
	ext_total = (buf[pos] << 8) | buf[pos + 1];
	pos += 2;
	if (pos + ext_total > len)
		ext_total = len - pos;
	/* 扩展遍历：type(2)+len(2)+data */
	exts = ext_total;
	while (exts >= 4 && pos + 4 <= len) {
		u16 etype = (buf[pos] << 8) | buf[pos + 1];
		u32 elen = (buf[pos + 2] << 8) | buf[pos + 3];
		u32 dpos = pos + 4;

		if (etype == 0 && elen >= 5 && dpos + elen <= len) {
			/* server_name 扩展：list_len(2) type(1) name_len(2) name */
			u32 list = (buf[dpos] << 8) | buf[dpos + 1];
			u32 npos = dpos + 2;

			if (list >= 3 && npos + 3 <= len && buf[npos] == 0) {
				u32 nlen = (buf[npos + 1] << 8) |
					   buf[npos + 2];
				u32 s = npos + 3;

				if (s + nlen <= len && s + nlen <= dpos + elen)
					memcpy(pl.sni, buf + s,
					       min_t(u32, nlen,
						     sizeof(pl.sni) - 1));
			}
			break;
		}
		pos = dpos + elen;
		exts = ext_total - (pos - (dpos - 4));
	}
out:
	ai_telemetry_emit_direct(AI_CAT_NET, AI_EV_HTTP_TLS, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
}

void ai_net_http_tls_scan(struct sock *sk, struct sk_buff *skb,
			  u32 payload_off, bool is_tx)
{
	char buf[256];
	u32 plen;
	u32 n;

	if (!skb || skb->len <= payload_off)
		return;
	plen = skb->len - payload_off;
	n = min_t(u32, plen, sizeof(buf));
	skb_copy_bits(skb, payload_off, buf, n);
	ai_net_http_scan(sk, skb, buf, n, plen, is_tx);
	ai_net_tls_scan(sk, skb, buf, n);
}
EXPORT_SYMBOL_GPL(ai_net_http_tls_scan);
