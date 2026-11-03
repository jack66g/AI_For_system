/* SPDX-License-Identifier: GPL-2.0 -*-
 *
 * apinl.c - T7b NETLINK_AI v2 定向 apply(参考 nl_pack_act/
 * nl_unpack_act_ack/nl_act;结构 "<QIBBHI4x8Q24s" 112B / "=IHHII" 16B 头 /
 * ack "<IIiI" 16B)。
 *
 * L1 现实:通用内核未注册协议 31 → socket() 即 EPROTONOSUPPORT
 * ("netlink socket: [Errno 93] Protocol not supported",录制实证)。
 * 特权成功路径按参考代码级实现(T7f qemu 内验)。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <linux/netlink.h>

#include "apic/api.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

/* "<QIBBHI4x8Q24s":u64 0,u32 0,u8 domain,u8 confidence,u16 0,u32 0,
 * 4B pad,u64 data[8],char param[24] */
int api_nl_pack_act(unsigned char out[AI_NL_ACT_SIZE], long long domain,
		    int confidence, const char *param, long long data0,
		    long long data1)
{
	uint64_t data[8];
	size_t plen;

	memset(out, 0, AI_NL_ACT_SIZE);
	memset(data, 0, sizeof(data));
	data[0] = (uint64_t)data0;
	data[1] = (uint64_t)data1;
	{
		uint64_t u64_0 = 0;
		uint32_t u32_0 = 0;
		uint8_t d8 = (uint8_t)domain;
		uint8_t c8 = (uint8_t)confidence;
		uint16_t h0 = 0;
		uint32_t r0 = 0;

		memcpy(out + 0, &u64_0, 8);
		memcpy(out + 8, &u32_0, 4);
		memcpy(out + 12, &d8, 1);
		memcpy(out + 13, &c8, 1);
		memcpy(out + 14, &h0, 2);
		memcpy(out + 16, &r0, 4);
		/* 20..23 pad 已清零 */
		memcpy(out + 24, data, 64);
	}
	plen = strlen(param);
	if (plen > AI_NL_ACT_PARAM_LEN - 1)
		plen = AI_NL_ACT_PARAM_LEN - 1;
	memcpy(out + 88, param, plen);
	return 0;
}

aik_json *api_nl_unpack_act_ack(const unsigned char *payload, size_t n)
{
	uint32_t executed, hit;
	int32_t ai_err;

	if (n < AI_NL_ACT_ACK_SIZE)
		return NULL;
	memcpy(&executed, payload + 0, 4);
	memcpy(&hit, payload + 4, 4);
	memcpy(&ai_err, payload + 8, 4);
	{
		aik_json *o = dt_new_obj();

		dt_put_int(o, "executed", (long long)executed);
		dt_put_int(o, "hit", (long long)hit);
		dt_put_int(o, "ai_err", (long long)ai_err);
		return o;
	}
}

/* 读 /proc/ai/control 并按名查参数(返回 malloc 结构副本;缺 → NULL) */
struct api_param_def {
	char name[128];
	long long domain, min, max, current, default_val;
	int task_scoped;
};

static struct api_param_def *find_control_param(const char *param)
{
	size_t n = 0;
	char *text = api_read_file(API_CONTROL_PROC, &n, NULL);
	struct api_param_def *out = NULL;
	char *line, *save;

	if (!text)
		return NULL;
	for (line = strtok_r(text, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char name[128];
		long long dom, lo, hi, cur, def;

		if (api_parse_control_line(line, name, sizeof(name), &dom,
					   &lo, &hi, &cur, &def) != 0)
			continue;
		if (strcmp(name, param) != 0)
			continue;
		out = malloc(sizeof(*out));
		if (!out)
			break;
		snprintf(out->name, sizeof(out->name), "%s", name);
		out->domain = dom;
		out->min = lo;
		out->max = hi;
		out->current = cur;
		out->default_val = def;
		out->task_scoped = api_is_task_param(name);
		break;
	}
	free(text);
	return out;
}

/* errno → python errno.errorcode 名 */
static const char *errno_code(int e)
{
	switch (e) {
	case 1:
		return "EPERM";
	case 2:
		return "ENOENT";
	case 13:
		return "EACCES";
	case 22:
		return "EINVAL";
	case 12:
		return "ENOMEM";
	case 16:
		return "EBUSY";
	case 95:
		return "EOPNOTSUPP";
	case 122:
		return "EDQUOT";
	default:
		return "?";
	}
}

int api_nl_act(const char *param, long long value, long long pid,
	       aik_json **ack_out, char **err_out)
{
	struct api_param_def *pdef = find_control_param(param);
	unsigned char payload[AI_NL_ACT_SIZE];
	unsigned char msg[16 + AI_NL_ACT_SIZE];
	unsigned char resp[65536];
	struct sockaddr_nl sa;
	socklen_t salen;
	int fd;
	uint32_t seq, portid;
	char emsg[256];
	ssize_t sn;
	long long deadline;

	*ack_out = NULL;
	*err_out = NULL;
	if (!pdef) {
		*err_out = strdup("param vanished from control table");
		return -1;
	}
	if (pdef->task_scoped)
		api_nl_pack_act(payload, pdef->domain, 90, param, pid,
				value);
	else
		api_nl_pack_act(payload, pdef->domain, 90, param, value, 0);
	free(pdef);

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_AI);
	if (fd < 0) {
		snprintf(emsg, sizeof(emsg), "netlink socket: [Errno %d] %s",
			 errno, strerror(errno));
		*err_out = strdup(emsg);
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		snprintf(emsg, sizeof(emsg), "netlink io: [Errno %d] %s",
			 errno, strerror(errno));
		*err_out = strdup(emsg);
		close(fd);
		return -1;
	}
	salen = sizeof(sa);
	if (getsockname(fd, (struct sockaddr *)&sa, &salen) == 0)
		portid = sa.nl_pid;
	else
		portid = (uint32_t)getpid();
	seq = (uint32_t)(api_time() & 0x7fffffff);
	{
		uint32_t len = 16 + AI_NL_ACT_SIZE;
		uint16_t type = AI_CMD_ACT;
		uint16_t flags = NLM_F_REQUEST_AI;
		memcpy(msg + 0, &len, 4);
		memcpy(msg + 4, &type, 2);
		memcpy(msg + 6, &flags, 2);
		memcpy(msg + 8, &seq, 4);
		memcpy(msg + 12, &portid, 4);
		memcpy(msg + 16, payload, AI_NL_ACT_SIZE);
	}
	{
		struct timeval tv = { 5, 0 };

		(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv,
				 sizeof(tv));
		(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv,
				 sizeof(tv));
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sn = sendto(fd, msg, sizeof(msg), 0, (struct sockaddr *)&sa,
		    sizeof(sa));
	if (sn < 0) {
		snprintf(emsg, sizeof(emsg), "netlink io: [Errno %d] %s",
			 errno, strerror(errno));
		*err_out = strdup(emsg);
		close(fd);
		return -1;
	}
	deadline = (long long)time(NULL) + 5;
	for (;;) {
		struct sockaddr_nl src;
		socklen_t slen = sizeof(src);
		ssize_t rn = recvfrom(fd, resp, sizeof(resp), 0,
				      (struct sockaddr *)&src, &slen);
		uint32_t rlen, rseq;
		uint16_t rtype;
		const unsigned char *body;

		if (rn < 0) {
			if (errno == EINTR)
				continue;
			*err_out = strdup("netlink reply timeout");
			close(fd);
			return -1;
		}
		if ((size_t)rn < 16 || src.nl_pid != 0)
			continue;
		memcpy(&rlen, resp + 0, 4);
		memcpy(&rtype, resp + 4, 2);
		memcpy(&rseq, resp + 8, 4);
		if (rseq != seq)
			continue;
		{
			uint32_t blen = rlen > 16 ? rlen - 16 : 0;

			if (16 + blen > (uint32_t)rn)
				blen = (uint32_t)rn - 16;
			body = resp + 16;
			if (rtype == AI_CMD_ACT) {
				*ack_out = api_nl_unpack_act_ack(body,
								 (size_t)blen);
				if (!*ack_out) {
					*err_out = strdup(
						"netlink ack(0) 未携带 "
						"act 应答");
					close(fd);
					return -1;
				}
				close(fd);
				return 0;
			}
			if (rtype == NLMSG_ERROR_AI) {
				int32_t errv = 0;

				memcpy(&errv, body, 4);
				if (errv == 0) {
					*err_out = strdup(
						"netlink ack(0) 未携带 "
						"act 应答");
				} else {
					snprintf(emsg, sizeof(emsg),
						 "kernel errno %d (%s)",
						 -errv, errno_code(-errv));
					*err_out = strdup(emsg);
				}
				close(fd);
				return -1;
			}
		}
		if ((long long)time(NULL) > deadline) {
			*err_out = strdup("netlink reply timeout");
			close(fd);
			return -1;
		}
	}
}
