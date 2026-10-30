// SPDX-License-Identifier: GPL-2.0
/*
 * netlink_probe.c - W79 诊断：NETLINK_AI 逐层 errno 探针（真客户端，无桩）
 *
 * 用途：在 AIKernel 真内核上定位 ACT 失败的确切层级与 errno，不靠猜。
 *   1. 原始 socket(AF_NETLINK, SOCK_RAW, NETLINK_AI) + bind 的 errno；
 *   2. 客户端 ai_nl_client_open 的返回码与 errno；
 *   3. REG 自检（只登记 portid，不改调度参数）；
 *   4. ACT 定向下发（param=sched.nice 等），打印请求字段与 ack/kern_err；
 *   5. 可选 SENSE（--sense；只拉 1 条，会排空 ring 尾部，默认不做）。
 *
 * 用法（guest 内 root）：
 *   ./netlink_probe                      # 只做 1-4（ACT 用 sched.nice pid=自己 value=0）
 *   ./netlink_probe sched.timeslice 20   # 指定 param/value（pid=自身）
 *   ./netlink_probe sched.nice 5 <pid>
 *   ./netlink_probe --sense
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#include "ai_types.h"
#include "netlink/ai_netlink_client.h"

static void show(int step, const char *what, int rc, int err)
{
	if (err)
		printf("[%d] %-28s rc=%-3d errno=%d (%s)\n", step, what, rc,
		       err, strerror(err));
	else
		printf("[%d] %-28s rc=%-3d errno=0\n", step, what, rc);
}

int main(int argc, char **argv)
{
	struct utsname un;
	const char *param = "sched.nice";
	long long value = 0, pid = (long long)getpid();
	int want_sense = 0, argi = 1;
	int fd, rc, err, kern_err = 0;
	struct sockaddr_nl addr;
	socklen_t alen;
	struct ai_nl_client cli;
	__s32 ai_err = 0;
	__u32 count = 0;

	if (argi < argc && strcmp(argv[argi], "--sense") == 0) {
		want_sense = 1;
		argi++;
	}
	if (argi < argc)
		param = argv[argi++];
	if (argi < argc)
		value = atoll(argv[argi++]);
	if (argi < argc)
		pid = atoll(argv[argi++]);

	printf("== netlink_probe（NETLINK_AI 逐层诊断）==\n");
	if (uname(&un) == 0)
		printf("kernel: %s %s %s\n", un.sysname, un.release,
		       un.machine);
	printf("/proc/ai/control: %s\n",
	       access("/proc/ai/control", R_OK) == 0 ? "存在" : "不存在");
	printf("uid=%u（ACT/REG 需 CAP_SYS_ADMIN）\n", (unsigned)getuid());

	/* 1. 原始 socket/bind */
	errno = 0;
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_AI);
	err = errno;
	show(1, "socket(AF_NETLINK,31)", fd, err);
	if (fd >= 0) {
		memset(&addr, 0, sizeof(addr));
		addr.nl_family = AF_NETLINK;
		errno = 0;
		rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
		err = errno;
		show(2, "bind(nl_pid=0)", rc, err);
		alen = sizeof(addr);
		if (rc == 0 && getsockname(fd, (struct sockaddr *)&addr,
					   &alen) == 0)
			printf("    portid=%u\n", addr.nl_pid);
		close(fd);
	}

	/* 2. 客户端 open */
	memset(&cli, 0, sizeof(cli));
	cli.fd = -1;
	errno = 0;
	rc = ai_nl_client_open(&cli);
	err = errno;
	show(3, "ai_nl_client_open", rc, err);
	if (rc != AI_OK)
		return 1;
	printf("    portid=%u timeout_ms=%d retries=%d\n", cli.portid,
	       cli.timeout_ms, cli.retries);

	/* 3. REG（只登记 portid） */
	rc = ai_nl_send_reg(&cli, 0, &ai_err, &count, &kern_err);
	printf("[4] %-28s rc=%d ai_err=%d count=%u kern_errno=%d%s%s\n",
	       "REG", rc, ai_err, count, kern_err,
	       kern_err ? " (" : "", kern_err ? strerror(kern_err) : "");
	if (kern_err)
		printf("    hint: %s\n",
		       ai_nl_errno_hint(kern_err) ?
		       ai_nl_errno_hint(kern_err) : "-");

	/* 4. ACT */
	{
		struct ai_nl_act req;
		struct ai_nl_act_ack ack;

		memset(&req, 0, sizeof(req));
		req.decision_type = 1;
		req.domain = 1;		/* AI_POLICY_DOMAIN_SCHED */
		req.confidence = 100;
		snprintf(req.param, sizeof(req.param), "%s", param);
		req.data[0] = (__u64)pid;
		req.data[1] = (__u64)value;
		printf("    ACT req: param=%s domain=%u decision_type=%u "
		       "trigger_event_id=%llu confidence=%u data[0]=%llu "
		       "data[1]=%lld\n",
		       req.param, req.domain, req.decision_type,
		       (unsigned long long)req.trigger_event_id,
		       req.confidence,
		       (unsigned long long)req.data[0], value);
		memset(&ack, 0, sizeof(ack));
		kern_err = 0;
		rc = ai_nl_send_act(&cli, &req, &ack, &kern_err);
		printf("[5] %-28s rc=%d kern_errno=%d%s%s executed=%u hit=%u "
		       "ai_err=%d\n", "ACT", rc, kern_err,
		       kern_err ? " (" : "", kern_err ? strerror(kern_err) : "",
		       ack.executed, ack.hit, ack.ai_err);
		if (kern_err)
			printf("    hint: %s\n",
			       ai_nl_errno_hint(kern_err) ?
			       ai_nl_errno_hint(kern_err) : "-");
	}

	/* 5. SENSE（可选；只拉 1 条） */
	if (want_sense) {
		struct ai_nl_sense_ack sack;
		void *stream = malloc(AI_NL_PAYLOAD_MAX);

		memset(&sack, 0, sizeof(sack));
		size_t slen = 0;

		kern_err = 0;
		rc = ai_nl_send_sense(&cli, AI_NL_SENSE_CPU_ALL, 1,
				      AI_NL_FORMAT_HUMAN, &sack, stream,
				      AI_NL_PAYLOAD_MAX, &slen, &kern_err);
		printf("[6] %-28s rc=%d kern_errno=%d%s%s records=%u bytes=%u\n",
		       "SENSE(max_records=1)", rc, kern_err,
		       kern_err ? " (" : "", kern_err ? strerror(kern_err) : "",
		       sack.records, sack.bytes);
		free(stream);
	}

	ai_nl_client_close(&cli);
	printf("== netlink_probe 结束 ==\n");
	return 0;
}
