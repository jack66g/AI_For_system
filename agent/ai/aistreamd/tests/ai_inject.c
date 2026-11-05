/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ai_inject.c - NETLINK_AI 事件注入器（**仅测试用 mock 工具**）
 *
 * 经 NETLINK_USERSOCK(2) 用户态↔用户态 netlink 单播，向 aistreamd 的
 * mock 通道（conf AI_MOCK_PROTO=2）发送 struct ai_nl_event 帧：
 * nlmsg_type=AI_CMD_EVENT(19)，category=POLICY(1)，event_id=decision_id
 * 递增，param 唯一（k3cmkNN）。注入器从 stats 文件读 nl_ai_portid 定位。
 *
 * K3d-2 扩展（向后兼容）：第 5 参可选 category——
 *   1 policy（默认，行为同旧）；3 device（16.01：code=0 probe/1 remove，
 *   param=设备名）；4 cpuhp（01.07：code=1 online/0 offline，param=cpu 号）；
 *   5 mce（16.03：param="cpu,bank"，severity=2）。
 *
 * 用法：ai_inject <stats_file> <count> [base_id] [prefix] [category]
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>

#define AI_CMD_EVENT 19
#define AI_NL_EV_POLICY 1

struct inj_event {
	unsigned long long ts;
	unsigned long long event_id;
	unsigned int category;
	unsigned int severity;
	int code;
	unsigned int reserved;
	char param[24];
};

int main(int argc, char **argv)
{
	const char *stats_file;
	int count, base = 1000;
	int category = 1;	/* K3d-2：默认 policy，兼容旧用法 */
	char prefix[16] = "k3cmk";
	char parambuf[24];
	struct sockaddr_nl local, target;
	char buf[NLMSG_SPACE(sizeof(struct inj_event))];
	struct nlmsghdr *nh;
	struct inj_event *ev;
	int fd, portid = -1, sent = 0;
	FILE *f;
	char line[256];

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s <stats_file> <count> [base_id] [prefix] "
			"[category 1|3|4|5]\n",
			argv[0]);
		return 2;
	}
	stats_file = argv[1];
	count = atoi(argv[2]);
	if (argc > 3)
		base = atoi(argv[3]);
	if (argc > 4)
		snprintf(prefix, sizeof(prefix), "%s", argv[4]);
	if (argc > 5) {
		category = atoi(argv[5]);
		if (category != 1 && category != 3 && category != 4 &&
		    category != 5) {
			fprintf(stderr, "category must be 1|3|4|5\n");
			return 2;
		}
	}

	f = fopen(stats_file, "r");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", stats_file, strerror(errno));
		return 1;
	}
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "nl_ai_portid=%d", &portid) == 1)
			break;
	}
	fclose(f);
	if (portid <= 0) {
		fprintf(stderr, "no nl_ai_portid in %s (mock stream open?)\n",
			stats_file);
		return 1;
	}

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
	if (fd < 0) {
		fprintf(stderr, "socket USERSOCK: %s\n", strerror(errno));
		return 1;
	}
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		fprintf(stderr, "bind: %s\n", strerror(errno));
		return 1;
	}
	for (int i = 0; i < count; i++) {
		memset(buf, 0, sizeof(buf));
		nh = (struct nlmsghdr *)buf;
		nh->nlmsg_len = NLMSG_LENGTH(sizeof(*ev));
		nh->nlmsg_type = AI_CMD_EVENT;
		nh->nlmsg_flags = 0;
		nh->nlmsg_seq = (unsigned)(1 + i);
		nh->nlmsg_pid = 0;
		ev = (struct inj_event *)NLMSG_DATA(nh);
		ev->ts = 0;
		ev->event_id = (unsigned long long)(base + i);
		ev->category = (unsigned int)category;
		ev->severity = 0;
		ev->code = 1;
		snprintf(ev->param, sizeof(ev->param), "%s%03d", prefix,
			 base + i);
		/* K3d-2 category 语义（as_streams.c parse_ai_msg 对齐） */
		if (category == 3) {
			ev->code = i % 2;	/* 0=probe 1=remove 轮换 */
			snprintf(parambuf, sizeof(parambuf), "%s%03d", prefix,
				 base + i);
			snprintf(ev->param, sizeof(ev->param), "%.23s",
				 parambuf);
		} else if (category == 4) {
			ev->code = 1;		/* online */
			snprintf(ev->param, sizeof(ev->param), "%d",
				 (base + i) % 128);
		} else if (category == 5) {
			ev->severity = 2;	/* error（MCE） */
			ev->code = 0;
			snprintf(ev->param, sizeof(ev->param), "%d,%d",
				 (base + i) % 8, i % 16);
		}
		memset(&target, 0, sizeof(target));
		target.nl_family = AF_NETLINK;
		target.nl_pid = (unsigned int)portid;
		if (sendto(fd, buf, nh->nlmsg_len, 0,
			   (struct sockaddr *)&target, sizeof(target)) < 0) {
			fprintf(stderr, "sendto %u: %s\n",
				(unsigned)portid, strerror(errno));
			break;
		}
		sent++;
	}
	close(fd);
	printf("injected %d/%d events (category=%d) to portid=%d\n", sent,
	       count, category, portid);
	return sent == count ? 0 : 1;
}
