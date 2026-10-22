// SPDX-License-Identifier: GPL-2.0
/*
 * w64-init.c - W64 QEMU 演练用极简 init（PID 1）
 *
 * 职责：
 *   1. 挂 proc/sysfs/cgroup2（initramfs 里没有 systemd）；
 *   2. fork+exec /w64-test.sh；
 *   3. 循环 waitpid(-1) 回收所有被收养的孤儿（沙盒 init 随 PDEATHSIG 死亡
 *      后会被 reparent 到 PID 1，若不回收会成为僵尸，干扰 cgroup 清空）；
 *   4. 测试脚本退出后 sync + poweroff。
 *
 * 静态编译（host gcc -static）。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	pid_t test;
	int st = 0;

	mkdir("/proc", 0555);
	mkdir("/sys", 0555);
	mkdir("/dev", 0755);
	mkdir("/sys/fs", 0555);
	mkdir("/sys/fs/cgroup", 0755);
	if (mount("proc", "/proc", "proc", 0, NULL))
		perror("mount /proc");
	if (mount("sysfs", "/sys", "sysfs", 0, NULL))
		perror("mount /sys");
	if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL))
		perror("mount /dev");
	if (mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, NULL))
		perror("mount cgroup2");

	printf("INIT: cgroup2 mounted, starting w64-test.sh\n");
	fflush(stdout);

	test = fork();
	if (test < 0) {
		perror("fork");
		reboot(RB_POWER_OFF);
		return 1;
	}
	if (test == 0) {
		execl("/w64-test.sh", "w64-test.sh", (char *)NULL);
		perror("exec /w64-test.sh");
		_exit(127);
	}
	for (;;) {
		pid_t p = waitpid(-1, &st, 0);

		if (p < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (p == test) {
			printf("INIT: test script exited status=%d\n", st);
			fflush(stdout);
			sleep(1);
			break;
		}
	}
	sync();
	reboot(RB_POWER_OFF);
	return 0;
}
