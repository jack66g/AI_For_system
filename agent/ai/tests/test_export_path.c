// SPDX-License-Identifier: GPL-2.0
/*
 * test_export_path.c - W43 memory_export 路径白名单回归（安全 finding 修复）
 *
 * 修复前：sme_export 的 path 参数无任何校验，可任意路径写（root 权限）
 * ——/etc/cron.d、ssh authorized_keys、systemd unit 均可被落盘。
 * 修复后：强制 realpath 规范化后必须落在 /tmp 或 /var/ai 下。
 *
 * 断言（非法路径在触碰网络前即被拒，返回 AI_ERR_INVALID_ARG）：
 *   /etc/cron.d/x、/root/x、/usr/local/bin/x（白名单外绝对路径）
 *   /tmp/../etc/x、/var/ai/../../root/x（".." 穿越分量）
 *   相对路径（强制绝对路径契约）
 *   目录符号链接逃逸（/tmp/link → /etc，落点解析为 /etc/...）
 *   既有文件符号链接逃逸（/tmp/sym.json → /etc/passwd）
 *   目录本身（/tmp）
 * 合法路径：/tmp 下既有名/新名 → 通过白名单进入请求段（SME 不可达时
 * 返回 AI_ERR_NETWORK）；默认路径（NULL）不回归。
 */
#define _GNU_SOURCE             /* setenv/symlink/unlink */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ai_types.h"
#include "memory/sme_client.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

int main(void)
{
	char out[1024];
	int rc;

	/* 端口 1：必然立即拒绝——合法路径会走到网络段返回 NETWORK */
	setenv("SME_URL", "http://127.0.0.1:1", 1);

	/* ---- 非法：白名单外绝对路径 ---- */
	rc = sme_export("/etc/cron.d/aik-w43-pwn", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "拒绝 /etc/cron.d 落盘");
	rc = sme_export("/root/aik-w43.json", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "拒绝 /root 落盘");
	rc = sme_export("/usr/local/bin/aik-w43.json", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "拒绝 /usr/local/bin 落盘");

	/* ---- 非法：".." 穿越分量 ---- */
	rc = sme_export("/tmp/../etc/aik-w43.json", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "拒绝 /tmp/../etc 穿越");
	rc = sme_export("/var/ai/../../root/aik-w43.json", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "拒绝 /var/ai/../../root 多层穿越");
	rc = sme_export("/tmp/aik-w43-v2/../../../etc/passwd", out,
			sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "拒绝多级 .. 深穿越");

	/* ---- 非法：相对路径（强制绝对路径契约） ---- */
	rc = sme_export("relative-aik-w43.json", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "拒绝相对路径");

	/* ---- 非法：符号链接逃逸 ---- */
	unlink("/tmp/aik-w43-etc-link");
	unlink("/tmp/aik-w43-sym.json");
	unlink("/tmp/aik-w43-real.json");
	if (symlink("/etc", "/tmp/aik-w43-etc-link") == 0) {
		rc = sme_export("/tmp/aik-w43-etc-link/cron.d/x", out,
				sizeof(out));
		CHECK(rc == AI_ERR_INVALID_ARG,
		      "拒绝目录符号链接逃逸（/tmp/link → /etc）");
		unlink("/tmp/aik-w43-etc-link");
	} else {
		printf("skip: 目录符号链接创建失败（环境限制）\n");
	}
	{
		FILE *fp = fopen("/tmp/aik-w43-real.json", "w");

		if (fp) {
			fclose(fp);
			if (symlink("/etc/passwd",
				    "/tmp/aik-w43-sym.json") == 0) {
				rc = sme_export("/tmp/aik-w43-sym.json", out,
						sizeof(out));
				CHECK(rc == AI_ERR_INVALID_ARG,
				      "拒绝既有文件符号链接逃逸"
				      "（realpath 解析到 /etc/passwd）");
				unlink("/tmp/aik-w43-sym.json");
			}
			unlink("/tmp/aik-w43-real.json");
		}
	}

	/* ---- 非法：目录本身 ---- */
	rc = sme_export("/tmp", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "拒绝目录本身（/tmp 非导出文件）");

	/* ---- 合法：/tmp 下（进入请求段，SME 不可达 → NETWORK） ---- */
	unlink("/tmp/aik-w43-export.json");
	rc = sme_export("/tmp/aik-w43-export.json", out, sizeof(out));
	CHECK(rc == AI_ERR_NETWORK, "合法路径 /tmp/x.json 通过白名单");
	unlink("/tmp/aik-w43-newfile.json");
	rc = sme_export("/tmp/aik-w43-newfile.json", out, sizeof(out));
	CHECK(rc == AI_ERR_NETWORK, "合法路径新建文件（目录 realpath 分支）");

	/* ---- 默认路径不回归 ---- */
	rc = sme_export(NULL, out, sizeof(out));
	CHECK(rc == AI_ERR_NETWORK, "默认路径 /tmp/sme-export.json 保持可用");

	printf("\n%s\n", g_fail ? "test_export_path: FAIL" :
			  "test_export_path: ALL PASS");
	return g_fail ? 1 : 0;
}
