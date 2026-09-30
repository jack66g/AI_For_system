/*
 * main.c - AI Shell 入口点（'ai' 二进制）
 *
 * UI Phase 起 'ai' 与 'aikernel-shell' 为同一终端 AI 界面程序：
 * 共享入口在 aikernel_shell_main()（linenoise REPL + 命令行参数 +
 * 单发模式 ai -p "问题"），本文件只做 main() 薄封装。
 * rootfs 安装时 /usr/local/bin/ai -> aikernel-shell（Makefile install）。
 */
#include <stdio.h>
#include <stdlib.h>

extern int aikernel_shell_main(int argc, char **argv);

int main(int argc, char **argv)
{
	return aikernel_shell_main(argc, argv);
}
