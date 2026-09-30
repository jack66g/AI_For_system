# SPDX-License-Identifier: GPL-2.0
#
# AIKernel/net - AI 网络子系统 Makefile
#
# 当前内容：
#   ai_netlink.o        - NETLINK_AI 协议族（Prompt 02，CONFIG_AIKERNEL_NETLINK）
#   ai_net.o            - AI 网络核心：Hook 空实现 + 决策框架 + 采样门控（Prompt 06）
#   ai_net_telemetry.o  - 第4类复杂解析发射（socket/tcp/udp/ip/nf/xdp/dns/neigh，
#                         自 ai_net.c 拆分）
#   ai_net_scan.o       - HTTP/TLS 内容识别发射（自 ai_net.c 拆分）
#   ai_tcp_cca.o        - AI TCP 拥塞控制 ai_cca（Prompt 06，CONFIG_AIKERNEL_NET）
#
# CONFIG_AIKERNEL_NET=n 时全部不参与构建 → 网络行为与原生一致（默认 CCA 仍为 cubic）。
#

obj-$(CONFIG_AIKERNEL_NETLINK)	+= ai_netlink.o
obj-$(CONFIG_AIKERNEL_NET)	+= ai_net.o ai_net_telemetry.o ai_net_scan.o ai_tcp_cca.o
