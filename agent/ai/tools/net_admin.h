/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net_admin.h - W78 P2 网络执行面（rtnetlink 写 + nft 事务，7 件全 W2）
 *
 * 件目：net_iface（up/down）、net_addr_add/net_addr_del、
 *       net_route_add/net_route_del、net_link_del（仅虚拟接口）、nft_txn
 * 通道：TOOL_CH_NETADMIN；执行器入口 exec_net_admin_channel()。
 * 风险：全 W2（lease D0-D4 逐次确认由 executor 通用闸门保障，无旁路）；
 * 每件写前先 rtnetlink 读旧值落输出（回滚凭据），写后回读验证。
 */
#ifndef _AI_NET_ADMIN_H
#define _AI_NET_ADMIN_H

#include <stddef.h>

/* 纯函数（导出供单测） */
int ai_net_admin_valid_iface(const char *s);   /* 接口名 [A-Za-z0-9._-]{1,15} */
int ai_net_admin_valid_nft_op(const char *op); /* nft 片段：禁 ; ` $( 换行等，
						* 1..512 字节可打印 */
int ai_net_admin_parse_cidr(const char *s, int *family, void *addr,
			    int *plen);       /* CIDR（必须带 /前缀），双栈
						   * inet_pton 真校验 */
int ai_net_admin_parse_ip(const char *s, int *family, void *addr);
					       /* 裸地址（禁 /）双栈校验 */
int ai_net_admin_table_id(const char *name, int *id);
					       /* main=254/local=255/
						* default=253/数字 0..2^31 */

/* 执行器入口（executor.c 的 TOOL_CH_NETADMIN 分发调用） */
int exec_net_admin_channel(const void *tool, const char *args_json,
			   char **out);

#endif /* _AI_NET_ADMIN_H */
