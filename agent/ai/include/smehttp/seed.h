/* SPDX-License-Identifier: GPL-2.0 */
/*
 * seed.h - T7a aikd 种子自导（--import-seed，T7A 口径）
 *
 * 在服务对外监听之前，对已装载引擎做一次差量种子导入（内部直调
 * /export 与 /memories/batch 的路由实现，不走网络回环）。幂等：
 * 现有 text 集合已覆盖种子时不写库。
 */
#ifndef _AIK_SMEHTTP_SEED_H
#define _AIK_SMEHTTP_SEED_H

#include "smehttp/http.h"

/*
 * aik_seed_import - 导入 JSONL 种子
 *
 * path  - sme-seed.jsonl（每行一个 JSON 对象；空行跳过）
 * err   - 失败文案缓冲（可为 NULL，errlen 随之为 0）
 * 返回  0 成功；-1 失败（文件/JSON/路由错误，不静默降级）
 */
int aik_seed_import(aik_http_server *s, const char *path, char *err,
		    size_t errlen);

#endif /* _AIK_SMEHTTP_SEED_H */
