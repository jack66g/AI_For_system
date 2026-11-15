/* SPDX-License: GPL-2.0 */
/*
 * aip_table.c — aipd 静态阈值表（**生成器产物，勿手改**；
 * gen_aip_table.py --check 冻结漂移检）。
 *
 * 源 spec: table_spec.json sha256=af253878682d36d541f27a964ba01cd4bdf3797fdd149dfe18a35b82e38690eb
 * 契约:   aip_model.h（struct ai_rule/枚举）+ aip_table.h
 * 序列化: 128B/条 <IIQqII + reason[96] NUL 填充
 * 摘要:   sha256(规则串连，无头) = AIP_TABLE_SHA256（自校验）
 * M1 影子语义: 只产影子记录，无任何 ACT 下发路径。
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>	/* ssize_t（aip_table.h 声明依赖） */

#include "aip_model.h"
#include "aip_table.h"

const size_t aip_nrules = 3;
const uint32_t aip_table_ver = AIP_TABLE_VER;

const struct ai_rule aip_rules[AIP_RULES_MAX] = {
	{ AIP_F_PSI_MEM_SOME, AIP_OP_GT,
	  409, 0,
	  AIP_ACT_RECLAIM_AGGRESSIVE, 100,
	  "psi_mem_some>409 (~20%): \xe5\xbb\xba\xe8\xae\xae\xe6\x8f\x90\xe5\x8d\x87 reclaim \xe6\xbf\x80\xe8\xbf\x9b\xe5\xba\xa6" },
	{ AIP_F_LAT_EWMA_NS, AIP_OP_GT,
	  10000000, 0,
	  AIP_ACT_SCHED_COMPENSATE, 10,
	  "lat_ewma_ns>10000000 (10ms): \xe5\xbb\xba\xe8\xae\xae\xe8\xb0\x83\xe5\xba\xa6\xe8\xa1\xa5\xe5\x81\xbf" },
	{ AIP_F_IOWAIT_PCT, AIP_OP_GT,
	  20, 0,
	  AIP_ACT_READAHEAD_BOOST, 512,
	  "iowait_pct>20: \xe5\xbb\xba\xe8\xae\xae readahead \xe6\x8f\x90\xe5\x8d\x87" },
};

/* sha256(序列化规则串)——aip_table_check 自校验常量 */
const char aip_table_sha256[] = "5810d14ade4ad08b94ed7843b36a006c3f632c48236245d336faff9f61ddeb8d";
