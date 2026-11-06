/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pq_dump.c - T8 差分向量驱动（C 侧）
 *
 * 用法：pq_dump <root> <vector-file>
 * 向量行格式（与 Python 差分 harness 逐字对齐；# 注释/空行忽略）：
 *   BTIME <sec>                          单调→墙钟基准（两例同值）
 *   T <ts_ns> <pid> <tgid> <cpu> <cat> <evt> <sev> <hex|->
 *                                        遥测行（hex=payload 十六进制，
 *                                        -=空 payload）
 *   GEN <n> <base_ts_ns> <cat> <evt> <payload_len>
 *                                        确定性生成 n 行：ts=base+i*1000000,
 *                                        pid=tgid=i%100000, cpu=i%8,
 *                                        sev=i%3, payload[j]=(i+j)&0xff
 *   D <23 字段，决策 schema 列序>         决策行
 *   C <同 D>                             因果链行
 *   FLUSH-T | FLUSH-D | FLUSH-C          触发对应 write_*（清该类缓冲）
 *   SEED ...                             由 harness 处理（驱动忽略）
 * 输出：每次 write 的返回值打印到 stdout（harness 对账用）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "as_parquet.h"

#define MAXROWS	70000

static struct pq_tel_row trows[MAXROWS];
static size_t tn;
static struct pq_dec_row drows[MAXROWS];
static size_t dn;
static struct pq_dec_row crows[MAXROWS];
static size_t cn;
static int64_t btime = -1;

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static uint8_t *hex_decode(const char *s, size_t *outn)
{
	size_t n = strlen(s) / 2;
	uint8_t *b = malloc(n ? n : 1);

	if (!b)
		return NULL;
	for (size_t i = 0; i < n; i++) {
		int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);

		if (hi < 0 || lo < 0) {
			free(b);
			return NULL;
		}
		b[i] = (uint8_t)(hi << 4 | lo);
	}
	*outn = n;
	return b;
}

int main(int argc, char **argv)
{
	FILE *f;
	char line[8192];

	if (argc != 3) {
		fprintf(stderr, "usage: pq_dump <root> <vector-file>\n");
		return 2;
	}
	f = fopen(argv[2], "r");
	if (!f) {
		perror(argv[2]);
		return 2;
	}
	while (fgets(line, sizeof(line), f)) {
		char op[16];

		line[strcspn(line, "\r\n")] = '\0';
		if (line[0] == '#' || line[0] == '\0')
			continue;
		if (sscanf(line, "%15s", op) != 1)
			continue;
		if (strcmp(op, "BTIME") == 0) {
			long long v;

			sscanf(line, "%*s %lld", &v);
			btime = v;
		} else if (strcmp(op, "SEED") == 0) {
			continue;			/* harness 预置，驱动忽略 */
		} else if (strcmp(op, "T") == 0) {
			long long ts, pid, tgid, cpu, cat, evt, sev;
			char hex[4096];

			if (sscanf(line, "%*s %lld %lld %lld %lld %lld %lld %lld %4095s",
				   &ts, &pid, &tgid, &cpu, &cat, &evt, &sev,
				   hex) != 8) {
				fprintf(stderr, "bad T line: %s\n", line);
				return 2;
			}
			{
				uint8_t *pl;
				size_t pln = 0;

				if (strcmp(hex, "-") != 0) {
					pl = hex_decode(hex, &pln);
					if (!pl) {
						fprintf(stderr, "bad hex\n");
						return 2;
					}
				} else {
					pl = malloc(1);
					pln = 0;
				}
				trows[tn].ts_ns = ts;
				trows[tn].pid = (int32_t)pid;
				trows[tn].tgid = (int32_t)tgid;
				trows[tn].cpu = (int16_t)cpu;
				trows[tn].category = (int8_t)cat;
				trows[tn].event_type = (int8_t)evt;
				trows[tn].severity = (int8_t)sev;
				trows[tn].data_len = (int16_t)pln;
				trows[tn].data = pl;	/* 行结束时统一释放 */
				tn++;
				if (tn >= MAXROWS) {
					fprintf(stderr, "too many rows\n");
					return 2;
				}
			}
		} else if (strcmp(op, "GEN") == 0) {
			long long n, base, cat, evt, plen;

			if (sscanf(line, "%*s %lld %lld %lld %lld %lld", &n,
				   &base, &cat, &evt, &plen) != 5 || n < 0 ||
			    plen < 0 || plen > 4096) {
				fprintf(stderr, "bad GEN line: %s\n", line);
				return 2;
			}
			for (long long i = 0; i < n; i++) {
				uint8_t *pl = malloc(plen ? (size_t)plen : 1);

				if (!pl)
					return 2;
				for (long long j = 0; j < plen; j++)
					pl[j] = (uint8_t)((i + j) & 0xff);
				trows[tn].ts_ns = base + i * 1000000;
				trows[tn].pid = (int32_t)(i % 100000);
				trows[tn].tgid = (int32_t)(i % 100000);
				trows[tn].cpu = (int16_t)(i % 8);
				trows[tn].category = (int8_t)cat;
				trows[tn].event_type = (int8_t)evt;
				trows[tn].severity = (int8_t)(i % 3);
				trows[tn].data_len = (int16_t)plen;
				trows[tn].data = pl;
				tn++;
				if (tn >= MAXROWS) {
					fprintf(stderr, "too many rows\n");
					return 2;
				}
			}
		} else if (strcmp(op, "D") == 0 || strcmp(op, "C") == 0) {
			struct pq_dec_row r;
			long long v[23];

			{
				int got = sscanf(line,
					"%*s %lld %lld %lld %lld %lld %lld "
					"%lld %lld %lld %lld %lld %lld %lld "
					"%lld %lld %lld %lld %lld %lld %lld "
					"%lld %lld %lld",
					&v[0], &v[1], &v[2], &v[3], &v[4],
					&v[5], &v[6], &v[7], &v[8], &v[9],
					&v[10], &v[11], &v[12], &v[13],
					&v[14], &v[15], &v[16], &v[17],
					&v[18], &v[19], &v[20], &v[21],
					&v[22]);

				if (got != 23) {
					fprintf(stderr, "bad %s line (%d): %s\n",
						op, got, line);
					return 2;
				}
			}
			memset(&r, 0, sizeof(r));
			r.decision_id = v[0];
			r.trigger_ts = v[1];
			r.trigger_event_id = v[2];
			r.decision_ts = v[3];
			r.decision_type = (int8_t)v[4];
			for (int i = 0; i < 8; i++)
				r.data[i] = v[5 + i];
			r.exec_ts = v[13];
			r.outcome_ts = v[14];
			r.outcome = (int8_t)v[15];
			r.metric_delta = v[16];
			r.model_version = (int32_t)v[17];
			r.confidence = (int8_t)v[18];
			r.domain = (int8_t)v[19];
			r.source = (int8_t)v[20];
			r.executed = (int8_t)v[21];
			r.safety_clamped = (int8_t)v[22];
			if (op[0] == 'D')
				drows[dn++] = r;
			else
				crows[cn++] = r;
		} else if (strcmp(op, "FLUSH-T") == 0) {
			int r = as_pq_write_telemetry(argv[1], trows, tn,
						      btime, 65536, NULL);

			printf("write_telemetry=%d\n", r);
			for (size_t i = 0; i < tn; i++)
				free((void *)trows[i].data);
			tn = 0;
		} else if (strcmp(op, "FLUSH-D") == 0) {
			int r = as_pq_write_decisions(argv[1], drows, dn,
						      btime, NULL);

			printf("write_decisions=%d\n", r);
			dn = 0;
		} else if (strcmp(op, "FLUSH-C") == 0) {
			int r = as_pq_write_chains(argv[1], crows, cn,
						   btime, NULL);

			printf("write_chains=%d\n", r);
			cn = 0;
		} else {
			fprintf(stderr, "unknown directive: %s\n", op);
			return 2;
		}
	}
	fclose(f);
	return 0;
}
