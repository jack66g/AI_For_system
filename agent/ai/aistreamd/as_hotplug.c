/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_hotplug.c - K3d-2 热插拔四级流水线实现（I-9 MVP）
 *
 * 管道：as_hotplug_tap（on_event 首位）→ 分类 → 专用配额 → infer
 * （sysfs 真前向 / 明示 mock / 2s 超时放弃）→ decide（advisory JSONL +
 * think 接口位）→ 落盘（0600 追加）。
 *
 * ###### 红线（C7，三处写死之一--另两处：aistreamd.conf 注释与
 * K3D2-REPORT.md）：本模块只有"建议"，act 级**不存在**--没有任何代码
 * 路径执行设备移除/下线/任何动作；advisory 的 "executed" 字段恒为
 * 字面量 false（hp_record_build 中硬编码，无变量参与）。任何未来自动化
 * 需单独立项过 I 轨登记。######################################
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "as_hotplug.h"
#include "as_util.h"

/* ---- NETLINK_AI sysfs 面（只读对齐 AIKernel/core/ai_sysfs.c） ---- */
#define AS_HP_SYSFS_INFER	"/sys/kernel/ai/model_infer"	/* 0200 写口 */
#define AS_HP_SYSFS_OUT		"/sys/kernel/ai/model_out"	/* 0440 读口 */

/* ---- infer 超时信号（尽力打断卡死的 sysfs 写；耗时判定为准） ---- */
static volatile sig_atomic_t g_hp_alarm;

static void on_hp_alarm(int sig)
{
	(void)sig;
	g_hp_alarm = 1;
}

/* ---- 本地 JSON 字符串转义（语义同 as_sme.c jesc） ---- */
static int jesc(const char *in, char *out, size_t cap)
{
	size_t o = 0;

	if (!in || !out || cap < 2)
		return -1;
	for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
		char tmp[8];

		if (*p == '"' || *p == '\\') {
			tmp[0] = '\\';
			tmp[1] = (char)*p;
			tmp[2] = '\0';
		} else if (*p < 0x20) {
			snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
		} else {
			tmp[0] = (char)*p;
			tmp[1] = '\0';
		}
		{
			size_t l = strlen(tmp);

			if (o + l + 1 >= cap)
				return -1;
			memcpy(out + o, tmp, l);
			o += l;
		}
	}
	out[o] = '\0';
	return 0;
}

/* ====================================================================
 * 1) sense：分类器（纯函数；解析冻结的 as_event 一行文本）
 * ==================================================================== */
static const char *hp_type_name(enum as_hp_type t)
{
	switch (t) {
	case AS_HP_DEV_ADD:	return "device.add";
	case AS_HP_DEV_REMOVE:	return "device.remove";
	case AS_HP_DEV_ONLINE:	return "device.online";
	case AS_HP_DEV_OFFLINE:	return "device.offline";
	case AS_HP_DEV_PROBE:	return "device.probe";
	case AS_HP_DEV_UNPROBE:	return "device.unprobe";
	case AS_HP_CPU_ONLINE:	return "cpu.online";
	case AS_HP_CPU_OFFLINE:	return "cpu.offline";
	case AS_HP_MCE:		return "mce";
	default:		return "?";
	}
}

int as_hp_classify(const struct as_event *ev, struct as_hp_event *out)
{
	int iuev = as_stream_idx(AS_STREAM_UEVENT);
	int iaie = as_stream_idx(AS_STREAM_EVENT);

	if (!ev || !out)
		return 1;
	memset(out, 0, sizeof(*out));
	out->cpu = -1;
	out->bank = -1;

	/* 来源一：uevent（KOBJECT_UEVENT，L1 真流）。热插拔 action 进，
	 * change/bind/unbind/move 等状态类不进（MVP 边界：add/remove/
	 * online/offline 即设备插入/移除/上线/下线；change 每次挂载环设备
	 * 都发，噪音大且非拓扑变化--如实记入报告取舍）。 */
	if (ev->stream_idx == iuev) {
		char dev[400] = "", subsys[64] = "";
		enum as_hp_type t = AS_HP_NONE;

		if (strcmp(ev->category, "add") == 0)
			t = AS_HP_DEV_ADD;
		else if (strcmp(ev->category, "remove") == 0)
			t = AS_HP_DEV_REMOVE;
		else if (strcmp(ev->category, "online") == 0)
			t = AS_HP_DEV_ONLINE;
		else if (strcmp(ev->category, "offline") == 0)
			t = AS_HP_DEV_OFFLINE;
		if (t == AS_HP_NONE)
			return 1;
		/* 行格式冻结（as_event_uevent）：
		 * "[kern] uevent <action> dev=<path> subsystem=<name>" */
		if (sscanf(ev->line, "[kern] uevent %*s dev=%399s subsystem=%63s",
			   dev, subsys) != 2)
			return 1;	/* 防御：不合形态不进 */
		out->type = t;
		out->source = "uevent";
		snprintf(out->dev, sizeof(out->dev), "%s", dev);
		snprintf(out->subsystem, sizeof(out->subsystem), "%s", subsys);
		out->ts_real_ms = ev->ts_real_ms;
		snprintf(out->payload_digest, sizeof(out->payload_digest), "%s",
			 ev->digest_hex);
		return 0;
	}

	/* 来源二：NETLINK_AI EVENT（L1 经 K3c mock 通道注入，qemu 真内核
	 * 收口）。category 3/4/5 = AS_AI_NL_EV_*（uapi 追加空间预留契约）。
	 * category 1/2（policy/model）是 K3c 记忆路，不进本流水线。 */
	if (ev->stream_idx == iaie) {
		if (strcmp(ev->category, "device") == 0) {
			/* "[kern] event device action=probe dev=<name>" */
			char act[16] = "", dev[128] = "";

			if (sscanf(ev->line,
				   "[kern] event device action=%15s dev=%127s",
				   act, dev) != 2)
				return 1;
			out->type = strcmp(act, "remove") == 0 ?
				    AS_HP_DEV_UNPROBE : AS_HP_DEV_PROBE;
			out->source = "ai-netlink";
			snprintf(out->dev, sizeof(out->dev), "%s", dev);
			out->ts_real_ms = ev->ts_real_ms;
			snprintf(out->payload_digest,
				 sizeof(out->payload_digest), "%s",
				 ev->digest_hex);
			return 0;
		}
		if (strcmp(ev->category, "cpuhp") == 0) {
			/* "[kern] event cpuhp cpu=<n> online=<0|1>" */
			int cpu = -1, online = 0;

			if (sscanf(ev->line,
				   "[kern] event cpuhp cpu=%d online=%d",
				   &cpu, &online) != 2)
				return 1;
			out->type = online ? AS_HP_CPU_ONLINE : AS_HP_CPU_OFFLINE;
			out->source = "ai-netlink";
			out->cpu = cpu;
			out->ts_real_ms = ev->ts_real_ms;
			snprintf(out->payload_digest,
				 sizeof(out->payload_digest), "%s",
				 ev->digest_hex);
			return 0;
		}
		if (strcmp(ev->category, "mce") == 0) {
			/* "[kern] event mce cpu=<n> bank=<n>" */
			int cpu = -1, bank = -1;

			if (sscanf(ev->line, "[kern] event mce cpu=%d bank=%d",
				   &cpu, &bank) != 2)
				return 1;
			out->type = AS_HP_MCE;
			out->source = "ai-netlink";
			out->cpu = cpu;
			out->bank = bank;
			out->ts_real_ms = ev->ts_real_ms;
			snprintf(out->payload_digest,
				 sizeof(out->payload_digest), "%s",
				 ev->digest_hex);
			return 0;
		}
	}
	return 1;	/* proc/net/nflog/taskstats/policy/model 等一律不进 */
}

/* ====================================================================
 * 2) infer：sysfs 真前向 / 明示 mock / 2s 超时放弃
 * ==================================================================== */

/* 特征向量（确定性公式，冻结--qemu 真 model 训练/校验的输入契约）：
 *   f[0]   = <as_hp_type 枚举值> / 10.0
 *   f[i>=1] = (int8_t)(payload FNV digest 的第 ((i-1)%8) 字节) / 128.0
 * 维度 = conf HOTPLUG_INFER_DIM；float32 小端 → hex（ai_sysfs 契约）。 */
static void hp_features(char *hex, size_t cap, const struct as_hp_event *h,
			int dim)
{
	uint64_t d = 0;
	size_t o = 0;

	/* digest hex → u64（classify 存的是 16 hex 字符） */
	for (int i = 0; i < 16 && h->payload_digest[i]; i++) {
		int v = h->payload_digest[i] >= 'a' ?
			h->payload_digest[i] - 'a' + 10 :
			h->payload_digest[i] - '0';

		d = (d << 4) | (uint64_t)(v & 0xf);
	}
	hex[0] = '\0';
	for (int i = 0; i < dim && o + 9 < cap; i++) {
		float f;
		uint32_t bits;
		union {
			uint32_t u;
			uint8_t b[4];
		} le;

		if (i == 0)
			f = (float)h->type / 10.0f;
		else
			f = (float)(int8_t)(d >> (unsigned)(((i - 1) % 8) * 8)) /
			    128.0f;
		memcpy(&bits, &f, 4);
		le.u = bits;	/* 小端序字节（x86/ARM LE 主流；异序环境重编即可） */
		o += (size_t)snprintf(hex + o, cap - o, "%02x%02x%02x%02x",
				      le.b[0], le.b[1], le.b[2], le.b[3]);
	}
}

/* 写 model_infer + 读 model_out（K3b 核对契约：写 "name hex..."）。
 * 返回 0 成功（out_hex 收到 model_out 的 hex 子串）；-1 失败。 */
static int hp_sysfs_infer(const char *model, const char *in_hex,
			  char *out_hex, size_t outcap)
{
	char wbuf[4352];	/* 名 64 + 空格 + 64 维*8 hex + NUL */
	char rbuf[8192];
	int fd, n;
	char model_out[80];
	size_t out_len;

	n = snprintf(wbuf, sizeof(wbuf), "%s %s", model, in_hex);
	if (n <= 0 || (size_t)n >= sizeof(wbuf))
		return -1;
	fd = open(AS_HP_SYSFS_INFER, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (write(fd, wbuf, (size_t)n) != n) {
		close(fd);
		return -1;
	}
	close(fd);

	fd = open(AS_HP_SYSFS_OUT, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = (int)read(fd, rbuf, sizeof(rbuf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	rbuf[n] = '\0';
	/* "model=%s out_len=%zu hex=%02x...\n" */
	{
		char hexfmt[16];

		out_len = 0;
		if (sscanf(rbuf, "model=%79s out_len=%zu hex=",
			   model_out, &out_len) != 2)
			return -1;
		(void)out_len;
		snprintf(hexfmt, sizeof(hexfmt), "%%%zus", outcap - 1);
		{
			const char *hx = strstr(rbuf, "hex=");

			if (!hx)
				return -1;
			if (sscanf(hx + 4, hexfmt, out_hex) != 1)
				return -1;
		}
	}
	return 0;
}

static void hp_infer(struct as_hotplug *hp, const struct as_hp_event *h,
		     struct as_hp_infer *ir)
{
	long long t0, t1;
	char in_hex[528];

	memset(ir, 0, sizeof(*ir));
	ir->status = "skipped_unconfigured";
	ir->out_digest[0] = '\0';

	if (!hp->conf->hotplug_model[0]) {
		hp->stats->hp.infer_skipped++;
		return;		/* 模型未配：流水线其余照走（规格 #2） */
	}

	hp_features(in_hex, sizeof(in_hex), h, (int)hp->conf->hotplug_infer_dim);

	t0 = as_now_mono_ns();
	if (hp->sysfs_present) {
		char out_hex[4200];

		/* 真内核面：setitimer 尽力打断卡死写；耗时判定为准 */
		struct itimerval it = {
			.it_value = { .tv_sec = hp->infer_timeout_ms / 1000,
				      .tv_usec = (hp->infer_timeout_ms % 1000) *
						 1000 },
		};
		int rc;

		g_hp_alarm = 0;
		setitimer(ITIMER_REAL, &it, NULL);
		rc = hp_sysfs_infer(hp->conf->hotplug_model, in_hex,
				    out_hex, sizeof(out_hex));
		memset(&it, 0, sizeof(it));
		setitimer(ITIMER_REAL, &it, NULL);
		t1 = as_now_mono_ns();
		ir->latency_ns = t1 - t0;
		if (t1 - t0 > hp->infer_timeout_ms * 1000000LL)
			goto timeout;	/* >2s：放弃该事件（含被 alarm 打断） */
		if (rc == 0) {
			/* 输出向量 digest = FNV-1a64(hex 解码字节) */
			uint8_t raw[2048];
			size_t n = 0;

			for (const char *p = out_hex; p[0] && p[1] && n < sizeof(raw); p += 2) {
				int hi = p[0] <= '9' ? p[0] - '0' : p[0] - 'a' + 10;
				int lo = p[1] <= '9' ? p[1] - '0' : p[1] - 'a' + 10;

				if (hi < 0 || lo < 0)
					break;
				raw[n++] = (uint8_t)((hi << 4) | lo);
			}
			as_digest_hex(as_fnv1a64((const char *)raw, n),
				      ir->out_digest);
			ir->ok = 1;
			ir->status = "ok";
			return;
		}
		ir->status = "error";	/* 真 sysfs 失败（EACCES 等）如实记 */
		return;
	}

	/* 无内核面（L1）：明示 mock（journal TEST ONLY）或诚实 skipped */
	if (!hp->conf->hotplug_infer_mock) {
		ir->status = "skipped_noiface";
		hp->stats->hp.infer_skipped++;
		return;
	}
	/* 确定性 mock 前向：out[i] = in[i]*0.5 + 0.25（同维）；
	 * TEST ONLY hook：test_sleep_ms 注入延迟走超时路径（单测） */
	if (hp->test_sleep_ms > 0)
		usleep((useconds_t)hp->test_sleep_ms * 1000);
	{
		uint64_t d = as_fnv1a64(in_hex, strlen(in_hex));

		as_digest_hex(d, ir->out_digest);
	}
	t1 = as_now_mono_ns();
	ir->latency_ns = t1 - t0;
	if (t1 - t0 > hp->infer_timeout_ms * 1000000LL)
		goto timeout;
	ir->ok = 1;
	ir->status = "mock";
	as_warn_ratelimit("hp-mock-infer", 60000,
			  "hotplug infer: MOCK forward (TEST ONLY - "
			  "no %s)", AS_HP_SYSFS_INFER);
	return;

timeout:
	ir->ok = 0;
	ir->status = "timeout";
	ir->out_digest[0] = '\0';
	hp->stats->hp.infer_timeout++;
}

/* ====================================================================
 * 3) decide：advisory JSONL（固定字段序冻结）+ think 接口位
 * ==================================================================== */

/* 建议映射（确定性、保守；action_knob 只引用既有 ACT 旋钮名或 "none"） */
static void hp_suggest(const struct as_hp_event *h, const char **knob,
		       const char **why)
{
	switch (h->type) {
	case AS_HP_DEV_ADD:
		*knob = "none";
		*why = "device registered - observe and baseline its IO/latency; "
		       "advisory mode (I-9 MVP), no automation";
		break;
	case AS_HP_DEV_PROBE:
		*knob = "none";
		*why = "driver probe completed - observe; advisory mode, "
		       "no automation";
		break;
	case AS_HP_DEV_REMOVE:
	case AS_HP_DEV_OFFLINE:
	case AS_HP_DEV_UNPROBE:
		*knob = "none";
		*why = "C7 RED LINE: device removal/offline actions are NEVER "
		       "auto-executed; human review required (advisory only)";
		break;
	case AS_HP_DEV_ONLINE:
		*knob = "none";
		*why = "device onlined - observe; advisory only";
		break;
	case AS_HP_CPU_ONLINE:
		*knob = "sched.affinity";
		*why = "cpu online: consider rebalancing task affinity across "
		       "the new topology - suggestion only, never executed";
		break;
	case AS_HP_CPU_OFFLINE:
		*knob = "sched.affinity";
		*why = "cpu offline: verify no task affinity is pinned to the "
		       "offline cpu - suggestion only, never executed "
		       "(offline is C7 red line, never automated)";
		break;
	case AS_HP_MCE:
		*knob = "none";
		*why = "hardware memory error: consider offline checks on the "
		       "affected page/cpu - advisory only, never executed";
		break;
	default:
		*knob = "none";
		*why = "unknown hotplug event - advisory only";
		break;
	}
}

unsigned long long as_hp_think(const struct as_hotplug *hp,
			       const struct as_hp_event *h,
			       const struct as_hp_infer *ir)
{
	/* 接口位（qemu 收口轮接真 /sys/kernel/ai/policy/think）：
	 *   write(think, "<event_id>,<domain>,<type>,<value>") →
	 *   decision_id 从 /proc/ai/decisions 尾条或 EVENT policy 推送回读。
	 * MVP 恒返回 0（advisory.decision_id=null）且绝不写 think sysfs。 */
	(void)hp; (void)h; (void)ir;
	return 0;
}

int as_hp_record_build(const struct as_hp_event *h, const struct as_hp_infer *ir,
		       const char *model, unsigned long long decision_id,
		       char *buf, size_t cap)
{
	char dev[808], subsys[128], mdl[128];
	const char *knob, *why;
	int n;

	if (jesc(h->dev, dev, sizeof(dev)) != 0)
		snprintf(dev, sizeof(dev), "?");
	if (jesc(h->subsystem, subsys, sizeof(subsys)) != 0)
		subsys[0] = '\0';
	if (jesc(model ? model : "", mdl, sizeof(mdl)) != 0)
		mdl[0] = '\0';
	hp_suggest(h, &knob, &why);

	n = snprintf(buf, cap, "{\"ts\":%lld,\"event\":{\"type\":\"%s\","
		     "\"source\":\"%s\"", h->ts_real_ms, hp_type_name(h->type),
		     h->source);
	if (n < 0 || (size_t)n >= cap)
		return -1;
	/* event 对象字段按类型冻结：device 类 dev(+subsystem|drv)；cpu 类
	 * cpu；mce 类 cpu+bank */
	if (h->type >= AS_HP_DEV_ADD && h->type <= AS_HP_DEV_UNPROBE) {
		n += snprintf(buf + n, cap - (size_t)n, ",\"dev\":\"%s\"",
			      dev);
		if (h->source[0] == 'u')	/* uevent → subsystem */
			n += snprintf(buf + n, cap - (size_t)n,
				      ",\"subsystem\":\"%s\"", subsys);
		else if (subsys[0])			/* ai-netlink → drv */
			n += snprintf(buf + n, cap - (size_t)n,
				      ",\"drv\":\"%s\"", subsys);
	} else if (h->type == AS_HP_MCE) {
		n += snprintf(buf + n, cap - (size_t)n, ",\"cpu\":%d,\"bank\":%d",
			      h->cpu, h->bank);
	} else {
		n += snprintf(buf + n, cap - (size_t)n, ",\"cpu\":%d", h->cpu);
	}
	if (n < 0 || (size_t)n >= cap)
		return -1;
	n += snprintf(buf + n, cap - (size_t)n,
		      ",\"payload_digest\":\"%s\"},\"infer\":{\"model\":\"%s\","
		      "\"status\":\"%s\",\"out_digest\":\"%s\",\"latency_ns\":%lld},"
		      "\"suggestion\":{\"action_knob\":\"%s\",\"rationale\":\"%s\"},"
		      "\"executed\":false,\"decision_id\":",
		      h->payload_digest, mdl, ir->status,
		      ir->out_digest[0] ? ir->out_digest : "",
		      ir->latency_ns, knob, why);
	if (n < 0 || (size_t)n >= cap)
		return -1;
	/* decision_id：think 闭环未接（MVP）→ null；接通后为数字 */
	if (decision_id)
		n += snprintf(buf + n, cap - (size_t)n, "%llu}\n", decision_id);
	else
		n += snprintf(buf + n, cap - (size_t)n, "null}\n");
	if (n < 0 || (size_t)n >= cap)
		return -1;
	return n;
}

/* ====================================================================
 * 4) 落盘（0600 追加；父目录不存在则创建 0700）
 *    （act 级不存在--见文件头红线；这里只写建议记录本身）
 * ==================================================================== */
static int hp_open_log(struct as_hotplug *hp)
{
	char dir[256];
	char *slash;
	struct stat st;

	if (hp->log_fd >= 0)
		return 0;
	/* 单层父目录创建（规格路径 /var/log/aikernel 一层足够；深路径由
	 * 管理员预建--如实记录） */
	snprintf(dir, sizeof(dir), "%s", hp->conf->hotplug_log);
	slash = strrchr(dir, '/');
	if (slash && slash != dir) {
		*slash = '\0';
		if (mkdir(dir, 0700) == 0)
			chmod(dir, 0700);
		else if (errno != EEXIST) {
			as_warn_ratelimit("hp-log", 60000,
					  "hotplug log mkdir %s: %s - advisories "
					  "NOT persisted", dir, strerror(errno));
			return -1;
		}
	}
	hp->log_fd = open(hp->conf->hotplug_log,
			  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (hp->log_fd < 0) {
		as_warn_ratelimit("hp-log", 60000,
				  "hotplug log open %s: %s - advisories NOT "
				  "persisted", hp->conf->hotplug_log,
				  strerror(errno));
		return -1;
	}
	/* 强制 0600（open 受 umask 影响只会更严，显式钉死供验收 stat） */
	fchmod(hp->log_fd, 0600);
	if (fstat(hp->log_fd, &st) == 0 && st.st_size == 0)
		as_log("hotplug advisory log created: %s (0600)",
		       hp->conf->hotplug_log);
	return 0;
}

static void hp_write_record(struct as_hotplug *hp, const struct as_hp_event *h,
			    const struct as_hp_infer *ir)
{
	char line[AS_HP_LINE_MAX];
	int n = as_hp_record_build(h, ir, hp->conf->hotplug_model,
				   as_hp_think(hp, h, ir), line,
				   sizeof(line));

	if (n <= 0) {
		as_warn_ratelimit("hp-record", 60000,
				  "advisory record build overflow (type=%d) - "
				  "dropped", h->type);
		return;
	}
	if (hp_open_log(hp) != 0)
		return;
	if (write(hp->log_fd, line, (size_t)n) != n) {
		as_warn_ratelimit("hp-log", 60000,
				  "hotplug log write: %s - advisory lost",
				  strerror(errno));
		return;
	}
	hp->stats->hp.advisory_written++;
}

/* ====================================================================
 * 生命周期与管道主入口
 * ==================================================================== */
int as_hotplug_init(struct as_hotplug *hp, struct as_conf *c,
		    struct as_stats *st)
{
	memset(hp, 0, sizeof(*hp));
	hp->conf = c;
	hp->stats = st;
	hp->log_fd = -1;
	hp->infer_timeout_ms = AS_HP_INFER_TIMEOUT_MS;
	hp->sysfs_present = access(AS_HP_SYSFS_INFER, W_OK) == 0;
	st->hp.enabled = c->hotplug_enabled ? 1 : 0;

	if (!c->hotplug_enabled) {
		as_log("hotplug pipeline: disabled (HOTPLUG_ENABLED=0) - "
		       "zero-overhead tap");
		return 0;
	}
	/* SIGALRM：infer 超时尽力打断（enabled 才装；handler 只置标志） */
	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_hp_alarm;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGALRM, &sa, NULL);
	}
	if (as_quota_init(&hp->quota, c->rate_per_min, c->hotplug_daily_max,
			  c->hotplug_daily_max) != 0)
		return -1;
	hp_open_log(hp);	/* 提前暴露路径问题；失败=降级不致命 */
	as_log("hotplug pipeline: enabled (model=%s dim=%lld daily_max=%lld "
	       "infer=%s%s) - ADVISORY ONLY, executed is always false (C7)",
	       c->hotplug_model[0] ? c->hotplug_model : "<unconfigured>",
	       c->hotplug_infer_dim, c->hotplug_daily_max,
	       hp->sysfs_present ? "sysfs" : "no-sysfs",
	       !hp->sysfs_present && c->hotplug_infer_mock ?
	       " + MOCK (TEST ONLY)" : "");
	if (!hp->sysfs_present)
		as_warn_ratelimit("hp-noiface", 3600000,
				  "%s not writable: model_infer via %s",
				  AS_HP_SYSFS_INFER,
				  c->hotplug_infer_mock ?
				  "MOCK forward (TEST ONLY)" :
				  "skipped_noiface");
	return 0;
}

void as_hotplug_close(struct as_hotplug *hp)
{
	if (hp->log_fd >= 0) {
		fsync(hp->log_fd);
		close(hp->log_fd);
		hp->log_fd = -1;
	}
	as_quota_free(&hp->quota);
}

void as_hotplug_tap(struct as_hotplug *hp, const struct as_event *ev)
{
	struct as_hp_event hpe;
	struct as_hp_infer ir;
	enum as_quota_verdict v;

	if (!hp || !hp->conf->hotplug_enabled)
		return;			/* A 侧（enabled=0）零开销 */
	if (as_hp_classify(ev, &hpe) != 0)
		return;			/* 无关事件不进（多数事件在此返回） */
	hp->stats->hp.seen++;

	/* 配额先行（防 infer 洪泛：超限事件不做模型调用）；复用既有配额器
	 * （专用实例：rate=RATE_PER_MIN，日限=每源路日限=HOTPLUG_DAILY_MAX） */
	v = as_quota_check(&hp->quota, ev->stream_idx, ev->ts_real_ms);
	if (v != AS_Q_ALLOW) {
		hp->stats->hp.dropped_noquota++;
		as_warn_ratelimit("hp-quota", 60000,
				  "hotplug advisory quota drop: %s "
				  "(dropped=%lld)",
				  as_quota_reason(v),
				  hp->stats->hp.dropped_noquota);
		return;
	}
	as_quota_commit(&hp->quota, ev->stream_idx, ev->ts_real_ms);

	hp_infer(hp, &hpe, &ir);
	if (strcmp(ir.status, "timeout") == 0)
		return;			/* >2s：放弃该事件（已计 infer_timeout） */
	if (ir.ok)
		hp->stats->hp.infer_ok++;

	hp_write_record(hp, &hpe, &ir);
}
