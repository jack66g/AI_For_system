/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dtcore.h - T6b desktop C 化共享基础:路径配置/冻结时钟/定序随机/
 * 日志/锁粒度/UTF-8 与 Python 语义工具/文件 IO/MD5+SHA256。
 *
 * 语义对齐 desktop/server.py(参考 2,172 行):
 *   - AIK_DESKTOP_* env 契约同名同语义;AIK_DESKTOP_BASE 为 C 侧新增
 *     (参考树 BASE_DIR=server.py 所在目录,C 二进制不在该树,重放器用它
 *     指向录制同构的 BASE 树;不影响参考侧行为);
 *   - 冻结旗标 --frozen-now/--frozen-random 与 T6a 录制 shim 等价:
 *     time()=epoch(整数语义,time.time() 在 shim 下返回 int)、
 *     time_ns()=epoch*1e9+第n次*1e6、random() 定序循环、strftime 走
 *     TZ 环境 + 冻结时刻。
 */
#ifndef _AIK_DESKTOP_DTCORE_H
#define _AIK_DESKTOP_DTCORE_H

#include <pthread.h>
#include <stddef.h>
#include <sys/types.h>

#include "store/store_json.h"

#define DT_PATH_MAX 4096
/* 配置路径字段留足 snprintf 拼接余量(防 format-truncation) */
#define DT_CFG_PATH 8192

/* ---------------------------------------------------------------- 配置 */

struct dt_cfg {
	char base_dir[DT_CFG_PATH];
	char static_dir[DT_CFG_PATH];
	char state_root[DT_CFG_PATH];
	char theme_file[DT_CFG_PATH];
	char theme_seed[DT_CFG_PATH];
	char locale_file[DT_CFG_PATH];
	char wallpaper_dir[DT_CFG_PATH];
	char chat_dir[DT_CFG_PATH];
	char pin_file[DT_CFG_PATH];
	char notif_file[DT_CFG_PATH];
	char desktop_file[DT_CFG_PATH];
	char screenshot_dir[DT_CFG_PATH];
	char icon_root[DT_CFG_PATH];
	char icon_out_dir[DT_CFG_PATH];
	char gen_icon_dir[DT_CFG_PATH];
	char catalog_file[DT_CFG_PATH];
	char seed_notifs[DT_CFG_PATH];
	char seed_desktop[DT_CFG_PATH];
	char seed_pin[DT_CFG_PATH];
	char model_toml[DT_CFG_PATH];
	char vm_conf[DT_CFG_PATH];
	char apps_dir[DT_CFG_PATH];
	int port;
	char bind_host[64];
	int vm_enabled;
	char screenshot_mode[64];
	char start_ts[32];
	char version[32];
};

extern struct dt_cfg g_cfg;

/* env 校验(失败时按参考语义向 stderr 写中文报错并退出 rc=1) */
void dt_env_port_or_die(void);
void dt_env_bind_or_die(void);
/* 校验通过后计算全部路径(BASE_DIR/STATIC_DIR/STATE_ROOT/...) */
int dt_paths_init(void);

/* 锁粒度:desktop/theme/chat/apps/zh/screenshot/vm/log 八把 + stats 一把;
 * 锁序 _DESKTOP_LOCK→_THEME_LOCK(/api/windows、/api/apps/launch 内嵌) */
extern pthread_mutex_t g_lock_desktop;
extern pthread_mutex_t g_lock_theme;
extern pthread_mutex_t g_lock_chat;
extern pthread_mutex_t g_lock_apps;
extern pthread_mutex_t g_lock_zh;
extern pthread_mutex_t g_lock_screenshot;
extern pthread_mutex_t g_lock_vm;
extern pthread_mutex_t g_lock_log;
extern pthread_mutex_t g_lock_stats;

/* ---------------------------------------------------------------- 时钟 */

void dt_freeze_set(long long epoch, int frozen_random);
int dt_frozen(void);
long long dt_time(void);          /* time.time():冻结时为 int 语义 epoch */
long long dt_time_ns(void);       /* epoch*1e9 + 第n次*1e6(冻结时) */
size_t dt_strftime(char *buf, size_t cap, const char *fmt); /* 本地时区 */

/* ---------------------------------------------------------------- 随机 */

/* random.random():--frozen-random 时按定序序列循环,否则真随机 */
double dt_random(void);

/* ---------------------------------------------------------------- 日志 */

void dt_log(const char *fmt, ...);

/* ---------------------------------------------------------------- sbuf */

struct dt_sbuf {
	char *p;
	size_t n;
	size_t cap;
	int bad;
};

void dt_sb_init(struct dt_sbuf *b);
void dt_sb_putc(struct dt_sbuf *b, char c);
void dt_sb_puts(struct dt_sbuf *b, const char *s, size_t n);
void dt_sb_putstr(struct dt_sbuf *b, const char *s);
int dt_sb_printf(struct dt_sbuf *b, const char *fmt, ...);
char *dt_sb_finish(struct dt_sbuf *b);   /* NUL 结尾,所有权转移 */

/* ---------------------------------------------------------------- UTF-8 */

/* Python len(str) = 码点数 */
size_t dt_utf8_cplen(const char *s, size_t bytes);
/* 第 cp 个码点起始字节偏移(cp 超界返回 bytes) */
size_t dt_cp_offset(const char *s, size_t bytes, size_t cp);
/* 截前 n 个码点(返回 malloc 串) */
char *dt_utf8_head(const char *s, size_t n);
/* 取末 n 个码点(返回 malloc 串) */
char *dt_utf8_tail(const char *s, size_t n);
/* 删除末尾 1 个码点后的新串 */
char *dt_utf8_chop_last(const char *s);

/* ---------------------------------------------------------------- 值语义 */

/* Python truthiness:null/false/0/0.0/""/[]/{} → 0 */
int dt_truthy(const aik_json *v);
/* Python str(v)(含容器 repr;STR/INT/NUM/BOOL/NULL/ARR/OBJ) */
char *dt_pystr(const aik_json *v);
/* Python str.strip()(ASCII 空白 + \x1c-\x1f;返回 malloc 串) */
char *dt_strip(const char *s);

/* ---------------------------------------------------------------- 文件 */

char *dt_read_file(const char *path, size_t *out_len);
int dt_write_file(const char *path, const void *buf, size_t n); /* 直写 */
int dt_mkdir_p(const char *path, int mode);
int dt_mkdir_if_absent(const char *path, int mode);
void dt_chmod600(const char *path);
/* 安全路径拼接(手工定长拼接,GCC 最坏情况不受格式化告警影响) */
void dt_path_join(char *out, size_t cap, const char *a, const char *b);
/* join(root, rel) 后 POSIX normpath(词法归一,不解析符号链接) */
void dt_normpath_join(char *out, size_t cap, const char *root,
		      const char *rel);
/* os.path.abspath 等价(相对路径补 cwd 后 normpath) */
void dt_abspath(char *out, size_t cap, const char *in);
/* urllib.parse.unquote(%XX 解码;非法序列原样保留) */
char *dt_unquote(const char *s);
int dt_is_file(const char *path);
int dt_is_dir(const char *path);

/* ---------------------------------------------------------------- 哈希 */

void dt_md5_hex(const void *data, size_t n, char out[33]);
void dt_sha256_hex(const void *data, size_t n, char out[65]);

/* ---------------------------------------------------------------- 杂项 */

int dt_regex_session(const char *sid);   /* ^[A-Za-z0-9_-]{1,64}$($ 尾\n 宽容) */
int dt_regex_win_id(const char *wid);    /* ^w-[0-9]{4,10}$ */
int dt_regex_app_id(const char *aid);    /* ^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$ */
int dt_regex_hex6(const char *hex);      /* ^#[0-9a-fA-F]{6}$ */
int dt_regex_pin(const char *pin);       /* ^\d{4,8}$ */

#endif /* _AIK_DESKTOP_DTCORE_H */
