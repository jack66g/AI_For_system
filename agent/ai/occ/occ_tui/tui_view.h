/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_view.h - occ TUI 视图框架：布局 + 事件队列 + 30fps 主循环（T9c2）
 *
 * 结构（OCD §1）：竖排会话侧栏（22 列，宽 <60 隐藏）| 主列 =
 * 转写区（tui_chat 双段 scrollbox）/ 元数据行 / 输入框 / 状态行。
 *
 * 线程模型（T9C2-PROGRESS 裁定 2/3）：worker 线程跑 occ_loop_run，
 * sink 回调 → tui_view_post（互斥事件环 + 自唤醒 pipe）→ 主循环
 * drain → 更新 chat 模型 → dirty → 30fps 渲染。主循环 poll(stdin∪pipe)。
 *
 * 中断（裁定 2）：运行中 Esc → hooks->on_interrupt（occ.c 置
 * occ_interrupt_flag + pthread_kill(worker, SIGINT)，复用 b2 通路；
 * 进屏后 SIGINT 处理器覆盖为仅置旗标，见 occ.c on_entered）。
 *
 * 取舍（报告）：OCD 双击 Esc 5s 武装窗口简化为运行中单 Esc 立即中断；
 * 侧栏宽度拖拽归 c3；转写区不回放历史（每进屏从空开始，裁定 12）。
 */
#ifndef OCC_TUI_VIEW_H
#define OCC_TUI_VIEW_H

#include <stddef.h>
#include <stdint.h>

#include "tui_core.h"
#include "tui_keymap.h"
#include "tui_overlay.h"
#include "tui_sidebar.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tui_view tui_view;

/*
 * UXAB A+B：图形化 footer 供数结构（fill_usage 填充；全部字段可零）。
 * 渲染形态：`model │ ▓░ N% │ ↑in ↓out ⟳cr │ cwd`（│ dim、
 * ↑ 绿/↓ 正常/⟳ 紫槽、进度条按 tui_usage_bar 分档+水位着色）。
 * est=1 → 百分比前缀 `~`；fallback=1 → 模型名后缀 `*`
 *（catalog 未命中语义与旧 meta 行一致——进屏 notice 注明口径不变）。
 */
struct tui_footer {
	char model[64];		/* 模型 id（如 glm-5.3） */
	char cwd[160];		/* 尾段目录（空=不渲染尾段） */
	long long in;		/* ↑ input tokens */
	long long out;		/* ↓ output tokens */
	long long cache_read;	/* ⟳ cache read tokens */
	int pct;		/* 上下文占用 %（tui_usage_pct；<0 未知） */
	int est;		/* 1=估算（~ 前缀） */
	int fallback;		/* 1=catalog 未命中（* 后缀） */
};

/*
 * 事件 kind：0..5 与 occ_sink_kind 逐位对齐（occ.c 直接透传 sink 事件，
 * 见 occ_loop.h）；6.. 为 view 本地事件。
 */
enum {
	TUI_VIEW_TEXT = 0,		/* == OCC_SINK_TEXT */
	TUI_VIEW_REASONING = 1,		/* == OCC_SINK_REASONING */
	TUI_VIEW_TOOL_START = 2,	/* == OCC_SINK_TOOL_START */
	TUI_VIEW_TOOL_END = 3,		/* == OCC_SINK_TOOL_END */
	TUI_VIEW_NOTICE = 4,		/* == OCC_SINK_NOTICE */
	TUI_VIEW_RESET = 5,		/* == OCC_SINK_RESET */
	TUI_VIEW_TURN_END = 6,		/* text=footer（可 NULL）；rc=0 正常 */
	/* ---- OCC-DEBT：历史回放（进屏//sessions 切换时 occ.c 投递；主线程
	 * 或 worker 均可 post——与 sink 事件同一队列） ---- */
	TUI_VIEW_HIST_USER = 7,		/* 定稿 user 消息（text） */
	TUI_VIEW_HIST_SEP = 8,		/* 「⋯ 更早 N 条」分隔行（text） */
	TUI_VIEW_HIST_BEGIN = 9,	/* assistant 回放块开始（live 语义） */
	TUI_VIEW_HIST_CLEAR = 10,	/* 清空转写（切会话前旧内容） */
	/* ---- OCC-DEBT：异步结果回投（向导验证 worker → 主循环）；
	 * rc/text 语义由 occ.c 定义（0=成功 1=失败(text=错误) 2=取消） ---- */
	TUI_VIEW_ASYNC_RESULT = 11
};

/* occ.c 提供的钩子（全部主线程调用；on_submit/on_interrupt 例外见注） */
typedef struct {
	void *ud;
	/* 进屏成功后调一次（occ.c 在此覆盖 SIGINT 为仅置旗标处理器） */
	void (*on_entered)(void *ud);
	/* 用户提交非命令文本；0=accepted（worker 已启动），1=busy */
	int (*on_submit)(void *ud, const char *text, size_t len);
	/* 运行中 Esc：置中断旗标 + pthread_kill(worker, SIGINT) */
	void (*on_interrupt)(void *ud);
	/* slash 命令（/exit /clear /help 由 view 内置，不到这）；
	 * 返回 0=已处理，1=未知命令（view 出提示） */
	int (*on_command)(void *ud, const char *line);
	/* 元数据行：写主体 "occ · model · 12.3k/200k"（不含百分比——
	 * view 按返回的 pct 追加 " (N%)" 并按 70 黄/90 红着色；
	 * pct<0=未知则不加后缀）。
	 * UXAB：fill_usage 存在时本钩子不被调用（新图形 footer 取代），
	 * 保留为回落路径（fill_usage==NULL 的嵌入方/旧测试）。 */
	int (*fill_meta)(void *ud, char *buf, size_t cap);
	/* 状态行（idle）：写 "cwd:branch"；返回写入长度。
	 * UXAB：同 fill_meta——fill_usage 存在时不再调用。 */
	int (*fill_status)(void *ud, char *buf, size_t cap);
	/* ---- UXAB A+B：顶栏 + 图形化 footer（结构化供数；任一为 NULL
	 * 则对应元素不渲染并回落旧两行布局——零钩子=完全旧行为） ---- */
	/* 顶栏：title=当前会话标题（空串=无会话，左侧留空）；model=
	 * "glm-5.3 · zhipu" 形式的模型标签（右侧）。NULL=不渲染顶栏行 */
	void (*fill_topbar)(void *ud, char *title, size_t tcap,
			    char *model, size_t mcap);
	/* footer 结构化供数（NULL=回落 fill_meta+fill_status 旧布局） */
	void (*fill_usage)(void *ud, struct tui_footer *out);
	/* 会话侧栏快照（启动/TURN_END/命令后 view 主动拉取） */
	void (*fill_sessions)(void *ud, tui_sb_data *out);
	/* 退屏后、销毁前调（occ.c：中断 + join worker） */
	void (*on_shutdown)(void *ud);
	/* ---- T9c3 覆盖层钩子（全部主线程；occ.c 决策并自行开关 overlay） ---- */
	/* 列表 Enter：idx=原始 items 下标（分组头不可选到）。返回 0=已处理
	 *（occ.c 可关/换内容）；非 0 → view 打状态行「该条目不可用」 */
	int (*on_overlay_submit)(void *ud, int ov_id, int idx);
	/* 输入态 Enter（rename/key/base_url） */
	int (*on_overlay_input)(void *ud, int ov_id, const char *text,
				size_t len);
	/* overlay 专用动作（model.add=ctrl+a / model.favorite=ctrl+f /
	 * model.nonchat=ctrl+t / busy 态 Esc → overlay.cancel）；
	 * idx=当前选择的原始下标（无=-1）；返回 0=已处理，非 0 → 状态行 */
	int (*on_overlay_key)(void *ud, int ov_id, const char *action,
			      int idx);
	/* Esc 关面板（occ 侧清理：向导取消时 key 即刻清零） */
	void (*on_overlay_close)(void *ud, int ov_id);
	/* ---- OCC-DEBT：异步 worker 结果（TUI_VIEW_ASYNC_RESULT 出队时；
	 * rc/text 语义 occ.c 定义——向导验证 0=成功 1=失败 2=取消） ---- */
	void (*on_async_result)(void *ud, int rc, const char *text);
} tui_view_hooks;

/* 创建视图（hooks 各回调可 NULL）。非 tty 的判定在 tui_view_run。 */
tui_view *tui_view_create(const tui_view_hooks *hooks);

/* 进屏 → 主循环 → 退屏。返回 0 正常退出；2=非 tty（stderr 已报人话）；
 * -1=系统错。销毁前会调 hooks->on_shutdown。 */
int tui_view_run(tui_view *v);

void tui_view_destroy(tui_view *v);

/*
 * 事件入队（线程安全；sink 回调线程可直接调）。text/arg 会被拷贝，
 * 调用方可立即释放。kind 见 TUI_VIEW_*；0..5 与 occ_sink_kind 对齐。
 * 返回 0=入队；-1=视图关闭中（事件丢弃）；-2=队列满超时（丢弃计数）。
 */
int tui_view_post(tui_view *v, int kind, const char *text, size_t len,
		  const char *arg, int rc);

/* 请求退出（/exit、ctrl+d 空缓冲等；主线程） */
void tui_view_quit(tui_view *v);

/* 主线程：往转写区推通告行（on_command 响应、/sessions 列表等） */
void tui_view_notice(tui_view *v, const char *text);

/* 被丢弃的事件数（诊断/测试断言） */
unsigned long tui_view_dropped(const tui_view *v);

/* ---- T9c3 覆盖层 API（occ.c 供数/决策；view 管键导航/渲染） ---- */

/* 开列表覆盖层（items 深拷贝；searchable=1 出过滤行）。0=ok */
int tui_view_open_list(tui_view *v, int ov_id, const char *title,
		       const tui_ov_item *items, int n, int searchable,
		       const char *footer);
/* 开输入覆盖层（mask=1 渲染 `*`——key 输入用） */
int tui_view_open_input(tui_view *v, int ov_id, const char *title,
			const char *prompt, const char *initial, int mask);
/* 关闭覆盖层 */
void tui_view_close_overlay(tui_view *v);
/* 框内状态行（向导「验证中…」/错误；msg=NULL 清除） */
void tui_view_overlay_status(tui_view *v, const char *msg, int is_err);
/* 覆盖层是否打开 */
int tui_view_overlay_open(const tui_view *v);
/* 立即渲染一帧（向导阻塞验证前预渲染状态；主线程、run 内调用） */
void tui_view_paint(tui_view *v);
/*
 * OCC-DEBT：busy 态（异步验证中）：①主循环按运行中口径常刷（spinner
 * 动画）；②覆盖层状态行前缀 spinner（tui_overlay_busy）；③覆盖层
 * dialog.close（Esc）不再关面板——改派 on_overlay_key "overlay.cancel"
 * （返回 0=已处理留步可重试；非 0=回落正常关闭）。
 */
void tui_view_set_busy(tui_view *v, int on);

/* B8：主线程拉会话侧栏快照并置脏（异步改名等改数据后的刷新口） */
void tui_view_refresh_sessions(tui_view *v);

/* UXAB：assistant 消息块头标签（`◆ <label> · HH:MM`；缺省 "occ"）。
 * occ.c 在模型解析/切换后设为模型名——每条 assistant 消息随块留档 */
void tui_view_set_assist_label(tui_view *v, const char *label);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_VIEW_H */
