/*
 * im_proto.h — fbterm 1.7 IM 协议定义（自含副本）
 *
 * 源=fbterm-1.7/src/immessage.h（GPL，Debian orig tarball）。AIKernel
 * client 自含一份避免依赖 fbterm 源树；**ABI 必须与 fbterm 侧逐字节
 * 一致**（type/len 头 + union，SetWin 的 len==sizeof(ImMsg) 是 fbterm
 * 侧 v1.5 兼容闸，improxy.cpp readyRead()）。
 */
#ifndef AIK_IM_PROTO_H
#define AIK_IM_PROTO_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
	IM_CONNECT = 0, IM_DISCONNECT,
	IM_ACTIVE, IM_DEACTIVE,
	IM_SENDKEY, IM_PUTTEXT,
	IM_SETWIN, IM_ACKWIN,
	IM_CURSORPOS, IM_FBTERMINFO, IM_TERMMODE,
	IM_SHOWUI, IM_HIDEUI, IM_ACKHIDEUI,
	IM_FILLRECT, IM_DRAWTEXT,
	IM_PING, IM_ACKPING
} ImType;

typedef struct {
	unsigned x, y;
	unsigned w, h;
} ImRect;

typedef struct {
	unsigned fontHeight, fontWidth;
	unsigned screenHeight, screenWidth;
} ImInfo;

#define IM_NR_WINS 10

typedef struct {
	uint16_t type;  /* ImType */
	uint16_t len;   /* 消息全长=头+体（含 len 自身） */
	union {
		char keys[0];    /* IM_SENDKEY：raw=0 时=K_UNICODE 翻译后的 UTF-8 字节流（含 CSI 序列） */
		char texts[0];   /* IM_PUTTEXT / IM_DRAWTEXT：UTF-8 */
		char raw;        /* IM_CONNECT：1=要 K_MEDIUMRAW scancode；aik-ime 用 0 */
		uint32_t winid;  /* IM_SHOWUI */
		ImInfo info;     /* IM_FBTERMINFO：像素单位 */
		struct { ImRect rect; uint32_t winid; } win; /* IM_SETWIN：rect 像素；空 rect=收窗 */
		struct { char crWithLf; char applicKeypad; char cursorEscO; } term; /* IM_TERMMODE */
		struct { uint32_t x, y; } cursor; /* IM_CURSORPOS：像素 */
		struct { ImRect rect; uint8_t color; } fillRect; /* color=256 调色板索引 */
		struct { uint32_t x, y; uint8_t fc, bc; char texts[0]; } drawText; /* x,y 像素；fc/bc 调色板索引 */
	};
} ImMsg;

/* 与 fbterm 侧 OFFSET() 同源；drawText.texts 紧跟 fc/bc 后（无 padding） */
#define IM_OFF(m) ((size_t)&((ImMsg *)0)->m)
#define IM_HDR_LEN IM_OFF(keys) /* =4 */

/* fbterm 侧 fixed-size 消息全部 len=sizeof(Message)；drawText 变长 */
#define IM_FIXED_LEN ((uint16_t)sizeof(ImMsg))

/* fbterm improxy.c waitImMessage(Connect) 只等 2 秒——client 必须先发
 * Connect 再做慢初始化（librime 字典部署可分钟级，预编数据后=秒级）。 */
#define IM_CONNECT_DEADLINE_S 2

#endif /* AIK_IM_PROTO_H */
