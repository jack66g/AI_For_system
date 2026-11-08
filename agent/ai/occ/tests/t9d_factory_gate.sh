#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# t9d_factory_gate.sh - T9d ac 三件套出厂部署门（**独立可迁移断言**）
#
# 为什么独立成脚本：T9e 会换代 qsmoke——本门不依赖 qsmoke 的断言框架，
# 只做「文件在/可执行/端口一致」三类静态断言，T9e 的 contentcheck 只需
# 一行调用即可迁移：
#     bash /usr/local/share/aikernel/t9d_factory_gate.sh --root "$CHROOT"
#
# 两种模式：
#   （缺省）仓库模式：检查 factory/ 资产 + 构建产物三二进制
#   --root DIR        镜像模式：检查 DIR 下的 /etc/systemd/system 与
#                     /usr/local/sbin（contentcheck 在 chroot 里跑）
#
# 断言（全绿 rc=0，任一失败 rc=1 并打印 FAIL 行）：
#   1) autocondense.service 存在、ExecStart 指向 autocondensed、端口 8762
#   2) aik-ac-hook 存在且可执行、转发 autocondense-hook、基地址 8762
#   3) 三二进制 autocondensed / autocondense-mcp / autocondense-hook 存在
#      且可执行（镜像模式）；仓库模式查构建产物
#   4) ac 侧零 8761（8761 归 aikernel-api——撞端口坑的清偿）
#   5) aikernel-api 仍占 8761（API 侧不许被改号波及）
set -u

ROOT=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	--root)
		ROOT="${2:-}"
		shift 2
		;;
	*)
		echo "unknown arg: $1" >&2
		exit 2
		;;
	esac
done

FAIL=0
ok() { printf 'ok %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*"; FAIL=$((FAIL + 1)); }

if [ -n "$ROOT" ]; then
	UNIT="$ROOT/etc/systemd/system/autocondense.service"
	HOOK="$ROOT/usr/local/sbin/aik-ac-hook"
	BIN_DIR="$ROOT/usr/local/sbin"
	API_UNIT="$ROOT/etc/systemd/system/aikernel-api.service"
	MODE=image
else
	# 仓库模式：从脚本自身定位仓库根（occ/tests/ → 仓库根，上跳 4 层）
	here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
	repo=$(CDPATH= cd -- "$here/../../../.." && pwd)
	UNIT="$repo/factory/etc/systemd/system/autocondense.service"
	HOOK="$repo/factory/usr/local/sbin/aik-ac-hook"
	BIN_DIR="$repo/agent/ai/autocondense"
	API_UNIT="$repo/factory/etc/systemd/system/aikernel-api.service"
	MODE=repo
fi

# ---- 1) 服务单元 ----
if [ -f "$UNIT" ]; then
	ok "ac-unit-exists ($MODE)"
else
	bad "ac-unit-exists (missing $UNIT)"
fi
if [ -f "$UNIT" ] && grep -q '^ExecStart=.*autocondensed' "$UNIT"; then
	ok "ac-unit-execstart"
else
	bad "ac-unit-execstart"
fi
if [ -f "$UNIT" ] && grep -q '8762' "$UNIT"; then
	ok "ac-unit-port-8762"
else
	bad "ac-unit-port-8762"
fi
# 注释里解释「8761 让给 aikernel-api」是允许的；只断言**生效配置行**无 8761
if [ -f "$UNIT" ] && grep -v '^[[:space:]]*#' "$UNIT" | grep -q '8761'; then
	bad "ac-unit-no-8761 (生效行仍出现 8761)"
else
	ok "ac-unit-no-8761"
fi

# ---- 2) hook 脚本 ----
if [ -f "$HOOK" ]; then
	ok "ac-hook-exists"
else
	bad "ac-hook-exists (missing $HOOK)"
fi
if [ -f "$HOOK" ] && [ -x "$HOOK" ]; then
	ok "ac-hook-executable"
else
	bad "ac-hook-executable"
fi
if [ -f "$HOOK" ] && grep -q 'autocondense-hook' "$HOOK"; then
	ok "ac-hook-forwards"
else
	bad "ac-hook-forwards"
fi
if [ -f "$HOOK" ] && grep -q '8762' "$HOOK"; then
	ok "ac-hook-port-8762"
else
	bad "ac-hook-port-8762"
fi

# ---- 3) 三二进制 ----
for b in autocondensed autocondense-mcp autocondense-hook; do
	if [ -x "$BIN_DIR/$b" ]; then
		ok "ac-bin-$b"
	else
		bad "ac-bin-$b (missing/not executable: $BIN_DIR/$b)"
	fi
done

# ---- 4) ac 侧运行期缺省端口 = 8762（只看代码缺省，不看注释/测试向量适配）----
if [ -z "$ROOT" ]; then
	AC_C="$repo/agent/ai/autocondense"
	AC_H="$repo/agent/ai/include/autocondense"
	if grep -q 'c->port = 8762' "$AC_C/acconfig.c"; then
		ok "acconfig-default-8762"
	else
		bad "acconfig-default-8762"
	fi
	if grep -qE '(=|return) 8761;' "$AC_C/acconfig.c" "$AC_C/acmcp.c" \
		"$AC_C/autocondensed.c"; then
		bad "ac-code-zero-8761 (仍有 8761 缺省)"
	else
		ok "ac-code-zero-8761"
	fi
	if grep -q 'DEFAULT_PORT "8762"' "$AC_C/acmcp.c"; then
		ok "acmcp-default-port-8762"
	else
		bad "acmcp-default-port-8762"
	fi
	if grep -q '8762' "$AC_H/acmcp.h" && grep -q '8762' "$AC_H/achook.h"; then
		ok "ac-headers-port-doc-8762"
	else
		bad "ac-headers-port-doc-8762"
	fi
fi

# ---- 5) aikernel-api 仍占 8761（API 侧不动）----
if [ -f "$API_UNIT" ] && grep -q '8761' "$API_UNIT"; then
	ok "api-unit-still-8761"
else
	bad "api-unit-still-8761 (API 端口被波及?)"
fi

if [ "$MODE" = image ]; then
	# 镜像模式：单元里 ExecStart 的二进制必须真实存在（防「单元在、二进制不在」）
	if grep -q '^ExecStart=' "$UNIT" 2>/dev/null; then
		es=$(grep '^ExecStart=' "$UNIT" | head -1 | sed 's/^ExecStart=//' | awk '{print $1}')
		if [ -n "$es" ] && [ -x "$ROOT$es" ]; then
			ok "ac-unit-binary-installed"
		else
			bad "ac-unit-binary-installed ($es)"
		fi
	fi
fi

echo "t9d_factory_gate($MODE): FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "t9d_factory_gate($MODE): ALL GREEN"
exit 0
