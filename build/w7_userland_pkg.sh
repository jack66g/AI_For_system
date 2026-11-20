#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# w7_userland_pkg.sh - W-7 用户态散件打包器（aik-upgrade install userland 的包源）
#
# 七件实体从本仓实际源收集（occ/aistreamd 为仓内构建产物，需先构建在位）：
#   agent/ai/occ/occ                      -> /usr/local/bin/occ
#   agent/ai/aistreamd/aistreamd          -> /usr/local/sbin/aistreamd
#   agent/ai/aipd/aipd                     -> /usr/local/sbin/aipd
#   ~/linux-k2/drivers/watchdog/softdog.ko
#                                        -> /lib/modules/6.18.39/kernel/drivers/watchdog/softdog.ko
#     （落位=modprobe/depmod 真实管理树（真机实证 11-17：modprobe 即从此
#       生效）；路径绑内核版本 #82/6.18.39——内核走 A/B 通道升级时自带
#       模块，本件仅随同内核热修渠道；装后需 depmod（演练脚本已带）；
#       可用 SOFTDOG_SRC=<路径> 覆盖源位置）
#   factory/etc/fonts/fonts.conf          -> /etc/fonts/fonts.conf
#   factory/etc/sysctl.d/50-aik-console-quiet.conf
#                                         -> /etc/sysctl.d/50-aik-console-quiet.conf
#   factory/usr/local/bin/aik-console     -> /usr/local/bin/aik-console
#
# 第七件 = model.toml 出厂模板一致性断言（非推送件）：出厂模板内嵌于
# factory/usr/local/sbin/aik-reset 的 write_factory_model_toml()，代码单源在
# agent/ai/include/ai_config.h 的 UI_DEFAULT_*。打包前逐槽比对 [ui] 显式值
# vs 宏值，任何漂移 die 拒绝出包——防止「出厂模板」与「代码默认」双源漂移
# （P-49 fail-closed 同款纪律：先校验后动手）。
#
# 包格式（aik-upgrade install userland 契约）：
#   manifest.tsv  每行 = sha256 \t mode \t owner:group \t type(f|l) \t path
#   files/<path>  与 manifest 逐行对应（type=l 时为软链目标文本；本包六件
#                全为实体文件 type=f，type=l 通道由台架测试覆盖）
#
# 用法：
#   build/w7_userland_pkg.sh <输出pkg.tar.gz>    # 断言过 → 打包六件
#   build/w7_userland_pkg.sh --list              # 只打印将打包清单（断言仍跑）
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SOFTDOG_SRC="${SOFTDOG_SRC:-$HOME/linux-k2/drivers/watchdog/softdog.ko}"

log() {
    printf '[w7_userland_pkg] %s\n' "$*" >&2
}

die() {
    log "ERROR: $*"
    exit 1
}

# dest | src | mode | owner:group | type  （src 为相对 REPO 的路径或绝对路径）
PIECES="
/etc/fonts/fonts.conf|factory/etc/fonts/fonts.conf|0644|root:root|f
/etc/sysctl.d/50-aik-console-quiet.conf|factory/etc/sysctl.d/50-aik-console-quiet.conf|0644|root:root|f
/usr/local/bin/aik-console|factory/usr/local/bin/aik-console|0755|root:root|f
/usr/local/bin/occ|agent/ai/occ/occ|0755|root:root|f
/lib/modules/6.18.39/kernel/drivers/watchdog/softdog.ko|SOFTDOG_SRC|0644|root:root|f
/usr/local/sbin/aistreamd|agent/ai/aistreamd/aistreamd|0755|root:root|f
/usr/local/sbin/aipd|agent/ai/aipd/aipd|0755|root:root|f
"

# ---------------------------------------------------------------------------
# 第七件：model.toml 出厂模板 [ui] vs ai_config.h UI_DEFAULT_* 单源断言
# ---------------------------------------------------------------------------
assert_model_ui_consistent() {
    local tmpl="$REPO/factory/usr/local/sbin/aik-reset"
    local hdr="$REPO/agent/ai/include/ai_config.h"
    [ -f "$tmpl" ] || die "factory template source missing: $tmpl"
    [ -f "$hdr" ] || die "code default source missing: $hdr"

    # 出厂模板内嵌在 aik-reset 的 heredoc（<<'EOF' ... EOF）里，先取出 [ui] 段
    local t_ui t_key t_val c_key c_val slot
    t_ui="$(sed -n "/<<'EOF'/,/^EOF$/p" "$tmpl" | awk '/^\[ui\]/{f=1;next} f&&/^\[/{f=0} f&&/=/{print}')"
    [ -n "$t_ui" ] || die "cannot extract [ui] section from factory template in $tmpl"

    # 逐槽断言：模板显式值 == 代码 UI_DEFAULT_*（带引号的字符串去引号比）
    local slots="ctx_len:UI_DEFAULT_CTX_LEN max_tokens:UI_DEFAULT_MAX_TOKENS session:UI_DEFAULT_SESSION lang:UI_DEFAULT_LANG"
    for slot in $slots; do
        t_key="${slot%%:*}"
        c_key="${slot##*:}"
        t_val="$(printf '%s\n' "$t_ui" | awk -v k="$t_key" '$1==k{print $3}')"
        [ -n "$t_val" ] || die "factory template [ui] missing explicit '$t_key = ...' (single-source assertion cannot run)"
        c_val="$(awk -v k="$c_key" '$1=="#define"&&$2==k{print $3}' "$hdr")"
        [ -n "$c_val" ] || die "ai_config.h missing #define $c_key (single-source assertion cannot run)"
        t_val="${t_val%\"}"; t_val="${t_val#\"}"
        c_val="${c_val%\"}"; c_val="${c_val#\"}"
        if [ "$t_val" != "$c_val" ]; then
            die "model.toml factory template drifted from code UI_DEFAULT: [ui] $t_key = '$t_val' (template) != '$c_val' ($c_key in ai_config.h) — fix one source before packaging"
        fi
        log "[assert-ok] [ui] $t_key = $t_val == ${c_key}"
    done
}

# ---------------------------------------------------------------------------
# 打包
# ---------------------------------------------------------------------------
main() {
    assert_model_ui_consistent

    local out="" line dest src mode og type
    case "${1:-}" in
        --list)
            printf '%-44s %-7s %-11s %-4s %s\n' 'DEST' 'MODE' 'OWNER:GRP' 'TYPE' 'SRC'
            while IFS='|' read -r dest src mode og type; do
                [ -n "$dest" ] || continue
                [ "$src" = SOFTDOG_SRC ] && src="$SOFTDOG_SRC"
                printf '%-44s %-7s %-11s %-4s %s\n' "$dest" "$mode" "$og" "$type" "$src"
            done <<EOF
$PIECES
EOF
            log "list above; sources resolved against repo root: $REPO"
            exit 0
            ;;
        '')
            die "usage: build/w7_userland_pkg.sh <输出pkg.tar.gz> | --list"
            ;;
        *)
            out="$1"
            ;;
    esac

    local work
    work="$(mktemp -d /tmp/w7-pkg.XXXXXX)"
    W7_WORK="$work"    # EXIT trap 在函数外执行，须走全局变量
    trap 'rm -rf "${W7_WORK:-}" 2>/dev/null || true' EXIT
    mkdir -p "$work/files"

    local ssha tsha n=0
    while IFS='|' read -r dest src mode og type; do
        [ -n "$dest" ] || continue
        [ "$src" = SOFTDOG_SRC ] && src="$SOFTDOG_SRC"
        case "$src" in /*)	;; *)	src="$REPO/$src" ;; esac
        [ -f "$src" ] || die "source missing: $src (occ/aistreamd 需先在仓内构建在位)"
        mkdir -p "$work/files$(dirname "$dest")"
        cp "$src" "$work/files$dest"
        # sha256 取自源文件，落包后复算比对（复制损坏即 die，fail-closed）
        ssha="$(sha256sum "$src" | awk '{print $1}')"
        tsha="$(sha256sum "$work/files$dest" | awk '{print $1}')"
        [ "$ssha" = "$tsha" ] || die "staged copy corrupt: $dest ($ssha != $tsha)"
        printf '%s\t%s\t%s\t%s\t%s\n' "$ssha" "$mode" "$og" "$type" "$dest" >> "$work/manifest.tsv"
        n=$((n + 1))
    done <<EOF
$PIECES
EOF
    [ "$n" = 7 ] || die "expected 7 pieces, collected $n — PIECES table broken"

    tar -czf "$out" -C "$work" manifest.tsv files
    # 出包自检：成员恰为 manifest.tsv + files/ 树，件数对得上
    local members
    members="$(tar -tzf "$out" | grep -v '/$' | wc -l)"
    [ "$members" = "$((n + 1))" ] || die "package self-check failed: $members members != $((n+1))"
    log "packaged $n pieces -> $out ($(du -h "$out" | cut -f1))"
    log "pkg sha256: $(sha256sum "$out" | awk '{print $1}')"
    printf '%s\n' '--- manifest.tsv ---'
    cat "$work/manifest.tsv"
}

main "$@"
