#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# tests_userland.sh - W-7 用户态散件安装通道台架测试（AIK_UPGRADE_ROOT 沙箱）
#
# 六案（全过才算绿）：
#   T1 成功安装：六件落地（内容 sha256 + 权限）+ 附带软链件（type=l 通道）
#   T2 毒包拒收：改一件内容（manifest sha 不匹配）→ 拒绝 + 安装面零变化
#   T3 缺件拒收：files/ 少一件 → 拒绝 + 安装面零变化
#   T4 安装失败自动回滚：某目标父目录只读 → 已装件全部回滚 + 沙箱恢复原状
#   T5 userland-rollback：还原上一次安装（旧件内容/权限/软链 + 墓碑删除）
#   T6 status 集成行 + 审计日志行齐全
# 另附 S 段冒烟：HEAD 原版 aik-upgrade vs 改后版逐子命令对比（rc/输出
# 全等，status/usage 只允许新增 userland 行）——证明未破坏既有子命令。
#
# 「安装面零变化」口径：沙箱指纹覆盖全部目标路径（find %y/%m + 逐文件
# sha256），剔除 var/log（拒绝也要落审计）与 userland 备份/状态（通道内
# 簿记，T4 另行断言备份清空）。
#
# 用法：
#   build/tests_userland.sh [demo包tar.gz]
#   缺省包：现场调用 build/w7_userland_pkg.sh 打一枚（需仓内 occ/aistreamd
#   已构建在位）。必须以非 root 跑（T4 依赖 DAC 生效）。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
AUP="$REPO/factory/usr/local/sbin/aik-upgrade"
PKG="${1:-}"
RUN="$(mktemp -d /tmp/aik-w7-tests.XXXXXX)"

PASS=0; FAIL=0; TFAIL=""
ok()  { printf '%s ... ok\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '%s ... FAIL: %s\n' "$1" "${2:-}"; FAIL=$((FAIL+1)); }
terr() { TFAIL="${TFAIL}${1}; "; }
t_end() { if [ -z "$TFAIL" ]; then ok "$1"; else bad "$1" "$TFAIL"; fi; TFAIL=""; }

[ "$(id -u)" != 0 ] || { echo "FAIL: run as non-root (T4 needs DAC to bite)"; exit 1; }
for t in sha256sum tar stat tac find awk diff comm; do
    command -v "$t" >/dev/null 2>&1 || { echo "FAIL: missing tool $t"; exit 1; }
done
[ -f "$AUP" ] || { echo "FAIL: no aik-upgrade at $AUP"; exit 1; }

# 沙箱指纹：目录树（类型+权限）+ 逐文件 sha256，剔除 ./var 整棵
# （var/log=拒绝也要落的审计；var/lib/aikernel=通道簿记——均非安装面；
# 本六件套不落 /var，T4 另行断言备份清空/状态字段）
fp() {
    (cd "$1" && \
     find . -path './var' -prune -o -printf '%P\t%y\t%m\n' | sort && \
     find . -path './var' -prune -o -type f -print | sort | xargs -r sha256sum) | sha256sum | awk '{print $1}'
}

RC=0; OUTF="$RUN/out"; ERRF="$RUN/err"
run_aik() { # run_aik <沙箱> <args...> → RC/OUTF/ERRF
    local sbx="$1"; shift
    if AIK_UPGRADE_ROOT="$sbx" bash "$AUP" "$@" >"$OUTF" 2>"$ERRF"; then RC=0; else RC=$?; fi
}
alog() { printf '%s\n' "$(cat "$1/var/log/aik-upgrade.log" 2>/dev/null || true)"; }

# ---------------------------------------------------------------- 缺省包
if [ -z "$PKG" ]; then
    bash "$HERE/w7_userland_pkg.sh" "$RUN/auto-pkg.tar.gz" >&2
    PKG="$RUN/auto-pkg.tar.gz"
fi
[ -f "$PKG" ] || { echo "FAIL: no package $PKG"; exit 1; }

# ================================================================ T1
t1() {
    local sbx="$RUN/t1"; rm -rf "$sbx"; mkdir -p "$sbx"
    # 软链件通道（type=l）：迷你包含一文件一软链（先装，六件套收尾→
    # last_pieces=6 供 T6 用）
    local d="$RUN/mini"; rm -rf "$d"; mkdir -p "$d/files/usr/local/bin"
    printf 'hello-w7\n' > "$d/files/usr/local/bin/w7-file"
    printf '/usr/local/bin/occ' > "$d/files/usr/local/bin/w7-link"
    { printf '%s\t0600\troot:root\tf\t/usr/local/bin/w7-file\n' "$(sha256sum "$d/files/usr/local/bin/w7-file" | awk '{print $1}')"
      printf '%s\t0777\troot:root\tl\t/usr/local/bin/w7-link\n' "$(sha256sum "$d/files/usr/local/bin/w7-link" | awk '{print $1}')"
    } > "$d/manifest.tsv"
    tar -czf "$RUN/mini.tar.gz" -C "$d" manifest.tsv files
    run_aik "$sbx" install userland "$RUN/mini.tar.gz"
    [ "$RC" = 0 ] || terr "T1b: mini install rc=$RC"
    [ "$(cat "$sbx/usr/local/bin/w7-file")" = "hello-w7" ] || terr "T1b: w7-file content"
    [ "$(stat -c%a "$sbx/usr/local/bin/w7-file")" = 600 ] || terr "T1b: w7-file mode"
    [ -L "$sbx/usr/local/bin/w7-link" ] || terr "T1b: w7-link not a symlink"
    [ "$(readlink "$sbx/usr/local/bin/w7-link")" = "/usr/local/bin/occ" ] || terr "T1b: w7-link target"
    # 六件套本体
    run_aik "$sbx" install userland "$PKG"
    [ "$RC" = 0 ] || terr "T1: install rc=$RC ($(head -1 "$ERRF"))"
    # 逐件：内容 sha256 + 权限 + 类型（对照包内 manifest）
    local line sha mode og type path want
    while IFS=$'\t' read -r sha mode og type path; do
        [ -n "${sha:-}" ] || continue
        if [ "$type" = f ]; then
            [ -f "$sbx$path" ] && [ ! -L "$sbx$path" ] || { terr "T1: $path not a regular file"; continue; }
            [ "$(sha256sum "$sbx$path" | awk '{print $1}')" = "$sha" ] || terr "T1: $path sha mismatch"
            want="$(printf '%o' "$((8#$mode))")"
            [ "$(stat -c%a "$sbx$path")" = "$want" ] || terr "T1: $path mode $(stat -c%a "$sbx$path") != $want"
        fi
    done < <(tar -xzOf "$PKG" manifest.tsv)
    # 备份目录留两枚（mini + 六件套，回滚凭据）
    [ "$(find "$sbx/var/lib/aikernel/userland-backups" -mindepth 1 -maxdepth 1 -type d | wc -l)" = 2 ] \
        || terr "T1: expected 2 backups (mini+demo), got $(find "$sbx/var/lib/aikernel/userland-backups" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
    t_end "T1 成功安装（六件内容+权限；mini 件软链）"
}

# ================================================================ T2
t2() {
    local sbx="$RUN/t2" src="$RUN/t2src"; rm -rf "$sbx" "$src"; mkdir -p "$sbx" "$src"
    tar -xzf "$PKG" -C "$src"
    printf 'POISON' >> "$src/files/etc/fonts/fonts.conf"   # 毒化一件，manifest sha 不动
    tar -czf "$RUN/t2-poison.tar.gz" -C "$src" manifest.tsv files
    local b; b="$(fp "$sbx")"
    run_aik "$sbx" install userland "$RUN/t2-poison.tar.gz"
    [ "$RC" != 0 ] || terr "T2: poison package accepted (rc=0)"
    grep -q "sha256 mismatch" "$ERRF" || terr "T2: no sha256 mismatch message"
    [ "$(fp "$sbx")" = "$b" ] || terr "T2: sandbox changed on reject"
    [ ! -d "$sbx/var/lib/aikernel/userland-backups" ] || [ -z "$(find "$sbx/var/lib/aikernel/userland-backups" -mindepth 1 -print -quit)" ] \
        || terr "T2: backup created on reject"
    grep -q "action=error" <(alog "$sbx") || terr "T2: no audit error line"
    t_end "T2 毒包拒收（sha 不匹配→拒绝，安装面零变化）"
}

# ================================================================ T3
t3() {
    local sbx="$RUN/t3" src="$RUN/t3src"; rm -rf "$sbx" "$src"; mkdir -p "$sbx" "$src"
    tar -xzf "$PKG" -C "$src"
    rm -f "$src/files/usr/local/sbin/aistreamd"           # 缺一件
    tar -czf "$RUN/t3-missing.tar.gz" -C "$src" manifest.tsv files
    local b; b="$(fp "$sbx")"
    run_aik "$sbx" install userland "$RUN/t3-missing.tar.gz"
    [ "$RC" != 0 ] || terr "T3: missing-piece package accepted (rc=0)"
    grep -q "missing from package" "$ERRF" || terr "T3: no missing-piece message"
    [ "$(fp "$sbx")" = "$b" ] || terr "T3: sandbox changed on reject"
    t_end "T3 缺件拒收（files/ 少一件→拒绝，安装面零变化）"
}

# ================================================================ T4
t4() {
    local sbx="$RUN/t4"; rm -rf "$sbx"; mkdir -p "$sbx/etc/fonts"
    chmod 555 "$sbx/etc/fonts"                            # fonts.conf 父目录只读：该件必失败
    local b; b="$(fp "$sbx")"
    run_aik "$sbx" install userland "$PKG"
    [ "$RC" != 0 ] || terr "T4: install should fail (rc=0)"
    grep -q "rolled back" "$ERRF" || terr "T4: no rollback message"
    [ "$(fp "$sbx")" = "$b" ] || terr "T4: sandbox not restored after auto-rollback"
    [ "$(stat -c%a "$sbx/etc/fonts")" = 555 ] || terr "T4: read-only dir perms changed"
    [ -z "$(find "$sbx/var/lib/aikernel/userland-backups" -mindepth 1 -print -quit 2>/dev/null)" ] \
        || terr "T4: backup not cleaned after auto-rollback"
    grep -q "phase=fail" <(alog "$sbx") || terr "T4: no phase=fail audit line"
    grep -q "phase=rollback" <(alog "$sbx") || terr "T4: no phase=rollback audit line"
    grep -q "failed-rolled-back" "$sbx/var/lib/aikernel/userland-state" || terr "T4: state not failed-rolled-back"
    t_end "T4 安装失败自动回滚（只读父目录→全部件还原，沙箱原状）"
}

# ================================================================ T5
t5() {
    local sbx="$RUN/t5"; rm -rf "$sbx"; mkdir -p "$sbx/usr/local/bin" "$sbx/etc/fonts"
    printf 'OLDOCC' > "$sbx/usr/local/bin/occ"; chmod 0700 "$sbx/usr/local/bin/occ"
    ln -s /etc/hostname "$sbx/etc/fonts/fonts.conf"        # 旧值：一文件一软链
    local oldsha; oldsha="$(printf 'OLDOCC' | sha256sum | awk '{print $1}')"   # 不 cat 二进制（免 null 字节告警）
    run_aik "$sbx" install userland "$PKG"
    [ "$RC" = 0 ] || terr "T5: install rc=$RC"
    [ "$(sha256sum "$sbx/usr/local/bin/occ" | awk '{print $1}')" != "$oldsha" ] || terr "T5: occ not replaced by package"
    [ -f "$sbx/etc/fonts/fonts.conf" ] && [ ! -L "$sbx/etc/fonts/fonts.conf" ] || terr "T5: link not replaced"
    run_aik "$sbx" userland-rollback
    [ "$RC" = 0 ] || terr "T5: userland-rollback rc=$RC ($(head -1 "$ERRF"))"
    [ "$(sha256sum "$sbx/usr/local/bin/occ" | awk '{print $1}')" = "$oldsha" ] || terr "T5: occ not restored"
    [ "$(stat -c%a "$sbx/usr/local/bin/occ")" = 700 ] || terr "T5: occ mode not restored"
    [ -L "$sbx/etc/fonts/fonts.conf" ] || terr "T5: fonts.conf not restored as symlink"
    [ "$(readlink "$sbx/etc/fonts/fonts.conf")" = "/etc/hostname" ] || terr "T5: fonts.conf link target drift"
    [ ! -e "$sbx/usr/local/sbin/aistreamd" ] || terr "T5: absent-tombstone piece not removed"
    [ ! -e "$sbx/lib/modules/6.18.39/kernel/drivers/watchdog/softdog.ko" ] || terr "T5: absent-tombstone piece not removed (softdog)"
    [ -z "$(find "$sbx/var/lib/aikernel/userland-backups" -mindepth 1 -print -quit 2>/dev/null)" ] \
        || terr "T5: backup not released after rollback"
    grep -q "last_result=rolled-back" "$sbx/var/lib/aikernel/userland-state" || terr "T5: state not rolled-back"
    grep -q "action=userland-rollback .*phase=done" <(alog "$sbx") || terr "T5: no userland-rollback done audit"
    t_end "T5 userland-rollback 还原上一次（旧件内容/权限/软链+墓碑删除）"
}

# ================================================================ T6
t6() {
    local sbx="$RUN/t1"                                    # 复用 T1 的成功安装态
    run_aik "$sbx" status
    [ "$RC" = 0 ] || terr "T6: status rc=$RC"
    grep -qE '^last install: ts=[0-9T:Z-]+ pieces=6 result=ok backups=' "$OUTF" \
        || terr "T6: status userland line missing/wrong: $(grep 'last install' "$OUTF" || echo none)"
    # 审计行齐全：begin / 件级 ok / done / fail / rollback / userland-rollback
    local log; log="$(alog "$sbx")"
    [ "$(grep -c 'action=install-userland .*phase=begin' <<<"$log")" -ge 1 ] || terr "T6: no begin"
    [ "$(grep -c 'action=install-userland .*phase=ok ' <<<"$log")" -ge 6 ] || terr "T6: <6 piece ok lines"
    [ "$(grep -c 'action=install-userland .*phase=done' <<<"$log")" -ge 1 ] || terr "T6: no done"
    local l4 l5
    l4="$(alog "$RUN/t4")"; l5="$(alog "$RUN/t5")"
    grep -q 'phase=fail' <<<"$l4" || terr "T6: T4 log no fail"
    grep -q 'phase=rollback' <<<"$l4" || terr "T6: T4 log no rollback"
    grep -q 'action=userland-rollback .*phase=done' <<<"$l5" || terr "T6: T5 log no rollback done"
    t_end "T6 status 集成行 + 审计日志行齐全"
}

# ================================================================ S 冒烟（HEAD 原版 vs 改后版）
norm_smoke() {
    grep -vE 'aik-upgrade (install userland|userland-rollback)|^=== userland \(W-7\) ===$|^last install: |^ {6,}' \
        | sed -e 's/([0-9.]*[KM])/(SIZE)/' -e 's/entries=[0-9]*/entries=N/'
}

smoke() {
    local orig="$RUN/aik-upgrade.orig"
    if ! git -C "$REPO" show HEAD:factory/usr/local/sbin/aik-upgrade > "$orig" 2>/dev/null || [ ! -s "$orig" ]; then
        bad "S  冒烟" "cannot materialize HEAD original aik-upgrade — skipped (run inside worktree/repo)"
        return
    fi
    local label ro rn
    # 归一化：a) bash 重定向失败时泄漏的 "$0: 行 N:" 消息（两版行为相同，
    # 但路径/行号不同）；b) 新增 userland 块与其前导空行；c) 尾随空行；
    # d) export 的体积/件数抖动。
    smoke_norm() {
        sed -e "s|$orig: 行 [0-9][0-9]*:|SCRIPT: 行 N:|g" -e "s|$AUP: 行 [0-9][0-9]*:|SCRIPT: 行 N:|g" \
            | norm_smoke \
            | awk '{a[NR]=$0} END{e=NR; while(e>0 && a[e]~/^[[:space:]]*$/) e--; for(i=1;i<=e;i++) print a[i]}'
    }
    smoke_pair() { # label args...
        local lbl="$1"; shift
        if env -u AIK_UPGRADE_ROOT bash "$orig" "$@" >"$RUN/so" 2>"$RUN/se"; then ro=0; else ro=$?; fi
        if env -u AIK_UPGRADE_ROOT bash "$AUP"  "$@" >"$RUN/no" 2>"$RUN/ne"; then rn=0; else rn=$?; fi
        [ "$ro" = "$rn" ] || terr "S$lbl: rc $ro != $rn"
        diff <(smoke_norm <"$RUN/so") <(smoke_norm <"$RUN/no") >/dev/null || terr "S$lbl: stdout diff"
        diff <(smoke_norm <"$RUN/se") <(smoke_norm <"$RUN/ne") >/dev/null || terr "S$lbl: stderr diff"
    }
    smoke_pair 1 status
    smoke_pair 2 healthcheck
    smoke_pair 3 install
    smoke_pair 4 install kernel
    smoke_pair 5 install kernel /nonexistent-w7 38
    smoke_pair 6 install shell /nonexistent-w7
    smoke_pair 7 export "$RUN/smoke.tar.gz" --no-sme
    smoke_pair 8 import /nonexistent-w7.tar.gz
    smoke_pair 9 grubenv dump
    if [ ! -w /boot/grub ]; then
        smoke_pair 10 rollback w7-smoke
    else
        printf 'S10 rollback ... skip (/boot/grub writable — 不冒险真跑)\n'
    fi
    # status 的新增块必须恰好在（除 userland 行外输出全等由上面保证）
    env -u AIK_UPGRADE_ROOT bash "$AUP" status >"$RUN/no" 2>/dev/null
    grep -q '^=== userland (W-7) ===$' "$RUN/no" || terr "S1: new status missing userland section"
    t_end "S  冒烟（HEAD 原版 vs 改后版：status/healthcheck/install/export/import/grubenv/rollback 全等）"
}

# ---------------------------------------------------------------- 跑
printf '# aik-upgrade userland 台架测试（run dir %s）\n' "$RUN"
printf '# pkg = %s\n\n' "$PKG"
t1; t2; t3; t4; t5; t6; smoke
printf '\n# 结果: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
rm -rf "$RUN"
[ "$FAIL" = 0 ]
