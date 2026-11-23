#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# check_tree.sh —— 树宪章门禁（宪章：docs/TREE-CHARTER.md 第 4 节，检查项一一对应）
#
# 用法（仓库内任意位置均可运行，自己找仓根；只依赖 bash + git + coreutils）：
#   bash agent/ai/tools/check_tree.sh                         全部检查，任一 FAIL 则退出码 1
#   bash agent/ai/tools/check_tree.sh --update-debt-baseline  只降不升地收紧硬编码债务基线
#
# 两个视图都查（两者都不得违规）：
#   ix = 索引视图，已暂存内容，即将被提交的东西；
#   wt = 工作区视图，被跟踪文件的当前内容 + 未跟踪且未被忽略的新文件——
#        测试在提交前跑，此时改动多半尚未 git add，只看索引会漏掉。
# 约定：明细里凡是「路径:行号」都只报位置，密钥命中字面量绝不打印。

set -u
export LC_ALL=C

# ---------------------------------------------------------------------------
# 白名单与清单（改这里，不要改下面的逻辑）
# ---------------------------------------------------------------------------
# 现役入库 ELF（二进制入库纪律仍有效；待迁制品库，见宪章第 5 节 ENG-07）
ELF_ALLOW=(
    agent/ai/occ/occ
    agent/ai/aistreamd/aistreamd
    agent/ai/aipd/aipd
    factory/usr/local/bin/aik-ime
    factory/usr/local/bin/busybox
    factory/usr/local/lib/aik-ime/libboost_regex.so.1.74.0
    factory/usr/local/lib/aik-ime/libicudata.so.70.1
    factory/usr/local/lib/aik-ime/libicui18n.so.70.1
    factory/usr/local/lib/aik-ime/libicuuc.so.70.1
    factory/usr/local/lib/aik-ime/libleveldb.so.1.23.0
    factory/usr/local/lib/aik-ime/libmarisa.so.0.0.0
    factory/usr/local/lib/aik-ime/libopencc.so.1.1.3
    factory/usr/local/lib/aik-ime/libsnappy.so.1.1.8
    factory/usr/local/lib/aik-ime/libyaml-cpp.so.0.7.0
)
# 运行报告（每次生成/测试都会重写的文本产物）——不得再被跟踪
RUN_REPORTS=(
    agent/ai/tools/tools_report.txt
    agent/ai/tools_report.txt
    agent/ai/occ/tests/orch_b2_report.txt
)
# 密钥扫描豁免：路径|模式|字面量sha256|理由
#   第三列留空 = 该文件在该模式下整体豁免；能钉到字面量的一律钉死（哈希取命中
#   字面量本身）。只许精确到文件，不许按目录或通配放行。
SECRET_ALLOW=(
    "agent/ai/tests/test_trace.c|sk|c4a3ff51a72f4cf5d50dc20f67558690a23b9ea7cf586cbb30bb43801b47427b|redaction unit test's fake key literal (source says 'my fake key'); only this exact literal"
    "agent/ai/tests/tls_test_certs.h|privkey||self-signed TLS test certificate chain fixture, regenerable via tests/tls_certs_regen.sh, not a production credential"
    "agent/ai/third_party/mbedtls/library/pk_internal.h|privkey||upstream source: macro definitions of the PEM BEGIN marker strings, not keys"
)
# 允许存在的嵌套 .gitignore（mbedtls 七件为上游原样；smehttp 一件待并回仓根）。
# 其余忽略规则一律写在仓根 .gitignore 一份里。
NESTED_GITIGNORE_OK=(
    agent/ai/smehttp/.gitignore
    agent/ai/third_party/mbedtls/.gitignore
    agent/ai/third_party/mbedtls/3rdparty/.gitignore
    agent/ai/third_party/mbedtls/3rdparty/everest/.gitignore
    agent/ai/third_party/mbedtls/3rdparty/p256-m/.gitignore
    agent/ai/third_party/mbedtls/include/.gitignore
    agent/ai/third_party/mbedtls/library/.gitignore
    agent/ai/third_party/mbedtls/pkgconfig/.gitignore
)
# 忽略规则自检哨兵：把 .gitignore 的语义钉死（规则与实际产物脱节是旧版的病根）
MUST_IGNORE=(     # 构建产物：必须被忽略
    agent/ai/aipd/obj/aip_canary.d agent/ai/aipd/tests/test_util.d agent/ai/apic/apiask.d
    agent/ai/occ/occ.d agent/ai/occ/obj/x.o
    agent/ai/aistreamd/obj/reuse/x.o agent/ai/tests/__pycache__/x.pyc agent/ai/tests/test_x.pyc
    agent/ai/build/x.o agent/ai/build-gcm/x.o agent/ai/build-compat/x.o
    agent/ai/tests/test_x agent/ai/aipd/tests/test_x agent/ai/occ/tests/test_x
    agent/ai/occ/occ_tui/tests/test_x agent/ai/aistreamd/tests/test_x agent/ai/apic/tests/test_x
    agent/ai/tests/netlink_probe agent/ai/tests/w10b_tls_probe agent/ai/tests/w10b_tls_probe_asan
    agent/ai/aistreamd/tests/ai_inject agent/ai/aistreamd/tests/pq_dump
    agent/ai/occ/tests/occ_smoke agent/ai/sandbox/tests/aik-sandbox
    agent/ai/aik-compat agent/ai/aik-gcm agent/ai/aistreamd/aik-pqdump agent/ai/apic/aikerneld-api
    agent/ai/smehttp/smehttp agent/ai/autocondense/autocondensed agent/ai/aikernel-shell
    agent/ai/ai agent/ai/aik-sandbox agent/ai/sandbox/aik-sandbox
    agent/ai/tools/tools_report.txt agent/ai/tools_report.txt agent/ai/occ/tests/orch_b2_report.txt
    agent/ai/tests/engine.actual.json
    kernel-overlays/kernel/x.o kernel-overlays/kernel/x.ko kernel-overlays/kernel/x.mod
    kernel-overlays/kernel/x.mod.c kernel-overlays/kernel/.x.cmd kernel-overlays/Module.symvers
    kernel-overlays/modules.order kernel-overlays/.tmp_versions/x
    build/x.log build/x.tmp x.orig x.rej x.swp model.toml api-token x.pem x.key x.iso x.tar.gz
)
MUST_TRACK=(       # 源码、夹具、白名单二进制、冻结基线：不得被忽略
    agent/ai/aipd/tests/test_x.c agent/ai/aipd/tests/test_x.h agent/ai/aipd/tests/test_x.py
    agent/ai/aipd/tests/test_x.sh agent/ai/tests/test_x.json agent/ai/tests/test_x.tsv
    agent/ai/tests/test_x.golden agent/ai/tests/test_x/fixture.bin agent/ai/tests/Makefile
    agent/ai/tests/redteam/redteam_drill.py agent/ai/tests/fixtures/x.vec
    agent/ai/occ/occ agent/ai/aistreamd/aistreamd agent/ai/aipd/aipd
    factory/usr/local/bin/aik-ime factory/usr/local/bin/busybox
    factory/usr/local/lib/aik-ime/libsnappy.so.1.1.8
    agent/ai/tools/tool_catalog.txt agent/ai/tools/tools.json factory/etc/aikernel/tools.json
    factory/etc/sysctl.d/50-aik-console-quiet.conf factory/etc/apt/apt.conf.d/51-aik-upgrade-policy
    factory/etc/ld.so.conf.d/aik-ime.conf factory/etc/aikernel/models.d/cloud.toml
    agent/ai/tests/tls_test_certs.h docs/TREE-CHARTER.md agent/ai/tools/check_tree_debt_baseline.txt
)

# 硬编码环境地址的正则。家目录路径拆开写，本脚本自身才不会成为债务。
RE_HOME='/home/jack'66g
RE_NET='192\.168\.245\.'
DEBT_BASELINE=agent/ai/tools/check_tree_debt_baseline.txt
ELF_MAGIC=$'\x7fELF'
# 密钥模式：编号|POSIX ERE（git grep -E）。用 (^|[^A-Za-z0-9_]) 代替 \b，不依赖 PCRE。
SECRET_RE=(
    'privkey|-----BEGIN [A-Z ]*PRIVATE KEY-----'
    'sk|(^|[^A-Za-z0-9_])sk-[A-Za-z0-9]{20,}'
    'ghp|(^|[^A-Za-z0-9_])ghp_[A-Za-z0-9]{30,}'
    'akia|(^|[^A-Za-z0-9_])AKIA[0-9A-Z]{16}([^0-9A-Z]|$)'
    'slack|(^|[^A-Za-z0-9_])xox[baprs]-[A-Za-z0-9-]{10,}'
)
JUNK_RE='(^|/)[^/]*\.(log|tmp|orig|rej|swp)$|~$'

# ---------------------------------------------------------------------------
# 基础设施
# ---------------------------------------------------------------------------
root=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$root" ]; then
    # 当前目录不在仓内（例如从别处用绝对路径调用）：按脚本自身位置定位仓根
    # （本脚本固定在 agent/ai/tools/，上三级即仓根）。
    root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." 2>/dev/null && pwd)
    [ -n "$root" ] && [ -f "$root/$DEBT_BASELINE" ] || { echo "check_tree: cannot locate the repository root" >&2; exit 2; }
fi
cd "$root" || exit 2

PASS=0; FAIL=0; FAILED=()
report() {                     # $1=检查名 $2=0(过)/1(败) 其余=明细行
    local name=$1 rc=$2 l; shift 2
    if [ "$rc" -eq 0 ]; then PASS=$((PASS + 1)); printf 'PASS  %s\n' "$name"
    else FAIL=$((FAIL + 1)); FAILED+=("$name"); printf 'FAIL  %s\n' "$name"; fi
    for l in "$@"; do printf '      %s\n' "$l"; done
}
viewflag() { [ "$1" = ix ] && echo --cached; return 0; }
# 文本扫描（债务、密钥）的视图开关：ix 查索引，wt 查工作区并带上未跟踪且未被忽略的新文件
scanflag() { if [ "$1" = ix ]; then echo --cached; else echo --untracked; fi; }
# 「二进制候选」= 普通文件 − 文本清单。ELF 头的 e_ident 填充区与 e_type 高字节必为
# NUL，git 一律判为二进制，所以任何 ELF 都进不了文本清单；再对候选读前 4 字节定性。
text_list() {                  # $1=视图 → 文本且非空的被跟踪文件路径
    local f; f=$(viewflag "$1")
    if [ -n "$f" ]; then git grep --cached -I -l -e ''; else git grep -I -l -e ''; fi
}
head4() {                      # $1=视图 $2=路径 → 前 4 字节（只读普通文件，防 FIFO 阻塞）
    local m=''
    if [ "$1" = ix ]; then git cat-file blob ":$2" 2>/dev/null | head -c 4
    elif [ -f "$root/$2" ]; then IFS= read -r -N4 m < "$root/$2" 2>/dev/null; printf '%s' "$m"; fi
}
count_by_file() {              # $1=视图 $2=正则 → 每行「路径<TAB>出现次数」
    local f; f=$(scanflag "$1")
    git grep $f -I -o -e "$2" | cut -d: -f1 | sort | uniq -c | sed -E 's/^ *([0-9]+) (.*)$/\2\t\1/'
    return 0
}
sha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

# 索引清单：只取普通文件（100644/100755）。符号链接的 blob 内容是目标路径，不是 ELF。
T_PATHS=(); declare -A T_MODE=()
while read -r mode blobid stage path; do
    case "$mode" in 100644|100755) T_PATHS+=("$path"); T_MODE["$path"]=$mode ;; esac
done < <(git ls-files -s)

# ---------------------------------------------------------------------------
# 1. 被跟踪的编译中间件
# ---------------------------------------------------------------------------
chk_artifacts() {
    local p hits=()
    for p in "${T_PATHS[@]}"; do
        case "$p" in *.d|*.o|*.pyc|*.pyo|*/obj/*) hits+=("$p") ;; esac
    done
    report tracked-artifacts $(( ${#hits[@]} ? 1 : 0 )) "${hits[@]}"
}

# ---------------------------------------------------------------------------
# 2. 被跟踪的 ELF 只能在白名单内（两个视图；白名单不得有失效项）
# ---------------------------------------------------------------------------
chk_elf() {
    local view p bad=0 hits=() stale=() a
    local -A allow=() text=() found=()
    for a in "${ELF_ALLOW[@]}"; do allow["$a"]=1; done
    for view in ix wt; do
        text=(); while IFS= read -r p; do text["$p"]=1; done < <(text_list "$view")
        for p in "${T_PATHS[@]}"; do
            [ -n "${text[$p]:-}" ] && continue
            [ "$(head4 "$view" "$p")" = "$ELF_MAGIC" ] || continue
            found["$p"]=1
            [ -n "${allow[$p]:-}" ] && continue
            bad=1; hits+=("[$view] tracked ELF not in whitelist: $p")
        done
    done
    for a in "${ELF_ALLOW[@]}"; do
        [ -n "${found[$a]:-}" ] || { bad=1; stale+=("stale whitelist entry (not a tracked ELF any more), remove from ELF_ALLOW: $a"); }
    done
    report elf-whitelist $bad "${hits[@]}" "${stale[@]}" "tracked ELF: ${#found[@]}, whitelist entries: ${#ELF_ALLOW[@]}"
}

# ---------------------------------------------------------------------------
# 3. 硬编码环境地址：基线法「不新增」
#    基线列：路径<TAB>命中数合计<TAB>home 路径处数<TAB>实验网段处数
# ---------------------------------------------------------------------------
declare -A BASE=() CUR=(); CURKEYS=()
load_baseline() {
    BASE=(); local f t h n
    [ -f "$DEBT_BASELINE" ] || return 0
    while IFS=$'\t' read -r f t h n; do
        case "$f" in '#'*) continue ;; esac
        BASE["$f,h"]=$h; BASE["$f,n"]=$n
    done < "$DEBT_BASELINE"
}
collect_debt() {               # $1=视图 → CUR[路径,h|n]=次数，CURKEYS=键列表
    CUR=(); CURKEYS=(); local f n
    while IFS=$'\t' read -r f n; do CUR["$f,h"]=$n; CURKEYS+=("$f,h"); done < <(count_by_file "$1" "$RE_HOME")
    while IFS=$'\t' read -r f n; do CUR["$f,n"]=$n; CURKEYS+=("$f,n"); done < <(count_by_file "$1" "$RE_NET")
    return 0
}
chk_debt() {
    local view key f k b c bad=0 up=() down=()
    if [ ! -f "$DEBT_BASELINE" ]; then
        report debt-baseline 1 "baseline file missing: $DEBT_BASELINE" "bootstrap it with: bash agent/ai/tools/check_tree.sh --update-debt-baseline"
        return 0
    fi
    for view in ix wt; do
        collect_debt "$view"
        for key in "${CURKEYS[@]}"; do
            f=${key%,*}; c=${CUR[$key]}; b=${BASE[$key]:-0}
            case "$key" in *,h) k=home-path ;; *) k=lab-net ;; esac
            if [ "$c" -gt "$b" ]; then bad=1; up+=("[$view] $f: $k hits $b -> $c")
            elif [ "$view" = ix ] && [ "$c" -lt "$b" ]; then down+=("$f: $k $b -> $c"); fi
        done
    done
    local -A files=(); local nh=0 nn=0
    for key in "${!BASE[@]}"; do
        f=${key%,*}; files["$f"]=1
        case "$key" in *,h) nh=$((nh + BASE[$key])) ;; *) nn=$((nn + BASE[$key])) ;; esac
    done
    [ ${#up[@]} -eq 0 ] || up+=("hardcoded environment addresses may only decrease: a new file or a higher count is rejected (cleanup is ENG-08)")
    [ ${#down[@]} -eq 0 ] || down+=("debt decreased; tighten the baseline: bash agent/ai/tools/check_tree.sh --update-debt-baseline")
    report debt-baseline $bad "${up[@]}" "${down[@]}" "baseline: ${#files[@]} files, home-path $nh + lab-net $nn hits (ratchet, down only)"
}
write_baseline() {             # 只降不升：新出现的债务不写入，仍由 chk_debt 判红
    local keys=() key f h n out='' nf=0 nh=0 nn=0 mode=tightened
    collect_debt ix
    if [ -f "$DEBT_BASELINE" ]; then keys=("${!BASE[@]}"); else mode=created; keys=("${CURKEYS[@]}"); fi
    local -A seen=()
    for key in "${keys[@]}"; do
        f=${key%,*}; [ -n "${seen[$f]:-}" ] && continue; seen["$f"]=1
        h=${CUR["$f,h"]:-0}; n=${CUR["$f,n"]:-0}
        if [ "$mode" = tightened ]; then
            [ "$h" -gt "${BASE[$f,h]:-0}" ] && h=${BASE[$f,h]}
            [ "$n" -gt "${BASE[$f,n]:-0}" ] && n=${BASE[$f,n]}
        fi
        [ $((h + n)) -gt 0 ] || continue
        out+="$f"$'\t'$((h + n))$'\t'"$h"$'\t'"$n"$'\n'
        nf=$((nf + 1)); nh=$((nh + h)); nn=$((nn + n))
    done
    {
        printf '# check_tree hardcoded-debt baseline (the "no new environment addresses" gate).\n'
        printf '# Generated by: bash agent/ai/tools/check_tree.sh --update-debt-baseline  (do not hand-edit)\n'
        printf '# Columns: path<TAB>total hits<TAB>home-path hits<TAB>lab-net hits\n'
        printf '# Scope: tracked text files (binaries skipped), counted per occurrence, index view.\n'
        printf '# Ratchet only: counts may go down, never up; new debt is never written here.\n'
        printf '# Total: %d files, %d hits (home-path %d, lab-net %d)\n' "$nf" "$((nh + nn))" "$nh" "$nn"
        printf '%s' "$out" | sort
    } > "$DEBT_BASELINE"
    printf 'debt baseline %s: %d files, %d hits -> %s\n' "$mode" "$nf" "$((nh + nn))" "$DEBT_BASELINE"
}

# ---------------------------------------------------------------------------
# 4. 密钥模式扫描（两个视图；命中字面量绝不打印）
# ---------------------------------------------------------------------------
chk_secrets() {
    local view f e re id line p ln m tok a ap aid ah bad=0 hits=() exempt
    local args=()
    for e in "${SECRET_RE[@]}"; do args+=(-e "${e#*|}"); done
    for view in ix wt; do
        f=$(scanflag "$view")
        while IFS= read -r line; do
            p=${line%%:*}; line=${line#*:}; ln=${line%%:*}; m=${line#*:}
            id=''
            for e in "${SECRET_RE[@]}"; do re=${e#*|}; if [[ $m =~ $re ]]; then id=${e%%|*}; break; fi; done
            [ -n "$id" ] || continue
            tok=$(printf '%s' "$m" | sed -E 's/^[^A-Za-z0-9_-]+//; s/[^A-Za-z0-9_-]+$//')
            exempt=0
            for a in "${SECRET_ALLOW[@]}"; do
                IFS='|' read -r ap aid ah _ <<< "$a"
                [ "$ap" = "$p" ] && [ "$aid" = "$id" ] || continue
                if [ -z "$ah" ] || [ "$(sha "$tok")" = "$ah" ]; then exempt=1; fi
                break
            done
            [ "$exempt" = 1 ] && continue
            bad=1; hits+=("[$view] $p:$ln: secret pattern <$id> (match not printed)")
        done < <(git grep $f -I -n -o -E "${args[@]}")
    done
    report secrets $bad "${hits[@]}"
}

# ---------------------------------------------------------------------------
# 5. 运行报告不得被跟踪
# ---------------------------------------------------------------------------
chk_reports() {
    local r bad=0 hits=()
    for r in "${RUN_REPORTS[@]}"; do
        [ -n "${T_MODE[$r]:-}" ] && { bad=1; hits+=("run report is tracked: $r"); }
    done
    report run-reports $bad "${hits[@]}"
}

# ---------------------------------------------------------------------------
# 6. 被跟踪文件名里不得有编辑器/补丁残留
# ---------------------------------------------------------------------------
chk_junk() {
    local p bad=0 hits=()
    for p in "${T_PATHS[@]}"; do
        if [[ $p =~ $JUNK_RE ]]; then bad=1; hits+=("$p"); fi
    done
    report junk-names $bad "${hits[@]}"
}

# ---------------------------------------------------------------------------
# 7. 忽略规则自检（哨兵路径 + 嵌套 .gitignore 清单）
# ---------------------------------------------------------------------------
chk_ignore() {
    local p bad=0 hits=() extra ignored
    ignored=$(printf '%s\n' "${MUST_IGNORE[@]}" "${MUST_TRACK[@]}" | git check-ignore --no-index --stdin)
    for p in "${MUST_IGNORE[@]}"; do
        grep -Fxq -- "$p" <<< "$ignored" || { bad=1; hits+=("must be ignored but is not: $p"); }
    done
    for p in "${MUST_TRACK[@]}"; do
        if grep -Fxq -- "$p" <<< "$ignored"; then
            bad=1; hits+=("must stay trackable but matches: $(printf '%s\n' "$p" | git check-ignore --no-index -v --stdin | cut -f1)")
        fi
    done
    extra=$(git ls-files -- '*.gitignore' | grep -v -x -F -f <(printf '%s\n' .gitignore "${NESTED_GITIGNORE_OK[@]}"))
    if [ -n "$extra" ]; then
        bad=1; hits+=("new nested .gitignore (all ignore rules live in the root .gitignore):" $extra)
    fi
    report ignore-selftest $bad "${hits[@]}" "sentinels: ${#MUST_IGNORE[@]} must-ignore, ${#MUST_TRACK[@]} must-track"
}

# ---------------------------------------------------------------------------
# 8. git status 可见的未跟踪文件里不得有构建产物（规则没跟上实际产物的信号）
# ---------------------------------------------------------------------------
chk_untracked() {
    local e b m bad=0 hits=()
    while IFS= read -r -d '' e; do
        case "$e" in */) continue ;; esac          # 整目录未跟踪：git status 本来就醒目
        b=${e##*/}
        case "$b" in *.d|*.o|*.pyc|*.pyo|*.a|*.ko) bad=1; hits+=("$e"); continue ;; esac
        case "$e" in */obj/*|*/__pycache__/*) bad=1; hits+=("$e"); continue ;; esac
        m=''; [ -f "$root/$e" ] && IFS= read -r -N4 m < "$root/$e" 2>/dev/null
        [ "$m" = "$ELF_MAGIC" ] && { bad=1; hits+=("$e (ELF)"); }
    done < <(git ls-files --others --exclude-standard -z --directory)
    [ ${#hits[@]} -eq 0 ] || hits+=("untracked build products visible in git status: add a category rule to .gitignore if they are products, otherwise remove them")
    report untracked-products $bad "${hits[@]}"
}

# ---------------------------------------------------------------------------
# 9. 没有被跟踪文件被 .gitignore 命中（本仓不设特例）
# ---------------------------------------------------------------------------
chk_tracked_ignored() {
    local hits=() l
    while IFS= read -r l; do [ -n "$l" ] && hits+=("$l"); done < <(git ls-files -ci --exclude-standard)
    report no-tracked-ignored $(( ${#hits[@]} ? 1 : 0 )) "${hits[@]}"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--update-debt-baseline" ]; then
    load_baseline; write_baseline; exit 0
fi
if [ $# -ne 0 ]; then echo "usage: check_tree.sh [--update-debt-baseline]" >&2; exit 2; fi

echo "== check_tree: $root =="
load_baseline
chk_artifacts
chk_elf
chk_debt
chk_secrets
chk_reports
chk_junk
chk_ignore
chk_untracked
chk_tracked_ignored
echo
echo "SUMMARY: pass=$PASS fail=$FAIL"
if [ "$FAIL" -ne 0 ]; then
    printf 'FAILED: %s\n' "${FAILED[*]}"
    echo "see docs/TREE-CHARTER.md section 4 (pre-commit checklist)."
    exit 1
fi
echo "ALL PASS"
