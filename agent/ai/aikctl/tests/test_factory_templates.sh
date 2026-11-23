#!/bin/sh
# test_factory_templates.sh - 出厂模板骨架回归（P-60 11-22 夜修复 4 等；
# 无需 root，任何用户可跑）。
#
# 背景：aik-reset 的出厂 model.toml 模板曾零 [models.*] 段——复位后 occ
# TUI 槽位解析（occ_provider_load_chain 全链空=-1 硬拒）先于 gate，
# rc=1 死循环（17.11 装机台架咬出）。本测试从 factory/usr/local/sbin/
# aik-reset 抽出 write_factory_model_toml 的 heredoc，断言骨架齐；并钉
# 出厂 SENSE 脱敏档（aistreamd.conf）与 policy 三段（policy.conf）。
#
# 断言面：
#   1. aik-reset bash -n 语法门；heredoc 抽得出（非空、行数合理）
#   2. heredoc：[default] model="cloud"／[ui]／[api] sense_redact="soft"／
#      [models.cloud] 段含 provider_type/base_url/model_name/api_key
#   3. aistreamd.conf：SENSE_REDACT=soft（与模板 [api] 同出厂默认）
#   4. policy.conf：[root]/[wheel]/[default] 三段各带 mode = 
set -u
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../../../.." && pwd)
RESET="$repo/factory/usr/local/sbin/aik-reset"
ASCONF="$repo/factory/etc/aikernel/aistreamd.conf"
POLCONF="$repo/factory/etc/aikernel/policy.conf"

pass=0
fail=0
ck() { # ck <描述> <条件（已展开的 test 表达式串）>
    if eval "$2"; then
        pass=$((pass+1)); echo "  PASS $1"
    else
        fail=$((fail+1)); echo "  FAIL $1"
    fi
}

echo "== 0. 出厂件在位 =="
ck "aik-reset 在" "[ -f '$RESET' ]"
ck "aistreamd.conf 在" "[ -f '$ASCONF' ]"
ck "policy.conf 在" "[ -f '$POLCONF' ]"

echo "== 1. aik-reset 语法门 + heredoc 抽取 =="
bash -n "$RESET"
ck "bash -n rc=0" "[ '$?' = 0 ]"
# write_factory_model_toml 的 heredoc：函数体内的 <<'EOF' … EOF（独占行）
tmpl=$(awk '/^write_factory_model_toml\(\)/{f=1} f && /<<.EOF.$/{p=1; next} p && /^EOF$/{exit} p' "$RESET")
nlines=$(printf '%s\n' "$tmpl" | grep -c '')
ck "heredoc 抽得出（非空）" "[ '$nlines' -ge 1 ]"
ck "heredoc 行数 ≥ 30（实测 $nlines）" "[ '$nlines' -ge 30 ]"

echo "== 2. 出厂 model.toml 模板骨架（heredoc） =="
# 段抽取：自 [section] 行到下一个 [ 段头前
sec() { printf '%s\n' "$tmpl" | awk -v s="$1" '$0==s{f=1; next} f && /^\[/{exit} f'; }
ck "[default] 段在且 model = \"cloud\"" \
   "printf '%s\n' \"\$(sec '[default]')\" | grep -q '^model = \"cloud\"'"
ck "[ui] 段在（非空）" "[ -n \"\$(sec '[ui]')\" ]"
ck "[api] 段在且 sense_redact = \"soft\"" \
   "printf '%s\n' \"\$(sec '[api]')\" | grep -q '^sense_redact = \"soft\"'"
ck "[models.cloud] 段在" "[ -n \"\$(sec '[models.cloud]')\" ]"
ck "[models.cloud] 含 provider_type" \
   "printf '%s\n' \"\$(sec '[models.cloud]')\" | grep -q '^provider_type = '"
ck "[models.cloud] 含 base_url（resolve 必填项）" \
   "printf '%s\n' \"\$(sec '[models.cloud]')\" | grep -q '^base_url = '"
ck "[models.cloud] 含 model_name" \
   "printf '%s\n' \"\$(sec '[models.cloud]')\" | grep -q '^model_name = '"
ck "[models.cloud] 含 api_key" \
   "printf '%s\n' \"\$(sec '[models.cloud]')\" | grep -q '^api_key = '"
# [models.cloud] 段只此一段在模板里（无 [models.local]——装机后自动生成）
ck "模板无 [models.local] 段（装机后自动生成）" \
   "! printf '%s\n' \"\$tmpl\" | grep -q '^\\[models\\.local\\]'"

echo "== 3. aistreamd.conf 出厂脱敏档 =="
ck "SENSE_REDACT=soft" "grep -q '^SENSE_REDACT=soft\$' '$ASCONF'"
ck "与模板 [api] sense_redact 同档（两面同为 soft）" \
   "printf '%s\n' \"\$(sec '[api]')\" | grep -q '^sense_redact = \"soft\"' && grep -q '^SENSE_REDACT=soft\$' '$ASCONF'"

echo "== 4. policy.conf 三段 =="
psec() { awk -v s="$1" '$0==s{f=1; next} f && /^\[/{exit} f' "$POLCONF"; }
ck "[root] 段带 mode =" "[ -n \"\$(psec '[root]' | grep '^mode[[:space:]]*=')\" ]"
ck "[wheel] 段带 mode =" "[ -n \"\$(psec '[wheel]' | grep '^mode[[:space:]]*=')\" ]"
ck "[default] 段带 mode =" "[ -n \"\$(psec '[default]' | grep '^mode[[:space:]]*=')\" ]"

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
