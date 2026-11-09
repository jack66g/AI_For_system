#!/bin/bash
# AIKernel agent current test runner (alpha.12.0 baseline).
# Run from agent/ai:  bash tests/run_all.sh
# Builds the full tests/Makefile suite and runs the non-root unit tests.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
agent=$(CDPATH= cd -- "$here/.." && pwd)
cd "$here" || exit 1

echo "== build tests =="
if ! make -j1; then
    echo "BUILD FAILED" >&2
    exit 1
fi

# The tests default --agent-dir to "."; provide the required ai symlink.
if [ ! -e "$agent/ai" ]; then
    ln -sf aikernel-shell "$agent/ai" 2>/dev/null || true
fi

tests=(
    test_clarify test_lease test_lease_gate
    test_w77_route test_w77_offline test_w77_offline_gate
    test_workspace test_workspace_backend test_desktop_tools test_sandbox_tools test_exec_contract test_exec_risk_matrix
    test_ask_autocompact test_compact_loop test_compact_20turns
    test_router_activation test_router_cap test_max_rounds
    test_ask_status_budget test_prompt_policy
    test_memory_api test_trace test_toolname_map
    test_utf8_body test_http_retry test_cloud_stream test_provider_stream
    test_parallel_toolcalls test_toolcall_backfill
    test_sandbox_programming test_sme_degraded test_export_path
    test_paste_merge test_ask_repair test_memory_degraded_all test_streams test_tls_srv test_macros test_net_admin
    test_sched test_bpf test_net_intent test_net_hit test_app_profile
    test_net_chain test_workspace_net test_range test_app_ctl
    test_app_policy test_device_tools test_compat test_telemetry_rate
)

pass=0
fail=0
failed=()
for t in "${tests[@]}"; do
    if [ ! -x "./$t" ]; then
        echo "MISSING $t"
        fail=$((fail + 1))
        failed+=("$t")
        continue
    fi
    if timeout 120 "./$t" > "/tmp/aik-$t.log" 2>&1; then
        printf "PASS %s\n" "$t"
        pass=$((pass + 1))
    else
        printf "FAIL %s (see /tmp/aik-%s.log)\n" "$t" "$t"
        fail=$((fail + 1))
        failed+=("$t")
    fi
done

echo "== shell/Makefile dependency test =="
if timeout 30 ./test_make_deps.sh > /tmp/aik-test-make-deps.log 2>&1; then
    echo "PASS test_make_deps"
    pass=$((pass + 1))
else
    echo "FAIL test_make_deps (see /tmp/aik-test-make-deps.log)"
    fail=$((fail + 1))
    failed+=("test_make_deps")
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "== root-only sysctl test =="
    if timeout 120 ./test_sysctl_tools > /tmp/aik-test_sysctl_tools.log 2>&1; then
        echo "PASS test_sysctl_tools"
        pass=$((pass + 1))
    else
        echo "FAIL test_sysctl_tools (see /tmp/aik-test_sysctl_tools.log)"
        fail=$((fail + 1))
        failed+=("test_sysctl_tools")
    fi
else
    echo "SKIP test_sysctl_tools (requires root)"
fi

echo "== API / clarify contract tests =="
# T9e 口径换代（aikernel-shell 出厂移除，OPENCODE-PLAN §0 裁定 #1）：
#   退役 2 项——test_clarify_gate.py / test_api_clarify_e2e.py 依赖真
#   `ai`（aikernel-shell）二进制走 ask→clarify→exec 闭环；该链已非出厂
#   能力（镜像内 /usr/local/bin/ai 移除 → aikkernel-api /ask 502 人话报错），
#   测试对象为已退役产品面。退役非因失败：repo 仍构建 shell 时两测技术上
#   仍可过——按任务书裁定随移除退役，分母如实记账（59 −2 + 新增）。
#   保留：test_api_clarify.py（AIKERNEL_AI_BIN=mock，不依赖真 shell）。
cd "$agent" || exit 1
for spec in \
    "tests/test_api_clarify.py" \
    "tests/test_registry_manifest.py" \
    'tests/test_corpus_aliases.py' \
    'tests/test_tls_gateway.py' \
    'tests/test_t9e_entry.py'
do
    # shellcheck disable=SC2086
    if timeout 300 python3 $spec > "/tmp/aik-$(basename "$spec" .py).log" 2>&1; then
        echo "PASS $spec"
        pass=$((pass + 1))
    else
        echo "FAIL $spec (see /tmp/aik-$(basename "$spec" .py).log)"
        fail=$((fail + 1))
        failed+=("$spec")
    fi
done

echo "== T9e factory gate (ac 三件出厂资产) =="
# 门依赖 autocondense 构建产物；先构建（复核指引在 flock 下跑 run_all，
# 此处不再嵌套 flock 防死锁）。构建失败 → 门因二进制缺失如实 FAIL。
make -C "$agent/autocondense" all > /tmp/aik-ac-build.log 2>&1
if timeout 120 bash "$agent/occ/tests/t9d_factory_gate.sh" \
        > /tmp/aik-t9d_factory_gate.log 2>&1; then
    echo "PASS t9d_factory_gate"
    pass=$((pass + 1))
else
    echo "FAIL t9d_factory_gate (see /tmp/aik-t9d_factory_gate.log)"
    fail=$((fail + 1))
    failed+=("t9d_factory_gate")
fi

if timeout 60 python3 tools/audit_capabilities.py --check > /tmp/aik-audit.log 2>&1; then
    echo "PASS audit_capabilities --check"
    pass=$((pass + 1))
else
    echo "FAIL audit_capabilities --check (see /tmp/aik-audit.log)"
    fail=$((fail + 1))
    failed+=("audit_capabilities")
fi

echo
echo "SUMMARY: pass=$pass fail=$fail"
if [ "$fail" -ne 0 ]; then
    printf 'FAILED: %s\n' "${failed[*]}"
    exit 1
fi
echo "ALL PASS"
