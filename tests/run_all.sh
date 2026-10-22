#!/bin/bash
# AIKernel agent current test runner (alpha.11.0 baseline).
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
    test_desktop_tools test_sandbox_tools test_exec_contract test_exec_risk_matrix
    test_ask_autocompact test_compact_loop test_compact_20turns
    test_router_activation test_router_cap test_max_rounds
    test_ask_status_budget test_prompt_policy
    test_memory_api test_trace test_toolname_map
    test_utf8_body test_http_retry test_cloud_stream test_provider_stream
    test_parallel_toolcalls test_toolcall_backfill
    test_sandbox_programming test_sme_degraded test_export_path
    test_paste_merge test_ask_repair test_memory_degraded_all
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
cd "$agent" || exit 1
for spec in \
    "tests/test_api_clarify.py" \
    "tests/test_clarify_gate.py --agent-dir ." \
    "tests/test_api_clarify_e2e.py --agent-dir ." \
    "tests/test_registry_manifest.py" \
    "tests/test_corpus_aliases.py"
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
