#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# W48 test runner: 11 existing suites + 3 new W48 suites.
set -u
# 调用者必须已在 agent/ai/tests 目录（脚本不自行 cd，避免 /tmp 干扰）
OUT=/tmp/w48-tests
LOG="$HOME/mbedtls-trim-evidence/logs/fix-w48/tests-w48.log"
mkdir -p "$OUT"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

CC=${CC:-cc}
INC="-I../include -I.. -I../runtime"
CORE="../tools/executor.c ../tools/tool_registry.c ../config/config_manager.c ../shell/commands/model_lifecycle.c ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../cloud/toolname_map.c ../runtime/netlink/ai_netlink_client.c ../memory/sme_client.c ../local/local_http.c ../trace/ai_trace.c"
POL="../policy/ai_user_policy.c"

build_run() {
    name=$1
    shift
    echo "==== build $name ===="
    if ! $CC -Wall -Wextra -std=c11 -O2 "$@" -o "$OUT/$name" "$name.c"; then
        echo "BUILD-FAIL: $name"
        return 1
    fi
    echo "==== run $name ===="
    "$OUT/$name"
    rc=$?
    if [ $rc -eq 0 ]; then echo "RESULT $name: PASS"; else echo "RESULT $name: FAIL($rc)"; fi
    return $rc
}

FAIL=0
build_run test_utf8_body $INC ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c || FAIL=$((FAIL+1))
build_run test_http_retry -I../include -I../local ../local/local_http.c ../runtime/ai_types.c || FAIL=$((FAIL+1))
build_run test_cloud_stream -I../include -DCONFIG_AI_STREAM_MODE -I.. -I../cloud -I../runtime -DMBEDTLS_CONFIG_FILE=\"config/mbedtls-trim.h\" -I../third_party/mbedtls/include ../cloud/provider_openai_compatible.c ../cloud/http/http_client.c ../runtime/communication/stream_parse.c ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c ../third_party/mbedtls/library/libmbedtls.a ../third_party/mbedtls/library/libmbedx509.a ../third_party/mbedtls/library/libmbedcrypto.a -lpthread || FAIL=$((FAIL+1))
build_run test_provider_stream -I../include -DCONFIG_AI_STREAM_MODE -I.. -I../local -I../runtime ../local/provider_local.c ../local/local_chat.c ../local/local_stream.c ../local/local_http.c ../local/ollama_native.c ../runtime/communication/stream_parse.c ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c || FAIL=$((FAIL+1))
build_run test_parallel_toolcalls -I../include -I.. -I../local ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c ../local/ollama_native.c ../local/local_chat.c ../local/local_http.c ../runtime/ai_types.c -lpthread || FAIL=$((FAIL+1))
build_run test_toolcall_backfill $INC ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c || FAIL=$((FAIL+1))
build_run test_toolname_map $INC ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c || FAIL=$((FAIL+1))
build_run test_sandbox_tools $INC test_sandbox_stubs.c ../tools/executor.c ../tools/tool_registry.c ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../cloud/toolname_map.c ../trace/ai_trace.c ../local/local_http.c ../config/config_manager.c ../shell/commands/model_lifecycle.c ../policy/ai_lease.c -lpthread || FAIL=$((FAIL+1))
build_run test_plan_mode $INC -DW42_REAL_POLICY test_sandbox_stubs.c ../tools/executor.c ../tools/tool_registry.c ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../cloud/toolname_map.c ../trace/ai_trace.c ../local/local_http.c $POL ../policy/ai_lease.c ../config/config_manager.c ../shell/commands/model_lifecycle.c -lpthread || FAIL=$((FAIL+1))
build_run test_sme_degraded -I../include -I.. -I../local ../memory/sme_client.c ../local/local_http.c ../runtime/ai_json_util.c ../runtime/ai_types.c -lpthread || FAIL=$((FAIL+1))
build_run test_model_lifecycle $INC ../shell/commands/model_lifecycle.c ../config/config_manager.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../cloud/toolname_map.c ../local/local_http.c -lpthread || FAIL=$((FAIL+1))
build_run test_onboarding_cloud $INC -I../runtime -I../shell/commands ../shell/commands/cmd_onboarding.c ../shell/commands/model_lifecycle.c ../config/config_manager.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../cloud/toolname_map.c ../local/local_http.c ../i18n/lang.c ../runtime/ai_chat_proto.c -lpthread || FAIL=$((FAIL+1))
build_run test_export_path -I../include -I.. -I../local ../memory/sme_client.c ../local/local_http.c ../runtime/ai_json_util.c ../runtime/ai_types.c -lpthread || FAIL=$((FAIL+1))
build_run test_memory_api -I../include -I.. -I../local ../memory/sme_client.c ../local/local_http.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../tools/tool_registry.c ../i18n/lang.c ../cloud/toolname_map.c -lpthread || FAIL=$((FAIL+1))

# W48 new suites
build_run test_risk_grading $INC $CORE ../policy/ai_lease.c $POL -lpthread || FAIL=$((FAIL+1))
build_run test_exec_risk_matrix $INC test_sandbox_stubs.c ../tools/executor.c ../tools/tool_registry.c ../config/config_manager.c ../shell/commands/model_lifecycle.c ../policy/ai_lease.c ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../cloud/toolname_map.c ../trace/ai_trace.c ../local/local_http.c -lpthread || FAIL=$((FAIL+1))
build_run test_sysctl_tools $INC $CORE ../policy/ai_lease.c $POL -lpthread || FAIL=$((FAIL+1))
build_run test_registry_shadow $INC ../tools/tool_registry.c ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../cloud/toolname_map.c || FAIL=$((FAIL+1))

# W55 new suites
build_run test_router_activation -I../include -I.. -I../runtime -I../shell/commands test_ask_stubs.c ../shell/commands/cmd_ask.c ../shell/commands/ask_clarify.c ../shell/commands/ask_context.c ../shell/commands/ask_compact.c ../tools/tool_registry.c ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c -lpthread || FAIL=$((FAIL+1))
build_run test_ask_status_budget -I../include -I.. -I../shell/commands ../shell/commands/ask_context.c ../runtime/ai_json_util.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c ../i18n/lang.c || FAIL=$((FAIL+1))

# W56 new suites
build_run test_prompt_policy -I../include -I.. -I../shell/commands ../shell/commands/ask_context.c ../i18n/lang.c || FAIL=$((FAIL+1))
build_run test_ask_autocompact -I../include -I.. -I../runtime -I../shell/commands test_ask_stubs.c ../shell/commands/cmd_ask.c ../shell/commands/ask_clarify.c ../shell/commands/ask_context.c ../shell/commands/ask_compact.c ../tools/tool_registry.c ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c -lpthread || FAIL=$((FAIL+1))

# W59 new suite: auto-compact loop guard (2 attempts -> truncate)
build_run test_compact_loop -I../include -I.. -I../runtime -I../shell/commands test_ask_stubs.c ../shell/commands/cmd_ask.c ../shell/commands/ask_clarify.c ../shell/commands/ask_context.c ../shell/commands/ask_compact.c ../tools/tool_registry.c ../i18n/lang.c ../runtime/ai_json_util.c ../runtime/ai_types.c ../runtime/ai_chat_proto.c ../cloud/toolname_map.c -lpthread || FAIL=$((FAIL+1))

echo "==== registry manifest self-test ===="
python3 test_registry_manifest.py
[ $? -eq 0 ] || FAIL=$((FAIL+1))

echo "==== corpus aliases self-test (W55 P4) ===="
python3 test_corpus_aliases.py
[ $? -eq 0 ] || FAIL=$((FAIL+1))

echo "==== sysctl legal write (sudo) ===="
if printf '%s\n' "${AIK_SUDO_PASS:-}" | sudo -S "$OUT/test_sysctl_tools" >/tmp/w48-tests/sysctl-root.log 2>&1; then
    cat /tmp/w48-tests/sysctl-root.log
    echo "RESULT sysctl-root: PASS"
else
    cat /tmp/w48-tests/sysctl-root.log
    echo "RESULT sysctl-root: FAIL"
    FAIL=$((FAIL+1))
fi

echo "==== W48 SUMMARY: failures=$FAIL ===="
exit $FAIL
