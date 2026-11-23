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

# ---- Gate 0: tree charter (docs/TREE-CHARTER.md section 4) ----------------
# Runs first: tracked build artifacts, non-whitelisted ELFs, new hardcoded
# environment addresses, secrets and stray run reports must never reach a commit.
echo "== tree charter gate (docs/TREE-CHARTER.md) =="
if timeout 120 bash "$agent/tools/check_tree.sh" > /tmp/aik-tree-charter.log 2>&1; then
    echo "PASS tree-charter"
    pass=$((pass + 1))
else
    echo "FAIL tree-charter (see /tmp/aik-tree-charter.log)"
    fail=$((fail + 1))
    failed+=("tree-charter")
fi

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

echo "== ORCH-E9 orch loop drill (回路自动化: 派发-验收-回炉-压缩-蒸馏) =="
# make target 自带 occ/test_orch 依赖构建（首次较慢）；演练全在
# /tmp 夹具（OCC_DB/OCC_SESSIONS_DIR/OCC_SNAPROOT 指临时目录）。
if timeout 300 make -C "$agent/occ" orch-drill > /tmp/aik-orch-drill.log 2>&1; then
    echo "PASS orch_drill"
    pass=$((pass + 1))
else
    echo "FAIL orch_drill (see /tmp/aik-orch-drill.log)"
    fail=$((fail + 1))
    failed+=("orch_drill")
fi

echo "== C1 compat classification bench (COMPAT-C1-DESIGN §3.3) =="
# 第 62 门：20 样本分类台架，python3 直跑、无 rig 依赖；probe 指向仓内
# 构建件 ../aik-compat（门测当前构建，非可能陈旧的装机副本；与 test_*
# 门从构建目录跑二进制同口径）。仓内件缺失（未 make）/缺 gcc
# = 如实 FAIL 非跳过（能力真实，不静默降级）。
if AIK_COMPAT_PROBE="$agent/aik-compat" \
   timeout 300 python3 "$here/c1_compat_samples.py" > /tmp/aik-c1_compat_samples.log 2>&1; then
    echo "PASS c1_compat_samples"
    pass=$((pass + 1))
else
    echo "FAIL c1_compat_samples (see /tmp/aik-c1_compat_samples.log)"
    fail=$((fail + 1))
    failed+=("c1_compat_samples")
fi

echo "== C2 compat dual-account bench (COMPAT-C2-DESIGN §1 棒3) =="
# 第 63 门：双账户台架 default 模式（非 root）：AIKERNEL_COMPAT_ROOT 指向
# mktemp 临时根零全局副作用（台架内自建自清）；账户①=可修类 13 样本
# aikctl compat plan→adapter 落盘+manifest 九字段完整率 100% 机判，
# 账户②=不可修类 10 样本零静默成功（拒绝输出带 code/layer 人话）。
# probe 沿第 62 门口径指向仓内构建件；aikctl 由台架按 probe 兄弟路径
# （aikctl/aikctl）自解析。--live root 全链（apply/verify/rollback+回滚
# 六条+promote 三轮）由主会话 sudo -n 亲跑，不进 run_all。仓内件缺失
# （未 make）/缺 gcc/缺 aikctl = 如实 FAIL 非跳过。
if AIK_COMPAT_PROBE="$agent/aik-compat" \
   timeout 420 python3 "$here/c2_compat_samples.py" > /tmp/aik-c2_compat_samples.log 2>&1; then
    echo "PASS c2_compat_samples"
    pass=$((pass + 1))
else
    echo "FAIL c2_compat_samples (see /tmp/aik-c2_compat_samples.log)"
    fail=$((fail + 1))
    failed+=("c2_compat_samples")
fi

echo "== C3 L3/L4/L5 bench (COMPAT-C3-DESIGN §4) =="
# 第 64 门：C3 台架 default 模式（非 root）：账户①层名 L3（§0 唯一口径，
# 与 Lane-1 compat_tools.c 面合同联调——其未合入的工树本账户对真 probe
# 如实红，期望按设计册冻结不因工树态调低/标注转绿）、②L3 缺席态机判
# （AIK_QEMU_USER_AARCH64=/nonexistent）+plan 透传诚实、③L4 五类 probe 级
# 判定表（aikctl compat hw --fixture/真机只读双路）、④L5 门机制全链
# （propose→list→错短语拒→批准→install 恒 dry-run→未批准拒负例→账本
# 四事件+行链校验+篡改检出；AIKMODULE_DIR/AIKERNEL_CONFIRM_DIR 指临时
# 目录零全局副作用）。probe 沿第 62/63 门口径指向仓内构建件；aikctl 由
# 台架按 probe 兄弟路径（aikctl/aikctl）自解析。--live root 三面（真
# aarch64 全链+hw 真机+L5 真目录）由主会话 sudo -n 亲跑，不进 run_all。
# 仓内件缺失（未 make）/缺 aikctl = 如实 FAIL 非跳过。
if AIK_COMPAT_PROBE="$agent/aik-compat" \
   timeout 420 python3 "$here/c3_compat_samples.py" > /tmp/aik-c3_compat_samples.log 2>&1; then
    echo "PASS c3_compat_samples"
    pass=$((pass + 1))
else
    echo "FAIL c3_compat_samples (see /tmp/aik-c3_compat_samples.log)"
    fail=$((fail + 1))
    failed+=("c3_compat_samples")
fi

echo "== L1 data three-layer bench (DATA-L1-DESIGN §4) =="
# 第 65 门：L1 数据三层台架 default 模式（非 root）三账户：①评分/
# promotion（aistreamd 短跑+ai_inject 混合 fixture 流→telemetry v3 13 列
# +promotion 率 5-15% 带内+flags 缺失位+curated 落盘+SME 死端口计数
# 诚实）；②三层保留（预植目录树+AS_ONCE 单事件短跑→TTL 边界/cat 覆盖/
# 当天永不删/curated 独立/异物保护+journal 台账）；③corpus（aikctl
# dataset list/export soft 脱敏门+corpus .aikcorp+manifest+aik-gcm dec
# 逐字节往返+delete 双发确认门+mock SME 批量 DELETE）。门内环境自足：
# AIKCTL/AIK_GCM/AISTREAMD/AI_INJECT 指仓内构建件（门测当前构建，非
# 可能陈旧的装机副本）。C13=真产物集成探针（aistreamd 实产 ai_*.parquet
# 命名 vs aikctl dataset 读契约）——未修读契约的树上如实红（期望冻结
# 不调低，c3 台「如实红」同款纪律）。仓内件缺失（未 make）/缺
# pyarrow = 如实 FAIL 非跳过。
if AIKCTL="$agent/aikctl/aikctl" AIK_GCM="$agent/aik-gcm" \
   AISTREAMD="$agent/aistreamd/aistreamd" \
   AI_INJECT="$agent/aistreamd/tests/ai_inject" \
   timeout 600 python3 "$here/l1_data_bench.py" > /tmp/aik-l1_data_bench.log 2>&1; then
    echo "PASS l1_data_bench"
    pass=$((pass + 1))
else
    echo "FAIL l1_data_bench (see /tmp/aik-l1_data_bench.log)"
    fail=$((fail + 1))
    failed+=("l1_data_bench")
fi

echo "== M1 AI fast-path bench (AIPD-M1-DESIGN §2.3) =="
# 第 66 门：M1 毫秒级快路径台架（非 root）四件：①p99——aipd bench
# --n 10000（mock 源+内置表）解析 AIPD_BENCH 行断言 p99_ns<1ms；②CPU
# ——mock 源起 aipd 30s，/proc/<pid>/stat utime+stime 折算 <1%（附
# TERM 优雅退出于查）；③不一致率口径——mock 双流 fixture 喂 aipd
# mismatch 计算路径（无该子命令面则台架同公式退化实现，输出明示走
# 哪条路——口径演示，真值=rig/VM E2E 登记）；④降级演练——起→
# SIGKILL→lock 释放（flock 非阻塞可获）/stats 终态静止/影子目录无
# ACT 痕迹/参数面零写（/sys/kernel/ai/policy 快照 hash；宿主无该面
# 则该项如实 SKIP 标注）。前置自检缺件（aipd 未 make——Lane-A 未
# 合入的树上）=如实 FAIL 非跳过（c3 台「如实红」同款纪律，期望冻结
# 不因工树态调低）。conf 全 mktemp 临时根零全局副作用。
if AIK_AIPD_BIN="$agent/aipd/aipd" \
   timeout 600 python3 "$here/m1_bench.py" > /tmp/aik-m1_bench.log 2>&1; then
    echo "PASS m1_bench"
    pass=$((pass + 1))
else
    echo "FAIL m1_bench (see /tmp/aik-m1_bench.log)"
    fail=$((fail + 1))
    failed+=("m1_bench")
fi

echo "== M2 canary/A-B/signed-table release pipeline bench (AIPD-M2-DESIGN §7) =="
# 第 67 门：M2 发布管线台架（非 root）六件分账：B1 误决策——≥120 标注
# 向量（table_spec.json 语义：命中/边界/信任门跳过/stale；oracle=台架
# 侧独立实现）灌 FEAT_SOURCE=mock 跑 aipd → 影子 parquet decision_type
# 对标签 err=0；B4 合同——未知 canary 键 exit 1（M1 契约一切未知键均
# 拒）+ENABLED 缺省=0 时 M1 等价（canary_dispatched=0/executed 全 0，
# M1 aipd 现在跑绿，Lane-A 合入后同断言兼容）；B5 table-verify python
# 侧（aikctl aipd table-verify 合法+三种非法同裁定）；B6 aikctl aipd
# release/rollback 台账回合（沙箱 AIKERNEL_AIPD_ROOT+--conf 临时文件，
# 不碰真 /etc/真 root）。B2 A/B/B3 签名门/B5 C 侧依赖 Lane-A
# CANARY_TABLE 面（M1 aipd 无该键）——断言写全、--integration 由主
# 会话集成期亲跑，默认模式 M2_DEFERRED 行如实列清单（不冒充跳过绿）。
# 前置自检缺件（aipd/aikctl 未 make、缺 pyarrow、table_spec 不可解析）
# =如实 FAIL 非跳过。AIK_AIPD_BIN/AIKCTL 沿第 65/66 门指仓内构建件。
if AIK_AIPD_BIN="$agent/aipd/aipd" AIKCTL="$agent/aikctl/aikctl" \
   timeout 600 python3 "$here/m2_bench.py" > /tmp/aik-m2_bench.log 2>&1; then
    echo "PASS m2_bench"
    pass=$((pass + 1))
else
    echo "FAIL m2_bench (see /tmp/aik-m2_bench.log)"
    fail=$((fail + 1))
    failed+=("m2_bench")
fi

# ---- 第 68 门：G1 解析器 fuzz（三族×确定性变异；崩溃=红 人话=绿）----
if FUZZ_CASES=30 timeout 300 python3 "$here/fuzz_parsers.py" \
        > /tmp/aik-fuzz.log 2>&1; then
    echo "PASS fuzz_parsers"
    pass=$((pass + 1))
else
    echo "FAIL fuzz_parsers (see /tmp/aik-fuzz.log)"
    fail=$((fail + 1))
    failed+=("fuzz_parsers")
fi

# ---- 第 69 门：S 棒红队攻击钻证（恶意 shim/提示注入/外泄/快照篡改）----
echo "== S-track redteam drill =="
if timeout 300 python3 "$here/redteam/redteam_drill.py" \
        > /tmp/aik-redteam.log 2>&1; then
    echo "PASS redteam_drill"
    pass=$((pass + 1))
else
    echo "FAIL redteam_drill (see /tmp/aik-redteam.log)"
    fail=$((fail + 1))
    failed+=("redteam_drill")
fi

echo
echo "SUMMARY: pass=$pass fail=$fail"
if [ "$fail" -ne 0 ]; then
    printf 'FAILED: %s\n' "${failed[*]}"
    exit 1
fi
echo "ALL PASS"
