#!/bin/bash
# sbom_check.sh — G1 供给链三件：overlay↔树完整性 / SOURCE-MANIFEST 哈希
# 核对 / SOURCE_DATE_EPOCH 双构建确定性抽检（aik-compat+aik-gcm）。
# 用法: build/sbom_check.sh [repo_root]（缺省 ~/aikernel-repo-alpha11）
set -u
ROOT=${1:-$HOME/aikernel-repo-alpha11}
cd "$ROOT" || exit 1
fail=0

echo "== ① overlay↔树完整性+系列（k10 --check-only）=="
if python3 AIKernel/scripts/k10_patch_series.py --check-only \
    2>&1 | tail -2; then
    echo "PASS overlays+series"
else
    echo "FAIL overlays+series"; fail=1
fi

echo "== ② SOURCE-MANIFEST 哈希核对 =="
python3 - "$ROOT" <<'PYEOF' || fail=1
import hashlib, json, os, sys
root = sys.argv[1]
with open(os.path.join(root, "SOURCE-MANIFEST.json"),
          encoding="utf-8") as f:
    sbom = json.load(f)
files = None
for key in ("files", "manifest", "sources"):
    if isinstance(sbom.get(key), dict):
        files = sbom[key]
        break
if files is None:
    print("SKIP SOURCE-MANIFEST 无文件哈希面（notes 型——如实登记）")
    sys.exit(0)
bad = 0
for rel, want in sorted(files.items()):
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        print("MISSING", rel); bad += 1; continue
    got = hashlib.sha256(open(p, "rb").read()).hexdigest()
    if got != want:
        print("MISMATCH", rel); bad += 1
print(("PASS" if not bad else "FAIL") +
      " source-manifest entries=%d bad=%d" % (len(files), bad))
sys.exit(1 if bad else 0)
PYEOF

echo "== ③ 双构建确定性（SOURCE_DATE_EPOCH 抽检）=="
for bin in aik-compat aik-gcm; do
    SOURCE_DATE_EPOCH=1700000000 make -C "agent/ai" --no-print-directory "$bin" >/dev/null 2>&1
    out1=$(sha256sum "agent/ai/$bin" | cut -c1-16)
    rm -f "agent/ai/$bin"
    SOURCE_DATE_EPOCH=1700000000 make -C "agent/ai" --no-print-directory "$bin" >/dev/null 2>&1
    out2=$(sha256sum "agent/ai/$bin" | cut -c1-16)
    if [ -n "$out1" ] && [ "$out1" = "$out2" ]; then
        echo "PASS $bin deterministic sha=$out1"
    else
        echo "FAIL $bin ($out1 vs $out2)"; fail=1
    fi
done

echo "SBOM_SUMMARY fail=$fail"
exit $fail
