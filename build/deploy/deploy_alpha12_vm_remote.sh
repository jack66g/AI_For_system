#!/bin/bash
# alpha.12 remote installer (runs on the production VM as root).
# Installs userland + seed(173) + model catalog + aik-reset/motd, removes the
# preloaded qwen2.5:1.5b (W77d: local models are install-on-demand), neutralizes
# [local] in model.toml (never touches [models.cloud]), restarts aikernel-api only.
# Never reboots the VM and never touches the kernel/A-B slots.
set -euo pipefail

[ "${AIK_ALPHA12_CONFIRM:-}" = "1" ] || {
    echo "refusing: AIK_ALPHA12_CONFIRM=1 required" >&2
    exit 2
}

STAGE=/root/aik-alpha12-stage
TS="$(date +%Y%m%dT%H%M%S)"
BAK="/root/aik-alpha12-backup-$TS"
BOOT_BEFORE="$(cat /proc/sys/kernel/random/boot_id)"
FAIL=0

fail() { echo "DEPLOY_FAIL: $*" >&2; FAIL=1; }
need_eq() {
    local label="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        echo "OK $label=$got"
    else
        fail "$label got=$got want=$want"
    fi
}
md5of() { md5sum "$1" | cut -d' ' -f1; }
check_md5() {
    local path="$1" want="$2" got
    got="$(md5of "$path")"
    need_eq "md5:$path" "$got" "$want"
}

[ -f "$STAGE/aikernel-shell" ] || { echo "missing stage" >&2; exit 2; }
mkdir -p "$BAK"
backup_file() {
    local path="$1"
    [ -e "$path" ] || return 0
    mkdir -p "$BAK$(dirname "$path")"
    cp -a "$path" "$BAK$path"
}
for f in \
    /usr/local/bin/ai \
    /usr/local/bin/aikernel-shell \
    /usr/local/sbin/aikernel-api \
    /usr/local/sbin/aik-reset \
    /usr/local/share/aikernel/tools.json \
    /etc/aikernel/tools.json \
    /usr/local/share/aikernel/tools.openai.json \
    /usr/local/share/aikernel/tools-sandbox.json \
    /usr/local/share/aikernel/tool_catalog.txt \
    /usr/local/share/aikernel/sme-seed.jsonl \
    /usr/local/share/aikernel/model-catalog.json \
    /etc/motd \
    /root/.aikernel/model.toml \
    /etc/passwd /etc/group /etc/shadow; do
    backup_file "$f"
done
{
    echo "backup=$BAK"
    echo "boot_id=$BOOT_BEFORE"
    echo "uptime_before=$(uptime)"
    echo "ollama_models_before:"; ollama list 2>/dev/null || true
    df -h / | tail -1
} > "$BAK/pre-state.txt"
echo "BACKUP=$BAK"

echo "== binaries/tools/seed/catalog =="
install -m 0755 "$STAGE/aikernel-shell" /usr/local/bin/aikernel-shell
install -m 0755 "$STAGE/aikernel-shell" /usr/local/bin/ai
install -m 0644 "$STAGE/tools.json" /usr/local/share/aikernel/tools.json
install -m 0644 "$STAGE/tools.json" /etc/aikernel/tools.json
install -m 0644 "$STAGE/tools.openai.json" /usr/local/share/aikernel/tools.openai.json
install -m 0644 "$STAGE/tools-sandbox.json" /usr/local/share/aikernel/tools-sandbox.json
install -m 0644 "$STAGE/tool_catalog.txt" /usr/local/share/aikernel/tool_catalog.txt
install -m 0644 "$STAGE/sme-seed.jsonl" /usr/local/share/aikernel/sme-seed.jsonl
install -m 0644 "$STAGE/model-catalog.json" /usr/local/share/aikernel/model-catalog.json
install -m 0755 "$STAGE/aik-reset" /usr/local/sbin/aik-reset
install -m 0644 "$STAGE/motd" /etc/motd

check_md5 /usr/local/bin/ai 784cc0f014409cfdd8186f95c557dcd0
check_md5 /usr/local/bin/aikernel-shell 784cc0f014409cfdd8186f95c557dcd0
check_md5 /usr/local/share/aikernel/tools.json eca2739901173bcf6505420bbf7d186d
check_md5 /etc/aikernel/tools.json eca2739901173bcf6505420bbf7d186d
check_md5 /usr/local/share/aikernel/tools.openai.json d5fedb738f5e4e56290dcbe67b26f055
check_md5 /usr/local/share/aikernel/tools-sandbox.json 226233e4d143db8a513bd136a6caae46
check_md5 /usr/local/share/aikernel/tool_catalog.txt 39be07cec5b3670591838e97a87563b6
check_md5 /usr/local/share/aikernel/sme-seed.jsonl 59e5ee4a87576320750cc05381e9871f
check_md5 /usr/local/share/aikernel/model-catalog.json 07fd7274227ff531a71f0bd4fb631de7
need_eq "seed_lines" "$(wc -l < /usr/local/share/aikernel/sme-seed.jsonl)" 173
need_eq "shell_version" "$(/usr/local/bin/ai --version 2>&1 | head -1)" \
    "ai (AIKernel Shell) 0.1.0-alpha.12.0"

echo "== seed differential import (167 -> 173) =="
systemctl start sme-seed.service || fail "sme-seed.service start"
tail -n 10 /tmp/sme-seed.log || true
grep -qE 'seed=173|total=173|added=6' /tmp/sme-seed.log \
    || fail "seed 173/added=6 not in log"
grep -q 'done rc=0' /tmp/sme-seed.log || fail "seed rc!=0"

echo "== W77d: remove preloaded local model, neutralize [local] =="
OLLAMA_MODELS_BEFORE="$(ollama list 2>/dev/null | grep -c '^qwen2.5:1.5b' || true)"
if [ "$OLLAMA_MODELS_BEFORE" -gt 0 ]; then
    ollama rm qwen2.5:1.5b || fail "ollama rm qwen2.5:1.5b"
fi
need_eq "ollama_qwen_gone" "$(ollama list 2>/dev/null | grep -c 'qwen2.5:1.5b' || true)" 0
# Only touch the [local] block; [models.cloud] and its api_key are never read,
# printed or modified here.
sed -i '/^\[local\]$/,/^\[/ { s/^enabled *= *.*/enabled = false/; s/^model *= *.*/model = ""/; }' \
    /root/.aikernel/model.toml
python3 - <<'PY' || fail "model.toml [local] neutralize"
import re
s = open('/root/.aikernel/model.toml', encoding='utf-8').read()
m = re.search(r'\[local\](.*?)(?=^\[)', s, re.S | re.M)
assert m, "no [local] section"
blk = m.group(1)
assert re.search(r'^enabled *= *false', blk, re.M), "enabled!=false"
assert re.search(r'^model *= *""', blk, re.M), 'model!=""'
cloud = s.split('[models.cloud]', 1)
assert len(cloud) == 2, "[models.cloud] still present"
print("local_neutralized_ok")
PY
need_eq "model_toml_perm" "$(stat -c '%a' /root/.aikernel/model.toml)" 600
need_eq "offline_intents" "$(grep -c '^offline_intents = true' /root/.aikernel/model.toml || true)" 1
need_eq "prefer_local_cloud_first" "$(grep -c '^prefer_local = false' /root/.aikernel/model.toml || true)" 1

echo "== api restart =="
systemctl restart aikernel-api
for _ in $(seq 1 20); do
    state="$(systemctl is-active aikernel-api || true)"
    [ "$state" = "active" ] && break
    sleep 1
done
need_eq "aikernel-api" "$(systemctl is-active aikernel-api || true)" active

TOKEN="$(cat /etc/aikernel/api-token)"
api_get() { curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$1"; }
api_code() { curl -sS -m 10 -o /tmp/a12-body -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$1"; }

for _ in $(seq 1 20); do
    code="$(api_code http://127.0.0.1:8761/health || true)"
    [ "$code" = "200" ] && break
    sleep 1
done
need_eq "api_health" "$code" 200
api_get http://127.0.0.1:8761/health | grep -q '"status": "ok"' \
    || fail "api health body"

api_get http://127.0.0.1:8761/tools > /tmp/a12-tools.json
read -r TOOL_COUNT TOOL_LISTED DESKTOP_N MODEL_N < <(
    python3 - <<'PY'
import json
d = json.load(open('/tmp/a12-tools.json', encoding='utf-8'))
names = [t['name'] for t in d.get('tools', [])]
print(d.get('tool_count'), d.get('count'),
      sum(1 for n in names if n.startswith('desktop_')),
      sum(1 for n in names if n.startswith('model_')))
PY
)
need_eq "api_tool_count" "$TOOL_COUNT" 156
need_eq "api_tool_listed" "$TOOL_LISTED" 156
need_eq "desktop_registered" "$DESKTOP_N" 20
need_eq "model_tools_registered" "$MODEL_N" 5
api_get http://127.0.0.1:8761/health | grep -q '"/clarify"' \
    || fail "api health missing /clarify"
CLARIFY_CODE="$(curl -sS -m 10 -o /tmp/a12-clarify -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"nonce":"cq-deadbeef","session":"api-deadbeefdeadbeef","selection":["1"]}' \
    http://127.0.0.1:8761/clarify || true)"
need_eq "api_clarify_unknown" "$CLARIFY_CODE" 404

echo "== model lifecycle smoke =="
printf 'model catalog\nexit\n' | timeout 30 /usr/local/bin/aikernel-shell \
    > /tmp/a12-catalog.out 2>&1 || fail "shell model catalog"
grep -q 'spark-x2.5:4b' /tmp/a12-catalog.out || fail "catalog missing spark-x2.5:4b"
grep -q 'entries' /tmp/a12-catalog.out || fail "catalog entries line"
printf 'model recommend\nexit\n' | timeout 30 /usr/local/bin/aikernel-shell \
    > /tmp/a12-recommend.out 2>&1 || fail "shell model recommend"
grep -qi 'recommend\|fit' /tmp/a12-recommend.out || fail "recommend output"

echo "== desktop unchanged (verify only) =="
need_eq "desktop_active" "$(systemctl is-active aik-desktop || true)" active
need_eq "desktop_enabled" "$(systemctl is-enabled aik-desktop || true)" enabled
code="$(curl -sS -m 8 -o /tmp/a12-dh -w '%{http_code}' http://127.0.0.1:8091/api/health || true)"
need_eq "desktop_health" "$code" 200
need_eq "desktop_loopback" \
    "$(ss -ltn | grep -c '127.0.0.1:8091' || true)" 1

echo "== core / no-reboot checks =="
printf 'exit\n' | timeout 30 /usr/local/bin/aikernel-shell >/tmp/a12-shell.out 2>&1 \
    || fail "aikernel-shell start"
need_eq "boot_id_unchanged" "$(cat /proc/sys/kernel/random/boot_id)" "$BOOT_BEFORE"
need_eq "failed_units" "$(systemctl --failed --no-legend | wc -l)" 0
echo "uptime_after=$(uptime)"
echo "ollama_models_after:"; ollama list 2>/dev/null || true
df -h / | tail -1

if [ "$FAIL" -ne 0 ]; then
    echo "ROLLBACK_BACKUP=$BAK"
    echo "ROLLBACK_HINT: restore $BAK userland files (incl model.toml), ollama pull qwen2.5:1.5b if needed, systemctl restart aikernel-api."
    exit 1
fi
echo "BACKUP=$BAK"
echo "ALPHA12_REMOTE_OK"
