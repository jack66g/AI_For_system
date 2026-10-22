#!/bin/bash
# alpha.11 remote installer (runs on the production VM as root).
# Installs userland + seed + API + desktop service, restarts aikernel-api only.
# Never reboots the VM and never touches the kernel/A-B slots.
set -euo pipefail

[ "${AIK_ALPHA11_CONFIRM:-}" = "1" ] || {
    echo "refusing: AIK_ALPHA11_CONFIRM=1 required" >&2
    exit 2
}

STAGE=/root/aik-alpha11-stage
TS="$(date +%Y%m%dT%H%M%S)"
BAK="/root/aik-alpha11-backup-$TS"
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
    /usr/local/share/aikernel/tools.json \
    /etc/aikernel/tools.json \
    /usr/local/share/aikernel/tools.openai.json \
    /usr/local/share/aikernel/tools-sandbox.json \
    /usr/local/share/aikernel/tool_catalog.txt \
    /usr/local/share/aikernel/sme-seed.jsonl \
    /etc/passwd /etc/group /etc/shadow; do
    backup_file "$f"
done
if [ -d /opt/aikdesktop ]; then
    mkdir -p "$BAK/opt"
    cp -a /opt/aikdesktop "$BAK/opt/aikdesktop"
fi
if [ -f /etc/systemd/system/aik-desktop.service ]; then
    backup_file /etc/systemd/system/aik-desktop.service
fi
{
    echo "backup=$BAK"
    echo "boot_id=$BOOT_BEFORE"
    echo "uptime_before=$(uptime)"
    md5sum \
        /usr/local/bin/ai \
        /usr/local/bin/aikernel-shell \
        /usr/local/sbin/aikernel-api \
        /usr/local/share/aikernel/tools.json \
        /etc/aikernel/tools.json \
        /usr/local/share/aikernel/tools.openai.json \
        /usr/local/share/aikernel/tools-sandbox.json \
        /usr/local/share/aikernel/tool_catalog.txt \
        /usr/local/share/aikernel/sme-seed.jsonl 2>/dev/null || true
} > "$BAK/pre.md5"
echo "BACKUP=$BAK"

echo "== binaries/tools/seed =="
install -m 0755 "$STAGE/aikernel-shell" /usr/local/bin/aikernel-shell
install -m 0755 "$STAGE/aikernel-shell" /usr/local/bin/ai
install -m 0755 "$STAGE/aikernel-api" /usr/local/sbin/aikernel-api
install -m 0644 "$STAGE/tools.json" /usr/local/share/aikernel/tools.json
install -m 0644 "$STAGE/tools.json" /etc/aikernel/tools.json
install -m 0644 "$STAGE/tools.openai.json" /usr/local/share/aikernel/tools.openai.json
install -m 0644 "$STAGE/tools-sandbox.json" /usr/local/share/aikernel/tools-sandbox.json
install -m 0644 "$STAGE/tool_catalog.txt" /usr/local/share/aikernel/tool_catalog.txt
install -m 0644 "$STAGE/sme-seed.jsonl" /usr/local/share/aikernel/sme-seed.jsonl

check_md5 /usr/local/bin/ai adb71f65c7e60fdcba2ce88da9093546
check_md5 /usr/local/bin/aikernel-shell adb71f65c7e60fdcba2ce88da9093546
check_md5 /usr/local/sbin/aikernel-api e007a7d9d9e8cd9e81ec977d92bd9056
check_md5 /usr/local/share/aikernel/tools.json 34d5af9ca7279e436690169c9af65873
check_md5 /etc/aikernel/tools.json 34d5af9ca7279e436690169c9af65873
check_md5 /usr/local/share/aikernel/tools.openai.json ab7656229c60fcebfab20b55952ae2f2
check_md5 /usr/local/share/aikernel/tools-sandbox.json 25f25c255bb75818f0db09fb80855a25
check_md5 /usr/local/share/aikernel/tool_catalog.txt ad3e216edad31fb16378329d41c3c777
check_md5 /usr/local/share/aikernel/sme-seed.jsonl f93767385a788bfff1a587f1eea2b321
need_eq "seed_lines" "$(wc -l < /usr/local/share/aikernel/sme-seed.jsonl)" 167
need_eq "shell_version" "$(/usr/local/bin/ai --version 2>&1 | head -1)" \
    "ai (AIKernel Shell) 0.1.0-alpha.11.0"

echo "== seed differential import =="
systemctl start sme-seed.service || fail "sme-seed.service start"
tail -n 8 /tmp/sme-seed.log || true
grep -q 'seed=167' /tmp/sme-seed.log || fail "seed=167 not in log"
grep -q 'done rc=0' /tmp/sme-seed.log || fail "seed rc!=0"

echo "== desktop bundle =="
if ! getent group aikdesk >/dev/null; then
    groupadd -g 998 aikdesk
fi
if ! getent passwd aikdesk >/dev/null; then
    useradd -u 998 -g 998 -M -d /var/lib/aikdesktop -s /usr/sbin/nologin aikdesk
fi
need_eq "aikdesk_uid" "$(id -u aikdesk)" 998
install -d -m 0700 -o aikdesk -g aikdesk /var/lib/aikdesktop
tar -C / -xpf "$STAGE/desktop-alpha11.tar"
chown root:root /etc/systemd/system/aik-desktop.service
chmod 0644 /etc/systemd/system/aik-desktop.service
systemctl daemon-reload
systemctl enable aik-desktop
systemctl restart aik-desktop

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
api_code() { curl -sS -m 10 -o /tmp/a10-body -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$1"; }

for _ in $(seq 1 20); do
    code="$(api_code http://127.0.0.1:8761/health || true)"
    [ "$code" = "200" ] && break
    sleep 1
done
need_eq "api_health" "$code" 200
api_get http://127.0.0.1:8761/health | grep -q '"status": "ok"' \
    || fail "api health body"

api_get http://127.0.0.1:8761/tools > /tmp/a10-tools.json
read -r TOOL_COUNT TOOL_LISTED DESKTOP_N < <(
    python3 - <<'PY'
import json
d = json.load(open('/tmp/a10-tools.json', encoding='utf-8'))
names = [t['name'] for t in d.get('tools', [])]
print(d.get('tool_count'), d.get('count'), sum(1 for n in names if n.startswith('desktop_')))
PY
)
need_eq "api_tool_count" "$TOOL_COUNT" 151
need_eq "api_tool_listed" "$TOOL_LISTED" 151
need_eq "desktop_registered" "$DESKTOP_N" 20
api_get http://127.0.0.1:8761/health | grep -q '"/clarify"' \
    || fail "api health missing /clarify"
CLARIFY_CODE="$(curl -sS -m 10 -o /tmp/a11-clarify -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"nonce":"cq-deadbeef","session":"api-deadbeefdeadbeef","selection":["1"]}' \
    http://127.0.0.1:8761/clarify || true)"
need_eq "api_clarify_unknown" "$CLARIFY_CODE" 404
need_eq "offline_intents" "$(grep -c '^offline_intents = true' /root/.aikernel/model.toml || true)" 1
need_eq "prefer_local_cloud_first" "$(grep -c '^prefer_local = false' /root/.aikernel/model.toml || true)" 1

echo "== desktop live checks =="
for _ in $(seq 1 20); do
    code="$(curl -sS -m 8 -o /tmp/a10-dh -w '%{http_code}' http://127.0.0.1:8091/api/health || true)"
    [ "$code" = "200" ] && break
    sleep 1
done
need_eq "desktop_active" "$(systemctl is-active aik-desktop || true)" active
need_eq "desktop_enabled" "$(systemctl is-enabled aik-desktop || true)" enabled
need_eq "desktop_health" "$code" 200
need_eq "desktop_loopback" \
    "$(ss -ltn | grep -c '127.0.0.1:8091' || true)" 1
need_eq "desktop_any_addr" \
    "$(ss -ltn | grep ':8091' | grep -vc '127.0.0.1:8091' || true)" 0
need_eq "desktop_state_mode" "$(stat -c '%a' /var/lib/aikdesktop)" 700
need_eq "desktop_state_owner" "$(stat -c '%U' /var/lib/aikdesktop)" aikdesk
SHOT="$(curl -sS -m 10 -o /tmp/a10-shot -w '%{http_code}' http://127.0.0.1:8091/api/screenshot || true)"
POWER="$(curl -sS -m 10 -o /tmp/a10-power -w '%{http_code}' \
    -H 'Content-Type: application/json' -d '{"action":"reboot"}' \
    http://127.0.0.1:8091/api/power || true)"
need_eq "screenshot_503" "$SHOT" 503
need_eq "power_501" "$POWER" 501

echo "== core / no-reboot checks =="
printf 'exit\n' | timeout 30 /usr/local/bin/aikernel-shell >/tmp/a10-shell.out 2>&1 \
    || fail "aikernel-shell start"
need_eq "boot_id_unchanged" "$(cat /proc/sys/kernel/random/boot_id)" "$BOOT_BEFORE"
need_eq "failed_units" "$(systemctl --failed --no-legend | wc -l)" 0
echo "uptime_after=$(uptime)"

if [ "$FAIL" -ne 0 ]; then
    echo "ROLLBACK_BACKUP=$BAK"
    echo "ROLLBACK_HINT: restore $BAK userland files, systemctl restart aikernel-api;"
    echo "ROLLBACK_HINT: systemctl disable --now aik-desktop and remove /opt/aikdesktop if needed."
    exit 1
fi
echo "BACKUP=$BAK"
echo "ALPHA11_REMOTE_OK"
