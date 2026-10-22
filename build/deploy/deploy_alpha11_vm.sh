#!/bin/bash
# alpha.11 host-side deployment orchestrator (Windows Git Bash).
# Relays artifacts L1 -> host -> VM (never remote-to-remote scp), verifies md5,
# then runs the remote installer. No VM reboot; aikernel-api restart only.
set -euo pipefail

L1="jack66g@192.168.245.136"
VM="root@192.168.245.138"
SSH_OPTS=(-o BatchMode=yes -o IdentitiesOnly=yes
          -o UserKnownHostsFile=C:/Users/Public/aik-ssh/known_hosts
          -i "$HOME/.ssh/aikernel_ed25519")
SRC="/home/jack66g/linux-6.18.39/agent/ai"
FACTORY="/home/jack66g/w7i-rootfs"
HERE="$(cd "$(dirname "$0")" && pwd)"
STAGE="$HERE/../../.tmp/aik-alpha11-stage"
REMOTE="$HERE/deploy_alpha11_vm_remote.sh"

if [ "${1:-}" != "--w77c" ]; then
    echo "refusing: pass --w77c (alpha.11 release; deploy only, no reboot)" >&2
    exit 2
fi

md5of() { md5sum "$1" | cut -d' ' -f1; }
expect() {
    local file="$1" want="$2" got
    got="$(md5of "$file")"
    [ "$got" = "$want" ] || { echo "md5 mismatch: $file got=$got want=$want" >&2; exit 1; }
    echo "MD5_OK $got $file"
}

rm -rf "$STAGE"
mkdir -p "$STAGE"

echo "== fetch from L1 =="
scp "${SSH_OPTS[@]}" "$L1:$SRC/aikernel-shell" "$STAGE/aikernel-shell"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/tools.json" "$STAGE/tools.json"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/tools.openai.json" "$STAGE/tools.openai.json"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/tools-sandbox.json" "$STAGE/tools-sandbox.json"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/sme-seed-w51.jsonl" "$STAGE/sme-seed.jsonl"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/tool_catalog.txt" "$STAGE/tool_catalog.txt"
scp "${SSH_OPTS[@]}" "$L1:$SRC/api/aikernel-api" "$STAGE/aikernel-api"
ssh "${SSH_OPTS[@]}" "$L1" \
    "tar -C $FACTORY -cf - ./opt/aikdesktop ./etc/systemd/system/aik-desktop.service" \
    > "$STAGE/desktop-alpha11.tar"

echo "== verify staged artifacts =="
expect "$STAGE/aikernel-shell" adb71f65c7e60fdcba2ce88da9093546
expect "$STAGE/aikernel-api" e007a7d9d9e8cd9e81ec977d92bd9056
expect "$STAGE/tools.json" 34d5af9ca7279e436690169c9af65873
expect "$STAGE/tools.openai.json" ab7656229c60fcebfab20b55952ae2f2
expect "$STAGE/tools-sandbox.json" 25f25c255bb75818f0db09fb80855a25
expect "$STAGE/sme-seed.jsonl" f93767385a788bfff1a587f1eea2b321
expect "$STAGE/tool_catalog.txt" ad3e216edad31fb16378329d41c3c777
[ "$(wc -l < "$STAGE/sme-seed.jsonl")" -eq 167 ] || { echo "seed not 167" >&2; exit 1; }
[ "$(tar -tf "$STAGE/desktop-alpha11.tar" | grep -c '^./opt/aikdesktop/')" -ge 60 ] \
    || { echo "desktop tar incomplete" >&2; exit 1; }
[ "$(tar -xOf "$STAGE/desktop-alpha11.tar" ./opt/aikdesktop/server.py | md5sum | cut -d' ' -f1)" \
    = f09f55a89631f63e118122c30b000c68 ] || { echo "desktop server md5" >&2; exit 1; }
[ "$(tar -xOf "$STAGE/desktop-alpha11.tar" ./etc/systemd/system/aik-desktop.service | md5sum | cut -d' ' -f1)" \
    = 16744040f5467de50be49bda6efe1aac ] || { echo "desktop unit md5" >&2; exit 1; }
echo "DESKTOP_TAR_OK"

echo "== upload to VM =="
ssh "${SSH_OPTS[@]}" "$VM" 'rm -rf /root/aik-alpha11-stage && mkdir -p /root/aik-alpha11-stage'
scp "${SSH_OPTS[@]}" "$STAGE"/* "$VM:/root/aik-alpha11-stage/"
scp "${SSH_OPTS[@]}" "$REMOTE" "$VM:/root/aik-alpha11-stage/deploy_alpha11_vm_remote.sh"

echo "== remote install =="
LOG="$HERE/../reports/alpha11-deploy-$(date +%Y%m%d-%H%M%S).log"
ssh "${SSH_OPTS[@]}" "$VM" \
    'AIK_ALPHA11_CONFIRM=1 bash /root/aik-alpha11-stage/deploy_alpha11_vm_remote.sh' \
    2>&1 | tee "$LOG"
echo "DEPLOY_LOG=$LOG"
echo "ALPHA11_DEPLOY_OK"
