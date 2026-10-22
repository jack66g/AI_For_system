#!/bin/bash
# alpha.12 host-side deployment orchestrator (Windows Git Bash).
# Relays artifacts L1 -> host -> VM (never remote-to-remote scp), verifies md5,
# then runs the remote installer. No VM reboot; aikernel-api restart only.
# W77d scope: new shell (alpha.12.0, 156 tools incl model_*), seed 173,
# model-catalog.json, cloud-first aik-reset/motd; VM drops preloaded qwen2.5:1.5b.
set -euo pipefail

L1="jack66g@192.168.245.136"
VM="root@192.168.245.138"
SSH_OPTS=(-o BatchMode=yes -o IdentitiesOnly=yes
          -o UserKnownHostsFile=C:/Users/Public/aik-ssh/known_hosts
          -i "$HOME/.ssh/aikernel_ed25519")
SRC="/home/jack66g/linux-6.18.39/agent/ai"
FACTORY="/home/jack66g/w7i-rootfs"
HERE="$(cd "$(dirname "$0")" && pwd)"
STAGE="$HERE/../../.tmp/aik-alpha12-stage"
REMOTE="$HERE/deploy_alpha12_vm_remote.sh"

if [ "${1:-}" != "--w77d" ]; then
    echo "refusing: pass --w77d (alpha.12 release; deploy only, no reboot)" >&2
    exit 2
fi

md5of() { md5sum "$1" | cut -d' ' -f1; }
expect() {
    local file="$1" want="$2" got
    got="$(md5of "$file")"
    [ "$got" = "$want" ] || { echo "md5 mismatch: $file got=$got want=$want" >&2; exit 1; }
    echo "MD5_OK $got $file"
}

mkdir -p "$STAGE"

echo "== fetch from L1 =="
scp "${SSH_OPTS[@]}" "$L1:$SRC/aikernel-shell" "$STAGE/aikernel-shell"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/tools.json" "$STAGE/tools.json"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/tools.openai.json" "$STAGE/tools.openai.json"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/tools-sandbox.json" "$STAGE/tools-sandbox.json"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/sme-seed-w51.jsonl" "$STAGE/sme-seed.jsonl"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/tool_catalog.txt" "$STAGE/tool_catalog.txt"
scp "${SSH_OPTS[@]}" "$L1:$SRC/tools/model-catalog.json" "$STAGE/model-catalog.json"
ssh "${SSH_OPTS[@]}" "$L1" \
    "/home/jack66g/aikernel-longterm/aik-sudo.sh cat $FACTORY/usr/local/sbin/aik-reset" \
    > "$STAGE/aik-reset"
ssh "${SSH_OPTS[@]}" "$L1" \
    "/home/jack66g/aikernel-longterm/aik-sudo.sh cat $FACTORY/etc/motd" \
    > "$STAGE/motd"

echo "== verify staged artifacts =="
expect "$STAGE/aikernel-shell" 784cc0f014409cfdd8186f95c557dcd0
expect "$STAGE/tools.json" eca2739901173bcf6505420bbf7d186d
expect "$STAGE/tools.openai.json" d5fedb738f5e4e56290dcbe67b26f055
expect "$STAGE/tools-sandbox.json" 226233e4d143db8a513bd136a6caae46
expect "$STAGE/sme-seed.jsonl" 59e5ee4a87576320750cc05381e9871f
expect "$STAGE/tool_catalog.txt" 39be07cec5b3670591838e97a87563b6
expect "$STAGE/model-catalog.json" 07fd7274227ff531a71f0bd4fb631de7
[ "$(wc -l < "$STAGE/sme-seed.jsonl")" -eq 173 ] || { echo "seed not 173" >&2; exit 1; }
grep -q "qwen2.5:1.5b" "$STAGE/aik-reset" && { echo "aik-reset still references qwen2.5:1.5b" >&2; exit 1; }
grep -q "0.1.0-alpha.12.0" "$STAGE/motd" || { echo "motd not alpha.12.0" >&2; exit 1; }
echo "STAGE_OK"

echo "== upload to VM =="
ssh "${SSH_OPTS[@]}" "$VM" 'rm -rf /root/aik-alpha12-stage && mkdir -p /root/aik-alpha12-stage'
scp "${SSH_OPTS[@]}" "$STAGE"/* "$VM:/root/aik-alpha12-stage/"
scp "${SSH_OPTS[@]}" "$REMOTE" "$VM:/root/aik-alpha12-stage/deploy_alpha12_vm_remote.sh"

echo "== remote install =="
LOG="$HERE/../reports/alpha12-deploy-$(date +%Y%m%d-%H%M%S).log"
ssh "${SSH_OPTS[@]}" "$VM" \
    'AIK_ALPHA12_CONFIRM=1 bash /root/aik-alpha12-stage/deploy_alpha12_vm_remote.sh' \
    2>&1 | tee "$LOG"
echo "DEPLOY_LOG=$LOG"
echo "ALPHA12_DEPLOY_OK"
