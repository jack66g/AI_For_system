#!/bin/sh
# Apply and verify the AIKernel kernel overlay set on a clean Linux tree.
# Usage: build/apply-overlays.sh /path/to/linux-6.18.39
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target=${1:?usage: $0 /path/to/linux-6.18.39}
manifest="$here/kernel-overlays/MANIFEST.sha256"

[ -f "$manifest" ] || { echo "missing $manifest" >&2; exit 1; }
[ -d "$target" ] || { echo "not a directory: $target" >&2; exit 1; }

while read -r hash rel; do
    [ -n "${rel:-}" ] || continue
    src="$here/kernel-overlays/$rel"
    dst="$target/$rel"
    [ -f "$src" ] || { echo "missing overlay: $rel" >&2; exit 1; }
    mkdir -p "$(dirname -- "$dst")"
    cp -p "$src" "$dst"
done < "$manifest"

fail=0
while read -r hash rel; do
    [ -n "${rel:-}" ] || continue
    got=$(sha256sum "$target/$rel" | awk '{print $1}')
    if [ "$got" != "$hash" ]; then
        echo "SHA256 MISMATCH: $rel (got $got want $hash)" >&2
        fail=1
    fi
done < "$manifest"

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "overlays applied and verified: $(wc -l < "$manifest") files -> $target"
