#!/usr/bin/env python3
"""Remove stale factory backups from the shipped rootfs (keep copies outside)."""
import os
import shutil

ROOT = "/home/jack66g/w7i-rootfs"
BAK = "/home/jack66g/w73-backup/factory-junk"
FILES = [
    "/usr/local/share/aikernel/sme-seed.jsonl.bak-w61",
    "/etc/apt/sources.list.bak-p2p4",
    "/etc/motd.bak-w61",
    "/root/README.md.bak-w61",
    "/root/.profile.pre-w4a",
]
os.makedirs(BAK, exist_ok=True)
for rel in FILES:
    src = ROOT + rel
    if not os.path.lexists(src):
        print("gone", rel)
        continue
    dst = BAK + rel
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if not os.path.lexists(dst):
        shutil.copy2(src, dst, follow_symlinks=False)
    os.unlink(src)
    print("removed", rel)
print("JUNK_CLEAN_OK")
