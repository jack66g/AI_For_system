#!/usr/bin/env python3
"""K17 波: refresh factory rootfs for 0.1.0-alpha.17.0 (run as ROOT on L1).

Sources from repo ~/aikernel-repo-alpha11 @ 5a4e45e+ (K0/K1/K2 userland).
Derived from w78_factory_refresh.py (alpha.13 wave) — md5 pins dropped
(fresh wave: REPORT baselines for the next qsmoke), invariants kept.
Backups to ~/w73-backup/factory-pre-alpha17.
"""
import hashlib
import json
import os
import shutil

REPO = "/home/jack66g/aikernel-repo-alpha11"
SRC = REPO + "/agent/ai"
FACT = REPO + "/factory"
ROOT = "/home/jack66g/w7i-rootfs"
BAK = "/home/jack66g/w73-backup/factory-pre-alpha17"
UPGRADE = "/home/jack66g/aikernel-longterm/aik-upgrade.patched"
CFG = "/home/jackg6"  # placeholder, fixed below
CFG = "/home/jack66g/w6i-tools/grub-iso.cfg"
OLD, NEW = "0.1.0-alpha.16.3", "0.1.0-alpha.17.0"


def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def backup(rel):
    src = ROOT + rel
    if not os.path.lexists(src):
        return
    dst = BAK + rel
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if not os.path.lexists(dst):
        shutil.copy2(src, dst, follow_symlinks=False)


def install(rel, src, mode=0o644):
    backup(rel)
    dst = ROOT + rel
    if os.path.lexists(dst) and (os.path.islink(dst) or os.path.isfile(dst)):
        os.unlink(dst)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(os.path.realpath(src), dst)
    os.chmod(dst, mode)
    os.chown(dst, 0, 0)
    print("install %s  md5=%s" % (rel, md5(dst)))


def text_replace(rel, old, new):
    p = ROOT + rel
    s = open(p, encoding="utf-8").read()
    if old not in s:
        if new in s:
            return
        raise SystemExit("missing %r in %s" % (old, p))
    backup(rel)
    open(p, "w", encoding="utf-8").write(s.replace(old, new))
    print("bump %s %s->%s" % (rel, old, new))


os.makedirs(BAK, exist_ok=True)

# 1) binaries (K1/K2 userland: occ act2/act2batch, api batch twin, aistreamd v2 schema)
install("/usr/local/bin/occ", SRC + "/occ/occ", 0o755)
install("/usr/local/bin/aik-sandbox", SRC + "/aik-sandbox", 0o755)
install("/usr/local/sbin/aikernel-api", SRC + "/apic/aikerneld-api", 0o755)
install("/usr/local/sbin/aistreamd", SRC + "/aistreamd/aistreamd", 0o755)

# 2) registries + seed (K2b regenerated family)
for n in ("tools.json", "tools.openai.json", "tools-sandbox.json",
          "tool_catalog.txt", "model-catalog.json"):
    install("/usr/local/share/aikernel/" + n, SRC + "/tools/" + n, 0o644)
install("/usr/local/share/aikernel/sme-seed.jsonl",
        SRC + "/tools/sme-seed-w51.jsonl", 0o644)
install("/etc/aikernel/tools.json", SRC + "/tools/tools.json", 0o644)
install("/etc/aikernel/sme-seed.jsonl", SRC + "/tools/sme-seed-w51.jsonl", 0o644)

# 3) factory conf/policy + systemd units
install("/etc/aikernel/aistreamd.conf", FACT + "/etc/aikernel/aistreamd.conf", 0o644)
install("/etc/aikernel/policy.conf", FACT + "/etc/aikernel/policy.conf", 0o644)
for u in os.listdir(FACT + "/etc/systemd/system"):
    install("/etc/systemd/system/" + u,
            FACT + "/etc/systemd/system/" + u, 0o644)

# 4) A/B updater (unchanged asset)
install("/usr/local/sbin/aik-upgrade", UPGRADE, 0o755)

# 5) release strings + grub menu
text_replace("/etc/motd", OLD, NEW)
text_replace("/root/README.md", OLD, NEW)
s = open(CFG, encoding="utf-8").read()
if OLD in s:
    shutil.copy2(CFG, BAK + "/grub-iso.cfg.pre-alpha17")
    open(CFG, "w", encoding="utf-8").write(s.replace(OLD, NEW))
    print("grub-iso.cfg bumped")

# 6) invariants (soft: report + assert the load-bearing ones)
doc = json.load(open(ROOT + "/usr/local/share/aikernel/tools.json",
                     encoding="utf-8"))
names = [t["name"] for t in doc.get("tools", [])]
assert doc.get("tool_count") == 237 and len(names) == 237, \
    (doc.get("tool_count"), len(names))
assert "crontab" not in names
seed_lines = sum(1 for _ in open(ROOT + "/usr/local/share/aikernel/sme-seed.jsonl",
                                 encoding="utf-8"))
conf = open(ROOT + "/etc/aikernel/aistreamd.conf", encoding="utf-8").read()
assert "SENSE_REDACT=off" in conf and "SENSE_REDACT_SALT=" in conf
assert "OUTCOME_ENABLED=0" in conf and "DECISIONS_ENABLED=0" in conf
motd = open(ROOT + "/etc/motd", encoding="utf-8").read()
assert NEW in motd and OLD not in motd
for rel in ("/usr/local/bin/occ", "/usr/local/sbin/aistreamd",
            "/usr/local/sbin/aikernel-api", "/usr/local/bin/aik-sandbox"):
    assert os.path.getsize(ROOT + rel) > 100000, rel

# 7) provenance snapshot
kern = "/home/jack66g/linux-k2/arch/x86/boot/bzImage"
snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-K17.txt"
open(snap, "w", encoding="utf-8").write(
    "version=%s\nkernel=6.18.39 K2 %s (%d bytes)\n"
    "userland=main@5a4e45e (+conf-salt/C4-comment)\n"
    "tools=237 seed=%d\nbuilt=2026-11-12 on L1 (K17 wave: K0+K1 trace+K2 batch)\n"
    % (NEW, md5(kern), os.path.getsize(kern), seed_lines))
print("seed_lines=%d  tools=237  snapshot written" % seed_lines)
print("REFRESH_OK")
