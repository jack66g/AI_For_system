#!/usr/bin/env python3
"""Soak-safe preflight for the alpha.11 factory refresh (no writes)."""
import hashlib
import json
import os
import sys

SRC = "/home/jack66g/linux-6.18.39/agent/ai"
ROOT = "/home/jack66g/w7i-rootfs"
CFG = "/home/jack66g/w6i-tools/grub-iso.cfg"
UPGRADE = "/home/jack66g/aikernel-longterm/aik-upgrade.patched"
W76B = "/home/jack66g/aikernel-longterm/w76b_install_desktop.py"
NAMES_SHA = "52cbbc49c18da3c339fb9daf5441cd89cf4bbc02555462387e5d43055b52d3c2"

SRC_EXPECT = {
    SRC + "/aikernel-shell": "adb71f65c7e60fdcba2ce88da9093546",
    SRC + "/aik-sandbox": "2fff618051be53bd6187b96ad11c9206",
    SRC + "/api/aikernel-api": "e007a7d9d9e8cd9e81ec977d92bd9056",
    SRC + "/tools/tools.json": "34d5af9ca7279e436690169c9af65873",
    SRC + "/tools/tools.openai.json": "ab7656229c60fcebfab20b55952ae2f2",
    SRC + "/tools/tools-sandbox.json": "25f25c255bb75818f0db09fb80855a25",
    SRC + "/tools/sme-seed-w51.jsonl": "f93767385a788bfff1a587f1eea2b321",
    SRC + "/tools/tool_catalog.txt": "ad3e216edad31fb16378329d41c3c777",
    UPGRADE: "6d3392d26b65201e5151227717d57e8c",
}


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg):
    print("FAIL", msg)
    sys.exit(1)


for path, want in SRC_EXPECT.items():
    if not os.path.isfile(path):
        fail("missing source %s" % path)
    got = md5(path)
    if got != want:
        fail("source md5 %s got %s want %s" % (path, got, want))
    print("SRC_OK", got, path)

doc = json.load(open(SRC + "/tools/tools.json", encoding="utf-8"))
names = [t["name"] for t in doc.get("tools", [])]
if doc.get("tool_count") != 151 or len(names) != 151:
    fail("tool count %r/%d" % (doc.get("tool_count"), len(names)))
sha = hashlib.sha256(("\n".join(names) + "\n").encode()).hexdigest()
if sha != NAMES_SHA or doc.get("tool_names_sha256") != NAMES_SHA:
    fail("names sha %s header %s" % (sha, doc.get("tool_names_sha256")))
domains = set()
for t in doc.get("tools", []):
    sub = t.get("sub")
    if isinstance(sub, list) and sub:
        domains.add(sub[0])
if len(domains) != 8:
    fail("domains %r" % sorted(domains))
if sum(1 for n in names if n.startswith("desktop_")) != 20:
    fail("desktop count")
print("REGISTRY_OK tools=151 domains=8 desktop=20 names_sha=%s" % sha)

sb = json.load(open(SRC + "/tools/tools-sandbox.json", encoding="utf-8"))
sb_tools = sb.get("tools", [])
cmds = sum(len((t.get("exec") or {}).get("commands", [])) for t in sb_tools)
if len(sb_tools) != 7 or cmds != 57:
    fail("sandbox tools=%d commands=%d" % (len(sb_tools), cmds))
print("SANDBOX_OK tools=7 commands=57")

seed = [l for l in open(SRC + "/tools/sme-seed-w51.jsonl",
                        encoding="utf-8").read().splitlines() if l.strip()]
if len(seed) != 167:
    fail("seed lines %d" % len(seed))
for i, line in enumerate(seed, 1):
    try:
        json.loads(line)
    except Exception as e:
        fail("seed line %d invalid: %s" % (i, e))
print("SEED_OK lines=167 json=valid")

motd = open(ROOT + "/etc/motd", encoding="utf-8").read()
if "0.1.0-alpha.10.0" not in motd or "0.1.0-alpha.9.0" in motd:
    fail("factory motd not at alpha.10.0")
readme = open(ROOT + "/root/README.md", encoding="utf-8").read()
if "0.1.0-alpha.10.0" not in readme:
    fail("factory README not at alpha.10.0")
cfg = open(CFG, encoding="utf-8").read()
if "0.1.0-alpha.10.0" not in cfg or "0.1.0-alpha.9.0" in cfg:
    fail("grub cfg not at alpha.10.0")
model = open(ROOT + "/root/.aikernel/model.toml", encoding="utf-8").read()
if "ctx_len = 32768" not in model and "ctx_len=32768" not in model:
    fail("ctx_len not 32768")
print("PRE_STATE_OK motd/readme/grub=alpha.10.0 ctx_len=32768")

for rel in ("/opt/aikdesktop/server.py",
            "/etc/systemd/system/aik-desktop.service",
            "/etc/systemd/system/aikernel-api.service"):
    if not os.path.isfile(ROOT + rel):
        fail("existing factory unit/bundle missing %s" % rel)
if not os.path.isfile(W76B) or "def install" not in open(W76B, encoding="utf-8").read():
    fail("w76b installer missing/invalid")
print("DESKTOP_PRE_OK bundle+unit+installer")

if not os.path.isdir("/home/jack66g/w73-backup"):
    fail("backup parent missing")
print("BACKUP_PARENT_OK /home/jack66g/w73-backup")
print("PREFLIGHT_OK")
