#!/usr/bin/env python3
"""W73: refresh the factory rootfs for alpha.11.0 (run as root on L1).

Installs the verified kernel-userland artifacts, bumps the release strings,
raises ctx_len, and records backups outside the factory tree.
"""
import hashlib
import os
import shutil
import stat
import sys

SRC = "/home/jack66g/linux-6.18.39/agent/ai"
ROOT = "/home/jack66g/w7i-rootfs"
BAK = "/home/jack66g/w73-backup/factory-pre-alpha11"
UPGRADE = "/home/jack66g/aikernel-longterm/aik-upgrade.patched"

EXPECT = {
    "/usr/local/bin/ai": "adb71f65c7e60fdcba2ce88da9093546",
    "/usr/local/bin/aikernel-shell": "adb71f65c7e60fdcba2ce88da9093546",
    "/usr/local/bin/aik-sandbox": "2fff618051be53bd6187b96ad11c9206",
    "/usr/local/sbin/aikernel-api": "e007a7d9d9e8cd9e81ec977d92bd9056",
    "/usr/local/share/aikernel/tools.json": "34d5af9ca7279e436690169c9af65873",
    "/etc/aikernel/tools.json": "34d5af9ca7279e436690169c9af65873",
    "/usr/local/share/aikernel/tools.openai.json": "ab7656229c60fcebfab20b55952ae2f2",
    "/usr/local/share/aikernel/tools-sandbox.json": "25f25c255bb75818f0db09fb80855a25",
    "/usr/local/share/aikernel/sme-seed.jsonl": "f93767385a788bfff1a587f1eea2b321",
    "/usr/local/share/aikernel/tool_catalog.txt": "ad3e216edad31fb16378329d41c3c777",
    "/usr/local/sbin/aik-upgrade": "6d3392d26b65201e5151227717d57e8c",
}


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
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
    if os.path.lexists(dst):
        if os.path.islink(dst) or os.path.isfile(dst):
            os.unlink(dst)
        else:
            raise SystemExit("refusing to replace non-file: %s" % dst)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(os.path.realpath(src), dst)
    os.chmod(dst, mode)
    os.chown(dst, 0, 0)


def text_replace(rel, old, new):
    path = ROOT + rel
    with open(path, encoding="utf-8") as f:
        s = f.read()
    if old not in s:
        if new in s:
            return  # already refreshed (idempotent re-run)
        raise SystemExit("missing %r in %s" % (old, path))
    backup(rel)
    with open(path, "w", encoding="utf-8") as f:
        f.write(s.replace(old, new))


os.makedirs(BAK, exist_ok=True)

# 1) binaries
install("/usr/local/bin/aikernel-shell", SRC + "/aikernel-shell", 0o755)
install("/usr/local/bin/ai", SRC + "/aikernel-shell", 0o755)
install("/usr/local/bin/aik-sandbox", SRC + "/aik-sandbox", 0o755)
install("/usr/local/sbin/aikernel-api", SRC + "/api/aikernel-api", 0o755)

# 2) registries and seed (factory ships the seed as sme-seed.jsonl)
for name in ("tools.json", "tools.openai.json", "tools-sandbox.json"):
    install("/usr/local/share/aikernel/" + name, SRC + "/tools/" + name, 0o644)
install("/usr/local/share/aikernel/sme-seed.jsonl",
        SRC + "/tools/sme-seed-w51.jsonl", 0o644)
install("/etc/aikernel/tools.json", SRC + "/tools/tools.json", 0o644)
if os.path.exists(SRC + "/tools/tool_catalog.txt"):
    install("/usr/local/share/aikernel/tool_catalog.txt",
            SRC + "/tools/tool_catalog.txt", 0o644)
# remove a stray copy created by the first refresh attempt
stray = "/usr/local/share/aikernel/sme-seed-w51.jsonl"
if os.path.exists(ROOT + stray):
    backup(stray)
    os.unlink(ROOT + stray)

# 3) patched A/B updater (commit copies the tested try image into the slot)
install("/usr/local/sbin/aik-upgrade", UPGRADE, 0o755)

# 4) release strings and context budget
text_replace("/etc/motd", "0.1.0-alpha.10.0", "0.1.0-alpha.11.0")
text_replace("/root/README.md", "0.1.0-alpha.10.0", "0.1.0-alpha.11.0")
text_replace("/root/.aikernel/model.toml", "ctx_len = 8192", "ctx_len = 32768")
text_replace("/root/.aikernel/model.toml", "ctx_len=8192", "ctx_len=32768")
os.chmod(ROOT + "/root/.aikernel/model.toml", 0o600)

# 5) ISO installer menu version (outside factory, root-owned)
cfg = "/home/jack66g/w6i-tools/grub-iso.cfg"
with open(cfg, encoding="utf-8") as f:
    s = f.read()
if "0.1.0-alpha.10.0" in s:
    shutil.copy2(cfg, "/home/jack66g/w73-backup/grub-iso.cfg.pre-alpha11")
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(s.replace("0.1.0-alpha.10.0", "0.1.0-alpha.11.0"))

# 6) verify
bad = []
for rel, want in EXPECT.items():
    got = md5(ROOT + rel)
    print("%s %s" % (got, rel))
    if got != want:
        bad.append((rel, want, got))
motd = open(ROOT + "/etc/motd", encoding="utf-8").read()
assert "0.1.0-alpha.11.0" in motd and "0.1.0-alpha.10.0" not in motd
assert "ctx_len = 32768" in open(ROOT + "/root/.aikernel/model.toml",
                                encoding="utf-8").read()
assert stat.S_IMODE(os.stat(ROOT + "/root/.aikernel/model.toml").st_mode) == 0o600
assert "0.1.0-alpha.11.0" in open(cfg, encoding="utf-8").read()
assert os.path.isfile(ROOT + "/etc/systemd/system/aikernel-api.service")
if bad:
    raise SystemExit("md5 mismatch: %r" % (bad,))

# 6b) registry/seed invariants: count, name hash, domains, desktop, seed
import json as _json
_doc = _json.load(open(ROOT + "/usr/local/share/aikernel/tools.json",
                       encoding="utf-8"))
_names = [t["name"] for t in _doc.get("tools", [])]
assert _doc.get("tool_count") == 151, _doc.get("tool_count")
assert len(_names) == 151, len(_names)
_names_sha = hashlib.sha256(("\n".join(_names) + "\n").encode("utf-8")).hexdigest()
assert _names_sha == "52cbbc49c18da3c339fb9daf5441cd89cf4bbc02555462387e5d43055b52d3c2", _names_sha
assert _doc.get("tool_names_sha256") == _names_sha
_domains = set()
for _t in _doc.get("tools", []):
    _sub = _t.get("sub")
    if isinstance(_sub, list) and _sub:
        _domains.add(_sub[0])
assert len(_domains) == 8, sorted(_domains)
assert sum(1 for _n in _names if _n.startswith("desktop_")) == 20
_seed = [l for l in open(ROOT + "/usr/local/share/aikernel/sme-seed.jsonl",
                         encoding="utf-8").read().splitlines() if l.strip()]
assert len(_seed) == 167, len(_seed)
print("REGISTRY_OK", len(_names), _names_sha, len(_seed))

# 7) W76b: desktop demo bundle + aik-desktop.service (independent of the
#    binary/tools/seed steps above; idempotent; never touches L1's 8091 demo).
sys.path.insert(0, "/home/jack66g/aikernel-longterm")
from w76b_install_desktop import install as install_desktop  # noqa: E402

install_desktop(quiet=True)
assert os.path.isfile(ROOT + "/opt/aikdesktop/server.py")
assert os.path.isfile(ROOT + "/etc/systemd/system/aik-desktop.service")
print("W76B_DESKTOP_OK")
print("FACTORY_REFRESH_OK")
