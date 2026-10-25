#!/usr/bin/env python3
"""W78: refresh the factory rootfs for alpha.13.0 (run as root on L1).

Installs the verified kernel-userland artifacts (shell=487b21b6, 182 tools,
9 domains incl. model_ x6, seed 199), bumps the release strings, records
backups outside the factory tree. Derived from w73_factory_refresh.py
(alpha.12 wave); adds /etc/aikernel/sme-seed.jsonl sync and the W78
aik-tls-gateway presence/disabled gate.
"""
import hashlib
import os
import shutil
import stat
import sys

SRC = "/home/jack66g/linux-6.18.39/agent/ai"
ROOT = "/home/jack66g/w7i-rootfs"
BAK = "/home/jack66g/w73-backup/factory-pre-alpha13"
UPGRADE = "/home/jack66g/aikernel-longterm/aik-upgrade.patched"

EXPECT = {
    "/usr/local/bin/ai": "487b21b6f974ed78a20353449991b477",
    "/usr/local/bin/aikernel-shell": "487b21b6f974ed78a20353449991b477",
    "/usr/local/bin/aik-sandbox": "2fff618051be53bd6187b96ad11c9206",
    "/usr/local/sbin/aikernel-api": "e007a7d9d9e8cd9e81ec977d92bd9056",
    "/usr/local/share/aikernel/tools.json": "f165a08119a4e1f27e57777cd80526e3",
    "/etc/aikernel/tools.json": "f165a08119a4e1f27e57777cd80526e3",
    "/usr/local/share/aikernel/tools.openai.json": "ee27b8c52342ce2b2bb7acc5496cbab0",
    "/usr/local/share/aikernel/tools-sandbox.json": "10c49596aa239a7c3ff985a63c51d4e2",
    "/usr/local/share/aikernel/sme-seed.jsonl": "3f4cada560e66d842a273ffd4d37eb48",
    "/etc/aikernel/sme-seed.jsonl": "3f4cada560e66d842a273ffd4d37eb48",
    "/usr/local/share/aikernel/tool_catalog.txt": "5bee830936c836fc1f4be10489474685",
    "/usr/local/share/aikernel/model-catalog.json": "07fd7274227ff531a71f0bd4fb631de7",
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
# W78: keep the /etc copy of the seed aligned with the shipped seed
install("/etc/aikernel/sme-seed.jsonl", SRC + "/tools/sme-seed-w51.jsonl", 0o644)
install("/usr/local/share/aikernel/tool_catalog.txt",
        SRC + "/tools/tool_catalog.txt", 0o644)
install("/usr/local/share/aikernel/model-catalog.json",
        SRC + "/tools/model-catalog.json", 0o644)

# 3) patched A/B updater (commit copies the tested try image into the slot)
install("/usr/local/sbin/aik-upgrade", UPGRADE, 0o755)

# 4) release strings
text_replace("/etc/motd", "0.1.0-alpha.12.0", "0.1.0-alpha.13.0")
text_replace("/root/README.md", "0.1.0-alpha.12.0", "0.1.0-alpha.13.0")

# 5) ISO installer menu version (outside factory, root-owned)
cfg = "/home/jack66g/w6i-tools/grub-iso.cfg"
with open(cfg, encoding="utf-8") as f:
    s = f.read()
if "0.1.0-alpha.12.0" in s:
    shutil.copy2(cfg, "/home/jack66g/w73-backup/grub-iso.cfg.pre-alpha13")
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(s.replace("0.1.0-alpha.12.0", "0.1.0-alpha.13.0"))

# 6) verify
bad = []
for rel, want in EXPECT.items():
    got = md5(ROOT + rel)
    print("%s %s" % (got, rel))
    if got != want:
        bad.append((rel, want, got))
motd = open(ROOT + "/etc/motd", encoding="utf-8").read()
assert "0.1.0-alpha.13.0" in motd and "0.1.0-alpha.12.0" not in motd
assert "0.1.0-alpha.13.0" in open(cfg, encoding="utf-8").read()
assert os.path.isfile(ROOT + "/etc/systemd/system/aikernel-api.service")
if bad:
    raise SystemExit("md5 mismatch: %r" % (bad,))

# 6b) registry/seed invariants: count, name hash, domains, desktop, seed
import json as _json
_doc = _json.load(open(ROOT + "/usr/local/share/aikernel/tools.json",
                       encoding="utf-8"))
_names = [t["name"] for t in _doc.get("tools", [])]
assert _doc.get("tool_count") == 182, _doc.get("tool_count")
assert len(_names) == 182, len(_names)
assert "crontab" not in _names, "crontab tool must not ship"
_names_sha = hashlib.sha256(("\n".join(_names) + "\n").encode("utf-8")).hexdigest()
assert _names_sha == "c3ce0b61a0e13ae4b0b92467f37821f28cefb12cf1fa54a8148d3130a64d4472", _names_sha
assert _doc.get("tool_names_sha256") == _names_sha
_domains = set()
for _t in _doc.get("tools", []):
    _sub = _t.get("sub")
    if isinstance(_sub, list) and _sub:
        _domains.add(_sub[0])
assert len(_domains) == 9, sorted(_domains)
assert sum(1 for _n in _names if _n.startswith("desktop_")) == 20
assert sum(1 for _n in _names if _n.startswith("model_")) == 6
_seed = [l for l in open(ROOT + "/usr/local/share/aikernel/sme-seed.jsonl",
                         encoding="utf-8").read().splitlines() if l.strip()]
assert len(_seed) == 199, len(_seed)
print("REGISTRY_OK", len(_names), _names_sha, len(_seed))

# 6c) W78: mTLS gateway unit present but disabled by default (no wants link)
import glob as _glob
_tls_unit = ROOT + "/etc/systemd/system/aik-tls-gateway.service"
assert os.path.isfile(_tls_unit), "aik-tls-gateway.service missing"
assert os.path.isfile(ROOT + "/usr/local/sbin/aik-tls-gateway")
_wants = [p for p in _glob.glob(ROOT + "/etc/systemd/system/*.wants/aik-tls-gateway.service")
          if os.path.islink(p)]
assert not _wants, "aik-tls-gateway must not be enabled: %r" % _wants
assert md5(ROOT + "/etc/aikernel/tools.json") == md5(ROOT + "/opt/w7s/tools.json")
print("TLS_GATEWAY_OK unit=present enabled=no w7s_tools=match")

# 7) W76b: desktop demo bundle + aik-desktop.service (idempotent)
sys.path.insert(0, "/home/jack66g/aikernel-longterm")
from w76b_install_desktop import install as install_desktop  # noqa: E402

install_desktop(quiet=True)
assert os.path.isfile(ROOT + "/opt/aikdesktop/server.py")
assert os.path.isfile(ROOT + "/etc/systemd/system/aik-desktop.service")
print("W76B_DESKTOP_OK")
print("FACTORY_REFRESH_OK")
