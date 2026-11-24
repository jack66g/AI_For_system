#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ENG-14: factory "built = shipped" manifest and audit.

Single source of truth for every AIKernel one-party piece in the factory
tree: install path, category, repo source / build recipe, post-processing,
install mode and which chain installs it.

Modes (read-only unless --write is given):
  --audit [--root DIR] [--repo DIR]
        Compare every manifest piece: factory tree vs repo artifact
        (post-processed identically, e.g. stripped).  Prints one row per
        piece with status MATCH / SCRIPT / DRIFT / NO_RECIPE / MISSING.
        Exit code 1 when any refresh-managed piece is DRIFT or MISSING.
  --write [--out FILE]
        Generate the factory manifest text (default
        build/FACTORY-MANIFEST.txt) with built_from_commit, per-piece repo
        md5 (after post-processing), factory md5, source last commit,
        build command and generation time.  Never installs anything.
  --check-installed
        Scan the managed factory directories and report one-party files
        that are not in the manifest.  Third-party/base-image files are
        explicitly whitelisted with reasons.  Exit code 1 on unmanaged
        one-party files.
  --selftest
        Build a throw-away fake factory tree and prove that MATCH, DRIFT
        and MISSING are all reported correctly.

No machine-specific absolute path is hard-coded here: the factory root is
$AIK_FACTORY_ROOT or ~/w7i-rootfs; the repo root defaults to this script's
parent directory.
"""
import argparse
import contextlib
import datetime
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REPO = os.path.dirname(HERE)
DEFAULT_ROOT = (os.environ.get("AIK_FACTORY_ROOT")
                or os.path.expanduser("~/w7i-rootfs"))

MANAGED_DIRS = ("usr/local/bin", "usr/local/sbin", "usr/local/lib")
WATCH_DIRS = ("usr/bin",)

# ---------------------------------------------------------------------------
# Manifest.  One entry per installed one-party piece.
#   path        install path inside the factory tree
#   kind        elf | script | asset
#   src         repo-relative artifact that the installer copies (None =
#               no in-repo artifact / no install recipe)
#   recipe      build command that produces src (documentation + rebuild
#               hint; the refresh script does not run make itself)
#   postprocess "none" or "strip"; audit and install both apply it to a
#               temporary copy so the repo artifact is never mutated
#   mode        install mode (octal string)
#   installer   "refresh" (w17n_factory_refresh.py copies it) or "none"
#   commit_paths  repo paths whose last commit defines the source vintage
#   rebuild_src   optional second artifact used only as evidence in --write
#                 and in the audit detail column (not installed)
#   note        short reason for NO_RECIPE / non-obvious choices
# ---------------------------------------------------------------------------
ENTRIES = [
    # --- /usr/local/bin ---------------------------------------------------
    dict(path="/usr/local/bin/occ", kind="elf",
         src="agent/ai/occ/occ",
         recipe="make -C agent/ai/occ",
         postprocess="none", mode="0755", installer="refresh",
         commit_paths=["agent/ai/occ"],
         note="tracked W-7 artifact; refresh installs it as-is"),
    dict(path="/usr/local/bin/aikctl", kind="script",
         src="agent/ai/aikctl/aikctl",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh", commit_paths=["agent/ai/aikctl/aikctl"],
         note="P-2 user/policy/session/quota/audit CLI (Python, tracked)"),
    dict(path="/usr/local/bin/aik-console", kind="script",
         src="factory/usr/local/bin/aik-console",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh", commit_paths=["factory/usr/local/bin/aik-console"],
         note="factory tree script; tracked"),
    dict(path="/usr/local/bin/aik-compat", kind="elf",
         src="agent/ai/aik-compat",
         recipe="make -C agent/ai aik-compat",
         postprocess="strip", mode="0755", installer="refresh",
         commit_paths=["tools/compat_main.c", "tools/compat_tools.c",
                       "tools/workspace_tools.c", "runtime/ai_json_util.c"],
         note="W4A/C1: strip before image (unstripped ELF layout SIGSEGV risk)"),
    dict(path="/usr/local/bin/aik-gcm", kind="elf",
         src="agent/ai/aik-gcm",
         recipe="make -C agent/ai aik-gcm",
         postprocess="strip", mode="0755", installer="refresh",
         commit_paths=["tools/gcm_main.c"],
         note="W4A/L1: strip before image (same rule as aik-compat)"),
    dict(path="/usr/local/bin/aik-sandbox", kind="elf",
         src="agent/ai/aik-sandbox",
         recipe="make -C agent/ai aik-sandbox",
         postprocess="none", mode="0755", installer="refresh",
         commit_paths=["agent/ai/sandbox/aik-sandbox.c"],
         note="Makefile output lives at agent/ai/aik-sandbox; the old "
              "untracked anchor agent/ai/sandbox/aik-sandbox is no longer used"),
    dict(path="/usr/local/bin/aik-ime", kind="elf",
         src="factory/usr/local/bin/aik-ime",
         recipe="make -C agent/ai/aikime",
         postprocess="none", mode="0755", installer="refresh",
         commit_paths=["factory/usr/local/bin/aik-ime",
                       "agent/ai/aikime/aik_ime.cpp"],
         rebuild_src="agent/ai/aikime/aik-ime",
         note="tracked factory artifact (needs ~/p55-poc librime to rebuild)"),
    dict(path="/usr/local/bin/aik-pqdump", kind="elf",
         src="agent/ai/aistreamd/aik-pqdump",
         recipe="make -C agent/ai/aistreamd aik-pqdump",
         postprocess="none", mode="0755", installer="refresh",
         commit_paths=["agent/ai/aistreamd/aik_pqdump.c",
                       "agent/ai/aistreamd/as_parquet.c"],
         note="untracked build artifact (P-27 parquet IO)"),
    # --- /usr/local/sbin --------------------------------------------------
    dict(path="/usr/local/sbin/aistreamd", kind="elf",
         src="agent/ai/aistreamd/aistreamd",
         recipe="make -C agent/ai/aistreamd",
         postprocess="none", mode="0755", installer="refresh",
         commit_paths=["agent/ai/aistreamd"],
         note="tracked W-7 artifact"),
    dict(path="/usr/local/sbin/aipd", kind="elf",
         src="agent/ai/aipd/aipd",
         recipe="make -C agent/ai/aipd",
         postprocess="none", mode="0755", installer="refresh",
         commit_paths=["agent/ai/aipd"],
         note="tracked W-7 artifact"),
    dict(path="/usr/local/sbin/aikd", kind="elf",
         src="agent/ai/smehttp/aikd",
         recipe="make -C agent/ai/smehttp -j1 all",
         postprocess="strip", mode="0755", installer="refresh",
         commit_paths=["agent/ai/smehttp", "agent/ai/smeconfig",
                       "agent/ai/engine", "agent/ai/retrieval",
                       "agent/ai/space", "agent/ai/store"],
         rebuild_src=None,
         note="second link name of smehttp main.c (T7a); strip matches the "
              "17.11.1 factory contract.  Includes MEM-01a/b/c + MEM-02a/b; "
              "the on-target MEM bench decides when it actually ships"),
    dict(path="/usr/local/sbin/aik-tls-gateway", kind="elf",
         src="agent/ai/tlsgw/aik-tls-gateway",
         recipe="make -C agent/ai/tlsgw -j1 all",
         postprocess="strip", mode="0755", installer="refresh",
         commit_paths=["agent/ai/tlsgw"],
         note="factory piece was already stripped by the legacy chain"),
    dict(path="/usr/local/sbin/autocondensed", kind="elf",
         src="agent/ai/autocondense/autocondensed",
         recipe="make -C agent/ai/autocondense -j1 all",
         postprocess="strip", mode="0755", installer="refresh",
         commit_paths=["agent/ai/autocondense"],
         note="legacy chain installed a stripped build (T9e)"),
    dict(path="/usr/local/sbin/autocondense-mcp", kind="elf",
         src="agent/ai/autocondense/autocondense-mcp",
         recipe="make -C agent/ai/autocondense -j1 all",
         postprocess="strip", mode="0755", installer="refresh",
         commit_paths=["agent/ai/autocondense"],
         note="legacy chain installed a stripped build (T9e)"),
    dict(path="/usr/local/sbin/autocondense-hook", kind="elf",
         src="agent/ai/autocondense/autocondense-hook",
         recipe="make -C agent/ai/autocondense -j1 all",
         postprocess="strip", mode="0755", installer="refresh",
         commit_paths=["agent/ai/autocondense"],
         note="legacy chain installed a stripped build (T9e)"),
    dict(path="/usr/local/sbin/aik-reset", kind="script",
         src="factory/usr/local/sbin/aik-reset",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh", commit_paths=["factory/usr/local/sbin/aik-reset"],
         note="factory tree script; tracked"),
    dict(path="/usr/local/sbin/aik-upgrade", kind="script",
         src="factory/usr/local/sbin/aik-upgrade",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh",
         commit_paths=["factory/usr/local/sbin/aik-upgrade"],
         note="factory tree script; tracked (W-7 userland channel)"),
    dict(path="/usr/local/sbin/aik-backup", kind="script",
         src="factory/usr/local/sbin/aik-backup",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh", commit_paths=["factory/usr/local/sbin/aik-backup"],
         note="factory tree script; legacy chain installed it, refresh now "
              "re-installs from the tracked source"),
    dict(path="/usr/local/sbin/aik-cert-gen", kind="script",
         src="factory/usr/local/sbin/aik-cert-gen",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh",
         commit_paths=["factory/usr/local/sbin/aik-cert-gen"],
         note="factory tree script; legacy chain installed it, refresh now "
              "re-installs from the tracked source"),
    dict(path="/usr/local/sbin/aik-token", kind="script",
         src="factory/usr/local/sbin/aik-token",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh", commit_paths=["factory/usr/local/sbin/aik-token"],
         note="factory tree script; legacy chain installed it, refresh now "
              "re-installs from the tracked source"),
    dict(path="/usr/local/sbin/aikernel-health.sh", kind="script",
         src="factory/usr/local/sbin/aikernel-health.sh",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh",
         commit_paths=["factory/usr/local/sbin/aikernel-health.sh"],
         note="factory tree script; legacy chain installed it, refresh now "
              "re-installs from the tracked source"),
    dict(path="/usr/local/sbin/aik-log-trim", kind="script",
         src="factory/usr/local/sbin/aik-log-trim",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh",
         commit_paths=["factory/usr/local/sbin/aik-log-trim"],
         note="factory tree script; legacy chain installed it, refresh now "
              "re-installs from the tracked source"),
    dict(path="/usr/local/sbin/aik-ac-hook", kind="script",
         src="factory/usr/local/sbin/aik-ac-hook",
         recipe=None, postprocess="none", mode="0755",
         installer="refresh",
         commit_paths=["factory/usr/local/sbin/aik-ac-hook"],
         note="installed by make install-autocondense in the legacy chain"),
    # --- NO_RECIPE: present in the factory tree, no current install step --
    dict(path="/usr/local/sbin/aikernel-api", kind="elf",
         src=None, recipe="make -C agent/ai/apic -j1 all",
         postprocess="none", mode="0755", installer="none",
         commit_paths=["agent/ai/apic"],
         rebuild_src="agent/ai/apic/aikerneld-api",
         note="build product is aikerneld-api; no install step, and the "
              "11-12 factory piece predates c79638a (K3 agent-id 0 -> 4). "
              "Kernel #82 freeze (H6): do not swap without a K3 kernel"),
    dict(path="/usr/local/sbin/aikd.rebuild-check", kind="skip",
         src=None, recipe="make -C agent/ai/smehttp -j1 all",
         postprocess="none", mode="0000", installer="none",
         commit_paths=[], note="internal placeholder, never audited"),
    dict(path="/usr/local/share/aikd/static/app.css", kind="asset",
         src="agent/ai/smehttp/static/app.css",
         recipe=None, postprocess="none", mode="0644",
         installer="refresh",
         commit_paths=["agent/ai/smehttp/static/app.css"],
         note="aikd web asset (aikernel-memory.service --static-dir); "
              "installed from the repo so a static update cannot silently "
              "lag the next ISO"),
    dict(path="/usr/local/share/aikd/static/app.js", kind="asset",
         src="agent/ai/smehttp/static/app.js",
         recipe=None, postprocess="none", mode="0644",
         installer="refresh",
         commit_paths=["agent/ai/smehttp/static/app.js"],
         note="aikd web asset; installed from the repo"),
    dict(path="/usr/local/share/aikd/static/index.html", kind="asset",
         src="agent/ai/smehttp/static/index.html",
         recipe=None, postprocess="none", mode="0644",
         installer="refresh",
         commit_paths=["agent/ai/smehttp/static/index.html"],
         note="aikd web asset; installed from the repo"),
    dict(path="/usr/bin/aikctl", kind="elf",
         src=None, recipe=None, postprocess="none", mode="0755",
         installer="none", commit_paths=[],
         note="stale C netlink CLI from the pre-repo build tree; source is "
              "outside this repo (linux tree tools/ai).  The live CLI is "
              "/usr/local/bin/aikctl (Python, P-2).  Not installed by any "
              "current script; kept only for the record"),
]
# Drop the internal placeholder used above to keep the sections readable.
ENTRIES = [e for e in ENTRIES if e["kind"] != "skip"]

# Third-party / base-image files in managed directories.  Exact path or
# directory prefix, each with the reason it is not an AIKernel piece.
WHITELIST = [
    ("usr/local/bin/busybox",
     "base image busybox (L0), not built by this repo"),
    ("usr/local/bin/ollama",
     "third-party ollama runtime shipped with the base image"),
    ("usr/local/lib/aik-ime/",
     "bundled third-party runtime libs for aik-ime (prebuilt upstream; "
     "copied verbatim by the refresh script, no repo build recipe)"),
    ("usr/local/lib/ollama/",
     "third-party ollama runtime libraries"),
]
BUSYBOX_LINK_TARGET = "busybox"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_normalized_file(path):
    """md5 with CRLF folded to LF (for tracked text assets whose working
    tree may carry CRLF while the git blob is LF)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    return hashlib.md5(data.replace(b"\r\n", b"\n")).hexdigest()


def size_of(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return -1


def mtime_of(path):
    try:
        return datetime.datetime.fromtimestamp(
            os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        return "?"


def is_elf(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def has_shebang(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(2)
        return head == b"#!"
    except OSError:
        return False


SHT_NOBITS = 8
SHF_ALLOC = 0x2


def elf_sections(path):
    """Return {name: (flags, sha256-of-content)} for ELF64 LE, or None."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_shentsize,) = struct.unpack_from("<H", data, 0x3A)
    (e_shnum,) = struct.unpack_from("<H", data, 0x3C)
    (e_shstrndx,) = struct.unpack_from("<H", data, 0x3E)
    if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
        return None
    try:
        shstr_off = struct.unpack_from(
            "<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
        shstr_size = struct.unpack_from(
            "<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x20)[0]
        strtab = data[shstr_off:shstr_off + shstr_size]
        out = {}
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            name_off = struct.unpack_from("<I", data, off)[0]
            sh_type = struct.unpack_from("<I", data, off + 4)[0]
            sh_flags = struct.unpack_from("<Q", data, off + 8)[0]
            sh_off = struct.unpack_from("<Q", data, off + 0x18)[0]
            sh_size = struct.unpack_from("<Q", data, off + 0x20)[0]
            end = strtab.find(b"\x00", name_off)
            name = strtab[name_off:end].decode("utf-8", "replace")
            content = b"" if sh_type == SHT_NOBITS else data[sh_off:
                                                           sh_off + sh_size]
            out[name] = (sh_flags,
                         hashlib.sha256(content).hexdigest())
        return out
    except (struct.error, IndexError):
        return None


def elf_alloc_fingerprint(path):
    secs = elf_sections(path)
    if secs is None:
        return None
    return {name: sha for name, (flags, sha) in secs.items()
            if (flags & SHF_ALLOC) and name != ".note.gnu.build-id"}


def elf_alloc_equal(a, b):
    fa, fb = elf_alloc_fingerprint(a), elf_alloc_fingerprint(b)
    if fa is None or fb is None:
        return False
    return fa == fb


def elf_diff_sections(a, b):
    sa, sb = elf_sections(a), elf_sections(b)
    if sa is None or sb is None:
        return []
    return sorted(set(sa) ^ set(sb) |
                  {n for n in set(sa) & set(sb) if sa[n][1] != sb[n][1]})


def git(repo, *args):
    try:
        out = subprocess.run(["git", "-C", repo] + list(args),
                             capture_output=True)
    except OSError:
        return None, b""
    return out.returncode, out.stdout


def head_commit(repo):
    rc, out = git(repo, "rev-parse", "HEAD")
    if rc != 0:
        return ""
    return out.decode().strip()


def last_commit(repo, paths):
    if not paths:
        return ""
    rc, out = git(repo, "log", "-1", "--format=%h %ci", "--",
                  *paths)
    if rc != 0:
        return ""
    return out.decode("utf-8", "replace").strip()


def blob_md5(repo, rev, relpath, normalize=False):
    if not rev or not relpath:
        return None
    rc, out = git(repo, "cat-file", "blob", "%s:%s" % (rev, relpath))
    if rc != 0:
        return None
    if normalize:
        out = out.replace(b"\r\n", b"\n")
    return hashlib.md5(out).hexdigest()


def snapshot_ref(root):
    """Last refresh commit recorded in the factory tree (if any)."""
    snap = os.path.join(root, "etc/aikernel/ISO-SNAPSHOT-W82.txt")
    try:
        with open(snap, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                for key in ("userland=", "refresh_commit="):
                    if line.startswith(key + "main@"):
                        return line.split("main@", 1)[1].strip()
    except OSError:
        pass
    return ""


def factory_path(root, rel):
    return os.path.join(root, rel.lstrip("/"))


# ---------------------------------------------------------------------------
# post-processing (never mutates the repo artifact)
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def prepared(entry, repo):
    src = os.path.join(repo, entry["src"]) if entry.get("src") else None
    if entry.get("postprocess") == "strip":
        fd, tmp = tempfile.mkstemp(prefix="eng14-strip-")
        os.close(fd)
        try:
            shutil.copyfile(src, tmp)
            os.chmod(tmp, 0o755)
            res = subprocess.run(["strip", tmp], capture_output=True)
            if res.returncode != 0:
                raise RuntimeError("strip failed for %s: %s"
                                   % (entry["path"],
                                      res.stderr.decode("utf-8", "replace")))
            yield tmp
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    else:
        yield src


def expected_md5(entry, repo):
    if not entry.get("src"):
        return None
    src = os.path.join(repo, entry["src"])
    if not os.path.isfile(src):
        return None
    with prepared(entry, repo) as payload:
        return md5_file(payload)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------
def audit_one(entry, root, repo, rev):
    dst = factory_path(root, entry["path"])
    row = {
        "path": entry["path"],
        "kind": entry["kind"],
        "installer": entry["installer"],
        "factory_md5": "-",
        "repo_md5": "-",
        "status": "MISSING",
        "detail": "",
    }
    if not os.path.lexists(dst):
        row["detail"] = "not present in factory tree"
        return row
    row["factory_md5"] = md5_file(dst) if os.path.isfile(dst) else "link"
    row["factory_size"] = size_of(dst)
    row["factory_mtime"] = mtime_of(dst)
    detail = []
    if entry["installer"] == "refresh":
        st = os.stat(dst)
        want_mode = int(entry["mode"], 8)
        got_mode = st.st_mode & 0o7777
        if got_mode != want_mode:
            detail.append("mode=%04o (expected %04o)"
                          % (got_mode, want_mode))
        if (st.st_uid, st.st_gid) != (0, 0):
            detail.append("owner=%d:%d (expected 0:0)"
                          % (st.st_uid, st.st_gid))
    if entry["installer"] == "none":
        row["status"] = "NO_RECIPE"
        detail.append("no install step in the current chain")
        if entry.get("src"):
            src = os.path.join(repo, entry["src"])
            if os.path.isfile(src):
                row["repo_md5"] = md5_file(src)
                if row["repo_md5"] != row["factory_md5"]:
                    detail.append("repo source differs from factory piece")
            else:
                detail.append("repo source missing: " + entry["src"])
        rs = entry.get("rebuild_src")
        if rs:
            rp = os.path.join(repo, rs)
            if os.path.isfile(rp):
                same_code = ""
                if entry["kind"] == "elf" and is_elf(rp) and is_elf(dst):
                    same_code = ("; rebuild code-identical"
                                 if elf_alloc_equal(dst, rp)
                                 else "; rebuild code differs")
                detail.append("rebuild=%s%s" % (md5_file(rp)[:12], same_code))
            else:
                detail.append("rebuild artifact missing")
        row["detail"] = "; ".join(detail)
        return row
    src = os.path.join(repo, entry["src"]) if entry.get("src") else None
    if not src or not os.path.isfile(src):
        row["status"] = "MISSING"
        row["detail"] = "repo artifact missing: %s (recipe: %s)" % (
            entry.get("src"), entry.get("recipe") or "-")
        return row
    with prepared(entry, repo) as payload:
        row["repo_md5"] = md5_file(payload)
        if row["repo_md5"] == row["factory_md5"]:
            row["status"] = "SCRIPT" if entry["kind"] == "script" else "MATCH"
        else:
            row["status"] = "DRIFT"
            detail.append("md5 %s != repo %s"
                          % (row["factory_md5"][:12], row["repo_md5"][:12]))
            if entry["kind"] == "elf" and is_elf(dst) and is_elf(payload):
                if elf_alloc_equal(dst, payload):
                    detail.append("code-identical: only build-id/debug/"
                                  "symbol sections differ (build path or "
                                  "strip state)")
                else:
                    diff = elf_diff_sections(dst, payload)
                    detail.append("code differs in sections: "
                                  + ", ".join(diff[:6]))
            detail.append("postprocess=%s" % entry["postprocess"])
    # Optional evidence: a second build artifact (not installed).
    rs = entry.get("rebuild_src")
    if rs:
        rp = os.path.join(repo, rs)
        if os.path.isfile(rp):
            same_code = ""
            if entry["kind"] == "elf" and is_elf(rp) and is_elf(dst):
                same_code = ("; rebuild code-identical"
                             if elf_alloc_equal(dst, rp)
                             else "; rebuild code differs")
            detail.append("rebuild=%s%s" % (md5_file(rp)[:12], same_code))
        else:
            detail.append("rebuild artifact missing")
    # Provenance: is the factory piece exactly the blob at the last
    # refresh commit?  Text assets may be CRLF in the factory tree while
    # the blob is LF, so compare them line-ending-normalised.
    if rev and entry.get("src") and not entry["src"].startswith("factory/"):
        is_text = entry["kind"] in ("script", "asset")
        bm = blob_md5(repo, rev, entry["src"], normalize=is_text)
        fm = (md5_normalized_file(dst) if is_text else row["factory_md5"])
        if bm:
            if bm == fm:
                detail.append("factory piece == blob@%s" % rev[:8])
            else:
                detail.append("factory piece != blob@%s" % rev[:8])
    row["detail"] = "; ".join(detail)
    return row


def run_audit(root, repo, rev=None, out=None):
    rows = []
    for entry in ENTRIES:
        rows.append(audit_one(entry, root, repo, rev))
    print_audit(rows, root, repo, rev, out=out)
    bad = [r for r in rows if r["status"] in ("DRIFT", "MISSING")]
    return 1 if bad else 0


def print_audit(rows, root, repo, rev, out=None):
    def emit(line):
        print(line)
        if out:
            out.write(line + "\n")

    emit("== ENG-14 factory audit ==")
    emit("factory_root=%s" % root)
    emit("repo=%s" % repo)
    emit("repo_head=%s" % (head_commit(repo) or "?"))
    emit("factory_refresh_commit=%s" % (rev or "not recorded"))
    emit("")
    emit("%-9s %-42s %-6s %-8s %-32s %-32s %s"
         % ("STATUS", "PATH", "KIND", "INSTALL", "FACTORY_MD5",
            "REPO_MD5", "DETAIL"))
    for r in rows:
        emit("%-9s %-42s %-6s %-8s %-32s %-32s %s"
             % (r["status"], r["path"], r["kind"], r["installer"],
                r["factory_md5"], r["repo_md5"], r["detail"]))
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    emit("")
    emit("SUMMARY total=%d %s" % (
        len(rows),
        " ".join("%s=%d" % (k, counts[k]) for k in sorted(counts))))
    drift = [r["path"] for r in rows if r["status"] == "DRIFT"]
    if drift:
        emit("DRIFT_PATHS %s" % " ".join(drift))


def audit_main(args):
    root = os.path.abspath(args.root or DEFAULT_ROOT)
    repo = os.path.abspath(args.repo or DEFAULT_REPO)
    if not os.path.isdir(root):
        print("factory root not found: %s" % root, file=sys.stderr)
        return 2
    rev = snapshot_ref(root)
    out = None
    if args.out:
        out = open(args.out, "w", encoding="utf-8")
    try:
        return run_audit(root, repo, rev=rev, out=out)
    finally:
        if out:
            out.close()


# ---------------------------------------------------------------------------
# --write
# ---------------------------------------------------------------------------
def write_manifest(path, root, repo):
    head = head_commit(repo)
    rev = snapshot_ref(root)
    now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")
    lines = []
    lines.append("# FACTORY-MANIFEST - generated by build/factory_manifest.py"
                 " --write")
    lines.append("# schema=1")
    lines.append("built_from_commit=%s" % head)
    lines.append("factory_refresh_commit=%s" % (rev or "not-recorded"))
    lines.append("generated=%s" % now)
    lines.append("factory_root=%s" % root)
    lines.append("manifest_entries=%d" % len(ENTRIES))
    lines.append("refresh_entries=%d"
                 % sum(1 for e in ENTRIES if e["installer"] == "refresh"))
    lines.append("norecipe_entries=%d"
                 % sum(1 for e in ENTRIES if e["installer"] == "none"))
    for e in ENTRIES:
        dst = factory_path(root, e["path"])
        lines.append("")
        lines.append("[%s]" % e["path"])
        lines.append("kind=%s" % e["kind"])
        lines.append("installer=%s" % e["installer"])
        lines.append("postprocess=%s" % e["postprocess"])
        lines.append("mode=%s" % e["mode"])
        lines.append("src=%s" % (e.get("src") or "-"))
        lines.append("recipe=%s" % (e.get("recipe") or "-"))
        lines.append("src_last_commit=%s"
                     % (last_commit(repo, e.get("commit_paths") or [])
                        or "-"))
        rm = expected_md5(e, repo)
        lines.append("repo_md5=%s" % (rm or "absent"))
        if os.path.lexists(dst):
            lines.append("factory_md5=%s" % (
                md5_file(dst) if os.path.isfile(dst) else "link"))
            lines.append("factory_size=%d" % size_of(dst))
            lines.append("factory_mtime=%s" % mtime_of(dst))
            st = os.lstat(dst)
            lines.append("factory_mode=%04o" % (st.st_mode & 0o7777))
            lines.append("factory_owner=%d:%d" % (st.st_uid, st.st_gid))
        else:
            lines.append("factory_md5=absent")
        if e.get("rebuild_src"):
            rp = os.path.join(repo, e["rebuild_src"])
            lines.append("rebuild_md5=%s"
                         % (md5_file(rp) if os.path.isfile(rp) else "absent"))
        if rev and e.get("src") and not e["src"].startswith("factory/"):
            is_text = e["kind"] in ("script", "asset")
            bm = blob_md5(repo, rev, e["src"], normalize=is_text)
            lines.append("blob_at_refresh_commit=%s" % (bm or "absent"))
        if e.get("note"):
            lines.append("note=%s" % e["note"])
    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote %s (%d bytes, %d entries)"
          % (path, len(text.encode("utf-8")), len(ENTRIES)))
    return 0


def write_main(args):
    root = os.path.abspath(args.root or DEFAULT_ROOT)
    repo = os.path.abspath(args.repo or DEFAULT_REPO)
    out = args.out or os.path.join(HERE, "FACTORY-MANIFEST.txt")
    return write_manifest(out, root, repo)


# ---------------------------------------------------------------------------
# --check-installed
# ---------------------------------------------------------------------------
def is_one_party_name(name):
    n = name.lower()
    return (n.startswith("aik") or n.startswith("occ")
            or n.startswith("autocondense") or n in ("aistreamd", "aipd"))


def whitelisted(rel):
    for pat, reason in WHITELIST:
        if pat.endswith("/"):
            if rel.startswith(pat):
                return reason
        elif rel == pat:
            return reason
    return None


def scan_dir(root, rel_dir):
    """Yield (relpath, abs path, is_symlink) for direct children."""
    base = os.path.join(root, rel_dir)
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return
    for name in names:
        ap = os.path.join(base, name)
        if os.path.isdir(ap) and not os.path.islink(ap):
            for sub in sorted(os.listdir(ap)):
                sp = os.path.join(ap, sub)
                if os.path.isdir(sp) and not os.path.islink(sp):
                    continue
                yield (os.path.join(rel_dir, name, sub), sp,
                       os.path.islink(sp))
        else:
            yield (os.path.join(rel_dir, name), ap, os.path.islink(ap))


def wl_key(rel):
    """Group whitelist hits by rule (exact path or directory prefix)."""
    for pat, reason in WHITELIST:
        if pat.endswith("/"):
            if rel.startswith(pat):
                return "%s (dir) %s" % (pat, reason)
        elif rel == pat:
            return "%s %s" % (pat, reason)
    return rel


def check_installed(root):
    known = {e["path"] for e in ENTRIES}
    unmanaged = []
    beyond_manifest = []
    wl_hits = {}
    scanned = 0
    for d in MANAGED_DIRS:
        for rel, ap, link in scan_dir(root, d):
            scanned += 1
            if ("/" + rel) in known:
                continue
            if link:
                try:
                    tgt = os.readlink(ap)
                except OSError:
                    tgt = ""
                if tgt == BUSYBOX_LINK_TARGET:
                    key = "%s applet symlinks -> %s" % (d, BUSYBOX_LINK_TARGET)
                    wl_hits[key] = wl_hits.get(key, 0) + 1
                    continue
                if whitelisted(rel):
                    key = wl_key(rel)
                    wl_hits[key] = wl_hits.get(key, 0) + 1
                    continue
                beyond_manifest.append((rel, "symlink->%s" % tgt))
                continue
            if whitelisted(rel):
                key = wl_key(rel)
                wl_hits[key] = wl_hits.get(key, 0) + 1
                continue
            one_party = (is_one_party_name(os.path.basename(rel))
                         or is_elf(ap) or has_shebang(ap))
            if one_party:
                unmanaged.append((rel, "elf" if is_elf(ap) else "script"))
            else:
                beyond_manifest.append((rel, "unclassified non-one-party"))
    # Watch dirs: one-party pieces outside the managed set are reported,
    # but do not fail the gate (they belong to ENG-05/07 cleanup).
    watch = []
    for d in WATCH_DIRS:
        for rel, ap, link in scan_dir(root, d):
            if link:
                continue
            if is_one_party_name(os.path.basename(rel)):
                watch.append(rel)
    print("== ENG-14 installed-file scan ==")
    print("factory_root=%s" % root)
    for key in sorted(wl_hits):
        print("WHITELIST %-48s x%d" % (key, wl_hits[key]))
    for rel, why in sorted(beyond_manifest):
        print("EXTRA     %-48s %s" % (rel, why))
    for rel, why in sorted(unmanaged):
        print("UNMANAGED %-48s %s" % (rel, why))
    for rel in sorted(watch):
        known_here = ("/" + rel) in known
        print("WATCH     %-48s %s" % (
            rel, "known NO_RECIPE" if known_here else "outside manifest"))
    print("SUMMARY scanned=%d manifest=%d whitelisted=%d extra=%d "
          "unmanaged=%d watch=%d"
          % (scanned, len(known), sum(wl_hits.values()),
             len(beyond_manifest), len(unmanaged), len(watch)))
    return 1 if unmanaged else 0


# ---------------------------------------------------------------------------
# --selftest
# ---------------------------------------------------------------------------
def _pick(entry_path):
    for e in ENTRIES:
        if e["path"] == entry_path:
            return e
    raise KeyError(entry_path)


def _install_fake(root, entry, repo):
    dst = factory_path(root, entry["path"])
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with prepared(entry, repo) as payload:
        shutil.copyfile(payload, dst)
    os.chmod(dst, int(entry["mode"], 8))


def selftest(repo):
    tmp = tempfile.mkdtemp(prefix="eng14-selftest-")
    ok = True

    def check(label, cond, extra=""):
        nonlocal ok
        print("%-6s %s%s" % ("PASS" if cond else "FAIL", label,
                             (" " + extra) if extra else ""))
        if not cond:
            ok = False

    try:
        elf = _pick("/usr/local/bin/aik-ime")       # tracked factory ELF
        script = _pick("/usr/local/bin/aik-console")  # tracked factory script
        for e in (elf, script):
            if not os.path.isfile(os.path.join(repo, e["src"])):
                print("SKIP selftest: tracked fixture missing: %s" % e["src"])
                return 2
            _install_fake(tmp, e, repo)
        rows = {r["path"]: r for r in
                (audit_one(e, tmp, repo, "") for e in (elf, script))}
        check("MATCH on identical ELF",
              rows[elf["path"]]["status"] == "MATCH",
              rows[elf["path"]]["status"])
        check("SCRIPT on identical script",
              rows[script["path"]]["status"] == "SCRIPT",
              rows[script["path"]]["status"])
        # Flip one byte in the middle of the ELF copy -> DRIFT.
        dpath = factory_path(tmp, elf["path"])
        with open(dpath, "r+b") as fh:
            fh.seek(os.path.getsize(dpath) // 2)
            b = fh.read(1)
            fh.seek(-1, os.SEEK_CUR)
            fh.write(bytes([b[0] ^ 0xFF]))
        row = audit_one(elf, tmp, repo, "")
        check("DRIFT after one-byte flip", row["status"] == "DRIFT",
              row["status"] + " | " + row["detail"])
        # Remove the script -> MISSING.
        os.unlink(factory_path(tmp, script["path"]))
        row = audit_one(script, tmp, repo, "")
        check("MISSING after deletion", row["status"] == "MISSING",
              row["status"])
        # NO_RECIPE entry is reported as such when present.
        nr = _pick("/usr/bin/aikctl")
        if os.path.lexists(factory_path(tmp, nr["path"])):
            pass
        else:
            os.makedirs(os.path.dirname(factory_path(tmp, nr["path"])),
                        exist_ok=True)
            shutil.copyfile(os.path.join(repo, elf["src"]),
                            factory_path(tmp, nr["path"]))
        row = audit_one(nr, tmp, repo, "")
        check("NO_RECIPE reported", row["status"] == "NO_RECIPE",
              row["status"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="ENG-14 factory manifest / audit (read-only by default)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--audit", action="store_true",
                   help="compare factory tree with repo artifacts")
    g.add_argument("--write", action="store_true",
                   help="write FACTORY-MANIFEST.txt")
    g.add_argument("--check-installed", action="store_true",
                   help="report one-party files missing from the manifest")
    g.add_argument("--selftest", action="store_true",
                   help="fake-tree MATCH/DRIFT/MISSING selftest")
    ap.add_argument("--root", default=None,
                    help="factory root (default: $AIK_FACTORY_ROOT or "
                         "~/w7i-rootfs)")
    ap.add_argument("--repo", default=None, help="repo root")
    ap.add_argument("--out", default=None,
                    help="output file (--audit table or --write manifest)")
    args = ap.parse_args(argv)
    if args.audit:
        return audit_main(args)
    if args.write:
        return write_main(args)
    if args.check_installed:
        root = os.path.abspath(args.root or DEFAULT_ROOT)
        return check_installed(root)
    if args.selftest:
        repo = os.path.abspath(args.repo or DEFAULT_REPO)
        return selftest(repo)
    return 2


if __name__ == "__main__":
    sys.exit(main())
