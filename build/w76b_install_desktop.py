#!/usr/bin/env python3
"""W76b: install the desktop demo bundle into the factory rootfs (idempotent).

Run as root on L1:
  python3 ~/aikernel-longterm/w76b_install_desktop.py

It is also invoked at the end of w73_factory_refresh.py so an alpha.10
factory refresh always carries /opt/aikdesktop + aik-desktop.service.
It never touches the existing aik-upgrade/tools/seed steps and never
touches the running L1 8091 demo.
"""
import argparse
import os
import shutil

DEFAULT_SRC = "/home/jack66g/aikernel-longterm/desktop"
DEFAULT_ROOT = "/home/jack66g/w7i-rootfs"
BACKUP = "/home/jack66g/w76b-backup/factory-pre-w76b"
TARGET_REL = "/opt/aikdesktop"
UNIT_REL = "/etc/systemd/system/aik-desktop.service"
WANTS_REL = "/etc/systemd/system/multi-user.target.wants/aik-desktop.service"
STATE_REL = "/var/lib/aikdesktop"
SERVICE_USER = "aikdesk"
SERVICE_UID = 998
SERVICE_GID = 998


def _read_kv(path, sep):
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split(sep)
            if len(parts) >= 3:
                out.append(parts)
    return out


def _ensure_service_user(root):
    """Create the fixed, locked aikdesk system account if absent.

    Idempotent; backs up /etc/{passwd,group,shadow} on the first change.
    The unit needs a real passwd entry (DynamicUser/nobody are deliberately
    avoided: the factory rootfs is offline and systemd warns about nobody).
    """
    passwd = root + "/etc/passwd"
    group = root + "/etc/group"
    shadow = root + "/etc/shadow"
    p_entry = None
    g_entry = None
    for parts in _read_kv(passwd, ":"):
        if parts[0] == SERVICE_USER:
            p_entry = parts
            break
    for parts in _read_kv(group, ":"):
        if parts[0] == SERVICE_USER:
            g_entry = parts
            break

    uid = int(p_entry[2]) if p_entry else SERVICE_UID
    if g_entry:
        gid = int(g_entry[2])
    elif p_entry:
        gid = int(p_entry[3])
    else:
        gid = SERVICE_GID

    if p_entry is None:
        if any(p[2].isdigit() and int(p[2]) == uid
               for p in _read_kv(passwd, ":")):
            raise SystemExit("UID %d already in use in %s" % (uid, passwd))
        _backup(root, "/etc/passwd")
        with open(passwd, "a", encoding="utf-8", newline="\n") as f:
            f.write("%s:x:%d:%d:AIKernel Desktop Service:"
                    "/var/lib/aikdesktop:/usr/sbin/nologin\n"
                    % (SERVICE_USER, uid, gid))
        os.chmod(passwd, 0o644)
        _chown_root(passwd)
    if g_entry is None:
        if any(p[2].isdigit() and int(p[2]) == gid
               for p in _read_kv(group, ":")):
            raise SystemExit("GID %d already in use in %s" % (gid, group))
        _backup(root, "/etc/group")
        with open(group, "a", encoding="utf-8", newline="\n") as f:
            f.write("%s:x:%d:\n" % (SERVICE_USER, gid))
        os.chmod(group, 0o644)
        _chown_root(group)
    if os.path.isfile(shadow):
        names = {p[0] for p in _read_kv(shadow, ":")}
        if SERVICE_USER not in names:
            _backup(root, "/etc/shadow")
            with open(shadow, "a", encoding="utf-8", newline="\n") as f:
                f.write("%s:!*:0:0:99999:7:::\n" % SERVICE_USER)
            _chown_root(shadow)
    return uid, gid


def _backup(root, rel):
    src = root + rel
    if not os.path.lexists(src):
        return
    dst = BACKUP + rel
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.lexists(dst):
        return  # keep the first pre-W76b copy
    if os.path.isdir(src) and not os.path.islink(src):
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst, follow_symlinks=False)


def _chown_root(path):
    try:
        os.chown(path, 0, 0, follow_symlinks=False)
    except PermissionError:
        pass


def _chown_uidgid(path, uid, gid):
    try:
        os.chown(path, uid, gid)
    except PermissionError:
        pass


def _apply_tree(root):
    """Directories 0755; regular files 0644; run.sh executable."""
    for dirpath, dirnames, filenames in os.walk(root):
        os.chmod(dirpath, 0o755)
        _chown_root(dirpath)
        for name in filenames:
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                continue
            mode = 0o755 if name == "run.sh" else 0o644
            os.chmod(p, mode)
            _chown_root(p)


def install(src=DEFAULT_SRC, root=DEFAULT_ROOT, enable=True, quiet=False):
    src = os.path.abspath(src)
    root = os.path.abspath(root)
    if not os.path.isfile(os.path.join(src, "server.py")):
        raise SystemExit("desktop source missing server.py: %s" % src)
    if not os.path.isdir(os.path.join(src, "static")):
        raise SystemExit("desktop source missing static/: %s" % src)
    os.makedirs(BACKUP, exist_ok=True)
    _backup(root, TARGET_REL)
    _backup(root, UNIT_REL)
    uid, gid = _ensure_service_user(root)

    target = root + TARGET_REL
    if os.path.lexists(target):
        if os.path.isdir(target) and not os.path.islink(target):
            shutil.rmtree(target)
        else:
            os.unlink(target)
    shutil.copytree(src, target, symlinks=False)
    _apply_tree(target)

    os.makedirs(os.path.dirname(root + UNIT_REL), exist_ok=True)
    shutil.copyfile(os.path.join(src, "aik-desktop.service"),
                    root + UNIT_REL)
    os.chmod(root + UNIT_REL, 0o644)
    _chown_root(root + UNIT_REL)

    state = root + STATE_REL
    os.makedirs(state, exist_ok=True)
    os.chmod(state, 0o700)
    _chown_uidgid(state, uid, gid)

    wants = root + WANTS_REL
    os.makedirs(os.path.dirname(wants), exist_ok=True)
    if enable:
        if os.path.lexists(wants):
            if not os.path.islink(wants):
                os.unlink(wants)
        if not os.path.lexists(wants):
            os.symlink("../aik-desktop.service", wants)
    else:
        if os.path.lexists(wants):
            os.unlink(wants)

    required = (
        "/server.py", "/theme.json", "/static/index.html",
        "/static/app.js", "/static/style.css", "/data/apps-catalog.json",
    )
    for rel in required:
        if not os.path.isfile(target + rel):
            raise SystemExit("W76b install incomplete: %s" % (target + rel))
    st = os.stat(state)
    if (st.st_mode & 0o777) != 0o700 or st.st_uid != uid:
        raise SystemExit("W76b state dir not 0700:%d: %s" % (uid, state))
    if enable and not os.path.islink(wants):
        raise SystemExit("W76b enable symlink missing: %s" % wants)

    if not quiet:
        print("W76B_DESKTOP_INSTALLED")
        print("  source  = %s" % src)
        print("  target  = %s" % target)
        print("  unit    = %s" % (root + UNIT_REL))
        print("  state   = %s (0700 aikdesk)" % state)
        print("  enabled = %s" % ("yes" if enable else "no"))
    return target


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEFAULT_SRC)
    ap.add_argument("--root", default=DEFAULT_ROOT)
    ap.add_argument("--no-enable", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    install(args.src, args.root, enable=not args.no_enable, quiet=args.quiet)


if __name__ == "__main__":
    main()
