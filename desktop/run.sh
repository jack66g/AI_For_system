#!/bin/sh
# W76b manual entry point (systemd normally starts /opt/aikdesktop/server.py).
# The writable state root defaults to /var/lib/aikdesktop on the factory/VM;
# for a throw-away L1 test set AIK_DESKTOP_ROOT and AIK_DESKTOP_PORT.
set -e
cd "$(dirname "$0")"
export AIK_DESKTOP_ROOT="${AIK_DESKTOP_ROOT:-/var/lib/aikdesktop}"
export AIK_DESKTOP_PORT="${AIK_DESKTOP_PORT:-8091}"
export AIK_DESKTOP_BIND="${AIK_DESKTOP_BIND:-127.0.0.1}"
export AIK_DESKTOP_VM="${AIK_DESKTOP_VM:-0}"
export AIK_DESKTOP_SCREENSHOT="${AIK_DESKTOP_SCREENSHOT:-0}"
exec /usr/bin/python3 ./server.py
