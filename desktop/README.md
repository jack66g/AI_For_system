# AIKernel desktop demo (W76b factory/VM bundle)

This directory is installed as `/opt/aikdesktop` and served by
`aik-desktop.service` on **127.0.0.1:8091 only**. It is the W76 Web demo
pinned into the factory rootfs; it is **not** a real OS window manager
(W84).

## Layout

- `server.py`, `static/**`, `locales/**`, `theme.json` — read-only payload.
- `data/apps-catalog.json` — virtual app catalog used only when the host has
  fewer than 5 real `.desktop` entries (the factory rootfs only ships a
  `NoDisplay` python3.10 entry). Catalog apps create virtual windows; no
  host process is started.
- `data/{notifs,desktop,pin}.json` — first-start seed templates.

## Runtime state

`AIK_DESKTOP_ROOT` (default `/var/lib/aikdesktop`, created by systemd
`StateDirectory=aikdesktop`, mode 0700, owner `aikdesk`) holds `theme.json`,
`desktop.json`, `notifs.json`, `pin.json`, `chats/`, `screenshots/` and
runtime-generated icons. State files are written atomically with mode
**0600**.

## Environment

| Variable | Default (unit) | Meaning |
|---|---|---|
| `AIK_DESKTOP_ROOT` | `/var/lib/aikdesktop` | writable state root |
| `AIK_DESKTOP_PORT` | `8091` | loopback HTTP port; 8000/8080/8761/9443/9999/11434 are refused |
| `AIK_DESKTOP_BIND` | `127.0.0.1` | loopback only (`127.0.0.1`, `localhost`, `::1`) |
| `AIK_DESKTOP_VM` | `0` | `1` re-enables the L1-only SSH tunnel to 138:8761; factory/VM must keep `0` |
| `AIK_DESKTOP_SCREENSHOT` | `0` | `auto` probes Playwright; factory keeps `0` → `/api/screenshot` 503 |
| `AIK_DESKTOP_APPS_DIR` | `/usr/share/applications` | real `.desktop` scan; <5 visible apps triggers the bundled virtual catalog |

## Health / invocation

```sh
systemctl status aik-desktop.service
curl -s http://127.0.0.1:8091/api/health
curl -s http://127.0.0.1:8091/api/windows
```

On the VM `desktop.screenshot` is **unavailable** (no Playwright/chromium):
`/api/screenshot` returns HTTP 503 `screenshot unavailable`, and `/api/health`
reports `desktop.screenshot = "unavailable"`. The W76 L1 demo's 12/12
screenshot evidence remains the screenshot evidence; VM screenshots are
W84/optional.

## Uninstall

```sh
systemctl disable --now aik-desktop.service
rm -f /etc/systemd/system/aik-desktop.service
systemctl daemon-reload
rm -rf /opt/aikdesktop /var/lib/aikdesktop
```

`ai`, `aikernel-api`, SME and all non-desktop tools do not depend on this
service; stopping/disabling it only makes `desktop_*` tools return
`E_DESKTOP_UNAVAILABLE`.
