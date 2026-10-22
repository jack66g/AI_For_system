#!/usr/bin/env python3
"""Create the alpha.11.0 qemu smoke driver from the W61 one."""
import os
import re

src = os.path.expanduser("~/mbedtls-trim-evidence/logs/fix-w61/qsmoke-w61.py")
dst = os.path.expanduser(
    "~/mbedtls-trim-evidence/logs/fix-alpha11/qsmoke-alpha11.py")
os.makedirs(os.path.dirname(dst), exist_ok=True)
s = open(src, encoding="utf-8").read()


def rep(old, new, n=1):
    global s
    c = s.count(old)
    assert c == n, (old[:80], c)
    s = s.replace(old, new)


# markers / paths
s = s.replace("W61", "A10")
s = s.replace("w61check.py", "a10check.py")
s = s.replace("qsmoke-w61.py", "qsmoke-alpha11.py")
s = s.replace("w61-qemu", "alpha11-qemu")

# release and ISO name
rep("AIKernel-0.1.0-alpha.8.0-x86_64.iso",
    "AIKernel-0.1.0-alpha.11.0-x86_64.iso")
s = s.replace("alpha.8.0", "alpha.11.0").replace("alpha80", "alpha110")
s = s.replace("motd80", "motd100").replace("readme80", "readme100")

# artifacts
s = s.replace("6846898c0f952d98ea667d36c226461b",
              "a50cafa6285bbef0f0a2011923481d8f")  # kernel #59
s = s.replace("14ef3d37c51f530a159048a3496d1886",
              "adb71f65c7e60fdcba2ce88da9093546")  # ai / shell
s = s.replace("a1d27df21f46bec064e751a3a19bb2b0",
              "2fff618051be53bd6187b96ad11c9206")  # sandbox
s = s.replace("e654434e373f95b470c5cb38d0778c54",
              "34d5af9ca7279e436690169c9af65873")  # tools
s = s.replace("b6aa0f670d52cdc3243af0846d3afc62",
              "ab7656229c60fcebfab20b55952ae2f2")  # openai
s = s.replace("2c34def158f8b7c88846402ee1c2073a",
              "25f25c255bb75818f0db09fb80855a25")  # sandbox tools
s = s.replace("054c58ab6fad3978a9c9f1cb680a7f9a",
              "f93767385a788bfff1a587f1eea2b321")  # seed
s = s.replace("#47", "#59").replace("k47", "k59")
s = s.replace("seed 355 行", "seed 167 行")

# counts
rep("'tools_len': '130'", "'tools_len': '151'")
rep("'tools_decl': '130'", "'tools_decl': '151'")
s = s.replace('seed_lines\': \'355\'', 'seed_lines\': \'167\'')
s = s.replace('seed_json_ok\': \'355\'', 'seed_json_ok\': \'167\'')

# EXPECT additions
rep("""    'memory_n': '30',
    'seed_lines': '167',""",
    """    'memory_n': '30',
    'desktop_n': '20',
    'desktop_bundle': '1',
    'desktop_unit': '1',
    'desktop_state': '1',
    'md5_catalog': 'ad3e216edad31fb16378329d41c3c777',
    'md5_upgrade': '6d3392d26b65201e5151227717d57e8c',
    'md5_api': 'e007a7d9d9e8cd9e81ec977d92bd9056',
    'api_unit': '1',
    'md5_desktop_server': 'f09f55a89631f63e118122c30b000c68',
    'md5_desktop_unit': '16744040f5467de50be49bda6efe1aac',
    'desktop_files': '70',
    'state_mode': '700',
    'state_uid': '998',
    'model_mode': '600',
    'seed_lines': '167',""")

# contentcheck additions
rep("""R['memory_n'] = sum(1 for n in names if n.startswith('memory_'))""",
    """R['memory_n'] = sum(1 for n in names if n.startswith('memory_'))
R['desktop_n'] = sum(1 for n in names if n.startswith('desktop_'))
R['desktop_bundle'] = int(os.path.isfile('/opt/aikdesktop/server.py'))
_unit = open('/etc/systemd/system/aik-desktop.service', encoding='utf-8').read()
R['desktop_unit'] = int('User=aikdesk' in _unit and 'IPAddressAllow=127.0.0.1' in _unit)
R['desktop_state'] = int('StateDirectory=aikdesktop' in _unit and 'StateDirectoryMode=0700' in _unit)
R['md5_catalog'] = md5(base + '/tool_catalog.txt')
R['md5_upgrade'] = md5('/usr/local/sbin/aik-upgrade')
R['md5_api'] = md5('/usr/local/sbin/aikernel-api')
R['api_unit'] = int(os.path.isfile('/etc/systemd/system/aikernel-api.service'))
R['md5_desktop_server'] = md5('/opt/aikdesktop/server.py')
R['md5_desktop_unit'] = md5('/etc/systemd/system/aik-desktop.service')
R['desktop_files'] = sum(len(fs) for _, _, fs in os.walk('/opt/aikdesktop'))
R['state_mode'] = oct(os.stat('/var/lib/aikdesktop').st_mode & 0o777)[2:]
R['state_uid'] = str(os.stat('/var/lib/aikdesktop').st_uid)
R['model_mode'] = oct(os.stat('/root/.aikernel/model.toml').st_mode & 0o777)[2:]
# qemu deskcheck only: skip first-run onboarding so the serial AI shell reaches REPL
os.makedirs('/etc/aikernel', exist_ok=True)
open('/etc/aikernel/.onboarded', 'w').write('onboarded=1\\n')
# deskcheck-only test disk tweak: keep serial in bash, not AI console
try:
    _p = '/root/.profile'
    _s = open(_p).read()
    if 'exec /usr/local/bin/aikernel-shell' in _s:
        open(_p, 'w').write(_s.replace(
            'exec /usr/local/bin/aikernel-shell',
            '# exec /usr/local/bin/aikernel-shell'))
except Exception:
    pass""")

# never embed the local sudo password in generated evidence
s = re.sub(r'printf "[^"]*" \| sudo -S sh -c',
           '/home/jack66g/aikernel-longterm/aik-sudo.sh sh -c', s)

# header comment update
s = s.replace("130 工具/4 sandbox/30 memory",
              "151 工具/20 desktop/4 sandbox/30 memory")
s = s.replace("<install|diskboot|contentcheck>",
              "<install|diskboot|deskcheck|contentcheck>")

DESKCHECK = r'''elif STAGE == 'deskcheck':
    cmd = qemu_common('-drive file=%s,if=virtio' % DISK)
    logp = WRK + '/serial-drive.log'
    off = os.path.getsize(logp) if os.path.exists(logp) else 0
    p = qstart(cmd, 'smoke4-deskcheck.log')
    ser = Serial(logp)
    ser.wait(b'#59 SMP PREEMPT_DYNAMIC', 240)
    ser.wait(b'root@aikernel', 300)
    time.sleep(2)
    send_lines(ser, [
        "for i in 1 2 3 4 5 6 7 8 9 10; do systemctl is-active --quiet aik-desktop && break; sleep 1; done",
        "systemctl is-active aik-desktop >/tmp/a10a 2>&1; echo A10_ACTIVE=$(cat /tmp/a10a)",
        "systemctl is-enabled aik-desktop >/tmp/a10e 2>&1; echo A10_ENABLED=$(cat /tmp/a10e)",
        "ss -ltn | grep -q '127.0.0.1:8091' && echo A10_LOOPBACK=1 || echo A10_LOOPBACK=0",
        "ss -ltn | grep -q ':8091' && ss -ltn | grep ':8091' | grep -qv '127.0.0.1:8091' && echo A10_ANY_ADDR=1 || echo A10_ANY_ADDR=0",
        "stat -c 'A10_STATE=%a' /var/lib/aikdesktop 2>/dev/null",
        "stat -c 'A10_STATE_OWNER=%U' /var/lib/aikdesktop 2>/dev/null",
        "echo A10_UID=$(id -u aikdesk)",
        "python3 - <<'PY'",
        "import urllib.request, urllib.error",
        "for path in ('/api/health','/api/screenshot'):",
        "    key = path.strip('/').replace('/','_').upper()",
        "    try:",
        "        r = urllib.request.urlopen('http://127.0.0.1:8091'+path, timeout=8)",
        "        print('A10_%s=%d' % (key, r.status))",
        "    except urllib.error.HTTPError as e:",
        "        print('A10_%s=%d' % (key, e.code))",
        "    except Exception:",
        "        print('A10_%s=ERR' % key)",
        "PY",
        "python3 - <<'PY'",
        "import urllib.request, urllib.error",
        "req = urllib.request.Request('http://127.0.0.1:8091/api/power', data=b'{\"action\":\"reboot\"}', headers={'Content-Type':'application/json'})",
        "try:",
        "    r = urllib.request.urlopen(req, timeout=8); print('A10_POWER=%d' % r.status)",
        "except urllib.error.HTTPError as e: print('A10_POWER=%d' % e.code)",
        "except Exception: print('A10_POWER=ERR')",
        "PY",
        "systemctl disable --now aik-desktop >/dev/null 2>&1; sleep 2; ss -ltn | grep -q ':8091' && echo A10_DISABLE=0 || echo A10_DISABLE=1",
        "ai --version >/dev/null 2>&1 && echo A10_AI=1 || echo A10_AI=0",
        "systemctl enable --now aik-desktop >/dev/null 2>&1; sleep 3; systemctl is-active aik-desktop >/dev/null && echo A10_REENABLE=1 || echo A10_REENABLE=0",
        "systemctl is-active aikernel-api >/tmp/a10api 2>&1; echo A10_API_ACTIVE=$(cat /tmp/a10api)",
        "ss -ltn | grep -q '127.0.0.1:8761' && echo A10_API_LOOPBACK=1 || echo A10_API_LOOPBACK=0",
        "echo A10_DONE=1",
    ], delay=0.7)
    ser.wait(b'A10_DONE=1', 180)
    time.sleep(3)
    ser.send(b'poweroff -f\r\n')
    ser.wait(b'Power down', 90)
    ser.drain_close()
    qstop(p)
    body = open(logp, 'rb').read()[off:]
    # 串口回显带 bracketed-paste/ANSI 与行首 \r；先归一化再抓标记
    body = re.sub(rb'\x1b\[[0-9;?]*[A-Za-z]', b'', body).replace(b'\r', b'\n')
    vals = {}
    for m in re.finditer(rb'(?m)^A10_(\w+)=(.*)$', body):
        vals[m.group(1).decode()] = m.group(2).decode('utf-8', 'replace').strip()
    checks = {
        'active': vals.get('ACTIVE') == 'active',
        'enabled': vals.get('ENABLED') == 'enabled',
        'loopback': vals.get('LOOPBACK') == '1',
        'no_any_addr': vals.get('ANY_ADDR') == '0',
        'state_mode': vals.get('STATE') == '700',
        'state_owner': vals.get('STATE_OWNER') == 'aikdesk',
        'uid_998': vals.get('UID') == '998',
        'health': vals.get('API_HEALTH') == '200',
        'screenshot_503': vals.get('API_SCREENSHOT') == '503',
        'power_501': vals.get('POWER') == '501',
        'disable': vals.get('DISABLE') == '1',
        'ai_core': vals.get('AI') == '1',
        'reenable': vals.get('REENABLE') == '1',
        'api_active': vals.get('API_ACTIVE') == 'active',
        'api_loopback': vals.get('API_LOOPBACK') == '1',
    }
    print('[raw]', vals)
    print('[verdict] deskcheck:', checks)
    sys.exit(0 if all(checks.values()) else 1)

'''

rep("elif STAGE == 'contentcheck':", DESKCHECK + "elif STAGE == 'contentcheck':")

s = s.replace("A10", "A11")
open(dst, "w", encoding="utf-8").write(s)
print("written", dst)
for key in ("alpha.11.0", "#59", "a50cafa6285bbef0f0a2011923481d8f",
            "adb71f65c7e60fdcba2ce88da9093546", "seed_lines': '167'",
            "md5_api", "api_unit", "desktop_n", "deskcheck", "aik-sudo.sh"):
    print(key, s.count(key))
