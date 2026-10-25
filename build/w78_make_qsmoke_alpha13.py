#!/usr/bin/env python3
"""W78: derive qsmoke-alpha13.py from the alpha.12 driver (read-only source).

Transformations (all asserted so a silent miss fails loudly):
  - md5 whitelist: shell/ai 487b21b6, tools f165a081 (x2), openai ee27b8c5,
    tools-sandbox 10c49596, seed 3f4cada5, catalog 5bee8309, kernel/vmlinuz
    026e33b7 (x2); sandbox/upgrade/api/desktop/model-catalog md5s unchanged
  - kernel build id: #59 -> #60 (6x), dict key k59 -> k60
  - counts: 156 -> 182 tools, 173 -> 199 seed lines
  - version strings alpha.12.0 -> alpha.13.0, dirs alpha12-qemu -> alpha13-qemu,
    markers A12 -> A13, tmp names a12* -> a13*
  - NEW assertions:
      contentcheck: /sys/kernel/security/lsm word-contains "ai" (securityfs
        mounted in initramfs; contentcheck cmdline now carries lsm=ai),
        /proc/pressure/cpu exists, ss -tin state established reports rtt
        over a live loopback pair (INET_DIAG), aik-tls-gateway.service
        present and NOT enabled, tools.json has no "crontab" entry,
        /opt/w7s/tools.json == /etc/aikernel/tools.json (md5)
      diskboot: dmesg "AIKernel: AI LSM" registered line (grub lsm=ai)
"""
SRC = '/home/jack66g/aikernel-longterm/evidence/w77f/qsmoke-alpha12.py'
DST = '/home/jack66g/aikernel-longterm/evidence/w78/release/qsmoke-alpha13.py'

s = open(SRC, encoding='utf-8').read()

# --- version strings, paths, markers (BEFORE md5 swap so new hex is safe) --
assert s.count('alpha.12.0') >= 4
s = s.replace('alpha.12.0', 'alpha.13.0')
assert s.count('alpha12') >= 3
s = s.replace('alpha12', 'alpha13')
assert s.count('A12') >= 10
s = s.replace('A12', 'A13')
assert s.count('a12') == 8, s.count('a12')  # /tmp/a12{a,e,api} x2 each + a12check.py x2
s = s.replace('a12', 'a13')

# --- kernel build id #59 -> #60 ------------------------------------------
assert s.count('#59') == 7, s.count('#59')
s = s.replace('#59', '#60')
assert s.count("'k59'") == 1
s = s.replace("'k59'", "'k60'")

# --- counts ---------------------------------------------------------------
assert s.count("'156'") == 2
s = s.replace("'156'", "'182'")
assert s.count("'173'") == 2
s = s.replace("'173'", "'199'")
assert s.count('156 工具(9 域)') == 1
s = s.replace('156 工具(9 域)', '182 工具(9 域)')
assert s.count('seed 173 行') == 1
s = s.replace('seed 173 行', 'seed 199 行')

# --- softdog.ko rebuilt against #60 (DEBUG_INFO/BTF on): 17376 -> 331728 ---
assert s.count("'17376'") == 1
s = s.replace("'17376'", "'331728'")

# --- md5 whitelist (computed on L1 2026-10-26 from agent tree/ISO) --------
for old, new, n in [
    ('784cc0f014409cfdd8186f95c557dcd0', '487b21b6f974ed78a20353449991b477', 2),
    ('eca2739901173bcf6505420bbf7d186d', 'f165a08119a4e1f27e57777cd80526e3', 2),
    ('d5fedb738f5e4e56290dcbe67b26f055', 'ee27b8c52342ce2b2bb7acc5496cbab0', 1),
    ('226233e4d143db8a513bd136a6caae46', '10c49596aa239a7c3ff985a63c51d4e2', 1),
    ('59e5ee4a87576320750cc05381e9871f', '3f4cada560e66d842a273ffd4d37eb48', 1),
    ('39be07cec5b3670591838e97a87563b6', '5bee830936c836fc1f4be10489474685', 1),
    ('a50cafa6285bbef0f0a2011923481d8f', '026e33b75af0661d5a8f9313414abe51', 2),
]:
    assert s.count(old) == n, (old, s.count(old))
    s = s.replace(old, new)

# --- contentcheck cmdline: carry lsm=ai (grub injects it on real boots) ---
old_append = 'rw init=/bin/sh loglevel=0 kunit.enable=0'
assert s.count(old_append) == 1
s = s.replace(old_append, 'rw init=/bin/sh loglevel=0 kunit.enable=0 lsm=ai')

# --- NEW: initramfs-side lsm/psi probes (contentcheck mount block) --------
anchor_mount = "        'mount -t sysfs sysfs /sys',\n"
assert s.count(anchor_mount) == 1
ins_mount = (anchor_mount +
             "        'mount -t securityfs securityfs /sys/kernel/security',\n"
             "        'grep -qw ai /sys/kernel/security/lsm; echo A13_LSM_AI=$?',\n"
             "        'test -f /proc/pressure/cpu; echo A13_PSI=$?',\n")
s = s.replace(anchor_mount, ins_mount)

# --- NEW: CHECK_PY gates (chroot python, disk content + kernel caps) ------
anchor_chk = "R['md5_model_catalog'] = md5(base + '/model-catalog.json')\n"
assert s.count(anchor_chk) == 1
ins_chk = anchor_chk + (
    "# W78 gates: INET_DIAG rtt over live loopback pair; mTLS gateway unit\n"
    "# shipped but disabled; no crontab tool; w7s feed tools.json in sync\n"
    "import glob as _glob\n"
    "import subprocess as _sp\n"
    "import socket as _sock\n"
    "try:\n"
    "    _sp.run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], capture_output=True)\n"
    "    _srv = _sock.socket()\n"
    "    _srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)\n"
    "    _srv.bind(('127.0.0.1', 0))\n"
    "    _srv.listen(1)\n"
    "    _cli = _sock.socket()\n"
    "    _cli.connect(('127.0.0.1', _srv.getsockname()[1]))\n"
    "    _acc, _ = _srv.accept()\n"
    "    _ssout = _sp.run(['/usr/bin/ss', '-tin', 'state', 'established'],\n"
    "                     capture_output=True, text=True).stdout\n"
    "    R['ss_established_rtt'] = int('rtt' in _ssout)\n"
    "except Exception as _e:\n"
    "    R['ss_established_rtt'] = 0\n"
    "    R['ss_err'] = str(_e)\n"
    "R['tls_gateway_unit'] = int(os.path.isfile('/etc/systemd/system/aik-tls-gateway.service'))\n"
    "R['tls_gateway_enabled'] = int(any(os.path.islink(p) for p in\n"
    "    _glob.glob('/etc/systemd/system/*.wants/aik-tls-gateway.service')))\n"
    "R['tools_no_crontab'] = int('crontab' not in names and\n"
    "    'crontab' not in open(base + '/tools.json', encoding='utf-8').read())\n"
    "R['w7s_tools_match'] = int(md5('/opt/w7s/tools.json') == md5('/etc/aikernel/tools.json'))\n")
s = s.replace(anchor_chk, ins_chk)

# --- NEW: EXPECT entries for the CHECK_PY gates ---------------------------
anchor_exp = "    'md5_model_catalog': '07fd7274227ff531a71f0bd4fb631de7',\n}"
assert s.count(anchor_exp) == 1
ins_exp = ("    'md5_model_catalog': '07fd7274227ff531a71f0bd4fb631de7',\n"
           "    'ss_established_rtt': '1',\n"
           "    'tls_gateway_unit': '1',\n"
           "    'tls_gateway_enabled': '0',\n"
           "    'tools_no_crontab': '1',\n"
           "    'w7s_tools_match': '1',\n"
           "}")
s = s.replace(anchor_exp, ins_exp)

# --- NEW: runtime softdog probe (disk modprobe on the running #60 kernel) -
# Rationale: diskboot console evidence for softdog load proved unreliable on
# this TCG serial (interleaved splicing); run1 lost even the service line.
# The probe below loads the SHIPPED module exactly as systemd-modules-load
# would and checks /proc/modules -- deterministic runtime equivalent.
anchor_mnt = "        'mount -t ext4 /dev/vda2 /mnt && echo A13MOUNTED',\n"
assert s.count(anchor_mnt) == 1
ins_mnt = (anchor_mnt +
           "        'chroot /mnt /usr/local/bin/modprobe -v softdog > /tmp/a13sd 2>&1; tail -3 /tmp/a13sd',\n"
           "        'grep -q softdog /proc/modules; echo A13_SOFTDOG_LOAD=$?',\n")
s = s.replace(anchor_mnt, ins_mnt)

# --- NEW: contentcheck verdict keys (lsm/psi/softdog from serial body) -----
anchor_cc = "    checks = {'mounted': b'A13MOUNTED' in body, 'check_output': got}\n"
assert s.count(anchor_cc) == 1
s = s.replace(anchor_cc, anchor_cc +
              "    checks['lsm_ai'] = b'A13_LSM_AI=0' in body\n"
              "    checks['psi_cpu'] = b'A13_PSI=0' in body\n"
              "    checks['softdog_modprobe'] = b'A13_SOFTDOG_LOAD=0' in body\n")

# --- NEW: diskboot dmesg gate (AI LSM registered via grub lsm=ai) ---------
anchor_db = "        'softdog_loaded': (b'softdog: initialized' in body) or (b'Software Watchdog' in body),\n"
assert s.count(anchor_db) == 1
s = s.replace(anchor_db, anchor_db +
              "        'ai_lsm': b'AIKernel: AI LSM' in body,\n")

# --- header note ----------------------------------------------------------
anchor_use = '# 用法: qsmoke-alpha13.py <install|diskboot|deskcheck|contentcheck>\n'
assert s.count(anchor_use) == 1
s = s.replace(anchor_use, anchor_use +
              '# W78：内核 #60（lsm=ai/PSI/INET_DIAG/BTF），182 工具/199 seed；\n'
              '# 新增断言：lsm 含 ai、/proc/pressure/cpu、ss established rtt、\n'
              '# aik-tls-gateway 出厂存在且未启用、tools.json 无 crontab、w7s tools.json 同步\n')

# --- serial driver: pump 6.7x faster in wait() (early-boot printk bursts
# overflow the qemu chardev socket buffer with 1s polls -> dropped dmesg
# lines, e.g. the AI LSM register line; 0.15s keeps the reader draining) ----
anchor_sleep = "                return False\n            time.sleep(1)\n"
assert s.count(anchor_sleep) == 1
s = s.replace(anchor_sleep,
              "                return False\n            time.sleep(0.15)\n")

# --- sanity ---------------------------------------------------------------
for gone in ('alpha.12', 'alpha12', 'A12', 'a12', '#59', "'k59'", '784cc0f0',
             'eca27399', 'd5fedb73', '226233e4', '59e5ee4a', '39be07ce',
             'a50cafa6', "'156'", "'173'", '156 工具', 'seed 173'):
    assert gone not in s, 'stale token: ' + gone
assert s.count('487b21b6f974ed78a20353449991b477') == 2
assert s.count('f165a08119a4e1f27e57777cd80526e3') == 2
assert s.count('026e33b75af0661d5a8f9313414abe51') == 2
assert 'AIKernel-0.1.0-alpha.13.0-x86_64.iso' in s
assert '/home/jack66g/alpha13-qemu' in s
assert 'a13check.py' in s
assert "b'AIKernel: AI LSM'" in s
assert 'A13_LSM_AI' in s and 'A13_PSI' in s and 'A13_SOFTDOG_LOAD' in s

open(DST, 'w', encoding='utf-8').write(s)
print('WROTE', DST, len(s), 'bytes')
