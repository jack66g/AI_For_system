#!/usr/bin/env python3
"""W77f: derive qsmoke-alpha12.py from the alpha.11 driver (read-only source).

Transformations (all asserted so a silent miss fails loudly):
  - md5 whitelist: shell/ai 784cc0f0, tools eca27399, openai d5fedb73,
    tools-sandbox 226233e4, seed 59e5ee4a, catalog 39be07ce
  - counts: 151 -> 156 tools, 167 -> 173 seed lines
  - version strings alpha.11.0 -> alpha.12.0, dirs alpha11-qemu -> alpha12-qemu
  - markers A11 -> A12, tmp names a10* -> a12*
  - NEW contentcheck assertions (installed disk == factory tar content):
      no /var/lib/ollama/models blobs, no /root/.ssh/authorized_keys,
      /usr/local/share/aikernel/model-catalog.json present with known md5
"""
SRC = '/home/jack66g/mbedtls-trim-evidence/logs/fix-alpha11/qsmoke-alpha11.py'
DST = '/home/jack66g/aikernel-longterm/evidence/w77f/qsmoke-alpha12.py'

s = open(SRC, encoding='utf-8').read()

# --- md5 whitelist -------------------------------------------------------
for old, new, n in [
    ('adb71f65c7e60fdcba2ce88da9093546', '784cc0f014409cfdd8186f95c557dcd0', 2),
    ('34d5af9ca7279e436690169c9af65873', 'eca2739901173bcf6505420bbf7d186d', 2),
    ('ab7656229c60fcebfab20b55952ae2f2', 'd5fedb738f5e4e56290dcbe67b26f055', 1),
    ('25f25c255bb75818f0db09fb80855a25', '226233e4d143db8a513bd136a6caae46', 1),
    ('f93767385a788bfff1a587f1eea2b321', '59e5ee4a87576320750cc05381e9871f', 1),
    ('ad3e216edad31fb16378329d41c3c777', '39be07cec5b3670591838e97a87563b6', 1),
]:
    assert s.count(old) == n, (old, s.count(old))
    s = s.replace(old, new)

# --- counts --------------------------------------------------------------
assert s.count("'151'") == 2
s = s.replace("'151'", "'156'")
assert s.count("'167'") == 2
s = s.replace("'167'", "'173'")
s = s.replace('151 工具/20 desktop/4 sandbox/30 memory',
              '156 工具(9 域)/20 desktop/4 sandbox/30 memory')
s = s.replace('seed 167 行 JSONL 全合法', 'seed 173 行 JSONL 全合法')

# --- version strings, paths, markers -------------------------------------
s = s.replace('alpha.11.0', 'alpha.12.0')
s = s.replace('alpha11', 'alpha12')
s = s.replace('A11', 'A12')
s = s.replace('a10', 'a12')

# --- NEW contentcheck assertions -----------------------------------------
anchor = "R['md5_vmlinuz'] = md5('/boot/vmlinuz-aikernel')"
assert s.count(anchor) == 1
ins = (
    "# W77f: factory-hygiene assertions (installed disk mirrors factory tar)\n"
    "R['ollama_blob_n'] = sum(len(fs) for _, _, fs in os.walk('/var/lib/ollama/models'))\n"
    "R['root_authkeys'] = int(os.path.exists('/root/.ssh/authorized_keys'))\n"
    "R['root_ssh_files'] = sum(len(fs) for _, _, fs in os.walk('/root/.ssh'))\n"
    "R['model_catalog'] = int(os.path.isfile(base + '/model-catalog.json'))\n"
    "R['md5_model_catalog'] = md5(base + '/model-catalog.json')\n"
)
s = s.replace(anchor, ins + anchor)

exp_old = "    'modules_dep_softdog': '1',\n}"
exp_new = ("    'modules_dep_softdog': '1',\n"
           "    'ollama_blob_n': '0',\n"
           "    'root_authkeys': '0',\n"
           "    'root_ssh_files': '0',\n"
           "    'model_catalog': '1',\n"
           "    'md5_model_catalog': '07fd7274227ff531a71f0bd4fb631de7',\n"
           "}")
assert s.count(exp_old) == 1
s = s.replace(exp_old, exp_new)

# --- sanity --------------------------------------------------------------
# NB: bare "151"/"167" appear inside legit md5 hex (aik-upgrade, desktop unit);
# only assert the semantic tokens are gone.
for gone in ('alpha.11', 'alpha11', 'A11', 'adb71f65', '34d5af9c', 'ab765622',
             '25f25c25', 'f9376738', "'151'", "'167'", '151 工具', 'seed 167',
             'a10check', '/tmp/a10'):
    assert gone not in s, 'stale token: ' + gone
assert s.count('784cc0f014409cfdd8186f95c557dcd0') == 2
assert 'AIKernel-0.1.0-alpha.12.0-x86_64.iso' in s
assert '/home/jack66g/alpha12-qemu' in s
assert 'a12check.py' in s

open(DST, 'w', encoding='utf-8').write(s)
print('WROTE', DST, len(s), 'bytes')
