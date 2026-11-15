#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_gcm.py - aik-gcm 单测（L1 棒③，DATA-L1-DESIGN §3）

覆盖面：
  1) NIST 向量：`aik-gcm selftest` 三组公开 AES-256-GCM 向量全过
  2) 往返：多尺寸（空/1B/块界 15/16/17/跨 64KiB/1MiB 随机）逐字节
  3) 包格式字节图：magic AIKCORP1|ver u16 LE|key_ref 32B NUL 填充|
     nonce 12B|tag 16B|ciphertext；总长=70+明文长
  4) 篡改必败：tag/密文/包头（magic/version）任一篡改=rc4/rc3 且
     stdout 零字节（绝不输出半明文）
  5) key 契约：31B/0644 权限/错 key；keygen 0600+拒绝覆盖
  6) 诊断路径：--nonce 定长复现（同 nonce 同包）；非法 nonce=rc1

前置：agent/ai 下 `make aik-gcm` 已构建（缺席=FAIL+指路，不静默跳过）。
退出码 0=全过，1=有 FAIL。
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.dirname(HERE)                       # agent/ai
GCM = os.path.join(AGENT, 'aik-gcm')

RESULTS = []


def check(cond, name, detail=''):
    RESULTS.append((bool(cond), name, detail))
    print(('PASS: ' if cond else 'FAIL: ') + name +
          (('  [' + str(detail) + ']') if (not cond and detail) else ''))


def run(args, data=b''):
    p = subprocess.run([GCM] + args, input=data,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr


def main():
    if not os.path.isfile(GCM):
        check(False, 'aik-gcm-built',
              '%s 缺席——先在 agent/ai 下 make aik-gcm' % GCM)
        return 1
    tmp = tempfile.mkdtemp(prefix='aikgcm-test-')
    key = os.path.join(tmp, 'corpus.key')

    # ---- 1) NIST 向量 ----
    rc, out, err = run(['selftest'])
    txt = out.decode('utf-8', 'replace')
    check(rc == 0, 'nist-selftest-rc0', 'rc=%d err=%s' % (rc, err[:80]))
    check('GCM_SELFTEST cases=3 ok=3' in txt and 'FAIL' not in txt,
          'nist-3-vectors-pass', txt.strip().replace('\n', ' | '))

    # ---- 2) keygen ----
    rc, out, err = run(['keygen', '--key', key])
    check(rc == 0, 'keygen-rc0', err[:80])
    check(os.path.isfile(key) and os.path.getsize(key) == 32,
          'keygen-32B', str(os.path.getsize(key) if
                            os.path.isfile(key) else -1))
    check(oct(os.stat(key).st_mode & 0o777) == '0o600', 'keygen-0600',
          oct(os.stat(key).st_mode & 0o777))
    rc, out, err = run(['keygen', '--key', key])
    check(rc == 2, 'keygen-refuse-overwrite', 'rc=%d' % rc)

    # ---- 3) 往返多尺寸 ----
    import hashlib
    sizes = [0, 1, 15, 16, 17, 64, 100, 4095, 4096, 65535, 65536, 65537,
             1 << 20]
    for n in sizes:
        data = (hashlib.sha256(bytes([n % 256])).digest()
                * (n // 32 + 1))[:n] if n else b''
        rc, pkg, err = run(['enc', '--key', key], data)
        ok = rc == 0 and len(pkg) == 70 + n
        if ok:
            rc2, back, err2 = run(['dec', '--key', key], pkg)
            ok = rc2 == 0 and back == data
        check(ok, 'roundtrip-%dB' % n,
              'enc rc=%d pkglen=%d' % (rc, len(pkg)))
    rc, pkg, _ = run(['enc', '--key', key], b'test')
    check(len(pkg) == 74, 'empty-plain-overhead-70B', str(len(pkg)))

    # ---- 4) 包格式字节图 ----
    hdr = pkg[:70]
    check(hdr[:8] == b'AIKCORP1', 'pkg-magic', repr(hdr[:8]))
    check(hdr[8:10] == b'\x01\x00', 'pkg-ver-1-le', repr(hdr[8:10]))
    kr = hdr[10:42]
    check(kr.startswith(b'keyfile:corpus.key') and kr[18:] == b'\x00' * 14,
          'pkg-keyref-32B-nulpad', repr(kr))
    check(hdr[42:54] != b'\x00' * 12, 'pkg-nonce-12B-nonzero')
    check(hdr[54:70] != b'\x00' * 16, 'pkg-tag-16B-nonzero')
    rc, out, err = run(['enc', '--key', key, '--key-ref',
                        'keyring:future-ref'], b'x')
    check(rc == 0 and out[10:42].startswith(b'keyring:future-ref'),
          'pkg-keyref-override')

    # ---- 5) 篡改必败 ----
    bad = pkg[:-1] + bytes([pkg[-1] ^ 0x01])          # tag 翻 1 位
    rc, out, err = run(['dec', '--key', key], bad)
    check(rc == 4 and out == b'', 'tamper-tag-rc4-nooutput',
          'rc=%d outlen=%d' % (rc, len(out)))
    check('篡改' in err.decode('utf-8', 'replace'),
          'tamper-tag-human-message', err[:60])
    bad = pkg[:70] + bytes([pkg[70] ^ 0x01]) + pkg[71:]   # 密文翻 1 位
    rc, out, err = run(['dec', '--key', key], bad)
    check(rc == 4 and out == b'', 'tamper-ct-rc4-nooutput', 'rc=%d' % rc)
    bad = b'X' + pkg[1:]                               # magic 破坏
    rc, out, err = run(['dec', '--key', key], bad)
    check(rc == 3 and out == b'', 'tamper-magic-rc3', 'rc=%d' % rc)
    bad = pkg[:8] + b'\x09\x00' + pkg[10:]             # 版本不识别
    rc, out, err = run(['dec', '--key', key], bad)
    check(rc == 3 and out == b'', 'tamper-version-rc3', 'rc=%d' % rc)
    rc, out, err = run(['dec', '--key', key], pkg[:69])
    check(rc == 3 and out == b'', 'truncated-rc3', 'rc=%d' % rc)
    # 包头篡改（nonce 位）也必败：AAD=tag 前包头
    bad = pkg[:43] + bytes([pkg[43] ^ 0x01]) + pkg[44:]
    rc, out, err = run(['dec', '--key', key], bad)
    check(rc == 4 and out == b'', 'tamper-nonce-aad-rc4', 'rc=%d' % rc)

    # ---- 6) key 契约 ----
    k31 = os.path.join(tmp, 'k31')
    with open(k31, 'wb') as f:
        f.write(b'x' * 31)
    os.chmod(k31, 0o600)
    rc, out, err = run(['enc', '--key', k31], b'x')
    check(rc == 2, 'key-31B-rc2', 'rc=%d' % rc)
    rc, out, err = run(['dec', '--key', k31], pkg)
    check(rc == 2, 'key-31B-dec-rc2', 'rc=%d' % rc)
    kopen = os.path.join(tmp, 'kopen')
    with open(kopen, 'wb') as f:
        f.write(b'x' * 32)
    os.chmod(kopen, 0o644)
    rc, out, err = run(['enc', '--key', kopen], b'x')
    check(rc == 2 and '0600' in err.decode('utf-8', 'replace'),
          'key-0644-rc2-chmod-hint', 'rc=%d' % rc)
    k2 = os.path.join(tmp, 'k2.key')
    run(['keygen', '--key', k2])
    rc, out, err = run(['dec', '--key', k2], pkg)
    check(rc == 4 and out == b'', 'wrong-key-rc4-nooutput', 'rc=%d' % rc)

    # ---- 7) 诊断 nonce 路径 ----
    nonce = '00' * 12
    rc1, p1, _ = run(['enc', '--key', key, '--nonce', nonce], b'vec')
    rc2, p2, _ = run(['enc', '--key', key, '--nonce', nonce], b'vec')
    check(rc1 == 0 and p1 == p2, 'nonce-deterministic-repro')
    rc, out, err = run(['dec', '--key', key], p1)
    check(rc == 0 and out == b'vec', 'nonce-pkg-roundtrip')
    rc, out, err = run(['enc', '--key', key, '--nonce', 'zz'], b'x')
    check(rc == 1, 'nonce-bad-hex-rc1', 'rc=%d' % rc)

    fail = sum(1 for ok, _, _ in RESULTS if not ok)
    total = len(RESULTS)
    print('\nTEST_GCM cases=%d ok=%d fail=%d' % (total, total - fail, fail))
    return 1 if fail else 0


if __name__ == '__main__':
    sys.exit(main())
