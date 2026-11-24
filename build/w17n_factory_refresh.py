#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W17N: rootfs 刷新（现役打版脚本；sudo 于 L1）。

版本号与发布说明是单点：build/VERSION、build/RELEASE-NOTES.txt。
旧版本串从出厂树 motd 现读（重跑幂等）。

本版收编清单（HEAD=c97bc3f+，P-2 全量随车）：
  P-2 Phase A: aikctl user 族（add/del/list/passwd+from-gate+回滚器）+
        aik-console v9 降权链；v10（P-60）= setpriv 前 root 预建
        per-user 回退工作区 /var/ai/work/<name>
  P-2 Phase A/C: occ 重编——gate 多条目双框+/su=root 门+models.d 三层
        读取链+exit-marker per-uid+sandbox deny /home+回退 per-user
  P-2 Phase B: aikctl policy/session/quota/audit 四件+policy.conf
        [user:名] 注释示例段（factory 树）
  P-2 Phase C + D-3①: SENSE 双面出厂 soft——aistreamd.conf
        SENSE_REDACT=soft（产生侧，435ad37）+出厂 model.toml [api]
        sense_redact="soft"（暴露侧，646fb31；w17n 从 aik-reset
        heredoc 单源抽取写 /root/.aikernel/model.toml——build-rootfs
        同款出厂链路复建，[ui] 单源纪律沿承）
  P-60 预建三目录: /etc/aikernel/models.d（系统层空目录）+
        /var/log/aik-console（0750）+/var/ai/work（0755）
  P-27: aik-pqdump 新入厂（/usr/local/bin）
内核沿用 #82（bzImage 7b35b41f…；softdog.ko 同树 9e50cb73…）。"""
import hashlib
import os
import re
import shutil
import subprocess

ROOT = "/home/jack66g/w7i-rootfs"
REPO = "/home/jack66g/aikernel-repo-alpha11"
CFG = "/home/jack66g/aikernel-repo-alpha11/build/w17j-grub-iso.cfg"
K2 = "/home/jack66g/linux-k2"
KREL = "6.18.39"
SOFTDOG_REL = "/lib/modules/%s/kernel/drivers/watchdog/softdog.ko" % KREL
BZ_MD5 = "7b35b41fb86f2c1c20e1fd57053e3d5e"
SOFTDOG_MD5 = "9e50cb73434ab8ba363127682646fa63"
NEW = open(REPO + "/build/VERSION", encoding="utf-8").read().strip()
RELEASE_NOTES = open(REPO + "/build/RELEASE-NOTES.txt",
                     encoding="utf-8").read().strip()
_motd = open(ROOT + "/etc/motd", encoding="utf-8").read()
_m = re.search(r"0\.1\.0-alpha\.[0-9]+(?:\.[0-9]+)*", _motd)
assert _m, "factory tree /etc/motd carries no version string"
OLD = _m.group(0)
assert re.fullmatch(r"0\.1\.0-alpha\.[0-9]+(?:\.[0-9]+)*", NEW), NEW
print("release: %s -> %s" % (OLD, NEW))
PROV_PUBKEY = "/home/jack66g/prov.pubkey"


def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def install_file(rel, src, mode):
    dst = ROOT + rel
    if os.path.lexists(dst):
        os.unlink(dst)
    shutil.copyfile(src, dst)
    os.chmod(dst, mode)
    os.chown(dst, 0, 0)
    print("install %s md5=%s" % (rel, md5(dst)))


def install_link(rel, target):
    dst = ROOT + rel
    if os.path.lexists(dst):
        os.unlink(dst)
    os.symlink(target, dst)
    os.lchown(dst, 0, 0)
    print("link %s -> %s" % (rel, target))


def ensure_dir(rel, mode):
    dst = ROOT + rel
    os.makedirs(dst, exist_ok=True)
    os.chmod(dst, mode)
    os.chown(dst, 0, 0)
    print("dir %s mode=%o" % (rel, mode))


F = REPO + "/factory"

# -1) 出厂树卫生前置门（ENG-01；与 build_iso 的 tar 卫生断言双保险）
_homes = sorted(set(os.listdir(ROOT + "/home")) - {"aiuser"})
assert not _homes, "factory tree has stray home dirs: %s" % _homes
for _rel in ("opt/w7s", "usr/local/bin/aik-console.pre-v3",
             "opt/aikdesktop/aik-desktop.service", "root/.occ",
             "root/.aikernel/history"):
    assert not os.path.lexists(ROOT + "/" + _rel), \
        "factory tree stray file: " + _rel
print("factory tree hygiene: ok")

# 0) P-33 前置门：#82 树一致性
bz = K2 + "/arch/x86/boot/bzImage"
assert md5(bz) == BZ_MD5, "linux-k2 bzImage not #82 final (7b35b41f)"
ko = K2 + "/drivers/watchdog/softdog.ko"
assert md5(ko) == SOFTDOG_MD5, "k2 softdog.ko drifted (expect 9e50cb73)"
print("P33 gate: bzImage+softdog same-tree #82 verified")

# 1) 二进制重装面（P-32：conf 键与二进制同刷）
install_file("/usr/local/bin/occ", REPO + "/agent/ai/occ/occ", 0o755)
install_file("/usr/local/sbin/aistreamd",
             REPO + "/agent/ai/aistreamd/aistreamd", 0o755)
install_file("/usr/local/bin/aik-console",
             F + "/usr/local/bin/aik-console", 0o755)
install_file("/usr/local/bin/aikctl", REPO + "/agent/ai/aikctl/aikctl", 0o755)
install_file("/usr/local/bin/aik-pqdump",
             REPO + "/agent/ai/aistreamd/aik-pqdump", 0o755)
install_file("/usr/local/sbin/aik-reset", F + "/usr/local/sbin/aik-reset", 0o755)

# 1b) P-2 Phase C：conf 双面（产生侧 soft）
install_file("/etc/aikernel/aistreamd.conf",
             F + "/etc/aikernel/aistreamd.conf", 0o644)
# P-2 Phase B：policy.conf（[user:名] 注释示例段随厂）
install_file("/etc/aikernel/policy.conf",
             F + "/etc/aikernel/policy.conf", 0o644)

# 1c) P-60 预建三目录（B 棒 build-rootfs 注记落位）
ensure_dir("/etc/aikernel/models.d", 0o755)
ensure_dir("/var/log/aik-console", 0o750)
ensure_dir("/var/ai/work", 0o755)
# P-60 定谳补件：系统层共享槽——fresh 用户三层链的可解析底座
# （全链空=load -1 硬拒契约；17.11 装机台架 admin 章咬出）
install_file("/etc/aikernel/models.d/cloud.toml",
             F + "/etc/aikernel/models.d/cloud.toml", 0o644)
# P-60：aik-gate 系统组（gate 文件 0640 组读面——非 root occ 须读
# gate 渲染 LOGIN；gid 942 定值=种子/断言用）
r = subprocess.run(["chroot", ROOT, "getent", "group", "aik-gate"],
                   capture_output=True, text=True)
if r.returncode != 0:
    r2 = subprocess.run(["chroot", ROOT, "groupadd", "-r", "-g", "942",
                         "aik-gate"], capture_output=True, text=True)
    assert r2.returncode == 0, "groupadd aik-gate: " + r2.stderr
    print("group aik-gate created (gid 942)")
else:
    print("group aik-gate present:", r.stdout.strip())

# 1d) P-2 Phase C：出厂 model.toml（暴露侧 soft）——单源= aik-reset
#     write_factory_model_toml heredoc（toml_replace_section 为逐段手术，
#     首启密钥向导写 [models.*] 不抹 [api]；occ 段分发只认 models.*/
#     provider.*，未知段忽略）
AIK_RESET = F + "/usr/local/sbin/aik-reset"
rs = open(AIK_RESET, encoding="utf-8").read()
m = re.search(r"cat > \"\$MODEL_TOML\.tmp\.\$\$\" <<'EOF'\n(.*?)\nEOF\n",
              rs, re.S)
assert m, "aik-reset heredoc not found"
tmpl = m.group(1) + "\n"
assert '[api]' in tmpl and 'sense_redact = "soft"' in tmpl, \
    "template lacks [api] soft (D-3①)"
assert '[models.cloud]' in tmpl and 'base_url = "http://127.0.0.1:11434/v1"' \
    in tmpl, "template lacks [models.cloud] skeleton (occ 零槽死循环修复)"
assert '[ui]' in tmpl and '[default]' in tmpl, "template malformed"
dst = ROOT + "/root/.aikernel"
os.makedirs(dst, exist_ok=True)
os.chown(dst, 0, 0)
os.chmod(dst, 0o700)
with open(dst + "/model.toml", "w", encoding="utf-8") as fh:
    fh.write(tmpl)
os.chmod(dst + "/model.toml", 0o600)
os.chown(dst + "/model.toml", 0, 0)
print("model.toml from aik-reset heredoc: %d bytes md5=%s"
      % (len(tmpl), hashlib.md5(tmpl.encode()).hexdigest()))

# 2) 17.7 既有件在位断言（本波不动）
for rel in ("/usr/local/bin/aik-compat", "/usr/local/bin/aik-gcm"):
    assert os.path.isfile(ROOT + rel), "missing legacy file: " + rel

# 3) conf/出厂面收编（既有波全量幂等重装）
install_file("/usr/local/sbin/aik-upgrade",
             F + "/usr/local/sbin/aik-upgrade", 0o755)
install_file("/etc/fonts/fonts.conf", F + "/etc/fonts/fonts.conf", 0o644)
install_file("/etc/sysctl.d/50-aik-console-quiet.conf",
             F + "/etc/sysctl.d/50-aik-console-quiet.conf", 0o644)

# 3b) 17.9 收编面刷件（幂等重装）
install_file("/usr/local/sbin/aipd", REPO + "/agent/ai/aipd/aipd", 0o755)
# aik-sandbox：取「出厂同源锚」（未跟踪件；make 目标输出在
# agent/ai/aik-sandbox，与此处取用位不是同一份——ENG-14 待处理）
SBX_ANCHOR = REPO + "/agent/ai/sandbox/aik-sandbox"
assert os.path.isfile(SBX_ANCHOR), \
    "aik-sandbox factory anchor missing: " + SBX_ANCHOR
install_file("/usr/local/bin/aik-sandbox", SBX_ANCHOR, 0o755)
install_file("/usr/local/bin/aik-ime", F + "/usr/local/bin/aik-ime", 0o755)
install_file("/root/.fbtermrc", F + "/root/.fbtermrc", 0o644)


def _copytree(src, dst):
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True)
    for root, dirs, files in os.walk(dst):
        os.chown(root, 0, 0)
        for fn in files:
            os.chown(os.path.join(root, fn), 0, 0)


_copytree(F + "/usr/share/rime-data", ROOT + "/usr/share/rime-data")
_copytree(F + "/usr/local/lib/aik-ime", ROOT + "/usr/local/lib/aik-ime")
n_rime = sum(len(fs) for _, _, fs in os.walk(ROOT + "/usr/share/rime-data"))
n_so = sum(len(fs) for _, _, fs in os.walk(ROOT + "/usr/local/lib/aik-ime"))
print("p55 staged: rime-data %d files, bundled .so %d" % (n_rime, n_so))

install_file("/etc/ld.so.conf.d/aik-ime.conf",
             F + "/etc/ld.so.conf.d/aik-ime.conf", 0o644)
r = subprocess.run(["chroot", ROOT, "ldconfig"], capture_output=True)
assert r.returncode == 0, "ldconfig failed"
r = subprocess.run(["chroot", ROOT, "ldconfig", "-p"],
                   capture_output=True, text=True)
n_hit = r.stdout.count("/usr/local/lib/aik-ime/")
assert n_hit >= 9, "ld cache lacks bundled so (%d)" % n_hit
print("ld.so.conf.aik-ime: cache hits=%d" % n_hit)

# 4) P-33 softdog 同树进厂
install_file(SOFTDOG_REL, ko, 0o644)

# 5) P-32 断言：conf/二进制一致（chroot 走真解析器，正反双向）
r = subprocess.run(
    ["chroot", ROOT, "/usr/local/sbin/aistreamd",
     "--check-conf", "--conf", "/etc/aikernel/aistreamd.conf"],
    capture_output=True, text=True)
assert r.returncode == 0, \
    "P-32: aistreamd conf/binary mismatch: %s%s" % (r.stdout, r.stderr)
pois = ROOT + "/tmp/w17n-pois.conf"
with open(pois, "w", encoding="utf-8") as fh:
    fh.write("SME_URL=http://127.0.0.1:8000\nBOGUS_KEY_W17N=1\n")
r = subprocess.run(
    ["chroot", ROOT, "/usr/local/sbin/aistreamd",
     "--check-conf", "--conf", "/tmp/w17n-pois.conf"],
    capture_output=True, text=True)
os.unlink(pois)
assert r.returncode != 0, "P-32: --check-conf lost teeth (bogus key passed)"
print("P32 check-conf two-way: good conf=rc0 / poisoned conf=rc!=0")

# 6) P-33 断言：模块配套
vr = subprocess.run(["modinfo", "-F", "vermagic", ROOT + SOFTDOG_REL],
                    capture_output=True, text=True)
assert vr.stdout.strip().startswith(KREL), \
    "softdog vermagic mismatch: " + vr.stdout
assert md5(ROOT + SOFTDOG_REL) == SOFTDOG_MD5, "installed softdog drifted"
dep = open(ROOT + "/lib/modules/%s/modules.dep" % KREL,
           encoding="utf-8").read()
assert "softdog.ko:" in dep, "modules.dep lacks softdog"
mld = ROOT + "/etc/modules-load.d"
mls = ""
for fn in sorted(os.listdir(mld)):
    p = os.path.join(mld, fn)
    if os.path.isfile(p):
        mls += open(p, encoding="utf-8").read()
assert "softdog" in mls, "modules-load.d lacks softdog"
print("P33 softdog: md5=%s vermagic=[%s]"
      % (SOFTDOG_MD5, vr.stdout.strip()))

# 7) 既有面字符串锚（17.8 起全量沿承）
occbin = open(ROOT + "/usr/local/bin/occ", "rb").read()
assert b"config_write_network" in occbin, "occ lacks netcfg tool"
assert b"OCC_NETCFG_TOOLS" in occbin
assert b"unstuck" in occbin, "occ lacks P-48 unstuck"
assert b"aik-occ-exit" in occbin, "occ lacks P-47 exit marker"
console = open(ROOT + "/usr/local/bin/aik-console",
               encoding="utf-8").read()
assert "occ-logout-marker" in console, "aik-console not v8"
assert "OCC_NETCFG_TOOLS=1" in console, "console missing netcfg flag"
upg = open(ROOT + "/usr/local/sbin/aik-upgrade",
           encoding="utf-8").read()
assert "userland" in upg, "aik-upgrade lacks W-7 userland channel"
fonts = open(ROOT + "/etc/fonts/fonts.conf", encoding="utf-8").read()
assert "Noto Sans Mono CJK SC" in fonts, "P-34 CJK prefer missing"
quiet = open(ROOT + "/etc/sysctl.d/50-aik-console-quiet.conf",
             encoding="utf-8").read()
assert "kernel.printk" in quiet, "P-38 printk quiet missing"
ret = open(ROOT + "/etc/aikernel/aistreamd.conf",
           encoding="utf-8").read()
assert "PARQUET_RETENTION_DAYS=7" in ret

# 7b) 17.9 新面锚（沿承）
aipdbin = open(ROOT + "/usr/local/sbin/aipd", "rb").read()
assert b"producer" in aipdbin, "aipd lacks P-56 producer"
assert b"aip_shadow_colname" in aipdbin, "aipd lacks P-56 API"
assert b"OCC_LANG" in occbin, "occ lacks O-20 lang"
assert b"tui_lang" in occbin, "occ lacks O-20 table"
sbx = open(ROOT + "/usr/local/bin/aik-sandbox", "rb").read()
assert b"which.debianutils" in sbx, "aik-sandbox lacks O-8 fixups"
assert b"mawk" in sbx, "aik-sandbox lacks O-8 awk"
imebin = open(ROOT + "/usr/local/bin/aik-ime", "rb").read()
assert b"/usr/local/lib/aik-ime" in imebin, "aik-ime lacks RPATH"
assert b"FBTERM_IM_SOCKET" in imebin, "aik-ime not fbterm IM protocol"
imerc = open(ROOT + "/root/.fbtermrc", encoding="utf-8").read()
assert "input-method=aik-ime" in imerc, "fbtermrc lacks IME hook"
assert os.path.isfile(ROOT + "/usr/share/rime-data/essay.txt"), "essay"
assert os.path.isfile(
    ROOT + "/usr/share/rime-data/build/luna_pinyin.prism.bin"), "prism"
assert os.path.isfile(
    ROOT + "/usr/share/rime-data/build/luna_pinyin.table.bin"), "table"
assert os.path.islink(
    ROOT + "/usr/local/lib/aik-ime/libleveldb.so.1d"), "so symlink"
print("17.9 anchors ok")

# 7c) 17.11 新面锚（P-2 全量+D-3①+P-60）
# aik-console v10：per-user 工作区预建 + v9 供给链
assert '/var/ai/work/$t_user' in console, "aik-console not v10 (workdir)"
assert '--from-gate' in console, "aik-console lacks v9 admin 归位"
# aikctl：user/policy/session/quota/audit 五族
ctl = open(ROOT + "/usr/local/bin/aikctl", encoding="utf-8").read()
for key in ("user add", "policy set", "session list", "quota get",
            "audit tail", "--from-gate", "[user:"):
    assert key in ctl, "aikctl lacks P-2 face: " + key
# occ：models.d 三层链+/su=root 门+gate 双框+per-user 回退常量
assert b"/etc/aikernel/models.d" in occbin, "occ lacks models.d chain"
assert b"/var/ai/work" in occbin, "occ lacks sandbox workdir const"
assert "本机未开 root 门".encode() in occbin, "occ lacks /su=root door"
assert "用户名或密码不正确".encode() in occbin, "occ lacks gate ghost 文案"
assert b"%63[^:]:%*[^:]:%u:%u" in occbin, "occ lacks per-user policy reader"
# aik-pqdump
pq = open(ROOT + "/usr/local/bin/aik-pqdump", "rb").read()
assert b"thrift" in pq.lower() or b"parquet" in pq.lower(), "pqdump bogus"
# SENSE 双面出厂
assert "SENSE_REDACT=soft" in ret, "aistreamd.conf not soft (D-3①)"
mtoml = open(ROOT + "/root/.aikernel/model.toml", encoding="utf-8").read()
assert '[api]' in mtoml and 'sense_redact = "soft"' in mtoml, \
    "model.toml lacks [api] soft (D-3① 暴露侧)"
polc = open(ROOT + "/etc/aikernel/policy.conf", encoding="utf-8").read()
assert "[user:" in polc, "policy.conf lacks [user:] 示例段"
assert os.path.isdir(ROOT + "/etc/aikernel/models.d")
r = subprocess.run(["chroot", ROOT, "getent", "group", "aik-gate"],
                   capture_output=True, text=True)
assert r.returncode == 0 and ":942:" in r.stdout, "aik-gate group missing"
mdc = open(ROOT + "/etc/aikernel/models.d/cloud.toml",
           encoding="utf-8").read()
assert "[models.cloud]" in mdc and "base_url" in mdc, \
    "models.d cloud.toml malformed"
assert os.path.isdir(ROOT + "/var/ai/work")
assert os.path.isdir(ROOT + "/var/log/aik-console")
# 7d) 17.11.1 新面锚（P-60 收口：gate 读失败根因 / aik-console v11+v12 /
#     occ W2 裁决审计）
assert 'FB_PRE="HOME=/root USER=root "' in console, \
    "aik-console not v11 (fbterm reads system config)"
assert "gate_perm_fix" in console, "aik-console not v12 (gate perm fix)"
assert "登录凭据不可读".encode() in occbin, \
    "occ lacks gate unreadable-credentials screen"
assert b"allow-w2" in occbin and b"tier-deny" in occbin, \
    "occ lacks W2 decision audit"
print("17.11.1 anchors: gate DENIED screen / aik-console v11+v12 / W2 audit")
print("17.11 anchors: P-2 全量（console v9/v10+aikctl 五族+occ 四面）"
      "+ SENSE 双面 soft + 预建三目录")

# 8) 沿用面在位断言（只验不装）
hard = open(ROOT + "/etc/ssh/sshd_config.d/50-aik-hardening.conf",
            encoding="utf-8").read()
assert "PermitRootLogin prohibit-password" in hard
assert "PasswordAuthentication no" in hard, "hardening keys missing"
trim = open(ROOT + "/usr/local/sbin/aik-log-trim",
            encoding="utf-8").read()
assert "KEEP_DAYS=14" in trim and "MAX_BYTES" in trim
health = open(ROOT + "/usr/local/sbin/aikernel-health.sh",
              encoding="utf-8").read()
assert "HEAL_GRACE_SEC" in health and "WEBHOOK_URL" in health
cron = open(ROOT + "/etc/systemd/system/aik-cron.service",
            encoding="utf-8").read()
assert "crond -f -S -l 8" in cron, "crond not foreground"
assert os.access(ROOT + "/usr/local/bin/busybox", os.X_OK)
assert os.path.islink(ROOT + "/usr/local/bin/crontab")
r = subprocess.run([ROOT + "/usr/local/bin/busybox", "--list"],
                   capture_output=True, text=True)
assert "crond" in r.stdout and "crontab" in r.stdout \
    and "fdisk" in r.stdout, "busybox applets missing"
assert not os.path.exists(ROOT + "/usr/share/man"), \
    "C-P2c: man pages should be deleted"
uup = ROOT + "/etc/apt/apt.conf.d/51-aik-upgrade-policy"
assert 'Unattended-Upgrade "0"' in open(uup, encoding="utf-8").read()

# 9) PROV_PUBKEY（可选——演示机首启 ssh 接管通道）
if os.path.isfile(PROV_PUBKEY):
    key = open(PROV_PUBKEY, encoding="utf-8").read().strip()
    assert key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")), \
        "prov.pubkey not a public key line"
    assert "\n" not in key, "prov.pubkey must be a single line"
    d = ROOT + "/root/.ssh"
    os.makedirs(d, exist_ok=True)
    with open(d + "/authorized_keys", "w", encoding="utf-8") as fh:
        fh.write(key + "\n")
    os.chmod(d, 0o700)
    os.chmod(d + "/authorized_keys", 0o600)
    os.chown(d, 0, 0)
    os.chown(d + "/authorized_keys", 0, 0)
    print("prov pubkey injected (md5=%s...)"
          % md5(d + "/authorized_keys")[:8])
else:
    print("NOTE: no prov.pubkey — ssh 首启接管需装后 nbd 预种")

# 10) 版本串 OLD → NEW
for rel in ("/etc/motd", "/root/README.md"):
    p = ROOT + rel
    s = open(p, encoding="utf-8").read()
    if OLD in s:
        open(p, "w", encoding="utf-8").write(s.replace(OLD, NEW))
        print("bump", rel)
s = open(CFG, encoding="utf-8").read()
if OLD in s:
    open(CFG, "w", encoding="utf-8").write(s.replace(OLD, NEW))
    print("grub-iso.cfg bumped")

# 11) ISO-SNAPSHOT-W82.txt 重写
head = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"],
                      capture_output=True, text=True).stdout.strip()
bzsize = os.path.getsize(bz)
# 快照数字实测（不写死）：工具数/通道数取出厂树现装的 tools.json，种子
# 行数取出厂树现装的种子文件；读不到就写 unknown，不编造。
import datetime
import json
today = datetime.date.today().isoformat()
try:
    _tj = json.load(open(ROOT + "/etc/aikernel/tools.json",
                         encoding="utf-8"))
    _tools = str(_tj.get("tool_count", "unknown"))
    _chans = str(len(_tj.get("channel_counts", {})) or "unknown")
except (OSError, ValueError) as _e:
    _tools = _chans = "unknown"
    print("WARN: tools.json not measurable:", _e)
try:
    _seed = str(sum(1 for _ in open(
        ROOT + "/usr/local/share/aikernel/sme-seed.jsonl",
        encoding="utf-8")))
except OSError as _e:
    _seed = "unknown"
    print("WARN: seed not measurable:", _e)
# aikd（记忆服务）不由本脚本重装：如实记它的出处，免得「userland=main@…」
# 被读成「整棵出厂树都是这次编的」（ENG-14）。
_aikd = ROOT + "/usr/local/sbin/aikd"
_aikd_md5 = md5(_aikd) if os.path.isfile(_aikd) else "absent"
snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-W82.txt"
with open(snap, "w", encoding="utf-8") as fh:
    fh.write(
        "version=%s-w82-%s\n"
        "kernel=6.18.39 #82 %s (%d bytes)\n"
        "softdog.ko=%s (same-tree linux-k2 #82; vermagic \"%s\")\n"
        "userland=main@%s\n"
        "tools=%s channels=%s seed=%s\n"
        "built=%s on L1\n"
        "aikd_md5=%s (memory service NOT rebuilt by this refresh; "
        "factory-tree file carried over)\n"
        "correction=2026-11-18: prior entry erroneously said #62 "
        "a667e9160b23036a859ebc8a70aae62b (provenance drift); the "
        "factory kernel is and was #82 = bzImage md5 above\n"
        % (NEW, today.replace("-", ""), BZ_MD5, bzsize, SOFTDOG_MD5,
           vr.stdout.strip(), head, _tools, _chans, _seed, today,
           _aikd_md5))
print("W82 snapshot rewritten")

# 12) K17 快照追加本版条目（发布说明单点=build/RELEASE-NOTES.txt；
#     同版本重跑不重复追加）
snap = ROOT + "/etc/aikernel/ISO-SNAPSHOT-K17.txt"
_k17 = open(snap, encoding="utf-8").read()
_entry = "%s version=%s\n" % (RELEASE_NOTES, NEW)
if ("version=%s\n" % NEW) not in _k17:
    with open(snap, "a", encoding="utf-8") as fh:
        fh.write(_entry)
    print("K17 snapshot: appended", NEW)
else:
    print("K17 snapshot: already has", NEW)
_LEGACY_17_11 = (
        "17.11: P-2 multiuser full suite (aikctl user/policy/session/"
        "quota/audit + aik-console v9 privdrop + v10 per-user workdir "
        "pre-seed + occ gate multi-entry dual-pane + /su=root door + "
        "models.d 3-layer + sandbox deny /home + per-user fallback + "
        "policy.conf [user:] sample) + SENSE factory soft both sides "
        "(aistreamd.conf producing + model.toml [api] exposure, single "
        "source = aik-reset heredoc) + aik-pqdump + factory dirs "
        "(models.d / var/log/aik-console / var/ai/work). kernel #82 "
        "unchanged. version=0.1.0-alpha.17.11\n")
# 17.11 的旧条目是 17.11 那次打版写下的（旧脚本每跑一次追加一次）；
# 这里只断言它在账上——出厂树若从没刷过 17.11 就不该拿本脚本刷补丁版。
assert _LEGACY_17_11 in _k17, "unexpected K17 state (no 17.11 entry)"
print("W17N_OK")
