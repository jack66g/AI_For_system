#!/bin/bash
# AIKernel L1 rootfs 构建脚本（在 VM 内以 root 运行）
# 产物: /home/jack66g/aikernel-root.raw (8G raw ext4, 无分区表, root=/dev/vda)
#
# W4A 启动参数建议（qemu 命令行，出厂 ISO 打包波参照）:
#   -m 4096   —— guest 内置 ollama+qwen2.5:1.5b（986MB 权重），
#                2G 实测 OOM 连环 panic（连 systemd PID1 都被杀）；
#                3G 临界；4G 稳定。另须挂载镜像内 /swapfile（2G，已含）。
#   加速提示: TCG 纯软件模拟下 1.5b prefill ~10min 级（大 prompt），
#             有 nested-KVM 的宿主请加 -enable-kvm。
set -euxo pipefail

PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKuhRsSrM2Cv6nS0crB+YooaZAdNBf6fQEDYnk4wTuHx aikernel-build'
IMG=/home/jack66g/aikernel-root.raw
MNT=/mnt/aikernel-root
SRC=/home/jack66g/linux-6.18.39
export DEBIAN_FRONTEND=noninteractive

echo "=== [0] host tools ==="
apt-get update -qq
apt-get install -y -qq debootstrap socat tmux >/dev/null
which debootstrap socat tmux qemu-img

echo "=== [1] image + ext4 (整盘无分区表) ==="
qemu-img create -f raw "$IMG" 8G
qemu-img info "$IMG" | head -3
mkfs.ext4 -F -L AIKERNEL -m 1 "$IMG"
tune2fs -l "$IMG" 2>/dev/null | grep -E "Filesystem volume name|Block count" || true

mkdir -p "$MNT"
mountpoint -q "$MNT" && umount "$MNT" || true
mount -o loop "$IMG" "$MNT"
df -h "$MNT" | tail -1

echo "=== [2] debootstrap jammy minbase ==="
if [ ! -x "$MNT/bin/bash" ]; then
    debootstrap --variant=minbase jammy "$MNT" http://archive.ubuntu.com/ubuntu
fi
ls "$MNT/bin/bash" "$MNT/usr/bin/apt-get"

echo "=== [3] chroot 准备 ==="
mount --bind /proc "$MNT/proc"
mount --bind /sys  "$MNT/sys"
mount --bind /dev  "$MNT/dev"
cp /etc/resolv.conf "$MNT/etc/resolv.conf"   # chroot 内 apt 用 VM 侧 DNS
printf '#!/bin/sh\nexit 101\n' > "$MNT/usr/sbin/policy-rc.d"   # chroot 内禁止起服务
chmod +x "$MNT/usr/sbin/policy-rc.d"

echo "=== [4] chroot 安装与配置 ==="
chroot "$MNT" /bin/bash -e -x <<'CHROOT'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv openssh-server python3 ca-certificates \
    iputils-ping iproute2 curl e2fsprogs
dpkg -l systemd openssh-server python3 | grep ^ii

# ---- root 免密: SSH 公钥 + 控制台 autologin（root 密码保持锁定）----
mkdir -p -m 700 /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKuhRsSrM2Cv6nS0crB+YooaZAdNBf6fQEDYnk4wTuHx aikernel-build' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
passwd -l root || true

# ---- sshd: 仅密钥登录 root ----
sed -i -E 's/^#?[[:space:]]*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i -E 's/^#?[[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config
mkdir -p /run/sshd

# ---- guest DNS: QEMU user-net ----
printf 'nameserver 10.0.2.3\n' > /etc/resolv.conf
cat /etc/resolv.conf

# ---- 主机名 ----
echo aikernel > /etc/hostname
cat > /etc/hosts <<'H'
127.0.0.1 localhost
127.0.1.1 aikernel
::1 localhost ip6-localhost ip6-loopback
H

# ---- fstab ----
printf '/dev/vda  /  ext4  defaults  1  1\n' > /etc/fstab
cat /etc/fstab

# ---- getty autologin (tty1 + 串口 ttyS0) ----
mkdir -p /etc/systemd/system/getty@tty1.service.d /etc/systemd/system/serial-getty@ttyS0.service.d
cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf <<'A'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
A
cat > /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf <<'A'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear --keep-baud 115200,57600,38400,9600 %I $TERM
A
cat /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf

# ---- W4A: 登录面接管（TTY 分流）----
# 控制台(ttyS0/tty1) autologin 落 bash 后读 .profile，命中控制台 TTY 即
# exec AI 控制台；SSH 会话为 /dev/pts/* 不匹配，保持 bash 运维通道。
cat > /root/.profile <<'PR'
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n 2> /dev/null || true

# W4A: console takeover -- 控制台登录面直进 AI 控制台
# .bashrc 已 source（AIKERNEL_TOOLS_JSON 环境就位）后再分流。
if [ -t 0 ] && [ -x /usr/local/bin/aikernel-shell ]; then
    case "$(tty 2>/dev/null)" in
        /dev/ttyS0|/dev/tty1)
            exec /usr/local/bin/aikernel-shell
            ;;
    esac
fi
PR
chown root:root /root/.profile && chmod 644 /root/.profile
cat /root/.profile
CHROOT

echo "=== [5] 拷入 AI 三件套 (静态) ==="
# W4A: 二进制必须 strip 再进镜像 —— 未 strip 的特定 ELF 布局在
# AIKernel 内核(#28 实测)上启动即 SIGSEGV（VM 宿主内核正常），strip
# 改变布局后稳定（另使镜像更小 3.2M→2.2M）。
strip "$SRC/agent/ai/ai" "$SRC/agent/ai/aikernel-shell" "$SRC/tools/ai/aikctl"
install -D -m755 "$SRC/agent/ai/ai"             "$MNT/usr/local/bin/ai"
install -D -m755 "$SRC/agent/ai/aikernel-shell" "$MNT/usr/local/bin/aikernel-shell"
install -D -m755 "$SRC/tools/ai/aikctl"         "$MNT/usr/local/bin/aikctl"
install -D -m644 "$SRC/agent/ai/tools/mock_ollama.py" "$MNT/usr/local/bin/mock_ollama.py"
file "$MNT/usr/local/bin/ai" "$MNT/usr/local/bin/aikernel-shell" "$MNT/usr/local/bin/aikctl" | sed 's/, BuildID.*//'
ls -la "$MNT/usr/local/bin/"

echo "=== [6] 拷入 SME (/opt/sme) + python 依赖 ==="
rm -rf "$MNT/opt/sme"
cp -a /home/jack66g/sme "$MNT/opt/sme"
rm -rf "$MNT/opt/sme/.git"
find "$MNT/opt/sme" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
# guest 内存储路径修正: /home/jack66g/sme -> /opt/sme
sed -i 's#/home/jack66g/sme/data/engine.json#/opt/sme/data/engine.json#g' "$MNT/opt/sme/data/sme.config.json"
grep -c '/opt/sme/data/engine.json' "$MNT/opt/sme/data/sme.config.json"
ls "$MNT/opt/sme/data/"

mkdir -p "$MNT/usr/local/lib/python3.10/dist-packages"
cp -a /home/jack66g/.local/lib/python3.10/site-packages/. "$MNT/usr/local/lib/python3.10/dist-packages/"
du -sh "$MNT/usr/local/lib/python3.10/dist-packages"

echo "=== [7] guest 版 sme-rest-server.py + start-sme.sh + systemd unit ==="
cat > "$MNT/usr/local/bin/sme-rest-server.py" <<'PY'
#!/usr/bin/env python3
"""SME REST 服务启动包装（guest 版）：先恢复快照再对外服务。

与宿主版逻辑一致，仅 SME_HOME 改为 /opt/sme。
"""
import os, sys

SME_HOME = "/opt/sme"
os.chdir(SME_HOME)
sys.path.insert(0, SME_HOME)

import uvicorn
from sme.api.server import resolve_engine, create_app

engine, config_file, source = resolve_engine()
loaded = engine.load()
print("[sme-rest-server] snapshot loaded=%s memories=%d regions=%d config=%s" % (
    loaded, len(engine.memories), len(engine.space.regions), config_file), flush=True)

app = create_app(engine, config_file=config_file, source=source)
uvicorn.run(app, host="127.0.0.1", port=8000)
PY
chmod 755 "$MNT/usr/local/bin/sme-rest-server.py"

cat > "$MNT/usr/local/bin/start-sme.sh" <<'SH'
#!/usr/bin/env bash
# SME (Spatial Memory Engine) 常驻启动脚本 — 幂等（guest 版）
# 服务: /usr/local/bin/sme-rest-server.py (启动时自动 load 快照，重启不丢数据)
# 数据落盘位置（固化，绝对路径）: /opt/sme/data/engine.json(.gz) + engine.embeddings.npz
# 配置文件（固化）: /opt/sme/data/sme.config.json
# 日志: /tmp/sme.log
HOST="127.0.0.1"
PORT="8000"

if pgrep -f "sme-rest-server.py" > /dev/null 2>&1; then
    echo "[start-sme] SME 已在运行 (pid=$(pgrep -f "sme-rest-server.py" | head -1))，跳过启动"
else
    nohup python3 /usr/local/bin/sme-rest-server.py > /tmp/sme.log 2>&1 &
    echo "[start-sme] SME 已启动 pid=$!"
fi

for i in $(seq 1 30); do
    if curl -s "http://$HOST:$PORT/health" | grep -q "ok"; then
        echo "[start-sme] health OK: $(curl -s http://$HOST:$PORT/health)"
        exit 0
    fi
    sleep 1
done
echo "[start-sme] 启动后健康检查失败，日志尾部："
tail -20 /tmp/sme.log
exit 1
SH
chmod 755 "$MNT/usr/local/bin/start-sme.sh"

cat > "$MNT/etc/systemd/system/aikernel-memory.service" <<'U'
[Unit]
Description=AIKernel SME Memory Engine (REST 127.0.0.1:8000)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/start-sme.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
U

echo "=== [7.5] W4A: 拷入本地 AI 栈 (ollama + qwen2.5:1.5b) ==="
# VM 宿主 ollama 二进制与模型目录整体进 guest，出厂自含 AI 栈
install -D -m755 /usr/local/bin/ollama "$MNT/usr/local/bin/ollama"
OLLAMA_SRC_DIR="${OLLAMA_SRC_DIR:-/usr/share/ollama/.ollama}"
mkdir -p "$MNT/var/lib/ollama/models"
cp -a "$OLLAMA_SRC_DIR/models/." "$MNT/var/lib/ollama/models/"
chown -R root:root "$MNT/var/lib/ollama/models"   # guest 侧由 ollama 用户运行时读
du -sh "$MNT/var/lib/ollama/models"
cat > "$MNT/etc/systemd/system/ollama.service" <<'U'
[Unit]
Description=Ollama Local LLM Engine (AIKernel built-in)
After=network.target

[Service]
Type=simple
User=ollama
Group=ollama
Environment=OLLAMA_MODELS=/var/lib/ollama/models
Environment=OLLAMA_HOST=127.0.0.1:11434
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
U
chroot "$MNT" useradd -r -d /var/lib/ollama -s /usr/sbin/nologin ollama 2>/dev/null || true
chroot "$MNT" chown -R ollama:ollama /var/lib/ollama
ls -la "$MNT/var/lib/ollama/models/manifests/registry.ollama.ai/library/" 2>/dev/null || true

echo "=== [8] guest root 的 aikernel-shell LLM 配置 (127.0.0.1:11434 guest 本地栈) ==="
mkdir -p "$MNT/root/.aikernel"
cat > "$MNT/root/.aikernel/model.toml" <<'M'
# AIKernel Model Configuration (guest: aikernel)
# 出厂链路: guest 内置 ollama (systemd 自启, Restart=always) -> qwen2.5:1.5b
[default]
model = "local"

[local]
enabled = true
base_url = "http://127.0.0.1:11434/v1"
model = "qwen2.5:1.5b"
timeout_ms = 120000
api_key = ""

[models.local]
provider_type = "local"
model_name = "qwen2.5:1.5b"
base_url = "http://127.0.0.1:11434/v1"
api_key = ""

# W4A: 出厂显式 ctx_len=8192 —— 默认 262144 会被钳到模型上限 32768，
# 1.5b 模型 32k KV cache(fp16) ~940MB，与 986MB 权重相加在 2G 内存 guest
# 上必然 OOM（实测 panic 连环杀）。8192 ctx 的 KV ~235MB 可稳态运行。
[ui]
ctx_len = 8192
max_tokens = 4096
stream = true
local_api = "native"
color = true
verbose = false
session = "default"
M
cat > "$MNT/root/.aikernel/provider.toml" <<'P'
# AIKernel Provider Configuration (guest: aikernel)
[providers]
available = ["openai_compatible", "local"]

[providers.openai_compatible]
type = "cloud"
description = "OpenAI-compatible API provider"
supports = ["chat", "stream"]

[providers.local]
type = "local"
description = "Local model inference"
supports = ["chat", "stream"]
P
cat "$MNT/root/.aikernel/model.toml"

echo "=== [9] 启用服务 + chroot 冒烟测试 ==="
chroot "$MNT" /bin/bash -e -x <<'CHROOT2'
systemctl enable aikernel-memory.service ollama.service ssh 2>&1 | tail -2 || true
ls /etc/systemd/system/multi-user.target.wants/ 
echo "--- python deps smoke ---"
python3 -c "import numpy, fastapi, uvicorn, httpx, networkx, multipart; print('PYDEPS_OK', numpy.__version__, fastapi.__version__, uvicorn.__version__)"
python3 -c "import sys; sys.path.insert(0,'/opt/sme'); from sme.api.server import resolve_engine; print('SME_IMPORT_OK')"
CHROOT2

echo "=== [10] 清理 + 卸载 ==="
rm -f "$MNT/usr/sbin/policy-rc.d"
rm -f "$MNT/etc/resolv.conf.bak" 2>/dev/null || true
umount "$MNT/proc" "$MNT/sys" "$MNT/dev"
umount "$MNT"
echo BUILD_OK
