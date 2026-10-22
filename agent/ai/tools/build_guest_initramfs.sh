#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# build_guest_initramfs.sh - 组装 QEMU guest 用的最小 initramfs（ask 工具闭环 E2E）
#
# 内容：
#   - busybox + 常用符号链接（/bin）
#   - 静态链接的 aikernel-shell + tools.json（工具注册表）
#   - /root/.aikernel/model.toml：provider 指向宿主机推理服务
#     （10.0.2.2:$GUEST_LLM_PORT，默认 11434=真实 Ollama qwen2.5:1.5b；
#     传 GUEST_LLM_PORT=11435 时指向 mock_ollama.py 确定性脚本）
#   - /init：挂载 proc/sys/dev → 配置 slirp 网络（10.0.2.15/24 网关 10.0.2.2，
#     无此步骤 guest 访问不到宿主服务，"Network is unreachable"）→ 采集
#     /proc/ai、/sys/kernel/ai 清单（注册表生成器的 QEMU dump 来源）→
#     跑两轮 ask（procfs-read 遥测与 netlink-act sched.nice(pid=1)）→ 关机
#   - guest 环境变量：SME_URL=http://10.0.2.2:8000（宿主机 SME 记忆服务）
#
# 产物: /tmp/ai-initramfs.cpio.gz
# 用法: bash build_guest_initramfs.sh [GUEST_LLM_PORT]
set -e

ROOT=/tmp/ai-initramfs
AI_DIR=$HOME/linux-6.18.39/agent/ai
LLM_PORT=${1:-${GUEST_LLM_PORT:-11434}}

rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/sbin" "$ROOT/proc" "$ROOT/sys" "$ROOT/dev" \
	 "$ROOT/root/.aikernel" "$ROOT/etc"

cp /usr/bin/busybox "$ROOT/bin/"
for app in sh mount cat ls find sleep poweroff echo grep head uname; do
	ln -sf busybox "$ROOT/bin/$app"
done

cp "$AI_DIR/aikernel-shell" "$ROOT/bin/"
cp "$AI_DIR/tools.json" "$ROOT/tools.json"

# guest 内模型配置：走宿主机（slirp 10.0.2.2 = 宿主 127.0.0.1）上的推理服务
cat > "$ROOT/root/.aikernel/model.toml" <<EOF
model = "local"

[local]
enabled = 1
base_url = "http://10.0.2.2:${LLM_PORT}/v1"
model = "qwen2.5:1.5b"
timeout_ms = 120000
api_key = ""

[models.local]
provider_type = "local"
model_name = "qwen2.5:1.5b"
base_url = "http://10.0.2.2:${LLM_PORT}/v1"
api_key = ""
EOF

cat > "$ROOT/init" <<EOF
#!/bin/sh
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
# slirp 网络静态配置（QEMU user 网络默认网段）：guest=10.0.2.15 网关/DNS=10.0.2.2。
# 不配置则 eth0 无 IP，访问宿主服务（SME 8000 / LLM 11434）报 Network unreachable
ifconfig lo 127.0.0.1 up 2>/dev/null
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
route add default gw 10.0.2.2 2>/dev/null || ip route add default via 10.0.2.2
export HOME=/root
export PATH=/bin
# guest 访问宿主机 SME 记忆服务（slirp: 10.0.2.2 -> 宿主 127.0.0.1）
export SME_URL=http://10.0.2.2:8000

echo "### cat /proc/ai/control ###"
cat /proc/ai/control
echo "### ls /proc/ai ###"
ls /proc/ai
echo "### find /proc/ai -maxdepth 2 -type f ###"
find /proc/ai -maxdepth 2 -type f
echo "### ls -R /sys/kernel/ai ###"
ls -R /sys/kernel/ai

echo "===== [5] ask 读取内核遥测并总结（procfs-read 通道）====="
echo "ask 读取内核遥测并总结" | /bin/aikernel-shell

echo "===== [6] ask 把 pid 1 的 nice 值设为 5（netlink-act 通道）====="
echo "ask 把 pid 1 的 nice 值设为 5" | /bin/aikernel-shell

echo "===== guest tests done ====="
poweroff -f
EOF
chmod +x "$ROOT/init"

cd "$ROOT"
find . | cpio -o -H newc --quiet | gzip > /tmp/ai-initramfs.cpio.gz
ls -la /tmp/ai-initramfs.cpio.gz
echo "OK (LLM port: ${LLM_PORT})"
