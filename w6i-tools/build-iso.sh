#!/bin/bash
# AIKernel ISO 构建脚本 (VM 侧执行)
# 用法: build-iso.sh [bzImage路径]  (默认现役内核)
# v1.1(I3): rootfs 改用 w7i-rootfs-factory.tar(现役出厂件)
# v1.4(W12): 产物 AIKernel-0.1.0-alpha.4-x86_64.iso;
#            ISO 双引导(BIOS+UEFI) —— grub-mkrescue 在检测到
#            /usr/lib/grub/x86_64-efi + mtools 时自动加 efi.img,
#            BIOS 与 UEFI 固件均可引导本 ISO; 双菜单结构不变
# v1.4.1(W14): 产物 AIKernel-0.1.0-alpha.4.1-x86_64.iso
#            【根治·出厂基线单一权威】~/w7i-rootfs/ 是出厂 rootfs 的
#            唯一权威树: w7i-rootfs-factory.tar 必须由 ~/w7i-rootfs/
#            现打生成 (sudo tar -C ~/w7i-rootfs -cf ~/w7i-rootfs-factory.tar .),
#            禁止用任何其他基线副本(w6i-rootfs/w10a-rootfs/w11-isodir/
#            w12-staging 增量 append tar 等)直接打包。
#            事故教训: W12 打 v1.4 时 tar 旧于树, 装机缺
#            /etc/nftables.conf、aikernel-health 三件、75 工具版
#            tools.json(root/.aikernel 处仍为 74 工具旧版)。
# v1.5(W15): 产物 AIKernel-0.1.0-alpha.5-x86_64.iso; 收 A/B/C 三波修复资产
# v1.5.1(W16): 产物 AIKernel-0.1.0-alpha.5.1-x86_64.iso;
#            新增 strip_chunked 段错误修复 (github chunked 解码越界读), 二进制重收编;
#            mbedtls 两级裁剪已收编进源码树 —— 裁剪只影响源码树与二进制
#            内容, 不影响本打包流程 (内核不重编, 流程不变)。
#            (agent 合并态二进制 strip 件、75 工具 tools.json 8aa47d3f 三处、
#            tool_catalog.txt 69fb0d34、SME 种子 193 条 ac5f79f1)
# v1.5.2(W17): 产物 AIKernel-0.1.0-alpha.5.2-x86_64.iso;
# v1.5.3(W19): 产物 AIKernel-0.1.0-alpha.5.3-x86_64.iso;
# v1.5.4(W20): 产物 AIKernel-0.1.0-alpha.5.4-x86_64.iso;
#            N 波五修复收编: per-provider max_tokens(双档 local 1024/cloud 8192,
#            出厂模板同步双档化)/compact 降级/tee 中转/W2 确认泄漏修复/
#            python3 白名单(tools.json 8ee9a5c6 加 python3 W2 级 + tool_catalog
#            9529a8b8 重生成)+exec 命令级 risk 闸门生效; 二进制重收编
#            (10494d16 构建树, strip 后进树)。
#            注: N 波在用户 VM 本机另构建部署了一版(399e38ef, build-essential
#            环境差异二进制不同、源码同一套), 功能等价(同源码同 tests);
#            ISO 出厂统一收编本机(L1)构建版。
#            M 波六大修复收编: 直说进 AI(免 ask 前缀分发)/预算治理/
#            fbterm 兼容/串口诊断/夹具自足 等; 二进制重收编
#            (2de3ad77 构建树, strip 后进树); model.toml 出厂模板
#            max_tokens 4096->1024 (M 波 W18 已改树, 本版随 tar 收口)。
#            1) agent 双语化(中/英可切换): 新增 i18n/lang.c tr() 表 +
#               lang 命令(持久化 model.toml [ui] lang) + AIKERNEL_LANG 环境变量,
#               UI 层文案全部入表(默认中文); 二进制重收编(3657a2bf strip 后)
#            2) motd 单源根治: /etc/motd 版本 token @@VERSION@@ 由本脚本
#               按 VERSION 注入(旧版手写 alpha.2 的 v1.2 遗留缺陷根治),
#               文案双语两行
#            3) bash banner 根治: .bashrc "L1 就绪(内部称呼)" 改双语正常文案
#            4) 出厂中文显示: fbterm 1.7-5 + fonts-wqy-microhei + 依赖库
#               (libfontconfig1/libfreetype6/libpng16-16/libx86-1) dpkg-deb -x
#               进树, deb 原件存 /var/cache/apt/archives/; GRUB 默认菜单项
#               (ISO grub-iso.cfg 与安装器 init 生成 /boot/grub/grub.cfg 双处)
#               linux 行加 vga=791 起 VESA framebuffer; /etc/profile.d/
#               auto-fbterm.sh tty1 自动进 fbterm(防递归, 串口不受影响)
#            5) 本版起打包预处理内建: motd 版本注入 + 清残 + 现打 factory tar
# v1.5.5(W22): 产物 AIKernel-0.1.0-alpha.5.5-x86_64.iso;
#            K 波内核 #38 收编 (md5 e0b1800b, 2026-10-04 08:35 构建):
#            net.qdisc 内核接线(独立 worker 持 rtnl 异步换根, 值域 0-3,
#            codel/fq/fq_codel, CONFIG_NET_SCH_FQ_CODEL=y 顺带开启) +
#            遥测 rate 接口 /proc/ai/telemetry 写路径(per-cat/ev 采样率,
#            KUnit dryrun 护栏 + qemu 冒烟 tc qdisc show 实证);
#            w21 tools.json c3ae09f9 三处(root/.aikernel 第三处 K 波
#            漏更 8ee9a5c6, 本波 W22 补齐) + tool_catalog 0a81e06f;
#            二进制 91cc02fa / model.toml 84a1b324(双档 8192/1024) /
#            sme-seed ac5f79f1 / policy 9bc4facb 不变。
#            K 波账目: 构建日志 build_38.log + kunit_38_ktap.log +
#            smoke_38_boot.log 见 ~/w21-evidence/logs/。
# v1.5.6(W24): 产物 AIKernel-0.1.0-alpha.5.6-x86_64.iso;
#            K 波 #39 内核收编 (md5 8b7977ce, 2026-10-06 18:02 构建, UTS
#            "#39 SMP PREEMPT_DYNAMIC"): W24 遥测环修复 —— 后台排空线程
#            (250ms ai_tel_drain) + 积压自适应降采样 + 环深 128K->256KB +
#            读/驱逐/写三处错位自愈防御; 无 initrd(沿用既有引导惯例)。
#            F 波(W23) agent 二进制收编: 会话进程级锁+并发派生隔离 +
#            ctx 预算新口径(ai_runtime_ctx_used, 85% 自动压缩对齐);
#            L1 确定性重建件 bea3c1f4(strip 后, /root 路径构建;
#            VM 侧 ae4ed532 与重建件源码/工具链全同, 链接布局抽样差异,
#            等价性证明见 iso-v156 证据)。
#            tools.json c3ae09f9 三处 / tool_catalog 0a81e06f /
#            model.toml 84a1b324 / sme-seed ac5f79f1 / policy 9bc4facb
#            均不变; motd 复原 sed 目标本版由 5.4 改指 5.5。
# v1.6.0(G2): 产物 AIKernel-0.1.0-alpha.6.0-x86_64.iso;
#            G 波 #40 内核收编 (md5 25e71110, softdog 上机生效): softdog
#            软件看门狗 (CONFIG_SOFT_WATCHDOG=m) + 出厂首次带模块树
#            /lib/modules/6.18.39 (g40-mods-vm.tar.gz 173c0fbc, 124KB,
#            softdog.ko 4dee79c3 标准路径 + depmod 索引全套) + 开机自启
#            两配置 (/etc/modules-load.d/aik-softdog.conf 单行 softdog +
#            system.conf RuntimeWatchdogSec=15s/RebootWatchdogSec=10min);
#            installer 完成摘要加 softdog 一行 ([5/8] 内核步骤不变)。
#            REPL 收生产 VM 现役件 b64c6435 (79 工具版, W29-W31:
#            结构化 API/aikctl/记忆演化/云端降级/file_patch; VM 态=出厂
#            目标态原则, W31 源码仅在 VM 侧故不做 L1 重编)。
#            aikernel-api dffa0818 / health.sh 9c43aa8c(W29 扩面) /
#            memory.service 4156c7c2(SME REST 常驻 Restart=always) /
#            tools.json 79 工具版 e8ceb970 三处统一 / tool_catalog
#            6dbbdf8a(VM 件 ffaf17d9+补 file_patch 行) / sme-seed
#            9feebe1e 205 条(w28 增量已并入) / model.toml 6f5ff359
#            (84a1b324 基础上加 [api]/[memory_evolve]/cloud_first_byte_
#            timeout 注释示例, 默认值不出厂) / nftables f4948dfd(W27/B
#            防爆破) / locale 新增 / A/B 升级+备份+盘检单元全套新增
#            (upgrade-commit/backup/disk-check svc+timer+wants 软链) /
#            sbin 五件套新增(aik-upgrade/aik-backup/aik-token/
#            aik-cert-gen/aik-reset)。
#            motd 复原 sed 目标本版由 5.5 改指 5.6。
set -e
BZ=${1:-/home/jack66g/linux-6.18.39/arch/x86/boot/bzImage}
ISODIR=/home/jack66g/w6i-isodir
VERSION=0.1.0-alpha.6.0
ISO=/home/jack66g/AIKernel-${VERSION}-x86_64.iso

echo "== 内核: $BZ =="
s() { printf '%s\n' '3124456607q' | sudo -S -p '' "$@"; }
s sed -i "s/0\.1\.0-alpha\.5\.6/@@VERSION@@/g" /home/jack66g/w7i-rootfs/etc/motd   # W19: motd token 恢复(上版已消费)
grep -q "@@VERSION@@" /home/jack66g/w7i-rootfs/etc/motd || { echo "motd token 恢复失败"; exit 1; }
echo "== [v1.5.2 预处理] motd 版本注入(单源) =="
s sed -i "s/@@VERSION@@/${VERSION}/g" /home/jack66g/w7i-rootfs/etc/motd
grep -q "${VERSION}" /home/jack66g/w7i-rootfs/etc/motd || { echo "motd 版本注入失败"; exit 1; }
if grep -q "@@VERSION@@" /home/jack66g/w7i-rootfs/etc/motd; then echo "motd 仍有未注入 token"; exit 1; fi
s cat /home/jack66g/w7i-rootfs/etc/motd

echo "== [v1.5.2 预处理] 清 chroot 残留（W14/W16 清单）=="
s truncate -s 0 /home/jack66g/w7i-rootfs/etc/machine-id
[ -f /home/jack66g/w7i-rootfs/var/lib/dbus/machine-id ] && s truncate -s 0 /home/jack66g/w7i-rootfs/var/lib/dbus/machine-id
s find /home/jack66g/w7i-rootfs/var/log -mindepth 1 -delete
s find /home/jack66g/w7i-rootfs/tmp /home/jack66g/w7i-rootfs/var/tmp -mindepth 1 -delete 2>/dev/null || true
s find /home/jack66g/w7i-rootfs/run -mindepth 1 -delete
echo "残留复核: var/log=$(s find /home/jack66g/w7i-rootfs/var/log -mindepth 1 | wc -l) tmp=$(s find /home/jack66g/w7i-rootfs/tmp -mindepth 1 | wc -l) run=$(s find /home/jack66g/w7i-rootfs/run -mindepth 1 | wc -l)"

echo "== [v1.5.2 预处理] 权威树现打 factory tar（单一权威）=="
TAR=/home/jack66g/w7i-rootfs-factory.tar
rm -f "$TAR"
s tar -C /home/jack66g/w7i-rootfs -cf "$TAR" .
s chmod 644 "$TAR"
sync
ls -la "$TAR"
md5sum "$TAR"
file "$BZ" | head -1

rm -rf "$ISODIR"
mkdir -p "$ISODIR/boot/grub"
cp "$BZ"                     "$ISODIR/boot/bzImage"
cp /home/jack66g/w6i-initrd.img "$ISODIR/boot/initrd.img"
cp /home/jack66g/w7i-rootfs-factory.tar "$ISODIR/rootfs-factory.tar"
cp /home/jack66g/w6i-tools/grub-iso.cfg "$ISODIR/boot/grub/grub.cfg"

grub-mkrescue -o "$ISO" "$ISODIR" 2>&1 | tail -3
ls -la "$ISO"
md5sum "$ISO"
echo ISO_BUILT
