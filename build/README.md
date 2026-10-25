# AIKernel 构建流水线总览（build/README.md）

> 建立于 W78（2026-10-26）。本文件画清"干净 Linux 6.18.39 → 出厂 ISO"的**三级
> 流水线**：每级给命令、输入输出、防呆点。发布版重建的正式说明见仓库根
> `BUILD.md`（alpha.12.0 口径）；本文件补充构建机（VM，7G 内存）实跑链与
> rootfs/ISO 级，两文冲突时以 BUILD.md 与脚本本身为准。

```
①kernel-overlays 应用 ──→ ②内核构建 ──→ ③rootfs + ISO 打包
  apply-overlays.sh          make bzImage      build-rootfs.sh → w7i-build-iso.sh
```

---

## ① kernel-overlays 应用（overlay → 内核树）

- **命令**（在仓库根 `aikernel-repo-alpha11/`）：
  ```bash
  bash build/apply-overlays.sh /path/to/linux-6.18.39
  cp .config /path/to/linux-6.18.39/.config
  ```
- **输入**：`kernel-overlays/`（168 文件，152 个 .c 埋点）+ `MANIFEST.sha256`
  （逐文件 sha256 清单）；输出：目标内核树被逐文件覆盖并校验。
- **脚本行为**（build/apply-overlays.sh）：按 MANIFEST 逐行 `cp -p` 复制，然后
  第二遍 `sha256sum` 校验目标文件哈希，任一不匹配即报 `SHA256 MISMATCH` 退出。
- **防呆点**：
  - **不要** `rsync -a kernel-overlays/ linux-6.18.39/` 整目录覆盖——`README.md`
    与 `MANIFEST.sha256` 是仓库元数据，不是内核文件；
  - 用完后可独立复核：`cd kernel-overlays && sha256sum -c MANIFEST.sha256`；
  - 基础版本固定 Linux 6.18.39；升内核不能直接套用，需按钩子逐个移植。
- **验证**：脚本末行打印 `overlays applied and verified: <N> files -> <target>`。

## ② 内核构建（bzImage）

- **命令**（在内核树，构建机 VM 内）：
  ```bash
  cd /home/jack66g/linux-6.18.39
  make -j3 bzImage        # 7G 内存机安全值；见下方防呆
  ```
- **输入**：① 产出并复制好的 `.config`（W78：DEBUG_INFO_BTF/PSI/FANOTIFY/
  INET_DIAG 家族/SCHED_CLASS_EXT=y，DEBUG_INFO_NONE 关）；输出：
  `arch/x86/boot/bzImage`（W78 #60：19,305,472 B，md5 026e33b7…，0 warning）。
- **防呆点（重要）**：
  - **7G 内存机上 `make -j8` 会 OOM 静默死**（进程被杀无报错，像卡住）；
    W78 实测 -j8 失败 → **-j3 通过**，把 -j3 当安全上限；
  - 复现发布构建号：`make KBUILD_BUILD_VERSION=<N> KBUILD_BUILD_TIMESTAMP="<...>"`
    （见仓库 BUILD.md §2）；
  - Windows/NTFS 树有大小写限制（13 对 netfilter 文件无法并存），**权威构建树是
    VM 内 `~/linux-6.18.39`**（`linux-6.18.39/.casefix/README.md`）。
- **agent/ai（用户态）构建**：与内核构建共用构建机时用文件锁串行，防并发内存峰值：
  ```bash
  flock /home/jack66g/aik-build.lock make -j1    # 在 agent/ai/ 下；.NOTPARALLEL，串行最稳
  ```
  （锁用法出处 `agent/ai/docs/W74-LEASE.md:285`；agent Makefile 头注：-j4 下 gold
  链接器偶发 internal error。）
- **验证**：`grep -c "warning:" build3.log` 为 0；`file arch/x86/boot/bzImage`。

## ③ rootfs + ISO（build-rootfs.sh → w7i-build-iso.sh）

### ③a rootfs

- **命令**（VM 内以 root）：`bash /home/jack66g/linux-6.18.39/agent/ai/build-rootfs.sh`
- **输入**：Ubuntu jammy 源 + 构建机工具（debootstrap/socat/tmux/qemu-img，脚本
  自装）；输出：`/home/jack66g/aikernel-root.raw`——8G raw ext4 **整盘无分区表**
  （root=/dev/vda 直接挂）。
- **流程**：qemu-img 建盘 → mkfs.ext4 → debootstrap jammy minbase → chroot 装配
  （systemd/openssh-server/python3 等，`policy-rc.d` 禁止 chroot 内起服务）→
  root 免密公钥 + 密码锁定（sshd 仅密钥）→ DNS/QEMU user-net 适配。
- **防呆点**：
  - 必须 root 运行（loop 挂载 + chroot）；
  - 重复运行对已有镜像跳过 debootstrap（`/bin/bash` 存在则不重建）；
  - QEMU 启动参数：`-m 4096`（2G 实测 OOM 连环 panic，3G 临界，4G 稳定），
    镜像内含 2G /swapfile；TCG 下 1.5b prefill ~10min 级，有 nested-KVM 加
    `-enable-kvm`（脚本头部 W4A 注记）。

### ③b ISO

- **命令**（VM 内）：`bash /home/jack66g/w7i-build-iso.sh [bzImage路径]`
  （默认取现役 `/home/jack66g/linux-6.18.39/arch/x86/boot/bzImage`）
- **输入**：bzImage + `/home/jack66g/w6i-initrd.img` + `/home/jack66g/w7i-rootfs-factory.tar`
  （factory rootfs tar，含 systemd AI 服务/10 timers/lsm=ai grub 模板）+
  `w6i-tools/grub-iso.cfg`；输出：`/home/jack66g/AIKernel-0.1.0-alpha-x86_64.iso`
  （grub-mkrescue 生成，打印 md5）。
- **防呆点**：
  - ISO 名固定 `AIKernel-0.1.0-alpha-x86_64.iso`（不含波次号），**出 ISO 后先记
    md5 再挪动**（发布记录以 md5 为准）；
  - factory tar 与 grub 模板必须同波配套（lsm=ai、ai.enabled=1 在
    w6i-tools/init:270,274 的装机模板里，不要手工只改一边）；
  - `w7i-build-iso.sh` 会先 `rm -rf` ISO 临时目录，不要把别的东西放进
    `/home/jack66g/w6i-isodir`。
- **验证**：脚本打印 `ISO_BUILT` + md5；装机冒烟（qemu install/diskboot）见仓库
  BUILD.md 与 longterm 波次报告。

---

## 三级流水线一页速查

| 级 | 脚本 | 输入 | 输出 | 最大坑 |
|---|---|---|---|---|
| ① | build/apply-overlays.sh | kernel-overlays + MANIFEST | 已埋点内核树 | 别 rsync 整目录 |
| ② | make -j3 bzImage（内核）/ flock aik-build.lock make -j1（agent） | .config | bzImage / aikernel-shell | -j8 OOM 静默死 |
| ③ | agent/ai/build-rootfs.sh → w7i-build-iso.sh | jammy 源 + bzImage + factory tar | aikernel-root.raw → AIKernel-0.1.0-alpha-x86_64.iso | root 运行；-m 4096；记 md5 |

*W78 文档波（棒3-F）建立。数字为 2026-10-26 实读；脚本行为以脚本本身为准。*
