# AIKernel K 轨补丁系列（K10.3 生成物）

- 基线：`/home/jack66g/linux-6.18.39`（alpha-11 出厂基线，**非 vanilla**；
  vanilla 上游系列=登记尾账，tarball 到位后 --base 换指再生）
- 源：kernel-overlays/（172 文件；与基线同内容 34 不入系）
- 再生：`python3 AIKernel/scripts/k10_patch_series.py`
- integrity：overlay↔构建树逐字节一致（--check-only 门禁位）

- **0001-kernel-core**：40 补丁
- **0002-mm**：23 补丁
- **0003-crypto**：1 补丁
- **0004-security**：3 补丁
- **0005-block**：8 补丁
- **0006-fs**：19 补丁
- **0007-net**：18 补丁
- **0008-virt**：1 补丁
- **0009-drivers**：9 补丁
- **0010-include**：3 补丁
- **0011-arch**：8 补丁
- **0099-misc**：5 补丁
