#!/usr/bin/env python3
"""Fix the factory model.toml comments to match the intentional 32768 override."""
from pathlib import Path

p = Path("/home/jack66g/w7i-rootfs/root/.aikernel/model.toml")
s = p.read_text(encoding="utf-8")
s = s.replace(
    "# 保持一致——ctx_len=32768 == UI_DEFAULT_CTX_LEN，",
    "# W73：本模板显式覆盖代码默认（UI_DEFAULT_CTX_LEN 仍 8192）；",
)
s = s.replace(
    "# W4A: 出厂显式 ctx_len=32768（防 32k KV cache OOM，见 build-rootfs.sh 注释）",
    "# W73: 出厂显式 ctx_len=32768（提升上下文预算；本地模型仍受 max_tokens 限制）",
)
p.write_text(s, encoding="utf-8")
print("PATCHED")
