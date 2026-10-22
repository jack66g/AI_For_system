#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""W77d read-only hardware / local-model inventory.

Emits a JSON document (schema aik-local-hardware/1) for model capacity
planning. No model install, no config write, no network download.
Run on the target host:
    python3 w77d_inventory.py /root/w77d-hardware.json
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


def run(args, timeout=10):
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, "", str(e)


def read(path, default=""):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def cpu_info():
    text = read("/proc/cpuinfo")
    model = ""
    flags = []
    cores = 0
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        if k == "model name" and not model:
            model = v
        elif k == "processor":
            cores += 1
        elif k == "flags" and not flags:
            flags = v.split()
    return {
        "arch": os.uname().machine,
        "model": model,
        "logical_cpus": cores or os.cpu_count(),
        "avx2": "avx2" in flags,
        "avx512": any(f.startswith("avx512") for f in flags),
        "avx_vnni": "avx_vnni" in flags,
        "flags_sample": [f for f in flags if f in
                         ("avx2", "avx512f", "avx_vnni", "f16c", "fma")],
    }


def mem_info():
    out = {"total_kb": 0, "available_kb": 0, "swap_total_kb": 0}
    for line in read("/proc/meminfo").splitlines():
        for key, field in (("MemTotal", "total_kb"),
                           ("MemAvailable", "available_kb"),
                           ("SwapTotal", "swap_total_kb")):
            if line.startswith(key + ":"):
                try:
                    out[field] = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
    return out


def disk_info():
    out = {}
    for mount in ("/", "/var/lib", "/root"):
        try:
            u = shutil.disk_usage(mount)
            out[mount] = {"total": u.total, "used": u.used, "free": u.free,
                          "free_gib": round(u.free / (1 << 30), 2)}
        except OSError:
            pass
    return out


def gpu_info():
    gpus = []
    _, lspci, _ = run(["lspci"])
    for line in lspci.splitlines():
        if re.search(r"(?i)(vga|3d|display)", line):
            gpus.append({"pci": line, "vendor": "unknown", "vram_mib": None})
    _, smi, _ = run(["nvidia-smi", "--query-gpu=name,memory.total",
                     "--format=csv,noheader,nounits"])
    if smi:
        for line in smi.splitlines():
            parts = [x.strip() for x in line.split(",")]
            if len(parts) >= 2:
                gpus.append({"name": parts[0], "vram_mib": parts[1],
                             "source": "nvidia-smi"})
    return gpus


def ollama_info():
    out = {"service": "", "version": "", "models": [], "models_dir_bytes": 0}
    rc, active, _ = run(["systemctl", "is-active", "ollama"])
    out["service"] = active or "unknown"
    _, ver, _ = run(["ollama", "--version"])
    out["version"] = ver
    _, listing, _ = run(["ollama", "list"])
    for line in listing.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("NAME"):
            out["models"].append({
                "name": parts[0], "id": parts[1],
                "size": " ".join(parts[2:4]),
            })
    for d in ("/root/.ollama/models", "/usr/share/ollama/.ollama/models",
              "/var/lib/ollama/models"):
        if os.path.isdir(d):
            try:
                total = 0
                for root, _, files in os.walk(d):
                    for f in files:
                        try:
                            total += os.path.getsize(os.path.join(root, f))
                        except OSError:
                            pass
                out["models_dir_bytes"] += total
            except OSError:
                pass
    return out


def capacity(mem_kb, free_bytes):
    """Conservative placeholder capacity; not a benchmark."""
    ram_gib = mem_kb / (1024 * 1024)
    # Q4 GGUF rough footprint + runtime headroom
    max_param_b = max(0.0, (ram_gib - 2.5) / 0.75)
    return {
        "ram_gib": round(ram_gib, 2),
        "free_disk_gib": round(free_bytes / (1 << 30), 2),
        "estimated_max_q4_params_b": round(max_param_b, 2),
        "note": "estimate only; benchmark is authoritative",
    }


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    cpu = cpu_info()
    mem = mem_info()
    disk = disk_info()
    root_free = (disk.get("/") or {}).get("free", 0)
    doc = {
        "schema": "aik-local-hardware/1",
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hostname": os.uname().nodename,
        "cpu": cpu,
        "memory": mem,
        "disk": disk,
        "gpu": gpu_info(),
        "ollama": ollama_info(),
        "capacity": capacity(mem["total_kb"], root_free),
        "limits": {
            "no_network_download": True,
            "no_config_write": True,
            "no_model_install": True,
        },
    }
    text = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
    if target:
        p = Path(target)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(str(p), 0o600)
        print("written %s" % p)
    print(text)


if __name__ == "__main__":
    main()
