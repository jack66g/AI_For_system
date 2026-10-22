#!/bin/sh
# AIKernel SME 首启种子 v2（W10-A，差量导入幂等）：
#   首次开机把 tag=aikernel-interface 接口语料灌入本机 SME。
#   v2 修复：出厂 /opt/sme/data 快照自带旧版语料（150 条）时，旧版
#   "tag 计数非零即跳过" 会永远拒绝新语料 → 改为按 text 差量导入：
#   只 POST 本机 SME 尚不存在的条目，天然幂等、不重复、可随版本升级。
# 由 sme-seed.service（oneshot）在 aikernel-memory/ollama 就绪后调用
SEED=/usr/local/share/aikernel/sme-seed.jsonl
URL=http://127.0.0.1:8000
LOG=/tmp/sme-seed.log

exec >"$LOG" 2>&1
echo "[sme-seed] start $(date)"

# 1. 等 SME 就绪（最多 150s，TCG 冷启动慢）
n=0
while [ $n -lt 50 ]; do
  if curl -sf -m 3 "$URL/health" >/dev/null 2>&1; then break; fi
  n=$((n+1)); sleep 3
done
curl -sf -m 3 "$URL/health" >/dev/null 2>&1 || { echo "[sme-seed] SME not ready, abort"; exit 1; }
echo "[sme-seed] SME health OK"

# 2. 差量导入：与 /export 现有文本集合求差，只灌缺失条目
python3 - "$SEED" <<'PYEOF'
import json, sys, urllib.request
def call(path, data=None):
    r = urllib.request.Request("http://127.0.0.1:8000" + path,
        data=json.dumps(data).encode("utf-8") if data is not None else None,
        headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(r, timeout=600).read().decode("utf-8"))
items = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
have = {m.get("text") for m in call("/export").get("memories", [])}
missing = [m for m in items if m.get("text") not in have]
print("[sme-seed] seed=%d existing=%d missing=%d" % (len(items), len(have), len(missing)))
if missing:
    resp = call("/memories/batch", {"memories": missing})
    print("[sme-seed] batch resp:", resp)
else:
    print("[sme-seed] corpus already complete, skip")
PYEOF
RC=$?
echo "[sme-seed] done rc=$RC $(date)"
exit $RC
