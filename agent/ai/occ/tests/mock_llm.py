#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""mock_llm.py - occ -p 冒烟用本地 mock LLM（仅测试，明标）

用法: python3 mock_llm.py <port> <req_dir>

POST /v1/chat/completions：
  - 请求体原样落 <req_dir>/req_<n>.json（冒烟脚本断言 system prompt/
    历史组装用；失败请求也落盘——重试演练按文件数计尝试次数）
  - 回放固定 SSE（Content-Length 一次回；occ_sse 按字节切分消费，
    与 chunked 语义等价——mock 仅测试，如实标注）

回复固定文本「你好，我是 occ 冒烟 mock 助手。」+ usage + finish=stop
+ [DONE]。

T9b2 演练扩展（环境变量，缺省全关=旧行为不变）：
  OCC_MOCK_SLOW        每 data 块后 flush+sleep 秒数（kill 留窗口）
  OCC_MOCK_TOOL        =1 → 第 1 个请求回两枚 bash tool_call（sleep 2
                       写 a.txt/b.txt），其后请求回普通回复
                       （recover/interrupt 演练的工具执行阶段）
  OCC_MOCK_FAIL_N      前 N 个请求注入失败（重试演练「第 N 次成功」）
  OCC_MOCK_ALWAYS_FAIL =1 → 全部失败（「永不成功封顶」）
  OCC_MOCK_FAIL_STATUS 失败状态码（缺省 503；408=超时类/401=不重试）
  OCC_MOCK_BIND        监听地址（缺省 127.0.0.1；重试演练用 127.0.0.2
                       ——非 loopback 字面量，避开 occ 的 forwarder→direct
                       兜底，绝不触真网）
BLLM 波次 B 扩展（缺省全关=旧行为不变）：
  OCC_MOCK_LENGTH_FIRST=1 → 第 1 个请求回 finish_reason=length 截断流
                       （正文 LONGPART-A），其后请求回普通回复
                       ——B1 OutputLimit 续跑链路演练
  OCC_MOCK_RETRY_AFTER  失败响应附 Retry-After 头（B4 定向退避演练；
                       值原样入头——"1"/"abc"/"3600" 覆盖正/畸/过大面）

ORCH-E9 回路演练扩展（按请求内容分流——模式参照 mock_ac_llm.py
的系统提示分流；主控/子会话的系统提示同文，分流锚点=首条 user 的
固定标记 + ac 填表的专属 system）：
  主控（user 含 ORCH-E9-主控）    回 task 工具调用序列
                       spawn→wait→read_result→return(拒)→
                       [回炉窗：轮询库等任务回 in_review]→wait→
                       read_result→return(过)→收队文本
  子·首报（user 含【子智能体任务书（brief）】且回炉标记）
                       纯文本自称完成——无工具调用无证据（一拒的靶）
  子·二报（user 含 E9-回炉整改）   先回 write×2 工具调用（产物
                       out_e9.bin + 结果文件 # VERDICT 机械判表），
                       见到工具结果后回完成摘要（一改一过）
  ac 判定（system 含 压缩判定助手） → 判定 JSON（同 mock_ac_llm）
  ac 摘要（system 含 会话压缩助手） → 五必填章节 markdown（≥200 字，
                       携带【会话材料】事实）
  其余请求 → 旧行为逐字节不变（差分/p-smoke 红线路径）
同端口附带 mock autocondense REST（OCC_AC_URL 指过来；仅 E9 演练
消费）：POST /session/start、GET /check（should=NO——非 force 不压）、
POST /judge、POST /begin、POST /commit（digest 落快照文件回
snapshot_path——E5 读回原子闸消费）。路由序与角色名落
<req_dir>/ac_routes.log 与 <req_dir>/roles.log（演练断言用）。

用法: python3 mock_llm.py <port> <req_dir> [db_path]
  db_path（可选）= E9 回炉窗轮询用只读库路径；不传=无轮询（旧行为）
"""
import json
import hashlib
import os
import re
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPLY = "你好，我是 occ 冒烟 mock 助手。"

SSE = (
    'data: {"choices":[{"delta":{"role":"assistant","content":"'
    + REPLY[:4]
    + '"}}]}\n\n'
    'data: {"choices":[{"delta":{"content":"'
    + REPLY[4:]
    + '"}}]}\n\n'
    'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'
    'data: {"choices":[],"usage":{"prompt_tokens":42,'
    '"completion_tokens":8,"prompt_tokens_details":{"cached_tokens":3}}}\n\n'
    'data: [DONE]\n\n'
)

# 工具阶段（T9b2）：一次回两枚 bash 调用（各 sleep 2 后各写一个文件）——
# kill/SIGINT 有稳定窗口；两跑产物可对拍。
TOOL_SSE = (
    'data: {"choices":[{"delta":{"role":"assistant","tool_calls":['
    '{"index":0,"id":"call_t1","type":"function","function":'
    '{"name":"bash","arguments":""}},'
    '{"index":1,"id":"call_t2","type":"function","function":'
    '{"name":"bash","arguments":""}}]}}]}\n\n'
    'data: {"choices":[{"delta":{"tool_calls":['
    '{"index":0,"function":{"arguments":'
    '"{\\"command\\":\\"sleep 2 && echo KILL-A > a.txt\\"}"}},'
    '{"index":1,"function":{"arguments":'
    '"{\\"command\\":\\"sleep 2 && echo KILL-B > b.txt\\"}"}}'
    ']}}]}\n\n'
    'data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}\n\n'
    'data: {"choices":[],"usage":{"prompt_tokens":50,'
    '"completion_tokens":30}}\n\n'
    'data: [DONE]\n\n'
)

# 慢流模式（durable 演练用）：每 data 块写后 flush + sleep，给 kill -9
# 留流式中途的时间窗。OCC_MOCK_SLOW=秒（缺省 0=一次写）。
SLOW = float(os.environ.get("OCC_MOCK_SLOW", "0"))
TOOL_MODE = os.environ.get("OCC_MOCK_TOOL", "") == "1"
FAIL_N = int(os.environ.get("OCC_MOCK_FAIL_N", "0") or "0")
ALWAYS_FAIL = os.environ.get("OCC_MOCK_ALWAYS_FAIL", "") == "1"
FAIL_STATUS = int(os.environ.get("OCC_MOCK_FAIL_STATUS", "503") or "503")
BIND = os.environ.get("OCC_MOCK_BIND", "127.0.0.1")
LENGTH_FIRST = os.environ.get("OCC_MOCK_LENGTH_FIRST", "") == "1"
RETRY_AFTER = os.environ.get("OCC_MOCK_RETRY_AFTER", "")

# B1：OutputLimit 截断流（finish=length + 正文，无后续轮内容）
LENGTH_SSE = (
    'data: {"choices":[{"delta":{"role":"assistant","content":'
    '"LONGPART-A"}}]}\n\n'
    'data: {"choices":[{"delta":{},"finish_reason":"length"}]}\n\n'
    'data: {"choices":[],"usage":{"prompt_tokens":40,'
    '"completion_tokens":7}}\n\n'
    'data: [DONE]\n\n'
)

state = {"n": 0}
lock = threading.Lock()

DB_PATH = ""            # E9 回炉窗轮询库（argv[3]，可空=旧行为）


# ================= ORCH-E9 回路演练角色（仅测试，明标） =================

E9_MAIN_MARK = "ORCH-E9-主控"
E9_BRIEF_MARK = "【子智能体任务书（brief）】"
E9_REDRIVE_MARK = "E9-回炉整改"
E9_DELIVERABLE = "ORCH-E9-DELIVERABLE"
E9_ARTIFACT = "ORCH-E9-DELIVERABLE\n回路演练产物 v1\n"
E9_ARTIFACT_MD5 = hashlib.md5(E9_ARTIFACT.encode("utf-8")).hexdigest()
E9_TID_RE = re.compile(r'"task_id":"(tsk_[0-9a-f]+)"')

E9_ACCEPTANCE = [
    "file:out_e9.bin",
    "md5:out_e9.bin=" + E9_ARTIFACT_MD5,
    "contains:out_e9.bin:" + E9_DELIVERABLE,
]

E9_SPAWN_BRIEF = {
    "goal": "产出 out_e9.bin（内容含 " + E9_DELIVERABLE +
            " 标记）并交付带 # VERDICT 机械判表的最终报告",
    "fileset": ["out_e9.bin"],
    "forbidden": ["Makefile", "occ_core/", "occ_tools/"],
    "deliverables": ["out_e9.bin"],
    "acceptance": E9_ACCEPTANCE,
    "selfcheck": ["md5sum out_e9.bin 与验收标准 md5 一致"],
    "auth_note": "ORCH-E9 回路演练授权：只写 out_e9.bin 与任务结果文件",
    "budget": {"wall_ms": 120000, "max_tokens": 200000},
    "context": "ORCH-E9 回路自动化演练（headless 派发-验收-回炉-压缩-蒸馏）",
    "rework_max": 2,
}

E9_REPORT = (
    "# VERDICT\n"
    "| criterion | result | evidence | self |\n"
    "| file:out_e9.bin | pass | file:out_e9.bin | 产物在场 |\n"
    "| md5:out_e9.bin=" + E9_ARTIFACT_MD5 +
    " | pass | md5:out_e9.bin=" + E9_ARTIFACT_MD5 + " | md5 亲算一致 |\n"
    "| contains:out_e9.bin:" + E9_DELIVERABLE +
    " | pass | contains:out_e9.bin:" + E9_DELIVERABLE + " | 断言命中 |\n"
    "\n完成摘要：二报整改完成，产物 out_e9.bin 与本报告齐备，自检逐条通过。\n"
)

E9_CHILD1_TEXT = (
    "任务已完成：产物已就绪、自检全部通过。"
    "（ORCH-E9 子角色首报：自称完成，无证据行）"
)
E9_CHILD2_TEXT = (
    "整改完成：产物 out_e9.bin 与 # VERDICT 报告已写入指定文件。"
    "（ORCH-E9 子角色二报：真证据交付）"
)
E9_MAIN_FINAL = (
    "ORCH-E9 主控收队：任务一拒一改一过后 done，"
    "蒸馏归档与完成触发压缩均已走完。"
)

E9_JUDGE_JSON = (
    '{"task_finished":true,"impact":"low",'
    '"impact_reason":"ORCH-E9 回路演练收口，历史可归档",'
    '"safe_to_compress":true,'
    '"reason":"会话已 durable 落库，压缩不丢状态","confidence":"high"}'
)


def e9_digest_md(user_text):
    """ac 摘要角色：五必填章节 + ≥200 字 + 携带【会话材料】事实。"""
    m = re.search(r"【会话材料】(.*?)\n请基于上面的会话材料",
                  user_text, re.S)
    body = m.group(1) if m else user_text
    fact = "\n".join(ln.strip() for ln in body.splitlines()
                     if ln.strip())[:1200] or "（无材料）"
    text = (
        "## 目标\nORCH-E9 回路演练：派发-验收-回炉-压缩-蒸馏全回路"
        "（mock 主控视角收队摘要）。\n\n"
        "## 已完成\n" + fact + "\n\n"
        "## 未完成\n- （无——任务已 done）\n\n"
        "## 文件变更清单\n- out_e9.bin（子智能体二报产物）\n\n"
        "## 恢复指针\n- 会话库：OCC_DB（演练临时库）\n"
        "- 关键标记：" + E9_DELIVERABLE + "\n"
    )
    if len(text) < 220:
        text += "\n" + "（E9 摘要占位补充行）" * 8 + "\n"
    return text


def hold_until_in_review(tid):
    """E9 回炉窗：轮询库等再派终局（条件等待，上限 45s——上限 < occ
    LLM 传输 60s 读超时；到点放行交由演练断言兜底。普通连接只 SELECT
    ——WAL 读者需可写 -shm，mode=ro 会读不到最新状态）。"""
    if not DB_PATH or not tid:
        return
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        try:
            con = sqlite3.connect(DB_PATH)
            try:
                row = con.execute(
                    "SELECT status FROM occ_task WHERE id=?",
                    (tid,)).fetchone()
            finally:
                con.close()
            if row and row[0] == "in_review":
                return
        except sqlite3.Error:
            pass            # 库未建/瞬态锁——继续轮询
        time.sleep(0.3)


def e9_main_decide(msgs):
    """主控角色决策：按对话内 task 工具结果推进剧本。

    返回 (kind, tid)：kind ∈ spawn/wait/read_result/return_fail/
    return_pass/final。"""
    tool_texts = [m.get("content") or "" for m in msgs
                  if m.get("role") == "tool"]
    joined = "\n".join(tool_texts)
    tid_m = None
    for m in E9_TID_RE.finditer(joined):
        tid_m = m.group(1)          # 最后一次出现=最新任务
    if not tool_texts:
        return ("spawn", tid_m)
    last = tool_texts[-1]
    returned_fail = ('"action":"return"' in joined and
                     '"state":"rework"' in joined)
    if '"action":"return"' in last:
        if '"state":"done"' in last:
            return ("final", tid_m)
        if '"state":"rework"' in last:
            return ("wait_hold", tid_m)   # 回炉窗起点
        return ("final", tid_m)           # escalated 等异常——收队兜底
    if '"action":"read_result"' in last:
        if not returned_fail:
            return ("return_fail", tid_m)
        return ("return_pass", tid_m)
    if '"action":"wait"' in last:
        if '"task_state":"in_review"' in last:
            return ("read_result", tid_m)
        if '"done":false' in last:
            return ("wait", tid_m)        # 未终局——继续限时等
        # 回炉态回声（task_state=rework/dispatched）：等再派终局再催收
        return ("wait_hold", tid_m)
    if '"action":"spawn"' in last:
        return ("wait", tid_m)
    return ("final", tid_m)


def e9_tool_args(kind, tid):
    """主控角色的 task 工具调用参数（JSON 对象）。"""
    if kind == "spawn":
        return {"action": "spawn", "brief": E9_SPAWN_BRIEF}
    if kind == "wait":
        return {"action": "wait", "task_id": tid,
                "timeout_ms": 15000}
    if kind == "wait_hold":
        return {"action": "wait", "task_id": tid,
                "timeout_ms": 15000}
    if kind == "read_result":
        return {"action": "read_result", "task_id": tid}
    if kind == "return_fail":
        return {"action": "return", "task_id": tid, "pass": False,
                "verdict": "不通过：首报无 # VERDICT 机械判表、零机检"
                           "证据（自称完成不采信）——ORCH-E9 一拒"}
    if kind == "return_pass":
        return {"action": "return", "task_id": tid, "pass": True,
                "verdict": "机械判全过 + 抽查亲跑 md5 一致——ORCH-E9 "
                           "二报通过"}
    return None


def sse_text(text):
    """纯文本回复 SSE（两 delta + stop + usage + DONE——同 SSE 风格）。"""
    d1 = {"choices": [{"delta": {"role": "assistant",
                                 "content": text[:4]}}]}
    d2 = {"choices": [{"delta": {"content": text[4:]}}]}
    d3 = {"choices": [{"delta": {}, "finish_reason": "stop"}]}
    d4 = {"choices": [], "usage": {"prompt_tokens": 42,
                                   "completion_tokens": 8,
                                   "prompt_tokens_details":
                                       {"cached_tokens": 3}}}
    parts = [d1, d2, d3, d4]
    return "".join("data: " + json.dumps(p, ensure_ascii=False) + "\n\n"
                   for p in parts) + "data: [DONE]\n\n"


def sse_tool_calls(calls):
    """工具调用回复 SSE（calls=[(id,name,args_obj)]；两段 delta +
    finish=tool_calls + usage + DONE——同 TOOL_SSE 风格）。"""
    skel = [{"index": i, "id": c[0], "type": "function",
             "function": {"name": c[1], "arguments": ""}}
            for i, c in enumerate(calls)]
    args = [{"index": i,
             "function": {"arguments": json.dumps(
                 c[2], ensure_ascii=False, separators=(",", ":"))}}
            for i, c in enumerate(calls)]
    d1 = {"choices": [{"delta": {"role": "assistant",
                                 "tool_calls": skel}}]}
    d2 = {"choices": [{"delta": {"tool_calls": args}}]}
    d3 = {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]}
    d4 = {"choices": [], "usage": {"prompt_tokens": 50,
                                   "completion_tokens": 30}}
    parts = [d1, d2, d3, d4]
    return "".join("data: " + json.dumps(p, ensure_ascii=False) + "\n\n"
                   for p in parts) + "data: [DONE]\n\n"


def e9_route(req):
    """按请求内容选角色：返回 (role, extra) 或 None=旧行为。"""
    msgs = req.get("messages") or []
    sysm = ""
    user1 = ""
    for m in msgs:
        c = m.get("content")
        if isinstance(c, list):
            c = " ".join(p.get("text", "") for p in c
                         if isinstance(p, dict))
        c = c or ""
        if m.get("role") == "system" and not sysm:
            sysm = c
        elif m.get("role") == "user" and not user1:
            user1 = c
    if "会话压缩助手" in sysm:
        return ("ac_digest", user1)
    if "压缩判定助手" in sysm:
        return ("ac_judge", user1)
    if E9_REDRIVE_MARK in user1:
        return ("child2", user1)
    if E9_BRIEF_MARK in user1:
        return ("child1", user1)
    if E9_MAIN_MARK in user1:
        return ("main", msgs)
    return None


def e9_reply(role, extra):
    """角色 → SSE 载荷文本（main/child2 两拍剧本在调用方分支处理）。"""
    if role == "ac_judge":
        return sse_text(E9_JUDGE_JSON)
    if role == "ac_digest":
        return sse_text(e9_digest_md(extra))
    if role == "child1":
        return sse_text(E9_CHILD1_TEXT)
    return sse_text(E9_MAIN_FINAL)


# ---- mock autocondense REST（E5 压缩链消费；仅 E9 演练路径） ----

AC_BEGIN_BODY = {
    "mode": "full",
    "template": "## 目标\n\n## 已完成\n\n## 未完成\n\n"
                "## 文件变更清单\n\n## 恢复指针\n",
    "guidance": "逐节如实填写，内容必须来自会话材料",
    "required_sections": ["## 目标", "## 已完成", "## 未完成",
                          "## 文件变更清单", "## 恢复指针"],
}


def ac_route_log(tag):
    with lock:
        try:
            with open(os.path.join(REQ_DIR, "ac_routes.log"), "a",
                      encoding="utf-8") as f:
                f.write(tag + "\n")
        except OSError:
            pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # 静默（冒烟输出干净）

    def _send_bytes(self, status, ctype, payload):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, status, obj):
        self._send_bytes(status, "application/json; charset=utf-8",
                         json.dumps(obj, ensure_ascii=False)
                         .encode("utf-8"))

    # ---- mock autocondense REST ----
    def do_GET(self):
        if self.path.startswith("/check"):
            ac_route_log("check")
            self._json(200, {"should": "NO", "trigger": "none",
                             "urgency": "low",
                             "reason": "E9 演练：非 force 不触发水位压缩",
                             "signals": {"turns": 1},
                             "action_hint": "none"})
            return
        self.send_error(404)

    def _ac_post(self, body):
        if self.path.startswith("/session/start"):
            ac_route_log("session/start")
            self._json(200, {"session_id": "ses_e9"})
        elif self.path.startswith("/judge"):
            ac_route_log("judge")
            self._json(200, {"decision": "COMPRESS_NOW",
                             "urgency": "normal", "reason": "E9 force 判定"})
        elif self.path.startswith("/begin"):
            ac_route_log("begin")
            self._json(200, AC_BEGIN_BODY)
        elif self.path.startswith("/commit"):
            ac_route_log("commit")
            # E5 读回原子闸：digest 落真快照文件并回 snapshot_path
            digest = ""
            try:
                j = json.loads(body.decode("utf-8", "replace"))
                digest = j.get("digest_md") or ""
            except Exception:
                pass
            snap = os.path.join(REQ_DIR, "ac_snapshot.md")
            with open(snap, "w", encoding="utf-8") as f:
                f.write(digest.replace("\\n", "\n"))
            self._json(200, {"ok": True, "snapshot_path": snap,
                             "segments_written": 0,
                             "sme": {"stored": False}})
        else:
            self._json(404, {"errors": [{"msg": "nope"}]})

    def do_POST(self):
        if not self.path.endswith("/chat/completions"):
            # E9：同端口承载 mock autocondense REST
            if (self.path.startswith("/session/start") or
                    self.path.startswith("/judge") or
                    self.path.startswith("/begin") or
                    self.path.startswith("/commit")):
                length = int(self.headers.get("Content-Length", "0"))
                self._ac_post(self.rfile.read(length))
                return
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with lock:
            state["n"] += 1
            n = state["n"]
            with open(f"{REQ_DIR}/req_{n}.json", "wb") as f:
                f.write(body)

        # ---- ORCH-E9 角色分流（内容命中才接管；否则旧行为不变） ----
        try:
            req = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            req = {}
        routed = e9_route(req) if req else None
        if routed:
            role, extra = routed
            with lock:
                try:
                    with open(os.path.join(REQ_DIR, "roles.log"), "a",
                              encoding="utf-8") as f:
                        f.write("%d %s\n" % (n, role))
                except OSError:
                    pass
            if role == "main":
                kind, tid = e9_main_decide(extra)
                if kind == "wait_hold":
                    # 回炉窗有界：>6 轮仍非 in_review=再派侧异常——
                    # 收队兜底退出（演练断言如实报 FAIL，绝不死循环）
                    with lock:
                        state["wait_hold"] = state.get("wait_hold", 0) + 1
                        n_hold = state["wait_hold"]
                    if n_hold > 6:
                        payload_s = sse_text(E9_MAIN_FINAL)
                    else:
                        hold_until_in_review(tid)
                        payload_s = sse_tool_calls(
                            [("call_e9m%d" % n, "task",
                              e9_tool_args("wait", tid))])
                elif kind == "final":
                    payload_s = sse_text(E9_MAIN_FINAL)
                else:
                    payload_s = sse_tool_calls(
                        [("call_e9m%d" % n, "task",
                          e9_tool_args(kind, tid))])
            elif role == "child2":
                rf_m = re.search(r"结果文件：(\S+)", extra or "")
                has_tool = any(m.get("role") == "tool"
                               for m in (req.get("messages") or []))
                if has_tool or not rf_m:
                    payload_s = sse_text(
                        E9_CHILD2_TEXT if rf_m else
                        "E9 子角色二报失败：结果文件路径缺失（演练夹具错）")
                else:
                    payload_s = sse_tool_calls([
                        ("call_e9w1", "write",
                         {"path": "out_e9.bin", "content": E9_ARTIFACT}),
                        ("call_e9w2", "write",
                         {"path": rf_m.group(1), "content": E9_REPORT}),
                    ])
            else:
                payload_s = e9_reply(role, extra)
            self._send_bytes(200, "text/event-stream",
                             payload_s.encode("utf-8"))
            return

        # ---- 注入失败（重试演练；请求仍计数/落盘） ----
        if ALWAYS_FAIL or n <= FAIL_N:
            err = json.dumps(
                {"error": {"message": "mock injected failure"}},
                ensure_ascii=False,
            ).encode("utf-8")
            if RETRY_AFTER:
                # B4：失败响应附 Retry-After 头（值原样）
                self.send_response(FAIL_STATUS)
                self.send_header("Content-Type",
                                 "application/json; charset=utf-8")
                self.send_header("Retry-After", RETRY_AFTER)
                self.send_header("Content-Length", str(len(err)))
                self.end_headers()
                self.wfile.write(err)
            else:
                self._send_bytes(FAIL_STATUS,
                                 "application/json; charset=utf-8", err)
            return

        if TOOL_MODE and n == 1:
            payload_s = TOOL_SSE
        elif LENGTH_FIRST and n == 1:
            payload_s = LENGTH_SSE
        else:
            payload_s = SSE
        payload = payload_s.encode("utf-8")

        if SLOW > 0:
            # 分块发送：先回 200 头，再逐块 flush+sleep（kill 窗口）
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                for chunk in payload_s.split("\n\n"):
                    if chunk:
                        self.wfile.write((chunk + "\n\n").encode("utf-8"))
                        self.wfile.flush()
                        time.sleep(SLOW)
            except (BrokenPipeError, ConnectionResetError):
                pass  # 客户端 kill -9 断连（durable 演练预期路径）
        else:
            self._send_bytes(200, "text/event-stream", payload)


if __name__ == "__main__":
    port = int(sys.argv[1])
    REQ_DIR = sys.argv[2]
    if len(sys.argv) > 3:
        DB_PATH = sys.argv[3]
    ThreadingHTTPServer((BIND, port), Handler).serve_forever()
