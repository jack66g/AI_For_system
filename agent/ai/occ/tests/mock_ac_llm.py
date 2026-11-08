#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mock_ac_llm.py - T9d ac 换窗演示用本地 mock LLM（**仅测试，明标**）

一个端口同时扮演三种角色，按请求里 system 的内容分流：
  1) 普通对话（system = occ 系统提示）  → 回一句确认收到的 SSE
  2) ac 判定表（system = ac 填表提示 + 用户含「压缩判定表」）
                                           → 输出判定 JSON（safe/finished/low）
  3) ac 摘要（system = ac 填表提示）      → 输出含全部必填章节的 markdown，
                                              并把【会话材料】里的事实原样
                                              带进摘要（换窗保留关键事实的
                                              机制演示——真模型同理）

请求计数落 <dir>/reqs.log（每行序号+角色），供演示核账。
用法: mock_ac_llm.py <port> <dir>
"""
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 0
DIR = sys.argv[2] if len(sys.argv) > 2 else "/tmp"
N = [0]

JUDGE_JSON = (
    '{"task_finished":true,"impact":"low",'
    '"impact_reason":"本批任务已收口，历史可归档",'
    '"safe_to_compress":true,'
    '"reason":"会话已 durable 落库，压缩不丢状态","confidence":"high"}'
)

DIGEST_TMPL = """## 目标
{goal}

## 已完成
{done}

## 未完成
- （无）

## 文件变更清单
- （本演示未改文件）

## 恢复指针
- transcript: ~/.occ/sessions/<id>.jsonl
- 关键事实：{fact}
"""


def material_of(text):
    """从填表 prompt 的【会话材料】段抽事实行（mock 版「读会话」）。"""
    m = re.search(r"【会话材料】.*?\n(.*?)\n请基于上面的会话材料",
                  text, re.S)
    if not m:
        m = re.search(r"【会话材料（截断）】\n(.*?)\n最近一次回复",
                      text, re.S)
    body = m.group(1) if m else text
    lines = [ln for ln in body.splitlines() if ln.strip()]
    return body, lines


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _sse(self, chunks, finish="stop"):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for c in chunks:
            payload = {
                "choices": [{"delta": {"content": c}}],
                "model": "mock-ac",
            }
            self.wfile.write(
                ("data: " + json.dumps(payload, ensure_ascii=False) + "\n\n")
                .encode("utf-8"))
            self.wfile.flush()
        done = {
            "choices": [{"delta": {}, "finish_reason": finish}],
            "model": "mock-ac",
        }
        self.wfile.write(
            ("data: " + json.dumps(done, ensure_ascii=False) + "\n\n")
            .encode("utf-8"))
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def do_GET(self):
        if self.path.startswith("/v1/models"):
            body = json.dumps({"data": [{"id": "mock-ac"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        ln = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(ln).decode("utf-8", "replace")
        try:
            req = json.loads(raw)
        except Exception:
            req = {}
        sysm = ""
        user = ""
        for m in req.get("messages", []):
            c = m.get("content")
            if isinstance(c, list):
                c = " ".join(
                    p.get("text", "") for p in c if isinstance(p, dict))
            c = c or ""
            if m.get("role") == "system":
                sysm += c
            elif m.get("role") == "user":
                user += c + "\n"

        role = "chat"
        if "会话压缩助手" in sysm or "压缩判定" in sysm:
            if "压缩判定表" in user:
                role = "judge"
                chunks = [JUDGE_JSON]
            else:
                role = "digest"
                body, lines = material_of(user)
                fact = "\n".join(lines[:40]) or "（无）"
                goal = "把本会话压缩成可恢复摘要（T9d 换窗演示）"
                done = fact
                text = DIGEST_TMPL.format(goal=goal, done=done, fact=fact)
                # ac 要求 ≥200 字符
                if len(text) < 200:
                    text += "\n" + "（占位）" * 40
                chunks = [text]
        else:
            chunks = [
                "收到：你让我记住的内容我已记下。"
                "（本回复来自本地 mock LLM，仅用于 T9d 演示，非真模型）"
            ]

        N[0] += 1
        try:
            with open(os.path.join(DIR, "reqs.log"), "a",
                      encoding="utf-8") as f:
                f.write("%d %s\n" % (N[0], role))
        except OSError:
            pass
        self._sse(chunks)


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print("mock_ac_llm listening %d" % srv.server_address[1], flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
