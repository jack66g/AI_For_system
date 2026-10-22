#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
mock_ollama.py - E2E 确定性 mock 推理服务（OpenAI /v1/chat/completions 兼容）

用途：Ollama 模型下载未完成时，验证 ask 工具闭环机制本身
（tools 协议 / tool_calls 解析 / 执行器路由 / role:tool 回填 / 终止条件），
与具体模型解耦。

固定脚本（按请求中出现 "role":"tool" 的次数推进阶段）：
  第 0 轮           -> tool_calls: exec.run({"command":"free","args":["-m"]})
  第 1 轮（有结果） -> tool_calls: memory.add({"text":...})
  第 2 轮（有结果） -> 最终文本回答

场景路由（按用户任务文本关键词）：
  默认       exec.run(free) -> memory.add -> 最终回答
  遥测       procfs.read.status -> 最终回答（QEMU guest procfs-read 通道）
  swappiness netlink.act.mm.swappiness(40) -> 最终回答（netlink-act 全局参数）
  nice       netlink.act.sched.nice(pid=1,5) -> 最终回答（netlink-act 任务参数）
  降级       纯文本 {"tool":...} -> {"answer":...}（文本 JSON 约定降级协议）
  回忆       memory.search("NETLINK_AI netlink 接口") -> 最终回答（SME 命中）

用法：python3 mock_ollama.py [port]   （默认 11434；请求原文记 /tmp/mock_ollama.log）
注意：宿主机真实 Ollama 常驻 11434 时，请用 11435 起 mock
（如 `python3 mock_ollama.py 11435`），两端口语义仅在配置层区分。
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 11434
LOG = open("/tmp/mock_ollama.log", "a", encoding="utf-8")


def resp_tool(call_id, name, args):
    """原生 tool_calls 响应（finish_reason=tool_calls）"""
    return {"id": "chatcmpl-mock", "object": "chat.completion", "created": 0,
            "model": "mock", "choices": [{"index": 0, "finish_reason": "tool_calls",
            "message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": call_id, "type": "function",
                 "function": {"name": name,
                              "arguments": json.dumps(args, ensure_ascii=False)}}]}}]}


def resp_text(text):
    """最终文本回答（finish_reason=stop）"""
    return {"id": "chatcmpl-mock", "object": "chat.completion", "created": 0,
            "model": "mock", "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": text}}]}


def user_question(body):
    """提取用户的原始问题：最后一条不以 '[TOOL' 开头的 user 消息。

    不能对整个请求体做关键词匹配——system prompt 的工具清单里就有
    "遥测"等字样，会误触发场景路由；降级模式下工具结果也伪装成
    user 消息（前缀 [TOOL ... RESULT]），同样要排除。
    """
    q = ""
    try:
        for m in json.loads(body).get("messages", []):
            if m.get("role") != "user":
                continue
            c = m.get("content") or ""
            if c.startswith("[TOOL"):
                continue
            q = c
    except Exception:
        pass
    return q


def user_task(body):
    """提取用户的任务文本（场景路由依据）。

    cmd_ask 把上下文注入（遥测摘要/SME 记忆命中）拼在任务文本**前面**，
    以"用户任务："标记分隔——上下文里可能出现"遥测"等关键词，若连同
    上下文一起匹配会误路由（比如 swappiness 任务的记忆命中里有
    "遥测"字样），所以只取标记之后的任务本身。
    """
    q = user_question(body)
    marker = "用户任务："
    idx = q.rfind(marker)
    return q[idx + len(marker):] if idx >= 0 else q


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        LOG.write(body + "\n===\n")
        LOG.flush()

        # 阶段推进：原生路径数 role:tool 消息；降级路径工具结果伪装成
        # user 消息（前缀 "[TOOL "），也要计入
        stage = body.count('"role":"tool"') + body.count('[TOOL ')
        # 用户任务文本（场景路由只看它，见 user_task 注释）
        question = user_task(body)

        def reply(out):
            data = json.dumps(out, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        # 场景三（内核遥测，QEMU guest）：procfs.read.status → 最终回答
        if "遥测" in question:
            if stage == 0:
                reply(resp_tool("call_t1", "procfs.read.status", {}))
            else:
                reply(resp_text("已通过 procfs-read 通道读取 /proc/ai/status，"
                                "内核 AI 子系统状态见上方工具结果（真实内核"
                                "链路）：enabled=1，决策与遥测通道均在线。"))
            return
        # 场景四（内核 ACT 全局参数，QEMU guest）：netlink.act.mm.swappiness
        if "swappiness" in question:
            if stage == 0:
                reply(resp_tool("call_n1", "netlink.act.mm.swappiness",
                                {"value": 40}))
            else:
                reply(resp_text("已通过 netlink-act 通道调用 NETLINK_AI ACT "
                                "把 mm.swappiness 设为 40（真实内核链路）。"))
            return
        # 场景六（内核 ACT 任务参数，QEMU guest）：netlink.act.sched.nice
        # 对 pid 1 下发（data[0]=pid, data[1]=value；init 以 root 运行，
        # CAP_SYS_ADMIN 满足内核侧权限检查）
        if "nice" in question:
            if stage == 0:
                reply(resp_tool("call_n2", "netlink.act.sched.nice",
                                {"pid": 1, "value": 5}))
            else:
                reply(resp_text("已通过 netlink-act 通道对 pid 1 下发 "
                                "sched.nice=5（NETLINK_AI ACT，真实内核"
                                "执行链路）。"))
            return
        # 场景五（降级文本 JSON 协议）：模型完全不用 tools 字段，第一轮
        # 回纯文本 {"tool":...}，第二轮回 {"answer":...}——验证
        # ai_chat_parse_text_toolcall 的两种解析与自动降级切换
        if "降级" in question:
            if stage == 0:
                reply(resp_text('{"tool":"exec.run",'
                                '"arguments":{"command":"uptime"}}'))
            else:
                reply(resp_text('{"answer":"降级（文本 JSON 约定）闭环验证'
                                '完成：已用 exec.run(uptime) 查询系统运行'
                                '时长。"}'))
            return
        # 场景二（回忆）：问题含"回忆"时走 memory.search 链路
        if "回忆" in question:
            if stage == 0:
                # 检索词指向 SME 预置的接口文档语料，验证真实命中
                reply(resp_tool("call_s1", "memory.search",
                                {"text": "NETLINK_AI netlink 接口",
                                 "top_k": 3}))
            else:
                reply(resp_text("根据 SME memory.search 命中的记录回答："
                                "之前记录过本机总内存（free -m 实测）。"
                                "检索命中见上方工具结果。"))
            return
        # 场景一（记录）：exec.run → memory.add → 最终回答
        if stage == 0:
            reply(resp_tool("call_1", "exec.run",
                            {"command": "free", "args": ["-m"]}))
        elif stage == 1:
            reply(resp_tool("call_2", "memory.add", {
                "text": "E2E 验证记录：本机总内存约 992 MiB（free -m 实测）",
                "metadata": "{\"src\":\"mock-e2e\"}"}))
        else:
            reply(resp_text("闭环验证完成：已用 exec.run(free -m) 读取内存，"
                            "并把结果写入 SME 记忆（memory.add），"
                            "total≈992 MiB。"))


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
