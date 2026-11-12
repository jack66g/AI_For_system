#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""K2b /act ops 批量面单测（mock netlink，无内核/VM 依赖）。

覆盖（KERNEL-K2-DESIGN D9）：
  - nl_pack_act_batch 嵌套 NLA 黄金字节（与客户端库/C 孪生逐字节一致）
  - nl_unpack_batch_ack 解包边界
  - validate_act_ops 四形态（全参/缺 value/超 27/重复名）+ 404/task-pid
  - HTTP /act ops：互斥 400、confirm 门 409、blast 拒 428（token 二段流
    放行）、ai_err 502、executed=0 409、成功 200 聚合响应（pre/post/
    clamped）
  - 单 param 旧路径响应逐字节回归（冻结红线：v2.vectors 409 体同形）
"""
import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

TOKEN = "test-token"
FAILS = []
PASSES = []


def check(name, cond, detail=""):
    if cond:
        PASSES.append(name)
        print("PASS: " + name)
    else:
        FAILS.append(name)
        print("FAIL: " + name + (("  [" + str(detail) + "]") if detail else ""))


def load_api(api_path):
    loader = importlib.machinery.SourceFileLoader("aikernel_api_batch_t",
                                                  str(api_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def http_raw(port, path, body, token=TOKEN, timeout=30):
    data = json.dumps(body, ensure_ascii=False).encode()
    headers = {"Content-Type": "application/json",
               "Authorization": "Bearer " + token}
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
                                 data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def http(port, path, body):
    code, text = http_raw(port, path, body)
    try:
        return code, json.loads(text)
    except ValueError:
        return code, {}


CONTROL_FIXTURE = (
    "mm.swappiness domain=2 [real] min=0 max=200 current=60 default=60\n"
    "llm.top_k domain=4 [real] min=0 max=100 current=40 default=40\n"
    "sched.nice domain=1 [real] min=-20 max=19 current=0 default=0\n"
    "proc.freeze domain=12 [real] min=0 max=1 current=0 default=0\n"
)


def fake_ack(**kw):
    base = {"executed": 2, "hit": 1, "ai_err": 0, "decision_id": 77,
            "trace_hi": 0xAA, "trace_lo": 5, "first_fail": -1,
            "blast_radius": 2, "token": 0}
    base.update(kw)
    return base


def main():
    base = Path(tempfile.mkdtemp(prefix="k2b-act-batch-"))
    home = base / "home"
    home.mkdir()
    (home / ".aikernel").mkdir()
    (home / ".aikernel" / "model.toml").write_text(
        "[api]\ntoken = \"%s\"\n" % TOKEN, encoding="utf-8")
    os.environ["HOME"] = str(home)

    api_path = Path(__file__).resolve().parent.parent / "api" / "aikernel-api"
    api = load_api(api_path)
    api.AUDIT_LOG = str(base / "audit.log")
    api.TOKEN_FILE = str(base / "api-token")
    api.TOML_FILE = str(home / ".aikernel" / "model.toml")
    api.CONTROL_PROC = str(base / "control")
    Path(api.CONTROL_PROC).write_text(CONTROL_FIXTURE, encoding="utf-8")

    # ---- 纯函数：打包黄金字节（140B；C 孪生/客户端库同字节） ----
    b = api.nl_pack_act_batch([("mm.swappiness", 60, 0),
                               ("sched.nice", 19, 4242)],
                              auto_rollback_ms=5000,
                              confirm_token=0xdeadbeef)
    check("pack_golden_len", len(b) == 140, len(b))
    check("pack_golden_hex",
          b.hex() ==
          "24000180120003006d6d2e7377617070696e6573730000000c000e00"
          "3c00000000000000280001800f00030073636865642e6e69636500000c"
          "000e00130000000000000008000f009210000008000200881300000c"
          "000300efbeadde000000000c00080000000000000000000c000900000"
          "00000000000000c000a00000000000000000008000c0000000000",
          b.hex())
    b0 = api.nl_pack_act_batch([("llm.top_k", 40, 0)])
    check("pack_single_op_len", len(b0) == 96, len(b0))
    check("pack_single_op_tail",
          b0.hex().endswith("0c000a00000000000000000008000c0000000000"),
          b0.hex()[-40:])

    # ---- 纯函数：ack 解包 ----
    ackb = (bytes([2, 1]) + b"\x00\x00" +
            (11).to_bytes(4, "little", signed=True) +
            (77).to_bytes(8, "little") + (1).to_bytes(8, "little") +
            (2).to_bytes(8, "little") + (-1).to_bytes(4, "little",
                                                      signed=True) +
            (5).to_bytes(4, "little") + (0x1234).to_bytes(8, "little"))
    ack = api.nl_unpack_batch_ack(ackb)
    check("ack_unpack", ack == {"executed": 2, "hit": 1, "ai_err": 11,
                                "decision_id": 77, "trace_hi": 1,
                                "trace_lo": 2, "first_fail": -1,
                                "blast_radius": 5,
                                "token": 0x1234}, ack)
    check("ack_unpack_short", api.nl_unpack_batch_ack(ackb[:40]) is None)

    # ---- 纯函数：validate 四形态 ----
    params = api.parse_control(CONTROL_FIXTURE)
    code, msg, norm = api.validate_act_ops(
        params, [{"param": "mm.swappiness", "value": "0x3c"},
                 {"param": "sched.nice", "value": 19, "pid": "4242"}])
    check("val_ok", code is None and
          norm == [("mm.swappiness", 60, 0), ("sched.nice", 19, 4242)],
          (code, msg, norm))
    code, msg, _ = api.validate_act_ops(
        params, [{"param": "mm.swappiness"}])
    check("val_missing_value", code == 400 and msg == "value 必须是整数",
          (code, msg))
    code, msg, _ = api.validate_act_ops(
        params, [{"param": "llm.top_k", "value": 1}] * 28)
    check("val_over_27", code == 400 and msg == "ops 项数超出 [1, 27]",
          (code, msg))
    code, msg, _ = api.validate_act_ops(
        params, [{"param": "llm.top_k", "value": 1},
                 {"param": "llm.top_k", "value": 2}])
    check("val_dup", code == 400 and "重复" in msg, (code, msg))
    code, msg, _ = api.validate_act_ops(
        params, [{"param": "nope.param", "value": 1}])
    check("val_unknown_404", code == 404, (code, msg))
    code, msg, _ = api.validate_act_ops(
        params, [{"param": "sched.nice", "value": 19}])
    check("val_task_no_pid", code == 400 and "pid" in msg, (code, msg))
    code, msg, _ = api.validate_act_ops(params, "oops")
    check("val_not_list", code == 400, (code, msg))

    # ---- HTTP 面 ----
    calls = {}

    def fake_nl_act_batch(ops, auto_rollback_ms=0, confirm_token=0,
                          timeout=5.0):
        calls["ops"] = ops
        calls["rollback"] = auto_rollback_ms
        calls["token"] = confirm_token
        return fake_ack(), None

    api.nl_act_batch = fake_nl_act_batch
    api.read_blast_threshold = lambda: 64

    def fake_nl_act(param, value, pid, timeout=5.0):
        calls["single"] = (param, value, pid)
        return {"executed": 1, "hit": 1, "ai_err": 0}, None

    api.nl_act = fake_nl_act

    srv = api.Server(("127.0.0.1", 0), api.Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    port = srv.server_address[1]
    try:
        # 互斥
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 1}],
                           "param": "llm.top_k", "value": 1,
                           "confirm": True})
        check("exclusive_400", code == 400 and
              body.get("error") == "ops_exclusive", (code, body))
        # 缺 value / 重复 / 超 27（invalid_ops 三形态）
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k"}],
                           "confirm": True})
        check("ops_missing_value_400",
              code == 400 and body.get("error") == "invalid_ops" and
              body.get("message") == "value 必须是整数", (code, body))
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 1},
                                   {"param": "llm.top_k", "value": 2}],
                           "confirm": True})
        check("ops_dup_400", code == 400 and "重复" in body.get("message", ""),
              (code, body))
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 1}] * 28,
                           "confirm": True})
        check("ops_over27_400", code == 400 and
              body.get("message") == "ops 项数超出 [1, 27]", (code, body))
        code, body = http(port, "/act",
                          {"ops": [{"param": "nope", "value": 1}],
                           "confirm": True})
        check("ops_unknown_404", code == 404 and
              body.get("error") == "unknown_param", (code, body))
        # auto_rollback_ms / confirm_token 型别门
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 1}],
                           "auto_rollback_ms": 600001, "confirm": True})
        check("rollback_max_400", code == 400 and
              body.get("error") == "invalid_auto_rollback_ms", (code, body))
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 1}],
                           "confirm_token": "zz", "confirm": True})
        check("token_str_bad_400", code == 400 and
              body.get("error") == "invalid_confirm_token", (code, body))
        # confirm 门（409 新形态：ops 回显）
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 40},
                                   {"param": "sched.nice", "value": 19,
                                    "pid": 4242}],
                           "auto_rollback_ms": 3000})
        check("need_confirm_409", code == 409 and
              body.get("code") == "NEED_CONFIRM" and
              body.get("ops") == [
                  {"param": "llm.top_k", "value": 40, "pid": None},
                  {"param": "sched.nice", "value": 19, "pid": 4242}] and
              body.get("auto_rollback_ms") == 3000, (code, body))
        # blast 拒 → 428；二段流 confirm_token 放行 → 200
        state = {"phase": 0}

        def fake_blast(ops, auto_rollback_ms=0, confirm_token=0,
                       timeout=5.0):
            if state["phase"] == 0:
                state["phase"] = 1
                return (fake_ack(ai_err=-11, token=0xBEAF,
                                 blast_radius=120, executed=0, hit=0),
                        None)
            calls["token"] = confirm_token
            return fake_ack(executed=2, blast_radius=120, token=0), None

        api.nl_act_batch = fake_blast
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 40},
                                   {"param": "sched.nice", "value": 19,
                                    "pid": 4242}],
                           "confirm": True})
        check("blast_428", code == 428 and
              body.get("error") == "BLAST_RADIUS" and
              body.get("blast_radius") == 120 and
              body.get("confirm_token") == 0xBEAF and
              body.get("threshold") == 64 and
              "confirm_token" in body.get("message", ""), (code, body))
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 40},
                                   {"param": "sched.nice", "value": 19,
                                    "pid": 4242}],
                           "confirm": True, "confirm_token": 0xBEAF})
        check("blast_second_pass_200", code == 200 and
              calls["token"] == 0xBEAF and body.get("ok") is True, (code, body))
        # 200 聚合响应形态（pre/post/clamped/decision_id/trace_id）
        check("agg_keys",
              list(body.keys()) == ["ok", "decision_id", "trace_id",
                                    "executed", "items", "first_fail",
                                    "rolled_back", "blast_radius"],
              list(body.keys()))
        check("agg_trace_id", body["trace_id"] == "0x%016x:0x%016x" % (0xAA, 5),
              body.get("trace_id"))
        check("agg_items",
              body["items"] == [
                  {"param": "llm.top_k", "pre": 40, "post": 40,
                   "clamped": False},
                  {"param": "sched.nice", "pre": 0, "post": 0,
                   "clamped": True}],
              body.get("items"))
        # ai_err 失败 → 502 + first_fail
        api.nl_act_batch = lambda ops, **kw: (
            fake_ack(ai_err=-5, executed=0, hit=0, first_fail=1), None)
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 40},
                                   {"param": "mm.swappiness", "value": 80}],
                           "confirm": True})
        check("ai_err_502", code == 502 and
              body.get("error") == "kernel_rejected" and
              body.get("first_fail") == 1 and
              body.get("decision_id") == 77 and
              body.get("executed") == 0, (code, body))
        # executed=0 → 409 not_applied
        api.nl_act_batch = lambda ops, **kw: (
            fake_ack(executed=0, hit=0), None)
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 40}],
                           "confirm": True})
        check("not_applied_409", code == 409 and
              body.get("error") == "not_applied", (code, body))
        # nl 传输失败 → 502
        api.nl_act_batch = lambda ops, **kw: (None, "netlink socket: boom")
        code, body = http(port, "/act",
                          {"ops": [{"param": "llm.top_k", "value": 40}],
                           "confirm": True})
        check("nl_err_502", code == 502 and
              body.get("message") == "netlink socket: boom", (code, body))

        # ---- 单 param 旧路径逐字节回归（冻结红线） ----
        code, text = http_raw(port, "/act",
                              {"param": "llm.top_k", "value": 40,
                               "confirm": True})
        expected = json.dumps(
            {"ok": True, "param": "llm.top_k", "value": 40, "pid": None,
             "executed": 1, "hit": 1, "current_before": 40,
             "current_after": 40}, ensure_ascii=False)
        check("single_param_bytes", code == 200 and text == expected,
              (code, text))
        code, text = http_raw(port, "/act",
                              {"param": "llm.top_k", "value": 40})
        expected409 = json.dumps(
            {"error": "need_confirm",
             "message": "受控写需显式确认：重发并带 \"confirm\": true",
             "code": "NEED_CONFIRM", "param": "llm.top_k", "value": 40,
             "pid": None, "current": 40, "min": 0, "max": 100,
             "default": 40, "task_scoped": False}, ensure_ascii=False)
        check("single_param_409_bytes", code == 409 and text == expected409,
              (code, text))
    finally:
        srv.shutdown()
        srv.server_close()

    print("\ntest_api_act_batch: %d pass, %d fail" % (len(PASSES),
                                                       len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
