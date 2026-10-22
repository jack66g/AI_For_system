#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# AIKernel IMG-1: AI-first 桌面 Web Demo 后端
# W76: 仅监听 127.0.0.1:8091(桌面控制面不进 LAN;远程查看走 SSH 端口转发)。
# 红线:不碰 8080/9999/9443 端口的既有进程;api_key 只在运行时从
# ~/.aikernel/model.toml 读取,绝不写日志、绝不回传给前端。
# W76 桌面 API:windows/apps launch+close/input/screenshot/clipboard 均只接受
# 固定形状 JSON,不执行任意 JS/命令;写操作由 Agent 侧 desktop_* 工具经
# ai_lease_gate 做 D0-D3 分级。

import hashlib
import json
import mimetypes
import os
import random
import re
import shutil
import socketserver
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
# W76b: 运行期可写状态根(theme/desktop/notifs/pin/chats/screenshots/icons)。
# Factory unit 设置 AIK_DESKTOP_ROOT=/var/lib/aikdesktop; 未设置时回落 demo data/。
STATE_ROOT = os.path.abspath(
    os.environ.get("AIK_DESKTOP_ROOT", "").strip()
    or os.path.join(BASE_DIR, "data"))
THEME_FILE = os.path.join(STATE_ROOT, "theme.json")
THEME_SEED = os.path.join(BASE_DIR, "theme.json")
LOCALE_FILE = os.path.join(BASE_DIR, "locales", "zh_CN.json")
WALLPAPER_DIR = os.path.join(STATIC_DIR, "wallpapers")
CHAT_DIR = os.path.join(STATE_ROOT, "chats")
PIN_FILE = os.path.join(STATE_ROOT, "pin.json")
NOTIF_FILE = os.path.join(STATE_ROOT, "notifs.json")
DESKTOP_FILE = os.path.join(STATE_ROOT, "desktop.json")
SCREENSHOT_DIR = os.path.join(STATE_ROOT, "screenshots")
VERSION = "IMG-7-W76b"
START_TS = time.strftime("%Y-%m-%d %H:%M:%S")
APPS_DIR = os.environ.get(
    "AIK_DESKTOP_APPS_DIR", "/usr/share/applications").strip()
ICON_ROOT = os.path.join(STATE_ROOT, "icons")
ICON_OUT_DIR = os.path.join(ICON_ROOT, "apps")
GEN_ICON_DIR = os.path.join(STATIC_DIR, "icons", "gen")
CATALOG_FILE = os.path.join(BASE_DIR, "data", "apps-catalog.json")
RESERVED_PORTS = {8000, 8080, 8761, 9443, 9999, 11434}


def _env_port():
    try:
        port = int(os.environ.get("AIK_DESKTOP_PORT", "8091"))
    except ValueError:
        raise SystemExit("AIK_DESKTOP_PORT 必须是整数")
    if not (1 <= port <= 65535):
        raise SystemExit("AIK_DESKTOP_PORT 越界: %d" % port)
    if port in RESERVED_PORTS:
        raise SystemExit(
            "AIK_DESKTOP_PORT=%d 与 AIKernel 既有端口冲突" % port)
    return port


def _env_bind():
    host = os.environ.get("AIK_DESKTOP_BIND", "127.0.0.1").strip()
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("AIK_DESKTOP_BIND 只允许 loopback: %r" % host)
    return host


PORT = _env_port()
BIND_HOST = _env_bind()
# W76b: factory/VM 默认不启用 L1 专用 SSH 隧道(18761 -> 138:8761)。
VM_ENABLED = os.environ.get("AIK_DESKTOP_VM", "0").strip().lower() not in (
    "0", "false", "no", "off", "disabled")
VM_DISABLED_REASON = "vm_unavailable: local desktop only (AIK_DESKTOP_VM=0)"
# W76b: factory unit 显式设 0 -> /api/screenshot 503, health=unavailable。
SCREENSHOT_MODE = os.environ.get(
    "AIK_DESKTOP_SCREENSHOT", "auto").strip().lower()

LLM_TIMEOUT = 25.0          # 云端 LLM 单次尝试超时(秒)
FALLBACK_DEADLINE = 15.0    # 降级路径整体预算(秒)

_log_lock = threading.Lock()


def log(msg):
    with _log_lock:
        sys.stdout.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
        sys.stdout.flush()


def _chmod600(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_state_json(path, obj):
    """原子写运行期 JSON;状态文件一律 0600。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def ensure_state():
    """创建可写状态根并种入 factory 默认值(幂等;不写只读 /opt)。"""
    os.makedirs(STATE_ROOT, exist_ok=True)
    try:
        os.chmod(STATE_ROOT, 0o700)
    except OSError:
        pass
    for d in (CHAT_DIR, SCREENSHOT_DIR, ICON_ROOT, ICON_OUT_DIR):
        os.makedirs(d, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    seeds = (
        (THEME_SEED, THEME_FILE, None),
        (os.path.join(BASE_DIR, "data", "notifs.json"), NOTIF_FILE, []),
        (os.path.join(BASE_DIR, "data", "desktop.json"), DESKTOP_FILE,
         {"mode": "ai", "windows": [], "next_id": 1, "z": 1,
          "clipboard": "", "clipboard_updated": None}),
        (os.path.join(BASE_DIR, "data", "pin.json"), PIN_FILE,
         {"enabled": False}),
    )
    for src, dst, default in seeds:
        if os.path.exists(dst):
            _chmod600(dst)
            continue
        if os.path.isfile(src):
            shutil.copyfile(src, dst)
        else:
            write_state_json(dst, default if default is not None else {})
        _chmod600(dst)
    try:
        for fn in os.listdir(CHAT_DIR):
            p = os.path.join(CHAT_DIR, fn)
            if os.path.isfile(p):
                _chmod600(p)
    except OSError:
        pass


# ---------------------------------------------------------------- model.toml
def read_model_conf():
    """运行时读取 ~/.aikernel/model.toml 的 [models.cloud] 段。
    只在内存中持有 api_key,不落日志。Python 3.10 无 tomllib,手解析三字段。"""
    conf = {"base_url": None, "api_key": None, "model_name": None}
    path = os.path.expanduser("~/.aikernel/model.toml")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
        m = re.search(r"\[models\.cloud\]([^\[]*)", txt, re.S)
        seg = m.group(1) if m else txt
        for k in ("base_url", "api_key", "model_name"):
            mm = re.search(r'^\s*%s\s*=\s*["\']?([^"\'\n#]+)' % k, seg, re.M)
            if mm:
                conf[k] = mm.group(1).strip()
    except Exception as e:
        log("model.toml 读取失败: %s" % type(e).__name__)
    return conf


def llm_endpoint(base_url):
    """由 base_url 拼 chat/completions 地址(兼容带不带 /v1 两种写法)。"""
    base = base_url.rstrip("/")
    if base.endswith("/v1"):
        return base + "/chat/completions"
    return base + "/v1/chat/completions"


# ---------------------------------------------------------------- LLM 调用
def call_llm(messages, timeout=LLM_TIMEOUT):
    """依次尝试: model.toml 的 base_url(9443 明文转发器) → 直连
    api.deepseek.com(同为 OpenAI 兼容)。都失败返回 None。"""
    conf = read_model_conf()
    if not conf["api_key"]:
        log("无 api_key,跳过云端调用")
        return None
    key = conf["api_key"]
    attempts = []
    if conf["base_url"]:
        attempts.append((llm_endpoint(conf["base_url"]),
                         conf["model_name"] or "deepseek-chat", "forwarder"))
    attempts.append(("https://api.deepseek.com/v1/chat/completions",
                     "deepseek-chat", "direct"))
    body = json.dumps({
        "model": None,  # 每次尝试时填
        "messages": messages,
        "temperature": 0.6,
        "max_tokens": 500,
        "stream": False,
    }).encode("utf-8")
    for url, model, tag in attempts:
        payload = json.loads(body.decode("utf-8"))
        payload["model"] = model
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + key})
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                obj = json.loads(resp.read().decode("utf-8", "replace"))
            text = obj["choices"][0]["message"]["content"]
            log("LLM OK via %s model=%s took=%.1fs" % (tag, model,
                                                       time.time() - t0))
            return {"text": text, "endpoint": tag, "model": model}
        except Exception as e:
            log("LLM %s(%s) 失败: %s" % (tag, url, type(e).__name__))
            continue
    return None


# ---------------------------------------------------------------- 意图解析
# 本地确定性意图解析:无论云端是否可达,语音命令都能驱动 UI(灵魂功能)。
INTENT_RULES = [
    ("set_theme_pink",
     r"变粉|粉色|粉色主题|粉红|粉系|pink"),
    ("set_theme_dark",
     r"暗色|深色|夜间模式|黑夜|dark(\s*mode)?|变暗"),
    ("set_theme_light",
     r"亮色|浅色|白天模式|light(\s*mode)?|变亮"),
    ("show_apps",
     r"(显示|列出|看看|打开|罗列).{0,8}(app|应用|软件|程序)|(app|应用|软件)"
     r".{0,6}(清单|列表|抽屉|网格)|show\s*apps?"),
    ("switch_desktop",
     r"(切|回|去|进|换|进入).{0,4}(传统)?桌面|传统桌面|desktop(\s*mode)?|"
     r"图标网格模式"),
    ("switch_ai",
     r"(切|回|返|回都).{0,4}(ai|AI|聊天|对话)|ai\s*(模式|界面)|回到对话"),
    ("sandbox_view",
     r"隔离区|沙箱|sandbox"),
    ("get_vm_status",
     r"(?<![A-Za-z0-9_])vm(?![A-Za-z0-9_])|真机|虚拟机|aikernel\s*api|生产机"),
    ("get_status",
     r"(系统)?状态|负载|内存|占用|性能|健康|status|monitor"),
]

ACTION_ALIASES = {
    "set_theme_pink": {"action": "set_theme", "theme": "pink"},
    "set_theme_dark": {"action": "set_theme", "theme": "dark"},
    "set_theme_light": {"action": "set_theme", "theme": "light"},
    "show_apps": {"action": "show_apps"},
    "switch_desktop": {"action": "switch_mode", "mode": "desktop"},
    "switch_ai": {"action": "switch_mode", "mode": "ai"},
    "get_vm_status": {"action": "get_vm_status"},
    "sandbox_view": {"action": "sandbox_view"},
    "get_status": {"action": "get_status"},
}


def parse_intents(text):
    """返回去重后的动作列表;顺序按规则表(主题优先,避免被 show_apps 吃掉)。"""
    actions, seen = [], set()
    for name, pat in INTENT_RULES:
        if re.search(pat, text, re.I):
            a = ACTION_ALIASES[name]
            sig = json.dumps(a, sort_keys=True)
            if sig not in seen:
                seen.add(sig)
                actions.append(a)
    return actions[:4]


# "打开/启动 <某应用>" 意图:在应用清单里按名字找(全知能力的直接体现)。
# 拦截非应用目标:整个目标词就是泛指词,或以抽屉/主题/桌面等泛指词结尾。
_OPEN_STOP = re.compile(
    r"^(应用|app|软件|程序|抽屉|主题|桌面|系统|模式|状态|图标|窗口)$"
    r"|抽屉$|主题$|桌面$|模式$|状态$|图标$|窗口$", re.I)


# 常用口语 -> 应用 id 子串(应用名可能是英文,先过别名表)
_APP_ALIASES = [
    ("设置", ["control-center", "settings"]),
    ("浏览器", ["firefox", "chrom", "browser"]),
    ("上网", ["firefox", "chrom", "browser"]),
    ("文件管理", ["nautilus", "files", "pcmanfm"]),
    ("文件", ["nautilus", "files", "pcmanfm"]),
    ("终端", ["terminal", "console", "xterm"]),
    ("命令行", ["terminal", "console", "xterm"]),
    ("计算器", ["calculator"]),
    ("文本编辑", ["gedit", "texteditor", "text-editor"]),
    ("编辑器", ["gedit", "texteditor", "text-editor"]),
    ("记事本", ["gedit", "texteditor"]),
    ("日历", ["calendar"]),
    ("邮件", ["thunderbird", "evolution", "mail"]),
    ("音乐", ["rhythmbox", "music"]),
    ("视频", ["totem", "video"]),
    ("截图", ["screenshot"]),
    ("系统监视", ["monitor", "usage"]),
    ("磁盘", ["disk"]),
    ("软件", ["software", "snap-store"]),
]


def match_open_app(text, apps):
    m = re.search(r"(?:打开|启动|运行|帮我开|launch|open)\s*(.{1,24}?)\s*[。.!]?\s*$",
                  text, re.I)
    if not m:
        return None
    target = m.group(1).strip()
    if not target or _OPEN_STOP.search(target):
        return None
    t = re.sub(r"^系统|^全部|^一下|^个", "", target).lower()
    # 1) 别名表(口语词 -> id 子串;含中文名匹配)
    for kw, idsubs in _APP_ALIASES:
        if kw in t:
            for sub in idsubs:
                for a in apps:
                    if sub in a["id"].lower():
                        return {"action": "open_app", "app": a["id"],
                                "name": (a.get("name_zh") or a["name"])}
    # 2) 精确名 -> 子串(至少 2 字符;含中文名)
    for a in apps:
        names = {a["name"].lower(), a["name_en"].lower(), a["id"].lower()}
        if a.get("name_zh"):
            names.add(a["name_zh"].lower())
        if t in names:
            return {"action": "open_app", "app": a["id"],
                    "name": (a.get("name_zh") or a["name"])}
    if len(t) >= 2:
        for a in apps:
            pool = [a["name"].lower(), a["name_en"].lower(), a["id"].lower()]
            if a.get("name_zh"):
                pool.append(a["name_zh"].lower())
            if any(t in p for p in pool):
                return {"action": "open_app", "app": a["id"],
                        "name": (a.get("name_zh") or a["name"])}
    return None


# ---------------------------------------------------------------- 演示应答器
def read_proc_stats():
    st = {}
    try:
        with open("/proc/loadavg") as f:
            p = f.read().split()
        st["load1"] = float(p[0])
        st["load5"] = float(p[1])
        st["cores"] = os.cpu_count()
    except Exception:
        st["load1"] = st["load5"] = 0.0
        st["cores"] = 1
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                info[k] = int(v.strip().split()[0])
        total, avail = info["MemTotal"], info["MemAvailable"]
        st["mem_total_mb"] = total // 1024
        st["mem_used_pct"] = round(100.0 * (total - avail) / total, 1)
    except Exception:
        st["mem_total_mb"] = st["mem_used_pct"] = 0
    try:
        with open("/proc/uptime") as f:
            st["uptime_h"] = round(float(f.read().split()[0]) / 3600, 1)
    except Exception:
        st["uptime_h"] = 0.0
    st["kernel"] = os.uname().release
    st["arch"] = os.uname().machine
    return st


def demo_reply(message, actions, apps_count):
    """内置演示应答器:云端不可达时兜底,仍可执行全部界面动作。"""
    stats = read_proc_stats()
    parts = []
    for a in actions:
        if a["action"] == "show_apps":
            parts.append("已为你打开应用抽屉:检测到 %d 款已安装应用,顶部框可搜索。" % apps_count)
        elif a["action"] == "set_theme":
            zh = {"pink": "粉色", "dark": "暗色", "light": "亮色"}[a["theme"]]
            parts.append("已把整套系统切换为%s主题,聊天区、任务栏、壁纸一并变色。" % zh)
        elif a["action"] == "switch_mode":
            parts.append("已切换到传统桌面模式,壁纸、图标网格与任务栏就绪;点左下角 AI 按钮随时回来。" if a["mode"] == "desktop"
                         else "已回到 AI 对话界面,我在。")
        elif a["action"] == "get_status":
            parts.append(
                "这是实时读取的系统态势:"
                "\n```\n$ uname -r\n%s (%s)\n$ uptime\nload %.2f / %d cores, up %.1fh\n$ free\nmem used %.1f%% of %d MB\n```"
                % (stats["kernel"], stats["arch"], stats["load1"],
                   stats["cores"], stats["uptime_h"], stats["mem_used_pct"],
                   stats["mem_total_mb"]))
        elif a["action"] == "get_vm_status":
            if VM_ENABLED:
                parts.append("正在经 SSH 隧道读取生产 VM(192.168.245.138)的 AIKernel 实况……")
            else:
                parts.append("当前是 factory 本地桌面演示(AIK_DESKTOP_VM=0),"
                             "不连接 138:8761;生产实况请用 aikernel-api/ai 工具。")
        elif a["action"] == "sandbox_view":
            if VM_ENABLED:
                parts.append("正在经 SSH 只读读取 VM /sandbox/ 隔离区实况(等价 sandbox_status 工具,R 级)……")
            else:
                parts.append("factory 本地桌面演示不连接生产 VM,隔离区视图不可用。")
        elif a["action"] == "open_app":
            parts.append("已为你定位「%s」,在应用抽屉中高亮显示(demo 不真正拉起进程)。"
                         % a.get("name", a.get("app", "?")))
    if not parts:
        parts.append(
            "我在 AIKernel 演示应答模式(当前云端模型不可达,但界面控制不受影响)。"
            "试试对我说:显示我装的 app / 把系统变粉 / 切到桌面 / 系统状态怎么样?")
    return " ".join(parts)


# ---------------------------------------------------------------- VM 真系统桥
# 生产 VM(192.168.245.138)aikernel-api(127.0.0.1:8761)经 SSH 隧道访问。
# 红线:只读白名单 /act;凭据运行时读 ~/.aikernel/vm138.conf(0600);
# 隧道懒启动、空闲 120s 自动关闭,不留常驻;异常即断开。

VM_CONF = os.path.expanduser("~/.aikernel/vm138.conf")
VM_LOCAL_PORT = 18761          # L1 本地端口 -> VM 127.0.0.1:8761
VM_IDLE_CLOSE = 120            # 秒
# VM 侧 HTTP /act 实测为"W 级参数写"(NETLINK_AI apply),按红线 GUI 不开放;
# sandbox 视图改为 SSH 只读实现(见 vm_sandbox_snapshot)。白名单留空。
VM_ACT_WHITELIST = set()

_vm = {"tunnel": None, "ts": 0.0, "last_err": "", "lock": threading.Lock()}


def _vm_conf():
    conf = {}
    try:
        with open(VM_CONF, "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    conf[k] = v
    except Exception:
        pass
    return conf


def vm_tunnel():
    """懒建立 SSH 隧道(自研 paramiko direct-tcpip 转发:监听 socket 归我们
    所有,shutdown 可靠,不依赖 sshtunnel 的 stop 行为)。
    W76b: AIK_DESKTOP_VM=0 时直接 unavailable,不 import paramiko、不连 138。"""
    if not VM_ENABLED:
        _vm["last_err"] = VM_DISABLED_REASON
        return None
    with _vm["lock"]:
        t = _vm["tunnel"]
        if t is not None:
            try:
                if t["alive"]() and time.time() - _vm["ts"] < VM_IDLE_CLOSE:
                    _vm["ts"] = time.time()
                    return t
            except Exception:
                pass
            vm_close_locked()
        try:
            import select
            import socketserver
            import paramiko
            c = _vm_conf()
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            cli.connect(c.get("host", "192.168.245.138"), 22,
                        c.get("user", "root"), c.get("password", ""),
                        timeout=8)
            transport = cli.get_transport()
            transport.set_keepalive(30)
            remote = ("127.0.0.1", 8761)

            class _Fwd(socketserver.BaseRequestHandler):
                def handle(self):
                    try:
                        chan = transport.open_channel(
                            "direct-tcpip", remote,
                            self.request.getpeername())
                    except Exception:
                        return
                    if chan is None:
                        return
                    try:
                        while True:
                            r, _, _ = select.select(
                                [self.request, chan], [], [], 60)
                            if not r:
                                break
                            if self.request in r:
                                d = self.request.recv(65536)
                                if not d:
                                    break
                                chan.sendall(d)
                            if chan in r:
                                d = chan.recv(65536)
                                if not d:
                                    break
                                self.request.sendall(d)
                    except Exception:
                        pass
                    finally:
                        for x in (chan, self.request):
                            try:
                                x.close()
                            except Exception:
                                pass

            class _Srv(socketserver.ThreadingTCPServer):
                daemon_threads = True
                allow_reuse_address = True

            srv = _Srv(("127.0.0.1", VM_LOCAL_PORT), _Fwd)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            t = {"cli": cli, "srv": srv,
                 "alive": lambda: transport.is_active()}
            _vm["tunnel"] = t
            _vm["ts"] = time.time()
            _vm["last_err"] = ""
            log("VM 隧道已建立 127.0.0.1:%d -> 138:8761" % VM_LOCAL_PORT)
            return t
        except Exception as e:
            _vm["last_err"] = "%s: %s" % (type(e).__name__, str(e)[:120])
            log("VM 隧道失败: %s" % _vm["last_err"])
            return None


def vm_close_locked():
    t = _vm["tunnel"]
    if t is not None:
        try:
            t["srv"].shutdown()
            t["srv"].server_close()
        except Exception:
            pass
        try:
            t["cli"].close()
        except Exception:
            pass
        _vm["tunnel"] = None
        log("VM 隧道已关闭")


def vm_housekeeping():
    """空闲超时自动关隧道(不留常驻)。"""
    while True:
        time.sleep(30)
        with _vm["lock"]:
            t = _vm["tunnel"]
            if t is not None and time.time() - _vm["ts"] > VM_IDLE_CLOSE:
                vm_close_locked()


def vm_token():
    """经 SSH 读 VM /etc/aikernel/api-token,只在内存持有。"""
    if not VM_ENABLED:
        return None
    try:
        import paramiko
        c = _vm_conf()
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(c.get("host", "192.168.245.138"), 22,
                    c.get("user", "root"), c.get("password", ""), timeout=8)
        try:
            _, out, _ = cli.exec_command("cat /etc/aikernel/api-token",
                                         timeout=8)
            tok = out.read().decode().strip()
            return tok or None
        finally:
            cli.close()
    except Exception as e:
        log("VM token 读取失败: %s" % type(e).__name__)
        return None


def vm_api(method, path, body=None, timeout=8.0):
    """经隧道调 aikernel-api。返回 (ok, data_or_err)。"""
    if not VM_ENABLED:
        return False, {"reachable": False, "available": False,
                       "error": VM_DISABLED_REASON}
    if not vm_tunnel():
        return False, {"error": "tunnel failed: " + _vm["last_err"]}
    tok = vm_token()
    if not tok:
        vm_close()
        return False, {"error": "no token"}
    url = "http://127.0.0.1:%d%s" % (VM_LOCAL_PORT, path)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + tok})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return True, json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        detail = getattr(e, "code", None)
        msg = "HTTP %s" % detail if detail else type(e).__name__
        return False, {"error": msg}


def vm_close():
    with _vm["lock"]:
        vm_close_locked()


def vm_status_snapshot():
    """GET /health + /sense 合并,供徽章与聊天用(VM API 无 /status 端点)。"""
    if not VM_ENABLED:
        with _DESKTOP_LOCK:
            obj = load_desktop()
        return {"reachable": False, "available": False, "mode": "local",
                "error": VM_DISABLED_REASON,
                "desktop": {"backend": "web-demo-virtual-window",
                            "windows": len(obj.get("windows", []))},
                "note": "factory/VM 只提供本地桌面状态;L1 VM 隧道已禁用"}
    ok1, st = vm_api("GET", "/health")
    ok2, se = vm_api("GET", "/sense?what=status")
    if not (ok1 or ok2):
        vm_close()
        return {"reachable": False, "error": st.get("error") or se.get("error")}
    return {"reachable": True, "status": st if ok1 else None,
            "sense": se if ok2 else None}


def vm_sandbox_snapshot():
    """等价 sandbox_status 工具(R 级只读):SSH 只读收集 VM /sandbox/
    目录、挂载点与存活进程。VM 的 HTTP /act 实为 W 级参数写端点,
    GUI 不开放;此处全程只读。"""
    if not VM_ENABLED:
        return {"reachable": False, "available": False, "raw": "",
                "empty": True, "error": VM_DISABLED_REASON}
    try:
        import paramiko
        c = _vm_conf()
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(c.get("host", "192.168.245.138"), 22,
                    c.get("user", "root"), c.get("password", ""), timeout=8)
        try:
            _, out, _ = cli.exec_command(
                "ls -la /sandbox/ 2>&1; echo ---MOUNTS---; "
                "mount | grep -i sandbox 2>&1; echo ---PROCS---; "
                "ps -eo pid,comm | grep -iw sandbox 2>&1", timeout=8)
            raw = out.read().decode("utf-8", "replace")[:2000]
            empty = ("total 8" in raw and "---MOUNTS---" in raw
                     and raw.count("\n") < 8)
            return {"reachable": True, "raw": raw, "empty": empty}
        finally:
            cli.close()
    except Exception as e:
        vm_close()
        return {"reachable": False,
                "error": "%s: %s" % (type(e).__name__, str(e)[:100])}


# ---------------------------------------------------------------- .desktop 解析
_ICON_SIZE_DIRS = ["512x512", "256x256", "192x192", "128x128",
                   "96x96", "64x64", "48x48", "32x32"]
_ICON_THEMES = ["Yaru", "hicolor", "Adwaita", "Humanity", "gnome"]


def find_icon_file(icon_name):
    """按 freedesktop 惯例找图标文件,返回绝对路径或 None(优先 PNG)。"""
    if not icon_name:
        return None
    if os.path.isabs(icon_name):
        return icon_name if os.path.isfile(icon_name) else None
    for theme in _ICON_THEMES:
        d = os.path.join("/usr/share/icons", theme)
        if not os.path.isdir(d):
            continue
        for size in _ICON_SIZE_DIRS:
            for ext in ("png", "svg", "xpm"):
                p = os.path.join(d, size, "apps", icon_name + "." + ext)
                if os.path.isfile(p):
                    return p
        for ext in ("png", "svg", "xpm"):
            p = os.path.join(d, "apps", icon_name + "." + ext)  # 无尺寸目录兜底
            if os.path.isfile(p):
                return p
    for ext in ("png", "svg", "xpm"):
        p = os.path.join("/usr/share/pixmaps", icon_name + "." + ext)
        if os.path.isfile(p):
            return p
    return None


def parse_desktop_file(path):
    """解析单个 .desktop,返回 dict 或 None(NoDisplay/Hidden 跳过)。"""
    entry = {"Name": None, "Name_zh": None, "Exec": None, "Icon": None,
             "Comment": None, "Comment_zh": None, "Categories": "",
             "Terminal": False, "NoDisplay": False, "Hidden": False}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            in_main = False
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("["):
                    in_main = (line.strip() == "[Desktop Entry]")
                    continue
                if not in_main or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k == "Name":
                    entry["Name"] = v
                elif k == "Name[zh_CN]":
                    entry["Name_zh"] = v
                elif k == "Exec":
                    entry["Exec"] = v
                elif k == "Icon":
                    entry["Icon"] = v
                elif k == "Comment":
                    entry["Comment"] = v
                elif k == "Comment[zh_CN]":
                    entry["Comment_zh"] = v
                elif k == "Categories":
                    entry["Categories"] = v
                elif k == "Terminal":
                    entry["Terminal"] = (v.strip().lower() == "true")
                elif k == "NoDisplay":
                    entry["NoDisplay"] = (v.strip().lower() == "true")
                elif k == "Hidden":
                    entry["Hidden"] = (v.strip().lower() == "true")
    except Exception:
        return None
    if entry["NoDisplay"] or entry["Hidden"] or not entry["Name"]:
        return None
    return entry


_ZH_LOCK = threading.Lock()
_ZH_CACHE = {"data": None, "ts": 0.0}


def zh_map():
    """加载 locales/zh_CN.json(应用名中文化映射;60s 缓存,热更友好)。"""
    with _ZH_LOCK:
        now = time.time()
        if _ZH_CACHE["data"] is None or now - _ZH_CACHE["ts"] > 60:
            try:
                with open(LOCALE_FILE, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                obj.pop("_meta", None)
                _ZH_CACHE["data"] = obj
            except Exception:
                _ZH_CACHE["data"] = {}
            _ZH_CACHE["ts"] = now
        return _ZH_CACHE["data"]


def _load_demo_catalog():
    """W76b factory 只带 python3.10.desktop(NoDisplay),真实应用为 0;
    用打包的虚拟桌面应用目录兜底(只产生虚拟窗口,不启动宿主进程)。"""
    try:
        with open(CATALOG_FILE, "r", encoding="utf-8") as f:
            obj = json.load(f)
        apps = obj.get("apps", obj) if isinstance(obj, dict) else obj
        return apps if isinstance(apps, list) else []
    except Exception:
        return []


def collect_apps():
    """扫描 /usr/share/applications/*.desktop,解析并落图标到 static/icons/apps。
    W76b: 真实应用 < 5 时合并打包的虚拟桌面应用目录(每项 virtual=true)。"""
    os.makedirs(ICON_OUT_DIR, exist_ok=True)
    zh = zh_map()
    apps = []
    if not os.path.isdir(APPS_DIR):
        return apps
    for fn in sorted(os.listdir(APPS_DIR)):
        if not fn.endswith(".desktop"):
            continue
        entry = parse_desktop_file(os.path.join(APPS_DIR, fn))
        if not entry:
            continue
        app_id = fn[:-8]
        icon_url = None
        src = find_icon_file(entry["Icon"])
        if src:
            ext = os.path.splitext(src)[1].lower()
            dst = os.path.join(ICON_OUT_DIR, app_id + ext)
            try:
                if (not os.path.exists(dst)
                        or os.path.getmtime(dst) < os.path.getmtime(src)):
                    shutil.copyfile(src, dst)
                icon_url = "/static/icons/apps/%s%s" % (app_id, ext)
            except Exception:
                icon_url = None
        if not icon_url:
            # 系统无图标 -> 找 AI 生成图标(static/icons/gen/<id>.png 等)
            for ext in (".png", ".jpg", ".jpeg", ".webp"):
                p = os.path.join(GEN_ICON_DIR, app_id + ext)
                if os.path.isfile(p):
                    icon_url = "/static/icons/gen/%s%s" % (app_id, ext)
                    break
        apps.append({
            "id": app_id,
            "name": entry["Name_zh"] or entry["Name"],
            "name_en": entry["Name"],
            "name_zh": zh.get(app_id) or zh.get(entry["Name"]) or None,
            "comment": entry["Comment_zh"] or entry["Comment"] or "",
            "exec": entry["Exec"] or "",
            "categories": [c for c in entry["Categories"].split(";") if c],
            "terminal": entry["Terminal"],
            "icon": icon_url,
            "virtual": False,
        })
    if len(apps) < 5:
        have = {a.get("id") for a in apps}
        for a in _load_demo_catalog():
            if not isinstance(a, dict) or not a.get("id") or a["id"] in have:
                continue
            item = dict(a)
            item["virtual"] = True
            item.setdefault("source", "w76b-demo-catalog")
            apps.append(item)
    return apps


# ---------------------------------------------------------------- 主题
_THEME_LOCK = threading.Lock()

# 内嵌完整色板(与 theme.json 同源):theme.json 缺失/损坏时自愈,
# 也杜绝 build_custom_theme 基于 display-only 骨架派生出空主题。
_BASE_THEMES = {
    "dark": {
        "display": "暗色", "bg": "#0b0f14", "bg2": "#111823",
        "panel": "rgba(17,24,35,0.86)", "panel_solid": "#141c28",
        "text": "#e6edf3", "text_dim": "#8b98a5", "accent": "#4f8cff",
        "accent_soft": "rgba(79,140,255,0.16)", "accent2": "#7ee787",
        "border": "rgba(255,255,255,0.08)",
        "shadow": "0 18px 50px rgba(0,0,0,0.5)",
        "wallpaper": "linear-gradient(135deg,#0b0f14 0%,#14202e 45%,#1d2f42 100%)",
        "bubble_ai": "#182230", "bubble_user": "#2a4d8f"},
    "light": {
        "display": "亮色", "bg": "#f4f6f9", "bg2": "#e9edf3",
        "panel": "rgba(255,255,255,0.88)", "panel_solid": "#ffffff",
        "text": "#1c2733", "text_dim": "#5c6b7a", "accent": "#2563eb",
        "accent_soft": "rgba(37,99,235,0.12)", "accent2": "#059669",
        "border": "rgba(28,39,51,0.12)",
        "shadow": "0 18px 50px rgba(30,50,80,0.18)",
        "wallpaper": "linear-gradient(135deg,#dfe7f0 0%,#eef3f9 50%,#dbe7f5 100%)",
        "bubble_ai": "#ffffff", "bubble_user": "#2563eb"},
    "pink": {
        "display": "粉色", "bg": "#fff0f5", "bg2": "#ffe1ec",
        "panel": "rgba(255,240,246,0.9)", "panel_solid": "#fff7fa",
        "text": "#4a2438", "text_dim": "#a86b87", "accent": "#ff5fa2",
        "accent_soft": "rgba(255,95,162,0.14)", "accent2": "#b36bff",
        "border": "rgba(255,120,180,0.28)",
        "shadow": "0 18px 50px rgba(255,95,162,0.25)",
        "wallpaper": "linear-gradient(135deg,#ffd6e8 0%,#ffeff6 45%,#f3d9ff 100%)",
        "bubble_ai": "#ffe4ef", "bubble_user": "#ff5fa2"},
}


def load_theme():
    with _THEME_LOCK:
        try:
            with open(THEME_FILE, "r", encoding="utf-8") as f:
                obj = json.load(f)
        except Exception:
            obj = {"current": "dark", "themes": {}}
        # 完整性自愈:任何内置主题缺关键字段(如并发写历史损坏)即修补
        dirty = False
        for name, base in _BASE_THEMES.items():
            cur = obj.get("themes", {}).get(name)
            if not isinstance(cur, dict) or "bg" not in cur:
                patched = dict(base)
                if isinstance(cur, dict) and cur.get("wallpaper_file"):
                    patched["wallpaper_file"] = cur["wallpaper_file"]
                if isinstance(cur, dict) and cur.get("display"):
                    patched["display"] = cur["display"]
                obj.setdefault("themes", {})[name] = patched
                dirty = True
        if not obj.get("themes"):
            obj["themes"] = dict(_BASE_THEMES)
            dirty = True
        obj.setdefault("wallpaper", "gradient")
        obj.setdefault("current", "dark")
        if dirty:
            try:
                tmp = THEME_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(obj, f, ensure_ascii=False, indent=2)
                os.replace(tmp, THEME_FILE)
                _chmod600(THEME_FILE)
                log("theme.json 完整性自愈完成")
            except Exception:
                pass
        return obj


def save_theme(obj):
    with _THEME_LOCK:
        tmp = THEME_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, THEME_FILE)


# ---------------------------------------------------------------- 壁纸画廊
def list_wallpapers():
    """列出 AI 生成的壁纸(文件名去扩展名;小于 10KB 视为坏文件不算)。"""
    try:
        return sorted(
            f[:-4] for f in os.listdir(WALLPAPER_DIR)
            if f.endswith(".png")
            and os.path.getsize(os.path.join(WALLPAPER_DIR, f)) > 10240)
    except Exception:
        return []


# ---------------------------------------------------------------- 自定义主题
_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def _hex_rgb(h):
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _rgb_hex(r, g, b):
    return "#%02x%02x%02x" % (max(0, min(255, r)), max(0, min(255, g)),
                              max(0, min(255, b)))


def _mix(h1, h2, t):
    """颜色线性混合:t=0 全 h1,t=1 全 h2。"""
    a, b = _hex_rgb(h1), _hex_rgb(h2)
    return _rgb_hex(*(round(a[i] + (b[i] - a[i]) * t) for i in range(3)))


def _rgba(hexcolor, alpha):
    r, g, b = _hex_rgb(hexcolor)
    return "rgba(%d,%d,%d,%.2f)" % (r, g, b, alpha)


def build_custom_theme(accent, base):
    """从用户主色派生整套主题(base=dark/light),写回 theme.json。"""
    src = json.loads(json.dumps(
        load_theme().get("themes", {}).get(base) or _BASE_THEMES[base]))
    src["display"] = "自定义(%s)" % accent
    src["accent"] = accent
    src["accent_soft"] = _rgba(accent, 0.16)
    src["accent2"] = _mix(accent, "#ffffff", 0.35)
    src["bg"] = _mix(src["bg"], accent, 0.06)
    src["bg2"] = _mix(src["bg2"], accent, 0.10)
    src["panel_solid"] = _mix(src["panel_solid"], accent, 0.08)
    src["bubble_ai"] = _mix(src["bubble_ai"], accent, 0.14)
    src["bubble_user"] = _mix(accent, "#000000", 0.15)
    src["wallpaper"] = "linear-gradient(135deg,%s 0%%,%s 50%%,%s 100%%)" % (
        _mix(src["bg"], accent, 0.16), src["bg"],
        _mix(src["bg"], accent, 0.28))
    src["wallpaper_file"] = None  # 自定义主题用派生渐变,不绑 AI 壁纸
    return src


# ---------------------------------------------------------------- 聊天持久化
_CHAT_LOCK = threading.Lock()
_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _chat_path(sid):
    return os.path.join(CHAT_DIR, sid + ".json")


def load_chat(sid):
    try:
        with open(_chat_path(sid), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def append_chat(sid, entry):
    """追加一条消息(单文件上限 200 条,超出丢最旧)。"""
    with _CHAT_LOCK:
        msgs = load_chat(sid)
        msgs.append(entry)
        if len(msgs) > 200:
            msgs = msgs[-200:]
        tmp = _chat_path(sid) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(msgs, f, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, _chat_path(sid))


def new_session_id():
    return time.strftime("%Y%m%d-%H%M%S") + "-" + \
        hashlib.md5(str(random.random()).encode()).hexdigest()[:6]


# ---------------------------------------------------------------- 遥测历史
# server 端环形序列(60 点):/api/stats 每次采样追加,刷新不丢曲线。
_STATS_HIST = {"load": [], "mem": []}
_STATS_HIST_MAX = 60


# ---------------------------------------------------------------- VM AI 内核遥测
def vm_aiops_snapshot():
    """决策流 + 遥测事件采样(全程只读)。
    - /proc/ai/decisions:决策 ring(实测可能为 0 字节,如实返回空态)
    - /proc/ai/telemetry:tail 采样,解析 ts/pid/cpu/cat/ev/sev/len
    能读到什么画什么,严禁编造。"""
    if not VM_ENABLED:
        return {"reachable": False, "available": False,
                "decisions_size": 0, "decisions_raw": "",
                "decisions_empty": True, "events": [],
                "event_total_recent": 0, "error": VM_DISABLED_REASON}
    try:
        import paramiko
        c = _vm_conf()
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(c.get("host", "192.168.245.138"), 22,
                    c.get("user", "root"), c.get("password", ""), timeout=8)
        try:
            _, out, _ = cli.exec_command(
                "wc -c /proc/ai/decisions 2>&1; echo ---; "
                "cat /proc/ai/decisions 2>&1 | head -c 4096; echo ---; "
                "tail -c 4096 /proc/ai/telemetry 2>&1", timeout=8)
            raw = out.read().decode("utf-8", "replace")
        finally:
            cli.close()
        parts = raw.split("---")
        dec_size = 0
        try:
            dec_size = int(parts[0].split()[0])
        except Exception:
            pass
        decisions_raw = (parts[1].strip() if len(parts) > 1 else "")
        tele_raw = (parts[2] if len(parts) > 2 else "")
        events = []
        for line in tele_raw.splitlines():
            m = re.match(
                r"ts=(\d+)\s+pid=(\d+)\s+tgid=\d+\s+cpu=(\d+)\s+"
                r"cat=(\d+)\s+ev=(\d+)\s+sev=(\d+)\s+len=(\d+)", line)
            if m:
                events.append({"ts": int(m.group(1)), "pid": int(m.group(2)),
                               "cpu": int(m.group(3)), "cat": int(m.group(4)),
                               "ev": int(m.group(5)), "sev": int(m.group(6)),
                               "len": int(m.group(7))})
        return {"reachable": True,
                "decisions_size": dec_size,
                "decisions_raw": decisions_raw[:2000],
                "decisions_empty": dec_size == 0,
                "events": events[-20:],
                "event_total_recent": len(events)}
    except Exception as e:
        vm_close()
        return {"reachable": False,
                "error": "%s: %s" % (type(e).__name__, str(e)[:100])}


def vm_ai_snapshot():
    """读 VM 的 /proc/ai/status(R 只读)+ loadavg + mem,解析关键字段。"""
    if not VM_ENABLED:
        return {"reachable": False, "available": False,
                "error": VM_DISABLED_REASON}
    try:
        import paramiko
        c = _vm_conf()
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(c.get("host", "192.168.245.138"), 22,
                    c.get("user", "root"), c.get("password", ""), timeout=8)
        try:
            _, out, _ = cli.exec_command(
                "cat /proc/ai/status 2>&1; echo ---; cat /proc/loadavg; "
                "echo ---; free -m | sed -n 2p", timeout=8)
            raw = out.read().decode("utf-8", "replace")
        finally:
            cli.close()
        if "runtime_state" not in raw:
            vm_close()
            return {"reachable": False, "error": "/proc/ai 不可读"}
        enabled = re.search(r"enabled:\s*(\d+)", raw)
        runtime = re.search(r"runtime_state:\s*(\d+)", raw)
        model = re.search(r"name=(\S+)\s+version=(\S+)\s+source=\d+\s+state=(\d+)",
                          raw)
        emitted = sum(int(x) for x in re.findall(r"cpu\d+: emitted=(\d+)", raw))
        dropped = sum(int(x) for x in re.findall(r"dropped=(\d+)", raw))
        load_line = raw.split("---")[1].strip().split()[0] if raw.count("---") >= 1 else "0"
        mem = "n/a"
        if raw.count("---") >= 2:
            parts = raw.split("---")[2].split()
            try:  # total used ... available(单位 MB)
                mem = round(100.0 * int(parts[2]) / int(parts[1]), 1)
            except Exception:
                mem = "n/a"
        return {"reachable": True,
                "ai": {"enabled": int(enabled.group(1)) if enabled else None,
                       "runtime_state": int(runtime.group(1)) if runtime else None,
                       "model": model.group(1) if model else None,
                       "model_state": int(model.group(3)) if model else None,
                       "telemetry_emitted": emitted,
                       "telemetry_dropped": dropped},
                "load1": float(load_line),
                "mem_pct": mem}
    except Exception as e:
        vm_close()
        return {"reachable": False,
                "error": "%s: %s" % (type(e).__name__, str(e)[:100])}


# ---------------------------------------------------------------- 锁屏 PIN
def load_pin():
    try:
        with open(PIN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"enabled": False}


def save_pin(obj):
    write_state_json(PIN_FILE, obj)


def pin_status_view():
    p = load_pin()
    now = time.time()
    locked = p.get("lock_until", 0) > now
    return {"enabled": bool(p.get("enabled")),
            "locked": locked,
            "retry_after": int(p["lock_until"] - now) if locked else 0,
            "fails": int(p.get("fails", 0))}


def pin_strength_warning(pin):
    """PIN 强度策略(IMG-5):返回警告文案或 None。策略:
    - <6 位:建议 6 位以上
    - 全同数字(1111):过弱
    - 连续升/降序(1234/4321):过弱"""
    if len(pin) < 6:
        return "PIN 少于 6 位,建议使用更长的 PIN"
    if len(set(pin)) == 1:
        return "PIN 为重复数字,过于薄弱"
    diffs = {ord(pin[i + 1]) - ord(pin[i]) for i in range(len(pin) - 1)}
    if diffs in ({1}, {-1}):
        return "PIN 为连续顺序数字,过于薄弱"
    return None


def chat_sessions():
    """列出会话:文件即存储;meta.json 存自定义标题。"""
    out = []
    try:
        for fn in sorted(os.listdir(CHAT_DIR)):
            if not fn.endswith(".json"):
                continue
            sid = fn[:-5]
            msgs = load_chat(sid)
            user_msgs = [m for m in msgs if m.get("role") == "user"]
            meta_path = os.path.join(CHAT_DIR, sid + ".meta.json")
            title = None
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    title = json.load(f).get("title")
            except Exception:
                pass
            out.append({
                "id": sid,
                "title": title or (user_msgs[0]["content"][:16]
                                   if user_msgs else sid),
                "count": len(msgs),
                "first": msgs[0].get("ts") if msgs else None,
                "last": msgs[-1].get("ts") if msgs else None,
            })
    except Exception:
        pass
    out.sort(key=lambda x: x.get("last") or "", reverse=True)
    return out


# ---------------------------------------------------------------- HTTP 服务
_APPS_CACHE = {"data": None, "ts": 0.0, "lock": threading.Lock()}


def get_apps(force=False):
    with _APPS_CACHE["lock"]:
        now = time.time()
        if force or _APPS_CACHE["data"] is None or now - _APPS_CACHE["ts"] > 120:
            _APPS_CACHE["data"] = collect_apps()
            _APPS_CACHE["ts"] = now
        return _APPS_CACHE["data"]


# ---------------------------------------------------------------- W76 桌面状态
# Web demo 的“桌面”是服务端持有的虚拟状态:窗口、焦点、z 序、窗口文本、
# 剪贴板。前端每 1.2s 拉取 /api/windows 复现同一状态,Playwright 截图也
# 走同一状态。这里是 W76 的受控桌面面,不是真 OS 窗口管理器(见 W84)。
_DESKTOP_LOCK = threading.Lock()
_SCREENSHOT_LOCK = threading.Lock()
_WIN_ID_RE = re.compile(r"^w-[0-9]{4,10}$")
_APP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$")
_THEME_NAME_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_WALLPAPER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_KEY_MODS = ("ctrl", "alt", "shift", "meta")
_KEY_NAMES = ("Enter", "Backspace", "Tab", "Escape", "Delete", "Home",
              "End", "PageUp", "PageDown", "ArrowUp", "ArrowDown",
              "ArrowLeft", "ArrowRight") + tuple("F%d" % i for i in range(1, 13))


def _desktop_default():
    return {"mode": "ai", "windows": [], "next_id": 1, "z": 1,
            "clipboard": "", "clipboard_updated": None}


def load_desktop():
    """读取 data/desktop.json;损坏/缺失时回落默认(不阻塞服务)。"""
    try:
        with open(DESKTOP_FILE, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            raise ValueError("not object")
    except Exception:
        obj = _desktop_default()
    obj.setdefault("mode", "ai")
    obj.setdefault("windows", [])
    obj.setdefault("next_id", 1)
    obj.setdefault("z", 1)
    obj.setdefault("clipboard", "")
    obj.setdefault("clipboard_updated", None)
    return obj


def save_desktop(obj):
    os.makedirs(os.path.dirname(DESKTOP_FILE), exist_ok=True)
    tmp = DESKTOP_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    # 窗口文本/剪贴板属敏感数据：只允许属主读写
    os.chmod(tmp, 0o600)
    os.replace(tmp, DESKTOP_FILE)


def _desktop_snapshot(obj):
    """返回给 API/前端的稳定视图(按 z 从小到大;id 稳定)。"""
    wins = sorted(obj.get("windows", []), key=lambda w: w.get("z", 0))
    wins = json.loads(json.dumps(wins))  # 深拷贝,避免锁外序列化竞态
    return {
        "mode": obj.get("mode", "ai"),
        "count": len(wins),
        "focused": obj.get("focused"),
        "windows": wins,
        "clipboard": {"length": len(obj.get("clipboard", "") or ""),
                      "updated_at": obj.get("clipboard_updated")},
        "backend": "web-demo-virtual-window",
        "note": "Web demo 虚拟窗口,不启动宿主进程;真 OS 桌面见 W84",
    }


def _find_app(app_id):
    for a in get_apps():
        if a.get("id") == app_id:
            return a
    return None


def _find_window(obj, wid):
    for w in obj.get("windows", []):
        if w.get("id") == wid:
            return w
    return None


def _focus_window(obj, wid):
    top = max([w.get("z", 0) for w in obj.get("windows", [])] or [0])
    for w in obj.get("windows", []):
        w["focused"] = (w.get("id") == wid)
        if w["focused"]:
            w["z"] = top + 1
            w["visible"] = True
            obj["focused"] = wid
    obj["z"] = top + 1
    obj["mode"] = "desktop"


def _top_focus(obj):
    wins = obj.get("windows", [])
    if not wins:
        obj["focused"] = None
        return
    top = max(wins, key=lambda w: w.get("z", 0))
    for w in wins:
        w["focused"] = (w is top)
    obj["focused"] = top.get("id")


def _window_text_append(w, text):
    cur = w.get("text", "") or ""
    room = 4096 - len(cur)
    if room <= 0:
        return 0
    add = text[:room]
    w["text"] = cur + add
    w["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return len(add)


def _window_launch(obj, app):
    existing = None
    for w in obj.get("windows", []):
        if w.get("app") == app["id"] and w.get("visible", True):
            existing = w
            break
    if existing:
        _focus_window(obj, existing["id"])
        return existing, False
    n = int(obj.get("next_id", 1))
    obj["next_id"] = n + 1
    wid = "w-%04d" % n
    geo = {"x": 120 + ((n - 1) % 5) * 42, "y": 96 + ((n - 1) % 4) * 38,
           "w": 520, "h": 320}
    win = {
        "id": wid,
        "title": app.get("name") or app["id"],
        "app": app["id"],
        "app_name": app.get("name") or app["id"],
        "geometry": geo,
        "focused": False,
        "visible": True,
        "z": 0,
        "text": "",
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "last_key": None,
    }
    obj.setdefault("windows", []).append(win)
    _focus_window(obj, wid)
    return win, True


def _validate_modifiers(mods):
    if mods in (None, ""):
        return []
    if not isinstance(mods, (str, list)):
        return None
    if isinstance(mods, str):
        items = [m.strip().lower() for m in mods.split(",") if m.strip()]
    else:
        items = [str(m).strip().lower() for m in mods]
    for m in items:
        if m not in _KEY_MODS:
            return None
    return items


def _clipboard_sha(text):
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def screenshot_backend():
    """返回 playwright|unavailable;factory 显式关闭时不再探测。"""
    if SCREENSHOT_MODE in ("0", "false", "no", "off", "disabled",
                           "unavailable"):
        return "unavailable"
    try:
        import importlib.util
        if importlib.util.find_spec("playwright") is not None:
            return "playwright"
    except Exception:
        pass
    return "unavailable"


def take_screenshot():
    """用 Playwright 截当前 demo 桌面;返回文件路径/字节数/sha256。
    失败抛 RuntimeError(由 HTTP 层映射为 503/500),绝不伪造空图。"""
    if screenshot_backend() != "playwright":
        raise RuntimeError(
            "screenshot unavailable: playwright_unavailable "
            "(AIK_DESKTOP_SCREENSHOT=%s)" % SCREENSHOT_MODE)
    if os.path.isdir("/dev/shm/ms-playwright"):
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH",
                              "/dev/shm/ms-playwright")
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise RuntimeError("playwright_unavailable: %s" % type(e).__name__)

    with _DESKTOP_LOCK:
        obj = load_desktop()
        nwin = len(obj.get("windows", []))
        force_desktop = obj.get("mode") == "desktop" or nwin > 0
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    name = "shot-%s-%d.png" % (time.strftime("%Y%m%d-%H%M%S"),
                              time.time_ns() % 1000000)
    path = os.path.join(SCREENSHOT_DIR, name)
    base = "http://%s:%d" % (BIND_HOST, PORT)
    with _SCREENSHOT_LOCK:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chromium",
                                        args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport={"width": 1280,
                                                  "height": 800})
                page.goto(base, wait_until="domcontentloaded",
                          timeout=30000)
                page.wait_for_function(
                    "document.getElementById('clock-time') && "
                    "document.getElementById('clock-time').textContent "
                    "!== '--:--:--'", timeout=15000)
                if force_desktop:
                    page.evaluate("setMode('desktop')")
                    page.wait_for_function(
                        "document.querySelectorAll('.win').length >= %d"
                        % nwin, timeout=10000)
                # 等开机引导浮层退场,否则截到黑底 boot 画面(白屏/无窗口)
                try:
                    page.wait_for_selector("#boot", state="detached",
                                           timeout=8000)
                except Exception:
                    pass
                page.wait_for_timeout(500)
                page.screenshot(path=path, full_page=False)
                # 截图含全部窗口内容：只允许属主读写
                os.chmod(path, 0o600)
            finally:
                browser.close()
    size = os.path.getsize(path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    if size <= 0:
        raise RuntimeError("empty_screenshot")
    return {"path": path, "bytes": size, "sha256": h.hexdigest(),
            "width": 1280, "height": 800, "ts": time.strftime("%Y-%m-%d %H:%M:%S")}


class Handler(BaseHTTPRequestHandler):
    server_version = "AIKernel-IMG1/1.0"
    protocol_version = "HTTP/1.1"

    # ---- 基础输出 ----
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _static(self, rel):
        """安全静态文件服务(禁止路径穿越)。W76b: /static/icons/* 先查
        只读 /opt 静态树,再查可写状态根(运行时生成的图标)。"""
        rel = unquote(rel)
        roots = [STATIC_DIR]
        if rel.startswith("icons/"):
            roots.append(STATE_ROOT)
        for root in roots:
            full = os.path.normpath(os.path.join(root, rel))
            if not (full == root or full.startswith(root + os.sep)):
                continue
            if not os.path.isfile(full):
                continue
            ctype = (mimetypes.guess_type(full)[0]
                     or "application/octet-stream")
            try:
                with open(full, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=300")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        self._send(404, {"error": "not found"})

    def _body_json(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n) if n else b"{}"
            return json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return {}

    def log_message(self, fmt, *args):  # 静默默认访问日志,只留关键日志
        pass

    # ---- 路由 ----
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path == "/" or path == "/index.html":
            self._static("index.html")
        elif path.startswith("/static/"):
            self._static(path[len("/static/"):])
        elif path == "/favicon.ico":
            self._static("icons/favicon.svg")
        elif path == "/api/health":
            obj = load_desktop()
            self._send(200, {"ok": True, "service": "img1",
                             "version": VERSION, "built": START_TS,
                             "bind": BIND_HOST, "port": PORT,
                             "state_root": STATE_ROOT,
                             "vm": ("l1-tunnel" if VM_ENABLED else "local"),
                             "desktop": {"backend": "web-demo",
                                         "windows": len(obj.get("windows", [])),
                                         "screenshot": screenshot_backend(),
                                         "input": "server-state",
                                         "power": "unavailable"},
                             "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        elif path == "/api/wallpaper":
            theme = load_theme()
            self._send(200, {"current": theme.get("wallpaper", "gradient"),
                             "available": list_wallpapers()})
        elif path == "/api/chat/history":
            sid = parse_qs(u.query).get("session", ["default"])[0]
            if not _SESSION_RE.match(sid):
                self._send(400, {"error": "bad session id"})
                return
            msgs = load_chat(sid)
            self._send(200, {"session": sid, "messages": msgs[-40:]})
        elif path == "/api/apps":
            apps = get_apps(force="refresh" in parse_qs(u.query))
            self._send(200, {"count": len(apps), "apps": apps})
        elif path == "/api/theme":
            self._send(200, load_theme())
        elif path == "/api/stats":
            st = read_proc_stats()
            _STATS_HIST["load"].append(st.get("load1", 0))
            _STATS_HIST["mem"].append(st.get("mem_used_pct", 0))
            for k in ("load", "mem"):
                if len(_STATS_HIST[k]) > _STATS_HIST_MAX:
                    _STATS_HIST[k] = _STATS_HIST[k][-_STATS_HIST_MAX:]
            st["hist"] = {"load": _STATS_HIST["load"],
                          "mem": _STATS_HIST["mem"]}
            self._send(200, st)
        elif path == "/api/vm/ai":
            self._send(200, vm_ai_snapshot())
        elif path == "/api/vm/aiops":
            self._send(200, vm_aiops_snapshot())
        elif path == "/api/notifs":
            try:
                with open(NOTIF_FILE, "r", encoding="utf-8") as f:
                    self._send(200, json.load(f))
            except Exception:
                self._send(200, [])
        elif path == "/api/pin/status":
            self._send(200, pin_status_view())
        elif path == "/api/chat/sessions":
            self._send(200, {"sessions": chat_sessions()})
        elif path == "/api/vm/status":
            self._send(200, vm_status_snapshot())
        elif path == "/api/vm/tools":
            if not VM_ENABLED:
                self._send(200, {"reachable": False, "available": False,
                                 "error": VM_DISABLED_REASON, "tools": []})
            else:
                ok, data = vm_api("GET", "/tools")
                self._send(200 if ok else 502, data if ok else
                           {"reachable": False, "error": data.get("error")})
        elif path == "/api/model":
            conf = read_model_conf()
            self._send(200, {"base_url": conf["base_url"],
                             "model": conf["model_name"],
                             "key_loaded": bool(conf["api_key"])})
        elif path == "/api/windows":
            with _DESKTOP_LOCK:
                obj = load_desktop()
                snap = _desktop_snapshot(obj)
                theme = load_theme()
                wp = theme.get("wallpaper", "gradient")
            snap["theme"] = {"current": theme.get("current", "dark")}
            snap["wallpaper"] = wp
            self._send(200, snap)
        elif path == "/api/screenshot":
            try:
                shot = take_screenshot()
                self._send(200, dict(ok=True, **shot))
            except Exception as e:
                msg = "%s: %s" % (type(e).__name__, str(e)[:300])
                code = 503 if ("playwright" in msg.lower()
                               or "screenshot unavailable" in msg.lower()) else 500
                self._send(code, {"ok": False, "error": msg,
                                  "backend": "playwright"})
        elif path == "/api/clipboard":
            with _DESKTOP_LOCK:
                obj = load_desktop()
                text = obj.get("clipboard", "") or ""
                upd = obj.get("clipboard_updated")
            self._send(200, {"text": text, "length": len(text),
                             "sha256": _clipboard_sha(text),
                             "updated_at": upd})
        elif path == "/api/chat" and "fallback" in parse_qs(u.query):
            # GET 调试入口:强制演示应答
            msg = parse_qs(u.query).get("fallback", ["你好"])[0]
            self._send(200, {"reply": demo_reply(msg, [], len(get_apps())),
                             "actions": [], "source": "demo"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/theme":
            body = self._body_json()
            theme = load_theme()
            if "custom" in body:  # 用户自定义主题:主色+基色,格式校验
                c = body["custom"] or {}
                accent = str(c.get("accent", ""))
                base = c.get("base", "dark")
                if not _HEX_RE.match(accent):
                    self._send(400, {"ok": False,
                                     "error": "accent 需为 #rrggbb 十六进制色"})
                    return
                if base not in ("dark", "light"):
                    self._send(400, {"ok": False,
                                     "error": "base 需为 dark|light"})
                    return
                theme["themes"]["custom"] = build_custom_theme(accent, base)
                theme["current"] = "custom"
                save_theme(theme)
                self._send(200, {"ok": True, "current": "custom",
                                 "theme": theme["themes"]["custom"]})
                return
            if "wallpaper" in body:  # 壁纸切换(兼容旧路径 /api/theme)
                name = str(body["wallpaper"])
                if name != "gradient" and name not in list_wallpapers():
                    self._send(400, {"ok": False,
                                     "error": "未知壁纸: %s" % name,
                                     "available": list_wallpapers()})
                    return
                theme["wallpaper"] = name
                save_theme(theme)
                self._send(200, {"ok": True, "wallpaper": name})
                return
            name = body.get("name", "")
            if name in theme.get("themes", {}):
                theme["current"] = name
                save_theme(theme)
                self._send(200, {"ok": True, "current": name,
                                 "theme": theme["themes"][name]})
            else:
                self._send(400, {"ok": False,
                                 "error": "unknown theme: %s" % name,
                                 "available": sorted(theme.get("themes", {}))})
        elif u.path == "/api/wallpaper":
            body = self._body_json()
            name = str(body.get("wallpaper", ""))
            if name != "gradient" and name not in list_wallpapers():
                self._send(400, {"ok": False,
                                 "error": "未知壁纸: %s" % name,
                                 "available": list_wallpapers()})
                return
            theme = load_theme()
            theme["wallpaper"] = name
            save_theme(theme)
            self._send(200, {"ok": True, "wallpaper": name})
        elif u.path == "/api/chat/rename":
            body = self._body_json()
            sid = str(body.get("session", ""))
            title = str(body.get("title", "")).strip()
            if not _SESSION_RE.match(sid) or not os.path.isfile(_chat_path(sid)):
                self._send(400, {"ok": False, "error": "会话不存在"})
                return
            title = title[:40]
            if not title:
                self._send(400, {"ok": False, "error": "标题不能为空"})
                return
            meta_path = os.path.join(CHAT_DIR, sid + ".meta.json")
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump({"title": title}, f, ensure_ascii=False)
            _chmod600(meta_path)
            self._send(200, {"ok": True, "session": sid, "title": title})
        elif u.path == "/api/chat/delete":
            body = self._body_json()
            sid = str(body.get("session", ""))
            if not _SESSION_RE.match(sid):
                self._send(400, {"ok": False, "error": "非法会话 id"})
                return
            removed = False
            for suffix in (".json", ".meta.json"):
                p = os.path.join(CHAT_DIR, sid + suffix)
                if os.path.isfile(p):
                    os.remove(p)
                    removed = True
            self._send(200, {"ok": removed, "session": sid})
        elif u.path == "/api/notifs":
            body = self._body_json()
            if "notifs" in body:
                notifs = body.get("notifs", [])
                if not isinstance(notifs, list):
                    self._send(400, {"ok": False, "error": "notifs 需为数组"})
                    return
                notifs = notifs[:100]  # 上限 100 条,超出丢最旧
            else:
                # W76 desktop.notifications.send:追加一条(不覆盖历史)
                title = body.get("title", "")
                text = body.get("body", "")
                if not isinstance(title, str) or not isinstance(text, str):
                    self._send(400, {"ok": False,
                                     "error": "title/body 需为字符串"})
                    return
                title = title.strip()[:80]
                text = text.strip()[:400]
                if not title:
                    self._send(400, {"ok": False, "error": "title 不能为空"})
                    return
                try:
                    with open(NOTIF_FILE, "r", encoding="utf-8") as f:
                        notifs = json.load(f)
                    if not isinstance(notifs, list):
                        notifs = []
                except Exception:
                    notifs = []
                notifs.append({
                    "title": title, "body": text,
                    "tag": str(body.get("tag", "ai"))[:24] or "ai",
                    "time": time.strftime("%H:%M"),
                    "id": "n-%d" % time.time_ns(),
                    "source": "desktop.notifications.send",
                })
                notifs = notifs[-100:]
            os.makedirs(os.path.dirname(NOTIF_FILE), exist_ok=True)
            tmp = NOTIF_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(notifs, f, ensure_ascii=False)
            os.chmod(tmp, 0o600)
            os.replace(tmp, NOTIF_FILE)
            self._send(200, {"ok": True, "count": len(notifs)})
        elif u.path == "/api/pin/set":
            body = self._body_json()
            pin = str(body.get("pin", ""))
            if not re.match(r"^\d{4,8}$", pin):
                self._send(400, {"ok": False,
                                 "error": "PIN 需为 4-8 位数字"})
                return
            warning = pin_strength_warning(pin)
            p = load_pin()
            p["salt"] = hashlib.md5(str(random.random()).encode(),
                                    usedforsecurity=False).hexdigest()[:12]
            p["hash"] = hashlib.sha256(
                (p["salt"] + ":" + pin).encode()).hexdigest()
            p["enabled"] = True
            p["fails"] = 0
            p["lock_until"] = 0
            save_pin(p)
            log("PIN 已设置(仅存 hash)")
            self._send(200, {"ok": True, "enabled": True,
                             "warning": warning})
        elif u.path == "/api/pin/clear":
            p = load_pin()
            p["enabled"] = False
            p["fails"] = 0
            p["lock_until"] = 0
            p.pop("hash", None)
            p.pop("salt", None)
            save_pin(p)
            self._send(200, {"ok": True, "enabled": False})
        elif u.path == "/api/pin/verify":
            body = self._body_json()
            pin = str(body.get("pin", ""))
            p = load_pin()
            now = time.time()
            if not p.get("enabled"):
                self._send(200, {"ok": True, "enabled": False})
                return
            if p.get("lock_until", 0) > now:
                self._send(200, {"ok": False, "locked": True,
                                 "retry_after": int(p["lock_until"] - now)})
                return
            h = hashlib.sha256(
                (p.get("salt", "") + ":" + pin).encode()).hexdigest()
            if h == p.get("hash"):
                p["fails"] = 0
                save_pin(p)
                self._send(200, {"ok": True})
            else:
                p["fails"] = p.get("fails", 0) + 1
                resp = {"ok": False, "fails": p["fails"]}
                if p["fails"] >= 3:
                    p["lock_until"] = now + 30
                    p["fails"] = 0
                    resp = {"ok": False, "locked": True, "retry_after": 30}
                save_pin(p)
                self._send(200, resp)
        elif u.path == "/api/chat/new":
            sid = new_session_id()
            append_chat(sid, {"role": "system",
                              "content": "会话开始",
                              "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
            self._send(200, {"ok": True, "session": sid})
        elif u.path == "/api/chat":
            self._handle_chat()
        elif u.path == "/api/vm/act":
            body = self._body_json()
            act = body.get("action", "")
            if act not in VM_ACT_WHITELIST:
                self._send(403, {"ok": False,
                                 "error": "VM /act 实测为 W 级参数写端点,"
                                          "GUI 演示阶段按红线不开放任何写;"
                                          "隔离区视图已改为 SSH 只读实现",
                                 "hint": "用对话「看一眼隔离区」体验只读视图"})
                return
            ok, data = vm_api("POST", "/act",
                              {"action": act, "confirm": True}, timeout=12)
            if not ok:
                vm_close()  # 异常即断开隧道
            self._send(200 if ok else 502,
                       data if ok else {"ok": False,
                                        "error": data.get("error")})
        elif u.path == "/api/apps/launch":
            body = self._body_json()
            app_id = str(body.get("app", ""))
            if not _APP_ID_RE.match(app_id):
                self._send(400, {"ok": False, "error": "app 参数非法"})
                return
            app = _find_app(app_id)
            if not app:
                self._send(404, {"ok": False,
                                 "error": "未知应用: %s" % app_id})
                return
            with _DESKTOP_LOCK:
                obj = load_desktop()
                win, created = _window_launch(obj, app)
                save_desktop(obj)
                snap = _desktop_snapshot(obj)
            self._send(200, {"ok": True, "created": created,
                             "window_id": win["id"], "window": win,
                             "focused": snap["focused"],
                             "backend": "web-demo-virtual-window",
                             "note": "Web demo 虚拟窗口;未启动宿主进程(W84)"})
        elif u.path == "/api/apps/close":
            body = self._body_json()
            app_id = str(body.get("app", ""))
            wid = str(body.get("id", ""))
            if not _APP_ID_RE.match(app_id) and not _WIN_ID_RE.match(wid):
                self._send(400, {"ok": False,
                                 "error": "需要合法 app 或 id"})
                return
            with _DESKTOP_LOCK:
                obj = load_desktop()
                closed = []
                keep = []
                for w in obj.get("windows", []):
                    hit = ((app_id and w.get("app") == app_id) or
                           (wid and w.get("id") == wid))
                    if hit:
                        closed.append(w.get("id"))
                    else:
                        keep.append(w)
                if not closed:
                    self._send(404, {"ok": False,
                                     "error": "没有匹配的窗口"})
                    return
                obj["windows"] = keep
                _top_focus(obj)
                save_desktop(obj)
                snap = _desktop_snapshot(obj)
            self._send(200, {"ok": True, "closed": closed,
                             "count": len(closed),
                             "focused": snap["focused"],
                             "windows": snap["count"]})
        elif u.path == "/api/windows/focus":
            body = self._body_json()
            wid = str(body.get("id", ""))
            if not _WIN_ID_RE.match(wid):
                self._send(400, {"ok": False, "error": "window id 非法"})
                return
            with _DESKTOP_LOCK:
                obj = load_desktop()
                if not _find_window(obj, wid):
                    self._send(404, {"ok": False,
                                     "error": "窗口不存在: %s" % wid})
                    return
                _focus_window(obj, wid)
                save_desktop(obj)
                snap = _desktop_snapshot(obj)
            self._send(200, {"ok": True, "id": wid,
                             "focused": snap["focused"],
                             "windows": snap["count"]})
        elif u.path == "/api/windows/close":
            body = self._body_json()
            wid = str(body.get("id", ""))
            if not _WIN_ID_RE.match(wid):
                self._send(400, {"ok": False, "error": "window id 非法"})
                return
            with _DESKTOP_LOCK:
                obj = load_desktop()
                win = _find_window(obj, wid)
                if not win:
                    self._send(404, {"ok": False,
                                     "error": "窗口不存在: %s" % wid})
                    return
                obj["windows"] = [w for w in obj["windows"]
                                  if w.get("id") != wid]
                _top_focus(obj)
                save_desktop(obj)
                snap = _desktop_snapshot(obj)
            self._send(200, {"ok": True, "closed": wid,
                             "focused": snap["focused"],
                             "windows": snap["count"]})
        elif u.path == "/api/input":
            body = self._body_json()
            kind = body.get("type", "")
            if kind not in ("type", "key"):
                self._send(400, {"ok": False,
                                 "error": "type 需为 type|key"})
                return
            mods = _validate_modifiers(body.get("modifiers"))
            if mods is None:
                self._send(400, {"ok": False,
                                 "error": "modifiers 仅支持 ctrl/alt/shift/meta"})
                return
            with _DESKTOP_LOCK:
                obj = load_desktop()
                focus = obj.get("focused")
                win = _find_window(obj, focus) if focus else None
                if not win:
                    self._send(409, {"ok": False,
                                     "error": "no focused window"})
                    return
                before = win.get("text", "") or ""
                changed = 0
                if kind == "type":
                    text = body.get("text", "")
                    if not isinstance(text, str):
                        self._send(400, {"ok": False,
                                         "error": "text 需为字符串"})
                        return
                    if len(text) > 4096:
                        self._send(400, {"ok": False,
                                         "error": "text 超长(>4096)"})
                        return
                    changed = _window_text_append(win, text)
                else:
                    key = body.get("key", "")
                    if not isinstance(key, str) or not key:
                        self._send(400, {"ok": False,
                                         "error": "key 不能为空"})
                        return
                    if (len(key) != 1 and key not in _KEY_NAMES):
                        self._send(400, {"ok": False,
                                         "error": "key 不在允许集"})
                        return
                    win["last_key"] = key
                    win["last_modifiers"] = mods
                    if "ctrl" in mods and key.lower() in ("l", "u"):
                        win["text"] = ""
                        changed = 1
                    elif key == "Backspace":
                        if win["text"]:
                            win["text"] = win["text"][:-1]
                            changed = 1
                    elif key == "Delete":
                        if win["text"]:
                            win["text"] = win["text"][:-1]
                            changed = 1
                    elif key == "Enter":
                        changed = _window_text_append(win, "\n")
                    elif key == "Tab":
                        changed = _window_text_append(win, "\t")
                    elif len(key) == 1:
                        changed = _window_text_append(win, key)
                    win["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                save_desktop(obj)
                after = win.get("text", "") or ""
            self._send(200, {"ok": True, "window_id": win["id"],
                             "input": {"type": kind, "text": body.get("text"),
                                       "key": body.get("key"),
                                       "modifiers": mods},
                             "changed": changed,
                             "text_before": before, "text_after": after,
                             "length": len(after),
                             "last_key": win.get("last_key")})
        elif u.path == "/api/clipboard":
            body = self._body_json()
            text = body.get("text", None)
            if not isinstance(text, str):
                self._send(400, {"ok": False, "error": "text 需为字符串"})
                return
            if len(text) > 65536:
                self._send(400, {"ok": False,
                                 "error": "剪贴板超长(>65536)"})
                return
            with _DESKTOP_LOCK:
                obj = load_desktop()
                prev = obj.get("clipboard", "") or ""
                obj["clipboard"] = text
                obj["clipboard_updated"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S")
                save_desktop(obj)
            self._send(200, {"ok": True, "length": len(text),
                             "sha256": _clipboard_sha(text),
                             "previous": prev,
                             "previous_length": len(prev),
                             "previous_sha256": _clipboard_sha(prev)})
        elif u.path == "/api/power":
            body = self._body_json()
            act = body.get("action", "")
            allowed = ("lock", "logout", "reboot", "shutdown", "suspend")
            if act not in allowed:
                self._send(400, {"ok": False,
                                 "error": "action 需为 %s" %
                                          "|".join(allowed)})
                return
            # W76：不再返回“演示回执”冒充成功。Web demo 无 logind/session
            # 控制面;明确 unavailable,由 W84 系统桌面接入真实后端。
            log("power 请求被拒绝(unavailable): %s" % act)
            self._send(501, {"ok": False, "available": False,
                             "executed": False, "action": act,
                             "backend": "unavailable",
                             "error": "电源后端不可用: Web demo 无 logind "
                                      "控制面;真桌面(W84)再接入",
                             "logind_seats": os.path.isdir("/run/systemd/seats"),
                             "rollback": "no-op(未执行)"})
        else:
            self._send(404, {"error": "not found"})

    # ---- 聊天主流程 ----
    def _handle_chat(self):
        t0 = time.time()
        u = urlparse(self.path)  # 注意:_handle_chat 自己解析,不依赖调用方作用域
        body = self._body_json()
        message = (body.get("message") or "").strip()
        sid = str(body.get("session") or "default")
        if not _SESSION_RE.match(sid):
            sid = "default"
        history = body.get("history") or []
        force_fallback = ("fallback" in parse_qs(u.query)) if u.query else False
        if not message:
            self._send(400, {"error": "empty message"})
            return
        if len(message) > 2000:
            message = message[:2000]
        actions = parse_intents(message)
        apps_list = get_apps()
        if not actions:
            oa = match_open_app(message, apps_list)
            if oa:
                actions.append(oa)
        apps_count = len(apps_list)
        source, reply_text = None, None

        if not force_fallback:
            sys_prompt = (
                "你是 AIKernel 操作系统的内置 AI 助手,运行在 AI-first 桌面 Demo 上。"
                "用户消息可能是语音式命令,你可以控制界面:显示应用抽屉、切换主题"
                "(暗色/亮色/粉色)、切换到传统桌面或回到 AI 对话、报告系统状态。\n"
                "规则:用简体中文回答,不超过 120 字;若用户意图是控制界面,在回复"
                "最前面输出一行 JSON 动作标签,格式:[[{\"action\":\"...\"}]],"
                "支持的 action: show_apps; set_theme(带 theme=dark|light|pink); "
                "switch_mode(带 mode=ai|desktop); get_status; open_app(带 "
                "app=<应用id> 与 name=<应用名>)。"
                "注意:创建隔离区等写操作在演示阶段不开放,若用户要求创建,"
                "如实说明只演示只读查看,不要声称已创建、不要编造界面按钮。"
                "示例:用户说\"变粉\"→ 回复 [[{\"action\":\"set_theme\","
                "\"theme\":\"pink\"}]] 已切换为粉色主题。普通闲聊则不加标签。")
            msgs = [{"role": "system", "content": sys_prompt}]
            # 上下文优先用 server 端持久化历史(最近 20 条),客户端历史兜底
            stored = [m for m in load_chat(sid)
                      if m.get("role") in ("user", "assistant")
                      and m.get("content")][-20:]
            ctx = stored or [h for h in history[-6:]
                             if isinstance(h, dict)
                             and h.get("role") in ("user", "assistant")]
            for h in ctx:
                msgs.append({"role": h["role"],
                             "content": str(h.get("content", ""))[:800]})
            msgs.append({"role": "user", "content": message})
            r = call_llm(msgs)
            if r:
                source = r["endpoint"]
                reply_text = r["text"]
                # 解析 LLM 回复里的动作标签 [[...]](兼容 [[{...}]] 与 [[[{...}]]])
                m = re.search(r"\[\[(.+?)\]\]", reply_text, re.S)
                if m:
                    try:
                        arr = json.loads(m.group(1))
                        if isinstance(arr, dict):
                            arr = [arr]
                        for a in arr:
                            if isinstance(a, dict) and "action" in a:
                                sig = json.dumps(a, sort_keys=True)
                                if sig not in [json.dumps(x, sort_keys=True)
                                               for x in actions]:
                                    actions.append(a)
                    except Exception:
                        pass
                    reply_text = reply_text[:m.start()] + reply_text[m.end():]
                reply_text = reply_text.strip()
        else:
            # 强制降级路径:给后面留预算
            if time.time() - t0 > FALLBACK_DEADLINE:
                log("聊天超预算,直接降级")
        if reply_text is None:
            reply_text = demo_reply(message, actions, apps_count)
            source = "demo"
        # VM 真系统数据(只读):无论回复来自云端还是演示器,都附加实况终端块
        if any(a.get("action") == "get_vm_status" for a in actions):
            snap = vm_status_snapshot()
            if snap["reachable"]:
                st, se = snap.get("status") or {}, snap.get("sense") or {}
                reply_text += "\n```\n[AIKernel VM 192.168.245.138 实况]\n"
                for k in ("uptime", "services", "sandbox", "version", "load"):
                    if isinstance(st, dict) and k in st:
                        reply_text += "%s: %s\n" % (k, st[k])
                for k, v in (se.items() if isinstance(se, dict) else []):
                    s = json.dumps(v, ensure_ascii=False)
                    reply_text += "%s: %s\n" % (k, s[:160])
                reply_text += "```"
            else:
                reply_text += "\n(VM 138 当前不可达:%s;已断开隧道)" \
                              % snap.get("error", "?")
                vm_close()
        # sandbox 视图(只读):真实渲染 VM /sandbox/ 实况
        if any(a.get("action") == "sandbox_view" for a in actions):
            snap = vm_sandbox_snapshot()
            if snap["reachable"]:
                body = snap["raw"].replace("\n---MOUNTS---\n", "\n$ mount | grep sandbox\n") \
                                  .replace("\n---PROCS---\n", "\n$ ps | grep sandbox\n")
                if snap["empty"]:
                    body += "(当前无任何隔离区;创建属 W1 写操作,GUI 演示阶段按红线不开放)"
                reply_text += "\n```\n[sandbox_status @ VM 138 (R 只读)]\n$ ls -la /sandbox/\n%s\n```" % body
            else:
                reply_text += "\n(隔离区读取失败:%s;已断开隧道)" % snap.get("error", "?")
        took = round((time.time() - t0) * 1000)
        # 持久化:用户消息与 AI 回复双写(刷新/重开浏览器不丢)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            append_chat(sid, {"role": "user", "content": message, "ts": ts})
            append_chat(sid, {"role": "assistant", "content": reply_text,
                              "ts": ts, "source": source})
        except Exception as e:
            log("聊天持久化失败: %s" % type(e).__name__)
        log("chat: src=%s acts=%s took=%dms msg=%r" %
            (source, [a.get("action") for a in actions], took, message[:40]))
        self._send(200, {"reply": reply_text, "actions": actions,
                         "source": source, "took_ms": took,
                         "session": sid})


def main():
    ensure_state()
    log("W76b desktop config root=%s port=%d bind=%s vm=%s screenshot=%s"
        % (STATE_ROOT, PORT, BIND_HOST,
           "enabled" if VM_ENABLED else "disabled", screenshot_backend()))
    # W76：桌面控制面只绑 loopback。远程查看用
    #   ssh -L 8091:127.0.0.1:8091 jack66g@192.168.245.136
    srv = ThreadingHTTPServer((BIND_HOST, PORT), Handler)
    srv.daemon_threads = True
    threading.Thread(target=vm_housekeeping, daemon=True).start()
    log("IMG-1 demo server listening on %s:%d (loopback only; W76 desktop API)"
        % (BIND_HOST, PORT))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
