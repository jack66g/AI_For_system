// SPDX-License-Identifier: GPL-2.0
// AIKernel IMG-1 前端逻辑:AI 对话第一屏 + 可切换传统桌面 + 全组件主题引擎
/* global fetch, document, window */
"use strict";

var $ = function (id) { return document.getElementById(id); };
var state = {
  theme: null, current: "dark", themes: {},
  apps: [], history: [], busy: false, aiSource: null,
  session: "default", wallpapers: [],
  windows: [], windowsInit: false, lastWinCount: 0
};
var iconOrder = null;
try { iconOrder = JSON.parse(localStorage.getItem("img1-icon-order") || "null"); } catch (e) {}

/* ---------------- 时钟 ---------------- */
function tickClock() {
  var d = new Date();
  var p = function (n) { return (n < 10 ? "0" : "") + n; };
  var wd = ["日", "一", "二", "三", "四", "五", "六"][d.getDay()];
  $("clock-time").textContent = p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  $("clock-date").textContent = d.getFullYear() + "年" + (d.getMonth() + 1) + "月" + d.getDate() + "日 · 周" + wd;
  $("tb-clock").textContent = p(d.getHours()) + ":" + p(d.getMinutes());
}

/* ---------------- 主题引擎 ---------------- */
function applyTheme(name, persist) {
  var t = state.themes[name];
  if (!t) { return; }
  state.current = name;
  document.body.dataset.theme = name;
  var root = document.documentElement.style;
  var keys = ["bg", "bg2", "panel", "panel_solid", "text", "text_dim", "accent",
    "accent_soft", "accent2", "border", "shadow", "wallpaper",
    "bubble_ai", "bubble_user"];
  keys.forEach(function (k) { if (t[k]) { root.setProperty("--" + k, t[k]); } });
  document.querySelectorAll("[data-theme-pick]").forEach(function (b) {
    b.style.fontWeight = (b.dataset.themePick === name) ? "700" : "400";
  });
  if (persist) {
    fetch("/api/theme", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: name })
    }).catch(function () {});
    // 主题联动壁纸:切主题自动配该主题的 AI 壁纸(无则回落渐变)
    var wf = t.wallpaper_file;
    setWallpaper(wf && state.wallpapers.indexOf(wf) >= 0 ? wf : "gradient",
                 true);
  }
}

/* ---------------- 壁纸引擎 ---------------- */
function setWallpaper(name, persist) {
  var el = document.querySelector(".desktop-view .wallpaper");
  if (!el) { return; }
  if (name && name !== "gradient") {
    el.style.backgroundImage = "url(/static/wallpapers/" + name +
      ".png), var(--wallpaper)";
    el.style.backgroundSize = "cover, 220% 220%";
    el.style.animation = "none";
  } else {
    el.style.backgroundImage = "";
    el.style.backgroundSize = "";
    el.style.animation = "";
  }
  if (persist) {
    fetch("/api/wallpaper", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ wallpaper: name })
    }).catch(function () {});
    if (name !== "gradient") {
      notify("壁纸已更换", "AI 画廊壁纸:" + name, "wallpaper");
    }
  }
}

function loadWallpaper() {
  fetch("/api/wallpaper").then(function (r) { return r.json(); })
    .then(function (j) {
      state.wallpapers = j.available || [];
      setWallpaper(j.current || "gradient", false);
    }).catch(function () { state.wallpapers = []; });
}

function loadTheme() {
  fetch("/api/theme").then(function (r) { return r.json(); }).then(function (j) {
    state.themes = j.themes || {};
    applyTheme(j.current || "dark", false);
  }).catch(function () {});
}

/* ---------------- W76 桌面窗口(服务端虚拟状态,AI 与人类共用) ---------------- */
function renderWindows(list) {
  var layer = $("win-layer");
  if (!layer) { return; }
  var sig = JSON.stringify((list || []).map(function (w) {
    return [w.id, w.title, w.focused, w.z, w.text, w.geometry, w.app];
  }));
  if (layer.dataset.sig === sig) { return; }
  layer.dataset.sig = sig;
  layer.innerHTML = "";
  (list || []).slice().sort(function (a, b) { return a.z - b.z; })
    .forEach(function (w) {
      var g = w.geometry || { x: 120, y: 96, w: 520, h: 320 };
      var el = document.createElement("div");
      el.className = "win" + (w.focused ? " focused" : "");
      el.dataset.id = w.id;
      el.style.left = g.x + "px";
      el.style.top = g.y + "px";
      el.style.width = g.w + "px";
      el.style.height = g.h + "px";
      el.style.zIndex = 10 + (w.z || 0);
      var bar = document.createElement("div");
      bar.className = "win-bar";
      var title = document.createElement("span");
      title.className = "win-title";
      title.textContent = w.title;
      var close = document.createElement("button");
      close.className = "win-close";
      close.textContent = "✕";
      close.title = "关闭窗口";
      close.addEventListener("click", function (e) {
        e.stopPropagation();
        fetch("/api/windows/close", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: w.id })
        }).then(refreshDesktop).catch(function () {});
      });
      bar.appendChild(title);
      bar.appendChild(close);
      var body = document.createElement("div");
      body.className = "win-body";
      body.textContent = w.text || "";
      var cursor = document.createElement("span");
      cursor.className = "win-cursor";
      cursor.textContent = w.focused ? "▍" : "";
      var line = document.createElement("div");
      line.className = "win-line";
      line.appendChild(body);
      line.appendChild(cursor);
      el.appendChild(bar);
      el.appendChild(line);
      el.addEventListener("mousedown", function () {
        fetch("/api/windows/focus", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: w.id })
        }).then(refreshDesktop).catch(function () {});
      });
      layer.appendChild(el);
    });
  var run = $("tb-running");
  if (run) {
    if (!list || !list.length) {
      run.innerHTML = '<span class="tb-hint">没有正在运行的应用</span>';
    } else {
      run.innerHTML = list.map(function (w) {
        return '<span class="tb-btn active">' + esc(w.app_name || w.app) +
          "</span>";
      }).join("");
    }
  }
}

function refreshDesktop() {
  return fetch("/api/windows").then(function (r) { return r.json(); })
    .then(function (j) {
      var list = j.windows || [];
      if (!state.windowsInit) {
        state.windowsInit = true;
        if (j.mode === "desktop") { setMode("desktop"); }
      } else if (list.length > state.lastWinCount) {
        setMode("desktop");   // AI 新开窗口时自动切到桌面
      }
      state.lastWinCount = list.length;
      state.windows = list;
      if (j.theme && j.theme.current && state.themes[j.theme.current] &&
          state.current !== j.theme.current) {
        applyTheme(j.theme.current, false);
      }
      if (j.wallpaper) { setWallpaper(j.wallpaper, false); }
      renderWindows(list);
    }).catch(function () {});
}

/* ---------------- 模式切换 ---------------- */
function setMode(mode) {
  document.body.dataset.mode = mode;
  $("btn-mode").title = mode === "ai" ? "切换到桌面" : "切换到 AI";
  toast(mode === "ai" ? "已回到 AI 对话" : "已进入传统桌面");
}

/* ---------------- Toast ---------------- */
var toastTimer = null;
function toast(text) {
  var t = $("toast");
  t.textContent = text;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function () { t.classList.remove("show"); }, 2600);
}

/* ---------------- 应用列表 ---------------- */
var TILE_COLORS = ["#4f8cff", "#7ee787", "#ff5fa2", "#b36bff", "#ffa94d",
  "#38d9a9", "#74c0fc", "#f783ac", "#69db7c", "#9775fa"];

function tileColor(name) {
  var h = 0;
  for (var i = 0; i < name.length; i++) { h = (h * 31 + name.charCodeAt(i)) >>> 0; }
  return TILE_COLORS[h % TILE_COLORS.length];
}

function dispName(app) { return app.name_zh || app.name; }

function iconHtml(app) {
  if (app.icon) {
    return '<img src="' + app.icon + '" alt="' + esc(dispName(app)) + '" loading="lazy">';
  }
  return '<div class="tile" style="background:' + tileColor(app.name) + '">' +
    esc(app.name.charAt(0).toUpperCase()) + "</div>";
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function loadApps() {
  return fetch("/api/apps").then(function (r) { return r.json(); })
    .then(function (j) {
      state.apps = j.apps || [];
      $("drawer-count").textContent = "(" + state.apps.length + ")";
      renderDesktopIcons();
      buildCatRow();
      renderDrawer("");
    }).catch(function () {
      toast("应用列表加载失败");
    });
}

/* 桌面网格:核心应用固定置顶,其余按字母序 */
var PINNED = ["firefox", "nautilus", "org.gnome.nautilus", "files",
  "terminal", "console", "gnome-control-center", "settings",
  "texteditor", "gedit", "org.gnome.texteditor", "calculator",
  "software", "snap-store"];

function pinScore(app) {
  var id = app.id.toLowerCase();
  for (var i = 0; i < PINNED.length; i++) {
    if (id.indexOf(PINNED[i]) >= 0) { return i; }
  }
  return 99;
}

function renderDesktopIcons() {
  var list = state.apps.slice().sort(function (a, b) {
    var d = pinScore(a) - pinScore(b);
    return d !== 0 ? d : dispName(a).localeCompare(dispName(b), "zh");
  });
  if (iconOrder) {  // 用户拖拽顺序(组内生效,置顶组仍优先)
    list.sort(function (a, b) {
      var pa = pinScore(a), pb = pinScore(b);
      if (pa !== pb) { return pa - pb; }
      var ia = iconOrder.indexOf(a.id), ib = iconOrder.indexOf(b.id);
      if (ia === -1 && ib === -1) { return 0; }
      if (ia === -1) { return 1; }
      if (ib === -1) { return -1; }
      return ia - ib;
    });
  }
  var g = $("icon-grid");
  g.innerHTML = list.slice(0, 30).map(function (a) {
    return '<div class="dicon" data-id="' + esc(a.id) +
      '" draggable="true">' + iconHtml(a) +
      '<div class="name">' + esc(dispName(a)) + "</div></div>";
  }).join("");
}

/* 抽屉分类过滤(分类中文化) */
var CAT_ZH = { Utility: "工具", Game: "游戏", Office: "办公", Network: "网络",
  AudioVideo: "影音", Graphics: "图形", Development: "开发", Education: "教育",
  Science: "科学", System: "系统", Settings: "设置", TextEditor: "文本",
  FileManager: "文件" };

var catState = "";

function buildCatRow() {
  var freq = {};
  state.apps.forEach(function (a) {
    (a.categories || []).forEach(function (c) {
      if (CAT_ZH[c]) { freq[c] = (freq[c] || 0) + 1; }
    });
  });
  var tops = Object.keys(freq).sort(function (a, b) {
    return freq[b] - freq[a];
  }).slice(0, 7);
  var row = $("cat-row");
  var html = '<button class="cat-chip active" data-cat="">全部(' +
    state.apps.length + ")</button>";
  tops.forEach(function (c) {
    html += '<button class="cat-chip" data-cat="' + c + '">' + CAT_ZH[c] +
      "(" + freq[c] + ")</button>";
  });
  row.innerHTML = html;
  row.querySelectorAll(".cat-chip").forEach(function (b) {
    b.addEventListener("click", function () {
      catState = b.dataset.cat;
      row.querySelectorAll(".cat-chip").forEach(function (x) {
        x.classList.toggle("active", x === b);
      });
      renderDrawer($("drawer-search").value);
    });
  });
}

function renderDrawer(filter) {
  var q = (filter || "").toLowerCase();
  var list = state.apps.filter(function (a) {
    if (catState && (a.categories || []).indexOf(catState) < 0) { return false; }
    var hay = [a.name, a.name_en, a.comment];
    if (a.name_zh) { hay.push(a.name_zh); }
    return !q || hay.some(function (s) {
      return (s || "").toLowerCase().indexOf(q) >= 0;
    });
  });
  var g = $("drawer-grid");
  g.innerHTML = list.map(function (a) {
    return '<div class="gicon" data-id="' + esc(a.id) + '" title="' +
      esc(a.comment || dispName(a)) + '">' + iconHtml(a) +
      '<div class="name">' + esc(dispName(a)) + "</div>" +
      (a.comment ? '<div class="comment">' + esc(a.comment) + "</div>" : "") +
      "</div>";
  }).join("") || '<div style="grid-column:1/-1;text-align:center;color:var(--text_dim);padding:40px">没有匹配的应用</div>';
}

function openDrawer() { $("drawer").classList.add("open"); }
function closeDrawer() { $("drawer").classList.remove("open"); }

/* ---------------- 聊天 ---------------- */
/* 富文本(最小实现):``` 围栏渲染为终端块,其余文本转义 */
function renderRich(el, text) {
  var parts = String(text).split("```");
  if (parts.length === 1) { el.textContent = text; return; }
  var html = "";
  for (var i = 0; i < parts.length; i++) {
    if (i % 2 === 1) {
      var block = parts[i].replace(/^[A-Za-z0-9_+-]*\r?\n/, ""); // 去语言标记行
      html += '<pre class="term">' + esc(block) + "</pre>";
    } else {
      html += esc(parts[i]);
    }
  }
  el.innerHTML = html;
}

function addMsg(role, text, srcTag, typewriter) {
  var wrap = document.createElement("div");
  wrap.className = "msg " + role;
  var av = document.createElement("div");
  av.className = "avatar";
  av.textContent = role === "ai" ? "AI" : "我";
  var col = document.createElement("div");
  var bub = document.createElement("div");
  bub.className = "bubble";
  col.appendChild(bub);
  if (srcTag) {
    var tag = document.createElement("div");
    tag.className = "src-tag";
    tag.textContent = srcTag;
    col.appendChild(tag);
  }
  wrap.appendChild(av);
  wrap.appendChild(col);
  $("chat-scroll").appendChild(wrap);
  $("chat-scroll").scrollTop = $("chat-scroll").scrollHeight;

  if (!typewriter) {
    renderRich(bub, text);
    return Promise.resolve();
  }
  if (String(text).indexOf("```") < 0) {
    return new Promise(function (done) {
      var i = 0;
      var timer = setInterval(function () {
        i = Math.min(text.length, i + 3);
        bub.textContent = text.slice(0, i);
        $("chat-scroll").scrollTop = $("chat-scroll").scrollHeight;
        if (i >= text.length) { clearInterval(timer); done(); }
      }, 14);
    });
  }
  // 含代码块:先打字机纯文本,完成后富渲染
  return new Promise(function (done) {
    var i = 0;
    var timer = setInterval(function () {
      i = Math.min(text.length, i + 4);
      bub.textContent = text.slice(0, i);
      $("chat-scroll").scrollTop = $("chat-scroll").scrollHeight;
      if (i >= text.length) {
        clearInterval(timer);
        renderRich(bub, text);
        done();
      }
    }, 10);
  });
}

function showTyping() {
  var wrap = document.createElement("div");
  wrap.className = "msg ai";
  wrap.id = "typing-row";
  wrap.innerHTML = '<div class="avatar">AI</div><div><div class="bubble">' +
    '<span class="typing"><i></i><i></i><i></i></span></div></div>';
  $("chat-scroll").appendChild(wrap);
  $("chat-scroll").scrollTop = $("chat-scroll").scrollHeight;
}
function hideTyping() {
  var t = $("typing-row");
  if (t) { t.remove(); }
}

/* 动作执行:AI 语音命令驱动 UI 的核心 */
function execActions(actions) {
  (actions || []).forEach(function (a) {
    if (!a || !a.action) { return; }
    if (a.action === "show_apps") {
      openDrawer();
      notify("应用抽屉已打开", "AI 指令:显示已装应用(" +
        state.apps.length + " 款)", "show_apps");
    } else if (a.action === "set_theme" && a.theme) {
      applyTheme(a.theme, true);
      var t = state.themes[a.theme] || {};
      toast("主题已切换:" + (t.display || a.theme));
      notify("主题已切换", (t.display || a.theme) + "主题已全系统生效",
             "theme");
    } else if (a.action === "switch_mode" && a.mode) {
      setMode(a.mode);
      notify("界面模式切换", a.mode === "ai" ? "已回到 AI 对话"
             : "已进入传统桌面", "theme");
    } else if (a.action === "open_app" && a.app) {
      var known = state.apps.some(function (x) { return x.id === a.app; });
      if (!known) {
        toast("AI 提到的应用「" + (a.name || a.app) + "」不在本机,已忽略");
        return;
      }
      openDrawer();
      // 定位并高亮目标应用
      setTimeout(function () {
        var el = document.querySelector(
          '.gicon[data-id="' + a.app + '"],.dicon[data-id="' + a.app + '"]');
        if (el) {
          el.scrollIntoView({ behavior: "smooth", block: "center" });
          el.classList.add("pulse");
          setTimeout(function () { el.classList.remove("pulse"); }, 2600);
        }
      }, 380);
      toast("AI 已定位应用:「" + (a.name || a.app) + "」");
    } else if (a.action === "get_status") {
      refreshStats();
    } else if (a.action === "get_vm_status") {
      probeVM();
    }
  });
}

/* VM 真系统探测(按需,不做周期轮询;隧道空闲自动关) */
function probeVM() {
  var b = $("badge-vm");
  b.textContent = "VM:探测中";
  fetch("/api/vm/status").then(function (r) { return r.json(); })
    .then(function (j) {
      if (j && j.reachable) {
        b.textContent = "VM:在线";
        b.classList.add("ok");
        toast("已接入生产 VM 138 真系统(只读),实况见聊天终端块");
        notify("VM 已连接", "生产 VM 138 真系统接入成功(只读)", "vm");
        probeVmAi().then(function (ai) {
          if (ai && ai.ai && ai.ai.enabled) {
            b.textContent = "VM:在线·AI 内核开";
            notify("AI 内核在线",
              "VM AI 子系统运行中,模型 " + (ai.ai.model || "n/a") +
              ",遥测事件 " + (ai.ai.telemetry_emitted || 0).toLocaleString(),
              "vm");
          }
        });
      } else {
        b.textContent = "VM:不可达";
        b.classList.remove("ok");
        toast("VM 138 不可达:" + ((j && j.error) || "未知") + ";隧道已断开");
        notify("VM 连接断开", "VM 138 不可达:" + ((j && j.error) || "未知"),
               "vm");
      }
    }).catch(function () {
      b.textContent = "VM:不可达";
      b.classList.remove("ok");
    });
}

function srcLabel(src) {
  if (src === "forwarder") { return "AIKernel 转发器 · DeepSeek"; }
  if (src === "direct") { return "DeepSeek 直连"; }
  if (src === "demo") { return "演示应答器(云端不可达)"; }
  return "";
}

function sendChat(text) {
  text = (text || "").trim();
  if (!text || state.busy) { return; }
  state.busy = true;
  $("btn-send").disabled = true;
  addMsg("user", text, null, false);
  showTyping();
  var t0 = Date.now();
  fetch("/api/chat", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: text, session: state.session })
  }).then(function (r) { return r.json(); })
    .then(function (j) {
      hideTyping();
      var took = ((Date.now() - t0) / 1000).toFixed(1);
      var label = srcLabel(j.source);
      state.aiSource = j.source;
      updateAiBadge();
      if (j.session) {
        state.session = j.session;
        try { localStorage.setItem("img1-session", state.session); } catch (e) {}
      }
      $("chat-meta").textContent = "回复来源:" + label + " · 耗时 " + took + "s" +
        (j.actions && j.actions.length ? " · 已执行 " + j.actions.length + " 个界面动作" : "");
      notify("AI 回复完成", (j.reply || "").slice(0, 60), "chat");
      addMsg("ai", j.reply || "(空回复)", label, true).then(function () {
        execActions(j.actions);
      });
      state.history.push({ role: "user", content: text });
      state.history.push({ role: "assistant", content: j.reply || "" });
    })
    .catch(function () {
      hideTyping();
      addMsg("ai", "网络错误:无法连接 AIKernel 本地服务(8091)。", null, false);
    })
    .then(function () {
      state.busy = false;
      $("btn-send").disabled = false;
    });
}

/* ---------------- 会话持久化 ---------------- */
function loadHistory() {
  fetch("/api/chat/history?session=" + encodeURIComponent(state.session))
    .then(function (r) { return r.json(); })
    .then(function (j) {
      var msgs = j.messages || [];
      msgs.forEach(function (m) {
        if (m.role === "user") { addMsg("user", m.content, null, false); }
        else if (m.role === "assistant") {
          addMsg("ai", m.content, srcLabel(m.source), false);
        }
      });
      if (msgs.length) {
        $("chat-meta").textContent = "已恢复会话 " + state.session +
          "(" + msgs.length + " 条历史),AI 记得之前聊过什么";
        $("chat-scroll").scrollTop = $("chat-scroll").scrollHeight;
      }
    }).catch(function () {});
}

function newChat() {
  fetch("/api/chat/new", { method: "POST" })
    .then(function (r) { return r.json(); })
    .then(function (j) {
      state.session = j.session;
      try { localStorage.setItem("img1-session", state.session); } catch (e) {}
      state.history = [];
      $("chat-scroll").innerHTML = "";
      addMsg("ai", "新会话已开始。之前的内容已存档,我可以随时接着聊。", null, false);
      $("chat-meta").textContent = "会话 " + state.session;
    })
    .catch(function () { toast("新会话创建失败"); });
}

/* ---------------- 状态徽章 ---------------- */
function refreshStats() {
  fetch("/api/stats").then(function (r) { return r.json(); }).then(function (s) {
    $("badge-load").textContent = "负载 " + (s.load1 != null ? s.load1.toFixed(2) : "--") + "/" + (s.cores || "?") + "核";
    $("badge-mem").textContent = "内存 " + (s.mem_used_pct != null ? s.mem_used_pct + "%" : "--");
    // AI 呼吸光晕跟随负载:忙时更亮更快
    var l = s.load1 || 0;
    var root = document.documentElement.style;
    root.setProperty("--orb-glow", Math.min(1, 0.25 + l / 3).toFixed(2));
    root.setProperty("--orb-speed", l > 1.5 ? "2.2s" : (l > 0.6 ? "3.4s" : "5s"));
  }).catch(function () {});
}

function updateAiBadge() {
  var b = $("badge-ai");
  if (state.aiSource === "demo") {
    b.textContent = "AI:演示模式";
    b.classList.remove("ok");
  } else if (state.aiSource) {
    b.textContent = "AI:DeepSeek 在线";
    b.classList.add("ok");
  }
}

function probeModel() {
  fetch("/api/model").then(function (r) { return r.json(); }).then(function (m) {
    if (!state.aiSource) {
      $("badge-ai").textContent = m.key_loaded ? "AI:云端已配置" : "AI:无密钥";
    }
  }).catch(function () {});
}

/* ---------------- 电源菜单 ---------------- */
function toggleMenu(id) {
  var m = $(id);
  var open = !m.classList.contains("open");
  document.querySelectorAll(".power-menu,.theme-menu").forEach(function (x) {
    x.classList.remove("open");
  });
  if (open) { m.classList.add("open"); }
}

var iconOrder = null;
try { iconOrder = JSON.parse(localStorage.getItem("img1-icon-order") || "null"); } catch (e) {}
state.notifs = [];
state.unread = 0;
state.vmAi = null;

/* ---------------- 通知中心(持久化到 data/notifs.json,上限 100) ---------------- */
var notifSaveTimer = null;

function saveNotifs() {
  clearTimeout(notifSaveTimer);
  notifSaveTimer = setTimeout(function () {
    fetch("/api/notifs", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ notifs: state.notifs.slice(0, 100) })
    }).catch(function () {});
  }, 800);
}

function loadNotifs() {
  fetch("/api/notifs").then(function (r) { return r.json(); })
    .then(function (j) {
      if (Array.isArray(j) && j.length) {
        state.notifs = j;
        renderNotifs();
      }
    }).catch(function () {});
}

function notify(title, body, tag) {
  state.notifs.unshift({
    title: title, body: body || "", tag: tag || "",
    time: new Date().toTimeString().slice(0, 5)
  });
  if (state.notifs.length > 50) { state.notifs.length = 50; }
  state.unread += 1;
  var b = $("bell-count");
  b.hidden = false;
  b.textContent = state.unread > 9 ? "9+" : state.unread;
  renderNotifs();
  saveNotifs();
}

function renderNotifs() {
  var l = $("notif-list");
  if (!state.notifs.length) {
    l.innerHTML = '<div class="notif-empty">暂无通知</div>';
    return;
  }
  l.innerHTML = state.notifs.map(function (n, i) {
    return '<div class="notif-item" data-i="' + i + '" data-tag="' +
      esc(n.tag) + '"><div class="nt">' + esc(n.title) + "</div>" +
      (n.body ? '<div class="nb">' + esc(n.body) + "</div>" : "") +
      '<div class="ntm">' + esc(n.time) + "</div></div>";
  }).join("");
}

function jumpTag(tag) {
  if (tag === "show_apps") { openDrawer(); }
  else if (tag === "theme") { $("btn-theme").click(); }
  else if (tag === "wallpaper") { setMode("desktop"); }
  else if (tag === "vm") { probeVM(); }
  else if (tag === "chat") { setMode("ai"); }
  else if (tag === "sessions") { loadSessions(); }
}

/* ---------------- sparkline 仪表 ---------------- */
function sparkline(svgId, data, maxV) {
  var svg = $(svgId);
  var pl = svg.querySelector("polyline");
  if (!data || data.length < 2) { pl.setAttribute("points", ""); return; }
  var max = Math.max(maxV, Math.max.apply(null, data) * 1.15, 0.001);
  var pts = data.map(function (v, i) {
    var x = 120 * i / (data.length - 1);
    var y = 30 - 28 * (v / max);
    return x.toFixed(1) + "," + Math.max(2, y).toFixed(1);
  }).join(" ");
  pl.setAttribute("points", pts);
}

function renderSpark() {
  if (!$("spark-panel").classList.contains("open")) { return; }
  fetch("/api/stats").then(function (r) { return r.json(); })
    .then(function (s) {
      sparkline("spark-load", s.hist.load, 1.0);
      sparkline("spark-mem", s.hist.mem, 100);
      $("spark-load-now").textContent =
        (s.hist.load.slice(-1)[0] || 0).toFixed(2);
      $("spark-mem-now").textContent =
        (s.hist.mem.slice(-1)[0] || 0).toFixed(0) + "%";
      if (state.vmAi) {
        var a = state.vmAi;
        $("spark-vm").textContent = "VM AI 内核:" +
          (a.ai && a.ai.enabled ? "运行中" : "已停用") +
          " · 模型 " + (a.ai && a.ai.model || "n/a") +
          " · 遥测事件 " + (a.ai ? a.ai.telemetry_emitted.toLocaleString() : "n/a") +
          " · 负载 " + (a.load1 != null ? a.load1.toFixed(2) : "n/a");
      }
    }).catch(function () {});
}

/* ---------------- 会话管理器 ---------------- */
function loadSessions() {
  fetch("/api/chat/sessions").then(function (r) { return r.json(); })
    .then(function (j) {
      var list = j.sessions || [];
      var l = $("sess-list");
      l.innerHTML = list.map(function (s) {
        return '<div class="sess-item' +
          (s.id === state.session ? " current" : "") + '" data-id="' +
          esc(s.id) + '"><div class="st"><span class="s-title">' +
          esc(s.title) + "</span></div>" +
          '<div class="si"><span>' + esc(s.id) + "</span><span>" +
          s.count + " 条</span>" +
          '<span class="sact ren" data-id="' + esc(s.id) + '">改名</span>' +
          '<span class="sact del" data-id="' + esc(s.id) + '">删除</span>' +
          "</div></div>";
      }).join("") || '<div class="notif-empty">还没有会话</div>';
      $("sessions-panel").classList.add("open");
    }).catch(function () { toast("会话列表加载失败"); });
}

function switchSession(sid) {
  state.session = sid;
  try { localStorage.setItem("img1-session", sid); } catch (e) {}
  state.history = [];
  $("chat-scroll").innerHTML = "";
  loadHistory();
  $("sessions-panel").classList.remove("open");
  toast("已切换会话:" + sid);
}

function bindSessions() {
  $("sess-list").addEventListener("click", function (e) {
    var ren = e.target.closest(".sact.ren");
    var del = e.target.closest(".sact.del");
    var item = e.target.closest(".sess-item");
    if (!item) { return; }
    var sid = item.dataset.id;
    if (ren) {
      e.stopPropagation();
      var span = item.querySelector(".s-title");
      if (span.querySelector("input")) { return; }
      var old = span.textContent;
      span.innerHTML = '<input value="' + esc(old) + '" maxlength="40">';
      var inp = span.querySelector("input");
      inp.focus();
      var commit = function () {
        var v = inp.value.trim();
        if (v && v !== old) {
          fetch("/api/chat/rename", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session: sid, title: v })
          }).then(function () { loadSessions(); });
        } else { loadSessions(); }
      };
      inp.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") { commit(); }
      });
      inp.addEventListener("blur", commit);
      return;
    }
    if (del) {
      e.stopPropagation();
      fetch("/api/chat/delete", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session: sid })
      }).then(function (r) { return r.json(); })
        .then(function (j) {
          toast(j.ok ? "会话已删除" : "删除失败");
          if (sid === state.session) { newChat(); }
          loadSessions();
        });
      return;
    }
    if (sid !== state.session) { switchSession(sid); }
    else { $("sessions-panel").classList.remove("open"); }
  });
}

/* ---------------- VM AI 内核遥测徽章 ---------------- */
function probeVmAi() {
  return fetch("/api/vm/ai").then(function (r) { return r.json(); })
    .then(function (j) {
      if (j.reachable) {
        state.vmAi = j;
        var a = j.ai || {};
        $("spark-vm").textContent = "VM AI 内核:" +
          (a.enabled ? "运行中" : "已停用") +
          " · 模型 " + (a.model || "n/a") +
          " · 遥测事件 " + (a.telemetry_emitted || 0).toLocaleString();
        return j;
      }
      state.vmAi = null;
      return null;
    }).catch(function () { return null; });
}

/* ---------------- 锁屏 PIN ---------------- */
function lockScreen() {
  $("lockscreen").classList.add("on");
  tickLock();
  fetch("/api/pin/status").then(function (r) { return r.json(); })
    .then(function (j) {
      var row = $("lock-pin-row");
      if (j.enabled) {
        row.hidden = false;
        $("lock-hint").textContent = "输入 PIN 解锁";
        $("lock-pin-input").focus();
      } else {
        row.hidden = true;
        $("lock-hint").textContent = "点击任意处解锁";
      }
    }).catch(function () {});
}

function verifyPin() {
  var pin = $("lock-pin-input").value.trim();
  if (!pin) { return; }
  fetch("/api/pin/verify", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pin: pin })
  }).then(function (r) { return r.json(); })
    .then(function (j) {
      if (j.ok) {
        $("lockscreen").classList.remove("on");
        $("lock-pin-input").value = "";
        $("lock-hint").textContent = "点击任意处解锁";
      } else if (j.locked) {
        $("lock-hint").textContent = "错误过多,已锁定 " + j.retry_after + " 秒";
        var left = j.retry_after;
        var t = setInterval(function () {
          left -= 1;
          if (left <= 0) {
            clearInterval(t);
            $("lock-hint").textContent = "请再试一次";
          } else {
            $("lock-hint").textContent = "错误过多,已锁定 " + left + " 秒";
          }
        }, 1000);
      } else {
        $("lock-hint").textContent = "PIN 错误(" + (j.fails || 1) + "/3)";
        $("lock-pin-input").value = "";
      }
    }).catch(function () { toast("PIN 校验失败:服务不可达"); });
}
/* ---------------- 决策流面板(VM /proc/ai 只读) ---------------- */
var CAT_NAMES = {18: "决策"};

function loadAiops() {
  $("aiops-panel").classList.add("open");
  var body = $("aiops-body");
  body.innerHTML = '<div class="aiops-na">读取 VM /proc/ai …(SSH 只读)</div>';
  fetch("/api/vm/aiops").then(function (r) { return r.json(); })
    .then(function (j) {
      if (!j.reachable) {
        body.innerHTML = '<div class="aiops-na">VM 不可达:' +
          esc(j.error || "?") + "<br>隧道已断开,可从顶栏 VM 徽章重试。</div>";
        return;
      }
      var html = "";
      if (j.decisions_empty) {
        html += '<div class="aiops-sec">决策记录</div>' +
          '<div class="aiops-na">决策 ring 为空(0 字节):引擎暂未产出' +
          "决策记录。如实呈现,不做模拟。</div>";
      } else {
        html += '<div class="aiops-sec">决策记录</div><div class="aiops-pre">' +
          esc(j.decisions_raw) + "</div>";
      }
      html += '<div class="aiops-sec">遥测事件流(tail 采样 ' +
        j.events.length + " 条)</div>";
      if (j.events.length) {
        html += '<table class="aiops-table"><tr><th>时间*</th><th>pid</th>' +
          "<th>cpu</th><th>类型</th><th>len</th></tr>";
        j.events.slice().reverse().forEach(function (ev) {
          var cat = CAT_NAMES[ev.cat] ? (CAT_NAMES[ev.cat] + "/" + ev.cat)
                                      : ("cat=" + ev.cat);
          html += "<tr><td>" + ev.ts + "</td><td>" + ev.pid + "</td><td>" +
            ev.cpu + '</td><td class="' + (ev.cat === 18 ? "cat18" : "") +
            '">' + cat + " ev=" + ev.ev + "</td><td>" + ev.len + "</td></tr>";
        });
        html += "</table>" +
          '<div class="aiops-na">*ts 为内核单调时间戳(原始值);' +
          "当前采样窗口内未见 cat=18 决策事件,以真实数据为准。</div>";
      } else {
        html += '<div class="aiops-na">采样窗口内无遥测事件。</div>';
      }
      body.innerHTML = html;
    }).catch(function () {
      body.innerHTML = '<div class="aiops-na">请求失败:本地服务不可达。</div>';
    });
}

var dragId = null;

function reorderIcons(srcId, dstId) {
  var g = $("icon-grid");
  var ids = Array.prototype.map.call(
    g.querySelectorAll(".dicon"), function (x) { return x.dataset.id; });
  var from = ids.indexOf(srcId), to = ids.indexOf(dstId);
  if (from < 0 || to < 0) { return; }
  ids.splice(to, 0, ids.splice(from, 1)[0]);
  iconOrder = ids;
  try { localStorage.setItem("img1-icon-order", JSON.stringify(ids)); } catch (e) {}
  renderDesktopIcons();
  toast("图标已重排(本机保存)");
}

function bindDrag() {
  var g = $("icon-grid");
  g.addEventListener("dragstart", function (e) {
    var el = e.target.closest(".dicon");
    if (!el) { return; }
    dragId = el.dataset.id;
    e.dataTransfer.setData("text/plain", dragId);
  });
  g.addEventListener("dragover", function (e) { e.preventDefault(); });
  g.addEventListener("drop", function (e) {
    e.preventDefault();
    var target = e.target.closest(".dicon");
    if (target && dragId && target.dataset.id !== dragId) {
      reorderIcons(dragId, target.dataset.id);
    }
    dragId = null;
  });
}

/* ---------------- 设置面板(自定义主题) ---------------- */
function openSettings() {
  $("settings").classList.add("open");
  refreshPinStatus();
}

function refreshPinStatus() {
  fetch("/api/pin/status").then(function (r) { return r.json(); })
    .then(function (j) {
      $("pin-status").textContent = j.enabled
        ? "PIN 已启用" + (j.locked ? "(已临时锁定 " + j.retry_after + "s)" : "")
        : "PIN 未启用(锁屏点击即解锁)";
    }).catch(function () {
      $("pin-status").textContent = "PIN 状态获取失败";
    });
}

function applyCustomTheme() {
  var accent = $("pick-accent").value;
  var base = $("set-base").value;
  fetch("/api/theme", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ custom: { accent: accent, base: base } })
  }).then(function (r) { return r.json(); })
    .then(function (j) {
      if (!j.ok) { toast("自定义主题失败:" + (j.error || "?")); return; }
      state.themes.custom = j.theme;
      applyTheme("custom", true);
      toast("自定义主题已生效并保存(主色 " + accent + ")");
      notify("自定义主题", "主色 " + accent + " 已全系统扇出并持久化",
             "theme");
    }).catch(function () { toast("自定义主题请求失败"); });
}

function openAbout() {
  fetch("/api/health").then(function (r) { return r.json(); })
    .then(function (j) {
      $("about-version").textContent = j.version || "IMG-3";
      $("about-built").textContent = j.built || "--";
    }).catch(function () {});
  $("about-modal").classList.add("open");
}

/* ---------------- 日历 ---------------- */
function renderCal() {
  var d = new Date(), y = d.getFullYear(), m = d.getMonth();
  var first = new Date(y, m, 1).getDay();
  var days = new Date(y, m + 1, 0).getDate();
  var prevDays = new Date(y, m, 0).getDate();
  var html = '<div class="cal-title">' + y + "年" + (m + 1) + "月</div>" +
    '<div class="cal-grid">';
  ["日", "一", "二", "三", "四", "五", "六"].forEach(function (w) {
    html += '<div class="wd">' + w + "</div>";
  });
  for (var i = first - 1; i >= 0; i--) {
    html += '<div class="day dim">' + (prevDays - i) + "</div>";
  }
  for (var dd = 1; dd <= days; dd++) {
    html += '<div class="' + (dd === d.getDate() ? "day today" : "day") + '">' +
      dd + "</div>";
  }
  var tail = (7 - ((first + days) % 7)) % 7;
  for (var k = 1; k <= tail; k++) { html += '<div class="day dim">' + k + "</div>"; }
  $("cal-menu").innerHTML = html + "</div>";
}

function showWallpaperMenu(anchor) {
  var wp = $("wp-menu");
  var html = '<button data-wp="gradient">CSS 渐变(兜底)</button>';
  (state.wallpapers || []).forEach(function (w) {
    html += '<button data-wp="' + w + '">' + w + "</button>";
  });
  wp.innerHTML = html;
  var r = anchor.getBoundingClientRect();
  wp.style.left = Math.min(r.right + 8, window.innerWidth - 200) + "px";
  wp.style.top = Math.min(r.top, window.innerHeight - 60 - (state.wallpapers.length + 1) * 40) + "px";
  wp.classList.add("open");
}

/* ---------------- 桌面右键菜单 ---------------- */
function showCtxMenu(x, y) {
  var m = $("ctx-menu");
  m.classList.add("open");
  var r = m.getBoundingClientRect();
  m.style.left = Math.min(x, window.innerWidth - r.width - 10) + "px";
  m.style.top = Math.min(y, window.innerHeight - r.height - 10) + "px";
}

function bindCtxMenu() {
  var dv = $("desktop-view");
  dv.addEventListener("contextmenu", function (e) {
    if (e.target.closest(".dicon") || e.target.closest(".taskbar")) { return; }
    e.preventDefault();
    showCtxMenu(e.clientX, e.clientY);
  });
  document.addEventListener("click", function (e) {
    if (!e.target.closest("#ctx-menu")) {
      $("ctx-menu").classList.remove("open");
    }
  });
  document.querySelectorAll("[data-ctx]").forEach(function (b) {
    b.addEventListener("click", function () {
      $("ctx-menu").classList.remove("open");
      var act = b.dataset.ctx;
      if (act === "ai") { setMode("ai"); }
      else if (act === "drawer") { openDrawer(); }
      else if (act === "ask") { $("mini-chat").classList.add("open"); }
      else if (act === "wallpaper") { showWallpaperMenu($("ctx-menu")); }
      else if (act === "about") { openAbout(); }
      else if (act.indexOf("theme-") === 0) { applyTheme(act.slice(6), true); }
    });
  });
}

/* ---------------- 迷你聊天窗 ---------------- */
function miniMsg(role, text, src) {
  var el = document.createElement("div");
  el.className = "mmsg " + role;
  el.textContent = text;
  $("mini-msgs").appendChild(el);
  if (src) {
    var s = document.createElement("div");
    s.className = "mini-src";
    s.textContent = src;
    $("mini-msgs").appendChild(s);
  }
  $("mini-msgs").scrollTop = $("mini-msgs").scrollHeight;
}

function sendMini(text) {
  text = (text || "").trim();
  if (!text) { return; }
  var input = $("mini-input");
  miniMsg("user", text);
  input.value = "";
  fetch("/api/chat", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: text, session: state.session })
  }).then(function (r) { return r.json(); })
    .then(function (j) {
      state.aiSource = j.source;
      updateAiBadge();
      miniMsg("ai", j.reply || "(空)", srcLabel(j.source));
      state.history.push({ role: "user", content: text });
      state.history.push({ role: "assistant", content: j.reply || "" });
      execActions(j.actions);
    })
    .catch(function () { miniMsg("ai", "网络错误:无法连接本地服务。"); });
}

/* ---------------- 事件绑定 ---------------- */
function bind() {
  $("btn-send").addEventListener("click", function () {
    var v = $("chat-input").value;
    $("chat-input").value = "";
    sendChat(v);
  });
  $("chat-input").addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      var v = $("chat-input").value;
      $("chat-input").value = "";
      sendChat(v);
    }
  });
  document.querySelectorAll(".chip").forEach(function (c) {
    c.addEventListener("click", function () { sendChat(c.dataset.say); });
  });
  $("btn-mode").addEventListener("click", function () {
    setMode(document.body.dataset.mode === "ai" ? "desktop" : "ai");
  });
  $("tb-ai").addEventListener("click", function () { setMode("ai"); });
  $("tb-ask").addEventListener("click", function () {
    $("mini-chat").classList.toggle("open");
    if ($("mini-chat").classList.contains("open")) { $("mini-input").focus(); }
  });
  $("mini-send").addEventListener("click", function () {
    sendMini($("mini-input").value);
  });
  $("mini-input").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { sendMini($("mini-input").value); }
  });
  $("mini-close").addEventListener("click", function () {
    $("mini-chat").classList.remove("open");
  });
  $("tb-clock").addEventListener("click", function () {
    if ($("cal-menu").classList.contains("open")) {
      $("cal-menu").classList.remove("open");
    } else {
      renderCal();
      $("cal-menu").classList.add("open");
    }
  });
  $("wp-menu").addEventListener("click", function (e) {
    var b = e.target.closest("[data-wp]");
    if (!b) { return; }
    $("wp-menu").classList.remove("open");
    setWallpaper(b.dataset.wp, true);
    toast(b.dataset.wp === "gradient" ? "壁纸:CSS 渐变(兜底)"
                                      : "壁纸已切换:" + b.dataset.wp);
  });
  $("btn-new-chat").addEventListener("click", newChat);
  $("pick-custom-entry").addEventListener("click", function () {
    $("theme-menu").classList.remove("open");
    $("settings").classList.add("open");
  });
  $("pick-accent").addEventListener("input", function () {
    $("pick-hex").textContent = $("pick-accent").value;
  });
  $("settings-apply").addEventListener("click", function () {
    applyCustomTheme();
    $("settings").classList.remove("open");
  });
  $("settings-close").addEventListener("click", function () {
    $("settings").classList.remove("open");
  });
  $("pin-save").addEventListener("click", function () {
    var pin = $("set-pin").value.trim();
    fetch("/api/pin/set", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pin: pin })
    }).then(function (r) { return r.json(); })
    .then(function (j) {
      if (j.ok) {
        $("set-pin").value = "";
        if (j.warning) {
          toast("PIN 已设置,但注意:" + j.warning);
          notify("锁屏 PIN", "PIN 已启用(强度提示:" + j.warning + ")",
                 "settings");
        } else {
          toast("PIN 已设置(仅存 hash)");
          notify("锁屏 PIN", "PIN 已启用", "settings");
        }
      } else { toast("设置失败:" + (j.error || "?")); }
      refreshPinStatus();
    });
  });
  $("pin-clear").addEventListener("click", function () {
    fetch("/api/pin/clear", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        toast(j.ok ? "PIN 已清除" : "清除失败");
        refreshPinStatus();
      });
  });
  $("about-close").addEventListener("click", function () {
    $("about-modal").classList.remove("open");
  });
  [["settings", "settings"], ["about-modal", "about"]].forEach(function (p) {
    $(p[0]).addEventListener("click", function (e) {
      if (e.target === $(p[0])) { $(p[0]).classList.remove("open"); }
    });
  });
  bindDrag();
  bindCtxMenu();
  $("tb-apps").addEventListener("click", function () {
    if ($("drawer").classList.contains("open")) { closeDrawer(); } else { openDrawer(); }
  });
  $("drawer-close").addEventListener("click", closeDrawer);
  $("badge-vm").addEventListener("click", probeVM);
  $("drawer-search").addEventListener("input", function (e) {
    renderDrawer(e.target.value);
  });
  $("btn-theme").addEventListener("click", function (e) {
    e.stopPropagation();
    toggleMenu("theme-menu");
  });
  document.querySelectorAll("[data-theme-pick]").forEach(function (b) {
    b.addEventListener("click", function () {
      applyTheme(b.dataset.themePick, true);
      toggleMenu("theme-menu");
    });
  });
  $("btn-power").addEventListener("click", function (e) {
    e.stopPropagation();
    toggleMenu("power-menu");
  });
  document.querySelectorAll("[data-power]").forEach(function (b) {
    b.addEventListener("click", function () {
      $("power-menu").classList.remove("open");
      if (b.dataset.power === "lock") { lockScreen(); }
      fetch("/api/power", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: b.dataset.power })
      }).then(function (r) { return r.json(); })
        .then(function (j) {
          if (b.dataset.power !== "lock") {
            toast("电源动作「" + b.dataset.power + "」不可用:" +
              (j.error || "backend unavailable"));
          }
        })
        .catch(function () { toast("电源请求失败"); });
    });
  });
  $("lockscreen").addEventListener("click", function (e) {
    if (e.target.closest("#lock-pin-row")) { return; }  // PIN 模式下点击输入区不解锁
    if ($("lock-pin-row").hidden) { $("lockscreen").classList.remove("on"); }
  });
  $("btn-bell").addEventListener("click", function (e) {
    e.stopPropagation();
    toggleMenu("notif-menu");
    renderNotifs();
  });
  $("notif-clear").addEventListener("click", function () {
    state.notifs = [];
    state.unread = 0;
    $("bell-count").hidden = true;
    renderNotifs();
    saveNotifs();
  });
  $("notif-list").addEventListener("click", function (e) {
    var it = e.target.closest(".notif-item");
    if (!it) { return; }
    $("notif-menu").classList.remove("open");
    jumpTag(it.dataset.tag);
  });
  $("badge-load").addEventListener("click", function () {
    $("spark-panel").classList.toggle("open");
    renderSpark();
  });
  $("btn-aiops").addEventListener("click", loadAiops);
  $("btn-aiops2").addEventListener("click", loadAiops);
  $("aiops-close").addEventListener("click", function () {
    $("aiops-panel").classList.remove("open");
  });
  $("aiops-refresh").addEventListener("click", loadAiops);
  $("btn-sessions").addEventListener("click", function () {
    if ($("sessions-panel").classList.contains("open")) {
      $("sessions-panel").classList.remove("open");
    } else { loadSessions(); }
  });
  $("sess-close").addEventListener("click", function () {
    $("sessions-panel").classList.remove("open");
  });
  $("lock-pin-btn").addEventListener("click", verifyPin);
  $("lock-pin-input").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { verifyPin(); }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      $("lockscreen").classList.remove("on");
      closeDrawer();
      $("ctx-menu").classList.remove("open");
      $("mini-chat").classList.remove("open");
      $("wp-menu").classList.remove("open");
      $("cal-menu").classList.remove("open");
      $("notif-menu").classList.remove("open");
      $("spark-panel").classList.remove("open");
      $("sessions-panel").classList.remove("open");
      $("aiops-panel").classList.remove("open");
      $("settings").classList.remove("open");
      $("about-modal").classList.remove("open");
    }
  });
  document.addEventListener("click", function (e) {
    if (!e.target.closest(".power-menu") && !e.target.closest("#btn-power")) {
      $("power-menu").classList.remove("open");
    }
    if (!e.target.closest(".theme-menu") && !e.target.closest("#btn-theme")) {
      $("theme-menu").classList.remove("open");
    }
    if (!e.target.closest("#cal-menu") && !e.target.closest("#tb-clock")) {
      $("cal-menu").classList.remove("open");
    }
    if (!e.target.closest("#wp-menu") && !e.target.closest("#ctx-menu")) {
      $("wp-menu").classList.remove("open");
    }
  });
  // 应用图标点击 -> 与 AI 相同的 /api/apps/launch(虚拟窗口)
  document.addEventListener("click", function (e) {
    var icon = e.target.closest(".gicon,.dicon");
    if (!icon) { return; }
    var app = state.apps.filter(function (a) { return a.id === icon.dataset.id; })[0];
    if (app) {
      fetch("/api/apps/launch", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ app: app.id })
      }).then(function (r) { return r.json(); })
        .then(function (j) {
          if (j.ok) {
            closeDrawer();
            refreshDesktop();
            toast("已打开「" + dispName(app) + "」(demo 虚拟窗口)");
          } else {
            toast("启动失败:" + (j.error || "unknown"));
          }
        }).catch(function () { toast("启动失败"); });
    }
  });
}

function tickLock() {
  if (!$("lockscreen").classList.contains("on")) { return; }
  var d = new Date();
  var p = function (n) { return (n < 10 ? "0" : "") + n; };
  $("lock-time").textContent = p(d.getHours()) + ":" + p(d.getMinutes());
  var wd = ["日", "一", "二", "三", "四", "五", "六"][d.getDay()];
  $("lock-date").textContent = d.getMonth() + 1 + "月" + d.getDate() + "日 · 周" + wd;
  setTimeout(tickLock, 1000);
}

/* ---------------- 开机引导(fake-boot) ---------------- */
var BOOT_LINES = [
  "[ 0.000012] AIKernel 6.18 booting on aikan-desktop",
  "[ 0.102331] Mounted /ai-memory (long-term memories loaded)",
  "[ 0.284110] ai-scheduler: 23 control params online",
  "[ 0.418902] sandbox: /sandbox/ mounted (R-only view)",
  "[ 0.523418] apps: 51 desktop entries indexed",
  "[ 0.688250] theme engine: dark / light / pink ready",
  "[ 0.741993] ai link: deepseek via aikernel relay",
  "[ 0.902377] Reached target AIKernel Graphical Interface"
];

function playBoot() {
  var box = $("boot"), bar = $("boot-bar-fill"), log = $("boot-log");
  var i = 0;
  var li = setInterval(function () {
    i += 1;
    bar.style.width = Math.min(100, i * 14) + "%";
    if (i <= BOOT_LINES.length) {
      var line = document.createElement("div");
      line.textContent = BOOT_LINES[i - 1];
      log.appendChild(line);
      while (log.children.length > 5) { log.removeChild(log.firstChild); }
    }
    if (i >= 8) {
      clearInterval(li);
      setTimeout(function () {
        box.classList.add("done");
        setTimeout(function () { box.remove(); }, 600);
      }, 350);
    }
  }, 150);
}

/* ---------------- 启动 ---------------- */
function boot() {
  playBoot();
  tickClock();
  setInterval(tickClock, 1000);
  try {
    var s = localStorage.getItem("img1-session");
    if (s && /^[A-Za-z0-9_-]{1,64}$/.test(s)) { state.session = s; }
  } catch (e) {}
  loadTheme();
  bind();
  loadApps();
  loadWallpaper();
  loadHistory();
  loadNotifs();
  refreshStats();
  setInterval(refreshStats, 5000);
  refreshDesktop();
  setInterval(refreshDesktop, 1200);
  probeModel();
  if (!$("chat-scroll").children.length) {
    addMsg("ai",
      "你好,我是 AIKernel 的内置 AI。我控制着整个可视化套件:可以帮你列出已装应用、切换主题、切换桌面模式、报告系统状态。直接说,比如「显示我装的 app」。",
      null, true);
  }
}

document.addEventListener("DOMContentLoaded", boot);
