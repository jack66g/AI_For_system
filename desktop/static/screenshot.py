#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# AIKernel IMG-1 截图验收(playwright + chromium)。
# 截四张:AI 首屏 / 桌面模式 / 应用抽屉 / 粉色主题;收集 console error;
# 每张 >30KB 防白屏。用法: python3 tests/screenshot.py [base] [outdir]

import json
import os
import sys
import time

# 磁盘满场景:chromium 装在 /dev/shm(重启即失),优先使用
if os.path.isdir("/dev/shm/ms-playwright"):
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/dev/shm/ms-playwright")

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8091"
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "screenshots")
os.makedirs(OUT, exist_ok=True)

console_errors = []
page_errors = []


def shot(page, name, min_kb=30):
    path = os.path.join(OUT, name)
    page.screenshot(path=path, full_page=False)
    size = os.path.getsize(path)
    ok = size > min_kb * 1024
    print("[%s] %s (%.1f KB)" % ("PASS" if ok else "FAIL", name, size / 1024))
    return ok, path


def main():
    results = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chromium",
                                    args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.on("console", lambda m: console_errors.append(m.text)
                if m.type == "error" else None)
        page.on("pageerror", lambda e: page_errors.append(str(e)))

        page.goto(BASE, wait_until="networkidle", timeout=30000)
        page.wait_for_function(
            "document.getElementById('clock-time').textContent !== '--:--:--'",
            timeout=10000)
        page.wait_for_timeout(2600)  # 等欢迎语打字机结束
        ok, _ = shot(page, "01-ai-first.png")
        results["ai_first"] = ok

        # 桌面模式
        page.click("#btn-mode")
        page.wait_for_timeout(900)
        ok, _ = shot(page, "02-desktop.png")
        results["desktop"] = ok

        # 应用抽屉
        page.click("#tb-apps")
        page.wait_for_timeout(700)
        ok, _ = shot(page, "03-drawer.png")
        results["drawer"] = ok
        page.click("#drawer-close")

        # 回 AI,语音命令驱动变色(灵魂功能验收)
        page.click("#tb-ai")
        page.wait_for_timeout(400)
        page.fill("#chat-input", "把系统变粉")
        page.click("#btn-send")
        page.wait_for_function(
            "document.body.dataset.theme === 'pink'", timeout=25000)
        page.wait_for_timeout(2500)  # 等打字机+动效
        ok, _ = shot(page, "04-pink-theme.png")
        results["pink_theme"] = ok

        # 锁屏(电源菜单 -> 锁定)
        page.click("#btn-power")
        page.wait_for_timeout(300)
        page.click('[data-power="lock"]')
        page.wait_for_timeout(600)
        ok, _ = shot(page, "05-lock.png")
        results["lock"] = ok
        page.click("#lockscreen")
        page.wait_for_timeout(400)

        # 还原暗色,保持 demo 默认态
        page.evaluate(
            "fetch('/api/theme',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'dark'})})")

        # 开机引导序列(重载页面,0.7s 时截图)
        page.goto(BASE + "/?boot=1", wait_until="domcontentloaded",
                  timeout=30000)
        page.wait_for_timeout(700)
        ok, _ = shot(page, "06-boot.png")
        results["boot"] = ok
        page.wait_for_selector("#boot", state="detached", timeout=8000)

        # 右键菜单 + 迷你聊天窗(桌面模式创新验收)
        page.goto(BASE, wait_until="networkidle", timeout=30000)
        page.click("#btn-mode")
        page.wait_for_timeout(700)
        page.mouse.click(640, 420, button="right")
        page.wait_for_timeout(400)
        ok, _ = shot(page, "07-ctx-menu.png")
        results["ctx_menu"] = ok
        page.keyboard.press("Escape")
        page.mouse.click(640, 560)  # 点空白处关闭(避开图标)
        page.click("#tb-ask")
        page.wait_for_timeout(400)
        page.fill("#mini-input", "系统状态怎么样")
        page.click("#mini-send")
        page.wait_for_timeout(2500)
        ok, _ = shot(page, "08-mini-chat.png")
        results["mini_chat"] = ok

        # 壁纸画廊:右键 -> 换壁纸 -> 选第一张 AI 壁纸
        page.mouse.click(640, 420, button="right")
        page.wait_for_timeout(300)
        page.click('[data-ctx="wallpaper"]')
        page.wait_for_timeout(300)
        wp_btn = page.query_selector('#wp-menu [data-wp]:not([data-wp="gradient"])')
        page.click("#wp-menu [data-wp]" if wp_btn is None
                   else '#wp-menu [data-wp="%s"]' % wp_btn.get_attribute("data-wp"))
        page.wait_for_timeout(900)
        ok, _ = shot(page, "09-wallpaper.png")
        results["wallpaper"] = ok

        # 日历弹出
        page.click("#tb-clock")
        page.wait_for_timeout(400)
        ok, _ = shot(page, "10-calendar.png")
        results["calendar"] = ok
        page.mouse.click(200, 300)

        # 关于弹窗
        page.mouse.click(640, 420, button="right")
        page.wait_for_timeout(300)
        page.click('[data-ctx="about"]')
        page.wait_for_timeout(500)
        ok, _ = shot(page, "11-about.png")
        results["about"] = ok
        page.click("#about-close")

        # 自定义主题(取色器主色 #22cc88 + 暗色基调)
        page.evaluate(
            "fetch('/api/theme',{method:'POST',headers:{'Content-Type':'application/json'},"
            "body:JSON.stringify({custom:{accent:'#22cc88',base:'dark'}})})")
        page.goto(BASE, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(2800)  # boot + 欢迎
        ok, _ = shot(page, "12-custom-theme.png")
        results["custom_theme"] = ok

        # 聊天持久化:发一句 -> 刷新 -> 历史恢复
        page.fill("#chat-input", "记住暗号菠萝")
        page.click("#btn-send")
        page.wait_for_timeout(3500)
        page.goto(BASE, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(2800)
        ok, _ = shot(page, "13-persistence.png")
        results["persistence"] = ok

        # 决策流面板(VM /proc/ai 只读时间线)
        page.click("#btn-aiops2")
        page.wait_for_timeout(3000)  # SSH 采样
        ok, _ = shot(page, "18-aiops.png")
        results["aiops"] = ok
        page.click("#aiops-close")

        # 还原默认主题与壁纸
        page.evaluate(
            "fetch('/api/theme',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'dark'})})")
        page.evaluate(
            "fetch('/api/wallpaper',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({wallpaper:'gradient'})})")
        page.goto(BASE, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(2800)

        # 通知中心(此前动作已产生通知)
        page.click("#btn-bell")
        page.wait_for_timeout(400)
        ok, _ = shot(page, "14-notifications.png")
        results["notifications"] = ok
        page.keyboard.press("Escape")

        # sparkline 仪表
        page.click("#badge-load")
        page.wait_for_timeout(900)
        ok, _ = shot(page, "15-sparkline.png")
        results["sparkline"] = ok
        page.keyboard.press("Escape")

        # 会话管理器
        page.click("#btn-sessions")
        page.wait_for_timeout(500)
        ok, _ = shot(page, "16-sessions.png")
        results["sessions"] = ok
        page.click("#sess-close")

        # 锁屏 PIN(设置 -> 锁定 -> 输入解锁)
        page.evaluate(
            "fetch('/api/pin/set',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin:'123456'})})")
        page.click("#btn-power")
        page.wait_for_timeout(300)
        page.click('[data-power="lock"]')
        page.wait_for_timeout(600)
        ok, _ = shot(page, "17-pin-lock.png")
        results["pin_lock"] = ok
        # PIN 双形态验收:启用 PIN 后输入框必须可见,输对必须解锁
        pin_visible = page.is_visible("#lock-pin-input")
        print("pin_visible =", pin_visible)
        results["pin_input_visible"] = pin_visible
        page.fill("#lock-pin-input", "123456")
        page.click("#lock-pin-btn")
        page.wait_for_timeout(500)
        results["pin_unlock_ok"] = not page.is_visible("#lock-pin-input")
        page.evaluate(
            "fetch('/api/pin/clear',{method:'POST'})")
        browser.close()

    summary = {
        "shots": results,
        "console_errors": console_errors,
        "page_errors": page_errors,
        "all_ok": all(results.values()) and not console_errors
                  and not page_errors,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    sys.exit(0 if summary["all_ok"] else 1)


if __name__ == "__main__":
    main()
