#!/usr/bin/env python3
"""
ClawCloud 自动登录脚本
- 等待设备验证批准（30秒）
- 智能2FA检测：有则处理，无则跳过
- 每次登录后自动更新 Cookie
- Telegram 通知
"""

import os
import sys
import time
import base64
import re
import urllib.parse
import requests
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# ==================== 配置 ====================
CLAW_CLOUD_URL = "https://ap-northeast-1.run.claw.cloud"
SIGNIN_URL = f"{CLAW_CLOUD_URL}/signin"
DEVICE_VERIFY_WAIT = 30  # 设备验证等待时间
TWO_FACTOR_WAIT = 120    # 2FA验证等待时间（备用，如果你未来开启2FA）


class Telegram:
    """Telegram 通知"""
    
    def __init__(self):
        self.token = os.environ.get('TG_BOT_TOKEN')
        self.chat_id = os.environ.get('TG_CHAT_ID')
        self.ok = bool(self.token and self.chat_id)
    
    def send(self, msg):
        if not self.ok:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                data={"chat_id": self.chat_id, "text": msg, "parse_mode": "HTML"},
                timeout=30
            )
        except:
            pass
    
    def photo(self, path, caption=""):
        if not self.ok or not os.path.exists(path):
            return
        try:
            with open(path, 'rb') as f:
                requests.post(
                    f"https://api.telegram.org/bot{self.token}/sendPhoto",
                    data={"chat_id": self.chat_id, "caption": caption[:1024]},
                    files={"photo": f},
                    timeout=60
                )
        except:
            pass
    
    def flush_updates(self):
        """刷新 offset 到最新，避免读到旧消息"""
        if not self.ok:
            return 0
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{self.token}/getUpdates",
                params={"timeout": 0},
                timeout=10
            )
            data = r.json()
            if data.get("ok") and data.get("result"):
                return data["result"][-1]["update_id"] + 1
        except:
            pass
        return 0
    
    def wait_code(self, timeout=120):
        """
        等待你在 TG 里发 /code 123456
        只接受来自 TG_CHAT_ID 的消息
        """
        if not self.ok:
            return None
        
        # 先刷新 offset，避免读到旧的 /code
        offset = self.flush_updates()
        deadline = time.time() + timeout
        pattern = re.compile(r"^/code\s+(\d{6,8})$")  # 6位TOTP 或 8位恢复码也行
        
        while time.time() < deadline:
            try:
                r = requests.get(
                    f"https://api.telegram.org/bot{self.token}/getUpdates",
                    params={"timeout": 20, "offset": offset},
                    timeout=30
                )
                data = r.json()
                if not data.get("ok"):
                    time.sleep(2)
                    continue
                
                for upd in data.get("result", []):
                    offset = upd["update_id"] + 1
                    msg = upd.get("message") or {}
                    chat = msg.get("chat") or {}
                    if str(chat.get("id")) != str(self.chat_id):
                        continue
                    
                    text = (msg.get("text") or "").strip()
                    m = pattern.match(text)
                    if m:
                        return m.group(1)
            
            except Exception:
                pass
            
            time.sleep(2)
        
        return None


class SecretUpdater:
    """GitHub Secret 更新器"""
    
    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.ok = bool(self.token and self.repo)
        if self.ok:
            print("✅ Secret 自动更新已启用")
        else:
            print("⚠️ Secret 自动更新未启用（需要 REPO_TOKEN）")
    
    def update(self, name, value):
        if not self.ok:
            return False
        try:
            from nacl import encoding, public
            
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            # 获取公钥
            r = requests.get(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key",
                headers=headers, timeout=30
            )
            if r.status_code != 200:
                return False
            
            key_data = r.json()
            pk = public.PublicKey(key_data['key'].encode(), encoding.Base64Encoder())
            encrypted = public.SealedBox(pk).encrypt(value.encode())
            
            # 更新 Secret
            r = requests.put(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}",
                headers=headers,
                json={"encrypted_value": base64.b64encode(encrypted).decode(), "key_id": key_data['key_id']},
                timeout=30
            )
            return r.status_code in [201, 204]
        except Exception as e:
            print(f"更新 Secret 失败: {e}")
            return False


class AutoLogin:
    """自动登录"""
    
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        self.tg = Telegram()
        self.secret = SecretUpdater()
        self.shots = []
        self.logs = []
        self.n = 0
        
    def _mask_url(self, url):
        """隐藏URL中的敏感参数，只显示主要部分"""
        if not url:
            return ""
        
        try:
            # 解析URL
            parsed = urllib.parse.urlparse(url)
            
            # 只显示域名和路径，隐藏查询参数
            if parsed.query:
                # 对于GitHub登录页面，我们可以显示基本路径
                if 'github.com/login' in url:
                    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?[登录参数已隐藏]"
                # 对于其他页面，也可以类似处理
                elif 'github.com' in url:
                    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?[...]"
                else:
                    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?[参数已隐藏]"
            else:
                # 没有查询参数的URL，直接显示
                return url
        except:
            # 解析失败，返回原始URL（或简化版）
            if len(url) > 100:
                return url[:80] + "..."
            return url
    
    def log(self, msg, level="INFO"):
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        line = f"{icons.get(level, '•')} {msg}"
        print(line)
        self.logs.append(line)
    
    def shot(self, page, name):
        self.n += 1
        f = f"{self.n:02d}_{name}.png"
        try:
            page.screenshot(path=f)
            self.shots.append(f)
        except:
            pass
        return f
    
    def click(self, page, sels, desc=""):
        for s in sels:
            try:
                el = page.locator(s).first
                if el.is_visible(timeout=3000):
                    el.click()
                    self.log(f"已点击: {desc}", "SUCCESS")
                    return True
            except:
                pass
        return False
    
    def find_and_click(self, page, selectors, desc="", timeout=3000):
        """查找并点击元素，有更好的错误处理"""
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=timeout):
                    el.click()
                    self.log(f"已点击: {desc} ({sel})", "SUCCESS")
                    return True
            except Exception as e:
                self.log(f"点击 {sel} 失败: {e}", "INFO")
                continue
        return False
    
    def get_session(self, context):
        """提取 Session Cookie"""
        try:
            for c in context.cookies():
                if c['name'] == 'user_session' and 'github' in c.get('domain', ''):
                    return c['value']
        except:
            pass
        return None
    
    def save_cookie(self, value):
        """保存新 Cookie"""
        if not value:
            return
        
        self.log(f"新 Cookie: {value[:15]}...{value[-8:]}", "SUCCESS")
        
        # 自动更新 Secret
        if self.secret.update('GH_SESSION', value):
            self.log("已自动更新 GH_SESSION", "SUCCESS")
            self.tg.send("🔑 <b>Cookie 已自动更新</b>\n\nGH_SESSION 已保存")
        else:
            # 通过 Telegram 发送
            self.tg.send(f"""🔑 <b>新 Cookie</b>

请更新 Secret <b>GH_SESSION</b>:
<code>{value}</code>""")
            self.log("已通过 Telegram 发送 Cookie", "SUCCESS")
    
    def wait_device(self, page):
        """等待设备验证 - 简化日志版"""
        self.log(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        shot = self.shot(page, "设备验证")
        
        self.tg.send(f"""⚠️ <b>需要设备验证</b>

请在 {DEVICE_VERIFY_WAIT} 秒内打开 GitHub App 批准本次登录。

请在 App 中批准后返回查看进度。""")
        
        if shot:
            self.tg.photo(shot, "设备验证页面")
        
        start_time = time.time()
        deadline = start_time + DEVICE_VERIFY_WAIT
        
        last_log_time = 0
        
        while time.time() < deadline:
            url = page.url
            
            # 如果离开设备验证流程页面，认为通过
            if "verified-device" not in url and "device-verification" not in url:
                self.log("设备验证通过！", "SUCCESS")
                self.tg.send("✅ <b>设备验证通过</b>")
                return True
            
            # 检查是否有"Continue"按钮可以点击
            continue_buttons = [
                'button:has-text("Continue")',
                'a:has-text("Continue")',
                'button:has-text("下一步")',
                'button:has-text("Next")',
                'button[type="submit"]',
                'input[type="submit"]',
                'button.primary',
                'button.btn-primary'
            ]
            
            if self.find_and_click(page, continue_buttons, "继续按钮"):
                time.sleep(2)
                page.wait_for_load_state('networkidle', timeout=10000)
                # 点击后再次检查URL
                if "verified-device" not in page.url and "device-verification" not in page.url:
                    self.log("点击继续按钮后设备验证通过！", "SUCCESS")
                    return True
            
            # 每 5 秒打印一次状态，但不要频繁打印URL
            elapsed = int(time.time() - start_time)
            if elapsed % 5 == 0 and elapsed != last_log_time:
                self.log(f"  等待设备验证... ({elapsed}/{DEVICE_VERIFY_WAIT}秒)")
                last_log_time = elapsed
            
            time.sleep(1)
        
        # 超时后强制尝试点击继续按钮
        self.log("设备验证等待超时，尝试强制继续...", "WARN")
        
        # 尝试所有可能的继续按钮
        force_continue_buttons = [
            'button:has-text("Continue")',
            'a:has-text("Continue")',
            'button:has-text("下一步")',
            'button:has-text("Next")',
            'button[type="submit"]',
            'input[type="submit"]',
            'button',
            'a'
        ]
        
        for btn in force_continue_buttons:
            try:
                elements = page.locator(btn).all()
                for element in elements:
                    if element.is_visible(timeout=1000):
                        try:
                            element.click()
                            self.log(f"强制点击了按钮", "SUCCESS")
                            time.sleep(2)
                            break
                        except:
                            pass
            except:
                pass
        
        # 检查是否成功
        if "verified-device" not in page.url and "device-verification" not in page.url:
            self.log("强制点击后设备验证通过！", "SUCCESS")
            self.tg.send("✅ <b>设备验证通过（强制点击）</b>")
            return True
        
        self.log("设备验证超时", "ERROR")
        self.tg.send("❌ <b>设备验证超时</b>")
        return False
    
    def detect_and_handle_2fa(self, page):
        """
        智能检测并处理2FA
        返回: True=成功处理或无需处理, False=处理失败
        """
        url = page.url
        self.log(f"检测2FA状态: {self._mask_url(url)}", "INFO")
        
        # 检查是否在2FA页面
        if "two-factor" not in url:
            self.log("未检测到2FA要求，跳过2FA步骤", "SUCCESS")
            return True
        
        self.log("检测到需要2FA验证", "WARN")
        self.shot(page, "2FA检测")
        
        # 检查2FA类型
        if "two-factor/mobile" in url:
            # GitHub Mobile 2FA: 等待在手机上批准
            return self._handle_mobile_2fa(page)
        else:
            # 其他2FA类型: TOTP验证码或恢复码
            return self._handle_code_2fa(page)
    
    def _handle_mobile_2fa(self, page):
        """处理GitHub Mobile 2FA"""
        self.log(f"需要GitHub Mobile 2FA，等待 {TWO_FACTOR_WAIT} 秒...", "WARN")
        
        # 先截图并立刻发出去
        shot = self.shot(page, "2FA_mobile")
        self.tg.send(f"""⚠️ <b>需要GitHub Mobile 2FA</b>

请打开手机GitHub App批准本次登录。
等待时间：{TWO_FACTOR_WAIT} 秒""")
        
        if shot:
            self.tg.photo(shot, "GitHub Mobile 2FA页面")
        
        # 不要频繁reload，避免把流程刷回登录页
        start_time = time.time()
        deadline = start_time + TWO_FACTOR_WAIT
        
        while time.time() < deadline:
            time.sleep(1)
            
            url = page.url
            
            # 如果离开 two-factor 流程页面，认为通过
            if "github.com/sessions/two-factor/" not in url:
                self.log("GitHub Mobile 2FA通过！", "SUCCESS")
                self.tg.send("✅ <b>GitHub Mobile 2FA通过</b>")
                return True
            
            # 如果被刷回登录页，说明这次流程断了
            if "github.com/login" in url:
                self.log("2FA后回到了登录页，需重新登录", "ERROR")
                return False
            
            # 每 10 秒打印一次，并补发一次截图
            elapsed = int(time.time() - start_time)
            if elapsed % 10 == 0 and elapsed != 0:
                self.log(f"  等待GitHub Mobile 2FA... ({elapsed}/{TWO_FACTOR_WAIT}秒)")
                shot = self.shot(page, f"2FA_mobile_{elapsed}s")
                if shot:
                    self.tg.photo(shot, f"GitHub Mobile 2FA页面（第{elapsed}秒）")
            
            # 只在 30 秒、60 秒... 做一次轻刷新
            if elapsed % 30 == 0 and elapsed != 0:
                try:
                    page.reload(timeout=30000)
                    page.wait_for_load_state('domcontentloaded', timeout=30000)
                except:
                    pass
        
        self.log("GitHub Mobile 2FA超时", "ERROR")
        self.tg.send("❌ <b>GitHub Mobile 2FA超时</b>")
        return False
    
    def _handle_code_2fa(self, page):
        """处理TOTP验证码2FA"""
        self.log("需要输入2FA验证码", "WARN")
        shot = self.shot(page, "2FA_code")
        
        # 发送提示并等待验证码
        self.tg.send(f"""🔐 <b>需要2FA验证码登录</b>

请在 Telegram 里发送：
<code>/code 你的6位验证码</code>

等待时间：{TWO_FACTOR_WAIT} 秒""")
        
        if shot:
            self.tg.photo(shot, "2FA验证码输入页面")
        
        self.log(f"等待2FA验证码（{TWO_FACTOR_WAIT}秒）...", "WARN")
        code = self.tg.wait_code(timeout=TWO_FACTOR_WAIT)
        
        if not code:
            self.log("等待2FA验证码超时", "ERROR")
            self.tg.send("❌ <b>等待2FA验证码超时</b>")
            return False
        
        # 不打印验证码明文，只提示收到
        self.log("收到2FA验证码，正在填入...", "SUCCESS")
        self.tg.send("✅ 收到2FA验证码，正在填入...")
        
        # 常见 OTP 输入框 selector（优先级排序）
        selectors = [
            'input[autocomplete="one-time-code"]',
            'input[name="app_otp"]',
            'input[name="otp"]',
            'input#app_totp',
            'input#otp',
            'input[inputmode="numeric"]'
        ]
        
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=2000):
                    el.fill(code)
                    self.log(f"已填入2FA验证码", "SUCCESS")
                    time.sleep(1)
                    
                    # 优先点击 Verify 按钮，不行再 Enter
                    submitted = False
                    verify_btns = [
                        'button:has-text("Verify")',
                        'button[type="submit"]',
                        'input[type="submit"]'
                    ]
                    for btn_sel in verify_btns:
                        try:
                            btn = page.locator(btn_sel).first
                            if btn.is_visible(timeout=1000):
                                btn.click()
                                submitted = True
                                self.log("已点击 Verify 按钮", "SUCCESS")
                                break
                        except:
                            pass
                    
                    if not submitted:
                        page.keyboard.press("Enter")
                        self.log("已按 Enter 提交", "SUCCESS")
                    
                    time.sleep(3)
                    page.wait_for_load_state('networkidle', timeout=30000)
                    self.shot(page, "2FA验证码提交后")
                    
                    # 检查是否通过
                    if "github.com/sessions/two-factor/" not in page.url:
                        self.log("2FA验证码验证通过！", "SUCCESS")
                        self.tg.send("✅ <b>2FA验证码验证通过</b>")
                        return True
                    else:
                        self.log("2FA验证码可能错误", "ERROR")
                        self.tg.send("❌ <b>2FA验证码可能错误，请检查后重试</b>")
                        return False
            except:
                pass
        
        self.log("没找到2FA验证码输入框", "ERROR")
        self.tg.send("❌ <b>没找到2FA验证码输入框</b>")
        return False
    
    def login_github(self, page):
        """登录 GitHub - 智能处理设备验证和2FA"""
        self.log("登录 GitHub...", "STEP")
        self.shot(page, "github_登录页")
        
        try:
            page.locator('input[name="login"]').fill(self.username)
            page.locator('input[name="password"]').fill(self.password)
            self.log("已输入凭据")
        except Exception as e:
            self.log(f"输入失败: {e}", "ERROR")
            return False
        
        self.shot(page, "github_已填写")
        
        try:
            submit_selectors = [
                'input[type="submit"]',
                'button[type="submit"]',
                'button:has-text("Sign in")',
                'button:has-text("登录")'
            ]
            
            for sel in submit_selectors:
                try:
                    el = page.locator(sel).first
                    if el.is_visible(timeout=2000):
                        el.click()
                        self.log("已点击登录按钮", "SUCCESS")
                        break
                except:
                    pass
        except:
            pass
        
        time.sleep(3)
        try:
            page.wait_for_load_state('networkidle', timeout=30000)
        except:
            pass
        
        self.shot(page, "github_登录后")
        
        url = page.url
        self.log(f"当前页面: {self._mask_url(url)}")
        
        # 1. 设备验证
        if 'verified-device' in url or 'device-verification' in url:
            if not self.wait_device(page):
                return False
            time.sleep(2)
            try:
                page.wait_for_load_state('networkidle', timeout=15000)
            except:
                pass
            self.shot(page, "验证后")
            
            # 设备验证后再次检查URL，可能需要点击继续
            url = page.url
            if 'verified-device' in url or 'device-verification' in url:
                self.log("仍在验证页面，尝试强制继续...", "WARN")
                # 尝试点击所有可能的按钮
                all_buttons = page.locator('button, a, input[type="submit"]')
                count = all_buttons.count()
                for i in range(min(count, 10)):  # 最多尝试前10个按钮
                    try:
                        btn = all_buttons.nth(i)
                        if btn.is_visible(timeout=1000):
                            btn.click()
                            self.log(f"点击了继续按钮", "INFO")
                            time.sleep(2)
                            break
                    except:
                        pass
        
        # 2. 智能检测和处理2FA
        if not self.detect_and_handle_2fa(page):
            return False
        
        # 错误检查
        try:
            err = page.locator('.flash-error').first
            if err.is_visible(timeout=2000):
                self.log(f"错误: {err.inner_text()}", "ERROR")
                return False
        except:
            pass
        
        return True
    
    def complete_oauth_flow(self, page):
        """完成 OAuth 流程 - 简化日志版"""
        self.log("处理 OAuth 流程...", "STEP")
        
        max_attempts = 30
        for attempt in range(max_attempts):
            url = page.url
            
            # 如果已经在ClawCloud，成功
            if 'claw.cloud' in url and 'signin' not in url.lower():
                self.log("已在ClawCloud页面", "SUCCESS")
                return True
            
            # 在GitHub授权页面
            if 'github.com/login/oauth/authorize' in url:
                if attempt % 5 == 0:  # 每5次记录一次
                    self.shot(page, f"oauth_授权页_{attempt}")
                    self.log("在GitHub OAuth授权页面", "INFO")
                
                # 尝试点击授权按钮
                authorize_selectors = [
                    'button[name="authorize"]',
                    'button:has-text("Authorize")',
                    'button:has-text("授权")',
                    'button[type="submit"]',
                    'button[data-ga-click*="authorize"]',
                    '[data-octo-click="oauth_authorize"]',
                    'button.btn-primary',
                    'button.primary'
                ]
                
                if self.find_and_click(page, authorize_selectors, "授权按钮"):
                    time.sleep(3)
                    try:
                        page.wait_for_load_state('networkidle', timeout=20000)
                    except:
                        pass
                    continue
            
            # 在GitHub其他页面（登录成功后的页面）
            elif 'github.com' in url and 'login' not in url and 'oauth' not in url:
                if attempt % 5 == 0:  # 每5次记录一次
                    self.log("在GitHub页面，尝试访问ClawCloud", "INFO")
                try:
                    page.goto(SIGNIN_URL, timeout=30000)
                    try:
                        page.wait_for_load_state('networkidle', timeout=15000)
                    except:
                        pass
                    time.sleep(2)
                    continue
                except:
                    pass
            
            # 如果还是回到ClawCloud登录页，尝试再次点击GitHub按钮
            elif 'claw.cloud' in url and 'signin' in url.lower():
                if attempt % 5 == 0:  # 每5次记录一次
                    self.shot(page, f"clawcloud_登录页_{attempt}")
                    self.log("回到ClawCloud登录页，尝试再次点击GitHub", "INFO")
                
                github_selectors = [
                    'button:has-text("GitHub")',
                    'button:has-text("Github")',
                    'button:has-text("github")',
                    'a:has-text("GitHub")',
                    'a:has-text("Github")',
                    'a:has-text("github")',
                    '[data-provider="github"]',
                    'button[data-provider="github"]',
                    'a[data-provider="github"]'
                ]
                
                if self.find_and_click(page, github_selectors, "GitHub按钮"):
                    time.sleep(3)
                    try:
                        page.wait_for_load_state('networkidle', timeout=20000)
                    except:
                        pass
                    continue
            
            time.sleep(1)
            if attempt % 5 == 0:
                self.log(f"  等待OAuth流程... ({attempt}/{max_attempts}秒)")
        
        self.log("OAuth流程超时", "ERROR")
        return False
    
    def keepalive(self, page):
        """保活"""
        self.log("保活...", "STEP")
        urls_to_visit = [
            (f"{CLAW_CLOUD_URL}/", "控制台"),
            (f"{CLAW_CLOUD_URL}/apps", "应用"),
            (f"{CLAW_CLOUD_URL}/account", "账户")
        ]
        
        for url, name in urls_to_visit:
            try:
                page.goto(url, timeout=30000)
                try:
                    page.wait_for_load_state('networkidle', timeout=15000)
                except:
                    pass
                self.log(f"已访问: {name}", "SUCCESS")
                time.sleep(2)
            except Exception as e:
                self.log(f"访问 {name} 失败: {e}", "WARN")
        
        # 最后确保回到控制台页面再截图
        try:
            page.goto(f"{CLAW_CLOUD_URL}/", timeout=30000)
            page.wait_for_load_state('networkidle', timeout=15000)
            time.sleep(2)
            self.shot(page, "完成")
        except:
            self.shot(page, "完成")
    
    def notify(self, ok, err=""):
        if not self.tg.ok:
            return
        
        msg = f"""<b>🤖 ClawCloud 自动登录</b>

<b>状态:</b> {"✅ 成功" if ok else "❌ 失败"}
<b>用户:</b> {self.username}
<b>时间:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"""
        
        if err:
            msg += f"\n<b>错误:</b> {err}"
        
        msg += "\n\n<b>日志:</b>\n" + "\n".join(self.logs[-10:])
        
        self.tg.send(msg)
        
        if self.shots:
            if not ok:
                # 发送最后3张截图
                for s in self.shots[-3:]:
                    self.tg.photo(s, s)
            else:
                self.tg.photo(self.shots[-1], "完成")
    
    def run(self):
        print("\n" + "="*50)
        print("🚀 ClawCloud 自动登录")
        print("="*50 + "\n")
        
        self.log(f"用户名: {self.username}")
        self.log(f"Session: {'有' if self.gh_session else '无'}")
        self.log(f"密码: {'有' if self.password else '无'}")
        
        if not self.username or not self.password:
            self.log("缺少凭据", "ERROR")
            self.notify(False, "凭据未配置")
            sys.exit(1)
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            page = context.new_page()
            
            try:
                # 预加载 Cookie
                if self.gh_session:
                    try:
                        context.add_cookies([
                            {'name': 'user_session', 'value': self.gh_session, 'domain': 'github.com', 'path': '/'},
                            {'name': 'logged_in', 'value': 'yes', 'domain': 'github.com', 'path': '/'}
                        ])
                        self.log("已加载 Session Cookie", "SUCCESS")
                    except:
                        self.log("加载 Cookie 失败", "WARN")
                
                # 1. 访问 ClawCloud
                self.log("步骤1: 打开 ClawCloud", "STEP")
                page.goto(SIGNIN_URL, timeout=60000)
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                except:
                    pass
                time.sleep(2)
                self.shot(page, "clawcloud")
                
                # 检查是否已登录
                if 'signin' not in page.url.lower():
                    self.log("已登录！", "SUCCESS")
                    self.keepalive(page)
                    # 提取并保存新 Cookie
                    new = self.get_session(context)
                    if new:
                        self.save_cookie(new)
                    self.notify(True)
                    print("\n✅ 成功！\n")
                    return
                
                # 2. 点击 GitHub
                self.log("步骤2: 点击 GitHub", "STEP")
                github_selectors = [
                    'button:has-text("GitHub")',
                    'button:has-text("Github")',
                    'button:has-text("github")',
                    'a:has-text("GitHub")',
                    'a:has-text("Github")',
                    'a:has-text("github")',
                    '[data-provider="github"]',
                    'button[data-provider="github"]',
                    'a[data-provider="github"]',
                    '[href*="github.com/login/oauth"]',
                    'button:has-text("Continue with GitHub")',
                    'button:has-text("Continue with Github")'
                ]
                
                if not self.find_and_click(page, github_selectors, "GitHub按钮"):
                    self.log("找不到GitHub按钮", "ERROR")
                    self.shot(page, "找不到按钮")
                    self.notify(False, "找不到 GitHub 按钮")
                    sys.exit(1)
                
                time.sleep(3)
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                except:
                    pass
                self.shot(page, "点击后")
                
                url = page.url
                self.log(f"当前页面: {self._mask_url(url)}")
                
                # 3. GitHub 登录（包含智能2FA处理）
                self.log("步骤3: GitHub 认证", "STEP")
                
                if 'github.com/login' in url or 'github.com/session' in url:
                    if not self.login_github(page):
                        self.shot(page, "登录失败")
                        self.notify(False, "GitHub 登录失败")
                        sys.exit(1)
                
                # 4. 完成 OAuth 流程
                self.log("步骤4: 完成 OAuth 流程", "STEP")
                if not self.complete_oauth_flow(page):
                    self.shot(page, "OAuth流程失败")
                    self.notify(False, "OAuth 流程失败")
                    sys.exit(1)
                
                self.shot(page, "流程完成")
                
                # 5. 验证
                self.log("步骤5: 验证", "STEP")
                if 'claw.cloud' not in page.url or 'signin' in page.url.lower():
                    self.shot(page, "验证失败")
                    self.notify(False, "验证失败")
                    sys.exit(1)
                
                # 6. 保活
                self.keepalive(page)
                
                # 7. 提取并保存新 Cookie
                self.log("步骤6: 更新 Cookie", "STEP")
                new = self.get_session(context)
                if new:
                    self.save_cookie(new)
                else:
                    self.log("未获取到新 Cookie", "WARN")
                
                self.notify(True)
                print("\n" + "="*50)
                print("✅ 成功！")
                print("="*50 + "\n")
                
            except Exception as e:
                self.log(f"异常: {e}", "ERROR")
                self.shot(page, "异常")
                import traceback
                traceback.print_exc()
                self.notify(False, str(e))
                sys.exit(1)
            finally:
                browser.close()


if __name__ == "__main__":
    AutoLogin().run()
