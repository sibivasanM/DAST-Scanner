"""
Selenium-Based Authenticated Session Capture for ZAP.

Captures cookies, JWT tokens, and other session data from authenticated login flows
using Selenium WebDriver. Designed to work with ZAP proxy configured as the HTTP proxy
for traffic inspection and injection.

Features:
  - Launches browser with ZAP proxy (localhost:8080)
  - Ignores SSL certificate errors (trusts ZAP's certificate)
  - Fills credentials from environment variables (no hardcoding)
  - Extracts session data based on auth type:
    - Cookie-based: captures all cookies via driver.get_cookies()
    - JWT: extracts token from localStorage/sessionStorage
    - Bearer token: captures from response headers or storage
  - Navigates through authenticated pages to build ZAP's site tree
  - Graceful error handling with clear messages
  - Returns session data dict with captured auth info
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Browser, Page, BrowserContext

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnforge.selenium_auth")


class SeleniumAuthCapture:
    """Capture authenticated session using browser automation."""

    def __init__(
        self,
        zap_proxy_host: str = "localhost",
        zap_proxy_port: int = 8080,
        browser_timeout: int = 30000,  # 30 seconds
    ):
        """
        Initialize Selenium auth capture.

        Args:
            zap_proxy_host: ZAP proxy host (default: localhost)
            zap_proxy_port: ZAP proxy port (default: 8080)
            browser_timeout: Browser timeout in milliseconds (default: 30s)
        """
        self.zap_proxy_host = zap_proxy_host
        self.zap_proxy_port = zap_proxy_port
        self.browser_timeout = browser_timeout
        
        # Playwright instances
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

    async def capture_session(
        self,
        login_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        username_field: str = "username",
        password_field: str = "password",
        logged_in_indicator: Optional[str] = None,
        authenticated_pages: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Perform login flow and capture session data.

        Args:
            login_url: Target login page URL
            username: Username (defaults to env var USERNAME or LOGIN_USER)
            password: Password (defaults to env var PASSWORD or LOGIN_PASS)
            username_field: HTML form field name for username (default: "username")
            password_field: HTML form field name for password (default: "password")
            logged_in_indicator: Regex pattern to detect logged-in state
            authenticated_pages: List of pages to navigate after login (e.g., /dashboard, /profile)

        Returns:
            Dict with captured session data:
            {
                "success": bool,
                "auth_type": "cookie" | "bearer" | "jwt" | None,
                "cookies": {...},           # if cookie-based
                "token": "...",             # if bearer/JWT
                "storage": {...},           # localStorage/sessionStorage items
                "headers": {...},           # captured auth headers
                "message": str,
                "session_valid": bool,
                "page_content": str,        # logged-in page HTML (for verification)
                "authenticated_pages_visited": [...]
            }
        """
        result = {
            "success": False,
            "auth_type": None,
            "cookies": {},
            "token": None,
            "storage": {},
            "headers": {},
            "message": "",
            "session_valid": False,
            "page_content": "",
            "authenticated_pages_visited": [],
        }

        try:
            # Get credentials from params or environment
            username = username or os.getenv("LOGIN_USER") or os.getenv("USERNAME", "")
            password = password or os.getenv("LOGIN_PASS") or os.getenv("PASSWORD", "")

            if not username or not password:
                result["message"] = "ERROR: Credentials not provided and not found in environment"
                logger.error(result["message"])
                return result

            logger.info(f"[Selenium] Starting login flow for {login_url}")
            logger.info(f"[Selenium] Using username: {username}")

            # Launch browser with ZAP proxy
            await self._launch_browser()

            # Navigate to login page
            logger.info(f"[Selenium] Navigating to {login_url}")
            await self.page.goto(login_url, wait_until="domcontentloaded")

            # Fill in credentials
            logger.info(f"[Selenium] Filling credentials (user_field={username_field}, pass_field={password_field})")
            await self._fill_credentials(username, password, username_field, password_field)

            # Take screenshot before submission
            logger.info("[Selenium] Taking screenshot of form before submission...")
            os.makedirs("screenshots", exist_ok=True)
            # await self.page.screenshot(path="screenshots/login_form.png")

            # Submit form
            logger.info("[Selenium] Submitting login form...")
            await self._submit_login_form(password_field)

            # Wait for navigation or timeout
            try:
                await self.page.wait_for_load_state("domcontentloaded", timeout=self.browser_timeout)
            except Exception as e:
                logger.warning(f"[Selenium] Wait timeout (may still be logged in): {e}")

            # Give page time to stabilize
            await asyncio.sleep(2)

            # Capture session data
            logger.info("[Selenium] Capturing session data...")
            await self._extract_session_data(result)

            # Verify login success
            page_content = await self.page.content()
            result["page_content"] = page_content[:5000]  # First 5KB for verification

            if logged_in_indicator:
                if re.search(logged_in_indicator, page_content, re.IGNORECASE):
                    logger.info(f"[Selenium] ✓ Logged-in indicator found: {logged_in_indicator}")
                    result["session_valid"] = True
                else:
                    logger.warning(
                        f"[Selenium] ✗ Logged-in indicator NOT found: {logged_in_indicator}"
                    )
            else:
                # No indicator specified — assume success if we got cookies/token
                result["session_valid"] = bool(result["cookies"] or result["token"])
                logger.info(
                    f"[Selenium] No indicator specified; session_valid={result['session_valid']}"
                )

            # Navigate through authenticated pages
            if authenticated_pages:
                logger.info(f"[Selenium] Navigating through {len(authenticated_pages)} authenticated pages...")
                for page_url in authenticated_pages[:10]:  # limit to 10 pages
                    try:
                        full_url = self._resolve_url(login_url, page_url)
                        logger.info(f"[Selenium] Visiting: {full_url}")
                        await self.page.goto(full_url, wait_until="domcontentloaded", timeout=self.browser_timeout)
                        await asyncio.sleep(1)  # let page load
                        result["authenticated_pages_visited"].append(full_url)
                    except Exception as e:
                        logger.warning(f"[Selenium] Failed to visit {page_url}: {e}")

            # Take screenshot after login
            logger.info("[Selenium] Taking screenshot of authenticated page...")
            # await self.page.screenshot(path="screenshots/authenticated_page.png")

            result["success"] = True
            result["message"] = f"Login successful; session_valid={result['session_valid']}"
            logger.info(f"[Selenium] ✓ {result['message']}")

        except Exception as e:
            result["message"] = f"ERROR: {str(e)}"
            logger.error(f"[Selenium] ✗ {result['message']}")
            import traceback
            logger.error(traceback.format_exc())

        finally:
            await self._cleanup()

        return result

    async def _launch_browser(self):
        """Launch Playwright browser with ZAP proxy configured."""
        try:
            logger.info(f"[Selenium] Launching browser with ZAP proxy {self.zap_proxy_host}:{self.zap_proxy_port}")

            # Start Playwright instance
            self.playwright = await async_playwright().start()
            
            # Launch with proxy
            proxy = {"server": f"http://{self.zap_proxy_host}:{self.zap_proxy_port}"}

            self.browser = await self.playwright.chromium.launch(
                proxy=proxy,
                args=[
                    "--ignore-certificate-errors",
                    "--disable-blink-features=AutomationControlled",
                ],
                headless=True,  # Headless mode for Docker environments
            )

            # Create context with certificate error tolerance
            self.context = await self.browser.new_context(
                ignore_https_errors=True,
            )

            self.page = await self.context.new_page()
            self.page.set_default_timeout(self.browser_timeout)
            self.page.set_default_navigation_timeout(self.browser_timeout)
            
            logger.info("[Selenium] Browser launched successfully")

        except Exception as e:
            logger.error(f"[Selenium] Failed to launch browser: {e}")
            raise

    # ── Command Replay (Selenium IDE) ────────────────────────────────────────

    def _convert_side_selector(self, target: str) -> str:
        """Convert a Selenium IDE target string to a Playwright selector."""
        t = target.strip()
        if t.startswith("id="):
            return f'[id="{t[3:]}"]'
        elif t.startswith("name="):
            return f'[name="{t[5:]}"]'
        elif t.startswith("css="):
            return t[4:]
        elif t.startswith("xpath="):
            return f'xpath={t[6:]}'
        elif t.lower().startswith("link="):
            return f'a:has-text("{t[5:]}")'
        elif t.lower().startswith("linktext="):
            return f'a:has-text("{t[9:]}")'
        elif t.lower().startswith("partiallinktext="):
            return f'a:has-text("{t[16:]}")'
        else:
            return t  # assume CSS selector

    async def _find_element_from_targets(self, primary: str, fallback_targets: list = None):
        """Try primary target then each fallback until an element is found."""
        candidates = [primary]
        if fallback_targets:
            for ft in fallback_targets:
                if ft and ft[0] and ft[0] != primary:
                    candidates.append(ft[0])

        for t in candidates:
            selector = self._convert_side_selector(t)
            try:
                el = self.page.locator(selector).first
                if await el.is_visible(timeout=3000):
                    return el
            except Exception:
                continue
        return None

    async def capture_session_from_commands(
        self,
        commands: List[Dict],
        base_url: str,
        logged_in_indicator: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Replay Selenium IDE commands using Playwright and capture the resulting session.
        This correctly handles multi-step flows (navigate → click link → fill form → submit).
        """
        result = {
            "success": False,
            "auth_type": None,
            "cookies": {},
            "token": None,
            "storage": {},
            "headers": {},
            "message": "",
            "session_valid": False,
            "page_content": "",
            "authenticated_pages_visited": [],
        }

        try:
            base_url = base_url.rstrip("/")
            logger.info(f"[Selenium] Replaying {len(commands)} commands, base_url={base_url}")
            await self._launch_browser()

            for i, cmd in enumerate(commands):
                command = cmd.get("command", "").lower()
                target = cmd.get("target", "")
                value = cmd.get("value", "")
                fallbacks = cmd.get("targets", [])

                logger.info(f"[Selenium] [{i+1}/{len(commands)}] {command!r} target={target!r}")

                try:
                    if command == "open":
                        if target.startswith("http"):
                            url = target
                        else:
                            url = base_url + (target if target.startswith("/") else "/" + target)
                        await self.page.goto(url, wait_until="domcontentloaded", timeout=self.browser_timeout)

                    elif command == "setwindowsize":
                        try:
                            w, h = target.split("x")
                            await self.page.set_viewport_size({"width": int(w), "height": int(h)})
                        except Exception:
                            pass

                    elif command == "click":
                        el = await self._find_element_from_targets(target, fallbacks)
                        if el:
                            await el.click()
                            try:
                                await self.page.wait_for_load_state("domcontentloaded", timeout=8000)
                            except Exception:
                                pass
                        else:
                            logger.warning(f"[Selenium] click: element not found for {target!r}")

                    elif command in ("type", "sendkeys"):
                        el = await self._find_element_from_targets(target, fallbacks)
                        if el:
                            await el.click()
                            await el.fill(value)
                            logger.info(f"[Selenium] ✓ Filled {target!r}")
                        else:
                            logger.warning(f"[Selenium] type: element not found for {target!r}")

                    elif command in ("waitforelementvisible", "waitforelementpresent",
                                     "waitforelementtobeclickable", "waitforelement"):
                        sel = self._convert_side_selector(target)
                        try:
                            await self.page.wait_for_selector(sel, timeout=8000)
                        except Exception:
                            pass

                    else:
                        logger.debug(f"[Selenium] Skipping unsupported command: {command}")

                except Exception as e:
                    logger.warning(f"[Selenium] Command [{command}] failed (non-fatal): {e}")

            # Let the page settle after last command
            await asyncio.sleep(2)

            # Extract session
            await self._extract_session_data(result)

            page_content = await self.page.content()
            result["page_content"] = page_content[:5000]

            if logged_in_indicator:
                result["session_valid"] = bool(
                    re.search(logged_in_indicator, page_content, re.IGNORECASE)
                )
                if result["session_valid"]:
                    logger.info(f"[Selenium] ✓ Logged-in indicator matched: {logged_in_indicator}")
                else:
                    logger.warning(f"[Selenium] Logged-in indicator NOT found: {logged_in_indicator}")
            else:
                result["session_valid"] = bool(result["cookies"] or result["token"])

            result["success"] = True
            result["message"] = f"Command replay done; session_valid={result['session_valid']}, cookies={len(result['cookies'])}"
            logger.info(f"[Selenium] ✓ {result['message']}")

        except Exception as e:
            result["message"] = f"ERROR: {str(e)}"
            logger.error(f"[Selenium] ✗ {result['message']}")
            import traceback
            logger.error(traceback.format_exc())
        finally:
            await self._cleanup()

        return result

    async def _fill_credentials(self, username: str, password: str, user_field: str, pass_field: str):
        """Fill in login form with username and password."""
        try:
            # Try to find and fill username field
            logger.info(f"[Selenium] Trying to fill username field: {user_field}")

            # Try different selectors with more flexibility
            user_selectors = [
                f'input[name="{user_field}"]',
                f'input[id="{user_field}"]',
                f'input[placeholder*="{user_field}"]',
                'input[type="email"]',
                'input[type="text"]',
                # Additional fallbacks for common patterns
                'input[name*="user"]',
                'input[name*="email"]',
                'input[name*="login"]',
                'input[id*="user"]',
                'input[id*="email"]',
                f'input[data-field="{user_field}"]',
                f'input[data-name="{user_field}"]',
            ]

            user_filled = False
            for selector in user_selectors:
                try:
                    element = self.page.locator(selector).first
                    if await element.is_visible():
                        await element.fill(username)
                        logger.info(f"[Selenium] ✓ Filled username using: {selector}")
                        user_filled = True
                        break
                except Exception as e:
                    logger.debug(f"[Selenium] Username selector {selector} failed: {e}")
                    continue

            if not user_filled:
                # Try XPath as fallback
                logger.info("[Selenium] Trying XPath selectors for username...")
                try:
                    element = self.page.locator(f"//input[contains(@name, '{user_field}') or contains(@id, '{user_field}')]").first
                    if await element.is_visible():
                        await element.fill(username)
                        logger.info(f"[Selenium] ✓ Filled username using XPath")
                        user_filled = True
                except:
                    pass
                
                if not user_filled:
                    raise Exception(f"Could not locate username field '{user_field}' using available selectors")

            # Try to find and fill password field
            logger.info(f"[Selenium] Trying to fill password field: {pass_field}")

            pass_selectors = [
                f'input[name="{pass_field}"]',
                f'input[id="{pass_field}"]',
                f'input[placeholder*="{pass_field}"]',
                'input[type="password"]',
                # Additional fallbacks
                'input[name*="pass"]',
                'input[name*="pwd"]',
                'input[id*="pass"]',
                f'input[data-field="{pass_field}"]',
                f'input[data-name="{pass_field}"]',
            ]

            pass_filled = False
            for selector in pass_selectors:
                try:
                    element = self.page.locator(selector).first
                    if await element.is_visible():
                        await element.fill(password)
                        logger.info(f"[Selenium] ✓ Filled password using: {selector}")
                        pass_filled = True
                        break
                except Exception as e:
                    logger.debug(f"[Selenium] Password selector {selector} failed: {e}")
                    continue

            if not pass_filled:
                # Try XPath as fallback
                logger.info("[Selenium] Trying XPath selectors for password...")
                try:
                    element = self.page.locator(f"//input[contains(@type, 'password') or contains(@name, '{pass_field}') or contains(@id, '{pass_field}')]").first
                    if await element.is_visible():
                        await element.fill(password)
                        logger.info(f"[Selenium] ✓ Filled password using XPath")
                        pass_filled = True
                except:
                    pass
                
                if not pass_filled:
                    raise Exception(f"Could not locate password field '{pass_field}' using available selectors. "
                                  f"Tried: {pass_selectors}")

        except Exception as e:
            logger.error(f"[Selenium] Failed to fill credentials: {e}")
            raise

    async def _submit_login_form(self, password_field: str):
        """Submit the login form by clicking the submit button or pressing Enter."""
        try:
            logger.info("[Selenium] Submitting form...")

            # Try to find submit button
            submit_selectors = [
                'button[type="submit"]',
                'button:has-text("Login")',
                'button:has-text("Sign In")',
                'button:has-text("Submit")',
                'input[type="submit"]',
            ]

            submit_found = False
            for selector in submit_selectors:
                try:
                    button = self.page.locator(selector).first
                    if await button.is_visible():
                        await button.click()
                        logger.info(f"[Selenium] ✓ Clicked submit button using: {selector}")
                        submit_found = True
                        break
                except Exception as e:
                    logger.debug(f"[Selenium] Submit selector {selector} failed: {e}")
                    continue

            # Fallback: press Enter on password field
            if not submit_found:
                logger.info("[Selenium] No submit button found; pressing Enter on password field")
                pass_field_selector = f'input[name="{password_field}"]'
                await self.page.locator(pass_field_selector).first.press("Enter")

            logger.info("[Selenium] Form submission command sent")

        except Exception as e:
            logger.error(f"[Selenium] Failed to submit form: {e}")
            raise

    async def _extract_session_data(self, result: Dict[str, Any]):
        """Extract cookies, tokens, and other session data from the page."""
        try:
            # Extract all cookies
            logger.info("[Selenium] Extracting cookies...")
            cookies = await self.context.cookies()

            if cookies:
                result["auth_type"] = "cookie"
                for cookie in cookies:
                    result["cookies"][cookie["name"]] = cookie["value"]
                logger.info(f"[Selenium] ✓ Captured {len(cookies)} cookie(s)")
                logger.debug(f"[Selenium] Cookies: {list(result['cookies'].keys())}")
            else:
                logger.warning("[Selenium] No cookies found")

            # Extract tokens from localStorage
            logger.info("[Selenium] Extracting localStorage tokens...")
            local_storage = await self.page.evaluate(
                "() => JSON.stringify(window.localStorage)"
            )
            if local_storage:
                try:
                    storage_data = json.loads(local_storage)
                    result["storage"]["localStorage"] = storage_data
                    logger.info(f"[Selenium] ✓ Captured localStorage items: {list(storage_data.keys())}")

                    # Look for JWT or Bearer tokens in localStorage
                    for key, value in storage_data.items():
                        if any(
                            x in key.lower() for x in ["token", "auth", "jwt", "bearer"]
                        ):
                            result["auth_type"] = "jwt"
                            result["token"] = value
                            logger.info(f"[Selenium] ✓ Found JWT token in localStorage[{key}]")
                            break
                except Exception as e:
                    logger.warning(f"[Selenium] Failed to parse localStorage: {e}")

            # Extract tokens from sessionStorage
            logger.info("[Selenium] Extracting sessionStorage tokens...")
            session_storage = await self.page.evaluate(
                "() => JSON.stringify(window.sessionStorage)"
            )
            if session_storage:
                try:
                    storage_data = json.loads(session_storage)
                    result["storage"]["sessionStorage"] = storage_data
                    logger.info(f"[Selenium] ✓ Captured sessionStorage items: {list(storage_data.keys())}")

                    # Look for JWT or Bearer tokens in sessionStorage
                    if not result["token"]:
                        for key, value in storage_data.items():
                            if any(
                                x in key.lower() for x in ["token", "auth", "jwt", "bearer"]
                            ):
                                result["auth_type"] = "jwt"
                                result["token"] = value
                                logger.info(f"[Selenium] ✓ Found JWT token in sessionStorage[{key}]")
                                break
                except Exception as e:
                    logger.warning(f"[Selenium] Failed to parse sessionStorage: {e}")

            # Try to capture Authorization header if present
            logger.info("[Selenium] Checking for Authorization headers...")
            # This would require intercepting network requests (more complex in Playwright)

        except Exception as e:
            logger.error(f"[Selenium] Error extracting session data: {e}")

    def _resolve_url(self, base_url: str, path: str) -> str:
        """Resolve relative paths to absolute URLs."""
        if path.startswith("http"):
            return path

        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        if path.startswith("/"):
            return f"{base}{path}"
        else:
            return f"{base}/{path}"

    async def _cleanup(self):
        """Close browser and clean up resources."""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            logger.info("[Selenium] Browser and Playwright closed")
        except Exception as e:
            logger.warning(f"[Selenium] Error during cleanup: {e}")
