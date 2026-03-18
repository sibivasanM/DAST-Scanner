"""
ZAP Scanner — OWASP ZAP authenticated scanning via its REST API.

Supports:
  - Form-based login (POST credentials to login URL)
  - Bearer / API token header auth
  - Cookie-based session auth
  - Custom header auth (e.g. X-API-Key)
  - Manual token injection

ZAP runs as a daemon (Docker sidecar) and is controlled via HTTP API.
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnforge.zap")

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "vulnforge-zap-key")

# Map ZAP risk codes to our severity levels
ZAP_RISK_MAP = {0: "info", 1: "low", 2: "medium", 3: "high"}
ZAP_CONFIDENCE_MAP = {0: "false_positive", 1: "low", 2: "medium", 3: "high", 4: "confirmed"}

# CVSS estimates per risk level
ZAP_RISK_CVSS = {0: 0.0, 1: 3.0, 2: 5.5, 3: 8.0}

SCAN_STRENGTH_MAP = {
    "quick": "LOW",
    "full": "MEDIUM",
    "deep": "HIGH",
    "insane": "INSANE",
}

SCAN_THRESHOLD_MAP = {
    "quick": "HIGH",
    "full": "MEDIUM",
    "deep": "LOW",
    "insane": "OFF",
}


class ZapScanner:
    """OWASP ZAP authenticated scanning engine."""

    def __init__(self, api_url: str = None, api_key: str = None):
        self.api_url = (api_url or ZAP_API_URL).rstrip("/")
        self.api_key = api_key or ZAP_API_KEY
        # Populated after each execute() call — accessible from the pipeline
        self.last_auth_result: dict = {}

    async def check_health(self) -> bool:
        """Check if ZAP daemon is running."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    f"{self.api_url}/JSON/core/view/version/",
                    params={"apikey": self.api_key},
                )
                data = r.json()
                version = data.get("version", "unknown")
                logger.info(f"ZAP health OK — version {version}")
                return True
        except Exception as e:
            logger.warning(f"ZAP health check failed: {e}")
            return False

    async def execute(
        self,
        target: str,
        auth_config: Optional[dict] = None,
        scan_type: str = "full",
        severity: list[str] = None,
    ) -> list[dict]:
        """
        Run an authenticated ZAP scan.

        auth_config schema:
        {
            "auth_type": "form" | "bearer" | "cookie" | "header" | "none",
            "login_url": "https://...",              # form auth
            "username_field": "username",             # form auth
            "password_field": "password",             # form auth
            "username": "admin",                      # form auth
            "password": "secret",                     # form auth
            "logged_in_indicator": "Logout|Dashboard",# regex to detect authenticated state
            "logged_out_indicator": "Login|Sign in",  # regex to detect logged-out state
            "token": "Bearer eyJ...",                 # bearer/header auth
            "header_name": "Authorization",           # header auth
            "header_value": "Bearer eyJ...",          # header auth
            "cookies": "session=abc123; token=xyz",   # cookie auth
            "exclude_urls": [".*logout.*"],           # URLs to skip during scan
        }
        """
        # connect=10 s per call; read=60 s per call (status polls are fast)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0)
        ) as client:
            try:
                logger.info(f"[ZAP] Starting scan for {target} (type={scan_type})")

                # Step 1: Create new session
                await self._zap_call(client, "core", "action", "newSession",
                                     {"name": f"scan_{int(time.time())}", "overwrite": "true"})
                logger.info("[ZAP] New session created")

                # Step 2: Configure authentication
                if auth_config and auth_config.get("auth_type", "none") != "none":
                    await self._configure_auth(client, target, auth_config)
                    logger.info(f"[ZAP] Auth configured: {auth_config.get('auth_type')}")

                    # Step 2b: Verify authentication actually worked
                    logger.info("[ZAP] Verifying authentication...")
                    auth_result = await self._verify_auth(client, target, auth_config)
                    self.last_auth_result = auth_result
                    status_icon = "✓" if auth_result["verified"] else "✗"
                    logger.info(f"[ZAP] Auth verification {status_icon}: {auth_result['message']}")
                    if not auth_result["verified"]:
                        logger.warning(
                            "[ZAP] Authentication may not be working — "
                            "scan will continue but results may be unauthenticated"
                        )
                else:
                    self.last_auth_result = {
                        "verified": True, "status_code": None,
                        "indicator_found": False, "message": "No auth configured (unauthenticated scan)",
                    }

                # Step 3: Spider the target
                logger.info(f"[ZAP] Spidering {target}...")
                await self._spider(client, target, auth_config)
                logger.info(f"[ZAP] Spider completed for {target}")

                # Step 4: Optional AJAX spider for JS-heavy apps
                logger.info(f"[ZAP] AJAX spidering {target}...")
                await self._ajax_spider(client, target)
                logger.info(f"[ZAP] AJAX spider completed for {target}")

                # Step 5: Configure scan policy
                strength = SCAN_STRENGTH_MAP.get(scan_type, "MEDIUM")
                threshold = SCAN_THRESHOLD_MAP.get(scan_type, "MEDIUM")

                # Step 6: Active scan
                logger.info(f"[ZAP] Active scanning (strength={strength}, threshold={threshold})...")
                await self._active_scan(client, target, strength, threshold)

                # Step 7: Collect alerts
                alerts = await self._get_alerts(client, target)
                logger.info(f"[ZAP] Scan complete — {len(alerts)} raw alerts returned from ZAP API")
                if not alerts:
                    logger.warning("[ZAP] No alerts found - spider may not have found URLs or scan may not have run")
                    # Try to get spider results for debugging
                    spider_r = await self._zap_call(client, "spider", "view", "results", {"scanId": "0"})
                    spider_urls = spider_r.get("results", [])
                    logger.info(f"[ZAP] Spider found {len(spider_urls)} URLs")
                    return []

                # Step 8: Normalize to our finding format
                findings = []
                for alert in alerts:
                    finding = self._normalize_alert(alert)
                    if finding:
                        if severity and finding["severity"] not in severity:
                            continue
                        findings.append(finding)

                logger.info(f"[ZAP] {len(findings)} findings after severity filter")

                # Step 9: Enrich with HTTP request/response from ZAP message history
                await self._enrich_with_http_messages(client, findings)

                return findings

            except Exception as e:
                logger.error(f"[ZAP] Scan failed: {e}")
                raise

    # ── Auth Verification ─────────────────────────────────────────────────────

    async def _verify_auth(self, client, target: str, auth_config: dict) -> dict:
        """
        After auth is configured, make ZAP fetch the target URL and inspect
        the response to confirm the session is authenticated.

        Checks (in priority order):
          1. logged_out_indicator regex found  → definite FAIL
          2. logged_in_indicator  regex found  → definite OK
          3. HTTP 401 / 403                   → likely FAIL
          4. HTTP 200-399                     → likely OK (no indicator set)
        """
        result = {
            "verified": False,
            "status_code": None,
            "indicator_found": False,
            "message": "Auth not verified",
        }
        logged_in  = (auth_config.get("logged_in_indicator")  or "").strip()
        logged_out = (auth_config.get("logged_out_indicator") or "").strip()

        try:
            # Ask ZAP to fetch the target (auth headers/cookies are already injected)
            await self._zap_call(client, "core", "action", "accessUrl",
                                 {"url": target, "followRedirects": "true"})
            await asyncio.sleep(2)  # allow ZAP to record the transaction

            # Pull recent messages for the target host
            msgs_r = await self._zap_call(client, "core", "view", "messages",
                                          {"baseurl": target, "start": "0", "count": "10"})
            messages = msgs_r.get("messages", [])
            if not messages:
                result["message"] = "No HTTP messages recorded — ZAP may not have reached the target"
                return result

            # Find the best matching message (prefer our verification request)
            target_host = target.split("//")[-1].split("/")[0]
            msg = next(
                (m for m in reversed(messages)
                 if target_host in m.get("requestHeader", "")),
                messages[-1],
            )

            # Parse status code from "HTTP/1.1 200 OK"
            resp_header = msg.get("responseHeader", "")
            resp_body   = msg.get("responseBody", "")
            status_code: int | None = None
            if resp_header:
                parts = resp_header.split("\n")[0].strip().split()
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                        result["status_code"] = status_code
                    except ValueError:
                        pass

            # Priority 1 — logged-out indicator → definite failure
            if logged_out and re.search(logged_out, resp_body, re.IGNORECASE):
                result["verified"] = False
                result["message"] = (
                    f"Auth FAILED — logged-out indicator '{logged_out[:60]}' "
                    f"found in response (HTTP {status_code})"
                )
                return result

            # Priority 2 — logged-in indicator → definite success
            if logged_in and re.search(logged_in, resp_body, re.IGNORECASE):
                result["verified"] = True
                result["indicator_found"] = True
                result["message"] = (
                    f"Auth OK — logged-in indicator '{logged_in[:60]}' "
                    f"matched (HTTP {status_code})"
                )
                return result

            # Priority 3 — status code heuristics
            if status_code == 401:
                result["message"] = "Auth FAILED — HTTP 401 Unauthorized"
            elif status_code == 403:
                result["message"] = "Auth may have failed — HTTP 403 Forbidden"
            elif status_code and status_code < 400:
                result["verified"] = True
                result["message"] = (
                    f"Auth likely OK — HTTP {status_code} "
                    f"(set logged_in_indicator for definitive check)"
                )
            else:
                result["message"] = f"Auth status unknown — HTTP {status_code}"

        except Exception as e:
            result["message"] = f"Auth verification error: {e}"
            logger.warning(f"[ZAP] Auth verification error: {e}")

        return result

    # ── Auth Configuration ────────────────────────────────────────────────────

    async def _configure_auth(self, client, target: str, auth: dict):
        """Configure ZAP authentication based on auth_type."""
        auth_type = auth.get("auth_type", "none")
        parsed = urlparse(target)
        context_name = "vulnforge"

        # Create context
        r = await self._zap_call(client, "context", "action", "newContext",
                                 {"contextName": context_name})
        context_id = r.get("contextId", "1")

        # Include target in context
        include_regex = f"{parsed.scheme}://{parsed.netloc}.*"
        await self._zap_call(client, "context", "action", "includeInContext",
                             {"contextName": context_name, "regex": include_regex})

        # Exclude URLs
        for pattern in auth.get("exclude_urls", []):
            await self._zap_call(client, "context", "action", "excludeFromContext",
                                 {"contextName": context_name, "regex": pattern})

        if auth_type == "form":
            await self._setup_form_auth(client, context_id, context_name, auth)

        elif auth_type == "bearer":
            token = auth.get("token", "")
            await self._inject_header(client, "Authorization", f"Bearer {token}")

        elif auth_type == "header":
            header_name = auth.get("header_name", "Authorization")
            header_value = auth.get("header_value", "")
            await self._inject_header(client, header_name, header_value)

        elif auth_type == "cookie":
            cookies = auth.get("cookies", "")
            await self._inject_header(client, "Cookie", cookies)

        elif auth_type == "script":
            await self._setup_script_auth(client, context_id, context_name, auth)

    async def _setup_form_auth(self, client, context_id: str, context_name: str, auth: dict):
        """Configure form-based authentication in ZAP."""
        login_url = auth.get("login_url", "")
        username_field = auth.get("username_field", "username")
        password_field = auth.get("password_field", "password")
        username = auth.get("username", "")
        password = auth.get("password", "")

        # Set form-based auth method
        login_request = (
            f"loginUrl={login_url}&"
            f"loginRequestData={username_field}%3D%7B%25username%25%7D"
            f"%26{password_field}%3D%7B%25password%25%7D"
        )
        await self._zap_call(client, "authentication", "action", "setAuthenticationMethod",
                             {"contextId": context_id, "authMethodName": "formBasedAuthentication",
                              "authMethodConfigParams": login_request})

        # Set logged-in indicator
        if auth.get("logged_in_indicator"):
            await self._zap_call(client, "authentication", "action", "setLoggedInIndicator",
                                 {"contextId": context_id, "loggedInIndicatorRegex": auth["logged_in_indicator"]})

        if auth.get("logged_out_indicator"):
            await self._zap_call(client, "authentication", "action", "setLoggedOutIndicator",
                                 {"contextId": context_id, "loggedOutIndicatorRegex": auth["logged_out_indicator"]})

        # Create user with credentials
        r = await self._zap_call(client, "users", "action", "newUser",
                                 {"contextId": context_id, "name": "vulnforge-user"})
        user_id = r.get("userId", "0")

        cred_params = f"username={username}&password={password}"
        await self._zap_call(client, "users", "action", "setAuthenticationCredentials",
                             {"contextId": context_id, "userId": user_id,
                              "authCredentialsConfigParams": cred_params})

        await self._zap_call(client, "users", "action", "setUserEnabled",
                             {"contextId": context_id, "userId": user_id, "enabled": "true"})

        await self._zap_call(client, "forcedUser", "action", "setForcedUser",
                             {"contextId": context_id, "userId": user_id})
        
        # Enable forced user mode (global setting, may fail on some ZAP versions)
        try:
            await self._zap_call(client, "forcedUser", "action", "setForcedUserModeEnabled",
                                 {"mode": "true"})
        except Exception as e:
            logger.warning(f"[ZAP] Could not enable forced user mode: {e}. Continuing with scan...")

        logger.info(f"[ZAP] Form auth configured: {login_url} (user={username})")

    async def _inject_header(self, client, name: str, value: str):
        """Add a custom header to all ZAP requests (replacer add-on)."""
        await self._zap_call(client, "replacer", "action", "addRule", {
            "description": f"Auth-{name}",
            "enabled": "true",
            "matchType": "REQ_HEADER",
            "matchRegex": "false",
            "matchString": name,
            "replacement": value,
            "initiators": "",
        })
        logger.info(f"[ZAP] Injected header: {name}: {value[:30]}...")

    # ── Token/Cookie Acquisition ──────────────────────────────────────────────

    async def fetch_auth_via_curl(self, curl_command: str) -> dict:
        """
        Execute a curl command to fetch authentication tokens/cookies.
        
        Args:
            curl_command: Full curl command string to execute (e.g., "curl -X POST https://app.com/login -d 'user=admin&pass=secret'")
        
        Returns:
            dict with keys: {
                "success": bool,
                "auth_type": str ("bearer", "cookie", "header", "json"),
                "token": str (extracted token/JWT),
                "cookies": str (Set-Cookie header values),
                "headers": dict (response headers),
                "raw_response": str (response body),
                "error": str (error message if failed)
            }
        """
        try:
            import subprocess
            
            logger.info(f"[ZAP] Executing curl command: {curl_command[:100]}...")
            result = subprocess.run(
                curl_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"curl failed with exit code {result.returncode}: {result.stderr}",
                    "auth_type": None,
                    "token": None,
                    "cookies": None,
                    "headers": {},
                    "raw_response": result.stdout
                }
            
            response_body = result.stdout.strip()
            logger.info(f"[ZAP] curl response received ({len(response_body)} bytes)")
            
            # Try to parse as JSON and extract token
            token = None
            auth_type = None
            try:
                data = json.loads(response_body)
                if isinstance(data, dict):
                    # Common token field names
                    for key in ["token", "access_token", "jwt", "authToken", "Bearer"]:
                        if key in data:
                            token = data[key]
                            auth_type = "bearer"
                            break
                    if not token:
                        logger.info(f"[ZAP] No recognized token field in JSON response. Keys: {list(data.keys())}")
            except json.JSONDecodeError:
                logger.info("[ZAP] Response is not JSON, treating as raw token/cookie")
                if response_body.startswith("eyJ"):  # likely JWT
                    token = response_body
                    auth_type = "bearer"
            
            return {
                "success": True,
                "auth_type": auth_type or "bearer",
                "token": token or response_body[:500],
                "cookies": None,
                "headers": {},
                "raw_response": response_body
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"curl execution error: {e}",
                "auth_type": None,
                "token": None,
                "cookies": None,
                "headers": {},
                "raw_response": ""
            }

    async def fetch_auth_via_python(self, login_url: str, credentials: dict) -> dict:
        """
        Fetch authentication tokens/cookies using Python HTTP client.
        
        Args:
            login_url: URL to POST login credentials to
            credentials: dict with keys like {
                "username": "admin",
                "password": "secret",
                "extra_field": "value"  # any additional fields to include in POST
            }
        
        Returns:
            Same dict format as fetch_auth_via_curl
        """
        try:
            logger.info(f"[ZAP] Fetching auth via Python: POST {login_url}")
            
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(login_url, data=credentials, follow_redirects=True)
                
                response_body = response.text
                logger.info(f"[ZAP] Auth response: {response.status_code} ({len(response_body)} bytes)")
                
                # Extract Set-Cookie headers
                cookies_list = response.headers.get_list("set-cookie")
                cookies_str = "; ".join(cookies_list) if cookies_list else None
                
                # Try to extract token from response
                token = None
                auth_type = None
                try:
                    data = response.json()
                    if isinstance(data, dict):
                        for key in ["token", "access_token", "jwt", "authToken", "Bearer"]:
                            if key in data:
                                token = data[key]
                                auth_type = "bearer"
                                break
                except:
                    if response_body.startswith("eyJ"):
                        token = response_body
                        auth_type = "bearer"
                
                return {
                    "success": response.status_code < 400,
                    "auth_type": auth_type or ("cookie" if cookies_str else "bearer"),
                    "token": token,
                    "cookies": cookies_str,
                    "headers": dict(response.headers),
                    "raw_response": response_body[:1000]
                }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Python auth fetch error: {e}",
                "auth_type": None,
                "token": None,
                "cookies": None,
                "headers": {},
                "raw_response": ""
            }

    async def fetch_auth_via_selenium(self, selenium_script: str) -> dict:
        """
        Fetch authentication using Selenium browser automation.
        
        Args:
            selenium_script: Python code to execute with Selenium. Must set:
                - window['_vulnforge_token'] for bearer token
                - window.document.cookie for cookies
                - window['_vulnforge_headers'] for custom headers
        
        Example script:
        '''
        from selenium import webdriver
        driver = webdriver.Chrome()
        driver.get("https://app.com/login")
        # interact with page...
        driver.execute_script("window._vulnforge_token = localStorage.getItem('auth_token')")
        '''
        
        Returns:
            Same dict format as fetch_auth_via_curl
        """
        try:
            logger.info("[ZAP] Fetching auth via Selenium...")
            
            # Check if Selenium is available
            try:
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options
            except ImportError:
                return {
                    "success": False,
                    "error": "Selenium not installed. Install with: pip install selenium",
                    "auth_type": None,
                    "token": None,
                    "cookies": None,
                    "headers": {},
                    "raw_response": ""
                }
            
            # Setup headless Chrome
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            
            driver = None
            try:
                driver = webdriver.Chrome(options=chrome_options)
                
                # Execute the provided script
                logger.info("[ZAP] Executing Selenium script...")
                exec(selenium_script, {"webdriver": webdriver, "driver": driver})
                
                # Extract collected auth data from JavaScript
                token = driver.execute_script("return window._vulnforge_token")
                cookies_str = driver.execute_script("return document.cookie")
                headers = driver.execute_script("return window._vulnforge_headers || {}")
                
                logger.info(f"[ZAP] Selenium auth result: token={'set' if token else 'not set'}, cookies={'set' if cookies_str else 'not set'}")
                
                return {
                    "success": bool(token or cookies_str),
                    "auth_type": "bearer" if token else ("cookie" if cookies_str else "header"),
                    "token": token,
                    "cookies": cookies_str,
                    "headers": headers if isinstance(headers, dict) else {},
                    "raw_response": f"token={bool(token)}, cookies={bool(cookies_str)}"
                }
            
            finally:
                if driver:
                    driver.quit()
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Selenium execution error: {e}",
                "auth_type": None,
                "token": None,
                "cookies": None,
                "headers": {},
                "raw_response": ""
            }

    async def initiate_authenticated_scan(self, target: str, auth_method: str, 
                                         auth_data: dict, scan_type: str = "full",
                                         severity: list[str] = None) -> list[dict]:
        """
        Initiate a ZAP scan with automatically fetched authentication credentials.
        
        Supports three methods to fetch credentials:
        1. curl: Execute a curl command
        2. python: HTTP POST to login URL
        3. selenium: Browser automation
        
        Args:
            target: Target URL to scan
            auth_method: "curl" | "python" | "selenium"
            auth_data: Configuration for the auth method:
                - For "curl": {"curl_command": "curl -X POST ..."}
                - For "python": {"login_url": "...", "credentials": {"username": "...", "password": "..."}}
                - For "selenium": {"script": "selenium python code..."}
            scan_type: "quick" | "full" | "deep" | "insane"
            severity: list of severity levels to include
        
        Returns:
            list of vulnerability findings from the scan
        """
        logger.info(f"[ZAP] Starting authenticated scan via {auth_method} method")
        
        # Step 1: Fetch authentication credentials
        auth_result = None
        if auth_method == "curl":
            auth_result = await self.fetch_auth_via_curl(auth_data.get("curl_command", ""))
        elif auth_method == "python":
            auth_result = await self.fetch_auth_via_python(
                auth_data.get("login_url", ""),
                auth_data.get("credentials", {})
            )
        elif auth_method == "selenium":
            auth_result = await self.fetch_auth_via_selenium(auth_data.get("script", ""))
        else:
            raise ValueError(f"Unknown auth_method: {auth_method}. Use 'curl', 'python', or 'selenium'")
        
        if not auth_result.get("success"):
            error_msg = auth_result.get("error", "Unknown error")
            logger.error(f"[ZAP] Auth fetch failed: {error_msg}")
            raise RuntimeError(f"Failed to fetch authentication: {error_msg}")
        
        logger.info(f"[ZAP] Auth fetch successful: {auth_result['auth_type']}")
        
        # Step 2: Build auth_config from the fetched credentials
        auth_config = {
            "auth_type": auth_result["auth_type"] or "bearer",
            "exclude_urls": auth_data.get("exclude_urls", []),
            "logged_in_indicator": auth_data.get("logged_in_indicator"),
            "logged_out_indicator": auth_data.get("logged_out_indicator"),
        }
        
        # Populate auth_config based on auth_type
        if auth_result["auth_type"] == "bearer":
            auth_config["token"] = auth_result.get("token", "")
        elif auth_result["auth_type"] == "cookie":
            auth_config["cookies"] = auth_result.get("cookies", "")
        elif auth_result["auth_type"] == "header":
            headers_dict = auth_result.get("headers", {})
            if headers_dict:
                for key, value in headers_dict.items():
                    if key.lower() in ["authorization", "x-api-key", "x-token"]:
                        auth_config["header_name"] = key
                        auth_config["header_value"] = value
                        break
        
        # Step 3: Execute the ZAP scan with injected credentials
        logger.info(f"[ZAP] Executing scan with injected {auth_result['auth_type']} auth")
        findings = await self.execute(target, auth_config=auth_config, 
                                     scan_type=scan_type, severity=severity)
        
        logger.info(f"[ZAP] Authenticated scan complete: {len(findings)} findings")
        return findings

    # ── Script-Based Authentication ───────────────────────────────────────────

    # Path inside ZAP container where the shared volume is mounted
    _ZAP_SCRIPT_DIR = "/zap/scripts/vulnforge"

    async def _get_available_engines(self, client) -> list[str]:
        """Return the list of scripting engine names ZAP has installed."""
        try:
            r = await self._zap_call(client, "script", "view", "listEngines", {})
            return r.get("listEngines", [])
        except Exception as e:
            logger.warning(f"[ZAP] Could not list script engines: {e}")
            return []

    def _pick_engine(self, ext: str, available: list[str]) -> str:
        """
        Choose the best available ZAP scripting engine for *ext*.
        Priority for .zst: ZEST first (ZAP recording format), then JS engines.
        Priority for .js:  GraalVM > ECMAScript > Nashorn (legacy).
        """
        if ext == "groovy":
            keywords = ["groovy"]
        elif ext == "py":
            keywords = ["jython", "python"]
        elif ext == "zst":
            # .zst could be a ZEST JSON recording OR a renamed JS script.
            # Try ZEST first so recordings work; fall back to JS engines.
            keywords = ["zest", "graalvm", "graal", "ecmascript", "nashorn"]
        else:
            # .js / unknown → JavaScript engine
            keywords = ["graalvm", "graal", "ecmascript", "nashorn"]

        for kw in keywords:
            for eng in available:
                if kw in eng.lower():
                    return eng

        # Last resort: first available engine or hard-coded fallback
        return available[0] if available else "GraalVM"

    async def _load_script_into_zap(self, client, script_name: str,
                                     engine_hint: str = None) -> None:
        """Register a ZAP authentication script from the shared volume."""
        script_path = os.path.join(self._ZAP_SCRIPT_DIR, script_name)

        # Remove any stale version first (ignore errors — script may not exist)
        try:
            await self._zap_call(client, "script", "action", "remove",
                                 {"scriptName": script_name})
        except Exception:
            pass

        if engine_hint:
            # Caller already determined the engine (e.g. "ZEST" for recordings)
            engine = engine_hint
            logger.info(f"[ZAP] Using engine hint '{engine}' for '{script_name}'")
        else:
            # Auto-detect from file extension and ZAP's installed engines
            engines = await self._get_available_engines(client)
            logger.info(f"[ZAP] Available script engines: {engines}")
            ext = script_name.rsplit(".", 1)[-1].lower()
            engine = self._pick_engine(ext, engines)
            logger.info(f"[ZAP] Auto-selected engine '{engine}' for '{script_name}'")

        await self._zap_call(client, "script", "action", "load", {
            "scriptName":        script_name,
            "scriptType":        "authentication",
            "scriptEngine":      engine,
            "fileName":          script_path,
            "scriptDescription": f"VulnForge auth script: {script_name}",
        })

        # Verify ZAP actually registered the script without errors
        await self._verify_script_loaded(client, script_name)
        logger.info(f"[ZAP] Auth script '{script_name}' ready (engine={engine})")

    async def _verify_script_loaded(self, client, script_name: str) -> None:
        """
        Check that ZAP registered the script and it has no compile errors.
        Raises RuntimeError with a human-readable message on failure.
        """
        try:
            r = await self._zap_call(client, "script", "view", "listScripts", {})
            scripts = r.get("listScripts", [])
        except Exception as e:
            logger.warning(f"[ZAP] Could not verify script list: {e}")
            return  # non-fatal — let setAuthenticationMethod surface any real error

        for s in scripts:
            if s.get("name") == script_name:
                if s.get("error"):
                    # Collect every detail ZAP gives us about the failure
                    details = []
                    for field in ("lastOutput", "description", "errorLine", "errorMsg"):
                        val = s.get(field, "")
                        if val:
                            details.append(f"{field}: {val}")

                    # Also try script/view/scriptInfo for richer error
                    try:
                        info = await self._zap_call(client, "script", "view",
                                                    "scriptInfo", {"scriptName": script_name})
                        for field in ("lastOutput", "errorLine", "errorMsg"):
                            val = info.get(field, "")
                            if val and f"{field}: {val}" not in details:
                                details.append(f"{field}: {val}")
                    except Exception:
                        pass

                    error_detail = " | ".join(details) if details else "no details from ZAP"
                    logger.error(f"[ZAP] Script '{script_name}' error: {error_detail}")

                    hint = (
                        "Common cause: script written for Nashorn uses importPackage() / "
                        "importClass() which GraalVM does not support. "
                        "Replace with Java.type('fully.qualified.ClassName') instead. "
                        "See: backend/zap_auth_script_template.js"
                    )
                    raise RuntimeError(
                        f"ZAP script '{script_name}' failed to load.\n"
                        f"ZAP error → {error_detail}\n"
                        f"Hint → {hint}"
                    )
                return

        raise RuntimeError(
            f"ZAP script '{script_name}' was not found after load attempt. "
            f"Check that the shared volume is mounted and the file exists at "
            f"{self._ZAP_SCRIPT_DIR}/{script_name}."
        )

    # Backend container path for the shared scripts volume
    _BACKEND_SCRIPT_DIR = os.getenv("ZAP_SCRIPTS_DIR", "/app/zap-scripts")

    def _try_extract_zest_auth(self, script_name: str) -> Optional[dict]:
        """
        If the script file is JSON (any structure), try to extract a login
        request from it and return a form-auth config.

        JSON files cannot be executed as JavaScript by ZAP's GraalVM engine —
        they are always ZEST recordings or some other JSON-based auth config.
        Returns None only if the file is not JSON or has no extractable POST.
        """
        from urllib.parse import parse_qs

        path = os.path.join(self._BACKEND_SCRIPT_DIR, script_name)
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except FileNotFoundError:
            logger.warning(f"[ZAP] Script file not found at {path}")
            return None
        except Exception as e:
            logger.warning(f"[ZAP] Could not read script file: {e}")
            return None

        # If the file is not JSON it is a real JS/Groovy/Python script — leave it alone
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.info(f"[ZAP] '{script_name}' is binary/text — treating as native script")
            return None

        if not isinstance(data, dict):
            return None

        top_keys = list(data.keys())
        logger.info(f"[ZAP] '{script_name}' is JSON — top-level keys: {top_keys}")

        _USER = {"user", "login", "email", "uid", "uname", "account", "username"}
        _PASS = {"pass", "pwd", "secret", "psw", "passw", "password", "passwd"}

        _USER = {"user", "login", "email", "uid", "uname", "account", "username"}
        _PASS = {"pass", "pwd", "secret", "psw", "passw", "password", "passwd"}

        statements = data.get("statements", [])
        elem_types = {s.get("elementType") for s in statements}
        logger.info(f"[ZAP] ZEST has {len(statements)} statement(s), types: {elem_types}")

        # ── Strategy 1: ZestRequest (HTTP-level proxy recording) ─────────────
        for stmt in statements:
            if stmt.get("elementType") != "ZestRequest":
                continue
            if stmt.get("method", "").upper() != "POST":
                continue
            url  = stmt.get("url", "").strip()
            body = stmt.get("data", "").strip()
            if not url:
                continue
            params = {}
            if body:
                try:
                    params = parse_qs(body, keep_blank_values=True)
                except Exception:
                    pass
            uf = pf = uv = pv = None
            for key, vals in params.items():
                val = vals[0] if vals else ""
                kl  = key.lower()
                if any(h in kl for h in _USER) and uf is None:
                    uf, uv = key, val
                elif any(h in kl for h in _PASS) and pf is None:
                    pf, pv = key, val
            logger.info(f"[ZAP] ZestRequest POST: url={url} user={uf} pass={pf}")
            return {"auth_type": "form", "login_url": url,
                    "username_field": uf or "username", "password_field": pf or "password",
                    "username": uv or "", "password": pv or "",
                    "logged_in_indicator": None, "logged_out_indicator": None,
                    "exclude_urls": []}

        # ── Strategy 2: ZestClient (browser-automation recording) ────────────
        # ZestClientLaunch gives the page URL.
        # ZestClientElementSendKeys gives the element ID and the typed value.
        launch_url = None
        uf = pf = uv = pv = None
        for stmt in statements:
            et = stmt.get("elementType", "")
            if et == "ZestClientLaunch" and not launch_url:
                launch_url = stmt.get("url", "").strip()
            elif et == "ZestClientElementSendKeys":
                element = stmt.get("element", "")   # HTML element id
                value   = stmt.get("value", "")
                kl      = element.lower()
                if any(h in kl for h in _USER) and uf is None:
                    uf, uv = element, value
                elif any(h in kl for h in _PASS) and pf is None:
                    pf, pv = element, value

        if launch_url and uf and pf:
            logger.info(
                f"[ZAP] ZestClient browser auth: url={launch_url} "
                f"user_field={uf}={uv!r} pass_field={pf}"
            )
            return {"auth_type": "form", "login_url": launch_url,
                    "username_field": uf, "password_field": pf,
                    "username": uv or "", "password": pv or "",
                    "logged_in_indicator": None, "logged_out_indicator": None,
                    "exclude_urls": []}

        logger.warning(f"[ZAP] '{script_name}' is JSON but no extractable login. Keys: {top_keys}")
        return None

    async def _setup_script_auth(self, client, context_id: str,
                                  context_name: str, auth: dict) -> None:
        """Configure ZAP context to use script-based authentication."""
        script_name = auth.get("script_name", "")
        engine_hint = auth.get("script_engine")
        if not script_name:
            raise ValueError("auth_type='script' requires script_name")

        # ── JSON files (ZEST recordings, custom formats) cannot run as JS scripts.
        # Check the file content FIRST — if it is JSON, extract form auth directly.
        # This avoids the GraalVM engine rejecting the file with a cryptic error.
        zest_auth = self._try_extract_zest_auth(script_name)
        if zest_auth is not None:
            await self._setup_form_auth(client, context_id, context_name, zest_auth)
            logger.info(f"[ZAP] JSON script '{script_name}' → form auth configured")
            return

        # ── Real JS / Groovy / Python auth script ────────────────────────────
        await self._load_script_into_zap(client, script_name, engine_hint=engine_hint)

        # 2. Set authentication method → scriptBasedAuthentication
        await self._zap_call(
            client, "authentication", "action", "setAuthenticationMethod", {
                "contextId":              context_id,
                "authMethodName":         "scriptBasedAuthentication",
                "authMethodConfigParams": f"scriptName={script_name}",
            }
        )

        # 3. Optional indicators
        if auth.get("logged_in_indicator"):
            await self._zap_call(client, "authentication", "action",
                                 "setLoggedInIndicator",
                                 {"contextId": context_id,
                                  "loggedInIndicatorRegex": auth["logged_in_indicator"]})
        if auth.get("logged_out_indicator"):
            await self._zap_call(client, "authentication", "action",
                                 "setLoggedOutIndicator",
                                 {"contextId": context_id,
                                  "loggedOutIndicatorRegex": auth["logged_out_indicator"]})

        # 4. Create a user + enable forced-user mode
        r = await self._zap_call(client, "users", "action", "newUser",
                                 {"contextId": context_id, "name": "vulnforge-script-user"})
        user_id = r.get("userId", "0")
        await self._zap_call(client, "users", "action", "setUserEnabled",
                             {"contextId": context_id, "userId": user_id, "enabled": "true"})
        await self._zap_call(client, "forcedUser", "action", "setForcedUser",
                             {"contextId": context_id, "userId": user_id})
        try:
            await self._zap_call(client, "forcedUser", "action",
                                 "setForcedUserModeEnabled", {"mode": "true"})
        except Exception:
            pass

        logger.info(f"[ZAP] Script-based auth configured with '{script_name}'")

    # ── Scanning Phases ───────────────────────────────────────────────────────

    async def _spider(self, client, target: str, auth_config: dict = None):
        """Run ZAP spider (traditional crawler)."""
        params = {"url": target, "maxChildren": "50", "recurse": "true",
                  "subtreeOnly": "true", "apikey": self.api_key}

        r = await self._zap_call(client, "spider", "action", "scan", params)
        logger.debug(f"[ZAP] Spider scan API response: {r}")
        scan_id = r.get("scan", r.get("scanId", "0"))  # Try both "scan" and "scanId"
        logger.info(f"[ZAP] Spider started with scanId={scan_id}")

        if scan_id == "0":
            logger.warning(f"[ZAP] Spider response returned no scan ID. Full response: {r}")

        for attempt in range(300):  # 5 min timeout
            r = await self._zap_call(client, "spider", "view", "status", {"scanId": scan_id})
            status = int(r.get("status", "0"))
            if attempt == 0 or attempt % 30 == 0:  # Log periodically
                logger.info(f"[ZAP] Spider status poll #{attempt}: {status}%")
            if status >= 100:
                logger.info(f"[ZAP] Spider completed at 100%")
                break
            await asyncio.sleep(1)

        r = await self._zap_call(client, "spider", "view", "results", {"scanId": scan_id})
        urls = r.get("results", [])
        logger.info(f"[ZAP] Spider found {len(urls)} URLs")

    async def _ajax_spider(self, client, target: str):
        """Run ZAP AJAX spider for JS-rendered content."""
        try:
            await self._zap_call(client, "ajaxSpider", "action", "scan",
                                 {"url": target, "subtreeOnly": "true"})

            for _ in range(120):  # 2 min timeout
                r = await self._zap_call(client, "ajaxSpider", "view", "status")
                if r.get("status") == "stopped":
                    break
                await asyncio.sleep(1)
            else:
                await self._zap_call(client, "ajaxSpider", "action", "stop")

            r = await self._zap_call(client, "ajaxSpider", "view", "numberOfResults")
            logger.info(f"[ZAP] AJAX spider found {r.get('numberOfResults', 0)} results")
        except Exception as e:
            logger.warning(f"[ZAP] AJAX spider failed (non-fatal): {e}")

    async def _active_scan(self, client, target: str, strength: str, threshold: str):
        """Run ZAP active scan."""
        # Set scan policy
        try:
            logger.info(f"[ZAP] Configuring scan policy: strength={strength}, threshold={threshold}")
            await self._zap_call(client, "ascan", "action", "enableAllScanners")
            await self._zap_call(client, "ascan", "action", "setOptionAttackStrength",
                                 {"String": strength})
            await self._zap_call(client, "ascan", "action", "setOptionAlertThreshold",
                                 {"String": threshold})
            logger.info(f"[ZAP] Scan policy configured successfully")
        except Exception as e:
            logger.warning(f"[ZAP] Could not configure scan policy (non-fatal): {e}")

        logger.info(f"[ZAP] Starting active scan on {target}...")
        r = await self._zap_call(client, "ascan", "action", "scan",
                                 {"url": target, "recurse": "true", "subtreeOnly": "true"})
        logger.debug(f"[ZAP] Active scan API response: {r}")
        scan_id = r.get("scan", r.get("scanId", "0"))  # Try both "scan" and "scanId"
        logger.info(f"[ZAP] Active scan started with scanId={scan_id}")
        
        if scan_id == "0":
            logger.warning(f"[ZAP] Active scan response returned no scan ID. Full response: {r}")

        consecutive_failures = 0
        max_consecutive_failures = 10
        last_log_status = -1

        for _ in range(1800):  # up to 1 hour (1800 × 2 s)
            try:
                r = await self._zap_call(client, "ascan", "view", "status", {"scanId": scan_id})
                status = int(r.get("status", "0"))
                consecutive_failures = 0
                if status >= 100:
                    logger.info("[ZAP] Active scan complete (100%)")
                    break
                if status % 10 == 0 and status != last_log_status:
                    last_log_status = status
                    logger.info(f"[ZAP] Active scan progress: {status}%")
            except Exception as e:
                consecutive_failures += 1
                logger.warning(
                    f"[ZAP] Status poll failed ({consecutive_failures}/{max_consecutive_failures}): {e}"
                )
                if consecutive_failures >= max_consecutive_failures:
                    logger.error("[ZAP] Too many consecutive poll failures — collecting partial results")
                    break
            await asyncio.sleep(2)
        else:
            try:
                await self._zap_call(client, "ascan", "action", "stop", {"scanId": scan_id})
            except Exception:
                pass
            logger.warning("[ZAP] Active scan timed out after 1 hour")

    async def _enrich_with_http_messages(self, client, findings: list[dict]) -> None:
        """
        Fetch full HTTP request/response from ZAP history for each finding.
        Populates http_request and http_response fields in-place.
        Strips the temp _zap_message_id field when done.
        """
        for finding in findings:
            msg_id = finding.pop("_zap_message_id", None)
            if not msg_id:
                continue
            try:
                r = await self._zap_call(client, "core", "view", "message", {"id": msg_id})
                msg = r.get("message", {})
                req_header = (msg.get("requestHeader") or "").strip()
                req_body   = (msg.get("requestBody")   or "").strip()
                resp_header = (msg.get("responseHeader") or "").strip()
                resp_body   = (msg.get("responseBody")   or "").strip()
                if req_header:
                    finding["http_request"] = req_header + ("\r\n\r\n" + req_body if req_body else "")
                if resp_header:
                    resp_body_trunc = resp_body[:8192] + ("…[truncated]" if len(resp_body) > 8192 else "")
                    finding["http_response"] = resp_header + ("\r\n\r\n" + resp_body_trunc if resp_body_trunc else "")
            except Exception as e:
                logger.debug(f"[ZAP] HTTP message fetch failed for msg {msg_id}: {e}")

    async def _get_alerts(self, client, target: str) -> list[dict]:
        """Fetch all alerts from ZAP."""
        r = await self._zap_call(client, "alert", "view", "alerts",
                                 {"baseurl": target, "start": "0", "count": "5000"})
        return r.get("alerts", [])

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _zap_call(self, client, component: str, op_type: str,
                        operation: str, params: dict = None, retries: int = 3) -> dict:
        """Make a ZAP API call with retry logic for transient failures."""
        url = f"{self.api_url}/JSON/{component}/{op_type}/{operation}/"
        p = {"apikey": self.api_key}
        if params:
            p.update(params)

        last_err: Exception = RuntimeError("No attempts made")
        for attempt in range(retries):
            try:
                r = await client.get(url, params=p)
                r.raise_for_status()
                return r.json()
            except Exception as e:
                last_err = e
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)  # 1 s, 2 s backoff
        raise last_err

    def _normalize_alert(self, alert: dict) -> Optional[dict]:
        """Convert a ZAP alert to our finding schema."""
        # Handle risk as either int or string (ZAP can return both)
        risk_val = alert.get("risk", "0")
        try:
            risk = int(risk_val) if isinstance(risk_val, str) else risk_val
        except (ValueError, TypeError):
            # If risk is a string like "Informational", "Low", etc., map it
            risk_map_str = {"informational": 0, "low": 1, "medium": 2, "high": 3}
            risk = risk_map_str.get(str(risk_val).lower(), 0)
        
        severity = ZAP_RISK_MAP.get(risk, "info")
        
        # Handle confidence similarly
        conf_val = alert.get("confidence", "0")
        try:
            confidence = int(conf_val) if isinstance(conf_val, str) else conf_val
        except (ValueError, TypeError):
            confidence = 0

        cwe_id = alert.get("cweid", "")
        cve_id = None
        if alert.get("reference", ""):
            # Try to extract CVE from references
            cve_match = re.search(r"CVE-\d{4}-\d+", alert.get("reference", ""))
            if cve_match:
                cve_id = cve_match.group()

        tags = ["zap", f"cwe-{cwe_id}" if cwe_id and cwe_id != "-1" else None,
                "authenticated-scan"]
        tags = [t for t in tags if t]

        return {
            "template_id": f"zap-{alert.get('pluginId', 'unknown')}",
            "name": alert.get("name", alert.get("alert", "Unknown ZAP Alert")),
            "severity": severity,
            "description": (alert.get("description", "") or "").strip(),
            "host": urlparse(alert.get("url", "")).netloc,
            "matched_at": alert.get("url", ""),
            "url": alert.get("url", ""),
            "curl_command": "",
            "extracted_results": json.dumps({
                "evidence": alert.get("evidence", ""),
                "param": alert.get("param", ""),
                "attack": alert.get("attack", ""),
                "other": alert.get("other", ""),
            }),
            "tags": json.dumps(tags),
            "reference": alert.get("reference", ""),
            "matcher_name": f"confidence-{ZAP_CONFIDENCE_MAP.get(confidence, 'unknown')}",
            "vuln_type": "zap-active-scan",
            "cve_id": cve_id,
            "cvss_score": ZAP_RISK_CVSS.get(risk, 0.0),
            # Temp field used by callers to fetch HTTP message; stripped before DB insert
            "_zap_message_id": str(alert.get("messageId", "")),
        }
