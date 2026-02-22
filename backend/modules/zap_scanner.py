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

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://zap:8080")
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
        async with httpx.AsyncClient(timeout=600) as client:
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

                # Step 3: Spider the target
                logger.info(f"[ZAP] Spidering {target}...")
                await self._spider(client, target, auth_config)

                # Step 4: Optional AJAX spider for JS-heavy apps
                logger.info(f"[ZAP] AJAX spidering {target}...")
                await self._ajax_spider(client, target)

                # Step 5: Configure scan policy
                strength = SCAN_STRENGTH_MAP.get(scan_type, "MEDIUM")
                threshold = SCAN_THRESHOLD_MAP.get(scan_type, "MEDIUM")

                # Step 6: Active scan
                logger.info(f"[ZAP] Active scanning (strength={strength}, threshold={threshold})...")
                await self._active_scan(client, target, strength, threshold)

                # Step 7: Collect alerts
                alerts = await self._get_alerts(client, target)
                logger.info(f"[ZAP] Scan complete — {len(alerts)} alerts found")

                # Step 8: Normalize to our finding format
                findings = []
                for alert in alerts:
                    finding = self._normalize_alert(alert)
                    if finding:
                        if severity and finding["severity"] not in severity:
                            continue
                        findings.append(finding)

                logger.info(f"[ZAP] {len(findings)} findings after severity filter")
                return findings

            except Exception as e:
                logger.error(f"[ZAP] Scan failed: {e}")
                raise

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
        await self._zap_call(client, "forcedUser", "action", "setForcedUserModeEnabled",
                             {"enabled": "true"})

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

    # ── Scanning Phases ───────────────────────────────────────────────────────

    async def _spider(self, client, target: str, auth_config: dict = None):
        """Run ZAP spider (traditional crawler)."""
        params = {"url": target, "maxChildren": "50", "recurse": "true",
                  "subtreeOnly": "true", "apikey": self.api_key}

        r = await self._zap_call(client, "spider", "action", "scan", params)
        scan_id = r.get("scan", "0")

        for _ in range(300):  # 5 min timeout
            r = await self._zap_call(client, "spider", "view", "status", {"scanId": scan_id})
            status = int(r.get("status", "0"))
            if status >= 100:
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
            await self._zap_call(client, "ascan", "action", "enableAllScanners")
            await self._zap_call(client, "ascan", "action", "setOptionAttackStrength",
                                 {"String": strength})
            await self._zap_call(client, "ascan", "action", "setOptionAlertThreshold",
                                 {"String": threshold})
        except Exception:
            pass  # Some ZAP versions don't support global setter

        r = await self._zap_call(client, "ascan", "action", "scan",
                                 {"url": target, "recurse": "true", "subtreeOnly": "true"})
        scan_id = r.get("scan", "0")

        for _ in range(3600):  # 1 hour timeout
            r = await self._zap_call(client, "ascan", "view", "status", {"scanId": scan_id})
            status = int(r.get("status", "0"))
            if status >= 100:
                break
            if status % 10 == 0:
                logger.info(f"[ZAP] Active scan progress: {status}%")
            await asyncio.sleep(2)
        else:
            await self._zap_call(client, "ascan", "action", "stop", {"scanId": scan_id})
            logger.warning("[ZAP] Active scan timed out after 1 hour")

    async def _get_alerts(self, client, target: str) -> list[dict]:
        """Fetch all alerts from ZAP."""
        r = await self._zap_call(client, "alert", "view", "alerts",
                                 {"baseurl": target, "start": "0", "count": "5000"})
        return r.get("alerts", [])

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _zap_call(self, client, component: str, op_type: str,
                        operation: str, params: dict = None) -> dict:
        """Make a ZAP API call."""
        url = f"{self.api_url}/JSON/{component}/{op_type}/{operation}/"
        p = {"apikey": self.api_key}
        if params:
            p.update(params)

        r = await client.get(url, params=p)
        r.raise_for_status()
        return r.json()

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
        }
