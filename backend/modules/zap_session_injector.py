"""
ZAP Session Injection — Inject captured session data into ZAP for authenticated scanning.

Supports:
  - Cookie-based sessions: Creates named sessions and injects cookies via httpSessions API
  - JWT / Bearer tokens: Uses Replacer API to inject Authorization header
  - Custom headers: Injects via Replacer API
  - Session verification: Makes test request to verify session is active
"""

import json
import logging
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnforge.zap_session")


class ZapSessionInjector:
    """Inject captured session data into ZAP for authenticated scanning."""

    def __init__(self, api_url: str = "http://zap:8080", api_key: str = "vulnforge-zap-key"):
        """
        Initialize ZAP session injector.

        Args:
            api_url: ZAP API URL (default: http://zap:8080)
            api_key: ZAP API key for authentication
        """
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key

    async def inject_session(
        self,
        target_url: str,
        session_data: Dict[str, Any],
        session_name: str = "vulnforge-session",
    ) -> Dict[str, Any]:
        """
        Inject captured session data into ZAP.

        Args:
            target_url: Target URL to scan (for context)
            session_data: Captured session data from Selenium:
                {
                    "auth_type": "cookie" | "bearer" | "jwt",
                    "cookies": {...},
                    "token": "...",
                    "storage": {...},
                    "headers": {...},
                }
            session_name: Name for ZAP named session (default: vulnforge-session)

        Returns:
            Dict with injection result:
            {
                "success": bool,
                "auth_type": str,
                "session_name": str,
                "message": str,
                "replacer_rules": [...],  # if using Bearer/JWT
                "cookies_injected": {...}, # if using cookies
                "verified": bool,
            }
        """
        result = {
            "success": False,
            "auth_type": session_data.get("auth_type", "unknown"),
            "session_name": session_name,
            "message": "",
            "replacer_rules": [],
            "cookies_injected": {},
            "verified": False,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                auth_type = session_data.get("auth_type", "").lower()

                if auth_type == "cookie":
                    await self._inject_cookies(
                        client, target_url, session_data, session_name, result
                    )
                elif auth_type in ("bearer", "jwt"):
                    await self._inject_bearer_token(client, session_data, result)
                else:
                    result["message"] = f"Unknown auth_type: {auth_type}"
                    logger.warning(f"[ZAP Session] {result['message']}")
                    return result

                result["success"] = True
                logger.info(f"[ZAP Session] ✓ Session injection successful for {auth_type}")

        except Exception as e:
            result["message"] = f"ERROR: {str(e)}"
            logger.error(f"[ZAP Session] ✗ Injection failed: {e}")
            import traceback
            logger.error(traceback.format_exc())

        return result

    async def _inject_cookies(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        session_data: Dict[str, Any],
        session_name: str,
        result: Dict[str, Any],
    ):
        """Inject cookies using ZAP's httpSessions API."""
        logger.info(f"[ZAP Session] Injecting cookies-based session: {session_name}")

        cookies = session_data.get("cookies", {})
        if not cookies:
            logger.warning("[ZAP Session] No cookies found to inject")
            result["message"] = "No cookies found in session data"
            return

        try:
            # Get target site name from URL
            parsed = urlparse(target_url)
            site_name = parsed.netloc or "localhost"

            # Step 1: Create a new named session
            logger.info(f"[ZAP Session] Creating named session: {session_name}")
            resp = await self._zap_call(
                client,
                "httpSessions",
                "action",
                "createSession",
                {"site": site_name, "session": session_name},
            )
            logger.info(f"[ZAP Session] Created session: {resp}")

            # Step 2: Inject each cookie into the session
            for cookie_name, cookie_value in cookies.items():
                logger.info(
                    f"[ZAP Session] Injecting cookie: {cookie_name}={cookie_value[:50]}..."
                )

                # Use ZAP's set cookie via script or via individual API calls
                # Most reliable: add cookie via httpSessions API
                resp = await self._zap_call(
                    client,
                    "httpSessions",
                    "action",
                    "setCookie",
                    {
                        "site": site_name,
                        "session": session_name,
                        "name": cookie_name,
                        "value": cookie_value,
                    },
                )
                logger.debug(f"[ZAP Session] Cookie injection result: {resp}")
                result["cookies_injected"][cookie_name] = cookie_value[:50]

            # Step 3: Set this session as active for the site
            logger.info(f"[ZAP Session] Setting active session: {session_name}")
            resp = await self._zap_call(
                client,
                "httpSessions",
                "action",
                "setActiveSession",
                {"site": site_name, "session": session_name},
            )
            logger.info(f"[ZAP Session] ✓ Active session set: {resp}")

            result["session_name"] = session_name
            result["message"] = f"Injected {len(cookies)} cookies into session '{session_name}'"

        except Exception as e:
            logger.error(f"[ZAP Session] Cookie injection failed: {e}")
            result["message"] = f"Cookie injection failed: {str(e)}"
            raise

    async def _inject_bearer_token(
        self,
        client: httpx.AsyncClient,
        session_data: Dict[str, Any],
        result: Dict[str, Any],
    ):
        """Inject Bearer/JWT token using ZAP's Replacer API."""
        logger.info("[ZAP Session] Injecting Bearer/JWT token via Replacer API")

        token = session_data.get("token")
        if not token:
            logger.warning("[ZAP Session] No token found to inject")
            result["message"] = "No token found in session data"
            return

        try:
            # Step 1: Get all existing replacer rules
            existing_rules = await self._zap_call(
                client, "replacer", "view", "rules", {}
            )
            logger.debug(f"[ZAP Session] Existing Replacer rules: {existing_rules}")

            # Step 2: Create a new Replacer rule to inject Authorization header
            # Rule format: Match ANY request, replace headers
            rule_description = f"Vulnforge Auth Injection - {int(time.time())}"

            await self._zap_call(
                client,
                "replacer",
                "action",
                "addRule",
                {
                    "description": rule_description,
                    "enabled": "true",
                    "matchtype": "REQ_HEADER",
                    "matchstring": "Authorization",
                    "replacement": f"Bearer {token}",
                    "regex": "false",
                },
            )
            logger.info(f"[ZAP Session] ✓ Created Replacer rule: {rule_description}")
            result["message"] = "Created Bearer token injection rule in Replacer"
            result["replacer_rules"].append(rule_description)

        except Exception as e:
            logger.error(f"[ZAP Session] Bearer token injection failed: {e}")
            result["message"] = f"Bearer token injection failed: {str(e)}"
            raise

    async def verify_session(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        session_name: str,
        logged_in_indicator: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify that the injected session is valid by making a test request through ZAP.

        Args:
            client: httpx AsyncClient
            target_url: Target URL to test
            session_name: Name of the injected session
            logged_in_indicator: Optional regex pattern to detect logged-in state

        Returns:
            Verification result dict
        """
        result = {
            "verified": False,
            "status_code": None,
            "message": "",
            "indicator_found": False,
        }

        try:
            logger.info(
                f"[ZAP Session] Verifying session: {session_name} against {target_url}"
            )

            # Make request through ZAP proxy
            async with httpx.AsyncClient(
                proxies=self.api_url,
                verify=False,
                timeout=10.0,
            ) as proxy_client:
                try:
                    response = await proxy_client.get(target_url)
                    result["status_code"] = response.status_code
                    logger.debug(f"[ZAP Session] Response status: {response.status_code}")

                    # Check for logged-in indicator
                    if logged_in_indicator:
                        import re
                        if re.search(logged_in_indicator, response.text, re.IGNORECASE):
                            result["indicator_found"] = True
                            result["verified"] = True
                            result["message"] = f"Session verified: found logged-in indicator"
                            logger.info(f"[ZAP Session] ✓ Logged-in indicator found")
                        else:
                            result["message"] = (
                                f"Session verification uncertain: "
                                f"logged-in indicator not found (but no error either)"
                            )
                            logger.warning(result["message"])
                    else:
                        # No indicator specified; assume valid if status is 2xx or 3xx
                        if 200 <= response.status_code < 400:
                            result["verified"] = True
                            result["message"] = f"Session appears valid (HTTP {response.status_code})"
                            logger.info(f"[ZAP Session] ✓ {result['message']}")
                        else:
                            result["message"] = (
                                f"Session may be invalid (HTTP {response.status_code})"
                            )
                            logger.warning(result["message"])

                except httpx.ProxyError as e:
                    result["message"] = f"Proxy error (ZAP may not be running): {str(e)}"
                    logger.error(f"[ZAP Session] {result['message']}")
                except httpx.RequestError as e:
                    result["message"] = f"Request error: {str(e)}"
                    logger.error(f"[ZAP Session] {result['message']}")

        except Exception as e:
            result["message"] = f"Verification failed: {str(e)}"
            logger.error(f"[ZAP Session] ✗ {result['message']}")

        return result

    async def _zap_call(
        self,
        client: httpx.AsyncClient,
        component: str,
        operation: str,
        action: str,
        params: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Make a ZAP API call.

        Args:
            client: httpx AsyncClient
            component: ZAP component (e.g., "httpSessions", "replacer")
            operation: "view", "action", etc.
            action: Specific action name
            params: Query parameters

        Returns:
            JSON response from ZAP
        """
        params["apikey"] = self.api_key
        url = f"{self.api_url}/JSON/{component}/{operation}/{action}/"

        logger.debug(f"[ZAP Session] API call: {url} with params {params}")

        response = await client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        logger.debug(f"[ZAP Session] API response: {data}")
        return data
