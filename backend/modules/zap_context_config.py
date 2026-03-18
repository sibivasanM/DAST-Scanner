"""
ZAP Context Configuration — Set up ZAP scanning context with authentication and URL handling.

Configures:
  - Context name and target URL patterns
  - Included and excluded URLs (e.g., exclude logout to prevent session loss)
  - Context-level settings for authenticated scanning
  - Session verification before starting scan
"""

import json
import logging
import re
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse

import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnforge.zap_context")


class ZapContextConfig:
    """Configure and manage ZAP scanning contexts."""

    def __init__(self, api_url: str = "http://zap:8080", api_key: str = "vulnforge-zap-key"):
        """
        Initialize ZAP context configurator.

        Args:
            api_url: ZAP API URL (default: http://zap:8080)
            api_key: ZAP API key for authentication
        """
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key

    async def create_context(
        self,
        target_url: str,
        context_name: str = "auth-scan-context",
        exclude_urls: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a ZAP context for authenticated scanning.

        Args:
            target_url: Target URL to scan (e.g., https://app.com)
            context_name: Name for the context (default: auth-scan-context)
            exclude_urls: URL patterns to exclude (e.g., /logout, /signout)
            include_patterns: URL patterns to include (default: all under target domain)

        Returns:
            Dict with context creation result:
            {
                "success": bool,
                "context_id": str,
                "context_name": str,
                "target_url": str,
                "message": str,
                "excluded_patterns": [...],
                "included_patterns": [...],
            }
        """
        result = {
            "success": False,
            "context_id": None,
            "context_name": context_name,
            "target_url": target_url,
            "message": "",
            "excluded_patterns": [],
            "included_patterns": [],
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                logger.info(f"[ZAP Context] Creating context: {context_name}")

                # Step 1: Create context
                parsed = urlparse(target_url)
                domain = parsed.netloc
                scheme = parsed.scheme

                # Default: include all URLs under target domain
                if not include_patterns:
                    include_patterns = [f"{scheme}://{domain}/.*"]

                # Default exclude patterns (logout, signout, etc.)
                if not exclude_urls:
                    exclude_urls = [
                        r".*logout.*",
                        r".*signout.*",
                        r".*/auth/logout.*",
                        r".*/auth/signout.*",
                        r".*sign_out.*",
                        r".*/reset-password.*",
                        r".*/forgot-password.*",
                        r".*/change-password.*",
                    ]

                # Create the context
                resp = await self._zap_call(
                    client,
                    "context",
                    "action",
                    "newContext",
                    {"contextName": context_name},
                )
                logger.info(f"[ZAP Context] Created context: {resp}")

                # Step 2: Set the context ID
                context_id = resp.get("contextId")
                if not context_id:
                    raise Exception("Failed to get context ID from response")

                result["context_id"] = context_id

                # Step 3: Set included URL patterns
                logger.info(f"[ZAP Context] Setting included URLs: {include_patterns}")
                for pattern in include_patterns:
                    await self._zap_call(
                        client,
                        "context",
                        "action",
                        "includeInContext",
                        {"contextName": context_name, "regex": pattern},
                    )
                result["included_patterns"] = include_patterns

                # Step 4: Set excluded URL patterns
                logger.info(f"[ZAP Context] Setting excluded URLs: {exclude_urls}")
                for pattern in exclude_urls:
                    await self._zap_call(
                        client,
                        "context",
                        "action",
                        "excludeFromContext",
                        {"contextName": context_name, "regex": pattern},
                    )
                result["excluded_patterns"] = exclude_urls

                # Step 5: Verify context creation
                contexts = await self._zap_call(
                    client, "context", "view", "contextList", {}
                )
                logger.debug(f"[ZAP Context] All contexts: {contexts}")

                if context_name in str(contexts):
                    logger.info(f"[ZAP Context] ✓ Context created successfully: {context_name}")
                    result["success"] = True
                    result["message"] = f"Context '{context_name}' created with {len(include_patterns)} include patterns and {len(exclude_urls)} exclude patterns"
                else:
                    logger.warning(f"[ZAP Context] Context not found in list after creation")
                    result["message"] = "Context created but not found in list (may still be valid)"
                    result["success"] = False

        except Exception as e:
            result["message"] = f"ERROR: {str(e)}"
            logger.error(f"[ZAP Context] ✗ Context creation failed: {e}")
            import traceback
            logger.error(traceback.format_exc())

        return result

    async def configure_context_auth(
        self,
        context_name: str,
        auth_type: str,
        login_url: Optional[str] = None,
        username_field: Optional[str] = None,
        password_field: Optional[str] = None,
        logged_in_indicator: Optional[str] = None,
        logged_out_indicator: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Configure authentication settings within a context.

        Args:
            context_name: Name of the context
            auth_type: "form" | "bearer" | "cookie" | "none"
            login_url: Login page URL (for form auth)
            username_field: Form field name for username
            password_field: Form field name for password
            logged_in_indicator: Regex to detect authenticated state
            logged_out_indicator: Regex to detect logged-out state

        Returns:
            Configuration result dict
        """
        result = {
            "success": False,
            "context_name": context_name,
            "auth_type": auth_type,
            "message": "",
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                logger.info(
                    f"[ZAP Context] Configuring auth for context: {context_name} (type={auth_type})"
                )

                # Set authentication method
                if auth_type == "form" and login_url:
                    logger.info(f"[ZAP Context] Setting form auth: {login_url}")

                    await self._zap_call(
                        client,
                        "authentication",
                        "action",
                        "setAuthenticationMethod",
                        {
                            "contextName": context_name,
                            "authType": "formBasedAuthentication",
                            "loginUrl": login_url,
                            "loginRequestData": f"{username_field}=%USERNAME%&{password_field}=%PASSWORD%",
                        },
                    )

                    if logged_in_indicator:
                        await self._zap_call(
                            client,
                            "authentication",
                            "action",
                            "setLoggedInIndicator",
                            {
                                "contextName": context_name,
                                "loggedInIndicator": logged_in_indicator,
                            },
                        )
                        logger.info(
                            f"[ZAP Context] Set logged-in indicator: {logged_in_indicator}"
                        )

                    if logged_out_indicator:
                        await self._zap_call(
                            client,
                            "authentication",
                            "action",
                            "setLoggedOutIndicator",
                            {
                                "contextName": context_name,
                                "loggedOutIndicator": logged_out_indicator,
                            },
                        )
                        logger.info(
                            f"[ZAP Context] Set logged-out indicator: {logged_out_indicator}"
                        )

                result["success"] = True
                result["message"] = f"Auth configured for context '{context_name}' (type={auth_type})"
                logger.info(f"[ZAP Context] ✓ {result['message']}")

        except Exception as e:
            result["message"] = f"ERROR: {str(e)}"
            logger.error(f"[ZAP Context] ✗ Auth configuration failed: {e}")

        return result

    async def verify_context_session(
        self,
        context_name: str,
        target_url: str,
        logged_in_indicator: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify that the authenticated session is valid in the context.

        Args:
            context_name: Name of the context
            target_url: Target URL to test
            logged_in_indicator: Regex pattern to detect logged-in state

        Returns:
            Verification result dict
        """
        result = {
            "verified": False,
            "status_code": None,
            "indicator_found": False,
            "message": "",
        }

        try:
            logger.info(
                f"[ZAP Context] Verifying session for context: {context_name} against {target_url}"
            )

            # Make test request through ZAP assuming the context is active
            async with httpx.AsyncClient(
                proxies=self.api_url,
                verify=False,
                timeout=10.0,
            ) as proxy_client:
                try:
                    response = await proxy_client.get(target_url)
                    result["status_code"] = response.status_code
                    logger.debug(f"[ZAP Context] Response status: {response.status_code}")

                    # Check for logged-in indicator
                    if logged_in_indicator:
                        if re.search(logged_in_indicator, response.text, re.IGNORECASE):
                            result["verified"] = True
                            result["indicator_found"] = True
                            result["message"] = "Session verified: logged-in indicator found"
                            logger.info(f"[ZAP Context] ✓ {result['message']}")
                        else:
                            result["message"] = (
                                f"Session may not be valid: logged-in indicator not found"
                            )
                            logger.warning(result["message"])
                    else:
                        # No indicator; assume valid if 2xx or 3xx
                        if 200 <= response.status_code < 400:
                            result["verified"] = True
                            result["message"] = f"Session appears valid (HTTP {response.status_code})"
                            logger.info(f"[ZAP Context] ✓ {result['message']}")
                        else:
                            result["message"] = f"Session may be invalid (HTTP {response.status_code})"
                            logger.warning(result["message"])

                except httpx.ProxyError as e:
                    result["message"] = f"Proxy error (ZAP may not be running): {str(e)}"
                    logger.error(f"[ZAP Context] {result['message']}")
                except httpx.RequestError as e:
                    result["message"] = f"Request error: {str(e)}"
                    logger.error(f"[ZAP Context] {result['message']}")

        except Exception as e:
            result["message"] = f"Verification failed: {str(e)}"
            logger.error(f"[ZAP Context] ✗ {result['message']}")

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
            component: ZAP component (e.g., "context", "authentication")
            operation: "view", "action", etc.
            action: Specific action name
            params: Query parameters

        Returns:
            JSON response from ZAP
        """
        params["apikey"] = self.api_key
        url = f"{self.api_url}/JSON/{component}/{operation}/{action}/"

        logger.debug(f"[ZAP Context] API call: {url} with params {params}")

        response = await client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        logger.debug(f"[ZAP Context] API response: {data}")
        return data
