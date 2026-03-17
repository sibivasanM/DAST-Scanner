"""
ZAP Spider and Active Scan Orchestration — Run spidering and active scanning with progress monitoring.

Features:
  - Ajax Spider (preferred) or traditional Spider for URL discovery
  - Progress monitoring with 10-second updates
  - Active Scanner execution on discovered URLs
  - Session expiry detection and re-injection
  - Configurable timeout (default: 60 minutes)
  - Graceful scan termination
"""

import asyncio
import json
import logging
import time
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta

import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnforge.zap_scan")


class ZapScanOrchestrator:
    """Orchestrate ZAP spidering and active scanning with progress tracking."""

    def __init__(self, api_url: str = "http://zap:8080", api_key: str = "vulnforge-zap-key"):
        """
        Initialize scan orchestrator.

        Args:
            api_url: ZAP API URL (default: http://zap:8080)
            api_key: ZAP API key for authentication
        """
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.last_session_check = time.time()
        # Re-auth state (set per run_authenticated_scan call)
        self._target_url: str = ""
        self._reauth_config: Optional[Dict] = None
        self.reauth_count: int = 0

    async def run_authenticated_scan(
        self,
        target_url: str,
        context_name: str,
        use_ajax_spider: bool = True,
        scan_type: str = "full",
        timeout_minutes: int = 60,
        logged_in_indicator: Optional[str] = None,
        reauth_config: Optional[Dict] = None,
        previous_urls: Optional[set] = None,
    ) -> Dict[str, Any]:
        """
        Run complete spidering and active scanning workflow.

        Args:
            target_url: Target URL to scan
            context_name: Name of ZAP context created with session
            use_ajax_spider: Use Ajax Spider (True) or traditional Spider (False)
            scan_type: "quick" | "full" | "deep"
            timeout_minutes: Maximum scan duration (default: 60 minutes)
            logged_in_indicator: Regex to verify session is still active

        Returns:
            Scan result dict with progress and findings
            {
                "success": bool,
                "scanner_id": str,
                "spider_id": str,
                "target": str,
                "scan_type": str,
                "duration_seconds": int,
                "urls_found": int,
                "alerts_found": int,
                "message": str,
                "errors": [],
                "alerts": [...],
                "session_valid_at_end": bool,
            }
        """
        # Store per-run state for re-auth callbacks
        self._target_url = target_url
        self._reauth_config = reauth_config
        self.reauth_count = 0

        result = {
            "success": False,
            "scanner_id": None,
            "spider_id": None,
            "target": target_url,
            "scan_type": scan_type,
            "duration_seconds": 0,
            "urls_found": 0,
            "alerts_found": 0,
            "message": "",
            "errors": [],
            "alerts": [],
            "session_valid_at_end": False,
            "reauth_count": 0,
            "crawled_urls": [],
            "incremental_new_urls": 0,
            "incremental_skipped_urls": 0,
        }

        start_time = time.time()
        timeout_seconds = timeout_minutes * 60
        last_progress_log = time.time()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                logger.info(
                    f"[ZAP Scan] Starting {scan_type} scan for {target_url} "
                    f"(timeout={timeout_minutes}min, ajax_spider={use_ajax_spider})"
                )

                # ── Phase 1: Run Spider ──────────────────────────────────────────────
                logger.info("[ZAP Scan] ▶ Phase 1: Spidering")

                spider_id = await self._run_spider(
                    client,
                    target_url,
                    context_name,
                    use_ajax_spider=use_ajax_spider,
                )
                result["spider_id"] = spider_id

                # Wait for spider to complete with progress monitoring
                logger.info(f"[ZAP Scan] Waiting for spider {spider_id} to complete...")
                urls_found, crawled_urls = await self._wait_for_spider(
                    client,
                    spider_id,
                    timeout_seconds=timeout_seconds,
                    logged_in_indicator=logged_in_indicator,
                )
                result["urls_found"] = urls_found
                result["crawled_urls"] = crawled_urls
                logger.info(f"[ZAP Scan] ✓ Spider completed; found {urls_found} URLs")

                # ── Incremental mode: exclude already-known URLs from active scan ─
                if previous_urls:
                    new_urls = [u for u in crawled_urls if u not in previous_urls]
                    skipped = len(crawled_urls) - len(new_urls)
                    result["incremental_new_urls"] = len(new_urls)
                    result["incremental_skipped_urls"] = skipped
                    if skipped > 0:
                        logger.info(
                            f"[ZAP Scan] Incremental mode: {len(new_urls)} new URLs, "
                            f"{skipped} known URLs excluded from active scan"
                        )
                        await self._exclude_known_urls_from_context(
                            client, context_name, crawled_urls, previous_urls
                        )
                    else:
                        logger.info("[ZAP Scan] Incremental mode: all URLs are new, running full active scan")

                # ── Phase 2: Run Active Scan ──────────────────────────────────────
                logger.info("[ZAP Scan] ▶ Phase 2: Active Scanning")

                scanner_id = await self._run_active_scan(
                    client,
                    target_url,
                    context_name,
                    scan_type=scan_type,
                )
                result["scanner_id"] = scanner_id

                # Wait for active scan to complete with progress monitoring
                logger.info(f"[ZAP Scan] Waiting for scanner {scanner_id} to complete...")
                alerts, scan_time = await self._wait_for_active_scan(
                    client,
                    scanner_id,
                    timeout_seconds=timeout_seconds - (time.time() - start_time),
                    logged_in_indicator=logged_in_indicator,
                )
                result["alerts"] = alerts
                result["alerts_found"] = len(alerts)
                logger.info(f"[ZAP Scan] ✓ Active scan completed; found {len(alerts)} alerts")

                # ── Phase 3: Verify Session ──────────────────────────────────────────
                if logged_in_indicator:
                    logger.info("[ZAP Scan] ▶ Phase 3: Verifying session is still active")
                    session_valid = await self._verify_session_still_active(
                        client, target_url, logged_in_indicator
                    )
                    result["session_valid_at_end"] = session_valid
                    logger.info(
                        f"[ZAP Scan] Session verification: {'✓ VALID' if session_valid else '✗ INVALID'}"
                    )

                duration = time.time() - start_time
                result["duration_seconds"] = int(duration)
                result["reauth_count"] = self.reauth_count
                result["success"] = True
                incremental_note = ""
                if result["incremental_skipped_urls"]:
                    incremental_note = (
                        f", incremental: {result['incremental_new_urls']} new "
                        f"/ {result['incremental_skipped_urls']} skipped"
                    )
                result["message"] = (
                    f"Scan completed in {int(duration)}s: "
                    f"spidered {urls_found} URLs, found {len(alerts)} alerts"
                    + (f", re-authenticated {self.reauth_count}x" if self.reauth_count else "")
                    + incremental_note
                )

                logger.info(f"[ZAP Scan] ✓ {result['message']}")

        except asyncio.TimeoutError as e:
            duration = time.time() - start_time
            result["duration_seconds"] = int(duration)
            result["message"] = f"ERROR: Scan timeout after {int(duration)}s"
            result["errors"].append(str(e))
            logger.error(f"[ZAP Scan] ✗ {result['message']}")
        except Exception as e:
            duration = time.time() - start_time
            result["duration_seconds"] = int(duration)
            result["message"] = f"ERROR: {str(e)}"
            result["errors"].append(str(e))
            logger.error(f"[ZAP Scan] ✗ {result['message']}")
            import traceback
            logger.error(traceback.format_exc())

        return result

    async def _run_spider(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        context_name: str,
        use_ajax_spider: bool = True,
    ) -> str:
        """Start spider and return spider ID."""
        if use_ajax_spider:
            logger.info(f"[ZAP Scan] Starting AJAX Spider on {target_url}")
            resp = await self._zap_call(
                client,
                "ajaxSpider",
                "action",
                "scan",
                {
                    "contextName": context_name,
                    "url": target_url,
                },
            )
            spider_id = resp.get("scan")
        else:
            logger.info(f"[ZAP Scan] Starting traditional Spider on {target_url}")
            resp = await self._zap_call(
                client,
                "spider",
                "action",
                "scan",
                {
                    "contextName": context_name,
                    "url": target_url,
                },
            )
            spider_id = resp.get("scan")

        if not spider_id:
            raise Exception(f"Failed to start spider: {resp}")

        logger.info(f"[ZAP Scan] Spider started with ID: {spider_id}")
        return spider_id

    async def _wait_for_spider(
        self,
        client: httpx.AsyncClient,
        spider_id: str,
        timeout_seconds: int = 3600,
        logged_in_indicator: Optional[str] = None,
        use_ajax_spider: bool = True,
    ) -> int:
        """Wait for spider to complete with progress monitoring."""
        component = "ajaxSpider" if use_ajax_spider else "spider"
        start_time = time.time()
        last_log_time = start_time

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout_seconds:
                raise asyncio.TimeoutError(
                    f"Spider timeout after {int(elapsed)}s (limit: {timeout_seconds}s)"
                )

            try:
                # Check spider status
                resp = await self._zap_call(client, component, "view", "status", {"scanId": spider_id})
                status = int(resp.get("status", 0))

                # Log progress every 10 seconds
                now = time.time()
                if now - last_log_time >= 10:
                    logger.info(f"[ZAP Scan] Spider progress: {status}% ({int(elapsed)}s)")
                    last_log_time = now

                # Check if complete
                if status >= 100:
                    logger.info(f"[ZAP Scan] Spider completed (status: {status}%)")
                    break

                # Verify session still active; re-authenticate if expired
                if logged_in_indicator and (now - self.last_session_check) > 30:
                    valid = await self._verify_session_still_active(
                        client, self._target_url, logged_in_indicator
                    )
                    if not valid:
                        logger.warning("[ZAP Scan] ⚠ Session expired during spider — attempting re-auth")
                        await self._reauth_and_reinject()
                    self.last_session_check = now

                await asyncio.sleep(5)

            except Exception as e:
                logger.warning(f"[ZAP Scan] Error checking spider status: {e}")
                await asyncio.sleep(5)

        # Get all discovered URLs from ZAP session (reliable across spider types)
        try:
            url_resp = await self._zap_call(client, "core", "view", "urls", {})
            url_list = url_resp.get("urls", [])
            if isinstance(url_list, list):
                url_list = [u for u in url_list if isinstance(u, str) and u.startswith("http")]
            else:
                url_list = []
            logger.info(f"[ZAP Scan] Spider found {len(url_list)} unique URLs")
            return len(url_list), url_list
        except Exception as e:
            logger.warning(f"[ZAP Scan] Could not retrieve spider URL list: {e}")
            return 0, []

    async def _run_active_scan(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        context_name: str,
        scan_type: str = "full",
    ) -> str:
        """Start active scan and return scanner ID."""
        strength = self._get_scan_strength(scan_type)
        threshold = self._get_scan_threshold(scan_type)

        logger.info(
            f"[ZAP Scan] Starting Active Scan on {target_url} "
            f"(strength={strength}, threshold={threshold})"
        )

        resp = await self._zap_call(
            client,
            "ascan",
            "action",
            "scan",
            {
                "contextName": context_name,
                "url": target_url,
                "policyName": "Default Policy",
                "attackStrength": strength,
                "alertThreshold": threshold,
            },
        )

        scanner_id = resp.get("scan")
        if not scanner_id:
            raise Exception(f"Failed to start active scan: {resp}")

        logger.info(f"[ZAP Scan] Active scan started with ID: {scanner_id}")
        return scanner_id

    async def _wait_for_active_scan(
        self,
        client: httpx.AsyncClient,
        scanner_id: str,
        timeout_seconds: int = 3600,
        logged_in_indicator: Optional[str] = None,
    ) -> tuple[List[Dict[str, Any]], int]:
        """Wait for active scan to complete with progress monitoring."""
        start_time = time.time()
        last_log_time = start_time

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout_seconds:
                raise asyncio.TimeoutError(
                    f"Active scan timeout after {int(elapsed)}s (limit: {timeout_seconds}s)"
                )

            try:
                # Check scan status
                resp = await self._zap_call(
                    client, "ascan", "view", "status", {"scanId": scanner_id}
                )
                status = int(resp.get("status", 0))

                # Log progress every 10 seconds
                now = time.time()
                if now - last_log_time >= 10:
                    logger.info(f"[ZAP Scan] Active scan progress: {status}% ({int(elapsed)}s)")
                    last_log_time = now

                # Check if complete
                if status >= 100:
                    logger.info(f"[ZAP Scan] Active scan completed (status: {status}%)")
                    break

                # Verify session still active; re-authenticate if expired
                if logged_in_indicator and (now - self.last_session_check) > 30:
                    valid = await self._verify_session_still_active(
                        client, self._target_url, logged_in_indicator
                    )
                    if not valid:
                        logger.warning("[ZAP Scan] ⚠ Session expired during active scan — attempting re-auth")
                        await self._reauth_and_reinject()
                    self.last_session_check = now

                await asyncio.sleep(5)

            except Exception as e:
                logger.warning(f"[ZAP Scan] Error checking scanner status: {e}")
                await asyncio.sleep(5)

        # Get alerts from scan
        alerts = await self._get_alerts(client)
        scan_duration = int(time.time() - start_time)
        logger.info(f"[ZAP Scan] Active scan took {scan_duration}s and found {len(alerts)} alerts")

        return alerts, scan_duration

    async def _verify_session_still_active(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        logged_in_indicator: str,
    ) -> bool:
        """Check if session is still active by probing logged-in indicator."""
        try:
            import re

            if not target_url:
                target_url = "/"

            # Make a simple request to check indicator
            async with httpx.AsyncClient(
                proxies="http://localhost:8080",
                verify=False,
                timeout=5.0,
            ) as proxy_client:
                try:
                    response = await proxy_client.get(target_url)
                    if re.search(logged_in_indicator, response.text, re.IGNORECASE):
                        logger.debug("[ZAP Scan] ✓ Session still active")
                        return True
                    else:
                        logger.warning("[ZAP Scan] ✗ Logged-in indicator not found")
                        return False
                except Exception as e:
                    logger.warning(f"[ZAP Scan] Session check request failed: {e}")
                    return False

        except Exception as e:
            logger.warning(f"[ZAP Scan] Session verification failed: {e}")
            return True  # Assume still active on error (be optimistic)

    async def _reauth_and_reinject(self) -> bool:
        """
        Re-authenticate using stored credentials and re-inject the fresh session into ZAP.

        Called automatically when the logged-in indicator is no longer found mid-scan,
        which indicates the session token has expired.  The scan itself keeps running —
        ZAP will use the new session for all subsequent requests.

        Returns:
            True if re-authentication and injection succeeded, False otherwise.
        """
        if not self._reauth_config:
            logger.warning("[ZAP Scan] No reauth_config supplied — cannot re-authenticate")
            return False

        try:
            from .selenium_auth import SeleniumAuthCapture
            from .zap_session_injector import ZapSessionInjector

            logger.info("[ZAP Scan] ↻ Re-authenticating with stored credentials…")

            selenium = SeleniumAuthCapture(
                zap_proxy_host=self._reauth_config.get("zap_proxy_host", "zap"),
                zap_proxy_port=int(self._reauth_config.get("zap_proxy_port", 8080)),
            )

            session = await selenium.capture_session(
                login_url=self._reauth_config["login_url"],
                username=self._reauth_config.get("username"),
                password=self._reauth_config.get("password"),
                username_field=self._reauth_config.get("username_field", "username"),
                password_field=self._reauth_config.get("password_field", "password"),
                logged_in_indicator=self._reauth_config.get("logged_in_indicator"),
            )

            if not session["success"]:
                logger.error(f"[ZAP Scan] Re-auth login failed: {session['message']}")
                return False

            injector = ZapSessionInjector(api_url=self.api_url, api_key=self.api_key)
            result = await injector.inject_session(
                target_url=self._target_url,
                session_data=session,
                session_name=f"vulnforge-reauth-{int(time.time())}",
            )

            if result["success"]:
                self.reauth_count += 1
                logger.info(
                    f"[ZAP Scan] ✓ Re-auth #{self.reauth_count} succeeded "
                    f"(auth_type={session.get('auth_type')}) — scan continues"
                )
                return True

            logger.error(f"[ZAP Scan] Re-injection failed: {result['message']}")
            return False

        except Exception as exc:
            logger.error(f"[ZAP Scan] Re-auth exception: {exc}")
            return False

    async def _exclude_known_urls_from_context(
        self,
        client: httpx.AsyncClient,
        context_name: str,
        all_urls: List[str],
        known_urls: set,
        max_exclusions: int = 200,
    ) -> None:
        """
        Exclude previously-crawled URLs from the ZAP context so the active scan
        only tests new/changed URLs.  Capped at max_exclusions to avoid excessive
        API calls when the URL set is very large.
        """
        import re as _re

        urls_to_exclude = [u for u in all_urls if u in known_urls][:max_exclusions]
        excluded = 0
        for url in urls_to_exclude:
            try:
                await self._zap_call(
                    client,
                    "context",
                    "action",
                    "excludeFromContext",
                    {"contextName": context_name, "regex": f"^{_re.escape(url)}$"},
                )
                excluded += 1
            except Exception as e:
                logger.debug(f"[ZAP Scan] Could not exclude URL from context: {url} — {e}")

        logger.info(
            f"[ZAP Scan] Excluded {excluded}/{len(urls_to_exclude)} known URLs from context '{context_name}'"
        )

    async def _get_alerts(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        """Retrieve all alerts from ZAP."""
        try:
            resp = await self._zap_call(client, "core", "view", "alerts", {})
            alerts = resp.get("alerts", [])
            logger.info(f"[ZAP Scan] Retrieved {len(alerts)} total alerts from ZAP")
            return alerts
        except Exception as e:
            logger.error(f"[ZAP Scan] Failed to retrieve alerts: {e}")
            return []

    def _get_scan_strength(self, scan_type: str) -> str:
        """Map scan_type to ZAP attack strength."""
        mapping = {
            "quick": "LOW",
            "full": "MEDIUM",
            "deep": "HIGH",
            "insane": "INSANE",
        }
        return mapping.get(scan_type, "MEDIUM")

    def _get_scan_threshold(self, scan_type: str) -> str:
        """Map scan_type to ZAP alert threshold."""
        mapping = {
            "quick": "HIGH",
            "full": "MEDIUM",
            "deep": "LOW",
            "insane": "OFF",
        }
        return mapping.get(scan_type, "MEDIUM")

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
            component: ZAP component (e.g., "spider", "ascan")
            operation: "view", "action", etc.
            action: Specific action name
            params: Query parameters

        Returns:
            JSON response from ZAP
        """
        params["apikey"] = self.api_key
        url = f"{self.api_url}/JSON/{component}/{operation}/{action}/"

        logger.debug(f"[ZAP Scan] API call: {url} with params {params}")

        response = await client.get(url, params=params, timeout=30.0)
        response.raise_for_status()
        data = response.json()

        logger.debug(f"[ZAP Scan] API response: {data}")
        return data
