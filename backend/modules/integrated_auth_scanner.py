"""
integrated_authenticated_scanner.py

Complete end-to-end tool that combines selinium tools:
1. Parse .side file
2. Run Selenium to execute login
3. Extract session/auth tokens
4. Inject into ZAP
5. Run authenticated scan

This bridges the provided selinium tools with the backend API.
"""

import asyncio
import json
import logging
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("vulnforge.integrated_auth")


class IntegratedAuthenticatedScanner:
    """
    Unified interface combining selinium tools + ZAP injection.
    
    Usage:
        scanner = IntegratedAuthenticatedScanner(zap_url="http://localhost:8080")
        session = await scanner.run_authenticated_scan(
            side_file_content=b"...",
            target_url="https://example.com"
        )
    """
    
    def __init__(
        self,
        zap_url: str = "http://localhost:8080",
        zap_api_key: str = "vulnforge-zap-key",
        selinium_path: Optional[Path] = None,
    ):
        """Initialize scanner with ZAP connection details."""
        self.zap_url = zap_url.rstrip("/")
        self.zap_api_key = zap_api_key
        
        # Path to selinium utilities
        self.selinium_path = selinium_path or Path(__file__).parent.parent / "selinium"
        
        # Ensure selinium directory exists
        if not self.selinium_path.exists():
            logger.warning(f"Selinium directory not found at {self.selinium_path}")
    
    async def run_authenticated_scan(
        self,
        side_file_content: bytes,
        target_url: str,
        run_scan: bool = True,
        timeout_minutes: int = 60,
    ) -> Dict[str, Any]:
        """
        Complete auth flow: parse .side → run Selenium → extract session → inject into ZAP → scan
        
        Returns:
            {
                "success": bool,
                "session_data": {...},  # Extracted session
                "injection_result": {...},  # ZAP injection details
                "scan_result": {...},  # Optional scan results
                "errors": []
            }
        """
        result = {
            "success": False,
            "session_data": None,
            "injection_result": None,
            "scan_result": None,
            "errors": [],
        }
        
        try:
            # Phase 1: Save .side file and parse it
            logger.info("[Phase 1] Parsing .side file...")
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.side', delete=False) as f:
                side_file_path = Path(f.name)
                f.write(side_file_content)
            
            side_data = self._parse_side_file(side_file_path)
            logger.info(f"[Phase 1] ✓ Parsed .side file: {len(side_data.get('tests', []))} tests")
            
            # Phase 2: Run Selenium to extract session
            logger.info("[Phase 2] Running Selenium to capture session...")
            session_data = await self._run_selenium_and_extract_session(
                side_file_path,
                target_url,
                timeout_minutes,
            )
            
            if not session_data:
                raise Exception("Failed to capture session from Selenium")
            
            result["session_data"] = session_data
            
            # Extract cookies from nested structure
            all_cookies = []
            if 'session' in session_data and 'all_cookies' in session_data['session']:
                all_cookies = session_data['session'].get('all_cookies', [])
            elif 'cookies' in session_data:
                all_cookies = session_data.get('cookies', [])
            
            logger.info(f"[Phase 2] ✓ Session captured: {len(all_cookies)} cookies")
            
            # Phase 3: Inject into ZAP
            logger.info("[Phase 3] Injecting session into ZAP...")
            injection_result = await self._inject_session_into_zap(session_data, target_url)
            result["injection_result"] = injection_result
            logger.info(f"[Phase 3] ✓ Session injected into ZAP")
            
            # Phase 4: Run scan if requested
            if run_scan:
                logger.info("[Phase 4] Running authenticated scan...")
                scan_result = await self._run_authenticated_scan_in_zap(target_url, timeout_minutes)
                result["scan_result"] = scan_result
                logger.info(f"[Phase 4] ✓ Scan completed: {scan_result.get('alerts_found', 0)} alerts")
            
            result["success"] = True
            return result
            
        except Exception as e:
            logger.error(f"Error in authenticated scan: {e}", exc_info=True)
            result["errors"].append(str(e))
            return result
        finally:
            # Cleanup
            try:
                if side_file_path and side_file_path.exists():
                    side_file_path.unlink()
            except Exception as cleanup_err:
                logger.warning(f"Failed to cleanup side file: {cleanup_err}")
    
    def _parse_side_file(self, side_file_path: Path) -> Dict[str, Any]:
        """Parse .side JSON file and extract test information."""
        try:
            with open(side_file_path) as f:
                data = json.load(f)
            
            return {
                "tests": data.get("tests", []),
                "suites": data.get("suites", []),
                "urls": data.get("urls", []),
                "plugins": data.get("plugins", []),
            }
        except Exception as e:
            logger.error(f"Failed to parse .side file: {e}")
            raise
    
    async def _run_selenium_and_extract_session(
        self,
        side_file_path: Path,
        target_url: str,
        timeout_minutes: int,
    ) -> Dict[str, Any]:
        """
        Use selinium tools to:
        1. Execute Selenium commands from .side
        2. Extract session data (cookies, JWT tokens, localStorage)
        
        Returns session JSON structure
        """
        
        # Key requirement: subprocess call to selinium/main.py to extract session
        import subprocess
        import time
        
        logger.info(f"Executing selinium tools to extract session...")
        
        # Create a unique output filename to avoid picking up old files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.selinium_path / f"session_{timestamp}.json"
        
        # Call the selinium/main.py with the .side file
        cmd = [
            "python3",
            str(self.selinium_path / "main.py"),
            "--side", str(side_file_path),
            "--headless",
            "--output", str(output_file),  # Force output to a specific file
        ]
        
        try:
            # Run selinium main.py which outputs session JSON file
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout_minutes * 60
            )
            
            logger.debug(f"Selinium output: {stdout.decode()}")
            
            if proc.returncode != 0:
                error_msg = stderr.decode()
                logger.error(f"Selinium failed: {error_msg}")
                raise Exception(f"Selenium execution failed: {error_msg}")
            
            # Load the session file we explicitly told selinium to create
            if not output_file.exists():
                raise Exception(f"Session file not created at expected path: {output_file}")
            
            logger.info(f"Found session file: {output_file.name}")
            
            with open(output_file) as f:
                session_data = json.load(f)
            
            return session_data
            
        except asyncio.TimeoutError:
            raise Exception(f"Selenium execution timeout after {timeout_minutes} minutes")
        except Exception as e:
            logger.error(f"Failed to run Selenium: {e}")
            raise
    
    async def _inject_session_into_zap(
        self,
        session_data: Dict[str, Any],
        target_url: str,
    ) -> Dict[str, Any]:
        """
        Inject captured session into OWASP ZAP.
        
        Calls ZAP API endpoints to:
        1. Create HTTP session
        2. Inject cookies
        3. Inject Bearer tokens via Replacer
        4. Set as active session
        """
        
        import httpx
        
        result = {
            "cookies_injected": 0,
            "tokens_injected": 0,
            "session_name": "authenticated-session",
        }
        
        try:
            async with httpx.AsyncClient() as client:
                domain = urlparse(target_url).netloc
                session_name = result["session_name"]
                
                # Create empty session in ZAP
                logger.info(f"Creating ZAP session: {session_name}")
                params = {
                    "apikey": self.zap_api_key,
                    "sessionname": session_name,
                    "overwrite": "true",
                }
                r = await client.get(
                    f"{self.zap_url}/JSON/httpsessions/action/createEmptySession/",
                    params=params
                )
                if r.status_code != 200:
                    logger.warning(f"Failed to create session: {r.text}")
                
                # Extract cookies from nested structure (selinium returns nested JSON)
                cookies = []
                if 'session' in session_data and 'all_cookies' in session_data['session']:
                    cookies = session_data['session'].get('all_cookies', [])
                elif 'cookies' in session_data:
                    cookies = session_data.get('cookies', [])
                
                for cookie in cookies:
                    try:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        
                        # Register as session token
                        params = {
                            "apikey": self.zap_api_key,
                            "sessionname": session_name,
                            "tokenname": cookie_name,
                        }
                        r = await client.get(
                            f"{self.zap_url}/JSON/httpsessions/action/addSessionToken/",
                            params=params
                        )
                        
                        result["cookies_injected"] += 1
                        logger.info(f"Injected cookie: {cookie_name}")
                    except Exception as e:
                        logger.warning(f"Failed to inject cookie {cookie.get('name')}: {e}")
                
                # Extract Bearer token from nested structure if present
                bearer_token = None
                if 'session' in session_data and 'jwt_tokens' in session_data['session']:
                    jwt_tokens = session_data['session'].get('jwt_tokens', {})
                    if jwt_tokens:
                        # Get first JWT token if available
                        bearer_token = next(iter(jwt_tokens.values())) if jwt_tokens else None
                
                if not bearer_token:
                    bearer_token = session_data.get("bearer_token") or session_data.get("jwt_token")
                    
                if bearer_token:
                    try:
                        params = {
                            "apikey": self.zap_api_key,
                            "description": "Selenium-extracted token",
                            "enabled": "true",
                            "matchtype": "REQ_HEADER",
                            "matchstring": "Authorization",
                            "matchregex": "false",
                            "replacement": f"Bearer {bearer_token[:50]}...",
                            "initiators": "",
                        }
                        r = await client.get(
                            f"{self.zap_url}/JSON/replacer/action/addRule/",
                            params=params
                        )
                        result["tokens_injected"] += 1
                        logger.info(f"Injected Bearer token")
                    except Exception as e:
                        logger.warning(f"Failed to inject Bearer token: {e}")
                
                # Set session as active
                params = {
                    "apikey": self.zap_api_key,
                    "sessionname": session_name,
                }
                await client.get(
                    f"{self.zap_url}/JSON/httpsessions/action/setActiveSession/",
                    params=params
                )
                logger.info(f"Session set as active in ZAP")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to inject session: {e}")
            raise
    
    async def _run_authenticated_scan_in_zap(
        self,
        target_url: str,
        timeout_minutes: int = 60,
    ) -> Dict[str, Any]:
        """
        Run ZAP spider + active scan with authenticated session.
        
        Returns alert summary.
        """
        
        import httpx
        import time
        
        result = {
            "spider_urls": 0,
            "alerts_found": 0,
            "scan_duration": 0,
            "alerts": [],
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                start_time = time.time()

                # Run Spider
                logger.info("Starting ZAP Spider...")
                params = {"apikey": self.zap_api_key, "url": target_url}
                r = await client.get(f"{self.zap_url}/JSON/spider/action/scan/", params=params)
                r.raise_for_status()
                spider_id = r.json().get("scan")

                # Wait for spider to complete
                while True:
                    params = {"apikey": self.zap_api_key, "scanid": spider_id}
                    r = await client.get(f"{self.zap_url}/JSON/spider/view/status/", params=params)
                    status = int(r.json().get("status", 0))
                    if status >= 100:
                        break
                    logger.info(f"Spider progress: {status}%")
                    await asyncio.sleep(10)

                # Get spider results
                params = {"apikey": self.zap_api_key, "scanid": spider_id}
                r = await client.get(f"{self.zap_url}/JSON/spider/view/results/", params=params)
                result["spider_urls"] = len(r.json().get("results", []))
                logger.info(f"Spider found {result['spider_urls']} URLs")

                # Run Active Scan
                logger.info("Starting ZAP Active Scan...")
                params = {"apikey": self.zap_api_key, "url": target_url}
                r = await client.get(f"{self.zap_url}/JSON/ascan/action/scan/", params=params)
                r.raise_for_status()
                scan_id = r.json().get("scan")

                # Wait for active scan to complete
                while True:
                    params = {"apikey": self.zap_api_key, "scanid": scan_id}
                    r = await client.get(f"{self.zap_url}/JSON/ascan/view/status/", params=params)
                    status = int(r.json().get("status", 0))
                    if status >= 100:
                        break
                    logger.info(f"Active Scan progress: {status}%")
                    await asyncio.sleep(15)

                # Get all alerts
                params = {"apikey": self.zap_api_key, "baseurl": target_url}
                r = await client.get(f"{self.zap_url}/JSON/core/view/alerts/", params=params)
                alerts = r.json().get("alerts", [])
                result["alerts_found"] = len(alerts)
                result["alerts"] = alerts  # Return full alert objects

                elapsed = time.time() - start_time
                result["scan_duration"] = int(elapsed)
                logger.info(f"Scan complete: {result['alerts_found']} alerts in {elapsed:.0f}s")

            return result
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
