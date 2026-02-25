#!/usr/bin/env python3
"""
Standalone CLI tool for authenticated DAST scanning using the backend API.

This tool communicates with the running backend API to:
1. Upload and parse .side files
2. Capture authenticated sessions via Selenium
3. Inject sessions into ZAP
4. Run authenticated scanning

Prerequisites:
  - Backend API running on http://localhost:8000
  - ZAP running on http://localhost:8080

Usage:
  python3 cli_api_scanner.py \
    --side-file altoro.side \
    --target https://altoro.testfire.net \
    --backend-url http://localhost:8000

Or with manual credentials:
  python3 cli_api_scanner.py \
    --login-url https://altoro.testfire.net/login \
    --username-field uid \
    --password-field passw \
    --username jsmith \
    --password demo1234 \
    --target https://altoro.testfire.net \
    --backend-url http://localhost:8000
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urljoin

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("vulnforge.cli")


class AuthenticatedScannerCLI:
    def __init__(self, backend_url: str = "http://localhost:8000"):
        self.backend_url = backend_url.rstrip("/")
        self.session = requests.Session()
        
    def check_backend(self) -> bool:
        """Check if backend API is available."""
        try:
            r = self.session.get(f"{self.backend_url}/api/health", timeout=5)
            if r.status_code == 200:
                data = r.json()
                logger.info(f"✓ Backend is healthy")
                logger.info(f"  - Nuclei available: {data.get('nuclei_available')}")
                logger.info(f"  - ZAP available: {data.get('zap_available')}")
                return True
        except Exception as e:
            logger.error(f"Backend health check failed: {e}")
        return False
    
    def upload_side_file(self, side_file: Path) -> Dict[str, Any]:
        """Upload and parse .side file."""
        logger.info(f"Uploading .side file: {side_file}")
        
        with open(side_file, 'rb') as f:
            files = {'file': (side_file.name, f, 'application/json')}
            r = self.session.post(
                f"{self.backend_url}/api/upload/selenium-test",
                files=files,
                timeout=10
            )
        
        if r.status_code != 200:
            raise Exception(f"Upload failed: {r.status_code} - {r.text}")
        
        data = r.json()
        config = data['auth_configuration']
        
        logger.info(f"✓ .side file parsed successfully")
        logger.info(f"  - Tests: {data['tests_count']}")
        logger.info(f"  - Login URL: {config['login_url']}")
        logger.info(f"  - Username field: {config['username_field']}")
        logger.info(f"  - Password field: {config['password_field']}")
        
        return config
    
    def capture_session(self, login_config: Dict[str, Any]) -> Dict[str, Any]:
        """Capture session via Selenium."""
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 1: SELENIUM LOGIN & SESSION CAPTURE")
        logger.info("=" * 80)
        
        logger.info(f"Logging in to {login_config['login_url']}")
        
        payload = {
            "login_url": login_config["login_url"],
            "username": login_config.get("username") or login_config.get("username_value"),
            "password": login_config.get("password") or login_config.get("password_value"),
            "username_field": login_config["username_field"],
            "password_field": login_config["password_field"],
            "logged_in_indicator": login_config.get("logged_in_indicator", "logout"),
            # Use docker-compose service name for internal container communication
            "zap_proxy_host": "zap",
            "zap_proxy_port": 8080,
        }
        
        r = self.session.post(
            f"{self.backend_url}/api/auth/capture-session-selenium",
            json=payload,
            timeout=120  # Long timeout for browser login
        )
        
        if r.status_code != 200:
            raise Exception(f"Session capture failed: {r.status_code} - {r.text}")
        
        session_data = r.json()
        
        logger.info(f"✓ Session captured successfully")
        if session_data.get('cookies'):
            logger.info(f"  - Cookies: {len(session_data['cookies'])}")
        if session_data.get('jwt_token'):
            logger.info(f"  - JWT: {session_data['jwt_token'][:20]}...")
        if session_data.get('bearer_token'):
            logger.info(f"  - Bearer: {session_data['bearer_token'][:20]}...")
        
        return session_data
    
    def run_authenticated_scan(self, 
                             target: str,
                             login_config: Dict[str, Any],
                             scan_type: str = "quick",
                             timeout_minutes: int = 60,
                             use_ajax_spider: bool = False) -> Dict[str, Any]:
        """Run full authenticated scan pipeline."""
        logger.info("\n" + "=" * 80)
        logger.info("AUTHENTICATED SCANNING PIPELINE")
        logger.info("=" * 80)
        
        payload = {
            "target": target,
            "login_url": login_config["login_url"],
            "username": login_config.get("username") or login_config.get("username_value"),
            "password": login_config.get("password") or login_config.get("password_value"),
            "username_field": login_config["username_field"],
            "password_field": login_config["password_field"],
            "logged_in_indicator": login_config.get("logged_in_indicator", "logout"),
            "scan_type": scan_type,
            "timeout_minutes": timeout_minutes,
            "use_ajax_spider": use_ajax_spider,
            "generate_poc": False,
            "ai_analysis": False,
            "severity_filter": ["Critical", "High"],
        }
        
        logger.info(f"Starting {scan_type} scan on {target}")
        logger.info(f"  - Timeout: {timeout_minutes} minutes")
        logger.info(f"  - Spider: {'Ajax Spider' if use_ajax_spider else 'Traditional Spider'}")
        
        r = self.session.post(
            f"{self.backend_url}/api/scans/authenticated/run",
            json=payload,
            timeout=30
        )
        
        if r.status_code != 200:
            raise Exception(f"Scan initiation failed: {r.status_code} - {r.text}")
        
        data = r.json()
        scan_id = data.get('scan_id')
        
        logger.info(f"✓ Scan queued with ID: {scan_id}")
        logger.info(f"  Status: {data.get('status')}")
        
        return {"scan_id": scan_id, "initial_response": data}
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status."""
        r = self.session.get(
            f"{self.backend_url}/api/scans/{scan_id}",
            timeout=10
        )
        
        if r.status_code != 200:
            raise Exception(f"Failed to get scan status: {r.status_code}")
        
        return r.json()
    
    def monitor_scan(self, scan_id: str, check_interval: int = 10):
        """Monitor scan progress."""
        start_time = time.time()
        last_phase = None
        last_progress = 0
        
        logger.info(f"\nMonitoring scan: {scan_id}")
        logger.info("(Press Ctrl+C to stop monitoring)")
        
        try:
            while True:
                try:
                    status = self.get_scan_status(scan_id)
                    
                    current_phase = status.get('current_phase', 'unknown')
                    progress = status.get('progress', 0)
                    scan_status = status.get('status', 'unknown')
                    
                    # Log phase changes
                    if current_phase != last_phase:
                        logger.info(f"\n→ Phase: {current_phase.upper()}")
                        last_phase = current_phase
                    
                    # Log progress updates
                    if progress != last_progress:
                        logger.info(f"  Progress: {progress}%")
                        last_progress = progress
                    
                    # Check if completed
                    if scan_status in ("completed", "failed"):
                        elapsed = time.time() - start_time
                        logger.info(f"\n✓ Scan {scan_status.upper()} (elapsed: {elapsed:.0f}s)")
                        
                        if status.get('alerts_found'):
                            logger.info(f"  Findings found: {status['alerts_found']}")
                        
                        return status
                    
                    time.sleep(check_interval)
                    
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Connection issue, retrying: {e}")
                    time.sleep(check_interval)
                    
        except KeyboardInterrupt:
            logger.info(f"\nMonitoring stopped. Scan {scan_id} is still running.")
            return None


def main():
    parser = argparse.ArgumentParser(
        description="Authenticated DAST Scanner CLI (using Backend API)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using .side file
  %(prog)s --side-file altoro.side --target https://altoro.testfire.net

  # Using manual credentials
  %(prog)s \\
    --login-url https://altoro.testfire.net/login \\
    --username-field uid --password-field passw \\
    --username jsmith --password demo1234 \\
    --target https://altoro.testfire.net

  # Only capture session, no scanning
  %(prog)s --side-file altoro.side --target https://altoro.testfire.net --no-scan
        """
    )
    
    # Input options
    input_group = parser.add_argument_group("Login Configuration")
    input_group.add_argument("--side-file", type=Path, help=".side file from Selenium IDE")
    input_group.add_argument("--login-url", help="Login page URL")
    input_group.add_argument("--username-field", help="Username field ID")
    input_group.add_argument("--password-field", help="Password field ID")
    input_group.add_argument("--username", help="Username")
    input_group.add_argument("--password", help="Password")
    input_group.add_argument("--logged-in-indicator", default="logout",
                           help="Success indicator (default: logout)")
    
    # Scanning options
    scan_group = parser.add_argument_group("Scanning")
    scan_group.add_argument("--target", required=True, help="Target URL to scan")
    scan_group.add_argument("--scan-type", choices=["quick", "full", "deep"], default="quick",
                          help="Scan depth (default: quick)")
    scan_group.add_argument("--timeout-minutes", type=int, default=60,
                          help="Timeout in minutes (default: 60)")
    scan_group.add_argument("--use-ajax-spider", action="store_true",
                          help="Use Ajax Spider")
    scan_group.add_argument("--no-scan", action="store_true",
                          help="Only capture session, skip scanning")
    scan_group.add_argument("--monitor", action="store_true", default=True,
                          help="Monitor scan progress (default: true)")
    
    # Backend options
    api_group = parser.add_argument_group("Backend API")
    api_group.add_argument("--backend-url", default="http://localhost:8000",
                         help="Backend API URL (default: http://localhost:8000)")
    
    args = parser.parse_args()
    
    # Initialize CLI
    cli = AuthenticatedScannerCLI(backend_url=args.backend_url)
    
    # Check backend availability
    if not cli.check_backend():
        logger.error("Backend API is not available. Ensure it's running on " + args.backend_url)
        return 1
    
    try:
        # Parse login configuration
        if args.side_file:
            if not args.side_file.exists():
                logger.error(f"File not found: {args.side_file}")
                return 1
            login_config = cli.upload_side_file(args.side_file)
        else:
            if not all([args.login_url, args.username_field, args.password_field, 
                       args.username, args.password]):
                parser.error("Either --side-file OR all of (--login-url, --username-field, "
                           "--password-field, --username, --password) required")
            login_config = {
                "login_url": args.login_url,
                "username": args.username,
                "password": args.password,
                "username_field": args.username_field,
                "password_field": args.password_field,
                "logged_in_indicator": args.logged_in_indicator,
            }
        
        # Ensure absolute login URL
        if not login_config["login_url"].startswith(("http://", "https://")):
            login_config["login_url"] = urljoin(args.target, login_config["login_url"])
        
        # Phase 1: Capture session
        session_data = cli.capture_session(login_config)
        
        if args.no_scan:
            logger.info("\nSession capture complete (--no-scan flag set)")
            return 0
        
        # Phase 2: Run authenticated scan
        scan_result = cli.run_authenticated_scan(
            target=args.target,
            login_config=login_config,
            scan_type=args.scan_type,
            timeout_minutes=args.timeout_minutes,
            use_ajax_spider=args.use_ajax_spider,
        )
        
        scan_id = scan_result['scan_id']
        
        # Monitor progress
        if args.monitor:
            final_status = cli.monitor_scan(scan_id)
            if final_status:
                logger.info("\n" + "=" * 80)
                logger.info("SCAN RESULTS")
                logger.info("=" * 80)
                logger.info(f"Status: {final_status.get('status')}")
                logger.info(f"Phase: {final_status.get('current_phase')}")
                logger.info(f"Findings: {final_status.get('alerts_found', 0)}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
