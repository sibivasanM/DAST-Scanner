#!/usr/bin/env python3
"""
Standalone CLI tool for authenticated DAST scanning with Selenium + ZAP.

Usage:
  python3 cli_auth_scanner.py \
    --login-url http://altoro.testfire.net/ \
    --username-field uid \
    --password-field passw \
    --username jsmith \
    --password demo1234 \
    --target http://altoro.testfire.net \
    --zap-url http://localhost:8080 \
    --api-key vulnforge-zap-key

Or with a .side file:
  python3 cli_auth_scanner.py \
    --side-file altoro.side \
    --target http://altoro.testfire.net \
    --zap-url http://localhost:8080 \
    --api-key vulnforge-zap-key
"""

import asyncio
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any

# Add backend module path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from modules.selenium_auth import SeleniumAuthCapture
from modules.zap_session_injector import ZapSessionInjector
from modules.zap_context_config import ZapContextConfig
from modules.zap_scan_orchestrator import ZapScanOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("vulnforge.cli")


def parse_side_file(side_file: Path) -> Dict[str, Any]:
    """Parse .side file and extract login configuration."""
    logger.info(f"Parsing .side file: {side_file}")
    
    with open(side_file, 'r') as f:
        data = json.load(f)
    
    config = {
        "login_url": None,
        "username_field": None,
        "password_field": None,
        "username": None,
        "password": None,
        "success_indicator": None,
    }
    
    # Extract first test's commands
    tests = data.get("tests", [])
    if not tests:
        raise ValueError("No tests found in .side file")
    
    test = tests[0]
    commands = test.get("commands", [])
    
    for cmd in commands:
        cmd_type = cmd.get("command", "").lower()
        target = cmd.get("target", "")
        value = cmd.get("value", "")
        
        # Parse open command for login URL
        if cmd_type == "open":
            if not config["login_url"]:
                config["login_url"] = value if value else target
        
        # Parse settext/type commands for credentials
        if cmd_type in ("settext", "type"):
            field_name = target.split("=")[-1] if "=" in target else target
            field_name_lower = field_name.lower()
            
            if any(x in field_name_lower for x in ["user", "login", "email", "uid", "username"]):
                config["username_field"] = field_name
                config["username"] = value
            elif any(x in field_name_lower for x in ["pass", "pwd", "password"]):
                config["password_field"] = field_name
                config["password"] = value
    
    logger.info(f"Extracted from .side: login_url={config['login_url']}, "
                f"username_field={config['username_field']}, password_field={config['password_field']}")
    
    return config


async def main():
    parser = argparse.ArgumentParser(
        description="Authenticated DAST Scanner: Selenium Login + ZAP Session Injection + Scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Input options
    input_group = parser.add_argument_group("Login Configuration")
    input_group.add_argument("--side-file", type=Path, help=".side file from Selenium IDE")
    input_group.add_argument("--login-url", help="Login page URL")
    input_group.add_argument("--username-field", help="Username field ID/name")
    input_group.add_argument("--password-field", help="Password field ID/name")
    input_group.add_argument("--username", help="Username credential")
    input_group.add_argument("--password", help="Password credential")
    input_group.add_argument("--logged-in-indicator", default="logout", 
                           help="Text/pattern indicating successful login (default: logout)")
    
    # Scanning options
    scan_group = parser.add_argument_group("Scanning Configuration")
    scan_group.add_argument("--target", required=True, help="Target URL to scan")
    scan_group.add_argument("--exclude-urls", default="logout,signout,reset-password",
                          help="Comma-separated logout/exit patterns")
    scan_group.add_argument("--scan-type", choices=["quick", "full", "deep"], default="quick",
                          help="Scan depth (default: quick)")
    scan_group.add_argument("--timeout-minutes", type=int, default=60,
                          help="Scan timeout in minutes (default: 60)")
    scan_group.add_argument("--use-ajax-spider", action="store_true",
                          help="Use Ajax Spider instead of traditional spider")
    
    # ZAP options
    zap_group = parser.add_argument_group("ZAP Configuration")
    zap_group.add_argument("--zap-url", default="http://localhost:8080",
                         help="ZAP API URL (default: http://localhost:8080)")
    zap_group.add_argument("--api-key", default="vulnforge-zap-key",
                         help="ZAP API key (default: vulnforge-zap-key)")
    
    # Browser options
    browser_group = parser.add_argument_group("Browser Configuration")
    browser_group.add_argument("--zap-proxy-host", default="localhost",
                            help="ZAP proxy host (default: localhost)")
    browser_group.add_argument("--zap-proxy-port", type=int, default=8080,
                            help="ZAP proxy port (default: 8080)")
    browser_group.add_argument("--skip-scan", action="store_true",
                             help="Only capture session, skip scanning")
    
    args = parser.parse_args()
    
    # Parse input configuration
    if args.side_file:
        if not args.side_file.exists():
            logger.error(f"File not found: {args.side_file}")
            return 1
        login_config = parse_side_file(args.side_file)
    else:
        if not all([args.login_url, args.username_field, args.password_field, 
                   args.username, args.password]):
            parser.error("Either --side-file OR all of (--login-url, --username-field, "
                        "--password-field, --username, --password) required")
        login_config = {
            "login_url": args.login_url,
            "username_field": args.username_field,
            "password_field": args.password_field,
            "username": args.username,
            "password": args.password,
            "logged_in_indicator": args.logged_in_indicator,
        }
    
    # Ensure absolute login_url
    if not login_config["login_url"].startswith(("http://", "https://")):
        # Make it relative to target
        from urllib.parse import urljoin
        login_config["login_url"] = urljoin(args.target, login_config["login_url"])
    
    logger.info("=" * 80)
    logger.info("PHASE 1: SELENIUM LOGIN & SESSION CAPTURE")
    logger.info("=" * 80)
    
    # Phase 1: Selenium login
    try:
        selenium_auth = SeleniumAuthCapture(
            zap_proxy_host=args.zap_proxy_host,
            zap_proxy_port=args.zap_proxy_port,
        )
        
        logger.info(f"Logging in to {login_config['login_url']}")
        session_data = await selenium_auth.capture_session(
            login_url=login_config["login_url"],
            username=login_config["username"],
            password=login_config["password"],
            username_field=login_config["username_field"],
            password_field=login_config["password_field"],
            logged_in_indicator=login_config.get("logged_in_indicator", "logout"),
        )
        
        logger.info(f"✓ Session captured successfully")
        logger.info(f"  - Cookies: {len(session_data.get('cookies', []))} captured")
        logger.info(f"  - JWT: {session_data.get('jwt_token', 'None')}")
        logger.info(f"  - Bearer: {session_data.get('bearer_token', 'None')}")
        
    except Exception as e:
        logger.error(f"✗ Selenium login failed: {e}")
        return 1
    
    if args.skip_scan:
        logger.info("Skipping scan (--skip-scan flag set)")
        return 0
    
    logger.info("\n" + "=" * 80)
    logger.info("PHASE 2: ZAP SESSION INJECTION")
    logger.info("=" * 80)
    
    # Phase 2: ZAP session injection
    try:
        zap_injector = ZapSessionInjector(api_url=args.zap_url, api_key=args.api_key)
        
        logger.info(f"Injecting session into ZAP")
        inject_result = await zap_injector.inject_session(
            target_url=args.target,
            session_data=session_data,
            session_name="authenticated-session"
        )
        
        logger.info(f"✓ Session injected successfully")
        logger.info(f"  - Method: {inject_result.get('method', 'unknown')}")
        logger.info(f"  - Items injected: {inject_result.get('count', 0)}")
        
    except Exception as e:
        logger.error(f"✗ Session injection failed: {e}")
        return 1
    
    logger.info("\n" + "=" * 80)
    logger.info("PHASE 3: ZAP CONTEXT CONFIGURATION")
    logger.info("=" * 80)
    
    # Phase 3: ZAP context configuration
    try:
        zap_context = ZapContextConfig(api_url=args.zap_url, api_key=args.api_key)
        
        exclude_patterns = [p.strip() for p in args.exclude_urls.split(",")]
        logger.info(f"Creating context for {args.target} (excluding: {', '.join(exclude_patterns)})")
        
        context_result = await zap_context.create_context(
            target_url=args.target,
            context_name="authenticated-context",
            exclude_urls=exclude_patterns,
        )
        
        logger.info(f"✓ Context configured successfully")
        
    except Exception as e:
        logger.error(f"✗ Context configuration failed: {e}")
        return 1
    
    logger.info("\n" + "=" * 80)
    logger.info(f"PHASE 4: AUTHENTICATED SCANNING ({args.scan_type.upper()})")
    logger.info("=" * 80)
    
    # Phase 4: Scanning
    try:
        zap_orchestrator = ZapScanOrchestrator(api_url=args.zap_url, api_key=args.api_key)
        
        logger.info(f"Starting {args.scan_type} scan with Ajax Spider={args.use_ajax_spider}")
        scan_result = await zap_orchestrator.run_authenticated_scan(
            target_url=args.target,
            context_name="authenticated-context",
            use_ajax_spider=args.use_ajax_spider,
            scan_type=args.scan_type,
            timeout_minutes=args.timeout_minutes,
            logged_in_indicator=login_config.get("logged_in_indicator", "logout"),
        )
        
        logger.info(f"✓ Scan completed successfully")
        logger.info(f"  - Duration: {scan_result.get('duration_seconds', 0):.0f} seconds")
        logger.info(f"  - URLs discovered: {scan_result.get('urls_found', 0)}")
        logger.info(f"  - Vulnerabilities found: {scan_result.get('alerts_found', 0)}")
        
        if scan_result.get("alerts_found", 0) > 0:
            logger.info(f"\n  Findings by severity:")
            alerts = scan_result.get("alerts", [])
            
            # Group by risk
            by_risk = {}
            for alert in alerts:
                risk = alert.get("risk", "Unknown")
                by_risk.setdefault(risk, 0)
                by_risk[risk] += 1
            
            for risk in ["Critical", "High", "Medium", "Low", "Info"]:
                count = by_risk.get(risk, 0)
                if count > 0:
                    logger.info(f"    {risk:12s}: {count:3d}")
        
        return 0
        
    except asyncio.TimeoutError:
        logger.error(f"✗ Scan timeout ({args.timeout_minutes} minutes exceeded)")
        return 1
    except Exception as e:
        logger.error(f"✗ Scanning failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
