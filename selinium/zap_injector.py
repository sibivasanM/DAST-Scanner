"""
zap_injector.py
Takes the extracted session JSON and injects it into OWASP ZAP.

Usage:
  python zap_injector.py --session session.json --target https://your-app.com
  python zap_injector.py --session session.json --target https://your-app.com --scan
"""

import argparse
import json
import sys
import time
import logging

logger = logging.getLogger(__name__)


class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    CYAN    = "\033[96m"
    DIM     = "\033[2m"


def load_session(path: str) -> dict:
    with open(path, "r") as f:
        data = json.load(f)
    return data


def inject_cookies(zap, target: str, cookies: list, session_name: str = "side-session"):
    """Create a ZAP HTTP session and inject cookies into it."""
    print(f"\n{C.BOLD}Injecting cookies into ZAP session '{session_name}'...{C.RESET}")

    # Create empty session
    zap.httpsessions.create_empty_session(target, session_name)
    zap.httpsessions.set_active_session(target, session_name)

    # Register each cookie as a session token
    for cookie in cookies:
        name = cookie["name"]
        value = cookie["value"]
        try:
            zap.httpsessions.add_session_token(target, name)
            print(f"  {C.GREEN}✅ Injected cookie: {name}{C.RESET}")
        except Exception as e:
            print(f"  {C.YELLOW}⚠ Could not register token {name}: {e}{C.RESET}")

    print(f"  {C.GREEN}✅ Session '{session_name}' is now active in ZAP{C.RESET}")


def inject_bearer_token(zap, token: str, description: str = "Side Session Bearer Token"):
    """Use ZAP's Replacer to inject Bearer token into every request."""
    print(f"\n{C.BOLD}Injecting Bearer token via ZAP Replacer...{C.RESET}")
    try:
        zap.replacer.add_rule(
            description=description,
            enabled="true",
            matchtype="REQ_HEADER",
            matchstring="Authorization",
            matchregex="false",
            replacement=f"Bearer {token}",
            initiators=""
        )
        print(f"  {C.GREEN}✅ Replacer rule added: Authorization: Bearer {token[:30]}...{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}✗ Failed to add replacer rule: {e}{C.RESET}")


def setup_context(zap, target: str, context_name: str = "side-auth-context") -> str:
    """Create a ZAP context for the target and return its ID."""
    print(f"\n{C.BOLD}Creating ZAP context '{context_name}'...{C.RESET}")
    context_id = zap.context.new_context(context_name)
    zap.context.include_in_context(context_name, f"{target}.*")

    # Common logout paths to exclude
    logout_patterns = [
        f"{target}.*/logout.*",
        f"{target}.*/signout.*",
        f"{target}.*/sign-out.*",
        f"{target}.*/auth/logout.*",
    ]
    for pattern in logout_patterns:
        try:
            zap.context.exclude_from_context(context_name, pattern)
        except Exception:
            pass

    print(f"  {C.GREEN}✅ Context created: ID={context_id}{C.RESET}")
    return context_id


def run_spider(zap, target: str, context_id: str, ajax: bool = True):
    """Run Ajax Spider or traditional spider on the target."""
    if ajax:
        print(f"\n{C.BOLD}Starting Ajax Spider...{C.RESET}")
        zap.ajaxSpider.scan(target, contextname=None, inscope=None)
        time.sleep(5)
        while zap.ajaxSpider.status == "running":
            print(f"  Ajax Spider running... URLs found: {len(zap.ajaxSpider.results())}")
            time.sleep(10)
        print(f"  {C.GREEN}✅ Ajax Spider complete. URLs: {len(zap.ajaxSpider.results())}{C.RESET}")
    else:
        print(f"\n{C.BOLD}Starting traditional Spider...{C.RESET}")
        scan_id = zap.spider.scan(target, contextid=context_id)
        while int(zap.spider.status(scan_id)) < 100:
            print(f"  Spider progress: {zap.spider.status(scan_id)}%")
            time.sleep(5)
        print(f"  {C.GREEN}✅ Spider complete. URLs: {len(zap.spider.results(scan_id))}{C.RESET}")


def run_active_scan(zap, target: str, context_id: str):
    """Run ZAP active scanner."""
    print(f"\n{C.BOLD}Starting Active Scan...{C.RESET}")
    scan_id = zap.ascan.scan(target, contextid=context_id)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"  Active Scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(10)
    print(f"  {C.GREEN}✅ Active Scan complete!{C.RESET}")


def print_alerts(zap):
    """Print a summary of ZAP alerts by risk level."""
    alerts = zap.core.alerts()
    risk_groups = {"High": [], "Medium": [], "Low": [], "Informational": []}
    for a in alerts:
        risk = a.get("risk", "Informational")
        risk_groups.setdefault(risk, []).append(a)

    print(f"\n{C.BOLD}{C.CYAN}━━ SCAN RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    colors = {"High": C.RED, "Medium": C.YELLOW, "Low": C.CYAN, "Informational": C.DIM}
    for risk, items in risk_groups.items():
        if items:
            print(f"  {colors.get(risk, C.RESET)}{risk}: {len(items)} alert(s){C.RESET}")
    print(f"{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}\n")

    return alerts


def main():
    parser = argparse.ArgumentParser(description="Inject extracted session into ZAP and optionally scan.")
    parser.add_argument("--session",  required=True,       help="Path to session JSON file from main.py")
    parser.add_argument("--target",   required=True,       help="Target URL e.g. https://your-app.com")
    parser.add_argument("--zap-url",  default="http://localhost:8080", help="ZAP API URL")
    parser.add_argument("--zap-key",  default="",          help="ZAP API key")
    parser.add_argument("--scan",     action="store_true", help="Also run spider + active scan after injection")
    parser.add_argument("--ajax",     action="store_true", default=True, help="Use Ajax Spider (for SPAs)")
    parser.add_argument("--report",   default=None,        help="Save HTML report to this path")
    args = parser.parse_args()

    try:
        from zapv2 import ZAPv2
    except ImportError:
        print(f"{C.RED}✗ zapv2 not installed. Run: pip install python-owasp-zap-v2.4{C.RESET}")
        sys.exit(1)

    # Load session data
    print(f"{C.BOLD}Loading session: {args.session}{C.RESET}")
    data = load_session(args.session)
    session = data["session"]
    injection = session.get("injection_ready", {})

    # Connect to ZAP
    print(f"{C.BOLD}Connecting to ZAP at {args.zap_url}...{C.RESET}")
    zap = ZAPv2(apikey=args.zap_key, proxies={"http": args.zap_url, "https": args.zap_url})

    try:
        version = zap.core.version
        print(f"  {C.GREEN}✅ Connected to ZAP {version}{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}✗ Cannot connect to ZAP: {e}{C.RESET}")
        print(f"  Make sure ZAP is running: zap.sh -daemon -port 8080 -config api.key={args.zap_key}")
        sys.exit(1)

    # Setup context
    context_id = setup_context(zap, args.target)

    # Inject based on what was captured
    if injection.get("raw_token"):
        inject_bearer_token(zap, injection["raw_token"])
    
    if session.get("auth_cookies"):
        inject_cookies(zap, args.target, session["auth_cookies"])

    if not injection.get("raw_token") and not session.get("auth_cookies"):
        print(f"{C.YELLOW}⚠ No injectable tokens found in session file.{C.RESET}")
        print(f"  Attempting to inject all cookies anyway...")
        if session.get("all_cookies"):
            inject_cookies(zap, args.target, session["all_cookies"])

    print(f"\n{C.GREEN}{C.BOLD}✅ Session injection complete!{C.RESET}")

    # Optionally run scan
    if args.scan:
        run_spider(zap, args.target, context_id, ajax=args.ajax)
        run_active_scan(zap, args.target, context_id)
        alerts = print_alerts(zap)

        if args.report:
            report = zap.core.htmlreport()
            with open(args.report, "w") as f:
                f.write(report)
            print(f"{C.GREEN}💾 HTML Report saved to: {args.report}{C.RESET}")
    else:
        print(f"\n{C.DIM}Tip: Run with --scan to start spider + active scan automatically.{C.RESET}")
        print(f"{C.DIM}ZAP is ready — you can now configure and run your scan manually.{C.RESET}\n")


if __name__ == "__main__":
    main()
