"""
main.py
CLI entry point for the Selenium .side → Session Extractor tool.

Usage:
  python main.py --side login.side
  python main.py --side login.side --proxy http://localhost:8080 --headless
  python main.py --side login.side --output session.json --browser firefox
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime

from dotenv import load_dotenv

from side_parser import parse_side_file, get_login_test, summarize
from selenium_runner import SideRunner, create_driver
from session_extractor import SessionExtractor

load_dotenv()

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


# ── Console log colours ────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    DIM     = "\033[2m"


def banner():
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════╗
║       SIDE → SESSION EXTRACTOR                       ║
║       Selenium IDE  ▶  Auth Token Capture            ║
╚══════════════════════════════════════════════════════╝
{C.RESET}""")


def log_callback(msg: str, level: str = "info"):
    color = {
        "info": C.RESET,
        "warning": C.YELLOW,
        "error": C.RED,
        "success": C.GREEN,
    }.get(level, C.RESET)
    print(f"{color}{msg}{C.RESET}")


def inject_credentials(commands, username: str, password: str):
    """
    Replace placeholder credential values in commands.
    Looks for ${USERNAME} / ${PASSWORD} variables or common field names.
    """
    credential_targets = ["username", "user", "email", "login", "uname", "userid", "user_id"]
    password_targets   = ["password", "pass", "passwd", "pwd", "secret"]

    for cmd in commands:
        v = cmd.value.lower()
        t = cmd.target.lower()

        if cmd.command in ("type", "sendKeys"):
            # Replace Selenium IDE variable placeholders
            if "${username}" in cmd.value.lower() or "${email}" in cmd.value.lower():
                cmd.value = username
            elif "${password}" in cmd.value.lower() or "${pass}" in cmd.value.lower():
                cmd.value = password
            # Replace by field target heuristic
            elif any(kw in t for kw in credential_targets) and not cmd.value:
                cmd.value = username
            elif any(kw in t for kw in password_targets) and not cmd.value:
                cmd.value = password

    return commands


def print_session_report(session: dict):
    s = session["summary"]
    ir = session.get("injection_ready", {})

    print(f"\n{C.BOLD}{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  SESSION EXTRACTION REPORT")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"  {C.DIM}Post-login URL  :{C.RESET} {session['current_url']}")
    print(f"  {C.DIM}Page Title      :{C.RESET} {session['page_title']}")
    print(f"\n  {C.BOLD}Token Summary:{C.RESET}")
    print(f"  {'Cookies (total)':<22}: {s['total_cookies']}")
    print(f"  {'Auth Cookies':<22}: {s['auth_cookies_found']}")
    print(f"  {'JWT Tokens':<22}: {s['jwt_tokens_found']}")
    print(f"  {'localStorage keys':<22}: {s['local_storage_keys']}")
    print(f"  {'sessionStorage keys':<22}: {s['session_storage_keys']}")

    if ir.get("cookie_header"):
        print(f"\n  {C.BOLD}{C.GREEN}✅ Cookie Header (for injection):{C.RESET}")
        print(f"  {C.DIM}Cookie: {ir['cookie_header'][:120]}...{C.RESET}" if len(ir['cookie_header']) > 120 else f"  Cookie: {ir['cookie_header']}")

    if ir.get("authorization_header"):
        print(f"\n  {C.BOLD}{C.GREEN}✅ Authorization Header (for injection):{C.RESET}")
        token = ir['authorization_header']
        print(f"  {token[:80]}..." if len(token) > 80 else f"  {token}")

    if session.get("jwt_tokens"):
        print(f"\n  {C.BOLD}JWT Tokens Found:{C.RESET}")
        for k, v in session["jwt_tokens"].items():
            display = str(v)[:60] + "..." if v and len(str(v)) > 60 else str(v)
            print(f"  {C.YELLOW}{k}{C.RESET}: {display}")

    if session["auth_cookies"]:
        print(f"\n  {C.BOLD}Auth Cookies:{C.RESET}")
        for c in session["auth_cookies"]:
            val = c['value'][:40] + "..." if len(c['value']) > 40 else c['value']
            print(f"  {C.YELLOW}{c['name']}{C.RESET}: {val}  {C.DIM}(domain={c.get('domain', '')} secure={c.get('secure', False)}){C.RESET}")

    print(f"\n{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}\n")


def run(args):
    banner()

    # ── Parse .side file ───────────────────────────────────────────────────────
    print(f"{C.BOLD}[1/4] Parsing .side file:{C.RESET} {args.side}")
    try:
        project = parse_side_file(args.side)
    except FileNotFoundError:
        print(f"{C.RED}✗ File not found: {args.side}{C.RESET}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{C.RED}✗ Invalid JSON in .side file: {e}{C.RESET}")
        sys.exit(1)

    summary = summarize(project)
    print(f"  Project : {summary['project_name']}")
    print(f"  Base URL: {summary['base_url']}")
    print(f"  Tests   : {summary['total_tests']}")

    # Pick which test to run
    if args.test_name:
        test = next((t for t in project.tests if t.name == args.test_name), None)
        if not test:
            print(f"{C.RED}✗ Test '{args.test_name}' not found. Available:{C.RESET}")
            for t in project.tests:
                print(f"   - {t.name}")
            sys.exit(1)
    else:
        test = get_login_test(project)
        if not test:
            print(f"{C.RED}✗ No tests found in .side file.{C.RESET}")
            sys.exit(1)
        print(f"  {C.DIM}Auto-selected test: {test.name}{C.RESET}")

    # ── Inject credentials from env / args ─────────────────────────────────────
    username = args.username or os.getenv("SIDE_USERNAME", "")
    password = args.password or os.getenv("SIDE_PASSWORD", "")

    if username or password:
        print(f"\n  {C.DIM}Injecting credentials for: {username or '(from .side file)'}{C.RESET}")
        test.commands = inject_credentials(test.commands, username, password)

    # ── Launch browser ─────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}[2/4] Launching {args.browser} browser...{C.RESET}")
    if args.proxy:
        print(f"  Proxying through: {args.proxy}")
    if args.headless:
        print(f"  {C.DIM}Running headless{C.RESET}")

    try:
        driver = create_driver(
            browser=args.browser,
            proxy=args.proxy,
            headless=args.headless
        )
    except Exception as e:
        print(f"{C.RED}✗ Failed to launch browser: {e}{C.RESET}")
        print(f"  Make sure ChromeDriver / GeckoDriver is installed and in PATH.")
        sys.exit(1)

    # ── Run the test ───────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}[3/4] Executing test: {test.name}{C.RESET}")
    runner = SideRunner(driver, project.url, log_callback=log_callback)

    start = time.time()
    results = runner.run_test(test)
    elapsed = time.time() - start

    print(f"\n  Completed in {elapsed:.1f}s  |  "
          f"{C.GREEN}✅ {results['passed']} passed{C.RESET}  "
          f"{C.RED}❌ {results['failed']} failed{C.RESET}")

    # Wait a moment for any post-login redirects / token storage to settle
    time.sleep(args.wait)

    # ── Extract session ────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}[4/4] Extracting session tokens...{C.RESET}")
    extractor = SessionExtractor(driver)
    session = extractor.extract_all()

    driver.quit()

    # ── Display report ─────────────────────────────────────────────────────────
    print_session_report(session)

    # ── Save output ────────────────────────────────────────────────────────────
    output_data = {
        "metadata": {
            "side_file": args.side,
            "test_name": test.name,
            "base_url": project.url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "browser": args.browser,
            "proxy": args.proxy,
            "test_results": results
        },
        "session": session
    }

    output_path = args.output or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, default=str)

    print(f"{C.GREEN}{C.BOLD}💾 Session saved to: {output_path}{C.RESET}\n")

    return session


def main():
    parser = argparse.ArgumentParser(
        description="Run a Selenium IDE .side file and extract the auth session.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --side login.side
  python main.py --side login.side --username admin --password secret
  python main.py --side login.side --proxy http://localhost:8080
  python main.py --side login.side --headless --output mysession.json
  python main.py --side login.side --test-name "Admin Login" --browser firefox

Credentials can also be set via environment variables or .env file:
  SIDE_USERNAME=admin
  SIDE_PASSWORD=secret123
        """
    )

    parser.add_argument("--side",       required=True,          help="Path to the .side file")
    parser.add_argument("--test-name",  default=None,           help="Specific test name to run (auto-detects login test if omitted)")
    parser.add_argument("--browser",    default="chrome",       choices=["chrome", "firefox"], help="Browser to use (default: chrome)")
    parser.add_argument("--proxy",      default=None,           help="Proxy URL e.g. http://localhost:8080 (routes through ZAP)")
    parser.add_argument("--headless",   action="store_true",    help="Run browser in headless mode")
    parser.add_argument("--username",   default=None,           help="Username to inject (overrides .side file value)")
    parser.add_argument("--password",   default=None,           help="Password to inject (overrides .side file value)")
    parser.add_argument("--wait",       type=float, default=2,  help="Seconds to wait after login before extracting session (default: 2)")
    parser.add_argument("--output",     default=None,           help="Output JSON file path (default: session_<timestamp>.json)")

    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
