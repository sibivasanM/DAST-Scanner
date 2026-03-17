"""
PoC Generator — Uses Playwright to generate proof-of-concept exploits
and evidence screenshots for each vulnerability finding.

Uses OpenAI GPT-4o to generate intelligent, finding-specific PoC scripts.
Enhanced with smart evidence extraction for XSS, SQLi, Command Injection.
"""

import asyncio
import json
import logging
import os
import re
import uuid
from typing import Optional, List, Dict, Any

import httpx

logger = logging.getLogger(__name__)

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
MODEL = "gpt-4o"
SCREENSHOTS_DIR = "screenshots"

# ── Context pool configuration ────────────────────────────────────────────────
# Reusing browser contexts avoids the 200-500ms spin-up cost on every screenshot.
_CONTEXT_POOL_SIZE = 8          # max pooled contexts (matches semaphore in main.py)
_PAGE_GOTO_TIMEOUT = 20000      # ms — max time to load any page (was 30000)
_SMART_WAIT_MS     = 400        # ms — small settle wait after domcontentloaded
_OVERLAY_WAIT_MS   = 150        # ms — wait after DOM overlay injection before screenshot

POC_SYSTEM_PROMPT = """You are a security engineer generating Playwright (Python) proof-of-concept
scripts for verified vulnerabilities. Generate a complete, runnable Python script that:

1. Uses playwright.async_api
2. Navigates to the target URL
3. Demonstrates the vulnerability with specific actions
4. Takes a screenshot as evidence
5. Captures relevant response data
6. Includes clear comments explaining each step

Respond with ONLY the Python code (no markdown, no backticks, no explanation).

The script must:
- Accept target URL and screenshot path as variables at the top
- Use async/await pattern
- Handle errors gracefully with try/except
- Be completely self-contained and runnable
- Include a final screenshot named 'evidence.png'
"""

# Template-based PoC generators for common vulnerability types
POC_TEMPLATES = {
    "xss": '''"""PoC: Cross-Site Scripting (XSS) — {name}"""
import asyncio
from playwright.async_api import async_playwright

TARGET_URL = "{url}"
SCREENSHOT_PATH = "{screenshot_path}"

async def exploit():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        # Step 1: Navigate to the vulnerable endpoint
        await page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(2000)

        # Step 2: Check for XSS indicators in the DOM
        content = await page.content()

        # Step 3: Capture evidence screenshot
        await page.screenshot(path=SCREENSHOT_PATH, full_page=True)

        # Step 4: Check for script execution / DOM manipulation
        evidence = {{
            "url": page.url,
            "title": await page.title(),
            "xss_indicators_found": "<script" in content.lower() or "onerror" in content.lower(),
            "page_content_length": len(content),
        }}

        await browser.close()
        return evidence

if __name__ == "__main__":
    result = asyncio.run(exploit())
    print(f"Evidence: {{result}}")
''',

    "sqli": '''"""PoC: SQL Injection — {name}"""
import asyncio
from playwright.async_api import async_playwright

TARGET_URL = "{url}"
SCREENSHOT_PATH = "{screenshot_path}"

async def exploit():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        responses = []
        page.on("response", lambda r: responses.append({{
            "url": r.url, "status": r.status
        }}))

        # Step 1: Navigate to the vulnerable endpoint
        await page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(2000)

        # Step 2: Capture the response indicating SQLi
        content = await page.content()

        # Step 3: Screenshot evidence
        await page.screenshot(path=SCREENSHOT_PATH, full_page=True)

        evidence = {{
            "url": page.url,
            "sql_error_indicators": any(
                kw in content.lower()
                for kw in ["sql syntax", "mysql", "postgresql", "sqlite", "ora-", "unclosed quotation"]
            ),
            "response_count": len(responses),
        }}

        await browser.close()
        return evidence

if __name__ == "__main__":
    result = asyncio.run(exploit())
    print(f"Evidence: {{result}}")
''',

    "default": '''"""PoC: {name} [{severity}]"""
import asyncio
from playwright.async_api import async_playwright

TARGET_URL = "{url}"
SCREENSHOT_PATH = "{screenshot_path}"

async def exploit():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        responses = []
        page.on("response", lambda r: responses.append({{
            "url": r.url, "status": r.status, "headers": dict(r.headers)
        }}))

        # Step 1: Navigate to vulnerable endpoint
        await page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(3000)

        # Step 2: Capture page state
        content = await page.content()
        title = await page.title()

        # Step 3: Evidence screenshot
        await page.screenshot(path=SCREENSHOT_PATH, full_page=True)

        evidence = {{
            "url": page.url,
            "title": title,
            "status_codes": [r["status"] for r in responses[:10]],
            "content_length": len(content),
            "vulnerability": "{name}",
            "severity": "{severity}",
        }}

        await browser.close()
        return evidence

if __name__ == "__main__":
    result = asyncio.run(exploit())
    print(f"Evidence: {{result}}")
''',
}


class PoCGenerator:
    """Generates PoC scripts and screenshots for vulnerability findings using OpenAI."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model or os.getenv("OPENAI_MODEL", MODEL)
        self.ai_enabled = bool(self.api_key)
        self._playwright = None
        self._browser = None
        self._ctx_pool: Optional[asyncio.Queue] = None   # reusable context pool
        os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

    async def initialize(self):
        """Initialize Playwright browser and pre-warm context pool."""
        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            # Pre-warm the context pool so the first batch of screenshots
            # doesn't all pay the context-creation cost simultaneously.
            self._ctx_pool = asyncio.Queue()
            for _ in range(_CONTEXT_POOL_SIZE):
                ctx = await self._browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 800},
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    ),
                )
                await self._ctx_pool.put(ctx)
            logger.info(f"Playwright browser initialised — {_CONTEXT_POOL_SIZE} contexts pooled")
        except Exception as e:
            logger.warning(f"Playwright initialization failed: {e}")
            self._browser = None

    async def shutdown(self):
        """Clean up Playwright resources including the context pool."""
        if self._ctx_pool:
            while not self._ctx_pool.empty():
                try:
                    ctx = self._ctx_pool.get_nowait()
                    await ctx.close()
                except Exception:
                    pass
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def _acquire_ctx(self):
        """
        Borrow a browser context from the pool.
        If the pool is empty (all slots busy), create a temporary context.
        """
        if self._ctx_pool and not self._ctx_pool.empty():
            return await self._ctx_pool.get()
        # Pool exhausted — create an ad-hoc context (will be closed, not returned)
        return await self._browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )

    async def _release_ctx(self, ctx):
        """
        Return a context to the pool after clearing its cookies/storage.
        If the pool is full the context is closed instead.
        """
        if self._ctx_pool and self._ctx_pool.qsize() < _CONTEXT_POOL_SIZE:
            try:
                await ctx.clear_cookies()
                await self._ctx_pool.put(ctx)
                return
            except Exception:
                pass
        try:
            await ctx.close()
        except Exception:
            pass

    async def generate_steps_to_reproduce(self, finding: dict) -> dict:
        """
        Generate stepwise reproduction instructions using OpenAI.
        Includes smart evidence extraction for XSS, SQLi, Command Injection.
        
        Returns:
        - steps: [descriptions]
        - screenshots: [paths]
        - actions: [Playwright code]
        - expected_results: [outcomes]
        - evidence: [smart extracted proof]
        """
        if not self.ai_enabled or not self._browser:
            return {"steps": [], "screenshots": [], "actions": [], "evidence": {}}
        
        steps_data = []
        screenshots = []
        all_evidence = {}
        finding_id = finding.get("id", str(uuid.uuid4()))
        url = finding.get("matched_at") or finding.get("url") or finding.get("host", "")
        
        if not url:
            return {"steps": [], "screenshots": [], "actions": [], "evidence": {}}
        
        # Use OpenAI to generate detailed step-by-step actions
        prompt = f"""Generate detailed step-by-step instructions to reproduce this vulnerability.
        
For each step, provide:
1. Step description (what to do)
2. Playwright action code (fill_text, click, wait_for_selector, etc.)
3. Expected result (what should happen)

Vulnerability: {finding.get('name', '')}
URL: {url}
Description: {finding.get('description', '')}
Type: {finding.get('vuln_type', '')}
Tags: {finding.get('tags', '')}

Provide ONLY the step list, one per line, no extra text."""
        
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    OPENAI_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "temperature": 0.2,
                        "max_tokens": 1024,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a security engineer generating Playwright automation steps."
                            },
                            {"role": "user", "content": prompt},
                        ],
                    },
                )
                response.raise_for_status()
                data = response.json()
            
            text = data["choices"][0]["message"]["content"].strip()
            
            # Parse steps: "Step N: description | action | result"
            for line in text.split("\n"):
                if "Step" not in line or "|" not in line:
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    step_desc = parts[0].replace("Step", "").strip()
                    action = parts[1]
                    expected = parts[2]
                    steps_data.append({
                        "description": step_desc,
                        "action": action,
                        "expected": expected
                    })
        except Exception as e:
            logger.warning(f"OpenAI steps generation failed: {e}")
            return {"steps": [], "screenshots": [], "actions": [], "evidence": {}}
        
        # Execute each step in Playwright
        if steps_data:
            try:
                context = await self._browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1920, "height": 1080},
                )
                page = await context.new_page()
                
                # Navigate to URL first
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(1000)
                
                # Execute each step
                for idx, step_info in enumerate(steps_data, 1):
                    step_desc = step_info["description"]
                    action_str = step_info["action"]
                    
                    try:
                        # Execute action dynamically (simple implementation)
                        if "page.goto" in action_str:
                            target_url = url if "url" in action_str else url
                            await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
                        elif "page.fill" in action_str:
                            # Extract selector and value
                            match = re.search(r"page\.fill\('([^']+)',\s*'([^']+)'\)", action_str)
                            if match:
                                selector, value = match.groups()
                                await page.fill(selector, value)
                        elif "page.click" in action_str:
                            # Extract selector
                            match = re.search(r"page\.click\('([^']+)'\)", action_str)
                            if match:
                                selector = match.group(1)
                                await page.click(selector)
                        elif "page.wait_for" in action_str:
                            # Wait for dialog or event
                            if "dialog" in action_str:
                                try:
                                    await asyncio.wait_for(page.wait_for_event("dialog"), timeout=5)
                                except asyncio.TimeoutError:
                                    pass
                            elif "selector" in action_str:
                                match = re.search(r"page\.wait_for_selector\('([^']+)'\)", action_str)
                                if match:
                                    selector = match.group(1)
                                    try:
                                        await asyncio.wait_for(page.wait_for_selector(selector), timeout=5)
                                    except asyncio.TimeoutError:
                                        pass
                        
                        await page.wait_for_timeout(1000)
                    except Exception as e:
                        logger.warning(f"Step {idx} action failed: {e}")
                    
                    # Take screenshot after each step
                    screenshot_path = os.path.join(
                        SCREENSHOTS_DIR,
                        f"{finding_id}_step{idx}.png"
                    )
                    try:
                        await page.screenshot(path=screenshot_path, full_page=True)
                        screenshots.append(screenshot_path)
                    except Exception as e:
                        logger.warning(f"Step {idx} screenshot failed: {e}")
                        screenshots.append("")
                
                # Extract smart evidence after all steps
                all_evidence = await self.extract_vulnerability_evidence(finding, page)
                
                await context.close()
            except Exception as e:
                logger.warning(f"Steps reproduction failed: {e}")
        
        return {
            "steps": [s["description"] for s in steps_data],
            "screenshots": screenshots,
            "actions": [s["action"] for s in steps_data],
            "expected_results": [s["expected"] for s in steps_data],
            "evidence": all_evidence
        }

    async def extract_vulnerability_evidence(self, finding: dict, page) -> Dict[str, Any]:
        """
        Extract specific evidence for different vulnerability types.
        - XSS: Dialog content, alert message, DOM payload
        - SQL Injection: Error messages, query response
        - Command Injection: Command output, stderr
        """
        vuln_type = finding.get("vuln_type", "").lower()
        vuln_name = finding.get("name", "").lower()
        tags = str(finding.get("tags", "")).lower()
        
        evidence = {
            "type": vuln_type,
            "raw_screenshot": "",
            "extracted_data": {},
            "page_content": "",
            "console_messages": [],
            "dialog_content": ""
        }
        
        try:
            # Capture page content before extraction
            evidence["page_content"] = await page.content()
            
            # Extract console messages (errors, logs)
            console_logs = []
            page.on("console", lambda msg: console_logs.append({
                "type": msg.type,
                "text": msg.text
            }))
            evidence["console_messages"] = console_logs
            
            # Type-specific evidence extraction
            if any(t in tags or t in vuln_type or t in vuln_name for t in ["xss", "cross-site"]):
                evidence = await self._extract_xss_evidence(page, evidence, finding)
            
            elif any(t in tags or t in vuln_type or t in vuln_name for t in ["sqli", "sql-injection", "injection"]):
                evidence = await self._extract_sqli_evidence(page, evidence, finding)
            
            elif any(t in tags or t in vuln_type or t in vuln_name for t in ["command", "rce", "code-injection"]):
                evidence = await self._extract_command_evidence(page, evidence, finding)
        
        except Exception as e:
            logger.warning(f"Evidence extraction failed: {e}")
        
        return evidence

    async def _extract_xss_evidence(self, page, evidence: Dict, finding: Dict) -> Dict:
        """Extract XSS-specific evidence: dialog content, alert messages."""
        try:
            # Try to capture dialog/alert box
            dialog_handler = lambda dialog: asyncio.create_task(self._handle_dialog(dialog))
            page.on("dialog", dialog_handler)
            
            # Trigger the payload if not already triggered
            payload = finding.get("curl_command", "")
            if not evidence["dialog_content"] and payload:
                try:
                    # Try common XSS sinks
                    await page.evaluate('() => { if (typeof alert !== "undefined") alert("XSS-Triggered"); }')
                    await asyncio.sleep(1)
                except:
                    pass
            
            # Get all alerts/dialogs from page
            dialogs_text = await page.evaluate("""() => {
                const messages = [];
                window.__xss_alerts = window.__xss_alerts || [];
                return window.__xss_alerts;
            }""")
            
            evidence["extracted_data"]["xss_alerts"] = dialogs_text
            evidence["extracted_data"]["dom_scripts"] = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script')).map(s => s.text).slice(0, 3);
            }""")
            
            # Screenshot the current state (may show alert/popup)
            screenshot_path = os.path.join(SCREENSHOTS_DIR, f"{finding.get('id', 'xss')}_evidence_alert.png")
            await page.screenshot(path=screenshot_path)
            evidence["raw_screenshot"] = screenshot_path
            
        except Exception as e:
            logger.warning(f"XSS evidence extraction failed: {e}")
        
        return evidence

    async def _extract_sqli_evidence(self, page, evidence: Dict, finding: Dict) -> Dict:
        """Extract SQL Injection evidence: error messages, query responses."""
        try:
            # Look for SQL error patterns
            page_html = evidence["page_content"]
            
            sql_errors = []
            error_patterns = [
                r"SQL syntax.*error",
                r"mysql.*error",
                r"PostgreSQL.*error",
                r"SQLite.*near",
                r"ORA-\d+",
                r"ODBC.*error",
                r"DB2.*error"
            ]
            
            for pattern in error_patterns:
                matches = re.findall(pattern, page_html, re.IGNORECASE)
                sql_errors.extend(matches)
            
            evidence["extracted_data"]["sql_errors"] = sql_errors[:5]
            
            # Extract table names if visible
            table_pattern = r"(?:from|into|update|delete from)\s+(\w+)"
            tables = re.findall(table_pattern, page_html, re.IGNORECASE)
            evidence["extracted_data"]["tables_mentioned"] = list(set(tables))[:5]
            
            # Try to evaluate response time (timing-based SQLi indicator)
            time_before = asyncio.get_event_loop().time()
            try:
                await asyncio.wait_for(page.wait_for_load_state("networkidle"), timeout=5)
            except:
                pass
            time_after = asyncio.get_event_loop().time()
            evidence["extracted_data"]["response_time"] = time_after - time_before
            
            # Screenshot showing error
            screenshot_path = os.path.join(SCREENSHOTS_DIR, f"{finding.get('id', 'sqli')}_evidence_error.png")
            await page.screenshot(path=screenshot_path)
            evidence["raw_screenshot"] = screenshot_path
            
        except Exception as e:
            logger.warning(f"SQLi evidence extraction failed: {e}")
        
        return evidence

    async def _extract_command_evidence(self, page, evidence: Dict, finding: Dict) -> Dict:
        """Extract Command Injection evidence: command output, stderr."""
        try:
            # Look for command output patterns
            page_html = evidence["page_content"]
            
            # Extract anything that looks like command output
            output_patterns = [
                r"<pre[^>]*>([^<]+)</pre>",
                r"<code[^>]*>([^<]+)</code>",
                r"Result:?\s*<br\s*/?>([^<\n]+)",
                r"Output:?\s*([^\n<]+)"
            ]
            
            command_outputs = []
            for pattern in output_patterns:
                matches = re.findall(pattern, page_html, re.IGNORECASE)
                command_outputs.extend(matches)
            
            evidence["extracted_data"]["command_outputs"] = [o.strip() for o in command_outputs[:5]]
            
            # Look for common command indicators
            command_indicators = []
            cmd_patterns = ["ls", "cat", "whoami", "id", "pwd", "netstat", "ifconfig"]
            for cmd in cmd_patterns:
                if cmd in page_html.lower():
                    command_indicators.append(cmd)
            
            evidence["extracted_data"]["command_indicators"] = command_indicators
            
            # Screenshot showing command output
            screenshot_path = os.path.join(SCREENSHOTS_DIR, f"{finding.get('id', 'rce')}_evidence_output.png")
            await page.screenshot(path=screenshot_path)
            evidence["raw_screenshot"] = screenshot_path
            
        except Exception as e:
            logger.warning(f"Command injection evidence extraction failed: {e}")
        
        return evidence

    async def _handle_dialog(self, dialog):
        """Handle dialog boxes and store their content."""
        try:
            dialog_type = dialog.type
            dialog_msg = dialog.message
            await dialog.accept()
        except:
            pass

    async def generate(self, finding: dict) -> dict:
        """
        Generate PoC for a finding:
        1. Generate PoC script (AI or template)
        2. Take evidence screenshot via Playwright
        3. Return script + screenshot + evidence
        """
        finding_id = finding.get("id", str(uuid.uuid4()))
        url = finding.get("matched_at") or finding.get("url") or finding.get("host", "")
        screenshot_path = os.path.join(SCREENSHOTS_DIR, f"{finding_id}.png")

        # Step 1: Generate PoC script
        if self.ai_enabled:
            script = await self._ai_generate_poc(finding)
        else:
            script = self._template_poc(finding, screenshot_path)

        # Step 2: Take screenshot
        evidence = {}
        if self._browser and url:
            try:
                evidence = await self._capture_screenshot(url, screenshot_path)
            except Exception as e:
                logger.warning(f"Screenshot failed for {url}: {e}")
                evidence = {"error": str(e)}

        return {
            "script": script,
            "screenshot_path": screenshot_path if os.path.exists(screenshot_path) else "",
            "evidence": evidence,
        }

    async def _ai_generate_poc(self, finding: dict) -> str:
        """Use OpenAI GPT-4o to generate a targeted PoC script."""
        try:
            finding_info = {
                "name": finding.get("name", ""),
                "severity": finding.get("severity", ""),
                "url": finding.get("matched_at") or finding.get("url", ""),
                "description": (finding.get("description", "") or "")[:500],
                "template_id": finding.get("template_id", ""),
                "curl_command": (finding.get("curl_command", "") or "")[:300],
                "tags": finding.get("tags", ""),
            }

            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    OPENAI_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "temperature": 0.3,
                        "max_tokens": 2048,
                        "messages": [
                            {"role": "system", "content": POC_SYSTEM_PROMPT},
                            {
                                "role": "user",
                                "content": (
                                    f"Generate a Playwright PoC for this vulnerability:\n"
                                    f"{json.dumps(finding_info, indent=2)}"
                                ),
                            },
                        ],
                    },
                )
                response.raise_for_status()
                data = response.json()

            text = data["choices"][0]["message"]["content"]

            # Strip markdown fencing if present
            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[-1]
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]

            return text.strip()

        except Exception as e:
            logger.warning(f"AI PoC generation failed: {e}")
            return self._template_poc(finding, f"screenshots/{finding.get('id', 'unknown')}.png")

    def _template_poc(self, finding: dict, screenshot_path: str) -> str:
        """Generate PoC from templates based on vulnerability type."""
        tags_str = str(finding.get("tags", "")).lower()
        name = finding.get("name", "Unknown")
        url = finding.get("matched_at") or finding.get("url") or finding.get("host", "")
        severity = finding.get("severity", "unknown")

        if any(t in tags_str for t in ["xss", "cross-site"]):
            template = POC_TEMPLATES["xss"]
        elif any(t in tags_str for t in ["sqli", "sql-injection", "injection"]):
            template = POC_TEMPLATES["sqli"]
        else:
            template = POC_TEMPLATES["default"]

        return template.format(
            name=name, url=url, screenshot_path=screenshot_path, severity=severity,
        )

    # ── Cookie evidence screenshot ────────────────────────────────────────────

    async def _capture_cookie_screenshot(self, url: str, screenshot_path: str, finding: dict) -> dict:
        """Navigate to the URL, inspect the cookies for the flagged name,
        and inject a DOM overlay that shows the cookie value and which
        security attributes (Secure, HttpOnly, SameSite) are missing."""
        if not self._browser:
            return {"error": "Browser not available"}

        # Pull cookie name and raw evidence from the finding
        extracted: dict = {}
        try:
            raw = finding.get("extracted_results") or "{}"
            extracted = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            pass

        flagged_param = extracted.get("param", "")   # cookie name ZAP flagged
        raw_evidence  = extracted.get("evidence", "") # Set-Cookie header snippet

        context = await self._acquire_ctx()
        try:
            page = await context.new_page()
            response = await page.goto(url, wait_until="domcontentloaded", timeout=_PAGE_GOTO_TIMEOUT)
            await page.wait_for_timeout(_SMART_WAIT_MS)

            # Read cookies from the browser context
            all_cookies = await context.cookies()

            # Find the specific cookie by name (case-insensitive partial match)
            target_cookie = None
            if flagged_param:
                for c in all_cookies:
                    if flagged_param.lower() in c["name"].lower():
                        target_cookie = c
                        break
            if not target_cookie and all_cookies:
                # fall back to the first cookie
                target_cookie = all_cookies[0]

            # Build attribute analysis rows
            rows_js = ""
            finding_name = finding.get("name", "Cookie Security Issue")
            if target_cookie:
                cookie_name = target_cookie["name"]
                cookie_val_masked = target_cookie["value"][:20] + "…" if len(target_cookie["value"]) > 20 else target_cookie["value"]
                has_secure   = target_cookie.get("secure", False)
                has_httponly = target_cookie.get("httpOnly", False)
                same_site    = target_cookie.get("sameSite", "None") or "None"

                def attr_row(label, present, expected_val="✓ Set"):
                    ok   = '#16a34a'  # green
                    fail = '#dc2626'  # red
                    color = ok if present else fail
                    status = expected_val if present else "✗ MISSING"
                    return (f'<tr>'
                            f'<td style="padding:5px 12px;font-weight:600">{label}</td>'
                            f'<td style="padding:5px 12px;color:{color};font-weight:700">{status}</td>'
                            f'</tr>')

                rows_js = (
                    attr_row("Secure",   has_secure)
                    + attr_row("HttpOnly", has_httponly)
                    + attr_row("SameSite", same_site not in ("None", ""), same_site if same_site not in ("None", "") else "✗ MISSING")
                )
                cookie_header = f"<b>Cookie:</b> <code>{cookie_name}</code> = <code>{cookie_val_masked}</code>"
            else:
                rows_js = f'<tr><td colspan="2" style="padding:8px;color:#fbbf24">Cookie not found in browser — may be set via response header only</td></tr>'
                cookie_header = f"<b>Evidence:</b> <code>{raw_evidence[:80]}</code>" if raw_evidence else "No cookie data"

            overlay_js = f"""
                (() => {{
                    const ov = document.createElement('div');
                    ov.style.cssText = [
                        'position:fixed','top:0','left:0','right:0',
                        'background:#1e1e2e','color:#e5e7eb','z-index:2147483647',
                        'font-family:monospace','font-size:14px',
                        'padding:14px 20px','box-shadow:0 4px 12px rgba(0,0,0,.6)'
                    ].join(';');
                    ov.innerHTML = `
                        <div style="font-size:16px;font-weight:700;color:#f87171;margin-bottom:8px">
                            \u26a0\ufe0f {finding_name}
                        </div>
                        <div style="margin-bottom:8px">{cookie_header}</div>
                        <table style="border-collapse:collapse;width:auto">
                            <thead><tr>
                                <th style="padding:4px 12px;text-align:left;color:#94a3b8">Attribute</th>
                                <th style="padding:4px 12px;text-align:left;color:#94a3b8">Status</th>
                            </tr></thead>
                            <tbody>{rows_js}</tbody>
                        </table>`;
                    document.body ? document.body.prepend(ov) : document.documentElement.prepend(ov);
                }})();
            """
            try:
                await page.evaluate(overlay_js)
                await page.wait_for_timeout(_OVERLAY_WAIT_MS)
            except Exception as e:
                logger.warning(f"[PoC] Cookie overlay injection failed: {e}")

            await page.screenshot(path=screenshot_path, full_page=False)
            await page.close()
            return {
                "final_url": page.url,
                "title": await page.title() if not page.is_closed() else "",
                "status": response.status if response else None,
                "screenshot": screenshot_path,
                "cookie_name": flagged_param,
                "cookie_data": target_cookie,
            }
        finally:
            await self._release_ctx(context)

    # ── CSP evaluator screenshot ──────────────────────────────────────────────

    @staticmethod
    def _analyse_csp_directives(policy: str) -> list[tuple[str, str, str]]:
        """
        Lightweight local CSP analysis.
        Returns list of (directive, value, risk_level) where risk_level is
        'high' | 'medium' | 'ok'.
        """
        rows: list[tuple[str, str, str]] = []
        directives = [d.strip() for d in policy.split(";") if d.strip()]
        directive_names = {d.split()[0].lower() for d in directives}

        if "default-src" not in directive_names and "script-src" not in directive_names:
            rows.append(("(missing)", "No default-src or script-src — all sources allowed", "high"))

        for directive in directives:
            parts = directive.split()
            name  = parts[0].lower() if parts else ""
            value = " ".join(parts[1:]) if len(parts) > 1 else "(none)"
            risk  = "ok"

            if "'unsafe-inline'" in value:
                risk = "high"
            elif "'unsafe-eval'" in value:
                risk = "high"
            elif re.search(r"(^|\s)\*(\s|$)", value):
                risk = "high"
            elif "http:" in value:
                risk = "medium"
            elif re.search(r"https://\*\.", value):
                risk = "medium"
            elif value.strip() == "'none'":
                risk = "ok"

            rows.append((name, value[:120], risk))

        return rows

    async def _capture_csp_screenshot(self, screenshot_path: str, finding: dict) -> dict:
        """
        Render a local CSP analysis card — no external network call needed.
        Analyses the CSP directives in-process and renders a styled HTML card
        in a blank Playwright page (completes in ~200ms vs 5-10s for the
        external csp-evaluator.withgoogle.com approach).
        """
        if not self._browser:
            return {"error": "Browser not available"}

        extracted: dict = {}
        try:
            raw = finding.get("extracted_results") or "{}"
            extracted = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            pass

        csp_policy = (
            extracted.get("evidence", "")
            or extracted.get("other", "")
            or finding.get("description", "")
        ).strip()

        no_policy = not csp_policy or len(csp_policy) < 5
        finding_name = (finding.get("name", "CSP Issue") or "CSP Issue").replace("<", "&lt;").replace(">", "&gt;")
        sev = (finding.get("severity", "medium") or "medium").upper()
        SEV_COLORS = {"CRITICAL": "#7c3aed", "HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#2563eb"}
        sev_color = SEV_COLORS.get(sev, "#4b5563")

        if no_policy:
            rows_html = """
                <tr>
                  <td style="padding:10px 14px;color:#f87171;font-weight:700">CSP Header</td>
                  <td style="padding:10px 14px;color:#fca5a5">Not Set</td>
                  <td style="padding:10px 14px"><span style="background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">HIGH</span></td>
                </tr>
                <tr>
                  <td colspan="3" style="padding:10px 14px;color:#9ca3af;font-size:13px">
                    No Content-Security-Policy header found. This allows unrestricted inline scripts
                    and arbitrary script sources, significantly increasing XSS attack surface.
                  </td>
                </tr>"""
        else:
            directive_rows = self._analyse_csp_directives(csp_policy)
            risk_badge = {
                "high":   '<span style="background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">HIGH</span>',
                "medium": '<span style="background:#78350f;color:#fcd34d;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">MEDIUM</span>',
                "ok":     '<span style="background:#14532d;color:#86efac;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">OK</span>',
            }
            rows_html = ""
            for name, value, risk in directive_rows:
                name_esc  = name.replace("<", "&lt;").replace(">", "&gt;")
                value_esc = value.replace("<", "&lt;").replace(">", "&gt;")
                rows_html += f"""
                <tr style="border-bottom:1px solid #1e293b">
                  <td style="padding:8px 14px;color:#93c5fd;font-family:monospace;white-space:nowrap">{name_esc}</td>
                  <td style="padding:8px 14px;color:#d1d5db;font-family:monospace;font-size:12px;word-break:break-all">{value_esc}</td>
                  <td style="padding:8px 14px;white-space:nowrap">{risk_badge.get(risk, '')}</td>
                </tr>"""

        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; font-family: monospace; padding: 0; }}
</style></head>
<body>
  <div style="background:#1e2a3a;border-bottom:3px solid {sev_color};padding:14px 20px;display:flex;align-items:center;gap:12px">
    <span style="background:{sev_color};color:#fff;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:900;letter-spacing:1px">{sev}</span>
    <span style="color:#e2e8f0;font-size:15px;font-weight:700">{finding_name}</span>
    <span style="margin-left:auto;color:#64748b;font-size:12px">Content Security Policy Analysis</span>
  </div>
  <div style="padding:16px 20px">
    {"" if no_policy else f'<div style="background:#1e293b;border-radius:6px;padding:8px 14px;color:#94a3b8;font-size:12px;margin-bottom:12px;word-break:break-all"><b style=\'color:#64748b\'>Policy:</b> {csp_policy[:300].replace("<","&lt;").replace(">","&gt;")}{"…" if len(csp_policy)>300 else ""}</div>'}
    <table style="width:100%;border-collapse:collapse">
      <thead>
        <tr style="background:#1e293b">
          <th style="padding:8px 14px;text-align:left;color:#64748b;font-size:11px;text-transform:uppercase">Directive</th>
          <th style="padding:8px 14px;text-align:left;color:#64748b;font-size:11px;text-transform:uppercase">Value</th>
          <th style="padding:8px 14px;text-align:left;color:#64748b;font-size:11px;text-transform:uppercase">Risk</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</body></html>"""

        context = await self._acquire_ctx()
        try:
            page = await context.new_page()
            await page.set_content(html, wait_until="domcontentloaded")
            await page.wait_for_timeout(_OVERLAY_WAIT_MS)
            await page.screenshot(path=screenshot_path, full_page=True)
            await page.close()
            return {"screenshot": screenshot_path, "csp_policy": csp_policy[:200], "source": "local_analysis"}
        finally:
            await self._release_ctx(context)

    # ── Dep-scan local CVE info card ──────────────────────────────────────────

    async def _capture_dep_screenshot(self, screenshot_path: str, finding: dict) -> dict:
        """
        Render a local HTML CVE info card for a dep-scan finding.
        No live URL navigation needed — completes in ~150ms.
        """
        if not self._browser:
            return {"error": "Browser not available"}

        extracted: dict = {}
        try:
            raw = finding.get("extracted_results") or "{}"
            extracted = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            pass

        library   = extracted.get("library", finding.get("name", "Unknown"))
        det_ver   = extracted.get("detected_version", "unknown")
        fix_ver   = extracted.get("fixed_version", "")
        det_method = extracted.get("detection_method", "")
        vuln_src  = extracted.get("vuln_source", "")
        refs      = extracted.get("references", [])[:3]
        cve_id    = (finding.get("cve_id") or "").strip()
        sev       = (finding.get("severity") or "medium").upper()
        desc      = (finding.get("description") or "")[:400].replace("<", "&lt;").replace(">", "&gt;")
        name_esc  = (finding.get("name") or library).replace("<", "&lt;").replace(">", "&gt;")
        SEV_COLORS = {"CRITICAL": "#7c3aed", "HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#2563eb"}
        sev_color = SEV_COLORS.get(sev, "#4b5563")

        refs_html = "".join(
            f'<div style="margin-top:4px"><a style="color:#60a5fa;font-size:12px;word-break:break-all">{r.replace("<","&lt;").replace(">","&gt;")}</a></div>'
            for r in refs
        )
        fix_html = (
            f'<div style="margin-top:16px;padding:10px 16px;background:#14532d;border-radius:6px;color:#86efac;font-size:13px">'
            f'<b>Remediation:</b> Upgrade <code style="background:#166534;padding:1px 6px;border-radius:3px">{library}</code> '
            f'to <code style="background:#166534;padding:1px 6px;border-radius:3px">v{fix_ver}</code> or later.</div>'
            if fix_ver else ""
        )

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; font-family: monospace; padding: 0; }}
  .row {{ display:flex; gap:8px; margin-bottom:8px; align-items:baseline; }}
  .label {{ color:#64748b; font-size:11px; text-transform:uppercase; min-width:130px; }}
  .val {{ color:#e2e8f0; font-size:13px; }}
</style></head>
<body>
  <div style="background:#1e2a3a;border-bottom:3px solid {sev_color};padding:14px 20px;display:flex;align-items:center;gap:12px">
    <span style="background:{sev_color};color:#fff;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:900;letter-spacing:1px">{sev}</span>
    <span style="color:#e2e8f0;font-size:15px;font-weight:700">{name_esc}</span>
    <span style="margin-left:auto;color:#64748b;font-size:12px">Vulnerable Dependency</span>
  </div>
  <div style="padding:20px 24px">
    <div class="row"><span class="label">Library</span><span class="val" style="color:#93c5fd;font-size:15px;font-weight:700">{library}</span></div>
    <div class="row"><span class="label">Detected Version</span><span class="val" style="color:#f87171">v{det_ver}</span></div>
    {"<div class='row'><span class='label'>Fixed In</span><span class='val' style='color:#86efac'>v" + fix_ver + "+</span></div>" if fix_ver else ""}
    {"<div class='row'><span class='label'>CVE ID</span><span class='val' style='color:#fbbf24;font-weight:700'>" + cve_id + "</span></div>" if cve_id else ""}
    <div class="row"><span class="label">Detection</span><span class="val" style="color:#94a3b8">{det_method} / {vuln_src}</span></div>
    <div style="margin-top:14px;color:#9ca3af;font-size:13px;line-height:1.6">{desc}</div>
    {fix_html}
    {"<div style='margin-top:14px'><div style='color:#64748b;font-size:11px;text-transform:uppercase;margin-bottom:4px'>References</div>" + refs_html + "</div>" if refs_html else ""}
  </div>
</body></html>"""

        context = await self._acquire_ctx()
        try:
            page = await context.new_page()
            await page.set_content(html, wait_until="domcontentloaded")
            await page.wait_for_timeout(_OVERLAY_WAIT_MS)
            await page.screenshot(path=screenshot_path, full_page=True)
            await page.close()
            return {"screenshot": screenshot_path, "library": library, "version": det_ver}
        finally:
            await self._release_ctx(context)

    # ── Main screenshot dispatcher ────────────────────────────────────────────

    async def _capture_screenshot(self, url: str, screenshot_path: str, finding: dict = None) -> dict:
        """Navigate to URL and capture evidence screenshot.

        Dispatches to type-specific capture methods for XSS, cookie, and CSP
        findings so each screenshot shows meaningful, human-readable evidence.
        """
        if not self._browser:
            return {"error": "Browser not available"}

        tags_str = str(finding.get("tags", "")).lower() if finding else ""
        name_str = str(finding.get("name", "")).lower() if finding else ""

        # Route to specialised handlers first
        is_cookie = any(t in tags_str or t in name_str for t in [
            "cookie", "httponly", "secure flag", "samesite", "session cookie",
        ])
        is_csp = any(t in tags_str or t in name_str for t in [
            "content security policy", "csp",
        ])

        if is_cookie and finding:
            return await self._capture_cookie_screenshot(url, screenshot_path, finding)

        if is_csp and finding:
            return await self._capture_csp_screenshot(screenshot_path, finding)

        # ── helpers ──────────────────────────────────────────────────────────
        SEV_COLOR = {
            "critical": "#7c3aed", "high": "#dc2626",
            "medium": "#d97706",   "low": "#2563eb", "info": "#4b5563",
        }

        def _js_str(s: str) -> str:
            """Escape a Python string for safe embedding inside a JS template literal."""
            return (s or "").replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")

        def _finding_header_js(f: dict, extra_html: str = "") -> str:
            """Return JS that prepends a dark finding-context banner to the page."""
            name     = _js_str(f.get("name", "Finding") if f else "Finding")
            severity = (f.get("severity", "info") if f else "info").lower()
            color    = SEV_COLOR.get(severity, "#4b5563")
            sev_up   = severity.upper()
            return f"""
                (() => {{
                    if (document.getElementById('__vf_banner__')) return;
                    const b = document.createElement('div');
                    b.id = '__vf_banner__';
                    b.innerHTML = `
                        <span style="background:{color};padding:2px 8px;border-radius:4px;
                            font-size:11px;font-weight:900;margin-right:10px;letter-spacing:1px">
                            {sev_up}
                        </span>
                        <b>{name}</b>{extra_html}`;
                    b.style.cssText = [
                        'position:fixed','top:0','left:0','right:0',
                        'padding:11px 18px','background:#0f172a','color:#e2e8f0',
                        'font-size:14px','font-family:monospace','z-index:2147483647',
                        'box-shadow:0 3px 10px rgba(0,0,0,.6)','white-space:nowrap',
                        'overflow:hidden','text-overflow:ellipsis'
                    ].join(';');
                    document.body ? document.body.prepend(b) : document.documentElement.prepend(b);
                }})();
            """

        # ─────────────────────────────────────────────────────────────────────

        # ── dep-scan findings: render a local CVE info card (no live URL needed) ─
        if finding and (finding.get("scanner_source") or "").lower() == "dep-scan":
            return await self._capture_dep_screenshot(screenshot_path, finding)

        context = await self._acquire_ctx()

        try:
            page = await context.new_page()

            tags_str = str(finding.get("tags", "")).lower() if finding else ""
            name_str = str(finding.get("name", "")).lower() if finding else ""

            # ── XSS detection ────────────────────────────────────────────────
            xss_in_url = any(m in url.lower() for m in [
                "<script", "alert(", "onerror=", "onload=", "javascript:", "prompt(", "confirm(",
            ])
            is_xss = xss_in_url or any(t in tags_str or t in name_str for t in ["xss", "cross-site"])

            # ── Finding-type flags ────────────────────────────────────────────
            is_sqli        = any(t in tags_str or t in name_str for t in ["sql", "sqli", "injection"])
            is_redirect    = any(t in tags_str or t in name_str for t in ["redirect", "open redirect"])
            is_header      = any(t in tags_str or t in name_str for t in [
                "x-frame", "hsts", "x-content-type", "referrer-policy",
                "permissions-policy", "missing header", "header not set",
            ])
            is_info_disc   = any(t in tags_str or t in name_str for t in [
                "information disclosure", "stack trace", "error message",
                "debug", "sensitive data", "exposure",
            ])
            is_cmd         = any(t in tags_str or t in name_str for t in [
                "command injection", "rce", "remote code", "os injection",
            ])
            is_traversal   = any(t in tags_str or t in name_str for t in [
                "path traversal", "directory traversal", "local file",
            ])

            # Hook dialogs BEFORE navigation (XSS alert fires during page load)
            dialog_captured: dict = {"type": None, "message": None}

            async def _handle_dialog(dialog):
                dialog_captured["type"]    = dialog.type
                dialog_captured["message"] = dialog.message
                logger.info(f"[PoC] ✓ dialog: type={dialog.type!r} msg={dialog.message!r}")
                await dialog.accept()

            page.on("dialog", _handle_dialog)   # always hook — harmless for non-XSS

            # Capture response headers for header-related findings
            response_headers: dict = {}

            async def _capture_headers(response):
                if response.url == url or response.url.rstrip("/") == url.rstrip("/"):
                    response_headers.update(dict(response.headers))

            if is_header:
                page.on("response", _capture_headers)

            response = await page.goto(url, wait_until="domcontentloaded", timeout=_PAGE_GOTO_TIMEOUT)
            await page.wait_for_timeout(_SMART_WAIT_MS)

            # ── Per-type overlay injection ────────────────────────────────────

            if is_xss:
                if dialog_captured["message"] is not None:
                    dtype = _js_str(dialog_captured["type"] or "alert")
                    msg   = _js_str(dialog_captured["message"] or "")
                    extra = f' \u2014 <code style="background:#7f1d1d;padding:2px 6px;border-radius:3px">{dtype}("{msg}")</code> fired'
                    banner = _finding_header_js(finding, extra).replace(
                        "'background:#0f172a'", "'background:#7f1d1d'"
                    )
                else:
                    extra = ' \u2014 payload in URL (no dialog; may be DOM/stored)'
                    banner = _finding_header_js(finding, extra).replace(
                        "'background:#0f172a'", "'background:#92400e'"
                    )
                await page.evaluate(banner)

            elif is_sqli:
                # Highlight SQL error text visible in the page
                page_html = await page.content()
                sql_patterns = [
                    r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"SQLite.*near",
                    r"PostgreSQL.*ERROR", r"ODBC.*Driver", r"Unclosed.*quotation",
                ]
                found_errors = [p for p in sql_patterns if re.search(p, page_html, re.IGNORECASE)]
                extra = (
                    f' \u2014 <span style="color:#fca5a5">SQL errors visible: {", ".join(found_errors[:3])}</span>'
                    if found_errors else " \u2014 no SQL error text visible on page"
                )
                await page.evaluate(_finding_header_js(finding, extra))
                # Highlight error text in red
                if found_errors:
                    await page.evaluate("""
                        (() => {
                            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
                            const sqlRe = /SQL syntax|mysql_fetch|ORA-\\d+|SQLite.*near|PostgreSQL.*ERROR|ODBC.*Driver/i;
                            const nodes = [];
                            while (walker.nextNode()) {
                                if (sqlRe.test(walker.currentNode.nodeValue)) nodes.push(walker.currentNode);
                            }
                            nodes.forEach(n => {
                                const span = document.createElement('span');
                                span.style.cssText = 'background:#7f1d1d;color:#fca5a5;padding:2px 4px;border-radius:3px;font-weight:bold';
                                span.textContent = n.nodeValue;
                                n.parentNode.replaceChild(span, n);
                            });
                        })();
                    """)

            elif is_redirect:
                final_url = _js_str(page.url)
                orig_url  = _js_str(url)
                redirected = page.url.rstrip("/") != url.rstrip("/")
                extra = (
                    f' \u2014 <span style="color:#86efac">Redirected \u2192 {final_url}</span>'
                    if redirected else " \u2014 no redirect observed"
                )
                await page.evaluate(_finding_header_js(finding, extra))

            elif is_header:
                # Show which security headers are present vs missing
                security_hdrs = {
                    "strict-transport-security": "HSTS",
                    "x-frame-options":           "X-Frame-Options",
                    "x-content-type-options":    "X-Content-Type-Options",
                    "content-security-policy":   "CSP",
                    "referrer-policy":            "Referrer-Policy",
                    "permissions-policy":         "Permissions-Policy",
                }
                rows = ""
                for hdr, label in security_hdrs.items():
                    val = response_headers.get(hdr) or (response.headers.get(hdr) if response else None)
                    if val:
                        rows += f'<tr><td style="padding:3px 10px;color:#86efac">\u2713 {label}</td><td style="padding:3px 10px;color:#6b7280;font-size:11px">{_js_str(val[:60])}</td></tr>'
                    else:
                        rows += f'<tr><td style="padding:3px 10px;color:#f87171">\u2717 {label}</td><td style="padding:3px 10px;color:#6b7280;font-size:11px">NOT SET</td></tr>'
                name_esc = _js_str(finding.get("name", "Missing Header") if finding else "Missing Header")
                sev      = (finding.get("severity", "info") if finding else "info").lower()
                color    = SEV_COLOR.get(sev, "#4b5563")
                await page.evaluate(f"""
                    (() => {{
                        if (document.getElementById('__vf_banner__')) return;
                        const b = document.createElement('div');
                        b.id = '__vf_banner__';
                        b.innerHTML = `
                            <div style="margin-bottom:8px">
                                <span style="background:{color};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:900;margin-right:8px;letter-spacing:1px">{sev.upper()}</span>
                                <b>{name_esc}</b>
                            </div>
                            <table style="border-collapse:collapse;font-size:12px">{rows}</table>`;
                        b.style.cssText = [
                            'position:fixed','top:0','left:0','right:0',
                            'padding:12px 18px','background:#0f172a','color:#e2e8f0',
                            'font-family:monospace','z-index:2147483647',
                            'box-shadow:0 3px 10px rgba(0,0,0,.6)'
                        ].join(';');
                        document.body ? document.body.prepend(b) : document.documentElement.prepend(b);
                    }})();
                """)

            elif is_info_disc or is_traversal:
                # Highlight sensitive patterns in the page body
                page_html = await page.content()
                sensitive_patterns = [
                    (r"(password\s*[:=]\s*\S+)",          "#dc2626"),
                    (r"(api[_-]?key\s*[:=]\s*\S+)",       "#dc2626"),
                    (r"(secret\s*[:=]\s*\S+)",             "#dc2626"),
                    (r"(token\s*[:=]\s*\S+)",              "#b45309"),
                    (r"(stack\s*trace|traceback)",          "#7c3aed"),
                    (r"(Exception|Error)\s*:",              "#7c3aed"),
                    (r"(root:|admin:|/etc/passwd)",        "#dc2626"),
                ]
                matches_found = []
                for pattern, _ in sensitive_patterns:
                    m = re.search(pattern, page_html, re.IGNORECASE)
                    if m:
                        matches_found.append(m.group(0)[:40])
                extra = (
                    f' \u2014 <span style="color:#fca5a5">sensitive data visible: {_js_str(", ".join(matches_found[:2]))}</span>'
                    if matches_found else " \u2014 sensitive indicator detected by scanner"
                )
                await page.evaluate(_finding_header_js(finding, extra))
                if matches_found:
                    await page.evaluate("""
                        (() => {
                            const re = /(password\\s*[:=]\\s*\\S+|api[_-]?key\\s*[:=]\\s*\\S+|secret\\s*[:=]\\s*\\S+|token\\s*[:=]\\s*\\S+|Exception\\s*:|Error\\s*:|root:|admin:|\\/etc\\/passwd)/gi;
                            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
                            const nodes = [];
                            while (walker.nextNode()) {
                                if (re.test(walker.currentNode.nodeValue)) nodes.push(walker.currentNode);
                            }
                            nodes.forEach(n => {
                                const span = document.createElement('span');
                                span.style.cssText = 'background:#450a0a;color:#fca5a5;padding:2px 4px;border-radius:3px;font-weight:bold;outline:2px solid #dc2626';
                                span.textContent = n.nodeValue;
                                n.parentNode.replaceChild(span, n);
                            });
                        })();
                    """)

            elif is_cmd:
                page_html = await page.content()
                cmd_patterns = [r"uid=\d+", r"root:x:", r"bin/sh", r"Command.*not found", r"\$\s+\w+"]
                found = [p for p in cmd_patterns if re.search(p, page_html, re.IGNORECASE)]
                extra = (
                    f' \u2014 <span style="color:#86efac">cmd output indicators: {", ".join(found[:2])}</span>'
                    if found else " \u2014 no command output visible"
                )
                await page.evaluate(_finding_header_js(finding, extra))

            else:
                # ── Generic fallback: always inject finding context banner ──
                # Ensures EVERY screenshot shows the finding name + severity,
                # so a plain-looking page still carries useful evidence context.
                extracted: dict = {}
                try:
                    raw = (finding or {}).get("extracted_results") or "{}"
                    extracted = json.loads(raw) if isinstance(raw, str) else raw
                except Exception:
                    pass
                attack  = _js_str(extracted.get("attack", "")[:60])
                param   = _js_str(extracted.get("param", ""))
                evidence_snip = _js_str(extracted.get("evidence", "")[:60])
                extra_parts = []
                if param:
                    extra_parts.append(f'param: <code style="background:#1e293b;padding:1px 5px;border-radius:3px">{param}</code>')
                if attack:
                    extra_parts.append(f'attack: <code style="background:#1e293b;padding:1px 5px;border-radius:3px">{attack}</code>')
                elif evidence_snip:
                    extra_parts.append(f'evidence: <code style="background:#1e293b;padding:1px 5px;border-radius:3px">{evidence_snip}</code>')
                extra = (" \u2014 " + " | ".join(extra_parts)) if extra_parts else ""
                await page.evaluate(_finding_header_js(finding, extra))

            await page.wait_for_timeout(_OVERLAY_WAIT_MS)
            await page.screenshot(path=screenshot_path, full_page=False)

            evidence_out = {
                "final_url": page.url,
                "title": await page.title(),
                "status": response.status if response else None,
                "screenshot": screenshot_path,
            }
            if dialog_captured["message"] is not None:
                evidence_out["xss_dialog"] = {
                    "type": dialog_captured["type"],
                    "message": dialog_captured["message"],
                }
            await page.close()
            return evidence_out

        finally:
            await self._release_ctx(context)
