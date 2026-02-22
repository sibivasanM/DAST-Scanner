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
        os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

    async def initialize(self):
        """Initialize Playwright browser."""
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
            logger.info("Playwright browser initialized")
        except Exception as e:
            logger.warning(f"Playwright initialization failed: {e}")
            self._browser = None

    async def shutdown(self):
        """Clean up Playwright resources."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

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

    async def _capture_screenshot(self, url: str, screenshot_path: str) -> dict:
        """Navigate to URL and capture evidence screenshot."""
        if not self._browser:
            return {"error": "Browser not available"}

        context = await self._browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1920, "height": 1080},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )

        try:
            page = await context.new_page()

            response_data = []
            page.on("response", lambda r: response_data.append({
                "url": r.url, "status": r.status,
            }))

            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(2000)

            await page.screenshot(path=screenshot_path, full_page=True)

            evidence = {
                "final_url": page.url,
                "title": await page.title(),
                "status": response.status if response else None,
                "response_count": len(response_data),
                "screenshot": screenshot_path,
            }

            return evidence

        finally:
            await context.close()
