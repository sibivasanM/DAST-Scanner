"""
PoC Generator — Uses Playwright to generate proof-of-concept exploits
and evidence screenshots for each vulnerability finding.

Uses OpenAI GPT-4o to generate intelligent, finding-specific PoC scripts.
"""

import asyncio
import json
import logging
import os
import uuid
from typing import Optional

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
