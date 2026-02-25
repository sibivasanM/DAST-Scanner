"""
selenium_runner.py
Executes Selenium IDE commands using WebDriver.
Maps .side command names → actual WebDriver API calls.
"""

import time
import re
import logging
from typing import Optional, Callable

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import TimeoutException, NoSuchElementException

from side_parser import SideCommand, SideTest, SideProject

logger = logging.getLogger(__name__)


def parse_locator(target: str):
    """
    Convert a Selenium IDE target string into a (By, value) tuple.
    Supports: id=, name=, css=, xpath=, linkText=, partialLinkText=
    """
    if target.startswith("id="):
        return By.ID, target[3:]
    elif target.startswith("name="):
        return By.NAME, target[5:]
    elif target.startswith("css="):
        return By.CSS_SELECTOR, target[4:]
    elif target.startswith("xpath=") or target.startswith("//") or target.startswith("(//"):
        val = target[6:] if target.startswith("xpath=") else target
        return By.XPATH, val
    elif target.startswith("linkText="):
        return By.LINK_TEXT, target[9:]
    elif target.startswith("partialLinkText="):
        return By.PARTIAL_LINK_TEXT, target[16:]
    elif target.startswith("class="):
        return By.CLASS_NAME, target[6:]
    elif target.startswith("tag="):
        return By.TAG_NAME, target[4:]
    else:
        # Try CSS as default fallback
        return By.CSS_SELECTOR, target


def create_driver(
    browser: str = "chrome",
    proxy: Optional[str] = None,
    headless: bool = False
) -> webdriver.Remote:
    """
    Create and return a configured WebDriver instance.
    Optionally route through a proxy (e.g., ZAP at localhost:8080).
    """
    if browser.lower() == "firefox":
        options = FirefoxOptions()
        if headless:
            options.add_argument("--headless")
        if proxy:
            host, port = proxy.replace("http://", "").split(":")
            options.set_preference("network.proxy.type", 1)
            options.set_preference("network.proxy.http", host)
            options.set_preference("network.proxy.http_port", int(port))
            options.set_preference("network.proxy.ssl", host)
            options.set_preference("network.proxy.ssl_port", int(port))
            options.set_preference("network.proxy.no_proxies_on", "")
        driver = webdriver.Firefox(options=options)
    else:
        options = ChromeOptions()
        if headless:
            options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        if proxy:
            options.add_argument(f"--proxy-server={proxy}")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--allow-insecure-localhost")
        driver = webdriver.Chrome(options=options)

    driver.set_window_size(1280, 800)
    return driver


class SideRunner:
    """
    Executes Selenium IDE commands from a parsed .side test.
    """

    DEFAULT_TIMEOUT = 15  # seconds

    def __init__(self, driver: webdriver.Remote, base_url: str, log_callback: Optional[Callable] = None):
        self.driver = driver
        self.base_url = base_url.rstrip("/")
        self.wait = WebDriverWait(driver, self.DEFAULT_TIMEOUT)
        self.variables = {}  # Stores variables set during test
        self.log_callback = log_callback or (lambda msg, level="info": None)

    def _log(self, msg: str, level: str = "info"):
        getattr(logger, level)(msg)
        self.log_callback(msg, level)

    def _resolve_value(self, value: str) -> str:
        """Replace ${varName} placeholders with stored variable values."""
        def replacer(match):
            var_name = match.group(1)
            return self.variables.get(var_name, match.group(0))
        return re.sub(r"\$\{(\w+)\}", replacer, value)

    def _find_element(self, target: str, timeout: int = DEFAULT_TIMEOUT):
        """Find element using the target locator string."""
        by, value = parse_locator(target)
        return WebDriverWait(self.driver, timeout).until(
            EC.presence_of_element_located((by, value))
        )

    def _find_clickable(self, target: str, timeout: int = DEFAULT_TIMEOUT):
        by, value = parse_locator(target)
        return WebDriverWait(self.driver, timeout).until(
            EC.element_to_be_clickable((by, value))
        )

    def execute_command(self, cmd: SideCommand) -> bool:
        """
        Execute a single Selenium IDE command.
        Returns True on success, False on failure.
        """
        command = cmd.command
        target = self._resolve_value(cmd.target)
        value = self._resolve_value(cmd.value)

        self._log(f"  ▶ {command} | target={target!r} | value={value!r}")

        try:
            # ── Navigation ──────────────────────────────────────────────
            if command == "open":
                url = target if target.startswith("http") else self.base_url + target
                self.driver.get(url)

            elif command == "setWindowSize":
                w, h = target.split("x")
                self.driver.set_window_size(int(w), int(h))

            # ── Clicks ───────────────────────────────────────────────────
            elif command in ("click", "clickAt"):
                self._find_clickable(target).click()

            elif command == "doubleClick":
                from selenium.webdriver.common.action_chains import ActionChains
                el = self._find_element(target)
                ActionChains(self.driver).double_click(el).perform()

            elif command == "clickAndWait":
                self._find_clickable(target).click()
                time.sleep(1)

            # ── Input ─────────────────────────────────────────────────────
            elif command in ("type", "sendKeys"):
                el = self._find_element(target)
                el.clear()
                el.send_keys(value)

            elif command == "sendKeysAndWait":
                el = self._find_element(target)
                el.clear()
                el.send_keys(value)
                time.sleep(1)

            elif command == "typeAndWait":
                el = self._find_element(target)
                el.clear()
                el.send_keys(value)
                time.sleep(1)

            elif command == "submit":
                self._find_element(target).submit()

            # ── Select / Dropdowns ────────────────────────────────────────
            elif command == "select":
                el = self._find_element(target)
                sel = Select(el)
                if value.startswith("label="):
                    sel.select_by_visible_text(value[6:])
                elif value.startswith("value="):
                    sel.select_by_value(value[6:])
                elif value.startswith("index="):
                    sel.select_by_index(int(value[6:]))
                else:
                    sel.select_by_visible_text(value)

            # ── Waits ─────────────────────────────────────────────────────
            elif command in ("waitForElementVisible", "waitForElementPresent"):
                self._find_element(target)

            elif command == "waitForElementNotVisible":
                by, val = parse_locator(target)
                WebDriverWait(self.driver, self.DEFAULT_TIMEOUT).until(
                    EC.invisibility_of_element_located((by, val))
                )

            elif command == "pause":
                ms = int(target) if target else int(value) if value else 1000
                time.sleep(ms / 1000)

            # ── Assertions (non-fatal: log warning if fails) ─────────────
            elif command in ("assertText", "verifyText"):
                el = self._find_element(target)
                assert value.lower() in el.text.lower(), \
                    f"Text assertion failed: expected {value!r} in {el.text!r}"

            elif command in ("assertElementPresent", "verifyElementPresent"):
                self._find_element(target)

            elif command in ("assertTitle", "verifyTitle"):
                assert value.lower() in self.driver.title.lower(), \
                    f"Title assertion failed: expected {value!r}, got {self.driver.title!r}"

            elif command in ("assertLocation", "verifyLocation"):
                assert value in self.driver.current_url, \
                    f"URL assertion failed: expected {value!r} in {self.driver.current_url!r}"

            # ── Variables ─────────────────────────────────────────────────
            elif command == "store":
                self.variables[value] = target

            elif command == "storeText":
                el = self._find_element(target)
                self.variables[value] = el.text

            elif command == "storeValue":
                el = self._find_element(target)
                self.variables[value] = el.get_attribute("value")

            elif command == "storeTitle":
                self.variables[value] = self.driver.title

            elif command == "storeLocation":
                self.variables[value] = self.driver.current_url

            elif command == "storeEval":
                result = self.driver.execute_script(f"return {target}")
                self.variables[value] = str(result)

            # ── JavaScript ────────────────────────────────────────────────
            elif command in ("runScript", "executeScript"):
                self.driver.execute_script(target)

            elif command == "executeAsyncScript":
                self.driver.execute_async_script(target)

            # ── Mouse ─────────────────────────────────────────────────────
            elif command == "mouseOver":
                from selenium.webdriver.common.action_chains import ActionChains
                el = self._find_element(target)
                ActionChains(self.driver).move_to_element(el).perform()

            # ── Checkboxes / Radio ─────────────────────────────────────────
            elif command == "check":
                el = self._find_element(target)
                if not el.is_selected():
                    el.click()

            elif command == "uncheck":
                el = self._find_element(target)
                if el.is_selected():
                    el.click()

            # ── Keyboard ──────────────────────────────────────────────────
            elif command == "sendKeyToElement":
                key_map = {
                    "${KEY_ENTER}": Keys.ENTER,
                    "${KEY_TAB}": Keys.TAB,
                    "${KEY_ESCAPE}": Keys.ESCAPE,
                    "${KEY_SPACE}": Keys.SPACE,
                }
                key = key_map.get(value, value)
                self._find_element(target).send_keys(key)

            # ── Alerts ────────────────────────────────────────────────────
            elif command == "acceptAlert":
                self.driver.switch_to.alert.accept()

            elif command == "dismissAlert":
                self.driver.switch_to.alert.dismiss()

            # ── Unknown / Unsupported ─────────────────────────────────────
            else:
                self._log(f"  ⚠ Unsupported command skipped: {command!r}", "warning")

            return True

        except TimeoutException:
            self._log(f"  ✗ Timeout waiting for element: {target!r}", "error")
            return False
        except AssertionError as e:
            self._log(f"  ✗ Assertion failed: {e}", "warning")
            return False
        except Exception as e:
            self._log(f"  ✗ Error executing {command!r}: {e}", "error")
            return False

    def run_test(self, test: SideTest) -> dict:
        """Run all commands in a test and return results."""
        self._log(f"\n🧪 Running test: {test.name}")
        results = []
        passed = 0
        failed = 0

        for i, cmd in enumerate(test.commands):
            success = self.execute_command(cmd)
            results.append({
                "step": i + 1,
                "command": cmd.command,
                "target": cmd.target,
                "value": cmd.value,
                "success": success
            })
            if success:
                passed += 1
            else:
                failed += 1

        self._log(f"\n  ✅ Passed: {passed}  ❌ Failed: {failed}")
        return {"test_name": test.name, "steps": results, "passed": passed, "failed": failed}
