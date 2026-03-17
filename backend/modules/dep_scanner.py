"""
Dependency / SCA Scanner
========================

Detects vulnerable third-party components used by a target web application and
emits findings in the standard VulnForge finding format.

Two detection engines run in parallel:

  1. Retire.js engine  — client-side JS/CSS libraries (600+ libraries)
       • URL regex patterns on <script src> / <link href>
       • File-content regex patterns (catches bundled/self-hosted libraries)
       • SHA1 hash matching for exact version pinning
       • DOM JS global probes (e.g. jQuery.fn.jquery)

  2. Wappalyzer engine — everything else (3000+ technologies)
       • HTTP response headers  (Server, X-Powered-By, X-Generator, …)
       • HTML meta generator tags
       • HTML body patterns     (admin paths, comment strings, …)
       • Script src URL patterns
       • Cookie name patterns
       • JS global probes

CVE lookup (per detected library/version):
  Primary  → Retire.js built-in vuln data  (JS only, no API call)
  Second   → OSV.dev API                   (npm/PyPI/Go/Cargo/Maven/…)
  Fallback → NVD API v2                    (CPE-based; servers, CMS, PHP, …)

NVD API key is optional (env: NVD_API_KEY).  Without it the scanner uses the
public unauthenticated rate limit (1 req/s instead of 5 req/s).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from modules.dep_db_cache import get_retire_db, get_wappalyzer_db

logger = logging.getLogger(__name__)

# ── External API URLs ─────────────────────────────────────────────────────────

OSV_API_URL = "https://api.osv.dev/v1/query"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Ecosystem map: Wappalyzer technology name → OSV ecosystem + package name
# Only entries where OSV has reliable data are listed.
_OSV_ECOSYSTEM_MAP: dict[str, tuple[str, str]] = {
    # JS frameworks
    "React":          ("npm", "react"),
    "Vue.js":         ("npm", "vue"),
    "Angular":        ("npm", "@angular/core"),
    "AngularJS":      ("npm", "angular"),
    "Next.js":        ("npm", "next"),
    "Nuxt.js":        ("npm", "nuxt"),
    "Svelte":         ("npm", "svelte"),
    "Ember.js":       ("npm", "ember-source"),
    "Backbone.js":    ("npm", "backbone"),
    "Meteor":         ("npm", "meteor"),
    # CSS frameworks
    "Bootstrap":      ("npm", "bootstrap"),
    "Tailwind CSS":   ("npm", "tailwindcss"),
    "Foundation":     ("npm", "foundation-sites"),
    "Bulma":          ("npm", "bulma"),
    # Build / utility
    "Webpack":        ("npm", "webpack"),
    "Lodash":         ("npm", "lodash"),
    "Moment.js":      ("npm", "moment"),
    "Axios":          ("npm", "axios"),
    # Server-side Python frameworks
    "Django":         ("PyPI", "django"),
    "Flask":          ("PyPI", "flask"),
    "FastAPI":        ("PyPI", "fastapi"),
    # Server-side Ruby
    "Ruby on Rails":  ("RubyGems", "rails"),
    # Server-side PHP
    "Laravel":        ("Packagist", "laravel/framework"),
    "Symfony":        ("Packagist", "symfony/symfony"),
    # Java
    "Spring":         ("Maven", "org.springframework:spring-core"),
    # Go
    "Gin":            ("Go", "github.com/gin-gonic/gin"),
    # Node.js frameworks
    "Express":        ("npm", "express"),
    "Koa":            ("npm", "koa"),
    "Hapi":           ("npm", "hapi"),
    "Fastify":        ("npm", "fastify"),
}

# CPE prefix map for NVD lookups (technologies not in OSV)
_NVD_CPE_MAP: dict[str, str] = {
    "WordPress":  "cpe:2.3:a:wordpress:wordpress",
    "Drupal":     "cpe:2.3:a:drupal:drupal",
    "Joomla":     "cpe:2.3:a:joomla:joomla\\!",
    "Magento":    "cpe:2.3:a:magento:magento",
    "PrestaShop": "cpe:2.3:a:prestashop:prestashop",
    "Apache":     "cpe:2.3:a:apache:http_server",
    "nginx":      "cpe:2.3:a:f5:nginx",
    "IIS":        "cpe:2.3:a:microsoft:internet_information_services",
    "PHP":        "cpe:2.3:a:php:php",
    "OpenSSL":    "cpe:2.3:a:openssl:openssl",
    "Tomcat":     "cpe:2.3:a:apache:tomcat",
    "Grafana":    "cpe:2.3:a:grafana:grafana",
    "GitLab":     "cpe:2.3:a:gitlab:gitlab",
    "Jenkins":    "cpe:2.3:a:jenkins:jenkins",
}

# Wappalyzer categories that warrant CVE lookup (skip pure analytics, ads, etc.)
_VULN_CATS = {
    1,   # CMS
    2,   # Message boards
    11,  # Blog
    12,  # Database managers
    18,  # Web frameworks
    22,  # Web servers
    23,  # Cache
    25,  # Rich text editors
    26,  # JavaScript frameworks
    28,  # Programming languages
    41,  # Search engines
    59,  # JavaScript graphics
    62,  # Static site generators
    63,  # SSO & access control
    65,  # Security
    67,  # LMS
    75,  # PHP frameworks
    78,  # Containers
    79,  # Authentication
}

MAX_SCRIPT_FETCH_KB = 50    # KB per external script to fetch for content analysis
MAX_CONCURRENT_FETCHES = 8  # parallel script fetches


# ── Utility ───────────────────────────────────────────────────────────────────

def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _semver_below(version: str, below: str) -> bool:
    """
    Return True if `version` < `below` using simple numeric tuple comparison.
    Falls back to string comparison when parsing fails.
    """
    def _parse(v: str):
        try:
            return tuple(int(x) for x in re.split(r"[.\-]", v)[:4])
        except Exception:
            return (0,)
    try:
        return _parse(version) < _parse(below)
    except Exception:
        return False


def _semver_atmost(version: str, atmost: str) -> bool:
    def _parse(v: str):
        try:
            return tuple(int(x) for x in re.split(r"[.\-]", v)[:4])
        except Exception:
            return (0,)
    try:
        return _parse(version) <= _parse(atmost)
    except Exception:
        return False


def _nvd_severity(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    if cvss_score > 0:
        return "low"
    return "info"


def _retire_severity(sev: str) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low"}.get((sev or "").lower(), "medium")


# ── Retire.js engine ──────────────────────────────────────────────────────────

def _retire_match_url(retire_db: dict, script_url: str) -> list[dict]:
    """Match a script URL against Retire.js URL patterns."""
    findings = []
    for lib_name, lib_data in retire_db.items():
        extractors = lib_data.get("extractors", {})
        for pattern in extractors.get("uri", extractors.get("filename", [])):
            # Patterns may be plain strings or /regex/
            m = re.search(r"^/(.+)/(\w*)$", pattern)
            try:
                regex = re.compile(m.group(1), re.IGNORECASE) if m else re.compile(re.escape(pattern), re.IGNORECASE)
                match = regex.search(script_url)
                if match:
                    version = match.group(1) if match.lastindex and match.lastindex >= 1 else "unknown"
                    findings.append({"library": lib_name, "version": version, "method": "url"})
                    break
            except re.error:
                continue
    return findings


def _retire_match_content(retire_db: dict, content: str, content_hash: str) -> list[dict]:
    """Match script content (and its hash) against Retire.js patterns."""
    findings = []
    for lib_name, lib_data in retire_db.items():
        extractors = lib_data.get("extractors", {})

        # Hash match (fastest)
        if content_hash in (extractors.get("hashes") or {}):
            version = extractors["hashes"][content_hash]
            findings.append({"library": lib_name, "version": version, "method": "hash"})
            continue

        # File-content regex
        for pattern in extractors.get("filecontent", []):
            m = re.search(r"^/(.+)/(\w*)$", pattern)
            try:
                flags = re.IGNORECASE | (re.MULTILINE if "m" in (m.group(2) if m else "") else 0)
                regex = re.compile(m.group(1) if m else re.escape(pattern), flags)
                match = regex.search(content)
                if match:
                    version = match.group(1) if match.lastindex and match.lastindex >= 1 else "unknown"
                    findings.append({"library": lib_name, "version": version, "method": "filecontent"})
                    break
            except re.error:
                continue
    return findings


def _retire_match_dom(retire_db: dict, dom_globals: dict) -> list[dict]:
    """
    Match DOM JS global values against Retire.js func extractors.
    dom_globals = { "jQuery.fn.jquery": "1.12.4", "angular.version.full": "1.5.0", … }
    """
    findings = []
    for lib_name, lib_data in retire_db.items():
        extractors = lib_data.get("extractors", {})
        for func_expr in extractors.get("func", []):
            # func_expr is the JS expression; dom_globals has pre-evaluated results
            val = dom_globals.get(func_expr)
            if val and isinstance(val, str) and re.match(r"\d+\.\d+", val):
                findings.append({"library": lib_name, "version": val, "method": "dom_global"})
                break
    return findings


def _retire_vulns(retire_db: dict, library: str, version: str) -> list[dict]:
    """Return vulnerability records for a detected library+version from Retire.js DB."""
    lib_data = retire_db.get(library, {})
    vulns = []
    for v in lib_data.get("vulnerabilities", []):
        below    = v.get("below", "")
        above    = v.get("above", "")
        at_or_below = v.get("atOrAbove", "")

        # Check version range
        in_range = True
        if below and not _semver_below(version, below):
            in_range = False
        if above and not _semver_below(above, version):
            in_range = False
        if at_or_below and not _semver_atmost(version, at_or_below):
            in_range = False

        if in_range:
            idents = v.get("identifiers", {})
            cves   = idents.get("CVE", [])
            summary = idents.get("summary", "") or idents.get("bug", "")
            refs   = v.get("info", [])
            sev    = _retire_severity(v.get("severity", "medium"))

            if cves:
                for cve in cves:
                    vulns.append({
                        "cve_id":   cve,
                        "severity": sev,
                        "summary":  summary,
                        "fixed_in": below or "",
                        "refs":     refs,
                        "source":   "retire.js",
                    })
            else:
                # No CVE ID but still a known vulnerability
                vulns.append({
                    "cve_id":   "",
                    "severity": sev,
                    "summary":  summary or f"Known vulnerability in {library} {version}",
                    "fixed_in": below or "",
                    "refs":     refs,
                    "source":   "retire.js",
                })
    return vulns


# ── Wappalyzer engine ─────────────────────────────────────────────────────────

def _wapp_field_to_regex(field) -> list[tuple[re.Pattern, int]]:
    """
    Wappalyzer field value can be:
      - a string  "pattern\\;version:\\1"
      - a list    ["pattern1", "pattern2"]
      - a dict    { "key": "pattern" }
    Returns list of (compiled_regex, version_group_index).
    """
    patterns = []
    raw_list = field if isinstance(field, list) else [field] if isinstance(field, str) else []
    for raw in raw_list:
        if not isinstance(raw, str):
            continue
        # Split off Wappalyzer metadata tags (;version:\1  ;confidence:75  ;tag:...)
        parts = raw.split("\\;")
        pattern_str = parts[0]
        version_group = 0
        for part in parts[1:]:
            if part.startswith("version:"):
                # version:\1  → capture group 1
                m = re.search(r"\\(\d+)", part)
                if m:
                    version_group = int(m.group(1))
        if not pattern_str:
            continue
        try:
            patterns.append((re.compile(pattern_str, re.IGNORECASE), version_group))
        except re.error:
            pass
    return patterns


def _wapp_detect(wapp_db: dict, probe_data: dict) -> list[dict]:
    """
    Run Wappalyzer fingerprinting against collected page data.

    probe_data keys:
      headers   : dict[str, str]       — HTTP response headers (lowercased keys)
      html      : str                  — full page HTML
      script_urls : list[str]          — all <script src> values
      cookies   : dict[str, str]       — cookie name → value
      meta      : dict[str, str]       — meta name → content
      js_globals: dict[str, str]       — JS global → value (from page.evaluate)
    """
    detected = []
    headers     = probe_data.get("headers", {})
    html        = probe_data.get("html", "")
    script_urls = probe_data.get("script_urls", [])
    scripts_str = " ".join(script_urls)
    cookies     = probe_data.get("cookies", {})
    meta        = probe_data.get("meta", {})
    js_globals  = probe_data.get("js_globals", {})

    for tech_name, tech in wapp_db.items():
        version = ""
        matched = False

        # ── headers ──────────────────────────────────────────────────────────
        for hdr_name, hdr_pattern in (tech.get("headers") or {}).items():
            hdr_val = headers.get(hdr_name.lower(), "")
            if not hdr_val:
                continue
            for regex, vg in _wapp_field_to_regex(hdr_pattern):
                m = regex.search(hdr_val)
                if m:
                    matched = True
                    if vg and m.lastindex and vg <= m.lastindex:
                        version = m.group(vg).strip(" .")
                    break
            if matched:
                break

        # ── html body ────────────────────────────────────────────────────────
        if not matched and html:
            for regex, vg in _wapp_field_to_regex(tech.get("html", "")):
                m = regex.search(html)
                if m:
                    matched = True
                    if vg and m.lastindex and vg <= m.lastindex:
                        version = m.group(vg).strip(" .")
                    break

        # ── meta tags ─────────────────────────────────────────────────────────
        if not matched:
            for meta_name, meta_pattern in (tech.get("meta") or {}).items():
                meta_val = meta.get(meta_name.lower(), "")
                if not meta_val:
                    continue
                for regex, vg in _wapp_field_to_regex(meta_pattern):
                    m = regex.search(meta_val)
                    if m:
                        matched = True
                        if vg and m.lastindex and vg <= m.lastindex:
                            version = m.group(vg).strip(" .")
                        break
                if matched:
                    break

        # ── script src URLs ───────────────────────────────────────────────────
        if not matched:
            for regex, vg in _wapp_field_to_regex(tech.get("script", "")):
                m = regex.search(scripts_str)
                if m:
                    matched = True
                    if vg and m.lastindex and vg <= m.lastindex:
                        version = m.group(vg).strip(" .")
                    break

        # ── cookies ───────────────────────────────────────────────────────────
        if not matched:
            for cookie_name, cookie_pattern in (tech.get("cookies") or {}).items():
                cookie_val = cookies.get(cookie_name, "")
                if not cookie_val and cookie_name not in cookies:
                    continue
                for regex, vg in _wapp_field_to_regex(cookie_pattern or ".*"):
                    m = regex.search(cookie_val)
                    if m:
                        matched = True
                        if vg and m.lastindex and vg <= m.lastindex:
                            version = m.group(vg).strip(" .")
                        break
                if matched:
                    break

        # ── JS globals (requires prior page.evaluate) ─────────────────────────
        if not matched:
            for js_expr, js_pattern in (tech.get("js") or {}).items():
                js_val = js_globals.get(js_expr, "")
                if not js_val:
                    continue
                for regex, vg in _wapp_field_to_regex(js_pattern or ".*"):
                    m = regex.search(str(js_val))
                    if m:
                        matched = True
                        if vg and m.lastindex and vg <= m.lastindex:
                            version = m.group(vg).strip(" .")
                        break
                if matched:
                    break

        if matched:
            cats = tech.get("cats", [])
            detected.append({
                "library": tech_name,
                "version": version or "unknown",
                "method":  "wappalyzer",
                "cats":    cats,
                "website": tech.get("website", ""),
                "cpe":     tech.get("cpe", ""),
            })

    return detected


# ── CVE Lookup ────────────────────────────────────────────────────────────────

async def _osv_lookup(client: httpx.AsyncClient, ecosystem: str, package: str, version: str) -> list[dict]:
    """Query OSV.dev for vulnerabilities affecting package@version."""
    try:
        resp = await client.post(
            OSV_API_URL,
            json={"version": version, "package": {"name": package, "ecosystem": ecosystem}},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = []
        for vuln in data.get("vulns", []):
            # Extract CVSS score
            cvss_score = 0.0
            sev_str    = "medium"
            for sev in vuln.get("severity", []):
                if sev.get("type") in ("CVSS_V3", "CVSS_V2"):
                    try:
                        score = float(sev.get("score", 0))
                        cvss_score = score
                        sev_str = _nvd_severity(score)
                    except (ValueError, TypeError):
                        pass
                    break

            aliases = vuln.get("aliases", [])
            cve_id  = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))
            fixed_in = ""
            for aff in vuln.get("affected", []):
                for rng in aff.get("ranges", []):
                    for evt in rng.get("events", []):
                        if "fixed" in evt:
                            fixed_in = evt["fixed"]
                            break

            vulns.append({
                "cve_id":     cve_id,
                "severity":   sev_str,
                "cvss_score": cvss_score,
                "summary":    vuln.get("summary", "") or vuln.get("details", "")[:200],
                "fixed_in":   fixed_in,
                "refs":       [r.get("url", "") for r in vuln.get("references", [])[:5]],
                "source":     "osv",
            })
        return vulns
    except Exception as exc:
        logger.debug(f"[DepScan] OSV lookup failed for {package}@{version}: {exc}")
        return []


async def _nvd_lookup(client: httpx.AsyncClient, cpe_prefix: str, version: str) -> list[dict]:
    """Query NVD v2 API for CVEs matching a CPE + version."""
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    params = {
        "cpeName": f"{cpe_prefix}:{version}:*:*:*:*:*:*:*",
        "resultsPerPage": 20,
    }
    try:
        resp = await client.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = []
        for item in data.get("vulnerabilities", []):
            cve_item = item.get("cve", {})
            cve_id   = cve_item.get("id", "")
            desc     = next(
                (d["value"] for d in cve_item.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            # CVSS score
            cvss_score = 0.0
            sev_str    = "medium"
            metrics = cve_item.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                for m in metrics.get(key, []):
                    try:
                        cvss_score = float(m["cvssData"]["baseScore"])
                        sev_str = _nvd_severity(cvss_score)
                    except (KeyError, TypeError, ValueError):
                        pass
                    break
                if cvss_score:
                    break

            refs = [r["url"] for r in cve_item.get("references", [])[:5]]
            vulns.append({
                "cve_id":     cve_id,
                "severity":   sev_str,
                "cvss_score": cvss_score,
                "summary":    desc[:300],
                "fixed_in":   "",
                "refs":       refs,
                "source":     "nvd",
            })
        return vulns
    except Exception as exc:
        logger.debug(f"[DepScan] NVD lookup failed for {cpe_prefix}@{version}: {exc}")
        return []


# ── Finding builder ───────────────────────────────────────────────────────────

def _build_clean_finding(scan_id: str, target_url: str, library: str, version: str,
                         method: str, website: str = "", cats: list = None) -> dict:
    """Emit an info-severity finding for a detected-but-not-vulnerable technology."""
    extracted = {
        "library":          library,
        "detected_version": version if version != "unknown" else None,
        "fixed_version":    None,
        "detection_method": method,
        "vuln_source":      None,
        "references":       [],
        "website":          website,
        "is_clean":         True,
        "categories":       cats or [],
    }
    return {
        "id":               str(uuid.uuid4()),
        "scan_id":          scan_id,
        "template_id":      f"dep-tech-{library.lower().replace(' ', '-')}",
        "name":             f"{library}{f' {version}' if version and version != 'unknown' else ''}",
        "severity":         "info",
        "cvss_score":       None,
        "cve_id":           None,
        "description":      f"Detected technology: {library}{f' version {version}' if version and version != 'unknown' else ''}. No known vulnerabilities found.",
        "host":             urlparse(target_url).netloc,
        "url":              target_url,
        "matched_at":       target_url,
        "scanner_source":   "dep-scan",
        "vuln_type":        "Technology Detected",
        "tags":             json.dumps(["dependency", library.lower().replace(" ", "-"), "tech-stack"]),
        "reference":        website,
        "extracted_results": json.dumps(extracted),
        "status":           "open",
        "created_at":       datetime.now(timezone.utc).isoformat(),
    }


def _build_finding(scan_id: str, target_url: str, library: str, version: str,
                   vuln: dict, method: str, website: str = "") -> dict:
    cve_id  = vuln.get("cve_id", "")
    sev     = vuln.get("severity", "medium")
    summary = vuln.get("summary", f"Vulnerable dependency: {library} {version}")
    fixed   = vuln.get("fixed_in", "")
    refs    = vuln.get("refs", [])
    cvss    = vuln.get("cvss_score", 0.0)
    source  = vuln.get("source", "unknown")

    name = f"{library} {version}"
    if cve_id:
        name += f" — {cve_id}"
    elif summary:
        name += f" — {summary[:60]}"

    description = (
        f"Detected {library} version {version} which is affected by a known vulnerability. "
        + (f"{summary}. " if summary else "")
        + (f"Upgrade to {fixed} or later to remediate." if fixed else "")
    )

    extracted = {
        "library":          library,
        "detected_version": version,
        "fixed_version":    fixed,
        "detection_method": method,
        "vuln_source":      source,
        "references":       refs[:5],
        "website":          website,
    }

    return {
        "id":               str(uuid.uuid4()),
        "scan_id":          scan_id,
        "template_id":      f"dep-{library.lower().replace(' ', '-')}-{cve_id or 'known-vuln'}",
        "name":             name,
        "severity":         sev,
        "cvss_score":       cvss if cvss else None,
        "cve_id":           cve_id,
        "description":      description,
        "host":             urlparse(target_url).netloc,
        "url":              target_url,
        "matched_at":       target_url,
        "scanner_source":   "dep-scan",
        "vuln_type":        "Vulnerable Dependency",
        "tags":             json.dumps(["dependency", library.lower().replace(" ", "-"), "sca"]),
        "reference":        refs[0] if refs else "",
        "extracted_results": json.dumps(extracted),
        "status":           "open",
        "created_at":       datetime.now(timezone.utc).isoformat(),
    }


# ── Main scanner class ────────────────────────────────────────────────────────

class DepScanner:
    """
    Dependency / SCA scanner.

    Usage::

        scanner = DepScanner()
        findings = await scanner.scan(
            url="https://target.com",
            scan_id="abc123",
            auth_cookies={"session": "xxx"},   # optional
        )
    """

    def __init__(self):
        self._nvd_semaphore = asyncio.Semaphore(
            5 if os.getenv("NVD_API_KEY") else 1
        )

    # ── Page probing (Playwright) ─────────────────────────────────────────────

    async def _probe_page(self, url: str, auth_cookies: Optional[dict] = None) -> dict:
        """
        Load the target URL with Playwright and collect all fingerprinting data.
        Returns a probe_data dict consumed by the Retire.js and Wappalyzer engines.
        """
        from playwright.async_api import async_playwright

        probe: dict = {
            "headers":      {},
            "html":         "",
            "script_urls":  [],
            "link_urls":    [],
            "cookies":      {},
            "meta":         {},
            "js_globals":   {},
            "scripts_content": [],   # list of (url, content, sha1)
        }

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (compatible; VulnForge/1.0; DepScanner)",
            )
            if auth_cookies:
                parsed = urlparse(url)
                domain = parsed.netloc
                await context.add_cookies([
                    {"name": k, "value": v, "domain": domain, "path": "/"}
                    for k, v in auth_cookies.items()
                ])

            page = await context.new_page()

            # Capture response headers from the main document
            response_headers: dict = {}
            async def _capture_headers(resp):
                if resp.request.resource_type == "document" and resp.url == url:
                    response_headers.update({k.lower(): v for k, v in resp.headers.items()})
            page.on("response", _capture_headers)

            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
            except Exception as e:
                logger.warning(f"[DepScan] Page load error {url}: {e}")
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    pass

            probe["headers"] = response_headers
            probe["html"]    = (await page.content())[:500_000]

            # Collect <script src> and <link href>
            probe["script_urls"] = await page.evaluate("""
                () => Array.from(document.querySelectorAll('script[src]'))
                          .map(s => s.src)
                          .filter(s => s.startsWith('http'))
            """)
            probe["link_urls"] = await page.evaluate("""
                () => Array.from(document.querySelectorAll('link[href]'))
                          .map(l => l.href)
                          .filter(h => h.startsWith('http'))
            """)

            # Meta tags
            meta_raw = await page.evaluate("""
                () => {
                    const m = {};
                    document.querySelectorAll('meta[name],[property]').forEach(el => {
                        const k = (el.getAttribute('name') || el.getAttribute('property') || '').toLowerCase();
                        const v = el.getAttribute('content') || '';
                        if (k && v) m[k] = v;
                    });
                    return m;
                }
            """)
            probe["meta"] = meta_raw or {}

            # Cookies
            cookies_raw = await context.cookies()
            probe["cookies"] = {c["name"]: c["value"] for c in cookies_raw}

            # JS global probes (Retire.js func extractors + Wappalyzer js probes)
            js_probe_exprs = [
                # Retire.js common globals
                "jQuery && jQuery.fn && jQuery.fn.jquery",
                "typeof jQuery !== 'undefined' && jQuery.fn.jquery",
                "window.angular && window.angular.version && window.angular.version.full",
                "window.React && window.React.version",
                "window.Vue && window.Vue.version",
                "window.Backbone && window.Backbone.VERSION",
                "window._ && window._.VERSION",
                "window.moment && window.moment.version",
                "window.axios && window.axios.VERSION",
                "window.Ember && window.Ember.VERSION",
                "window.$ && window.$.fn && window.$.fn.jquery",
                # Next.js
                "window.__NEXT_DATA__ && window.__NEXT_DATA__.buildId && 'next'",
                # Bootstrap
                "window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION",
            ]

            js_globals: dict = {}
            for expr in js_probe_exprs:
                try:
                    val = await page.evaluate(f"() => {{ try {{ return String({expr} || ''); }} catch(e) {{ return ''; }} }}")
                    if val and val not in ("undefined", "null", "false", ""):
                        js_globals[expr] = val
                except Exception:
                    pass
            probe["js_globals"] = js_globals

            await browser.close()

        return probe

    # ── Fetch external scripts ────────────────────────────────────────────────

    async def _fetch_scripts(
        self,
        client: httpx.AsyncClient,
        script_urls: list[str],
    ) -> list[tuple[str, str, str]]:
        """
        Fetch external JS script bodies for content fingerprinting.
        Returns list of (url, content, sha1_hash).
        """
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)
        max_bytes = MAX_SCRIPT_FETCH_KB * 1024

        async def _fetch(url: str):
            async with semaphore:
                try:
                    resp = await client.get(url, timeout=10, follow_redirects=True)
                    content = resp.text[:max_bytes]
                    h = _sha1(resp.content[:max_bytes])
                    return url, content, h
                except Exception:
                    return url, "", ""

        results = await asyncio.gather(*[_fetch(u) for u in script_urls[:50]])
        return [(u, c, h) for u, c, h in results if c]

    # ── CVE resolution ────────────────────────────────────────────────────────

    async def _resolve_vulns(
        self,
        client: httpx.AsyncClient,
        retire_db: dict,
        library: str,
        version: str,
        method: str,
        cats: list[int],
        cpe: str,
        website: str,
    ) -> list[dict]:
        """Resolve vulnerabilities for a single detected library."""
        if version == "unknown":
            return []

        # 1. Retire.js built-in (no API call, instant)
        if method in ("url", "filecontent", "hash", "dom_global"):
            vulns = _retire_vulns(retire_db, library, version)
            if vulns:
                return vulns

        # 2. OSV.dev
        eco_pkg = _OSV_ECOSYSTEM_MAP.get(library)
        if eco_pkg:
            ecosystem, package = eco_pkg
            vulns = await _osv_lookup(client, ecosystem, package, version)
            if vulns:
                return vulns

        # 3. NVD API (CPE-based) — for servers, CMS, PHP, etc.
        cpe_prefix = _NVD_CPE_MAP.get(library) or cpe
        if cpe_prefix and version != "unknown":
            async with self._nvd_semaphore:
                if not os.getenv("NVD_API_KEY"):
                    await asyncio.sleep(1.0)   # respect 1 req/s public limit
                vulns = await _nvd_lookup(client, cpe_prefix, version)
                if vulns:
                    return vulns

        return []

    # ── Public API ────────────────────────────────────────────────────────────

    async def scan(
        self,
        url: str,
        scan_id: str,
        auth_cookies: Optional[dict] = None,
    ) -> list[dict]:
        """
        Run the full dependency scan against `url`.

        Returns a list of VulnForge finding dicts (may be empty).
        """
        logger.info(f"[DepScan] Starting dependency scan for {url}")

        # 1. Load databases (from cache — fast if already cached)
        retire_db, wapp_db = await asyncio.gather(
            get_retire_db(),
            get_wappalyzer_db(),
        )

        if not retire_db and not wapp_db:
            logger.warning("[DepScan] Both databases unavailable — skipping")
            return []

        # 2. Probe the page
        try:
            probe = await self._probe_page(url, auth_cookies=auth_cookies)
        except Exception as e:
            logger.error(f"[DepScan] Page probe failed for {url}: {e}")
            return []

        async with httpx.AsyncClient(verify=False) as client:
            # 3. Fetch external script content for content/hash analysis
            scripts_content = await self._fetch_scripts(client, probe["script_urls"])

            # 4. Fingerprint — Retire.js engine
            retire_detected: list[dict] = []
            seen_retire: set[tuple] = set()

            # URL matching
            for script_url in probe["script_urls"]:
                for m in _retire_match_url(retire_db, script_url):
                    key = (m["library"], m["version"])
                    if key not in seen_retire:
                        seen_retire.add(key)
                        retire_detected.append({**m, "script_url": script_url})

            # Content + hash matching
            for sc_url, content, sha1 in scripts_content:
                for m in _retire_match_content(retire_db, content, sha1):
                    key = (m["library"], m["version"])
                    if key not in seen_retire:
                        seen_retire.add(key)
                        retire_detected.append({**m, "script_url": sc_url})

            # DOM global matching
            for m in _retire_match_dom(retire_db, probe["js_globals"]):
                key = (m["library"], m["version"])
                if key not in seen_retire:
                    seen_retire.add(key)
                    retire_detected.append({**m, "script_url": url})

            logger.info(f"[DepScan] Retire.js: {len(retire_detected)} libraries detected")

            # 5. Fingerprint — Wappalyzer engine
            wapp_detected_raw = _wapp_detect(wapp_db, probe)
            # Filter to vulnerability-relevant categories only
            wapp_detected = [
                d for d in wapp_detected_raw
                if any(c in _VULN_CATS for c in d.get("cats", [])) or d.get("cpe")
            ]
            # Deduplicate against already-found Retire.js libraries
            retire_lib_names = {d["library"].lower() for d in retire_detected}
            wapp_detected = [d for d in wapp_detected if d["library"].lower() not in retire_lib_names]

            logger.info(
                f"[DepScan] Wappalyzer: {len(wapp_detected_raw)} technologies, "
                f"{len(wapp_detected)} eligible for CVE lookup"
            )

            # 6. CVE resolution for Retire.js findings
            all_findings: list[dict] = []
            for det in retire_detected:
                try:
                    vulns = await self._resolve_vulns(
                        client, retire_db,
                        library=det["library"],
                        version=det["version"],
                        method=det["method"],
                        cats=[],
                        cpe="",
                        website="",
                    )
                    if vulns:
                        for vuln in vulns:
                            all_findings.append(_build_finding(
                                scan_id, url, det["library"], det["version"],
                                vuln, det["method"],
                            ))
                    else:
                        # No CVEs — still record the detection
                        all_findings.append(_build_clean_finding(
                            scan_id, url, det["library"], det["version"], det["method"],
                        ))
                except Exception as e:
                    logger.warning(f"[DepScan] CVE lookup failed for {det['library']}: {e}")

            # 7. CVE resolution for Wappalyzer findings
            for det in wapp_detected:
                try:
                    vulns = await self._resolve_vulns(
                        client, retire_db,
                        library=det["library"],
                        version=det["version"],
                        method=det["method"],
                        cats=det.get("cats", []),
                        cpe=det.get("cpe", ""),
                        website=det.get("website", ""),
                    )
                    if vulns:
                        for vuln in vulns:
                            all_findings.append(_build_finding(
                                scan_id, url, det["library"], det["version"],
                                vuln, det["method"], det.get("website", ""),
                            ))
                    else:
                        # No CVEs — still record the detection
                        all_findings.append(_build_clean_finding(
                            scan_id, url, det["library"], det["version"],
                            det["method"], det.get("website", ""), det.get("cats", []),
                        ))
                except Exception as e:
                    logger.warning(f"[DepScan] CVE lookup failed for {det['library']}: {e}")

            # 7b. All Wappalyzer detections outside _VULN_CATS — record as tech stack only
            wapp_all_others = [
                d for d in wapp_detected_raw
                if not any(c in _VULN_CATS for c in d.get("cats", [])) and not d.get("cpe")
                and d["library"].lower() not in {x["library"].lower() for x in wapp_detected}
                and d["library"].lower() not in retire_lib_names
            ]
            for det in wapp_all_others:
                all_findings.append(_build_clean_finding(
                    scan_id, url, det["library"], det["version"],
                    det["method"], det.get("website", ""), det.get("cats", []),
                ))

        # Deduplicate findings by (library, cve_id)
        seen_findings: set[tuple] = set()
        unique_findings: list[dict] = []
        for f in all_findings:
            ext = json.loads(f.get("extracted_results", "{}"))
            key = (ext.get("library", ""), f.get("cve_id", ""), f.get("name", ""))
            if key not in seen_findings:
                seen_findings.add(key)
                unique_findings.append(f)

        logger.info(
            f"[DepScan] Complete — {len(unique_findings)} vulnerable dependency findings for {url}"
        )
        return unique_findings
