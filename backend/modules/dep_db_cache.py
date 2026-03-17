"""
Dependency Scanner Database Cache

Downloads and caches:
  - Retire.js vulnerability database  (JS/CSS libraries — 600+ entries)
  - Wappalyzer technology definitions  (CMS, servers, frameworks, runtimes — 3000+ entries)

Both databases are stored in /tmp and refreshed every 24 hours so scans never
block on a network download more than once per day.
"""

import asyncio
import json
import logging
import os
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── URLs ──────────────────────────────────────────────────────────────────────

RETIRE_JS_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
)

# Wappalyzer splits its DB across multiple category files; this is the combined
# flat file exported by the community wappalyzer-core package.
WAPPALYZER_URLS = [
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/a.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/b.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/c.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/d.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/e.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/f.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/g.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/h.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/i.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/j.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/k.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/l.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/m.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/n.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/o.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/p.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/q.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/r.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/s.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/t.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/u.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/v.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/w.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/x.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/y.json",
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/z.json",
]

RETIRE_CACHE_PATH     = "/tmp/vulnforge_retire_db.json"
WAPPALYZER_CACHE_PATH = "/tmp/vulnforge_wappalyzer_db.json"
CACHE_TTL_SECONDS     = 86400  # 24 hours


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cache_valid(path: str) -> bool:
    """Return True if the cached file exists and is younger than TTL."""
    try:
        return os.path.exists(path) and (time.time() - os.path.getmtime(path)) < CACHE_TTL_SECONDS
    except OSError:
        return False


async def _fetch_json(client: httpx.AsyncClient, url: str) -> Optional[dict]:
    try:
        resp = await client.get(url, timeout=30, follow_redirects=True)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(f"[DepDB] Failed to fetch {url}: {exc}")
        return None


# ── Retire.js ─────────────────────────────────────────────────────────────────

async def get_retire_db() -> dict:
    """
    Return the Retire.js vulnerability database as a dict.

    Schema (simplified):
      {
        "jquery": {
          "extractors": {
            "func": ["jQuery.fn.jquery"],         # JS globals to eval
            "filename": ["/jquery-([0-9.]+)/"],   # URL regex → group 1 = version
            "filecontent": ["/jQuery v([0-9.]+)/"],
            "hashes": { "<sha1>": "<version>" }
          },
          "vulnerabilities": [
            {
              "below": "3.4.0",
              "severity": "medium",
              "identifiers": { "CVE": ["CVE-2019-11358"], "summary": "..." },
              "info": ["https://..."]
            }
          ]
        },
        ...
      }
    """
    if _cache_valid(RETIRE_CACHE_PATH):
        try:
            with open(RETIRE_CACHE_PATH) as f:
                return json.load(f)
        except Exception:
            pass

    logger.info("[DepDB] Downloading Retire.js database…")
    async with httpx.AsyncClient() as client:
        data = await _fetch_json(client, RETIRE_JS_URL)

    if data:
        try:
            with open(RETIRE_CACHE_PATH, "w") as f:
                json.dump(data, f)
            logger.info(f"[DepDB] Retire.js DB cached ({len(data)} entries)")
        except Exception as e:
            logger.warning(f"[DepDB] Could not write Retire.js cache: {e}")
        return data

    # If network fails, try stale cache
    if os.path.exists(RETIRE_CACHE_PATH):
        logger.warning("[DepDB] Using stale Retire.js cache (network unavailable)")
        with open(RETIRE_CACHE_PATH) as f:
            return json.load(f)

    logger.error("[DepDB] Retire.js DB unavailable — JS dependency scanning disabled")
    return {}


# ── Wappalyzer ────────────────────────────────────────────────────────────────

async def get_wappalyzer_db() -> dict:
    """
    Return a merged Wappalyzer technology definitions dict.

    Each entry:
      {
        "WordPress": {
          "cats": [1],
          "headers": { "X-Powered-By": "WordPress" },
          "html": "<link[^>]+/wp-content/",
          "meta": { "generator": "WordPress ?([\\d.]+)" },
          "url": "/wp-content/",
          "website": "https://wordpress.org",
          "cpe": "cpe:2.3:a:wordpress:wordpress"   (not always present)
        },
        ...
      }

    Detection fields used by dep_scanner:
      headers, html, meta, script (URL pattern), url, cookies, js (global eval)
    """
    if _cache_valid(WAPPALYZER_CACHE_PATH):
        try:
            with open(WAPPALYZER_CACHE_PATH) as f:
                return json.load(f)
        except Exception:
            pass

    logger.info(f"[DepDB] Downloading Wappalyzer DB ({len(WAPPALYZER_URLS)} files)…")
    merged: dict = {}

    async with httpx.AsyncClient() as client:
        tasks = [_fetch_json(client, url) for url in WAPPALYZER_URLS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, dict):
            merged.update(result)

    if merged:
        try:
            with open(WAPPALYZER_CACHE_PATH, "w") as f:
                json.dump(merged, f)
            logger.info(f"[DepDB] Wappalyzer DB cached ({len(merged)} technologies)")
        except Exception as e:
            logger.warning(f"[DepDB] Could not write Wappalyzer cache: {e}")
        return merged

    if os.path.exists(WAPPALYZER_CACHE_PATH):
        logger.warning("[DepDB] Using stale Wappalyzer cache (network unavailable)")
        with open(WAPPALYZER_CACHE_PATH) as f:
            return json.load(f)

    logger.error("[DepDB] Wappalyzer DB unavailable — tech fingerprinting disabled")
    return {}


# ── Combined pre-fetch ────────────────────────────────────────────────────────

async def prefetch_databases() -> tuple[dict, dict]:
    """Fetch both databases concurrently. Safe to call at startup."""
    retire_db, wappalyzer_db = await asyncio.gather(
        get_retire_db(),
        get_wappalyzer_db(),
        return_exceptions=True,
    )
    if isinstance(retire_db, Exception):
        logger.error(f"[DepDB] Retire.js fetch failed: {retire_db}")
        retire_db = {}
    if isinstance(wappalyzer_db, Exception):
        logger.error(f"[DepDB] Wappalyzer fetch failed: {wappalyzer_db}")
        wappalyzer_db = {}
    return retire_db, wappalyzer_db
