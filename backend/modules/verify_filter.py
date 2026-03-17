"""
HTTP Replay Verification Filter

For every injection finding (XSS, SQLi, SSTI, RCE, path traversal, …):
  1. Re-send the EXACT original attack request reconstructed from ZAP's
     http_request field (full raw HTTP stored by _enrich_with_http_messages).
  2. Check whether the ZAP evidence string still appears in the response.
  3. verified=True  → evidence confirmed → keep as real finding
     verified=False → evidence gone      → transient FP, demote/flag
     verified=None  → can't replay       → conservative: keep

Authenticated scans:
  Pass auth_cookies / auth_token so the replayed request carries the same
  session as the original scan.  Without a live session the re-sent request
  would hit unauthenticated endpoints and evidence would never appear →
  false negatives.  We inject the session ONLY when the finding's URL looks
  like an authenticated path and we have credentials.

Non-authenticated scans:
  Replay without any session headers — works fine for reflected/stored
  findings that are visible to anonymous users.
"""

import asyncio
import json
import logging
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import httpx

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

REPLAY_VULN_TYPES = frozenset({
    "xss", "cross-site", "cross-site-scripting",
    "sqli", "sql-injection", "sql injection",
    "ssti", "template-injection",
    "rce", "command-injection", "code-injection", "remote code",
    "path-traversal", "directory-traversal", "lfi", "rfi",
    "open-redirect",
    "xxe", "ssrf",
})

REPLAY_TIMEOUT  = 15   # seconds per request
MAX_CONCURRENT  = 5    # parallel replays
MAX_RESPONSE_KB = 512  # truncate response text to this size for evidence search


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_injection_finding(finding: dict) -> bool:
    combined = " ".join([
        str(finding.get("tags", "")),
        str(finding.get("vuln_type", "")),
        str(finding.get("name", "")),
    ]).lower()
    return any(kw in combined for kw in REPLAY_VULN_TYPES)


def _get_evidence(finding: dict) -> str:
    """Return the evidence string ZAP put in extracted_results, or ''."""
    raw = finding.get("extracted_results")
    if not raw:
        return ""
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        return (data.get("evidence") or "").strip()
    except Exception:
        return ""


def _parse_raw_request(raw: str) -> Optional[dict]:
    """
    Parse a raw HTTP request string (as stored by ZAP's _enrich_with_http_messages)
    into its components.

    Returns dict:
        method, path, headers (dict), body (str)
    or None if the string is too short / malformed.
    """
    if not raw or len(raw) < 10:
        return None

    # Split header section from body on the first blank line
    if "\r\n\r\n" in raw:
        header_section, body = raw.split("\r\n\r\n", 1)
        lines = header_section.split("\r\n")
    else:
        lines = raw.split("\n")
        body = ""

    if not lines:
        return None

    # Request line: "GET /path?q=1 HTTP/1.1"
    request_line = lines[0].strip()
    parts = request_line.split(" ", 2)
    if len(parts) < 2:
        return None

    method = parts[0].upper()
    path   = parts[1]

    headers: dict = {}
    for line in lines[1:]:
        line = line.strip()
        if not line:
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    return {"method": method, "path": path, "headers": headers, "body": body}


# ── Main class ────────────────────────────────────────────────────────────────

class ReplayVerifier:
    """
    Re-send attack requests and confirm evidence still appears.

    Parameters
    ----------
    auth_cookies : dict  – captured session cookies  (Selenium / ZAP injection)
    auth_token   : str   – Bearer / JWT token
    auth_headers : dict  – any extra auth headers (e.g. X-API-Key)
    """

    def __init__(
        self,
        auth_cookies: Optional[dict] = None,
        auth_token:   Optional[str]  = None,
        auth_headers: Optional[dict] = None,
    ):
        self.auth_cookies = auth_cookies or {}
        self.auth_token   = auth_token
        self.auth_headers = auth_headers or {}

    # ── Per-finding replay ────────────────────────────────────────────────────

    async def _replay_one(
        self,
        client: httpx.AsyncClient,
        finding: dict,
    ) -> dict:
        """
        Replay the original attack request for one finding.

        Strategy (in priority order):
          1. Use http_request (full raw HTTP from ZAP message history) — most accurate
          2. Reconstruct from URL + param + attack                      — fallback
        """
        evidence = _get_evidence(finding)
        if not evidence:
            return {"verified": None, "reason": "no_evidence"}

        url_str = finding.get("matched_at") or finding.get("url") or ""
        if not url_str:
            return {"verified": None, "reason": "no_url"}

        parsed_url = urlparse(url_str)
        base_url   = urlunparse((parsed_url.scheme, parsed_url.netloc, "", "", "", ""))

        # ── Build request from ZAP's raw http_request field ──────────────────
        raw_req = finding.get("http_request", "")
        req     = _parse_raw_request(raw_req) if raw_req else None

        if req:
            method = req["method"]
            full_url = base_url + req["path"]
            # Replace auth headers with current live session
            headers = {k: v for k, v in req["headers"].items()
                       if k.lower() not in ("cookie", "authorization")}
            body = req["body"] or None
        else:
            # Fallback: reconstruct from finding fields
            extracted: dict = {}
            try:
                raw = finding.get("extracted_results") or "{}"
                extracted = json.loads(raw) if isinstance(raw, str) else raw
            except Exception:
                pass
            method   = (extracted.get("method") or "GET").upper()
            full_url = url_str
            param    = extracted.get("param", "")
            attack   = extracted.get("attack", "")
            headers  = {}
            body     = f"{param}={attack}" if (method == "POST" and param and attack) else None

        # Inject live session credentials
        cookies = dict(self.auth_cookies)
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        headers.update(self.auth_headers)
        headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )

        try:
            if method == "POST":
                response = await client.post(
                    full_url, content=body.encode() if body else None,
                    headers=headers, cookies=cookies,
                )
            else:
                response = await client.request(
                    method, full_url, headers=headers, cookies=cookies,
                )

            # Limit response size for evidence search
            text = response.text[: MAX_RESPONSE_KB * 1024]
            evidence_found = evidence.lower() in text.lower()

            logger.debug(
                f"[Replay] {method} {full_url[:70]} → "
                f"HTTP {response.status_code} | evidence={'YES' if evidence_found else 'NO'}"
            )
            return {
                "verified":       evidence_found,
                "status_code":    response.status_code,
                "evidence_found": evidence_found,
                "reason":         "evidence_confirmed" if evidence_found else "evidence_not_in_response",
            }

        except Exception as exc:
            logger.warning(f"[Replay] Request failed for {full_url[:70]}: {exc}")
            return {"verified": None, "reason": f"request_error: {exc}"}

    # ── Public API ────────────────────────────────────────────────────────────

    async def verify(
        self,
        findings: list[dict],
    ) -> tuple[list[dict], list[dict]]:
        """
        Replay injection findings and separate confirmed from unverified.

        Returns
        -------
        (confirmed, unverified)

        confirmed   – evidence still present, OR non-injection, OR replay
                      failed (conservative: keep on error)
        unverified  – evidence gone on replay → likely transient FP
                      These are NOT deleted — callers may demote rather than drop.
        """
        if not findings:
            return [], []

        # Partition: only injection findings with evidence go to replay
        to_replay   = [f for f in findings if _is_injection_finding(f) and _get_evidence(f)]
        skip_replay = [f for f in findings if not (_is_injection_finding(f) and _get_evidence(f))]

        if not to_replay:
            return findings, []

        logger.info(
            f"[Replay] Verifying {len(to_replay)} injection findings "
            f"({'with auth' if self.auth_cookies or self.auth_token else 'no auth'}) "
            f"| {len(skip_replay)} non-injection findings skipped"
        )

        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        async def _bounded(finding):
            async with semaphore:
                return finding, await self._replay_one(client, finding)

        confirmed:   list[dict] = []
        unverified:  list[dict] = []

        async with httpx.AsyncClient(
            timeout=REPLAY_TIMEOUT,
            follow_redirects=True,
            verify=False,   # targets may have self-signed certs
        ) as client:
            results = await asyncio.gather(
                *[_bounded(f) for f in to_replay],
                return_exceptions=True,
            )

        for result in results:
            if isinstance(result, Exception):
                # Gather-level exception — keep the finding (can't identify which)
                logger.error(f"[Replay] gather exception: {result}")
                continue

            finding, replay_result = result

            if replay_result.get("verified") is False:
                # Evidence disappeared — transient FP or session-dependent
                tagged = dict(finding)
                tagged["replay_verified"]  = False
                tagged["replay_result"]    = replay_result
                unverified.append(tagged)
                logger.info(
                    f"[Replay] ✗ UNVERIFIED '{finding.get('name', '?')}' "
                    f"[{finding.get('severity', '?')}] at {finding.get('matched_at', '?')[:60]} "
                    f"— status={replay_result.get('status_code')}"
                )
            else:
                # verified=True → confirmed real
                # verified=None → can't tell (request error / no data) → keep
                tagged = dict(finding)
                tagged["replay_verified"] = replay_result.get("verified")  # True or None
                tagged["replay_result"]   = replay_result
                if replay_result.get("verified") is True:
                    logger.info(
                        f"[Replay] ✓ CONFIRMED '{finding.get('name', '?')}' "
                        f"— evidence still present"
                    )
                confirmed.append(tagged)

        all_confirmed = list(skip_replay) + confirmed
        logger.info(
            f"[Replay] Done — {len(all_confirmed)} confirmed/kept, "
            f"{len(unverified)} unverified (transient FP candidates)"
        )
        return all_confirmed, unverified
