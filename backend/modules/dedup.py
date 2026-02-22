"""
Deduplication Engine — Content-aware deduplication of vulnerability findings.

Uses multi-level hashing:
  Level 1: Exact match (template_id + host + matched_at)
  Level 2: Fuzzy match (template_id + host + normalized path)
  Level 3: Cross-scan (template_id + host, across all scans)

Findings are only stored once per unique vulnerability instance.
"""

import hashlib
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)


class DeduplicationEngine:
    """Content-aware deduplication for vulnerability findings."""

    def __init__(self):
        self._seen_hashes: set[str] = set()
        self._cross_scan_hashes: set[str] = set()

    def deduplicate(self, findings: list[dict], scan_id: str) -> list[dict]:
        """
        Remove duplicate findings using multi-level deduplication.

        Returns only unique findings not seen in this scan or previous scans.
        """
        unique = []
        scan_hashes = set()

        for finding in findings:
            # Level 1: Exact match within this scan
            exact_hash = self._exact_hash(finding)
            if exact_hash in scan_hashes:
                logger.debug(f"Dedup L1 (exact): {finding.get('name')}")
                continue

            # Level 2: Fuzzy match (normalized URL)
            fuzzy_hash = self._fuzzy_hash(finding)
            if fuzzy_hash in scan_hashes:
                logger.debug(f"Dedup L2 (fuzzy): {finding.get('name')}")
                continue

            # Level 3: Cross-scan dedup
            cross_hash = self._cross_scan_hash(finding)
            if cross_hash in self._cross_scan_hashes:
                logger.debug(f"Dedup L3 (cross-scan): {finding.get('name')}")
                continue

            # New unique finding
            finding["dedup_hash"] = exact_hash
            scan_hashes.add(exact_hash)
            scan_hashes.add(fuzzy_hash)
            self._cross_scan_hashes.add(cross_hash)
            unique.append(finding)

        deduped = len(findings) - len(unique)
        if deduped > 0:
            logger.info(
                f"Deduplicated {deduped}/{len(findings)} findings "
                f"({len(unique)} unique)"
            )

        return unique

    def _exact_hash(self, finding: dict) -> str:
        """Hash: template_id + host + exact matched_at URL."""
        key = "|".join([
            finding.get("template_id", ""),
            finding.get("host", ""),
            finding.get("matched_at", ""),
            finding.get("matcher_name", ""),
        ])
        return hashlib.sha256(key.encode()).hexdigest()

    def _fuzzy_hash(self, finding: dict) -> str:
        """Hash: template_id + host + normalized URL path (ignoring params)."""
        url = finding.get("matched_at", finding.get("url", ""))
        normalized = self._normalize_url(url)
        key = "|".join([
            finding.get("template_id", ""),
            finding.get("host", ""),
            normalized,
        ])
        return hashlib.sha256(key.encode()).hexdigest()

    def _cross_scan_hash(self, finding: dict) -> str:
        """Hash: template_id + host (broad match across scans)."""
        key = "|".join([
            finding.get("template_id", ""),
            finding.get("host", ""),
            finding.get("severity", ""),
        ])
        return hashlib.sha256(key.encode()).hexdigest()

    def _normalize_url(self, url: str) -> str:
        """
        Normalize a URL for fuzzy matching:
        - Strip query parameter VALUES (keep keys)
        - Replace numeric path segments with {N}
        - Lowercase scheme and host
        - Remove fragments
        - Sort query keys
        """
        if not url:
            return ""

        try:
            parsed = urlparse(url)

            # Normalize path: replace numeric segments
            path = re.sub(r"/\d+(/|$)", "/{N}\\1", parsed.path)
            # Also replace UUIDs
            path = re.sub(
                r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                "/{UUID}",
                path,
                flags=re.IGNORECASE,
            )

            # Normalize query: keep keys, replace values
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                normalized_params = {k: "{V}" for k in sorted(params.keys())}
                query = urlencode(normalized_params)
            else:
                query = ""

            return f"{parsed.scheme}://{parsed.netloc.lower()}{path}?{query}" if query else \
                   f"{parsed.scheme}://{parsed.netloc.lower()}{path}"

        except Exception:
            return url.lower()

    def reset(self):
        """Reset all dedup caches (for testing)."""
        self._seen_hashes.clear()
        self._cross_scan_hashes.clear()
