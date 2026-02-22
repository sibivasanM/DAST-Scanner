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
        Also groups similar findings under a parent finding.

        Returns unique findings with grouped instances consolidated.
        """
        unique = []
        scan_hashes = set()
        findings_by_fuzzy = {}  # Group by fuzzy hash for consolidation

        for finding in findings:
            # Level 1: Exact match within this scan
            exact_hash = self._exact_hash(finding)
            if exact_hash in scan_hashes:
                logger.debug(f"Dedup L1 (exact): {finding.get('name')}")
                continue

            # Level 2: Fuzzy match (normalized URL) - for grouping
            fuzzy_hash = self._fuzzy_hash(finding)
            if fuzzy_hash not in findings_by_fuzzy:
                findings_by_fuzzy[fuzzy_hash] = []
            findings_by_fuzzy[fuzzy_hash].append(finding)

            # Level 3: Cross-scan dedup
            cross_hash = self._cross_scan_hash(finding)
            if cross_hash in self._cross_scan_hashes:
                logger.debug(f"Dedup L3 (cross-scan): {finding.get('name')}")
                # Still add to fuzzy grouping for consolidation
                continue

            # Mark as seen
            scan_hashes.add(exact_hash)
            scan_hashes.add(fuzzy_hash)
            self._cross_scan_hashes.add(cross_hash)
        
        # Now consolidate grouped findings
        processed_fuzzy_hashes = set()
        for fuzzy_hash, similar_findings in findings_by_fuzzy.items():
            if fuzzy_hash in processed_fuzzy_hashes:
                continue
            
            if len(similar_findings) > 1:
                # Group these similar findings under one parent finding
                parent = self._consolidate_findings(similar_findings)
                unique.append(parent)
                processed_fuzzy_hashes.add(fuzzy_hash)
            elif len(similar_findings) == 1 and fuzzy_hash not in self._cross_scan_hashes:
                # Single finding in group
                finding = similar_findings[0]
                finding["dedup_hash"] = self._exact_hash(finding)
                unique.append(finding)
                processed_fuzzy_hashes.add(fuzzy_hash)

        deduped = len(findings) - len(unique)
        if deduped > 0:
            logger.info(
                f"Deduplicated {deduped}/{len(findings)} findings "
                f"({len(unique)} unique/grouped)"
            )

        return unique

    def _consolidate_findings(self, similar_findings: list[dict]) -> dict:
        """
        Consolidate multiple similar findings into one grouped finding.
        Stores all URLs, payloads, and steps together.
        """
        if not similar_findings:
            return {}
        
        # Use first finding as base
        parent = similar_findings[0].copy()
        
        # Consolidate data from all similar findings
        all_urls = []
        all_payloads = []
        all_matched_at = []
        all_extracted_results = []
        
        for finding in similar_findings:
            # Collect URLs
            if finding.get("url"):
                all_urls.append(finding["url"])
            if finding.get("matched_at"):
                all_matched_at.append(finding["matched_at"])
            
            # Collect payloads from curl commands
            curl = finding.get("curl_command", "")
            if curl:
                all_payloads.append(curl)
            
            # Collect extracted results
            if finding.get("extracted_results"):
                try:
                    import json
                    extracted = json.loads(finding["extracted_results"]) if isinstance(finding["extracted_results"], str) else finding["extracted_results"]
                    all_extracted_results.append(extracted)
                except:
                    pass
        
        # Store consolidated data
        parent["vulnerable_urls"] = list(set(all_urls + all_matched_at))[:10]  # Top 10 unique URLs
        parent["payloads"] = list(set(all_payloads))[:5]  # Top 5 unique payloads
        parent["consolidated_findings_count"] = len(similar_findings)
        
        # Consolidate extracted results (for steps to reproduce)
        if all_extracted_results:
            try:
                import json
                parent["extracted_results"] = json.dumps({
                    "consolidated_from": len(similar_findings),
                    "findings": all_extracted_results,
                    "steps_to_reproduce": all_extracted_results[0].get("steps_to_reproduce") if all_extracted_results else {}
                })
            except:
                pass
        
        parent["dedup_hash"] = self._fuzzy_hash(parent)
        parent["is_consolidated_group"] = True
        
        logger.info(f"Consolidated {len(similar_findings)} similar findings: {parent.get('name')}")
        
        return parent

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
