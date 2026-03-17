"""
Finding Consolidator
====================

Groups near-duplicate findings that represent the same vulnerability class
firing across multiple URLs/parameters on the same host, then collapses them
into a single representative finding.

Why this is different from dedup.py
------------------------------------
dedup.py removes *exact* duplicates (same hash → same request, same param,
same evidence).  The consolidator handles the complementary case: the *same*
vulnerability type hitting *different* URLs / parameters on the same host.

Example:
  Before consolidation (15 individual findings):
    Reflected XSS  /search?q=      high  example.com
    Reflected XSS  /filter?tag=    high  example.com
    Reflected XSS  /profile?name=  high  example.com
    … (12 more)

  After consolidation (1 grouped finding):
    Reflected XSS  example.com  [15 instances]
      vulnerable_urls: [/search?q=, /filter?tag=, /profile?name=, …]

Group keys (tried in priority order — most specific first)
-----------------------------------------------------------
  K1  template_id  + host                  (Nuclei: exact same template)
  K2  name         + host + scanner_source (ZAP / dep-scan: same alert name)
  K3  cve_id       + host                  (dep-scan: same CVE on same host)

Threshold
---------
Only consolidate a group when it has >= MIN_GROUP_SIZE members.
Smaller groups pass through unchanged (avoids hiding a lone critical finding).

Output format
-------------
The representative finding gets these extra fields in extracted_results:
  is_consolidated_group : True
  consolidated_from     : int   — total instance count
  vulnerable_urls       : list  — matched_at / url for every member
  instance_params       : list  — param values (for ZAP param-level grouping)
  instance_attacks      : list  — attack payloads for all instances
  group_key             : str   — which key was used
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Optional

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

MIN_GROUP_SIZE = 3          # consolidate only when >= this many instances share a key
MAX_URLS_STORED = 50        # cap the vulnerable_urls list to keep extracted_results lean
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sev_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def _group_keys(finding: dict) -> list[str]:
    """
    Return candidate group keys for a finding, most-specific first.
    Only non-empty keys are returned — a finding with no template_id and no
    cve_id will still get a K2 key based on name + host + scanner_source.
    """
    host          = (finding.get("host") or "").lower().strip()
    template_id   = (finding.get("template_id") or "").strip()
    name          = (finding.get("name") or "").lower().strip()
    scanner       = (finding.get("scanner_source") or "nuclei").lower()
    cve_id        = (finding.get("cve_id") or "").strip()

    keys: list[str] = []

    # K1: exact template match (Nuclei — most precise)
    if template_id and host and scanner == "nuclei":
        keys.append(f"tpl|{template_id}|{host}")

    # K2: name + host + scanner (ZAP alerts, dep-scan without CVE)
    if name and host:
        keys.append(f"name|{name}|{host}|{scanner}")

    # K3: CVE + host (dep-scan, Nuclei CVE templates)
    if cve_id and host:
        keys.append(f"cve|{cve_id}|{host}")

    return keys


def _extract_zap_fields(finding: dict) -> tuple[str, str]:
    """Return (param, attack) from extracted_results, or ('', '')."""
    raw = finding.get("extracted_results")
    if not raw:
        return "", ""
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(data, dict):
            return data.get("param", "") or "", data.get("attack", "") or ""
    except Exception:
        pass
    return "", ""


def _best_severity(findings: list[dict]) -> str:
    """Return the highest severity seen across a group."""
    best = len(SEVERITY_ORDER) - 1
    for f in findings:
        best = min(best, _sev_rank(f.get("severity", "info")))
    return SEVERITY_ORDER[best]


def _pick_representative(findings: list[dict]) -> dict:
    """
    Choose the best representative from a group:
      1. Highest severity
      2. Among ties, prefer one with http_request (has raw evidence)
      3. Among ties, prefer one with poc_screenshot
    """
    def _score(f: dict) -> tuple:
        return (
            _sev_rank(f.get("severity", "info")),      # lower = better
            0 if f.get("http_request") else 1,
            0 if f.get("poc_screenshot") else 1,
        )
    return min(findings, key=_score)


def _merge_extracted_results(representative: dict, group: list[dict],
                              group_key: str) -> dict:
    """
    Build a merged extracted_results dict for the representative finding.
    Preserves the representative's own fields and appends group-level metadata.
    """
    base: dict = {}
    raw = representative.get("extracted_results")
    if raw:
        try:
            base = json.loads(raw) if isinstance(raw, str) else dict(raw)
            if not isinstance(base, dict):
                base = {}
        except Exception:
            base = {}

    # Collect per-instance data
    urls:    list[str] = []
    params:  list[str] = []
    attacks: list[str] = []

    for f in group:
        url = (f.get("matched_at") or f.get("url") or "").strip()
        if url and url not in urls:
            urls.append(url)
        param, attack = _extract_zap_fields(f)
        if param and param not in params:
            params.append(param)
        if attack and attack not in attacks:
            attacks.append(attack)

    base["is_consolidated_group"] = True
    base["consolidated_from"]     = len(group)
    base["vulnerable_urls"]       = urls[:MAX_URLS_STORED]
    base["group_key"]             = group_key
    if params:
        base["instance_params"]   = params[:MAX_URLS_STORED]
    if attacks:
        base["instance_attacks"]  = attacks[:MAX_URLS_STORED]

    return base


# ── Public API ────────────────────────────────────────────────────────────────

def consolidate_findings(
    findings: list[dict],
    min_group_size: int = MIN_GROUP_SIZE,
) -> tuple[list[dict], int]:
    """
    Group and consolidate similar findings.

    Parameters
    ----------
    findings      : full list of findings after dedup
    min_group_size: only consolidate groups with >= this many members

    Returns
    -------
    (consolidated_list, savings)
      consolidated_list — new finding list (may be shorter)
      savings           — how many individual findings were replaced by groups
    """
    if not findings:
        return [], 0

    # ── Step 1: assign each finding to its primary group key ─────────────────
    # A finding may qualify for multiple keys; we use the most-specific one.
    # Findings with no usable key go straight to the passthrough list.

    # key → list of finding indices
    groups:       dict[str, list[int]] = defaultdict(list)
    # finding index → assigned key (so we don't assign twice)
    assigned_key: dict[int, str]       = {}

    for idx, finding in enumerate(findings):
        keys = _group_keys(finding)
        if keys:
            # Assign to the first (most specific) key only
            groups[keys[0]].append(idx)
            assigned_key[idx] = keys[0]

    # ── Step 2: separate groups that meet the threshold from singletons ───────
    consolidated: list[dict] = []
    used_indices: set[int]   = set()
    savings = 0

    for key, indices in groups.items():
        if len(indices) < min_group_size:
            continue  # too small — let members pass through individually

        group_findings = [findings[i] for i in indices]
        rep            = _pick_representative(group_findings)
        best_sev       = _best_severity(group_findings)
        merged_ext     = _merge_extracted_results(rep, group_findings, key)

        consolidated_finding = dict(rep)
        consolidated_finding["severity"]          = best_sev
        consolidated_finding["extracted_results"] = json.dumps(merged_ext)

        # Update the name to reflect grouping
        original_name = rep.get("name", "Unknown")
        host          = (rep.get("host") or "").strip()
        count         = len(group_findings)
        consolidated_finding["name"] = f"{original_name} [{count} instances on {host}]"

        # matched_at → point to the host root so it's clear this is multi-URL
        consolidated_finding["matched_at"] = (
            rep.get("matched_at") or rep.get("url") or host
        )

        consolidated.append(consolidated_finding)
        used_indices.update(indices)
        savings += count - 1  # replaced N findings with 1

        logger.info(
            f"[Consolidator] Grouped {count} '{original_name}' findings on {host} "
            f"→ 1 consolidated finding (key={key[:60]})"
        )

    # ── Step 3: pass through findings that weren't consolidated ───────────────
    passthrough = [f for i, f in enumerate(findings) if i not in used_indices]
    result      = consolidated + passthrough

    if savings:
        logger.info(
            f"[Consolidator] {len(findings)} findings → {len(result)} "
            f"({savings} collapsed into {len(consolidated)} groups, "
            f"{len(passthrough)} passed through)"
        )
    else:
        logger.debug(f"[Consolidator] No groups met threshold ({min_group_size}) — all passed through")

    return result, savings
