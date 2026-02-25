"""
Rule-Based False-Positive Filter

Applies deterministic heuristics to drop well-known scanner noise
BEFORE findings are stored.  No AI / network calls — runs in microseconds.

Rules (conservative — when in doubt, keep the finding):
  R1  ZAP self-reported false positive (confidence=false_positive)
  R2  Active injection finding on a static asset (css/js/png/…)
  R3  ZAP low-confidence informational finding (pure noise)
  R4  Injection/XSS/SQLi with empty evidence AND empty attack (ZAP artefact)
  R5  XSS where the payload is HTML-encoded in the evidence (sanitised)
  R6  Nuclei info-only detect/tech templates (exposure, not vulnerability)
  R7  Finding URL is a redirect chain only (no content)
"""

import json
import logging
import os
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

STATIC_EXTENSIONS = frozenset({
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".txt", ".xml", ".csv",
})

# Tags / vuln-type keywords that indicate an active/injection vulnerability
INJECTION_KEYWORDS = frozenset({
    "xss", "cross-site", "cross-site-scripting",
    "sqli", "sql-injection", "sql injection",
    "rce", "command-injection", "code-injection",
    "ssti", "template-injection",
    "xxe", "ssrf", "lfi", "rfi", "path-traversal",
    "idor", "open-redirect",
})

# Nuclei template prefixes / suffixes that are pure tech-detection (not exploitable)
NUCLEI_INFO_PREFIXES = ("tech-", "detect-", "fingerprint-")
NUCLEI_INFO_SUFFIXES = ("-detect", "-fingerprint", "-version", "-technology")

# ZAP confidence strings that map to false positive / very low confidence
ZAP_FP_CONFIDENCE = ("confidence-false_positive",)
ZAP_LOW_CONFIDENCE = ("confidence-low",)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_zap_fields(finding: dict) -> tuple[str, str, str]:
    """Pull (evidence, attack, param) from extracted_results JSON."""
    raw = finding.get("extracted_results")
    if not raw:
        return "", "", ""
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(data, dict):
            return "", "", ""
        return (
            (data.get("evidence") or "").strip(),
            (data.get("attack") or "").strip(),
            (data.get("param") or "").strip(),
        )
    except (json.JSONDecodeError, TypeError):
        return "", "", ""


def _is_injection_finding(tags: str, vuln_type: str, name: str) -> bool:
    combined = f"{tags} {vuln_type} {name}".lower()
    return any(kw in combined for kw in INJECTION_KEYWORDS)


def _static_ext(url: str) -> str:
    """Return the file extension of the URL path, or ''."""
    try:
        path = urlparse(url).path
        _, ext = os.path.splitext(path)
        return ext.lower()
    except Exception:
        return ""


# ── Core classifier ───────────────────────────────────────────────────────────

def is_false_positive(finding: dict) -> tuple[bool, str]:
    """
    Return (True, reason) if the finding should be dropped, else (False, "").
    All rules are conservative — any ambiguity keeps the finding.
    """
    url         = (finding.get("matched_at") or finding.get("url") or "").lower()
    matcher     = (finding.get("matcher_name") or "").lower()
    severity    = (finding.get("severity") or "info").lower()
    scanner     = (finding.get("scanner_source") or "nuclei").lower()
    template_id = (finding.get("template_id") or "").lower()
    tags        = str(finding.get("tags") or "").lower()
    vuln_type   = (finding.get("vuln_type") or "").lower()
    name        = (finding.get("name") or "").lower()

    evidence, attack, _param = _extract_zap_fields(finding)

    # ── R1: DISABLED - ZAP confidence=0 doesn't mean false positive ───────────
    # ZAP confidence=0 just means "low confidence", not that the finding is wrong.
    # Real findings like CSP headers, CSRF tokens, etc. often have confidence=0.
    # We rely on other rules (R2-R6) to identify actual false positives.
    # if any(fp in matcher for fp in ZAP_FP_CONFIDENCE):
    #     return True, "ZAP confidence=false_positive"

    # ── R2: Active injection finding on a static asset ────────────────────────
    ext = _static_ext(url)
    if ext in STATIC_EXTENSIONS and _is_injection_finding(tags, vuln_type, name):
        return True, f"Injection alert on static asset ({ext})"

    # ── R3: ZAP low-confidence informational (pure noise) ────────────────────
    if (
        scanner == "zap"
        and any(lc in matcher for lc in ZAP_LOW_CONFIDENCE)
        and severity == "info"
    ):
        return True, "ZAP low-confidence informational alert"

    # ── R4: Injection/XSS/SQLi with no evidence AND no attack (ZAP artefact) ─
    if (
        scanner == "zap"
        and _is_injection_finding(tags, vuln_type, name)
        and not evidence
        and not attack
    ):
        return True, "Injection alert with no evidence or attack payload"

    # ── R5: XSS payload HTML-encoded in evidence (payload was sanitised) ──────
    is_xss = any(k in f"{tags} {vuln_type} {name}" for k in ("xss", "cross-site"))
    if is_xss and evidence:
        encoded_patterns = ("&lt;script", "&lt;img", "&#x3c;script", "%3cscript")
        if any(p in evidence.lower() for p in encoded_patterns):
            return True, "XSS payload is HTML-encoded in server response (sanitised)"

    # ── R6: Nuclei pure tech-detect / fingerprint templates ──────────────────
    if scanner == "nuclei" and severity == "info":
        tid = template_id.split("/")[-1]  # strip directory prefix
        if any(tid.startswith(p) for p in NUCLEI_INFO_PREFIXES) or \
           any(tid.endswith(s) for s in NUCLEI_INFO_SUFFIXES):
            return True, f"Nuclei informational detect template ({template_id})"

    return False, ""


# ── Public API ────────────────────────────────────────────────────────────────

def filter_false_positives(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Apply all rules to a list of findings.

    Returns:
        (real_findings, removed_findings)

    Each removed finding gets a 'fp_reason' field explaining why it was dropped.
    """
    real: list[dict] = []
    removed: list[dict] = []

    for finding in findings:
        fp, reason = is_false_positive(finding)
        if fp:
            finding = dict(finding)          # don't mutate caller's object
            finding["fp_reason"] = reason
            removed.append(finding)
            logger.info(
                f"[FP-filter] Dropped '{finding.get('name', '?')}' "
                f"[{finding.get('severity', '?')}] — {reason}"
            )
        else:
            real.append(finding)

    if removed:
        logger.info(
            f"[FP-filter] {len(removed)} false positives removed, "
            f"{len(real)} findings retained"
        )
    return real, removed
