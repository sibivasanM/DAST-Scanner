"""
AI-Assisted False-Positive Scorer

Pipes low/medium confidence ZAP findings through GPT-4o for a focused
FP verdict BEFORE findings are persisted to the database.

Design decisions:
  - Only targets ZAP findings with confidence-low or confidence-medium.
    High/confirmed confidence and all Nuclei findings are passed through untouched.
  - Uses a dedicated, concise prompt (not the full analysis prompt) to keep
    latency and cost low.
  - Batches up to BATCH_SIZE findings per API call.
  - Falls back gracefully (keep all findings) if the API is unavailable.
  - Adds 'ai_fp_reason' to removed findings for audit logging.
"""

import json
import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

# Confidence levels that trigger AI review
REVIEW_CONFIDENCE_LEVELS = {"confidence-low", "confidence-medium"}

# Max findings per GPT-4o call (keep prompt tokens manageable)
BATCH_SIZE = 20

# Model — same as ai_analyzer for consistency
DEFAULT_MODEL = "gpt-4o"

# ── Prompts ───────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a DAST false-positive triage expert embedded in an automated security scanner.
Your ONLY job is to decide, for each finding, whether it is a genuine vulnerability or a false positive.

Rules:
- Be conservative: when genuinely uncertain, return verdict "real".
- A finding is a false positive if the evidence clearly shows the application handled the payload safely
  (e.g. the payload is reflected but HTML-encoded, the response is a generic error unrelated to the input,
  the alert fired on a static resource, or the scanner triggered on a URL that returned 3xx/404).
- A finding is real if there is any credible evidence of exploitation (injected payload echoed unencoded,
  error message reveals internals, suspicious response diff, etc.).

You MUST respond with ONLY a valid JSON array — no markdown, no explanation outside JSON.

Response schema (one object per input finding):
[
  {
    "id": "<finding id>",
    "verdict": "real" | "fp",
    "reason": "<one concise sentence>"
  }
]"""


def _build_user_message(findings: list[dict]) -> str:
    """Serialize findings into a compact representation for the prompt."""
    items = []
    for f in findings:
        extracted = {}
        raw = f.get("extracted_results")
        if raw:
            try:
                extracted = json.loads(raw) if isinstance(raw, str) else raw
            except (json.JSONDecodeError, TypeError):
                pass

        items.append({
            "id": f.get("id", ""),
            "name": f.get("name", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("matcher_name", ""),
            "url": f.get("matched_at") or f.get("url", ""),
            "param": extracted.get("param", ""),
            "attack": (extracted.get("attack") or "")[:200],
            "evidence": (extracted.get("evidence") or "")[:300],
            "description": (f.get("description") or "")[:200],
            "method": extracted.get("method", ""),
            "http_status": extracted.get("http_status", ""),
        })

    return (
        f"Triage these {len(items)} ZAP findings and return a verdict for each:\n\n"
        + json.dumps(items, indent=2)
    )


# ── Core scorer ───────────────────────────────────────────────────────────────

class AIFalsePositiveScorer:
    """GPT-4o powered FP verdict engine for low/medium confidence ZAP findings."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
        self.enabled = bool(self.api_key)
        if not self.enabled:
            logger.warning(
                "[AI-FP] OPENAI_API_KEY not set — AI FP scoring disabled, "
                "all low/medium confidence findings will be kept."
            )

    def _needs_review(self, finding: dict) -> bool:
        """Return True if this finding should be sent to the AI scorer."""
        if (finding.get("scanner_source") or "").lower() != "zap":
            return False
        confidence = (finding.get("matcher_name") or "").lower()
        return confidence in REVIEW_CONFIDENCE_LEVELS

    async def _call_api(self, findings: list[dict]) -> list[dict]:
        """Call GPT-4o and return parsed verdict list."""
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                OPENAI_API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "temperature": 0.1,          # low temp for consistent verdicts
                    "max_tokens": 2048,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": _build_user_message(findings)},
                    ],
                },
            )
            response.raise_for_status()
            data = response.json()

        text = data["choices"][0]["message"]["content"].strip()

        # Strip accidental markdown fencing
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        parsed = json.loads(text)
        # GPT-4o with json_object format sometimes wraps array in a key
        if isinstance(parsed, dict):
            for val in parsed.values():
                if isinstance(val, list):
                    return val
            return []
        return parsed  # already a list

    async def score(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """
        Score findings and separate real from AI-detected false positives.

        Returns:
            (real_findings, ai_fp_findings)

        Findings that don't need review (Nuclei, high/confirmed confidence)
        are passed straight through to real_findings without an API call.
        """
        if not findings:
            return [], []

        # Split findings into those that need AI review and those that don't
        to_review = [f for f in findings if self._needs_review(f)]
        skip_review = [f for f in findings if not self._needs_review(f)]

        if not to_review or not self.enabled:
            if to_review and not self.enabled:
                logger.info(
                    f"[AI-FP] Skipping {len(to_review)} findings — API key not set"
                )
            return findings, []

        logger.info(
            f"[AI-FP] Sending {len(to_review)} low/medium confidence ZAP findings "
            f"for FP review ({len(skip_review)} findings skipped — not eligible)"
        )

        # Build a verdict map from batched API calls
        verdict_map: dict[str, dict] = {}
        for i in range(0, len(to_review), BATCH_SIZE):
            batch = to_review[i: i + BATCH_SIZE]
            try:
                verdicts = await self._call_api(batch)
                for v in verdicts:
                    fid = v.get("id")
                    if fid:
                        verdict_map[fid] = v
                logger.info(
                    f"[AI-FP] Batch {i // BATCH_SIZE + 1}: "
                    f"received {len(verdicts)} verdicts"
                )
            except Exception as e:
                logger.error(
                    f"[AI-FP] API call failed for batch "
                    f"{i // BATCH_SIZE + 1}: {e} — keeping all findings in this batch"
                )
                # On error, treat all findings in the batch as real
                for f in batch:
                    verdict_map[f.get("id", "")] = {"verdict": "real", "reason": "api_error"}

        # Classify findings based on verdicts
        real_findings: list[dict] = list(skip_review)
        ai_fp_findings: list[dict] = []

        for finding in to_review:
            fid = finding.get("id", "")
            verdict = verdict_map.get(fid, {})

            if verdict.get("verdict") == "fp":
                tagged = dict(finding)
                tagged["ai_fp_reason"] = verdict.get("reason", "AI-flagged as false positive")
                ai_fp_findings.append(tagged)
                logger.info(
                    f"[AI-FP] Removed '{finding.get('name', '?')}' "
                    f"[{finding.get('severity', '?')}|{finding.get('matcher_name', '?')}] "
                    f"— {tagged['ai_fp_reason']}"
                )
            else:
                real_findings.append(finding)

        logger.info(
            f"[AI-FP] Result: {len(real_findings)} kept, "
            f"{len(ai_fp_findings)} removed as AI-detected false positives"
        )
        return real_findings, ai_fp_findings
