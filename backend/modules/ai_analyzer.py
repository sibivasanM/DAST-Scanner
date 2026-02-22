"""
AI Analyzer — Uses OpenAI GPT-4o for intelligent vulnerability
analysis, correlation, attack chain detection, and remediation prioritization.
"""

import json
import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
MODEL = "gpt-4o"

ANALYSIS_SYSTEM_PROMPT = """You are Vulnerability scanner AI, an expert security analyst integrated into
an automated penetration testing platform. Your role is to analyze vulnerability scan results
and provide actionable intelligence.

You MUST respond with ONLY valid JSON (no markdown, no backticks, no preamble).

Your analysis must include:
1. **Risk Assessment**: True business risk, not just CVSS scores
2. **Attack Chain Analysis**: How findings can be chained together
3. **Correlation**: Group related findings that form exploitable paths
4. **Prioritized Remediation**: What to fix first and why
5. **Finding Enrichment**: Per-finding context and exploitation guidance

Respond in this exact JSON structure:
{
  "executive_summary": "2-3 sentence overview of the security posture",
  "risk_score": 0-100,
  "attack_chains": [
    {
      "chain_id": "string",
      "name": "Descriptive name for the attack chain",
      "description": "How these vulnerabilities chain together",
      "severity": "critical|high|medium|low",
      "finding_ids": ["id1", "id2"],
      "exploitation_steps": ["step1", "step2"],
      "impact": "What an attacker achieves"
    }
  ],
  "correlation_groups": [
    {
      "group_name": "string",
      "finding_ids": ["id1", "id2"],
      "relationship": "Description of how findings relate"
    }
  ],
  "remediation_priority": [
    {
      "priority": 1,
      "finding_ids": ["id1"],
      "action": "Specific remediation action",
      "effort": "low|medium|high",
      "impact_reduction": "How much risk this removes"
    }
  ],
  "enrichments": [
    {
      "finding_id": "string",
      "exploitability": "trivial|easy|moderate|difficult",
      "business_impact": "string",
      "false_positive_likelihood": "low|medium|high",
      "recommended_verification": "How to manually verify",
      "cwe_mapping": "CWE-XXX",
      "attack_vector": "Description of how to exploit",
      "references": ["url1", "url2"]
    }
  ]
}"""


class AIAnalyzer:
    """AI-powered vulnerability analysis and correlation engine using OpenAI."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model or os.getenv("OPENAI_MODEL", MODEL)
        self.enabled = bool(self.api_key)
        if not self.enabled:
            logger.warning(
                "OPENAI_API_KEY not set — AI analysis will return heuristic results"
            )

    async def analyze_findings(self, findings: list[dict], target: str) -> dict:
        """Analyze findings using OpenAI API or fall back to heuristic analysis."""
        if not findings:
            return self._empty_analysis()

        if self.enabled:
            try:
                return await self._api_analysis(findings, target)
            except Exception as e:
                logger.error(f"AI analysis failed, falling back to heuristic: {e}")

        return self._heuristic_analysis(findings, target)

    async def _api_analysis(self, findings: list[dict], target: str) -> dict:
        """Call OpenAI Chat Completions API for deep analysis."""
        findings_summary = []
        for f in findings[:50]:
            findings_summary.append({
                "id": f.get("id", ""),
                "name": f.get("name", ""),
                "severity": f.get("severity", ""),
                "template_id": f.get("template_id", ""),
                "host": f.get("host", ""),
                "url": f.get("matched_at", f.get("url", "")),
                "description": (f.get("description", "") or "")[:300],
                "cve_id": f.get("cve_id"),
                "cvss_score": f.get("cvss_score"),
                "tags": f.get("tags", ""),
                "matcher_name": f.get("matcher_name", ""),
            })

        user_message = (
            f"Analyze these {len(findings_summary)} vulnerability findings "
            f"for target: {target}\n\n"
            f"Findings:\n{json.dumps(findings_summary, indent=2)}"
        )

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                OPENAI_API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "temperature": 0.2,
                    "max_tokens": 4096,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": ANALYSIS_SYSTEM_PROMPT},
                        {"role": "user", "content": user_message},
                    ],
                },
            )
            response.raise_for_status()
            data = response.json()

        text = data["choices"][0]["message"]["content"]

        # Strip any accidental markdown fencing
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        return json.loads(text)

    def _heuristic_analysis(self, findings: list[dict], target: str) -> dict:
        """Fallback heuristic analysis when API is unavailable."""
        severity_groups = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_groups.setdefault(sev, []).append(f)

        critical = severity_groups.get("critical", [])
        high = severity_groups.get("high", [])

        risk_score = min(100, (
            len(critical) * 25 + len(high) * 15
            + len(severity_groups.get("medium", [])) * 5
            + len(severity_groups.get("low", [])) * 1
        ))

        chains = []
        auth_vulns = [f for f in findings if any(
            t in str(f.get("tags", ""))
            for t in ["auth", "login", "bypass", "default-login"]
        )]
        info_disclosure = [f for f in findings if any(
            t in str(f.get("tags", ""))
            for t in ["exposure", "disclosure", "config", "env"]
        )]
        injection_vulns = [f for f in findings if any(
            t in str(f.get("tags", ""))
            for t in ["sqli", "xss", "ssti", "injection", "rce"]
        )]

        if info_disclosure and auth_vulns:
            chains.append({
                "chain_id": "chain-recon-to-auth",
                "name": "Information Disclosure → Authentication Bypass",
                "description": "Exposed configuration or credentials can be leveraged to bypass authentication controls.",
                "severity": "critical" if auth_vulns else "high",
                "finding_ids": [f["id"] for f in (info_disclosure + auth_vulns)[:6]],
                "exploitation_steps": [
                    "Harvest credentials/tokens from exposed endpoints",
                    "Use gathered information to authenticate",
                    "Escalate privileges if possible",
                ],
                "impact": "Full unauthorized access to the application",
            })

        if injection_vulns:
            chains.append({
                "chain_id": "chain-injection",
                "name": "Injection Attack Path",
                "description": "Injection vulnerabilities may lead to data exfiltration or RCE.",
                "severity": "critical",
                "finding_ids": [f["id"] for f in injection_vulns[:5]],
                "exploitation_steps": [
                    "Identify injection point",
                    "Craft payload to extract data or execute commands",
                    "Pivot to internal systems if RCE achieved",
                ],
                "impact": "Data breach, remote code execution, lateral movement",
            })

        enrichments = []
        for f in findings:
            sev = f.get("severity", "info")
            enrichments.append({
                "finding_id": f.get("id", ""),
                "exploitability": {"critical": "easy", "high": "moderate", "medium": "moderate", "low": "difficult", "info": "difficult"}.get(sev, "moderate"),
                "business_impact": f"Severity {sev} — potential impact on confidentiality/integrity",
                "false_positive_likelihood": "low" if sev in ("critical", "high") else "medium",
                "recommended_verification": "Manual verification recommended",
                "cwe_mapping": "",
                "attack_vector": f.get("description", "")[:200] or "See template description",
                "references": [],
            })

        return {
            "executive_summary": (
                f"Scan of {target} revealed {len(findings)} unique vulnerabilities: "
                f"{len(critical)} critical, {len(high)} high, "
                f"{len(severity_groups.get('medium', []))} medium. "
                f"{'Immediate action required.' if critical else 'Review recommended.'}"
            ),
            "risk_score": risk_score,
            "attack_chains": chains,
            "correlation_groups": [],
            "remediation_priority": [
                {
                    "priority": i + 1,
                    "finding_ids": [f["id"]],
                    "action": f"Remediate {f['severity']} finding: {f['name']}",
                    "effort": "medium",
                    "impact_reduction": "Reduces risk by ~{}%".format({'critical':25,'high':15,'medium':5}.get(f['severity'], 2)),
                }
                for i, f in enumerate((critical + high)[:10])
            ],
            "enrichments": enrichments,
        }

    def _empty_analysis(self) -> dict:
        return {
            "executive_summary": "No findings to analyze.",
            "risk_score": 0,
            "attack_chains": [],
            "correlation_groups": [],
            "remediation_priority": [],
            "enrichments": [],
        }
