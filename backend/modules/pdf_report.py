"""
PDF Report Generator — Simple and reliable vulnerability report generation.
"""

import json
import os
from datetime import datetime, timezone
from io import BytesIO
from typing import List, Dict, Any, Optional

from PIL import Image as PILImage

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER


# Max width for screenshots inside the PDF content area
_MAX_IMG_WIDTH  = 6.5 * inch
_MAX_IMG_HEIGHT = 4.0 * inch


def _embed_image(path: str, max_width: float = _MAX_IMG_WIDTH, max_height: float = _MAX_IMG_HEIGHT) -> Optional[Image]:
    """
    Return a ReportLab Image that fits within max_width × max_height while
    preserving the original aspect ratio.  Returns None if the file doesn't
    exist or can't be opened.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        with PILImage.open(path) as im:
            orig_w, orig_h = im.size
        if orig_w == 0 or orig_h == 0:
            return None
        scale = min(max_width / orig_w, max_height / orig_h, 1.0)
        return Image(path, width=orig_w * scale, height=orig_h * scale)
    except Exception:
        return None


def _screenshot_caption(finding: dict) -> str:
    """Return a human-readable caption describing what the screenshot shows."""
    tags    = str(finding.get("tags", "")).lower()
    name    = str(finding.get("name", "")).lower()
    vtype   = str(finding.get("vuln_type", "")).lower()
    combined = f"{tags} {name} {vtype}"

    replay = finding.get("replay_verified")

    if any(k in combined for k in ("xss", "cross-site", "cross-site-scripting")):
        base = "XSS — alert() dialog confirmed via DOM overlay"
    elif any(k in combined for k in ("cookie", "httponly", "samesite", "secure flag")):
        base = "Cookie Security — missing attribute flags highlighted"
    elif any(k in combined for k in ("csp", "content-security-policy", "content security policy")):
        base = "CSP Evaluation — policy analysed via CSP Evaluator"
    elif any(k in combined for k in ("sqli", "sql-injection", "sql injection")):
        base = "SQL Injection — database error / response diff captured"
    elif any(k in combined for k in ("open-redirect", "redirect")):
        base = "Open Redirect — final redirect destination shown"
    elif any(k in combined for k in ("header", "hsts", "x-frame", "x-content")):
        base = "Missing Security Header — header presence table overlay"
    elif any(k in combined for k in ("path-traversal", "directory-traversal", "lfi", "rfi")):
        base = "Path Traversal — sensitive file content highlighted"
    elif any(k in combined for k in ("rce", "command-injection", "code-injection")):
        base = "RCE / Command Injection — output indicators highlighted"
    elif any(k in combined for k in ("info", "disclosure", "exposure")):
        base = "Information Disclosure — sensitive data highlighted"
    else:
        base = "Proof-of-Concept — finding context captured"

    if replay is True:
        return f"{base}  ✓ REPLAY CONFIRMED"
    elif replay is False:
        return f"{base}  ⚠ REPLAY UNVERIFIED (transient)"
    return base


class PDFReportGenerator:
    """Generate simple, reliable PDF vulnerability reports."""

    def __init__(self):
        self.severity_order = ["critical", "high", "medium", "low", "info"]

    # ── Styles ────────────────────────────────────────────────────────────────

    def _caption_style(self, styles):
        return ParagraphStyle(
            "Caption",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=HexColor("#555555"),
            leftIndent=4,
            spaceAfter=4,
        )

    def _badge_style(self, styles, color: str):
        return ParagraphStyle(
            "Badge",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=white,
            backColor=HexColor(color),
            leftIndent=6,
            rightIndent=6,
            borderPadding=(3, 6, 3, 6),
        )

    def _mono_style(self, styles):
        return ParagraphStyle(
            "Mono",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            leftIndent=6,
            rightIndent=6,
            backColor=HexColor("#f4f4f4"),
            borderPadding=(4, 4, 4, 4),
            wordWrap="CJK",
        )

    # ── Auth proof section ────────────────────────────────────────────────────

    def _add_auth_proof(self, story, scan: dict, styles):
        """If the scan has an auth proof screenshot, add an Auth section."""
        auth_status_raw = scan.get("auth_status")
        if not auth_status_raw:
            return
        try:
            auth_status = (
                json.loads(auth_status_raw)
                if isinstance(auth_status_raw, str)
                else auth_status_raw
            )
        except (json.JSONDecodeError, TypeError):
            return

        if not isinstance(auth_status, dict):
            return

        auth_shot = auth_status.get("auth_screenshot") or ""
        img = _embed_image(auth_shot)
        if img is None:
            return

        story.append(Paragraph("<b>Authentication Proof</b>", styles["Heading2"]))
        story.append(Paragraph(
            "The screenshot below was captured immediately after successful login, "
            "confirming the scanner ran with an authenticated session.",
            styles["Normal"],
        ))
        story.append(Spacer(1, 0.1 * inch))
        story.append(img)
        story.append(Paragraph(
            f"Logged in as: {self._safe_str(auth_status.get('username', 'N/A'))}  |  "
            f"Method: {self._safe_str(auth_status.get('auth_type', 'form'))}",
            self._caption_style(styles),
        ))
        story.append(Spacer(1, 0.3 * inch))

    # ── Replay badge ──────────────────────────────────────────────────────────

    def _add_replay_badge(self, story, finding: dict, styles):
        """Add a coloured replay-verification badge when present."""
        replay = finding.get("replay_verified")
        if replay is True:
            story.append(Paragraph(
                "✓  REPLAY CONFIRMED — evidence re-verified by live HTTP replay",
                self._badge_style(styles, "#166534"),   # dark green
            ))
        elif replay is False:
            story.append(Paragraph(
                "⚠  REPLAY UNVERIFIED — evidence not present on replay (may be transient)",
                self._badge_style(styles, "#92400e"),   # amber
            ))
        # None → no badge (replay not attempted or inconclusive)

    # ── Main generate ─────────────────────────────────────────────────────────

    def generate_report(
        self,
        scan: Dict[str, Any],
        findings: List[Dict[str, Any]],
        report_title: str = "Vulnerability Scan Report",
    ) -> BytesIO:
        """Generate a PDF report for a scan and its findings."""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph(f"<b>{report_title}</b>", styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))

        # Scan info
        story.append(Paragraph(f"<b>Target:</b> {scan.get('target', 'Unknown')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Scan Type:</b> {scan.get('scan_type', 'N/A')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Engine:</b> {scan.get('scanner_engine', 'N/A')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Date:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
        story.append(Spacer(1, 0.3 * inch))

        # Summary table
        story.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
        summary_data = self._build_summary_data(findings)
        summary_table = Table(summary_data, colWidths=[3 * inch, 1.5 * inch])
        summary_table.setStyle(self._get_table_style())
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))

        # Severity breakdown
        story.append(Paragraph("<b>Severity Breakdown</b>", styles["Heading2"]))
        severity_data = self._build_severity_data(findings)
        severity_table = Table(severity_data, colWidths=[2 * inch, 1.5 * inch, 2 * inch])
        severity_table.setStyle(self._get_table_style())
        story.append(severity_table)
        story.append(Spacer(1, 0.3 * inch))

        # Auth proof screenshot (if available)
        self._add_auth_proof(story, scan, styles)

        # Page break before findings
        story.append(PageBreak())

        # Detailed findings
        story.append(Paragraph("<b>Detailed Findings</b>", styles["Heading2"]))
        story.append(Spacer(1, 0.1 * inch))

        if findings:
            sorted_findings = self._sort_findings(findings)
            for idx, finding in enumerate(sorted_findings, 1):
                story.append(Paragraph(
                    f"<b>{idx}. {self._safe_str(finding.get('name', 'Unknown'))[:80]}</b> "
                    f"[{finding.get('severity', 'info').upper()}]",
                    styles["Heading3"],
                ))

                # Replay badge (immediately under the title)
                self._add_replay_badge(story, finding, styles)

                # ── Basic metadata ────────────────────────────────────────────
                for line in [
                    f"<b>Host:</b> {self._safe_str(finding.get('host', 'N/A'))[:80]}",
                    f"<b>URL:</b> {self._safe_str(finding.get('url', finding.get('matched_at', 'N/A')))[:100]}",
                    f"<b>CVE:</b> {self._safe_str(finding.get('cve_id', 'N/A'))[:50]}",
                    f"<b>CVSS:</b> {finding.get('cvss_score', 'N/A')}",
                    f"<b>Type:</b> {self._safe_str(finding.get('vuln_type', 'N/A'))[:60]}",
                    f"<b>Source:</b> {self._safe_str(finding.get('scanner_source', 'nuclei')).upper()}",
                ]:
                    story.append(Paragraph(line, styles["Normal"]))

                # ── Parse extracted_results once ──────────────────────────────
                extracted: dict = {}
                if finding.get("extracted_results"):
                    try:
                        extracted = (
                            json.loads(finding["extracted_results"])
                            if isinstance(finding["extracted_results"], str)
                            else finding["extracted_results"]
                        )
                        if not isinstance(extracted, dict):
                            extracted = {}
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        extracted = {}

                # ── Consolidated group info ───────────────────────────────────
                if extracted.get("is_consolidated_group"):
                    count = extracted.get("consolidated_from", 1)
                    story.append(Paragraph(
                        f"<b>Consolidated Group:</b> {count} confirmed vulnerable instance{'' if count == 1 else 's'} on the same host",
                        styles["Normal"],
                    ))
                    vulnerable_urls = extracted.get("vulnerable_urls", [])
                    if vulnerable_urls:
                        story.append(Spacer(1, 4))
                        story.append(Paragraph(f"<b>All Affected URLs ({len(vulnerable_urls)}):</b>", styles["Normal"]))
                        for i, vurl in enumerate(vulnerable_urls, 1):
                            story.append(Paragraph(
                                f"  {i}. {self._safe_str(vurl)[:140]}", styles["Normal"]
                            ))
                    instance_params = extracted.get("instance_params", [])
                    if instance_params:
                        story.append(Spacer(1, 4))
                        story.append(Paragraph(
                            f"<b>Vulnerable Parameters:</b> {', '.join(self._safe_str(p)[:40] for p in instance_params[:20])}",
                            styles["Normal"],
                        ))
                    instance_attacks = extracted.get("instance_attacks", [])
                    if instance_attacks:
                        story.append(Spacer(1, 4))
                        story.append(Paragraph(f"<b>Attack Payloads ({len(instance_attacks)}):</b>", styles["Normal"]))
                        for atk in instance_attacks[:10]:
                            story.append(Paragraph(
                                f"  • {self._safe_str(atk)[:120]}", styles["Normal"]
                            ))

                # ── Attack / evidence details (ZAP or Nuclei) ─────────────────
                for label, key in [("Parameter", "param"), ("Attack Payload", "attack"),
                                    ("Evidence", "evidence")]:
                    val = extracted.get(key, "") or ""
                    if val:
                        story.append(Paragraph(
                            f"<b>{label}:</b> {self._safe_str(val)[:300]}", styles["Normal"]
                        ))

                # Curl command
                curl = (finding.get("curl_command") or extracted.get("curl") or "").strip()
                if curl:
                    story.append(Paragraph("<b>Request (curl):</b>", styles["Normal"]))
                    story.append(Paragraph(self._safe_str(curl)[:500], styles["Normal"]))

                # ── Description ───────────────────────────────────────────────
                if finding.get("description"):
                    story.append(Paragraph(
                        f"<b>Description:</b> {self._safe_str(finding['description'])[:400]}",
                        styles["Normal"],
                    ))

                # ── AI Analysis ───────────────────────────────────────────────
                if finding.get("ai_analysis"):
                    try:
                        ai_data = json.loads(finding["ai_analysis"])
                        if isinstance(ai_data, dict):
                            if ai_data.get("business_impact"):
                                story.append(Paragraph(
                                    f"<b>Business Impact:</b> "
                                    f"{self._safe_str(ai_data['business_impact'])[:300]}",
                                    styles["Normal"],
                                ))
                            if ai_data.get("remediation"):
                                story.append(Paragraph(
                                    f"<b>Remediation:</b> "
                                    f"{self._safe_str(ai_data['remediation'])[:300]}",
                                    styles["Normal"],
                                ))
                    except (json.JSONDecodeError, TypeError):
                        pass

                # ── Tags ──────────────────────────────────────────────────────
                if finding.get("tags"):
                    try:
                        tags = finding["tags"]
                        if isinstance(tags, str):
                            tags = json.loads(tags) if tags else []
                        if tags and isinstance(tags, list):
                            story.append(Paragraph(
                                f"<b>Tags:</b> "
                                f"{', '.join(self._safe_str(str(t))[:20] for t in tags[:8])}",
                                styles["Normal"],
                            ))
                    except (json.JSONDecodeError, TypeError):
                        pass

                story.append(Spacer(1, 0.15 * inch))

                # ── HTTP Request / Response ───────────────────────────────────
                http_req = (finding.get("http_request") or "").strip()
                http_resp = (finding.get("http_response") or "").strip()
                if http_req or http_resp:
                    story.append(Paragraph("<b>HTTP Transaction</b>", styles["Heading3"]))
                    mono = self._mono_style(styles)
                    if http_req:
                        story.append(Paragraph("<b>Request:</b>", styles["Normal"]))
                        req_display = http_req[:3000] + ("…[truncated]" if len(http_req) > 3000 else "")
                        story.append(Paragraph(self._safe_str(req_display), mono))
                        story.append(Spacer(1, 0.08 * inch))
                    if http_resp:
                        story.append(Paragraph("<b>Response:</b>", styles["Normal"]))
                        resp_display = http_resp[:3000] + ("…[truncated]" if len(http_resp) > 3000 else "")
                        story.append(Paragraph(self._safe_str(resp_display), mono))
                        story.append(Spacer(1, 0.08 * inch))

                # ── Steps to Reproduce ────────────────────────────────────────
                str_data = extracted.get("steps_to_reproduce", {})
                if not isinstance(str_data, dict):
                    str_data = {}
                steps = str_data.get("steps", [])

                if steps:
                    story.append(Paragraph("<b>Steps to Reproduce:</b>", styles["Heading3"]))
                    for step_num, step in enumerate(steps, 1):
                        story.append(Paragraph(
                            f"<b>Step {step_num}:</b> {self._safe_str(step)}", styles["Normal"]
                        ))
                    story.append(Spacer(1, 0.1 * inch))

                # ── Evidence Screenshot (primary PoC) ─────────────────────────
                poc_shot = finding.get("poc_screenshot") or ""
                img = _embed_image(poc_shot)
                if img is not None:
                    caption = _screenshot_caption(finding)
                    story.append(Paragraph("<b>Evidence Screenshot:</b>", styles["Normal"]))
                    story.append(Spacer(1, 0.05 * inch))
                    story.append(img)
                    story.append(Paragraph(caption, self._caption_style(styles)))
                    story.append(Spacer(1, 0.1 * inch))
                elif poc_shot:
                    story.append(Paragraph(
                        f"<i>Screenshot file not found: {self._safe_str(poc_shot)}</i>",
                        styles["Normal"],
                    ))

                # ── Per-instance screenshots (consolidated groups) ─────────────
                instance_shots = extracted.get("instance_screenshots", [])
                if instance_shots:
                    story.append(Paragraph(
                        "<b>Per-Instance Evidence:</b>", styles["Heading3"]
                    ))
                    for inst in instance_shots:
                        inst_url  = self._safe_str(inst.get("url", ""))[:120]
                        inst_path = inst.get("screenshot", "")
                        story.append(Paragraph(f"  URL: {inst_url}", styles["Normal"]))
                        inst_img = _embed_image(inst_path)
                        if inst_img is not None:
                            story.append(inst_img)
                            story.append(Spacer(1, 0.1 * inch))

                story.append(Spacer(1, 0.2 * inch))
                story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e5e7eb")))
                story.append(Spacer(1, 0.1 * inch))
        else:
            story.append(Paragraph("No vulnerabilities found in this scan.", styles["Normal"]))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

    def _build_summary_data(self, findings: List[Dict[str, Any]]) -> List[List[str]]:
        """Build summary statistics data."""
        if not isinstance(findings, list):
            findings = []

        valid_findings = [f for f in findings if isinstance(f, dict)]
        total    = len(valid_findings)
        critical = sum(1 for f in valid_findings if f.get("severity") == "critical")
        high     = sum(1 for f in valid_findings if f.get("severity") == "high")
        medium   = sum(1 for f in valid_findings if f.get("severity") == "medium")
        low      = sum(1 for f in valid_findings if f.get("severity") == "low")
        info     = sum(1 for f in valid_findings if f.get("severity") == "info")

        return [
            ["Metric", "Count"],
            ["Total Vulnerabilities", str(total)],
            ["Critical", str(critical)],
            ["High", str(high)],
            ["Medium", str(medium)],
            ["Low", str(low)],
            ["Informational", str(info)],
        ]

    def _build_severity_data(self, findings: List[Dict[str, Any]]) -> List[List[str]]:
        """Build severity breakdown data."""
        if not isinstance(findings, list):
            findings = []

        valid_findings = [f for f in findings if isinstance(f, dict)]
        severity_counts = {sev: 0 for sev in self.severity_order}
        for finding in valid_findings:
            sev = finding.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        data = [["Severity", "Count", "Percentage"]]
        total = len(valid_findings) or 1
        for sev in self.severity_order:
            count = severity_counts[sev]
            pct = round((count / total) * 100, 1)
            data.append([sev.capitalize(), str(count), f"{pct}%"])

        return data

    def _sort_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by severity."""
        valid_findings = [f for f in findings if isinstance(f, dict)]
        return sorted(
            valid_findings,
            key=lambda f: (
                self.severity_order.index(f.get("severity", "info").lower()),
                f.get("name", ""),
            ),
        )

    def _get_table_style(self) -> TableStyle:
        """Get standard table styling."""
        return TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  HexColor("#1e2028")),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0),  11),
            ("BOTTOMPADDING", (0, 0), (-1, 0),  12),
            ("BACKGROUND",    (0, 1), (-1, -1), HexColor("#f9fafb")),
            ("GRID",          (0, 0), (-1, -1), 1, HexColor("#e5e7eb")),
            ("TOPPADDING",    (0, 1), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
        ])

    @staticmethod
    def _safe_str(value: Any) -> str:
        """Safely convert value to string."""
        if value is None:
            return "N/A"
        return str(value).replace("<", "&lt;").replace(">", "&gt;")
